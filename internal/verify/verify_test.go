package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/scope"
)

type fakeReproducer struct {
	results []bool
	err     error
	calls   int
}

func (r *fakeReproducer) Reproduce(context.Context, finding.Finding) (bool, error) {
	r.calls++
	if r.err != nil {
		return false, r.err
	}
	return r.results[(r.calls-1)%len(r.results)], nil
}

type fakeRefuter struct {
	verdict RefuteVerdict
	err     error
	calls   int
}

func (r *fakeRefuter) Refute(context.Context, finding.Finding) (Refutation, error) {
	r.calls++
	return Refutation{Verdict: r.verdict, Reason: "because " + string(r.verdict)}, r.err
}

func goodFinding() finding.Finding {
	return finding.Finding{
		ID: "f1", Source: "nuclei", RuleID: "exposed-panel", Status: finding.Candidate,
		Target:   "https://app.test/admin",
		Evidence: finding.Evidence{Request: "GET /admin", Response: "HTTP/1.1 200 OK"},
	}
}

type harness struct {
	pipeline   *Pipeline
	reproducer *fakeReproducer
	refuter    *fakeRefuter
	budget     *budget.Budget
}

func newHarness(t *testing.T, limits budget.Limits) harness {
	t.Helper()
	policy, err := scope.New(scope.Config{Hosts: []string{"app.test"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := budget.New(limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := harness{
		reproducer: &fakeReproducer{results: []bool{true}},
		refuter:    &fakeRefuter{verdict: Holds},
		budget:     b,
	}
	h.pipeline, err = NewPipeline(func() time.Time { return time.Unix(1_700_000_000, 0) },
		EvidenceStage{},
		ScopeStage{Policy: policy},
		ReproduceStage{Reproducer: h.reproducer, Attempts: 2, Budget: b},
		RefuteStage{Refuter: h.refuter, Budget: b},
	)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var roomyLimits = budget.Limits{Tokens: 1 << 30, Turns: 100, SandboxRuns: 100, DurationSeconds: 3600}

func lastVerdict(f finding.Finding) finding.Verdict {
	return f.Verdicts[len(f.Verdicts)-1]
}

func TestFindingThatPassesEveryStageIsConfirmed(t *testing.T) {
	h := newHarness(t, roomyLimits)
	original := goodFinding()

	got := h.pipeline.Verify(context.Background(), original)

	if got.Status != finding.Confirmed {
		t.Fatalf("status = %s; verdicts = %+v", got.Status, got.Verdicts)
	}
	if len(got.Verdicts) != 4 || h.reproducer.calls != 2 || h.refuter.calls != 1 {
		t.Fatalf("verdicts = %d, reproductions = %d, refutations = %d", len(got.Verdicts), h.reproducer.calls, h.refuter.calls)
	}
	if original.Status != finding.Candidate || len(original.Verdicts) != 0 {
		t.Fatal("the input finding was modified")
	}
	if got.Verdicts[0].At.IsZero() {
		t.Fatal("verdicts are not timestamped")
	}
}

func TestStageFailuresSetTheStatusAndStopVerification(t *testing.T) {
	cases := []struct {
		name          string
		mutate        func(*finding.Finding, *harness)
		wantStatus    finding.Status
		wantStage     string
		reproductions int
		refutations   int
	}{
		{"no response captured", func(f *finding.Finding, _ *harness) { f.Evidence.Response = "" },
			finding.Unconfirmed, "evidence", 0, 0},
		{"target is not a URL", func(f *finding.Finding, _ *harness) { f.Target = "app.test:22" },
			finding.Unconfirmed, "evidence", 0, 0},
		{"target outside scope", func(f *finding.Finding, _ *harness) { f.Target = "https://other.test/admin" },
			finding.OutOfScope, "scope", 0, 0},
		{"port outside scope", func(f *finding.Finding, _ *harness) { f.Target = "https://app.test:8443/" },
			finding.OutOfScope, "scope", 0, 0},
		{"does not reproduce", func(_ *finding.Finding, h *harness) { h.reproducer.results = []bool{false} },
			finding.Refuted, "reproduce", 1, 0},
		{"reproduces only once", func(_ *finding.Finding, h *harness) { h.reproducer.results = []bool{true, false} },
			finding.Refuted, "reproduce", 2, 0},
		{"refuter disproves it", func(_ *finding.Finding, h *harness) { h.refuter.verdict = Disproved },
			finding.Refuted, "refute", 2, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, roomyLimits)
			f := goodFinding()
			tc.mutate(&f, &h)

			got := h.pipeline.Verify(context.Background(), f)

			if got.Status != tc.wantStatus {
				t.Fatalf("status = %s; want %s; verdicts = %+v", got.Status, tc.wantStatus, got.Verdicts)
			}
			if last := lastVerdict(got); last.Stage != tc.wantStage || last.Outcome != finding.Fail || last.Reason == "" {
				t.Fatalf("last verdict = %+v; want a failure with a reason at %s", last, tc.wantStage)
			}
			if h.reproducer.calls != tc.reproductions || h.refuter.calls != tc.refutations {
				t.Fatalf("reproductions = %d, refutations = %d", h.reproducer.calls, h.refuter.calls)
			}
		})
	}
}

func TestUndecidedStagesLeaveTheFindingUnconfirmed(t *testing.T) {
	cases := map[string]func(*harness){
		"reproduction tool error":          func(h *harness) { h.reproducer.err = errors.New("sandbox failed") },
		"refuter unsure":                   func(h *harness) { h.refuter.verdict = Uncertain },
		"refuter error":                    func(h *harness) { h.refuter.err = errors.New("api down") },
		"refuter gives an unknown verdict": func(h *harness) { h.refuter.verdict = "maybe" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, roomyLimits)
			mutate(&h)

			got := h.pipeline.Verify(context.Background(), goodFinding())

			if got.Status != finding.Unconfirmed {
				t.Fatalf("status = %s; want unconfirmed; verdicts = %+v", got.Status, got.Verdicts)
			}
		})
	}
}

func TestALaterFailureStillRefutesAfterAnUndecidedStage(t *testing.T) {
	h := newHarness(t, roomyLimits)
	h.reproducer.err = errors.New("sandbox failed")
	h.refuter.verdict = Disproved

	got := h.pipeline.Verify(context.Background(), goodFinding())

	if got.Status != finding.Refuted {
		t.Fatalf("status = %s; want refuted", got.Status)
	}
}

func TestSpentBudgetNeverConfirms(t *testing.T) {
	cases := map[string]budget.Limits{
		"one sandbox run for two attempts": {Tokens: 1 << 30, Turns: 100, SandboxRuns: 1, DurationSeconds: 3600},
	}
	for name, limits := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, limits)

			got := h.pipeline.Verify(context.Background(), goodFinding())

			if got.Status != finding.Unconfirmed {
				t.Fatalf("status = %s; want unconfirmed", got.Status)
			}
			if h.reproducer.calls != 1 {
				t.Fatalf("reproductions = %d; the second must be refused", h.reproducer.calls)
			}
		})
	}

	t.Run("tokens already spent", func(t *testing.T) {
		h := newHarness(t, budget.Limits{Tokens: 10, Turns: 100, SandboxRuns: 100, DurationSeconds: 3600})
		h.budget.AddTokens(10)

		got := h.pipeline.Verify(context.Background(), goodFinding())

		if got.Status != finding.Unconfirmed || h.reproducer.calls != 0 || h.refuter.calls != 0 {
			t.Fatalf("status = %s, reproductions = %d, refutations = %d", got.Status, h.reproducer.calls, h.refuter.calls)
		}
	})
}

func TestCancelledVerificationIsUnconfirmedAndRunsNothing(t *testing.T) {
	h := newHarness(t, roomyLimits)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := h.pipeline.Verify(ctx, goodFinding())

	if got.Status != finding.Unconfirmed || h.reproducer.calls != 0 || h.refuter.calls != 0 {
		t.Fatalf("status = %s, reproductions = %d, refutations = %d", got.Status, h.reproducer.calls, h.refuter.calls)
	}
	if !strings.Contains(lastVerdict(got).Reason, "cancelled") {
		t.Fatalf("reason = %q", lastVerdict(got).Reason)
	}
}

func TestVerifyAllKeepsOrder(t *testing.T) {
	h := newHarness(t, roomyLimits)
	outside := goodFinding()
	outside.ID, outside.Target = "f2", "https://other.test/"

	got := h.pipeline.VerifyAll(context.Background(), []finding.Finding{goodFinding(), outside})

	if len(got) != 2 || got[0].Status != finding.Confirmed || got[1].Status != finding.OutOfScope || got[1].ID != "f2" {
		t.Fatalf("results = %+v", got)
	}
}

func TestNewPipelineRejectsEmptyAndNilStages(t *testing.T) {
	if _, err := NewPipeline(nil); err == nil {
		t.Error("an empty pipeline was accepted")
	}
	if _, err := NewPipeline(nil, EvidenceStage{}, nil); err == nil {
		t.Error("a nil stage was accepted")
	}
}

func TestReproduceStageNeedsAtLeastOneAttempt(t *testing.T) {
	stage := ReproduceStage{Reproducer: &fakeReproducer{results: []bool{true}}}
	if outcome, _ := stage.Check(context.Background(), goodFinding()); outcome != finding.Inconclusive {
		t.Fatalf("outcome = %s; zero attempts must not pass", outcome)
	}
}

func TestTargetHostPort(t *testing.T) {
	cases := []struct {
		target string
		host   string
		port   uint16
		ok     bool
	}{
		{"https://app.test/x", "app.test", 443, true},
		{"http://app.test", "app.test", 80, true},
		{"https://app.test:8443/x?y=1", "app.test", 8443, true},
		{"http://[2001:db8::1]:8080/", "2001:db8::1", 8080, true},
		{"ftp://app.test/", "", 0, false},
		{"app.test:443", "", 0, false},
		{"https:///path", "", 0, false},
		{"https://app.test:0/", "", 0, false},
		{"http://app.test:99999/", "", 0, false},
		{"://bad", "", 0, false},
	}
	for _, tc := range cases {
		host, port, err := TargetHostPort(tc.target)
		if tc.ok != (err == nil) || host != tc.host || port != tc.port {
			t.Errorf("TargetHostPort(%q) = %q, %d, %v", tc.target, host, port, err)
		}
	}
}
