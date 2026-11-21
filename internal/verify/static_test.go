package verify

import (
	"context"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

func staticFinding() finding.Finding {
	return finding.Finding{
		ID: "s1", Kind: finding.Static, Source: "semgrep", RuleID: "sqli", Status: finding.Candidate,
		Target:   "app/views.py:4",
		Location: &finding.Location{File: "app/views.py", Line: 4},
		Evidence: finding.Evidence{Code: ">     4 | db.execute(query)\n"},
	}
}

func TestStaticStages(t *testing.T) {
	cases := []struct {
		name   string
		stage  Stage
		mutate func(*finding.Finding)
		want   finding.Outcome
	}{
		{"evidence present", CodeEvidenceStage{}, func(*finding.Finding) {}, finding.Pass},
		{"no location", CodeEvidenceStage{}, func(f *finding.Finding) { f.Location = nil }, finding.Fail},
		{"no line", CodeEvidenceStage{}, func(f *finding.Finding) { f.Location = &finding.Location{File: "a.py"} }, finding.Fail},
		{"source could not be read", CodeEvidenceStage{}, func(f *finding.Finding) { f.Evidence.Code = "" }, finding.Fail},
		{"file in the tree", SourceScopeStage{}, func(*finding.Finding) {}, finding.Pass},
		{"file outside the tree", SourceScopeStage{}, func(f *finding.Finding) { f.Location = &finding.Location{File: "../x.py", Line: 1} }, finding.Fail},
		{"absolute file", SourceScopeStage{}, func(f *finding.Finding) { f.Location = &finding.Location{File: "/etc/passwd", Line: 1} }, finding.Fail},
		{"scope without location", SourceScopeStage{}, func(f *finding.Finding) { f.Location = nil }, finding.Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := staticFinding()
			tc.mutate(&f)
			outcome, reason := tc.stage.Check(context.Background(), f)
			if outcome != tc.want || reason == "" {
				t.Fatalf("outcome = %s (%q); want %s", outcome, reason, tc.want)
			}
		})
	}
	if (CodeEvidenceStage{}).FailStatus() != finding.Unconfirmed || (SourceScopeStage{}).FailStatus() != finding.OutOfScope {
		t.Fatal("fail statuses are wrong")
	}
	if (CodeEvidenceStage{}).Name() != "evidence" || (SourceScopeStage{}).Name() != "scope" {
		t.Fatal("stage names are wrong")
	}
}

func TestSourceRouterSendsEachFindingBackToItsScanner(t *testing.T) {
	hit, miss := &fakeReproducer{results: []bool{true}}, &fakeReproducer{results: []bool{false}}
	router := SourceRouter{"a": hit, "b": miss, "nil": nil}

	matched, err := router.Reproduce(context.Background(), finding.Finding{Source: "a"})
	if err != nil || !matched || hit.calls != 1 || miss.calls != 0 {
		t.Fatalf("matched = %v, err = %v", matched, err)
	}
	if matched, _ := router.Reproduce(context.Background(), finding.Finding{Source: "b"}); matched {
		t.Fatal("the wrong reproducer answered")
	}
	for _, source := range []string{"unknown", "nil"} {
		if matched, err := router.Reproduce(context.Background(), finding.Finding{Source: source}); err == nil || matched {
			t.Errorf("%s: matched = %v, err = %v; an unroutable finding must be an error", source, matched, err)
		}
	}
}

func TestPackageEvidenceStage(t *testing.T) {
	stage := PackageEvidenceStage{}
	ok := finding.Finding{Evidence: finding.Evidence{Extracted: []string{"npm/lodash@4.17.20"}}}
	if outcome, reason := stage.Check(context.Background(), ok); outcome != finding.Pass || reason == "" {
		t.Fatalf("outcome = %s", outcome)
	}
	for _, bad := range []finding.Finding{{}, {Evidence: finding.Evidence{Extracted: []string{""}}}} {
		if outcome, _ := stage.Check(context.Background(), bad); outcome != finding.Fail {
			t.Fatalf("outcome = %s; a finding that names no package must fail", outcome)
		}
	}
	if stage.Name() != "evidence" || stage.FailStatus() != finding.Unconfirmed {
		t.Fatal("stage identity is wrong")
	}
}

func TestReproduceStageWithoutABudgetStillRuns(t *testing.T) {
	r := &fakeReproducer{results: []bool{true}}
	stage := ReproduceStage{Reproducer: r, Attempts: 2}
	if outcome, _ := stage.Check(context.Background(), staticFinding()); outcome != finding.Pass || r.calls != 2 {
		t.Fatalf("outcome = %s, calls = %d", outcome, r.calls)
	}
}
