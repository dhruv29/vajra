package refute

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/verify"
)

type fixedRefuter struct {
	verdict verify.RefuteVerdict
	err     error
	calls   int
}

func (r *fixedRefuter) Refute(context.Context, finding.Finding) (verify.Refutation, error) {
	r.calls++
	return verify.Refutation{Verdict: r.verdict, Reason: "reason-" + string(r.verdict) + "."}, r.err
}

func TestPanel(t *testing.T) {
	cases := []struct {
		name        string
		severity    finding.Severity
		first       verify.RefuteVerdict
		second      verify.RefuteVerdict
		secondErr   error
		want        verify.RefuteVerdict
		secondAsked bool
		mentions    string
	}{
		{"both hold a serious finding", finding.SeverityHigh, verify.Holds, verify.Holds, nil, verify.Holds, true, "Two reviewers"},
		{"second disproves", finding.SeverityCritical, verify.Holds, verify.Disproved, nil, verify.Uncertain, true, "disagree"},
		{"second unsure", finding.SeverityHigh, verify.Holds, verify.Uncertain, nil, verify.Uncertain, true, "disagree"},
		{"second fails", finding.SeverityHigh, verify.Holds, verify.Holds, errors.New("api down"), verify.Uncertain, true, "could not be consulted"},
		{"minor finding needs one reviewer", finding.SeverityMedium, verify.Holds, verify.Disproved, nil, verify.Holds, false, "reason-holds"},
		{"first disproves", finding.SeverityCritical, verify.Disproved, verify.Holds, nil, verify.Disproved, false, "reason-refuted"},
		{"first unsure", finding.SeverityCritical, verify.Uncertain, verify.Holds, nil, verify.Uncertain, false, "reason-uncertain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, second := &fixedRefuter{verdict: tc.first}, &fixedRefuter{verdict: tc.second, err: tc.secondErr}
			panel := Panel{Primary: first, Second: second, MinSeverity: finding.SeverityHigh}

			got, err := panel.Refute(context.Background(), finding.Finding{Severity: tc.severity})

			if err != nil || got.Verdict != tc.want || !strings.Contains(got.Reason, tc.mentions) {
				t.Fatalf("refutation = %+v, err = %v; want %s mentioning %q", got, err, tc.want, tc.mentions)
			}
			if (second.calls == 1) != tc.secondAsked || first.calls != 1 {
				t.Fatalf("first asked %d times, second %d times", first.calls, second.calls)
			}
		})
	}
}

func TestPanelPassesOnThePrimaryReviewersError(t *testing.T) {
	second := &fixedRefuter{verdict: verify.Holds}
	panel := Panel{Primary: &fixedRefuter{err: errors.New("api down")}, Second: second, MinSeverity: finding.SeverityLow}

	if _, err := panel.Refute(context.Background(), finding.Finding{Severity: finding.SeverityCritical}); err == nil || second.calls != 0 {
		t.Fatalf("err = %v, second asked %d times", err, second.calls)
	}
}
