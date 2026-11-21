package refute

import (
	"context"
	"fmt"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/verify"
)

// Panel asks a second reviewer about findings that matter most. One model
// agreeing with a scanner is weaker evidence than two models that were asked
// separately, so a serious finding is confirmed only when both hold it, and a
// disagreement is handed to a person.
type Panel struct {
	Primary verify.Refuter
	Second  verify.Refuter
	// MinSeverity is the lowest severity that gets a second opinion.
	MinSeverity finding.Severity
}

// Refute returns the primary reviewer's verdict, unless it supports a finding
// at or above MinSeverity; then the second reviewer must support it too.
func (p Panel) Refute(ctx context.Context, f finding.Finding) (verify.Refutation, error) {
	first, err := p.Primary.Refute(ctx, f)
	if err != nil {
		return verify.Refutation{}, err
	}
	if first.Verdict != verify.Holds || f.Severity.Rank() < p.MinSeverity.Rank() {
		return first, nil
	}
	second, err := p.Second.Refute(ctx, f)
	if err != nil {
		return verify.Refutation{
			Verdict: verify.Uncertain,
			Reason:  fmt.Sprintf("The first reviewer held the finding (%s) but the second could not be consulted: %v", first.Reason, err),
		}, nil
	}
	if second.Verdict == verify.Holds {
		return verify.Refutation{
			Verdict: verify.Holds,
			Reason:  fmt.Sprintf("Two reviewers held it. First: %s Second: %s", first.Reason, second.Reason),
		}, nil
	}
	return verify.Refutation{
		Verdict: verify.Uncertain,
		Reason: fmt.Sprintf("The reviewers disagree, so a person should decide. First (holds): %s Second (%s): %s",
			first.Reason, second.Verdict, second.Reason),
	}, nil
}
