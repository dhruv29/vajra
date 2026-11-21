// Package verify decides whether a scanner result deserves to be reported.
//
// A finding passes through stages in order. A stage that fails ends
// verification and sets the status that stage owns; a stage that cannot decide
// leaves the finding unconfirmed. Only a finding that passes every stage is
// confirmed.
package verify

import (
	"context"
	"errors"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
)

// Stage is one verification step.
type Stage interface {
	Name() string
	// FailStatus is the status a finding takes when this stage fails.
	FailStatus() finding.Status
	// Check returns the outcome and a reason a person can read.
	Check(ctx context.Context, f finding.Finding) (finding.Outcome, string)
}

// Pipeline runs stages in order.
type Pipeline struct {
	stages []Stage
	now    func() time.Time
}

// NewPipeline builds a pipeline. now may be nil.
func NewPipeline(now func() time.Time, stages ...Stage) (*Pipeline, error) {
	if len(stages) == 0 {
		return nil, errors.New("verify: a pipeline needs at least one stage")
	}
	for _, s := range stages {
		if s == nil {
			return nil, errors.New("verify: nil stage")
		}
	}
	if now == nil {
		now = time.Now
	}
	return &Pipeline{stages: stages, now: now}, nil
}

// Verify runs every stage against f and returns a copy carrying the verdicts
// and the resulting status. f itself is not modified.
func (p *Pipeline) Verify(ctx context.Context, f finding.Finding) finding.Finding {
	undecided := false
	for _, stage := range p.stages {
		outcome, reason := finding.Inconclusive, "verification was cancelled"
		if ctx.Err() == nil {
			outcome, reason = stage.Check(ctx, f)
		}
		f = f.WithVerdict(finding.Verdict{
			Stage: stage.Name(), Outcome: outcome, Reason: reason, At: p.now().UTC(),
		})
		switch outcome {
		case finding.Fail:
			return f.WithStatus(stage.FailStatus())
		case finding.Pass:
		default:
			// Anything that is not a clear pass counts as undecided.
			undecided = true
		}
	}
	if undecided {
		return f.WithStatus(finding.Unconfirmed)
	}
	return f.WithStatus(finding.Confirmed)
}

// VerifyAll verifies each finding in turn and returns the results in order.
func (p *Pipeline) VerifyAll(ctx context.Context, findings []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, p.Verify(ctx, f))
	}
	return out
}
