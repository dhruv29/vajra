package verify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/scope"
)

// TargetHostPort extracts the host and port a finding's target URL points at.
func TargetHostPort(target string) (string, uint16, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", 0, fmt.Errorf("target is not a URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", 0, fmt.Errorf("target scheme %q is not http or https", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", 0, errors.New("target has no host")
	}
	portText := u.Port()
	if portText == "" {
		if u.Scheme == "https" {
			return u.Hostname(), 443, nil
		}
		return u.Hostname(), 80, nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("target port %q is invalid", portText)
	}
	return u.Hostname(), uint16(port), nil
}

// EvidenceStage requires a finding to carry the request and response that
// support it. Without them nothing later can be checked.
type EvidenceStage struct{}

func (EvidenceStage) Name() string               { return "evidence" }
func (EvidenceStage) FailStatus() finding.Status { return finding.Unconfirmed }

func (EvidenceStage) Check(_ context.Context, f finding.Finding) (finding.Outcome, string) {
	if _, _, err := TargetHostPort(f.Target); err != nil {
		return finding.Fail, err.Error()
	}
	if f.Evidence.Request == "" || f.Evidence.Response == "" {
		return finding.Fail, "the scanner did not capture both a request and a response"
	}
	return finding.Pass, "request and response captured"
}

// ScopeStage rejects findings about targets the policy does not cover, so an
// out-of-scope host is never re-tested or reported as the operator's problem.
type ScopeStage struct {
	Policy *scope.Policy
}

func (ScopeStage) Name() string               { return "scope" }
func (ScopeStage) FailStatus() finding.Status { return finding.OutOfScope }

func (s ScopeStage) Check(_ context.Context, f finding.Finding) (finding.Outcome, string) {
	host, port, err := TargetHostPort(f.Target)
	if err != nil {
		return finding.Fail, err.Error()
	}
	if err := s.Policy.CheckTarget(host, port); err != nil {
		return finding.Fail, err.Error()
	}
	return finding.Pass, "target is in scope"
}

// Reproducer re-runs the check behind a finding and reports whether it still
// matches.
type Reproducer interface {
	Reproduce(ctx context.Context, f finding.Finding) (bool, error)
}

// ReproduceStage re-runs the finding and requires every attempt to match. A
// result that appears once and not again is noise, not a vulnerability.
type ReproduceStage struct {
	Reproducer Reproducer
	Attempts   int
	Budget     *budget.Budget
}

func (ReproduceStage) Name() string               { return "reproduce" }
func (ReproduceStage) FailStatus() finding.Status { return finding.Refuted }

func (s ReproduceStage) Check(ctx context.Context, f finding.Finding) (finding.Outcome, string) {
	if s.Attempts < 1 {
		return finding.Inconclusive, "no reproduction attempts are configured"
	}
	for attempt := 1; attempt <= s.Attempts; attempt++ {
		if err := s.Budget.SpendRun(); err != nil {
			return finding.Inconclusive, err.Error()
		}
		matched, err := s.Reproducer.Reproduce(ctx, f)
		if err != nil {
			return finding.Inconclusive, fmt.Sprintf("attempt %d could not run: %v", attempt, err)
		}
		if !matched {
			return finding.Fail, fmt.Sprintf("did not reproduce on attempt %d of %d", attempt, s.Attempts)
		}
	}
	return finding.Pass, fmt.Sprintf("reproduced %d of %d times", s.Attempts, s.Attempts)
}

// RefuteVerdict is a refuter's conclusion.
type RefuteVerdict string

const (
	// Holds means the refuter tried to disprove the finding and could not.
	Holds RefuteVerdict = "holds"
	// Disproved means the evidence does not support the claim.
	Disproved RefuteVerdict = "refuted"
	// Uncertain means the refuter could not decide.
	Uncertain RefuteVerdict = "uncertain"
)

// Refutation is a refuter's conclusion and its reasoning.
type Refutation struct {
	Verdict RefuteVerdict
	Reason  string
}

// Refuter argues against a finding from its evidence.
type Refuter interface {
	Refute(ctx context.Context, f finding.Finding) (Refutation, error)
}

// RefuteStage asks an independent reviewer to disprove the finding. Budget is
// nil only when the reviewer makes no model call.
type RefuteStage struct {
	Refuter Refuter
	Budget  *budget.Budget
}

func (RefuteStage) Name() string               { return "refute" }
func (RefuteStage) FailStatus() finding.Status { return finding.Refuted }

func (s RefuteStage) Check(ctx context.Context, f finding.Finding) (finding.Outcome, string) {
	if s.Budget != nil {
		if err := s.Budget.SpendTurn(); err != nil {
			return finding.Inconclusive, err.Error()
		}
		// The review may not outlive the run's time budget.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Budget.Remaining())
		defer cancel()
	}
	r, err := s.Refuter.Refute(ctx, f)
	if err != nil {
		return finding.Inconclusive, fmt.Sprintf("refuter could not run: %v", err)
	}
	switch r.Verdict {
	case Holds:
		return finding.Pass, r.Reason
	case Disproved:
		return finding.Fail, r.Reason
	default:
		return finding.Inconclusive, r.Reason
	}
}
