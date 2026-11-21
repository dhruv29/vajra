// Package budget caps what a run may spend. Every limit is mandatory: there is
// no unlimited mode.
package budget

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Limits are the hard caps for one run.
type Limits struct {
	Tokens          int64 `json:"tokens"`
	Turns           int   `json:"turns"`
	SandboxRuns     int   `json:"sandbox_runs"`
	DurationSeconds int   `json:"duration_seconds"`
}

// Usage is a snapshot of what a run has spent.
type Usage struct {
	Tokens      int64         `json:"tokens"`
	Turns       int           `json:"turns"`
	SandboxRuns int           `json:"sandbox_runs"`
	Elapsed     time.Duration `json:"elapsed_ns"`
}

// Exhausted reports which limit stopped the run.
type Exhausted struct {
	Resource string
}

func (e *Exhausted) Error() string {
	return fmt.Sprintf("budget exhausted: %s", e.Resource)
}

// IsExhausted reports whether err is, or wraps, a budget stop.
func IsExhausted(err error) bool {
	var e *Exhausted
	return errors.As(err, &e)
}

// Budget tracks spending against Limits. It is safe for concurrent use.
type Budget struct {
	limits Limits
	now    func() time.Time
	start  time.Time

	mu    sync.Mutex
	usage Usage
}

// New starts the clock on a budget. now may be nil.
func New(limits Limits, now func() time.Time) (*Budget, error) {
	if limits.Tokens <= 0 || limits.Turns <= 0 || limits.SandboxRuns <= 0 || limits.DurationSeconds <= 0 {
		return nil, errors.New("budget: tokens, turns, sandbox_runs and duration_seconds must all be set above zero")
	}
	if now == nil {
		now = time.Now
	}
	return &Budget{limits: limits, now: now, start: now()}, nil
}

// Check reports whether the run may continue.
func (b *Budget) Check() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checkLocked()
}

func (b *Budget) checkLocked() error {
	if b.now().Sub(b.start) >= time.Duration(b.limits.DurationSeconds)*time.Second {
		return &Exhausted{Resource: "duration"}
	}
	if b.usage.Tokens >= b.limits.Tokens {
		return &Exhausted{Resource: "tokens"}
	}
	return nil
}

// SpendTurn claims one model turn, or fails without claiming it.
func (b *Budget) SpendTurn() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkLocked(); err != nil {
		return err
	}
	if b.usage.Turns >= b.limits.Turns {
		return &Exhausted{Resource: "turns"}
	}
	b.usage.Turns++
	return nil
}

// SpendRun claims one sandbox run, or fails without claiming it.
func (b *Budget) SpendRun() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkLocked(); err != nil {
		return err
	}
	if b.usage.SandboxRuns >= b.limits.SandboxRuns {
		return &Exhausted{Resource: "sandbox_runs"}
	}
	b.usage.SandboxRuns++
	return nil
}

// AddTokens records tokens a model call already consumed. The cost is known
// only after the call, so it is always recorded; the next Check or Spend then
// fails if the limit was crossed.
func (b *Budget) AddTokens(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.usage.Tokens += n
}

// Remaining returns the time left before the duration limit.
func (b *Budget) Remaining() time.Duration {
	left := time.Duration(b.limits.DurationSeconds)*time.Second - b.now().Sub(b.start)
	if left < 0 {
		return 0
	}
	return left
}

// Usage returns a snapshot of spending so far.
func (b *Budget) Usage() Usage {
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.usage
	u.Elapsed = b.now().Sub(b.start)
	return u
}

// Limits returns the caps this budget enforces.
func (b *Budget) Limits() Limits {
	return b.limits
}
