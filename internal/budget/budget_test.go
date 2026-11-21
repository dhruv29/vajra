package budget

import (
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newBudget(t *testing.T, l Limits) (*Budget, *clock) {
	t.Helper()
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b, err := New(l, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return b, c
}

var testLimits = Limits{Tokens: 1000, Turns: 2, SandboxRuns: 2, DurationSeconds: 60}

func TestNewRequiresEveryLimit(t *testing.T) {
	for name, l := range map[string]Limits{
		"no limits":   {},
		"no tokens":   {Turns: 1, SandboxRuns: 1, DurationSeconds: 1},
		"no turns":    {Tokens: 1, SandboxRuns: 1, DurationSeconds: 1},
		"no runs":     {Tokens: 1, Turns: 1, DurationSeconds: 1},
		"no duration": {Tokens: 1, Turns: 1, SandboxRuns: 1},
		"negative":    {Tokens: -1, Turns: 1, SandboxRuns: 1, DurationSeconds: 1},
	} {
		if _, err := New(l, nil); err == nil {
			t.Errorf("%s: New succeeded; want an error", name)
		}
	}
}

func TestTurnsAndRunsStopAtTheLimit(t *testing.T) {
	b, _ := newBudget(t, testLimits)
	for i := 0; i < 2; i++ {
		if err := b.SpendTurn(); err != nil {
			t.Fatalf("turn %d: %v", i, err)
		}
		if err := b.SpendRun(); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	if err := b.SpendTurn(); !IsExhausted(err) {
		t.Fatalf("third turn: err = %v; want exhausted", err)
	}
	if err := b.SpendRun(); !IsExhausted(err) {
		t.Fatalf("third run: err = %v; want exhausted", err)
	}
	if u := b.Usage(); u.Turns != 2 || u.SandboxRuns != 2 {
		t.Fatalf("usage = %+v; a refused spend must not be counted", u)
	}
}

func TestCrossingTheTokenLimitStopsEverything(t *testing.T) {
	b, _ := newBudget(t, testLimits)
	b.AddTokens(400)
	if err := b.Check(); err != nil {
		t.Fatalf("under the limit: %v", err)
	}

	b.AddTokens(700)
	b.AddTokens(-5) // ignored

	if err := b.Check(); !IsExhausted(err) {
		t.Fatalf("Check = %v; want exhausted", err)
	}
	if err := b.SpendTurn(); !IsExhausted(err) {
		t.Fatalf("SpendTurn = %v; want exhausted", err)
	}
	if err := b.SpendRun(); !IsExhausted(err) {
		t.Fatalf("SpendRun = %v; want exhausted", err)
	}
	if got := b.Usage().Tokens; got != 1100 {
		t.Fatalf("tokens = %d; want 1100", got)
	}
}

func TestDurationLimit(t *testing.T) {
	b, c := newBudget(t, testLimits)
	c.advance(59 * time.Second)
	if err := b.Check(); err != nil {
		t.Fatalf("before the deadline: %v", err)
	}
	if got := b.Remaining(); got != time.Second {
		t.Fatalf("Remaining = %v; want 1s", got)
	}

	c.advance(2 * time.Second)

	if err := b.Check(); !IsExhausted(err) || err.Error() != "budget exhausted: duration" {
		t.Fatalf("Check = %v; want duration exhausted", err)
	}
	if got := b.Remaining(); got != 0 {
		t.Fatalf("Remaining = %v; want 0", got)
	}
	if got := b.Usage().Elapsed; got != 61*time.Second {
		t.Fatalf("Elapsed = %v", got)
	}
}

func TestConcurrentSpendingNeverExceedsTheLimit(t *testing.T) {
	limits := Limits{Tokens: 1 << 40, Turns: 50, SandboxRuns: 50, DurationSeconds: 3600}
	b, _ := newBudget(t, limits)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.SpendTurn()
			_ = b.SpendRun()
			b.AddTokens(1)
		}()
	}
	wg.Wait()

	u := b.Usage()
	if u.Turns != 50 || u.SandboxRuns != 50 || u.Tokens != 200 {
		t.Fatalf("usage = %+v", u)
	}
	if b.Limits() != limits {
		t.Fatalf("Limits() = %+v", b.Limits())
	}
}
