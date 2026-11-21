package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
)

var errRefused = errors.New("gate: out of scope")

// fakeNet answers dials from a table: "open", "refused", or anything else
// (including absent) means closed. Open dials hand back one end of a
// net.Pipe and keep the other end so the test can check it was closed.
type fakeNet struct {
	mu       sync.Mutex
	table    map[string]string
	peers    []net.Conn
	dialed   []string
	inFlight atomic.Int32
	maxSeen  atomic.Int32
	delay    time.Duration
	// onDial, when set, runs at the start of every dial.
	onDial func(ctx context.Context)
}

func (f *fakeNet) dial(ctx context.Context, address string) (net.Conn, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		seen := f.maxSeen.Load()
		if n <= seen || f.maxSeen.CompareAndSwap(seen, n) {
			break
		}
	}
	if f.onDial != nil {
		f.onDial(ctx)
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialed = append(f.dialed, address)
	switch f.table[address] {
	case "open":
		client, server := net.Pipe()
		f.peers = append(f.peers, server)
		return client, nil
	case "refused":
		return nil, errRefused
	default:
		return nil, errors.New("connection refused")
	}
}

func isRefused(err error) bool { return errors.Is(err, errRefused) }

func opts(hosts []string, ports []int, expected ...int) Options {
	return Options{Hosts: hosts, Ports: ports, Expected: expected, Timeout: time.Second, Refused: isRefused}
}

func scan(t *testing.T, f *fakeNet, o Options) Result {
	t.Helper()
	s, err := New(f.dial, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func TestClassificationAndFindings(t *testing.T) {
	f := &fakeNet{table: map[string]string{
		"web.test:80": "open", "web.test:443": "open", "web.test:8080": "open", "web.test:22": "refused",
		"10.0.0.5:8080": "open", "10.0.0.5:443": "refused",
	}}
	res := scan(t, f, opts([]string{"web.test", "10.0.0.5"}, []int{8080, 443, 80, 22}, 80, 443))

	// Sorted by host, then numerically by port.
	wantOpen := []string{"10.0.0.5:8080", "web.test:80", "web.test:443", "web.test:8080"}
	if !slices.Equal(res.Open, wantOpen) {
		t.Errorf("open = %v, want %v", res.Open, wantOpen)
	}
	if want := []string{"10.0.0.5:443", "web.test:22"}; !slices.Equal(res.Refused, want) {
		t.Errorf("refused = %v, want %v", res.Refused, want)
	}
	if len(f.dialed) != 8 {
		t.Errorf("dialed %d addresses, want 8", len(f.dialed))
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	got := res.Findings[0]
	target := "tcp://10.0.0.5:8080"
	want := finding.Finding{
		ID: finding.StableID(Source, ruleUnexpectedPort, target, ""), Kind: finding.Dynamic, Source: Source,
		RuleID: ruleUnexpectedPort, Title: "Unexpected service listening on 10.0.0.5:8080",
		Description: "The operator listed the ports expected to be open on this host; this one is open and is not among them.",
		Severity:    finding.SeverityMedium, Target: target, CWE: []string{"cwe-16"}, Tags: []string{"network", "exposure"},
		Status: finding.Candidate,
		Evidence: finding.Evidence{Request: "TCP connect to 10.0.0.5:8080", Response: "connection accepted",
			MatchedAt: target, Extracted: []string{"tcp connect succeeded"}},
	}
	if !equalFinding(got, want) {
		t.Errorf("finding =\n%+v\nwant\n%+v", got, want)
	}
	if res.Findings[1].Target != "tcp://web.test:8080" {
		t.Errorf("second finding = %s", res.Findings[1].Target)
	}

	// Every open connection was closed and nothing was written to it.
	for _, peer := range f.peers {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("peer read = %d, %v; want closed with nothing sent", n, err)
		}
	}
	if len(f.peers) != 4 {
		t.Errorf("peers = %d", len(f.peers))
	}
}

func equalFinding(a, b finding.Finding) bool {
	return a.ID == b.ID && a.Kind == b.Kind && a.Source == b.Source && a.RuleID == b.RuleID && a.Title == b.Title &&
		a.Description == b.Description && a.Severity == b.Severity && a.Target == b.Target && a.Status == b.Status &&
		slices.Equal(a.CWE, b.CWE) && slices.Equal(a.Tags, b.Tags) && a.Evidence.Request == b.Evidence.Request &&
		a.Evidence.Response == b.Evidence.Response && a.Evidence.MatchedAt == b.Evidence.MatchedAt &&
		slices.Equal(a.Evidence.Extracted, b.Evidence.Extracted)
}

func TestNilRefusedTreatsEverythingAsClosed(t *testing.T) {
	f := &fakeNet{table: map[string]string{"h.test:22": "refused"}}
	o := opts([]string{"h.test"}, []int{22})
	o.Refused = nil
	res := scan(t, f, o)
	if len(res.Refused) != 0 || len(res.Open) != 0 || len(res.Findings) != 0 {
		t.Errorf("result = %+v", res)
	}
	if res.Open == nil || res.Refused == nil || res.Findings == nil {
		t.Error("empty lists should be non-nil so they encode as []")
	}
}

func TestIPv6Formatting(t *testing.T) {
	f := &fakeNet{table: map[string]string{"[2001:db8::1]:8443": "open"}}
	res := scan(t, f, opts([]string{"2001:db8::1"}, []int{8443}))
	if !slices.Equal(res.Open, []string{"[2001:db8::1]:8443"}) || len(res.Findings) != 1 {
		t.Fatalf("result = %+v", res)
	}
	got := res.Findings[0]
	if got.Target != "tcp://[2001:db8::1]:8443" || got.Title != "Unexpected service listening on [2001:db8::1]:8443" ||
		got.Evidence.Request != "TCP connect to [2001:db8::1]:8443" {
		t.Errorf("finding = %+v", got)
	}
}

func TestConcurrencyBound(t *testing.T) {
	hosts := []string{"a.test", "b.test", "c.test", "d.test"}
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8}
	for _, limit := range []int{1, 3} {
		f := &fakeNet{delay: 2 * time.Millisecond}
		o := opts(hosts, ports)
		o.Concurrency = limit
		scan(t, f, o)
		if got := int(f.maxSeen.Load()); got > limit || got < 1 {
			t.Errorf("limit %d: max in flight = %d", limit, got)
		}
		if len(f.dialed) != 32 {
			t.Errorf("dialed %d", len(f.dialed))
		}
	}
	f := &fakeNet{delay: 2 * time.Millisecond}
	scan(t, f, opts(hosts, ports))
	if got := int(f.maxSeen.Load()); got > DefaultConcurrency {
		t.Errorf("default: max in flight = %d", got)
	}
}

func TestTimeoutPerAttempt(t *testing.T) {
	var mu sync.Mutex
	var remaining []time.Duration
	f := &fakeNet{onDial: func(ctx context.Context) {
		deadline, ok := ctx.Deadline()
		mu.Lock()
		defer mu.Unlock()
		if !ok {
			remaining = append(remaining, -1)
			return
		}
		remaining = append(remaining, time.Until(deadline))
	}}
	o := opts([]string{"h.test"}, []int{1, 2})
	o.Timeout = 250 * time.Millisecond
	scan(t, f, o)
	if len(remaining) != 2 {
		t.Fatalf("dials = %d", len(remaining))
	}
	for _, r := range remaining {
		if r <= 0 || r > o.Timeout {
			t.Errorf("deadline in %v, want within (0, %v]", r, o.Timeout)
		}
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	f := &fakeNet{onDial: func(context.Context) {
		if calls.Add(1) == 2 {
			cancel()
		}
	}}
	o := opts([]string{"h.test"}, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	o.Concurrency = 1
	s, err := New(f.dial, o)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if len(res.Open)+len(res.Findings) != 0 {
		t.Errorf("result = %+v", res)
	}
	if n := calls.Load(); n >= 10 {
		t.Errorf("scan did not stop: %d dials", n)
	}
}

func TestDeterministic(t *testing.T) {
	table := map[string]string{}
	hosts := []string{"z.test", "a.test", "m.test"}
	ports := []int{9000, 80, 22, 443, 8080}
	for _, h := range hosts {
		for _, p := range ports {
			table[net.JoinHostPort(h, itoa(p))] = "open"
		}
	}
	first := scan(t, &fakeNet{table: table}, opts(hosts, ports))
	if first.Open[0] != "a.test:22" || first.Open[4] != "a.test:9000" {
		t.Errorf("open not sorted by host then port: %v", first.Open)
	}
	for range 5 {
		again := scan(t, &fakeNet{table: table}, opts(hosts, ports))
		if !slices.Equal(again.Open, first.Open) || len(again.Findings) != len(first.Findings) {
			t.Fatal("results differ between runs")
		}
		for i := range again.Findings {
			if again.Findings[i].ID != first.Findings[i].ID {
				t.Fatal("finding order differs between runs")
			}
		}
	}
}

func itoa(p int) string { return strconv.Itoa(p) }

func TestNewValidation(t *testing.T) {
	f := &fakeNet{}
	good := opts([]string{"h.test"}, []int{80})
	many := func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = i + 1
		}
		return out
	}
	manyHosts := make([]string, MaxHosts+1)
	for i := range manyHosts {
		manyHosts[i] = "h" + itoa(i) + ".test"
	}
	cases := map[string]func(o *Options){
		"no hosts":           func(o *Options) { o.Hosts = nil },
		"no ports":           func(o *Options) { o.Ports = nil },
		"port zero":          func(o *Options) { o.Ports = []int{0} },
		"port too high":      func(o *Options) { o.Ports = []int{65536} },
		"duplicate port":     func(o *Options) { o.Ports = []int{80, 80} },
		"too many ports":     func(o *Options) { o.Ports = many(MaxPorts + 1) },
		"too many hosts":     func(o *Options) { o.Hosts = manyHosts },
		"expected bad":       func(o *Options) { o.Expected = []int{70000} },
		"zero timeout":       func(o *Options) { o.Timeout = 0 },
		"negative conc":      func(o *Options) { o.Concurrency = -1 },
		"empty host":         func(o *Options) { o.Hosts = []string{" "} },
		"duplicate host":     func(o *Options) { o.Hosts = []string{"h.test", "h.test"} },
		"host with port":     func(o *Options) { o.Hosts = []string{"h.test:80"} },
		"host with scheme":   func(o *Options) { o.Hosts = []string{"http://h.test"} },
		"host with path":     func(o *Options) { o.Hosts = []string{"h.test/x"} },
		"bracketed ipv6":     func(o *Options) { o.Hosts = []string{"[::1]"} },
		"ipv6 with port":     func(o *Options) { o.Hosts = []string{"[::1]:80"} },
		"host with space":    func(o *Options) { o.Hosts = []string{"h test"} },
		"host with userinfo": func(o *Options) { o.Hosts = []string{"u@h.test"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := good
			mutate(&o)
			if _, err := New(f.dial, o); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := New(nil, good); err == nil {
		t.Error("nil dialer accepted")
	}
	ok := good
	ok.Hosts = []string{"10.0.0.1", "::1", " web.test "}
	ok.Ports = many(MaxPorts)
	if _, err := New(f.dial, ok); err != nil {
		t.Errorf("valid options rejected: %v", err)
	}
}

func TestReproduce(t *testing.T) {
	f := &fakeNet{table: map[string]string{"h.test:8080": "open", "[::1]:9000": "open"}}
	s, err := New(f.dial, opts([]string{"h.test", "::1"}, []int{8080, 9000}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Run(context.Background())
	if err != nil || len(res.Findings) != 2 {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	ctx := context.Background()
	for _, fd := range res.Findings {
		if got, err := s.Reproduce(ctx, fd); err != nil || !got {
			t.Errorf("%s: Reproduce = %v, %v", fd.Target, got, err)
		}
	}

	f.mu.Lock()
	f.table["h.test:8080"] = "closed"
	f.table["[::1]:9000"] = "refused"
	f.mu.Unlock()
	v6, v4 := res.Findings[0], res.Findings[1]
	if got, err := s.Reproduce(ctx, v4); err != nil || got {
		t.Errorf("closed: Reproduce = %v, %v", got, err)
	}
	if _, err := s.Reproduce(ctx, v6); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("refused: err = %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Reproduce(cancelled, v4); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v", err)
	}

	foreign := []finding.Finding{
		{Source: "other", Target: "tcp://h.test:8080"},
		{Source: Source, Target: "http://h.test:8080"},
		{Source: Source, Target: "tcp://h.test"},
		{Source: Source, Target: "tcp://h.test:http"},
		{Source: Source, Target: "tcp://h.test:22"},
		{Source: Source, Target: "tcp://other.test:8080"},
	}
	for _, fd := range foreign {
		if _, err := s.Reproduce(ctx, fd); err == nil {
			t.Errorf("%+v: want error", fd)
		}
	}
}
