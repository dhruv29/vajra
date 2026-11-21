// Package portscan finds TCP services listening on in-scope hosts that the
// operator did not expect.
//
// It never opens connections itself. It is given a dial function, which in
// production goes through the scope-enforcing egress gate, so the gate decides
// which connections are allowed. The check is a bare TCP connect: nothing is
// sent and nothing is read, and the connection is closed at once.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// Source is the value of Finding.Source for results from this package.
	Source = "vajra-portscan"
	// MaxHosts is the most hosts one scan may cover.
	MaxHosts = 64
	// MaxPorts is the most ports tried on every host.
	MaxPorts = 64
	// DefaultConcurrency is how many connection attempts run at once when
	// Options.Concurrency is zero.
	DefaultConcurrency = 8

	ruleUnexpectedPort = "unexpected-open-port"
	targetScheme       = "tcp://"
)

// Dialer opens a TCP connection to "host:port". In production this is a
// SOCKS5 client pointed at the egress gate, so the gate decides whether the
// connection is allowed.
type Dialer func(ctx context.Context, address string) (net.Conn, error)

// Options configures a Scanner.
type Options struct {
	// Hosts are host names or IPs; required, at most MaxHosts.
	Hosts []string
	// Ports are tried on every host; required, each 1-65535, at most MaxPorts.
	Ports []int
	// Expected are the ports the operator expects to be open (e.g. 80, 443);
	// an open port outside this list is reported.
	Expected []int
	// Concurrency bounds the attempts in flight; zero means DefaultConcurrency.
	Concurrency int
	// Timeout bounds each connection attempt; required.
	Timeout time.Duration
	// Refused reports whether an error from the Dialer means the gate refused
	// the connection as out of scope (as opposed to the port being closed).
	// Nil means no error is treated as a refusal.
	Refused func(error) bool
}

// Result is what one scan found.
type Result struct {
	// Open lists "host:port" that accepted a connection, sorted.
	Open []string `json:"open"`
	// Refused lists "host:port" the gate would not allow, sorted.
	Refused []string `json:"refused"`
	// Findings has one candidate per open port that was not expected.
	Findings []finding.Finding `json:"findings"`
}

// Scanner runs connect checks for one configuration.
type Scanner struct {
	dial        Dialer
	jobs        []job
	pairs       map[job]bool
	expected    map[int]bool
	concurrency int
	timeout     time.Duration
	refused     func(error) bool
}

type job struct {
	host string
	port int
}

func (j job) address() string { return net.JoinHostPort(j.host, strconv.Itoa(j.port)) }

type state int

const (
	closed state = iota
	open
	refused
)

// New validates the options and prepares a scanner.
func New(dial Dialer, opts Options) (*Scanner, error) {
	if dial == nil {
		return nil, errors.New("portscan: a dialer is required")
	}
	hosts, err := validHosts(opts.Hosts)
	if err != nil {
		return nil, err
	}
	ports, err := validPorts(opts.Ports)
	if err != nil {
		return nil, err
	}
	expected := map[int]bool{}
	for _, p := range opts.Expected {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("portscan: expected port %d is outside 1-65535", p)
		}
		expected[p] = true
	}
	if opts.Timeout <= 0 {
		return nil, errors.New("portscan: a per-connection timeout is required")
	}
	concurrency := opts.Concurrency
	switch {
	case concurrency < 0:
		return nil, fmt.Errorf("portscan: concurrency %d is negative", concurrency)
	case concurrency == 0:
		concurrency = DefaultConcurrency
	}
	// Hosts sorted by name and ports by number make every result ordered.
	slices.Sort(hosts)
	slices.Sort(ports)
	jobs := make([]job, 0, len(hosts)*len(ports))
	pairs := make(map[job]bool, len(hosts)*len(ports))
	for _, h := range hosts {
		for _, p := range ports {
			j := job{host: h, port: p}
			jobs = append(jobs, j)
			pairs[j] = true
		}
	}
	return &Scanner{
		dial: dial, jobs: jobs, pairs: pairs, expected: expected,
		concurrency: concurrency, timeout: opts.Timeout, refused: opts.Refused,
	}, nil
}

func validHosts(hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, errors.New("portscan: at least one host is required")
	}
	if len(hosts) > MaxHosts {
		return nil, fmt.Errorf("portscan: %d hosts exceed the limit of %d", len(hosts), MaxHosts)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		h := strings.TrimSpace(raw)
		// A port, scheme, path or user name would change what is dialled; an
		// IPv6 address is the only host that may contain a colon.
		if h == "" || strings.ContainsAny(h, "/@[] \t\r\n") ||
			(strings.Contains(h, ":") && net.ParseIP(h) == nil) {
			return nil, fmt.Errorf("portscan: host %q must be a bare host name or IP address", raw)
		}
		if seen[h] {
			return nil, fmt.Errorf("portscan: host %q is listed twice", h)
		}
		seen[h] = true
		out = append(out, h)
	}
	return out, nil
}

func validPorts(ports []int) ([]int, error) {
	if len(ports) == 0 {
		return nil, errors.New("portscan: at least one port is required")
	}
	if len(ports) > MaxPorts {
		return nil, fmt.Errorf("portscan: %d ports exceed the limit of %d", len(ports), MaxPorts)
	}
	seen := map[int]bool{}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("portscan: port %d is outside 1-65535", p)
		}
		if seen[p] {
			return nil, fmt.Errorf("portscan: port %d is listed twice", p)
		}
		seen[p] = true
	}
	return slices.Clone(ports), nil
}

// Run tries every host and port with bounded concurrency. If ctx ends first,
// the scan stops and ctx.Err() is returned.
func (s *Scanner) Run(ctx context.Context) (Result, error) {
	states := make([]state, len(s.jobs))
	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup
dispatch:
	for i, j := range s.jobs {
		select {
		case <-ctx.Done():
			break dispatch
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-sem
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			states[i] = s.attempt(ctx, j.address())
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	res := Result{Open: []string{}, Refused: []string{}, Findings: []finding.Finding{}}
	for i, j := range s.jobs {
		switch states[i] {
		case open:
			res.Open = append(res.Open, j.address())
			if !s.expected[j.port] {
				res.Findings = append(res.Findings, newFinding(j))
			}
		case refused:
			res.Refused = append(res.Refused, j.address())
		}
	}
	return res, nil
}

// attempt connects once and closes the connection immediately.
func (s *Scanner) attempt(ctx context.Context, address string) state {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	conn, err := s.dial(ctx, address)
	if err == nil {
		_ = conn.Close() // a connect check only: nothing is sent or read
		return open
	}
	if s.refused != nil && s.refused(err) {
		return refused
	}
	return closed
}

func newFinding(j job) finding.Finding {
	address := j.address()
	target := targetScheme + address
	return finding.Finding{
		ID:          finding.StableID(Source, ruleUnexpectedPort, target, ""),
		Kind:        finding.Dynamic,
		Source:      Source,
		RuleID:      ruleUnexpectedPort,
		Title:       "Unexpected service listening on " + address,
		Description: "The operator listed the ports expected to be open on this host; this one is open and is not among them.",
		Severity:    finding.SeverityMedium,
		Target:      target,
		CWE:         []string{"cwe-16"},
		Tags:        []string{"network", "exposure"},
		Status:      finding.Candidate,
		Evidence: finding.Evidence{
			Request:   "TCP connect to " + address,
			Response:  "connection accepted",
			MatchedAt: target,
			Extracted: []string{"tcp connect succeeded"},
		},
	}
}

// Reproduce connects to the address behind f again: true if it is still
// open, false if it is closed. A refusal by the gate is an error, as is a
// finding for an address this scanner was not configured to try.
func (s *Scanner) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	j, err := s.parseTarget(f)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	switch s.attempt(ctx, j.address()) {
	case open:
		return true, nil
	case refused:
		return false, fmt.Errorf("portscan: the gate refused the connection to %s, so the finding could not be re-tested", j.address())
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Scanner) parseTarget(f finding.Finding) (job, error) {
	notOurs := fmt.Errorf("portscan: finding %q was not produced by this scanner", f.Target)
	if f.Source != Source {
		return job{}, notOurs
	}
	address, ok := strings.CutPrefix(f.Target, targetScheme)
	if !ok {
		return job{}, notOurs
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return job{}, notOurs
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return job{}, notOurs
	}
	j := job{host: host, port: port}
	if !s.pairs[j] {
		return job{}, notOurs
	}
	return j, nil
}
