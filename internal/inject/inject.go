// Package inject runs Vajra's built-in active checks for the three classic
// input-handling flaws against URLs with query parameters: reflected input
// (cross-site scripting), database errors provoked by a quote (a signal of SQL
// injection) and open redirects.
//
// Every request is a GET through a probe.Fetcher, so it runs in the sandbox
// behind the egress gate like any other traffic. The payloads are benign: a
// random marker wrapped in HTML metacharacters, a single and a doubled quote,
// and a redirect target on a host under .invalid that cannot resolve. Nothing
// sent can read, change or delete data, and the probe never follows a
// redirect, so the canary host is never contacted.
//
// The proof rules are deliberately strict. A false positive costs the
// operator's trust; a missed signal costs one more manual test. When in doubt
// the checker reports nothing.
package inject

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

const (
	// Source is the value of Finding.Source for results from this package.
	Source = "inject"

	ruleXSS      = "reflected-xss"
	ruleSQLError = "sql-error"
	ruleRedirect = "open-redirect"

	// requestIDPrefix starts every request ID; the rest is the position of
	// the request in the run, which keeps IDs unique across batches.
	requestIDPrefix = "inject-"
	// tokenBytes is how much randomness goes into each marker and canary
	// host: enough that a value can only have come from this run's request.
	tokenBytes = 6
)

// Options configures a Checker.
type Options struct {
	// Headers are sent with every request (for example a session). Their
	// values are treated as credentials and never written into evidence.
	Headers map[string]string
	// MaxRequests is a hard cap on the requests one Run may send. It must be
	// positive.
	MaxRequests int
	// InScope says whether a URL may be requested. The caller wires this to
	// the scope policy; the gate enforces it again. It is required.
	InScope func(rawURL string) bool
}

// Result is what one Run did and found.
type Result struct {
	// Findings are candidates, ordered by host, path, parameter and check.
	Findings []finding.Finding `json:"findings"`
	// Tested is the number of distinct (host, path, parameter) combinations
	// whose requests were all sent.
	Tested int `json:"tested"`
	// Untested is the number of combinations left out because MaxRequests
	// would have been exceeded.
	Untested int `json:"untested"`
	// Requests is the number of requests sent.
	Requests int `json:"requests"`
	// Truncated is true when MaxRequests stopped the run before every
	// parameter was tested.
	Truncated bool `json:"truncated"`
	// Unanswered counts requests the target itself did not answer (the gate
	// refused, or the network failed). No check is judged on such a response.
	Unanswered int `json:"unanswered"`
	// Skipped lists input URLs that were not tested: not http(s), carrying
	// credentials, out of scope (themselves or with a payload in place), or
	// looking like they change state. Sorted.
	Skipped []string `json:"skipped"`
}

// Checker runs the checks through the probe.
type Checker struct {
	fetcher     probe.Fetcher
	headers     map[string]string
	maxRequests int
	inScope     func(rawURL string) bool
	// newToken returns fresh random hex. Tests replace it.
	newToken func() (string, error)
}

// New validates the options and prepares a checker.
func New(fetcher probe.Fetcher, opts Options) (*Checker, error) {
	switch {
	case fetcher == nil:
		return nil, errors.New("inject: a fetcher is required")
	case opts.MaxRequests <= 0:
		return nil, errors.New("inject: MaxRequests must be greater than zero")
	case opts.InScope == nil:
		return nil, errors.New("inject: InScope is required")
	}
	for name := range opts.Headers {
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("inject: a header name is empty")
		}
	}
	return &Checker{
		fetcher: fetcher, headers: maps.Clone(opts.Headers), maxRequests: opts.MaxRequests,
		inScope: opts.InScope, newToken: randomToken,
	}, nil
}

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("inject: random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Run tests every distinct (host, path, parameter) found in urls, within the
// request cap. A fetcher error or a cancelled context ends the run; the
// counts so far are returned with the error.
func (c *Checker) Run(ctx context.Context, urls []string) (Result, error) {
	targets, skipped := c.targets(urls)
	result := Result{Findings: []finding.Finding{}, Skipped: skipped}
	p, err := c.plan(targets)
	if err != nil {
		return result, err
	}
	if len(p.outOfScope) > 0 {
		result.Skipped = slices.Compact(slices.Sorted(slices.Values(append(result.Skipped, p.outOfScope...))))
	}
	result.Tested, result.Untested, result.Truncated = len(p.cases), len(targets)-len(p.cases)-p.dropped, p.truncated
	responses, err := c.fetch(ctx, p.urls)
	result.Requests = len(responses)
	if err != nil {
		return result, err
	}
	for _, r := range responses {
		if !r.Answered() {
			result.Unanswered++
		}
	}
	for _, tc := range p.cases {
		result.Findings = append(result.Findings, c.judge(tc, p.lookup(responses))...)
	}
	return result, nil
}

// testCase is one target with the exact URLs sent to test it.
type testCase struct {
	target
	// marker is the random text in the reflection payload; canary is the
	// random host in the redirect payload.
	marker, canary string
	baseline, xss  string
	quote, doubled string
	// redirect is empty when the parameter is not a redirect candidate.
	redirect string
}

// plan holds the URLs to request, each once, and the cases they serve.
type plan struct {
	urls      []string
	index     map[string]int
	cases     []testCase
	truncated bool
	// outOfScope lists the URLs whose payload requests the scope refused,
	// and dropped counts the targets left out for that reason.
	outOfScope []string
	dropped    int
}

// lookup returns a function giving the response for one planned URL.
func (p plan) lookup(responses []probe.Response) func(string) probe.Response {
	return func(u string) probe.Response { return responses[p.index[u]] }
}

// plan builds the requests for each target in order and stops before the
// first target whose requests would exceed the cap: half a test proves
// nothing, so a target is tested whole or not at all. URLs are shared, so a
// baseline request serves every parameter of the same URL.
func (c *Checker) plan(targets []target) (plan, error) {
	p := plan{index: map[string]int{}}
	for _, t := range targets {
		tc, err := c.testCase(t)
		if err != nil {
			return p, err
		}
		// Only the query differs from a URL already in scope, but the scope
		// may look at the query too, so every request is checked.
		if slices.ContainsFunc(tc.urls(), c.outOfScope) {
			p.outOfScope, p.dropped = append(p.outOfScope, t.original), p.dropped+1
			continue
		}
		fresh := p.unplanned(tc.urls())
		if len(p.urls)+len(fresh) > c.maxRequests {
			p.truncated = true
			break
		}
		for _, u := range fresh {
			p.index[u] = len(p.urls)
			p.urls = append(p.urls, u)
		}
		p.cases = append(p.cases, tc)
	}
	return p, nil
}

func (c *Checker) outOfScope(u string) bool { return !c.inScope(u) }

// unplanned returns the URLs not already in the plan, each once.
func (p plan) unplanned(urls []string) []string {
	var out []string
	for _, u := range urls {
		if _, ok := p.index[u]; !ok && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// testCase builds the payload URLs for one target. A target is given its own
// random token so that a payload stored by the application and shown on a
// later page can never be credited to the wrong parameter.
func (c *Checker) testCase(t target) (testCase, error) {
	token, err := c.newToken()
	if err != nil {
		return testCase{}, err
	}
	tc := testCase{target: t, marker: markerPrefix + token, canary: token + "." + canaryDomain}
	tc.baseline = t.with(t.value)
	tc.xss = t.with(xssPayload(tc.marker))
	tc.quote, tc.doubled = t.with(t.value+"'"), t.with(t.value+"''")
	if redirectCandidate(t.param, t.value) {
		tc.redirect = t.with(canaryURL(tc.canary))
	}
	return tc, nil
}

// urls lists the URLs a case needs, in a fixed order.
func (tc testCase) urls() []string {
	out := []string{tc.baseline, tc.xss, tc.quote, tc.doubled}
	if tc.redirect != "" {
		out = append(out, tc.redirect)
	}
	return out
}

// fetch requests every URL, in as few batches as the probe allows.
func (c *Checker) fetch(ctx context.Context, urls []string) ([]probe.Response, error) {
	out := make([]probe.Response, 0, len(urls))
	for start := 0; start < len(urls); start += probe.MaxRequests {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("inject: stopped after %d requests: %w", len(out), err)
		}
		end := min(start+probe.MaxRequests, len(urls))
		chunk := make([]probe.Request, 0, end-start)
		for i, u := range urls[start:end] {
			chunk = append(chunk, c.request(requestIDPrefix+strconv.Itoa(start+i+1), u))
		}
		responses, err := c.fetcher.Do(ctx, chunk)
		if err != nil {
			return out, fmt.Errorf("inject: fetch: %w", err)
		}
		if len(responses) != len(chunk) {
			return out, fmt.Errorf("inject: fetch: %d responses for %d requests", len(responses), len(chunk))
		}
		out = append(out, responses...)
	}
	return out, nil
}

func (c *Checker) request(id, u string) probe.Request {
	return probe.Request{ID: id, Method: http.MethodGet, URL: u, Headers: maps.Clone(c.headers)}
}

// judge applies the three proof rules to one case.
func (c *Checker) judge(tc testCase, get func(string) probe.Response) []finding.Finding {
	var out []finding.Finding
	if r, ok := findReflection(get(tc.xss), tc.marker); ok {
		out = append(out, c.xssFinding(tc, get(tc.xss), r))
	}
	if e, ok := judgeSQL(get(tc.baseline), get(tc.quote), get(tc.doubled)); ok {
		out = append(out, c.sqlFinding(tc, get(tc.quote), e))
	}
	if tc.redirect != "" {
		if location, ok := judgeRedirect(get(tc.redirect), tc.canary); ok {
			out = append(out, c.redirectFinding(tc, get(tc.redirect), location))
		}
	}
	return out
}
