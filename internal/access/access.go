// Package access tests access control: for each protected URL it makes the
// same request as every configured identity and reports when someone who
// should be refused is served.
//
// This is the class of flaw generic scanners miss, because only the operator
// knows who is supposed to see what. The operator states the rule; Vajra
// checks it.
package access

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

const (
	// Source is the value of Finding.Source for results from this package.
	Source = "vajra-access"
	// Anonymous is the built-in identity that sends no credentials.
	Anonymous = "anonymous"

	ruleUnauthenticated = "unauthenticated-access"
	ruleUnauthorized    = "unauthorized-access"
	// similarLengthPercent is how close two body lengths must be for two
	// responses to count as "the same page".
	similarLengthPercent = 15
)

// Identity is one account to test as. Headers holds its credentials.
type Identity struct {
	Name    string
	Headers map[string]string
}

// Check is one access rule: only the identities in Allow may get the
// resource.
type Check struct {
	Name   string
	Method string
	URL    string
	Allow  []string
}

// Checker runs access checks through the probe.
type Checker struct {
	fetcher    probe.Fetcher
	identities []Identity
	checks     []Check
	// byFinding remembers which check and identity produced each finding, so
	// that it can be re-run.
	byFinding map[string]attempt
}

type attempt struct {
	check    Check
	identity Identity
}

var safeMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true}

// NewChecker validates the identities and checks. Only read-only methods are
// accepted: a check is repeated as every identity, so a method that changes
// data would change it several times.
func NewChecker(fetcher probe.Fetcher, identities []Identity, checks []Check) (*Checker, error) {
	if fetcher == nil {
		return nil, errors.New("access: a fetcher is required")
	}
	known := map[string]bool{Anonymous: true}
	all := []Identity{{Name: Anonymous}}
	for _, id := range identities {
		if strings.TrimSpace(id.Name) == "" || known[id.Name] {
			return nil, fmt.Errorf("access: identity name %q is empty, reserved or repeated", id.Name)
		}
		if len(id.Headers) == 0 {
			return nil, fmt.Errorf("access: identity %q has no credentials", id.Name)
		}
		known[id.Name] = true
		all = append(all, id)
	}
	names := map[string]bool{}
	normalized := make([]Check, 0, len(checks))
	for _, c := range checks {
		if c.Method == "" {
			c.Method = http.MethodGet
		}
		c.Method = strings.ToUpper(c.Method)
		if strings.TrimSpace(c.Name) == "" || names[c.Name] {
			return nil, fmt.Errorf("access: check name %q is empty or repeated", c.Name)
		}
		if !safeMethods[c.Method] {
			return nil, fmt.Errorf("access: check %q uses %s; only GET, HEAD and OPTIONS are tested", c.Name, c.Method)
		}
		for _, allowed := range c.Allow {
			if !known[allowed] {
				return nil, fmt.Errorf("access: check %q allows unknown identity %q", c.Name, allowed)
			}
		}
		names[c.Name] = true
		normalized = append(normalized, c)
	}
	return &Checker{fetcher: fetcher, identities: all, checks: normalized, byFinding: map[string]attempt{}}, nil
}

// SecretHeaders lists the header names that carry credentials, for redaction.
func (c *Checker) SecretHeaders() []string {
	set := map[string]bool{}
	for _, id := range c.identities {
		for name := range id.Headers {
			set[name] = true
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Run performs every check as every identity and returns a candidate finding
// for each identity that was served something it is not allowed.
func (c *Checker) Run(ctx context.Context) ([]finding.Finding, error) {
	if len(c.checks) == 0 {
		return []finding.Finding{}, nil
	}
	var requests []probe.Request
	for ci, check := range c.checks {
		for ii, id := range c.identities {
			requests = append(requests, c.request(fmt.Sprintf("%d/%d", ci, ii), check, id))
		}
	}
	responses, err := c.fetchAll(ctx, requests)
	if err != nil {
		return nil, err
	}
	findings := []finding.Finding{}
	for ci, check := range c.checks {
		row := responses[ci*len(c.identities) : (ci+1)*len(c.identities)]
		findings = append(findings, c.judge(check, row)...)
	}
	return findings, nil
}

func (c *Checker) request(id string, check Check, identity Identity) probe.Request {
	return probe.Request{ID: id, Method: check.Method, URL: check.URL, Headers: identity.Headers}
}

func (c *Checker) fetchAll(ctx context.Context, requests []probe.Request) ([]probe.Response, error) {
	out := make([]probe.Response, 0, len(requests))
	for start := 0; start < len(requests); start += probe.MaxRequests {
		end := min(start+probe.MaxRequests, len(requests))
		responses, err := c.fetcher.Do(ctx, requests[start:end])
		if err != nil {
			return nil, fmt.Errorf("access: %w", err)
		}
		out = append(out, responses...)
	}
	return out, nil
}

// judge compares what each identity got for one check.
func (c *Checker) judge(check Check, row []probe.Response) []finding.Finding {
	allowed := map[string]bool{}
	for _, name := range check.Allow {
		allowed[name] = true
	}
	baseline, baselineName := probe.Response{}, ""
	for i, id := range c.identities {
		if allowed[id.Name] && served(row[i]) {
			baseline, baselineName = row[i], id.Name
			break
		}
	}
	var out []finding.Finding
	for i, id := range c.identities {
		if allowed[id.Name] || !served(row[i]) {
			continue
		}
		f := c.finding(check, id, row[i], baseline, baselineName)
		c.byFinding[f.ID] = attempt{check: check, identity: id}
		out = append(out, f)
	}
	return out
}

// served reports whether the target answered with the resource itself, as
// opposed to refusing, redirecting to a login page or not answering.
func served(r probe.Response) bool {
	return r.Answered() && r.Status >= 200 && r.Status < 300
}

func (c *Checker) finding(check Check, id Identity, got, baseline probe.Response, baselineName string) finding.Finding {
	rule, cwe, who := ruleUnauthorized, "cwe-862", "the account \""+id.Name+"\""
	if id.Name == Anonymous {
		rule, cwe, who = ruleUnauthenticated, "cwe-306", "a visitor who is not signed in"
	}
	comparison := "No allowed account was served this resource, so there is nothing to compare the response with."
	if baselineName != "" {
		comparison = fmt.Sprintf("Compared with the allowed account %q (HTTP %d, %d bytes): %s.",
			baselineName, baseline.Status, len(baseline.Body), similarity(got, baseline))
	}
	return finding.Finding{
		ID:     finding.StableID(Source, rule, check.Method+" "+check.URL, id.Name),
		Kind:   finding.Dynamic,
		Source: Source,
		RuleID: rule,
		Title:  fmt.Sprintf("%s is served to %s", check.Name, who),
		Description: fmt.Sprintf("The access rule for %q allows only: %s. The request below, sent as %s, was answered with HTTP %d.",
			check.Name, describeAllow(check.Allow), who, got.Status),
		Severity: finding.SeverityHigh,
		Target:   check.URL,
		CWE:      []string{cwe},
		Tags:     []string{"access-control"},
		Status:   finding.Candidate,
		Evidence: finding.Evidence{
			Request:   probe.FormatRequest(c.request("", check, id), c.SecretHeaders()),
			Response:  probe.FormatResponse(got),
			MatchedAt: check.URL,
			Matcher:   id.Name,
			Extracted: []string{comparison},
		},
	}
}

func describeAllow(allow []string) string {
	if len(allow) == 0 {
		return "nobody"
	}
	return strings.Join(allow, ", ")
}

// similarity says, in words, how alike two responses are. Identical bodies
// are strong evidence the protected resource itself was served; a very
// different body may be a generic page.
func similarity(a, b probe.Response) string {
	if sha256.Sum256([]byte(a.Body)) == sha256.Sum256([]byte(b.Body)) {
		return "the bodies are identical"
	}
	longer, shorter := max(len(a.Body), len(b.Body)), min(len(a.Body), len(b.Body))
	if longer == 0 || (longer-shorter)*100/longer <= similarLengthPercent {
		return "the bodies differ but are about the same size"
	}
	return "the bodies are clearly different, so this may be a generic page rather than the resource"
}

// Reproduce repeats the request behind f and reports whether it is still
// served. A target that does not answer is an error, not a miss.
func (c *Checker) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	a, ok := c.byFinding[f.ID]
	if !ok {
		return false, errors.New("access: this finding did not come from a check in the current configuration")
	}
	responses, err := c.fetcher.Do(ctx, []probe.Request{c.request("retest", a.check, a.identity)})
	if err != nil {
		return false, fmt.Errorf("access: %w", err)
	}
	if !responses[0].Answered() {
		return false, fmt.Errorf("access: %s did not answer, so the finding could not be re-tested", a.check.URL)
	}
	return served(responses[0]), nil
}
