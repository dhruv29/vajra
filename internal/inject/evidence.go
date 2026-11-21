package inject

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
	"github.com/dhruv29/vajra/internal/redact"
)

const (
	// evidenceContext is how many bytes of body are kept on each side of the
	// part of a response that proves a finding.
	evidenceContext = 300
	// redirectBodyBytes is how much of a redirect's body is kept; the proof is
	// in the status and the Location header.
	redirectBodyBytes = 300
	clipNote          = "[clipped by Vajra]"

	// Prefixes of the Evidence.Extracted lines that Reproduce reads back.
	keyMarker  = "marker: "
	keyCanary  = "canary host: "
	keyContext = "context: "
)

// secretNames lists the configured header names, for redaction.
func (c *Checker) secretNames() []string {
	return slices.Sorted(maps.Keys(c.headers))
}

// scrub removes every configured credential from captured text, by header
// name and by value, so a target that echoes a header cannot leak it.
func (c *Checker) scrub(text string) string {
	values := make([]string, 0, len(c.headers))
	for _, v := range c.headers {
		values = append(values, v)
	}
	return redact.Values(redact.Headers(text, c.secretNames()...), values...)
}

// base fills in what every finding from this package shares. The ID depends
// only on the check, host, path and parameter, so the same flaw found through
// a different URL or in a later run keeps its ID.
func (c *Checker) base(rule string, tc testCase, attackURL string, resp probe.Response, start, end int) finding.Finding {
	asset := ""
	if u, ok := testable(tc.original); ok {
		asset = u.Scheme + "://" + u.Host
	}
	return finding.Finding{
		ID:       finding.StableID(Source, rule, tc.host+tc.path, tc.param),
		Kind:     finding.Dynamic,
		Source:   Source,
		RuleID:   rule,
		Target:   attackURL,
		AssetURL: asset,
		Status:   finding.Candidate,
		Evidence: finding.Evidence{
			Request:   c.scrub(probe.FormatRequest(c.request("", attackURL), c.secretNames())),
			Response:  c.scrub(probe.FormatResponse(clipBody(resp, start, end))),
			MatchedAt: attackURL,
			ScanInput: tc.original,
			Matcher:   tc.param,
		},
	}
}

func (c *Checker) xssFinding(tc testCase, resp probe.Response, r reflection) finding.Finding {
	f := c.base(ruleXSS, tc, tc.xss, resp, r.at-evidenceContext, r.at+regionLen(tc.marker)+evidenceContext)
	f.Title = fmt.Sprintf("Reflected cross-site scripting in parameter %q", tc.param)
	f.Description = fmt.Sprintf("The parameter %q was set to a random marker wrapped in HTML metacharacters. "+
		"The HTML response returned it in a %s context with the character that escapes that context unencoded, "+
		"so a crafted link can make this page run script in a visitor's browser. "+
		"No script was sent; the payload only proves the characters are not encoded.", tc.param, r.context)
	f.Severity = finding.SeverityHigh
	f.CWE = []string{"cwe-79"}
	f.Tags = []string{"xss", "injection", "reflected"}
	f.Evidence.Extracted = []string{keyMarker + tc.marker, keyContext + r.context}
	return f
}

func (c *Checker) sqlFinding(tc testCase, resp probe.Response, e dbError) finding.Finding {
	f := c.base(ruleSQLError, tc, tc.quote, resp, e.at-evidenceContext, e.at+len(e.matched)+evidenceContext)
	f.Title = fmt.Sprintf("Database error provoked by a quote in parameter %q", tc.param)
	f.Description = fmt.Sprintf("Shown: adding one single quote to the parameter %q made the response contain a %s "+
		"error message, while the original value and the value with a doubled quote ('') produced no database error "+
		"message. An error that follows the balance of quotes means the input reaches an SQL parser without being "+
		"escaped, which is a strong signal of SQL injection. Not shown: that data can be read or changed; no "+
		"exploitation was attempted and only quotes were sent.", tc.param, e.database)
	f.Severity = finding.SeverityMedium
	f.CWE = []string{"cwe-89"}
	f.Tags = []string{"sqli", "injection", "error-based"}
	f.Evidence.Extracted = []string{
		"database: " + e.database,
		"signature: " + e.matched,
		"baseline (original value): " + tc.baseline + " (no database error)",
		"doubled quote: " + tc.doubled + " (no database error)",
	}
	return f
}

func (c *Checker) redirectFinding(tc testCase, resp probe.Response, location string) finding.Finding {
	f := c.base(ruleRedirect, tc, tc.redirect, resp, 0, redirectBodyBytes)
	f.Title = fmt.Sprintf("Open redirect through parameter %q", tc.param)
	f.Description = fmt.Sprintf("Setting the parameter %q to a URL on a random host under the reserved .invalid "+
		"domain made the server answer with HTTP %d and a Location header pointing at exactly that host. "+
		"A link to this site can therefore send visitors anywhere, which lends the site's name to phishing. "+
		"The redirect was not followed.", tc.param, resp.Status)
	f.Severity = finding.SeverityLow
	f.CWE = []string{"cwe-601"}
	f.Tags = []string{"open-redirect", "redirect"}
	f.Evidence.Extracted = []string{keyCanary + tc.canary, "location: " + location}
	return f
}

// clipBody keeps only body[start:end] (bounded to the body and never cutting
// a character in half) and notes what was left out.
func clipBody(r probe.Response, start, end int) probe.Response {
	body := r.Body
	start, end = max(0, start), min(len(body), max(end, 0))
	for start > 0 && start < len(body) && !utf8.RuneStart(body[start]) {
		start--
	}
	for end < len(body) && end > 0 && !utf8.RuneStart(body[end]) {
		end--
	}
	if start >= end {
		start, end = 0, 0
	}
	clipped := body[start:end]
	if start > 0 {
		clipped = clipNote + "\n" + clipped
	}
	if end < len(body) {
		clipped += "\n" + clipNote
	}
	r.Body = clipped
	return r
}

// extracted returns the value of the Extracted line that starts with key.
func extracted(f finding.Finding, key string) string {
	for _, line := range f.Evidence.Extracted {
		if value, ok := strings.CutPrefix(line, key); ok {
			return value
		}
	}
	return ""
}

// targetFor rebuilds the target a finding was made from, using only its
// evidence.
func targetFor(f finding.Finding) (target, error) {
	u, ok := testable(f.Evidence.ScanInput)
	if !ok {
		return target{}, fmt.Errorf("inject: the finding's scan input %q is not a testable URL", f.Evidence.ScanInput)
	}
	for _, p := range params(u.RawQuery) {
		if p.name == f.Evidence.Matcher {
			return target{
				original: strings.TrimSpace(f.Evidence.ScanInput), host: strings.ToLower(u.Host),
				path: u.Path, param: p.name, value: p.value,
			}, nil
		}
	}
	return target{}, fmt.Errorf("inject: parameter %q is not in the finding's scan input", f.Evidence.Matcher)
}
