package inject

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

// Evidence is untrusted data. Reproduce only accepts tokens of the exact
// shape Run generates, so an edited finding cannot make it send an arbitrary
// payload or redirect target.
var (
	markerPattern = regexp.MustCompile(`^` + markerPrefix + `[0-9a-f]{` + strconv.Itoa(2*tokenBytes) + `}$`)
	canaryPattern = regexp.MustCompile(`^[0-9a-f]{` + strconv.Itoa(2*tokenBytes) + `}\.` + regexp.QuoteMeta(canaryDomain) + `$`)
)

// Reproduce re-sends the requests recorded in f's evidence, with the
// checker's own headers, and re-applies the same proof rule. It needs nothing
// but the finding, so a finding from an earlier run can be re-tested. A
// target that does not answer is an error, not a miss.
func (c *Checker) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	if f.Source != Source {
		return false, fmt.Errorf("inject: the finding comes from %q, not from this checker", f.Source)
	}
	t, err := targetFor(f)
	if err != nil {
		return false, err
	}
	tc, urls, err := rebuild(f, t)
	if err != nil {
		return false, err
	}
	for _, u := range urls {
		if !c.inScope(u) {
			return false, fmt.Errorf("inject: %s is out of scope, so the finding was not re-tested", u)
		}
	}
	responses, err := c.fetch(ctx, urls)
	if err != nil {
		return false, err
	}
	for i, r := range responses {
		if !r.Answered() {
			return false, fmt.Errorf("inject: %s did not answer, so the finding could not be re-tested", urls[i])
		}
	}
	return rejudge(f.RuleID, tc, responses), nil
}

// rebuild recreates the test case behind f and the URLs to re-send, in the
// order rejudge expects. The rebuilt attack URL must be exactly the one the
// evidence records.
func rebuild(f finding.Finding, t target) (testCase, []string, error) {
	tc := testCase{target: t, marker: extracted(f, keyMarker), canary: extracted(f, keyCanary)}
	var urls []string
	var attack string
	switch f.RuleID {
	case ruleXSS:
		if !markerPattern.MatchString(tc.marker) {
			return tc, nil, fmt.Errorf("inject: the finding's marker %q is not one this checker makes", tc.marker)
		}
		tc.xss = t.with(xssPayload(tc.marker))
		urls, attack = []string{tc.xss}, tc.xss
	case ruleSQLError:
		tc.baseline, tc.quote, tc.doubled = t.with(t.value), t.with(t.value+"'"), t.with(t.value+"''")
		urls, attack = []string{tc.baseline, tc.quote, tc.doubled}, tc.quote
	case ruleRedirect:
		if !canaryPattern.MatchString(tc.canary) {
			return tc, nil, fmt.Errorf("inject: the finding's canary host %q is not one this checker makes", tc.canary)
		}
		tc.redirect = t.with(canaryURL(tc.canary))
		urls, attack = []string{tc.redirect}, tc.redirect
	default:
		return tc, nil, fmt.Errorf("inject: unknown rule %q", f.RuleID)
	}
	if attack != f.Evidence.MatchedAt {
		return tc, nil, fmt.Errorf("inject: the evidence records %q but its parts rebuild %q", f.Evidence.MatchedAt, attack)
	}
	return tc, urls, nil
}

// rejudge applies the rule to responses in the order rebuild listed the URLs.
func rejudge(rule string, tc testCase, responses []probe.Response) bool {
	switch rule {
	case ruleXSS:
		_, ok := findReflection(responses[0], tc.marker)
		return ok
	case ruleSQLError:
		_, ok := judgeSQL(responses[0], responses[1], responses[2])
		return ok
	default:
		_, ok := judgeRedirect(responses[0], tc.canary)
		return ok
	}
}
