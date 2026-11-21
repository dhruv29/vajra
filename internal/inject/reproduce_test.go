package inject

import (
	"context"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
	"net/url"
)

// findingsFor runs the checker over the vulnerable endpoints.
func findingsFor(t *testing.T) map[string]finding.Finding {
	t.Helper()
	result := run(t, newChecker(t, newApp(), Options{}), host+"/search?q=a", host+"/item?id=1", host+"/go?next=/x")
	out := map[string]finding.Finding{}
	for _, f := range result.Findings {
		out[f.RuleID] = f
	}
	if len(out) != 3 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	return out
}

func TestReproduceConfirmsEachCheckFromEvidenceAlone(t *testing.T) {
	findings := findingsFor(t)
	app := newApp()
	// A fresh checker: nothing is remembered from the run.
	c := newChecker(t, app, Options{Headers: map[string]string{"Cookie": "sid=abc"}})
	for rule, f := range findings {
		app.requests = nil
		ok, err := c.Reproduce(context.Background(), f)
		if err != nil || !ok {
			t.Errorf("%s: reproduce = %v, %v", rule, ok, err)
		}
		if app.requests[len(app.requests)-1].Headers["Cookie"] != "sid=abc" {
			t.Errorf("%s: the checker's headers were not sent", rule)
		}
	}
}

func TestReproduceReportsAFixedFlawAsGone(t *testing.T) {
	findings := findingsFor(t)
	fixed := newApp()
	fixed.routes["/search"] = fixed.routes["/safe-search"]
	fixed.routes["/item"] = func(url.Values, probe.Request) probe.Response { return page("item") }
	fixed.routes["/go"] = func(url.Values, probe.Request) probe.Response { return redirect("/home") }
	c := newChecker(t, fixed, Options{})
	for rule, f := range findings {
		if ok, err := c.Reproduce(context.Background(), f); err != nil || ok {
			t.Errorf("%s: reproduce = %v, %v", rule, ok, err)
		}
	}
}

func TestReproduceTreatsAnUnansweredTargetAsAnError(t *testing.T) {
	findings := findingsFor(t)
	down := newApp()
	down.down = true
	c := newChecker(t, down, Options{})
	for rule, f := range findings {
		if ok, err := c.Reproduce(context.Background(), f); err == nil || ok {
			t.Errorf("%s: reproduce = %v, %v", rule, ok, err)
		}
	}
	failing := newApp()
	failing.err = context.DeadlineExceeded
	if _, err := newChecker(t, failing, Options{}).Reproduce(context.Background(), findings[ruleXSS]); err == nil {
		t.Error("a fetcher error was not returned")
	}
}

func TestReproduceRefusesEvidenceItDidNotMake(t *testing.T) {
	findings := findingsFor(t)
	tamper := map[string]func(f finding.Finding) finding.Finding{
		"another source": func(f finding.Finding) finding.Finding { f.Source = "nuclei"; return f },
		"unknown rule":   func(f finding.Finding) finding.Finding { f.RuleID = "rce"; return f },
		"bad scan input": func(f finding.Finding) finding.Finding { f.Evidence.ScanInput = "ftp://x"; return f },
		"missing param":  func(f finding.Finding) finding.Finding { f.Evidence.Matcher = "nope"; return f },
		"edited marker": func(f finding.Finding) finding.Finding {
			f.Evidence.Extracted = []string{keyMarker + "<script>alert(1)</script>"}
			return f
		},
		"mismatched URL": func(f finding.Finding) finding.Finding {
			f.Evidence.MatchedAt = host + "/search?q=other"
			return f
		},
	}
	app := newApp()
	c := newChecker(t, app, Options{})
	for name, edit := range tamper {
		if ok, err := c.Reproduce(context.Background(), edit(findings[ruleXSS])); err == nil || ok {
			t.Errorf("%s: reproduce = %v, %v", name, ok, err)
		}
	}
	redirectFinding := findings[ruleRedirect]
	redirectFinding.Evidence.Extracted = []string{keyCanary + "evil.example"}
	if _, err := c.Reproduce(context.Background(), redirectFinding); err == nil {
		t.Error("an edited canary host was accepted")
	}
	if len(app.requests) != 0 {
		t.Errorf("tampered findings caused requests: %v", app.urls())
	}
}

func TestReproduceNeverLeavesScope(t *testing.T) {
	findings := findingsFor(t)
	app := newApp()
	c := newChecker(t, app, Options{InScope: func(u string) bool { return !strings.Contains(u, "/item") }})
	if _, err := c.Reproduce(context.Background(), findings[ruleSQLError]); err == nil || len(app.requests) != 0 {
		t.Fatalf("err = %v, requests %v", err, app.urls())
	}
}
