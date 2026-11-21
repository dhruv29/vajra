package report

import (
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/topology"
)

const hostile = "<script>alert(1)</script> ![x](https://evil.test/leak) | # **bold**"

func sampleRun(t *testing.T, events []egress.Event) record.Run {
	t.Helper()
	rep := record.Report{
		GeneratedAt:   time.Date(2026, 11, 21, 19, 54, 0, 0, time.UTC),
		Authorization: record.Authorization{Operator: "sec@example.test", Statement: "Approved in CHG-1"},
		Targets:       []string{"https://app.test"},
		Scope:         scope.Config{Hosts: []string{"app.test"}, Ports: []int{443, 8443}},
		Summary:       map[finding.Status]int{finding.Confirmed: 2, finding.Unconfirmed: 1, finding.Refuted: 1},
		Findings: []finding.Finding{
			{ID: "xss", Title: "Reflected XSS", Target: "https://app.test/search", Status: finding.Confirmed,
				Severity: finding.SeverityMedium, CWE: []string{"cwe-79"}, Source: "nuclei", RuleID: "xss-reflect"},
			{ID: "sqli", Title: "SQL injection " + hostile, Target: "https://app.test/orders", Status: finding.Confirmed,
				Severity: finding.SeverityHigh, CWE: []string{"cwe-89"}, Source: "nuclei", RuleID: "sqli-error",
				Evidence: finding.Evidence{
					Request:  "GET /orders?id=1' HTTP/1.1",
					Response: "HTTP/1.1 500\n\n```\n# Injected heading\n" + hostile,
				},
				Verdicts: []finding.Verdict{
					{Stage: "reproduce", Outcome: finding.Pass, Reason: "reproduced 2 of 2 times"},
					{Stage: "refute", Outcome: finding.Pass, Reason: "The error shows the query. " + hostile},
				}},
			{ID: "maybe", Title: "Possible debug page", Target: "https://app.test/debug", Status: finding.Unconfirmed,
				Severity: finding.SeverityLow},
			{ID: "noise", Title: "Generic match", Target: "https://app.test/x", Status: finding.Refuted,
				Severity: finding.SeverityCritical, CWE: []string{"cwe-78"},
				Verdicts: []finding.Verdict{{Stage: "reproduce", Outcome: finding.Fail, Reason: "did not reproduce on attempt 1 of 2"}}},
		},
	}
	decl := topology.Declaration{
		Assets: []topology.DeclaredAsset{{ID: "orders-db", Kind: topology.Datastore, Name: "Orders database", DataClasses: []string{"pii"}}},
		Links:  []topology.DeclaredLink{{From: "app.test", To: "orders-db", Relation: topology.Reads}},
	}
	run, err := record.Build("20261121-195440-0a1b2c3d", rep, decl, events)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

var sampleEvents = []egress.Event{
	{Target: "app.test:443", Allowed: true},
	{Target: "evil.test:443", Reason: "host is not in scope " + hostile},
}

func mustContain(t *testing.T, doc string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestMarkdownCoversTheRunAndOrdersByBlastRadius(t *testing.T) {
	doc := Markdown(sampleRun(t, sampleEvents))

	mustContain(t, doc,
		"# Security test report", "sec@example.test", "Approved in CHG-1",
		"| confirmed | 2 |", "| out of scope | 0 |",
		"### 1. SQL injection", "### 2. Reflected XSS", "### 3. Possible debug page",
		"Orders database", "| datastore | inferred |", "reproduce: **pass**. reproduced 2 of 2 times",
		"## Dismissed results", "| Generic match |", "did not reproduce on attempt 1 of 2",
		"- **Hosts:** app.test", "- **Ports:** 443, 8443", "| Sandbox runs |",
		"1 connection(s) allowed, 1 refused.", "| app.test:443 | allowed | 1 | |",
	)
	if strings.Contains(doc, "### 4.") {
		t.Error("a dismissed result was listed as needing attention")
	}
}

func TestMarkdownNeutralisesHostileText(t *testing.T) {
	doc := Markdown(sampleRun(t, sampleEvents))

	if strings.Contains(doc, "<script>") && !strings.Contains(doc, "````") {
		t.Fatal("raw HTML appears outside a code fence")
	}
	for _, line := range strings.Split(doc, "\n") {
		inline := !strings.HasPrefix(line, "HTTP/") && !strings.HasPrefix(line, "GET ") && line != "# Injected heading" && !strings.HasPrefix(line, "<script>")
		if inline && (strings.Contains(line, "![x](") || strings.Contains(line, "<script>")) {
			t.Errorf("unescaped hostile text on an inline line: %q", line)
		}
	}
	// The response contains a ``` line, so its fence must be longer.
	start := strings.Index(doc, "**Response.**")
	block := doc[start:]
	if !strings.Contains(block, "````\nHTTP/1.1 500") {
		t.Fatalf("the response fence was not lengthened:\n%s", block[:200])
	}
	if !strings.Contains(block, "# Injected heading\n"+hostile+"\n````\n") {
		t.Fatal("the fence does not close after the whole response")
	}
}

func TestFencedOutlastsAnyBacktickRun(t *testing.T) {
	cases := map[string]string{
		"plain":           "```\nplain\n```\n",
		"a ``` inside":    "````\na ``` inside\n````\n",
		"five ````` here": "``````\nfive ````` here\n``````\n",
		"trailing\n\n":    "```\ntrailing\n```\n",
	}
	for input, want := range cases {
		if got := fenced(input); got != want {
			t.Errorf("fenced(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestMarkdownHandlesAnEmptyRunWithoutAnAuditLog(t *testing.T) {
	run, err := record.Build("20261121-195440-0a1b2c3d", record.Report{Summary: map[finding.Status]int{}}, topology.Declaration{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	doc := Markdown(run)

	mustContain(t, doc, "## Findings that need attention\n\nNone.", "## Dismissed results\n\nNone.",
		"- **Hosts:** none", "- **Ports:** none", "No gate audit log was supplied")
}

func TestHTMLIsSelfContainedAndEscapesHostileText(t *testing.T) {
	raw, err := HTML(sampleRun(t, sampleEvents))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	mustContain(t, doc,
		"<title>Security test report 20261121-195440-0a1b2c3d</title>",
		"3 findings need attention", "Orders database", "blast radius / 100",
		`<span class="conf inferred">inferred</span>`, "did not reproduce on attempt 1 of 2",
		"1 connection(s) allowed, 1 refused.", "&lt;script&gt;alert(1)&lt;/script&gt;",
		`default-src 'none'`,
	)
	for _, banned := range []string{"<script", "<img", "<link", "http://", "src=", "@import", "url("} {
		if strings.Contains(doc, banned) {
			t.Errorf("the page contains %q; it must have no scripts or external resources", banned)
		}
	}
	if strings.Index(doc, "SQL injection") > strings.Index(doc, "Reflected XSS") {
		t.Error("findings are not ordered by blast radius")
	}
}

func TestHTMLHeadlineAgreesInNumberAndRoundsTime(t *testing.T) {
	run := sampleRun(t, nil)
	run.Report.Findings = run.Report.Findings[:1]
	run.Report.Budget.Usage.Elapsed = 641080667 * time.Nanosecond

	raw, err := HTML(run)

	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(raw), "1 finding needs attention", "<td>1s</td>")
}

func TestHTMLHandlesAnEmptyRun(t *testing.T) {
	run, _ := record.Build("20261121-195440-0a1b2c3d", record.Report{Summary: map[finding.Status]int{}}, topology.Declaration{}, nil)

	raw, err := HTML(run)

	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(raw), "0 findings need attention", "Nothing was confirmed or left undecided",
		"No scanner result was refuted", "No gate audit log was supplied")
}

func TestLongEvidenceIsClippedInReports(t *testing.T) {
	run := sampleRun(t, nil)
	run.Report.Findings[1].Evidence.Response = strings.Repeat("A", maxEvidenceChars*2)

	doc := Markdown(run)

	if strings.Contains(doc, strings.Repeat("A", maxEvidenceChars+1)) || !strings.Contains(doc, "[truncated in this report") {
		t.Fatal("long evidence was not clipped")
	}
}
