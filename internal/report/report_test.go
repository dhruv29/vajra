package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/osv"
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

func TestReportsShowCodeFindingsWithTheirPath(t *testing.T) {
	run := sampleRun(t, nil)
	run.Report.SourceRoot = "/srv/shop"
	run.Report.Targets = nil
	run.Report.Findings[1] = finding.Finding{
		ID: "sqli", Kind: finding.Static, Title: "tainted sql string", Target: "app/views.py:4", Status: finding.Confirmed,
		Severity: finding.SeverityHigh, Source: "semgrep", RuleID: "rules.sqli", Description: "Input reaches a query. " + hostile,
		Location: &finding.Location{File: "app/views.py", Line: 4},
		Evidence: finding.Evidence{
			Code: ">     4 |     return db.execute(query)  # ``` " + hostile + "\n",
			Trace: []finding.TraceStep{
				{Role: "source", File: "app/views.py", Line: 2, Content: "request.args.get('id')"},
				{Role: "sink", File: "app/views.py", Line: 4, Content: "db.execute(query) " + hostile},
			},
		},
	}

	doc := Markdown(run)
	raw, err := HTML(run)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)

	mustContain(t, doc, "- **Source analysed:** /srv/shop", "- **Targets:** none", "**Code.**", "````\n>     4 |",
		"| source | app/views.py:2 | request.args.get('id') |", "| sink | app/views.py:4 |", "Input reaches a query.")
	mustContain(t, page, "<dt>Source analysed</dt><dd>/srv/shop</dd>", "<summary>Code</summary>", "db.execute(query)",
		"<td>source</td><td>app/views.py:2</td>", "Input reaches a query.")
	if strings.Contains(page, "<script") || strings.Contains(page, "<img") {
		t.Fatal("hostile text in a code finding reached the HTML unescaped")
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| sink") && (strings.Contains(line, "<script>") || strings.Contains(line, "![x](")) {
			t.Fatalf("unescaped hostile text in the path table: %q", line)
		}
	}
}

// hostileMD is how the hostile string must appear when written inline.
const hostileMD = `&lt;script&gt;alert(1)&lt;/script&gt; \!\[x\](https://evil.test/leak) \| \# \*\*bold\*\*`

// quietRun is the sample run without the evidence that puts hostile text
// inside code fences, so any hostile text left in a report is inline.
func quietRun(t *testing.T) record.Run {
	t.Helper()
	run := sampleRun(t, nil)
	run.Report.Findings[1].Evidence = finding.Evidence{}
	return run
}

// render returns both formats and fails on anything that would let the
// hostile string act as markup in either.
func render(t *testing.T, run record.Run) (doc, page string) {
	t.Helper()
	doc = Markdown(run)
	raw, err := HTML(run)
	if err != nil {
		t.Fatal(err)
	}
	page = string(raw)
	for _, line := range strings.Split(doc, "\n") {
		for _, raw := range []string{"<script>", "![x](", "| # **bold**", " **bold**"} {
			if strings.Contains(line, raw) {
				t.Errorf("unescaped hostile text %q in Markdown line %q", raw, line)
			}
		}
	}
	for _, banned := range []string{"<script", "<img", "<link", "http://", "src=", "@import", "url("} {
		if strings.Contains(page, banned) {
			t.Errorf("the page contains %q", banned)
		}
	}
	return doc, page
}

func mustNotContain(t *testing.T, doc string, unwanted ...string) {
	t.Helper()
	for _, s := range unwanted {
		if strings.Contains(doc, s) {
			t.Errorf("unexpected %q", s)
		}
	}
}

func hostileChains() []blast.Chain {
	return []blast.Chain{
		{
			Steps: []blast.Step{
				{FindingID: "xss", Title: "Leaked key " + hostile, Capability: blast.CredentialExposure,
					Why: "The chain starts here. " + hostile},
				{FindingID: "sqli", Capability: blast.DataAccess, Why: "The previous step reaches the orders service."},
			},
			Reach: []string{"a", "b"}, DataClasses: []string{"pii", "class " + hostile}, Score: 88,
			Summary: "2 findings combine. " + hostile,
		},
		{
			Steps: []blast.Step{{FindingID: "a", Title: "First"}, {FindingID: "b", Title: "Second"}},
			Score: 41, Summary: "A chain that reaches no classified data.", DataClasses: []string{},
		},
	}
}

func TestReportsShowAttackChainsBetweenTheSummaryAndTheFindings(t *testing.T) {
	run := quietRun(t)
	run.Chains = hostileChains()

	doc, page := render(t, run)

	mustContain(t, doc,
		"## Attack chains", "### Chain 1: score 88 / 100", "2 findings combine. "+hostileMD,
		"| Step | Finding | Capability | Why |",
		"| 1 | Leaked key "+hostileMD+" | credential exposure | The chain starts here. "+hostileMD+" |",
		"| 2 | sqli | data access | The previous step reaches the orders service. |",
		"**Data classes reached:** pii, class "+hostileMD,
		"### Chain 2: score 41 / 100", "**Data classes reached:** none",
	)
	if summary, chains, attention := strings.Index(doc, "## Summary"), strings.Index(doc, "## Attack chains"),
		strings.Index(doc, "## Findings that need attention"); !(summary < chains && chains < attention) {
		t.Errorf("Markdown order: summary %d, chains %d, findings %d", summary, chains, attention)
	}

	mustContain(t, page,
		`<h2 id="chains">Attack chains</h2>`, "<h3>Chain 1</h3>", "<b>88</b><span>chain score / 100</span>",
		"<strong>Leaked key &lt;script&gt;alert(1)&lt;/script&gt;", `<span class="tag">credential exposure</span>`,
		"<strong>sqli</strong>", `<span class="tag">data access</span>`, "<p>The previous step reaches the orders service.</p>",
		"Data classes reached: pii, class &lt;script&gt;", "<h3>Chain 2</h3>", "Data classes reached: none",
	)
	if counts, chains, attention := strings.Index(page, `class="counts"`), strings.Index(page, `id="chains"`),
		strings.Index(page, `id="attention"`); !(counts < chains && chains < attention) {
		t.Errorf("HTML order: counts %d, chains %d, findings %d", counts, chains, attention)
	}
}

func TestReportsLeaveOutSectionsWithNothingToShow(t *testing.T) {
	doc, page := render(t, quietRun(t))

	mustNotContain(t, doc, "Attack chains", "What else the run did", "Corroborated by", "Autonomous explorer")
	mustNotContain(t, page, `id="chains"`, "Attack chains", "What else the run did", "Corroborated by", "Autonomous explorer")
	mustContain(t, doc, "No gate audit log was supplied")
}

func TestReportsLabelTheKindAndNameCorroboratingFindings(t *testing.T) {
	run := quietRun(t)
	f := run.Report.Findings
	f[0].Kind, f[0].CorroboratedBy = finding.Dynamic, []string{"sqli", "missing-id", "maybe"}
	f[1].Kind, f[1].CorroboratedBy = finding.Static, []string{"gone"}
	f[2].Kind = finding.Dependency
	f[2].Title, f[2].RuleID = "", "GHSA-demo"

	doc, page := render(t, run)

	mustContain(t, doc,
		"- **Found by:** live test\n", "- **Found by:** code analysis\n", "- **Found by:** dependency\n",
		"- **Corroborated by:** SQL injection "+hostileMD+" (https://app.test/orders); GHSA-demo (https://app.test/debug)\n",
	)
	mustContain(t, page,
		`<span class="tag kind">live test</span>`, `<span class="tag kind">code analysis</span>`, `<span class="tag kind">dependency</span>`,
		`<li>SQL injection &lt;script&gt;alert(1)&lt;/script&gt;`, `<span class="where">https://app.test/orders</span></li>`,
		`<li>GHSA-demo <span class="where">https://app.test/debug</span></li>`,
	)
	if n := strings.Count(doc, "Corroborated by"); n != 1 {
		t.Errorf("Markdown names corroboration %d times; only one finding has an ID the run holds", n)
	}
	if n := strings.Count(page, "Corroborated by"); n != 1 {
		t.Errorf("HTML names corroboration %d times; want 1", n)
	}
	mustNotContain(t, doc+page, "missing-id", "gone")
}

func TestReportsTreatAnOldOrUnknownKindSafely(t *testing.T) {
	run := quietRun(t)
	run.Report.Findings[0].Kind = finding.Kind("new_kind " + hostile)

	doc, page := render(t, run)

	// The second and third findings have no kind: they predate kinds and were live tests.
	if n := strings.Count(doc, "- **Found by:** live test\n"); n != 2 {
		t.Errorf("%d findings without a kind were labelled as live tests; want 2", n)
	}
	mustContain(t, doc, "- **Found by:** new kind "+hostileMD+"\n")
	mustContain(t, page, `<span class="tag kind">new kind &lt;script&gt;`)
}

func hostileActivity() record.Activity {
	return record.Activity{
		DiscoveredHosts:   []string{"api.app.test", "found " + hostile},
		RejectedHosts:     []string{"rejected " + hostile},
		Endpoints:         []string{"https://app.test/a", "https://app.test/b"},
		PagesCrawled:      7,
		CrawlTruncated:    true,
		SkippedOperations: []string{"DELETE /orders/{id}: could change data " + hostile},
		Packages:          []osv.Package{{Name: "a"}, {Name: "b"}, {Name: "c " + hostile}},
		AgentSteps: []agent.Step{
			{N: 1, Tool: "http_request", Summary: "GET https://app.test/ " + hostile, Outcome: "exchange_id: x1 " + hostile},
			{N: 2, Tool: "tool " + hostile, Summary: "done", Outcome: "exploration ended"},
		},
		AgentStopped: "finished " + hostile,
		AgentSummary: "Covered the login flow. " + hostile,
		Notes:        []string{"A note. " + hostile},
	}
}

func TestReportsShowWhatElseTheRunDid(t *testing.T) {
	run := quietRun(t)
	run.Report.Activity = hostileActivity()

	doc, page := render(t, run)

	mustContain(t, doc,
		"### What else the run did",
		"**Hosts discovered (2).**\n\n- api.app.test\n- found "+hostileMD+"\n",
		"**Hosts rejected because they resolve outside the scope (1).**\n\n- rejected "+hostileMD+"\n",
		"**Crawl.** 7 page(s) crawled, 2 endpoint(s) found. Crawling stopped at its limit, so some pages were not visited.",
		"**API operations skipped (1).**\n\n- DELETE /orders/{id}: could change data "+hostileMD+"\n",
		"**Dependencies.** 3 package(s) inventoried.",
		"**Autonomous explorer.**", "| Step | Tool | What | Outcome |",
		"| 1 | http request | GET https://app.test/ "+hostileMD+" | exchange\\_id: x1 "+hostileMD+" |",
		"| 2 | tool "+hostileMD+" | done | exploration ended |",
		"Why it stopped: finished "+hostileMD, "Its summary: Covered the login flow. "+hostileMD,
		"**Notes (1).**\n\n- A note. "+hostileMD+"\n",
	)
	if touched, did := strings.Index(doc, "### What the run touched"), strings.Index(doc, "### What else the run did"); did < touched {
		t.Error("the activity is not after what the run touched")
	}
	mustNotContain(t, doc, " more")

	mustContain(t, page,
		`<h3 class="sub">What else the run did</h3>`,
		"<h4>Hosts discovered</h4>", "<li>api.app.test</li><li>found &lt;script&gt;",
		"<h4>Hosts rejected because they resolve outside the scope</h4>", "<li>rejected &lt;script&gt;",
		"7 page(s) crawled, 2 endpoint(s) found.", "Crawling stopped at its limit",
		"<h4>API operations skipped</h4>", "<li>DELETE /orders/{id}: could change data &lt;script&gt;",
		"3 package(s) inventoried.",
		"<h4>Autonomous explorer</h4>", "<tr><td>1</td><td>http request</td><td>GET https://app.test/ &lt;script&gt;",
		"<td>tool &lt;script&gt;", "Why it stopped: finished &lt;script&gt;", "Its summary: Covered the login flow. &lt;script&gt;",
		"<h4>Notes</h4>", "<li>A note. &lt;script&gt;",
	)
	mustNotContain(t, page, " more</li>", "more step(s)")
}

func TestReportsShowOnlyTheActivityThatHappened(t *testing.T) {
	cases := map[string]struct {
		activity record.Activity
		want     string
		absent   []string
	}{
		"a note": {record.Activity{Notes: []string{"Only a note."}}, "Only a note.",
			[]string{"Hosts discovered", "Hosts rejected", "Crawl", "API operations skipped", "Dependencies", "Autonomous explorer"}},
		"a crawl that was not cut short": {record.Activity{PagesCrawled: 3}, "3 page(s) crawled, 0 endpoint(s) found.",
			[]string{"Crawling stopped", "Notes", "Autonomous explorer", "Hosts"}},
		"an explorer that stopped before its first step": {record.Activity{AgentStopped: "step limit reached"}, "Why it stopped: step limit reached",
			[]string{"| Step | Tool |", "<th>Tool</th>", "Its summary", "Crawl", "Notes"}},
		"packages": {record.Activity{Packages: []osv.Package{{Name: "a"}}}, "1 package(s) inventoried.",
			[]string{"Autonomous explorer", "Crawl", "Notes"}},
	}
	for name, c := range cases {
		run := quietRun(t)
		run.Report.Activity = c.activity

		doc, page := render(t, run)

		for format, text := range map[string]string{"Markdown": doc, "HTML": page} {
			part := text[strings.Index(text, "What else the run did"):]
			if !strings.Contains(text, "What else the run did") || !strings.Contains(part, c.want) {
				t.Errorf("%s, %s: missing %q", name, format, c.want)
			}
			for _, absent := range c.absent {
				if strings.Contains(part, absent) {
					t.Errorf("%s, %s: unexpected %q", name, format, absent)
				}
			}
		}
	}
}

func TestReportsCapLongActivityLists(t *testing.T) {
	const extraHosts, extraSteps = 10, 25
	run := quietRun(t)
	a := record.Activity{}
	for i := 0; i < maxListRows+extraHosts; i++ {
		a.DiscoveredHosts = append(a.DiscoveredHosts, fmt.Sprintf("d%03d.app.test", i))
		a.RejectedHosts = append(a.RejectedHosts, fmt.Sprintf("r%03d.app.test", i))
		a.SkippedOperations = append(a.SkippedOperations, fmt.Sprintf("GET /op%03d: no example", i))
		a.Notes = append(a.Notes, fmt.Sprintf("note %03d", i))
	}
	for i := 0; i < maxListRows+extraSteps; i++ {
		a.AgentSteps = append(a.AgentSteps, agent.Step{N: i + 1, Tool: "http_request", Summary: fmt.Sprintf("request %03d", i)})
	}
	// Exactly at the cap nothing is left out.
	a.Endpoints = make([]string, maxListRows)
	run.Report.Activity = a

	doc, page := render(t, run)

	last, cut := maxListRows-1, maxListRows
	mustContain(t, doc,
		fmt.Sprintf("**Hosts discovered (%d).**", maxListRows+extraHosts),
		fmt.Sprintf("- d%03d.app.test\n- and %d more\n", last, extraHosts),
		fmt.Sprintf("- r%03d.app.test\n- and %d more\n", last, extraHosts),
		fmt.Sprintf("- GET /op%03d: no example\n- and %d more\n", last, extraHosts),
		fmt.Sprintf("- note %03d\n- and %d more\n", last, extraHosts),
		fmt.Sprintf("| request %03d |  |\n\nand %d more step(s)\n", last, extraSteps),
	)
	mustContain(t, page,
		fmt.Sprintf(`<li>d%03d.app.test</li><li class="note">and %d more</li>`, last, extraHosts),
		fmt.Sprintf(`<li>r%03d.app.test</li><li class="note">and %d more</li>`, last, extraHosts),
		fmt.Sprintf(`<li>GET /op%03d: no example</li><li class="note">and %d more</li>`, last, extraHosts),
		fmt.Sprintf(`<li>note %03d</li><li class="note">and %d more</li>`, last, extraHosts),
		fmt.Sprintf(`<p class="note">and %d more step(s)</p>`, extraSteps),
	)
	for _, beyond := range []string{
		fmt.Sprintf("d%03d.app.test", cut), fmt.Sprintf("r%03d.app.test", cut), fmt.Sprintf("/op%03d:", cut),
		fmt.Sprintf("note %03d", cut), fmt.Sprintf("request %03d", cut),
	} {
		mustNotContain(t, doc, beyond)
		mustNotContain(t, page, beyond)
	}

	exact := quietRun(t)
	exact.Report.Activity = record.Activity{Notes: a.Notes[:maxListRows]}
	doc, page = render(t, exact)
	mustContain(t, doc, fmt.Sprintf("**Notes (%d).**", maxListRows), fmt.Sprintf("- note %03d\n", last))
	mustNotContain(t, doc+page, " more")
}
