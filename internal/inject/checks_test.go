package inject

import (
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

const host = "https://app.test"

// only returns the findings of one rule.
func only(findings []finding.Finding, rule string) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestReflectedInputInHTMLTextIsReportedWithItsContext(t *testing.T) {
	result := run(t, newChecker(t, newApp(), Options{}), host+"/search?q=hello")
	got := only(result.Findings, ruleXSS)
	if len(got) != 1 || len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	f := got[0]
	marker := markerPrefix + "000000000001"
	switch {
	case f.ID != finding.StableID(Source, ruleXSS, "app.test/search", "q"):
		t.Errorf("ID = %q", f.ID)
	case f.Kind != finding.Dynamic || f.Source != Source || f.Status != finding.Candidate:
		t.Errorf("kind/source/status = %q %q %q", f.Kind, f.Source, f.Status)
	case f.CWE[0] != "cwe-79" || f.Severity != finding.SeverityHigh || f.AssetURL != host:
		t.Errorf("cwe/severity/asset = %v %q %q", f.CWE, f.Severity, f.AssetURL)
	case extracted(f, keyMarker) != marker || extracted(f, keyContext) != ctxText:
		t.Errorf("extracted = %v", f.Evidence.Extracted)
	case !strings.Contains(f.Evidence.Response, marker+"<"+marker+">"):
		t.Errorf("response evidence lacks the raw reflection: %s", f.Evidence.Response)
	case !strings.HasPrefix(f.Evidence.Request, "GET "+f.Evidence.MatchedAt) || f.Evidence.ScanInput != host+"/search?q=hello":
		t.Errorf("request evidence = %q, scan input %q", f.Evidence.Request, f.Evidence.ScanInput)
	}
}

func TestReflectionThatBreaksOutOfADoubleQuotedAttributeIsReported(t *testing.T) {
	result := run(t, newChecker(t, newApp(), Options{}), host+"/profile?name=ann")
	got := only(result.Findings, ruleXSS)
	if len(got) != 1 || extracted(got[0], keyContext) != ctxDouble {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

func TestEncodedReflectionsAreNotReported(t *testing.T) {
	// Fully encoded text, and an attribute whose quotes are encoded while its
	// angle brackets are not (harmless inside a quoted value).
	result := run(t, newChecker(t, newApp(), Options{}), host+"/safe-search?q=a", host+"/attr-safe?name=b")
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

func TestRawReflectionsOutsideRenderedHTMLAreNotReported(t *testing.T) {
	result := run(t, newChecker(t, newApp(), Options{}),
		host+"/api/search?q=a", host+"/text?q=b", host+"/comment?q=c")
	if len(result.Findings) != 0 {
		t.Fatalf("JSON, plain text and comment reflections were reported: %+v", result.Findings)
	}
	if result.Tested != 3 {
		t.Fatalf("tested = %d", result.Tested)
	}
}

func TestContextAtNamesWhereTheReflectionLands(t *testing.T) {
	for prefix, want := range map[string]string{
		"":                             ctxText,
		"<p>hi ":                       ctxText,
		`<a href="x" title="`:          ctxDouble,
		`<a title='`:                   ctxSingle,
		`<a title="it's" data=`:        ctxUnquoted,
		"<script>var a = ":             ctxScript,
		"<script></script><p>":         ctxText,
		"<!-- note ":                   ctxComment,
		`<input value="a" name="b" x=`: ctxUnquoted,
	} {
		if got := contextAt(prefix); got != want {
			t.Errorf("contextAt(%q) = %q, want %q", prefix, got, want)
		}
	}
}

func TestBreakOutRulesDemandTheCharacterThatEscapesEachContext(t *testing.T) {
	m := "vj0123456789ab"
	html := func(body string) probe.Response { return withType(200, "text/html", body) }
	cases := map[string]bool{
		"<p>" + xssPayload(m) + "</p>":                                      true,
		"<p>" + m + "&quot;" + m + "&#39;" + m + "<" + m + ">":              true,
		"<a title='" + xssPayload(m) + "'>":                                 true,
		"<a title='" + m + `"` + m + "&#39;" + m + "&lt;" + m + "&gt;'>":    false,
		"<input value=" + xssPayload(m) + ">":                               true,
		"<input value=" + m + "&quot;" + m + "&#39;" + m + "&lt;" + m + ">": false,
		"<p>" + m + `"` + m + "'" + m + "&lt;" + m + "&gt;</p>":             false,
	}
	for body, want := range cases {
		if _, got := findReflection(html(body), m); got != want {
			t.Errorf("findReflection(%q) = %v, want %v", body, got, want)
		}
	}
	if _, got := findReflection(probe.Response{Gate: "failed", Status: 502}, m); got {
		t.Error("an unanswered response was judged")
	}
}

func TestSQLErrorThatFollowsTheBalanceOfQuotesIsReported(t *testing.T) {
	result := run(t, newChecker(t, newApp(), Options{}), host+"/item?id=7")
	got := only(result.Findings, ruleSQLError)
	if len(got) != 1 || len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	f := got[0]
	switch {
	case f.Severity != finding.SeverityMedium || f.CWE[0] != "cwe-89":
		t.Errorf("severity/cwe = %q %v", f.Severity, f.CWE)
	case !strings.Contains(f.Description, "Shown:") || !strings.Contains(f.Description, "Not shown:"):
		t.Errorf("description does not separate what was and was not shown: %s", f.Description)
	case extracted(f, "database: ") != "MySQL/MariaDB":
		t.Errorf("extracted = %v", f.Evidence.Extracted)
	case f.Evidence.MatchedAt != host+"/item?id=7%27" || !strings.Contains(f.Evidence.Response, "SQL syntax"):
		t.Errorf("evidence = %+v", f.Evidence)
	}
}

func TestSQLErrorAlreadyInTheBaselineIsNotReported(t *testing.T) {
	if result := run(t, newChecker(t, newApp(), Options{}), host+"/noisy?id=1"); len(result.Findings) != 0 {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

func TestSQLErrorWithBothQuoteFormsIsNotReported(t *testing.T) {
	if result := run(t, newChecker(t, newApp(), Options{}), host+"/both?id=1"); len(result.Findings) != 0 {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

func TestSQLRuleNeedsCompleteAnsweredResponses(t *testing.T) {
	clean := page("ok")
	broken := withType(500, "text/html", "unrecognized token: \"'\"")
	if e, ok := judgeSQL(clean, broken, clean); !ok || e.database != "SQLite" {
		t.Fatalf("the plain differential was not accepted: %+v %v", e, ok)
	}
	truncated := clean
	truncated.BodyTruncated = true
	unanswered := probe.Response{Error: "timeout"}
	for name, rs := range map[string][3]probe.Response{
		"truncated baseline":   {truncated, broken, clean},
		"truncated doubled":    {clean, broken, truncated},
		"unanswered doubled":   {clean, broken, unanswered},
		"no error with quote":  {clean, clean, clean},
		"error in the doubled": {clean, broken, broken},
	} {
		if _, ok := judgeSQL(rs[0], rs[1], rs[2]); ok {
			t.Errorf("%s: reported", name)
		}
	}
}

func TestEachDatabaseHasASignature(t *testing.T) {
	for db, text := range map[string]string{
		"MySQL/MariaDB": "Warning: mysqli_query() expects",
		"PostgreSQL":    "ERROR:  unterminated quoted string at or near \"'\"",
		"SQLite":        `near "'": syntax error`,
		"MSSQL":         "Unclosed quotation mark after the character string ''.",
		"Oracle":        "ORA-01756: quoted string not properly terminated",
	} {
		if e, ok := findDBError(text); !ok || e.database != db {
			t.Errorf("%q: got %+v %v, want %s", text, e, ok, db)
		}
	}
	if _, ok := findDBError("<p>Our SQL course covers syntax errors and Oracle databases.</p>"); ok {
		t.Error("ordinary prose matched a database signature")
	}
}

func TestRedirectToTheCanaryHostIsReported(t *testing.T) {
	result := run(t, newChecker(t, newApp(), Options{}), host+"/go?next=/home")
	got := only(result.Findings, ruleRedirect)
	if len(got) != 1 || len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	f := got[0]
	canary := "000000000001." + canaryDomain
	switch {
	case f.CWE[0] != "cwe-601" || f.Severity != finding.SeverityLow:
		t.Errorf("cwe/severity = %v %q", f.CWE, f.Severity)
	case extracted(f, keyCanary) != canary || extracted(f, "location: ") != "https://"+canary+"/":
		t.Errorf("extracted = %v", f.Evidence.Extracted)
	case !strings.Contains(f.Evidence.Response, "HTTP 302") || !strings.Contains(f.Evidence.Response, canary):
		t.Errorf("response evidence = %s", f.Evidence.Response)
	}
}

func TestRedirectsThatStayOnSiteOrOnlyMentionTheCanaryAreNotReported(t *testing.T) {
	result := run(t, newChecker(t, newApp(), Options{}),
		host+"/login?returnTo=/account", host+"/sso?continue=x", host+"/hop?url=https://app.test/")
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

func TestJudgeRedirectWantsA3xxWithExactlyTheCanaryHost(t *testing.T) {
	canary := "abc." + canaryDomain
	cases := map[string]probe.Response{
		"200 with Location":       {Status: 200, Headers: map[string][]string{"Location": {"https://" + canary + "/"}}},
		"canary in the path":      redirect("https://app.test/" + canary),
		"canary as user info":     redirect("https://" + canary + "@app.test/"),
		"canary with a suffix":    redirect("https://" + canary + ".app.test/"),
		"Location does not parse": redirect("https://%zz"),
		"unanswered":              {Error: "refused"},
	}
	for name, r := range cases {
		if _, ok := judgeRedirect(r, canary); ok {
			t.Errorf("%s: reported", name)
		}
	}
	if _, ok := judgeRedirect(redirect("//"+strings.ToUpper(canary)+"/x"), canary); !ok {
		t.Error("a protocol-relative Location to the canary was missed")
	}
}

func TestOnlyRedirectCandidatesGetACanaryRequest(t *testing.T) {
	app := newApp()
	run(t, newChecker(t, app, Options{}), host+"/search?q=hello")
	for _, u := range app.urls() {
		if strings.Contains(u, canaryDomain) {
			t.Fatalf("a canary was sent to a parameter that is not a redirect candidate: %s", u)
		}
	}
	for name, want := range map[string]bool{"returnTo": true, "RETURN_URL": true, "next": true, "q": false} {
		if got := redirectCandidate(name, "plain"); got != want {
			t.Errorf("redirectCandidate(%q) = %v", name, got)
		}
	}
	if !redirectCandidate("ref", "https://x.test/") || !redirectCandidate("ref", "/path") {
		t.Error("URL- and path-like values are redirect candidates")
	}
}
