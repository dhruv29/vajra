package sarif

import (
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

// codeQLReport is shaped like CodeQL's output: rules carry security-severity
// and CWE tags, and locations are relative to %SRCROOT%.
const codeQLReport = `{
 "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
 "version": "2.1.0",
 "runs": [{
  "results": [
   {"ruleId": "js/sql-injection", "ruleIndex": 1,
    "message": {"text": "This query depends on a user-provided value."},
    "locations": [{"physicalLocation": {
      "artifactLocation": {"uri": "src/db.js", "uriBaseId": "%SRCROOT%", "index": 0},
      "region": {"startLine": 5, "startColumn": 3, "snippet": {"text": "db.query(\"SELECT * FROM u WHERE id=\" + id)"}}}}]},
   {"ruleId": "js/xss", "ruleIndex": 0, "level": "error",
    "message": {"text": "Cross-site scripting vulnerability due to user-provided value."},
    "locations": [{"physicalLocation": {
      "artifactLocation": {"uri": "file:///home/runner/work/app/app/src/view.js"},
      "region": {"startLine": 3, "endLine": 4}}}]},
   {"ruleId": "js/unused-local-variable", "ruleIndex": 2, "message": {"text": "Unused variable x."},
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.js", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 2}}}]},
   {"ruleId": "js/xss", "message": {"text": "suppressed in source"}, "suppressions": [{"kind": "inSource"}],
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/view.js", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 8}}}]},
   {"ruleId": "js/xss", "message": {"text": "a rejected suppression does not hide a result"},
    "suppressions": [{"kind": "external", "status": "rejected"}],
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/view.js", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 9}}}]},
   {"ruleId": "js/xss", "baselineState": "absent", "message": {"text": "fixed"},
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/view.js", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 10}}}]},
   {"ruleId": "js/xss", "kind": "pass", "message": {"text": "passed"},
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/view.js", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 11}}}]},
   {"ruleId": "js/xss", "message": {"text": "escapes"},
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "../../etc/passwd", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 1}}}]},
   {"ruleId": "js/xss", "message": {"text": "no line"},
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/view.js", "uriBaseId": "%SRCROOT%"}}}]}
  ],
  "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///home/runner/work/app/app/"}},
  "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.19.0", "rules": [
   {"id": "js/xss", "name": "js/xss", "shortDescription": {"text": "Client-side cross-site scripting"},
    "defaultConfiguration": {"level": "error"},
    "properties": {"tags": ["security", "external/cwe/cwe-079", "external/cwe/cwe-116"], "security-severity": "6.1"}},
   {"id": "js/sql-injection", "shortDescription": {"text": "Database query built from user-controlled sources"},
    "properties": {"tags": ["Security", "external/cwe/cwe-089"], "security-severity": 8.8}},
   {"id": "js/unused-local-variable", "shortDescription": {"text": "Unused variable"},
    "defaultConfiguration": {"level": "note"}, "properties": {"tags": ["maintainability"]}}
  ]}}
 }]
}`

// minimalReport is shaped like a small tool's output: no rules, no base ids,
// plain relative paths.
const minimalReport = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bandit"}},"results":[
 {"ruleId":"B602","level":"warning","message":{"text":"subprocess call with shell=True"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/run.py"},"region":{"startLine":7}}}]},
 {"ruleId":"B105","message":{"text":"Possible hardcoded password"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/settings.py"},"region":{"startLine":2,"snippet":{"text":"PASSWORD = 'hunter2'\n"}}}}]}
]}]}`

func parse(t *testing.T, doc string, opts Options) ([]finding.Finding, Stats) {
	t.Helper()
	findings, stats, err := ParseWithStats(strings.NewReader(doc), opts)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return findings, stats
}

func TestParseReadsACodeQLStyleReportAndCountsWhatItSkips(t *testing.T) {
	findings, stats := parse(t, codeQLReport, Options{})

	want := Stats{Excluded: 3, Unsafe: 1, Unusable: 1}
	if stats != want {
		t.Errorf("stats = %+v; want %+v", stats, want)
	}
	got := make([]string, 0, len(findings))
	for _, f := range findings {
		got = append(got, f.Target+" "+f.RuleID)
	}
	wantOrder := []string{"src/db.js:2 js/unused-local-variable", "src/db.js:5 js/sql-injection", "src/view.js:3 js/xss", "src/view.js:9 js/xss"}
	if !slices.Equal(got, wantOrder) {
		t.Fatalf("findings = %q; want %q", got, wantOrder)
	}
	sqli := findings[1]
	if sqli.Source != "sarif:codeql" || sqli.Kind != finding.Static || sqli.Status != finding.Candidate {
		t.Errorf("source/kind/status = %s/%s/%s", sqli.Source, sqli.Kind, sqli.Status)
	}
	if sqli.Severity != finding.SeverityHigh || sqli.Title != "Database query built from user-controlled sources" {
		t.Errorf("severity/title = %s/%q", sqli.Severity, sqli.Title)
	}
	if sqli.Description != "This query depends on a user-provided value." {
		t.Errorf("description = %q", sqli.Description)
	}
	if !slices.Equal(sqli.CWE, []string{"cwe-89"}) || !slices.Equal(sqli.Tags, []string{"external/cwe/cwe-089", "security"}) {
		t.Errorf("cwe/tags = %q/%q", sqli.CWE, sqli.Tags)
	}
	if len(sqli.Evidence.Extracted) != 1 || !strings.HasPrefix(sqli.Evidence.Extracted[0], "db.query(") || sqli.Evidence.Code != "" {
		t.Errorf("evidence = %+v; want the snippet as extracted and no code", sqli.Evidence)
	}
	if *sqli.Location != (finding.Location{File: "src/db.js", Line: 5, EndLine: 5}) {
		t.Errorf("location = %+v", *sqli.Location)
	}
	xss := findings[2]
	if xss.Severity != finding.SeverityMedium || !slices.Equal(xss.CWE, []string{"cwe-116", "cwe-79"}) {
		t.Errorf("xss severity/cwe = %s/%q", xss.Severity, xss.CWE)
	}
	if *xss.Location != (finding.Location{File: "src/view.js", Line: 3, EndLine: 4}) {
		t.Errorf("an absolute uri under %%SRCROOT%% was not made relative: %+v", *xss.Location)
	}
	if unused := findings[0]; unused.Severity != finding.SeverityLow {
		t.Errorf("a note-level rule default gave %s; want low", unused.Severity)
	}
}

func TestParseReadsAMinimalReport(t *testing.T) {
	findings, skipped, err := Parse(strings.NewReader(minimalReport), Options{})

	if err != nil || skipped != 0 || len(findings) != 2 {
		t.Fatalf("findings = %d, skipped = %d, err = %v", len(findings), skipped, err)
	}
	run, pw := findings[0], findings[1]
	if run.Location.File != "app/run.py" || run.Severity != finding.SeverityMedium || run.Title != "B602" {
		t.Errorf("first = %+v", run)
	}
	if pw.Source != "sarif:bandit" || pw.Severity != finding.SeverityMedium || pw.Evidence.Extracted[0] != "PASSWORD = 'hunter2'\n" {
		t.Errorf("second = %+v", pw)
	}
	if pw.ID != finding.StableID("sarif:bandit", "B105", "app/settings.py:2", "") {
		t.Errorf("id %s is not derived from source, rule, path and line", pw.ID)
	}
}

func TestParseOutputAndIDsAreDeterministic(t *testing.T) {
	a, _ := parse(t, minimalReport, Options{})
	swapped := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bandit"}},"results":[
 {"ruleId":"B105","message":{"text":"Possible hardcoded password"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/settings.py"},"region":{"startLine":2}}}]},
 {"ruleId":"B602","level":"warning","message":{"text":"subprocess call with shell=True"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"./app/run.py"},"region":{"startLine":7}}}]}]}]}`
	b, _ := parse(t, swapped, Options{})

	if len(a) != len(b) {
		t.Fatalf("lengths %d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Target != b[i].Target {
			t.Errorf("finding %d: %s %s vs %s %s", i, a[i].ID, a[i].Target, b[i].ID, b[i].Target)
		}
	}
}

func TestParseDropsRepeatsOfTheSameRuleFileAndLineKeepingTheMostSevere(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[
 {"tool":{"driver":{"name":"gosec"}},"results":[
  {"ruleId":"G101","level":"note","message":{"text":"low"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":4,"startColumn":1}}}]},
  {"ruleId":"G101","level":"error","message":{"text":"high"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":4,"startColumn":9}}}]}]},
 {"tool":{"driver":{"name":"gosec"}},"results":[
  {"ruleId":"G101","level":"warning","message":{"text":"again"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":4}}}]}]}]}`

	findings, stats := parse(t, doc, Options{})

	if len(findings) != 1 || stats.Duplicate != 2 || findings[0].Severity != finding.SeverityHigh {
		t.Fatalf("findings = %+v, stats = %+v", findings, stats)
	}
}

func TestParseEnforcesTheByteCap(t *testing.T) {
	_, _, err := Parse(strings.NewReader(codeQLReport), Options{MaxBytes: 100})
	if err == nil || !strings.HasPrefix(err.Error(), "sarif: ") || !strings.Contains(err.Error(), "larger than 100 bytes") {
		t.Fatalf("err = %v", err)
	}
	exact := int64(len(minimalReport))
	if _, _, err := Parse(strings.NewReader(minimalReport), Options{MaxBytes: exact}); err != nil {
		t.Errorf("a document of exactly MaxBytes was refused: %v", err)
	}
	if _, _, err := Parse(strings.NewReader(minimalReport), Options{MaxBytes: exact - 1}); err == nil {
		t.Error("a document one byte over MaxBytes was accepted")
	}
}

func TestParseEnforcesTheResultCap(t *testing.T) {
	findings, stats := parse(t, minimalReport, Options{MaxResults: 1})

	if len(findings) != 1 || stats.OverCap != 1 || findings[0].RuleID != "B602" {
		t.Fatalf("findings = %d, stats = %+v; want the first result kept", len(findings), stats)
	}
}

func TestParseRejectsDocumentsThatAreNotSARIF(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"not json":         "<html>",
		"an array":         "[]",
		"no runs":          `{"version":"2.1.0"}`,
		"old version":      `{"version":"1.0.0","runs":[]}`,
		"version a number": `{"version":2,"runs":[]}`,
		"runs an object":   `{"runs":{}}`,
		"run a string":     `{"runs":["x"]}`,
		"results a string": `{"runs":[{"results":"x"}]}`,
		"truncated":        codeQLReport[:len(codeQLReport)/2],
		"broken result":    `{"runs":[{"results":[{"ruleId":]}]}`,
		"broken key":       `{"runs":[{1:2}]}`,
	}
	for name, doc := range cases {
		findings, _, err := Parse(strings.NewReader(doc), Options{})
		if err == nil || !strings.HasPrefix(err.Error(), "sarif: ") || findings != nil {
			t.Errorf("%s: findings = %v, err = %v; want a sarif: error", name, findings, err)
		}
	}
}

func TestParseToleratesOddShapesWithoutFailing(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[
 {"tool":{"driver":{"name":42,"rules":"nope"}},"results":null},
 {"tool":{"driver":{"name":"Odd","rules":[{"id":"r1","properties":{"tags":"security","security-severity":"high"}},7]}},
  "originalUriBaseIds":["x"],
  "results":[
   {"ruleId":"r1","level":5,"message":"text","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":"3"}}}]},
   {"ruleId":"r1","ruleIndex":99,"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]},
   {"rule":{"index":0},"locations":"nope"},
   {"rule":{"index":0},"locations":[7,{"physicalLocation":{"artifactLocation":{"uri":"b.py"},"region":{"startLine":2}}}]},
   {"rule":{"index":0},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"c.py"},"region":{"startLine":2}}}]},
   "not an object", 12, null, [],
   {"ruleId":"r1","suppressions":"x","locations":[{"physicalLocation":{"artifactLocation":{"uri":"d.py"},"region":{"startLine":-4}}}]}
  ],
  "unknownProperty":{"deep":[1,2,{"x":null}]}}],
 "inlineExternalProperties":[]}`

	findings, stats := parse(t, doc, Options{})

	got := []string{}
	for _, f := range findings {
		got = append(got, f.Target+" "+f.RuleID+" "+string(f.Severity))
	}
	want := []string{"a.py:1 r1 medium", "c.py:2 r1 medium"}
	if !slices.Equal(got, want) {
		t.Errorf("findings = %q; want %q", got, want)
	}
	if stats.Unusable != 8 {
		t.Errorf("stats = %+v; want 8 unusable", stats)
	}
}

func TestParseCapsFieldLengthsAndStripsControlCharacters(t *testing.T) {
	long := strings.Repeat("é", maxMessageBytes)
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + strings.Repeat("Tool ", 50) + `"}},"results":[
 {"ruleId":"` + strings.Repeat("r", 1000) + `","message":{"text":"line one\u001b[31m\r` + long + `"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1,"snippet":{"text":"` + long + long + `"}}}}],
  "properties":{"tags":["` + strings.Repeat("t", 500) + `"]}}]}]}`

	findings, _ := parse(t, doc, Options{})

	f := findings[0]
	if len(f.RuleID) != maxRuleIDBytes || len(f.Description) > maxMessageBytes || strings.ContainsAny(f.Description, "\x1b\r") {
		t.Errorf("rule id %d bytes, description %d bytes %q...", len(f.RuleID), len(f.Description), f.Description[:20])
	}
	if !strings.HasPrefix(f.Description, "line one[31m") {
		t.Errorf("description = %q", f.Description[:20])
	}
	if len(f.Evidence.Extracted[0]) > maxSnippetBytes || len(f.Tags[0]) != maxTagBytes || !IsSource(f.Source) {
		t.Errorf("snippet %d bytes, tag %d bytes, source %q", len(f.Evidence.Extracted[0]), len(f.Tags[0]), f.Source)
	}
}

func TestParseReadsCWEFromTaxaAndRelationships(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Snyk Code","rules":[
 {"id":"javascript/Sqli","properties":{"tags":["CWE-89: SQL Injection"]},
  "relationships":[{"target":{"id":"20","toolComponent":{"name":"CWE"}}},{"target":{"id":"999","toolComponent":{"name":"OWASP"}}}]}]}},
 "results":[{"ruleId":"javascript/Sqli","taxa":[{"id":"CWE-943","toolComponent":{"name":"CWE"}},{"id":"0","toolComponent":{"name":"cwe"}}],
  "properties":{"security-severity":9.8},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"routes/index.js"},"region":{"startLine":40}}}]}]}]}`

	findings, _ := parse(t, doc, Options{})

	f := findings[0]
	if !slices.Equal(f.CWE, []string{"cwe-20", "cwe-89", "cwe-943"}) {
		t.Errorf("cwe = %q", f.CWE)
	}
	if f.Source != "sarif:snyk-code" || f.Severity != finding.SeverityCritical {
		t.Errorf("source/severity = %s/%s", f.Source, f.Severity)
	}
}

func TestSecuritySeverityAndLevelMapLikeGitHubCodeScanning(t *testing.T) {
	scores := map[float64]finding.Severity{
		10: finding.SeverityCritical, 9.0: finding.SeverityCritical, 8.9: finding.SeverityHigh,
		7.0: finding.SeverityHigh, 6.9: finding.SeverityMedium, 4.0: finding.SeverityMedium,
		3.9: finding.SeverityLow, 0.1: finding.SeverityLow, 0: finding.SeverityInfo,
	}
	for s, want := range scores {
		if got := fromScore(s); got != want {
			t.Errorf("score %v = %s; want %s", s, got, want)
		}
	}
	levels := map[string]finding.Severity{
		"error": finding.SeverityHigh, "warning": finding.SeverityMedium, "": finding.SeverityMedium,
		"note": finding.SeverityLow, "none": finding.SeverityInfo, "ERROR": finding.SeverityHigh, "fatal": finding.SeverityUnknown,
	}
	for level, want := range levels {
		if got := fromLevel(level); got != want {
			t.Errorf("level %q = %s; want %s", level, got, want)
		}
	}
}

func TestAnOutOfRangeSecuritySeverityFallsBackToTheLevel(t *testing.T) {
	for _, raw := range []string{`"11"`, `-1`, `"NaN"`, `"n/a"`, `true`, `null`} {
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},"results":[{"ruleId":"r","level":"note",
 "properties":{"security-severity":` + raw + `},
 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]}]}]}`
		findings, _ := parse(t, doc, Options{})
		if findings[0].Severity != finding.SeverityLow {
			t.Errorf("security-severity %s gave %s; want the level's low", raw, findings[0].Severity)
		}
	}
}

func TestSourceNamesAreSanitisedAndRecognised(t *testing.T) {
	cases := map[string]string{
		"CodeQL":                   "sarif:codeql",
		"Snyk Open Source":         "sarif:snyk-open-source",
		"  --Semgrep OSS!! ":       "sarif:semgrep-oss",
		"":                         "sarif:unknown",
		"日本語":                      "sarif:unknown",
		"../../evil\nname":         "sarif:evil-name",
		strings.Repeat("ab-", 100): "sarif:" + strings.Repeat("ab-", 13) + "a",
	}
	for name, want := range cases {
		got := sourceFor(name)
		if got != want || !IsSource(got) {
			t.Errorf("sourceFor(%q) = %q (IsSource %v); want %q", name, got, IsSource(got), want)
		}
	}
	for _, s := range []string{"semgrep", "sarif:", "sarif:Bad", "sarif:a--b", "sarif:-a", "sarif:a b", "sarif:" + strings.Repeat("a", 41)} {
		if IsSource(s) {
			t.Errorf("IsSource(%q) = true", s)
		}
	}
}

func TestStatsTotalAddsEveryReason(t *testing.T) {
	if got := (Stats{Excluded: 1, Unsafe: 2, Unusable: 3, OverCap: 4, Duplicate: 5}).Total(); got != 15 {
		t.Errorf("total = %d", got)
	}
}

func TestParseCapsListsAndKeepsOneLineFieldsOnOneLine(t *testing.T) {
	many := make([]string, 0, 100)
	for i := range 100 {
		many = append(many, `"tag`+strings.Repeat("x", i)+`"`)
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[{"id":"r",
 "shortDescription":{"text":"two\nlines"},"fullDescription":{"text":"What the rule finds."},
 "properties":{"tags":[` + strings.Join(many, ",") + `]}}]}},
 "results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]}]}]}`

	findings, _ := parse(t, doc, Options{})

	f := findings[0]
	if len(f.Tags) != maxTags || f.Title != "two lines" || f.Description != "What the rule finds." {
		t.Errorf("tags = %d, title = %q, description = %q", len(f.Tags), f.Title, f.Description)
	}
}

func TestClippingNeverSplitsACharacter(t *testing.T) {
	if got := clipRaw("aé", 2); got != "a" {
		t.Errorf("clipRaw = %q", got)
	}
	if got := clip("  \x07 ", 10); got != "" {
		t.Errorf("clip = %q", got)
	}
}
