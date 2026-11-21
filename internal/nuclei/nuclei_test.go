package nuclei

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
)

const sampleOutput = `{"template-id":"exposed-env","info":{"name":"Exposed .env file","severity":"high"},"host":"app.test","url":"/https://app.test","matched-at":"https://app.test/.env","matcher-name":"db-password","extracted-results":["DB_PASSWORD=hunter2"],"request":"GET /.env HTTP/1.1\r\nHost: app.test\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\nDB_PASSWORD=hunter2"}

not json at all
{"info":{"name":"no template id"}}
{"template-id":"tech-detect","info":{"severity":"INFO"},"host":"https://app.test"}
`

func TestParseReadsResultsAndSkipsJunk(t *testing.T) {
	findings, skipped, err := Parse(strings.NewReader(sampleOutput))

	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || skipped != 2 {
		t.Fatalf("findings = %d, skipped = %d; want 2 and 2", len(findings), skipped)
	}
	first := findings[0]
	want := finding.Finding{
		ID: first.ID, Source: "nuclei", RuleID: "exposed-env", Title: "Exposed .env file",
		Severity: finding.SeverityHigh, Target: "https://app.test/.env", Status: finding.Candidate,
	}
	if first.Source != want.Source || first.RuleID != want.RuleID || first.Title != want.Title ||
		first.Severity != want.Severity || first.Target != want.Target || first.Status != want.Status {
		t.Fatalf("first = %+v", first)
	}
	if first.Evidence.Matcher != "db-password" || !strings.Contains(first.Evidence.Response, "hunter2") ||
		!slices.Equal(first.Evidence.Extracted, []string{"DB_PASSWORD=hunter2"}) {
		t.Fatalf("evidence = %+v", first.Evidence)
	}
	if first.Evidence.ScanInput != "https://app.test" {
		t.Fatalf("scan input = %q", first.Evidence.ScanInput)
	}
	if first.ID == "" || first.ID == findings[1].ID {
		t.Fatalf("IDs = %q, %q", first.ID, findings[1].ID)
	}
	second := findings[1]
	if second.Title != "tech-detect" || second.Target != "https://app.test" || second.Severity != finding.SeverityInfo {
		t.Fatalf("second = %+v; want fallbacks for a missing name and matched-at", second)
	}
}

func TestParseReadsTagsAndCWEInEitherShape(t *testing.T) {
	output := `{"template-id":"a","info":{"tags":["Config"," git ",""],"classification":{"cwe-id":["CWE-200"]}}}
{"template-id":"b","info":{"tags":"sqli, injection","classification":{"cwe-id":"cwe-89"}}}
{"template-id":"c","info":{"tags":42,"classification":{"cwe-id":null}}}
`
	findings, skipped, err := Parse(strings.NewReader(output))

	if err != nil || skipped != 0 || len(findings) != 3 {
		t.Fatalf("findings = %d, skipped = %d, err = %v", len(findings), skipped, err)
	}
	if !slices.Equal(findings[0].Tags, []string{"config", "git"}) || !slices.Equal(findings[0].CWE, []string{"cwe-200"}) {
		t.Errorf("array shape: tags = %v, cwe = %v", findings[0].Tags, findings[0].CWE)
	}
	if !slices.Equal(findings[1].Tags, []string{"sqli", "injection"}) || !slices.Equal(findings[1].CWE, []string{"cwe-89"}) {
		t.Errorf("string shape: tags = %v, cwe = %v", findings[1].Tags, findings[1].CWE)
	}
	if len(findings[2].Tags) != 0 || len(findings[2].CWE) != 0 {
		t.Errorf("unexpected shape: tags = %v, cwe = %v", findings[2].Tags, findings[2].CWE)
	}
}

func TestParseReportsOversizedLines(t *testing.T) {
	_, _, err := Parse(strings.NewReader(strings.Repeat("x", maxLineBytes+1)))
	if err == nil {
		t.Fatal("an oversized line was not reported")
	}
}

type fakeRunner struct {
	specs  []sandbox.Spec
	result sandbox.Result
	err    error
}

func (f *fakeRunner) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	f.specs = append(f.specs, spec)
	return f.result, f.err
}

func newScanner(runner sandbox.Runner) *Scanner {
	return &Scanner{
		Runner: runner, Image: "vajra-nuclei:local", TemplatesDir: "/opt/nuclei-templates",
		Network: "vajra-task-net", ProxyURL: "http://gate:3128", Timeout: time.Minute,
	}
}

func TestScanRunsNucleiBehindTheGate(t *testing.T) {
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(sampleOutput)}}

	findings, err := newScanner(runner).Scan(context.Background(), []string{"https://app.test", "https://app.test:8443/api"})

	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %d, err = %v", len(findings), err)
	}
	spec := runner.specs[0]
	if spec.Network != "vajra-task-net" || spec.Image != "vajra-nuclei:local" || spec.Timeout != time.Minute {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.Env["HTTPS_PROXY"] != "http://gate:3128" || spec.Env["HOME"] != "/tmp" {
		t.Fatalf("env = %v", spec.Env)
	}
	joined := strings.Join(spec.Argv, " ")
	for _, want := range []string{
		"-jsonl", "-disable-update-check", "-no-interactsh",
		"-templates /opt/nuclei-templates", "-proxy http://gate:3128", "-rate-limit 20",
		"-target https://app.test", "-target https://app.test:8443/api",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv is missing %q\n got: %s", want, joined)
		}
	}
}

func TestScanRecordsWhichConfiguredTargetEachFindingCameFrom(t *testing.T) {
	output := `{"template-id":"a","matched-at":"https://app.test:8443/api/v1/debug","request":"r","response":"s"}
{"template-id":"b","matched-at":"https://app.test/.env","request":"r","response":"s"}
{"template-id":"c","matched-at":"app.test:22"}
`
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(output)}}

	findings, err := newScanner(runner).Scan(context.Background(), []string{"https://app.test:8443/api", "https://app.test"})

	if err != nil || len(findings) != 3 {
		t.Fatalf("findings = %d, err = %v", len(findings), err)
	}
	want := []string{"https://app.test:8443/api", "https://app.test", ""}
	for i, f := range findings {
		if f.Evidence.ScanInput != want[i] {
			t.Errorf("finding %d scan input = %q; want %q", i, f.Evidence.ScanInput, want[i])
		}
	}
}

func TestScanRejectsBadTargetsBeforeRunningAnything(t *testing.T) {
	for _, targets := range [][]string{nil, {"app.test"}, {"https://app.test", "-proxy=http://evil"}, {"ftp://app.test"}} {
		runner := &fakeRunner{}
		if _, err := newScanner(runner).Scan(context.Background(), targets); err == nil {
			t.Errorf("Scan(%v) succeeded; want an error", targets)
		}
		if len(runner.specs) != 0 {
			t.Errorf("Scan(%v) started a sandbox", targets)
		}
	}
}

func TestRunFailuresAreErrorsNotEmptyResults(t *testing.T) {
	cases := map[string]fakeRunner{
		"sandbox error":    {err: errors.New("docker unavailable")},
		"timeout":          {result: sandbox.Result{TimedOut: true}},
		"non-zero exit":    {result: sandbox.Result{ExitCode: 1, Stderr: []byte("could not load templates")}},
		"truncated output": {result: sandbox.Result{Truncated: true, Stdout: []byte(sampleOutput)}},
	}
	for name, runner := range cases {
		t.Run(name, func(t *testing.T) {
			r := runner
			if _, err := newScanner(&r).Scan(context.Background(), []string{"https://app.test"}); err == nil {
				t.Fatal("Scan succeeded; a failed run must not look like a clean scan")
			}
		})
	}
}

func TestExitErrorCarriesTheEndOfStderr(t *testing.T) {
	stderr := strings.Repeat("noise ", 500) + "FATAL: templates missing"
	runner := &fakeRunner{result: sandbox.Result{ExitCode: 2, Stderr: []byte(stderr)}}

	_, err := newScanner(runner).Scan(context.Background(), []string{"https://app.test"})

	if err == nil || !strings.Contains(err.Error(), "FATAL: templates missing") || len(err.Error()) > stderrTailBytes+100 {
		t.Fatalf("err = %v", err)
	}
}

func candidate() finding.Finding {
	return finding.Finding{
		Source: Source, RuleID: "exposed-env", Target: "https://app.test/.env",
		Evidence: finding.Evidence{Matcher: "db-password", ScanInput: "https://app.test"},
	}
}

func TestReproduceRunsOnlyTheOneTemplateAgainstTheMatchedURL(t *testing.T) {
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(sampleOutput)}}

	matched, err := newScanner(runner).Reproduce(context.Background(), candidate())

	if err != nil || !matched {
		t.Fatalf("matched = %v, err = %v", matched, err)
	}
	joined := strings.Join(runner.specs[0].Argv, " ")
	if !strings.Contains(joined, "-target https://app.test -template-id exposed-env") {
		t.Fatalf("argv = %s", joined)
	}
}

func TestReproduceReportsNoMatch(t *testing.T) {
	cases := map[string]func(*finding.Finding, *fakeRunner){
		"no output":              func(_ *finding.Finding, r *fakeRunner) { r.result.Stdout = nil },
		"different matcher":      func(f *finding.Finding, _ *fakeRunner) { f.Evidence.Matcher = "aws-key" },
		"different template":     func(f *finding.Finding, _ *fakeRunner) { f.RuleID = "other-template" },
		"matched somewhere else": func(f *finding.Finding, _ *fakeRunner) { f.Target = "https://app.test/backup/.env" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(sampleOutput)}}
			f := candidate()
			mutate(&f, runner)

			matched, err := newScanner(runner).Reproduce(context.Background(), f)

			if err != nil || matched {
				t.Fatalf("matched = %v, err = %v; want no match", matched, err)
			}
		})
	}
}

func TestReproduceFallsBackToTheTargetWithoutAScanInput(t *testing.T) {
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(sampleOutput)}}
	f := candidate()
	f.Evidence.ScanInput = ""

	if _, err := newScanner(runner).Reproduce(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(runner.specs[0].Argv, " "); !strings.Contains(joined, "-target https://app.test/.env -template-id") {
		t.Fatalf("argv = %s", joined)
	}
}

func TestReproduceMatchesAnyMatcherWhenTheFindingHasNone(t *testing.T) {
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(sampleOutput)}}
	f := candidate()
	f.Evidence.Matcher = ""

	if matched, err := newScanner(runner).Reproduce(context.Background(), f); err != nil || !matched {
		t.Fatalf("matched = %v, err = %v", matched, err)
	}
}

func TestReproduceRejectsHostileInputAndPropagatesErrors(t *testing.T) {
	for name, mutate := range map[string]func(*finding.Finding){
		"flag as template id": func(f *finding.Finding) { f.RuleID = "-templates=/etc" },
		"path as template id": func(f *finding.Finding) { f.RuleID = "../../etc/passwd" },
		"target is not a URL": func(f *finding.Finding) { f.Target = "-proxy" },
	} {
		runner := &fakeRunner{}
		f := candidate()
		mutate(&f)
		if _, err := newScanner(runner).Reproduce(context.Background(), f); err == nil {
			t.Errorf("%s: Reproduce succeeded; want an error", name)
		}
		if len(runner.specs) != 0 {
			t.Errorf("%s: a sandbox was started", name)
		}
	}

	runner := &fakeRunner{err: errors.New("docker unavailable")}
	if _, err := newScanner(runner).Reproduce(context.Background(), candidate()); err == nil {
		t.Error("a sandbox error was swallowed")
	}
}

func TestValidateNamesEachMissingSetting(t *testing.T) {
	mutations := map[string]func(*Scanner){
		"runner":       func(s *Scanner) { s.Runner = nil },
		"image":        func(s *Scanner) { s.Image = "" },
		"templates":    func(s *Scanner) { s.TemplatesDir = "" },
		"network":      func(s *Scanner) { s.Network = "" },
		"network none": func(s *Scanner) { s.Network = sandbox.NetworkNone },
		"proxy":        func(s *Scanner) { s.ProxyURL = "" },
		"timeout":      func(s *Scanner) { s.Timeout = 0 },
	}
	for name, mutate := range mutations {
		s := newScanner(&fakeRunner{})
		mutate(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
		if _, err := s.Scan(context.Background(), []string{"https://app.test"}); err == nil {
			t.Errorf("%s: Scan ran with an invalid scanner", name)
		}
	}
	custom := newScanner(&fakeRunner{})
	custom.RateLimit = 5
	if args := strings.Join(custom.baseArgs(), " "); !strings.Contains(args, "-rate-limit 5") {
		t.Errorf("args = %s", args)
	}
}
