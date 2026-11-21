package semgrep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
)

const sampleOutput = `{"results":[
 {"check_id":"python.flask.security.injection.tainted-sql-string","path":"app/views.py",
  "start":{"line":4},"end":{"line":4},
  "extra":{"message":"User input flows into a SQL string.","severity":"ERROR",
   "metadata":{"cwe":["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],"category":"Security"},
   "dataflow_trace":{
     "taint_source":["CliLoc",[{"path":"app/views.py","start":{"line":2},"end":{"line":2}},"request.args.get('id')"]],
     "intermediate_vars":[{"location":{"path":"app/views.py","start":{"line":2},"end":{"line":2}},"content":"order_id"}],
     "taint_sink":["CliLoc",[{"path":"app/views.py","start":{"line":4},"end":{"line":4}},"db.execute(query)"]]}}},
 {"check_id":"generic.secrets.hardcoded","path":"./config.py","start":{"line":1},"end":{"line":0},
  "extra":{"message":"m","severity":"warning","metadata":{"cwe":"CWE-798: Hard-coded Credentials"}}},
 {"check_id":"no.line","path":"a.py","start":{"line":0},"end":{"line":0},"extra":{}},
 {"check_id":"escapes.root","path":"../outside.py","start":{"line":1},"end":{"line":1},"extra":{}},
 {"check_id":"absolute.path","path":"/etc/passwd","start":{"line":1},"end":{"line":1},"extra":{}},
 {"check_id":"","path":"a.py","start":{"line":1},"end":{"line":1},"extra":{}}
],"errors":[]}`

func TestParseReadsResultsAndDropsUnlocatableOnes(t *testing.T) {
	findings, err := Parse(strings.NewReader(sampleOutput))

	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %d, err = %v; want 2", len(findings), err)
	}
	sqli := findings[0]
	if sqli.Kind != finding.Static || sqli.Source != "semgrep" || sqli.Title != "tainted sql string" ||
		sqli.Severity != finding.SeverityHigh || sqli.Target != "app/views.py:4" || sqli.Status != finding.Candidate {
		t.Fatalf("finding = %+v", sqli)
	}
	if *sqli.Location != (finding.Location{File: "app/views.py", Line: 4, EndLine: 4}) {
		t.Fatalf("location = %+v", *sqli.Location)
	}
	if !slices.Equal(sqli.CWE, []string{"cwe-89"}) || !slices.Equal(sqli.Tags, []string{"security"}) || sqli.Description == "" {
		t.Fatalf("cwe = %v, tags = %v", sqli.CWE, sqli.Tags)
	}
	wantTrace := []finding.TraceStep{
		{Role: "source", File: "app/views.py", Line: 2, Content: "request.args.get('id')"},
		{Role: "propagation", File: "app/views.py", Line: 2, Content: "order_id"},
		{Role: "sink", File: "app/views.py", Line: 4, Content: "db.execute(query)"},
	}
	if !slices.Equal(sqli.Evidence.Trace, wantTrace) {
		t.Fatalf("trace = %+v", sqli.Evidence.Trace)
	}
	secret := findings[1]
	if secret.Location.File != "config.py" || secret.Location.EndLine != 1 || secret.Severity != finding.SeverityMedium ||
		!slices.Equal(secret.CWE, []string{"cwe-798"}) || secret.Evidence.Trace != nil {
		t.Fatalf("second finding = %+v, location = %+v", secret, *secret.Location)
	}
	if sqli.ID == secret.ID || sqli.ID == "" {
		t.Fatal("IDs are missing or collide")
	}
}

func TestParseToleratesOddShapesAndRejectsNonJSON(t *testing.T) {
	odd := `{"results":[{"check_id":"r","path":"a.py","start":{"line":3},"end":{"line":3},
	  "extra":{"severity":"UNKNOWN","metadata":{"cwe":42},
	   "dataflow_trace":{"taint_source":["CliCall",[1,2,3]],"taint_sink":"nope","intermediate_vars":[]}}}]}`
	findings, err := Parse(strings.NewReader(odd))
	if err != nil || len(findings) != 1 || len(findings[0].Evidence.Trace) != 0 || len(findings[0].CWE) != 0 ||
		findings[0].Severity != finding.SeverityUnknown {
		t.Fatalf("findings = %+v, err = %v", findings, err)
	}
	if _, err := Parse(strings.NewReader("Scanning...")); err == nil {
		t.Fatal("non-JSON output was accepted")
	}
	for raw, want := range map[string]finding.Severity{"CRITICAL": finding.SeverityCritical, "high": finding.SeverityHigh, "Info": finding.SeverityLow, "LOW": finding.SeverityLow} {
		if got := severity(raw); got != want {
			t.Errorf("severity(%q) = %s", raw, got)
		}
	}
}

// sourceTree writes a small project and returns its root.
func sourceTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	views := "def order():\n    order_id = request.args.get('id')\n    query = \"SELECT * FROM orders WHERE id = \" + order_id\n    return db.execute(query)\n\n# end\n"
	if err := os.WriteFile(filepath.Join(root, "app", "views.py"), []byte(views), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.py"), []byte("KEY = 'x'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
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

func newScanner(t *testing.T, runner sandbox.Runner) *Scanner {
	t.Helper()
	return &Scanner{
		Runner: runner, Image: "vajra-semgrep:local", SourceRoot: sourceTree(t),
		RulesImagePath: "/opt/semgrep-rules", AssetURL: "https://app.test", Timeout: time.Minute,
	}
}

func TestScanRunsOfflineOnAReadOnlyTreeAndAddsContext(t *testing.T) {
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(sampleOutput), ExitCode: 1}}
	s := newScanner(t, runner)

	findings, err := s.Scan(context.Background())

	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %d, err = %v", len(findings), err)
	}
	spec := runner.specs[0]
	if spec.Network != sandbox.NetworkNone || spec.Entrypoint != "semgrep" || spec.Workdir != "/src" {
		t.Fatalf("spec = %+v", spec)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0] != (sandbox.Mount{Source: s.SourceRoot, Target: "/src"}) {
		t.Fatalf("mounts = %+v", spec.Mounts)
	}
	if err := spec.Validate(); err != nil {
		// Defaults are applied by the runner; only the fields set here matter.
		if !strings.Contains(err.Error(), "user") {
			t.Fatalf("the spec is not runnable: %v", err)
		}
	}
	joined := strings.Join(spec.Argv, " ")
	for _, want := range []string{"scan --json", "--metrics=off", "--disable-version-check", "--config /opt/semgrep-rules", " ."} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv is missing %q: %s", want, joined)
		}
	}
	sqli := findings[0]
	if sqli.AssetURL != "https://app.test" {
		t.Fatalf("asset URL = %q", sqli.AssetURL)
	}
	if !strings.Contains(sqli.Evidence.Code, ">     4 |     return db.execute(query)") ||
		!strings.Contains(sqli.Evidence.Code, "      2 |     order_id = request.args.get('id')") {
		t.Fatalf("code context = %q", sqli.Evidence.Code)
	}
}

func TestScanMountsHostRulesReadOnly(t *testing.T) {
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(`{"results":[]}`)}}
	s := newScanner(t, runner)
	s.RulesImagePath, s.RulesHostDir = "", "/srv/rules"

	if _, err := s.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	spec := runner.specs[0]
	if len(spec.Mounts) != 2 || spec.Mounts[1] != (sandbox.Mount{Source: "/srv/rules", Target: "/rules"}) {
		t.Fatalf("mounts = %+v", spec.Mounts)
	}
	if !strings.Contains(strings.Join(spec.Argv, " "), "--config /rules") {
		t.Fatalf("argv = %v", spec.Argv)
	}
}

func TestRunFailuresAreErrorsNotCleanScans(t *testing.T) {
	cases := map[string]fakeRunner{
		"sandbox error": {err: errors.New("docker unavailable")},
		"timeout":       {result: sandbox.Result{TimedOut: true}},
		"fatal exit":    {result: sandbox.Result{ExitCode: 2, Stderr: []byte("invalid rule")}},
		"truncated":     {result: sandbox.Result{Truncated: true, Stdout: []byte(sampleOutput)}},
		"not json":      {result: sandbox.Result{Stdout: []byte("oops")}},
	}
	for name, runner := range cases {
		t.Run(name, func(t *testing.T) {
			r := runner
			if _, err := newScanner(t, &r).Scan(context.Background()); err == nil {
				t.Fatal("Scan succeeded")
			}
		})
	}
}

func TestReproduceReanalysesOneFileAndMatchesRuleAndLine(t *testing.T) {
	runner := &fakeRunner{result: sandbox.Result{Stdout: []byte(sampleOutput)}}
	s := newScanner(t, runner)
	f := finding.Finding{RuleID: "python.flask.security.injection.tainted-sql-string", Location: &finding.Location{File: "app/views.py", Line: 4}}

	matched, err := s.Reproduce(context.Background(), f)

	if err != nil || !matched {
		t.Fatalf("matched = %v, err = %v", matched, err)
	}
	if argv := runner.specs[0].Argv; argv[len(argv)-1] != "./app/views.py" {
		t.Fatalf("target = %q; want the one file, prefixed so it cannot be read as a flag", argv[len(argv)-1])
	}
	for name, mutate := range map[string]func(*finding.Finding){
		"another line": func(f *finding.Finding) { f.Location = &finding.Location{File: "app/views.py", Line: 9} },
		"another rule": func(f *finding.Finding) { f.RuleID = "other.rule" },
		"another file": func(f *finding.Finding) { f.Location = &finding.Location{File: "app/other.py", Line: 4} },
	} {
		g := f
		mutate(&g)
		if matched, err := s.Reproduce(context.Background(), g); err != nil || matched {
			t.Errorf("%s: matched = %v, err = %v", name, matched, err)
		}
	}
}

func TestReproduceRejectsUnusableLocationsWithoutRunning(t *testing.T) {
	for name, loc := range map[string]*finding.Location{
		"none": nil, "escaping": {File: "../../etc/passwd", Line: 1}, "absolute": {File: "/etc/passwd", Line: 1},
	} {
		runner := &fakeRunner{}
		if _, err := newScanner(t, runner).Reproduce(context.Background(), finding.Finding{RuleID: "r", Location: loc}); err == nil {
			t.Errorf("%s: Reproduce succeeded", name)
		}
		if len(runner.specs) != 0 {
			t.Errorf("%s: a sandbox was started", name)
		}
	}
	runner := &fakeRunner{err: errors.New("docker unavailable")}
	if _, err := newScanner(t, runner).Reproduce(context.Background(), finding.Finding{RuleID: "r", Location: &finding.Location{File: "a.py", Line: 1}}); err == nil {
		t.Error("a sandbox error was swallowed")
	}
}

func TestValidate(t *testing.T) {
	mutations := map[string]func(*Scanner){
		"runner":          func(s *Scanner) { s.Runner = nil },
		"image":           func(s *Scanner) { s.Image = "" },
		"relative source": func(s *Scanner) { s.SourceRoot = "src" },
		"unclean source":  func(s *Scanner) { s.SourceRoot = "/srv/../etc" },
		"no rules":        func(s *Scanner) { s.RulesImagePath = "" },
		"both rules":      func(s *Scanner) { s.RulesHostDir = "/srv/rules" },
		"relative rules":  func(s *Scanner) { s.RulesImagePath = "rules" },
		"timeout":         func(s *Scanner) { s.Timeout = 0 },
	}
	for name, mutate := range mutations {
		s := newScanner(t, &fakeRunner{})
		mutate(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
		if _, err := s.Scan(context.Background()); err == nil {
			t.Errorf("%s: Scan ran", name)
		}
	}
}

func TestReadContextIsConfinedToTheSourceRoot(t *testing.T) {
	root := sourceTree(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOP SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.py")); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", maxLineChars*2) + "\n"
	if err := os.WriteFile(filepath.Join(root, "long.py"), []byte(long), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := map[string]*finding.Location{
		"symlink out of the tree": {File: "link.py", Line: 1},
		"parent path":             {File: "../secret.txt", Line: 1},
		"absolute path":           {File: outside, Line: 1},
		"missing file":            {File: "nope.py", Line: 1},
		"line past the end":       {File: "config.py", Line: 99},
		"line zero":               {File: "config.py", Line: 0},
		"no location":             nil,
	}
	for name, loc := range cases {
		if got := readContext(root, loc); got != "" {
			t.Errorf("%s: context = %q; want none", name, got)
		}
	}
	if got := readContext(filepath.Join(root, "missing-root"), &finding.Location{File: "config.py", Line: 1}); got != "" {
		t.Errorf("missing root: context = %q", got)
	}
	if got := readContext(root, &finding.Location{File: "config.py", Line: 1}); got != ">     1 | KEY = 'x'\n" {
		t.Errorf("context = %q", got)
	}
	if got := readContext(root, &finding.Location{File: "long.py", Line: 1}); !strings.Contains(got, "[line truncated]") || len(got) > maxLineChars+60 {
		t.Errorf("a long line was not truncated: %d bytes", len(got))
	}
	ranged := readContext(root, &finding.Location{File: "app/views.py", Line: 2, EndLine: 3})
	if strings.Count(ranged, "\n>") != 2 || !strings.HasPrefix(ranged, "      1 |") || !strings.Contains(ranged, ">     3 |") {
		t.Errorf("multi-line context = %q", ranged)
	}
}
