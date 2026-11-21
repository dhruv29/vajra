package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/store"
)

const baseConfig = `{
  "authorization": {"operator": "sec-team@example.test", "statement": "Approved in CHG-1"},
  "scope": {"hosts": ["app.test"]},
  "budget": {"tokens": 100000, "turns": 50, "sandbox_runs": 20, "duration_seconds": 1800},
  "targets": ["https://app.test"],
  "sandbox": {"network": "vajra-task-net", "proxy_url": "http://gate:3128"},
  "nuclei": {"image": "vajra-nuclei:local", "templates_dir": "/opt/nuclei-templates", "timeout_seconds": 900},
  "refuter": {"provider": "REFUTER"}
}`

func loadConfig(t *testing.T, refuter string) (config.Config, *scope.Policy) {
	t.Helper()
	cfg, policy, err := config.Parse(strings.NewReader(strings.Replace(baseConfig, "REFUTER", refuter, 1)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, policy
}

func line(templateID, severity, matchedAt string) string {
	raw, _ := json.Marshal(map[string]any{
		"template-id": templateID, "info": map[string]string{"name": templateID, "severity": severity},
		"matched-at": matchedAt, "request": "GET / HTTP/1.1", "response": "HTTP/1.1 200 OK",
	})
	return string(raw) + "\n"
}

// scriptedRunner answers the first run (the scan) with scan output, and each
// later run (a reproduction) according to which template was requested.
type scriptedRunner struct {
	scanOutput   string
	reproducible map[string]bool
	staticOutput string
	staticSpecs  []sandbox.Spec
	runs         int
	err          error
}

func (r *scriptedRunner) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	r.runs++
	if r.err != nil {
		return sandbox.Result{}, r.err
	}
	if spec.Entrypoint == "semgrep" {
		r.staticSpecs = append(r.staticSpecs, spec)
		return sandbox.Result{Stdout: []byte(r.staticOutput)}, nil
	}
	if slices.Contains(spec.Argv, "/opt/vajra/canary.yaml") {
		return sandbox.Result{Stdout: []byte(line("vajra-canary", "info", "https://app.test"))}, nil
	}
	for i, arg := range spec.Argv {
		if arg != "-template-id" {
			continue
		}
		id := spec.Argv[i+1]
		if !r.reproducible[id] {
			return sandbox.Result{}, nil
		}
		return sandbox.Result{Stdout: []byte(r.linesFor(id))}, nil
	}
	return sandbox.Result{Stdout: []byte(r.scanOutput)}, nil
}

// linesFor replays the scan output lines for one template, as a re-run that
// matches the same place would.
func (r *scriptedRunner) linesFor(id string) string {
	var out strings.Builder
	for _, l := range strings.SplitAfter(r.scanOutput, "\n") {
		if strings.Contains(l, `"template-id":"`+id+`"`) {
			out.WriteString(l)
		}
	}
	return out.String()
}

// refuterServer plays the model: it disproves any finding whose prompt
// mentions "false-alarm" and supports the rest.
func refuterServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		verdict := "holds"
		if strings.Contains(string(body), "false-alarm") {
			verdict = "refuted"
		}
		_, _ = io.WriteString(w, `{"content":[{"type":"tool_use","name":"record_verdict","input":{"verdict":"`+verdict+
			`","reason":"checked against the response"}}],"usage":{"input_tokens":500,"output_tokens":50}}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func testDeps(runner sandbox.Runner, modelURL string) Deps {
	return Deps{
		Runner:       runner,
		CheckNetwork: func(context.Context, string) error { return nil },
		Getenv:       func(name string) string { return map[string]string{"ANTHROPIC_API_KEY": "test-key"}[name] },
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0) },
		ModelBaseURL: modelURL,
	}
}

func statusByRule(report Report) map[string]finding.Status {
	out := map[string]finding.Status{}
	for _, f := range report.Findings {
		out[f.RuleID] = f.Status
	}
	return out
}

func TestScanVerifiesEveryCandidateAndSortsTheReport(t *testing.T) {
	cfg, policy := loadConfig(t, "anthropic")
	runner := &scriptedRunner{
		scanOutput: line("flaky", "critical", "https://app.test/a") +
			line("real-issue", "medium", "https://app.test/b") +
			line("real-issue", "medium", "https://app.test/b") + // duplicate
			line("false-alarm", "high", "https://app.test/c") +
			line("elsewhere", "high", "https://other.test/d") +
			line("worse-issue", "high", "https://app.test/e"),
		reproducible: map[string]bool{"real-issue": true, "false-alarm": true, "worse-issue": true},
	}

	report, err := Scan(context.Background(), cfg, policy, testDeps(runner, refuterServer(t).URL))

	if err != nil {
		t.Fatal(err)
	}
	want := map[string]finding.Status{
		"real-issue": finding.Confirmed, "worse-issue": finding.Confirmed,
		"flaky": finding.Refuted, "false-alarm": finding.Refuted, "elsewhere": finding.OutOfScope,
	}
	got := statusByRule(report)
	if len(report.Findings) != 5 {
		t.Fatalf("findings = %d; the duplicate must be dropped", len(report.Findings))
	}
	for rule, status := range want {
		if got[rule] != status {
			t.Errorf("%s = %s; want %s", rule, got[rule], status)
		}
	}
	if report.Findings[0].RuleID != "worse-issue" || report.Findings[1].RuleID != "real-issue" {
		t.Errorf("order = %s, %s; want confirmed findings first, most severe first",
			report.Findings[0].RuleID, report.Findings[1].RuleID)
	}
	if report.Summary[finding.Confirmed] != 2 || report.Summary[finding.Refuted] != 2 || report.Summary[finding.OutOfScope] != 1 {
		t.Errorf("summary = %v", report.Summary)
	}
	// 1 scan + flaky (1, stops) + real-issue (2) + false-alarm (2) + worse-issue (2); none for out-of-scope.
	// The miss on "flaky" adds one canary run to check the target answers.
	if runner.runs != 9 || report.Budget.Usage.SandboxRuns != 8 {
		t.Errorf("sandbox runs = %d, charged = %d; want 9 and 8", runner.runs, report.Budget.Usage.SandboxRuns)
	}
	if report.Budget.Usage.Turns != 3 || report.Budget.Usage.Tokens != 3*550 {
		t.Errorf("usage = %+v; want 3 model turns", report.Budget.Usage)
	}
	if report.Tool != "vajra" || report.Authorization.Operator == "" || report.Refuter != "anthropic" || report.GeneratedAt.IsZero() {
		t.Errorf("report header = %+v", report)
	}
}

func TestWithoutARefuterNothingIsConfirmed(t *testing.T) {
	cfg, policy := loadConfig(t, "none")
	runner := &scriptedRunner{
		scanOutput:   line("real-issue", "high", "https://app.test/b"),
		reproducible: map[string]bool{"real-issue": true},
	}

	report, err := Scan(context.Background(), cfg, policy, testDeps(runner, ""))

	if err != nil {
		t.Fatal(err)
	}
	if got := statusByRule(report)["real-issue"]; got != finding.Unconfirmed {
		t.Fatalf("status = %s; a reproduced but unreviewed finding must be unconfirmed", got)
	}
	if report.Budget.Usage.Turns != 0 {
		t.Fatalf("model turns = %d; none is made without a refuter", report.Budget.Usage.Turns)
	}
}

func TestVerifyOutputChecksSavedScannerOutput(t *testing.T) {
	cfg, policy := loadConfig(t, "anthropic")
	saved := line("real-issue", "low", "https://app.test/b") + line("gone", "high", "https://app.test/z")
	runner := &scriptedRunner{scanOutput: saved, reproducible: map[string]bool{"real-issue": true}}

	report, err := VerifyOutput(context.Background(), cfg, policy, testDeps(runner, refuterServer(t).URL), strings.NewReader(saved))

	if err != nil {
		t.Fatal(err)
	}
	got := statusByRule(report)
	if got["real-issue"] != finding.Confirmed || got["gone"] != finding.Refuted {
		t.Fatalf("statuses = %v", got)
	}
	if runner.runs != 4 {
		t.Fatalf("sandbox runs = %d; want 3 reproductions, 1 canary and no scan", runner.runs)
	}
}

func TestScanFailsLoudly(t *testing.T) {
	cfg, policy := loadConfig(t, "anthropic")
	t.Run("scanner error", func(t *testing.T) {
		runner := &scriptedRunner{err: errors.New("docker unavailable")}
		if _, err := Scan(context.Background(), cfg, policy, testDeps(runner, "")); err == nil {
			t.Fatal("a failed scan returned a report")
		}
	})
	t.Run("missing API key", func(t *testing.T) {
		deps := testDeps(&scriptedRunner{}, "")
		deps.Getenv = func(string) string { return "" }
		_, err := Scan(context.Background(), cfg, policy, deps)
		if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
			t.Fatalf("err = %v; want it to name the variable", err)
		}
	})
	t.Run("missing dependencies", func(t *testing.T) {
		if _, err := Scan(context.Background(), cfg, policy, Deps{}); err == nil {
			t.Fatal("Scan ran without a runner")
		}
		if _, err := VerifyOutput(context.Background(), cfg, policy, Deps{}, strings.NewReader("")); err == nil {
			t.Fatal("VerifyOutput ran without a runner")
		}
	})
	t.Run("spent budget", func(t *testing.T) {
		spent := cfg
		spent.Budget.DurationSeconds = 1
		deps := testDeps(&scriptedRunner{}, "")
		start := time.Unix(1_700_000_000, 0)
		calls := 0
		deps.Now = func() time.Time { calls++; return start.Add(time.Duration(calls) * time.Minute) }
		if _, err := Scan(context.Background(), spent, policy, deps); err == nil {
			t.Fatal("Scan ran past its time budget")
		}
	})
}

func TestServeGateEnforcesScopeAndAudits(t *testing.T) {
	policy, err := scope.New(scope.Config{Hosts: []string{"app.test"}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var audit syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeGate(ctx, policy, listener, &audit) }()

	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://not-in-scope.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeGate returned %v after cancellation", err)
	}
	if !strings.Contains(audit.String(), `"allowed":false`) || !strings.Contains(audit.String(), "not-in-scope.test:80") {
		t.Fatalf("audit log = %q", audit.String())
	}
}

func TestServeGateReturnsWhenTheListenerFails(t *testing.T) {
	policy, _ := scope.New(scope.Config{Hosts: []string{"app.test"}})
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	listener.Close()

	if err := ServeGate(context.Background(), policy, listener, io.Discard); err == nil {
		t.Fatal("ServeGate did not report a dead listener")
	}
	if err := ServeGate(context.Background(), nil, listener, io.Discard); err == nil {
		t.Fatal("ServeGate accepted a nil policy")
	}
}

// syncBuffer is a bytes.Buffer safe to write from the server goroutine and
// read from the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestRecordSavesARunWithGraphRadiiAndReach(t *testing.T) {
	cfg, policy := loadConfig(t, "anthropic")
	runner := &scriptedRunner{
		scanOutput:   line("real-issue", "high", "https://app.test/b"),
		reproducible: map[string]bool{"real-issue": true},
	}
	rep, err := Scan(context.Background(), cfg, policy, testDeps(runner, refuterServer(t).URL))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	audit := strings.NewReader(
		`{"time":"2023-11-14T22:00:00Z","method":"GET","target":"earlier-run.test:443","allowed":true}` + "\n" +
			`{"time":"2023-11-14T22:13:25Z","method":"GET","target":"app.test:443","allowed":true}` + "\n")
	started := time.Unix(1_700_000_000, 0) // 2023-11-14T22:13:20Z

	run, err := Record(rep, cfg, audit, started, dir, started.Add(time.Minute))

	if err != nil {
		t.Fatal(err)
	}
	if len(run.Radii) != 1 || run.Radii[0].Score == 0 || run.Reach == nil || run.Reach.AllowedTotal != 1 {
		t.Fatalf("run = %+v", run)
	}
	st, _ := store.Open(dir)
	saved, err := st.Get(run.ID)
	if err != nil || saved.Report.Findings[0].RuleID != "real-issue" {
		t.Fatalf("saved = %+v, err = %v", saved, err)
	}
	for format, want := range map[string]string{"json": `"radii"`, "md": "# Security test report", "html": "<!doctype html>"} {
		out, err := Render(saved, format)
		if err != nil || !strings.Contains(string(out), want) {
			t.Errorf("Render(%s): err = %v, missing %q", format, err, want)
		}
	}
	if _, err := Render(saved, "pdf"); err == nil {
		t.Error("an unknown format was accepted")
	}
}

func TestRecordWithoutAnAuditLogAndWithABadDirectory(t *testing.T) {
	cfg, _ := loadConfig(t, "none")
	run, err := Record(Report{Summary: map[finding.Status]int{}}, cfg, nil, time.Time{}, t.TempDir(), time.Unix(1_700_000_000, 0))
	if err != nil || run.Reach != nil {
		t.Fatalf("run = %+v, err = %v", run, err)
	}
	if _, err := Record(Report{}, cfg, nil, time.Time{}, "", time.Now()); err == nil {
		t.Fatal("an empty data directory was accepted")
	}
}

const staticOutput = `{"results":[
 {"check_id":"rules.sqli","path":"views.py","start":{"line":3},"end":{"line":3},
  "extra":{"message":"Input reaches a query.","severity":"ERROR","metadata":{"cwe":["CWE-89"]}}},
 {"check_id":"rules.false-alarm","path":"views.py","start":{"line":1},"end":{"line":1},
  "extra":{"message":"m","severity":"WARNING","metadata":{"cwe":["CWE-79"]}}},
 {"check_id":"rules.ghost","path":"deleted.py","start":{"line":9},"end":{"line":9},"extra":{"severity":"ERROR"}}
]}`

// staticConfig returns a configuration with a source tree. withTargets keeps
// the live targets too.
func staticConfig(t *testing.T, withTargets bool) (config.Config, *scope.Policy) {
	t.Helper()
	root := t.TempDir()
	code := "def order():\n    q = \"SELECT \" + request.args[\"id\"]\n    return db.execute(q)\n"
	if err := os.WriteFile(filepath.Join(root, "views.py"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	source := `"source": {"root": "` + root + `", "serves": "SERVES",
	  "semgrep": {"image": "vajra-semgrep:local", "rules_image_path": "/opt/rules", "timeout_seconds": 600}},`
	raw := strings.Replace(baseConfig, `"targets":`, source+` "targets":`, 1)
	raw = strings.Replace(raw, "REFUTER", "anthropic", 1)
	if withTargets {
		raw = strings.Replace(raw, "SERVES", "https://app.test", 1)
	} else {
		raw = strings.Replace(raw, `"serves": "SERVES",`, "", 1)
		raw = strings.Replace(raw, `"targets": ["https://app.test"],`, "", 1)
		raw = strings.Replace(raw, `"scope": {"hosts": ["app.test"]},`, "", 1)
	}
	cfg, policy, err := config.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, policy
}

func TestScanAnalysesSourceOfflineAndVerifiesCodeFindings(t *testing.T) {
	cfg, policy := staticConfig(t, false)
	if policy != nil {
		t.Fatal("a code-only configuration produced a network policy")
	}
	runner := &scriptedRunner{staticOutput: staticOutput}

	report, err := Scan(context.Background(), cfg, policy, testDeps(runner, refuterServer(t).URL))

	if err != nil {
		t.Fatal(err)
	}
	got := statusByRule(report)
	want := map[string]finding.Status{
		"rules.sqli": finding.Confirmed, "rules.false-alarm": finding.Refuted, "rules.ghost": finding.Unconfirmed,
	}
	for rule, status := range want {
		if got[rule] != status {
			t.Errorf("%s = %s; want %s", rule, got[rule], status)
		}
	}
	for _, spec := range runner.staticSpecs {
		if spec.Network != sandbox.NetworkNone || spec.Mounts[0].Writable {
			t.Fatalf("the analyser was given a network or a writable tree: %+v", spec)
		}
	}
	// One scan, then one reproduction each for the two findings whose source was readable.
	if len(runner.staticSpecs) != 3 || report.Budget.Usage.SandboxRuns != 3 || report.Budget.Usage.Turns != 2 {
		t.Fatalf("static runs = %d, usage = %+v", len(runner.staticSpecs), report.Budget.Usage)
	}
	if report.SourceRoot != cfg.Source.Root || len(report.Targets) != 0 {
		t.Fatalf("report source = %q, targets = %v", report.SourceRoot, report.Targets)
	}
	for _, f := range report.Findings {
		if f.RuleID == "rules.sqli" && (f.Kind != finding.Static || !strings.Contains(f.Evidence.Code, ">     3 |     return db.execute(q)")) {
			t.Fatalf("code finding = %+v", f)
		}
	}
	if _, err := VerifyOutput(context.Background(), cfg, policy, testDeps(runner, ""), strings.NewReader("")); err == nil {
		t.Fatal("saved live-scanner output was verified without any targets configured")
	}
}

func TestScanCombinesLiveAndCodeFindingsAndLinksCodeToItsService(t *testing.T) {
	cfg, policy := staticConfig(t, true)
	runner := &scriptedRunner{
		scanOutput:   line("real-issue", "high", "https://app.test/b"),
		reproducible: map[string]bool{"real-issue": true},
		staticOutput: staticOutput,
	}

	report, err := Scan(context.Background(), cfg, policy, testDeps(runner, refuterServer(t).URL))

	if err != nil {
		t.Fatal(err)
	}
	got := statusByRule(report)
	if got["real-issue"] != finding.Confirmed || got["rules.sqli"] != finding.Confirmed || len(report.Findings) != 4 {
		t.Fatalf("statuses = %v", got)
	}
	run, err := Record(report, cfg, nil, time.Time{}, t.TempDir(), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.RuleID != "rules.sqli" {
			continue
		}
		radius, _ := run.Radius(f.ID)
		if f.AssetURL != "https://app.test" || radius.OriginID != "service:app.test:443" || radius.Score == 0 {
			t.Fatalf("code finding asset = %q, radius = %+v", f.AssetURL, radius)
		}
	}
}

func TestScanRefusesATaskNetworkThatIsNotClosedOff(t *testing.T) {
	cfg, policy := loadConfig(t, "none")
	runner := &scriptedRunner{scanOutput: line("real-issue", "high", "https://app.test/b")}
	deps := testDeps(runner, "")
	var asked string
	deps.CheckNetwork = func(_ context.Context, name string) error {
		asked = name
		return errors.New("network is not internal")
	}

	_, scanErr := Scan(context.Background(), cfg, policy, deps)
	_, verifyErr := VerifyOutput(context.Background(), cfg, policy, deps, strings.NewReader(""))

	if scanErr == nil || verifyErr == nil || runner.runs != 0 {
		t.Fatalf("scan err = %v, verify err = %v, sandbox runs = %d; nothing may run on an open network", scanErr, verifyErr, runner.runs)
	}
	if asked != "vajra-task-net" {
		t.Fatalf("checked network %q", asked)
	}
	deps.CheckNetwork = nil
	if _, err := Scan(context.Background(), cfg, policy, deps); err == nil {
		t.Fatal("Scan ran live targets without a network check")
	}
}

// timeoutRunner records the timeout each sandbox run was given.
type timeoutRunner struct {
	timeouts []time.Duration
}

func (r *timeoutRunner) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	r.timeouts = append(r.timeouts, spec.Timeout)
	return sandbox.Result{}, nil
}

func TestSandboxRunsAreCutOffAtTheRemainingTimeBudget(t *testing.T) {
	cfg, policy := loadConfig(t, "none")
	cfg.Budget.DurationSeconds = 120 // the scanner's own timeout is 900s
	runner := &timeoutRunner{}

	if _, err := Scan(context.Background(), cfg, policy, testDeps(runner, "")); err != nil {
		t.Fatal(err)
	}
	if len(runner.timeouts) != 1 || runner.timeouts[0] != 120*time.Second {
		t.Fatalf("timeouts = %v; want the run clamped to the 120s budget", runner.timeouts)
	}

	clock := time.Unix(1_700_000_000, 0)
	spent := testDeps(runner, "")
	spent.Now = func() time.Time { return clock }
	r, err := assemble(cfg, policy, spent)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(3 * time.Minute)
	if _, err := r.deps.Runner.Run(context.Background(), sandbox.Spec{Timeout: time.Minute}); !budget.IsExhausted(err) {
		t.Fatalf("err = %v; a sandbox run must be refused once the time budget is spent", err)
	}
}

func TestFindingsOfAnUnconfiguredKindAreMarkedUnconfirmed(t *testing.T) {
	cfg, policy := loadConfig(t, "none")
	r, err := assemble(cfg, policy, testDeps(&scriptedRunner{}, ""))
	if err != nil {
		t.Fatal(err)
	}

	report := r.verify(context.Background(), []finding.Finding{{ID: "s1", Kind: finding.Static, Status: finding.Candidate}})

	f := report.Findings[0]
	if f.Status != finding.Unconfirmed || len(f.Verdicts) != 1 || !strings.Contains(f.Verdicts[0].Reason, "not configured") {
		t.Fatalf("finding = %+v", f)
	}
}
