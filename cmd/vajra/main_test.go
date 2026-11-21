package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/sandbox"
)

const validConfig = `{
  "authorization": {"operator": "sec-team@example.test", "statement": "Approved in CHG-1"},
  "scope": {"hosts": ["app.test"]},
  "budget": {"tokens": 100000, "turns": 50, "sandbox_runs": 20, "duration_seconds": 1800},
  "targets": ["https://app.test"],
  "sandbox": {"network": "vajra-task-net", "proxy_url": "http://gate:3128"},
  "nuclei": {"image": "vajra-nuclei:local", "templates_dir": "/opt/nuclei-templates", "timeout_seconds": 900}
}`

// idleRunner stands in for Docker: no test here reaches a real scan.
type idleRunner struct{}

func (idleRunner) Run(context.Context, sandbox.Spec) (sandbox.Result, error) {
	return sandbox.Result{}, nil
}

func TestMain(m *testing.M) {
	newDeps = func() app.Deps {
		return app.Deps{
			Runner:       idleRunner{},
			CheckNetwork: func(context.Context, string) error { return nil },
			Getenv:       func(string) string { return "" },
		}
	}
	os.Exit(m.Run())
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func invoke(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestUsageErrors(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	cases := map[string][]string{
		"no command":          {},
		"unknown command":     {"attack"},
		"scan without config": {"scan"},
		"verify without -in":  {"verify", "-config", cfg},
		"unknown flag":        {"scan", "-nope"},
		"gate without config": {"gate"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := invoke(args...)
			if code == exitOK || stderr == "" {
				t.Fatalf("code = %d, stderr = %q; want a failure with a message", code, stderr)
			}
		})
	}
}

func TestHelpPrintsUsage(t *testing.T) {
	code, stdout, _ := invoke("help")
	if code != exitOK || !strings.Contains(stdout, "vajra scan") {
		t.Fatalf("code = %d, stdout = %q", code, stdout)
	}
	if code, _, _ := invoke("scan", "-h"); code != exitUsage {
		t.Fatalf("scan -h exit code = %d", code)
	}
}

func TestBadConfigIsRejectedBeforeAnythingRuns(t *testing.T) {
	outOfScope := strings.Replace(validConfig, `["https://app.test"]`, `["https://elsewhere.test"]`, 1)
	for name, content := range map[string]string{"out-of-scope target": outOfScope, "not json": "nope"} {
		t.Run(name, func(t *testing.T) {
			cfg := writeFile(t, "run.json", content)
			for _, command := range []string{"scan", "gate"} {
				code, _, stderr := invoke(command, "-config", cfg)
				if code != exitError || !strings.Contains(stderr, "config:") {
					t.Errorf("%s: code = %d, stderr = %q", command, code, stderr)
				}
			}
		})
	}
	if code, _, _ := invoke("scan", "-config", filepath.Join(t.TempDir(), "missing.json")); code != exitError {
		t.Errorf("missing config: code = %d", code)
	}
}

func TestVerifyWritesAPrivateReportForEmptyInput(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	in := writeFile(t, "empty.jsonl", "")
	out := filepath.Join(t.TempDir(), "report.json")

	code, _, stderr := invoke("verify", "-config", cfg, "-in", in, "-out", out, "-fail-on-confirmed")

	if code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "0 confirmed") {
		t.Fatalf("stderr = %q", stderr)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %v; want 0600", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), `"tool": "vajra"`) || !strings.Contains(string(raw), "sec-team@example.test") {
		t.Fatalf("report = %s", raw)
	}
}

func TestVerifyPrintsTheReportAndReportsAMissingInput(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	in := writeFile(t, "empty.jsonl", "")

	code, stdout, _ := invoke("verify", "-config", cfg, "-in", in)
	if code != exitOK || !strings.Contains(stdout, `"findings"`) {
		t.Fatalf("code = %d, stdout = %q", code, stdout)
	}
	if code, _, _ := invoke("verify", "-config", cfg, "-in", filepath.Join(t.TempDir(), "none.jsonl")); code != exitError {
		t.Fatalf("missing input: code = %d", code)
	}
}

func TestGateStartsAuditsToAFileAndStopsOnCancel(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"gate", "-config", cfg, "-listen", "127.0.0.1:0", "-audit", audit}, &bytes.Buffer{}, &stderr)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("code = %d, stderr = %q", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gate did not stop after cancellation")
	}
	if info, err := os.Stat(audit); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("audit file: %v, %v", info, err)
	}
	if code, _, _ := invoke("gate", "-config", cfg, "-listen", "not-an-address"); code != exitError {
		t.Fatalf("bad listen address: code = %d", code)
	}
}

func TestSavedRunsCanBeListedAndRendered(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	in := writeFile(t, "out.jsonl", `{"template-id":"x","matched-at":"https://elsewhere.test/a","request":"r","response":"s"}`+"\n")
	audit := writeFile(t, "audit.jsonl", `{"time":"2999-01-01T00:00:00Z","method":"GET","target":"app.test:443","allowed":true}`+"\n")
	data := t.TempDir()

	if code, stdout, _ := invoke("runs", "-data", data); code != exitOK || !strings.Contains(stdout, "no saved runs") {
		t.Fatalf("empty list: code = %d, stdout = %q", code, stdout)
	}
	code, stdout, stderr := invoke("verify", "-config", cfg, "-in", in, "-data", data, "-gate-audit", audit)
	if code != exitOK || stdout != "" || !strings.Contains(stderr, "saved run ") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	id := strings.TrimSpace(strings.SplitN(strings.SplitN(stderr, "saved run ", 2)[1], "\n", 2)[0])

	code, stdout, _ = invoke("runs", "-data", data)
	if code != exitOK || !strings.Contains(stdout, id) || !strings.Contains(stdout, "https://app.test") {
		t.Fatalf("list: code = %d, stdout = %q", code, stdout)
	}
	for format, want := range map[string]string{"html": "<!doctype html>", "md": "| out of scope | 1 |", "json": `"reach"`} {
		code, stdout, stderr := invoke("report", "-data", data, "-run", id, "-format", format)
		if code != exitOK || !strings.Contains(stdout, want) {
			t.Errorf("%s: code = %d, stderr = %q, missing %q", format, code, stderr, want)
		}
	}
	out := filepath.Join(t.TempDir(), "report.html")
	if code, _, _ := invoke("report", "-data", data, "-run", id, "-out", out); code != exitOK {
		t.Fatalf("report -out: code = %d", code)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
		t.Fatalf("report file: %v, %v", info, err)
	}
}

func TestReportAndRunsUsageErrors(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	data := t.TempDir()
	cases := map[string][]string{
		"runs without data":    {"runs"},
		"report without run":   {"report", "-data", data},
		"report unknown run":   {"report", "-data", data, "-run", "20261121-195440-0a1b2c3d"},
		"report malformed run": {"report", "-data", data, "-run", "../../etc/passwd"},
		"audit without data":   {"verify", "-config", cfg, "-in", cfg, "-gate-audit", cfg},
		"missing audit file":   {"verify", "-config", cfg, "-in", writeFile(t, "e.jsonl", ""), "-data", data, "-gate-audit", "/nonexistent/audit"},
	}
	for name, args := range cases {
		if code, _, stderr := invoke(args...); code == exitOK || stderr == "" {
			t.Errorf("%s: code = %d, stderr = %q", name, code, stderr)
		}
	}
}

// lockedBuffer lets the test read what a running command has written so far.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServeOpensTheInterfaceOnLoopbackWithAToken(t *testing.T) {
	data := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve", "-data", data, "-listen", "127.0.0.1:0"}, &bytes.Buffer{}, stderr)
	}()

	var link string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, after, found := strings.Cut(stderr.String(), "vajra: open "); found && strings.Contains(after, "\n") {
			link = strings.TrimSpace(strings.SplitN(after, "\n", 2)[0])
			break
		}
	}
	base, token, found := strings.Cut(link, "/#token=")
	if !found || len(token) != 64 {
		t.Fatalf("link = %q", link)
	}

	page, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	page.Body.Close()
	denied, _ := http.Get(base + "/api/runs")
	denied.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/runs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	allowed, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	allowed.Body.Close()

	if page.StatusCode != http.StatusOK || denied.StatusCode != http.StatusUnauthorized || allowed.StatusCode != http.StatusOK {
		t.Fatalf("page = %d, without token = %d, with token = %d", page.StatusCode, denied.StatusCode, allowed.StatusCode)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("code = %d, stderr = %q", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after cancellation")
	}
}

func TestServeRefusesNonLoopbackAndMissingData(t *testing.T) {
	data := t.TempDir()
	for name, args := range map[string][]string{
		"all interfaces": {"serve", "-data", data, "-listen", "0.0.0.0:8700"},
		"lan address":    {"serve", "-data", data, "-listen", "192.168.1.5:8700"},
		"no data":        {"serve"},
	} {
		if code, _, stderr := invoke(args...); code != exitError || stderr == "" {
			t.Errorf("%s: code = %d, stderr = %q", name, code, stderr)
		}
	}
}

func TestDemoSavesASampleRunThatCanBeReported(t *testing.T) {
	data := t.TempDir()

	code, stdout, stderr := invoke("demo", "-data", data)

	if code != exitOK || !strings.Contains(stdout, "saved sample run ") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	id := strings.SplitN(strings.SplitN(stdout, "saved sample run ", 2)[1], ";", 2)[0]
	if code, md, _ := invoke("report", "-data", data, "-run", id, "-format", "md"); code != exitOK || !strings.Contains(md, "| confirmed | 4 |") {
		t.Fatalf("report: code = %d", code)
	}
	if code, _, _ := invoke("demo"); code != exitError {
		t.Fatalf("demo without -data: code = %d", code)
	}
}

func TestReportsOverwriteAnExistingFilePrivately(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	in := writeFile(t, "empty.jsonl", "")
	out := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(out, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := invoke("verify", "-config", cfg, "-in", in, "-out", out); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if info, _ := os.Stat(out); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v; an existing world-readable file must be tightened", info.Mode().Perm())
	}
}
