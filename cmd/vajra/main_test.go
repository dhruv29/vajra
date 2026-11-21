package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfig = `{
  "authorization": {"operator": "sec-team@example.test", "statement": "Approved in CHG-1"},
  "scope": {"hosts": ["app.test"]},
  "budget": {"tokens": 100000, "turns": 50, "sandbox_runs": 20, "duration_seconds": 1800},
  "targets": ["https://app.test"],
  "sandbox": {"network": "vajra-task-net", "proxy_url": "http://gate:3128"},
  "nuclei": {"image": "vajra-nuclei:local", "templates_dir": "/opt/nuclei-templates", "timeout_seconds": 900}
}`

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
