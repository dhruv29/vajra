package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/config"
)

const (
	// inScopeResult is scanner output the idle runner cannot reproduce, which
	// leaves a finding that still needs attention.
	inScopeResult = `{"template-id":"x","matched-at":"https://app.test/a","request":"r","response":"s"}` + "\n"
	notifyConfig  = `"notify": {"webhook_url_env": "VAJRA_TEST_WEBHOOK", "allow_private": true},`
)

func withNotify(cfg string) string {
	return strings.Replace(cfg, `"targets":`, notifyConfig+"\n  "+`"targets":`, 1)
}

func savedRunID(t *testing.T, stderr string) string {
	t.Helper()
	_, after, found := strings.Cut(stderr, "saved run ")
	if !found {
		t.Fatalf("no saved run in %q", stderr)
	}
	return strings.TrimSpace(strings.SplitN(after, "\n", 2)[0])
}

func TestScanFlagsThatNeedASavedRunAreRejectedWithoutOne(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	in := writeFile(t, "empty.jsonl", "")
	data := t.TempDir()
	cases := map[string][]string{
		"scan baseline without data":     {"scan", "-config", cfg, "-baseline", unknownRunID},
		"verify baseline without data":   {"verify", "-config", cfg, "-in", in, "-baseline", unknownRunID},
		"notify without data":            {"scan", "-config", cfg, "-notify"},
		"fail-on-new without a baseline": {"scan", "-config", cfg, "-data", data, "-fail-on-new"},
		"unknown baseline":               {"verify", "-config", cfg, "-in", in, "-data", data, "-baseline", unknownRunID},
		"malformed baseline":             {"verify", "-config", cfg, "-in", in, "-data", data, "-baseline", malformedRunID},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := invoke(args...)
			if code != exitError || stderr == "" || stdout != "" || strings.Contains(stderr, "saved run") {
				t.Fatalf("code = %d, stdout = %q, stderr = %q; want a refusal before anything runs", code, stdout, stderr)
			}
		})
	}
}

func TestVerifyComparesTheRunWithABaseline(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	data := t.TempDir()
	_, _, stderr := invoke("verify", "-config", cfg, "-in", writeFile(t, "empty.jsonl", ""), "-data", data)
	baseline := savedRunID(t, stderr)
	in := writeFile(t, "out.jsonl", inScopeResult)

	code, stdout, stderr := invoke("verify", "-config", cfg, "-in", in, "-data", data, "-baseline", baseline)
	if code != exitOK || stdout != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	for _, want := range []string{"### Vajra run comparison", "Base " + baseline, "**1 new**, 0 resolved, 0 persisting"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in:\n%s", want, stderr)
		}
	}
	head := savedRunID(t, stderr)

	if code, _, stderr := invoke("verify", "-config", cfg, "-in", in, "-data", data, "-baseline", baseline, "-fail-on-new"); code != exitConfirmed {
		t.Fatalf("-fail-on-new: code = %d, stderr = %q", code, stderr)
	}
	// The same finding again is not new, so the gate passes.
	code, _, stderr = invoke("verify", "-config", cfg, "-in", in, "-data", data, "-baseline", head, "-fail-on-new")
	if code != exitOK || !strings.Contains(stderr, "**0 new**, 0 resolved, 1 persisting") {
		t.Fatalf("unchanged: code = %d, stderr = %q", code, stderr)
	}
}

func TestNotifyPostsASummaryOfTheSavedRun(t *testing.T) {
	var posts atomic.Int32
	var body atomic.Value
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body.Store(string(raw))
		posts.Add(1)
	}))
	defer hook.Close()
	deps := newDeps()
	deps.Getenv = func(name string) string { return map[string]string{"VAJRA_TEST_WEBHOOK": hook.URL + "/hook"}[name] }
	useDeps(t, deps)
	cfg := writeFile(t, "run.json", withNotify(validConfig))
	in := writeFile(t, "empty.jsonl", "")

	code, _, stderr := invoke("verify", "-config", cfg, "-in", in, "-data", t.TempDir(), "-notify")

	if code != exitOK || posts.Load() != 1 || !strings.Contains(stderr, "sent a summary of run "+savedRunID(t, stderr)) {
		t.Fatalf("code = %d, posts = %d, stderr = %q", code, posts.Load(), stderr)
	}
	if sent, _ := body.Load().(string); !strings.Contains(sent, savedRunID(t, stderr)) {
		t.Fatalf("posted body = %q", sent)
	}
}

func TestAFailedNotificationIsOnlyAWarning(t *testing.T) {
	in := writeFile(t, "empty.jsonl", "")
	for name, content := range map[string]string{
		"webhook variable not set": withNotify(validConfig),
		"nothing configured":       validConfig,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := writeFile(t, "run.json", content)
			data := t.TempDir()

			code, _, stderr := invoke("verify", "-config", cfg, "-in", in, "-data", data, "-notify")

			if code != exitOK || !strings.Contains(stderr, "warning: the run was saved but the notification was not sent") {
				t.Fatalf("code = %d, stderr = %q", code, stderr)
			}
			if code, stdout, _ := invoke("runs", "-data", data); code != exitOK || !strings.Contains(stdout, savedRunID(t, stderr)) {
				t.Fatalf("the run was not saved: %q", stdout)
			}
		})
	}
}

func TestScanClearsAStaleStopRequestAndSavesTheRun(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	data := filepath.Join(t.TempDir(), "not-created-yet")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invoke("stop", "-data", data); code != exitOK {
		t.Fatalf("stop: code = %d, stderr = %q", code, stderr)
	}

	code, _, stderr := invoke("scan", "-config", cfg, "-data", data)

	if code != exitOK || !strings.Contains(stderr, "saved run ") {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if stopRequested(data)() {
		t.Fatal("the stale stop file survived the start of a scan")
	}
}

func TestOperatorControlsFollowTheConfigurationAndTheDataDirectory(t *testing.T) {
	ask := config.Config{Agent: &config.Agent{UnsafeRequests: config.UnsafeAsk}}
	deny := config.Config{Agent: &config.Agent{UnsafeRequests: config.UnsafeDeny}}

	t.Run("no data directory and no agent leaves the defaults", func(t *testing.T) {
		deps, err := withOperatorControls(app.Deps{}, config.Config{}, "", strings.NewReader(""), io.Discard)
		if err != nil || deps.Approve != nil || deps.Stop != nil {
			t.Fatalf("approve set = %v, stop set = %v, err = %v", deps.Approve != nil, deps.Stop != nil, err)
		}
	})
	t.Run("deny never prompts", func(t *testing.T) {
		deps, err := withOperatorControls(app.Deps{}, deny, "", strings.NewReader("y\n"), io.Discard)
		if err != nil || deps.Approve != nil {
			t.Fatalf("approve set = %v, err = %v", deps.Approve != nil, err)
		}
	})
	t.Run("ask prompts on the terminal", func(t *testing.T) {
		var prompt bytes.Buffer
		deps, err := withOperatorControls(app.Deps{}, ask, "", strings.NewReader("y\n"), &prompt)
		if err != nil || deps.Approve == nil || deps.Stop != nil {
			t.Fatalf("approve set = %v, stop set = %v, err = %v", deps.Approve != nil, deps.Stop != nil, err)
		}
		if ok, err := deps.Approve(context.Background(), "DELETE https://app.test/items/1"); !ok || err != nil {
			t.Fatalf("approved = %v, err = %v", ok, err)
		}
		if prompt.String() != "Allow the explorer to send: DELETE https://app.test/items/1? [y/N] " {
			t.Fatalf("prompt = %q", prompt.String())
		}
	})
	t.Run("a data directory is created and watched for a stop request", func(t *testing.T) {
		data := filepath.Join(t.TempDir(), "data")
		deps, err := withOperatorControls(app.Deps{}, config.Config{}, data, strings.NewReader(""), io.Discard)
		if err != nil || deps.Stop == nil || deps.Stop() {
			t.Fatalf("stop set = %v, err = %v", deps.Stop != nil, err)
		}
		if code, _, stderr := invoke("stop", "-data", data); code != exitOK {
			t.Fatalf("stop: code = %d, stderr = %q", code, stderr)
		}
		if !deps.Stop() {
			t.Fatal("the stop request was not seen")
		}
	})
	t.Run("an unusable data directory is an error", func(t *testing.T) {
		file := writeFile(t, "plain-file", "")
		if _, err := withOperatorControls(app.Deps{}, config.Config{}, file, strings.NewReader(""), io.Discard); err == nil {
			t.Fatal("a file was accepted as a data directory")
		}
	})
}

func TestTerminalApproverAllowsOnlyAnExplicitYes(t *testing.T) {
	cases := map[string]struct {
		input string
		want  bool
	}{
		"y":                    {"y\n", true},
		"yes":                  {"yes\n", true},
		"upper case and space": {"  YES \r\n", true},
		"n":                    {"n\n", false},
		"empty line":           {"\n", false},
		"something else":       {"yep\n", false},
		"end of input":         {"", false},
		"unfinished line":      {"y", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			approve := terminalApprover(strings.NewReader(tc.input), io.Discard)
			got, err := approve(context.Background(), "POST https://app.test/a")
			if got != tc.want || err != nil {
				t.Fatalf("approved = %v, err = %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestTerminalApproverReadsOneLinePerQuestion(t *testing.T) {
	var prompt bytes.Buffer
	approve := terminalApprover(strings.NewReader("y\nn\n"), &prompt)

	first, _ := approve(context.Background(), "POST https://app.test/a")
	second, _ := approve(context.Background(), "DELETE https://app.test/b\r\x1b[2KGET https://app.test/harmless")
	third, _ := approve(context.Background(), "PUT https://app.test/c")

	if !first || second || third {
		t.Fatalf("answers = %v, %v, %v; want yes, no, and no once the input ends", first, second, third)
	}
	if strings.ContainsAny(prompt.String(), "\r\x1b") || !strings.Contains(prompt.String(), "DELETE https://app.test/b  [2KGET") {
		t.Fatalf("control characters reached the terminal: %q", prompt.String())
	}
}

func TestTerminalApproverGivesUpWhenTheScanIsCancelled(t *testing.T) {
	terminal, keyboard := io.Pipe()
	defer keyboard.Close()
	approve := terminalApprover(terminal, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if ok, err := approve(ctx, "POST https://app.test/a"); ok || err == nil {
		t.Fatalf("approved = %v, err = %v; want a refusal with the cancellation", ok, err)
	}

	// The read the cancelled question left behind serves the next question.
	go keyboard.Write([]byte("yes\n"))
	if ok, err := approve(context.Background(), "POST https://app.test/b"); !ok || err != nil {
		t.Fatalf("approved = %v, err = %v", ok, err)
	}
}

// listeningAddr waits for a "listening" line with the given prefix and
// returns the address on it.
func listeningAddr(t *testing.T, stderr *lockedBuffer, prefix string) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, after, found := strings.Cut(stderr.String(), prefix); found && strings.Contains(after, "\n") {
			return strings.TrimSpace(strings.SplitN(after, "\n", 2)[0])
		}
	}
	t.Fatalf("no %q in %q", prefix, stderr.String())
	return ""
}

func TestGateAlsoServesSOCKSAndStopsOnCancel(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"gate", "-config", cfg, "-listen", "127.0.0.1:0", "-socks", "127.0.0.1:0", "-audit", audit}, &bytes.Buffer{}, stderr)
	}()

	proxy := listeningAddr(t, stderr, "egress gate listening on ")
	socks := listeningAddr(t, stderr, "egress gate listening for SOCKS5 on ")
	if proxy == socks {
		t.Fatalf("both front ends report %s", proxy)
	}
	for _, addr := range []string{proxy, socks} {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("%s is not accepting connections: %v", addr, err)
		}
		conn.Close()
	}
	cancel()

	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("code = %d, stderr = %q", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the gate did not stop after cancellation")
	}
	for _, addr := range []string{proxy, socks} {
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			t.Errorf("%s is still listening after the gate stopped", addr)
		}
	}
}

func TestGateReleasesTheProxyPortWhenSOCKSCannotListen(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"gate", "-config", cfg, "-listen", "127.0.0.1:0", "-socks", taken.Addr().String()}, &bytes.Buffer{}, &stderr)

	if code != exitError {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	_, after, _ := strings.Cut(stderr.String(), "egress gate listening on ")
	proxy := strings.TrimSpace(strings.SplitN(after, "\n", 2)[0])
	if conn, err := net.DialTimeout("tcp", proxy, time.Second); err == nil {
		conn.Close()
		t.Fatalf("the proxy port %s was left open", proxy)
	}
}

func TestPauseAndResumeToggleTheFileTheExplorerWatches(t *testing.T) {
	data := t.TempDir()
	paused := fileExists(filepath.Join(data, pauseFileName))

	if code, stdout, stderr := invoke("pause", "-data", data); code != exitOK || !strings.Contains(stdout, "waits") {
		t.Fatalf("pause: code = %d, stderr = %q", code, stderr)
	}
	if !paused() {
		t.Fatal("pause did not create the file")
	}
	if info, _ := os.Stat(filepath.Join(data, pauseFileName)); info.Mode().Perm() != 0o600 {
		t.Fatalf("pause file mode = %v", info.Mode().Perm())
	}
	if code, _, _ := invoke("pause", "-data", data); code != exitOK {
		t.Fatal("pausing twice failed")
	}
	if code, _, _ := invoke("resume", "-data", data); code != exitOK || paused() {
		t.Fatal("resume did not remove the file")
	}
	if code, _, _ := invoke("resume", "-data", data); code != exitOK {
		t.Fatal("resuming when not paused failed")
	}
	for _, args := range [][]string{{"pause"}, {"resume"}, {"pause", "-data", filepath.Join(data, "missing")}} {
		if code, _, stderr := invoke(args...); code == exitOK || stderr == "" {
			t.Errorf("%v: code = %d", args, code)
		}
	}
}
