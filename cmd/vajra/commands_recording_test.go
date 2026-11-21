package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const sessionRecording = `{"log":{"entries":[
 {"request":{"method":"GET","url":"https://app.test/account","headers":[{"name":"Cookie","value":"sid=LIVESESSION"}]}},
 {"request":{"method":"GET","url":"https://app.test/account","headers":[{"name":"Cookie","value":"sid=LIVESESSION"}]}},
 {"request":{"method":"GET","url":"https://app.test/about","headers":[]}},
 {"request":{"method":"POST","url":"https://app.test/transfer","headers":[{"name":"Cookie","value":"sid=LIVESESSION"}]}},
 {"request":{"method":"GET","url":"https://elsewhere.test/pixel","headers":[{"name":"Cookie","value":"sid=LIVESESSION"}]}}
]}}`

func TestRecordingDraftsChecksOnlyForSignedInReadOnlyPagesInScope(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	recording := writeFile(t, "session.har", sessionRecording)
	var stdout, stderr bytes.Buffer

	code := runWith(context.Background(), []string{"recording", "-config", cfg, "-har", recording, "-allow", "alice"}, nil, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var checks []suggestedCheck
	if err := json.Unmarshal(stdout.Bytes(), &checks); err != nil {
		t.Fatalf("output is not JSON: %v: %s", err, stdout.String())
	}
	if len(checks) != 1 || checks[0].URL != "https://app.test/account" || checks[0].Method != "GET" || len(checks[0].Allow) != 1 || checks[0].Allow[0] != "alice" {
		t.Fatalf("checks = %+v; want one check for the account page, allowed to alice", checks)
	}
	if strings.Contains(stdout.String()+stderr.String(), "LIVESESSION") {
		t.Fatal("the recorded session cookie was printed")
	}
	if !strings.Contains(stderr.String(), "1 request(s) outside the scope") || !strings.Contains(stderr.String(), "delete the public ones") {
		t.Fatalf("stderr = %q; want the dropped request counted and the review warning", stderr.String())
	}
}

func TestRecordingNeedsItsInputs(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	notHAR := writeFile(t, "bad.har", "<html>")
	cases := map[string][]string{
		"no flags":       {"recording"},
		"missing file":   {"recording", "-config", cfg, "-har", "/nonexistent/session.har"},
		"not a HAR":      {"recording", "-config", cfg, "-har", notHAR},
		"missing config": {"recording", "-config", "/nonexistent/run.json", "-har", notHAR},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runWith(context.Background(), args, nil, &stdout, &stderr); code == 0 || stdout.Len() != 0 {
				t.Fatalf("exit %d with output %q; want a failure and nothing printed", code, stdout.String())
			}
		})
	}
}
