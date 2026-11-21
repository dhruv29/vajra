package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/sandbox"
)

// gateStub is a forward proxy for plain HTTP that answers from a table,
// standing in for the egress gate and the targets behind it.
func gateStub(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Host {
		case "app.test":
			switch r.URL.Path {
			case "/redirect":
				http.Redirect(w, r, "http://elsewhere.test/", http.StatusFound)
			case "/big":
				_, _ = io.WriteString(w, strings.Repeat("A", MaxBodyBytes+100))
			case "/echo":
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Set-Cookie", "session=abc123")
				fmt.Fprintf(w, "%s %s auth=%s body=%s", r.Method, r.URL.Path, r.Header.Get("Authorization"), body)
			default:
				_, _ = io.WriteString(w, "hello")
			}
		case "down.test":
			w.Header().Set(gateHeader, "failed")
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
		default:
			w.Header().Set(gateHeader, "denied")
			http.Error(w, "blocked by scope policy", http.StatusForbidden)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestExecuteGoesThroughTheGateAndReportsEachOutcome(t *testing.T) {
	gate := gateStub(t)
	client, err := NewClient(gate.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	batch := Batch{Requests: []Request{
		{ID: "ok", Method: "GET", URL: "http://app.test/"},
		{ID: "post", Method: "POST", URL: "http://app.test/echo", Headers: map[string]string{"Authorization": "Bearer t"}, Body: "x=1"},
		{ID: "redirect", Method: "GET", URL: "http://app.test/redirect"},
		{ID: "big", Method: "GET", URL: "http://app.test/big"},
		{ID: "denied", Method: "GET", URL: "http://out-of-scope.test/"},
		{ID: "down", Method: "GET", URL: "http://down.test/"},
	}}

	got := Execute(context.Background(), client, batch).Responses

	if len(got) != 6 {
		t.Fatalf("responses = %d", len(got))
	}
	byID := map[string]Response{}
	for i, r := range got {
		if r.ID != batch.Requests[i].ID {
			t.Fatalf("response %d has ID %q; order must match the requests", i, r.ID)
		}
		byID[r.ID] = r
	}
	if r := byID["ok"]; !r.Answered() || r.Status != 200 || r.Body != "hello" {
		t.Errorf("ok = %+v", r)
	}
	if r := byID["post"]; r.Body != "POST /echo auth=Bearer t body=x=1" {
		t.Errorf("post body = %q", r.Body)
	}
	if r := byID["redirect"]; r.Status != http.StatusFound || r.Headers["Location"][0] != "http://elsewhere.test/" {
		t.Errorf("redirect = %+v; a redirect must be reported, not followed", r)
	}
	if r := byID["big"]; len(r.Body) != MaxBodyBytes || !r.BodyTruncated {
		t.Errorf("big: len = %d, truncated = %v", len(r.Body), r.BodyTruncated)
	}
	if r := byID["denied"]; r.Answered() || r.Gate != "denied" {
		t.Errorf("denied = %+v; a gate refusal is not an answer from the target", r)
	}
	if r := byID["down"]; r.Answered() || r.Gate != "failed" {
		t.Errorf("down = %+v", r)
	}
	if _, leaked := byID["denied"].Headers[gateHeader]; leaked {
		t.Error("the gate header was left in the response headers")
	}
}

func TestExecuteRecordsTransportErrorsAndCancellation(t *testing.T) {
	gate := gateStub(t)
	client, _ := NewClient(gate.URL, false)
	gate.Close()
	batch := Batch{Requests: []Request{{ID: "a", Method: "GET", URL: "http://app.test/"}, {ID: "b", Method: "GET", URL: "http://app.test/"}}}

	failed := Execute(context.Background(), client, batch).Responses
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := Execute(ctx, client, batch).Responses

	if len(failed) != 2 || failed[0].Error == "" || failed[0].Answered() || len(failed[0].Error) > 320 {
		t.Fatalf("failed = %+v", failed)
	}
	if len(cancelled) != 2 || !strings.Contains(cancelled[1].Error, "cancelled") {
		t.Fatalf("cancelled = %+v", cancelled)
	}
	for text, want := range map[string]string{"proxyconnect: Forbidden": "refused", "Bad Gateway": "could not reach"} {
		if got := describe(errors.New(text)); !strings.Contains(got, want) {
			t.Errorf("describe(%q) = %q", text, got)
		}
	}
}

func TestBatchValidation(t *testing.T) {
	ok := Request{ID: "a", Method: "GET", URL: "https://app.test/"}
	many := make([]Request, MaxRequests+1)
	for i := range many {
		many[i] = ok
	}
	cases := map[string]Batch{
		"empty":          {},
		"too many":       {Requests: many},
		"unknown method": {Requests: []Request{{ID: "a", Method: "TRACE", URL: "https://app.test/"}}},
		"connect method": {Requests: []Request{{ID: "a", Method: "CONNECT", URL: "https://app.test/"}}},
		"not http":       {Requests: []Request{{ID: "a", Method: "GET", URL: "file:///etc/passwd"}}},
		"no host":        {Requests: []Request{{ID: "a", Method: "GET", URL: "https:///x"}}},
		"oversized body": {Requests: []Request{{ID: "a", Method: "POST", URL: "https://app.test/", Body: strings.Repeat("x", MaxRequestBodyBytes+1)}}},
	}
	for name, batch := range cases {
		if err := batch.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
	if err := (Batch{Requests: []Request{ok}}).Validate(); err != nil {
		t.Errorf("valid batch: %v", err)
	}
	for _, proxy := range []string{"", "gate:3128", "socks5://gate:1080", "http://"} {
		if _, err := NewClient(proxy, false); err == nil {
			t.Errorf("NewClient(%q) succeeded", proxy)
		}
	}
}

func TestRunReadsABatchAndWritesResults(t *testing.T) {
	gate := gateStub(t)
	in := strings.NewReader(`{"requests":[{"id":"a","method":"GET","url":"http://app.test/"}]}`)
	var out bytes.Buffer

	if err := Run(context.Background(), gate.URL, in, &out); err != nil {
		t.Fatal(err)
	}
	var results Results
	if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results.Responses) != 1 || results.Responses[0].Body != "hello" {
		t.Fatalf("results = %+v, err = %v", results, err)
	}
	for name, input := range map[string]string{"not json": "nope", "invalid batch": `{"requests":[]}`} {
		if err := Run(context.Background(), gate.URL, strings.NewReader(input), io.Discard); err == nil {
			t.Errorf("%s: Run succeeded", name)
		}
	}
	if err := Run(context.Background(), "not-a-proxy", strings.NewReader(`{"requests":[{"id":"a","method":"GET","url":"http://app.test/"}]}`), io.Discard); err == nil {
		t.Error("a bad proxy was accepted")
	}
}

type fakeSandbox struct {
	spec   sandbox.Spec
	result sandbox.Result
	err    error
}

func (f *fakeSandbox) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	f.spec = spec
	return f.result, f.err
}

func newRunner(s sandbox.Runner) *Runner {
	return &Runner{Sandbox: s, Image: "vajra:local", Network: "vajra-task-net", ProxyURL: "http://gate:3128", Timeout: time.Minute}
}

var twoRequests = []Request{{ID: "a", Method: "GET", URL: "https://app.test/a"}, {ID: "b", Method: "GET", URL: "https://app.test/b"}}

func TestRunnerSendsTheBatchToASandboxOnTheTaskNetwork(t *testing.T) {
	fake := &fakeSandbox{result: sandbox.Result{Stdout: []byte(`{"responses":[{"id":"a","status":200},{"id":"b","status":404}]}` + "\n")}}
	runner := newRunner(fake)
	runner.InsecureTLS = true

	got, err := runner.Do(context.Background(), twoRequests)

	if err != nil || len(got) != 2 || got[1].Status != 404 {
		t.Fatalf("responses = %+v, err = %v", got, err)
	}
	spec := fake.spec
	if spec.Network != "vajra-task-net" || spec.Image != "vajra:local" || strings.Join(spec.Argv, " ") != "probe -proxy http://gate:3128" {
		t.Fatalf("spec = %+v", spec)
	}
	var sent Batch
	if err := json.Unmarshal(spec.Stdin, &sent); err != nil || len(sent.Requests) != 2 || !sent.InsecureTLS {
		t.Fatalf("stdin = %s", spec.Stdin)
	}
	if len(spec.Mounts) != 0 || len(spec.Env) != 0 {
		t.Fatalf("the probe was given mounts or environment: %+v", spec)
	}
}

func TestRunnerRejectsBadRunsAndMismatchedResults(t *testing.T) {
	cases := map[string]sandbox.Result{
		"timeout":           {TimedOut: true},
		"non-zero exit":     {ExitCode: 1, Stderr: []byte("probe: no requests")},
		"truncated":         {Truncated: true},
		"not json":          {Stdout: []byte("oops")},
		"too few responses": {Stdout: []byte(`{"responses":[{"id":"a","status":200}]}`)},
		"wrong order":       {Stdout: []byte(`{"responses":[{"id":"b","status":200},{"id":"a","status":200}]}`)},
	}
	for name, result := range cases {
		if _, err := newRunner(&fakeSandbox{result: result}).Do(context.Background(), twoRequests); err == nil {
			t.Errorf("%s: Do succeeded", name)
		}
	}
	if _, err := newRunner(&fakeSandbox{err: errors.New("docker unavailable")}).Do(context.Background(), twoRequests); err == nil {
		t.Error("a sandbox error was swallowed")
	}
	if _, err := newRunner(&fakeSandbox{}).Do(context.Background(), nil); err == nil {
		t.Error("an empty batch was sent")
	}
	mutations := map[string]func(*Runner){
		"sandbox": func(r *Runner) { r.Sandbox = nil }, "image": func(r *Runner) { r.Image = "" },
		"network": func(r *Runner) { r.Network = sandbox.NetworkNone }, "proxy": func(r *Runner) { r.ProxyURL = "" },
		"timeout": func(r *Runner) { r.Timeout = 0 },
	}
	for name, mutate := range mutations {
		r := newRunner(&fakeSandbox{})
		mutate(r)
		if _, err := r.Do(context.Background(), twoRequests); err == nil {
			t.Errorf("%s: Do ran with an invalid runner", name)
		}
	}
}

func TestFormattingRedactsCredentials(t *testing.T) {
	req := Request{Method: "POST", URL: "https://app.test/orders", Body: `{"id":1}`,
		Headers: map[string]string{"Authorization": "Bearer secret-token", "X-Api-Key": "k-123", "Accept": "application/json"}}
	resp := Response{Status: 200, Body: "ok", BodyTruncated: true,
		Headers: map[string][]string{"Set-Cookie": {"session=abc123"}, "Content-Type": {"text/plain"}}}

	reqText := FormatRequest(req, []string{"authorization", "X-API-KEY"})
	respText := FormatResponse(resp)

	want := "POST https://app.test/orders\nAccept: application/json\nAuthorization: [redacted]\nX-Api-Key: [redacted]\n\n{\"id\":1}"
	if reqText != want {
		t.Fatalf("request text = %q", reqText)
	}
	if strings.Contains(reqText, "secret-token") || strings.Contains(reqText, "k-123") || strings.Contains(respText, "abc123") {
		t.Fatal("a credential survived formatting")
	}
	if !strings.Contains(respText, "HTTP 200") || !strings.Contains(respText, "Content-Type: text/plain") || !strings.Contains(respText, "[body truncated]") {
		t.Fatalf("response text = %q", respText)
	}
	if got := FormatResponse(Response{Error: "timeout"}); got != "no response: timeout" {
		t.Fatalf("error response text = %q", got)
	}
}

func TestAResponseCutOffMidBodyIsNotAnAnswer(t *testing.T) {
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = io.WriteString(w, "partial")
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer cut.Close()
	client, _ := NewClient(cut.URL, false)

	got := Execute(context.Background(), client, Batch{Requests: []Request{{ID: "a", Method: "GET", URL: "http://app.test/"}}}).Responses[0]

	if got.Answered() || !strings.Contains(got.Error, "before its body was complete") {
		t.Fatalf("response = %+v; a truncated body must not count as served", got)
	}
}

func TestATargetCannotPoseAsTheGateOverHTTPS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(gateHeader, "denied") // pretending the gate refused, to hide a finding
		_, _ = io.WriteString(w, "secret page")
	}))
	defer target.Close()
	// A minimal CONNECT proxy standing in for the gate.
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream, err := net.Dial("tcp", target.Listener.Addr().String())
		if err != nil {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		client, _, _ := w.(http.Hijacker).Hijack()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(upstream, client); upstream.Close() }()
		_, _ = io.Copy(client, upstream)
		client.Close()
	}))
	defer gate.Close()
	client, _ := NewClient(gate.URL, true)

	got := Execute(context.Background(), client, Batch{Requests: []Request{{ID: "a", Method: "GET", URL: "https://app.test/"}}}).Responses[0]

	if !got.Answered() || got.Gate != "" || got.Body != "secret page" {
		t.Fatalf("response = %+v; over HTTPS the header can only come from the target and must be ignored", got)
	}
}

func TestURLsWithCredentialsAreRefused(t *testing.T) {
	batch := Batch{Requests: []Request{{ID: "a", Method: "GET", URL: "https://user:pw@app.test/"}}}
	if err := batch.Validate(); err == nil {
		t.Fatal("a URL carrying a password was accepted")
	}
}
