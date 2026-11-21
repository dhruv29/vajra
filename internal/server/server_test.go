package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/store"
	"github.com/dhruv29/vajra/internal/topology"
)

const (
	testHost = "127.0.0.1:8700"
	runID    = "20261121-195440-0a1b2c3d"
)

var testToken = strings.Repeat("ab", tokenBytes)

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rep := record.Report{
		GeneratedAt: time.Unix(1_700_000_000, 0).UTC(), Targets: []string{"https://app.test"},
		Authorization: record.Authorization{Operator: "sec@example.test"},
		Summary:       map[finding.Status]int{finding.Confirmed: 1},
		Findings: []finding.Finding{{
			ID: "f1", Title: "SQL injection", Target: "https://app.test/orders",
			Status: finding.Confirmed, Severity: finding.SeverityHigh, CWE: []string{"cwe-89"},
		}},
	}
	run, err := record.Build(runID, rep, topology.Declaration{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(run); err != nil {
		t.Fatal(err)
	}
	h, err := New(st, testToken, []string{testHost, "localhost:8700"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type request struct {
	method, path, host, token string
}

func do(h http.Handler, r request) (*http.Response, string) {
	if r.method == "" {
		r.method = http.MethodGet
	}
	if r.host == "" {
		r.host = testHost
	}
	req := httptest.NewRequest(r.method, "http://"+r.host+r.path, nil)
	req.Host = r.host
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestAPIRequiresTheToken(t *testing.T) {
	h := newHandler(t)
	for name, token := range map[string]string{
		"no token": "", "wrong token": strings.Repeat("cd", tokenBytes), "prefix of the token": testToken[:10],
	} {
		for _, path := range []string{"/api/runs", "/api/runs/" + runID, "/api/runs/" + runID + "/report?format=json"} {
			resp, body := do(h, request{path: path, token: token})
			if resp.StatusCode != http.StatusUnauthorized || strings.Contains(body, "SQL injection") {
				t.Errorf("%s %s: status = %d, body = %q", name, path, resp.StatusCode, body)
			}
		}
	}
	// The token is only read from the Authorization header.
	if resp, _ := do(h, request{path: "/api/runs?token=" + testToken}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token in the query string: status = %d", resp.StatusCode)
	}
}

func TestRequestsForAnotherHostAreRefused(t *testing.T) {
	h := newHandler(t)
	for _, host := range []string{"evil.test", "evil.test:8700", "127.0.0.1:9999", "192.168.1.5:8700"} {
		for _, path := range []string{"/", "/api/runs"} {
			resp, body := do(h, request{path: path, host: host, token: testToken})
			if resp.StatusCode != http.StatusForbidden || strings.Contains(body, runID) {
				t.Errorf("host %s %s: status = %d", host, path, resp.StatusCode)
			}
		}
	}
	if resp, _ := do(h, request{path: "/api/runs", host: "LOCALHOST:8700", token: testToken}); resp.StatusCode != http.StatusOK {
		t.Errorf("an allowed host in another case: status = %d", resp.StatusCode)
	}
}

func TestListAndGetRuns(t *testing.T) {
	h := newHandler(t)

	resp, body := do(h, request{path: "/api/runs", token: testToken})
	var list []record.Summary
	if err := json.Unmarshal([]byte(body), &list); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q, err = %v", resp.StatusCode, body, err)
	}
	if len(list) != 1 || list[0].ID != runID || list[0].TopScore == 0 {
		t.Fatalf("list = %+v", list)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", resp.Header)
	}

	resp, body = do(h, request{path: "/api/runs/" + runID, token: testToken})
	var run record.Run
	if err := json.Unmarshal([]byte(body), &run); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, err = %v", resp.StatusCode, err)
	}
	if run.ID != runID || len(run.Radii) != 1 || run.Report.Findings[0].Title != "SQL injection" {
		t.Fatalf("run = %+v", run)
	}
}

func TestRunErrors(t *testing.T) {
	h := newHandler(t)
	cases := map[string]int{
		"/api/runs/20261121-195440-ffffffff":                  http.StatusNotFound,
		"/api/runs/not-an-id":                                 http.StatusBadRequest,
		"/api/runs/..%2F..%2Fetc%2Fpasswd":                    http.StatusBadRequest,
		"/api/runs/" + runID + "/report":                      http.StatusBadRequest,
		"/api/runs/" + runID + "/report?format=pdf":           http.StatusBadRequest,
		"/api/runs/20261121-195440-ffffffff/report?format=md": http.StatusNotFound,
		"/api/nope": http.StatusNotFound,
	}
	for path, want := range cases {
		resp, body := do(h, request{path: path, token: testToken})
		if resp.StatusCode != want {
			t.Errorf("%s: status = %d; want %d (%s)", path, resp.StatusCode, want, body)
		}
	}
}

func TestReportsDownloadInEachFormat(t *testing.T) {
	h := newHandler(t)
	cases := map[string]struct{ contentType, contains string }{
		"html": {"text/html; charset=utf-8", "<!doctype html>"},
		"md":   {"text/markdown; charset=utf-8", "# Security test report"},
		"json": {"application/json", `"radii"`},
	}
	for format, want := range cases {
		resp, body := do(h, request{path: "/api/runs/" + runID + "/report?format=" + format, token: testToken})
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != want.contentType || !strings.Contains(body, want.contains) {
			t.Errorf("%s: status = %d, type = %q", format, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if got := resp.Header.Get("Content-Disposition"); got != `attachment; filename="vajra-`+runID+`.`+format+`"` {
			t.Errorf("%s: disposition = %q", format, got)
		}
	}
}

func TestTheAPIIsReadOnly(t *testing.T) {
	h := newHandler(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		resp, _ := do(h, request{method: method, path: "/api/runs/" + runID, token: testToken})
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d; want 405", method, resp.StatusCode)
		}
	}
}

func TestStaticInterfaceIsServedWithoutATokenAndHoldsNoData(t *testing.T) {
	h := newHandler(t)
	for path, want := range map[string]string{"/": "<title>Vajra</title>", "/app.js": "Bearer", "/app.css": "--ink"} {
		resp, body := do(h, request{path: path})
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("%s: status = %d, missing %q", path, resp.StatusCode, want)
		}
		if strings.Contains(body, "SQL injection") || strings.Contains(body, testToken) {
			t.Errorf("%s contains run data or the token", path)
		}
	}
	if resp, _ := do(h, request{path: "/server.go"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a file outside the web directory was served: %d", resp.StatusCode)
	}
}

func TestSecurityHeadersAreSetOnEveryResponse(t *testing.T) {
	h := newHandler(t)
	for _, r := range []request{{path: "/"}, {path: "/api/runs"}, {path: "/api/runs", token: testToken}, {path: "/", host: "evil.test"}} {
		resp, _ := do(h, r)
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
			t.Errorf("%+v: CSP = %q", r, csp)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("X-Frame-Options") != "DENY" ||
			resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%+v: headers = %v", r, resp.Header)
		}
	}
}

func TestTheInterfaceNeverParsesDataAsHTML(t *testing.T) {
	_, script := do(newHandler(t), request{path: "/app.js"})
	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(script, sink) {
			t.Errorf("app.js uses %s", sink)
		}
	}
	_, page := do(newHandler(t), request{path: "/"})
	for _, banned := range []string{"http://", "https://", "onclick=", "<style", "style="} {
		if strings.Contains(page, banned) {
			t.Errorf("index.html contains %q", banned)
		}
	}
}

func TestNewAndHelpers(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	for name, build := range map[string]func() (http.Handler, error){
		"nil store":   func() (http.Handler, error) { return New(nil, testToken, []string{testHost}) },
		"short token": func() (http.Handler, error) { return New(st, "short", []string{testHost}) },
		"no hosts":    func() (http.Handler, error) { return New(st, testToken, nil) },
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	first, err := NewToken()
	second, _ := NewToken()
	if err != nil || len(first) != tokenBytes*2 || first == second {
		t.Fatalf("tokens = %q, %q, err = %v", first, second, err)
	}
}

func TestLoopbackAddr(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8700", "localhost:8700", "[::1]:8700"} {
		hosts, err := LoopbackAddr(addr)
		if err != nil || len(hosts) == 0 || hosts[0] != addr {
			t.Errorf("LoopbackAddr(%q) = %v, %v", addr, hosts, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8700", ":8700", "192.168.1.5:8700", "example.com:8700", "no-port"} {
		if _, err := LoopbackAddr(addr); err == nil {
			t.Errorf("LoopbackAddr(%q) succeeded; only loopback is allowed", addr)
		}
	}
}
