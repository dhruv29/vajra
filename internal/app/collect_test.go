package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/scope"
)

const (
	adminCredential = "Bearer admin-credential-1"
	userCredential  = "Bearer user-credential-2"
	noResults       = `{"results":[]}`
)

// labConfig builds a configuration from baseConfig, with a probe section
// added and the changes of mutate applied to its generic form.
func labConfig(t *testing.T, refuter string, mutate func(m map[string]any)) (config.Config, *scope.Policy) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.Replace(baseConfig, "REFUTER", refuter, 1)), &m); err != nil {
		t.Fatal(err)
	}
	m["probe"] = map[string]any{"image": "vajra:local", "timeout_seconds": 60}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	cfg, policy, err := config.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, policy
}

// labRunner is a sandbox that also plays the probe: a run of "vajra probe"
// is answered request by request from respond. Everything else goes to the
// embedded scriptedRunner.
type labRunner struct {
	scriptedRunner
	respond    func(probe.Request) probe.Response
	probeErr   error
	probeRuns  int
	requests   []probe.Request
	scanSpecs  []sandbox.Spec
	canaryRuns int
}

func (r *labRunner) Run(ctx context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	if len(spec.Argv) == 0 || spec.Argv[0] != "probe" {
		if spec.Entrypoint != "semgrep" {
			r.scanSpecs = append(r.scanSpecs, spec)
		}
		if slices.Contains(spec.Argv, "/opt/vajra/canary.yaml") {
			r.canaryRuns++
		}
		return r.scriptedRunner.Run(ctx, spec)
	}
	r.runs++
	r.probeRuns++
	if r.probeErr != nil {
		return sandbox.Result{}, r.probeErr
	}
	var batch probe.Batch
	if err := json.Unmarshal(spec.Stdin, &batch); err != nil {
		return sandbox.Result{}, err
	}
	results := probe.Results{}
	for _, req := range batch.Requests {
		r.requests = append(r.requests, req)
		resp := probe.Response{Status: http.StatusNotFound, Body: "not found"}
		if r.respond != nil {
			resp = r.respond(req)
		}
		resp.ID = req.ID
		results.Responses = append(results.Responses, resp)
	}
	out, err := json.Marshal(results)
	return sandbox.Result{Stdout: out}, err
}

// requested lists "METHOD URL" for every request the probe was given.
func (r *labRunner) requested() []string {
	out := make([]string, 0, len(r.requests))
	for _, req := range r.requests {
		out = append(out, req.Method+" "+req.URL)
	}
	return out
}

// site answers probe requests from a table keyed by "METHOD URL". Anything
// else is a 404.
type site map[string]probe.Response

func (s site) respond(req probe.Request) probe.Response {
	if resp, ok := s[req.Method+" "+req.URL]; ok {
		return resp
	}
	return probe.Response{Status: http.StatusNotFound, Body: "not found"}
}

func htmlPage(body string) probe.Response {
	return probe.Response{Status: http.StatusOK, Headers: map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}, Body: body}
}

// labDeps is testDeps with more environment variables.
func labDeps(runner sandbox.Runner, modelURL string, env map[string]string) Deps {
	deps := testDeps(runner, modelURL)
	deps.Getenv = func(name string) string {
		if name == "ANTHROPIC_API_KEY" {
			return "test-key"
		}
		return env[name]
	}
	return deps
}

// modelFake plays the model API for the reviewer, the agent and the fix
// proposer, told apart by the tool the request forces.
type modelFake struct {
	mu     sync.Mutex
	server *httptest.Server
	// verdict decides the reviewer's answer; nil means "holds".
	verdict func(model, body string) string
	// agentTurns are the content blocks of each agent reply, in order. When
	// they run out the model answers with plain text.
	agentTurns []string
	// agentFailFrom is the agent call (counted from 1) from which the API
	// fails; 0 means never.
	agentFailFrom int
	// fixInput is the input of the propose_fix call; empty makes the API fail.
	fixInput string

	bodies      []string
	agentBodies []string
	models      []string
}

func newModelFake(t *testing.T) *modelFake {
	t.Helper()
	m := &modelFake{}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *modelFake) handle(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Model      string `json:"model"`
		ToolChoice struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"tool_choice"`
	}
	_ = json.Unmarshal(raw, &req)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, string(raw))
	m.models = append(m.models, req.Model)
	usage := `,"usage":{"input_tokens":100,"output_tokens":10}}`
	switch {
	case req.ToolChoice.Name == "record_verdict":
		verdict := "holds"
		if m.verdict != nil {
			verdict = m.verdict(req.Model, string(raw))
		}
		_, _ = io.WriteString(w, `{"content":[`+toolUse("v", "record_verdict", map[string]any{"verdict": verdict, "reason": "reviewed by " + req.Model + "."})+`]`+usage)
	case req.ToolChoice.Name == "propose_fix" && m.fixInput != "":
		_, _ = io.WriteString(w, `{"content":[{"type":"tool_use","id":"p","name":"propose_fix","input":`+m.fixInput+`}]`+usage)
	case req.ToolChoice.Type == "any":
		m.agentBodies = append(m.agentBodies, string(raw))
		n := len(m.agentBodies)
		if m.agentFailFrom > 0 && n >= m.agentFailFrom {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":{"type":"overloaded_error"}}`)
			return
		}
		content := `{"type":"text","text":"Nothing more to try."}`
		if n <= len(m.agentTurns) {
			content = m.agentTurns[n-1]
		}
		_, _ = io.WriteString(w, `{"content":[`+content+`]`+usage)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"type":"api_error"}}`)
	}
}

func (m *modelFake) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bodies)
}

// allBodies returns everything that was sent to the model, as one text.
func (m *modelFake) allBodies() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Join(m.bodies, "\n")
}

// callsTo counts the requests that named model.
func (m *modelFake) callsTo(model string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, name := range m.models {
		if name == model {
			n++
		}
	}
	return n
}

// toolUse renders one tool_use content block.
func toolUse(id, name string, input map[string]any) string {
	raw, _ := json.Marshal(map[string]any{"type": "tool_use", "id": id, "name": name, "input": input})
	return string(raw)
}

func reportJSON(t *testing.T, report Report) string {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// findingFor returns the one finding of a rule.
func findingFor(t *testing.T, report Report, rule string) finding.Finding {
	t.Helper()
	for _, f := range report.Findings {
		if f.RuleID == rule {
			return f
		}
	}
	t.Fatalf("no finding for rule %q among %v", rule, statusByRule(report))
	return finding.Finding{}
}

func lastReason(f finding.Finding) string {
	if len(f.Verdicts) == 0 {
		return ""
	}
	return f.Verdicts[len(f.Verdicts)-1].Reason
}

func hasNote(report Report, text string) bool {
	return slices.ContainsFunc(report.Activity.Notes, func(note string) bool { return strings.Contains(note, text) })
}

// sourceTree writes files under a fresh directory and returns it.
func sourceTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// withAccessCheck replaces the targets with two test accounts and one rule:
// only "admin" may get /admin.
func withAccessCheck(m map[string]any) {
	delete(m, "targets")
	m["auth"] = map[string]any{
		"identities": []map[string]any{
			{"name": "admin", "headers_env": map[string]string{"Authorization": "ADMIN_TOKEN"}},
			{"name": "user", "headers_env": map[string]string{"Authorization": "USER_TOKEN"}},
		},
		"access_checks": []map[string]any{{"name": "admin console", "url": "https://app.test/admin", "allow": []string{"admin"}}},
	}
}

var accountEnv = map[string]string{"ADMIN_TOKEN": adminCredential, "USER_TOKEN": userCredential}

// adminPage serves /admin to the credentials in servedTo and refuses
// everybody else.
func adminPage(servedTo ...string) func(probe.Request) probe.Response {
	return func(req probe.Request) probe.Response {
		if req.URL == "https://app.test/admin" && slices.Contains(servedTo, req.Headers["Authorization"]) {
			return htmlPage("<h1>Admin console</h1><p>42 users</p>")
		}
		return probe.Response{Status: http.StatusUnauthorized, Body: "sign in first"}
	}
}

func TestAccessCheckReportsAnAccountServedWhatItMayNotSee(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", withAccessCheck)
	runner := &labRunner{respond: adminPage(adminCredential, userCredential)}
	model := newModelFake(t)

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, model.server.URL, accountEnv))

	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %v; want only the one for \"user\"", statusByRule(report))
	}
	f := findingFor(t, report, "unauthorized-access")
	if f.Status != finding.Confirmed || f.Source != "vajra-access" || f.Evidence.Matcher != "user" || f.Target != "https://app.test/admin" {
		t.Fatalf("finding = %+v", f)
	}
	// One batch for the check as anonymous, admin and user, then two re-tests.
	if runner.probeRuns != 3 || len(runner.requests) != 5 || report.Budget.Usage.SandboxRuns != 3 {
		t.Fatalf("probe runs = %d, requests = %d, charged = %d; want 3, 5 and 3", runner.probeRuns, len(runner.requests), report.Budget.Usage.SandboxRuns)
	}
	for _, retest := range runner.requests[3:] {
		if retest.Headers["Authorization"] != userCredential {
			t.Fatalf("the re-test was not made as \"user\": %+v", retest)
		}
	}
	if len(runner.scanSpecs) != 0 || len(report.Targets) != 0 {
		t.Fatalf("scanner runs = %d, targets = %v; nothing but the access check was configured", len(runner.scanSpecs), report.Targets)
	}
	for _, credential := range []string{"admin-credential-1", "user-credential-2"} {
		if strings.Contains(reportJSON(t, report), credential) {
			t.Errorf("the report contains the credential %q", credential)
		}
		if strings.Contains(model.allBodies(), credential) {
			t.Errorf("the reviewer was sent the credential %q", credential)
		}
	}
	if !strings.Contains(f.Evidence.Request, "Authorization: [redacted]") {
		t.Errorf("request evidence = %q; want the header kept and its value redacted", f.Evidence.Request)
	}
}

func TestAccessCheckOutcomesFollowTheReTest(t *testing.T) {
	t.Run("nobody but the allowed account is served", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAccessCheck)
		runner := &labRunner{respond: adminPage(adminCredential)}
		report, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", accountEnv))
		if err != nil || len(report.Findings) != 0 || runner.probeRuns != 1 {
			t.Fatalf("findings = %v, probe runs = %d, err = %v", statusByRule(report), runner.probeRuns, err)
		}
	})
	t.Run("served once and refused on the re-test", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAccessCheck)
		runner := &labRunner{}
		runner.respond = func(req probe.Request) probe.Response {
			if runner.probeRuns > 1 {
				return adminPage(adminCredential)(req)
			}
			return adminPage(adminCredential, userCredential)(req)
		}
		model := newModelFake(t)
		report, err := Scan(context.Background(), cfg, policy, labDeps(runner, model.server.URL, accountEnv))
		if err != nil {
			t.Fatal(err)
		}
		if got := findingFor(t, report, "unauthorized-access").Status; got != finding.Refuted || model.calls() != 0 {
			t.Fatalf("status = %s, model calls = %d; a result that does not repeat is refuted without review", got, model.calls())
		}
	})
	t.Run("the target stops answering", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAccessCheck)
		runner := &labRunner{}
		runner.respond = func(req probe.Request) probe.Response {
			if runner.probeRuns > 1 {
				return probe.Response{Error: "connection reset"}
			}
			return adminPage(adminCredential, userCredential)(req)
		}
		report, err := Scan(context.Background(), cfg, policy, labDeps(runner, newModelFake(t).server.URL, accountEnv))
		if err != nil {
			t.Fatal(err)
		}
		if got := findingFor(t, report, "unauthorized-access").Status; got != finding.Unconfirmed {
			t.Fatalf("status = %s; a finding that could not be re-tested must be unconfirmed", got)
		}
	})
	t.Run("the probe fails", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAccessCheck)
		runner := &labRunner{probeErr: errors.New("docker unavailable")}
		if _, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", accountEnv)); err == nil {
			t.Fatal("a failed access check returned a report")
		}
	})
}

func TestAccessCheckSetupErrors(t *testing.T) {
	t.Run("missing credential", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAccessCheck)
		runner := &labRunner{respond: adminPage(adminCredential)}
		_, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", map[string]string{"ADMIN_TOKEN": adminCredential}))
		if err == nil || !strings.Contains(err.Error(), "USER_TOKEN") || !strings.Contains(err.Error(), `"user"`) {
			t.Fatalf("err = %v; want it to name the identity and the variable", err)
		}
		if runner.runs != 0 {
			t.Fatalf("sandbox runs = %d; nothing may be sent with an account missing", runner.runs)
		}
	})
	check := func(m map[string]any) map[string]any {
		return m["auth"].(map[string]any)["access_checks"].([]map[string]any)[0]
	}
	for name, mutate := range map[string]func(m map[string]any){
		"a method that changes data": func(m map[string]any) { check(m)["method"] = "POST" },
		"an unknown allowed account": func(m map[string]any) { check(m)["allow"] = []string{"auditor"} },
		"a check without a name":     func(m map[string]any) { check(m)["name"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			// A malformed check is refused when the configuration is read,
			// long before anything could be sent.
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.Replace(baseConfig, "REFUTER", "none", 1)), &m); err != nil {
				t.Fatal(err)
			}
			m["probe"] = map[string]any{"image": "vajra:local", "timeout_seconds": 60}
			withAccessCheck(m)
			mutate(m)
			raw, _ := json.Marshal(m)
			if _, _, err := config.Parse(bytes.NewReader(raw)); err == nil {
				t.Fatal("the configuration was accepted")
			}
		})
	}
	t.Run("an unusable probe", func(t *testing.T) {
		cfg, policy := labConfig(t, "none", withAccessCheck)
		cfg.Probe.Image = ""
		if _, err := Scan(context.Background(), cfg, policy, labDeps(&labRunner{}, "", accountEnv)); err == nil {
			t.Fatal("Scan ran without a probe image")
		}
	})
}

// echoLine is a scanner result whose captured request repeats the headers
// the scanner was told to send.
func echoLine(templateID, matchedAt string, headers ...string) string {
	request := "GET /b HTTP/1.1\r\nHost: app.test\r\n" + strings.Join(headers, "\r\n") + "\r\n\r\n"
	raw, _ := json.Marshal(map[string]any{
		"template-id": templateID, "info": map[string]string{"name": templateID, "severity": "high"},
		"matched-at": matchedAt, "request": request, "response": "HTTP/1.1 200 OK\r\nSet-Cookie: sid=session-credential-4\r\n\r\nok",
	})
	return string(raw) + "\n"
}

func withScanAs(m map[string]any) {
	m["auth"] = map[string]any{
		"identities": []map[string]any{
			{"name": "user", "headers_env": map[string]string{"Authorization": "USER_TOKEN", "X-Tenant-Key": "TENANT_KEY"}},
		},
		"scan_as": "user",
	}
	m["crawl"] = map[string]any{"max_pages": 1, "max_depth": 0}
}

func TestScanAsSendsTheAccountToTheScannerAndKeepsItOutOfTheReport(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", withScanAs)
	env := map[string]string{"USER_TOKEN": userCredential, "TENANT_KEY": "tenant-credential-3"}
	output := echoLine("real-issue", "https://app.test/b", "Authorization: "+userCredential, "x-tenant-key: tenant-credential-3")
	runner := &labRunner{respond: site{"GET https://app.test/": htmlPage("<p>home</p>")}.respond}
	runner.scanOutput, runner.reproducible = output, map[string]bool{"real-issue": true}
	model := newModelFake(t)

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, model.server.URL, env))

	if err != nil {
		t.Fatal(err)
	}
	if len(runner.scanSpecs) != 3 {
		t.Fatalf("scanner runs = %d; want the scan and two re-tests", len(runner.scanSpecs))
	}
	for _, spec := range runner.scanSpecs {
		for _, header := range []string{"Authorization: " + userCredential, "X-Tenant-Key: tenant-credential-3"} {
			at := slices.Index(spec.Argv, header)
			if at < 1 || spec.Argv[at-1] != "-header" {
				t.Fatalf("scanner arguments %v lack -header %q", spec.Argv, header)
			}
		}
	}
	if len(runner.requests) != 1 || runner.requests[0].Headers["Authorization"] != userCredential {
		t.Fatalf("crawl requests = %+v; the crawler must use the scan_as account", runner.requests)
	}
	f := findingFor(t, report, "real-issue")
	if f.Status != finding.Confirmed || !strings.Contains(f.Evidence.Request, "Authorization: [redacted]") || !strings.Contains(f.Evidence.Request, "Host: app.test") {
		t.Fatalf("finding = %+v", f)
	}
	saved, err := VerifyOutput(context.Background(), cfg, policy, labDeps(runner, model.server.URL, env), strings.NewReader(output))
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"scan report": reportJSON(t, report), "verify report": reportJSON(t, saved), "model input": model.allBodies()} {
		for _, credential := range []string{"user-credential-2", "tenant-credential-3", "session-credential-4"} {
			if strings.Contains(text, credential) {
				t.Errorf("the %s contains the credential %q", name, credential)
			}
		}
	}
}

const shopAPI = `{"openapi":"3.0.3","info":{"title":"Shop","version":"1"},"paths":{
 "/orders":{
  "get":{"operationId":"listOrders","security":[{"bearer":[]}],"responses":{"200":{"description":"ok"}}},
  "post":{"operationId":"createOrder","security":[{"bearer":[]}],"responses":{"201":{"description":"ok"}}}},
 "/invoices":{"get":{"operationId":"listInvoices","security":[{"bearer":[]}],"responses":{"200":{"description":"ok"}}}},
 "/health":{"get":{"operationId":"health","responses":{"200":{"description":"ok"}}}}}}`

func withAPI(m map[string]any) {
	delete(m, "targets")
	m["api"] = map[string]any{"spec": "/specs/shop.json", "base_url": "https://app.test/api"}
}

func TestAPITestReportsAProtectedOperationThatAnswersAnonymously(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", withAPI)
	runner := &labRunner{respond: site{
		"GET https://app.test/api/orders":   {Status: http.StatusOK, Body: `[{"id":1,"total":"12.00"}]`},
		"GET https://app.test/api/invoices": {Status: http.StatusUnauthorized, Body: `{"error":"sign in"}`},
	}.respond}
	deps := labDeps(runner, newModelFake(t).server.URL, nil)
	var read []string
	deps.ReadFile = func(path string) ([]byte, error) {
		read = append(read, path)
		return []byte(shopAPI), nil
	}

	report, err := Scan(context.Background(), cfg, policy, deps)

	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(read, []string{"/specs/shop.json"}) {
		t.Fatalf("files read = %v", read)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %v; want only the operation that answered", statusByRule(report))
	}
	f := findingFor(t, report, "auth-not-enforced")
	if f.Status != finding.Confirmed || f.Source != "vajra-api" || f.Target != "https://app.test/api/orders" || f.Evidence.Matcher != "listOrders" {
		t.Fatalf("finding = %+v", f)
	}
	want := []string{
		"GET https://app.test/api/invoices", "GET https://app.test/api/orders", // the two protected, read-only operations
		"GET https://app.test/api/orders", "GET https://app.test/api/orders", // two re-tests
	}
	if !slices.Equal(runner.requested(), want) || runner.probeRuns != 3 {
		t.Fatalf("requests = %v in %d probe runs", runner.requested(), runner.probeRuns)
	}
	skipped := report.Activity.SkippedOperations
	if len(skipped) != 1 || !strings.HasPrefix(skipped[0], "createOrder: POST may change data") {
		t.Fatalf("skipped operations = %v; the unsafe operation must be listed with its reason", skipped)
	}
}

func TestAPITestSetupErrors(t *testing.T) {
	cfg, policy := labConfig(t, "none", withAPI)
	cases := map[string]struct {
		read func(string) ([]byte, error)
		want string
	}{
		"unreadable spec": {func(string) ([]byte, error) { return nil, errors.New("permission denied") }, "read the API description"},
		"not JSON":        {func(string) ([]byte, error) { return []byte("openapi: 3.0.3\n"), nil }, "openapi"},
		"not OpenAPI 3":   {func(string) ([]byte, error) { return []byte(`{"swagger":"2.0"}`), nil }, "openapi"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			runner := &labRunner{}
			deps := labDeps(runner, "", nil)
			deps.ReadFile = tc.read
			_, err := Scan(context.Background(), cfg, policy, deps)
			if err == nil || !strings.Contains(err.Error(), tc.want) || runner.runs != 0 {
				t.Fatalf("err = %v, sandbox runs = %d; want an error mentioning %q before anything runs", err, runner.runs, tc.want)
			}
		})
	}
	t.Run("the spec is read from disk by default", func(t *testing.T) {
		deps := labDeps(&labRunner{}, "", nil)
		if _, err := Scan(context.Background(), cfg, policy, deps); err == nil || !strings.Contains(err.Error(), "/specs/shop.json") {
			t.Fatalf("err = %v; want the missing file named", err)
		}
	})
	t.Run("the probe fails", func(t *testing.T) {
		deps := labDeps(&labRunner{probeErr: errors.New("docker unavailable")}, "", nil)
		deps.ReadFile = func(string) ([]byte, error) { return []byte(shopAPI), nil }
		if _, err := Scan(context.Background(), cfg, policy, deps); err == nil {
			t.Fatal("a failed API test returned a report")
		}
	})
}

func withCrawl(maxPages int) func(m map[string]any) {
	return func(m map[string]any) { m["crawl"] = map[string]any{"max_pages": maxPages, "max_depth": 2} }
}

var crawlSite = site{
	"GET https://app.test/":  htmlPage(`<a href="/a">a</a> <a href="/b">b</a> <a href="https://other.test/x">x</a> <img src="/logo.png">`),
	"GET https://app.test/a": htmlPage(`<a href="/c">c</a> <a href="/">home</a>`),
	"GET https://app.test/b": {Error: "connection reset"},
	"GET https://app.test/c": htmlPage(`<a href="/d">too deep</a>`),
}

func TestCrawlRecordsThePagesItFound(t *testing.T) {
	cfg, policy := labConfig(t, "none", withCrawl(10))
	runner := &labRunner{respond: crawlSite.respond}

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", nil))

	if err != nil {
		t.Fatal(err)
	}
	activity := report.Activity
	want := []string{"https://app.test/", "https://app.test/a", "https://app.test/c"}
	if !slices.Equal(activity.Endpoints, want) {
		t.Fatalf("endpoints = %v; want %v (the page that did not answer is left out)", activity.Endpoints, want)
	}
	if activity.PagesCrawled != 4 || activity.CrawlTruncated || len(activity.Notes) != 0 {
		t.Fatalf("activity = %+v; want 4 pages fetched and no truncation", activity)
	}
	for _, requested := range runner.requested() {
		if strings.Contains(requested, "other.test") || strings.Contains(requested, "logo.png") || strings.HasSuffix(requested, "/d") {
			t.Errorf("the crawler requested %s", requested)
		}
	}
	// One probe run per depth (0, 1 and 2) and one scanner run.
	if runner.probeRuns != 3 || report.Budget.Usage.SandboxRuns != 4 {
		t.Fatalf("probe runs = %d, charged = %d", runner.probeRuns, report.Budget.Usage.SandboxRuns)
	}
}

func TestCrawlStoppedAtThePageLimitIsReported(t *testing.T) {
	cfg, policy := labConfig(t, "none", withCrawl(2))
	runner := &labRunner{respond: crawlSite.respond}

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", nil))

	if err != nil {
		t.Fatal(err)
	}
	if report.Activity.PagesCrawled != 2 || !report.Activity.CrawlTruncated || !hasNote(report, "page limit of 2") {
		t.Fatalf("activity = %+v; want the truncation recorded and explained", report.Activity)
	}

	runner = &labRunner{probeErr: errors.New("docker unavailable")}
	if _, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", nil)); err == nil || !strings.Contains(err.Error(), "crawl") {
		t.Fatalf("err = %v; a failed crawl must fail the scan", err)
	}
}

// zone is a resolver that knows a fixed set of names, or every name.
type zone struct {
	names    map[string]string
	catchAll bool
}

func (z zone) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if z.catchAll {
		return []netip.Addr{netip.MustParseAddr("203.0.113.99")}, nil
	}
	if addr, ok := z.names[host]; ok {
		return []netip.Addr{netip.MustParseAddr(addr)}, nil
	}
	return nil, errors.New("no such host")
}

func withRecon(targets ...string) func(m map[string]any) {
	return func(m map[string]any) {
		m["scope"] = map[string]any{"hosts": []string{"*.example.test"}}
		m["targets"] = targets
		m["recon"] = map[string]any{"max_names": 10, "words": []string{"www", "intranet", "missing"}}
	}
}

// scanTargets returns the -target arguments of one scanner run.
func scanTargets(spec sandbox.Spec) []string {
	var out []string
	for i, arg := range spec.Argv {
		if arg == "-target" && i+1 < len(spec.Argv) {
			out = append(out, spec.Argv[i+1])
		}
	}
	return out
}

func TestDiscoveryAddsHostsThatResolveInScopeAndScansThem(t *testing.T) {
	cfg, policy := labConfig(t, "none", withRecon("https://app.example.test"))
	runner := &labRunner{}
	deps := labDeps(runner, "", nil)
	deps.Resolver = zone{names: map[string]string{"www.example.test": "203.0.113.10", "intranet.example.test": "10.0.0.5"}}

	report, err := Scan(context.Background(), cfg, policy, deps)

	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(report.Activity.DiscoveredHosts, []string{"www.example.test"}) || !slices.Equal(report.Activity.RejectedHosts, []string{"intranet.example.test"}) {
		t.Fatalf("discovered = %v, rejected = %v", report.Activity.DiscoveredHosts, report.Activity.RejectedHosts)
	}
	want := []string{"https://app.example.test", "http://www.example.test", "https://www.example.test"}
	if !slices.Equal(report.Targets, want) {
		t.Fatalf("targets = %v; want %v", report.Targets, want)
	}
	if len(runner.scanSpecs) != 1 || !slices.Equal(scanTargets(runner.scanSpecs[0]), want) {
		t.Fatalf("scanner runs = %d, scanned = %v; want %v", len(runner.scanSpecs), runner.scanSpecs, want)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("the configuration's own target list was changed: %v", cfg.Targets)
	}
}

func TestDiscoveryUnderACatchAllZoneIsSkippedAndSaysSo(t *testing.T) {
	cfg, policy := labConfig(t, "none", withRecon())
	runner := &labRunner{}
	deps := labDeps(runner, "", nil)
	deps.Resolver = zone{catchAll: true}

	report, err := Scan(context.Background(), cfg, policy, deps)

	if err != nil {
		t.Fatal(err)
	}
	if !hasNote(report, "Every name under example.test resolves") || len(report.Activity.DiscoveredHosts) != 0 {
		t.Fatalf("activity = %+v", report.Activity)
	}
	if len(report.Targets) != 0 || runner.runs != 0 {
		t.Fatalf("targets = %v, sandbox runs = %d; with nothing discovered there is nothing to scan", report.Targets, runner.runs)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(cancelled, cfg, policy, deps); err == nil {
		t.Fatal("a discovery that was cancelled returned a report")
	}
}
