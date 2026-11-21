package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/secrets"
	"github.com/dhruv29/vajra/internal/semgrep"
)

const boundQueryFix = `{"start_line":2,"end_line":3,
 "replacement":"    q = \"SELECT ?\"\n    return db.execute(q, (request.args[\"id\"],))",
 "explanation":"Pass the value as a bound parameter."}`

// codeRun is a saved run holding the SQL injection finding of staticConfig's
// source tree, and a finding from another scanner.
func codeRun() record.Run {
	return record.Run{ID: "run-1", Report: Report{Findings: []finding.Finding{
		{
			ID: "code-1", Kind: finding.Static, Source: semgrep.Source, RuleID: "rules.sqli", Title: "sqli",
			Description: "Input reaches a query.", Target: "views.py:3", Status: finding.Confirmed,
			Location: &finding.Location{File: "views.py", Line: 3, EndLine: 3},
		},
		{
			ID: "secret-1", Kind: finding.Static, Source: secrets.Source, RuleID: "generic-credential-assignment",
			Target: "views.py:1", Status: finding.Confirmed, Location: &finding.Location{File: "views.py", Line: 1},
		},
	}}}
}

func TestFixProposesAPatchChecksItAndLeavesTheSourceAlone(t *testing.T) {
	cfg, _ := staticConfig(t, false)
	source := filepath.Join(cfg.Source.Root, "views.py")
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	runner := &labRunner{}
	runner.staticOutput = noResults
	model := newModelFake(t)
	model.fixInput = boundQueryFix

	result, err := Fix(context.Background(), cfg, labDeps(runner, model.server.URL, nil), codeRun(), "code-1")

	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.FindingID != "code-1" || result.File != "views.py" || result.Explanation != "Pass the value as a bound parameter." {
		t.Fatalf("result = %+v", result)
	}
	for _, want := range []string{"--- a/views.py", "+++ b/views.py", "-    return db.execute(q)", `+    return db.execute(q, (request.args["id"],))`} {
		if !strings.Contains(result.Patch, want) {
			t.Errorf("patch lacks %q:\n%s", want, result.Patch)
		}
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the source file was changed (err = %v)", err)
	}
	if len(runner.staticSpecs) != 1 {
		t.Fatalf("analyser runs = %d; want one, on the patched copy", len(runner.staticSpecs))
	}
	spec := runner.staticSpecs[0]
	if spec.Mounts[0].Source == cfg.Source.Root || spec.Mounts[0].Writable || spec.Argv[len(spec.Argv)-1] != "./views.py" {
		t.Fatalf("the analyser was run on %+v with %v; want a read-only copy of the one file", spec.Mounts, spec.Argv)
	}
	if !strings.Contains(model.allBodies(), "return db.execute(q)") || model.calls() != 1 {
		t.Fatalf("model calls = %d; want one, carrying the code", model.calls())
	}
}

func TestFixIsNotVerifiedUnlessTheRuleStopsMatching(t *testing.T) {
	cfg, _ := staticConfig(t, false)
	t.Run("the rule still matches", func(t *testing.T) {
		runner := &labRunner{}
		runner.staticOutput = sqliOutput
		model := newModelFake(t)
		model.fixInput = boundQueryFix
		result, err := Fix(context.Background(), cfg, labDeps(runner, model.server.URL, nil), codeRun(), "code-1")
		if err != nil || result.Verified || result.Patch == "" || !strings.Contains(result.Reason, "still matches") {
			t.Fatalf("result = %+v, err = %v", result, err)
		}
	})
	t.Run("the proposal is unusable", func(t *testing.T) {
		runner := &labRunner{}
		model := newModelFake(t)
		model.fixInput = `{"start_line":40,"end_line":41,"replacement":"pass","explanation":"x"}`
		result, err := Fix(context.Background(), cfg, labDeps(runner, model.server.URL, nil), codeRun(), "code-1")
		if err != nil || result.Verified || result.Patch != "" || runner.runs != 0 {
			t.Fatalf("result = %+v, err = %v, sandbox runs = %d", result, err, runner.runs)
		}
	})
	t.Run("the model fails", func(t *testing.T) {
		runner := &labRunner{}
		if _, err := Fix(context.Background(), cfg, labDeps(runner, newModelFake(t).server.URL, nil), codeRun(), "code-1"); err == nil || runner.runs != 0 {
			t.Fatalf("err = %v, sandbox runs = %d", err, runner.runs)
		}
	})
	t.Run("the analyser fails", func(t *testing.T) {
		runner := &labRunner{} // empty output is not a result
		model := newModelFake(t)
		model.fixInput = boundQueryFix
		if result, err := Fix(context.Background(), cfg, labDeps(runner, model.server.URL, nil), codeRun(), "code-1"); err == nil {
			t.Fatalf("result = %+v; a patch that could not be checked must be an error", result)
		}
	})
}

func TestFixRefusesWhatItCannotDo(t *testing.T) {
	cfg, _ := staticConfig(t, false)
	without := func(change func(c *config.Config)) config.Config {
		c := cfg
		change(&c)
		return c
	}
	keyless := labDeps(&labRunner{}, "", nil)
	keyless.Getenv = func(string) string { return "" }
	cases := map[string]struct {
		cfg     config.Config
		deps    Deps
		finding string
		want    string
	}{
		"unknown finding":       {cfg, labDeps(&labRunner{}, "", nil), "nope", `no finding "nope"`},
		"not a code finding":    {cfg, labDeps(&labRunner{}, "", nil), "secret-1", "only findings from code analysis"},
		"missing API key":       {cfg, keyless, "code-1", "ANTHROPIC_API_KEY"},
		"no source":             {without(func(c *config.Config) { c.Source = nil }), labDeps(&labRunner{}, "", nil), "code-1", "source.semgrep"},
		"no analyser":           {without(func(c *config.Config) { s := *c.Source; s.Semgrep = nil; c.Source = &s }), labDeps(&labRunner{}, "", nil), "code-1", "source.semgrep"},
		"no model":              {without(func(c *config.Config) { c.Refuter.Provider = config.RefuterNone }), labDeps(&labRunner{}, "", nil), "code-1", "refuter.provider"},
		"no runner":             {cfg, Deps{Getenv: keyless.Getenv}, "code-1", "sandbox runner"},
		"no environment lookup": {cfg, Deps{Runner: &labRunner{}}, "code-1", "environment lookup"},
		"no budget":             {without(func(c *config.Config) { c.Budget = budget.Limits{} }), labDeps(&labRunner{}, "", nil), "code-1", "budget"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := Fix(context.Background(), tc.cfg, tc.deps, codeRun(), tc.finding)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("result = %+v, err = %v; want an error mentioning %q", result, err, tc.want)
			}
		})
	}
}

func TestExposureReturnsOnlyAdvisoriesPublishedSinceTheRun(t *testing.T) {
	cfg, policy := dependencyConfig(t, sourceTree(t, map[string]string{"package-lock.json": packageLock}))
	published := []string{"ADV-test-0001"}
	advisories := newOSVFake(t, func(_ int, name string) []string {
		if name == "shop-utils" {
			return published
		}
		return nil
	})
	deps := labDeps(&labRunner{}, "", nil)
	deps.OSVBaseURL = advisories.server.URL
	report, err := Scan(context.Background(), cfg, policy, deps)
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("findings = %v, err = %v", statusByRule(report), err)
	}
	// The run is read back from storage, as the command line does.
	raw, err := json.Marshal(record.Run{ID: "run-1", Report: report})
	if err != nil {
		t.Fatal(err)
	}
	var run record.Run
	if err := json.Unmarshal(raw, &run); err != nil {
		t.Fatal(err)
	}

	fresh, err := Exposure(context.Background(), deps, run)
	if err != nil || fresh == nil || len(fresh) != 0 {
		t.Fatalf("fresh = %v, err = %v; nothing new was published", fresh, err)
	}

	advisories.mu.Lock()
	published = []string{"ADV-test-0001", "ADV-test-0002"}
	advisories.mu.Unlock()
	fresh, err = Exposure(context.Background(), deps, run)

	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 1 || fresh[0].RuleID != "ADV-test-0002" || fresh[0].Kind != finding.Dependency || fresh[0].Status != finding.Candidate {
		t.Fatalf("fresh = %+v; want only the advisory that was not in the run", fresh)
	}
	if fresh[0].Evidence.Extracted[0] != "npm/shop-utils@4.17.20" {
		t.Fatalf("fresh finding = %+v", fresh[0])
	}
}

func TestExposureErrors(t *testing.T) {
	advisories := newOSVFake(t, knownAdvisory)
	advisories.fail = true
	deps := Deps{OSVBaseURL: advisories.server.URL}
	inventory := record.Run{Report: Report{Activity: record.Activity{Packages: []osv.Package{{Ecosystem: "npm", Name: "shop-utils", Version: "4.17.20"}}}}}

	if _, err := Exposure(context.Background(), deps, record.Run{ID: "run-0"}); err == nil || !strings.Contains(err.Error(), "no dependency inventory") {
		t.Fatalf("err = %v; a run without an inventory cannot be checked", err)
	}
	if fresh, err := Exposure(context.Background(), deps, inventory); err == nil || !strings.Contains(err.Error(), "dependency lookup") {
		t.Fatalf("fresh = %v, err = %v; a failed lookup must not read as \"nothing new\"", fresh, err)
	}
}

// webhook records what was posted to it.
type webhook struct {
	mu     sync.Mutex
	server *httptest.Server
	status int
	paths  []string
	bodies []string
}

func newWebhook(t *testing.T) *webhook {
	t.Helper()
	h := &webhook{status: http.StatusNoContent}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		h.paths = append(h.paths, r.Method+" "+r.URL.Path)
		h.bodies = append(h.bodies, string(body))
		w.WriteHeader(h.status)
	}))
	t.Cleanup(h.server.Close)
	return h
}

func withNotify(allowPrivate bool) func(m map[string]any) {
	return func(m map[string]any) {
		m["notify"] = map[string]any{"webhook_url_env": "VAJRA_WEBHOOK", "allow_private": allowPrivate}
	}
}

func notifiedRun() record.Run {
	return record.Run{ID: "run-7", Report: Report{
		Targets: []string{"https://app.test"},
		Findings: []finding.Finding{
			{ID: "f1", Title: "Admin console open", Severity: finding.SeverityHigh, Target: "https://app.test/admin", Status: finding.Confirmed,
				Evidence: finding.Evidence{Request: "GET /admin evidence-request-marker", Response: "HTTP 200 evidence-response-marker", Extracted: []string{"evidence-extracted-marker"}}},
			{ID: "f2", Title: "Old panel", Severity: finding.SeverityLow, Target: "https://app.test/old", Status: finding.Refuted},
			{ID: "f3", Title: "Maybe", Severity: finding.SeverityLow, Target: "https://app.test/m", Status: finding.Unconfirmed},
		},
	}}
}

func TestNotifyPostsCountsAndTitlesButNoEvidence(t *testing.T) {
	cfg, _ := labConfig(t, "none", withNotify(true))
	hook := newWebhook(t)
	env := map[string]string{"VAJRA_WEBHOOK": hook.server.URL + "/hooks/webhook-token-5"}

	err := Notify(context.Background(), cfg, labDeps(&labRunner{}, "", env), notifiedRun())

	if err != nil {
		t.Fatal(err)
	}
	if len(hook.paths) != 1 || hook.paths[0] != "POST /hooks/webhook-token-5" {
		t.Fatalf("requests = %v", hook.paths)
	}
	var sent struct {
		RunID       string `json:"run_id"`
		Confirmed   int    `json:"confirmed"`
		Unconfirmed int    `json:"unconfirmed"`
		Refuted     int    `json:"refuted"`
		TopFindings []struct {
			Title string `json:"title"`
		} `json:"top_findings"`
	}
	if err := json.Unmarshal([]byte(hook.bodies[0]), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.RunID != "run-7" || sent.Confirmed != 1 || sent.Unconfirmed != 1 || sent.Refuted != 1 {
		t.Fatalf("sent = %+v", sent)
	}
	if len(sent.TopFindings) != 1 || sent.TopFindings[0].Title != "Admin console open" {
		t.Fatalf("top findings = %+v", sent.TopFindings)
	}
	if strings.Contains(hook.bodies[0], "evidence-") {
		t.Fatalf("the notification carries evidence: %s", hook.bodies[0])
	}
}

func TestNotifyErrors(t *testing.T) {
	cfg, _ := labConfig(t, "none", withNotify(true))
	hook := newWebhook(t)
	url := hook.server.URL + "/hooks/webhook-token-5"
	t.Run("not configured", func(t *testing.T) {
		plain, _ := labConfig(t, "none", nil)
		err := Notify(context.Background(), plain, labDeps(&labRunner{}, "", map[string]string{"VAJRA_WEBHOOK": url}), notifiedRun())
		if err == nil || !strings.Contains(err.Error(), "no notification is configured") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("empty variable", func(t *testing.T) {
		err := Notify(context.Background(), cfg, labDeps(&labRunner{}, "", nil), notifiedRun())
		if err == nil || !strings.Contains(err.Error(), "VAJRA_WEBHOOK") {
			t.Fatalf("err = %v; want it to name the variable", err)
		}
	})
	t.Run("no environment lookup", func(t *testing.T) {
		if err := Notify(context.Background(), cfg, Deps{}, notifiedRun()); err == nil {
			t.Fatal("Notify ran without an environment lookup")
		}
	})
	t.Run("private address not allowed", func(t *testing.T) {
		strict, _ := labConfig(t, "none", withNotify(false))
		err := Notify(context.Background(), strict, labDeps(&labRunner{}, "", map[string]string{"VAJRA_WEBHOOK": url}), notifiedRun())
		if err == nil || strings.Contains(err.Error(), "webhook-token-5") {
			t.Fatalf("err = %v; want a refusal that does not repeat the token", err)
		}
	})
	if len(hook.paths) != 0 {
		t.Fatalf("requests = %v; none of these may reach the webhook", hook.paths)
	}
	t.Run("the webhook refuses", func(t *testing.T) {
		hook.status = http.StatusInternalServerError
		err := Notify(context.Background(), cfg, labDeps(&labRunner{}, "", map[string]string{"VAJRA_WEBHOOK": url}), notifiedRun())
		if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "webhook-token-5") {
			t.Fatalf("err = %v; want the status and not the token", err)
		}
	})
}

// osvFake plays the advisory database.
type osvFake struct {
	mu     sync.Mutex
	server *httptest.Server
	// advisories returns the advisory IDs for a package on the nth batch
	// query (counted from 1).
	advisories func(batch int, name string) []string
	fail       bool
	batches    int
}

func newOSVFake(t *testing.T, advisories func(batch int, name string) []string) *osvFake {
	t.Helper()
	o := &osvFake{advisories: advisories}
	o.server = httptest.NewServer(http.HandlerFunc(o.handle))
	t.Cleanup(o.server.Close)
	return o
}

func (o *osvFake) handle(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok && r.Method == http.MethodGet {
		_, _ = io.WriteString(w, `{"id":"`+id+`","summary":"Unsafe merge in shop-utils","database_specific":{"severity":"HIGH","cwe_ids":["CWE-1321"]},
		 "affected":[{"package":{"name":"shop-utils","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`)
		return
	}
	var batch struct {
		Queries []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"queries"`
	}
	if r.URL.Path != "/v1/querybatch" || json.NewDecoder(r.Body).Decode(&batch) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	o.batches++
	type vuln struct {
		ID string `json:"id"`
	}
	type result struct {
		Vulns []vuln `json:"vulns"`
	}
	results := make([]result, len(batch.Queries))
	for i, query := range batch.Queries {
		for _, id := range o.advisories(o.batches, query.Package.Name) {
			results[i].Vulns = append(results[i].Vulns, vuln{ID: id})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}

func (o *osvFake) batchCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.batches
}

const packageLock = `{
  "name": "shop",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "shop", "version": "1.0.0"},
    "node_modules/shop-http": {"version": "4.19.2"},
    "node_modules/shop-utils": {"version": "4.17.20"}
  }
}
`

// dependencyConfig is a code-only configuration that checks the packages
// pinned under root.
func dependencyConfig(t *testing.T, root string) (config.Config, *scope.Policy) {
	t.Helper()
	return labConfig(t, "anthropic", func(m map[string]any) {
		m["source"] = map[string]any{"root": root, "dependencies": map[string]any{"osv": true}}
		delete(m, "targets")
	})
}

func knownAdvisory(_ int, name string) []string {
	if name == "shop-utils" {
		return []string{"ADV-test-0001"}
	}
	return nil
}

func TestDependenciesAreLookedUpAndConfirmedWithoutAModel(t *testing.T) {
	cfg, policy := dependencyConfig(t, sourceTree(t, map[string]string{"package-lock.json": packageLock}))
	advisories := newOSVFake(t, knownAdvisory)
	model := newModelFake(t)
	deps := labDeps(&labRunner{}, model.server.URL, nil)
	deps.OSVBaseURL = advisories.server.URL

	report, err := Scan(context.Background(), cfg, policy, deps)

	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %v", statusByRule(report))
	}
	f := findingFor(t, report, "ADV-test-0001")
	if f.Kind != finding.Dependency || string(f.Kind) != "sca" || f.Status != finding.Confirmed || f.Severity != finding.SeverityHigh {
		t.Fatalf("finding = %+v", f)
	}
	if !slices.Equal(f.Evidence.Extracted, []string{"npm/shop-utils@4.17.20"}) || !strings.Contains(f.Description, "4.17.21") {
		t.Fatalf("finding = %+v", f)
	}
	// One lookup for the scan and exactly one more to confirm the finding.
	if advisories.batchCount() != 2 {
		t.Fatalf("advisory lookups = %d; want 2", advisories.batchCount())
	}
	if model.calls() != 0 || report.Budget.Usage.Turns != 0 || report.Budget.Usage.Tokens != 0 {
		t.Fatalf("model calls = %d, usage = %+v; a dependency finding is a lookup, not a judgement", model.calls(), report.Budget.Usage)
	}
	packages := report.Activity.Packages
	if len(packages) != 2 || packages[0].Name != "shop-http" || packages[1].Name != "shop-utils" || packages[1].Version != "4.17.20" || packages[1].Ecosystem != "npm" {
		t.Fatalf("inventory = %+v", packages)
	}
}

func TestDependencyLookupFailuresAndGaps(t *testing.T) {
	t.Run("the advisory service fails", func(t *testing.T) {
		cfg, policy := dependencyConfig(t, sourceTree(t, map[string]string{"package-lock.json": packageLock}))
		advisories := newOSVFake(t, knownAdvisory)
		advisories.fail = true
		deps := labDeps(&labRunner{}, "", nil)
		deps.OSVBaseURL = advisories.server.URL
		report, err := Scan(context.Background(), cfg, policy, deps)
		if err == nil || !strings.Contains(err.Error(), "dependency lookup") {
			t.Fatalf("report = %+v, err = %v; a lookup that failed must not read as \"no vulnerabilities\"", report, err)
		}
	})
	t.Run("no lockfile", func(t *testing.T) {
		cfg, policy := dependencyConfig(t, sourceTree(t, map[string]string{"main.py": "print('hello')\n"}))
		advisories := newOSVFake(t, knownAdvisory)
		deps := labDeps(&labRunner{}, "", nil)
		deps.OSVBaseURL = advisories.server.URL
		report, err := Scan(context.Background(), cfg, policy, deps)
		if err != nil || len(report.Findings) != 0 || !hasNote(report, "No lockfile") || advisories.batchCount() != 0 {
			t.Fatalf("report = %+v, err = %v, lookups = %d", report, err, advisories.batchCount())
		}
	})
	t.Run("the advisory is gone on the second lookup", func(t *testing.T) {
		cfg, policy := dependencyConfig(t, sourceTree(t, map[string]string{"package-lock.json": packageLock}))
		advisories := newOSVFake(t, func(batch int, name string) []string {
			if batch > 1 {
				return nil
			}
			return knownAdvisory(batch, name)
		})
		deps := labDeps(&labRunner{}, "", nil)
		deps.OSVBaseURL = advisories.server.URL
		report, err := Scan(context.Background(), cfg, policy, deps)
		if err != nil || findingFor(t, report, "ADV-test-0001").Status != finding.Refuted {
			t.Fatalf("statuses = %v, err = %v; want the withdrawn advisory refuted", statusByRule(report), err)
		}
	})
	t.Run("the service fails on the second lookup", func(t *testing.T) {
		cfg, policy := dependencyConfig(t, sourceTree(t, map[string]string{"package-lock.json": packageLock}))
		advisories := newOSVFake(t, knownAdvisory)
		deps := labDeps(&labRunner{}, "", nil)
		deps.OSVBaseURL = advisories.server.URL
		r, err := assemble(cfg, policy, deps)
		if err != nil {
			t.Fatal(err)
		}
		candidates, err := r.collect(context.Background())
		if err != nil || len(candidates) != 1 {
			t.Fatalf("candidates = %v, err = %v", candidates, err)
		}
		advisories.mu.Lock()
		advisories.fail = true
		advisories.mu.Unlock()
		unknown := candidates[0]
		unknown.ID, unknown.Evidence.Extracted = "other", []string{"npm/shop-extra@1.0.0"}
		report := r.verify(context.Background(), append(candidates, unknown))
		for _, f := range report.Findings {
			if f.Status != finding.Unconfirmed {
				t.Errorf("%s = %s (%s); a finding that could not be looked up again must be unconfirmed", f.ID, f.Status, lastReason(f))
			}
		}
		if _, err := r.osv.Reproduce(context.Background(), finding.Finding{}); err == nil {
			t.Error("a finding that names no package was looked up")
		}
	})
	t.Run("the source tree cannot be read", func(t *testing.T) {
		root := sourceTree(t, map[string]string{"package-lock.json": packageLock})
		cfg, policy := dependencyConfig(t, root)
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}
		if _, err := Scan(context.Background(), cfg, policy, labDeps(&labRunner{}, "", nil)); err == nil {
			t.Fatal("a source tree that cannot be read returned a clean report")
		}
	})
}
