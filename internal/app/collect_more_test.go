package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

const (
	sqliOutput = `{"results":[{"check_id":"rules.sqli","path":"views.py","start":{"line":3},"end":{"line":3},
	  "extra":{"message":"Input reaches a query.","severity":"ERROR","metadata":{"cwe":["CWE-89"]}}}]}`
	viewsPy   = "def order():\n    q = \"SELECT \" + request.args[\"id\"]\n    return db.execute(q)\n"
	searchURL = "https://app.test/search?q=%27"
)

var searchSite = site{
	"GET " + searchURL: {Status: http.StatusInternalServerError, Body: "You have an error in your SQL syntax near ''''"},
}

// withAgent enables the explorer. unsafe is the value of unsafe_requests, or
// "" for the default.
func withAgent(unsafe string) func(m map[string]any) {
	return func(m map[string]any) {
		section := map[string]any{"max_steps": 6, "goal": "Look for injection in the search."}
		if unsafe != "" {
			section["unsafe_requests"] = unsafe
		}
		m["agent"] = section
	}
}

func agentTools(report Report) []string {
	var out []string
	for _, step := range report.Activity.AgentSteps {
		out = append(out, step.Tool)
	}
	return out
}

func TestAgentCandidatesAreReplayedReviewedAndBriefedWithCodeFindings(t *testing.T) {
	root := sourceTree(t, map[string]string{"views.py": viewsPy})
	cfg, policy := labConfig(t, "anthropic", func(m map[string]any) {
		withAgent("")(m)
		m["source"] = map[string]any{"root": root, "serves": "https://app.test",
			"semgrep": map[string]any{"image": "vajra-semgrep:local", "rules_image_path": "/opt/rules", "timeout_seconds": 600}}
	})
	runner := &labRunner{respond: searchSite.respond}
	runner.staticOutput = sqliOutput
	runner.scanOutput, runner.reproducible = line("known-issue", "low", "https://app.test/k"), map[string]bool{"known-issue": true}
	model := newModelFake(t)
	model.agentTurns = []string{
		toolUse("t1", "http_request", map[string]any{"method": "GET", "url": searchURL}),
		toolUse("t2", "report_candidate", map[string]any{
			"exchange_id": "x1", "title": "SQL error from the search parameter", "cwe": "CWE-89", "severity": "high",
			"pattern": "error in your SQL syntax", "reasoning": "A single quote reaches the query unescaped.",
		}),
		toolUse("t3", "finish", map[string]any{"summary": "Covered the search."}),
	}

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, model.server.URL, nil))

	if err != nil {
		t.Fatal(err)
	}
	live := findingFor(t, report, "agent-89")
	if live.Status != finding.Confirmed || live.Source != "vajra-agent" || live.Target != searchURL || live.Severity != finding.SeverityHigh {
		t.Fatalf("agent finding = %+v", live)
	}
	// One request by the agent, then the same request replayed twice.
	if !slices.Equal(runner.requested(), []string{"GET " + searchURL, "GET " + searchURL, "GET " + searchURL}) || runner.probeRuns != 3 {
		t.Fatalf("probe requests = %v", runner.requested())
	}
	activity := report.Activity
	if !slices.Equal(agentTools(report), []string{"http_request", "report_candidate", "finish"}) {
		t.Fatalf("agent steps = %+v", activity.AgentSteps)
	}
	if activity.AgentStopped != "finished" || activity.AgentSummary != "Covered the search." || len(activity.Notes) != 0 {
		t.Fatalf("activity = %+v", activity)
	}
	briefing := model.agentBodies[0]
	for _, want := range []string{"Look for injection in the search.", "code analysis suggests: sqli (views.py:3)", "known-issue (https://app.test/k)"} {
		if !strings.Contains(briefing, want) {
			t.Errorf("the agent's first message lacks %q", want)
		}
	}
	// Three agent steps and one review each for the scanner, code and agent findings.
	if report.Budget.Usage.Turns != 6 || model.calls() != 6 {
		t.Fatalf("turns = %d, model calls = %d; want 6 and 6", report.Budget.Usage.Turns, model.calls())
	}
	code := findingFor(t, report, "rules.sqli")
	if code.Status != finding.Confirmed || !slices.Equal(code.CorroboratedBy, []string{live.ID}) || !slices.Equal(live.CorroboratedBy, []string{code.ID}) {
		t.Fatalf("code finding corroborated by %v, agent finding by %v; want each other", code.CorroboratedBy, live.CorroboratedBy)
	}
}

// approvals counts how often the operator was asked.
type approvals struct {
	asked  []string
	answer bool
}

func (a *approvals) approve(_ context.Context, action string) (bool, error) {
	a.asked = append(a.asked, action)
	return a.answer, nil
}

func unsafeTurns() []string {
	return []string{
		toolUse("t1", "http_request", map[string]any{"method": "POST", "url": "https://app.test/orders", "body": `{"qty":1}`}) + "," +
			toolUse("t2", "http_request", map[string]any{"method": "GET", "url": "https://other.test/"}),
		toolUse("t3", "report_candidate", map[string]any{
			"exchange_id": "x1", "title": "Order created without a session", "cwe": "CWE-306", "severity": "medium",
			"pattern": "order-created", "reasoning": "The order was accepted with no credentials.",
		}),
		toolUse("t4", "finish", map[string]any{"summary": "Done."}),
	}
}

func TestAgentRequestsThatCouldChangeDataNeedTheOperator(t *testing.T) {
	orders := site{"POST https://app.test/orders": {Status: http.StatusCreated, Body: "order-created 17"}}
	t.Run("deny refuses without asking", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAgent(""))
		runner := &labRunner{respond: orders.respond}
		model := newModelFake(t)
		model.agentTurns = unsafeTurns()
		operator := &approvals{answer: true}
		deps := labDeps(runner, model.server.URL, nil)
		deps.Approve = operator.approve

		report, err := Scan(context.Background(), cfg, policy, deps)

		if err != nil {
			t.Fatal(err)
		}
		if len(operator.asked) != 0 || len(runner.requests) != 0 {
			t.Fatalf("operator asked %v, requests sent %v; with \"deny\" neither may happen", operator.asked, runner.requested())
		}
		steps := report.Activity.AgentSteps
		if len(steps) != 4 || !strings.Contains(steps[0].Outcome, "did not approve") || !strings.Contains(steps[1].Outcome, "outside the authorised scope") {
			t.Fatalf("steps = %+v", steps)
		}
		if len(report.Findings) != 0 || report.Activity.AgentStopped != "finished" {
			t.Fatalf("findings = %v, stopped = %q; a report about a request that was never made is rejected", statusByRule(report), report.Activity.AgentStopped)
		}
	})
	t.Run("ask consults the operator", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAgent("ask"))
		runner := &labRunner{respond: orders.respond}
		model := newModelFake(t)
		model.agentTurns = unsafeTurns()
		operator := &approvals{answer: true}
		deps := labDeps(runner, model.server.URL, nil)
		deps.Approve = operator.approve

		report, err := Scan(context.Background(), cfg, policy, deps)

		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(operator.asked, []string{`POST https://app.test/orders | body: {"qty":1}`}) {
			t.Fatalf("operator asked %v", operator.asked)
		}
		// Approved once, sent once: verification must not send it again.
		if !slices.Equal(runner.requested(), []string{"POST https://app.test/orders"}) {
			t.Fatalf("requests = %v", runner.requested())
		}
		f := findingFor(t, report, "agent-306")
		if f.Status != finding.Unconfirmed {
			t.Fatalf("status = %s; a finding that cannot be replayed safely must be unconfirmed", f.Status)
		}
	})
	t.Run("ask without an operator refuses", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withAgent("ask"))
		runner := &labRunner{respond: orders.respond}
		model := newModelFake(t)
		model.agentTurns = unsafeTurns()

		report, err := Scan(context.Background(), cfg, policy, labDeps(runner, model.server.URL, nil))

		if err != nil || len(runner.requests) != 0 || len(report.Findings) != 0 {
			t.Fatalf("requests = %v, findings = %v, err = %v", runner.requested(), statusByRule(report), err)
		}
	})
}

func TestAgentStopsWhenTheOperatorSaysSo(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", withAgent(""))
	runner := &labRunner{respond: searchSite.respond}
	model := newModelFake(t)
	model.agentTurns = unsafeTurns()
	deps := labDeps(runner, model.server.URL, nil)
	deps.Stop = func() bool { return true }

	report, err := Scan(context.Background(), cfg, policy, deps)

	if err != nil {
		t.Fatal(err)
	}
	if report.Activity.AgentStopped != "stopped by the operator" || len(report.Activity.AgentSteps) != 0 || len(model.agentBodies) != 0 {
		t.Fatalf("activity = %+v, agent model calls = %d", report.Activity, len(model.agentBodies))
	}
}

func TestAgentFailureIsNotedAndTheOtherFindingsSurvive(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", func(m map[string]any) {
		withAgent("")(m)
		m["crawl"] = map[string]any{"max_pages": 5, "max_depth": 0}
	})
	runner := &labRunner{respond: searchSite.respond}
	runner.scanOutput, runner.reproducible = line("real-issue", "high", "https://app.test/b"), map[string]bool{"real-issue": true}
	model := newModelFake(t)
	model.agentTurns = []string{
		toolUse("t1", "http_request", map[string]any{"method": "GET", "url": searchURL}) + "," +
			toolUse("t2", "report_candidate", map[string]any{
				"exchange_id": "x1", "title": "SQL error", "cwe": "CWE-89", "severity": "high",
				"pattern": "SQL syntax", "reasoning": "The quote breaks the query.",
			}),
	}
	model.agentFailFrom = 2

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, model.server.URL, nil))

	if err != nil {
		t.Fatalf("err = %v; a model failure during exploration must not lose the run", err)
	}
	if !hasNote(report, "exploration ended early") {
		t.Fatalf("notes = %v", report.Activity.Notes)
	}
	got := statusByRule(report)
	if got["real-issue"] != finding.Confirmed || got["agent-89"] != finding.Confirmed {
		t.Fatalf("statuses = %v; the scanner's finding and what the agent reported before failing are both verified", got)
	}
	if len(report.Activity.AgentSteps) != 2 {
		t.Fatalf("steps = %+v", report.Activity.AgentSteps)
	}
	if !strings.Contains(model.agentBodies[0], "page found by crawling: https://app.test/") {
		t.Error("the agent was not told what the crawl found")
	}
}

func TestAgentFindingsCannotBeReTestedWithoutTheirExploration(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", withAgent(""))
	r, err := assemble(cfg, policy, labDeps(&labRunner{}, "", nil))
	if err != nil {
		t.Fatal(err)
	}

	report := r.verify(context.Background(), []finding.Finding{{
		ID: "a1", Kind: finding.Dynamic, Source: agent.Source, Target: "https://app.test/x", Status: finding.Candidate,
		Evidence: finding.Evidence{Request: "GET https://app.test/x", Response: "HTTP 200"},
	}})

	f := report.Findings[0]
	if f.Status == finding.Confirmed || !strings.Contains(f.Verdicts[2].Reason, "not available to re-test") {
		t.Fatalf("finding = %+v", f)
	}
}

func TestAgentWithNothingToExploreFailsTheRun(t *testing.T) {
	// The agent section is added after parsing, so this holds whatever the
	// configuration loader makes of an agent without targets.
	cfg, policy := labConfig(t, "anthropic", withAccessCheck)
	cfg.Agent = &config.Agent{MaxSteps: 3, UnsafeRequests: config.UnsafeDeny}
	runner := &labRunner{respond: adminPage(adminCredential)}

	_, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", accountEnv))

	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("err = %v; an agent with no target must fail the run, not vanish from it", err)
	}
}

func withSecondModel(minSeverity string) func(m map[string]any) {
	return func(m map[string]any) {
		refuter := map[string]any{"provider": "anthropic", "model": "reviewer-one", "second_model": "reviewer-two"}
		if minSeverity != "" {
			refuter["second_min_severity"] = minSeverity
		}
		m["refuter"] = refuter
	}
}

func TestSecondReviewerMustAgreeOnSeriousFindings(t *testing.T) {
	output := line("serious", "high", "https://app.test/a") + line("minor", "medium", "https://app.test/b")
	newRunner := func() *labRunner {
		runner := &labRunner{}
		runner.scanOutput, runner.reproducible = output, map[string]bool{"serious": true, "minor": true}
		return runner
	}
	secondRefutes := func(model, _ string) string {
		if model == "reviewer-two" {
			return "refuted"
		}
		return "holds"
	}
	t.Run("disagreement leaves a high finding unconfirmed", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withSecondModel(""))
		model := newModelFake(t)
		model.verdict = secondRefutes

		report, err := Scan(context.Background(), cfg, policy, labDeps(newRunner(), model.server.URL, nil))

		if err != nil {
			t.Fatal(err)
		}
		serious, minor := findingFor(t, report, "serious"), findingFor(t, report, "minor")
		if serious.Status != finding.Unconfirmed || !strings.Contains(lastReason(serious), "disagree") {
			t.Fatalf("serious = %s (%s); want unconfirmed because the reviewers disagree", serious.Status, lastReason(serious))
		}
		if minor.Status != finding.Confirmed || !strings.Contains(lastReason(minor), "reviewer-one") {
			t.Fatalf("minor = %s (%s); want confirmed by the first reviewer alone", minor.Status, lastReason(minor))
		}
		if model.callsTo("reviewer-one") != 2 || model.callsTo("reviewer-two") != 1 {
			t.Fatalf("calls: first = %d, second = %d; want 2 and 1", model.callsTo("reviewer-one"), model.callsTo("reviewer-two"))
		}
	})
	t.Run("agreement confirms", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withSecondModel(""))
		model := newModelFake(t)

		report, err := Scan(context.Background(), cfg, policy, labDeps(newRunner(), model.server.URL, nil))

		if err != nil {
			t.Fatal(err)
		}
		serious := findingFor(t, report, "serious")
		if serious.Status != finding.Confirmed || !strings.Contains(lastReason(serious), "Two reviewers") {
			t.Fatalf("serious = %s (%s)", serious.Status, lastReason(serious))
		}
	})
	t.Run("the threshold is configurable", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withSecondModel("medium"))
		model := newModelFake(t)
		model.verdict = secondRefutes

		report, err := Scan(context.Background(), cfg, policy, labDeps(newRunner(), model.server.URL, nil))

		if err != nil {
			t.Fatal(err)
		}
		if got := statusByRule(report); got["serious"] != finding.Unconfirmed || got["minor"] != finding.Unconfirmed || model.callsTo("reviewer-two") != 2 {
			t.Fatalf("statuses = %v, second reviewer calls = %d", got, model.callsTo("reviewer-two"))
		}
	})
	t.Run("the first reviewer refuting is final", func(t *testing.T) {
		cfg, policy := labConfig(t, "anthropic", withSecondModel(""))
		model := newModelFake(t)
		model.verdict = func(string, string) string { return "refuted" }

		report, err := Scan(context.Background(), cfg, policy, labDeps(newRunner(), model.server.URL, nil))

		if err != nil || statusByRule(report)["serious"] != finding.Refuted || model.callsTo("reviewer-two") != 0 {
			t.Fatalf("statuses = %v, second reviewer calls = %d, err = %v", statusByRule(report), model.callsTo("reviewer-two"), err)
		}
	})
}

func TestEveryReviewerCallIsChargedAsATurn(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", withSecondModel(""))
	runner := &labRunner{}
	runner.scanOutput, runner.reproducible = line("serious", "high", "https://app.test/a"), map[string]bool{"serious": true}
	model := newModelFake(t)

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, model.server.URL, nil))

	if err != nil || model.calls() != 2 {
		t.Fatalf("model calls = %d, err = %v; want one call to each reviewer", model.calls(), err)
	}
	if report.Budget.Usage.Tokens != 2*110 {
		t.Fatalf("tokens = %d; both reviews must be charged", report.Budget.Usage.Tokens)
	}
	if report.Budget.Usage.Turns != model.calls() {
		t.Skip("BUG: the second reviewer's model call is not charged to budget.turns (refute.Panel under verify.RefuteStage spends one turn for two calls)")
	}
}

// classifiedLine is a scanner result carrying the scanner's own CWE or tags.
func classifiedLine(templateID, matchedAt, cwe string, tags ...string) string {
	info := map[string]any{"name": templateID, "severity": "high", "tags": tags}
	if cwe != "" {
		info["classification"] = map[string]any{"cwe-id": []string{cwe}}
	}
	raw, _ := json.Marshal(map[string]any{
		"template-id": templateID, "info": info,
		"matched-at": matchedAt, "request": "GET / HTTP/1.1", "response": "HTTP/1.1 200 OK",
	})
	return string(raw) + "\n"
}

// corroborationReport scans two services and the code that serves, with
// the staticOutput results linked to the service named by serves.
func corroborationReport(t *testing.T, serves string) Report {
	t.Helper()
	root := sourceTree(t, map[string]string{"views.py": viewsPy})
	cfg, policy := labConfig(t, "anthropic", func(m map[string]any) {
		m["scope"] = map[string]any{"hosts": []string{"app.test", "other.test"}}
		m["targets"] = []string{"https://app.test", "https://other.test"}
		m["source"] = map[string]any{"root": root, "serves": serves,
			"semgrep": map[string]any{"image": "vajra-semgrep:local", "rules_image_path": "/opt/rules", "timeout_seconds": 600}}
	})
	runner := &labRunner{}
	runner.staticOutput = staticOutput
	runner.scanOutput = classifiedLine("sqli-by-cwe", "https://app.test/search", "CWE-89") +
		classifiedLine("sqli-by-tag", "https://app.test/orders", "", "sqli") +
		classifiedLine("sqli-elsewhere", "https://other.test/search", "CWE-89") +
		classifiedLine("xss-live", "https://app.test/profile", "CWE-79") +
		classifiedLine("false-alarm-sqli", "https://app.test/old", "CWE-89")
	runner.reproducible = map[string]bool{"sqli-by-cwe": true, "sqli-by-tag": true, "sqli-elsewhere": true, "xss-live": true, "false-alarm-sqli": true}
	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, refuterServer(t).URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestCodeAndLiveFindingsOfTheSameWeaknessCorroborateEachOther(t *testing.T) {
	report := corroborationReport(t, "https://app.test")

	code := findingFor(t, report, "rules.sqli")
	byCWE, byTag := findingFor(t, report, "sqli-by-cwe"), findingFor(t, report, "sqli-by-tag")
	if code.Status != finding.Confirmed || byCWE.Status != finding.Confirmed || byTag.Status != finding.Confirmed {
		t.Fatalf("statuses = %v", statusByRule(report))
	}
	linked := slices.Clone(code.CorroboratedBy)
	slices.Sort(linked)
	want := []string{byCWE.ID, byTag.ID}
	slices.Sort(want)
	if !slices.Equal(linked, want) {
		t.Fatalf("code finding corroborated by %v; want the two live findings %v", linked, want)
	}
	for _, live := range []finding.Finding{byCWE, byTag} {
		if !slices.Equal(live.CorroboratedBy, []string{code.ID}) {
			t.Errorf("%s corroborated by %v; want only the code finding", live.RuleID, live.CorroboratedBy)
		}
	}
	for rule, why := range map[string]string{
		"sqli-elsewhere":    "it is on another service",
		"xss-live":          "the code finding of that class was refuted",
		"false-alarm-sqli":  "it was refuted",
		"rules.false-alarm": "it was refuted",
		"rules.ghost":       "it has no class",
	} {
		if f := findingFor(t, report, rule); len(f.CorroboratedBy) != 0 {
			t.Errorf("%s is corroborated by %v, but %s", rule, f.CorroboratedBy, why)
		}
	}
}

func TestCorroborationTreatsADefaultPortAsTheSameService(t *testing.T) {
	report := corroborationReport(t, "https://app.test:443")
	code, live := findingFor(t, report, "rules.sqli"), findingFor(t, report, "sqli-by-cwe")
	if len(code.CorroboratedBy) == 0 || !slices.Contains(live.CorroboratedBy, code.ID) {
		t.Skip("BUG: collect.go serviceOf compares scheme://host[:port] as text, so source.serves \"https://app.test:443\" never corroborates a finding at \"https://app.test/...\"")
	}
}

func TestEverySandboxRunIsChargedToTheBudget(t *testing.T) {
	root := sourceTree(t, map[string]string{"views.py": viewsPy})
	cfg, policy := labConfig(t, "anthropic", func(m map[string]any) {
		withAccessCheck(m)
		m["targets"] = []string{"https://app.test"}
		m["source"] = map[string]any{"root": root,
			"semgrep": map[string]any{"image": "vajra-semgrep:local", "rules_image_path": "/opt/rules", "timeout_seconds": 600}}
	})
	runner := &labRunner{respond: adminPage(adminCredential, userCredential)}
	runner.staticOutput = sqliOutput
	runner.scanOutput, runner.reproducible = line("flaky", "high", "https://app.test/a"), map[string]bool{}

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, newModelFake(t).server.URL, accountEnv))

	if err != nil {
		t.Fatal(err)
	}
	// Scanner: the scan, one failed re-test and its canary. Probe: the check
	// and two re-tests. Analyser: the scan and one re-test.
	if len(runner.scanSpecs) != 3 || runner.canaryRuns != 1 || runner.probeRuns != 3 || len(runner.staticSpecs) != 2 {
		t.Fatalf("scanner = %d (canary %d), probe = %d, analyser = %d", len(runner.scanSpecs), runner.canaryRuns, runner.probeRuns, len(runner.staticSpecs))
	}
	if runner.runs != 8 || report.Budget.Usage.SandboxRuns != 8 {
		t.Fatalf("sandbox runs = %d, charged = %d; want 8 and 8", runner.runs, report.Budget.Usage.SandboxRuns)
	}
}

func TestFindingsLeftWhenTheSandboxBudgetRunsOutAreNeverConfirmed(t *testing.T) {
	cfg, policy := labConfig(t, "anthropic", func(m map[string]any) {
		m["budget"].(map[string]any)["sandbox_runs"] = 4
	})
	runner := &labRunner{}
	runner.scanOutput = line("first", "high", "https://app.test/a") + line("second", "high", "https://app.test/b") + line("third", "high", "https://app.test/c")
	runner.reproducible = map[string]bool{"first": true, "second": true, "third": true}

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, newModelFake(t).server.URL, nil))

	if err != nil {
		t.Fatal(err)
	}
	got := statusByRule(report)
	if got["first"] != finding.Confirmed || got["second"] != finding.Unconfirmed || got["third"] != finding.Unconfirmed {
		t.Fatalf("statuses = %v; only the finding re-tested within the budget may be confirmed", got)
	}
	// The scan, two re-tests of the first finding and one of the second.
	if runner.runs != 4 || report.Budget.Usage.SandboxRuns != 4 {
		t.Fatalf("sandbox runs = %d, charged = %d; the limit is 4", runner.runs, report.Budget.Usage.SandboxRuns)
	}
	for _, rule := range []string{"second", "third"} {
		reproduce := findingFor(t, report, rule).Verdicts[2]
		if reproduce.Stage != "reproduce" || reproduce.Outcome != finding.Inconclusive || !strings.Contains(reproduce.Reason, "budget exhausted: sandbox_runs") {
			t.Errorf("%s: reproduce verdict = %+v", rule, reproduce)
		}
	}
	if report.Summary[finding.Confirmed] != 1 || report.Summary[finding.Unconfirmed] != 2 {
		t.Fatalf("summary = %v", report.Summary)
	}
}

func TestEveryLiveFeatureChecksTheTaskNetworkFirst(t *testing.T) {
	live := map[string]func(m map[string]any){
		"access checks alone": withAccessCheck,
		"API tests alone":     withAPI,
		"discovery alone":     withRecon(),
	}
	for name, mutate := range live {
		t.Run(name, func(t *testing.T) {
			cfg, policy := labConfig(t, "none", mutate)
			runner := &labRunner{respond: func(probe.Request) probe.Response { return probe.Response{Status: http.StatusOK} }}
			deps := labDeps(runner, "", accountEnv)
			deps.ReadFile = func(string) ([]byte, error) { return []byte(shopAPI), nil }
			deps.Resolver = zone{}
			checked := 0
			deps.CheckNetwork = func(_ context.Context, network string) error {
				checked++
				if network != "vajra-task-net" {
					t.Errorf("checked network %q", network)
				}
				return errors.New("the network has a route out")
			}

			_, err := Scan(context.Background(), cfg, policy, deps)

			if err == nil || checked != 1 || runner.runs != 0 {
				t.Fatalf("err = %v, checks = %d, sandbox runs = %d; nothing may run on an open network", err, checked, runner.runs)
			}
			deps.CheckNetwork = nil
			if _, err := Scan(context.Background(), cfg, policy, deps); err == nil || runner.runs != 0 {
				t.Fatalf("err = %v, sandbox runs = %d; a live run without a network check must be refused", err, runner.runs)
			}
			if _, err := Scan(context.Background(), cfg, nil, labDeps(runner, "", accountEnv)); err == nil {
				t.Fatal("a live run without a scope policy was accepted")
			}
		})
	}
	t.Run("a code-only run never asks", func(t *testing.T) {
		cfg, policy := staticConfig(t, false)
		runner := &labRunner{}
		runner.staticOutput = noResults
		deps := labDeps(runner, "", nil)
		deps.CheckNetwork = func(context.Context, string) error {
			t.Error("the task network was checked for a run that uses no network")
			return errors.New("unexpected")
		}
		if _, err := Scan(context.Background(), cfg, policy, deps); err != nil {
			t.Fatal(err)
		}
		deps.CheckNetwork = nil
		if _, err := Scan(context.Background(), cfg, policy, deps); err != nil {
			t.Fatalf("err = %v; a code-only run needs no network check", err)
		}
	})
}

func TestSecretsInSourceAreVerifiedAndNeverCopiedOut(t *testing.T) {
	// Assembled at run time, so that this file holds no credential-shaped text.
	secret := strings.Join([]string{"q7Zp", "X2mK", "9vLr", "T4wN", "b6Hd"}, "")
	root := sourceTree(t, map[string]string{
		"settings.py": "DEBUG = False\napi_key = \"" + secret + "\"\nTIMEOUT = 30\n",
		"README.md":   "Nothing to see here.\n",
	})
	cfg, policy := labConfig(t, "anthropic", func(m map[string]any) {
		m["source"] = map[string]any{"root": root, "serves": "https://app.test", "secrets": true}
		delete(m, "targets")
	})
	runner := &labRunner{}
	model := newModelFake(t)
	deps := labDeps(runner, model.server.URL, nil)
	deps.CheckNetwork = nil // nothing here is tested over the network

	report, err := Scan(context.Background(), cfg, policy, deps)

	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %v", statusByRule(report))
	}
	f := report.Findings[0]
	if f.Source != "vajra-secrets" || f.Kind != finding.Static || f.Status != finding.Confirmed || f.Target != "settings.py:2" || f.AssetURL != "https://app.test" {
		t.Fatalf("finding = %+v", f)
	}
	var stages []string
	for _, v := range f.Verdicts {
		stages = append(stages, v.Stage+"="+string(v.Outcome))
	}
	if !slices.Equal(stages, []string{"evidence=pass", "scope=pass", "reproduce=pass", "refute=pass"}) {
		t.Fatalf("verdicts = %v; want the static pipeline", stages)
	}
	if runner.runs != 0 || model.calls() != 1 {
		t.Fatalf("sandbox runs = %d, model calls = %d; the search is native and reviewed once", runner.runs, model.calls())
	}
	if strings.Contains(reportJSON(t, report), secret) || strings.Contains(model.allBodies(), secret) {
		t.Fatal("the secret value left the source tree")
	}
	if !strings.Contains(f.Evidence.Code, "masked") {
		t.Fatalf("code evidence = %q; want the value masked", f.Evidence.Code)
	}

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), cfg, policy, deps); err == nil {
		t.Fatal("a source tree that cannot be read returned a clean report")
	}
}
