package demo

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/report"
)

func TestRunIsConsistentAndRenders(t *testing.T) {
	run, err := Run("20261121-195440-0a1b2c3d", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}

	counted := 0
	for _, n := range run.Report.Summary {
		counted += n
	}
	if counted != len(run.Report.Findings) || len(run.Radii) != len(run.Report.Findings) {
		t.Fatalf("summary counts %d of %d findings; radii = %d", counted, len(run.Report.Findings), len(run.Radii))
	}
	if run.Report.Summary[finding.Confirmed] != 4 || run.Radii[0].FindingID != "demo-rce" || run.Radii[0].Score < 90 {
		t.Fatalf("summary = %v, top radius = %+v", run.Report.Summary, run.Radii[0])
	}
	if env, _ := run.Radius("demo-env"); env.Capability != "credential_exposure" {
		t.Fatalf("the exposed key was classified as %s", env.Capability)
	}
	if run.Reach == nil || run.Reach.DeniedTotal != 14 {
		t.Fatalf("reach = %+v", run.Reach)
	}
	if code, _ := run.Radius("demo-code-cmdi"); code.OriginID != "service:shop.example.test:443" || code.Score < 80 {
		t.Fatalf("the code finding is not anchored to its service: %+v", code)
	}
	for _, f := range run.Report.Findings {
		if f.Kind == finding.Static || f.Kind == finding.Dependency {
			continue
		}
		if !strings.Contains(f.Target, ".example.test") {
			t.Errorf("%s uses a host that is not reserved for examples: %s", f.ID, f.Target)
		}
	}
	html, err := report.HTML(run)
	if err != nil || !strings.Contains(string(html), "8 findings need attention") {
		t.Fatalf("HTML report: err = %v", err)
	}
}

func sampleRun(t *testing.T) record.Run {
	t.Helper()
	run, err := Run("20261121-195440-0a1b2c3d", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func findingByID(t *testing.T, run record.Run, id string) finding.Finding {
	t.Helper()
	for _, f := range run.Report.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("the sample run has no finding %s", id)
	return finding.Finding{}
}

func TestRunShowsEveryKindOfFinding(t *testing.T) {
	run := sampleRun(t)

	want := map[finding.Status]int{finding.Confirmed: 4, finding.Unconfirmed: 4, finding.Refuted: 2, finding.OutOfScope: 1}
	for status, n := range want {
		if run.Report.Summary[status] != n {
			t.Errorf("%d findings are %s; want %d", run.Report.Summary[status], status, n)
		}
	}

	dep := findingByID(t, run, "demo-dep-lodash")
	if dep.Kind != finding.Dependency || dep.Source != "osv" || len(dep.Evidence.Extracted) != 1 ||
		dep.Evidence.Extracted[0] != "npm/lodash@4.17.20" || !strings.Contains(dep.Evidence.Code, `"version": "4.17.20"`) {
		t.Errorf("the dependency finding does not show its package and lockfile line: %+v", dep)
	}

	secret := findingByID(t, run, "demo-secret")
	if secret.Kind != finding.Static || secret.Source != "vajra-secrets" {
		t.Errorf("the secret finding = %+v", secret)
	}
	// Every quoted value near the secret must be masked or plainly not one.
	if !strings.Contains(secret.Evidence.Code, "[masked 20 chars]") || !strings.Contains(secret.Evidence.Extracted[0], "[masked") ||
		strings.Count(secret.Evidence.Code, "MAIL_PASSWORD") != 1 {
		t.Errorf("the secret finding shows something other than a masked value: %q", secret.Evidence.Code)
	}
	if radius, _ := run.Radius("demo-secret"); radius.Capability != "credential_exposure" || radius.OriginID == "" {
		t.Errorf("the secret finding's radius = %+v", radius)
	}
}

func TestRunHasCodeAndLiveFindingsThatCorroborateEachOther(t *testing.T) {
	run := sampleRun(t)
	pairs := 0
	for _, f := range run.Report.Findings {
		for _, otherID := range f.CorroboratedBy {
			other := findingByID(t, run, otherID)
			isCode := func(k finding.Kind) bool { return k == finding.Static }
			if isCode(f.Kind) == isCode(other.Kind) {
				t.Errorf("%s and %s are of the same kind, so neither corroborates the other", f.ID, otherID)
			}
			if !slices.Contains(other.CorroboratedBy, f.ID) {
				t.Errorf("%s names %s, but not the other way round", f.ID, otherID)
			}
			pairs++
		}
	}
	if pairs == 0 || len(findingByID(t, run, "demo-code-cmdi").CorroboratedBy) != 2 {
		t.Fatalf("corroborating pairs = %d", pairs)
	}
}

func TestRunHasAChainThatCrossesHosts(t *testing.T) {
	run := sampleRun(t)

	if len(run.Chains) < 1 {
		t.Fatal("the sample run has no attack chain")
	}
	for _, chain := range run.Chains {
		for _, step := range chain.Steps {
			if findingByID(t, run, step.FindingID).Status != finding.Confirmed {
				t.Errorf("chain step %s is not a confirmed finding", step.FindingID)
			}
		}
	}
	crossing := slices.ContainsFunc(run.Chains, func(c blast.Chain) bool {
		return c.Steps[0].FindingID == "demo-env" && strings.Contains(c.Steps[1].Why, "Payments API key")
	})
	if !crossing {
		t.Errorf("no chain starts with the key leaked on staging: %+v", run.Chains)
	}
}

func TestRunRecordsItsActivity(t *testing.T) {
	a := sampleRun(t).Report.Activity

	if len(a.DiscoveredHosts) < 1 || len(a.RejectedHosts) != 1 || a.PagesCrawled == 0 || len(a.SkippedOperations) != 1 ||
		len(a.AgentSteps) < 3 || a.AgentStopped == "" || a.AgentSummary == "" || len(a.Notes) != 1 {
		t.Fatalf("activity = %+v", a)
	}
	if n := len(a.Packages); n < 2 || n > 3 {
		t.Errorf("%d packages inventoried; want two or three", n)
	}
	hosts := slices.Concat(a.DiscoveredHosts, a.RejectedHosts)
	for _, host := range hosts {
		if !strings.HasSuffix(host, ".example.test") {
			t.Errorf("%s is not reserved for examples", host)
		}
	}
	for _, endpoint := range a.Endpoints {
		if !strings.HasPrefix(endpoint, "https://shop.example.test/") {
			t.Errorf("endpoint %s is not on the sample target", endpoint)
		}
	}
	for i, step := range a.AgentSteps {
		if step.N != i+1 || step.Tool == "" || step.Summary == "" || step.Outcome == "" {
			t.Errorf("explorer step %d = %+v", i, step)
		}
	}
}

func TestRunRendersEveryNewSectionInBothFormats(t *testing.T) {
	run := sampleRun(t)

	page, err := report.HTML(run)
	if err != nil {
		t.Fatal(err)
	}
	doc := report.Markdown(run)

	for format, text := range map[string]string{"HTML": string(page), "Markdown": doc} {
		for _, want := range []string{
			"Attack chains", "Chain 1", "Corroborated by", "live test", "code analysis", "dependency",
			"What else the run did", "staging.shop.example.test", "legacy.shop.example.test", "37 page(s) crawled",
			"3 package(s) inventoried", "Autonomous explorer", "Why it stopped: finished", "page limit of 37",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s report: missing %q", format, want)
			}
		}
	}
	if !strings.Contains(doc, "| confirmed | 4 |") {
		t.Error("the sample run must keep exactly four confirmed findings")
	}
}
