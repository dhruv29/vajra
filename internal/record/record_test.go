package record

import (
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/topology"
)

func sampleReport() Report {
	return Report{
		GeneratedAt:   time.Unix(1_700_000_000, 0).UTC(),
		Authorization: Authorization{Operator: "sec@example.test"},
		Targets:       []string{"https://app.test"},
		Summary:       map[finding.Status]int{finding.Confirmed: 2, finding.Refuted: 1},
		Findings: []finding.Finding{
			{ID: "xss", Target: "https://app.test/search", Status: finding.Confirmed, Severity: finding.SeverityMedium, CWE: []string{"cwe-79"}},
			{ID: "sqli", Target: "https://app.test/orders", Status: finding.Confirmed, Severity: finding.SeverityHigh, CWE: []string{"cwe-89"}},
			{ID: "noise", Target: "https://app.test/x", Status: finding.Refuted, Severity: finding.SeverityCritical, CWE: []string{"cwe-78"}},
		},
	}
}

var sampleDeclaration = topology.Declaration{
	Assets: []topology.DeclaredAsset{{ID: "orders-db", Kind: topology.Datastore, Name: "Orders", DataClasses: []string{"pii"}}},
	Links:  []topology.DeclaredLink{{From: "app.test", To: "orders-db", Relation: topology.Reads}},
}

func TestBuildDerivesTheGraphAndRanksRadiiByScore(t *testing.T) {
	run, err := Build("run-1", sampleReport(), sampleDeclaration, nil)

	if err != nil {
		t.Fatal(err)
	}
	if _, ok := run.Graph.Asset("endpoint:https://app.test/orders"); !ok {
		t.Fatal("a finding's endpoint is missing from the graph")
	}
	if _, ok := run.Graph.Asset("orders-db"); !ok {
		t.Fatal("the declared data store is missing from the graph")
	}
	if len(run.Radii) != 3 || run.Radii[0].FindingID != "sqli" || run.Radii[2].FindingID != "noise" || run.Radii[2].Score != 0 {
		t.Fatalf("radii order = %+v", run.Radii)
	}
	if run.Reach != nil {
		t.Fatal("reach must be absent when no audit log was supplied")
	}
	if r, ok := run.Radius("sqli"); !ok || len(r.DataClasses) != 1 || r.DataClasses[0] != "pii" {
		t.Fatalf("sqli radius = %+v", r)
	}
	if _, ok := run.Radius("missing"); ok {
		t.Fatal("Radius found a finding that does not exist")
	}
}

func TestBuildSummarisesTheAuditLogWhenGiven(t *testing.T) {
	events := []egress.Event{{Target: "app.test:443", Allowed: true}, {Target: "evil.test:443", Reason: "host is not in scope"}}

	run, err := Build("run-1", sampleReport(), topology.Declaration{}, events)

	if err != nil || run.Reach == nil || run.Reach.AllowedTotal != 1 || run.Reach.DeniedTotal != 1 {
		t.Fatalf("reach = %+v, err = %v", run.Reach, err)
	}
}

func TestBuildRejectsABadDeclaration(t *testing.T) {
	bad := topology.Declaration{Assets: []topology.DeclaredAsset{{ID: "x", Kind: "spaceship", Name: "x"}}}
	if _, err := Build("run-1", sampleReport(), bad, nil); err == nil {
		t.Fatal("a bad declaration was accepted")
	}
}

func TestSummarizeReportsTheTopScore(t *testing.T) {
	run, _ := Build("run-1", sampleReport(), sampleDeclaration, nil)

	s := run.Summarize()

	if s.ID != "run-1" || s.Operator != "sec@example.test" || s.Counts[finding.Confirmed] != 2 || s.TopScore != run.Radii[0].Score || s.TopScore == 0 {
		t.Fatalf("summary = %+v", s)
	}
}
