package blast

import (
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/topology"
)

// labGraph is a small estate: a web app with an admin service on the same
// host, an orders database, a deploy key, and a billing service that reads a
// ledger.
func labGraph(t *testing.T) topology.Graph {
	t.Helper()
	b := topology.NewBuilder()
	b.AddURL("https://app.test/api/run")
	b.AddURL("https://app.test:8443/admin")
	err := b.AddDeclaration(topology.Declaration{
		Assets: []topology.DeclaredAsset{
			{ID: "orders-db", Kind: topology.Datastore, Name: "Orders database", DataClasses: []string{"pii", "payment"}},
			{ID: "deploy-key", Kind: topology.Identity, Name: "Deploy key", DataClasses: []string{"credentials"}},
			{ID: "ledger", Kind: topology.Datastore, Name: "Ledger", DataClasses: []string{"financial"}},
			{ID: "wiki", Kind: topology.Datastore, Name: "Wiki", DataClasses: []string{"internal-docs"}},
		},
		Links: []topology.DeclaredLink{
			{From: "app.test", To: "orders-db", Relation: topology.Reads},
			{From: "app.test", To: "deploy-key", Relation: topology.AuthenticatesWith},
			{From: "app.test", To: "billing.internal", Relation: topology.Calls},
			{From: "billing.internal", To: "ledger", Relation: topology.Reads},
			{From: "unrelated.test", To: "wiki", Relation: topology.Reads},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.Graph()
}

func confirmed(cwe string, severity finding.Severity) finding.Finding {
	return finding.Finding{
		ID: "f1", Target: "https://app.test/api/run?cmd=id", Status: finding.Confirmed,
		Severity: severity, CWE: []string{cwe},
	}
}

func reached(r Radius) map[string]Hop {
	out := map[string]Hop{}
	for _, h := range r.Reach {
		out[h.AssetID] = h
	}
	return out
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		f    finding.Finding
		want Capability
	}{
		{"cwe wins", finding.Finding{CWE: []string{"CWE-89"}, Tags: []string{"xss"}}, DataAccess},
		{"strongest cwe wins", finding.Finding{CWE: []string{"cwe-200", " cwe-78 "}}, CodeExecution},
		{"tags when no cwe matches", finding.Finding{CWE: []string{"cwe-99999"}, Tags: []string{"exposure", "ssrf"}}, RequestForgery},
		{"nothing known", finding.Finding{Tags: []string{"tech"}}, Unclassified},
		{"exposed secret upgrades a disclosure", finding.Finding{
			CWE: []string{"cwe-200"}, Evidence: finding.Evidence{Extracted: []string{"DB_PASSWORD=hunter2"}},
		}, CredentialExposure},
		{"exposed secret upgrades an unclassified finding", finding.Finding{
			Evidence: finding.Evidence{Extracted: []string{"api_key: abc123"}},
		}, CredentialExposure},
		{"exposed secret does not downgrade code execution", finding.Finding{
			CWE: []string{"cwe-94"}, Evidence: finding.Evidence{Extracted: []string{"token=abc"}},
		}, CodeExecution},
		{"ordinary extracted text is not a secret", finding.Finding{
			CWE: []string{"cwe-200"}, Evidence: finding.Evidence{Extracted: []string{"nginx/1.25", "password reset page"}},
		}, InfoDisclosure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, basis := Classify(tc.f)
			if got != tc.want || basis == "" {
				t.Fatalf("Classify = %s (%q); want %s", got, basis, tc.want)
			}
		})
	}
}

func TestCodeExecutionSpreadsAcrossTheHostAndWhatItCanReach(t *testing.T) {
	r := Compute(labGraph(t), confirmed("cwe-78", finding.SeverityCritical))
	got := reached(r)

	want := map[string]Confidence{
		"endpoint:https://app.test/api/run": Proven,
		"service:app.test:443":              Inferred,
		"host:app.test":                     Inferred,
		"service:app.test:8443":             Inferred, // sibling on the same host
		"orders-db":                         Inferred,
		"deploy-key":                        Inferred,
		"host:billing.internal":             Assumed,
		"ledger":                            Assumed, // one step past a called service
	}
	if len(got) != len(want) {
		t.Fatalf("reach = %v", slices.Collect(mapKeys(got)))
	}
	for id, confidence := range want {
		if got[id].Confidence != confidence || got[id].Why == "" || got[id].Name == "" {
			t.Errorf("%s = %+v; want confidence %s", id, got[id], confidence)
		}
	}
	if _, leaked := got["wiki"]; leaked {
		t.Error("an unconnected asset is inside the radius")
	}
	if got["endpoint:https://app.test/api/run"].Depth != 0 || got["ledger"].Depth != 3 || got["orders-db"].From != "host:app.test" {
		t.Errorf("depths or routes are wrong: %+v", r.Reach)
	}
	if !slices.Equal(r.DataClasses, []string{"credentials", "financial", "payment", "pii"}) {
		t.Errorf("data classes = %v", r.DataClasses)
	}
	if r.Score != 100 || r.OriginID != "endpoint:https://app.test/api/run" {
		t.Errorf("score = %d, origin = %s", r.Score, r.OriginID)
	}
	if !strings.Contains(r.Summary, "code execution reaches 7 further asset(s)") || !strings.Contains(r.Summary, "pii") {
		t.Errorf("summary = %q", r.Summary)
	}
}

func mapKeys(m map[string]Hop) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func TestEachCapabilityReachesOnlyWhatItAllows(t *testing.T) {
	cases := []struct {
		cwe        string
		capability Capability
		reaches    []string
		excludes   []string
	}{
		{"cwe-89", DataAccess, []string{"orders-db", "host:app.test"}, []string{"deploy-key", "host:billing.internal", "service:app.test:8443"}},
		{"cwe-22", FileRead, []string{"host:app.test", "deploy-key"}, []string{"orders-db", "host:billing.internal"}},
		{"cwe-798", CredentialExposure, []string{"deploy-key", "orders-db"}, []string{"host:billing.internal", "ledger"}},
		{"cwe-287", AuthBypass, []string{"service:app.test:443", "orders-db"}, []string{"deploy-key", "service:app.test:8443"}},
		{"cwe-918", RequestForgery, []string{"host:billing.internal", "service:app.test:8443"}, []string{"orders-db", "ledger", "deploy-key"}},
		{"cwe-79", ClientSide, nil, []string{"service:app.test:443", "host:app.test", "orders-db"}},
		{"cwe-200", InfoDisclosure, nil, []string{"host:app.test", "orders-db"}},
	}
	g := labGraph(t)
	for _, tc := range cases {
		t.Run(string(tc.capability), func(t *testing.T) {
			r := Compute(g, confirmed(tc.cwe, finding.SeverityHigh))
			got := reached(r)
			if r.Capability != tc.capability {
				t.Fatalf("capability = %s", r.Capability)
			}
			for _, id := range tc.reaches {
				if _, ok := got[id]; !ok {
					t.Errorf("%s should be reachable; reach = %v", id, slices.Collect(mapKeys(got)))
				}
			}
			for _, id := range tc.excludes {
				if _, ok := got[id]; ok {
					t.Errorf("%s should not be reachable", id)
				}
			}
			if tc.reaches == nil && (len(r.Reach) != 1 || !strings.HasPrefix(r.Summary, "Limited to")) {
				t.Errorf("reach = %+v, summary = %q; want the origin only", r.Reach, r.Summary)
			}
		})
	}
}

func TestScoreRanksByImpactAndDiscountsUnconfirmed(t *testing.T) {
	g := labGraph(t)
	rce := Compute(g, confirmed("cwe-78", finding.SeverityHigh)).Score
	sqli := Compute(g, confirmed("cwe-89", finding.SeverityHigh)).Score
	xss := Compute(g, confirmed("cwe-79", finding.SeverityHigh)).Score
	lowXSS := Compute(g, confirmed("cwe-79", finding.SeverityLow)).Score
	if !(rce > sqli && sqli > xss && xss > lowXSS && lowXSS > 0) {
		t.Fatalf("scores: rce %d, sqli %d, xss %d, low xss %d; want strictly descending", rce, sqli, xss, lowXSS)
	}
	if xss != 35 {
		t.Fatalf("a confirmed high finding with no spread scores %d; want its severity points, 35", xss)
	}

	unconfirmed := confirmed("cwe-89", finding.SeverityHigh)
	unconfirmed.Status = finding.Unconfirmed
	r := Compute(g, unconfirmed)
	if r.Score >= sqli || r.Score == 0 {
		t.Fatalf("unconfirmed score = %d; want below the confirmed %d and above 0", r.Score, sqli)
	}
	if r.Reach[0].Confidence != Assumed {
		t.Fatalf("origin confidence = %s; an unconfirmed finding is not proven", r.Reach[0].Confidence)
	}
}

func TestRefutedAndOutOfScopeFindingsHaveNoRadius(t *testing.T) {
	g := labGraph(t)
	for _, status := range []finding.Status{finding.Refuted, finding.OutOfScope} {
		f := confirmed("cwe-78", finding.SeverityCritical)
		f.Status = status

		r := Compute(g, f)

		if r.Score != 0 || len(r.Reach) != 1 || !strings.HasPrefix(r.Summary, "No blast radius") {
			t.Errorf("%s: score = %d, reach = %d, summary = %q", status, r.Score, len(r.Reach), r.Summary)
		}
	}
}

func TestFindingOutsideTheGraphGetsAnEmptyRadius(t *testing.T) {
	f := confirmed("cwe-78", finding.SeverityCritical)
	f.Target = "https://unknown.test/x"

	r := Compute(labGraph(t), f)

	if r.OriginID != "" || r.Score != 0 || r.Reach == nil || len(r.Reach) != 0 || r.DataClasses == nil || r.Summary == "" {
		t.Fatalf("radius = %+v", r)
	}
}

func TestServiceLevelFindingUsesItsHost(t *testing.T) {
	f := confirmed("cwe-89", finding.SeverityHigh)
	f.Target = "https://app.test/"

	got := reached(Compute(labGraph(t), f))

	if _, ok := got["orders-db"]; !ok || got["service:app.test:443"].Depth != 0 {
		t.Fatalf("reach = %+v", got)
	}
}
