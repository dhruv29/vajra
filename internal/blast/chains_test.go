package blast

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/topology"
)

const (
	cweSSRF     = "cwe-918"
	cweRCE      = "cwe-78"
	cweSQLi     = "cwe-89"
	cweFileRead = "cwe-22"
	cweXSS      = "cwe-79"
)

// estate builds a graph from the URLs a run touched and what the operator
// declared.
func estate(t *testing.T, urls []string, d topology.Declaration) topology.Graph {
	t.Helper()
	b := topology.NewBuilder()
	for _, u := range urls {
		b.AddURL(u)
	}
	if err := b.AddDeclaration(d); err != nil {
		t.Fatal(err)
	}
	return b.Graph()
}

func calls(from, to string) topology.DeclaredLink {
	return topology.DeclaredLink{From: from, To: to, Relation: topology.Calls}
}

// at is a confirmed finding of the given class on a URL.
func at(id, target, cwe string, severity finding.Severity) finding.Finding {
	return finding.Finding{
		ID: id, Title: "Issue " + id, Target: target, Status: finding.Confirmed,
		Severity: severity, CWE: []string{cwe},
	}
}

func radiiOf(g topology.Graph, findings []finding.Finding) []Radius {
	out := make([]Radius, 0, len(findings))
	for _, f := range findings {
		out = append(out, Compute(g, f))
	}
	return out
}

// paths renders each chain as its finding IDs, in the order returned.
func paths(chains []Chain) []string {
	out := make([]string, 0, len(chains))
	for _, c := range chains {
		ids := make([]string, 0, len(c.Steps))
		for _, s := range c.Steps {
			ids = append(ids, s.FindingID)
		}
		out = append(out, strings.Join(ids, ">"))
	}
	return out
}

// pivotEstate is a public app that calls an internal billing service, which
// reads a ledger.
func pivotEstate(t *testing.T) (topology.Graph, []finding.Finding) {
	t.Helper()
	g := estate(t, []string{"https://app.test/fetch", "https://billing.internal/api/run"}, topology.Declaration{
		Assets: []topology.DeclaredAsset{
			{ID: "ledger", Kind: topology.Datastore, Name: "Ledger", DataClasses: []string{"financial"}},
		},
		Links: []topology.DeclaredLink{
			calls("app.test", "billing.internal"),
			{From: "billing.internal", To: "ledger", Relation: topology.Reads},
		},
	})
	return g, []finding.Finding{
		at("ssrf", "https://app.test/fetch?url=x", cweSSRF, finding.SeverityMedium),
		at("rce", "https://billing.internal/api/run", cweRCE, finding.SeverityMedium),
	}
}

func TestRequestForgeryChainsIntoCodeExecutionOnTheServiceItReaches(t *testing.T) {
	g, findings := pivotEstate(t)

	chains := Chains(g, findings, radiiOf(g, findings))

	if got := paths(chains); !slices.Equal(got, []string{"ssrf>rce"}) {
		t.Fatalf("chains = %v; want only ssrf>rce (code execution on billing reaches nothing that leads back)", got)
	}
	c := chains[0]
	first, second := c.Steps[0], c.Steps[1]
	if first.Via != "" || first.Capability != RequestForgery || first.OriginID != "endpoint:https://app.test/fetch" ||
		first.Title != "Issue ssrf" || !strings.Contains(first.Why, "request forgery") {
		t.Errorf("first step = %+v", first)
	}
	if second.Via != "host:billing.internal" || second.Capability != CodeExecution ||
		second.OriginID != "endpoint:https://billing.internal/api/run" || !strings.Contains(second.Why, "billing.internal") {
		t.Errorf("second step = %+v; want it entered through the host the forged request reaches", second)
	}
	wantReach := []string{
		"endpoint:https://app.test/fetch", "endpoint:https://billing.internal/api/run",
		"host:app.test", "host:billing.internal", "ledger",
		"service:app.test:443", "service:billing.internal:443",
	}
	if !slices.Equal(c.Reach, wantReach) || !slices.Equal(c.DataClasses, []string{"financial"}) {
		t.Errorf("reach = %v, data classes = %v", c.Reach, c.DataClasses)
	}
	// The stronger step scores 47; one extra step adds 8 and one data class
	// the first step could not reach adds 5.
	if c.Score != 60 {
		t.Errorf("score = %d; want 60", c.Score)
	}
	want := "2 findings combine: Issue ssrf -> Issue rce; together they reach 7 assets including data classed financial."
	if c.Summary != want {
		t.Errorf("summary = %q; want %q", c.Summary, want)
	}
}

// sharedKeyEstate is two unconnected services that authenticate with the
// same key.
func sharedKeyEstate(t *testing.T) topology.Graph {
	t.Helper()
	return estate(t, []string{"https://files.test/download", "https://vault.test/admin/exec"}, topology.Declaration{
		Assets: []topology.DeclaredAsset{
			{ID: "shared-key", Kind: topology.Identity, Name: "Shared signing key", DataClasses: []string{"credentials"}},
			{ID: "secrets-db", Kind: topology.Datastore, Name: "Secrets", DataClasses: []string{"secrets", "pii", "payment"}},
		},
		Links: []topology.DeclaredLink{
			{From: "files.test", To: "shared-key", Relation: topology.AuthenticatesWith},
			{From: "vault.test", To: "shared-key", Relation: topology.AuthenticatesWith},
			{From: "vault.test", To: "secrets-db", Relation: topology.Reads},
		},
	})
}

func TestALeakedCredentialChainsIntoTheServiceItBelongsTo(t *testing.T) {
	g := sharedKeyEstate(t)
	for _, cwe := range []string{cweFileRead, "cwe-798"} {
		t.Run(cwe, func(t *testing.T) {
			findings := []finding.Finding{
				at("leak", "https://files.test/download?f=x", cwe, finding.SeverityCritical),
				at("exec", "https://vault.test/admin/exec", cweRCE, finding.SeverityCritical),
			}

			chains := Chains(g, findings, radiiOf(g, findings))

			if got := paths(chains); !slices.Equal(got, []string{"leak>exec"}) {
				t.Fatalf("chains = %v; want only leak>exec", got)
			}
			second := chains[0].Steps[1]
			if second.Via != "shared-key" || !strings.Contains(second.Why, "credential Shared signing key") ||
				!strings.Contains(second.Why, "belongs to vault.test") {
				t.Errorf("second step = %+v; want it explained by the leaked credential", second)
			}
			if chains[0].Score != maxScore {
				t.Errorf("score = %d; want it capped at %d", chains[0].Score, maxScore)
			}
		})
	}
}

func TestACredentialOnlyLinksFindingsWhenThePreviousStepCanLeakIt(t *testing.T) {
	g := sharedKeyEstate(t)
	findings := []finding.Finding{
		// Code execution reaches the key too, but through the service that
		// holds it, not as a secret carried elsewhere.
		at("exec-files", "https://files.test/download", cweRCE, finding.SeverityHigh),
		at("exec-vault", "https://vault.test/admin/exec", cweRCE, finding.SeverityHigh),
	}

	chains := Chains(g, findings, radiiOf(g, findings))

	if len(chains) != 0 {
		t.Fatalf("chains = %v; want none", paths(chains))
	}
}

func TestAFindingOnAReachedServiceIsEnteredThroughThatService(t *testing.T) {
	g := estate(t, []string{"https://app.test/fetch", "https://app.test:8443/"}, topology.Declaration{
		Assets: []topology.DeclaredAsset{
			{ID: "orders-db", Kind: topology.Datastore, Name: "Orders", DataClasses: []string{"pii"}},
		},
		Links: []topology.DeclaredLink{{From: "app.test", To: "orders-db", Relation: topology.Reads}},
	})
	findings := []finding.Finding{
		at("ssrf", "https://app.test/fetch", cweSSRF, finding.SeverityMedium),
		at("sqli", "https://app.test:8443/", cweSQLi, finding.SeverityMedium),
	}

	chains := Chains(g, findings, radiiOf(g, findings))

	index := slices.Index(paths(chains), "ssrf>sqli")
	if index < 0 {
		t.Fatalf("chains = %v; want ssrf>sqli among them", paths(chains))
	}
	second := chains[index].Steps[1]
	if second.Via != "service:app.test:8443" || !strings.Contains(second.Why, "the asset this finding is on") {
		t.Errorf("second step = %+v; want the sibling service itself as the way in", second)
	}
}

func TestNoChainWhenTheSecondFindingAddsNoNewReach(t *testing.T) {
	cases := map[string]string{
		// The sibling service is already inside the first finding's radius.
		"finding on an asset already reached": "https://app.test:8443/",
		// A new endpoint on a reached service is not new reach by itself.
		"finding that reaches only its own endpoint": "https://app.test/profile",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			g := estate(t, []string{"https://app.test/api/run", target}, topology.Declaration{})
			findings := []finding.Finding{
				at("rce", "https://app.test/api/run", cweRCE, finding.SeverityHigh),
				at("xss", target, cweXSS, finding.SeverityHigh),
			}

			chains := Chains(g, findings, radiiOf(g, findings))

			if len(chains) != 0 {
				t.Fatalf("chains = %v; want none", paths(chains))
			}
		})
	}
}

func TestOnlyConfirmedFindingsTakePartInAChain(t *testing.T) {
	statuses := []finding.Status{finding.Unconfirmed, finding.Candidate, finding.Refuted, finding.OutOfScope}
	for _, status := range statuses {
		for step := range 2 {
			t.Run(fmt.Sprintf("%s step %d", status, step+1), func(t *testing.T) {
				g, findings := pivotEstate(t)
				findings[step].Status = status

				chains := Chains(g, findings, radiiOf(g, findings))

				if len(chains) != 0 {
					t.Fatalf("chains = %v; a %s finding must not appear in a chain", paths(chains), status)
				}
			})
		}
	}
}

func TestChainsNeverRepeatAFindingOrStayOnOneAsset(t *testing.T) {
	// Two services that call each other, so each finding can follow the other.
	g := estate(t, []string{"https://x.test/fetch", "https://y.test/fetch"}, topology.Declaration{
		Links: []topology.DeclaredLink{calls("x.test", "y.test"), calls("y.test", "x.test")},
	})
	findings := []finding.Finding{
		at("a", "https://x.test/fetch", cweSSRF, finding.SeverityMedium),
		at("b", "https://y.test/fetch", cweSSRF, finding.SeverityMedium),
		// On the same endpoint as "a": neither makes the other reachable.
		at("a2", "https://x.test/fetch?again=1", cweSSRF, finding.SeverityMedium),
		// The same finding reported twice.
		at("a", "https://x.test/fetch", cweSSRF, finding.SeverityMedium),
	}
	radii := radiiOf(g, findings)

	chains := Chains(g, findings, radii)

	if got := paths(chains); !slices.Equal(got, []string{"a>b", "a2>b", "b>a", "b>a2"}) {
		t.Fatalf("chains = %v", got)
	}
	for _, c := range chains {
		seen := map[string]bool{}
		for i, s := range c.Steps {
			if seen[s.FindingID] {
				t.Errorf("chain %v repeats %s", paths([]Chain{c}), s.FindingID)
			}
			seen[s.FindingID] = true
			if i > 0 && s.OriginID == c.Steps[i-1].OriginID {
				t.Errorf("chain %v links two findings on %s", paths([]Chain{c}), s.OriginID)
			}
		}
	}
}

// relayEstate is count services in a line, each calling the next, with a
// request forgery finding "f1".."fN" on each.
func relayEstate(t *testing.T, count int) (topology.Graph, []finding.Finding) {
	t.Helper()
	var urls []string
	var links []topology.DeclaredLink
	var findings []finding.Finding
	for i := 1; i <= count; i++ {
		target := fmt.Sprintf("https://s%d.test/fetch", i)
		urls = append(urls, target)
		findings = append(findings, at(fmt.Sprintf("f%d", i), target, cweSSRF, finding.SeverityMedium))
		if i < count {
			links = append(links, calls(fmt.Sprintf("s%d.test", i), fmt.Sprintf("s%d.test", i+1)))
		}
	}
	return estate(t, urls, topology.Declaration{Links: links}), findings
}

func TestChainsStopAtTheMaximumLengthAndDropPrefixes(t *testing.T) {
	g, findings := relayEstate(t, 6)

	chains := Chains(g, findings, radiiOf(g, findings))

	// Four steps is the limit, so the line of six is covered by overlapping
	// chains. f1>f2, f1>f2>f3 and the like are prefixes of longer chains and
	// are dropped. Ties in score are broken by finding IDs.
	want := []string{"f1>f2>f3>f4", "f2>f3>f4>f5", "f3>f4>f5>f6", "f4>f5>f6", "f5>f6"}
	if got := paths(chains); !slices.Equal(got, want) {
		t.Fatalf("chains = %v; want %v", got, want)
	}
	for i, c := range chains {
		if len(c.Steps) > maxChainSteps || len(c.Steps) < minChainSteps {
			t.Errorf("chain %d has %d steps", i, len(c.Steps))
		}
		if i > 0 && c.Score > chains[i-1].Score {
			t.Errorf("chain %d scores %d, above the %d before it", i, c.Score, chains[i-1].Score)
		}
	}
	// Each forgery scores 37 alone; three extra steps add 24.
	if chains[0].Score != 61 || chains[4].Score != 45 {
		t.Errorf("scores = %d and %d; want 61 for four steps and 45 for two", chains[0].Score, chains[4].Score)
	}
}

func TestChainsAreTheSameWhateverOrderTheInputsArriveIn(t *testing.T) {
	g, findings := relayEstate(t, 6)
	radii := radiiOf(g, findings)
	reversedFindings, reversedRadii := slices.Clone(findings), slices.Clone(radii)
	slices.Reverse(reversedFindings)
	slices.Reverse(reversedRadii[1:]) // and no longer aligned with the findings

	forward := Chains(g, findings, radii)
	backward := Chains(g, reversedFindings, reversedRadii)

	if !reflect.DeepEqual(forward, backward) {
		t.Fatalf("chains depend on input order:\n%v\n%v", paths(forward), paths(backward))
	}
}

func TestOnlyTheHighestScoringChainsAreReturned(t *testing.T) {
	const targets, weak = maxChains + 5, 3
	urls := []string{"https://hub.test/fetch"}
	findings := []finding.Finding{at("hub", "https://hub.test/fetch", cweSSRF, finding.SeverityLow)}
	var links []topology.DeclaredLink
	for i := range targets {
		host := fmt.Sprintf("t%02d.test", i)
		severity := finding.SeverityHigh
		if i < weak {
			severity = finding.SeverityLow // these sort first by ID, so only the score can exclude them
		}
		urls = append(urls, "https://"+host+"/run")
		links = append(links, calls("hub.test", host))
		findings = append(findings, at(host, "https://"+host+"/run", cweRCE, severity))
	}
	g := estate(t, urls, topology.Declaration{Links: links})

	chains := Chains(g, findings, radiiOf(g, findings))

	if len(chains) != maxChains {
		t.Fatalf("got %d chains; want the cap of %d", len(chains), maxChains)
	}
	for _, path := range paths(chains) {
		for i := range weak {
			if strings.HasSuffix(path, fmt.Sprintf("t%02d.test", i)) {
				t.Errorf("%s was kept ahead of a higher-scoring chain", path)
			}
		}
	}
}

func TestChainsWithNothingToCombineAreEmptyNotNil(t *testing.T) {
	g, findings := pivotEstate(t)
	radii := radiiOf(g, findings)
	outside := at("outside", "https://unknown.test/x", cweRCE, finding.SeverityCritical)
	cases := []struct {
		name     string
		graph    topology.Graph
		findings []finding.Finding
		radii    []Radius
	}{
		{"no inputs", topology.Graph{}, nil, nil},
		{"no radii", g, findings, nil},
		{"one finding", g, findings[:1], radii[:1]},
		{"radius missing for the second step", g, findings, radii[:1]},
		{"radius missing for the first step", g, findings, radii[1:]},
		{"finding outside the graph", g, []finding.Finding{findings[0], outside}, []Radius{radii[0], Compute(g, outside)}},
		{"radii for other findings", g, findings, []Radius{{FindingID: "someone-else", OriginID: "host:app.test"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chains := Chains(tc.graph, tc.findings, tc.radii)

			if chains == nil || len(chains) != 0 {
				t.Fatalf("chains = %#v; want an empty, non-nil slice", chains)
			}
		})
	}
}

func TestChainSummaryClipsLongTitlesAndNamesUntitledFindings(t *testing.T) {
	g, findings := pivotEstate(t)
	findings[0].Title = strings.Repeat("é", maxTitleRunes+20)
	findings[1].Title = "  "

	chains := Chains(g, findings, radiiOf(g, findings))

	if len(chains) != 1 {
		t.Fatalf("chains = %v", paths(chains))
	}
	clipped := strings.Repeat("é", maxTitleRunes-len(titleEllipsis)) + titleEllipsis
	if want := "2 findings combine: " + clipped + " -> rce; together"; !strings.HasPrefix(chains[0].Summary, want) {
		t.Errorf("summary = %q; want it to start %q", chains[0].Summary, want)
	}
	if chains[0].Steps[0].Title != findings[0].Title {
		t.Error("the step's own title was clipped; only the summary should be")
	}
}

func TestChainSummaryOmitsDataClassesWhenNoneAreReached(t *testing.T) {
	g, findings := relayEstate(t, 2)

	chains := Chains(g, findings, radiiOf(g, findings))

	want := "2 findings combine: Issue f1 -> Issue f2; together they reach 6 assets."
	if len(chains) != 1 || chains[0].Summary != want || chains[0].DataClasses == nil {
		t.Fatalf("chains = %+v; want one chain summarised %q", chains, want)
	}
}

func TestChainsTerminateOnACyclicDeclaration(t *testing.T) {
	// Two hosts each declared to host the other: the walk up from a finding
	// to what contains it must not loop.
	g := estate(t, []string{"https://x.test/fetch", "https://y.test/run"}, topology.Declaration{
		Links: []topology.DeclaredLink{
			{From: "x.test", To: "y.test", Relation: topology.Hosts},
			{From: "y.test", To: "x.test", Relation: topology.Hosts},
			calls("x.test", "z.test"),
		},
	})
	findings := []finding.Finding{
		at("a", "https://x.test/fetch", cweSSRF, finding.SeverityMedium),
		at("b", "https://y.test/run", cweRCE, finding.SeverityMedium),
	}

	chains := Chains(g, findings, radiiOf(g, findings))

	for _, c := range chains {
		if len(c.Steps) != minChainSteps {
			t.Errorf("chain %v; with two findings every chain has two steps", paths([]Chain{c}))
		}
	}
}
