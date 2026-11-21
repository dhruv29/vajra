package bench

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

func sqli(id string, status finding.Status) finding.Finding {
	return finding.Finding{
		ID: id, Kind: finding.Dynamic, RuleID: "generic-sqli-error", Target: "https://app.test/search?q=1",
		CWE: []string{"CWE-79", "CWE-89"}, Status: status,
	}
}

func sampleKey() Key {
	return Key{Name: "demo", Expectations: []Expectation{
		{Name: "sql injection in search", Present: true, CWE: "cwe-89", TargetContains: "/search"},
		{Name: "open redirect", Present: true, RuleContains: "open-redirect"},
		{Name: "escaped reflection", Present: false, RuleContains: "xss", TargetContains: "/safe"},
		{Name: "static decoy", Present: false, Kind: finding.Static, CWE: "CWE-22"},
	}}
}

func TestEvaluateClassifiesEachExpectation(t *testing.T) {
	present := Expectation{Name: "real", Present: true, CWE: "cwe-89"}
	decoy := Expectation{Name: "decoy", Present: false, CWE: "cwe-89"}
	tests := []struct {
		name       string
		exp        Expectation
		findings   []finding.Finding
		wantResult string
		wantID     string
		wantStatus finding.Status
	}{
		{"real issue confirmed is a true positive", present,
			[]finding.Finding{sqli("f1", finding.Confirmed)}, TruePositive, "f1", finding.Confirmed},
		{"real issue never found is a false negative", present, nil, FalseNegative, "", ""},
		{"real issue found but unconfirmed is a false negative that names the finding", present,
			[]finding.Finding{sqli("f1", finding.Unconfirmed)}, FalseNegative, "f1", finding.Unconfirmed},
		{"false negative records the match closest to confirmed", present,
			[]finding.Finding{sqli("f1", finding.OutOfScope), sqli("f2", finding.Refuted), sqli("f3", finding.Candidate), sqli("f4", finding.Unconfirmed), sqli("f5", finding.Unconfirmed)},
			FalseNegative, "f4", finding.Unconfirmed},
		{"a confirmed match wins over an earlier refuted one", present,
			[]finding.Finding{sqli("f1", finding.Refuted), sqli("f2", finding.Confirmed)}, TruePositive, "f2", finding.Confirmed},
		{"decoy confirmed is a false positive", decoy,
			[]finding.Finding{sqli("f1", finding.Confirmed)}, FalsePositive, "f1", finding.Confirmed},
		{"decoy refuted is a true negative", decoy,
			[]finding.Finding{sqli("f1", finding.Refuted)}, TrueNegative, "f1", finding.Refuted},
		{"decoy never found is a true negative", decoy, nil, TrueNegative, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := Key{Name: "k", Expectations: []Expectation{tt.exp}}

			got := Evaluate(key, tt.findings).Outcomes[0]

			if got.Result != tt.wantResult || got.FindingID != tt.wantID || got.Status != tt.wantStatus {
				t.Fatalf("outcome = %+v; want %s %q %q", got, tt.wantResult, tt.wantID, tt.wantStatus)
			}
		})
	}
}

func TestMatchRequiresEveryFilterThatIsSet(t *testing.T) {
	f := sqli("f1", finding.Confirmed)
	tests := []struct {
		name string
		exp  Expectation
		want bool
	}{
		{"cwe matches case-insensitively", Expectation{CWE: "cwe-89"}, true},
		{"cwe matches any of the finding's", Expectation{CWE: "CWE-79"}, true},
		{"cwe that is absent does not match", Expectation{CWE: "cwe-22"}, false},
		{"cwe is not a prefix match", Expectation{CWE: "cwe-8"}, false},
		{"rule substring matches", Expectation{RuleContains: "sqli"}, true},
		{"rule substring that is absent does not match", Expectation{RuleContains: "xss"}, false},
		{"target substring matches", Expectation{TargetContains: "/search"}, true},
		{"target substring that is absent does not match", Expectation{TargetContains: "/login"}, false},
		{"kind must agree", Expectation{Kind: finding.Static, CWE: "cwe-89"}, false},
		{"same kind matches", Expectation{Kind: finding.Dynamic, CWE: "cwe-89"}, true},
		{"one failing filter is enough to miss", Expectation{CWE: "cwe-89", RuleContains: "sqli", TargetContains: "/login"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matches(tt.exp, f); got != tt.want {
				t.Fatalf("matches = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateScoresAWholeRun(t *testing.T) {
	findings := []finding.Finding{
		sqli("f1", finding.Confirmed), // true positive
		{ID: "f2", RuleID: "open-redirect", Target: "https://app.test/go", Status: finding.Unconfirmed},      // false negative
		{ID: "f3", RuleID: "reflected-xss", Target: "https://app.test/safe", Status: finding.Confirmed},      // false positive
		{ID: "f4", Kind: finding.Static, CWE: []string{"CWE-22"}, Target: "a.go:3", Status: finding.Refuted}, // true negative
		{ID: "z9", RuleID: "exposed-panel", Target: "https://app.test/admin", Status: finding.Confirmed},     // unexpected
		{ID: "a1", RuleID: "tech-detect", Target: "https://app.test/", Status: finding.Confirmed},            // unexpected
		{ID: "n1", RuleID: "noise", Target: "https://app.test/", Status: finding.Refuted},
		{ID: "n2", RuleID: "noise", Target: "https://app.test/", Status: finding.Candidate},
	}

	got := Evaluate(sampleKey(), findings)

	if got.Key != "demo" || got.TruePositives != 1 || got.FalseNegatives != 1 || got.FalsePositives != 1 || got.TrueNegatives != 1 {
		t.Fatalf("counts = %+v", got)
	}
	wantOrder := []string{TruePositive, FalseNegative, FalsePositive, TrueNegative}
	for i, o := range got.Outcomes {
		if o.Result != wantOrder[i] || o.Expectation.Name != sampleKey().Expectations[i].Name {
			t.Errorf("outcome %d = %+v; want %s in key order", i, o, wantOrder[i])
		}
	}
	if !reflect.DeepEqual(got.Unexpected, []string{"a1", "z9"}) {
		t.Errorf("unexpected = %v; want sorted [a1 z9]", got.Unexpected)
	}
	if got.Precision != 0.25 { // 1 / (1 TP + 1 FP + 2 unexpected)
		t.Errorf("precision = %v; want 0.25", got.Precision)
	}
	if got.Recall != 0.5 {
		t.Errorf("recall = %v; want 0.5", got.Recall)
	}
	if got.NoiseRemoved != 0.5 { // 4 of 8 findings were not confirmed
		t.Errorf("noise removed = %v; want 0.5", got.NoiseRemoved)
	}
}

func TestRatiosWithZeroDenominators(t *testing.T) {
	onlyDecoys := Key{Name: "k", Expectations: []Expectation{{Name: "decoy", CWE: "cwe-1"}}}
	onlyReal := Key{Name: "k", Expectations: []Expectation{{Name: "real", Present: true, CWE: "cwe-89"}}}
	tests := []struct {
		name          string
		key           Key
		findings      []finding.Finding
		wantPrecision float64
		wantRecall    float64
		wantNoise     float64
	}{
		{"no findings at all", onlyDecoys, nil, 1, 1, 0},
		{"empty key and no findings", Key{}, nil, 1, 1, 0},
		{"nothing reported gives full precision but no recall", onlyReal,
			[]finding.Finding{sqli("f1", finding.Refuted)}, 1, 0, 1},
		{"no real issues gives full recall; an unexpected report costs precision", onlyDecoys,
			[]finding.Finding{sqli("f1", finding.Confirmed)}, 0, 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.key, tt.findings)

			if got.Precision != tt.wantPrecision || got.Recall != tt.wantRecall || got.NoiseRemoved != tt.wantNoise {
				t.Fatalf("precision, recall, noise = %v, %v, %v; want %v, %v, %v",
					got.Precision, got.Recall, got.NoiseRemoved, tt.wantPrecision, tt.wantRecall, tt.wantNoise)
			}
			if got.Outcomes == nil || got.Unexpected == nil {
				t.Fatalf("slices must be non-nil so they encode as []: %+v", got)
			}
		})
	}
}

func TestEvaluateDoesNotModifyItsInputs(t *testing.T) {
	key := sampleKey()
	findings := []finding.Finding{sqli("b", finding.Confirmed), {ID: "a", RuleID: "x", Status: finding.Confirmed}}

	Evaluate(key, findings)

	if !reflect.DeepEqual(key, sampleKey()) || findings[0].ID != "b" || findings[1].ID != "a" {
		t.Fatalf("inputs changed: %+v %+v", key, findings)
	}
}

func TestParseKeyAcceptsAValidKey(t *testing.T) {
	const raw = `{"name":"demo","expectations":[
		{"name":"sqli","present":true,"kind":"dast","cwe":"cwe-89","target_contains":"/search"},
		{"name":"decoy","present":false,"rule_contains":"xss"}]}`

	got, err := ParseKey(strings.NewReader(raw))

	want := Key{Name: "demo", Expectations: []Expectation{
		{Name: "sqli", Present: true, Kind: finding.Dynamic, CWE: "cwe-89", TargetContains: "/search"},
		{Name: "decoy", RuleContains: "xss"},
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("key = %+v, err = %v", got, err)
	}
}

func TestParseKeyRejectsInvalidKeys(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"malformed JSON", `{"name":`, "parse key"},
		{"unknown top-level field", `{"name":"k","expectation":[]}`, "unknown field"},
		{"misspelt filter", `{"name":"k","expectations":[{"name":"a","cwe":"cwe-1","rule_contain":"x"}]}`, "unknown field"},
		{"trailing data", `{"name":"k","expectations":[{"name":"a","cwe":"cwe-1"}]} {}`, "after the key"},
		{"no expectations", `{"name":"k","expectations":[]}`, "no expectations"},
		{"missing name", `{"name":"k","expectations":[{"cwe":"cwe-1"}]}`, "has no name"},
		{"blank name", `{"name":"k","expectations":[{"name":"  ","cwe":"cwe-1"}]}`, "has no name"},
		{"no filter", `{"name":"k","expectations":[{"name":"a","present":true}]}`, "needs cwe"},
		{"kind is not a filter on its own", `{"name":"k","expectations":[{"name":"a","kind":"sast"}]}`, "needs cwe"},
		{"unknown kind", `{"name":"k","expectations":[{"name":"a","kind":"iast","cwe":"cwe-1"}]}`, "unknown kind"},
		{"duplicate names", `{"name":"k","expectations":[{"name":"a","cwe":"cwe-1"},{"name":"a","cwe":"cwe-2"}]}`, "used twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKey(strings.NewReader(tt.raw))

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v; want one containing %q", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, Key{}) {
				t.Fatalf("a rejected key must come back empty, got %+v", got)
			}
		})
	}
}

func TestPassedNeedsBothThresholds(t *testing.T) {
	score := Score{Precision: 0.8, Recall: 0.6}
	tests := []struct {
		name                    string
		minPrecision, minRecall float64
		want                    bool
	}{
		{"both met exactly", 0.8, 0.6, true},
		{"both comfortably met", 0.5, 0.5, true},
		{"precision too low", 0.81, 0.6, false},
		{"recall too low", 0.8, 0.61, false},
		{"zero thresholds always pass", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := score.Passed(tt.minPrecision, tt.minRecall); got != tt.want {
				t.Fatalf("Passed = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestTextShowsOutcomesAndNumbers(t *testing.T) {
	findings := []finding.Finding{
		sqli("f1", finding.Confirmed),
		{ID: "f2", RuleID: "open-redirect", Status: finding.Unconfirmed},
		{ID: "u1", RuleID: "extra", Status: finding.Confirmed},
		{ID: "n1", RuleID: "noise", Status: finding.Refuted},
	}

	got := Evaluate(sampleKey(), findings).Text()

	for _, want := range []string{
		"Benchmark: demo", "RESULT", "sql injection in search", "true_positive", "false_negative",
		"true_negative", "f1", "f2", "unconfirmed", "Unexpected confirmed findings (1): u1",
		"true positives 1  false positives 0  false negatives 1  true negatives 2",
		"precision 0.50", "recall 0.50", "noise removed 50%",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text lacks %q:\n%s", want, got)
		}
	}
}

func TestTextOmitsUnexpectedLineAndStripsControlCharacters(t *testing.T) {
	key := Key{Name: "k\x1b[2J", Expectations: []Expectation{{Name: "a\nb", Present: true, CWE: "cwe-89"}}}

	got := Evaluate(key, []finding.Finding{sqli("f\x1b1", finding.Confirmed)}).Text()

	if strings.Contains(got, "Unexpected") {
		t.Errorf("no unexpected findings, yet:\n%s", got)
	}
	if strings.ContainsRune(got, '\x1b') || strings.Contains(got, "a\nb") {
		t.Errorf("control characters reached the terminal: %q", got)
	}
}

func TestEachConfirmedFindingCountsForOneRealIssueAtMost(t *testing.T) {
	real := Expectation{Name: "sql injection", Present: true, CWE: "cwe-89"}
	sameIssue := Expectation{Name: "sql injection in search", Present: true, TargetContains: "/search"}
	decoy := Expectation{Name: "decoy", Present: false, RuleContains: "sqli"}
	tests := []struct {
		name           string
		key            []Expectation
		findings       []finding.Finding
		wantResults    []string
		wantIDs        []string
		wantUnexpected []string
		wantPrecision  float64
		wantRecall     float64
	}{
		{"a second confirmed finding for one issue is unexpected", []Expectation{real},
			[]finding.Finding{sqli("f1", finding.Confirmed), sqli("f2", finding.Confirmed)},
			[]string{TruePositive}, []string{"f1"}, []string{"f2"}, 0.5, 1},
		{"one finding cannot satisfy two real issues", []Expectation{real, sameIssue},
			[]finding.Finding{sqli("f1", finding.Confirmed)},
			[]string{TruePositive, FalseNegative}, []string{"f1", ""}, []string{}, 1, 0.5},
		{"two findings satisfy two real issues in key order", []Expectation{real, sameIssue},
			[]finding.Finding{sqli("f1", finding.Confirmed), sqli("f2", finding.Confirmed)},
			[]string{TruePositive, TruePositive}, []string{"f1", "f2"}, []string{}, 1, 1},
		{"a false negative names an unconfirmed match, not a consumed one", []Expectation{real, sameIssue},
			[]finding.Finding{sqli("f1", finding.Confirmed), sqli("f2", finding.Unconfirmed)},
			[]string{TruePositive, FalseNegative}, []string{"f1", "f2"}, []string{}, 1, 0.5},
		{"a surplus duplicate that matches a decoy is the decoy's false positive", []Expectation{real, decoy},
			[]finding.Finding{sqli("f1", finding.Confirmed), sqli("f2", finding.Confirmed)},
			[]string{TruePositive, FalsePositive}, []string{"f1", "f1"}, []string{}, 0.5, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(Key{Name: "k", Expectations: tt.key}, tt.findings)

			var results, ids []string
			for _, o := range got.Outcomes {
				results, ids = append(results, o.Result), append(ids, o.FindingID)
			}
			if !reflect.DeepEqual(results, tt.wantResults) || !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Fatalf("outcomes = %v %v; want %v %v", results, ids, tt.wantResults, tt.wantIDs)
			}
			if !reflect.DeepEqual(got.Unexpected, tt.wantUnexpected) || got.Precision != tt.wantPrecision || got.Recall != tt.wantRecall {
				t.Fatalf("unexpected = %v, precision = %v, recall = %v; want %v, %v, %v",
					got.Unexpected, got.Precision, got.Recall, tt.wantUnexpected, tt.wantPrecision, tt.wantRecall)
			}
		})
	}
}
