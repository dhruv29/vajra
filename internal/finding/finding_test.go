package finding

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": SeverityCritical,
		" High ":   SeverityHigh,
		"MEDIUM":   SeverityMedium,
		"low":      SeverityLow,
		"info":     SeverityInfo,
		"":         SeverityUnknown,
		"severe":   SeverityUnknown,
	}
	for raw, want := range cases {
		if got := ParseSeverity(raw); got != want {
			t.Errorf("ParseSeverity(%q) = %q; want %q", raw, got, want)
		}
	}
}

func TestSeverityRankOrdersBySeriousness(t *testing.T) {
	order := []Severity{SeverityUnknown, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Errorf("%q should rank below %q", order[i-1], order[i])
		}
	}
}

func TestStableIDIsDeterministicAndFieldSensitive(t *testing.T) {
	a := StableID("nuclei", "rule-1", "https://app.test/x", "m")
	if a != StableID("nuclei", "rule-1", "https://app.test/x", "m") {
		t.Fatal("the same inputs gave different IDs")
	}
	if len(a) != 16 {
		t.Fatalf("len(ID) = %d; want 16", len(a))
	}
	others := []string{
		StableID("semgrep", "rule-1", "https://app.test/x", "m"),
		StableID("nuclei", "rule-2", "https://app.test/x", "m"),
		StableID("nuclei", "rule-1", "https://app.test/y", "m"),
		StableID("nuclei", "rule-1", "https://app.test/x", "n"),
		StableID("nuclei", "rule-1https://app.test/x", "", "m"), // field boundaries matter
	}
	for i, other := range others {
		if other == a {
			t.Errorf("variant %d collided with the original ID", i)
		}
	}
}

func TestWithVerdictAndWithStatusDoNotModifyTheOriginal(t *testing.T) {
	original := Finding{ID: "f1", Status: Candidate, Verdicts: make([]Verdict, 1, 4)}
	original.Verdicts[0] = Verdict{Stage: "evidence", Outcome: Pass}

	updated := original.WithVerdict(Verdict{Stage: "scope", Outcome: Fail}).WithStatus(OutOfScope)
	second := original.WithVerdict(Verdict{Stage: "other", Outcome: Pass})

	if original.Status != Candidate || len(original.Verdicts) != 1 {
		t.Fatalf("original was modified: %+v", original)
	}
	if updated.Status != OutOfScope || len(updated.Verdicts) != 2 || updated.Verdicts[1].Stage != "scope" {
		t.Fatalf("updated = %+v", updated)
	}
	if second.Verdicts[1].Stage != "other" || updated.Verdicts[1].Stage != "scope" {
		t.Fatal("two copies share the same backing array")
	}
}

func TestSafeRelPath(t *testing.T) {
	for path, want := range map[string]bool{
		"a.py": true, "app/views.py": true, "-rf": true, "a..b/c.py": true,
		"": false, "/etc/passwd": false, "..": false, "../x": false, "a/../../x": false, "a//b": false, "./a": false, "a\x00b": false,
	} {
		if got := SafeRelPath(path); got != want {
			t.Errorf("SafeRelPath(%q) = %v; want %v", path, got, want)
		}
	}
}
