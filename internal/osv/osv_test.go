package osv

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

func TestFindingsMapsEveryField(t *testing.T) {
	// Arrange
	pkg := parsePackageLock(packageLockSample)
	pkg = sortedUnique(pkg)[2:3] // lodash
	pkg[0].File = "web/package-lock.json"
	adv := Advisory{
		ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}, Summary: "Command Injection\n in   lodash",
		Severity: finding.SeverityHigh, FixedIn: []string{"4.17.21", "5.0.0"}, CWE: []string{"cwe-77"},
	}

	// Act
	got := Findings(pkg, [][]Advisory{{adv}})

	// Assert
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	want := finding.Finding{
		ID:          finding.StableID("osv", "GHSA-35jh-r3h4-6jhm", "npm/lodash@4.17.20", ""),
		Kind:        finding.Dependency,
		Source:      "osv",
		RuleID:      "GHSA-35jh-r3h4-6jhm",
		Title:       "lodash 4.17.20: Command Injection in lodash",
		Description: "Fixed in 4.17.21, 5.0.0.",
		Severity:    finding.SeverityHigh,
		Target:      "web/package-lock.json:9",
		Location:    &finding.Location{File: "web/package-lock.json", Line: 9},
		Tags:        []string{"dependency", "npm"},
		CWE:         []string{"cwe-77"},
		Status:      finding.Candidate,
		Evidence: finding.Evidence{
			Code:      ">     9 |     \"node_modules/lodash\": {\n>    10 |       \"version\": \"4.17.20\",\n",
			Extracted: []string{"npm/lodash@4.17.20"},
		},
	}
	gotJSON, _ := json.Marshal(got[0])
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("finding:\n got %s\nwant %s", gotJSON, wantJSON)
	}
}

func TestFindingsVariants(t *testing.T) {
	long := strings.Repeat("é", maxSummaryChars+40)
	tests := []struct {
		name            string
		pkg             Package
		adv             Advisory
		wantTitle       string
		wantDescription string
		wantTarget      string
		wantLocation    bool
	}{
		{
			name:            "no line, no summary, no fix",
			pkg:             Package{Ecosystem: "crates.io", Name: "time", Version: "0.1.0", File: "Cargo.lock", code: "ignored"},
			adv:             Advisory{ID: "RUSTSEC-2020-0071", Severity: finding.SeverityUnknown},
			wantTitle:       "time 0.1.0: RUSTSEC-2020-0071",
			wantDescription: "No fixed version is published.",
			wantTarget:      "Cargo.lock",
		},
		{
			name:            "long summary is clipped on a character boundary",
			pkg:             Package{Ecosystem: "PyPI", Name: "flask", Version: "2.0.1", File: "requirements.txt", Line: 3},
			adv:             Advisory{ID: "PYSEC-1", Summary: long, FixedIn: []string{"2.0.2"}},
			wantTitle:       "flask 2.0.1: " + strings.Repeat("é", maxSummaryChars),
			wantDescription: "Fixed in 2.0.2.",
			wantTarget:      "requirements.txt:3",
			wantLocation:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Findings([]Package{tt.pkg}, [][]Advisory{{tt.adv}})[0]

			if got.Title != tt.wantTitle || got.Description != tt.wantDescription || got.Target != tt.wantTarget {
				t.Errorf("title %q, description %q, target %q", got.Title, got.Description, got.Target)
			}
			if (got.Location != nil) != tt.wantLocation {
				t.Errorf("location = %v", got.Location)
			}
			if !tt.wantLocation && got.Evidence.Code != "" {
				t.Errorf("code %q shown without a line", got.Evidence.Code)
			}
			if got.Tags[1] != strings.ToLower(tt.pkg.Ecosystem) {
				t.Errorf("tags = %v", got.Tags)
			}
		})
	}
}

func TestFindingsOnePerPackageAndAdvisory(t *testing.T) {
	// Arrange
	pkgs := []Package{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0", File: "package-lock.json"},
		{Ecosystem: "npm", Name: "b", Version: "1.0.0", File: "package-lock.json"},
		{Ecosystem: "npm", Name: "c", Version: "1.0.0", File: "package-lock.json"},
	}
	advisories := [][]Advisory{{{ID: "X-1"}, {ID: "X-2"}}, nil, {{ID: "X-1"}}}

	// Act
	got := Findings(pkgs, advisories)

	// Assert
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f.ID] {
			t.Errorf("duplicate id %s", f.ID)
		}
		seen[f.ID] = true
	}
	if again := Findings(pkgs, advisories); again[0].ID != got[0].ID {
		t.Error("ids are not stable")
	}
	if short := Findings(pkgs, advisories[:1]); len(short) != 2 {
		t.Errorf("mismatched lengths: got %d findings, want 2", len(short))
	}
	if none := Findings(nil, nil); len(none) != 0 {
		t.Errorf("got %v from nothing", none)
	}
}
