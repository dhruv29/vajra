package verify

import (
	"context"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

func staticFinding() finding.Finding {
	return finding.Finding{
		ID: "s1", Kind: finding.Static, Source: "semgrep", RuleID: "sqli", Status: finding.Candidate,
		Target:   "app/views.py:4",
		Location: &finding.Location{File: "app/views.py", Line: 4},
		Evidence: finding.Evidence{Code: ">     4 | db.execute(query)\n"},
	}
}

func TestStaticStages(t *testing.T) {
	cases := []struct {
		name   string
		stage  Stage
		mutate func(*finding.Finding)
		want   finding.Outcome
	}{
		{"evidence present", CodeEvidenceStage{}, func(*finding.Finding) {}, finding.Pass},
		{"no location", CodeEvidenceStage{}, func(f *finding.Finding) { f.Location = nil }, finding.Fail},
		{"no line", CodeEvidenceStage{}, func(f *finding.Finding) { f.Location = &finding.Location{File: "a.py"} }, finding.Fail},
		{"source could not be read", CodeEvidenceStage{}, func(f *finding.Finding) { f.Evidence.Code = "" }, finding.Fail},
		{"file in the tree", SourceScopeStage{}, func(*finding.Finding) {}, finding.Pass},
		{"file outside the tree", SourceScopeStage{}, func(f *finding.Finding) { f.Location = &finding.Location{File: "../x.py", Line: 1} }, finding.Fail},
		{"absolute file", SourceScopeStage{}, func(f *finding.Finding) { f.Location = &finding.Location{File: "/etc/passwd", Line: 1} }, finding.Fail},
		{"scope without location", SourceScopeStage{}, func(f *finding.Finding) { f.Location = nil }, finding.Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := staticFinding()
			tc.mutate(&f)
			outcome, reason := tc.stage.Check(context.Background(), f)
			if outcome != tc.want || reason == "" {
				t.Fatalf("outcome = %s (%q); want %s", outcome, reason, tc.want)
			}
		})
	}
	if (CodeEvidenceStage{}).FailStatus() != finding.Unconfirmed || (SourceScopeStage{}).FailStatus() != finding.OutOfScope {
		t.Fatal("fail statuses are wrong")
	}
	if (CodeEvidenceStage{}).Name() != "evidence" || (SourceScopeStage{}).Name() != "scope" {
		t.Fatal("stage names are wrong")
	}
}
