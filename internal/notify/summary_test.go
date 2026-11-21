package notify

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
)

func confirmed(id, title string) finding.Finding {
	return finding.Finding{
		ID: id, Title: title, Severity: finding.SeverityHigh, Status: finding.Confirmed,
		Target:   "https://app.test/" + id,
		Evidence: finding.Evidence{Request: "GET /secret-request", Response: "secret-response-body"},
	}
}

func runWith(findings []finding.Finding, radii []blast.Radius) record.Run {
	return record.Run{
		ID:     "20261121-195440-0a1b2c3d",
		Report: record.Report{Targets: []string{"https://app.test"}, Findings: findings},
		Radii:  radii,
	}
}

func TestSummarizeCountsFindingsByStatus(t *testing.T) {
	run := runWith([]finding.Finding{
		confirmed("c1", "SQL injection"),
		{ID: "u1", Status: finding.Unconfirmed},
		{ID: "u2", Status: finding.Unconfirmed},
		{ID: "r1", Status: finding.Refuted},
		{ID: "r2", Status: finding.Refuted},
		{ID: "r3", Status: finding.Refuted},
		{ID: "o1", Status: finding.OutOfScope},
		{ID: "x1", Status: finding.Candidate},
	}, []blast.Radius{{FindingID: "c1", Score: 80}})

	got := Summarize(run)

	want := Summary{
		RunID: "20261121-195440-0a1b2c3d", Targets: []string{"https://app.test"},
		Confirmed: 1, Unconfirmed: 2, Refuted: 3, OutOfScope: 1,
		TopFindings: []TopFinding{{Title: "SQL injection", Severity: "high", Score: 80, Target: "https://app.test/c1"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary = %+v\nwant      %+v", got, want)
	}
}

func TestSummarizeRanksConfirmedFindingsByScoreAndKeepsFive(t *testing.T) {
	scores := []int{10, 90, 40, 90, 70, 20, 60}
	findings := []finding.Finding{{ID: "refuted", Title: "refuted", Status: finding.Refuted}}
	radii := []blast.Radius{{FindingID: "refuted", Score: 100}}
	for i, score := range scores {
		id := fmt.Sprintf("f%d", i)
		findings = append(findings, confirmed(id, id))
		radii = append(radii, blast.Radius{FindingID: id, Score: score})
	}
	findings = append(findings, confirmed("unscored", "unscored"))

	got := Summarize(runWith(findings, radii))

	titles := []string{}
	for _, top := range got.TopFindings {
		titles = append(titles, fmt.Sprintf("%s=%d", top.Title, top.Score))
	}
	// f1 and f3 tie at 90 and keep the report's order.
	want := []string{"f1=90", "f3=90", "f4=70", "f6=60", "f2=40"}
	if !reflect.DeepEqual(titles, want) {
		t.Fatalf("top findings = %v; want %v", titles, want)
	}
	if got.Confirmed != len(scores)+1 {
		t.Fatalf("confirmed = %d; want every confirmed finding counted, not only the top five", got.Confirmed)
	}
}

func TestSummarizeClipsTitlesAndTargetsOnCharacterBoundaries(t *testing.T) {
	long := strings.Repeat("é", 300)
	f := confirmed("c1", long)
	f.Target = "https://app.test/" + long
	run := runWith([]finding.Finding{f}, nil)
	run.Report.Targets = []string{long, "https://short.test"}

	got := Summarize(run)

	for name, value := range map[string]string{
		"title": got.TopFindings[0].Title, "finding target": got.TopFindings[0].Target, "run target": got.Targets[0],
	} {
		if n := utf8.RuneCountInString(value); n != 200 || !utf8.ValidString(value) {
			t.Errorf("%s: %d chars, valid = %v; want 200 valid chars", name, n, utf8.ValidString(value))
		}
	}
	if got.Targets[1] != "https://short.test" {
		t.Errorf("short target changed: %q", got.Targets[1])
	}
}

func TestSummaryJSONHasTheDocumentedShapeAndNoEvidence(t *testing.T) {
	run := runWith([]finding.Finding{confirmed("c1", "SQL injection")}, []blast.Radius{{FindingID: "c1", Score: 80}})

	raw, err := json.Marshal(Summarize(run))
	if err != nil {
		t.Fatal(err)
	}

	const want = `{"run_id":"20261121-195440-0a1b2c3d","targets":["https://app.test"],` +
		`"confirmed":1,"unconfirmed":0,"refuted":0,"out_of_scope":0,` +
		`"top_findings":[{"title":"SQL injection","severity":"high","score":80,"target":"https://app.test/c1"}]}`
	if string(raw) != want {
		t.Fatalf("payload = %s\nwant      %s", raw, want)
	}
}

func TestSummaryOfAnEmptyRunEncodesListsNotNull(t *testing.T) {
	raw, err := json.Marshal(Summarize(record.Run{ID: "empty"}))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(raw), `"targets":[]`) || !strings.Contains(string(raw), `"top_findings":[]`) {
		t.Fatalf("payload = %s; want empty lists", raw)
	}
}
