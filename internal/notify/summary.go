// Package notify posts a short summary of a run to a webhook the operator
// configured, such as a chat tool or a ticketing bridge.
package notify

import (
	"sort"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
)

const (
	// maxTopFindings keeps a notification short enough to read in a chat.
	maxTopFindings = 5
	// maxLabelChars bounds text that originates from a scanner or a target.
	maxLabelChars = 200
)

// Summary is what a notification carries. It deliberately has no evidence,
// request or response text: a webhook leads to a third-party system, and
// captured material may hold secrets of the system under test.
type Summary struct {
	RunID       string   `json:"run_id"`
	Targets     []string `json:"targets"`
	Confirmed   int      `json:"confirmed"`
	Unconfirmed int      `json:"unconfirmed"`
	Refuted     int      `json:"refuted"`
	OutOfScope  int      `json:"out_of_scope"`
	// TopFindings holds at most 5 entries, highest score first.
	TopFindings []TopFinding `json:"top_findings"`
}

// TopFinding is one confirmed finding in a notification.
type TopFinding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Score is the finding's blast-radius score.
	Score  int    `json:"score"`
	Target string `json:"target"`
}

// Summarize builds a Summary from a run: top findings are confirmed ones by
// blast-radius score, descending. Titles and targets are clipped to 200
// chars. Findings are counted from the list itself, not from the report's
// own tally, so the numbers always describe the findings that were ranked.
func Summarize(run record.Run) Summary {
	summary := Summary{
		RunID:       run.ID,
		Targets:     clipAll(run.Report.Targets),
		TopFindings: []TopFinding{},
	}
	for _, f := range run.Report.Findings {
		switch f.Status {
		case finding.Confirmed:
			summary.Confirmed++
			summary.TopFindings = append(summary.TopFindings, topFinding(run, f))
		case finding.Unconfirmed:
			summary.Unconfirmed++
		case finding.Refuted:
			summary.Refuted++
		case finding.OutOfScope:
			summary.OutOfScope++
		}
	}
	// Stable, so findings with equal scores keep the report's order.
	sort.SliceStable(summary.TopFindings, func(i, j int) bool {
		return summary.TopFindings[i].Score > summary.TopFindings[j].Score
	})
	if len(summary.TopFindings) > maxTopFindings {
		summary.TopFindings = summary.TopFindings[:maxTopFindings]
	}
	return summary
}

// topFinding scores a finding with no computed radius as zero.
func topFinding(run record.Run, f finding.Finding) TopFinding {
	radius, _ := run.Radius(f.ID)
	return TopFinding{
		Title:    clip(f.Title),
		Severity: string(f.Severity),
		Score:    radius.Score,
		Target:   clip(f.Target),
	}
}

// clipAll always returns a non-nil slice, so the JSON field is a list and
// never null.
func clipAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, clip(v))
	}
	return out
}

// clip cuts on a character boundary, so the result is still valid text.
func clip(s string) string {
	runes := []rune(s)
	if len(runes) <= maxLabelChars {
		return s
	}
	return string(runes[:maxLabelChars])
}
