// Package record defines what a run leaves behind: the verified findings, the
// asset graph, each finding's blast radius, and what the run touched.
package record

import (
	"sort"
	"time"

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/topology"
)

// Authorization records who approved the test.
type Authorization struct {
	Operator  string `json:"operator"`
	Statement string `json:"statement"`
}

// BudgetReport shows the caps of a run and what it spent.
type BudgetReport struct {
	Limits budget.Limits `json:"limits"`
	Usage  budget.Usage  `json:"usage"`
}

// Activity records what a run did besides scanning the listed targets.
type Activity struct {
	// DiscoveredHosts are names found under wildcard scope entries.
	DiscoveredHosts []string `json:"discovered_hosts,omitempty"`
	// RejectedHosts resolve, but to addresses outside the scope.
	RejectedHosts []string `json:"rejected_hosts,omitempty"`
	// Endpoints are URLs found by crawling.
	Endpoints      []string `json:"endpoints,omitempty"`
	PagesCrawled   int      `json:"pages_crawled,omitempty"`
	CrawlTruncated bool     `json:"crawl_truncated,omitempty"`
	// SkippedOperations are API operations that could not be tested.
	SkippedOperations []string `json:"skipped_operations,omitempty"`
	// Packages is the dependency inventory, kept so that advisories published
	// later can be matched without scanning again.
	Packages []osv.Package `json:"packages,omitempty"`
	// AgentSteps is the autonomous explorer's timeline.
	AgentSteps   []agent.Step `json:"agent_steps,omitempty"`
	AgentStopped string       `json:"agent_stopped,omitempty"`
	AgentSummary string       `json:"agent_summary,omitempty"`
	// Notes are things the operator should know that are not findings.
	Notes []string `json:"notes,omitempty"`
}

// Report is the verified output of a run.
type Report struct {
	Tool          string        `json:"tool"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Authorization Authorization `json:"authorization"`
	Targets       []string      `json:"targets"`
	// SourceRoot is the analysed source tree, when there was one.
	SourceRoot string                 `json:"source_root,omitempty"`
	Scope      scope.Config           `json:"scope"`
	Budget     BudgetReport           `json:"budget"`
	Refuter    string                 `json:"refuter"`
	Summary    map[finding.Status]int `json:"summary"`
	Findings   []finding.Finding      `json:"findings"`
	Activity   Activity               `json:"activity"`
}

// Run is a report enriched with the asset graph, blast radii and the record
// of what the run was allowed to touch.
type Run struct {
	ID     string         `json:"id"`
	Report Report         `json:"report"`
	Graph  topology.Graph `json:"graph"`
	Radii  []blast.Radius `json:"radii"`
	// Chains are paths that combine several confirmed findings.
	Chains []blast.Chain `json:"chains"`
	// Reach is nil when no gate audit log was supplied.
	Reach *egress.Reach `json:"reach,omitempty"`
}

// Summary is the short form of a run, for listings.
type Summary struct {
	ID          string                 `json:"id"`
	GeneratedAt time.Time              `json:"generated_at"`
	Operator    string                 `json:"operator"`
	Targets     []string               `json:"targets"`
	Counts      map[finding.Status]int `json:"counts"`
	TopScore    int                    `json:"top_score"`
}

// Build assembles a Run from a report. The graph is derived from every URL
// the run touched plus the operator's declaration.
func Build(id string, report Report, decl topology.Declaration, events []egress.Event) (Run, error) {
	b := topology.NewBuilder()
	for _, target := range report.Targets {
		b.AddURL(target)
	}
	for _, f := range report.Findings {
		b.AddURL(f.Target)
		b.AddURL(f.AssetURL)
	}
	for _, endpoint := range report.Activity.Endpoints {
		b.AddURL(endpoint)
	}
	for _, host := range report.Activity.DiscoveredHosts {
		b.AddURL("https://" + host)
	}
	if err := b.AddDeclaration(decl); err != nil {
		return Run{}, err
	}
	graph := b.Graph()
	radii := make([]blast.Radius, 0, len(report.Findings))
	for _, f := range report.Findings {
		radii = append(radii, blast.Compute(graph, f))
	}
	chains := blast.Chains(graph, report.Findings, radii)
	sort.SliceStable(radii, func(i, j int) bool { return radii[i].Score > radii[j].Score })
	run := Run{ID: id, Report: report, Graph: graph, Radii: radii, Chains: chains}
	if events != nil {
		reach := egress.Summarize(events)
		run.Reach = &reach
	}
	return run, nil
}

// Radius returns the blast radius of one finding.
func (r Run) Radius(findingID string) (blast.Radius, bool) {
	for _, radius := range r.Radii {
		if radius.FindingID == findingID {
			return radius, true
		}
	}
	return blast.Radius{}, false
}

// Summarize returns the short form of the run.
func (r Run) Summarize() Summary {
	top := 0
	for _, radius := range r.Radii {
		if radius.Score > top {
			top = radius.Score
		}
	}
	return Summary{
		ID: r.ID, GeneratedAt: r.Report.GeneratedAt, Operator: r.Report.Authorization.Operator,
		Targets: r.Report.Targets, Counts: r.Report.Summary, TopScore: top,
	}
}
