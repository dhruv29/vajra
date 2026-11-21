package report

import (
	"fmt"
	"strings"

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/record"
)

// capped is a list cut to maxListRows, with a count of what was left out.
type capped[T any] struct {
	Rows []T
	More int
}

func capList[T any](all []T) capped[T] {
	if len(all) <= maxListRows {
		return capped[T]{Rows: all}
	}
	return capped[T]{Rows: all[:maxListRows], More: len(all) - maxListRows}
}

// activity is what a run did besides scanning the listed targets, prepared
// for both report formats. Every string in it is untrusted.
type activity struct {
	// Present is false when there is nothing to show, so the whole part is
	// left out of the report.
	Present    bool
	Discovered capped[string]
	Rejected   capped[string]
	// Crawled is set when the crawler ran.
	Crawled   bool
	Pages     int
	Endpoints int
	Truncated bool
	Skipped   capped[string]
	Packages  int
	// Explored is set when the autonomous explorer ran.
	Explored bool
	Steps    capped[agent.Step]
	Stopped  string
	Summary  string
	Notes    capped[string]
}

func newActivity(a record.Activity) activity {
	v := activity{
		Discovered: capList(a.DiscoveredHosts),
		Rejected:   capList(a.RejectedHosts),
		Crawled:    a.PagesCrawled > 0 || len(a.Endpoints) > 0 || a.CrawlTruncated,
		Pages:      a.PagesCrawled,
		Endpoints:  len(a.Endpoints),
		Truncated:  a.CrawlTruncated,
		Skipped:    capList(a.SkippedOperations),
		Packages:   len(a.Packages),
		Explored:   len(a.AgentSteps) > 0 || a.AgentStopped != "" || a.AgentSummary != "",
		Steps:      capList(a.AgentSteps),
		Stopped:    a.AgentStopped,
		Summary:    a.AgentSummary,
		Notes:      capList(a.Notes),
	}
	v.Present = v.Crawled || v.Explored || v.Packages > 0 ||
		len(a.DiscoveredHosts)+len(a.RejectedHosts)+len(a.SkippedOperations)+len(a.Notes) > 0
	return v
}

func writeActivity(b *strings.Builder, a activity) {
	if !a.Present {
		return
	}
	b.WriteString("### What else the run did\n\n")
	writeList(b, "Hosts discovered", a.Discovered)
	writeList(b, "Hosts rejected because they resolve outside the scope", a.Rejected)
	if a.Crawled {
		fmt.Fprintf(b, "**Crawl.** %d page(s) crawled, %d endpoint(s) found.", a.Pages, a.Endpoints)
		if a.Truncated {
			b.WriteString(" Crawling stopped at its limit, so some pages were not visited.")
		}
		b.WriteString("\n\n")
	}
	writeList(b, "API operations skipped", a.Skipped)
	if a.Packages > 0 {
		fmt.Fprintf(b, "**Dependencies.** %d package(s) inventoried.\n\n", a.Packages)
	}
	writeExplorer(b, a)
	writeList(b, "Notes", a.Notes)
}

// writeList writes a titled bullet list, or nothing when the list is empty.
func writeList(b *strings.Builder, title string, list capped[string]) {
	if len(list.Rows) == 0 {
		return
	}
	fmt.Fprintf(b, "**%s (%d).**\n\n", title, len(list.Rows)+list.More)
	for _, row := range list.Rows {
		fmt.Fprintf(b, "- %s\n", mdParagraph(row))
	}
	if list.More > 0 {
		fmt.Fprintf(b, "- and %d more\n", list.More)
	}
	b.WriteString("\n")
}

func writeExplorer(b *strings.Builder, a activity) {
	if !a.Explored {
		return
	}
	b.WriteString("**Autonomous explorer.**\n\n")
	if len(a.Steps.Rows) > 0 {
		b.WriteString("| Step | Tool | What | Outcome |\n|---|---|---|---|\n")
		for _, step := range a.Steps.Rows {
			fmt.Fprintf(b, "| %d | %s | %s | %s |\n", step.N, md(label(step.Tool)), md(step.Summary), md(step.Outcome))
		}
		b.WriteString("\n")
		if a.Steps.More > 0 {
			fmt.Fprintf(b, "and %d more step(s)\n\n", a.Steps.More)
		}
	}
	if a.Stopped != "" {
		fmt.Fprintf(b, "Why it stopped: %s\n\n", md(a.Stopped))
	}
	if a.Summary != "" {
		fmt.Fprintf(b, "Its summary: %s\n\n", md(a.Summary))
	}
}
