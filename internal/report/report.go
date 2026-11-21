// Package report renders a stored run for people: Markdown for tickets and
// pull requests, and a self-contained HTML page that prints cleanly.
//
// Everything a report shows about a finding came from a scanner, a target or
// a model, so every value is escaped for the format it is written into.
package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
)

const (
	maxEvidenceChars = 4000
	minFenceLength   = 3
	truncationNote   = "\n[truncated in this report; the full text is in the run record]"
)

//go:embed report.html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"label":   label,
	"seconds": func(d time.Duration) string { return fmt.Sprintf("%.0fs", d.Seconds()) },
}).Parse(htmlSource))

// item is one finding joined with its blast radius.
type item struct {
	Finding  finding.Finding
	Radius   blast.Radius
	Request  string
	Response string
	Code     string
}

// view is what the templates render.
type view struct {
	Run       record.Run
	Counts    []count
	Attention []item // confirmed and unconfirmed, highest blast radius first
	Dismissed []item // refuted and out of scope
}

type count struct {
	Status finding.Status
	N      int
}

var statusOrder = []finding.Status{finding.Confirmed, finding.Unconfirmed, finding.Refuted, finding.OutOfScope}

func newView(run record.Run) view {
	v := view{Run: run}
	for _, status := range statusOrder {
		v.Counts = append(v.Counts, count{Status: status, N: run.Report.Summary[status]})
	}
	for _, f := range run.Report.Findings {
		radius, _ := run.Radius(f.ID)
		it := item{
			Finding: f, Radius: radius,
			Request: clip(f.Evidence.Request), Response: clip(f.Evidence.Response), Code: clip(f.Evidence.Code),
		}
		if f.Status == finding.Confirmed || f.Status == finding.Unconfirmed {
			v.Attention = append(v.Attention, it)
		} else {
			v.Dismissed = append(v.Dismissed, it)
		}
	}
	sort.SliceStable(v.Attention, func(i, j int) bool { return v.Attention[i].Radius.Score > v.Attention[j].Radius.Score })
	return v
}

func clip(s string) string {
	if len(s) <= maxEvidenceChars {
		return s
	}
	return s[:maxEvidenceChars] + truncationNote
}

// label turns an identifier such as "out_of_scope" into "out of scope".
func label(v any) string {
	return strings.ReplaceAll(fmt.Sprint(v), "_", " ")
}

// HTML renders the run as one self-contained page: no scripts and no
// external resources.
func HTML(run record.Run) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, newView(run)); err != nil {
		return nil, fmt.Errorf("report: render HTML: %w", err)
	}
	return buf.Bytes(), nil
}

// mdEscaper neutralises characters that would otherwise be read as Markdown
// or HTML when untrusted text is placed inline.
var mdEscaper = strings.NewReplacer(
	"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
	"<", "&lt;", ">", "&gt;", "|", "\\|", "#", "\\#", "!", "\\!",
	"\r", " ", "\n", " ",
)

func md(s string) string { return mdEscaper.Replace(s) }

// fenced wraps untrusted text in a code fence longer than any run of
// backticks inside it, so the text cannot close the fence early.
func fenced(s string) string {
	longest, current := 0, 0
	for _, r := range s {
		if r == '`' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	fence := strings.Repeat("`", max(minFenceLength, longest+1))
	return fence + "\n" + strings.TrimRight(s, "\n") + "\n" + fence + "\n"
}

// Markdown renders the run as Markdown.
func Markdown(run record.Run) string {
	v := newView(run)
	r := run.Report
	var b strings.Builder
	fmt.Fprintf(&b, "# Security test report\n\n")
	fmt.Fprintf(&b, "- **Run:** %s\n- **Generated:** %s\n- **Operator:** %s\n- **Authorisation:** %s\n- **Targets:** %s\n",
		md(run.ID), r.GeneratedAt.Format("2006-01-02 15:04 MST"), md(r.Authorization.Operator),
		md(r.Authorization.Statement), md(orNone(strings.Join(r.Targets, ", "))))
	if r.SourceRoot != "" {
		fmt.Fprintf(&b, "- **Source analysed:** %s\n", md(r.SourceRoot))
	}
	b.WriteString("\n")

	b.WriteString("## Summary\n\n| Status | Findings |\n|---|---|\n")
	for _, c := range v.Counts {
		fmt.Fprintf(&b, "| %s | %d |\n", label(c.Status), c.N)
	}
	b.WriteString("\n")

	b.WriteString("## Findings that need attention\n\n")
	if len(v.Attention) == 0 {
		b.WriteString("None.\n\n")
	}
	for i, it := range v.Attention {
		writeFinding(&b, i+1, it)
	}

	b.WriteString("## Dismissed results\n\n")
	if len(v.Dismissed) == 0 {
		b.WriteString("None.\n\n")
	} else {
		b.WriteString("| Result | Target | Status | Why |\n|---|---|---|---|\n")
		for _, it := range v.Dismissed {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", md(it.Finding.Title), md(it.Finding.Target),
				label(it.Finding.Status), md(lastReason(it.Finding)))
		}
		b.WriteString("\n")
	}

	writeAppendix(&b, run)
	return b.String()
}

func writeFinding(b *strings.Builder, n int, it item) {
	f, radius := it.Finding, it.Radius
	fmt.Fprintf(b, "### %d. %s\n\n", n, md(f.Title))
	fmt.Fprintf(b, "- **Status:** %s\n- **Severity:** %s\n- **Blast radius score:** %d / 100\n- **Where:** %s\n- **Rule:** %s (%s)\n\n",
		label(f.Status), f.Severity, radius.Score, md(f.Target), md(f.RuleID), md(f.Source))
	if f.Description != "" {
		fmt.Fprintf(b, "%s\n\n", md(f.Description))
	}

	fmt.Fprintf(b, "**Blast radius.** %s Classified as %s: %s.\n\n", md(radius.Summary), label(radius.Capability), md(radius.CapabilityBasis))
	if len(radius.Reach) > 1 {
		b.WriteString("| Reachable asset | Kind | Confidence | Why |\n|---|---|---|---|\n")
		for _, hop := range radius.Reach {
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n", md(hop.Name), hop.Kind, hop.Confidence, md(hop.Why))
		}
		b.WriteString("\n")
	}

	b.WriteString("**Verification.**\n\n")
	for _, verdict := range f.Verdicts {
		fmt.Fprintf(b, "- %s: **%s**. %s\n", verdict.Stage, verdict.Outcome, md(verdict.Reason))
	}
	b.WriteString("\n")

	if it.Code != "" {
		b.WriteString("**Code.**\n\n" + fenced(it.Code) + "\n")
	}
	if len(f.Evidence.Trace) > 0 {
		b.WriteString("**Path from input to the dangerous call.**\n\n| Step | Where | Code |\n|---|---|---|\n")
		for _, step := range f.Evidence.Trace {
			fmt.Fprintf(b, "| %s | %s:%d | %s |\n", md(step.Role), md(step.File), step.Line, md(step.Content))
		}
		b.WriteString("\n")
	}
	if it.Request != "" {
		b.WriteString("**Request.**\n\n" + fenced(it.Request) + "\n")
	}
	if it.Response != "" {
		b.WriteString("**Response.**\n\n" + fenced(it.Response) + "\n")
	}
}

func lastReason(f finding.Finding) string {
	if len(f.Verdicts) == 0 {
		return ""
	}
	return f.Verdicts[len(f.Verdicts)-1].Reason
}

func writeAppendix(b *strings.Builder, run record.Run) {
	r := run.Report
	b.WriteString("## Appendix\n\n### Scope\n\n")
	fmt.Fprintf(b, "- **Hosts:** %s\n- **CIDRs:** %s\n- **Ports:** %s\n\n",
		md(orNone(strings.Join(r.Scope.Hosts, ", "))), md(orNone(strings.Join(r.Scope.CIDRs, ", "))),
		orNone(strings.Trim(strings.Join(strings.Fields(fmt.Sprint(r.Scope.Ports)), ", "), "[]")))

	u, l := r.Budget.Usage, r.Budget.Limits
	b.WriteString("### Budget\n\n| Resource | Used | Limit |\n|---|---|---|\n")
	fmt.Fprintf(b, "| Model tokens | %d | %d |\n| Model turns | %d | %d |\n| Sandbox runs | %d | %d |\n| Seconds | %d | %d |\n\n",
		u.Tokens, l.Tokens, u.Turns, l.Turns, u.SandboxRuns, l.SandboxRuns, int(u.Elapsed.Seconds()), l.DurationSeconds)

	b.WriteString("### What the run touched\n\n")
	if run.Reach == nil {
		b.WriteString("No gate audit log was supplied for this run.\n")
		return
	}
	fmt.Fprintf(b, "%d connection(s) allowed, %d refused.\n\n", run.Reach.AllowedTotal, run.Reach.DeniedTotal)
	if len(run.Reach.Allowed)+len(run.Reach.Denied) == 0 {
		return
	}
	b.WriteString("| Target | Decision | Count | Reason |\n|---|---|---|---|\n")
	for _, t := range run.Reach.Allowed {
		fmt.Fprintf(b, "| %s | allowed | %d | |\n", md(t.Target), t.Count)
	}
	for _, t := range run.Reach.Denied {
		fmt.Fprintf(b, "| %s | refused | %d | %s |\n", md(t.Target), t.Count, md(t.Reason))
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
