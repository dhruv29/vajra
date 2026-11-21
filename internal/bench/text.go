package bench

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"unicode"
)

const (
	tabPadding  = 2
	percentFull = 100
	noFinding   = "-"
)

// Text renders the score as a short plain-text table for a terminal.
func (s Score) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Benchmark: %s\n", printable(s.Key))
	if s.CountsUnreviewed {
		fmt.Fprintln(&b, "Counted as reported: confirmed findings, and findings that passed every check but were not reviewed.")
	}
	fmt.Fprintln(&b)
	w := tabwriter.NewWriter(&b, 0, 0, tabPadding, ' ', 0)
	fmt.Fprintln(w, "RESULT\tEXPECTATION\tFINDING\tSTATUS")
	for _, o := range s.Outcomes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", o.Result, printable(o.Expectation.Name),
			orDash(o.FindingID), orDash(string(o.Status)))
	}
	w.Flush() // a strings.Builder cannot fail
	if len(s.Unexpected) > 0 {
		fmt.Fprintf(&b, "\nUnexpected confirmed findings (%d): %s\n",
			len(s.Unexpected), printable(strings.Join(s.Unexpected, ", ")))
	}
	fmt.Fprintf(&b, "\ntrue positives %d  false positives %d  false negatives %d  true negatives %d\n",
		s.TruePositives, s.FalsePositives, s.FalseNegatives, s.TrueNegatives)
	fmt.Fprintf(&b, "precision %.2f  recall %.2f  noise removed %.0f%%\n",
		s.Precision, s.Recall, s.NoiseRemoved*percentFull)
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return noFinding
	}
	return printable(s)
}

// printable drops control characters, so a name or ID read from a file cannot
// drive the terminal with escape sequences or break the table.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
