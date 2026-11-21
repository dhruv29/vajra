// Package osv finds the third-party packages a source tree pins and looks up
// the known vulnerabilities for them in the OSV database.
package osv

import (
	"fmt"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// Source is the value of Finding.Source for results from this package.
	Source = "osv"

	dependencyTag   = "dependency"
	maxSummaryChars = 160
	maxLineChars    = 300
)

// Package is one pinned dependency.
type Package struct {
	Ecosystem string `json:"ecosystem"` // OSV ecosystem name: "Go", "npm", "PyPI", "crates.io", "RubyGems"
	Name      string `json:"name"`
	Version   string `json:"version"`
	File      string `json:"file"` // lockfile path relative to root
	Line      int    `json:"line"` // 1-based line where the package is pinned, 0 if unknown

	// code is the lockfile text that pins the package, numbered. Inventory
	// captures it while it holds the file, so that Findings can show the
	// evidence without reading the source tree a second time. It is not
	// serialised: a package that has been through JSON yields no code.
	code string
}

// Advisory is one known vulnerability affecting a package version.
type Advisory struct {
	ID       string           `json:"id"`
	Aliases  []string         `json:"aliases,omitempty"` // e.g. CVE ids
	Summary  string           `json:"summary"`
	Severity finding.Severity `json:"severity"`
	FixedIn  []string         `json:"fixed_in,omitempty"`
	CWE      []string         `json:"cwe,omitempty"` // lower-case "cwe-79" form
}

// Findings turns packages and their advisories into candidate findings, one
// per package and advisory. advisories is indexed like pkgs, as Query returns
// it; entries beyond the shorter of the two are ignored.
func Findings(pkgs []Package, advisories [][]Advisory) []finding.Finding {
	var out []finding.Finding
	for i := 0; i < len(pkgs) && i < len(advisories); i++ {
		for _, adv := range advisories[i] {
			out = append(out, toFinding(pkgs[i], adv))
		}
	}
	return out
}

func toFinding(pkg Package, adv Advisory) finding.Finding {
	coordinate := pkg.Ecosystem + "/" + pkg.Name + "@" + pkg.Version
	f := finding.Finding{
		ID:          finding.StableID(Source, adv.ID, coordinate, ""),
		Kind:        finding.Dependency,
		Source:      Source,
		RuleID:      adv.ID,
		Title:       title(pkg, adv),
		Description: fixDescription(adv.FixedIn),
		Severity:    adv.Severity,
		Target:      pkg.File,
		Tags:        []string{dependencyTag, strings.ToLower(pkg.Ecosystem)},
		CWE:         adv.CWE,
		Status:      finding.Candidate,
		Evidence:    finding.Evidence{Extracted: []string{coordinate}},
	}
	if pkg.Line > 0 {
		f.Target = fmt.Sprintf("%s:%d", pkg.File, pkg.Line)
		f.Location = &finding.Location{File: pkg.File, Line: pkg.Line}
		f.Evidence.Code = pkg.code
	}
	return f
}

// title names the package and the problem on one line. The summary comes from
// the advisory database, so it is flattened and clipped before it is shown.
func title(pkg Package, adv Advisory) string {
	summary := strings.Join(strings.Fields(adv.Summary), " ")
	if summary == "" {
		summary = adv.ID
	}
	if runes := []rune(summary); len(runes) > maxSummaryChars {
		summary = string(runes[:maxSummaryChars])
	}
	return pkg.Name + " " + pkg.Version + ": " + summary
}

func fixDescription(fixedIn []string) string {
	if len(fixedIn) == 0 {
		return "No fixed version is published."
	}
	return "Fixed in " + strings.Join(fixedIn, ", ") + "."
}

// numbered renders the given 1-based lines in the format used for source
// evidence elsewhere in Vajra, each marked as reported. Numbers outside the
// file are left out.
func numbered(lines []string, numbers ...int) string {
	var b strings.Builder
	for _, n := range numbers {
		if n < 1 || n > len(lines) {
			continue
		}
		text := lines[n-1]
		if len(text) > maxLineChars {
			text = text[:maxLineChars] + " [line truncated]"
		}
		fmt.Fprintf(&b, "> %5d | %s\n", n, text)
	}
	return b.String()
}
