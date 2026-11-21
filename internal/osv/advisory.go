package osv

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

const gitRangeType = "GIT"

var (
	cwePattern          = regexp.MustCompile(`^cwe-[0-9]+$`)
	pythonSeparatorRuns = regexp.MustCompile(`[-_.]+`)
)

// vulnDetail is the subset of an OSV record that Vajra uses.
type vulnDetail struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Aliases []string `json:"aliases"`
	// DatabaseSpecific has no fixed schema: each source database fills it as
	// it likes. It is decoded field by field, so an unexpected shape costs
	// only that field and not the advisory.
	DatabaseSpecific json.RawMessage `json:"database_specific"`
	Affected         []struct {
		Package queryPackage `json:"package"`
		Ranges  []struct {
			Type   string `json:"type"`
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// advisoryFor describes the record as it applies to pkg. One record can cover
// several packages with different fixes, so the fixed versions are read only
// from the entries for this package.
func (d vulnDetail) advisoryFor(id string, pkg Package) Advisory {
	fields := d.databaseFields()
	return Advisory{
		ID:       id,
		Aliases:  d.Aliases,
		Summary:  d.Summary,
		Severity: severityOf(fields["severity"]),
		FixedIn:  d.fixedIn(pkg),
		CWE:      cweList(fields["cwe_ids"]),
	}
}

func (d vulnDetail) databaseFields() map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(d.DatabaseSpecific, &fields) != nil {
		return nil
	}
	return fields
}

// severityOf maps the label a source database assigned. Records that carry
// only a CVSS vector are rated unknown: deriving a score from a vector takes
// a full CVSS implementation, and a guess would be worse than no rating.
func severityOf(raw json.RawMessage) finding.Severity {
	var label string
	if json.Unmarshal(raw, &label) != nil {
		return finding.SeverityUnknown
	}
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "LOW":
		return finding.SeverityLow
	case "MODERATE", "MEDIUM":
		return finding.SeverityMedium
	case "HIGH":
		return finding.SeverityHigh
	case "CRITICAL":
		return finding.SeverityCritical
	}
	return finding.SeverityUnknown
}

func cweList(raw json.RawMessage) []string {
	var ids []string
	if json.Unmarshal(raw, &ids) != nil {
		return nil
	}
	var out []string
	for _, id := range ids {
		id = strings.ToLower(strings.TrimSpace(id))
		if cwePattern.MatchString(id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// fixedIn lists the versions that fix the advisory for pkg, in the order the
// record gives them. Ranges over git commits are left out: a commit hash is
// not a version a lockfile can pin.
func (d vulnDetail) fixedIn(pkg Package) []string {
	var out []string
	for _, affected := range d.Affected {
		if !samePackage(affected.Package, pkg) {
			continue
		}
		for _, r := range affected.Ranges {
			if strings.EqualFold(r.Type, gitRangeType) {
				continue
			}
			for _, event := range r.Events {
				if event.Fixed != "" && !slices.Contains(out, event.Fixed) {
					out = append(out, event.Fixed)
				}
			}
		}
	}
	return out
}

func samePackage(listed queryPackage, pkg Package) bool {
	if listed.Ecosystem != pkg.Ecosystem {
		return false
	}
	if pkg.Ecosystem == ecosystemPyPI {
		return pythonName(listed.Name) == pythonName(pkg.Name)
	}
	return listed.Name == pkg.Name
}

// pythonName applies the Python packaging rule under which "Flask_Cors",
// "flask.cors" and "flask-cors" are one project.
func pythonName(name string) string {
	return pythonSeparatorRuns.ReplaceAllString(strings.ToLower(name), "-")
}
