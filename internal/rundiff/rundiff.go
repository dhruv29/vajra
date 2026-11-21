// Package rundiff compares two runs, so continuous testing can report only
// what changed since the last one.
package rundiff

import (
	"sort"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
)

// Change is one finding's movement between two runs.
type Change struct {
	// Finding is the head version, or the base version for a resolved one.
	Finding finding.Finding `json:"finding"`
	// Before and After are empty when the finding is absent from that run.
	Before finding.Status `json:"before,omitempty"`
	After  finding.Status `json:"after,omitempty"`
	// Score is the blast-radius score in the head run, or the base run for a
	// resolved finding.
	Score int `json:"score"`
}

// Diff is what changed between a base run and a head run. A finding needs
// attention while it is confirmed or unconfirmed.
type Diff struct {
	Base string `json:"base"`
	Head string `json:"head"`
	// New needs attention in head and was absent or dismissed in base.
	New []Change `json:"new"`
	// Resolved needed attention in base and is absent or dismissed in head.
	Resolved []Change `json:"resolved"`
	// Persisting needs attention in both runs.
	Persisting []Change `json:"persisting"`
	// StatusChanged is the part of Persisting whose status differs, e.g.
	// unconfirmed in base and confirmed in head.
	StatusChanged []Change `json:"status_changed"`
}

// Compare matches the findings of two runs by ID, which is stable across
// runs, and sorts each list by score, highest first.
func Compare(base, head record.Run) Diff {
	d := Diff{
		Base: base.ID, Head: head.ID,
		New: []Change{}, Resolved: []Change{}, Persisting: []Change{}, StatusChanged: []Change{},
	}
	before, after := index(base), index(head)
	for _, f := range unique(head) {
		if !needsAttention(f.Status) {
			continue
		}
		prior, known := before[f.ID]
		change := Change{Finding: f, Before: prior.Status, After: f.Status, Score: score(head, f.ID)}
		if !known || !needsAttention(prior.Status) {
			d.New = append(d.New, change)
			continue
		}
		d.Persisting = append(d.Persisting, change)
		if prior.Status != f.Status {
			d.StatusChanged = append(d.StatusChanged, change)
		}
	}
	for _, f := range unique(base) {
		if now := after[f.ID]; needsAttention(f.Status) && !needsAttention(now.Status) {
			d.Resolved = append(d.Resolved, Change{Finding: f, Before: f.Status, After: now.Status, Score: score(base, f.ID)})
		}
	}
	for _, list := range [][]Change{d.New, d.Resolved, d.Persisting, d.StatusChanged} {
		rank(list)
	}
	return d
}

// HasNew reports whether head has anything base did not, or a finding that
// became confirmed, which is what should fail a continuous-testing gate.
func (d Diff) HasNew() bool {
	return len(d.New) > 0 || len(d.Escalated()) > 0
}

// Escalated returns the status changes to confirmed from anything else, in
// the order of StatusChanged.
func (d Diff) Escalated() []Change {
	out := []Change{}
	for _, c := range d.StatusChanged {
		if c.After == finding.Confirmed && c.Before != finding.Confirmed {
			out = append(out, c)
		}
	}
	return out
}

func needsAttention(s finding.Status) bool {
	return s == finding.Confirmed || s == finding.Unconfirmed
}

// unique returns a run's findings without repeats of an ID, keeping the
// first, so a malformed run cannot list one change twice.
func unique(run record.Run) []finding.Finding {
	seen := make(map[string]bool, len(run.Report.Findings))
	out := make([]finding.Finding, 0, len(run.Report.Findings))
	for _, f := range run.Report.Findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f)
		}
	}
	return out
}

func index(run record.Run) map[string]finding.Finding {
	byID := make(map[string]finding.Finding, len(run.Report.Findings))
	for _, f := range unique(run) {
		byID[f.ID] = f
	}
	return byID
}

// score is zero for a finding the run computed no blast radius for.
func score(run record.Run, id string) int {
	radius, _ := run.Radius(id)
	return radius.Score
}

func rank(changes []Change) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Score != changes[j].Score {
			return changes[i].Score > changes[j].Score
		}
		return changes[i].Finding.ID < changes[j].Finding.ID
	})
}
