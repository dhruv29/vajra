// Package bench measures how accurate a run was against an answer key: a list
// of issues a benchmark target is known to have, and decoys it is known not to
// have.
package bench

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

// The four ways an expectation can fare.
const (
	TruePositive  = "true_positive"
	FalseNegative = "false_negative"
	TrueNegative  = "true_negative"
	FalsePositive = "false_positive"
)

const (
	// maxKeyBytes bounds how much of a key file is read; a key is a short,
	// hand-written list.
	maxKeyBytes = 1 << 20
	// perfect is what a ratio is when nothing could have gone wrong: no
	// reports means no wrong reports, no real issues means none missed.
	perfect = 1.0
)

// Expectation is one issue a benchmark target is known to have, or known not
// to have. A finding matches when every filter that is set matches.
type Expectation struct {
	// Name is a human label, unique within the key.
	Name string `json:"name"`
	// Present is true for a real vulnerability and false for a decoy that
	// must not be confirmed.
	Present bool         `json:"present"`
	Kind    finding.Kind `json:"kind,omitempty"`
	// CWE is compared case-insensitively, e.g. "cwe-89".
	CWE string `json:"cwe,omitempty"`
	// RuleContains is a substring of Finding.RuleID.
	RuleContains string `json:"rule_contains,omitempty"`
	// TargetContains is a substring of Finding.Target.
	TargetContains string `json:"target_contains,omitempty"`
}

// Key is an answer key file.
type Key struct {
	Name         string        `json:"name"`
	Expectations []Expectation `json:"expectations"`
}

// Outcome says how one expectation fared.
type Outcome struct {
	Expectation Expectation `json:"expectation"`
	// Result is TruePositive, FalseNegative, TrueNegative or FalsePositive.
	Result string `json:"result"`
	// FindingID and Status describe the matched finding, if any. On a false
	// negative they show the issue was found but not confirmed.
	FindingID string         `json:"finding_id,omitempty"`
	Status    finding.Status `json:"status,omitempty"`
}

// Score is the result of comparing a run with a key.
type Score struct {
	Key            string    `json:"key"`
	Outcomes       []Outcome `json:"outcomes"`
	TruePositives  int       `json:"true_positives"`
	FalsePositives int       `json:"false_positives"`
	FalseNegatives int       `json:"false_negatives"`
	TrueNegatives  int       `json:"true_negatives"`
	// Unexpected holds the IDs of confirmed findings that match no
	// expectation. They count against precision: the key is the whole truth.
	Unexpected []string `json:"unexpected"`
	// Precision is TP / (TP + FP + len(Unexpected)), 1 when nothing was reported.
	Precision float64 `json:"precision"`
	// Recall is TP / (TP + FN), 1 when the key has no real issues.
	Recall float64 `json:"recall"`
	// NoiseRemoved is the share of the scanner's raw results that
	// verification kept out of "confirmed".
	NoiseRemoved float64 `json:"noise_removed"`
}

// ParseKey reads and validates an answer key. Unknown fields are rejected so
// that a misspelt filter cannot silently widen what an expectation matches.
func ParseKey(r io.Reader) (Key, error) {
	dec := json.NewDecoder(io.LimitReader(r, maxKeyBytes))
	dec.DisallowUnknownFields()
	var key Key
	if err := dec.Decode(&key); err != nil {
		return Key{}, fmt.Errorf("bench: parse key: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Key{}, errors.New("bench: parse key: unexpected data after the key")
	}
	if err := validate(key); err != nil {
		return Key{}, err
	}
	return key, nil
}

func validate(key Key) error {
	// An empty key would score a perfect 1.0 whatever the run did.
	if len(key.Expectations) == 0 {
		return errors.New("bench: key has no expectations")
	}
	seen := make(map[string]bool, len(key.Expectations))
	for i, e := range key.Expectations {
		if strings.TrimSpace(e.Name) == "" {
			return fmt.Errorf("bench: expectation %d has no name", i)
		}
		if seen[e.Name] {
			return fmt.Errorf("bench: expectation name %q is used twice", e.Name)
		}
		seen[e.Name] = true
		if err := validateFilters(e); err != nil {
			return err
		}
	}
	return nil
}

func validateFilters(e Expectation) error {
	// Kind alone would match every finding of that kind, which is never what
	// an answer key means.
	if e.CWE == "" && e.RuleContains == "" && e.TargetContains == "" {
		return fmt.Errorf("bench: expectation %q needs cwe, rule_contains or target_contains", e.Name)
	}
	switch e.Kind {
	case "", finding.Dynamic, finding.Static, finding.Dependency:
		return nil
	default:
		// An unknown kind matches nothing, so a decoy would always pass.
		return fmt.Errorf("bench: expectation %q has unknown kind %q", e.Name, e.Kind)
	}
}

// Evaluate compares the findings of a run with a key. Only confirmed findings
// count as reported.
func Evaluate(key Key, findings []finding.Finding) Score {
	score := Score{Key: key.Name, Outcomes: make([]Outcome, 0, len(key.Expectations))}
	for _, e := range key.Expectations {
		o := judge(e, findings)
		score.Outcomes = append(score.Outcomes, o)
		switch o.Result {
		case TruePositive:
			score.TruePositives++
		case FalsePositive:
			score.FalsePositives++
		case FalseNegative:
			score.FalseNegatives++
		default:
			score.TrueNegatives++
		}
	}
	score.Unexpected = unexpected(key, findings)
	reported := score.TruePositives + score.FalsePositives + len(score.Unexpected)
	score.Precision = ratio(score.TruePositives, reported, perfect)
	score.Recall = ratio(score.TruePositives, score.TruePositives+score.FalseNegatives, perfect)
	score.NoiseRemoved = ratio(len(findings)-confirmedCount(findings), len(findings), 0)
	return score
}

// Passed reports whether the score meets both thresholds.
func (s Score) Passed(minPrecision, minRecall float64) bool {
	return s.Precision >= minPrecision && s.Recall >= minRecall
}

func judge(e Expectation, findings []finding.Finding) Outcome {
	best, found := bestMatch(e, findings)
	reported := found && best.Status == finding.Confirmed
	o := Outcome{Expectation: e, Result: result(e.Present, reported)}
	if found {
		o.FindingID, o.Status = best.ID, best.Status
	}
	return o
}

func result(present, reported bool) string {
	switch {
	case present && reported:
		return TruePositive
	case present:
		return FalseNegative
	case reported:
		return FalsePositive
	default:
		return TrueNegative
	}
}

// bestMatch returns the matching finding that got furthest through
// verification; the first one wins a tie.
func bestMatch(e Expectation, findings []finding.Finding) (finding.Finding, bool) {
	var best finding.Finding
	found := false
	for _, f := range findings {
		if !matches(e, f) {
			continue
		}
		if !found || closeness(f.Status) > closeness(best.Status) {
			best, found = f, true
		}
	}
	return best, found
}

// closeness orders statuses by how near they are to "confirmed".
func closeness(s finding.Status) int {
	switch s {
	case finding.Confirmed:
		return 4
	case finding.Unconfirmed:
		return 3
	case finding.Candidate:
		return 2
	case finding.Refuted:
		return 1
	default:
		return 0
	}
}

func matches(e Expectation, f finding.Finding) bool {
	return (e.Kind == "" || e.Kind == f.Kind) &&
		(e.CWE == "" || hasCWE(f.CWE, e.CWE)) &&
		strings.Contains(f.RuleID, e.RuleContains) &&
		strings.Contains(f.Target, e.TargetContains)
}

func hasCWE(have []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, cwe := range have {
		if strings.EqualFold(strings.TrimSpace(cwe), want) {
			return true
		}
	}
	return false
}

// unexpected lists, sorted, the confirmed findings no expectation accounts for.
func unexpected(key Key, findings []finding.Finding) []string {
	ids := []string{}
	for _, f := range findings {
		if f.Status == finding.Confirmed && !matchesAny(key, f) {
			ids = append(ids, f.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func matchesAny(key Key, f finding.Finding) bool {
	for _, e := range key.Expectations {
		if matches(e, f) {
			return true
		}
	}
	return false
}

func confirmedCount(findings []finding.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Status == finding.Confirmed {
			n++
		}
	}
	return n
}

func ratio(part, whole int, whenEmpty float64) float64 {
	if whole == 0 {
		return whenEmpty
	}
	return float64(part) / float64(whole)
}
