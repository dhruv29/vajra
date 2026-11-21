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
	"github.com/dhruv29/vajra/internal/verify"
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
	// Unexpected holds the IDs of confirmed findings that no expectation
	// accounts for: those matching none, and surplus duplicates of a real issue
	// that another confirmed finding already counted for. A confirmed finding
	// matching a decoy is that decoy's false positive instead. They count
	// against precision: the key is the whole truth.
	Unexpected []string `json:"unexpected"`
	// Precision is TP / (TP + FP + len(Unexpected)), 1 when nothing was reported.
	Precision float64 `json:"precision"`
	// Recall is TP / (TP + FN), 1 when the key has no real issues.
	Recall float64 `json:"recall"`
	// NoiseRemoved is the share of the scanner's raw results that
	// verification kept out of what counts as reported.
	NoiseRemoved float64 `json:"noise_removed"`
	// CountsUnreviewed is true when findings that passed every check except
	// a review that never took place were counted as reported (see Options).
	CountsUnreviewed bool `json:"counts_unreviewed,omitempty"`
}

// Options changes what counts as reported.
type Options struct {
	// CountUnreviewed also counts as reported a finding that is unconfirmed
	// only because no reviewer looked at it: every verification stage passed
	// except the review, which was inconclusive. It measures the checks and
	// their reproduction on a run without a model. A finding that failed or
	// could not finish any other stage still does not count.
	CountUnreviewed bool
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
// count as reported. Each confirmed finding is the true positive of at most one
// real issue: expectations take, in key order, the first confirmed match no
// earlier expectation took.
func Evaluate(key Key, findings []finding.Finding) Score {
	return EvaluateWith(key, findings, Options{})
}

// EvaluateWith is Evaluate with options; with the zero Options it is
// Evaluate.
func EvaluateWith(key Key, findings []finding.Finding, opts Options) Score {
	score := Score{Key: key.Name, Outcomes: make([]Outcome, 0, len(key.Expectations)), CountsUnreviewed: opts.CountUnreviewed}
	isReported := func(f finding.Finding) bool { return reported(f, opts) }
	consumed := make([]bool, len(findings))
	for _, e := range key.Expectations {
		o := judge(e, findings, consumed, isReported)
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
	score.Unexpected = unexpected(key, findings, consumed, isReported)
	reported := score.TruePositives + score.FalsePositives + len(score.Unexpected)
	score.Precision = ratio(score.TruePositives, reported, perfect)
	score.Recall = ratio(score.TruePositives, score.TruePositives+score.FalseNegatives, perfect)
	score.NoiseRemoved = ratio(len(findings)-reportedCount(findings, isReported), len(findings), 0)
	return score
}

// Passed reports whether the score meets both thresholds.
func (s Score) Passed(minPrecision, minRecall float64) bool {
	return s.Precision >= minPrecision && s.Recall >= minRecall
}

// reported says whether a finding counts as reported under opts.
func reported(f finding.Finding, opts Options) bool {
	if f.Status == finding.Confirmed {
		return true
	}
	return opts.CountUnreviewed && f.Status == finding.Unconfirmed && onlyReviewMissing(f.Verdicts)
}

// reviewStage is the name of the verification stage a model reviewer runs.
var reviewStage = verify.RefuteStage{}.Name()

// onlyReviewMissing reports whether the review stage ran and was
// inconclusive while every other stage passed.
func onlyReviewMissing(verdicts []finding.Verdict) bool {
	reviewed := false
	for _, v := range verdicts {
		switch {
		case v.Stage == reviewStage && v.Outcome == finding.Inconclusive:
			reviewed = true
		case v.Outcome != finding.Pass:
			return false
		}
	}
	return reviewed
}

// judge decides one expectation. A real issue consumes the reported finding
// that counts for it and ignores findings already consumed; a decoy consumes
// nothing.
func judge(e Expectation, findings []finding.Finding, consumed []bool, isReported func(finding.Finding) bool) Outcome {
	candidates := findings
	if e.Present {
		candidates = make([]finding.Finding, 0, len(findings))
		for i, f := range findings {
			if consumed[i] || !matches(e, f) {
				continue
			}
			if isReported(f) {
				consumed[i] = true
				return Outcome{Expectation: e, Result: TruePositive, FindingID: f.ID, Status: f.Status}
			}
			candidates = append(candidates, f)
		}
	}
	best, found := bestMatch(e, candidates, isReported)
	o := Outcome{Expectation: e, Result: result(e.Present, found && isReported(best))}
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
// verification, a reported one first; the first one wins a tie.
func bestMatch(e Expectation, findings []finding.Finding, isReported func(finding.Finding) bool) (finding.Finding, bool) {
	var best finding.Finding
	found := false
	rank := func(f finding.Finding) int {
		if isReported(f) {
			return closeness(finding.Confirmed)
		}
		return closeness(f.Status)
	}
	for _, f := range findings {
		if !matches(e, f) {
			continue
		}
		if !found || rank(f) > rank(best) {
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

// unexpected lists, sorted, the reported findings no expectation accounts
// for: not consumed by a real issue and not matching a decoy.
func unexpected(key Key, findings []finding.Finding, consumed []bool, isReported func(finding.Finding) bool) []string {
	ids := []string{}
	for i, f := range findings {
		if isReported(f) && !consumed[i] && !matchesDecoy(key, f) {
			ids = append(ids, f.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func matchesDecoy(key Key, f finding.Finding) bool {
	for _, e := range key.Expectations {
		if !e.Present && matches(e, f) {
			return true
		}
	}
	return false
}

func reportedCount(findings []finding.Finding, isReported func(finding.Finding) bool) int {
	n := 0
	for _, f := range findings {
		if isReported(f) {
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
