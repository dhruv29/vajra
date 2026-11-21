// Package finding is the data model for a reported issue and the record of how
// it was verified.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"time"
)

// Status is where a finding stands after verification.
type Status string

const (
	// Candidate is a raw scanner result that has not been verified.
	Candidate Status = "candidate"
	// Confirmed was reproduced and survived refutation.
	Confirmed Status = "confirmed"
	// Refuted failed reproduction or was disproved.
	Refuted Status = "refuted"
	// Unconfirmed could not be proven either way; a person should look.
	Unconfirmed Status = "unconfirmed"
	// OutOfScope names a target the scope policy does not allow.
	OutOfScope Status = "out_of_scope"
)

// Severity is the scanner's rating, normalised.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

// ParseSeverity normalises a scanner's severity label.
func ParseSeverity(raw string) Severity {
	switch s := Severity(strings.ToLower(strings.TrimSpace(raw))); s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return s
	default:
		return SeverityUnknown
	}
}

// Rank orders severities from least (0) to most serious.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Kind says how a finding was found.
type Kind string

const (
	// Dynamic findings come from testing a running application.
	Dynamic Kind = "dast"
	// Static findings come from analysing source code.
	Static Kind = "sast"
	// Dependency findings are known vulnerabilities in third-party packages
	// the project depends on.
	Dependency Kind = "sca"
	// Network findings are facts about what is listening on a host.
	Network Kind = "net"
)

// Location is a place in source code, relative to the scanned source root.
type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line,omitempty"`
}

// SafeRelPath reports whether p is a clean relative path that stays inside
// the source root it is relative to.
func SafeRelPath(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != ".." &&
		!strings.HasPrefix(p, "../") && !strings.ContainsRune(p, 0)
}

// TraceStep is one step on the path from untrusted input to a dangerous call.
type TraceStep struct {
	Role    string `json:"role"` // source, propagation or sink
	File    string `json:"file"`
	Line    int    `json:"line"`
	Content string `json:"content"`
}

// Evidence is what proves a finding. Everything here came from the target or
// a tool and is untrusted data.
type Evidence struct {
	Request   string `json:"request,omitempty"`
	Response  string `json:"response,omitempty"`
	MatchedAt string `json:"matched_at,omitempty"`
	// ScanInput is the URL the scanner was given when it produced this result.
	// Reproduction starts from it, because a rule builds its own request path.
	ScanInput string   `json:"scan_input,omitempty"`
	Matcher   string   `json:"matcher,omitempty"`
	Extracted []string `json:"extracted,omitempty"`
	// Code is the source around a static finding, with line numbers. Vajra
	// reads it from the source tree itself rather than trusting the scanner.
	Code string `json:"code,omitempty"`
	// Trace is the scanner's source-to-sink path, when it reports one.
	Trace []TraceStep `json:"trace,omitempty"`
}

// Outcome is the result of one verification stage.
type Outcome string

const (
	Pass         Outcome = "pass"
	Fail         Outcome = "fail"
	Inconclusive Outcome = "inconclusive"
)

// Verdict records what one verification stage concluded and why.
type Verdict struct {
	Stage   string    `json:"stage"`
	Outcome Outcome   `json:"outcome"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
}

// Finding is one reported issue.
type Finding struct {
	ID     string `json:"id"`
	Kind   Kind   `json:"kind,omitempty"`
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	Title  string `json:"title"`
	// Description is the scanner's explanation of the rule, when it gives one.
	Description string   `json:"description,omitempty"`
	Severity    Severity `json:"severity"`
	// Target is a URL for a dynamic finding and "file:line" for a static one.
	Target string `json:"target"`
	// Location is set for static findings.
	Location *Location `json:"location,omitempty"`
	// AssetURL is the running service a static finding's code belongs to, when
	// the operator declared one. It anchors the finding in the asset graph.
	AssetURL string `json:"asset_url,omitempty"`
	// Tags and CWE are the scanner's own classification of the rule.
	Tags     []string  `json:"tags,omitempty"`
	CWE      []string  `json:"cwe,omitempty"`
	Evidence Evidence  `json:"evidence"`
	Status   Status    `json:"status"`
	Verdicts []Verdict `json:"verdicts,omitempty"`
	// CorroboratedBy lists findings of the other kind (code for a live one,
	// live for a code one) that show the same weakness on the same service.
	CorroboratedBy []string `json:"corroborated_by,omitempty"`
}

// StableID derives an ID from what identifies a finding, so the same issue
// found twice gets the same ID.
func StableID(source, ruleID, target, matcher string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{source, ruleID, target, matcher}, "\x1f")))
	return hex.EncodeToString(sum[:8])
}

// WithVerdict returns a copy of f with v appended. f is not modified.
func (f Finding) WithVerdict(v Verdict) Finding {
	verdicts := make([]Verdict, 0, len(f.Verdicts)+1)
	verdicts = append(verdicts, f.Verdicts...)
	f.Verdicts = append(verdicts, v)
	return f
}

// WithStatus returns a copy of f with its status set. f is not modified.
func (f Finding) WithStatus(s Status) Finding {
	f.Status = s
	return f
}
