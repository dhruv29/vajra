// Package fix proposes a code change for a confirmed code finding and checks
// that the change works.
//
// The source tree is never modified. The proposed change is applied to a
// throwaway copy of the one file, the rule that reported the finding is run
// again on that copy, and the result is a patch for a person to review. A
// patch is called verified only when the rule no longer fires.
package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	maxFileBytes    = 1 << 20
	maxChangedLines = 200
	maxReplacement  = 32 << 10
	diffContext     = 3
	dirMode         = 0o755
	fileMode        = 0o644
)

// Proposal is a change to one range of lines.
type Proposal struct {
	// StartLine and EndLine are 1-based and inclusive.
	StartLine   int
	EndLine     int
	Replacement string
	Explanation string
}

// Proposer suggests a change for a finding, given the file with line numbers.
type Proposer interface {
	Propose(ctx context.Context, f finding.Finding, numbered string) (Proposal, error)
}

// Rescan analyses one file under root and returns what the scanner finds.
type Rescan func(ctx context.Context, root, relPath string) ([]finding.Finding, error)

// Result is the outcome of one attempt.
type Result struct {
	FindingID string `json:"finding_id"`
	File      string `json:"file"`
	// Verified is true when the rule no longer matches the patched file.
	Verified    bool   `json:"verified"`
	Reason      string `json:"reason"`
	Explanation string `json:"explanation"`
	// Patch is a unified diff against the original file.
	Patch string `json:"patch"`
}

// Attempt asks for a change, applies it to a copy, and re-runs the scanner.
func Attempt(ctx context.Context, sourceRoot string, f finding.Finding, proposer Proposer, rescan Rescan) (Result, error) {
	if proposer == nil || rescan == nil {
		return Result{}, errors.New("fix: a proposer and a rescan function are required")
	}
	if f.Kind != finding.Static || f.Location == nil || !finding.SafeRelPath(f.Location.File) {
		return Result{}, errors.New("fix: only code findings with a file location can be fixed")
	}
	rel := f.Location.File
	original, err := readConfined(sourceRoot, rel)
	if err != nil {
		return Result{}, err
	}
	lines := splitLines(original)
	if f.Location.Line < 1 || f.Location.Line > len(lines) {
		return Result{}, fmt.Errorf("fix: line %d is not in %s", f.Location.Line, rel)
	}
	proposal, err := proposer.Propose(ctx, f, numbered(lines))
	if err != nil {
		return Result{}, fmt.Errorf("fix: %w", err)
	}
	result := Result{FindingID: f.ID, File: rel, Explanation: strings.TrimSpace(proposal.Explanation)}
	if reason := invalid(proposal, len(lines)); reason != "" {
		result.Reason = "the proposed change was not usable: " + reason
		return result, nil
	}
	patched := apply(lines, proposal)
	if strings.Join(patched, "\n") == strings.Join(lines, "\n") {
		result.Reason = "the proposed change leaves the file as it was"
		return result, nil
	}
	result.Patch = unifiedDiff(rel, lines, patched, proposal)

	remaining, err := rescanCopy(ctx, rel, patched, hadTrailingNewline(original), rescan)
	if err != nil {
		return Result{}, err
	}
	for _, r := range remaining {
		if r.RuleID == f.RuleID {
			result.Reason = fmt.Sprintf("the rule still matches the patched file at line %d", lineOf(r))
			return result, nil
		}
	}
	result.Verified = true
	result.Reason = "the rule no longer matches the patched file; review the change before applying it"
	return result, nil
}

func lineOf(f finding.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.Line
}

// readConfined reads a file through os.Root, so a path or link leading out of
// the source tree is refused.
func readConfined(sourceRoot, rel string) (string, error) {
	root, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return "", fmt.Errorf("fix: open source tree: %w", err)
	}
	defer root.Close()
	file, err := root.Open(rel)
	if err != nil {
		return "", fmt.Errorf("fix: open %s: %w", rel, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("fix: read %s: %w", rel, err)
	}
	if len(raw) > maxFileBytes {
		return "", fmt.Errorf("fix: %s is too large to patch automatically", rel)
	}
	return string(raw), nil
}

func hadTrailingNewline(content string) bool { return strings.HasSuffix(content, "\n") }

func splitLines(content string) []string {
	return strings.Split(strings.TrimSuffix(content, "\n"), "\n")
}

func numbered(lines []string) string {
	var b strings.Builder
	for i, line := range lines {
		fmt.Fprintf(&b, "%5d | %s\n", i+1, line)
	}
	return b.String()
}

// invalid returns why a proposal cannot be applied, or "".
func invalid(p Proposal, lineCount int) string {
	switch {
	case p.StartLine < 1 || p.EndLine < p.StartLine || p.EndLine > lineCount:
		return fmt.Sprintf("lines %d-%d are not a range within the file's %d lines", p.StartLine, p.EndLine, lineCount)
	case p.EndLine-p.StartLine+1 > maxChangedLines:
		return fmt.Sprintf("it rewrites more than %d lines", maxChangedLines)
	case len(p.Replacement) > maxReplacement:
		return "the replacement is too large"
	case strings.ContainsRune(p.Replacement, 0):
		return "the replacement contains a NUL byte"
	}
	return ""
}

func apply(lines []string, p Proposal) []string {
	var replacement []string
	if p.Replacement != "" {
		replacement = splitLines(p.Replacement)
	}
	out := make([]string, 0, len(lines)+len(replacement))
	out = append(out, lines[:p.StartLine-1]...)
	out = append(out, replacement...)
	return append(out, lines[p.EndLine:]...)
}

// rescanCopy writes the patched file into an empty temporary tree at the same
// relative path and analyses it there.
func rescanCopy(ctx context.Context, rel string, patched []string, trailingNewline bool, rescan Rescan) ([]finding.Finding, error) {
	tmp, err := os.MkdirTemp("", "vajra-fix-")
	if err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	defer os.RemoveAll(tmp)
	// The scanner runs as an unprivileged user and must be able to read it.
	if err := os.Chmod(tmp, dirMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	target := filepath.Join(tmp, rel)
	if err := os.MkdirAll(filepath.Dir(target), dirMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	content := strings.Join(patched, "\n")
	if trailingNewline {
		content += "\n"
	}
	if err := os.WriteFile(target, []byte(content), fileMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	findings, err := rescan(ctx, resolved, rel)
	if err != nil {
		return nil, fmt.Errorf("fix: re-run the scanner on the patched file: %w", err)
	}
	return findings, nil
}

// unifiedDiff renders the one changed range as a unified diff hunk.
func unifiedDiff(rel string, before, after []string, p Proposal) string {
	removed := before[p.StartLine-1 : p.EndLine]
	added := after[p.StartLine-1 : p.StartLine-1+len(after)-len(before)+len(removed)]
	from := max(1, p.StartLine-diffContext)
	to := min(len(before), p.EndLine+diffContext)
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", rel, rel)
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", from, to-from+1, from, to-from+1+len(added)-len(removed))
	for _, line := range before[from-1 : p.StartLine-1] {
		b.WriteString(" " + line + "\n")
	}
	for _, line := range removed {
		b.WriteString("-" + line + "\n")
	}
	for _, line := range added {
		b.WriteString("+" + line + "\n")
	}
	for _, line := range before[p.EndLine:to] {
		b.WriteString(" " + line + "\n")
	}
	return b.String()
}
