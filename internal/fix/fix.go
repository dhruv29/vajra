// Package fix proposes a code change for a confirmed code finding and checks
// that the change works.
//
// The source tree is never modified. The proposed change is applied to a
// throwaway copy of the one file, the rule that reported the finding is run
// again on that copy, and the result is a patch for a person to review. A
// patch is called verified only when it changes code within the lines the
// model was shown, the rule fired on the unpatched copy and no longer fires on
// the patched one, and no rule fires that did not fire before.
package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	maxFileBytes    = 1 << 20
	maxChangedLines = 200
	maxReplacement  = 32 << 10
	diffContext     = 3
	dirMode         = 0o755
	privateDirMode  = 0o700
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
	// Verified is true when the change alters code, the rule matched the
	// unpatched file but no longer matches the patched one, and no new rule
	// matches.
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
	result := Result{FindingID: f.ID, File: rel, Explanation: strings.TrimSpace(stripInvisible(proposal.Explanation))}
	if reason := invalid(proposal, len(lines), f.Location.Line); reason != "" {
		result.Reason = "the proposed change was not usable: " + reason
		return result, nil
	}
	patched := apply(lines, proposal)
	if strings.Join(patched, "\n") == strings.Join(lines, "\n") {
		result.Reason = "the proposed change leaves the file as it was"
		return result, nil
	}
	trailing := hadTrailingNewline(original)
	result.Patch = unifiedDiff(rel, lines, patched, proposal, trailing)
	if !changesCode(lines[proposal.StartLine-1:proposal.EndLine], proposal.Replacement) {
		result.Reason = "the proposed change only removes or comments out code, which is not a fix"
		return result, nil
	}

	before, err := rescanCopy(ctx, rel, lines, trailing, rescan)
	if err != nil {
		return Result{}, fmt.Errorf("fix: run the scanner on the unpatched file: %w", err)
	}
	baseline := map[string]bool{}
	for _, b := range before {
		baseline[b.RuleID] = true
	}
	if !baseline[f.RuleID] {
		result.Reason = "the scanner does not report this finding on the unpatched file, so a clean result after the change proves nothing"
		return result, nil
	}
	remaining, err := rescanCopy(ctx, rel, patched, trailing, rescan)
	if err != nil {
		return Result{}, fmt.Errorf("fix: re-run the scanner on the patched file: %w", err)
	}
	for _, r := range remaining {
		if r.RuleID == f.RuleID {
			result.Reason = fmt.Sprintf("the rule still matches the patched file at line %d", lineOf(r))
			return result, nil
		}
	}
	for _, r := range remaining {
		if !baseline[r.RuleID] {
			result.Reason = fmt.Sprintf("the change introduces a finding the original did not have: rule %s at line %d", oneLine(r.RuleID), lineOf(r))
			return result, nil
		}
	}
	result.Verified = true
	result.Reason = "the rule no longer matches the patched file; review the change before applying it"
	return result, nil
}

// changesCode reports whether the replacement holds at least one line of code,
// not blank and not only a comment, that was not already among the replaced
// lines. A change that only deletes or comments out code does not.
func changesCode(removed []string, replacement string) bool {
	old := map[string]bool{}
	for _, line := range removed {
		old[strings.TrimSpace(line)] = true
	}
	for _, line := range strings.Split(replacement, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isComment(trimmed) || old[trimmed] {
			continue
		}
		return true
	}
	return false
}

var commentPrefixes = []string{"#", "//", "/*", "*", "--", "<!--"}

func isComment(trimmed string) bool {
	for _, prefix := range commentPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// invisible reports a control character other than newline and tab, or a
// format character such as a bidirectional override or a zero-width space.
func invisible(r rune) bool {
	return (unicode.Is(unicode.Cc, r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r)
}

// stripInvisible removes what invisible reports, for text shown to a person.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if invisible(r) {
			return -1
		}
		return r
	}, s)
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

// invalid returns why a proposal cannot be applied, or "". line is the
// finding's line; the model was shown only WindowLines either side of it.
func invalid(p Proposal, lineCount, line int) string {
	shownFrom, shownTo := max(1, line-WindowLines), min(lineCount, line+WindowLines)
	switch {
	case p.StartLine < 1 || p.EndLine < p.StartLine || p.EndLine > lineCount:
		return fmt.Sprintf("lines %d-%d are not a range within the file's %d lines", p.StartLine, p.EndLine, lineCount)
	case p.EndLine-p.StartLine+1 > maxChangedLines:
		return fmt.Sprintf("it rewrites more than %d lines", maxChangedLines)
	case p.StartLine < shownFrom || p.EndLine > shownTo:
		return fmt.Sprintf("lines %d-%d are outside the lines %d-%d shown around the finding", p.StartLine, p.EndLine, shownFrom, shownTo)
	case len(p.Replacement) > maxReplacement:
		return "the replacement is too large"
	case strings.ContainsRune(p.Replacement, 0):
		return "the replacement contains a NUL byte"
	case strings.ContainsFunc(p.Replacement, invisible):
		return "the replacement contains control or invisible characters"
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

// rescanCopy writes the file into an empty temporary tree at the same
// relative path and analyses it there. The tree must be readable by the
// scanner, which runs as another user, so it sits inside a private parent
// directory that other local users cannot enter.
func rescanCopy(ctx context.Context, rel string, patched []string, trailingNewline bool, rescan Rescan) ([]finding.Finding, error) {
	parent, err := os.MkdirTemp("", "vajra-fix-")
	if err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	defer os.RemoveAll(parent)
	if err := os.Chmod(parent, privateDirMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	tmp := filepath.Join(parent, "tree")
	if err := os.Mkdir(tmp, dirMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	// The scanner runs as an unprivileged user and must be able to read it.
	if err := os.Chmod(tmp, dirMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	target := filepath.Join(tmp, rel)
	if err := os.MkdirAll(filepath.Dir(target), dirMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	content := strings.Join(patched, "\n")
	if trailingNewline && content != "" {
		content += "\n"
	}
	if err := os.WriteFile(target, []byte(content), fileMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	// Modes are set explicitly: a restrictive umask would otherwise leave the
	// copy unreadable to the scanner.
	if err := os.Chmod(target, fileMode); err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	for dir := filepath.Dir(target); dir != tmp && strings.HasPrefix(dir, tmp); dir = filepath.Dir(dir) {
		if err := os.Chmod(dir, dirMode); err != nil {
			return nil, fmt.Errorf("fix: %w", err)
		}
	}
	resolved, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		return nil, fmt.Errorf("fix: %w", err)
	}
	return rescan(ctx, resolved, rel)
}

// noNewlineMarker is what a unified diff writes after a last line that has no
// newline; without it the patch does not apply to such a file.
const noNewlineMarker = "\\ No newline at end of file\n"

// unifiedDiff renders the one changed range as a unified diff hunk.
func unifiedDiff(rel string, before, after []string, p Proposal, trailingNewline bool) string {
	removed := before[p.StartLine-1 : p.EndLine]
	added := after[p.StartLine-1 : p.StartLine-1+len(after)-len(before)+len(removed)]
	from := max(1, p.StartLine-diffContext)
	to := min(len(before), p.EndLine+diffContext)
	// mark follows a line that is the last of its file when that file does
	// not end in a newline.
	mark := func(isLastLine bool) string {
		if isLastLine && !trailingNewline {
			return noNewlineMarker
		}
		return ""
	}
	changesLastLine := p.EndLine == len(before)
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", rel, rel)
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", from, to-from+1, from, to-from+1+len(added)-len(removed))
	for _, line := range before[from-1 : p.StartLine-1] {
		b.WriteString(" " + line + "\n")
	}
	for i, line := range removed {
		b.WriteString("-" + line + "\n" + mark(changesLastLine && i == len(removed)-1))
	}
	for i, line := range added {
		b.WriteString("+" + line + "\n" + mark(changesLastLine && i == len(added)-1))
	}
	for i, line := range before[p.EndLine:to] {
		b.WriteString(" " + line + "\n" + mark(p.EndLine+i+1 == len(before)))
	}
	return b.String()
}
