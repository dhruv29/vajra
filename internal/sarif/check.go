package sarif

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

// snippetSlack is how many lines either side of the cited region a reported
// snippet may sit. Tools disagree by a line or two about where a match
// starts; more than this and the code has moved or the report is invented.
const snippetSlack = 3

// Reason says why a claim was kept or thrown out.
type Reason string

const (
	// Matches: the cited code exists and looks like what was reported.
	Matches Reason = "matches"
	// MissingFile: the report cites a file the source tree does not have.
	MissingFile Reason = "missing_file"
	// PastEnd: the cited line is beyond the end of the file.
	PastEnd Reason = "past_end"
	// SnippetMismatch: the code the tool quoted is not at the cited place.
	SnippetMismatch Reason = "snippet_mismatch"
	// NotCode: the cited lines are blank or only comments.
	NotCode Reason = "not_code"
)

// Assessment is the checker's conclusion about one finding and a sentence a
// person can read in the report.
type Assessment struct {
	Holds  bool
	Reason Reason
	Detail string
}

// Checker tests SARIF claims against the source tree. A third-party tool
// cannot be re-run, so reproducing one of its results means confirming that
// the code it describes is really there. Every read goes through os.Root:
// no path or symbolic link can reach outside the project.
type Checker struct {
	root string
}

// NewChecker returns a checker for the project at root.
func NewChecker(root string) (*Checker, error) {
	if root == "" {
		return nil, errors.New("sarif: a source root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("sarif: source root: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("sarif: source root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("sarif: source root %q is not a directory", abs)
	}
	return &Checker{root: abs}, nil
}

// Reproduce reports whether the code f describes is in the source tree. It
// satisfies verify.Reproducer. A file that exists but cannot be read is an
// error (inconclusive), never a refutation.
func (c *Checker) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	a, err := c.Assess(ctx, f)
	return a.Holds, err
}

// Explain says in one sentence why f was kept or thrown out.
func (c *Checker) Explain(f finding.Finding) string {
	a, err := c.Assess(context.Background(), f)
	if err != nil {
		return "the claim could not be checked: " + err.Error()
	}
	return a.Detail
}

// Assess checks f against the source tree, in order: the file exists, the
// line exists, the quoted snippet is there, and the cited lines are code.
func (c *Checker) Assess(ctx context.Context, f finding.Finding) (Assessment, error) {
	if err := ctx.Err(); err != nil {
		return Assessment{}, err
	}
	loc, err := usableLocation(f)
	if err != nil {
		return Assessment{}, err
	}
	lines, err := c.readLines(loc.File)
	if errors.Is(err, errMissing) {
		return refuted(MissingFile, "the report cites %s, which is not in the source tree", loc.File), nil
	}
	if err != nil {
		return Assessment{}, err
	}
	if loc.Line > len(lines) {
		return refuted(PastEnd, "the report cites line %d of %s, which has only %d lines", loc.Line, loc.File, len(lines)), nil
	}
	if snippet := claimedSnippet(f); snippet != "" && !snippetNear(lines, loc, snippet) {
		return refuted(SnippetMismatch, "the code the tool quoted is not within %d lines of %s:%d; the code changed or the report is wrong",
			snippetSlack, loc.File, loc.Line), nil
	}
	if !regionHasCode(loc, lines) {
		return refuted(NotCode, "%s:%d is blank or only a comment", loc.File, loc.Line), nil
	}
	return Assessment{Holds: true, Reason: Matches, Detail: fmt.Sprintf("the cited code is present at %s:%d", loc.File, loc.Line)}, nil
}

// Context returns a copy of f whose Evidence.Code is the real source around
// the cited lines, numbered, with those lines marked, in the same form the
// semgrep scanner uses. The report then shows the code, not the tool's
// account of it. f is not modified.
func (c *Checker) Context(f finding.Finding) (finding.Finding, error) {
	loc, err := usableLocation(f)
	if err != nil {
		return f, err
	}
	lines, err := c.readLines(loc.File)
	if err != nil {
		return f, fmt.Errorf("sarif: read %s: %w", loc.File, err)
	}
	if loc.Line > len(lines) {
		return f, fmt.Errorf("sarif: line %d is past the end of %s", loc.Line, loc.File)
	}
	f.Evidence.Code = renderContext(lines, loc)
	return f, nil
}

func usableLocation(f finding.Finding) (finding.Location, error) {
	if f.Location == nil || !finding.SafeRelPath(f.Location.File) || f.Location.Line < 1 {
		return finding.Location{}, errors.New("sarif: the finding has no usable file location")
	}
	loc := *f.Location
	loc.EndLine = max(loc.Line, loc.EndLine)
	return loc, nil
}

func refuted(reason Reason, format string, args ...any) Assessment {
	return Assessment{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// claimedSnippet is the code the tool quoted. Only this package's findings
// carry one in Evidence.Extracted; other sources use that field differently.
func claimedSnippet(f finding.Finding) string {
	if !IsSource(f.Source) || len(f.Evidence.Extracted) == 0 || normalise(f.Evidence.Extracted[0]) == "" {
		return ""
	}
	return f.Evidence.Extracted[0]
}

// snippetNear reports whether the snippet appears, whitespace aside, in the
// cited region widened by snippetSlack lines each way.
func snippetNear(lines []string, loc finding.Location, snippet string) bool {
	span := strings.Count(snippet, "\n") + 1
	first := max(1, loc.Line-snippetSlack)
	last := min(len(lines), max(loc.EndLine, loc.Line+span-1)+snippetSlack)
	window := normalise(strings.Join(lines[first-1:last], "\n"))
	return strings.Contains(window, normalise(snippet))
}

// normalise collapses every run of whitespace to one space, so indentation
// and line-ending differences do not count as a different snippet.
func normalise(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
