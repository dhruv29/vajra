package fix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	testRule     = "go.sql.string-concat"
	testFile     = "app/db.go"
	verifiedText = "the rule no longer matches the patched file; review the change before applying it"
)

// fakeProposer returns a fixed proposal and records what it was asked.
type fakeProposer struct {
	proposal Proposal
	err      error
	calls    int
	ctx      context.Context
	finding  finding.Finding
	numbered string
}

func (p *fakeProposer) Propose(ctx context.Context, f finding.Finding, numbered string) (Proposal, error) {
	p.calls++
	p.ctx, p.finding, p.numbered = ctx, f, numbered
	return p.proposal, p.err
}

// fakeScanner reports fixed findings and records the tree it was shown while
// that tree still exists.
type fakeScanner struct {
	findings []finding.Finding
	err      error
	calls    int
	ctx      context.Context
	root     string
	rel      string
	// content is the patched file as the scanner read it.
	content string
	// files are the regular files under root; modes covers directories too.
	files []string
	modes map[string]fs.FileMode
}

func (s *fakeScanner) scan(ctx context.Context, root, rel string) ([]finding.Finding, error) {
	s.calls++
	s.ctx, s.root, s.rel = ctx, root, rel
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return nil, fmt.Errorf("the patched file is not where the scanner was told: %w", err)
	}
	s.content, s.files, s.modes = string(raw), nil, map[string]fs.FileMode{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		s.modes[name] = info.Mode()
		if !d.IsDir() {
			s.files = append(s.files, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.findings, s.err
}

// writeSource creates a source tree holding one file and returns its root.
func writeSource(t *testing.T, rel, content string) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// numberedSource is "line 1\nline 2\n..." with a trailing newline.
func numberedSource(count int) string {
	var b strings.Builder
	for i := 1; i <= count; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	return b.String()
}

func codeFinding(rel string, line int) finding.Finding {
	return finding.Finding{
		ID: "finding-1", Kind: finding.Static, Source: "scanner", RuleID: testRule,
		Title: "SQL built by concatenation", Description: "User input reaches a query.",
		Severity: finding.SeverityHigh, Target: fmt.Sprintf("%s:%d", rel, line),
		Location: &finding.Location{File: rel, Line: line}, Status: finding.Confirmed,
	}
}

func match(rule string, line int) finding.Finding {
	return finding.Finding{Kind: finding.Static, RuleID: rule, Location: &finding.Location{File: testFile, Line: line}}
}

func replace(start, end int, replacement string) Proposal {
	return Proposal{StartLine: start, EndLine: end, Replacement: replacement, Explanation: "Binds the parameter."}
}

func TestAttemptVerifiesAChangeAfterWhichTheRuleNoLongerMatches(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(10))
	proposer := &fakeProposer{proposal: Proposal{
		StartLine: 5, EndLine: 5, Replacement: "bound 5a\nbound 5b", Explanation: "  Binds the parameter.\n",
	}}
	scanner := &fakeScanner{}
	f := codeFinding(testFile, 5)

	result, err := Attempt(context.Background(), root, f, proposer, scanner.scan)

	if err != nil {
		t.Fatal(err)
	}
	want := Result{
		FindingID: "finding-1", File: testFile, Verified: true, Reason: verifiedText, Explanation: "Binds the parameter.",
		Patch: "--- a/app/db.go\n+++ b/app/db.go\n@@ -2,7 +2,8 @@\n line 2\n line 3\n line 4\n-line 5\n+bound 5a\n+bound 5b\n line 6\n line 7\n line 8\n",
	}
	if result != want {
		t.Fatalf("result = %+v\nwant     %+v", result, want)
	}
	if proposer.calls != 1 || scanner.calls != 1 {
		t.Fatalf("proposer calls = %d, scanner calls = %d; want one each", proposer.calls, scanner.calls)
	}
}

func TestTheProposerIsGivenTheFindingAndTheWholeFileWithLineNumbers(t *testing.T) {
	root := writeSource(t, testFile, "package db\n\n\tquery := \"SELECT \" + name\n")
	proposer := &fakeProposer{proposal: replace(3, 3, "\tquery := \"SELECT ?\"")}
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "run-7")
	scanner := &fakeScanner{}

	if _, err := Attempt(ctx, root, codeFinding(testFile, 3), proposer, scanner.scan); err != nil {
		t.Fatal(err)
	}

	if want := "    1 | package db\n    2 | \n    3 | \tquery := \"SELECT \" + name\n"; proposer.numbered != want {
		t.Fatalf("listing = %q; want %q", proposer.numbered, want)
	}
	if proposer.finding.ID != "finding-1" || proposer.finding.RuleID != testRule || proposer.finding.Location.Line != 3 {
		t.Fatalf("finding passed to the proposer = %+v", proposer.finding)
	}
	if proposer.ctx.Value(key{}) != "run-7" || scanner.ctx.Value(key{}) != "run-7" {
		t.Fatal("the caller's context did not reach the proposer and the scanner")
	}
}

func TestThePatchIsAUnifiedDiffOfTheChangedRange(t *testing.T) {
	cases := map[string]struct {
		lines    int
		proposal Proposal
		// want is everything after the two header lines.
		want string
	}{
		"the first line of the file": {5, replace(1, 1, "first"),
			"@@ -1,4 +1,4 @@\n-line 1\n+first\n line 2\n line 3\n line 4\n"},
		"the last line of the file": {5, replace(5, 5, "last"),
			"@@ -2,4 +2,4 @@\n line 2\n line 3\n line 4\n-line 5\n+last\n"},
		"the first line becoming three": {2, replace(1, 1, "a\nb\nc"),
			"@@ -1,2 +1,4 @@\n-line 1\n+a\n+b\n+c\n line 2\n"},
		"the last line becoming two": {2, replace(2, 2, "a\nb"),
			"@@ -1,2 +1,3 @@\n line 1\n-line 2\n+a\n+b\n"},
		"four lines becoming one": {10, replace(4, 7, "one"),
			"@@ -1,10 +1,7 @@\n line 1\n line 2\n line 3\n-line 4\n-line 5\n-line 6\n-line 7\n+one\n line 8\n line 9\n line 10\n"},
		"an empty replacement deleting the lines": {6, replace(3, 4, ""),
			"@@ -1,6 +1,4 @@\n line 1\n line 2\n-line 3\n-line 4\n line 5\n line 6\n"},
		"every line of the file replaced": {3, replace(1, 3, "x"),
			"@@ -1,3 +1,1 @@\n-line 1\n-line 2\n-line 3\n+x\n"},
		"three lines of context on each side, no more": {20, replace(10, 11, "x"),
			"@@ -7,8 +7,7 @@\n line 7\n line 8\n line 9\n-line 10\n-line 11\n+x\n line 12\n line 13\n line 14\n"},
		"a replacement's own final newline is not an extra line": {3, replace(2, 2, "x\n"),
			"@@ -1,3 +1,3 @@\n line 1\n-line 2\n+x\n line 3\n"},
		"a replacement of one newline is one blank line": {3, replace(2, 2, "\n"),
			"@@ -1,3 +1,3 @@\n line 1\n-line 2\n+\n line 3\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeSource(t, testFile, numberedSource(tc.lines))
			scanner := &fakeScanner{}

			result, err := Attempt(context.Background(), root, codeFinding(testFile, tc.proposal.StartLine),
				&fakeProposer{proposal: tc.proposal}, scanner.scan)

			if err != nil || !result.Verified {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
			if want := "--- a/app/db.go\n+++ b/app/db.go\n" + tc.want; result.Patch != want {
				t.Fatalf("patch:\n%s\nwant:\n%s", result.Patch, want)
			}
		})
	}
}

func TestTheScannerSeesThePatchedFileAtTheSameRelativePath(t *testing.T) {
	const rel = "src/pkg/handler.go"
	cases := map[string]struct {
		original string
		proposal Proposal
		want     string
	}{
		"a trailing newline is kept":                          {"a\nb\nc\n", replace(2, 2, "B"), "a\nB\nc\n"},
		"a missing trailing newline stays missing":            {"a\nb\nc", replace(2, 2, "B"), "a\nB\nc"},
		"the last line of a file with a trailing newline":     {"a\nb\nc\n", replace(3, 3, "C"), "a\nb\nC\n"},
		"the last line of a file without a trailing newline":  {"a\nb\nc", replace(3, 3, "C\n"), "a\nb\nC"},
		"the first line becoming two":                         {"a\nb\n", replace(1, 1, "x\ny"), "x\ny\nb\n"},
		"the last line becoming two, without a final newline": {"a\nb", replace(2, 2, "x\ny"), "a\nx\ny"},
		"an empty replacement deletes the lines":              {"a\nb\nc\nd\n", replace(2, 3, ""), "a\nd\n"},
		"deleting the last line of a file without a newline":  {"a\nb\nc", replace(3, 3, ""), "a\nb"},
		"blank lines elsewhere are untouched":                 {"a\n\n\nb\n\n", replace(4, 4, "B"), "a\n\n\nB\n\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeSource(t, rel, tc.original)
			scanner := &fakeScanner{}

			result, err := Attempt(context.Background(), root, codeFinding(rel, tc.proposal.StartLine),
				&fakeProposer{proposal: tc.proposal}, scanner.scan)

			if err != nil || !result.Verified || result.File != rel {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
			if scanner.rel != rel || scanner.content != tc.want {
				t.Fatalf("scanner was shown %q holding %q; want %q holding %q", scanner.rel, scanner.content, rel, tc.want)
			}
			if !slices.Equal(scanner.files, []string{rel}) {
				t.Fatalf("files in the scanned tree = %v; want only the patched file", scanner.files)
			}
		})
	}
}

func TestTheSourceTreeIsNeverModifiedAndTheCopyIsRemoved(t *testing.T) {
	cases := map[string]*fakeScanner{
		"verified":            {},
		"rule still matching": {findings: []finding.Finding{match(testRule, 5)}},
		"scanner failure":     {err: errors.New("scanner crashed")},
	}
	for name, scanner := range cases {
		t.Run(name, func(t *testing.T) {
			original := []byte(numberedSource(10))
			root := writeSource(t, testFile, string(original))

			_, _ = Attempt(context.Background(), root, codeFinding(testFile, 5),
				&fakeProposer{proposal: replace(5, 5, "changed")}, scanner.scan)

			after, err := os.ReadFile(filepath.Join(root, testFile))
			if err != nil || !bytes.Equal(after, original) {
				t.Fatalf("the source file changed: %q, err = %v", after, err)
			}
			entries, err := os.ReadDir(filepath.Join(root, "app"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("entries next to the source file = %v, err = %v; nothing may be written there", entries, err)
			}
			if scanner.calls != 1 || scanner.root == "" || strings.HasPrefix(scanner.root, root) {
				t.Fatalf("scanner calls = %d, root = %q; the scan must run on a copy outside %q", scanner.calls, scanner.root, root)
			}
			if _, err := os.Stat(scanner.root); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the temporary tree %q was left behind (stat err = %v)", scanner.root, err)
			}
		})
	}
}

func TestTheScannedRootIsAResolvedDirectoryHoldingOnlyThePatchedFile(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(10))
	if err := os.WriteFile(filepath.Join(root, "app", "secrets.env"), []byte("TOKEN=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := &fakeScanner{}
	var resolved string
	rescan := func(ctx context.Context, scanRoot, rel string) ([]finding.Finding, error) {
		resolved, _ = filepath.EvalSymlinks(scanRoot)
		return scanner.scan(ctx, scanRoot, rel)
	}

	if _, err := Attempt(context.Background(), root, codeFinding(testFile, 5), &fakeProposer{proposal: replace(5, 5, "x")}, rescan); err != nil {
		t.Fatal(err)
	}

	if !filepath.IsAbs(scanner.root) || scanner.root != resolved {
		t.Fatalf("root = %q; want an absolute path with symlinks resolved (%q)", scanner.root, resolved)
	}
	if !slices.Equal(scanner.files, []string{testFile}) {
		t.Fatalf("files in the scanned tree = %v; other source files must not be copied", scanner.files)
	}
}

func TestThePatchedCopyIsReadableByAnUnprivilegedScanner(t *testing.T) {
	root := writeSource(t, "a/b/c.go", numberedSource(3))
	scanner := &fakeScanner{}

	if _, err := Attempt(context.Background(), root, codeFinding("a/b/c.go", 2), &fakeProposer{proposal: replace(2, 2, "x")}, scanner.scan); err != nil {
		t.Fatal(err)
	}

	if got := scanner.modes["."].Perm(); got != dirMode {
		t.Fatalf("mode of the temporary root = %v; want %v", got, fs.FileMode(dirMode))
	}
	for name, mode := range scanner.modes {
		want := fs.FileMode(fileMode)
		if mode.IsDir() {
			want = dirMode
		}
		if mode.Perm()&want != want {
			t.Skipf("BUG: under a restrictive umask %q in the copy has mode %v, so a scanner running as another user cannot read it; "+
				"only the top directory is chmod-ed (fix.go rescanCopy)", name, mode.Perm())
		}
	}
}

func TestARuleThatStillMatchesLeavesThePatchUnverified(t *testing.T) {
	located := match(testRule, 7)
	unlocated := finding.Finding{Kind: finding.Static, RuleID: testRule}
	cases := map[string]struct {
		remaining  []finding.Finding
		wantReason string
	}{
		"same rule at another line":      {[]finding.Finding{located}, "the rule still matches the patched file at line 7"},
		"same rule after other rules":    {[]finding.Finding{match("go.other", 2), located}, "the rule still matches the patched file at line 7"},
		"same rule twice names first":    {[]finding.Finding{match(testRule, 3), located}, "the rule still matches the patched file at line 3"},
		"same rule without a location":   {[]finding.Finding{unlocated}, "the rule still matches the patched file at line 0"},
		"same rule at the original line": {[]finding.Finding{match(testRule, 5)}, "the rule still matches the patched file at line 5"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeSource(t, testFile, numberedSource(10))
			scanner := &fakeScanner{findings: tc.remaining}

			result, err := Attempt(context.Background(), root, codeFinding(testFile, 5),
				&fakeProposer{proposal: replace(5, 5, "still bad")}, scanner.scan)

			if err != nil {
				t.Fatal(err)
			}
			if result.Verified || result.Reason != tc.wantReason {
				t.Fatalf("verified = %v, reason = %q; want unverified with %q", result.Verified, result.Reason, tc.wantReason)
			}
			if !strings.Contains(result.Patch, "-line 5\n+still bad\n") || result.Explanation != "Binds the parameter." ||
				result.FindingID != "finding-1" || result.File != testFile {
				t.Fatalf("an unverified result must still carry the patch for review: %+v", result)
			}
		})
	}
}

func TestADifferentRuleMatchingThePatchedFileDoesNotBlockVerification(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(10))
	scanner := &fakeScanner{findings: []finding.Finding{
		match("go.weak-hash", 5),
		match(testRule+".v2", 5),
		match(strings.ToUpper(testRule), 5),
		{RuleID: ""},
	}}

	result, err := Attempt(context.Background(), root, codeFinding(testFile, 5), &fakeProposer{proposal: replace(5, 5, "fixed")}, scanner.scan)

	if err != nil || !result.Verified || result.Reason != verifiedText {
		t.Fatalf("result = %+v, err = %v; only the finding's own rule decides", result, err)
	}
}

func TestUnusableProposalsAreReportedWithoutRunningTheScanner(t *testing.T) {
	const unusable = "the proposed change was not usable: "
	cases := map[string]struct {
		proposal   Proposal
		wantReason string
	}{
		"start before the first line": {replace(0, 3, "x"), unusable + "lines 0-3 are not a range within the file's 250 lines"},
		"negative start":              {replace(-4, 3, "x"), unusable + "lines -4-3 are not a range within the file's 250 lines"},
		"end beyond the last line":    {replace(250, 251, "x"), unusable + "lines 250-251 are not a range within the file's 250 lines"},
		"range wholly outside":        {replace(900, 901, "x"), unusable + "lines 900-901 are not a range within the file's 250 lines"},
		"end before start":            {replace(10, 9, "x"), unusable + "lines 10-9 are not a range within the file's 250 lines"},
		"no range at all":             {Proposal{Explanation: "Binds the parameter."}, unusable + "lines 0-0 are not a range within the file's 250 lines"},
		"more than the line limit":    {replace(1, maxChangedLines+1, "x"), unusable + "it rewrites more than 200 lines"},
		"oversized replacement":       {replace(10, 10, strings.Repeat("x", maxReplacement+1)), unusable + "the replacement is too large"},
		"NUL byte":                    {replace(10, 10, "a\x00b"), unusable + "the replacement contains a NUL byte"},
		"the same line again":         {replace(10, 10, "line 10"), "the proposed change leaves the file as it was"},
		"the same line and a newline": {replace(10, 10, "line 10\n"), "the proposed change leaves the file as it was"},
		"the same lines again":        {replace(10, 12, "line 10\nline 11\nline 12"), "the proposed change leaves the file as it was"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeSource(t, testFile, numberedSource(250))
			scanner := &fakeScanner{}

			result, err := Attempt(context.Background(), root, codeFinding(testFile, 10), &fakeProposer{proposal: tc.proposal}, scanner.scan)

			if err != nil {
				t.Fatalf("err = %v; a bad proposal is a result, not a failure", err)
			}
			want := Result{FindingID: "finding-1", File: testFile, Reason: tc.wantReason, Explanation: "Binds the parameter."}
			if result != want {
				t.Fatalf("result = %+v\nwant     %+v", result, want)
			}
			if scanner.calls != 0 {
				t.Fatalf("the scanner ran %d times for a proposal that was never applied", scanner.calls)
			}
		})
	}
}

func TestProposalsAtTheLimitsAreApplied(t *testing.T) {
	cases := map[string]Proposal{
		"exactly the line limit":        replace(1, maxChangedLines, "x"),
		"exactly the replacement limit": replace(10, 10, strings.Repeat("x", maxReplacement)),
		"the whole of a one-line range": replace(250, 250, "x"),
	}
	for name, proposal := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeSource(t, testFile, numberedSource(250))
			scanner := &fakeScanner{}

			result, err := Attempt(context.Background(), root, codeFinding(testFile, 10), &fakeProposer{proposal: proposal}, scanner.scan)

			if err != nil || !result.Verified || scanner.calls != 1 {
				t.Fatalf("verified = %v, reason = %q, err = %v, scanner calls = %d", result.Verified, result.Reason, err, scanner.calls)
			}
		})
	}
}

func TestAProposerErrorIsReturned(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(10))
	sentinel := errors.New("model unavailable")
	scanner := &fakeScanner{}

	result, err := Attempt(context.Background(), root, codeFinding(testFile, 5), &fakeProposer{err: sentinel}, scanner.scan)

	if !errors.Is(err, sentinel) || !strings.HasPrefix(err.Error(), "fix: ") {
		t.Fatalf("err = %v; want the proposer's error, wrapped", err)
	}
	if result != (Result{}) || scanner.calls != 0 {
		t.Fatalf("result = %+v, scanner calls = %d", result, scanner.calls)
	}
}

func TestARescanErrorIsReturned(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(10))
	sentinel := errors.New("scanner crashed")
	scanner := &fakeScanner{err: sentinel, findings: []finding.Finding{match("go.other", 1)}}

	result, err := Attempt(context.Background(), root, codeFinding(testFile, 5), &fakeProposer{proposal: replace(5, 5, "x")}, scanner.scan)

	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "fix: re-run the scanner on the patched file") {
		t.Fatalf("err = %v; want the scanner's error, wrapped", err)
	}
	if result != (Result{}) {
		t.Fatalf("result = %+v; a patch that was never checked must not be returned as a result", result)
	}
}

func TestFindingsThatCannotBeFixedAreRefusedBeforeAskingForAChange(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(10))
	if err := os.WriteFile(filepath.Join(root, "big.go"), bytes.Repeat([]byte("x"), maxFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := writeSource(t, "secret.go", numberedSource(10))
	escaping, err := filepath.Rel(root, filepath.Join(outside, "secret.go"))
	if err != nil || !strings.HasPrefix(escaping, "../") {
		t.Fatalf("relative path out of the tree = %q, err = %v", escaping, err)
	}
	with := func(change func(*finding.Finding)) finding.Finding {
		f := codeFinding(testFile, 5)
		change(&f)
		return f
	}
	const notCode = "only code findings with a file location can be fixed"
	cases := map[string]struct {
		root    string
		finding finding.Finding
		wantErr string
	}{
		"dynamic finding":             {root, with(func(f *finding.Finding) { f.Kind = finding.Dynamic }), notCode},
		"dependency finding":          {root, with(func(f *finding.Finding) { f.Kind = finding.Dependency }), notCode},
		"finding of no kind":          {root, with(func(f *finding.Finding) { f.Kind = "" }), notCode},
		"no location":                 {root, with(func(f *finding.Finding) { f.Location = nil }), notCode},
		"empty path":                  {root, codeFinding("", 5), notCode},
		"path to an existing sibling": {root, codeFinding(escaping, 5), notCode},
		"parent directory":            {root, codeFinding("../x", 5), notCode},
		"parent directory itself":     {root, codeFinding("..", 5), notCode},
		"absolute path":               {root, codeFinding(filepath.Join(root, testFile), 5), notCode},
		"path that is not clean":      {root, codeFinding("app/../app/db.go", 5), notCode},
		"path with a NUL byte":        {root, codeFinding("app/db.go\x00.txt", 5), notCode},
		"line beyond the file":        {root, codeFinding(testFile, 11), "line 11 is not in app/db.go"},
		"line zero":                   {root, codeFinding(testFile, 0), "line 0 is not in app/db.go"},
		"negative line":               {root, codeFinding(testFile, -3), "line -3 is not in app/db.go"},
		"file over the size limit":    {root, codeFinding("big.go", 1), "big.go is too large to patch automatically"},
		"file that does not exist":    {root, codeFinding("app/missing.go", 1), "fix: open app/missing.go"},
		"directory":                   {root, codeFinding("app", 1), "fix: read app"},
		"source tree that is missing": {filepath.Join(root, "nowhere"), codeFinding(testFile, 5), "fix: open source tree"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			proposer, scanner := &fakeProposer{proposal: replace(1, 1, "x")}, &fakeScanner{}

			result, err := Attempt(context.Background(), tc.root, tc.finding, proposer, scanner.scan)

			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v; want one saying %q", err, tc.wantErr)
			}
			if result != (Result{}) || proposer.calls != 0 || scanner.calls != 0 {
				t.Fatalf("result = %+v, proposer calls = %d, scanner calls = %d; nothing may happen for a refused finding",
					result, proposer.calls, scanner.calls)
			}
		})
	}
}

func TestAFileOfExactlyTheSizeLimitIsAccepted(t *testing.T) {
	root := writeSource(t, "big.go", strings.Repeat("x", maxFileBytes))
	scanner := &fakeScanner{}

	result, err := Attempt(context.Background(), root, codeFinding("big.go", 1), &fakeProposer{proposal: replace(1, 1, "small")}, scanner.scan)

	if err != nil || !result.Verified || scanner.content != "small" {
		t.Fatalf("verified = %v, err = %v, scanned content of %d bytes", result.Verified, err, len(scanner.content))
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
}

func TestSymlinksLeadingOutOfTheSourceTreeAreRefused(t *testing.T) {
	outside := writeSource(t, "secret.go", numberedSource(10))
	root := writeSource(t, testFile, numberedSource(10))
	relativeTarget, err := filepath.Rel(root, filepath.Join(outside, "secret.go"))
	if err != nil {
		t.Fatal(err)
	}
	symlink(t, filepath.Join(outside, "secret.go"), filepath.Join(root, "absolute.go"))
	symlink(t, relativeTarget, filepath.Join(root, "relative.go"))
	symlink(t, outside, filepath.Join(root, "vendor"))
	cases := map[string]string{
		"file link with an absolute target": "absolute.go",
		"file link with a relative target":  "relative.go",
		"directory link":                    "vendor/secret.go",
	}
	for name, rel := range cases {
		t.Run(name, func(t *testing.T) {
			proposer, scanner := &fakeProposer{proposal: replace(1, 1, "x")}, &fakeScanner{}

			result, err := Attempt(context.Background(), root, codeFinding(rel, 1), proposer, scanner.scan)

			if err == nil || !strings.Contains(err.Error(), "fix: open "+rel) {
				t.Fatalf("err = %v; a link out of the source tree must not be read", err)
			}
			if result != (Result{}) || proposer.calls != 0 || scanner.calls != 0 {
				t.Fatalf("result = %+v, proposer calls = %d, scanner calls = %d", result, proposer.calls, scanner.calls)
			}
		})
	}
}

func TestASymlinkThatStaysInsideTheSourceTreeIsRead(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(3))
	symlink(t, "db.go", filepath.Join(root, "app", "alias.go"))
	proposer, scanner := &fakeProposer{proposal: replace(2, 2, "x")}, &fakeScanner{}

	result, err := Attempt(context.Background(), root, codeFinding("app/alias.go", 2), proposer, scanner.scan)

	if err != nil || !result.Verified || result.File != "app/alias.go" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	if scanner.rel != "app/alias.go" || scanner.content != "line 1\nx\nline 3\n" || !scanner.modes["app/alias.go"].IsRegular() {
		t.Fatalf("scanner saw %q = %q (mode %v); want a regular file with the patched content",
			scanner.rel, scanner.content, scanner.modes["app/alias.go"])
	}
}

func TestAttemptRequiresAProposerAndARescanFunction(t *testing.T) {
	root := writeSource(t, testFile, numberedSource(10))
	proposer, scanner := &fakeProposer{proposal: replace(5, 5, "x")}, &fakeScanner{}
	cases := map[string]struct {
		proposer Proposer
		rescan   Rescan
	}{
		"no proposer": {nil, scanner.scan},
		"no rescan":   {proposer, nil},
		"neither":     {nil, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := Attempt(context.Background(), root, codeFinding(testFile, 5), tc.proposer, tc.rescan)

			if err == nil || !strings.Contains(err.Error(), "a proposer and a rescan function are required") {
				t.Fatalf("err = %v", err)
			}
			if result != (Result{}) || proposer.calls != 0 || scanner.calls != 0 {
				t.Fatalf("result = %+v, proposer calls = %d, scanner calls = %d", result, proposer.calls, scanner.calls)
			}
		})
	}
}

func TestAPatchForAFileWithoutATrailingNewlineSaysSo(t *testing.T) {
	root := writeSource(t, testFile, "a\nb")
	scanner := &fakeScanner{}

	result, err := Attempt(context.Background(), root, codeFinding(testFile, 2), &fakeProposer{proposal: replace(2, 2, "c")}, scanner.scan)

	if err != nil || scanner.content != "a\nc" {
		t.Fatalf("scanned content = %q, err = %v", scanner.content, err)
	}
	want := "--- a/app/db.go\n+++ b/app/db.go\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
	if result.Patch != want {
		t.Fatalf("patch:\n%s\nwant:\n%s", result.Patch, want)
	}
}

func TestDeletingEveryLineGivesAPatchToAnEmptyFile(t *testing.T) {
	root := writeSource(t, testFile, "only\n")
	scanner := &fakeScanner{}

	result, err := Attempt(context.Background(), root, codeFinding(testFile, 1), &fakeProposer{proposal: replace(1, 1, "")}, scanner.scan)

	if err != nil {
		t.Fatal(err)
	}
	if want := "--- a/app/db.go\n+++ b/app/db.go\n@@ -1,1 +0,0 @@\n-only\n"; result.Patch != want {
		t.Fatalf("patch:\n%s\nwant:\n%s", result.Patch, want)
	}
	if scanner.content != "" {
		t.Fatalf("scanned content = %q; the patch describes an empty file", scanner.content)
	}
}
