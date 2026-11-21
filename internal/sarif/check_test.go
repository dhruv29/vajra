package sarif

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/verify"
)

var _ verify.Reproducer = (*Checker)(nil)

const dbJS = `const db = require("./db");

// look up a user by id
function find(id) {
    db.query("SELECT * FROM u WHERE id=" + id)
}

/*
 * block comment
 */
*p = 1;
`

const settingsPy = "import os\r\nPASSWORD = 'hunter2'\r\n\r\n# TODO rotate\r\n"

// sourceTree writes a small project and returns its root.
func sourceTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"src/db.js":       dbJS,
		"app/settings.py": settingsPy,
		"notes.txt":       "# not a comment in an unknown language\n",
		"Dockerfile":      "FROM alpine\n# pinned\n",
		"empty.go":        "",
	}
	for name, content := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func newChecker(t *testing.T, root string) *Checker {
	t.Helper()
	c, err := NewChecker(root)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func claim(source, file string, line, end int, snippet string) finding.Finding {
	f := finding.Finding{Source: source, RuleID: "r", Location: &finding.Location{File: file, Line: line, EndLine: end}}
	if snippet != "" {
		f.Evidence.Extracted = []string{snippet}
	}
	return f
}

func TestReproduceChecksEachClaimAgainstTheSourceTree(t *testing.T) {
	c := newChecker(t, sourceTree(t))
	const tool = "sarif:codeql"
	cases := []struct {
		name   string
		f      finding.Finding
		reason Reason
	}{
		{"code is there", claim(tool, "src/db.js", 5, 0, ""), Matches},
		{"snippet at the line", claim(tool, "src/db.js", 5, 0, `db.query("SELECT * FROM u WHERE id=" + id)`), Matches},
		{"snippet with other whitespace", claim(tool, "src/db.js", 5, 0, "db.query(\"SELECT *   FROM u\n WHERE id=\" + id)"), Matches},
		{"snippet a few lines off", claim(tool, "src/db.js", 4, 0, "const db = require"), Matches},
		{"multi-line snippet", claim(tool, "src/db.js", 4, 0, "function find(id) {\n    db.query("), Matches},
		{"whitespace-only snippet is no claim", claim(tool, "src/db.js", 5, 0, " \n "), Matches},
		{"crlf file", claim(tool, "app/settings.py", 2, 0, "PASSWORD = 'hunter2'"), Matches},
		{"range with some code", claim(tool, "src/db.js", 2, 4, ""), Matches},
		{"dereference is code", claim(tool, "src/db.js", 11, 0, ""), Matches},
		{"unknown language", claim(tool, "notes.txt", 1, 0, ""), Matches},
		{"other sources' extracted values are not snippets", claim("semgrep", "src/db.js", 5, 0, "nothing like it"), Matches},
		{"missing file", claim(tool, "src/gone.js", 1, 0, ""), MissingFile},
		{"missing directory", claim(tool, "nope/a.js", 1, 0, ""), MissingFile},
		{"file used as a directory", claim(tool, "src/db.js/x", 1, 0, ""), MissingFile},
		{"line past the end", claim(tool, "src/db.js", 12, 0, ""), PastEnd},
		{"empty file", claim(tool, "empty.go", 1, 0, ""), PastEnd},
		{"snippet not there", claim(tool, "src/db.js", 5, 0, "eval(userInput)"), SnippetMismatch},
		{"snippet too far away", claim(tool, "src/db.js", 1, 0, "db.query("), SnippetMismatch},
		{"blank line", claim(tool, "src/db.js", 2, 0, ""), NotCode},
		{"line comment", claim(tool, "src/db.js", 3, 0, ""), NotCode},
		{"block comment", claim(tool, "src/db.js", 8, 10, ""), NotCode},
		{"hash comment with crlf", claim(tool, "app/settings.py", 3, 4, ""), NotCode},
		{"dockerfile comment", claim(tool, "Dockerfile", 2, 0, ""), NotCode},
	}
	for _, tc := range cases {
		a, err := c.Assess(context.Background(), tc.f)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if a.Reason != tc.reason || a.Holds != (tc.reason == Matches) || a.Detail == "" {
			t.Errorf("%s: %+v; want %s", tc.name, a, tc.reason)
		}
		held, err := c.Reproduce(context.Background(), tc.f)
		if err != nil || held != a.Holds {
			t.Errorf("%s: Reproduce = %v, %v; Assess said %v", tc.name, held, err, a.Holds)
		}
	}
}

func TestReproduceIsAnErrorWhenTheFileCannotBeRead(t *testing.T) {
	root := sourceTree(t)
	outside := filepath.Join(t.TempDir(), "secret.py")
	write(t, outside, "SECRET = 1\n")
	if err := os.Symlink(outside, filepath.Join(root, "link.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../../../../../etc", filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "big.py"), strings.Repeat("x = 1\n", maxSourceBytes/6+1))
	write(t, filepath.Join(root, "blob.bin"), "MZ\x00\x00code")
	write(t, filepath.Join(root, "locked.py"), "x = 1\n")
	if err := os.Chmod(filepath.Join(root, "locked.py"), 0); err != nil {
		t.Fatal(err)
	}
	c := newChecker(t, root)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := map[string]struct {
		ctx context.Context
		f   finding.Finding
	}{
		"symlink out of the tree":     {context.Background(), claim("sarif:t", "link.py", 1, 0, "")},
		"symlinked directory outside": {context.Background(), claim("sarif:t", "etc/passwd", 1, 0, "")},
		"too large":                   {context.Background(), claim("sarif:t", "big.py", 1, 0, "")},
		"binary":                      {context.Background(), claim("sarif:t", "blob.bin", 1, 0, "")},
		"a directory":                 {context.Background(), claim("sarif:t", "src", 1, 0, "")},
		"parent path":                 {context.Background(), claim("sarif:t", "../secret.py", 1, 0, "")},
		"absolute path":               {context.Background(), claim("sarif:t", outside, 1, 0, "")},
		"no location":                 {context.Background(), finding.Finding{Source: "sarif:t"}},
		"line zero":                   {context.Background(), claim("sarif:t", "src/db.js", 0, 0, "")},
		"cancelled":                   {cancelled, claim("sarif:t", "src/db.js", 5, 0, "")},
	}
	if os.Geteuid() != 0 {
		cases["permission denied"] = struct {
			ctx context.Context
			f   finding.Finding
		}{context.Background(), claim("sarif:t", "locked.py", 1, 0, "")}
	}
	for name, tc := range cases {
		held, err := c.Reproduce(tc.ctx, tc.f)
		if err == nil || held {
			t.Errorf("%s: held = %v, err = %v; want an error", name, held, err)
		}
		if got := c.Explain(tc.f); name != "cancelled" && !strings.HasPrefix(got, "the claim could not be checked") {
			t.Errorf("%s: explanation = %q", name, got)
		}
		if strings.Contains(c.Explain(tc.f), "SECRET") {
			t.Errorf("%s: content outside the root leaked", name)
		}
	}
}

func TestReproduceFailsWhenTheRootDisappears(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proj")
	write(t, filepath.Join(root, "a.py"), "x = 1\n")
	c := newChecker(t, root)
	if err := os.Rename(root, root+".moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reproduce(context.Background(), claim("sarif:t", "a.py", 1, 0, "")); err == nil {
		t.Error("a vanished root gave no error")
	}
}

func TestExplainSaysWhyAClaimWasThrownOut(t *testing.T) {
	c := newChecker(t, sourceTree(t))
	cases := map[string]finding.Finding{
		"which is not in the source tree": claim("sarif:t", "gone.py", 1, 0, ""),
		"which has only 11 lines":         claim("sarif:t", "src/db.js", 40, 0, ""),
		"the code the tool quoted":        claim("sarif:t", "src/db.js", 5, 0, "eval(x)"),
		"is blank or only a comment":      claim("sarif:t", "src/db.js", 3, 0, ""),
		"the cited code is present":       claim("sarif:t", "src/db.js", 5, 0, ""),
	}
	for want, f := range cases {
		if got := c.Explain(f); !strings.Contains(got, want) {
			t.Errorf("Explain = %q; want it to mention %q", got, want)
		}
	}
}

func TestContextShowsTheRealCodeWithoutChangingTheInput(t *testing.T) {
	c := newChecker(t, sourceTree(t))
	in := claim("sarif:t", "src/db.js", 5, 6, "what the tool claimed")
	in.Tags = []string{"security"}

	out, err := c.Context(in)

	if err != nil {
		t.Fatal(err)
	}
	if in.Evidence.Code != "" {
		t.Error("Context modified its input")
	}
	lines := strings.Split(strings.TrimSuffix(out.Evidence.Code, "\n"), "\n")
	if len(lines) != 11 || lines[0] != "      1 | const db = require(\"./db\");" {
		t.Fatalf("context = %q", out.Evidence.Code)
	}
	if lines[4] != `>     5 |     db.query("SELECT * FROM u WHERE id=" + id)` || lines[5] != ">     6 | }" || !strings.HasPrefix(lines[6], "      7 |") {
		t.Errorf("marked lines = %q", lines[4:7])
	}
	if !slices.Equal(out.Evidence.Extracted, []string{"what the tool claimed"}) || !slices.Equal(out.Tags, in.Tags) {
		t.Errorf("other evidence changed: %+v", out.Evidence)
	}
}

func TestContextTruncatesLongLinesAndRefusesUnreadableClaims(t *testing.T) {
	root := sourceTree(t)
	write(t, filepath.Join(root, "long.py"), strings.Repeat("x", maxLineChars*2)+"\n")
	c := newChecker(t, root)

	out, err := c.Context(claim("sarif:t", "long.py", 1, 0, ""))
	if err != nil || !strings.HasSuffix(out.Evidence.Code, " [line truncated]\n") {
		t.Errorf("context = %q, err = %v", out.Evidence.Code, err)
	}
	for name, f := range map[string]finding.Finding{
		"missing":      claim("sarif:t", "gone.py", 1, 0, ""),
		"past the end": claim("sarif:t", "src/db.js", 99, 0, ""),
		"no location":  {},
	} {
		if out, err := c.Context(f); err == nil || out.Evidence.Code != "" {
			t.Errorf("%s: code = %q, err = %v; want an error and no code", name, out.Evidence.Code, err)
		}
	}
}

func TestNewCheckerNeedsAnExistingDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	write(t, file, "x")
	for name, root := range map[string]string{
		"empty":     "",
		"missing":   filepath.Join(t.TempDir(), "nope"),
		"not a dir": file,
	} {
		if c, err := NewChecker(root); err == nil || c != nil || !strings.HasPrefix(err.Error(), "sarif: ") {
			t.Errorf("%s: checker = %v, err = %v", name, c, err)
		}
	}
}

func TestImportedFindingsFlowThroughTheReproduceStage(t *testing.T) {
	root := sourceTree(t)
	report := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[
 {"ruleId":"sqli","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.js"},"region":{"startLine":5,"snippet":{"text":"db.query("}}}}]},
 {"ruleId":"invented","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.js"},"region":{"startLine":5,"snippet":{"text":"os.system(cmd)"}}}}]}]}]}`
	findings, _ := parse(t, report, Options{})
	c := newChecker(t, root)
	pipeline, err := verify.NewPipeline(nil, verify.ReproduceStage{Reproducer: verify.SourceRouter{findings[0].Source: c}, Attempts: 1})
	if err != nil {
		t.Fatal(err)
	}

	got := pipeline.VerifyAll(context.Background(), findings)

	if got[0].RuleID != "invented" || got[0].Status != finding.Refuted || got[1].Status != finding.Confirmed {
		t.Errorf("statuses = %s %s / %s %s", got[0].RuleID, got[0].Status, got[1].RuleID, got[1].Status)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
