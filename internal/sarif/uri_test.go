package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

// oneResult builds a document with one result at uri (relative to baseID
// when set) under the given originalUriBaseIds.
func oneResult(t *testing.T, uri, baseID, bases string) string {
	t.Helper()
	art := map[string]string{"uri": uri}
	if baseID != "" {
		art["uriBaseId"] = baseID
	}
	encoded, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	if bases == "" {
		bases = "{}"
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},"originalUriBaseIds":` + bases + `,
 "results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":` + string(encoded) + `,"region":{"startLine":1}}}]}]}]}`
}

const srcRoot = `{"%SRCROOT%":{"uri":"file:///work/repo/"}}`

func TestParseSkipsEveryPathThatCouldLeaveTheProject(t *testing.T) {
	cases := []struct{ name, uri, base, bases string }{
		{"parent traversal", "../../etc/passwd", "", ""},
		{"traversal inside a path", "src/../../etc/passwd", "", ""},
		{"traversal through the root base", "../../etc/passwd", "%SRCROOT%", srcRoot},
		{"absolute path", "/etc/passwd", "", ""},
		{"absolute path with a root known", "/etc/passwd", "", srcRoot},
		{"file uri", "file:///etc/passwd", "", ""},
		{"file uri outside the root", "file:///etc/passwd", "", srcRoot},
		{"file uri that is the root itself", "file:///work/repo", "", srcRoot},
		{"file uri on another host", "file://evil.example/repo/a.py", "", ""},
		{"backslash traversal", `..\..\etc\passwd`, "", ""},
		{"mixed slash traversal", `src\..\..\x.py`, "", ""},
		{"windows drive", `C:\Windows\win.ini`, "", ""},
		{"url-encoded dot dot", "%2e%2e/%2e%2e/etc/passwd", "", ""},
		{"url-encoded slash and dots", "src%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd", "", ""},
		{"url-encoded backslash", "..%5C..%5Cetc%5Cpasswd", "", ""},
		{"invalid percent escape", "%zz/a.py", "", ""},
		{"network path", "//server/share/a.py", "", ""},
		{"http uri", "https://example.com/a.py", "", ""},
		{"opaque uri", "file:a.py", "", ""},
		{"query string", "a.py?x=1", "", ""},
		{"fragment", "a.py#L1", "", ""},
		{"nul byte", "a\x00.py", "", ""},
		{"encoded newline", "a%0A.py", "", ""},
		{"current directory", ".", "", ""},
		{"collapses to the root", "src/..", "", ""},
		{"overlong", strings.Repeat("a/", maxPathBytes), "", ""},
		{"relative base that escapes", "a.py", "UP", `{"UP":{"uri":"../"}}`},
		{"base with a bad scheme", "a.py", "WEB", `{"WEB":{"uri":"https://example.com/"}}`},
		{"base cycle", "a.py", "A", `{"A":{"uri":"x/","uriBaseId":"B"},"B":{"uri":"y/","uriBaseId":"A"}}`},
		{"base with a bad parent", "a.py", "A", `{"A":{"uri":"x/","uriBaseId":"B"},"B":{"uri":"http://x/"}}`},
		{"absolute base outside the root", "a.py", "SYS", `{"%SRCROOT%":{"uri":"file:///work/repo/"},"SYS":{"uri":"file:///usr/include/"}}`},
	}
	for _, tc := range cases {
		findings, stats := parse(t, oneResult(t, tc.uri, tc.base, tc.bases), Options{})
		if len(findings) != 0 || stats.Unsafe != 1 {
			t.Errorf("%s (%q): findings = %v, stats = %+v; want it skipped as unsafe", tc.name, tc.uri, findings, stats)
		}
	}
}

func TestParseKeepsPathsInsideTheProjectAndCleansThem(t *testing.T) {
	cases := []struct{ name, uri, base, bases, root, want string }{
		{"plain", "src/a.py", "", "", "", "src/a.py"},
		{"dot slash", "./src/a.py", "", "", "", "src/a.py"},
		{"harmless dot dot", "src/x/../a.py", "", "", "", "src/a.py"},
		{"backslashes", `src\a.py`, "", "", "", "src/a.py"},
		{"encoded space", "my%20dir/a.py", "", "", "", "my dir/a.py"},
		{"root base", "src/a.py", "%SRCROOT%", srcRoot, "", "src/a.py"},
		{"root base without a definition", "src/a.py", "%SRCROOT%", "", "", "src/a.py"},
		{"undefined base", "src/a.py", "PROJECTROOT", "", "", "src/a.py"},
		{"base with no uri", "src/a.py", "SRCROOT", `{"SRCROOT":{"description":{"text":"root"}}}`, "", "src/a.py"},
		{"absolute file uri under the root", "file:///work/repo/src/a.py", "", srcRoot, "", "src/a.py"},
		{"absolute path under the operator root", "/home/me/proj/src/a.py", "", "", "/home/me/proj", "src/a.py"},
		{"file uri under the operator root", "file:///home/me/proj/a.py", "", "", "/home/me/proj/", "a.py"},
		{"windows drive under the root", `C:\work\repo\a.py`, "", `{"%SRCROOT%":{"uri":"file:///C:/work/repo/"}}`, "", "a.py"},
		{"relative base", "a.py", "SRC", `{"SRC":{"uri":"src/"}}`, "", "src/a.py"},
		{"chained base", "a.py", "PKG", `{"%SRCROOT%":{"uri":"file:///work/repo/"},"PKG":{"uri":"pkg/","uriBaseId":"%SRCROOT%"}}`, "", "pkg/a.py"},
		{"sibling absolute base", "a.py", "BUILD", `{"%SRCROOT%":{"uri":"file:///work/repo/"},"BUILD":{"uri":"file:///work/repo/build/"}}`, "", "build/a.py"},
		{"lone absolute base stands in for the root", "src/a.py", "PROJ", `{"PROJ":{"uri":"file:///elsewhere/proj/"}}`, "", "src/a.py"},
	}
	for _, tc := range cases {
		findings, stats := parse(t, oneResult(t, tc.uri, tc.base, tc.bases), Options{Root: tc.root})
		if len(findings) != 1 || findings[0].Location.File != tc.want {
			t.Errorf("%s: findings = %v, stats = %+v; want %q", tc.name, findings, stats, tc.want)
			continue
		}
		if !finding.SafeRelPath(findings[0].Location.File) {
			t.Errorf("%s: %q is not a safe relative path", tc.name, findings[0].Location.File)
		}
	}
}

func TestARelativeOperatorRootIsIgnored(t *testing.T) {
	_, stats := parse(t, oneResult(t, "/proj/a.py", "", ""), Options{Root: "proj"})
	if stats.Unsafe != 1 {
		t.Errorf("stats = %+v; want the absolute path refused", stats)
	}
}
