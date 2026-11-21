package rundiff

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
)

type scored struct {
	id     string
	status finding.Status
	score  int
}

func run(id string, items ...scored) record.Run {
	r := record.Run{ID: id}
	for _, item := range items {
		r.Report.Findings = append(r.Report.Findings, finding.Finding{
			ID: item.id, Title: "title " + item.id + " in " + id, Target: "https://app.test/" + item.id, Status: item.status,
		})
		r.Radii = append(r.Radii, blast.Radius{FindingID: item.id, Score: item.score})
	}
	return r
}

func ids(changes []Change) string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Finding.ID)
	}
	return strings.Join(out, ",")
}

func TestCompareClassifiesOneFindingByItsStatusInEachRun(t *testing.T) {
	const absent = finding.Status("")
	tests := []struct {
		name         string
		base, head   finding.Status
		wantNew      bool
		wantResolved bool
		wantPersist  bool
		wantChanged  bool
	}{
		{"absent then confirmed is new", absent, finding.Confirmed, true, false, false, false},
		{"absent then unconfirmed is new", absent, finding.Unconfirmed, true, false, false, false},
		{"refuted then confirmed is new", finding.Refuted, finding.Confirmed, true, false, false, false},
		{"out of scope then unconfirmed is new", finding.OutOfScope, finding.Unconfirmed, true, false, false, false},
		{"candidate then confirmed is new", finding.Candidate, finding.Confirmed, true, false, false, false},
		{"confirmed then absent is resolved", finding.Confirmed, absent, false, true, false, false},
		{"confirmed then refuted is resolved", finding.Confirmed, finding.Refuted, false, true, false, false},
		{"unconfirmed then out of scope is resolved", finding.Unconfirmed, finding.OutOfScope, false, true, false, false},
		{"confirmed in both persists", finding.Confirmed, finding.Confirmed, false, false, true, false},
		{"unconfirmed in both persists", finding.Unconfirmed, finding.Unconfirmed, false, false, true, false},
		{"unconfirmed then confirmed persists with a status change", finding.Unconfirmed, finding.Confirmed, false, false, true, true},
		{"confirmed then unconfirmed persists with a status change", finding.Confirmed, finding.Unconfirmed, false, false, true, true},
		{"refuted in both is not a change", finding.Refuted, finding.Refuted, false, false, false, false},
		{"absent then refuted is not a change", absent, finding.Refuted, false, false, false, false},
		{"refuted then absent is not a change", finding.Refuted, absent, false, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, head := run("base"), run("head")
			if tt.base != absent {
				base = run("base", scored{"f1", tt.base, 10})
			}
			if tt.head != absent {
				head = run("head", scored{"f1", tt.head, 20})
			}

			d := Compare(base, head)

			got := []bool{len(d.New) == 1, len(d.Resolved) == 1, len(d.Persisting) == 1, len(d.StatusChanged) == 1}
			want := []bool{tt.wantNew, tt.wantResolved, tt.wantPersist, tt.wantChanged}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("new, resolved, persisting, changed = %v; want %v", got, want)
			}
			if d.HasNew() != tt.wantNew {
				t.Errorf("HasNew = %v; want %v", d.HasNew(), tt.wantNew)
			}
			for _, c := range append(append(append(d.New, d.Resolved...), d.Persisting...), d.StatusChanged...) {
				if c.Before != tt.base || c.After != tt.head {
					t.Errorf("before, after = %q, %q; want %q, %q", c.Before, c.After, tt.base, tt.head)
				}
			}
		})
	}
}

func TestCompareTakesFindingAndScoreFromTheRightRun(t *testing.T) {
	base := run("base", scored{"gone", finding.Confirmed, 31}, scored{"stays", finding.Unconfirmed, 40}, scored{"back", finding.Refuted, 5})
	head := run("head", scored{"stays", finding.Confirmed, 55}, scored{"back", finding.Confirmed, 66}, scored{"gone", finding.Refuted, 99})

	d := Compare(base, head)

	if d.Base != "base" || d.Head != "head" {
		t.Fatalf("run ids = %q, %q", d.Base, d.Head)
	}
	if c := d.Resolved[0]; c.Score != 31 || c.Finding.Title != "title gone in base" || c.Finding.Status != finding.Confirmed {
		t.Errorf("resolved must carry the base version and score: %+v", c)
	}
	if c := d.Persisting[0]; c.Score != 55 || c.Finding.Title != "title stays in head" {
		t.Errorf("persisting must carry the head version and score: %+v", c)
	}
	if c := d.StatusChanged[0]; c.Score != 55 || c.Before != finding.Unconfirmed || c.After != finding.Confirmed {
		t.Errorf("status change = %+v", c)
	}
	if c := d.New[0]; c.Score != 66 || c.Finding.Title != "title back in head" || c.Before != finding.Refuted {
		t.Errorf("new must carry the head version and score: %+v", c)
	}
}

func TestCompareSortsByScoreDescendingThenID(t *testing.T) {
	base := run("base",
		scored{"r-b", finding.Confirmed, 10}, scored{"r-a", finding.Confirmed, 10}, scored{"r-c", finding.Confirmed, 90},
		scored{"p-b", finding.Unconfirmed, 0}, scored{"p-a", finding.Unconfirmed, 0}, scored{"p-c", finding.Unconfirmed, 0})
	head := run("head",
		scored{"n-b", finding.Confirmed, 50}, scored{"n-a", finding.Confirmed, 50}, scored{"n-c", finding.Unconfirmed, 70},
		scored{"p-b", finding.Confirmed, 20}, scored{"p-a", finding.Confirmed, 20}, scored{"p-c", finding.Confirmed, 80})

	d := Compare(base, head)

	for name, pair := range map[string][2]string{
		"new":            {ids(d.New), "n-c,n-a,n-b"},
		"resolved":       {ids(d.Resolved), "r-c,r-a,r-b"},
		"persisting":     {ids(d.Persisting), "p-c,p-a,p-b"},
		"status changed": {ids(d.StatusChanged), "p-c,p-a,p-b"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s order = %s; want %s", name, pair[0], pair[1])
		}
	}
}

func TestCompareScoresZeroWithoutARadiusAndIgnoresRepeatedIDs(t *testing.T) {
	head := record.Run{ID: "head", Report: record.Report{Findings: []finding.Finding{
		{ID: "f1", Status: finding.Confirmed}, {ID: "f1", Status: finding.Unconfirmed},
	}}}

	d := Compare(record.Run{ID: "base"}, head)

	if len(d.New) != 1 || d.New[0].Score != 0 || d.New[0].After != finding.Confirmed {
		t.Fatalf("new = %+v; want the first f1 once with score 0", d.New)
	}
}

func TestCompareOfEmptyRunsGivesEmptyNonNilLists(t *testing.T) {
	d := Compare(record.Run{}, record.Run{})

	if d.New == nil || d.Resolved == nil || d.Persisting == nil || d.StatusChanged == nil {
		t.Fatalf("lists must be non-nil: %+v", d)
	}
	if d.HasNew() {
		t.Error("HasNew on an empty diff")
	}
	raw, err := json.Marshal(d)
	const want = `{"base":"","head":"","new":[],"resolved":[],"persisting":[],"status_changed":[]}`
	if err != nil || string(raw) != want {
		t.Fatalf("json = %s, err = %v; want %s", raw, err, want)
	}
}

func TestCompareDoesNotModifyTheRuns(t *testing.T) {
	base := run("base", scored{"b", finding.Confirmed, 1}, scored{"a", finding.Confirmed, 9})
	head := run("head", scored{"z", finding.Confirmed, 1}, scored{"y", finding.Confirmed, 9})

	Compare(base, head)

	if base.Report.Findings[0].ID != "b" || head.Report.Findings[0].ID != "z" {
		t.Fatal("Compare reordered a run's findings")
	}
}

func TestMarkdownSummarisesWhatChanged(t *testing.T) {
	base := run("20261120-010101-aaaaaaaa", scored{"gone", finding.Confirmed, 31}, scored{"stays", finding.Unconfirmed, 40}, scored{"same", finding.Confirmed, 12})
	head := run("20261121-010101-bbbbbbbb", scored{"fresh", finding.Confirmed, 72}, scored{"stays", finding.Confirmed, 55}, scored{"same", finding.Confirmed, 12})

	got := Compare(base, head).Markdown()

	for _, want := range []string{
		"Base 20261120-010101-aaaaaaaa, head 20261121-010101-bbbbbbbb.",
		"**1 new**, 1 resolved, 2 persisting (1 changed status).",
		"#### New (1)", "- **confirmed**, was not reported, score 72: title fresh in 20261121-010101-bbbbbbbb at https://app.test/fresh (fresh)",
		"#### Status changed (1)", "- **confirmed**, was unconfirmed, score 55: title stays",
		"#### Resolved (1)", "- **no longer reported**, was confirmed, score 31: title gone in 20261120-010101-aaaaaaaa",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "title same") {
		t.Errorf("an unchanged finding must only be counted:\n%s", got)
	}
}

func TestMarkdownOfAnEmptyDiffHasNoSections(t *testing.T) {
	got := Compare(record.Run{ID: "a"}, record.Run{ID: "b"}).Markdown()

	if !strings.Contains(got, "**0 new**, 0 resolved, 0 persisting (0 changed status).") || strings.Contains(got, "####") {
		t.Fatalf("markdown = %s", got)
	}
}

func TestMarkdownEscapesUntrustedText(t *testing.T) {
	hostile := finding.Finding{
		ID:     "id|<b>",
		Title:  "x</td><script>alert(1)</script>\r\n# Owned\n- [click](http://evil.test) ![i](http://evil.test/p.png) **b** _i_ `c` ~s~ @org/team &lt;",
		Target: "https://app.test/?q=<img src=x onerror=alert(1)>|a\u2028b\\",
		Status: finding.Confirmed,
	}
	// A status this package does not know never needs attention, so it
	// cannot reach the comment however it is spelt.
	ignored := finding.Finding{ID: "ignored", Title: "<i>ignored</i>", Status: "confirmed\n\n# status"}
	head := record.Run{ID: "head\n<h1>", Report: record.Report{Findings: []finding.Finding{hostile, ignored}}}

	got := Compare(record.Run{ID: "base"}, head).Markdown()

	for _, want := range []string{
		`x\</td\>\<script\>alert\(1\)\</script\>  \# Owned - \[click\]\(http://evil.test\) \!\[i\]\(http://evil.test/p.png\) \*\*b\*\* \_i\_ ` + "\\`c\\` \\~s\\~ \\@org/team \\&lt;",
		`(id\|\<b\>)`,
		`https://app.test/?q=\<img src=x onerror=alert\(1\)\>\|a b\\`,
		`Base base, head head \<h1\>.`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown lacks %q:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "\n- "); n != 1 {
		t.Errorf("want exactly one list item, got %d:\n%s", n, got)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "# ") || strings.Contains(unescaped(line), "<") {
			t.Errorf("injected markup survived in line %q", line)
		}
	}
}

// unescaped removes every backslash-escaped character, leaving only what a
// Markdown renderer would treat as live syntax.
func unescaped(line string) string {
	var b strings.Builder
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' {
			i++
			continue
		}
		b.WriteRune(runes[i])
	}
	return b.String()
}

func TestEscapeNeutralisesEachSpecialCharacter(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain text is untouched", "SQL injection in /search", "SQL injection in /search"},
		{"backslash", `a\b`, `a\\b`},
		{"backtick", "a`b", "a\\`b"},
		{"emphasis", "*a* _b_", `\*a\* \_b\_`},
		{"link", "[a](b)", `\[a\]\(b\)`},
		{"html", "<b>", `\<b\>`},
		{"table cell", "a|b", `a\|b`},
		{"heading and image", "# !", `\# \!`},
		{"mention and entity", "@a &amp;", `\@a \&amp;`},
		{"newlines become spaces", "a\nb\r\nc\td", "a b  c d"},
		{"unicode line separators become spaces", "a\u2028b\u2029c\u0085d", "a b c d"},
		{"long text is cut", strings.Repeat("é", maxTextRunes+5), strings.Repeat("é", maxTextRunes) + ellipsis},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escape(tt.in); got != tt.want {
				t.Fatalf("escape(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMarkdownCapsLongLists(t *testing.T) {
	items := make([]scored, 0, maxListed+3)
	for i := 0; i < maxListed+3; i++ {
		items = append(items, scored{fmt.Sprintf("f%02d", i), finding.Confirmed, 1})
	}

	got := Compare(run("base"), run("head", items...)).Markdown()

	if !strings.Contains(got, "#### New (23)") || !strings.Contains(got, "- and 3 more\n") || strings.Count(got, "\n- ") != maxListed+1 {
		t.Fatalf("markdown = %s", got)
	}
}
