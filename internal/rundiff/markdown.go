package rundiff

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// maxListed keeps the summary well inside a pull-request comment's size
	// limit however many findings a run has.
	maxListed = 20
	// maxTextRunes bounds one title or target, which a target controls.
	maxTextRunes = 160
	ellipsis     = "…"
	// markdownSpecials are backslash-escaped so untrusted text stays literal:
	// no markup, links, images, tables, headings, HTML, entities, mentions
	// or autolinked URLs.
	markdownSpecials = "\\`*_[]<>|#!~()@&:"
	absentBefore     = "not reported"
	absentAfter      = "no longer reported"
)

// Markdown renders a short summary suitable for a pull-request comment. It
// lists what changed; findings that merely persist are only counted. Finding
// titles and targets come from the target under test, so all such text is
// escaped.
func (d Diff) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Vajra run comparison\n\nBase %s, head %s.\n\n", escape(d.Base), escape(d.Head))
	fmt.Fprintf(&b, "**%d new**, %d resolved, %d persisting (%d changed status).\n",
		len(d.New), len(d.Resolved), len(d.Persisting), len(d.StatusChanged))
	if n := len(d.Escalated()); n > 0 {
		fmt.Fprintf(&b, "**%d finding(s) became confirmed.**\n", n)
	}
	section(&b, "New", d.New)
	section(&b, "Status changed", d.StatusChanged)
	section(&b, "Resolved", d.Resolved)
	return b.String()
}

func section(b *strings.Builder, title string, changes []Change) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintf(b, "\n#### %s (%d)\n\n", title, len(changes))
	for i, c := range changes {
		if i == maxListed {
			fmt.Fprintf(b, "- and %d more\n", len(changes)-maxListed)
			return
		}
		fmt.Fprintf(b, "- **%s**, was %s, score %d: %s at %s (%s)\n",
			status(c.After, absentAfter), status(c.Before, absentBefore), c.Score,
			escape(c.Finding.Title), escape(c.Finding.Target), escape(c.Finding.ID))
	}
}

func status(s finding.Status, whenAbsent string) string {
	if s == "" {
		return whenAbsent
	}
	return escape(string(s))
}

// escape makes untrusted text safe to place inside a line of Markdown. Line
// breaks and other control characters become spaces so the text cannot start
// a new block; format characters such as bidirectional overrides and
// zero-width spaces are dropped.
func escape(s string) string {
	var b strings.Builder
	for _, r := range truncate(s) {
		switch {
		case unicode.Is(unicode.Cf, r):
			continue
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			b.WriteByte(' ')
		case strings.ContainsRune(markdownSpecials, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func truncate(s string) string {
	runes := []rune(s)
	if len(runes) <= maxTextRunes {
		return s
	}
	return string(runes[:maxTextRunes]) + ellipsis
}
