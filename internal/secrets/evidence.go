package secrets

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// maskPrefixChars is how much of a secret stays readable: enough to tell
	// which credential it is, not enough to use it.
	maskPrefixChars = 4
	// contextLines is how many lines are shown on each side of a finding.
	contextLines = 3
	// maxLineChars keeps one minified line from filling the evidence.
	maxLineChars = 300
)

// mask returns the form of a secret that is safe to store and show: its first
// characters and a count of the rest. A value no longer than the prefix is
// hidden completely.
func mask(value string) string {
	chars := utf8.RuneCountInString(value)
	if chars <= maskPrefixChars {
		return fmt.Sprintf("…[masked %d chars]", chars)
	}
	prefix := string([]rune(value)[:maskPrefixChars])
	return fmt.Sprintf("%s…[masked %d chars]", prefix, chars-maskPrefixChars)
}

// maskSpans returns text with each span replaced by its masked form.
// Overlapping spans are masked as one, so no part of either is left behind.
func maskSpans(text string, spans []span) string {
	if len(spans) == 0 {
		return text
	}
	sorted := slices.Clone(spans)
	slices.SortFunc(sorted, func(a, b span) int { return cmp.Compare(a.start, b.start) })

	var b strings.Builder
	pos := 0
	for i := 0; i < len(sorted); {
		merged := sorted[i]
		for i++; i < len(sorted) && sorted[i].start <= merged.end; i++ {
			merged.end = max(merged.end, sorted[i].end)
		}
		b.WriteString(text[pos:merged.start])
		b.WriteString(mask(text[merged.start:merged.end]))
		pos = merged.end
	}
	b.WriteString(text[pos:])
	return b.String()
}

// maskWhole masks everything on a line except its indentation. It is used for
// the body of a private key, where the whole line is secret.
func maskWhole(text string) string {
	content := strings.TrimSpace(text)
	if content == "" {
		return text
	}
	return strings.Replace(text, content, mask(content), 1)
}

// renderContext returns the already-masked lines around a finding, numbered,
// with the reported line marked.
func renderContext(masked []string, line int) string {
	first, last := max(1, line-contextLines), min(len(masked), line+contextLines)
	var b strings.Builder
	for n := first; n <= last; n++ {
		marker := " "
		if n == line {
			marker = ">"
		}
		fmt.Fprintf(&b, "%s %5d | %s\n", marker, n, truncate(masked[n-1]))
	}
	return b.String()
}

// truncate shortens a long line without cutting a character in half.
func truncate(text string) string {
	if len(text) <= maxLineChars {
		return text
	}
	cut := maxLineChars
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + " [line truncated]"
}
