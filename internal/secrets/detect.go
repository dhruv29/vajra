package secrets

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// ignoreMarker on a line tells the scanner that a person has looked at it.
	ignoreMarker = "vajra:ignore-secret"

	// minEntropy is the Shannon entropy, in bits per byte, that a generic
	// value must exceed. Words and simple patterns fall below it; random keys
	// and most real passwords are above it.
	minEntropy = 3.0

	// pemEndMarker starts the last line of a PEM block.
	pemEndMarker = "-----END"
	// maxKeyBodyLines bounds how far a private key header masks the lines
	// after it: up to the end line, or this many lines when none follows. It
	// is far above any real key (a 4096-bit RSA key is about 50 lines, an
	// 8192-bit one or a PGP block with subkeys over 100), so no tail is shown.
	maxKeyBodyLines = 4096

	// maxFindingsPerFile and maxFindingsPerScan bound the output. A generated
	// or hostile file of key-shaped lines would otherwise yield tens of
	// thousands of findings, each with its own context.
	maxFindingsPerFile = 200
	maxFindingsPerScan = 5_000
)

// placeholderWords mark a value as documentation or a reference to where the
// secret really lives, not a secret. They are compared in lower case.
var placeholderWords = []string{
	"example", "changeme", "change-me", "placeholder", "your_", "yourkey",
	"xxxx", "dummy", "test", "sample", "redacted", "%s",
	"os.environ", "process.env", "getenv",
}

// templatePattern matches <name>, ${name} and {{name}} substitutions.
var templatePattern = regexp.MustCompile(`<[^<>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}`)

// span is a half-open byte range in a line. tagged says it starts with a
// provider's public tag, which may stay readable when it is masked.
type span struct {
	start, end int
	tagged     bool
}

// mask returns the masked form of the span's part of text.
func (s span) mask(text string) string {
	if s.tagged {
		return maskTagged(text[s.start:s.end])
	}
	return mask(text[s.start:s.end])
}

func (s span) overlaps(other span) bool {
	return s.start < other.end && other.start < s.end
}

// hit is one rule matching one line. It carries the masked value only, so the
// secret does not travel further than the line it was read from.
type hit struct {
	rule   *rule
	line   int
	masked string
}

// matchLine returns the rules that match text, at most once each, and every
// span that must be masked before the line is shown to anyone.
func matchLine(text string) (hits []hit, masks []span) {
	for i := range providerRules {
		r := &providerRules[i]
		for n, value := range r.values(text) {
			masks = append(masks, value)
			if n == 0 {
				hits = append(hits, hit{rule: r, masked: value.mask(text)})
			}
		}
	}
	providerSpans := masks[:len(masks):len(masks)]
	reported := false
	for _, value := range genericRule.values(text) {
		// A provider rule says more about the same secret, so it wins. The
		// whole quoted value is still masked.
		claimed := slices.ContainsFunc(providerSpans, value.overlaps)
		if !claimed && !looksSecret(text[value.start:value.end]) {
			continue
		}
		masks = append(masks, value)
		if !claimed && !reported {
			hits = append(hits, hit{rule: &genericRule, masked: value.mask(text)})
			reported = true
		}
	}
	return hits, append(masks, assignedValues(text)...)
}

// assignedValues returns the value of every credential-like assignment on the
// line, whether or not a rule reports it, so that context lines never show a
// password the entropy or placeholder checks let through.
func assignedValues(text string) []span {
	var out []span
	for _, loc := range credentialAssignment.FindAllStringSubmatchIndex(text, -1) {
		for group := 2; group+1 < len(loc); group += 2 {
			if loc[group] >= 0 {
				out = append(out, span{start: loc[group], end: loc[group+1]})
				break
			}
		}
	}
	return out
}

// looksSecret applies the checks that keep the generic rule from reporting
// documentation, templates and trivial values.
func looksSecret(value string) bool {
	return !isPlaceholder(value) && shannonEntropy(value) > minEntropy
}

func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, word := range placeholderWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	first, _ := utf8.DecodeRuneInString(value)
	isOneRepeatedChar := strings.TrimFunc(value, func(c rune) bool { return c == first }) == ""
	return isOneRepeatedChar || templatePattern.MatchString(value)
}

// shannonEntropy returns the entropy of value in bits per byte.
func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(len(value))
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// analyse scans the lines of one file. Every line is masked, including lines
// with the ignore marker and the body of a private key, because any of them
// can end up in the context shown for a finding on a nearby line.
func analyse(file string, lines []string) []finding.Finding {
	masked := make([]string, len(lines))
	var hits []hit
	keyBodyLeft := 0
	for i, text := range lines {
		lineHits, masks := matchLine(text)
		if keyBodyLeft > 0 && !strings.Contains(text, pemEndMarker) {
			masked[i] = maskWhole(text)
			keyBodyLeft--
		} else {
			masked[i] = maskSpans(text, masks)
			keyBodyLeft = 0
		}
		if opensKeyBlock(text, lineHits) {
			keyBodyLeft = maxKeyBodyLines
		}
		if strings.Contains(text, ignoreMarker) {
			continue
		}
		for _, h := range lineHits {
			h.line = i + 1
			hits = append(hits, h)
		}
	}
	hits = hits[:min(len(hits), maxFindingsPerFile)]
	findings := make([]finding.Finding, 0, len(hits))
	for _, h := range hits {
		findings = append(findings, h.toFinding(file, renderContext(masked, h.line)))
	}
	return findings
}

// opensKeyBlock reports whether a private key starts on this line and
// continues on the lines below it.
func opensKeyBlock(text string, hits []hit) bool {
	isKeyHeader := slices.ContainsFunc(hits, func(h hit) bool { return h.rule.id == privateKeyRuleID })
	return isKeyHeader && !strings.Contains(text, pemEndMarker)
}

func (h hit) toFinding(file, code string) finding.Finding {
	target := fmt.Sprintf("%s:%d", file, h.line)
	return finding.Finding{
		ID:          finding.StableID(Source, h.rule.id, target, ""),
		Kind:        finding.Static,
		Source:      Source,
		RuleID:      h.rule.id,
		Title:       h.rule.title,
		Description: h.rule.description,
		Severity:    h.rule.severity,
		Target:      target,
		Location:    &finding.Location{File: file, Line: h.line, EndLine: h.line},
		Tags:        []string{tagSecrets},
		CWE:         []string{cweHardCodedCredentials},
		Status:      finding.Candidate,
		Evidence: finding.Evidence{
			Code:      code,
			Extracted: []string{h.masked},
		},
	}
}
