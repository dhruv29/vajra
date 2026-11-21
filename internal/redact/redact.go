// Package redact removes credentials from text before it is stored, shown or
// sent to a model.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Placeholder replaces a removed value.
const Placeholder = "[redacted]"

// alwaysSecret are headers that carry credentials whatever the configuration.
var alwaysSecret = []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token"}

// Headers replaces the value of every credential-bearing header line in a
// captured HTTP message. extra names more headers to treat as secret, such as
// the ones the operator configured for test accounts. Matching ignores case.
func Headers(message string, extra ...string) string {
	if message == "" {
		return message
	}
	names := make([]string, 0, len(alwaysSecret)+len(extra))
	for _, name := range append(append([]string{}, alwaysSecret...), extra...) {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, regexp.QuoteMeta(name))
		}
	}
	// (?im): case-insensitive, and ^ $ match at line boundaries. The header
	// name is kept; everything after the colon on that line is replaced.
	pattern := regexp.MustCompile(`(?im)^(` + strings.Join(names, "|") + `)[ \t]*:.*?(\r?)$`)
	return pattern.ReplaceAllString(message, "${1}: "+Placeholder+"${2}")
}

// minSecretPart is the shortest fragment of a credential that is scrubbed on
// its own. Shorter fragments (such as the word "Bearer") would erase ordinary
// text.
const minSecretPart = 8

// Values replaces every occurrence of each secret in text, wherever it
// appears. Header-name redaction misses a credential that a target echoes
// back in a response body, a URL or an error; this does not. A secret made of
// several words, such as "Bearer abc123def", is also scrubbed part by part.
func Values(text string, secrets ...string) string {
	if text == "" {
		return text
	}
	for _, secret := range expand(secrets) {
		text = strings.ReplaceAll(text, secret, Placeholder)
	}
	return text
}

// expand returns the secrets and their long-enough parts, longest first, so
// that a whole value is replaced before any fragment of it.
func expand(secrets []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); len(s) >= minSecretPart && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, secret := range secrets {
		add(secret)
		for _, part := range strings.FieldsFunc(secret, func(r rune) bool { return r == ' ' || r == ';' || r == '=' || r == ',' }) {
			add(part)
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}
