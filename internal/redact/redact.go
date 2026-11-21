// Package redact removes credentials from text before it is stored, shown or
// sent to a model.
package redact

import (
	"regexp"
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
