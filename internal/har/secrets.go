package har

import (
	"net/url"
	"strings"

	"github.com/dhruv29/vajra/internal/redact"
)

const (
	// maxSecrets bounds how many distinct credential spellings are remembered
	// for the final scrub, which keeps the scrub fast on a hostile file. A
	// recording with more than this is refused outright: scrubbing only the
	// first ones would let the later credentials through.
	maxSecrets = 8192
	// minSecretLength matches the shortest value redact.Values scrubs on its
	// own; shorter values would only erase ordinary text.
	minSecretLength = 8
	// maxHeaderVerdicts bounds the cache of header-name decisions.
	maxHeaderVerdicts = 512
)

// secretNameParts mark a parameter or header name as carrying a credential.
// Matching is by substring and deliberately broad: wrongly emptying a value
// costs a scanner one parameter, wrongly keeping one leaks a credential.
var secretNameParts = []string{
	"token", "key", "sess", "pass", "pwd", "secret", "sig", "code", "auth",
	"cred", "jwt", "otp", "nonce", "sid", "cookie", "saml", "ticket", "csrf", "xsrf", "bearer",
}

// looksSecret reports whether a parameter or header name looks like it
// carries a credential.
func looksSecret(name string) bool {
	lower := strings.ToLower(name)
	for _, part := range secretNameParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// secretSet remembers credential values seen anywhere in the recording. It is
// only ever used to scrub what is kept; it is never returned.
type secretSet struct {
	values map[string]struct{}
	// overflowed is set when a credential could not be remembered.
	overflowed bool
	verdicts   map[string]bool // lower-cased header name -> sensitive
}

func newSecretSet() *secretSet {
	return &secretSet{values: map[string]struct{}{}, verdicts: map[string]bool{}}
}

// add remembers a credential value, line by line so that no remembered value
// contains a newline, together with its percent-encoded spellings, because
// what it is scrubbed from is held encoded.
func (s *secretSet) add(value string) {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > maxURLLength {
			continue // could not appear inside anything that is kept
		}
		s.remember(line)
		for _, part := range strings.FieldsFunc(line, isSecretSeparator) {
			s.remember(part)
		}
	}
}

// isSecretSeparator splits values the way redact.Values splits them, so that
// the encoded spelling of each part is remembered too.
func isSecretSeparator(r rune) bool {
	return r == ' ' || r == ';' || r == '=' || r == ','
}

func (s *secretSet) remember(value string) {
	if len(value) < minSecretLength {
		return
	}
	for _, spelling := range []string{value, url.QueryEscape(value), url.PathEscape(value)} {
		if _, known := s.values[spelling]; known {
			continue
		}
		if len(s.values) >= maxSecrets {
			s.overflowed = true
			return
		}
		s.values[spelling] = struct{}{}
	}
}

func (s *secretSet) list() []string {
	out := make([]string, 0, len(s.values))
	for value := range s.values {
		out = append(out, value)
	}
	return out
}

// addHeaders remembers the values of credential headers and cookies, and
// reports whether the request carried any. HTTP/2 pseudo-headers such as
// ":path" are skipped: the URL already holds what they say.
func (s *secretSet) addHeaders(headers, cookies []nameValue) bool {
	authenticated := false
	for _, h := range headers {
		name := strings.TrimSpace(h.Name)
		if name == "" || strings.HasPrefix(name, ":") || strings.TrimSpace(h.Value) == "" {
			continue
		}
		if s.sensitiveHeader(name) {
			authenticated = true
			s.add(h.Value)
		}
	}
	for _, c := range cookies {
		if strings.TrimSpace(c.Value) != "" {
			authenticated = true
			s.add(c.Value)
		}
	}
	return authenticated
}

// sensitiveHeader reports whether a header carries a credential, either by
// internal/redact's own list or because its name looks like a secret.
func (s *secretSet) sensitiveHeader(name string) bool {
	if len(name) > maxNameLength || looksSecret(name) {
		return true
	}
	lower := strings.ToLower(name)
	if verdict, ok := s.verdicts[lower]; ok {
		return verdict
	}
	verdict := redactTreatsAsSecret(name)
	if len(s.verdicts) < maxHeaderVerdicts {
		s.verdicts[lower] = verdict
	}
	return verdict
}

// redactTreatsAsSecret asks internal/redact whether it would hide the value
// of a header with this name, so that this package never keeps a header that
// redact considers a credential, whatever redact's list grows to hold.
func redactTreatsAsSecret(name string) bool {
	line := name + ": probe"
	return redact.Headers(line) != line
}
