package har

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/dhruv29/vajra/internal/scope"
)

const (
	// maxURLLength bounds a URL. Real ones, even with long query strings, fit
	// comfortably; a longer one is counted as malformed.
	maxURLLength = 8192
	// maxNameLength bounds a parameter name. A longer "name" is usually a
	// value in the wrong place, such as a bare token, so it is dropped.
	maxNameLength = 128
	// maxParams bounds how many parameters are read from one query or body.
	maxParams = 64
)

var defaultPorts = map[string]uint16{"http": 80, "https": 443}

// dropReason says why an entry was not kept.
type dropReason int

const (
	keep dropReason = iota
	outOfScope
	unsupportedScheme
	malformed
)

// pair is one parameter. In target.query both halves are percent-encoded.
type pair struct {
	name, value string
}

// target is a URL that passed the scheme, shape and scope checks.
type target struct {
	origin      string // scheme://host[:port], no user information
	escapedPath string
	decodedPath string
	query       []pair
	namesAction bool
}

// parseTarget checks a recorded URL and returns its kept parts. Secret query
// values are handed to secrets before the scope check, so that they are
// scrubbed elsewhere even when this entry is dropped.
func parseTarget(raw string, policy *scope.Policy, secrets *secretSet) (target, dropReason) {
	raw = strings.TrimSpace(raw)
	if reason := checkScheme(raw); reason != keep {
		return target{}, reason
	}
	if len(raw) > maxURLLength {
		return target{}, malformed
	}
	u, err := url.Parse(raw)
	if err != nil {
		return target{}, malformed
	}
	scheme := strings.ToLower(u.Scheme)
	host, port, ok := hostPort(u, scheme)
	if !ok {
		return target{}, malformed
	}
	query, queryParts := parseQuery(u.RawQuery, secrets)
	if policy.CheckTarget(host, port) != nil {
		return target{}, outOfScope
	}
	t := target{
		origin:      origin(scheme, host, port),
		escapedPath: canonicalPath(u.Path),
		decodedPath: u.Path,
		query:       query,
	}
	if t.escapedPath == "" {
		t.escapedPath, t.decodedPath = "/", "/"
	}
	t.namesAction = namesAction(t.decodedPath, queryParts)
	return t, keep
}

// checkScheme looks only at the text before the first colon, so a huge
// data: URL is recognised as an unsupported scheme without being parsed.
func checkScheme(raw string) dropReason {
	scheme, _, found := strings.Cut(raw, ":")
	if !found || !validScheme(scheme) {
		return malformed
	}
	if _, web := defaultPorts[strings.ToLower(scheme)]; !web {
		return unsupportedScheme
	}
	return keep
}

// validScheme follows RFC 3986: a letter, then letters, digits, "+", "-", ".".
func validScheme(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isOther := (r >= '0' && r <= '9') || r == '+' || r == '-' || r == '.'
		if !isLetter && (i == 0 || !isOther) {
			return false
		}
	}
	return true
}

// hostPort returns the normalised host and the port, defaulting by scheme.
func hostPort(u *url.URL, scheme string) (string, uint16, bool) {
	host := scope.NormalizeHost(u.Hostname())
	if host == "" {
		return "", 0, false
	}
	portText := u.Port()
	if portText == "" {
		return host, defaultPorts[scheme], true
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, false
	}
	return host, uint16(port), true
}

// origin writes scheme, host and port the one way they are compared and
// returned: IPv6 literals in brackets, the default port left out.
func origin(scheme, host string, port uint16) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != defaultPorts[scheme] {
		host += ":" + strconv.Itoa(int(port))
	}
	return scheme + "://" + host
}

// parseQuery returns the query parameters percent-encoded and sorted by
// name, with the values of secret-looking names emptied, together with every
// decoded name and value for the state-changing check.
func parseQuery(rawQuery string, secrets *secretSet) ([]pair, []string) {
	decoded := splitPairs(rawQuery)
	pairs := make([]pair, 0, len(decoded))
	parts := make([]string, 0, 2*len(decoded))
	for _, p := range decoded {
		parts = append(parts, p.name, p.value)
		value := p.value
		if looksSecret(p.name) {
			secrets.add(value)
			value = ""
		}
		pairs = append(pairs, pair{name: url.QueryEscape(p.name), value: url.QueryEscape(value)})
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
	return pairs, parts
}

// splitPairs decodes "a=1&b=2" text. A piece that does not decode, has an
// empty or overlong name, or comes after maxParams is dropped: dropping can
// only lose a parameter, never leak one.
func splitPairs(raw string) []pair {
	var out []pair
	for _, piece := range strings.Split(raw, "&") {
		if len(out) >= maxParams {
			break
		}
		rawName, rawValue, _ := strings.Cut(piece, "=")
		name, nameErr := url.QueryUnescape(rawName)
		value, valueErr := url.QueryUnescape(rawValue)
		if nameErr != nil || valueErr != nil || !validParamName(name) {
			continue
		}
		out = append(out, pair{name: name, value: value})
	}
	return out
}

func validParamName(name string) bool {
	return strings.TrimSpace(name) != "" && len(name) <= maxNameLength
}

// canonicalPath re-escapes a decoded path one segment at a time. A recording
// can spell the same path many ways ("%2f" or "%2F", "%61" for "a"); the
// credential scrub compares exact text, so it needs the one spelling that the
// remembered credentials were also written in.
func canonicalPath(decoded string) string {
	segments := strings.Split(decoded, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}
