package inject

import (
	"net/url"
	"slices"
	"strings"
)

// target is one parameter of one endpoint: the unit of work. However many
// URLs differ only in parameter values, each (host, path, parameter) is
// tested once.
type target struct {
	// original is the URL the parameter was found on (the first, in sorted
	// order, of all URLs that share the host, path and parameter).
	original string
	host     string
	path     string
	param    string
	// value is the parameter's value in original.
	value string
}

func (t target) key() string {
	return t.host + "\x00" + t.path + "\x00" + t.param
}

// with returns original with the parameter set to value. Only that one
// parameter is rewritten; every other piece of the query is kept byte for
// byte, so the application sees exactly what the page linked to.
func (t target) with(value string) string {
	u, err := url.Parse(t.original)
	if err != nil {
		return "" // unreachable: original was parsed when the target was made
	}
	u.Fragment, u.RawFragment = "", ""
	pieces := strings.Split(u.RawQuery, "&")
	for i, piece := range pieces {
		if name, ok := pieceName(piece); ok && name == t.param {
			pieces[i] = url.QueryEscape(t.param) + "=" + url.QueryEscape(value)
			break
		}
	}
	u.RawQuery = strings.Join(pieces, "&")
	return u.String()
}

// param is one decoded query parameter.
type param struct{ name, value string }

// pieceName decodes the name of one "name=value" piece of a raw query.
func pieceName(piece string) (string, bool) {
	rawName, _, _ := strings.Cut(piece, "=")
	name, err := url.QueryUnescape(rawName)
	return name, err == nil && strings.TrimSpace(name) != ""
}

// params returns the first occurrence of each parameter, in query order.
// Pieces that do not decode are left alone rather than guessed at.
func params(rawQuery string) []param {
	var out []param
	seen := map[string]bool{}
	for _, piece := range strings.Split(rawQuery, "&") {
		name, ok := pieceName(piece)
		if !ok || seen[name] {
			continue
		}
		_, rawValue, _ := strings.Cut(piece, "=")
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			continue
		}
		seen[name] = true
		out = append(out, param{name: name, value: value})
	}
	return out
}

// testable parses a URL and reports whether it may be tested at all: http(s)
// with a host and no credentials (the probe refuses those, and they would be
// written into evidence).
func testable(raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return nil, false
	}
	return u, true
}

// targets turns the input URLs into distinct targets, sorted, and lists the
// URLs it refused. The input is sorted first so that which URL represents a
// target does not depend on the order the caller found them in.
func (c *Checker) targets(urls []string) ([]target, []string) {
	sorted := slices.Compact(slices.Sorted(slices.Values(urls)))
	skipped := []string{}
	seen := map[string]bool{}
	var out []target
	for _, raw := range sorted {
		u, ok := testable(raw)
		if !ok || !c.inScope(raw) || changesState(u) {
			skipped = append(skipped, raw)
			continue
		}
		for _, p := range params(u.RawQuery) {
			t := target{original: strings.TrimSpace(raw), host: strings.ToLower(u.Host), path: u.Path, param: p.name, value: p.value}
			if !seen[t.key()] {
				seen[t.key()] = true
				out = append(out, t)
			}
		}
	}
	slices.SortFunc(out, func(a, b target) int { return strings.Compare(a.key(), b.key()) })
	return out, skipped
}

// stateChangingWords name actions a GET to a badly designed application may
// still perform. Each check re-sends the URL with the operator's session, so a
// URL that may log out or destroy something is not tested at all.
var stateChangingWords = []string{
	"logout", "log-out", "signout", "sign-out", "logoff", "delete", "remove", "destroy",
	"revoke", "unsubscribe", "deactivate", "disable", "reset", "purge", "cancel",
}

// changesState reports whether any path segment, parameter name or value
// contains one of stateChangingWords as whole words, so "user_delete" matches
// but "presets" does not match "reset".
func changesState(u *url.URL) bool {
	parts := strings.Split(u.Path, "/")
	for _, p := range params(u.RawQuery) {
		parts = append(parts, p.name, p.value)
	}
	return slices.ContainsFunc(parts, func(part string) bool {
		padded := "-" + words(part) + "-"
		return slices.ContainsFunc(stateChangingWords, func(word string) bool {
			return strings.Contains(padded, "-"+words(word)+"-")
		})
	})
}

// words lower-cases text and writes every word separator as "-".
func words(text string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune("-_.+~ ", r) {
			return '-'
		}
		return r
	}, strings.ToLower(text))
}
