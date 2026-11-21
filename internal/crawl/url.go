package crawl

import (
	"net/url"
	"path"
	"slices"
	"strings"
)

var defaultPorts = map[string]string{"http": "80", "https": "443"}

// staticExtensions are file types that are never worth fetching in a crawl:
// they hold no links and no endpoints, only bytes.
var staticExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".css": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".pdf": true, ".zip": true, ".gz": true,
}

// stateChangingWords name actions a GET to a badly designed application may
// still perform. A link whose path segment or query key or value is one of
// them is not fetched: with the operator's session it could log them out or
// destroy data in the application under test.
var stateChangingWords = []string{
	"logout", "log-out", "signout", "sign-out", "logoff", "delete", "remove", "destroy",
	"revoke", "unsubscribe", "deactivate", "disable", "reset", "purge", "cancel",
}

// wordSeparators split the words of a segment, key or value, so that
// "user_delete" and "logout.php" match but "presets" does not match "reset".
const wordSeparators = "-_.+~ "

// changesState reports whether a normalised URL looks like it triggers one of
// stateChangingWords.
func changesState(normalised string) bool {
	parsed, err := url.Parse(normalised)
	if err != nil {
		return false
	}
	parts := strings.Split(parsed.Path, "/")
	query, _ := url.ParseQuery(parsed.RawQuery) // what parses is still checked
	for key, values := range query {
		parts = append(parts, key)
		parts = append(parts, values...)
	}
	return slices.ContainsFunc(parts, namesStateChange)
}

// namesStateChange reports whether one part of a URL contains a
// stateChangingWords entry as whole words.
func namesStateChange(part string) bool {
	padded := "-" + words(part) + "-"
	return slices.ContainsFunc(stateChangingWords, func(word string) bool {
		return strings.Contains(padded, "-"+words(word)+"-")
	})
}

// words lower-cases text and writes every separator as "-".
func words(text string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(wordSeparators, r) {
			return '-'
		}
		return r
	}, strings.ToLower(text))
}

// normalise gives a URL the one spelling used to recognise it again: lower
// case scheme and host, no fragment, no default port, "/" for an empty path
// and query parameters in sorted order. It reports false for anything that is
// not an http(s) URL with a host.
func normalise(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	scheme, host := strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Hostname())
	if (scheme != "http" && scheme != "https") || host == "" {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // an IPv6 literal
	}
	if port := parsed.Port(); port != "" && port != defaultPorts[scheme] {
		host += ":" + port
	}
	out := url.URL{
		Scheme: scheme, User: parsed.User, Host: host,
		Path: parsed.Path, RawPath: parsed.RawPath, RawQuery: sortQuery(parsed.RawQuery),
	}
	if out.Path == "" {
		out.Path = "/"
	}
	return out.String(), true
}

// sortQuery orders the parameters of a query string. The pieces are moved,
// never re-encoded, so the application receives exactly the bytes the page
// linked to.
func sortQuery(rawQuery string) string {
	parts := slices.DeleteFunc(strings.Split(rawQuery, "&"), func(part string) bool { return part == "" })
	slices.SortStableFunc(parts, func(a, b string) int {
		nameA, _, _ := strings.Cut(a, "=")
		nameB, _, _ := strings.Cut(b, "=")
		return strings.Compare(nameA, nameB)
	})
	return strings.Join(parts, "&")
}

// isStaticAsset reports whether the path of a normalised URL ends in a
// static-asset extension.
func isStaticAsset(normalised string) bool {
	parsed, err := url.Parse(normalised)
	if err != nil {
		return false
	}
	return staticExtensions[strings.ToLower(path.Ext(parsed.Path))]
}

// resolve turns an attribute or header value into an absolute http(s) URL, or
// "" when it is not one (mailto:, javascript:, tel:, data:, a bare fragment,
// or something that does not parse).
func resolve(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return ""
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	absolute := base.ResolveReference(reference)
	if (absolute.Scheme != "http" && absolute.Scheme != "https") || absolute.Host == "" {
		return ""
	}
	return absolute.String()
}
