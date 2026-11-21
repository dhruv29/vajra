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
