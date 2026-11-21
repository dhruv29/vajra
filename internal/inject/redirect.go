package inject

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/dhruv29/vajra/internal/probe"
)

// canaryDomain is the parent of every canary host. The .invalid top-level
// domain is reserved (RFC 2606) and can never resolve, and the egress gate
// would refuse it anyway; the probe never follows redirects in the first
// place.
const canaryDomain = "vajra-canary.invalid"

// redirectNames are parameter names that commonly carry a redirect target,
// lower case and without separators ("return_to" and "returnTo" both become
// "returnto").
var redirectNames = map[string]bool{
	"next": true, "url": true, "redirect": true, "redirecturl": true, "redirecturi": true,
	"redir": true, "return": true, "returnto": true, "returnurl": true, "returnpath": true,
	"continue": true, "dest": true, "destination": true, "goto": true, "target": true,
	"forward": true,
}

// redirectCandidate reports whether a parameter is worth an open-redirect
// test: its value already looks like a URL or an absolute path, or its name
// is one of the usual suspects.
func redirectCandidate(name, value string) bool {
	if redirectNames[strings.ReplaceAll(words(name), "-", "")] {
		return true
	}
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "/")
}

func canaryURL(host string) string {
	return "https://" + host + "/"
}

// judgeRedirect applies the open-redirect proof rule: the target answered
// with a 3xx whose Location header names exactly the canary host. A Location
// that merely contains the canary (in its path or query, or as a subdomain
// of something else) is not a redirect to it and does not count.
func judgeRedirect(r probe.Response, canary string) (string, bool) {
	if !r.Answered() || r.Status < http.StatusMultipleChoices || r.Status >= http.StatusBadRequest {
		return "", false
	}
	location := strings.TrimSpace(header(r, "Location"))
	u, err := url.Parse(location)
	if err != nil || strings.ToLower(u.Hostname()) != canary {
		return "", false
	}
	return location, true
}
