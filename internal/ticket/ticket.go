// Package ticket files a finding as an issue in a tracker: GitHub Issues or
// Jira Cloud. Filing is idempotent: each ticket carries the finding's stable
// ID as a marker, and a ticket that already has the marker is returned
// instead of a second one being opened.
//
// Credentials are passed in by the caller as plain option fields. They are
// sent only in request headers and never appear in an error.
package ticket

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// markerPrefix starts the line that ties a ticket to its finding. The line
// is visible in the ticket on purpose: whoever reads it can find the finding
// in the report, and the search that prevents duplicates looks for it.
const markerPrefix = "vajra-finding: "

// findingIDPattern is what a finding ID may look like before it goes into a
// search query. Stable IDs are hex; the demo uses words and dashes. Nothing
// here can close a quoted string in a GitHub search or a JQL query.
var findingIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Issue is what gets filed.
type Issue struct {
	// FindingID is the finding's stable ID. It is the duplicate marker.
	FindingID string
	// Title and Body are clipped to the tracker's limits when filed.
	Title string
	Body  string
}

// Result is the ticket that was filed, or the one that already existed.
type Result struct {
	// URL is the ticket's page in the tracker's web interface.
	URL string
	// Key is "owner/repo#number" on GitHub and the issue key ("SEC-12") on
	// Jira.
	Key string
	// State is the tracker's state name ("open", "closed", "To Do"), when the
	// tracker reported one.
	State string
	// Existing is true when no ticket was filed because one was found.
	Existing bool
}

// Filer files an issue, or returns the ticket already filed for the same
// finding.
type Filer interface {
	File(ctx context.Context, issue Issue) (Result, error)
}

// checkIssue refuses an issue that could not be filed or searched for.
func checkIssue(issue Issue) error {
	if !findingIDPattern.MatchString(issue.FindingID) {
		return fmt.Errorf("ticket: finding ID %q is not a plain identifier (letters, digits, '.', '_' and '-', up to 64)", clipRunes(issue.FindingID, maxQuotedIDRunes))
	}
	if strings.TrimSpace(issue.Title) == "" {
		return errors.New("ticket: the issue has no title")
	}
	return nil
}

// maxQuotedIDRunes keeps a rejected ID from flooding the error message.
const maxQuotedIDRunes = 80

func markerLine(findingID string) string {
	return markerPrefix + findingID
}

// hasMarker reports whether text has the marker for findingID on a line of
// its own. Search engines match loosely ("demo-sqli" may match
// "demo-sqli-2"), so each hit is checked exactly before it is trusted.
func hasMarker(text, findingID string) bool {
	want := markerLine(findingID)
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// bodyWithMarker clips body so that the body, a blank line and the marker
// line fit in limit characters together. The marker goes last and is never
// cut, because the duplicate check depends on it.
func bodyWithMarker(body, findingID string, limit int) string {
	suffix := "\n\n" + markerLine(findingID) + "\n"
	room := limit - utf8.RuneCountInString(suffix)
	return clipRunes(strings.TrimRight(body, "\n"), room) + suffix
}

// cleanTitle puts a title on one line and clips it. Trackers show the title
// in lists, where a line break or control character would garble it.
func cleanTitle(title string, limit int) string {
	return clipRunes(strings.Join(strings.Fields(title), " "), limit)
}

// clipNote marks a clipped string, so that a reader knows text is missing.
const clipNote = "…"

// clipRunes shortens s to at most limit characters (runes, which is how both
// trackers count), ending with clipNote when anything was cut.
func clipRunes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return string(runes[:limit-1]) + clipNote
}

// hasUnsafeChars reports whether s has whitespace or control characters. A
// credential with either would be a copy-and-paste mistake, and in a header
// it could break the request.
func hasUnsafeChars(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) >= 0
}
