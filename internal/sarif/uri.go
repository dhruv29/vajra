package sarif

import (
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// maxBaseDepth bounds chains of uriBaseIds that refer to other base ids,
	// so a cycle cannot loop forever.
	maxBaseDepth = 4
	maxPathBytes = 4096
)

// srcRootIDs are the names tools give the base id meaning "the project root".
var srcRootIDs = []string{"%SRCROOT%", "SRCROOT"}

// resolver turns a SARIF artifact location into a clean path relative to the
// project root, or refuses it.
type resolver struct {
	bases baseIDs
	// roots are absolute paths (slash-separated, cleaned) that stand for the
	// project root: the SARIF's own %SRCROOT% and the operator's Options.Root.
	roots []string
}

func newResolver(bases baseIDs, operatorRoot string) resolver {
	r := resolver{bases: bases}
	for _, id := range srcRootIDs {
		if p, abs, ok := r.base(id, 0); ok && abs {
			r.roots = append(r.roots, p)
		}
	}
	if operatorRoot != "" && filepath.IsAbs(operatorRoot) {
		r.roots = append(r.roots, path.Clean(filepath.ToSlash(operatorRoot)))
	}
	return r
}

// resolve returns the location as a path inside the project. ok is false for
// anything that leaves the project, is absolute outside it, uses a scheme
// other than file, or contains characters no real path should.
func (r resolver) resolve(loc artifactLocation) (string, bool) {
	p, abs, ok := parseURI(loc.URI)
	if !ok {
		return "", false
	}
	if !abs && loc.URIBaseID != "" {
		prefix, baseAbs, ok := r.base(loc.URIBaseID, 0)
		if !ok {
			return "", false
		}
		// With no known project root, an absolute base is the best guess at
		// one: the uri stays relative and must still stay inside it.
		if !baseAbs || len(r.roots) > 0 {
			p, abs = path.Join(prefix, p), baseAbs
		}
	}
	p = path.Clean(p)
	if abs {
		if p, ok = r.relativise(p); !ok {
			return "", false
		}
	}
	return p, safe(p)
}

// base resolves a uriBaseId to a directory prefix. A base the document does
// not define, or defines without a uri, is taken to be the project root:
// that is what %SRCROOT% and similar names mean in practice.
func (r resolver) base(id string, depth int) (string, bool, bool) {
	if depth > maxBaseDepth {
		return "", false, false
	}
	loc, defined := r.bases[id]
	if !defined || loc.URI == "" {
		return "", false, true
	}
	p, abs, ok := parseURI(loc.URI)
	if !ok {
		return "", false, false
	}
	if abs || loc.URIBaseID == "" {
		return path.Clean(p), abs, true
	}
	parent, parentAbs, ok := r.base(loc.URIBaseID, depth+1)
	if !ok {
		return "", false, false
	}
	return path.Join(parent, p), parentAbs, true
}

// relativise strips a project-root prefix from an absolute path.
func (r resolver) relativise(p string) (string, bool) {
	for _, root := range r.roots {
		if rel, found := strings.CutPrefix(p, strings.TrimSuffix(root, "/")+"/"); found {
			return rel, true
		}
	}
	return "", false
}

// parseURI decodes a SARIF uri (a URI reference) into a slash-separated
// path. abs reports whether it is absolute. Backslashes are read as
// separators, because Windows tools write them and a literal backslash would
// hide a "..\" step from the containment check.
func parseURI(raw string) (p string, abs bool, ok bool) {
	if raw == "" || len(raw) > maxPathBytes {
		return "", false, false
	}
	raw = strings.ReplaceAll(raw, `\`, "/")
	if isDrivePath(raw) {
		raw = "/" + raw // C:/x is absolute, just as file:///C:/x is
	}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", false, false
	}
	switch u.Scheme {
	case "":
		if u.Host != "" {
			return "", false, false // "//host/share" is a network path
		}
	case "file":
		if u.Host != "" && u.Host != "localhost" {
			return "", false, false
		}
	default:
		return "", false, false
	}
	p = strings.ReplaceAll(u.Path, `\`, "/") // %5C decodes to a backslash
	if p == "" || hasControl(p) {
		return "", false, false
	}
	return p, strings.HasPrefix(p, "/"), true
}

func isDrivePath(s string) bool {
	return len(s) >= 3 && s[1] == ':' && s[2] == '/' &&
		((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z'))
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

// safe is finding.SafeRelPath plus the checks a report path also needs.
func safe(p string) bool {
	return finding.SafeRelPath(p) && p != "." && len(p) <= maxPathBytes && !hasControl(p)
}
