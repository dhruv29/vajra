package har

import (
	"cmp"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/dhruv29/vajra/internal/redact"
)

// escapedPlaceholder is redact.Placeholder as it is written inside a URL.
var escapedPlaceholder = url.PathEscape(redact.Placeholder)

// fieldSeparator joins the kept fields for one scrub pass. Every field is
// percent-encoded and no remembered secret contains it, so a replacement can
// never span two fields.
const fieldSeparator = "\n"

// finish scrubs the kept requests, deduplicates them again (a scrub can make
// two paths equal) and sorts everything into a stable order.
func (b *builder) finish() Recording {
	rec := Recording{Requests: []Request{}, URLs: []string{}, Skipped: b.skipped}
	seen := map[string]struct{}{}
	seeds := map[string]struct{}{}
	for _, c := range b.scrubbed() {
		key := c.key()
		if _, dup := seen[key]; dup {
			rec.Skipped.Duplicate++
			continue
		}
		seen[key] = struct{}{}
		req := c.request()
		rec.Requests = append(rec.Requests, req)
		if c.method == "GET" && !c.stateChanging && !c.static {
			seeds[req.URL] = struct{}{}
		}
	}
	slices.SortFunc(rec.Requests, compareRequests)
	for seed := range seeds {
		rec.URLs = append(rec.URLs, seed)
	}
	sort.Strings(rec.URLs)
	return rec
}

// compareRequests orders by URL, then method, then parameter names, which
// together are unique after deduplication.
func compareRequests(a, b Request) int {
	return cmp.Or(
		strings.Compare(a.URL, b.URL),
		strings.Compare(a.Method, b.Method),
		slices.Compare(a.BodyParams, b.BodyParams),
	)
}

// scrubbed returns copies of the kept candidates with every remembered
// credential removed from their paths, parameter names and query values.
func (b *builder) scrubbed() []candidate {
	if len(b.kept) == 0 {
		return nil
	}
	fields := collectFields(b.kept)
	secrets := b.secrets.list()
	out := strings.Split(redact.Values(strings.Join(fields, fieldSeparator), secrets...), fieldSeparator)
	if len(out) != len(fields) {
		// Impossible by construction, but if it ever happens, scrub field by
		// field rather than return anything unscrubbed or misaligned.
		out = make([]string, 0, len(fields))
		for _, field := range fields {
			out = append(out, redact.Values(field, secrets...))
		}
	}
	return applyFields(b.kept, out)
}

// collectFields lists the free-text parts of the candidates in a fixed order
// that applyFields walks again.
func collectFields(kept []candidate) []string {
	var fields []string
	for _, c := range kept {
		fields = append(fields, c.path)
		for _, q := range c.query {
			fields = append(fields, q.name, q.value)
		}
		for _, name := range c.bodyNames {
			fields = append(fields, url.QueryEscape(name))
		}
	}
	return fields
}

// applyFields builds new candidates from the scrubbed fields.
func applyFields(kept []candidate, fields []string) []candidate {
	next := 0
	take := func() string {
		next++
		return fields[next-1]
	}
	out := make([]candidate, 0, len(kept))
	for _, c := range kept {
		scrubbed := c
		scrubbed.path = fixPath(take())
		scrubbed.query = make([]pair, 0, len(c.query))
		for range c.query {
			scrubbed.query = append(scrubbed.query, pair{name: fixQuery(take()), value: fixQuery(take())})
		}
		sort.SliceStable(scrubbed.query, func(i, j int) bool { return scrubbed.query[i].name < scrubbed.query[j].name })
		scrubbed.bodyNames = make([]string, 0, len(c.bodyNames))
		for range c.bodyNames {
			name, _ := url.QueryUnescape(fixQuery(take())) // fixQuery guarantees it decodes
			scrubbed.bodyNames = append(scrubbed.bodyNames, name)
		}
		out = append(out, scrubbed)
	}
	return out
}

// fixPath keeps a scrubbed path a valid, absolute, escaped path. A
// replacement in the middle of a %XX escape would leave it undecodable; the
// whole path is then replaced, since part of it was a credential.
func fixPath(escaped string) string {
	escaped = strings.ReplaceAll(escaped, redact.Placeholder, escapedPlaceholder)
	if _, err := url.PathUnescape(escaped); err != nil {
		return "/" + escapedPlaceholder
	}
	if !strings.HasPrefix(escaped, "/") {
		escaped = "/" + escaped
	}
	return escaped
}

// fixQuery does the same for one escaped query name or value.
func fixQuery(escaped string) string {
	escaped = strings.ReplaceAll(escaped, redact.Placeholder, escapedPlaceholder)
	if _, err := url.QueryUnescape(escaped); err != nil {
		return escapedPlaceholder
	}
	return escaped
}

// request is the exported form of a scrubbed candidate.
func (c candidate) request() Request {
	return Request{
		Method:        c.method,
		URL:           c.url(),
		QueryParams:   decodedNames(c.query),
		BodyParams:    sortedUnique(c.bodyNames),
		ContentType:   c.contentType,
		StateChanging: c.stateChanging,
		Authenticated: c.authenticated,
	}
}

func (c candidate) url() string {
	if len(c.query) == 0 {
		return c.origin + c.path
	}
	parts := make([]string, 0, len(c.query))
	for _, q := range c.query {
		parts = append(parts, q.name+"="+q.value)
	}
	return c.origin + c.path + "?" + strings.Join(parts, "&")
}

func pairNames(pairs []pair) []string {
	names := make([]string, 0, len(pairs))
	for _, p := range pairs {
		names = append(names, p.name)
	}
	return names
}

func decodedNames(pairs []pair) []string {
	names := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if name, err := url.QueryUnescape(p.name); err == nil {
			names = append(names, name)
		}
	}
	return sortedUnique(names)
}
