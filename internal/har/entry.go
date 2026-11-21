package har

import (
	"encoding/json"
	"errors"
	"mime"
	"strings"

	"github.com/dhruv29/vajra/internal/scope"
)

const (
	// maxMethodLength bounds a method name; the longest real ones (such as
	// PROPPATCH or UNSUBSCRIBE) are well inside it.
	maxMethodLength = 16
	// maxContentTypeLength bounds a media type; a longer one is dropped.
	maxContentTypeLength = 128
)

// harEntry is the part of a HAR entry this package reads. Everything else,
// the response included, is ignored.
type harEntry struct {
	Request harRequest `json:"request"`
}

type harRequest struct {
	Method   string       `json:"method"`
	URL      string       `json:"url"`
	Headers  []nameValue  `json:"headers"`
	Cookies  []nameValue  `json:"cookies"`
	PostData *harPostData `json:"postData"`
}

type harPostData struct {
	MimeType string      `json:"mimeType"`
	Params   []nameValue `json:"params"`
	Text     string      `json:"text"`
	// Encoding is not in HAR 1.2 for requests, but some proxies write
	// "base64" here for binary bodies.
	Encoding string `json:"encoding"`
}

type nameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// candidate is a request that passed every check, before the final scrub.
// Path, query names and values and body names are held percent-encoded, so
// none of them can contain the newline the scrub joins them with.
type candidate struct {
	method        string
	origin        string // scheme://host[:port]
	path          string // escaped
	query         []pair // escaped, sorted by name
	bodyNames     []string
	contentType   string
	stateChanging bool
	authenticated bool
	static        bool
}

// builder accumulates candidates as entries stream past.
type builder struct {
	policy     *scope.Policy
	maxEntries int
	seen       map[string]struct{}
	kept       []candidate
	secrets    *secretSet
	skipped    Skipped
}

func newBuilder(policy *scope.Policy, opts Options) *builder {
	return &builder{
		policy:     policy,
		maxEntries: opts.MaxEntries,
		seen:       map[string]struct{}{},
		secrets:    newSecretSet(),
	}
}

// add turns one raw entry into a candidate, or counts why it was dropped.
// Credentials are collected from every entry that decodes, in scope or not:
// a token issued by an out-of-scope login server can still turn up in an
// in-scope URL.
func (b *builder) add(raw json.RawMessage) {
	var entry harEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		b.skipped.Malformed++
		return
	}
	req := entry.Request
	authenticated := b.secrets.addHeaders(req.Headers, req.Cookies)
	media := contentType(req)
	bodyNames := b.bodyNames(req.PostData, media)
	t, reason := parseTarget(req.URL, b.policy, b.secrets)
	if reason != keep {
		b.count(reason)
		return
	}
	method, ok := normaliseMethod(req.Method)
	if !ok {
		b.skipped.Malformed++
		return
	}
	c := newCandidate(method, t, bodyNames, media, authenticated)
	b.keep(c)
}

// keep records c unless an equivalent request is already held or the cap is
// reached.
func (b *builder) keep(c candidate) {
	key := c.key()
	if _, dup := b.seen[key]; dup {
		b.skipped.Duplicate++
		return
	}
	if len(b.kept) >= b.maxEntries {
		b.skipped.OverLimit++
		return
	}
	b.seen[key] = struct{}{}
	b.kept = append(b.kept, c)
}

func (b *builder) count(reason dropReason) {
	switch reason {
	case outOfScope:
		b.skipped.OutOfScope++
	case unsupportedScheme:
		b.skipped.UnsupportedScheme++
	default:
		b.skipped.Malformed++
	}
}

func newCandidate(method string, t target, bodyNames []string, ctype string, authenticated bool) candidate {
	return candidate{
		method:        method,
		origin:        t.origin,
		path:          t.escapedPath,
		query:         t.query,
		bodyNames:     bodyNames,
		contentType:   ctype,
		stateChanging: !safeMethods[method] || t.namesAction,
		authenticated: authenticated,
		static:        isStaticAsset(t.decodedPath),
	}
}

// key identifies requests that exercise the same code: the method, where
// they go, and which parameters they send, but not the parameter values.
func (c candidate) key() string {
	var b strings.Builder
	b.WriteString(c.method)
	b.WriteByte(0)
	b.WriteString(c.origin)
	b.WriteString(c.path)
	b.WriteByte(0)
	b.WriteString(strings.Join(sortedUnique(pairNames(c.query)), "&"))
	b.WriteByte(0)
	b.WriteString(strings.Join(sortedUnique(c.bodyNames), "&"))
	return b.String()
}

// safeMethods are the methods that do not change state by definition. Any
// other method, including ones this package has never heard of, is treated
// as state-changing.
var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// normaliseMethod upper-cases a method and reports whether it is a valid
// HTTP token of reasonable length.
func normaliseMethod(raw string) (string, bool) {
	method := strings.ToUpper(strings.TrimSpace(raw))
	if method == "" || len(method) > maxMethodLength {
		return "", false
	}
	for _, r := range method {
		if r < 'A' || r > 'Z' {
			if r != '-' && r != '_' {
				return "", false
			}
		}
	}
	return method, true
}

// contentType is the media type of the body, taken from postData and failing
// that from the Content-Type header. Parameters such as charset or boundary
// are dropped: they are not needed and a boundary can carry anything.
func contentType(req harRequest) string {
	raw := ""
	if req.PostData != nil {
		raw = req.PostData.MimeType
	}
	if strings.TrimSpace(raw) == "" {
		for _, h := range req.Headers {
			if strings.EqualFold(strings.TrimSpace(h.Name), "Content-Type") {
				raw = h.Value
				break
			}
		}
	}
	return mediaType(raw)
}

func mediaType(raw string) string {
	if len(raw) > maxContentTypeLength {
		return ""
	}
	media, _, err := mime.ParseMediaType(raw)
	if err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter) {
		return "" // a bad parameter still leaves a usable media type
	}
	return media
}
