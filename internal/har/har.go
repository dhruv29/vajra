// Package har imports a browser recording (a HAR 1.2 file exported from
// browser developer tools or an intercepting proxy) so that pages a crawler
// can not reach on its own, such as single-page applications and pages behind
// a login flow, can still be tested.
//
// The file is treated as hostile input. It is read through a byte limit and
// decoded one entry at a time, so an oversized file fails with a clear error
// instead of exhausting memory; the number of requests kept and the length of
// every field are capped; and odd shapes (a missing postData, params instead
// of text, base64 bodies, values of the wrong JSON type) are skipped or counted
// as malformed, never a panic.
//
// Scope is deny-by-default, as everywhere else: every URL in the file is
// checked with the scope policy's own CheckTarget, after its host has been
// normalised with scope.NormalizeHost. Entries outside scope are counted and
// dropped, never returned. Only http and https URLs are kept; data:, blob:,
// ws:, chrome-extension: and every other scheme is counted and dropped.
//
// A recording is full of live credentials, so what is kept is deliberately
// narrow:
//
//   - No header value is kept at all. Cookie, Authorization, Set-Cookie,
//     every header internal/redact treats as a credential, and every header
//     whose name looks like a secret only mark the request as Authenticated.
//   - No request body value is kept, only the names of form and JSON fields.
//   - User information ("user:password@") and fragments are removed from URLs.
//   - Query parameters whose name looks like a secret (token, key, session,
//     password, secret, sig, code, auth and similar) keep their name and lose
//     their value. Other query values are kept, because the scanners need a
//     URL that still works.
//   - As a second line of defence, every credential value seen anywhere in the
//     file (header and cookie values, secret query and body values) is scrubbed
//     with redact.Values from the paths, parameter names and query values that
//     are kept, so a session token echoed in another URL does not survive.
//
// Requests are deduplicated by method, scheme, host, path and the sorted
// names of their parameters: values differ from one session to the next, so
// two requests that differ only in values exercise the same code.
package har

import (
	"errors"
	"io"

	"github.com/dhruv29/vajra/internal/scope"
)

const (
	// DefaultMaxBytes is how much of a recording is read when Options does not
	// say. Browser exports of a long session run to tens of megabytes; much
	// beyond this is more likely an attack on memory than a real recording.
	DefaultMaxBytes int64 = 64 << 20

	// DefaultMaxEntries is how many distinct requests are kept when Options
	// does not say. It is far more than one application's endpoints.
	DefaultMaxEntries = 5000
)

// Options bounds how much of a recording is read and kept.
type Options struct {
	// MaxBytes is the most bytes read from the file. Zero or less means
	// DefaultMaxBytes. A larger file is an error, not a partial import.
	MaxBytes int64
	// MaxEntries is the most distinct requests kept. Zero or less means
	// DefaultMaxEntries. Requests beyond it are counted in Skipped.OverLimit.
	MaxEntries int
}

// Request is one distinct request taken from the recording.
type Request struct {
	Method string `json:"method"`
	// URL is absolute, http or https, without user information or fragment,
	// with query parameters in name order and secret values removed.
	URL string `json:"url"`
	// QueryParams and BodyParams are the sorted, distinct parameter names.
	// JSON fields inside objects are written "parent.child".
	QueryParams []string `json:"query_params,omitempty"`
	BodyParams  []string `json:"body_params,omitempty"`
	// ContentType is the media type of the body, without parameters.
	ContentType string `json:"content_type,omitempty"`
	// StateChanging is true for every method but GET, HEAD and OPTIONS, and
	// for a GET whose path or query names an action such as logout or delete.
	StateChanging bool `json:"state_changing"`
	// Authenticated is true when the recorded request carried a cookie or a
	// credential header. The values themselves are never kept.
	Authenticated bool `json:"authenticated"`
}

// Skipped counts the entries that were not kept, by reason.
type Skipped struct {
	OutOfScope        int `json:"out_of_scope"`
	UnsupportedScheme int `json:"unsupported_scheme"`
	Malformed         int `json:"malformed"`
	Duplicate         int `json:"duplicate"`
	OverLimit         int `json:"over_limit"`
}

// Recording is what was imported from one file.
type Recording struct {
	// Requests are the distinct in-scope requests, sorted by URL then method.
	Requests []Request `json:"requests"`
	// URLs are the distinct in-scope GET URLs that are safe to seed a crawler
	// or scanner with: not state-changing and not a static asset. Sorted.
	URLs    []string `json:"urls"`
	Skipped Skipped  `json:"skipped"`
}

// Parse reads a HAR file from r and returns the in-scope requests it holds.
// Every URL is checked against policy; a nil policy is an error, because
// there is no "allow everything" scope.
func Parse(r io.Reader, policy *scope.Policy, opts Options) (Recording, error) {
	if r == nil {
		return Recording{}, errors.New("har: a reader is required")
	}
	if policy == nil {
		return Recording{}, errors.New("har: a scope policy is required")
	}
	opts = opts.withDefaults()
	b := newBuilder(policy, opts)
	if err := decodeEntries(r, opts.MaxBytes, b.add); err != nil {
		return Recording{}, err
	}
	return b.finish(), nil
}

// withDefaults returns a copy of o with unset limits filled in.
func (o Options) withDefaults() Options {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	return o
}
