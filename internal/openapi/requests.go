package openapi

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/dhruv29/vajra/internal/probe"
)

const (
	contentTypeHeader = "Content-Type"

	reasonUnsafeMethod      = "%s may change data; set IncludeUnsafe to send it"
	reasonUnsupportedMethod = "the probe does not send %s requests"
	reasonMissingPathParam  = "no value for path parameter %q"
	reasonBodyTooLarge      = "the body example is larger than the probe accepts"
	reasonBadPathTemplate   = "the path template %q is not a plain path starting with /"
	reasonDotPathParam      = "the value of path parameter %q would change the route"
)

// placeholderPattern matches one {name} in a path template.
var placeholderPattern = regexp.MustCompile(`\{([^{}/]+)\}`)

// safeMethods are sent without IncludeUnsafe: they are defined not to change
// anything on the server.
var safeMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true}

// unsafeMethods need IncludeUnsafe. Anything in neither set (TRACE) is a
// method the probe refuses to send at all.
var unsafeMethods = map[string]bool{
	http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// RequestOptions says how to fill in an operation.
type RequestOptions struct {
	// BaseURL is required, for example https://api.example.com/v1. The
	// servers listed in the document are not used: where to send requests is
	// the caller's decision, not the description's.
	BaseURL string
	// Params gives values for path and query parameters by name. Examples
	// from the spec are used when a name is missing.
	Params map[string]string
	// Headers are sent with every request (for example Authorization). May
	// be nil.
	Headers map[string]string
	// IncludeUnsafe allows POST, PUT, PATCH and DELETE. Without it only GET,
	// HEAD and OPTIONS are generated, because other methods may change data.
	IncludeUnsafe bool
}

// Skipped is an operation that was left out, and why.
type Skipped struct {
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
}

// Requests builds one probe.Request per operation that can be filled in, in
// the order of d.Operations. Skipped lists the operations left out and why
// (unsafe method, a path parameter with no value). When BaseURL is not an
// http(s) URL nothing can be built, and every operation is skipped for that
// reason.
func (d Document) Requests(opts RequestOptions) (requests []probe.Request, skipped []Skipped) {
	base, err := baseURL(opts.BaseURL)
	for _, op := range d.Operations {
		if err != nil {
			skipped = append(skipped, Skipped{Operation: op.ID, Reason: err.Error()})
			continue
		}
		request, reason := op.request(base, opts)
		if reason != "" {
			skipped = append(skipped, Skipped{Operation: op.ID, Reason: reason})
			continue
		}
		requests = append(requests, request)
	}
	return requests, skipped
}

// baseURL checks the base and returns it without a trailing slash, query or
// fragment, ready to have a path appended.
func baseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("the base URL %q is not an http(s) URL", raw)
	}
	return parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.EscapedPath(), "/"), nil
}

// request fills in one operation, or says why it cannot be sent.
func (op Operation) request(base string, opts RequestOptions) (probe.Request, string) {
	switch {
	case unsafeMethods[op.Method] && !opts.IncludeUnsafe:
		return probe.Request{}, fmt.Sprintf(reasonUnsafeMethod, op.Method)
	case !unsafeMethods[op.Method] && !safeMethods[op.Method]:
		return probe.Request{}, fmt.Sprintf(reasonUnsupportedMethod, op.Method)
	}
	if !plainPathTemplate(op.Path) {
		return probe.Request{}, fmt.Sprintf(reasonBadPathTemplate, op.Path)
	}
	path, missing, dotted := op.fillPath(opts.Params)
	switch {
	case missing != "":
		return probe.Request{}, fmt.Sprintf(reasonMissingPathParam, missing)
	case dotted != "":
		return probe.Request{}, fmt.Sprintf(reasonDotPathParam, dotted)
	}
	request := probe.Request{
		ID:      op.ID,
		Method:  op.Method,
		URL:     base + path + op.query(opts.Params),
		Headers: maps.Clone(opts.Headers),
	}
	if op.BodyExample == "" || safeMethods[op.Method] {
		return request, ""
	}
	if len(op.BodyExample) > probe.MaxRequestBodyBytes {
		return probe.Request{}, reasonBodyTooLarge
	}
	request.Body = op.BodyExample
	request.Headers = withContentType(request.Headers)
	return request, ""
}

// plainPathTemplate reports whether a path template can be appended to the
// base URL as it is. A "?" or "#" would start a query or fragment the caller
// did not ask for, and whitespace, backslashes and control characters are
// read differently by different servers and proxies.
func plainPathTemplate(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	return !strings.ContainsFunc(path, func(r rune) bool {
		return r == '?' || r == '#' || r == '\\' || unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

// fillPath replaces every {name} in the template with its escaped value. It
// returns the name of the first parameter that has none, and of the first
// whose value is "." or "..". An empty value counts as none, and a dot
// segment is not escaped by PathEscape: either would reach a different route.
func (op Operation) fillPath(params map[string]string) (path, missing, dotted string) {
	path = placeholderPattern.ReplaceAllStringFunc(op.Path, func(placeholder string) string {
		name := strings.Trim(placeholder, "{}")
		value := params[name]
		if value == "" {
			value = op.pathExamples[name]
		}
		if value == "" && missing == "" {
			missing = name
		}
		if (value == "." || value == "..") && dotted == "" {
			dotted = name
		}
		return url.PathEscape(value)
	})
	return path, missing, dotted
}

// query builds the query string, with its leading "?". A parameter is sent
// when the caller gave a value, when the spec gives an example, or when it is
// required; a required one with nothing to say is sent empty so the request
// still has the shape the API expects.
func (op Operation) query(params map[string]string) string {
	var pairs []string
	for _, param := range op.QueryParams {
		value, given := params[param.Name]
		if !given {
			value = param.Example
		}
		if !given && value == "" && !param.Required {
			continue
		}
		pairs = append(pairs, url.QueryEscape(param.Name)+"="+url.QueryEscape(value))
	}
	if len(pairs) == 0 {
		return ""
	}
	return "?" + strings.Join(pairs, "&")
}

// withContentType marks a body as JSON unless the caller already chose a
// content type.
func withContentType(headers map[string]string) map[string]string {
	for name := range headers {
		if strings.EqualFold(name, contentTypeHeader) {
			return headers
		}
	}
	if headers == nil {
		headers = map[string]string{}
	}
	headers[contentTypeHeader] = jsonMediaType
	return headers
}

// placeholders lists the parameter names of a path template in order, each
// once.
func placeholders(path string) []string {
	var names []string
	seen := map[string]bool{}
	for _, match := range placeholderPattern.FindAllStringSubmatch(path, -1) {
		if !seen[match[1]] {
			seen[match[1]] = true
			names = append(names, match[1])
		}
	}
	return names
}
