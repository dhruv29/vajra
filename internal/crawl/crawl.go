// Package crawl discovers the pages and endpoints of a web application by
// following links, staying inside the scope it was given.
//
// It never opens a connection itself: every request goes through a
// probe.Fetcher, so it runs in the sandbox behind the egress gate like any
// other traffic. It only sends GET requests and never interprets JavaScript.
package crawl

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dhruv29/vajra/internal/probe"
)

const (
	// MaxLinksPerPage is the most links taken from one page. A page that
	// generates links without end must not crowd out the rest of the site.
	MaxLinksPerPage = 500

	// maxBodyBytes bounds how much of one response body is searched for links.
	maxBodyBytes = 1 << 20

	// requestIDPrefix starts every request ID; the rest is the position of
	// the request in the whole crawl, which keeps IDs unique across batches.
	requestIDPrefix = "crawl-"
)

// Options controls how far a crawl goes.
type Options struct {
	// MaxPages is the most URLs that will be fetched. It must be positive.
	MaxPages int
	// MaxDepth is how many links away from a start URL the crawl may go.
	// Zero means only the start URLs. It must not be negative.
	MaxDepth int
	// InScope says whether a URL may be fetched. The caller wires this to the
	// scope policy; the gate enforces it again. It is required.
	InScope func(rawURL string) bool
	// Headers are sent with every request (for example a session). May be nil.
	Headers map[string]string
}

// Page is one fetched URL.
type Page struct {
	URL    string `json:"url"`
	Depth  int    `json:"depth"`
	Status int    `json:"status"`
	// Links are the in-scope URLs found on the page: absolute, sorted and
	// de-duplicated.
	Links []string `json:"links"`
	Forms []Form   `json:"forms,omitempty"`
	// Error is set when the target did not answer (the gate refused or the
	// network failed).
	Error string `json:"error,omitempty"`
}

// Form is an HTML form found on a page.
type Form struct {
	// Action is the absolute URL the form submits to.
	Action string `json:"action"`
	// Method is upper case; a form without one uses GET.
	Method string `json:"method"`
	// Fields are the names of its input, select and textarea elements, sorted.
	Fields []string `json:"fields"`
}

// Result is everything a crawl saw.
type Result struct {
	// Pages are in the order fetched (breadth-first).
	Pages []Page `json:"pages"`
	// Exchanges holds every request with its response, in the same order.
	Exchanges []probe.Exchange `json:"exchanges"`
	// Truncated is true when MaxPages stopped the crawl with URLs still queued.
	Truncated bool `json:"truncated"`
	// Skipped are links the crawl would have followed but did not, because
	// they look like they change state (log out, delete, revoke, ...) and the
	// crawl sends the operator's session. They stay in Page.Links. Normalised,
	// sorted and de-duplicated.
	Skipped []string `json:"skipped"`
}

// crawler holds the state of one crawl.
type crawler struct {
	fetcher probe.Fetcher
	opts    Options
	// queued holds every normalised URL that was ever put on a level, so no
	// URL is fetched twice.
	queued map[string]bool
}

// Crawl fetches the start URLs and then, level by level, the in-scope links
// found on them. Each level is one batch, so the number of sandbox runs grows
// with the depth of the site and not with its size.
//
// A URL that fails is recorded on its Page and the crawl goes on. An error
// from the fetcher, or a cancelled context, ends the crawl; the pages fetched
// so far are returned with the error.
func Crawl(ctx context.Context, fetcher probe.Fetcher, start []string, opts Options) (Result, error) {
	if err := validate(fetcher, opts); err != nil {
		return Result{}, err
	}
	c := &crawler{fetcher: fetcher, opts: opts, queued: map[string]bool{}}
	level, err := c.startLevel(start)
	if err != nil {
		return Result{}, err
	}
	result := Result{Pages: []Page{}, Exchanges: []probe.Exchange{}, Skipped: []string{}}
	for depth := 0; len(level) > 0; depth++ {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("crawl: stopped before depth %d: %w", depth, err)
		}
		if room := opts.MaxPages - len(result.Pages); len(level) > room {
			level, result.Truncated = level[:room], true
		}
		exchanges, err := c.fetch(ctx, level, len(result.Exchanges))
		if err != nil {
			return result, err
		}
		var next []string
		for _, exchange := range exchanges {
			page := c.page(exchange, depth)
			result.Pages = append(result.Pages, page)
			if depth < opts.MaxDepth {
				follow, skipped := splitStateChanging(page.Links)
				next = c.enqueue(next, follow)
				if len(skipped) > 0 {
					result.Skipped = slices.Compact(slices.Sorted(slices.Values(append(result.Skipped, skipped...))))
				}
			}
		}
		result.Exchanges = append(result.Exchanges, exchanges...)
		level = next
	}
	return result, nil
}

// splitStateChanging separates the links that look safe to fetch from those
// that look like they change state.
func splitStateChanging(links []string) (follow, skipped []string) {
	for _, target := range links {
		if changesState(target) {
			skipped = append(skipped, target)
		} else {
			follow = append(follow, target)
		}
	}
	return follow, skipped
}

func validate(fetcher probe.Fetcher, opts Options) error {
	switch {
	case fetcher == nil:
		return errors.New("crawl: a fetcher is required")
	case opts.MaxPages <= 0:
		return errors.New("crawl: MaxPages must be greater than zero")
	case opts.MaxDepth < 0:
		return errors.New("crawl: MaxDepth must not be negative")
	case opts.InScope == nil:
		return errors.New("crawl: InScope is required")
	}
	return nil
}

// startLevel turns the start URLs into the first level. A start URL that is
// not an http(s) URL is a mistake by the caller and is reported; one that is
// out of scope is left out, and it is an error when none remain, because a
// crawl that silently fetches nothing looks like an empty site.
func (c *crawler) startLevel(start []string) ([]string, error) {
	if len(start) == 0 {
		return nil, errors.New("crawl: at least one start URL is required")
	}
	normalised := make([]string, 0, len(start))
	for _, raw := range start {
		target, ok := normalise(raw)
		if !ok {
			return nil, fmt.Errorf("crawl: start URL %q is not an http(s) URL", raw)
		}
		normalised = append(normalised, target)
	}
	level := c.enqueue(nil, c.inScope(normalised))
	if len(level) == 0 {
		return nil, errors.New("crawl: no start URL is in scope")
	}
	return level, nil
}

// enqueue appends the URLs that were never queued before.
func (c *crawler) enqueue(level []string, urls []string) []string {
	for _, target := range urls {
		if !c.queued[target] {
			c.queued[target] = true
			level = append(level, target)
		}
	}
	return level
}

func (c *crawler) inScope(urls []string) []string {
	kept := make([]string, 0, len(urls))
	for _, target := range urls {
		if c.opts.InScope(target) {
			kept = append(kept, target)
		}
	}
	return kept
}

// fetch requests one level, in as few batches as the probe allows. offset is
// the number of requests made before this level and keeps request IDs unique.
func (c *crawler) fetch(ctx context.Context, urls []string, offset int) ([]probe.Exchange, error) {
	requests := make([]probe.Request, len(urls))
	for i, target := range urls {
		requests[i] = probe.Request{
			ID:      requestIDPrefix + strconv.Itoa(offset+i+1),
			Method:  http.MethodGet,
			URL:     target,
			Headers: maps.Clone(c.opts.Headers),
		}
	}
	exchanges := make([]probe.Exchange, 0, len(requests))
	for chunk := range slices.Chunk(requests, probe.MaxRequests) {
		responses, err := c.fetcher.Do(ctx, chunk)
		if err != nil {
			return nil, fmt.Errorf("crawl: fetch: %w", err)
		}
		if len(responses) != len(chunk) {
			return nil, fmt.Errorf("crawl: fetch: %d responses for %d requests", len(responses), len(chunk))
		}
		for i, request := range chunk {
			exchanges = append(exchanges, probe.Exchange{Request: request, Response: responses[i]})
		}
	}
	return exchanges, nil
}

// page describes one fetched URL and what it links to.
func (c *crawler) page(exchange probe.Exchange, depth int) Page {
	response := exchange.Response
	page := Page{
		URL: exchange.Request.URL, Depth: depth, Status: response.Status,
		Links: []string{}, Error: failure(response),
	}
	pageURL, err := url.Parse(page.URL)
	if err != nil || !response.Answered() {
		return page
	}
	var found extraction
	if isHTML(response) {
		found = extract(clip(response.Body), pageURL)
	}
	if target := redirectTarget(response, pageURL); target != "" {
		found.links = append([]string{target}, found.links...)
	}
	page.Links = c.acceptLinks(found.links)
	page.Forms = c.acceptForms(found.forms)
	return page
}

// failure explains why a response does not count as the target's answer.
func failure(response probe.Response) string {
	switch {
	case response.Error != "":
		return response.Error
	case response.Gate != "":
		return "the egress gate answered instead of the target: " + response.Gate
	case response.Status <= 0:
		return "no HTTP response was received"
	}
	return ""
}

func clip(body string) string {
	if len(body) > maxBodyBytes {
		return body[:maxBodyBytes]
	}
	return body
}

// acceptLinks keeps the links worth following: http(s), not a static asset,
// in scope, each once. The cap applies in document order before sorting, so
// which links survive it does not depend on how they sort.
func (c *crawler) acceptLinks(candidates []string) []string {
	accepted := []string{}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if len(accepted) == MaxLinksPerPage {
			break
		}
		target, ok := normalise(candidate)
		if !ok || seen[target] {
			continue
		}
		seen[target] = true
		if isStaticAsset(target) || !c.opts.InScope(target) {
			continue
		}
		accepted = append(accepted, target)
	}
	slices.Sort(accepted)
	return accepted
}

// acceptForms keeps the forms that submit to an in-scope URL. A form that
// posts somewhere else is not part of the application being tested.
func (c *crawler) acceptForms(forms []Form) []Form {
	var accepted []Form
	for _, form := range forms {
		action, ok := normalise(form.Action)
		if !ok || !c.opts.InScope(action) {
			continue
		}
		form.Action = action
		accepted = append(accepted, form)
	}
	return accepted
}

// isHTML reports whether a response says it is an HTML document. Anything
// else (JSON, images, downloads) is not searched for links.
func isHTML(response probe.Response) bool {
	mediaType, _, _ := strings.Cut(header(response, "Content-Type"), ";")
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "text/html", "application/xhtml+xml":
		return true
	}
	return false
}

// redirectTarget returns where a 3xx response points, resolved against the
// page. The probe never follows redirects, so the crawler treats the target
// as one more link and the scope check applies to it like to any other.
func redirectTarget(response probe.Response, pageURL *url.URL) string {
	if response.Status < 300 || response.Status > 399 {
		return ""
	}
	return resolve(pageURL, header(response, "Location"))
}

// header returns the first value of a response header. Names are compared
// without regard to case because the map may come from JSON, not net/http.
func header(response probe.Response, name string) string {
	for key, values := range response.Headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
