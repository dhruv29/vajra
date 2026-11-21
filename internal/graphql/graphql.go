// Package graphql checks a GraphQL endpoint for two common weaknesses:
// introspection that anonymous clients can use to read the whole schema, and
// an endpoint the operator expects to require authentication that answers
// anonymous queries anyway.
//
// Only read-only queries are sent; nothing here ever issues a mutation.
package graphql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

const (
	// Source is the value of Finding.Source for results from this package.
	Source = "vajra-graphql"

	ruleIntrospection   = "graphql-introspection-enabled"
	ruleAuthNotEnforced = "graphql-auth-not-enforced"

	introspectionQuery = `{"query":"{__schema{queryType{name} types{name kind}}}"}`
	typenameQuery      = `{"query":"{__typename}"}`

	idIntrospectionAnon = "introspection-anonymous"
	idTypenameAnon      = "typename-anonymous"
	idIntrospectionAuth = "introspection-authenticated"
)

// Options configures a Tester.
type Options struct {
	// Endpoint is the full URL of the GraphQL endpoint, http(s), required.
	Endpoint string
	// Headers are optional credentials of a test account.
	Headers map[string]string
	// RequiresAuth says the operator expects the endpoint to refuse anonymous
	// queries.
	RequiresAuth bool
}

// Tester runs the checks against one endpoint.
type Tester struct {
	fetcher      probe.Fetcher
	endpoint     string
	headers      map[string]string
	requiresAuth bool
	// byFinding remembers the request and rule behind each finding, for
	// re-testing.
	byFinding map[string]attempt
}

type attempt struct {
	rule    string
	request probe.Request
}

// New validates the options and prepares a tester.
func New(fetcher probe.Fetcher, opts Options) (*Tester, error) {
	if fetcher == nil {
		return nil, errors.New("graphql: a fetcher is required")
	}
	endpoint := strings.TrimSpace(opts.Endpoint)
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("graphql: endpoint %q must be an http(s) URL with a host", endpoint)
	}
	// Credentials in the URL would end up in evidence with it.
	if u.User != nil {
		return nil, errors.New("graphql: the endpoint URL may not carry a user name or password")
	}
	headers := make(map[string]string, len(opts.Headers))
	for name, value := range opts.Headers {
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("graphql: a header name is empty")
		}
		headers[name] = value
	}
	return &Tester{
		fetcher: fetcher, endpoint: endpoint, headers: headers,
		requiresAuth: opts.RequiresAuth, byFinding: map[string]attempt{},
	}, nil
}

// SecretHeaders returns the names of the configured headers, for redaction.
func (t *Tester) SecretHeaders() []string {
	out := make([]string, 0, len(t.headers))
	for name := range t.headers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (t *Tester) request(id, body string, withCredentials bool) probe.Request {
	headers := map[string]string{"Content-Type": "application/json"}
	if withCredentials {
		for name, value := range t.headers {
			headers[name] = value
		}
	}
	return probe.Request{ID: id, Method: http.MethodPost, URL: t.endpoint, Headers: headers, Body: body}
}

// Run sends the checks in one batch and returns a candidate finding for each
// weakness the anonymous requests show.
func (t *Tester) Run(ctx context.Context) ([]finding.Finding, error) {
	requests := []probe.Request{
		t.request(idIntrospectionAnon, introspectionQuery, false),
		t.request(idTypenameAnon, typenameQuery, false),
	}
	// The authenticated introspection is sent so the exchange is on record,
	// but introspection open to a signed-in account is not a finding.
	if len(t.headers) > 0 {
		requests = append(requests, t.request(idIntrospectionAuth, introspectionQuery, true))
	}
	responses, err := t.fetcher.Do(ctx, requests)
	if err != nil {
		return nil, fmt.Errorf("graphql: %w", err)
	}
	if len(responses) != len(requests) {
		return nil, fmt.Errorf("graphql: %d responses for %d requests", len(responses), len(requests))
	}
	findings := []finding.Finding{}
	if count, ok := schemaOpen(responses[0]); ok {
		findings = append(findings, t.record(ruleIntrospection, requests[0], responses[0], fmt.Sprintf("%d types listed", count)))
	}
	if t.requiresAuth && typenameAnswered(responses[1]) {
		findings = append(findings, t.record(ruleAuthNotEnforced, requests[1], responses[1], ""))
	}
	return findings, nil
}

func (t *Tester) record(rule string, req probe.Request, resp probe.Response, extracted string) finding.Finding {
	f := finding.Finding{
		ID:     finding.StableID(Source, rule, t.endpoint, ""),
		Kind:   finding.Dynamic,
		Source: Source,
		RuleID: rule,
		Target: t.endpoint,
		Tags:   []string{"graphql", "api"},
		Status: finding.Candidate,
		Evidence: finding.Evidence{
			Request:   probe.FormatRequest(req, t.SecretHeaders()),
			Response:  probe.FormatResponse(resp),
			MatchedAt: t.endpoint,
		},
	}
	switch rule {
	case ruleIntrospection:
		f.Title = "GraphQL introspection is open to anonymous clients"
		f.Description = "An introspection query sent without credentials was answered with the schema. " +
			"Anyone can read every type and field the API offers, which maps its attack surface. " +
			"Introspection should be disabled in production or limited to authenticated clients."
		f.Severity = finding.SeverityLow
		f.CWE = []string{"cwe-200"}
		f.Evidence.Extracted = []string{extracted}
	default:
		f.Title = "GraphQL endpoint answers queries without authentication"
		f.Description = "The operator stated that this endpoint requires authentication, but a query " +
			"sent without credentials was answered with data."
		f.Severity = finding.SeverityHigh
		f.CWE = []string{"cwe-306"}
	}
	t.byFinding[f.ID] = attempt{rule: rule, request: req}
	return f
}

// envelope is the part of a GraphQL response the checks look at.
type envelope struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []json.RawMessage          `json:"errors"`
}

// decode returns the data of a clean, successful GraphQL answer: a 2xx from
// the target itself, a complete JSON body, data present and no errors.
func decode(r probe.Response) (map[string]json.RawMessage, bool) {
	if !r.Answered() || r.Status < http.StatusOK || r.Status >= http.StatusMultipleChoices ||
		r.BodyTruncated || len(r.Body) > probe.MaxBodyBytes {
		return nil, false
	}
	var env envelope
	if err := json.Unmarshal([]byte(r.Body), &env); err != nil || env.Data == nil || len(env.Errors) > 0 {
		return nil, false
	}
	return env.Data, true
}

// schemaOpen reports whether r carries a non-null __schema object, and how
// many types it lists.
func schemaOpen(r probe.Response) (int, bool) {
	data, ok := decode(r)
	if !ok {
		return 0, false
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(data["__schema"], &schema); err != nil || schema == nil {
		return 0, false
	}
	var types []json.RawMessage
	_ = json.Unmarshal(schema["types"], &types) // a schema without a types list still counts, as 0
	return len(types), true
}

// typenameAnswered reports whether r answers {__typename} with a name.
func typenameAnswered(r probe.Response) bool {
	data, ok := decode(r)
	if !ok {
		return false
	}
	var name string
	return json.Unmarshal(data["__typename"], &name) == nil && name != ""
}

// Reproduce repeats the request behind f and applies the same condition. A
// target that does not answer is an error, not a miss.
func (t *Tester) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	a, ok := t.byFinding[f.ID]
	if !ok {
		return false, errors.New("graphql: this finding was not produced by this tester")
	}
	responses, err := t.fetcher.Do(ctx, []probe.Request{a.request})
	if err != nil {
		return false, fmt.Errorf("graphql: %w", err)
	}
	if len(responses) != 1 {
		return false, fmt.Errorf("graphql: %d responses for 1 request", len(responses))
	}
	if !responses[0].Answered() {
		return false, fmt.Errorf("graphql: %s did not answer, so the finding could not be re-tested", t.endpoint)
	}
	if a.rule == ruleIntrospection {
		_, open := schemaOpen(responses[0])
		return open, nil
	}
	return typenameAnswered(responses[0]), nil
}
