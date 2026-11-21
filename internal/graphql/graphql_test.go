package graphql

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

const (
	endpoint = "https://api.test/graphql"
	token    = "Bearer s3cr3t-t0ken"

	schemaBody   = `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"},{"name":"String","kind":"SCALAR"}]}}}`
	typenameBody = `{"data":{"__typename":"Query"}}`
	disabledBody = `{"errors":[{"message":"introspection is disabled"}]}`
)

// fakeGraphQL answers each request by the query in its body and whether it
// carries credentials, and records every batch.
type fakeGraphQL struct {
	introspection, authIntrospection, typename probe.Response
	batches                                    [][]probe.Request
	err                                        error
	short                                      bool
}

func (f *fakeGraphQL) Do(_ context.Context, requests []probe.Request) ([]probe.Response, error) {
	f.batches = append(f.batches, slices.Clone(requests))
	if f.err != nil {
		return nil, f.err
	}
	out := make([]probe.Response, 0, len(requests))
	for _, r := range requests {
		var resp probe.Response
		switch {
		case strings.Contains(r.Body, "__typename"):
			resp = f.typename
		case r.Headers["Authorization"] != "":
			resp = f.authIntrospection
		default:
			resp = f.introspection
		}
		resp.ID = r.ID
		out = append(out, resp)
	}
	if f.short {
		out = out[:len(out)-1]
	}
	return out, nil
}

func ok(body string) probe.Response { return probe.Response{Status: 200, Body: body} }

func denied() probe.Response {
	return probe.Response{Status: 401, Body: `{"errors":[{"message":"unauthorized"}]}`}
}

func newTester(t *testing.T, f probe.Fetcher, opts Options) *Tester {
	t.Helper()
	if opts.Endpoint == "" {
		opts.Endpoint = endpoint
	}
	tester, err := New(f, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tester
}

func run(t *testing.T, tester *Tester) []finding.Finding {
	t.Helper()
	findings, err := tester.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func rules(fs []finding.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestIntrospectionOpenIsReported(t *testing.T) {
	fake := &fakeGraphQL{introspection: ok(schemaBody), typename: ok(typenameBody)}
	findings := run(t, newTester(t, fake, Options{}))
	if len(findings) != 1 {
		t.Fatalf("want one finding, got %v", rules(findings))
	}
	f := findings[0]
	want := finding.Finding{
		ID: finding.StableID(Source, ruleIntrospection, endpoint, ""), Kind: finding.Dynamic, Source: Source,
		RuleID: ruleIntrospection, Severity: finding.SeverityLow, Target: endpoint, Status: finding.Candidate,
	}
	if f.ID != want.ID || f.Kind != want.Kind || f.Source != want.Source || f.RuleID != want.RuleID ||
		f.Severity != want.Severity || f.Target != want.Target || f.Status != want.Status {
		t.Errorf("finding = %+v", f)
	}
	if f.Title != "GraphQL introspection is open to anonymous clients" || !strings.Contains(f.Description, "production") {
		t.Errorf("title/description = %q / %q", f.Title, f.Description)
	}
	if !slices.Equal(f.CWE, []string{"cwe-200"}) || !slices.Equal(f.Tags, []string{"graphql", "api"}) {
		t.Errorf("cwe/tags = %v %v", f.CWE, f.Tags)
	}
	if !slices.Equal(f.Evidence.Extracted, []string{"3 types listed"}) {
		t.Errorf("extracted = %v", f.Evidence.Extracted)
	}
	if f.Evidence.MatchedAt != endpoint || !strings.HasPrefix(f.Evidence.Request, "POST "+endpoint) ||
		!strings.Contains(f.Evidence.Request, "__schema") || !strings.HasPrefix(f.Evidence.Response, "HTTP 200") {
		t.Errorf("evidence = %+v", f.Evidence)
	}
}

func TestAuthNotEnforcedIsReportedOnlyWhenRequired(t *testing.T) {
	fake := &fakeGraphQL{introspection: ok(disabledBody), typename: ok(typenameBody)}
	findings := run(t, newTester(t, fake, Options{RequiresAuth: true}))
	if !slices.Equal(rules(findings), []string{ruleAuthNotEnforced}) {
		t.Fatalf("rules = %v", rules(findings))
	}
	f := findings[0]
	if f.Severity != finding.SeverityHigh || !slices.Equal(f.CWE, []string{"cwe-306"}) ||
		f.Title != "GraphQL endpoint answers queries without authentication" ||
		f.ID != finding.StableID(Source, ruleAuthNotEnforced, endpoint, "") || !strings.Contains(f.Evidence.Request, "__typename") {
		t.Errorf("finding = %+v", f)
	}

	if got := run(t, newTester(t, fake, Options{})); len(got) != 0 {
		t.Errorf("RequiresAuth false: got %v", rules(got))
	}
}

func TestBothRules(t *testing.T) {
	fake := &fakeGraphQL{introspection: ok(schemaBody), typename: ok(typenameBody)}
	got := rules(run(t, newTester(t, fake, Options{RequiresAuth: true})))
	if !slices.Equal(got, []string{ruleIntrospection, ruleAuthNotEnforced}) {
		t.Errorf("rules = %v", got)
	}
}

func TestNegativeResponses(t *testing.T) {
	cases := map[string]probe.Response{
		"introspection disabled": ok(disabledBody),
		"401":                    {Status: 401, Body: schemaBody},
		"403":                    {Status: 403, Body: schemaBody},
		"404":                    {Status: 404, Body: schemaBody},
		"302":                    {Status: 302, Body: schemaBody},
		"not json":               ok("<html>" + schemaBody),
		"data null":              ok(`{"data":null}`),
		"schema null":            ok(`{"data":{"__schema":null}}`),
		"schema not object":      ok(`{"data":{"__schema":"yes"}}`),
		"typename empty":         ok(`{"data":{"__typename":""}}`),
		"typename not string":    ok(`{"data":{"__typename":7}}`),
		"errors with data": ok(`{"data":{"__schema":{"types":[]},"__typename":"Query"},
			"errors":[{"message":"partial"}]}`),
		"gate":      {Status: 200, Body: schemaBody, Gate: "denied"},
		"error":     {Status: 200, Body: schemaBody, Error: "connection reset"},
		"truncated": {Status: 200, Body: schemaBody, BodyTruncated: true},
		"too large": ok(`{"data":{"__typename":"Query"},"pad":"` + strings.Repeat("a", probe.MaxBodyBytes) + `"}`),
		"empty":     {},
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeGraphQL{introspection: resp, typename: resp, authIntrospection: resp}
			got := run(t, newTester(t, fake, Options{RequiresAuth: true, Headers: map[string]string{"Authorization": token}}))
			if len(got) != 0 {
				t.Errorf("got %v", rules(got))
			}
		})
	}
}

func TestEmptyErrorsArrayDoesNotHide(t *testing.T) {
	fake := &fakeGraphQL{introspection: ok(disabledBody), typename: ok(`{"data":{"__typename":"Query"},"errors":[]}`)}
	if got := rules(run(t, newTester(t, fake, Options{RequiresAuth: true}))); len(got) != 1 {
		t.Errorf("rules = %v", got)
	}
}

func TestAuthenticatedIntrospectionAloneIsNotAFinding(t *testing.T) {
	fake := &fakeGraphQL{introspection: denied(), typename: denied(), authIntrospection: ok(schemaBody)}
	got := run(t, newTester(t, fake, Options{RequiresAuth: true, Headers: map[string]string{"Authorization": token}}))
	if len(got) != 0 {
		t.Errorf("got %v", rules(got))
	}
}

func TestRequestsAndCredentials(t *testing.T) {
	headers := map[string]string{"Authorization": token, "X-Api-Key": "k3y-value"}
	fake := &fakeGraphQL{introspection: ok(schemaBody), typename: ok(typenameBody), authIntrospection: ok(schemaBody)}
	tester := newTester(t, fake, Options{RequiresAuth: true, Headers: headers})
	findings := run(t, tester)
	if len(fake.batches) != 1 || len(fake.batches[0]) != 3 {
		t.Fatalf("batches = %v", fake.batches)
	}
	for i, r := range fake.batches[0] {
		if r.Method != "POST" || r.URL != endpoint || r.Headers["Content-Type"] != "application/json" || !json.Valid([]byte(r.Body)) {
			t.Errorf("request %d = %+v", i, r)
		}
		authed := r.Headers["Authorization"] == token && r.Headers["X-Api-Key"] == "k3y-value"
		if wantAuth := i == 2; authed != wantAuth {
			t.Errorf("request %d carries credentials = %v, want %v", i, authed, wantAuth)
		}
		if i < 2 && len(r.Headers) != 1 {
			t.Errorf("anonymous request %d has headers %v", i, r.Headers)
		}
	}
	if fake.batches[0][0].Body != introspectionQuery || fake.batches[0][1].Body != typenameQuery ||
		fake.batches[0][2].Body != introspectionQuery {
		t.Errorf("bodies = %q %q %q", fake.batches[0][0].Body, fake.batches[0][1].Body, fake.batches[0][2].Body)
	}
	raw, _ := json.Marshal(findings)
	for _, secret := range []string{token, "s3cr3t", "k3y-value"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("finding JSON contains %q", secret)
		}
	}
	if got := tester.SecretHeaders(); !slices.Equal(got, []string{"Authorization", "X-Api-Key"}) {
		t.Errorf("SecretHeaders = %v", got)
	}

	anon := &fakeGraphQL{introspection: ok(schemaBody), typename: ok(typenameBody)}
	run(t, newTester(t, anon, Options{}))
	if len(anon.batches) != 1 || len(anon.batches[0]) != 2 {
		t.Errorf("without headers want 2 requests in one call, got %v", anon.batches)
	}
}

func TestRunErrors(t *testing.T) {
	_, err := newTester(t, &fakeGraphQL{err: errors.New("sandbox down")}, Options{}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sandbox down") {
		t.Errorf("err = %v", err)
	}
	_, err = newTester(t, &fakeGraphQL{short: true}, Options{}).Run(context.Background())
	if err == nil {
		t.Error("short response list: want error")
	}
}

func TestReproduce(t *testing.T) {
	fake := &fakeGraphQL{introspection: ok(schemaBody), typename: ok(typenameBody)}
	tester := newTester(t, fake, Options{RequiresAuth: true})
	findings := run(t, tester)
	if len(findings) != 2 {
		t.Fatalf("findings = %v", rules(findings))
	}
	ctx := context.Background()
	for _, f := range findings {
		fake.batches = nil
		got, err := tester.Reproduce(ctx, f)
		if err != nil || !got {
			t.Errorf("%s: Reproduce = %v, %v", f.RuleID, got, err)
		}
		if len(fake.batches) != 1 || len(fake.batches[0]) != 1 {
			t.Errorf("%s: batches = %v", f.RuleID, fake.batches)
		}
	}

	fake.introspection, fake.typename = ok(disabledBody), denied()
	for _, f := range findings {
		if got, err := tester.Reproduce(ctx, f); err != nil || got {
			t.Errorf("%s fixed: Reproduce = %v, %v", f.RuleID, got, err)
		}
	}

	fake.introspection = probe.Response{Gate: "failed"}
	if _, err := tester.Reproduce(ctx, findings[0]); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("unanswered: err = %v", err)
	}

	fake.err = errors.New("sandbox down")
	if _, err := tester.Reproduce(ctx, findings[0]); err == nil || !strings.Contains(err.Error(), "sandbox down") {
		t.Errorf("fetch error: err = %v", err)
	}
	fake.err = nil

	fake.short = true
	if _, err := tester.Reproduce(ctx, findings[0]); err == nil {
		t.Error("no response: want error")
	}

	if _, err := tester.Reproduce(ctx, finding.Finding{ID: "other"}); err == nil {
		t.Error("unknown finding: want error")
	}
}

func TestNewValidation(t *testing.T) {
	fake := &fakeGraphQL{}
	if _, err := New(nil, Options{Endpoint: endpoint}); err == nil {
		t.Error("nil fetcher accepted")
	}
	for _, bad := range []string{"", "ftp://api.test/graphql", "api.test/graphql", "https:///graphql",
		"https://user:pw@api.test/graphql", "https://user@api.test/graphql", "http://[::1", "https://:443/graphql"} {
		if _, err := New(fake, Options{Endpoint: bad}); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
	if _, err := New(fake, Options{Endpoint: endpoint, Headers: map[string]string{" ": "x"}}); err == nil {
		t.Error("empty header name accepted")
	}
	for _, good := range []string{"http://api.test/graphql", " https://api.test:8443/q ", "http://[::1]:8080/graphql"} {
		if _, err := New(fake, Options{Endpoint: good}); err != nil {
			t.Errorf("endpoint %q rejected: %v", good, err)
		}
	}
	tester := newTester(t, fake, Options{Endpoint: " https://api.test/graphql "})
	if tester.endpoint != endpoint {
		t.Errorf("endpoint not trimmed: %q", tester.endpoint)
	}
	if got := tester.SecretHeaders(); len(got) != 0 {
		t.Errorf("SecretHeaders = %v", got)
	}
}
