package apitest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/openapi"
	"github.com/dhruv29/vajra/internal/probe"
)

const (
	baseURL   = "https://api.test/v1"
	ordersURL = baseURL + "/orders"
	meURL     = baseURL + "/me"
)

// ordersSpec protects each operation on its own; /status declares nothing and
// /health says outright that it is public.
const ordersSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "Orders"},
  "paths": {
    "/status": {"get": {"operationId": "status"}},
    "/health": {"get": {"operationId": "health", "security": []}},
    "/me": {"head": {"operationId": "headMe", "security": [{"bearer": []}]}},
    "/orders": {
      "get": {"operationId": "listOrders", "security": [{"bearer": []}]},
      "post": {"operationId": "createOrder", "security": [{"bearer": []}],
        "requestBody": {"content": {"application/json": {"example": {"item": "book"}}}}}
    },
    "/orders/{id}": {
      "get": {"operationId": "getOrder", "security": [{"bearer": []}],
        "parameters": [{"name": "id", "in": "path", "required": true}]},
      "delete": {"operationId": "deleteOrder", "security": [{"bearer": []}]}
    }
  }
}`

// fakeAPI answers by URL and records every batch it was sent.
type fakeAPI struct {
	pages map[string]probe.Response
	// otherwise answers any URL not in pages; the zero value means 401.
	otherwise probe.Response
	batches   [][]probe.Request
	err       error
	// healthyCalls is how many calls succeed before err is returned.
	healthyCalls int
}

func (a *fakeAPI) Do(_ context.Context, requests []probe.Request) ([]probe.Response, error) {
	a.batches = append(a.batches, slices.Clone(requests))
	if a.err != nil && len(a.batches) > a.healthyCalls {
		return nil, a.err
	}
	out := make([]probe.Response, 0, len(requests))
	for _, r := range requests {
		resp, ok := a.pages[r.URL]
		if !ok {
			resp = a.otherwise
		}
		if resp.Status == 0 && resp.Error == "" {
			resp = probe.Response{Status: 401, Body: `{"error":"unauthorized"}`}
		}
		resp.ID = r.ID
		out = append(out, resp)
	}
	return out, nil
}

// sent lists every request made, as "METHOD URL".
func (a *fakeAPI) sent() []string {
	out := []string{}
	for _, batch := range a.batches {
		for _, r := range batch {
			out = append(out, r.Method+" "+r.URL)
		}
	}
	return out
}

func ok(body string) probe.Response { return probe.Response{Status: 200, Body: body} }

func serving(pages map[string]probe.Response) *fakeAPI { return &fakeAPI{pages: pages} }

func parse(t *testing.T, spec string) openapi.Document {
	t.Helper()
	doc, err := openapi.Parse(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func tester(t *testing.T, api *fakeAPI, spec string, params map[string]string) *Tester {
	t.Helper()
	tt, err := New(api, parse(t, spec), baseURL, params)
	if err != nil {
		t.Fatal(err)
	}
	return tt
}

func skippedReason(tt *Tester, operation string) string {
	for _, s := range tt.Skipped {
		if s.Operation == operation {
			return s.Reason
		}
	}
	return ""
}

func TestOnlyProtectedReadOnlyOperationsAreRequested(t *testing.T) {
	api := serving(nil)
	tt := tester(t, api, ordersSpec, nil)

	findings, err := tt.Run(context.Background())

	if err != nil || len(findings) != 0 {
		t.Fatalf("findings = %+v, err = %v; every request was refused", findings, err)
	}
	if want := []string{"HEAD " + meURL, "GET " + ordersURL}; !slices.Equal(api.sent(), want) {
		t.Fatalf("requests = %v; want %v (not the public /status and /health, nothing that changes data)", api.sent(), want)
	}
	if len(api.batches) != 1 {
		t.Fatalf("fetcher calls = %d; want one batch", len(api.batches))
	}
}

func TestAProtectedOperationServedAnonymouslyIsACandidateFinding(t *testing.T) {
	api := serving(map[string]probe.Response{
		ordersURL: {Status: 200, Body: `[{"id":1}]`, Headers: map[string][]string{"Content-Type": {"application/json"}}},
	})
	tt := tester(t, api, ordersSpec, nil)

	findings, err := tt.Run(context.Background())

	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %+v, err = %v; want exactly the order list", findings, err)
	}
	f := findings[0]
	if f.ID != finding.StableID("vajra-api", "auth-not-enforced", "GET /orders", "") || f.Kind != finding.Dynamic ||
		f.Source != "vajra-api" || Source != "vajra-api" || f.RuleID != "auth-not-enforced" ||
		f.Severity != finding.SeverityHigh || f.Status != finding.Candidate || f.Target != ordersURL || f.Location != nil {
		t.Fatalf("finding = %+v", f)
	}
	if !slices.Equal(f.CWE, []string{"cwe-306"}) || !slices.Equal(f.Tags, []string{"api", "access-control"}) {
		t.Fatalf("cwe = %v, tags = %v", f.CWE, f.Tags)
	}
	if f.Title != "GET /orders answers without authentication" ||
		f.Description != `The API description says "listOrders" requires authentication, but a request with no credentials was answered with HTTP 200.` {
		t.Fatalf("title = %q, description = %q", f.Title, f.Description)
	}
	want := finding.Evidence{
		Request:   "GET " + ordersURL + "\n",
		Response:  "HTTP 200\nContent-Type: application/json\n\n[{\"id\":1}]",
		MatchedAt: ordersURL,
		Matcher:   "listOrders",
	}
	if got := f.Evidence; got.Request != want.Request || got.Response != want.Response || got.MatchedAt != want.MatchedAt ||
		got.Matcher != want.Matcher || got.ScanInput != "" || got.Extracted != nil || got.Code != "" || got.Trace != nil {
		t.Fatalf("evidence = %+v\nwant       %+v", got, want)
	}
}

func TestEveryServedOperationIsReportedInDocumentOrder(t *testing.T) {
	api := serving(map[string]probe.Response{ordersURL: ok("orders"), meURL: {Status: 204}})
	tt := tester(t, api, ordersSpec, nil)

	findings, err := tt.Run(context.Background())

	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %+v, err = %v", findings, err)
	}
	if findings[0].Evidence.Matcher != "headMe" || findings[0].Title != "HEAD /me answers without authentication" ||
		findings[0].Target != meURL || !strings.Contains(findings[0].Description, "HTTP 204") ||
		findings[1].Evidence.Matcher != "listOrders" || findings[0].ID == findings[1].ID {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestOnlyASuccessFromTheTargetItselfIsAFinding(t *testing.T) {
	cases := map[string]struct {
		response probe.Response
		want     bool
	}{
		"200 OK":                           {probe.Response{Status: 200, Body: "orders"}, true},
		"201 Created":                      {probe.Response{Status: 201}, true},
		"204 No Content":                   {probe.Response{Status: 204}, true},
		"206 Partial Content":              {probe.Response{Status: 206, Body: "ord"}, true},
		"299 at the top of the range":      {probe.Response{Status: 299}, true},
		"101 below the range":              {probe.Response{Status: 101}, false},
		"199 below the range":              {probe.Response{Status: 199}, false},
		"300 above the range":              {probe.Response{Status: 300}, false},
		"302 redirect to a login page":     {probe.Response{Status: 302, Headers: map[string][]string{"Location": {"/login"}}}, false},
		"401 Unauthorized":                 {probe.Response{Status: 401}, false},
		"403 Forbidden":                    {probe.Response{Status: 403}, false},
		"404 Not Found":                    {probe.Response{Status: 404, Body: "not found"}, false},
		"500 Internal Server Error":        {probe.Response{Status: 500}, false},
		"gate denied with its own page":    {probe.Response{Status: 200, Body: "blocked", Gate: "denied"}, false},
		"gate could not reach the target":  {probe.Response{Status: 502, Gate: "failed"}, false},
		"no response at all":               {probe.Response{Error: "connection refused"}, false},
		"error alongside a success status": {probe.Response{Status: 200, Error: "body read failed"}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			api := serving(map[string]probe.Response{ordersURL: tc.response})
			tt := tester(t, api, ordersSpec, nil)

			findings, err := tt.Run(context.Background())

			if err != nil || findings == nil {
				t.Fatalf("findings = %v, err = %v", findings, err)
			}
			if got := len(findings) == 1; got != tc.want || len(findings) > 1 {
				t.Fatalf("findings = %+v; want a finding: %v", findings, tc.want)
			}
		})
	}
}

func TestOperationsThatChangeDataAreNeverSentAndAreListedAsSkipped(t *testing.T) {
	api := &fakeAPI{otherwise: ok("served")}
	tt := tester(t, api, ordersSpec, map[string]string{"id": "42"})

	findings, err := tt.Run(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	for _, request := range api.sent() {
		if method, _, _ := strings.Cut(request, " "); method != "GET" && method != "HEAD" {
			t.Fatalf("%s was sent; requests = %v", method, api.sent())
		}
	}
	for _, f := range findings {
		if f.Evidence.Matcher == "createOrder" || f.Evidence.Matcher == "deleteOrder" {
			t.Fatalf("a finding was reported for an operation that was never requested: %+v", f)
		}
	}
	want := []openapi.Skipped{
		{Operation: "createOrder", Reason: "POST may change data; set IncludeUnsafe to send it"},
		{Operation: "deleteOrder", Reason: "DELETE may change data; set IncludeUnsafe to send it"},
	}
	if !slices.Equal(tt.Skipped, want) {
		t.Fatalf("skipped = %+v; want %+v", tt.Skipped, want)
	}
}

func TestEveryMethodThatChangesDataIsLeftOut(t *testing.T) {
	const spec = `{"openapi":"3.1.0","info":{"title":"t"},"security":[{"key":[]}],"paths":{"/thing":{
		"get":{"operationId":"read"},"head":{"operationId":"peek"},"options":{"operationId":"ask"},
		"post":{"operationId":"create"},"put":{"operationId":"replace"},"patch":{"operationId":"change"},
		"delete":{"operationId":"remove"},"trace":{"operationId":"echo"}}}}`
	api := &fakeAPI{otherwise: ok("served")}
	tt := tester(t, api, spec, nil)

	findings, err := tt.Run(context.Background())

	// OPTIONS is not requested either: servers answer preflight requests
	// without credentials by design.
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %+v, err = %v; want GET and HEAD", findings, err)
	}
	thing := baseURL + "/thing"
	if want := []string{"GET " + thing, "HEAD " + thing}; !slices.Equal(api.sent(), want) {
		t.Fatalf("requests = %v; want %v", api.sent(), want)
	}
	for _, operation := range []string{"create", "replace", "change", "remove"} {
		if reason := skippedReason(tt, operation); !strings.Contains(reason, "may change data") {
			t.Errorf("%s: skipped reason = %q", operation, reason)
		}
	}
	if reason := skippedReason(tt, "echo"); reason != "the probe does not send TRACE requests" || len(tt.Skipped) != 5 {
		t.Fatalf("TRACE reason = %q, skipped = %+v", reason, tt.Skipped)
	}
}

func TestAPathParameterWithoutAValueIsSkippedWithAReason(t *testing.T) {
	api := &fakeAPI{otherwise: ok("served")}
	tt := tester(t, api, ordersSpec, nil)

	findings, err := tt.Run(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	if reason := skippedReason(tt, "getOrder"); reason != `no value for path parameter "id"` {
		t.Fatalf("reason = %q; skipped = %+v", reason, tt.Skipped)
	}
	for _, request := range api.sent() {
		if strings.Contains(request, "/orders/") {
			t.Fatalf("%s was requested without a value for {id}", request)
		}
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v; the other protected operations are still tested", findings)
	}
}

func TestAPathParameterIsFilledFromParamsOrTheDescriptionsExample(t *testing.T) {
	const exampleSpec = `{"openapi":"3.0.3","info":{"title":"t"},"security":[{"key":[]}],"paths":{"/orders/{id}":{"get":{
		"operationId":"getOrder","parameters":[{"name":"id","in":"path","required":true,"example":7}]}}}}`
	cases := map[string]struct {
		spec    string
		params  map[string]string
		wantURL string
	}{
		"value from params":                {ordersSpec, map[string]string{"id": "42"}, baseURL + "/orders/42"},
		"value from params is escaped":     {ordersSpec, map[string]string{"id": "a/b c"}, baseURL + "/orders/a%2Fb%20c"},
		"example from the description":     {exampleSpec, nil, baseURL + "/orders/7"},
		"params win over the example":      {exampleSpec, map[string]string{"id": "42"}, baseURL + "/orders/42"},
		"unrelated params leave the route": {exampleSpec, map[string]string{"other": "x"}, baseURL + "/orders/7"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			api := serving(map[string]probe.Response{tc.wantURL: ok("order")})
			tt := tester(t, api, tc.spec, tc.params)

			findings, err := tt.Run(context.Background())

			if err != nil || len(findings) != 1 {
				t.Fatalf("findings = %+v, err = %v; requests = %v", findings, err, api.sent())
			}
			f := findings[0]
			if f.Target != tc.wantURL || f.Evidence.MatchedAt != tc.wantURL || f.Evidence.Request != "GET "+tc.wantURL+"\n" ||
				f.Evidence.Matcher != "getOrder" || f.Title != "GET /orders/{id} answers without authentication" {
				t.Fatalf("finding = %+v", f)
			}
			if f.ID != finding.StableID(Source, ruleAuthNotEnforced, "GET /orders/{id}", "") {
				t.Fatalf("id = %q; the ID must come from the route, not the value substituted into it", f.ID)
			}
			if skippedReason(tt, "getOrder") != "" {
				t.Fatalf("skipped = %+v", tt.Skipped)
			}
		})
	}
}

func TestQueryParametersAreSentAsTheDescriptionAsks(t *testing.T) {
	const spec = `{"openapi":"3.0.3","info":{"title":"t"},"paths":{"/search":{"get":{"operationId":"search",
		"security":[{"key":[]}],"parameters":[{"name":"q","in":"query","required":true,"example":"book"},
		{"name":"page","in":"query"}]}}}}`
	wantURL := baseURL + "/search?q=book"
	api := serving(map[string]probe.Response{wantURL: ok("results")})
	tt := tester(t, api, spec, nil)

	findings, err := tt.Run(context.Background())

	if err != nil || len(findings) != 1 || findings[0].Target != wantURL {
		t.Fatalf("findings = %+v, err = %v; requests = %v", findings, err, api.sent())
	}
}

func TestNoCredentialsOrBodiesAreEverSent(t *testing.T) {
	api := &fakeAPI{otherwise: ok("served")}
	tt := tester(t, api, ordersSpec, map[string]string{"id": "42"})

	findings, err := tt.Run(context.Background())
	if err != nil || len(findings) == 0 {
		t.Fatalf("findings = %+v, err = %v", findings, err)
	}
	if _, err := tt.Reproduce(context.Background(), findings[0]); err != nil {
		t.Fatal(err)
	}

	requests := 0
	for _, batch := range api.batches {
		for _, r := range batch {
			requests++
			if len(r.Headers) != 0 || r.Body != "" {
				t.Fatalf("%s %s was sent with headers %v and body %q; the check is anonymous", r.Method, r.URL, r.Headers, r.Body)
			}
		}
	}
	if requests != 4 {
		t.Fatalf("requests = %v; want three from the run and one re-test", api.sent())
	}
	for _, f := range findings {
		if strings.Contains(f.Evidence.Request, ":  ") || strings.Count(f.Evidence.Request, "\n") != 1 {
			t.Fatalf("request evidence carries headers: %q", f.Evidence.Request)
		}
	}
}

func TestTheDocumentsDefaultSecurityProtectsOperationsThatDoNotOptOut(t *testing.T) {
	const spec = `{"openapi":"3.0.3","info":{"title":"t"},"security":[{"bearer":[]}],"paths":{
		"/health":{"get":{"operationId":"health","security":[]}},
		"/docs":{"get":{"operationId":"docs","security":[{},{"bearer":[]}]}},
		"/orders":{"get":{"operationId":"listOrders"}},
		"/admin":{"get":{"operationId":"admin","security":[{"bearer":["admin"]}]}}}}`
	api := &fakeAPI{otherwise: ok("served")}
	tt := tester(t, api, spec, nil)

	findings, err := tt.Run(context.Background())

	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %+v, err = %v", findings, err)
	}
	if want := []string{"GET " + baseURL + "/admin", "GET " + ordersURL}; !slices.Equal(api.sent(), want) {
		t.Fatalf("requests = %v; want %v (/health is public, /docs accepts no credentials)", api.sent(), want)
	}
}

// protectedSpec describes count protected GET operations.
func protectedSpec(t *testing.T, count int) string {
	t.Helper()
	paths := map[string]any{}
	for i := range count {
		paths[fmt.Sprintf("/items/%04d", i)] = map[string]any{"get": map[string]any{
			"operationId": fmt.Sprintf("item%04d", i),
			"security":    []any{map[string]any{"key": []any{}}},
		}}
	}
	raw, err := json.Marshal(map[string]any{"openapi": "3.0.3", "info": map[string]any{"title": "Items"}, "paths": paths})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestProtectedOperationsAreSentInBatchesTheProbeAccepts(t *testing.T) {
	cases := map[string]struct {
		operations  int
		wantBatches []int
	}{
		"one under the limit":      {probe.MaxRequests - 1, []int{probe.MaxRequests - 1}},
		"exactly the limit":        {probe.MaxRequests, []int{probe.MaxRequests}},
		"one over the limit":       {probe.MaxRequests + 1, []int{probe.MaxRequests, 1}},
		"two full batches and one": {2*probe.MaxRequests + 1, []int{probe.MaxRequests, probe.MaxRequests, 1}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{otherwise: ok("served")}
			tt := tester(t, api, protectedSpec(t, tc.operations), nil)

			findings, err := tt.Run(context.Background())

			if err != nil {
				t.Fatal(err)
			}
			sizes := make([]int, 0, len(api.batches))
			for _, batch := range api.batches {
				sizes = append(sizes, len(batch))
			}
			if !slices.Equal(sizes, tc.wantBatches) {
				t.Fatalf("batch sizes = %v; want %v", sizes, tc.wantBatches)
			}
			if len(findings) != tc.operations {
				t.Fatalf("findings = %d; want one per served operation (%d)", len(findings), tc.operations)
			}
			ids := map[string]bool{}
			for i, f := range findings {
				if want := fmt.Sprintf("item%04d", i); f.Evidence.Matcher != want || f.Target != fmt.Sprintf("%s/items/%04d", baseURL, i) {
					t.Fatalf("finding %d is for %q at %s; want %q", i, f.Evidence.Matcher, f.Target, want)
				}
				ids[f.ID] = true
			}
			if len(ids) != tc.operations {
				t.Fatalf("distinct finding IDs = %d; want %d", len(ids), tc.operations)
			}
			last := findings[len(findings)-1]
			if still, err := tt.Reproduce(context.Background(), last); err != nil || !still {
				t.Fatalf("re-test of a finding from the last batch: served = %v, err = %v", still, err)
			}
		})
	}
}

func TestAFetcherErrorIsReturned(t *testing.T) {
	sentinel := errors.New("sandbox failed")
	cases := map[string]struct {
		operations, healthyCalls, wantCalls int
	}{
		"on the only batch":  {3, 0, 1},
		"on a later batch":   {probe.MaxRequests + 1, 1, 2},
		"on the first of 2":  {probe.MaxRequests + 1, 0, 1},
		"on the third batch": {2*probe.MaxRequests + 1, 2, 3},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{otherwise: ok("served"), err: sentinel, healthyCalls: tc.healthyCalls}
			tt := tester(t, api, protectedSpec(t, tc.operations), nil)

			findings, err := tt.Run(context.Background())

			if !errors.Is(err, sentinel) || !strings.HasPrefix(err.Error(), "apitest: ") {
				t.Fatalf("err = %v; want the fetcher's error, wrapped", err)
			}
			if findings != nil || len(api.batches) != tc.wantCalls {
				t.Fatalf("findings = %d, fetcher calls = %d; want none and %d", len(findings), len(api.batches), tc.wantCalls)
			}
		})
	}
}

func TestReproduce(t *testing.T) {
	api := serving(map[string]probe.Response{ordersURL: ok("orders")})
	tt := tester(t, api, ordersSpec, nil)
	findings, err := tt.Run(context.Background())
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %+v, err = %v", findings, err)
	}
	api.batches = nil

	still, err := tt.Reproduce(context.Background(), findings[0])
	if err != nil || !still {
		t.Fatalf("still served = %v, err = %v", still, err)
	}
	if want := []string{"GET " + ordersURL}; !slices.Equal(api.sent(), want) || len(api.batches) != 1 {
		t.Fatalf("re-test requests = %v in %d calls; want only %v", api.sent(), len(api.batches), want)
	}

	api.pages[ordersURL] = probe.Response{Status: 204}
	if still, err := tt.Reproduce(context.Background(), findings[0]); err != nil || !still {
		t.Fatalf("served with another 2xx: served = %v, err = %v", still, err)
	}

	for _, status := range []int{401, 403, 302, 404} {
		api.pages[ordersURL] = probe.Response{Status: status}
		fixed, err := tt.Reproduce(context.Background(), findings[0])
		if err != nil || fixed {
			t.Fatalf("now answered with %d: served = %v, err = %v", status, fixed, err)
		}
	}

	unanswered := map[string]probe.Response{
		"gate could not reach the target": {Status: 502, Gate: "failed"},
		"gate denied the request":         {Status: 200, Gate: "denied"},
		"no response":                     {Error: "connection refused"},
	}
	for name, response := range unanswered {
		api.pages[ordersURL] = response
		served, err := tt.Reproduce(context.Background(), findings[0])
		if err == nil || served || !strings.Contains(err.Error(), ordersURL+" did not answer") {
			t.Fatalf("%s: served = %v, err = %v; an unanswered re-test must be an error", name, served, err)
		}
	}

	sentinel := errors.New("sandbox failed")
	api.pages[ordersURL], api.err = ok("orders"), sentinel
	if served, err := tt.Reproduce(context.Background(), findings[0]); !errors.Is(err, sentinel) || served {
		t.Fatalf("served = %v, err = %v; a fetch error was swallowed", served, err)
	}
}

func TestReproduceRefusesAFindingFromElsewhere(t *testing.T) {
	api := serving(map[string]probe.Response{ordersURL: ok("orders")})
	ran := tester(t, api, ordersSpec, nil)
	findings, err := ran.Run(context.Background())
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %+v, err = %v", findings, err)
	}
	fresh := tester(t, api, ordersSpec, nil)
	renamed := findings[0]
	renamed.ID = "0000000000000000"
	api.batches = nil
	cases := map[string]struct {
		tester  *Tester
		finding finding.Finding
	}{
		"unknown ID":                       {ran, finding.Finding{ID: "unknown"}},
		"no ID":                            {ran, finding.Finding{}},
		"tester that has not run":          {fresh, findings[0]},
		"same target under a different ID": {ran, renamed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			served, err := tc.tester.Reproduce(context.Background(), tc.finding)

			if err == nil || served || !strings.Contains(err.Error(), "did not come from the current API description") {
				t.Fatalf("served = %v, err = %v", served, err)
			}
			if len(api.batches) != 0 {
				t.Fatalf("requests = %v; nothing may be sent for a finding from elsewhere", api.sent())
			}
		})
	}
}

func TestAFindingKeepsItsIDAcrossRunsAndStaysReproducible(t *testing.T) {
	api := serving(map[string]probe.Response{ordersURL: ok("orders")})
	tt := tester(t, api, ordersSpec, nil)

	first, err1 := tt.Run(context.Background())
	skippedOnce := slices.Clone(tt.Skipped)
	second, err2 := tt.Run(context.Background())

	if err1 != nil || err2 != nil || len(first) != 1 || len(second) != 1 || first[0].ID != second[0].ID {
		t.Fatalf("first = %+v (%v), second = %+v (%v)", first, err1, second, err2)
	}
	if !slices.Equal(tt.Skipped, skippedOnce) || len(skippedOnce) != 3 {
		t.Fatalf("skipped after two runs = %+v; want the same three as after one", tt.Skipped)
	}
	if still, err := tt.Reproduce(context.Background(), first[0]); err != nil || !still {
		t.Fatalf("served = %v, err = %v", still, err)
	}
}

func TestNewValidation(t *testing.T) {
	doc := parse(t, ordersSpec)
	api := serving(nil)

	if tt, err := New(nil, doc, baseURL, nil); err == nil || tt != nil || !strings.Contains(err.Error(), "a fetcher is required") {
		t.Errorf("nil fetcher: tester = %v, err = %v", tt, err)
	}
	if tt, err := New(api, doc, "", nil); err == nil || tt != nil || !strings.Contains(err.Error(), "must be an http(s) URL") {
		t.Errorf("empty base URL: tester = %v, err = %v", tt, err)
	}
	tt, err := New(api, doc, baseURL, nil)
	if err != nil || tt == nil || len(tt.Skipped) != 0 || len(api.batches) != 0 {
		t.Fatalf("tester = %+v, err = %v, fetcher calls = %d; New must not send anything", tt, err, len(api.batches))
	}
}

func TestTheBaseURLIsJoinedToEachPath(t *testing.T) {
	cases := map[string]struct{ base, wantURL string }{
		"trailing slash":        {"https://api.test/v1/", "https://api.test/v1/orders"},
		"no path":               {"https://api.test", "https://api.test/orders"},
		"port and plain http":   {"http://localhost:8080/api", "http://localhost:8080/api/orders"},
		"surrounding space":     {"  https://api.test/v1 ", "https://api.test/v1/orders"},
		"query string dropped":  {"https://api.test/v1?token=abc", "https://api.test/v1/orders"},
		"fragment also dropped": {"https://api.test/v1#top", "https://api.test/v1/orders"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			api := serving(map[string]probe.Response{tc.wantURL: ok("orders")})
			tt, err := New(api, parse(t, ordersSpec), tc.base, nil)
			if err != nil {
				t.Fatal(err)
			}

			findings, err := tt.Run(context.Background())

			if err != nil || len(findings) != 1 || findings[0].Target != tc.wantURL {
				t.Fatalf("findings = %+v, err = %v; requests = %v", findings, err, api.sent())
			}
		})
	}
}

func TestABaseURLThatIsNotHTTPIsRefused(t *testing.T) {
	for _, base := range []string{"api.test/v1", "ftp://api.test", "https://", "file:///etc/passwd"} {
		t.Run(base, func(t *testing.T) {
			api := &fakeAPI{otherwise: ok("served")}

			tt, err := New(api, parse(t, ordersSpec), base, nil)

			// An unusable base URL must fail loudly: "nothing could be
			// tested" must never look like "nothing was found".
			if err == nil || tt != nil || len(api.batches) != 0 {
				t.Fatalf("tester = %v, err = %v, fetcher calls = %d", tt, err, len(api.batches))
			}
		})
	}
}

func TestRunWithNoProtectedOperationsMakesNoRequests(t *testing.T) {
	cases := map[string]string{
		"no operations":       `{"openapi":"3.0.3","info":{"title":"t"},"paths":{}}`,
		"no paths at all":     `{"openapi":"3.0.3","info":{"title":"t"}}`,
		"only public":         `{"openapi":"3.0.3","info":{"title":"t"},"paths":{"/a":{"get":{}},"/b":{"get":{"security":[]}}}}`,
		"default opted out":   `{"openapi":"3.0.3","info":{"title":"t"},"security":[{"key":[]}],"paths":{"/a":{"get":{"security":[]}}}}`,
		"only unsafe methods": `{"openapi":"3.0.3","info":{"title":"t"},"security":[{"key":[]}],"paths":{"/a":{"post":{},"delete":{}}}}`,
		"only unfilled paths": `{"openapi":"3.0.3","info":{"title":"t"},"security":[{"key":[]}],"paths":{"/a/{id}":{"get":{}}}}`,
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{otherwise: ok("served")}
			tt := tester(t, api, spec, nil)

			findings, err := tt.Run(context.Background())

			if err != nil || findings == nil || len(findings) != 0 {
				t.Fatalf("findings = %#v, err = %v; want an empty, non-nil slice", findings, err)
			}
			if len(api.batches) != 0 {
				t.Fatalf("requests = %v; want none", api.sent())
			}
		})
	}
}

func TestAPublicOperationIsNotMistakenForAProtectedOneSharingItsID(t *testing.T) {
	const spec = `{"openapi":"3.0.3","info":{"title":"t"},"paths":{
		"/a":{"get":{"operationId":"GET /secret"}},
		"/secret":{"get":{"security":[{"key":[]}]}}}}`
	api := serving(map[string]probe.Response{baseURL + "/a": ok("public page")})
	tt := tester(t, api, spec, nil)

	findings, err := tt.Run(context.Background())

	if err != nil || len(findings) != 0 {
		t.Fatalf("findings = %+v, err = %v; /secret answered 401 and /a is public", findings, err)
	}
	if want := []string{"GET " + baseURL + "/secret"}; !slices.Equal(api.sent(), want) {
		t.Fatalf("requests = %v; want %v", api.sent(), want)
	}
}
