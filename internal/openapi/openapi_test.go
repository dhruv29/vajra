package openapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/probe"
)

// shopSpec is a small but realistic description: shared parameters through
// $ref, a security default with one public operation, examples in several
// places and a body described only by its schema.
const shopSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "Shop API", "version": "1.4.0"},
  "servers": [{"url": "https://api.shop.test/v1"}, {"url": "https://staging.shop.test/v1"}, {"description": "no url"}],
  "security": [{"bearer": []}],
  "x-internal": true,
  "paths": {
    "x-note": "not a path",
    "/orders": {
      "get": {
        "operationId": "listOrders",
        "summary": "List orders",
        "parameters": [
          {"$ref": "#/components/parameters/Limit"},
          {"name": "status", "in": "query", "required": true, "schema": {"type": "string", "enum": ["open", "shipped"], "default": "open"}},
          {"name": "cursor", "in": "query"},
          {"name": "X-Trace", "in": "header", "example": "abc"}
        ]
      },
      "post": {
        "operationId": "createOrder",
        "requestBody": {"$ref": "#/components/requestBodies/NewOrder"},
        "callbacks": {"onShipped": {"{$request.body#/hook}": {"post": {"operationId": "ignoredCallback"}}}}
      }
    },
    "/orders/{orderId}": {
      "parameters": [
        {"$ref": "#/components/parameters/OrderID"},
        {"name": "expand", "in": "query", "example": "items"}
      ],
      "get": {
        "operationId": "getOrder",
        "parameters": [{"name": "expand", "in": "query", "required": true, "examples": {"b": {"value": "customer"}, "a": {"$ref": "#/components/examples/ExpandAll"}}}]
      },
      "delete": {"summary": "Cancel an order"},
      "patch": {
        "operationId": "updateOrder",
        "requestBody": {"content": {"application/merge-patch+json": {"examples": {"note": {"value": {"note": "leave at the door"}}}}}}
      }
    },
    "/orders/{orderId}/items/{itemId}": {
      "parameters": [{"$ref": "#/components/parameters/OrderID"}, {"name": "itemId", "in": "path", "required": true, "schema": {"type": "integer"}}],
      "put": {
        "operationId": "replaceItem",
        "requestBody": {"content": {"application/json": {"example": {"sku": "A-1", "quantity": 2}}}}
      }
    },
    "/health": {
      "get": {"operationId": "health", "security": []},
      "head": {"security": [{}, {"bearer": []}]},
      "trace": {"operationId": "traceHealth"}
    },
    "/upload": {
      "post": {"operationId": "upload", "security": [{"apiKey": []}], "requestBody": {"content": {"multipart/form-data": {"schema": {"type": "object"}}}}}
    }
  },
  "webhooks": {"shipped": {"post": {"operationId": "ignoredWebhook"}}},
  "components": {
    "parameters": {
      "Limit": {"name": "limit", "in": "query", "schema": {"$ref": "#/components/schemas/Limit"}},
      "OrderID": {"name": "orderId", "in": "path", "required": true, "example": 1001}
    },
    "examples": {"ExpandAll": {"value": "all"}},
    "requestBodies": {
      "NewOrder": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewOrder"}}}}
    },
    "schemas": {
      "Limit": {"type": "integer", "example": 25},
      "NewOrder": {
        "type": "object",
        "properties": {
          "id": {"type": "integer", "readOnly": true},
          "customer": {"type": "string"},
          "quantity": {"type": "integer"},
          "total": {"type": "number"},
          "gift": {"type": "boolean"},
          "tags": {"type": "array", "items": {"type": "string"}},
          "channel": {"type": "string", "enum": ["web", "store"]},
          "address": {"$ref": "#/components/schemas/Address"}
        }
      },
      "Address": {"properties": {"city": {"type": ["null", "string"]}, "zip": {"type": "string", "default": "00000"}}}
    }
  }
}`

func parseSpec(t *testing.T, spec string) Document {
	t.Helper()
	doc, err := Parse(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func operationByID(t *testing.T, doc Document, id string) Operation {
	t.Helper()
	for _, op := range doc.Operations {
		if op.ID == id {
			return op
		}
	}
	t.Fatalf("no operation %q in %v", id, operationIDs(doc))
	return Operation{}
}

func operationIDs(doc Document) []string {
	ids := make([]string, 0, len(doc.Operations))
	for _, op := range doc.Operations {
		ids = append(ids, op.ID)
	}
	return ids
}

// withSchema wraps a request body schema in the smallest valid document.
func withSchema(schema string, components string) string {
	return `{"openapi":"3.1.0","paths":{"/things":{"post":{"requestBody":{"content":{"application/json":{"schema":` +
		schema + `}}}}}},"components":{"schemas":` + components + `}}`
}

func TestParseReadsTitleServersAndSortedOperations(t *testing.T) {
	doc := parseSpec(t, shopSpec)

	if doc.Title != "Shop API" {
		t.Fatalf("title = %q", doc.Title)
	}
	if !slices.Equal(doc.Servers, []string{"https://api.shop.test/v1", "https://staging.shop.test/v1"}) {
		t.Fatalf("servers = %v", doc.Servers)
	}
	want := []string{
		"health", "HEAD /health", "traceHealth",
		"listOrders", "createOrder",
		"DELETE /orders/{orderId}", "getOrder", "updateOrder",
		"replaceItem", "upload",
	}
	if got := operationIDs(doc); !slices.Equal(got, want) {
		t.Fatalf("operations = %v; want %v (by path, then method; callbacks and webhooks ignored)", got, want)
	}
	cancel := operationByID(t, doc, "DELETE /orders/{orderId}")
	if cancel.Method != "DELETE" || cancel.Path != "/orders/{orderId}" || cancel.Summary != "Cancel an order" {
		t.Fatalf("operation without an operationId = %+v", cancel)
	}
}

func TestParseAppliesSecurityRules(t *testing.T) {
	doc := parseSpec(t, shopSpec)
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"document default applies", "listOrders", true},
		{"empty list on the operation means public", "health", false},
		{"an empty requirement makes credentials optional", "HEAD /health", false},
		{"operation's own requirement", "upload", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := operationByID(t, doc, tt.id).RequiresAuth; got != tt.want {
				t.Fatalf("RequiresAuth = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestParseWithoutSecurityAnywhereRequiresNoAuth(t *testing.T) {
	doc := parseSpec(t, `{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}`)

	if doc.Operations[0].RequiresAuth || doc.Title != "" || doc.Servers == nil || len(doc.Servers) != 0 {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestParseMergesPathAndOperationParameters(t *testing.T) {
	doc := parseSpec(t, shopSpec)

	list := operationByID(t, doc, "listOrders")
	wantList := []Param{{Name: "cursor"}, {Name: "limit", Example: "25"}, {Name: "status", Required: true, Example: "open"}}
	if !slices.Equal(list.QueryParams, wantList) || len(list.PathParams) != 0 {
		t.Fatalf("listOrders params = %+v; want %+v (sorted, header parameter left out)", list.QueryParams, wantList)
	}
	get := operationByID(t, doc, "getOrder")
	if !slices.Equal(get.QueryParams, []Param{{Name: "expand", Required: true, Example: "all"}}) {
		t.Fatalf("getOrder query = %+v; the operation's parameter replaces the path's, example from the first of examples", get.QueryParams)
	}
	if !slices.Equal(get.PathParams, []string{"orderId"}) {
		t.Fatalf("getOrder path params = %v", get.PathParams)
	}
	cancel := operationByID(t, doc, "DELETE /orders/{orderId}")
	if !slices.Equal(cancel.QueryParams, []Param{{Name: "expand", Example: "items"}}) {
		t.Fatalf("path-level parameter not inherited: %+v", cancel.QueryParams)
	}
	replace := operationByID(t, doc, "replaceItem")
	if !slices.Equal(replace.PathParams, []string{"orderId", "itemId"}) {
		t.Fatalf("path params = %v; want template order", replace.PathParams)
	}
}

func TestParseFindsBodyExamples(t *testing.T) {
	doc := parseSpec(t, shopSpec)
	tests := []struct {
		name     string
		id       string
		wantBody bool
		want     string
	}{
		{"no request body", "listOrders", false, ""},
		{"example on the media type", "replaceItem", true, `{"quantity":2,"sku":"A-1"}`},
		{"first of examples on a JSON-based media type", "updateOrder", true, `{"note":"leave at the door"}`},
		{"synthesised from a schema behind two references", "createOrder", true,
			`{"address":{"city":"string","zip":"00000"},"channel":"web","customer":"string","gift":false,"quantity":0,"tags":["string"],"total":0}`},
		{"body that is not JSON has no example", "upload", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := operationByID(t, doc, tt.id)

			if op.HasBody != tt.wantBody || op.BodyExample != tt.want {
				t.Fatalf("HasBody = %v, BodyExample = %s; want %v and %s", op.HasBody, op.BodyExample, tt.wantBody, tt.want)
			}
		})
	}
}

func TestParseSynthesisesBodiesFromSchemas(t *testing.T) {
	tests := []struct {
		name       string
		schema     string
		components string
		want       string
	}{
		{"schema example wins", `{"type":"object","example":{"a":1.50}}`, `{}`, `{"a":1.50}`},
		{"string", `{"type":"string"}`, `{}`, `"string"`},
		{"array of objects", `{"type":"array","items":{"properties":{"n":{"type":"integer"}}}}`, `{}`, `[{"n":0}]`},
		{"array recognised by its items", `{"items":{"type":"boolean"}}`, `{}`, `[false]`},
		{"array whose items say nothing", `{"type":"array"}`, `{}`, `[]`},
		{"properties of unknown type left out", `{"type":"object","properties":{"a":{},"b":{"type":"string"},"c":{"type":"null"}}}`, `{}`, `{"b":"string"}`},
		{"allOf merges properties", `{"allOf":[{"$ref":"#/components/schemas/Base"},{"properties":{"own":{"type":"string"}}}]}`,
			`{"Base":{"properties":{"id":{"type":"integer"}}}}`, `{"id":0,"own":"string"}`},
		{"objects nest three levels and no deeper",
			`{"properties":{"l2":{"properties":{"l3":{"properties":{"l4":{"properties":{"x":{"type":"string"}}},"kept":{"type":"string"}}}}}}}`,
			`{}`, `{"l2":{"l3":{"kept":"string"}}}`},
		{"schema that contains itself", `{"$ref":"#/components/schemas/Node"}`,
			`{"Node":{"properties":{"name":{"type":"string"},"child":{"$ref":"#/components/schemas/Node"},"children":{"type":"array","items":{"$ref":"#/components/schemas/Node"}}}}}`,
			`{"child":{"child":{"name":"string"},"children":[],"name":"string"},"children":[{"name":"string"}],"name":"string"}`},
		{"array that contains itself", `{"$ref":"#/components/schemas/Nest"}`,
			`{"Nest":{"type":"array","items":{"$ref":"#/components/schemas/Nest"}}}`, `[[[]]]`},
		{"reference with an escaped name", `{"$ref":"#/components/schemas/a~1b%20c"}`, `{"a/b c":{"type":"integer"}}`, `0`},
		{"no schema type at all", `{"description":"anything"}`, `{}`, ``},
		{"reference that leads nowhere", `{"$ref":"#/components/schemas/Missing"}`, `{}`, ``},
		{"reference to another document", `{"$ref":"https://other.test/schemas.json#/Order"}`, `{}`, ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := parseSpec(t, withSchema(tt.schema, tt.components))

			op := doc.Operations[0]
			if !op.HasBody || op.BodyExample != tt.want {
				t.Fatalf("HasBody = %v, BodyExample = %s; want %s", op.HasBody, op.BodyExample, tt.want)
			}
		})
	}
}

func TestParseSurvivesReferenceCycles(t *testing.T) {
	spec := `{
  "openapi": "3.0.0",
  "paths": {
    "/loop": {"$ref": "#/paths/~1loop"},
    "/a": {
      "parameters": [{"$ref": "#/components/parameters/P"}],
      "post": {
        "parameters": [{"name": "q", "in": "query", "schema": {"$ref": "#/components/schemas/A"}}],
        "requestBody": {"$ref": "#/components/requestBodies/R"}
      },
      "put": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}}},
      "patch": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Deep"}}}}}
    }
  },
  "components": {
    "parameters": {"P": {"$ref": "#/components/parameters/Q"}, "Q": {"$ref": "#/components/parameters/P"}},
    "requestBodies": {"R": {"$ref": "#/components/requestBodies/R"}},
    "schemas": {
      "A": {"$ref": "#/components/schemas/B"},
      "B": {"$ref": "#/components/schemas/A"},
      "Deep": {"allOf": [{"$ref": "#/components/schemas/Deep"}], "properties": {"x": {"type": "string"}}}
    }
  }
}`
	done := make(chan Document, 1)

	go func() {
		doc, err := Parse(strings.NewReader(spec))
		if err != nil {
			t.Error(err)
		}
		done <- doc
	}()

	select {
	case doc := <-done:
		if got := operationIDs(doc); !slices.Equal(got, []string{"PATCH /a", "POST /a", "PUT /a"}) {
			t.Fatalf("operations = %v", got)
		}
		post := operationByID(t, doc, "POST /a")
		if !post.HasBody || post.BodyExample != "" || !slices.Equal(post.QueryParams, []Param{{Name: "q"}}) {
			t.Fatalf("POST /a = %+v", post)
		}
		if patch := operationByID(t, doc, "PATCH /a"); patch.BodyExample != `{"x":"string"}` {
			t.Fatalf("allOf cycle body = %s", patch.BodyExample)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Parse did not return: a reference cycle is being followed forever")
	}
}

func TestParseGivesRepeatedOperationIDsAFallback(t *testing.T) {
	doc := parseSpec(t, `{"openapi":"3.0.0","paths":{"/a":{"get":{"operationId":"same"}},"/b":{"get":{"operationId":"same"}}}}`)

	if got := operationIDs(doc); !slices.Equal(got, []string{"same", "GET /b"}) {
		t.Fatalf("IDs = %v", got)
	}
}

func TestParseIsDeterministic(t *testing.T) {
	first, err := json.Marshal(parseSpec(t, shopSpec))
	if err != nil {
		t.Fatal(err)
	}

	for range 20 {
		again, _ := json.Marshal(parseSpec(t, shopSpec))
		if string(again) != string(first) {
			t.Fatalf("two parses of the same document differ:\n%s\n%s", first, again)
		}
	}
}

func TestParseRejectsWhatItCannotRead(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"YAML", "openapi: 3.0.3\ninfo:\n  title: Shop\npaths: {}\n", "convert it to JSON"},
		{"YAML with a document marker", "---\nopenapi: 3.0.3\n", "YAML"},
		{"JSON array", `[{"openapi":"3.0.0"}]`, "not JSON"},
		{"Swagger 2", `{"swagger":"2.0","info":{"title":"Old"},"paths":{}}`, "Swagger 2.0 document; convert it to OpenAPI 3"},
		{"OpenAPI 4", `{"openapi":"4.0.0","paths":{}}`, `version "4.0.0" is not supported`},
		{"no version", `{"info":{"title":"x"}}`, `no "openapi" version`},
		{"version that is not a string", `{"openapi":3.0}`, `no "openapi" version`},
		{"malformed JSON", `{"openapi":"3.0.0","paths":{`, "not valid JSON"},
		{"two documents", `{"openapi":"3.0.0"}{"openapi":"3.0.0"}`, "more after the first object"},
		{"empty", " \n ", "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.input))

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v; want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestParseAcceptsAByteOrderMark(t *testing.T) {
	doc, err := Parse(strings.NewReader("\xEF\xBB\xBF" + `{"openapi":"3.1.0","info":{"title":"BOM"}}`))

	if err != nil || doc.Title != "BOM" || doc.Operations == nil || len(doc.Operations) != 0 {
		t.Fatalf("doc = %+v, err = %v", doc, err)
	}
}

func TestParseRejectsOversizedInput(t *testing.T) {
	huge := io.MultiReader(strings.NewReader(`{"openapi":"3.0.0","info":{"title":"`), &zeros{left: MaxDocumentBytes}, strings.NewReader(`"}}`))

	_, err := Parse(huge)

	if err == nil || !strings.Contains(err.Error(), "larger than the limit of 20 MiB") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseReportsAReadError(t *testing.T) {
	boom := errors.New("disk on fire")

	_, err := Parse(io.MultiReader(strings.NewReader(`{"openapi":`), failingReader{boom}))

	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

// zeros yields a fixed number of '0' bytes without holding them in memory.
type zeros struct{ left int }

func (z *zeros) Read(p []byte) (int, error) {
	if z.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), z.left)
	for i := range n {
		p[i] = '0'
	}
	z.left -= n
	return n, nil
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

func requestByID(t *testing.T, requests []probe.Request, id string) probe.Request {
	t.Helper()
	for _, request := range requests {
		if request.ID == id {
			return request
		}
	}
	t.Fatalf("no request %q", id)
	return probe.Request{}
}

func TestRequestsWithoutIncludeUnsafeBuildsOnlySafeMethods(t *testing.T) {
	doc := parseSpec(t, shopSpec)

	requests, skipped := doc.Requests(RequestOptions{BaseURL: "https://api.shop.test/v1/"})

	want := []probe.Request{
		{ID: "health", Method: "GET", URL: "https://api.shop.test/v1/health"},
		{ID: "HEAD /health", Method: "HEAD", URL: "https://api.shop.test/v1/health"},
		{ID: "listOrders", Method: "GET", URL: "https://api.shop.test/v1/orders?limit=25&status=open"},
		{ID: "getOrder", Method: "GET", URL: "https://api.shop.test/v1/orders/1001?expand=all"},
	}
	if len(requests) != len(want) {
		t.Fatalf("requests = %+v; want %d", requests, len(want))
	}
	for i, request := range requests {
		if request.ID != want[i].ID || request.Method != want[i].Method || request.URL != want[i].URL ||
			request.Body != "" || request.Headers != nil {
			t.Errorf("request %d = %+v; want %+v", i, request, want[i])
		}
	}
	wantSkipped := []Skipped{
		{"traceHealth", "the probe does not send TRACE requests"},
		{"createOrder", "POST may change data; set IncludeUnsafe to send it"},
		{"DELETE /orders/{orderId}", "DELETE may change data; set IncludeUnsafe to send it"},
		{"updateOrder", "PATCH may change data; set IncludeUnsafe to send it"},
		{"replaceItem", "PUT may change data; set IncludeUnsafe to send it"},
		{"upload", "POST may change data; set IncludeUnsafe to send it"},
	}
	if !slices.Equal(skipped, wantSkipped) {
		t.Fatalf("skipped = %+v; want %+v", skipped, wantSkipped)
	}
	if err := (probe.Batch{Requests: requests}).Validate(); err != nil {
		t.Fatalf("the probe would refuse these requests: %v", err)
	}
}

func TestRequestsWithIncludeUnsafeSendsBodies(t *testing.T) {
	doc := parseSpec(t, shopSpec)
	opts := RequestOptions{
		BaseURL:       "https://api.shop.test/v1",
		Params:        map[string]string{"itemId": "7"},
		Headers:       map[string]string{"Authorization": "Bearer t0ken"},
		IncludeUnsafe: true,
	}

	requests, skipped := doc.Requests(opts)

	if !slices.Equal(skipped, []Skipped{{"traceHealth", "the probe does not send TRACE requests"}}) {
		t.Fatalf("skipped = %+v", skipped)
	}
	if len(requests) != len(doc.Operations)-1 {
		t.Fatalf("requests = %d for %d operations", len(requests), len(doc.Operations))
	}
	replace := requestByID(t, requests, "replaceItem")
	if replace.Method != "PUT" || replace.URL != "https://api.shop.test/v1/orders/1001/items/7" ||
		replace.Body != `{"quantity":2,"sku":"A-1"}` || replace.Headers["Content-Type"] != "application/json" ||
		replace.Headers["Authorization"] != "Bearer t0ken" {
		t.Fatalf("replaceItem = %+v", replace)
	}
	for _, id := range []string{"upload", "DELETE /orders/{orderId}", "getOrder"} {
		request := requestByID(t, requests, id)
		if _, set := request.Headers["Content-Type"]; set || request.Body != "" {
			t.Errorf("%s has no body to send but got %+v", id, request)
		}
		if request.Headers["Authorization"] != "Bearer t0ken" {
			t.Errorf("%s lost the caller's headers: %v", id, request.Headers)
		}
	}
	if len(opts.Headers) != 1 {
		t.Fatalf("the caller's header map was changed: %v", opts.Headers)
	}
	if err := (probe.Batch{Requests: requests}).Validate(); err != nil {
		t.Fatalf("the probe would refuse these requests: %v", err)
	}
}

func TestRequestsSetsContentTypeOnlyWhenTheCallerDidNot(t *testing.T) {
	doc := Document{Operations: []Operation{{ID: "create", Method: "POST", Path: "/things", HasBody: true, BodyExample: `{}`}}}
	tests := []struct {
		name    string
		headers map[string]string
		want    map[string]string
	}{
		{"no headers", nil, map[string]string{"Content-Type": "application/json"}},
		{"other headers", map[string]string{"X-Run": "1"}, map[string]string{"X-Run": "1", "Content-Type": "application/json"}},
		{"caller's content type in another case", map[string]string{"content-type": "application/vnd.api+json"}, map[string]string{"content-type": "application/vnd.api+json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests, _ := doc.Requests(RequestOptions{BaseURL: "http://api.test", Headers: tt.headers, IncludeUnsafe: true})

			if len(requests) != 1 || requests[0].Body != `{}` || len(requests[0].Headers) != len(tt.want) {
				t.Fatalf("requests = %+v", requests)
			}
			for name, value := range tt.want {
				if requests[0].Headers[name] != value {
					t.Fatalf("headers = %v; want %v", requests[0].Headers, tt.want)
				}
			}
		})
	}
}

func TestRequestsSkipsAnOperationWithAMissingPathParameter(t *testing.T) {
	doc := parseSpec(t, shopSpec)
	tests := []struct {
		name   string
		params map[string]string
		want   []Skipped
	}{
		{"no value and no example", nil, []Skipped{{"replaceItem", `no value for path parameter "itemId"`}}},
		{"an empty value is no value", map[string]string{"itemId": ""}, []Skipped{{"replaceItem", `no value for path parameter "itemId"`}}},
		{"value given", map[string]string{"itemId": "3"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, skipped := doc.Requests(RequestOptions{BaseURL: "https://api.shop.test", Params: tt.params, IncludeUnsafe: true})

			skipped = slices.DeleteFunc(skipped, func(s Skipped) bool { return s.Operation == "traceHealth" })
			if !slices.Equal(skipped, tt.want) {
				t.Fatalf("skipped = %+v; want %+v", skipped, tt.want)
			}
		})
	}
}

func TestRequestsNamesTheFirstMissingPathParameter(t *testing.T) {
	doc := Document{Operations: []Operation{{ID: "op", Method: "GET", Path: "/a/{one}/b/{two}/{three}"}}}

	requests, skipped := doc.Requests(RequestOptions{BaseURL: "http://api.test", Params: map[string]string{"one": "1"}})

	if len(requests) != 0 || !slices.Equal(skipped, []Skipped{{"op", `no value for path parameter "two"`}}) {
		t.Fatalf("requests = %+v, skipped = %+v", requests, skipped)
	}
}

func TestRequestsEscapesParameterValues(t *testing.T) {
	doc := Document{Operations: []Operation{{
		ID: "search", Method: "GET", Path: "/files/{name}/versions/{name}",
		QueryParams: []Param{
			{Name: "empty required", Required: true},
			{Name: "filter", Example: "from spec"},
			{Name: "optional"},
			{Name: "q"},
		},
	}}}
	tests := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"slashes, spaces and ampersands", map[string]string{"name": "a/b c&d", "q": "x/y z&w=1"},
			"https://api.test/files/a%2Fb%20c&d/versions/a%2Fb%20c&d?empty+required=&filter=from+spec&q=x%2Fy+z%26w%3D1"},
		{"path traversal and reserved characters", map[string]string{"name": "../etc?x#y", "filter": "é+%"},
			"https://api.test/files/..%2Fetc%3Fx%23y/versions/..%2Fetc%3Fx%23y?empty+required=&filter=%C3%A9%2B%25"},
		{"an empty value given by the caller is sent", map[string]string{"name": "n", "optional": "", "filter": ""},
			"https://api.test/files/n/versions/n?empty+required=&filter=&optional="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests, skipped := doc.Requests(RequestOptions{BaseURL: "https://api.test", Params: tt.params})

			if len(requests) != 1 || len(skipped) != 0 || requests[0].URL != tt.want {
				t.Fatalf("requests = %+v, skipped = %+v; want URL %s", requests, skipped, tt.want)
			}
		})
	}
}

func TestRequestsJoinsTheBaseURLWithoutDoublingSlashes(t *testing.T) {
	tests := []struct {
		name string
		base string
		path string
		want string
	}{
		{"no trailing slash", "https://api.test/v1", "/orders", "https://api.test/v1/orders"},
		{"trailing slash", "https://api.test/v1/", "/orders", "https://api.test/v1/orders"},
		{"several trailing slashes", "https://api.test/v1///", "/orders", "https://api.test/v1/orders"},
		{"host only", "http://api.test:8080", "/orders", "http://api.test:8080/orders"},
		{"host with a slash", "http://api.test/", "/", "http://api.test/"},
		{"query and fragment on the base are dropped", "https://api.test/v1?key=1#top", "/orders", "https://api.test/v1/orders"},
		{"base with surrounding spaces", " https://api.test/v1 ", "/orders", "https://api.test/v1/orders"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := Document{Operations: []Operation{{ID: "op", Method: "GET", Path: tt.path}}}

			requests, _ := doc.Requests(RequestOptions{BaseURL: tt.base})

			if len(requests) != 1 || requests[0].URL != tt.want {
				t.Fatalf("requests = %+v; want URL %s", requests, tt.want)
			}
		})
	}
}

func TestRequestsRejectsABaseURLThatIsNotHTTP(t *testing.T) {
	doc := parseSpec(t, shopSpec)
	for _, base := range []string{"", "api.shop.test/v1", "ftp://api.shop.test", "file:///etc/passwd", "https://", "http://[bad"} {
		t.Run(base, func(t *testing.T) {
			requests, skipped := doc.Requests(RequestOptions{BaseURL: base, IncludeUnsafe: true})

			if len(requests) != 0 || len(skipped) != len(doc.Operations) {
				t.Fatalf("requests = %d, skipped = %d; want every operation skipped", len(requests), len(skipped))
			}
			if !strings.Contains(skipped[0].Reason, "is not an http(s) URL") {
				t.Fatalf("reason = %q", skipped[0].Reason)
			}
		})
	}
}

func TestRequestsDoesNotSendABodyOnASafeMethodOrAnOversizedOne(t *testing.T) {
	doc := Document{Operations: []Operation{
		{ID: "search", Method: "GET", Path: "/search", HasBody: true, BodyExample: `{"q":"x"}`},
		{ID: "import", Method: "POST", Path: "/import", HasBody: true, BodyExample: strings.Repeat("x", probe.MaxRequestBodyBytes+1)},
	}}

	requests, skipped := doc.Requests(RequestOptions{BaseURL: "http://api.test", IncludeUnsafe: true})

	if len(requests) != 1 || requests[0].Body != "" || requests[0].Headers != nil {
		t.Fatalf("requests = %+v", requests)
	}
	if !slices.Equal(skipped, []Skipped{{"import", "the body example is larger than the probe accepts"}}) {
		t.Fatalf("skipped = %+v", skipped)
	}
}

func TestRequestsAreInTheSameOrderEveryTime(t *testing.T) {
	doc := parseSpec(t, shopSpec)
	opts := RequestOptions{BaseURL: "https://api.shop.test", Params: map[string]string{"itemId": "1", "cursor": "c", "limit": "5"}, IncludeUnsafe: true}
	first, _ := doc.Requests(opts)

	for range 20 {
		again, _ := parseSpec(t, shopSpec).Requests(opts)
		if len(again) != len(first) {
			t.Fatalf("lengths differ: %d and %d", len(again), len(first))
		}
		for i := range again {
			if again[i].ID != first[i].ID || again[i].URL != first[i].URL || again[i].Body != first[i].Body {
				t.Fatalf("request %d differs: %+v and %+v", i, again[i], first[i])
			}
		}
	}
	if got := requestByID(t, first, "listOrders").URL; got != "https://api.shop.test/orders?cursor=c&limit=5&status=open" {
		t.Fatalf("listOrders URL = %s; caller's values replace the spec's examples, in name order", got)
	}
}

func TestStringifyRendersExampleValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"string", "open", "open"},
		{"number as written", json.Number("1.50"), "1.50"},
		{"boolean", true, "true"},
		{"list", []any{"a", json.Number("2")}, `["a",2]`},
		{"value that cannot be encoded", func() {}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stringify(tt.value); got != tt.want {
				t.Fatalf("stringify(%v) = %q; want %q", tt.value, got, tt.want)
			}
		})
	}
}

// parseWithin runs Parse on spec and fails when it takes longer than limit,
// so a document that makes Parse do exponential work fails the test instead
// of hanging it.
func parseWithin(t *testing.T, spec string, limit time.Duration) Document {
	t.Helper()
	done := make(chan Document, 1)
	go func() {
		doc, err := Parse(strings.NewReader(spec))
		if err != nil {
			t.Error(err)
		}
		done <- doc
	}()
	select {
	case doc := <-done:
		return doc
	case <-time.After(limit):
		t.Fatalf("Parse did not return within %v", limit)
		return Document{}
	}
}

func TestParseBoundsAllOfFanOut(t *testing.T) {
	for _, n := range []int{3, 8} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			parts := strings.TrimSuffix(strings.Repeat(`{"$ref":"#/components/schemas/A"},`, n), ",")
			spec := withSchema(`{"$ref":"#/components/schemas/A"}`,
				`{"A":{"allOf":[`+parts+`],"properties":{"x":{"type":"string"}}}}`)

			doc := parseWithin(t, spec, 5*time.Second)

			if len(doc.Operations) != 1 || !doc.Operations[0].HasBody {
				t.Fatalf("operations = %+v", doc.Operations)
			}
		})
	}
}

func TestParseBoundsWideSelfReferencingObjects(t *testing.T) {
	const width = 5000
	properties := make([]string, 0, width)
	for i := range width {
		properties = append(properties, fmt.Sprintf(`"p%04d":{"$ref":"#/components/schemas/W"}`, i))
	}
	spec := withSchema(`{"$ref":"#/components/schemas/W"}`,
		`{"W":{"type":"object","properties":{`+strings.Join(properties, ",")+`}}}`)

	doc := parseWithin(t, spec, 5*time.Second)

	var body map[string]any
	if err := json.Unmarshal([]byte(doc.Operations[0].BodyExample), &body); err != nil {
		t.Fatalf("body example %q: %v", doc.Operations[0].BodyExample, err)
	}
	if len(body) > maxExampleProperties {
		t.Fatalf("body has %d properties; want at most %d", len(body), maxExampleProperties)
	}
}

func TestParseCapsPropertiesPerSynthesisedObject(t *testing.T) {
	properties := make([]string, 0, 2*maxExampleProperties)
	for i := range 2 * maxExampleProperties {
		properties = append(properties, fmt.Sprintf(`"p%03d":{"type":"integer"}`, i))
	}
	doc := parseSpec(t, withSchema(`{"properties":{`+strings.Join(properties, ",")+`}}`, `{}`))

	var body map[string]any
	if err := json.Unmarshal([]byte(doc.Operations[0].BodyExample), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != maxExampleProperties || body["p000"] == nil || body[fmt.Sprintf("p%03d", maxExampleProperties)] != nil {
		t.Fatalf("body has %d properties; want the first %d by name", len(body), maxExampleProperties)
	}
}

func TestRequestsSkipsPathTemplatesThatAreNotPlainPaths(t *testing.T) {
	for _, path := range []string{"orders", "/a?admin=1", "/a#frag", "/a b", "/a\tb", "/a\\b", "/a\x00b", "/a\x7fb", ""} {
		t.Run(path, func(t *testing.T) {
			doc := Document{Operations: []Operation{{ID: "op", Method: "GET", Path: path}}}

			requests, skipped := doc.Requests(RequestOptions{BaseURL: "https://api.test"})

			want := []Skipped{{"op", fmt.Sprintf(reasonBadPathTemplate, path)}}
			if len(requests) != 0 || !slices.Equal(skipped, want) {
				t.Fatalf("requests = %+v, skipped = %+v", requests, skipped)
			}
		})
	}
}

func TestRequestsSkipsDotAndEmptyPathParameterValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"dot", ".", `the value of path parameter "id" would change the route`},
		{"dot dot", "..", `the value of path parameter "id" would change the route`},
		{"empty", "", `no value for path parameter "id"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := Document{Operations: []Operation{{ID: "op", Method: "GET", Path: "/users/{id}/profile"}}}

			requests, skipped := doc.Requests(RequestOptions{BaseURL: "https://api.test", Params: map[string]string{"id": tt.value}})

			if len(requests) != 0 || !slices.Equal(skipped, []Skipped{{"op", tt.want}}) {
				t.Fatalf("requests = %+v, skipped = %+v", requests, skipped)
			}
		})
	}
}
