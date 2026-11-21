package har

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/scope"
)

func testPolicy(t testing.TB) *scope.Policy {
	t.Helper()
	p, err := scope.New(scope.Config{
		Hosts: []string{"app.example.com", "*.example.org"},
		CIDRs: []string{"203.0.113.0/24"},
		Ports: []int{80, 443, 8443},
	})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return p
}

// entry is a HAR entry under construction. Fields are added by the options.
type entry map[string]any

func get(rawURL string, opts ...func(entry)) entry {
	return request("GET", rawURL, opts...)
}

func request(method, rawURL string, opts ...func(entry)) entry {
	e := entry{"method": method, "url": rawURL, "httpVersion": "HTTP/1.1", "headers": []any{}}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func header(name, value string) func(entry) {
	return func(e entry) {
		e["headers"] = append(e["headers"].([]any), map[string]any{"name": name, "value": value})
	}
}

func cookie(name, value string) func(entry) {
	return func(e entry) {
		cookies, _ := e["cookies"].([]any)
		e["cookies"] = append(cookies, map[string]any{"name": name, "value": value})
	}
}

func body(mimeType, text string) func(entry) {
	return func(e entry) { e["postData"] = map[string]any{"mimeType": mimeType, "text": text} }
}

func harOf(t testing.TB, entries ...entry) string {
	t.Helper()
	wrapped := make([]any, 0, len(entries))
	for _, e := range entries {
		wrapped = append(wrapped, map[string]any{
			"startedDateTime": "2026-01-01T00:00:00Z",
			"request":         map[string]any(e),
			"response": map[string]any{"status": 200, "headers": []any{
				map[string]any{"name": "Set-Cookie", "value": "session=RESPONSE-SET-COOKIE-SECRET"},
			}},
		})
	}
	doc := map[string]any{"log": map[string]any{
		"version": "1.2", "creator": map[string]any{"name": "test"}, "pages": []any{}, "entries": wrapped,
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func mustParse(t *testing.T, har string, opts Options) Recording {
	t.Helper()
	rec, err := Parse(strings.NewReader(har), testPolicy(t), opts)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return rec
}

func findRequest(t *testing.T, rec Recording, method, prefix string) Request {
	t.Helper()
	for _, r := range rec.Requests {
		if r.Method == method && strings.HasPrefix(r.URL, prefix) {
			return r
		}
	}
	t.Fatalf("no %s request starting %q in %+v", method, prefix, rec.Requests)
	return Request{}
}

func TestParseImportsARealisticRecording(t *testing.T) {
	har := harOf(t,
		get("https://app.example.com/dashboard", cookie("sid", "abcdefgh12345678"), header("Accept", "text/html")),
		get("https://app.example.com/static/app.css"),
		get("https://app.example.com/api/items?page=2&sort=name", header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")),
		request("POST", "https://app.example.com/api/items", body("application/json; charset=utf-8", `{"title":"x","tags":["a"],"owner":{"id":1}}`)),
	)
	rec := mustParse(t, har, Options{})

	if len(rec.Requests) != 4 {
		t.Fatalf("requests = %+v; want 4", rec.Requests)
	}
	want := []string{"https://app.example.com/api/items?page=2&sort=name", "https://app.example.com/dashboard"}
	if !slices.Equal(rec.URLs, want) {
		t.Fatalf("URLs = %v; want %v (static assets and POSTs are not seeds)", rec.URLs, want)
	}
	page := findRequest(t, rec, "GET", "https://app.example.com/dashboard")
	if !page.Authenticated || page.StateChanging {
		t.Errorf("dashboard = %+v; want authenticated, not state-changing", page)
	}
	list := findRequest(t, rec, "GET", "https://app.example.com/api/items")
	if !slices.Equal(list.QueryParams, []string{"page", "sort"}) || !list.Authenticated {
		t.Errorf("list = %+v", list)
	}
	create := findRequest(t, rec, "POST", "https://app.example.com/api/items")
	if !create.StateChanging || create.ContentType != "application/json" {
		t.Errorf("create = %+v; want state-changing JSON", create)
	}
	if want := []string{"owner", "owner.id", "tags", "title"}; !slices.Equal(create.BodyParams, want) {
		t.Errorf("body params = %v; want %v", create.BodyParams, want)
	}
	if rec.Skipped != (Skipped{}) {
		t.Errorf("skipped = %+v; want none", rec.Skipped)
	}
}

func TestParseDropsAndCountsOutOfScopeEntries(t *testing.T) {
	har := harOf(t,
		get("https://app.example.com/"),
		get("https://cdn.thirdparty.net/lib.js"),
		get("https://example.com/apex-is-not-covered-by-the-wildcard"),
		get("https://api.example.org/v1/me"),
		get("http://127.0.0.1/"),
		get("http://169.254.169.254/latest/meta-data/"),
		get("https://app.example.com:9000/wrong-port"),
		get("https://203.0.113.7:8443/admin"),
	)
	rec := mustParse(t, har, Options{})
	want := []string{"https://203.0.113.7:8443/admin", "https://api.example.org/v1/me", "https://app.example.com/"}
	if !slices.Equal(rec.URLs, want) {
		t.Fatalf("URLs = %v; want %v", rec.URLs, want)
	}
	if rec.Skipped.OutOfScope != 5 {
		t.Errorf("out of scope = %d; want 5", rec.Skipped.OutOfScope)
	}
	assertAllInScope(t, testPolicy(t), rec)
}

func TestParseDeduplicatesRequestsThatDifferOnlyInParameterValues(t *testing.T) {
	har := harOf(t,
		get("https://app.example.com/search?q=one&page=1"),
		get("https://app.example.com/search?page=9&q=two"),
		get("https://APP.example.com./search?q=three&page=3"),
		get("https://app.example.com/search?q=only"),
		request("POST", "https://app.example.com/login", body(formMediaType, "user=a&pass=b")),
		request("POST", "https://app.example.com/login", body(formMediaType, "pass=c&user=d")),
		request("POST", "https://app.example.com/login", body(formMediaType, "user=e")),
	)
	rec := mustParse(t, har, Options{})
	if len(rec.Requests) != 4 || rec.Skipped.Duplicate != 3 {
		t.Fatalf("requests = %+v, skipped = %+v; want 4 kept, 3 duplicates", rec.Requests, rec.Skipped)
	}
	first := findRequest(t, rec, "GET", "https://app.example.com/search?page=1")
	if first.URL != "https://app.example.com/search?page=1&q=one" {
		t.Errorf("kept %q; want the first one seen, with sorted parameters", first.URL)
	}
}

func TestParseNeverReturnsCredentials(t *testing.T) {
	secrets := []string{
		"COOKIE-SECRET-1234", "BEARER-SECRET-5678", "APIKEY-SECRET-9012", "CUSTOM-SESSION-SECRET",
		"QUERY-TOKEN-SECRET", "USERINFO-PASSWORD", "FORM-PASSWORD-SECRET", "JSON-TOKEN-SECRET",
		"COOKIE-ARRAY-SECRET", "RESPONSE-SET-COOKIE-SECRET", "PARAMS-SECRET-VALUE", "a+b/c=d+SIG-SECRET",
	}
	har := harOf(t,
		get("https://app.example.com/home",
			header("Cookie", "theme=dark; session=COOKIE-SECRET-1234"),
			header("Authorization", "Bearer BEARER-SECRET-5678"),
			header("X-Api-Key", "APIKEY-SECRET-9012"),
			header("X-Session-Id", "CUSTOM-SESSION-SECRET"),
			cookie("sid", "COOKIE-ARRAY-SECRET")),
		get("https://user:USERINFO-PASSWORD@app.example.com/profile?access_token=QUERY-TOKEN-SECRET&tab=billing"),
		get("https://app.example.com/download?sig=a%2Bb%2Fc%3Dd%2BSIG-SECRET&file=report"),
		request("POST", "https://app.example.com/login", body(formMediaType, "user=alice&password=FORM-PASSWORD-SECRET")),
		request("POST", "https://app.example.com/api", body("application/json", `{"auth":{"token":"JSON-TOKEN-SECRET"}}`)),
		request("POST", "https://app.example.com/upload", func(e entry) {
			e["postData"] = map[string]any{"mimeType": "multipart/form-data; boundary=x", "params": []any{
				map[string]any{"name": "apiKey", "value": "PARAMS-SECRET-VALUE"},
			}}
		}),
		// The session cookie echoed in a path and in an innocent-looking
		// query value is still scrubbed.
		get("https://app.example.com/s/COOKIE-SECRET-1234/view?ref=BEARER-SECRET-5678"),
	)
	rec := mustParse(t, har, Options{})
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(raw)
	for _, secret := range secrets {
		for _, spelling := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
			if strings.Contains(text, spelling) {
				t.Errorf("recording contains %q:\n%s", spelling, text)
			}
		}
	}
	profile := findRequest(t, rec, "GET", "https://app.example.com/profile")
	if profile.URL != "https://app.example.com/profile?access_token=&tab=billing" {
		t.Errorf("profile URL = %q; want the token value emptied and other values kept", profile.URL)
	}
	if !findRequest(t, rec, "GET", "https://app.example.com/home").Authenticated {
		t.Error("a request with credentials is not marked authenticated")
	}
}

func TestParseCountsUnsupportedSchemes(t *testing.T) {
	har := harOf(t,
		get("data:image/png;base64,"+strings.Repeat("A", maxURLLength*2)),
		get("blob:https://app.example.com/1234"),
		get("ws://app.example.com/socket"),
		get("wss://app.example.com/socket"),
		get("chrome-extension://abcdef/page.html"),
		get("ftp://app.example.com/file"),
		get("javascript:alert(1)"),
		get("https://app.example.com/ok"),
	)
	rec := mustParse(t, har, Options{})
	if rec.Skipped.UnsupportedScheme != 7 || len(rec.Requests) != 1 {
		t.Fatalf("skipped = %+v, requests = %+v; want 7 unsupported, 1 kept", rec.Skipped, rec.Requests)
	}
}

func TestParseCountsMalformedEntries(t *testing.T) {
	har := `{"log":{"entries":[
		"not an object",
		{"request":{"method":"GET","url":"https://app.example.com/a","headers":"wrong type"}},
		{"request":{"method":"G E T","url":"https://app.example.com/b"}},
		{"request":{"method":"GET"}},
		{"request":{"method":"GET","url":"https://app.example.com:0/c"}},
		{"request":{"method":"GET","url":"https://app.example.com:99999/c"}},
		{"request":{"method":"GET","url":"https:///no-host"}},
		{"request":{"method":"GET","url":"https://app.example.com/` + strings.Repeat("x", maxURLLength) + `"}},
		{"request":{"method":"GET","url":"https://app.example.com/%zz"}},
		{"request":{"method":"","url":"https://app.example.com/d"}},
		{"request":{"method":"GET","url":"1http://app.example.com/"}},
		{},
		{"request":{"method":"get","url":" https://app.example.com/fine "}}
	]}}`
	rec := mustParse(t, har, Options{})
	if rec.Skipped.Malformed != 12 {
		t.Errorf("malformed = %d; want 12 (%+v)", rec.Skipped.Malformed, rec.Skipped)
	}
	if len(rec.Requests) != 1 || rec.Requests[0].Method != "GET" || rec.Requests[0].URL != "https://app.example.com/fine" {
		t.Errorf("requests = %+v", rec.Requests)
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	cases := map[string]string{
		"empty input":           "",
		"truncated object":      `{"log":{"entries":[`,
		"top level array":       `[]`,
		"no log object":         `{"version":"1.2"}`,
		"log is not an object":  `{"log":[]}`,
		"entries not an array":  `{"log":{"entries":{}}}`,
		"broken entry":          `{"log":{"entries":[{]}}`,
		"non-string key":        `{1:2}`,
		"broken skipped value":  `{"other":[1,}`,
		"broken log key":        `{"log":{1:2}}`,
		"broken log value":      `{"log":{"pages":[,]}}`,
		"trailing garbage only": `{"log":{"entries":[]}`,
		"entries token error":   `{"log":{"entries":}}`,
		"unclosed entries":      `{"log":{"entries":[{}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(input), testPolicy(t), Options{})
			if err == nil || !strings.HasPrefix(err.Error(), "har: ") {
				t.Fatalf("err = %v; want a har: error", err)
			}
		})
	}
}

func TestParseAcceptsNullEntriesAndSkipsUnknownKeys(t *testing.T) {
	rec := mustParse(t, `{"x":{"y":[1,2]},"log":{"version":"1.2","entries":null,"pages":[{"id":"p"}]}}`, Options{})
	if len(rec.Requests) != 0 || rec.Requests == nil || rec.URLs == nil {
		t.Fatalf("rec = %+v; want empty, non-nil lists", rec)
	}
}

// endless is a reader that never ends, like a hostile pipe.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestParseFailsFastOnOversizedInput(t *testing.T) {
	big := harOf(t, get("https://app.example.com/"+strings.Repeat("a", 4096)))
	_, err := Parse(strings.NewReader(big), testPolicy(t), Options{MaxBytes: 1024})
	if err == nil || !strings.Contains(err.Error(), "larger than the 1024-byte limit") {
		t.Fatalf("err = %v; want a size error", err)
	}
	_, err = Parse(io.MultiReader(strings.NewReader(`{"log":{"entries":[`), endless{}), testPolicy(t), Options{MaxBytes: 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("endless input: err = %v; want a size error", err)
	}
	exact := `{"log":{"entries":[]}}`
	if _, err := Parse(strings.NewReader(exact), testPolicy(t), Options{MaxBytes: int64(len(exact))}); err != nil {
		t.Fatalf("input of exactly MaxBytes: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

func TestParseReportsReaderFailuresAsReadErrors(t *testing.T) {
	_, err := Parse(failingReader{}, testPolicy(t), Options{})
	if err == nil || !strings.Contains(err.Error(), "har: reading recording: disk on fire") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRequiresAReaderAndAPolicy(t *testing.T) {
	if _, err := Parse(nil, testPolicy(t), Options{}); err == nil {
		t.Error("nil reader accepted")
	}
	if _, err := Parse(strings.NewReader(`{"log":{}}`), nil, Options{}); err == nil {
		t.Error("nil policy accepted; scope is deny-by-default")
	}
}

func TestParseStopsKeepingAtTheEntryCap(t *testing.T) {
	var entries []entry
	for _, p := range []string{"a", "b", "c", "d", "e"} {
		entries = append(entries, get("https://app.example.com/"+p))
	}
	entries = append(entries, get("https://app.example.com/a"))
	rec := mustParse(t, harOf(t, entries...), Options{MaxEntries: 3})
	if len(rec.Requests) != 3 || rec.Skipped.OverLimit != 2 || rec.Skipped.Duplicate != 1 {
		t.Fatalf("requests = %d, skipped = %+v; want 3 kept, 2 over the limit, 1 duplicate", len(rec.Requests), rec.Skipped)
	}
}

func TestParseReadsFormAndJSONBodyParameterNames(t *testing.T) {
	deep := `{"a":{"b":{"c":{"d":{"e":1}}}},"list":[{"x":1},{"y":2}],"` + strings.Repeat("k", maxNameLength+1) + `":1}`
	cases := []struct {
		name string
		e    entry
		want []string
	}{
		{"form text", request("POST", "https://app.example.com/1", body(formMediaType, "b=2&a=1&a=3&=x&%zz=1")), []string{"a", "b"}},
		{"form params win over text", request("POST", "https://app.example.com/2", func(e entry) {
			e["postData"] = map[string]any{"mimeType": formMediaType, "text": "ignored=1", "params": []any{
				map[string]any{"name": "user"}, map[string]any{"name": ""},
			}}
		}), []string{"user"}},
		{"json depth and arrays", request("POST", "https://app.example.com/3", body("application/vnd.api+json", deep)), []string{"a", "a.b", "a.b.c", "a.b.c.d", "list", "list.x", "list.y"}},
		{"top-level json array", request("PUT", "https://app.example.com/4", body("text/json", `[{"id":1},{"name":"n"}]`)), []string{"id", "name"}},
		{"json that does not parse", request("PATCH", "https://app.example.com/5", body("application/json", `{"a":`)), nil},
		{"base64 form", request("POST", "https://app.example.com/6", func(e entry) {
			e["postData"] = map[string]any{"mimeType": formMediaType, "encoding": "base64", "text": "Zm9vPTEmYmFyPTI="}
		}), []string{"bar", "foo"}},
		{"base64 that does not decode", request("POST", "https://app.example.com/7", func(e entry) {
			e["postData"] = map[string]any{"mimeType": formMediaType, "encoding": "base64", "text": "!!!"}
		}), nil},
		{"no postData", request("DELETE", "https://app.example.com/8"), nil},
		{"content type from header", request("POST", "https://app.example.com/9", header("content-type", "application/json"), func(e entry) {
			e["postData"] = map[string]any{"text": `{"q":1}`}
		}), []string{"q"}},
		{"plain text body", request("POST", "https://app.example.com/10", body("text/plain", "a=1")), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := mustParse(t, harOf(t, tc.e), Options{})
			if len(rec.Requests) != 1 {
				t.Fatalf("requests = %+v", rec.Requests)
			}
			if got := rec.Requests[0].BodyParams; !slices.Equal(got, tc.want) {
				t.Errorf("body params = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestParseCapsParametersPerRequest(t *testing.T) {
	var query []string
	for i := range maxParams + 10 {
		query = append(query, "p"+strings.Repeat("x", i)+"=1")
	}
	rec := mustParse(t, harOf(t, get("https://app.example.com/?"+strings.Join(query, "&"))), Options{})
	if got := len(rec.Requests[0].QueryParams); got != maxParams {
		t.Errorf("query params = %d; want %d", got, maxParams)
	}
}

func TestParseStripsUserinfoAndFragments(t *testing.T) {
	rec := mustParse(t, harOf(t, get("https://alice:hunter22@APP.Example.com.:443/a%20b?x=1#frag")), Options{})
	if got, want := rec.Requests[0].URL, "https://app.example.com/a%20b?x=1"; got != want {
		t.Errorf("URL = %q; want %q", got, want)
	}
}

func TestParseMarksActionGETsAsStateChangingAndKeepsThemOutOfSeeds(t *testing.T) {
	har := harOf(t,
		get("https://app.example.com/account/logout"),
		get("https://app.example.com/items?action=delete&id=4"),
		get("https://app.example.com/presets"),
		request("OPTIONS", "https://app.example.com/api"),
		request("PROPFIND", "https://app.example.com/dav"),
	)
	rec := mustParse(t, har, Options{})
	if !slices.Equal(rec.URLs, []string{"https://app.example.com/presets"}) {
		t.Errorf("URLs = %v; want only the harmless page", rec.URLs)
	}
	for _, r := range rec.Requests {
		wantChanging := r.Method != "OPTIONS" && !strings.HasSuffix(r.URL, "/presets")
		if r.StateChanging != wantChanging {
			t.Errorf("%s %s state-changing = %v; want %v", r.Method, r.URL, r.StateChanging, wantChanging)
		}
	}
}

func TestParseScrubsAPathWhoseEscapeASecretSplits(t *testing.T) {
	har := harOf(t, get("https://app.example.com/%41BCDEFGHIJ/x", cookie("s", "1BCDEFGHIJ")))
	rec := mustParse(t, har, Options{})
	if got := rec.Requests[0].URL; got != "https://app.example.com/"+escapedPlaceholder {
		t.Errorf("URL = %q; want the whole path replaced", got)
	}
	assertAllInScope(t, testPolicy(t), rec)
}

func TestParseScrubsSecretsFromParameterNames(t *testing.T) {
	har := harOf(t,
		get("https://app.example.com/a", header("Authorization", "Bearer LONGTOKENVALUE99")),
		get("https://app.example.com/b?LONGTOKENVALUE99=1&ok=LONGTOKENVALUE99"),
		request("POST", "https://app.example.com/c", body("application/json", `{"LONGTOKENVALUE99":1}`)),
	)
	rec := mustParse(t, har, Options{})
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "LONGTOKENVALUE99") {
		t.Fatalf("secret survived: %s", raw)
	}
	if b := findRequest(t, rec, "GET", "https://app.example.com/b"); !slices.Contains(b.QueryParams, "[redacted]") {
		t.Errorf("query params = %v", b.QueryParams)
	}
}

func TestParseOutputIsDeterministic(t *testing.T) {
	entries := []entry{
		get("https://app.example.com/z?b=1&a=2"),
		request("POST", "https://app.example.com/z", body("application/json", `{"y":1,"x":2}`)),
		request("POST", "https://app.example.com/z", body("application/json", `{"w":1}`)),
		get("https://api.example.org/m"),
		get("https://app.example.com/a"),
	}
	reversed := slices.Clone(entries)
	slices.Reverse(reversed)
	first := mustParse(t, harOf(t, entries...), Options{})
	for range 5 {
		if again := mustParse(t, harOf(t, reversed...), Options{}); !reflect.DeepEqual(first, again) {
			t.Fatalf("output depends on input order:\n%+v\n%+v", first, again)
		}
	}
	urls := make([]string, 0, len(first.Requests))
	for _, r := range first.Requests {
		urls = append(urls, r.URL)
	}
	if !slices.IsSorted(urls) || !slices.IsSorted(first.URLs) {
		t.Errorf("not sorted: %v / %v", urls, first.URLs)
	}
}

func TestMediaTypeKeepsOnlyTheTypeAndDropsJunk(t *testing.T) {
	cases := map[string]string{
		"Application/JSON; charset=utf-8":  "application/json",
		"multipart/form-data; boundary=x;": "multipart/form-data",
		"not a media type///":              "",
		strings.Repeat("a", 200) + "/b":    "",
	}
	for in, want := range cases {
		if got := mediaType(in); got != want {
			t.Errorf("mediaType(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSensitiveHeaderFollowsRedactAndNameRules(t *testing.T) {
	s := newSecretSet()
	for _, name := range []string{"Cookie", "authorization", "X-Api-Key", "Proxy-Authorization", "X-CSRF-Token", strings.Repeat("h", maxNameLength+1)} {
		if !s.sensitiveHeader(name) {
			t.Errorf("%q not treated as sensitive", name)
		}
	}
	for range 2 { // the second round comes from the cache
		if s.sensitiveHeader("Accept") {
			t.Error("Accept treated as sensitive")
		}
	}
}

func TestSecretSetStopsGrowingAtItsCap(t *testing.T) {
	s := newSecretSet()
	for i := range maxSecrets {
		s.add("secret-value-" + strings.Repeat("x", i%50) + string(rune('a'+i%26)) + strings.Repeat("y", i/50))
	}
	if len(s.list()) > maxSecrets {
		t.Errorf("secrets = %d; cap is %d", len(s.list()), maxSecrets)
	}
}

// assertAllInScope checks every URL in rec against policy the way the rest of
// the toolkit does before a request is sent.
func assertAllInScope(t testing.TB, policy *scope.Policy, rec Recording) {
	t.Helper()
	all := slices.Clone(rec.URLs)
	for _, r := range rec.Requests {
		all = append(all, r.URL)
	}
	for _, raw := range all {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("returned URL %q does not parse: %v", raw, err)
		}
		if u.User != nil || u.Fragment != "" {
			t.Fatalf("returned URL %q keeps user information or a fragment", raw)
		}
		host, port, ok := hostPort(u, u.Scheme)
		if !ok || (u.Scheme != "http" && u.Scheme != "https") {
			t.Fatalf("returned URL %q is not an http(s) URL with a host", raw)
		}
		if err := policy.CheckTarget(host, port); err != nil {
			t.Fatalf("returned URL %q is out of scope: %v", raw, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(harOf(f,
		get("https://app.example.com/a?token=x&b=1", cookie("s", "abcdefghijk")),
		request("POST", "https://api.example.org/x", body("application/json", `{"a":{"b":[1]}}`)),
		get("http://[2001:db8::1]/"),
		get("https://203.0.113.9:8443/%41"),
	))
	f.Add(`{"log":{"entries":[{"request":{"method":"GET","url":"https://u:p@app.example.com./x#f"}}]}}`)
	f.Add(`{"log":{"entries":[{"request":{"method":"POST","url":"data:,x","postData":{"encoding":"base64","text":"=="}}}]}}`)
	f.Add(`{"log":null}`)
	f.Add(`not json`)
	policy := testPolicy(f)
	f.Fuzz(func(t *testing.T, input string) {
		rec, err := Parse(strings.NewReader(input), policy, Options{MaxBytes: 1 << 16, MaxEntries: 50})
		if err != nil {
			if !strings.HasPrefix(err.Error(), "har: ") {
				t.Fatalf("error without prefix: %v", err)
			}
			return
		}
		assertAllInScope(t, policy, rec)
	})
}
