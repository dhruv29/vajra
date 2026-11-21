package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

// fakeOSV is an in-memory stand-in for the API. It records what it was asked
// so tests can check batching, paging and caching.
type fakeOSV struct {
	mu sync.Mutex
	// vulns maps "ecosystem/name@version" to pages of advisory ids.
	vulns map[string][][]string
	// details maps an advisory id to the JSON served for it.
	details map[string]string

	batchSizes  []int
	tokens      []string
	detailCalls map[string]int
}

func newFakeOSV() *fakeOSV {
	return &fakeOSV{vulns: map[string][][]string{}, details: map[string]string{}, detailCalls: map[string]int{}}
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == batchPath:
		f.serveBatch(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, vulnPath):
		id := strings.TrimPrefix(r.URL.Path, vulnPath)
		f.detailCalls[id]++
		body, ok := f.details[id]
		if !ok {
			http.Error(w, `{"code":5,"message":"Vulnerability not found"}`, http.StatusNotFound)
			return
		}
		fmt.Fprint(w, body)
	default:
		http.Error(w, "unexpected request", http.StatusTeapot)
	}
}

func (f *fakeOSV) serveBatch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.batchSizes = append(f.batchSizes, len(req.Queries))
	type result struct {
		Vulns []map[string]string `json:"vulns,omitempty"`
		Next  string              `json:"next_page_token,omitempty"`
	}
	results := make([]result, len(req.Queries))
	for i, q := range req.Queries {
		pages := f.vulns[q.Package.Ecosystem+"/"+q.Package.Name+"@"+q.Version]
		page := 0
		if q.PageToken != "" {
			f.tokens = append(f.tokens, q.PageToken)
			fmt.Sscanf(q.PageToken, "page-%d", &page)
		}
		if page >= len(pages) {
			continue
		}
		for _, id := range pages[page] {
			results[i].Vulns = append(results[i].Vulns, map[string]string{"id": id, "modified": "2026-01-01T00:00:00Z"})
		}
		if page+1 < len(pages) {
			results[i].Next = fmt.Sprintf("page-%d", page+1)
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"results": results})
}

func (f *fakeOSV) client(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return NewClient(Options{BaseURL: srv.URL + "/", HTTP: srv.Client()})
}

// lodashDetail is trimmed from a real record: one advisory covering several
// packages, each with its own fix.
const lodashDetail = `{
  "id": "GHSA-35jh-r3h4-6jhm",
  "summary": "Command Injection in lodash",
  "aliases": ["CVE-2021-23337"],
  "database_specific": {"github_reviewed": true, "cwe_ids": ["CWE-77", "CWE-94", "CWE-77", "nonsense"], "severity": "HIGH"},
  "affected": [
    {"package": {"name": "lodash", "ecosystem": "npm"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]},
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "3469357cff39"}]}]},
    {"package": {"name": "lodash-es", "ecosystem": "npm"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.22"}]}]},
    {"package": {"name": "lodash.template", "ecosystem": "npm"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "4.5.0"}]}]}
  ],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}]
}`

func TestQueryReturnsAdvisoriesPerPackage(t *testing.T) {
	// Arrange
	fake := newFakeOSV()
	fake.vulns["npm/lodash@4.17.20"] = [][]string{{"GHSA-35jh-r3h4-6jhm", "GO-2021-0113"}}
	fake.vulns["npm/lodash-es@4.17.20"] = [][]string{{"GHSA-35jh-r3h4-6jhm"}}
	fake.details["GHSA-35jh-r3h4-6jhm"] = lodashDetail
	fake.details["GO-2021-0113"] = `{"id":"GO-2021-0113","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}`
	pkgs := []Package{
		{Ecosystem: "npm", Name: "lodash-es", Version: "4.17.20"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "npm", Name: "unversioned"},
	}

	// Act
	got, err := fake.client(t).Query(context.Background(), pkgs)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(pkgs) {
		t.Fatalf("got %d results, want %d", len(got), len(pkgs))
	}
	if len(got[0]) != 1 || len(got[1]) != 0 || len(got[2]) != 2 || len(got[3]) != 0 {
		t.Fatalf("advisory counts wrong: %v", got)
	}
	adv := got[2][0]
	if adv.ID != "GHSA-35jh-r3h4-6jhm" || adv.Summary != "Command Injection in lodash" || adv.Severity != finding.SeverityHigh {
		t.Errorf("advisory = %+v", adv)
	}
	if !equalStrings(adv.Aliases, []string{"CVE-2021-23337"}) {
		t.Errorf("aliases = %v", adv.Aliases)
	}
	if !equalStrings(adv.CWE, []string{"cwe-77", "cwe-94"}) {
		t.Errorf("cwe = %v", adv.CWE)
	}
	if !equalStrings(adv.FixedIn, []string{"4.17.21"}) {
		t.Errorf("lodash fixed in %v, want only its own fix", adv.FixedIn)
	}
	if !equalStrings(got[0][0].FixedIn, []string{"4.17.22"}) {
		t.Errorf("lodash-es fixed in %v", got[0][0].FixedIn)
	}
	if vectorOnly := got[2][1]; vectorOnly.Severity != finding.SeverityUnknown || vectorOnly.FixedIn != nil {
		t.Errorf("vector-only advisory = %+v", vectorOnly)
	}
	if n := fake.batchSizes; len(n) != 1 || n[0] != 3 {
		t.Errorf("batch sizes = %v, want one batch of the 3 queryable packages", n)
	}
}

func TestQueryFetchesEachAdvisoryOnce(t *testing.T) {
	// Arrange
	fake := newFakeOSV()
	fake.details["X-1"] = `{"id":"X-1"}`
	var pkgs []Package
	for i := range 40 {
		p := Package{Ecosystem: "npm", Name: fmt.Sprintf("p%d", i), Version: "1.0.0"}
		fake.vulns["npm/"+p.Name+"@1.0.0"] = [][]string{{"X-1", "X-1"}}
		pkgs = append(pkgs, p)
	}

	// Act
	got, err := fake.client(t).Query(context.Background(), pkgs)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if fake.detailCalls["X-1"] != 1 {
		t.Errorf("advisory fetched %d times, want 1", fake.detailCalls["X-1"])
	}
	for i, advs := range got {
		if len(advs) != 1 || advs[0].ID != "X-1" {
			t.Fatalf("package %d: %v", i, advs)
		}
	}
}

func TestQueryBatchesAndKeepsOrder(t *testing.T) {
	// Arrange
	fake := newFakeOSV()
	total := 2*maxBatchQueries + 7
	pkgs := make([]Package, total)
	for i := range pkgs {
		pkgs[i] = Package{Ecosystem: "PyPI", Name: fmt.Sprintf("p%d", i), Version: "1.0"}
	}
	for _, i := range []int{0, maxBatchQueries, total - 1} {
		id := fmt.Sprintf("ID-%d", i)
		fake.vulns["PyPI/"+pkgs[i].Name+"@1.0"] = [][]string{{id}}
		fake.details[id] = fmt.Sprintf(`{"id":%q}`, id)
	}

	// Act
	got, err := fake.client(t).Query(context.Background(), pkgs)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{maxBatchQueries, maxBatchQueries, 7}; fmt.Sprint(fake.batchSizes) != fmt.Sprint(want) {
		t.Errorf("batch sizes = %v, want %v", fake.batchSizes, want)
	}
	for i, advs := range got {
		want := 0
		if i == 0 || i == maxBatchQueries || i == total-1 {
			want = 1
		}
		if len(advs) != want || (want == 1 && advs[0].ID != fmt.Sprintf("ID-%d", i)) {
			t.Fatalf("package %d: %v", i, advs)
		}
	}
}

func TestQueryFollowsPages(t *testing.T) {
	// Arrange
	fake := newFakeOSV()
	fake.vulns["Go/a@v1.0.0"] = [][]string{{"C"}, {"A"}, {"B"}}
	fake.vulns["Go/b@v1.0.0"] = [][]string{{"A"}}
	for _, id := range []string{"A", "B", "C"} {
		fake.details[id] = fmt.Sprintf(`{"id":%q}`, id)
	}
	pkgs := []Package{{Ecosystem: "Go", Name: "a", Version: "v1.0.0"}, {Ecosystem: "Go", Name: "b", Version: "v1.0.0"}}

	// Act
	got, err := fake.client(t).Query(context.Background(), pkgs)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	ids := func(advs []Advisory) (out []string) {
		for _, a := range advs {
			out = append(out, a.ID)
		}
		return out
	}
	if !equalStrings(ids(got[0]), []string{"A", "B", "C"}) || !equalStrings(ids(got[1]), []string{"A"}) {
		t.Errorf("got %v and %v", ids(got[0]), ids(got[1]))
	}
	if !equalStrings(fake.tokens, []string{"page-1", "page-2"}) {
		t.Errorf("page tokens sent = %v", fake.tokens)
	}
	if want := []int{2, 1, 1}; fmt.Sprint(fake.batchSizes) != fmt.Sprint(want) {
		t.Errorf("batch sizes = %v, want %v: only the paged package is asked again", fake.batchSizes, want)
	}
}

func TestQueryWithNoPackagesMakesNoRequests(t *testing.T) {
	fake := newFakeOSV()

	got, err := fake.client(t).Query(context.Background(), nil)

	if err != nil || len(got) != 0 || len(fake.batchSizes) != 0 {
		t.Fatalf("got %v, %v after %d requests", got, err, len(fake.batchSizes))
	}
}

func TestQueryFailures(t *testing.T) {
	const secret = "body-text-that-must-not-leak"
	oneResult := `{"results":[{"vulns":[{"id":"X-1"}]}]}`
	tests := []struct {
		name    string
		batch   func(w http.ResponseWriter)
		detail  func(w http.ResponseWriter)
		wantErr string
	}{
		{"batch non-200", func(w http.ResponseWriter) { http.Error(w, secret, http.StatusInternalServerError) }, nil, "500"},
		{"batch rate limited", func(w http.ResponseWriter) { http.Error(w, secret, http.StatusTooManyRequests) }, nil, "429"},
		{"batch malformed JSON", func(w http.ResponseWriter) { fmt.Fprint(w, `{"results": [`+secret) }, nil, "decode reply"},
		{"batch wrong result count", func(w http.ResponseWriter) { fmt.Fprint(w, `{"results":[{},{}]}`) }, nil, "2 results for 1 queries"},
		{"batch empty reply", func(w http.ResponseWriter) { fmt.Fprint(w, `{}`) }, nil, "0 results for 1 queries"},
		{"batch endless pages", func(w http.ResponseWriter) { fmt.Fprint(w, `{"results":[{"next_page_token":"again"}]}`) }, nil, "still incomplete"},
		{"batch oversized", func(w http.ResponseWriter) {
			fmt.Fprint(w, `{"results":[{"next_page_token":"`+strings.Repeat("a", maxResponseBytes)+`"}]}`)
		}, nil, "larger than the read limit"},
		{"detail not found", func(w http.ResponseWriter) { fmt.Fprint(w, oneResult) },
			func(w http.ResponseWriter) { http.Error(w, secret, http.StatusNotFound) }, "404"},
		{"detail malformed JSON", func(w http.ResponseWriter) { fmt.Fprint(w, oneResult) },
			func(w http.ResponseWriter) { fmt.Fprint(w, secret) }, "decode reply"},
		{"detail without id", func(w http.ResponseWriter) { fmt.Fprint(w, oneResult) },
			func(w http.ResponseWriter) { fmt.Fprint(w, `{}`) }, "not an advisory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == batchPath {
					tt.batch(w)
					return
				}
				tt.detail(w)
			}))
			defer srv.Close()
			client := NewClient(Options{BaseURL: srv.URL, HTTP: srv.Client()})

			// Act
			got, err := client.Query(context.Background(), []Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}})

			// Assert
			if err == nil || got != nil {
				t.Fatalf("got %v, %v; want an error and no result", got, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error quotes the response body: %q", err)
			}
		})
	}
}

func TestQueryStopsDetailLookupsAfterAFailure(t *testing.T) {
	// Arrange
	fake := newFakeOSV()
	var ids []string
	for i := range 200 {
		ids = append(ids, fmt.Sprintf("MISSING-%03d", i))
	}
	fake.vulns["npm/a@1.0.0"] = [][]string{ids}

	// Act
	_, err := fake.client(t).Query(context.Background(), []Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}})

	// Assert
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v, want the 404", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.detailCalls) == len(ids) {
		t.Errorf("all %d advisories were requested after the first failure", len(ids))
	}
}

func TestQueryHonoursCancellation(t *testing.T) {
	t.Run("before the first request", func(t *testing.T) {
		fake := newFakeOSV()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := fake.client(t).Query(ctx, []Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}})

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("between the batch query and the details", func(t *testing.T) {
		// Arrange
		ctx, cancel := context.WithCancel(context.Background())
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"results":[{"vulns":[{"id":"X-1"}]}]}`)
			cancel()
		}))
		defer srv.Close()
		client := NewClient(Options{BaseURL: srv.URL, HTTP: srv.Client()})

		// Act
		got, err := client.Query(ctx, []Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}})

		// Assert
		if !errors.Is(err, context.Canceled) || got != nil {
			t.Fatalf("got %v, %v; want context.Canceled", got, err)
		}
	})
}

func TestQueryUnreachableServerIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	_, err := NewClient(Options{BaseURL: srv.URL}).Query(context.Background(), []Package{{Ecosystem: "npm", Name: "a", Version: "1"}})

	if err == nil {
		t.Fatal("want an error when the server cannot be reached")
	}
}

func TestQueryRejectsAnUnusableBaseURL(t *testing.T) {
	_, err := NewClient(Options{BaseURL: "http://bad host"}).Query(context.Background(), []Package{{Ecosystem: "npm", Name: "a", Version: "1"}})

	if err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("err = %v, want a request-building error", err)
	}
}

func TestNewClientDefaults(t *testing.T) {
	c := NewClient(Options{})

	if c.baseURL != defaultBaseURL || c.http == nil {
		t.Fatalf("client = %+v", c)
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		database string
		want     finding.Severity
	}{
		{`{"severity":"LOW"}`, finding.SeverityLow},
		{`{"severity":"MODERATE"}`, finding.SeverityMedium},
		{`{"severity":"medium"}`, finding.SeverityMedium},
		{`{"severity":" High "}`, finding.SeverityHigh},
		{`{"severity":"CRITICAL"}`, finding.SeverityCritical},
		{`{"severity":"SPICY"}`, finding.SeverityUnknown},
		{`{"severity":7.5}`, finding.SeverityUnknown},
		{`{"severity":["HIGH"]}`, finding.SeverityUnknown},
		{`{}`, finding.SeverityUnknown},
		{`"a string"`, finding.SeverityUnknown},
		{``, finding.SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.database, func(t *testing.T) {
			detail := vulnDetail{ID: "X", DatabaseSpecific: json.RawMessage(tt.database)}

			got := detail.advisoryFor("X", Package{})

			if got.Severity != tt.want {
				t.Errorf("severity = %q, want %q", got.Severity, tt.want)
			}
		})
	}
}

func TestAdvisoryToleratesOddDatabaseFields(t *testing.T) {
	// A field of the wrong type costs only that field.
	var detail vulnDetail
	raw := `{"id":"X","database_specific":{"severity":"LOW","cwe_ids":"CWE-79"},
	  "affected":[{"package":{"name":"Flask_Cors","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"4.0.1"},{"fixed":"4.0.1"},{"fixed":"5.0.0"}]}]},
	              {"package":{"name":"flask-cors","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"9.9.9"}]}]}]}`
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		t.Fatal(err)
	}

	got := detail.advisoryFor("X", Package{Ecosystem: "PyPI", Name: "flask.cors", Version: "3.0.0"})

	if got.Severity != finding.SeverityLow || got.CWE != nil {
		t.Errorf("severity %q, cwe %v", got.Severity, got.CWE)
	}
	if !equalStrings(got.FixedIn, []string{"4.0.1", "5.0.0"}) {
		t.Errorf("fixed in %v", got.FixedIn)
	}
}
