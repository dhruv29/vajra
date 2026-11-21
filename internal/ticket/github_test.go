package ticket

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// secretToken stands for a real credential. No error may contain it.
const secretToken = "ghp_s3cr3tT0ken"

var sampleIssue = Issue{FindingID: "0a1b2c3d4e5f6071", Title: "[high] SQL injection in order lookup", Body: "**Target.** https://shop.test/orders\n"}

func assertNoSecret(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got none")
	}
	for _, s := range append([]string{secretToken, "s3cr3t"}, secrets...) {
		if strings.Contains(err.Error(), s) {
			t.Errorf("error leaks %q: %v", s, err)
		}
	}
}

// fakeGitHub answers the two calls a GitHub filer makes. existing, when set,
// is returned by the search.
type fakeGitHub struct {
	t        *testing.T
	existing []githubIssue
	searches atomic.Int32
	creates  atomic.Int32
	query    atomic.Value
	created  atomic.Value
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+secretToken || r.Header.Get("X-GitHub-Api-Version") != githubAPIVersion {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/search/issues":
		f.searches.Add(1)
		f.query.Store(r.URL.Query().Get("q"))
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.existing})
	case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/shop/issues":
		f.creates.Add(1)
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.created.Store(got)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"number":42,"html_url":"https://github.com/acme/shop/issues/42","state":"open"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newGitHubFiler(t *testing.T, base string) *GitHub {
	t.Helper()
	g, err := NewGitHub(GitHubOptions{BaseURL: base, Repo: "acme/shop", Token: secretToken})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGitHubFilesANewIssueWithTheFindingMarker(t *testing.T) {
	fake := &fakeGitHub{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	got, err := newGitHubFiler(t, srv.URL).File(context.Background(), sampleIssue)

	if err != nil {
		t.Fatal(err)
	}
	want := Result{URL: "https://github.com/acme/shop/issues/42", Key: "acme/shop#42", State: "open"}
	if got != want {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
	if q, _ := fake.query.Load().(string); q != `repo:acme/shop is:issue author:@me in:body "vajra-finding: 0a1b2c3d4e5f6071"` {
		t.Fatalf("search query = %q", q)
	}
	sent, _ := fake.created.Load().(map[string]string)
	if sent["title"] != sampleIssue.Title || !hasMarker(sent["body"], sampleIssue.FindingID) || !strings.HasPrefix(sent["body"], "**Target.**") {
		t.Fatalf("created issue = %#v", sent)
	}
}

func TestGitHubReturnsTheExistingIssueInsteadOfFilingAgain(t *testing.T) {
	fake := &fakeGitHub{t: t, existing: []githubIssue{
		// A loose match for another finding, and a pull request, come first.
		{Number: 7, HTMLURL: "https://github.com/acme/shop/issues/7", Body: "vajra-finding: 0a1b2c3d4e5f6071-other"},
		{Number: 8, HTMLURL: "https://github.com/acme/shop/pull/8", Body: "vajra-finding: 0a1b2c3d4e5f6071", PullRequest: &struct {
			URL string `json:"url"`
		}{URL: "x"}},
		{Number: 9, HTMLURL: "https://github.com/acme/shop/issues/9", State: "closed", Body: "text\n\nvajra-finding: 0a1b2c3d4e5f6071\n"},
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	got, err := newGitHubFiler(t, srv.URL).File(context.Background(), sampleIssue)

	if err != nil {
		t.Fatal(err)
	}
	if !got.Existing || got.Key != "acme/shop#9" || got.State != "closed" || fake.creates.Load() != 0 {
		t.Fatalf("result = %+v, creates = %d", got, fake.creates.Load())
	}
}

func TestGitHubFilesWhenSearchHitsAreOnlyLooseMatches(t *testing.T) {
	fake := &fakeGitHub{t: t, existing: []githubIssue{{Number: 7, Body: "mentions vajra-finding: 0a1b2c3d4e5f6071 inline"}}}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	got, err := newGitHubFiler(t, srv.URL).File(context.Background(), sampleIssue)

	if err != nil || got.Existing || fake.creates.Load() != 1 {
		t.Fatalf("result = %+v, err = %v, creates = %d", got, err, fake.creates.Load())
	}
}

func TestGitHubWorksOverTLSWithTheCallersClient(t *testing.T) {
	fake := &fakeGitHub{t: t}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	g, err := NewGitHub(GitHubOptions{BaseURL: srv.URL + "/", Repo: "acme/shop", Token: secretToken, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}

	got, err := g.File(context.Background(), sampleIssue)

	if err != nil || got.Key != "acme/shop#42" {
		t.Fatalf("result = %+v, err = %v", got, err)
	}
}

func TestGitHubClipsTheTitleAndBodyButKeepsTheMarker(t *testing.T) {
	fake := &fakeGitHub{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	long := Issue{FindingID: "abc", Title: strings.Repeat("ü\n", 400), Body: strings.Repeat("é", githubBodyLimit*2)}

	if _, err := newGitHubFiler(t, srv.URL).File(context.Background(), long); err != nil {
		t.Fatal(err)
	}

	sent, _ := fake.created.Load().(map[string]string)
	title, body := []rune(sent["title"]), []rune(sent["body"])
	if len(title) != githubTitleLimit || strings.Contains(sent["title"], "\n") {
		t.Errorf("title is %d characters: %.40q", len(title), sent["title"])
	}
	if len(body) > githubBodyLimit || !hasMarker(sent["body"], "abc") || !strings.Contains(sent["body"], clipNote) {
		t.Errorf("body is %d characters, marker kept: %v", len(body), hasMarker(sent["body"], "abc"))
	}
}

func TestGitHubCreateReplyWithoutANumberIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"items":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	_, err := newGitHubFiler(t, srv.URL).File(context.Background(), sampleIssue)

	if err == nil || !strings.Contains(err.Error(), "did not say where it is") {
		t.Fatalf("err = %v", err)
	}
	assertNoSecret(t, err)
}

func TestBadGitHubOptionsAreRefused(t *testing.T) {
	cases := map[string]GitHubOptions{
		"no slash":           {Repo: "acmeshop", Token: secretToken},
		"empty owner":        {Repo: "/shop", Token: secretToken},
		"empty repo":         {Repo: "acme/", Token: secretToken},
		"extra path":         {Repo: "acme/shop/issues", Token: secretToken},
		"dot dot":            {Repo: "acme/..", Token: secretToken},
		"query in name":      {Repo: "acme/shop?x=1", Token: secretToken},
		"space in owner":     {Repo: "ac me/shop", Token: secretToken},
		"owner too long":     {Repo: strings.Repeat("a", 40) + "/shop", Token: secretToken},
		"no token":           {Repo: "acme/shop"},
		"token with newline": {Repo: "acme/shop", Token: secretToken + "\nX-Evil: 1"},
		"plain http":         {Repo: "acme/shop", Token: secretToken, BaseURL: "http://api.github.com"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewGitHub(opts)
			assertNoSecret(t, err)
			if !strings.HasPrefix(err.Error(), "ticket: ") {
				t.Errorf("error lacks the package prefix: %v", err)
			}
		})
	}
}

func TestTheDefaultGitHubAPIIsUsedWhenNoneIsGiven(t *testing.T) {
	g, err := NewGitHub(GitHubOptions{Repo: "acme/shop.go", Token: secretToken})
	if err != nil || g.api.base != DefaultGitHubAPI {
		t.Fatalf("g = %+v, err = %v", g, err)
	}
}
