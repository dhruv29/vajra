package ticket

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// filers builds one filer of each kind against base, so that every check of
// the shared client runs for both trackers.
func filers(t *testing.T, base string) map[string]Filer {
	t.Helper()
	return map[string]Filer{
		"github": newGitHubFiler(t, base),
		"jira":   newJiraFiler(t, base),
	}
}

func TestAnErrorStatusIsReportedWithAClippedMessageAndNoToken(t *testing.T) {
	replies := map[string]string{
		"github shape": `{"message":"Bad credentials for ` + secretToken + `","documentation_url":"https://docs.github.com"}`,
		"jira shape":   `{"errorMessages":["Field 'x' cannot be set ` + secretToken + `"],"errors":{"summary":"too long"}}`,
		"html page":    "<html>" + strings.Repeat("down for maintenance ", 50) + secretToken + "</html>",
	}
	for name, reply := range replies {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, reply)
		}))
		for kind, f := range filers(t, srv.URL) {
			t.Run(name+"/"+kind, func(t *testing.T) {
				_, err := f.File(context.Background(), sampleIssue)
				assertNoSecret(t, err)
				if !strings.Contains(err.Error(), "status 403") || len(err.Error()) > 400 {
					t.Errorf("err = %v", err)
				}
			})
		}
		srv.Close()
	}
}

func TestAnErrorStatusWithAnEmptyBodyStillNamesTheStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	for kind, f := range filers(t, srv.URL) {
		_, err := f.File(context.Background(), sampleIssue)
		if err == nil || !strings.HasSuffix(err.Error(), "returned status 502") {
			t.Errorf("%s: err = %v", kind, err)
		}
	}
}

func TestARedirectIsNotFollowed(t *testing.T) {
	var reached atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	for kind, f := range filers(t, srv.URL) {
		_, err := f.File(context.Background(), sampleIssue)
		assertNoSecret(t, err)
		if !strings.Contains(err.Error(), "redirect (status 307)") {
			t.Errorf("%s: err = %v", kind, err)
		}
	}
	// Even a client from the caller that would follow redirects does not.
	g, err := NewGitHub(GitHubOptions{BaseURL: srv.URL, Repo: "acme/shop", Token: secretToken, HTTP: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.File(context.Background(), sampleIssue); err == nil {
		t.Error("a caller's client followed the redirect")
	}
	if reached.Load() != 0 {
		t.Fatalf("the redirect target was reached %d times", reached.Load())
	}
}

func TestAnOversizedReplyIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"items":[],"pad":"`+strings.Repeat("x", maxResponseBytes)+`"}`)
	}))
	defer srv.Close()
	for kind, f := range filers(t, srv.URL) {
		_, err := f.File(context.Background(), sampleIssue)
		if !errors.Is(err, errReplyTooLarge) {
			t.Errorf("%s: err = %v", kind, err)
		}
	}
}

func TestAReplyThatIsNotJSONIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>ok</html>")
	}))
	defer srv.Close()
	for kind, f := range filers(t, srv.URL) {
		_, err := f.File(context.Background(), sampleIssue)
		if err == nil || !strings.Contains(err.Error(), "not the JSON expected") {
			t.Errorf("%s: err = %v", kind, err)
		}
	}
}

func TestAnUnreachableTrackerGivesAnErrorWithoutTheQueryOrToken(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	for kind, f := range filers(t, base) {
		_, err := f.File(context.Background(), sampleIssue)
		// The query names the finding; the wrapper that would repeat it is gone.
		assertNoSecret(t, err, "vajra-finding", "jql=", "q=")
		if !strings.Contains(err.Error(), base) {
			t.Errorf("%s: err does not name the tracker: %v", kind, err)
		}
	}
}

func TestACancelledContextStopsTheRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for kind, f := range filers(t, srv.URL) {
		if _, err := f.File(ctx, sampleIssue); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: err = %v", kind, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server was reached %d times", hits.Load())
	}
}

func TestAPIBaseURLsAreChecked(t *testing.T) {
	cases := []struct {
		raw     string
		wantErr string
		want    string
	}{
		{raw: "https://api.github.com", want: "https://api.github.com"},
		{raw: "https://ghe.example.test/api/v3/", want: "https://ghe.example.test/api/v3"},
		{raw: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{raw: "http://[::1]:8080/", want: "http://[::1]:8080"},
		{raw: "http://localhost:8080", wantErr: "must use https"},
		{raw: "http://10.0.0.5", wantErr: "must use https"},
		{raw: "http://api.github.com", wantErr: "must use https"},
		{raw: "ftp://api.github.com", wantErr: "not supported"},
		{raw: "https://user:" + secretToken + "@api.github.com", wantErr: "user name or password"},
		{raw: "https://api.github.com/?token=" + secretToken, wantErr: "query or fragment"},
		{raw: "https://api.github.com/#" + secretToken, wantErr: "query or fragment"},
		{raw: "https:///nohost", wantErr: "no host"},
		{raw: "https://bad host/" + secretToken + "%zz", wantErr: "malformed"},
		{raw: "", wantErr: "no host"},
	}
	for _, c := range cases {
		got, err := checkBaseURL("github", c.raw)
		if c.wantErr == "" {
			if err != nil || got != c.want {
				t.Errorf("%q: got %q, %v; want %q", c.raw, got, err, c.want)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%q: err = %v, want one containing %q", c.raw, err, c.wantErr)
			continue
		}
		assertNoSecret(t, err)
	}
}

func TestAnIssueWithABadFindingIDOrNoTitleIsRefusedBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	bad := []Issue{
		{FindingID: `x" OR labels is not EMPTY OR "`, Title: "t"},
		{FindingID: "", Title: "t"},
		{FindingID: "-leading-dash", Title: "t"},
		{FindingID: strings.Repeat("a", 65), Title: "t"},
		{FindingID: "abc", Title: " \n "},
	}
	for kind, f := range filers(t, srv.URL) {
		for _, issue := range bad {
			if _, err := f.File(context.Background(), issue); err == nil {
				t.Errorf("%s: %+v was accepted", kind, issue)
			}
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server was reached %d times", hits.Load())
	}
}

func TestARequestOverTheSizeCapIsNotSent(t *testing.T) {
	_, err := encodeRequest("github", map[string]string{"body": strings.Repeat("x", maxRequestBytes)})
	if err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Fatalf("err = %v", err)
	}
	if _, err := encodeRequest("github", map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("an unencodable request was accepted")
	}
}

func TestClipRunesCountsCharactersAndMarksTheCut(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 4, "hel" + clipNote},
		{"ééééé", 3, "éé" + clipNote},
		{"hello", 0, ""},
	}
	for _, c := range cases {
		if got := clipRunes(c.in, c.limit); got != c.want {
			t.Errorf("clipRunes(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
	}
}

func TestTheMarkerMustBeOnALineOfItsOwn(t *testing.T) {
	cases := map[string]bool{
		"vajra-finding: abc":              true,
		"intro\n  vajra-finding: abc  \n": true,
		"vajra-finding: abcd":             false,
		"see vajra-finding: abc":          false,
		"":                                false,
	}
	for text, want := range cases {
		if got := hasMarker(text, "abc"); got != want {
			t.Errorf("hasMarker(%q) = %v, want %v", text, got, want)
		}
	}
}
