package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const testTrackerToken = "ghp_cl1T0kenValue"

// demoRun saves the sample run and returns its data directory and ID. It has
// confirmed findings (demo-sqli) and unconfirmed ones (demo-xss).
func demoRun(t *testing.T) (string, string) {
	t.Helper()
	data := t.TempDir()
	_, stdout, _ := invoke("demo", "-data", data)
	return data, strings.SplitN(strings.SplitN(stdout, "saved sample run ", 2)[1], ";", 2)[0]
}

// withTrackerEnv points GitHub filing at base and supplies credentials.
func withTrackerEnv(t *testing.T, base string, env map[string]string) {
	t.Helper()
	deps := newDeps()
	deps.GitHubBaseURL = base
	deps.Getenv = func(name string) string { return env[name] }
	useDeps(t, deps)
}

// stubGitHub answers search with existing (when set) and records creates.
func stubGitHub(t *testing.T, existing string, creates *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testTrackerToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"message":"Bad credentials"}`)
			return
		}
		if r.Method == http.MethodGet {
			items := []any{}
			if existing != "" {
				items = append(items, map[string]any{"number": 5, "html_url": existing, "state": "open", "body": "x\n\nvajra-finding: demo-sqli\n"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
			return
		}
		creates.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"number":12,"html_url":"https://github.com/acme/shop/issues/12","state":"open"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTicketFilesAConfirmedFindingOnGitHub(t *testing.T) {
	data, id := demoRun(t)
	var creates atomic.Int32
	srv := stubGitHub(t, "", &creates)
	withTrackerEnv(t, srv.URL, map[string]string{envGitHubToken: testTrackerToken + "\n"})

	code, out, stderr := invoke("ticket", "-data", data, "-run", id, "-finding", "demo-sqli", "-file", "github", "-repo", "acme/shop")

	if code != exitOK || out != "filed acme/shop#12: https://github.com/acme/shop/issues/12\n" || creates.Load() != 1 {
		t.Fatalf("code = %d, out = %q, stderr = %q, creates = %d", code, out, stderr, creates.Load())
	}
}

func TestTicketReportsAnExistingGitHubIssueInsteadOfFilingAgain(t *testing.T) {
	data, id := demoRun(t)
	var creates atomic.Int32
	srv := stubGitHub(t, "https://github.com/acme/shop/issues/5", &creates)
	withTrackerEnv(t, srv.URL, map[string]string{envGitHubToken: testTrackerToken})

	code, out, stderr := invoke("ticket", "-data", data, "-run", id, "-finding", "demo-sqli", "-file", "github", "-repo", "acme/shop")

	if code != exitOK || !strings.Contains(out, "already filed as acme/shop#5 (open)") || creates.Load() != 0 {
		t.Fatalf("code = %d, out = %q, stderr = %q, creates = %d", code, out, stderr, creates.Load())
	}
}

func TestTicketFilesAConfirmedFindingInJira(t *testing.T) {
	data, id := demoRun(t)
	var jql atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "sec@example.test" || pass != testTrackerToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			jql.Store(r.URL.Query().Get("jql"))
			_, _ = io.WriteString(w, `{"issues":[]}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"key":"SEC-3"}`)
	}))
	defer srv.Close()
	withTrackerEnv(t, unreachableURL, map[string]string{envJiraEmail: "sec@example.test", envJiraToken: testTrackerToken})

	code, out, stderr := invoke("ticket", "-data", data, "-run", id, "-finding", "demo-sqli", "-file", "jira", "-jira-url", srv.URL, "-jira-project", "SEC")

	if code != exitOK || out != "filed SEC-3: "+srv.URL+"/browse/SEC-3\n" {
		t.Fatalf("code = %d, out = %q, stderr = %q", code, out, stderr)
	}
	if q, _ := jql.Load().(string); !strings.Contains(q, `labels = "vajra-demo-sqli"`) {
		t.Fatalf("jql = %q", q)
	}
}

func TestTicketRefusesToFileAnUnconfirmedFindingWithoutForce(t *testing.T) {
	data, id := demoRun(t)
	var creates atomic.Int32
	srv := stubGitHub(t, "", &creates)
	withTrackerEnv(t, srv.URL, map[string]string{envGitHubToken: testTrackerToken})
	args := []string{"ticket", "-data", data, "-run", id, "-finding", "demo-xss", "-file", "github", "-repo", "acme/shop"}

	code, _, stderr := invoke(args...)

	if code == exitOK || !strings.Contains(stderr, "demo-xss is unconfirmed") || creates.Load() != 0 {
		t.Fatalf("code = %d, stderr = %q, creates = %d", code, stderr, creates.Load())
	}
	if code, _, stderr := invoke(append(args, "-force")...); code != exitOK || creates.Load() != 1 {
		t.Fatalf("with -force: code = %d, stderr = %q", code, stderr)
	}
}

func TestTicketFilingErrorsNeverShowTheToken(t *testing.T) {
	data, id := demoRun(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"token `+testTrackerToken+` lacks scope"}`)
	}))
	defer srv.Close()
	withTrackerEnv(t, srv.URL, map[string]string{envGitHubToken: testTrackerToken})

	code, out, stderr := invoke("ticket", "-data", data, "-run", id, "-finding", "demo-sqli", "-file", "github", "-repo", "acme/shop")

	if code != exitError || !strings.Contains(stderr, "status 403") || strings.Contains(stderr+out, testTrackerToken) {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
}

func TestTicketFilingFlagMistakesAreReported(t *testing.T) {
	data, id := demoRun(t)
	withTrackerEnv(t, unreachableURL, map[string]string{})
	base := []string{"ticket", "-data", data, "-run", id, "-finding", "demo-sqli"}
	cases := map[string]struct {
		args []string
		want string
	}{
		"unknown tracker":      {[]string{"-file", "gitlab"}, "unknown tracker"},
		"github without repo":  {[]string{"-file", "github"}, "needs -repo"},
		"jira without project": {[]string{"-file", "jira", "-jira-url", "https://x.atlassian.net"}, "needs -jira-url and -jira-project"},
		"out with file":        {[]string{"-file", "github", "-repo", "a/b", "-out", "x.md"}, "-out cannot be used"},
		"repo without file":    {[]string{"-repo", "a/b"}, "need -file"},
		"no github token":      {[]string{"-file", "github", "-repo", "a/b"}, "set " + envGitHubToken},
		"no jira credentials":  {[]string{"-file", "jira", "-jira-url", "https://x.atlassian.net", "-jira-project", "SEC"}, "set " + envJiraEmail},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := invoke(append(append([]string(nil), base...), c.args...)...)
			if code == exitOK || !strings.Contains(stderr, c.want) {
				t.Fatalf("code = %d, stderr = %q, want %q", code, stderr, c.want)
			}
		})
	}
}

func TestTicketFilingRefusesBadTrackerSettings(t *testing.T) {
	data, id := demoRun(t)
	withTrackerEnv(t, unreachableURL, map[string]string{envGitHubToken: testTrackerToken, envJiraEmail: "sec@example.test", envJiraToken: testTrackerToken})
	base := []string{"ticket", "-data", data, "-run", id, "-finding", "demo-sqli"}
	cases := map[string][]string{
		"repo with extra path": {"-file", "github", "-repo", "a/b/c"},
		"repo with query":      {"-file", "github", "-repo", "a/b?x=1"},
		"http to the internet": {"-file", "jira", "-jira-url", "http://x.atlassian.net", "-jira-project", "SEC"},
		"lower-case project":   {"-file", "jira", "-jira-url", "https://x.atlassian.net", "-jira-project", "sec"},
		"project with quote":   {"-file", "jira", "-jira-url", "https://x.atlassian.net", "-jira-project", `SEC" OR "1`},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := invoke(append(append([]string(nil), base...), extra...)...)
			if code == exitOK || !strings.Contains(stderr, "ticket: ") || strings.Contains(stderr, testTrackerToken) {
				t.Fatalf("code = %d, stderr = %q", code, stderr)
			}
		})
	}
}
