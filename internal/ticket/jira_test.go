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
	"unicode/utf8"
)

const jiraEmail = "secops@example.test"

// fakeJira answers the search and create calls. existingKey, when set, is
// what the search finds.
type fakeJira struct {
	existingKey string
	createdKey  string
	jql         atomic.Value
	created     atomic.Value
	creates     atomic.Int32
}

func (f *fakeJira) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if user, pass, ok := r.BasicAuth(); !ok || user != jiraEmail || pass != secretToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/search/jql":
		f.jql.Store(r.URL.Query().Get("jql"))
		issues := []any{}
		if f.existingKey != "" {
			issues = append(issues, map[string]any{"key": f.existingKey, "fields": map[string]any{"status": map[string]string{"name": "In Progress"}}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issues": issues})
	case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
		f.creates.Add(1)
		raw, _ := io.ReadAll(r.Body)
		f.created.Store(string(raw))
		key := f.createdKey
		if key == "" {
			key = "SEC-101"
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "10001", "key": key})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newJiraFiler(t *testing.T, base string) *Jira {
	t.Helper()
	j, err := NewJira(JiraOptions{BaseURL: base, Project: "SEC", Email: jiraEmail, Token: secretToken})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestJiraFilesANewIssueWithTheFindingLabel(t *testing.T) {
	fake := &fakeJira{}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	got, err := newJiraFiler(t, srv.URL).File(context.Background(), sampleIssue)

	if err != nil {
		t.Fatal(err)
	}
	if want := (Result{URL: srv.URL + "/browse/SEC-101", Key: "SEC-101"}); got != want {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
	if jql, _ := fake.jql.Load().(string); jql != `project = "SEC" AND labels = "vajra-0a1b2c3d4e5f6071" ORDER BY created ASC` {
		t.Fatalf("jql = %q", jql)
	}
	var sent struct {
		Fields struct {
			Project     map[string]string `json:"project"`
			IssueType   map[string]string `json:"issuetype"`
			Summary     string            `json:"summary"`
			Labels      []string          `json:"labels"`
			Description struct {
				Type    string `json:"type"`
				Version int    `json:"version"`
				Content []struct {
					Type    string `json:"type"`
					Content []struct{ Type, Text string }
				} `json:"content"`
			} `json:"description"`
		} `json:"fields"`
	}
	raw, _ := fake.created.Load().(string)
	if err := json.Unmarshal([]byte(raw), &sent); err != nil {
		t.Fatal(err)
	}
	f := sent.Fields
	doc := f.Description
	if f.Project["key"] != "SEC" || f.IssueType["name"] != "Bug" || f.Summary != sampleIssue.Title || len(f.Labels) != 1 || f.Labels[0] != "vajra-0a1b2c3d4e5f6071" {
		t.Fatalf("fields = %+v", f)
	}
	if doc.Type != "doc" || doc.Version != 1 || len(doc.Content) != 2 || doc.Content[0].Type != "codeBlock" ||
		doc.Content[0].Content[0].Text != strings.TrimRight(sampleIssue.Body, "\n") || doc.Content[1].Content[0].Text != "vajra-finding: 0a1b2c3d4e5f6071" {
		t.Fatalf("description = %+v", doc)
	}
}

func TestJiraReturnsTheExistingIssueInsteadOfFilingAgain(t *testing.T) {
	fake := &fakeJira{existingKey: "SEC-7"}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	got, err := newJiraFiler(t, srv.URL).File(context.Background(), sampleIssue)

	if err != nil {
		t.Fatal(err)
	}
	if want := (Result{URL: srv.URL + "/browse/SEC-7", Key: "SEC-7", State: "In Progress", Existing: true}); got != want || fake.creates.Load() != 0 {
		t.Fatalf("result = %+v, want %+v; creates = %d", got, want, fake.creates.Load())
	}
}

func TestJiraRefusesAnIssueKeyFromTheReplyThatIsNotAKey(t *testing.T) {
	for _, key := range []string{"SEC", "SEC-1/../../admin", "javascript:alert(1)", "sec-1"} {
		fake := &fakeJira{createdKey: key}
		srv := httptest.NewServer(fake)

		_, err := newJiraFiler(t, srv.URL).File(context.Background(), sampleIssue)

		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "issue key that is not valid") {
			t.Errorf("key %q: err = %v", key, err)
		}
	}
}

func TestJiraDescriptionIsClippedAndKeepsTheMarker(t *testing.T) {
	doc := adfDocument(strings.Repeat("x", jiraDescriptionLimit*2), "abc")
	content := doc["content"].([]any)
	code := content[0].(map[string]any)["content"].([]any)[0].(map[string]string)["text"]
	marker := content[1].(map[string]any)["content"].([]any)[0].(map[string]string)["text"]
	if total := utf8.RuneCountInString(code + marker); total > jiraDescriptionLimit || marker != "vajra-finding: abc" {
		t.Fatalf("text is %d characters, marker %q", total, marker)
	}
}

func TestAnEmptyBodyGivesADescriptionWithOnlyTheMarker(t *testing.T) {
	content := adfDocument("\n", "abc")["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["type"] != "paragraph" {
		t.Fatalf("content = %#v", content)
	}
}

func TestJiraLabelsAreSanitisedAndBounded(t *testing.T) {
	cases := map[string]string{
		"0a1b2c3d":               "vajra-0a1b2c3d",
		"demo-sqli":              "vajra-demo-sqli",
		"a b\"c:d":               "vajra-a_b_c_d",
		strings.Repeat("a", 300): "vajra-" + strings.Repeat("a", jiraLabelLimit-len("vajra-")-1) + clipNote,
	}
	for id, want := range cases {
		if got := jiraLabel(id); got != want {
			t.Errorf("jiraLabel(%.20q) = %.40q, want %.40q", id, got, want)
		}
	}
}

func TestBadJiraOptionsAreRefused(t *testing.T) {
	good := JiraOptions{BaseURL: "https://example.atlassian.net", Project: "SEC", Email: jiraEmail, Token: secretToken}
	cases := map[string]func(o *JiraOptions){
		"lower-case project":     func(o *JiraOptions) { o.Project = "sec" },
		"project with quote":     func(o *JiraOptions) { o.Project = `SEC" OR project = "X` },
		"one-letter project":     func(o *JiraOptions) { o.Project = "S" },
		"empty project":          func(o *JiraOptions) { o.Project = "" },
		"issue type with break":  func(o *JiraOptions) { o.IssueType = "Bug\nX" },
		"issue type padded":      func(o *JiraOptions) { o.IssueType = " Bug" },
		"issue type too long":    func(o *JiraOptions) { o.IssueType = strings.Repeat("B", 61) },
		"no email":               func(o *JiraOptions) { o.Email = "" },
		"no token":               func(o *JiraOptions) { o.Token = "" },
		"email without at":       func(o *JiraOptions) { o.Email = "secops" },
		"email with newline":     func(o *JiraOptions) { o.Email = "a@b\n" },
		"token with space":       func(o *JiraOptions) { o.Token = secretToken + " x" },
		"plain http to internet": func(o *JiraOptions) { o.BaseURL = "http://example.atlassian.net" },
		"no URL":                 func(o *JiraOptions) { o.BaseURL = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			opts := good
			change(&opts)
			_, err := NewJira(opts)
			assertNoSecret(t, err)
		})
	}
	j, err := NewJira(good)
	if err != nil || j.issueType != DefaultJiraIssueType {
		t.Fatalf("good options: %+v, %v", j, err)
	}
	withType := good
	withType.IssueType = "Security Bug"
	if j, err := NewJira(withType); err != nil || j.issueType != "Security Bug" {
		t.Fatalf("custom issue type: %+v, %v", j, err)
	}
}
