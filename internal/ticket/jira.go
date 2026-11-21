package ticket

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	jiraService = "jira"
	// DefaultJiraIssueType is the issue type used when none is given.
	DefaultJiraIssueType = "Bug"

	// Jira refuses a summary over 255 characters. A description field holds
	// at most 32767 characters; the limit is applied to the text of the
	// document, with room left for its structure.
	jiraSummaryLimit     = 255
	jiraDescriptionLimit = 32000
	// Labels may not contain spaces and are at most 255 characters.
	jiraLabelLimit   = 255
	jiraLabelPrefix  = "vajra-"
	jiraIssueTypeMax = 60
	maxEmailLength   = 254
)

var (
	// A Jira project key starts with an upper-case letter, followed by
	// upper-case letters, digits or underscores.
	jiraProjectPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,49}$`)
	// An issue key is the project key, a dash and a number. A key from a
	// reply is checked before it goes into a link.
	jiraIssueKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,49}-[0-9]{1,18}$`)
	// jiraLabelUnsafe matches characters left out of labels, to keep them
	// plain in JQL and in Jira's interface.
	jiraLabelUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)
)

// JiraOptions configures NewJira.
type JiraOptions struct {
	// BaseURL is the site, such as https://example.atlassian.net.
	BaseURL string
	// Project is the project key, such as "SEC".
	Project string
	// IssueType is the issue type's name. Empty means DefaultJiraIssueType.
	IssueType string
	// Email and Token are the Atlassian account and its API token, sent with
	// basic authentication.
	Email string
	Token string
	// HTTP replaces the default client, for tests. Redirects are refused
	// whatever it says.
	HTTP *http.Client
}

// Jira files Jira Cloud issues.
type Jira struct {
	api       *apiClient
	project   string
	issueType string
}

// NewJira checks opts and returns a filer for one project.
func NewJira(opts JiraOptions) (*Jira, error) {
	if !jiraProjectPattern.MatchString(opts.Project) {
		return nil, fmt.Errorf("ticket: Jira project key %q is not valid: use upper-case letters, digits and underscores, starting with a letter", clipRunes(opts.Project, maxQuotedIDRunes))
	}
	issueType, err := checkIssueType(opts.IssueType)
	if err != nil {
		return nil, err
	}
	if err := checkJiraCredentials(opts.Email, opts.Token); err != nil {
		return nil, err
	}
	authorize := func(req *http.Request) { req.SetBasicAuth(opts.Email, opts.Token) }
	api, err := newAPIClient(jiraService, opts.BaseURL, opts.HTTP, authorize, opts.Token)
	if err != nil {
		return nil, err
	}
	return &Jira{api: api, project: opts.Project, issueType: issueType}, nil
}

func checkIssueType(name string) (string, error) {
	if name == "" {
		return DefaultJiraIssueType, nil
	}
	if utf8.RuneCountInString(name) > jiraIssueTypeMax || strings.TrimSpace(name) != name || printable(name) != name {
		return "", fmt.Errorf("ticket: Jira issue type %q is not valid", clipRunes(name, maxQuotedIDRunes))
	}
	return name, nil
}

func checkJiraCredentials(email, token string) error {
	if email == "" || token == "" {
		return errors.New("ticket: a Jira account email and API token are required")
	}
	if len(email) > maxEmailLength || !strings.Contains(email, "@") || hasUnsafeChars(email) {
		return errors.New("ticket: the Jira account email is not valid")
	}
	if hasUnsafeChars(token) {
		return errors.New("ticket: the Jira API token contains spaces or control characters")
	}
	return nil
}

// jiraLabel is the label that marks a finding's ticket.
func jiraLabel(findingID string) string {
	return clipRunes(jiraLabelUnsafe.ReplaceAllString(jiraLabelPrefix+findingID, "_"), jiraLabelLimit)
}

// File returns the issue in the project that already has the finding's
// label, whatever its status, or files a new one.
func (j *Jira) File(ctx context.Context, issue Issue) (Result, error) {
	if err := checkIssue(issue); err != nil {
		return Result{}, err
	}
	found, ok, err := j.find(ctx, issue.FindingID)
	if err != nil {
		return Result{}, err
	}
	if ok {
		return j.result(found.Key, found.Fields.Status.Name, true)
	}
	return j.create(ctx, issue)
}

type jiraFoundIssue struct {
	Key    string `json:"key"`
	Fields struct {
		Status struct {
			Name string `json:"name"`
		} `json:"status"`
	} `json:"fields"`
}

// find looks for the label with JQL. The project key and the label were
// both checked against patterns that cannot close a quoted JQL string.
func (j *Jira) find(ctx context.Context, findingID string) (jiraFoundIssue, bool, error) {
	query := url.Values{}
	query.Set("jql", fmt.Sprintf(`project = "%s" AND labels = "%s" ORDER BY created ASC`, j.project, jiraLabel(findingID)))
	query.Set("fields", "status")
	query.Set("maxResults", "1")
	var reply struct {
		Issues []jiraFoundIssue `json:"issues"`
	}
	if err := j.api.do(ctx, http.MethodGet, "/rest/api/3/search/jql", query, nil, &reply); err != nil {
		return jiraFoundIssue{}, false, err
	}
	if len(reply.Issues) == 0 {
		return jiraFoundIssue{}, false, nil
	}
	return reply.Issues[0], true, nil
}

func (j *Jira) create(ctx context.Context, issue Issue) (Result, error) {
	request := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": j.project},
			"issuetype":   map[string]string{"name": j.issueType},
			"summary":     cleanTitle(issue.Title, jiraSummaryLimit),
			"description": adfDocument(issue.Body, issue.FindingID),
			"labels":      []string{jiraLabel(issue.FindingID)},
		},
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := j.api.do(ctx, http.MethodPost, "/rest/api/3/issue", nil, request, &created); err != nil {
		return Result{}, err
	}
	return j.result(created.Key, "", false)
}

// adfDocument puts the Markdown body in a code block, which keeps it exactly
// as written, and the marker in a paragraph after it. Atlassian Document
// Format has no Markdown node, and converting Markdown is out of scope.
func adfDocument(body, findingID string) map[string]any {
	marker := markerLine(findingID)
	text := clipRunes(strings.TrimRight(body, "\n"), jiraDescriptionLimit-utf8.RuneCountInString(marker))
	content := []any{}
	// ADF refuses an empty text node, so an empty body has no code block.
	if text != "" {
		content = append(content, map[string]any{
			"type":    "codeBlock",
			"content": []any{map[string]string{"type": "text", "text": text}},
		})
	}
	content = append(content, map[string]any{
		"type":    "paragraph",
		"content": []any{map[string]string{"type": "text", "text": marker}},
	})
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

// result builds the link to an issue. The key comes from the reply, so it is
// checked before it becomes part of a URL.
func (j *Jira) result(key, state string, existing bool) (Result, error) {
	if !jiraIssueKeyPattern.MatchString(key) {
		return Result{}, fmt.Errorf("ticket: jira at %s replied with an issue key that is not valid", j.api.base)
	}
	return Result{
		URL:      j.api.base + "/browse/" + url.PathEscape(key),
		Key:      key,
		State:    state,
		Existing: existing,
	}, nil
}
