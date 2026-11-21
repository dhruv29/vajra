package ticket

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	// DefaultGitHubAPI is the API of github.com. GitHub Enterprise Server
	// serves it under https://HOST/api/v3.
	DefaultGitHubAPI = "https://api.github.com"
	githubAPIVersion = "2022-11-28"
	githubService    = "github"

	// GitHub refuses a title over 256 characters and a body over 65536.
	githubTitleLimit = 256
	githubBodyLimit  = 65536
	// githubSearchPage is how many search hits are checked for the exact
	// marker. More than one finding rarely matches the same phrase.
	githubSearchPage = 20
)

var (
	// GitHub user and organisation names: letters, digits and single dashes,
	// up to 39 characters. Consecutive dashes are allowed here; GitHub
	// itself will refuse a name that does not exist.
	githubOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	githubRepoPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// GitHubOptions configures NewGitHub.
type GitHubOptions struct {
	// BaseURL is the API. Empty means DefaultGitHubAPI.
	BaseURL string
	// Repo is "owner/name".
	Repo string
	// Token is a personal access token or app token with permission to read
	// and create issues. It is sent only as a bearer token.
	Token string
	// HTTP replaces the default client, for tests. Redirects are refused
	// whatever it says.
	HTTP *http.Client
}

// GitHub files GitHub issues.
type GitHub struct {
	api   *apiClient
	owner string
	repo  string
}

// NewGitHub checks opts and returns a filer for one repository.
func NewGitHub(opts GitHubOptions) (*GitHub, error) {
	owner, repo, err := splitRepo(opts.Repo)
	if err != nil {
		return nil, err
	}
	if opts.Token == "" {
		return nil, errors.New("ticket: a GitHub token is required")
	}
	if hasUnsafeChars(opts.Token) {
		return nil, errors.New("ticket: the GitHub token contains spaces or control characters")
	}
	base := opts.BaseURL
	if base == "" {
		base = DefaultGitHubAPI
	}
	authorize := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	}
	api, err := newAPIClient(githubService, base, opts.HTTP, authorize, opts.Token)
	if err != nil {
		return nil, err
	}
	return &GitHub{api: api, owner: owner, repo: repo}, nil
}

func splitRepo(full string) (owner, repo string, err error) {
	owner, repo, found := strings.Cut(full, "/")
	if !found || !githubOwnerPattern.MatchString(owner) || !githubRepoPattern.MatchString(repo) || repo == "." || repo == ".." {
		return "", "", fmt.Errorf("ticket: GitHub repository %q is not of the form owner/name", clipRunes(full, maxQuotedIDRunes))
	}
	return owner, repo, nil
}

// githubIssue is the part of an issue, from search or create, used here.
type githubIssue struct {
	Number      int    `json:"number"`
	HTMLURL     string `json:"html_url"`
	State       string `json:"state"`
	Body        string `json:"body"`
	PullRequest *struct {
		URL string `json:"url"`
	} `json:"pull_request"`
}

// File returns the open or closed issue that already carries the finding's
// marker, or files a new one. A closed issue is returned too: someone may
// have closed it on purpose, and reopening that decision is theirs to make.
func (g *GitHub) File(ctx context.Context, issue Issue) (Result, error) {
	if err := checkIssue(issue); err != nil {
		return Result{}, err
	}
	found, ok, err := g.find(ctx, issue.FindingID)
	if err != nil {
		return Result{}, err
	}
	if ok {
		return g.result(found, true), nil
	}
	return g.create(ctx, issue)
}

// find searches the repository's issues for the marker. GitHub's search
// index lags a little behind, so an issue filed seconds earlier may not be
// found yet.
func (g *GitHub) find(ctx context.Context, findingID string) (githubIssue, bool, error) {
	query := url.Values{}
	query.Set("q", fmt.Sprintf("repo:%s/%s is:issue in:body %q", g.owner, g.repo, markerLine(findingID)))
	query.Set("per_page", strconv.Itoa(githubSearchPage))
	var reply struct {
		Items []githubIssue `json:"items"`
	}
	if err := g.api.do(ctx, http.MethodGet, "/search/issues", query, nil, &reply); err != nil {
		return githubIssue{}, false, err
	}
	for _, item := range reply.Items {
		if item.PullRequest == nil && hasMarker(item.Body, findingID) {
			return item, true, nil
		}
	}
	return githubIssue{}, false, nil
}

func (g *GitHub) create(ctx context.Context, issue Issue) (Result, error) {
	request := struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}{
		Title: cleanTitle(issue.Title, githubTitleLimit),
		Body:  bodyWithMarker(issue.Body, issue.FindingID, githubBodyLimit),
	}
	path := "/repos/" + url.PathEscape(g.owner) + "/" + url.PathEscape(g.repo) + "/issues"
	var created githubIssue
	if err := g.api.do(ctx, http.MethodPost, path, nil, request, &created); err != nil {
		return Result{}, err
	}
	if created.Number <= 0 || created.HTMLURL == "" {
		return Result{}, fmt.Errorf("ticket: github at %s accepted the issue but did not say where it is", g.api.base)
	}
	return g.result(created, false), nil
}

func (g *GitHub) result(issue githubIssue, existing bool) Result {
	return Result{
		URL:      issue.HTMLURL,
		Key:      fmt.Sprintf("%s/%s#%d", g.owner, g.repo, issue.Number),
		State:    issue.State,
		Existing: existing,
	}
}
