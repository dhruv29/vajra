package access

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/probe"
)

// fakeApp answers by URL and by the bearer token on the request.
type fakeApp struct {
	// pages maps URL -> token ("" for anonymous) -> response.
	pages map[string]map[string]probe.Response
	calls int
	err   error
	down  bool
}

func (a *fakeApp) Do(_ context.Context, requests []probe.Request) ([]probe.Response, error) {
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	out := make([]probe.Response, 0, len(requests))
	for _, r := range requests {
		resp, ok := a.pages[r.URL][r.Headers["Authorization"]]
		if !ok {
			resp = probe.Response{Status: 403, Body: "forbidden"}
		}
		if a.down {
			resp = probe.Response{Gate: "failed", Status: 502}
		}
		resp.ID = r.ID
		out = append(out, resp)
	}
	return out, nil
}

var identities = []Identity{
	{Name: "admin", Headers: map[string]string{"Authorization": "Bearer admin-token"}},
	{Name: "user", Headers: map[string]string{"Authorization": "Bearer user-token"}},
}

const (
	adminURL  = "https://app.test/admin/users"
	ordersURL = "https://app.test/orders/42"
)

func ok(body string) probe.Response { return probe.Response{Status: 200, Body: body} }

func newApp() *fakeApp {
	return &fakeApp{pages: map[string]map[string]probe.Response{
		adminURL: {
			"Bearer admin-token": ok("user list: alice, bob"),
			"Bearer user-token":  ok("user list: alice, bob"), // broken: user sees the admin page
		},
		ordersURL: {
			"Bearer admin-token": ok("order 42"),
			"Bearer user-token":  ok("order 42"),
			"":                   {Status: 302, Headers: map[string][]string{"Location": {"/login"}}},
		},
	}}
}

func checker(t *testing.T, app *fakeApp, checks ...Check) *Checker {
	t.Helper()
	c, err := NewChecker(app, identities, checks)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRunReportsOnlyIdentitiesServedSomethingTheyAreNotAllowed(t *testing.T) {
	c := checker(t, newApp(),
		Check{Name: "User administration", URL: adminURL, Allow: []string{"admin"}},
		Check{Name: "Order detail", URL: ordersURL, Allow: []string{"admin", "user"}})

	findings, err := c.Run(context.Background())

	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %+v, err = %v; want exactly the user reaching the admin page", findings, err)
	}
	f := findings[0]
	if f.RuleID != "unauthorized-access" || f.Target != adminURL || f.Evidence.Matcher != "user" ||
		f.CWE[0] != "cwe-862" || f.Kind != finding.Dynamic || f.Source != Source || f.Status != finding.Candidate {
		t.Fatalf("finding = %+v", f)
	}
	if !strings.Contains(f.Title, `the account "user"`) || !strings.Contains(f.Description, "allows only: admin") {
		t.Fatalf("title = %q, description = %q", f.Title, f.Description)
	}
	if !strings.Contains(f.Evidence.Extracted[0], `allowed account "admin"`) || !strings.Contains(f.Evidence.Extracted[0], "identical") {
		t.Fatalf("comparison = %q", f.Evidence.Extracted[0])
	}
}

func TestCredentialsNeverAppearInAFinding(t *testing.T) {
	c := checker(t, newApp(), Check{Name: "User administration", URL: adminURL, Allow: []string{"admin"}})

	findings, _ := c.Run(context.Background())

	raw, _ := json.Marshal(findings)
	for _, secret := range []string{"admin-token", "user-token"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the credential %q is in the finding", secret)
		}
	}
	if !strings.Contains(findings[0].Evidence.Request, "Authorization: [redacted]") {
		t.Fatalf("request evidence = %q", findings[0].Evidence.Request)
	}
}

func TestAnonymousAccessIsItsOwnRule(t *testing.T) {
	app := newApp()
	app.pages[ordersURL][""] = ok("order 42")
	c := checker(t, app, Check{Name: "Order detail", URL: ordersURL, Allow: []string{"admin", "user"}})

	findings, _ := c.Run(context.Background())

	if len(findings) != 1 || findings[0].RuleID != "unauthenticated-access" || findings[0].CWE[0] != "cwe-306" ||
		!strings.Contains(findings[0].Title, "not signed in") {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestComparisonSaysWhenThePageIsProbablyGeneric(t *testing.T) {
	app := newApp()
	app.pages[adminURL]["Bearer user-token"] = ok("Welcome. " + strings.Repeat("Please sign in to continue. ", 40))
	c := checker(t, app,
		Check{Name: "User administration", URL: adminURL, Allow: []string{"admin"}},
		Check{Name: "Nobody page", URL: ordersURL})

	findings, _ := c.Run(context.Background())

	byTarget := map[string][]finding.Finding{}
	for _, f := range findings {
		byTarget[f.Target] = append(byTarget[f.Target], f)
	}
	if got := byTarget[adminURL][0].Evidence.Extracted[0]; !strings.Contains(got, "clearly different") {
		t.Fatalf("comparison = %q", got)
	}
	if len(byTarget[ordersURL]) != 2 || !strings.Contains(byTarget[ordersURL][0].Evidence.Extracted[0], "nothing to compare") ||
		!strings.Contains(byTarget[ordersURL][0].Description, "allows only: nobody") {
		t.Fatalf("a check that allows nobody: %+v", byTarget[ordersURL])
	}
}

func TestSimilarity(t *testing.T) {
	a := probe.Response{Body: strings.Repeat("a", 100)}
	cases := map[string]probe.Response{
		"identical":         {Body: strings.Repeat("a", 100)},
		"same size":         {Body: strings.Repeat("b", 95)},
		"clearly different": {Body: strings.Repeat("b", 10)},
	}
	for want, b := range cases {
		if got := similarity(a, b); !strings.Contains(got, want) {
			t.Errorf("similarity = %q; want it to say %q", got, want)
		}
	}
	if got := similarity(probe.Response{}, probe.Response{}); !strings.Contains(got, "identical") {
		t.Errorf("two empty bodies: %q", got)
	}
}

func TestReproduce(t *testing.T) {
	app := newApp()
	c := checker(t, app, Check{Name: "User administration", URL: adminURL, Allow: []string{"admin"}})
	findings, _ := c.Run(context.Background())

	still, err := c.Reproduce(context.Background(), findings[0])
	if err != nil || !still {
		t.Fatalf("still served = %v, err = %v", still, err)
	}

	app.pages[adminURL]["Bearer user-token"] = probe.Response{Status: 403}
	fixed, err := c.Reproduce(context.Background(), findings[0])
	if err != nil || fixed {
		t.Fatalf("after the fix: served = %v, err = %v", fixed, err)
	}

	app.down = true
	if _, err := c.Reproduce(context.Background(), findings[0]); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("target down: err = %v; an unanswered re-test must be an error", err)
	}
	app.down, app.err = false, errors.New("sandbox failed")
	if _, err := c.Reproduce(context.Background(), findings[0]); err == nil {
		t.Fatal("a fetch error was swallowed")
	}
	if _, err := c.Reproduce(context.Background(), finding.Finding{ID: "unknown"}); err == nil {
		t.Fatal("a finding from elsewhere was re-tested")
	}
}

func TestRunWithNoChecksAndWithAFetchError(t *testing.T) {
	app := newApp()
	c := checker(t, app)
	findings, err := c.Run(context.Background())
	if err != nil || findings == nil || len(findings) != 0 || app.calls != 0 {
		t.Fatalf("findings = %v, err = %v, calls = %d", findings, err, app.calls)
	}
	failing := &fakeApp{err: errors.New("sandbox failed")}
	c2, _ := NewChecker(failing, identities, []Check{{Name: "x", URL: adminURL}})
	if _, err := c2.Run(context.Background()); err == nil {
		t.Fatal("a fetch error was swallowed")
	}
}

func TestUnansweredRequestsAreNotFindings(t *testing.T) {
	app := newApp()
	app.down = true
	c := checker(t, app, Check{Name: "User administration", URL: adminURL, Allow: []string{"admin"}})

	findings, err := c.Run(context.Background())

	if err != nil || len(findings) != 0 {
		t.Fatalf("findings = %+v, err = %v; the gate's own error page is not access to the resource", findings, err)
	}
}

func TestNewCheckerValidation(t *testing.T) {
	good := Check{Name: "c", URL: adminURL, Allow: []string{"admin"}}
	cases := map[string]struct {
		ids    []Identity
		checks []Check
	}{
		"identity without a name":      {[]Identity{{Headers: map[string]string{"A": "b"}}}, nil},
		"identity named anonymous":     {[]Identity{{Name: "anonymous", Headers: map[string]string{"A": "b"}}}, nil},
		"repeated identity":            {[]Identity{identities[0], identities[0]}, nil},
		"identity without credentials": {[]Identity{{Name: "x"}}, nil},
		"check without a name":         {identities, []Check{{URL: adminURL}}},
		"repeated check":               {identities, []Check{good, good}},
		"unknown allowed identity":     {identities, []Check{{Name: "c", URL: adminURL, Allow: []string{"root"}}}},
		"method that changes data":     {identities, []Check{{Name: "c", URL: adminURL, Method: "delete"}}},
	}
	for name, tc := range cases {
		if _, err := NewChecker(newApp(), tc.ids, tc.checks); err == nil {
			t.Errorf("%s: NewChecker succeeded", name)
		}
	}
	if _, err := NewChecker(nil, identities, nil); err == nil {
		t.Error("a nil fetcher was accepted")
	}
	c, err := NewChecker(newApp(), identities, []Check{{Name: "c", URL: adminURL, Method: "head", Allow: []string{"anonymous"}}})
	if err != nil || c.checks[0].Method != "HEAD" {
		t.Fatalf("checker = %+v, err = %v", c, err)
	}
	if got := c.SecretHeaders(); len(got) != 1 || got[0] != "Authorization" {
		t.Fatalf("secret headers = %v", got)
	}
}
