package inject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/probe"
)

func TestNewValidatesItsOptions(t *testing.T) {
	app := newApp()
	cases := map[string]struct {
		fetcher probe.Fetcher
		opts    Options
	}{
		"no fetcher":        {nil, Options{MaxRequests: 1, InScope: allInScope}},
		"no request cap":    {app, Options{InScope: allInScope}},
		"no scope function": {app, Options{MaxRequests: 1}},
		"empty header name": {app, Options{MaxRequests: 1, InScope: allInScope, Headers: map[string]string{" ": "x"}}},
	}
	for name, tc := range cases {
		if _, err := New(tc.fetcher, tc.opts); err == nil || !strings.HasPrefix(err.Error(), "inject: ") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := New(app, Options{MaxRequests: 1, InScope: allInScope}); err != nil {
		t.Fatal(err)
	}
}

func TestEveryRequestIsAGetWithTheConfiguredHeaders(t *testing.T) {
	app := newApp()
	run(t, newChecker(t, app, Options{Headers: map[string]string{"Authorization": "Bearer s3cret-token"}}),
		host+"/go?next=/x")
	if len(app.requests) != 5 {
		t.Fatalf("requests = %v", app.urls())
	}
	for _, r := range app.requests {
		if r.Method != "GET" || r.Headers["Authorization"] != "Bearer s3cret-token" || r.Body != "" {
			t.Errorf("request = %+v", r)
		}
	}
}

func TestRequestCapIsEnforcedAndReported(t *testing.T) {
	app := newApp()
	// Each target needs four requests; a cap of six fits only the first.
	c := newChecker(t, app, Options{MaxRequests: 6})
	result := run(t, c, host+"/item?id=1", host+"/search?q=a", host+"/both?id=2")
	switch {
	case !result.Truncated || result.Tested != 1 || result.Untested != 2:
		t.Errorf("truncated/tested/untested = %v %d %d", result.Truncated, result.Tested, result.Untested)
	case result.Requests != 4 || len(app.requests) != 4:
		t.Errorf("requests = %d, sent %d", result.Requests, len(app.requests))
	}
	full := run(t, newChecker(t, newApp(), Options{MaxRequests: 12}), host+"/item?id=1", host+"/search?q=a", host+"/both?id=2")
	if full.Truncated || full.Tested != 3 || full.Requests != 12 {
		t.Errorf("an exact fit was truncated: %+v", full)
	}
}

func TestOutOfScopeAndUntestableURLsAreNeverRequested(t *testing.T) {
	app := newApp()
	inScope := func(u string) bool { return strings.HasPrefix(u, host+"/") }
	c := newChecker(t, app, Options{InScope: inScope})
	result := run(t, c,
		"https://other.test/search?q=a",
		"ftp://app.test/search?q=a",
		"https://user:pw@app.test/search?q=a",
		host+"/account/delete?id=3",
		host+"/search?mode=logout",
		host+"/search?q=a",
	)
	for _, u := range app.urls() {
		if !strings.HasPrefix(u, host+"/search?q=") {
			t.Errorf("requested %s", u)
		}
	}
	if len(result.Skipped) != 5 || !slices.IsSorted(result.Skipped) {
		t.Errorf("skipped = %v", result.Skipped)
	}
}

func TestEachHostPathAndParameterIsTestedOnce(t *testing.T) {
	app := newApp()
	result := run(t, newChecker(t, app, Options{}),
		host+"/search?q=a&page=1",
		host+"/search?q=b&page=2",
		host+"/search?q=a&page=1",
	)
	// Two parameters of one URL share its baseline: 1 + 3 + 3 requests.
	if result.Tested != 2 || result.Requests != 7 || len(app.requests) != 7 {
		t.Fatalf("tested %d, requests %d: %v", result.Tested, result.Requests, app.urls())
	}
	if len(result.Findings) != 1 || result.Findings[0].Evidence.Matcher != "q" {
		t.Fatalf("findings = %+v", result.Findings)
	}
	for _, u := range app.urls() {
		if !strings.Contains(u, "?q=a&") && !strings.HasSuffix(u, "&page=1") {
			t.Errorf("URL %s did not keep the other parameter as given", u)
		}
	}
}

func TestHostCaseAndFragmentsDoNotMakeANewTarget(t *testing.T) {
	app := newApp()
	result := run(t, newChecker(t, app, Options{}), "https://APP.test/search?q=c#top", host+"/search?q=d")
	if result.Tested != 1 || result.Requests != 4 {
		t.Fatalf("tested %d, requests %d", result.Tested, result.Requests)
	}
	for _, u := range app.urls() {
		if strings.Contains(u, "#") {
			t.Errorf("a fragment was sent: %s", u)
		}
	}
}

func TestOutputIsDeterministicWhateverTheInputOrder(t *testing.T) {
	urls := []string{host + "/go?next=/a", host + "/item?id=1", host + "/search?q=x", host + "/profile?name=y"}
	first := run(t, newChecker(t, newApp(), Options{}), urls...)
	reversed := slices.Clone(urls)
	slices.Reverse(reversed)
	second := run(t, newChecker(t, newApp(), Options{}), reversed...)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) || len(first.Findings) != 4 {
		t.Fatalf("runs differ or miss findings:\n%s\n%s", a, b)
	}
	if !slices.Equal(urls, []string{host + "/go?next=/a", host + "/item?id=1", host + "/search?q=x", host + "/profile?name=y"}) {
		t.Error("the caller's slice was reordered")
	}
}

func TestCredentialsNeverAppearInEvidence(t *testing.T) {
	app := newApp()
	headers := map[string]string{"Authorization": "Bearer s3cret-token", "X-Tenant": "tenant-secret-42"}
	c := newChecker(t, app, Options{Headers: headers})
	headers["Authorization"] = "changed-after-new"
	result := run(t, c, host+"/echo?q=a")
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	if app.requests[0].Headers["Authorization"] != "Bearer s3cret-token" {
		t.Error("changing the caller's map after New changed what was sent")
	}
	text, _ := json.Marshal(result.Findings)
	for _, secret := range []string{"s3cret-token", "tenant-secret-42"} {
		if strings.Contains(string(text), secret) {
			t.Errorf("evidence contains %q: %s", secret, text)
		}
	}
	if !strings.Contains(result.Findings[0].Evidence.Request, "Authorization: [redacted]") {
		t.Errorf("request evidence = %s", result.Findings[0].Evidence.Request)
	}
}

func TestUnansweredRequestsAreCountedAndNeverJudged(t *testing.T) {
	app := newApp()
	app.down = true
	result := run(t, newChecker(t, app, Options{}), host+"/item?id=1", host+"/go?next=/x")
	if len(result.Findings) != 0 || result.Unanswered != result.Requests || result.Requests != 9 {
		t.Fatalf("result = %+v", result)
	}
}

func TestACancelledContextStopsTheRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	app := newApp()
	result, err := newChecker(t, app, Options{}).Run(ctx, []string{host + "/search?q=a"})
	if !errors.Is(err, context.Canceled) || len(app.requests) != 0 || result.Requests != 0 {
		t.Fatalf("err = %v, sent %d", err, len(app.requests))
	}
}

func TestACancellationBetweenBatchesKeepsTheCountSoFar(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	app := newApp()
	app.afterBatch = cancel
	var urls []string
	for i := range 130 { // 130 parameters x 4 requests: more than one batch
		urls = append(urls, fmt.Sprintf("%s/search?p%03d=x", host, i))
	}
	result, err := newChecker(t, app, Options{}).Run(ctx, urls)
	if !errors.Is(err, context.Canceled) || result.Requests != probe.MaxRequests || app.batches != 1 {
		t.Fatalf("err = %v, requests %d, batches %d", err, result.Requests, app.batches)
	}
}

func TestLargeRunsAreSplitIntoProbeSizedBatchesWithUniqueIDs(t *testing.T) {
	app := newApp()
	var urls []string
	for i := range 130 {
		urls = append(urls, fmt.Sprintf("%s/search?p%03d=x", host, i))
	}
	result := run(t, newChecker(t, app, Options{}), urls...)
	ids := map[string]bool{}
	for _, r := range app.requests {
		ids[r.ID] = true
	}
	if app.batches != 2 || result.Requests != 520 || len(ids) != 520 {
		t.Fatalf("batches %d, requests %d, unique IDs %d", app.batches, result.Requests, len(ids))
	}
}

func TestFetcherFailuresAreErrors(t *testing.T) {
	app := newApp()
	app.err = errors.New("sandbox down")
	if _, err := newChecker(t, app, Options{}).Run(context.Background(), []string{host + "/search?q=a"}); err == nil ||
		!strings.Contains(err.Error(), "sandbox down") {
		t.Errorf("err = %v", err)
	}
	short := newApp()
	short.short = true
	if _, err := newChecker(t, short, Options{}).Run(context.Background(), []string{host + "/search?q=a"}); err == nil {
		t.Error("a short response list was accepted")
	}
	broken := newChecker(t, newApp(), Options{})
	broken.newToken = func() (string, error) { return "", errors.New("inject: no entropy") }
	if _, err := broken.Run(context.Background(), []string{host + "/search?q=a"}); err == nil {
		t.Error("a token failure was ignored")
	}
}

func TestNothingToTestIsAnEmptyResult(t *testing.T) {
	app := newApp()
	result := run(t, newChecker(t, app, Options{}), host+"/no-query", host+"/x?=v&%zz=1")
	if result.Tested != 0 || result.Requests != 0 || app.batches != 0 || result.Findings == nil {
		t.Fatalf("result = %+v, batches %d", result, app.batches)
	}
}

func TestRandomTokensAreHexOfTheExpectedLength(t *testing.T) {
	a, err := randomToken()
	b, _ := randomToken()
	if err != nil || len(a) != 2*tokenBytes || a == b || !markerPattern.MatchString(markerPrefix+a) {
		t.Fatalf("tokens %q %q, err %v", a, b, err)
	}
}

func TestClipBodyKeepsAWindowAndSaysSo(t *testing.T) {
	r := probe.Response{Status: 200, Body: "0123456789"}
	if got := clipBody(r, 2, 5).Body; got != clipNote+"\n234\n"+clipNote {
		t.Errorf("middle = %q", got)
	}
	if got := clipBody(r, -10, 100).Body; got != "0123456789" {
		t.Errorf("whole = %q", got)
	}
	if got := clipBody(probe.Response{Body: "aé"}, 2, 3).Body; got != clipNote+"\né" {
		t.Errorf("multibyte = %q", got)
	}
	if got := clipBody(r, 8, 3).Body; got != "\n"+clipNote {
		t.Errorf("empty window = %q", got)
	}
}

func TestAPayloadRequestTheScopeRefusesIsNeverSent(t *testing.T) {
	app := newApp()
	// A scope that refuses any query carrying an encoded angle bracket.
	inScope := func(u string) bool { return !strings.Contains(u, "%3C") }
	result := run(t, newChecker(t, app, Options{InScope: inScope}), host+"/search?q=a")
	if len(app.requests) != 0 || result.Tested != 0 || result.Untested != 0 ||
		!slices.Equal(result.Skipped, []string{host + "/search?q=a"}) {
		t.Fatalf("result = %+v, sent %v", result, app.urls())
	}
}
