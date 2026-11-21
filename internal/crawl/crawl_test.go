package crawl

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/probe"
)

const origin = "https://app.test"

// fakeSite is a Fetcher that serves pages from memory and remembers every
// batch it was asked for.
type fakeSite struct {
	pages   map[string]probe.Response
	batches [][]probe.Request
	err     error
	onDo    func()
	short   bool // answer with one response too few
}

func (s *fakeSite) Do(_ context.Context, requests []probe.Request) ([]probe.Response, error) {
	s.batches = append(s.batches, requests)
	if s.onDo != nil {
		s.onDo()
	}
	if s.err != nil {
		return nil, s.err
	}
	responses := make([]probe.Response, 0, len(requests))
	for _, request := range requests {
		response, ok := s.pages[request.URL]
		if !ok {
			response = htmlPage("not found")
			response.Status = 404
		}
		response.ID = request.ID
		responses = append(responses, response)
	}
	if s.short {
		responses = responses[:len(responses)-1]
	}
	return responses, nil
}

func (s *fakeSite) fetched() []string {
	var urls []string
	for _, batch := range s.batches {
		for _, request := range batch {
			urls = append(urls, request.URL)
		}
	}
	return urls
}

func htmlPage(body string) probe.Response {
	return probe.Response{Status: 200, Headers: map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}, Body: body}
}

func redirect(status int, location string) probe.Response {
	return probe.Response{Status: status, Headers: map[string][]string{"location": {location}}}
}

func links(paths ...string) string {
	var b strings.Builder
	for _, path := range paths {
		fmt.Fprintf(&b, `<a href="%s">x</a>`, path)
	}
	return b.String()
}

func onAppHost(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && parsed.Hostname() == "app.test"
}

func options(maxPages, maxDepth int) Options {
	return Options{MaxPages: maxPages, MaxDepth: maxDepth, InScope: onAppHost}
}

func pageURLs(result Result) []string {
	urls := make([]string, 0, len(result.Pages))
	for _, page := range result.Pages {
		urls = append(urls, page.URL)
	}
	return urls
}

func crawlOnePage(t *testing.T, response probe.Response) Page {
	t.Helper()
	site := &fakeSite{pages: map[string]probe.Response{origin + "/dir/page": response}}
	result, err := Crawl(context.Background(), site, []string{origin + "/dir/page"}, options(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	return result.Pages[0]
}

func TestCrawlVisitsBreadthFirstAndStopsAtMaxDepth(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/":   htmlPage(links("/b", "/a")),
		origin + "/a":  htmlPage(links("/a1")),
		origin + "/b":  htmlPage(links("/b1", "/a")),
		origin + "/a1": htmlPage(links("/too-deep")),
		origin + "/b1": htmlPage(""),
	}}

	result, err := Crawl(context.Background(), site, []string{origin}, options(100, 2))

	if err != nil {
		t.Fatal(err)
	}
	want := []string{origin + "/", origin + "/a", origin + "/b", origin + "/a1", origin + "/b1"}
	if got := pageURLs(result); !slices.Equal(got, want) {
		t.Fatalf("pages = %v; want %v", got, want)
	}
	depths := []int{}
	for _, page := range result.Pages {
		depths = append(depths, page.Depth)
	}
	if !slices.Equal(depths, []int{0, 1, 1, 2, 2}) {
		t.Fatalf("depths = %v", depths)
	}
	if result.Truncated {
		t.Fatal("a crawl stopped by MaxDepth is not truncated")
	}
	if got := result.Pages[3].Links; !slices.Equal(got, []string{origin + "/too-deep"}) {
		t.Fatalf("links at the depth limit = %v; they are listed even though not followed", got)
	}
	if len(result.Exchanges) != len(result.Pages) {
		t.Fatalf("exchanges = %d, pages = %d", len(result.Exchanges), len(result.Pages))
	}
	for i, exchange := range result.Exchanges {
		wantID := fmt.Sprintf("crawl-%d", i+1)
		if exchange.Request.URL != result.Pages[i].URL || exchange.Request.Method != "GET" ||
			exchange.Request.ID != wantID || exchange.Response.ID != wantID {
			t.Fatalf("exchange %d = %+v", i, exchange.Request)
		}
	}
}

func TestCrawlWithDepthZeroFetchesOnlyTheStartURLs(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{origin + "/": htmlPage(links("/a"))}}

	result, err := Crawl(context.Background(), site, []string{origin + "/", origin + "/other"}, options(10, 0))

	if err != nil {
		t.Fatal(err)
	}
	if got := pageURLs(result); !slices.Equal(got, []string{origin + "/", origin + "/other"}) {
		t.Fatalf("pages = %v", got)
	}
	if result.Pages[1].Status != 404 || result.Truncated {
		t.Fatalf("second page = %+v, truncated = %v", result.Pages[1], result.Truncated)
	}
}

func TestCrawlStopsAtMaxPages(t *testing.T) {
	tests := []struct {
		name          string
		maxPages      int
		wantPages     int
		wantTruncated bool
	}{
		{"limit inside a level", 2, 2, true},
		{"limit exactly at the end of a level with more queued", 3, 3, true},
		{"limit equal to the size of the site", 4, 4, false},
		{"limit larger than the site", 50, 4, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			site := &fakeSite{pages: map[string]probe.Response{
				origin + "/":  htmlPage(links("/a", "/b")),
				origin + "/a": htmlPage(links("/c")),
				origin + "/b": htmlPage(""),
				origin + "/c": htmlPage(""),
			}}

			result, err := Crawl(context.Background(), site, []string{origin}, options(tt.maxPages, 5))

			if err != nil {
				t.Fatal(err)
			}
			if len(result.Pages) != tt.wantPages || result.Truncated != tt.wantTruncated {
				t.Fatalf("pages = %d, truncated = %v; want %d and %v",
					len(result.Pages), result.Truncated, tt.wantPages, tt.wantTruncated)
			}
			if got := len(site.fetched()); got != tt.wantPages {
				t.Fatalf("fetched %d URLs; want %d", got, tt.wantPages)
			}
		})
	}
}

func TestCrawlNeverFetchesTheSameNormalisedURLTwice(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/": htmlPage(links(
			"/list?b=2&a=1", "/list?a=1&b=2#top", "HTTPS://APP.TEST:443/list?a=1&&b=2",
			"https://app.test", "/#section", "#only-a-fragment", "/list?a=1&b=2",
		)),
		origin + "/list?a=1&b=2": htmlPage(links("/")),
	}}

	result, err := Crawl(context.Background(), site, []string{"HTTPS://App.Test:443", origin + "/#x"}, options(100, 5))

	if err != nil {
		t.Fatal(err)
	}
	want := []string{origin + "/", origin + "/list?a=1&b=2"}
	if got := site.fetched(); !slices.Equal(got, want) {
		t.Fatalf("fetched = %v; want %v", got, want)
	}
	if got := result.Pages[0].Links; !slices.Equal(got, want) {
		t.Fatalf("links = %v; want %v", got, want)
	}
}

func TestNormalise(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"lower-cases scheme and host but not the path", "HTTP://App.Test/Admin", "http://app.test/Admin"},
		{"drops the default http port", "http://app.test:80/x", "http://app.test/x"},
		{"drops the default https port", "https://app.test:443/x", "https://app.test/x"},
		{"keeps another port", "https://app.test:8443/x", "https://app.test:8443/x"},
		{"keeps port 80 on https", "https://app.test:80/", "https://app.test:80/"},
		{"gives an empty path a slash", "https://app.test?q=1", "https://app.test/?q=1"},
		{"drops the fragment", "https://app.test/x#y", "https://app.test/x"},
		{"sorts parameters by name and keeps repeated names in order", "https://app.test/?b=2&a=z&a=y", "https://app.test/?a=z&a=y&b=2"},
		{"keeps the encoding of the query", "https://app.test/?q=a%20b+c", "https://app.test/?q=a%20b+c"},
		{"drops an empty query", "https://app.test/x?", "https://app.test/x"},
		{"keeps an escaped slash in the path", "https://app.test/a%2Fb", "https://app.test/a%2Fb"},
		{"brackets an IPv6 host", "http://[::1]:8080/x", "http://[::1]:8080/x"},
		{"trims surrounding space", "  https://app.test/x ", "https://app.test/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalise(tt.raw)

			if !ok || got != tt.want {
				t.Fatalf("normalise(%q) = %q, %v; want %q", tt.raw, got, ok, tt.want)
			}
		})
	}
}

func TestNormaliseRejectsWhatIsNotAnHTTPURL(t *testing.T) {
	for _, raw := range []string{"", "/relative", "mailto:a@app.test", "ftp://app.test/", "http:///nohost", "http://app.test/%zz", "https:opaque"} {
		if got, ok := normalise(raw); ok {
			t.Errorf("normalise(%q) = %q; want it rejected", raw, got)
		}
	}
}

func TestCrawlNeitherFetchesNorListsOutOfScopeLinks(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/": htmlPage(links("/in", "https://other.test/out", "//cdn.test/lib", "http://app.test.evil.test/")),
	}}

	result, err := Crawl(context.Background(), site, []string{origin}, options(100, 3))

	if err != nil {
		t.Fatal(err)
	}
	if got := result.Pages[0].Links; !slices.Equal(got, []string{origin + "/in"}) {
		t.Fatalf("links = %v", got)
	}
	if got := site.fetched(); !slices.Equal(got, []string{origin + "/", origin + "/in"}) {
		t.Fatalf("fetched = %v", got)
	}
}

func TestCrawlFollowsRedirectsItselfAndOnlyInScope(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/":        htmlPage(links("/old", "/leave", "/nowhere")),
		origin + "/old":     redirect(302, "new?x=1"),
		origin + "/leave":   redirect(301, "https://other.test/landing"),
		origin + "/nowhere": {Status: 302},
		origin + "/new?x=1": htmlPage("arrived"),
	}}

	result, err := Crawl(context.Background(), site, []string{origin}, options(100, 2))

	if err != nil {
		t.Fatal(err)
	}
	want := []string{origin + "/", origin + "/leave", origin + "/nowhere", origin + "/old", origin + "/new?x=1"}
	if got := pageURLs(result); !slices.Equal(got, want) {
		t.Fatalf("pages = %v; want %v", got, want)
	}
	leave, nowhere, old, arrived := result.Pages[1], result.Pages[2], result.Pages[3], result.Pages[4]
	if leave.Status != 301 || len(leave.Links) != 0 {
		t.Fatalf("redirect out of scope = %+v; its target must not be listed", leave)
	}
	if nowhere.Status != 302 || len(nowhere.Links) != 0 || nowhere.Error != "" {
		t.Fatalf("redirect without a Location = %+v", nowhere)
	}
	if !slices.Equal(old.Links, []string{origin + "/new?x=1"}) || arrived.Depth != 2 {
		t.Fatalf("redirect = %+v, target = %+v", old, arrived)
	}
}

func TestCrawlDoesNotFollowARedirectAtTheDepthLimit(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{origin + "/": redirect(307, "/login")}}

	result, err := Crawl(context.Background(), site, []string{origin}, options(100, 0))

	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pages) != 1 || !slices.Equal(result.Pages[0].Links, []string{origin + "/login"}) {
		t.Fatalf("pages = %+v", result.Pages)
	}
}

func TestExtractResolvesRelativeLinks(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"against the page", links("sibling", "../up", "/root", "?q=1", "./"),
			[]string{origin + "/dir/", origin + "/dir/page?q=1", origin + "/dir/sibling", origin + "/root", origin + "/up"}},
		{"against an absolute base href", `<base href="https://app.test/other/">` + links("x", "/y"),
			[]string{origin + "/other/x", origin + "/y"}},
		{"against a relative base href", `<BASE HREF="/static/app/">` + links("x"),
			[]string{origin + "/static/app/x"}},
		{"against only the first base href", `<base href="/one/"><base href="/two/">` + links("x"),
			[]string{origin + "/one/x"}},
		{"against the page when the base is unusable", `<base href="mailto:nobody@app.test"><base target="_blank">` + links("x"),
			[]string{origin + "/dir/x"}},
		{"against an out-of-scope base, which puts its links out of scope", `<base href="https://other.test/">` + links("x", "https://app.test/kept"),
			[]string{origin + "/kept"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := crawlOnePage(t, htmlPage(tt.body))

			if !slices.Equal(page.Links, tt.want) {
				t.Fatalf("links = %v; want %v", page.Links, tt.want)
			}
		})
	}
}

func TestExtractReadsTolerantMarkup(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"unquoted attribute", `<a href=/plain>x</a><a class=btn href=/second/>y</a>`,
			[]string{origin + "/plain", origin + "/second/"}},
		{"single quotes and spaces around the equals sign", `<a href = '/single'>x</a>`, []string{origin + "/single"}},
		{"upper-case tag and attribute across lines", "<A\n  CLASS=\"x\"\n  HREF=\"/upper\">x</A>", []string{origin + "/upper"}},
		{"entities in quoted and unquoted values", `<a href="/s?a=1&amp;b=2">x</a><a href=/t?c=3&amp;d=4>y</a><a href="/u?e=&#x41;">z</a>`,
			[]string{origin + "/s?a=1&b=2", origin + "/t?c=3&d=4", origin + "/u?e=A"}},
		{"every link-bearing tag", `<link href="/feed"><area href="/map"><iframe src="/frame"></iframe><script src="/app.js"></script>`,
			[]string{origin + "/app.js", origin + "/feed", origin + "/frame", origin + "/map"}},
		{"the first of two href attributes", `<a href="/first" href="/second">x</a>`, []string{origin + "/first"}},
		{"href mentioned inside another attribute", `<a title="see href=/fake" data-href="/also-fake" href="/real">x</a>`, []string{origin + "/real"}},
		{"other tags and similar names ignored", `<img src="/pic"><abbr href="/abbr"></abbr><a-card href="/custom"></a-card><div href="/div">`, []string{}},
		{"schemes that are not http", links("mailto:a@app.test", "javascript:void(0)", "tel:+1", "data:text/html,x", "ftp://app.test/f", "JavaScript:alert(1)", ""), []string{}},
		{"links in comments, scripts and styles ignored", `<!-- <a href="/commented"> --><script>var s = '<a href="/in-js">';</script><style>a{}/* <a href="/in-css"> */</style><a href="/after">x</a>`,
			[]string{origin + "/after"}},
		{"unparseable link ignored", `<a href="http://[broken">x</a><a href="/fine">y</a>`, []string{origin + "/fine"}},
		{"repeated link listed once", links("/same", "/same#a", "/same"), []string{origin + "/same"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := crawlOnePage(t, htmlPage(tt.body))

			if !slices.Equal(page.Links, tt.want) {
				t.Fatalf("links = %v; want %v", page.Links, tt.want)
			}
		})
	}
}

func TestCrawlParsesOnlyHTMLResponses(t *testing.T) {
	body := links("/found")
	tests := []struct {
		name        string
		contentType []string
		wantParsed  bool
	}{
		{"text/html", []string{"text/html"}, true},
		{"html with a charset and odd case", []string{"Text/HTML ; charset=UTF-8"}, true},
		{"xhtml", []string{"application/xhtml+xml"}, true},
		{"json", []string{"application/json"}, false},
		{"plain text", []string{"text/plain"}, false},
		{"javascript", []string{"text/javascript"}, false},
		{"no content type", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := probe.Response{Status: 200, Body: body, Headers: map[string][]string{"content-type": tt.contentType}}

			page := crawlOnePage(t, response)

			if parsed := len(page.Links) == 1; parsed != tt.wantParsed {
				t.Fatalf("links = %v; want parsed = %v", page.Links, tt.wantParsed)
			}
		})
	}
}

func TestCrawlSkipsStaticAssets(t *testing.T) {
	assets := []string{"/a.png", "/a.jpg", "/a.JPEG", "/a.gif", "/a.svg", "/a.ico", "/a.css?v=3", "/a.woff", "/a.woff2",
		"/a.ttf", "/a.eot", "/a.mp4", "/a.mp3", "/a.pdf", "/a.zip", "/a.tar.gz"}
	kept := []string{"/app.js", "/download?file=report.pdf", "/png", "/page.html"}
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/":     htmlPage(links(append(assets, kept...)...)),
		origin + "/away": redirect(302, "/brochure.pdf"),
	}}

	result, err := Crawl(context.Background(), site, []string{origin, origin + "/away"}, options(100, 1))

	if err != nil {
		t.Fatal(err)
	}
	want := []string{origin + "/app.js", origin + "/download?file=report.pdf", origin + "/page.html", origin + "/png"}
	if got := result.Pages[0].Links; !slices.Equal(got, want) {
		t.Fatalf("links = %v; want %v", got, want)
	}
	if got := result.Pages[1].Links; len(got) != 0 {
		t.Fatalf("redirect to a static asset listed %v", got)
	}
	if got := len(site.fetched()); got != 2+len(want) {
		t.Fatalf("fetched %v", site.fetched())
	}
}

func TestCrawlCollectsFormsAndFields(t *testing.T) {
	body := `
<form action="/login?next=%2F&amp;lang=en" method="post">
  <input type="text" name="user"><input name=password type=password>
  <select name="role"><option>a</option></select>
  <textarea name="note"></textarea>
  <input type="submit" value="Go"><input name="user">
</form>
<input name="outside-any-form">
<form><input name="q"></form>
<FORM ACTION="search" METHOD=" get "><input name="term">
<form action="#" method="dialog"></form>
<form action="https://other.test/collect" method="post"><input name="email"></form>
<form action="javascript:submit()"><input name="js"></form>
<form action="/unclosed"><input name="last">`

	page := crawlOnePage(t, htmlPage(body))

	want := []Form{
		{Action: origin + "/login?lang=en&next=%2F", Method: "POST", Fields: []string{"note", "password", "role", "user"}},
		{Action: origin + "/dir/page", Method: "GET", Fields: []string{"q"}},
		{Action: origin + "/dir/search", Method: "GET", Fields: []string{"term"}},
		{Action: origin + "/dir/page", Method: "DIALOG", Fields: []string{}},
		{Action: origin + "/unclosed", Method: "GET", Fields: []string{"last"}},
	}
	if len(page.Forms) != len(want) {
		t.Fatalf("forms = %+v; want %d of them", page.Forms, len(want))
	}
	for i, form := range page.Forms {
		if form.Action != want[i].Action || form.Method != want[i].Method || !slices.Equal(form.Fields, want[i].Fields) {
			t.Errorf("form %d = %+v; want %+v", i, form, want[i])
		}
	}
	wantLinks := []string{origin + "/dir/page", origin + "/dir/search", origin + "/unclosed"}
	if !slices.Equal(page.Links, wantLinks) {
		t.Fatalf("links = %v; want the in-scope GET form actions %v", page.Links, wantLinks)
	}
}

func TestCrawlRecordsAURLThatFailedAndGoesOn(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/":        htmlPage(links("/down", "/denied", "/silent", "/fine")),
		origin + "/down":    {Error: "connection refused"},
		origin + "/denied":  {Status: 403, Gate: "denied", Body: links("/from-the-gate"), Headers: map[string][]string{"Content-Type": {"text/html"}}},
		origin + "/silent":  {},
		origin + "/fine":    htmlPage(links("/next")),
		origin + "/next":    htmlPage(""),
		origin + "/unknown": htmlPage(""),
	}}

	result, err := Crawl(context.Background(), site, []string{origin}, options(100, 2))

	if err != nil {
		t.Fatal(err)
	}
	byURL := map[string]Page{}
	for _, page := range result.Pages {
		byURL[page.URL] = page
	}
	if got := byURL[origin+"/down"]; got.Error != "connection refused" || got.Status != 0 || got.Links == nil {
		t.Fatalf("network failure = %+v", got)
	}
	if got := byURL[origin+"/denied"]; !strings.Contains(got.Error, "denied") || got.Status != 403 || len(got.Links) != 0 {
		t.Fatalf("gate refusal = %+v; the gate's own page must not be parsed", got)
	}
	if got := byURL[origin+"/silent"]; got.Error == "" {
		t.Fatalf("response without a status = %+v", got)
	}
	if _, ok := byURL[origin+"/next"]; !ok || len(result.Pages) != 6 {
		t.Fatalf("pages = %v; the crawl must continue past failures", pageURLs(result))
	}
}

func TestCrawlReturnsAFetcherError(t *testing.T) {
	boom := errors.New("sandbox unavailable")
	site := &fakeSite{pages: map[string]probe.Response{origin + "/": htmlPage(links("/a"))}}
	site.onDo = func() {
		if len(site.batches) == 2 {
			site.err = boom
		}
	}

	result, err := Crawl(context.Background(), site, []string{origin}, options(100, 3))

	if !errors.Is(err, boom) {
		t.Fatalf("err = %v; want it to wrap %v", err, boom)
	}
	if len(result.Pages) != 1 || len(result.Exchanges) != 1 {
		t.Fatalf("result = %+v; want the level fetched before the failure", result)
	}
}

func TestCrawlRejectsAResponseCountThatDoesNotMatch(t *testing.T) {
	site := &fakeSite{short: true}

	_, err := Crawl(context.Background(), site, []string{origin}, options(10, 0))

	if err == nil || !strings.Contains(err.Error(), "0 responses for 1 requests") {
		t.Fatalf("err = %v", err)
	}
}

func TestCrawlMakesOneBatchPerLevel(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/":   htmlPage(links("/a", "/b", "/c")),
		origin + "/a":  htmlPage(links("/a1", "/a2")),
		origin + "/b":  htmlPage(links("/b1")),
		origin + "/c":  htmlPage(""),
		origin + "/a1": htmlPage(""),
	}}
	opts := options(100, 5)
	opts.Headers = map[string]string{"Cookie": "session=abc"}

	result, err := Crawl(context.Background(), site, []string{origin}, opts)

	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{}
	for _, batch := range site.batches {
		sizes = append(sizes, len(batch))
	}
	if !slices.Equal(sizes, []int{1, 3, 3}) {
		t.Fatalf("batch sizes = %v; want one Do call per level", sizes)
	}
	for _, exchange := range result.Exchanges {
		if exchange.Request.Headers["Cookie"] != "session=abc" {
			t.Fatalf("request %s lost the headers: %v", exchange.Request.URL, exchange.Request.Headers)
		}
	}
	site.batches[0][0].Headers["Cookie"] = "changed"
	if opts.Headers["Cookie"] != "session=abc" {
		t.Fatal("requests must not share the caller's header map")
	}
}

func TestCrawlSplitsALargeLevelAndCapsLinksPerPage(t *testing.T) {
	many := func(prefix string, n int) string {
		paths := make([]string, n)
		for i := range paths {
			paths[i] = fmt.Sprintf("/%s/%04d", prefix, i)
		}
		return links(paths...)
	}
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/":  htmlPage(links("/a", "/b")),
		origin + "/a": htmlPage(many("a", MaxLinksPerPage+100)),
		origin + "/b": htmlPage(many("b", 100)),
	}}

	result, err := Crawl(context.Background(), site, []string{origin}, options(5000, 2))

	if err != nil {
		t.Fatal(err)
	}
	fromA := result.Pages[1].Links
	if len(fromA) != MaxLinksPerPage || fromA[len(fromA)-1] != fmt.Sprintf("%s/a/%04d", origin, MaxLinksPerPage-1) {
		t.Fatalf("links from one page = %d, last %q; want the first %d", len(fromA), fromA[len(fromA)-1], MaxLinksPerPage)
	}
	sizes := []int{}
	for _, batch := range site.batches {
		sizes = append(sizes, len(batch))
	}
	if !slices.Equal(sizes, []int{1, 2, probe.MaxRequests, 100}) {
		t.Fatalf("batch sizes = %v; a level larger than a batch is split", sizes)
	}
	ids := map[string]bool{}
	for _, exchange := range result.Exchanges {
		ids[exchange.Request.ID] = true
	}
	if len(ids) != len(result.Exchanges) {
		t.Fatalf("%d distinct request IDs for %d requests", len(ids), len(result.Exchanges))
	}
}

func TestCrawlIgnoresTheBodyBeyondTheLimit(t *testing.T) {
	body := links("/early") + strings.Repeat(" ", maxBodyBytes) + links("/late")

	page := crawlOnePage(t, htmlPage(body))

	if !slices.Equal(page.Links, []string{origin + "/early"}) {
		t.Fatalf("links = %v", page.Links)
	}
}

func TestCrawlStopsWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	site := &fakeSite{pages: map[string]probe.Response{origin + "/": htmlPage(links("/a"))}, onDo: cancel}

	result, err := Crawl(ctx, site, []string{origin}, options(100, 3))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if len(result.Pages) != 1 || len(site.batches) != 1 {
		t.Fatalf("pages = %d, batches = %d; want the crawl to stop after the level in flight", len(result.Pages), len(site.batches))
	}
}

func TestCrawlRejectsBadArguments(t *testing.T) {
	site := &fakeSite{}
	valid := options(10, 1)
	tests := []struct {
		name    string
		fetcher probe.Fetcher
		start   []string
		opts    Options
		want    string
	}{
		{"no fetcher", nil, []string{origin}, valid, "fetcher"},
		{"zero MaxPages", site, []string{origin}, Options{MaxDepth: 1, InScope: onAppHost}, "MaxPages"},
		{"negative MaxDepth", site, []string{origin}, Options{MaxPages: 1, MaxDepth: -1, InScope: onAppHost}, "MaxDepth"},
		{"no InScope", site, []string{origin}, Options{MaxPages: 1}, "InScope"},
		{"no start URL", site, nil, valid, "start URL"},
		{"start URL that is not http", site, []string{origin, "ftp://app.test/"}, valid, `"ftp://app.test/"`},
		{"start URLs all out of scope", site, []string{"https://other.test/"}, valid, "in scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Crawl(context.Background(), tt.fetcher, tt.start, tt.opts)

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v; want it to mention %q", err, tt.want)
			}
			if len(site.batches) != 0 {
				t.Fatal("nothing may be fetched when the arguments are wrong")
			}
		})
	}
}

func TestCrawlLeavesOutOfScopeStartURLsOut(t *testing.T) {
	site := &fakeSite{}

	result, err := Crawl(context.Background(), site, []string{"https://other.test/", origin}, options(10, 0))

	if err != nil {
		t.Fatal(err)
	}
	if got := site.fetched(); !slices.Equal(got, []string{origin + "/"}) || len(result.Pages) != 1 {
		t.Fatalf("fetched = %v", got)
	}
}

func TestCrawlDoesNotFetchTheActionOfAPOSTForm(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{
		origin + "/": htmlPage(`<form action="/transfer" method="post"><input name="amount"></form>` +
			`<form action="/search"><input name="q"></form>`),
	}}

	result, err := Crawl(context.Background(), site, []string{origin + "/"}, options(10, 1))

	if err != nil {
		t.Fatal(err)
	}
	if fetched := site.fetched(); !slices.Equal(fetched, []string{origin + "/", origin + "/search"}) {
		t.Fatalf("fetched = %v; the POST form's action must not be requested", fetched)
	}
	forms := result.Pages[0].Forms
	if len(forms) != 2 || forms[0].Action != origin+"/transfer" || forms[0].Method != "POST" {
		t.Fatalf("forms = %+v; the POST form must still be listed", forms)
	}
}

func TestCrawlListsButDoesNotFetchStateChangingLinks(t *testing.T) {
	risky := []string{
		"/logout", "/Account/Sign-Out", "/session?action=delete", "/api/tokens/7?Revoke=1",
		"/user_delete", "/logout.php", "/settings/reset", "/logout",
	}
	safe := []string{"/presets", "/removed-items-report", "/dashboard?tab=settings", "/canceled"}
	site := &fakeSite{pages: map[string]probe.Response{origin + "/": htmlPage(links(append(risky, safe...)...))}}

	result, err := Crawl(context.Background(), site, []string{origin + "/"}, options(50, 1))

	if err != nil {
		t.Fatal(err)
	}
	wantSkipped := []string{
		origin + "/Account/Sign-Out", origin + "/api/tokens/7?Revoke=1", origin + "/logout",
		origin + "/logout.php", origin + "/session?action=delete", origin + "/settings/reset", origin + "/user_delete",
	}
	if !slices.Equal(result.Skipped, wantSkipped) {
		t.Fatalf("skipped = %v; want %v", result.Skipped, wantSkipped)
	}
	fetched := site.fetched()
	for _, skipped := range wantSkipped {
		if slices.Contains(fetched, skipped) {
			t.Errorf("fetched %s", skipped)
		}
		if !slices.Contains(result.Pages[0].Links, skipped) {
			t.Errorf("%s is not listed in the page's links", skipped)
		}
	}
	for _, path := range safe {
		if !slices.Contains(fetched, origin+path) {
			t.Errorf("did not fetch the ordinary link %s", path)
		}
	}
}

func TestCrawlReportsNoSkippedLinksAsAnEmptyList(t *testing.T) {
	site := &fakeSite{pages: map[string]probe.Response{origin + "/": htmlPage(links("/a"))}}

	result, err := Crawl(context.Background(), site, []string{origin + "/"}, options(10, 1))

	if err != nil || result.Skipped == nil || len(result.Skipped) != 0 {
		t.Fatalf("skipped = %#v, err = %v; want an empty list", result.Skipped, err)
	}
}
