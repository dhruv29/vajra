package inject

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/probe"
)

// handler answers one path of the fake application.
type handler func(q url.Values, r probe.Request) probe.Response

// fakeApp is a small application with deliberately vulnerable and safe
// endpoints. It records every request it is sent.
type fakeApp struct {
	routes   map[string]handler
	requests []probe.Request
	batches  int
	err      error
	short    bool
	down     bool
	// afterBatch runs after each batch is answered.
	afterBatch func()
}

func (a *fakeApp) Do(_ context.Context, requests []probe.Request) ([]probe.Response, error) {
	a.batches++
	if a.err != nil {
		return nil, a.err
	}
	out := make([]probe.Response, 0, len(requests))
	for _, r := range requests {
		a.requests = append(a.requests, r)
		out = append(out, a.answer(r))
	}
	if a.short {
		out = out[:len(out)-1]
	}
	if a.afterBatch != nil {
		a.afterBatch()
	}
	return out, nil
}

func (a *fakeApp) answer(r probe.Request) probe.Response {
	resp := page("<p>not found</p>")
	resp.Status = 404
	if a.down {
		resp = probe.Response{Gate: "failed", Status: 502}
	} else if u, err := url.Parse(r.URL); err == nil {
		if h, ok := a.routes[u.Path]; ok {
			resp = h(u.Query(), r)
		}
	}
	resp.ID = r.ID
	return resp
}

func (a *fakeApp) urls() []string {
	out := make([]string, 0, len(a.requests))
	for _, r := range a.requests {
		out = append(out, r.URL)
	}
	return out
}

func page(body string) probe.Response {
	return withType(200, "text/html; charset=utf-8", "<html><body>"+body+"</body></html>")
}

func withType(status int, contentType, body string) probe.Response {
	return probe.Response{Status: status, Headers: map[string][]string{"Content-Type": {contentType}}, Body: body}
}

func redirect(location string) probe.Response {
	return probe.Response{Status: 302, Headers: map[string][]string{"Location": {location}}}
}

const mysqlError = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"

// newApp builds the fake application.
func newApp() *fakeApp {
	return &fakeApp{routes: map[string]handler{
		// Reflected input.
		"/search": func(q url.Values, _ probe.Request) probe.Response {
			return page("<p>Results for " + q.Get("q") + "</p>")
		},
		"/safe-search": func(q url.Values, _ probe.Request) probe.Response {
			return page("<p>" + html.EscapeString(q.Get("q")) + "</p>")
		},
		"/profile": func(q url.Values, _ probe.Request) probe.Response {
			return page(`<input name="n" value="` + q.Get("name") + `">`)
		},
		"/attr-safe": func(q url.Values, _ probe.Request) probe.Response {
			// Quotes encoded, angle brackets raw: harmless inside a quoted value.
			v := strings.NewReplacer(`"`, "&quot;", "'", "&#39;").Replace(q.Get("name"))
			return page(`<input value="` + v + `">`)
		},
		"/api/search": func(q url.Values, _ probe.Request) probe.Response {
			return withType(200, "application/json", `{"q":"`+q.Get("q")+`"}`)
		},
		"/text":    func(q url.Values, _ probe.Request) probe.Response { return withType(200, "text/plain", q.Get("q")) },
		"/comment": func(q url.Values, _ probe.Request) probe.Response { return page("<!-- debug: " + q.Get("q") + " -->") },
		// SQL errors.
		"/item": func(q url.Values, _ probe.Request) probe.Response {
			if strings.Count(q.Get("id"), "'")%2 == 1 {
				return withType(500, "text/html", "<b>Fatal:</b> "+mysqlError+" near '''")
			}
			return page("item " + html.EscapeString(q.Get("id")))
		},
		"/noisy": func(q url.Values, _ probe.Request) probe.Response {
			return page("<pre>old log: " + mysqlError + "</pre>")
		},
		"/both": func(q url.Values, _ probe.Request) probe.Response {
			if strings.Contains(q.Get("id"), "'") {
				return withType(500, "text/html", "ORA-00933: SQL command not properly ended")
			}
			return page("ok")
		},
		// Redirects.
		"/go": func(q url.Values, _ probe.Request) probe.Response { return redirect(q.Get("next")) },
		"/login": func(q url.Values, _ probe.Request) probe.Response {
			if v := q.Get("returnTo"); strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
				return redirect(v)
			}
			return redirect("/home")
		},
		"/sso": func(q url.Values, _ probe.Request) probe.Response {
			return redirect("https://app.test/signin?continue=" + url.QueryEscape(q.Get("continue")))
		},
		"/hop": func(q url.Values, _ probe.Request) probe.Response {
			u, _ := url.Parse(q.Get("url"))
			return redirect("https://" + u.Hostname() + ".app.test/")
		},
		// Echoes the session header: a credential leak waiting to happen.
		"/echo": func(q url.Values, r probe.Request) probe.Response {
			return page("<p>" + q.Get("q") + "</p><p>you sent " + r.Headers["Authorization"] + "</p>")
		},
	}}
}

// counterTokens replaces the random token with a predictable sequence.
func counterTokens() func() (string, error) {
	n := 0
	return func() (string, error) {
		n++
		return fmt.Sprintf("%012x", n), nil
	}
}

func allInScope(string) bool { return true }

func newChecker(t *testing.T, app probe.Fetcher, opts Options) *Checker {
	t.Helper()
	if opts.MaxRequests == 0 {
		opts.MaxRequests = 1000
	}
	if opts.InScope == nil {
		opts.InScope = allInScope
	}
	c, err := New(app, opts)
	if err != nil {
		t.Fatal(err)
	}
	c.newToken = counterTokens()
	return c
}

func run(t *testing.T, c *Checker, urls ...string) Result {
	t.Helper()
	result, err := c.Run(context.Background(), urls)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
