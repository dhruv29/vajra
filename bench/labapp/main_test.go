package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	userToken = "Bearer lab-user-token"
	// probe is the kind of value a scanner sends: HTML metacharacters and
	// quotes around a recognisable marker.
	probe = `mk"mk'mk<mk>`
)

type exchange struct {
	status   int
	location string
	ctype    string
	body     string
}

func get(t *testing.T, h http.Handler, path string, headers map[string]string) exchange {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return exchange{
		status: rec.Code, location: rec.Header().Get("Location"),
		ctype: rec.Header().Get("Content-Type"), body: string(body),
	}
}

func withQuery(path, name, value string) string {
	return path + "?" + url.Values{name: {value}}.Encode()
}

const mysqlError = "You have an error in your SQL syntax"

func TestRoutesBehaveAsLabelled(t *testing.T) {
	h := newHandler()
	admin := map[string]string{"Authorization": adminToken}
	user := map[string]string{"Authorization": userToken}
	tests := []struct {
		name    string
		path    string
		headers map[string]string
		check   func(exchange) bool
	}{
		{"index links every route and has a GET form", "/", nil, func(e exchange) bool {
			for _, want := range []string{"/vuln/search?q=", "/vuln/product?id=", "/vuln/redirect?next=", "/vuln/admin/report",
				"/safe/search?q=", "/safe/api/search?q=", "/safe/status?id=", "/safe/redirect?next=", "/safe/comment?q=",
				"/safe/admin/settings", `<form action="/vuln/lookup" method="get"><input name="term"`, "intentionally vulnerable"} {
				if !strings.Contains(e.body, want) {
					return false
				}
			}
			return e.status == http.StatusOK
		}},
		{"unknown path is not found", "/nope", nil, func(e exchange) bool { return e.status == http.StatusNotFound }},

		{"flaw: search reflects input raw into HTML", withQuery("/vuln/search", "q", probe), nil, func(e exchange) bool {
			return strings.HasPrefix(e.ctype, "text/html") && strings.Contains(e.body, "Results for: "+probe)
		}},
		{"flaw: lookup reflects input raw into a quoted attribute", withQuery("/vuln/lookup", "term", probe), nil, func(e exchange) bool {
			return strings.HasPrefix(e.ctype, "text/html") && strings.Contains(e.body, `value="`+probe+`"`)
		}},
		{"flaw: product shows a database error for one quote", withQuery("/vuln/product", "id", "1'"), nil, func(e exchange) bool {
			return e.status == http.StatusInternalServerError && strings.Contains(e.body, mysqlError)
		}},
		{"flaw: product has no error for a doubled quote", withQuery("/vuln/product", "id", "1''"), nil, func(e exchange) bool {
			return e.status == http.StatusOK && !strings.Contains(e.body, mysqlError)
		}},
		{"flaw: product has no error for the plain value", withQuery("/vuln/product", "id", "1"), nil, func(e exchange) bool {
			return e.status == http.StatusOK && !strings.Contains(e.body, mysqlError)
		}},
		{"flaw: product escapes the input it shows", withQuery("/vuln/product", "id", probe), nil, func(e exchange) bool {
			return strings.Contains(e.body, mysqlError) && !strings.Contains(e.body, "<mk>")
		}},
		{"flaw: redirect goes to any site", withQuery("/vuln/redirect", "next", "https://elsewhere.invalid/"), nil, func(e exchange) bool {
			return e.status == http.StatusFound && e.location == "https://elsewhere.invalid/"
		}},
		{"flaw: admin report is served anonymously", "/vuln/admin/report", nil, func(e exchange) bool {
			return e.status == http.StatusOK && strings.Contains(e.body, "Sales report")
		}},
		{"flaw: admin report is served to an ordinary user", "/vuln/admin/report", user, func(e exchange) bool {
			return e.status == http.StatusOK && strings.Contains(e.body, "Sales report")
		}},

		{"decoy: search escapes input", withQuery("/safe/search", "q", probe), nil, func(e exchange) bool {
			return strings.Contains(e.body, "mk&#34;mk&#39;mk&lt;mk&gt;") && !strings.Contains(e.body, "<mk>")
		}},
		{"decoy: API reflects input only as JSON", withQuery("/safe/api/search", "q", probe), nil, func(e exchange) bool {
			return e.ctype == jsonType && strings.Contains(e.body, "<mk>")
		}},
		{"decoy: status shows a database error whatever the input", withQuery("/safe/status", "id", "1"), nil, func(e exchange) bool {
			return e.status == http.StatusOK && strings.Contains(e.body, mysqlError)
		}},
		{"decoy: status shows the same page with a doubled quote", withQuery("/safe/status", "id", "1''"), nil, func(e exchange) bool {
			return strings.Contains(e.body, mysqlError)
		}},
		{"decoy: redirect refuses another site", withQuery("/safe/redirect", "next", "https://elsewhere.invalid/"), nil, func(e exchange) bool {
			return e.status == http.StatusFound && e.location == "/"
		}},
		{"decoy: redirect refuses a protocol-relative URL", withQuery("/safe/redirect", "next", "//elsewhere.invalid/"), nil, func(e exchange) bool {
			return e.location == "/"
		}},
		{"decoy: redirect refuses a backslash URL", withQuery("/safe/redirect", "next", `/\elsewhere.invalid/`), nil, func(e exchange) bool {
			return e.location == "/"
		}},
		{"decoy: redirect follows a same-site path", withQuery("/safe/redirect", "next", "/vuln/search?q=x"), nil, func(e exchange) bool {
			return e.status == http.StatusFound && e.location == "/vuln/search?q=x"
		}},
		{"decoy: comment holds the input with no way out", withQuery("/safe/comment", "q", "x --> <b>"), nil, func(e exchange) bool {
			return strings.Contains(e.body, "<!-- search term: x __&gt; <b&gt; -->") && strings.Count(e.body, "-->") == 1
		}},
		{"decoy: settings refuse anonymous visitors", "/safe/admin/settings", nil, func(e exchange) bool {
			return e.status == http.StatusForbidden && !strings.Contains(e.body, "Shop name")
		}},
		{"decoy: settings refuse an ordinary user", "/safe/admin/settings", user, func(e exchange) bool {
			return e.status == http.StatusForbidden && !strings.Contains(e.body, "Shop name")
		}},
		{"decoy: settings serve the administrator", "/safe/admin/settings", admin, func(e exchange) bool {
			return e.status == http.StatusOK && strings.Contains(e.body, "Shop name")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := get(t, h, tt.path, tt.headers)

			if !tt.check(got) {
				t.Fatalf("GET %s: status %d, location %q, type %q, body:\n%s", tt.path, got.status, got.location, got.ctype, got.body)
			}
		})
	}
}

func TestSameSitePath(t *testing.T) {
	tests := map[string]string{
		"/":                   "/",
		"/account?tab=orders": "/account?tab=orders",
		"":                    "/",
		"account":             "/",
		"https://x.invalid/":  "/",
		"//x.invalid/":        "/",
		`/\x.invalid/`:        "/",
		"/a\r\nSet-Cookie: x": "/",
	}
	for in, want := range tests {
		if got := sameSitePath(in); got != want {
			t.Errorf("sameSitePath(%q) = %q, want %q", in, got, want)
		}
	}
}
