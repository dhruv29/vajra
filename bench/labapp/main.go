// Command labapp is a DELIBERATELY VULNERABLE web application for Vajra's
// test lab. It exists only so that scripts/e2e.sh can measure how many real
// flaws Vajra finds and how many false ones it raises, against the answer key
// in bench/labapp.json.
//
// Never run it anywhere but an isolated lab network. Several routes are
// insecure on purpose.
//
// Routes under /vuln/ carry a real flaw Vajra should report. Routes under
// /safe/ are decoys: they look suspicious to a careless scanner but are not
// exploitable, and reporting them is a false positive. There is no database;
// the SQL error is simulated from the balance of quotes in the input.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// adminToken is the lab's administrator credential: a fixed, public lab
	// value, not a secret. scripts/e2e.sh passes it to Vajra through the
	// environment.
	adminToken = "Bearer lab-admin-token"

	htmlType = "text/html; charset=utf-8"
	jsonType = "application/json"

	readHeaderTimeout = 5 * time.Second
)

// indexPage links every route with a sample query, so a crawler finds them,
// and carries a GET form whose action is linked from nowhere else.
const indexPage = `<!doctype html>
<html><head><title>Lab shop (intentionally vulnerable)</title></head>
<body>
<h1>Lab shop</h1>
<p>This application is intentionally vulnerable and exists only for the Vajra test lab.</p>
<h2>Shop</h2>
<ul>
<li><a href="/vuln/search?q=shoes">Search</a></li>
<li><a href="/vuln/product?id=1">Product 1</a></li>
<li><a href="/vuln/redirect?next=/">Continue</a></li>
<li><a href="/vuln/admin/report">Sales report (administrators)</a></li>
<li><a href="/safe/search?q=shoes">Search (escaped)</a></li>
<li><a href="/safe/api/search?q=shoes">Search API</a></li>
<li><a href="/safe/status?id=1">Database status article</a></li>
<li><a href="/safe/redirect?next=/">Continue (same site only)</a></li>
<li><a href="/safe/comment?q=shoes">Search (debug comment)</a></li>
<li><a href="/safe/admin/settings">Settings (administrators)</a></li>
</ul>
<form action="/vuln/lookup" method="get"><input name="term" value=""><button>Look up</button></form>
</body></html>
`

// sqlErrorArticle is a help page that always quotes a database error. The
// text is the same whatever the request, so it proves nothing about input.
const sqlErrorArticle = `<p>Seeing "You have an error in your SQL syntax; check the manual that ` +
	`corresponds to your MySQL server version"? That message comes from the database, not from this shop.</p>`

func main() {
	listen := flag.String("listen", ":80", "address to listen on")
	flag.Parse()
	log.Printf("labapp: INTENTIONALLY VULNERABLE lab application listening on %s", *listen)
	server := &http.Server{Addr: *listen, Handler: newHandler(), ReadHeaderTimeout: readHeaderTimeout}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("labapp: %v", err)
		os.Exit(1)
	}
}

// newHandler wires every route.
func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", index)
	mux.HandleFunc("GET /vuln/search", vulnSearch)
	mux.HandleFunc("GET /vuln/lookup", vulnLookup)
	mux.HandleFunc("GET /vuln/product", vulnProduct)
	mux.HandleFunc("GET /vuln/redirect", vulnRedirect)
	mux.HandleFunc("GET /vuln/admin/report", vulnAdminReport)
	mux.HandleFunc("GET /safe/search", safeSearch)
	mux.HandleFunc("GET /safe/api/search", safeAPISearch)
	mux.HandleFunc("GET /safe/status", safeStatus)
	mux.HandleFunc("GET /safe/redirect", safeRedirect)
	mux.HandleFunc("GET /safe/comment", safeComment)
	mux.HandleFunc("GET /safe/admin/settings", safeAdminSettings)
	return mux
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", htmlType)
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func page(title, content string) string {
	return "<!doctype html><html><head><title>" + title + "</title></head><body>" +
		content + `<p><a href="/">home</a></p></body></html>`
}

func index(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, http.StatusOK, indexPage)
}

// vulnSearch is FLAW 1: q is written into the page unescaped (reflected
// cross-site scripting in HTML text).
func vulnSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	writeHTML(w, http.StatusOK, page("Search", "<p>Results for: "+q+"</p><p>No products found.</p>"))
}

// vulnLookup is FLAW 2, reachable only through the index page's form: term
// is written into a double-quoted attribute unescaped.
func vulnLookup(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("term")
	writeHTML(w, http.StatusOK, page("Look up", `<form action="/vuln/lookup"><input name="term" value="`+term+`"></form>`))
}

// vulnProduct is FLAW 3: id is pasted into a simulated SQL query, so an odd
// number of single quotes breaks the query and the database's error is shown.
// A doubled quote is how SQL escapes a quote, so it parses. The error text
// escapes the input so that this route has no second, unintended flaw.
func vulnProduct(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// The simulated query is SELECT name, price FROM products WHERE id = '<id>'.
	if strings.Count(id, "'")%2 == 1 {
		near := id + "'"
		writeHTML(w, http.StatusInternalServerError, page("Error",
			"<pre>Error 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to "+
				"your MySQL server version for the right syntax to use near '"+html.EscapeString(near)+"' at line 1</pre>"))
		return
	}
	writeHTML(w, http.StatusOK, page("Product", "<p>Product "+html.EscapeString(id)+": canvas shoes, 42.00</p>"))
}

// vulnRedirect is FLAW 4: next goes into the Location header verbatim, so a
// link to this site can send a visitor to any other site.
func vulnRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", r.URL.Query().Get("next"))
	w.WriteHeader(http.StatusFound)
}

// vulnAdminReport is FLAW 5: the sales report is meant for the admin
// account only, but the check was forgotten and anyone is served it.
func vulnAdminReport(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, http.StatusOK, page("Sales report", "<h1>Sales report</h1><p>Revenue this month: 12,345.00</p>"))
}

// safeSearch is a DECOY: q is reflected, but HTML-escaped.
func safeSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	writeHTML(w, http.StatusOK, page("Search", "<p>Results for: "+html.EscapeString(q)+"</p><p>No products found.</p>"))
}

// safeAPISearch is a DECOY: q comes back raw, but inside JSON served as
// JSON, which a browser does not render as markup.
func safeAPISearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", jsonType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // the raw characters reach the body; the content type is what makes it safe
	if err := enc.Encode(map[string]any{"query": r.URL.Query().Get("q"), "results": []string{}}); err != nil {
		log.Printf("labapp: encode: %v", err)
	}
}

// safeStatus is a DECOY: it always shows a database error message, whatever
// the input, because it is an article about that message.
func safeStatus(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, http.StatusOK, page("Database status", sqlErrorArticle))
}

// safeRedirect is a DECOY: next is followed only when it is a path on this
// site; anything else goes to the home page.
func safeRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", sameSitePath(r.URL.Query().Get("next")))
	w.WriteHeader(http.StatusFound)
}

// sameSitePath returns next when it is a path on this site and "/"
// otherwise. "//host" and "/\host" are treated by browsers as other sites.
func sameSitePath(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, `/\`) ||
		strings.ContainsAny(next, "\r\n\t") {
		return "/"
	}
	return next
}

// safeComment is a DECOY: q lands only inside an HTML comment, with every
// character that could close the comment neutralised, so the raw "<" in it is
// never markup.
func safeComment(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, http.StatusOK, page("Search", "<!-- search term: "+commentSafe(r.URL.Query().Get("q"))+
		" --><p>No products found.</p>"))
}

// commentSafe removes what could end an HTML comment early: "-" (for "-->"
// and "--!>") and ">" (for "<!-->"-style abrupt endings).
func commentSafe(s string) string {
	return strings.NewReplacer("-", "_", ">", "&gt;").Replace(s)
}

// safeAdminSettings is a DECOY: like the sales report it is for the admin
// account only, and here the check is in place.
func safeAdminSettings(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != adminToken {
		writeHTML(w, http.StatusForbidden, page("Forbidden", "<p>Administrators only.</p>"))
		return
	}
	writeHTML(w, http.StatusOK, page("Settings", "<h1>Settings</h1><p>Shop name: Lab shop</p>"))
}
