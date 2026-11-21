// Package demo builds a sample run, so the reports and the web interface can
// be explored without scanning anything. Every host in it is fictional.
package demo

import (
	"time"

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/topology"
)

const (
	shop = "https://shop.example.test"
	// staging is a host the sample run "discovered" under the wildcard scope.
	staging = "https://staging.shop.example.test"
)

func verdicts(at time.Time, steps ...[3]string) []finding.Verdict {
	out := make([]finding.Verdict, 0, len(steps))
	for _, s := range steps {
		out = append(out, finding.Verdict{Stage: s[0], Outcome: finding.Outcome(s[1]), Reason: s[2], At: at})
	}
	return out
}

func passed(at time.Time, refutation string) []finding.Verdict {
	return verdicts(at,
		[3]string{"evidence", "pass", "request and response captured"},
		[3]string{"scope", "pass", "target is in scope"},
		[3]string{"reproduce", "pass", "reproduced 2 of 2 times"},
		[3]string{"refute", "pass", refutation})
}

func findings(at time.Time) []finding.Finding {
	return []finding.Finding{
		{
			ID: "demo-rce", Source: "nuclei", RuleID: "template-injection", Title: "Server-side template injection in invoice preview",
			Severity: finding.SeverityCritical, Target: shop + "/invoices/preview", CWE: []string{"cwe-94"}, Status: finding.Confirmed,
			Evidence: finding.Evidence{
				Request:  "POST /invoices/preview HTTP/1.1\r\nHost: shop.example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nnote={{7*191}}",
				Response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p class=\"note\">1337</p>",
			},
			// Code execution on the shop, seen from the running application and
			// from its source: each side corroborates the other.
			CorroboratedBy: []string{"demo-code-cmdi"},
			Verdicts:       passed(at, "The response contains 1337, the product of the injected expression, so the template engine evaluated attacker input."),
		},
		{
			ID: "demo-sqli", Source: "nuclei", RuleID: "error-based-sqli", Title: "SQL injection in order lookup",
			Severity: finding.SeverityHigh, Target: shop + "/orders", CWE: []string{"cwe-89"}, Status: finding.Confirmed,
			Evidence: finding.Evidence{
				Request:  "GET /orders?id=1%27 HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
				Response: "HTTP/1.1 500 Internal Server Error\r\n\r\npq: unterminated quoted string at or near \"'1''\"",
			},
			Verdicts: passed(at, "The database error quotes the injected character inside the query text, which shows the parameter reaches the query unescaped."),
		},
		{
			ID: "demo-env", Source: "nuclei", RuleID: "exposed-env", Title: "Environment file served over HTTP",
			Severity: finding.SeverityHigh, Target: staging + "/.env", CWE: []string{"cwe-200"}, Status: finding.Confirmed,
			Evidence: finding.Evidence{
				Request:   "GET /.env HTTP/1.1\r\nHost: staging.shop.example.test\r\n\r\n",
				Response:  "HTTP/1.1 200 OK\r\n\r\nAPP_ENV=production\nPAYMENTS_API_KEY=[redacted in demo]",
				Extracted: []string{"PAYMENTS_API_KEY=[redacted in demo]"},
			},
			Verdicts: passed(at, "The body is a real environment file with a populated key, not a placeholder or an error page."),
		},
		{
			ID: "demo-code-cmdi", Kind: finding.Static, Source: "semgrep", RuleID: "rules.python-command-injection",
			Title: "python command injection", Severity: finding.SeverityHigh, Target: "shop/exports.py:41",
			Description: "Request input reaches a shell command. Pass arguments as a list without a shell, and validate them against an allow-list.",
			Location:    &finding.Location{File: "shop/exports.py", Line: 41, EndLine: 41},
			AssetURL:    shop, CWE: []string{"cwe-78"}, Status: finding.Confirmed,
			CorroboratedBy: []string{"demo-rce", "demo-cmdi"},
			Evidence: finding.Evidence{
				Code: "     37 | @app.route(\"/exports\")\n     38 | @login_required\n     39 | def export_orders():\n     40 |     fmt = request.args.get(\"format\", \"csv\")\n>    41 |     os.system(\"./bin/export --format \" + fmt)\n     42 |     return send_file(\"/tmp/export.\" + fmt)\n",
				Trace: []finding.TraceStep{
					{Role: "source", File: "shop/exports.py", Line: 40, Content: "request.args.get(\"format\", \"csv\")"},
					{Role: "propagation", File: "shop/exports.py", Line: 40, Content: "fmt"},
					{Role: "sink", File: "shop/exports.py", Line: 41, Content: "os.system(\"./bin/export --format \" + fmt)"},
				},
			},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "source located and read"},
				[3]string{"scope", "pass", "file is inside the analysed source tree"},
				[3]string{"reproduce", "pass", "reproduced 1 of 1 times"},
				[3]string{"refute", "pass", "Line 40 reads the format parameter from the request and line 41 concatenates it into a shell command with no validation between them."}),
		},
		{
			ID: "demo-cmdi", Kind: finding.Dynamic, Source: agent.Source, RuleID: "agent-78", Title: "Shell error when the export format contains a semicolon",
			Description: "A semicolon in the format parameter produces an error from a shell rather than from the application, which suggests the value is passed to a command line.",
			Severity:    finding.SeverityHigh, Target: shop + "/exports?format=csv%3Bid", CWE: []string{"cwe-78"},
			Tags: []string{"agent"}, Status: finding.Unconfirmed,
			Evidence: finding.Evidence{
				Request:   "GET /exports?format=csv%3Bid HTTP/1.1\r\nHost: shop.example.test\r\nCookie: [redacted]\r\n\r\n",
				Response:  "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nsh: 1: ./bin/export: unknown format 'csv'\n",
				MatchedAt: shop + "/exports?format=csv%3Bid",
				Matcher:   `sh: \d+: \./bin/export`,
			},
			CorroboratedBy: []string{"demo-code-cmdi"},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "request and response captured"},
				[3]string{"scope", "pass", "target is in scope"},
				[3]string{"reproduce", "pass", "reproduced 2 of 2 times"},
				[3]string{"refute", "inconclusive", "The error comes from a shell, but the response does not show output of the injected command, so execution is not proven from the outside."}),
		},
		{
			ID: "demo-secret", Kind: finding.Static, Source: "vajra-secrets", RuleID: "generic-credential",
			Title: "Hard-coded credential in source", Severity: finding.SeverityMedium, Target: "shop/settings.py:18",
			Description: "A value assigned to a credential-like name looks like a real secret, which anyone with the code can read; change the credential and load it from the environment or a secret manager.",
			Location:    &finding.Location{File: "shop/settings.py", Line: 18, EndLine: 18},
			AssetURL:    shop, CWE: []string{"cwe-798"}, Tags: []string{"secrets"}, Status: finding.Unconfirmed,
			Evidence: finding.Evidence{
				// Only the masked form is ever stored; there is no real value here.
				Code:      "     17 | MAIL_HOST = \"mail.internal.example.test\"\n>    18 | MAIL_PASSWORD = \"demo…[masked 20 chars]\"\n     19 | MAIL_USE_TLS = True\n",
				Extracted: []string{"demo…[masked 20 chars]"},
			},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "source located and read"},
				[3]string{"scope", "pass", "file is inside the analysed source tree"},
				[3]string{"reproduce", "pass", "reproduced 1 of 1 times"},
				[3]string{"refute", "inconclusive", "The value has the shape of a real password, but whether the mail account still accepts it cannot be told from the code."}),
		},
		{
			ID: "demo-dep-lodash", Kind: finding.Dependency, Source: osv.Source, RuleID: "GHSA-demo-0000-0000",
			Title: "lodash 4.17.20: Regular Expression Denial of Service (ReDoS) in lodash", Description: "Fixed in 4.17.21.",
			Severity: finding.SeverityMedium, Target: "web/package-lock.json:2231",
			Location: &finding.Location{File: "web/package-lock.json", Line: 2231},
			Tags:     []string{"dependency", "npm"}, CWE: []string{"cwe-1333"}, Status: finding.Unconfirmed,
			Evidence: finding.Evidence{
				Code:      ">  2231 |     \"node_modules/lodash\": {\n>  2232 |       \"version\": \"4.17.20\",\n",
				Extracted: []string{"npm/lodash@4.17.20"},
			},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "the lockfile pins this version"},
				[3]string{"scope", "pass", "file is inside the analysed source tree"},
				[3]string{"reproduce", "pass", "the advisory still lists this version as affected"},
				[3]string{"refute", "inconclusive", "The package is installed, but whether the application calls the affected functions with untrusted input was not determined."}),
		},
		{
			ID: "demo-xss", Source: "nuclei", RuleID: "reflected-xss", Title: "Reflected cross-site scripting in search",
			Severity: finding.SeverityMedium, Target: shop + "/search", CWE: []string{"cwe-79"}, Status: finding.Unconfirmed,
			Evidence: finding.Evidence{
				Request:  "GET /search?q=%3Csvg%20onload%3D1%3E HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
				Response: "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'self'\r\n\r\n<h1>Results for <svg onload=1></h1>",
			},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "request and response captured"},
				[3]string{"scope", "pass", "target is in scope"},
				[3]string{"reproduce", "pass", "reproduced 2 of 2 times"},
				[3]string{"refute", "inconclusive", "The input is reflected unescaped, but the response sets a content-security policy that may block the script. A browser check is needed."}),
		},
		{
			ID: "demo-admin", Source: "nuclei", RuleID: "admin-panel-detect", Title: "Admin panel exposed",
			Severity: finding.SeverityHigh, Target: shop + "/admin", CWE: []string{"cwe-306"}, Status: finding.Refuted,
			Evidence: finding.Evidence{
				Request:  "GET /admin HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
				Response: "HTTP/1.1 302 Found\r\nLocation: /login?next=/admin\r\n\r\n",
			},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "request and response captured"},
				[3]string{"scope", "pass", "target is in scope"},
				[3]string{"reproduce", "pass", "reproduced 2 of 2 times"},
				[3]string{"refute", "fail", "The response is a redirect to the login page. The panel requires authentication, so nothing is exposed."}),
		},
		{
			ID: "demo-flaky", Source: "nuclei", RuleID: "open-redirect", Title: "Open redirect on logout",
			Severity: finding.SeverityLow, Target: shop + "/logout", CWE: []string{"cwe-601"}, Status: finding.Refuted,
			Evidence: finding.Evidence{Request: "GET /logout?next=//evil.example.test HTTP/1.1", Response: "HTTP/1.1 302 Found"},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "request and response captured"},
				[3]string{"scope", "pass", "target is in scope"},
				[3]string{"reproduce", "fail", "did not reproduce on attempt 1 of 2"}),
		},
		{
			ID: "demo-cdn", Source: "nuclei", RuleID: "s3-listing", Title: "Bucket listing enabled",
			Severity: finding.SeverityMedium, Target: "https://assets.cdn-provider.example.test/", Status: finding.OutOfScope,
			Evidence: finding.Evidence{Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK"},
			Verdicts: verdicts(at,
				[3]string{"evidence", "pass", "request and response captured"},
				[3]string{"scope", "fail", "scope denied assets.cdn-provider.example.test:443: host is not in scope"}),
		},
	}
}

var declaration = topology.Declaration{
	Assets: []topology.DeclaredAsset{
		{ID: "orders-db", Kind: topology.Datastore, Name: "Orders database", DataClasses: []string{"pii", "payment"}},
		{ID: "payments-key", Kind: topology.Identity, Name: "Payments API key", DataClasses: []string{"credentials"}},
		{ID: "ledger", Kind: topology.Datastore, Name: "Billing ledger", DataClasses: []string{"financial"}},
		{ID: "sessions", Kind: topology.Datastore, Name: "Session cache", DataClasses: []string{"auth"}},
	},
	Links: []topology.DeclaredLink{
		{From: "shop.example.test", To: "orders-db", Relation: topology.Reads},
		{From: "shop.example.test", To: "sessions", Relation: topology.Reads},
		{From: "shop.example.test", To: "payments-key", Relation: topology.AuthenticatesWith},
		{From: "shop.example.test", To: "billing.internal.example.test", Relation: topology.Calls},
		{From: "billing.internal.example.test", To: "ledger", Relation: topology.Reads},
		// Staging was deployed with the production key, which is what turns
		// its exposed environment file into the first step of a chain.
		{From: "staging.shop.example.test", To: "payments-key", Relation: topology.AuthenticatesWith},
	},
}

func events() []egress.Event {
	out := []egress.Event{}
	add := func(target string, allowed bool, reason string, n int) {
		for i := 0; i < n; i++ {
			out = append(out, egress.Event{Method: "CONNECT", Target: target, Allowed: allowed, Reason: reason})
		}
	}
	add("shop.example.test:443", true, "", 412)
	add("staging.shop.example.test:443", true, "", 38)
	add("assets.cdn-provider.example.test:443", false, "host is not in scope", 9)
	add("169.254.169.254:80", false, "address range can never be a target", 3)
	add("updates.scanner-vendor.example.test:443", false, "host is not in scope", 2)
	return out
}

// activity is what the sample run did besides scanning its targets.
func activity() record.Activity {
	return record.Activity{
		DiscoveredHosts: []string{"staging.shop.example.test", "status.shop.example.test"},
		RejectedHosts:   []string{"legacy.shop.example.test"},
		Endpoints: []string{
			shop + "/search", shop + "/orders", shop + "/exports", shop + "/invoices/preview", shop + "/api/v1/orders",
		},
		PagesCrawled:      37,
		CrawlTruncated:    true,
		SkippedOperations: []string{"DELETE /api/v1/orders/{id}: the method can change data and the run was not allowed to send it"},
		Packages: []osv.Package{
			{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", File: "web/package-lock.json", Line: 2231},
			{Ecosystem: "npm", Name: "express", Version: "4.19.2", File: "web/package-lock.json", Line: 1480},
			{Ecosystem: "PyPI", Name: "jinja2", Version: "3.1.4", File: "requirements.txt", Line: 7},
		},
		AgentSteps: []agent.Step{
			{N: 1, Tool: "http_request", Summary: "GET " + shop + "/exports?format=csv", Outcome: "exchange_id: x1"},
			{N: 2, Tool: "http_request", Summary: "GET " + shop + "/exports?format=csv%3Bid", Outcome: "exchange_id: x2"},
			{N: 3, Tool: "report_candidate", Summary: "Shell error when the export format contains a semicolon (exchange x2)", Outcome: "recorded; it will be re-tested and reviewed"},
			{N: 4, Tool: "http_request", Summary: "POST " + shop + "/api/v1/orders", Outcome: "refused: the operator did not approve a request that could change data"},
			{N: 5, Tool: "finish", Summary: "Covered the export and order endpoints; one candidate reported.", Outcome: "exploration ended"},
		},
		AgentStopped: "finished",
		AgentSummary: "Covered the export and order endpoints; one candidate reported.",
		Notes:        []string{"Crawling stopped at the page limit of 37 with links still unvisited."},
	}
}

// Run builds the sample run.
func Run(id string, now time.Time) (record.Run, error) {
	all := findings(now.UTC())
	summary := map[finding.Status]int{}
	for _, f := range all {
		summary[f.Status]++
	}
	report := record.Report{
		Tool: "vajra", GeneratedAt: now.UTC(),
		Authorization: record.Authorization{Operator: "demo", Statement: "Sample data. No system was tested."},
		Targets:       []string{shop},
		SourceRoot:    "/srv/checkouts/shop",
		Scope:         scope.Config{Hosts: []string{"shop.example.test", "*.shop.example.test"}, Ports: []int{443}},
		Budget: record.BudgetReport{
			Limits: budget.Limits{Tokens: 500000, Turns: 200, SandboxRuns: 100, DurationSeconds: 3600},
			Usage:  budget.Usage{Tokens: 41280, Turns: 6, SandboxRuns: 13, Elapsed: 7*time.Minute + 12*time.Second},
		},
		Refuter: "anthropic", Summary: summary, Findings: all, Activity: activity(),
	}
	return record.Build(id, report, declaration, events())
}
