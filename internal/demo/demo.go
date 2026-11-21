// Package demo builds a sample run, so the reports and the web interface can
// be explored without scanning anything. Every host in it is fictional.
package demo

import (
	"time"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/topology"
)

const shop = "https://shop.example.test"

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
			Verdicts: passed(at, "The response contains 1337, the product of the injected expression, so the template engine evaluated attacker input."),
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
			Severity: finding.SeverityHigh, Target: shop + "/.env", CWE: []string{"cwe-200"}, Status: finding.Confirmed,
			Evidence: finding.Evidence{
				Request:   "GET /.env HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
				Response:  "HTTP/1.1 200 OK\r\n\r\nAPP_ENV=production\nPAYMENTS_API_KEY=[redacted in demo]",
				Extracted: []string{"PAYMENTS_API_KEY=[redacted in demo]"},
			},
			Verdicts: passed(at, "The body is a real environment file with a populated key, not a placeholder or an error page."),
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
	add("assets.cdn-provider.example.test:443", false, "host is not in scope", 9)
	add("169.254.169.254:80", false, "address range can never be a target", 3)
	add("updates.scanner-vendor.example.test:443", false, "host is not in scope", 2)
	return out
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
		Scope:         scope.Config{Hosts: []string{"shop.example.test"}, Ports: []int{443}},
		Budget: record.BudgetReport{
			Limits: budget.Limits{Tokens: 500000, Turns: 200, SandboxRuns: 100, DurationSeconds: 3600},
			Usage:  budget.Usage{Tokens: 41280, Turns: 6, SandboxRuns: 13, Elapsed: 7*time.Minute + 12*time.Second},
		},
		Refuter: "anthropic", Summary: summary, Findings: all,
	}
	return record.Build(id, report, declaration, events())
}
