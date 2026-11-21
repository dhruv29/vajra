// A made-up run in the exact shape "vajra scan -data" saves. The shop, its
// hosts and every finding are fictional.
window.VAJRA_SAMPLE = {
 "id": "20261121-232138-c4c29a56",
 "report": {
  "tool": "vajra",
  "generated_at": "2026-11-21T23:21:38.831493Z",
  "authorization": {
   "operator": "demo",
   "statement": "Sample data. No system was tested."
  },
  "targets": [
   "https://shop.example.test"
  ],
  "source_root": "/srv/checkouts/shop",
  "scope": {
   "hosts": [
    "shop.example.test",
    "*.shop.example.test"
   ],
   "cidrs": null,
   "ports": [
    443
   ]
  },
  "budget": {
   "limits": {
    "tokens": 500000,
    "turns": 200,
    "sandbox_runs": 100,
    "duration_seconds": 3600
   },
   "usage": {
    "tokens": 41280,
    "turns": 6,
    "sandbox_runs": 13,
    "elapsed_ns": 432000000000
   }
  },
  "refuter": "anthropic",
  "summary": {
   "confirmed": 4,
   "out_of_scope": 1,
   "refuted": 2,
   "unconfirmed": 4
  },
  "findings": [
   {
    "id": "demo-rce",
    "source": "nuclei",
    "rule_id": "template-injection",
    "title": "Server-side template injection in invoice preview",
    "severity": "critical",
    "target": "https://shop.example.test/invoices/preview",
    "cwe": [
     "cwe-94"
    ],
    "evidence": {
     "request": "POST /invoices/preview HTTP/1.1\r\nHost: shop.example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nnote={{7*191}}",
     "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p class=\"note\">1337</p>"
    },
    "status": "confirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "target is in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 2 of 2 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "pass",
      "reason": "The response contains 1337, the product of the injected expression, so the template engine evaluated attacker input.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ],
    "corroborated_by": [
     "demo-code-cmdi"
    ]
   },
   {
    "id": "demo-sqli",
    "source": "nuclei",
    "rule_id": "error-based-sqli",
    "title": "SQL injection in order lookup",
    "severity": "high",
    "target": "https://shop.example.test/orders",
    "cwe": [
     "cwe-89"
    ],
    "evidence": {
     "request": "GET /orders?id=1%27 HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
     "response": "HTTP/1.1 500 Internal Server Error\r\n\r\npq: unterminated quoted string at or near \"'1''\""
    },
    "status": "confirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "target is in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 2 of 2 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "pass",
      "reason": "The database error quotes the injected character inside the query text, which shows the parameter reaches the query unescaped.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   },
   {
    "id": "demo-env",
    "source": "nuclei",
    "rule_id": "exposed-env",
    "title": "Environment file served over HTTP",
    "severity": "high",
    "target": "https://staging.shop.example.test/.env",
    "cwe": [
     "cwe-200"
    ],
    "evidence": {
     "request": "GET /.env HTTP/1.1\r\nHost: staging.shop.example.test\r\n\r\n",
     "response": "HTTP/1.1 200 OK\r\n\r\nAPP_ENV=production\nPAYMENTS_API_KEY=[redacted in demo]",
     "extracted": [
      "PAYMENTS_API_KEY=[redacted in demo]"
     ]
    },
    "status": "confirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "target is in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 2 of 2 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "pass",
      "reason": "The body is a real environment file with a populated key, not a placeholder or an error page.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   },
   {
    "id": "demo-code-cmdi",
    "kind": "sast",
    "source": "semgrep",
    "rule_id": "rules.python-command-injection",
    "title": "python command injection",
    "description": "Request input reaches a shell command. Pass arguments as a list without a shell, and validate them against an allow-list.",
    "severity": "high",
    "target": "shop/exports.py:41",
    "location": {
     "file": "shop/exports.py",
     "line": 41,
     "end_line": 41
    },
    "asset_url": "https://shop.example.test",
    "cwe": [
     "cwe-78"
    ],
    "evidence": {
     "code": "     37 | @app.route(\"/exports\")\n     38 | @login_required\n     39 | def export_orders():\n     40 |     fmt = request.args.get(\"format\", \"csv\")\n>    41 |     os.system(\"./bin/export --format \" + fmt)\n     42 |     return send_file(\"/tmp/export.\" + fmt)\n",
     "trace": [
      {
       "role": "source",
       "file": "shop/exports.py",
       "line": 40,
       "content": "request.args.get(\"format\", \"csv\")"
      },
      {
       "role": "propagation",
       "file": "shop/exports.py",
       "line": 40,
       "content": "fmt"
      },
      {
       "role": "sink",
       "file": "shop/exports.py",
       "line": 41,
       "content": "os.system(\"./bin/export --format \" + fmt)"
      }
     ]
    },
    "status": "confirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "source located and read",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "file is inside the analysed source tree",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 1 of 1 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "pass",
      "reason": "Line 40 reads the format parameter from the request and line 41 concatenates it into a shell command with no validation between them.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ],
    "corroborated_by": [
     "demo-rce",
     "demo-cmdi"
    ]
   },
   {
    "id": "demo-cmdi",
    "kind": "dast",
    "source": "vajra-agent",
    "rule_id": "agent-78",
    "title": "Shell error when the export format contains a semicolon",
    "description": "A semicolon in the format parameter produces an error from a shell rather than from the application, which suggests the value is passed to a command line.",
    "severity": "high",
    "target": "https://shop.example.test/exports?format=csv%3Bid",
    "tags": [
     "agent"
    ],
    "cwe": [
     "cwe-78"
    ],
    "evidence": {
     "request": "GET /exports?format=csv%3Bid HTTP/1.1\r\nHost: shop.example.test\r\nCookie: [redacted]\r\n\r\n",
     "response": "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nsh: 1: ./bin/export: unknown format 'csv'\n",
     "matched_at": "https://shop.example.test/exports?format=csv%3Bid",
     "matcher": "sh: \\d+: \\./bin/export"
    },
    "status": "unconfirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "target is in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 2 of 2 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "inconclusive",
      "reason": "The error comes from a shell, but the response does not show output of the injected command, so execution is not proven from the outside.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ],
    "corroborated_by": [
     "demo-code-cmdi"
    ]
   },
   {
    "id": "demo-secret",
    "kind": "sast",
    "source": "vajra-secrets",
    "rule_id": "generic-credential",
    "title": "Hard-coded credential in source",
    "description": "A value assigned to a credential-like name looks like a real secret, which anyone with the code can read; change the credential and load it from the environment or a secret manager.",
    "severity": "medium",
    "target": "shop/settings.py:18",
    "location": {
     "file": "shop/settings.py",
     "line": 18,
     "end_line": 18
    },
    "asset_url": "https://shop.example.test",
    "tags": [
     "secrets"
    ],
    "cwe": [
     "cwe-798"
    ],
    "evidence": {
     "extracted": [
      "demo\u2026[masked 20 chars]"
     ],
     "code": "     17 | MAIL_HOST = \"mail.internal.example.test\"\n>    18 | MAIL_PASSWORD = \"demo\u2026[masked 20 chars]\"\n     19 | MAIL_USE_TLS = True\n"
    },
    "status": "unconfirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "source located and read",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "file is inside the analysed source tree",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 1 of 1 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "inconclusive",
      "reason": "The value has the shape of a real password, but whether the mail account still accepts it cannot be told from the code.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   },
   {
    "id": "demo-dep-lodash",
    "kind": "sca",
    "source": "osv",
    "rule_id": "GHSA-demo-0000-0000",
    "title": "lodash 4.17.20: Regular Expression Denial of Service (ReDoS) in lodash",
    "description": "Fixed in 4.17.21.",
    "severity": "medium",
    "target": "web/package-lock.json:2231",
    "location": {
     "file": "web/package-lock.json",
     "line": 2231
    },
    "tags": [
     "dependency",
     "npm"
    ],
    "cwe": [
     "cwe-1333"
    ],
    "evidence": {
     "extracted": [
      "npm/lodash@4.17.20"
     ],
     "code": ">  2231 |     \"node_modules/lodash\": {\n>  2232 |       \"version\": \"4.17.20\",\n"
    },
    "status": "unconfirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "the lockfile pins this version",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "file is inside the analysed source tree",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "the advisory still lists this version as affected",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "inconclusive",
      "reason": "The package is installed, but whether the application calls the affected functions with untrusted input was not determined.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   },
   {
    "id": "demo-xss",
    "source": "nuclei",
    "rule_id": "reflected-xss",
    "title": "Reflected cross-site scripting in search",
    "severity": "medium",
    "target": "https://shop.example.test/search",
    "cwe": [
     "cwe-79"
    ],
    "evidence": {
     "request": "GET /search?q=%3Csvg%20onload%3D1%3E HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
     "response": "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'self'\r\n\r\n<h1>Results for <svg onload=1></h1>"
    },
    "status": "unconfirmed",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "target is in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 2 of 2 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "inconclusive",
      "reason": "The input is reflected unescaped, but the response sets a content-security policy that may block the script. A browser check is needed.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   },
   {
    "id": "demo-admin",
    "source": "nuclei",
    "rule_id": "admin-panel-detect",
    "title": "Admin panel exposed",
    "severity": "high",
    "target": "https://shop.example.test/admin",
    "cwe": [
     "cwe-306"
    ],
    "evidence": {
     "request": "GET /admin HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
     "response": "HTTP/1.1 302 Found\r\nLocation: /login?next=/admin\r\n\r\n"
    },
    "status": "refuted",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "target is in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "pass",
      "reason": "reproduced 2 of 2 times",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "refute",
      "outcome": "fail",
      "reason": "The response is a redirect to the login page. The panel requires authentication, so nothing is exposed.",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   },
   {
    "id": "demo-flaky",
    "source": "nuclei",
    "rule_id": "open-redirect",
    "title": "Open redirect on logout",
    "severity": "low",
    "target": "https://shop.example.test/logout",
    "cwe": [
     "cwe-601"
    ],
    "evidence": {
     "request": "GET /logout?next=//evil.example.test HTTP/1.1",
     "response": "HTTP/1.1 302 Found"
    },
    "status": "refuted",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "pass",
      "reason": "target is in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "reproduce",
      "outcome": "fail",
      "reason": "did not reproduce on attempt 1 of 2",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   },
   {
    "id": "demo-cdn",
    "source": "nuclei",
    "rule_id": "s3-listing",
    "title": "Bucket listing enabled",
    "severity": "medium",
    "target": "https://assets.cdn-provider.example.test/",
    "evidence": {
     "request": "GET / HTTP/1.1",
     "response": "HTTP/1.1 200 OK"
    },
    "status": "out_of_scope",
    "verdicts": [
     {
      "stage": "evidence",
      "outcome": "pass",
      "reason": "request and response captured",
      "at": "2026-11-21T23:21:38.831493Z"
     },
     {
      "stage": "scope",
      "outcome": "fail",
      "reason": "scope denied assets.cdn-provider.example.test:443: host is not in scope",
      "at": "2026-11-21T23:21:38.831493Z"
     }
    ]
   }
  ],
  "activity": {
   "discovered_hosts": [
    "staging.shop.example.test",
    "status.shop.example.test"
   ],
   "rejected_hosts": [
    "legacy.shop.example.test"
   ],
   "endpoints": [
    "https://shop.example.test/search",
    "https://shop.example.test/orders",
    "https://shop.example.test/exports",
    "https://shop.example.test/invoices/preview",
    "https://shop.example.test/api/v1/orders"
   ],
   "pages_crawled": 37,
   "crawl_truncated": true,
   "skipped_operations": [
    "DELETE /api/v1/orders/{id}: the method can change data and the run was not allowed to send it"
   ],
   "packages": [
    {
     "ecosystem": "npm",
     "name": "lodash",
     "version": "4.17.20",
     "file": "web/package-lock.json",
     "line": 2231
    },
    {
     "ecosystem": "npm",
     "name": "express",
     "version": "4.19.2",
     "file": "web/package-lock.json",
     "line": 1480
    },
    {
     "ecosystem": "PyPI",
     "name": "jinja2",
     "version": "3.1.4",
     "file": "requirements.txt",
     "line": 7
    }
   ],
   "agent_steps": [
    {
     "n": 1,
     "tool": "http_request",
     "summary": "GET https://shop.example.test/exports?format=csv",
     "outcome": "exchange_id: x1"
    },
    {
     "n": 2,
     "tool": "http_request",
     "summary": "GET https://shop.example.test/exports?format=csv%3Bid",
     "outcome": "exchange_id: x2"
    },
    {
     "n": 3,
     "tool": "report_candidate",
     "summary": "Shell error when the export format contains a semicolon (exchange x2)",
     "outcome": "recorded; it will be re-tested and reviewed"
    },
    {
     "n": 4,
     "tool": "http_request",
     "summary": "POST https://shop.example.test/api/v1/orders",
     "outcome": "refused: the operator did not approve a request that could change data"
    },
    {
     "n": 5,
     "tool": "finish",
     "summary": "Covered the export and order endpoints; one candidate reported.",
     "outcome": "exploration ended"
    }
   ],
   "agent_stopped": "finished",
   "agent_summary": "Covered the export and order endpoints; one candidate reported.",
   "notes": [
    "Crawling stopped at the page limit of 37 with links still unvisited."
   ]
  }
 },
 "graph": {
  "assets": [
   {
    "id": "endpoint:https://shop.example.test/admin",
    "kind": "endpoint",
    "name": "https://shop.example.test/admin",
    "origin": "derived"
   },
   {
    "id": "endpoint:https://shop.example.test/api/v1/orders",
    "kind": "endpoint",
    "name": "https://shop.example.test/api/v1/orders",
    "origin": "derived"
   },
   {
    "id": "endpoint:https://shop.example.test/exports",
    "kind": "endpoint",
    "name": "https://shop.example.test/exports",
    "origin": "derived"
   },
   {
    "id": "endpoint:https://shop.example.test/invoices/preview",
    "kind": "endpoint",
    "name": "https://shop.example.test/invoices/preview",
    "origin": "derived"
   },
   {
    "id": "endpoint:https://shop.example.test/logout",
    "kind": "endpoint",
    "name": "https://shop.example.test/logout",
    "origin": "derived"
   },
   {
    "id": "endpoint:https://shop.example.test/orders",
    "kind": "endpoint",
    "name": "https://shop.example.test/orders",
    "origin": "derived"
   },
   {
    "id": "endpoint:https://shop.example.test/search",
    "kind": "endpoint",
    "name": "https://shop.example.test/search",
    "origin": "derived"
   },
   {
    "id": "endpoint:https://staging.shop.example.test/.env",
    "kind": "endpoint",
    "name": "https://staging.shop.example.test/.env",
    "origin": "derived"
   },
   {
    "id": "host:assets.cdn-provider.example.test",
    "kind": "host",
    "name": "assets.cdn-provider.example.test",
    "origin": "derived"
   },
   {
    "id": "host:billing.internal.example.test",
    "kind": "host",
    "name": "billing.internal.example.test",
    "origin": "declared"
   },
   {
    "id": "host:shop.example.test",
    "kind": "host",
    "name": "shop.example.test",
    "origin": "derived"
   },
   {
    "id": "host:staging.shop.example.test",
    "kind": "host",
    "name": "staging.shop.example.test",
    "origin": "derived"
   },
   {
    "id": "host:status.shop.example.test",
    "kind": "host",
    "name": "status.shop.example.test",
    "origin": "derived"
   },
   {
    "id": "ledger",
    "kind": "datastore",
    "name": "Billing ledger",
    "data_classes": [
     "financial"
    ],
    "origin": "declared"
   },
   {
    "id": "orders-db",
    "kind": "datastore",
    "name": "Orders database",
    "data_classes": [
     "payment",
     "pii"
    ],
    "origin": "declared"
   },
   {
    "id": "payments-key",
    "kind": "identity",
    "name": "Payments API key",
    "data_classes": [
     "credentials"
    ],
    "origin": "declared"
   },
   {
    "id": "service:assets.cdn-provider.example.test:443",
    "kind": "service",
    "name": "https://assets.cdn-provider.example.test:443",
    "origin": "derived"
   },
   {
    "id": "service:shop.example.test:443",
    "kind": "service",
    "name": "https://shop.example.test:443",
    "origin": "derived"
   },
   {
    "id": "service:staging.shop.example.test:443",
    "kind": "service",
    "name": "https://staging.shop.example.test:443",
    "origin": "derived"
   },
   {
    "id": "service:status.shop.example.test:443",
    "kind": "service",
    "name": "https://status.shop.example.test:443",
    "origin": "derived"
   },
   {
    "id": "sessions",
    "kind": "datastore",
    "name": "Session cache",
    "data_classes": [
     "auth"
    ],
    "origin": "declared"
   }
  ],
  "edges": [
   {
    "from": "host:assets.cdn-provider.example.test",
    "to": "service:assets.cdn-provider.example.test:443",
    "relation": "hosts",
    "origin": "derived"
   },
   {
    "from": "host:billing.internal.example.test",
    "to": "ledger",
    "relation": "reads",
    "origin": "declared"
   },
   {
    "from": "host:shop.example.test",
    "to": "host:billing.internal.example.test",
    "relation": "calls",
    "origin": "declared"
   },
   {
    "from": "host:shop.example.test",
    "to": "orders-db",
    "relation": "reads",
    "origin": "declared"
   },
   {
    "from": "host:shop.example.test",
    "to": "payments-key",
    "relation": "authenticates_with",
    "origin": "declared"
   },
   {
    "from": "host:shop.example.test",
    "to": "service:shop.example.test:443",
    "relation": "hosts",
    "origin": "derived"
   },
   {
    "from": "host:shop.example.test",
    "to": "sessions",
    "relation": "reads",
    "origin": "declared"
   },
   {
    "from": "host:staging.shop.example.test",
    "to": "payments-key",
    "relation": "authenticates_with",
    "origin": "declared"
   },
   {
    "from": "host:staging.shop.example.test",
    "to": "service:staging.shop.example.test:443",
    "relation": "hosts",
    "origin": "derived"
   },
   {
    "from": "host:status.shop.example.test",
    "to": "service:status.shop.example.test:443",
    "relation": "hosts",
    "origin": "derived"
   },
   {
    "from": "service:shop.example.test:443",
    "to": "endpoint:https://shop.example.test/admin",
    "relation": "serves",
    "origin": "derived"
   },
   {
    "from": "service:shop.example.test:443",
    "to": "endpoint:https://shop.example.test/api/v1/orders",
    "relation": "serves",
    "origin": "derived"
   },
   {
    "from": "service:shop.example.test:443",
    "to": "endpoint:https://shop.example.test/exports",
    "relation": "serves",
    "origin": "derived"
   },
   {
    "from": "service:shop.example.test:443",
    "to": "endpoint:https://shop.example.test/invoices/preview",
    "relation": "serves",
    "origin": "derived"
   },
   {
    "from": "service:shop.example.test:443",
    "to": "endpoint:https://shop.example.test/logout",
    "relation": "serves",
    "origin": "derived"
   },
   {
    "from": "service:shop.example.test:443",
    "to": "endpoint:https://shop.example.test/orders",
    "relation": "serves",
    "origin": "derived"
   },
   {
    "from": "service:shop.example.test:443",
    "to": "endpoint:https://shop.example.test/search",
    "relation": "serves",
    "origin": "derived"
   },
   {
    "from": "service:staging.shop.example.test:443",
    "to": "endpoint:https://staging.shop.example.test/.env",
    "relation": "serves",
    "origin": "derived"
   }
  ]
 },
 "radii": [
  {
   "finding_id": "demo-rce",
   "capability": "code_execution",
   "capability_basis": "scanner classification CWE-94",
   "origin_id": "endpoint:https://shop.example.test/invoices/preview",
   "reach": [
    {
     "asset_id": "endpoint:https://shop.example.test/invoices/preview",
     "name": "https://shop.example.test/invoices/preview",
     "kind": "endpoint",
     "depth": 0,
     "confidence": "proven",
     "why": "the finding was reproduced here"
    },
    {
     "asset_id": "host:shop.example.test",
     "name": "shop.example.test",
     "kind": "host",
     "depth": 1,
     "from": "endpoint:https://shop.example.test/invoices/preview",
     "confidence": "inferred",
     "why": "injected code runs with this service's privileges on its host"
    },
    {
     "asset_id": "service:shop.example.test:443",
     "name": "https://shop.example.test:443",
     "kind": "service",
     "depth": 1,
     "from": "endpoint:https://shop.example.test/invoices/preview",
     "confidence": "inferred",
     "why": "injected code runs with this service's privileges on its host"
    },
    {
     "asset_id": "host:billing.internal.example.test",
     "name": "billing.internal.example.test",
     "kind": "host",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "calls",
     "confidence": "assumed",
     "why": "reachable from the compromised service's network position"
    },
    {
     "asset_id": "orders-db",
     "name": "Orders database",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the compromised service can already read this data store",
     "data_classes": [
      "payment",
      "pii"
     ]
    },
    {
     "asset_id": "payments-key",
     "name": "Payments API key",
     "kind": "identity",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "authenticates_with",
     "confidence": "inferred",
     "why": "the compromised service holds this credential",
     "data_classes": [
      "credentials"
     ]
    },
    {
     "asset_id": "sessions",
     "name": "Session cache",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the compromised service can already read this data store",
     "data_classes": [
      "auth"
     ]
    },
    {
     "asset_id": "ledger",
     "name": "Billing ledger",
     "kind": "datastore",
     "depth": 3,
     "from": "host:billing.internal.example.test",
     "via": "reads",
     "confidence": "assumed",
     "why": "readable if the attacker moves on to the called service",
     "data_classes": [
      "financial"
     ]
    }
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 100,
   "summary": "From https://shop.example.test/invoices/preview, code execution reaches 7 further asset(s), including data classed auth, credentials, financial, payment, pii."
  },
  {
   "finding_id": "demo-code-cmdi",
   "capability": "code_execution",
   "capability_basis": "scanner classification CWE-78",
   "origin_id": "service:shop.example.test:443",
   "reach": [
    {
     "asset_id": "service:shop.example.test:443",
     "name": "https://shop.example.test:443",
     "kind": "service",
     "depth": 0,
     "confidence": "proven",
     "why": "the finding was reproduced here"
    },
    {
     "asset_id": "host:shop.example.test",
     "name": "shop.example.test",
     "kind": "host",
     "depth": 1,
     "from": "service:shop.example.test:443",
     "confidence": "inferred",
     "why": "injected code runs with this service's privileges on its host"
    },
    {
     "asset_id": "host:billing.internal.example.test",
     "name": "billing.internal.example.test",
     "kind": "host",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "calls",
     "confidence": "assumed",
     "why": "reachable from the compromised service's network position"
    },
    {
     "asset_id": "orders-db",
     "name": "Orders database",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the compromised service can already read this data store",
     "data_classes": [
      "payment",
      "pii"
     ]
    },
    {
     "asset_id": "payments-key",
     "name": "Payments API key",
     "kind": "identity",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "authenticates_with",
     "confidence": "inferred",
     "why": "the compromised service holds this credential",
     "data_classes": [
      "credentials"
     ]
    },
    {
     "asset_id": "sessions",
     "name": "Session cache",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the compromised service can already read this data store",
     "data_classes": [
      "auth"
     ]
    },
    {
     "asset_id": "ledger",
     "name": "Billing ledger",
     "kind": "datastore",
     "depth": 3,
     "from": "host:billing.internal.example.test",
     "via": "reads",
     "confidence": "assumed",
     "why": "readable if the attacker moves on to the called service",
     "data_classes": [
      "financial"
     ]
    }
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 86,
   "summary": "From https://shop.example.test:443, code execution reaches 6 further asset(s), including data classed auth, credentials, financial, payment, pii."
  },
  {
   "finding_id": "demo-sqli",
   "capability": "data_access",
   "capability_basis": "scanner classification CWE-89",
   "origin_id": "endpoint:https://shop.example.test/orders",
   "reach": [
    {
     "asset_id": "endpoint:https://shop.example.test/orders",
     "name": "https://shop.example.test/orders",
     "kind": "endpoint",
     "depth": 0,
     "confidence": "proven",
     "why": "the finding was reproduced here"
    },
    {
     "asset_id": "host:shop.example.test",
     "name": "shop.example.test",
     "kind": "host",
     "depth": 1,
     "from": "endpoint:https://shop.example.test/orders",
     "confidence": "inferred",
     "why": "queries run with this service's database access"
    },
    {
     "asset_id": "service:shop.example.test:443",
     "name": "https://shop.example.test:443",
     "kind": "service",
     "depth": 1,
     "from": "endpoint:https://shop.example.test/orders",
     "confidence": "inferred",
     "why": "queries run with this service's database access"
    },
    {
     "asset_id": "orders-db",
     "name": "Orders database",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the injectable service reads this data store",
     "data_classes": [
      "payment",
      "pii"
     ]
    },
    {
     "asset_id": "sessions",
     "name": "Session cache",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the injectable service reads this data store",
     "data_classes": [
      "auth"
     ]
    }
   ],
   "data_classes": [
    "auth",
    "payment",
    "pii"
   ],
   "score": 80,
   "summary": "From https://shop.example.test/orders, data access reaches 4 further asset(s), including data classed auth, payment, pii."
  },
  {
   "finding_id": "demo-env",
   "capability": "credential_exposure",
   "capability_basis": "values in the response look like credentials (taken from the target's own output, so unverified)",
   "origin_id": "endpoint:https://staging.shop.example.test/.env",
   "reach": [
    {
     "asset_id": "endpoint:https://staging.shop.example.test/.env",
     "name": "https://staging.shop.example.test/.env",
     "kind": "endpoint",
     "depth": 0,
     "confidence": "proven",
     "why": "the finding was reproduced here"
    },
    {
     "asset_id": "host:staging.shop.example.test",
     "name": "staging.shop.example.test",
     "kind": "host",
     "depth": 1,
     "from": "endpoint:https://staging.shop.example.test/.env",
     "confidence": "inferred",
     "why": "the exposed credential belongs to this service"
    },
    {
     "asset_id": "service:staging.shop.example.test:443",
     "name": "https://staging.shop.example.test:443",
     "kind": "service",
     "depth": 1,
     "from": "endpoint:https://staging.shop.example.test/.env",
     "confidence": "inferred",
     "why": "the exposed credential belongs to this service"
    },
    {
     "asset_id": "payments-key",
     "name": "Payments API key",
     "kind": "identity",
     "depth": 2,
     "from": "host:staging.shop.example.test",
     "via": "authenticates_with",
     "confidence": "inferred",
     "why": "this credential may be the one exposed",
     "data_classes": [
      "credentials"
     ]
    }
   ],
   "data_classes": [
    "credentials"
   ],
   "score": 60,
   "summary": "From https://staging.shop.example.test/.env, credential exposure reaches 3 further asset(s), including data classed credentials."
  },
  {
   "finding_id": "demo-cmdi",
   "capability": "code_execution",
   "capability_basis": "scanner classification CWE-78",
   "origin_id": "endpoint:https://shop.example.test/exports",
   "reach": [
    {
     "asset_id": "endpoint:https://shop.example.test/exports",
     "name": "https://shop.example.test/exports",
     "kind": "endpoint",
     "depth": 0,
     "confidence": "assumed",
     "why": "reported by the scanner but not confirmed"
    },
    {
     "asset_id": "host:shop.example.test",
     "name": "shop.example.test",
     "kind": "host",
     "depth": 1,
     "from": "endpoint:https://shop.example.test/exports",
     "confidence": "inferred",
     "why": "injected code runs with this service's privileges on its host"
    },
    {
     "asset_id": "service:shop.example.test:443",
     "name": "https://shop.example.test:443",
     "kind": "service",
     "depth": 1,
     "from": "endpoint:https://shop.example.test/exports",
     "confidence": "inferred",
     "why": "injected code runs with this service's privileges on its host"
    },
    {
     "asset_id": "host:billing.internal.example.test",
     "name": "billing.internal.example.test",
     "kind": "host",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "calls",
     "confidence": "assumed",
     "why": "reachable from the compromised service's network position"
    },
    {
     "asset_id": "orders-db",
     "name": "Orders database",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the compromised service can already read this data store",
     "data_classes": [
      "payment",
      "pii"
     ]
    },
    {
     "asset_id": "payments-key",
     "name": "Payments API key",
     "kind": "identity",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "authenticates_with",
     "confidence": "inferred",
     "why": "the compromised service holds this credential",
     "data_classes": [
      "credentials"
     ]
    },
    {
     "asset_id": "sessions",
     "name": "Session cache",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "inferred",
     "why": "the compromised service can already read this data store",
     "data_classes": [
      "auth"
     ]
    },
    {
     "asset_id": "ledger",
     "name": "Billing ledger",
     "kind": "datastore",
     "depth": 3,
     "from": "host:billing.internal.example.test",
     "via": "reads",
     "confidence": "assumed",
     "why": "readable if the attacker moves on to the called service",
     "data_classes": [
      "financial"
     ]
    }
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 54,
   "summary": "From https://shop.example.test/exports, code execution reaches 7 further asset(s), including data classed auth, credentials, financial, payment, pii."
  },
  {
   "finding_id": "demo-secret",
   "capability": "credential_exposure",
   "capability_basis": "scanner classification CWE-798",
   "origin_id": "service:shop.example.test:443",
   "reach": [
    {
     "asset_id": "service:shop.example.test:443",
     "name": "https://shop.example.test:443",
     "kind": "service",
     "depth": 0,
     "confidence": "assumed",
     "why": "reported by the scanner but not confirmed"
    },
    {
     "asset_id": "host:shop.example.test",
     "name": "shop.example.test",
     "kind": "host",
     "depth": 1,
     "from": "service:shop.example.test:443",
     "confidence": "inferred",
     "why": "the exposed credential belongs to this service"
    },
    {
     "asset_id": "orders-db",
     "name": "Orders database",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "assumed",
     "why": "an exposed credential may grant the same access the service has",
     "data_classes": [
      "payment",
      "pii"
     ]
    },
    {
     "asset_id": "payments-key",
     "name": "Payments API key",
     "kind": "identity",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "authenticates_with",
     "confidence": "inferred",
     "why": "this credential may be the one exposed",
     "data_classes": [
      "credentials"
     ]
    },
    {
     "asset_id": "sessions",
     "name": "Session cache",
     "kind": "datastore",
     "depth": 2,
     "from": "host:shop.example.test",
     "via": "reads",
     "confidence": "assumed",
     "why": "an exposed credential may grant the same access the service has",
     "data_classes": [
      "auth"
     ]
    }
   ],
   "data_classes": [
    "auth",
    "credentials",
    "payment",
    "pii"
   ],
   "score": 38,
   "summary": "From https://shop.example.test:443, credential exposure reaches 4 further asset(s), including data classed auth, credentials, payment, pii."
  },
  {
   "finding_id": "demo-xss",
   "capability": "client_side",
   "capability_basis": "scanner classification CWE-79",
   "origin_id": "endpoint:https://shop.example.test/search",
   "reach": [
    {
     "asset_id": "endpoint:https://shop.example.test/search",
     "name": "https://shop.example.test/search",
     "kind": "endpoint",
     "depth": 0,
     "confidence": "assumed",
     "why": "reported by the scanner but not confirmed"
    }
   ],
   "data_classes": [],
   "score": 13,
   "summary": "Limited to https://shop.example.test/search (client side)."
  },
  {
   "finding_id": "demo-dep-lodash",
   "capability": "unclassified",
   "capability_basis": "the scanner gave no CWE or recognised tag, so only the affected asset is counted",
   "origin_id": "",
   "reach": [],
   "data_classes": [],
   "score": 0,
   "summary": "The affected asset is not in the asset graph, so no reach was computed."
  },
  {
   "finding_id": "demo-admin",
   "capability": "auth_bypass",
   "capability_basis": "scanner classification CWE-306",
   "origin_id": "endpoint:https://shop.example.test/admin",
   "reach": [
    {
     "asset_id": "endpoint:https://shop.example.test/admin",
     "name": "https://shop.example.test/admin",
     "kind": "endpoint",
     "depth": 0,
     "confidence": "assumed",
     "why": "reported by the scanner but not confirmed"
    }
   ],
   "data_classes": [],
   "score": 0,
   "summary": "No blast radius: this finding was refuted."
  },
  {
   "finding_id": "demo-flaky",
   "capability": "client_side",
   "capability_basis": "scanner classification CWE-601",
   "origin_id": "endpoint:https://shop.example.test/logout",
   "reach": [
    {
     "asset_id": "endpoint:https://shop.example.test/logout",
     "name": "https://shop.example.test/logout",
     "kind": "endpoint",
     "depth": 0,
     "confidence": "assumed",
     "why": "reported by the scanner but not confirmed"
    }
   ],
   "data_classes": [],
   "score": 0,
   "summary": "No blast radius: this finding was refuted."
  },
  {
   "finding_id": "demo-cdn",
   "capability": "unclassified",
   "capability_basis": "the scanner gave no CWE or recognised tag, so only the affected asset is counted",
   "origin_id": "service:assets.cdn-provider.example.test:443",
   "reach": [
    {
     "asset_id": "service:assets.cdn-provider.example.test:443",
     "name": "https://assets.cdn-provider.example.test:443",
     "kind": "service",
     "depth": 0,
     "confidence": "assumed",
     "why": "reported by the scanner but not confirmed"
    }
   ],
   "data_classes": [],
   "score": 0,
   "summary": "No blast radius: this finding was out of scope."
  }
 ],
 "chains": [
  {
   "steps": [
    {
     "finding_id": "demo-env",
     "title": "Environment file served over HTTP",
     "capability": "credential_exposure",
     "origin_id": "endpoint:https://staging.shop.example.test/.env",
     "why": "The chain starts with credential exposure on https://staging.shop.example.test/.env."
    },
    {
     "finding_id": "demo-code-cmdi",
     "title": "python command injection",
     "capability": "code_execution",
     "origin_id": "service:shop.example.test:443",
     "via": "payments-key",
     "why": "The previous step can leak the credential Payments API key, which belongs to shop.example.test, where this finding is."
    }
   ],
   "reach": [
    "endpoint:https://staging.shop.example.test/.env",
    "host:billing.internal.example.test",
    "host:shop.example.test",
    "host:staging.shop.example.test",
    "ledger",
    "orders-db",
    "payments-key",
    "service:shop.example.test:443",
    "service:staging.shop.example.test:443",
    "sessions"
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 100,
   "summary": "2 findings combine: Environment file served over HTTP -> python command injection; together they reach 10 assets including data classed auth, credentials, financial, payment, pii."
  },
  {
   "steps": [
    {
     "finding_id": "demo-env",
     "title": "Environment file served over HTTP",
     "capability": "credential_exposure",
     "origin_id": "endpoint:https://staging.shop.example.test/.env",
     "why": "The chain starts with credential exposure on https://staging.shop.example.test/.env."
    },
    {
     "finding_id": "demo-rce",
     "title": "Server-side template injection in invoice preview",
     "capability": "code_execution",
     "origin_id": "endpoint:https://shop.example.test/invoices/preview",
     "via": "payments-key",
     "why": "The previous step can leak the credential Payments API key, which belongs to shop.example.test, where this finding is."
    }
   ],
   "reach": [
    "endpoint:https://shop.example.test/invoices/preview",
    "endpoint:https://staging.shop.example.test/.env",
    "host:billing.internal.example.test",
    "host:shop.example.test",
    "host:staging.shop.example.test",
    "ledger",
    "orders-db",
    "payments-key",
    "service:shop.example.test:443",
    "service:staging.shop.example.test:443",
    "sessions"
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 100,
   "summary": "2 findings combine: Environment file served over HTTP -> Server-side template injection in invoice preview; together they reach 11 assets including data classed auth, credentials, financial, payment, pii."
  },
  {
   "steps": [
    {
     "finding_id": "demo-env",
     "title": "Environment file served over HTTP",
     "capability": "credential_exposure",
     "origin_id": "endpoint:https://staging.shop.example.test/.env",
     "why": "The chain starts with credential exposure on https://staging.shop.example.test/.env."
    },
    {
     "finding_id": "demo-sqli",
     "title": "SQL injection in order lookup",
     "capability": "data_access",
     "origin_id": "endpoint:https://shop.example.test/orders",
     "via": "payments-key",
     "why": "The previous step can leak the credential Payments API key, which belongs to shop.example.test, where this finding is."
    },
    {
     "finding_id": "demo-code-cmdi",
     "title": "python command injection",
     "capability": "code_execution",
     "origin_id": "service:shop.example.test:443",
     "via": "service:shop.example.test:443",
     "why": "The previous step reaches https://shop.example.test:443, the asset this finding is on."
    }
   ],
   "reach": [
    "endpoint:https://shop.example.test/orders",
    "endpoint:https://staging.shop.example.test/.env",
    "host:billing.internal.example.test",
    "host:shop.example.test",
    "host:staging.shop.example.test",
    "ledger",
    "orders-db",
    "payments-key",
    "service:shop.example.test:443",
    "service:staging.shop.example.test:443",
    "sessions"
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 100,
   "summary": "3 findings combine: Environment file served over HTTP -> SQL injection in order lookup -> python command injection; together they reach 11 assets including data classed auth, credentials, financial, payment, pii."
  },
  {
   "steps": [
    {
     "finding_id": "demo-env",
     "title": "Environment file served over HTTP",
     "capability": "credential_exposure",
     "origin_id": "endpoint:https://staging.shop.example.test/.env",
     "why": "The chain starts with credential exposure on https://staging.shop.example.test/.env."
    },
    {
     "finding_id": "demo-sqli",
     "title": "SQL injection in order lookup",
     "capability": "data_access",
     "origin_id": "endpoint:https://shop.example.test/orders",
     "via": "payments-key",
     "why": "The previous step can leak the credential Payments API key, which belongs to shop.example.test, where this finding is."
    },
    {
     "finding_id": "demo-rce",
     "title": "Server-side template injection in invoice preview",
     "capability": "code_execution",
     "origin_id": "endpoint:https://shop.example.test/invoices/preview",
     "via": "service:shop.example.test:443",
     "why": "The previous step reaches https://shop.example.test:443, which contains the asset this finding is on."
    }
   ],
   "reach": [
    "endpoint:https://shop.example.test/invoices/preview",
    "endpoint:https://shop.example.test/orders",
    "endpoint:https://staging.shop.example.test/.env",
    "host:billing.internal.example.test",
    "host:shop.example.test",
    "host:staging.shop.example.test",
    "ledger",
    "orders-db",
    "payments-key",
    "service:shop.example.test:443",
    "service:staging.shop.example.test:443",
    "sessions"
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 100,
   "summary": "3 findings combine: Environment file served over HTTP -> SQL injection in order lookup -> Server-side template injection in invoice preview; together they reach 12 assets including data classed auth, credentials, financial, payment, pii."
  },
  {
   "steps": [
    {
     "finding_id": "demo-sqli",
     "title": "SQL injection in order lookup",
     "capability": "data_access",
     "origin_id": "endpoint:https://shop.example.test/orders",
     "why": "The chain starts with data access on https://shop.example.test/orders."
    },
    {
     "finding_id": "demo-code-cmdi",
     "title": "python command injection",
     "capability": "code_execution",
     "origin_id": "service:shop.example.test:443",
     "via": "service:shop.example.test:443",
     "why": "The previous step reaches https://shop.example.test:443, the asset this finding is on."
    }
   ],
   "reach": [
    "endpoint:https://shop.example.test/orders",
    "host:billing.internal.example.test",
    "host:shop.example.test",
    "ledger",
    "orders-db",
    "payments-key",
    "service:shop.example.test:443",
    "sessions"
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 100,
   "summary": "2 findings combine: SQL injection in order lookup -> python command injection; together they reach 8 assets including data classed auth, credentials, financial, payment, pii."
  },
  {
   "steps": [
    {
     "finding_id": "demo-sqli",
     "title": "SQL injection in order lookup",
     "capability": "data_access",
     "origin_id": "endpoint:https://shop.example.test/orders",
     "why": "The chain starts with data access on https://shop.example.test/orders."
    },
    {
     "finding_id": "demo-rce",
     "title": "Server-side template injection in invoice preview",
     "capability": "code_execution",
     "origin_id": "endpoint:https://shop.example.test/invoices/preview",
     "via": "service:shop.example.test:443",
     "why": "The previous step reaches https://shop.example.test:443, which contains the asset this finding is on."
    }
   ],
   "reach": [
    "endpoint:https://shop.example.test/invoices/preview",
    "endpoint:https://shop.example.test/orders",
    "host:billing.internal.example.test",
    "host:shop.example.test",
    "ledger",
    "orders-db",
    "payments-key",
    "service:shop.example.test:443",
    "sessions"
   ],
   "data_classes": [
    "auth",
    "credentials",
    "financial",
    "payment",
    "pii"
   ],
   "score": 100,
   "summary": "2 findings combine: SQL injection in order lookup -> Server-side template injection in invoice preview; together they reach 9 assets including data classed auth, credentials, financial, payment, pii."
  }
 ],
 "reach": {
  "allowed": [
   {
    "target": "shop.example.test:443",
    "count": 412
   },
   {
    "target": "staging.shop.example.test:443",
    "count": 38
   }
  ],
  "denied": [
   {
    "target": "assets.cdn-provider.example.test:443",
    "count": 9,
    "reason": "host is not in scope"
   },
   {
    "target": "169.254.169.254:80",
    "count": 3,
    "reason": "address range can never be a target"
   },
   {
    "target": "updates.scanner-vendor.example.test:443",
    "count": 2,
    "reason": "host is not in scope"
   }
  ],
  "allowed_total": 450,
  "denied_total": 14
 }
};
