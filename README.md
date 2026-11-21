# Vajra

Security testing that proves its findings.

Vajra tests applications you are authorised to test, then tries to disprove
every result before it reports one. A finding is `confirmed` only after it was
reproduced and survived an independent review. The aim is a short list of true
issues with evidence, ranked by what an attacker could reach from each one.

> Status: young. Every feature below is built and unit-tested, and
> `scripts/e2e.sh` runs the core of it against lab targets in Docker. Some
> parts have not yet been exercised against real systems; see
> [What has and has not been verified](#what-has-and-has-not-been-verified).
> The roadmap is in [PLAN.md](PLAN.md); to help, see
> [CONTRIBUTING.md](CONTRIBUTING.md).

## What it does

| Check | How |
|---|---|
| Live scanning | nuclei, inside a sandbox, optionally as a test account |
| Access control | The same request as every test account; reports who is served what they should not be |
| API | Operations an OpenAPI description marks as protected are requested without credentials |
| GraphQL | Whether anyone can read the schema, and whether queries are answered without credentials |
| Ports | Services listening on ports you did not expect, tried through the gate |
| Discovery | Sub-domains under wildcard scope entries; link-following crawl of the targets; pages imported from a browser recording |
| Code | Semgrep with no network over a read-only copy of the source |
| Secrets | Built-in search for hard-coded credentials; values are masked everywhere |
| Dependencies | Pinned packages checked against the OSV advisory database (opt-in) |
| Exploration | A model that decides what to try next, limited to gated tools and evidence-bound reports |

Everything found goes through the same verification, and then:

- **Blast radius:** what each finding reaches, with a confidence on every step.
- **Attack chains:** confirmed findings that combine into a longer path.
- **Corroboration:** a code finding and a live finding that show the same
  weakness on the same service point at each other.

## How it stays safe

- **Scope is enforced by the network.** Task containers sit on a Docker network
  with no route out. The only peer is the egress gate, which allows a
  connection only when the host, port and every resolved address are in scope.
  Vajra checks that the network really is internal before every run.
- **Deny by default.** No scope, no budget or no authorisation statement means
  the run does not start.
- **One throwaway container per tool run.** Read-only root, no capabilities, no
  host environment, non-root user, memory, process and time limits.
- **Vajra's own requests are sandboxed too.** Access checks, API tests, the
  crawler and the explorer send requests through a probe that runs inside the
  sandbox, behind the same gate.
- **Hard budgets.** Model tokens, model turns, sandbox runs and wall-clock time
  are all capped, and the time limit cuts off running tools.
- **Nothing is silently dropped.** Refuted and unconfirmed findings stay in the
  report with the reason.
- **Credentials stay out of reports.** Test-account credentials are removed by
  value from everything stored or shown to a model, even when a target echoes
  them back. They reach the scanner on standard input, never on a command
  line, and are sent only to the targets you listed, not to hosts that
  discovery turns up. Found secrets are masked.
- **An interrupted run is an error.** A run that was cut short exits non-zero
  and is not saved, so it cannot be mistaken for a clean result.

## Requirements

- Go 1.27 or newer
- Docker

## Quick start

```bash
make build images                        # the CLI and the three container images

cp examples/run.json run.local.json      # then edit: who authorised it, scope, limits

mkdir -p data/audit                      # the gate writes its audit log here
VAJRA_UID=$(id -u) VAJRA_GID=$(id -g) \
  VAJRA_CONFIG="$PWD/run.local.json" VAJRA_AUDIT_DIR="$PWD/data/audit" \
  docker compose -f deploy/docker-compose.yml up -d --build

export ANTHROPIC_API_KEY=...             # only if refuter.provider is "anthropic"
./vajra scan -config run.local.json -data data -gate-audit data/audit/audit.jsonl

./vajra serve -data data                 # look at the result in a browser
```

To look around without scanning anything: `./vajra demo -data data` and then
`./vajra serve -data data`.

`scripts/e2e.sh` does the whole flow against throwaway lab targets and checks
the result. Restart the gate after changing the scope: it reads the
configuration once at start.

## Configuration

One JSON file describes a run. [examples/run.json](examples/run.json) is a
minimal one and [examples/full.json](examples/full.json) uses every section.
Unknown fields are rejected, so a misspelt setting is never silently ignored.

| Section | Purpose |
|---|---|
| `authorization` | Who approved the test. Always required; copied into every report. |
| `budget` | Caps on model tokens, model turns, sandbox runs and seconds. Always required. |
| `scope` | Allowed hosts (`app.example.com`, `*.staging.example.com`), CIDRs and ports (default 80 and 443). |
| `targets` | URLs to scan. Each must be inside `scope`. |
| `sandbox` | The internal Docker network and the gate's address on it. |
| `nuclei` | Scanner image, template directory, timeout, request rate. |
| `probe` | Image and timeout for Vajra's own HTTP client. Needed by `auth`, `api`, `crawl` and `agent`. |
| `auth` | Test accounts, which one the scanner uses, and access rules to check. |
| `api` | An OpenAPI 3 JSON file and the base URL to test it against. |
| `graphql` | A GraphQL endpoint to check. |
| `ports` | Hosts and ports to try, and which ports are expected to be open. |
| `crawl` | Page and depth limits for link-following discovery. |
| `recording` | A browser recording (HAR file) whose in-scope pages are added to the scan: `{"path": "session.har", "max_targets": 200}`. For single-page applications and screens behind a login, which link-following cannot reach. Every address in the file is checked against the scope; cookies, credentials and body values in it are discarded; requests that change state are counted, not replayed. |
| `recon` | Limits for discovering hosts under wildcard scope entries. |
| `source` | A source tree and which analyses to run on it. |
| `agent` | The autonomous explorer: step limit, goal, and what to do about risky requests. |
| `verify` | `reproduce_attempts` (default 2, maximum 5). |
| `refuter` | The reviewer: `anthropic` or `none`, and an optional second model. |
| `topology` | What the targets connect to; feeds the blast radius. |
| `notify` | A webhook that receives a short summary of each run. |

A run needs `targets`, `source`, or one of the other live checks. A run that
only analyses code needs no scope, gate or scanner settings, because nothing
touches a network.

Scope rules worth knowing:

- Loopback, link-local (including cloud metadata), multicast and addresses
  that embed an IPv4 address inside IPv6 can never be targets, even if listed.
- Private addresses are allowed only when a listed CIDR covers them.
- An IP-literal target must fall inside a listed CIDR.

### Test accounts and access rules

```json
"probe": {"image": "vajra:local", "timeout_seconds": 120},
"auth": {
  "identities": [
    {"name": "admin", "headers_env": {"Authorization": "SHOP_ADMIN_TOKEN"}},
    {"name": "user",  "headers_env": {"Authorization": "SHOP_USER_TOKEN"}}
  ],
  "scan_as": "user",
  "access_checks": [
    {"name": "User administration", "url": "https://app.example.com/admin/users", "allow": ["admin"]}
  ]
}
```

Credentials are read from the named environment variables at run time and
never appear in the file or in a report. Each access check is requested as
every account and as an anonymous visitor; anyone outside `allow` who is
served the resource is reported. Only `GET`, `HEAD` and `OPTIONS` are used,
because a check is repeated once per account.

### API description

```json
"api": {"spec": "/absolute/path/openapi.json", "base_url": "https://app.example.com", "params": {"id": "42"}}
```

Every read-only operation the description marks as needing authentication is
requested without any. Operations that could change data are never sent and
are listed in the report as skipped. The file must be JSON; convert YAML first.

### GraphQL and ports

```json
"graphql": {"endpoint": "https://app.example.com/graphql", "requires_auth": true},
"sandbox": {"network": "vajra-task-net", "proxy_url": "http://gate:3128", "socks_addr": "gate:1080"},
"ports": {"hosts": ["app.example.com"], "ports": [443, 5432, 6379], "expected": [443], "timeout_seconds": 60}
```

The GraphQL check sends two read-only queries without credentials and reports
when the schema is readable by anyone or, with `requires_auth`, when queries
are answered at all.

Port discovery opens a TCP connection to each host and port and reports the
open ones that are not in `expected`. It sends nothing and reads nothing. It
connects through the gate's SOCKS5 front end (start the gate with `-socks`),
so only ports listed in `scope` can be tried, and the gate logs each attempt.
An open port is a plain fact, so it is confirmed by a second connection
without a reviewer.

### Source analysis

```json
"source": {
  "root": "/absolute/path/to/checkout",
  "serves": "https://app.example.com",
  "semgrep": {"image": "vajra-semgrep:local", "rules_host_dir": "/absolute/path/to/vajra/rules/starter", "timeout_seconds": 900},
  "secrets": true,
  "dependencies": {"osv": true}
}
```

- `serves` names the running service the code belongs to, so code findings
  get a blast radius and can corroborate live ones.
- Semgrep rules are never downloaded during a scan. `rules/starter` holds a
  few precise Python rules; point `rules_host_dir` at your own set.
- `dependencies.osv` sends the names and versions of your pinned packages,
  and nothing else, to the public OSV service. It is off unless you set it.
  A dependency finding states a fact (this version is pinned, this advisory
  covers it); it does not claim the flaw is reachable.

### Autonomous explorer

```json
"agent": {"max_steps": 40, "goal": "Look at the order and invoice endpoints.", "unsafe_requests": "deny"}
```

The explorer can only call three tools: send a request (through the gate),
report a weakness, and finish. A report must name an exchange it actually
made and a pattern that the recorded response matches, so it cannot report
something it merely believes. Its reports are re-tested and reviewed like any
other. Requests that could change data are refused unless `unsafe_requests`
is `"ask"`, in which case you are shown the method, URL, header names and body
on the terminal and asked each time. Headers that make a server treat a
request as another method are always refused.

`vajra pause -data DIR` makes an exploration wait after its current step,
`vajra resume` lets it continue, and `vajra stop` ends it. The run's time
limit keeps counting while it is paused.

### A second reviewer

```json
"refuter": {"provider": "anthropic", "model": "claude-opus-5-5", "second_model": "claude-sonnet-5-5", "second_min_severity": "high"}
```

Findings at or above the given severity are confirmed only when both models
hold them. A disagreement leaves the finding `unconfirmed` for a person.

### Blast radius and topology

Vajra can see hosts, services and endpoints for itself. It cannot see what
sits behind them, so you declare that:

```json
"topology": {
  "assets": [{"id": "orders-db", "kind": "datastore", "name": "Orders database", "data_classes": ["pii", "payment"]}],
  "links": [{"from": "app.example.com", "to": "orders-db", "relation": "reads"}]
}
```

Asset kinds: `host`, `service`, `datastore`, `identity`, `external`.
Relations: `reads`, `calls`, `authenticates_with`, `hosts`.

Each finding gets a score from 0 to 100 and a list of what it reaches. The
reach depends on the kind of weakness: code execution spreads to the host and
everything the service can read; SQL injection reaches the data stores the
service reads; cross-site scripting stays where it is. Every step carries a
confidence: `proven`, `inferred` or `assumed`. The score is an ordering aid,
not a measurement.

## Finding statuses

| Status | Meaning |
|---|---|
| `confirmed` | Reproduced on every attempt and survived review |
| `refuted` | Did not reproduce while the target was answering, or the evidence does not support the claim |
| `unconfirmed` | Could not be decided: missing evidence, tool error, target not answering, reviewer unsure or unavailable, reviewers disagree, or budget spent |
| `out_of_scope` | The result names a target outside the scope; it was not re-tested |

## Commands

| Command | What it does |
|---|---|
| `vajra scan -config FILE` | Run every enabled check, then verify each result |
| `vajra verify -config FILE -in OUTPUT.jsonl` | Verify nuclei output saved earlier |
| `vajra gate -config FILE [-socks ADDR]` | Run the egress gate (HTTP proxy, optionally SOCKS5 for raw TCP tools) |
| `vajra pause`, `resume`, `stop` `-data DIR` | Pause, continue or end a running exploration |
| `vajra cleanup` | Remove sandbox containers left by an interrupted run |
| `vajra runs -data DIR` | List saved runs |
| `vajra report -data DIR -run ID` | Render a run as `html`, `md` or `json` |
| `vajra serve -data DIR` | Web interface over saved runs, on this machine only |
| `vajra diff -data DIR -base ID -head ID` | What changed between two runs |
| `vajra bench -data DIR -run ID -key FILE` | Score a run against an answer key |
| `vajra exposure -data DIR -run ID` | New advisories for a run's recorded dependencies |
| `vajra fix -config FILE -data DIR -run ID -finding ID` | Propose a patch for a code finding and re-check it |
| `vajra ticket -data DIR -run ID -finding ID` | Write one finding as a Markdown issue, or file it in GitHub or Jira |
| `vajra keygen`, `sign`, `verify-signature` | Sign reports and check signatures |
| `vajra demo -data DIR` | Save a sample run to explore |

Flags for `scan` and `verify`:

- `-data DIR` saves the run, with its asset graph, blast radii and chains.
- `-gate-audit FILE` adds the gate's audit log, so the report shows what the
  run touched and what it was refused.
- `-out FILE` writes the findings as JSON (mode 0600).
- `-baseline RUN -fail-on-new` compares with an earlier run and exits with
  status 3 only when something new needs attention.
- `-fail-on-confirmed` exits with status 3 when any finding is confirmed.
- `-notify` posts a summary to the configured webhook.

### Filing tickets

Without `-file`, `vajra ticket` prints the issue for you to paste. With it,
the issue is filed for you:

```bash
VAJRA_GITHUB_TOKEN=... ./vajra ticket -data data -run RUN_ID -finding ID -file github -repo acme/shop
VAJRA_JIRA_EMAIL=you@example.com VAJRA_JIRA_TOKEN=... \
  ./vajra ticket -data data -run RUN_ID -finding ID \
  -file jira -jira-url https://example.atlassian.net -jira-project SEC [-jira-type Bug]
```

- Only `confirmed` findings are filed; `-force` files one with another status.
- Filing is idempotent. The ticket carries the line `vajra-finding: ID`
  (and, in Jira, the label `vajra-ID`); if a ticket with that marker already
  exists, open or closed, it is reported and nothing new is filed. GitHub's
  search index lags by a few seconds, so filing the same finding twice in
  quick succession can still make two issues.
- Credentials are read only from the environment, never from flags, and never
  appear in errors. The API must be https (plain http only to a loopback
  address), redirects are not followed, and replies are size-capped.
- Jira descriptions hold the Markdown in a code block, unconverted.

## Continuous testing

Keep the ID of the last run you accepted, and compare each new run with it:

```bash
./vajra scan -config run.json -data data -baseline "$(cat baseline-run-id)" -fail-on-new
./vajra exposure -data data -run "$(cat baseline-run-id)"   # advisories published since
```

[examples/continuous.yml](examples/continuous.yml) is a pipeline that does
this on every push and nightly.

## Measuring accuracy

An answer key lists what a target is known to have, and decoys it must not
report:

```bash
./vajra bench -data data -run RUN_ID -key bench/lab.json -min-precision 1 -min-recall 1
```

`kind` in a key takes `dast`, `sast` or `sca`. [bench/lab.json](bench/lab.json)
is the key for the lab that `scripts/e2e.sh` builds.

## Fixing a code finding

```bash
./vajra fix -config run.json -data data -run RUN_ID -finding FINDING_ID -out fix.patch
```

A model proposes a change, Vajra applies it to a throwaway copy of the file
and re-runs the rule there. Your source tree is never modified. The patch is
called verified only when the rule no longer fires; review it before applying.

## Signing reports

```bash
./vajra keygen -private vajra.key -public vajra.pub
./vajra report -data data -run RUN_ID -format html -out report.html
./vajra sign -in report.html -key vajra.key
./vajra verify-signature -in report.html -sig report.html.sig -public vajra.pub
```

## What has and has not been verified

Verified by `scripts/e2e.sh` against lab targets in Docker:

- A task container cannot reach the internet or the target except through the
  gate; the gate refuses out-of-scope hosts and logs every decision.
- Live scanning finds and reproduces a planted exposure; a stale result is
  refuted when the target answers and left unconfirmed when it does not.
- Code analysis finds a planted injection and leaves the safe variant alone.
- Access checks, API tests, GraphQL checks and the secret search find planted
  flaws, and no credential or full secret reaches a report or a saved run.
- Port discovery finds an unexpected open port through the SOCKS5 gate and
  confirms it with a second connection.

Covered by unit tests only, not yet run against a real system:

- The model reviewer, the second reviewer, the autonomous explorer and the
  patch proposer. They are tested against a stand-in for the model API.
  `E2E_REFUTER=anthropic ./scripts/e2e.sh` runs the reviewer for real and
  scores it against the answer key; it needs a valid API key.
- Host discovery, crawling and dependency advisories.
- Blast-radius rules, scores and attack chains are heuristics that have not
  been calibrated against real incidents.

Two rounds of independent security review have been done, and their findings
fixed; the fixes from the second round have not themselves been re-reviewed.

Not built: browser-driven crawling (a recording made in your own browser can
be imported instead), business-logic checks, and user accounts and roles in
the web interface. Ticket filing to GitHub and Jira is tested only against
stand-ins for their APIs. The release workflow, which publishes checksummed
binaries and a signed container image when a version tag is pushed, has not
run yet.

## Development

```bash
make check     # gofmt, go vet, unit tests with the race detector
make e2e       # end-to-end against the lab (needs Docker)
make sbom      # software bill of materials for the binary
```

The binary has no third-party Go modules, and two builds of the same commit
are byte-identical. Base images are pinned by digest; `make digests` prints
the current ones when you want to update the pins.

## Authorised use only

Test only systems you own or have written permission to test. Vajra records
the authorisation statement and operator in every report.

## Licence

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
