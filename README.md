# Vajra

Security testing that proves its findings.

Vajra runs scanners against applications you are authorised to test, then tries
to disprove every result before it reports one. A finding is `confirmed` only
after it was reproduced and survived an independent review. The aim is a short
list of true issues with evidence, not thousands of alerts.

> Status: early. The gated core and the verification pipeline exist and are
> unit-tested. The web UI, blast-radius view and report formats are planned;
> see [PLAN.md](PLAN.md).

## How it works

```
vajra scan ──> scanner in a sandbox ──> candidates
                     │                       │
              internal network        evidence check
                     │                 scope check
               egress gate             reproduction (re-run, must match every time)
              (scope + audit)          refutation (a model tries to disprove it)
                     │                       │
                  targets          confirmed | refuted | unconfirmed | out_of_scope
```

- **Scope is enforced by the network.** Task containers sit on a Docker network
  with no route out. The only peer is the egress gate, which allows a
  connection only when the host, port and every resolved address are in scope.
- **Deny by default.** No scope, no budget or no authorisation statement means
  the run does not start.
- **One throwaway container per tool run.** Read-only root, no capabilities, no
  host environment, non-root user, memory, process and time limits.
- **Nothing is silently dropped.** Refuted and unconfirmed findings stay in the
  report with the reason.

## Requirements

- Go 1.27 or newer
- Docker

## Quick start

```bash
# 1. Build the CLI
go build -o vajra ./cmd/vajra

# 2. Describe the run: who authorised it, what is in scope, the limits
cp examples/run.json run.local.json      # then edit it

# 3. Build the scanner image and start the egress gate
docker build -t vajra-nuclei:local -f deploy/nuclei.Dockerfile deploy
VAJRA_CONFIG="$PWD/run.local.json" docker compose -f deploy/docker-compose.yml up -d --build

# 4. Scan and verify
export ANTHROPIC_API_KEY=...             # only if refuter.provider is "anthropic"
./vajra scan -config run.local.json -out report.json
```

Restart the gate after changing the scope: it reads the configuration once at
start.

## Commands

| Command | What it does |
|---|---|
| `vajra scan -config FILE` | Scan the configured targets, then verify each result |
| `vajra verify -config FILE -in OUTPUT.jsonl` | Verify nuclei JSONL output saved earlier |
| `vajra gate -config FILE` | Run the egress gate (normally started by Docker Compose) |

`-out FILE` writes the report to a file (mode 0600) instead of standard output.
`-fail-on-confirmed` exits with status 3 when any finding is confirmed, for use
in CI.

## Configuration

See [examples/run.json](examples/run.json). Every section is required except
`verify` and `refuter`.

| Section | Purpose |
|---|---|
| `authorization` | Who approved the test. Copied into every report. |
| `scope` | Allowed hosts (`app.example.com`, `*.staging.example.com`), CIDRs and ports. Ports default to 80 and 443. |
| `budget` | Hard caps on model tokens, model turns, sandbox runs and wall-clock time. All four are mandatory. |
| `targets` | URLs to scan. Each must be inside `scope`. |
| `sandbox` | The internal Docker network and the gate's address on it. |
| `nuclei` | Scanner image, template directory, timeout and request rate. |
| `verify` | `reproduce_attempts` (default 2, maximum 5). |
| `refuter` | `provider` is `anthropic` or `none`. With `none`, nothing can be confirmed. |

Scope rules worth knowing:

- Loopback, link-local (including cloud metadata) and multicast addresses can
  never be targets, even if listed.
- Private addresses are allowed only when a listed CIDR covers them.
- An IP-literal target must fall inside a listed CIDR.
- The API key is read from an environment variable and never from the file.

## Finding statuses

| Status | Meaning |
|---|---|
| `confirmed` | Reproduced on every attempt and survived refutation |
| `refuted` | Did not reproduce, or the evidence does not support the claim |
| `unconfirmed` | Could not be decided: missing evidence, tool error, reviewer unsure, or budget spent |
| `out_of_scope` | The result names a target outside the scope; it was not re-tested |

## Development

```bash
go vet ./...
go test ./... -race -cover
```

## Authorised use only

Test only systems you own or have written permission to test. Vajra records the
authorisation statement and operator in every report.
