#!/usr/bin/env bash
# End-to-end check against a local lab target.
#
# Builds the images, starts a lab web server that exposes a .git/config file,
# puts the egress gate in front of it, runs a real scan, and checks that:
#   1. the exposed file is found and reproduced,
#   2. a task container has no direct route out,
#   3. the gate refuses an out-of-scope host,
#   4. the gate wrote an audit log,
#   5. the saved run renders as reports with a blast radius,
#   6. a result that no longer reproduces is refuted only if the target answers,
#   7. code analysis finds a planted injection and ignores the safe variant,
#   8. access checks, API tests, GraphQL checks, port discovery and the secret
#      search find planted flaws, and no credential or full secret reaches a
#      report.
#
# Set E2E_REFUTER=anthropic (with ANTHROPIC_API_KEY) to also have a live model
# review the findings and to score the result against bench/lab.json.
#
# Set E2E_KEEP=/some/dir to keep the generated reports.
#
# Everything it creates is prefixed vajra-e2e and removed on exit.
set -euo pipefail

cd "$(dirname "$0")/.."

TASK_NET=vajra-e2e-tasks
LAB_NET=vajra-e2e-lab
OUT_NET=vajra-e2e-egress
LAB_SUBNET=172.31.250.0/24
GATE=vajra-e2e-gate
TARGET=vajra-e2e-target
WORK="$(mktemp -d)"
PROBE_IMAGE=busybox:1.36

cleanup() {
  docker rm -f "$GATE" "$TARGET" >/dev/null 2>&1 || true
  docker network rm "$TASK_NET" "$LAB_NET" "$OUT_NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
cleanup_networks_only() { docker network rm "$TASK_NET" "$LAB_NET" "$OUT_NET" >/dev/null 2>&1 || true; }

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

# retry runs a command up to three times. Building the scanner image downloads
# its templates, which now and then fails for reasons that have nothing to do
# with this repository.
retry() {
  local attempt
  for attempt in 1 2 3; do
    "$@" && return 0
    echo "attempt $attempt failed: $*" >&2
    sleep 5
  done
  return 1
}

# wait_for_target blocks until the lab web server answers through the gate.
# A container that has just been started is not listening yet, and a scan
# that begins too early would find nothing and blame the target.
wait_for_target() {
  local attempt
  for attempt in $(seq 1 40); do
    if docker run --rm --network "$TASK_NET" -e http_proxy=http://gate:3128 "$PROBE_IMAGE" \
      wget -q -T 5 -O /dev/null "http://target/" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  fail "the lab target did not start answering through the gate"
}

echo "== building images"
docker build -q -t vajra:local . >/dev/null
retry docker build -q -t vajra-nuclei:local -f deploy/nuclei.Dockerfile deploy >/dev/null
docker build -q -t vajra-semgrep:local -f deploy/semgrep.Dockerfile deploy >/dev/null
go build -o "$WORK/vajra" ./cmd/vajra

echo "== starting the lab"
docker rm -f "$GATE" "$TARGET" >/dev/null 2>&1 || true
cleanup_networks_only
docker network create --internal "$TASK_NET" >/dev/null
docker network create --internal --subnet "$LAB_SUBNET" "$LAB_NET" >/dev/null
docker network create "$OUT_NET" >/dev/null

mkdir -p "$WORK/site/.git"
printf '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://example.invalid/repo.git\n' > "$WORK/site/.git/config"
echo '<h1>lab</h1>' > "$WORK/site/index.html"
chmod -R a+rX "$WORK/site"
docker run -d --name "$TARGET" --network "$LAB_NET" --network-alias target \
  -v "$WORK/site:/usr/share/nginx/html:ro" nginx:alpine >/dev/null

cat > "$WORK/run.json" <<EOF
{
  "authorization": {"operator": "e2e", "statement": "Local lab target created by scripts/e2e.sh"},
  "scope": {"hosts": ["target"], "cidrs": ["$LAB_SUBNET"], "ports": [80, 8081]},
  "budget": {"tokens": 100000, "turns": 20, "sandbox_runs": 20, "duration_seconds": 1200},
  "targets": ["http://target"],
  "sandbox": {"network": "$TASK_NET", "proxy_url": "http://gate:3128"},
  "nuclei": {"image": "vajra-nuclei:local", "templates_dir": "/opt/nuclei-templates/http/exposures/configs/git-config.yaml", "timeout_seconds": 300},
  "refuter": {"provider": "none"},
  "topology": {
    "assets": [
      {"id": "lab-repo", "kind": "datastore", "name": "Source repository", "data_classes": ["source-code", "secrets"]},
      {"id": "lab-db", "kind": "datastore", "name": "Lab database", "data_classes": ["pii"]}
    ],
    "links": [
      {"from": "target", "to": "lab-repo", "relation": "reads"},
      {"from": "target", "to": "lab-db", "relation": "reads"}
    ]
  }
}
EOF
chmod a+r "$WORK/run.json"
mkdir -p "$WORK/audit"

# The gate runs as the invoking user, so the audit log it writes (owner-only)
# is readable by the person who started it. On Linux, file ownership inside a
# bind mount is real; a gate running as another user would lock them out.
docker create --name "$GATE" --network "$TASK_NET" --network-alias gate \
  --user "$(id -u):$(id -g)" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$WORK/run.json:/etc/vajra/run.json:ro" \
  -v "$WORK/audit:/var/log/vajra" \
  vajra:local gate -config /etc/vajra/run.json -listen :3128 -socks :1080 -audit /var/log/vajra/audit.jsonl >/dev/null
docker network connect "$LAB_NET" "$GATE"
docker network connect "$OUT_NET" "$GATE"
docker start "$GATE" >/dev/null
for _ in $(seq 1 30); do
  docker logs "$GATE" 2>&1 | grep -q "egress gate listening" && break
  sleep 0.5
done
docker logs "$GATE" 2>&1 | grep -q "egress gate listening" || fail "the gate did not start: $(docker logs "$GATE" 2>&1 | tail -3)"

wait_for_target

echo "== isolation checks"
if docker run --rm --network "$TASK_NET" "$PROBE_IMAGE" wget -q -T 5 -O /dev/null http://1.1.1.1/ 2>/dev/null; then
  fail "a task container reached the internet directly"
fi
pass "task container has no direct route out"

if docker run --rm --network "$TASK_NET" "$PROBE_IMAGE" wget -q -T 5 -O /dev/null "http://$TARGET/" 2>/dev/null; then
  fail "a task container reached the lab target without the gate"
fi
pass "task container cannot reach the target except through the gate"

denied="$(docker run --rm --network "$TASK_NET" -e http_proxy=http://gate:3128 "$PROBE_IMAGE" \
  wget -T 10 -O /dev/null http://example.com/ 2>&1 || true)"
echo "$denied" | grep -q "403" || fail "the gate did not refuse an out-of-scope host: $denied"
pass "gate refuses an out-of-scope host"

allowed="$(docker run --rm --network "$TASK_NET" -e http_proxy=http://gate:3128 "$PROBE_IMAGE" \
  wget -q -T 10 -O - http://target/ 2>&1 || true)"
echo "$allowed" | grep -q "lab" || fail "the gate did not forward an in-scope request: $allowed"
pass "gate forwards an in-scope request"

echo "== scan"
"$WORK/vajra" scan -config "$WORK/run.json" -out "$WORK/report.json" -data "$WORK/data" -gate-audit "$WORK/audit/audit.jsonl"
grep -q '"rule_id": "git-config"' "$WORK/report.json" || fail "the exposed .git/config was not reported: $(cat "$WORK/report.json")"
grep -q '"reason": "reproduced 2 of 2 times"' "$WORK/report.json" || fail "the finding was not reproduced: $(cat "$WORK/report.json")"
grep -q '"status": "unconfirmed"' "$WORK/report.json" || fail "with no refuter the finding must be unconfirmed"
pass "scan found the exposure, reproduced it twice, and left it unconfirmed without a reviewer"

echo "== audit"
audit="$(cat "$WORK/audit/audit.jsonl")"
echo "$audit" | grep -q '"target":"example.com:80","allowed":false' || fail "the denial is missing from the audit log"
echo "$audit" | grep -q '"target":"target:80","allowed":true' || fail "the allowed requests are missing from the audit log"
pass "audit log records allowed and denied connections"

echo "== saved run and reports"
run_id="$("$WORK/vajra" runs -data "$WORK/data" | awk 'NR==2 {print $1}')"
[ -n "$run_id" ] || fail "the run was not saved"
"$WORK/vajra" report -data "$WORK/data" -run "$run_id" -format html -out "$WORK/report.html"
"$WORK/vajra" report -data "$WORK/data" -run "$run_id" -format md -out "$WORK/report.md"
grep -q "Blast radius score:" "$WORK/report.md" || fail "the Markdown report is missing the blast radius"
grep -q "refused" "$WORK/report.md" || fail "the report does not show what the gate refused"
grep -q "blast radius / 100" "$WORK/report.html" || fail "the HTML report is missing the blast radius"
pass "run $run_id saved; HTML and Markdown reports show the blast radius and the run's reach"
if [ -n "${E2E_KEEP:-}" ]; then
  mkdir -p "$E2E_KEEP" && cp "$WORK/report.html" "$WORK/report.md" "$WORK/report.json" "$E2E_KEEP/"
  echo "reports kept in $E2E_KEEP"
fi

echo "== a result that does not reproduce"
echo '{"template-id":"git-config","matched-at":"http://target/missing/.git/config","request":"GET /missing/.git/config HTTP/1.1","response":"HTTP/1.1 200 OK"}' > "$WORK/stale.jsonl"
"$WORK/vajra" verify -config "$WORK/run.json" -in "$WORK/stale.jsonl" -out "$WORK/stale-report.json"
grep -q '"status": "refuted"' "$WORK/stale-report.json" || fail "a result that does not reproduce on a live target was not refuted: $(cat "$WORK/stale-report.json")"
pass "a stale result was refuted, after the canary showed the target was answering"

docker stop "$TARGET" >/dev/null
"$WORK/vajra" verify -config "$WORK/run.json" -in "$WORK/stale.jsonl" -out "$WORK/down-report.json"
grep -q '"status": "unconfirmed"' "$WORK/down-report.json" || fail "with the target down the result must be unconfirmed, not refuted: $(cat "$WORK/down-report.json")"
grep -q 'did not answer' "$WORK/down-report.json" || fail "the reason does not say the target was unreachable"
pass "with the target down, the same result is left unconfirmed instead of being dismissed"

echo "== code analysis"
mkdir -p "$WORK/src/shop"
cat > "$WORK/src/shop/views.py" <<'PYEOF'
from flask import request


def find_order(db):
    order_id = request.args.get("id")
    query = "SELECT * FROM orders WHERE id = " + order_id
    return db.execute(query)


def find_order_safely(db):
    order_id = request.args.get("id")
    return db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
PYEOF
chmod -R a+rX "$WORK/src"
cat > "$WORK/code.json" <<EOF
{
  "authorization": {"operator": "e2e", "statement": "Lab source created by scripts/e2e.sh"},
  "budget": {"tokens": 100000, "turns": 20, "sandbox_runs": 20, "duration_seconds": 1200},
  "source": {
    "root": "$WORK/src",
    "semgrep": {"image": "vajra-semgrep:local", "rules_host_dir": "$PWD/rules/starter", "timeout_seconds": 600}
  },
  "refuter": {"provider": "none"}
}
EOF
"$WORK/vajra" scan -config "$WORK/code.json" -out "$WORK/code-report.json" -data "$WORK/data"
grep -q 'python-sql-injection"' "$WORK/code-report.json" || fail "the SQL injection was not reported: $(cat "$WORK/code-report.json")"
grep -q '"target": "shop/views.py:7"' "$WORK/code-report.json" || fail "the finding is not at the vulnerable line: $(cat "$WORK/code-report.json")"
grep -q 'shop/views.py:12' "$WORK/code-report.json" && fail "the parameterised query was reported as a vulnerability"
grep -q '"reason": "reproduced 1 of 1 times"' "$WORK/code-report.json" || fail "the code finding was not reproduced"
grep -q '"reason": "source located and read"' "$WORK/code-report.json" || fail "the source context was not read"
grep -q 'return db.execute(query)' "$WORK/code-report.json" || fail "the code around the finding is missing from the evidence"
pass "code analysis found the injection at line 7, left the safe query alone, and captured the code as evidence"
if [ -n "${E2E_KEEP:-}" ]; then cp "$WORK/code-report.json" "$E2E_KEEP/"; fi

echo "== access control, API, crawl and secrets on a second lab app"
docker stop "$TARGET" >/dev/null 2>&1 || true
docker rm -f "$TARGET" >/dev/null 2>&1 || true
mkdir -p "$WORK/app"
cat > "$WORK/app/index.html" <<'HTMLEOF'
<h1>lab shop</h1>
<a href="/about.html">About</a> <a href="/account">Account</a>
<a href="https://example.com/elsewhere">Partner</a>
<form action="/search" method="get"><input name="q"></form>
HTMLEOF
echo '<h1>about</h1><a href="/">home</a>' > "$WORK/app/about.html"
echo '<h1>user list: alice, bob</h1>' > "$WORK/app/admin-users.html"
echo '<h1>your account</h1>' > "$WORK/app/account.html"
echo '<h1>sign in</h1>' > "$WORK/app/login.html"
cat > "$WORK/nginx.conf" <<'NGINXEOF'
server {
  listen 80;
  root /usr/share/nginx/html;
  # Broken on purpose: an ordinary user is served the administration page.
  location = /admin/users {
    if ($http_authorization !~ "^Bearer (lab-admin-token|lab-user-token)$") { return 403; }
    try_files /admin-users.html =404;
  }
  location = /account {
    if ($http_authorization !~ "^Bearer (lab-admin-token|lab-user-token)$") { return 302 /login.html; }
    try_files /account.html =404;
  }
  # Broken on purpose: the description says this needs authentication.
  location = /api/orders { default_type application/json; return 200 '{"orders":[{"id":1,"total":42}]}'; }
  location = /api/health { default_type application/json; return 200 '{"ok":true}'; }
  # Left open on purpose: anyone can read the whole schema.
  location = /graphql { default_type application/json; return 200 '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT"},{"name":"Order","kind":"OBJECT"}]}}}'; }
}
# A second service on a port the operator does not expect to be open.
server {
  listen 8081;
  location / { return 200 'internal admin console'; }
}
NGINXEOF
chmod -R a+rX "$WORK/app" "$WORK/nginx.conf"
docker run -d --name "$TARGET" --network "$LAB_NET" --network-alias target \
  -v "$WORK/app:/usr/share/nginx/html:ro" -v "$WORK/nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
wait_for_target
cat > "$WORK/openapi.json" <<'APIEOF'
{
  "openapi": "3.0.3",
  "info": {"title": "Lab shop", "version": "1"},
  "security": [{"bearer": []}],
  "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
  "paths": {
    "/api/orders": {
      "get": {"operationId": "listOrders", "responses": {"200": {"description": "ok"}}},
      "post": {"operationId": "createOrder", "responses": {"201": {"description": "created"}}}
    },
    "/api/health": {"get": {"operationId": "health", "security": [], "responses": {"200": {"description": "ok"}}}}
  }
}
APIEOF
# A credential-shaped value for the secret search to find. It is assembled
# here so that this script does not itself contain one.
fake_key="AKIA""QWERTYUIOPASDFGH"
mkdir -p "$WORK/src2"
printf 'AWS_ACCESS_KEY_ID = "%s"\nREGION = "eu-west-1"\n' "$fake_key" > "$WORK/src2/settings.py"
chmod -R a+rX "$WORK/src2"
cat > "$WORK/full.json" <<EOF
{
  "authorization": {"operator": "e2e", "statement": "Local lab target created by scripts/e2e.sh"},
  "scope": {"hosts": ["target"], "cidrs": ["$LAB_SUBNET"], "ports": [80, 8081]},
  "budget": {"tokens": 200000, "turns": 40, "sandbox_runs": 60, "duration_seconds": 1200},
  "sandbox": {"network": "$TASK_NET", "proxy_url": "http://gate:3128", "socks_addr": "gate:1080"},
  "probe": {"image": "vajra:local", "timeout_seconds": 120},
  "graphql": {"endpoint": "http://target/graphql"},
  "ports": {"hosts": ["target"], "ports": [80, 8081], "expected": [80], "timeout_seconds": 60},
  "auth": {
    "identities": [
      {"name": "admin", "headers_env": {"Authorization": "VAJRA_E2E_ADMIN"}},
      {"name": "user", "headers_env": {"Authorization": "VAJRA_E2E_USER"}}
    ],
    "access_checks": [
      {"name": "User administration", "url": "http://target/admin/users", "allow": ["admin"]},
      {"name": "Account page", "url": "http://target/account", "allow": ["admin", "user"]}
    ]
  },
  "api": {"spec": "$WORK/openapi.json", "base_url": "http://target"},
  "source": {"root": "$WORK/src2", "secrets": true},
  "refuter": {"provider": "${E2E_REFUTER:-none}"}
}
EOF
VAJRA_E2E_ADMIN="Bearer lab-admin-token" VAJRA_E2E_USER="Bearer lab-user-token" \
  "$WORK/vajra" scan -config "$WORK/full.json" -out "$WORK/full-report.json" -data "$WORK/data" -gate-audit "$WORK/audit/audit.jsonl"
full="$WORK/full-report.json"
grep -q '"rule_id": "unauthorized-access"' "$full" || fail "the user reaching the admin page was not reported: $(cat "$full")"
grep -q 'User administration is served to the account' "$full" || fail "the access finding does not name the rule that was broken"
grep -q '"rule_id": "unauthenticated-access"' "$full" && fail "the account page redirects anonymous visitors, so it must not be reported"
grep -q '"rule_id": "auth-not-enforced"' "$full" || fail "the unprotected API operation was not reported"
grep -q 'createOrder' "$full" || fail "the skipped state-changing API operation is not listed"
grep -q '"rule_id": "aws-access-key-id"' "$full" || fail "the hard-coded key was not reported"
grep -q "$fake_key" "$full" && fail "the full secret value is in the report"
grep -q 'lab-user-token\|lab-admin-token' "$full" && fail "a test account's credential is in the report"
grep -q 'lab-user-token\|lab-admin-token' "$WORK"/data/runs/*.json && fail "a test account's credential is in a saved run"
grep -q '"rule_id": "graphql-introspection-enabled"' "$full" || fail "open GraphQL introspection was not reported"
grep -q '"target": "tcp://target:8081"' "$full" || fail "the unexpected service on port 8081 was not reported"
grep -q '"target": "tcp://target:80"' "$full" && fail "the expected port 80 was reported as unexpected"
python3 - "$full" <<'PYEOF' || fail "the open port must be confirmed by a second connection, with no reviewer needed"
import json, sys
findings = json.load(open(sys.argv[1]))["findings"]
port = [f for f in findings if f["rule_id"] == "unexpected-open-port"]
sys.exit(0 if len(port) == 1 and port[0]["status"] == "confirmed" else 1)
PYEOF
pass "an ordinary user reaching the admin page, an unprotected API operation and a hard-coded key were all found"
pass "open GraphQL introspection was found, and an unexpected open port was found and confirmed through the SOCKS5 gate"
pass "no credential and no full secret appears in the report or the saved runs"
if [ -n "${E2E_KEEP:-}" ]; then cp "$full" "$E2E_KEEP/"; fi

if [ "${E2E_REFUTER:-none}" = "anthropic" ]; then
  echo "== accuracy against the answer key (with a live reviewer)"
  run_id="$("$WORK/vajra" runs -data "$WORK/data" | awk 'NR==2 {print $1}')"
  "$WORK/vajra" bench -data "$WORK/data" -run "$run_id" -key bench/lab.json -min-precision 1 -min-recall 1 \
    || fail "the lab benchmark did not reach full precision and recall"
  pass "every planted flaw was confirmed and nothing else was"
fi

echo "ALL CHECKS PASSED"
