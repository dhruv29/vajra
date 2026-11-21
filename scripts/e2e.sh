#!/usr/bin/env bash
# End-to-end check against a local lab target.
#
# Builds the images, starts a lab web server that exposes a .git/config file,
# puts the egress gate in front of it, runs a real scan, and checks that:
#   1. the exposed file is found and reproduced,
#   2. a task container has no direct route out,
#   3. the gate refuses an out-of-scope host,
#   4. the gate wrote an audit log,
#   5. the saved run renders as reports with a blast radius.
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

echo "== building images"
docker build -q -t vajra:local . >/dev/null
docker build -q -t vajra-nuclei:local -f deploy/nuclei.Dockerfile deploy >/dev/null
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
  "scope": {"hosts": ["target"], "cidrs": ["$LAB_SUBNET"], "ports": [80]},
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
mkdir -p "$WORK/audit" && chmod 777 "$WORK/audit"

docker create --name "$GATE" --network "$TASK_NET" --network-alias gate \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$WORK/run.json:/etc/vajra/run.json:ro" \
  -v "$WORK/audit:/var/log/vajra" \
  vajra:local gate -config /etc/vajra/run.json -listen :3128 -audit /var/log/vajra/audit.jsonl >/dev/null
docker network connect "$LAB_NET" "$GATE"
docker network connect "$OUT_NET" "$GATE"
docker start "$GATE" >/dev/null
for _ in $(seq 1 30); do
  docker logs "$GATE" 2>&1 | grep -q "egress gate listening" && break
  sleep 0.5
done
docker logs "$GATE" 2>&1 | grep -q "egress gate listening" || fail "the gate did not start: $(docker logs "$GATE" 2>&1 | tail -3)"

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

echo "ALL CHECKS PASSED"
