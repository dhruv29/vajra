// Renders a saved Vajra run. A run is untrusted input: its evidence holds raw
// HTTP responses from scanned sites and code from scanned repositories. Every
// piece of it reaches the page as text through createElement/textContent,
// never as markup; URLs are shown as text, never as links; and anything not
// shaped like a run is refused, and everything else capped, before drawing.
"use strict";

const STATUSES = ["confirmed", "unconfirmed", "refuted", "out_of_scope"];
const STATUS_LABELS = { confirmed: "Confirmed", unconfirmed: "Unconfirmed", refuted: "Refuted", out_of_scope: "Out of scope" };
const STATUS_SUBS = {
  confirmed: "reproduced every time and survived review",
  unconfirmed: "could not be decided; left for a person",
  refuted: "disproved, with the reason kept",
  out_of_scope: "outside the scope; never re-tested",
};
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const OUTCOMES = ["pass", "fail", "inconclusive"];
const CONFIDENCES = ["proven", "inferred", "assumed"];
const KIND_LABELS = { dast: "Live test", sast: "Code", sca: "Dependency", net: "Network" };
const STAGES = ["evidence", "scope", "reproduce", "refute"];
const STAGE_LABELS = { candidate: "Candidate", evidence: "Evidence", scope: "Scope", reproduce: "Reproduce", refute: "Refute", verdict: "Verdict" };
const OUTCOME_LABELS = { pass: "passed", fail: "failed", inconclusive: "undecided", skipped: "not reached", missing: "not recorded" };
const SEVERITY_FILTERS = {
  any: () => true,
  high: (f) => SEVERITIES.indexOf(f.severity) <= 1,
  critical: (f) => f.severity === "critical",
};
const MAX_FILE_BYTES = 40 * 1024 * 1024;
const MAX_FINDINGS = 5000;
const MAX_TEXT = 600;
const MAX_BLOB = 20000;
const MAX_LIST = 200;
const MAX_ASSETS = 2000;
const MAX_EDGES = 6000;
const MAX_HOPS = 200;
const MAX_CHAINS = 200;
const MAX_DEPTH = 20;
const SVG_NS = "http://www.w3.org/2000/svg";

let state = {
  run: null, isSample: true, status: "all", severity: "any", kind: "any", query: "", open: new Set(), trail: null,
};

function setState(patch) {
  state = { ...state, ...patch };
}

/** Creates an element with text content and attributes; never parses HTML. */
function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.text !== undefined) node.textContent = options.text;
  if (options.className) node.className = options.className;
  for (const [name, value] of Object.entries(options.attrs || {})) node.setAttribute(name, value);
  for (const child of children) if (child) node.append(child);
  return node;
}

/** Same for SVG; geometry goes in attributes, colour comes from the stylesheet. */
function svg(tag, attrs = {}, children = []) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
  for (const child of children) node.append(child);
  return node;
}

function button(label, className, onClick, attrs = {}) {
  const node = el("button", { className, text: label, attrs: { type: "button", ...attrs } });
  node.addEventListener("click", onClick);
  return node;
}

/* ---------- reading an untrusted run ---------- */

const isObj = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value, max = MAX_TEXT) => (typeof value === "string" ? value.slice(0, max) : "");
const pick = (value, allowed, fallback) => (allowed.includes(value) ? value : fallback);
const list = (value, cap) => (Array.isArray(value) ? value : []).slice(0, cap).filter(isObj);
const strings = (value, cap, max = MAX_TEXT) => (Array.isArray(value) ? value : []).slice(0, cap).map((s) => text(s, max)).filter(Boolean);
const int = (value, max = 1e12) => (Number.isFinite(value) && value > 0 ? Math.min(Math.floor(value), max) : 0);

function deriveKind(raw, f) {
  if (KIND_LABELS[raw.kind] && Object.hasOwn(KIND_LABELS, raw.kind)) return raw.kind;
  const source = f.source.toLowerCase();
  if (/advis|depend/.test(source) || /^(ghsa|cve|pysec|rustsec|go)-/i.test(f.ruleId)) return "sca";
  if (/port/.test(source)) return "net";
  if ((f.evidence.code || f.evidence.trace.length || f.location) && !f.evidence.request) return "sast";
  return "dast";
}

function cleanEvidence(raw) {
  const ev = isObj(raw) ? raw : {};
  return {
    request: text(ev.request, MAX_BLOB),
    response: text(ev.response, MAX_BLOB),
    matchedAt: text(ev.matched_at, 2000),
    matcher: text(ev.matcher),
    extracted: strings(ev.extracted, 20, 2000),
    code: text(ev.code, MAX_BLOB),
    trace: list(ev.trace, 40).map((t) => ({ role: text(t.role, 20), file: text(t.file), line: int(t.line), content: text(t.content, 1000) })),
  };
}

function cleanFinding(raw, index, seen) {
  if (!isObj(raw)) return null;
  let id = text(raw.id, 120) || "finding-" + (index + 1);
  while (seen.has(id)) id += "'";
  seen.add(id);
  const f = {
    uid: "f" + index,
    id,
    title: text(raw.title) || "Untitled finding",
    severity: pick(raw.severity, SEVERITIES, "info"),
    status: pick(raw.status, STATUSES, "unconfirmed"),
    source: text(raw.source, 80),
    ruleId: text(raw.rule_id, 200),
    target: text(raw.target, 2000),
    cwe: strings(raw.cwe, 10, 40),
    location: isObj(raw.location) ? { file: text(raw.location.file), line: int(raw.location.line) } : null,
    evidence: cleanEvidence(raw.evidence),
    verdicts: list(raw.verdicts, 20).map((v) => ({
      stage: text(v.stage, 40) || "stage", outcome: pick(v.outcome, OUTCOMES, "inconclusive"), reason: text(v.reason, 2000), at: text(v.at, 40),
    })),
    corroboratedBy: strings(raw.corroborated_by, 20, 120),
  };
  return { ...f, kind: deriveKind(raw, f) };
}

function cleanGraph(raw) {
  const g = isObj(raw) ? raw : {};
  return {
    assets: list(g.assets, MAX_ASSETS).map((a) => ({
      id: text(a.id, 400), kind: text(a.kind, 40), name: text(a.name, 400) || text(a.id, 400),
      origin: text(a.origin, 20), dataClasses: strings(a.data_classes, 20, 40),
    })).filter((a) => a.id),
    edges: list(g.edges, MAX_EDGES).map((e) => ({ from: text(e.from, 400), to: text(e.to, 400), relation: text(e.relation, 40), origin: text(e.origin, 20) }))
      .filter((e) => e.from && e.to),
  };
}

function cleanRadius(r) {
  return {
    findingId: text(r.finding_id, 120),
    capability: text(r.capability, 60),
    basis: text(r.capability_basis),
    originId: text(r.origin_id, 400),
    reach: list(r.reach, MAX_HOPS).map((h) => ({
      assetId: text(h.asset_id, 400), name: text(h.name, 400) || text(h.asset_id, 400), kind: text(h.kind, 40),
      depth: int(h.depth, MAX_DEPTH), from: text(h.from, 400), via: text(h.via, 40),
      confidence: pick(h.confidence, CONFIDENCES, "assumed"), why: text(h.why),
    })).filter((h) => h.assetId),
    dataClasses: strings(r.data_classes, 20, 40),
    score: Math.min(100, int(r.score)),
    summary: text(r.summary, 1000),
  };
}

function cleanChain(c, index) {
  return {
    uid: "c" + index,
    steps: list(c.steps, 10).map((s) => ({
      findingId: text(s.finding_id, 120), title: text(s.title), capability: text(s.capability, 60), originId: text(s.origin_id, 400), why: text(s.why, 1000),
    })).filter((s) => s.findingId),
    reach: strings(c.reach, 400, 400),
    dataClasses: strings(c.data_classes, 20, 40),
    score: Math.min(100, int(c.score)),
    summary: text(c.summary, 1000),
  };
}

function cleanTargets(value) {
  return list(value, MAX_LIST).map((t) => ({ target: text(t.target, 300), count: int(t.count), reason: text(t.reason, 300) })).filter((t) => t.target);
}

function cleanActivity(raw) {
  const a = isObj(raw) ? raw : {};
  return {
    discoveredHosts: strings(a.discovered_hosts, MAX_LIST, 300),
    rejectedHosts: strings(a.rejected_hosts, MAX_LIST, 300),
    endpoints: strings(a.endpoints, 2000, 1000),
    pagesCrawled: int(a.pages_crawled),
    crawlTruncated: a.crawl_truncated === true,
    skipped: strings(a.skipped_operations, MAX_LIST),
    packages: list(a.packages, 5000).length,
    steps: list(a.agent_steps, 500).map((s) => ({ n: int(s.n), tool: text(s.tool, 60), summary: text(s.summary), outcome: text(s.outcome) })),
    agentStopped: text(a.agent_stopped, 200),
    notes: strings(a.notes, MAX_LIST),
  };
}

function cleanRun(raw) {
  if (!isObj(raw) || !isObj(raw.report) || !Array.isArray(raw.report.findings)) {
    throw new Error("That file is not a saved Vajra run: it has no report with a list of findings. Runs are saved by: vajra scan -data DIR");
  }
  const report = raw.report;
  if (report.findings.length > MAX_FINDINGS) throw new Error("That run has more findings than this page will show.");
  const seen = new Set();
  const findings = report.findings.map((f, i) => cleanFinding(f, i, seen)).filter(Boolean);
  const budget = isObj(report.budget) ? report.budget : {};
  const limits = isObj(budget.limits) ? budget.limits : {};
  const usage = isObj(budget.usage) ? budget.usage : {};
  const scope = isObj(report.scope) ? report.scope : {};
  const auth = isObj(report.authorization) ? report.authorization : {};
  const reach = isObj(raw.reach) ? raw.reach : null;
  return {
    id: text(raw.id, 120),
    generatedAt: text(report.generated_at, 40),
    operator: text(auth.operator, 200),
    statement: text(auth.statement, 2000),
    targets: strings(report.targets, MAX_LIST, 1000),
    sourceRoot: text(report.source_root, 500),
    scope: { hosts: strings(scope.hosts, MAX_LIST, 300), cidrs: strings(scope.cidrs, MAX_LIST, 60), ports: (Array.isArray(scope.ports) ? scope.ports : []).slice(0, 100).map((p) => int(p, 65535)).filter(Boolean) },
    budget: [
      ["Model tokens", int(usage.tokens), int(limits.tokens)],
      ["Model turns", int(usage.turns), int(limits.turns)],
      ["Sandbox runs", int(usage.sandbox_runs), int(limits.sandbox_runs)],
      ["Minutes", Math.round(int(usage.elapsed_ns) / 6e10), Math.round(int(limits.duration_seconds) / 60)],
    ],
    reviewer: text(report.refuter, 40),
    findings,
    activity: cleanActivity(report.activity),
    graph: cleanGraph(raw.graph),
    radii: list(raw.radii, MAX_FINDINGS).map(cleanRadius).filter((r) => r.findingId),
    chains: list(raw.chains, MAX_CHAINS).map(cleanChain).filter((c) => c.steps.length),
    reach: reach ? { allowed: cleanTargets(reach.allowed), denied: cleanTargets(reach.denied), allowedTotal: int(reach.allowed_total), deniedTotal: int(reach.denied_total) } : null,
  };
}

/* ---------- derived views ---------- */

function findingById(id) {
  return state.run.findings.find((f) => f.id === id) || null;
}

function radiusOf(id) {
  return state.run.radii.find((r) => r.findingId === id) || null;
}

function scoreOf(f) {
  return radiusOf(f.id)?.score ?? 0;
}

/** Names what raised a finding without naming any outside product. */
function sourceLabel(f) {
  const s = f.source.toLowerCase();
  if (s.startsWith("vajra")) {
    const known = [["agent", "the explorer"], ["secret", "the secret search"], ["inject", "a built-in input check"], ["access", "an access check"],
      ["auth", "an access check"], ["graphql", "the GraphQL check"], ["api", "the API check"], ["port", "port discovery"], ["sarif", "an imported SARIF report"]];
    const hit = known.find(([key]) => s.includes(key));
    if (hit) return hit[1];
  }
  if (s.includes("sarif")) return "an imported SARIF report";
  return { dast: "a scanner template", sast: "a code rule", sca: "an advisory database", net: "port discovery" }[f.kind];
}

const human = (value) => value.replace(/_/g, " ");

function countBy(items, key) {
  return items.reduce((acc, item) => ({ ...acc, [key(item)]: (acc[key(item)] || 0) + 1 }), {});
}

function statusPill(status) {
  return el("span", { className: "status-pill", attrs: { "data-status": status }, text: STATUS_LABELS[status] });
}

function sevPill(severity) {
  return el("span", { className: "sev-pill", attrs: { "data-sev": severity }, text: severity });
}

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function goTo(id, focusId) {
  const target = document.getElementById(id);
  if (!target) return;
  target.scrollIntoView({ block: "start", behavior: prefersReducedMotion() ? "auto" : "smooth" });
  const focus = document.getElementById(focusId || "");
  if (focus) focus.focus({ preventScroll: true });
}

/* ---------- verdict tiles ---------- */

function renderVerdicts(run) {
  const counts = countBy(run.findings, (f) => f.status);
  const total = run.findings.length;
  const kept = counts.confirmed || 0;
  const removed = total - kept;
  const headline = document.getElementById("headline");
  headline.replaceChildren(
    el("strong", { text: total + (total === 1 ? " candidate in, " : " candidates in, ") + kept + " confirmed out." }),
    el("span", { text: removed
      ? " " + removed + " kept off your fix list, every one with the reason it was refuted, left undecided or ruled out of scope."
      : " Nothing was thrown out." }),
  );
  let x = 0;
  document.getElementById("funnel").replaceChildren(...STATUSES.filter((s) => counts[s]).map((s) => {
    const width = (counts[s] / (total || 1)) * 100;
    const rect = svg("rect", { x, y: 0, width, height: 8, class: "fill", "data-status": s });
    x += width;
    return rect;
  }));
  document.getElementById("tally").replaceChildren(...STATUSES.map((status) => {
    const show = button("List them", "tile-link", () => {
      setState({ status, severity: "any", kind: "any", query: "" });
      syncControls();
      renderFindings(state.run);
      goTo("findings-heading");
    }, { "aria-label": "List " + STATUS_LABELS[status].toLowerCase() + " findings" });
    return el("div", { className: "tile", attrs: { "data-status": status } }, [
      el("dt", { text: STATUS_LABELS[status] }),
      el("dd", {}, [
        el("span", { className: "tile-value", text: String(counts[status] || 0) }),
        el("span", { className: "tile-sub", text: STATUS_SUBS[status] }),
        counts[status] ? show : null,
      ]),
    ]);
  }));
}

/* ---------- fix these first ---------- */

function meter(value, max, className) {
  const width = max ? Math.min(100, (value / max) * 100) : 0;
  return svg("svg", { class: "meter " + (className || ""), viewBox: "0 0 100 4", preserveAspectRatio: "none", "aria-hidden": "true" }, [
    svg("rect", { x: 0, y: 0, width: 100, height: 4, class: "track" }),
    svg("rect", { x: 0, y: 0, width, height: 4, class: "fill" }),
  ]);
}

function dataChips(classes) {
  return el("ul", { className: "chips", attrs: { "aria-label": "Data reached" } }, classes.map((c) => el("li", { className: "data-chip", text: human(c) })));
}

function renderFixFirst(run) {
  const host = document.getElementById("fixfirst");
  const confirmed = run.findings.filter((f) => f.status === "confirmed")
    .sort((a, b) => scoreOf(b) - scoreOf(a) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  if (!confirmed.length) {
    host.replaceChildren(el("li", { className: "empty", text: "Nothing in this run was confirmed. Check the unconfirmed findings: each says what a person needs to decide." }));
    return;
  }
  host.replaceChildren(...confirmed.map((f, i) => {
    const radius = radiusOf(f.id);
    const score = radius ? radius.score : 0;
    const title = button(f.title, "fix-title", () => openTrail(f.id));
    const actions = el("p", { className: "fix-actions" }, [
      button("Verification trail", "link-button", () => openTrail(f.id)),
      radius && radius.reach.length ? button("Blast radius on the map", "link-button", () => showOnMap(f.id)) : null,
    ]);
    return el("li", { className: "fix", attrs: { "data-sev": f.severity } }, [
      el("div", { className: "fix-score" }, [
        el("span", { className: "fix-rank", text: String(i + 1).padStart(2, "0") }),
        el("span", { className: "fix-value", text: String(score) }),
        el("span", { className: "fix-unit", text: "reach score" }),
        meter(score, 100, "meter-score"),
      ]),
      el("div", { className: "fix-body" }, [
        title,
        el("p", { className: "risk-meta" }, [sevPill(f.severity), el("span", { className: "kind-tag", text: KIND_LABELS[f.kind] }), el("code", { className: "mono", text: f.target })]),
        radius && radius.summary ? el("p", { className: "fix-why", text: radius.summary }) : null,
        radius && radius.dataClasses.length ? dataChips(radius.dataClasses) : null,
        actions,
      ]),
    ]);
  }));
}

/* ---------- egress gate ---------- */

function renderGate(run) {
  const host = document.getElementById("gate");
  if (!run.reach) {
    host.replaceChildren(el("p", { className: "panel-note", text: "No gate audit log was attached to this run (scan with -gate-audit), so what it touched is not shown here." }));
    return;
  }
  const r = run.reach;
  const side = (label, value, tone) => el("div", { className: "where-side", attrs: { "data-tone": tone } }, [
    el("span", { className: "where-label", text: label }), el("span", { className: "where-value", text: String(value) }),
  ]);
  const rows = (items, tone) => items.map((t) => el("li", { className: "gate-row", attrs: { "data-tone": tone } }, [
    el("code", { className: "mono", text: t.target }),
    el("span", { className: "gate-count", text: String(t.count) }),
    t.reason ? el("span", { className: "gate-reason", text: t.reason }) : null,
  ]));
  host.replaceChildren(
    el("div", { className: "where-row" }, [side("Requests allowed", r.allowedTotal, "allow"), side("Refused", r.deniedTotal, "deny")]),
    el("h4", { className: "mini-head", text: "Refused, with the reason" }),
    el("ul", { className: "gate-list" }, r.denied.length ? rows(r.denied, "deny") : [el("li", { className: "panel-note", text: "Nothing was refused." })]),
    el("h4", { className: "mini-head", text: "Allowed" }),
    el("ul", { className: "gate-list" }, rows(r.allowed, "allow")),
  );
}

/* ---------- verification trail ---------- */

function stationsFor(f) {
  const stages = [...STAGES, ...f.verdicts.map((v) => v.stage).filter((s) => !STAGES.includes(s))];
  const decisive = f.verdicts.find((v) => v.outcome !== "pass") || null;
  let decided = false;
  const stations = [{ stage: "candidate", outcome: "pass", reason: "Raised by " + sourceLabel(f) + (f.ruleId ? " (rule " + f.ruleId + ")" : "") + ".", at: "" }];
  for (const stage of stages) {
    const verdict = f.verdicts.find((v) => v.stage === stage);
    if (verdict) stations.push({ ...verdict, decisive: verdict === decisive });
    else stations.push({ stage, outcome: decided ? "skipped" : "missing", reason: decided ? "Not run: the finding was already decided." : "No result was recorded for this stage.", at: "" });
    if (verdict && verdict === decisive) decided = true;
  }
  return { stations, decisive };
}

function verdictLine(f, decisive) {
  const at = decisive ? (STAGE_LABELS[decisive.stage] || decisive.stage).toLowerCase() : "";
  if (f.status === "confirmed") return "Confirmed. It passed every stage.";
  if (f.status === "out_of_scope") return "Stopped at scope. It was never re-tested.";
  if (f.status === "refuted") return decisive ? "Thrown out at " + at + "." : "Refuted.";
  return decisive ? "Left for a person at " + at + "." : "Left for a person: it passed every check that ran, but nothing confirmed it.";
}

function trailStation(s, index) {
  const isVerdict = s.stage === "verdict";
  return el("li", { className: "station" + (s.decisive ? " is-decisive" : "") + (isVerdict ? " is-verdict" : ""), attrs: { "data-outcome": s.outcome, "data-i": String(Math.min(index, 7)) } }, [
    el("span", { className: "station-dot", attrs: { "aria-hidden": "true" } }),
    el("span", { className: "station-name", text: STAGE_LABELS[s.stage] || s.stage }),
    el("span", { className: "station-outcome", text: isVerdict ? STATUS_LABELS[s.outcome] : OUTCOME_LABELS[s.outcome] || s.outcome }),
  ]);
}

function trailEntry(s) {
  const time = s.at ? s.at.replace("T", " ").slice(0, 19) : "";
  return el("li", { className: "entry" + (s.decisive ? " is-decisive" : ""), attrs: { "data-outcome": s.outcome } }, [
    el("div", { className: "entry-head" }, [
      el("span", { className: "entry-stage", text: STAGE_LABELS[s.stage] || s.stage }),
      el("span", { className: "entry-outcome", text: OUTCOME_LABELS[s.outcome] || s.outcome }),
      time ? el("time", { className: "entry-time mono", text: time }) : null,
    ]),
    el("p", { className: "entry-reason", text: s.reason || "No reason recorded." }),
  ]);
}

function renderTrailView(f) {
  const host = document.getElementById("trail-view");
  if (!f) {
    host.replaceChildren(el("p", { className: "panel-note", text: "This run has no findings." }));
    return;
  }
  const { stations, decisive } = stationsFor(f);
  const verdict = { stage: "verdict", outcome: f.status, reason: "", at: "" };
  const radius = radiusOf(f.id);
  host.replaceChildren(
    el("div", { className: "trail-head" }, [
      el("p", { className: "risk-meta" }, [statusPill(f.status), sevPill(f.severity), el("span", { className: "kind-tag", text: KIND_LABELS[f.kind] }), el("code", { className: "mono", text: f.id })]),
      el("h4", { className: "trail-title", text: f.title }),
      el("code", { className: "mono trail-target", text: f.target }),
    ]),
    el("ol", { className: "track", attrs: { "aria-label": "Stages" } }, [...stations, verdict].map(trailStation)),
    el("div", { className: "decision", attrs: { "data-status": f.status } }, [
      el("p", { className: "decision-line", text: verdictLine(f, decisive) }),
      decisive && decisive.reason ? el("blockquote", { className: "decision-reason", text: decisive.reason }) : null,
      f.status === "confirmed" && radius ? el("p", { className: "decision-sub", text: radius.summary }) : null,
    ]),
    el("ol", { className: "timeline", attrs: { "aria-label": "Stage by stage" } }, stations.map(trailEntry)),
    el("p", { className: "fix-actions" }, [
      button("Evidence in the findings table", "link-button", () => revealFinding(f.id)),
      radius && radius.reach.length && f.status !== "refuted" && f.status !== "out_of_scope" ? button("Blast radius on the map", "link-button", () => showOnMap(f.id)) : null,
    ]),
  );
}

function trailOrder(run) {
  return STATUSES.flatMap((status) => run.findings.filter((f) => f.status === status)
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.title.localeCompare(b.title)));
}

function renderTrail(run) {
  const ordered = trailOrder(run);
  const current = findingById(state.trail) || ordered.find((f) => f.status === "refuted") || ordered[0] || null;
  setState({ trail: current ? current.id : null });
  const select = document.getElementById("trail-select");
  select.replaceChildren(...STATUSES.filter((s) => ordered.some((f) => f.status === s)).map((status) =>
    el("optgroup", { attrs: { label: STATUS_LABELS[status] } }, ordered.filter((f) => f.status === status).map((f) =>
      el("option", { text: f.title, attrs: { value: f.uid } })))));
  if (current) select.value = current.uid;
  document.getElementById("trail-list").replaceChildren(...STATUSES.filter((s) => ordered.some((f) => f.status === s)).map((status) => {
    const items = ordered.filter((f) => f.status === status);
    return el("div", { className: "trail-group" }, [
      el("p", { className: "group-title" }, [statusPill(status), el("span", { className: "group-count", text: String(items.length) })]),
      el("ul", { className: "trail-picks" }, items.map((f) => el("li", {}, [
        button(f.title, "trail-pick-btn", () => openTrail(f.id, true), { "aria-pressed": String(current && f.id === current.id), id: "pick-" + f.uid, "data-sev": f.severity }),
      ]))),
    ]);
  }));
  renderTrailView(current);
}

function openTrail(id, keepFocus) {
  setState({ trail: id });
  renderTrail(state.run);
  if (keepFocus) {
    const f = findingById(id);
    document.getElementById("pick-" + (f ? f.uid : ""))?.focus();
    return;
  }
  goTo("trail-heading");
}

/* ---------- findings table ---------- */

function haystack(f) {
  const e = f.evidence;
  return [f.title, f.id, f.target, f.ruleId, f.cwe.join(" "), KIND_LABELS[f.kind], e.request, e.response, e.code, e.matchedAt, ...e.extracted,
    ...f.verdicts.map((v) => v.reason)].join("\n").toLowerCase();
}

function matches(f) {
  if (state.status !== "all" && f.status !== state.status) return false;
  if (state.kind !== "any" && f.kind !== state.kind) return false;
  if (!SEVERITY_FILTERS[state.severity](f)) return false;
  const query = state.query.trim().toLowerCase();
  return !query || haystack(f).includes(query);
}

function block(title, children) {
  return el("div", { className: "detail-block" }, [el("h5", { text: title }), ...children]);
}

function evidenceBlocks(f) {
  const e = f.evidence;
  const blocks = [];
  if (e.request) blocks.push(block("Request", [el("pre", { className: "pre", text: e.request })]));
  if (e.response) blocks.push(block("Response", [el("pre", { className: "pre", text: e.response })]));
  if (e.code) blocks.push(block("Code" + (f.location && f.location.file ? " · " + f.location.file : ""), [el("pre", { className: "pre", text: e.code })]));
  if (e.trace.length) {
    blocks.push(block("Data flow", [el("ol", { className: "trace" }, e.trace.map((t) => el("li", {}, [
      el("span", { className: "trace-role", text: t.role || "step" }),
      el("code", { className: "mono", text: t.file + (t.line ? ":" + t.line : "") + "  " + t.content }),
    ])))]));
  }
  const facts = [["Matched at", e.matchedAt], ["Matcher", e.matcher], ["Extracted", e.extracted.join("\n")], ["Rule", f.ruleId],
    ["CWE", f.cwe.join(", ")], ["Raised by", sourceLabel(f)], ["Same weakness as", f.corroboratedBy.join(", ")]].filter(([, v]) => v);
  blocks.push(block("Details", [el("dl", { className: "facts-list" }, facts.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { className: "mono", text: v })]))]));
  return blocks;
}

function detailRow(f, columns) {
  const { decisive } = stationsFor(f);
  const verdict = el("div", { className: "detail-verdict", attrs: { "data-status": f.status } }, [
    el("p", { className: "decision-line", text: verdictLine(f, decisive) }),
    decisive && decisive.reason ? el("p", { className: "panel-note", text: decisive.reason }) : null,
    el("p", { className: "fix-actions" }, [button("Open its verification trail", "link-button", () => openTrail(f.id))]),
  ]);
  const cell = el("td", { attrs: { colspan: String(columns) } }, [el("div", { className: "detail" }, [verdict, ...evidenceBlocks(f)])]);
  return el("tr", { className: "detail-row", attrs: { id: "detail-" + f.uid } }, [cell]);
}

function findingRows(f) {
  const isOpen = state.open.has(f.uid);
  const toggle = el("button", {
    className: "row-toggle",
    attrs: { type: "button", id: "toggle-" + f.uid, "aria-expanded": String(isOpen), "aria-controls": "detail-" + f.uid },
  }, [el("span", { className: "chevron", attrs: { "aria-hidden": "true" } }), el("span", { text: f.title })]);
  toggle.addEventListener("click", () => {
    const open = new Set(state.open);
    if (open.has(f.uid)) open.delete(f.uid); else open.add(f.uid);
    setState({ open });
    renderFindings(state.run);
    document.getElementById("toggle-" + f.uid)?.focus();
  });
  const radius = radiusOf(f.id);
  const row = el("tr", { className: "row" + (isOpen ? " is-open" : ""), attrs: { "data-status": f.status } }, [
    el("td", { className: "cell-name", attrs: { "data-label": "Finding" } }, [toggle]),
    el("td", { attrs: { "data-label": "Verdict" } }, [statusPill(f.status)]),
    el("td", { attrs: { "data-label": "Severity" } }, [sevPill(f.severity)]),
    el("td", { attrs: { "data-label": "Kind" }, text: KIND_LABELS[f.kind] }),
    el("td", { className: "mono cell-seen", attrs: { "data-label": "Target" }, text: f.target || "–" }),
    el("td", { className: "mono cell-num", attrs: { "data-label": "Reach" }, text: radius && radius.score ? String(radius.score) : "–" }),
  ]);
  return isOpen ? [row, detailRow(f, 6)] : [row];
}

function renderFindings(run) {
  const shown = run.findings.filter(matches)
    .sort((a, b) => STATUSES.indexOf(a.status) - STATUSES.indexOf(b.status) || scoreOf(b) - scoreOf(a) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  document.getElementById("shown").textContent = "Showing " + shown.length + " of " + run.findings.length;
  const host = document.getElementById("findings");
  if (!shown.length) {
    host.replaceChildren(el("div", { className: "empty" }, [el("p", { text: "Nothing matches these filters." }), button("Clear filters", "btn btn-small btn-ghost", clearFilters)]));
    return;
  }
  const head = el("thead", {}, [el("tr", {}, ["Finding", "Verdict", "Severity", "Kind", "Target", "Reach"].map((h) => el("th", { text: h, attrs: { scope: "col" } })))]);
  host.replaceChildren(el("table", { className: "inv-table" }, [head, el("tbody", {}, shown.flatMap(findingRows))]));
}

function revealFinding(id) {
  const f = findingById(id);
  if (!f) return;
  setState({ status: "all", severity: "any", kind: "any", query: "", open: new Set([...state.open, f.uid]) });
  syncControls();
  renderFindings(state.run);
  const toggle = document.getElementById("toggle-" + f.uid);
  if (!toggle) return;
  toggle.scrollIntoView({ block: "center", behavior: prefersReducedMotion() ? "auto" : "smooth" });
  toggle.focus({ preventScroll: true });
}

/* ---------- coverage ---------- */

function factBlock(title, facts) {
  const rows = facts.filter(([, v]) => v !== "" && v !== null && v !== undefined);
  return el("div", { className: "cov-block" }, [
    el("h4", { className: "mini-head", text: title }),
    el("dl", { className: "facts-list" }, rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: String(v) })])),
  ]);
}

function gapsFor(run) {
  const a = run.activity;
  const gaps = [];
  if (!run.reviewer || run.reviewer === "none") gaps.push("No model reviewer ran, so nothing could be confirmed by review.");
  if (a.crawlTruncated) gaps.push("The crawl stopped at its page limit with links still unvisited.");
  gaps.push(...a.skipped.map((s) => "Not sent: " + s));
  gaps.push(...a.steps.filter((s) => /^refused/i.test(s.outcome)).map((s) => "Explorer step " + s.n + " (" + s.summary + ") " + s.outcome));
  if (a.agentStopped && a.agentStopped !== "finished") gaps.push("The explorer stopped early: " + a.agentStopped + ".");
  gaps.push(...a.rejectedHosts.map((h) => "Found but not tested, outside scope: " + h));
  gaps.push(...a.notes.filter((n) => !(a.crawlTruncated && /crawl/i.test(n))));
  return gaps;
}

function renderCoverage(run) {
  const a = run.activity;
  const budget = el("div", { className: "cov-block" }, [
    el("h4", { className: "mini-head", text: "Budget used" }),
    el("ul", { className: "budget" }, run.budget.filter(([, , limit]) => limit).map(([label, used, limit]) => el("li", {}, [
      el("span", { className: "budget-label", text: label }),
      el("span", { className: "budget-value mono", text: used.toLocaleString("en") + " / " + limit.toLocaleString("en") }),
      meter(used, limit, "meter-budget"),
    ]))),
  ]);
  const gaps = gapsFor(run);
  document.getElementById("coverage").replaceChildren(
    factBlock("Authorisation and scope", [
      ["Operator", run.operator], ["Statement", run.statement], ["Targets", run.targets.join(", ")],
      ["Hosts", run.scope.hosts.join(", ")], ["Ports", run.scope.ports.join(", ")], ["CIDRs", run.scope.cidrs.join(", ")],
      ["Source", run.sourceRoot], ["Reviewer", run.reviewer && run.reviewer !== "none" ? "a model reviewer" : "none"],
    ]),
    budget,
    factBlock("What it covered", [
      ["Pages crawled", a.pagesCrawled ? a.pagesCrawled + (a.crawlTruncated ? " (limit reached)" : "") : ""],
      ["Endpoints", a.endpoints.length || ""], ["Hosts found", a.discoveredHosts.join(", ")],
      ["Packages read", a.packages || ""], ["Explorer steps", a.steps.length || ""],
    ]),
    el("div", { className: "cov-block cov-gaps" }, [
      el("h4", { className: "mini-head", text: "Did not do" }),
      el("ul", { className: "gap-list" }, gaps.length ? gaps.map((g) => el("li", { text: g })) : [el("li", { text: "The run recorded no gaps." })]),
    ]),
  );
}

/* ---------- controls and loading ---------- */

function syncControls() {
  for (const seg of document.querySelectorAll(".seg")) seg.setAttribute("aria-pressed", String(seg.dataset.status === state.status));
  document.getElementById("query").value = state.query;
  document.getElementById("severity").value = state.severity;
  document.getElementById("kind").value = state.kind;
}

function clearFilters() {
  setState({ status: "all", query: "", severity: "any", kind: "any" });
  syncControls();
  renderFindings(state.run);
}

function render() {
  const run = state.run;
  document.getElementById("run-heading").textContent = run.targets[0] || run.sourceRoot || "Saved run";
  document.getElementById("run-id").textContent = run.id;
  document.getElementById("source-badge").textContent = state.isSample ? "Sample" : "Your file";
  document.getElementById("reset").hidden = state.isSample;
  syncControls();
  renderVerdicts(run);
  renderMap(run);
  renderFixFirst(run);
  renderGate(run);
  renderTrail(run);
  renderFindings(run);
  renderCoverage(run);
}

function say(message) {
  document.getElementById("status").textContent = message;
}

function load(run, isSample) {
  setState({ run, isSample, status: "all", query: "", severity: "any", kind: "any", open: new Set(), trail: null });
  render();
}

async function openFile(file) {
  if (!file) return;
  try {
    if (file.size > MAX_FILE_BYTES) throw new Error("That file is too large to be a run this page can show.");
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      throw new Error("That file is not JSON. Open run.json from a run directory saved by vajra scan -data DIR.");
    }
    load(cleanRun(parsed), false);
    say("Showing " + file.name.slice(0, 120) + ". It was read in this tab and not sent anywhere.");
    document.getElementById("run").scrollIntoView();
  } catch (error) {
    say(error.message);
  }
}

function showSample() {
  try {
    load(cleanRun(window.VAJRA_SAMPLE), true);
    say("");
  } catch (error) {
    say("The sample run could not be shown: " + error.message);
  }
}

function wireControls() {
  for (const seg of document.querySelectorAll(".seg")) {
    seg.addEventListener("click", () => {
      setState({ status: STATUSES.includes(seg.dataset.status) ? seg.dataset.status : "all" });
      syncControls();
      renderFindings(state.run);
    });
  }
  document.getElementById("query").addEventListener("input", (event) => {
    setState({ query: event.target.value.slice(0, 200) });
    renderFindings(state.run);
  });
  document.getElementById("severity").addEventListener("change", (event) => {
    setState({ severity: Object.hasOwn(SEVERITY_FILTERS, event.target.value) ? event.target.value : "any" });
    renderFindings(state.run);
  });
  document.getElementById("kind").addEventListener("change", (event) => {
    setState({ kind: Object.hasOwn(KIND_LABELS, event.target.value) ? event.target.value : "any" });
    renderFindings(state.run);
  });
  document.getElementById("trail-select").addEventListener("change", (event) => {
    const f = state.run.findings.find((x) => x.uid === event.target.value);
    if (f) { setState({ trail: f.id }); renderTrail(state.run); }
  });
  document.getElementById("file").addEventListener("change", (event) => {
    openFile(event.target.files[0]);
    event.target.value = "";
  });
  document.getElementById("reset").addEventListener("click", showSample);
}

function wireCopy() {
  const copy = document.getElementById("copy");
  const command = document.getElementById("command-text");
  const done = (message) => {
    copy.textContent = message;
    window.setTimeout(() => { copy.textContent = "Copy"; }, 1600);
  };
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(command.textContent);
      done("Copied");
    } catch {
      const range = document.createRange();
      range.selectNodeContents(command);
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      done("Selected");
    }
  });
}

function wireDrop() {
  const overlay = document.getElementById("drop");
  let depth = 0;
  const carriesFile = (event) => Array.from(event.dataTransfer?.types || []).includes("Files");
  window.addEventListener("dragenter", (event) => {
    if (!carriesFile(event)) return;
    depth += 1;
    overlay.hidden = false;
  });
  window.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    overlay.hidden = depth === 0;
  });
  window.addEventListener("dragover", (event) => {
    if (carriesFile(event)) event.preventDefault();
  });
  window.addEventListener("drop", (event) => {
    if (!carriesFile(event)) return;
    event.preventDefault();
    depth = 0;
    overlay.hidden = true;
    openFile(event.dataTransfer.files[0]);
  });
}

wireControls();
wireCopy();
wireDrop();
showSample();
