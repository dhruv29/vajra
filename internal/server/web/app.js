// Vajra web interface. Everything shown about a finding came from a scanner,
// a target or a model, so it is only ever written with textContent or
// setAttribute, never parsed as HTML.

const SVG_NS = "http://www.w3.org/2000/svg";
const STATUSES = ["confirmed", "unconfirmed", "refuted", "out_of_scope"];
const TOKEN_KEY = "vajra-token";
const NODE = { width: 178, height: 46, columnGap: 54, rowGap: 16, pad: 12, maxLabel: 25 };

const $ = (id) => document.getElementById(id);
const label = (value) => String(value).replaceAll("_", " ");

/** Build an element. Children may be nodes or strings; strings become text. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value !== null && value !== undefined && value !== false) node.setAttribute(name, value);
  }
  add(node, ...children);
  return node;
}

/** Append children to a node, skipping any that are null. */
function add(parent, ...children) {
  parent.append(...children.filter((child) => child !== null && child !== undefined));
}

function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  node.append(...children);
  return node;
}

// ---- Token and URL state -------------------------------------------------

/** The token arrives once in the URL fragment and is then kept out of it. */
function takeToken(params) {
  const fromURL = params.get("token");
  if (fromURL) {
    sessionStorage.setItem(TOKEN_KEY, fromURL);
    params.delete("token");
    history.replaceState(null, "", "#" + params.toString());
  }
  return sessionStorage.getItem(TOKEN_KEY);
}

function readState() {
  const params = new URLSearchParams(location.hash.slice(1));
  return { params, run: params.get("run"), finding: params.get("finding"), status: params.get("status") };
}

function writeState(changes) {
  const { params } = readState();
  for (const [key, value] of Object.entries(changes)) {
    if (value) params.set(key, value);
    else params.delete(key);
  }
  location.hash = params.toString();
}

// ---- API -----------------------------------------------------------------

let token = null;

async function api(path) {
  const response = await fetch(path, { headers: { Authorization: "Bearer " + token } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return response;
}

function notify(message) {
  const notice = $("notice");
  notice.textContent = message || "";
  notice.hidden = !message;
}

// ---- Runs rail -----------------------------------------------------------

function renderRuns(runs, currentID) {
  const list = $("runs");
  list.replaceChildren();
  if (runs.length === 0) {
    list.append(el("li", { class: "empty" }, "No saved runs yet. Run a scan with -data to save one."));
    return;
  }
  for (const run of runs) {
    const confirmed = run.counts?.confirmed || 0;
    const button = el("button", { type: "button", "aria-current": run.id === currentID ? "true" : null },
      el("span", { class: "when" }, new Date(run.generated_at).toLocaleString()),
      el("span", { class: "tally" + (confirmed ? "" : " zero"), title: "Confirmed findings" }, String(confirmed)),
      el("span", { class: "target" }, (run.targets || []).join(", ")));
    button.addEventListener("click", () => writeState({ run: run.id, finding: null, status: null }));
    list.append(el("li", {}, button));
  }
}

// ---- Overview ------------------------------------------------------------

function renderOverview(run, statusFilter) {
  const report = run.report;
  const counts = report.summary || {};
  const attention = (counts.confirmed || 0) + (counts.unconfirmed || 0);
  $("overview-eyebrow").textContent = "Run " + run.id;
  $("overview-heading").textContent =
    attention === 1 ? "1 finding needs attention" : `${attention} findings need attention`;

  const meta = $("overview-meta");
  meta.replaceChildren();
  const rows = [
    ["Generated", new Date(report.generated_at).toLocaleString()],
    ["Operator", report.authorization?.operator],
    ["Authorisation", report.authorization?.statement],
    ["Targets", (report.targets || []).join(", ")],
    ["Reviewer", report.refuter === "none" ? "none configured: nothing can be confirmed" : report.refuter],
  ];
  for (const [name, value] of rows) meta.append(el("dt", {}, name), el("dd", {}, value || "not recorded"));

  const tiles = $("counts");
  tiles.replaceChildren();
  for (const status of STATUSES) {
    const pressed = statusFilter === status;
    const tile = el("button", { type: "button", "aria-pressed": String(pressed) },
      el("b", {}, String(counts[status] || 0)), el("span", {}, label(status)));
    tile.addEventListener("click", () => writeState({ status: pressed ? null : status, finding: null }));
    tiles.append(tile);
  }
  $("overview").hidden = false;
}

// ---- Findings list -------------------------------------------------------

function radiusOf(run, findingID) {
  return (run.radii || []).find((radius) => radius.finding_id === findingID) || { score: 0, reach: [] };
}

/** Findings ordered by blast radius, with dismissed results last. */
function orderedFindings(run, statusFilter) {
  const dismissed = (finding) => (finding.status === "refuted" || finding.status === "out_of_scope" ? 1 : 0);
  return (run.report.findings || [])
    .filter((finding) => !statusFilter || finding.status === statusFilter)
    .map((finding) => ({ finding, radius: radiusOf(run, finding.id) }))
    .sort((a, b) => dismissed(a.finding) - dismissed(b.finding) || b.radius.score - a.radius.score);
}

function renderFindings(items, currentID) {
  const list = $("findings");
  list.replaceChildren();
  if (items.length === 0) {
    list.append(el("li", { class: "empty" }, "No findings with this status."));
    return;
  }
  for (const { finding, radius } of items) {
    const button = el("button",
      { type: "button", class: finding.status, "aria-current": finding.id === currentID ? "true" : null },
      el("span", { class: "title" }, finding.title || finding.rule_id),
      el("span", { class: "score" + (radius.score ? "" : " none"), title: "Blast radius score out of 100" }, String(radius.score)),
      el("span", { class: "where" }, finding.target));
    button.addEventListener("click", () => writeState({ finding: finding.id }));
    list.append(el("li", {}, button));
  }
}

// ---- Blast radius graph --------------------------------------------------

function truncate(text) {
  return text.length > NODE.maxLabel ? text.slice(0, NODE.maxLabel - 1) + "…" : text;
}

/** Lay hops out in columns by depth and draw an edge from each hop's source. */
function renderGraph(reach) {
  const columns = new Map();
  for (const hop of reach) {
    if (!columns.has(hop.depth)) columns.set(hop.depth, []);
    columns.get(hop.depth).push(hop);
  }
  const depths = [...columns.keys()].sort((a, b) => a - b);
  const tallest = Math.max(...[...columns.values()].map((column) => column.length));
  const width = depths.length * NODE.width + (depths.length - 1) * NODE.columnGap + NODE.pad * 2;
  const height = tallest * NODE.height + (tallest - 1) * NODE.rowGap + NODE.pad * 2;

  const position = new Map();
  depths.forEach((depth, columnIndex) => {
    const column = columns.get(depth);
    const columnHeight = column.length * NODE.height + (column.length - 1) * NODE.rowGap;
    const top = (height - columnHeight) / 2;
    column.forEach((hop, rowIndex) => {
      position.set(hop.asset_id, {
        x: NODE.pad + columnIndex * (NODE.width + NODE.columnGap),
        y: top + rowIndex * (NODE.height + NODE.rowGap),
      });
    });
  });

  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img" },
    svg("title", {}, `Blast radius: ${reach.length} asset(s)`));
  for (const hop of reach) {
    const from = position.get(hop.from);
    const to = position.get(hop.asset_id);
    if (!from || !to) continue;
    const x1 = from.x + NODE.width, y1 = from.y + NODE.height / 2;
    const x2 = to.x, y2 = to.y + NODE.height / 2;
    const bend = (x2 - x1) / 2;
    root.append(svg("path", {
      class: "edge " + hop.confidence,
      d: `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`,
    }));
  }
  for (const hop of reach) {
    const at = position.get(hop.asset_id);
    const name = svg("text", { class: "name", x: at.x + 10, y: at.y + 19 });
    name.textContent = truncate(hop.name);
    const kind = svg("text", { class: "kind", x: at.x + 10, y: at.y + 35 });
    kind.textContent = hop.kind + (hop.via ? " · " + label(hop.via) : "");
    const tip = svg("title", {});
    tip.textContent = `${hop.name}: ${hop.why}`;
    root.append(svg("g", { class: `node ${hop.confidence}` + (hop.depth === 0 ? " origin" : "") },
      svg("rect", { x: at.x, y: at.y, width: NODE.width, height: NODE.height, rx: 3 }), name, kind, tip));
  }
  return el("div", { class: "graph" }, root);
}

function renderReachTable(reach) {
  const body = el("tbody");
  for (const hop of reach) {
    body.append(el("tr", {},
      el("td", {}, hop.name), el("td", { class: "fixed" }, hop.kind),
      el("td", { class: "fixed" }, el("span", { class: "conf " + hop.confidence }, hop.confidence)),
      el("td", {}, hop.why)));
  }
  return el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, el("th", {}, "Reachable asset"), el("th", {}, "Kind"), el("th", {}, "Confidence"), el("th", {}, "Why"))),
    body));
}

// ---- Finding detail ------------------------------------------------------

function evidenceBlock(title, text) {
  return text ? el("details", {}, el("summary", {}, title), el("pre", {}, text)) : null;
}

function renderDetail(item) {
  const body = $("detail-body");
  body.replaceChildren();
  if (!item) {
    body.append(el("p", { class: "placeholder" }, "Select a finding to see how it was verified and what it reaches."));
    return;
  }
  const { finding, radius } = item;
  const reach = radius.reach || [];
  const fill = el("i");
  fill.style.transform = `scaleX(${radius.score / 100})`;

  const steps = el("ol", { class: "steps" });
  for (const verdict of finding.verdicts || []) {
    steps.append(el("li", { class: verdict.outcome },
      el("strong", {}, verdict.stage), `: ${verdict.outcome}. ${verdict.reason}`));
  }

  add(body,
    el("div", { class: "tags" },
      el("span", { class: "tag " + finding.status }, label(finding.status)),
      el("span", { class: "tag" }, finding.severity),
      radius.capability ? el("span", { class: "tag" }, label(radius.capability)) : null),
    el("h3", {}, finding.title || finding.rule_id),
    el("p", { class: "where" }, finding.target),

    el("div", { class: "radius-head" },
      el("p", { class: "eyebrow" }, "Blast radius"),
      el("div", { class: "radius-score" }, String(radius.score), el("small", {}, "/ 100"))),
    el("div", { class: "meter", role: "presentation" }, fill),
    el("p", {}, radius.summary || "No blast radius was computed."),
    radius.capability_basis ? el("p", { class: "basis" }, "Classified from " + radius.capability_basis + ".") : null,
  );
  if (reach.length > 1) {
    body.append(
      el("div", { class: "legend", "aria-hidden": "true" },
        el("span", { class: "proven" }, "proven"), el("span", { class: "inferred" }, "inferred"), el("span", { class: "assumed" }, "assumed")),
      renderGraph(reach), renderReachTable(reach));
  }
  add(body,
    el("h4", {}, "Verification"), steps,
    el("h4", {}, "Evidence"),
    evidenceBlock("Request", finding.evidence?.request),
    evidenceBlock("Response", finding.evidence?.response),
    !finding.evidence?.request && !finding.evidence?.response ? el("p", { class: "basis" }, "The scanner captured no request or response.") : null,
  );
}

// ---- Run reach -----------------------------------------------------------

function reachColumn(title, entries, kind) {
  const column = el("div", {}, el("h3", {}, title));
  if (entries.length === 0) {
    column.append(el("p", {}, "None."));
    return column;
  }
  const busiest = Math.max(...entries.map((entry) => entry.count));
  for (const entry of entries) {
    const fill = el("i");
    fill.style.width = `${Math.max(4, (entry.count / busiest) * 100)}%`;
    column.append(el("div", { class: "bar " + kind },
      el("span", { class: "name" }, entry.target), el("span", { class: "track" }, fill), el("span", { class: "n" }, String(entry.count)),
      entry.reason ? el("span", { class: "why" }, entry.reason) : null));
  }
  return column;
}

function renderRunReach(run) {
  const body = $("reach-body");
  body.replaceChildren();
  if (!run.reach) {
    body.append(el("p", {}, "No gate audit log was saved with this run. Pass -gate-audit to scan to record what it touched."));
  } else {
    body.append(
      el("p", {}, `${run.reach.allowed_total} connection(s) allowed, ${run.reach.denied_total} refused by the scope gate.`),
      el("div", { class: "reach-grid" },
        reachColumn("Allowed", run.reach.allowed || [], "allowed"),
        reachColumn("Refused", run.reach.denied || [], "denied")));
  }
  $("reach").hidden = false;
}

// ---- Export --------------------------------------------------------------

async function exportReport(runID, format) {
  try {
    const response = await api(`/api/runs/${encodeURIComponent(runID)}/report?format=${format}`);
    const url = URL.createObjectURL(await response.blob());
    const link = el("a", { href: url, download: `vajra-${runID}.${format}` });
    link.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    notify("The report could not be exported: " + error.message);
  }
}

// ---- Page ----------------------------------------------------------------

let loaded = { id: null, run: null };

async function render() {
  const state = readState();
  try {
    const runs = await (await api("/api/runs")).json();
    const runID = state.run || runs[0]?.id || null;
    renderRuns(runs, runID);
    if (!runID) {
      for (const id of ["overview", "workbench", "reach", "exports"]) $(id).hidden = true;
      return;
    }
    if (loaded.id !== runID) {
      loaded = { id: runID, run: await (await api("/api/runs/" + encodeURIComponent(runID))).json() };
    }
    const run = loaded.run;
    const items = orderedFindings(run, state.status);
    const current = items.find((item) => item.finding.id === state.finding) || items[0] || null;
    renderOverview(run, state.status);
    renderFindings(items, current?.finding.id);
    renderDetail(current);
    renderRunReach(run);
    $("workbench").hidden = false;
    $("exports").hidden = false;
    notify("");
  } catch (error) {
    notify(error.status === 401
      ? "This session has no valid access token. Open the link that vajra serve printed."
      : "Could not load: " + error.message);
  }
}

function start() {
  token = takeToken(readState().params);
  if (!token) {
    notify("Open the link that vajra serve printed: it carries the access token for this session.");
    return;
  }
  for (const button of $("exports").querySelectorAll("button")) {
    button.addEventListener("click", () => loaded.id && exportReport(loaded.id, button.dataset.format));
  }
  window.addEventListener("hashchange", render);
  render();
}

start();
