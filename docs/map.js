// Reach map: findings, the asset each sits on, and what each can reach, laid
// out left to right by distance, with attack chains as paths you can step
// through. Loaded before app.js and called from its render(); it uses app.js
// helpers (el, svg, button, statusPill, sevPill, dataChips, human, radiusOf,
// findingById, openTrail, goTo, STATUS_LABELS, SEVERITIES) at call time.
// Everything from the run goes in as text or as numeric SVG attributes; colour
// and line style come from classes in app.css. Below 720px the SVG is hidden
// and the detail panel, a vertical path view, carries the same information.
"use strict";

const MAPG = { width: 960, top: 34, pad: 4, colGap: 26, rowH: 66, nodeH: 56, findingWeight: 1.45, maxPerCol: 10, maxFindings: 12, maxCol: 5 };
const COL_TITLES = ["Finding", "Found on", "1 step away", "2 steps away", "3 steps away", "4+ steps away"];
const LEVEL_TITLES = ["Found on", "1 step away", "2 steps away", "3 steps away", "4 or more steps away"];
const CONF_RANK = { proven: 0, inferred: 1, assumed: 2 };
const NAME_CHAR = 7.4;
const SUB_CHAR = 6.1;

const mapState = { sel: null, model: null, nodes: new Map(), edges: [] };

function clip(value, width, charW) {
  const max = Math.max(3, Math.floor(width / charW));
  return value.length > max ? value.slice(0, max - 1) + "…" : value;
}

/** Breaks a label into at most two lines at spaces, dots, slashes or dashes. */
function wrap(value, width, charW) {
  const max = Math.max(4, Math.floor(width / charW));
  if (value.length <= max) return [value];
  const tokens = value.split(/(?<=[\s./_-])/);
  let first = "";
  while (tokens.length && (first + tokens[0]).length <= max) first += tokens.shift();
  if (!first) return [clip(value, width, charW)];
  return [first.trimEnd(), clip(tokens.join(""), width, charW)];
}

/** One or two name lines; a single line sits lower so the box looks balanced. */
function nameLines(lines, x, y, className) {
  const top = lines.length === 1 ? y + 7 : y + 2;
  return lines.map((line, i) => svg("text", { x, y: top + i * 14, class: className }, [line]));
}

/** A short, readable name for an asset; the full name stays in the title and detail. */
function shortName(asset) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/]+)(\/.*)?$/i.exec(asset.name);
  if (!m) return asset.name;
  if (asset.kind === "endpoint" && m[2]) return m[2];
  return m[1] + (m[2] && m[2] !== "/" ? m[2] : "");
}

function hostOf(asset) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:]+)/i.exec(asset.name);
  return m ? m[1] : "";
}

/* ---------- model ---------- */

function parentOf(hop, hops, edgeSet, originId) {
  if (hop.from && hops.some((h) => h.assetId === hop.from)) return hop.from;
  const candidates = hops.filter((h) => h.depth === hop.depth - 1 && h.assetId !== hop.assetId)
    .filter((h) => edgeSet.has(h.assetId + "\u0000" + hop.assetId) || edgeSet.has(hop.assetId + "\u0000" + h.assetId))
    .map((h) => h.assetId).sort();
  return candidates[0] || originId;
}

function buildModel(run) {
  const assets = new Map(run.graph.assets.map((a) => [a.id, a]));
  const edgeSet = new Set(run.graph.edges.map((e) => e.from + "\u0000" + e.to));
  const eligible = run.findings
    .filter((f) => f.status === "confirmed" || f.status === "unconfirmed")
    .map((f) => ({ f, r: radiusOf(f.id) }))
    .filter(({ r }) => r && r.originId && r.reach.length)
    .sort((a, b) => b.r.score - a.r.score || SEVERITIES.indexOf(a.f.severity) - SEVERITIES.indexOf(b.f.severity) || a.f.title.localeCompare(b.f.title));
  const mapped = eligible.slice(0, MAPG.maxFindings);
  const depthOf = new Map();
  const edges = new Map();
  const addEdge = (from, to, owner, conf) => {
    if (from === to) return;
    const key = from + "\u0000" + to;
    const prior = edges.get(key) || { key, a: from, b: to, owners: new Map() };
    edges.set(key, { ...prior, owners: new Map([...prior.owners, [owner, conf]]) });
  };
  for (const { f, r } of mapped) {
    for (const h of r.reach) {
      if (!assets.has(h.assetId)) assets.set(h.assetId, { id: h.assetId, kind: h.kind, name: h.name, origin: "derived", dataClasses: [] });
      depthOf.set(h.assetId, Math.min(depthOf.get(h.assetId) ?? 99, h.depth));
    }
    if (!depthOf.has(r.originId)) depthOf.set(r.originId, 0);
    if (!assets.has(r.originId)) assets.set(r.originId, { id: r.originId, kind: "", name: r.originId, origin: "derived", dataClasses: [] });
    const originHop = r.reach.find((h) => h.assetId === r.originId);
    addEdge("f:" + f.id, "a:" + r.originId, f.id, originHop ? originHop.confidence : "assumed");
    for (const h of r.reach) {
      if (h.assetId === r.originId) continue;
      addEdge("a:" + parentOf(h, r.reach, edgeSet, r.originId), "a:" + h.assetId, f.id, h.confidence);
    }
  }
  return { assets, mapped, hiddenFindings: eligible.length - mapped.length, depthOf, edges: [...edges.values()] };
}

/* ---------- layout ---------- */

function layout(model) {
  const columns = [[]];
  for (const [id, depth] of model.depthOf) {
    const col = Math.min(MAPG.maxCol, depth + 1);
    while (columns.length <= col) columns.push([]);
    columns[col].push("a:" + id);
  }
  const colCount = Math.max(3, columns.length);
  const unit = (MAPG.width - 2 * MAPG.pad) / (colCount - 1 + MAPG.findingWeight);
  const colX = Array.from({ length: colCount }, (_, i) => MAPG.pad + (i === 0 ? 0 : (MAPG.findingWeight + i - 1) * unit));
  const colWidth = (i) => (i === 0 ? MAPG.findingWeight : 1) * unit - MAPG.colGap;
  const scoreOfKey = new Map();
  for (const e of model.edges) {
    for (const owner of e.owners.keys()) {
      const score = radiusOf(owner)?.score ?? 0;
      for (const k of [e.a, e.b]) scoreOfKey.set(k, Math.max(scoreOfKey.get(k) ?? 0, score));
    }
  }
  const parentsOf = (key) => model.edges.filter((e) => e.b === key).map((e) => e.a);
  const placed = new Map();
  const overflow = [];
  const rows = Math.min(MAPG.maxPerCol, Math.max(model.mapped.length, ...columns.map((c) => c.length)));
  const height = MAPG.top + rows * MAPG.rowH + 8;
  const place = (col, keys) => {
    const shown = keys.length > MAPG.maxPerCol ? keys.slice(0, MAPG.maxPerCol - 1) : keys;
    const slots = shown.length + (keys.length > shown.length ? 1 : 0);
    const y0 = MAPG.top + ((rows - slots) * MAPG.rowH) / 2;
    const w = colWidth(col);
    shown.forEach((key, i) => placed.set(key, { x: colX[col], y: y0 + i * MAPG.rowH + (MAPG.rowH - MAPG.nodeH) / 2, w, h: MAPG.nodeH, col }));
    if (keys.length > shown.length) overflow.push({ x: colX[col], y: y0 + shown.length * MAPG.rowH + (MAPG.rowH - MAPG.nodeH) / 2, w, extra: keys.length - shown.length });
  };
  const centre = (key) => { const p = placed.get(key); return p ? p.y : null; };
  const bary = (key) => {
    const ys = parentsOf(key).map(centre).filter((y) => y !== null);
    return ys.length ? ys.reduce((s, y) => s + y, 0) / ys.length : 1e9;
  };
  const name = (key) => model.assets.get(key.slice(2))?.name || key;
  if (columns[1]) place(1, [...columns[1]].sort((a, b) => (scoreOfKey.get(b) ?? 0) - (scoreOfKey.get(a) ?? 0) || name(a).localeCompare(name(b))));
  const findingKeys = model.mapped.map(({ f }) => "f:" + f.id);
  const originY = (key) => {
    const e = model.edges.find((x) => x.a === key);
    return e ? centre(e.b) ?? 1e9 : 1e9;
  };
  place(0, findingKeys.map((k, i) => [k, i]).sort((a, b) => originY(a[0]) - originY(b[0]) || a[1] - b[1]).map(([k]) => k));
  for (let col = 2; col < columns.length; col += 1) {
    place(col, [...columns[col]].sort((a, b) => bary(a) - bary(b) || name(a).localeCompare(name(b))));
  }
  return { placed, overflow, height, colCount, colX };
}

/* ---------- drawing ---------- */

function edgePath(p, q) {
  const ax = p.x + p.w, ay = p.y + p.h / 2;
  if (q.col > p.col) {
    const bx = q.x, by = q.y + q.h / 2, mid = (ax + bx) / 2;
    return `M${ax} ${ay} C${mid} ${ay} ${mid} ${by} ${bx} ${by}`;
  }
  const bx = q.x + q.w, by = q.y + q.h / 2, out = Math.min(MAPG.colGap - 6, 14 + Math.abs(by - ay) / 6);
  return `M${ax} ${ay} C${ax + out} ${ay} ${bx + out} ${by} ${bx} ${by}`;
}

function bestConf(edge) {
  return [...edge.owners.values()].sort((a, b) => CONF_RANK[a] - CONF_RANK[b])[0] || "assumed";
}

function drawFindingNode(f, r, box) {
  const lines = wrap(f.title, box.w - 50, NAME_CHAR);
  const subLow = lines.length > 1;
  const label = f.title + ", " + STATUS_LABELS[f.status].toLowerCase() + ", " + f.severity + ", reach score " + r.score;
  return svg("g", { class: "map-node node-finding", tabindex: 0, role: "button", "aria-pressed": "false", "aria-label": label, "data-sev": f.severity, "data-status": f.status }, [
    svg("title", {}, [f.title]),
    svg("rect", { x: box.x, y: box.y, width: box.w, height: box.h, rx: 6, class: "node-box" }),
    svg("rect", { x: box.x, y: box.y + 6, width: 3, height: box.h - 12, rx: 1.5, class: "node-sev" }),
    ...nameLines(lines, box.x + 11, box.y + 17, "node-name"),
    svg("text", { x: box.x + 11, y: box.y + (subLow ? 47 : 41), class: "node-sub" }, [clip(STATUS_LABELS[f.status].toLowerCase() + " · " + f.severity, box.w - 50, SUB_CHAR)]),
    svg("text", { x: box.x + box.w - 9, y: box.y + 33, "text-anchor": "end", class: "node-score" }, [String(r.score)]),
    svg("g", { class: "step-badge", "aria-hidden": "true" }, [
      svg("circle", { cx: box.x, cy: box.y, r: 9 }),
      svg("text", { x: box.x, y: box.y + 3.5, "text-anchor": "middle" }, [""]),
    ]),
  ]);
}

function drawAssetNode(asset, box) {
  const host = asset.kind === "endpoint" ? hostOf(asset) : "";
  const sub = [asset.kind || "asset", host || asset.dataClasses.map(human).join(", ")].filter(Boolean).join(" · ");
  const declared = asset.origin === "declared";
  const lines = wrap(shortName(asset), box.w - 18, NAME_CHAR);
  const subLow = lines.length > 1;
  return svg("g", {
    class: "map-node node-asset" + (declared ? " is-declared" : ""), tabindex: 0, role: "button", "aria-pressed": "false",
    "aria-label": asset.name + ", " + (asset.kind || "asset") + (declared ? ", declared in the run's topology" : ""),
  }, [
    svg("title", {}, [asset.name]),
    svg("rect", { x: box.x, y: box.y, width: box.w, height: box.h, rx: 6, class: "node-box" }),
    ...nameLines(lines, box.x + 10, box.y + 17, "node-name"),
    svg("text", { x: box.x + 10, y: box.y + (subLow ? 47 : 41), class: "node-sub" }, [clip(sub, box.w - 18, SUB_CHAR)]),
  ]);
}

/* ---------- selection and highlight ---------- */

function selectionSets(sel) {
  const model = mapState.model;
  if (!sel || !model) return null;
  if (sel.type === "finding") {
    const on = new Set(["f:" + sel.id]);
    const conf = new Map();
    for (const e of model.edges) {
      if (!e.owners.has(sel.id)) continue;
      on.add(e.a); on.add(e.b); conf.set(e.key, e.owners.get(sel.id));
    }
    return { on, conf, current: new Set(["f:" + sel.id]), steps: new Map() };
  }
  const chain = state.run.chains[sel.index];
  if (!chain) return null;
  const owners = new Set(chain.steps.map((s) => s.findingId));
  const on = new Set([...chain.steps.map((s) => "f:" + s.findingId), ...chain.reach.map((id) => "a:" + id)]);
  const conf = new Map();
  for (const e of model.edges) {
    const mine = [...e.owners].filter(([o]) => owners.has(o));
    if (mine.length && on.has(e.a) && on.has(e.b)) conf.set(e.key, mine.map(([, c]) => c).sort((a, b) => CONF_RANK[a] - CONF_RANK[b])[0]);
  }
  const step = chain.steps[sel.step] || chain.steps[0];
  const current = new Set(["f:" + step.findingId, "a:" + step.originId]);
  const steps = new Map(chain.steps.map((s, i) => ["f:" + s.findingId, i + 1]));
  return { on, conf, current, steps };
}

function applyHighlight(sel) {
  const canvas = document.getElementById("map-svg");
  if (!canvas) return;
  const sets = selectionSets(sel);
  canvas.classList.toggle("is-focusing", Boolean(sets));
  for (const [key, node] of mapState.nodes) {
    node.classList.toggle("is-on", Boolean(sets) && sets.on.has(key));
    node.classList.toggle("is-current", Boolean(sets) && sets.current.has(key));
    const isSelected = mapState.sel && ((mapState.sel.type === "finding" && key === "f:" + mapState.sel.id));
    node.setAttribute("aria-pressed", String(Boolean(isSelected)));
    const badge = node.querySelector(".step-badge");
    if (badge) {
      const n = sets ? sets.steps.get(key) : undefined;
      badge.classList.toggle("is-shown", n !== undefined);
      badge.querySelector("text").textContent = n === undefined ? "" : String(n);
    }
  }
  for (const edge of mapState.edges) {
    const conf = sets ? sets.conf.get(edge.key) : undefined;
    edge.node.classList.toggle("is-on", conf !== undefined);
    edge.node.setAttribute("data-conf", conf || edge.best);
  }
}

function select(sel, focusId) {
  mapState.sel = sel;
  applyHighlight(sel);
  renderPicks();
  renderDetail();
  if (focusId) document.getElementById(focusId)?.focus();
}

function showOnMap(findingId) {
  select({ type: "finding", id: findingId });
  goTo("map-heading");
}

/* ---------- picker chips (all widths; the only way to choose on a phone) ---------- */

function pickChip(label, sub, pressed, sel, id, extra = {}) {
  const node = el("button", { className: "pick", attrs: { type: "button", id, "aria-pressed": String(pressed), ...extra } }, [
    el("span", { className: "pick-label", text: label }), sub ? el("span", { className: "pick-sub", text: sub }) : null,
  ]);
  node.addEventListener("click", () => select(pressed ? null : sel, id));
  node.addEventListener("mouseenter", () => applyHighlight(sel));
  node.addEventListener("mouseleave", () => applyHighlight(mapState.sel));
  return el("li", {}, [node]);
}

function renderPicks() {
  const sel = mapState.sel;
  const chains = state.run.chains;
  document.getElementById("chain-picks").replaceChildren(...(chains.length ? chains.map((c, i) => pickChip(
    "Chain " + (i + 1), c.steps.length + " steps · " + c.reach.length + " assets",
    Boolean(sel && sel.type === "chain" && sel.index === i), { type: "chain", index: i, step: 0 }, "pick-chain-" + i,
  )) : [el("li", { className: "panel-note", text: "No confirmed findings combine into a chain." })]));
  const mapped = mapState.model ? mapState.model.mapped : [];
  document.getElementById("finding-picks").replaceChildren(...mapped.map(({ f, r }) => pickChip(
    f.title, STATUS_LABELS[f.status].toLowerCase() + " · " + r.score,
    Boolean(sel && sel.type === "finding" && sel.id === f.id), { type: "finding", id: f.id }, "pick-finding-" + f.uid, { "data-sev": f.severity },
  )));
}

/* ---------- detail: the vertical path view ---------- */

function hopItem(name, kind, conf, why) {
  return el("li", { className: "hop", attrs: { "data-conf": conf } }, [
    el("span", { className: "hop-name", text: name }),
    el("span", { className: "hop-meta" }, [el("span", { className: "kind-tag", text: kind || "asset" }), el("span", { className: "conf-tag", attrs: { "data-conf": conf }, text: conf })]),
    why ? el("span", { className: "hop-why", text: why }) : null,
  ]);
}

function findingDetail(f) {
  const r = radiusOf(f.id);
  const levels = new Map();
  for (const h of r.reach) {
    const d = Math.min(4, h.depth);
    levels.set(d, [...(levels.get(d) || []), h]);
  }
  const path = [...levels.keys()].sort((a, b) => a - b).map((d) => el("li", { className: "level" }, [
    el("span", { className: "level-label", text: LEVEL_TITLES[d] }),
    el("ul", { className: "hops" }, levels.get(d).map((h) => hopItem(h.name, h.kind, h.confidence, h.why))),
  ]));
  return [
    el("p", { className: "detail-kicker", text: "Blast radius · score " + r.score }),
    el("h4", { className: "map-detail-title", text: f.title }),
    el("p", { className: "risk-meta" }, [statusPill(f.status), sevPill(f.severity)]),
    el("p", { className: "map-detail-meta", text: "Treated as " + human(r.capability || "unclassified") + (r.basis ? ": " + r.basis : "") + "." }),
    el("ol", { className: "path" }, path),
    r.dataClasses.length ? el("h5", { text: "Data within reach" }) : null,
    r.dataClasses.length ? dataChips(r.dataClasses) : null,
    el("p", { className: "fix-actions" }, [button("Verification trail", "link-button", () => openTrail(f.id))]),
  ];
}

function chainDetail(index, stepIndex) {
  const chain = state.run.chains[index];
  const steps = chain.steps.map((s, i) => {
    const f = findingById(s.findingId);
    const origin = mapState.model?.assets.get(s.originId);
    const go = el("button", { className: "step-btn", attrs: { type: "button", id: "chain-step-" + i, "aria-pressed": String(i === stepIndex) } }, [
      el("span", { className: "step-n", text: String(i + 1) }),
      el("span", { className: "step-title", text: f ? f.title : s.title }),
    ]);
    go.addEventListener("click", () => select({ type: "chain", index, step: i }, "chain-step-" + i));
    return el("li", { className: "chain-step" + (i === stepIndex ? " is-current" : "") }, [
      go,
      el("span", { className: "step-on mono", text: "on " + (origin ? origin.name : s.originId) }),
      el("span", { className: "hop-why", text: s.why }),
      f ? el("span", { className: "step-meta" }, [statusPill(f.status), sevPill(f.severity)]) : null,
    ]);
  });
  const nav = (label, to, id) => {
    const b = button(label, "btn btn-small btn-ghost", () => select({ type: "chain", index, step: to }, id), { id });
    b.disabled = to < 0 || to >= chain.steps.length;
    return b;
  };
  const reached = chain.reach.map((id) => mapState.model?.assets.get(id)).filter(Boolean);
  return [
    el("p", { className: "detail-kicker", text: "Attack chain " + (index + 1) + " of " + state.run.chains.length + " · score " + chain.score }),
    el("h4", { className: "map-detail-title", text: chain.steps.length + " findings that combine" }),
    el("ol", { className: "chain-steps" }, steps),
    el("div", { className: "step-nav" }, [
      nav("Previous step", stepIndex - 1, "chain-prev"),
      el("span", { className: "step-count", text: "Step " + (stepIndex + 1) + " of " + chain.steps.length }),
      nav("Next step", stepIndex + 1, "chain-next"),
    ]),
    el("h5", { text: "Together they reach " + chain.reach.length + " assets" }),
    el("ul", { className: "chips" }, reached.map((a) => el("li", { className: "asset-chip", text: shortName(a) }))),
    chain.dataClasses.length ? dataChips(chain.dataClasses) : null,
  ];
}

function renderDetail() {
  const host = document.getElementById("map-detail");
  const sel = mapState.sel;
  const f = sel && sel.type === "finding" ? findingById(sel.id) : null;
  if (f && radiusOf(f.id)) host.replaceChildren(...findingDetail(f));
  else if (sel && sel.type === "chain" && state.run.chains[sel.index]) host.replaceChildren(...chainDetail(sel.index, sel.step));
  else host.replaceChildren(el("p", { className: "map-detail-empty", text: "Pick an attack chain or a finding to see what it reaches, and how sure the run is of each step." }));
}

/* ---------- nodes ---------- */

function assetSelection(key) {
  const owner = mapState.model.edges.find((e) => (e.a === key || e.b === key) && e.owners.size);
  const ids = owner ? [...owner.owners.keys()] : [];
  const best = mapState.model.mapped.find(({ f }) => ids.includes(f.id));
  return best ? { type: "finding", id: best.f.id } : null;
}

function wireNode(node, key) {
  const selFor = () => (key.startsWith("f:") ? { type: "finding", id: key.slice(2) } : assetSelection(key));
  const choose = () => {
    const sel = selFor();
    const same = sel && mapState.sel && mapState.sel.type === "finding" && mapState.sel.id === sel.id;
    select(same ? null : sel);
    node.focus();
  };
  node.addEventListener("mouseenter", () => applyHighlight(selFor()));
  node.addEventListener("mouseleave", () => applyHighlight(mapState.sel));
  node.addEventListener("focus", () => applyHighlight(selFor()));
  node.addEventListener("blur", () => applyHighlight(mapState.sel));
  node.addEventListener("click", choose);
  node.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); choose(); }
  });
}

function renderMapText(model) {
  const lines = model.mapped.map(({ f, r }) => el("li", {
    text: f.title + " (" + STATUS_LABELS[f.status].toLowerCase() + ", score " + r.score + ") reaches: " +
      r.reach.map((h) => h.name + " (" + h.confidence + ")").join(", ") + ".",
  }));
  const chains = state.run.chains.map((c, i) => el("li", {
    text: "Attack chain " + (i + 1) + ": " + c.steps.map((s) => findingById(s.findingId)?.title || s.title).join(", then ") + ". " + c.summary,
  }));
  document.getElementById("map-text").replaceChildren(...lines, ...chains);
}

function renderMap(run) {
  const model = buildModel(run);
  mapState.model = model;
  mapState.nodes = new Map();
  const host = document.getElementById("map-canvas");
  if (!model.mapped.length) {
    mapState.edges = [];
    mapState.sel = null;
    host.replaceChildren(el("p", { className: "map-detail-empty", text: "No confirmed or unconfirmed finding in this run has a blast radius to draw." }));
  } else {
    const geo = layout(model);
    const heads = COL_TITLES.slice(0, geo.colCount).map((t, i) => svg("text", { x: geo.colX[i], y: 14, class: "col-label" }, [t]));
    const guides = Array.from({ length: geo.colCount - 1 }, (_, i) => svg("line", {
      x1: geo.colX[i + 1] - MAPG.colGap / 2, x2: geo.colX[i + 1] - MAPG.colGap / 2, y1: 22, y2: geo.height - 4, class: "col-guide",
    }));
    mapState.edges = model.edges.filter((e) => geo.placed.has(e.a) && geo.placed.has(e.b)).map((e) => {
      const best = bestConf(e);
      return { key: e.key, best, node: svg("path", { d: edgePath(geo.placed.get(e.a), geo.placed.get(e.b)), class: "map-edge", "data-conf": best }) };
    });
    const nodes = [];
    for (const { f, r } of model.mapped) {
      const box = geo.placed.get("f:" + f.id);
      if (box) nodes.push(["f:" + f.id, drawFindingNode(f, r, box)]);
    }
    for (const [id] of model.depthOf) {
      const box = geo.placed.get("a:" + id);
      if (box) nodes.push(["a:" + id, drawAssetNode(model.assets.get(id), box)]);
    }
    for (const [key, node] of nodes) { mapState.nodes.set(key, node); wireNode(node, key); }
    const more = geo.overflow.map((o) => svg("g", { class: "map-more" }, [
      svg("rect", { x: o.x, y: o.y, width: o.w, height: MAPG.nodeH, rx: 6 }),
      svg("text", { x: o.x + o.w / 2, y: o.y + MAPG.nodeH / 2 + 4, "text-anchor": "middle" }, ["+" + o.extra + " more"]),
    ]));
    const canvas = svg("svg", { id: "map-svg", class: "map-svg", viewBox: `0 0 ${MAPG.width} ${geo.height}`, "aria-labelledby": "map-heading map-note" },
      [...guides, ...heads, svg("g", {}, mapState.edges.map((e) => e.node)), ...nodes.map(([, n]) => n), ...more]);
    canvas.addEventListener("keydown", (event) => { if (event.key === "Escape") select(null); });
    host.replaceChildren(canvas);
    mapState.sel = run.chains.length ? { type: "chain", index: 0, step: 0 } : { type: "finding", id: model.mapped[0].f.id };
  }
  const notDrawn = run.findings.filter((f) => f.status === "refuted" || f.status === "out_of_scope").length;
  const noReach = run.findings.filter((f) => (f.status === "confirmed" || f.status === "unconfirmed") && !(radiusOf(f.id)?.reach.length)).length;
  const caps = [];
  if (notDrawn) caps.push(notDrawn + " refuted or out-of-scope finding" + (notDrawn === 1 ? " is" : "s are") + " not drawn: they reach nothing.");
  if (noReach) caps.push(noReach + " finding" + (noReach === 1 ? " has" : "s have") + " no asset in the graph, so no reach was computed.");
  if (model.hiddenFindings) caps.push("Only the " + MAPG.maxFindings + " highest-scoring findings are drawn.");
  caps.push("Scores and reach are heuristics, not yet calibrated against real incidents.");
  document.getElementById("map-caps").textContent = caps.join(" ");
  renderMapText(model);
  applyHighlight(mapState.sel);
  renderPicks();
  renderDetail();
}
