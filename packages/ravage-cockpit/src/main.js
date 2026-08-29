// Ravage live operator cockpit.
//
// A boring, stable pentest console for a black-box HTTP agent. No website
// preview — the agent sends HTTP, it never renders a page. Layout:
//   [ info rail ] [ agent timeline ] [ step evidence ]  +  docker strip + raw drawer
// It consumes the incremental SSE feed (one `state` snapshot, then `step` /
// `docker` / `target` / `status` deltas), so the DOM is built once and only the
// changed panel mutates — no flicker, no scroll jumps.

const app = document.querySelector("#app");

const refs = {};
const state = {
  runKey: null,
  startedAt: null,
  mode: "live",
  targetUrl: null,
  seenSteps: new Set(),
  commandsByKey: new Map(),
  actionRows: new Map(), // action_id -> { row, command, startedAt }
  focusKey: null,
  autoFollow: true,
  rawLines: [],
  autoScroll: true,
  streamConnected: false,
  lastStreamAt: 0,
  flags: { count: 0, values: [] },
  status: {},
};

const FALLBACK_POLL_MS = 15000;
const STREAM_STALE_MS = 20000;

boot();

async function boot() {
  buildShell();
  startElapsedClock();
  await seedFromState();
  connectStream();
  window.setInterval(() => {
    const stale = Date.now() - state.lastStreamAt > STREAM_STALE_MS;
    if (!window.EventSource || !state.streamConnected || stale) {
      seedFromState({ polling: true });
    }
  }, FALLBACK_POLL_MS);
}

// ---- transport ----------------------------------------------------------

async function seedFromState(options = {}) {
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) return;
    applyState(await response.json());
    if (options.polling) markConnection(false);
  } catch {
    markConnection(false);
  }
}

function connectStream() {
  if (!window.EventSource) return;
  const stream = new EventSource("/api/events/stream");
  stream.addEventListener("state", (e) => withData(e, applyState));
  stream.addEventListener("step", (e) => withData(e, appendStep));
  stream.addEventListener("docker", (e) => withData(e, updateDocker));
  stream.addEventListener("target", (e) => withData(e, updateTarget));
  stream.addEventListener("status", (e) => withData(e, updateStatus));
  stream.onopen = () => markConnection(true);
  stream.onerror = () => markConnection(false);
}

function withData(event, handler) {
  markConnection(true);
  try {
    handler(JSON.parse(event.data));
  } catch {
    /* ignore malformed frame */
  }
}

function markConnection(connected) {
  state.streamConnected = connected;
  if (connected) state.lastStreamAt = Date.now();
  refs.connDot.className = connected ? "conn ok" : "conn stale";
  refs.connDot.title = connected ? "live stream connected" : "stream disconnected — polling";
}

// ---- shell --------------------------------------------------------------

function buildShell() {
  app.replaceChildren();
  const root = el("main", "cockpit");

  const bar = el("header", "topbar");
  refs.connDot = el("span", "conn stale");
  refs.benchmark = textEl("span", "Ravage", "bench");
  refs.spinner = el("span", "spin");
  refs.runState = textEl("span", "waiting", "runstate");
  refs.elapsed = textEl("span", "00:00", "elapsed");
  refs.turn = textEl("span", "", "fact");
  refs.model = textEl("span", "", "fact");
  refs.cost = textEl("span", "", "fact");
  refs.target = textEl("span", "target pending", "target");
  refs.result = textEl("span", "", "result");
  bar.append(
    refs.connDot,
    refs.benchmark,
    refs.spinner,
    refs.runState,
    sep(),
    refs.elapsed,
    refs.turn,
    refs.model,
    refs.cost,
    sep(),
    refs.target,
    grow(),
    refs.result,
  );

  const main = el("div", "main");

  // Left info rail.
  refs.rail = el("aside", "rail");
  main.append(refs.rail);
  renderRail({});

  // Middle timeline.
  const timelineCol = el("section", "timeline-col");
  const timelineHead = el("div", "col-head");
  timelineHead.append(textEl("strong", "Agent timeline"));
  refs.stepCount = textEl("span", "0", "count");
  refs.followBtn = button("Following", () => toggleFollow(), "follow on");
  timelineHead.append(refs.stepCount, grow(), refs.followBtn);
  refs.steps = el("ol", "step-list");
  refs.steps.addEventListener("scroll", onStepScroll);
  timelineCol.append(timelineHead, refs.steps);
  main.append(timelineCol);

  // Right evidence detail.
  const detailCol = el("section", "detail-col");
  const detailHead = el("div", "col-head");
  refs.detailTitle = textEl("strong", "Step evidence");
  detailHead.append(refs.detailTitle);
  refs.detail = el("div", "detail-body");
  detailCol.append(detailHead, refs.detail);
  renderDetailEmpty();
  main.append(detailCol);

  // Slim Docker + evidence strip.
  refs.strip = el("div", "strip");

  // Raw drawer.
  const drawer = el("details", "drawer");
  const summary = el("summary");
  summary.append(textEl("span", "Raw event / log"));
  refs.drawerCount = textEl("span", "", "count");
  summary.append(refs.drawerCount);
  const drawerTools = el("div", "drawer-tools");
  refs.search = document.createElement("input");
  refs.search.type = "search";
  refs.search.placeholder = "filter…";
  refs.search.addEventListener("input", renderRaw);
  drawerTools.append(refs.search, button("Copy", () => copyRaw()));
  refs.raw = el("pre", "raw-output");
  drawer.append(summary, drawerTools, refs.raw);

  root.append(bar, main, refs.strip, drawer);
  app.append(root);
}

// ---- full snapshot ------------------------------------------------------

function applyState(snapshot) {
  const viewer = snapshot.viewer || {};
  const runKey = runKeyOf(snapshot);
  if (runKey !== state.runKey) {
    state.runKey = runKey;
    state.seenSteps = new Set();
    state.commandsByKey = new Map();
    state.actionRows = new Map();
    state.rawLines = [];
    state.focusKey = null;
    state.autoFollow = true;
    refs.steps.replaceChildren();
    renderDetailEmpty();
    state.autoScroll = true;
  }
  updateStatus({
    mode: snapshot.mode,
    metrics: snapshot.metrics,
    warnings: snapshot.warnings,
    flags: snapshot.flags,
    run: viewer.run,
    evidence: viewer.evidence,
    surface: viewer.surface,
    findings: snapshot.findings,
    stage_flow: snapshot.stage_flow,
    selection: snapshot.selection,
  });
  (viewer.commands || []).forEach((command) => appendStep(command, { quiet: true }));
  updateTarget({ mode: snapshot.mode, target: viewer.target, run: viewer.run });
  updateDocker({ docker: snapshot.docker, docker_log: snapshot.docker_log });
  renderRaw();
  scrollStepsIfPinned();
}

function runKeyOf(snapshot) {
  const manifest = snapshot.manifest;
  if (manifest && manifest.run_id) {
    return [manifest.run_id, manifest.created_at || manifest.docker_project || ""].join("|");
  }
  const paths = snapshot.paths || {};
  return String(paths.workspace_dir || "");
}

// ---- steps (append-only) ------------------------------------------------

function appendStep(command, options = {}) {
  const key = stepKey(command);
  if (state.seenSteps.has(key)) return;
  state.seenSteps.add(key);
  command._key = key;
  state.commandsByKey.set(key, command);

  const row = renderStepRow(command);
  refs.steps.append(row);
  if (command.kind === "action_started" && command.action_id) {
    state.actionRows.set(command.action_id, { row, command, startedAt: tsOf(command) });
  }
  resolvePairing(command);

  state.rawLines.push(rawLine(command));
  refs.stepCount.textContent = String(state.seenSteps.size);

  if (state.autoFollow) focusStep(key, { silent: true });
  if (!options.quiet) {
    renderRaw();
    scrollStepsIfPinned();
  }
}

function renderStepRow(command) {
  const status = command.status || "pending";
  const row = el("li", `step ${status}`);
  if (command.depth) row.classList.add("nested");
  row.dataset.key = command._key;
  row.dataset.kind = command.kind || "";
  if (command.action_id) row.dataset.actionId = command.action_id;

  const marker = el("span", "marker");
  const label = textEl("span", command.label || formatKind(command.kind), "step-label");
  const meta = textEl("span", stepMeta(command), `step-meta ${statusClass((command.request || {}).status)}`);
  row.append(marker, label, meta);
  row.addEventListener("click", () => focusStep(command._key));
  return row;
}

function stepMeta(command) {
  if (command.kind === "http_step") {
    const req = command.request || {};
    if (req.status) return `${req.status}${req.ok ? " ✓" : ""}`;
    return "sent";
  }
  if (command.status === "started") return "running";
  return formatTime(command.timestamp);
}

function resolvePairing(command) {
  const isFinish =
    command.action_id &&
    command.kind !== "action_started" &&
    (String(command.kind).startsWith("tool_") ||
      command.kind === "flag_captured" ||
      command.kind === "agent_final");
  if (!isFinish) return;
  const started = state.actionRows.get(command.action_id);
  if (!started) return;
  const outcome = command.status === "failed" ? "failed" : "completed";
  started.row.className = `step ${outcome}${started.command.depth ? " nested" : ""}`;
  const seconds = (tsOf(command) - started.startedAt) / 1000;
  const meta = started.row.querySelector(".step-meta");
  if (meta && Number.isFinite(seconds) && seconds >= 0) meta.textContent = formatDuration2(seconds);
  started.command.status = outcome;
  state.actionRows.delete(command.action_id);
  if (state.focusKey === started.command._key) renderDetail(started.command);
}

function stepKey(command) {
  return [command.commandId, command.timestamp, command.kind, command.label].join("|");
}

function onStepScroll() {
  const node = refs.steps;
  const distance = node.scrollHeight - node.clientHeight - node.scrollTop;
  state.autoScroll = distance <= 24;
}

function scrollStepsIfPinned() {
  if (state.autoScroll) refs.steps.scrollTop = refs.steps.scrollHeight;
}

// ---- focus / detail pane (the evidence view) ----------------------------

function toggleFollow() {
  state.autoFollow = !state.autoFollow;
  refs.followBtn.textContent = state.autoFollow ? "Following" : "Follow latest";
  refs.followBtn.className = `btn follow ${state.autoFollow ? "on" : ""}`.trim();
  if (state.autoFollow) {
    const last = refs.steps.lastElementChild;
    if (last) focusStep(last.dataset.key, { silent: true });
    scrollStepsIfPinned();
  }
}

function focusStep(key, options = {}) {
  const command = state.commandsByKey.get(key);
  if (!command) return;
  if (!options.silent) {
    state.autoFollow = false;
    refs.followBtn.textContent = "Follow latest";
    refs.followBtn.className = "btn follow";
  }
  state.focusKey = key;
  for (const row of refs.steps.children) {
    row.classList.toggle("focused", row.dataset.key === key);
  }
  renderDetail(command);
}

function renderDetailEmpty() {
  refs.detailTitle.textContent = "Step evidence";
  refs.detail.replaceChildren();
  refs.detail.append(textEl("div", "Select a step, or wait for the agent to act.", "muted pad"));
}

function renderDetail(command) {
  refs.detailTitle.textContent = command.label || formatKind(command.kind);
  refs.detail.replaceChildren();

  const head = el("div", "detail-head");
  head.append(statusPill(command.status));
  head.append(textEl("span", command.label || formatKind(command.kind), "detail-label"));
  head.append(grow());
  head.append(textEl("span", command.kind || "", "detail-kind"));
  head.append(textEl("span", formatTime(command.timestamp), "detail-time"));
  refs.detail.append(head);

  if (command.detail) refs.detail.append(textEl("div", command.detail, "detail-note"));

  if (Array.isArray(command.why) && command.why.length) {
    const block = el("div", "detail-block");
    block.append(textEl("div", "reasoning", "block-title"));
    command.why.forEach((row) => {
      const line = el("div", "why");
      line.append(textEl("span", row.label, "why-key"));
      line.append(textEl("span", row.text, "why-text"));
      block.append(line);
    });
    refs.detail.append(block);
  }

  const request = command.request;
  if (request) refs.detail.append(requestBlock(request));
  if (request && request.status !== undefined) refs.detail.append(responseHeadBlock(request));

  if (command.output) {
    const block = el("div", "detail-block");
    const title =
      command.kind === "model_reply_received"
        ? "model output"
        : command.kind === "http_step"
          ? "response body"
          : "output";
    block.append(textEl("div", title, "block-title"));
    const pre = el("pre", "block-pre");
    pre.textContent = command.output;
    block.append(pre);
    refs.detail.append(block);
  }

  if (command.errorMessage) {
    const err = el("div", "detail-block");
    err.append(textEl("div", "error", "block-title"));
    err.append(textEl("div", command.errorMessage, "block-pre err"));
    refs.detail.append(err);
  }

  if (!request && !command.output && !command.detail && !(command.why || []).length && !command.errorMessage) {
    refs.detail.append(textEl("div", "No request or output recorded for this step.", "muted pad"));
  }
}

function requestBlock(request) {
  const block = el("div", "detail-block");
  block.append(textEl("div", "request", "block-title"));
  if (Array.isArray(request.steps)) {
    request.steps.forEach((step) => block.append(httpLine(step.method, step.path || step.url, step.fields)));
  } else if (request.method || request.path) {
    block.append(httpLine(request.method, request.path, request.fields, request.status, request.ok));
  } else if (request.command) {
    const pre = el("pre", "block-pre");
    pre.textContent = request.command;
    block.append(pre);
  } else if (request.probe) {
    block.append(textEl("div", `probe: ${request.probe}`, "kvline"));
  }
  return block;
}

function responseHeadBlock(request) {
  const block = el("div", "detail-block");
  const head = el("div", "block-title-row");
  head.append(textEl("span", "response", "block-title"));
  if (request.status) head.append(statusCode(request.status, request.ok));
  block.append(head);
  const headers = request.response_headers;
  if (headers && typeof headers === "object" && Object.keys(headers).length) {
    Object.entries(headers).forEach(([key, value]) => {
      block.append(textEl("div", `${key}: ${value}`, "kvline"));
    });
  } else {
    block.append(textEl("div", "no response headers captured", "muted kvline"));
  }
  return block;
}

function httpLine(method, path, fields, status, ok) {
  const wrap = el("div", "http");
  const head = el("div", "http-head");
  head.append(textEl("span", String(method || "GET").toUpperCase(), "method"));
  head.append(textEl("span", path || "", "path"));
  if (status) head.append(statusCode(status, ok));
  wrap.append(head);
  if (fields && typeof fields === "object" && Object.keys(fields).length) {
    Object.entries(fields).forEach(([key, value]) => {
      wrap.append(textEl("div", `${key} = ${value}`, "kvline"));
    });
  }
  return wrap;
}

function statusCode(status, ok) {
  const node = el("span", `code ${statusClass(status)}`);
  node.textContent = `${status}${ok ? " ✓" : ""}`;
  return node;
}

function statusClass(status) {
  const code = Number(status);
  if (!code) return "";
  if (code < 300) return "s2";
  if (code < 400) return "s3";
  if (code < 500) return "s4";
  return "s5";
}

function statusPill(status) {
  const pill = el("span", `pill ${status || "pending"}`);
  const label = { started: "running", completed: "done", failed: "failed", warned: "warn" };
  pill.textContent = label[status] || status || "pending";
  return pill;
}

// ---- left info rail -----------------------------------------------------

function renderRail(block) {
  const run = block.run || {};
  const metrics = block.metrics || {};
  const selection = block.selection || {};
  const surface = block.surface || {};
  const findings = Array.isArray(block.findings) ? block.findings : [];
  const stages = Array.isArray(block.stage_flow) ? block.stage_flow : [];

  refs.rail.replaceChildren();

  // Objective.
  const obj = railSection("Objective");
  obj.body.append(textEl("div", run.objective || "waiting for the agent to plan…", "objective"));
  refs.rail.append(obj.section);

  // Kill chain.
  const kc = railSection("Kill chain");
  kc.body.append(killChain(stages));
  refs.rail.append(kc.section);

  // Run facts.
  const facts = railSection("Run");
  facts.body.append(factRow("phase", run.phase || "—"));
  facts.body.append(factRow("turn", run.max_turns ? `${run.turn || 0} / ${run.max_turns}` : String(run.turn || 0)));
  const route = selection.last_model_route || {};
  facts.body.append(factRow("model", [route.model, route.provider].filter(Boolean).join(" · ") || "—"));
  facts.body.append(factRow("requests", String(run.model_requests ?? metrics.model_replies ?? 0)));
  facts.body.append(factRow("cost", run.cost_usd ? `$${run.cost_usd}` : "$0"));
  const tools = Array.isArray(selection.selected_tools) ? selection.selected_tools : [];
  facts.body.append(factRow("tools", tools.length ? tools.join(", ") : "builtin"));
  refs.rail.append(facts.section);

  // Findings.
  const fnd = railSection(`Findings (${findings.length})`);
  if (!findings.length) {
    fnd.body.append(textEl("div", "none yet", "muted"));
  } else {
    findings.slice(0, 12).forEach((finding) => fnd.body.append(findingRow(finding)));
  }
  refs.rail.append(fnd.section);

  // Recon surface.
  const facts2 = surface.facts;
  const surf = railSection("Surface");
  surf.body.append(factRow("routes", String(surface.route_count ?? "—")));
  if (Array.isArray(facts2) && facts2.length) {
    facts2.slice(-6).forEach((fact) => surf.body.append(textEl("div", `• ${valueText(fact)}`, "fact-note")));
  }
  refs.rail.append(surf.section);
}

function railSection(title) {
  const section = el("section", "rail-section");
  section.append(textEl("div", title, "rail-title"));
  const body = el("div", "rail-body");
  section.append(body);
  return { section, body };
}

function killChain(stages) {
  const wrap = el("div", "killchain");
  const list = stages.length
    ? stages
    : ["Setup", "Recon", "Access", "Exploit", "Validate", "Proof"].map((label) => ({ label, status: "pending" }));
  let lastDone = -1;
  list.forEach((stage, index) => {
    if (stage.status === "done") lastDone = index;
  });
  list.forEach((stage, index) => {
    let cls = "kc-seg";
    if (stage.status === "done") cls += " done";
    else if (index === lastDone + 1) cls += " current";
    const seg = el("div", cls);
    seg.append(el("span", "kc-dot"));
    seg.append(textEl("span", stage.label, "kc-label"));
    wrap.append(seg);
  });
  return wrap;
}

function findingRow(finding) {
  const status = String(finding.status || "").toLowerCase();
  const tone = status.includes("confirm") ? "pass" : status.includes("reject") ? "fail" : "warn";
  const row = el("div", `finding ${tone}`);
  row.append(el("span", "fdot"));
  row.append(textEl("span", finding.vuln_class || "finding", "fclass"));
  row.append(textEl("span", shortStatus(status), "fstatus"));
  return row;
}

function shortStatus(status) {
  if (status.includes("confirm")) return "confirmed";
  if (status.includes("reject")) return "rejected";
  return status || "open";
}

function factRow(name, value) {
  const row = el("div", "fact-row");
  row.append(textEl("span", name, "fact-key"));
  row.append(textEl("span", value, "fact-val"));
  return row;
}

// ---- status / header ----------------------------------------------------

function updateStatus(block) {
  state.status = { ...state.status, ...block };
  const run = block.run || {};
  const metrics = block.metrics || {};
  state.mode = block.mode || state.mode;
  state.startedAt = run.started_at ? Date.parse(run.started_at) : state.startedAt;
  state.flags = block.flags || state.flags;

  refs.benchmark.textContent = run.benchmark_id || run.lab_name || "Ravage";
  const active = Boolean(run.active) && state.mode !== "replay";
  refs.spinner.className = active ? "spin on" : "spin";
  const phase = run.phase || "idle";
  const label = run.label || metrics.run_label || "";
  refs.runState.textContent = state.mode === "replay" ? `replay · ${label}` : `${phase} · ${label}`;
  refs.runState.className = `runstate ${statusTone(run, metrics, state.mode)}`;

  refs.turn.textContent = run.max_turns ? `turn ${run.turn || 0}/${run.max_turns}` : (run.turn ? `turn ${run.turn}` : "");
  const route = (block.selection || {}).last_model_route || {};
  refs.model.textContent = route.model ? `· ${route.model}` : "";
  refs.cost.textContent = run.cost_usd ? `· $${run.cost_usd}` : "";

  const flags = state.flags || {};
  const findings = (block.evidence && block.evidence.findings) || metrics.findings || 0;
  if (flags.count > 0) {
    const value = Array.isArray(flags.values) && flags.values[0] ? flags.values[0] : `${flags.count} flag`;
    refs.result.textContent = `✔ ${value}`;
    refs.result.className = "result pass";
  } else {
    refs.result.textContent = `${findings} finding${findings === 1 ? "" : "s"} · no flag`;
    refs.result.className = "result muted";
  }
  renderElapsed();
  renderRail(state.status);
}

function statusTone(run, metrics, mode) {
  if ((state.flags && state.flags.count) || metrics.flags) return "pass";
  const label = String(run.label || metrics.run_label || "");
  if (label.startsWith("Stopped")) return "warn";
  if (mode === "replay" || run.active === false) return "done";
  return "run";
}

// ---- target (topbar info only) ------------------------------------------

function updateTarget(block) {
  const target = block.target || {};
  const run = block.run || {};
  const mode = block.mode || state.mode;
  state.mode = mode;
  const url = target.url || run.target_url || "";
  state.targetUrl = url;
  const status = target.status || {};
  if (!url) {
    refs.target.textContent = "target pending";
    return;
  }
  let suffix = "";
  if (mode === "replay") suffix = " · torn down";
  else if (status.reachable === false) suffix = " · offline";
  else if (status.status) suffix = ` · HTTP ${status.status}`;
  refs.target.textContent = url + suffix;
}

// ---- docker + evidence strip -------------------------------------------

function updateDocker(block) {
  const docker = block.docker || {};
  const containers = Array.isArray(docker.containers) ? docker.containers : [];
  const logs = Array.isArray(docker.logs) ? docker.logs : block.docker_log || [];
  refs.strip.replaceChildren();

  refs.strip.append(textEl("span", "docker", "strip-label"));
  if (!containers.length) {
    refs.strip.append(textEl("span", "no containers", "muted"));
  } else {
    containers.forEach((container) => refs.strip.append(containerChip(container)));
  }
  refs.strip.append(grow());
  const flags = state.flags || {};
  refs.strip.append(evidenceChip("flags", flags.count || 0, (flags.count || 0) > 0));
  refs.strip.append(logChip(logs));
}

function containerChip(container) {
  const chip = el("details", "chip");
  const summary = el("summary");
  summary.append(healthDot(container));
  summary.append(textEl("span", container.name || container.id || "container", "chip-name"));
  if (container.ports) summary.append(textEl("span", container.ports, "chip-ports"));
  chip.append(summary);
  const pre = el("pre", "chip-log");
  pre.textContent = (Array.isArray(container.logs) ? container.logs : []).slice(-40).join("\n") || "No lines";
  chip.append(pre);
  return chip;
}

function logChip(logs) {
  const chip = el("details", "chip");
  const summary = el("summary");
  summary.append(textEl("span", "docker log", "chip-name"));
  summary.append(textEl("span", String(logs.length), "chip-ports"));
  chip.append(summary);
  const pre = el("pre", "chip-log");
  pre.textContent = logs.slice(-80).join("\n") || "No lines";
  chip.append(pre);
  return chip;
}

function evidenceChip(name, value, on) {
  const chip = el("span", `ev ${on ? "on" : ""}`);
  chip.append(textEl("strong", String(value)));
  chip.append(textEl("span", name));
  return chip;
}

function healthDot(container) {
  const st = String(container.state || container.status || "").toLowerCase();
  const cls = st.includes("run") || st.includes("up") ? "ok" : st ? "down" : "unknown";
  return el("span", `hdot ${cls}`);
}

// ---- raw drawer ---------------------------------------------------------

function rawLine(command) {
  const time = formatTime(command.timestamp);
  const label = command.label || command.kind || "event";
  const detail = command.detail ? ` — ${command.detail}` : "";
  return `${time}  [${command.kind || "event"}] ${label}${detail}`;
}

function renderRaw() {
  const query = (refs.search.value || "").toLowerCase();
  const lines = query
    ? state.rawLines.filter((line) => line.toLowerCase().includes(query))
    : state.rawLines;
  refs.raw.textContent = lines.slice(-500).join("\n");
  refs.drawerCount.textContent = String(state.rawLines.length);
}

async function copyRaw() {
  try {
    await navigator.clipboard.writeText(state.rawLines.join("\n"));
  } catch {
    /* clipboard may be blocked; ignore */
  }
}

// ---- elapsed clock ------------------------------------------------------

function startElapsedClock() {
  window.setInterval(renderElapsed, 1000);
}

function renderElapsed() {
  if (!state.startedAt) {
    refs.elapsed.textContent = "00:00";
    return;
  }
  const seconds = Math.max(0, Math.floor((Date.now() - state.startedAt) / 1000));
  refs.elapsed.textContent = formatDuration(seconds);
}

function formatDuration(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const pad = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${pad(h)}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

function formatDuration2(seconds) {
  if (seconds < 10) return `${seconds.toFixed(1)}s`;
  if (seconds < 60) return `${Math.round(seconds)}s`;
  return formatDuration(Math.round(seconds));
}

// ---- tiny helpers -------------------------------------------------------

function valueText(value) {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function tsOf(command) {
  const value = Date.parse(command.timestamp || "");
  return Number.isNaN(value) ? Date.now() : value;
}

function formatKind(value) {
  return String(value || "event").replace(/_/g, " ");
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function button(text, onClick, className = "") {
  const node = el("button", `btn ${className}`.trim());
  node.type = "button";
  node.textContent = text;
  node.onclick = onClick;
  return node;
}

function sep() {
  return el("span", "sep");
}

function grow() {
  return el("span", "grow");
}

function textEl(tag, text, className = "") {
  const node = el(tag, className);
  node.textContent = text;
  return node;
}

function el(tag, className = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  return node;
}
