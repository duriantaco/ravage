// Display rules shared by the live cockpit and offline regression checks.

export function formatCost(run = {}) {
  const value = run.cost_usd;
  if (run.cost_status === "unknown" || typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return "Unknown";
  }
  const amount = `$${value}`;
  return run.cost_status === "partial" ? `Partial: ${amount}` : amount;
}

export function resultSummary(block = {}) {
  const findings = Array.isArray(block.findings) ? block.findings : [];
  const total = block.evidence?.findings ?? block.metrics?.findings ?? findings.length;
  const confirmed = findings.filter((finding) => String(finding.status || "").toLowerCase() === "confirmed").length;
  const flags = block.flags?.count ?? block.metrics?.flags ?? 0;
  const parts = [`${total} finding${total === 1 ? "" : "s"} recorded`];
  if (confirmed > 0) parts.push(`${confirmed} confirmed`);
  if (flags > 0) parts.push(`${flags} flag${flags === 1 ? "" : "s"} captured`);
  return { text: parts.join(" · "), tone: confirmed > 0 || flags > 0 ? "pass" : "muted" };
}

export function runTone(run = {}, metrics = {}, mode = "live") {
  const label = String(run.label || metrics.run_label || "").toLowerCase();
  const status = String(run.status || "").toLowerCase();
  if (/stopped|issues|failed|incomplete|interrupted|cancelled/.test(`${label} ${status}`)) return "warn";
  if (mode === "replay" || run.active === false || metrics.completed === true) return "done";
  return "run";
}

export function targetSuffix(target = {}, run = {}, mode = "live") {
  if (run.status === "torn_down") return " · torn down";
  // Replay describes the saved assessment, not the target's current lifecycle.
  if (mode === "replay") return " · recorded target";
  const status = target.status || {};
  if (status.reachable === false) return " · offline";
  if (status.status) return ` · HTTP ${status.status}`;
  return "";
}
