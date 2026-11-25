import assert from "node:assert/strict";
import test from "node:test";
import { formatCost, resultSummary, runTone, targetSuffix } from "../src/presentation.js";

test("unknown or incomplete accounting never masquerades as a free run", () => {
  for (const value of [undefined, null, "", "0", Number.NaN, Infinity, -1]) {
    assert.equal(formatCost({ cost_usd: value }), "Unknown");
  }
  assert.equal(formatCost({ cost_usd: 0, cost_status: "unknown" }), "Unknown");
  assert.equal(formatCost({ cost_usd: 0, cost_status: "known" }), "$0");
  assert.equal(formatCost({ cost_usd: 1.25, cost_status: "partial" }), "Partial: $1.25");
});

test("ordinary findings are visible without requiring a flag or overstating candidates", () => {
  assert.deepEqual(resultSummary({ findings: [{ status: "confirmed" }], flags: { count: 0 } }), {
    text: "1 finding recorded · 1 confirmed", tone: "pass",
  });
  assert.deepEqual(resultSummary({ findings: [{ status: "unconfirmed" }, { status: "rejected" }] }), {
    text: "2 findings recorded", tone: "muted",
  });
  assert.deepEqual(resultSummary({ evidence: { findings: 0 }, metrics: { findings: 3 } }), {
    text: "0 findings recorded", tone: "muted",
  });
});

test("captured benchmark flags do not override an incomplete run's status", () => {
  const metrics = { flags: 1, completed: true, run_label: "Stopped: action limit" };
  assert.equal(resultSummary({ metrics }).text, "0 findings recorded · 1 flag captured");
  assert.equal(runTone({}, metrics, "replay"), "warn");
  assert.equal(runTone({ active: false, label: "Completed" }, { completed: true }), "done");
  assert.equal(runTone({ active: true }, { flags: 1 }), "run");
});

test("replaying saved evidence does not claim to have removed the target", () => {
  assert.equal(targetSuffix({ status: { reachable: false } }, {}, "replay"), " · recorded target");
  assert.equal(targetSuffix({}, { status: "finished" }, "replay"), " · recorded target");
  assert.equal(targetSuffix({}, { status: "torn_down" }, "replay"), " · torn down");
  assert.equal(targetSuffix({ status: { reachable: false } }), " · offline");
  assert.equal(targetSuffix({ status: { status: 200 } }), " · HTTP 200");
});
