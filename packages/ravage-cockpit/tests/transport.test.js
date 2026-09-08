import assert from "node:assert/strict";
import test from "node:test";
import { cockpitFetch, consumeEventStream, openCockpitSession, SESSION_KEY } from "../src/transport.js";

function browser({ capability = "", session = "" } = {}) {
  const sequence = [];
  const values = new Map(session ? [[SESSION_KEY, session]] : []);
  const status = { textContent: "" };
  const location = new URL(`http://127.0.0.1:8787/${capability ? `#token=${capability}` : ""}`);
  location.replace = (path) => sequence.push(["redirect", path]);
  globalThis.window = {
    location,
    history: { replaceState(_state, _title, path) { sequence.push(["clear", path]); } },
    sessionStorage: {
      getItem: (key) => values.get(key) || null,
      setItem(key, value) { sequence.push(["store"]); values.set(key, value); },
      removeItem: (key) => values.delete(key),
    },
  };
  globalThis.document = { querySelector: () => status };
  return { sequence, values, status };
}

test("capability handoff clears URL before network/storage and stores a separate session", async () => {
  const fixture = browser({ capability: "launch-secret" });
  globalThis.fetch = async (url, options) => {
    assert.deepEqual(fixture.sequence, [["clear", "/"]]);
    assert.equal(url, "http://127.0.0.1:8787/api/session");
    assert.equal(options.method, "POST");
    assert.equal(options.headers.Authorization, "Bearer launch-secret");
    assert.equal(options.credentials, "omit");
    assert.equal(options.redirect, "error");
    assert.equal(options.mode, "same-origin");
    assert.equal(options.referrerPolicy, "same-origin");
    return { ok: true, json: async () => ({ session_token: "session-secret" }) };
  };
  await openCockpitSession();
  assert.equal(fixture.values.get(SESSION_KEY), "session-secret");
  assert.deepEqual(fixture.sequence, [["clear", "/"], ["store"], ["redirect", "/index.html"]]);
});

test("an existing tab session can reopen the cockpit", async () => {
  const fixture = browser({ session: "session-secret" });
  globalThis.fetch = async (_url, options) => {
    assert.equal(options.headers.Authorization, "Bearer session-secret");
    assert.equal(options.method, undefined);
    return { ok: true };
  };
  await openCockpitSession();
  assert.deepEqual(fixture.sequence, [["clear", "/"], ["redirect", "/index.html"]]);
});

test("denied and failed bootstrap requests leave an actionable reconnect message", async () => {
  for (const outcome of ["denied", "offline"]) {
    const fixture = browser({ session: "expired" });
    globalThis.fetch = async () => {
      if (outcome === "offline") throw new Error("offline");
      return { ok: false };
    };
    await openCockpitSession();
    assert.ok(fixture.status.textContent.includes("link printed by Ravage"));
    assert.deepEqual(fixture.sequence, [["clear", "/"]]);
    if (outcome === "denied") assert.equal(fixture.values.size, 0);
  }
});

test("state, SSE, and mutation fetches carry explicit credentials without cookies", async () => {
  browser({ session: "session-secret" });
  for (const path of ["/api/state", "/api/events/stream", "/api/teardown"]) {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, `http://127.0.0.1:8787${path}`);
      assert.equal(options.headers.Authorization, "Bearer session-secret");
      assert.equal(options.credentials, "omit");
      assert.equal(options.redirect, "error");
      assert.equal(options.mode, "same-origin");
      assert.equal(options.referrerPolicy, "same-origin");
      return { status: 200 };
    };
    await cockpitFetch(path, path === "/api/teardown" ? { method: "POST" } : {});
  }
});

test("credentials cannot be sent to another origin, port, or a static resource", async () => {
  browser({ session: "session-secret" });
  let sent = false;
  globalThis.fetch = async () => { sent = true; };
  for (const path of ["http://127.0.0.1:8765/api/state", "http://other.invalid/api/state", "/index.html"]) {
    await assert.rejects(cockpitFetch(path), /same-origin API destination/);
  }
  assert.equal(sent, false);
});

test("sessions that expired after a server restart are cleared", async () => {
  const fixture = browser({ session: "expired" });
  globalThis.fetch = async () => ({ status: 401 });
  await assert.rejects(cockpitFetch("/api/state"), /session has expired/);
  assert.equal(fixture.values.size, 0);
  assert.deepEqual(fixture.sequence, [["redirect", "/"]]);
});

test("stream parser survives byte boundaries and preserves multiple events", async () => {
  const raw = new TextEncoder().encode(
    ': keepalive\n\nevent: state\ndata: {"name":"caf\u00e9"}\n\nevent: step\ndata: first\ndata: second\n\n'
  );
  const body = new ReadableStream({
    start(controller) {
      for (const byte of raw) controller.enqueue(Uint8Array.of(byte));
      controller.close();
    },
  });
  const events = [];
  await consumeEventStream(body, (event) => events.push(event));
  assert.deepEqual(events, [
    { type: "state", data: '{"name":"caf\u00e9"}' },
    { type: "step", data: "first\nsecond" },
  ]);
  assert.equal(body.locked, false);
});
