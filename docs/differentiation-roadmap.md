---
title: Differentiation Roadmap
---

# Differentiation Roadmap

This page separates what Ravage already does from what still needs to be built.
For the current system design, read [Architecture](architecture.md). For code
pointers and contribution rules, read [Technical Guide](technical-guide.md).

## Current Differentiators

### Evidence-First Agent Loop

Ravage does not accept model-written claims as findings. The model selects JSON
actions, the scoped runtime executes them, observations are recorded, and
findings are accepted only after tool-backed evidence.

This matters because agent traces can be inspected after the run:

- model action;
- tool request;
- tool response or summarized observation;
- evidence decision;
- report output.

### Shared Runtime For Agent And DAST

`ravage attack` and `ravage scan` share the same broad run shape:

- engagement brief;
- scope checks;
- tool capability preflight;
- audit database;
- workspace artifacts;
- report output;
- optional observer.

This lets deterministic scans and model-driven runs be compared without
inventing different report formats.

### Managed Authenticated Attack Boundary

`ravage attack BRIEF --identity ALIAS` can establish a configured form,
bearer, or static-header identity before the model runs. A sole identity is
auto-selected by the public wrapper, while multiple identities require an
explicit choice. Authentication secrets are resolved from a private env-file
overlay without being exported into the process environment.

The selected identity is owned by a refreshable, health-checked HTTP session.
Eligible base-agent built-in probes and structured PoC replay use that session;
the bounded agent graph uses it only through scope-checked structured HTTP.
Recorded traffic and observations retain an identity/session-mode label while
recognized credentials are redacted. Graph traffic resume and the runtime
policy manifest bind that identity alias, preventing a resumed run from
silently changing principals.

The boundary is deliberately capability-limited. Authentication-boundary
probes run anonymously so they can test login rejection honestly. Command,
Python, persistent-process, external probe-runner, and graph PoC-process lanes
are unavailable in authenticated mode rather than receiving exported secrets
or silently running without the selected identity. The authenticated graph
does not attach a process executor at all; its executable set is managed
structured HTTP plus flag capture only for a flag mission.

### Scoped Tool Runtime

Ravage is localhost-first in the active CLI. Public/DNS targets require an
in-scope brief URL and `--authorized-remote-target`. External tools can run on
the host, in Docker, or in auto mode for local targets; remote command-like
tools are forced through an internal Docker network and a DNS-pinned forwarder
limited to scoped target host/port pairs.
Required capabilities fail closed unless degraded mode is explicitly allowed.

### Source-Guided Dynamic Proof

Ravage can inspect source context when the selected mode permits it, extract
routes/params/sinks, then run bounded dynamic workflows against the live target.

Implemented workflow areas include SQLi, XSS, SSTI, command injection, LFI,
IDOR/authz, SSRF, XXE, JWT/session issues, auth bypass, GraphQL IDOR, uploads,
deserialization, encrypted cookies, and selected source-secret pivots.

The important distinction is that source context guides candidates; it does not
become proof by itself.

### Benchmark Honesty

XBEN runs record the benchmark context mode:

- `black-box`;
- `white-box`;
- `source-aware`;
- compatibility `source-aware` alias for `white-box`.

This prevents mixing description-only black-box and white-box results as if
they were the same benchmark.

### Local Reviewed Memory

Memory is local SQLite, redacted, reviewable, and advisory. It can suggest
lessons, but it cannot report findings, capture flags, override scope, or store
raw secrets.

### Inspectable Run Artifacts

Runs produce machine-readable and human-reviewable outputs:

- `audit.db`;
- `workspace/events.jsonl`;
- `workspace/transcript.jsonl`;
- `workspace/artifacts/`;
- `report.json`;
- rendered report artifacts when available.

Trace-quality and failure-taxonomy tooling make benchmark misses easier to
debug without changing the benchmark result itself.

### Scoped Traffic History And Agent Provenance

`ravage traffic` provides the first operator-facing request-history layer:

- capture bounded agent-graph structured HTTP automatically, including redirect
  legs and transport-failure results;
- capture requests produced by a scope-restricted Playwright browser;
- list redacted application requests and aggregate stable request shapes;
- inspect redacted request and response metadata;
- link agent request IDs to exact observation and evidence IDs without exposing
  evidence payloads;
- replay one request through the structured HTTP runtime;
- compare a capture and replay result offline.

`list` and `show` discover nested graph traffic from the attack run directory.
Generated JSON and Markdown reports carry the same identifier-only agent HTTP
evidence links. A strict recorder prevents an uncaptured structured request from
being promoted as evidence, while resume preserves its request count and DNS
pins.

Remote capture and replay require `--authorized-remote-target`, and every URL,
redirect, and routed HTTP(S) browser subresource remains scope checked.
WebSocket handshakes are scope checked, but frames are not stored. Capture is
same-origin, so external SSO/identity providers and cross-origin API or CDN
requests are blocked. State-changing replay is separately armed with
`--allow-state-change`, and replay stops at redirects rather than following
them automatically.

Remote routed browser TCP is additionally forced through a loopback SOCKS5
proxy restricted to the captured origin and its pre-approved numeric DNS pins;
QUIC and proxy bypass are disabled. This closes the DNS-rebinding gap without
intercepting end-to-end TLS.

Persisted artifacts omit all query and request-body values and all raw response
bodies, in addition to authentication headers, cookies, passwords, tokens, and
recognized secrets. This workflow is not a complete host egress sandbox and
does not capture WebRTC/STUN/TURN, other non-HTTP browser transports, or traffic
from `curl`, Docker tools, scanners, and other external processes.

## Current Limits

### HTTP History And Replay UI

The CLI foundation now covers automatic agent structured HTTP history and
evidence links, scoped browser capture, redacted history, single-request replay,
offline diff, and report summaries. It is not yet a full Burp/Caido-style proxy
or UI: there is no TLS interception for external tools, interception editor,
broad mutation workspace, WebSocket frame history, complete browser egress
containment, or unified ingestion of scanner traffic.

### Auth Workflow Breadth

The managed form, bearer, and static-header path is shipped, including role
metadata, protected health checks, refreshable sessions, secret-safe env-file
resolution, eligible deterministic probes, base-agent PoC replay, and
agent-graph structured HTTP. The current boundary still needs:

- JSON and complex SPA login adapters;
- browser-driven login and external OAuth/OIDC or SAML identity providers;
- WebAuthn, CAPTCHA, push MFA, and operator checkpoints;
- CLI scaffolding for advanced TOTP configuration;
- simultaneous multi-identity authorization comparison inside one attack;
- a credential-safe broker for selected external tools, if one can preserve
  scope, replay, redaction, and process-isolation guarantees;
- richer durable session review and role-oriented operator controls.

### Multi-Agent Orchestration

The bounded `agent-graph` route is implemented with durable workers, budgets,
and evidence ownership. Richer independently optimized planner/recon/exploit/
report roles and a broader operator review surface remain future work.

### Proof Confidence Scoring

Ravage has evidence gates and optional proof-bundle verification, but confidence
is not yet a consistently scored first-class report dimension across every
finding class.

### Source-Guided Breadth

Source-guided workflows are broad but uneven. Some vulnerability families have
multiple tested patterns; others still need more frameworks, encodings, auth
states, and negative tests.

### Terminal Robustness

Named terminal sessions exist for approved tools, but prompt detection, stall
recovery, long-running process health, and structured interactive workflows
need more hardening.

### Native Benchmark Infrastructure

XBEN can run locally, but Apple Silicon Docker emulation can distort target
behavior for some amd64 images. Serious scoring should run on native amd64
Linux with stable Docker storage.

## Build Order

1. Request history and replay — agent foundation shipped
   Automatic agent HTTP capture, evidence links, nested CLI discovery, and
   report integration are current. Extend them with richer mutation, external
   scanner ingestion, and an operator review surface.

2. Authenticated workflow expansion — managed HTTP core shipped
   Extend the current form, bearer, and static-header boundary with JSON and
   browser-driven login, role comparison, operator checkpoints, and richer
   review. Do not open process lanes until credentials can remain non-exported
   and every request retains scope and evidence provenance.

3. Proof confidence
   Normalize confidence fields across finding classes and connect them to proof
   bundles, replay results, and report rendering.

4. Graph role specialization
   Extend the shipped bounded graph with richer role-specific contracts for
   recon, exploitation, source-guided analysis, browser workflows, and reporting
   without losing the audit trail.

5. Source-guided expansion
   Extend workflows with more framework coverage, more negative tests, and
   better failure classification.

6. Operator review surface
   Add a richer UI for reviewing runs, memory candidates, proof bundles,
   requests, and benchmark failures.

7. Benchmark infrastructure
   Standardize native amd64 benchmark runners, cost controls, artifact retention,
   and repeatable comparison reports.

## Non-Goals

Ravage should not become:

- a stealth exploitation platform;
- an unsupervised public-internet scanner;
- a benchmark-specific script collection;
- a system that reports vulnerabilities from model text alone;
- a memory system that stores raw secrets or raw customer responses.

## Keeping This Roadmap Honest

When adding roadmap claims:

- point to the implementing files or tests when a feature is marked current;
- distinguish source-guided and description-only black-box behavior;
- do not claim benchmark performance without run artifacts;
- keep old execution plans out of the primary docs path;
- update [How To Use](how-to-use.md), [Architecture](architecture.md), and
  [Technical Guide](technical-guide.md) when CLI or runtime behavior changes.
