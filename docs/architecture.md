---
title: Architecture
---

# Architecture

Ravage is a source-checkout research workspace for autonomous web application
testing on controlled, authorized targets. The core design is evidence-first:
models propose work, but scoped tools, typed observations, deterministic
control, evidence gates, and reports decide what executes and what becomes a
finding.

This page describes the current implemented architecture, not an old execution
plan. It distinguishes the **base agent loop** from the optional
**post-base graph route**. The published 85/104 XBEN run exercised an earlier
snapshot of the base hybrid proposal/selection loop and its bounded
specialists; it did not exercise the newer graph or authorized remote runtime.

The structured HTTP path is **request-aware gray-box testing**, not white-box
testing. It can use request shapes observed from the running application and
typed evidence produced by Ravage, but it does not assume source-code,
database, server, or deployment access. Source-guided analysis is a separate
input when an operator deliberately provides source context.

## Mental Model

Think of Ravage as five control layers:

1. Scope and policy decide what the run is allowed to touch.
2. A planner proposes work from the current mission state.
3. Deterministic routing decides what work is admissible and which worker owns
   it.
4. Scoped tools execute the action and return typed observations.
5. Evidence gates decide whether the observation is strong enough to become a
   finding or benchmark flag.

The model is useful for planning, but it is not trusted as policy or proof.
Tool output is evidence input. Reports are accepted only after the evidence
path is recorded and the applicable proof gate passes.

The current checkout exposes two target-entry policies:

- **Local lane:** run the base first. If it proves the objective, stop.
  If it terminates unsolved through model-request or exploration exhaustion, an
  explicitly selected autonomous route may continue from its retained state.
- **Authorized remote lane:** after an explicit authorization acknowledgement,
  default to native metered HTTP under the whole-run low-noise policy. An
  explicitly selected observe-mode run can expose command, Python, process,
  scanner, structured HTTP, typed-probe, and Playwright surfaces; command-like
  tools are then forced into scoped Docker. The optional graph can continue an
  eligible miss.
- **Managed-identity lane:** when the brief selects an authentication identity,
  eligible in-process probes and PoC replay share a refreshable scoped HTTP
  owner. Command, Python, process, browser/OCR, raw-WebSocket, and unmanaged
  binary transports are removed. This lane is the same locally and remotely and
  does not construct Docker. Anonymous raw-WebSocket handshakes are otherwise
  scoped, DNS-pinned, paced, and physically counted; managed mode omits
  `browser_boundary` because its raw callback cannot traverse the identity owner
  or inherit credentials and refresh semantics. Direct binary downloads are
  scoped and metered anonymously, but managed mode omits `cms_exposure` until an
  owner-controlled binary-response adapter exists.

## High-Level Flow

<div class="mermaid">
flowchart TB
    Brief["Authorized brief, scope, ROE, and budgets"]
    Brief --> Local["Local target"]
    Brief --> Remote["Explicitly authorized remote target"]

    Local --> Base["Base agent loop<br/>up to 40 model turns"]
    Base --> BaseProof{"Proof confirmed?"}
    BaseProof -->|yes| Proof
    BaseProof -->|eligible unsolved stop| LocalGraph["Opt-in bounded agent graph"]
    LocalGraph --> LocalRuntime["Existing scoped local runtime"]

    Remote --> RemoteBase["Same ai-web base<br/>explicit acknowledgement"]
    RemoteBase --> RemoteRuntime["Default metered native HTTP<br/>or opt-in scoped Docker tools"]
    RemoteBase --> RemoteProof{"Proof confirmed?"}
    RemoteProof -->|eligible unsolved stop| RemoteGraph["Opt-in bounded agent graph"]
    RemoteGraph --> RemoteRuntime

    LocalRuntime --> Evidence["Typed evidence blackboard<br/>and target observation"]
    RemoteRuntime --> Evidence
    Evidence --> Proof["Proof gate and terminal outcome"]
    Proof --> Artifacts["Audit, state, receipts, and report"]
</div>

<script type="module">
  import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";
  mermaid.initialize({ startOnLoad: true, theme: "neutral" });
</script>

Text fallback:

```text
authorized brief
  +-> local:  base -> eligible unsolved stop -> opt-in graph -> local tools
  `-> remote: explicit authorization -> low-noise base (or observe + Docker) -> optional graph

both -> typed observations -> proof gate -> durable audit and terminal outcome
```

## Packages

- `packages/ravage`: runtime package, CLI, agent loop, tools, benchmarks, labs,
  reports, source-guided workflows, and the additive autonomous graph.
- `packages/schemas`: shared schema package published as `ravage-schemas`,
  imported as `pentest_schemas`.
- `packages/agents/*`: early specialist-agent packages.
- `packages/mcp_servers/*`: MCP wrappers for external tools.
- `ravage xben`: XBEN runner used for controlled benchmark execution.

The console command is `ravage`, implemented by
`packages/ravage/src/ravage/__main__.py`.

## Entry Points

Primary operator commands:

- `ravage attack`: model-driven `ai-web` execution.
  `--autonomous-route --autonomous-route-engine agent-graph` opts into the
  bounded graph route. Any remote target additionally requires
  `--authorized-remote-target`.
- `ravage scan`: deterministic DAST without model calls.
- `ravage traffic`: automatic base and agent-graph structured HTTP history,
  optional scoped Playwright capture, redacted inspection, single-request
  replay, and offline comparison.
- `ravage tools`: tool-runtime list/check helpers. Tool installation lives in
  `scripts/install_tools.sh`.
- `ravage lab`: local lab management helpers.
- `ravage observe`: live dashboard for an existing run.
- `ravage audit verify`: audit hash-chain verification.
- `ravage competitors`: isolated competitor-harness workflows.

Benchmark entry points:

- `ravage xben ...`: official-style XBEN validation benchmark runs.
- `ravage benchmark ...`: compatibility alias for `ravage xben`.
- `scripts/run_memory_eval.py`: memory off/read comparison.
- `scripts/grade_xben_failures.py`: post-run failure categorization.

## Base Agent Loop And Evaluated Snapshot

The `ai-web` loop builds a prompt from the brief, scope, discovered target state,
available tools, memory hints, source-guided observations, planner
recommendations, and prior findings.

The model must return one JSON action. The runtime validates the action, checks
scope, executes the tool, records the observation, and appends the observation
to the next model turn. Tool output is wrapped as untrusted observation data so
target-controlled text cannot masquerade as agent instructions.

The agent supports two modes:

- `hybrid`: normal local/manual operation with runtime recommendations,
  deterministic proof support, and evidence gates.
- `ctf-free-roam`: benchmark/CTF mode that encourages bounded autonomous
  exploration and flag capture.

The frozen 2026-07-12 XBEN result came from an earlier snapshot of this base
architecture. It used one
stateful planner, deterministic proposal selection, persistent mission state,
23 evidence-promotion rules, 26 bounded specialists, repetition control, and a
tool-origin proof gate. The current base remains the local first stage and
defaults to 40 model turns. This is a model-request budget, not a physical
HTTP-request limit. Entering the graph does not reset or enlarge the base budget;
the graph has its own separate 24-model-request budget.

## Bounded Agent Graph Route

The additive `agent-graph` route is a durable execution graph, not a prompt that
merely tells one agent to try harder. Its default hard limits are six nodes, two
concurrent nodes, 24 model requests, 96 tool calls, a 20-minute wall clock, and
four model requests reserved for proof work. A configured cost ceiling is also
global. These limits are persisted with graph identity and checked in code.

The route has the following control structure:

- A coordinator owns graph-wide budgets, node admission, scheduling, and the
  terminal result.
- Each worker has a named objective, bounded lease, durable model session, and
  typed inbox rather than receiving every other worker's transcript.
- A typed evidence blackboard stores observations, contracts, proof provenance,
  coverage, and failure certificates. New workers must identify a distinct
  objective and, after broad exploration, cite evidence.
- Dynamic workers are raised from observed gaps or closure obligations. The
  node cap, objective fingerprinting, ownership rules, and seed-admission policy
  prevent an unrestricted agent swarm.
- Investigation campaigns vary one declared dimension at a time, measure
  information gain, and terminate with progress or a failure certificate.
- A semantic repeat watchdog blocks equivalent low-value actions even when
  their surface text changes. One bounded stall review may propose a materially
  different route; it cannot reset budgets or recurse into more reviews.
- Provider continuity can retry or move an interrupted worker session to a
  configured compatible endpoint while preserving request and cost accounting.
- Old model-session text is replaced by a deterministic digest receipt while
  authoritative typed context and a recent exact tail remain. No model-written
  summary is trusted as graph state.

Budget growth is graduated rather than granted up front. The most constrained
global budget controls the phase:

| Pressure | Phase | Enforced behavior |
| --- | --- | --- |
| below 70% | Explore | finite, objective-scoped exploration is allowed |
| 70–85% | Focus | stop broad recon; admit only named evidence-backed work |
| 85–100% | Close | admit only proof or closure work |
| 100% | Exhausted | only submit proof or finish |

The graph is run-local adaptive control, not online model training. Coverage,
failures, observations, and decisions improve later choices in the same durable
run. Cross-run or cross-target learning is not silently applied.

## Canonical Identity-Aware Surface Graph

Both phases use the same target-bound surface-graph schema. The base snapshot is
persisted at `workspace/working_state.json`. When the graph enters, it clones
that state to `workspace/autonomous-route/agent-graph/working_state.json`; the
graph persists and resumes its current state there while the root file remains
the base snapshot. An operation has a stable identity derived from its protocol,
method, origin, normalized route shape, and optional selector.
Identity-independent request shape—parameter names and locations, content types,
header names, and bounded hints—lives on that operation. Separate observation
edges record which identity and source saw it, whether it was declared,
requested, or answered, its response status, scope and replayability decisions,
and evidence references.

Automatic production ingestion currently comes from native recon, including
bounded JavaScript request templates; executor-owned typed probe results,
including OpenAPI and GraphQL structural findings; and the base and graph
executors' own structured HTTP exchanges. Code-level adapters also accept
already-fetched JavaScript, OpenAPI v2/v3 documents, GraphQL SDL or
introspection, typed captured exchanges with browser/probe provenance, and
strict value-free external observation batches. These adapters perform no
fetching. Standalone
`ravage traffic capture` history and unstructured external-tool stdout are not
automatically imported into attack state. Strict external batches reject a
malformed or over-limit batch atomically; captured-exchange and document
adapters use their own bounded staging and truncation rules. Older flat-surface
state is projected through a compatibility view for the planner and specialists.

The graph is not a traffic archive. Query, body, and header values and response
bodies are omitted; only structural names, types, statuses, and identifier-only
evidence links are retained. Dynamic identifier-like path segments are
normalized conservatively so repeated object routes can converge without
collapsing known collection actions such as `search`, `new`, or `settings`.

## Local Route Entry

For a local target, `--autonomous-route` always starts with the base unless
valid base artifacts already exist for a resume. The graph enters only when the
base has no confirmed proof and terminates through model-request or exploration
exhaustion. A solved base, cost stop, error, or interruption does not
automatically open more work.

The base loop and unauthenticated graph can call the structured HTTP executor
under the brief's scope. The graph also reuses the verified local runtime
handoff for its eligible bounded probes, proof validators, and command/Python
actions. With a managed identity, its execute surface is structured HTTP plus
proof capture only; no process executor is attached. Its state lives below
`workspace/autonomous-route/agent-graph/`, separate from base artifacts.

## Explicit Authorized Remote Runtime

Remote operation is a separate production boundary:

```bash
ravage attack brief.yaml \
  --authorized-remote-target \
  --run-dir runs/authorized-remote
```

That command uses the default unauthenticated low-noise native-HTTP lane. If
the brief configures an identity, add `--identity ALIAS`; scoped managed HTTP is
the only target transport and process actions are unavailable. Use
`--traffic-policy observe --tool-runtime docker` only when the written ROE
explicitly permits the broader process-capable lane.

All target origins must still be declared in the brief. The acknowledgement
flag does not expand scope; it only allows a declared non-local target to pass
the remote-entry guard.

Remote shell, Python, persistent-process, and scanner actions never use the
host runtime. Ravage creates an internal Docker network and attaches tools to a
fixed, read-only forwarder. The forwarder can connect only to host/port pairs
derived from `scope.in_scope`; remote DNS is resolved once and the destination
addresses are pinned in network evidence. Tool requests retain the original
hostname for HTTP Host headers and TLS SNI.

Structured HTTP probes check the target, every redirect, and remote DNS
identity. Playwright intercepts routed HTTP(S) requests, including redirects
and subresources, and aborts anything outside scope. This does not turn the
host browser into a complete non-HTTP egress sandbox. The less controllable
Chrome DevTools fallback is disabled for remote targets. Proof recognition
continues to require target-derived evidence rather than model prose.

Raw TCP tools cannot distinguish `/authorized/path` from another path on the
same origin. Their hard boundary is therefore host and port. Only authorize
broad command/scanner use when the whole origin is in scope; use structured
HTTP, typed probes, or the browser when authorization is path-limited.

The base agent owns a durable whole-run traffic controller at
`workspace/traffic-policy.json`. Authentication bootstrap, native recon,
built-in probes, PoC replay, and the optional graph's structured HTTP executor
all attach to that ledger. Local attacks default to observe mode, which counts
native dispatches and marks the result as a lower bound if an opaque process lane
runs. Authorized remote attacks default to **low-noise** enforcement:

```bash
ravage attack brief.yaml \
  --authorized-remote-target \
  --traffic-policy low-noise \
  --max-physical-requests 150 \
  --traffic-max-rps 0.25
```

- a persistent 300-request default whole-run ceiling;
- at most 0.5 requests per second by default, or a stricter CLI/brief ROE rate;
- conservative anonymous GET/HEAD cache and in-flight deduplication;
- bounded safe-read retries, adaptive backoff, and circuit breaking;
- opaque command, Python, browser-process, and external-process actions blocked
  before execution;
- exact config and physical counts restored on resume, with changed settings
  rejected.

Current ledgers are mandatory and corruption or configuration mismatch fails
closed. A genuinely pre-ledger local/observe workspace with neither a ledger nor
its lock can be migrated once: Ravage creates an observe ledger and marks it
`lower_bound` before new target traffic. A legacy low-noise resume without its
ledger remains rejected.

The optional agent graph remains available after the full base. Its
`--operational-profile low-noise` adds graph-specific scheduling constraints,
while the whole-run traffic controller remains the authoritative physical count
and cap across both phases.

This is traffic restraint and auditability, not stealth, fingerprint evasion,
WAF bypass, persistence, or an assurance that testing will be undetected.

## HTTP Traffic History, Capture, And Replay

`ravage traffic` is the first request-history foundation. Its smallest local
operator-driven browser workflow is:

```bash
ravage traffic capture http://127.0.0.1:3000
ravage traffic list RUN_DIR
ravage traffic show RUN_DIR REQUEST_ID
ravage traffic replay RUN_DIR REQUEST_ID
ravage traffic diff RUN_DIR REQUEST_ID REPLAY_ID
```

The base loop and bounded agent graph record structured HTTP automatically; no
separate `traffic capture` process is required. Each phase owns a separate
private traffic store and target-bound evidence blackboard: the base lane lives
under `workspace/`, and the graph lane lives under
`workspace/autonomous-route/agent-graph/`. Each executor records every
transport result, including redirect legs and failures with no HTTP status.
Redirect legs share one safe observation ID, so their request IDs can link back
to the same evidence records. Capture is strict at this boundary: if the store
cannot durably append a request, the action fails before its observation can
reach evidence promotion.

`ravage traffic list RUN_DIR` discovers and validates both canonical lanes. If
only one lane exists, short IDs such as `rq_0001` keep working. When both lanes
exist, output uses qualified IDs because each private store can independently
contain `rq_0001` or `rp_0001`:

```bash
ravage traffic list RUN_DIR
ravage traffic show RUN_DIR base:rq_0001
ravage traffic replay RUN_DIR autonomous_graph:rq_0001
ravage traffic diff RUN_DIR \
  autonomous_graph:rq_0001 autonomous_graph:rp_0001
```

An unqualified ID is accepted only when it identifies one record across all
discovered lanes. `diff` requires both records to come from the same lane/store.
Passing an exact manifested workspace path intentionally selects only that lane
and retains its short local IDs.
Discovery fails closed if a lane is malformed or if the lane manifests disagree
on target or scope. The commands validate each lane's evidence blackboard and
join only exact, nonempty observation IDs. Their evidence view contains
identifiers, kind, source, producer, and material status—not evidence payloads
or request/response content. Markdown and JSON reports include the same
request-to-observation-to-evidence links in their Agent HTTP Evidence section.

Within one running process, anonymous base `http_request` actions share a cookie
jar; configured identities use their trusted managed-session owner. Ravage does
not write cookie values to the traffic store or HTTP state. A process-level
resume therefore reopens the durable lane but starts a new in-memory cookie jar
and releases session-dependent work so authentication must be re-established.
Durable request counts, remote DNS pins, target identity, scope, and capture
session do survive interruption. Resume fails closed if HTTP state, traffic
history, captured counts, or the adjacent evidence blackboard no longer agree.
For a managed identity, the persistent ceiling counts every physical health,
login, refresh, retry, action, and redirect request; credential-bearing
lifecycle traffic is not added to operator history, so the persisted physical
count may be greater than—but never lower than—the captured action count.

Observed forms and surface-graph operations act as replay templates. After a
promising evidence result, the evidence-lead lock can require the same origin,
method, normalized route, body encoding, and affected input locations for the
next bounded mutations. An authentication denial pauses that obligation rather
than sending the agent to an unrelated route; a real session-state change
reactivates it. This routing discipline keeps follow-up requests tied to the
observed shape, but it is not itself vulnerability proof.

Manual browser capture comes from an executor-owned adapter around Ravage's
Playwright context. Routed HTTP(S) navigations, redirects, and subresources are
checked against capture scope before they are sent.
WebSocket connection handshakes are scope checked, but frames are not stored. A
direct URL creates a same-origin capture boundary, so external SSO/identity
providers and cross-origin APIs or CDNs are blocked. Remote capture requires
`--authorized-remote-target`; the acknowledgement enables the declared target
but does not add origins to scope. Capture defaults to a 5,000-request ceiling,
configurable with `--max-requests`; additional HTTP(S) and WebSocket requests
are blocked fail-closed after the ceiling is reached.

For remote capture, the target is DNS-pinned before browser launch. Chromium is
forced through an ephemeral loopback SOCKS5 proxy that accepts only the target
host and port and dials only those numeric pins. The launch disables QUIC and
proxy bypass, so ambient proxies, DNS rebinding, and alternate host/port
connections cannot replace the approved routed TCP destination. TLS remains
end-to-end, preserving the original URL host for SNI and HTTP authority.

The captured store separates individual observations from normalized request
shapes. Stable request IDs let the CLI list repeated application requests
without flooding the terminal with static assets, inspect a redacted template,
and retain provenance for replay results. `show` and `diff` are offline. Replay
loads one captured request, revalidates its destination, applies explicit
replacement values, sends it through Ravage's structured HTTP path, and records
a separate replay result. It does not follow redirects automatically: each
redirected request must be inspected and replayed separately.

Replay reserves the captured request durably before network dispatch and uses
an OS-locked append log, so concurrent processes cannot allocate the same
attempt or retry an outcome that became unknown after send. One captured
request ID therefore has at most one dispatch. The transport ignores ambient
proxy settings and connects directly to the exact numeric addresses approved
by the outer scope decision while retaining the URL hostname for HTTP Host and
TLS SNI.

Replay is fail-closed for methods that may change server state. Safe methods
can run directly; POST, PUT, PATCH, DELETE, and other unsafe methods require the
operator to add `--allow-state-change` for that invocation. Remote replay also
requires a fresh `--authorized-remote-target` acknowledgement.
Method-override headers use the same state-change gate. Custom Host and
host/path/resource-routing headers are non-replayable because their effective
destination cannot be authorized from the request URL alone.

The persisted record is deliberately not a raw browser profile. Every query
value, every request-body value, and every raw response body is omitted.
Authorization, Cookie, and Set-Cookie values, passwords, tokens, and recognized
secret fields are also omitted or replaced with typed placeholders. File
permissions restrict the capture store to its owner. If replay needs an omitted
value, the operator must supply it explicitly; Ravage does not recover a secret
from the redacted artifact. URL-path redaction is conservative and heuristic,
so operators must still treat the capture store as sensitive.
Textual bodies require a complete opaque replacement; multipart, binary, and
content-encoded bodies are non-replayable. Browser bodies declared above 1 MiB
are not materialized.

This path governs routed browser HTTP(S) requests and WebSocket handshakes, plus
Ravage's structured HTTP requests. It is not a transparent proxy or a complete
host egress sandbox, does not install a TLS interception certificate, and does
not capture WebRTC/STUN/TURN, other non-HTTP browser transports, or encrypted
traffic produced by external processes such as `curl`, Docker tools, or
scanners. Docker's scoped network remains the preferred boundary for Ravage
attack tools that support it; a hard browser boundary requires a separately
isolated environment.

## Runtime Tools

The base model action contract is `http_request`, `run_command`, `run_python`,
`run_probe`, `validate_poc`, conditional `capture_flag`, and `final`.
`http_request` is a direct, scope-checked base action for replaying or mutating
an observed request shape through the persistent in-process HTTP session. Typed
browser and vulnerability-specific operations still sit behind probes and
validators; names such as `http_get` and `browser_open` are not direct
base-model actions.

The optional graph has a separate contract. It exposes structured
`http_request` and, only in a process-capable profile, bounded process actions;
its exact allowlist depends on traffic policy, identity, and objective. External
tools are reached through scoped command/process execution only when that lane
is enabled.

The full process-backed surface is available locally in observe mode and to an
explicitly authorized, unauthenticated remote observe-mode run. Remote
command-like work is then forced through scoped Docker. Default remote low-noise
blocks opaque command, Python, process, and browser-process execution. Managed
identity removes process/browser execution and gives the graph managed
`http_request`, plus `capture_flag` only for flag objectives.

## Source-Guided Workflows

When source context is available, Ravage parses routes, parameters, sinks,
headers, credentials, JWT/session logic, upload flows, GraphQL shapes, and
framework-specific patterns. Source-guided workflows then attempt bounded
dynamic proof against the running target.

Implemented workflow areas include:

- SQL injection;
- XSS;
- SSTI;
- command injection;
- LFI and path traversal;
- IDOR and privilege boundaries;
- SSRF;
- XXE;
- JWT forgery and header trust;
- auth bypass;
- GraphQL IDOR;
- file upload;
- insecure deserialization;
- encrypted cookies;
- SSH/source-secret pivots.

These workflows are not benchmark shortcuts. They are reusable proof loops that
turn source signals into scoped runtime attempts and still require live target
evidence before reporting.

## Evidence And Reporting

Ravage separates hints, attempts, and accepted findings:

- Memory and taxonomy hints are advisory.
- Source-guided candidates are not findings by themselves.
- Tool evidence must show confirmation before reporting.
- Benchmark flags must be observed in target-origin tool output before
  `capture_flag` is accepted.
- Proof-bundle verification can require semantic proof before selected IDOR/SSTI
  findings are promoted.

Runs write:

- `audit.db`: tamper-evident audit rows.
- `workspace/events.jsonl`: runtime events.
- `workspace/transcript.jsonl`: model and observation transcript.
- `workspace/traffic-policy.json`: durable physical-request ledger.
- `workspace/artifacts/`: large outputs.
- `report.json`: canonical machine-readable report for every public attack,
  including incomplete and failed runs.
- `report.md`: optional redacted human-readable report when `--report` is used.

Optional Ravage Pro report renderers can additionally write PDF or DOCX; core
does not produce `report.html`. Canonical JSON finalization reads only saved run
artifacts: it makes no model or target requests and atomically replaces a
private-permission file. Report JSON includes `traffic_accounting`, while
Markdown prints the physical-request count and accounting status. That status is
`exact`, `lower_bound` after opaque/unmetered execution, or `unavailable` when
the ledger is missing or unreadable. Findings, captured proofs, and highest
outcome stage are separate fields, so a no-flag run can still report
evidence-backed vulnerabilities.

When base or agent-graph structured HTTP history is present, report JSON
includes an `agent_http_evidence` summary and Markdown includes **Agent HTTP
Evidence**. Report request IDs are lane-qualified, so links remain unambiguous
when both private stores contain the same local ID. Both report forms contain
identifier-only links; the private traffic and evidence stores remain the
source of detailed captured metadata.

## Safety Model

`ravage scan` and `ravage attack` remain localhost-first: a non-local target is
rejected unless the operator explicitly acknowledges authorization. The flag
does not add scope; the target must already match the brief and rules of
engagement. Default authorized-remote low-noise operation does not require
Docker because opaque process actions are blocked. If an unauthenticated remote
observe-mode run enables command-like tools, they are forced through scoped
Docker and fail closed when Docker is unavailable.

HTTP, browser, and external-tool actions are scope checked. Remote structured
requests enforce URL scope; the internal Docker network enforces the scoped
host/port set for raw tools. Initial remote DNS identities and Docker forwarding
destinations are pinned and retained as evidence.

The system is designed for authorized research, local labs, controlled
benchmarks, and explicitly scoped assessments. It is not designed for
persistence, broad internet scanning, detection bypass, or unsanctioned
exploitation.

## Current Limits

Important limits still remain:

- `ravage traffic` now covers automatic base and graph structured HTTP
  provenance and scoped browser history, replay, and diff, but is not a full
  Burp/Caido replacement. It has no transparent proxy, interception editor,
  `curl`/Docker tool/scanner traffic capture, or complete mutation UI.
- Eligible remote observe-mode browser probes require Playwright. Ravage
  disables the Chrome DevTools fallback remotely because it cannot enforce every
  subresource.
- Raw TCP tools enforce host/port scope, not URL-path scope. Scanner-specific
  rate and concurrency flags must also be chosen to fit the engagement ROE.
- The whole-run and graph low-noise profiles reduce request rate and variability
  but are not anti-detection systems.
- Browser and anonymous structured-HTTP cookie state is stable within one
  process but is not restored after a process-level resume. Base and graph
  structured HTTP request counts and DNS pins are restored separately.
- Provider continuity is not a heterogeneous challenger architecture; workers
  currently use the configured model portfolio rather than independently
  optimized role models.
- There is no operator steering channel for waking, pausing, or redirecting a
  live graph.
- The graph route, remote runtime, budget phases, and session projection were
  added after the frozen 85/104 run. Focused and regression tests establish
  control behavior, not benchmark accuracy.
- Source-guided coverage is broad but uneven across frameworks and vulnerability
  variants.
- XBEN scoring is sensitive to target Docker health, architecture, model route,
  turn budget, and selected context mode.

See [Technical Guide](technical-guide.md) for implementation pointers.
