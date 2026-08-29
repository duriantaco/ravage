---
title: Technical Guide
---

# Technical Guide

This guide is for contributors changing Ravage internals. For operator commands,
start with [How To Use](how-to-use.md). For the system flow, read
[Architecture](architecture.md).

## First Principles

Most Ravage changes should preserve these rules:

- Scope checks happen before network access.
- Model output is an action request, not proof.
- Tool output is wrapped as untrusted data.
- Findings require live evidence.
- Benchmark helpers must not hardcode benchmark IDs, flags, or one-off paths.
- Memory is advisory and redacted.
- Run artifacts should make failures debuggable after the fact.

## Repository Map

Core runtime:

- `packages/ravage/src/ravage/__main__.py`: CLI parser and command dispatch.
- `packages/ravage/src/ravage/agent_core/ai_agent.py`: base `ai-web` runtime loop.
- `packages/ravage/src/ravage/agent_core/autonomous_graph/`: bounded graph
  coordinator, workers, budgets, scoped HTTP, evidence, and durable state.
- `packages/ravage/src/ravage/dast_scan.py`: deterministic scan runtime.
- `packages/ravage/src/ravage/benchmark.py`: local benchmark harness.
- `packages/ravage/src/ravage/xben_parts/`: XBEN runner implementation.
- `packages/ravage/src/ravage/run_data/audit.py`: audit store and hash-chain
  verification.
- `packages/ravage/src/ravage/run_data/workspace.py`: workspace paths and
  artifacts.
- `packages/ravage/src/ravage/runtime/`: external tool execution modes.
- `packages/ravage/src/ravage/web_core/scope_policy.py`: same-origin and
  explicit-scope enforcement.

Agent internals:

- `agent_core/action_parser.py`: current model-action parsing.
- `agent_core/action_executor.py`: scoped local action execution and evidence
  recording.
- `agent_core/agent_state.py`: evaluated-base working state.
- `agent_core/surface_graph.py`: canonical target-bound operations and
  identity/source-specific access observations.
- `agent_core/surface_graph_ingest.py`: bounded native recon, JavaScript,
  OpenAPI, GraphQL, probe, typed captured-exchange, and strict external-batch
  adapters. Adapters perform no fetching; production callers decide which typed
  sources enter base or nested graph state.
- `outcome_evidence.py`: evidence-stage reconstruction across base, route, and
  graph event streams.
- `agent_core/autonomous_route_selection.py`: explicit post-base route
  selection.
- `agent_core/autonomous_graph/model_bridge.py`: graph model routing and
  accounting.
- `agent_core/autonomous_graph/scoped_http.py`: remote structured-HTTP
  enforcement.
- `probe_suite.py` and `probes/`: deterministic specialist catalog and proof
  closure.
- `traffic/policy.py`: durable whole-run physical-request accounting, pacing,
  cache/deduplication, retry/backoff, circuit breaking, and enforcement.

Benchmark and evaluation:

- `ravage xben`: command-line wrapper for XBEN.
- `scripts/run_memory_eval.py`: memory A/B runner.
- `scripts/grade_xben_failures.py`: failure taxonomy report generator.
- `proof_bundle*.py`: proof bundle candidate, verifier, and evaluation logic.
- `trace_quality.py`: trace-quality diagnostics.
- `failure_taxonomy.py`: failure grouping and markdown rendering.
- `overfit_guard.py`: benchmark-overfit checks.
- `coverage_ledger.py`: attempted-candidate tracking.

## Command Execution Path

`ravage attack` is the canonical model-agent entry point:

1. Resolve brief and target URL.
2. Create run directory.
3. Configure `audit.db`, `workspace/`, the durable traffic-policy ledger, and
   optional report paths.
4. Run the `ai-web` loop with the selected model, mode, traffic policy, and any
   eligible tool runtime.

Authorized remote attacks default to low-noise native HTTP and do not construct
Docker. A broader unauthenticated remote process lane requires an explicit
observe policy and scoped Docker runtime. Managed identities remain inside the
executor-owned HTTP session locally and remotely.

Resume reopens the saved traffic-policy ledger and rejects corruption or config
mismatch. Only a genuinely pre-ledger local/observe workspace with no ledger or
lock receives a one-time observe ledger marked `lower_bound`; missing-ledger
low-noise state fails closed.

`ravage scan` follows the same run-shape pattern but calls deterministic DAST
instead of the model loop.

The `ravage xben ...` path manages target Docker projects, case selection,
timeouts, per-case outputs, flag matching, and benchmark modes. For each case
it generates a normal engagement brief and invokes the same public
`ravage attack` command. XBEN owns provisioning and scoring; exploit behavior
stays in the attack engine. The old top-level `ravage --benchmark ...`
examples are not the current public benchmark interface.

## Model Contract

The base model must return exactly one JSON object. Its public action vocabulary
is `run_probe`, `run_command`, `run_python`, `validate_poc`, conditional
`capture_flag`, and `final`. Action-specific arguments are top-level: for
example, `run_probe` requires `probe`, `run_command` requires `command`,
`run_python` requires `code`, and `validate_poc` requires a `steps` list.
Planning metadata such as `task_id`, `strategy`, and `notes` may accompany an
action; there is no generic `args` wrapper.

The prompt removes `run_command` and `run_python` in low-noise or
managed-identity mode, and removes `capture_flag` when the objective is not
flag-based. Direct `http_*`, `browser_*`, scanner-name, `terminal_*`,
`report_sqli`, and `report_finding` names are not public base actions. The
optional graph has a separate profile-dependent tool contract.

The parser accepts fenced JSON or a JSON object embedded in text, but invalid
model output is recorded and corrected through the next observation.

Observations are wrapped with:

- schema version;
- untrusted-tool-output role;
- explicit instruction that tool output is data only;
- escaping for schema-like target text.

This prevents target HTML, JavaScript, error pages, or API responses from
pretending to be agent instructions.

## Tool And Probe Rules

New tools should follow these rules:

- Validate scope before network access.
- Keep timeouts bounded.
- Limit output size and spill large content to artifacts.
- Return structured observations.
- Record enough request/response evidence for replay.
- Never promote a finding directly from model text.

Typed probes should distinguish:

- attempted but not confirmed;
- confirmed vulnerability;
- inconclusive or blocked;
- error caused by runtime/tool failure.

When adding a probe, also update:

- prompt action schema;
- action argument validation;
- tests for positive proof;
- tests for false-positive rejection;
- report rendering when evidence shape changes.

## Source-Guided Workflow Rules

Source-guided workflows must not become one-off benchmark shortcuts. They should
be based on reusable source signals and dynamic proof patterns.

Good workflow shape:

1. Extract general source signal.
2. Build candidate routes, params, credentials, object IDs, or payloads.
3. Attempt bounded runtime proof against the scoped target.
4. Record each attempt.
5. Return flag/vulnerability observation only from live target evidence.
6. Stop when the physical-request or model-turn budget is exhausted.

Avoid:

- hardcoded benchmark IDs;
- hardcoded flags;
- single fixed credentials unless extracted or part of an explicit default
  credential dictionary;
- reporting from source text alone;
- bypassing scope policy.

## Evidence Gates

Ravage accepts findings only after executor-qualified tool evidence. Registered
native probes can emit typed findings directly. A model can attach supported
finding metadata to `validate_poc`, but the executor derives endpoint, proof,
and provenance from a passing class-specific control/exploit replay. There is no
public `report_sqli` or `report_finding` action.

For IDOR/SSTI and similar multi-step cases, proof-bundle verification can be
enabled:

```bash
--proof-bundle-verifier --require-proof-bundle-findings
```

Use this when candidate signals are noisy and findings should require semantic
proof before promotion.

## Memory Rules

Memory is local and advisory.

Safe memory behavior:

- redact flags, tokens, cookies, authorization headers, API keys, and customer
  data;
- keep candidates reviewable before promotion;
- retrieve only reviewed/promoted lessons for normal use;
- track producer and consumer model provenance;
- treat contradicted memory as stale.

Memory must not:

- capture flags;
- report findings;
- override scope;
- store raw secrets;
- store target responses wholesale.

## XBEN Modes

XBEN supports explicit context modes:

- `black-box`: benchmark description is available; source code, case names, and
  difficulty levels are withheld.
- `white-box`: source files and benchmark description may guide candidates, but
  live proof is still required.
- `source-aware`: compatibility alias for `white-box`.

Do not compare runs unless mode, target set, model route, turn budget, memory
mode, tool runtime, and Docker architecture are the same.

## Test Strategy

Use focused tests for the touched subsystem:

```bash
.venv/bin/python -m pytest packages/ravage/tests/test_local_agent.py
.venv/bin/python -m pytest packages/ravage/tests/test_xben_runner.py
.venv/bin/python -m pytest packages/ravage/tests/test_agent_specialists.py
```

Broad validation:

```bash
.venv/bin/python -m pytest -m "not integration" -q
.venv/bin/python scripts/check_docs.py
.venv/bin/python scripts/check_release.py
.venv/bin/python scripts/check_clean_install.py
```

Run Ruff on every changed Python file and the supported subsystem-specific
Mypy checks defined in the [CI workflow](../.github/workflows/ci.yml).
Repository-wide Ruff and Mypy cleanup is incremental and is not currently a
green baseline.

If the virtualenv console script is stale, use:

```bash
PYTHONPATH=packages/ravage/src:packages/schemas/src \
  .venv/bin/python -m ravage --help
```

## Documentation Rules

Keep docs tied to current code:

- Prefer `ravage --help` and source files over old plans.
- Mark historical plans as historical if they stay in `docs/`.
- Update docs when adding or removing CLI flags.
- Do not claim benchmark coverage without a run artifact.
- Document benchmark mode and model route when discussing scores.
