---
title: AI Agent Execution Plan
---

# AI Agent Execution Plan

> Archived historical execution plan. This file is not current technical
> documentation. Use [Architecture](../../architecture.md),
> [Technical Guide](../../technical-guide.md), and
> [How To Use](../../how-to-use.md) for current behavior.

This plan is written for an execution agent working in `/Users/oha/ravage`.
The goal is to turn ravage from a deterministic SQLi harness plus a basic AI
loop into a benchmark-native, evidence-first pentest agent that can run with
hosted or local models.

## Ground Rules

- Only test localhost, explicitly sandboxed targets, or authorized remote
  targets listed in the engagement scope.
- Do not weaken localhost-by-default, same-origin, or in-scope checks.
- Do not report a finding unless a tool produced proof and the validator gate
  accepted it.
- Every model reply, action, tool call, observation, rejection, and finding must
  be auditable.
- Every new capability must have at least one passing positive test and one
  false-positive/rejection test.
- Fake-model tests prove control flow only. They do not count as benchmark
  performance.

## Current Baseline

Implemented:

- `local-sqli`: deterministic SQLi agent.
- `ai-web`: model-driven loop with JSON actions and scoped HTTP/SQLi tools.
- `ai-web` workspace traces: `events.jsonl`, `transcript.jsonl`, and artifact
  spillover for large model/tool content.
- Model provider profiles for OpenAI-compatible local and hosted models.
- Local benchmark harness for `local-sqli` and `ai-web`.
- XBEN subset runner for controlled local Docker targets.

Known gaps:

- No successful real-model benchmark run has been completed for `ai-web`.
  The latest real attempt wrote
  `runs/benchmarks/ai-web-real-attempt-workspace/report.json` and failed because
  no Ollama/LM Studio/LiteLLM/vLLM endpoint was listening.
- No browser/auth/session runtime.
- No source-aware recon.
- Tool runtime is HTTP + SQLi probe only.
- No resumable workspace/log bundle.
- XBEN runner lacks resume/retry/range ergonomics.

## Milestone 1: Score `ai-web` In The Local Benchmark Harness

Status: completed. `BenchmarkCase.agent` supports `local-sqli | ai-web`,
`eval/ai_web_manifest.yaml` exists, and the test suite covers positive scoring,
report-without-proof rejection, and false negatives when the model never tests
the expected parameter.

Purpose: stop hiding behind deterministic `local-sqli` scores. The benchmark
runner must be able to run and score the real AI loop.

Files to edit:

- `packages/ravage/src/ravage/benchmark.py`
- `packages/ravage/tests/test_benchmark.py`
- `packages/ravage/tests/test_ai_agent.py`
- `eval/local_sqli_manifest.yaml`
- add `eval/ai_web_manifest.yaml`
- update `README.md`

Implementation steps:

1. Extend `BenchmarkCase.agent` from only `local-sqli` to `local-sqli | ai-web`.
2. Add optional benchmark fields:
   - `model_config: str | null`
   - `model_profile: str = local-ollama`
   - `model_tier: high | mid | low = mid`
   - `max_turns: int = 12`
3. Dispatch in `_run_case`:
   - `local-sqli` keeps existing path.
   - `ai-web` calls `run_ai_web_agent(...)`.
4. Keep fixture HTTP clients reusable for both agents.
5. For unit tests only, allow injecting a fake model client into the benchmark
   runner through an internal optional parameter. Do not expose this as a user
   CLI flag.
6. Update trace scoring:
     - Required common actions:
     - `orchestrator/engagement_loaded`
     - `orchestrator/scope_firewall_plan_generated`
     - `orchestrator/run_completed`
   - For `local-sqli`, keep `local_sqli_agent/attack_surface_emitted`.
   - For `ai-web`, require:
     - `ai_web_agent/model_routes_ready`
     - `ai_web_agent/model_reply_received`
     - at least one `ai_web_agent/agent_action_selected`
     - for positive cases, `ai_web_agent/finding_confirmed`
7. Add `eval/ai_web_manifest.yaml` with the same three cases as
   `eval/local_sqli_manifest.yaml`, but `agent: ai-web`.
8. Add tests:
   - `ai-web` benchmark passes vulnerable fixture with scripted model actions.
   - `ai-web` benchmark fails if the model tries `report_sqli` without prior
     `test_sqli_param`.
   - `ai-web` benchmark records a false negative if the model never tests the
     expected param.

Acceptance criteria:

```bash
cd /Users/oha/ravage
.venv/bin/python -m pytest packages/ravage/tests/test_benchmark.py packages/ravage/tests/test_ai_agent.py
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy packages scripts/xben/run_xben.py
```

Manual real-model command, only after Ollama/LM Studio/LiteLLM is running:

```bash
cd /Users/oha/ravage
PYTHONPATH=packages/ravage/src:packages/schemas/src \
  RAVAGE_OLLAMA_MODEL=qwen2.5-coder:32b \
  OLLAMA_BASE_URL=http://localhost:11434/v1 \
  .venv/bin/python -m ravage \
  --benchmark eval/ai_web_manifest.yaml \
  --output-dir runs/benchmarks/ai-web-local
```

Do not claim benchmark success until this real-model run completes and
`runs/benchmarks/ai-web-local/report.json` is inspected.

## Milestone 2: Make The AI Loop Observable Enough To Debug

Status: completed. `ai-web` now writes workspace events, transcripts, and
large-content artifacts. Benchmark `ai-web` cases write workspaces next to their
case DBs under the benchmark output directory.

Purpose: make ravage's trace clearer than other agents. The user should see
exactly what the agent is doing and why.

Files to edit:

- `packages/ravage/src/ravage/ai_agent.py`
- `packages/ravage/src/ravage/audit.py`
- add `packages/ravage/src/ravage/workspace.py`
- add tests under `packages/ravage/tests/`

Implementation steps:

1. Create a workspace directory:
   - default `.ravage/workspaces/<engagement_id>/`
   - allow override through settings/CLI later
2. Write JSONL event stream:
   - `events.jsonl`
   - one line per model reply, selected action, tool input, tool output,
     rejection, finding, final summary
3. Write model transcript:
   - `transcript.jsonl`
   - role/content entries, truncated at configured max length
4. Add stdout trace lines for:
   - model route selected
   - action selected
   - tool started
   - tool completed
   - evidence confirmed/rejected
5. Add audit row IDs or event IDs so SQLite rows and JSONL events can be
   correlated.
6. Add output truncation policy:
   - store full output in workspace artifact file when over 6,000 chars
   - audit row stores artifact path and snippet

Acceptance criteria:

- Running `ai-web` produces a workspace with `events.jsonl` and
  `transcript.jsonl`.
- Unit test verifies at least one model reply, one tool call, and one
  observation event are written.
- Large output test verifies artifact spillover instead of huge audit payloads.

## Milestone 3: Improve The Agent Protocol

Purpose: make the model less brittle and easier to steer.

Files to edit:

- `packages/ravage/src/ravage/ai_agent.py`
- `packages/ravage/tests/test_ai_agent.py`

Implementation steps:

1. Replace free-form `args: dict[str, object]` validation with per-action
   Pydantic models:
   - `DiscoverAttackSurfaceArgs`
   - `HttpGetArgs`
   - `HttpPostJsonArgs`
   - `TestSqliParamArgs`
   - `ReportSqliArgs`
   - `FinalArgs`
2. Return structured validation errors to the model when it emits invalid args.
3. Add explicit planner state:
   - discovered routes
   - tested params
   - confirmed evidence
   - rejected reports
4. Include a compact state summary in each observation.
5. Add `think` only as a private field if needed, but do not persist secrets or
   sensitive data outside audit policy.

Acceptance criteria:

- Invalid args do not crash the agent.
- Model gets a useful correction observation.
- Tests cover invalid path, escaped target, missing param, wrong method, and
  malformed JSON.

## Milestone 4: Add Source-Aware Recon

Purpose: differentiate from black-box-only agents with source-derived candidate
generation while remaining model-provider agnostic.

Files to add:

- `packages/ravage/src/ravage/source_recon.py`
- `packages/ravage/tests/test_source_recon.py`

Implementation steps:

1. Add optional CLI/settings field:
   - `--repo-path /path/to/app`
2. Implement static route extraction for common patterns:
   - FastAPI decorators: `@app.get`, `@router.post`, etc.
   - Flask decorators: `@app.route`
   - Express routes: `app.get`, `router.post`
   - Next.js app/pages API route paths by file layout
3. Extract likely sinks:
   - raw SQL calls
   - string-built queries
   - template rendering sinks
   - subprocess calls
   - outbound request/SSRF sinks
4. Emit source-derived attack surface entries with:
   - route path
   - method
   - params when obvious
   - source file path
   - line number
   - sink hints
5. Feed source recon into `discover_attack_surface` observation.

Acceptance criteria:

- Test fixture repo with FastAPI route and raw SQL sink produces a route and
  sink hint.
- Source recon never runs outside user-supplied repo path.
- AI observation includes both dynamic and source-derived routes.

## Milestone 5: Browser/Auth Runtime

Purpose: handle authenticated targets and real workflows.

Files to add/edit:

- add `packages/ravage/src/ravage/auth_config.py`
- add `packages/ravage/src/ravage/browser_tools.py`
- update schemas if needed
- add Playwright dependency only when the repo is ready for it

Implementation steps:

1. Add auth config model:
   - `login_type: form | sso | none`
   - `login_url`
   - credentials
   - optional TOTP secret
   - natural-language login steps
   - success condition: `url_contains` or `element_present`
2. Add browser tools:
   - `browser_open`
   - `browser_click`
   - `browser_type`
   - `browser_extract_forms`
   - `browser_snapshot`
3. Add session reuse:
   - cookies persisted inside workspace
   - never outside workspace by default
4. Validate auth before expensive agent runs.
5. Feed forms and authenticated routes into attack surface.

Acceptance criteria:

- Test against a local form-login fixture.
- Agent can log in, detect success condition, and use authenticated session.
- Failed login produces clear audit row and stops early.

## Milestone 6: Tool Runtime Expansion

Purpose: move from one SQLi probe to a real agent toolbelt.

Files to add/edit:

- `packages/ravage/src/ravage/tool_runtime.py`
- MCP server packages under `packages/mcp_servers/`
- tests for each wrapper

Implementation order:

1. HTTP tools:
   - GET/POST form/POST JSON
   - headers
   - cookies
   - redirect policy
2. Directory/content discovery:
   - ffuf wrapper
   - bounded wordlists
   - same-origin only
3. Crawler:
   - katana wrapper
   - max depth/pages
4. Template scanner:
   - nuclei wrapper
   - severity filters
5. SQLi validator:
   - sqlmap wrapper for local/sandbox only
   - require explicit endpoint/param
   - fixed timeout
6. Python scratch tool:
   - workspace-only files
   - no network except target origin
   - timeout and output cap

Acceptance criteria:

- Every wrapper has:
   - timeout
   - output cap
   - target-scope validation
   - audit event
   - positive test
   - blocked out-of-scope test

## Milestone 7: Vulnerability Specialists

Purpose: split work by objective and vulnerability class without overbuilding
first.

Files to add:

- `packages/ravage/src/ravage/specialists.py`
- prompt files under `packages/agents/*/prompts/`

Implementation steps:

1. Define specialist contract:
   - objective
   - scoped context
   - allowed tools
   - max turns
   - findings queue
2. Start with:
   - `recon`
   - `injection`
   - `xss`
   - `auth`
   - `authz`
   - `ssrf`
3. Keep fresh context per specialist:
   - only pass relevant routes/evidence/history
   - durable state stays in workspace/audit
4. Add coordinator OPPLAN:
   - current objective
   - why now
   - allowed tools
   - stop condition

Acceptance criteria:

- Coordinator can run recon then injection specialist on existing SQLi fixture.
- Specialist cannot report without validator proof.
- Specialist traces are separated in workspace.

## Milestone 8: Upgrade XBEN Runner

Purpose: make iteration honest and repeatable.

Files to edit:

- `scripts/xben/run_xben.py`
- add tests where feasible without Docker

Implementation steps:

1. Add benchmark selection:
   - `--range 1-10`
   - `--ids 1,5,10`
   - `--all`
   - keep `--all-sqli`
2. Add resume:
   - write `state.json`
   - skip completed success cases unless `--force`
3. Add retry failed:
   - `--retry-failed <run-dir>`
   - infer latest run if no path
4. Add flag modes:
   - exact expected flag
   - any flag
   - pattern flag
5. Add per-case timeout.
6. Add model profile/tier flags and pass them to `ai-web`.
7. Emit summary:
   - solved
   - failed
   - errored
   - timed out
   - runtime
   - model profile

Acceptance criteria:

- Dry-run selection prints expected XBEN IDs.
- Resume skips completed cases.
- Retry-failed selects only failed/errored/timed-out cases.
- Existing SQL smoke still works.

## Milestone 9: Real Benchmark Runs

Purpose: collect honest numbers.

Prerequisites:

- Local OpenAI-compatible model server running, or hosted key configured.
- Docker running.
- Prefer native amd64 Linux host for XBEN. Apple Silicon emulation caused
  MySQL 5.7 crashes.

Commands:

```bash
cd /Users/oha/ravage
curl -sS http://127.0.0.1:11434/v1/models
```

Local harness:

```bash
PYTHONPATH=packages/ravage/src:packages/schemas/src \
  RAVAGE_OLLAMA_MODEL=qwen2.5-coder:32b \
  OLLAMA_BASE_URL=http://localhost:11434/v1 \
  .venv/bin/python -m ravage \
  --benchmark eval/ai_web_manifest.yaml \
  --output-dir runs/benchmarks/ai-web-local
```

XBEN smoke:

```bash
PYTHONPATH=packages/ravage/src:packages/schemas/src \
.venv/bin/python scripts/xben/run_xben.py \
  --benchmarks-root /private/tmp/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/ai-web-sqli-smoke \
  --ids XBEN-006-24 XBEN-038-24 XBEN-071-24 \
  --mode black-box \
  --comparison-profile mapta-awe-xben \
  --agent ai-web \
  --agent-mode ctf-free-roam \
  --model-profile local-ollama \
  --model-tier mid
```

Acceptance criteria:

- Save reports under `runs/`.
- Summarize solved/failed/errored exactly.
- Do not compare against other repos unless the benchmark mode is comparable
  (black-box vs source-aware, hints/no hints, native Docker vs emulation).

## Milestone 10: Differentiation Checklist

Ravage should explicitly optimize for these differentiators:

1. Evidence-first
   LLMs propose actions; tools and validators decide findings.

2. Local-first
   Ollama, LM Studio, vLLM, llama.cpp, and LiteLLM must be normal paths, not
   side paths.

3. Transparent trace
   A user can inspect every step, observation, and rejection.

4. Hybrid deterministic + AI
   Deterministic exploit/validator modules should do proof-heavy work.

5. Benchmark-native
   Every feature lands with a benchmark or fixture.

6. Safe by default
   Localhost/same-origin/scope enforcement remains non-negotiable.

7. Source + dynamic
   Combine source-aware recon with live proof, not one or the other.

## First Task For The Next Execution Agent

Start with Milestone 1 only.

Deliverables:

- `ai-web` supported in `benchmark.py`.
- `eval/ai_web_manifest.yaml`.
- tests proving benchmark scoring of the AI loop with a fake model.
- README command for running real `ai-web` benchmark.
- All checks passing:

```bash
.venv/bin/python -m pytest packages/schemas packages/ravage/tests
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy packages scripts/xben/run_xben.py
```

Stop after Milestone 1 and report the exact benchmark command to run with a real
model endpoint.
