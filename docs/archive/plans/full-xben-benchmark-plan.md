---
title: Full XBEN Benchmark Plan
---

# Full XBEN Benchmark Plan

> Archived historical benchmark plan. This file is not current technical
> documentation. Use [Benchmarking](../../benchmarking.md),
> [How To Use](../../how-to-use.md), and
> [Technical Guide](../../technical-guide.md) for current XBEN commands and
> behavior.

This is the execution plan for making Ravage compete on the real XBOW/XBEN
validation benchmark, not the local three-case SQLi smoke manifest.

## Target Benchmark

Use the official XBOW validation benchmark set:

- Repository: https://github.com/xbow-engineering/validation-benchmarks
- Local path currently used by this workspace:
  `/private/tmp/xbow-validation-benchmarks/benchmarks`
- Target universe: `XBEN-001-24` through `XBEN-104-24`
- Scoring mode: one hidden flag per benchmark case
- Default evaluation mode: black-box, no source inspection, using only the
  challenge metadata/description and the running target

Why this target:

- The XBOW repository describes this as a 104-case benchmark set for evaluating
  web offensive tools.
- It supports all-case, range, resume, retry-failed, flag verification, cost
  tracking, and per-case log workflows.
- It allows comparable by-level and all-level totals when the benchmark context
  mode is stated clearly.

## Non-Negotiable Outcome

Ravage must produce a comparable report:

```json
{
  "benchmark": "xbow-validation-benchmarks",
  "mode": "black-box",
  "total": 104,
  "solved": 0,
  "failed": 0,
  "errored": 0,
  "timeout": 0,
  "model_profile": "hosted-openai",
  "model_tier": "low",
  "total_cost_usd": null,
  "cases": []
}
```

Each case result must include:

- benchmark ID
- name
- level
- target URL
- injected flag hash or flag ID
- solved/failed/errored/timeout status
- found flag, if any
- elapsed seconds
- model request count
- HTTP request count
- estimated or actual token/cost data when available
- workspace path
- transcript path
- events path
- artifacts path
- final agent answer
- failure reason

The final benchmark claim must be phrased as:

```text
Ravage solved X/104 official XBOW validation benchmarks in black-box mode,
using <model/profile>, with <$cost> total cost and <runtime> total runtime.
```

No comparison against other agents is valid unless the report includes the same
case universe and mode.

## Current Gaps

1. The current `eval/ai_web_manifest.yaml` is only three local cases.
2. The legacy subset runner was removed; use `scripts/xben/run_xben.py`.
3. The AI tool contract now covers several non-SQLi probes, but still lacks the
   breadth and depth needed for most of XBEN.
4. The finding schema supports SQLi plus a generic vulnerability finding for
   supported probe classes; richer per-class schemas are still future work.
5. Recon is too shallow for arbitrary web apps.
6. There is no general flag-capture action.
7. There is no browser or form workflow.
8. There is no multipart upload, arbitrary header, cookie, XML, GraphQL, or raw
   HTTP request support.
9. There is no full-run resume/retry/range/level workflow.
10. The local Apple Silicon Docker environment may distort results for some
    amd64 targets.
11. KIV: local Docker is currently not a reliable XBEN runner on this machine.
    A 10-case memory A/B attempt exhausted host disk during `XBEN-066-24`, and
    Docker logs later showed containerd blob input/output errors. Treat local
    Docker scoring as paused until Docker Desktop is factory-reset or XBEN is
    moved to a native x86_64 Linux host.

## Build Track 1: Real XBEN Runner

Goal: replace the smoke runner with a benchmark-native runner that can execute
all 104 cases with the real agent.

Add:

- `scripts/run_xben.py`
- `packages/ravage/src/ravage/xben.py`
- `packages/ravage/tests/test_xben_runner.py`

Required CLI:

```bash
docker build -t ravage-kali:latest -f sandbox/kali.Dockerfile sandbox

.venv/bin/python scripts/run_xben.py \
  --benchmarks-root /private/tmp/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/full-blackbox \
  --all \
  --mode black-box \
  --agent ai-web \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --max-turns 40 \
  --case-timeout-seconds 1800 \
  --max-model-requests-per-case 40 \
  --max-cost-usd 150 \
  --allow-paid-models
```

Also support:

- `--range 1-10`
- `--ids XBEN-006-24 XBEN-038-24`
- `--levels 1 2 3`
- `--resume`
- `--retry-failed`
- `--dry-run`
- `--list`
- `--preflight`
- `--concurrency 1`
- `--docker-platform linux/amd64`
- `--flag-mode exact`
- `--flag-mode pattern`

Runner behavior:

1. Discover all benchmark directories and sort by numeric ID.
2. Parse `benchmark.yaml`; fall back to `benchmark/benchmark-config.json` if
   needed.
3. Generate a unique flag per case:

   ```text
   flag{ravage_<run_id>_<xben_id>}
   ```

4. Build with both forms because benchmark Dockerfiles vary:

   ```bash
   docker compose build --build-arg flag=<flag> --build-arg FLAG=<flag>
   ```

5. Start with:

   ```bash
   docker compose up -d --wait
   ```

6. Resolve target URL from `benchmark.yaml` `main-service` and
   `main-service-port` when present; otherwise fall back to first published
   compose port.
7. Write a per-case engagement brief that includes:
   - target URL
   - official challenge description
   - flag objective
   - legal sandbox scope
   - max runtime/model/HTTP budgets
8. Run `ai-web`.
9. Score solved if the exact injected flag appears in:
   - `capture_flag` events
   - findings proof
   - transcript observations
   - artifacts
   - final answer
10. Always stop containers with:

    ```bash
    docker compose down --remove-orphans -v
    ```

Acceptance:

- `--dry-run --all` lists all 104 cases.
- `--preflight --all` writes a no-spend budget report.
- `--range 1-3` runs `ai-web`, not `local-sqli`.
- Interrupted runs can resume without rerunning solved cases.
- `--retry-failed` only reruns failed/errored/timeouts.
- Report JSON is valid and includes per-case workspaces.

## Build Track 2: General Agent Action Contract

Goal: continue reducing SQLi-specific assumptions so the model can operate
across the benchmark.

Change:

- `packages/ravage/src/ravage/ai_agent.py`
- `packages/ravage/src/ravage/agent_skills/web-pentest/skills.md`
- `packages/ravage/tests/test_ai_agent.py`

Add actions:

```text
discover_attack_surface
http_request
form_post
multipart_upload
set_cookie
set_header
graphql_request
xml_request
test_sqli_param
test_xss_param
test_ssti_param
test_command_injection_param
test_lfi_param
test_idor_candidate
test_jwt_tamper
capture_flag
report_finding
final
```

Replace narrow actions:

- Keep `http_get` and `http_post_json` as compatibility wrappers.
- New primary action is `http_request`:

```json
{
  "action": "http_request",
  "args": {
    "method": "POST",
    "path": "/login",
    "query": {},
    "headers": {},
    "cookies": {},
    "body_type": "form|json|xml|raw|none",
    "body": {}
  }
}
```

Add hard gates:

- `capture_flag` only accepts strings matching the injected flag pattern or
  exact generated flag.
- `report_finding` only accepts findings with tool-produced evidence.
- No out-of-origin requests unless the benchmark metadata explicitly exposes an
  in-scope internal service through the target app.
- Every action must record kill-chain stage, request, response snippet, and
  artifact IDs.

Acceptance:

- Unit tests prove the model can submit arbitrary form and JSON requests.
- Unit tests prove `capture_flag` records a solved case.
- Unit tests prove fake flags or guessed flags are rejected.
- Unit tests prove out-of-scope URLs are blocked.

## Build Track 3: Recon Upgrade

Goal: discover enough surface for arbitrary benchmark apps.

Change:

- `packages/ravage/src/ravage/dry_run.py`
- `packages/ravage/src/ravage/ai_agent.py`

Add:

- HTML form parser:
  - method
  - action
  - input names/types/defaults
  - submit buttons
  - hidden fields
- Link crawler:
  - same-origin only
  - configurable depth
  - deduplicate normalized URLs
  - collect status/title/content-type
- JavaScript endpoint extractor:
  - fetch/XHR URLs
  - route-like strings
  - GraphQL endpoint candidates
- Common path discovery:
  - `/robots.txt`
  - `/sitemap.xml`
  - `/login`
  - `/admin`
  - `/api`
  - `/graphql`
  - challenge-specific hints from description
- Cookie/session inventory.
- Response classifier:
  - login page
  - reflected input
  - upload form
  - JSON API
  - XML/SOAP API
  - error stack trace
  - likely framework

Acceptance:

- Recon against at least 10 representative XBEN apps emits forms, links, cookies,
  and candidate endpoints.
- Recon output is persisted as `attack_surface.json`.
- The agent prompt receives a compact recon summary, not raw giant HTML.

## Build Track 4: Vulnerability Specialists

Goal: cover the benchmark categories that dominate the 104 cases.

Add:

- `packages/ravage/src/ravage/tools/xss.py`
- `packages/ravage/src/ravage/tools/ssti.py`
- `packages/ravage/src/ravage/tools/command_injection.py`
- `packages/ravage/src/ravage/tools/lfi.py`
- `packages/ravage/src/ravage/tools/idor.py`
- `packages/ravage/src/ravage/tools/jwt.py`
- `packages/ravage/src/ravage/tools/upload.py`
- `packages/ravage/src/ravage/tools/xxe.py`
- `packages/ravage/src/ravage/tools/deserialization.py`

Priority order:

1. SQLi/blind SQLi/GraphQL SQLi
2. XSS
3. SSTI
4. Command injection
5. LFI/path traversal/static resource disclosure
6. IDOR/authz/default credentials/business logic
7. Upload/XXE
8. JWT/cookie/crypto/deserialization
9. CVE-specific probes
10. race/smuggling hard cases

Each specialist must expose:

```text
candidate selector -> bounded probe -> evidence evaluator -> flag extractor
```

Acceptance:

- Each specialist has isolated unit tests.
- Each specialist has at least one local integration fixture or XBEN case run.
- Specialists never report a finding without evidence.
- Specialists can pass discovered flags back through `capture_flag`.

## Build Track 5: Browser/Auth Runtime

Goal: solve cases that require login flows, DOM behavior, uploads, XSS
confirmation, or session workflows.

Add:

- `packages/ravage/src/ravage/browser.py`
- Optional Playwright dependency group.
- Browser tool actions:

```text
browser_open
browser_click
browser_fill
browser_submit
browser_login
browser_eval
browser_screenshot
browser_upload_file
browser_cookies
browser_local_storage
```

Use browser only when needed:

- login form
- JS-rendered app
- XSS verification
- upload form
- stateful workflow

`browser_login` should be the default for ordinary username/password forms. It
fills configured selectors, submits the form, validates success/failure markers,
and syncs same-origin browser cookies into the HTTP client without exposing raw
cookie values in observations.

Acceptance:

- Login workflow test against a fixture.
- Upload workflow test against a fixture.
- XSS reflection/DOM confirmation test against a fixture.
- Browser artifacts include screenshots and DOM snippets.

## Build Track 6: Findings And Flag Schema

Goal: record benchmark progress and security proof without forcing every case
through `SqlInjectionFinding`. The current schema has a generic
`VulnerabilityFinding`; richer per-class schemas remain future work.

Change:

- `packages/schemas/src/pentest_schemas/finding.py`
- `packages/ravage/src/ravage/audit.py`

Add finding classes:

```text
XssFinding
SstiFinding
CommandInjectionFinding
LfiFinding
PathTraversalFinding
IdorFinding
AuthBypassFinding
SsrfFinding
XxeFinding
JwtFinding
FileUploadFinding
DeserializationFinding
InformationDisclosureFinding
BusinessLogicFinding
CveFinding
GenericFlagCaptureFinding
```

Add event:

```json
{
  "actor": "ai_web_agent",
  "action": "flag_captured",
  "payload": {
    "benchmark_id": "XBEN-001-24",
    "flag": "flag{...}",
    "source": "http_response|artifact|final_answer|finding_proof",
    "proof_request": "...",
    "proof_response_snippet": "..."
  }
}
```

Acceptance:

- Scoring can solve a case without a typed vulnerability finding if the flag is
  captured with proof.
- Findings remain useful for human reports.
- JSON report includes both `solved` and `findings`.

## Build Track 7: Cost And Safety Gates

Goal: prevent wasting credits on a broken full run.

Add to XBEN preflight:

- total selected cases
- max model requests
- max output tokens
- model route readiness
- expected worst-case cost when pricing exists
- Docker availability
- benchmark root existence
- benchmark case metadata validity
- native architecture warning
- paid model explicit approval requirement

Add runtime kill switches:

- per-case model request cap
- per-case HTTP request cap
- per-case wall-clock timeout
- total run cost cap
- target-scope guard
- repeated-action loop detector
- no-progress timeout

Acceptance:

- Full `--preflight --all` does not call the model.
- Full run refuses paid hosted models without `--allow-paid-models`.
- Runner stops before exceeding configured budget.

## Build Track 8: First Competitive Milestones

Do not jump straight to 104 paid cases. The milestones below are the path to a
real full benchmark without burning money blindly.

### Milestone A: Harness correctness

Command:

```bash
.venv/bin/python scripts/run_xben.py \
  --benchmarks-root /private/tmp/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/preflight-all \
  --all \
  --agent ai-web \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --preflight
```

Pass criteria:

- sees 104 cases
- no model calls
- no Docker mutation
- valid JSON budget report

### Milestone B: No-spend deterministic plumbing

Run 3-5 known easy cases with a fake model script or deterministic tool policy.

Pass criteria:

- build/up/down works
- target URL resolution works
- flag injection works
- score detects solved vs unsolved correctly

### Milestone C: Hosted canary on 5 XBEN cases

Use one case each from:

- SQLi
- XSS
- SSTI
- command injection
- IDOR/default credentials

Pass criteria:

- report has 5 cases
- each case has workspace artifacts
- no runner crashes
- at least one non-SQLi path is attempted

KIV note: do not run Milestone C or larger XBEN batches on the current local
Mac Docker Desktop state. Use a repaired Docker data store or a native x86_64
Linux runner, then rerun the same selected cases with `--memory off` and
`--memory read` for the memory-learning comparison.

### Milestone D: Level 1 full run

Run all level-1 cases.

Pass criteria:

- comparable `solved/N` report
- failures categorized by missing capability
- cost and runtime included

### Milestone E: Full 104 run

Run all 104 cases only after Level 1 has stable harness behavior.

Pass criteria:

- completed report for 104 selected cases
- each case marked solved/failed/errored/timeout
- retry-failed works
- report can be shared as the honest benchmark result

## Expected Short-Term Score

With only SQLi-level coverage, Ravage should not be expected to compete.

After Tracks 1-3 and SQLi/blind SQLi upgrades:

- likely solves: simple SQLi and some information-disclosure cases
- likely misses: most XSS, SSTI, command injection, authz, upload, browser, JWT,
  deserialization, crypto, race/smuggling

After Tracks 1-7:

- Ravage can legitimately attempt the full 104-case run.
- The first full score will still likely trail established agents, but it will
  be a real comparable number instead of a smoke-test claim.

## Definition Of Done

This work is done when the repo can run:

```bash
.venv/bin/python scripts/run_xben.py \
  --benchmarks-root /private/tmp/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/full-blackbox \
  --all \
  --mode black-box \
  --agent ai-web \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --max-turns 40 \
  --case-timeout-seconds 1800 \
  --max-model-requests-per-case 40 \
  --max-cost-usd 150 \
  --allow-paid-models
```

and produce:

- `runs/xben/full-blackbox/report.json`
- `runs/xben/full-blackbox/preflight.json`
- one workspace per benchmark case
- per-case Docker logs
- per-case transcript/events/artifacts
- exact solved count over 104
- total runtime
- total cost estimate or actual cost
- failure categories suitable for the next improvement cycle
