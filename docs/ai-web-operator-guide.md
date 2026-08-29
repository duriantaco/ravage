---
title: AI Web Operator Guide
---

# AI Web Operator Guide

`ai-web` is the first real model-driven ravage agent. It runs a loop:

1. send scoped context to the model,
2. require one JSON action,
3. execute one scoped tool,
4. append the observation back to the transcript,
5. repeat until `final` or the turn budget is reached.

It runs against localhost targets by default. A public/DNS target is rejected
unless its URL is declared in the brief and the operator passes
`--authorized-remote-target`. Authorized remote attacks default to native
metered HTTP under the whole-run low-noise policy and do not construct Docker.
An unauthenticated remote run can deliberately opt into broader process-backed
work with `--traffic-policy observe --tool-runtime docker`. With a managed
identity those process lanes are always absent, so requests stay inside the
scoped in-process HTTP owner. Tools must stay on the authorized target origin
and inside scope.
Findings are only written after a matching typed probe produces confirmed,
replayable evidence for the same class, endpoint, and parameter.

HTTP redirects are validated before they are followed. In the optional
process-capable observe/Docker lane, the runtime records
`orchestrator/scope_firewall_plan_generated`, applies the container egress
firewall before supported external tools run, and then records
`orchestrator/scope_firewall_rules_applied` with a rule digest. Local host
runtime records the plan only and relies on application-layer scope checks.
Firewall-plan destinations are IP/CIDR-only; hostname entries are skipped rather
than supported with broad DNS egress.

Use `ai-web` only for local research, authorized defensive testing, and
controlled benchmarks. Do not run it against third-party systems or any
environment where you do not have explicit written authorization and agreed
rules of engagement.

The default runtime strategy is code-owned. An optional reviewed knowledge pack
containing one or more `SKILL.md` files can be supplied with
`--knowledge-pack PATH`; its path and SHA-256 metadata are recorded with the
run and benchmark artifacts.

## Preconditions

Install Ravage from this source checkout and run commands from the repository
root. If the CLI is not on `PATH`, use `.venv/bin/ravage`.

Start a legal local target. For the bundled Acme lab:

```bash
ravage doctor --workflow lab
ravage lab up ravage-acme-box
```

Start a model endpoint. For Ollama:

```bash
ollama serve
```

Verify the model server:

```bash
curl -sS http://127.0.0.1:11434/v1/models
```

If this command returns connection refused, `ai-web` cannot run with
`local-ollama`.

## Run `ai-web`

```bash
RAVAGE_OLLAMA_MODEL=qwen2.5-coder:32b \
OLLAMA_BASE_URL=http://localhost:11434/v1 \
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --model-profile local-ollama \
  --model-tier mid \
  --memory off \
  --max-turns 12 \
  --report
```

The wrapper prints the run directory, stdout path, report path, traffic summary,
and final status. Plain progress and tool summaries are written to
`runs/<brief>-attack-<timestamp>/stdout.log`; structured model actions and
observations remain in the workspace events and transcript.

Expected detailed trace shape:

```text
[plan] mode=ai-agent agent=ai-web model_profile=local-ollama model_tier=mid
[kill-chain] 1/7 authorization_scope detail=...
[kill-chain] 4/7 hypothesis_generation detail=...
[ai:turn] 1 stage=2/7 reconnaissance action=run_probe probe=surface_map
[tool] run_probe probe=surface_map routes=...
[observation] OBSERVATION ...
```

When an observation is appended to the model transcript, Ravage wraps it in a
`BEGIN_RAVAGE_UNTRUSTED_TOOL_OBSERVATION` envelope using
`ravage-observation-envelope-v1`. Target-derived strings that look like agent
action JSON, confirmation fields, or reporting commands are escaped in the
transcript; the raw evidence payload remains in audit/workspace events.

If a confirmed SQLi is found, stdout includes:

```text
[finding] confirmed sql_injection endpoint=... param=...
```

Stop the lab when finished:

```bash
ravage lab down ravage-acme-box
```

## Run Deterministic DAST

Use `ravage scan` when you want a reproducible DAST pass without spending model
turns. It reuses the same scoped route discovery, typed probes, audit store, and
report writer as `ai-web`, but chooses recommended probes deterministically.

```bash
ravage scan examples/labs/ravage-acme-box/brief.yaml \
  --run-dir runs/acme-scan \
  --probe surface_map \
  --probe secret_sweep \
  --report
```

Use `--all-probes` to run the full deterministic catalog, or repeat `--probe`
for a focused run. Inspect available probes with:

```bash
ravage scan --help
ravage tools list
```

Each run writes:

```text
runs/<brief>-scan-<timestamp>/
  audit.db
  report.md
  report.json
  workspace/
```

The scan command is deterministic and should normally use a new `--run-dir` for
each run. External tool runtime selection is accepted for command compatibility;
the current built-in scan probes run in-process:

```bash
ravage scan examples/labs/ravage-acme-box/brief.yaml \
  --all-probes \
  --report
```

Install tools where Ravage runs. For a host runtime, that means the
same shell, VM, WSL environment, or PATH that launches Ravage. For Docker
runtime, pull the signed image (with a local-build fallback) with
`ravage tools install --method docker --execute`.
From a source checkout, `ravage tools install --execute` is the direct fix
for missing-tool preflight output.
The helper sets `.tools/bin`, `.tools/go-root/bin`, and repo-local HOME/XDG
state directories before running `ravage tools check`.
The host installer writes Go-based tools to `.tools/bin` and can bootstrap a
repo-local Go toolchain under `.tools/go-root` when the system has no `go`.
A separate vulnerable target VM does not need those tools unless Ravage itself
is running inside that VM.

## Current CLI Shape

The current public entry point uses explicit subcommands such as
`ravage attack`, `ravage scan`, `ravage xben`, and `ravage competitors`.
Historical YAML run-loader examples are not active operator instructions.

For attack runs, pass the brief and run settings directly:

```bash
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --memory off \
  --allow-paid-models \
  --report
```

The public CLI currently accepts `--memory off` only. Active retrieval, writes,
review, and promotion are design-stage. See [Memory Design](memory.md) for the
planned local SQLite model and review policy.

## Authorized Remote Target

Use this only for a site you own or have written permission to test. The target
URL must match an entry in the brief scope.

```yaml
# examples/remote_authorized_brief.yaml
engagement_id: "99999999-9999-4999-8999-999999999999"
scope:
  in_scope:
    - "https://staging.example.test"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "web_application_assessment"
budget:
  max_cost_usd: 5.0
  max_runtime_min: 20
```

For a normal pentest, prefer `web_application_assessment` or
`api_security_assessment`. Do not ask operators to guess a vulnerability class
such as `xss` or `jwt` before testing. Use specific objectives only for a
targeted retest where the class is known from prior evidence.

Recommended objective patterns:

- Broad web pentest: `objectives: ["web_application_assessment"]`
- API-focused pentest: `objectives: ["api_security_assessment"]`
- Targeted retest: `objectives: ["xss"]`, `["jwt"]`, `["sql_injection"]`, or
  another known class.
- Benchmark/lab: keep `capture_flag`; use the challenge description and live
  target evidence rather than vulnerability-class labels.

If the actual issue is XSS but a user accidentally writes `jwt`, Ravage should
not treat that label as proof. Prefer the broad objective for first-pass
testing so live route, response, browser, source-guided, and tool signals drive
the workflow.

For a user-owned staging app, generate the brief from its actual URL and
explicitly acknowledge the remote target when traffic starts:

```bash
ravage init https://staging.example.test --brief brief.yaml
ravage doctor --workflow attack \
  --brief brief.yaml \
  --authorized-remote-target
ravage attack brief.yaml \
  --authorized-remote-target \
  --allow-paid-models \
  --max-turns 12 \
  --report
```

The documented remote command uses native metered HTTP only. Whole-run low-noise
mode disables bounded tool recon and all opaque process/browser-process schemas
so every permitted target request shares the durable cap and sub-1-RPS pacing.
Local attacks instead default to observe mode and `--tool-runtime host`; use
`--tool-runtime auto` for local Docker fallback or `--tool-runtime docker` to
require the image.

If the complete remote origin is authorized and the written ROE permits command,
Python, scanner, or other process-backed work, prepare the tool image separately:

```bash
ravage tools install --method docker --execute
```

Then opt into that broader unauthenticated lane explicitly:

```bash
ravage attack brief.yaml \
  --authorized-remote-target \
  --traffic-policy observe \
  --tool-runtime docker \
  --allow-paid-models \
  --report
```

For a localhost run that deliberately uses Docker fallback, the corresponding
tool-runtime selection is:

```bash
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --env-file .env.ravage \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --max-turns 20 \
  --allow-paid-models \
  --report
```

For normal new attacks, leave `--run-dir` unset so Ravage creates a timestamped
state directory. Reuse a prior attack directory only with `--resume`.

In the optional remote observe/Docker lane, tool containers have no general
egress: an internal network and fixed forwarder restrict them to scoped target
host/port pairs, with initial DNS resolution pinned in run evidence. Raw TCP
tools cannot enforce a URL path, so use that lane only when the whole scoped
origin is authorized.

## Actions The Model Can Call

The base `ai-web` loop accepts exactly one JSON object per turn. Its public
action vocabulary is `run_probe`, `run_command`, `run_python`, `validate_poc`,
`capture_flag`, and `final`. Action-specific fields are top-level; there is no
generic `args` wrapper:

```json
{
  "action": "run_probe",
  "task_id": "<active task id>",
  "probe": "surface_map",
  "timeout_seconds": 10,
  "notes": "map the scoped surface",
  "expected_signal": "routes, forms, or API endpoints",
  "fallback": "run the next eligible specialist"
}
```

The effective catalog is narrower than the parser vocabulary:

- `run_probe` must select an entry in the current turn's `available_probes`.
- `validate_poc` replays a short supported control/exploit HTTP sequence. It may
  carry finding metadata, but the executor derives endpoint, proof, and
  provenance and accepts only class-specific evidence.
- `run_command` and `run_python` are available only to eligible unauthenticated
  observe-mode runs. Low-noise and managed-identity modes remove them.
- `capture_flag` appears only when the brief has a flag objective and accepts
  only an exact proof string already observed in target evidence.
- `final` closes the loop without inventing a finding or flag.

A verified `run_probe` result can record a typed finding automatically.
`report_sqli` and `report_finding` are not public actions; `invalid` is an
internal parser result, not a model-callable action. Direct `http_*`, `browser_*`,
scanner-name, and `terminal_*` actions are also not part of the base contract.
The optional graph uses a separate, profile-dependent tool contract.

Browser confirmation is reached through an eligible probe such as
`run_probe dom_execution`, not a direct browser action. In unauthenticated
observe mode that probe can use Playwright; remote navigation, redirects, and
subresources remain scope checked, and the Chrome DevTools fallback stays
local-only. Low-noise mode removes external-process browser probes, and managed
identity excludes them because they cannot preserve executor-owned credentials.

## Tool Runtime Install Manager

Use `ravage tools check` to see which tools are available on the host and in
the Docker tool image:

```bash
ravage tools check
```

## Runtime Preflight

Use `ravage doctor --workflow attack --brief BRIEF.yaml` to validate the selected
target, model route, traffic policy, and any required runtime. Use
`ravage tools check` to inspect host and Docker scanner availability. The public
attack loop builds `available_probes` dynamically for each prompt from the
traffic policy, identity boundary, and installed runtime; it does not expose an
operator-authored broad scanner-action catalog or promise a
`workspace/capabilities.json` preflight artifact.

Installing Ravage from this source checkout gives you the `ravage` CLI. The
Python install does not install external scanners such as `nmap`, `gobuster`,
`sqlmap`, `nikto`, `katana`, or `nuclei`; those are host or Docker runtime
tools.

Use `ravage tools install` from a source checkout to preview or install
external tools before running model-driven attacks:

```bash
ravage tools install --method apt
ravage tools install --method apt --execute
ravage tools check
```

From a source checkout, prefer the wrapper when you want the script to manage
repo-local tool paths, state directories, installation, and verification:

```bash
ravage tools install --method apt --execute
ravage tools install --method docker --execute
```

The apt path installs apt-available tools such as `nmap`, `whatweb`,
`gobuster`, `dirb`, `nikto`, and `sqlmap`, then installs Go-based tools such as
`ffuf`, `katana`, and `nuclei` into `.tools/bin`. If Go is missing, the helper
bootstraps it under `.tools/go-root`.

The install manager is a dry run by default. Add `--execute` only when you want
Ravage to run the selected Docker, apt, or Homebrew commands:

```bash
ravage tools install --method docker --execute
```

Install methods:

- `auto`: chooses Docker first, then Homebrew on macOS, apt on Linux/Kali/WSL,
  then manual guidance.
- `docker`: pulls and verifies the signed multi-architecture GHCR image, then
  tags it locally as `ravage-kali:latest`. If the pull fails, inspect the error
  and rerun with `--no-cache` only to request an unsigned local build fallback.
  This is the most repeatable path when Docker is available.
- `apt`: installs tools into the current Linux/Kali/WSL/VM environment.
- `brew`: installs tools into the current macOS shell.
- `manual`: prints PATH and `RAVAGE_<TOOL>_BIN` guidance without running an
  installer.

Tools need to be available wherever the Ravage process runs: the host shell,
WSL, a Kali VM, or the Docker tool image. They do not need to be installed
inside the vulnerable target VM unless Ravage itself is running there.

Host checks use `RAVAGE_<TOOL>_BIN` overrides first, then `PATH`. This covers
custom install paths such as `RAVAGE_NMAP_BIN=C:\Program Files\Nmap\nmap.exe`
on Windows. Source-checkout host checks also look in `.tools/bin`. After
installing or setting overrides, run `ravage tools check` again before starting
the attack.

## Local Lab Boxes

For more realistic local targets, use the lab boxes under `examples/labs/`. They are
deliberately vulnerable applications with working websites, real services,
seeded flags, and intended attack chains.

Do not deploy them outside a local authorized lab. They are research targets,
not production services.

Available boxes:

- `ravage-acme-box`: Python support portal with login, invoice IDOR, catalog
  SQL injection, weak JWT admin escalation, SSRF, and four seeded flags.
- `ravage-forgeops-box`: harder Go release-operations portal with project BOLA,
  audit query injection, weak JWT admin escalation, artifact traversal,
  diagnostics command injection, SSRF, mass assignment, reflected input, and six
  seeded flags.
- `ravage-node-market-box`: Node/Express market operations portal with order
  BOLA, catalog SQL injection, JWT admin confusion, prototype-pollution-style
  beta config abuse, internal admin pivot, and five seeded flags.

```bash
ravage lab up ravage-acme-box
```

Then run the agent:

```bash
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --memory off \
  --allow-paid-models
```

The intended assisted chain is initial access with the seed account in
`OPERATOR_NOTES.md`, invoice IDOR, catalog SQL injection, weak JWT admin
escalation, and SSRF to the internal metadata service. The live website does not
display credentials. The agent must still capture flags from live observations;
the manifest and notes are operator context, not proof.

Stop the box when finished:

```bash
ravage lab down ravage-acme-box
```

For the harder Go box, substitute `ravage-forgeops-box`:

```bash
ravage lab up ravage-forgeops-box
ravage attack examples/labs/ravage-forgeops-box/brief.yaml \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --memory off \
  --allow-paid-models
ravage lab down ravage-forgeops-box
```

For the Node market box, substitute `ravage-node-market-box`:

```bash
ravage lab up ravage-node-market-box
ravage attack examples/labs/ravage-node-market-box/brief.yaml \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --memory off \
  --allow-paid-models
ravage lab down ravage-node-market-box
```

## Coverage Strategy

`ai-web` uses retrieved memory and heuristic recommendations as hints, but
coverage is still driven by tool evidence. A failed probe is classified by
outcome: normal negative evidence closes that candidate for the current run,
while authentication or privilege denial is tracked as blocked. When access
state changes through a managed cookie or header identity, accepted default
credential, or accepted JWT tamper, blocked candidates are released and can be
retried under the new context.

Bounded multi-path probes, such as JWT tampering against several admin-like
routes, mark every attempted path in the coverage ledger. This avoids spending
later turns on the same failed variant family. JSON account, profile,
preferences, and config routes are also eligible for a bounded business-logic
probe that checks for mass-assignment or merge-style privilege changes, then
verifies impact through separate routes before accepting evidence.

Local capture-flag labs also get bounded proof follow-ups after confirmed
command injection or local file inclusion. Those follow-ups are read-only, run
only against localhost targets, and use generic flag file names such as
`flag.txt` rather than lab-specific paths. A flag is still accepted only when it
appears in tool evidence.

## Live Dashboard

For a local run, start the dashboard before or during the agent execution:

```bash
ravage dashboard \
  --workspace-dir runs/test-repo-ai-web.workspace \
  --db-path runs/test-repo-ai-web.db \
  --stdout-path runs/test-repo-ai-web.stdout \
  --lab-manifest examples/labs/ravage-acme-box/ravage-lab.yaml \
  --port 8787
```

Open `http://127.0.0.1:8787`. The page polls the local workspace and audit DB
for the stage graph, active agents, run timeline, work charts,
findings, masked flags, transcript, audit rows, optional process-session records,
and stdout.
It does not call the model or target by itself.

To attach to a conventional run directory:

```bash
ravage observe runs/brief-YYYYMMDDHHMMSS \
  --lab-manifest examples/labs/ravage-acme-box/ravage-lab.yaml
```

## Artifacts

Conventional `ravage attack` artifacts under `RUN_DIR`:

- audit DB: `audit.db`;
- canonical machine-readable report: `report.json` for every attack, including
  incomplete and failed runs;
- redacted human report: `report.md` when `--report` is used;
- plain progress log: `stdout.log`;
- base workspace state: `workspace/working_state.json`;
- events and model transcript: `workspace/events.jsonl` and
  `workspace/transcript.jsonl`;
- optional process-session records: `workspace/terminal/<session>.jsonl`;
- larger output artifacts: `workspace/artifacts/`;
- durable physical-request ledger: `workspace/traffic-policy.json`.

Canonical JSON finalization is local and does not make model or target requests.
It atomically replaces an owner-private file. Use `--report` for the additional
Markdown rendering, or a supported `--report-path` for optional Ravage Pro PDF
or DOCX output.

The final `traffic` line and report's `traffic_accounting` object read this
ledger. `exact` means every target dispatch was metered, `lower bound` means an
opaque action may have emitted additional traffic, and `unavailable` means the
ledger is missing or unreadable. If the agent graph starts, its current state
and events live under `workspace/autonomous-route/agent-graph/`; the root state
remains the base snapshot.

Benchmark-run artifacts:

- summary report: `<output-dir>/report.json`
- per-case DB: `<output-dir>/<case-id>.db`
- per-case workspace: `<output-dir>/<case-id>.workspace/`

## Resume A Run

Use `--run-dir` with `--resume` to continue an existing attack workspace.
Without `--resume`, Ravage refuses to reuse an existing attack state:

```bash
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --run-dir runs/acme-attack \
  --resume \
  --model-profile hosted-openai \
  --model-tier low \
  --memory off \
  --allow-paid-models
```

Resume requires the saved traffic-policy ledger and matching configuration. A
genuinely pre-ledger local/observe workspace with neither a ledger nor its lock
is migrated once to an observe ledger marked `lower_bound` before target
traffic; a legacy low-noise workspace without its ledger is rejected.

Inspect `report.json`, `stdout.log`, `workspace/events.jsonl`, and
`transcript.jsonl` before resuming so the resumed run has a clear operator
reason.

## Inspect The Audit DB

List audit actions:

```bash
sqlite3 runs/test-repo-ai-web.db \
  'select id, actor, action from audit_log order by id;'
```

List findings:

```bash
sqlite3 runs/test-repo-ai-web.db \
  'select finding_id, vuln_class, status, validator_vote from findings;'
```

Pretty-print the latest finding payload:

```bash
sqlite3 -json runs/test-repo-ai-web.db \
  'select payload_json from findings limit 1;' | jq .
```

## Inspect The Workspace

Show event kinds:

```bash
jq -r '.kind' .ravage/workspaces/<engagement_id>/events.jsonl
```

Show model actions:

```bash
jq 'select(.kind == "agent_action")' \
  RUN_DIR/workspace/events.jsonl
```

Show kill-chain progress:

```bash
jq 'select(.kind == "kill_chain_stage")' \
  RUN_DIR/workspace/events.jsonl
```

Show loaded skill metadata:

```bash
jq 'select(.kind == "agent_skill_loaded")' \
  RUN_DIR/workspace/events.jsonl
```

Show model replies:

```bash
jq 'select(.kind == "model_reply")' \
  RUN_DIR/workspace/events.jsonl
```

Show transcript roles:

```bash
jq -r '.role' RUN_DIR/workspace/transcript.jsonl
```

If an optional process runtime produced session records, list them with:

```bash
ls RUN_DIR/workspace/terminal
```

Inspect one such transcript:

```bash
jq . RUN_DIR/workspace/terminal/<session>.jsonl
```

## Common Failures

`connection refused`

: The model endpoint is not running or `*_BASE_URL` points to the wrong port.

`invalid_model_action`

: The model returned prose or invalid JSON. The agent sends a correction
  observation and continues.

`tool target escaped target origin`

: The model tried to call a URL outside the configured target origin. The tool
  is blocked and the model receives an error observation.

`remote targets require --authorized-remote-target`

: The CLI received a public/DNS target without the explicit authorization
  acknowledgement. Confirm that the target is in `scope.in_scope`, then rerun
  with `--authorized-remote-target`.

`authorized remote targets do not support host tool runtime`

: Host process execution was explicitly selected for an unauthenticated remote
  target. For the default native low-noise run, remove `--tool-runtime host`.
  For process-capable testing, use
  `--traffic-policy observe --tool-runtime docker`.

`finding_rejected_no_evidence`

: The model tried to report a vulnerability without confirmed proof. This is
  expected behavior and should not be relaxed.

## Safety Boundaries

Do not remove these without an explicit design change and tests:

- localhost-by-default target gate,
- explicit remote scope gate,
- same-origin and in-scope tool gate,
- proof gate before findings,
- audit/workspace trace recording.
