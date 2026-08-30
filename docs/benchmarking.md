---
title: Benchmarking
---

# Benchmarking

Ravage has two current benchmark surfaces:

- `ravage xben`: run Ravage against XBEN-style benchmark cases with exact flag
  scoring, per-case logs, preflight, paid-model controls, and audit artifacts.
- `ravage competitors`: run Ravage or external agents through the isolated
  head-to-head harness and generate comparison artifacts from configured
  adapters.

The repository does not currently publish a reproducible full-suite baseline,
an external-agent matrix, or a leaderboard. The checked-in competitor
configuration contains smoke adapters and is not a head-to-head result.

The old top-level `ravage --benchmark ...` examples were from an earlier local
manifest path. Do not use them for public results. Use `ravage xben` for XBEN
validation and `ravage competitors` for referee-style comparisons.

For the local lab matrix, flag counts, and scoring policy, see [Benchmarks And
Local Test
Boxes](https://github.com/duriantaco/ravage/blob/main/BENCHMARKS.md).

## Historical Pre-Relaunch Result

Private records from a pre-relaunch 2026-07-12 checkout report 85 / 104 public
XBEN cases (81.73%) solved in description-only black-box mode, with 16
failures, 1 error, 2 timeouts, and $55.758722 in provider-usage list-price
model cost. The raw bundle is retained privately because it contains sensitive
security-test material and is not part of this repository.

That result belongs to an earlier source snapshot and is historical context
only. It is not a current, reproducible, or public baseline for this checkout.
Create and retain a fresh run from a named relaunch commit before making a
current performance claim.

[XBOW now describes this public suite as outdated and saturated](https://github.com/xbow-engineering/validation-benchmarks).
Use any new result as a public-benchmark regression and evidence-integrity
baseline, not as proof of frontier performance, unseen-task generalization, or
expected production pentest efficacy. The top-level
[Honest Limitations](https://github.com/duriantaco/ravage#honest-limitations)
also covers repeatability, model dependence, cost scope, weaker coverage areas,
runtime portability, and raw-evidence risk.

## XBEN Flow

XBEN is an execution envelope around the public attack command. It provisions
the case, writes a normal brief, runs `ravage attack`, exact-matches the hidden
random proof, and tears the case down. The attacker used here is therefore the
same attacker users run against local labs and their own authorized boxes.

List available cases before spending model calls:

```bash
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --levels 1 2 \
  --list
```

Run a no-spend preflight for a small selection:

Enter the key without putting its value in shell history. Keep it exported only
for the bounded preflight and run, then unset it:

```bash
read -rsp "OpenAI API key: " OPENAI_API_KEY && printf '\n'
export OPENAI_API_KEY
```

```bash
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/preflight \
  --ids XBEN-001-24 XBEN-002-24 \
  --mode black-box \
  --comparison-profile none \
  --agent-mode ctf-free-roam \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime host \
  --max-turns 8 \
  --max-model-requests-per-case 8 \
  --max-cost-usd 5 \
  --preflight
```

Inspect `runs/xben/preflight/preflight.json` before running paid
models. Hosted or paid-risk routes are blocked unless `--allow-paid-models` is
present. A selected-case run is a diagnostic and cannot satisfy the strict
MAPTA/AWE comparison profile.

Run the same selected cases:

```bash
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/selected \
  --ids XBEN-001-24 XBEN-002-24 \
  --mode black-box \
  --comparison-profile none \
  --agent-mode ctf-free-roam \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime host \
  --max-turns 8 \
  --max-model-requests-per-case 8 \
  --max-cost-usd 5 \
  --allow-paid-models
```

```bash
unset OPENAI_API_KEY
```

Useful selection flags:

- `--ids XBEN-001-24 XBEN-002-24`: run explicit IDs.
- `--range 1-10`: run a numeric range.
- `--levels 1 2`: filter by benchmark level.
- `--sample 10 --sample-seed 1234`: run a reproducible random sample.
- `--exclude-ids ...`: remove known-bad or out-of-scope cases from a selection.
- `--resume`: continue an interrupted run.
- `--retry-failed`: rerun only failed cases from an existing output directory.

Useful execution and scoring flags:

- `--mode black-box|white-box|source-aware`: select benchmark context.
- `--comparison-profile none`: run a selected, sampled, resumed, or otherwise
  diagnostic campaign without claiming strict comparability.
- `--comparison-profile mapta-awe-xben`: enforce the full-suite comparison
  contract described below.
- `--flag-mode exact|pattern`: choose exact flag matching or pattern matching.
- `--case-timeout-seconds N`: cap one case wall-clock runtime.
- `--max-model-requests-per-case N`: cap model calls per case.
- `--max-cost-usd N`: block runs when pricing metadata estimates exceed the
  cap.
- `--operator-log-root PATH`: store operator logs outside the run directory
  when needed.
- `--tool-runtime host|docker|auto`: choose host tools, Docker-backed tools, or
  auto mode.

## Strict MAPTA/AWE Comparison Profile

`--comparison-profile mapta-awe-xben` is deliberately stricter than an ordinary
XBEN run. It requires all 104 canonical cases in order and rejects filters,
sampling, resume, retry, knowledge packs, degraded mode, cockpit mode, and
retained targets. It also requires a clean source tree, exact scoring, one-case
concurrency, Docker tools, a tool image pinned by digest, 40 turns and model
requests per case, a 600-second case timeout, case-image pruning, and a fresh
output directory.

Set an immutable image reference first:

```bash
export RAVAGE_TOOL_IMAGE='registry.example/ravage-kali@sha256:<64-hex-digest>'
```

Run strict preflight into an output directory that does not exist:

```bash
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/full-preflight-YYYYMMDD \
  --all \
  --mode black-box \
  --comparison-profile mapta-awe-xben \
  --agent-mode ctf-free-roam \
  --model-profile hosted-openai \
  --model-tier high \
  --tool-runtime docker \
  --tool-image "$RAVAGE_TOOL_IMAGE" \
  --max-turns 40 \
  --case-timeout-seconds 600 \
  --max-model-requests-per-case 40 \
  --max-cost-usd 100 \
  --allow-paid-models \
  --require-clean-source \
  --flag-mode exact \
  --concurrency 1 \
  --prune-case-images \
  --preflight
```

After preflight passes, run the same frozen contract without `--preflight` and
with a second, still-nonexistent output directory such as
`runs/xben/full-run-YYYYMMDD`. Reusing the preflight directory is invalid: the
strict profile requires the actual run directory not to exist before it starts.
Do not add case filters or any omitted opt-in feature.

## Output Shape

An XBEN run writes one directory per run:

```text
runs/xben/selected/
  preflight.json
  report.json
  artifacts.sha256
  operator-logs/
  XBEN-001-24/
    audit.db
    agent.stdout
    docker.log
    workspace/
```

Important report fields:

- `summary.total`, `summary.solved`, `summary.failed`, `summary.errored`, and
  timeout counts.
- per-case `status`, `found_flag`, `elapsed_seconds`, `model_request_count`,
  token usage, and `cost_usd`.
- paths to stdout, workspace events, audit DB, transcripts, artifacts, and
  target evidence.
- failure text for cases that did not produce a valid benchmark flag.

For public claims, keep the raw run directory, the report, and hash manifests.
Do not edit logs after the run. If you need to rerun, write to a new directory
and document the commit SHA used for that run.

## Competitor Harness

Use the competitor harness when the claim is a head-to-head comparison rather
than a single Ravage score:

The checked-in `eval/competitor_harness.example.yaml` is a harness smoke test.
Replace its agents, expected flags, commits, models, and commands before
treating any output as benchmark evidence.

```bash
ravage competitors preflight \
  --config eval/competitor_harness.example.yaml \
  --output-dir runs/competitors/preflight
```

Then run:

```bash
ravage competitors run \
  --config eval/competitor_harness.example.yaml \
  --output-dir runs/competitors/head-to-head
```

The harness creates an isolated Docker network per target box and scores each
agent artifact using the same fields. A valid public leaderboard should include:

- agent name, adapter version, target box, and model route;
- valid flags, invalid/self-reported flags, false positives, and out-of-scope
  findings;
- cost or `cost_status: unknown`;
- artifact links for the adapter JSON, stdout, stderr, report, and hash file.

See [Competitor Harness](competitor-harness.md) for the adapter contract.

## Evidence Standard

Benchmark claims should be evidence-first:

- A flag counts only when it is observed from the target and matches the
  expected flag policy.
- A vulnerability finding needs replayable request/response proof or another
  target-origin evidence artifact.
- Model text is never proof by itself.
- Source-aware hints can guide attempts, but reported findings still need live
  confirmation.
- Cost must be reported as measured, computed from token/pricing metadata, or
  explicitly marked unknown.

## Public Artifact Handling

Publish only reviewed, redacted evidence artifacts. Keep raw transcripts,
authentication material, model completion identifiers, machine-local paths,
complete exploit traces, ephemeral session values, and customer data in
access-controlled storage. A narrow provider-key scan is not a general safety
guarantee.

For a public evidence release, generate a complete inventory, check for extra
files, suppress operating-system metadata during packaging, and publish
checksums for the exact reviewed bundle. Never include real customer or
production credentials.

Publishing randomized flags does not reveal the value used by a later run, but
publishing complete solution traces can contaminate future evaluation on the
same public cases through browsing or training exposure. Label later XBEN runs
as public-regression results, keep agent tool networks isolated from the public
internet, and use fresh or private variants for unseen-task claims.

## Repeatability

For a release-quality run:

1. Record the git commit SHA before running.
2. Run preflight and keep the preflight output.
3. Run the benchmark into a fresh output directory.
4. Generate hash manifests for reports, logs, artifacts, and archives.
5. Commit only the evidence artifacts after the code commit if the goal is to
   prove no code changed between runs.

This is the proof story Ravage should lead with: same harness, same commit,
exact-flag scoring, retained logs, and auditable cost fields.
