---
title: XBEN Description-Only Comparison Runbook
---

# XBEN Description-Only Comparison Runbook

Use this whenever running Ravage against XBOW/XBEN for MAPTA/AWE-comparable
claims.

## Correct Comparison Mode

Run XBEN as description-only black box:

- Use `--mode black-box`.
- Use `--comparison-profile none` for selected diagnostic canaries.
- Use `--comparison-profile mapta-awe-xben` only for the enforced full suite.
- Use `--agent-mode ctf-free-roam`.
- Give the agent the target URL and benchmark challenge description.
- Do not give benchmark tags, vulnerability categories, case name/id, level,
  source, database schema, logs, or internal config.
- Use only `capture_flag` as the benchmark objective.
- Use a 10-minute case timeout for MAPTA/AWE-style comparison:
  `--case-timeout-seconds 600`.

Why: MAPTA's CTF/XBOW evaluation received only local target URLs and challenge
descriptions, while withholding source, schemas, internal config, and vulnerability
classifications. AWE describes a black-box HTTP attacker and says each XBOW
challenge used a ten-minute budget matching MAPTA.

Primary sources:

- MAPTA: https://arxiv.org/html/2508.20816
- AWE: https://arxiv.org/html/2603.00960

## Never Use For Clean Comparisons

Do not use these modes or artifacts for MAPTA/AWE-comparable claims:

- `black-box-with-tags`
- `pure-black-box`
- `source-aware`
- `white-box`
- old reports whose `hint_policy.metadata_assisted` is `true`
- old reports whose `hint_policy.source_available` is `true`
- old reports whose `hint_policy.description_visible` is `false`

Historical runs in this workspace include tag-assisted, source-aware, and
no-description pure-black-box artifacts. Treat them as engineering diagnostics,
not clean benchmark scores.

## Required Preflight

Run preflight before spending model calls. The example below uses a two-case
canary. Set `XBEN_ROOT` to a clean checkout of the benchmark repository:

```bash
export XBEN_ROOT=/path/to/validation-benchmarks/benchmarks
read -rsp "OpenAI API key: " OPENAI_API_KEY && printf '\n'
export OPENAI_API_KEY
ravage xben \
  --benchmarks-root "$XBEN_ROOT" \
  --output-dir runs/xben/description-only-canary \
  --ids XBEN-005-24 XBEN-030-24 \
  --mode black-box \
  --comparison-profile none \
  --agent-mode ctf-free-roam \
  --model-profile hosted-openai \
  --model-tier high \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --max-turns 40 \
  --case-timeout-seconds 600 \
  --max-model-requests-per-case 40 \
  --max-cost-usd 20 \
  --allow-paid-models \
  --concurrency 1 \
  --preflight
```

Stop if preflight reports `blocked=true`. Fix the block before running.

## Actual Run

After preflight passes, rerun the same command without `--preflight`:

```bash
ravage xben \
  --benchmarks-root "$XBEN_ROOT" \
  --output-dir runs/xben/description-only-canary-run \
  --ids XBEN-005-24 XBEN-030-24 \
  --mode black-box \
  --comparison-profile none \
  --agent-mode ctf-free-roam \
  --model-profile hosted-openai \
  --model-tier high \
  --tool-runtime auto \
  --tool-image ravage-kali:latest \
  --max-turns 40 \
  --case-timeout-seconds 600 \
  --max-model-requests-per-case 40 \
  --max-cost-usd 20 \
  --allow-paid-models \
  --concurrency 1
```

```bash
unset OPENAI_API_KEY
```

For a full clean score, follow the
[strict MAPTA/AWE profile](benchmarking.md#strict-maptaawe-comparison-profile).
It requires all 104 cases, Docker, an immutable tool-image digest, a clean
source tree, exact scoring, image pruning, and distinct fresh preflight and run
directories.

## Report Acceptance Check

Only accept a report as clean-comparable if `report.json` has:

```json
{
  "mode": "black-box",
  "comparison_profile": {
    "name": "mapta-awe-xben",
    "comparable": true,
    "enforced": true,
    "issues": []
  },
  "hint_policy": {
    "source_available": false,
    "description_visible": true,
    "metadata_assisted": false,
    "source_aware": false
  }
}
```

Also inspect at least one generated `brief.yaml` before running a new campaign.
The brief context must not contain `tags`, `benchmark_hints`, `benchmark_id`,
`name`, `level`, `source_root`, or `allowed_source_roots`.
