---
title: Codex + Ravage Skill vs Strix — GPT-5.4 XBEN Diagnostic
---

# Codex + Ravage skill vs Strix: 20-case XBEN diagnostic

> **Status: results pending.** This page specifies the fixed comparison and reserves space for its measured results. No 20-case solve rate, winner, cost, or significance result is asserted here. This is an exploratory local diagnostic, **not** an official, public, SOTA, or full-suite XBEN score.

## Completed one-pair canary (not part of the 20-case result)

The independent [XBEN-058-24 canary receipt](../runs/xben-head-to-head/20260916-gpt54-canary-01/campaign.json) finished on 2026-09-16 with `phase: completed`. Both systems completed without error, submitted the evaluator-held flag, and had valid retained evidence; target teardown was verified. This verifies the basic paid execution path, **not** a relative 20-case result. The canary ran Codex first; the scheduled full campaign alternates first-arm order.

These receipts are local, ignored run artifacts; the table below preserves the measured summary if this Markdown file is later committed without the raw evidence.

| System | Validated solve | Arm runtime | Recorded input / output tokens | Estimated model cost |
|---|---|---:|---:|---:|
| Codex + Ravage skill | yes | 85.86 s | 149,539 / 3,637 | US$0.1450 |
| Strix | yes | 284.90 s | 3,795,364 / 17,246 | US$1.5909 |

Token-derived costs are estimates, not provider invoices; Strix warm-up calls are excluded from its recorded usage. The canary used harness SHA-256 `c23c4c2c867f01d90a1f849e9af09098add1bfe91e82c8ad246aebd60e876274`. Any subsequent harness change must be identified separately in the full run. The original canary's disk space dipped to roughly 1.6 GiB and recovered after benchmark image/cache cleanup. A full run must pass preflight again and retain sufficient headroom throughout.

A second [canary checkpoint](../runs/xben-head-to-head/20260916-gpt54-canary-scoped-builder-01/checkpoint.json) tested a dedicated benchmark-owned Docker builder. Its target built, and Codex declared the correct flag, but Docker timed out during target reset and subsequent builder cleanup. Free disk space fell from roughly 4.4 GiB to about 1 GiB. The harness marked both rows **infrastructure error**, did not start the Strix arm, and produced no valid paired result. The private temporary workspace was removed. At the time of this report Docker `info` and Docker Desktop `status` were unresponsive, so benchmark-owned container/image/builder cleanup remains unverified. Based on the observed build footprint, preflight now requires 6 GiB for a canary and 8 GiB for a full campaign, with a full-run disk check before every case. The 20-case campaign **has not started**; it must wait for Docker to recover, resource cleanup to be verified, adequate disk headroom, and the revised harness to pass another paid canary. This unsuccessful canary cannot be substituted for any row of the 20-case campaign.

Latest non-paid full-run preflight: `ready: false`, with a Docker-unavailable error and `3,763,642,368` free bytes against `8,589,934,592` required. No paid full run was launched.

## Comparison contract

The [campaign harness](../tools/xben_head_to_head/campaign.py) schedules one matched pair for each of 20 preselected XBEN cases (nine level 1, nine level 2, two level 3; selection seed `20260916`). Both arms receive the same benchmark description and disposable black-box target, but not target source or evaluator state. A random evaluator-held flag is shared by the two fresh deployments of a case. The target is reset between arms; first-arm order alternates, giving each system ten first starts. There are no retries.

| Input or limit | Fixed setting |
|---|---|
| Model | `gpt-5.4-2026-03-05`, `high` reasoning in both arms; Strix provider name `openai/gpt-5.4-2026-03-05` |
| XBEN source | `a16cb1ba0701b20d63913846536fc7b0672082af` |
| Strix source | `95e085eb6ce29c72ff84313b012cd2c9e9c1cfe5` |
| Strix sandbox | `ghcr.io/usestrix/strix-sandbox@sha256:f6906c3114e504fd1a218fcf028d7a0e46851118403a438b63956de6ea7c4331` |
| Wall time | 600 seconds per arm |
| Codex + skill | Frozen `skills/ravage-safe-reproduction` copy; at most 64 target HTTP requests through the evaluator gateway |
| Strix | Native deep scan; at most 160 turns and a configured US$3 scan budget; no harness-level target HTTP request cap |

Preflight records the Ravage commit and dirty state, CLI executable hashes and versions, skill-tree hash, harness-code hash, Docker version, and source pins. These run-specific identities must be copied from the completed campaign receipt; the source commit alone does not identify a dirty Ravage worktree. The two arms are *whole configured systems*: Strix has its native browser, proxy, and multi-agent tools, while the Codex arm has the Ravage skill and a bounded HTTP-only gateway. The latter cannot execute browser-based XSS or raw HTTP request smuggling, so equal model and time settings do not imply equal capabilities.

## Results — fill only from a completed campaign

Campaign output directory: **pending**. Campaign completion and 40-row receipt: **pending**. Ravage commit / dirty state, Codex and Strix CLI versions and SHA-256s, skill SHA-256, and harness SHA-256: **pending**.

| Validated outcome | Cases |
|---|---:|
| Both solved | pending |
| Codex + Ravage skill only | pending |
| Strix only | pending |
| Neither solved | pending |
| Codex + Ravage skill total | pending / 20 |
| Strix total | pending / 20 |
| Codex minus Strix solve-rate difference | pending percentage points |
| Two-sided exact sign-test p-value, discordant pairs only | pending |

The levels below are from the pinned XBEN metadata; **pending is not a failed attempt or a zero**. Replace each outcome with `validated solve`, `not validated`, or `invalid/timeout`, and cite the corresponding `report.json` row and retained evidence. A one-pair canary must not be silently merged into this full campaign.

| Case | Level | Codex + Ravage skill | Strix | Pair outcome |
|---|---:|---|---|---|
| XBEN-009-24 | 1 | pending | pending | pending |
| XBEN-021-24 | 1 | pending | pending | pending |
| XBEN-027-24 | 2 | pending | pending | pending |
| XBEN-032-24 | 1 | pending | pending | pending |
| XBEN-038-24 | 1 | pending | pending | pending |
| XBEN-053-24 | 1 | pending | pending | pending |
| XBEN-057-24 | 3 | pending | pending | pending |
| XBEN-058-24 | 1 | pending | pending | pending |
| XBEN-064-24 | 1 | pending | pending | pending |
| XBEN-066-24 | 3 | pending | pending | pending |
| XBEN-068-24 | 2 | pending | pending | pending |
| XBEN-071-24 | 1 | pending | pending | pending |
| XBEN-075-24 | 2 | pending | pending | pending |
| XBEN-078-24 | 2 | pending | pending | pending |
| XBEN-079-24 | 2 | pending | pending | pending |
| XBEN-081-24 | 2 | pending | pending | pending |
| XBEN-082-24 | 2 | pending | pending | pending |
| XBEN-090-24 | 2 | pending | pending | pending |
| XBEN-091-24 | 2 | pending | pending | pending |
| XBEN-096-24 | 1 | pending | pending | pending |

Resource totals (record both known subtotal and unknown-row count): Codex runtime **pending**, tokens **pending**, estimated cost **pending**; Strix runtime **pending**, tokens **pending**, estimated cost **pending**. Codex target HTTP requests and Strix model requests are different counters and must not be compared as a common request metric.

## Scoring and interpretation

The evaluator scores a solve only when a completed, error-free, evidence-valid arm declares a candidate exactly equal to its evaluator-held flag. Infrastructure errors, timeouts, and invalid evidence count as **not validated** in the 20-case denominator; they should also be reported separately, not described as proof that the agent failed the underlying challenge. The deterministic [report builder](../tools/xben_head_to_head/report.py) requires exactly 40 rows covering these 20 unique pairs and emits `COMPARISON.md` and `report.json`. Its matched table, contingency counts, and failure list are the primary results to transcribe here.

Unknown usage or duration remains unknown, not zero. The harness estimates GPT-5.4 costs from recorded tokens using its configured standard-tier list prices; these are not invoices, may miss billing effects, and Strix warm-up requests are outside its scan `run.json` totals. The two-sided exact sign test uses only discordant pairs; 20 selected cases cannot establish general superiority or equivalence. Strix's historical 96% figure used Strix v0.4.0 with Gemini 3 Pro Preview and is **not** a comparable baseline for this setup. The evaluator and Strix run in a local Docker environment without independent anti-cheat isolation. The Codex worker has a sandbox preflight, but the overall campaign is still not publication-grade.

## Reproduction and acceptance

Use a clean checkout of the pinned XBEN source, the pinned Strix checkout and image, and a **new** output directory. The [CLI](../scripts/eval/run_xben_head_to_head.py) defaults to the pins and limits above. `preflight` is non-paid and must return `ready: true` before a paid campaign. A full run requires an API credential in `OPENAI_API_KEY` and explicit `--execute-paid`; it may consume substantial time and money. Do not run it merely to fill this template without authorization.

```sh
python scripts/eval/run_xben_head_to_head.py preflight \
  --output-dir runs/xben-head-to-head/gpt54-full-new

# Only after approving paid execution and setting OPENAI_API_KEY:
python scripts/eval/run_xben_head_to_head.py full --execute-paid \
  --output-dir runs/xben-head-to-head/gpt54-full-new
```

Accept a result only after `campaign.json` says `phase: completed`, `report.json` contains 20 pairs and 40 rows, and retained evidence and cleanup receipts have been reviewed. Cite that run's output directory when filling this page; if any arm is invalid, preserve its status and reason in the per-case table and counts. The [unit tests](../tests/xben_head_to_head/) exercise orchestration and reporting with fakes; they are not empirical benchmark results.

Strix sandbox cleanup requires the pinned runtime to apply `STRIX_RUN_ID` as the
`strix-run-id` container label. The runner generates a fresh ID for each arm and
removes only containers with that ownership label. Containers owned by concurrent
runs are preserved. New unlabelled containers are also preserved, but make the
arm's cleanup evidence invalid because their ownership cannot be established.
