---
title: Referee Launch Plan
---

# Referee Launch Plan

Ravage has a historical pre-relaunch result and a future referee-launch gate.
They must not be collapsed into one claim: the historical result is not a
current public baseline, while a referee launch requires fresh external-agent
rows and repeated runs from a named relaunch commit.

## Historical Note: Pre-Relaunch Ravage Run

Private records from a 2026-07-12 checkout describe one uninterrupted Ravage
run across all 104 public XBEN cases under a frozen description-only black-box
contract:

- 85 / 104 exact randomized flags
- 81.73% solve rate
- $55.758722 in provider-usage list-price model cost
- $0.655985 per valid flag
- 1,151 model replies accounted for, with zero unmatched attempts
- 16 failures, 1 error, and 2 timeouts retained
- no retries, row replacement, or code changes recorded during execution

The raw evidence bundle is retained privately because it contains sensitive
security-test material and is not part of this repository. The result belongs
to an earlier source snapshot and cannot serve as a current, reproducible, or
public baseline for the relaunched checkout.

[XBOW now labels the public suite outdated and saturated](https://github.com/xbow-engineering/validation-benchmarks)
and says its vulnerabilities are present in model training. Randomized flags
protect exact-output scoring, but they do not make the vulnerability patterns
novel again. The historical result is context for future regression work, not
a frontier-capability, production-efficacy, or head-to-head claim.

### What Stage 1 Does Not Establish

- Current-checkout performance: the run predates the clean-history relaunch.
- Repeatability: there is one historical full run, not a repeated sample with
  variance or confidence intervals.
- Competitive rank: no external agent has a published row from Ravage's
  harness.
- Unseen-task performance: XBEN and many solution traces are public.
- Production pentest quality: flag capture does not measure normal-application
  false positives, business impact, remediation, reporting, or organizational
  safety.
- Model independence: the result belongs to the complete Ravage plus
  `gpt-5.4-2026-03-05` configuration.
- Total operating cost: the reported dollars cover provider-usage list-price
  model text tokens, not compute, storage, engineering, or review labor.
- Portable speed: the recorded runtime used amd64 containers on an ARM host.

The broader product and evidence caveats are listed under
[Honest Limitations](https://github.com/duriantaco/ravage#honest-limitations).

### Do Not Use As Relaunch Copy

```text
A pre-relaunch 2026-07-12 run recorded 85 of 104 exact randomized XBEN flags.
Its raw evidence is retained privately, and the result has not been reproduced
from the current checkout. Treat it as historical context, not a current
baseline or claim of unseen-task superiority.
```

Do not headline the relaunch with this number, call it a leaderboard, or say
that Ravage benchmarked other agents. Publish a current score only after a new
run from a named relaunch commit passes the evidence and repeatability gates.

## Stage 2: Cross-Agent Referee

The referee launch starts only after Ravage and at least two real external
agents have complete results under one declared protocol. The repository
currently contains the harness and smoke examples, but no public
external-agent matrix.

Before any result is known, freeze and publish:

- benchmark and harness commit SHAs;
- complete target set and input-visibility contract;
- agent names, versions, adapters, models, and reasoning settings;
- time, turn, request, retry, isolation, and cost policies;
- evaluator-owned exact-flag and false-positive rules;
- infrastructure-failure and exclusion policy;
- cost source, including whether it is measured, list-price computed, or
  unknown;
- whether each row was maintainer-run or operator-run.

If systems cannot use meaningfully comparable models, budgets, or tool access,
report them in separate cohorts rather than presenting a controlled ranking.
The table compares complete system configurations, not the underlying models
in isolation.

### Minimum Public Artifact

A public head-to-head claim needs all of these:

- `report.json`, `leaderboard.tsv`, and `leaderboard.md`;
- `artifacts.sha256` plus immutable code and target provenance;
- per-agent `stdout.log`, `stderr.log`, and `agent-result.json`;
- complete rows for every selected target, including errors and timeouts;
- valid, invalid, self-reported, false-positive, and out-of-scope counts;
- cost source or an explicit `cost_status: unknown`;
- an explanation of every failed, errored, or excluded row;
- repeat runs reported separately rather than merged into a best-of score.

Do not publish a headline score from a local note, screenshot, or
self-reported finding count. Scores come from evaluator-scored artifacts.

### Execution Order

1. Tag a stable harness version and select comparable external adapters.
2. Publish and freeze the protocol before seeing full-matrix results.
3. Run a small non-reportable adapter smoke test.
4. Freeze the source and execute the complete matrix without source changes.
5. Repeat the same complete matrix from the same frozen source.
6. Audit all errors and false positives plus a sample of passes.
7. Give named maintainers a factual-review window and publish any errata.
8. Publish the table only after both runs and every terminal row are explained.

### Scoreboard Rules

- Exact evaluator-owned flags count as valid.
- Unknown flags count as invalid.
- Findings without replayable proof count as false positives.
- Out-of-scope findings are reported separately and count against false
  positives.
- Unknown cost is not zero cost.
- Cost per valid flag is reported only when cost is known or computable.
- Errored and timed-out rows remain visible.
- A repeat run is a separate observation, not a replacement result.

### Stage 2 Launch Copy

Use this only after the required multi-agent artifacts exist:

```text
We ran Ravage, X, and Y under one declared benchmark protocol with
evaluator-scored exact flags, replayable proof requirements, false-positive
accounting, and cost per valid flag. This compares the complete system
configurations—not their underlying models in isolation. Every row links to
its provenance, terminal status, cost accounting, and artifact bundle.
```

## Claim Language

Use precise descriptions:

- evaluator-scored exact randomized flags;
- frozen public-benchmark regression;
- complete artifact bundle;
- declared model, limits, and cost accounting;
- historical Ravage-only result until fresh external rows exist.

Avoid claims that the evidence does not support:

- cheat-proof;
- the only benchmark or the only cost-aware benchmark;
- nobody else reports cost;
- state of the art;
- better than Strix, MAPTA, or another system without a controlled comparison;
- plural "agents" before stage two exists.

XBEN, MAPTA, Strix, BountyBench, HAL, and other evaluation projects already
publish benchmark, evidence, or cost artifacts. Ravage's prospective
differentiator is the declared web-agent execution contract and interoperable
row-level evidence—not the invention of benchmarks, scoreboards, or cost
tracking.
