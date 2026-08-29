---
title: Ravage Docs
---

# Ravage Docs

This directory backs the GitHub Pages documentation. The linked docs below are
the current operator and technical references for the source-checkout
workspace.

New readers should start with [How To Use](how-to-use.md) and choose one of two
paths: test a localhost development app, or test an explicitly authorized URL
through the native low-noise HTTP lane. [Setup](setup.md) is the supporting reference for
installation, model providers, briefs, and tool troubleshooting. Included labs,
observers, autonomous routing, full probe sets, and benchmarks are optional;
the no-model `surface_map` scan is the recommended first target check.

Private records from a pre-relaunch 2026-07-12 checkout report 85 / 104 XBEN
flags. The raw bundle is access-controlled, is not shipped here, and has not
been reproduced from the current checkout. It is historical context, not a
current public baseline. A cross-agent referee table has not been published.

The operational source of truth is:

- [README](https://github.com/duriantaco/ravage#readme): current project summary
  and copy-paste localhost and authorized-URL starts.
- [How To Use](how-to-use.md): the two primary testing paths, result inspection,
  optional workflows, and troubleshooting.
- [Setup](setup.md): lean source install, `ravage doctor`, `ravage init`,
  workflow-specific optional dependencies, model routes, brief setup,
  remote-target flags, and troubleshooting.
- [AI Web Operator Guide](ai-web-operator-guide.md): running `ravage attack`,
  `ravage scan`, local tools, lab boxes, observation, and troubleshooting.
- [Model Providers](model-providers.md): Ollama, LM Studio, vLLM, LiteLLM,
  hosted OpenAI, native Anthropic Claude, and model route inspection.
- [Memory Design](memory.md): planned local SQLite memory model, redaction,
  review policy, retention, and evaluation standard.
- [Improvement Lab](improvement-lab.md): isolated prior-run projection,
  historical replay, immutable candidate archive, repeated no-regression gates,
  advisory tournaments, operator approval records, and normal reviewed patch
  promotion.
- [Knowledge Skills](skills.md): opt-in advisory cards, built-in pack usage,
  loader safeguards, and pack-off versus pack-on promotion rules.
- [Passive SATCOM Analysis](satcom.md): offline TLE and CCSDS Space Packet
  inventory, conservative signals, safety boundaries, and capability stages.
- [Benchmarking](benchmarking.md): XBEN validation, preflight, hosted-model
  canaries, scoring, evidence, and report interpretation.
- [XBEN Comparison Runbook](xben-comparison-runbook.md): description-only
  comparison contract, canary command, and report acceptance checks.
- [Competitor Harness](competitor-harness.md): isolated external-agent
  comparison, disk preflight, adapter shape, and false-positive scoring.
- [Referee Launch Plan](benchmark-referee-launch.md): historical-result
  boundaries and the proof requirements for a future cross-agent table.
- [Benchmarks And Local Test Boxes](https://github.com/duriantaco/ravage/blob/main/BENCHMARKS.md): lab matrix, flag counts,
  local scoring policy, and latest recorded local run notes.

The technical source of truth is:

- [Architecture](architecture.md): current implemented system design, model
  loop, tool runtime, source-guided workflows, evidence gates, and safety model.
- [Open Core And Pro Reports](open-core.md): Apache-2.0 core, paid report
  formats, and the `ravage_pro.report` extension contract.
- [Technical Guide](technical-guide.md): code map, model/action contract,
  workflow rules, evidence rules, XBEN modes, and test strategy.
- [Differentiation Roadmap](differentiation-roadmap.md): roadmap and remaining
  product/engineering gaps.

Superseded execution plans live under [`archive/`](archive/README.md) as
repository history and are excluded from the published docs site. If historical
material conflicts with `ravage --help`, [Architecture](architecture.md), or
[Technical Guide](technical-guide.md), the current docs and CLI help win.

## Current Truth

Ravage is a source-checkout research workspace with publishable package
boundaries. The current public command is `ravage`, provided by the
`packages/ravage` workspace member. The runtime package boundary is
`packages/ravage`; the repository root remains a development workspace and
should not be published as the package. Shared schemas are packaged as
`ravage-schemas`, while their Python import path remains `pentest_schemas`.
Publishable package versions follow semantic versioning and should match
release tags such as `vMAJOR.MINOR.PATCH`.

`ravage attack` runs the real model-driven `ai-web` loop. It calls the configured
model route, requires a JSON action, executes a scoped tool, records the
observation, and repeats until `final` or the turn budget is reached. Every
attack writes a canonical `report.json`; `--report` additionally writes the
human-readable `report.md`. Every run also retains `audit.db`, `stdout.log`, and
workspace artifacts.

`ravage scan` is optional deterministic DAST. It performs scoped discovery and
typed probes without an LLM action loop and writes an auditable run directory.
Attack workspaces can be resumed; deterministic scans do not use that resume
flow.

The public attack loop builds its `available_probes` catalog dynamically from
the traffic policy, identity boundary, and eligible runtime. Use
`ravage doctor --workflow attack --brief BRIEF.yaml` and `ravage tools check`
for preflight; do not rely on a broad scanner-action catalog or a
`workspace/capabilities.json` artifact in the public attack path. The
`ravage-perimeter-box` lab remains a two-port local target for exercising scoped
recon and content discovery.

Local lab boxes are intentionally vulnerable and must stay local or isolated:

- `ravage-acme-box`: 4 flags, medium.
- `ravage-forgeops-box`: 6 flags, hard.
- `ravage-node-market-box`: 5 flags, medium.
- `ravage-perimeter-box`: 5 flags, hard, multi-port recon.
- `ravage-session-boundary-box`: 3 flags, medium, browser/session boundaries.

Ravage Memory is design-stage in the current public CLI. Public benchmark and
agent runs should keep memory off unless a future release explicitly exposes
reviewed memory modes in `ravage --help`.

Fake-model tests only prove loop mechanics and scoring behavior. They are not
benchmark performance.

XBEN support has explicit context modes:

- `black-box`: benchmark description is visible; source code, case names, and
  difficulty levels are withheld.
- `white-box`: source context may guide candidates, but reported findings still
  require dynamic confirmation.
