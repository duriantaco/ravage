---
title: Memory Design
---

# Memory Design

This page documents the Ravage Memory design, not an active operator command
set. In the current public CLI, `ravage attack --memory off` is accepted for
reproducibility parity and active memory is not wired into the `ai-web` entry
point. There is no active memory review command in the current CLI.

Use this page as implementation context for future memory work. For current
runs and benchmark claims, keep memory off and rely on live target evidence.

`scripts/run_memory_eval.py` and its compatibility API explicitly report that
memory A/B evaluation is unavailable. The command exits 2 without calling a
model, opening a memory database, or writing a report. Earlier hard-coded
outputs from this entry point are not evaluation evidence.

## Design Goal

Ravage Memory is intended to be a local-first learning loop for `ai-web`. It is
not model training and it is not proof. It stores redacted lessons from previous
runs, retrieves relevant verified memories as advisory hints, and promotes only
reviewed, replay-tested tactics.

The design is conservative:

- memory is local SQLite by default;
- retrieval uses SQLite FTS5 and does not require a vector service;
- memories cannot report findings or capture flags;
- scope and same-origin rules always override memory;
- live tool evidence always overrides memory;
- promotion requires human review and replay evidence;
- benchmarks default to memory off.

## Current CLI Status

Current attack runs should use:

```bash
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --model-profile local-ollama \
  --model-tier mid \
  --memory off
```

`--memory off` is the only public memory mode accepted by `ravage attack` in the
current entry point. If your checkout later exposes more modes, confirm with:

```bash
ravage attack --help
ravage --help
```

## Proposed Modes

The design reserves four modes for future work:

- `off`: no retrieval and no writes.
- `read`: retrieve only `verified` or `promoted` memories.
- `write`: write redacted candidate memories after a run, but do not retrieve.
- `learn`: retrieve memories, write candidates, and record usage feedback.

Benchmarks should remain `off` unless a benchmark is explicitly measuring the
memory system itself. Public benchmark claims should state the memory mode.

## Proposed Review Workflow

Future memory review should follow this policy:

1. Candidate memories are redacted before storage.
2. A reviewer inspects the source run and rejects overfit or unsafe candidates.
3. A promoted memory requires replay on a controlled target.
4. Retrieved memories are advisory hints only.
5. Findings still require target-origin proof from the current run.

Future command families should cover review, show, promote, reject, redacted
export, and garbage collection. They should not be documented as operator
instructions until they appear in `ravage --help`.

## Redaction And Retention

The memory layer should redact flags, JWTs, cookies, auth headers, bearer
tokens, API keys, and session IDs before storage. Large strings should be
truncated, and unsafe memory writes should be rejected.

The DB should keep useful replay-backed memories hot while compacting or
purging noisy material:

- `promoted` and `verified`: retrievable, protected by default.
- `candidate`: review queue; old unpromoted candidates become `archived`.
- `stale`: ignored or repeatedly failed; not retrieved.
- `contradicted`: verified/promoted memory failed more than it succeeded; not
  retrieved.
- `rejected`: reviewer rejected it; details are kept briefly for audit.
- `expired`, `archived`, `stale`, `contradicted`, `superseded`: retained only
  until their TTL or size pressure purges detail.

When detail is purged, the design keeps a tiny tombstone with the memory id,
original status/type, source run, reason, timestamp, and a summary hash. This
prevents unbounded growth while preserving enough history to avoid relearning
the same bad lesson.

## Evaluation Standard

Memory should be treated as useful only if it improves held-out controlled
cases without increasing false positives. A future memory evaluation should run
the same selected benchmark cases twice:

1. `memory-off`: no retrieval.
2. `memory-read`: reviewed memories injected as hints.

The comparison should report:

- delta in valid findings or flags;
- delta in false positives;
- delta in missed findings;
- token/cost changes;
- proof that the same commit and case selection were used.

For public benchmark claims, do not mix memory-assisted scores with normal
memory-off scores unless the report clearly separates them.
