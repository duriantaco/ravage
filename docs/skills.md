---
title: Knowledge Skills
---

# Knowledge Skills

Ravage knowledge skills are small, optional `SKILL.md` cards that help the
model prioritize an existing typed probe or evidence workflow. They do not add
tools, widen target scope, grant an identity, bypass the traffic policy, or
confirm a finding.

Skills are off unless the operator selects a pack. The normal `ravage attack`,
`ravage scan`, and frozen XBEN comparison paths therefore keep their existing
behavior.

## Use The Built-In Pack

Inspect and validate the repository-owned pack first:

```bash
ravage skills list builtin
ravage skills validate builtin
```

The built-in pack contains twelve bounded skills:

- `hunt-idor`: paired owner/non-owner authorization testing;
- `hunt-graphql`: bounded schema and resolver investigation;
- `hunt-ssrf`: server-side URL-fetch differentials;
- `hunt-xxe`: XML parser and external-entity controls;
- `hunt-deserialization`: serialized-data trust boundaries;
- `hunt-xss`: reflected, stored, and DOM execution validation;
- `hunt-sqli`: paired SQL query differentials;
- `hunt-ssti`: server-side template-evaluation controls;
- `hunt-lfi`: local file inclusion and traversal validation;
- `hunt-rce`: command and server-execution boundaries;
- `hunt-file-upload`: upload, storage, readback, and parser boundaries; and
- `analyze-satcom`: passive interpretation of supported offline SATCOM
  artifacts.

Every hunting card routes only to existing native probes, requires a replayable
paired control before confirmation, keeps `contract_missing` results suspected,
and retains validated vulnerabilities independently of any challenge artifact.

Enable the web skills through the explicit experimental wrapper:

```bash
ravage code-bug ravage-brief.yaml \
  --skills builtin \
  --card-limit 2 \
  --max-card-chars 3000 \
  --allow-paid-models \
  --report
```

The selector considers operator context and code-owned typed state. It does not
route from the model's summaries, hypotheses, memory, or proposed next actions,
so a card cannot make itself increasingly likely merely by repeating its own
topic. Routing scans every operation in the bounded surface graph, including
typed parameters, content types, provenance, and hints; only allowlisted native
marker values can activate a card. The serialized card payload is bounded by
`--max-card-chars`. Ravage never tail-truncates a card because that could remove
its evidence gate or stop conditions; a complete card that cannot fit is omitted.

Every loaded pack and selected card is content-hashed in run events and
benchmark reports. The absolute pack path remains operator-side metadata and is
not sent to the model. Ravage consumes only `SKILL.md`; it never executes a
skill's scripts or treats its assets as runtime authority.

## Why A Skill Can Still Make Results Worse

A poorly scoped card can consume prompt space, bias exploration toward the
wrong family, or spend turns on a low-value branch. The hard scope, tool,
traffic, and evidence gates limit the damage, but they cannot make bad
prioritization useful. Keep new packs opt-in until a matched evaluation shows a
repeatable gain.

For a useful comparison, hold the model, target snapshots, case matrix, request
policy, and repeat seeds fixed. Run at least three matched repeats with the
pack off and on, include clean controls and previously passing cases, and
compare:

- evidence-backed vulnerabilities and per-case success;
- false positives, proof-integrity failures, and control findings;
- physical and model requests, cost, timeouts, and incomplete runs; and
- card-selection frequency and whether selected branches advanced evidence.

An experimental pack-on result is not a frozen pack-free benchmark result.
Archive accepted and rejected pack digests through the
[Improvement Lab](improvement-lab.md), and promote only the exact reviewed
digest that passes the no-regression gates.

## Add A Pack

A pack is either one skill directory or a directory containing skill
directories. Each skill directory must match its frontmatter name:

```text
my-pack/
└── hunt-example/
    └── SKILL.md
```

```markdown
---
name: hunt-example
description: Explain the typed signals that should activate this workflow.
---

# Hunt Example

Describe a bounded workflow, its evidence gate, and explicit stop conditions.
```

Names use lowercase letters, digits, and hyphens. Frontmatter is deliberately
flat and limited to `name`, `description`, and the optional legacy
`report_count`. The loader rejects duplicate or unknown fields, name/path
mismatches, unsafe permissions, symlinks, hard links, oversized files, invalid
UTF-8, and control characters.

Validate before use:

```bash
ravage skills validate /absolute/path/to/my-pack
ravage code-bug ravage-brief.yaml --skills /absolute/path/to/my-pack
```

For a reproduced or archived run, pin the value printed by `ravage skills
validate`:

```bash
ravage code-bug ravage-brief.yaml \
  --skills /absolute/path/to/my-pack \
  --skills-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The wrapper always forwards the resolved digest to the attack or experimental
XBEN child. A pack changed after resolution fails before model or target work
instead of being silently substituted. For a resume, explicitly supply the
digest retained in the original run report; automatic migration of older
workspaces to a persistent pack-binding manifest is still future work. The
example digest is schematic; use the exact 64-character lowercase value from
the validator.

A new card should point only to probes and capabilities that actually exist in
Ravage. Stable execution belongs in typed code-owned adapters; a prose skill is
not a substitute for a parser, protocol implementation, or evidence validator.
