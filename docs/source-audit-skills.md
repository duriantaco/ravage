---
title: Source Audit Skills
---

# Source Audit Skills

Ravage carries a separate pack of thirteen skills for agents reviewing an
authorized source repository. This pack is not the runtime knowledge-card pack:
it does not run the application, builds, tests, installers, PoCs, Ravage probes,
browsers, or target requests.

Start a broad review with:

~~~text
Use $ravage-source-audit to audit this authorized repository for security bugs
and business-logic flaws. Keep the review source-only.
~~~

The broad auditor maps the repository and routes promising boundaries to:

- `ravage-source-access-control`;
- `ravage-source-business-logic`;
- `ravage-source-concurrency`;
- `ravage-source-injection`;
- `ravage-source-files-and-parsers`;
- `ravage-source-outbound-requests`;
- `ravage-source-identity-tokens`;
- `ravage-source-security-config`; and
- `ravage-source-supply-chain`.

Known-vulnerability work is deliberately separate:

- `ravage-source-advisory-discovery` inventories exact repository dependencies
  and researches current primary advisory records;
- `ravage-source-advisory-applicability` checks a specific CVE, GHSA, vendor
  advisory, or public-exploit claim against version, patch, build, feature,
  configuration, and source call-path evidence; and
- `ravage-source-adjudication` independently classifies a completed source
  candidate as `source-supported`, `candidate`, `rejected`, or `blocked`.

Public exploit availability is metadata only. The skills never retrieve or
execute exploit code, and a version match never proves applicability.

## Durable Pattern Dictionary

The broad audit skill uses
`skills/ravage-source-audit/references/code-patterns.json`. Its versioned
records describe stable bug shapes such as ownership-check mismatches,
state-machine bypasses, check-then-act races, query grammar crossings, path
canonicalization gaps, URL check/use mismatches, token-verifier trust, effective
configuration errors, and build-trust violations.

The dictionary tells an agent what semantic path and counterevidence to inspect
in code it has never seen. It is not a signature scanner, a CVE database, or a
completeness claim. Absence of a match must not suppress novel-code reasoning.
Changing advisory data remains in the advisory-discovery workflow with source
URLs and retrieval times.

## Agent Discovery

Canonical skill text lives under `skills/`. Project adapters are symlinks, so
there is only one maintained copy:

- Codex discovers the pack through `.agents/skills/` and provides
  `ravage_source_auditor` and `ravage_source_adjudicator`;
- Claude Code discovers it through `.claude/skills/` and provides
  `ravage-source-auditor` and `ravage-source-adjudicator`.

Both specialists are read-only. Every candidate must include snapshot identity,
exact paths and lines, a complete semantic trace, required configuration,
counterevidence, assumptions, confidence, and coverage gaps. Even a
`source-supported` verdict leaves runtime exploitability unverified.
