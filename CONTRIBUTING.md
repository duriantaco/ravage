# Contributing To Ravage

Thank you for helping improve Ravage. Contributions are welcome across the
runtime, deterministic probes, local labs, evidence tooling, documentation,
tests, and external-agent adapters.

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).

## Before Starting

Search existing issues and pull requests first. Open an issue before a
substantial change to public CLI behavior, schemas, safety boundaries,
benchmark protocol, packaging, or licensing. Small fixes, focused tests, and
documentation corrections may go directly to a pull request.

Report security vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Safety Boundaries

Contributions must:

- operate only on explicitly scoped, authorized targets;
- keep intentionally vulnerable labs on localhost or isolated networks;
- use synthetic credentials, flags, sessions, and target data;
- preserve scope checks, evidence gates, rate bounds, and non-destructive
  defaults;
- include negative tests for out-of-scope or unsafe behavior when relevant.

Never commit provider keys, real credentials, cookies, customer data, private
target output, or unreviewed raw run archives. Do not weaken a safety check
merely to make a test or benchmark pass.

## Development Setup

Ravage currently supports Python 3.12.

```bash
scripts/bootstrap.sh
source .venv/bin/activate
ravage --version
```

Use `ravage --help`, current maintained documentation, and the source as the
authority when archived plans or old examples disagree.

## Tests And Static Checks

Run the narrowest relevant tests while developing, then the applicable broader
tier before requesting review.

Targeted tests:

```bash
.venv/bin/python -m pytest path/to/test_file.py -q
```

Non-integration suite:

```bash
.venv/bin/python -m pytest -m "not integration" -q
```

Docker or external-service integration tests:

```bash
.venv/bin/python -m pytest -m integration -q
```

Check changed Python files for syntax and undefined-name errors:

```bash
.venv/bin/python -m ruff check --select E9,F path/to/changed_file.py
```

Run the supported schema type-checking baseline when schemas change:

```bash
MYPYPATH=packages/schemas/src \
  .venv/bin/python -m mypy packages/schemas/src packages/schemas/tests
```

For packaging or release changes:

```bash
.venv/bin/python scripts/check_release.py
```

For documentation, examples, or CLI command changes:

```bash
.venv/bin/python scripts/check_docs.py
```

Keep touched Python files clean in Pyright/Pylance. Avoid blanket type
suppressions; validate or narrow unknown data at its boundary.

The pull-request body must list the exact commands run and their results. If a
repository-wide command has a known unrelated baseline failure, report it
explicitly and show the targeted result. Never describe an unrun or failing
command as passing.

## Code And Documentation Expectations

- Add positive and negative tests for behavior changes.
- Keep probes bounded, reusable, and independent of particular benchmark IDs
  or flags.
- Do not add target-specific shortcuts, expected flags, hidden solution paths,
  or competitor-specific scoring exceptions.
- Preserve typed interfaces and readable control flow.
- Update current CLI and operator documentation whenever commands, flags,
  schemas, outputs, or safety behavior change.
- Keep generated artifacts and unrelated formatting out of functional commits.

## Benchmark And Reproduction Contributions

Label every submitted result as a smoke/development run, partial reproduction,
or complete release-quality run. Only a complete release-quality run may update
a published score.

Complete runs must identify and retain:

- clean Ravage and benchmark worktrees with exact commit SHAs;
- target selection, mode, input contract, seed, and exclusions;
- model provider, model snapshot, route tier, turn limits, and pricing
  source/date;
- tool-runtime version, image digest, and architecture;
- preflight output and a fresh output directory;
- all failures, errors, and timeouts without replacement rows;
- every retry, resume, or protocol deviation;
- exact-flag, false-positive, out-of-scope, and cost accounting;
- reports, audit records, redacted traces, and SHA-256 manifests;
- a completed redaction and secret review.

Public XBEN results must be described as public-regression evidence, not
unseen-task performance. Competitor results must use the same target set and
declared scoring contract. Self-reported solves are not accepted without
replayable target evidence.

Prefer separate pull requests for implementation changes and frozen run
evidence. A code change made after a run cannot be claimed as part of that old
run.

## Commits And Pull Requests

Use a conventional pull-request title such as `feat:`, `fix:`, `docs:`,
`test:`, `refactor:`, `ci:`, or `chore:`. Keep commits logical and avoid mixing
unrelated changes. Release Please owns normal version and changelog updates;
do not manually bump versions except during an approved release repair.

Every pull request should explain:

- what changed and why;
- safety and scope impact;
- exact tests and results;
- benchmark or evidence impact;
- documentation and compatibility changes;
- known limitations or follow-up work.

Maintainers may squash commits when merging.
