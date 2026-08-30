# Changelog

This file records public Ravage releases and the current unreleased source
state. Release tags use `vMAJOR.MINOR.PATCH` and must exist in this repository
before an entry is described as released.

## Unreleased

## 0.6.0 - 2026-08-30

### Security

- Removed provider keys and arbitrary parent secrets from model-selected host
  shell, Python, and graph-process environments.
- Made host execution an explicit localhost opt-in and kept process-capable
  remote attacks inside scoped Docker execution without silent host fallback.
- Blocked schema-only and unaccountable paid model routes before credential
  access or network dispatch.
- Pinned publishing actions to immutable commits and added main-commit,
  changelog, version-consistency, and unused-PyPI-version release checks.

### Fixed

- Persisted confirmed deterministic vulnerabilities even when no CTF flag is
  present, while keeping raw observations and unconfirmed candidates separate.
- Prioritized breadth-first reconnaissance and constrained discovered DOM and
  form targets to valid, same-origin, in-scope URLs.
- Added deterministic scan work, reconnaissance, and validated lower-bound
  request accounting to reports.
- Bundled the Cockpit frontend, logo, and five local labs into wheels and source
  distributions so installed commands work outside a repository checkout.
- Added clean-install smoke coverage for all packaged labs and Cockpit assets.

### Changed

- Replaced the CLI's remote HTTP-only lane with the full `ai-web` base for
  explicitly authorized remote targets, forcing command-like tools through a
  DNS-pinned, target-scoped Docker network and extending URL scope to probes and
  Playwright-backed DOM validation.
- Clarified the frozen Ravage-only XBEN evidence and its limitations.
- Added passive API authorization inventory and loop-verification hardening.
- Simplified public onboarding and separated current docs from archived plans.
- Added security reporting, contribution guidance, and repository templates.
- Added supported wheel-install guidance and a reproducible TestPyPI,
  production release, verification, and yank runbook.

## 0.5.0 PyPI Preview - 2026-07-14

`ravage==0.5.0` and `ravage-schemas==0.5.0` were published to PyPI without a
matching GitHub tag or release. The repository later diverged while still
identifying itself as `0.5.0`, so those immutable artifacts do not represent
the current source tree. They remain a historical preview and must not be
overwritten or treated as the `0.6.0` release candidate.

Notable capabilities in the source line around that preview included:

- the model-driven agent and deterministic scan paths;
- local deliberately vulnerable labs;
- hash-chained audit and proof-gated reporting;
- XBEN execution and frozen evidence tooling;
- the competitor adapter and referee harness.

## 0.0.1 Legacy Preview - 2026-05-28

`ravage==0.0.1` and `ravage-schemas==0.0.1` were published to PyPI as early
preview packages. They are not the canonical state of the current checkout.

Detailed pre-public development notes are retained in
[`docs/archive/pre-public-changelog.md`](docs/archive/pre-public-changelog.md).
