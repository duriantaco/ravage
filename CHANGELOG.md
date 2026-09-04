# Changelog

This file records public Ravage releases and the current unreleased source
state. Release tags use `vMAJOR.MINOR.PATCH` and must exist in this repository
before an entry is described as released.

## Unreleased

### Added

- Added a request-aware, gray-box HTTP action path for model-driven runs. It
  reuses session cookies, records redacted request contracts, replays observed
  request shapes, and links each agent request to durable evidence identifiers.
- Added evidence-lead locking for validation replays, including authentication
  pause/reactivation and crash-safe HTTP, traffic, and evidence state.
- Added lane-aware traffic inspection for runs that contain both base-agent and
  autonomous-graph histories. Combined output uses qualified identifiers such
  as `base:rq_0001` and `autonomous_graph:rq_0001`.
- Added a separate, environment-scoped TestPyPI rehearsal workflow with
  installed-wheel verification. Repository environment and trusted-publisher
  configuration remain required before it can be used.

### Security

- Bound evidence-lead replays to their recorded origin, including relative
  requests, so an auxiliary-service lead cannot drift back to the primary
  target.
- Prevented automatic proof capture from accepting request-authored header
  names or values, including repeatedly percent-encoded variants, as target
  evidence.
- Bound report traffic and policy-ledger inputs to the report target and exact
  engagement scope, with post-load boundary revalidation to close artifact
  replacement races.
- Hardened production publication to require an unused version and an exact
  peeled release-tag commit matching current `main` before either package is
  built or published.
- Made Release Please main-only with an explicit automation token, and stopped
  GitHub prereleases from publishing PyPI packages or Kali image manifests.

### Fixed

- Fixed report generation rejecting the valid two-lane traffic layout produced
  by a normal base-then-graph run.
- Made reports fail closed when durable base-agent HTTP state exists without
  its required traffic history, matching the graph lane's provenance rule.

### Changed

- Added an opt-in, cost-accounted `hosted-abliteration` model profile using
  abliteration.ai's OpenAI-compatible API.
- Replaced the CLI's remote HTTP-only lane with the full `ai-web` base for
  explicitly authorized remote targets, forcing command-like tools through a
  DNS-pinned, target-scoped Docker network and extending URL scope to probes and
  Playwright-backed DOM validation.
- Clarified the frozen Ravage-only XBEN evidence and its limitations.
- Added passive API authorization inventory and loop-verification hardening.
- Simplified public onboarding and separated current docs from archived plans.
- Added security reporting, contribution guidance, and repository templates.

## 0.5.0 PyPI Preview - 2026-07-14

`ravage==0.5.0` and `ravage-schemas==0.5.0` were published to PyPI without a
matching GitHub tag or release. The repository later diverged while still
identifying itself as `0.5.0`, so those immutable artifacts do not represent
the current source tree and must not be overwritten.

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
