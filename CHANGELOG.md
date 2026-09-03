# Changelog

This file records public Ravage releases and the current unreleased source
state. Release tags use `vMAJOR.MINOR.PATCH` and must exist in this repository
before an entry is described as released.

## Unreleased

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

## 0.5.0 Source Baseline - 2026-07-11

`0.5.0` is the current source version and Release Please manifest baseline. It
was not published as a GitHub tag or PyPI release, so it is not presented as a
released artifact.

Notable source capabilities at this baseline include:

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
