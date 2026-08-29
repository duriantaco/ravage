# Examples

This directory contains engagement briefs, model-route examples, and local lab
definitions. Every example is for a system you own or are explicitly
authorized to test.

## Start With A Local Lab

Use the [included labs](labs/README.md) for the safest first run. They are
deliberately vulnerable and must remain on localhost or an isolated network.

```bash
ravage doctor --workflow lab
ravage lab list
ravage lab up ravage-acme-box
ravage scan examples/labs/ravage-acme-box/brief.yaml \
  --probe surface_map \
  --run-dir runs/quickstart-acme-scan \
  --report
ravage audit verify runs/quickstart-acme-scan
ravage lab down ravage-acme-box
```

`lab up` finds the included labs and waits for the health endpoint. The
deterministic scan does not call a model or require an API key.

## File Guide

- `model_profiles.yaml`: local and hosted model-route examples. Credentials are
  read from environment variables, never stored in the file.
- `attack.localhost.yaml`: example localhost agent configuration.
- `attack.remote-authorized.yaml`: historical/experimental remote configuration;
  the active public CLI remains localhost-first.
- `benchmark.ai-web-hosted.yaml`: example hosted-model benchmark configuration.
- `remote_authorized_brief.yaml`: engagement-brief shape for explicitly
  authorized scope; check current CLI locality restrictions before use.
- `bwapp.yaml` and `dvwa.yaml`: sample briefs for local installations of those
  intentionally vulnerable applications.
- `test_repo.yaml`: development fixture, not the recommended first-run brief.

Use `ravage --help` and the maintained [documentation](../docs/README.md) when
an older example disagrees with the active CLI.
