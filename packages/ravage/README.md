# Ravage

Ravage is an evidence-first web security research agent for controlled,
authorized targets. This package provides the `ravage` CLI and runtime modules.

The project is a pre-1.0 research alpha. Use it only on local fixtures, isolated
labs, or systems you own and are explicitly authorized to assess. The active
public CLI is localhost-first.

## Source Checkout

The canonical development setup is the repository bootstrap:

```bash
scripts/bootstrap.sh
source .venv/bin/activate
ravage doctor
```

For an unreleased checkout, record the exact commit when reporting results.
Use a tagged release for reproducible production or benchmark comparisons.

## Active Commands

Create a brief and run the safest first scan against a running localhost app:

```bash
ravage init http://127.0.0.1:3000
ravage doctor --workflow scan --brief brief.yaml
ravage scan brief.yaml --probe surface_map --report
```

This path needs no model key, browser, Docker daemon, or external scanner. For
the model-driven agent, add a useful `context.description` to the brief and a
provider key to `.env.ravage`, then run:

```bash
ravage doctor --workflow attack --brief brief.yaml
ravage attack brief.yaml --allow-paid-models --report
```

Every attack writes the canonical private `RUN_DIR/report.json`, including
incomplete or failed runs and runs without `--report`. This JSON-only
finalization is atomic and sends no model or target requests. `--report` adds
the human-readable `RUN_DIR/report.md`; PDF and DOCX outputs require Ravage Pro.

Ravage loads `.env.ravage` beside the brief directly and infers a configured
hosted route; do not shell-source the file. Use `--env-file`,
`--model-profile`, or `--model-tier` only when overriding those defaults.

Inspect and verify a run:

```bash
ravage observe RUN_DIR
ravage audit verify RUN_DIR
ravage report RUN_DIR --brief brief.yaml
```

Use `ravage --help` and each subcommand's `--help` for the installed version.

When an attack enters the bounded `agent-graph` route, structured HTTP history
is captured automatically in its nested workspace, including redirect legs and
transport-failure results. No browser install is needed to inspect it:

```bash
ravage traffic list RUN_DIR
ravage traffic show RUN_DIR REQUEST_ID
```

These commands expose identifier-only links from request IDs to graph
observation and evidence IDs. Markdown and JSON reports include the same Agent
HTTP Evidence summary. Capture is strict—persistence failure blocks evidence
promotion—and resume retains the structured request count and DNS pins. Traffic
from `curl`, Docker tools, scanners, and other external processes is not added
to this history.

External scanners such as `nmap`, `sqlmap`, `katana`, `nuclei`, and `ffuf` are
not Python dependencies. From a source checkout, use
`ravage tools install --method docker --execute`, then run
`ravage tools check`.

For separate, operator-driven browser traffic capture from a source checkout, run
`scripts/bootstrap.sh --install-browser`, reactivate `.venv`, and then run
`ravage doctor --workflow traffic --target-url URL`. The traffic capture/replay
artifact store currently requires macOS, Linux, or WSL; use WSL rather than
native Windows for that command family.

## Documentation

See the [repository README](https://github.com/duriantaco/ravage#readme),
[setup guide](https://github.com/duriantaco/ravage/blob/main/docs/setup.md), and
[operator guide](https://github.com/duriantaco/ravage/blob/main/docs/ai-web-operator-guide.md).

Ravage is open source under the Apache License 2.0. See the repository
`SECURITY.md`, `CONTRIBUTING.md`, `DISCLAIMER.md`, and `LICENSE` before use or
contribution.
