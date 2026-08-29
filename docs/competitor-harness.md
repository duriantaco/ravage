---
title: Competitor Harness
---

# Competitor Harness

The competitor harness is the reproducible path for head-to-head false-positive
measurement. It runs each configured agent against each configured box, gives the
agent only the target URL plus an internal Docker network name, and scores the
agent artifact using the same fields for Ravage and any external adapter.

Status: the harness is implemented, but this repository currently includes no
real external-agent matrix or published competitor leaderboard. The checked-in
example configuration is smoke-only; replace every adapter, target, expected
flag, model declaration, and command before treating output as comparative
evidence.

Start with preflight. It checks Docker availability and local free disk before
any target setup or agent command runs:

```bash
ravage competitors preflight \
  --config eval/competitor_harness.example.yaml \
  --output-dir runs/competitors/preflight
```

The default disk guard is 20 GiB. If the machine is below that threshold,
preflight writes `preflight.json` with `blocked: true`. That is intentional:
competitor images and model traces can be large, and a partial benchmark is worse
than no benchmark. Lower `min_free_gib` only for a known-small adapter smoke run:

```bash
ravage competitors preflight \
  --config eval/competitor_harness.example.yaml \
  --output-dir runs/competitors/smoke \
  --min-free-gib 5
```

Run the configured matrix only after preflight is acceptable:

```bash
ravage competitors run \
  --config eval/competitor_harness.example.yaml \
  --output-dir runs/competitors/head-to-head
```

`competitors run` also performs preflight itself, writes `preflight.json` into
the run directory, and exits before launching adapters when the checks block.
The separate command remains useful for inspecting readiness without starting
the matrix.

The same command is available through the standalone eval wrapper:

```bash
python eval/competitor_harness.py preflight \
  --config eval/competitor_harness.example.yaml
```

The run writes:

```text
runs/competitors/head-to-head/
  preflight.json
  config.normalized.yaml
  report.json
  leaderboard.tsv
  leaderboard.md
  artifacts.sha256
  agents/<agent>/<box>/
    agent-result.json
    stdout.log
    stderr.log
```

## Ravage Self-Adapter

Use `adapt-ravage` to convert one Ravage benchmark case into the same
`agent-result.json` shape that the competitor harness scores:

```bash
ravage competitors adapt-ravage \
  --benchmark-report runs/benchmarks/report.json \
  --case-id ai-vulnerable-search \
  --output runs/competitors/ravage/agent-result.json
```

The adapter reads the benchmark report, case DB, and workspace trace. It emits
Ravage-native telemetry including budgets, actuals, artifact paths, termination,
kill-chain phase coverage, and replayable proof objects for confirmed findings.

## Isolation Contract

For each box, the harness creates a Docker network with `--internal`:

```text
docker network create --internal ravage-bench-<box>-<suffix>
```

Agent commands receive these environment variables:

- `RAVAGE_COMPETITOR_DOCKER_NETWORK`
- `RAVAGE_COMPETITOR_TARGET_URL`
- `RAVAGE_COMPETITOR_OUTPUT_DIR`
- `RAVAGE_COMPETITOR_RESULT_PATH`
- `RAVAGE_COMPETITOR_AGENT`
- `RAVAGE_COMPETITOR_BOX`
- `RAVAGE_COMPETITOR_MODEL`
- `RAVAGE_COMPETITOR_PROVIDER`

Launch containerized competitors with that network and do not mount the Docker
socket. If a command needs shell interpolation, make that explicit with
`["sh", "-lc", "..."]` in the YAML. The harness itself does not run commands
through a shell.

## Result Adapter Shape

Each agent command must write JSON to `RAVAGE_COMPETITOR_RESULT_PATH`:

```json
{
  "cost_usd": 0.0,
  "raw_flags": ["flag{example}"],
  "audit_evidence_path": "audit.db",
  "findings": [
    {
      "vuln_class": "ssrf",
      "in_scope": true,
      "proof": {
        "http_request_final": "GET /fetch?url=http://internal/flag HTTP/1.1",
        "response_final": "HTTP/1.1 200 OK..."
      }
    }
  ]
}
```

`findings` may also use `proof_path` or `evidence_path`, but paths must exist
relative to the agent run directory, remain contained beneath that directory,
and refer to a non-empty file. Absolute paths, parent-directory escapes, and
symlink escapes are rejected. A finding without replayable request and
response material is scored as a false positive. Out-of-scope findings are
counted separately and also count against false positives.

The aggregate report is written to `<output-dir>/report.json` and contains per
agent totals for raw flags, valid flags, out-of-scope findings, false positives,
false-positive rate, cost, cost status, and cost per valid flag. Self-reported
vulnerability counts are intentionally not used as scores.

If an adapter cannot report `cost_usd` or enough token/pricing fields to compute
cost, the harness records `cost_status: unknown` and does not compute
cost-per-valid-flag for that row. Unknown cost must not be compared as zero.
