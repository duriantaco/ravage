# Scripts

Top-level files in this directory are compatibility wrappers. Put new
implementation scripts in one of these folders:

- `xben/`: benchmark runners and XBEN report tools.
- `qa/`: static checks and release checks.
- `eval/`: offline evaluation utilities.
- `ops/`: environment setup and install helpers.

Run the maintained-document link and stale-command check with:

```bash
.venv/bin/python scripts/check_docs.py
```

Run the experimental, source-checkout-only improvement sidecar with:

```bash
.venv/bin/python scripts/improvement_lab.py --help
```

See [Improvement Lab](../docs/improvement-lab.md) for its raw-log trust
boundary, immutable archive, candidate gates, and human promotion workflow.
