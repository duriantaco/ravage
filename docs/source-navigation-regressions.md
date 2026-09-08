# Source navigation regressions

The permanent runner checks route inventory and a harmless local source-to-request
handoff. Use it to catch regressions before changing the source reader or its
authorization gate.

The separate [read-only review quality gate](review-quality-gate.md) measures
repeated GPT-5.4 reviews against a frozen detection baseline and blocks the
required CI aggregate when quality regresses.

## Offline inventory

From a checkout with the development dependencies installed:

```bash
python scripts/eval/run_source_navigation_eval.py offline \
  --output /tmp/source-navigation-inventory.json
```

The [fixture manifest](../packages/ravage/tests/fixtures/source_navigation_eval/cases.json)
contains manually labelled source strings. The evaluator reads each fixture in
forward and reverse file order, then compares the exact authorized method/path
set against those labels. It also checks that the HTTP action gate rejects the
explicit forbidden routes. It never executes the fixture source or opens sockets.

| Category | Cases | Expected behavior |
| --- | ---: | --- |
| Supported | 8 | Find the labelled Flask, FastAPI, and Express routes, including Python mounts and nested prefixes. Ignore unrelated strings and comments. |
| Negative | 3 | Reject orphan routers, missing imports, and competing handlers. |
| Unsupported | 3 | Keep dynamic paths, dynamic prefixes, and incomplete runtime snapshots blocked. |

The initial baseline is 28 evaluations, 18 expected route observations, zero
missed routes, and zero unexpected authorizations. Recall covers only the
supported route labels. Unsupported cases are reported separately; a passing
rejection does not mean their routes were discovered. The test suite also changes
a route while retaining its original label to confirm that a regression fails.

CI runs this command and the regression tests without model calls or API costs.
JSON reports include per-case errors, omissions, observation volume, the corpus
hash, the evaluated Git revision, and a hash of the evaluator and relevant code.
A changed revision or toolchain during a run invalidates the result.

## Local receipt canary

```bash
python scripts/eval/run_source_navigation_eval.py canary --pairs 3 \
  --output /tmp/source-navigation-canary.json
```

Each pair uses a new random route in a small two-module FastAPI-shaped fixture.
The source strings are never executed. A separate loopback server returns a
random receipt only at that route. One arm receives source-reader access; its
paired control receives no source or route labels. Arm order alternates from a
random starting order, and every arm has an eight-turn limit.

The harness uses the production source executor, prompt helper, and authorization
gate. Its action dispatcher permits fixture reads and bodyless GET requests to
its own loopback server. Both arms receive the same explicit path and request
field limits. Rejected actions fail the run with a fixed diagnostic code without
recording their raw contents. It does not launch the full agent. A treatment pass
requires source evidence, an advertised route, a proposed and selected request,
the observed server request, and the exact server-issued receipt to agree.
The control must not obtain the receipt. Reports store hashes and boolean links,
not the random route or receipt value.

The default scripted driver tests this wiring deterministically. Its treatment
reads the known fixture files; its control requests `/`. Those scripted outcomes
are not model performance evidence.

## Optional GPT-5.4 check

With a clean committed checkout and `OPENAI_API_KEY` configured:

```bash
python scripts/eval/run_source_navigation_eval.py canary \
  --driver gpt54 --allow-paid-models --pairs 1 --budget-usd 2 \
  --output /tmp/source-navigation-gpt54.json
```

This uses the existing `hosted-openai-gpt-5.4-high` profile and requires the exact
`gpt-5.4-2026-03-05` response model with `high` reasoning. The adapter limits each
response to 4,096 output tokens. Model identity and usage are checked on every
response; failures stop the campaign. A conservative pre-request cost bound
applies to the shared budget across all arms. Reports distinguish known cost from
incomplete accounting after a failed call. The model snapshot and reasoning
options are documented in the [official model reference](https://developers.openai.com/api/docs/models/gpt-5.4).

The paid run evaluates this bounded fixture reader and gate. It does not measure
the full agent's search breadth, runtime framework behavior, or vulnerability
recall. The offline corpus supplies all captured source; it tests structural
coverage, not whether a model would choose the right files.

Reports never overwrite an existing output file. Use a new filename for each run.
