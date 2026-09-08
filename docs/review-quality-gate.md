# Read-only review quality gate

The `Read-only review quality` CI job measures the production read-only repository
reviewer against a frozen, labelled corpus. `Fast checks` depends on this job and
requires its result to be `success`. The existing main-branch rule requires
`Fast checks`, so a missing, failed, cancelled, or skipped quality job blocks that
required aggregate. A green unit-test suite alone is insufficient.

The aggregate uses `always()` with explicit dependency results, following
[GitHub's required-check guidance](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

## What is measured

The corpus contains ten source fixtures: five with labelled weaknesses and five
paired negative cases, covering four labelled classes. Each fixture is reviewed
three times with literal source access and three times with source-candidate
assistance: 60 reviews per evaluation. Both modes use the actual read-only review
loop and its normal prompts. The model chooses its own source reads. The evaluator
never executes the fixture source or contacts application targets.

The provider must return `gpt-5.4-2026-03-05`, with high reasoning and an explicit
output limit. Every response must include verified model identity and complete
usage accounting. There are no fallback models, replayed model responses, or
automatic provider retries. Python and evaluation dependencies are pinned. The
report records the engine revision, source and evaluator hashes, model settings,
dependency versions, individual results, and provider usage.

These are diagnostic source-review results. They do not establish performance on
exploitation, external websites, or unseen repositories. The 60 reviews are
repeated observations of ten fixtures, not 60 independent applications.

## Failure conditions

- Any missing, duplicate, failed, or unexpected case, review mode, or repetition.
- A different model, runtime, labelled corpus, evaluator, or review budget.
- Fewer detections of **any individual expected finding** than the baseline,
  measured separately in each review mode across the three repetitions.
- More false positives for any case and mode. A gain elsewhere cannot offset it.
- More findings outside a fixture's labelled classes. These require adjudication;
  they are reported separately instead of being described as verified discoveries
  or automatically labelled false positives.
- Aggregate precision below 90% or recall below 80% in either review mode.
- Model calls above 1.5 times the baseline plus one call per repetition, or token
  cost above the larger of 1.5 times baseline and baseline plus $0.02 per repetition.
  Token cost uses uncached input prices so cache discounts cannot hide increased
  work. Actual provider cost is recorded separately.
- An exceeded per-review limit of 24 turns or $0.50, or the shared $10 evaluation
  ceiling. The next provider request must fit a conservative remaining-cost bound.
- Missing credentials, incomplete provider usage, or code changing during a run.

The limits live in `benchmarks/repository-review/policy.json`. The baseline stores
the observed samples, not just an aggregate score. Comparisons use strict counts;
three repetitions reduce sensitivity to a single lucky run but do not eliminate
model variance. A failed evaluation stays failed. Inspect its artifacts before
rerunning; do not repeatedly rerun until a favourable result appears.

## Run the gate

Use Python 3.12.13 and the pinned constraints:

```bash
python -m pip install -c benchmarks/repository-review/requirements.txt \
  -r benchmarks/repository-review/requirements.txt \
  -e packages/schemas -e packages/ravage
python scripts/eval/run_review_quality_gate.py check \
  --allow-paid-models \
  --output-dir /tmp/review-quality-check-001
```

Set `OPENAI_API_KEY` locally, or configure it as a GitHub Actions repository secret
for CI. Never put the key in a command line or a result file. Each CI workflow run
can spend up to $10; push and pull-request events can each launch a run. Fork PRs
do not receive repository secrets and will fail closed. A maintainer must review
the code before running it on a trusted branch with credentials. This workflow
does not use `pull_request_target` to run fork code with secrets.

Dependabot events use a separate secret store and do not receive Actions secrets.
They also block unless the key is deliberately configured there, or a maintainer
runs the reviewed change on a trusted branch. See
[GitHub's Dependabot secret rules](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-on-actions).

The output directory must be new. It retains `verdict.json`, `summary.md`, provider
accounting, the completed measurement when available, and the underlying review
report. CI uploads the directory even after failure and keeps it for 30 days.
Cancelled jobs may have incomplete evidence; they cannot pass. No score is
accepted solely because a report file exists.

## Baseline maintenance

Initial installation uses an explicit `record` command, which runs the same live
evaluation, applies the absolute quality floors, and exclusively creates
`benchmarks/repository-review/baseline.json`. It refuses to overwrite a baseline.
CI only invokes `check`; it cannot promote its own results.

During initial calibration, the 12-turn configuration completed 58 of 60 reviews.
Two literal-source reviews of `keystone`, the larger negative fixture, exhausted
their turn limit. That run was rejected and retained, despite finding every
labelled weakness in the completed reviews. The common turn budget was then set
to 24 for all cases and both modes before recording a baseline. The corpus,
model, score floors, and dollar ceilings were unchanged.
The [rejected calibration summary](../benchmarks/repository-review/calibration-12-turns.json)
preserves the partial scores, failures, provider usage, and original report hash.

Once baseline and policy files exist on the base commit, ordinary CI runs reject
changes to either file. Changes to corpus labels, scoring, runtime, or budgets
require a separately reviewed baseline migration. Preserve the previous reports
and explain why the old and new measurements are no longer directly comparable.
Do not relax thresholds in the feature change being evaluated.

This gate assumes maintainers review changes to CI and scoring code. It is not a
security boundary against someone authorised to rewrite workflows or repository
rules. As the corpus grows, add independently labelled fixtures and negative
controls, then establish a new versioned baseline through that review process.
