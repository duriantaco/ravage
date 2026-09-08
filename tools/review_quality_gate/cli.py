"""Run the read-only quality gate, retaining evidence even when it fails."""

# The CLI retains a failed verdict for all preflight errors.
# ruff: noqa: TRY301

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ravage.repository_review_eval_runner import run_repository_review_ab_evaluation

from tools.review_quality_gate.client import ExactReviewClient
from tools.review_quality_gate.gate import (
    BASELINE_PATH,
    MANIFEST,
    POLICY_PATH,
    ROOT,
    SCHEMA,
    Measurement,
    Policy,
    _git,
    cases_for,
    decide,
    digest,
    extract_samples,
    fingerprint,
    protect_baseline,
    read_json,
    revision,
    runtime_versions,
    validate_measurement,
    write_json,
)


def measure(root: Path, policy: Policy, output: Path, *, allow_paid_models: bool) -> Measurement:
    cases_for(policy, root)
    source_paths = ("packages/ravage/src", "packages/schemas/src")
    if _git(root, "status", "--porcelain", "--untracked-files=all", "--", *source_paths):
        msg = "commit production source changes before measuring a baseline or candidate"
        raise ValueError(msg)
    before = (revision(root), fingerprint(root, evaluator=False), fingerprint(root, evaluator=True))
    client = ExactReviewClient(policy, allow_paid_models=allow_paid_models, progress=_progress)
    started = time.monotonic()
    try:
        report = run_repository_review_ab_evaluation(
            manifest_path=root / MANIFEST,
            repository_root=root,
            route=client.route,
            client=client,
            repeats=policy.repeats,
            max_turns=policy.max_turns,
            max_cost_usd_per_run=policy.max_cost_per_run_usd,
            aggregate_cost_ceiling_usd=policy.max_cost_usd,
            allow_paid_models=True,
        )
    finally:
        write_json(
            output / "provider-usage.json",
            {
                "attempted_calls": client.calls,
                "verified_calls": client.verified_calls,
                "known_cost_usd": client.cost_usd,
                "unverified_call": client.failed,
            },
        )
    write_json(output / "raw-report.json", report)
    after = (revision(root), fingerprint(root, evaluator=False), fingerprint(root, evaluator=True))
    if before != after:
        msg = "code changed during the evaluation; retained report is invalid"
        raise ValueError(msg)
    if client.calls != client.verified_calls:
        msg = "evaluation contains a model call without verified identity and usage"
        raise ValueError(msg)
    measurement = Measurement(
        schema_version=SCHEMA,
        policy=policy,
        revision=before[0],
        engine_digest=before[1],
        evaluator_digest=before[2],
        raw_report_digest=digest((output / "raw-report.json").read_bytes()),
        measured_at=datetime.now(UTC).isoformat(),
        elapsed_seconds=time.monotonic() - started,
        verified_model_calls=client.verified_calls,
        runtime=runtime_versions(),
        samples=extract_samples(report, policy, root),
    )
    validate_measurement(measurement, root)
    write_json(output / "measurement.json", measurement.model_dump())
    return measurement


def _progress(calls: int, cost: float) -> None:
    if calls % 10 == 0:
        sys.stderr.write(f"Verified model calls: {calls}; recorded cost: ${cost:.4f}\n")
        sys.stderr.flush()


def _summary(verdict: dict[str, Any]) -> str:
    rows = ["## Read-only review quality", "", "PASS" if verdict["passed"] else "FAIL", ""]
    rows.extend(
        f"- {score['arm']}: {score['true_positives']} correct, "
        f"{score['false_negatives']} missed, {score['false_positives']} false positives; "
        f"precision {score['precision']:.1%}, recall {score['recall']:.1%}; "
        f"{score['unscored_findings']} findings outside labelled classes."
        for score in verdict.get("scores", [])
    )
    rows.extend(f"- {issue}" for issue in verdict["issues"])
    rows.extend(
        ["", "Scope: frozen read-only source fixtures; no exploitation or website tests.", ""]
    )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "record"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--base-revision", help="protected PR base or push-before commit")
    parser.add_argument("--allow-paid-models", action="store_true")
    args = parser.parse_args(argv)
    output, root = args.output_dir.resolve(), args.repository_root.resolve()
    # A fresh directory prevents retries from mixing old measurements with new verdicts.
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        parser.exit(2, f"use a new output directory: {exc}\n")
    verdict: dict[str, Any]
    try:
        policy = Policy.model_validate(read_json(root / POLICY_PATH))
        baseline = None
        if args.command == "check":
            protect_baseline(root, args.base_revision)
            baseline = Measurement.model_validate(read_json(root / BASELINE_PATH))
            validate_measurement(baseline, root)
            if (
                baseline.policy != policy
                or baseline.evaluator_digest != fingerprint(root, evaluator=True)
                or baseline.runtime != runtime_versions()
            ):
                msg = "frozen policy or scoring implementation changed; do not silently rebaseline"
                raise ValueError(msg)
        elif (root / BASELINE_PATH).exists():
            msg = "record never overwrites an existing baseline"
            raise ValueError(msg)
        current = measure(root, policy, output, allow_paid_models=args.allow_paid_models)
        verdict = decide(current, baseline, root)
        if args.command == "record" and verdict["passed"]:
            write_json(root / BASELINE_PATH, current.model_dump())
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.CalledProcessError,
    ) as exc:
        verdict = {"passed": False, "issues": [f"{type(exc).__name__}: {exc}"], "scores": []}
    write_json(output / "verdict.json", verdict)
    summary = _summary(verdict)
    (output / "summary.md").write_text(summary, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
            stream.write(summary)
    sys.stdout.write(summary)
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
