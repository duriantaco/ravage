"""Frozen measurements and per-finding regression decisions for read-only review."""

# Gate diagnostics intentionally name the contract that failed.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import subprocess
from collections import Counter, defaultdict
from importlib.metadata import version
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field
from ravage.repository_review_eval import score_repository_review
from ravage.repository_review_eval_runner import load_repository_review_eval_manifest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "packages/ravage/tests/repository_review_eval_manifest.json"
POLICY_PATH = "benchmarks/repository-review/policy.json"
BASELINE_PATH = "benchmarks/repository-review/baseline.json"
ARMS = ("literal_only", "candidate_assisted")
SCHEMA: Final = "ravage.repository-review-quality.v1"
MAX_JSON_BYTES = 10_000_000


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Policy(StrictModel):
    schema_version: Literal["ravage.repository-review-quality-policy.v1"]
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    model: Literal["gpt-5.4-2026-03-05"]
    reasoning_effort: Literal["high"]
    repeats: int = Field(ge=3, le=10)
    max_turns: int = Field(ge=1, le=24)
    max_output_tokens: int = Field(ge=256, le=8192)
    max_cost_per_run_usd: float = Field(gt=0, le=1)
    max_cost_usd: float = Field(gt=0, le=10)
    input_price: float = Field(gt=0)
    output_price: float = Field(gt=0)
    min_precision: float = Field(ge=0.9, le=1)
    min_recall: float = Field(ge=0.8, le=1)
    max_effort_ratio: float = Field(ge=1, le=2)


class Sample(StrictModel):
    case_id: str
    arm: Literal["literal_only", "candidate_assisted"]
    repeat: int = Field(ge=1)
    hits: list[str]
    false_positives: int = Field(ge=0)
    unscored_findings: int = Field(ge=0)
    model_calls: int = Field(ge=1)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_usd: float = Field(ge=0)


class Measurement(StrictModel):
    schema_version: Literal["ravage.repository-review-quality.v1"]
    policy: Policy
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    engine_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evaluator_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    raw_report_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    measured_at: str
    elapsed_seconds: float = Field(ge=0)
    verified_model_calls: int = Field(ge=1)
    runtime: dict[str, str]
    samples: list[Sample]


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("quality-gate JSON exceeds the size limit")
    result = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    if not isinstance(result, dict):
        raise TypeError("quality-gate input must be a JSON object")
    return result


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents a check or failed retry from replacing evidence.
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(  # noqa: S603 - fixed argv; never a shell.
        ["git", "-C", str(root), *args],  # noqa: S607 - developer Git installation.
        stderr=subprocess.PIPE,
    )


def revision(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD").decode().strip()


def runtime_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        **{
            name: version(name)
            for name in ("pydantic", "pathspec", "PyYAML", "cryptography", "rich")
        },
    }


def fingerprint(root: Path, *, evaluator: bool) -> str:
    if evaluator:
        paths = [
            *sorted((root / "tools/review_quality_gate").glob("*.py")),
            root / "scripts/eval/run_review_quality_gate.py",
            root / "packages/ravage/src/ravage/repository_review_eval.py",
            root / "packages/ravage/src/ravage/repository_review_eval_runner.py",
        ]
    else:
        paths = sorted((root / "packages/ravage/src").rglob("*.py"))
        paths += sorted((root / "packages/schemas/src").rglob("*.py"))
    return digest(
        b"".join(
            str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0"
            for path in paths
        )
    )


def protect_baseline(root: Path, base_revision: str | None) -> None:
    """Reject ordinary changes to a baseline/policy already present on the base."""
    if not base_revision:
        return
    if not re.fullmatch(r"[0-9a-f]{40}", base_revision) or set(base_revision) == {"0"}:
        raise ValueError("base revision must be an existing full Git commit SHA")
    _git(root, "cat-file", "-e", f"{base_revision}^{{commit}}")
    for relative in (POLICY_PATH, BASELINE_PATH):
        entry = _git(root, "ls-tree", base_revision, "--", relative)
        if not entry:
            continue  # Initial installation; later checks must retain these exact bytes.
        original = _git(root, "show", f"{base_revision}:{relative}")
        if not (root / relative).is_file() or (root / relative).read_bytes() != original:
            raise ValueError(
                f"frozen {relative} changed; baseline maintenance needs separate review"
            )


def cases_for(policy: Policy, root: Path) -> dict[str, Any]:
    if digest((root / MANIFEST).read_bytes()) != policy.manifest_digest:
        raise ValueError("labelled corpus changed; a frozen baseline cannot score different cases")
    manifest = load_repository_review_eval_manifest(root / MANIFEST)
    return {case.case_id: case for case in manifest.cases}


def extract_samples(  # noqa: C901 - explicit report-integrity checks.
    report: dict[str, Any], policy: Policy, root: Path
) -> list[Sample]:
    """Recompute scores from review evidence instead of trusting aggregate scores."""
    cases = cases_for(policy, root)
    expected_config = {
        "arms": list(ARMS),
        "repeats": policy.repeats,
        "max_turns": policy.max_turns,
        "max_cost_usd_per_run": policy.max_cost_per_run_usd,
        "aggregate_cost_ceiling_usd": policy.max_cost_usd,
        "allow_paid_models": True,
    }
    if any(report["configuration"].get(key) != value for key, value in expected_config.items()):
        raise ValueError("evaluation settings do not match the frozen policy")
    for key, value in {
        "provider": "openai",
        "model": policy.model,
        "reasoning_effort": policy.reasoning_effort,
        "max_output_tokens": policy.max_output_tokens,
    }.items():
        if report["route"].get(key) != value:
            raise ValueError("evaluation model settings changed")
    if report["budget"]["exhausted"]:
        raise ValueError("evaluation exhausted its aggregate budget")
    if report["failures"]:
        failed = ", ".join(
            f"{row['case_id']}/{row['arm']} repeat {row['repeat']} ({row['type']})"
            for row in report["failures"]
        )
        raise ValueError(f"incomplete reviews: {failed}")
    samples = []
    for row in report["runs"]:
        if row["completed"] is not True or row["failure"] is not None:
            raise ValueError("every planned review must finish with a valid final action")
        case = cases[row["case_id"]]
        review, model = row["review"], row["model"]
        if review["snapshot_id"] != case.snapshot_id:
            raise ValueError("review does not match its labelled source snapshot")
        if model["cost_known"] is not True or model["requests"] != model["replies"]:
            raise ValueError("model usage accounting is incomplete")
        if model["invalid_replies"] or model["unknown_cost_replies"]:
            raise ValueError("invalid or unaccounted model replies")
        score = score_repository_review(case, review)
        if score.to_json() != row["score"]:
            raise ValueError(
                "stored detection counts disagree with independently recomputed scores"
            )
        samples.append(
            Sample(
                case_id=case.case_id,
                arm=row["arm"],
                repeat=row["repeat"],
                hits=[match.expected_id for match in score.matches],
                false_positives=score.metrics.false_positives,
                unscored_findings=len(score.unscored_finding_indexes),
                model_calls=model["requests"],
                input_tokens=model["input_tokens"],
                output_tokens=model["output_tokens"],
                cost_usd=model["actual_cost_usd"],
            )
        )
    return samples


def validate_measurement(measurement: Measurement, root: Path) -> None:
    policy = measurement.policy
    cases = cases_for(policy, root)
    expected = {
        (case_id, arm, repeat)
        for case_id in cases
        for arm in ARMS
        for repeat in range(1, policy.repeats + 1)
    }
    actual = [(row.case_id, row.arm, row.repeat) for row in measurement.samples]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError(
            "missing, duplicate, or unexpected case/arm/repeat; evaluation is incomplete"
        )
    if sum(row.model_calls for row in measurement.samples) != measurement.verified_model_calls:
        raise ValueError("not every model call has verified identity and usage")
    if sum(row.cost_usd for row in measurement.samples) > policy.max_cost_usd + 1e-6:
        raise ValueError("evaluation exceeded the aggregate cost limit")
    for row in measurement.samples:
        known = {item.vulnerability_id for item in cases[row.case_id].expected}
        if len(row.hits) != len(set(row.hits)) or not set(row.hits) <= known:
            raise ValueError("duplicate or unknown expected finding in a score")
        if row.model_calls > policy.max_turns or row.cost_usd > policy.max_cost_per_run_usd + 1e-6:
            raise ValueError("a review exceeded its frozen turn or cost budget")


def _groups(measurement: Measurement) -> dict[tuple[str, str], list[Sample]]:
    groups: dict[tuple[str, str], list[Sample]] = defaultdict(list)
    for row in measurement.samples:
        groups[row.case_id, row.arm].append(row)
    return groups


def _effort(rows: list[Sample], policy: Policy) -> float:
    # Normalise away cache discounts so warm CI calls cannot fake efficiency gains.
    return (
        sum(
            row.input_tokens * policy.input_price + row.output_tokens * policy.output_price
            for row in rows
        )
        / 1_000_000
    )


def decide(current: Measurement, baseline: Measurement | None, root: Path) -> dict[str, Any]:
    validate_measurement(current, root)
    policy = current.policy
    cases = cases_for(policy, root)
    issues: list[str] = []
    groups = _groups(current)
    totals = []
    for arm in ARMS:
        rows = [row for row in current.samples if row.arm == arm]
        tp = sum(len(row.hits) for row in rows)
        fp = sum(row.false_positives for row in rows)
        expected = sum(len(case.expected) for case in cases.values()) * policy.repeats
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / expected if expected else 1.0
        if precision < policy.min_precision or recall < policy.min_recall:
            issues.append(f"{arm}: below absolute precision/recall floors")
        totals.append(
            {
                "arm": arm,
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": expected - tp,
                "precision": precision,
                "recall": recall,
                "unscored_findings": sum(row.unscored_findings for row in rows),
                "model_calls": sum(row.model_calls for row in rows),
                "actual_cost_usd": round(sum(row.cost_usd for row in rows), 6),
            }
        )
    if baseline is not None:
        validate_measurement(baseline, root)
        if (
            policy != baseline.policy
            or current.evaluator_digest != baseline.evaluator_digest
            or current.runtime != baseline.runtime
        ):
            raise ValueError("policy, scoring implementation, or runtime changed from the baseline")
        for key, old in _groups(baseline).items():
            new = groups[key]
            label = "/".join(key)
            old_hits = Counter(hit for row in old for hit in row.hits)
            new_hits = Counter(hit for row in new for hit in row.hits)
            for finding, count in old_hits.items():
                if new_hits[finding] < count:
                    issues.append(
                        f"{label}: fewer detections of {finding} ({new_hits[finding]}/{count})"
                    )
            issues.extend(
                f"{label}: increased {field}"
                for field in ("false_positives", "unscored_findings")
                if sum(getattr(row, field) for row in new) > sum(getattr(row, field) for row in old)
            )
            if (
                sum(row.model_calls for row in new)
                > math.ceil(sum(row.model_calls for row in old) * policy.max_effort_ratio)
                + policy.repeats
            ):
                issues.append(f"{label}: model-call cost regressed")
            if _effort(new, policy) > max(
                _effort(old, policy) * policy.max_effort_ratio,
                _effort(old, policy) + 0.02 * policy.repeats,
            ):
                issues.append(f"{label}: token cost regressed")
    return {
        "schema_version": "ravage.repository-review-quality-verdict.v1",
        "passed": not issues,
        "issues": issues,
        "scores": totals,
        "baseline_revision": baseline.revision if baseline is not None else None,
        "evaluated_revision": current.revision,
        "case_count": len(cases),
        "sample_count": len(current.samples),
        "claim_limit": (
            "Read-only review on the frozen diagnostic source corpus. Scores cover only "
            "labelled classes; other findings are counted separately. This does not measure "
            "exploitation, external websites, or generalisation to unseen repositories."
        ),
    }
