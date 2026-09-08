"""Deliberately degraded measurements must never pass as quality improvements."""

# Synthetic score mutations test gate behavior; they are not model measurements.
# ruff: noqa: PLR2004

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, Literal, cast

import pytest
from pydantic import ValidationError

from tools.review_quality_gate.gate import (
    ARMS,
    POLICY_PATH,
    ROOT,
    Measurement,
    Policy,
    Sample,
    cases_for,
    decide,
    read_json,
    runtime_versions,
    write_json,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def baseline() -> Measurement:
    policy = Policy.model_validate(read_json(ROOT / POLICY_PATH))
    samples = [
        Sample(
            case_id=case.case_id,
            arm=cast("Literal['literal_only', 'candidate_assisted']", arm),
            repeat=repeat,
            hits=[item.vulnerability_id for item in case.expected],
            false_positives=0,
            unscored_findings=0,
            model_calls=3,
            input_tokens=1000,
            output_tokens=1000,
            cost_usd=0.02,
        )
        for case in cases_for(policy, ROOT).values()
        for arm in ARMS
        for repeat in range(1, policy.repeats + 1)
    ]
    return Measurement(
        schema_version="ravage.repository-review-quality.v1",
        policy=policy,
        revision="a" * 40,
        engine_digest="sha256:" + "b" * 64,
        evaluator_digest="sha256:" + "c" * 64,
        raw_report_digest="sha256:" + "d" * 64,
        measured_at="2026-09-08T00:00:00+00:00",
        elapsed_seconds=1.0,
        verified_model_calls=sum(row.model_calls for row in samples),
        runtime=runtime_versions(),
        samples=samples,
    )


def test_identical_observations_pass(baseline: Measurement) -> None:
    result = decide(baseline, baseline, ROOT)
    assert result["passed"]
    assert result["case_count"] == 10
    assert result["sample_count"] == 60


def test_one_miss_fails_even_above_the_aggregate_recall_floor(baseline: Measurement) -> None:
    current = deepcopy(baseline)
    current.samples[0].hits.clear()
    result = decide(current, baseline, ROOT)
    assert not result["passed"]
    assert result["scores"][0]["recall"] > baseline.policy.min_recall
    assert any("fewer detections" in issue for issue in result["issues"])


def test_improvement_elsewhere_cannot_hide_a_lost_finding(baseline: Measurement) -> None:
    old = deepcopy(baseline)
    old.samples[12].hits.clear()
    current = deepcopy(baseline)
    current.samples[0].hits.clear()
    result = decide(current, old, ROOT)
    assert not result["passed"]
    assert sum(len(row.hits) for row in current.samples) == sum(
        len(row.hits) for row in old.samples
    )


@pytest.mark.parametrize("field", ["false_positives", "unscored_findings"])
def test_new_findings_on_a_negative_fixture_fail(baseline: Measurement, field: str) -> None:
    current = deepcopy(baseline)
    row = next(row for row in current.samples if row.case_id == "boreal")
    setattr(row, field, 1)
    assert not decide(current, baseline, ROOT)["passed"]


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra_arm", "wrong_repeat"])
def test_incomplete_or_replayed_samples_fail(baseline: Measurement, mutation: str) -> None:
    current = deepcopy(baseline)
    if mutation == "missing":
        current.samples.pop()
    elif mutation == "duplicate":
        current.samples[-1] = deepcopy(current.samples[0])
    elif mutation == "extra_arm":
        current.samples[-1].arm = "unknown"  # type: ignore[assignment]
    else:
        current.samples[-1].repeat = 4
    with pytest.raises(ValueError, match="missing, duplicate, or unexpected"):
        decide(current, baseline, ROOT)


@pytest.mark.parametrize("field", ["evaluator_digest", "runtime", "policy"])
def test_different_scoring_or_settings_cannot_be_compared(
    baseline: Measurement, field: str
) -> None:
    current = deepcopy(baseline)
    if field == "evaluator_digest":
        current.evaluator_digest = "sha256:" + "e" * 64
    elif field == "runtime":
        current.runtime["python"] = "3.12.99"
    else:
        current.policy.max_turns += 1
    with pytest.raises(ValueError, match="changed from the baseline"):
        decide(current, baseline, ROOT)


def test_zero_finding_engine_cannot_be_frozen_as_a_good_baseline(baseline: Measurement) -> None:
    for row in baseline.samples:
        row.hits.clear()
    result = decide(baseline, None, ROOT)
    assert not result["passed"]
    assert all(score["recall"] == 0 for score in result["scores"])


@pytest.mark.parametrize("field", ["model_calls", "output_tokens"])
def test_efficiency_regression_fails(baseline: Measurement, field: str) -> None:
    current = deepcopy(baseline)
    for row in current.samples:
        setattr(row, field, getattr(row, field) * 3)
    current.verified_model_calls = sum(row.model_calls for row in current.samples)
    assert not decide(current, baseline, ROOT)["passed"]


def test_cheaper_cache_hits_do_not_hide_more_token_work(baseline: Measurement) -> None:
    current = deepcopy(baseline)
    for row in current.samples:
        row.output_tokens *= 4
        row.cost_usd /= 2
    assert not decide(current, baseline, ROOT)["passed"]


def test_every_call_requires_verified_usage(baseline: Measurement) -> None:
    current = deepcopy(baseline)
    current.verified_model_calls -= 1
    with pytest.raises(ValueError, match="every model call"):
        decide(current, baseline, ROOT)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1, True])
def test_invalid_counts_and_costs_are_rejected(baseline: Measurement, bad: float) -> None:
    payload = baseline.model_dump()
    payload["samples"][0]["cost_usd"] = bad
    with pytest.raises(ValidationError):
        Measurement.model_validate(payload)


def test_missing_baseline_and_duplicate_json_keys_fail(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_json(tmp_path / "missing.json")
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"passed": false, "passed": true}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        read_json(duplicate)


def test_evidence_files_are_never_silently_replaced(tmp_path: Path) -> None:
    output = tmp_path / "verdict.json"
    write_json(output, {"passed": False})
    with pytest.raises(FileExistsError):
        write_json(output, {"passed": True})
    assert read_json(output) == {"passed": False}
