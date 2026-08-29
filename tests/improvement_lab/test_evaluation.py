# Repeated-run fixtures intentionally assert the exact small gate counts.
# ruff: noqa: PLR2004

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab.evaluation import (
    EVALUATION_SCHEMA_VERSION,
    EvaluationConfig,
    RunReceipt,
    canonical_run_receipts_bytes,
    evaluate_candidate,
    evaluation_suite_from_receipts,
    load_canonical_run_receipts,
    load_evaluation_receipt,
    load_run_receipts,
    write_evaluation_receipt,
)

if TYPE_CHECKING:
    from pathlib import Path


def _receipt(  # noqa: PLR0913 - the receipt fixture mirrors the public schema.
    case_id: str,
    repeat: int,
    *,
    cohort: str,
    control: bool,
    side: str,
    execution_kind: str = "live",
    evidence: int = 0,
    verified: int | None = None,
    confirmed: int | None = None,
    suspected: int = 0,
    success: bool = False,
    status: str = "completed",
    physical_requests: int = 10,
    model_requests: int = 2,
    cost_usd: float | None = 1.0,
    expected: int | None = 1,
) -> dict[str, object]:
    def digest(value: str) -> str:
        return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"

    return {
        "schema_version": "test.aggregate-run.v1",
        "case_id": case_id,
        "cohort": cohort,
        "repeat": repeat,
        "execution_kind": execution_kind,
        "status": status,
        "is_control": control,
        "case_success": success,
        "expected_vulnerability_count": expected,
        "run_id": digest(f"run:{side}:{case_id}:{repeat}"),
        "pair_seed_digest": digest(f"seed:{case_id}:{repeat}"),
        "target_snapshot_digest": digest(f"target:{case_id}:{repeat}"),
        "model_fingerprint": digest("model:fixed"),
        "prompt_fingerprint": digest(f"prompt:{side}"),
        "metrics": {
            "evidence_backed_vulnerability_count": evidence,
            "verified_vulnerability_count": evidence if verified is None else verified,
            "confirmed_finding_count": evidence if confirmed is None else confirmed,
            "suspected_vulnerability_count": suspected,
            "proof_integrity_failure_count": 0,
            "false_proof_count": 0,
            "request_accounting_mismatch_count": 0,
            "loop_violation_count": 0,
            "provenance_violation_count": 0,
            "secret_leak_violation_count": 0,
            "unmetered_action_count": 0,
            "incomplete_request_count": 0,
            "physical_request_count": physical_requests,
            "model_request_count": model_requests,
            "cost_usd": cost_usd,
            "request_accounting_status": "exact",
        },
    }


def _passing_panel() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    champion: list[dict[str, object]] = []
    candidate: list[dict[str, object]] = []
    for repeat in range(1, 4):
        champion.append(
            _receipt(
                "capability-case",
                repeat,
                cohort="development_failure",
                control=False,
                side="champion",
            )
        )
        candidate.append(
            _receipt(
                "capability-case",
                repeat,
                cohort="development_failure",
                control=False,
                side="candidate",
                evidence=1 if repeat <= 2 else 0,
                success=repeat <= 2,
            )
        )
        champion.append(
            _receipt(
                "control-case",
                repeat,
                cohort="development_control",
                control=True,
                side="champion",
                evidence=1,
                success=True,
            )
        )
        candidate.append(
            _receipt(
                "control-case",
                repeat,
                cohort="development_control",
                control=True,
                side="candidate",
                evidence=1,
                success=True,
            )
        )
    return champion, candidate


def _codes(receipt: object) -> set[str]:
    return {item.code for item in receipt.rejections}  # type: ignore[attr-defined]


def _candidate_item(
    candidate: list[dict[str, object]],
    *,
    case_id: str,
    repeat: int,
) -> dict[str, object]:
    return next(
        item for item in candidate if item["case_id"] == case_id and item["repeat"] == repeat
    )


def _metrics(item: dict[str, object]) -> dict[str, object]:
    metrics = item["metrics"]
    assert isinstance(metrics, dict)
    return metrics


def test_repeated_evidence_backed_improvement_promotes() -> None:
    champion, candidate = _passing_panel()

    receipt = evaluate_candidate(champion, candidate)
    payload = receipt.to_json()

    assert receipt.accepted is True
    assert receipt.decision == "promote"
    assert receipt.rejections == ()
    assert payload["schema_version"] == EVALUATION_SCHEMA_VERSION
    receipt_digest = payload["receipt_digest"]
    assert isinstance(receipt_digest, str)
    assert receipt_digest.startswith("sha256:")
    assert receipt.stability["stable_improved_cases"] == 1
    assert receipt.stability["wins"] == 2
    promotable = receipt.aggregate["promotable_receipts"]
    assert isinstance(promotable, dict)
    delta = promotable["delta"]
    assert isinstance(delta, dict)
    assert delta["evidence_backed_vulnerability_count"] == 2.0


def test_missing_safety_metric_fails_closed() -> None:
    champion, candidate = _passing_panel()
    del _metrics(candidate[0])["secret_leak_violation_count"]

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "invalid_run_receipt" in _codes(receipt)
    invalid = next(item for item in receipt.rejections if item.code == "invalid_run_receipt")
    assert "secret_leak_violation_count" in str(invalid.details["reason"])


def test_historical_replay_alone_is_never_promotable() -> None:
    champion, candidate = _passing_panel()
    for item in (*champion, *candidate):
        item["execution_kind"] = "historical_replay"

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "historical_replay_only" in _codes(receipt)
    assert receipt.matching["promotable_pairs"] == 0
    assert receipt.matching["historical_replay_pairs"] == 6


def test_unmatched_matrix_and_insufficient_repeats_are_explained() -> None:
    champion, candidate = _passing_panel()
    champion = champion[:4]
    candidate = candidate[:3]

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert {"unmatched_run_receipts", "insufficient_repeats"} <= _codes(receipt)


def test_every_safety_and_proof_violation_is_a_hard_rejection() -> None:
    champion, candidate = _passing_panel()
    metrics = _metrics(_candidate_item(candidate, case_id="capability-case", repeat=1))
    for name in (
        "proof_integrity_failure_count",
        "false_proof_count",
        "request_accounting_mismatch_count",
        "loop_violation_count",
        "provenance_violation_count",
        "secret_leak_violation_count",
    ):
        metrics[name] = 1

    receipt = evaluate_candidate(champion, candidate)

    assert {
        "candidate_proof_integrity_failure",
        "candidate_false_proof",
        "candidate_request_accounting_mismatch",
        "candidate_loop_violation",
        "candidate_provenance_violation",
        "candidate_secret_leak_violation",
    } <= _codes(receipt)


def test_request_accounting_cannot_be_weakened() -> None:
    champion, candidate = _passing_panel()
    metrics = _metrics(_candidate_item(candidate, case_id="capability-case", repeat=1))
    metrics["request_accounting_status"] = "lower_bound"
    metrics["unmetered_action_count"] = 1
    metrics["incomplete_request_count"] = 1

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "request_accounting_regression" in _codes(receipt)


def test_any_matched_control_detection_loss_rejects() -> None:
    champion, candidate = _passing_panel()
    item = _candidate_item(candidate, case_id="control-case", repeat=2)
    metrics = _metrics(item)
    metrics["evidence_backed_vulnerability_count"] = 0
    metrics["verified_vulnerability_count"] = 0
    metrics["confirmed_finding_count"] = 0
    item["case_success"] = False

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "control_regression" in _codes(receipt)


def test_suspected_only_growth_is_reported_but_never_rewarded() -> None:
    champion, candidate = _passing_panel()
    for item in candidate:
        if item["case_id"] != "capability-case":
            continue
        metrics = _metrics(item)
        metrics["evidence_backed_vulnerability_count"] = 0
        metrics["verified_vulnerability_count"] = 0
        metrics["confirmed_finding_count"] = 0
        metrics["suspected_vulnerability_count"] = 1
        item["case_success"] = False

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "no_stable_detection_improvement" in _codes(receipt)
    assert "aggregate_detection_did_not_improve" in _codes(receipt)
    promotable = receipt.aggregate["promotable_receipts"]
    assert isinstance(promotable, dict)
    candidate_aggregate = promotable["candidate"]
    assert isinstance(candidate_aggregate, dict)
    assert candidate_aggregate["suspected_vulnerability_count"] == 3


def test_known_clean_control_false_positive_is_rejected() -> None:
    champion, candidate = _passing_panel()
    for panel, count in ((champion, 0), (candidate, 1)):
        for item in panel:
            if item["case_id"] != "control-case":
                continue
            item["expected_vulnerability_count"] = 0
            metrics = _metrics(item)
            metrics["evidence_backed_vulnerability_count"] = count
            metrics["verified_vulnerability_count"] = count
            metrics["confirmed_finding_count"] = count

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert {
        "clean_control_false_positive",
        "finding_count_exceeds_ground_truth",
    } <= _codes(receipt)


def test_ctf_success_without_vulnerability_gain_cannot_promote() -> None:
    champion, candidate = _passing_panel()
    for item in candidate:
        if item["case_id"] != "capability-case":
            continue
        metrics = _metrics(item)
        metrics["evidence_backed_vulnerability_count"] = 0
        metrics["verified_vulnerability_count"] = 0
        metrics["confirmed_finding_count"] = 0
        item["case_success"] = item["repeat"] in {1, 2}

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert {
        "no_stable_detection_improvement",
        "aggregate_detection_did_not_improve",
    } <= _codes(receipt)
    assert "case_successes" not in receipt.stability["detection_delta"]


def test_case_success_is_a_non_regression_signal_not_utility() -> None:
    champion, candidate = _passing_panel()
    for item in champion:
        if item["case_id"] == "capability-case":
            item["case_success"] = True

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "case_outcome_regression" in _codes(receipt)


def test_explicit_null_case_success_is_valid_for_no_flag_capability_case() -> None:
    champion, _candidate = _passing_panel()
    item = _candidate_item(champion, case_id="capability-case", repeat=1)
    item["case_success"] = None

    parsed = RunReceipt.from_mapping(item)

    assert parsed.case_success is None


def test_one_lucky_win_does_not_satisfy_repeat_stability() -> None:
    champion, candidate = _passing_panel()
    item = _candidate_item(candidate, case_id="capability-case", repeat=2)
    metrics = _metrics(item)
    metrics["evidence_backed_vulnerability_count"] = 0
    metrics["verified_vulnerability_count"] = 0
    metrics["confirmed_finding_count"] = 0
    item["case_success"] = False

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "no_stable_detection_improvement" in _codes(receipt)


def test_repeat_labels_cannot_reuse_execution_or_seed_attestations() -> None:
    champion, candidate = _passing_panel()
    first = _candidate_item(candidate, case_id="capability-case", repeat=1)
    second = _candidate_item(candidate, case_id="capability-case", repeat=2)
    second["run_id"] = first["run_id"]
    second["pair_seed_digest"] = first["pair_seed_digest"]

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert "duplicate_execution_attestation" in _codes(receipt)


def test_matched_runs_require_same_seed_snapshot_and_distinct_sessions() -> None:
    champion, candidate = _passing_panel()
    champion_item = _candidate_item(champion, case_id="capability-case", repeat=1)
    candidate_item = _candidate_item(candidate, case_id="capability-case", repeat=1)
    candidate_item["pair_seed_digest"] = "sha256:" + "a" * 64
    candidate_item["target_snapshot_digest"] = "sha256:" + "b" * 64
    candidate_item["run_id"] = champion_item["run_id"]

    receipt = evaluate_candidate(champion, candidate)

    assert receipt.accepted is False
    assert {"paired_execution_mismatch", "execution_session_reused"} <= _codes(receipt)


def test_timeout_and_error_are_explicit_reliability_rejections() -> None:
    champion, candidate = _passing_panel()
    _candidate_item(candidate, case_id="capability-case", repeat=1)["status"] = "timeout"
    _candidate_item(candidate, case_id="capability-case", repeat=2)["status"] = "error"

    receipt = evaluate_candidate(champion, candidate)

    assert {"candidate_timeout", "candidate_error"} <= _codes(receipt)


def test_efficiency_regressions_and_missing_cost_are_rejected() -> None:
    champion, candidate = _passing_panel()
    for item in candidate:
        metrics = _metrics(item)
        metrics["physical_request_count"] = 100
        metrics["model_request_count"] = 50
        metrics["cost_usd"] = 20.0

    regressed = evaluate_candidate(champion, candidate)

    assert {
        "physical_request_efficiency_regression",
        "model_request_efficiency_regression",
        "cost_efficiency_regression",
    } <= _codes(regressed)

    champion, candidate = _passing_panel()
    _metrics(candidate[0])["cost_usd"] = None
    missing = evaluate_candidate(champion, candidate)
    assert "efficiency_metric_missing" in _codes(missing)


def test_receipt_write_load_and_digest_validation(tmp_path: Path) -> None:
    champion, candidate = _passing_panel()
    candidate[0]["raw_flag"] = "this field must never enter the referee receipt"
    receipt = evaluate_candidate(champion, candidate)
    path = tmp_path / "evaluation.json"

    write_evaluation_receipt(path, receipt)
    loaded = load_evaluation_receipt(path)

    assert loaded.to_json() == receipt.to_json()
    assert path.read_text(encoding="utf-8") == receipt.canonical_json() + "\n"
    assert "raw_flag" not in path.read_text(encoding="utf-8")

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["accepted"] = False
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        load_evaluation_receipt(path)


def test_run_receipt_loader_uses_the_same_fail_closed_schema(tmp_path: Path) -> None:
    valid = _receipt(
        "fixture-case",
        1,
        cohort="fixture_control",
        control=True,
        side="champion",
        execution_kind="fixture",
        success=True,
    )
    path = tmp_path / "receipts.json"
    path.write_text(json.dumps({"receipts": [valid]}), encoding="utf-8")

    loaded = load_run_receipts(path)
    assert len(loaded) == 1
    assert loaded[0].execution_kind == "fixture"

    del _metrics(valid)["request_accounting_mismatch_count"]
    path.write_text(json.dumps([valid]), encoding="utf-8")
    with pytest.raises(ValueError, match="request_accounting_mismatch_count"):
        load_run_receipts(path)


def test_campaign_suite_rejects_a_favorable_subset() -> None:
    champion, candidate = _passing_panel()
    parsed_champion = tuple(RunReceipt.from_mapping(item) for item in champion)
    suite = evaluation_suite_from_receipts(
        parsed_champion,
        trusted_tests_digest=f"sha256:{'a' * 64}",
        runner_command=("/usr/local/bin/python", "-I", "/trusted-tests/trusted_referee.py"),
    )
    champion = [
        item for item in champion if not (item["case_id"] == "control-case" and item["repeat"] == 3)
    ]
    candidate = [
        item
        for item in candidate
        if not (item["case_id"] == "control-case" and item["repeat"] == 3)
    ]

    receipt = evaluate_candidate(champion, candidate, suite=suite)

    assert "evaluation_suite_matrix_mismatch" in _codes(receipt)


def test_campaign_suite_rejects_a_path_resolved_runner() -> None:
    champion, _candidate = _passing_panel()
    parsed_champion = tuple(RunReceipt.from_mapping(item) for item in champion)

    with pytest.raises(ValueError, match="runner executable must be absolute"):
        evaluation_suite_from_receipts(
            parsed_champion,
            trusted_tests_digest=f"sha256:{'a' * 64}",
            runner_command=("python", "-I", "/trusted-tests/trusted_referee.py"),
        )


def test_retained_receipt_set_is_byte_canonical_and_replayable() -> None:
    champion, _candidate = _passing_panel()
    parsed = tuple(RunReceipt.from_mapping(item) for item in champion)
    encoded = canonical_run_receipts_bytes(parsed)

    assert load_canonical_run_receipts(encoded) == tuple(
        sorted(parsed, key=lambda item: (item.key, item.run_id))
    )
    with pytest.raises(ValueError, match="byte-canonical"):
        load_canonical_run_receipts(encoded + b"\n")


def test_config_enforces_three_or_more_repeats() -> None:
    with pytest.raises(ValueError, match="at least three repeats"):
        EvaluationConfig(min_repeats=2)
