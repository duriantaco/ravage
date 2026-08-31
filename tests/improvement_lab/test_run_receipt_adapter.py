from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

import tools.improvement_lab.run_receipt_adapter as adapter
from tools.improvement_lab.attestation import generate_referee_keypair
from tools.improvement_lab.evaluation import RunReceipt, canonical_run_receipts_bytes
from tools.improvement_lab.execution_attestation import (
    ExecutionBinding,
    ExternalRunObservations,
    FindingVerdict,
    SignedExecutionEnvelope,
    execution_envelope_digest,
    sign_execution_envelope,
)
from tools.improvement_lab.offline_executor import FrozenOutputTree, freeze_output_tree
from tools.improvement_lab.run_receipt_adapter import (
    RunReceiptAdapterError,
    derive_run_receipt,
    finding_reference_digest,
    write_run_receipt,
)

if TYPE_CHECKING:
    from pathlib import Path

_EXTERNAL_PHYSICAL_REQUESTS = 5
_EXPECTED_ACCOUNTING_MISMATCHES = 3


@dataclass(frozen=True)
class _AttestedRun:
    envelope: SignedExecutionEnvelope
    public_key: bytes


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _artifact_root(
    tmp_path: Path,
    *,
    finding_ids: tuple[str, ...] = ("finding-one",),
    report_requests: int = 7,
    ledger_requests: int = 7,
) -> Path:
    root = tmp_path / "artifacts"
    case = root / "case-one"
    _write_json(
        case / "report.json",
        {
            "captured_proofs": {"count": 0, "masked": []},
            "findings": [
                {"finding_id": finding_id, "status": "confirmed"}
                for finding_id in finding_ids
            ],
            "outcome": {"evidence": []},
            "traffic_accounting": {
                "status": "exact",
                "physical_request_count": report_requests,
                "incomplete_request_count": 0,
                "unmetered_action_count": 0,
            },
        },
    )
    _write_json(
        case / "workspace" / "traffic-policy.json",
        {
            "schema": "ravage.traffic-policy",
            "physical_request_count": ledger_requests,
            "incomplete_request_count": 0,
            "unmetered_action_count": 0,
        },
    )
    return root.resolve()


def _envelope(  # noqa: PLR0913 - test fixture exposes independent signed counters.
    root: Path,
    *,
    verdicts: tuple[tuple[str, str], ...] = (),
    physical_requests: int | None = 7,
    case_success: bool | None = None,
    proof_integrity_failures: int = 0,
    accounting_mismatches: int = 0,
) -> _AttestedRun:
    frozen = freeze_output_tree(root)
    binding = ExecutionBinding(
        campaign_id=f"campaign_{'a' * 24}",
        candidate_id=f"candidate_{'b' * 24}",
        candidate_tree_digest="c" * 40,
        candidate_content_digest=_digest("1"),
        evaluation_suite_object=_digest("2"),
        trusted_tests_digest=_digest("3"),
        runner_image=f"example.invalid/referee@{_digest('4')}",
        job_spec_digest=_digest("5"),
        artifact_tree_digest=frozen.digest,
        artifact_case_path="case-one",
        case_id="case-one",
        cohort="development",
        repeat=1,
        execution_kind="fixture",
        evaluation_side="candidate",
        is_control=False,
        expected_vulnerability_count=None,
        run_id=_digest("6"),
        pair_seed_digest=_digest("7"),
        target_snapshot_digest=_digest("8"),
        model_fingerprint=_digest("9"),
        prompt_fingerprint=_digest("a"),
    )
    observations = ExternalRunObservations(
        status="completed",
        case_success=case_success,
        physical_request_count=physical_requests,
        model_request_count=2,
        cost_usd=0.25,
        request_accounting_status="exact",
        proof_integrity_failure_count=proof_integrity_failures,
        false_proof_count=0,
        request_accounting_mismatch_count=accounting_mismatches,
        loop_violation_count=0,
        provenance_violation_count=0,
        secret_leak_violation_count=0,
        unmetered_action_count=0,
        incomplete_request_count=0,
    )
    finding_verdicts = tuple(
        sorted(
            (
                FindingVerdict(
                    finding_reference_digest(finding_id),
                    stage,
                )
                for finding_id, stage in verdicts
            ),
            key=lambda item: item.finding_digest,
        )
    )
    private_key, public_key = generate_referee_keypair()
    return _AttestedRun(
        envelope=sign_execution_envelope(
            binding,
            observations,
            finding_verdicts,
            private_key=private_key,
        ),
        public_key=public_key,
    )


def _derive(root: Path, attested: _AttestedRun) -> RunReceipt:
    return derive_run_receipt(
        root,
        envelope=attested.envelope,
        executor_public_key=attested.public_key,
    )


def test_no_flag_confirmed_vulnerability_still_counts(tmp_path: Path) -> None:
    root = _artifact_root(tmp_path)
    envelope = _envelope(
        root,
        verdicts=(("finding-one", "confirmed_finding"),),
        case_success=None,
    )

    receipt = _derive(root, envelope)

    assert receipt.case_success is None
    assert receipt.evidence_backed_vulnerability_count == 1
    assert receipt.verified_vulnerability_count == 1
    assert receipt.confirmed_finding_count == 1
    assert receipt.proof_integrity_failure_count == 0
    assert receipt.execution_attestation_digest == execution_envelope_digest(
        envelope.envelope
    )
    assert receipt == envelope.envelope.to_run_receipt()


def test_self_reported_confirmed_finding_does_not_count_without_signed_verdict(
    tmp_path: Path,
) -> None:
    root = _artifact_root(tmp_path)

    receipt = _derive(root, _envelope(root, proof_integrity_failures=1))

    assert receipt.evidence_backed_vulnerability_count == 0
    assert receipt.verified_vulnerability_count == 0
    assert receipt.confirmed_finding_count == 0
    assert receipt.proof_integrity_failure_count == 1


def test_unaccounted_self_reported_confirmation_is_rejected(tmp_path: Path) -> None:
    root = _artifact_root(tmp_path)

    with pytest.raises(RunReceiptAdapterError, match="proof-integrity failures"):
        _derive(root, _envelope(root))


def test_unknown_signed_finding_verdict_is_rejected(tmp_path: Path) -> None:
    root = _artifact_root(tmp_path)
    envelope = _envelope(
        root,
        verdicts=(("not-in-the-report", "confirmed_finding"),),
    )

    with pytest.raises(RunReceiptAdapterError, match="does not match"):
        _derive(root, envelope)


def test_unverified_envelope_or_wrong_executor_key_is_rejected(tmp_path: Path) -> None:
    root = _artifact_root(tmp_path)
    attested = _envelope(root)
    _unused_private, wrong_public = generate_referee_keypair()

    with pytest.raises(RunReceiptAdapterError, match="envelope is invalid"):
        derive_run_receipt(
            root,
            envelope=attested.envelope,
            executor_public_key=wrong_public,
        )


def test_traffic_report_and_external_count_mismatches_are_counted(
    tmp_path: Path,
) -> None:
    root = _artifact_root(
        tmp_path,
        finding_ids=(),
        report_requests=4,
        ledger_requests=3,
    )

    receipt = _derive(
        root,
        _envelope(
            root,
            physical_requests=_EXTERNAL_PHYSICAL_REQUESTS,
            accounting_mismatches=_EXPECTED_ACCOUNTING_MISMATCHES,
        ),
    )

    assert receipt.physical_request_count == _EXTERNAL_PHYSICAL_REQUESTS
    assert receipt.request_accounting_mismatch_count == _EXPECTED_ACCOUNTING_MISMATCHES


def test_unaccounted_traffic_mismatches_are_rejected(tmp_path: Path) -> None:
    root = _artifact_root(
        tmp_path,
        finding_ids=(),
        report_requests=4,
        ledger_requests=3,
    )

    with pytest.raises(RunReceiptAdapterError, match="request-accounting mismatches"):
        _derive(root, _envelope(root, physical_requests=_EXTERNAL_PHYSICAL_REQUESTS))


def test_artifact_tampering_after_signature_is_rejected(tmp_path: Path) -> None:
    root = _artifact_root(tmp_path)
    envelope = _envelope(root)
    report_path = root / "case-one" / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["findings"] = []
    _write_json(report_path, report)

    with pytest.raises(RunReceiptAdapterError, match="differs from the signed execution"):
        _derive(root, envelope)


def test_artifact_mutation_during_derivation_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _artifact_root(tmp_path)
    attested = _envelope(root, proof_integrity_failures=1)
    original_freeze = freeze_output_tree
    freeze_calls = 0

    def mutating_freeze(path: Path) -> FrozenOutputTree:
        nonlocal freeze_calls
        frozen = original_freeze(path)
        freeze_calls += 1
        if freeze_calls == 1:
            report_path = root / "case-one" / "report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["candidate_changed_after_freeze"] = True
            _write_json(report_path, report)
        return frozen

    monkeypatch.setattr(adapter, "freeze_output_tree", mutating_freeze)

    with pytest.raises(RunReceiptAdapterError, match="changed while deriving"):
        _derive(root, attested)


def test_canonical_receipt_write_is_deterministic_private_and_non_overwriting(
    tmp_path: Path,
) -> None:
    root = _artifact_root(tmp_path)
    receipt = _derive(root, _envelope(root, proof_integrity_failures=1))
    first = tmp_path / "receipts-a" / "receipt.json"
    second = tmp_path / "receipts-b" / "receipt.json"

    write_run_receipt(first, receipt)
    write_run_receipt(second, receipt)

    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes() == canonical_run_receipts_bytes((receipt,))
    assert first.stat().st_mode & 0o077 == 0
    with pytest.raises(RunReceiptAdapterError, match="overwrite"):
        write_run_receipt(first, receipt)


@pytest.mark.parametrize(
    "report_text",
    [
        (
            '{"findings":[],"findings":[],"outcome":{"evidence":[]},'
            '"traffic_accounting":{}}'
        ),
        (
            '{"findings":[],"outcome":{"evidence":[]},'
            '"traffic_accounting":{},"not_a_number":NaN}'
        ),
    ],
    ids=("duplicate-key", "non-finite"),
)
def test_duplicate_and_non_finite_artifact_json_is_rejected(
    tmp_path: Path,
    report_text: str,
) -> None:
    root = _artifact_root(tmp_path, finding_ids=())
    (root / "case-one" / "report.json").write_text(report_text, encoding="utf-8")
    envelope = _envelope(root)

    with pytest.raises(RunReceiptAdapterError, match="invalid JSON"):
        _derive(root, envelope)
