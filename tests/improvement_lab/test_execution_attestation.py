from __future__ import annotations

import json
import os
import stat
from copy import deepcopy
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab import execution_attestation as module
from tools.improvement_lab.attestation import generate_referee_keypair, referee_key_id
from tools.improvement_lab.evaluation import canonical_json
from tools.improvement_lab.execution_attestation import (
    EXECUTION_ATTESTATION_SCHEMA_VERSION,
    ExecutionAttestationError,
    ExecutionBinding,
    ExternalRunObservations,
    FindingVerdict,
    SignedExecutionEnvelope,
    execution_envelope_digest,
    load_canonical_execution_envelope_bytes,
    load_signed_execution_envelope,
    sign_execution_envelope,
    verify_signed_execution_envelope,
    write_signed_execution_envelope,
)

if TYPE_CHECKING:
    from pathlib import Path

_EXPECTED_EVIDENCE_BACKED = 3
_EXPECTED_VERIFIED = 2
_EXPECTED_PHYSICAL_REQUESTS = 17
_PRIVATE_MODE = 0o600


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _binding() -> ExecutionBinding:
    return ExecutionBinding(
        campaign_id=f"campaign_{'a' * 24}",
        candidate_id=f"candidate_{'b' * 24}",
        candidate_tree_digest="c" * 40,
        candidate_content_digest=_digest("1"),
        evaluation_suite_object=_digest("2"),
        trusted_tests_digest=_digest("3"),
        runner_image=f"example.invalid/evaluator@{_digest('4')}",
        job_spec_digest=_digest("5"),
        artifact_tree_digest=_digest("6"),
        artifact_case_path="cases/capability-1/repeat-1",
        case_id="capability-1",
        cohort="sealed",
        repeat=1,
        execution_kind="live",
        evaluation_side="candidate",
        is_control=False,
        expected_vulnerability_count=3,
        run_id=_digest("7"),
        pair_seed_digest=_digest("8"),
        target_snapshot_digest=_digest("9"),
        model_fingerprint=_digest("a"),
        prompt_fingerprint=_digest("b"),
    )


def _observations() -> ExternalRunObservations:
    return ExternalRunObservations(
        status="completed",
        case_success=None,
        physical_request_count=17,
        model_request_count=4,
        cost_usd=0.125,
        request_accounting_status="exact",
        proof_integrity_failure_count=0,
        false_proof_count=0,
        request_accounting_mismatch_count=0,
        loop_violation_count=0,
        provenance_violation_count=0,
        secret_leak_violation_count=0,
        unmetered_action_count=0,
        incomplete_request_count=0,
    )


def _verdicts() -> tuple[FindingVerdict, ...]:
    return (
        FindingVerdict(_digest("1"), "suspected_vulnerability"),
        FindingVerdict(_digest("2"), "evidence_backed_vulnerability"),
        FindingVerdict(_digest("3"), "verified_vulnerability"),
        FindingVerdict(_digest("4"), "confirmed_finding"),
    )


def _signed() -> tuple[SignedExecutionEnvelope, bytes, bytes]:
    private, public = generate_referee_keypair()
    signed = sign_execution_envelope(
        _binding(),
        _observations(),
        _verdicts(),
        private_key=private,
    )
    return signed, private, public


def test_round_trip_binds_every_identity_and_derives_receipt_metrics() -> None:
    signed, _private, public = _signed()

    verified = verify_signed_execution_envelope(signed.to_json(), public_key=public)
    receipt = verified.to_run_receipt()

    assert verified == signed
    assert verified.signing_key_id == referee_key_id(public)
    assert verified.binding.to_json() == _binding().to_json()
    assert verified.observations.to_json() == _observations().to_json()
    assert verified.finding_verdicts == _verdicts()
    assert receipt.evidence_backed_vulnerability_count == _EXPECTED_EVIDENCE_BACKED
    assert receipt.verified_vulnerability_count == _EXPECTED_VERIFIED
    assert receipt.confirmed_finding_count == 1
    assert receipt.suspected_vulnerability_count == 1
    assert receipt.physical_request_count == _EXPECTED_PHYSICAL_REQUESTS
    assert receipt.run_id == _digest("7")


def test_canonical_envelope_bytes_can_be_verified_without_a_file() -> None:
    signed, _private, public = _signed()
    content = (canonical_json(signed.to_json()) + "\n").encode()

    assert load_canonical_execution_envelope_bytes(content, public_key=public) == signed

    with pytest.raises(ExecutionAttestationError, match="byte-canonical"):
        load_canonical_execution_envelope_bytes(content.rstrip(), public_key=public)


_BINDING_TAMPERS = {
    "campaign_id": f"campaign_{'d' * 24}",
    "candidate_id": f"candidate_{'e' * 24}",
    "candidate_tree_digest": "d" * 40,
    "candidate_content_digest": _digest("c"),
    "evaluation_suite_object": _digest("d"),
    "trusted_tests_digest": _digest("e"),
    "runner_image": f"other.invalid/evaluator@{_digest('f')}",
    "job_spec_digest": _digest("c"),
    "artifact_tree_digest": _digest("d"),
    "artifact_case_path": "cases/other/repeat-1",
    "case_id": "other-case",
    "cohort": "control",
    "repeat": 2,
    "execution_kind": "fixture",
    "evaluation_side": "champion",
    "is_control": True,
    "expected_vulnerability_count": 4,
    "run_id": _digest("c"),
    "pair_seed_digest": _digest("d"),
    "target_snapshot_digest": _digest("e"),
    "model_fingerprint": _digest("f"),
    "prompt_fingerprint": _digest("0"),
}


@pytest.mark.parametrize(("field", "replacement"), _BINDING_TAMPERS.items())
def test_every_execution_binding_substitution_breaks_the_signature(
    field: str,
    replacement: object,
) -> None:
    signed, _private, public = _signed()
    payload = deepcopy(signed.to_json())
    payload["binding"][field] = replacement  # type: ignore[index]

    with pytest.raises(ExecutionAttestationError, match="signature verification"):
        verify_signed_execution_envelope(payload, public_key=public)


_OBSERVATION_TAMPERS = {
    "status": "failed",
    "case_success": True,
    "physical_request_count": 18,
    "model_request_count": 5,
    "cost_usd": 0.25,
    "request_accounting_status": "reported",
    "proof_integrity_failure_count": 1,
    "false_proof_count": 1,
    "request_accounting_mismatch_count": 1,
    "loop_violation_count": 1,
    "provenance_violation_count": 1,
    "secret_leak_violation_count": 1,
    "unmetered_action_count": 1,
    "incomplete_request_count": 1,
}


@pytest.mark.parametrize(("field", "replacement"), _OBSERVATION_TAMPERS.items())
def test_every_external_observation_substitution_breaks_the_signature(
    field: str,
    replacement: object,
) -> None:
    signed, _private, public = _signed()
    payload = deepcopy(signed.to_json())
    payload["observations"][field] = replacement  # type: ignore[index]

    with pytest.raises(ExecutionAttestationError, match="signature verification"):
        verify_signed_execution_envelope(payload, public_key=public)


def test_finding_verdict_substitution_breaks_the_signature() -> None:
    signed, _private, public = _signed()
    payload = deepcopy(signed.to_json())
    payload["finding_verdicts"][1]["stage"] = "verified_vulnerability"  # type: ignore[index]

    with pytest.raises(ExecutionAttestationError, match="signature verification"):
        verify_signed_execution_envelope(payload, public_key=public)


def test_wrong_key_key_id_and_signature_are_rejected() -> None:
    signed, _private, _public = _signed()
    _other_private, other_public = generate_referee_keypair()

    with pytest.raises(ExecutionAttestationError, match="wrong key"):
        verify_signed_execution_envelope(signed.to_json(), public_key=other_public)

    bad_key_id = deepcopy(signed.to_json())
    bad_key_id["signing_key_id"] = _digest("f")
    with pytest.raises(ExecutionAttestationError, match="wrong key"):
        verify_signed_execution_envelope(bad_key_id, public_key=_public)

    bad_signature = deepcopy(signed.to_json())
    bad_signature["signature"] = "0" * 128
    with pytest.raises(ExecutionAttestationError, match="signature verification"):
        verify_signed_execution_envelope(bad_signature, public_key=_public)


@pytest.mark.parametrize("container", ["top", "binding", "observations", "verdict"])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_exact_schemas_reject_missing_or_extra_fields(container: str, operation: str) -> None:
    signed, _private, public = _signed()
    payload = deepcopy(signed.to_json())
    selected: dict[str, object]
    if container == "top":
        selected = payload
    elif container == "verdict":
        selected = payload["finding_verdicts"][0]  # type: ignore[assignment,index]
    else:
        selected = payload[container]  # type: ignore[assignment]
    if operation == "missing":
        selected.pop(next(iter(selected)))
    else:
        selected["unexpected"] = True

    with pytest.raises(ExecutionAttestationError, match=r"fields|schema"):
        verify_signed_execution_envelope(payload, public_key=public)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute",
        "../escape",
        "case/../escape",
        "case/./report",
        "case//report",
        "case/",
        "case\\report",
    ],
)
def test_artifact_case_path_must_be_normalized_relative_posix(path: str) -> None:
    with pytest.raises(ExecutionAttestationError, match="artifact_case_path"):
        replace(_binding(), artifact_case_path=path)

    assert replace(_binding(), artifact_case_path=".").artifact_case_path == "."


def test_evaluation_side_is_explicit_and_bounded() -> None:
    assert replace(_binding(), evaluation_side="champion").evaluation_side == "champion"

    with pytest.raises(ExecutionAttestationError, match="evaluation_side"):
        replace(_binding(), evaluation_side="baseline")


def test_types_bounds_accounting_and_verdict_identity_fail_closed() -> None:
    with pytest.raises(ExecutionAttestationError, match="repeat"):
        replace(_binding(), repeat=True)
    with pytest.raises(ExecutionAttestationError, match="expected_vulnerability_count"):
        replace(_binding(), expected_vulnerability_count=-1)
    with pytest.raises(ExecutionAttestationError, match="pinned"):
        replace(_binding(), runner_image="example.invalid/evaluator:latest")
    with pytest.raises(ExecutionAttestationError, match="physical request"):
        replace(_observations(), physical_request_count=None)
    with pytest.raises(ExecutionAttestationError, match="cost_usd"):
        replace(_observations(), cost_usd=float("inf"))
    with pytest.raises(ExecutionAttestationError, match="outside"):
        replace(_observations(), loop_violation_count=-1)
    with pytest.raises(ExecutionAttestationError, match="distinct"):
        sign_execution_envelope(
            _binding(),
            _observations(),
            (_verdicts()[0], _verdicts()[0]),
            private_key=generate_referee_keypair()[0],
        )
    with pytest.raises(ExecutionAttestationError, match="canonical digest order"):
        sign_execution_envelope(
            _binding(),
            _observations(),
            tuple(reversed(_verdicts())),
            private_key=generate_referee_keypair()[0],
        )


def test_nullable_external_metrics_remain_explicit() -> None:
    observations = replace(
        _observations(),
        physical_request_count=None,
        model_request_count=None,
        cost_usd=None,
        request_accounting_status="unavailable",
    )
    private, public = generate_referee_keypair()
    signed = sign_execution_envelope(
        _binding(), observations, (), private_key=private
    )

    receipt = verify_signed_execution_envelope(signed.to_json(), public_key=public).to_run_receipt()

    assert receipt.physical_request_count is None
    assert receipt.model_request_count is None
    assert receipt.cost_usd is None
    assert receipt.request_accounting_status == "unavailable"


def test_file_round_trip_is_private_byte_canonical_and_non_overwriting(
    tmp_path: Path,
) -> None:
    signed, _private, public = _signed()
    path = tmp_path / "sealed" / "execution.json"

    write_signed_execution_envelope(path, signed)
    loaded = load_signed_execution_envelope(path, public_key=public)

    assert loaded == signed
    assert stat.S_IMODE(path.stat().st_mode) == _PRIVATE_MODE
    assert path.read_bytes() == (canonical_json(signed.to_json()) + "\n").encode()
    assert execution_envelope_digest(loaded) == execution_envelope_digest(signed)
    with pytest.raises(ExecutionAttestationError, match="already exists"):
        write_signed_execution_envelope(path, signed)


def test_loader_rejects_noncanonical_duplicate_nonfinite_and_oversize_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _private, public = generate_referee_keypair()
    path = tmp_path / "execution.json"
    path.write_text('{"schema_version":1, "schema_version":2}\n', encoding="utf-8")
    with pytest.raises(ExecutionAttestationError, match="duplicate"):
        load_signed_execution_envelope(path, public_key=public)

    path.write_text('{"cost":NaN}\n', encoding="utf-8")
    with pytest.raises(ExecutionAttestationError, match="unsupported NaN"):
        load_signed_execution_envelope(path, public_key=public)

    path.write_text(json.dumps({"schema_version": 1}, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ExecutionAttestationError, match="byte-canonical"):
        load_signed_execution_envelope(path, public_key=public)

    path.write_bytes(b"x" * 65)
    monkeypatch.setattr(module, "_MAX_SIGNED_BYTES", 64)
    with pytest.raises(ExecutionAttestationError, match="byte cap"):
        load_signed_execution_envelope(path, public_key=public)


def test_loader_rejects_symlinks_and_hardlinks(tmp_path: Path) -> None:
    signed, _private, public = _signed()
    original = tmp_path / "original.json"
    write_signed_execution_envelope(original, signed)
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(original)
    with pytest.raises(ExecutionAttestationError, match="single-link"):
        load_signed_execution_envelope(symlink, public_key=public)

    hardlink = tmp_path / "hardlink.json"
    os.link(original, hardlink)
    with pytest.raises(ExecutionAttestationError, match="single-link"):
        load_signed_execution_envelope(hardlink, public_key=public)


def test_raw_key_sizes_and_strict_lowercase_digests_are_required() -> None:
    with pytest.raises(ExecutionAttestationError, match="private key"):
        sign_execution_envelope(_binding(), _observations(), (), private_key=b"short")
    signed, _private, _public = _signed()
    with pytest.raises(ExecutionAttestationError, match="public key"):
        verify_signed_execution_envelope(signed.to_json(), public_key=b"short")
    with pytest.raises(ExecutionAttestationError, match="digest"):
        replace(_binding(), run_id=f"sha256:{'A' * 64}")


def test_schema_version_is_signed_and_strict() -> None:
    signed, _private, public = _signed()
    payload = signed.to_json()
    assert payload["schema_version"] == EXECUTION_ATTESTATION_SCHEMA_VERSION
    payload["schema_version"] = "ravage.improvement-execution-attestation.v2"

    with pytest.raises(ExecutionAttestationError, match="unsupported"):
        verify_signed_execution_envelope(payload, public_key=public)
