from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab.attestation import (
    AttestationError,
    EvaluationBinding,
    generate_referee_keypair,
    load_signed_evaluation,
    read_private_key,
    referee_key_id,
    sign_evaluation,
    verify_signed_evaluation,
    write_referee_key,
    write_signed_evaluation,
)
from tools.improvement_lab.evaluation import EvaluationConfig, EvaluationReceipt

if TYPE_CHECKING:
    from pathlib import Path


def _binding() -> EvaluationBinding:
    return EvaluationBinding(
        campaign_id=f"campaign_{'a' * 24}",
        candidate_id=f"candidate_{'b' * 24}",
        candidate_parent_ref=f"source:{'c' * 40}",
        champion_commit="c" * 40,
        champion_tree="d" * 40,
        candidate_patch_object=f"sha256:{'1' * 64}",
        candidate_config_object=f"sha256:{'2' * 64}",
        evaluation_config_object=f"sha256:{'3' * 64}",
        evaluation_suite_object=f"sha256:{'4' * 64}",
        runner_image=f"example.invalid/referee@sha256:{'5' * 64}",
        champion_receipts_object=f"sha256:{'6' * 64}",
        candidate_receipts_object=f"sha256:{'7' * 64}",
    )


def _receipt() -> EvaluationReceipt:
    return EvaluationReceipt(
        accepted=True,
        config=EvaluationConfig(),
        matching={"promotable_pairs": 6},
        aggregate={"bound": True},
        stability={"stable_improved_cases": 1},
        rejections=(),
    )


def test_signed_evaluation_binds_receipt_and_every_experiment_identity() -> None:
    private, public = generate_referee_keypair()
    signed = sign_evaluation(_receipt(), _binding(), private_key=private)

    verified = verify_signed_evaluation(signed.to_json(), public_key=public)

    assert verified == signed
    assert verified.signing_key_id == referee_key_id(public)
    assert verified.binding.candidate_patch_object == f"sha256:{'1' * 64}"


def test_signed_evaluation_rejects_candidate_or_receipt_substitution() -> None:
    private, public = generate_referee_keypair()
    payload = sign_evaluation(_receipt(), _binding(), private_key=private).to_json()
    tampered_candidate = deepcopy(payload)
    tampered_candidate["binding"]["candidate_id"] = f"candidate_{'f' * 24}"
    with pytest.raises(AttestationError, match="signature verification"):
        verify_signed_evaluation(tampered_candidate, public_key=public)

    tampered_receipt = deepcopy(payload)
    tampered_receipt["receipt"]["accepted"] = False
    with pytest.raises(AttestationError, match="receipt is invalid"):
        verify_signed_evaluation(tampered_receipt, public_key=public)


def test_wrong_referee_key_is_rejected() -> None:
    private, _public = generate_referee_keypair()
    _other_private, other_public = generate_referee_keypair()
    payload = sign_evaluation(_receipt(), _binding(), private_key=private).to_json()

    with pytest.raises(AttestationError, match="wrong referee key"):
        verify_signed_evaluation(payload, public_key=other_public)


def test_key_and_signed_receipt_files_are_private_and_non_overwriting(tmp_path: Path) -> None:
    private, public = generate_referee_keypair()
    private_path = tmp_path / "keys" / "referee.private"
    public_path = tmp_path / "keys" / "referee.public"
    receipt_path = tmp_path / "evaluation.json"
    write_referee_key(private_path, private, public=False)
    write_referee_key(public_path, public, public=True)
    signed = sign_evaluation(_receipt(), _binding(), private_key=private)
    write_signed_evaluation(receipt_path, signed)

    loaded = load_signed_evaluation(receipt_path, public_key=public)

    assert loaded == signed
    assert private_path.stat().st_mode & 0o077 == 0
    private_path.chmod(0o644)
    with pytest.raises(AttestationError, match="group or other"):
        read_private_key(private_path)
    with pytest.raises(AttestationError, match="already exists"):
        write_signed_evaluation(receipt_path, signed)
