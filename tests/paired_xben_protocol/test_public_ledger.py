# ruff: noqa: ARG005,EM101,PLR2004,SLF001,TRY003
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.paired_xben_protocol import test_protocol as protocol_test_support
from tools.paired_xben import authenticity as authenticity_module
from tools.paired_xben import public_ledger
from tools.paired_xben import report as paired_report
from tools.paired_xben.protocol import reserve_primary_matrix

CAMPAIGN = "campaign-001"
REPOSITORY = "example/ravage"
SOURCE_SHA = "a" * 40
IDENTITY = "https://github.com/example/ravage/.github/workflows/paired-xben.yml@refs/heads/main"
DRAND_VERIFIER = b"frozen drand verifier\n"
COSIGN_VERIFIER = b"frozen cosign verifier\n"


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: object, *, ensure_ascii: bool = True) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=ensure_ascii,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _protocol_document(body: dict[str, object]) -> dict[str, object]:
    return {**body, "document_digest": _sha256(_canonical(body))}


def _campaign(tmp_path: Path) -> Path:
    root = tmp_path / "campaign"
    root.mkdir()
    preflight = b'{"blocked":false}\n'
    trusted_root = b'{"mediaType":"application/vnd.dev.sigstore.trustedroot.v0.2+json"}\n'
    (root / "preflight-source.json").write_bytes(preflight)
    (root / "verifiers").mkdir()
    (root / "verifiers/sigstore-trusted-root.json").write_bytes(trusted_root)
    (root / "verifiers/drandverify").write_bytes(DRAND_VERIFIER)
    (root / "verifiers/cosign").write_bytes(COSIGN_VERIFIER)
    commitment = _protocol_document(
        {
            "schema_version": "ravage.paired-xben.commitment.v1",
            "campaign_id": CAMPAIGN,
            "preflight_source": {"sha256": _sha256(preflight)},
            "attempt_policy": {
                "scored_attempts": "scheduled_primary_only",
                "reruns_are_scored": False,
                "overwrite_allowed": False,
            },
            "run_contract": {"sources": {"ravage": {"commit_sha": SOURCE_SHA}}},
            "authenticity_policy": {
                "drand": {
                    "binary_file": "verifiers/drandverify",
                    "binary_sha256": _sha256(DRAND_VERIFIER),
                    "binary_size": len(DRAND_VERIFIER),
                },
                "publication": {
                    "certificate_identity": IDENTITY,
                    "certificate_oidc_issuer": public_ledger.OIDC_ISSUER,
                    "cosign_binary_file": "verifiers/cosign",
                    "cosign_binary_sha256": _sha256(COSIGN_VERIFIER),
                    "cosign_binary_size": len(COSIGN_VERIFIER),
                    "trusted_root_file": "verifiers/sigstore-trusted-root.json",
                    "trusted_root_sha256": _sha256(trusted_root),
                },
            },
        }
    )
    _write_json(root / "commitment.json", commitment)
    return root


def _commitment_submission(tmp_path: Path) -> tuple[Path, Path]:
    campaign = _campaign(tmp_path)
    submission = tmp_path / "submission"
    public_ledger.create_submission(campaign, submission, phase="commitment")
    return campaign, submission


def _prepare_commitment_entry(tmp_path: Path, submission: Path) -> Path:
    entry_dir = tmp_path / "ledger" / "01-commitment"
    tag = public_ledger.release_tag(CAMPAIGN, "commitment")
    public_ledger.prepare_entry(
        submission,
        entry_dir,
        repository=REPOSITORY,
        repository_id=10,
        workflow_sha=SOURCE_SHA,
        run_id=20,
        run_attempt=1,
        actor_id=30,
        release_id=40,
        release_url=f"https://github.com/{REPOSITORY}/releases/tag/{tag}",
        source_run_id=50,
        source_run_head_sha="b" * 40,
        source_artifact_name="paired-xben-submission-50",
    )
    return entry_dir


def _bind_crypto_inputs(campaign: Path, cosign: Path) -> Path:
    commitment_path = campaign / "commitment.json"
    commitment = json.loads(commitment_path.read_text(encoding="utf-8"))
    body = {key: value for key, value in commitment.items() if key != "document_digest"}
    publication = body["authenticity_policy"]["publication"]
    publication.update(
        {
            "cosign_binary_file": "verifiers/cosign",
            "cosign_binary_sha256": _sha256(cosign.read_bytes()),
            "cosign_binary_size": cosign.stat().st_size,
            "trusted_root_file": "verifiers/sigstore-trusted-root.json",
        }
    )
    _write_json(commitment_path, _protocol_document(body))
    return campaign / "verifiers/sigstore-trusted-root.json"


def _bind_protocol_verifiers(campaign: Path, drand: bytes, cosign: bytes) -> None:
    commitment_path = campaign / "commitment.json"
    commitment = json.loads(commitment_path.read_text(encoding="utf-8"))
    body = {key: value for key, value in commitment.items() if key != "document_digest"}
    body["authenticity_policy"]["drand"].update(
        {
            "binary_sha256": _sha256(drand),
            "binary_size": len(drand),
        }
    )
    body["authenticity_policy"]["publication"].update(
        {
            "cosign_binary_sha256": _sha256(cosign),
            "cosign_binary_size": len(cosign),
        }
    )
    _write_json(commitment_path, _protocol_document(body))


def _verifier_kwargs(root: Path) -> dict[str, Path]:
    return {
        "drand_verifier_path": root / "verifiers/drandverify",
        "cosign_path": root / "verifiers/cosign",
        "trusted_root_path": root / "verifiers/sigstore-trusted-root.json",
    }


def _verification_protocol_kwargs(root: Path) -> dict[str, Path]:
    return {
        "drand_verifier_path": root / "verifiers/drandverify",
        "protocol_cosign_path": root / "verifiers/cosign",
        "protocol_trusted_root_path": root / "verifiers/sigstore-trusted-root.json",
    }


def _prepare_phase_entry(
    tmp_path: Path,
    submission: Path,
    *,
    phase: str,
    ordinal: int,
    previous_entry: Path,
) -> Path:
    entry_dir = tmp_path / "ledger" / f"{ordinal:02d}-{phase}"
    tag = public_ledger.release_tag(CAMPAIGN, phase)
    source_run_id = 50 + ordinal
    public_ledger.prepare_entry(
        submission,
        entry_dir,
        repository=REPOSITORY,
        repository_id=10,
        workflow_sha=SOURCE_SHA,
        run_id=20 + ordinal,
        run_attempt=1,
        actor_id=30,
        release_id=40 + ordinal,
        release_url=f"https://github.com/{REPOSITORY}/releases/tag/{tag}",
        source_run_id=source_run_id,
        source_run_head_sha="b" * 40,
        source_artifact_name=f"paired-xben-submission-{source_run_id}",
        previous_entry_path=previous_entry,
        **_verifier_kwargs(submission / "payload"),
    )
    return entry_dir


def _bundle(artifact: Path) -> dict[str, object]:
    digest = base64.b64encode(hashlib.sha256(artifact.read_bytes()).digest()).decode("ascii")
    return {
        "mediaType": public_ledger.SIGSTORE_BUNDLE_MEDIA_TYPE,
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": digest},
            "signature": base64.b64encode(b"signature").decode("ascii"),
        },
        "verificationMaterial": {
            "timestampVerificationData": {
                "rfc3161Timestamps": [
                    {"signedTimestamp": base64.b64encode(b"timestamp").decode("ascii")}
                ]
            },
            "tlogEntries": [{}],
        },
    }


def _add_matrix(campaign: Path) -> None:
    (campaign / "verifiers/drandverify").write_bytes(DRAND_VERIFIER)
    (campaign / "verifiers/cosign").write_bytes(COSIGN_VERIFIER)
    (campaign / "verifiers/drandverify").chmod(0o700)
    (campaign / "verifiers/cosign").chmod(0o700)
    for relative in public_ledger._RESOLUTION_FILES:
        path = campaign / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.name != "selection.json":
            _write_json(path, {"retained": path.name})
    schedule = []
    for slot_number in range(1, 41):
        pair_index = (slot_number + 1) // 2
        schedule.append(
            {
                "slot": slot_number,
                "slot_id": f"primary-{slot_number:03d}",
                "pair_index": pair_index,
                "position_within_pair": 1 if slot_number % 2 else 2,
                "case_id": f"XBEN-{pair_index:03d}-24",
                "system": "ravage" if slot_number % 2 else "strix",
                "purpose": "primary",
                "score_eligible": True,
            }
        )
    slots = [row["slot_id"] for row in schedule]
    commitment = json.loads((campaign / "commitment.json").read_text(encoding="utf-8"))
    commitment_digest = commitment["document_digest"]
    selection = _protocol_document(
        {
            "schema_version": "ravage.paired-xben.selection.v1",
            "campaign_id": CAMPAIGN,
            "commitment_digest": commitment_digest,
            "selected_case_ids": [f"XBEN-{index:03d}-24" for index in range(1, 21)],
            "schedule": schedule,
        }
    )
    _write_json(campaign / "resolution/selection.json", selection)
    records: list[dict[str, object]] = []
    for slot in slots:
        attempt = _protocol_document(
            {
                "schema_version": "ravage.paired-xben.attempt.v1",
                "attempt_id": slot,
                "purpose": "primary",
                "score_eligible": True,
                "parent_primary_slot_id": None,
            }
        )
        _write_json(campaign / f"attempts/primary/{slot}/attempt.json", attempt)
        (campaign / f"attempts/primary/{slot}/artifacts").mkdir()
        records.append(
            {
                "slot_id": slot,
                "attempt_manifest": f"{slot}/attempt.json",
                "attempt_document_digest": attempt["document_digest"],
            }
        )
    matrix = _protocol_document(
        {
            "schema_version": "ravage.paired-xben.primary-matrix.v1",
            "campaign_id": CAMPAIGN,
            "commitment_digest": commitment_digest,
            "selection_digest": selection["document_digest"],
            "scheduled_primary_attempts": 40,
            "policy": {
                "all_slots_reserved_before_execution": True,
                "resume_incomplete_reservation": False,
                "replace_primary_attempt": False,
            },
            "attempts": records,
        }
    )
    _write_json(campaign / "attempts/primary-reservation.json", matrix)


def _verified_protocol(root: Path, *, require_all_primary_attempts: bool) -> dict[str, object]:
    assert require_all_primary_attempts is True
    commitment = json.loads((root / "commitment.json").read_text(encoding="utf-8"))
    selection = json.loads((root / "resolution/selection.json").read_text(encoding="utf-8"))
    matrix = json.loads((root / "attempts/primary-reservation.json").read_text(encoding="utf-8"))
    assert (root / "resolution/beacon-source.json").is_file()
    assert (root / "resolution/beacon-source-secondary.json").is_file()
    assert (root / "resolution/drand-fetch.json").is_file()
    assert (root / "resolution/drand-chain-info-source.json").is_file()
    assert (root / "resolution/publication-anchor-source.json").is_file()
    assert (root / "resolution/publication-anchor.json").is_file()
    assert (root / "resolution/beacon.json").is_file()
    assert (root / "verifiers/drandverify").is_file()
    assert (root / "verifiers/cosign").is_file()
    assert os.access(root / "verifiers/drandverify", os.X_OK)
    assert os.access(root / "verifiers/cosign", os.X_OK)
    assert all(
        (root / f"attempts/primary/primary-{index:03d}/artifacts").is_dir()
        for index in range(1, 41)
    )
    return {
        "phase": "resolved",
        "structurally_valid": True,
        "beacon_authenticity_verified": True,
        "publication_anchor_verified": True,
        "campaign_id": commitment["campaign_id"],
        "commitment_digest": commitment["document_digest"],
        "selection_digest": selection["document_digest"],
        "selected_cases": 20,
        "scheduled_primary_attempts": 40,
        "recorded_primary_attempts": 40,
        "missing_primary_attempts": 0,
        "primary_matrix_reserved": True,
        "primary_matrix_digest": matrix["document_digest"],
        "diagnostic_reruns": 0,
    }


def _stub_protocol_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(public_ledger, "verify_campaign", _verified_protocol)


def _add_start(campaign: Path) -> None:
    commitment = json.loads((campaign / "commitment.json").read_text(encoding="utf-8"))
    selection = json.loads((campaign / "resolution/selection.json").read_text(encoding="utf-8"))
    matrix = json.loads(
        (campaign / "attempts/primary-reservation.json").read_text(encoding="utf-8")
    )
    slots = [f"primary-{index:03d}" for index in range(1, 41)]
    _write_json(
        campaign / "execution/start.json",
        public_ledger._document(
            {
                "schema_version": "ravage.paired-xben.execution-start.v1",
                "created_at": "2026-09-12T00:00:00+00:00",
                "campaign_id": CAMPAIGN,
                "commitment_digest": commitment["document_digest"],
                "selection_digest": selection["document_digest"],
                "primary_matrix_digest": matrix["document_digest"],
                "evidence_class": "test",
                "official_attestation_eligible": False,
                "registered_row_count": 40,
                "registered_row_ids": slots,
                "row_instances": [],
                "policy": {
                    "resume_allowed": False,
                    "row_retry_allowed": False,
                    "row_replacement_allowed": False,
                    "adjacent_pair_schedule": True,
                },
            }
        ),
    )


def _row_manifest(row_root: Path) -> None:
    lines = []
    for path in sorted(candidate for candidate in row_root.rglob("*") if candidate.is_file()):
        if path.name == "artifacts.sha256":
            continue
        lines.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.relative_to(row_root).as_posix()}"
        )
    (row_root / "artifacts.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _add_complete_results(campaign: Path) -> None:
    commitment = json.loads((campaign / "commitment.json").read_text(encoding="utf-8"))
    selection = json.loads((campaign / "resolution/selection.json").read_text(encoding="utf-8"))
    row_seals = []
    for index, scheduled in enumerate(selection["schedule"], start=1):
        slot = f"primary-{index:03d}"
        row_root = campaign / f"attempts/primary/{slot}/artifacts/row"
        row_root.mkdir(parents=True)
        candidate = f"flag{{test_{index:03d}}}\n".encode()
        expected_flag_sha256 = hashlib.sha256(candidate.rstrip()).hexdigest()
        _write_json(
            row_root / "row-result.json",
            {
                "schema_version": "ravage.xben.external-comparison-row.v2",
                "schedule_binding": {
                    "campaign_id": CAMPAIGN,
                    "commitment_digest": commitment["document_digest"],
                    "selection_digest": selection["document_digest"],
                    "primary_slot_id": slot,
                },
                "case": {"benchmark_id": scheduled.get("case_id")},
                "agent": {"system_id": scheduled.get("system")},
                "policy": {
                    "attempt": 1,
                    "retry_allowed": False,
                    "replacement_allowed": False,
                    "fresh_target_per_row": True,
                    "pair_scoped_flag": True,
                },
                "status": "solved",
                "score": {
                    "expected_flag_sha256": expected_flag_sha256,
                    "solved": True,
                    "artifact": {
                        "path": "answer.txt",
                        "sha256": hashlib.sha256(candidate).hexdigest(),
                    },
                },
            },
        )
        _write_json(row_root / "process-receipt.json", {"retained": slot})
        raw_token = f"row-gateway-token-{index:046d}"
        assert len(raw_token) == 64
        _write_json(
            row_root / "model-gateway-receipt.json",
            public_ledger._document(
                {
                    "schema_version": "ravage.xben.model-gateway-receipt.v1",
                    "row_id": slot,
                    "row_token_sha256": _sha256(raw_token.encode()),
                }
            ),
        )
        (row_root / "sandbox-profile.sb").write_text("(version 1)\n", encoding="utf-8")
        _write_json(row_root / "target-build.json", {"status": "succeeded"})
        _write_json(row_root / "target-teardown.json", {"status": "succeeded"})
        _write_json(
            row_root / "flag-commitment.json",
            {"expected_flag_sha256": expected_flag_sha256},
        )
        native = row_root / "native-output"
        native.mkdir()
        (native / "answer.txt").write_bytes(candidate)
        _row_manifest(row_root)
        row_seals.append(
            {
                "slot_id": slot,
                "row_manifest_sha256": _sha256((row_root / "artifacts.sha256").read_bytes()),
                "row_result_sha256": _sha256((row_root / "row-result.json").read_bytes()),
                "adapter_result_sha256": None,
                "process_receipt_sha256": _sha256((row_root / "process-receipt.json").read_bytes()),
                "model_gateway_receipt_sha256": _sha256(
                    (row_root / "model-gateway-receipt.json").read_bytes()
                ),
                "sandbox_profile_sha256": _sha256((row_root / "sandbox-profile.sb").read_bytes()),
                "target_build_sha256": _sha256((row_root / "target-build.json").read_bytes()),
                "target_teardown_sha256": _sha256((row_root / "target-teardown.json").read_bytes()),
            }
        )
    pair_seals = []
    for index in range(1, 21):
        pair_id = f"pair-{index:03d}"
        pair_root = campaign / f"execution/targets/{pair_id}.prepared"
        _write_json(pair_root / "prepared.json", {"pair_id": pair_id})
        _write_json(pair_root / "release.json", {"pair_id": pair_id, "released": True})
        pair_seals.append(
            {
                "pair_index": index,
                "case_id": selection["schedule"][(index - 1) * 2]["case_id"],
                "pair_id": pair_id,
                "prepared_target_sha256": _sha256((pair_root / "prepared.json").read_bytes()),
                "release_sha256": _sha256((pair_root / "release.json").read_bytes()),
            }
        )
    model = public_ledger._document(
        {
            "schema_version": "ravage.xben.model-gateway-campaign-receipt.v1",
            "row_count": 40,
        }
    )
    _write_json(campaign / "campaign-model-gateway.json", model)
    results = public_ledger._document(
        {
            "schema_version": "ravage.paired-xben.primary-results.v1",
            "created_at": "2026-09-12T01:00:00+00:00",
            "campaign_id": CAMPAIGN,
            "commitment_digest": commitment["document_digest"],
            "selection_digest": selection["document_digest"],
            "row_count": 40,
            "rows": row_seals,
            "paired_targets": pair_seals,
            "all_terminal": True,
        }
    )
    _write_json(campaign / "primary-results.json", results)
    terminal = public_ledger._document(
        {
            "schema_version": "ravage.paired-xben.execution-terminal.v1",
            "created_at": "2026-09-12T01:01:00+00:00",
            "campaign_id": CAMPAIGN,
            "commitment_digest": commitment["document_digest"],
            "selection_digest": selection["document_digest"],
            "rows_terminal": 40,
            "pairs_terminal": 20,
            "model_gateway_receipt_sha256": _sha256(
                (campaign / "campaign-model-gateway.json").read_bytes()
            ),
            "model_gateway_document_sha256": model["document_sha256"],
            "primary_results_sha256": _sha256((campaign / "primary-results.json").read_bytes()),
            "complete": True,
        }
    )
    _write_json(campaign / "execution/terminal.json", terminal)


def _stub_row_recomputation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paired_report, "_validate_row_result", lambda *args, **kwargs: None)
    monkeypatch.setattr(paired_report, "_verify_row_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        paired_report,
        "_verify_declared_native_artifact",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(paired_report, "_verify_row_lifecycle", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        paired_report,
        "_validate_unique_row_state",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        paired_report,
        "_validate_schedule_execution_order",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        paired_report,
        "_paired_results",
        lambda *args, **kwargs: {
            "systems": {
                "ravage": {"solved": 20, "total": 20},
                "strix": {"solved": 20, "total": 20},
            }
        },
    )


def test_commitment_submission_is_exact_create_only_and_tamper_evident(tmp_path: Path) -> None:
    campaign, submission = _commitment_submission(tmp_path)
    manifest_path = submission / "submission.json"
    manifest = public_ledger.validate_submission(
        submission,
        expected_campaign_id=CAMPAIGN,
        expected_phase="commitment",
        expected_file_sha256=_sha256(manifest_path.read_bytes()),
    )
    assert [item["path"] for item in manifest["artifacts"]] == [
        "commitment.json",
        "preflight-source.json",
        "verifiers/sigstore-trusted-root.json",
    ]
    with pytest.raises(public_ledger.PublicLedgerError, match="refusing to reuse"):
        public_ledger.create_submission(campaign, submission, phase="commitment")
    (submission / "payload/preflight-source.json").write_bytes(b"changed\n")
    with pytest.raises(public_ledger.PublicLedgerError, match="digest mismatch"):
        public_ledger.validate_submission(submission)


def test_matrix_accepts_only_the_forty_reserved_primary_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_protocol_verifier(monkeypatch)
    campaign, submission = _commitment_submission(tmp_path)
    entry_dir = _prepare_commitment_entry(tmp_path, submission)
    _add_matrix(campaign)
    matrix_submission = tmp_path / "matrix-submission"
    manifest_path = public_ledger.create_submission(
        campaign,
        matrix_submission,
        phase="matrix",
        previous_entry_path=entry_dir / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    manifest = public_ledger.validate_submission(
        matrix_submission,
        **_verifier_kwargs(campaign),
    )
    paths = [item["path"] for item in manifest["artifacts"]]
    assert len(paths) == 94
    assert set(public_ledger._RESOLUTION_FILES).issubset(paths)
    assert {"verifiers/drandverify", "verifiers/cosign"}.issubset(paths)
    assert sum(path.endswith(public_ledger._EMPTY_RESERVATION_MARKER) for path in paths) == 40
    assert all(
        (matrix_submission / f"payload/attempts/primary/primary-{index:03d}/artifacts").is_dir()
        for index in range(1, 41)
    )
    assert all("rerun" not in path for path in paths)
    assert manifest_path.exists()

    invalid = tmp_path / "invalid-campaign"
    shutil.copytree(campaign, invalid)
    attempt_path = invalid / "attempts/primary/primary-001/attempt.json"
    attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
    attempt_body = {key: value for key, value in attempt.items() if key != "document_digest"}
    attempt_body["purpose"] = "rerun"
    attempt = _protocol_document(attempt_body)
    _write_json(attempt_path, attempt)
    matrix_path = invalid / "attempts/primary-reservation.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix_body = {key: value for key, value in matrix.items() if key != "document_digest"}
    matrix_body["attempts"][0]["attempt_document_digest"] = attempt["document_digest"]
    _write_json(matrix_path, _protocol_document(matrix_body))
    with pytest.raises(public_ledger.PublicLedgerError, match="rerun or non-primary"):
        public_ledger.create_submission(
            invalid,
            tmp_path / "invalid-submission",
            phase="matrix",
            previous_entry_path=entry_dir / "ledger-entry.json",
            **_verifier_kwargs(invalid),
        )


def test_matrix_rejects_resolution_that_protocol_verifier_cannot_authenticate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, submission = _commitment_submission(tmp_path)
    entry_dir = _prepare_commitment_entry(tmp_path, submission)
    _add_matrix(campaign)

    def reject_resolution(_root: Path, *, require_all_primary_attempts: bool) -> dict[str, object]:
        assert require_all_primary_attempts is True
        raise public_ledger.PairedXbenProtocolError("official relay responses disagree")

    monkeypatch.setattr(public_ledger, "verify_campaign", reject_resolution)
    with pytest.raises(public_ledger.PublicLedgerError, match="protocol verification"):
        public_ledger.create_submission(
            campaign,
            tmp_path / "rejected-matrix",
            phase="matrix",
            previous_entry_path=entry_dir / "ledger-entry.json",
            **_verifier_kwargs(campaign),
        )


def test_postcommitment_never_executes_embedded_verifier_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = tmp_path / "embedded-verifier-ran"
    script = (
        "#!/bin/sh\n"
        'case "$0" in\n'
        "  *ravage-ledger-protocol-*) exit 0 ;;\n"
        f"  *) printf ran >'{sentinel}' ; exit 91 ;;\n"
        "esac\n"
    ).encode()
    campaign = _campaign(tmp_path)
    _bind_protocol_verifiers(campaign, script, script)
    commitment_submission = tmp_path / "sentinel-commitment-submission"
    public_ledger.create_submission(campaign, commitment_submission, phase="commitment")
    commitment_entry = _prepare_commitment_entry(tmp_path, commitment_submission)
    _add_matrix(campaign)
    (campaign / "verifiers/drandverify").write_bytes(script)
    (campaign / "verifiers/cosign").write_bytes(script)

    trusted = tmp_path / "out-of-band-trusted-verifiers"
    (trusted / "verifiers").mkdir(parents=True)
    (trusted / "verifiers/drandverify").write_bytes(script)
    (trusted / "verifiers/cosign").write_bytes(script)
    shutil.copyfile(
        campaign / "verifiers/sigstore-trusted-root.json",
        trusted / "verifiers/sigstore-trusted-root.json",
    )

    with pytest.raises(public_ledger.PublicLedgerError, match="trusted external"):
        public_ledger.create_submission(
            campaign,
            tmp_path / "blocked-without-trusted-verifiers",
            phase="matrix",
            previous_entry_path=commitment_entry / "ledger-entry.json",
        )
    assert not sentinel.exists()

    def execute_only_received_verifier(
        root: Path,
        *,
        require_all_primary_attempts: bool,
    ) -> dict[str, object]:
        assert require_all_primary_attempts is True
        assert "ravage-ledger-protocol-" in str(root)
        subprocess.run(  # noqa: S603
            [str(root / "verifiers/drandverify")],
            check=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        return _verified_protocol(root, require_all_primary_attempts=True)

    monkeypatch.setattr(public_ledger, "verify_campaign", execute_only_received_verifier)
    public_ledger.create_submission(
        campaign,
        tmp_path / "safe-matrix-submission",
        phase="matrix",
        previous_entry_path=commitment_entry / "ledger-entry.json",
        **_verifier_kwargs(trusted),
    )
    assert not sentinel.exists()


def test_matrix_real_protocol_verifier_survives_submission_and_zip_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def download(url: str) -> bytes:
        name = (
            "input-beacon-secondary.json"
            if url.startswith("https://drand.cloudflare.com/")
            else "input-beacon.json"
        )
        return (tmp_path / name).read_bytes()

    monkeypatch.setattr(authenticity_module, "_download_drand_response", download)
    monkeypatch.setattr(public_ledger, "WORKFLOW_FILE", ".github/workflows/benchmark.yml")
    campaign = tmp_path / "real-protocol-campaign"
    protocol_test_support._commit(campaign)

    commitment_submission = tmp_path / "real-commitment-submission"
    public_ledger.create_submission(campaign, commitment_submission, phase="commitment")
    commitment_entry = tmp_path / "real-ledger/01-commitment"
    commitment_tag = public_ledger.release_tag("paired-xben-test", "commitment")
    public_ledger.prepare_entry(
        commitment_submission,
        commitment_entry,
        repository=REPOSITORY,
        repository_id=10,
        workflow_sha=SOURCE_SHA,
        run_id=101,
        run_attempt=1,
        actor_id=30,
        release_id=201,
        release_url=f"https://github.com/{REPOSITORY}/releases/tag/{commitment_tag}",
        source_run_id=301,
        source_run_head_sha="b" * 40,
        source_artifact_name="paired-xben-submission-301",
    )

    protocol_test_support._resolve(campaign, tmp_path)
    reserve_primary_matrix(campaign, created_at=protocol_test_support.RETRIEVED_AT)
    matrix_submission = tmp_path / "real-matrix-submission"
    public_ledger.create_submission(
        campaign,
        matrix_submission,
        phase="matrix",
        previous_entry_path=commitment_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    validated = public_ledger.validate_submission(
        matrix_submission,
        **_verifier_kwargs(campaign),
    )
    paths = [item["path"] for item in validated["artifacts"]]
    assert sum(path.endswith(public_ledger._EMPTY_RESERVATION_MARKER) for path in paths) == 40
    assert os.access(matrix_submission / "payload/verifiers/drandverify", os.X_OK)
    assert os.access(matrix_submission / "payload/verifiers/cosign", os.X_OK)

    matrix_entry = tmp_path / "real-ledger/02-matrix"
    matrix_tag = public_ledger.release_tag("paired-xben-test", "matrix")
    public_ledger.prepare_entry(
        matrix_submission,
        matrix_entry,
        repository=REPOSITORY,
        repository_id=10,
        workflow_sha=SOURCE_SHA,
        run_id=102,
        run_attempt=1,
        actor_id=30,
        release_id=202,
        release_url=f"https://github.com/{REPOSITORY}/releases/tag/{matrix_tag}",
        source_run_id=302,
        source_run_head_sha="c" * 40,
        source_artifact_name="paired-xben-submission-302",
        previous_entry_path=commitment_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    _write_json(
        matrix_entry / "ledger-entry.sigstore.json", _bundle(matrix_entry / "ledger-entry.json")
    )
    verified = public_ledger.verify_entry(
        matrix_entry,
        cosign_path=None,
        trusted_root_path=None,
        expected_repository=REPOSITORY,
        **_verification_protocol_kwargs(campaign),
    )
    assert verified["artifact_integrity_verified"] is True


def test_results_submission_is_blocked_without_full_independent_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_protocol_verifier(monkeypatch)
    _stub_row_recomputation(monkeypatch)
    campaign, commitment_submission = _commitment_submission(tmp_path)
    commitment_entry = _prepare_commitment_entry(tmp_path, commitment_submission)
    _add_matrix(campaign)
    matrix_submission = tmp_path / "matrix-submission"
    public_ledger.create_submission(
        campaign,
        matrix_submission,
        phase="matrix",
        previous_entry_path=commitment_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    matrix_entry = _prepare_phase_entry(
        tmp_path,
        matrix_submission,
        phase="matrix",
        ordinal=2,
        previous_entry=commitment_entry / "ledger-entry.json",
    )
    _add_start(campaign)
    start_submission = tmp_path / "start-submission"
    public_ledger.create_submission(
        campaign,
        start_submission,
        phase="start",
        previous_entry_path=matrix_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    start_entry = _prepare_phase_entry(
        tmp_path,
        start_submission,
        phase="start",
        ordinal=3,
        previous_entry=matrix_entry / "ledger-entry.json",
    )
    _add_complete_results(campaign)
    results_submission = tmp_path / "results-submission"
    monkeypatch.setattr(
        paired_report,
        "_paired_results",
        lambda *args, **kwargs: pytest.fail("results aggregation must remain unreachable"),
    )

    with pytest.raises(public_ledger.PublicLedgerError) as blocked:
        public_ledger.create_submission(
            campaign,
            results_submission,
            phase="results",
            previous_entry_path=start_entry / "ledger-entry.json",
            **_verifier_kwargs(campaign),
        )

    assert str(blocked.value) == (
        "results publication is hard-blocked until a relocation-safe full independent "
        "evidence verifier authenticates every row, target, model, evaluator component, "
        "and public execution attestation"
    )
    assert not results_submission.exists()


def test_results_reject_summary_only_without_row_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_protocol_verifier(monkeypatch)
    _stub_row_recomputation(monkeypatch)
    campaign, submission = _commitment_submission(tmp_path)
    commitment_entry = _prepare_commitment_entry(tmp_path, submission)
    _add_matrix(campaign)
    matrix_submission = tmp_path / "matrix-submission"
    public_ledger.create_submission(
        campaign,
        matrix_submission,
        phase="matrix",
        previous_entry_path=commitment_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    matrix_entry = _prepare_phase_entry(
        tmp_path,
        matrix_submission,
        phase="matrix",
        ordinal=2,
        previous_entry=commitment_entry / "ledger-entry.json",
    )
    _add_start(campaign)
    start_submission = tmp_path / "start-submission"
    public_ledger.create_submission(
        campaign,
        start_submission,
        phase="start",
        previous_entry_path=matrix_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    start_entry = _prepare_phase_entry(
        tmp_path,
        start_submission,
        phase="start",
        ordinal=3,
        previous_entry=matrix_entry / "ledger-entry.json",
    )
    _add_complete_results(campaign)
    shutil.rmtree(campaign / "attempts/primary/primary-001/artifacts/row")
    with pytest.raises(public_ledger.PublicLedgerError, match=r"row result|evidence"):
        public_ledger.create_submission(
            campaign,
            tmp_path / "summary-only-results",
            phase="results",
            previous_entry_path=start_entry / "ledger-entry.json",
            **_verifier_kwargs(campaign),
        )


def test_publication_hygiene_rejects_known_provider_and_gateway_credentials() -> None:
    with pytest.raises(public_ledger.PublicLedgerError, match="provider API key"):
        public_ledger._reject_high_confidence_secrets(
            "stdout.log",
            b"OPENAI_API_KEY=sk-" + b"proj-abcdefghijklmnopqrstuvwxyz0123456789",
        )
    gateway = b"A" * 64
    with pytest.raises(public_ledger.PublicLedgerError, match="row gateway token"):
        public_ledger._reject_gateway_token_variants(
            "native-output/debug.txt",
            b"token=" + gateway + b"\n",
            {_sha256(gateway)},
        )
    with pytest.raises(public_ledger.PublicLedgerError, match="sensitive field"):
        public_ledger._reject_sensitive_json_fields(
            {"authorization": "Bearer this-must-never-be-published"},
            path="debug.json",
        )


def test_publication_hygiene_rejects_hardlinked_campaign_artifacts(tmp_path: Path) -> None:
    campaign = _campaign(tmp_path)
    os.link(campaign / "preflight-source.json", campaign / "preflight-copy.json")
    with pytest.raises(public_ledger.PublicLedgerError, match="regular file"):
        public_ledger.create_submission(
            campaign,
            tmp_path / "hardlinked-submission",
            phase="commitment",
        )


def test_later_phase_cannot_swap_the_published_commitment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_protocol_verifier(monkeypatch)
    campaign, submission = _commitment_submission(tmp_path)
    entry_dir = _prepare_commitment_entry(tmp_path, submission)

    commitment_path = campaign / "commitment.json"
    commitment = json.loads(commitment_path.read_text(encoding="utf-8"))
    replacement = {key: value for key, value in commitment.items() if key != "document_digest"}
    replacement["operator_note"] = "different commitment under the same campaign id"
    _write_json(commitment_path, _protocol_document(replacement))
    _add_matrix(campaign)

    with pytest.raises(public_ledger.PublicLedgerError, match="changed an earlier binding"):
        public_ledger.create_submission(
            campaign,
            tmp_path / "replacement-matrix-submission",
            phase="matrix",
            previous_entry_path=entry_dir / "ledger-entry.json",
            **_verifier_kwargs(campaign),
        )


def test_offline_ledger_rejects_cross_phase_binding_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_protocol_verifier(monkeypatch)
    campaign, submission = _commitment_submission(tmp_path)
    published_commitment = _prepare_commitment_entry(tmp_path, submission)
    _write_json(
        published_commitment / "ledger-entry.sigstore.json",
        _bundle(published_commitment / "ledger-entry.json"),
    )
    _write_json(
        published_commitment / "commitment.sigstore.json",
        _bundle(published_commitment / "commitment.json"),
    )

    commitment_path = campaign / "commitment.json"
    commitment = json.loads(commitment_path.read_text(encoding="utf-8"))
    replacement = {key: value for key, value in commitment.items() if key != "document_digest"}
    replacement["operator_note"] = "unpublished replacement"
    _write_json(commitment_path, _protocol_document(replacement))
    replacement_submission = tmp_path / "replacement-commitment-submission"
    public_ledger.create_submission(
        campaign,
        replacement_submission,
        phase="commitment",
    )
    replacement_entry = tmp_path / "replacement-commitment-entry"
    commitment_tag = public_ledger.release_tag(CAMPAIGN, "commitment")
    public_ledger.prepare_entry(
        replacement_submission,
        replacement_entry,
        repository=REPOSITORY,
        repository_id=10,
        workflow_sha=SOURCE_SHA,
        run_id=51,
        run_attempt=1,
        actor_id=30,
        release_id=41,
        release_url=f"https://github.com/{REPOSITORY}/releases/tag/{commitment_tag}",
        source_run_id=52,
        source_run_head_sha="b" * 40,
        source_artifact_name="paired-xben-submission-52",
    )

    _add_matrix(campaign)
    matrix_submission = tmp_path / "replacement-matrix-submission"
    public_ledger.create_submission(
        campaign,
        matrix_submission,
        phase="matrix",
        previous_entry_path=replacement_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    matrix_entry = tmp_path / "ledger" / "02-matrix"
    matrix_tag = public_ledger.release_tag(CAMPAIGN, "matrix")
    public_ledger.prepare_entry(
        matrix_submission,
        matrix_entry,
        repository=REPOSITORY,
        repository_id=10,
        workflow_sha=SOURCE_SHA,
        run_id=53,
        run_attempt=1,
        actor_id=30,
        release_id=42,
        release_url=f"https://github.com/{REPOSITORY}/releases/tag/{matrix_tag}",
        source_run_id=54,
        source_run_head_sha="c" * 40,
        source_artifact_name="paired-xben-submission-54",
        previous_entry_path=replacement_entry / "ledger-entry.json",
        **_verifier_kwargs(campaign),
    )
    entry_path = matrix_entry / "ledger-entry.json"
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    entry_body = {key: value for key, value in entry.items() if key != "document_sha256"}
    prior = json.loads((published_commitment / "ledger-entry.json").read_text(encoding="utf-8"))
    entry_body["previous_entry_document_sha256"] = prior["document_sha256"]
    _write_json(entry_path, public_ledger._document(entry_body))
    _write_json(matrix_entry / "ledger-entry.sigstore.json", _bundle(entry_path))

    with pytest.raises(public_ledger.PublicLedgerError, match="changed an earlier binding"):
        public_ledger.verify_ledger(
            tmp_path / "ledger",
            **_verification_protocol_kwargs(campaign),
        )


def test_offline_entry_verification_preserves_claim_boundaries(tmp_path: Path) -> None:
    _, submission = _commitment_submission(tmp_path)
    entry_dir = _prepare_commitment_entry(tmp_path, submission)
    _write_json(entry_dir / "ledger-entry.sigstore.json", _bundle(entry_dir / "ledger-entry.json"))
    _write_json(entry_dir / "commitment.sigstore.json", _bundle(entry_dir / "commitment.json"))
    result = public_ledger.verify_entry(
        entry_dir,
        cosign_path=None,
        trusted_root_path=None,
        expected_repository=REPOSITORY,
    )
    assert result["artifact_integrity_verified"] is True
    assert result["cryptographic_signature_verified"] is False
    github = result["entry"]["github"]
    assert github["source_run_head_sha"] == "b" * 40
    assert github["source_run_url"] == "https://github.com/example/ravage/actions/runs/50"
    assert github["source_branch"] == "paired-xben-intake/campaign-001-commitment"
    ledger = public_ledger.verify_ledger(tmp_path / "ledger")
    assert ledger["fixed_repository_phase_path_format_verified"] is True
    assert ledger["github_release_immutability_verified_offline"] is False
    assert ledger["prepublication_repository_admin_override_excluded"] is False
    assert ledger["independently_administered_namespace_verified"] is False
    assert ledger["no_alternative_commitments_verified"] is False
    assert ledger["public_execution_verified"] is False
    assert ledger["sota_claim_supported"] is False
    assert ledger["claim_ready"] is False


def test_offline_verification_rejects_unbound_always_success_cosign(tmp_path: Path) -> None:
    campaign = _campaign(tmp_path)
    committed_cosign = tmp_path / "committed-cosign"
    committed_cosign.write_bytes(b"#!/bin/sh\nexit 1\n")
    committed_cosign.chmod(0o700)
    trusted_root = _bind_crypto_inputs(campaign, committed_cosign)
    submission = tmp_path / "submission"
    public_ledger.create_submission(campaign, submission, phase="commitment")
    entry_dir = _prepare_commitment_entry(tmp_path, submission)
    _write_json(entry_dir / "ledger-entry.sigstore.json", _bundle(entry_dir / "ledger-entry.json"))
    _write_json(entry_dir / "commitment.sigstore.json", _bundle(entry_dir / "commitment.json"))

    always_success = tmp_path / "always-success-cosign"
    always_success.write_bytes(b"#!/bin/sh\nexit 0\n")
    always_success.chmod(0o700)
    with pytest.raises(public_ledger.PublicLedgerError, match="Cosign differs"):
        public_ledger.verify_entry(
            entry_dir,
            cosign_path=always_success,
            trusted_root_path=trusted_root,
            expected_repository=REPOSITORY,
        )


def test_offline_verification_rejects_substituted_trusted_root(tmp_path: Path) -> None:
    campaign = _campaign(tmp_path)
    committed_cosign = tmp_path / "committed-cosign"
    committed_cosign.write_bytes(b"#!/bin/sh\nexit 0\n")
    committed_cosign.chmod(0o700)
    _bind_crypto_inputs(campaign, committed_cosign)
    submission = tmp_path / "submission"
    public_ledger.create_submission(campaign, submission, phase="commitment")
    entry_dir = _prepare_commitment_entry(tmp_path, submission)
    _write_json(entry_dir / "ledger-entry.sigstore.json", _bundle(entry_dir / "ledger-entry.json"))
    _write_json(entry_dir / "commitment.sigstore.json", _bundle(entry_dir / "commitment.json"))

    substituted_root = tmp_path / "attacker-trusted-root.json"
    substituted_root.write_text('{"attacker_root":true}\n', encoding="utf-8")
    with pytest.raises(public_ledger.PublicLedgerError, match="trusted root differs"):
        public_ledger.verify_entry(
            entry_dir,
            cosign_path=committed_cosign,
            trusted_root_path=substituted_root,
            expected_repository=REPOSITORY,
        )


def test_cosign_verification_is_forced_offline() -> None:
    require_offline = b"""#!/bin/sh
for value in "$@"; do
  if [ "$value" = "--offline" ]; then
    exit 0
  fi
done
exit 92
"""
    public_ledger._verify_cosign(
        require_offline,
        b"{}\n",
        artifact_bytes=b"artifact",
        bundle_bytes=b"{}\n",
        identity=IDENTITY,
        repository=REPOSITORY,
        workflow_sha=SOURCE_SHA,
    )


def test_signing_config_and_bundle_require_official_timestamp_evidence(
    tmp_path: Path,
) -> None:
    config = {
        "mediaType": public_ledger.SIGNING_CONFIG_MEDIA_TYPE,
        "tsaUrls": [
            {
                "url": public_ledger.OFFICIAL_TSA_URL,
                "operator": "sigstore.dev",
                "majorApiVersion": 1,
            }
        ],
        "rekorTlogUrls": [
            {
                "url": public_ledger.OFFICIAL_REKOR_URL,
                "operator": "sigstore.dev",
                "majorApiVersion": 1,
            }
        ],
    }
    config_path = tmp_path / "signing-config.json"
    _write_json(config_path, config)
    assert public_ledger.validate_signing_config(config_path) == config
    config["tsaUrls"].append(
        {"url": "https://operator.invalid", "operator": "other", "majorApiVersion": 1}
    )
    _write_json(tmp_path / "bad-config.json", config)
    with pytest.raises(public_ledger.PublicLedgerError, match="sole configured TSA"):
        public_ledger.validate_signing_config(tmp_path / "bad-config.json")

    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"exact bytes")
    bundle_path = tmp_path / "bundle.json"
    _write_json(bundle_path, _bundle(artifact))
    public_ledger.validate_sigstore_bundle(bundle_path, artifact)
    artifact.write_bytes(b"different bytes")
    with pytest.raises(public_ledger.PublicLedgerError, match="differs from the artifact"):
        public_ledger.validate_sigstore_bundle(bundle_path, artifact)


def test_workflows_are_pinned_create_only_and_have_untrusted_ingress() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    publication = (repository_root / ".github/workflows/paired-xben.yml").read_text(
        encoding="utf-8"
    )
    intake = (repository_root / ".github/workflows/paired-xben-intake.yml").read_text(
        encoding="utf-8"
    )
    action_refs = re.findall(r"uses:\s+[^@\s]+@([^\s]+)", publication + intake)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert "id-token: write" in publication
    assert "secrets.PAIRED_XBEN_ADMIN_READ_TOKEN" in publication
    assert "Public-ledger publication is disabled" in publication
    assert publication.index("Public-ledger publication is disabled") < publication.index(
        "actions/download-artifact"
    )
    block = publication.index("Public-ledger publication is disabled")
    assert publication.index("exit 1", block) < publication.index("actions/setup-python")
    block_step = publication[
        publication.rfind("- name:", 0, block) : publication.index("- name: Set up Python", block)
    ]
    assert "if:" not in block_step
    assert '"repos/${GITHUB_REPOSITORY}/immutable-releases"' in publication
    assert '.default_branch == "main"' in publication
    assert "GITHUB_RUN_ATTEMPT" in publication
    assert "actions/runs/${SOURCE_RUN_ID}" in publication
    assert '.path == ".github/workflows/paired-xben-intake.yml"' in publication
    assert ".head_branch == $branch" in publication
    assert "source-intake-workflow.yml" in publication
    assert "cmp -s .github/workflows/paired-xben-intake.yml" in publication
    assert '--source-run-head-sha "${SOURCE_RUN_HEAD_SHA}"' in publication
    assert "paired-xben-submission-${SOURCE_RUN_ID}" in publication
    assert publication.index('"repos/${GITHUB_REPOSITORY}/git/refs"') < publication.index(
        "cosign sign-blob"
    )
    assert "--clobber" not in publication
    assert ".immutable == true" in publication
    assert "overwrite: false" in publication
    assert "workflow_dispatch:" not in intake
    assert "permissions:\n  contents: read" in intake
    assert "secrets." not in intake
    assert "id-token" not in intake
    assert "paired-xben-intake/**" in intake
    assert "paired-xben-submission-${{ github.run_id }}" in intake
    assert "overwrite: false" in intake
