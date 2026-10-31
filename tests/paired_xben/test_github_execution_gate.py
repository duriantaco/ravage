# ruff: noqa: PLR2004,TC003
from __future__ import annotations

import hashlib
import json
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from tools.paired_xben import github_execution_gate, github_runner
from tools.paired_xben.protocol import canonical_json

REPOSITORY = "duriantaco/ravage"
WORKFLOW_SHA = "1" * 40
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
CAMPAIGN = github_execution_gate.CampaignBinding(
    campaign_id="paired-xben-public-20260912",
    commitment_digest=SHA_A,
    selection_digest=SHA_B,
    primary_matrix_digest=SHA_C,
    pair_matrix_digest=SHA_D,
)


def _document(body: dict[str, object]) -> dict[str, object]:
    digest = "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
    return {**body, "document_digest": digest}


def _environment(*, run_id: int = 987654, attempt: int = 1) -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_SHA": WORKFLOW_SHA,
        "GITHUB_WORKFLOW_SHA": WORKFLOW_SHA,
        "GITHUB_RUN_ID": str(run_id),
        "GITHUB_RUN_ATTEMPT": str(attempt),
        "GITHUB_WORKFLOW_REF": (
            f"{REPOSITORY}/.github/workflows/paired-xben-execution.yml@refs/heads/main"
        ),
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }


def _reservation(*, run_id: int = 987654) -> dict[str, object]:
    return _document(
        {
            "schema_version": github_runner.EXECUTION_RESERVATION_SCHEMA,
            "campaign_id": CAMPAIGN.campaign_id,
            "commitment_digest": CAMPAIGN.commitment_digest,
            "selection_digest": CAMPAIGN.selection_digest,
            "primary_matrix_digest": CAMPAIGN.primary_matrix_digest,
            "pair_matrix_digest": CAMPAIGN.pair_matrix_digest,
            "repository": REPOSITORY,
            "workflow_path": github_execution_gate.EXECUTION_WORKFLOW_PATH,
            "workflow_sha": WORKFLOW_SHA,
            "workflow_run_id": run_id,
            "workflow_run_attempt": 1,
            "github_event": "workflow_dispatch",
            "github_ref": "refs/heads/main",
            "pair_jobs": 20,
            "primary_rows": 40,
            "retry_resume_or_replacement_allowed": False,
        }
    )


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _release_fixture(
    root: Path,
    *,
    reservation: dict[str, object] | None = None,
) -> tuple[Path, Path, dict[str, object]]:
    release = root / "start-release"
    release.mkdir()
    raw_reservation = (
        json.dumps(reservation or _reservation(), separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )
    payload = release / "payload.zip"
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(github_execution_gate.RESERVATION_MEMBER, raw_reservation)
    (release / "ledger-entry.json").write_bytes(b'{"signed":"entry"}\n')
    (release / "ledger-entry.sigstore.json").write_bytes(b'{"signed":"bundle"}\n')
    artifacts = [
        {
            "path": github_execution_gate.RESERVATION_MEMBER,
            "sha256": _sha(raw_reservation),
            "size_bytes": len(raw_reservation),
        }
    ]
    entry: dict[str, object] = {
        "phase": "start",
        "phase_ordinal": 3,
        "campaign_id": CAMPAIGN.campaign_id,
        "document_sha256": SHA_D,
        "bindings": {
            "campaign_id": CAMPAIGN.campaign_id,
            "commitment_document_sha256": CAMPAIGN.commitment_digest,
            "selection_document_sha256": CAMPAIGN.selection_digest,
            "primary_matrix_document_sha256": CAMPAIGN.primary_matrix_digest,
        },
        "github": {
            "repository": REPOSITORY,
            "release_tag": f"paired-xben-v1/{CAMPAIGN.campaign_id}/03-start",
            "release_id": 12345,
        },
        "artifacts": artifacts,
    }
    asset_records = []
    for path in sorted(release.iterdir()):
        raw = path.read_bytes()
        asset_records.append(
            {
                "name": path.name,
                "state": "uploaded",
                "size": len(raw),
                "digest": _sha(raw),
            }
        )
    tag = f"paired-xben-v1/{CAMPAIGN.campaign_id}/03-start"
    observation = {
        "id": 12345,
        "tag_name": tag,
        "html_url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}",
        "draft": False,
        "prerelease": True,
        "immutable": True,
        "published_at": "2026-09-12T00:00:00Z",
        "assets": asset_records,
    }
    observation_path = root / "release-observation.json"
    observation_path.write_text(json.dumps(observation), encoding="utf-8")
    return release, observation_path, entry


def _admit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    reservation: dict[str, object] | None = None,
    environment: dict[str, str] | None = None,
    campaign: github_execution_gate.CampaignBinding = CAMPAIGN,
) -> dict[str, object]:
    release, observation, entry = _release_fixture(tmp_path, reservation=reservation)
    monkeypatch.setattr(
        github_execution_gate.public_ledger,
        "verify_entry",
        lambda *_args, **_kwargs: {
            "entry": entry,
            "cryptographic_signature_verified": True,
        },
    )
    return github_execution_gate.admit_public_start(
        start_release_dir=release,
        release_observation_path=observation,
        cosign_path=tmp_path / "cosign",
        trusted_root_path=tmp_path / "trusted-root.json",
        campaign=campaign,
        environment=environment or _environment(),
        output_path=tmp_path / "admission.json",
    )


def test_live_binding_requires_protected_first_attempt_and_no_provider_secret() -> None:
    binding = github_execution_gate.live_github_run_binding(_environment())
    assert binding.run_id == 987654
    assert binding.run_attempt == 1

    rerun = _environment(attempt=2)
    with pytest.raises(github_execution_gate.GithubExecutionAdmissionError, match="reruns"):
        github_execution_gate.live_github_run_binding(rerun)

    secret_bearing = _environment()
    secret_bearing["OPENAI_API_KEY"] = "must-not-enter-authorization-job"
    with pytest.raises(
        github_execution_gate.GithubExecutionAdmissionError, match="provider secret"
    ):
        github_execution_gate.live_github_run_binding(secret_bearing)

    unprotected = _environment()
    unprotected["GITHUB_REF_PROTECTED"] = "false"
    with pytest.raises(github_execution_gate.GithubExecutionAdmissionError, match="REF_PROTECTED"):
        github_execution_gate.live_github_run_binding(unprotected)

    workflow_copy = _environment()
    workflow_copy["GITHUB_WORKFLOW_SHA"] = "2" * 40
    with pytest.raises(
        github_execution_gate.GithubExecutionAdmissionError,
        match="workflow bytes and checked-out source",
    ):
        github_execution_gate.live_github_run_binding(workflow_copy)


def test_public_start_admits_only_the_run_named_by_immutable_signed_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admission = _admit(tmp_path, monkeypatch)

    assert admission["github"]["run_id"] == 987654  # type: ignore[index]
    assert admission["public_start"]["release_immutable_observed_online"] is True  # type: ignore[index]
    assert admission["policy"]["paid_execution_permitted_after_revalidation"] is True  # type: ignore[index]
    assert (
        github_execution_gate.validate_admission_receipt(
            admission,
            campaign=CAMPAIGN,
            environment=_environment(),
        )
        == admission
    )


def test_second_operator_selected_run_cannot_reuse_the_public_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(
        github_execution_gate.GithubExecutionAdmissionError,
        match="does not reserve this exact execution workflow run",
    ):
        _admit(tmp_path, monkeypatch, environment=_environment(run_id=987655))


def test_rerun_cannot_reuse_the_public_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(github_execution_gate.GithubExecutionAdmissionError, match="reruns"):
        _admit(tmp_path, monkeypatch, environment=_environment(attempt=2))


def test_copied_campaign_cannot_reuse_the_public_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied = github_execution_gate.CampaignBinding(
        campaign_id=CAMPAIGN.campaign_id,
        commitment_digest=CAMPAIGN.commitment_digest,
        selection_digest="sha256:" + "9" * 64,
        primary_matrix_digest=CAMPAIGN.primary_matrix_digest,
        pair_matrix_digest=CAMPAIGN.pair_matrix_digest,
    )
    with pytest.raises(
        github_execution_gate.GithubExecutionAdmissionError,
        match="selection_document_sha256",
    ):
        _admit(tmp_path, monkeypatch, campaign=copied)


def test_start_reservation_with_operator_selected_run_id_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(
        github_execution_gate.GithubExecutionAdmissionError,
        match="does not reserve this exact execution workflow run",
    ):
        _admit(tmp_path, monkeypatch, reservation=_reservation(run_id=111111))


def test_mutable_release_observation_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, observation_path, entry = _release_fixture(tmp_path)
    observation = json.loads(observation_path.read_text())
    observation["immutable"] = False
    observation_path.write_text(json.dumps(observation), encoding="utf-8")
    monkeypatch.setattr(
        github_execution_gate.public_ledger,
        "verify_entry",
        lambda *_args, **_kwargs: {
            "entry": entry,
            "cryptographic_signature_verified": True,
        },
    )

    with pytest.raises(github_execution_gate.GithubExecutionAdmissionError, match="immutable"):
        github_execution_gate.admit_public_start(
            start_release_dir=release,
            release_observation_path=observation_path,
            cosign_path=tmp_path / "cosign",
            trusted_root_path=tmp_path / "trusted-root.json",
            campaign=CAMPAIGN,
            environment=_environment(),
            output_path=tmp_path / "admission.json",
        )


def test_matrix_worker_revalidation_rejects_copied_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admission = _admit(tmp_path, monkeypatch)
    copied = deepcopy(admission)
    copied["github"]["run_id"] = 123  # type: ignore[index]
    copied.pop("document_digest")
    copied = _document(copied)

    with pytest.raises(
        github_execution_gate.GithubExecutionAdmissionError,
        match="another workflow run",
    ):
        github_execution_gate.validate_admission_receipt(
            copied,
            campaign=CAMPAIGN,
            environment=_environment(),
        )
