# ruff: noqa: PLR2004,SLF001,TC003
from __future__ import annotations

import hashlib
import json
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from tools.paired_xben import github_execution_start, github_runner
from tools.paired_xben.protocol import PRIMARY_MATRIX_SCHEMA, SELECTION_SCHEMA, canonical_json

REPOSITORY = "duriantaco/ravage"
WORKFLOW_SHA = "1" * 40
COMMITMENT_DIGEST = "sha256:" + "a" * 64


def _document(body: dict[str, object]) -> dict[str, object]:
    digest = "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
    return {**body, "document_digest": digest}


def _selection() -> dict[str, object]:
    cases = [f"XBEN-{number:03d}-24" for number in range(1, 21)]
    schedule: list[dict[str, object]] = []
    for pair_index, case_id in enumerate(cases, start=1):
        systems = ("ravage", "strix") if pair_index % 2 else ("strix", "ravage")
        for position, system in enumerate(systems, start=1):
            slot = len(schedule) + 1
            schedule.append(
                {
                    "slot": slot,
                    "slot_id": f"primary-{slot:03d}",
                    "pair_index": pair_index,
                    "position_within_pair": position,
                    "case_id": case_id,
                    "system": system,
                    "purpose": "primary",
                    "score_eligible": True,
                }
            )
    return _document(
        {
            "schema_version": SELECTION_SCHEMA,
            "campaign_id": "paired-xben-public-20260912",
            "commitment_digest": COMMITMENT_DIGEST,
            "beacon_digest": "sha256:" + "b" * 64,
            "eligible_pool_digest": "sha256:" + "c" * 64,
            "draw_key_sha256": "sha256:" + "d" * 64,
            "algorithms": {},
            "case_ranking": [],
            "selected_case_ids": cases,
            "pair_order": cases,
            "schedule": schedule,
            "attempt_policy": {},
        }
    )


def _primary_matrix(selection: dict[str, object]) -> dict[str, object]:
    attempts = [
        {
            "slot_id": f"primary-{index:03d}",
            "attempt_manifest": f"primary-{index:03d}/attempt.json",
            "artifact_directory": f"primary-{index:03d}/artifacts",
            "attempt_document_digest": "sha256:" + f"{index:064x}",
        }
        for index in range(1, 41)
    ]
    return _document(
        {
            "schema_version": PRIMARY_MATRIX_SCHEMA,
            "campaign_id": selection["campaign_id"],
            "commitment_digest": COMMITMENT_DIGEST,
            "selection_digest": selection["document_digest"],
            "created_at": "2026-09-12T00:00:00Z",
            "primary_directory": "primary",
            "scheduled_primary_attempts": 40,
            "attempts": attempts,
            "attempt_documents_digest": (
                "sha256:" + hashlib.sha256(canonical_json(attempts).encode()).hexdigest()
            ),
            "policy": {
                "all_slots_reserved_before_execution": True,
                "resume_incomplete_reservation": False,
                "replace_primary_attempt": False,
            },
        }
    )


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


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fixture(
    root: Path,
    *,
    entry_workflow_sha: str = WORKFLOW_SHA,
    reorder_primary: bool = False,
) -> tuple[Path, Path, dict[str, object]]:
    root.mkdir(parents=True, exist_ok=True)
    selection = _selection()
    primary = _primary_matrix(selection)
    if reorder_primary:
        primary["attempts"] = list(reversed(primary["attempts"]))  # type: ignore[arg-type]
        primary.pop("document_digest")
        primary = _document(primary)
    release = root / "matrix-release"
    release.mkdir()
    with zipfile.ZipFile(release / "payload.zip", "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            github_execution_start.MATRIX_SELECTION_MEMBER,
            json.dumps(selection, separators=(",", ":"), sort_keys=True) + "\n",
        )
        archive.writestr(
            github_execution_start.MATRIX_RESERVATION_MEMBER,
            json.dumps(primary, separators=(",", ":"), sort_keys=True) + "\n",
        )
    (release / "ledger-entry.json").write_text('{"entry":true}\n', encoding="utf-8")
    (release / "ledger-entry.sigstore.json").write_text('{"bundle":true}\n', encoding="utf-8")
    campaign_id = str(selection["campaign_id"])
    entry: dict[str, object] = {
        "phase": "matrix",
        "phase_ordinal": 2,
        "campaign_id": campaign_id,
        "bindings": {
            "campaign_id": campaign_id,
            "commitment_document_sha256": COMMITMENT_DIGEST,
            "selection_document_sha256": selection["document_digest"],
            "primary_matrix_document_sha256": primary["document_digest"],
        },
        "github": {
            "repository": REPOSITORY,
            "release_tag": f"paired-xben-v1/{campaign_id}/02-matrix",
            "release_id": 321,
            "workflow_sha": entry_workflow_sha,
        },
    }
    assets = []
    for path in sorted(release.iterdir()):
        raw = path.read_bytes()
        assets.append(
            {
                "name": path.name,
                "state": "uploaded",
                "size": len(raw),
                "digest": _sha(raw),
            }
        )
    tag = f"paired-xben-v1/{campaign_id}/02-matrix"
    observation = {
        "id": 321,
        "tag_name": tag,
        "html_url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}",
        "draft": False,
        "prerelease": True,
        "immutable": True,
        "published_at": "2026-09-12T00:00:00Z",
        "assets": assets,
    }
    observation_path = root / "matrix-release.json"
    observation_path.write_text(json.dumps(observation), encoding="utf-8")
    return release, observation_path, entry


def _prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    environment: dict[str, str] | None = None,
    entry_workflow_sha: str = WORKFLOW_SHA,
    reorder_primary: bool = False,
) -> dict[str, object]:
    release, observation, entry = _fixture(
        tmp_path,
        entry_workflow_sha=entry_workflow_sha,
        reorder_primary=reorder_primary,
    )
    monkeypatch.setattr(
        github_execution_start.public_ledger,
        "verify_entry",
        lambda *_args, **_kwargs: {
            "entry": entry,
            "cryptographic_signature_verified": True,
        },
    )
    return github_execution_start.prepare_same_run_start_overlay(
        matrix_release_dir=release,
        release_observation_path=observation,
        cosign_path=tmp_path / "cosign",
        trusted_root_path=tmp_path / "trusted-root.json",
        environment=environment or _environment(),
        output_dir=tmp_path / "start-overlay",
    )


def test_prepares_exact_complete_documents_for_only_the_live_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _prepare(tmp_path, monkeypatch)

    reservation = result["reservation"]
    start = result["start"]
    assert reservation["workflow_run_id"] == 987654  # type: ignore[index]
    assert reservation["workflow_run_attempt"] == 1  # type: ignore[index]
    assert start["registered_row_ids"] == [  # type: ignore[index]
        f"primary-{index:03d}" for index in range(1, 41)
    ]
    assert start["registered_pair_job_ids"] == [  # type: ignore[index]
        f"pair-{index:03d}" for index in range(1, 21)
    ]
    assert result["paid_execution_permitted"] is False
    assert result["public_start_published"] is False
    assert set((tmp_path / "start-overlay" / "execution").iterdir()) == {
        tmp_path / "start-overlay" / github_execution_start.OUTPUT_PAIR_MATRIX,
        tmp_path / "start-overlay" / github_execution_start.OUTPUT_RESERVATION,
        tmp_path / "start-overlay" / github_execution_start.OUTPUT_START,
    }


def test_has_no_operator_run_id_sha_matrix_or_subset_cli_input() -> None:
    destinations = {action.dest for action in github_execution_start._parser()._actions}
    assert not destinations & {
        "campaign_id",
        "workflow_run_id",
        "workflow_sha",
        "pair_indexes",
        "matrix_json",
        "retry",
        "resume",
        "replacement",
    }


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        (_environment(attempt=2), "live GitHub execution binding"),
        ({**_environment(), "OPENAI_API_KEY": "forbidden"}, "live GitHub execution binding"),
        ({**_environment(), "GITHUB_REF_PROTECTED": "false"}, "live GitHub execution binding"),
    ],
)
def test_rerun_secret_bearing_or_unprotected_start_builder_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    environment: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(github_execution_start.GithubExecutionStartError, match=message):
        _prepare(tmp_path, monkeypatch, environment=environment)


def test_missing_external_protocol_verifiers_blocks_before_overlay_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release, observation, _entry = _fixture(tmp_path)

    def require_external_verifiers(*_args: object, **kwargs: object) -> object:
        assert kwargs.get("drand_verifier_path") is None
        assert kwargs.get("protocol_cosign_path") is None
        assert kwargs.get("protocol_trusted_root_path") is None
        raise github_execution_start.public_ledger.PublicLedgerError(
            "post-commitment validation requires trusted external verifier inputs"
        )

    monkeypatch.setattr(
        github_execution_start.public_ledger,
        "verify_entry",
        require_external_verifiers,
    )
    output = tmp_path / "start-overlay"

    with pytest.raises(
        github_execution_start.GithubExecutionStartError,
        match="matrix ledger entry did not verify cryptographically",
    ):
        github_execution_start.prepare_same_run_start_overlay(
            matrix_release_dir=release,
            release_observation_path=observation,
            cosign_path=tmp_path / "cosign",
            trusted_root_path=tmp_path / "trusted-root.json",
            environment=_environment(),
            output_dir=output,
        )

    assert not output.exists()


def test_matrix_from_another_source_revision_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(
        github_execution_start.GithubExecutionStartError,
        match="source revision differs",
    ):
        _prepare(tmp_path, monkeypatch, entry_workflow_sha="2" * 40)


def test_reordered_primary_reservations_are_rejected_even_when_redigested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(
        github_execution_start.GithubExecutionStartError,
        match="incomplete or reordered",
    ):
        _prepare(tmp_path, monkeypatch, reorder_primary=True)


def test_overlay_is_create_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prepare(tmp_path, monkeypatch)
    release, observation, entry = _fixture(tmp_path / "second")
    monkeypatch.setattr(
        github_execution_start.public_ledger,
        "verify_entry",
        lambda *_args, **_kwargs: {
            "entry": entry,
            "cryptographic_signature_verified": True,
        },
    )
    with pytest.raises(
        github_execution_start.GithubExecutionStartError,
        match="new canonical path",
    ):
        github_execution_start.prepare_same_run_start_overlay(
            matrix_release_dir=release,
            release_observation_path=observation,
            cosign_path=tmp_path / "cosign",
            trusted_root_path=tmp_path / "trusted-root.json",
            environment=_environment(),
            output_dir=tmp_path / "start-overlay",
        )


def test_start_validator_rejects_a_redigested_run_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _prepare(tmp_path, monkeypatch)
    start = deepcopy(result["start"])
    assert isinstance(start, dict)
    github = start["github"]
    assert isinstance(github, dict)
    github["workflow_run_id"] = 111111
    start.pop("document_digest")
    start = _document(start)
    reservation = result["reservation"]
    pair_matrix = result["pair_matrix"]
    assert isinstance(reservation, dict)
    assert isinstance(pair_matrix, dict)

    with pytest.raises(github_runner.GithubRunnerContractError, match="reservation"):
        github_runner.validate_github_execution_start(
            start,
            reservation=reservation,
            pair_matrix=pair_matrix,
            selection=_selection(),
            campaign_id=str(start["campaign_id"]),
            commitment_digest=str(start["commitment_digest"]),
            selection_digest=str(start["selection_digest"]),
            primary_matrix_digest=str(start["primary_matrix_digest"]),
            repository=REPOSITORY,
            workflow_sha=WORKFLOW_SHA,
        )
