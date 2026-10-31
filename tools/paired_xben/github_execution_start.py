# ruff: noqa: C901,D202,D213,EM101,EM102,PLR0913,PLR0915,PLR2004,TRY003
"""Prepare a same-run paired-XBEN public-start overlay without spending.

This command is intended for the secretless authorization job of the fixed
GitHub execution workflow.  It verifies the immutable, signed ``02-matrix``
release, derives the complete pair matrix, and binds ``03-start`` documents to
the *current* first-attempt GitHub run.  Run identity is read only from GitHub's
live environment; there is no run-ID, SHA, subset, retry, or replacement input.

The output is only an overlay for a future same-run public-ledger publisher.
This module does not reserve a tag, create a release, start Docker or a target,
read a provider key, or permit model execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Final, cast

from tools.paired_xben import public_ledger
from tools.paired_xben.github_execution_gate import (
    EXECUTION_WORKFLOW_PATH,
    CampaignBinding,
    GithubExecutionAdmissionError,
    live_github_run_binding,
)
from tools.paired_xben.github_runner import (
    BOUNDARY_KIND,
    EXECUTION_RESERVATION_SCHEMA,
    EXPECTED_PAIRS,
    EXPECTED_ROWS,
    GITHUB_EXECUTION_START_SCHEMA,
    GithubRunnerContractError,
    build_pair_job_matrix,
    load_json,
    validate_execution_reservation,
    validate_github_execution_start,
    write_json_exclusive,
)
from tools.paired_xben.protocol import PRIMARY_MATRIX_SCHEMA, canonical_json

MATRIX_PHASE: Final = "matrix"
MATRIX_ORDINAL: Final = 2
MATRIX_SELECTION_MEMBER: Final = "resolution/selection.json"
MATRIX_RESERVATION_MEMBER: Final = "attempts/primary-reservation.json"
OUTPUT_PAIR_MATRIX: Final = "execution/github-pair-matrix.json"
OUTPUT_RESERVATION: Final = "execution/github-execution-reservation.json"
OUTPUT_START: Final = "execution/start.json"

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_EXPECTED_RELEASE_ASSETS = frozenset(
    {"ledger-entry.json", "ledger-entry.sigstore.json", "payload.zip"}
)
_PRIMARY_MATRIX_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_id",
        "commitment_digest",
        "selection_digest",
        "created_at",
        "primary_directory",
        "scheduled_primary_attempts",
        "attempts",
        "attempt_documents_digest",
        "policy",
        "document_digest",
    }
)
_MAX_ARCHIVE_BYTES = 1600 * 1024 * 1024
_MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


class GithubExecutionStartError(ValueError):
    """The signed matrix cannot authorize a same-run public start."""


def prepare_same_run_start_overlay(
    *,
    matrix_release_dir: Path,
    release_observation_path: Path,
    cosign_path: Path,
    trusted_root_path: Path,
    environment: Mapping[str, str],
    output_dir: Path,
) -> dict[str, object]:
    """Verify ``02-matrix`` and emit create-only start documents for this run."""

    try:
        live = live_github_run_binding(environment)
    except GithubExecutionAdmissionError as exc:
        raise GithubExecutionStartError("live GitHub execution binding is not admissible") from exc

    root = _directory(matrix_release_dir, "matrix release directory")
    try:
        verified = public_ledger.verify_entry(
            root,
            cosign_path=cosign_path,
            trusted_root_path=trusted_root_path,
            expected_repository=live.repository,
        )
    except (OSError, public_ledger.PublicLedgerError) as exc:
        raise GithubExecutionStartError(
            "matrix ledger entry did not verify cryptographically"
        ) from exc
    if verified.get("cryptographic_signature_verified") is not True:
        raise GithubExecutionStartError("matrix release lacks cryptographic verification")
    entry = _mapping(verified.get("entry"), "matrix ledger entry")
    if entry.get("phase") != MATRIX_PHASE or entry.get("phase_ordinal") != MATRIX_ORDINAL:
        raise GithubExecutionStartError("verified release is not a matrix phase")
    campaign_id = _campaign_id(entry.get("campaign_id"))
    github = _mapping(entry.get("github"), "matrix ledger GitHub receipt")
    expected_tag = f"paired-xben-v1/{campaign_id}/02-matrix"
    release_id = _positive_int(github.get("release_id"), "matrix release ID")
    if (
        github.get("repository") != live.repository
        or github.get("release_tag") != expected_tag
        or github.get("workflow_sha") != live.workflow_sha
    ):
        raise GithubExecutionStartError(
            "signed matrix repository, tag, or source revision differs from this run"
        )
    _validate_release_observation(
        load_json(release_observation_path, label="online matrix release observation"),
        expected_tag=expected_tag,
        expected_release_id=release_id,
        expected_repository=live.repository,
        local_assets=_local_assets(root),
    )

    bindings = _mapping(entry.get("bindings"), "matrix ledger bindings")
    commitment_digest = _digest(bindings.get("commitment_document_sha256"), "commitment digest")
    selection_digest = _digest(bindings.get("selection_document_sha256"), "selection digest")
    primary_matrix_digest = _digest(
        bindings.get("primary_matrix_document_sha256"), "primary matrix digest"
    )
    if bindings.get("campaign_id") != campaign_id:
        raise GithubExecutionStartError("matrix ledger copied a different campaign")

    payload_path = root / "payload.zip"
    selection = _zip_json(payload_path, MATRIX_SELECTION_MEMBER)
    primary_matrix = _zip_json(payload_path, MATRIX_RESERVATION_MEMBER)
    if _verified_document_digest(selection, "selection") != selection_digest:
        raise GithubExecutionStartError("signed selection digest differs from its matrix binding")
    if selection.get("campaign_id") != campaign_id:
        raise GithubExecutionStartError("signed selection belongs to another campaign")
    if selection.get("commitment_digest") != commitment_digest:
        raise GithubExecutionStartError("signed selection has a different commitment")
    _validate_primary_matrix(
        primary_matrix,
        campaign_id=campaign_id,
        commitment_digest=commitment_digest,
        selection_digest=selection_digest,
        primary_matrix_digest=primary_matrix_digest,
    )
    try:
        pair_matrix = build_pair_job_matrix(selection)
    except GithubRunnerContractError as exc:
        raise GithubExecutionStartError(
            "signed selection cannot produce the exact complete pair matrix"
        ) from exc
    pair_matrix_digest = _digest(pair_matrix.get("document_digest"), "pair matrix digest")
    campaign = CampaignBinding(
        campaign_id=campaign_id,
        commitment_digest=commitment_digest,
        selection_digest=selection_digest,
        primary_matrix_digest=primary_matrix_digest,
        pair_matrix_digest=pair_matrix_digest,
    )
    reservation = _document(
        {
            "schema_version": EXECUTION_RESERVATION_SCHEMA,
            "campaign_id": campaign.campaign_id,
            "commitment_digest": campaign.commitment_digest,
            "selection_digest": campaign.selection_digest,
            "primary_matrix_digest": campaign.primary_matrix_digest,
            "pair_matrix_digest": campaign.pair_matrix_digest,
            "repository": live.repository,
            "workflow_path": EXECUTION_WORKFLOW_PATH,
            "workflow_sha": live.workflow_sha,
            "workflow_run_id": live.run_id,
            "workflow_run_attempt": 1,
            "github_event": "workflow_dispatch",
            "github_ref": "refs/heads/main",
            "pair_jobs": EXPECTED_PAIRS,
            "primary_rows": EXPECTED_ROWS,
            "retry_resume_or_replacement_allowed": False,
        }
    )
    try:
        validate_execution_reservation(
            reservation,
            campaign_id=campaign.campaign_id,
            commitment_digest=campaign.commitment_digest,
            selection_digest=campaign.selection_digest,
            primary_matrix_digest=campaign.primary_matrix_digest,
            pair_matrix_digest=campaign.pair_matrix_digest,
            repository=live.repository,
            workflow_sha=live.workflow_sha,
            workflow_run_id=live.run_id,
        )
    except GithubRunnerContractError as exc:  # pragma: no cover - construction invariant
        raise GithubExecutionStartError("constructed execution reservation is invalid") from exc

    include = cast("list[Mapping[str, object]]", pair_matrix["include"])
    row_ids = [
        cast("str", job[field]) for job in include for field in ("first_slot_id", "second_slot_id")
    ]
    pair_ids = [cast("str", job["pair_id"]) for job in include]
    start = _document(
        {
            "schema_version": GITHUB_EXECUTION_START_SCHEMA,
            "campaign_id": campaign.campaign_id,
            "commitment_digest": campaign.commitment_digest,
            "selection_digest": campaign.selection_digest,
            "primary_matrix_digest": campaign.primary_matrix_digest,
            "pair_matrix_digest": campaign.pair_matrix_digest,
            "execution_reservation_digest": reservation["document_digest"],
            "evidence_class": BOUNDARY_KIND,
            "official_attestation_eligible": False,
            "registered_row_count": EXPECTED_ROWS,
            "registered_row_ids": row_ids,
            "registered_pair_job_count": EXPECTED_PAIRS,
            "registered_pair_job_ids": pair_ids,
            "github": {
                "repository": live.repository,
                "workflow_path": EXECUTION_WORKFLOW_PATH,
                "workflow_ref": live.workflow_ref,
                "workflow_sha": live.workflow_sha,
                "workflow_run_id": live.run_id,
                "workflow_run_attempt": 1,
            },
            "policy": {
                "public_start_immutable_before_model_or_target": True,
                "authorization_job_provider_secret_present": False,
                "pair_job_revalidates_same_run_admission_before_secret": True,
                "resume_allowed": False,
                "row_retry_allowed": False,
                "row_replacement_allowed": False,
                "adjacent_pair_schedule": True,
                "failed_or_missing_row_is_terminal_not_replaced": True,
            },
        }
    )
    try:
        validate_github_execution_start(
            start,
            reservation=reservation,
            pair_matrix=pair_matrix,
            selection=selection,
            campaign_id=campaign.campaign_id,
            commitment_digest=campaign.commitment_digest,
            selection_digest=campaign.selection_digest,
            primary_matrix_digest=campaign.primary_matrix_digest,
            repository=live.repository,
            workflow_sha=live.workflow_sha,
        )
    except GithubRunnerContractError as exc:  # pragma: no cover - construction invariant
        raise GithubExecutionStartError("constructed GitHub execution start is invalid") from exc

    destination = _create_directory(output_dir, "start overlay directory")
    execution = _create_child_directory(destination, "execution")
    write_json_exclusive(execution / "github-pair-matrix.json", pair_matrix)
    write_json_exclusive(execution / "github-execution-reservation.json", reservation)
    write_json_exclusive(execution / "start.json", start)
    return {
        "campaign": campaign,
        "pair_matrix": pair_matrix,
        "reservation": reservation,
        "start": start,
        "output_paths": (OUTPUT_PAIR_MATRIX, OUTPUT_RESERVATION, OUTPUT_START),
        "paid_execution_permitted": False,
        "public_start_published": False,
    }


def _validate_primary_matrix(
    value: Mapping[str, object],
    *,
    campaign_id: str,
    commitment_digest: str,
    selection_digest: str,
    primary_matrix_digest: str,
) -> None:
    if set(value) != _PRIMARY_MATRIX_FIELDS:
        raise GithubExecutionStartError("primary matrix fields are invalid")
    if _verified_document_digest(value, "primary matrix") != primary_matrix_digest:
        raise GithubExecutionStartError("primary matrix digest differs from its ledger binding")
    attempts = value.get("attempts")
    if not isinstance(attempts, list) or len(attempts) != EXPECTED_ROWS:
        raise GithubExecutionStartError("primary matrix is not the exact forty-row reservation")
    expected_slots = [f"primary-{index:03d}" for index in range(1, EXPECTED_ROWS + 1)]
    if [
        item.get("slot_id") if isinstance(item, Mapping) else None for item in attempts
    ] != expected_slots:
        raise GithubExecutionStartError("primary matrix slots are incomplete or reordered")
    if (
        value.get("schema_version") != PRIMARY_MATRIX_SCHEMA
        or value.get("campaign_id") != campaign_id
        or value.get("commitment_digest") != commitment_digest
        or value.get("selection_digest") != selection_digest
        or value.get("primary_directory") != "primary"
        or value.get("scheduled_primary_attempts") != EXPECTED_ROWS
        or value.get("policy")
        != {
            "all_slots_reserved_before_execution": True,
            "resume_incomplete_reservation": False,
            "replace_primary_attempt": False,
        }
    ):
        raise GithubExecutionStartError("primary matrix permits substitution or is misbound")


def _validate_release_observation(
    observation: Mapping[str, object],
    *,
    expected_tag: str,
    expected_release_id: int,
    expected_repository: str,
    local_assets: Mapping[str, tuple[str, int]],
) -> None:
    expected_url = f"https://github.com/{expected_repository}/releases/tag/{expected_tag}"
    if (
        observation.get("id") != expected_release_id
        or observation.get("tag_name") != expected_tag
        or observation.get("html_url") != expected_url
        or observation.get("draft") is not False
        or observation.get("prerelease") is not True
        or observation.get("immutable") is not True
        or not isinstance(observation.get("published_at"), str)
        or not observation.get("published_at")
    ):
        raise GithubExecutionStartError("GitHub does not report the exact matrix release immutable")
    assets = observation.get("assets")
    if not isinstance(assets, list) or len(assets) != len(_EXPECTED_RELEASE_ASSETS):
        raise GithubExecutionStartError("online matrix release asset set is invalid")
    observed: dict[str, tuple[str, int]] = {}
    for raw in assets:
        asset = _mapping(raw, "online matrix release asset")
        name = asset.get("name")
        if (
            not isinstance(name, str)
            or name not in _EXPECTED_RELEASE_ASSETS
            or name in observed
            or asset.get("state") != "uploaded"
        ):
            raise GithubExecutionStartError("online matrix release asset is invalid")
        observed[name] = (
            _digest(asset.get("digest"), f"matrix release asset {name} digest"),
            _positive_int(asset.get("size"), f"matrix release asset {name} size"),
        )
    if observed != dict(local_assets):
        raise GithubExecutionStartError(
            "downloaded matrix assets differ from GitHub's immutable release observation"
        )


def _local_assets(root: Path) -> dict[str, tuple[str, int]]:
    names = {item.name for item in root.iterdir()}
    if names != _EXPECTED_RELEASE_ASSETS:
        raise GithubExecutionStartError("downloaded matrix release asset set is not exact")
    result: dict[str, tuple[str, int]] = {}
    for name in sorted(names):
        path = _regular_file(root / name, f"matrix release asset {name}")
        raw = path.read_bytes()
        result[name] = (_sha256(raw), len(raw))
    return result


def _zip_json(path: Path, member: str) -> dict[str, object]:
    archive_path = _regular_file(path, "matrix payload archive")
    if archive_path.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise GithubExecutionStartError("matrix payload archive exceeds its byte limit")
    pure = PurePosixPath(member)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != member:
        raise GithubExecutionStartError("matrix payload member path is invalid")
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            matches = [info for info in archive.infolist() if info.filename == member]
            if len(matches) != 1:
                raise GithubExecutionStartError(f"matrix payload lacks one exact {member} member")
            info = matches[0]
            if info.is_dir() or info.file_size > _MAX_DOCUMENT_BYTES:
                raise GithubExecutionStartError(f"matrix payload member {member} is invalid")
            raw = archive.read(info)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise GithubExecutionStartError("matrix payload archive is unreadable") from exc
    if len(raw) != info.file_size:
        raise GithubExecutionStartError("matrix payload member changed during extraction")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GithubExecutionStartError(f"matrix payload member {member} is malformed") from exc
    if not isinstance(value, dict):
        raise GithubExecutionStartError(f"matrix payload member {member} must be an object")
    return cast("dict[str, object]", value)


def _verified_document_digest(value: Mapping[str, object], label: str) -> str:
    observed = _digest(value.get("document_digest"), f"{label} digest")
    body = {name: member for name, member in value.items() if name != "document_digest"}
    if _digest_value(body) != observed:
        raise GithubExecutionStartError(f"{label} digest does not verify")
    return observed


def _document(body: Mapping[str, object]) -> dict[str, object]:
    value = dict(body)
    return {**value, "document_digest": _digest_value(value)}


def _digest_value(value: object) -> str:
    return _sha256(canonical_json(value).encode("utf-8"))


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise GithubExecutionStartError("JSON document contains a duplicate member name")
        result[name] = value
    return result


def _directory(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise GithubExecutionStartError(f"{label} must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise GithubExecutionStartError(f"{label} is unavailable") from exc
    if not resolved.is_dir():
        raise GithubExecutionStartError(f"{label} must be a directory")
    return resolved


def _create_directory(path: Path, label: str) -> Path:
    candidate = path.expanduser().absolute()
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise GithubExecutionStartError(f"{label} parent is unavailable") from exc
    if candidate.parent.absolute() != parent or candidate.exists() or candidate.is_symlink():
        raise GithubExecutionStartError(f"{label} must be a new canonical path")
    try:
        candidate.mkdir(mode=0o700)
    except OSError as exc:
        raise GithubExecutionStartError(f"could not create {label}") from exc
    return candidate


def _create_child_directory(parent: Path, name: str) -> Path:
    target = parent / name
    try:
        target.mkdir(mode=0o700)
    except OSError as exc:
        raise GithubExecutionStartError(f"could not create start overlay child {name}") from exc
    return target


def _regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GithubExecutionStartError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GithubExecutionStartError(f"{label} must be a regular file")
    return path


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise GithubExecutionStartError(f"{label} must be an object")
    return cast("Mapping[str, object]", value)


def _campaign_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) < 3
        or len(value) > 80
        or not value[0].isalnum()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value)
    ):
        raise GithubExecutionStartError("campaign ID is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise GithubExecutionStartError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GithubExecutionStartError(f"{label} must be a positive integer")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-release-dir", type=Path, required=True)
    parser.add_argument("--release-observation", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        prepare_same_run_start_overlay(
            matrix_release_dir=args.matrix_release_dir,
            release_observation_path=args.release_observation,
            cosign_path=args.cosign,
            trusted_root_path=args.trusted_root,
            environment=os.environ,
            output_dir=args.output_dir,
        )
    except (GithubExecutionStartError, GithubRunnerContractError) as exc:
        sys.stderr.write(f"blocked: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
