# ruff: noqa: D202,D213,EM101,EM102,PLR0913,PLR2004,TRY003
"""Public-start admission gate for one paired-XBEN GitHub execution run.

This gate is designed to run in the small authorization job *before* the
20-pair matrix is expanded and before any step receives a provider secret.  It
accepts only the exact first-attempt workflow run named by the cryptographically
verified immutable ``03-start`` release.  Its output is public authorization
evidence, not a credential.

The module never starts Docker, a target, or a model gateway.  A future Linux
pair worker must require and revalidate the emitted admission receipt; the
current implementation assessment keeps that worker disabled.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from tools.paired_xben import public_ledger
from tools.paired_xben.github_runner import (
    GithubRunnerContractError,
    load_json,
    validate_execution_reservation,
    write_json_exclusive,
)
from tools.paired_xben.protocol import canonical_json

ADMISSION_SCHEMA: Final = "ravage.paired-xben.github-execution-admission.v1"
EXECUTION_WORKFLOW_PATH: Final = ".github/workflows/paired-xben-execution.yml"
RESERVATION_MEMBER: Final = "execution/github-execution-reservation.json"
START_PHASE: Final = "start"
START_PHASE_ORDINAL: Final = 3
PROVIDER_SECRET_ENV_NAMES: Final = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
    }
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_CAMPAIGN_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
_RELEASE_FIELDS = frozenset(
    {
        "id",
        "tag_name",
        "html_url",
        "draft",
        "prerelease",
        "immutable",
        "published_at",
        "assets",
    }
)
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_RESERVATION_BYTES = 64 * 1024
_EXPECTED_RELEASE_ASSETS = frozenset(
    {"ledger-entry.json", "ledger-entry.sigstore.json", "payload.zip"}
)


class GithubExecutionAdmissionError(ValueError):
    """The current workflow run is not authorized by the public start."""


@dataclass(frozen=True)
class GithubRunBinding:
    """Unforgeable-by-dispatch live values supplied by GitHub Actions."""

    repository: str
    workflow_sha: str
    run_id: int
    run_attempt: int
    workflow_ref: str


@dataclass(frozen=True)
class CampaignBinding:
    """Frozen protocol digests that a copied campaign may not replace."""

    campaign_id: str
    commitment_digest: str
    selection_digest: str
    primary_matrix_digest: str
    pair_matrix_digest: str


def live_github_run_binding(environment: Mapping[str, str]) -> GithubRunBinding:
    """Validate the authorization job's exact GitHub-controlled environment."""

    leaked = sorted(name for name in PROVIDER_SECRET_ENV_NAMES if environment.get(name))
    if leaked:
        raise GithubExecutionAdmissionError(
            "authorization job received a provider secret before public start admission"
        )
    repository = _repository(environment.get("GITHUB_REPOSITORY"))
    workflow_sha = _git_sha(environment.get("GITHUB_WORKFLOW_SHA"), "GITHUB_WORKFLOW_SHA")
    head_sha = _git_sha(environment.get("GITHUB_SHA"), "GITHUB_SHA")
    if head_sha != workflow_sha:
        raise GithubExecutionAdmissionError(
            "execution workflow bytes and checked-out source are not the same revision"
        )
    run_id = _decimal_positive_int(environment.get("GITHUB_RUN_ID"), "GITHUB_RUN_ID")
    run_attempt = _decimal_positive_int(environment.get("GITHUB_RUN_ATTEMPT"), "GITHUB_RUN_ATTEMPT")
    workflow_ref = f"{repository}/{EXECUTION_WORKFLOW_PATH}@refs/heads/main"
    expected = {
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_WORKFLOW_REF": workflow_ref,
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }
    for name, value in expected.items():
        if environment.get(name) != value:
            raise GithubExecutionAdmissionError(
                f"live workflow environment field {name} is not authorized"
            )
    if run_attempt != 1:
        raise GithubExecutionAdmissionError("GitHub workflow reruns are permanently forbidden")
    return GithubRunBinding(
        repository=repository,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_ref=workflow_ref,
    )


def admit_public_start(
    *,
    start_release_dir: Path,
    release_observation_path: Path,
    cosign_path: Path,
    trusted_root_path: Path,
    campaign: CampaignBinding,
    environment: Mapping[str, str],
    output_path: Path,
) -> dict[str, object]:
    """Verify public start and create one local first-attempt admission receipt."""

    live = live_github_run_binding(environment)
    _validate_campaign_binding(campaign)
    try:
        verified = public_ledger.verify_entry(
            start_release_dir,
            cosign_path=cosign_path,
            trusted_root_path=trusted_root_path,
            expected_repository=live.repository,
        )
    except (OSError, public_ledger.PublicLedgerError) as exc:
        raise GithubExecutionAdmissionError(
            "public start ledger entry did not verify cryptographically"
        ) from exc
    if verified.get("cryptographic_signature_verified") is not True:
        raise GithubExecutionAdmissionError("public start lacks cryptographic verification")
    entry = _mapping(verified.get("entry"), "public start ledger entry")
    if (
        entry.get("phase") != START_PHASE
        or entry.get("phase_ordinal") != START_PHASE_ORDINAL
        or entry.get("campaign_id") != campaign.campaign_id
    ):
        raise GithubExecutionAdmissionError("verified ledger entry is not this campaign's start")
    entry_digest = _digest(entry.get("document_sha256"), "start ledger entry digest")
    entry_github = _mapping(entry.get("github"), "start ledger GitHub receipt")
    release_id = _positive_int(entry_github.get("release_id"), "start release ID")
    expected_tag = f"paired-xben-v1/{campaign.campaign_id}/03-start"
    if (
        entry_github.get("repository") != live.repository
        or entry_github.get("release_tag") != expected_tag
    ):
        raise GithubExecutionAdmissionError("public start release identity is invalid")
    bindings = _mapping(entry.get("bindings"), "start ledger bindings")
    expected_bindings = {
        "campaign_id": campaign.campaign_id,
        "commitment_document_sha256": campaign.commitment_digest,
        "selection_document_sha256": campaign.selection_digest,
        "primary_matrix_document_sha256": campaign.primary_matrix_digest,
    }
    for name, value in expected_bindings.items():
        if bindings.get(name) != value:
            raise GithubExecutionAdmissionError(
                f"public start ledger binding {name!r} differs from the frozen campaign"
            )

    root = _directory(start_release_dir, "start release directory")
    local_assets = _local_release_assets(root)
    observation = load_json(release_observation_path, label="online start release observation")
    _validate_online_release_observation(
        observation,
        expected_tag=expected_tag,
        expected_release_id=release_id,
        expected_repository=live.repository,
        local_assets=local_assets,
    )
    reservation_raw = _read_exact_zip_member(root / "payload.zip", RESERVATION_MEMBER)
    reservation = _decode_json_object(reservation_raw, "GitHub execution reservation")
    try:
        validated_reservation = validate_execution_reservation(
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
    except GithubRunnerContractError as exc:
        raise GithubExecutionAdmissionError(
            "public start does not reserve this exact execution workflow run"
        ) from exc
    reservation_digest = _digest(
        validated_reservation.get("document_digest"), "execution reservation digest"
    )
    _require_artifact_binding(entry, RESERVATION_MEMBER, reservation_raw)

    admission = _with_digest(
        {
            "schema_version": ADMISSION_SCHEMA,
            "campaign_id": campaign.campaign_id,
            "commitment_digest": campaign.commitment_digest,
            "selection_digest": campaign.selection_digest,
            "primary_matrix_digest": campaign.primary_matrix_digest,
            "pair_matrix_digest": campaign.pair_matrix_digest,
            "github": {
                "repository": live.repository,
                "workflow_path": EXECUTION_WORKFLOW_PATH,
                "workflow_ref": live.workflow_ref,
                "workflow_sha": live.workflow_sha,
                "run_id": live.run_id,
                "run_attempt": 1,
            },
            "public_start": {
                "release_tag": expected_tag,
                "release_id": release_id,
                "release_immutable_observed_online": True,
                "ledger_entry_digest": entry_digest,
                "payload_sha256": local_assets["payload.zip"][0],
                "reservation_member": RESERVATION_MEMBER,
                "reservation_digest": reservation_digest,
                "sigstore_cryptographic_signature_verified": True,
                "rekor_and_rfc3161_evidence_verified_by_public_ledger": True,
            },
            "policy": {
                "provider_secret_present_during_admission": False,
                "target_started_during_admission": False,
                "model_gateway_started_during_admission": False,
                "workflow_rerun_allowed": False,
                "different_workflow_run_allowed": False,
                "copied_campaign_allowed": False,
                "paid_execution_permitted_after_revalidation": True,
            },
        }
    )
    write_json_exclusive(output_path, admission)
    return admission


def validate_admission_receipt(
    receipt: Mapping[str, object],
    *,
    campaign: CampaignBinding,
    environment: Mapping[str, str],
) -> dict[str, object]:
    """Revalidate a public admission in every matrix worker before secrets."""

    live = live_github_run_binding(environment)
    _validate_campaign_binding(campaign)
    required = {
        "schema_version",
        "campaign_id",
        "commitment_digest",
        "selection_digest",
        "primary_matrix_digest",
        "pair_matrix_digest",
        "github",
        "public_start",
        "policy",
        "document_digest",
    }
    if set(receipt) != required or receipt.get("schema_version") != ADMISSION_SCHEMA:
        raise GithubExecutionAdmissionError("execution admission receipt fields are invalid")
    _verified_digest(receipt, "execution admission receipt")
    expected_campaign = {
        "campaign_id": campaign.campaign_id,
        "commitment_digest": campaign.commitment_digest,
        "selection_digest": campaign.selection_digest,
        "primary_matrix_digest": campaign.primary_matrix_digest,
        "pair_matrix_digest": campaign.pair_matrix_digest,
    }
    for name, value in expected_campaign.items():
        if receipt.get(name) != value:
            raise GithubExecutionAdmissionError(
                f"execution admission receipt copied a different {name}"
            )
    github = _mapping(receipt.get("github"), "execution admission GitHub binding")
    if github != {
        "repository": live.repository,
        "workflow_path": EXECUTION_WORKFLOW_PATH,
        "workflow_ref": live.workflow_ref,
        "workflow_sha": live.workflow_sha,
        "run_id": live.run_id,
        "run_attempt": 1,
    }:
        raise GithubExecutionAdmissionError("execution admission belongs to another workflow run")
    start = _mapping(receipt.get("public_start"), "execution admission public start")
    if (
        set(start)
        != {
            "release_tag",
            "release_id",
            "release_immutable_observed_online",
            "ledger_entry_digest",
            "payload_sha256",
            "reservation_member",
            "reservation_digest",
            "sigstore_cryptographic_signature_verified",
            "rekor_and_rfc3161_evidence_verified_by_public_ledger",
        }
        or start.get("release_tag") != f"paired-xben-v1/{campaign.campaign_id}/03-start"
        or _positive_int(start.get("release_id"), "start release ID") <= 0
        or start.get("release_immutable_observed_online") is not True
        or _digest(start.get("ledger_entry_digest"), "ledger entry digest")
        != start.get("ledger_entry_digest")
        or _digest(start.get("payload_sha256"), "payload digest") != start.get("payload_sha256")
        or start.get("reservation_member") != RESERVATION_MEMBER
        or _digest(start.get("reservation_digest"), "reservation digest")
        != start.get("reservation_digest")
        or start.get("sigstore_cryptographic_signature_verified") is not True
        or start.get("rekor_and_rfc3161_evidence_verified_by_public_ledger") is not True
    ):
        raise GithubExecutionAdmissionError("execution admission public-start proof is invalid")
    if receipt.get("policy") != {
        "provider_secret_present_during_admission": False,
        "target_started_during_admission": False,
        "model_gateway_started_during_admission": False,
        "workflow_rerun_allowed": False,
        "different_workflow_run_allowed": False,
        "copied_campaign_allowed": False,
        "paid_execution_permitted_after_revalidation": True,
    }:
        raise GithubExecutionAdmissionError("execution admission policy is invalid")
    return dict(receipt)


def _validate_online_release_observation(
    observation: Mapping[str, object],
    *,
    expected_tag: str,
    expected_release_id: int,
    expected_repository: str,
    local_assets: Mapping[str, tuple[str, int]],
) -> None:
    if not set(observation).issuperset(_RELEASE_FIELDS):
        raise GithubExecutionAdmissionError("online release observation fields are incomplete")
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
        raise GithubExecutionAdmissionError(
            "GitHub does not report the exact start release immutable"
        )
    raw_assets = observation.get("assets")
    if not isinstance(raw_assets, list) or len(raw_assets) != len(_EXPECTED_RELEASE_ASSETS):
        raise GithubExecutionAdmissionError("online start release asset set is invalid")
    observed: dict[str, tuple[str, int]] = {}
    for raw in raw_assets:
        asset = _mapping(raw, "online release asset")
        name = asset.get("name")
        if (
            not isinstance(name, str)
            or name not in _EXPECTED_RELEASE_ASSETS
            or name in observed
            or asset.get("state") != "uploaded"
        ):
            raise GithubExecutionAdmissionError("online start release asset is invalid")
        observed[name] = (
            _digest(asset.get("digest"), f"release asset {name} digest"),
            _positive_int(asset.get("size"), f"release asset {name} size"),
        )
    if observed != dict(local_assets):
        raise GithubExecutionAdmissionError(
            "downloaded start assets differ from GitHub's immutable release observation"
        )


def _local_release_assets(root: Path) -> dict[str, tuple[str, int]]:
    names = {item.name for item in root.iterdir()}
    if names != _EXPECTED_RELEASE_ASSETS:
        raise GithubExecutionAdmissionError("downloaded start release asset set is not exact")
    result: dict[str, tuple[str, int]] = {}
    for name in sorted(names):
        path = _regular_file(root / name, f"start release asset {name}")
        raw = path.read_bytes()
        result[name] = (_sha256(raw), len(raw))
    return result


def _read_exact_zip_member(path: Path, member: str) -> bytes:
    archive_path = _regular_file(path, "start payload archive")
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            matches = [info for info in archive.infolist() if info.filename == member]
            if len(matches) != 1:
                raise GithubExecutionAdmissionError(
                    "public start payload lacks one exact execution reservation"
                )
            info = matches[0]
            if info.is_dir() or info.file_size > _MAX_RESERVATION_BYTES:
                raise GithubExecutionAdmissionError("execution reservation member is invalid")
            raw = archive.read(info)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise GithubExecutionAdmissionError("public start payload archive is unreadable") from exc
    if len(raw) != info.file_size or len(raw) > _MAX_RESERVATION_BYTES:
        raise GithubExecutionAdmissionError("execution reservation changed during extraction")
    return raw


def _require_artifact_binding(entry: Mapping[str, object], path: str, raw: bytes) -> None:
    artifacts = entry.get("artifacts")
    if not isinstance(artifacts, list):
        raise GithubExecutionAdmissionError("public start artifact manifest is invalid")
    matches = [item for item in artifacts if isinstance(item, Mapping) and item.get("path") == path]
    if len(matches) != 1:
        raise GithubExecutionAdmissionError("public start does not bind the execution reservation")
    record = matches[0]
    if record.get("sha256") != _sha256(raw) or record.get("size_bytes") != len(raw):
        raise GithubExecutionAdmissionError("execution reservation artifact digest is invalid")


def _validate_campaign_binding(campaign: CampaignBinding) -> None:
    _campaign_id(campaign.campaign_id)
    _digest(campaign.commitment_digest, "commitment digest")
    _digest(campaign.selection_digest, "selection digest")
    _digest(campaign.primary_matrix_digest, "primary matrix digest")
    _digest(campaign.pair_matrix_digest, "pair matrix digest")


def _with_digest(body: Mapping[str, object]) -> dict[str, object]:
    value = dict(body)
    return {**value, "document_digest": _digest_value(value)}


def _verified_digest(value: Mapping[str, object], label: str) -> str:
    observed = _digest(value.get("document_digest"), f"{label} digest")
    body = {name: member for name, member in value.items() if name != "document_digest"}
    if _digest_value(body) != observed:
        raise GithubExecutionAdmissionError(f"{label} digest does not verify")
    return observed


def _digest_value(value: object) -> str:
    return _sha256(canonical_json(value).encode("utf-8"))


def _decode_json_object(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GithubExecutionAdmissionError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict):
        raise GithubExecutionAdmissionError(f"{label} must be a JSON object")
    return cast("dict[str, object]", value)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise GithubExecutionAdmissionError("JSON document contains a duplicate member name")
        result[name] = value
    return result


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise GithubExecutionAdmissionError(f"{label} must be an object")
    return cast("Mapping[str, object]", value)


def _directory(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise GithubExecutionAdmissionError(f"{label} must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise GithubExecutionAdmissionError(f"{label} is unavailable") from exc
    if not resolved.is_dir():
        raise GithubExecutionAdmissionError(f"{label} must be a directory")
    return resolved


def _regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GithubExecutionAdmissionError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GithubExecutionAdmissionError(f"{label} must be a regular file")
    if metadata.st_size > _MAX_JSON_BYTES and path.suffix == ".json":
        raise GithubExecutionAdmissionError(f"{label} exceeds its byte limit")
    return path


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise GithubExecutionAdmissionError(f"{label} is invalid")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None:
        raise GithubExecutionAdmissionError(f"{label} is invalid")
    return value


def _campaign_id(value: object) -> str:
    if not isinstance(value, str) or _CAMPAIGN_RE.fullmatch(value) is None:
        raise GithubExecutionAdmissionError("campaign ID is invalid")
    return value


def _repository(value: object) -> str:
    if (
        not isinstance(value, str)
        or value.count("/") != 1
        or len(value) > 200
        or any(not part or part in {".", ".."} for part in value.split("/"))
    ):
        raise GithubExecutionAdmissionError("GitHub repository is invalid")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GithubExecutionAdmissionError(f"{label} must be a positive integer")
    return value


def _decimal_positive_int(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise GithubExecutionAdmissionError(f"{label} must be a decimal integer")
    return _positive_int(int(value), label)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-release-dir", type=Path, required=True)
    parser.add_argument("--release-observation", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--commitment-digest", required=True)
    parser.add_argument("--selection-digest", required=True)
    parser.add_argument("--primary-matrix-digest", required=True)
    parser.add_argument("--pair-matrix-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    campaign = CampaignBinding(
        campaign_id=args.campaign_id,
        commitment_digest=args.commitment_digest,
        selection_digest=args.selection_digest,
        primary_matrix_digest=args.primary_matrix_digest,
        pair_matrix_digest=args.pair_matrix_digest,
    )
    try:
        admit_public_start(
            start_release_dir=args.start_release_dir,
            release_observation_path=args.release_observation,
            cosign_path=args.cosign,
            trusted_root_path=args.trusted_root,
            campaign=campaign,
            environment=os.environ,
            output_path=args.output,
        )
    except (GithubExecutionAdmissionError, GithubRunnerContractError) as exc:
        sys.stderr.write(f"blocked: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
