# ruff: noqa: C901,D202,D213,EM101,EM102,PLR0912,PLR0913,PLR0915,PLR2004,TRY003
"""Create and verify public, immutable-release ledger entries for paired XBEN.

The ledger is deliberately narrower than an execution attestation.  A valid
entry proves the integrity, signer identity, timestamp, and phase ordering of
the artifacts that were published.  Repository-controlled publication cannot
prove that no other campaign identifier, repository, or unpublished
commitment existed, and it cannot prove that local execution began only after
the public ``start`` entry.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, cast

from tools.paired_xben.protocol import PairedXbenProtocolError, verify_campaign

SUBMISSION_SCHEMA: Final = "ravage.paired-xben.public-ledger-submission.v1"
ENTRY_SCHEMA: Final = "ravage.paired-xben.public-ledger-entry.v1"
VERIFICATION_SCHEMA: Final = "ravage.paired-xben.public-ledger-verification.v1"
SIGSTORE_BUNDLE_MEDIA_TYPE: Final = "application/vnd.dev.sigstore.bundle.v0.3+json"
SIGNING_CONFIG_MEDIA_TYPE: Final = "application/vnd.dev.sigstore.signingconfig.v0.2+json"
OFFICIAL_TSA_URL: Final = "https://timestamp.sigstore.dev/api/v1/timestamp"
OFFICIAL_REKOR_URL: Final = "https://rekor.sigstore.dev"
WORKFLOW_FILE: Final = ".github/workflows/paired-xben.yml"
OIDC_ISSUER: Final = "https://token.actions.githubusercontent.com"
PHASES: Final = ("commitment", "matrix", "start", "results")
PHASE_ORDINAL = {phase: index for index, phase in enumerate(PHASES, start=1)}
_RESULTS_PUBLICATION_BLOCK_REASON: Final = (
    "results publication is hard-blocked until a relocation-safe full independent "
    "evidence verifier authenticates every row, target, model, evaluator component, "
    "and public execution attestation"
)
BINDING_FIELDS: Final = frozenset(
    {
        "campaign_id",
        "commitment_document_sha256",
        "selection_document_sha256",
        "primary_matrix_document_sha256",
        "execution_start_document_sha256",
        "primary_results_document_sha256",
        "model_gateway_document_sha256",
        "execution_terminal_document_sha256",
        "ravage_source_commit",
        "publication_certificate_identity",
        "publication_certificate_oidc_issuer",
    }
)

_CAMPAIGN_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SLOT_RE = re.compile(r"primary-(?:00[1-9]|0[1-3][0-9]|040)")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 300 * 1024 * 1024
_MAX_ROW_ARTIFACT_BYTES = 128 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 1536 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 1600 * 1024 * 1024
_MAX_ARTIFACTS = 50_000
_MAX_ROW_ARTIFACTS = 10_000
_MAX_SUBPROCESS_OUTPUT = 128 * 1024
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_EMPTY_RESERVATION_MARKER: Final = ".public-ledger-empty-directory-v1"
_EMPTY_RESERVATION_MARKER_BYTES: Final = b"ravage.paired-xben.public-ledger-empty-directory.v1\n"
_FROZEN_VERIFIER_FILES: Final = (
    "verifiers/drandverify",
    "verifiers/cosign",
    "verifiers/sigstore-trusted-root.json",
)
_RESOLUTION_FILES: Final = (
    "resolution/beacon-source.json",
    "resolution/beacon-source-secondary.json",
    "resolution/drand-fetch.json",
    "resolution/drand-chain-info-source.json",
    "resolution/publication-anchor-source.json",
    "resolution/publication-anchor.json",
    "resolution/beacon.json",
    "resolution/selection.json",
)
_HIGH_CONFIDENCE_SECRET_PATTERNS: Final = (
    (
        "private key",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "provider API key",
        re.compile(
            rb"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}"
            rb"(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "GitHub access token",
        re.compile(
            rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|"
            rb"github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])"
        ),
    ),
    (
        "AWS access-key identifier",
        re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        "bearer credential",
        re.compile(rb"(?i)\bbearer[ \t]+(?!\[?redacted)[A-Za-z0-9._~+/-]{20,}={0,2}"),
    ),
)
_GATEWAY_TOKEN_TEXT_RE = re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{64}(?![A-Za-z0-9_-])")
_GATEWAY_TOKEN_HEX_RE = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{128}(?![0-9A-Fa-f])")
_GATEWAY_TOKEN_BASE64_RE = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{86}==(?![A-Za-z0-9+/=])")
_SENSITIVE_JSON_KEYS: Final = frozenset(
    {
        "api_key",
        "openai_api_key",
        "anthropic_api_key",
        "upstream_api_key",
        "authorization",
        "client_secret",
        "access_token",
        "refresh_token",
        "gateway_token",
        "row_token",
        "password",
        "private_key",
    }
)


class PublicLedgerError(ValueError):
    """The public-ledger artifact set is unsafe, inconsistent, or incomplete."""


@dataclass(frozen=True)
class _TrustedProtocolVerifiers:
    drand: bytes
    cosign: bytes
    trusted_root: bytes


def release_tag(campaign_id: str, phase: str) -> str:
    """Return the one fixed GitHub release tag for a campaign phase."""

    campaign = _campaign(campaign_id)
    normalized_phase = _phase(phase)
    return f"paired-xben-v1/{campaign}/{PHASE_ORDINAL[normalized_phase]:02d}-{normalized_phase}"


def previous_release_tag(campaign_id: str, phase: str) -> str | None:
    """Return the immediately preceding fixed tag, if the phase has one."""

    normalized_phase = _phase(phase)
    position = PHASES.index(normalized_phase)
    if position == 0:
        return None
    return release_tag(campaign_id, PHASES[position - 1])


def create_submission(
    campaign_dir: Path,
    output_dir: Path,
    *,
    phase: str,
    previous_entry_path: Path | None = None,
    drand_verifier_path: Path | None = None,
    cosign_path: Path | None = None,
    trusted_root_path: Path | None = None,
) -> Path:
    """Copy the exact phase artifacts into one create-only submission."""

    campaign_root = _directory(campaign_dir, "campaign directory")
    normalized_phase = _phase(phase)
    trusted_verifiers = (
        _trusted_protocol_verifiers(
            drand_verifier_path,
            cosign_path,
            trusted_root_path,
            required=True,
        )
        if normalized_phase != "commitment"
        else None
    )
    documents, bindings = _validated_campaign_phase(
        campaign_root,
        normalized_phase,
        trusted_verifiers=trusted_verifiers,
    )
    _validate_publication_hygiene(campaign_root, documents, phase=normalized_phase)
    previous_digest = _previous_entry_digest(
        previous_entry_path,
        campaign_id=cast("str", bindings["campaign_id"]),
        phase=normalized_phase,
        current_bindings=bindings,
    )
    destination = _create_directory(output_dir, "submission directory")
    payload_root = _create_child_directory(destination, "payload")
    artifacts: list[dict[str, object]] = []
    total = 0
    for relative in documents:
        body = _campaign_artifact_bytes(campaign_root, relative)
        total += len(body)
        if total > _MAX_PAYLOAD_BYTES:
            raise PublicLedgerError("submission payload exceeds the total byte limit")
        target = _safe_payload_path(payload_root, relative)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _write_exclusive(target, body, mode=_artifact_mode(relative))
        artifacts.append({"path": relative, "sha256": _sha256(body), "size_bytes": len(body)})
    submission = _document(
        {
            "schema_version": SUBMISSION_SCHEMA,
            "campaign_id": bindings["campaign_id"],
            "phase": normalized_phase,
            "phase_ordinal": PHASE_ORDINAL[normalized_phase],
            "previous_entry_document_sha256": previous_digest,
            "artifacts": artifacts,
            "bindings": bindings,
            "policy": {
                "primary_results_only": True,
                "diagnostic_reruns_included": False,
                "replacement_allowed": False,
            },
        }
    )
    submission_path = destination / "submission.json"
    _write_json_exclusive(submission_path, submission)
    validate_submission(
        destination,
        expected_campaign_id=cast("str", bindings["campaign_id"]),
        expected_phase=normalized_phase,
        expected_file_sha256=_sha256(
            _read_regular(submission_path, "submission manifest", _MAX_JSON_BYTES)
        ),
        drand_verifier_path=drand_verifier_path,
        cosign_path=cosign_path,
        trusted_root_path=trusted_root_path,
    )
    return submission_path


def validate_submission(
    submission_dir: Path,
    *,
    expected_campaign_id: str | None = None,
    expected_phase: str | None = None,
    expected_file_sha256: str | None = None,
    drand_verifier_path: Path | None = None,
    cosign_path: Path | None = None,
    trusted_root_path: Path | None = None,
) -> dict[str, object]:
    """Validate a downloaded submission without trusting archive metadata."""

    root = _directory(submission_dir, "submission directory")
    if {item.name for item in root.iterdir()} != {"payload", "submission.json"}:
        raise PublicLedgerError("submission directory fields are invalid")
    payload_root = _directory(root / "payload", "submission payload")
    submission_path = _regular_file(root / "submission.json", "submission manifest")
    raw = _read_regular(submission_path, "submission manifest", _MAX_JSON_BYTES)
    if expected_file_sha256 is not None and _digest(expected_file_sha256) != _sha256(raw):
        raise PublicLedgerError("submission file differs from its dispatch digest")
    submission = _json_document(raw, "submission manifest", SUBMISSION_SCHEMA)
    required = {
        "schema_version",
        "campaign_id",
        "phase",
        "phase_ordinal",
        "previous_entry_document_sha256",
        "artifacts",
        "bindings",
        "policy",
        "document_sha256",
    }
    if set(submission) != required:
        raise PublicLedgerError("submission manifest fields are invalid")
    campaign = _campaign(submission["campaign_id"])
    phase = _phase(submission["phase"])
    if submission["phase_ordinal"] != PHASE_ORDINAL[phase]:
        raise PublicLedgerError("submission phase ordinal is invalid")
    if expected_campaign_id is not None and campaign != _campaign(expected_campaign_id):
        raise PublicLedgerError("submission campaign differs from dispatch input")
    if expected_phase is not None and phase != _phase(expected_phase):
        raise PublicLedgerError("submission phase differs from dispatch input")
    previous = submission["previous_entry_document_sha256"]
    if (phase == "commitment" and previous is not None) or (
        phase != "commitment" and _digest(previous) != previous
    ):
        raise PublicLedgerError("submission previous-entry binding is invalid")
    if submission["policy"] != {
        "primary_results_only": True,
        "diagnostic_reruns_included": False,
        "replacement_allowed": False,
    }:
        raise PublicLedgerError("submission replacement policy is invalid")
    artifacts = _artifact_records(submission["artifacts"])
    actual_paths = _payload_paths(payload_root)
    if tuple(item["path"] for item in artifacts) != actual_paths:
        raise PublicLedgerError("submission payload differs from its exact artifact manifest")
    total = 0
    for artifact in artifacts:
        relative = cast("str", artifact["path"])
        body = _read_regular(
            _regular_file(payload_root / relative, f"payload artifact {relative}"),
            f"payload artifact {relative}",
            _artifact_byte_limit(relative),
        )
        total += len(body)
        if artifact["size_bytes"] != len(body) or artifact["sha256"] != _sha256(body):
            raise PublicLedgerError(f"payload artifact digest mismatch: {relative}")
    if total > _MAX_PAYLOAD_BYTES:
        raise PublicLedgerError("submission payload exceeds the total byte limit")
    trusted_verifiers = (
        _trusted_protocol_verifiers(
            drand_verifier_path,
            cosign_path,
            trusted_root_path,
            required=True,
        )
        if phase != "commitment"
        else None
    )
    expected_paths, bindings = _validated_campaign_phase(
        payload_root,
        phase,
        trusted_verifiers=trusted_verifiers,
    )
    if actual_paths != expected_paths or submission["bindings"] != bindings:
        raise PublicLedgerError("submission phase artifacts or bindings are invalid")
    _validate_publication_hygiene(payload_root, expected_paths, phase=phase)
    return submission


def prepare_entry(
    submission_dir: Path,
    output_dir: Path,
    *,
    repository: str,
    repository_id: int,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    actor_id: int,
    release_id: int,
    release_url: str,
    source_run_id: int,
    source_run_head_sha: str,
    source_artifact_name: str,
    previous_entry_path: Path | None = None,
    drand_verifier_path: Path | None = None,
    cosign_path: Path | None = None,
    trusted_root_path: Path | None = None,
) -> Path:
    """Build the exact entry that the GitHub workflow signs and releases."""

    submission = validate_submission(
        submission_dir,
        drand_verifier_path=drand_verifier_path,
        cosign_path=cosign_path,
        trusted_root_path=trusted_root_path,
    )
    campaign = cast("str", submission["campaign_id"])
    phase = cast("str", submission["phase"])
    repository_name = _repository(repository)
    source_sha = _git_sha(workflow_sha)
    bindings = _mapping(submission["bindings"], "submission bindings")
    if source_sha != bindings["ravage_source_commit"]:
        raise PublicLedgerError("workflow SHA differs from the committed Ravage source")
    identity = f"https://github.com/{repository_name}/{WORKFLOW_FILE}@refs/heads/main"
    if identity != bindings["publication_certificate_identity"]:
        raise PublicLedgerError("workflow identity differs from the commitment policy")
    expected_previous = submission["previous_entry_document_sha256"]
    observed_previous = _previous_entry_digest(
        previous_entry_path,
        campaign_id=campaign,
        phase=phase,
        current_bindings=bindings,
    )
    if observed_previous != expected_previous:
        raise PublicLedgerError("submission does not bind the published previous entry")
    if _positive_int(run_attempt, "workflow run attempt") != 1:
        raise PublicLedgerError("workflow reruns cannot create ledger entries")
    intake_run_id = _positive_int(source_run_id, "source run ID")
    intake_head_sha = _git_sha(source_run_head_sha)
    intake_artifact = _text(source_artifact_name, "source artifact name", 200)
    if intake_artifact != f"paired-xben-submission-{intake_run_id}":
        raise PublicLedgerError("source artifact is not canonical for its intake run")
    destination = _create_directory(output_dir, "ledger entry directory")
    payload_path = destination / "payload.zip"
    _write_payload_zip(Path(submission_dir) / "payload", payload_path)
    payload = _read_regular(payload_path, "payload archive", _MAX_ARCHIVE_BYTES)
    tag = release_tag(campaign, phase)
    entry = _document(
        {
            "schema_version": ENTRY_SCHEMA,
            "campaign_id": campaign,
            "phase": phase,
            "phase_ordinal": PHASE_ORDINAL[phase],
            "previous_entry_document_sha256": observed_previous,
            "submission_document_sha256": submission["document_sha256"],
            "artifacts": submission["artifacts"],
            "bindings": bindings,
            "payload": {
                "file": "payload.zip",
                "sha256": _sha256(payload),
                "size_bytes": len(payload),
                "format": "zip-stored-canonical-v1",
            },
            "github": {
                "repository": repository_name,
                "repository_id": _positive_int(repository_id, "repository ID"),
                "workflow_identity": identity,
                "workflow_ref": "refs/heads/main",
                "workflow_sha": source_sha,
                "workflow_event": "workflow_dispatch",
                "run_id": _positive_int(run_id, "workflow run ID"),
                "run_attempt": 1,
                "actor_id": _positive_int(actor_id, "workflow actor ID"),
                "source_run_id": intake_run_id,
                "source_run_url": (
                    f"https://github.com/{repository_name}/actions/runs/{intake_run_id}"
                ),
                "source_run_head_sha": intake_head_sha,
                "source_branch": f"paired-xben-intake/{campaign}-{phase}",
                "source_artifact_name": intake_artifact,
                "release_tag": tag,
                "release_id": _positive_int(release_id, "release ID"),
                "release_url": _exact_release_url(release_url, repository_name, tag),
                "immutable_releases_enabled_before_reservation": True,
                "tag_reserved_by_create_ref": True,
                "release_assets_uploaded_without_clobber": True,
            },
            "claims": {
                "fixed_repository_campaign_phase_first_writer": True,
                "prepublication_repository_admin_override_excluded": False,
                "independently_administered_namespace": False,
                "no_alternative_commitments_verified": False,
                "github_observed_local_execution": False,
                "public_execution_verified": False,
                "sota_claim_supported": False,
            },
        }
    )
    entry_path = destination / "ledger-entry.json"
    _write_json_exclusive(entry_path, entry)
    if phase == "commitment":
        commitment = _read_regular(
            Path(submission_dir) / "payload" / "commitment.json",
            "commitment",
            _MAX_JSON_BYTES,
        )
        _write_exclusive(destination / "commitment.json", commitment)
    return entry_path


def validate_signing_config(path: Path) -> dict[str, object]:
    """Require Sigstore's official Rekor and RFC3161 services."""

    value = _load_json(path, "Sigstore signing config")
    if value.get("mediaType") != SIGNING_CONFIG_MEDIA_TYPE:
        raise PublicLedgerError("Sigstore signing config media type is unsupported")
    tsa = value.get("tsaUrls")
    rekor = value.get("rekorTlogUrls")
    if not _service_present(tsa, OFFICIAL_TSA_URL, exact_count=True):
        raise PublicLedgerError("official Sigstore RFC3161 TSA is not the sole configured TSA")
    if not _service_present(rekor, OFFICIAL_REKOR_URL, exact_count=False):
        raise PublicLedgerError("official Sigstore transparency log is absent")
    return value


def validate_sigstore_bundle(bundle_path: Path, artifact_path: Path) -> dict[str, object]:
    """Structurally bind one standardized bundle to an exact artifact digest."""

    bundle_raw = _read_regular(
        _regular_file(bundle_path, "Sigstore bundle"),
        "Sigstore bundle",
        _MAX_JSON_BYTES,
    )
    artifact = _read_regular(artifact_path, "signed artifact", _MAX_ARCHIVE_BYTES)
    return _validate_sigstore_bundle_bytes(bundle_raw, artifact)


def _validate_sigstore_bundle_bytes(bundle_raw: bytes, artifact: bytes) -> dict[str, object]:
    bundle = _decode_json(bundle_raw, "Sigstore bundle")
    if not isinstance(bundle, dict):
        raise PublicLedgerError("Sigstore bundle must be a JSON object")
    if bundle.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        raise PublicLedgerError("Sigstore bundle media type is unsupported")
    message = _mapping(bundle.get("messageSignature"), "Sigstore message signature")
    digest = _mapping(message.get("messageDigest"), "Sigstore message digest")
    if digest.get("algorithm") != "SHA2_256":
        raise PublicLedgerError("Sigstore bundle does not use SHA2_256")
    expected = base64.b64encode(hashlib.sha256(artifact).digest()).decode("ascii")
    if digest.get("digest") != expected:
        raise PublicLedgerError("Sigstore bundle message digest differs from the artifact")
    verification = _mapping(bundle.get("verificationMaterial"), "Sigstore verification material")
    timestamp_data = _mapping(
        verification.get("timestampVerificationData"), "Sigstore timestamp data"
    )
    timestamps = timestamp_data.get("rfc3161Timestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise PublicLedgerError("Sigstore bundle has no RFC3161 timestamp")
    for timestamp in timestamps:
        raw = _mapping(timestamp, "RFC3161 timestamp").get("signedTimestamp")
        _canonical_base64(raw, "RFC3161 timestamp")
    entries = verification.get("tlogEntries")
    if not isinstance(entries, list) or not entries:
        raise PublicLedgerError("Sigstore bundle has no transparency-log entry")
    return bundle


def verify_entry(
    entry_dir: Path,
    *,
    cosign_path: Path | None,
    trusted_root_path: Path | None,
    drand_verifier_path: Path | None = None,
    protocol_cosign_path: Path | None = None,
    protocol_trusted_root_path: Path | None = None,
    expected_repository: str | None = None,
) -> dict[str, object]:
    """Verify one downloaded release entry, optionally including Cosign."""

    root = _directory(entry_dir, "ledger entry directory")
    entry_path = _regular_file(root / "ledger-entry.json", "ledger entry")
    entry_raw = _read_regular(entry_path, "ledger entry", _MAX_JSON_BYTES)
    entry = _json_document(entry_raw, "ledger entry", ENTRY_SCHEMA)
    _validate_entry_fields(entry, expected_repository=expected_repository)
    expected_files = {
        "ledger-entry.json",
        "ledger-entry.sigstore.json",
        "payload.zip",
    }
    if entry["phase"] == "commitment":
        expected_files.update({"commitment.json", "commitment.sigstore.json"})
    if {item.name for item in root.iterdir()} != expected_files:
        raise PublicLedgerError("ledger release assets are not the exact allowed set")
    payload = _mapping(entry["payload"], "entry payload")
    payload_path = _regular_file(root / "payload.zip", "entry payload archive")
    raw_payload = _read_regular(payload_path, "entry payload archive", _MAX_ARCHIVE_BYTES)
    if payload["sha256"] != _sha256(raw_payload) or payload["size_bytes"] != len(raw_payload):
        raise PublicLedgerError("entry payload archive differs from its binding")
    artifacts = _artifact_records(entry["artifacts"])
    _verify_payload_zip(payload_path, artifacts)
    phase = cast("str", entry["phase"])
    trusted_verifiers = (
        _trusted_protocol_verifiers(
            drand_verifier_path,
            protocol_cosign_path,
            protocol_trusted_root_path,
            required=True,
        )
        if phase != "commitment"
        else None
    )
    _verify_payload_semantics(
        payload_path,
        artifacts,
        phase=phase,
        expected_bindings=_mapping(entry["bindings"], "entry bindings"),
        trusted_verifiers=trusted_verifiers,
    )
    bundle_path = _regular_file(root / "ledger-entry.sigstore.json", "entry Sigstore bundle")
    bundle_raw = _read_regular(bundle_path, "entry Sigstore bundle", _MAX_JSON_BYTES)
    _validate_sigstore_bundle_bytes(bundle_raw, entry_raw)
    cryptographic = False
    if (cosign_path is None) != (trusted_root_path is None):
        raise PublicLedgerError("Cosign and trusted-root paths must be provided together")
    if cosign_path is not None and trusted_root_path is not None:
        cosign_bytes, trusted_root_bytes = _verify_frozen_crypto_inputs(
            payload_path,
            cosign_path=cosign_path,
            trusted_root_path=trusted_root_path,
        )
        github = _mapping(entry["github"], "entry GitHub receipt")
        _verify_cosign(
            cosign_bytes,
            trusted_root_bytes,
            artifact_bytes=entry_raw,
            bundle_bytes=bundle_raw,
            identity=cast("str", github["workflow_identity"]),
            repository=cast("str", github["repository"]),
            workflow_sha=cast("str", github["workflow_sha"]),
        )
        cryptographic = True
    if phase == "commitment":
        commitment_path = _regular_file(root / "commitment.json", "published commitment")
        archive_commitment = _read_zip_member(payload_path, "commitment.json")
        commitment_raw = _read_regular(commitment_path, "published commitment", _MAX_JSON_BYTES)
        if commitment_raw != archive_commitment:
            raise PublicLedgerError("direct commitment asset differs from the payload")
        commitment_bundle = _regular_file(
            root / "commitment.sigstore.json", "commitment Sigstore bundle"
        )
        commitment_bundle_raw = _read_regular(
            commitment_bundle,
            "commitment Sigstore bundle",
            _MAX_JSON_BYTES,
        )
        _validate_sigstore_bundle_bytes(commitment_bundle_raw, commitment_raw)
        if cosign_path is not None and trusted_root_path is not None:
            github = _mapping(entry["github"], "entry GitHub receipt")
            _verify_cosign(
                cosign_bytes,
                trusted_root_bytes,
                artifact_bytes=commitment_raw,
                bundle_bytes=commitment_bundle_raw,
                identity=cast("str", github["workflow_identity"]),
                repository=cast("str", github["repository"]),
                workflow_sha=cast("str", github["workflow_sha"]),
            )
    return {
        "entry": entry,
        "artifact_integrity_verified": True,
        "sigstore_bundle_structure_verified": True,
        "rfc3161_timestamp_present": True,
        "transparency_log_entry_present": True,
        "cryptographic_signature_verified": cryptographic,
    }


def verify_ledger(
    ledger_root: Path,
    *,
    cosign_path: Path | None = None,
    trusted_root_path: Path | None = None,
    drand_verifier_path: Path | None = None,
    protocol_cosign_path: Path | None = None,
    protocol_trusted_root_path: Path | None = None,
    expected_repository: str | None = None,
) -> dict[str, object]:
    """Verify an ordered, gap-free export of fixed-phase release assets."""

    root = _directory(ledger_root, "ledger export")
    names = tuple(sorted(item.name for item in root.iterdir()))
    expected_names = tuple(f"{index:02d}-{phase}" for index, phase in enumerate(PHASES, start=1))
    if not names or names != expected_names[: len(names)]:
        raise PublicLedgerError("ledger export must be a non-empty, gap-free phase prefix")
    entries: list[dict[str, object]] = []
    previous: str | None = None
    previous_bindings: Mapping[str, object] | None = None
    campaign: str | None = None
    for index, name in enumerate(names):
        result = verify_entry(
            root / name,
            cosign_path=cosign_path,
            trusted_root_path=trusted_root_path,
            drand_verifier_path=drand_verifier_path,
            protocol_cosign_path=protocol_cosign_path,
            protocol_trusted_root_path=protocol_trusted_root_path,
            expected_repository=expected_repository,
        )
        entry = cast("dict[str, object]", result["entry"])
        if entry["phase"] != PHASES[index] or entry["phase_ordinal"] != index + 1:
            raise PublicLedgerError("ledger directory and signed phase differ")
        if campaign is None:
            campaign = cast("str", entry["campaign_id"])
        if entry["campaign_id"] != campaign or entry["previous_entry_document_sha256"] != previous:
            raise PublicLedgerError("ledger entry hash chain is invalid")
        current_bindings = _validated_entry_bindings(entry, campaign=campaign, phase=PHASES[index])
        if previous_bindings is not None:
            _require_preserved_bindings(previous_bindings, current_bindings)
        previous = cast("str", entry["document_sha256"])
        previous_bindings = current_bindings
        entries.append(entry)
    cryptographic = cosign_path is not None
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "campaign_id": campaign,
        "phases_verified": [entry["phase"] for entry in entries],
        "ledger_head": previous,
        "artifact_integrity_verified": True,
        "phase_chain_verified": True,
        "cryptographic_signatures_verified": cryptographic,
        "rfc3161_timestamps_verified": cryptographic,
        "fixed_repository_phase_path_format_verified": True,
        "github_release_immutability_verified_offline": False,
        "prepublication_repository_admin_override_excluded": False,
        "independently_administered_namespace_verified": False,
        "no_alternative_commitments_verified": False,
        "public_execution_verified": False,
        "sota_claim_supported": False,
        "claim_ready": False,
    }


def _validated_campaign_phase(
    root: Path,
    phase: str,
    *,
    trusted_verifiers: _TrustedProtocolVerifiers | None = None,
) -> tuple[tuple[str, ...], dict[str, object]]:
    # The existing retained-evidence walker is intentionally insufficient for
    # publication: it consumes evaluator-produced verdicts and can recompute a
    # numeric summary without independently authenticating every execution
    # boundary after relocation.  Keep every create, validation, and signing
    # path closed until that complete verifier exists.
    if phase == "results":
        raise PublicLedgerError(_RESULTS_PUBLICATION_BLOCK_REASON)
    commitment = _protocol_document(root / "commitment.json", "commitment")
    if commitment.get("schema_version") != "ravage.paired-xben.commitment.v1":
        raise PublicLedgerError("commitment schema is invalid")
    campaign = _campaign(commitment.get("campaign_id"))
    commitment_digest = _digest(commitment.get("document_digest"))
    attempt_policy = _mapping(commitment.get("attempt_policy"), "commitment attempt policy")
    if (
        attempt_policy.get("reruns_are_scored") is not False
        or attempt_policy.get("overwrite_allowed") is not False
        or attempt_policy.get("scored_attempts") != "scheduled_primary_only"
    ):
        raise PublicLedgerError("commitment attempt policy permits result substitution")
    run_contract = _mapping(commitment.get("run_contract"), "commitment run contract")
    sources = _mapping(run_contract.get("sources"), "run-contract sources")
    ravage_source = _mapping(sources.get("ravage"), "Ravage source binding")
    ravage_commit = _git_sha(ravage_source.get("commit_sha"))
    authenticity = _mapping(commitment.get("authenticity_policy"), "authenticity policy")
    publication = _mapping(authenticity.get("publication"), "publication policy")
    identity = _text(publication.get("certificate_identity"), "publication identity", 1000)
    if publication.get("certificate_oidc_issuer") != OIDC_ISSUER:
        raise PublicLedgerError("commitment publication issuer is not GitHub Actions")
    preflight = _read_regular(root / "preflight-source.json", "preflight source", _MAX_JSON_BYTES)
    preflight_source = _mapping(commitment.get("preflight_source"), "preflight binding")
    if preflight_source.get("sha256") != _sha256(preflight):
        raise PublicLedgerError("preflight source differs from the commitment")
    trusted_root_path = root / "verifiers/sigstore-trusted-root.json"
    trusted_root = _read_regular(trusted_root_path, "Sigstore trusted root", _MAX_JSON_BYTES)
    if publication.get("trusted_root_sha256") != _sha256(trusted_root):
        raise PublicLedgerError("Sigstore trusted root differs from the commitment")
    _decode_json(trusted_root, "Sigstore trusted root")
    paths = ["commitment.json", "preflight-source.json", "verifiers/sigstore-trusted-root.json"]
    bindings: dict[str, object] = {
        "campaign_id": campaign,
        "commitment_document_sha256": commitment_digest,
        "selection_document_sha256": None,
        "primary_matrix_document_sha256": None,
        "execution_start_document_sha256": None,
        "primary_results_document_sha256": None,
        "model_gateway_document_sha256": None,
        "execution_terminal_document_sha256": None,
        "ravage_source_commit": ravage_commit,
        "publication_certificate_identity": identity,
        "publication_certificate_oidc_issuer": OIDC_ISSUER,
    }
    if phase == "commitment":
        return tuple(paths), bindings

    if trusted_verifiers is None:
        raise PublicLedgerError(
            "post-commitment validation requires trusted external verifier inputs"
        )

    verifier_paths = _payload_paths(_directory(root / "verifiers", "frozen verifier directory"))
    if verifier_paths != tuple(
        sorted(path.removeprefix("verifiers/") for path in _FROZEN_VERIFIER_FILES)
    ):
        raise PublicLedgerError("frozen verifier directory is not the exact committed set")
    resolution_paths = _payload_paths(_directory(root / "resolution", "resolution directory"))
    if resolution_paths != tuple(
        sorted(path.removeprefix("resolution/") for path in _RESOLUTION_FILES)
    ):
        raise PublicLedgerError("resolution directory is not the exact retained evidence set")
    reruns = root / "attempts" / "reruns"
    if reruns.exists() or reruns.is_symlink():
        raise PublicLedgerError("diagnostic reruns cannot exist in a public primary campaign")
    _bind_trusted_protocol_verifiers(
        root,
        commitment=commitment,
        trusted_verifiers=trusted_verifiers,
    )
    paths.extend((*_FROZEN_VERIFIER_FILES[:2], *_RESOLUTION_FILES))

    selection = _protocol_document(root / "resolution/selection.json", "selection")
    if selection.get("schema_version") != "ravage.paired-xben.selection.v1":
        raise PublicLedgerError("selection schema is invalid")
    selection_digest = _digest(selection.get("document_digest"))
    if (
        selection.get("campaign_id") != campaign
        or selection.get("commitment_digest") != commitment_digest
    ):
        raise PublicLedgerError("selection does not bind the commitment")
    schedule = selection.get("schedule")
    if not isinstance(schedule, list) or len(schedule) != 40:
        raise PublicLedgerError("selection schedule is not exactly forty rows")
    slots = [row.get("slot_id") for row in schedule if isinstance(row, Mapping)]
    if slots != [f"primary-{index:03d}" for index in range(1, 41)]:
        raise PublicLedgerError("selection primary slots are invalid")
    matrix = _protocol_document(root / "attempts/primary-reservation.json", "primary matrix")
    if (
        matrix.get("schema_version") != "ravage.paired-xben.primary-matrix.v1"
        or matrix.get("campaign_id") != campaign
        or matrix.get("commitment_digest") != commitment_digest
        or matrix.get("selection_digest") != selection_digest
        or matrix.get("scheduled_primary_attempts") != 40
        or matrix.get("policy")
        != {
            "all_slots_reserved_before_execution": True,
            "resume_incomplete_reservation": False,
            "replace_primary_attempt": False,
        }
    ):
        raise PublicLedgerError("primary matrix is not a sealed no-replacement reservation")
    raw_attempts = matrix.get("attempts")
    if not isinstance(raw_attempts, list) or len(raw_attempts) != 40:
        raise PublicLedgerError("primary matrix does not bind forty attempts")
    paths.append("attempts/primary-reservation.json")
    for index, record in enumerate(raw_attempts, start=1):
        item = _mapping(record, "primary matrix attempt")
        slot = f"primary-{index:03d}"
        relative = f"attempts/primary/{slot}/attempt.json"
        if item.get("slot_id") != slot or item.get("attempt_manifest") != f"{slot}/attempt.json":
            raise PublicLedgerError("primary matrix attempt ordering is invalid")
        attempt = _protocol_document(root / relative, f"attempt {slot}")
        if attempt.get("schema_version") != "ravage.paired-xben.attempt.v1":
            raise PublicLedgerError("primary attempt schema is invalid")
        if attempt.get("document_digest") != item.get("attempt_document_digest"):
            raise PublicLedgerError("primary attempt differs from its matrix reservation")
        if (
            attempt.get("purpose") != "primary"
            or attempt.get("score_eligible") is not True
            or attempt.get("parent_primary_slot_id") is not None
            or attempt.get("attempt_id") != slot
        ):
            raise PublicLedgerError("matrix contains a rerun or non-primary attempt")
        paths.append(relative)
    try:
        protocol = _verify_campaign_with_trusted_verifiers(
            root,
            trusted_verifiers=trusted_verifiers,
            slots=slots,
        )
    except (OSError, PairedXbenProtocolError) as exc:
        raise PublicLedgerError(
            f"retained randomness, publication, selection, or reservation evidence failed "
            f"protocol verification: {exc}"
        ) from exc
    if (
        protocol.get("phase") != "resolved"
        or protocol.get("structurally_valid") is not True
        or protocol.get("beacon_authenticity_verified") is not True
        or protocol.get("publication_anchor_verified") is not True
        or protocol.get("campaign_id") != campaign
        or protocol.get("commitment_digest") != commitment_digest
        or protocol.get("selection_digest") != selection_digest
        or protocol.get("selected_cases") != 20
        or protocol.get("scheduled_primary_attempts") != 40
        or protocol.get("recorded_primary_attempts") != 40
        or protocol.get("missing_primary_attempts") != 0
        or protocol.get("primary_matrix_reserved") is not True
        or protocol.get("primary_matrix_digest") != matrix.get("document_digest")
        or protocol.get("diagnostic_reruns") != 0
    ):
        raise PublicLedgerError(
            "protocol verification did not authenticate the exact twenty-case, forty-row matrix"
        )
    bindings["selection_document_sha256"] = selection_digest
    bindings["primary_matrix_document_sha256"] = _digest(matrix.get("document_digest"))
    if phase in {"matrix", "start"}:
        paths.extend(_validated_empty_reservation_markers(root, slots))
    if phase == "matrix":
        return tuple(sorted(paths)), bindings

    start = _coordinator_document(root / "execution/start.json", "execution start")
    if (
        start.get("schema_version") != "ravage.paired-xben.execution-start.v1"
        or start.get("campaign_id") != campaign
        or start.get("commitment_digest") != commitment_digest
        or start.get("selection_digest") != selection_digest
        or start.get("primary_matrix_digest") != bindings["primary_matrix_document_sha256"]
        or start.get("registered_row_count") != 40
        or start.get("registered_row_ids") != slots
        or start.get("policy")
        != {
            "resume_allowed": False,
            "row_retry_allowed": False,
            "row_replacement_allowed": False,
            "adjacent_pair_schedule": True,
        }
    ):
        raise PublicLedgerError("execution start permits resume, retry, or row replacement")
    paths.append("execution/start.json")
    bindings["execution_start_document_sha256"] = _digest(start.get("document_sha256"))
    if phase == "start":
        return tuple(sorted(paths)), bindings

    terminal = _coordinator_document(root / "execution/terminal.json", "execution terminal")
    if (
        terminal.get("schema_version") != "ravage.paired-xben.execution-terminal.v1"
        or terminal.get("campaign_id") != campaign
        or terminal.get("commitment_digest") != commitment_digest
        or terminal.get("selection_digest") != selection_digest
        or not isinstance(terminal.get("complete"), bool)
    ):
        raise PublicLedgerError("execution terminal bindings are invalid")
    paths.append("execution/terminal.json")
    bindings["execution_terminal_document_sha256"] = _digest(terminal.get("document_sha256"))
    result_path = root / "primary-results.json"
    model_path = root / "campaign-model-gateway.json"
    result_exists = result_path.exists() or result_path.is_symlink()
    model_exists = model_path.exists() or model_path.is_symlink()
    if (
        terminal.get("complete") is not True
        or terminal.get("rows_terminal") != 40
        or terminal.get("pairs_terminal") != 20
        or not result_exists
        or not model_exists
    ):
        raise PublicLedgerError(
            "results publication requires one complete terminal forty-row campaign"
        )
    results = _coordinator_document(result_path, "primary results")
    if (
        results.get("schema_version") != "ravage.paired-xben.primary-results.v1"
        or results.get("campaign_id") != campaign
        or results.get("commitment_digest") != commitment_digest
        or results.get("selection_digest") != selection_digest
        or results.get("row_count") != 40
        or results.get("all_terminal") is not True
        or terminal.get("primary_results_sha256")
        != _sha256(_read_regular(result_path, "primary results", _MAX_JSON_BYTES))
    ):
        raise PublicLedgerError("primary results seal is invalid")
    rows = results.get("rows")
    if (
        not isinstance(rows, list)
        or [row.get("slot_id") for row in rows if isinstance(row, Mapping)] != slots
    ):
        raise PublicLedgerError("primary results are not the exact reserved rows")
    model = _coordinator_document(model_path, "model gateway campaign seal")
    if (
        model.get("schema_version") != "ravage.xben.model-gateway-campaign-receipt.v1"
        or terminal.get("model_gateway_receipt_sha256")
        != _sha256(_read_regular(model_path, "model gateway campaign seal", _MAX_JSON_BYTES))
        or terminal.get("model_gateway_document_sha256") != model.get("document_sha256")
    ):
        raise PublicLedgerError("model gateway campaign seal differs from terminal")
    paths.extend(("primary-results.json", "campaign-model-gateway.json"))
    row_paths, target_paths = _validated_complete_results_evidence(
        root,
        selection=selection,
        results=results,
        slots=slots,
    )
    paths.extend((*row_paths, *target_paths))
    attestation_path = root / "public-execution-attestation.json"
    if attestation_path.exists() or attestation_path.is_symlink():
        _regular_file(attestation_path, "public execution attestation")
        paths.append("public-execution-attestation.json")
    bindings["primary_results_document_sha256"] = _digest(results.get("document_sha256"))
    bindings["model_gateway_document_sha256"] = _digest(model.get("document_sha256"))
    return tuple(sorted(paths)), bindings


def _trusted_protocol_verifiers(
    drand_verifier_path: Path | None,
    cosign_path: Path | None,
    trusted_root_path: Path | None,
    *,
    required: bool,
) -> _TrustedProtocolVerifiers | None:
    provided = (drand_verifier_path, cosign_path, trusted_root_path)
    if any(path is not None for path in provided) and not all(
        path is not None for path in provided
    ):
        raise PublicLedgerError("drand, Cosign, and trusted-root paths must be provided together")
    if all(path is None for path in provided):
        if required:
            raise PublicLedgerError(
                "post-commitment validation requires trusted external drand, Cosign, "
                "and trusted-root paths"
            )
        return None
    return _TrustedProtocolVerifiers(
        drand=_read_regular(
            cast("Path", drand_verifier_path),
            "trusted drand verifier",
            _MAX_ARTIFACT_BYTES,
        ),
        cosign=_read_regular(
            cast("Path", cosign_path),
            "trusted Cosign verifier",
            _MAX_ARTIFACT_BYTES,
        ),
        trusted_root=_read_regular(
            cast("Path", trusted_root_path),
            "trusted Sigstore root",
            _MAX_JSON_BYTES,
        ),
    )


def _bind_trusted_protocol_verifiers(
    root: Path,
    *,
    commitment: Mapping[str, object],
    trusted_verifiers: _TrustedProtocolVerifiers,
) -> None:
    authenticity = _mapping(commitment.get("authenticity_policy"), "authenticity policy")
    drand_policy = _mapping(authenticity.get("drand"), "drand authenticity policy")
    publication = _mapping(authenticity.get("publication"), "publication policy")
    expected = (
        (
            "verifiers/drandverify",
            trusted_verifiers.drand,
            drand_policy.get("binary_file"),
            drand_policy.get("binary_sha256"),
            drand_policy.get("binary_size"),
            "drand verifier",
        ),
        (
            "verifiers/cosign",
            trusted_verifiers.cosign,
            publication.get("cosign_binary_file"),
            publication.get("cosign_binary_sha256"),
            publication.get("cosign_binary_size"),
            "Cosign verifier",
        ),
        (
            "verifiers/sigstore-trusted-root.json",
            trusted_verifiers.trusted_root,
            publication.get("trusted_root_file"),
            publication.get("trusted_root_sha256"),
            len(trusted_verifiers.trusted_root),
            "Sigstore trusted root",
        ),
    )
    for relative, trusted, policy_file, policy_digest, policy_size, label in expected:
        if policy_file != relative:
            raise PublicLedgerError(f"committed {label} path is invalid")
        size = _positive_int(policy_size, f"committed {label} size")
        if size != len(trusted) or _digest(policy_digest) != _sha256(trusted):
            raise PublicLedgerError(f"trusted external {label} differs from the commitment")
        retained = _read_regular(
            root / relative,
            f"retained {label}",
            _artifact_byte_limit(relative),
        )
        if retained != trusted:
            raise PublicLedgerError(f"retained {label} differs from the trusted external input")


def _verify_campaign_with_trusted_verifiers(
    root: Path,
    *,
    trusted_verifiers: _TrustedProtocolVerifiers,
    slots: Sequence[object],
) -> dict[str, object]:
    """Run the protocol only on trusted executables in a private minimal copy."""

    with tempfile.TemporaryDirectory(prefix="ravage-ledger-protocol-") as temporary:
        snapshot = Path(temporary)
        files = [
            "commitment.json",
            "preflight-source.json",
            "attempts/primary-reservation.json",
            *_RESOLUTION_FILES,
        ]
        for slot_value in slots:
            slot = _text(slot_value, "primary slot", 32)
            files.append(f"attempts/primary/{slot}/attempt.json")
        for relative in files:
            destination = _safe_payload_path(snapshot, relative)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_exclusive(
                destination,
                _read_regular(
                    root / relative,
                    f"protocol input {relative}",
                    _artifact_byte_limit(relative),
                ),
            )
        verifier_files = {
            "verifiers/drandverify": trusted_verifiers.drand,
            "verifiers/cosign": trusted_verifiers.cosign,
            "verifiers/sigstore-trusted-root.json": trusted_verifiers.trusted_root,
        }
        for relative, body in verifier_files.items():
            destination = _safe_payload_path(snapshot, relative)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_exclusive(destination, body, mode=_artifact_mode(relative))
        for slot_value in slots:
            slot = _text(slot_value, "primary slot", 32)
            (snapshot / f"attempts/primary/{slot}/artifacts").mkdir(
                parents=True,
                mode=0o700,
            )
        return verify_campaign(snapshot, require_all_primary_attempts=True)


def _validated_complete_results_evidence(
    root: Path,
    *,
    selection: Mapping[str, object],
    results: Mapping[str, object],
    slots: Sequence[object],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the exact raw row and target evidence needed to replay scoring.

    Target receipts contain evaluator-local absolute paths.  Those strings are
    retained verbatim, while this exporter carries the complete target evidence
    subtree at its campaign-relative location.  The row score itself is
    recomputed with the pinned report implementation; no summary-only input is
    accepted.
    """

    try:
        from tools.paired_xben import report as report_module  # noqa: PLC0415
    except (ImportError, RuntimeError) as exc:
        raise PublicLedgerError("the pinned paired-XBEN report verifier is unavailable") from exc

    raw_schedule = selection.get("schedule")
    if not isinstance(raw_schedule, list) or len(raw_schedule) != 40:
        raise PublicLedgerError("results selection has no exact forty-row schedule")
    schedule: list[Mapping[str, object]] = []
    for row in raw_schedule:
        if not isinstance(row, Mapping):
            raise PublicLedgerError("results selection contains a non-object row")
        schedule.append(row)

    raw_records = results.get("rows")
    if not isinstance(raw_records, list) or len(raw_records) != 40:
        raise PublicLedgerError("primary results seal does not contain forty row bindings")
    expected_record_fields = {
        "slot_id",
        "row_manifest_sha256",
        "row_result_sha256",
        "adapter_result_sha256",
        "process_receipt_sha256",
        "model_gateway_receipt_sha256",
        "sandbox_profile_sha256",
        "target_build_sha256",
        "target_teardown_sha256",
    }
    campaign = _campaign(selection.get("campaign_id"))
    commitment_digest = _digest(selection.get("commitment_digest"))
    selection_digest = _digest(selection.get("document_digest"))
    row_paths: list[str] = []
    row_results: list[dict[str, object]] = []
    gateway_token_digests: set[str] = set()

    for index, (scheduled, raw_record) in enumerate(
        zip(schedule, raw_records, strict=True), start=1
    ):
        record = _mapping(raw_record, "primary result row binding")
        if set(record) != expected_record_fields:
            raise PublicLedgerError("primary result row binding fields are invalid")
        slot = f"primary-{index:03d}"
        if slots[index - 1] != slot or scheduled.get("slot_id") != slot:
            raise PublicLedgerError("primary result row order differs from the frozen schedule")
        if record.get("slot_id") != slot:
            raise PublicLedgerError("primary result row seal is out of order")
        attempt_root = _directory(
            root / f"attempts/primary/{slot}",
            f"primary attempt {slot}",
        )
        artifact_root = _directory(attempt_root / "artifacts", f"primary artifacts {slot}")
        artifact_files = _payload_paths(artifact_root)
        if not artifact_files or len(artifact_files) > _MAX_ROW_ARTIFACTS:
            raise PublicLedgerError(f"primary row {slot} has an invalid evidence file count")
        result_matches = [
            name for name in artifact_files if PurePosixPath(name).name == "row-result.json"
        ]
        if len(result_matches) != 1:
            raise PublicLedgerError(f"primary row {slot} lacks one unambiguous row result")
        result_relative = PurePosixPath(result_matches[0])
        row_root_relative = result_relative.parent
        if any(
            PurePosixPath(name).parent != row_root_relative
            and row_root_relative not in PurePosixPath(name).parents
            for name in artifact_files
        ):
            raise PublicLedgerError(f"primary row {slot} contains sibling evidence ambiguity")
        row_root = artifact_root.joinpath(*row_root_relative.parts)
        manifest_path = _regular_file(row_root / "artifacts.sha256", f"row {slot} manifest")
        manifest = _validated_sha256_manifest(row_root, manifest_path, slot=slot)
        if record.get("row_manifest_sha256") != _sha256(
            _read_regular(manifest_path, f"row {slot} manifest", _MAX_JSON_BYTES)
        ):
            raise PublicLedgerError(f"primary row {slot} manifest differs from its results seal")

        bound_files = {
            "row_result_sha256": "row-result.json",
            "process_receipt_sha256": "process-receipt.json",
            "model_gateway_receipt_sha256": "model-gateway-receipt.json",
            "sandbox_profile_sha256": "sandbox-profile.sb",
            "target_build_sha256": "target-build.json",
            "target_teardown_sha256": "target-teardown.json",
        }
        for field, relative in bound_files.items():
            if relative not in manifest:
                raise PublicLedgerError(f"primary row {slot} manifest omits {relative}")
            path = _regular_file(row_root / relative, f"row {slot} {relative}")
            if record.get(field) != _sha256(
                _read_regular(path, f"row {slot} {relative}", _artifact_byte_limit(relative))
            ):
                raise PublicLedgerError(f"primary row {slot} {relative} differs from its seal")
        adapter_relative = "native-output/adapter-result.json"
        adapter_present = adapter_relative in manifest
        adapter_digest = record.get("adapter_result_sha256")
        if adapter_present is not (adapter_digest is not None):
            raise PublicLedgerError(f"primary row {slot} adapter seal presence is inconsistent")
        if adapter_present:
            adapter_path = _regular_file(
                row_root / adapter_relative,
                f"row {slot} adapter result",
            )
            if adapter_digest != _sha256(
                _read_regular(
                    adapter_path,
                    f"row {slot} adapter result",
                    _MAX_JSON_BYTES,
                )
            ):
                raise PublicLedgerError(f"primary row {slot} adapter result differs from its seal")

        row_result_path = row_root / "row-result.json"
        row_result = _load_json(row_result_path, f"row {slot} result")
        model_receipt = _coordinator_document(
            row_root / "model-gateway-receipt.json",
            f"row {slot} model gateway receipt",
        )
        token_digest = _digest(model_receipt.get("row_token_sha256"))
        if token_digest in gateway_token_digests:
            raise PublicLedgerError("model gateway repeated a row credential digest")
        gateway_token_digests.add(token_digest)
        try:
            report_module._validate_row_result(  # noqa: SLF001
                row_result,
                scheduled=scheduled,
                campaign_id=campaign,
                commitment_digest=commitment_digest,
                selection_digest=selection_digest,
            )
            report_module._verify_row_manifest(row_root)  # noqa: SLF001
            report_module._verify_declared_native_artifact(  # noqa: SLF001
                row_result,
                row_root=row_root,
                slot_id=slot,
            )
            report_module._verify_row_lifecycle(  # noqa: SLF001
                row_result,
                row_root=row_root,
                slot_id=slot,
            )
        except (OSError, ValueError, report_module.PairedXbenReportError) as exc:
            raise PublicLedgerError(
                f"primary row {slot} cannot be independently rescored: {exc}"
            ) from exc
        row_results.append(row_result)
        row_prefix = f"attempts/primary/{slot}/artifacts/"
        row_paths.extend(row_prefix + name for name in artifact_files)

    if len(gateway_token_digests) != 40:
        raise PublicLedgerError("results do not bind forty unique row credentials")
    try:
        report_module._validate_unique_row_state(schedule, row_results)  # noqa: SLF001
        report_module._validate_schedule_execution_order(row_results)  # noqa: SLF001
        recomputed = report_module._paired_results(schedule, row_results)  # noqa: SLF001
    except (ValueError, report_module.PairedXbenReportError) as exc:
        raise PublicLedgerError(f"paired score recomputation failed: {exc}") from exc
    systems = recomputed.get("systems") if isinstance(recomputed, Mapping) else None
    if (
        not isinstance(systems, Mapping)
        or set(systems) != {"ravage", "strix"}
        or any(
            not isinstance(systems.get(system), Mapping)
            or cast("Mapping[str, object]", systems[system]).get("total") != 20
            for system in ("ravage", "strix")
        )
    ):
        raise PublicLedgerError("paired score recomputation did not produce two twenty-case arms")

    raw_pairs = results.get("paired_targets")
    if not isinstance(raw_pairs, list) or len(raw_pairs) != 20:
        raise PublicLedgerError("primary results seal does not contain twenty pair bindings")
    for index, raw_pair in enumerate(raw_pairs, start=1):
        pair = _mapping(raw_pair, "primary result pair binding")
        if set(pair) != {
            "pair_index",
            "case_id",
            "pair_id",
            "prepared_target_sha256",
            "release_sha256",
        }:
            raise PublicLedgerError("primary result pair binding fields are invalid")
        expected_pair_id = f"pair-{index:03d}"
        expected_case = schedule[(index - 1) * 2].get("case_id")
        if pair.get("pair_index") != index or pair.get("case_id") != expected_case:
            raise PublicLedgerError("primary result pair order differs from the frozen schedule")
        prepared_digest = pair.get("prepared_target_sha256")
        release_digest = pair.get("release_sha256")
        if prepared_digest is None:
            if pair.get("pair_id") is not None or release_digest is not None:
                raise PublicLedgerError("absent pair preparation has invented release evidence")
            continue
        if pair.get("pair_id") != expected_pair_id:
            raise PublicLedgerError("prepared pair identity differs from its frozen pair index")
        prepared = root / f"execution/targets/{expected_pair_id}.prepared/prepared.json"
        if prepared_digest != _sha256(
            _read_regular(prepared, f"pair {index} prepared evidence", _MAX_JSON_BYTES)
        ):
            raise PublicLedgerError("prepared pair evidence differs from its results seal")
        release = root / f"execution/targets/{expected_pair_id}.prepared/release.json"
        if release_digest is None:
            if release.exists() or release.is_symlink():
                raise PublicLedgerError("unsealed pair release evidence is present")
        elif release_digest != _sha256(
            _read_regular(release, f"pair {index} release evidence", _MAX_JSON_BYTES)
        ):
            raise PublicLedgerError("pair release evidence differs from its results seal")

    targets_root = root / "execution" / "targets"
    if targets_root.exists() or targets_root.is_symlink():
        target_files = _payload_paths(_directory(targets_root, "target evidence directory"))
        target_paths = tuple(f"execution/targets/{name}" for name in target_files)
    else:
        if any(
            isinstance(pair, Mapping) and pair.get("prepared_target_sha256") is not None
            for pair in raw_pairs
        ):
            raise PublicLedgerError("sealed pair evidence directory is missing")
        target_paths = ()
    return tuple(sorted(row_paths)), tuple(sorted(target_paths))


def _validated_empty_reservation_markers(
    root: Path,
    slots: Sequence[object],
) -> tuple[str, ...]:
    """Represent the 40 required empty artifact directories in a file-only ZIP."""

    markers: list[str] = []
    for slot_value in slots:
        slot = _text(slot_value, "primary slot", 32)
        artifact_root = _directory(
            root / f"attempts/primary/{slot}/artifacts",
            f"empty primary artifact reservation {slot}",
        )
        marker = artifact_root / _EMPTY_RESERVATION_MARKER
        children = list(artifact_root.iterdir())
        if children:
            if len(children) != 1 or children[0].name != _EMPTY_RESERVATION_MARKER:
                raise PublicLedgerError(
                    f"pre-execution primary reservation {slot} already contains evidence"
                )
            if (
                _read_regular(
                    marker,
                    f"empty-directory marker for {slot}",
                    len(_EMPTY_RESERVATION_MARKER_BYTES),
                )
                != _EMPTY_RESERVATION_MARKER_BYTES
            ):
                raise PublicLedgerError(f"empty-directory marker for {slot} is invalid")
        markers.append(f"attempts/primary/{slot}/artifacts/{_EMPTY_RESERVATION_MARKER}")
    if len(markers) != 40:
        raise PublicLedgerError("matrix does not have forty empty artifact reservations")
    return tuple(markers)


def _campaign_artifact_bytes(root: Path, relative: str) -> bytes:
    """Read an artifact, synthesizing only the canonical empty-directory marker."""

    normalized = _relative_path(relative)
    path = root / normalized
    if PurePosixPath(normalized).name != _EMPTY_RESERVATION_MARKER:
        return _read_regular(
            path,
            f"campaign artifact {normalized}",
            _artifact_byte_limit(normalized),
        )
    if path.exists() or path.is_symlink():
        body = _read_regular(
            path,
            f"empty-directory marker {normalized}",
            len(_EMPTY_RESERVATION_MARKER_BYTES),
        )
        if body != _EMPTY_RESERVATION_MARKER_BYTES:
            raise PublicLedgerError(f"empty-directory marker is invalid: {normalized}")
        return body
    parent = _directory(path.parent, f"empty-directory reservation for {normalized}")
    if any(parent.iterdir()):
        raise PublicLedgerError(f"empty-directory reservation changed before copying: {normalized}")
    return _EMPTY_RESERVATION_MARKER_BYTES


def _validated_sha256_manifest(
    row_root: Path,
    manifest_path: Path,
    *,
    slot: str,
) -> dict[str, str]:
    raw = _read_regular(manifest_path, f"row {slot} SHA256 manifest", _MAX_JSON_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicLedgerError(f"row {slot} SHA256 manifest is not UTF-8") from exc
    declared: dict[str, str] = {}
    for line in text.splitlines():
        digest, separator, relative_text = line.partition("  ")
        if not separator or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise PublicLedgerError(f"row {slot} SHA256 manifest contains an invalid line")
        relative = _relative_path(relative_text)
        if relative == "artifacts.sha256" or relative in declared:
            raise PublicLedgerError(f"row {slot} SHA256 manifest is recursive or duplicated")
        declared[relative] = digest
    actual: dict[str, Path] = {}
    for relative in _payload_paths(row_root):
        if relative != "artifacts.sha256":
            actual[relative] = row_root.joinpath(*PurePosixPath(relative).parts)
    if not declared or set(declared) != set(actual):
        raise PublicLedgerError(f"row {slot} manifest does not enumerate its exact evidence")
    for relative, path in actual.items():
        body = _read_regular(
            path, f"row {slot} evidence {relative}", _artifact_byte_limit(relative)
        )
        if hashlib.sha256(body).hexdigest() != declared[relative]:
            raise PublicLedgerError(f"row {slot} evidence digest mismatch: {relative}")
    return declared


def _validate_entry_fields(entry: Mapping[str, object], *, expected_repository: str | None) -> None:
    required = {
        "schema_version",
        "campaign_id",
        "phase",
        "phase_ordinal",
        "previous_entry_document_sha256",
        "submission_document_sha256",
        "artifacts",
        "bindings",
        "payload",
        "github",
        "claims",
        "document_sha256",
    }
    if set(entry) != required:
        raise PublicLedgerError("ledger entry fields are invalid")
    campaign = _campaign(entry["campaign_id"])
    phase = _phase(entry["phase"])
    if entry["phase_ordinal"] != PHASE_ORDINAL[phase]:
        raise PublicLedgerError("ledger entry ordinal is invalid")
    previous = entry.get("previous_entry_document_sha256")
    if (phase == "commitment" and previous is not None) or (
        phase != "commitment" and _digest(previous) != previous
    ):
        raise PublicLedgerError("ledger entry previous-document binding is invalid")
    _digest(entry.get("submission_document_sha256"))
    github = _mapping(entry["github"], "entry GitHub receipt")
    expected_github_fields = {
        "repository",
        "repository_id",
        "workflow_identity",
        "workflow_ref",
        "workflow_sha",
        "workflow_event",
        "run_id",
        "run_attempt",
        "actor_id",
        "source_run_id",
        "source_run_url",
        "source_run_head_sha",
        "source_branch",
        "source_artifact_name",
        "release_tag",
        "release_id",
        "release_url",
        "immutable_releases_enabled_before_reservation",
        "tag_reserved_by_create_ref",
        "release_assets_uploaded_without_clobber",
    }
    if set(github) != expected_github_fields:
        raise PublicLedgerError("ledger entry GitHub receipt fields are invalid")
    repository = _repository(github.get("repository"))
    if expected_repository is not None and repository != _repository(expected_repository):
        raise PublicLedgerError("ledger repository differs from the expected repository")
    if (
        github.get("workflow_ref") != "refs/heads/main"
        or github.get("workflow_event") != "workflow_dispatch"
        or github.get("release_tag") != release_tag(campaign, phase)
        or github.get("immutable_releases_enabled_before_reservation") is not True
        or github.get("tag_reserved_by_create_ref") is not True
        or github.get("release_assets_uploaded_without_clobber") is not True
    ):
        raise PublicLedgerError("ledger GitHub publication policy is invalid")
    source_run_id = _positive_int(github.get("source_run_id"), "source run ID")
    if (
        _positive_int(github.get("repository_id"), "repository ID") <= 0
        or _git_sha(github.get("workflow_sha")) != github.get("workflow_sha")
        or _positive_int(github.get("run_id"), "workflow run ID") <= 0
        or _positive_int(github.get("run_attempt"), "workflow run attempt") != 1
        or _positive_int(github.get("actor_id"), "workflow actor ID") <= 0
        or github.get("source_artifact_name") != f"paired-xben-submission-{source_run_id}"
        or _git_sha(github.get("source_run_head_sha")) != github.get("source_run_head_sha")
        or github.get("source_run_url")
        != f"https://github.com/{repository}/actions/runs/{source_run_id}"
        or github.get("source_branch") != f"paired-xben-intake/{campaign}-{phase}"
        or _positive_int(github.get("release_id"), "release ID") <= 0
        or _exact_release_url(github.get("release_url"), repository, release_tag(campaign, phase))
        != github.get("release_url")
    ):
        raise PublicLedgerError("ledger GitHub receipt fields are invalid")
    identity = f"https://github.com/{repository}/{WORKFLOW_FILE}@refs/heads/main"
    bindings = _validated_entry_bindings(entry, campaign=campaign, phase=phase)
    if (
        github.get("workflow_identity") != identity
        or bindings.get("publication_certificate_identity") != identity
        or github.get("workflow_sha") != bindings.get("ravage_source_commit")
    ):
        raise PublicLedgerError("ledger workflow identity is not source-bound")
    payload = _mapping(entry.get("payload"), "entry payload")
    if (
        set(payload) != {"file", "sha256", "size_bytes", "format"}
        or payload.get("file") != "payload.zip"
        or payload.get("format") != "zip-stored-canonical-v1"
        or _digest(payload.get("sha256")) != payload.get("sha256")
        or _nonnegative_int(payload.get("size_bytes"), "payload size") <= 0
    ):
        raise PublicLedgerError("ledger entry payload binding is invalid")
    _artifact_records(entry.get("artifacts"))
    claims = entry.get("claims")
    if claims != {
        "fixed_repository_campaign_phase_first_writer": True,
        "prepublication_repository_admin_override_excluded": False,
        "independently_administered_namespace": False,
        "no_alternative_commitments_verified": False,
        "github_observed_local_execution": False,
        "public_execution_verified": False,
        "sota_claim_supported": False,
    }:
        raise PublicLedgerError("ledger entry overstates its evidentiary claims")


def _previous_entry_digest(
    path: Path | None,
    *,
    campaign_id: str,
    phase: str,
    current_bindings: Mapping[str, object],
) -> str | None:
    position = PHASES.index(phase)
    if position == 0:
        if path is not None:
            raise PublicLedgerError("commitment phase cannot have a previous entry")
        return None
    if path is None:
        raise PublicLedgerError("post-commitment phase requires the previous signed entry")
    entry = _json_document(
        _read_regular(path, "previous ledger entry", _MAX_JSON_BYTES),
        "previous ledger entry",
        ENTRY_SCHEMA,
    )
    _validate_entry_fields(entry, expected_repository=None)
    if entry.get("campaign_id") != campaign_id or entry.get("phase") != PHASES[position - 1]:
        raise PublicLedgerError("previous ledger entry is not the required campaign phase")
    previous_bindings = _validated_entry_bindings(
        entry,
        campaign=campaign_id,
        phase=PHASES[position - 1],
    )
    _require_preserved_bindings(previous_bindings, current_bindings)
    return _digest(entry.get("document_sha256"))


def _validated_entry_bindings(
    entry: Mapping[str, object],
    *,
    campaign: str,
    phase: str,
) -> Mapping[str, object]:
    bindings = _mapping(entry.get("bindings"), "entry bindings")
    if set(bindings) != BINDING_FIELDS:
        raise PublicLedgerError("ledger entry binding fields are invalid")
    if bindings.get("campaign_id") != campaign:
        raise PublicLedgerError("ledger entry bindings use a different campaign")
    _digest(bindings.get("commitment_document_sha256"))
    _git_sha(bindings.get("ravage_source_commit"))
    _text(bindings.get("publication_certificate_identity"), "publication identity", 1000)
    if bindings.get("publication_certificate_oidc_issuer") != OIDC_ISSUER:
        raise PublicLedgerError("ledger entry publication issuer is invalid")

    digest_fields = (
        "selection_document_sha256",
        "primary_matrix_document_sha256",
        "execution_start_document_sha256",
        "primary_results_document_sha256",
        "model_gateway_document_sha256",
        "execution_terminal_document_sha256",
    )
    for name in digest_fields:
        value = bindings.get(name)
        if value is not None:
            _digest(value)

    required_by_phase = {
        "commitment": frozenset(),
        "matrix": frozenset({"selection_document_sha256", "primary_matrix_document_sha256"}),
        "start": frozenset(
            {
                "selection_document_sha256",
                "primary_matrix_document_sha256",
                "execution_start_document_sha256",
            }
        ),
        "results": frozenset(
            {
                "selection_document_sha256",
                "primary_matrix_document_sha256",
                "execution_start_document_sha256",
                "execution_terminal_document_sha256",
            }
        ),
    }[_phase(phase)]
    if any(bindings.get(name) is None for name in required_by_phase):
        raise PublicLedgerError("ledger entry is missing a binding required by its phase")

    future_by_phase = {
        "commitment": frozenset(digest_fields),
        "matrix": frozenset(digest_fields[2:]),
        "start": frozenset(digest_fields[3:]),
        "results": frozenset(),
    }[_phase(phase)]
    if any(bindings.get(name) is not None for name in future_by_phase):
        raise PublicLedgerError("ledger entry contains a binding from a future phase")
    return bindings


def _require_preserved_bindings(
    previous: Mapping[str, object],
    current: Mapping[str, object],
) -> None:
    if set(current) != BINDING_FIELDS:
        raise PublicLedgerError("current ledger binding fields are invalid")
    for name, value in previous.items():
        if value is not None and current.get(name) != value:
            raise PublicLedgerError(f"ledger phase changed an earlier binding: {name}")


def _write_payload_zip(payload_root: Path, output_path: Path) -> None:
    root = _directory(payload_root, "submission payload")
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with (
            os.fdopen(descriptor, "wb", closefd=False) as raw,
            zipfile.ZipFile(
                raw, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True
            ) as archive,
        ):
            for relative in _payload_paths(root):
                body = _read_regular(
                    root / relative,
                    f"payload artifact {relative}",
                    _artifact_byte_limit(relative),
                )
                info = zipfile.ZipInfo(relative, date_time=_ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | _artifact_mode(relative)) << 16
                archive.writestr(info, body)
    finally:
        os.close(descriptor)


def _verify_payload_zip(path: Path, artifacts: Sequence[Mapping[str, object]]) -> None:
    expected = {cast("str", item["path"]): item for item in artifacts}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > _MAX_ARTIFACTS:
                raise PublicLedgerError("payload ZIP contains too many entries")
            if [info.filename for info in infos] != list(expected):
                raise PublicLedgerError("payload ZIP entries differ from the signed manifest")
            total = 0
            for info in infos:
                relative = _relative_path(info.filename)
                total += info.file_size
                if (
                    info.date_time != _ZIP_TIMESTAMP
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.is_dir()
                    or (info.external_attr >> 16) != (stat.S_IFREG | _artifact_mode(relative))
                    or info.file_size > _artifact_byte_limit(relative)
                    or total > _MAX_PAYLOAD_BYTES
                ):
                    raise PublicLedgerError("payload ZIP metadata is not canonical")
                body = archive.read(info)
                record = expected[info.filename]
                if len(body) != record["size_bytes"] or _sha256(body) != record["sha256"]:
                    raise PublicLedgerError("payload ZIP member digest mismatch")
    except (OSError, zipfile.BadZipFile) as exc:
        raise PublicLedgerError("payload ZIP is invalid") from exc


def _verify_payload_semantics(
    path: Path,
    artifacts: Sequence[Mapping[str, object]],
    *,
    phase: str,
    expected_bindings: Mapping[str, object],
    trusted_verifiers: _TrustedProtocolVerifiers | None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="ravage-ledger-payload-") as temporary:
        root = Path(temporary)
        try:
            with zipfile.ZipFile(path, "r") as archive:
                for artifact in artifacts:
                    relative = cast("str", artifact["path"])
                    destination = _safe_payload_path(root, relative)
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    _write_exclusive(
                        destination,
                        archive.read(relative),
                        mode=_artifact_mode(relative),
                    )
        except (OSError, KeyError, zipfile.BadZipFile) as exc:
            raise PublicLedgerError("payload ZIP cannot be validated") from exc
        paths, bindings = _validated_campaign_phase(
            root,
            phase,
            trusted_verifiers=trusted_verifiers,
        )
        if paths != tuple(item["path"] for item in artifacts) or bindings != expected_bindings:
            raise PublicLedgerError("entry payload semantics differ from its signed bindings")


def _read_zip_member(path: Path, member: str) -> bytes:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            return archive.read(member)
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise PublicLedgerError(f"payload ZIP member is unavailable: {member}") from exc


def _verify_frozen_crypto_inputs(
    payload_path: Path,
    *,
    cosign_path: Path,
    trusted_root_path: Path,
) -> tuple[bytes, bytes]:
    """Bind caller-trusted verification tools to the frozen commitment policy."""

    commitment_raw = _read_zip_member(payload_path, "commitment.json")
    commitment = _decode_json(commitment_raw, "payload commitment")
    if not isinstance(commitment, Mapping):
        raise PublicLedgerError("payload commitment must be a JSON object")
    authenticity = _mapping(commitment.get("authenticity_policy"), "authenticity policy")
    publication = _mapping(authenticity.get("publication"), "publication policy")
    if (
        publication.get("cosign_binary_file") != "verifiers/cosign"
        or publication.get("trusted_root_file") != "verifiers/sigstore-trusted-root.json"
    ):
        raise PublicLedgerError("commitment verification input paths are invalid")

    cosign = _read_regular(cosign_path, "Cosign executable", _MAX_ARTIFACT_BYTES)
    expected_cosign_size = _positive_int(
        publication.get("cosign_binary_size"), "committed Cosign binary size"
    )
    if expected_cosign_size > _MAX_ARTIFACT_BYTES:
        raise PublicLedgerError("committed Cosign binary exceeds the byte limit")
    if len(cosign) != expected_cosign_size or _sha256(cosign) != _digest(
        publication.get("cosign_binary_sha256")
    ):
        raise PublicLedgerError("caller-supplied Cosign differs from the commitment")

    trusted_root = _read_regular(
        trusted_root_path,
        "Sigstore trusted root",
        _MAX_JSON_BYTES,
    )
    archived_trusted_root = _read_zip_member(
        payload_path,
        "verifiers/sigstore-trusted-root.json",
    )
    expected_root_digest = _digest(publication.get("trusted_root_sha256"))
    if (
        trusted_root != archived_trusted_root
        or _sha256(trusted_root) != expected_root_digest
        or _sha256(archived_trusted_root) != expected_root_digest
    ):
        raise PublicLedgerError(
            "caller-supplied trusted root differs from the commitment-bound payload"
        )
    return cosign, trusted_root


def _verify_cosign(
    cosign_bytes: bytes,
    trusted_root_bytes: bytes,
    *,
    artifact_bytes: bytes,
    bundle_bytes: bytes,
    identity: str,
    repository: str,
    workflow_sha: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="ravage-ledger-verify-") as temporary:
        snapshot_root = Path(temporary)
        cosign = snapshot_root / "cosign"
        trusted_root = snapshot_root / "trusted-root.json"
        artifact = snapshot_root / "artifact"
        bundle = snapshot_root / "bundle.json"
        _write_exclusive(cosign, cosign_bytes, mode=0o700)
        _write_exclusive(trusted_root, trusted_root_bytes)
        _write_exclusive(artifact, artifact_bytes)
        _write_exclusive(bundle, bundle_bytes)
        environment = {"PATH": "/usr/bin:/bin", "HOME": temporary}
        command = (
            str(cosign),
            "verify-blob",
            "--bundle",
            str(bundle),
            "--trusted-root",
            str(trusted_root),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            OIDC_ISSUER,
            "--certificate-github-workflow-repository",
            repository,
            "--certificate-github-workflow-ref",
            "refs/heads/main",
            "--certificate-github-workflow-sha",
            workflow_sha,
            "--certificate-github-workflow-trigger",
            "workflow_dispatch",
            "--offline",
            "--use-signed-timestamps",
            str(artifact),
        )
        try:
            result = subprocess.run(  # noqa: S603
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=90,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PublicLedgerError("Cosign verification failed") from exc
    if (
        result.returncode != 0
        or len(result.stdout) > _MAX_SUBPROCESS_OUTPUT
        or len(result.stderr) > _MAX_SUBPROCESS_OUTPUT
    ):
        raise PublicLedgerError("Sigstore bundle did not verify offline against frozen policy")


def _service_present(value: object, url: str, *, exact_count: bool) -> bool:
    if not isinstance(value, list) or (exact_count and len(value) != 1):
        return False
    return any(
        isinstance(item, Mapping)
        and item.get("url") == url
        and item.get("operator") == "sigstore.dev"
        and item.get("majorApiVersion") == 1
        for item in value
    )


def _artifact_records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value or len(value) > _MAX_ARTIFACTS:
        raise PublicLedgerError("artifact manifest must be a non-empty list")
    records: list[dict[str, object]] = []
    previous = ""
    total = 0
    for item in value:
        record = _mapping(item, "artifact manifest record")
        if set(record) != {"path", "sha256", "size_bytes"}:
            raise PublicLedgerError("artifact manifest fields are invalid")
        path = _relative_path(record["path"])
        if path <= previous:
            raise PublicLedgerError("artifact manifest paths must be unique and sorted")
        previous = path
        size = _nonnegative_int(record["size_bytes"], "artifact size")
        if size > _artifact_byte_limit(path):
            raise PublicLedgerError(f"artifact exceeds its per-file byte limit: {path}")
        total += size
        if total > _MAX_PAYLOAD_BYTES:
            raise PublicLedgerError("artifact manifest exceeds the total byte limit")
        records.append({"path": path, "sha256": _digest(record["sha256"]), "size_bytes": size})
    return records


def _payload_paths(root: Path) -> tuple[str, ...]:
    paths: list[str] = []
    for candidate in sorted(root.rglob("*")):
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise PublicLedgerError("payload cannot contain symbolic links")
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise PublicLedgerError("payload cannot contain hard-linked files")
            paths.append(_relative_path(candidate.relative_to(root).as_posix()))
            if len(paths) > _MAX_ARTIFACTS:
                raise PublicLedgerError("payload contains too many files")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise PublicLedgerError("payload contains a non-regular filesystem entry")
    return tuple(sorted(paths))


def _artifact_byte_limit(relative: str) -> int:
    normalized = _relative_path(relative)
    if normalized in _FROZEN_VERIFIER_FILES[:2]:
        return _MAX_ARTIFACT_BYTES
    if normalized.startswith("attempts/primary/"):
        return _MAX_ROW_ARTIFACT_BYTES
    return _MAX_ROW_ARTIFACT_BYTES


def _artifact_mode(relative: str) -> int:
    return 0o700 if _relative_path(relative) in _FROZEN_VERIFIER_FILES[:2] else 0o600


def _validate_publication_hygiene(
    root: Path,
    paths: Sequence[str],
    *,
    phase: str,
) -> None:
    """Reject unsafe filesystem objects and recognizable retained credentials.

    The scan is intentionally a publication safety gate, not an assurance that
    arbitrary child-controlled bytes can never encode a secret.  Exact row
    gateway-token hashes let us reject their ordinary, hexadecimal, or base64
    byte variants without retaining the raw tokens themselves.
    """

    if not paths or len(paths) > _MAX_ARTIFACTS or tuple(paths) != tuple(sorted(set(paths))):
        raise PublicLedgerError("phase artifact paths must be non-empty, unique, and sorted")
    gateway_token_digests: set[str] = set()
    if phase == "results":
        for relative in paths:
            if relative.startswith("attempts/primary/") and relative.endswith(
                "/model-gateway-receipt.json"
            ):
                receipt = _coordinator_document(root / relative, "row model gateway receipt")
                gateway_token_digests.add(_digest(receipt.get("row_token_sha256")))
        if len(gateway_token_digests) != 40:
            raise PublicLedgerError("publication hygiene cannot bind forty row-token digests")

    total = 0
    for relative in paths:
        normalized = _relative_path(relative)
        basename = PurePosixPath(normalized).name.casefold()
        if basename in {".env", "credentials.json", "id_rsa", "id_ed25519"} or basename.endswith(
            (".p12", ".pfx", ".key")
        ):
            raise PublicLedgerError(f"payload contains a credential-bearing path: {normalized}")
        body = _campaign_artifact_bytes(root, normalized)
        total += len(body)
        if total > _MAX_PAYLOAD_BYTES:
            raise PublicLedgerError("publication payload exceeds the total byte limit")
        if normalized not in _FROZEN_VERIFIER_FILES[:2]:
            _reject_high_confidence_secrets(normalized, body)
            _reject_gateway_token_variants(normalized, body, gateway_token_digests)
        if normalized.endswith(".json"):
            value = _decode_json(body, f"publication JSON {normalized}")
            _reject_sensitive_json_fields(value, path=normalized)


def _reject_high_confidence_secrets(relative: str, body: bytes) -> None:
    for label, pattern in _HIGH_CONFIDENCE_SECRET_PATTERNS:
        if pattern.search(body) is not None:
            raise PublicLedgerError(
                f"publication artifact contains a recognizable {label}: {relative}"
            )


def _reject_gateway_token_variants(
    relative: str,
    body: bytes,
    token_digests: set[str],
) -> None:
    if not token_digests:
        return
    candidates: set[bytes] = set(_GATEWAY_TOKEN_TEXT_RE.findall(body))
    for encoded in _GATEWAY_TOKEN_HEX_RE.findall(body):
        try:
            candidates.add(bytes.fromhex(encoded.decode("ascii")))
        except (UnicodeDecodeError, ValueError):
            continue
    for encoded in _GATEWAY_TOKEN_BASE64_RE.findall(body):
        try:
            candidates.add(base64.b64decode(encoded, validate=True))
        except ValueError:
            continue
    if any(_sha256(candidate) in token_digests for candidate in candidates):
        raise PublicLedgerError(
            f"publication artifact contains a raw row gateway token: {relative}"
        )


def _reject_sensitive_json_fields(value: object, *, path: str) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise PublicLedgerError(f"publication JSON has a non-string key: {path}")
            key = raw_key.casefold().replace("-", "_")
            if key in _SENSITIVE_JSON_KEYS and not _redacted_or_digest(child):
                raise PublicLedgerError(
                    f"publication JSON contains a sensitive field value: {path}:{raw_key}"
                )
            _reject_sensitive_json_fields(child, path=path)
    elif isinstance(value, list):
        for child in value:
            _reject_sensitive_json_fields(child, path=path)


def _redacted_or_digest(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    return _SHA_RE.fullmatch(normalized) is not None or "redacted" in normalized.casefold()


def _protocol_document(path: Path, label: str) -> dict[str, object]:
    value = _load_json(path, label)
    digest = _digest(value.get("document_digest"))
    body = {key: item for key, item in value.items() if key != "document_digest"}
    if digest != _sha256(_canonical_json(body, ensure_ascii=True)):
        raise PublicLedgerError(f"{label} document digest mismatch")
    return value


def _coordinator_document(path: Path, label: str) -> dict[str, object]:
    value = _load_json(path, label)
    digest = _digest(value.get("document_sha256"))
    body = {key: item for key, item in value.items() if key != "document_sha256"}
    if digest != _sha256(_canonical_json(body, ensure_ascii=False)):
        raise PublicLedgerError(f"{label} document digest mismatch")
    return value


def _document(body: Mapping[str, object]) -> dict[str, object]:
    value = dict(body)
    return {**value, "document_sha256": _sha256(_canonical_json(value, ensure_ascii=True))}


def _json_document(raw: bytes, label: str, schema: str) -> dict[str, object]:
    value = _decode_json(raw, label)
    if not isinstance(value, dict) or value.get("schema_version") != schema:
        raise PublicLedgerError(f"{label} schema is unsupported")
    digest = _digest(value.get("document_sha256"))
    body = {key: item for key, item in value.items() if key != "document_sha256"}
    if digest != _sha256(_canonical_json(body, ensure_ascii=True)):
        raise PublicLedgerError(f"{label} document digest mismatch")
    return value


def _load_json(path: Path, label: str) -> dict[str, object]:
    raw = _read_regular(_regular_file(path, label), label, _MAX_JSON_BYTES)
    value = _decode_json(raw, label)
    if not isinstance(value, dict):
        raise PublicLedgerError(f"{label} must be a JSON object")
    return value


def _decode_json(raw: bytes, label: str) -> object:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PublicLedgerError(f"{label} is not valid UTF-8 JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_nonfinite_json(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _canonical_json(value: object, *, ensure_ascii: bool) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=ensure_ascii,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PublicLedgerError("ledger value is not canonical JSON") from exc


def _write_json_exclusive(path: Path, value: Mapping[str, object]) -> None:
    raw = json.dumps(value, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _write_exclusive(path, raw)


def _write_exclusive(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise PublicLedgerError(f"refusing to overwrite ledger artifact: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    source = _regular_file(path, label)
    try:
        size = source.stat().st_size
        if size > maximum:
            raise PublicLedgerError(f"{label} exceeds the byte limit")
        raw = source.read_bytes()
    except OSError as exc:
        raise PublicLedgerError(f"cannot read {label}") from exc
    if len(raw) != size or len(raw) > maximum:
        raise PublicLedgerError(f"{label} changed while it was read")
    return raw


def _regular_file(path: Path, label: str) -> Path:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise PublicLedgerError(f"{label} does not exist") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise PublicLedgerError(f"{label} must be a regular file")
    return candidate


def _directory(path: Path, label: str) -> Path:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise PublicLedgerError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PublicLedgerError(f"{label} must be a real directory")
    return candidate


def _create_directory(path: Path, label: str) -> Path:
    destination = Path(path)
    try:
        destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    except OSError as exc:
        raise PublicLedgerError(f"refusing to reuse {label}: {destination}") from exc
    return _directory(destination, label)


def _create_child_directory(parent: Path, name: str) -> Path:
    target = _directory(parent, "ledger parent") / name
    try:
        target.mkdir(mode=0o700, exist_ok=False)
    except OSError as exc:
        raise PublicLedgerError(f"refusing to reuse ledger child: {target}") from exc
    return _directory(target, "ledger child")


def _safe_payload_path(root: Path, relative: str) -> Path:
    normalized = _relative_path(relative)
    return root.joinpath(*PurePosixPath(normalized).parts)


def _relative_path(value: object) -> str:
    text = _text(value, "artifact path", 500)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(path.parts) > 32
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
    ):
        raise PublicLedgerError("artifact path is unsafe")
    if {"rerun", "reruns"}.intersection(part.casefold() for part in path.parts):
        raise PublicLedgerError("diagnostic reruns cannot enter the primary public ledger")
    return text


def _exact_release_url(value: object, repository: str, tag: str) -> str:
    text = _text(value, "release URL", 1000)
    if text != f"https://github.com/{repository}/releases/tag/{tag}":
        raise PublicLedgerError("release URL is not the fixed campaign phase URL")
    return text


def _canonical_base64(value: object, label: str) -> bytes:
    text = _text(value, label, 2 * _MAX_JSON_BYTES)
    try:
        decoded = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise PublicLedgerError(f"{label} is not canonical base64") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != text:
        raise PublicLedgerError(f"{label} is not canonical base64")
    return decoded


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise PublicLedgerError(f"{label} must be an object")
    return cast("Mapping[str, object]", value)


def _phase(value: object) -> str:
    if not isinstance(value, str) or value not in PHASES:
        raise PublicLedgerError("ledger phase is unsupported")
    return value


def _campaign(value: object) -> str:
    if not isinstance(value, str) or _CAMPAIGN_RE.fullmatch(value) is None:
        raise PublicLedgerError("campaign ID is invalid")
    return value


def _repository(value: object) -> str:
    if not isinstance(value, str) or _REPOSITORY_RE.fullmatch(value) is None:
        raise PublicLedgerError("GitHub repository identity is invalid")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None:
        raise PublicLedgerError("Git commit SHA is invalid")
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise PublicLedgerError("SHA-256 digest is invalid")
    return value


def _text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or value.strip() != value:
        raise PublicLedgerError(f"{label} is invalid")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise PublicLedgerError(f"{label} contains control characters")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PublicLedgerError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PublicLedgerError(f"{label} must be a non-negative integer")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or verify paired-XBEN public-ledger artifacts"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-submission")
    create.add_argument("--campaign-dir", type=Path, required=True)
    create.add_argument("--output-dir", type=Path, required=True)
    create.add_argument("--phase", choices=PHASES, required=True)
    create.add_argument("--previous-entry", type=Path)
    create.add_argument("--drand-verifier", type=Path)
    create.add_argument("--cosign", type=Path)
    create.add_argument("--trusted-root", type=Path)
    validate = commands.add_parser("validate-submission")
    validate.add_argument("--submission-dir", type=Path, required=True)
    validate.add_argument("--campaign-id", required=True)
    validate.add_argument("--phase", choices=PHASES, required=True)
    validate.add_argument("--expected-file-sha256", required=True)
    validate.add_argument("--drand-verifier", type=Path)
    validate.add_argument("--cosign", type=Path)
    validate.add_argument("--trusted-root", type=Path)
    signing = commands.add_parser("validate-signing-config")
    signing.add_argument("--path", type=Path, required=True)
    prepare = commands.add_parser("prepare-entry")
    prepare.add_argument("--submission-dir", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--repository-id", type=int, required=True)
    prepare.add_argument("--workflow-sha", required=True)
    prepare.add_argument("--run-id", type=int, required=True)
    prepare.add_argument("--run-attempt", type=int, required=True)
    prepare.add_argument("--actor-id", type=int, required=True)
    prepare.add_argument("--release-id", type=int, required=True)
    prepare.add_argument("--release-url", required=True)
    prepare.add_argument("--source-run-id", type=int, required=True)
    prepare.add_argument("--source-run-head-sha", required=True)
    prepare.add_argument("--source-artifact-name", required=True)
    prepare.add_argument("--previous-entry", type=Path)
    prepare.add_argument("--drand-verifier", type=Path)
    prepare.add_argument("--cosign", type=Path)
    prepare.add_argument("--trusted-root", type=Path)
    verify = commands.add_parser("verify-ledger")
    verify.add_argument("--ledger-root", type=Path, required=True)
    verify.add_argument("--cosign", type=Path)
    verify.add_argument("--trusted-root", type=Path)
    verify.add_argument("--drand-verifier", type=Path)
    verify.add_argument("--protocol-cosign", type=Path)
    verify.add_argument("--protocol-trusted-root", type=Path)
    verify.add_argument("--repository")
    one = commands.add_parser("verify-entry")
    one.add_argument("--entry-dir", type=Path, required=True)
    one.add_argument("--cosign", type=Path)
    one.add_argument("--trusted-root", type=Path)
    one.add_argument("--drand-verifier", type=Path)
    one.add_argument("--protocol-cosign", type=Path)
    one.add_argument("--protocol-trusted-root", type=Path)
    one.add_argument("--repository")
    tag = commands.add_parser("tag")
    tag.add_argument("--campaign-id", required=True)
    tag.add_argument("--phase", choices=PHASES, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create-submission":
            path = create_submission(
                args.campaign_dir,
                args.output_dir,
                phase=args.phase,
                previous_entry_path=args.previous_entry,
                drand_verifier_path=args.drand_verifier,
                cosign_path=args.cosign,
                trusted_root_path=args.trusted_root,
            )
            payload: object = {"submission": str(path), "file_sha256": _sha256(path.read_bytes())}
        elif args.command == "validate-submission":
            payload = validate_submission(
                args.submission_dir,
                expected_campaign_id=args.campaign_id,
                expected_phase=args.phase,
                expected_file_sha256=args.expected_file_sha256,
                drand_verifier_path=args.drand_verifier,
                cosign_path=args.cosign,
                trusted_root_path=args.trusted_root,
            )
        elif args.command == "validate-signing-config":
            payload = {"valid": True, "config": validate_signing_config(args.path)}
        elif args.command == "prepare-entry":
            path = prepare_entry(
                args.submission_dir,
                args.output_dir,
                repository=args.repository,
                repository_id=args.repository_id,
                workflow_sha=args.workflow_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                actor_id=args.actor_id,
                release_id=args.release_id,
                release_url=args.release_url,
                source_run_id=args.source_run_id,
                source_run_head_sha=args.source_run_head_sha,
                source_artifact_name=args.source_artifact_name,
                previous_entry_path=args.previous_entry,
                drand_verifier_path=args.drand_verifier,
                cosign_path=args.cosign,
                trusted_root_path=args.trusted_root,
            )
            payload = {
                "entry": str(path),
                "document_sha256": _load_json(path, "entry")["document_sha256"],
            }
        elif args.command == "verify-ledger":
            payload = verify_ledger(
                args.ledger_root,
                cosign_path=args.cosign,
                trusted_root_path=args.trusted_root,
                drand_verifier_path=args.drand_verifier,
                protocol_cosign_path=args.protocol_cosign,
                protocol_trusted_root_path=args.protocol_trusted_root,
                expected_repository=args.repository,
            )
        elif args.command == "verify-entry":
            payload = verify_entry(
                args.entry_dir,
                cosign_path=args.cosign,
                trusted_root_path=args.trusted_root,
                drand_verifier_path=args.drand_verifier,
                protocol_cosign_path=args.protocol_cosign,
                protocol_trusted_root_path=args.protocol_trusted_root,
                expected_repository=args.repository,
            )
        else:
            payload = {
                "tag": release_tag(args.campaign_id, args.phase),
                "previous_tag": previous_release_tag(args.campaign_id, args.phase),
            }
    except (OSError, PublicLedgerError) as exc:
        sys.stderr.write(f"[paired-xben-public-ledger:blocked] {exc}\n")
        return 2
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ENTRY_SCHEMA",
    "PHASES",
    "SUBMISSION_SCHEMA",
    "PublicLedgerError",
    "create_submission",
    "main",
    "prepare_entry",
    "previous_release_tag",
    "release_tag",
    "validate_signing_config",
    "validate_sigstore_bundle",
    "validate_submission",
    "verify_entry",
    "verify_ledger",
]
