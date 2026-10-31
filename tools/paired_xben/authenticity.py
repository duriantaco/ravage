"""Cryptographic authenticity gates for the paired-XBEN draw.

The protocol does not accept operator-entered URLs or timestamps as evidence.
A draw becomes usable only when:

* the resolver itself downloads matching exact-round responses from two fixed
  official drand relays and retains their exact HTTP bodies;
* a retained verifier using the pinned official drand library validates its
  BLS signature against chain information whose hash matches the commitment;
* a patched cosign binary verifies a standardized Sigstore v0.3 bundle over
  the exact commitment bytes against a frozen identity, issuer, and trusted
  root; and
* a verified RFC3161 TSA time over the commitment precedes the draw round.

All subprocesses use argv arrays (never a shell), fixed timeouts, bounded
outputs, and copied create-only verifier binaries whose digests are frozen in
the commitment.

Scope limitation: these offline artifacts prove that *this* commitment was
published before its draw. They cannot discover another pre-draw commitment
for a different future round. A public "no alternative commitments" claim
therefore also needs a canonical append-only namespace whose independently
enforced rule is first-entry-wins. The policy and verification output expose
this limitation rather than treating a Rekor entry as global uniqueness.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Final, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

AUTHENTICITY_POLICY_SCHEMA: Final = "ravage.paired-xben.authenticity-policy.v1"
DRAND_RECEIPT_SCHEMA: Final = "ravage.paired-xben.drand-verification.v1"
DRAND_SELF_SCHEMA: Final = "ravage.paired-xben.drand-verifier-self.v1"
PUBLICATION_RECEIPT_SCHEMA: Final = "ravage.paired-xben.sigstore-verification.v1"
DRAND_LIBRARY_MODULE: Final = "github.com/drand/drand/v2"
DRAND_LIBRARY_VERSION: Final = "v2.1.6"
MINIMUM_COSIGN_VERSION: Final = (3, 1, 3)
SIGSTORE_BUNDLE_MEDIA_TYPE: Final = "application/vnd.dev.sigstore.bundle.v0.3+json"

DRAND_BINARY_FILE: Final = "verifiers/drandverify"
COSIGN_BINARY_FILE: Final = "verifiers/cosign"
SIGSTORE_TRUSTED_ROOT_FILE: Final = "verifiers/sigstore-trusted-root.json"

MAX_JSON_BYTES: Final = 256 * 1024
MAX_TRUSTED_ROOT_BYTES: Final = 2 * 1024 * 1024
MAX_VERIFIER_BYTES: Final = 300 * 1024 * 1024
MAX_SUBPROCESS_OUTPUT_BYTES: Final = 64 * 1024
SUBPROCESS_TIMEOUT_SECONDS: Final = 90
DRAND_HTTP_TIMEOUT_SECONDS: Final = 20

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_HEX_64_RE = re.compile(r"[0-9a-f]{64}")
_COSIGN_VERSION_RE = re.compile(r"(?m)^GitVersion:\s*v?(\d+)\.(\d+)\.(\d+)(?:[-+][^\s]+)?\s*$")
DRAND_RELAY_URL_TEMPLATES: Final = (
    "https://api.drand.sh/{chain_hash}/public/{round_number}",
    "https://drand.cloudflare.com/{chain_hash}/public/{round_number}",
)
_DRAND_SOURCE_FILES = ("main.go", "go.mod", "go.sum")


class AuthenticityError(ValueError):
    """Resolution evidence did not meet the cryptographic gate."""


@dataclass(frozen=True, slots=True)
class DrandRelayResponse:
    """One resolver-owned HTTPS retrieval and its exact response body."""

    source_url: str
    body: bytes


def drand_source_bundle_digest() -> str:
    """Digest the reviewable source and module lock used to build the helper."""

    source_root = Path(__file__).resolve().parent / "drandverify"
    entries: list[dict[str, str]] = []
    for name in _DRAND_SOURCE_FILES:
        content = _read_bounded_regular(source_root / name, MAX_JSON_BYTES, f"drand {name}")
        entries.append({"path": name, "sha256": _sha256(content)})
    return _sha256(_canonical_json(entries))


def prepare_authenticity_policy(
    *,
    drand_verifier_binary_path: Path,
    cosign_binary_path: Path,
    sigstore_trusted_root_path: Path,
    publication_certificate_identity: str,
    publication_certificate_oidc_issuer: str,
) -> dict[str, object]:
    """Inspect verifiers before the future round and return their frozen policy."""

    source_digest = drand_source_bundle_digest()
    drand_path = _executable(drand_verifier_binary_path, "drand verifier")
    drand_digest, drand_size = _file_digest(drand_path, MAX_VERIFIER_BYTES, "drand verifier")
    cosign_path = _executable(cosign_binary_path, "cosign verifier")
    cosign_digest, cosign_size = _file_digest(cosign_path, MAX_VERIFIER_BYTES, "cosign verifier")
    with tempfile.TemporaryDirectory(prefix="ravage-auth-policy-") as temporary:
        snapshot_root = Path(temporary)
        drand_snapshot = snapshot_root / "drandverify"
        cosign_snapshot = snapshot_root / "cosign"
        _copy_exclusive(
            drand_path,
            drand_snapshot,
            expected_digest=drand_digest,
            expected_size=drand_size,
            executable=True,
            label="drand verifier",
        )
        _copy_exclusive(
            cosign_path,
            cosign_snapshot,
            expected_digest=cosign_digest,
            expected_size=cosign_size,
            executable=True,
            label="cosign verifier",
        )
        self_info = _run_json(
            [str(drand_snapshot), "--self-info"],
            label="drand verifier self-info",
        )
        cosign_version = _cosign_version(cosign_snapshot)
    if self_info != {
        "schema_version": DRAND_SELF_SCHEMA,
        "library_module": DRAND_LIBRARY_MODULE,
        "library_version": DRAND_LIBRARY_VERSION,
        "source_bundle_sha256": source_digest,
    }:
        raise AuthenticityError(
            "drand verifier is not bound to the current pinned official helper source"
        )
    trusted_root = _read_bounded_regular(
        sigstore_trusted_root_path,
        MAX_TRUSTED_ROOT_BYTES,
        "Sigstore trusted root",
    )
    _decode_json(trusted_root, "Sigstore trusted root")
    identity = _bounded_text(
        publication_certificate_identity,
        "publication certificate identity",
        maximum=1000,
    )
    issuer = _bounded_text(
        publication_certificate_oidc_issuer,
        "publication certificate OIDC issuer",
        maximum=1000,
    )
    _require_https_url(issuer, "publication certificate OIDC issuer")
    return {
        "schema_version": AUTHENTICITY_POLICY_SCHEMA,
        "drand": {
            "relay_quorum": 2,
            "relay_url_templates": list(DRAND_RELAY_URL_TEMPLATES),
            "library_module": DRAND_LIBRARY_MODULE,
            "library_version": DRAND_LIBRARY_VERSION,
            "source_bundle_sha256": source_digest,
            "binary_file": DRAND_BINARY_FILE,
            "binary_sha256": drand_digest,
            "binary_size": drand_size,
        },
        "publication": {
            "kind": "sigstore-keyless-rekor-v0.3",
            "bundle_media_type": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "certificate_identity": identity,
            "certificate_oidc_issuer": issuer,
            "cosign_minimum_version": _version_text(MINIMUM_COSIGN_VERSION),
            "cosign_version": cosign_version,
            "cosign_binary_file": COSIGN_BINARY_FILE,
            "cosign_binary_sha256": cosign_digest,
            "cosign_binary_size": cosign_size,
            "trusted_root_file": SIGSTORE_TRUSTED_ROOT_FILE,
            "trusted_root_sha256": _sha256(trusted_root),
            "offline_verification_required": True,
            "transparency_log_inclusion_proof_required": True,
            "rfc3161_timestamp_required": True,
            "canonical_namespace_required_for_no_alternatives_claim": True,
            "offline_namespace_uniqueness_verifiable": False,
        },
    }


def copy_frozen_verifiers(
    campaign_root: Path,
    *,
    policy: Mapping[str, object],
    drand_verifier_binary_path: Path,
    cosign_binary_path: Path,
    sigstore_trusted_root_path: Path,
) -> None:
    """Copy inspected verifier material create-only into a new campaign."""

    normalized = validate_authenticity_policy(policy)
    verifier_root = _exclusive_directory(campaign_root / "verifiers")
    drand = _mapping(normalized["drand"], "drand authenticity policy")
    publication = _mapping(normalized["publication"], "publication authenticity policy")
    _copy_exclusive(
        drand_verifier_binary_path,
        verifier_root / "drandverify",
        expected_digest=str(drand["binary_sha256"]),
        expected_size=_positive_bounded_int(
            drand["binary_size"], "drand verifier binary size", MAX_VERIFIER_BYTES
        ),
        executable=True,
        label="drand verifier",
    )
    _copy_exclusive(
        cosign_binary_path,
        verifier_root / "cosign",
        expected_digest=str(publication["cosign_binary_sha256"]),
        expected_size=_positive_bounded_int(
            publication["cosign_binary_size"], "cosign binary size", MAX_VERIFIER_BYTES
        ),
        executable=True,
        label="cosign verifier",
    )
    _copy_exclusive(
        sigstore_trusted_root_path,
        verifier_root / "sigstore-trusted-root.json",
        expected_digest=str(publication["trusted_root_sha256"]),
        expected_size=None,
        executable=False,
        label="Sigstore trusted root",
    )


def validate_authenticity_policy(policy: Mapping[str, object]) -> dict[str, object]:
    """Validate a commitment's frozen authenticity policy."""

    value = dict(policy)
    if set(value) != {"schema_version", "drand", "publication"}:
        raise AuthenticityError("authenticity policy fields are invalid")
    if value["schema_version"] != AUTHENTICITY_POLICY_SCHEMA:
        raise AuthenticityError("authenticity policy schema is unsupported")
    drand = _mapping(value["drand"], "drand authenticity policy")
    if set(drand) != {
        "relay_quorum",
        "relay_url_templates",
        "library_module",
        "library_version",
        "source_bundle_sha256",
        "binary_file",
        "binary_sha256",
        "binary_size",
    }:
        raise AuthenticityError("drand authenticity policy fields are invalid")
    if (
        drand["relay_quorum"] != 2
        or drand["relay_url_templates"] != list(DRAND_RELAY_URL_TEMPLATES)
        or drand["library_module"] != DRAND_LIBRARY_MODULE
        or drand["library_version"] != DRAND_LIBRARY_VERSION
        or drand["source_bundle_sha256"] != drand_source_bundle_digest()
        or drand["binary_file"] != DRAND_BINARY_FILE
    ):
        raise AuthenticityError("drand authenticity policy is not the supported pinned policy")
    _digest(drand["binary_sha256"], "drand verifier binary digest")
    _positive_bounded_int(drand["binary_size"], "drand verifier binary size", MAX_VERIFIER_BYTES)

    publication = _mapping(value["publication"], "publication authenticity policy")
    if set(publication) != {
        "kind",
        "bundle_media_type",
        "certificate_identity",
        "certificate_oidc_issuer",
        "cosign_minimum_version",
        "cosign_version",
        "cosign_binary_file",
        "cosign_binary_sha256",
        "cosign_binary_size",
        "trusted_root_file",
        "trusted_root_sha256",
        "offline_verification_required",
        "transparency_log_inclusion_proof_required",
        "rfc3161_timestamp_required",
        "canonical_namespace_required_for_no_alternatives_claim",
        "offline_namespace_uniqueness_verifiable",
    }:
        raise AuthenticityError("publication authenticity policy fields are invalid")
    if (
        publication["kind"] != "sigstore-keyless-rekor-v0.3"
        or publication["bundle_media_type"] != SIGSTORE_BUNDLE_MEDIA_TYPE
        or publication["cosign_minimum_version"] != _version_text(MINIMUM_COSIGN_VERSION)
        or publication["cosign_binary_file"] != COSIGN_BINARY_FILE
        or publication["trusted_root_file"] != SIGSTORE_TRUSTED_ROOT_FILE
        or publication["offline_verification_required"] is not True
        or publication["transparency_log_inclusion_proof_required"] is not True
        or publication["rfc3161_timestamp_required"] is not True
        or publication["canonical_namespace_required_for_no_alternatives_claim"] is not True
        or publication["offline_namespace_uniqueness_verifiable"] is not False
    ):
        raise AuthenticityError("publication authenticity policy is not fail-closed")
    _bounded_text(publication["certificate_identity"], "certificate identity", maximum=1000)
    issuer = _bounded_text(
        publication["certificate_oidc_issuer"],
        "certificate OIDC issuer",
        maximum=1000,
    )
    _require_https_url(issuer, "certificate OIDC issuer")
    if _parse_version(str(publication["cosign_version"])) < MINIMUM_COSIGN_VERSION:
        raise AuthenticityError("frozen cosign version contains a known verification bypass")
    _digest(publication["cosign_binary_sha256"], "cosign binary digest")
    _positive_bounded_int(
        publication["cosign_binary_size"],
        "cosign binary size",
        MAX_VERIFIER_BYTES,
    )
    _digest(publication["trusted_root_sha256"], "Sigstore trusted-root digest")
    return value


def fetch_official_drand_responses(
    *,
    policy: Mapping[str, object],
    chain_hash: str,
    round_number: int,
) -> tuple[DrandRelayResponse, DrandRelayResponse]:
    """Fetch an exact round from two policy-fixed official HTTPS relays.

    The caller cannot supply URLs or response files. This is the online part
    of resolution; all later campaign verification is deliberately offline.
    """

    normalized_policy = validate_authenticity_policy(policy)
    drand = _mapping(normalized_policy["drand"], "drand authenticity policy")
    if _HEX_64_RE.fullmatch(chain_hash) is None or round_number <= 0:
        raise AuthenticityError("committed drand chain or round is invalid")
    if drand["relay_url_templates"] != list(DRAND_RELAY_URL_TEMPLATES):
        raise AuthenticityError("drand relay policy is not the fixed official quorum")

    responses: list[DrandRelayResponse] = []
    for template in DRAND_RELAY_URL_TEMPLATES:
        url = template.format(chain_hash=chain_hash, round_number=round_number)
        body = _download_drand_response(url)
        _beacon_source(body, chain_hash=chain_hash, round_number=round_number)
        responses.append(
            DrandRelayResponse(
                source_url=url,
                body=body,
            )
        )
    return responses[0], responses[1]


def verify_drand_evidence(
    campaign_root: Path,
    *,
    policy: Mapping[str, object],
    chain_info_path: Path,
    primary_beacon_path: Path,
    secondary_beacon_path: Path,
    chain_hash: str,
    round_number: int,
    genesis_time: int,
    period_seconds: int,
    relay_sources: tuple[Mapping[str, object], Mapping[str, object]],
) -> dict[str, object]:
    """Verify relay agreement and a BLS signature with the retained helper."""

    normalized_policy = validate_authenticity_policy(policy)
    drand_policy = _mapping(normalized_policy["drand"], "drand authenticity policy")
    if _HEX_64_RE.fullmatch(chain_hash) is None or round_number <= 0:
        raise AuthenticityError("committed drand chain or round is invalid")

    chain_bytes = _read_bounded_regular(chain_info_path, MAX_JSON_BYTES, "drand chain info")
    primary_bytes = _read_bounded_regular(primary_beacon_path, MAX_JSON_BYTES, "primary beacon")
    secondary_bytes = _read_bounded_regular(
        secondary_beacon_path,
        MAX_JSON_BYTES,
        "secondary beacon",
    )
    primary = _beacon_source(primary_bytes, chain_hash=chain_hash, round_number=round_number)
    secondary = _beacon_source(secondary_bytes, chain_hash=chain_hash, round_number=round_number)
    normalized_sources = _validated_relay_sources(
        relay_sources,
        primary_bytes=primary_bytes,
        secondary_bytes=secondary_bytes,
        chain_hash=chain_hash,
        round_number=round_number,
    )
    compared_fields = ("round", "signature", "previous_signature", "randomness")
    if any(primary[field] != secondary[field] for field in compared_fields):
        raise AuthenticityError("official drand relay responses disagree for the committed round")

    verifier = _campaign_file(
        campaign_root,
        str(drand_policy["binary_file"]),
        "retained drand verifier",
    )
    verifier_digest, verifier_size = _file_digest(
        verifier,
        MAX_VERIFIER_BYTES,
        "retained drand verifier",
    )
    if (
        verifier_digest != drand_policy["binary_sha256"]
        or verifier_size != drand_policy["binary_size"]
    ):
        raise AuthenticityError("retained drand verifier differs from its commitment")
    with tempfile.TemporaryDirectory(prefix="ravage-drand-auth-") as temporary:
        snapshot_root = Path(temporary)
        verifier_snapshot = snapshot_root / "drandverify"
        _copy_exclusive(
            verifier,
            verifier_snapshot,
            expected_digest=verifier_digest,
            expected_size=verifier_size,
            executable=True,
            label="retained drand verifier",
        )
        chain_snapshot = _write_snapshot(snapshot_root / "chain-info.json", chain_bytes)
        beacon_snapshot = _write_snapshot(snapshot_root / "beacon.json", primary_bytes)
        self_info = _run_json(
            [str(verifier_snapshot), "--self-info"],
            label="drand verifier self-info",
        )
        if self_info != {
            "schema_version": DRAND_SELF_SCHEMA,
            "library_module": DRAND_LIBRARY_MODULE,
            "library_version": DRAND_LIBRARY_VERSION,
            "source_bundle_sha256": drand_policy["source_bundle_sha256"],
        }:
            raise AuthenticityError("retained drand verifier identity is invalid")

        receipt = _run_json(
            [
                str(verifier_snapshot),
                "--chain-info",
                str(chain_snapshot),
                "--beacon",
                str(beacon_snapshot),
                "--expected-chain-hash",
                chain_hash,
                "--expected-round",
                str(round_number),
                "--expected-genesis-time",
                str(genesis_time),
                "--expected-period-seconds",
                str(period_seconds),
            ],
            label="drand BLS verifier",
        )
    expected_receipt_fields = {
        "schema_version",
        "verified",
        "library_module",
        "library_version",
        "chain_hash",
        "round",
        "scheme",
        "randomness",
        "chain_info_sha256",
        "beacon_sha256",
        "public_key_sha256",
    }
    if set(receipt) != expected_receipt_fields:
        raise AuthenticityError("drand verifier receipt fields are invalid")
    if (
        receipt["schema_version"] != DRAND_RECEIPT_SCHEMA
        or receipt["verified"] is not True
        or receipt["library_module"] != DRAND_LIBRARY_MODULE
        or receipt["library_version"] != DRAND_LIBRARY_VERSION
        or receipt["chain_hash"] != chain_hash
        or receipt["round"] != round_number
        or receipt["randomness"] != primary["randomness"]
        or receipt["chain_info_sha256"] != _sha256(chain_bytes)
        or receipt["beacon_sha256"] != _sha256(primary_bytes)
    ):
        raise AuthenticityError("drand verifier receipt does not bind the retained evidence")
    _bounded_text(receipt["scheme"], "drand scheme", maximum=100)
    _digest(receipt["public_key_sha256"], "drand public-key digest")
    return {
        "receipt": receipt,
        "relay_quorum": 2,
        "relay_sources": normalized_sources,
        "chain_info_sha256": _sha256(chain_bytes),
        "verifier_binary_sha256": verifier_digest,
    }


def verify_publication_evidence(
    campaign_root: Path,
    *,
    policy: Mapping[str, object],
    commitment_path: Path,
    bundle_path: Path,
    commitment_created_at: str,
    draw_not_before: str,
) -> dict[str, object]:
    """Verify a Rekor-backed Sigstore bundle over the exact commitment file."""

    normalized_policy = validate_authenticity_policy(policy)
    publication = _mapping(normalized_policy["publication"], "publication policy")
    commitment = _read_bounded_regular(commitment_path, MAX_JSON_BYTES, "commitment")
    bundle_bytes = _read_bounded_regular(bundle_path, MAX_JSON_BYTES, "Sigstore bundle")
    bundle = _decode_json(bundle_bytes, "Sigstore bundle")
    if not isinstance(bundle, dict):
        raise AuthenticityError("Sigstore bundle must be a JSON object")
    if bundle.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        raise AuthenticityError("only standardized Sigstore v0.3 bundles are accepted")
    if "messageSignature" not in bundle or "dsseEnvelope" in bundle:
        raise AuthenticityError("publication bundle must carry one blob message signature")
    verification_material = _mapping(
        bundle.get("verificationMaterial"),
        "Sigstore verification material",
    )
    entries = verification_material.get("tlogEntries")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], Mapping):
        raise AuthenticityError("Sigstore bundle must contain exactly one transparency-log entry")
    entry = dict(entries[0])
    if not isinstance(entry.get("inclusionProof"), Mapping):
        raise AuthenticityError("Sigstore bundle lacks a transparency-log inclusion proof")
    integrated_seconds = _positive_bounded_int(
        entry.get("integratedTime"),
        "Rekor integrated time",
        4_102_444_800,
        allow_decimal_string=True,
    )
    integrated_time = datetime.fromtimestamp(integrated_seconds, tz=UTC)
    timestamp_data = _mapping(
        verification_material.get("timestampVerificationData"),
        "Sigstore timestamp verification data",
    )
    timestamps = timestamp_data.get("rfc3161Timestamps")
    if not isinstance(timestamps, list) or len(timestamps) != 1:
        raise AuthenticityError("Sigstore bundle must contain exactly one RFC3161 timestamp")
    timestamp_entry = _mapping(timestamps[0], "RFC3161 timestamp")
    if set(timestamp_entry) != {"signedTimestamp"} or not isinstance(
        timestamp_entry["signedTimestamp"], str
    ):
        raise AuthenticityError("RFC3161 timestamp entry is invalid")
    try:
        timestamp_response = base64.b64decode(
            timestamp_entry["signedTimestamp"],
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise AuthenticityError("RFC3161 timestamp is not canonical base64") from exc
    tsa_time = _rfc3161_gen_time(timestamp_response)
    created = _timestamp(commitment_created_at, "commitment creation time")
    draw_time = _timestamp(draw_not_before, "committed draw time")
    if tsa_time <= created or tsa_time >= draw_time:
        raise AuthenticityError(
            "verified RFC3161 time must be after commitment creation and before draw"
        )

    cosign = _campaign_file(
        campaign_root,
        str(publication["cosign_binary_file"]),
        "retained cosign verifier",
    )
    cosign_digest, cosign_size = _file_digest(
        cosign,
        MAX_VERIFIER_BYTES,
        "retained cosign verifier",
    )
    if (
        cosign_digest != publication["cosign_binary_sha256"]
        or cosign_size != publication["cosign_binary_size"]
    ):
        raise AuthenticityError("retained cosign verifier differs from its commitment")
    trusted_root = _campaign_file(
        campaign_root,
        str(publication["trusted_root_file"]),
        "retained Sigstore trusted root",
    )
    trusted_root_bytes = _read_bounded_regular(
        trusted_root,
        MAX_TRUSTED_ROOT_BYTES,
        "retained Sigstore trusted root",
    )
    if _sha256(trusted_root_bytes) != publication["trusted_root_sha256"]:
        raise AuthenticityError("retained Sigstore trusted root differs from its commitment")

    with tempfile.TemporaryDirectory(prefix="ravage-sigstore-auth-") as temporary:
        snapshot_root = Path(temporary)
        cosign_snapshot = snapshot_root / "cosign"
        _copy_exclusive(
            cosign,
            cosign_snapshot,
            expected_digest=cosign_digest,
            expected_size=cosign_size,
            executable=True,
            label="retained cosign verifier",
        )
        bundle_snapshot = _write_snapshot(snapshot_root / "bundle.json", bundle_bytes)
        commitment_snapshot = _write_snapshot(snapshot_root / "commitment.json", commitment)
        trusted_root_snapshot = _write_snapshot(
            snapshot_root / "trusted-root.json",
            trusted_root_bytes,
        )
        version = _cosign_version(cosign_snapshot)
        if version != publication["cosign_version"]:
            raise AuthenticityError("retained cosign version differs from its commitment")
        _run_command(
            [
                str(cosign_snapshot),
                "verify-blob",
                "--bundle",
                str(bundle_snapshot),
                "--trusted-root",
                str(trusted_root_snapshot),
                "--certificate-identity",
                str(publication["certificate_identity"]),
                "--certificate-oidc-issuer",
                str(publication["certificate_oidc_issuer"]),
                "--offline",
                "--use-signed-timestamps",
                str(commitment_snapshot),
            ],
            label="cosign Sigstore bundle verification",
        )
    return {
        "schema_version": PUBLICATION_RECEIPT_SCHEMA,
        "verified": True,
        "bundle_media_type": SIGSTORE_BUNDLE_MEDIA_TYPE,
        "bundle_sha256": _sha256(bundle_bytes),
        "commitment_file_sha256": _sha256(commitment),
        "certificate_identity": publication["certificate_identity"],
        "certificate_oidc_issuer": publication["certificate_oidc_issuer"],
        "rekor_log_index": _positive_bounded_int(
            entry.get("logIndex"),
            "Rekor log index",
            2**63 - 1,
            allow_zero=True,
            allow_decimal_string=True,
        ),
        "rekor_integrated_time": integrated_time.isoformat(),
        "rfc3161_gen_time": tsa_time.isoformat(),
        "rfc3161_response_sha256": _sha256(timestamp_response),
        "rfc3161_timestamp_verified": True,
        "inclusion_proof_verified": True,
        "cosign_version": version,
        "cosign_binary_sha256": cosign_digest,
        "trusted_root_sha256": publication["trusted_root_sha256"],
        "offline_verification": True,
    }


def _beacon_source(
    content: bytes,
    *,
    chain_hash: str,
    round_number: int,
) -> dict[str, object]:
    payload = _decode_json(content, "saved drand beacon")
    if not isinstance(payload, dict):
        raise AuthenticityError("saved drand beacon must be a JSON object")
    required = {"round", "signature", "previous_signature", "randomness"}
    if set(payload) != required:
        raise AuthenticityError("saved drand beacon fields do not match the required schema")
    if payload["round"] != round_number:
        raise AuthenticityError("saved beacon does not match the committed round")
    for field in ("signature", "previous_signature"):
        value = payload[field]
        if not isinstance(value, str) or not value or len(value) > 512:
            raise AuthenticityError(f"saved beacon {field} must be bounded hexadecimal")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise AuthenticityError(f"saved beacon {field} must be hexadecimal") from exc
    randomness = payload["randomness"]
    if not isinstance(randomness, str) or _HEX_64_RE.fullmatch(randomness) is None:
        raise AuthenticityError("saved beacon randomness must be 32-byte lowercase hex")
    if hashlib.sha256(bytes.fromhex(str(payload["signature"]))).hexdigest() != randomness:
        raise AuthenticityError("saved beacon randomness is not SHA-256(signature)")
    return payload


def _validated_relay_sources(
    relay_sources: tuple[Mapping[str, object], Mapping[str, object]],
    *,
    primary_bytes: bytes,
    secondary_bytes: bytes,
    chain_hash: str,
    round_number: int,
) -> list[dict[str, object]]:
    expected_urls = [
        template.format(chain_hash=chain_hash, round_number=round_number)
        for template in DRAND_RELAY_URL_TEMPLATES
    ]
    expected_bodies = (primary_bytes, secondary_bytes)
    normalized: list[dict[str, object]] = []
    for index, source in enumerate(relay_sources):
        value = _mapping(source, f"drand relay source {index + 1}")
        if set(value) != {"source_url", "sha256"}:
            raise AuthenticityError("drand relay provenance fields are invalid")
        if value["source_url"] != expected_urls[index]:
            raise AuthenticityError("drand relay provenance is not resolver-fixed")
        expected_digest = _sha256(expected_bodies[index])
        if value["sha256"] != expected_digest:
            raise AuthenticityError("drand relay provenance does not bind the raw response")
        normalized.append(
            {
                "host": _official_relay_host(expected_urls[index], chain_hash, round_number),
                "source_url": expected_urls[index],
                "sha256": expected_digest,
                "transport": "resolver-https-system-trust",
            }
        )
    return normalized


def _download_drand_response(url: str) -> bytes:
    """Perform one bounded fetch of a fixed drand URL and reject redirects."""

    _require_https_url(url, "drand relay URL")
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "ravage-paired-xben/1",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=DRAND_HTTP_TIMEOUT_SECONDS) as response:
            if response.status != 200 or response.geturl() != url:
                raise AuthenticityError("drand relay returned a redirect or non-success status")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    advertised_size = int(content_length)
                except ValueError as exc:
                    raise AuthenticityError("drand relay Content-Length is invalid") from exc
                if advertised_size < 0 or advertised_size > MAX_JSON_BYTES:
                    raise AuthenticityError("drand relay response exceeds the byte limit")
            content = cast("bytes", response.read(MAX_JSON_BYTES + 1))
    except AuthenticityError:
        raise
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise AuthenticityError("could not fetch the fixed official drand relay") from exc
    if len(content) > MAX_JSON_BYTES:
        raise AuthenticityError("drand relay response exceeds the byte limit")
    return content


def _rfc3161_gen_time(response: bytes) -> datetime:
    """Extract the signed TSTInfo.genTime from one DER TimeStampResponse.

    Cosign is responsible for cryptographically verifying the response and
    its message imprint. This small strict DER reader only obtains the time
    value so the protocol can compare it with the committed future round.
    """

    if not response or len(response) > MAX_JSON_BYTES:
        raise AuthenticityError("RFC3161 response is empty or exceeds the byte limit")
    outer_tag, outer_value, outer_end = _der_tlv(response, 0)
    if outer_tag != 0x30 or outer_end != len(response):
        raise AuthenticityError("RFC3161 response is not one DER sequence")
    response_children = _der_children(outer_value)
    if len(response_children) != 2 or response_children[0][0] != 0x30:
        raise AuthenticityError("RFC3161 response lacks a timestamp token")
    token_tag, token_value = response_children[1]
    if token_tag != 0x30:
        raise AuthenticityError("RFC3161 timestamp token is invalid")
    content_info = _der_children(token_value)
    if len(content_info) != 2 or content_info[0][0] != 0x06 or content_info[1][0] != 0xA0:
        raise AuthenticityError("RFC3161 timestamp ContentInfo is invalid")
    signed_wrapped = _der_children(content_info[1][1])
    if len(signed_wrapped) != 1 or signed_wrapped[0][0] != 0x30:
        raise AuthenticityError("RFC3161 SignedData wrapper is invalid")
    signed_data = _der_children(signed_wrapped[0][1])
    if len(signed_data) < 3 or signed_data[0][0] != 0x02 or signed_data[1][0] != 0x31:
        raise AuthenticityError("RFC3161 SignedData is invalid")
    encap_tag, encap_value = signed_data[2]
    if encap_tag != 0x30:
        raise AuthenticityError("RFC3161 encapsulated content is invalid")
    encap = _der_children(encap_value)
    if len(encap) != 2 or encap[0][0] != 0x06 or encap[1][0] != 0xA0:
        raise AuthenticityError("RFC3161 TSTInfo wrapper is invalid")
    octets = _der_children(encap[1][1])
    if len(octets) != 1 or octets[0][0] != 0x04:
        raise AuthenticityError("RFC3161 TSTInfo must be one primitive octet string")
    tst_tag, tst_value, tst_end = _der_tlv(octets[0][1], 0)
    if tst_tag != 0x30 or tst_end != len(octets[0][1]):
        raise AuthenticityError("RFC3161 TSTInfo is invalid")
    tst_fields = _der_children(tst_value)
    if (
        len(tst_fields) < 5
        or tst_fields[0][0] != 0x02
        or tst_fields[1][0] != 0x06
        or tst_fields[2][0] != 0x30
        or tst_fields[3][0] != 0x02
        or tst_fields[4][0] != 0x18
    ):
        raise AuthenticityError("RFC3161 TSTInfo fields are invalid")
    try:
        time_text = tst_fields[4][1].decode("ascii")
    except UnicodeError as exc:
        raise AuthenticityError("RFC3161 genTime is not ASCII") from exc
    match = re.fullmatch(r"(\d{14})(?:\.(\d{1,9}))?Z", time_text)
    if match is None:
        raise AuthenticityError("RFC3161 genTime is not canonical UTC GeneralizedTime")
    try:
        result = datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AuthenticityError("RFC3161 genTime is invalid") from exc
    fraction = match.group(2)
    if fraction:
        result = result.replace(microsecond=int((fraction + "000000")[:6]))
    return result


def _der_tlv(source: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset < 0 or offset + 2 > len(source):
        raise AuthenticityError("truncated RFC3161 DER value")
    tag = source[offset]
    if tag & 0x1F == 0x1F:
        raise AuthenticityError("high-tag-number RFC3161 DER values are unsupported")
    first_length = source[offset + 1]
    cursor = offset + 2
    if first_length & 0x80:
        width = first_length & 0x7F
        if width == 0 or width > 4 or cursor + width > len(source):
            raise AuthenticityError("invalid RFC3161 DER length")
        if source[cursor] == 0:
            raise AuthenticityError("non-minimal RFC3161 DER length")
        length = int.from_bytes(source[cursor : cursor + width], "big")
        if length < 128:
            raise AuthenticityError("non-minimal RFC3161 DER length")
        cursor += width
    else:
        length = first_length
    end = cursor + length
    if end > len(source):
        raise AuthenticityError("truncated RFC3161 DER content")
    return tag, source[cursor:end], end


def _der_children(value: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, content, end = _der_tlv(value, offset)
        children.append((tag, content))
        offset = end
    if offset != len(value):
        raise AuthenticityError("RFC3161 DER children are truncated")
    return children


def _official_relay_host(source_url: str, chain_hash: str, round_number: int) -> str:
    _require_https_url(source_url, "saved beacon source URL")
    parsed = urlsplit(source_url)
    host = (parsed.hostname or "").lower()
    expected_urls = {
        template.format(chain_hash=chain_hash, round_number=round_number)
        for template in DRAND_RELAY_URL_TEMPLATES
    }
    if source_url not in expected_urls:
        raise AuthenticityError(
            "saved beacon source must be an official chain-qualified exact-round URL"
        )
    return host


def _cosign_version(path: Path) -> str:
    output = _run_command([str(path), "version"], label="cosign version")
    match = _COSIGN_VERSION_RE.search(output.decode("utf-8", errors="strict"))
    if match is None:
        raise AuthenticityError("cosign version output is not recognized")
    version = tuple(int(part) for part in match.groups())
    if version < MINIMUM_COSIGN_VERSION:
        raise AuthenticityError("cosign version contains a known verification bypass")
    return _version_text(cast("tuple[int, int, int]", version))


def _parse_version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise AuthenticityError("cosign version is invalid")
    return cast("tuple[int, int, int]", tuple(int(part) for part in match.groups()))


def _version_text(value: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in value)


def _run_json(argv: list[str], *, label: str) -> dict[str, object]:
    output = _run_command(argv, label=label)
    payload = _decode_json(output, label)
    if not isinstance(payload, dict):
        raise AuthenticityError(f"{label} did not return one JSON object")
    return payload


def _run_command(argv: list[str], *, label: str) -> bytes:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise AuthenticityError(f"{label} argv is invalid")
    environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
            raise AuthenticityError(f"{label} output pipes are unavailable")
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        selector = selectors.DefaultSelector()
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + SUBPROCESS_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AuthenticityError(f"{label} exceeded its timeout")
            for key, _mask in selector.select(timeout=remaining):
                selected_stream = cast("IO[bytes]", key.fileobj)
                buffer = streams[selected_stream]
                chunk = os.read(key.fd, min(8192, MAX_SUBPROCESS_OUTPUT_BYTES + 1 - len(buffer)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer.extend(chunk)
                if len(buffer) > MAX_SUBPROCESS_OUTPUT_BYTES:
                    raise AuthenticityError(f"{label} output exceeds the byte limit")
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        stdout = bytes(streams[process.stdout])
        stderr = bytes(streams[process.stderr])
    except AuthenticityError:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise AuthenticityError(f"{label} could not complete safely") from exc
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    if return_code != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()[:500]
        raise AuthenticityError(f"{label} rejected the evidence: {detail or 'no detail'}")
    return stdout


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise AuthenticityError("authenticity value is not canonical JSON") from exc


def _decode_json(content: bytes, label: str) -> object:
    try:
        return json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuthenticityError(f"{label} is not valid JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuthenticityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise AuthenticityError(f"non-finite JSON value is forbidden: {value}")


def _file_digest(path: Path, maximum: int, label: str) -> tuple[str, int]:
    source = _regular_file(path, label)
    digest = hashlib.sha256()
    size = 0
    try:
        with source.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                if size > maximum:
                    raise AuthenticityError(f"{label} exceeds the byte limit")
                digest.update(chunk)
    except OSError as exc:
        raise AuthenticityError(f"cannot read {label}") from exc
    return f"sha256:{digest.hexdigest()}", size


def _read_bounded_regular(path: Path, maximum: int, label: str) -> bytes:
    source = _regular_file(path, label)
    try:
        with source.open("rb") as handle:
            content = handle.read(maximum + 1)
    except OSError as exc:
        raise AuthenticityError(f"cannot read {label}") from exc
    if len(content) > maximum:
        raise AuthenticityError(f"{label} exceeds the byte limit")
    return content


def _regular_file(path: Path, label: str) -> Path:
    target = Path(path).expanduser()
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise AuthenticityError(f"{label} is not a readable regular file") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AuthenticityError(f"{label} must be a real regular file")
    return target.resolve()


def _executable(path: Path, label: str) -> Path:
    target = _regular_file(path, label)
    if not os.access(target, os.X_OK):
        raise AuthenticityError(f"{label} is not executable")
    return target


def _campaign_file(root: Path, relative: str, label: str) -> Path:
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise AuthenticityError(f"{label} path is invalid")
    campaign = Path(root).resolve()
    target = _regular_file(campaign / relative, label)
    try:
        target.relative_to(campaign)
    except ValueError as exc:
        raise AuthenticityError(f"{label} escapes the campaign") from exc
    return target


def _exclusive_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700, exist_ok=False)
    except OSError as exc:
        raise AuthenticityError("cannot create frozen verifier directory") from exc
    if path.is_symlink():
        raise AuthenticityError("frozen verifier directory cannot be a symlink")
    return path


def _copy_exclusive(
    source_path: Path,
    destination: Path,
    *,
    expected_digest: str,
    expected_size: int | None,
    executable: bool,
    label: str,
) -> None:
    source = _regular_file(source_path, label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    size = 0
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, flags, 0o700 if executable else 0o600)
        with source.open("rb") as source_handle, os.fdopen(descriptor, "wb") as target_handle:
            descriptor = None
            while chunk := source_handle.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_VERIFIER_BYTES:
                    raise AuthenticityError(f"{label} exceeds the byte limit")
                digest.update(chunk)
                target_handle.write(chunk)
            target_handle.flush()
            os.fsync(target_handle.fileno())
    except OSError as exc:
        raise AuthenticityError(f"cannot retain {label} create-only") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    actual_digest = f"sha256:{digest.hexdigest()}"
    if actual_digest != expected_digest or (expected_size is not None and size != expected_size):
        raise AuthenticityError(f"{label} changed while it was frozen")


def _write_snapshot(path: Path, content: bytes) -> Path:
    """Write bytes once inside a private temporary directory and fsync them."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise AuthenticityError("could not create a verifier input snapshot") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return path


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise AuthenticityError(f"{label} must be an object")
    return dict(value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AuthenticityError(f"{label} must be a SHA-256 digest")
    return value


def _bounded_text(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise AuthenticityError(f"{label} must be non-empty and bounded")
    return value.strip()


def _positive_bounded_int(
    value: object,
    label: str,
    maximum: int,
    *,
    allow_zero: bool = False,
    allow_decimal_string: bool = False,
) -> int:
    if allow_decimal_string and isinstance(value, str) and value.isdecimal():
        value = int(value)
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AuthenticityError(f"{label} is outside the accepted range")
    return value


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuthenticityError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthenticityError(f"{label} must include a UTC offset")
    return parsed.astimezone(UTC)


def _require_https_url(value: str, label: str) -> None:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise AuthenticityError(f"{label} must be an external HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not host
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or host == "localhost"
        or host.endswith(".local")
        or parsed.fragment
    ):
        raise AuthenticityError(f"{label} must be an external HTTPS URL")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


__all__ = [
    "AUTHENTICITY_POLICY_SCHEMA",
    "AuthenticityError",
    "DRAND_RELAY_URL_TEMPLATES",
    "DrandRelayResponse",
    "copy_frozen_verifiers",
    "drand_source_bundle_digest",
    "fetch_official_drand_responses",
    "prepare_authenticity_policy",
    "validate_authenticity_policy",
    "verify_drand_evidence",
    "verify_publication_evidence",
]
