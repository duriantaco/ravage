"""Create and verify a beacon-bound, paired twenty-case XBEN protocol.

The protocol is intentionally separate from the ordinary XBEN sampler.  A
commitment is created while the selected cases are still unknowable.  A later
drand response resolves that commitment into one deterministic sample and run
schedule.  Every protocol artifact is create-only.

The offline verifier establishes integrity for one published commitment. It
cannot prove that no alternative future-round commitment was published. A
public no-alternatives claim additionally requires an externally enforced,
append-only canonical namespace with a first-entry-wins rule.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Final, cast
from urllib.parse import urlsplit

from tools.paired_xben.authenticity import (
    AuthenticityError,
    DrandRelayResponse,
    copy_frozen_verifiers,
    fetch_official_drand_responses,
    prepare_authenticity_policy,
    validate_authenticity_policy,
    verify_drand_evidence,
    verify_publication_evidence,
)
from tools.paired_xben.preflight import (
    MAX_PREFLIGHT_JSON_BYTES,
    PREFLIGHT_SCHEMA,
    STRIX_CANONICAL_ORIGIN_URL,
    XBEN_CANONICAL_ORIGIN_URL,
)

COMMITMENT_SCHEMA: Final = "ravage.paired-xben.commitment.v1"
BEACON_SCHEMA: Final = "ravage.paired-xben.beacon.v1"
SELECTION_SCHEMA: Final = "ravage.paired-xben.selection.v1"
ATTEMPT_SCHEMA: Final = "ravage.paired-xben.attempt.v1"
PRIMARY_MATRIX_SCHEMA: Final = "ravage.paired-xben.primary-matrix.v1"
VERIFICATION_SCHEMA: Final = "ravage.paired-xben.verification.v1"
POOL_SCHEMA: Final = "ravage.paired-xben.pool.v1"
RUN_CONTRACT_SCHEMA: Final = "ravage.paired-xben.run-contract.v2"
PUBLICATION_ANCHOR_SCHEMA: Final = "ravage.paired-xben.publication-anchor.v1"
DRAND_FETCH_SCHEMA: Final = "ravage.paired-xben.drand-fetch.v1"
PROTOCOL_ID: Final = "paired-xben-20-v1"

COMMITMENT_FILE: Final = "commitment.json"
PREFLIGHT_SOURCE_FILE: Final = "preflight-source.json"
RESOLUTION_DIRECTORY: Final = "resolution"
BEACON_SOURCE_FILE: Final = "beacon-source.json"
SECONDARY_BEACON_SOURCE_FILE: Final = "beacon-source-secondary.json"
DRAND_FETCH_FILE: Final = "drand-fetch.json"
DRAND_CHAIN_INFO_SOURCE_FILE: Final = "drand-chain-info-source.json"
PUBLICATION_ANCHOR_SOURCE_FILE: Final = "publication-anchor-source.json"
PUBLICATION_ANCHOR_FILE: Final = "publication-anchor.json"
BEACON_FILE: Final = "beacon.json"
SELECTION_FILE: Final = "selection.json"
PRIMARY_ATTEMPTS_DIRECTORY: Final = "attempts/primary"
PRIMARY_MATRIX_FILE: Final = "attempts/primary-reservation.json"
RERUN_ATTEMPTS_DIRECTORY: Final = "attempts/reruns"

SAMPLE_SIZE: Final = 20
SYSTEMS: Final = ("ravage", "strix")
MAX_POOL_SIZE: Final = 104
MAX_JSON_BYTES: Final = 256 * 1024
MAX_CONTRACT_BYTES: Final = 64 * 1024

SELECTION_ALGORITHM: Final = "sha256-rank-v2-nonmalleable"
SCHEDULE_ALGORITHM: Final = "sha256-counterbalanced-paired-interleave-v1"
DRAW_DOMAIN: Final = b"ravage.paired-xben.draw.v1"
CASE_RANK_DOMAIN: Final = b"ravage.paired-xben.case-rank.v1"
PAIR_ORDER_DOMAIN: Final = b"ravage.paired-xben.pair-order.v1"
ARM_ORDER_DOMAIN: Final = b"ravage.paired-xben.arm-order.v1"

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_OCI_REFERENCE_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_MODEL_SNAPSHOT_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,180}-20\d{2}-\d{2}-\d{2}")
_HEX_64_RE = re.compile(r"[0-9a-f]{64}")
_HEX_RE = re.compile(r"(?:[0-9a-f]{2})+")
_CASE_ID_RE = re.compile(r"XBEN-(\d{3})-24")
_CAMPAIGN_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
_ATTEMPT_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
_FLAG_VALUE_RE = re.compile(r"(?i)(?:flag|xben|ctf|htb)\{[^}\r\n]{1,512}\}")
_FORBIDDEN_CONTRACT_KEYS = frozenset(
    {
        "answer",
        "answers",
        "expectedflag",
        "expectedflags",
        "flag",
        "flags",
        "groundtruth",
        "solution",
        "solutions",
    }
)
_CANONICAL_XBEN_IDS = tuple(f"XBEN-{index:03d}-24" for index in range(1, 105))
_ADAPTER_SCHEMA_VERSION: Final = "ravage.xben.comparison-adapter.v4"
_ADAPTER_VERSION: Final = "paired-description-only-black-box-v4"
_RUNTIME_ENVIRONMENT_SCHEMA: Final = "ravage.xben.runtime-environment.v1"
_COMPATIBILITY_CATALOG_SCHEMA: Final = "ravage.paired-xben.compatibility-catalog.v1"
_MODEL_GATEWAY_POLICY_SCHEMA: Final = "ravage.xben.model-gateway-policy.v1"
_MODEL_GATEWAY_ROW_RECEIPT_SCHEMA: Final = "ravage.xben.model-gateway-receipt.v1"
_MODEL_GATEWAY_CAMPAIGN_RECEIPT_SCHEMA: Final = "ravage.xben.model-gateway-campaign-receipt.v1"
_EVALUATOR_COMPONENTS: Final = (
    "tools/paired_xben/protocol.py",
    "tools/paired_xben/report.py",
    "tools/paired_xben/authenticity.py",
    "tools/paired_xben/preflight.py",
    "tools/paired_xben/cli.py",
    "tools/paired_xben/coordinator.py",
    "tools/paired_xben/public_ledger.py",
    "tools/paired_xben/github_runner.py",
    "tools/paired_xben/github_execution_gate.py",
    "tools/paired_xben/github_execution_start.py",
    "tools/paired_xben/images/target-gateway.Dockerfile",
    ".github/workflows/paired-xben-intake.yml",
    ".github/workflows/paired-xben.yml",
    ".github/workflows/paired-xben-execution.yml",
    ".github/workflows/paired-xben-helper-image.yml",
    "scripts/eval/run_paired_xben_protocol.py",
    "packages/ravage/src/ravage/xben_parts/external_comparison.py",
    "packages/ravage/src/ravage/xben_parts/comparison_adapters.py",
    "packages/ravage/src/ravage/xben_parts/comparison_agent_vm.py",
    "packages/ravage/src/ravage/xben_parts/comparison_model_gateway.py",
    "packages/ravage/src/ravage/xben_parts/comparison_target.py",
    "packages/ravage/src/ravage/xben_parts/comparison_process_backend.py",
    "packages/ravage/src/ravage/xben_parts/http_meter_gateway.py",
)
_OCI_IMAGE_ROLES: Final = (
    "ravage_tool",
    "strix_sandbox",
    "target_gateway",
    "target_probe",
)


class PairedXbenProtocolError(ValueError):
    """The paired-XBEN protocol or one of its retained artifacts is invalid."""


def canonical_json(value: object) -> str:
    """Return the byte-stable JSON representation used for every digest."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise PairedXbenProtocolError("protocol value is not canonical JSON") from exc


def eligible_pool_digest(case_ids: Sequence[str]) -> str:
    """Digest a normalized eligible population, not a caller's file formatting."""

    normalized = _normalize_case_ids(case_ids)
    return _sha256_json({"schema_version": POOL_SCHEMA, "case_ids": list(normalized)})


def create_commitment(
    output_dir: Path,
    *,
    campaign_id: str,
    preflight_json_path: Path,
    eligible_case_ids: Sequence[str],
    chain_hash: str,
    chain_genesis_time: int,
    chain_period_seconds: int,
    observed_latest_round: int,
    draw_round: int,
    run_contract: Mapping[str, object],
    drand_verifier_binary_path: Path | None = None,
    cosign_binary_path: Path | None = None,
    sigstore_trusted_root_path: Path | None = None,
    publication_certificate_identity: str | None = None,
    publication_certificate_oidc_issuer: str | None = None,
    created_at: str | None = None,
) -> dict[str, object]:
    """Exclusively create a plan that binds a future drand round and population."""

    campaign = _campaign_id(campaign_id)
    pool = _normalize_case_ids(eligible_case_ids)
    if pool != _CANONICAL_XBEN_IDS:
        raise PairedXbenProtocolError(
            "eligible pool must be exactly canonical XBEN-001-24 through XBEN-104-24"
        )
    normalized_chain_hash = _hex_64(chain_hash, "drand chain hash")
    genesis_time = _positive_int(chain_genesis_time, "drand chain genesis time")
    period_seconds = _positive_int(chain_period_seconds, "drand chain period")
    latest = _positive_int(observed_latest_round, "observed latest drand round")
    future_round = _positive_int(draw_round, "committed drand draw round")
    if future_round <= latest:
        raise PairedXbenProtocolError(
            "committed drand draw round must be later than the observed latest round"
        )
    contract = _bounded_contract(run_contract)
    preflight_path = _regular_file(preflight_json_path, "paired-XBEN preflight")
    preflight_bytes = _read_bounded_bytes(preflight_path, "paired-XBEN preflight")
    if len(preflight_bytes) > MAX_PREFLIGHT_JSON_BYTES:
        raise PairedXbenProtocolError("paired-XBEN preflight exceeds the byte limit")
    preflight_digest = _sha256_bytes(preflight_bytes)
    preflight_pool = _validated_preflight_source(
        _decode_json(preflight_bytes, "paired-XBEN preflight"),
        contract=contract,
        artifact_digest=preflight_digest,
    )
    if preflight_pool != pool:
        raise PairedXbenProtocolError("eligible population differs from the frozen preflight")
    timestamp = _timestamp(created_at)
    draw_not_before = datetime.fromtimestamp(
        genesis_time + (future_round - 1) * period_seconds,
        tz=UTC,
    )
    commitment_time = datetime.fromisoformat(timestamp)
    if draw_not_before <= commitment_time:
        raise PairedXbenProtocolError(
            "committed drand draw round must occur after the recorded commitment time"
        )
    pool_digest = eligible_pool_digest(pool)
    if (
        drand_verifier_binary_path is None
        or cosign_binary_path is None
        or sigstore_trusted_root_path is None
        or publication_certificate_identity is None
        or publication_certificate_oidc_issuer is None
    ):
        raise PairedXbenProtocolError(
            "cryptographic drand and Sigstore verifier inputs are required before commitment"
        )
    try:
        authenticity_policy = prepare_authenticity_policy(
            drand_verifier_binary_path=drand_verifier_binary_path,
            cosign_binary_path=cosign_binary_path,
            sigstore_trusted_root_path=sigstore_trusted_root_path,
            publication_certificate_identity=publication_certificate_identity,
            publication_certificate_oidc_issuer=publication_certificate_oidc_issuer,
        )
    except AuthenticityError as exc:
        raise PairedXbenProtocolError(f"authenticity policy is not ready: {exc}") from exc
    body: dict[str, object] = {
        "schema_version": COMMITMENT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": campaign,
        "created_at": timestamp,
        "benchmark": "XBEN",
        "systems": list(SYSTEMS),
        "sample_size": SAMPLE_SIZE,
        "preflight_source": {
            "file": PREFLIGHT_SOURCE_FILE,
            "sha256": preflight_digest,
        },
        "eligible_pool": {
            "schema_version": POOL_SCHEMA,
            "count": len(pool),
            "case_ids": list(pool),
            "digest": pool_digest,
        },
        "randomness_commitment": {
            "provider": "drand",
            "chain_hash": normalized_chain_hash,
            "chain_genesis_time": genesis_time,
            "chain_period_seconds": period_seconds,
            "observed_latest_round": latest,
            "draw_round": future_round,
            "draw_not_before": draw_not_before.isoformat(),
        },
        "authenticity_policy": authenticity_policy,
        "algorithms": {
            "selection": SELECTION_ALGORITHM,
            "schedule": SCHEDULE_ALGORITHM,
            "domain_separators": {
                "draw": DRAW_DOMAIN.decode(),
                "case_rank": CASE_RANK_DOMAIN.decode(),
                "pair_order": PAIR_ORDER_DOMAIN.decode(),
                "arm_order": ARM_ORDER_DOMAIN.decode(),
            },
        },
        "attempt_policy": {
            "primary_attempts_per_system_case": 1,
            "scored_attempts": "scheduled_primary_only",
            "primary_directory": PRIMARY_ATTEMPTS_DIRECTORY,
            "rerun_directory": RERUN_ATTEMPTS_DIRECTORY,
            "reruns_are_scored": False,
            "overwrite_allowed": False,
        },
        "run_contract": contract,
    }
    document = _document(body)
    root = Path(output_dir).expanduser()
    _create_private_directory(root)
    _write_bytes_exclusive(root / PREFLIGHT_SOURCE_FILE, preflight_bytes)
    try:
        copy_frozen_verifiers(
            root,
            policy=authenticity_policy,
            drand_verifier_binary_path=drand_verifier_binary_path,
            cosign_binary_path=cosign_binary_path,
            sigstore_trusted_root_path=sigstore_trusted_root_path,
        )
    except AuthenticityError as exc:
        raise PairedXbenProtocolError(f"could not freeze authenticity verifiers: {exc}") from exc
    _write_json_exclusive(root / COMMITMENT_FILE, document)
    return document


def resolve_commitment(
    campaign_dir: Path,
    *,
    drand_chain_info_json_path: Path,
    publication_anchor_json_path: Path,
    eligible_case_ids: Sequence[str] | None = None,
    expected_commitment_digest: str,
) -> dict[str, object]:
    """Resolve once by directly fetching the committed round from fixed relays."""

    root = _existing_directory(campaign_dir, "campaign directory")
    commitment = _load_campaign_commitment(root)
    expected_digest = _sha256_digest(expected_commitment_digest, "expected commitment digest")
    if commitment["document_digest"] != expected_digest:
        raise PairedXbenProtocolError(
            "campaign commitment digest does not match the expected digest"
        )
    if eligible_case_ids is not None:
        _require_matching_pool(commitment, eligible_case_ids)

    chain_info_path = _regular_file(drand_chain_info_json_path, "drand chain info")
    chain_info_bytes = _read_bounded_bytes(chain_info_path, "drand chain info")
    anchor_source_path = _regular_file(publication_anchor_json_path, "Sigstore publication bundle")
    anchor_source_bytes = _read_bounded_bytes(
        anchor_source_path,
        "Sigstore publication bundle",
    )
    randomness = _mapping(commitment["randomness_commitment"], "randomness commitment")
    authenticity_policy = _mapping(commitment["authenticity_policy"], "authenticity policy")
    try:
        round_number = _positive_int(randomness["draw_round"], "committed drand round")
        primary_response, secondary_response = fetch_official_drand_responses(
            policy=authenticity_policy,
            chain_hash=str(randomness["chain_hash"]),
            round_number=round_number,
        )
        source_bytes = primary_response.body
        secondary_source_bytes = secondary_response.body
        fetch_manifest = _drand_fetch_manifest(
            commitment,
            primary_response=primary_response,
            secondary_response=secondary_response,
        )
        relay_sources = _drand_fetch_sources(fetch_manifest, commitment=commitment)
        with tempfile.TemporaryDirectory(prefix="ravage-paired-xben-drand-") as temporary:
            temporary_root = Path(temporary)
            source_path = temporary_root / "primary.json"
            secondary_source_path = temporary_root / "secondary.json"
            _write_bytes_exclusive(source_path, source_bytes)
            _write_bytes_exclusive(secondary_source_path, secondary_source_bytes)
            drand_authenticity = verify_drand_evidence(
                root,
                policy=authenticity_policy,
                chain_info_path=chain_info_path,
                primary_beacon_path=source_path,
                secondary_beacon_path=secondary_source_path,
                chain_hash=str(randomness["chain_hash"]),
                round_number=round_number,
                genesis_time=_positive_int(randomness["chain_genesis_time"], "drand genesis time"),
                period_seconds=_positive_int(randomness["chain_period_seconds"], "drand period"),
                relay_sources=relay_sources,
            )
        publication_authenticity = verify_publication_evidence(
            root,
            policy=authenticity_policy,
            commitment_path=root / COMMITMENT_FILE,
            bundle_path=anchor_source_path,
            commitment_created_at=str(commitment["created_at"]),
            draw_not_before=str(randomness["draw_not_before"]),
        )
    except AuthenticityError as exc:
        raise PairedXbenProtocolError(
            f"resolution authenticity verification failed: {exc}"
        ) from exc

    source_payload = _decode_json(source_bytes, "saved drand beacon")
    beacon = _normalized_beacon(
        source_payload,
        commitment=commitment,
        source_document_sha256=_sha256_bytes(source_bytes),
        authenticity=drand_authenticity,
    )
    anchor = _normalized_publication_anchor(
        publication_authenticity,
        commitment=commitment,
        source_document_sha256=_sha256_bytes(anchor_source_bytes),
    )
    selection = _build_selection(commitment, beacon)

    resolution = _create_exclusive_child_directory(root, RESOLUTION_DIRECTORY)
    # Retain the accepted source bytes as evidence.  A crash between these
    # create-only writes leaves a permanently incomplete, fail-closed campaign.
    _write_bytes_exclusive(resolution / BEACON_SOURCE_FILE, source_bytes)
    _write_bytes_exclusive(resolution / SECONDARY_BEACON_SOURCE_FILE, secondary_source_bytes)
    _write_json_exclusive(resolution / DRAND_FETCH_FILE, fetch_manifest)
    _write_bytes_exclusive(resolution / DRAND_CHAIN_INFO_SOURCE_FILE, chain_info_bytes)
    _write_bytes_exclusive(resolution / PUBLICATION_ANCHOR_SOURCE_FILE, anchor_source_bytes)
    _write_json_exclusive(resolution / PUBLICATION_ANCHOR_FILE, anchor)
    _write_json_exclusive(resolution / BEACON_FILE, beacon)
    _write_json_exclusive(resolution / SELECTION_FILE, selection)
    return selection


def create_primary_attempt_manifest(
    campaign_dir: Path,
    *,
    slot_id: str,
    created_at: str | None = None,
) -> Path:
    """Reject the obsolete selective primary-slot reservation operation.

    Scored campaigns must reserve the complete matrix in one fail-closed
    operation. Keeping this symbol as a rejecting compatibility shim makes an
    older caller fail loudly instead of creating a cherry-pickable campaign.
    """

    del campaign_dir, slot_id, created_at
    raise PairedXbenProtocolError(
        "individual primary reservation is disabled; use reserve_primary_matrix"
    )


def reserve_primary_matrix(
    campaign_dir: Path,
    *,
    created_at: str | None = None,
) -> Path:
    """Reserve every scored schedule row exactly once, then seal the matrix.

    The primary root itself is the exclusive reservation lock. All forty
    attempt documents and artifact directories are created beneath it before
    the binding manifest is written. A crash can therefore leave a visibly
    incomplete root, but no valid reservation marker. The operation will never
    resume or fill such a root on a later invocation.
    """

    root, commitment, selection = _load_resolved_campaign(campaign_dir)
    schedule = _schedule(selection)
    expected_rows = SAMPLE_SIZE * len(SYSTEMS)
    if len(schedule) != expected_rows:
        raise PairedXbenProtocolError(
            f"selection must contain exactly {expected_rows} scheduled primary rows"
        )

    timestamp = _timestamp(created_at)
    documents: list[tuple[Mapping[str, object], dict[str, object]]] = []
    reservation_entries: list[dict[str, object]] = []
    seen_slots: set[str] = set()
    for row in schedule:
        slot_id = _attempt_id(row.get("slot_id"), "primary slot ID")
        if slot_id in seen_slots:
            raise PairedXbenProtocolError("selection schedule contains duplicate primary slots")
        seen_slots.add(slot_id)
        document = _document(
            _attempt_body(
                commitment=commitment,
                selection=selection,
                attempt_id=slot_id,
                purpose="primary",
                score_eligible=True,
                row=row,
                parent_primary_slot_id=None,
                reason=None,
                created_at=timestamp,
            )
        )
        documents.append((row, document))
        reservation_entries.append(
            {
                "slot_id": slot_id,
                "attempt_manifest": f"{slot_id}/attempt.json",
                "artifact_directory": f"{slot_id}/artifacts",
                "attempt_document_digest": document["document_digest"],
            }
        )

    expected_slots = {f"primary-{index:03d}" for index in range(1, expected_rows + 1)}
    if seen_slots != expected_slots:
        raise PairedXbenProtocolError("selection primary slots are not exactly 001 through 040")

    reservation = _document(
        {
            "schema_version": PRIMARY_MATRIX_SCHEMA,
            "campaign_id": commitment["campaign_id"],
            "commitment_digest": commitment["document_digest"],
            "selection_digest": selection["document_digest"],
            "created_at": timestamp,
            "primary_directory": "primary",
            "scheduled_primary_attempts": expected_rows,
            "attempts": reservation_entries,
            "attempt_documents_digest": _sha256_json(reservation_entries),
            "policy": {
                "all_slots_reserved_before_execution": True,
                "resume_incomplete_reservation": False,
                "replace_primary_attempt": False,
            },
        }
    )

    attempts_root = _ensure_child_directory(root, "attempts")
    marker_path = root / PRIMARY_MATRIX_FILE
    if marker_path.exists() or marker_path.is_symlink():
        raise PairedXbenProtocolError("primary matrix has already been reserved")
    primary_root = _create_exclusive_child_directory(attempts_root, "primary")
    for row, document in documents:
        slot_id = str(row["slot_id"])
        attempt_dir = _create_exclusive_child_directory(primary_root, slot_id)
        _create_exclusive_child_directory(attempt_dir, "artifacts")
        _write_json_exclusive(attempt_dir / "attempt.json", document)

    # This seal is intentionally last. Its absence makes an interrupted
    # reservation permanently incomplete and therefore unusable for scoring.
    _write_json_exclusive(marker_path, reservation)
    return marker_path


def create_rerun_attempt_manifest(
    campaign_dir: Path,
    *,
    rerun_id: str,
    primary_slot_id: str,
    reason: str,
    created_at: str | None = None,
) -> Path:
    """Create a retained diagnostic rerun that can never enter the primary score."""

    root, commitment, selection = _load_resolved_campaign(campaign_dir)
    _verify_primary_matrix_reservation(
        root,
        commitment=commitment,
        selection=selection,
        allow_absent=False,
    )
    normalized_rerun_id = _attempt_id(rerun_id, "rerun ID")
    row = _schedule_row(selection, primary_slot_id)
    primary_manifest = root / PRIMARY_ATTEMPTS_DIRECTORY / primary_slot_id / "attempt.json"
    _validate_attempt_document(
        _load_document(primary_manifest, "primary attempt manifest"),
        commitment=commitment,
        selection=selection,
        expected_row=row,
        expected_purpose="primary",
    )
    normalized_reason = _bounded_text(reason, "rerun reason", maximum=500)
    body = _attempt_body(
        commitment=commitment,
        selection=selection,
        attempt_id=normalized_rerun_id,
        purpose="diagnostic_rerun",
        score_eligible=False,
        row=row,
        parent_primary_slot_id=primary_slot_id,
        reason=normalized_reason,
        created_at=created_at,
    )
    attempts_root = _ensure_child_directory(root, "attempts")
    reruns_root = _ensure_child_directory(attempts_root, "reruns")
    attempt_dir = _create_exclusive_child_directory(reruns_root, normalized_rerun_id)
    _create_exclusive_child_directory(attempt_dir, "artifacts")
    path = attempt_dir / "attempt.json"
    _write_json_exclusive(path, _document(body))
    return path


def verify_campaign(
    campaign_dir: Path,
    *,
    require_all_primary_attempts: bool = False,
) -> dict[str, object]:
    """Verify all protocol bindings offline without modifying the campaign."""

    root = _existing_directory(campaign_dir, "campaign directory")
    commitment = _load_campaign_commitment(root)
    resolution_dir = root / RESOLUTION_DIRECTORY
    if not resolution_dir.exists() and not resolution_dir.is_symlink():
        return {
            "schema_version": VERIFICATION_SCHEMA,
            "structurally_valid": True,
            "claim_ready": False,
            "beacon_authenticity_verified": False,
            "publication_anchor_verified": False,
            "canonical_namespace_first_entry_verified": False,
            "claim_ready_scope": "single-commitment-integrity-only",
            "phase": "committed",
            "campaign_id": commitment["campaign_id"],
            "commitment_digest": commitment["document_digest"],
            "preflight_digest": cast("Mapping[str, object]", commitment["preflight_source"])[
                "sha256"
            ],
            "selected_cases": 0,
            "scheduled_primary_attempts": 0,
            "recorded_primary_attempts": 0,
            "primary_matrix_reserved": False,
            "primary_matrix_digest": None,
            "diagnostic_reruns": 0,
        }

    beacon, anchor, selection = _load_authenticated_resolution(root, commitment)

    attempt_summary = _verify_attempt_manifests(
        root,
        commitment=commitment,
        selection=selection,
    )
    if require_all_primary_attempts and attempt_summary["missing_primary_attempts"]:
        raise PairedXbenProtocolError("not every scheduled primary attempt has a retained manifest")
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "structurally_valid": True,
        # This verifier establishes protocol structure and the pre-draw
        # randomness/publication bindings only.  Execution receipts, terminal
        # results seals, and canonical public-namespace evidence are verified
        # by the report layer; structural validity must never be advertised as
        # a comparison-ready result.
        "claim_ready": False,
        "beacon_authenticity_verified": True,
        "publication_anchor_verified": True,
        "canonical_namespace_first_entry_verified": False,
        "claim_ready_scope": "structural-protocol-integrity-only",
        "phase": "resolved",
        "campaign_id": commitment["campaign_id"],
        "commitment_digest": commitment["document_digest"],
        "preflight_digest": cast("Mapping[str, object]", commitment["preflight_source"])["sha256"],
        "beacon_digest": beacon["document_digest"],
        "publication_anchor_digest": anchor["document_digest"],
        "selection_digest": selection["document_digest"],
        "eligible_pool_digest": cast("Mapping[str, object]", commitment["eligible_pool"])["digest"],
        "selected_cases": SAMPLE_SIZE,
        "scheduled_primary_attempts": SAMPLE_SIZE * len(SYSTEMS),
        **attempt_summary,
    }


def load_eligible_pool(path: Path) -> tuple[str, ...]:
    """Load a bounded pool from a JSON list or an ``eligible_case_ids`` object."""

    payload = _load_untrusted_json(path, "eligible pool")
    if isinstance(payload, list):
        raw_ids = payload
    elif isinstance(payload, dict) and set(payload) == {"eligible_case_ids"}:
        raw_ids = payload["eligible_case_ids"]
    elif isinstance(payload, dict) and isinstance(payload.get("xben"), dict):
        raw_ids = payload["xben"].get("eligible_case_ids")
    else:
        raise PairedXbenProtocolError(
            "eligible pool must be a JSON list, an eligible_case_ids object, or a preflight report"
        )
    if not isinstance(raw_ids, list) or any(not isinstance(item, str) for item in raw_ids):
        raise PairedXbenProtocolError("eligible_case_ids must be a list of strings")
    return _normalize_case_ids(raw_ids)


def load_run_contract(path: Path) -> dict[str, object]:
    """Load the public, non-ground-truth metadata bound into a commitment."""

    payload = _load_untrusted_json(path, "run contract")
    if not isinstance(payload, dict):
        raise PairedXbenProtocolError("run contract must be a JSON object")
    return _bounded_contract(payload)


def validate_run_contract(value: Mapping[str, object]) -> dict[str, object]:
    """Validate and normalize the exact v2 contract without reading a file."""

    return _bounded_contract(value)


def _build_selection(
    commitment: Mapping[str, object],
    beacon: Mapping[str, object],
) -> dict[str, object]:
    pool_payload = _mapping(commitment.get("eligible_pool"), "eligible pool")
    pool = _normalize_case_ids(_string_sequence(pool_payload.get("case_ids"), "eligible case IDs"))
    commitment_digest = _sha256_digest(commitment.get("document_digest"), "commitment digest")
    beacon_digest = _sha256_digest(beacon.get("document_digest"), "beacon digest")
    randomness = _hex_64(beacon.get("randomness"), "drand randomness")
    randomness_contract = _mapping(commitment["randomness_commitment"], "randomness commitment")
    chain_hash = _hex_64(randomness_contract["chain_hash"], "drand chain hash")
    draw_round = _positive_int(randomness_contract["draw_round"], "committed drand draw round")
    pool_digest = _sha256_digest(pool_payload["digest"], "eligible pool digest")
    # Do not seed from the commitment digest: it includes operator-controlled
    # labels/timestamps and therefore permits digest grinding.  These inputs
    # are fixed by the protocol/population/chain/round plus verified beacon.
    draw_key = hashlib.sha256(
        DRAW_DOMAIN
        + b"\0"
        + PROTOCOL_ID.encode()
        + b"\0"
        + bytes.fromhex(pool_digest.removeprefix("sha256:"))
        + b"\0"
        + bytes.fromhex(chain_hash)
        + b"\0"
        + draw_round.to_bytes(8, "big")
        + b"\0"
        + bytes.fromhex(randomness)
    ).digest()

    ranked = sorted(
        ((_rank_key(CASE_RANK_DOMAIN, draw_key, case_id), case_id) for case_id in pool),
        key=lambda item: (item[0], item[1]),
    )
    if len({key for key, _case_id in ranked}) != len(ranked):
        raise PairedXbenProtocolError("case-ranking hash collision")
    selected = tuple(case_id for _key, case_id in ranked[:SAMPLE_SIZE])
    pair_order = tuple(
        case_id
        for _key, case_id in sorted(
            ((_rank_key(PAIR_ORDER_DOMAIN, draw_key, case_id), case_id) for case_id in selected),
            key=lambda item: (item[0], item[1]),
        )
    )
    arm_ranking = sorted(
        ((_rank_key(ARM_ORDER_DOMAIN, draw_key, case_id), case_id) for case_id in selected),
        key=lambda item: (item[0], item[1]),
    )
    ravage_first = {case_id for _key, case_id in arm_ranking[: SAMPLE_SIZE // 2]}

    schedule: list[dict[str, object]] = []
    slot = 0
    for pair_index, case_id in enumerate(pair_order, start=1):
        system_order = SYSTEMS if case_id in ravage_first else tuple(reversed(SYSTEMS))
        for position, system in enumerate(system_order, start=1):
            slot += 1
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

    body: dict[str, object] = {
        "schema_version": SELECTION_SCHEMA,
        "campaign_id": commitment["campaign_id"],
        "commitment_digest": commitment_digest,
        "beacon_digest": beacon_digest,
        "eligible_pool_digest": pool_payload["digest"],
        "draw_key_sha256": f"sha256:{draw_key.hex()}",
        "algorithms": commitment["algorithms"],
        "case_ranking": [
            {
                "rank": index,
                "case_id": case_id,
                "selection_key": f"sha256:{key}",
                "selected": index <= SAMPLE_SIZE,
            }
            for index, (key, case_id) in enumerate(ranked, start=1)
        ],
        "selected_case_ids": list(selected),
        "pair_order": list(pair_order),
        "schedule": schedule,
        "attempt_policy": commitment["attempt_policy"],
    }
    return _document(body)


def _drand_fetch_manifest(
    commitment: Mapping[str, object],
    *,
    primary_response: DrandRelayResponse,
    secondary_response: DrandRelayResponse,
) -> dict[str, object]:
    """Bind resolver-owned transport metadata to both exact raw responses."""

    return _document(
        {
            "schema_version": DRAND_FETCH_SCHEMA,
            "campaign_id": commitment["campaign_id"],
            "commitment_digest": commitment["document_digest"],
            "relay_sources": [
                {
                    "source_url": primary_response.source_url,
                    "sha256": _sha256_bytes(primary_response.body),
                },
                {
                    "source_url": secondary_response.source_url,
                    "sha256": _sha256_bytes(secondary_response.body),
                },
            ],
        }
    )


def _drand_fetch_sources(
    manifest: Mapping[str, object],
    *,
    commitment: Mapping[str, object],
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    expected_fields = {
        "schema_version",
        "campaign_id",
        "commitment_digest",
        "relay_sources",
        "document_digest",
    }
    if (
        set(manifest) != expected_fields
        or manifest.get("schema_version") != DRAND_FETCH_SCHEMA
        or manifest.get("campaign_id") != commitment["campaign_id"]
        or manifest.get("commitment_digest") != commitment["document_digest"]
    ):
        raise PairedXbenProtocolError("drand fetch manifest is invalid")
    sources = manifest.get("relay_sources")
    if (
        not isinstance(sources, list)
        or len(sources) != 2
        or not all(isinstance(item, Mapping) for item in sources)
    ):
        raise PairedXbenProtocolError("drand fetch manifest requires exactly two relays")
    return cast("tuple[Mapping[str, object], Mapping[str, object]]", tuple(sources))


def _normalized_beacon(
    payload: object,
    *,
    commitment: Mapping[str, object],
    source_document_sha256: str,
    authenticity: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise PairedXbenProtocolError("saved drand beacon must be a JSON object")
    required = {"round", "signature", "previous_signature", "randomness"}
    if set(payload) != required:
        raise PairedXbenProtocolError("saved drand beacon fields do not match the accepted schema")
    randomness_contract = _mapping(commitment.get("randomness_commitment"), "randomness commitment")
    chain_hash = _hex_64(randomness_contract["chain_hash"], "committed drand chain hash")
    round_number = _positive_int(payload["round"], "saved beacon round")
    if round_number != randomness_contract["draw_round"]:
        raise PairedXbenProtocolError("saved beacon does not use the committed drand round")
    signature = _hex(payload["signature"], "saved beacon signature", maximum=512)
    randomness = _hex_64(payload["randomness"], "saved beacon randomness")
    derived = hashlib.sha256(bytes.fromhex(signature)).hexdigest()
    if randomness != derived:
        raise PairedXbenProtocolError("saved beacon randomness is not SHA-256(signature)")
    previous_signature = _hex(
        payload["previous_signature"],
        "saved beacon previous signature",
        maximum=512,
    )
    authenticity_value = _mapping(authenticity, "drand authenticity receipt")
    receipt = _mapping(authenticity_value.get("receipt"), "drand verifier receipt")
    relay_sources = authenticity_value.get("relay_sources")
    if (
        authenticity_value.get("relay_quorum") != 2
        or not isinstance(relay_sources, list)
        or len(relay_sources) != 2
        or receipt.get("verified") is not True
        or receipt.get("chain_hash") != chain_hash
        or receipt.get("round") != round_number
        or receipt.get("randomness") != randomness
    ):
        raise PairedXbenProtocolError("drand authenticity receipt is not fail-closed")
    primary_source = _mapping(relay_sources[0], "primary drand relay source")
    source_url = _bounded_text(primary_source["source_url"], "drand source URL", maximum=500)
    body: dict[str, object] = {
        "schema_version": BEACON_SCHEMA,
        "campaign_id": commitment["campaign_id"],
        "commitment_digest": commitment["document_digest"],
        "provider": "drand",
        "chain_hash": chain_hash,
        "round": round_number,
        "signature": signature,
        "previous_signature": previous_signature,
        "randomness": randomness,
        "source_url": source_url,
        "source_document_sha256": source_document_sha256,
        "verification": {
            "round_matches_commitment": True,
            "chain_hash_matches_commitment": True,
            "randomness_equals_sha256_signature": True,
            "bls_signature_verified": True,
            "official_relay_quorum_verified": True,
            "relay_sources": relay_sources,
            "chain_info_sha256": authenticity_value["chain_info_sha256"],
            "verifier_binary_sha256": authenticity_value["verifier_binary_sha256"],
            "verifier_receipt": receipt,
        },
    }
    return _document(body)


def _normalized_publication_anchor(
    receipt: Mapping[str, object],
    *,
    commitment: Mapping[str, object],
    source_document_sha256: str,
) -> dict[str, object]:
    value = _mapping(receipt, "Sigstore publication verification receipt")
    if (
        value.get("verified") is not True
        or value.get("inclusion_proof_verified") is not True
        or value.get("rfc3161_timestamp_verified") is not True
    ):
        raise PairedXbenProtocolError("publication anchor is not cryptographically verified")
    published_at = _timestamp(str(value.get("rfc3161_gen_time")))
    created_at = datetime.fromisoformat(str(commitment["created_at"]))
    randomness = _mapping(commitment["randomness_commitment"], "randomness commitment")
    draw_not_before = datetime.fromisoformat(str(randomness["draw_not_before"]))
    published_time = datetime.fromisoformat(published_at)
    if published_time <= created_at or published_time >= draw_not_before:
        raise PairedXbenProtocolError(
            "publication anchor time must be after commitment creation and before the draw"
        )
    return _document(
        {
            "schema_version": PUBLICATION_ANCHOR_SCHEMA,
            "campaign_id": commitment["campaign_id"],
            "anchor_kind": "sigstore-keyless-rekor-v0.3",
            "commitment_digest": commitment["document_digest"],
            "published_at": published_at,
            "source_document_sha256": source_document_sha256,
            "bundle_sha256": value["bundle_sha256"],
            "certificate_identity": value["certificate_identity"],
            "certificate_oidc_issuer": value["certificate_oidc_issuer"],
            "rekor_log_index": value["rekor_log_index"],
            "rekor_integrated_time": value["rekor_integrated_time"],
            "rfc3161_response_sha256": value["rfc3161_response_sha256"],
            "external_timestamp_verified": True,
            "inclusion_proof_verified": True,
            "rfc3161_timestamp_verified": True,
            "offline_verification": True,
            "verification_receipt": value,
        }
    )


def _validated_preflight_source(
    payload: object,
    *,
    contract: Mapping[str, object],
    artifact_digest: str,
) -> tuple[str, ...]:
    """Validate the exact readiness artifact whose bytes the contract binds."""

    if not isinstance(payload, dict):
        raise PairedXbenProtocolError("paired-XBEN preflight must be a JSON object")
    expected_fields = {
        "schema_version",
        "captured_at",
        "blocked",
        "block_reasons",
        "policy",
        "disk",
        "docker",
        "git",
        "xben",
        "strix",
        "provider_environment",
        "website",
    }
    if set(payload) != expected_fields or payload.get("schema_version") != PREFLIGHT_SCHEMA:
        raise PairedXbenProtocolError("paired-XBEN preflight fields are invalid")
    if payload.get("blocked") is not False or payload.get("block_reasons") != []:
        raise PairedXbenProtocolError("paired-XBEN preflight is blocked")
    _timestamp(str(payload["captured_at"]))

    policy = _mapping(payload["policy"], "preflight policy")
    if policy != {
        "require_clean_sources": True,
        "require_source_pins": True,
        "require_website_target": True,
    }:
        raise PairedXbenProtocolError("paired-XBEN preflight policy is not fail closed")
    disk = _mapping(payload["disk"], "preflight disk")
    if disk.get("ready") is not True or disk.get("status") != "ready":
        raise PairedXbenProtocolError("paired-XBEN preflight disk gate is not ready")
    docker = _mapping(payload["docker"], "preflight docker")
    if (
        docker.get("ready") is not True
        or docker.get("executable_present") is not True
        or docker.get("daemon_responsive") is not True
        or docker.get("status") != "ready"
    ):
        raise PairedXbenProtocolError("paired-XBEN preflight docker gate is not ready")
    strix = _mapping(payload["strix"], "preflight Strix")
    if (
        strix.get("ready") is not True
        or strix.get("source_present") is not True
        or strix.get("executable_present") is not True
        or strix.get("dependency_probe_ok") is not True
        or strix.get("status") != "ready"
    ):
        raise PairedXbenProtocolError("paired-XBEN preflight Strix gate is not ready")
    provider = _mapping(payload["provider_environment"], "preflight provider environment")
    required_provider = provider.get("required")
    if (
        provider.get("ready") is not True
        or provider.get("missing") != []
        or provider.get("source") != "process_environment_only"
        or provider.get("dotenv_loaded") is not False
        or not isinstance(required_provider, list)
        or not required_provider
        or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("name"), str)
            or item.get("present") is not True
            for item in required_provider
        )
    ):
        raise PairedXbenProtocolError("paired-XBEN preflight provider gate is not ready")
    website = _mapping(payload["website"], "preflight website")
    if (
        website.get("required") is not True
        or website.get("configured") is not True
        or website.get("resolved") is not True
        or website.get("raw_reference_emitted") is not False
    ):
        raise PairedXbenProtocolError("paired-XBEN preflight website gate is not ready")
    _sha256_digest(website.get("reference_sha256"), "preflight website reference digest")

    xben = _mapping(payload["xben"], "preflight XBEN gate")
    if (
        xben.get("ready") is not True
        or xben.get("status") != "ready"
        or xben.get("case_count") != MAX_POOL_SIZE
        or xben.get("eligible_case_count") != MAX_POOL_SIZE
        or xben.get("expected_case_count") != MAX_POOL_SIZE
        or xben.get("exact_case_set") is not True
    ):
        raise PairedXbenProtocolError("paired-XBEN preflight does not bind the canonical 104 cases")
    pool = _normalize_case_ids(_string_sequence(xben.get("eligible_case_ids"), "eligible case IDs"))
    if pool != _CANONICAL_XBEN_IDS:
        raise PairedXbenProtocolError("paired-XBEN preflight pool is not canonical")
    preflight_ids_digest = _sha256_bytes(canonical_json(list(pool)).encode())
    if xben.get("eligible_case_ids_sha256") != preflight_ids_digest:
        raise PairedXbenProtocolError("paired-XBEN preflight case-list digest mismatch")

    contract_sources = _mapping(contract.get("sources"), "run contract sources")
    git = _mapping(payload["git"], "preflight git state")
    if set(git) != {"ravage", "strix", "xben"}:
        raise PairedXbenProtocolError("paired-XBEN preflight git sources are incomplete")
    for source_name in ("ravage", "strix", "xben"):
        state = _mapping(git[source_name], f"preflight {source_name} git state")
        if set(state) != {"available", "head", "dirty", "pin_status", "expected_head"}:
            raise PairedXbenProtocolError(
                f"paired-XBEN preflight {source_name} git fields are invalid"
            )
        head = state.get("head")
        expected_head = state.get("expected_head")
        frozen = _mapping(contract_sources.get(source_name), f"{source_name} source")
        if (
            state.get("available") is not True
            or state.get("dirty") is not False
            or state.get("pin_status") != "match"
            or not isinstance(head, str)
            or _GIT_SHA_RE.fullmatch(head) is None
            or expected_head != head
            or frozen.get("commit_sha") != head
            or frozen.get("dirty") is not False
        ):
            raise PairedXbenProtocolError(
                f"paired-XBEN preflight {source_name} source binding is invalid"
            )

    strix_binding = _validated_preflight_source_binding(
        strix.get("source_binding"),
        label="Strix",
        expected_head=_mapping(git["strix"], "preflight Strix git state").get("head"),
        expected_origin=STRIX_CANONICAL_ORIGIN_URL,
        expected_tree_path=".",
    )
    strix_source = _mapping(contract_sources["strix"], "frozen Strix source")
    if (
        strix_source.get("commit_sha") != strix_binding.get("expected_head")
        or strix_source.get("tree_object") != strix_binding.get("tree_object")
        or strix_source.get("tree_path") != strix_binding.get("tree_path")
        or strix_source.get("origin_url") != strix_binding.get("origin_url")
    ):
        raise PairedXbenProtocolError("run contract Strix tree/origin binding is invalid")
    _validated_strix_executable_identity(strix, source_binding=strix_binding)
    xben_binding = _validated_preflight_source_binding(
        xben.get("source_binding"),
        label="XBEN",
        expected_head=_mapping(git["xben"], "preflight XBEN git state").get("head"),
        expected_origin=XBEN_CANONICAL_ORIGIN_URL,
        expected_tree_path="benchmarks",
    )
    xben_source = _mapping(contract_sources["xben"], "frozen XBEN source")
    if (
        xben_source.get("commit_sha") != xben_binding.get("expected_head")
        or xben_source.get("tree_object") != xben_binding.get("tree_object")
        or xben_source.get("tree_path") != xben_binding.get("tree_path")
        or xben_source.get("origin_url") != xben_binding.get("origin_url")
    ):
        raise PairedXbenProtocolError("run contract XBEN tree/origin binding is invalid")

    if contract.get("preflight_digest") != artifact_digest:
        raise PairedXbenProtocolError("run contract preflight digest does not match its artifact")
    _reject_ground_truth(payload)
    return pool


def _validated_preflight_source_binding(
    value: object,
    *,
    label: str,
    expected_head: object,
    expected_origin: str,
    expected_tree_path: str,
) -> dict[str, object]:
    binding = _mapping(value, f"preflight {label} source binding")
    fields = {
        "ready",
        "status",
        "repository_root_verified",
        "expected_head",
        "expected_origin_url",
        "origin_url",
        "origin_matches_expected",
        "origin_observed_sha256",
        "tree_path",
        "tree_object",
        "tree_object_algorithm",
        "tree_matches_worktree",
        "location_is_canonical",
    }
    if set(binding) != fields:
        raise PairedXbenProtocolError(f"paired-XBEN preflight {label} source fields are invalid")
    head = expected_head
    if not isinstance(head, str) or _GIT_SHA_RE.fullmatch(head) is None:
        raise PairedXbenProtocolError(f"paired-XBEN preflight {label} source head is invalid")
    tree_object = binding.get("tree_object")
    expected_algorithm = "sha1" if len(head) == 40 else "sha256"
    if (
        binding.get("ready") is not True
        or binding.get("status") != "ready"
        or binding.get("repository_root_verified") is not True
        or binding.get("expected_head") != head
        or binding.get("expected_origin_url") != expected_origin
        or binding.get("origin_url") != expected_origin
        or binding.get("origin_matches_expected") is not True
        or binding.get("tree_path") != expected_tree_path
        or not isinstance(tree_object, str)
        or _GIT_SHA_RE.fullmatch(tree_object) is None
        or binding.get("tree_object_algorithm") != expected_algorithm
        or binding.get("tree_matches_worktree") is not True
        or binding.get("location_is_canonical") is not True
    ):
        raise PairedXbenProtocolError(
            f"paired-XBEN preflight {label} source is not canonically bound"
        )
    _sha256_digest(
        binding.get("origin_observed_sha256"),
        f"preflight {label} origin digest",
    )
    return binding


def _validated_strix_executable_identity(
    strix: Mapping[str, object],
    *,
    source_binding: Mapping[str, object],
) -> None:
    expected_fields = {
        "ready",
        "source_present",
        "executable_present",
        "dependency_probe_ok",
        "executable_source",
        "executable_sha256",
        "expected_executable_sha256",
        "identity_mode",
        "identity_verified",
        "source_relative_executable",
        "source_blob_object",
        "source_blob_algorithm",
        "source_binding",
        "status",
    }
    if set(strix) != expected_fields or _mapping(
        strix.get("source_binding"), "preflight Strix source binding"
    ) != dict(source_binding):
        raise PairedXbenProtocolError("paired-XBEN preflight Strix identity fields are invalid")
    executable_digest = _sha256_digest(
        strix.get("executable_sha256"),
        "preflight Strix executable digest",
    )
    mode = strix.get("identity_mode")
    if (
        mode not in {"pinned_source_blob", "binary_sha256"}
        or strix.get("identity_verified") is not True
    ):
        raise PairedXbenProtocolError("paired-XBEN preflight Strix executable is unverified")
    expected_digest = strix.get("expected_executable_sha256")
    if expected_digest is not None:
        _sha256_digest(expected_digest, "expected Strix executable digest")
    if mode == "binary_sha256":
        if expected_digest != executable_digest:
            raise PairedXbenProtocolError("paired-XBEN preflight Strix binary digest is unbound")
        return
    relative = strix.get("source_relative_executable")
    blob = strix.get("source_blob_object")
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith("/")
        or ".." in Path(relative).parts
        or not isinstance(blob, str)
        or _GIT_SHA_RE.fullmatch(blob) is None
        or strix.get("source_blob_algorithm") != ("sha1" if len(blob) == 40 else "sha256")
    ):
        raise PairedXbenProtocolError("paired-XBEN preflight Strix source blob is unbound")


def _load_commitment(path: Path) -> dict[str, object]:
    document = _load_document(path, "commitment manifest")
    expected_fields = {
        "schema_version",
        "protocol_id",
        "campaign_id",
        "created_at",
        "benchmark",
        "systems",
        "sample_size",
        "preflight_source",
        "eligible_pool",
        "randomness_commitment",
        "authenticity_policy",
        "algorithms",
        "attempt_policy",
        "run_contract",
        "document_digest",
    }
    if set(document) != expected_fields or document.get("schema_version") != COMMITMENT_SCHEMA:
        raise PairedXbenProtocolError("commitment fields do not match the supported schema")
    if document["protocol_id"] != PROTOCOL_ID:
        raise PairedXbenProtocolError("commitment protocol ID is unsupported")
    _campaign_id(document["campaign_id"])
    _timestamp(str(document["created_at"]))
    if document["benchmark"] != "XBEN" or document["systems"] != list(SYSTEMS):
        raise PairedXbenProtocolError("commitment benchmark or systems are invalid")
    if document["sample_size"] != SAMPLE_SIZE:
        raise PairedXbenProtocolError("commitment sample size must be exactly twenty")
    contract = _bounded_contract(_mapping(document["run_contract"], "run contract"))
    preflight_source = _mapping(document["preflight_source"], "preflight source")
    if preflight_source != {
        "file": PREFLIGHT_SOURCE_FILE,
        "sha256": contract["preflight_digest"],
    }:
        raise PairedXbenProtocolError("commitment preflight source binding is invalid")
    pool_payload = _mapping(document["eligible_pool"], "eligible pool")
    if set(pool_payload) != {"schema_version", "count", "case_ids", "digest"}:
        raise PairedXbenProtocolError("eligible pool fields are invalid")
    if pool_payload["schema_version"] != POOL_SCHEMA:
        raise PairedXbenProtocolError("eligible pool schema is unsupported")
    pool = _normalize_case_ids(_string_sequence(pool_payload["case_ids"], "eligible case IDs"))
    if pool != _CANONICAL_XBEN_IDS or pool_payload["count"] != len(pool):
        raise PairedXbenProtocolError("eligible pool count is invalid")
    if pool_payload["digest"] != eligible_pool_digest(pool):
        raise PairedXbenProtocolError("eligible pool digest mismatch")
    randomness = _mapping(document["randomness_commitment"], "randomness commitment")
    if set(randomness) != {
        "provider",
        "chain_hash",
        "chain_genesis_time",
        "chain_period_seconds",
        "observed_latest_round",
        "draw_round",
        "draw_not_before",
    }:
        raise PairedXbenProtocolError("randomness commitment fields are invalid")
    if randomness["provider"] != "drand":
        raise PairedXbenProtocolError("randomness provider must be drand")
    _hex_64(randomness["chain_hash"], "drand chain hash")
    genesis_time = _positive_int(randomness["chain_genesis_time"], "drand chain genesis time")
    period_seconds = _positive_int(randomness["chain_period_seconds"], "drand chain period")
    latest = _positive_int(randomness["observed_latest_round"], "observed latest drand round")
    draw_round = _positive_int(randomness["draw_round"], "committed drand draw round")
    if draw_round <= latest:
        raise PairedXbenProtocolError("committed drand round was not future at commitment")
    expected_draw_time = datetime.fromtimestamp(
        genesis_time + (draw_round - 1) * period_seconds,
        tz=UTC,
    )
    draw_not_before = datetime.fromisoformat(_timestamp(str(randomness["draw_not_before"])))
    commitment_time = datetime.fromisoformat(_timestamp(str(document["created_at"])))
    if draw_not_before != expected_draw_time or draw_not_before <= commitment_time:
        raise PairedXbenProtocolError("committed drand round time is inconsistent")
    try:
        validate_authenticity_policy(
            _mapping(document["authenticity_policy"], "authenticity policy")
        )
    except AuthenticityError as exc:
        raise PairedXbenProtocolError(f"commitment authenticity policy is invalid: {exc}") from exc
    algorithms = _mapping(document["algorithms"], "algorithms")
    if algorithms != {
        "selection": SELECTION_ALGORITHM,
        "schedule": SCHEDULE_ALGORITHM,
        "domain_separators": {
            "draw": DRAW_DOMAIN.decode(),
            "case_rank": CASE_RANK_DOMAIN.decode(),
            "pair_order": PAIR_ORDER_DOMAIN.decode(),
            "arm_order": ARM_ORDER_DOMAIN.decode(),
        },
    }:
        raise PairedXbenProtocolError("commitment algorithms are unsupported")
    if document["attempt_policy"] != {
        "primary_attempts_per_system_case": 1,
        "scored_attempts": "scheduled_primary_only",
        "primary_directory": PRIMARY_ATTEMPTS_DIRECTORY,
        "rerun_directory": RERUN_ATTEMPTS_DIRECTORY,
        "reruns_are_scored": False,
        "overwrite_allowed": False,
    }:
        raise PairedXbenProtocolError("attempt policy is invalid")
    return document


def _load_campaign_commitment(root: Path) -> dict[str, object]:
    commitment = _load_commitment(root / COMMITMENT_FILE)
    preflight_source = _mapping(commitment["preflight_source"], "preflight source")
    preflight_bytes = _read_bounded_bytes(
        _regular_file(root / PREFLIGHT_SOURCE_FILE, "retained paired-XBEN preflight"),
        "retained paired-XBEN preflight",
    )
    if len(preflight_bytes) > MAX_PREFLIGHT_JSON_BYTES:
        raise PairedXbenProtocolError("retained paired-XBEN preflight exceeds the byte limit")
    artifact_digest = _sha256_bytes(preflight_bytes)
    if artifact_digest != preflight_source["sha256"]:
        raise PairedXbenProtocolError("retained paired-XBEN preflight digest mismatch")
    preflight_pool = _validated_preflight_source(
        _decode_json(preflight_bytes, "retained paired-XBEN preflight"),
        contract=_mapping(commitment["run_contract"], "run contract"),
        artifact_digest=artifact_digest,
    )
    pool = _mapping(commitment["eligible_pool"], "eligible pool")
    if preflight_pool != tuple(_string_sequence(pool["case_ids"], "eligible case IDs")):
        raise PairedXbenProtocolError("commitment pool differs from retained preflight")
    return commitment


def _validate_beacon_document(
    beacon: Mapping[str, object],
    *,
    commitment: Mapping[str, object],
    source_payload: object,
    source_bytes: bytes,
    authenticity: Mapping[str, object],
) -> None:
    expected = _normalized_beacon(
        source_payload,
        commitment=commitment,
        source_document_sha256=_sha256_bytes(source_bytes),
        authenticity=authenticity,
    )
    if beacon != expected:
        raise PairedXbenProtocolError("normalized drand beacon does not match its source")


def _load_authenticated_resolution(
    root: Path,
    commitment: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Re-run both cryptographic gates over retained, create-only evidence."""

    resolution = _existing_directory(root / RESOLUTION_DIRECTORY, "resolution directory")
    primary_path = _regular_file(resolution / BEACON_SOURCE_FILE, "saved drand beacon")
    secondary_path = _regular_file(
        resolution / SECONDARY_BEACON_SOURCE_FILE,
        "secondary saved drand beacon",
    )
    fetch_manifest = _load_document(
        resolution / DRAND_FETCH_FILE,
        "drand fetch manifest",
    )
    relay_sources = _drand_fetch_sources(fetch_manifest, commitment=commitment)
    chain_info_path = _regular_file(
        resolution / DRAND_CHAIN_INFO_SOURCE_FILE,
        "drand chain info",
    )
    bundle_path = _regular_file(
        resolution / PUBLICATION_ANCHOR_SOURCE_FILE,
        "Sigstore publication bundle",
    )
    primary_bytes = _read_bounded_bytes(primary_path, "saved drand beacon")
    bundle_bytes = _read_bounded_bytes(bundle_path, "Sigstore publication bundle")
    randomness = _mapping(commitment["randomness_commitment"], "randomness commitment")
    policy = _mapping(commitment["authenticity_policy"], "authenticity policy")
    try:
        drand_authenticity = verify_drand_evidence(
            root,
            policy=policy,
            chain_info_path=chain_info_path,
            primary_beacon_path=primary_path,
            secondary_beacon_path=secondary_path,
            chain_hash=str(randomness["chain_hash"]),
            round_number=_positive_int(randomness["draw_round"], "committed drand round"),
            genesis_time=_positive_int(randomness["chain_genesis_time"], "drand genesis time"),
            period_seconds=_positive_int(randomness["chain_period_seconds"], "drand period"),
            relay_sources=relay_sources,
        )
        publication_authenticity = verify_publication_evidence(
            root,
            policy=policy,
            commitment_path=root / COMMITMENT_FILE,
            bundle_path=bundle_path,
            commitment_created_at=str(commitment["created_at"]),
            draw_not_before=str(randomness["draw_not_before"]),
        )
    except AuthenticityError as exc:
        raise PairedXbenProtocolError(f"retained authenticity evidence is invalid: {exc}") from exc

    beacon = _load_document(resolution / BEACON_FILE, "normalized drand beacon")
    _validate_beacon_document(
        beacon,
        commitment=commitment,
        source_payload=_decode_json(primary_bytes, "saved drand beacon"),
        source_bytes=primary_bytes,
        authenticity=drand_authenticity,
    )
    anchor = _load_document(resolution / PUBLICATION_ANCHOR_FILE, "publication anchor")
    expected_anchor = _normalized_publication_anchor(
        publication_authenticity,
        commitment=commitment,
        source_document_sha256=_sha256_bytes(bundle_bytes),
    )
    if anchor != expected_anchor:
        raise PairedXbenProtocolError("publication anchor does not match verified evidence")
    selection = _load_document(resolution / SELECTION_FILE, "selection manifest")
    if selection != _build_selection(commitment, beacon):
        raise PairedXbenProtocolError("selection manifest does not reproduce from its commitment")
    return beacon, anchor, selection


def _require_matching_pool(commitment: Mapping[str, object], case_ids: Sequence[str]) -> None:
    supplied = _normalize_case_ids(case_ids)
    pool_payload = _mapping(commitment.get("eligible_pool"), "eligible pool")
    committed = tuple(_string_sequence(pool_payload.get("case_ids"), "eligible case IDs"))
    if supplied != committed or eligible_pool_digest(supplied) != pool_payload.get("digest"):
        raise PairedXbenProtocolError("eligible population changed after commitment")


def _load_resolved_campaign(
    campaign_dir: Path,
) -> tuple[Path, dict[str, object], dict[str, object]]:
    root = _existing_directory(campaign_dir, "campaign directory")
    commitment = _load_campaign_commitment(root)
    _beacon, _anchor, selection = _load_authenticated_resolution(root, commitment)
    return root, commitment, selection


def _attempt_body(
    *,
    commitment: Mapping[str, object],
    selection: Mapping[str, object],
    attempt_id: str,
    purpose: str,
    score_eligible: bool,
    row: Mapping[str, object],
    parent_primary_slot_id: str | None,
    reason: str | None,
    created_at: str | None,
) -> dict[str, object]:
    return {
        "schema_version": ATTEMPT_SCHEMA,
        "campaign_id": commitment["campaign_id"],
        "commitment_digest": commitment["document_digest"],
        "selection_digest": selection["document_digest"],
        "attempt_id": attempt_id,
        "created_at": _timestamp(created_at),
        "purpose": purpose,
        "score_eligible": score_eligible,
        "primary_slot_id": row["slot_id"],
        "case_id": row["case_id"],
        "system": row["system"],
        "pair_index": row["pair_index"],
        "position_within_pair": row["position_within_pair"],
        "parent_primary_slot_id": parent_primary_slot_id,
        "reason": reason,
        "artifact_directory": "artifacts",
    }


def _verify_attempt_manifests(
    root: Path,
    *,
    commitment: Mapping[str, object],
    selection: Mapping[str, object],
) -> dict[str, object]:
    schedule = _schedule(selection)
    schedule_by_slot = {str(row["slot_id"]): row for row in schedule}
    matrix = _verify_primary_matrix_reservation(
        root,
        commitment=commitment,
        selection=selection,
        allow_absent=True,
    )
    primary_ids = cast("tuple[str, ...]", matrix["primary_ids"])
    rerun_root = root / RERUN_ATTEMPTS_DIRECTORY

    rerun_ids = _attempt_directory_ids(rerun_root, "diagnostic reruns")
    for rerun_id in rerun_ids:
        document = _load_document(
            rerun_root / rerun_id / "attempt.json", "diagnostic rerun manifest"
        )
        parent = str(document.get("parent_primary_slot_id") or "")
        if parent not in primary_ids:
            raise PairedXbenProtocolError("diagnostic rerun has no retained primary parent")
        _validate_attempt_document(
            document,
            commitment=commitment,
            selection=selection,
            expected_row=schedule_by_slot[parent],
            expected_purpose="diagnostic_rerun",
        )
        if document.get("attempt_id") != rerun_id:
            raise PairedXbenProtocolError("diagnostic rerun directory and manifest IDs differ")
    return {
        "recorded_primary_attempts": len(primary_ids),
        "missing_primary_attempts": len(schedule_by_slot) - len(primary_ids),
        "primary_matrix_reserved": matrix["reserved"],
        "primary_matrix_digest": matrix["reservation_digest"],
        "diagnostic_reruns": len(rerun_ids),
    }


def _verify_primary_matrix_reservation(
    root: Path,
    *,
    commitment: Mapping[str, object],
    selection: Mapping[str, object],
    allow_absent: bool,
) -> dict[str, object]:
    """Validate the all-at-once primary reservation and every bound slot."""

    primary_root = root / PRIMARY_ATTEMPTS_DIRECTORY
    marker_path = root / PRIMARY_MATRIX_FILE
    root_present = primary_root.exists() or primary_root.is_symlink()
    marker_present = marker_path.exists() or marker_path.is_symlink()
    if not root_present and not marker_present:
        if allow_absent:
            return {"reserved": False, "reservation_digest": None, "primary_ids": ()}
        raise PairedXbenProtocolError("primary matrix has not been reserved")
    if not root_present or not marker_present:
        raise PairedXbenProtocolError(
            "primary matrix reservation is incomplete and cannot be resumed"
        )

    schedule = _schedule(selection)
    expected_rows = SAMPLE_SIZE * len(SYSTEMS)
    if len(schedule) != expected_rows:
        raise PairedXbenProtocolError("selection schedule does not contain exactly 40 rows")
    schedule_by_slot = {str(row["slot_id"]): row for row in schedule}
    if len(schedule_by_slot) != expected_rows:
        raise PairedXbenProtocolError("selection schedule contains duplicate primary slots")

    primary_ids = _attempt_directory_ids(primary_root, "primary attempts")
    expected_ids = tuple(sorted(schedule_by_slot))
    if primary_ids != expected_ids:
        raise PairedXbenProtocolError(
            "primary matrix reservation does not contain every scheduled slot exactly once"
        )

    actual_entries: list[dict[str, object]] = []
    for slot_id in primary_ids:
        attempt_root = _existing_directory(primary_root / slot_id, "primary attempt")
        children = {child.name for child in attempt_root.iterdir()}
        if children != {"artifacts", "attempt.json"}:
            raise PairedXbenProtocolError(
                f"primary attempt {slot_id} has unexpected or missing reservation entries"
            )
        _existing_directory(attempt_root / "artifacts", "primary artifact directory")
        document = _load_document(attempt_root / "attempt.json", "primary attempt manifest")
        _validate_attempt_document(
            document,
            commitment=commitment,
            selection=selection,
            expected_row=schedule_by_slot[slot_id],
            expected_purpose="primary",
        )
        actual_entries.append(
            {
                "slot_id": slot_id,
                "attempt_manifest": f"{slot_id}/attempt.json",
                "artifact_directory": f"{slot_id}/artifacts",
                "attempt_document_digest": document["document_digest"],
            }
        )

    reservation = _load_document(marker_path, "primary matrix reservation")
    expected_fields = {
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
    if (
        set(reservation) != expected_fields
        or reservation.get("schema_version") != PRIMARY_MATRIX_SCHEMA
    ):
        raise PairedXbenProtocolError("primary matrix reservation fields are invalid")
    _timestamp(str(reservation.get("created_at")))
    if (
        reservation.get("campaign_id") != commitment["campaign_id"]
        or reservation.get("commitment_digest") != commitment["document_digest"]
        or reservation.get("selection_digest") != selection["document_digest"]
        or reservation.get("primary_directory") != "primary"
        or reservation.get("scheduled_primary_attempts") != expected_rows
        or reservation.get("attempts") != actual_entries
        or reservation.get("attempt_documents_digest") != _sha256_json(actual_entries)
        or reservation.get("policy")
        != {
            "all_slots_reserved_before_execution": True,
            "resume_incomplete_reservation": False,
            "replace_primary_attempt": False,
        }
    ):
        raise PairedXbenProtocolError("primary matrix reservation binding is invalid")
    return {
        "reserved": True,
        "reservation_digest": reservation["document_digest"],
        "primary_ids": primary_ids,
    }


def _validate_attempt_document(
    document: Mapping[str, object],
    *,
    commitment: Mapping[str, object],
    selection: Mapping[str, object],
    expected_row: Mapping[str, object],
    expected_purpose: str,
) -> None:
    fields = {
        "schema_version",
        "campaign_id",
        "commitment_digest",
        "selection_digest",
        "attempt_id",
        "created_at",
        "purpose",
        "score_eligible",
        "primary_slot_id",
        "case_id",
        "system",
        "pair_index",
        "position_within_pair",
        "parent_primary_slot_id",
        "reason",
        "artifact_directory",
        "document_digest",
    }
    if set(document) != fields or document.get("schema_version") != ATTEMPT_SCHEMA:
        raise PairedXbenProtocolError("attempt manifest fields are invalid")
    if (
        document["campaign_id"] != commitment["campaign_id"]
        or document["commitment_digest"] != commitment["document_digest"]
        or document["selection_digest"] != selection["document_digest"]
    ):
        raise PairedXbenProtocolError("attempt manifest campaign binding is invalid")
    _attempt_id(document["attempt_id"], "attempt ID")
    _timestamp(str(document["created_at"]))
    schedule_fields = {
        "primary_slot_id": "slot_id",
        "case_id": "case_id",
        "system": "system",
        "pair_index": "pair_index",
        "position_within_pair": "position_within_pair",
    }
    for key, row_key in schedule_fields.items():
        if document[key] != expected_row[row_key]:
            raise PairedXbenProtocolError(f"attempt manifest {key} differs from its schedule")
    if document["artifact_directory"] != "artifacts":
        raise PairedXbenProtocolError("attempt artifact directory is invalid")
    if expected_purpose == "primary":
        if (
            document["purpose"] != "primary"
            or document["score_eligible"] is not True
            or document["attempt_id"] != expected_row["slot_id"]
            or document["parent_primary_slot_id"] is not None
            or document["reason"] is not None
        ):
            raise PairedXbenProtocolError("primary attempt manifest policy is invalid")
    elif (
        document["purpose"] != "diagnostic_rerun"
        or document["score_eligible"] is not False
        or document["parent_primary_slot_id"] != expected_row["slot_id"]
        or not isinstance(document["reason"], str)
        or not document["reason"].strip()
    ):
        raise PairedXbenProtocolError("diagnostic rerun manifest policy is invalid")


def _schedule_row(selection: Mapping[str, object], slot_id: str) -> Mapping[str, object]:
    normalized = _attempt_id(slot_id, "primary slot ID")
    rows = [row for row in _schedule(selection) if row["slot_id"] == normalized]
    if len(rows) != 1:
        raise PairedXbenProtocolError("primary slot is not present exactly once in the schedule")
    return rows[0]


def _schedule(selection: Mapping[str, object]) -> list[Mapping[str, object]]:
    raw = selection.get("schedule")
    if not isinstance(raw, list) or any(not isinstance(row, Mapping) for row in raw):
        raise PairedXbenProtocolError("selection schedule is invalid")
    return cast("list[Mapping[str, object]]", raw)


def _attempt_directory_ids(path: Path, label: str) -> tuple[str, ...]:
    if not path.exists():
        return ()
    root = _existing_directory(path, label)
    ids: list[str] = []
    for child in sorted(root.iterdir()):
        if child.is_symlink() or not child.is_dir():
            raise PairedXbenProtocolError(f"{label} contains a non-directory entry")
        ids.append(_attempt_id(child.name, f"{label} entry"))
    return tuple(ids)


def _document(body: Mapping[str, object]) -> dict[str, object]:
    if "document_digest" in body:
        raise PairedXbenProtocolError("document body already contains a digest")
    normalized = dict(body)
    return {**normalized, "document_digest": _sha256_json(normalized)}


def _load_document(path: Path, label: str) -> dict[str, object]:
    payload = _load_untrusted_json(path, label)
    if not isinstance(payload, dict):
        raise PairedXbenProtocolError(f"{label} must be a JSON object")
    digest = _sha256_digest(payload.get("document_digest"), f"{label} digest")
    body = {key: value for key, value in payload.items() if key != "document_digest"}
    if digest != _sha256_json(body):
        raise PairedXbenProtocolError(f"{label} digest mismatch")
    _reject_ground_truth(payload)
    return payload


def _load_untrusted_json(path: Path, label: str) -> object:
    source = _regular_file(path, label)
    return _decode_json(_read_bounded_bytes(source, label), label)


def _decode_json(content: bytes, label: str) -> object:
    try:
        return json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PairedXbenProtocolError(f"{label} is not valid JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PairedXbenProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise PairedXbenProtocolError(f"non-finite JSON value is forbidden: {value}")


def _bounded_contract(value: Mapping[str, object]) -> dict[str, object]:
    contract = dict(value)
    expected_fields = {
        "schema_version",
        "mode",
        "objective",
        "sources",
        "compatibility_catalog",
        "adapter",
        "runtime_manifests",
        "model_gateway",
        "budgets",
        "evaluator_components",
        "execution_policy",
        "oci_images",
        "target_helper_image_ids",
        "preflight_digest",
    }
    if set(contract) != expected_fields:
        raise PairedXbenProtocolError("run contract fields do not match the frozen schema")
    if contract.get("schema_version") != RUN_CONTRACT_SCHEMA:
        raise PairedXbenProtocolError("run contract schema is unsupported")
    if contract.get("mode") != "description-only-black-box":
        raise PairedXbenProtocolError("run contract mode must be description-only black box")
    if contract.get("objective") != "capture_flag":
        raise PairedXbenProtocolError("run contract objective must be capture_flag")
    sources = _mapping(contract.get("sources"), "run contract sources")
    if set(sources) != {"ravage", "strix", "xben"}:
        raise PairedXbenProtocolError("run contract must freeze Ravage, Strix, and XBEN")
    expected_source_paths = {"ravage": ".", "strix": ".", "xben": "benchmarks"}
    expected_origins = {
        "strix": STRIX_CANONICAL_ORIGIN_URL,
        "xben": XBEN_CANONICAL_ORIGIN_URL,
    }
    for system in expected_source_paths:
        source = _mapping(sources[system], f"{system} source")
        if set(source) != {
            "commit_sha",
            "tree_object",
            "tree_path",
            "origin_url",
            "dirty",
        }:
            raise PairedXbenProtocolError(f"{system} source fields are invalid")
        commit_sha = source["commit_sha"]
        tree_object = source["tree_object"]
        if (
            not isinstance(commit_sha, str)
            or _GIT_SHA_RE.fullmatch(commit_sha) is None
            or not isinstance(tree_object, str)
            or _GIT_SHA_RE.fullmatch(tree_object) is None
            or len(tree_object) != len(commit_sha)
        ):
            raise PairedXbenProtocolError(
                f"{system} commit and tree must be full same-algorithm Git object IDs"
            )
        if source["tree_path"] != expected_source_paths[system]:
            raise PairedXbenProtocolError(f"{system} source tree path is invalid")
        origin = _bounded_ascii_text(source["origin_url"], f"{system} source origin", maximum=500)
        _require_public_https_url(origin, f"{system} source origin")
        if system in expected_origins and origin != expected_origins[system]:
            raise PairedXbenProtocolError(f"{system} source origin is not canonical")
        if source["dirty"] is not False:
            raise PairedXbenProtocolError(f"{system} source must be frozen with dirty=false")

    catalog = _mapping(contract.get("compatibility_catalog"), "compatibility catalog")
    if (
        set(catalog) != {"schema_version", "sha256"}
        or catalog.get("schema_version") != _COMPATIBILITY_CATALOG_SCHEMA
    ):
        raise PairedXbenProtocolError("compatibility catalog binding is invalid")
    _sha256_digest(catalog.get("sha256"), "compatibility catalog digest")

    adapter = _mapping(contract.get("adapter"), "comparison adapter")
    if set(adapter) != {"schema_version", "adapter_version", "source_sha256"} or (
        adapter.get("schema_version") != _ADAPTER_SCHEMA_VERSION
        or adapter.get("adapter_version") != _ADAPTER_VERSION
    ):
        raise PairedXbenProtocolError("comparison adapter schema or version is invalid")
    adapter_source_digest = _sha256_digest(
        adapter.get("source_sha256"), "comparison adapter source digest"
    )

    runtime_manifests = _mapping(contract.get("runtime_manifests"), "runtime environment manifests")
    if set(runtime_manifests) != set(SYSTEMS):
        raise PairedXbenProtocolError("both runtime environment manifests must be frozen")
    for system in SYSTEMS:
        manifest = _mapping(runtime_manifests[system], f"{system} runtime manifest")
        digest_fields = {
            "sha256",
            "executable_sha256",
            "interpreter_sha256",
            "lockfile_sha256",
            "distribution_inventory_sha256",
            "site_packages_tree_sha256",
        }
        if (
            set(manifest) != {"schema_version", *digest_fields}
            or manifest.get("schema_version") != _RUNTIME_ENVIRONMENT_SCHEMA
        ):
            raise PairedXbenProtocolError(f"{system} runtime manifest binding is invalid")
        for name in digest_fields:
            _sha256_digest(manifest.get(name), f"{system} runtime {name}")

    gateway = _mapping(contract.get("model_gateway"), "model gateway contract")
    if set(gateway) != {
        "row_receipt_schema_version",
        "campaign_receipt_schema_version",
        "provider",
        "agent_provider",
        "service_tier",
        "store",
        "policy",
        "policy_sha256",
        "pricing_source",
    }:
        raise PairedXbenProtocolError("model gateway contract fields are invalid")
    if (
        gateway.get("row_receipt_schema_version") != _MODEL_GATEWAY_ROW_RECEIPT_SCHEMA
        or gateway.get("campaign_receipt_schema_version") != _MODEL_GATEWAY_CAMPAIGN_RECEIPT_SCHEMA
        or gateway.get("provider") != "openai"
        or gateway.get("agent_provider") != "paired-row-gateway"
        or gateway.get("service_tier") != "default"
        or gateway.get("store") is not False
    ):
        raise PairedXbenProtocolError("model gateway request snapshot is invalid")
    policy = _validated_model_gateway_policy(gateway.get("policy"))
    policy_digest = _sha256_json(policy)
    if gateway.get("policy_sha256") != policy_digest:
        raise PairedXbenProtocolError("model gateway policy digest does not reproduce")
    _validated_pricing_source(
        gateway.get("pricing_source"),
        model=cast("str", policy["model"]),
    )

    budgets = _mapping(contract.get("budgets"), "run contract budgets")
    if set(budgets) != {"campaign", "per_row"}:
        raise PairedXbenProtocolError("run contract budget fields are invalid")
    campaign_budget = _validated_budget_scope(budgets["campaign"], label="campaign")
    row_budget = _validated_budget_scope(budgets["per_row"], label="per-row")
    row_count = SAMPLE_SIZE * len(SYSTEMS)
    for name in ("wall_seconds", "max_model_requests", "max_target_requests"):
        if campaign_budget[name] != row_count * cast("int", row_budget[name]):
            raise PairedXbenProtocolError(f"campaign {name} must equal forty times the per-row cap")
    row_cost = _decimal(row_budget["max_cost_usd"], "per-row cost cap")
    with localcontext() as context:
        context.prec = max(context.prec, len(row_cost.as_tuple().digits) + len(str(row_count)))
        campaign_cost = row_count * row_cost
    if _decimal(campaign_budget["max_cost_usd"], "campaign cost cap") != campaign_cost:
        raise PairedXbenProtocolError(
            "campaign max_cost_usd must equal forty times the per-row cap"
        )
    if policy.get("campaign_max_cost_usd") != campaign_budget["max_cost_usd"]:
        raise PairedXbenProtocolError("gateway and campaign cost ceilings differ")

    components = _mapping(contract.get("evaluator_components"), "evaluator components")
    if set(components) != set(_EVALUATOR_COMPONENTS):
        raise PairedXbenProtocolError("evaluator component source set is incomplete")
    for path in _EVALUATOR_COMPONENTS:
        _sha256_digest(components[path], f"evaluator source digest for {path}")
    adapter_path = "packages/ravage/src/ravage/xben_parts/comparison_adapters.py"
    if components[adapter_path] != adapter_source_digest:
        raise PairedXbenProtocolError("adapter source digest differs from component inventory")

    execution = _mapping(contract.get("execution_policy"), "execution policy")
    evaluator_host = _mapping(execution.get("evaluator_host"), "evaluator host policy")
    if set(evaluator_host) != {
        "platform",
        "containment_backend",
        "sandbox_executable_path",
        "sandbox_executable_sha256",
        "systems",
    }:
        raise PairedXbenProtocolError("evaluator host policy fields are invalid")
    if (
        evaluator_host.get("platform") != "darwin"
        or evaluator_host.get("containment_backend") != "sandbox-exec"
        or evaluator_host.get("sandbox_executable_path") != "/usr/bin/sandbox-exec"
    ):
        raise PairedXbenProtocolError("evaluator host containment policy is unsupported")
    _sha256_digest(
        evaluator_host.get("sandbox_executable_sha256"),
        "evaluator sandbox executable digest",
    )
    host_systems = _mapping(evaluator_host.get("systems"), "evaluator host system policies")
    if set(host_systems) != set(SYSTEMS):
        raise PairedXbenProtocolError("evaluator host must freeze both system policies")
    for system in SYSTEMS:
        system_policy = _mapping(host_systems[system], f"{system} evaluator host policy")
        if set(system_policy) != {
            "evidence_class",
            "runtime_read_roots_sha256",
            "runtime_read_root_count",
            "docker_socket_access",
            "docker_socket_path_sha256",
            "docker_host_sha256",
        }:
            raise PairedXbenProtocolError(f"{system} evaluator host fields are invalid")
        evidence_class = system_policy.get("evidence_class")
        docker_access = system_policy.get("docker_socket_access")
        docker_path_digest = system_policy.get("docker_socket_path_sha256")
        docker_host_digest = system_policy.get("docker_host_sha256")
        if evidence_class not in {"strict_official", "paired_local"} or not isinstance(
            docker_access, bool
        ):
            raise PairedXbenProtocolError(f"{system} evaluator evidence class is invalid")
        if (evidence_class == "strict_official" and docker_access) or (
            evidence_class == "paired_local" and not docker_access
        ):
            raise PairedXbenProtocolError(
                f"{system} evaluator Docker access conflicts with its evidence class"
            )
        if docker_access:
            _sha256_digest(docker_path_digest, f"{system} Docker socket path digest")
            _sha256_digest(docker_host_digest, f"{system} Docker host digest")
        elif docker_path_digest is not None or docker_host_digest is not None:
            raise PairedXbenProtocolError(
                f"{system} strict evaluator policy unexpectedly binds a Docker socket"
            )
        runtime_count = _positive_int(
            system_policy.get("runtime_read_root_count"),
            f"{system} runtime read-root count",
        )
        if runtime_count > 128:
            raise PairedXbenProtocolError(f"{system} runtime read-root count exceeds its bound")
        _sha256_digest(
            system_policy.get("runtime_read_roots_sha256"),
            f"{system} runtime read-root digest",
        )
    expected_execution = {
        "platform": "linux/amd64",
        "model_gateway_endpoint_mode": "host_loopback_row_token",
        "process_group_policy": "joined_evaluator_outer_group",
        "outer_process_group_environment": "joined_evaluator_group_v1",
        "evaluator_host": evaluator_host,
        "target_endpoint_modes": {
            "ravage": "host_loopback",
            "strix": "docker_alias",
        },
        "flag_scope": "fresh_random_256bit_flag_per_case_pair",
        "flag_disclosure": "withheld_until_both_arms_terminal",
        "build_once_per_case_pair": True,
        "same_prepared_image_ids_for_both_arms": True,
        "fresh_project_per_arm": True,
        "fresh_containers_per_arm": True,
        "fresh_volumes_per_arm": True,
        "runtime_build_allowed": False,
        "runtime_pull_allowed": False,
        "target_build_input_boundary": {
            "pinned_source_and_compatibility_catalog": True,
            "explicit_privileged_or_remote_compose_build_features_forbidden": True,
            "preparation_registry_and_default_build_network_available": True,
            "external_base_references_may_be_mutable": True,
            "post_resolution_local_image_ids_frozen": True,
            "hermetic_rebuild_claimed": False,
        },
    }
    if execution != expected_execution:
        raise PairedXbenProtocolError("execution policy is not the frozen paired-image policy")

    images = _mapping(contract.get("oci_images"), "OCI image references")
    if set(images) != set(_OCI_IMAGE_ROLES):
        raise PairedXbenProtocolError("OCI image reference set is incomplete")
    for role in _OCI_IMAGE_ROLES:
        image = images[role]
        if not isinstance(image, str) or _OCI_REFERENCE_RE.fullmatch(image) is None:
            raise PairedXbenProtocolError(f"{role} must be a digest-pinned OCI reference")

    helper_image_ids = _mapping(contract.get("target_helper_image_ids"), "target helper image IDs")
    if set(helper_image_ids) != {"target_gateway", "target_probe"}:
        raise PairedXbenProtocolError("target helper image ID set is incomplete")
    for role, image_id in helper_image_ids.items():
        if not isinstance(image_id, str) or _SHA256_RE.fullmatch(image_id) is None:
            raise PairedXbenProtocolError(f"{role} must freeze a local sha256 image ID")

    _sha256_digest(contract.get("preflight_digest"), "preflight digest")
    _reject_ground_truth(contract)
    if len(canonical_json(contract).encode()) > MAX_CONTRACT_BYTES:
        raise PairedXbenProtocolError("run contract exceeds the byte limit")
    return contract


def _validated_model_gateway_policy(value: object) -> dict[str, object]:
    policy = _mapping(value, "model gateway policy")
    fields = {
        "schema_version",
        "upstream",
        "model",
        "reasoning_effort",
        "pricing_usd_per_million_tokens",
        "campaign_max_cost_usd",
        "max_completion_tokens_per_request",
        "max_request_body_bytes",
        "max_upstream_response_bytes",
        "upstream_timeout_seconds",
        "max_parallel_requests",
        "input_token_reservation",
        "retry_policy",
        "unknown_usage_policy",
    }
    if set(policy) != fields:
        raise PairedXbenProtocolError("model gateway policy fields are invalid")
    if (
        policy.get("schema_version") != _MODEL_GATEWAY_POLICY_SCHEMA
        or policy.get("upstream") != "https://api.openai.com/v1/chat/completions"
        or policy.get("retry_policy") != "gateway_never_retries"
        or policy.get("unknown_usage_policy") != "charge_full_reservation_and_invalidate_row"
        or policy.get("input_token_reservation")
        != {
            "algorithm": "utf8_body_bytes_plus_fixed_overhead",
            "fixed_overhead_tokens": 4096,
            "cached_discount_assumed": False,
        }
    ):
        raise PairedXbenProtocolError("model gateway policy constants are invalid")
    model_snapshot = _bounded_ascii_text(policy.get("model"), "model snapshot", maximum=200)
    if _MODEL_SNAPSHOT_RE.fullmatch(model_snapshot) is None:
        raise PairedXbenProtocolError(
            "model must be an immutable date-suffixed snapshot, not an alias"
        )
    try:
        datetime.fromisoformat(model_snapshot[-10:])
    except ValueError as exc:
        raise PairedXbenProtocolError("model snapshot date is invalid") from exc
    _bounded_ascii_text(policy.get("reasoning_effort"), "reasoning effort", maximum=200)
    pricing = _mapping(policy.get("pricing_usd_per_million_tokens"), "model pricing")
    if set(pricing) != {
        "input_per_million",
        "cached_input_per_million",
        "output_per_million",
    }:
        raise PairedXbenProtocolError("model pricing fields are invalid")
    _canonical_decimal_text(pricing["input_per_million"], "input price", positive=True)
    _canonical_decimal_text(
        pricing["cached_input_per_million"], "cached-input price", positive=False
    )
    _canonical_decimal_text(pricing["output_per_million"], "output price", positive=True)
    _canonical_decimal_text(policy.get("campaign_max_cost_usd"), "campaign cost", positive=True)
    for name in (
        "max_completion_tokens_per_request",
        "max_request_body_bytes",
        "max_upstream_response_bytes",
        "upstream_timeout_seconds",
        "max_parallel_requests",
    ):
        _positive_int(policy.get(name), f"model gateway {name}")
    return policy


def _validated_pricing_source(value: object, *, model: str) -> dict[str, object]:
    """Validate the commitment-bound official pricing-page snapshot identity."""

    source = _mapping(value, "model pricing source")
    if set(source) != {
        "kind",
        "url",
        "published_on",
        "retrieved_at",
        "artifact_sha256",
    }:
        raise PairedXbenProtocolError("model pricing source fields are invalid")
    if source.get("kind") != "openai_model_page_markdown":
        raise PairedXbenProtocolError("model pricing source kind is unsupported")
    url = _bounded_ascii_text(source.get("url"), "model pricing source URL", maximum=500)
    parsed = urlsplit(url)
    expected_path = f"/api/docs/models/{model[:-11]}.md"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "developers.openai.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise PairedXbenProtocolError(
            "model pricing source must be the canonical official snapshot Markdown URL"
        )
    published_on = source.get("published_on")
    if published_on is not None:
        if not isinstance(published_on, str):
            raise PairedXbenProtocolError("model pricing publication date is invalid")
        try:
            parsed_date = datetime.strptime(published_on, "%Y-%m-%d").date()
        except ValueError as exc:
            raise PairedXbenProtocolError("model pricing publication date is invalid") from exc
        if parsed_date.isoformat() != published_on:
            raise PairedXbenProtocolError("model pricing publication date is not canonical")
    retrieved_at = _timestamp(str(source.get("retrieved_at")))
    retrieved = datetime.fromisoformat(retrieved_at)
    if retrieved.utcoffset() != UTC.utcoffset(retrieved):
        raise PairedXbenProtocolError("model pricing retrieval time must be UTC")
    _sha256_digest(source.get("artifact_sha256"), "model pricing source artifact digest")
    return source


def _validated_budget_scope(value: object, *, label: str) -> dict[str, object]:
    budget = _mapping(value, f"{label} budget")
    if set(budget) != {
        "wall_seconds",
        "max_model_requests",
        "max_target_requests",
        "max_cost_usd",
    }:
        raise PairedXbenProtocolError(f"{label} budget fields are invalid")
    for name in ("wall_seconds", "max_model_requests", "max_target_requests"):
        _positive_int(budget.get(name), f"{label} {name}")
    _canonical_decimal_text(budget.get("max_cost_usd"), f"{label} cost cap", positive=True)
    return budget


def _reject_ground_truth(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in _FORBIDDEN_CONTRACT_KEYS:
                raise PairedXbenProtocolError("protocol metadata must not contain ground truth")
            _reject_ground_truth(nested)
    elif isinstance(value, list | tuple):
        for item in value:
            _reject_ground_truth(item)
    elif isinstance(value, str) and _FLAG_VALUE_RE.search(value):
        raise PairedXbenProtocolError("protocol metadata must not contain flag-shaped values")


def _normalize_case_ids(case_ids: Sequence[str]) -> tuple[str, ...]:
    if isinstance(case_ids, str) or not isinstance(case_ids, Sequence):
        raise PairedXbenProtocolError("eligible case IDs must be a sequence")
    normalized: list[tuple[int, str]] = []
    seen: set[str] = set()
    for raw in case_ids:
        if not isinstance(raw, str):
            raise PairedXbenProtocolError("eligible case ID must be a string")
        case_id = raw.strip().upper()
        match = _CASE_ID_RE.fullmatch(case_id)
        if match is None or not 1 <= int(match.group(1)) <= MAX_POOL_SIZE:
            raise PairedXbenProtocolError(f"invalid canonical XBEN case ID: {raw!r}")
        if case_id in seen:
            raise PairedXbenProtocolError(f"duplicate eligible XBEN case ID: {case_id}")
        seen.add(case_id)
        normalized.append((int(match.group(1)), case_id))
    if len(normalized) > MAX_POOL_SIZE:
        raise PairedXbenProtocolError("eligible pool exceeds the canonical XBEN size")
    normalized.sort()
    return tuple(case_id for _number, case_id in normalized)


def _string_sequence(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PairedXbenProtocolError(f"{label} must be a list of strings")
    return tuple(value)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise PairedXbenProtocolError(f"{label} must be an object")
    return dict(value)


def _campaign_id(value: object) -> str:
    if not isinstance(value, str) or _CAMPAIGN_ID_RE.fullmatch(value) is None:
        raise PairedXbenProtocolError("campaign ID is invalid")
    return value


def _attempt_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _ATTEMPT_ID_RE.fullmatch(value) is None:
        raise PairedXbenProtocolError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PairedXbenProtocolError(f"{label} must be a positive integer")
    return value


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PairedXbenProtocolError(f"{label} must be a positive finite number")
    try:
        normalized = float(value)
    except OverflowError as exc:
        raise PairedXbenProtocolError(f"{label} must be a positive finite number") from exc
    if not math.isfinite(normalized) or normalized <= 0:
        raise PairedXbenProtocolError(f"{label} must be a positive finite number")
    return normalized


def _decimal(value: object, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, str):
        raise PairedXbenProtocolError(f"{label} must be a canonical decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise PairedXbenProtocolError(f"{label} must be a canonical decimal string") from exc
    if not result.is_finite() or result < 0:
        raise PairedXbenProtocolError(f"{label} must be a non-negative finite decimal")
    return result


def _canonical_decimal_text(value: object, label: str, *, positive: bool) -> str:
    result = _decimal(value, label)
    normalized = format(result, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    normalized = "0" if normalized in {"", "-0"} else normalized
    if value != normalized or (positive and result <= 0):
        qualifier = "positive " if positive else "non-negative "
        raise PairedXbenProtocolError(f"{label} must be a canonical {qualifier}decimal string")
    return normalized


def _hex_64(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_64_RE.fullmatch(value.lower()) is None:
        raise PairedXbenProtocolError(f"{label} must be 32-byte lowercase hex")
    return value.lower()


def _hex(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise PairedXbenProtocolError(f"{label} must be hex")
    normalized = value.lower()
    if not normalized or len(normalized) > maximum or _HEX_RE.fullmatch(normalized) is None:
        raise PairedXbenProtocolError(f"{label} must be bounded even-length hex")
    return normalized


def _sha256_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise PairedXbenProtocolError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PairedXbenProtocolError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PairedXbenProtocolError("timestamp must include a UTC offset")
    return parsed.isoformat()


def _bounded_text(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise PairedXbenProtocolError(f"{label} must be non-empty and bounded")
    return value.strip()


def _bounded_ascii_text(value: object, label: str, *, maximum: int) -> str:
    text = _bounded_text(value, label, maximum=maximum)
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PairedXbenProtocolError(f"{label} must contain only ASCII") from exc
    return text


def _require_public_https_url(value: str, label: str) -> None:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise PairedXbenProtocolError(f"{label} must be an external HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not host
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or host == "localhost"
        or host.endswith(".local")
        or parsed.query
        or parsed.fragment
    ):
        raise PairedXbenProtocolError(f"{label} must be an external HTTPS URL")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise PairedXbenProtocolError(f"{label} must be an external HTTPS URL")


def _rank_key(domain: bytes, draw_key: bytes, case_id: str) -> str:
    return hashlib.sha256(domain + b"\0" + draw_key + b"\0" + case_id.encode()).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(canonical_json(value).encode())


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _create_private_directory(path: Path) -> None:
    target = Path(path).expanduser()
    try:
        target.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError as exc:
        raise PairedXbenProtocolError(f"refusing to reuse protocol directory: {target}") from exc
    if target.is_symlink():
        raise PairedXbenProtocolError("protocol directory cannot be a symlink")


def _ensure_child_directory(parent: Path, name: str) -> Path:
    """Create or validate one fixed-name child without following a planted symlink."""

    root = _existing_directory(parent, "protocol directory parent")
    target = root / name
    try:
        target.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise PairedXbenProtocolError(f"cannot create protocol directory: {target}") from exc
    return _existing_directory(target, "protocol directory")


def _create_exclusive_child_directory(parent: Path, name: str) -> Path:
    """Create one direct child exactly once after validating its real parent."""

    root = _existing_directory(parent, "protocol directory parent")
    target = root / name
    try:
        target.mkdir(mode=0o700)
    except OSError as exc:
        raise PairedXbenProtocolError(f"refusing to reuse protocol directory: {target}") from exc
    return _existing_directory(target, "protocol directory")


def _existing_directory(path: Path, label: str) -> Path:
    target = Path(path).expanduser()
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise PairedXbenProtocolError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PairedXbenProtocolError(f"{label} must be a real directory")
    return target


def _regular_file(path: Path, label: str) -> Path:
    target = Path(path).expanduser()
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise PairedXbenProtocolError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PairedXbenProtocolError(f"{label} must be a regular file")
    return target


def _read_bounded_bytes(path: Path, label: str) -> bytes:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise PairedXbenProtocolError(f"{label} exceeds the byte limit")
        content = path.read_bytes()
    except OSError as exc:
        raise PairedXbenProtocolError(f"cannot read {label}") from exc
    if len(content) > MAX_JSON_BYTES:
        raise PairedXbenProtocolError(f"{label} exceeds the byte limit")
    return content


def _write_json_exclusive(path: Path, payload: object) -> None:
    _write_bytes_exclusive(path, (canonical_json(payload) + "\n").encode())


def _write_bytes_exclusive(path: Path, content: bytes) -> None:
    target = Path(path)
    if len(content) > MAX_JSON_BYTES:
        raise PairedXbenProtocolError("protocol artifact exceeds the byte limit")
    parent = _existing_directory(target.parent, "protocol artifact parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(parent / target.name, flags, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("protocol artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise PairedXbenProtocolError(f"refusing to overwrite protocol artifact: {target}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


__all__ = [
    "ATTEMPT_SCHEMA",
    "BEACON_SCHEMA",
    "COMMITMENT_SCHEMA",
    "PRIMARY_MATRIX_SCHEMA",
    "PairedXbenProtocolError",
    "PROTOCOL_ID",
    "RUN_CONTRACT_SCHEMA",
    "SAMPLE_SIZE",
    "SELECTION_SCHEMA",
    "SYSTEMS",
    "canonical_json",
    "create_commitment",
    "create_primary_attempt_manifest",
    "create_rerun_attempt_manifest",
    "eligible_pool_digest",
    "load_eligible_pool",
    "load_run_contract",
    "resolve_commitment",
    "reserve_primary_matrix",
    "validate_run_contract",
    "verify_campaign",
]
