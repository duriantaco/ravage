"""Fresh, evaluator-owned Docker targets for paired XBEN comparisons.

The comparison target is deliberately stricter than the interactive XBEN runner:

* source is exported from one exact, clean Git commit into a private directory;
* an optional compatibility patch is accepted only with a pinned SHA-256;
* the copied Compose model is rewritten onto one unique internal network, with no
  published ports and no host-level container privileges;
* readiness is measured by a digest-pinned probe container;
* the agent receives only a digest-pinned evaluator gateway URL; and
* teardown is not successful until Docker reports no remaining project resources.

No claim rests on a gateway implementation saying that it is safe.  This module
creates the gateway itself and derives the relevant facts from Docker inspection.
If the required gateway or probe identity is absent, startup fails closed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import io
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol
from urllib.parse import urlsplit

import yaml  # type: ignore[import-untyped]

from ravage.xben_parts.cases import _load_xben_case
from ravage.xben_parts.comparison_contracts import ExternalTarget
from ravage.xben_parts.http_meter_gateway import (
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    HTTP_METER_PROTOCOL,
    HTTP_METER_SCHEMA_VERSION,
    MAX_BUFFERED_BODY_BYTES,
    MAX_CONCURRENT_REQUESTS,
    MAX_RECEIPT_BYTES,
    program_sha256,
    validate_receipt_payload,
)
from ravage.xben_parts.models import XbenCase

_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_SHA256_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
_RAW_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_IMAGE_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_EXPECTED_FLAG_RE = re.compile(r"flag\{ravage_cmp_[0-9a-f]{64}\}")
_CASE_ID_RE = re.compile(r"XBEN-[0-9]{3}-[0-9]{2}")
_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 20_000
_MAX_COMPATIBILITY_PATCH_BYTES = 16 * 1024 * 1024
_MAX_COMPATIBILITY_CATALOG_BYTES = 1024 * 1024
_COMPATIBILITY_CATALOG_SCHEMA_VERSION = "ravage.paired-xben.compatibility-catalog.v1"
_COMPATIBILITY_CATALOG_ORIGIN = "https://github.com/xbow-engineering/validation-benchmarks.git"
_COMPATIBILITY_CATALOG_CASE_PATTERN = "XBEN-001-24..XBEN-104-24"
_COMPATIBILITY_CATALOG_CASE_IDS = frozenset(f"XBEN-{number:03d}-24" for number in range(1, 105))
_COMPATIBILITY_CATALOG_PURPOSE = (
    "Restore package-index availability for archived Debian releases without changing "
    "challenge application logic, services, credentials, vulnerabilities, or flags."
)
_MAX_EVIDENCE_STREAM_BYTES = 64 * 1024
_MAX_GATEWAY_LOG_BYTES = 64 * 1024
_MAX_RETAINED_DOCUMENT_BYTES = 32 * 1024 * 1024
_GATEWAY_RUNTIME_DIR = "/run/ravage-http-meter"
_GATEWAY_CONFIG_PATH = f"{_GATEWAY_RUNTIME_DIR}/listen.json"
_GATEWAY_RECEIPT_PATH = f"{_GATEWAY_RUNTIME_DIR}/receipt.json"
_GATEWAY_MODULE = "ravage.xben_parts.http_meter_gateway"
_GATEWAY_DOCKER_ALIAS = "ravage-target"
_GATEWAY_UID_GID = "65532:65532"
REQUEST_METER_STOP_SCHEMA_VERSION = "ravage.xben.request-meter-stop.v2"
PREPARED_TARGET_SCHEMA_VERSION = "ravage.xben.prepared-target.v1"
PREPARED_TARGET_ARM_SCHEMA_VERSION = "ravage.xben.prepared-target-arm.v1"
PREPARED_TARGET_ARM_ABANDONMENT_SCHEMA_VERSION = "ravage.xben.prepared-target-arm-abandonment.v1"
PREPARED_TARGET_ARM_TERMINAL_STATE_SCHEMA_VERSION = (
    "ravage.xben.prepared-target-arm-terminal-state.v1"
)
_PAIR_FLAG_SCOPE = "one-fresh-256-bit-flag-shared-by-two-adjacent-arms"
_PAIR_FLAG_DISCLOSURE = "withheld_until_both_arms_terminal"
_PREPARED_ARMS = frozenset({"ravage", "strix"})
_PREPARED_ARM_ABANDONMENT_REASONS = frozenset(
    {
        "prelaunch_failure",
        "campaign_cancelled_before_target_start",
    }
)
_PREPARED_TARGET_KEYS = {
    "schema_version",
    "pair_id",
    "benchmark_id",
    "pair_flag_sha256",
    "pair_flag_scope",
    "flag_disclosure",
    "expected_arms",
    "build_once",
    "runtime_build_allowed",
    "runtime_pull_allowed",
    "platform",
    "build_input_boundary",
    "source_path",
    "source_sha256",
    "build_path",
    "build_sha256",
    "prepared_source_tree_sha256",
    "service_images",
    "image_ids_by_service",
    "created_at",
    "verification_kind",
    "cryptographically_attested",
    "valid",
}
_PREPARED_TARGET_ARM_KEYS = {
    "schema_version",
    "comparison_safe",
    "paired_comparison_safe",
    "comparison_safe_scope",
    "fresh",
    "pair_id",
    "benchmark_id",
    "arm",
    "pair_flag_sha256",
    "pair_flag_scope",
    "flag_disclosure",
    "build_once_per_case_pair",
    "build_invocations_this_arm",
    "runtime_build_allowed",
    "runtime_pull_allowed",
    "runtime_build_or_pull_allowed",
    "prepared_provenance_path",
    "prepared_provenance_sha256",
    "prepared_source_tree_sha256",
    "prepared_image_reuse_verified",
    "target_image_ids",
    "target_image_ids_by_service",
    "target_request_counting_verified",
    "max_target_requests",
    "target_request_protocol",
    "gateway_endpoint_mode",
    "backend",
    "platform",
    "project",
    "target_network",
    "target_url",
    "evidence_dir",
    "source_path",
    "source_sha256",
    "build_path",
    "build_sha256",
    "verification_kind",
    "cryptographically_attested",
    "valid",
}
_REQUEST_METER_STOP_KEYS = {
    "schema_version",
    "receipt_schema_version",
    "protocol",
    "meter_program_sha256",
    "instance_id",
    "endpoint_mode",
    "access_boundary",
    "caller_authentication",
    "trusted_host_no_concurrent_local_adversary",
    "sealed",
    "http_only",
    "https_connect_supported",
    "websocket_upgrade_supported",
    "chunked_request_body_supported",
    "max_request_body_bytes",
    "max_response_body_bytes",
    "max_concurrent_requests",
    "observed_count",
    "accepted_count",
    "target_request_attempt_count",
    "unsupported_count",
    "rejected_over_limit_count",
    "upstream_error_count",
    "oversize_response_count",
    "hard_limit",
    "limit_enforced",
    "complete",
    "receipt_path",
    "receipt_sha256",
    "verification_kind",
    "cryptographically_attested",
    "valid",
}

GatewayEndpointMode = Literal[
    "host_loopback",
    "docker_alias",
    "cross_daemon_host_gateway",
]
_GATEWAY_LABEL = "com.ravage.evaluator.gateway"
_INSTANCE_LABEL = "com.ravage.evaluator.instance"
_AGENT_NETWORK_LABEL = "com.ravage.evaluator.agent-network"


class ComparisonTargetError(RuntimeError):
    """Base class for comparison target contract failures."""


class SourceMaterializationError(ComparisonTargetError):
    """Raised when pinned source cannot be materialized exactly and privately."""


class UnsafeComposeError(ComparisonTargetError):
    """Raised when a Compose model cannot be made comparison-safe."""


class GatewayUnavailableError(ComparisonTargetError):
    """Raised when the evaluator-owned gateway boundary is unavailable."""


class DockerEvidenceError(ComparisonTargetError):
    """Raised when Docker inspection cannot prove the required boundary."""


class TeardownVerificationError(ComparisonTargetError):
    """Raised when target resources remain after teardown."""


def validate_request_meter_stop_provenance(
    payload: object,
    *,
    evidence_dir: Path,
) -> dict[str, object]:
    """Validate a terminal request meter and its retained create-only receipt."""

    if not isinstance(payload, dict) or set(payload) != _REQUEST_METER_STOP_KEYS:
        raise DockerEvidenceError("request meter stop provenance has an invalid field set")
    expected_literals = {
        "schema_version": REQUEST_METER_STOP_SCHEMA_VERSION,
        "receipt_schema_version": HTTP_METER_SCHEMA_VERSION,
        "protocol": HTTP_METER_PROTOCOL,
        "http_only": True,
        "https_connect_supported": False,
        "websocket_upgrade_supported": False,
        "chunked_request_body_supported": False,
        "limit_enforced": True,
        "complete": True,
        "verification_kind": "operational-docker-inspection-and-meter-receipt",
        "cryptographically_attested": False,
        "valid": True,
    }
    for name, expected in expected_literals.items():
        if payload.get(name) != expected:
            raise DockerEvidenceError(f"request meter stop field {name!r} is invalid")
    if payload.get("endpoint_mode") not in {
        "host_loopback",
        "docker_alias",
        "cross_daemon_host_gateway",
    }:
        raise DockerEvidenceError("request meter stop endpoint mode is invalid")
    endpoint_mode = payload["endpoint_mode"]
    expected_access_boundary = {
        "host_loopback": "trusted-host-loopback",
        "docker_alias": "evaluator-owned-docker-network",
        "cross_daemon_host_gateway": "root-owned-cross-daemon-loopback",
    }[endpoint_mode]
    if (
        payload.get("access_boundary") != expected_access_boundary
        or payload.get("caller_authentication") != "none"
        or payload.get("trusted_host_no_concurrent_local_adversary")
        is not (endpoint_mode == "host_loopback")
        or payload.get("sealed") is not True
    ):
        raise DockerEvidenceError("request meter stop access-boundary declaration is invalid")
    instance_id = payload.get("instance_id")
    if not isinstance(instance_id, str) or _SAFE_NAME_RE.fullmatch(instance_id) is None:
        raise DockerEvidenceError("request meter stop instance ID is invalid")
    for name in ("meter_program_sha256", "receipt_sha256"):
        value = payload.get(name)
        if not isinstance(value, str) or _RAW_SHA256_RE.fullmatch(value) is None:
            raise DockerEvidenceError(f"request meter stop field {name!r} is invalid")
    integer_names = (
        "max_request_body_bytes",
        "max_response_body_bytes",
        "max_concurrent_requests",
        "observed_count",
        "accepted_count",
        "target_request_attempt_count",
        "unsupported_count",
        "rejected_over_limit_count",
        "upstream_error_count",
        "oversize_response_count",
        "hard_limit",
    )
    integers: dict[str, int] = {}
    for name in integer_names:
        value = payload.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DockerEvidenceError(f"request meter stop field {name!r} is invalid")
        integers[name] = value
    if integers["hard_limit"] <= 0:
        raise DockerEvidenceError("request meter stop hard limit is invalid")
    for name in ("max_request_body_bytes", "max_response_body_bytes"):
        if not 0 < integers[name] <= MAX_BUFFERED_BODY_BYTES:
            raise DockerEvidenceError(f"request meter stop field {name!r} is out of bounds")
    if integers["max_concurrent_requests"] != MAX_CONCURRENT_REQUESTS:
        raise DockerEvidenceError("request meter stop concurrency limit is invalid")
    if integers["observed_count"] != (
        integers["accepted_count"]
        + integers["unsupported_count"]
        + integers["rejected_over_limit_count"]
    ):
        raise DockerEvidenceError("request meter stop counts do not balance")
    if integers["accepted_count"] > integers["hard_limit"]:
        raise DockerEvidenceError("request meter stop accepted count exceeds its hard limit")
    if integers["rejected_over_limit_count"] != max(
        0,
        integers["observed_count"] - integers["hard_limit"],
    ):
        raise DockerEvidenceError("request meter stop rejection count is inconsistent")
    if integers["target_request_attempt_count"] > integers["accepted_count"]:
        raise DockerEvidenceError("request meter stop target attempt count is inconsistent")
    if integers["upstream_error_count"] > integers["accepted_count"]:
        raise DockerEvidenceError("request meter stop upstream error count is inconsistent")
    if integers["oversize_response_count"] > min(
        integers["upstream_error_count"],
        integers["target_request_attempt_count"],
    ):
        raise DockerEvidenceError("request meter stop oversize response count is inconsistent")

    raw_path = payload.get("receipt_path")
    if not isinstance(raw_path, str) or not raw_path:
        raise DockerEvidenceError("request meter stop receipt path is invalid")
    receipt_path = Path(raw_path)
    if receipt_path.is_symlink():
        raise DockerEvidenceError("request meter stop receipt must not be a symlink")
    try:
        resolved_receipt = receipt_path.resolve(strict=True)
    except OSError as exc:
        raise DockerEvidenceError("request meter stop receipt is unavailable") from exc
    if resolved_receipt.parent != evidence_dir.resolve() or resolved_receipt.name != (
        "request-count.json"
    ):
        raise DockerEvidenceError("request meter stop receipt escaped its evidence directory")
    receipt_bytes = resolved_receipt.read_bytes()
    if len(receipt_bytes) > _MAX_EVIDENCE_STREAM_BYTES:
        raise DockerEvidenceError("request meter stop receipt exceeds its retained size limit")
    if hashlib.sha256(receipt_bytes).hexdigest() != payload["receipt_sha256"]:
        raise DockerEvidenceError("request meter stop receipt SHA-256 is invalid")
    try:
        wrapper = json.loads(receipt_bytes)
    except json.JSONDecodeError as exc:
        raise DockerEvidenceError("request meter stop receipt JSON is malformed") from exc
    if not isinstance(wrapper, dict) or set(wrapper) != {
        "status",
        "receipt",
        "enforcement",
        "http_only",
        "terminal_admission_closed",
    }:
        raise DockerEvidenceError("request meter stop receipt wrapper is invalid")
    if (
        wrapper.get("status") != "verified"
        or wrapper.get("enforcement") != "hard inbound HTTP request allowance"
        or wrapper.get("http_only") is not True
        or wrapper.get("terminal_admission_closed") is not True
    ):
        raise DockerEvidenceError("request meter stop receipt wrapper is not verified")
    try:
        receipt = validate_receipt_payload(wrapper.get("receipt"))
    except ValueError as exc:
        raise DockerEvidenceError("request meter stop receipt payload is invalid") from exc
    expected_receipt_values = {
        "schema_version": payload["receipt_schema_version"],
        "program_sha256": payload["meter_program_sha256"],
        "protocol": payload["protocol"],
        "instance_id": payload["instance_id"],
        "sealed": True,
        "access_boundary": payload["access_boundary"],
        "caller_authentication": payload["caller_authentication"],
        "trusted_host_no_concurrent_local_adversary": payload[
            "trusted_host_no_concurrent_local_adversary"
        ],
        "max_target_requests": integers["hard_limit"],
        "max_request_body_bytes": integers["max_request_body_bytes"],
        "max_response_body_bytes": integers["max_response_body_bytes"],
        "max_concurrent_requests": integers["max_concurrent_requests"],
        "observed_requests": integers["observed_count"],
        "accepted_requests": integers["accepted_count"],
        "target_request_attempts": integers["target_request_attempt_count"],
        "unsupported_requests": integers["unsupported_count"],
        "rejected_over_limit": integers["rejected_over_limit_count"],
        "upstream_errors": integers["upstream_error_count"],
        "oversize_responses": integers["oversize_response_count"],
        "in_flight_requests": 0,
    }
    for name, expected in expected_receipt_values.items():
        if receipt.get(name) != expected:
            raise DockerEvidenceError(
                f"request meter stop receipt field {name!r} does not match provenance"
            )
    return dict(payload)


def validate_prepared_target_provenance(
    payload: object,
    *,
    evidence_dir: Path,
) -> dict[str, object]:
    """Validate a build-once pair target against its retained source/build closure."""

    if not isinstance(payload, dict) or set(payload) != _PREPARED_TARGET_KEYS:
        raise DockerEvidenceError("prepared target provenance has an invalid field set")
    expected_literals = {
        "schema_version": PREPARED_TARGET_SCHEMA_VERSION,
        "pair_flag_scope": _PAIR_FLAG_SCOPE,
        "flag_disclosure": _PAIR_FLAG_DISCLOSURE,
        "expected_arms": ["ravage", "strix"],
        "build_once": True,
        "runtime_build_allowed": False,
        "runtime_pull_allowed": False,
        "platform": "linux/amd64",
        "source_path": "source.json",
        "build_path": "build.json",
        "verification_kind": "operational-build-and-local-docker-image-inspection",
        "cryptographically_attested": False,
        "valid": True,
    }
    for name, expected in expected_literals.items():
        if payload.get(name) != expected:
            raise DockerEvidenceError(f"prepared target field {name!r} is invalid")
    if payload.get("build_input_boundary") != {
        "pinned_source_and_compatibility_catalog": True,
        "explicit_privileged_or_remote_compose_build_features_forbidden": True,
        "preparation_registry_and_default_build_network_available": True,
        "external_base_references_may_be_mutable": True,
        "post_resolution_local_image_ids_frozen": True,
        "hermetic_rebuild_claimed": False,
    }:
        raise DockerEvidenceError("prepared target build-input boundary is invalid")
    pair_id = payload.get("pair_id")
    benchmark_id = payload.get("benchmark_id")
    if not isinstance(pair_id, str) or _SAFE_NAME_RE.fullmatch(pair_id) is None:
        raise DockerEvidenceError("prepared target pair ID is invalid")
    if not isinstance(benchmark_id, str) or benchmark_id not in _COMPATIBILITY_CATALOG_CASE_IDS:
        raise DockerEvidenceError("prepared target benchmark ID is invalid")
    for name in (
        "pair_flag_sha256",
        "source_sha256",
        "build_sha256",
        "prepared_source_tree_sha256",
    ):
        value = payload.get(name)
        if not isinstance(value, str) or _RAW_SHA256_RE.fullmatch(value) is None:
            raise DockerEvidenceError(f"prepared target field {name!r} is invalid")
    try:
        created_at = datetime.fromisoformat(str(payload.get("created_at") or ""))
    except ValueError as exc:
        raise DockerEvidenceError("prepared target timestamp is invalid") from exc
    if created_at.tzinfo is None:
        raise DockerEvidenceError("prepared target timestamp lacks a timezone")

    raw_images = payload.get("service_images")
    raw_image_map = payload.get("image_ids_by_service")
    if not isinstance(raw_images, list) or not raw_images or not isinstance(raw_image_map, dict):
        raise DockerEvidenceError("prepared target service image set is invalid")
    normalized_map: dict[str, str] = {}
    seen_services: set[str] = set()
    image_keys = {
        "service",
        "source_reference",
        "image_id",
        "repo_digests",
        "created",
        "architecture",
        "os",
        "size",
        "rootfs_layers",
        "owned_prepared_tag",
    }
    for raw_image in raw_images:
        if not isinstance(raw_image, dict) or set(raw_image) != image_keys:
            raise DockerEvidenceError("prepared target service image record is invalid")
        service = raw_image.get("service")
        image_id = raw_image.get("image_id")
        source_reference = raw_image.get("source_reference")
        repo_digests = raw_image.get("repo_digests")
        rootfs_layers = raw_image.get("rootfs_layers")
        size = raw_image.get("size")
        if (
            not isinstance(service, str)
            or _SAFE_NAME_RE.fullmatch(service) is None
            or service in seen_services
            or not isinstance(image_id, str)
            or _SHA256_RE.fullmatch(image_id) is None
            or image_id != _normalized_sha256(image_id)
            or not isinstance(source_reference, str)
            or not source_reference
            or type(raw_image.get("owned_prepared_tag")) is not bool
            or not isinstance(repo_digests, list)
            or any(
                not isinstance(digest, str) or _IMAGE_DIGEST_RE.fullmatch(digest) is None
                for digest in repo_digests
            )
            or not isinstance(rootfs_layers, list)
            or any(
                not isinstance(layer, str)
                or _SHA256_RE.fullmatch(layer) is None
                or layer != _normalized_sha256(layer)
                for layer in rootfs_layers
            )
            or not isinstance(raw_image.get("created"), str)
            or not raw_image.get("created")
            or raw_image.get("architecture") != "amd64"
            or raw_image.get("os") != "linux"
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise DockerEvidenceError("prepared target service image identity is invalid")
        seen_services.add(service)
        normalized_map[service] = image_id
    if raw_image_map != normalized_map:
        raise DockerEvidenceError("prepared target image map does not match its records")

    evidence_root = evidence_dir.expanduser().resolve(strict=True)
    for label in ("source", "build"):
        path = evidence_root / f"{label}.json"
        if path.is_symlink() or not path.is_file():
            raise DockerEvidenceError(f"prepared target {label} evidence is unavailable")
        raw = path.read_bytes()
        if len(raw) > _MAX_RETAINED_DOCUMENT_BYTES:
            raise DockerEvidenceError(f"prepared target {label} evidence exceeds its size limit")
        if hashlib.sha256(raw).hexdigest() != payload[f"{label}_sha256"]:
            raise DockerEvidenceError(f"prepared target {label} evidence digest is invalid")
        if _EXPECTED_FLAG_RE.search(raw.decode("utf-8", errors="replace")) is not None:
            raise DockerEvidenceError(f"prepared target {label} evidence leaks the pair flag")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DockerEvidenceError(f"prepared target {label} evidence is malformed") from exc
        if label == "source":
            if not isinstance(document, dict) or (
                _mapping(document.get("prepared_pristine_tree")).get("sha256")
                != payload["prepared_source_tree_sha256"]
            ):
                raise DockerEvidenceError("prepared target source closure is inconsistent")
        elif (
            not isinstance(document, dict)
            or document.get("service_images") != raw_images
            or document.get("build_input_boundary") != payload["build_input_boundary"]
            or document.get("source_sha256") != payload["source_sha256"]
            or document.get("build_invocations") != 1
        ):
            raise DockerEvidenceError("prepared target build closure is inconsistent")
    return dict(payload)


def validate_prepared_target_arm_provenance(
    payload: object,
    *,
    evidence_dir: Path,
) -> dict[str, object]:
    """Validate one arm's public build receipt against its build-once pair closure."""

    if not isinstance(payload, dict) or set(payload) != _PREPARED_TARGET_ARM_KEYS:
        raise DockerEvidenceError("prepared target arm provenance has an invalid field set")
    expected_literals = {
        "schema_version": PREPARED_TARGET_ARM_SCHEMA_VERSION,
        "comparison_safe": True,
        "paired_comparison_safe": True,
        "comparison_safe_scope": "fresh target and gateway isolation boundary",
        "fresh": True,
        "pair_flag_scope": _PAIR_FLAG_SCOPE,
        "flag_disclosure": _PAIR_FLAG_DISCLOSURE,
        "build_once_per_case_pair": True,
        "build_invocations_this_arm": 0,
        "runtime_build_allowed": False,
        "runtime_pull_allowed": False,
        "runtime_build_or_pull_allowed": False,
        "prepared_image_reuse_verified": True,
        "target_request_counting_verified": True,
        "target_request_protocol": HTTP_METER_PROTOCOL,
        "backend": "docker-pinned-git-http-meter-gateway-v3",
        "platform": "linux/amd64",
        "source_path": "source.json",
        "build_path": "build.json",
        "verification_kind": "operational-docker-inspection-and-prepared-image-closure",
        "cryptographically_attested": False,
        "valid": True,
    }
    for name, expected in expected_literals.items():
        if payload.get(name) != expected:
            raise DockerEvidenceError(f"prepared target arm field {name!r} is invalid")
    if payload.get("arm") not in _PREPARED_ARMS:
        raise DockerEvidenceError("prepared target arm identity is invalid")
    if payload.get("gateway_endpoint_mode") not in {
        "host_loopback",
        "docker_alias",
        "cross_daemon_host_gateway",
    }:
        raise DockerEvidenceError("prepared target arm endpoint mode is invalid")
    raw_target_url = payload.get("target_url")
    if not isinstance(raw_target_url, str):
        raise DockerEvidenceError("prepared target arm URL is invalid")
    try:
        parsed_target_url = urlsplit(raw_target_url)
        target_port = parsed_target_url.port
    except ValueError as exc:
        raise DockerEvidenceError("prepared target arm URL is invalid") from exc
    endpoint_mode = payload["gateway_endpoint_mode"]
    expected_target_host = (
        "127.0.0.1"
        if endpoint_mode == "host_loopback"
        else _GATEWAY_DOCKER_ALIAS
        if endpoint_mode == "docker_alias"
        else parsed_target_url.hostname
    )
    cross_daemon_host_valid = True
    if endpoint_mode == "cross_daemon_host_gateway":
        try:
            cross_daemon_host = ipaddress.ip_address(str(parsed_target_url.hostname or ""))
        except ValueError:
            cross_daemon_host_valid = False
        else:
            cross_daemon_host_valid = bool(
                cross_daemon_host.version == 4
                and not cross_daemon_host.is_unspecified
                and not cross_daemon_host.is_loopback
                and not cross_daemon_host.is_multicast
                and not cross_daemon_host.is_link_local
            )
    valid_target_port = bool(
        target_port is not None
        and (
            49_152 <= target_port <= 65_535
            if payload["gateway_endpoint_mode"] in {"host_loopback", "cross_daemon_host_gateway"}
            else 1_024 <= target_port <= 65_535
        )
    )
    if (
        parsed_target_url.scheme != "http"
        or parsed_target_url.hostname != expected_target_host
        or not cross_daemon_host_valid
        or not valid_target_port
        or parsed_target_url.username is not None
        or parsed_target_url.password is not None
        or parsed_target_url.path not in {"", "/"}
        or parsed_target_url.query
        or parsed_target_url.fragment
    ):
        raise DockerEvidenceError("prepared target arm URL does not match its endpoint mode")
    for name in ("pair_id", "project", "target_network"):
        value = payload.get(name)
        if not isinstance(value, str) or _SAFE_NAME_RE.fullmatch(value) is None:
            raise DockerEvidenceError(f"prepared target arm field {name!r} is invalid")
    benchmark_id = payload.get("benchmark_id")
    if not isinstance(benchmark_id, str) or benchmark_id not in _COMPATIBILITY_CATALOG_CASE_IDS:
        raise DockerEvidenceError("prepared target arm benchmark ID is invalid")
    for name in (
        "pair_flag_sha256",
        "prepared_provenance_sha256",
        "prepared_source_tree_sha256",
        "source_sha256",
        "build_sha256",
    ):
        value = payload.get(name)
        if not isinstance(value, str) or _RAW_SHA256_RE.fullmatch(value) is None:
            raise DockerEvidenceError(f"prepared target arm field {name!r} is invalid")
    max_target_requests = payload.get("max_target_requests")
    if (
        isinstance(max_target_requests, bool)
        or not isinstance(max_target_requests, int)
        or max_target_requests <= 0
    ):
        raise DockerEvidenceError("prepared target arm request limit is invalid")

    raw_image_map = payload.get("target_image_ids_by_service")
    raw_image_ids = payload.get("target_image_ids")
    if (
        not isinstance(raw_image_map, dict)
        or not raw_image_map
        or not isinstance(raw_image_ids, list)
    ):
        raise DockerEvidenceError("prepared target arm image identity set is invalid")
    image_map: dict[str, str] = {}
    for raw_service, raw_image_id in raw_image_map.items():
        if (
            not isinstance(raw_service, str)
            or _SAFE_NAME_RE.fullmatch(raw_service) is None
            or not isinstance(raw_image_id, str)
            or _SHA256_RE.fullmatch(raw_image_id) is None
            or raw_image_id != _normalized_sha256(raw_image_id)
        ):
            raise DockerEvidenceError("prepared target arm image identity is invalid")
        image_map[raw_service] = raw_image_id
    if raw_image_ids != sorted(set(image_map.values())):
        raise DockerEvidenceError("prepared target arm image list does not match its service map")

    try:
        arm_root = evidence_dir.expanduser().resolve(strict=True)
    except OSError as exc:
        raise DockerEvidenceError("prepared target arm evidence directory is unavailable") from exc
    if payload.get("evidence_dir") != str(arm_root):
        raise DockerEvidenceError("prepared target arm evidence directory binding is invalid")
    documents: dict[str, Mapping[str, object]] = {}
    for label in ("source", "build"):
        path = arm_root / f"{label}.json"
        if path.is_symlink() or not path.is_file():
            raise DockerEvidenceError(f"prepared target arm {label} evidence is unavailable")
        raw = path.read_bytes()
        if len(raw) > _MAX_RETAINED_DOCUMENT_BYTES:
            raise DockerEvidenceError(
                f"prepared target arm {label} evidence exceeds its retained size limit"
            )
        if hashlib.sha256(raw).hexdigest() != payload[f"{label}_sha256"]:
            raise DockerEvidenceError(f"prepared target arm {label} evidence digest is invalid")
        if _EXPECTED_FLAG_RE.search(raw.decode("utf-8", errors="replace")) is not None:
            raise DockerEvidenceError(f"prepared target arm {label} evidence leaks the pair flag")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DockerEvidenceError(f"prepared target arm {label} evidence is malformed") from exc
        if not isinstance(document, dict):
            raise DockerEvidenceError(f"prepared target arm {label} evidence is malformed")
        documents[label] = document

    pair_id = str(payload["pair_id"])
    expected_prepared_path = arm_root.parent / f"{pair_id}.prepared" / "prepared.json"
    raw_prepared_path = payload.get("prepared_provenance_path")
    if not isinstance(raw_prepared_path, str) or Path(raw_prepared_path) != expected_prepared_path:
        raise DockerEvidenceError("prepared target arm pair provenance path is invalid")
    if expected_prepared_path.is_symlink() or not expected_prepared_path.is_file():
        raise DockerEvidenceError("prepared target arm pair provenance is unavailable")
    prepared_bytes = expected_prepared_path.read_bytes()
    if len(prepared_bytes) > _MAX_RETAINED_DOCUMENT_BYTES:
        raise DockerEvidenceError("prepared target pair provenance exceeds its retained size limit")
    if hashlib.sha256(prepared_bytes).hexdigest() != payload["prepared_provenance_sha256"]:
        raise DockerEvidenceError("prepared target arm pair provenance digest is invalid")
    if _EXPECTED_FLAG_RE.search(prepared_bytes.decode("utf-8", errors="replace")) is not None:
        raise DockerEvidenceError("prepared target pair provenance leaks the pair flag")
    try:
        prepared_document = json.loads(prepared_bytes)
    except json.JSONDecodeError as exc:
        raise DockerEvidenceError("prepared target pair provenance is malformed") from exc
    validated_prepared = validate_prepared_target_provenance(
        prepared_document,
        evidence_dir=expected_prepared_path.parent,
    )
    prepared_expected = {
        "pair_id": payload["pair_id"],
        "benchmark_id": payload["benchmark_id"],
        "pair_flag_sha256": payload["pair_flag_sha256"],
        "pair_flag_scope": payload["pair_flag_scope"],
        "flag_disclosure": payload["flag_disclosure"],
        "prepared_source_tree_sha256": payload["prepared_source_tree_sha256"],
        "image_ids_by_service": image_map,
    }
    for name, expected in prepared_expected.items():
        if validated_prepared.get(name) != expected:
            raise DockerEvidenceError(
                f"prepared target arm pair field {name!r} does not match its provenance"
            )

    source_binding = _mapping(documents["source"].get("prepared_pair_binding"))
    if (
        source_binding.get("schema_version") != PREPARED_TARGET_SCHEMA_VERSION
        or source_binding.get("pair_id") != payload["pair_id"]
        or source_binding.get("prepared_provenance_path") != raw_prepared_path
        or source_binding.get("prepared_provenance_sha256") != payload["prepared_provenance_sha256"]
        or source_binding.get("prepared_source_tree_sha256")
        != payload["prepared_source_tree_sha256"]
        or source_binding.get("private_arm_copy") is not True
    ):
        raise DockerEvidenceError("prepared target arm source binding is inconsistent")

    build_document = documents["build"]
    pair_binding = _mapping(build_document.get("paired_prepared_target"))
    expected_pair_binding = {
        "enabled": True,
        "pair_id": payload["pair_id"],
        "arm": payload["arm"],
        "prepared_provenance_path": raw_prepared_path,
        "prepared_provenance_sha256": payload["prepared_provenance_sha256"],
        "pair_flag_sha256": payload["pair_flag_sha256"],
        "pair_flag_scope": payload["pair_flag_scope"],
        "flag_disclosure": payload["flag_disclosure"],
        "build_invocations_this_arm": 0,
        "runtime_build_allowed": False,
        "runtime_pull_allowed": False,
        "exact_prepared_images_verified": True,
        "image_ids_by_service": image_map,
    }
    if build_document.get("schema_version") != PREPARED_TARGET_ARM_SCHEMA_VERSION:
        raise DockerEvidenceError("prepared target arm build schema is invalid")
    if (
        build_document.get("project") != payload["project"]
        or build_document.get("target_network") != payload["target_network"]
        or build_document.get("paired_comparison_safe") is not True
    ):
        raise DockerEvidenceError("prepared target arm Docker project binding is inconsistent")
    if pair_binding != expected_pair_binding:
        raise DockerEvidenceError("prepared target arm build binding is inconsistent")
    if build_document.get("target_image_ids") != raw_image_ids:
        raise DockerEvidenceError("prepared target arm build image list is inconsistent")
    target_inspection = _mapping(build_document.get("target_inspection"))
    raw_containers = target_inspection.get("containers")
    target_network = _mapping(target_inspection.get("network"))
    if not isinstance(raw_containers, list) or not raw_containers:
        raise DockerEvidenceError("prepared target arm container inspection is unavailable")
    inspected_image_map: dict[str, str] = {}
    for raw_container in raw_containers:
        if not isinstance(raw_container, dict):
            raise DockerEvidenceError("prepared target arm container inspection is malformed")
        service = raw_container.get("service")
        image_id = raw_container.get("image_id")
        if (
            not isinstance(service, str)
            or service in inspected_image_map
            or not isinstance(image_id, str)
            or raw_container.get("running") is not True
            or raw_container.get("networks") != [payload["target_network"]]
            or raw_container.get("published_host_ports") != []
            or raw_container.get("docker_socket_mounted") is not False
        ):
            raise DockerEvidenceError("prepared target arm container boundary is invalid")
        inspected_image_map[service] = image_id
    if inspected_image_map != image_map:
        raise DockerEvidenceError("prepared target arm inspected image IDs drifted")
    if (
        target_network.get("name") != payload["target_network"]
        or target_network.get("internal") is not True
        or not isinstance(target_network.get("id"), str)
        or _SHA256_RE.fullmatch(str(target_network["id"])) is None
    ):
        raise DockerEvidenceError("prepared target arm network inspection is invalid")
    mount_isolation = _mapping(build_document.get("mount_isolation"))
    if (
        mount_isolation.get("gateway_evaluator_source_mounts_absent") is not True
        or mount_isolation.get("gateway_docker_socket_mounts_absent") is not True
        or mount_isolation.get("target_docker_socket_mounts_absent") is not True
        or build_document.get("source_path_exposed_to_agent") is not False
        or mount_isolation.get("verification_kind") != "operational-docker-inspect"
    ):
        raise DockerEvidenceError("prepared target arm mount inspection is invalid")
    gateway = _mapping(build_document.get("gateway"))
    if (
        gateway.get("endpoint_mode") != payload["gateway_endpoint_mode"]
        or gateway.get("protocol") != HTTP_METER_PROTOCOL
        or gateway.get("max_target_requests") != max_target_requests
        or gateway.get("selected_url") != raw_target_url
        or gateway.get("same_meter_and_upstream_contract") is not True
        or gateway.get("http_only") is not True
        or gateway.get("caller_authentication") != "none"
    ):
        raise DockerEvidenceError("prepared target arm gateway binding is inconsistent")
    commands = build_document.get("commands")
    if not isinstance(commands, list):
        raise DockerEvidenceError("prepared target arm command evidence is invalid")
    compose_up_commands: list[Mapping[str, object]] = []
    for command in commands:
        if not isinstance(command, dict):
            raise DockerEvidenceError("prepared target arm command evidence is malformed")
        operation = command.get("operation")
        if operation in {"compose build", "prepare compose build once"}:
            raise DockerEvidenceError("prepared target arm performed a forbidden runtime build")
        if operation == "compose up":
            compose_up_commands.append(command)
    if len(compose_up_commands) != 1:
        raise DockerEvidenceError("prepared target arm compose launch evidence is ambiguous")
    compose_argv = compose_up_commands[0].get("argv")
    if not isinstance(compose_argv, list) or not all(
        isinstance(part, str) for part in compose_argv
    ):
        raise DockerEvidenceError("prepared target arm compose launch command is malformed")
    try:
        pull_index = compose_argv.index("--pull")
    except ValueError as exc:
        raise DockerEvidenceError("prepared target arm launch lacks a no-pull policy") from exc
    if (
        "--no-build" not in compose_argv
        or pull_index + 1 >= len(compose_argv)
        or compose_argv[pull_index + 1] != "never"
        or compose_up_commands[0].get("returncode") != 0
    ):
        raise DockerEvidenceError("prepared target arm launch did not enforce frozen images")
    return dict(payload)


@dataclass(frozen=True)
class CommandResult:
    """Bounded process result used by Git and Docker operations."""

    command: tuple[str, ...]
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    elapsed_seconds: float = 0.0


class CommandRunner(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult: ...


@dataclass(frozen=True)
class BoundedSubprocessRunner:
    """No-shell runner with hard wall-time and captured-output bounds."""

    max_stdout_bytes: int = _MAX_ARCHIVE_BYTES
    max_stderr_bytes: int = 16 * _MAX_EVIDENCE_STREAM_BYTES

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        if timeout_seconds <= 0:
            raise ValueError("command timeout must be positive")
        if self.max_stdout_bytes <= 0 or self.max_stderr_bytes <= 0:
            raise ValueError("command output limits must be positive")
        argv = tuple(str(part) for part in command)
        started = time.monotonic()
        process = subprocess.Popen(  # noqa: S603 - argv is explicit and never uses a shell.
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract.
            process.kill()
            raise RuntimeError("bounded command pipes are unavailable")
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {
            "stdout": self.max_stdout_bytes,
            "stderr": self.max_stderr_bytes,
        }
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = started + timeout_seconds
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(
                        argv,
                        timeout_seconds,
                        output=bytes(captured["stdout"]),
                        stderr=bytes(captured["stderr"]),
                    )
                for key, _events in selector.select(timeout=min(remaining, 0.1)):
                    stream_name = str(key.data)
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured[stream_name].extend(chunk)
                    if len(captured[stream_name]) > limits[stream_name]:
                        raise RuntimeError(
                            f"command {stream_name} exceeded its fixed capture limit"
                        )
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL is terminal.
                process.kill()
                process.wait()
            raise
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
        return CommandResult(
            command=argv,
            returncode=process.returncode,
            stdout=bytes(captured["stdout"]),
            stderr=bytes(captured["stderr"]),
            elapsed_seconds=time.monotonic() - started,
        )


@dataclass(frozen=True)
class CompatibilityPatch:
    """Repository-relative compatibility patch pinned by content digest."""

    path: Path
    sha256: str
    touched_files: tuple[PurePosixPath, ...]

    def normalized_sha256(self) -> str:
        match = _SHA256_RE.fullmatch(self.sha256)
        if match is None:
            raise SourceMaterializationError("compatibility patch SHA-256 is invalid")
        return match.group(1)


@dataclass(frozen=True)
class CompatibilityPatchCatalog:
    """A complete pre-draw compatibility policy pinned by its raw file digest."""

    path: Path
    sha256: str

    def normalized_sha256(self) -> str:
        match = _RAW_SHA256_RE.fullmatch(self.sha256)
        if match is None:
            raise SourceMaterializationError("compatibility catalog SHA-256 is invalid")
        return match.group(0)


@dataclass(frozen=True)
class PinnedXbenSource:
    """Exact source identity for one XBEN checkout."""

    repository: Path
    commit: str
    compatibility_patch_catalog: CompatibilityPatchCatalog
    case_prefix: PurePosixPath = PurePosixPath("benchmarks")


@dataclass(frozen=True)
class _ResolvedCompatibilityPatchCatalog:
    path: Path
    raw_sha256: str
    size_bytes: int
    source: Mapping[str, object]
    coverage: Mapping[str, object]
    policy: Mapping[str, object]
    entries: tuple[Mapping[str, object], ...]
    patches: Mapping[str, CompatibilityPatch]


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SourceMaterializationError("compatibility catalog contains a duplicate key")
        result[key] = value
    return result


def _require_catalog_keys(
    value: object,
    *,
    expected: set[str],
    context: str,
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SourceMaterializationError(f"compatibility catalog {context} fields are invalid")
    return value


def _safe_catalog_relative_path(value: object, *, context: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise SourceMaterializationError(f"compatibility catalog {context} path is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or "." in path.parts
        or ".." in path.parts
        or path.as_posix() != value
    ):
        raise SourceMaterializationError(f"compatibility catalog {context} path is unsafe")
    return path


def _read_compatibility_patch_bytes(configured: CompatibilityPatch) -> bytes:
    candidate = configured.path.expanduser()
    try:
        if candidate.is_symlink():
            raise SourceMaterializationError("compatibility patch cannot be a symlink")
        patch_path = candidate.resolve(strict=True)
        with patch_path.open("rb") as input_file:
            if not stat.S_ISREG(os.fstat(input_file.fileno()).st_mode):
                raise SourceMaterializationError("compatibility patch must be a regular file")
            patch_bytes = input_file.read(_MAX_COMPATIBILITY_PATCH_BYTES + 1)
    except SourceMaterializationError:
        raise
    except OSError as exc:
        raise SourceMaterializationError("compatibility patch is unavailable") from exc
    if len(patch_bytes) > _MAX_COMPATIBILITY_PATCH_BYTES:
        raise SourceMaterializationError("compatibility patch exceeds the size limit")
    actual = hashlib.sha256(patch_bytes).hexdigest()
    if actual != configured.normalized_sha256():
        raise SourceMaterializationError(
            "compatibility patch content does not match pinned SHA-256"
        )
    return patch_bytes


def _resolve_compatibility_patch_catalog(
    configured: CompatibilityPatchCatalog,
    *,
    expected_commit: str,
) -> _ResolvedCompatibilityPatchCatalog:
    candidate = configured.path.expanduser()
    try:
        if candidate.is_symlink():
            raise SourceMaterializationError("compatibility catalog cannot be a symlink")
        catalog_path = candidate.resolve(strict=True)
        with catalog_path.open("rb") as input_file:
            if not stat.S_ISREG(os.fstat(input_file.fileno()).st_mode):
                raise SourceMaterializationError("compatibility catalog must be a regular file")
            raw = input_file.read(_MAX_COMPATIBILITY_CATALOG_BYTES + 1)
    except SourceMaterializationError:
        raise
    except OSError as exc:
        raise SourceMaterializationError("compatibility catalog is unavailable") from exc
    if len(raw) > _MAX_COMPATIBILITY_CATALOG_BYTES:
        raise SourceMaterializationError("compatibility catalog exceeds the size limit")
    actual_catalog_sha = hashlib.sha256(raw).hexdigest()
    if actual_catalog_sha != configured.normalized_sha256():
        raise SourceMaterializationError(
            "compatibility catalog content does not match pinned SHA-256"
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except SourceMaterializationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceMaterializationError("compatibility catalog is not valid JSON") from exc
    root = _require_catalog_keys(
        payload,
        expected={"schema_version", "benchmark", "source", "coverage", "policy", "patches"},
        context="top-level",
    )
    if root["schema_version"] != _COMPATIBILITY_CATALOG_SCHEMA_VERSION:
        raise SourceMaterializationError("compatibility catalog schema is unsupported")
    if root["benchmark"] != "XBEN":
        raise SourceMaterializationError("compatibility catalog benchmark is not XBEN")

    source = _require_catalog_keys(
        root["source"],
        expected={"origin", "commit_sha", "benchmarks_tree_sha"},
        context="source",
    )
    if source["origin"] != _COMPATIBILITY_CATALOG_ORIGIN:
        raise SourceMaterializationError("compatibility catalog source origin is invalid")
    if source["commit_sha"] != expected_commit:
        raise SourceMaterializationError(
            "compatibility catalog source commit does not match the pinned checkout"
        )
    tree_sha = source["benchmarks_tree_sha"]
    if not isinstance(tree_sha, str) or _COMMIT_RE.fullmatch(tree_sha) is None:
        raise SourceMaterializationError("compatibility catalog source tree SHA is invalid")

    coverage = _require_catalog_keys(
        root["coverage"],
        expected={
            "case_id_pattern",
            "case_count",
            "default_action",
            "unlisted_cases_receive_patch",
        },
        context="coverage",
    )
    if (
        coverage["case_id_pattern"] != _COMPATIBILITY_CATALOG_CASE_PATTERN
        or type(coverage["case_count"]) is not int
        or coverage["case_count"] != len(_COMPATIBILITY_CATALOG_CASE_IDS)
        or coverage["default_action"] != "no_patch"
        or coverage["unlisted_cases_receive_patch"] is not False
    ):
        raise SourceMaterializationError(
            "compatibility catalog does not define the complete fail-closed no-patch policy"
        )

    policy = _require_catalog_keys(
        root["policy"],
        expected={
            "purpose",
            "allowed_change_class",
            "semantic_challenge_changes_allowed",
            "selection_time_changes_allowed",
            "post_draw_changes_allowed",
        },
        context="policy",
    )
    if (
        policy["purpose"] != _COMPATIBILITY_CATALOG_PURPOSE
        or policy["allowed_change_class"] != "legacy_debian_apt_mirror_only"
        or policy["semantic_challenge_changes_allowed"] is not False
        or policy["selection_time_changes_allowed"] is not False
        or policy["post_draw_changes_allowed"] is not False
    ):
        raise SourceMaterializationError("compatibility catalog policy is unsafe")

    raw_entries = root["patches"]
    if not isinstance(raw_entries, list) or len(raw_entries) > len(_COMPATIBILITY_CATALOG_CASE_IDS):
        raise SourceMaterializationError("compatibility catalog patch list is invalid")
    catalog_dir = catalog_path.parent.resolve()
    seen_case_ids: set[str] = set()
    seen_patch_paths: set[str] = set()
    patches: dict[str, CompatibilityPatch] = {}
    entries: list[Mapping[str, object]] = []
    for raw_entry in raw_entries:
        entry = _require_catalog_keys(
            raw_entry,
            expected={"case_id", "path", "sha256", "touched_files"},
            context="patch entry",
        )
        case_id = entry["case_id"]
        if not isinstance(case_id, str) or case_id not in _COMPATIBILITY_CATALOG_CASE_IDS:
            raise SourceMaterializationError("compatibility catalog patch case is unknown")
        if case_id in seen_case_ids:
            raise SourceMaterializationError("compatibility catalog patch case is duplicated")
        seen_case_ids.add(case_id)
        relative_patch = _safe_catalog_relative_path(entry["path"], context="patch")
        relative_patch_text = relative_patch.as_posix()
        if relative_patch_text in seen_patch_paths:
            raise SourceMaterializationError("compatibility catalog patch path is duplicated")
        seen_patch_paths.add(relative_patch_text)
        patch_candidate = catalog_dir.joinpath(*relative_patch.parts)
        try:
            if patch_candidate.is_symlink():
                raise SourceMaterializationError("compatibility patch cannot be a symlink")
            patch_path = patch_candidate.resolve(strict=True)
            patch_path.relative_to(catalog_dir)
        except SourceMaterializationError:
            raise
        except (OSError, ValueError) as exc:
            raise SourceMaterializationError("compatibility catalog patch path is unsafe") from exc
        patch_sha = entry["sha256"]
        if not isinstance(patch_sha, str) or _RAW_SHA256_RE.fullmatch(patch_sha) is None:
            raise SourceMaterializationError("compatibility catalog patch SHA-256 is invalid")
        raw_touched_files = entry["touched_files"]
        if not isinstance(raw_touched_files, list) or not raw_touched_files:
            raise SourceMaterializationError("compatibility catalog touched-files list is invalid")
        touched_files: list[PurePosixPath] = []
        seen_touched: set[str] = set()
        expected_case_prefix = PurePosixPath("benchmarks") / case_id
        for raw_touched in raw_touched_files:
            touched = _safe_catalog_relative_path(raw_touched, context="touched-file")
            if touched.parent == PurePosixPath(".") or not touched.is_relative_to(
                expected_case_prefix
            ):
                raise SourceMaterializationError(
                    "compatibility catalog patch touches a different case"
                )
            if touched.name != "Dockerfile":
                raise SourceMaterializationError(
                    "compatibility catalog patch is outside its allowed change class"
                )
            if touched.as_posix() in seen_touched:
                raise SourceMaterializationError("compatibility catalog touched-file is duplicated")
            seen_touched.add(touched.as_posix())
            touched_files.append(touched)
        patch = CompatibilityPatch(
            path=patch_path,
            sha256=patch_sha,
            touched_files=tuple(touched_files),
        )
        # Verify every catalog member before a case is selected for patching.  The
        # selected member is read and hashed again immediately before application.
        _read_compatibility_patch_bytes(patch)
        patches[case_id] = patch
        entries.append(
            {
                "case_id": case_id,
                "path": relative_patch_text,
                "sha256": patch_sha,
                "touched_files": [path.as_posix() for path in touched_files],
            }
        )
    return _ResolvedCompatibilityPatchCatalog(
        path=catalog_path,
        raw_sha256=actual_catalog_sha,
        size_bytes=len(raw),
        source=dict(source),
        coverage=dict(coverage),
        policy=dict(policy),
        entries=tuple(entries),
        patches=patches,
    )


@dataclass(frozen=True)
class MaterializedCase:
    """Private copy and source evidence produced from a pinned Git archive."""

    root: Path
    case_path: Path
    source_evidence: Mapping[str, object]


@dataclass
class PreparedCase:
    """One post-draw build shared by exactly one Ravage and one Strix arm."""

    pair_id: str
    benchmark_id: str
    case: XbenCase
    expected_flag: str = field(repr=False)
    materialized: MaterializedCase
    prepare_compose_path: Path
    pristine_case_manifest: Mapping[str, object]
    service_images: Mapping[str, Mapping[str, object]]
    owned_image_references: tuple[str, ...]
    evidence_dir: Path
    provenance: Mapping[str, object]
    provenance_sha256: str
    started_arms: dict[str, str] = field(default_factory=dict)
    stopped_arms: set[str] = field(default_factory=set)
    abandoned_arms: dict[str, str] = field(default_factory=dict)
    abandonment_receipt_sha256: dict[str, str] = field(default_factory=dict)
    released: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


def _case_metadata_identity(case: XbenCase) -> dict[str, object]:
    """Return every execution-relevant case field other than its copy location."""

    return {
        "benchmark_id": case.benchmark_id,
        "name": case.name,
        "level": case.level,
        "description": case.description,
        "main_service": case.main_service,
        "main_service_port": case.main_service_port,
    }


@dataclass
class PinnedGitCaseMaterializer:
    """Export one case from an exact, clean Git commit without copying worktree state."""

    source: PinnedXbenSource
    private_root: Path
    runner: CommandRunner = field(default_factory=BoundedSubprocessRunner)
    git_timeout_seconds: int = 60

    def materialize(self, *, case: XbenCase, instance_id: str) -> MaterializedCase:
        _validate_instance_id(instance_id)
        commit = self.source.commit
        if _COMMIT_RE.fullmatch(commit) is None:
            raise SourceMaterializationError("source commit must be an exact lowercase 40-hex SHA")
        if _CASE_ID_RE.fullmatch(case.benchmark_id) is None:
            raise SourceMaterializationError("case benchmark ID is invalid")
        if (
            self.source.case_prefix.is_absolute()
            or not self.source.case_prefix.parts
            or ".." in self.source.case_prefix.parts
        ):
            raise SourceMaterializationError("source case prefix must be a safe relative path")
        if self.source.case_prefix != PurePosixPath("benchmarks"):
            raise SourceMaterializationError(
                "the frozen compatibility catalog only supports the XBEN benchmarks tree"
            )
        catalog = _resolve_compatibility_patch_catalog(
            self.source.compatibility_patch_catalog,
            expected_commit=commit,
        )
        repository = self.source.repository.expanduser().resolve(strict=True)
        if not repository.is_dir():
            raise SourceMaterializationError("source repository is not a directory")
        expected_case_relative = self.source.case_prefix / case.benchmark_id
        checkout_case = repository.joinpath(*expected_case_relative.parts).resolve()
        if case.path.expanduser().resolve() != checkout_case:
            raise SourceMaterializationError(
                "case path is not the selected case inside the pinned source repository"
            )

        env = _minimal_command_environment()
        head = self._git(repository, ("rev-parse", "HEAD"), env=env).strip()
        if head != commit:
            raise SourceMaterializationError(
                f"source checkout HEAD {head!r} does not match pinned commit {commit!r}"
            )
        commit_object = self._git(
            repository,
            ("rev-parse", f"{commit}^{{commit}}"),
            env=env,
        ).strip()
        if commit_object != commit:
            raise SourceMaterializationError("pinned source does not resolve to the exact commit")
        status = self._git(
            repository,
            ("status", "--porcelain=v1", "--untracked-files=all"),
            env=env,
        )
        if status:
            raise SourceMaterializationError(
                "source checkout is dirty; refusing comparison materialization"
            )
        self._verify_catalog_source(repository=repository, catalog=catalog, env=env)

        archive_result = self.runner.run(
            (
                "git",
                "-C",
                str(repository),
                "archive",
                "--format=tar",
                commit,
                str(expected_case_relative),
            ),
            cwd=repository,
            environment=env,
            timeout_seconds=self.git_timeout_seconds,
        )
        _require_success(
            archive_result, operation="git archive", error_type=SourceMaterializationError
        )
        if len(archive_result.stdout) > _MAX_ARCHIVE_BYTES:
            raise SourceMaterializationError("case archive exceeds the materialization size limit")

        root = _claim_private_instance_dir(self.private_root, instance_id)
        try:
            _extract_safe_git_archive(archive_result.stdout, root=root)
            materialized_case = root.joinpath(*expected_case_relative.parts)
            if not materialized_case.is_dir():
                raise SourceMaterializationError("case path is absent from the pinned archive")
            try:
                archived_case = _load_xben_case(materialized_case)
            except Exception as exc:  # noqa: BLE001 - normalize metadata parser failures.
                raise SourceMaterializationError(
                    "case metadata in the pinned archive is invalid"
                ) from exc
            if _case_metadata_identity(archived_case) != _case_metadata_identity(case):
                raise SourceMaterializationError(
                    "runtime case metadata differs from the pinned archive"
                )
            archived_manifest = _tree_manifest(materialized_case)
            selected_patch = catalog.patches.get(case.benchmark_id)
            patch_evidence = self._apply_patch(
                root=root,
                case_path=materialized_case,
                case_id=case.benchmark_id,
                configured=selected_patch,
                env=env,
            )
            post_patch_manifest = _tree_manifest(materialized_case)
            _verify_compatibility_patch_delta(
                before=archived_manifest,
                after=post_patch_manifest,
                configured=selected_patch,
                case_prefix=self.source.case_prefix / case.benchmark_id,
            )
            final_head = self._git(repository, ("rev-parse", "HEAD"), env=env).strip()
            final_status = self._git(
                repository,
                ("status", "--porcelain=v1", "--untracked-files=all"),
                env=env,
            )
            if final_head != commit or final_status:
                raise SourceMaterializationError("source checkout changed during materialization")
            evidence: dict[str, object] = {
                "mode": "clean-pinned-git-archive",
                "repository": str(repository),
                "commit": commit,
                "case_relative_path": expected_case_relative.as_posix(),
                "archive_sha256": hashlib.sha256(archive_result.stdout).hexdigest(),
                "archive_size_bytes": len(archive_result.stdout),
                "checkout_clean_before_and_after": True,
                "archived_tree": archived_manifest,
                "compatibility_patch_catalog": {
                    "schema_version": _COMPATIBILITY_CATALOG_SCHEMA_VERSION,
                    "catalog_sha256": catalog.raw_sha256,
                    "catalog_size_bytes": catalog.size_bytes,
                    "source": dict(catalog.source),
                    "coverage": dict(catalog.coverage),
                    "policy": dict(catalog.policy),
                    "patch_count": len(catalog.entries),
                    "patches": [dict(entry) for entry in catalog.entries],
                    "all_patch_file_digests_verified": True,
                    "source_tree_verified": True,
                    "complete_case_set_verified": True,
                    "selected_case_id": case.benchmark_id,
                    "selected_action": "apply_patch" if selected_patch is not None else "no_patch",
                    "selected_patch_sha256": selected_patch.normalized_sha256()
                    if selected_patch is not None
                    else None,
                },
                "compatibility_patch": patch_evidence,
                "post_patch_tree": post_patch_manifest,
            }
            return MaterializedCase(
                root=root, case_path=materialized_case, source_evidence=evidence
            )
        except Exception:
            _remove_private_instance(root=root, private_root=self.private_root)
            raise

    def _git(self, repository: Path, args: Sequence[str], *, env: Mapping[str, str]) -> str:
        result = self.runner.run(
            ("git", "-C", str(repository), *args),
            cwd=repository,
            environment=env,
            timeout_seconds=self.git_timeout_seconds,
        )
        _require_success(result, operation=f"git {args[0]}", error_type=SourceMaterializationError)
        return result.stdout.decode("utf-8", errors="replace").strip()

    def _verify_catalog_source(
        self,
        *,
        repository: Path,
        catalog: _ResolvedCompatibilityPatchCatalog,
        env: Mapping[str, str],
    ) -> None:
        tree_spec = f"{self.source.commit}:{self.source.case_prefix.as_posix()}"
        actual_tree = self._git(repository, ("rev-parse", tree_spec), env=env)
        if actual_tree != catalog.source["benchmarks_tree_sha"]:
            raise SourceMaterializationError(
                "compatibility catalog benchmarks tree does not match the pinned source"
            )
        tree_entries = self._git(
            repository,
            ("ls-tree", "-d", "--name-only", tree_spec),
            env=env,
        ).splitlines()
        actual_case_ids = {
            entry for entry in tree_entries if _CASE_ID_RE.fullmatch(entry) is not None
        }
        if actual_case_ids != _COMPATIBILITY_CATALOG_CASE_IDS:
            raise SourceMaterializationError(
                "pinned source does not match the compatibility catalog's complete case set"
            )
        for patch in catalog.patches.values():
            for touched_file in patch.touched_files:
                object_type = self._git(
                    repository,
                    ("cat-file", "-t", f"{self.source.commit}:{touched_file.as_posix()}"),
                    env=env,
                )
                if object_type != "blob":
                    raise SourceMaterializationError(
                        "compatibility catalog touched-file is absent from the pinned source"
                    )

    def _apply_patch(
        self,
        *,
        root: Path,
        case_path: Path,
        case_id: str,
        configured: CompatibilityPatch | None,
        env: Mapping[str, str],
    ) -> Mapping[str, object] | None:
        if configured is None:
            return None
        patch_bytes = _read_compatibility_patch_bytes(configured)
        actual = hashlib.sha256(patch_bytes).hexdigest()
        # Apply the bytes that were hashed, not the caller-owned path.  This
        # closes the read/hash/apply race if another process replaces that file.
        frozen_patch = root / ".ravage-compatibility.patch"
        try:
            with frozen_patch.open("xb") as output:
                output.write(patch_bytes)
            frozen_patch.chmod(0o400)
            for action in ("--check", "--apply"):
                args = ["git", "apply", "--whitespace=nowarn"]
                if action == "--check":
                    args.append("--check")
                args.append(str(frozen_patch))
                result = self.runner.run(
                    args,
                    cwd=root,
                    environment=env,
                    timeout_seconds=self.git_timeout_seconds,
                )
                _require_success(
                    result,
                    operation=f"compatibility patch {action}",
                    error_type=SourceMaterializationError,
                )
        finally:
            frozen_patch.unlink(missing_ok=True)
        _reject_entries_outside_case(root=root, case_path=case_path)
        return {
            "case_id": case_id,
            "sha256": actual,
            "size_bytes": len(patch_bytes),
            "touched_files": [path.as_posix() for path in configured.touched_files],
            "applied": True,
        }


@dataclass(frozen=True)
class GatewayConfiguration:
    """Pinned, evaluator-controlled gateway and agent-side network identity."""

    image: str
    expected_image_id: str
    agent_network: str | None
    expected_agent_network_id: str | None
    expected_program_sha256: str
    max_target_requests: int
    endpoint_mode: GatewayEndpointMode
    agent_host_gateway: str | None = None
    listen_port: int = 8080
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    max_response_body_bytes: int = DEFAULT_MAX_RESPONSE_BODY_BYTES
    upstream_timeout_seconds: int = DEFAULT_UPSTREAM_TIMEOUT_SECONDS


@dataclass(frozen=True)
class ProbeConfiguration:
    """Digest-pinned HTTP readiness probe."""

    image: str
    expected_image_id: str
    attempts: int = 20
    per_attempt_timeout_seconds: int = 5


@dataclass(frozen=True)
class DockerTargetConfiguration:
    """Bounded Docker settings for one comparison target backend."""

    gateway: GatewayConfiguration | None
    probe: ProbeConfiguration | None
    platform: str = "linux/amd64"
    build_timeout_seconds: int = 900
    startup_timeout_seconds: int = 180
    inspect_timeout_seconds: int = 30
    teardown_timeout_seconds: int = 90


@dataclass
class _LiveState:
    instance_id: str
    project: str
    network: str
    materialized: MaterializedCase
    compose_path: Path
    evidence_dir: Path
    gateway_name: str
    gateway_configuration: GatewayConfiguration
    prepared: PreparedCase | None = None
    prepared_arm: Literal["ravage", "strix"] | None = None
    gateway_id: str | None = None
    target_container_ids: set[str] = field(default_factory=set)
    target_network_id: str | None = None
    target_volume_names: set[str] = field(default_factory=set)
    expected_flag: str = field(repr=False, default="")
    gateway_created: bool = False
    gateway_meter_verified: bool = False
    gateway_agent_ip: str | None = None
    gateway_upstream_service: str | None = None
    gateway_upstream_port: int | None = None
    stopped: bool = False


@dataclass
class DockerComparisonTargetBackend:
    """Concrete fresh Docker target satisfying ``ExternalTargetBackend``."""

    materializer: PinnedGitCaseMaterializer
    evidence_root: Path
    configuration: DockerTargetConfiguration
    runner: CommandRunner = field(default_factory=BoundedSubprocessRunner)
    _live: dict[str, _LiveState] = field(default_factory=dict, init=False)
    _seen_flag_hashes: set[str] = field(default_factory=set, init=False)
    _prepared_pairs: dict[str, PreparedCase | None] = field(default_factory=dict, init=False)

    def prepare_case(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        pair_id: str,
    ) -> PreparedCase:
        """Build one selected case once for its two adjacent solver arms."""

        self._validate_configuration()
        _validate_instance_id(pair_id)
        if case.benchmark_id not in _COMPATIBILITY_CATALOG_CASE_IDS:
            raise ComparisonTargetError("prepared target benchmark ID is invalid")
        if _EXPECTED_FLAG_RE.fullmatch(expected_flag) is None:
            raise ComparisonTargetError("prepared target flag does not match the nonce contract")
        flag_hash = hashlib.sha256(expected_flag.encode()).hexdigest()
        if flag_hash in self._seen_flag_hashes:
            raise ComparisonTargetError("prepared target flag was already used by this backend")
        if pair_id in self._prepared_pairs:
            raise ComparisonTargetError("prepared target pair ID was already used")
        # Both reservations are irreversible, including failed preparation. A
        # build failure is terminal for this draw and can never be retried into
        # a more favorable observation.
        self._seen_flag_hashes.add(flag_hash)
        self._prepared_pairs[pair_id] = None
        evidence_dir = _claim_evidence_dir(self.evidence_root, f"{pair_id}.prepared")
        preparation_instance = f"{pair_id}.prepared"
        project = _docker_project_name(preparation_instance)
        network = f"{project}_target"
        materialized: MaterializedCase | None = None
        owned_references: tuple[str, ...] = ()
        records: list[dict[str, object]] = []
        try:
            self._assert_project_unused(project=project, cwd=evidence_dir, records=records)
            materialized = self.materializer.materialize(
                case=case,
                instance_id=preparation_instance,
            )
            pristine_manifest = _tree_manifest(materialized.case_path)
            compose_path, transform = _write_sanitized_compose(
                case_path=materialized.case_path,
                project=project,
                network_name=network,
                instance_id=preparation_instance,
            )
            image_references, owned_references = _assign_prepared_image_references(
                compose_path=compose_path,
                project=project,
            )
            env = _docker_environment(self.configuration.platform)
            preparation_pull_invocations = 0
            for service_name, image_reference in sorted(image_references.items()):
                if image_reference in owned_references:
                    continue
                pulled = self._docker(
                    (
                        "docker",
                        "image",
                        "pull",
                        "--platform",
                        self.configuration.platform,
                        image_reference,
                    ),
                    cwd=compose_path.parent,
                    env=env,
                    timeout=self.configuration.build_timeout_seconds,
                    records=records,
                    operation=f"prepare image-only service resolution ({service_name})",
                )
                _require_success(
                    pulled,
                    operation="prepare image-only service resolution",
                    error_type=ComparisonTargetError,
                )
                preparation_pull_invocations += 1
            build = self._docker(
                (
                    "docker",
                    "compose",
                    "-f",
                    str(compose_path),
                    "-p",
                    project,
                    "build",
                    "--pull=false",
                    "--build-arg",
                    f"flag={expected_flag}",
                    "--build-arg",
                    f"FLAG={expected_flag}",
                ),
                cwd=compose_path.parent,
                env=env,
                timeout=self.configuration.build_timeout_seconds,
                records=records,
                operation="prepare compose build once",
                redact=(expected_flag,),
            )
            _require_success(
                build,
                operation="prepare compose build once",
                error_type=ComparisonTargetError,
            )
            if (
                _tree_manifest_excluding(
                    materialized.case_path,
                    excluded={compose_path.relative_to(materialized.case_path).as_posix()},
                )
                != pristine_manifest
            ):
                raise SourceMaterializationError("Docker preparation changed the private source")
            service_images = self._inspect_prepared_service_images(
                image_references=image_references,
                owned_references=set(owned_references),
                cwd=compose_path.parent,
                records=records,
            )
            image_records = [dict(service_images[name]) for name in sorted(service_images)]
            source_document = dict(materialized.source_evidence)
            source_document.update(
                {
                    "prepared_pristine_tree": pristine_manifest,
                    "preparation_compose_transform": transform,
                    "preparation_runtime_tree": _tree_manifest(materialized.case_path),
                }
            )
            _ensure_secret_absent(source_document, expected_flag=expected_flag)
            _write_json_exclusive(evidence_dir / "source.json", source_document)
            build_document = {
                "schema_version": PREPARED_TARGET_SCHEMA_VERSION,
                "status": "prepared",
                "pair_id": pair_id,
                "benchmark_id": case.benchmark_id,
                "pair_flag_sha256": flag_hash,
                "pair_flag_scope": _PAIR_FLAG_SCOPE,
                "flag_disclosure": _PAIR_FLAG_DISCLOSURE,
                "build_invocations": 1,
                "preparation_pull_invocations": preparation_pull_invocations,
                "build_once": True,
                "runtime_build_allowed": False,
                "runtime_pull_allowed": False,
                "platform": self.configuration.platform,
                "build_input_boundary": {
                    "pinned_source_and_compatibility_catalog": True,
                    "explicit_privileged_or_remote_compose_build_features_forbidden": True,
                    "preparation_registry_and_default_build_network_available": True,
                    "external_base_references_may_be_mutable": True,
                    "post_resolution_local_image_ids_frozen": True,
                    "hermetic_rebuild_claimed": False,
                },
                "default_build_network_available": True,
                "source_sha256": _file_sha256(evidence_dir / "source.json"),
                "service_images": image_records,
                "commands": records,
            }
            _ensure_secret_absent(build_document, expected_flag=expected_flag)
            _write_json_exclusive(evidence_dir / "build.json", build_document)
            provenance: dict[str, object] = {
                "schema_version": PREPARED_TARGET_SCHEMA_VERSION,
                "pair_id": pair_id,
                "benchmark_id": case.benchmark_id,
                "pair_flag_sha256": flag_hash,
                "pair_flag_scope": _PAIR_FLAG_SCOPE,
                "flag_disclosure": _PAIR_FLAG_DISCLOSURE,
                "expected_arms": ["ravage", "strix"],
                "build_once": True,
                "runtime_build_allowed": False,
                "runtime_pull_allowed": False,
                "platform": self.configuration.platform,
                "build_input_boundary": {
                    "pinned_source_and_compatibility_catalog": True,
                    "explicit_privileged_or_remote_compose_build_features_forbidden": True,
                    "preparation_registry_and_default_build_network_available": True,
                    "external_base_references_may_be_mutable": True,
                    "post_resolution_local_image_ids_frozen": True,
                    "hermetic_rebuild_claimed": False,
                },
                "source_path": "source.json",
                "source_sha256": _file_sha256(evidence_dir / "source.json"),
                "build_path": "build.json",
                "build_sha256": _file_sha256(evidence_dir / "build.json"),
                "prepared_source_tree_sha256": pristine_manifest["sha256"],
                "service_images": image_records,
                "image_ids_by_service": {
                    service: str(record["image_id"])
                    for service, record in sorted(service_images.items())
                },
                "created_at": datetime.now(UTC).isoformat(),
                "verification_kind": "operational-build-and-local-docker-image-inspection",
                "cryptographically_attested": False,
                "valid": True,
            }
            _ensure_secret_absent(provenance, expected_flag=expected_flag)
            _write_json_exclusive(evidence_dir / "prepared.json", provenance)
            validated = validate_prepared_target_provenance(
                provenance,
                evidence_dir=evidence_dir,
            )
            prepared = PreparedCase(
                pair_id=pair_id,
                benchmark_id=case.benchmark_id,
                case=case,
                expected_flag=expected_flag,
                materialized=materialized,
                prepare_compose_path=compose_path,
                pristine_case_manifest=pristine_manifest,
                service_images=service_images,
                owned_image_references=owned_references,
                evidence_dir=evidence_dir,
                provenance=validated,
                provenance_sha256=_file_sha256(evidence_dir / "prepared.json"),
            )
            self._prepared_pairs[pair_id] = prepared
            return prepared
        except Exception as exc:
            cleanup_absent: list[str] = []
            cleanup_errors: list[str] = []
            if materialized is not None:
                if owned_references:
                    cleanup_absent, cleanup_errors = self._release_owned_prepared_tags(
                        references=owned_references,
                        cwd=materialized.case_path,
                        records=records,
                    )
                try:
                    _remove_private_instance(
                        root=materialized.root,
                        private_root=self.materializer.private_root,
                    )
                except Exception:  # noqa: BLE001 - retain the failed cleanup evidence.
                    cleanup_errors.append("prepared private source removal failed")
            workspace_removed = materialized is None or not materialized.root.exists()
            if not workspace_removed:
                cleanup_errors.append("prepared private source remains")
            failure = {
                "status": "preparation_failed",
                "pair_id": pair_id,
                "benchmark_id": case.benchmark_id,
                "error": _safe_error_without_flag(exc, expected_flag=expected_flag),
                "cleanup": {
                    "workspace_removed": workspace_removed,
                    "owned_image_references": list(owned_references),
                    "owned_image_references_absent": cleanup_absent,
                    "errors": cleanup_errors,
                    "valid": not cleanup_errors,
                },
                "commands": records,
            }
            _ensure_secret_absent(failure, expected_flag=expected_flag)
            _write_json_if_absent(evidence_dir / "failure.json", failure)
            if cleanup_errors:
                raise TeardownVerificationError(
                    "prepared target creation failed and cleanup could not be verified: "
                    + "; ".join(cleanup_errors)
                ) from None
            raise

    def start_prepared(
        self,
        *,
        prepared: PreparedCase,
        arm: Literal["ravage", "strix"],
        instance_id: str,
    ) -> ExternalTarget:
        """Launch one fresh arm from the exact images frozen by ``prepare_case``."""

        self._validate_configuration()
        _validate_instance_id(instance_id)
        if arm not in _PREPARED_ARMS:
            raise ComparisonTargetError("prepared target arm is invalid")
        _validate_prepared_case_handle(prepared)
        if prepared.provenance.get("platform") != self.configuration.platform:
            raise ComparisonTargetError("prepared target platform binding is invalid")
        with prepared._lock:
            if prepared.released:
                raise ComparisonTargetError("prepared target was already released")
            if arm in prepared.started_arms:
                raise ComparisonTargetError("prepared target arm was already attempted")
            if arm in prepared.abandoned_arms:
                raise ComparisonTargetError("prepared target arm was already terminalized")
            if instance_id in {
                *prepared.started_arms.values(),
                *prepared.abandoned_arms.values(),
            }:
                raise ComparisonTargetError("prepared target instance ID is duplicated")
            prepared.started_arms[arm] = instance_id
        try:
            return self._start_instance(
                case=prepared.case,
                expected_flag=prepared.expected_flag,
                instance_id=instance_id,
                prepared=prepared,
                prepared_arm=arm,
            )
        except Exception:
            with prepared._lock:
                prepared.stopped_arms.add(arm)
            raise

    def abandon_prepared_arm(
        self,
        *,
        prepared: PreparedCase,
        arm: Literal["ravage", "strix"],
        instance_id: str,
        reason_code: Literal[
            "prelaunch_failure",
            "campaign_cancelled_before_target_start",
        ] = "prelaunch_failure",
    ) -> Mapping[str, object]:
        """Terminalize one arm that failed before the target backend was started.

        This transition is deliberately one-shot.  It accepts a frozen reason
        code rather than exception text so credentials or flags cannot enter
        retained evidence.  An arm for which ``start_prepared`` was attempted
        must be stopped through the normal target lifecycle instead.
        """

        self._require_prepared_owner(prepared)
        _validate_prepared_case_handle(prepared)
        _validate_instance_id(instance_id)
        if arm not in _PREPARED_ARMS:
            raise ComparisonTargetError("prepared target arm is invalid")
        if reason_code not in _PREPARED_ARM_ABANDONMENT_REASONS:
            raise ComparisonTargetError("prepared target abandonment reason is invalid")
        with prepared._lock:
            if prepared.released:
                raise ComparisonTargetError("prepared target was already released")
            if arm in prepared.started_arms:
                raise ComparisonTargetError("a started prepared target arm cannot be abandoned")
            if arm in prepared.abandoned_arms:
                raise ComparisonTargetError("prepared target arm was already abandoned")
            if instance_id in {
                *prepared.started_arms.values(),
                *prepared.abandoned_arms.values(),
            }:
                raise ComparisonTargetError("prepared target instance ID is duplicated")
            evidence = {
                "schema_version": PREPARED_TARGET_ARM_ABANDONMENT_SCHEMA_VERSION,
                "pair_id": prepared.pair_id,
                "benchmark_id": prepared.benchmark_id,
                "arm": arm,
                "instance_id": instance_id,
                "pair_flag_sha256": prepared.provenance["pair_flag_sha256"],
                "prepared_provenance_sha256": prepared.provenance_sha256,
                "reason_code": reason_code,
                "target_backend_start_attempted": False,
                "row_terminal": True,
                "created_at": datetime.now(UTC).isoformat(),
                "verification_kind": "evaluator-lifecycle-state-transition",
                "cryptographically_attested": False,
                "valid": True,
            }
            _ensure_secret_absent(evidence, expected_flag=prepared.expected_flag)
            path = prepared.evidence_dir / f"abandoned-{arm}.json"
            try:
                _write_json_exclusive(path, evidence)
            except FileExistsError as exc:
                raise ComparisonTargetError(
                    "prepared target abandonment evidence path was already reserved"
                ) from exc
            digest = _file_sha256(path)
            prepared.abandoned_arms[arm] = instance_id
            prepared.abandonment_receipt_sha256[arm] = digest
        return {
            **evidence,
            "evidence_path": str(path),
            "evidence_sha256": digest,
        }

    def terminalize_prepared_arm(
        self,
        *,
        prepared: PreparedCase,
        arm: Literal["ravage", "strix"],
        instance_id: str,
        reason_code: Literal[
            "prelaunch_failure",
            "campaign_cancelled_before_target_start",
        ] = "prelaunch_failure",
    ) -> Mapping[str, object]:
        """Reconcile an arm after a coordinator-side execution exception.

        A completed target lifecycle remains a completed target lifecycle; it
        is never relabelled as abandonment.  Only a wholly unstarted arm is
        delegated to the create-only abandonment transition.
        """

        self._require_prepared_owner(prepared)
        _validate_prepared_case_handle(prepared)
        _validate_instance_id(instance_id)
        if arm not in _PREPARED_ARMS:
            raise ComparisonTargetError("prepared target arm is invalid")
        if reason_code not in _PREPARED_ARM_ABANDONMENT_REASONS:
            raise ComparisonTargetError("prepared target abandonment reason is invalid")
        with prepared._lock:
            if prepared.released:
                raise ComparisonTargetError("prepared target was already released")
            started_instance = prepared.started_arms.get(arm)
            abandoned_instance = prepared.abandoned_arms.get(arm)
            if started_instance is not None:
                if started_instance != instance_id:
                    raise ComparisonTargetError(
                        "prepared target terminal instance binding is invalid"
                    )
                if arm not in prepared.stopped_arms:
                    raise TeardownVerificationError(
                        "prepared target arm is still live and cannot be terminalized"
                    )
                if abandoned_instance is not None:
                    raise TeardownVerificationError(
                        "prepared target arm lifecycle state is contradictory"
                    )
                result: dict[str, object] = {
                    "schema_version": PREPARED_TARGET_ARM_TERMINAL_STATE_SCHEMA_VERSION,
                    "status": "already_terminal_via_target_lifecycle",
                    "pair_id": prepared.pair_id,
                    "benchmark_id": prepared.benchmark_id,
                    "arm": arm,
                    "instance_id": instance_id,
                    "pair_flag_sha256": prepared.provenance["pair_flag_sha256"],
                    "target_backend_start_attempted": True,
                    "row_terminal": True,
                    "cryptographically_attested": False,
                    "valid": True,
                }
                _ensure_secret_absent(result, expected_flag=prepared.expected_flag)
                return result
            if arm in prepared.stopped_arms:
                raise TeardownVerificationError(
                    "prepared target arm stopped without a launch reservation"
                )
            if abandoned_instance is not None:
                if abandoned_instance != instance_id:
                    raise ComparisonTargetError(
                        "prepared target terminal instance binding is invalid"
                    )
                digest = prepared.abandonment_receipt_sha256.get(arm)
                if not isinstance(digest, str):
                    raise TeardownVerificationError(
                        "prepared target abandonment receipt binding is missing"
                    )
                _validate_prepared_arm_abandonment_receipt(
                    prepared=prepared,
                    arm=arm,
                    instance_id=instance_id,
                    expected_sha256=digest,
                )
                result = {
                    "schema_version": PREPARED_TARGET_ARM_TERMINAL_STATE_SCHEMA_VERSION,
                    "status": "already_abandoned_before_target_start",
                    "pair_id": prepared.pair_id,
                    "benchmark_id": prepared.benchmark_id,
                    "arm": arm,
                    "instance_id": instance_id,
                    "pair_flag_sha256": prepared.provenance["pair_flag_sha256"],
                    "target_backend_start_attempted": False,
                    "row_terminal": True,
                    "cryptographically_attested": False,
                    "valid": True,
                }
                _ensure_secret_absent(result, expected_flag=prepared.expected_flag)
                return result
        # A concurrent launch between the inspection above and this call makes
        # abandonment reject rather than producing a false pre-launch receipt.
        return self.abandon_prepared_arm(
            prepared=prepared,
            arm=arm,
            instance_id=instance_id,
            reason_code=reason_code,
        )

    def release_prepared(self, *, prepared: PreparedCase) -> Mapping[str, object]:
        """Release private source and owned tags after both one-shot arms terminate."""

        self._require_prepared_owner(prepared)
        _validate_prepared_case_handle(prepared)
        with prepared._lock:
            if prepared.released:
                raise TeardownVerificationError("prepared target was already released")
            started = set(prepared.started_arms)
            abandoned = set(prepared.abandoned_arms)
            if (
                started & abandoned
                or started | abandoned != _PREPARED_ARMS
                or prepared.stopped_arms != started
                or set(prepared.abandonment_receipt_sha256) != abandoned
            ):
                raise TeardownVerificationError(
                    "prepared target cannot be released before both arms terminate"
                )
            for arm in sorted(abandoned):
                _validate_prepared_arm_abandonment_receipt(
                    prepared=prepared,
                    arm=arm,
                    instance_id=prepared.abandoned_arms[arm],
                    expected_sha256=prepared.abandonment_receipt_sha256[arm],
                )
            arms = {
                **prepared.started_arms,
                **prepared.abandoned_arms,
            }
            prepared.released = True
        records: list[dict[str, object]] = []
        absent_references, errors = self._release_owned_prepared_tags(
            references=prepared.owned_image_references,
            cwd=prepared.prepare_compose_path.parent,
            records=records,
        )
        try:
            _remove_private_instance(
                root=prepared.materialized.root,
                private_root=self.materializer.private_root,
            )
        except Exception:
            errors.append("prepared private source removal failed")
        evidence = {
            "schema_version": "ravage.xben.prepared-target-release.v1",
            "pair_id": prepared.pair_id,
            "benchmark_id": prepared.benchmark_id,
            "arms": dict(sorted(arms.items())),
            "both_arms_terminated": (
                prepared.stopped_arms == set(prepared.started_arms) and set(arms) == _PREPARED_ARMS
            ),
            "prepared_source_removed": not prepared.materialized.root.exists(),
            "owned_image_references_released": list(prepared.owned_image_references),
            "owned_image_references_absent": absent_references,
            "owned_image_reference_absence_verified": (
                absent_references == list(prepared.owned_image_references)
            ),
            "commands": records,
            "errors": errors,
            "valid": not errors,
        }
        _ensure_secret_absent(evidence, expected_flag=prepared.expected_flag)
        _write_json_exclusive(prepared.evidence_dir / "release.json", evidence)
        if errors:
            raise TeardownVerificationError("; ".join(errors))
        return {
            **evidence,
            "evidence_path": str(prepared.evidence_dir / "release.json"),
            "evidence_sha256": _file_sha256(prepared.evidence_dir / "release.json"),
        }

    def _require_prepared_owner(self, prepared: PreparedCase) -> None:
        if self._prepared_pairs.get(prepared.pair_id) is not prepared:
            raise ComparisonTargetError(
                "prepared target must be released or abandoned by its preparation backend"
            )

    def _release_owned_prepared_tags(
        self,
        *,
        references: Sequence[str],
        cwd: Path,
        records: list[dict[str, object]],
    ) -> tuple[list[str], list[str]]:
        absent: list[str] = []
        errors: list[str] = []
        for reference in references:
            try:
                self._docker(
                    ("docker", "image", "rm", reference),
                    cwd=cwd,
                    env=_docker_environment(self.configuration.platform),
                    timeout=self.configuration.teardown_timeout_seconds,
                    records=records,
                    operation="prepared image tag release",
                )
            except Exception:  # noqa: BLE001 - inventory is the terminal authority.
                pass
            try:
                inventory = self._docker(
                    ("docker", "image", "ls", "--no-trunc", "--quiet", reference),
                    cwd=cwd,
                    env=_docker_environment(self.configuration.platform),
                    timeout=self.configuration.inspect_timeout_seconds,
                    records=records,
                    operation="prepared image tag absence inventory",
                )
            except Exception:  # noqa: BLE001 - unavailable inventory fails closed.
                errors.append("prepared image tag absence inventory did not complete")
                continue
            if inventory.returncode != 0:
                errors.append("prepared image tag absence inventory failed")
            elif inventory.stdout.strip():
                errors.append("prepared image tag remains after release")
            else:
                absent.append(reference)
        return absent, errors

    def start(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        instance_id: str,
    ) -> ExternalTarget:
        """Legacy single-build launch; paired campaigns must use the prepared API."""

        return self._start_instance(
            case=case,
            expected_flag=expected_flag,
            instance_id=instance_id,
            prepared=None,
            prepared_arm=None,
        )

    def _start_instance(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        instance_id: str,
        prepared: PreparedCase | None,
        prepared_arm: Literal["ravage", "strix"] | None,
    ) -> ExternalTarget:
        self._validate_configuration()
        gateway_configuration = self.configuration.gateway
        if gateway_configuration is None:  # narrowed after fail-closed validation
            raise GatewayUnavailableError("comparison target gateway is unavailable")
        gateway_configuration = _runtime_gateway_configuration(gateway_configuration)
        _validate_instance_id(instance_id)
        if _EXPECTED_FLAG_RE.fullmatch(expected_flag) is None:
            raise ComparisonTargetError(
                "comparison target flag does not match the fresh nonce contract"
            )
        flag_hash = hashlib.sha256(expected_flag.encode()).hexdigest()
        if prepared is None:
            if flag_hash in self._seen_flag_hashes:
                raise ComparisonTargetError(
                    "comparison target flag was already used by this backend"
                )
            # Reservation is intentionally irreversible within this evaluator
            # process, including failed startup, so a target is never rebuilt
            # with the same proof after an outcome is observed.
            self._seen_flag_hashes.add(flag_hash)
        elif (
            prepared_arm not in _PREPARED_ARMS
            or flag_hash != prepared.provenance.get("pair_flag_sha256")
            or case.benchmark_id != prepared.benchmark_id
        ):
            raise ComparisonTargetError("prepared target binding is invalid")
        if instance_id in self._live:
            raise ComparisonTargetError("target instance is already live")
        project = _docker_project_name(instance_id)
        target_network = f"{project}_target"
        gateway_name = f"{project}_gateway"
        evidence_dir = _claim_evidence_dir(self.evidence_root, instance_id)
        materialized: MaterializedCase | None = None
        state: _LiveState | None = None
        command_records: list[dict[str, object]] = []
        try:
            self._assert_project_unused(project=project, cwd=evidence_dir, records=command_records)
            self._assert_container_name_unused(
                name=gateway_name,
                cwd=evidence_dir,
                records=command_records,
            )
            if prepared is None:
                materialized = self.materializer.materialize(
                    case=case,
                    instance_id=instance_id,
                )
            else:
                materialized = _copy_prepared_materialization(
                    prepared=prepared,
                    private_root=self.materializer.private_root,
                    instance_id=instance_id,
                )
            compose_path, transform = _write_sanitized_compose(
                case_path=materialized.case_path,
                project=project,
                network_name=target_network,
                instance_id=instance_id,
            )
            prepared_runtime_transform: Mapping[str, object] | None = None
            if prepared is not None:
                prepared_runtime_transform = _bind_prepared_service_images(
                    compose_path=compose_path,
                    service_images=prepared.service_images,
                )
            state = _LiveState(
                instance_id=instance_id,
                project=project,
                network=target_network,
                materialized=materialized,
                compose_path=compose_path,
                evidence_dir=evidence_dir,
                gateway_name=gateway_name,
                gateway_configuration=gateway_configuration,
                prepared=prepared,
                prepared_arm=prepared_arm,
                expected_flag=expected_flag,
            )
            source_evidence = dict(materialized.source_evidence)
            source_evidence["runtime_compose_transform"] = transform
            source_evidence["prepared_runtime_transform"] = prepared_runtime_transform
            source_evidence["runtime_tree"] = _tree_manifest(materialized.case_path)
            _ensure_secret_absent(source_evidence, expected_flag=expected_flag)
            _write_json_exclusive(evidence_dir / "source.json", source_evidence)

            env = _docker_environment(self.configuration.platform)
            if prepared is None:
                build = self._docker(
                    (
                        "docker",
                        "compose",
                        "-f",
                        str(compose_path),
                        "-p",
                        project,
                        "build",
                        "--pull=false",
                        "--build-arg",
                        f"flag={expected_flag}",
                        "--build-arg",
                        f"FLAG={expected_flag}",
                    ),
                    cwd=compose_path.parent,
                    env=env,
                    timeout=self.configuration.build_timeout_seconds,
                    records=command_records,
                    operation="compose build",
                    redact=(expected_flag,),
                )
                _require_success(
                    build,
                    operation="compose build",
                    error_type=ComparisonTargetError,
                )
            runtime_image_arguments: tuple[str, ...] = ()
            if prepared is not None:
                runtime_image_arguments = ("--no-build", "--pull", "never")
            up = self._docker(
                (
                    "docker",
                    "compose",
                    "-f",
                    str(compose_path),
                    "-p",
                    project,
                    "up",
                    "-d",
                    *runtime_image_arguments,
                    "--remove-orphans",
                    "--wait",
                    "--wait-timeout",
                    str(self.configuration.startup_timeout_seconds),
                ),
                cwd=compose_path.parent,
                env=env,
                timeout=self.configuration.startup_timeout_seconds,
                records=command_records,
                operation="compose up",
            )
            _require_success(up, operation="compose up", error_type=ComparisonTargetError)

            target_inspection = self._inspect_target(state=state, records=command_records)
            if prepared is not None:
                _verify_prepared_container_images(
                    target_inspection=target_inspection,
                    service_images=prepared.service_images,
                )
            image_evidence = self._inspect_images(
                image_ids=target_inspection["image_ids"],
                cwd=compose_path.parent,
                records=command_records,
            )
            readiness = self._probe_readiness(case=case, state=state, records=command_records)
            gateway_evidence, target_url = self._start_gateway(
                case=case,
                state=state,
                gateway=gateway_configuration,
                records=command_records,
            )
            build_evidence = {
                "schema_version": (
                    PREPARED_TARGET_ARM_SCHEMA_VERSION
                    if prepared is not None
                    else "ravage.xben.target-build.v2"
                ),
                "comparison_safe": True,
                "paired_comparison_safe": prepared is not None,
                "comparison_safe_scope": "fresh target and gateway isolation boundary",
                "fresh": True,
                "paired_prepared_target": {
                    "enabled": prepared is not None,
                    "pair_id": prepared.pair_id if prepared is not None else None,
                    "arm": prepared_arm,
                    "prepared_provenance_path": (
                        str(prepared.evidence_dir / "prepared.json")
                        if prepared is not None
                        else None
                    ),
                    "prepared_provenance_sha256": (
                        prepared.provenance_sha256 if prepared is not None else None
                    ),
                    "pair_flag_sha256": flag_hash if prepared is not None else None,
                    "pair_flag_scope": (_PAIR_FLAG_SCOPE if prepared is not None else None),
                    "flag_disclosure": (_PAIR_FLAG_DISCLOSURE if prepared is not None else None),
                    "build_invocations_this_arm": 0 if prepared is not None else 1,
                    "runtime_build_allowed": prepared is None,
                    "runtime_pull_allowed": False,
                    "exact_prepared_images_verified": prepared is not None,
                    "image_ids_by_service": (
                        {
                            service: str(record["image_id"])
                            for service, record in sorted(prepared.service_images.items())
                        }
                        if prepared is not None
                        else None
                    ),
                },
                "source_path_exposed_to_agent": False,
                "target_request_counting": {
                    "verified_by_this_backend": True,
                    "verification_kind": "operational-docker-inspection-and-meter-receipt",
                    "cryptographically_attested": False,
                    "caller_authentication": "none",
                    "access_boundary": _gateway_access_boundary(gateway_configuration),
                    "trusted_host_no_concurrent_local_adversary": (
                        gateway_configuration.endpoint_mode == "host_loopback"
                    ),
                    "enforcement": "hard evaluator-owned HTTP gateway allowance",
                    "protocol": HTTP_METER_PROTOCOL,
                    "http2_supported": False,
                    "upstream_scheme": "http",
                    "max_target_requests": gateway_configuration.max_target_requests,
                    "https_connect_supported": False,
                    "websocket_upgrade_supported": False,
                    "chunked_request_body_supported": False,
                    "max_request_body_bytes": gateway_configuration.max_request_body_bytes,
                    "chunked_response_supported": True,
                    "response_without_content_length_supported": True,
                    "streaming_response_supported": False,
                    "response_trailers_forwarded": False,
                    "upstream_must_complete_within_seconds": (
                        gateway_configuration.upstream_timeout_seconds
                    ),
                    "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
                    "max_response_body_bytes": gateway_configuration.max_response_body_bytes,
                    "downstream_response_framing": "buffered-content-length-and-connection-close",
                    "final_receipt_path": "request-count.json",
                },
                "mount_isolation": {
                    "gateway_evaluator_source_mounts_absent": True,
                    "gateway_docker_socket_mounts_absent": True,
                    "target_docker_socket_mounts_absent": True,
                    "target_bind_mount_policy": "private-materialized-case-only",
                    "verification_kind": "operational-docker-inspect",
                    "cryptographically_attested": False,
                    "agent_runtime_mounts_in_scope": False,
                },
                "project": project,
                "target_network": target_network,
                "source_evidence_path": "source.json",
                "target_inspection": target_inspection["evidence"],
                "images": image_evidence,
                "target_image_ids": sorted(str(image["id"]) for image in image_evidence),
                "build_input_boundary": {
                    "explicit_build_network_override_forbidden": True,
                    "privileged_build_forbidden": True,
                    "remote_build_contexts_forbidden": True,
                    "remote_cache_and_ssh_inputs_forbidden": True,
                    "runtime_pull_policy": "never",
                    "default_build_network_available": prepared is None,
                    "default_build_network_reason": (
                        "pinned XBEN source may require package installation during preparation"
                        if prepared is None
                        else "runtime launch is image-only with build definitions removed"
                    ),
                },
                "readiness": readiness,
                "gateway": gateway_evidence,
                "commands": command_records,
            }
            _ensure_secret_absent(build_evidence, expected_flag=expected_flag)
            _write_json_exclusive(evidence_dir / "build.json", build_evidence)
            if prepared is not None:
                target_image_ids_by_service = {
                    service: str(record["image_id"])
                    for service, record in sorted(prepared.service_images.items())
                }
                public_build_provenance: Mapping[str, object] = {
                    "schema_version": PREPARED_TARGET_ARM_SCHEMA_VERSION,
                    "comparison_safe": True,
                    "paired_comparison_safe": True,
                    "comparison_safe_scope": "fresh target and gateway isolation boundary",
                    "fresh": True,
                    "pair_id": prepared.pair_id,
                    "benchmark_id": prepared.benchmark_id,
                    "arm": prepared_arm,
                    "pair_flag_sha256": flag_hash,
                    "pair_flag_scope": _PAIR_FLAG_SCOPE,
                    "flag_disclosure": _PAIR_FLAG_DISCLOSURE,
                    "build_once_per_case_pair": True,
                    "build_invocations_this_arm": 0,
                    "runtime_build_allowed": False,
                    "runtime_pull_allowed": False,
                    "runtime_build_or_pull_allowed": False,
                    "prepared_provenance_path": str(prepared.evidence_dir / "prepared.json"),
                    "prepared_provenance_sha256": prepared.provenance_sha256,
                    "prepared_source_tree_sha256": prepared.provenance[
                        "prepared_source_tree_sha256"
                    ],
                    "prepared_image_reuse_verified": True,
                    "target_image_ids": sorted(set(target_image_ids_by_service.values())),
                    "target_image_ids_by_service": target_image_ids_by_service,
                    "target_request_counting_verified": True,
                    "max_target_requests": gateway_configuration.max_target_requests,
                    "target_request_protocol": HTTP_METER_PROTOCOL,
                    "gateway_endpoint_mode": gateway_configuration.endpoint_mode,
                    "backend": "docker-pinned-git-http-meter-gateway-v3",
                    "platform": self.configuration.platform,
                    "project": project,
                    "target_network": target_network,
                    "target_url": target_url,
                    "evidence_dir": str(evidence_dir),
                    "source_path": "source.json",
                    "source_sha256": _file_sha256(evidence_dir / "source.json"),
                    "build_path": "build.json",
                    "build_sha256": _file_sha256(evidence_dir / "build.json"),
                    "verification_kind": (
                        "operational-docker-inspection-and-prepared-image-closure"
                    ),
                    "cryptographically_attested": False,
                    "valid": True,
                }
                _ensure_secret_absent(
                    public_build_provenance,
                    expected_flag=expected_flag,
                )
                public_build_provenance = validate_prepared_target_arm_provenance(
                    public_build_provenance,
                    evidence_dir=evidence_dir,
                )
            else:
                public_build_provenance = {
                    "comparison_safe": True,
                    "paired_comparison_safe": False,
                    "comparison_safe_scope": "fresh target and gateway isolation boundary",
                    "fresh": True,
                    "target_request_counting_verified": True,
                    "max_target_requests": gateway_configuration.max_target_requests,
                    "target_request_protocol": HTTP_METER_PROTOCOL,
                    "gateway_endpoint_mode": gateway_configuration.endpoint_mode,
                    "backend": "docker-pinned-git-http-meter-gateway-v2",
                    "project": project,
                    "target_network": target_network,
                    "target_image_ids": sorted(str(image["id"]) for image in image_evidence),
                    "prepared_pair_id": None,
                    "prepared_arm": None,
                    "prepared_provenance_path": None,
                    "prepared_provenance_sha256": None,
                    "prepared_image_reuse_verified": False,
                    "runtime_build_or_pull_allowed": True,
                    "evidence_dir": str(evidence_dir),
                    "source_sha256": _file_sha256(evidence_dir / "source.json"),
                    "build_sha256": _file_sha256(evidence_dir / "build.json"),
                }
            self._live[instance_id] = state
            return ExternalTarget(
                instance_id=instance_id,
                target_url=target_url,
                build_provenance=public_build_provenance,
                backend_handle=state,
            )
        except Exception as startup_error:
            cleanup_error: Exception | None = None
            if state is not None:
                try:
                    self._cleanup(state=state, records=command_records)
                except Exception as exc:  # noqa: BLE001 - preserve both startup and cleanup failures.
                    cleanup_error = exc
            elif materialized is not None:
                _remove_private_instance(
                    root=materialized.root,
                    private_root=self.materializer.private_root,
                )
            failure = {
                "status": "startup_failed",
                "error": _bounded_text(_redact_text(str(startup_error), redact=(expected_flag,))),
                "cleanup_error": (
                    _bounded_text(_redact_text(str(cleanup_error), redact=(expected_flag,)))
                    if cleanup_error
                    else None
                ),
                "commands": command_records,
            }
            _ensure_secret_absent(failure, expected_flag=expected_flag)
            _write_json_if_absent(evidence_dir / "failure.json", failure)
            if cleanup_error is not None:
                raise TeardownVerificationError(
                    "target startup failed and cleanup could not be verified: "
                    + _safe_error_without_flag(
                        cleanup_error,
                        expected_flag=expected_flag,
                    )
                ) from None
            safe_startup_error = _safe_error_without_flag(
                startup_error,
                expected_flag=expected_flag,
            )
            if safe_startup_error != str(startup_error):
                raise ComparisonTargetError(safe_startup_error) from None
            raise

    def stop(self, *, target: ExternalTarget) -> Mapping[str, object]:
        state = target.backend_handle
        if not isinstance(state, _LiveState) or state.instance_id != target.instance_id:
            raise TeardownVerificationError("target backend handle is invalid")
        if state.stopped:
            raise TeardownVerificationError("target instance was already stopped")
        records: list[dict[str, object]] = []
        # Teardown is a one-shot evidence transition even when verification
        # fails.  A second attempt could replace the first terminal narrative.
        state.stopped = True
        self._live.pop(target.instance_id, None)
        try:
            return self._cleanup(state=state, records=records)
        finally:
            if state.prepared is not None and state.prepared_arm is not None:
                with state.prepared._lock:
                    state.prepared.stopped_arms.add(state.prepared_arm)

    def _validate_configuration(self) -> None:
        gateway = self.configuration.gateway
        probe = self.configuration.probe
        if self.configuration.platform != "linux/amd64":
            raise GatewayUnavailableError(
                "paired comparison target platform must be frozen to linux/amd64"
            )
        if gateway is None:
            raise GatewayUnavailableError("comparison target requires an evaluator-owned gateway")
        if probe is None:
            raise GatewayUnavailableError("comparison target requires a pinned readiness probe")
        _validate_pinned_image(gateway.image, gateway.expected_image_id, label="gateway")
        _validate_pinned_image(probe.image, probe.expected_image_id, label="probe")
        if gateway.endpoint_mode == "cross_daemon_host_gateway":
            if gateway.agent_network is not None or gateway.expected_agent_network_id is not None:
                raise GatewayUnavailableError(
                    "cross-daemon gateway must not accept an agent Docker network"
                )
            try:
                host_gateway = ipaddress.ip_address(str(gateway.agent_host_gateway or ""))
            except ValueError as exc:
                raise GatewayUnavailableError(
                    "cross-daemon agent host-gateway address is invalid"
                ) from exc
            if (
                host_gateway.version != 4
                or host_gateway.is_unspecified
                or host_gateway.is_loopback
                or host_gateway.is_multicast
                or host_gateway.is_link_local
            ):
                raise GatewayUnavailableError("cross-daemon agent host-gateway address is unsafe")
        else:
            if (
                not isinstance(gateway.agent_network, str)
                or _SAFE_NAME_RE.fullmatch(gateway.agent_network) is None
            ):
                raise GatewayUnavailableError("agent network name is invalid")
            if (
                not isinstance(gateway.expected_agent_network_id, str)
                or _SHA256_RE.fullmatch(gateway.expected_agent_network_id) is None
            ):
                raise GatewayUnavailableError("expected agent network ID is invalid")
            if gateway.agent_host_gateway is not None:
                raise GatewayUnavailableError(
                    "shared-daemon gateway unexpectedly configures a cross-daemon host gateway"
                )
        if _SHA256_RE.fullmatch(gateway.expected_program_sha256) is None:
            raise GatewayUnavailableError("expected gateway program SHA-256 is invalid")
        if _raw_sha256(gateway.expected_program_sha256) != program_sha256():
            raise GatewayUnavailableError(
                "gateway program SHA-256 does not match the local evaluator implementation"
            )
        if not 1024 <= gateway.listen_port <= 65535:
            raise GatewayUnavailableError("gateway listen port is invalid")
        if (
            gateway.endpoint_mode == "cross_daemon_host_gateway"
            and not 49_152 <= gateway.listen_port <= 65_535
        ):
            raise GatewayUnavailableError(
                "cross-daemon gateway requires a precommitted dynamic-range port"
            )
        if gateway.endpoint_mode not in {
            "host_loopback",
            "docker_alias",
            "cross_daemon_host_gateway",
        }:
            raise GatewayUnavailableError("gateway endpoint mode is invalid")
        if gateway.max_target_requests <= 0:
            raise GatewayUnavailableError("gateway target request limit must be positive")
        if gateway.max_request_body_bytes <= 0:
            raise GatewayUnavailableError("gateway request body limit must be positive")
        if gateway.max_request_body_bytes > MAX_BUFFERED_BODY_BYTES:
            raise GatewayUnavailableError("gateway request body limit exceeds the hard safety cap")
        if not 0 < gateway.max_response_body_bytes <= MAX_BUFFERED_BODY_BYTES:
            raise GatewayUnavailableError("gateway response body limit is invalid")
        if gateway.upstream_timeout_seconds <= 0:
            raise GatewayUnavailableError("gateway upstream timeout must be positive")
        if self.configuration.teardown_timeout_seconds <= gateway.upstream_timeout_seconds + 5:
            raise GatewayUnavailableError(
                "teardown timeout must exceed the gateway upstream timeout by more than five seconds"
            )
        if probe.attempts <= 0 or probe.per_attempt_timeout_seconds <= 0:
            raise GatewayUnavailableError("probe bounds must be positive")
        for label, value in (
            ("build", self.configuration.build_timeout_seconds),
            ("startup", self.configuration.startup_timeout_seconds),
            ("inspect", self.configuration.inspect_timeout_seconds),
            ("teardown", self.configuration.teardown_timeout_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{label} timeout must be positive")

    def _assert_project_unused(
        self,
        *,
        project: str,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        for resource in ("container", "network", "volume"):
            command = _project_inventory_command(resource=resource, project=project)
            result = self._docker(
                command,
                cwd=cwd,
                env=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                records=records,
                operation=f"preflight {resource} inventory",
            )
            _require_success(
                result, operation=f"Docker {resource} inventory", error_type=DockerEvidenceError
            )
            if result.stdout.strip():
                raise DockerEvidenceError(f"Docker project name collision for {project}")

    def _assert_container_name_unused(
        self,
        *,
        name: str,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        result = self._docker(
            _exact_container_name_inventory_command(name),
            cwd=cwd,
            env=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            records=records,
            operation="preflight gateway-name inventory",
        )
        _require_success(
            result,
            operation="preflight gateway-name inventory",
            error_type=DockerEvidenceError,
        )
        if result.stdout.strip():
            raise DockerEvidenceError("gateway container name is already reserved")

    def _inspect_target(
        self,
        *,
        state: _LiveState,
        records: list[dict[str, object]],
    ) -> dict[str, object]:
        env = _docker_environment(self.configuration.platform)
        ps = self._docker(
            (
                "docker",
                "compose",
                "-f",
                str(state.compose_path),
                "-p",
                state.project,
                "ps",
                "--all",
                "-q",
            ),
            cwd=state.compose_path.parent,
            env=env,
            timeout=self.configuration.inspect_timeout_seconds,
            records=records,
            operation="compose ps",
        )
        _require_success(ps, operation="compose ps", error_type=DockerEvidenceError)
        container_ids = tuple(line for line in _decoded_lines(ps.stdout) if line)
        expected_services = _declared_compose_services(state.compose_path)
        if len(container_ids) != len(expected_services):
            raise DockerEvidenceError(
                "Compose target container count does not match its declared service count"
            )
        inspected = self._docker_json(
            ("docker", "inspect", *container_ids),
            cwd=state.compose_path.parent,
            records=records,
            operation="target container inspect",
        )
        if not isinstance(inspected, list) or len(inspected) != len(container_ids):
            raise DockerEvidenceError("target container inspection is incomplete")
        evidence: list[dict[str, object]] = []
        image_ids: set[str] = set()
        for raw in inspected:
            if not isinstance(raw, dict):
                raise DockerEvidenceError("target container inspection is malformed")
            record = _verify_target_container(
                raw,
                project=state.project,
                network=state.network,
                private_source=state.materialized.root,
            )
            evidence.append(record)
            state.target_container_ids.add(str(record["container_id"]))
            image_ids.add(str(record["image_id"]))
            volume_names = record.get("volume_names")
            if isinstance(volume_names, list):
                state.target_volume_names.update(str(name) for name in volume_names)
        observed_services = [str(record.get("service") or "") for record in evidence]
        if len(set(observed_services)) != len(observed_services) or set(observed_services) != (
            expected_services
        ):
            raise DockerEvidenceError(
                "running target containers do not match the declared Compose services"
            )
        network_payload = self._docker_json(
            ("docker", "network", "inspect", state.network),
            cwd=state.compose_path.parent,
            records=records,
            operation="target network inspect",
        )
        if (
            not isinstance(network_payload, list)
            or len(network_payload) != 1
            or not isinstance(network_payload[0], dict)
        ):
            raise DockerEvidenceError("target network inspection is malformed")
        network_raw = network_payload[0]
        network_labels = _string_mapping(network_raw.get("Labels"))
        network_id = str(network_raw.get("Id") or "")
        if _SHA256_RE.fullmatch(network_id) is None:
            raise DockerEvidenceError("target network lacks an immutable Docker ID")
        if network_raw.get("Name") != state.network or network_raw.get("Internal") is not True:
            raise DockerEvidenceError("target network is not the required unique internal network")
        if network_labels.get(_INSTANCE_LABEL) != state.instance_id:
            raise DockerEvidenceError("target network instance label is invalid")
        state.target_network_id = network_id
        return {
            "evidence": {
                "containers": evidence,
                "network": {
                    "id": network_id,
                    "name": state.network,
                    "internal": True,
                    "instance_id": state.instance_id,
                },
            },
            "image_ids": sorted(image_ids),
        }

    def _inspect_images(
        self,
        *,
        image_ids: object,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        if (
            not isinstance(image_ids, list)
            or not image_ids
            or not all(isinstance(item, str) for item in image_ids)
        ):
            raise DockerEvidenceError("target image identity set is invalid")
        payload = self._docker_json(
            ("docker", "image", "inspect", *image_ids),
            cwd=cwd,
            records=records,
            operation="target image inspect",
        )
        if not isinstance(payload, list) or len(payload) != len(image_ids):
            raise DockerEvidenceError("target image inspection is incomplete")
        return [_image_evidence(item) for item in payload]

    def _inspect_prepared_service_images(
        self,
        *,
        image_references: Mapping[str, str],
        owned_references: set[str],
        cwd: Path,
        records: list[dict[str, object]],
    ) -> Mapping[str, Mapping[str, object]]:
        service_images: dict[str, Mapping[str, object]] = {}
        for service, reference in sorted(image_references.items()):
            payload = self._docker_json(
                ("docker", "image", "inspect", reference),
                cwd=cwd,
                records=records,
                operation=f"prepared service image inspect {service}",
            )
            if (
                not isinstance(payload, list)
                or len(payload) != 1
                or not isinstance(payload[0], dict)
            ):
                raise DockerEvidenceError("prepared service image inspection is incomplete")
            inspected = _image_evidence(payload[0])
            service_images[service] = {
                "service": service,
                "source_reference": reference,
                "image_id": inspected["id"],
                "repo_digests": inspected["repo_digests"],
                "created": inspected["created"],
                "architecture": inspected["architecture"],
                "os": inspected["os"],
                "size": inspected["size"],
                "rootfs_layers": inspected["rootfs_layers"],
                "owned_prepared_tag": reference in owned_references,
            }
        return service_images

    def _probe_readiness(
        self,
        *,
        case: XbenCase,
        state: _LiveState,
        records: list[dict[str, object]],
    ) -> Mapping[str, object]:
        probe = self.configuration.probe
        if probe is None:  # guarded before any source/Docker work
            raise GatewayUnavailableError("readiness probe is unavailable")
        service, port = _required_service_endpoint(case)
        state.gateway_upstream_service = service
        state.gateway_upstream_port = port
        self._verify_local_image(
            image=probe.image,
            expected_image_id=probe.expected_image_id,
            cwd=state.compose_path.parent,
            records=records,
            label="probe",
        )
        upstream = f"http://{service}:{port}/"
        attempts: list[dict[str, object]] = []
        for ordinal in range(1, probe.attempts + 1):
            result = self._docker(
                (
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network",
                    state.network,
                    probe.image,
                    "--silent",
                    "--show-error",
                    "--max-time",
                    str(probe.per_attempt_timeout_seconds),
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    upstream,
                ),
                cwd=state.compose_path.parent,
                env=_docker_environment(self.configuration.platform),
                timeout=probe.per_attempt_timeout_seconds + 5,
                records=records,
                operation=f"readiness probe {ordinal}",
            )
            status = result.stdout.decode("utf-8", errors="replace").strip()
            attempts.append(
                {
                    "ordinal": ordinal,
                    "returncode": result.returncode,
                    "http_status": status if status.isdigit() else None,
                }
            )
            if result.returncode == 0 and status.isdigit() and 100 <= int(status) < 500:
                return {
                    "status": "ready",
                    "upstream": upstream,
                    "probe_image": probe.image,
                    "probe_image_id": probe.expected_image_id,
                    "attempts": attempts,
                }
        raise DockerEvidenceError(
            "target did not become HTTP-ready within the bounded probe attempts"
        )

    def _start_gateway(
        self,
        *,
        case: XbenCase,
        state: _LiveState,
        gateway: GatewayConfiguration,
        records: list[dict[str, object]],
    ) -> tuple[Mapping[str, object], str]:
        service, port = _required_service_endpoint(case)
        self._verify_local_image(
            image=gateway.image,
            expected_image_id=gateway.expected_image_id,
            cwd=state.compose_path.parent,
            records=records,
            label="gateway",
        )
        cross_daemon = gateway.endpoint_mode == "cross_daemon_host_gateway"
        agent_network: Mapping[str, object] | None = None
        if not cross_daemon:
            agent_network = self._inspect_agent_network(
                gateway=gateway,
                instance_id=state.instance_id,
                cwd=state.compose_path.parent,
                records=records,
                expected_container_ids=set(),
                phase="pre-gateway",
            )
        alias = _GATEWAY_DOCKER_ALIAS
        publish_arguments: tuple[str, ...] = ()
        if gateway.endpoint_mode in {"host_loopback", "cross_daemon_host_gateway"}:
            publish_arguments = (
                "--publish",
                f"127.0.0.1:{gateway.listen_port}:{gateway.listen_port}",
            )
        # Store the deterministic name before creation so a client-side timeout
        # cannot orphan a container whose ID never reached the evaluator.
        state.gateway_id = state.gateway_name
        command = _gateway_serve_command(
            gateway=gateway,
            instance_id=state.instance_id,
            upstream_service=service,
            upstream_port=port,
        )
        initial_network = state.network if cross_daemon else str(gateway.agent_network)
        network_alias_arguments = () if cross_daemon else ("--network-alias", alias)
        run = self._docker(
            (
                "docker",
                "run",
                "-d",
                "--pull=never",
                "--name",
                state.gateway_name,
                "--label",
                f"{_GATEWAY_LABEL}=true",
                "--label",
                f"{_INSTANCE_LABEL}={state.instance_id}",
                "--label",
                f"com.docker.compose.project={state.project}",
                "--network",
                initial_network,
                *network_alias_arguments,
                *publish_arguments,
                "--read-only",
                "--tmpfs",
                (
                    f"{_GATEWAY_RUNTIME_DIR}:rw,noexec,nosuid,nodev,size=1m,"
                    "mode=0700,uid=65532,gid=65532"
                ),
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--pids-limit=64",
                "--memory=256m",
                "--cpus=0.25",
                "--no-healthcheck",
                "--user",
                _GATEWAY_UID_GID,
                "--entrypoint",
                "python3",
                gateway.image,
                *command,
            ),
            cwd=state.compose_path.parent,
            env=_docker_environment(self.configuration.platform),
            timeout=self.configuration.startup_timeout_seconds,
            records=records,
            operation="gateway create",
        )
        _require_success(run, operation="gateway create", error_type=GatewayUnavailableError)
        gateway_id = run.stdout.decode("utf-8", errors="replace").strip()
        if not gateway_id:
            raise GatewayUnavailableError("Docker did not return a gateway container ID")
        state.gateway_id = gateway_id
        state.gateway_created = True
        if not cross_daemon:
            connected = self._docker(
                (
                    "docker",
                    "network",
                    "connect",
                    state.network,
                    gateway_id,
                ),
                cwd=state.compose_path.parent,
                env=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                records=records,
                operation="gateway target-network connect",
            )
            _require_success(
                connected,
                operation="gateway network connect",
                error_type=GatewayUnavailableError,
            )
        payload = self._docker_json(
            ("docker", "inspect", gateway_id),
            cwd=state.compose_path.parent,
            records=records,
            operation="gateway inspect",
        )
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise DockerEvidenceError("gateway inspection is malformed")
        evidence = _verify_gateway_container(
            payload[0],
            gateway=gateway,
            instance_id=state.instance_id,
            target_network=state.network,
            target_network_id=state.target_network_id,
            private_source=state.materialized.root,
            agent_network_id=(str(agent_network["id"]) if agent_network is not None else None),
            agent_alias=alias if not cross_daemon else None,
            upstream_service=service,
            upstream_port=port,
        )
        attached_agent_network: Mapping[str, object] = {
            "status": "not-applicable",
            "reason": "cross-daemon gateway has no agent-daemon network attachment",
        }
        if not cross_daemon:
            attached_agent_network = self._inspect_agent_network(
                gateway=gateway,
                instance_id=state.instance_id,
                cwd=state.compose_path.parent,
                records=records,
                expected_container_ids={gateway_id},
                phase="post-gateway",
            )
        agent_ip = evidence.get("agent_listen_ip")
        if not isinstance(agent_ip, str) or not agent_ip:
            raise DockerEvidenceError("gateway inspection did not yield an agent-network address")
        state.gateway_agent_ip = agent_ip
        configured = self._docker(
            (
                "docker",
                "exec",
                gateway_id,
                "python3",
                "-m",
                _GATEWAY_MODULE,
                "configure",
                "--path",
                _GATEWAY_CONFIG_PATH,
                "--listen-host",
                agent_ip,
            ),
            cwd=state.compose_path.parent,
            env=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            records=records,
            operation="gateway bind configuration",
        )
        _require_success(
            configured,
            operation="gateway bind configuration",
            error_type=GatewayUnavailableError,
        )
        identity = self._docker_json(
            (
                "docker",
                "exec",
                gateway_id,
                "python3",
                "-m",
                _GATEWAY_MODULE,
                "identity",
            ),
            cwd=state.compose_path.parent,
            records=records,
            operation="gateway meter identity",
        )
        identity_evidence = _verify_meter_identity(identity, gateway=gateway)
        initial_receipt = self._read_meter_receipt(
            state=state,
            gateway=gateway,
            records=records,
            require_idle=True,
        )
        _validate_meter_receipt_context(
            initial_receipt,
            gateway=gateway,
            state=state,
            upstream_service=service,
            upstream_port=port,
            require_zero=True,
            require_sealed=False,
        )
        _write_json_exclusive(
            state.evidence_dir / "request-count-start.json",
            {"status": "verified", "receipt": initial_receipt},
        )
        state.gateway_meter_verified = True
        evidence = {
            **evidence,
            "agent_network_membership": attached_agent_network,
            "cross_daemon_boundary": {
                "enabled": cross_daemon,
                "agent_host_gateway": (gateway.agent_host_gateway if cross_daemon else None),
                "rootful_publish_host": "127.0.0.1" if cross_daemon else None,
                "rootful_gateway_target_network_only": (
                    evidence.get("rootful_target_network_only") is True if cross_daemon else None
                ),
                "agent_docker_network_attached": False if cross_daemon else None,
                "root_owned_uid_firewall_required": cross_daemon,
                "root_owned_uid_firewall_verified_here": False,
                "live_rootless_route_qualification_required": cross_daemon,
            },
            "meter_identity": identity_evidence,
            "startup_receipt_path": "request-count-start.json",
            "startup_receipt_sha256": _file_sha256(state.evidence_dir / "request-count-start.json"),
            "max_target_requests": gateway.max_target_requests,
            "protocol": HTTP_METER_PROTOCOL,
            "http_only": True,
            "caller_authentication": "none",
            "access_boundary": _gateway_access_boundary(gateway),
            "trusted_host_no_concurrent_local_adversary": (
                gateway.endpoint_mode == "host_loopback"
            ),
            "host_loopback_security_note": (
                "operational loopback isolation assumes a trusted evaluator host with no "
                "concurrent local adversary; it is not caller-authenticated"
                if gateway.endpoint_mode == "host_loopback"
                else None
            ),
            "http2_supported": False,
            "upstream_scheme": "http",
            "https_connect_supported": False,
            "websocket_upgrade_supported": False,
            "chunked_request_body_supported": False,
            "max_request_body_bytes": gateway.max_request_body_bytes,
            "chunked_response_supported": True,
            "response_without_content_length_supported": True,
            "streaming_response_supported": False,
            "response_trailers_forwarded": False,
            "upstream_must_complete_within_seconds": gateway.upstream_timeout_seconds,
            "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
            "max_response_body_bytes": gateway.max_response_body_bytes,
            "downstream_response_framing": "buffered-content-length-and-connection-close",
        }
        selected_host = (
            "127.0.0.1"
            if gateway.endpoint_mode == "host_loopback"
            else str(gateway.agent_host_gateway)
            if gateway.endpoint_mode == "cross_daemon_host_gateway"
            else alias
        )
        target_url = f"http://{selected_host}:{gateway.listen_port}"
        evidence = {
            **evidence,
            "endpoint_mode": gateway.endpoint_mode,
            "selected_url": target_url,
            "routes": {
                "docker_alias": {
                    "url": f"http://{alias}:{gateway.listen_port}",
                    "enabled": gateway.endpoint_mode != "cross_daemon_host_gateway",
                    "gateway_container_id": gateway_id,
                },
                "host_loopback": {
                    "url": f"http://127.0.0.1:{gateway.listen_port}",
                    "enabled": gateway.endpoint_mode == "host_loopback",
                    "gateway_container_id": gateway_id,
                },
                "cross_daemon_host_gateway": {
                    "url": (
                        f"http://{gateway.agent_host_gateway}:{gateway.listen_port}"
                        if gateway.endpoint_mode == "cross_daemon_host_gateway"
                        else None
                    ),
                    "enabled": gateway.endpoint_mode == "cross_daemon_host_gateway",
                    "gateway_container_id": gateway_id,
                    "rootful_publish_host": "127.0.0.1",
                },
            },
            "same_meter_and_upstream_contract": True,
        }
        return evidence, target_url

    def _inspect_agent_network(
        self,
        *,
        gateway: GatewayConfiguration,
        instance_id: str,
        cwd: Path,
        records: list[dict[str, object]],
        expected_container_ids: set[str],
        phase: str,
    ) -> Mapping[str, object]:
        if not isinstance(gateway.agent_network, str) or not isinstance(
            gateway.expected_agent_network_id, str
        ):
            raise DockerEvidenceError(
                "cross-daemon gateway cannot be inspected as an agent network"
            )
        payload = self._docker_json(
            ("docker", "network", "inspect", gateway.agent_network),
            cwd=cwd,
            records=records,
            operation="agent network inspect",
        )
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise DockerEvidenceError("agent network inspection is malformed")
        raw = payload[0]
        network_id = str(raw.get("Id") or "")
        labels = _string_mapping(raw.get("Labels"))
        if raw.get("Name") != gateway.agent_network:
            raise DockerEvidenceError("agent network name does not match the frozen contract")
        if network_id != _raw_sha256(gateway.expected_agent_network_id):
            raise DockerEvidenceError("agent network ID does not match the frozen contract")
        if labels.get(_AGENT_NETWORK_LABEL) != "true":
            raise DockerEvidenceError("agent network is not evaluator-owned")
        if labels.get(_INSTANCE_LABEL) != instance_id:
            raise DockerEvidenceError("agent network is not unique to the target instance")
        if raw.get("Internal") is not True:
            raise DockerEvidenceError("agent network must be Docker-internal")
        attached = raw.get("Containers")
        if attached is None:
            attached = {}
        if not isinstance(attached, dict) or any(
            not isinstance(container_id, str) or _RAW_SHA256_RE.fullmatch(container_id) is None
            for container_id in attached
        ):
            raise DockerEvidenceError("agent network membership is malformed")
        actual_container_ids = set(attached)
        if actual_container_ids != expected_container_ids:
            raise DockerEvidenceError(f"agent network membership is invalid during {phase}")
        return {
            "id": network_id,
            "name": raw.get("Name"),
            "internal": True,
            "evaluator_owned": True,
            "phase": phase,
            "container_ids": sorted(actual_container_ids),
        }

    def _verify_local_image(
        self,
        *,
        image: str,
        expected_image_id: str,
        cwd: Path,
        records: list[dict[str, object]],
        label: str,
    ) -> None:
        payload = self._docker_json(
            ("docker", "image", "inspect", image),
            cwd=cwd,
            records=records,
            operation=f"{label} image inspect",
        )
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise DockerEvidenceError(f"{label} image inspection is malformed")
        if payload[0].get("Id") != _normalized_sha256(expected_image_id):
            raise DockerEvidenceError(f"{label} image ID does not match its pinned digest")

    def _read_meter_receipt(
        self,
        *,
        state: _LiveState,
        gateway: GatewayConfiguration,
        records: list[dict[str, object]],
        require_idle: bool,
        require_sealed: bool = False,
    ) -> dict[str, object]:
        if state.gateway_id is None:
            raise DockerEvidenceError("gateway receipt requested without a gateway container")
        receipt_wait_seconds = gateway.upstream_timeout_seconds + 2
        command = [
            "docker",
            "exec",
            state.gateway_id,
            "python3",
            "-m",
            _GATEWAY_MODULE,
            "receipt",
            "--path",
            _GATEWAY_RECEIPT_PATH,
            "--wait-seconds",
            str(receipt_wait_seconds),
        ]
        if require_idle:
            command.append("--require-idle")
        if require_sealed:
            command.append("--require-sealed")
        result = self._docker(
            command,
            cwd=state.compose_path.parent,
            env=_docker_environment(self.configuration.platform),
            timeout=receipt_wait_seconds + 5,
            records=records,
            operation="gateway request-count receipt",
            redact=(state.expected_flag,),
        )
        _require_success(
            result,
            operation="gateway request-count receipt",
            error_type=DockerEvidenceError,
        )
        if len(result.stdout) > MAX_RECEIPT_BYTES:
            raise DockerEvidenceError("gateway request-count receipt exceeds its size limit")
        try:
            payload = json.loads(result.stdout)
            return validate_receipt_payload(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            raise DockerEvidenceError("gateway request-count receipt is malformed") from exc

    def _capture_gateway_logs(
        self,
        *,
        state: _LiveState,
        records: list[dict[str, object]],
    ) -> Mapping[str, object]:
        if state.gateway_id is None:
            return {"status": "not_started"}
        result = self._docker(
            ("docker", "logs", "--tail", "200", state.gateway_id),
            cwd=state.compose_path.parent,
            env=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            records=records,
            operation="gateway bounded logs",
            redact=(state.expected_flag,),
        )
        stdout = _bounded_gateway_log(result.stdout, redact=(state.expected_flag,))
        stderr = _bounded_gateway_log(result.stderr, redact=(state.expected_flag,))
        evidence: dict[str, object] = {
            "status": "captured" if result.returncode == 0 else "error",
            "tail_lines": 200,
            "max_bytes_per_stream": _MAX_GATEWAY_LOG_BYTES,
            "returncode": result.returncode,
            "stdout": stdout["text"],
            "stdout_truncated": stdout["truncated"],
            "stderr": stderr["text"],
            "stderr_truncated": stderr["truncated"],
        }
        _ensure_secret_absent(evidence, expected_flag=state.expected_flag)
        return evidence

    def _cleanup(
        self,
        *,
        state: _LiveState,
        records: list[dict[str, object]],
    ) -> Mapping[str, object]:
        errors: list[str] = []
        env = _docker_environment(self.configuration.platform)
        gateway = state.gateway_configuration
        request_count_evidence: dict[str, object] = {"status": "not_started"}
        if state.gateway_id is not None and not state.gateway_created:
            self._resolve_owned_gateway_after_uncertain_create(
                state=state,
                records=records,
                errors=errors,
            )
        agent_network_evidence: dict[str, object] = {}
        if gateway.endpoint_mode == "cross_daemon_host_gateway":
            agent_network_evidence["pre_seal"] = {
                "status": "not-applicable",
                "agent_network_attached": False,
                "reason": "rootful gateway remains only on its private target network",
            }
        agent_network_boundary_verified = True
        if (
            gateway is not None
            and gateway.endpoint_mode != "cross_daemon_host_gateway"
            and state.gateway_created
            and state.gateway_id is not None
            and _RAW_SHA256_RE.fullmatch(state.gateway_id) is not None
        ):
            try:
                agent_network_evidence["pre_seal"] = self._inspect_agent_network(
                    gateway=gateway,
                    instance_id=state.instance_id,
                    cwd=state.compose_path.parent,
                    records=records,
                    expected_container_ids={state.gateway_id},
                    phase="pre-seal",
                )
            except Exception as exc:  # noqa: BLE001 - still seal and clean the target.
                agent_network_boundary_verified = False
                errors.append("agent network membership could not be verified before sealing")
                agent_network_evidence["pre_seal"] = {
                    "status": "error",
                    "error": _safe_error_without_flag(exc, expected_flag=state.expected_flag),
                }
        request_meter: dict[str, object] = {
            "schema_version": REQUEST_METER_STOP_SCHEMA_VERSION,
            "receipt_schema_version": HTTP_METER_SCHEMA_VERSION,
            "protocol": HTTP_METER_PROTOCOL,
            "meter_program_sha256": (
                _raw_sha256(gateway.expected_program_sha256) if gateway is not None else None
            ),
            "instance_id": state.instance_id,
            "endpoint_mode": gateway.endpoint_mode if gateway is not None else None,
            "access_boundary": _gateway_access_boundary(gateway) if gateway else None,
            "caller_authentication": "none",
            "trusted_host_no_concurrent_local_adversary": (
                gateway is not None and gateway.endpoint_mode == "host_loopback"
            ),
            "sealed": False,
            "http_only": True,
            "https_connect_supported": False,
            "websocket_upgrade_supported": False,
            "chunked_request_body_supported": False,
            "max_request_body_bytes": gateway.max_request_body_bytes if gateway else None,
            "max_response_body_bytes": gateway.max_response_body_bytes if gateway else None,
            "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
            "observed_count": None,
            "accepted_count": None,
            "target_request_attempt_count": None,
            "unsupported_count": None,
            "rejected_over_limit_count": None,
            "upstream_error_count": None,
            "oversize_response_count": None,
            "hard_limit": gateway.max_target_requests if gateway is not None else None,
            "limit_enforced": False,
            "complete": False,
            "receipt_path": None,
            "receipt_sha256": None,
            "verification_kind": "operational-docker-inspection-and-meter-receipt",
            "cryptographically_attested": False,
            "valid": False,
        }
        gateway_log_evidence: Mapping[str, object] = {"status": "not_started"}
        if state.gateway_meter_verified:
            try:
                if gateway is None:
                    raise DockerEvidenceError("gateway configuration disappeared before teardown")
                if state.gateway_id is None:
                    raise DockerEvidenceError("gateway identity disappeared before teardown")
                sealed = self._docker(
                    ("docker", "kill", "--signal=USR1", state.gateway_id),
                    cwd=state.compose_path.parent,
                    env=env,
                    timeout=self.configuration.inspect_timeout_seconds,
                    records=records,
                    operation="gateway admission seal",
                )
                _require_success(
                    sealed,
                    operation="gateway admission seal",
                    error_type=DockerEvidenceError,
                )
                receipt = self._read_meter_receipt(
                    state=state,
                    gateway=gateway,
                    records=records,
                    require_idle=True,
                    require_sealed=True,
                )
                if state.gateway_upstream_service is None or state.gateway_upstream_port is None:
                    raise DockerEvidenceError("gateway upstream identity is unavailable")
                _validate_meter_receipt_context(
                    receipt,
                    gateway=gateway,
                    state=state,
                    upstream_service=state.gateway_upstream_service,
                    upstream_port=state.gateway_upstream_port,
                    require_zero=False,
                    require_sealed=True,
                )
                request_count_evidence = {
                    "status": "verified",
                    "receipt": receipt,
                    "enforcement": "hard inbound HTTP request allowance",
                    "http_only": True,
                    "terminal_admission_closed": True,
                }
                _ensure_secret_absent(
                    request_count_evidence,
                    expected_flag=state.expected_flag,
                )
                _write_json_exclusive(
                    state.evidence_dir / "request-count.json",
                    request_count_evidence,
                )
                request_count_path = state.evidence_dir / "request-count.json"
                candidate_request_meter: dict[str, object] = {
                    "schema_version": REQUEST_METER_STOP_SCHEMA_VERSION,
                    "receipt_schema_version": HTTP_METER_SCHEMA_VERSION,
                    "protocol": HTTP_METER_PROTOCOL,
                    "meter_program_sha256": receipt["program_sha256"],
                    "instance_id": state.instance_id,
                    "endpoint_mode": gateway.endpoint_mode,
                    "access_boundary": receipt["access_boundary"],
                    "caller_authentication": receipt["caller_authentication"],
                    "trusted_host_no_concurrent_local_adversary": receipt[
                        "trusted_host_no_concurrent_local_adversary"
                    ],
                    "sealed": receipt["sealed"],
                    "http_only": True,
                    "https_connect_supported": False,
                    "websocket_upgrade_supported": False,
                    "chunked_request_body_supported": False,
                    "max_request_body_bytes": receipt["max_request_body_bytes"],
                    "max_response_body_bytes": receipt["max_response_body_bytes"],
                    "max_concurrent_requests": receipt["max_concurrent_requests"],
                    "observed_count": receipt["observed_requests"],
                    "accepted_count": receipt["accepted_requests"],
                    "target_request_attempt_count": receipt["target_request_attempts"],
                    "unsupported_count": receipt["unsupported_requests"],
                    "rejected_over_limit_count": receipt["rejected_over_limit"],
                    "upstream_error_count": receipt["upstream_errors"],
                    "oversize_response_count": receipt["oversize_responses"],
                    "hard_limit": receipt["max_target_requests"],
                    "limit_enforced": True,
                    "complete": True,
                    "receipt_path": str(request_count_path),
                    "receipt_sha256": _file_sha256(request_count_path),
                    "verification_kind": "operational-docker-inspection-and-meter-receipt",
                    "cryptographically_attested": False,
                    "valid": True,
                }
                if agent_network_boundary_verified:
                    request_meter = validate_request_meter_stop_provenance(
                        candidate_request_meter,
                        evidence_dir=state.evidence_dir,
                    )
                else:
                    candidate_request_meter["complete"] = False
                    candidate_request_meter["valid"] = False
                    request_meter = candidate_request_meter
            except Exception as exc:  # noqa: BLE001 - invalid receipt must not prevent cleanup.
                errors.append("gateway request-count receipt could not be verified")
                request_count_evidence = {
                    "status": "error",
                    "error": _safe_error_without_flag(exc, expected_flag=state.expected_flag),
                }
        if state.gateway_created:
            try:
                gateway_log_evidence = self._capture_gateway_logs(
                    state=state,
                    records=records,
                )
                if gateway_log_evidence.get("status") != "captured":
                    errors.append("gateway logs could not be captured")
                _write_json_exclusive(
                    state.evidence_dir / "gateway-log.json",
                    gateway_log_evidence,
                )
            except Exception as exc:  # noqa: BLE001 - retain cleanup despite evidence failure.
                errors.append("gateway logs could not be retained")
                gateway_log_evidence = {
                    "status": "error",
                    "error": _safe_error_without_flag(exc, expected_flag=state.expected_flag),
                }
        if state.gateway_created and state.gateway_id is not None:
            try:
                gateway_down = self._docker(
                    ("docker", "rm", "-f", state.gateway_id),
                    cwd=state.compose_path.parent,
                    env=env,
                    timeout=self.configuration.teardown_timeout_seconds,
                    records=records,
                    operation="gateway teardown",
                )
                if gateway_down.returncode != 0:
                    errors.append("gateway teardown command failed")
            except Exception:  # noqa: BLE001 - continue cleaning independent resources.
                errors.append("gateway teardown command did not complete")
        if gateway is not None and gateway.endpoint_mode != "cross_daemon_host_gateway":
            try:
                agent_network_evidence["post_gateway_removal"] = self._inspect_agent_network(
                    gateway=gateway,
                    instance_id=state.instance_id,
                    cwd=state.compose_path.parent,
                    records=records,
                    expected_container_ids=set(),
                    phase="post-gateway-removal",
                )
            except Exception as exc:  # noqa: BLE001 - continue target cleanup.
                agent_network_boundary_verified = False
                errors.append("agent network membership is not empty after gateway removal")
                agent_network_evidence["post_gateway_removal"] = {
                    "status": "error",
                    "error": _safe_error_without_flag(exc, expected_flag=state.expected_flag),
                }
        elif gateway is not None:
            agent_network_evidence["post_gateway_removal"] = {
                "status": "not-applicable",
                "agent_network_attached": False,
            }
        try:
            down = self._docker(
                (
                    "docker",
                    "compose",
                    "-f",
                    str(state.compose_path),
                    "-p",
                    state.project,
                    "down",
                    "--remove-orphans",
                    "-v",
                ),
                cwd=state.compose_path.parent,
                env=env,
                timeout=self.configuration.teardown_timeout_seconds,
                records=records,
                operation="compose teardown",
            )
            if down.returncode != 0:
                errors.append("compose teardown command failed")
        except Exception:  # noqa: BLE001 - inventories may still prove partial cleanup.
            errors.append("compose teardown command did not complete")
        residual: dict[str, list[str]] = {}
        for resource in ("container", "network", "volume"):
            try:
                listed = self._docker(
                    _project_inventory_command(resource=resource, project=state.project),
                    cwd=state.compose_path.parent,
                    env=env,
                    timeout=self.configuration.inspect_timeout_seconds,
                    records=records,
                    operation=f"post-teardown {resource} inventory",
                )
            except Exception:  # noqa: BLE001 - retain an explicit unavailable result.
                errors.append(f"post-teardown {resource} inventory failed")
                residual[resource] = ["inventory_unavailable"]
                continue
            if listed.returncode != 0:
                errors.append(f"post-teardown {resource} inventory failed")
                residual[resource] = ["inventory_unavailable"]
                continue
            residual[resource] = _decoded_lines(listed.stdout)
            if residual[resource]:
                errors.append(f"residual Docker {resource} resources remain")
        known_residual = self._known_resource_residuals(state=state, records=records)
        for resource, identities in known_residual.items():
            if identities:
                errors.append(f"known target {resource} resources remain")
        try:
            _remove_private_instance(
                root=state.materialized.root,
                private_root=self.materializer.private_root,
            )
        except Exception:  # noqa: BLE001 - report and retain all other terminal evidence.
            errors.append("private source workspace removal failed")
        workspace_removed = not state.materialized.root.exists()
        if not workspace_removed:
            errors.append("private source workspace remains")
        if not agent_network_boundary_verified and request_meter.get("valid") is True:
            request_meter["complete"] = False
            request_meter["valid"] = False
        evidence = {
            "status": "succeeded" if not errors else "error",
            "project": state.project,
            "gateway_removed": state.gateway_id is None or not residual.get("container"),
            "workspace_removed": workspace_removed,
            "residual_resources": residual,
            "known_resource_residuals": known_residual,
            "request_count": request_count_evidence,
            "request_meter": request_meter,
            "gateway_logs": gateway_log_evidence,
            "agent_network_membership": agent_network_evidence,
            "errors": errors,
            "commands": records,
        }
        _ensure_secret_absent(evidence, expected_flag=state.expected_flag)
        try:
            _write_json_exclusive(state.evidence_dir / "teardown.json", evidence)
        except FileExistsError as exc:
            raise TeardownVerificationError("teardown evidence path was already reserved") from exc
        if errors:
            raise TeardownVerificationError("; ".join(errors))
        request_count_path = state.evidence_dir / "request-count.json"
        result: dict[str, object] = {
            "removed": True,
            "verified": True,
            "project": state.project,
            "evidence_path": str(state.evidence_dir / "teardown.json"),
            "evidence_sha256": _file_sha256(state.evidence_dir / "teardown.json"),
            "request_count": request_count_evidence,
            "request_meter": request_meter,
        }
        if request_count_path.is_file():
            result["request_count_receipt_path"] = str(request_count_path)
            result["request_count_receipt_sha256"] = _file_sha256(request_count_path)
        return result

    def _resolve_owned_gateway_after_uncertain_create(
        self,
        *,
        state: _LiveState,
        records: list[dict[str, object]],
        errors: list[str],
    ) -> None:
        """Resolve a timed-out create without ever deleting an unowned name collision."""
        try:
            listed = self._docker(
                _exact_container_name_inventory_command(state.gateway_name),
                cwd=state.compose_path.parent,
                env=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                records=records,
                operation="uncertain gateway-name inventory",
            )
        except Exception:  # noqa: BLE001 - never delete an identity that was not resolved.
            errors.append("uncertain gateway creation could not be inventoried")
            return
        if listed.returncode != 0:
            errors.append("uncertain gateway creation could not be inventoried")
            return
        identities = _decoded_lines(listed.stdout)
        if not identities:
            state.gateway_id = None
            return
        if len(identities) != 1 or _RAW_SHA256_RE.fullmatch(identities[0]) is None:
            errors.append("uncertain gateway creation has an ambiguous identity")
            return
        gateway_id = identities[0]
        try:
            payload = self._docker_json(
                ("docker", "inspect", gateway_id),
                cwd=state.compose_path.parent,
                records=records,
                operation="uncertain gateway ownership inspect",
            )
        except Exception:  # noqa: BLE001 - never delete an identity that was not verified.
            errors.append("uncertain gateway ownership could not be inspected")
            return
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            errors.append("uncertain gateway ownership inspection is malformed")
            return
        raw = payload[0]
        labels = _string_mapping(_mapping(raw.get("Config")).get("Labels"))
        gateway = state.gateway_configuration
        owned = (
            str(raw.get("Id") or "") == gateway_id
            and str(raw.get("Name") or "").lstrip("/") == state.gateway_name
            and labels.get(_GATEWAY_LABEL) == "true"
            and labels.get(_INSTANCE_LABEL) == state.instance_id
            and labels.get("com.docker.compose.project") == state.project
            and gateway is not None
            and raw.get("Image") == _normalized_sha256(gateway.expected_image_id)
        )
        if not owned:
            errors.append("uncertain gateway name is occupied by an unowned container")
            return
        state.gateway_id = gateway_id
        state.gateway_created = True

    def _known_resource_residuals(
        self,
        *,
        state: _LiveState,
        records: list[dict[str, object]],
    ) -> dict[str, list[str]]:
        checks: tuple[tuple[str, tuple[str, ...], set[str]], ...] = (
            (
                "container",
                ("docker", "container", "ls", "-aq", "--no-trunc"),
                state.target_container_ids
                | (
                    {state.gateway_id}
                    if state.gateway_id and _SHA256_RE.fullmatch(state.gateway_id)
                    else set()
                ),
            ),
            (
                "network",
                ("docker", "network", "ls", "-q", "--no-trunc"),
                {state.target_network_id} if state.target_network_id else set(),
            ),
            (
                "volume",
                ("docker", "volume", "ls", "-q"),
                state.target_volume_names,
            ),
        )
        residuals: dict[str, list[str]] = {}
        for resource, command, known in checks:
            try:
                listed = self._docker(
                    command,
                    cwd=state.compose_path.parent,
                    env=_docker_environment(self.configuration.platform),
                    timeout=self.configuration.inspect_timeout_seconds,
                    records=records,
                    operation=f"post-teardown complete {resource} inventory",
                )
            except Exception:  # noqa: BLE001 - cleanup evidence must record uncertainty.
                residuals[resource] = ["inventory_unavailable"]
                continue
            if listed.returncode != 0:
                residuals[resource] = ["inventory_unavailable"]
                continue
            present = set(_decoded_lines(listed.stdout))
            residuals[resource] = sorted(known & present)
        return residuals

    def _docker_json(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        records: list[dict[str, object]],
        operation: str,
    ) -> object:
        result = self._docker(
            command,
            cwd=cwd,
            env=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            records=records,
            operation=operation,
        )
        _require_success(result, operation=operation, error_type=DockerEvidenceError)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise DockerEvidenceError(f"{operation} returned invalid JSON") from exc

    def _docker(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: int,
        records: list[dict[str, object]],
        operation: str,
        redact: Sequence[str] = (),
    ) -> CommandResult:
        if timeout <= 0:
            raise ValueError("Docker timeout must be positive")
        result = self.runner.run(
            command,
            cwd=cwd,
            environment=env,
            timeout_seconds=timeout,
        )
        records.append(
            _command_evidence(result, operation=operation, timeout=timeout, redact=redact)
        )
        return result


@dataclass(frozen=True)
class PreparedTargetArmBackend:
    """Bind the legacy row lifecycle to one evaluator-owned prepared pair arm."""

    backend: DockerComparisonTargetBackend
    prepared: PreparedCase
    arm: Literal["ravage", "strix"]

    def start(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        instance_id: str,
    ) -> ExternalTarget:
        if self.arm not in _PREPARED_ARMS:
            raise ComparisonTargetError("prepared target adapter arm is invalid")
        if case != self.prepared.case:
            raise ComparisonTargetError("prepared target adapter case binding is invalid")
        if _EXPECTED_FLAG_RE.fullmatch(expected_flag) is None:
            raise ComparisonTargetError("prepared target adapter flag format is invalid")
        expected_digest = self.prepared.provenance.get("pair_flag_sha256")
        actual_digest = hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
        if not isinstance(expected_digest, str) or not secrets.compare_digest(
            actual_digest,
            expected_digest,
        ):
            raise ComparisonTargetError("prepared target adapter flag binding is invalid")
        return self.backend.start_prepared(
            prepared=self.prepared,
            arm=self.arm,
            instance_id=instance_id,
        )

    def stop(self, *, target: ExternalTarget) -> Mapping[str, object]:
        provenance = target.build_provenance
        if (
            provenance.get("schema_version") != PREPARED_TARGET_ARM_SCHEMA_VERSION
            or provenance.get("pair_id") != self.prepared.pair_id
            or provenance.get("arm") != self.arm
        ):
            raise TeardownVerificationError("prepared target adapter received a foreign target")
        return self.backend.stop(target=target)


def _validate_prepared_arm_abandonment_receipt(
    *,
    prepared: PreparedCase,
    arm: str,
    instance_id: str,
    expected_sha256: str,
) -> Mapping[str, object]:
    path = prepared.evidence_dir / f"abandoned-{arm}.json"
    if path.is_symlink() or not path.is_file():
        raise TeardownVerificationError("prepared target abandonment evidence is unavailable")
    raw = path.read_bytes()
    if len(raw) > _MAX_EVIDENCE_STREAM_BYTES:
        raise TeardownVerificationError(
            "prepared target abandonment evidence exceeds its size limit"
        )
    if _RAW_SHA256_RE.fullmatch(expected_sha256) is None or not secrets.compare_digest(
        hashlib.sha256(raw).hexdigest(), expected_sha256
    ):
        raise TeardownVerificationError("prepared target abandonment evidence digest is invalid")
    if _EXPECTED_FLAG_RE.search(raw.decode("utf-8", errors="replace")) is not None:
        raise TeardownVerificationError("prepared target abandonment evidence leaks the pair flag")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TeardownVerificationError(
            "prepared target abandonment evidence is malformed"
        ) from exc
    expected_keys = {
        "schema_version",
        "pair_id",
        "benchmark_id",
        "arm",
        "instance_id",
        "pair_flag_sha256",
        "prepared_provenance_sha256",
        "reason_code",
        "target_backend_start_attempted",
        "row_terminal",
        "created_at",
        "verification_kind",
        "cryptographically_attested",
        "valid",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise TeardownVerificationError(
            "prepared target abandonment evidence has an invalid field set"
        )
    expected_values = {
        "schema_version": PREPARED_TARGET_ARM_ABANDONMENT_SCHEMA_VERSION,
        "pair_id": prepared.pair_id,
        "benchmark_id": prepared.benchmark_id,
        "arm": arm,
        "instance_id": instance_id,
        "pair_flag_sha256": prepared.provenance.get("pair_flag_sha256"),
        "prepared_provenance_sha256": prepared.provenance_sha256,
        "target_backend_start_attempted": False,
        "row_terminal": True,
        "verification_kind": "evaluator-lifecycle-state-transition",
        "cryptographically_attested": False,
        "valid": True,
    }
    for name, expected in expected_values.items():
        if payload.get(name) != expected:
            raise TeardownVerificationError(
                f"prepared target abandonment field {name!r} is invalid"
            )
    if payload.get("reason_code") not in _PREPARED_ARM_ABANDONMENT_REASONS:
        raise TeardownVerificationError("prepared target abandonment reason is invalid")
    try:
        created_at = datetime.fromisoformat(str(payload.get("created_at") or ""))
    except ValueError as exc:
        raise TeardownVerificationError("prepared target abandonment timestamp is invalid") from exc
    if created_at.tzinfo is None:
        raise TeardownVerificationError("prepared target abandonment timestamp lacks a timezone")
    return payload


def _validate_prepared_case_handle(prepared: PreparedCase) -> None:
    if (
        _SAFE_NAME_RE.fullmatch(prepared.pair_id) is None
        or prepared.benchmark_id != prepared.case.benchmark_id
        or prepared.provenance.get("pair_id") != prepared.pair_id
        or prepared.provenance.get("benchmark_id") != prepared.benchmark_id
    ):
        raise ComparisonTargetError("prepared target handle identity is invalid")
    expected_flag_digest = prepared.provenance.get("pair_flag_sha256")
    actual_flag_digest = hashlib.sha256(prepared.expected_flag.encode("utf-8")).hexdigest()
    if (
        _EXPECTED_FLAG_RE.fullmatch(prepared.expected_flag) is None
        or not isinstance(expected_flag_digest, str)
        or not secrets.compare_digest(actual_flag_digest, expected_flag_digest)
    ):
        raise ComparisonTargetError("prepared target handle flag binding is invalid")
    prepared_path = prepared.evidence_dir / "prepared.json"
    if prepared_path.is_symlink() or not prepared_path.is_file():
        raise ComparisonTargetError("prepared target handle provenance is unavailable")
    raw = prepared_path.read_bytes()
    if len(raw) > _MAX_RETAINED_DOCUMENT_BYTES:
        raise ComparisonTargetError("prepared target handle provenance exceeds its size limit")
    if not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), prepared.provenance_sha256):
        raise ComparisonTargetError("prepared target handle provenance digest is invalid")
    try:
        retained = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ComparisonTargetError("prepared target handle provenance is malformed") from exc
    validated = validate_prepared_target_provenance(
        retained,
        evidence_dir=prepared.evidence_dir,
    )
    if validated != dict(prepared.provenance):
        raise ComparisonTargetError("prepared target handle differs from retained provenance")
    raw_records = validated.get("service_images")
    if not isinstance(raw_records, list):
        raise ComparisonTargetError("prepared target handle image records are invalid")
    retained_records = {
        str(record["service"]): record
        for record in raw_records
        if isinstance(record, dict) and isinstance(record.get("service"), str)
    }
    handle_records = {
        str(service): dict(record) for service, record in prepared.service_images.items()
    }
    if retained_records != handle_records:
        raise ComparisonTargetError("prepared target handle image records drifted")
    retained_owned = tuple(
        sorted(
            str(record["source_reference"])
            for record in raw_records
            if isinstance(record, dict) and record.get("owned_prepared_tag") is True
        )
    )
    if retained_owned != tuple(sorted(prepared.owned_image_references)):
        raise ComparisonTargetError("prepared target handle image ownership drifted")
    if prepared.pristine_case_manifest.get("sha256") != validated.get(
        "prepared_source_tree_sha256"
    ):
        raise ComparisonTargetError("prepared target handle source closure drifted")
    try:
        materialized_root = prepared.materialized.root.resolve(strict=True)
        materialized_case = prepared.materialized.case_path.resolve(strict=True)
        prepare_compose = prepared.prepare_compose_path.resolve(strict=True)
        materialized_case.relative_to(materialized_root)
        prepare_compose.relative_to(materialized_case)
    except (OSError, ValueError) as exc:
        raise ComparisonTargetError("prepared target handle private paths are invalid") from exc


def _write_sanitized_compose(
    *,
    case_path: Path,
    project: str,
    network_name: str,
    instance_id: str,
) -> tuple[Path, Mapping[str, object]]:
    source_path = _find_compose(case_path)
    raw = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise UnsafeComposeError("Compose document must be a mapping")
    if "include" in raw:
        raise UnsafeComposeError("Compose include is not allowed in comparison targets")
    services = raw.get("services")
    if not isinstance(services, dict) or not services:
        raise UnsafeComposeError("Compose services are missing")
    network_key = "ravage_comparison_target"
    removed_ports = 0
    rewritten_containers = 0
    local_only_image_references = 0
    private_root = case_path.resolve()
    for service_name, value in services.items():
        if not isinstance(value, dict):
            raise UnsafeComposeError(f"Compose service {service_name!r} is not a mapping")
        forbidden = sorted(
            key
            for key in (
                "cap_add",
                "cgroup",
                "cgroup_parent",
                "device_cgroup_rules",
                "devices",
                "dns",
                "dns_opt",
                "dns_search",
                "external_links",
                "extends",
                "gpus",
                "ipc",
                "isolation",
                "logging",
                "network_mode",
                "pid",
                "privileged",
                "provider",
                "runtime",
                "security_opt",
                "storage_opt",
                "sysctls",
                "use_api",
                "userns_mode",
                "uts",
                "volumes_from",
                "credential_spec",
                "deploy",
            )
            if key in value
        )
        if forbidden:
            raise UnsafeComposeError(
                f"Compose service {service_name!r} uses forbidden settings: {', '.join(forbidden)}"
            )
        _validate_service_paths(value, private_root=private_root)
        if "pull_policy" in value:
            raise UnsafeComposeError(
                f"Compose service {service_name!r} declares its own pull policy"
            )
        value["pull_policy"] = "never"
        declared_platform = value.get("platform")
        if declared_platform not in {None, "linux/amd64"}:
            raise UnsafeComposeError(
                f"Compose service {service_name!r} declares a non-frozen platform"
            )
        value["platform"] = "linux/amd64"
        if "image" in value:
            local_only_image_references += 1
        raw_ports = value.pop("ports", [])
        if isinstance(raw_ports, list):
            removed_ports += len(raw_ports)
        elif raw_ports:
            removed_ports += 1
        if value.pop("container_name", None) is not None:
            rewritten_containers += 1
        value["networks"] = [network_key]
        value["labels"] = _merged_labels(
            value.get("labels"),
            {
                _INSTANCE_LABEL: instance_id,
                "com.ravage.evaluator.target": "true",
            },
        )
    raw.pop("name", None)
    raw["networks"] = {
        network_key: {
            "name": network_name,
            "internal": True,
            "labels": {
                _INSTANCE_LABEL: instance_id,
                "com.ravage.evaluator.target-network": "true",
            },
        }
    }
    volumes = raw.get("volumes")
    if volumes is not None:
        if not isinstance(volumes, dict):
            raise UnsafeComposeError("top-level Compose volumes must be a mapping")
        rewritten_volumes: dict[str, object] = {}
        for ordinal, (name, value) in enumerate(sorted(volumes.items()), start=1):
            if value is not None and not isinstance(value, dict):
                raise UnsafeComposeError(f"Compose volume {name!r} is not a mapping")
            config = dict(value or {})
            if config.get("external"):
                raise UnsafeComposeError(f"external Compose volume {name!r} is forbidden")
            unsupported_volume_keys = sorted(set(config) - {"external", "labels", "name"})
            if unsupported_volume_keys:
                raise UnsafeComposeError(
                    f"Compose volume {name!r} uses unsupported host driver settings"
                )
            config.pop("external", None)
            config["name"] = f"{project}_volume_{ordinal:03d}"
            config["labels"] = _merged_labels(
                config.get("labels"),
                {_INSTANCE_LABEL: instance_id},
            )
            rewritten_volumes[str(name)] = config
        raw["volumes"] = rewritten_volumes
    for resource_kind in ("configs", "secrets"):
        resources = raw.get(resource_kind)
        if resources is None:
            continue
        if not isinstance(resources, dict):
            raise UnsafeComposeError(f"top-level Compose {resource_kind} must be a mapping")
        rewritten_resources: dict[str, object] = {}
        for ordinal, (name, value) in enumerate(sorted(resources.items()), start=1):
            if not isinstance(value, dict):
                raise UnsafeComposeError(f"Compose {resource_kind[:-1]} {name!r} is not a mapping")
            config = dict(value)
            if config.get("external"):
                raise UnsafeComposeError(
                    f"external Compose {resource_kind[:-1]} {name!r} is forbidden"
                )
            if set(config) - {"file", "name", "labels", "external"}:
                raise UnsafeComposeError(
                    f"Compose {resource_kind[:-1]} {name!r} uses a non-file source"
                )
            source_file = config.get("file")
            if source_file is None:
                raise UnsafeComposeError(
                    f"Compose {resource_kind[:-1]} {name!r} must use a private file"
                )
            _validate_private_relative_path(
                str(source_file),
                private_root=private_root,
                label=f"{resource_kind[:-1]} file",
            )
            config.pop("external", None)
            config["name"] = f"{project}_{resource_kind[:-1]}_{ordinal:03d}"
            config["labels"] = _merged_labels(
                config.get("labels"),
                {_INSTANCE_LABEL: instance_id},
            )
            rewritten_resources[str(name)] = config
        raw[resource_kind] = rewritten_resources
    output_path = source_path.with_name("ravage-comparison.compose.yml")
    if output_path.exists():
        raise UnsafeComposeError("runtime Compose output already exists")
    output_path.write_text(
        yaml.safe_dump(raw, sort_keys=True, default_flow_style=False),
        encoding="utf-8",
    )
    return output_path, {
        "source_compose_relative_path": source_path.relative_to(case_path).as_posix(),
        "runtime_compose_relative_path": output_path.relative_to(case_path).as_posix(),
        "source_compose_sha256": _file_sha256(source_path),
        "runtime_compose_sha256": _file_sha256(output_path),
        "published_ports_removed": removed_ports,
        "container_names_removed": rewritten_containers,
        "network_name": network_name,
        "network_internal": True,
        "unique_volume_count": len(raw.get("volumes", {})),
        "runtime_pull_policy": "never",
        "local_only_image_reference_count": local_only_image_references,
        "explicit_build_network_controls_forbidden": True,
    }


def _assign_prepared_image_references(
    *,
    compose_path: Path,
    project: str,
) -> tuple[Mapping[str, str], tuple[str, ...]]:
    raw = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = _mapping(raw).get("services")
    if not isinstance(raw, dict) or not isinstance(services, dict) or not services:
        raise UnsafeComposeError("prepared Compose services are missing")
    references: dict[str, str] = {}
    owned: list[str] = []
    for service_name, raw_service in sorted(services.items()):
        if (
            not isinstance(service_name, str)
            or _SAFE_NAME_RE.fullmatch(service_name) is None
            or not isinstance(raw_service, dict)
        ):
            raise UnsafeComposeError("prepared Compose service identity is invalid")
        if "build" in raw_service:
            service_digest = hashlib.sha256(service_name.encode()).hexdigest()[:16]
            reference = f"{project}-prepared-{service_digest}:pair"
            raw_service["image"] = reference
            owned.append(reference)
        else:
            raw_reference = raw_service.get("image")
            if (
                not isinstance(raw_reference, str)
                or not raw_reference
                or "$" in raw_reference
                or any(character.isspace() for character in raw_reference)
            ):
                raise UnsafeComposeError(
                    "prepared Compose image-only service lacks a concrete local reference"
                )
            reference = raw_reference
        raw_service["pull_policy"] = "never"
        references[service_name] = reference
    compose_path.write_text(
        yaml.safe_dump(raw, sort_keys=True, default_flow_style=False),
        encoding="utf-8",
    )
    return references, tuple(sorted(owned))


def _bind_prepared_service_images(
    *,
    compose_path: Path,
    service_images: Mapping[str, Mapping[str, object]],
) -> Mapping[str, object]:
    raw = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = _mapping(raw).get("services")
    if not isinstance(raw, dict) or not isinstance(services, dict):
        raise UnsafeComposeError("prepared runtime Compose services are missing")
    if set(services) != set(service_images):
        raise DockerEvidenceError("prepared runtime service set drifted from its build")
    image_ids: dict[str, str] = {}
    removed_builds = 0
    for service, raw_service in services.items():
        if not isinstance(raw_service, dict):
            raise UnsafeComposeError("prepared runtime Compose service is malformed")
        record = service_images[str(service)]
        image_id = record.get("image_id")
        if not isinstance(image_id, str) or _SHA256_RE.fullmatch(image_id) is None:
            raise DockerEvidenceError("prepared runtime image ID is invalid")
        if raw_service.pop("build", None) is not None:
            removed_builds += 1
        raw_service["image"] = image_id
        raw_service["pull_policy"] = "never"
        image_ids[str(service)] = image_id
    compose_path.write_text(
        yaml.safe_dump(raw, sort_keys=True, default_flow_style=False),
        encoding="utf-8",
    )
    return {
        "prepared_provenance_bound": True,
        "build_definitions_removed": removed_builds,
        "runtime_build_allowed": False,
        "runtime_pull_allowed": False,
        "image_ids_by_service": dict(sorted(image_ids.items())),
        "runtime_compose_sha256": _file_sha256(compose_path),
    }


def _copy_prepared_materialization(
    *,
    prepared: PreparedCase,
    private_root: Path,
    instance_id: str,
) -> MaterializedCase:
    prepare_compose_relative = prepared.prepare_compose_path.relative_to(
        prepared.materialized.case_path
    ).as_posix()
    current_pristine = _tree_manifest_excluding(
        prepared.materialized.case_path,
        excluded={prepare_compose_relative},
    )
    if current_pristine != prepared.pristine_case_manifest:
        raise SourceMaterializationError("prepared private source changed after its build")
    root = _claim_private_instance_dir(private_root, instance_id)
    try:
        shutil.copytree(
            prepared.materialized.root,
            root,
            dirs_exist_ok=True,
            symlinks=False,
        )
        relative_case = prepared.materialized.case_path.relative_to(prepared.materialized.root)
        case_path = root / relative_case
        copied_prepare_compose = case_path.joinpath(*PurePosixPath(prepare_compose_relative).parts)
        copied_prepare_compose.unlink()
        copied_manifest = _tree_manifest(case_path)
        if copied_manifest != prepared.pristine_case_manifest:
            raise SourceMaterializationError("prepared arm source copy failed closure verification")
        source_evidence = dict(prepared.materialized.source_evidence)
        source_evidence["prepared_pair_binding"] = {
            "schema_version": PREPARED_TARGET_SCHEMA_VERSION,
            "pair_id": prepared.pair_id,
            "prepared_provenance_path": str(prepared.evidence_dir / "prepared.json"),
            "prepared_provenance_sha256": prepared.provenance_sha256,
            "prepared_source_tree_sha256": copied_manifest["sha256"],
            "private_arm_copy": True,
        }
        return MaterializedCase(root=root, case_path=case_path, source_evidence=source_evidence)
    except Exception:
        _remove_private_instance(root=root, private_root=private_root)
        raise


def _verify_prepared_container_images(
    *,
    target_inspection: Mapping[str, object],
    service_images: Mapping[str, Mapping[str, object]],
) -> None:
    evidence = _mapping(target_inspection.get("evidence"))
    raw_containers = evidence.get("containers")
    if not isinstance(raw_containers, list):
        raise DockerEvidenceError("prepared target container evidence is missing")
    observed: dict[str, str] = {}
    for raw_container in raw_containers:
        if not isinstance(raw_container, dict):
            raise DockerEvidenceError("prepared target container evidence is malformed")
        service = raw_container.get("service")
        image_id = raw_container.get("image_id")
        if not isinstance(service, str) or not isinstance(image_id, str) or service in observed:
            raise DockerEvidenceError("prepared target container identity is invalid")
        observed[service] = image_id
    expected = {
        service: str(record.get("image_id") or "") for service, record in service_images.items()
    }
    if observed != expected:
        raise DockerEvidenceError("prepared target container image IDs drifted from the pair build")


def _declared_compose_services(compose_path: Path) -> set[str]:
    raw = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("services"), dict):
        raise DockerEvidenceError("runtime Compose service declaration is malformed")
    services = {str(name) for name in raw["services"]}
    if not services:
        raise DockerEvidenceError("runtime Compose declares no services")
    return services


def _validate_service_paths(service: Mapping[str, object], *, private_root: Path) -> None:
    for key in ("env_file",):
        values = service.get(key)
        entries = values if isinstance(values, list) else [values] if values is not None else []
        for entry in entries:
            if isinstance(entry, dict):
                if set(entry) - {"path", "required", "format"} or not entry.get("path"):
                    raise UnsafeComposeError("Compose env_file entry is invalid")
                entry = entry["path"]
            if not isinstance(entry, str):
                raise UnsafeComposeError("Compose env_file entry must be a private path")
            _validate_private_relative_path(entry, private_root=private_root, label=key)
    build = service.get("build")
    if isinstance(build, str):
        _validate_private_relative_path(build, private_root=private_root, label="build context")
    elif isinstance(build, dict):
        forbidden_build_features = sorted(
            key
            for key in (
                "additional_contexts",
                "cache_from",
                "cache_to",
                "entitlements",
                "network",
                "privileged",
                "pull",
                "secrets",
                "ssh",
                "tags",
            )
            if key in build
        )
        if forbidden_build_features:
            raise UnsafeComposeError(
                "Compose build uses forbidden host/remote inputs: "
                + ", ".join(forbidden_build_features)
            )
        context = build.get("context", ".")
        _validate_private_relative_path(
            str(context), private_root=private_root, label="build context"
        )
        dockerfile = build.get("dockerfile")
        if dockerfile is not None:
            _validate_private_relative_path(
                str(dockerfile), private_root=private_root, label="dockerfile"
            )
    volumes = service.get("volumes")
    if volumes is not None and not isinstance(volumes, list):
        raise UnsafeComposeError("Compose service volumes must be a list")
    if isinstance(volumes, list):
        for entry in volumes:
            if isinstance(entry, dict):
                volume_type = str(entry.get("type") or "volume")
                if volume_type not in {"bind", "tmpfs", "volume"}:
                    raise UnsafeComposeError("Compose volume type is unsupported")
                if volume_type == "tmpfs" and (
                    entry.get("source") is not None or entry.get("src") is not None
                ):
                    raise UnsafeComposeError("Compose tmpfs mount must not declare a source")
            source = _volume_source(entry)
            if (
                isinstance(entry, dict)
                and str(entry.get("type") or "") == "bind"
                and source is None
            ):
                raise UnsafeComposeError("Compose bind mount requires a private source path")
            if source is None:
                continue
            _reject_compose_interpolation(source, label="volume source")
            if _looks_like_named_volume(source):
                continue
            _validate_private_relative_path(source, private_root=private_root, label="bind mount")
            if "docker.sock" in source.lower():
                raise UnsafeComposeError("Docker socket mounts are forbidden")
    extra_hosts = service.get("extra_hosts")
    if extra_hosts:
        raise UnsafeComposeError("extra_hosts is forbidden in comparison targets")


def _volume_source(entry: object) -> str | None:
    if isinstance(entry, str):
        if ":" not in entry:
            return None
        return entry.split(":", maxsplit=1)[0]
    if isinstance(entry, dict) and str(entry.get("type") or "") == "bind":
        source = entry.get("source") or entry.get("src")
        return str(source) if source is not None else None
    return None


def _looks_like_named_volume(source: str) -> bool:
    return "/" not in source and "\\" not in source and source not in {".", ".."}


def _reject_compose_interpolation(value: str, *, label: str) -> None:
    # Compose interpolation happens after this YAML-level sanitizer. Any '$'
    # in a host-side path can therefore turn a value that appears relative here
    # into an absolute path (or into a different named resource) at execution.
    # Reject '$$' too: Compose reduces it to a literal '$', so accepting it
    # would make the retained document differ from the path we validated.
    if "$" in value:
        raise UnsafeComposeError(f"Compose interpolation in {label} is forbidden")


def _validate_private_relative_path(value: str, *, private_root: Path, label: str) -> None:
    _reject_compose_interpolation(value, label=label)
    if "://" in value or value.startswith(("~", "git@")):
        raise UnsafeComposeError(f"remote or home-relative {label} is forbidden")
    path = Path(value)
    if path.is_absolute():
        raise UnsafeComposeError(f"absolute {label} is forbidden")
    resolved = (private_root / path).resolve()
    try:
        resolved.relative_to(private_root)
    except ValueError as exc:
        raise UnsafeComposeError(f"{label} escapes the private case copy") from exc


def _verify_target_container(
    raw: Mapping[str, object],
    *,
    project: str,
    network: str,
    private_source: Path,
) -> dict[str, object]:
    container_id = str(raw.get("Id") or "")
    if _SHA256_RE.fullmatch(container_id) is None:
        raise DockerEvidenceError("target container ID is missing")
    config = _mapping(raw.get("Config"))
    host = _mapping(raw.get("HostConfig"))
    labels = _string_mapping(config.get("Labels"))
    state = _mapping(raw.get("State"))
    network_settings = _mapping(raw.get("NetworkSettings"))
    networks = _mapping(network_settings.get("Networks"))
    if labels.get("com.docker.compose.project") != project:
        raise DockerEvidenceError("target container has the wrong Compose project label")
    if labels.get("com.ravage.evaluator.target") != "true":
        raise DockerEvidenceError("target container lacks the evaluator target label")
    if state.get("Running") is not True:
        raise DockerEvidenceError("target container is not running")
    healthcheck = _mapping(config.get("Healthcheck"))
    health_test = healthcheck.get("Test")
    health_required = bool(
        isinstance(health_test, list)
        and health_test
        and [str(item).upper() for item in health_test] != ["NONE"]
    )
    health_status: str | None = None
    if health_required:
        health_status = str(_mapping(state.get("Health")).get("Status") or "")
        if health_status != "healthy":
            raise DockerEvidenceError("target container healthcheck is not healthy")
    if host.get("Privileged") is not False:
        raise DockerEvidenceError("target container is privileged")
    if host.get("PidMode") not in {None, ""} or host.get("IpcMode") not in {None, "", "private"}:
        raise DockerEvidenceError("target container shares a host namespace")
    cap_add = host.get("CapAdd")
    if isinstance(cap_add, list) and cap_add:
        raise DockerEvidenceError("target container has added Linux capabilities")
    devices = host.get("Devices")
    if isinstance(devices, list) and devices:
        raise DockerEvidenceError("target container has host devices")
    device_requests = host.get("DeviceRequests")
    if isinstance(device_requests, list) and device_requests:
        raise DockerEvidenceError("target container has host device requests")
    if set(networks) != {network}:
        raise DockerEvidenceError("target container is attached outside its unique target network")
    if _published_bindings(host.get("PortBindings")) or _published_bindings(
        network_settings.get("Ports")
    ):
        raise DockerEvidenceError("target container has published host ports")
    mounts = raw.get("Mounts")
    if not isinstance(mounts, list):
        raise DockerEvidenceError("target mount inspection is malformed")
    volume_names: list[str] = []
    private_bind_mount_count = 0
    for mount in mounts:
        if not isinstance(mount, dict):
            raise DockerEvidenceError("target mount inspection is malformed")
        source = str(mount.get("Source") or "")
        destination = str(mount.get("Destination") or "")
        if str(mount.get("Type") or "") == "bind":
            private_bind_mount_count += 1
            try:
                Path(source).resolve().relative_to(private_source.resolve())
            except ValueError as exc:
                raise DockerEvidenceError(
                    "target bind mount escapes the private source copy"
                ) from exc
        if "docker.sock" in source.lower() or "docker.sock" in destination.lower():
            raise DockerEvidenceError("target container can access a Docker socket")
        if str(mount.get("Type") or "") == "volume":
            volume_name = str(mount.get("Name") or source)
            if not volume_name:
                raise DockerEvidenceError("target volume mount lacks an immutable name")
            volume_names.append(volume_name)
    image_id = str(raw.get("Image") or "")
    if _SHA256_RE.fullmatch(image_id) is None:
        raise DockerEvidenceError("target container image ID is missing")
    return {
        "container_id": container_id,
        "name": str(raw.get("Name") or "").lstrip("/"),
        "service": labels.get("com.docker.compose.service"),
        "image_id": image_id,
        "running": True,
        "healthcheck_required": health_required,
        "health_status": health_status,
        "networks": sorted(networks),
        "published_host_ports": [],
        "docker_socket_mounted": False,
        "private_bind_mount_count": private_bind_mount_count,
        "volume_names": sorted(volume_names),
    }


def _gateway_serve_command(
    *,
    gateway: GatewayConfiguration,
    instance_id: str,
    upstream_service: str,
    upstream_port: int,
) -> tuple[str, ...]:
    return (
        "-m",
        _GATEWAY_MODULE,
        "serve",
        "--listen-config",
        _GATEWAY_CONFIG_PATH,
        "--receipt",
        _GATEWAY_RECEIPT_PATH,
        "--instance-id",
        instance_id,
        "--listen-port",
        str(gateway.listen_port),
        "--upstream-host",
        upstream_service,
        "--upstream-port",
        str(upstream_port),
        "--max-target-requests",
        str(gateway.max_target_requests),
        "--access-boundary",
        _gateway_access_boundary(gateway),
        "--max-request-body-bytes",
        str(gateway.max_request_body_bytes),
        "--max-response-body-bytes",
        str(gateway.max_response_body_bytes),
        "--upstream-timeout-seconds",
        str(gateway.upstream_timeout_seconds),
    )


def _verify_meter_identity(
    payload: object,
    *,
    gateway: GatewayConfiguration,
) -> Mapping[str, object]:
    expected = {
        "schema_version": HTTP_METER_SCHEMA_VERSION,
        "program_sha256": _raw_sha256(gateway.expected_program_sha256),
        "protocol": HTTP_METER_PROTOCOL,
    }
    if payload != expected:
        raise DockerEvidenceError(
            "gateway meter program identity does not match the frozen contract"
        )
    return {**expected, "derived_from": "docker exec inside inspected pinned image"}


def _gateway_access_boundary(gateway: GatewayConfiguration) -> str:
    if gateway.endpoint_mode == "host_loopback":
        return "trusted-host-loopback"
    if gateway.endpoint_mode == "cross_daemon_host_gateway":
        return "root-owned-cross-daemon-loopback"
    return "evaluator-owned-docker-network"


def _runtime_gateway_configuration(gateway: GatewayConfiguration) -> GatewayConfiguration:
    if gateway.endpoint_mode != "host_loopback":
        return gateway
    # A high-entropy port is not caller authentication. It only narrows
    # accidental cross-run interference under the explicitly retained trusted-
    # host assumption. Docker creation fails closed if the chosen port collides.
    return replace(gateway, listen_port=49_152 + secrets.randbelow(16_384))


def _validate_meter_receipt_context(
    receipt: Mapping[str, object],
    *,
    gateway: GatewayConfiguration,
    state: _LiveState,
    upstream_service: str,
    upstream_port: int,
    require_zero: bool,
    require_sealed: bool,
) -> None:
    expected = {
        "schema_version": HTTP_METER_SCHEMA_VERSION,
        "program_sha256": _raw_sha256(gateway.expected_program_sha256),
        "protocol": HTTP_METER_PROTOCOL,
        "instance_id": state.instance_id,
        "ready": True,
        "sealed": require_sealed,
        "access_boundary": _gateway_access_boundary(gateway),
        "caller_authentication": "none",
        "trusted_host_no_concurrent_local_adversary": (gateway.endpoint_mode == "host_loopback"),
        "listen_host": state.gateway_agent_ip,
        "listen_port": gateway.listen_port,
        "upstream_host": upstream_service,
        "upstream_port": upstream_port,
        "max_target_requests": gateway.max_target_requests,
        "max_request_body_bytes": gateway.max_request_body_bytes,
        "max_response_body_bytes": gateway.max_response_body_bytes,
        "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
    }
    for name, value in expected.items():
        if receipt.get(name) != value:
            raise DockerEvidenceError(
                f"gateway request-count receipt field {name!r} does not match the run contract"
            )
    if receipt.get("in_flight_requests") != 0:
        raise DockerEvidenceError("gateway request-count receipt is not terminal")
    if require_zero:
        for name in (
            "observed_requests",
            "accepted_requests",
            "target_request_attempts",
            "unsupported_requests",
            "rejected_over_limit",
            "upstream_errors",
            "oversize_responses",
        ):
            if receipt.get(name) != 0:
                raise DockerEvidenceError("gateway startup receipt is not at zero")


def _verify_gateway_tmpfs(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {_GATEWAY_RUNTIME_DIR}:
        raise DockerEvidenceError("gateway receipt tmpfs is missing or ambiguous")
    options = {item.strip().lower() for item in str(value[_GATEWAY_RUNTIME_DIR]).split(",")}
    required = {
        "rw",
        "noexec",
        "nosuid",
        "nodev",
        "mode=0700",
        "uid=65532",
        "gid=65532",
    }
    if not required.issubset(options) or not ({"size=1m", "size=1048576"} & options):
        raise DockerEvidenceError("gateway receipt tmpfs options are unsafe")


def _verify_gateway_port_binding(
    *,
    gateway: GatewayConfiguration,
    host_bindings: object,
    runtime_ports: object,
) -> list[dict[str, str]]:
    expected_key = f"{gateway.listen_port}/tcp"
    host_payload = host_bindings if isinstance(host_bindings, dict) else {}
    runtime_payload = runtime_ports if isinstance(runtime_ports, dict) else {}
    if gateway.endpoint_mode == "docker_alias":
        if _published_bindings(host_payload) or _published_bindings(runtime_payload):
            raise DockerEvidenceError("Docker-alias gateway unexpectedly publishes a host port")
        return []
    if set(host_payload) != {expected_key} or set(runtime_payload) != {expected_key}:
        raise DockerEvidenceError("host-loopback gateway port binding is incomplete or ambiguous")
    expected = {"HostIp": "127.0.0.1", "HostPort": str(gateway.listen_port)}
    host_entries = host_payload.get(expected_key)
    runtime_entries = runtime_payload.get(expected_key)
    if host_entries != [expected] or runtime_entries != [expected]:
        raise DockerEvidenceError(
            "gateway port is not bound exactly to the contracted loopback port"
        )
    return [
        {
            "host_ip": "127.0.0.1",
            "host_port": str(gateway.listen_port),
            "container_port": str(gateway.listen_port),
            "protocol": "tcp",
        }
    ]


def _verify_gateway_mounts(
    value: object,
    *,
    private_source: Path,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise DockerEvidenceError("gateway mount inspection is malformed")
    evidence: list[dict[str, object]] = []
    for mount in value:
        if not isinstance(mount, dict):
            raise DockerEvidenceError("gateway mount inspection entry is malformed")
        source = str(mount.get("Source") or "")
        destination = str(mount.get("Destination") or "")
        mount_type = str(mount.get("Type") or "")
        if (
            mount_type != "tmpfs"
            or destination != _GATEWAY_RUNTIME_DIR
            or source
            or "docker.sock" in source.lower()
            or "docker.sock" in destination.lower()
            or _is_within(Path(source), private_source)
        ):
            raise DockerEvidenceError(
                "gateway can access a non-ephemeral mount, evaluator source, or Docker control"
            )
        evidence.append(
            {
                "type": "tmpfs",
                "destination": _GATEWAY_RUNTIME_DIR,
                "read_write": mount.get("RW") is True,
            }
        )
    if len(evidence) > 1:
        raise DockerEvidenceError("gateway has multiple receipt tmpfs mounts")
    return evidence


def _verify_gateway_container(
    raw: Mapping[str, object],
    *,
    gateway: GatewayConfiguration,
    instance_id: str,
    target_network: str,
    target_network_id: str | None,
    private_source: Path,
    agent_network_id: str | None,
    agent_alias: str | None,
    upstream_service: str,
    upstream_port: int,
) -> Mapping[str, object]:
    container_id = str(raw.get("Id") or "")
    if _SHA256_RE.fullmatch(container_id) is None:
        raise DockerEvidenceError("gateway container ID is missing")
    config = _mapping(raw.get("Config"))
    labels = _string_mapping(config.get("Labels"))
    state = _mapping(raw.get("State"))
    host = _mapping(raw.get("HostConfig"))
    network_settings = _mapping(raw.get("NetworkSettings"))
    networks = _mapping(network_settings.get("Networks"))
    if raw.get("Image") != _normalized_sha256(gateway.expected_image_id):
        raise DockerEvidenceError("gateway container image ID does not match the frozen contract")
    if labels.get(_GATEWAY_LABEL) != "true" or labels.get(_INSTANCE_LABEL) != instance_id:
        raise DockerEvidenceError("gateway ownership labels do not match the target instance")
    if state.get("Running") is not True:
        raise DockerEvidenceError("gateway container is not running")
    target_attachment = _mapping(networks.get(target_network))
    if target_network_id is None or target_attachment.get("NetworkID") != target_network_id:
        raise DockerEvidenceError("gateway target-network attachment has the wrong ID")
    cross_daemon = gateway.endpoint_mode == "cross_daemon_host_gateway"
    if cross_daemon:
        if set(networks) != {target_network}:
            raise DockerEvidenceError(
                "cross-daemon gateway is not attached only to the private target network"
            )
        if agent_network_id is not None or agent_alias is not None:
            raise DockerEvidenceError(
                "cross-daemon gateway inspection unexpectedly accepts an agent network"
            )
        listen_attachment = target_attachment
    else:
        if not isinstance(gateway.agent_network, str) or set(networks) != {
            target_network,
            gateway.agent_network,
        }:
            raise DockerEvidenceError(
                "gateway is not attached to exactly the target and agent networks"
            )
        agent_attachment = _mapping(networks.get(gateway.agent_network))
        if agent_attachment.get("NetworkID") != agent_network_id:
            raise DockerEvidenceError("gateway agent-network attachment has the wrong ID")
        aliases = agent_attachment.get("Aliases")
        if not isinstance(aliases, list) or agent_alias not in aliases:
            raise DockerEvidenceError("gateway agent-network alias is unavailable")
        listen_attachment = agent_attachment
    raw_agent_ip = str(listen_attachment.get("IPAddress") or "")
    try:
        agent_ip = ipaddress.ip_address(raw_agent_ip)
    except ValueError as exc:
        raise DockerEvidenceError("gateway agent-network address is invalid") from exc
    if (
        agent_ip.version != 4
        or agent_ip.is_unspecified
        or agent_ip.is_loopback
        or agent_ip.is_multicast
    ):
        raise DockerEvidenceError("gateway agent-network address is unsafe")
    if host.get("Privileged") is not False or host.get("ReadonlyRootfs") is not True:
        raise DockerEvidenceError("gateway privilege boundary is incomplete")
    cap_drop = host.get("CapDrop")
    if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
        raise DockerEvidenceError("gateway did not drop all Linux capabilities")
    security_opt = host.get("SecurityOpt")
    if not isinstance(security_opt, list) or not any(
        "no-new-privileges" in str(item) for item in security_opt
    ):
        raise DockerEvidenceError("gateway lacks no-new-privileges")
    if host.get("PidsLimit") != 64 or host.get("Memory") != 256 * 1024 * 1024:
        raise DockerEvidenceError("gateway process or memory limit is not enforced")
    if host.get("NanoCpus") != 250_000_000:
        raise DockerEvidenceError("gateway CPU limit is not enforced")
    if config.get("Entrypoint") != ["python3"]:
        raise DockerEvidenceError("gateway entrypoint is not the evaluator HTTP meter")
    if config.get("User") != _GATEWAY_UID_GID:
        raise DockerEvidenceError("gateway is not running as the frozen unprivileged user")
    if _mapping(config.get("Healthcheck")).get("Test") != ["NONE"]:
        raise DockerEvidenceError("gateway image healthcheck was not disabled")
    expected_command = list(
        _gateway_serve_command(
            gateway=gateway,
            instance_id=instance_id,
            upstream_service=upstream_service,
            upstream_port=upstream_port,
        )
    )
    if config.get("Cmd") != expected_command:
        raise DockerEvidenceError("gateway command does not match the evaluator-owned route")
    published_ports = _verify_gateway_port_binding(
        gateway=gateway,
        host_bindings=host.get("PortBindings"),
        runtime_ports=network_settings.get("Ports"),
    )
    _verify_gateway_tmpfs(host.get("Tmpfs"))
    mounts = raw.get("Mounts")
    mount_evidence = _verify_gateway_mounts(mounts, private_source=private_source)
    return {
        "status": "verified",
        "container_id": container_id,
        "image": gateway.image,
        "image_id": raw.get("Image"),
        "networks": sorted(networks),
        "agent_network_id": agent_network_id,
        "agent_network_attached": not cross_daemon,
        "rootful_target_network_only": cross_daemon,
        "agent_listen_ip": str(agent_ip),
        "target_network": target_network,
        "published_host_ports": published_ports,
        "read_only": True,
        "user": _GATEWAY_UID_GID,
        "privileged": False,
        "capabilities_dropped": ["ALL"],
        "no_new_privileges": True,
        "mounts": mount_evidence,
        "evaluator_source_mounted": False,
        "docker_socket_mounted": False,
        "mount_verification": "operational-docker-inspect",
        "derived_from": "docker inspect",
    }


def _image_evidence(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise DockerEvidenceError("target image inspection entry is malformed")
    image_id = raw.get("Id")
    if not isinstance(image_id, str) or _SHA256_RE.fullmatch(image_id) is None:
        raise DockerEvidenceError("target image inspection lacks an immutable image ID")
    root_fs = _mapping(raw.get("RootFS"))
    layers = root_fs.get("Layers")
    return {
        "id": image_id,
        "repo_digests": raw.get("RepoDigests") if isinstance(raw.get("RepoDigests"), list) else [],
        "created": raw.get("Created"),
        "architecture": raw.get("Architecture"),
        "os": raw.get("Os"),
        "size": raw.get("Size"),
        "rootfs_layers": layers if isinstance(layers, list) else [],
    }


def _extract_safe_git_archive(payload: bytes, *, root: Path) -> None:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
    except tarfile.TarError as exc:
        raise SourceMaterializationError("git archive output is not a valid tar archive") from exc
    members = archive.getmembers()
    if len(members) > _MAX_ARCHIVE_MEMBERS:
        raise SourceMaterializationError("case archive contains too many entries")
    total_size = sum(member.size for member in members if member.isfile())
    if total_size > _MAX_ARCHIVE_BYTES:
        raise SourceMaterializationError("expanded case archive exceeds the size limit")
    for member in members:
        pure = PurePosixPath(member.name)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts:
            raise SourceMaterializationError("case archive contains an unsafe path")
        destination = root.joinpath(*pure.parts)
        if member.isdir():
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            continue
        if not member.isfile():
            raise SourceMaterializationError("case archive links and special entries are forbidden")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise SourceMaterializationError("case archive file content is unavailable")
        with destination.open("xb") as output:
            shutil.copyfileobj(source, output)
        mode = 0o700 if member.mode & stat.S_IXUSR else 0o600
        destination.chmod(mode)


def _tree_manifest(root: Path) -> Mapping[str, object]:
    files: list[dict[str, object]] = []
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise SourceMaterializationError("source tree symlinks are forbidden")
        if not path.is_file():
            continue
        content = path.read_bytes()
        file_sha = hashlib.sha256(content).hexdigest()
        files.append({"path": relative, "sha256": file_sha, "size_bytes": len(content)})
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_sha))
        digest.update(b"\0")
    return {
        "sha256": digest.hexdigest(),
        "file_count": len(files),
        "files": files,
    }


def _tree_manifest_excluding(
    root: Path,
    *,
    excluded: set[str],
) -> Mapping[str, object]:
    files: list[dict[str, object]] = []
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        if path.is_symlink():
            raise SourceMaterializationError("source tree symlinks are forbidden")
        if not path.is_file():
            continue
        content = path.read_bytes()
        file_sha = hashlib.sha256(content).hexdigest()
        files.append({"path": relative, "sha256": file_sha, "size_bytes": len(content)})
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_sha))
        digest.update(b"\0")
    return {"sha256": digest.hexdigest(), "file_count": len(files), "files": files}


def _manifest_file_identities(manifest: Mapping[str, object]) -> Mapping[str, tuple[str, int]]:
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise SourceMaterializationError("source tree manifest is malformed")
    identities: dict[str, tuple[str, int]] = {}
    for raw_file in raw_files:
        if not isinstance(raw_file, dict):
            raise SourceMaterializationError("source tree manifest entry is malformed")
        path = raw_file.get("path")
        sha256 = raw_file.get("sha256")
        size_bytes = raw_file.get("size_bytes")
        if (
            not isinstance(path, str)
            or not isinstance(sha256, str)
            or _RAW_SHA256_RE.fullmatch(sha256) is None
            or type(size_bytes) is not int
            or size_bytes < 0
            or path in identities
        ):
            raise SourceMaterializationError("source tree manifest entry is invalid")
        identities[path] = (sha256, size_bytes)
    return identities


def _verify_compatibility_patch_delta(
    *,
    before: Mapping[str, object],
    after: Mapping[str, object],
    configured: CompatibilityPatch | None,
    case_prefix: PurePosixPath,
) -> None:
    before_files = _manifest_file_identities(before)
    after_files = _manifest_file_identities(after)
    observed = {
        path
        for path in before_files.keys() | after_files.keys()
        if before_files.get(path) != after_files.get(path)
    }
    if configured is None:
        if observed:
            raise SourceMaterializationError(
                "unlisted case changed despite the catalog's default no-patch policy"
            )
        return
    expected: set[str] = set()
    for touched_file in configured.touched_files:
        try:
            expected.add(touched_file.relative_to(case_prefix).as_posix())
        except ValueError as exc:
            raise SourceMaterializationError(
                "compatibility catalog patch touches a different case"
            ) from exc
    if observed != expected:
        raise SourceMaterializationError(
            "compatibility patch changed files outside its catalog declaration"
        )


def _reject_entries_outside_case(*, root: Path, case_path: Path) -> None:
    for path in root.rglob("*"):
        if path == case_path or path in case_path.parents:
            continue
        try:
            path.relative_to(case_path)
        except ValueError as exc:
            raise SourceMaterializationError(
                "compatibility patch wrote outside the selected case"
            ) from exc


def _claim_private_instance_dir(private_root: Path, instance_id: str) -> Path:
    root = private_root.expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    claimed = root / instance_id
    try:
        claimed.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise SourceMaterializationError("private target workspace already exists") from exc
    return claimed


def _claim_evidence_dir(evidence_root: Path, instance_id: str) -> Path:
    root = evidence_root.expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    claimed = root / instance_id
    try:
        claimed.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise ComparisonTargetError("target evidence directory already exists") from exc
    return claimed


def _remove_private_instance(*, root: Path, private_root: Path) -> None:
    expected_parent = private_root.expanduser().resolve()
    resolved = root.resolve()
    if resolved.parent != expected_parent or resolved == expected_parent:
        raise TeardownVerificationError("refusing to remove an unscoped target workspace")
    if resolved.exists():
        shutil.rmtree(resolved)


def _find_compose(case_path: Path) -> Path:
    direct = [case_path / name for name in _COMPOSE_NAMES if (case_path / name).is_file()]
    nested = [path for name in _COMPOSE_NAMES for path in case_path.glob(f"*/{name}")]
    candidates = sorted((*direct, *nested))
    if not candidates:
        raise UnsafeComposeError("selected case has no Compose file")
    if len(candidates) != 1:
        raise UnsafeComposeError("selected case has multiple ambiguous Compose files")
    return candidates[0]


def _required_service_endpoint(case: XbenCase) -> tuple[str, int]:
    if not case.main_service or case.main_service_port is None:
        raise UnsafeComposeError("case metadata must declare main service and port")
    if _SAFE_NAME_RE.fullmatch(case.main_service) is None:
        raise UnsafeComposeError("case main service name is invalid")
    if not 1 <= case.main_service_port <= 65535:
        raise UnsafeComposeError("case main service port is invalid")
    return case.main_service, case.main_service_port


def _validate_pinned_image(image: str, expected_id: str, *, label: str) -> None:
    if _IMAGE_DIGEST_RE.fullmatch(image) is None:
        raise GatewayUnavailableError(f"{label} image must be pinned by repository digest")
    if _SHA256_RE.fullmatch(expected_id) is None:
        raise GatewayUnavailableError(f"{label} expected image ID is invalid")


def _validate_instance_id(instance_id: str) -> None:
    if _SAFE_NAME_RE.fullmatch(instance_id) is None:
        raise ComparisonTargetError("target instance ID is invalid")


def _docker_project_name(instance_id: str) -> str:
    nonce = secrets.token_hex(8)
    identity = hashlib.sha256(f"{instance_id}:{nonce}".encode()).hexdigest()[:20]
    return f"ravagecmp_{identity}"


def _minimal_command_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "LC_ALL": "C",
        "LANG": "C",
    }


def _docker_environment(platform: str) -> dict[str, str]:
    environment = _minimal_command_environment()
    environment["DOCKER_DEFAULT_PLATFORM"] = platform
    for name in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _require_success(
    result: CommandResult,
    *,
    operation: str,
    error_type: type[ComparisonTargetError],
) -> None:
    if result.returncode == 0:
        return
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    if not detail:
        detail = result.stdout.decode("utf-8", errors="replace").strip()
    safe_detail = _bounded_text(_redact_text(detail, redact=()))
    raise error_type(f"{operation} failed with status {result.returncode}: {safe_detail}")


def _command_evidence(
    result: CommandResult,
    *,
    operation: str,
    timeout: int,
    redact: Sequence[str],
) -> dict[str, object]:
    argv = [_redact_text(part, redact=redact) for part in result.command]
    stdout = _redact_bytes(result.stdout, redact=redact)
    stderr = _redact_bytes(result.stderr, redact=redact)
    return {
        "operation": operation,
        "argv": argv,
        "timeout_seconds": timeout,
        "returncode": result.returncode,
        "elapsed_seconds": round(result.elapsed_seconds, 6),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_excerpt": _bounded_text(stdout.decode("utf-8", errors="replace")),
        "stderr_excerpt": _bounded_text(stderr.decode("utf-8", errors="replace")),
    }


def _redact_bytes(value: bytes, *, redact: Sequence[str]) -> bytes:
    text = value.decode("utf-8", errors="replace")
    return _redact_text(text, redact=redact).encode("utf-8")


def _redact_text(value: str, *, redact: Sequence[str]) -> str:
    redacted = value
    for sensitive in redact:
        if sensitive:
            redacted = redacted.replace(sensitive, "[REDACTED_EXPECTED_FLAG]")
    return _EXPECTED_FLAG_RE.sub("[REDACTED_EXPECTED_FLAG]", redacted)


def _bounded_text(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_STREAM_BYTES:
        return value
    return encoded[:_MAX_EVIDENCE_STREAM_BYTES].decode("utf-8", errors="replace") + "\n[truncated]"


def _bounded_gateway_log(
    value: bytes,
    *,
    redact: Sequence[str],
) -> dict[str, object]:
    redacted = _redact_bytes(value, redact=redact)
    truncated = len(redacted) > _MAX_GATEWAY_LOG_BYTES
    retained = redacted[:_MAX_GATEWAY_LOG_BYTES]
    return {
        "text": retained.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "retained_bytes": len(retained),
        "original_sha256_after_redaction": hashlib.sha256(redacted).hexdigest(),
    }


def _safe_error_without_flag(exc: Exception, *, expected_flag: str) -> str:
    return _bounded_text(_redact_text(str(exc), redact=(expected_flag,)))


def _ensure_secret_absent(payload: Mapping[str, object], *, expected_flag: str) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    if expected_flag in serialized or _EXPECTED_FLAG_RE.search(serialized):
        raise ComparisonTargetError("expected flag leaked into public target provenance")


def _write_json_exclusive(path: Path, payload: Mapping[str, object]) -> None:
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8") as output:
        output.write(serialized)


def _write_json_if_absent(path: Path, payload: Mapping[str, object]) -> None:
    try:
        _write_json_exclusive(path, payload)
    except FileExistsError:
        return


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        return {}
    return value


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _merged_labels(value: object, required: Mapping[str, str]) -> dict[str, str]:
    labels: dict[str, str] = {}
    if isinstance(value, dict):
        labels.update({str(key): str(item) for key, item in value.items()})
    elif isinstance(value, list):
        for item in value:
            name, separator, label_value = str(item).partition("=")
            labels[name] = label_value if separator else ""
    labels.update(required)
    return labels


def _published_bindings(value: object) -> list[object]:
    if value in (None, {}):
        return []
    if not isinstance(value, dict):
        return [value]
    bindings: list[object] = []
    for raw in value.values():
        if raw in (None, []):
            continue
        if isinstance(raw, list):
            bindings.extend(raw)
        else:
            bindings.append(raw)
    return bindings


def _project_inventory_command(*, resource: str, project: str) -> tuple[str, ...]:
    if resource not in {"container", "network", "volume"}:
        raise ValueError("unsupported Docker inventory resource")
    all_resources = ("-a",) if resource == "container" else ()
    return (
        "docker",
        resource,
        "ls",
        *all_resources,
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
    )


def _exact_container_name_inventory_command(name: str) -> tuple[str, ...]:
    return (
        "docker",
        "container",
        "ls",
        "-a",
        "-q",
        "--no-trunc",
        "--filter",
        f"name=^/{name}$",
    )


def _decoded_lines(value: bytes) -> list[str]:
    return [
        line.strip()
        for line in value.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def _normalized_sha256(value: str) -> str:
    match = _SHA256_RE.fullmatch(value)
    if match is None:
        return value
    return f"sha256:{match.group(1)}"


def _raw_sha256(value: str) -> str:
    match = _SHA256_RE.fullmatch(value)
    if match is None:
        return value
    return match.group(1)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True
