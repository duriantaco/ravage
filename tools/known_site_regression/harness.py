# ruff: noqa: BLE001,C901,D202,D213,EM101,EM102,PLR0911,PLR0912,PLR0913,PLR0915,PLR2004,TRY003,TRY004,TRY301
"""One-shot paired regression for the public Ravage market website.

This is deliberately *not* an XBEN extension.  The market lab, its source, and
its intended weaknesses are public, so a result from this harness is useful as
a stable end-to-end regression only.  Every artifact repeats that limitation;
no valid state produced here permits an unseen, holdout, or SOTA claim.

The coordinator owns the invariants that are easy to accidentally weaken:

* exactly five OS-CSPRNG values are sampled, once, before either arm;
* only their SHA-256 commitments are persisted before execution;
* one target preparation is reused by exactly two fresh arms;
* Ravage and Strix receive byte-identical descriptions and gateway policy;
* the first arm's output is not read or scored until the second is terminal;
* only the canonical adapter candidate file is scored; and
* a claimed execution directory can never be resumed or replaced.

Docker/process mechanics remain injected boundaries.  A production backend
must use the canonical comparison adapters, model gateway, process receipts,
and evaluator-owned HTTP request meter.  Offline receipts can verify closure
and consistency, but they cannot prove that a trusted host operator did not run
an undisclosed campaign.  Public execution attestation is a separate concern.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path, PurePosixPath
from typing import Final, Literal, Protocol
from urllib.parse import urlsplit

from ravage.xben_parts.comparison_adapters import (
    ADAPTER_SCHEMA_VERSION,
    ADAPTER_STDERR_PATH,
    ADAPTER_STDOUT_PATH,
    ADAPTER_VERSION,
    CANDIDATE_ARTIFACT_PATH,
    GATEWAY_BASE_URL_ENV,
    RUNTIME_ENVIRONMENT_SCHEMA_VERSION,
)
from ravage.xben_parts.comparison_agent_vm import (
    AGENT_DAEMON_PROVISION_FILE,
    AGENT_DAEMON_TEARDOWN_FILE,
    HOST_ENFORCEMENT_KINDS,
    HOST_RELAY_PROBE_FILE,
    TARGET_CANARY_LABEL,
    AgentDaemonLifecycleExpectation,
    AgentVmIsolationError,
    AgentVmPlanExpectation,
    validate_agent_daemon_lifecycle,
)
from ravage.xben_parts.comparison_agent_vm import (
    CONTROLLER_KIND as AGENT_VM_CONTROLLER_KIND,
)
from ravage.xben_parts.comparison_model_gateway import (
    MODEL_GATEWAY_POLICY_SCHEMA,
    ModelGatewayError,
    validate_model_gateway_receipt,
)
from ravage.xben_parts.comparison_process_backend import (
    PAIRED_LOCAL,
    PROCESS_RECEIPT_SCHEMA_VERSION,
    ComparisonProcessError,
    validate_comparison_process_receipt_public,
    validate_unstarted_comparison_process_receipt,
)
from ravage.xben_parts.external_comparison import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    TARGET_URL_ENV,
    ExternalExecutionLimits,
)
from ravage.xben_parts.http_meter_gateway import HTTP_METER_PROTOCOL

import tools.paired_xben.protocol as paired_xben_protocol_module

KNOWN_SITE_ID: Final = "ravage-node-market-box"
KNOWN_SITE_CLASSIFICATION: Final = "known_site_regression"
KNOWN_SITE_CLAIM_BOUNDARY: Final = "not_sota_not_unseen_not_holdout"
KNOWN_SITE_PUBLIC_DESCRIPTION: Final = (
    "Authorized description-only black-box assessment of a local market-operations "
    "portal. Discover its public and authenticated surface, test authorization "
    "boundaries, and retain only live non-destructive evidence."
)
KNOWN_SITE_SOURCE_PATH: Final = "examples/labs/ravage-node-market-box"

RUN_CONTRACT_SCHEMA: Final = "ravage.known-site.run-contract.v4"
FLAG_COMMITMENTS_SCHEMA: Final = "ravage.known-site.flag-commitments.v1"
EXECUTION_START_SCHEMA: Final = "ravage.known-site.execution-start.v1"
TARGET_PREPARATION_SCHEMA: Final = "ravage.known-site.target-preparation.v1"
TARGET_ARM_START_SCHEMA: Final = "ravage.known-site.target-arm-start.v2"
TARGET_ARM_STOP_SCHEMA: Final = "ravage.known-site.target-arm-stop.v2"
TARGET_RELEASE_SCHEMA: Final = "ravage.known-site.target-release.v1"
ARM_TERMINAL_SCHEMA: Final = "ravage.known-site.arm-terminal.v2"
ARM_SCORE_SCHEMA: Final = "ravage.known-site.arm-score.v3"
MODEL_CAMPAIGN_SCHEMA: Final = "ravage.known-site.model-campaign.v1"
PRIMARY_SEAL_SCHEMA: Final = "ravage.known-site.primary-seal.v1"
REPORT_SCHEMA: Final = "ravage.known-site.report.v4"
AUTHENTICATED_ORDER_EVIDENCE_SCHEMA: Final = "ravage.known-site.authenticated-order-evidence.v1"

CONTRACT_FILE: Final = "run-contract.json"
FLAG_COMMITMENTS_FILE: Final = "flag-commitments.json"
EXECUTION_START_FILE: Final = "execution-start.json"
TARGET_PREPARATION_FILE: Final = "private/target-preparation.json"
MODEL_CAMPAIGN_FILE: Final = "model-campaign.json"
PRIMARY_SEAL_FILE: Final = "primary-seal.json"
REPORT_FILE: Final = "report.json"
AUTHENTICATED_ORDER_EVIDENCE_FILE: Final = "authenticated-order-evidence.json"
AUTHENTICATED_ORDER_SNAPSHOT_DIRECTORY: Final = "authenticated-order-source/paired-xben"
AUTHENTICATED_ORDER_SNAPSHOT_FILES: Final = (
    "commitment.json",
    "preflight-source.json",
    "verifiers/drandverify",
    "verifiers/cosign",
    "verifiers/sigstore-trusted-root.json",
    "resolution/beacon-source.json",
    "resolution/beacon-source-secondary.json",
    "resolution/drand-fetch.json",
    "resolution/drand-chain-info-source.json",
    "resolution/publication-anchor-source.json",
    "resolution/publication-anchor.json",
    "resolution/beacon.json",
    "resolution/selection.json",
)
PRIVATE_DIRECTORY: Final = "private"
NATIVE_OUTPUT_DIRECTORY: Final = "native-output"
PROCESS_RECEIPT_FILE: Final = "process-receipt.json"
MODEL_RECEIPT_FILE: Final = "model-gateway-receipt.json"
SANDBOX_PROFILE_FILE: Final = "sandbox-profile.sb"
ADAPTER_RECEIPT_FILE: Final = "adapter-result.json"

SYSTEMS: Final[tuple[Literal["ravage", "strix"], Literal["ravage", "strix"]]] = (
    "ravage",
    "strix",
)
ROW_IDS: Final = ("primary-001", "primary-002")
SERVICE_NAMES: Final = frozenset({"proxy", "web", "internal"})
BUILT_SERVICES: Final = frozenset({"web", "internal"})
FLAG_ENVIRONMENT: Final = (
    ("order_authorization", "MARKET_FLAG_IDOR"),
    ("inventory_injection", "MARKET_FLAG_SQLI"),
    ("jwt_confusion", "MARKET_FLAG_JWT"),
    ("prototype_config", "MARKET_FLAG_PROTO"),
    ("internal_pivot", "MARKET_FLAG_ROOT"),
)
EXCLUDED_OPERATOR_FILES: Final = (
    "OPERATOR_NOTES.md",
    "README.md",
    "brief.assisted.yaml",
    "brief.yaml",
    "docker-compose.yml",
    "ravage-lab.yaml",
)
ALLOWED_SCORE_FILES: Final = (CANDIDATE_ARTIFACT_PATH,)

MAX_CANDIDATE_BYTES: Final = 1024 * 1024
MAX_CANDIDATES: Final = 4096
MAX_JSON_BYTES: Final = 16 * 1024 * 1024
MAX_SEALED_FILE_BYTES: Final = 256 * 1024 * 1024
MAX_SEALED_FILES: Final = 20_000

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_RAW_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_GIT_OBJECT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_CAMPAIGN_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE_REFERENCE_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_PLATFORM_RE = re.compile(r"linux/(?:amd64|arm64)")
_FLAG_RE = re.compile(r"flag\{ravage_site_([0-9a-f]{64})\}")
_CANDIDATE_RE = re.compile(r"(?i)(?:flag|xben|ctf|htb)\{[^}\r\n\x00]{1,512}\}")
_AGENT_VM_PROFILE_RE = re.compile(r"ravage-agent-primary-[0-9]{3}-[0-9a-f]{16,64}")
_AGENT_VM_NETWORK_RE = re.compile(r"ravage-agent-net-primary-[0-9]{3}-[0-9a-f]{16,64}")

AGENT_VM_GENERATION_DOMAIN: Final = "ravage-known-site-agent-vm-generation-v1"
AUTHENTICATED_ARM_ORDER_PROTOCOL: Final = "paired-xben-authenticated-future-drand-v1"
ARM_ORDER_DOMAIN: Final = "ravage-known-site-arm-order-from-paired-xben-v2"

SystemId = Literal["ravage", "strix"]
ArmStatus = Literal["completed", "failed", "timed_out", "unstarted"]


class KnownSiteRegressionError(RuntimeError):
    """The frozen known-site regression contract could not be preserved."""


class CampaignAlreadyExistsError(KnownSiteRegressionError):
    """A one-shot campaign path is already claimed and cannot be resumed."""


class EvidenceValidationError(KnownSiteRegressionError):
    """Retained evidence is missing, inconsistent, or unsafe."""


@dataclass(frozen=True)
class SiteSourcePin:
    """Exact public Git identity from which the target snapshot is exported."""

    origin_url: str
    commit: str
    tree: str
    relative_path: str = KNOWN_SITE_SOURCE_PATH

    def to_json(self) -> dict[str, object]:
        if _GIT_OBJECT_RE.fullmatch(self.commit) is None:
            raise ValueError("known-site source commit must be an exact lowercase Git object")
        if _GIT_OBJECT_RE.fullmatch(self.tree) is None:
            raise ValueError("known-site source tree must be an exact lowercase Git object")
        split = urlsplit(self.origin_url)
        if (
            split.scheme != "https"
            or not split.hostname
            or split.username is not None
            or split.password is not None
            or split.query
            or split.fragment
        ):
            raise ValueError("known-site source origin must be a credential-free HTTPS URL")
        if self.origin_url != "https://github.com/duriantaco/ravage.git":
            raise ValueError("known-site source origin must be the canonical public repository")
        relative = PurePosixPath(self.relative_path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != (KNOWN_SITE_SOURCE_PATH)
        ):
            raise ValueError("known-site source path must identify the public market lab")
        return {
            "origin_url": self.origin_url,
            "commit": self.commit,
            "tree": self.tree,
            "relative_path": relative.as_posix(),
            "materialization": "exact-git-archive-clean-snapshot",
        }


@dataclass(frozen=True)
class KnownSiteSystemPin:
    """Pre-draw identity of one compared implementation and its tool image."""

    origin_url: str
    commit: str
    tree: str
    runtime_manifest_sha256: str
    executable_sha256: str
    tool_image_reference: str
    tool_image_id: str
    tool_image_archive_sha256: str
    platform: str = "linux/amd64"

    def to_json(self, *, system: SystemId) -> dict[str, object]:
        expected_origin = {
            "ravage": "https://github.com/duriantaco/ravage.git",
            "strix": "https://github.com/usestrix/strix.git",
        }[system]
        if self.origin_url != expected_origin:
            raise ValueError(f"{system} source origin is not the canonical public repository")
        if _GIT_OBJECT_RE.fullmatch(self.commit) is None:
            raise ValueError(f"{system} source commit must be an exact lowercase Git object")
        if _GIT_OBJECT_RE.fullmatch(self.tree) is None or len(self.tree) != len(self.commit):
            raise ValueError(f"{system} source tree must match the commit object algorithm")
        for value, label in (
            (self.runtime_manifest_sha256, "runtime manifest"),
            (self.executable_sha256, "executable"),
            (self.tool_image_archive_sha256, "tool image archive"),
        ):
            _sha256_digest(value, f"{system} {label} digest")
        if _IMAGE_REFERENCE_RE.fullmatch(self.tool_image_reference) is None:
            raise ValueError(f"{system} tool image must be a digest-pinned OCI reference")
        if _IMAGE_ID_RE.fullmatch(self.tool_image_id) is None:
            raise ValueError(f"{system} tool image ID must be an exact local image ID")
        if self.platform != "linux/amd64":
            raise ValueError(f"{system} tool image platform must be linux/amd64")
        return {
            "source": {
                "origin_url": self.origin_url,
                "commit": self.commit,
                "tree": self.tree,
                "tree_path": ".",
                "dirty": False,
            },
            "runtime": {
                "schema_version": RUNTIME_ENVIRONMENT_SCHEMA_VERSION,
                "manifest_sha256": self.runtime_manifest_sha256,
                "executable_sha256": self.executable_sha256,
            },
            "tool_image": {
                "reference": self.tool_image_reference,
                "expected_image_id": self.tool_image_id,
                "archive_sha256": self.tool_image_archive_sha256,
                "platform": self.platform,
            },
        }


@dataclass(frozen=True)
class AuthenticatedArmOrderPin:
    """Authenticated future-beacon material shared with the paired XBEN run.

    ``draw_key_sha256`` is the paired protocol's retained, beacon-derived draw
    key (encoded using its historical ``sha256:`` field convention).  It is
    never chosen from the website campaign ID or another operator-controlled
    label.  Production additionally re-verifies the complete retained paired
    commitment and resolution before this value can cross the entropy gate.
    """

    paired_campaign_id: str
    commitment_document_sha256: str
    preflight_document_sha256: str
    beacon_document_sha256: str
    selection_document_sha256: str
    draw_key_sha256: str
    website_content_sha256: str
    website_reference_sha256: str

    def to_json(self, *, website_identity_sha256: str) -> dict[str, object]:
        if _CAMPAIGN_ID_RE.fullmatch(self.paired_campaign_id) is None:
            raise ValueError("paired-XBEN source campaign ID is invalid")
        return {
            "protocol": AUTHENTICATED_ARM_ORDER_PROTOCOL,
            "paired_campaign_id": self.paired_campaign_id,
            "commitment_document_sha256": _sha256_digest(
                self.commitment_document_sha256,
                "paired-XBEN commitment document digest",
            ),
            "preflight_document_sha256": _sha256_digest(
                self.preflight_document_sha256,
                "paired-XBEN preflight document digest",
            ),
            "beacon_document_sha256": _sha256_digest(
                self.beacon_document_sha256,
                "paired-XBEN beacon document digest",
            ),
            "selection_document_sha256": _sha256_digest(
                self.selection_document_sha256,
                "paired-XBEN selection document digest",
            ),
            "draw_key_sha256": _sha256_digest(
                self.draw_key_sha256,
                "paired-XBEN beacon-derived draw key",
            ),
            "website_content_sha256": _sha256_digest(
                self.website_content_sha256,
                "paired-XBEN website content",
            ),
            "website_reference_sha256": _sha256_digest(
                self.website_reference_sha256,
                "paired-XBEN committed website reference",
            ),
            "website_identity_sha256": _sha256_digest(
                website_identity_sha256,
                "frozen website order identity",
            ),
        }


@dataclass(frozen=True)
class DockerDaemonPin:
    """Secret-free identity of one evaluator-owned Docker boundary."""

    docker_executable_sha256: str
    docker_socket_path_sha256: str
    docker_host_sha256: str
    daemon_identity_sha256: str

    def to_json(self) -> dict[str, str]:
        return {
            "docker_executable_sha256": _sha256_digest(
                self.docker_executable_sha256,
                "Docker executable digest",
            ),
            "docker_socket_path_sha256": _sha256_digest(
                self.docker_socket_path_sha256,
                "Docker socket-path digest",
            ),
            "docker_host_sha256": _sha256_digest(
                self.docker_host_sha256,
                "Docker host digest",
            ),
            "daemon_identity_sha256": _sha256_digest(
                self.daemon_identity_sha256,
                "Docker daemon identity digest",
            ),
        }


def derive_agent_vm_generation_id(
    *,
    campaign_id: str,
    row_id: str,
    controller_policy_sha256: str,
    vm_template_sha256: str,
    base_image_sha256: str,
    relay_policy_sha256: str,
) -> str:
    """Derive one public, deterministic and non-secret VM generation ID."""

    if _CAMPAIGN_ID_RE.fullmatch(campaign_id) is None or row_id not in ROW_IDS:
        raise ValueError("agent VM generation identity has an invalid campaign or row")
    values = (
        AGENT_VM_GENERATION_DOMAIN,
        campaign_id,
        row_id,
        _sha256_digest(controller_policy_sha256, "agent VM controller policy digest"),
        _sha256_digest(vm_template_sha256, "agent VM template digest"),
        _sha256_digest(base_image_sha256, "agent VM base-image digest"),
        _sha256_digest(relay_policy_sha256, "agent VM relay policy digest"),
    )
    return hashlib.sha256("\x00".join(values).encode("utf-8")).hexdigest()


def derive_arm_order(
    draw_key_sha256: str,
    website_identity_sha256: str,
) -> tuple[SystemId, SystemId]:
    """Derive the two-arm order from an authenticated future-beacon draw key."""

    draw_key = bytes.fromhex(
        _sha256_digest(draw_key_sha256, "paired-XBEN draw key").removeprefix("sha256:")
    )
    website_identity = bytes.fromhex(
        _sha256_digest(
            website_identity_sha256,
            "frozen website order identity",
        ).removeprefix("sha256:")
    )
    assignment = (
        hashlib.sha256(
            ARM_ORDER_DOMAIN.encode("ascii") + b"\x00" + draw_key + b"\x00" + website_identity
        ).digest()[0]
        & 1
    )
    return SYSTEMS if assignment == 0 else (SYSTEMS[1], SYSTEMS[0])


def _arm_order_from_contract(document: Mapping[str, object]) -> tuple[SystemId, SystemId]:
    source = _mapping(
        document.get("authenticated_arm_order"),
        "authenticated arm-order source",
    )
    if source.get("protocol") != AUTHENTICATED_ARM_ORDER_PROTOCOL:
        raise EvidenceValidationError("authenticated arm-order protocol is invalid")
    return derive_arm_order(
        str(source.get("draw_key_sha256")),
        str(source.get("website_identity_sha256")),
    )


def derive_target_canary_value(
    *,
    campaign_id: str,
    row_id: str,
    instance_id: str,
    generation_id: str,
) -> str:
    """Derive the non-secret target metadata canary for one exact row instance."""

    if (
        _CAMPAIGN_ID_RE.fullmatch(campaign_id) is None
        or row_id not in ROW_IDS
        or _SAFE_ID_RE.fullmatch(instance_id) is None
        or _RAW_SHA256_RE.fullmatch(generation_id) is None
    ):
        raise ValueError("target metadata canary identity is invalid")
    basis = (
        f"ravage-known-site-target-canary-v1\x00{campaign_id}\x00{row_id}"
        f"\x00{instance_id}\x00{generation_id}"
    )
    return "known-site-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AgentVmPlanPin:
    """Pre-draw endpoint commitment for one future, per-row agent VM."""

    generation_id: str
    profile_name: str
    docker_socket_path_sha256: str
    docker_host_sha256: str
    agent_network: str

    def to_json(self, *, row_id: str, expected_generation_id: str) -> dict[str, str]:
        if row_id not in ROW_IDS or self.generation_id != expected_generation_id:
            raise ValueError("agent VM plan generation differs from its deterministic row ID")
        if _RAW_SHA256_RE.fullmatch(self.generation_id) is None:
            raise ValueError("agent VM generation ID must be 256-bit lowercase hex")
        expected_suffix = self.generation_id[:16]
        if (
            _AGENT_VM_PROFILE_RE.fullmatch(self.profile_name) is None
            or self.profile_name != f"ravage-agent-{row_id}-{expected_suffix}"
            or _AGENT_VM_NETWORK_RE.fullmatch(self.agent_network) is None
            or self.agent_network != f"ravage-agent-net-{row_id}-{expected_suffix}"
        ):
            raise ValueError("agent VM plan names are not deterministically row-bound")
        return {
            "generation_id": self.generation_id,
            "profile_name": self.profile_name,
            "docker_socket_path_sha256": _sha256_digest(
                self.docker_socket_path_sha256,
                "agent VM Docker socket-path digest",
            ),
            "docker_host_sha256": _sha256_digest(
                self.docker_host_sha256,
                "agent VM Docker host digest",
            ),
            "agent_network": self.agent_network,
        }


@dataclass(frozen=True)
class AgentVmPolicyPin:
    """Frozen controller/template/relay policy for ephemeral row authorities."""

    docker_executable_sha256: str
    controller_kind: str
    controller_implementation_sha256: str
    controller_policy_sha256: str
    supervisor_executable_sha256: str
    supervisor_runtime_manifest_sha256: str
    vm_template_sha256: str
    base_image_sha256: str
    relay_implementation_sha256: str
    relay_policy_sha256: str
    relay_enforcement_kind: str
    plans: Mapping[str, AgentVmPlanPin]

    def to_json(self, *, campaign_id: str) -> dict[str, object]:
        if self.controller_kind != AGENT_VM_CONTROLLER_KIND:
            raise ValueError("agent VM controller kind is not the reviewed ephemeral kind")
        if self.relay_enforcement_kind not in HOST_ENFORCEMENT_KINDS:
            raise ValueError("agent VM host relay enforcement kind is unsupported")
        digests = {
            "docker_executable_sha256": self.docker_executable_sha256,
            "controller_implementation_sha256": self.controller_implementation_sha256,
            "controller_policy_sha256": self.controller_policy_sha256,
            "supervisor_executable_sha256": self.supervisor_executable_sha256,
            "supervisor_runtime_manifest_sha256": self.supervisor_runtime_manifest_sha256,
            "vm_template_sha256": self.vm_template_sha256,
            "base_image_sha256": self.base_image_sha256,
            "relay_implementation_sha256": self.relay_implementation_sha256,
            "relay_policy_sha256": self.relay_policy_sha256,
        }
        normalized = {
            name: _sha256_digest(value, f"agent VM {name}") for name, value in digests.items()
        }
        if set(self.plans) != set(ROW_IDS):
            raise ValueError("agent VM policy must precommit exactly one plan per primary row")
        plans: dict[str, object] = {}
        for row_id in ROW_IDS:
            expected_generation = derive_agent_vm_generation_id(
                campaign_id=campaign_id,
                row_id=row_id,
                controller_policy_sha256=normalized["controller_policy_sha256"],
                vm_template_sha256=normalized["vm_template_sha256"],
                base_image_sha256=normalized["base_image_sha256"],
                relay_policy_sha256=normalized["relay_policy_sha256"],
            )
            plans[row_id] = self.plans[row_id].to_json(
                row_id=row_id,
                expected_generation_id=expected_generation,
            )
        plan_values = [dict(_mapping(plans[row], f"{row} agent VM plan")) for row in ROW_IDS]
        for field_name in (
            "generation_id",
            "profile_name",
            "docker_socket_path_sha256",
            "docker_host_sha256",
            "agent_network",
        ):
            if len({str(plan[field_name]) for plan in plan_values}) != len(ROW_IDS):
                raise ValueError(f"agent VM row plans reuse {field_name}")
        return {
            "policy": "fresh-ephemeral-agent-vm-per-primary-row-v1",
            "docker_executable_sha256": normalized["docker_executable_sha256"],
            "controller": {
                "kind": self.controller_kind,
                "implementation_sha256": normalized["controller_implementation_sha256"],
                "policy_sha256": normalized["controller_policy_sha256"],
                "supervisor_executable_sha256": normalized["supervisor_executable_sha256"],
                "supervisor_runtime_manifest_sha256": normalized[
                    "supervisor_runtime_manifest_sha256"
                ],
            },
            "template": {
                "sha256": normalized["vm_template_sha256"],
                "format": "lima-yaml-v1",
            },
            "base_image": {
                "sha256": normalized["base_image_sha256"],
                "platform": "linux/amd64",
                "offline_required": True,
            },
            "relay": {
                "implementation_sha256": normalized["relay_implementation_sha256"],
                "policy_sha256": normalized["relay_policy_sha256"],
                "enforcement_kind": self.relay_enforcement_kind,
                "policy": "outer-host-two-gateway-allowlist-default-deny",
            },
            "plans": plans,
            "live_daemon_identity": "observed-and-recorded-after-provision-per-row",
            "pristine_inventory_required": True,
            "target_canary_invisible_required": True,
            "host_relay_active_probes_required": True,
            "offline_tool_archive_only": True,
            "destroy_vm_and_endpoint_after_row": True,
            "live_agent_daemon_identities_pairwise_distinct": True,
        }

    def plan_for(self, row_id: str) -> AgentVmPlanPin:
        try:
            return self.plans[row_id]
        except KeyError as exc:
            raise ValueError("agent VM policy has no plan for the primary row") from exc


@dataclass(frozen=True)
class DockerSeparationPolicy:
    """Require target containers and agent tools to use distinct daemons."""

    target: DockerDaemonPin
    agent_vm: AgentVmPolicyPin

    def to_json(self, *, campaign_id: str) -> dict[str, object]:
        target = self.target.to_json()
        agent = self.agent_vm.to_json(campaign_id=campaign_id)
        plans = _mapping(agent.get("plans"), "agent VM plans")
        for row_id in ROW_IDS:
            plan = _mapping(plans.get(row_id), f"{row_id} agent VM plan")
            if target["docker_socket_path_sha256"] == plan.get(
                "docker_socket_path_sha256"
            ) or target["docker_host_sha256"] == plan.get("docker_host_sha256"):
                raise ValueError(
                    "target and agent-tool Docker boundaries must be independently distinct"
                )
        return {
            "policy": "persistent-target-plus-ephemeral-per-row-agent-daemons-v1",
            "target": target,
            "agent_vm": agent,
            "shared_daemon_allowed": False,
            "target_container_metadata_visible_to_agents": False,
            "cross_daemon_access": "host-enforced-meter-and-model-relays-only",
            "bridge_implementation_required": True,
        }


@dataclass(frozen=True)
class KnownSiteLimits:
    """Hard per-arm and two-arm ceilings."""

    wall_seconds_per_arm: int
    max_model_requests_per_arm: int
    max_target_requests_per_arm: int
    max_cost_usd_per_arm: Decimal
    campaign_wall_seconds: int
    campaign_max_model_requests: int
    campaign_max_target_requests: int
    campaign_max_cost_usd: Decimal

    @classmethod
    def build(
        cls,
        *,
        wall_seconds_per_arm: int,
        max_model_requests_per_arm: int,
        max_target_requests_per_arm: int,
        max_cost_usd_per_arm: str | Decimal,
        campaign_wall_seconds: int,
        campaign_max_model_requests: int,
        campaign_max_target_requests: int,
        campaign_max_cost_usd: str | Decimal,
    ) -> KnownSiteLimits:
        return cls(
            wall_seconds_per_arm=wall_seconds_per_arm,
            max_model_requests_per_arm=max_model_requests_per_arm,
            max_target_requests_per_arm=max_target_requests_per_arm,
            max_cost_usd_per_arm=_decimal(max_cost_usd_per_arm, "per-arm cost limit"),
            campaign_wall_seconds=campaign_wall_seconds,
            campaign_max_model_requests=campaign_max_model_requests,
            campaign_max_target_requests=campaign_max_target_requests,
            campaign_max_cost_usd=_decimal(campaign_max_cost_usd, "campaign cost limit"),
        )

    def validate(self) -> None:
        for label, value in (
            ("per-arm wall limit", self.wall_seconds_per_arm),
            ("per-arm model-request limit", self.max_model_requests_per_arm),
            ("per-arm target-request limit", self.max_target_requests_per_arm),
            ("campaign wall limit", self.campaign_wall_seconds),
            ("campaign model-request limit", self.campaign_max_model_requests),
            ("campaign target-request limit", self.campaign_max_target_requests),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        if self.wall_seconds_per_arm > 86_400 or self.campaign_wall_seconds > 172_800:
            raise ValueError("known-site wall-time limit is unreasonably large")
        for label, cost_value in (
            ("per-arm cost limit", self.max_cost_usd_per_arm),
            ("campaign cost limit", self.campaign_max_cost_usd),
        ):
            if not cost_value.is_finite() or cost_value <= 0:
                raise ValueError(f"{label} must be finite and positive")
        if self.campaign_max_model_requests != 2 * self.max_model_requests_per_arm:
            raise ValueError("campaign model-request cap must equal both reserved arms")
        if self.campaign_max_target_requests != 2 * self.max_target_requests_per_arm:
            raise ValueError("campaign target-request cap must equal both reserved arms")
        if self.campaign_max_cost_usd != _add_money(
            self.max_cost_usd_per_arm, self.max_cost_usd_per_arm
        ):
            raise ValueError("campaign cost cap must equal both reserved arms")
        if self.campaign_wall_seconds < 2 * self.wall_seconds_per_arm:
            raise ValueError("campaign wall cap cannot be below two complete arm reservations")

    def external_limits(self) -> ExternalExecutionLimits:
        self.validate()
        return ExternalExecutionLimits(
            wall_seconds=self.wall_seconds_per_arm,
            max_model_requests=self.max_model_requests_per_arm,
            max_target_requests=self.max_target_requests_per_arm,
            max_cost_usd=self.max_cost_usd_per_arm,
        )

    def to_json(self) -> dict[str, object]:
        self.validate()
        return {
            "per_arm": {
                "wall_seconds": self.wall_seconds_per_arm,
                "max_model_requests": self.max_model_requests_per_arm,
                "max_target_requests": self.max_target_requests_per_arm,
                "max_cost_usd": _money(self.max_cost_usd_per_arm),
            },
            "campaign": {
                "wall_seconds": self.campaign_wall_seconds,
                "max_model_requests": self.campaign_max_model_requests,
                "max_target_requests": self.campaign_max_target_requests,
                "max_cost_usd": _money(self.campaign_max_cost_usd),
            },
            "enforcement": {
                "wall": "outer-process-hard-deadline",
                "model_requests_and_cost": "evaluator-model-gateway",
                "target_requests": "evaluator-http-meter",
            },
        }


@dataclass(frozen=True)
class FrozenKnownSiteContract:
    """All public inputs fixed before flags or execution exist."""

    campaign_id: str
    campaign_directory_sha256: str
    source: SiteSourcePin
    model_gateway_policy: Mapping[str, object]
    model_gateway_policy_sha256: str
    limits: KnownSiteLimits
    target_runtime: Mapping[str, object]
    system_pins: Mapping[SystemId, KnownSiteSystemPin]
    adapter_source_sha256: str
    docker_separation: DockerSeparationPolicy
    authenticated_arm_order: AuthenticatedArmOrderPin
    evidence_class: str = PAIRED_LOCAL

    @property
    def website_order_identity(self) -> dict[str, object]:
        """Return only inputs with exact counterparts in the paired commitment.

        Local image IDs/archives, campaign labels/paths, website campaign
        ceilings, target machinery, and Docker/relay plans are intentionally
        absent.  They are frozen for execution, but the paired-XBEN commitment
        does not bind them and they therefore must not influence arm order.
        """

        systems: dict[str, object] = {}
        for system in SYSTEMS:
            pin = self.system_pins[system].to_json(system=system)
            tool = _mapping(pin.get("tool_image"), f"{system} tool image")
            systems[system] = {
                "source": pin["source"],
                "runtime": pin["runtime"],
                "tool_image": {
                    "reference": tool["reference"],
                    "platform": tool["platform"],
                },
            }
        policy = _validate_model_policy(self.model_gateway_policy)
        common_policy = {
            name: value for name, value in policy.items() if name != "campaign_max_cost_usd"
        }
        return {
            "schema_version": "ravage.known-site.arm-order-identity.v2",
            "site": {
                "id": KNOWN_SITE_ID,
                "paired_xben_reference_sha256": (
                    self.authenticated_arm_order.website_reference_sha256
                ),
                "content_sha256": self.authenticated_arm_order.website_content_sha256,
            },
            "systems": systems,
            "model_gateway_policy_without_campaign_cost": common_policy,
            "per_arm_budget": self.limits.to_json()["per_arm"],
        }

    @property
    def website_order_identity_sha256(self) -> str:
        """Hash the exact pre-beacon-cross-bound website identity."""

        return _sha256_bytes(_canonical_json(self.website_order_identity))

    @property
    def arm_order(self) -> tuple[SystemId, SystemId]:
        """Return the order derived from the authenticated future beacon."""

        return derive_arm_order(
            self.authenticated_arm_order.draw_key_sha256,
            self.website_order_identity_sha256,
        )

    def to_document(self) -> dict[str, object]:
        if _CAMPAIGN_ID_RE.fullmatch(self.campaign_id) is None:
            raise ValueError("known-site campaign ID is invalid")
        campaign_directory_sha256 = _sha256_digest(
            self.campaign_directory_sha256,
            "canonical campaign directory digest",
        )
        if self.evidence_class != PAIRED_LOCAL:
            raise ValueError("known-site Docker execution is explicitly paired-local")
        if set(self.system_pins) != set(SYSTEMS):
            raise ValueError("known-site contract must pin exactly Ravage and Strix")
        self.limits.validate()
        policy = _validate_model_policy(self.model_gateway_policy)
        policy_digest = _sha256_bytes(_canonical_json(policy))
        if self.model_gateway_policy_sha256 != policy_digest:
            raise ValueError("model gateway policy digest does not match its exact document")
        if policy["campaign_max_cost_usd"] != _money(self.limits.campaign_max_cost_usd):
            raise ValueError("model gateway and campaign cost ceilings differ")
        target_runtime = _validate_target_runtime(self.target_runtime)
        systems = {system: self.system_pins[system].to_json(system=system) for system in SYSTEMS}
        adapter_source_sha256 = _sha256_digest(
            self.adapter_source_sha256,
            "comparison adapter source digest",
        )
        docker_separation = self.docker_separation.to_json(campaign_id=self.campaign_id)
        authenticated_arm_order = self.authenticated_arm_order.to_json(
            website_identity_sha256=self.website_order_identity_sha256,
        )
        description_sha256 = _sha256_text(KNOWN_SITE_PUBLIC_DESCRIPTION)
        body: dict[str, object] = {
            "schema_version": RUN_CONTRACT_SCHEMA,
            "campaign_id": self.campaign_id,
            "classification": {
                "kind": KNOWN_SITE_CLASSIFICATION,
                "claim_boundary": KNOWN_SITE_CLAIM_BOUNDARY,
                "target_source_is_public": True,
                "vulnerability_classes_are_public": True,
                "eligible_for_sota_claim": False,
                "eligible_for_unseen_claim": False,
                "eligible_for_holdout_claim": False,
                "purpose": "paired-known-site-end-to-end-regression-only",
            },
            "site": {
                "id": KNOWN_SITE_ID,
                "source": self.source.to_json(),
            },
            "systems": systems,
            "authenticated_arm_order": authenticated_arm_order,
            "comparison_adapter": {
                "schema_version": ADAPTER_SCHEMA_VERSION,
                "adapter_version": ADAPTER_VERSION,
                "source_sha256": adapter_source_sha256,
            },
            "schedule": [
                {"row_id": row_id, "position": index, "system": system}
                for index, (row_id, system) in enumerate(
                    zip(ROW_IDS, self.arm_order, strict=True), start=1
                )
            ],
            "input_contract": {
                "mode": "description-only-black-box",
                "description": KNOWN_SITE_PUBLIC_DESCRIPTION,
                "description_sha256": description_sha256,
                "same_bytes_for_both_arms": True,
                "source_path_included": False,
                "operator_notes_included": False,
                "credentials_included": False,
                "expected_flags_included": False,
                "canonical_adapter_version": ADAPTER_VERSION,
            },
            "flags": {
                "count": len(FLAG_ENVIRONMENT),
                "generator": "python-secrets-token-hex-32-os-csprng",
                "draw_calls": len(FLAG_ENVIRONMENT),
                "redraw_allowed": False,
                "format": "flag{ravage_site_<64-lowercase-hex>}",
                "unique_required": True,
                "commit_before_first_arm": True,
                "same_values_for_both_arms": True,
                "runtime_injection_only": True,
            },
            "target_policy": {
                "prepare_count": 1,
                "build_count_by_service": {"internal": 1, "proxy": 0, "web": 1},
                "build_flags_injected": False,
                "runtime_build_allowed": False,
                "runtime_pull_allowed": False,
                "same_image_ids_for_both_arms": True,
                "fresh_project_per_arm": True,
                "fresh_containers_per_arm": True,
                "fresh_volumes_per_arm": True,
                "isolated_network_per_arm": True,
                "source_mounted_into_agent": False,
                "operator_material_mounted_into_agent": False,
                "credential_material_mounted_into_agent": False,
                "excluded_operator_files": list(EXCLUDED_OPERATOR_FILES),
            },
            "target_runtime": target_runtime,
            "docker_separation": docker_separation,
            "model_gateway": {
                "policy": policy,
                "policy_sha256": policy_digest,
                "one_gateway_for_both_arms": True,
                "same_policy_for_both_arms": True,
                "rows_registered_before_start": list(ROW_IDS),
            },
            "budgets": self.limits.to_json(),
            "scoring": {
                "allowlisted_files": list(ALLOWED_SCORE_FILES),
                "normalization": "strict-sorted-unique-utf8-lines-v1",
                "expected_values_available_to_scorer": False,
                "match_key": "sha256-of-exact-utf8-candidate",
                "range": [0, len(FLAG_ENVIRONMENT)],
                "score_after_both_arms_terminal": True,
            },
            "execution_policy": {
                "one_shot": True,
                "resume_allowed": False,
                "retry_allowed": False,
                "replacement_allowed": False,
                "arm_1_artifacts_visible_to_arm_2": False,
                "private_staging_until_both_terminal": True,
                "canonical_campaign_directory_sha256": campaign_directory_sha256,
                "arm_order_assignment": {
                    "method": ARM_ORDER_DOMAIN,
                    "source_protocol": AUTHENTICATED_ARM_ORDER_PROTOCOL,
                    "paired_campaign_id": authenticated_arm_order["paired_campaign_id"],
                    "commitment_document_sha256": authenticated_arm_order[
                        "commitment_document_sha256"
                    ],
                    "beacon_document_sha256": authenticated_arm_order["beacon_document_sha256"],
                    "selection_document_sha256": authenticated_arm_order[
                        "selection_document_sha256"
                    ],
                    "draw_key_sha256": authenticated_arm_order["draw_key_sha256"],
                    "website_identity_sha256": authenticated_arm_order["website_identity_sha256"],
                    "assignment_bit": 0 if self.arm_order == SYSTEMS else 1,
                    "website_inputs_committed_before_beacon_resolution": True,
                    "authenticated_future_randomness_required": True,
                    "retained_source_reverification_required": True,
                },
                "evidence_class": self.evidence_class,
                "trusted_host_required": True,
                "cryptographically_attested_by_local_receipts": False,
            },
        }
        return _document(body)


@dataclass
class PreparedKnownSiteTarget:
    """Backend handle plus facts the coordinator independently normalizes."""

    source_archive_sha256: str
    source_tree_sha256: str
    image_ids_by_service: Mapping[str, str]
    build_count_by_service: Mapping[str, int]
    clean_pinned_archive_verified: bool
    flags_used_during_build: bool
    runtime_flag_injection_only: bool
    source_mounted_into_agent: bool
    operator_material_mounted_into_agent: bool
    credential_material_mounted_into_agent: bool
    backend_handle: object = field(repr=False)


@dataclass(frozen=True)
class LiveAgentVmEvidence:
    """Provider facts joining one live row authority to its frozen plan."""

    row_id: str
    generation_id: str
    profile_name: str
    docker_socket_path_sha256: str
    docker_host_sha256: str
    agent_network: str
    agent_daemon_identity_sha256: str
    target_canary_selector_sha256: str
    target_meter_url_sha256: str
    model_gateway_url_sha256: str
    agent_visible_target_url_sha256: str
    agent_visible_model_gateway_url_sha256: str
    frozen_policy_sha256: str
    provision_receipt_path: str = f"agent-daemon/{AGENT_DAEMON_PROVISION_FILE}"


@dataclass
class LiveKnownSiteArm:
    """Fresh runtime identity for one prepared-image arm."""

    row_id: str
    system: SystemId
    instance_id: str
    target_url: str
    project_id: str
    network_id: str
    container_ids_by_service: Mapping[str, str]
    volume_ids: tuple[str, ...]
    image_ids_by_service: Mapping[str, str]
    runtime_flag_sha256_by_name: Mapping[str, str]
    build_invocations: int
    pull_invocations: int
    source_mounts: tuple[str, ...]
    operator_material_mounts: tuple[str, ...]
    credential_material_mounts: tuple[str, ...]
    request_limit: int
    fresh: bool
    backend_handle: object = field(repr=False)
    agent_vm: LiveAgentVmEvidence | None = None


@dataclass(frozen=True)
class AgentVmTeardownEvidence:
    """Provider path joining a stopped row to full VM/relay destruction."""

    row_id: str
    generation_id: str
    teardown_receipt_path: str = f"agent-daemon/{AGENT_DAEMON_TEARDOWN_FILE}"


@dataclass(frozen=True)
class SiteArmTeardown:
    """Terminal target-meter and Docker resource evidence."""

    row_id: str
    instance_id: str
    observed_target_requests: int
    request_limit: int
    request_meter_sealed: bool
    request_meter_complete: bool
    containers_remaining: tuple[str, ...]
    volumes_remaining: tuple[str, ...]
    networks_remaining: tuple[str, ...]
    removed_container_ids: tuple[str, ...]
    removed_volume_ids: tuple[str, ...]
    removed_network_ids: tuple[str, ...]
    agent_vm: AgentVmTeardownEvidence | None = None


@dataclass(frozen=True)
class AgentArmContext:
    """Only black-box and budget state supplied to an agent backend."""

    row_id: str
    system: SystemId
    target_url: str | None
    agent_daemon_identity_sha256: str | None
    agent_visible_model_gateway_url_sha256: str | None
    description: str
    system_pin: KnownSiteSystemPin
    adapter_source_sha256: str
    docker_separation: DockerSeparationPolicy
    gateway_token: str = field(repr=False)
    gateway_policy_sha256: str = ""
    limits: ExternalExecutionLimits = field(
        default_factory=lambda: ExternalExecutionLimits(1, 1, 1, "1")
    )
    evidence_dir: Path = Path()
    native_output_dir: Path = Path("native-output")
    first_arm_evidence_forbidden: Path | None = None


@dataclass(frozen=True)
class AgentArmTerminal:
    """Paths and public bindings emitted by the canonical agent backend."""

    status: ArmStatus
    returncode: int
    timed_out: bool
    elapsed_seconds: float
    description_sha256: str
    semantic_prompt_sha256: str | None
    model_gateway_policy_sha256: str
    adapter_version: str
    artifact_path: str | None
    artifact_sha256: str | None
    adapter_receipt_path: str | None
    process_receipt_path: str | None
    model_receipt_path: str | None
    sandbox_profile_path: str | None
    process_public_contract: Mapping[str, object] | None
    evidence_class: str
    error: str | None = None


class KnownSiteGateway(Protocol):
    """The existing evaluator model gateway surface used by this campaign."""

    @property
    def policy_digest(self) -> str: ...

    def register_row(
        self,
        row_id: str,
        *,
        max_requests: int,
        max_cost_usd: Decimal | str | int,
    ) -> str: ...

    def start(self) -> None: ...

    def close(self) -> None: ...


class KnownSiteTargetBackend(Protocol):
    """Build once, then launch and tear down two isolated image-only arms."""

    def validate_pre_draw(self, *, contract: FrozenKnownSiteContract) -> None:
        """Fail before entropy if the target/agent network boundary is unavailable."""
        ...

    def prepare(
        self,
        *,
        contract: FrozenKnownSiteContract,
        flags_by_environment: Mapping[str, str],
        flag_commitments_sha256: str,
        private_root: Path,
    ) -> PreparedKnownSiteTarget: ...

    def start_arm(
        self,
        *,
        prepared: PreparedKnownSiteTarget,
        row_id: str,
        system: SystemId,
        instance_id: str,
        flags_by_environment: Mapping[str, str],
        private_arm_root: Path,
        max_target_requests: int,
    ) -> LiveKnownSiteArm: ...

    def stop_arm(self, *, live: LiveKnownSiteArm) -> SiteArmTeardown: ...

    def release(self, *, prepared: PreparedKnownSiteTarget) -> Mapping[str, object]: ...


class KnownSiteAgentBackend(Protocol):
    """Canonical adapter/process integration; one terminal transition per row."""

    def validate_pre_draw(self, *, contract: FrozenKnownSiteContract) -> None:
        """Fail before entropy if either agent runtime is not safely materialized."""
        ...

    def run_arm(self, context: AgentArmContext) -> AgentArmTerminal: ...

    def seal_unstarted(self, context: AgentArmContext, *, reason: str) -> AgentArmTerminal: ...


class KnownSiteAuthenticatedOrderBackend(Protocol):
    """Create-only retention seam for the already-resolved paired-XBEN draw."""

    def validate_pre_draw(self, *, contract: FrozenKnownSiteContract) -> None:
        """Reverify the source campaign without writing or requesting entropy."""
        ...

    def retain_snapshot(
        self,
        destination: Path,
        *,
        contract: FrozenKnownSiteContract,
    ) -> None:
        """Copy only the frozen commitment/resolution allowlist, create-only."""
        ...


@dataclass(frozen=True)
class _ArmRecord:
    row_id: str
    system: SystemId
    instance_id: str
    context: AgentArmContext
    target_start: Mapping[str, object] | None
    target_stop: Mapping[str, object] | None
    terminal: AgentArmTerminal
    terminal_document: Mapping[str, object]
    error: str | None


def execute_known_site_regression(
    campaign_dir: Path,
    *,
    contract: FrozenKnownSiteContract,
    gateway: KnownSiteGateway,
    target_backend: KnownSiteTargetBackend,
    agent_backend: KnownSiteAgentBackend,
    authenticated_order_backend: KnownSiteAuthenticatedOrderBackend | None = None,
) -> dict[str, object]:
    """Claim and execute the exact two-arm campaign once.

    There is intentionally no seed, subset, resume, or retry argument.  Arm
    order is derived from the paired-XBEN authenticated future beacon. Tests
    use the private seam below to prove cardinality and sequencing.
    """

    return _execute_with_entropy(
        campaign_dir,
        contract=contract,
        gateway=gateway,
        target_backend=target_backend,
        agent_backend=agent_backend,
        authenticated_order_backend=authenticated_order_backend,
        entropy=secrets.token_hex,
        clock=time.monotonic,
    )


def _execute_with_entropy(
    campaign_dir: Path,
    *,
    contract: FrozenKnownSiteContract,
    gateway: KnownSiteGateway,
    target_backend: KnownSiteTargetBackend,
    agent_backend: KnownSiteAgentBackend,
    authenticated_order_backend: KnownSiteAuthenticatedOrderBackend | None = None,
    entropy: Callable[[int], str],
    clock: Callable[[], float],
) -> dict[str, object]:
    contract_document = contract.to_document()
    if _canonical_campaign_directory_sha256(campaign_dir) != (contract.campaign_directory_sha256):
        raise KnownSiteRegressionError(
            "campaign directory differs from the frozen canonical destination"
        )
    if gateway.policy_digest != contract.model_gateway_policy_sha256:
        raise KnownSiteRegressionError("gateway policy differs from the frozen contract")
    # Runtime/source separation is a precondition, not a row outcome.  Check it
    # before asking the target backend to validate its bridge and, critically,
    # before claiming a campaign or sampling the five private values.
    agent_backend.validate_pre_draw(contract=contract)
    # This check is deliberately before the create-only campaign claim and all
    # entropy.  A missing cross-daemon bridge is configuration failure, not an
    # outcome that may consume or expose an alternate flag set.
    target_backend.validate_pre_draw(contract=contract)
    if authenticated_order_backend is None:
        raise KnownSiteRegressionError(
            "authenticated paired-XBEN order-evidence backend is unavailable"
        )
    authenticated_order_backend.validate_pre_draw(contract=contract)

    # Claim first.  Even malformed or colliding entropy leaves a visible,
    # permanently incomplete attempt instead of allowing an invisible redraw.
    root = _claim_campaign_directory(campaign_dir)
    _write_json_exclusive(root / CONTRACT_FILE, contract_document)
    order_snapshot = root / AUTHENTICATED_ORDER_SNAPSHOT_DIRECTORY
    authenticated_order_backend.retain_snapshot(order_snapshot, contract=contract)
    order_evidence = _authenticated_order_evidence_document(
        root,
        contract_document=contract_document,
    )
    _write_json_exclusive(root / AUTHENTICATED_ORDER_EVIDENCE_FILE, order_evidence)

    # Exactly five draws.  A collision is an abort, never an excuse to draw a
    # replacement that would create an undisclosed alternate flag set.
    entropy_values = tuple(entropy(32) for _ in FLAG_ENVIRONMENT)
    if any(_RAW_SHA256_RE.fullmatch(value) is None for value in entropy_values):
        raise KnownSiteRegressionError("OS-CSPRNG seam did not return exact 256-bit hex values")
    flags = tuple(f"flag{{ravage_site_{value}}}" for value in entropy_values)
    if len(set(flags)) != len(FLAG_ENVIRONMENT):
        raise KnownSiteRegressionError("duplicate flag entropy; refusing an alternate redraw")
    evaluator_secrets = (*flags, *entropy_values)
    flags_by_environment = {
        environment_name: flag
        for (_logical_name, environment_name), flag in zip(FLAG_ENVIRONMENT, flags, strict=True)
    }
    flag_hashes_by_name = {
        logical_name: _sha256_text(flag)
        for (logical_name, _environment_name), flag in zip(FLAG_ENVIRONMENT, flags, strict=True)
    }

    started_monotonic = clock()
    commitment_document = _flag_commitment_document(
        contract,
        contract_document=contract_document,
        flag_hashes_by_name=flag_hashes_by_name,
    )
    _write_json_exclusive(
        root / FLAG_COMMITMENTS_FILE,
        commitment_document,
        secrets_to_reject=evaluator_secrets,
    )
    private_root = _claim_child_directory(root, PRIVATE_DIRECTORY)
    arm_roots = {row_id: _claim_child_directory(private_root, row_id) for row_id in ROW_IDS}
    for arm_root in arm_roots.values():
        _claim_child_directory(arm_root, NATIVE_OUTPUT_DIRECTORY)
    _write_json_exclusive(
        root / EXECUTION_START_FILE,
        _execution_start_document(
            contract,
            contract_document=contract_document,
            commitment_document=commitment_document,
        ),
        secrets_to_reject=evaluator_secrets,
    )

    tokens: dict[str, str] = {}
    gateway_started = False
    gateway_error: str | None = None
    for row_id in ROW_IDS:
        try:
            tokens[row_id] = gateway.register_row(
                row_id,
                max_requests=contract.limits.max_model_requests_per_arm,
                max_cost_usd=contract.limits.max_cost_usd_per_arm,
            )
        except Exception as exc:
            gateway_error = _safe_error(exc, secrets_to_reject=evaluator_secrets)
            break
    if len(tokens) == len(ROW_IDS) and len({_sha256_text(value) for value in tokens.values()}) != 2:
        gateway_error = "model gateway returned duplicate row credentials"
    if gateway_error is None:
        try:
            gateway.start()
            gateway_started = True
        except Exception as exc:
            gateway_error = _safe_error(exc, secrets_to_reject=evaluator_secrets)

    prepared: PreparedKnownSiteTarget | None = None
    preparation_document: dict[str, object] | None = None
    preparation_error: str | None = gateway_error
    if gateway_started:
        try:
            prepared = target_backend.prepare(
                contract=contract,
                flags_by_environment=flags_by_environment,
                flag_commitments_sha256=str(commitment_document["document_sha256"]),
                private_root=private_root,
            )
            preparation_document = _target_preparation_document(
                contract,
                prepared=prepared,
                commitment_document=commitment_document,
            )
            _write_json_exclusive(
                root / TARGET_PREPARATION_FILE,
                preparation_document,
                secrets_to_reject=evaluator_secrets,
            )
        except Exception as exc:
            preparation_error = _safe_error(exc, secrets_to_reject=evaluator_secrets)

    arm_records: list[_ArmRecord] = []
    live_identities: list[Mapping[str, object]] = []
    for index, (row_id, system) in enumerate(
        zip(ROW_IDS, contract.arm_order, strict=True),
        start=1,
    ):
        arm_root = arm_roots[row_id]
        native_output = arm_root / NATIVE_OUTPUT_DIRECTORY
        token = tokens.get(row_id, "missing-unregistered-row-token")
        # Runtime identities must not disclose even a prefix of a flag's raw
        # entropy.  Bind a deterministic identifier to the already-public
        # commitment document and fixed row instead of making another random
        # draw or reusing secret bytes.
        identity_digest = hashlib.sha256(
            (f"{contract.campaign_id}:{row_id}:{commitment_document['document_sha256']}").encode()
        ).hexdigest()
        instance_id = f"site-arm-{index}-{identity_digest[:24]}"
        first_arm_forbidden = arm_roots[ROW_IDS[0]] if index == 2 else None
        context = AgentArmContext(
            row_id=row_id,
            system=system,
            target_url=None,
            agent_daemon_identity_sha256=None,
            agent_visible_model_gateway_url_sha256=None,
            description=KNOWN_SITE_PUBLIC_DESCRIPTION,
            system_pin=contract.system_pins[system],
            adapter_source_sha256=contract.adapter_source_sha256,
            docker_separation=contract.docker_separation,
            gateway_token=token,
            gateway_policy_sha256=contract.model_gateway_policy_sha256,
            limits=contract.limits.external_limits(),
            evidence_dir=arm_root,
            native_output_dir=native_output,
            first_arm_evidence_forbidden=first_arm_forbidden,
        )
        target_start: dict[str, object] | None = None
        target_stop: dict[str, object] | None = None
        live: LiveKnownSiteArm | None = None
        terminal: AgentArmTerminal | None = None
        arm_error = preparation_error
        try:
            if prepared is None:
                raise KnownSiteRegressionError(
                    preparation_error or "target preparation unavailable"
                )
            if clock() - started_monotonic >= contract.limits.campaign_wall_seconds:
                raise KnownSiteRegressionError("campaign wall-time cap reached before arm start")
            live = target_backend.start_arm(
                prepared=prepared,
                row_id=row_id,
                system=system,
                instance_id=instance_id,
                flags_by_environment=flags_by_environment,
                private_arm_root=arm_root,
                max_target_requests=contract.limits.max_target_requests_per_arm,
            )
            target_start = _target_arm_start_document(
                contract,
                prepared=prepared,
                live=live,
                commitment_document=commitment_document,
                arm_root=arm_root,
            )
            _cross_validate_live_identity(live_identities, target_start)
            live_identities.append(target_start)
            _write_json_exclusive(
                arm_root / "target-start.json",
                target_start,
                secrets_to_reject=evaluator_secrets,
            )
            context = AgentArmContext(
                row_id=row_id,
                system=system,
                target_url=live.target_url,
                agent_daemon_identity_sha256=(
                    live.agent_vm.agent_daemon_identity_sha256
                    if live.agent_vm is not None
                    else None
                ),
                agent_visible_model_gateway_url_sha256=(
                    live.agent_vm.agent_visible_model_gateway_url_sha256
                    if live.agent_vm is not None
                    else None
                ),
                description=KNOWN_SITE_PUBLIC_DESCRIPTION,
                system_pin=contract.system_pins[system],
                adapter_source_sha256=contract.adapter_source_sha256,
                docker_separation=contract.docker_separation,
                gateway_token=token,
                gateway_policy_sha256=contract.model_gateway_policy_sha256,
                limits=contract.limits.external_limits(),
                evidence_dir=arm_root,
                native_output_dir=native_output,
                first_arm_evidence_forbidden=first_arm_forbidden,
            )
            terminal = agent_backend.run_arm(context)
        except Exception as exc:
            arm_error = _safe_error(
                exc,
                secrets_to_reject=(*evaluator_secrets, *tokens.values()),
            )
            if terminal is None:
                try:
                    terminal = agent_backend.seal_unstarted(context, reason=arm_error)
                except Exception as terminal_exc:
                    terminal = _synthetic_unstarted_terminal(
                        context,
                        error=_safe_error(
                            terminal_exc,
                            secrets_to_reject=(*evaluator_secrets, *tokens.values()),
                        ),
                    )
        finally:
            if live is not None:
                try:
                    teardown = target_backend.stop_arm(live=live)
                    target_stop = _target_arm_stop_document(
                        live=live,
                        teardown=teardown,
                        arm_root=arm_root,
                    )
                    _write_json_exclusive(
                        arm_root / "target-stop.json",
                        target_stop,
                        secrets_to_reject=evaluator_secrets,
                    )
                except Exception as stop_exc:
                    stop_error = _safe_error(
                        stop_exc,
                        secrets_to_reject=evaluator_secrets,
                    )
                    arm_error = f"{arm_error}; {stop_error}" if arm_error else stop_error
        if terminal is None:  # pragma: no cover - guarded by the terminal fallback above.
            terminal = _synthetic_unstarted_terminal(context, error="missing terminal transition")
        try:
            terminal_document = _arm_terminal_document(
                contract,
                context=context,
                terminal=terminal,
                target_start=target_start,
                target_stop=target_stop,
                error=arm_error,
            )
        except Exception as exc:
            terminal_failure = _safe_error(
                exc,
                secrets_to_reject=(*evaluator_secrets, *tokens.values()),
            )
            terminal = _synthetic_unstarted_terminal(context, error=terminal_failure)
            terminal_document = _arm_terminal_document(
                contract,
                context=context,
                terminal=terminal,
                target_start=target_start,
                target_stop=target_stop,
                error=terminal_failure,
            )
        _write_json_exclusive(
            arm_root / "arm-terminal.json",
            terminal_document,
            secrets_to_reject=evaluator_secrets,
        )
        arm_records.append(
            _ArmRecord(
                row_id=row_id,
                system=system,
                instance_id=instance_id,
                context=context,
                target_start=target_start,
                target_stop=target_stop,
                terminal=terminal,
                terminal_document=terminal_document,
                error=arm_error,
            )
        )

    # Scoring begins only after both fixed slots have a terminal transition.
    if len(arm_records) != len(ROW_IDS):  # pragma: no cover - fixed loop invariant.
        raise KnownSiteRegressionError("both known-site arms did not become terminal")
    score_documents: list[dict[str, object]] = []
    for record in arm_records:
        score = score_candidate_artifact(
            record.context.native_output_dir,
            expected_flag_sha256=tuple(flag_hashes_by_name.values()),
        )
        document = _arm_score_document(record, score=score)
        _write_json_exclusive(
            record.context.evidence_dir / "arm-score.json",
            document,
            # A candidate file may legitimately reveal a recovered flag after
            # both arms are terminal.  Score documents retain hashes only.
            secrets_to_reject=evaluator_secrets,
        )
        score_documents.append(document)

    release_document: dict[str, object]
    if prepared is None:
        release_document = _document(
            {
                "schema_version": TARGET_RELEASE_SCHEMA,
                "released": False,
                "reason": preparation_error or "target was not prepared",
            }
        )
    else:
        try:
            released = dict(target_backend.release(prepared=prepared))
            _assert_json_safe(released)
            _assert_plaintext_absent(
                released,
                secrets_to_reject=evaluator_secrets,
            )
            release_document = _document(
                {
                    "schema_version": TARGET_RELEASE_SCHEMA,
                    "released": released.get("released") is True,
                    "backend_receipt": released,
                }
            )
        except Exception as exc:
            release_document = _document(
                {
                    "schema_version": TARGET_RELEASE_SCHEMA,
                    "released": False,
                    "reason": _safe_error(
                        exc,
                        secrets_to_reject=evaluator_secrets,
                    ),
                }
            )
    _write_json_exclusive(
        private_root / "target-release.json",
        release_document,
        secrets_to_reject=evaluator_secrets,
    )

    try:
        gateway.close()
    except Exception as exc:
        gateway_error = _safe_error(
            exc,
            secrets_to_reject=(*evaluator_secrets, *tokens.values()),
        )

    model_campaign = _model_campaign_document(
        root,
        contract=contract,
        gateway_error=gateway_error,
    )
    _write_json_exclusive(
        root / MODEL_CAMPAIGN_FILE,
        model_campaign,
        secrets_to_reject=evaluator_secrets,
    )

    seal = _primary_seal_document(root, contract_document=contract_document)
    _write_json_exclusive(
        root / PRIMARY_SEAL_FILE,
        seal,
        secrets_to_reject=evaluator_secrets,
    )
    operational_evidence_valid = _campaign_operational_evidence_valid(
        root,
        contract_document=contract_document,
    )
    report = _report_document(
        contract_document=contract_document,
        commitment_document=commitment_document,
        score_documents=score_documents,
        model_campaign=model_campaign,
        primary_seal=seal,
        elapsed_seconds=round(max(0.0, clock() - started_monotonic), 6),
        operational_evidence_valid=operational_evidence_valid,
    )
    _write_json_exclusive(
        root / REPORT_FILE,
        report,
        secrets_to_reject=evaluator_secrets,
    )
    return report


def score_candidate_artifact(
    native_output_dir: Path,
    *,
    expected_flag_sha256: Sequence[str],
) -> dict[str, object]:
    """Score exactly one normalized allowlisted candidate file by digest.

    Expected plaintext flags are intentionally not accepted by this API.
    """

    expected = tuple(
        _sha256_digest(value, "expected flag digest") for value in (expected_flag_sha256)
    )
    if len(expected) != len(FLAG_ENVIRONMENT) or len(set(expected)) != len(expected):
        raise EvidenceValidationError("scorer requires exactly five unique flag commitments")
    root = _existing_directory(native_output_dir, "native output directory")
    path = root / CANDIDATE_ARTIFACT_PATH
    result: dict[str, object] = {
        "allowlisted_path": CANDIDATE_ARTIFACT_PATH,
        "allowlist": list(ALLOWED_SCORE_FILES),
        "normalization": "strict-sorted-unique-utf8-lines-v1",
        "status": "missing",
        "artifact_sha256": None,
        "artifact_size_bytes": None,
        "candidate_count": 0,
        "candidate_sha256": [],
        "matched_flag_sha256": [],
        "score": 0,
        "maximum_score": len(expected),
    }
    if path.is_symlink() or not path.exists():
        result["status"] = "invalid_symlink" if path.is_symlink() else "missing"
        return result
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        result["status"] = "invalid_escape_or_unreadable"
        return result
    try:
        body = _read_bounded_regular_file(resolved, maximum_bytes=MAX_CANDIDATE_BYTES)
    except EvidenceValidationError as exc:
        result["status"] = f"invalid_{str(exc).replace(' ', '_')[:80]}"
        return result
    result["artifact_sha256"] = _sha256_bytes(body)
    result["artifact_size_bytes"] = len(body)
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        result["status"] = "invalid_non_utf8"
        return result
    if "\r" in text or "\x00" in text:
        result["status"] = "invalid_control_character"
        return result
    lines = text.splitlines()
    if len(lines) > MAX_CANDIDATES:
        result["status"] = "invalid_too_many_candidates"
        return result
    if any(not line or _CANDIDATE_RE.fullmatch(line) is None for line in lines):
        result["status"] = "invalid_noncanonical_candidate_line"
        return result
    if lines != sorted(set(lines)):
        result["status"] = "invalid_not_sorted_unique"
        return result
    expected_body = "".join(f"{line}\n" for line in lines).encode("utf-8")
    if body != expected_body:
        result["status"] = "invalid_noncanonical_line_endings"
        return result
    candidate_digests = sorted({_sha256_text(line) for line in lines})
    matches = sorted(set(candidate_digests).intersection(expected))
    result.update(
        {
            "status": "scored",
            "candidate_count": len(candidate_digests),
            "candidate_sha256": candidate_digests,
            "matched_flag_sha256": matches,
            "score": len(matches),
        }
    )
    return result


def _authenticated_order_snapshot_inventory(snapshot: Path) -> list[dict[str, object]]:
    root = _existing_directory(snapshot, "authenticated order snapshot")
    observed: set[str] = set()
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise EvidenceValidationError("authenticated order snapshot contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise EvidenceValidationError(
                "authenticated order snapshot contains a non-regular entry"
            )
        relative = path.relative_to(root).as_posix()
        observed.add(relative)
        body = _read_bounded_regular_file(path, maximum_bytes=MAX_SEALED_FILE_BYTES)
        executable = bool(stat.S_IMODE(path.stat().st_mode) & 0o111)
        entries.append(
            {
                "path": relative,
                "sha256": _sha256_bytes(body),
                "size_bytes": len(body),
                "executable": executable,
            }
        )
    if observed != set(AUTHENTICATED_ORDER_SNAPSHOT_FILES):
        raise EvidenceValidationError(
            "authenticated order snapshot file set is not the frozen allowlist"
        )
    executable_paths = {str(entry["path"]) for entry in entries if entry["executable"] is True}
    if executable_paths != {"verifiers/drandverify", "verifiers/cosign"}:
        raise EvidenceValidationError("authenticated order snapshot verifier modes are invalid")
    return entries


def _validate_precommitted_order_identity_inputs(
    *,
    paired_contract: Mapping[str, object],
    paired_preflight: Mapping[str, object],
    known_contract: Mapping[str, object],
) -> None:
    """Cross-bind every arm-order input to exact pre-beacon paired bytes."""

    paired_sources = _mapping(paired_contract.get("sources"), "paired-XBEN sources")
    paired_runtimes = _mapping(
        paired_contract.get("runtime_manifests"),
        "paired-XBEN runtime manifests",
    )
    paired_images = _mapping(paired_contract.get("oci_images"), "paired-XBEN OCI images")
    paired_execution = _mapping(
        paired_contract.get("execution_policy"),
        "paired-XBEN execution policy",
    )
    known_systems = _mapping(known_contract.get("systems"), "known-site systems")
    image_roles = {"ravage": "ravage_tool", "strix": "strix_sandbox"}
    for system in SYSTEMS:
        paired_source = _mapping(paired_sources.get(system), f"paired-XBEN {system} source")
        paired_runtime = _mapping(
            paired_runtimes.get(system),
            f"paired-XBEN {system} runtime",
        )
        known = _mapping(known_systems.get(system), f"known-site {system} system")
        known_source = _mapping(known.get("source"), f"known-site {system} source")
        known_runtime = _mapping(known.get("runtime"), f"known-site {system} runtime")
        known_tool = _mapping(known.get("tool_image"), f"known-site {system} tool image")
        if (
            paired_source.get("origin_url") != known_source.get("origin_url")
            or paired_source.get("commit_sha") != known_source.get("commit")
            or paired_source.get("tree_object") != known_source.get("tree")
            or paired_source.get("tree_path") != known_source.get("tree_path")
            or paired_source.get("dirty") is not False
            or known_source.get("dirty") is not False
        ):
            raise EvidenceValidationError(
                f"paired-XBEN {system} source differs from the website system pin"
            )
        if (
            paired_runtime.get("schema_version") != known_runtime.get("schema_version")
            or paired_runtime.get("sha256") != known_runtime.get("manifest_sha256")
            or paired_runtime.get("executable_sha256") != known_runtime.get("executable_sha256")
        ):
            raise EvidenceValidationError(
                f"paired-XBEN {system} runtime differs from the website system pin"
            )
        if paired_images.get(image_roles[system]) != known_tool.get(
            "reference"
        ) or paired_execution.get("platform") != known_tool.get("platform"):
            raise EvidenceValidationError(
                f"paired-XBEN {system} tool image differs from the website system pin"
            )

    site = _mapping(known_contract.get("site"), "known-site target")
    site_source = _mapping(site.get("source"), "known-site target source")
    ravage_source = _mapping(
        _mapping(known_systems.get("ravage"), "known-site Ravage").get("source"),
        "known-site Ravage source",
    )
    if site_source.get("origin_url") != ravage_source.get("origin_url") or site_source.get(
        "commit"
    ) != ravage_source.get("commit"):
        raise EvidenceValidationError(
            "website target is not bound to the paired-XBEN Ravage revision"
        )

    paired_gateway = _mapping(
        paired_contract.get("model_gateway"),
        "paired-XBEN model gateway",
    )
    paired_policy = _mapping(paired_gateway.get("policy"), "paired-XBEN model policy")
    known_gateway = _mapping(known_contract.get("model_gateway"), "website model gateway")
    known_policy = _mapping(known_gateway.get("policy"), "website model policy")
    if {
        name: value for name, value in paired_policy.items() if name != "campaign_max_cost_usd"
    } != {name: value for name, value in known_policy.items() if name != "campaign_max_cost_usd"}:
        raise EvidenceValidationError("paired-XBEN and website model policies differ")

    paired_budgets = _mapping(paired_contract.get("budgets"), "paired-XBEN budgets")
    known_budgets = _mapping(known_contract.get("budgets"), "website budgets")
    if _mapping(paired_budgets.get("per_row"), "paired-XBEN per-row budget") != _mapping(
        known_budgets.get("per_arm"),
        "website per-arm budget",
    ):
        raise EvidenceValidationError("paired-XBEN and website per-arm budgets differ")

    order = _mapping(
        known_contract.get("authenticated_arm_order"),
        "authenticated arm-order source",
    )
    preflight_website = _mapping(
        paired_preflight.get("website"),
        "paired-XBEN website reference",
    )
    if preflight_website.get("reference_sha256") != order.get("website_reference_sha256"):
        raise EvidenceValidationError("paired-XBEN pre-draw website reference differs from its pin")
    expected_reference = _sha256_text(
        "content-addressed-website:" + str(order.get("website_content_sha256"))
    )
    if expected_reference != order.get("website_reference_sha256"):
        raise EvidenceValidationError(
            "paired-XBEN website reference does not bind its content digest"
        )


def _validate_authenticated_order_snapshot(
    snapshot: Path,
    *,
    contract_document: Mapping[str, object],
) -> dict[str, object]:
    """Re-run paired-XBEN cryptography and cross-bind the frozen website inputs."""

    _authenticated_order_snapshot_inventory(snapshot)
    try:
        verification = paired_xben_protocol_module.verify_campaign(
            snapshot,
            require_all_primary_attempts=False,
        )
    except Exception as exc:
        raise EvidenceValidationError(
            "retained paired-XBEN commitment/resolution verification failed"
        ) from exc
    order = _mapping(
        contract_document.get("authenticated_arm_order"),
        "authenticated arm-order source",
    )
    expected = {
        "phase": "resolved",
        "structurally_valid": True,
        "beacon_authenticity_verified": True,
        "publication_anchor_verified": True,
        "campaign_id": order.get("paired_campaign_id"),
        "commitment_digest": order.get("commitment_document_sha256"),
        "preflight_digest": order.get("preflight_document_sha256"),
        "beacon_digest": order.get("beacon_document_sha256"),
        "selection_digest": order.get("selection_document_sha256"),
    }
    if any(verification.get(name) != value for name, value in expected.items()):
        raise EvidenceValidationError(
            "retained paired-XBEN verification differs from the frozen order source"
        )
    commitment = _read_json(snapshot / "commitment.json", label="paired-XBEN commitment")
    preflight = _read_json(snapshot / "preflight-source.json", label="paired-XBEN preflight")
    selection = _read_json(
        snapshot / "resolution" / "selection.json",
        label="paired-XBEN selection",
    )
    if selection.get("draw_key_sha256") != order.get("draw_key_sha256"):
        raise EvidenceValidationError("retained paired-XBEN draw key differs from its pin")
    paired_contract = _mapping(commitment.get("run_contract"), "paired-XBEN run contract")
    _validate_precommitted_order_identity_inputs(
        paired_contract=paired_contract,
        paired_preflight=preflight,
        known_contract=contract_document,
    )
    raw_schedule = contract_document.get("schedule")
    if not isinstance(raw_schedule, list):
        raise EvidenceValidationError("website schedule must be a list")
    scheduled_systems = [
        _mapping(row, "website schedule row").get("system") for row in raw_schedule
    ]
    if scheduled_systems != list(_arm_order_from_contract(contract_document)):
        raise EvidenceValidationError("website schedule does not reproduce from the draw key")
    return {
        name: verification[name]
        for name in (
            "schema_version",
            "phase",
            "structurally_valid",
            "claim_ready",
            "beacon_authenticity_verified",
            "publication_anchor_verified",
            "claim_ready_scope",
            "campaign_id",
            "commitment_digest",
            "preflight_digest",
            "beacon_digest",
            "publication_anchor_digest",
            "selection_digest",
            "eligible_pool_digest",
            "selected_cases",
        )
    }


def _authenticated_order_evidence_document(
    root: Path,
    *,
    contract_document: Mapping[str, object],
) -> dict[str, object]:
    snapshot = root / AUTHENTICATED_ORDER_SNAPSHOT_DIRECTORY
    verification = _validate_authenticated_order_snapshot(
        snapshot,
        contract_document=contract_document,
    )
    order = _mapping(
        contract_document.get("authenticated_arm_order"),
        "authenticated arm-order source",
    )
    return _document(
        {
            "schema_version": AUTHENTICATED_ORDER_EVIDENCE_SCHEMA,
            "contract_sha256": contract_document.get("document_sha256"),
            "source_protocol": AUTHENTICATED_ARM_ORDER_PROTOCOL,
            "snapshot_directory": AUTHENTICATED_ORDER_SNAPSHOT_DIRECTORY,
            "source_pins": order,
            "derived_arm_order": list(_arm_order_from_contract(contract_document)),
            "snapshot_files": _authenticated_order_snapshot_inventory(snapshot),
            "offline_verification": verification,
            "verified_before_website_entropy": True,
        }
    )


def verify_known_site_regression(campaign_dir: Path) -> dict[str, object]:
    """Offline, fail-closed verification of the sealed two-arm evidence set."""

    root = _existing_directory(campaign_dir, "known-site campaign directory")
    errors: list[str] = []
    comparison_valid = False
    try:
        contract = _load_document(root / CONTRACT_FILE, RUN_CONTRACT_SCHEMA)
        _validate_contract_document(contract)
        execution_policy = _mapping(contract.get("execution_policy"), "execution policy")
        if execution_policy.get("canonical_campaign_directory_sha256") != (
            _canonical_campaign_directory_sha256(root)
        ):
            raise EvidenceValidationError(
                "campaign evidence is not at its frozen canonical destination"
            )
        retained_order = _load_document(
            root / AUTHENTICATED_ORDER_EVIDENCE_FILE,
            AUTHENTICATED_ORDER_EVIDENCE_SCHEMA,
        )
        if retained_order != _authenticated_order_evidence_document(
            root,
            contract_document=contract,
        ):
            raise EvidenceValidationError(
                "authenticated order evidence differs from retained verifier output"
            )
        commitments = _load_document(root / FLAG_COMMITMENTS_FILE, FLAG_COMMITMENTS_SCHEMA)
        _validate_flag_commitment_document(commitments, contract_document=contract)
        start = _load_document(root / EXECUTION_START_FILE, EXECUTION_START_SCHEMA)
        expected_start_fields = {
            "schema_version",
            "created_at",
            "campaign_id",
            "contract_sha256",
            "flag_commitments_sha256",
            "schedule",
            "attempts_per_arm",
            "retry_allowed",
            "resume_allowed",
            "replacement_allowed",
            "evaluation_classification",
            "claim_boundary",
            "eligible_for_sota_claim",
            "eligible_for_unseen_claim",
            "document_sha256",
        }
        if (
            set(start) != expected_start_fields
            or start.get("campaign_id") != contract.get("campaign_id")
            or start.get("contract_sha256") != contract["document_sha256"]
            or start.get("flag_commitments_sha256") != commitments["document_sha256"]
            or start.get("schedule") != contract["schedule"]
            or start.get("attempts_per_arm") != 1
            or start.get("retry_allowed") is not False
            or start.get("resume_allowed") is not False
            or start.get("replacement_allowed") is not False
        ):
            raise EvidenceValidationError("execution start bindings are inconsistent")
        release = _load_document(
            root / PRIVATE_DIRECTORY / "target-release.json",
            TARGET_RELEASE_SCHEMA,
        )
        _validate_target_release_document(release)
        commitment_entries = _commitment_entries(commitments)
        expected_hashes = tuple(str(entry["sha256"]) for entry in commitment_entries)
        expected_hashes_by_name = {
            str(entry["logical_name"]): str(entry["sha256"]) for entry in commitment_entries
        }
        arm_scores: list[dict[str, object]] = []
        target_starts: list[dict[str, object]] = []
        semantic_prompt_digests: list[str] = []
        operational_evidence_valid = True
        preparation_path = root / TARGET_PREPARATION_FILE
        prepared_images: dict[str, object] | None = None
        if preparation_path.exists():
            preparation = _load_document(preparation_path, TARGET_PREPARATION_SCHEMA)
            _validate_target_preparation_document(
                preparation,
                contract_document=contract,
                commitment_document=commitments,
            )
            prepared_images = _mapping(
                _mapping(preparation.get("build"), "prepared build").get("image_ids_by_service"),
                "prepared images",
            )
        for row_id, system in zip(
            ROW_IDS,
            _arm_order_from_contract(contract),
            strict=True,
        ):
            arm_root = root / PRIVATE_DIRECTORY / row_id
            terminal = _load_document(arm_root / "arm-terminal.json", ARM_TERMINAL_SCHEMA)
            if terminal.get("row_id") != row_id or terminal.get("system") != system:
                raise EvidenceValidationError("arm terminal schedule binding is invalid")
            target_start_path = arm_root / "target-start.json"
            target_stop_path = arm_root / "target-stop.json"
            target_start_exists = target_start_path.exists() or target_start_path.is_symlink()
            target_stop_exists = target_stop_path.exists() or target_stop_path.is_symlink()
            if target_stop_exists and not target_start_exists:
                raise EvidenceValidationError("target stop exists without a target start")
            target_start: dict[str, object] | None = None
            target_stop: dict[str, object] | None = None
            target_lifecycle_complete = False
            if target_start_exists:
                if prepared_images is None:
                    raise EvidenceValidationError(
                        "target arm exists without a sealed target preparation"
                    )
                target_start = _load_document(target_start_path, TARGET_ARM_START_SCHEMA)
                _validate_target_start_document(
                    target_start,
                    arm_root=arm_root,
                    contract_document=contract,
                    expected_row_id=row_id,
                    expected_system=system,
                    expected_flag_hashes_by_name=expected_hashes_by_name,
                    expected_image_ids_by_service=prepared_images,
                    expected_flag_commitments_sha256=str(commitments["document_sha256"]),
                    expected_target_limit=_contract_limit(contract, "max_target_requests"),
                )
                _cross_validate_live_identity(target_starts, target_start)
                target_starts.append(target_start)
                if target_stop_exists:
                    target_stop = _load_document(target_stop_path, TARGET_ARM_STOP_SCHEMA)
                    _validate_target_terminal_pair(
                        target_start,
                        target_stop,
                        arm_root=arm_root,
                        contract_document=contract,
                        expected_row_id=row_id,
                        expected_system=system,
                        expected_flag_hashes_by_name=expected_hashes_by_name,
                        expected_image_ids_by_service=prepared_images,
                        expected_flag_commitments_sha256=str(commitments["document_sha256"]),
                        expected_target_limit=_contract_limit(
                            contract,
                            "max_target_requests",
                        ),
                    )
                    target_lifecycle_complete = True
            score = _load_document(arm_root / "arm-score.json", ARM_SCORE_SCHEMA)
            if (
                score.get("row_id") != row_id
                or score.get("system") != system
                or score.get("scored_after_both_arms_terminal") is not True
                or score.get("terminal_document_sha256") != terminal.get("document_sha256")
                or score.get("terminal_status") != terminal.get("status")
            ):
                raise EvidenceValidationError("arm score schedule binding is invalid")
            terminal_success = _validate_terminal_contract(terminal, contract=contract)
            reportable_observation = _terminal_is_reportable_observation(terminal)
            recomputed = score_candidate_artifact(
                arm_root / NATIVE_OUTPUT_DIRECTORY,
                expected_flag_sha256=expected_hashes,
            )
            retained_score = (
                recomputed
                if terminal_success
                else _unsuccessful_zero_score(candidate_observation=recomputed)
            )
            raw_value = recomputed.get("score")
            maximum = recomputed.get("maximum_score")
            solved = bool(
                terminal_success
                and recomputed.get("status") == "scored"
                and isinstance(raw_value, int)
                and not isinstance(raw_value, bool)
                and raw_value == maximum
            )
            if (
                score.get("candidate_observation") != recomputed
                or score.get("score") != retained_score
            ):
                raise EvidenceValidationError("retained arm score differs from candidate bytes")
            if (
                score.get("eligible_for_score") is not reportable_observation
                or score.get("attempt_succeeded") is not terminal_success
                or score.get("solved") is not solved
            ):
                raise EvidenceValidationError("arm score verdict differs from its terminal")
            arm_scores.append(score)
            semantic = terminal.get("semantic_prompt_sha256")
            if isinstance(semantic, str):
                semantic_prompt_digests.append(semantic)
            _validate_terminal_target_bindings(
                terminal,
                target_start=target_start,
                target_stop=target_stop,
            )
            if target_start is not None and reportable_observation:
                _validate_process_target_binding(terminal, target_start)
            receipts_operational = _verify_agent_receipts(
                arm_root,
                terminal=terminal,
                contract=contract,
            )
            operational_evidence_valid = bool(
                operational_evidence_valid
                and reportable_observation
                and target_lifecycle_complete
                and receipts_operational
            )
        if semantic_prompt_digests and len(set(semantic_prompt_digests)) != 1:
            raise EvidenceValidationError("started arms did not receive one identical prompt")
        model_campaign = _load_document(root / MODEL_CAMPAIGN_FILE, MODEL_CAMPAIGN_SCHEMA)
        rebuilt_model = _model_campaign_document_from_contract_document(root, contract)
        if _semantic_document_body(model_campaign) != _semantic_document_body(rebuilt_model):
            raise EvidenceValidationError("model campaign receipt does not recompute")
        seal = _load_document(root / PRIMARY_SEAL_FILE, PRIMARY_SEAL_SCHEMA)
        _verify_primary_seal(root, seal=seal, contract_document=contract)
        report = _load_document(root / REPORT_FILE, REPORT_SCHEMA)
        rebuilt_report = _report_document(
            contract_document=contract,
            commitment_document=commitments,
            score_documents=arm_scores,
            model_campaign=model_campaign,
            primary_seal=seal,
            elapsed_seconds=_finite_nonnegative_float(
                report.get("elapsed_seconds"),
                "report elapsed time",
            ),
            operational_evidence_valid=operational_evidence_valid,
        )
        if _semantic_document_body(report) != _semantic_document_body(rebuilt_report):
            raise EvidenceValidationError("known-site report does not recompute")
        comparison_valid = rebuilt_report.get("valid_for_paired_known_site_regression") is True
    except Exception as exc:  # Every malformed artifact must fail closed, never crash verification.
        errors.append(_safe_error(exc, secrets_to_reject=()))
        report = {}
    return {
        "schema_version": "ravage.known-site.verification.v2",
        "classification": KNOWN_SITE_CLASSIFICATION,
        "claim_boundary": KNOWN_SITE_CLAIM_BOUNDARY,
        "eligible_for_sota_claim": False,
        "eligible_for_unseen_claim": False,
        "structurally_valid": not errors,
        "valid_for_paired_known_site_regression": bool(not errors and comparison_valid),
        "errors": errors,
        "report_document_sha256": report.get("document_sha256"),
    }


def _flag_commitment_document(
    contract: FrozenKnownSiteContract,
    *,
    contract_document: Mapping[str, object],
    flag_hashes_by_name: Mapping[str, str],
) -> dict[str, object]:
    entries = []
    for logical_name, environment_name in FLAG_ENVIRONMENT:
        entries.append(
            {
                "logical_name": logical_name,
                "runtime_environment_name": environment_name,
                "sha256": _sha256_digest(flag_hashes_by_name[logical_name], "flag digest"),
            }
        )
    return _document(
        {
            "schema_version": FLAG_COMMITMENTS_SCHEMA,
            "created_at": _now(),
            "campaign_id": contract.campaign_id,
            "contract_sha256": contract_document["document_sha256"],
            "algorithm": "sha256-of-exact-utf8-flag",
            "generator": "python-secrets-token-hex-32-os-csprng",
            "draw_calls": len(FLAG_ENVIRONMENT),
            "redraw_allowed": False,
            "unique": len(set(flag_hashes_by_name.values())) == len(FLAG_ENVIRONMENT),
            "commitments": entries,
            "plaintext_values_persisted": False,
            "committed_before_either_arm": True,
        }
    )


def _execution_start_document(
    contract: FrozenKnownSiteContract,
    *,
    contract_document: Mapping[str, object],
    commitment_document: Mapping[str, object],
) -> dict[str, object]:
    return _document(
        {
            "schema_version": EXECUTION_START_SCHEMA,
            "created_at": _now(),
            "campaign_id": contract.campaign_id,
            "contract_sha256": contract_document["document_sha256"],
            "flag_commitments_sha256": commitment_document["document_sha256"],
            "schedule": contract_document["schedule"],
            "attempts_per_arm": 1,
            "retry_allowed": False,
            "resume_allowed": False,
            "replacement_allowed": False,
        }
    )


def _target_preparation_document(
    contract: FrozenKnownSiteContract,
    *,
    prepared: PreparedKnownSiteTarget,
    commitment_document: Mapping[str, object],
) -> dict[str, object]:
    images = _image_map(prepared.image_ids_by_service)
    build_counts = _build_count_map(prepared.build_count_by_service)
    if not prepared.clean_pinned_archive_verified:
        raise EvidenceValidationError("target was not exported as a clean pinned Git archive")
    if prepared.flags_used_during_build or not prepared.runtime_flag_injection_only:
        raise EvidenceValidationError("site flags must not participate in the shared image build")
    if any(
        (
            prepared.source_mounted_into_agent,
            prepared.operator_material_mounted_into_agent,
            prepared.credential_material_mounted_into_agent,
        )
    ):
        raise EvidenceValidationError("target preparation exposes evaluator/source material")
    return _document(
        {
            "schema_version": TARGET_PREPARATION_SCHEMA,
            "created_at": _now(),
            "campaign_id": contract.campaign_id,
            "site_id": KNOWN_SITE_ID,
            "source": {
                **contract.source.to_json(),
                "archive_sha256": _sha256_digest(
                    prepared.source_archive_sha256, "source archive digest"
                ),
                "snapshot_tree_sha256": _sha256_digest(
                    prepared.source_tree_sha256, "source snapshot tree digest"
                ),
                "clean_pinned_archive_verified": True,
            },
            "flag_commitments_sha256": commitment_document["document_sha256"],
            "target_runtime": _validate_target_runtime(contract.target_runtime),
            "build": {
                "prepare_invocations": 1,
                "count_by_service": build_counts,
                "image_ids_by_service": images,
                "flags_used_during_build": False,
                "runtime_flag_injection_only": True,
            },
            "agent_exposure": {
                "source_mounted": False,
                "operator_material_mounted": False,
                "credential_material_mounted": False,
                "excluded_operator_files": list(EXCLUDED_OPERATOR_FILES),
            },
            "runtime_policy": {
                "expected_arms": list(contract.arm_order),
                "runtime_build_allowed": False,
                "runtime_pull_allowed": False,
                "identical_image_ids_required": True,
            },
        }
    )


def _target_arm_start_document(
    contract: FrozenKnownSiteContract,
    *,
    prepared: PreparedKnownSiteTarget,
    live: LiveKnownSiteArm,
    commitment_document: Mapping[str, object],
    arm_root: Path,
) -> dict[str, object]:
    expected_system = (
        contract.arm_order[ROW_IDS.index(live.row_id)] if live.row_id in ROW_IDS else None
    )
    if live.system != expected_system:
        raise EvidenceValidationError("live target arm differs from the frozen schedule")
    if not live.fresh or live.build_invocations != 0 or live.pull_invocations != 0:
        raise EvidenceValidationError("target arm was not a fresh image-only launch")
    images = _image_map(live.image_ids_by_service)
    if images != _image_map(prepared.image_ids_by_service):
        raise EvidenceValidationError("target arm did not reuse the prepared image IDs")
    containers = _service_id_map(live.container_ids_by_service, "container")
    volumes = _unique_safe_ids(live.volume_ids, "volume", require_nonempty=True)
    flag_hashes = {
        name: _sha256_digest(value, f"runtime flag digest {name}")
        for name, value in sorted(live.runtime_flag_sha256_by_name.items())
    }
    expected_commitments = {
        str(entry["logical_name"]): str(entry["sha256"])
        for entry in _commitment_entries(commitment_document)
    }
    if flag_hashes != expected_commitments:
        raise EvidenceValidationError("runtime flags differ from the pre-arm commitments")
    if live.request_limit != contract.limits.max_target_requests_per_arm:
        raise EvidenceValidationError("target arm request limit differs from the contract")
    if live.source_mounts or live.operator_material_mounts or live.credential_material_mounts:
        raise EvidenceValidationError("target arm exposed prohibited host material")
    _validated_http_url(live.target_url)
    agent_vm = _live_agent_vm_evidence_document(
        contract,
        live=live,
        arm_root=arm_root,
    )
    return _document(
        {
            "schema_version": TARGET_ARM_START_SCHEMA,
            "created_at": _now(),
            "row_id": live.row_id,
            "system": live.system,
            "instance_id": _safe_id(live.instance_id, "target instance ID"),
            "target_url_sha256": _sha256_text(live.target_url),
            "project_id": _safe_id(live.project_id, "Docker project ID"),
            "network_id": _safe_id(live.network_id, "Docker network ID"),
            "container_ids_by_service": containers,
            "volume_ids": list(volumes),
            "image_ids_by_service": images,
            "runtime_flag_sha256_by_name": flag_hashes,
            "flag_commitments_sha256": commitment_document["document_sha256"],
            "fresh": True,
            "build_invocations": 0,
            "pull_invocations": 0,
            "source_mounts": [],
            "operator_material_mounts": [],
            "credential_material_mounts": [],
            "request_limit": live.request_limit,
            "request_meter": "evaluator-owned-hard-http-allowance",
            "agent_vm": agent_vm,
        }
    )


def _target_arm_stop_document(
    *,
    live: LiveKnownSiteArm,
    teardown: SiteArmTeardown,
    arm_root: Path,
) -> dict[str, object]:
    if teardown.row_id != live.row_id or teardown.instance_id != live.instance_id:
        raise EvidenceValidationError("target teardown identity differs from its live arm")
    if (
        isinstance(teardown.observed_target_requests, bool)
        or not isinstance(teardown.observed_target_requests, int)
        or not 0 <= teardown.observed_target_requests <= live.request_limit
        or teardown.request_limit != live.request_limit
    ):
        raise EvidenceValidationError("target request-meter terminal count is invalid")
    if not teardown.request_meter_sealed or not teardown.request_meter_complete:
        raise EvidenceValidationError("target request meter did not seal completely")
    if teardown.containers_remaining or teardown.volumes_remaining or teardown.networks_remaining:
        raise EvidenceValidationError("target resources remain after terminal teardown")
    expected_containers = set(live.container_ids_by_service.values())
    if set(teardown.removed_container_ids) != expected_containers:
        raise EvidenceValidationError("removed target containers differ from the started arm")
    if set(teardown.removed_volume_ids) != set(live.volume_ids):
        raise EvidenceValidationError("removed target volumes differ from the started arm")
    if set(teardown.removed_network_ids) != {live.network_id}:
        raise EvidenceValidationError("removed target network differs from the started arm")
    agent_vm = live.agent_vm
    stopped_vm = teardown.agent_vm
    if (
        agent_vm is None
        or stopped_vm is None
        or stopped_vm.row_id != live.row_id
        or stopped_vm.generation_id != agent_vm.generation_id
    ):
        raise EvidenceValidationError("agent VM teardown is absent or differs from its live row")
    teardown_path = _safe_evidence_relative(
        arm_root,
        stopped_vm.teardown_receipt_path,
        label="agent VM teardown receipt",
    )
    return _document(
        {
            "schema_version": TARGET_ARM_STOP_SCHEMA,
            "created_at": _now(),
            "row_id": live.row_id,
            "instance_id": live.instance_id,
            "request_meter": {
                "observed_target_requests": teardown.observed_target_requests,
                "hard_limit": teardown.request_limit,
                "sealed": True,
                "complete": True,
                "within_limit": True,
            },
            "resources": {
                "removed_container_ids": sorted(teardown.removed_container_ids),
                "removed_volume_ids": sorted(teardown.removed_volume_ids),
                "removed_network_ids": sorted(teardown.removed_network_ids),
                "containers_remaining": [],
                "volumes_remaining": [],
                "networks_remaining": [],
            },
            "agent_vm": {
                "row_id": stopped_vm.row_id,
                "generation_id": stopped_vm.generation_id,
                "teardown_receipt": {
                    "path": stopped_vm.teardown_receipt_path,
                    "file_sha256": _sha256_regular_file(teardown_path),
                },
            },
        }
    )


def _live_agent_vm_evidence_document(
    contract: FrozenKnownSiteContract,
    *,
    live: LiveKnownSiteArm,
    arm_root: Path,
) -> dict[str, object]:
    evidence = live.agent_vm
    if evidence is None or evidence.row_id != live.row_id:
        raise EvidenceValidationError("live agent VM provision evidence is absent")
    policy = contract.docker_separation.agent_vm.to_json(campaign_id=contract.campaign_id)
    plans = _mapping(policy.get("plans"), "agent VM plans")
    expected_plan = _mapping(plans.get(live.row_id), "agent VM row plan")
    observed_plan = {
        "generation_id": evidence.generation_id,
        "profile_name": evidence.profile_name,
        "docker_socket_path_sha256": _sha256_digest(
            evidence.docker_socket_path_sha256,
            "live agent VM Docker socket digest",
        ),
        "docker_host_sha256": _sha256_digest(
            evidence.docker_host_sha256,
            "live agent VM Docker host digest",
        ),
        "agent_network": evidence.agent_network,
    }
    if observed_plan != expected_plan:
        raise EvidenceValidationError("live agent VM differs from its precommitted row plan")
    expected_policy_digest = _sha256_bytes(_canonical_json(policy))
    if evidence.frozen_policy_sha256 != expected_policy_digest:
        raise EvidenceValidationError("live agent VM policy binding differs from the contract")
    target_identity = contract.docker_separation.target.daemon_identity_sha256
    agent_identity = _sha256_digest(
        evidence.agent_daemon_identity_sha256,
        "live agent Docker daemon identity digest",
    )
    if agent_identity == target_identity:
        raise EvidenceValidationError("live target and agent Docker daemon identities are shared")
    target_meter = _sha256_digest(
        evidence.target_meter_url_sha256,
        "target meter URL digest",
    )
    canary_value = derive_target_canary_value(
        campaign_id=contract.campaign_id,
        row_id=live.row_id,
        instance_id=live.instance_id,
        generation_id=evidence.generation_id,
    )
    expected_canary = _sha256_text(f"{TARGET_CANARY_LABEL}={canary_value}")
    if evidence.target_canary_selector_sha256 != expected_canary:
        raise EvidenceValidationError("target metadata canary is not bound to the live row")
    model_gateway = _sha256_digest(
        evidence.model_gateway_url_sha256,
        "model gateway URL digest",
    )
    if target_meter == model_gateway:
        raise EvidenceValidationError("target meter and model gateway relay bindings are shared")
    agent_target = _sha256_digest(
        evidence.agent_visible_target_url_sha256,
        "agent-visible target URL digest",
    )
    agent_model = _sha256_digest(
        evidence.agent_visible_model_gateway_url_sha256,
        "agent-visible model gateway URL digest",
    )
    if agent_target != _sha256_text(live.target_url) or agent_target == agent_model:
        raise EvidenceValidationError("agent-visible relay endpoints are invalid")
    provision_path = _safe_evidence_relative(
        arm_root,
        evidence.provision_receipt_path,
        label="agent VM provision receipt",
    )
    return {
        "row_id": evidence.row_id,
        "plan": observed_plan,
        "frozen_policy_sha256": expected_policy_digest,
        "observed_agent_daemon_identity_sha256": agent_identity,
        "target_canary_selector_sha256": expected_canary,
        "target_meter_url_sha256": target_meter,
        "model_gateway_url_sha256": model_gateway,
        "agent_visible_target_url_sha256": agent_target,
        "agent_visible_model_gateway_url_sha256": agent_model,
        "provision_receipt": {
            "path": evidence.provision_receipt_path,
            "file_sha256": _sha256_regular_file(provision_path),
        },
    }


def _arm_terminal_document(
    contract: FrozenKnownSiteContract,
    *,
    context: AgentArmContext,
    terminal: AgentArmTerminal,
    target_start: Mapping[str, object] | None,
    target_stop: Mapping[str, object] | None,
    error: str | None,
) -> dict[str, object]:
    if terminal.adapter_version != ADAPTER_VERSION and terminal.status != "unstarted":
        raise EvidenceValidationError("known-site arm did not use the frozen canonical adapter")
    if terminal.description_sha256 != _sha256_text(KNOWN_SITE_PUBLIC_DESCRIPTION):
        raise EvidenceValidationError("known-site arm description bytes drifted")
    if terminal.model_gateway_policy_sha256 != contract.model_gateway_policy_sha256:
        raise EvidenceValidationError("known-site arm model gateway policy drifted")
    if terminal.evidence_class != PAIRED_LOCAL:
        raise EvidenceValidationError("known-site arm must disclose its paired-local boundary")
    if terminal.artifact_path not in {None, CANDIDATE_ARTIFACT_PATH}:
        raise EvidenceValidationError("known-site arm declared a non-allowlisted score artifact")
    artifact_receipt: dict[str, object] | None = None
    if terminal.artifact_path is None:
        if terminal.artifact_sha256 is not None:
            raise EvidenceValidationError("known-site arm declared a digest without an artifact")
    else:
        artifact = _safe_evidence_relative(
            context.native_output_dir,
            terminal.artifact_path,
            label="candidate artifact",
        )
        artifact_sha256 = _sha256_bytes(
            _read_bounded_regular_file(artifact, maximum_bytes=MAX_CANDIDATE_BYTES)
        )
        if terminal.artifact_sha256 != artifact_sha256:
            raise EvidenceValidationError(
                "known-site candidate bytes differ from the adapter terminal digest"
            )
        artifact_receipt = {
            "path": f"{NATIVE_OUTPUT_DIRECTORY}/{terminal.artifact_path}",
            "file_sha256": artifact_sha256,
            "size_bytes": artifact.stat().st_size,
        }
    if (
        isinstance(terminal.returncode, bool)
        or not isinstance(terminal.returncode, int)
        or isinstance(terminal.elapsed_seconds, bool)
        or not isinstance(terminal.elapsed_seconds, (int, float))
        or not math.isfinite(terminal.elapsed_seconds)
        or terminal.elapsed_seconds < 0
        or terminal.elapsed_seconds > context.limits.wall_seconds
    ):
        raise EvidenceValidationError("known-site arm process timing is invalid")
    receipt_hashes: dict[str, object] = {}
    receipt_hashes["candidate_artifact"] = artifact_receipt
    for name, relative in (
        ("adapter", terminal.adapter_receipt_path),
        ("process", terminal.process_receipt_path),
        ("model", terminal.model_receipt_path),
        ("sandbox_profile", terminal.sandbox_profile_path),
    ):
        if relative is None:
            receipt_hashes[name] = None
            continue
        path = _safe_evidence_relative(context.evidence_dir, relative, label=f"{name} receipt")
        receipt_hashes[name] = {
            "path": relative,
            "file_sha256": _sha256_regular_file(path),
            "size_bytes": path.stat().st_size,
        }
    for name, relative in (
        ("agent_vm_provision", f"agent-daemon/{AGENT_DAEMON_PROVISION_FILE}"),
        ("agent_vm_relay_probes", f"agent-daemon/{HOST_RELAY_PROBE_FILE}"),
        ("agent_vm_teardown", f"agent-daemon/{AGENT_DAEMON_TEARDOWN_FILE}"),
    ):
        required = target_start is not None
        if name == "agent_vm_teardown":
            required = target_stop is not None
        if not required:
            receipt_hashes[name] = None
            continue
        path = _safe_evidence_relative(context.evidence_dir, relative, label=f"{name} receipt")
        receipt_hashes[name] = {
            "path": relative,
            "file_sha256": _sha256_regular_file(path),
            "size_bytes": path.stat().st_size,
        }
    terminal_error = _merged_terminal_error(terminal.error, error)
    # A successful agent exit cannot make an arm successful when its target
    # lifecycle failed.  Preserve the process return code and receipts, but
    # truthfully terminalize the composite arm as failed.
    status: ArmStatus = terminal.status
    if status == "completed" and terminal_error is not None:
        status = "failed"
    return _document(
        {
            "schema_version": ARM_TERMINAL_SCHEMA,
            "created_at": _now(),
            "row_id": context.row_id,
            "system": context.system,
            "status": status,
            "returncode": terminal.returncode,
            "timed_out": terminal.timed_out,
            "elapsed_seconds": round(float(terminal.elapsed_seconds), 6),
            "description_sha256": terminal.description_sha256,
            "semantic_prompt_sha256": terminal.semantic_prompt_sha256,
            "model_gateway_policy_sha256": terminal.model_gateway_policy_sha256,
            "adapter_version": terminal.adapter_version,
            "artifact_path": terminal.artifact_path,
            "artifact_sha256": terminal.artifact_sha256,
            "evidence_class": terminal.evidence_class,
            "process_public_contract": terminal.process_public_contract,
            "target_started": target_start is not None,
            "target_start_sha256": target_start.get("document_sha256")
            if target_start is not None
            else None,
            "target_stopped": target_stop is not None,
            "target_stop_sha256": target_stop.get("document_sha256")
            if target_stop is not None
            else None,
            "receipts": receipt_hashes,
            "error": terminal_error,
            "attempt": 1,
            "retry_allowed": False,
            "resume_allowed": False,
            "replacement_allowed": False,
        }
    )


def _arm_score_document(
    record: _ArmRecord,
    *,
    score: Mapping[str, object],
) -> dict[str, object]:
    terminal_success = _terminal_is_success(record.terminal_document)
    reportable_observation = _terminal_is_reportable_observation(record.terminal_document)
    retained_score = (
        dict(score) if terminal_success else _unsuccessful_zero_score(candidate_observation=score)
    )
    raw_value = score.get("score")
    maximum = score.get("maximum_score")
    solved = bool(
        terminal_success
        and score.get("status") == "scored"
        and isinstance(raw_value, int)
        and not isinstance(raw_value, bool)
        and raw_value == maximum
    )
    return _document(
        {
            "schema_version": ARM_SCORE_SCHEMA,
            "created_at": _now(),
            "row_id": record.row_id,
            "system": record.system,
            "scored_after_both_arms_terminal": True,
            "terminal_document_sha256": record.terminal_document["document_sha256"],
            "terminal_status": record.terminal_document["status"],
            "eligible_for_score": reportable_observation,
            "attempt_succeeded": terminal_success,
            "solved": solved,
            "candidate_observation": dict(score),
            "score": retained_score,
        }
    )


def _unsuccessful_zero_score(
    *,
    candidate_observation: Mapping[str, object],
) -> dict[str, object]:
    result = dict(candidate_observation)
    result.update(
        {
            "status": "retained_unsuccessful_zero",
            "matched_flag_sha256": [],
            "score": 0,
        }
    )
    return result


def _model_campaign_document(
    root: Path,
    *,
    contract: FrozenKnownSiteContract,
    gateway_error: str | None,
) -> dict[str, object]:
    return _model_campaign_document_from_values(
        root,
        policy=contract.model_gateway_policy,
        policy_sha256=contract.model_gateway_policy_sha256,
        limits=contract.limits,
        arm_order=contract.arm_order,
        gateway_error=gateway_error,
    )


def _model_campaign_document_from_contract_document(
    root: Path,
    contract: Mapping[str, object],
) -> dict[str, object]:
    gateway = _mapping(contract.get("model_gateway"), "model gateway contract")
    budgets = _mapping(contract.get("budgets"), "budget contract")
    per_arm = _mapping(budgets.get("per_arm"), "per-arm budget")
    campaign = _mapping(budgets.get("campaign"), "campaign budget")
    limits = KnownSiteLimits.build(
        wall_seconds_per_arm=_positive_int(per_arm.get("wall_seconds"), "arm wall limit"),
        max_model_requests_per_arm=_positive_int(
            per_arm.get("max_model_requests"), "arm model request limit"
        ),
        max_target_requests_per_arm=_positive_int(
            per_arm.get("max_target_requests"), "arm target request limit"
        ),
        max_cost_usd_per_arm=str(per_arm.get("max_cost_usd")),
        campaign_wall_seconds=_positive_int(campaign.get("wall_seconds"), "campaign wall limit"),
        campaign_max_model_requests=_positive_int(
            campaign.get("max_model_requests"), "campaign model request limit"
        ),
        campaign_max_target_requests=_positive_int(
            campaign.get("max_target_requests"), "campaign target request limit"
        ),
        campaign_max_cost_usd=str(campaign.get("max_cost_usd")),
    )
    return _model_campaign_document_from_values(
        root,
        policy=_mapping(gateway.get("policy"), "model policy"),
        policy_sha256=str(gateway.get("policy_sha256")),
        limits=limits,
        arm_order=_arm_order_from_contract(contract),
        # The retained document records a gateway lifecycle error; it is not
        # inferable from receipts.  Reuse it solely for deterministic rebuild.
        gateway_error=_load_document(root / MODEL_CAMPAIGN_FILE, MODEL_CAMPAIGN_SCHEMA).get(
            "gateway_error"
        )
        if (root / MODEL_CAMPAIGN_FILE).exists()
        else None,
    )


def _model_campaign_document_from_values(
    root: Path,
    *,
    policy: Mapping[str, object],
    policy_sha256: str,
    limits: KnownSiteLimits,
    arm_order: tuple[SystemId, SystemId],
    gateway_error: object,
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    charged = Decimal(0)
    actual = Decimal(0)
    requests = 0
    all_valid = True
    for row_id, system in zip(
        ROW_IDS,
        arm_order,
        strict=True,
    ):
        path = root / PRIVATE_DIRECTORY / row_id / MODEL_RECEIPT_FILE
        try:
            payload = _read_json(path, label=f"model receipt {row_id}")
            validated = validate_model_gateway_receipt(
                payload,
                expected_row_id=row_id,
                expected_policy_sha256=policy_sha256,
                expected_max_requests=limits.max_model_requests_per_arm,
                expected_max_cost_usd=limits.max_cost_usd_per_arm,
            )
            totals = _mapping(validated.get("totals"), "model receipt totals")
            row_charged = _decimal(totals.get("charged_cost_usd"), "charged model cost")
            row_actual = _decimal(totals.get("known_actual_cost_usd"), "actual model cost")
            row_requests = _nonnegative_int(
                totals.get("requests_started"), "model requests started"
            )
            row_valid = validated.get("valid") is True
            rows.append(
                {
                    "row_id": row_id,
                    "system": system,
                    "receipt_path": f"{PRIVATE_DIRECTORY}/{row_id}/{MODEL_RECEIPT_FILE}",
                    "receipt_file_sha256": _sha256_regular_file(path),
                    "receipt_document_sha256": validated["document_sha256"],
                    "requests_started": row_requests,
                    "charged_cost_usd": _money(row_charged),
                    "known_actual_cost_usd": _money(row_actual),
                    "valid": row_valid,
                    "error": None,
                }
            )
            charged = _add_money(charged, row_charged)
            actual = _add_money(actual, row_actual)
            requests += row_requests
            all_valid = all_valid and row_valid
        except (OSError, EvidenceValidationError, ModelGatewayError, InvalidOperation) as exc:
            all_valid = False
            rows.append(
                {
                    "row_id": row_id,
                    "system": system,
                    "receipt_path": f"{PRIVATE_DIRECTORY}/{row_id}/{MODEL_RECEIPT_FILE}",
                    "receipt_file_sha256": None,
                    "receipt_document_sha256": None,
                    "requests_started": None,
                    "charged_cost_usd": None,
                    "known_actual_cost_usd": None,
                    "valid": False,
                    "error": str(exc)[:500],
                }
            )
    within_cost = charged <= limits.campaign_max_cost_usd
    within_requests = requests <= limits.campaign_max_model_requests
    return _document(
        {
            "schema_version": MODEL_CAMPAIGN_SCHEMA,
            "created_at": _now(),
            "policy": _validate_model_policy(policy),
            "policy_sha256": _sha256_digest(policy_sha256, "model policy digest"),
            "expected_row_ids": list(ROW_IDS),
            "rows": rows,
            "totals": {
                "requests_started": requests,
                "charged_cost_usd": _money(charged),
                "known_actual_cost_usd": _money(actual),
                "campaign_max_requests": limits.campaign_max_model_requests,
                "campaign_max_cost_usd": _money(limits.campaign_max_cost_usd),
                "within_request_limit": within_requests,
                "within_cost_limit": within_cost,
            },
            "gateway_error": gateway_error,
            "all_rows_sealed": all(row.get("receipt_document_sha256") is not None for row in rows),
            "valid": bool(all_valid and within_cost and within_requests and gateway_error is None),
        }
    )


def _primary_seal_document(
    root: Path,
    *,
    contract_document: Mapping[str, object],
) -> dict[str, object]:
    files = _sealed_file_manifest(root)
    return _document(
        {
            "schema_version": PRIMARY_SEAL_SCHEMA,
            "created_at": _now(),
            "campaign_id": contract_document["campaign_id"],
            "contract_sha256": contract_document["document_sha256"],
            "classification": KNOWN_SITE_CLASSIFICATION,
            "claim_boundary": KNOWN_SITE_CLAIM_BOUNDARY,
            "expected_rows": list(ROW_IDS),
            "evidence_files": files,
            "file_count": len(files),
            "retry_count": 0,
            "resume_count": 0,
            "replacement_count": 0,
        }
    )


def _report_document(
    *,
    contract_document: Mapping[str, object],
    commitment_document: Mapping[str, object],
    score_documents: Sequence[Mapping[str, object]],
    model_campaign: Mapping[str, object],
    primary_seal: Mapping[str, object],
    elapsed_seconds: float,
    operational_evidence_valid: bool,
) -> dict[str, object]:
    scores: dict[str, int] = {}
    statuses: dict[str, str] = {}
    candidate_statuses: dict[str, str] = {}
    terminal_statuses: dict[str, str] = {}
    reportable_observations: dict[str, bool] = {}
    attempts_succeeded: dict[str, bool] = {}
    solved: dict[str, bool] = {}
    score_documents_valid = True
    expected_rows_by_system = {
        system: row_id
        for row_id, system in zip(
            ROW_IDS,
            _arm_order_from_contract(contract_document),
            strict=True,
        )
    }
    observed_rows: set[str] = set()
    for document in score_documents:
        system = str(document.get("system"))
        row_id = str(document.get("row_id"))
        if (
            system in scores
            or system not in SYSTEMS
            or row_id in observed_rows
            or expected_rows_by_system.get(system) != row_id
        ):
            raise EvidenceValidationError("known-site score systems are invalid")
        observed_rows.add(row_id)
        score = _mapping(document.get("score"), "arm score")
        candidate = _mapping(document.get("candidate_observation"), "candidate observation")
        value = score.get("score")
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 5:
            raise EvidenceValidationError("known-site score is outside 0..5")
        scores[system] = value
        statuses[system] = str(score.get("status"))
        candidate_statuses[system] = str(candidate.get("status"))
        terminal_statuses[system] = str(document.get("terminal_status"))
        reportable_observations[system] = document.get("eligible_for_score") is True
        attempts_succeeded[system] = document.get("attempt_succeeded") is True
        solved[system] = document.get("solved") is True
        formal_score_valid = (
            score.get("status") == candidate.get("status")
            if attempts_succeeded[system]
            else score.get("status") == "retained_unsuccessful_zero" and value == 0
        )
        score_documents_valid = bool(
            score_documents_valid
            and reportable_observations[system]
            and formal_score_valid
            and (not solved[system] or attempts_succeeded[system])
        )
    all_precommitted_rows_terminal = bool(
        len(score_documents) == len(SYSTEMS) and set(scores) == set(SYSTEMS)
    )
    # ``complete`` is comparison completeness, not merely the presence of two
    # terminal row slots.  An unstarted slot remains sealed evidence but does
    # not become a loss for a system that never ran.
    complete = bool(all_precommitted_rows_terminal and score_documents_valid)
    scoreable = complete
    model_gateway_valid = model_campaign.get("valid") is True
    valid_for_paired_known_site_regression = bool(
        scoreable and model_gateway_valid and operational_evidence_valid
    )
    comparison_withheld_reasons: list[str] = []
    if not scoreable:
        comparison_withheld_reasons.append("campaign_not_scoreable")
    if not model_gateway_valid:
        comparison_withheld_reasons.append("model_gateway_invalid")
    if not operational_evidence_valid:
        comparison_withheld_reasons.append("operational_evidence_invalid")
    body = {
        "schema_version": REPORT_SCHEMA,
        "created_at": _now(),
        "campaign_id": contract_document["campaign_id"],
        "classification": KNOWN_SITE_CLASSIFICATION,
        "claim_boundary": KNOWN_SITE_CLAIM_BOUNDARY,
        "purpose": "paired-known-site-end-to-end-regression-only",
        "eligible_for_sota_claim": False,
        "eligible_for_unseen_claim": False,
        "eligible_for_holdout_claim": False,
        "contract_sha256": contract_document["document_sha256"],
        "flag_commitments_sha256": commitment_document["document_sha256"],
        "primary_seal_sha256": primary_seal["document_sha256"],
        "model_campaign_sha256": model_campaign["document_sha256"],
        "elapsed_seconds": elapsed_seconds,
        "arms_terminal": len(score_documents),
        "expected_arms": len(SYSTEMS),
        "all_precommitted_rows_terminal": all_precommitted_rows_terminal,
        "complete": complete,
        "scores_out_of_five": (
            dict(sorted(scores.items()))
            if valid_for_paired_known_site_regression
            else {
                "available": False,
                "withheld": True,
                "reasons": comparison_withheld_reasons,
            }
        ),
        "score_artifact_status": dict(sorted(statuses.items())),
        "candidate_artifact_status": dict(sorted(candidate_statuses.items())),
        "arm_terminal_status": dict(sorted(terminal_statuses.items())),
        "arm_reportable_observation": dict(sorted(reportable_observations.items())),
        "arm_attempt_succeeded": dict(sorted(attempts_succeeded.items())),
        "arm_solved": dict(sorted(solved.items())),
        "all_attempts_succeeded": bool(
            all_precommitted_rows_terminal and all(attempts_succeeded.values())
        ),
        "all_arms_solved": bool(all_precommitted_rows_terminal and all(solved.values())),
        "scoreable": scoreable,
        "model_gateway_valid": model_gateway_valid,
        "agent_vm_lifecycle_valid": operational_evidence_valid,
        "canonical_process_target_evidence_valid": operational_evidence_valid,
        "valid_for_paired_known_site_regression": valid_for_paired_known_site_regression,
        "local_evidence_is_cryptographic_execution_attestation": False,
        "trusted_host_boundary": (
            "paired-local Docker/process evidence cannot prove absence of undisclosed host runs"
        ),
    }
    return _document(body)


def _campaign_operational_evidence_valid(
    root: Path,
    *,
    contract_document: Mapping[str, object],
) -> bool:
    """Re-run portable target and canonical process checks before reporting."""

    try:
        commitments = _load_document(root / FLAG_COMMITMENTS_FILE, FLAG_COMMITMENTS_SCHEMA)
        preparation = _load_document(
            root / TARGET_PREPARATION_FILE,
            TARGET_PREPARATION_SCHEMA,
        )
        release = _load_document(
            root / PRIVATE_DIRECTORY / "target-release.json",
            TARGET_RELEASE_SCHEMA,
        )
        _validate_target_release_document(release)
        _validate_target_preparation_document(
            preparation,
            contract_document=contract_document,
            commitment_document=commitments,
        )
        commitment_entries = _commitment_entries(commitments)
        expected_hashes_by_name = {
            str(entry["logical_name"]): str(entry["sha256"]) for entry in commitment_entries
        }
        prepared_images = _mapping(
            _mapping(preparation.get("build"), "prepared build").get("image_ids_by_service"),
            "prepared images",
        )
        starts: list[dict[str, object]] = []
        semantic_prompt_digests: list[str] = []
        for row_id, system in zip(
            ROW_IDS,
            _arm_order_from_contract(contract_document),
            strict=True,
        ):
            arm_root = root / PRIVATE_DIRECTORY / row_id
            start = _load_document(arm_root / "target-start.json", TARGET_ARM_START_SCHEMA)
            stop = _load_document(arm_root / "target-stop.json", TARGET_ARM_STOP_SCHEMA)
            terminal = _load_document(arm_root / "arm-terminal.json", ARM_TERMINAL_SCHEMA)
            _validate_target_terminal_pair(
                start,
                stop,
                arm_root=arm_root,
                contract_document=contract_document,
                expected_row_id=row_id,
                expected_system=system,
                expected_flag_hashes_by_name=expected_hashes_by_name,
                expected_image_ids_by_service=prepared_images,
                expected_flag_commitments_sha256=str(commitments["document_sha256"]),
                expected_target_limit=_contract_limit(
                    contract_document,
                    "max_target_requests",
                ),
            )
            _cross_validate_live_identity(starts, start)
            starts.append(start)
            _validate_terminal_contract(terminal, contract=contract_document)
            if not _terminal_is_reportable_observation(terminal):
                return False
            _validate_terminal_target_bindings(
                terminal,
                target_start=start,
                target_stop=stop,
            )
            _validate_process_target_binding(terminal, start)
            semantic = terminal.get("semantic_prompt_sha256")
            if not isinstance(semantic, str):
                return False
            semantic_prompt_digests.append(semantic)
            if not _verify_agent_receipts(
                arm_root,
                terminal=terminal,
                contract=contract_document,
            ):
                return False
        if len(set(semantic_prompt_digests)) != 1:
            return False
    except (
        EvidenceValidationError,
        ModelGatewayError,
        ComparisonProcessError,
        OSError,
    ):
        return False
    return True


def _validate_target_release_document(document: Mapping[str, object]) -> None:
    """Require the target backend's one terminal release to have succeeded."""

    if document.get("released") is not True:
        raise EvidenceValidationError("known-site target release is incomplete")
    receipt = _mapping(document.get("backend_receipt"), "target release backend receipt")
    if receipt.get("released") is not True:
        raise EvidenceValidationError("known-site target backend did not confirm release")


def _verify_agent_receipts(
    arm_root: Path,
    *,
    terminal: Mapping[str, object],
    contract: Mapping[str, object],
) -> bool:
    receipts = _mapping(terminal.get("receipts"), "arm receipts")
    expected_receipts = {
        "candidate_artifact",
        "adapter",
        "model",
        "process",
        "sandbox_profile",
        "agent_vm_provision",
        "agent_vm_relay_probes",
        "agent_vm_teardown",
    }
    if set(receipts) != expected_receipts:
        raise EvidenceValidationError("arm receipt set is invalid")
    model_record = _mapping(receipts.get("model"), "model receipt record")
    process_record = _mapping(receipts.get("process"), "process receipt record")
    sandbox_record = _mapping(receipts.get("sandbox_profile"), "sandbox receipt record")
    model_path = _bound_receipt_path(arm_root, model_record, MODEL_RECEIPT_FILE, native=False)
    process_path = _bound_receipt_path(arm_root, process_record, PROCESS_RECEIPT_FILE, native=False)
    sandbox_path = _bound_receipt_path(arm_root, sandbox_record, SANDBOX_PROFILE_FILE, native=False)
    target_started = terminal.get("target_started") is True
    target_stopped = terminal.get("target_stopped") is True
    for name, relative in (
        ("agent_vm_provision", f"agent-daemon/{AGENT_DAEMON_PROVISION_FILE}"),
        ("agent_vm_relay_probes", f"agent-daemon/{HOST_RELAY_PROBE_FILE}"),
        ("agent_vm_teardown", f"agent-daemon/{AGENT_DAEMON_TEARDOWN_FILE}"),
    ):
        required = target_started if name != "agent_vm_teardown" else target_stopped
        value = receipts.get(name)
        path = arm_root / relative
        if not required:
            if value is not None or path.exists() or path.is_symlink():
                raise EvidenceValidationError(f"unexpected {name} receipt exists")
            continue
        record = _mapping(value, f"{name} receipt record")
        if record.get("path") != relative:
            raise EvidenceValidationError(f"{name} receipt path is invalid")
        resolved = _safe_evidence_relative(arm_root, relative, label=f"{name} receipt")
        if (
            record.get("file_sha256") != _sha256_regular_file(resolved)
            or record.get("size_bytes") != resolved.stat().st_size
        ):
            raise EvidenceValidationError(f"{name} receipt binding is invalid")
    gateway = _mapping(contract.get("model_gateway"), "model gateway contract")
    limits = _mapping(_mapping(contract.get("budgets"), "budgets").get("per_arm"), "limits")
    model = _read_json(model_path, label="model receipt")
    validated_model = validate_model_gateway_receipt(
        model,
        expected_row_id=str(terminal["row_id"]),
        expected_policy_sha256=str(gateway["policy_sha256"]),
        expected_max_requests=_positive_int(limits.get("max_model_requests"), "model cap"),
        expected_max_cost_usd=str(limits.get("max_cost_usd")),
    )
    process = _read_json(process_path, label="process receipt")
    if terminal.get("status") == "unstarted":
        if receipts.get("adapter") is not None or receipts.get("candidate_artifact") is not None:
            raise EvidenceValidationError("unstarted arm invented adapter or candidate evidence")
        for relative in (
            f"{NATIVE_OUTPUT_DIRECTORY}/{ADAPTER_RECEIPT_FILE}",
            f"{NATIVE_OUTPUT_DIRECTORY}/{ADAPTER_STDOUT_PATH}",
            f"{NATIVE_OUTPUT_DIRECTORY}/{ADAPTER_STDERR_PATH}",
            f"{NATIVE_OUTPUT_DIRECTORY}/{CANDIDATE_ARTIFACT_PATH}",
        ):
            path = arm_root / relative
            if path.exists() or path.is_symlink():
                raise EvidenceValidationError("unstarted arm retained unexpected launched evidence")
        try:
            validate_unstarted_comparison_process_receipt(
                process,
                expected_row_id=str(terminal["row_id"]),
                expected_limits=ExternalExecutionLimits(
                    wall_seconds=_positive_int(limits.get("wall_seconds"), "wall cap"),
                    max_model_requests=_positive_int(
                        limits.get("max_model_requests"),
                        "model cap",
                    ),
                    max_target_requests=_positive_int(
                        limits.get("max_target_requests"),
                        "target cap",
                    ),
                    max_cost_usd=_decimal(limits.get("max_cost_usd"), "cost cap"),
                ),
                expected_policy_sha256=str(gateway["policy_sha256"]),
                expected_evidence_class=PAIRED_LOCAL,
                model_receipt_file_sha256=_sha256_regular_file(model_path),
                model_receipt_document_sha256=str(validated_model["document_sha256"]),
                sandbox_profile=_read_bounded_regular_file(
                    sandbox_path,
                    maximum_bytes=MAX_JSON_BYTES,
                ),
            )
        except (ComparisonProcessError, ValueError) as exc:
            raise EvidenceValidationError("unstarted process receipt is invalid") from exc
        return True

    adapter_record = receipts.get("adapter")
    candidate_record = receipts.get("candidate_artifact")
    if adapter_record is None:
        if terminal.get("status") not in {"failed", "timed_out"}:
            raise EvidenceValidationError("successful arm is missing its adapter receipt")
        adapter_path = arm_root / NATIVE_OUTPUT_DIRECTORY / ADAPTER_RECEIPT_FILE
        if adapter_path.exists() or adapter_path.is_symlink():
            raise EvidenceValidationError("undeclared adapter receipt exists")
    else:
        adapter_path = _bound_receipt_path(
            arm_root,
            _mapping(adapter_record, "adapter receipt record"),
            ADAPTER_RECEIPT_FILE,
            native=True,
        )
        candidate_path: Path | None = None
        if candidate_record is not None:
            candidate_path = _bound_receipt_path(
                arm_root,
                _mapping(candidate_record, "candidate artifact record"),
                CANDIDATE_ARTIFACT_PATH,
                native=True,
            )
            if _mapping(candidate_record, "candidate artifact record").get(
                "file_sha256"
            ) != terminal.get("artifact_sha256"):
                raise EvidenceValidationError(
                    "candidate artifact differs from its terminal binding"
                )
        elif terminal.get("artifact_path") is not None:
            raise EvidenceValidationError("terminal candidate is missing its receipt")
        else:
            undeclared_candidate = arm_root / NATIVE_OUTPUT_DIRECTORY / CANDIDATE_ARTIFACT_PATH
            if undeclared_candidate.exists() or undeclared_candidate.is_symlink():
                raise EvidenceValidationError("undeclared candidate artifact exists")
        _validate_adapter_receipt(
            _read_json(adapter_path, label="adapter receipt"),
            terminal=terminal,
            contract=contract,
            candidate_path=candidate_path,
            native_output_dir=arm_root / NATIVE_OUTPUT_DIRECTORY,
        )

    public_contract = terminal.get("process_public_contract")
    if public_contract is None:
        _validate_failed_process_receipt(
            process,
            terminal=terminal,
            contract=contract,
            model_receipt_file_sha256=_sha256_regular_file(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=_read_bounded_regular_file(
                sandbox_path,
                maximum_bytes=MAX_JSON_BYTES,
            ),
        )
        # This fallback preserves truthful terminal evidence for a launch or
        # validation failure.  It cannot prove the exact started command and
        # environment and therefore is never a comparable observation.
        return False
    else:
        public = _mapping(public_contract, "process public contract")
        if public.get("model_gateway_row_token_sha256") != validated_model.get("row_token_sha256"):
            raise EvidenceValidationError(
                "process public contract is not bound to the model row token"
            )
        validate_comparison_process_receipt_public(
            process,
            expected_row_id=str(terminal["row_id"]),
            public_contract=public,
            model_receipt_file_sha256=_sha256_regular_file(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=_read_bounded_regular_file(
                sandbox_path,
                maximum_bytes=MAX_JSON_BYTES,
            ),
            expected_output_directory=arm_root / NATIVE_OUTPUT_DIRECTORY,
            require_official_safety=False,
        )
    return True


def _validate_failed_process_receipt(
    receipt: Mapping[str, object],
    *,
    terminal: Mapping[str, object],
    contract: Mapping[str, object],
    model_receipt_file_sha256: str,
    model_receipt_document_sha256: str,
    sandbox_profile: bytes,
) -> None:
    """Validate a sealed outer-process failure without blessing it as success."""

    expected_fields = {
        "schema_version",
        "created_at",
        "row_id",
        "evidence_class",
        "command",
        "environment",
        "cwd",
        "limits",
        "sandbox",
        "execution",
        "model_gateway",
        "official_attestation_eligible",
        "valid",
        "document_sha256",
    }
    if (
        set(receipt) != expected_fields
        or receipt.get("schema_version") != PROCESS_RECEIPT_SCHEMA_VERSION
        or receipt.get("row_id") != terminal.get("row_id")
        or receipt.get("evidence_class") != PAIRED_LOCAL
        or receipt.get("document_sha256")
        != _sha256_bytes(_canonical_json(_body_without_digest(receipt)))
        or receipt.get("cwd")
        != {"mode": "row_native_output", "relative_path": NATIVE_OUTPUT_DIRECTORY}
        or receipt.get("official_attestation_eligible") is not False
        or receipt.get("valid") is not False
    ):
        raise EvidenceValidationError("failed process receipt identity is invalid")
    per_arm = _mapping(_mapping(contract.get("budgets"), "budgets").get("per_arm"), "limits")
    expected_limits = {
        "wall_seconds": per_arm.get("wall_seconds"),
        "max_model_requests": per_arm.get("max_model_requests"),
        "max_target_requests": per_arm.get("max_target_requests"),
        "max_cost_usd": _money(_decimal(per_arm.get("max_cost_usd"), "per-arm cost")),
    }
    if receipt.get("limits") != expected_limits:
        raise EvidenceValidationError("failed process limits differ from the contract")
    model_gateway = _mapping(receipt.get("model_gateway"), "failed process model gateway")
    gateway = _mapping(contract.get("model_gateway"), "model gateway contract")
    if model_gateway != {
        "receipt_path": MODEL_RECEIPT_FILE,
        "receipt_file_sha256": model_receipt_file_sha256,
        "receipt_document_sha256": model_receipt_document_sha256,
        "policy_sha256": gateway.get("policy_sha256"),
        "sealed_in_finally": True,
        "validator_passed": True,
        "error": None,
    }:
        raise EvidenceValidationError("failed process model receipt binding is invalid")
    sandbox = _mapping(receipt.get("sandbox"), "failed process sandbox")
    if sandbox.get("profile_path") != SANDBOX_PROFILE_FILE or sandbox.get(
        "profile_sha256"
    ) != _sha256_bytes(sandbox_profile):
        raise EvidenceValidationError("failed process sandbox profile binding is invalid")
    execution = _mapping(receipt.get("execution"), "failed process execution")
    expected_execution_fields = {
        "started_at",
        "completed_at",
        "elapsed_seconds",
        "returncode",
        "timed_out",
        "spawn_succeeded",
        "wall_timeout_enforced",
        "process_group_created",
        "process_group_teardown_complete",
        "stdout",
        "stderr",
        "error",
    }
    elapsed = _finite_nonnegative_float(
        execution.get("elapsed_seconds"),
        "failed process elapsed time",
    )
    if (
        set(execution) != expected_execution_fields
        or execution.get("returncode") != terminal.get("returncode")
        or execution.get("wall_timeout_enforced") is not True
        or execution.get("process_group_teardown_complete") is not True
        or elapsed != terminal.get("elapsed_seconds")
        or not all(
            isinstance(execution.get(name), bool)
            for name in (
                "timed_out",
                "spawn_succeeded",
                "process_group_created",
                "process_group_teardown_complete",
            )
        )
        or (terminal.get("status") == "timed_out" and execution.get("timed_out") is not True)
        or (terminal.get("status") == "failed" and execution.get("timed_out") is not False)
        or (
            execution.get("error") is None
            and execution.get("spawn_succeeded") is True
            and execution.get("process_group_created") is True
        )
    ):
        raise EvidenceValidationError("failed process lifecycle is internally inconsistent")
    for name in ("stdout", "stderr"):
        _validate_failed_process_capture(execution.get(name), name)


def _validate_failed_process_capture(value: object, label: str) -> None:
    capture = _mapping(value, f"failed process {label} capture")
    if set(capture) != {
        "raw_sha256",
        "raw_size_bytes",
        "retained_size_bytes",
        "max_retained_bytes",
        "truncated",
        "complete",
    }:
        raise EvidenceValidationError(f"failed process {label} capture fields are invalid")
    _sha256_digest(capture.get("raw_sha256"), f"failed process {label} digest")
    raw = _nonnegative_int(capture.get("raw_size_bytes"), f"failed process {label} bytes")
    retained = _nonnegative_int(
        capture.get("retained_size_bytes"),
        f"retained failed process {label} bytes",
    )
    maximum = _positive_int(
        capture.get("max_retained_bytes"),
        f"failed process {label} capture cap",
    )
    if (
        retained > raw
        or retained > maximum
        or capture.get("truncated") is not (raw > retained)
        or capture.get("complete") is not True
    ):
        raise EvidenceValidationError(f"failed process {label} capture is incomplete")


def _validate_target_preparation_document(
    preparation: Mapping[str, object],
    *,
    contract_document: Mapping[str, object],
    commitment_document: Mapping[str, object],
) -> None:
    source = _mapping(preparation.get("source"), "prepared source")
    site = _mapping(contract_document.get("site"), "site contract")
    expected_source = _mapping(site.get("source"), "source contract")
    for name in ("origin_url", "commit", "tree", "relative_path", "materialization"):
        if source.get(name) != expected_source.get(name):
            raise EvidenceValidationError("prepared target source binding drifted")
    if (
        preparation.get("campaign_id") != contract_document.get("campaign_id")
        or preparation.get("site_id") != KNOWN_SITE_ID
        or preparation.get("flag_commitments_sha256") != commitment_document.get("document_sha256")
        or source.get("clean_pinned_archive_verified") is not True
    ):
        raise EvidenceValidationError("prepared target campaign binding is invalid")
    expected_runtime = _mapping(contract_document.get("target_runtime"), "target runtime")
    if preparation.get("target_runtime") != expected_runtime:
        raise EvidenceValidationError("prepared target runtime pins drifted")
    _sha256_digest(source.get("archive_sha256"), "prepared source archive digest")
    _sha256_digest(source.get("snapshot_tree_sha256"), "prepared source tree digest")
    build = _mapping(preparation.get("build"), "prepared target build")
    if (
        build.get("prepare_invocations") != 1
        or build.get("count_by_service") != {"internal": 1, "proxy": 0, "web": 1}
        or build.get("flags_used_during_build") is not False
        or build.get("runtime_flag_injection_only") is not True
    ):
        raise EvidenceValidationError("prepared target build-once contract is invalid")
    _image_map(_mapping(build.get("image_ids_by_service"), "prepared images"))  # type: ignore[arg-type]
    exposure = _mapping(preparation.get("agent_exposure"), "prepared target exposure")
    if (
        exposure.get("source_mounted") is not False
        or exposure.get("operator_material_mounted") is not False
        or exposure.get("credential_material_mounted") is not False
        or exposure.get("excluded_operator_files") != list(EXCLUDED_OPERATOR_FILES)
    ):
        raise EvidenceValidationError("prepared target exposes prohibited evaluator material")
    runtime = _mapping(preparation.get("runtime_policy"), "prepared runtime policy")
    if (
        runtime.get("expected_arms") != list(_arm_order_from_contract(contract_document))
        or runtime.get("runtime_build_allowed") is not False
        or runtime.get("runtime_pull_allowed") is not False
        or runtime.get("identical_image_ids_required") is not True
    ):
        raise EvidenceValidationError("prepared target runtime policy is invalid")


def _validate_adapter_receipt(
    receipt: Mapping[str, object],
    *,
    terminal: Mapping[str, object],
    contract: Mapping[str, object],
    candidate_path: Path | None,
    native_output_dir: Path,
) -> None:
    expected_fields = {
        "schema_version",
        "adapter_version",
        "system_id",
        "status",
        "returncode",
        "wrapper_returncode",
        "process_group_policy",
        "timed_out",
        "command_sha256",
        "target_url_sha256",
        "gateway_base_url_sha256",
        "docker_host_sha256",
        "gateway",
        "limits",
        "tool_image",
        "input_contract",
        "runtime",
        "capture",
        "candidate_extraction",
        "environment_policy",
    }
    adapter_status = receipt.get("status")
    adapter_returncode = receipt.get("returncode")
    wrapper_returncode = receipt.get("wrapper_returncode")
    adapter_timed_out = receipt.get("timed_out")
    if (
        set(receipt) != expected_fields
        or receipt.get("schema_version") != ADAPTER_SCHEMA_VERSION
        or receipt.get("adapter_version") != ADAPTER_VERSION
        or receipt.get("system_id") != terminal.get("system")
        or adapter_status not in {"completed", "agent_nonzero", "timed_out"}
        or isinstance(adapter_returncode, bool)
        or not isinstance(adapter_returncode, int)
        or isinstance(wrapper_returncode, bool)
        or not isinstance(wrapper_returncode, int)
        or wrapper_returncode != terminal.get("returncode")
        or not isinstance(adapter_timed_out, bool)
        or receipt.get("process_group_policy") != "joined_evaluator_outer_group"
    ):
        raise EvidenceValidationError("canonical adapter receipt identity is invalid")
    if (
        (adapter_status == "completed" and (adapter_returncode != 0 or adapter_timed_out))
        or (adapter_status == "agent_nonzero" and (adapter_returncode == 0 or adapter_timed_out))
        or (
            adapter_status == "agent_nonzero"
            and wrapper_returncode != _portable_adapter_returncode(adapter_returncode)
        )
        or (
            adapter_status == "timed_out"
            and (
                adapter_timed_out is not True
                or adapter_returncode == 0
                or wrapper_returncode != 124
            )
        )
        or (terminal.get("status") == "timed_out") is not (adapter_status == "timed_out")
        or (
            terminal.get("status") == "completed"
            and (adapter_status != "completed" or wrapper_returncode != 0)
        )
    ):
        raise EvidenceValidationError("canonical adapter outcome is internally inconsistent")
    extraction = _mapping(receipt.get("candidate_extraction"), "candidate extraction")
    candidate_count = extraction.get("candidate_count")
    extraction_complete = extraction.get("complete")
    if (
        not isinstance(extraction_complete, bool)
        or extraction.get("expected_flag_used") is not False
        or isinstance(candidate_count, bool)
        or not isinstance(candidate_count, int)
        or candidate_count < 0
    ):
        raise EvidenceValidationError("adapter candidate extraction declaration is invalid")
    if adapter_status != "timed_out" and extraction_complete is not True:
        raise EvidenceValidationError("non-timeout adapter candidate extraction is incomplete")
    if adapter_status == "timed_out" and extraction_complete is not False:
        raise EvidenceValidationError("timed-out adapter invented candidate extraction")
    if adapter_status == "completed" and wrapper_returncode != (0 if extraction_complete else 125):
        raise EvidenceValidationError("canonical adapter wrapper outcome is inconsistent")
    if extraction_complete:
        if candidate_path is None or extraction.get("artifact_path") != CANDIDATE_ARTIFACT_PATH:
            raise EvidenceValidationError(
                "complete adapter extraction lacks its candidate artifact"
            )
        candidate_body = _read_bounded_regular_file(
            candidate_path,
            maximum_bytes=MAX_CANDIDATE_BYTES,
        )
        candidate_lines = candidate_body.splitlines()
        if (
            candidate_count != len(candidate_lines)
            or candidate_body != b"".join(line + b"\n" for line in candidate_lines)
            or _sha256_bytes(candidate_body) != terminal.get("artifact_sha256")
        ):
            raise EvidenceValidationError("adapter candidate extraction is incomplete")
    elif (
        candidate_path is not None
        or extraction.get("artifact_path") is not None
        or candidate_count != 0
        or terminal.get("artifact_path") is not None
    ):
        raise EvidenceValidationError("incomplete adapter extraction invented a candidate")
    _validate_adapter_capture(
        receipt.get("capture"),
        native_output_dir=native_output_dir,
    )
    public = _mapping(terminal.get("process_public_contract"), "process public contract")
    process_command = _mapping(public.get("command"), "process public command")
    process_environment = _mapping(public.get("environment"), "process public environment")
    value_digests = _mapping(
        process_environment.get("value_sha256"),
        "process environment digests",
    )
    docker_policy = _mapping(contract.get("docker_separation"), "Docker separation policy")
    agent_policy = _mapping(docker_policy.get("agent_vm"), "agent VM policy")
    agent_plans = _mapping(agent_policy.get("plans"), "agent VM plans")
    agent_plan = _mapping(
        agent_plans.get(str(terminal.get("row_id"))),
        "agent VM row plan",
    )
    if (
        receipt.get("command_sha256") != process_command.get("argv_sha256")
        or receipt.get("target_url_sha256") != value_digests.get(TARGET_URL_ENV)
        or receipt.get("gateway_base_url_sha256") != value_digests.get(GATEWAY_BASE_URL_ENV)
        or receipt.get("docker_host_sha256") != agent_plan.get("docker_host_sha256")
    ):
        raise EvidenceValidationError("adapter endpoint binding is invalid")
    gateway_contract = _mapping(contract.get("model_gateway"), "model gateway contract")
    policy = _mapping(gateway_contract.get("policy"), "model gateway policy")
    adapter_gateway = _mapping(receipt.get("gateway"), "adapter gateway")
    if (
        adapter_gateway.get("base_url_sha256") != value_digests.get(GATEWAY_BASE_URL_ENV)
        or adapter_gateway.get("token_sha256") != value_digests.get(COMPARISON_GATEWAY_TOKEN_ENV)
        or adapter_gateway.get("model") != policy.get("model")
        or adapter_gateway.get("reasoning_effort") != policy.get("reasoning_effort")
        or adapter_gateway.get("pricing") != policy.get("pricing_usd_per_million_tokens")
        or adapter_gateway.get("max_output_tokens")
        != policy.get("max_completion_tokens_per_request")
    ):
        raise EvidenceValidationError("adapter model gateway binding is invalid")
    budgets = _mapping(contract.get("budgets"), "budget contract")
    per_arm = _mapping(budgets.get("per_arm"), "per-arm budget")
    expected_limits = {
        "wall_seconds": per_arm.get("wall_seconds"),
        "max_model_requests": per_arm.get("max_model_requests"),
        "max_target_requests": per_arm.get("max_target_requests"),
        "max_cost_usd": _money(_decimal(per_arm.get("max_cost_usd"), "per-arm cost")),
    }
    systems = _mapping(contract.get("systems"), "system pins")
    system_pin = _mapping(systems.get(str(terminal.get("system"))), "system pin")
    source_pin = _mapping(system_pin.get("source"), "system source pin")
    runtime_pin = _mapping(system_pin.get("runtime"), "system runtime pin")
    tool_pin = _mapping(system_pin.get("tool_image"), "system tool image pin")
    runtime = _mapping(receipt.get("runtime"), "adapter runtime")
    if (
        receipt.get("limits") != expected_limits
        or receipt.get("tool_image") != tool_pin.get("reference")
        or runtime.get("source_origin_url") != source_pin.get("origin_url")
        or runtime.get("source_commit") != source_pin.get("commit")
        or runtime.get("source_tree") != source_pin.get("tree")
        or runtime.get("environment_manifest_sha256") != runtime_pin.get("manifest_sha256")
        or runtime.get("executable_sha256") != runtime_pin.get("executable_sha256")
    ):
        raise EvidenceValidationError("adapter pre-draw source/runtime binding is invalid")
    input_contract = _mapping(receipt.get("input_contract"), "adapter input contract")
    if (
        input_contract.get("mode") != "description-only-black-box"
        or input_contract.get("description_sha256") != terminal.get("description_sha256")
        or input_contract.get("semantic_prompt_sha256") != terminal.get("semantic_prompt_sha256")
        or input_contract.get("target_url_in_semantic_prompt") is not False
        or input_contract.get("case_id_included") is not False
        or input_contract.get("source_path_included") is not False
        or input_contract.get("expected_flag_used") is not False
    ):
        raise EvidenceValidationError("adapter black-box input binding is invalid")
    environment = _mapping(receipt.get("environment_policy"), "adapter environment policy")
    redacted_credentials = environment.get("persisted_row_credentials_redacted")
    if (
        environment.get("inherits_parent") is not False
        or environment.get("row_gateway_only") is not True
        or environment.get("ambient_proxy_or_provider_credentials") is not False
        or environment.get("fresh_home_work_run") is not True
        or isinstance(redacted_credentials, bool)
        or not isinstance(redacted_credentials, int)
        or redacted_credentials < 0
    ):
        raise EvidenceValidationError("adapter environment isolation is invalid")


def _validate_adapter_capture(value: object, *, native_output_dir: Path) -> None:
    capture = _mapping(value, "adapter capture")
    if set(capture) != {"stdout", "stderr"}:
        raise EvidenceValidationError("adapter capture streams are invalid")
    for stream, filename in (
        ("stdout", ADAPTER_STDOUT_PATH),
        ("stderr", ADAPTER_STDERR_PATH),
    ):
        observed = _mapping(capture.get(stream), f"adapter {stream} capture")
        if set(observed) != {
            "sha256",
            "total_bytes",
            "retained_bytes",
            "truncated",
            "complete",
        }:
            raise EvidenceValidationError(f"adapter {stream} capture is invalid")
        total = _nonnegative_int(
            observed.get("total_bytes"),
            f"adapter {stream} total bytes",
        )
        retained = _nonnegative_int(
            observed.get("retained_bytes"),
            f"adapter {stream} retained bytes",
        )
        if observed.get("truncated") is not False or observed.get("complete") is not True:
            raise EvidenceValidationError(f"adapter {stream} capture is incomplete")
        body = _read_bounded_regular_file(
            native_output_dir / filename,
            maximum_bytes=MAX_JSON_BYTES,
        )
        if (
            total != retained
            or retained != len(body)
            or observed.get("sha256") != (_sha256_bytes(body))
        ):
            raise EvidenceValidationError(
                f"adapter {stream} capture does not reproduce retained bytes"
            )


def _portable_adapter_returncode(value: int) -> int:
    """Recompute the canonical adapter wrapper's portable exit status."""

    if value < 0:
        return 128 + min(127, abs(value))
    return min(value, 125)


def _validate_contract_document(document: Mapping[str, object]) -> None:
    """Rebuild the entire frozen contract instead of trusting policy booleans."""

    try:
        campaign_id = _required_string(document.get("campaign_id"), "campaign ID")
        site = _mapping(document.get("site"), "site contract")
        source_value = _mapping(site.get("source"), "site source")
        source = SiteSourcePin(
            origin_url=_required_string(source_value.get("origin_url"), "site source origin"),
            commit=_required_string(source_value.get("commit"), "site source commit"),
            tree=_required_string(source_value.get("tree"), "site source tree"),
            relative_path=_required_string(
                source_value.get("relative_path"),
                "site source relative path",
            ),
        )
        raw_systems = _mapping(document.get("systems"), "system pins")
        if set(raw_systems) != set(SYSTEMS):
            raise EvidenceValidationError("known-site system pin set is incomplete")
        system_pins: dict[SystemId, KnownSiteSystemPin] = {}
        for system in SYSTEMS:
            raw_pin = _mapping(raw_systems.get(system), f"{system} system pin")
            raw_source = _mapping(raw_pin.get("source"), f"{system} source pin")
            raw_runtime = _mapping(raw_pin.get("runtime"), f"{system} runtime pin")
            raw_tool = _mapping(raw_pin.get("tool_image"), f"{system} tool image pin")
            system_pins[system] = KnownSiteSystemPin(
                origin_url=_required_string(
                    raw_source.get("origin_url"),
                    f"{system} source origin",
                ),
                commit=_required_string(raw_source.get("commit"), f"{system} source commit"),
                tree=_required_string(raw_source.get("tree"), f"{system} source tree"),
                runtime_manifest_sha256=_required_string(
                    raw_runtime.get("manifest_sha256"),
                    f"{system} runtime manifest digest",
                ),
                executable_sha256=_required_string(
                    raw_runtime.get("executable_sha256"),
                    f"{system} executable digest",
                ),
                tool_image_reference=_required_string(
                    raw_tool.get("reference"),
                    f"{system} tool image reference",
                ),
                tool_image_id=_required_string(
                    raw_tool.get("expected_image_id"),
                    f"{system} tool image ID",
                ),
                tool_image_archive_sha256=_required_string(
                    raw_tool.get("archive_sha256"),
                    f"{system} tool image archive digest",
                ),
                platform=_required_string(raw_tool.get("platform"), f"{system} platform"),
            )
        adapter = _mapping(document.get("comparison_adapter"), "comparison adapter")
        gateway = _mapping(document.get("model_gateway"), "model gateway contract")
        policy = _mapping(gateway.get("policy"), "model policy")
        budgets = _mapping(document.get("budgets"), "budget contract")
        per_arm = _mapping(budgets.get("per_arm"), "per-arm budget")
        campaign = _mapping(budgets.get("campaign"), "campaign budget")
        limits = KnownSiteLimits.build(
            wall_seconds_per_arm=_positive_int(
                per_arm.get("wall_seconds"),
                "per-arm wall limit",
            ),
            max_model_requests_per_arm=_positive_int(
                per_arm.get("max_model_requests"),
                "per-arm model request limit",
            ),
            max_target_requests_per_arm=_positive_int(
                per_arm.get("max_target_requests"),
                "per-arm target request limit",
            ),
            max_cost_usd_per_arm=str(per_arm.get("max_cost_usd")),
            campaign_wall_seconds=_positive_int(
                campaign.get("wall_seconds"),
                "campaign wall limit",
            ),
            campaign_max_model_requests=_positive_int(
                campaign.get("max_model_requests"),
                "campaign model request limit",
            ),
            campaign_max_target_requests=_positive_int(
                campaign.get("max_target_requests"),
                "campaign target request limit",
            ),
            campaign_max_cost_usd=str(campaign.get("max_cost_usd")),
        )
        docker = _mapping(document.get("docker_separation"), "Docker separation policy")
        target_daemon = _mapping(docker.get("target"), "target Docker daemon")
        agent_policy = _mapping(docker.get("agent_vm"), "agent VM policy")

        def daemon_pin(value: Mapping[str, object], label: str) -> DockerDaemonPin:
            return DockerDaemonPin(
                docker_executable_sha256=_required_string(
                    value.get("docker_executable_sha256"),
                    f"{label} Docker executable digest",
                ),
                docker_socket_path_sha256=_required_string(
                    value.get("docker_socket_path_sha256"),
                    f"{label} Docker socket digest",
                ),
                docker_host_sha256=_required_string(
                    value.get("docker_host_sha256"),
                    f"{label} Docker host digest",
                ),
                daemon_identity_sha256=_required_string(
                    value.get("daemon_identity_sha256"),
                    f"{label} daemon identity digest",
                ),
            )

        controller = _mapping(agent_policy.get("controller"), "agent VM controller")
        template = _mapping(agent_policy.get("template"), "agent VM template")
        base_image = _mapping(agent_policy.get("base_image"), "agent VM base image")
        relay = _mapping(agent_policy.get("relay"), "agent VM relay")
        raw_plans = _mapping(agent_policy.get("plans"), "agent VM plans")
        plans: dict[str, AgentVmPlanPin] = {}
        for row_id in ROW_IDS:
            raw_plan = _mapping(raw_plans.get(row_id), f"{row_id} agent VM plan")
            plans[row_id] = AgentVmPlanPin(
                generation_id=_required_string(
                    raw_plan.get("generation_id"),
                    f"{row_id} agent VM generation",
                ),
                profile_name=_required_string(
                    raw_plan.get("profile_name"),
                    f"{row_id} agent VM profile",
                ),
                docker_socket_path_sha256=_required_string(
                    raw_plan.get("docker_socket_path_sha256"),
                    f"{row_id} agent VM Docker socket digest",
                ),
                docker_host_sha256=_required_string(
                    raw_plan.get("docker_host_sha256"),
                    f"{row_id} agent VM Docker host digest",
                ),
                agent_network=_required_string(
                    raw_plan.get("agent_network"),
                    f"{row_id} agent VM network",
                ),
            )
        raw_order = _mapping(
            document.get("authenticated_arm_order"),
            "authenticated arm-order source",
        )
        if raw_order.get("protocol") != AUTHENTICATED_ARM_ORDER_PROTOCOL:
            raise EvidenceValidationError("authenticated arm-order protocol is invalid")
        authenticated_arm_order = AuthenticatedArmOrderPin(
            paired_campaign_id=_required_string(
                raw_order.get("paired_campaign_id"),
                "paired-XBEN source campaign ID",
            ),
            commitment_document_sha256=_required_string(
                raw_order.get("commitment_document_sha256"),
                "paired-XBEN commitment digest",
            ),
            preflight_document_sha256=_required_string(
                raw_order.get("preflight_document_sha256"),
                "paired-XBEN preflight digest",
            ),
            beacon_document_sha256=_required_string(
                raw_order.get("beacon_document_sha256"),
                "paired-XBEN beacon digest",
            ),
            selection_document_sha256=_required_string(
                raw_order.get("selection_document_sha256"),
                "paired-XBEN selection digest",
            ),
            draw_key_sha256=_required_string(
                raw_order.get("draw_key_sha256"),
                "paired-XBEN draw key",
            ),
            website_reference_sha256=_required_string(
                raw_order.get("website_reference_sha256"),
                "paired-XBEN website reference digest",
            ),
            website_content_sha256=_required_string(
                raw_order.get("website_content_sha256"),
                "paired-XBEN website content digest",
            ),
        )
        execution = _mapping(document.get("execution_policy"), "execution policy")
        rebuilt = FrozenKnownSiteContract(
            campaign_id=campaign_id,
            campaign_directory_sha256=_required_string(
                execution.get("canonical_campaign_directory_sha256"),
                "canonical campaign directory digest",
            ),
            source=source,
            model_gateway_policy=policy,
            model_gateway_policy_sha256=_required_string(
                gateway.get("policy_sha256"),
                "model policy digest",
            ),
            limits=limits,
            target_runtime=_mapping(document.get("target_runtime"), "target runtime"),
            system_pins=system_pins,
            adapter_source_sha256=_required_string(
                adapter.get("source_sha256"),
                "comparison adapter source digest",
            ),
            authenticated_arm_order=authenticated_arm_order,
            docker_separation=DockerSeparationPolicy(
                target=daemon_pin(target_daemon, "target"),
                agent_vm=AgentVmPolicyPin(
                    docker_executable_sha256=_required_string(
                        agent_policy.get("docker_executable_sha256"),
                        "agent VM Docker executable digest",
                    ),
                    controller_kind=_required_string(
                        controller.get("kind"),
                        "agent VM controller kind",
                    ),
                    controller_implementation_sha256=_required_string(
                        controller.get("implementation_sha256"),
                        "agent VM controller implementation digest",
                    ),
                    controller_policy_sha256=_required_string(
                        controller.get("policy_sha256"),
                        "agent VM controller policy digest",
                    ),
                    supervisor_executable_sha256=_required_string(
                        controller.get("supervisor_executable_sha256"),
                        "agent VM supervisor executable digest",
                    ),
                    supervisor_runtime_manifest_sha256=_required_string(
                        controller.get("supervisor_runtime_manifest_sha256"),
                        "agent VM supervisor runtime manifest digest",
                    ),
                    vm_template_sha256=_required_string(
                        template.get("sha256"),
                        "agent VM template digest",
                    ),
                    base_image_sha256=_required_string(
                        base_image.get("sha256"),
                        "agent VM base-image digest",
                    ),
                    relay_implementation_sha256=_required_string(
                        relay.get("implementation_sha256"),
                        "agent VM relay implementation digest",
                    ),
                    relay_policy_sha256=_required_string(
                        relay.get("policy_sha256"),
                        "agent VM relay policy digest",
                    ),
                    relay_enforcement_kind=_required_string(
                        relay.get("enforcement_kind"),
                        "agent VM relay enforcement kind",
                    ),
                    plans=plans,
                ),
            ),
            evidence_class=_required_string(
                execution.get("evidence_class"),
                "execution evidence class",
            ),
        ).to_document()
    except EvidenceValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceValidationError("known-site run contract is invalid") from exc
    if _body_without_digest(document) != _body_without_digest(rebuilt):
        raise EvidenceValidationError(
            "known-site run contract differs from the complete frozen schema"
        )


def _validate_flag_commitment_document(
    document: Mapping[str, object],
    *,
    contract_document: Mapping[str, object],
) -> None:
    expected_fields = {
        "schema_version",
        "created_at",
        "campaign_id",
        "contract_sha256",
        "algorithm",
        "generator",
        "draw_calls",
        "redraw_allowed",
        "unique",
        "commitments",
        "plaintext_values_persisted",
        "committed_before_either_arm",
        "evaluation_classification",
        "claim_boundary",
        "eligible_for_sota_claim",
        "eligible_for_unseen_claim",
        "document_sha256",
    }
    if set(document) != expected_fields:
        raise EvidenceValidationError("known-site flag commitment fields are invalid")
    entries = document.get("commitments")
    if not isinstance(entries, list) or len(entries) != len(FLAG_ENVIRONMENT):
        raise EvidenceValidationError("known-site flag commitment count is invalid")
    expected_names = list(FLAG_ENVIRONMENT)
    observed: list[tuple[str, str]] = []
    digests: list[str] = []
    for entry in entries:
        mapping = _mapping(entry, "flag commitment")
        if set(mapping) != {"logical_name", "runtime_environment_name", "sha256"}:
            raise EvidenceValidationError("known-site flag commitment entry is invalid")
        observed.append(
            (str(mapping.get("logical_name")), str(mapping.get("runtime_environment_name")))
        )
        digests.append(_sha256_digest(mapping.get("sha256"), "flag commitment digest"))
    if (
        observed != expected_names
        or len(set(digests)) != len(digests)
        or document.get("campaign_id") != contract_document.get("campaign_id")
        or document.get("contract_sha256") != contract_document.get("document_sha256")
        or document.get("algorithm") != "sha256-of-exact-utf8-flag"
        or document.get("generator") != "python-secrets-token-hex-32-os-csprng"
        or document.get("draw_calls") != len(FLAG_ENVIRONMENT)
        or document.get("redraw_allowed") is not False
        or document.get("unique") is not True
        or document.get("plaintext_values_persisted") is not False
        or document.get("committed_before_either_arm") is not True
    ):
        raise EvidenceValidationError("known-site flag commitments are invalid")


def _validate_terminal_contract(
    terminal: Mapping[str, object],
    *,
    contract: Mapping[str, object],
) -> bool:
    """Validate one terminal state and return whether it is score-eligible.

    A first-attempt failure is a legitimate primary observation.  Structural
    validity therefore describes the truthfulness and closure of its evidence,
    while the returned boolean describes the much narrower all-success state.
    """

    expected_fields = {
        "schema_version",
        "created_at",
        "row_id",
        "system",
        "status",
        "returncode",
        "timed_out",
        "elapsed_seconds",
        "description_sha256",
        "semantic_prompt_sha256",
        "model_gateway_policy_sha256",
        "adapter_version",
        "artifact_path",
        "artifact_sha256",
        "evidence_class",
        "process_public_contract",
        "target_started",
        "target_start_sha256",
        "target_stopped",
        "target_stop_sha256",
        "receipts",
        "error",
        "attempt",
        "retry_allowed",
        "resume_allowed",
        "replacement_allowed",
        "evaluation_classification",
        "claim_boundary",
        "eligible_for_sota_claim",
        "eligible_for_unseen_claim",
        "document_sha256",
    }
    if set(terminal) != expected_fields:
        raise EvidenceValidationError("arm terminal fields are invalid")
    gateway = _mapping(contract.get("model_gateway"), "model gateway contract")
    per_arm = _mapping(
        _mapping(contract.get("budgets"), "budget contract").get("per_arm"),
        "per-arm budget",
    )
    elapsed = _finite_nonnegative_float(
        terminal.get("elapsed_seconds"),
        "arm elapsed time",
    )
    status = terminal.get("status")
    returncode = terminal.get("returncode")
    timed_out = terminal.get("timed_out")
    error = terminal.get("error")
    target_started = terminal.get("target_started")
    target_stopped = terminal.get("target_stopped")
    process_public_contract = terminal.get("process_public_contract")
    if (
        status not in {"completed", "failed", "timed_out", "unstarted"}
        or isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or not isinstance(timed_out, bool)
        or not isinstance(target_started, bool)
        or not isinstance(target_stopped, bool)
        or (target_stopped and not target_started)
        or elapsed > _positive_int(per_arm.get("wall_seconds"), "arm wall limit")
        or terminal.get("description_sha256") != _sha256_text(KNOWN_SITE_PUBLIC_DESCRIPTION)
        or terminal.get("model_gateway_policy_sha256") != gateway.get("policy_sha256")
        or terminal.get("adapter_version") != ADAPTER_VERSION
        or terminal.get("evidence_class") != PAIRED_LOCAL
        or terminal.get("attempt") != 1
        or terminal.get("retry_allowed") is not False
        or terminal.get("resume_allowed") is not False
        or terminal.get("replacement_allowed") is not False
    ):
        raise EvidenceValidationError("arm terminal does not satisfy the one-shot contract")
    if process_public_contract is not None and not isinstance(process_public_contract, Mapping):
        raise EvidenceValidationError("arm terminal process public contract is invalid")
    if error is not None:
        _required_string(error, "arm terminal error")
    semantic = terminal.get("semantic_prompt_sha256")
    artifact_path = terminal.get("artifact_path")
    artifact_digest = terminal.get("artifact_sha256")
    if semantic is not None:
        _sha256_digest(semantic, "semantic prompt digest")
    if artifact_path is None:
        if artifact_digest is not None:
            raise EvidenceValidationError("arm terminal has an artifact digest without a path")
    elif artifact_path == CANDIDATE_ARTIFACT_PATH:
        _sha256_digest(artifact_digest, "candidate artifact digest")
    else:
        raise EvidenceValidationError("arm terminal candidate path is invalid")

    if status == "completed":
        valid = bool(
            returncode == 0
            and timed_out is False
            and error is None
            and target_started
            and target_stopped
            and semantic is not None
            and artifact_path == CANDIDATE_ARTIFACT_PATH
            and terminal.get("process_public_contract") is not None
        )
        if not valid:
            raise EvidenceValidationError("completed arm terminal is internally inconsistent")
        return True
    if status == "failed":
        if (
            timed_out is not False
            or not target_started
            or error is None
            or (returncode == 0 and target_stopped)
        ):
            raise EvidenceValidationError("failed arm terminal is internally inconsistent")
        return False
    if status == "timed_out":
        if (
            timed_out is not True
            or returncode == 0
            or not target_started
            or error is None
            or artifact_path is not None
        ):
            raise EvidenceValidationError("timed-out arm terminal is internally inconsistent")
        return False
    if (
        returncode != -1
        or timed_out is not False
        or elapsed != 0.0
        or semantic is not None
        or artifact_path is not None
        or terminal.get("process_public_contract") is not None
        or error is None
    ):
        raise EvidenceValidationError("unstarted arm terminal is internally inconsistent")
    return False


def _terminal_is_success(terminal: Mapping[str, object]) -> bool:
    return bool(
        terminal.get("status") == "completed"
        and terminal.get("returncode") == 0
        and terminal.get("timed_out") is False
        and terminal.get("error") is None
        and terminal.get("target_started") is True
        and terminal.get("target_stopped") is True
    )


def _terminal_is_reportable_observation(terminal: Mapping[str, object]) -> bool:
    """Return true only when an agent really ran and target cleanup completed."""

    if not isinstance(terminal.get("process_public_contract"), Mapping):
        return False
    if _terminal_is_success(terminal):
        return True
    receipts = terminal.get("receipts")
    return bool(
        terminal.get("status") in {"failed", "timed_out"}
        and terminal.get("target_started") is True
        and terminal.get("target_stopped") is True
        and terminal.get("semantic_prompt_sha256") is not None
        and isinstance(receipts, Mapping)
        and isinstance(receipts.get("adapter"), Mapping)
        and isinstance(receipts.get("process"), Mapping)
        and isinstance(receipts.get("model"), Mapping)
        and isinstance(receipts.get("sandbox_profile"), Mapping)
    )


def _validate_terminal_target_bindings(
    terminal: Mapping[str, object],
    *,
    target_start: Mapping[str, object] | None,
    target_stop: Mapping[str, object] | None,
) -> None:
    expected_start = target_start.get("document_sha256") if target_start is not None else None
    expected_stop = target_stop.get("document_sha256") if target_stop is not None else None
    if (
        terminal.get("target_started") is not (target_start is not None)
        or terminal.get("target_stopped") is not (target_stop is not None)
        or terminal.get("target_start_sha256") != expected_start
        or terminal.get("target_stop_sha256") != expected_stop
    ):
        raise EvidenceValidationError("arm terminal target lifecycle binding is invalid")


def _merged_terminal_error(*values: str | None) -> str | None:
    messages: list[str] = []
    for value in values:
        if value and value not in messages:
            messages.append(value)
    return "; ".join(messages) if messages else None


def _validate_process_target_binding(
    terminal: Mapping[str, object],
    target_start: Mapping[str, object],
) -> None:
    public = _mapping(terminal.get("process_public_contract"), "process public contract")
    environment = _mapping(public.get("environment"), "process public environment")
    value_digests = _mapping(
        environment.get("value_sha256"),
        "process environment value digests",
    )
    if value_digests.get(TARGET_URL_ENV) != target_start.get(
        "target_url_sha256"
    ) or value_digests.get(DESCRIPTION_ENV) != terminal.get("description_sha256"):
        raise EvidenceValidationError("process environment is not bound to target and description")
    agent_vm = _mapping(target_start.get("agent_vm"), "agent VM start evidence")
    if value_digests.get(GATEWAY_BASE_URL_ENV) != agent_vm.get(
        "agent_visible_model_gateway_url_sha256"
    ):
        raise EvidenceValidationError("process model endpoint is not bound to the host relay")
    plan = _mapping(agent_vm.get("plan"), "agent VM row plan")
    sandbox = _mapping(public.get("sandbox"), "process sandbox contract")
    socket_path = sandbox.get("docker_socket_path")
    if (
        sandbox.get("docker_socket_access") is not True
        or not isinstance(socket_path, str)
        or _sha256_text(socket_path) != plan.get("docker_socket_path_sha256")
    ):
        raise EvidenceValidationError("process sandbox is not bound to the row Docker socket")


def _validate_target_terminal_pair(
    start: Mapping[str, object],
    stop: Mapping[str, object],
    *,
    arm_root: Path,
    contract_document: Mapping[str, object],
    expected_row_id: str,
    expected_system: str,
    expected_flag_hashes_by_name: Mapping[str, str],
    expected_image_ids_by_service: Mapping[str, object],
    expected_flag_commitments_sha256: str,
    expected_target_limit: int,
) -> None:
    _validate_target_start_document(
        start,
        arm_root=arm_root,
        contract_document=contract_document,
        expected_row_id=expected_row_id,
        expected_system=expected_system,
        expected_flag_hashes_by_name=expected_flag_hashes_by_name,
        expected_image_ids_by_service=expected_image_ids_by_service,
        expected_flag_commitments_sha256=expected_flag_commitments_sha256,
        expected_target_limit=expected_target_limit,
    )
    if stop.get("row_id") != expected_row_id or stop.get("instance_id") != start.get("instance_id"):
        raise EvidenceValidationError("target arm stop evidence is invalid")
    meter = _mapping(stop.get("request_meter"), "target request meter")
    observed_requests = _nonnegative_int(
        meter.get("observed_target_requests"),
        "observed target requests",
    )
    if (
        meter.get("hard_limit") != expected_target_limit
        or observed_requests > expected_target_limit
        or meter.get("sealed") is not True
        or meter.get("complete") is not True
        or meter.get("within_limit") is not True
    ):
        raise EvidenceValidationError("target request meter did not enforce its cap")
    resources = _mapping(stop.get("resources"), "target teardown resources")
    if any(
        resources.get(name) != []
        for name in (
            "containers_remaining",
            "volumes_remaining",
            "networks_remaining",
        )
    ):
        raise EvidenceValidationError("target resources remain after teardown")
    containers = _mapping(start.get("container_ids_by_service"), "target containers")
    volumes = _string_list(start.get("volume_ids"), "target volumes")
    removed_containers = _string_list(
        resources.get("removed_container_ids"),
        "removed target containers",
    )
    removed_volumes = _string_list(
        resources.get("removed_volume_ids"),
        "removed target volumes",
    )
    removed_networks = _string_list(
        resources.get("removed_network_ids"),
        "removed target networks",
    )
    if (
        set(removed_containers) != {str(value) for value in containers.values()}
        or set(removed_volumes) != set(volumes)
        or set(removed_networks) != {start.get("network_id")}
    ):
        raise EvidenceValidationError("target teardown removed-resource closure is invalid")
    _validate_agent_vm_terminal_pair(
        start,
        stop,
        arm_root=arm_root,
        contract_document=contract_document,
        expected_row_id=expected_row_id,
        expected_system=expected_system,
    )


def _validate_target_start_document(
    start: Mapping[str, object],
    *,
    arm_root: Path,
    contract_document: Mapping[str, object],
    expected_row_id: str,
    expected_system: str,
    expected_flag_hashes_by_name: Mapping[str, str],
    expected_image_ids_by_service: Mapping[str, object],
    expected_flag_commitments_sha256: str,
    expected_target_limit: int,
) -> None:
    if (
        start.get("row_id") != expected_row_id
        or start.get("system") != expected_system
        or start.get("fresh") is not True
        or start.get("build_invocations") != 0
        or start.get("pull_invocations") != 0
        or start.get("source_mounts") != []
        or start.get("operator_material_mounts") != []
        or start.get("credential_material_mounts") != []
        or start.get("request_limit") != expected_target_limit
        or start.get("flag_commitments_sha256") != expected_flag_commitments_sha256
    ):
        raise EvidenceValidationError("target arm start evidence is invalid")
    flags = _mapping(start.get("runtime_flag_sha256_by_name"), "runtime flag commitments")
    if flags != dict(expected_flag_hashes_by_name):
        raise EvidenceValidationError("target arm runtime flags differ from commitments")
    images = _mapping(start.get("image_ids_by_service"), "target arm images")
    if images != dict(expected_image_ids_by_service):
        raise EvidenceValidationError("target arm images differ from target preparation")
    _validate_agent_vm_start_binding(
        start,
        arm_root=arm_root,
        contract_document=contract_document,
        expected_row_id=expected_row_id,
        expected_system=expected_system,
    )


def _validate_agent_vm_start_binding(
    start: Mapping[str, object],
    *,
    arm_root: Path,
    contract_document: Mapping[str, object],
    expected_row_id: str,
    expected_system: str,
) -> None:
    """Bind a provisioned VM even when its later teardown failed."""

    start_vm = _mapping(start.get("agent_vm"), "agent VM start evidence")
    docker = _mapping(contract_document.get("docker_separation"), "Docker separation policy")
    target = _mapping(docker.get("target"), "target Docker authority")
    policy = _mapping(docker.get("agent_vm"), "agent VM policy")
    controller = _mapping(policy.get("controller"), "agent VM controller policy")
    relay_policy = _mapping(policy.get("relay"), "agent VM relay policy")
    plans = _mapping(policy.get("plans"), "agent VM plans")
    expected_plan = _mapping(plans.get(expected_row_id), "agent VM row plan")
    provision_ref = _mapping(start_vm.get("provision_receipt"), "agent VM provision receipt")
    relative = f"agent-daemon/{AGENT_DAEMON_PROVISION_FILE}"
    if (
        start_vm.get("row_id") != expected_row_id
        or _mapping(start_vm.get("plan"), "live agent VM plan") != expected_plan
        or start_vm.get("frozen_policy_sha256") != _sha256_bytes(_canonical_json(policy))
        or provision_ref.get("path") != relative
    ):
        raise EvidenceValidationError("agent VM start differs from its frozen plan")
    provision_path = _safe_evidence_relative(
        arm_root,
        relative,
        label="agent VM provision receipt",
    )
    if provision_ref.get("file_sha256") != _sha256_regular_file(provision_path):
        raise EvidenceValidationError("agent VM provision receipt file binding is invalid")
    provision = _read_json(provision_path, label="agent VM provision receipt")
    relay = _mapping(provision.get("relay_receipt"), "agent VM host relay receipt")
    observed_tool = _mapping(provision.get("tool_image"), "agent VM tool image")
    systems = _mapping(contract_document.get("systems"), "system pins")
    system = _mapping(systems.get(expected_system), "system pin")
    expected_tool = _mapping(system.get("tool_image"), "system tool image")
    expected_agent_identity = _sha256_digest(
        start_vm.get("observed_agent_daemon_identity_sha256"),
        "observed agent Docker daemon identity",
    )
    if (
        provision.get("controller_kind") != controller.get("kind")
        or provision.get("controller_policy_sha256") != controller.get("policy_sha256")
        or provision.get("relay_policy_sha256") != relay_policy.get("policy_sha256")
        or relay.get("enforcement_kind") != relay_policy.get("enforcement_kind")
        or provision.get("generation_id") != expected_plan.get("generation_id")
        or provision.get("profile_name") != expected_plan.get("profile_name")
        or provision.get("docker_socket_path_sha256")
        != expected_plan.get("docker_socket_path_sha256")
        or provision.get("docker_host_sha256") != expected_plan.get("docker_host_sha256")
        or provision.get("agent_network") != expected_plan.get("agent_network")
        or provision.get("target_daemon_identity_sha256") != target.get("daemon_identity_sha256")
        or provision.get("agent_daemon_identity_sha256") != expected_agent_identity
        or provision.get("target_canary_selector_sha256")
        != start_vm.get("target_canary_selector_sha256")
        or observed_tool.get("reference") != expected_tool.get("reference")
        or observed_tool.get("image_id") != expected_tool.get("expected_image_id")
        or observed_tool.get("archive_sha256") != expected_tool.get("archive_sha256")
        or observed_tool.get("platform") != expected_tool.get("platform")
        or relay.get("target_meter_url_sha256") != start_vm.get("target_meter_url_sha256")
        or relay.get("model_gateway_url_sha256") != start_vm.get("model_gateway_url_sha256")
        or start_vm.get("agent_visible_target_url_sha256") != start.get("target_url_sha256")
    ):
        raise EvidenceValidationError("agent VM provision is not bound to the frozen campaign")


def _validate_agent_vm_terminal_pair(
    start: Mapping[str, object],
    stop: Mapping[str, object],
    *,
    arm_root: Path,
    contract_document: Mapping[str, object],
    expected_row_id: str,
    expected_system: str,
) -> None:
    start_vm = _mapping(start.get("agent_vm"), "agent VM start evidence")
    stop_vm = _mapping(stop.get("agent_vm"), "agent VM stop evidence")
    if start_vm.get("row_id") != expected_row_id or stop_vm.get("row_id") != expected_row_id:
        raise EvidenceValidationError("agent VM lifecycle row binding is invalid")
    docker = _mapping(contract_document.get("docker_separation"), "Docker separation policy")
    target = _mapping(docker.get("target"), "target Docker authority")
    policy = _mapping(docker.get("agent_vm"), "agent VM policy")
    plans = _mapping(policy.get("plans"), "agent VM plans")
    expected_plan = _mapping(plans.get(expected_row_id), "agent VM row plan")
    observed_plan = _mapping(start_vm.get("plan"), "live agent VM plan")
    if (
        observed_plan != expected_plan
        or stop_vm.get("generation_id") != expected_plan.get("generation_id")
        or start_vm.get("frozen_policy_sha256") != _sha256_bytes(_canonical_json(policy))
    ):
        raise EvidenceValidationError("agent VM lifecycle differs from its frozen plan")
    provision_ref = _mapping(start_vm.get("provision_receipt"), "agent VM provision receipt")
    teardown_ref = _mapping(stop_vm.get("teardown_receipt"), "agent VM teardown receipt")
    expected_provision_relative = f"agent-daemon/{AGENT_DAEMON_PROVISION_FILE}"
    expected_teardown_relative = f"agent-daemon/{AGENT_DAEMON_TEARDOWN_FILE}"
    if (
        provision_ref.get("path") != expected_provision_relative
        or teardown_ref.get("path") != expected_teardown_relative
    ):
        raise EvidenceValidationError("agent VM lifecycle receipt paths are not canonical")
    provision_path = _safe_evidence_relative(
        arm_root,
        expected_provision_relative,
        label="agent VM provision receipt",
    )
    teardown_path = _safe_evidence_relative(
        arm_root,
        expected_teardown_relative,
        label="agent VM teardown receipt",
    )
    if provision_ref.get("file_sha256") != _sha256_regular_file(provision_path) or teardown_ref.get(
        "file_sha256"
    ) != _sha256_regular_file(teardown_path):
        raise EvidenceValidationError("agent VM lifecycle receipt file binding is invalid")
    controller = _mapping(policy.get("controller"), "agent VM controller policy")
    template = _mapping(policy.get("template"), "agent VM template policy")
    base_image = _mapping(policy.get("base_image"), "agent VM base-image policy")
    relay_policy = _mapping(policy.get("relay"), "agent VM relay policy")
    systems = _mapping(contract_document.get("systems"), "system pins")
    system = _mapping(systems.get(expected_system), "system pin")
    expected_tool = _mapping(system.get("tool_image"), "system tool image")
    expectation = AgentDaemonLifecycleExpectation(
        row_id=expected_row_id,
        plan=AgentVmPlanExpectation(
            row_id=expected_row_id,
            profile_name=_required_string(
                expected_plan.get("profile_name"),
                "agent VM profile",
            ),
            generation_id=_required_string(
                expected_plan.get("generation_id"),
                "agent VM generation",
            ),
            docker_host_sha256=_required_string(
                expected_plan.get("docker_host_sha256"),
                "agent VM Docker host digest",
            ),
            docker_socket_path_sha256=_required_string(
                expected_plan.get("docker_socket_path_sha256"),
                "agent VM Docker socket digest",
            ),
            agent_network=_required_string(
                expected_plan.get("agent_network"),
                "agent VM network",
            ),
        ),
        static_inputs={
            "agent_docker_executable_sha256": policy.get("docker_executable_sha256"),
            "controller_implementation_sha256": controller.get("implementation_sha256"),
            "controller_policy_sha256": controller.get("policy_sha256"),
            "supervisor_runtime_manifest_sha256": controller.get(
                "supervisor_runtime_manifest_sha256"
            ),
            "vm_template_sha256": template.get("sha256"),
            "base_image_sha256": base_image.get("sha256"),
            "base_image_platform": base_image.get("platform"),
            "base_image_local_only": base_image.get("offline_required"),
            "download_or_update_performed": False,
            "relay_implementation_sha256": relay_policy.get("implementation_sha256"),
            "relay_policy_sha256": relay_policy.get("policy_sha256"),
            "relay_enforcement_kind": relay_policy.get("enforcement_kind"),
        },
        target_daemon_identity_sha256=_required_string(
            target.get("daemon_identity_sha256"),
            "target Docker daemon identity",
        ),
        target_canary_selector_sha256=_required_string(
            start_vm.get("target_canary_selector_sha256"),
            "target canary selector digest",
        ),
        target_meter_url_sha256=_required_string(
            start_vm.get("target_meter_url_sha256"),
            "target meter URL digest",
        ),
        model_gateway_url_sha256=_required_string(
            start_vm.get("model_gateway_url_sha256"),
            "model gateway URL digest",
        ),
        agent_visible_target_url_sha256=_required_string(
            start_vm.get("agent_visible_target_url_sha256"),
            "agent-visible target URL digest",
        ),
        agent_visible_model_gateway_url_sha256=_required_string(
            start_vm.get("agent_visible_model_gateway_url_sha256"),
            "agent-visible model URL digest",
        ),
        tool_image_reference=_required_string(
            expected_tool.get("reference"),
            "agent tool image reference",
        ),
        tool_image_id=_required_string(
            expected_tool.get("expected_image_id"),
            "agent tool image ID",
        ),
        tool_archive_sha256=_required_string(
            expected_tool.get("archive_sha256"),
            "agent tool archive digest",
        ),
        tool_platform=_required_string(
            expected_tool.get("platform"),
            "agent tool platform",
        ),
    )
    try:
        lifecycle = validate_agent_daemon_lifecycle(
            provision_path=provision_path,
            teardown_path=teardown_path,
            expectation=expectation,
        )
    except (AgentVmIsolationError, OSError, TypeError, ValueError) as exc:
        raise EvidenceValidationError("agent VM lifecycle receipts are invalid") from exc
    if (
        lifecycle.get("valid") is not True
        or lifecycle.get("provision_file_sha256") != provision_ref.get("file_sha256")
        or lifecycle.get("teardown_file_sha256") != teardown_ref.get("file_sha256")
    ):
        raise EvidenceValidationError("agent VM lifecycle validator did not join retained files")
    provision = _read_json(provision_path, label="agent VM provision receipt")
    relay = _mapping(provision.get("relay_receipt"), "agent VM host relay receipt")
    observed_tool = _mapping(provision.get("tool_image"), "agent VM tool image")
    expected_agent_identity = _sha256_digest(
        start_vm.get("observed_agent_daemon_identity_sha256"),
        "observed agent Docker daemon identity",
    )
    if (
        provision.get("controller_kind") != controller.get("kind")
        or provision.get("controller_policy_sha256") != controller.get("policy_sha256")
        or provision.get("relay_policy_sha256") != relay_policy.get("policy_sha256")
        or relay.get("enforcement_kind") != relay_policy.get("enforcement_kind")
        or provision.get("generation_id") != expected_plan.get("generation_id")
        or provision.get("profile_name") != expected_plan.get("profile_name")
        or provision.get("docker_socket_path_sha256")
        != expected_plan.get("docker_socket_path_sha256")
        or provision.get("docker_host_sha256") != expected_plan.get("docker_host_sha256")
        or provision.get("agent_network") != expected_plan.get("agent_network")
        or provision.get("target_daemon_identity_sha256") != target.get("daemon_identity_sha256")
        or provision.get("agent_daemon_identity_sha256") != expected_agent_identity
        or provision.get("target_canary_selector_sha256")
        != start_vm.get("target_canary_selector_sha256")
        or observed_tool.get("reference") != expected_tool.get("reference")
        or observed_tool.get("image_id") != expected_tool.get("expected_image_id")
        or observed_tool.get("archive_sha256") != expected_tool.get("archive_sha256")
        or observed_tool.get("platform") != expected_tool.get("platform")
        or relay.get("target_meter_url_sha256") != start_vm.get("target_meter_url_sha256")
        or relay.get("model_gateway_url_sha256") != start_vm.get("model_gateway_url_sha256")
        or start_vm.get("agent_visible_target_url_sha256") != start.get("target_url_sha256")
    ):
        raise EvidenceValidationError("agent VM lifecycle is not bound to the frozen campaign")


def _cross_validate_live_identity(
    earlier: Sequence[Mapping[str, object]],
    current: Mapping[str, object],
) -> None:
    for prior in earlier:
        if prior.get("image_ids_by_service") != current.get("image_ids_by_service"):
            raise EvidenceValidationError("the two arms use different prepared images")
        for name in ("project_id", "network_id", "instance_id"):
            if prior.get(name) == current.get(name):
                raise EvidenceValidationError(f"the two arms reused {name}")
        prior_containers = set(
            _mapping(prior.get("container_ids_by_service"), "containers").values()
        )
        current_containers = set(
            _mapping(current.get("container_ids_by_service"), "containers").values()
        )
        if prior_containers.intersection(current_containers):
            raise EvidenceValidationError("the two arms reused a container")
        prior_volumes = set(_string_list(prior.get("volume_ids"), "prior volume IDs"))
        current_volumes = set(_string_list(current.get("volume_ids"), "current volume IDs"))
        if prior_volumes.intersection(current_volumes):
            raise EvidenceValidationError("the two arms reused a volume")
        prior_vm = _mapping(prior.get("agent_vm"), "prior agent VM evidence")
        current_vm = _mapping(current.get("agent_vm"), "current agent VM evidence")
        prior_plan = _mapping(prior_vm.get("plan"), "prior agent VM plan")
        current_plan = _mapping(current_vm.get("plan"), "current agent VM plan")
        for name in (
            "generation_id",
            "profile_name",
            "docker_socket_path_sha256",
            "docker_host_sha256",
            "agent_network",
        ):
            if prior_plan.get(name) == current_plan.get(name):
                raise EvidenceValidationError(f"the two arms reused agent VM {name}")
        if prior_vm.get("observed_agent_daemon_identity_sha256") == current_vm.get(
            "observed_agent_daemon_identity_sha256"
        ):
            raise EvidenceValidationError("the two arms reused a live agent Docker daemon")


def _verify_primary_seal(
    root: Path,
    *,
    seal: Mapping[str, object],
    contract_document: Mapping[str, object],
) -> None:
    if (
        seal.get("contract_sha256") != contract_document.get("document_sha256")
        or seal.get("classification") != KNOWN_SITE_CLASSIFICATION
        or seal.get("claim_boundary") != KNOWN_SITE_CLAIM_BOUNDARY
        or seal.get("expected_rows") != list(ROW_IDS)
        or seal.get("retry_count") != 0
        or seal.get("resume_count") != 0
        or seal.get("replacement_count") != 0
    ):
        raise EvidenceValidationError("known-site primary seal policy is invalid")
    expected = _sealed_file_manifest(root)
    if seal.get("evidence_files") != expected or seal.get("file_count") != len(expected):
        raise EvidenceValidationError("known-site primary seal file manifest differs")


def _sealed_file_manifest(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    excluded = {PRIMARY_SEAL_FILE, REPORT_FILE}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative in excluded or path.is_dir():
            continue
        if path.is_symlink():
            raise EvidenceValidationError("primary evidence contains a symlink")
        if len(entries) >= MAX_SEALED_FILES:
            raise EvidenceValidationError("primary evidence file count exceeds the fixed bound")
        body = _read_bounded_regular_file(path, maximum_bytes=MAX_SEALED_FILE_BYTES)
        entries.append(
            {
                "path": relative,
                "sha256": _sha256_bytes(body),
                "size_bytes": len(body),
            }
        )
    return entries


def _synthetic_unstarted_terminal(
    context: AgentArmContext,
    *,
    error: str,
) -> AgentArmTerminal:
    return AgentArmTerminal(
        status="unstarted",
        returncode=-1,
        timed_out=False,
        elapsed_seconds=0.0,
        description_sha256=_sha256_text(context.description),
        semantic_prompt_sha256=None,
        model_gateway_policy_sha256=context.gateway_policy_sha256,
        adapter_version=ADAPTER_VERSION,
        artifact_path=None,
        artifact_sha256=None,
        adapter_receipt_path=None,
        process_receipt_path=None,
        model_receipt_path=None,
        sandbox_profile_path=None,
        process_public_contract=None,
        evidence_class=PAIRED_LOCAL,
        error=error,
    )


def _validate_model_policy(value: Mapping[str, object]) -> dict[str, object]:
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
    if set(value) != fields or value.get("schema_version") != MODEL_GATEWAY_POLICY_SCHEMA:
        raise ValueError("known-site model policy is not the canonical gateway policy")
    if value.get("retry_policy") != "gateway_never_retries":
        raise ValueError("known-site gateway retry policy is invalid")
    if value.get("unknown_usage_policy") != "charge_full_reservation_and_invalidate_row":
        raise ValueError("known-site gateway unknown-usage policy is invalid")
    for name in ("model", "reasoning_effort", "upstream"):
        text = value.get(name)
        if not isinstance(text, str) or not text or text != text.strip() or len(text) > 512:
            raise ValueError(f"known-site model policy {name} is invalid")
    pricing = _mapping(value.get("pricing_usd_per_million_tokens"), "model pricing")
    if set(pricing) != {"input_per_million", "cached_input_per_million", "output_per_million"}:
        raise ValueError("known-site model pricing fields are invalid")
    for name, raw in pricing.items():
        price = _decimal(raw, f"model price {name}")
        if price < 0 or (name != "cached_input_per_million" and price <= 0):
            raise ValueError("known-site model price is invalid")
    _decimal(value.get("campaign_max_cost_usd"), "campaign cost")
    for name in (
        "max_completion_tokens_per_request",
        "max_request_body_bytes",
        "max_upstream_response_bytes",
        "upstream_timeout_seconds",
        "max_parallel_requests",
    ):
        _positive_int(value.get(name), f"model policy {name}")
    return dict(value)


def _validate_target_runtime(value: Mapping[str, object]) -> dict[str, object]:
    if set(value) != {
        "platform",
        "images",
        "http_meter",
        "dependency_lock",
        "proxy_configuration",
    }:
        raise ValueError("known-site target runtime fields are invalid")
    platform = value.get("platform")
    if not isinstance(platform, str) or _PLATFORM_RE.fullmatch(platform) is None:
        raise ValueError("known-site target platform must be exact Linux amd64 or arm64")
    images = _mapping(value.get("images"), "known-site target images")
    if set(images) != {"node_base", "proxy", "http_meter", "readiness_probe"}:
        raise ValueError("known-site target image pin set is incomplete")
    normalized_images: dict[str, object] = {}
    for name, raw in sorted(images.items()):
        pin = _mapping(raw, f"known-site {name} image pin")
        reference = pin.get("reference")
        image_id = pin.get("expected_image_id")
        if (
            set(pin) != {"reference", "expected_image_id"}
            or not isinstance(reference, str)
            or _IMAGE_REFERENCE_RE.fullmatch(reference) is None
            or not isinstance(image_id, str)
            or _IMAGE_ID_RE.fullmatch(image_id) is None
        ):
            raise ValueError(f"known-site {name} image pin is not immutable")
        normalized_images[name] = {
            "reference": reference,
            "expected_image_id": image_id,
        }
    meter = _mapping(value.get("http_meter"), "known-site HTTP meter")
    program_digest = meter.get("program_sha256")
    if (
        set(meter) != {"program_sha256", "protocol"}
        or not isinstance(program_digest, str)
        or _RAW_SHA256_RE.fullmatch(program_digest) is None
        or meter.get("protocol") != HTTP_METER_PROTOCOL
    ):
        raise ValueError("known-site HTTP meter pin is invalid")
    lock = _mapping(value.get("dependency_lock"), "known-site dependency lock")
    if (
        set(lock)
        != {
            "required",
            "relative_path",
            "sha256",
            "package_json_sha256",
            "installer",
        }
        or lock.get("required") is not True
        or lock.get("relative_path") != "web/package-lock.json"
        or lock.get("installer") != "npm-ci-omit-dev"
    ):
        raise ValueError("known-site dependency-lock policy is invalid")
    _sha256_digest(lock.get("sha256"), "dependency lock digest")
    _sha256_digest(lock.get("package_json_sha256"), "package manifest digest")
    proxy = _mapping(value.get("proxy_configuration"), "known-site proxy configuration")
    if (
        set(proxy) != {"relative_path", "sha256"}
        or proxy.get("relative_path") != "proxy/nginx.conf"
    ):
        raise ValueError("known-site proxy configuration pin is invalid")
    _sha256_digest(proxy.get("sha256"), "proxy configuration digest")
    return {
        "platform": platform,
        "images": normalized_images,
        "http_meter": dict(meter),
        "dependency_lock": dict(lock),
        "proxy_configuration": dict(proxy),
    }


def _validate_contract_limit(document: Mapping[str, object], name: str) -> int:
    return _contract_limit(document, name)


def _contract_limit(document: Mapping[str, object], name: str) -> int:
    budgets = _mapping(document.get("budgets"), "budgets")
    per_arm = _mapping(budgets.get("per_arm"), "per-arm budgets")
    return _positive_int(per_arm.get(name), f"per-arm {name}")


def _image_map(value: Mapping[str, str]) -> dict[str, str]:
    if set(value) != SERVICE_NAMES:
        raise EvidenceValidationError("known-site target service image set is incomplete")
    result = {str(name): str(image) for name, image in sorted(value.items())}
    if any(_IMAGE_ID_RE.fullmatch(image) is None for image in result.values()):
        raise EvidenceValidationError("known-site target image ID is not immutable")
    return result


def _build_count_map(value: Mapping[str, int]) -> dict[str, int]:
    if set(value) != SERVICE_NAMES:
        raise EvidenceValidationError("known-site build-count service set is incomplete")
    result = {str(name): count for name, count in sorted(value.items())}
    expected = {"internal": 1, "proxy": 0, "web": 1}
    if result != expected:
        raise EvidenceValidationError("web/internal must be built exactly once and proxy never")
    return result


def _service_id_map(value: Mapping[str, str], label: str) -> dict[str, str]:
    if set(value) != SERVICE_NAMES:
        raise EvidenceValidationError(f"known-site {label} service set is incomplete")
    result = {
        str(service): _safe_id(identifier, f"{label} ID")
        for service, identifier in sorted(value.items())
    }
    if len(set(result.values())) != len(result):
        raise EvidenceValidationError(f"known-site {label} IDs are not unique")
    return result


def _unique_safe_ids(
    values: Sequence[str],
    label: str,
    *,
    require_nonempty: bool,
) -> tuple[str, ...]:
    result = tuple(_safe_id(value, f"{label} ID") for value in values)
    if require_nonempty and not result:
        raise EvidenceValidationError(f"known-site arm has no fresh {label}s")
    if len(set(result)) != len(result):
        raise EvidenceValidationError(f"known-site {label} IDs are not unique")
    return tuple(sorted(result))


def _bound_receipt_path(
    arm_root: Path,
    record: Mapping[str, object],
    filename: str,
    *,
    native: bool,
) -> Path:
    expected = f"{NATIVE_OUTPUT_DIRECTORY}/{filename}" if native else filename
    if record.get("path") != expected:
        raise EvidenceValidationError(f"retained {filename} path is invalid")
    path = _safe_evidence_relative(arm_root, expected, label=filename)
    if (
        record.get("file_sha256") != _sha256_regular_file(path)
        or record.get("size_bytes") != path.stat().st_size
    ):
        raise EvidenceValidationError(f"retained {filename} digest is invalid")
    return path


def _safe_evidence_relative(root: Path, relative: str, *, label: str) -> Path:
    raw = PurePosixPath(relative)
    if raw.is_absolute() or not raw.parts or ".." in raw.parts or "\\" in relative:
        raise EvidenceValidationError(f"{label} path is unsafe")
    path = root.joinpath(*raw.parts)
    if path.is_symlink():
        raise EvidenceValidationError(f"{label} must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise EvidenceValidationError(f"{label} escaped its arm evidence root") from exc
    if not resolved.is_file():
        raise EvidenceValidationError(f"{label} is not a regular file")
    return resolved


def _claim_campaign_directory(path: Path) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise CampaignAlreadyExistsError("campaign directory must not be a symlink")
    resolved = requested.resolve(strict=False)
    try:
        resolved.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise CampaignAlreadyExistsError(
            "known-site campaign is already claimed; resume and replacement are forbidden"
        ) from exc
    return resolved


def _canonical_campaign_directory_sha256(path: Path) -> str:
    """Hash the absolute normalized destination without creating it."""

    requested = path.expanduser()
    if not requested.is_absolute():
        raise KnownSiteRegressionError("canonical campaign directory must be absolute")
    try:
        normalized = requested.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise KnownSiteRegressionError("canonical campaign directory is invalid") from exc
    return _sha256_text(normalized.as_posix())


def _claim_child_directory(parent: Path, name: str) -> Path:
    path = parent / name
    try:
        path.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise CampaignAlreadyExistsError(f"evidence directory {name!r} already exists") from exc
    return path


def _write_json_exclusive(
    path: Path,
    payload: Mapping[str, object],
    *,
    secrets_to_reject: Sequence[str] = (),
) -> None:
    _assert_json_safe(payload)
    body = _canonical_json(payload) + b"\n"
    if len(body) > MAX_JSON_BYTES:
        raise EvidenceValidationError("JSON evidence exceeds the fixed size bound")
    for secret in secrets_to_reject:
        if secret and secret.encode("utf-8") in body:
            raise EvidenceValidationError("refusing to persist evaluator-only plaintext")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise CampaignAlreadyExistsError(f"refusing to replace evidence {path.name!r}") from exc
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_document(path: Path, schema: str) -> dict[str, object]:
    document = _read_json(path, label=path.name)
    if document.get("schema_version") != schema:
        raise EvidenceValidationError(f"{path.name} has an invalid schema")
    if (
        document.get("evaluation_classification") != KNOWN_SITE_CLASSIFICATION
        or document.get("claim_boundary") != KNOWN_SITE_CLAIM_BOUNDARY
        or document.get("eligible_for_sota_claim") is not False
        or document.get("eligible_for_unseen_claim") is not False
    ):
        raise EvidenceValidationError(f"{path.name} weakens the known-site claim boundary")
    digest = document.get("document_sha256")
    if digest != _sha256_bytes(_canonical_json(_body_without_digest(document))):
        raise EvidenceValidationError(f"{path.name} has an invalid document digest")
    return document


def _read_json(path: Path, *, label: str) -> dict[str, object]:
    body = _read_bounded_regular_file(path, maximum_bytes=MAX_JSON_BYTES)
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EvidenceValidationError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{label} must be a JSON object")
    return value


def _read_bounded_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    if path.is_symlink():
        raise EvidenceValidationError("file_is_a_symlink")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise EvidenceValidationError("file_is_unreadable") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise EvidenceValidationError("file_is_not_a_single_link_regular_file")
    if metadata.st_size > maximum_bytes:
        raise EvidenceValidationError("file_is_too_large")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            body = handle.read(maximum_bytes + 1)
            closed = os.fstat(handle.fileno())
    except OSError as exc:
        raise EvidenceValidationError("file_changed_or_became_unreadable") from exc
    if (
        len(body) > maximum_bytes
        or opened.st_dev != metadata.st_dev
        or opened.st_ino != metadata.st_ino
        or opened.st_size != metadata.st_size
        or closed.st_dev != opened.st_dev
        or closed.st_ino != opened.st_ino
        or closed.st_size != opened.st_size
        or closed.st_mtime_ns != opened.st_mtime_ns
        or closed.st_ctime_ns != opened.st_ctime_ns
    ):
        raise EvidenceValidationError("file_changed_while_reading")
    return body


def _document(body: Mapping[str, object]) -> dict[str, object]:
    result = dict(body)
    if "document_sha256" in result:
        raise ValueError("document body already contains its digest field")
    result.setdefault("evaluation_classification", KNOWN_SITE_CLASSIFICATION)
    result.setdefault("claim_boundary", KNOWN_SITE_CLAIM_BOUNDARY)
    result.setdefault("eligible_for_sota_claim", False)
    result.setdefault("eligible_for_unseen_claim", False)
    if (
        result["evaluation_classification"] != KNOWN_SITE_CLASSIFICATION
        or result["claim_boundary"] != KNOWN_SITE_CLAIM_BOUNDARY
        or result["eligible_for_sota_claim"] is not False
        or result["eligible_for_unseen_claim"] is not False
    ):
        raise ValueError("known-site document attempts to weaken its claim boundary")
    _assert_json_safe(result)
    result["document_sha256"] = _sha256_bytes(_canonical_json(result))
    return result


def _body_without_digest(document: Mapping[str, object]) -> dict[str, object]:
    return {name: value for name, value in document.items() if name != "document_sha256"}


def _semantic_document_body(document: Mapping[str, object]) -> dict[str, object]:
    """Remove only nondeterministic creation time and the digest covering it."""

    return {
        name: value
        for name, value in document.items()
        if name not in {"created_at", "document_sha256"}
    }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _assert_json_safe(value: object) -> None:
    try:
        _canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceValidationError("evidence is not finite canonical JSON") from exc


def _assert_plaintext_absent(
    value: object,
    *,
    secrets_to_reject: Sequence[str],
) -> None:
    body = _canonical_json(value)
    if any(secret and secret.encode("utf-8") in body for secret in secrets_to_reject):
        raise EvidenceValidationError("backend receipt contains evaluator-only plaintext")


def _safe_error(exc: BaseException, *, secrets_to_reject: Sequence[str]) -> str:
    value = str(exc).strip() or type(exc).__name__
    for secret in secrets_to_reject:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    # Also suppress any correctly shaped site flag an unsafe backend echoed.
    value = _FLAG_RE.sub("[REDACTED]", value)
    return value[:1000]


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha256_regular_file(path: Path) -> str:
    return _sha256_bytes(_read_bounded_regular_file(path, maximum_bytes=MAX_SEALED_FILE_BYTES))


def _sha256_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise EvidenceValidationError(f"{label} is not a SHA-256 digest")
    return value


def _decimal(value: object, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValueError(f"{label} is invalid")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not result.is_finite():
        raise ValueError(f"{label} is invalid")
    return result


def _add_money(left: Decimal, right: Decimal) -> Decimal:
    """Add receipt amounts without depending on the ambient decimal precision."""

    with localcontext() as context:
        context.prec = max(
            context.prec,
            max(left.adjusted(), right.adjusted())
            - min(int(left.as_tuple().exponent), int(right.as_tuple().exponent))
            + 2,
        )
        return left + right


def _money(value: Decimal) -> str:
    normalized = format(value, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EvidenceValidationError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceValidationError(f"{label} must be a nonnegative integer")
    return value


def _finite_nonnegative_float(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceValidationError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise EvidenceValidationError(f"{label} must be finite and nonnegative")
    return result


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise EvidenceValidationError(f"{label} must be an object")
    return {str(name): item for name, item in value.items()}


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise EvidenceValidationError(f"{label} must be a string list")
    return tuple(value)


def _commitment_entries(document: Mapping[str, object]) -> tuple[dict[str, object], ...]:
    value = document.get("commitments")
    if not isinstance(value, list):
        raise EvidenceValidationError("flag commitments must be a list")
    return tuple(_mapping(entry, "flag commitment") for entry in value)


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise EvidenceValidationError(f"{label} is invalid")
    return value


def _required_string(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
    ):
        raise EvidenceValidationError(f"{label} is invalid")
    return value


def _validated_http_url(value: str) -> str:
    split = urlsplit(value)
    if (
        split.scheme != "http"
        or not split.hostname
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
    ):
        raise EvidenceValidationError("known-site target URL must be credential-free HTTP")
    try:
        port = split.port
    except ValueError as exc:
        raise EvidenceValidationError("known-site target URL port is invalid") from exc
    if port is None or not 0 < port < 65536:
        raise EvidenceValidationError("known-site target URL requires an explicit port")
    return value


def _existing_directory(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise EvidenceValidationError(f"{label} must not be a symlink")
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise EvidenceValidationError(f"{label} does not exist") from exc
    if not resolved.is_dir():
        raise EvidenceValidationError(f"{label} is not a directory")
    return resolved


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "AGENT_VM_GENERATION_DOMAIN",
    "ARM_ORDER_DOMAIN",
    "AUTHENTICATED_ARM_ORDER_PROTOCOL",
    "KNOWN_SITE_CLASSIFICATION",
    "KNOWN_SITE_ID",
    "KNOWN_SITE_PUBLIC_DESCRIPTION",
    "AgentArmContext",
    "AgentArmTerminal",
    "AgentVmPlanPin",
    "AgentVmPolicyPin",
    "AgentVmTeardownEvidence",
    "AuthenticatedArmOrderPin",
    "CampaignAlreadyExistsError",
    "DockerDaemonPin",
    "DockerSeparationPolicy",
    "EvidenceValidationError",
    "FrozenKnownSiteContract",
    "KnownSiteAgentBackend",
    "KnownSiteGateway",
    "KnownSiteLimits",
    "KnownSiteRegressionError",
    "KnownSiteSystemPin",
    "KnownSiteTargetBackend",
    "LiveAgentVmEvidence",
    "LiveKnownSiteArm",
    "PreparedKnownSiteTarget",
    "SiteArmTeardown",
    "SiteSourcePin",
    "derive_agent_vm_generation_id",
    "derive_arm_order",
    "derive_target_canary_value",
    "execute_known_site_regression",
    "score_candidate_artifact",
    "verify_known_site_regression",
]
