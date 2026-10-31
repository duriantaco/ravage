# ruff: noqa: C901,D202,D213,EM101,EM102,PLR0915,PLR2004,SLF001,TRY003
"""Production assembly for the paired known-site website regression.

This module deliberately keeps configuration/preparation separate from the
one-shot campaign directory.  Preparing a request performs no randomness,
model, registry, Docker build, or target action.  Execution accepts only the
create-only executor document emitted by a successful preparation and still
revalidates every mutable local identity before the harness can claim a
campaign or draw its five private flags.

The cross-daemon HTTP relay is intentionally an injected protocol.  There is
no permissive default: until a reviewed provider can prove the target daemon,
agent daemon, and agent-visible metered relay are distinct, both ``prepare``
and ``execute`` fail closed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast
from urllib.parse import urlsplit

import ravage.xben_parts.comparison_adapters as comparison_adapters_module
import ravage.xben_parts.comparison_agent_vm as comparison_agent_vm_module
import ravage.xben_parts.comparison_model_gateway as comparison_model_gateway_module
import ravage.xben_parts.comparison_process_backend as comparison_process_backend_module
import ravage.xben_parts.external_comparison as external_comparison_module
import ravage.xben_parts.http_meter_gateway as http_meter_gateway_module
from ravage.xben_parts.comparison_adapters import (
    GatewayPricing,
    PinnedAgentRuntime,
    RowModelGateway,
    build_ravage_agent,
    build_strix_agent,
    verify_pinned_runtime,
)
from ravage.xben_parts.comparison_agent_vm import (
    AgentToolArchivePin,
    PlannedAgentVm,
)
from ravage.xben_parts.comparison_model_gateway import (
    ComparisonModelGateway,
    ModelGatewayPolicy,
    ModelPricing,
)
from ravage.xben_parts.comparison_process_backend import (
    PAIRED_LOCAL,
    ComparisonProcessBackend,
)

import tools.known_site_regression.agent_backend as known_site_agent_backend_module
import tools.known_site_regression.docker_target as known_site_docker_target_module
import tools.known_site_regression.harness as known_site_harness_module
import tools.paired_xben.prepare as paired_xben_prepare_module
import tools.paired_xben.protocol as paired_xben_protocol_module
from tools.known_site_regression.agent_backend import (
    CanonicalKnownSiteAgentBackend,
    _validate_forbidden_source_separation,
)
from tools.known_site_regression.harness import (
    KNOWN_SITE_CLAIM_BOUNDARY,
    KNOWN_SITE_CLASSIFICATION,
    KNOWN_SITE_SOURCE_PATH,
    ROW_IDS,
    AgentArmContext,
    AgentVmPlanPin,
    AgentVmPolicyPin,
    AuthenticatedArmOrderPin,
    DockerDaemonPin,
    DockerSeparationPolicy,
    EvidenceValidationError,
    FrozenKnownSiteContract,
    KnownSiteLimits,
    KnownSiteRegressionError,
    KnownSiteSystemPin,
    KnownSiteTargetBackend,
    SiteSourcePin,
    SystemId,
    derive_agent_vm_generation_id,
    execute_known_site_regression,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from ravage.xben_parts.external_comparison import (
        ExternalAgentCommand,
        ExternalProcessBackend,
    )

PRODUCTION_REQUEST_SCHEMA: Final = "ravage.known-site.production-request.v4"
PRODUCTION_PREPARATION_SCHEMA: Final = "ravage.known-site.production-preparation.v4"
EXECUTOR_CONFIGURATION_SCHEMA: Final = "ravage.known-site.executor-configuration.v4"

REQUEST_FILE: Final = "request.json"
DRAFT_CONTRACT_FILE: Final = "draft-run-contract.json"
RUN_CONTRACT_FILE: Final = "run-contract.json"
EXECUTOR_CONFIGURATION_FILE: Final = "executor-config.json"
PREPARATION_FILE: Final = "preparation.json"
STATUS_FILE: Final = "STATUS.md"
HASH_MANIFEST_FILE: Final = "ARTIFACTS.sha256"

_MAX_JSON_BYTES: Final = 2 * 1024 * 1024
_MAX_IDENTITY_FILE_BYTES: Final = 2 * 1024 * 1024 * 1024
_MAX_GIT_OUTPUT_BYTES: Final = 1024 * 1024
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_ENVIRONMENT_RE = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_NETWORK_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SAFE_PROVIDER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
_SYSTEMS: Final[tuple[SystemId, SystemId]] = ("ravage", "strix")

_REQUEST_FIELDS: Final = {
    "schema_version",
    "campaign_id",
    "canonical_campaign_directory",
    "authenticated_order_source",
    "site_source",
    "systems",
    "target_runtime",
    "model_gateway_policy",
    "limits",
    "docker_separation",
    "execution",
    "isolation_provider",
}
_ORDER_SOURCE_FIELDS: Final = {
    "paired_campaign_directory",
    "paired_campaign_id",
    "commitment_document_sha256",
    "preflight_document_sha256",
    "beacon_document_sha256",
    "selection_document_sha256",
    "draw_key_sha256",
    "website_content_sha256",
    "website_reference_sha256",
}
_SYSTEM_FIELDS: Final = {
    "origin_url",
    "repository",
    "commit",
    "tree",
    "executable",
    "executable_sha256",
    "runtime_environment_manifest",
    "runtime_environment_manifest_sha256",
    "runtime_read_roots",
    "tool_image_reference",
    "tool_image_id",
    "tool_image_archive",
    "tool_image_archive_sha256",
    "platform",
}
_DAEMON_FIELDS: Final = {
    "docker_executable",
    "docker_executable_sha256",
    "docker_socket_path",
    "docker_socket_path_sha256",
    "docker_host",
    "docker_host_sha256",
    "daemon_identity_sha256",
}
_AGENT_VM_FIELDS: Final = {
    "docker_executable",
    "docker_executable_sha256",
    "controller_kind",
    "controller_implementation",
    "controller_implementation_sha256",
    "controller_policy",
    "controller_policy_sha256",
    "supervisor_executable",
    "supervisor_executable_sha256",
    "supervisor_runtime_manifest",
    "supervisor_runtime_manifest_sha256",
    "vm_template",
    "vm_template_sha256",
    "base_image",
    "base_image_sha256",
    "relay_implementation",
    "relay_implementation_sha256",
    "relay_enforcement_kind",
    "relay_policy",
    "relay_policy_sha256",
    "plans",
}
_AGENT_VM_PLAN_FIELDS: Final = {
    "docker_socket_path",
    "docker_socket_path_sha256",
    "docker_host",
    "docker_host_sha256",
}
_EXECUTION_FIELDS: Final = {
    "trusted_path",
    "sandbox_executable",
    "sandbox_executable_sha256",
    "upstream_api_key_environment",
}
_PROVIDER_FIELDS: Final = {
    "name",
    "implementation_path",
    "implementation_sha256",
    "target_meter_exposure",
    "agent_visible_target_path",
}


class KnownSiteProductionError(KnownSiteRegressionError):
    """A production request or its live assembly is incomplete or unsafe."""


@dataclass(frozen=True)
class SystemRuntimeConfiguration:
    """Local-only runtime material corresponding to one public system pin."""

    repository: Path
    runtime: PinnedAgentRuntime
    runtime_read_roots: tuple[Path, ...]
    tool_image_archive: Path


@dataclass(frozen=True)
class DockerAuthorityConfiguration:
    """Local endpoint material corresponding to one secret-free daemon pin."""

    docker_executable: Path
    docker_socket_path: Path
    docker_host: str
    pin: DockerDaemonPin


@dataclass(frozen=True)
class AgentVmProductionConfiguration:
    """Local immutable material and side-effect-free plans for row VMs."""

    docker_executable: Path
    controller_implementation: Path
    controller_policy: Path
    supervisor_executable: Path
    supervisor_runtime_manifest: Path
    vm_template: Path
    base_image: Path
    relay_implementation: Path
    relay_policy: Path
    plans: Mapping[str, PlannedAgentVm]
    pin: AgentVmPolicyPin


@dataclass(frozen=True)
class IsolationProviderPin:
    """Exact reviewed implementation expected by an injected provider."""

    name: str
    implementation_path: Path
    implementation_sha256: str
    target_meter_exposure: str
    agent_visible_target_path: str


@dataclass(frozen=True)
class AuthenticatedOrderSourceConfiguration:
    """Local resolved paired-XBEN campaign and its exact public pins."""

    paired_campaign_directory: Path
    pin: AuthenticatedArmOrderPin


@dataclass(frozen=True)
class KnownSiteProductionConfiguration:
    """Frozen public contract plus machine-local execution material."""

    request_document: Mapping[str, object]
    contract: FrozenKnownSiteContract
    canonical_campaign_directory: Path
    site_repository: Path
    systems: Mapping[SystemId, SystemRuntimeConfiguration]
    target_docker: DockerAuthorityConfiguration
    agent_vm: AgentVmProductionConfiguration
    trusted_path: str
    sandbox_executable: Path
    sandbox_executable_sha256: str
    upstream_api_key_environment: str
    isolation_provider: IsolationProviderPin
    authenticated_order_source: AuthenticatedOrderSourceConfiguration


@dataclass(frozen=True)
class AgentToolBoundary:
    """Agent-daemon connection resolved after a target arm exposes its relay.

    ``docker_host`` and ``docker_socket_path`` belong only to the agent-tool
    daemon.  ``agent_network`` is likewise an agent-daemon network and must
    never be a target-daemon network.  The agent-visible target URL is supplied
    independently by ``KnownSiteTargetBackend.start_arm``.
    """

    docker_host: str
    docker_socket_path: Path
    daemon_identity_sha256: str
    generation_id: str
    profile_name: str
    agent_network: str
    agent_visible_target_url: str
    agent_visible_model_gateway_url: str


class KnownSiteIsolationProvider(Protocol):
    """Reviewed dual-daemon and meter-only relay integration.

    ``validate_pre_draw`` may perform read-only identity probes, but it must not
    sample entropy, start a target, build/pull an image, or contact a model.
    ``planned_agent_vm`` is side-effect-free and must reproduce the exact two
    endpoint plans. ``build_target_backend`` is construction-only. Its returned
    backend owns the whole per-row order: start the target and its deterministic
    canary; provision the pristine VM and host relay; return only after the
    generic provision receipt exists; then, in ``stop_arm``, drain/stop the
    relay, delete the VM/socket/profile, retain the generic teardown receipt,
    and only then stop the target meter. A partially failed ``start_arm`` must
    clean up and poison that generation itself because the harness has no live
    handle to stop. Controller/template/base-image/relay/tool pins must be
    rehashed immediately before every provision.

    ``agent_tool_boundary`` is lookup-only: it must never lazily provision or
    retry. Both returned HTTP endpoints are the agent-visible host-enforced
    relay endpoints, never the source loopback target meter/model gateway.
    """

    @property
    def implementation_path(self) -> Path: ...

    def validate_pre_draw(
        self,
        *,
        contract: FrozenKnownSiteContract,
        configuration: KnownSiteProductionConfiguration,
    ) -> None: ...

    def build_target_backend(
        self,
        *,
        contract: FrozenKnownSiteContract,
        configuration: KnownSiteProductionConfiguration,
        model_gateway: ComparisonModelGateway,
    ) -> KnownSiteTargetBackend: ...

    def planned_agent_vm(
        self,
        *,
        row_id: str,
        generation_id: str,
    ) -> PlannedAgentVm: ...

    def agent_tool_boundary(
        self,
        *,
        row_id: str,
        system: SystemId,
    ) -> AgentToolBoundary: ...


def build_production_configuration(
    document: Mapping[str, object],
) -> KnownSiteProductionConfiguration:
    """Build a complete frozen contract from one strict secret-free request."""

    if set(document) != _REQUEST_FIELDS or document.get("schema_version") != (
        PRODUCTION_REQUEST_SCHEMA
    ):
        raise KnownSiteProductionError("known-site production request fields are invalid")
    request = _json_round_trip(document)
    campaign_id = _text(request.get("campaign_id"), "campaign ID")
    canonical_campaign_directory = _absolute_path(
        request.get("canonical_campaign_directory"),
        "canonical campaign directory",
    )
    order_raw = _mapping(
        request.get("authenticated_order_source"),
        "authenticated order source",
    )
    if set(order_raw) != _ORDER_SOURCE_FIELDS:
        raise KnownSiteProductionError("authenticated order source fields are invalid")
    authenticated_order_source = AuthenticatedOrderSourceConfiguration(
        paired_campaign_directory=_absolute_path(
            order_raw.get("paired_campaign_directory"),
            "paired-XBEN campaign directory",
        ),
        pin=AuthenticatedArmOrderPin(
            paired_campaign_id=_text(
                order_raw.get("paired_campaign_id"),
                "paired-XBEN campaign ID",
            ),
            commitment_document_sha256=_digest(
                order_raw.get("commitment_document_sha256"),
                "paired-XBEN commitment document",
            ),
            preflight_document_sha256=_digest(
                order_raw.get("preflight_document_sha256"),
                "paired-XBEN preflight document",
            ),
            beacon_document_sha256=_digest(
                order_raw.get("beacon_document_sha256"),
                "paired-XBEN beacon document",
            ),
            selection_document_sha256=_digest(
                order_raw.get("selection_document_sha256"),
                "paired-XBEN selection document",
            ),
            draw_key_sha256=_digest(
                order_raw.get("draw_key_sha256"),
                "paired-XBEN draw key",
            ),
            website_content_sha256=_digest(
                order_raw.get("website_content_sha256"),
                "paired-XBEN website content",
            ),
            website_reference_sha256=_digest(
                order_raw.get("website_reference_sha256"),
                "paired-XBEN website reference",
            ),
        ),
    )

    site = _mapping(request.get("site_source"), "site source")
    if set(site) != {"origin_url", "repository", "commit", "tree", "relative_path"}:
        raise KnownSiteProductionError("known-site source fields are invalid")
    site_repository = _absolute_path(site.get("repository"), "site repository")
    source = SiteSourcePin(
        origin_url=_text(site.get("origin_url"), "site source origin"),
        commit=_git_object(site.get("commit"), "site source commit"),
        tree=_git_object(site.get("tree"), "site source tree"),
        relative_path=_text(site.get("relative_path"), "site relative path"),
    )

    raw_systems = _mapping(request.get("systems"), "system configurations")
    if set(raw_systems) != {"ravage", "strix"}:
        raise KnownSiteProductionError("known-site system set must be Ravage and Strix")
    system_pins: dict[SystemId, KnownSiteSystemPin] = {}
    runtime_configurations: dict[SystemId, SystemRuntimeConfiguration] = {}
    for system in _SYSTEMS:
        raw = _mapping(raw_systems.get(system), f"{system} configuration")
        if set(raw) != _SYSTEM_FIELDS:
            raise KnownSiteProductionError(f"{system} configuration fields are invalid")
        repository = _absolute_path(raw.get("repository"), f"{system} repository")
        runtime = PinnedAgentRuntime(
            executable=_absolute_path(raw.get("executable"), f"{system} executable"),
            executable_sha256=_digest(raw.get("executable_sha256"), f"{system} executable"),
            source_root=repository,
            source_commit=_git_object(raw.get("commit"), f"{system} commit"),
            source_tree=_git_object(raw.get("tree"), f"{system} tree"),
            source_origin_url=_text(raw.get("origin_url"), f"{system} origin"),
            runtime_environment_manifest=_absolute_path(
                raw.get("runtime_environment_manifest"),
                f"{system} runtime manifest",
            ),
            runtime_environment_manifest_sha256=_digest(
                raw.get("runtime_environment_manifest_sha256"),
                f"{system} runtime manifest",
            ),
        )
        roots = _path_tuple(raw.get("runtime_read_roots"), f"{system} runtime read roots")
        pin = KnownSiteSystemPin(
            origin_url=runtime.source_origin_url,
            commit=runtime.source_commit,
            tree=runtime.source_tree,
            runtime_manifest_sha256=runtime.runtime_environment_manifest_sha256,
            executable_sha256=runtime.executable_sha256,
            tool_image_reference=_text(raw.get("tool_image_reference"), f"{system} tool image"),
            tool_image_id=_text(raw.get("tool_image_id"), f"{system} tool image ID"),
            tool_image_archive_sha256=_digest(
                raw.get("tool_image_archive_sha256"),
                f"{system} tool image archive",
            ),
            platform=_text(raw.get("platform"), f"{system} platform"),
        )
        pin.to_json(system=system)
        system_pins[system] = pin
        runtime_configurations[system] = SystemRuntimeConfiguration(
            repository=repository,
            runtime=runtime,
            runtime_read_roots=roots,
            tool_image_archive=_absolute_path(
                raw.get("tool_image_archive"),
                f"{system} tool image archive",
            ),
        )

    model_policy = _model_policy(
        _mapping(request.get("model_gateway_policy"), "model gateway policy")
    )
    limits = _limits(_mapping(request.get("limits"), "known-site limits"))
    docker = _mapping(request.get("docker_separation"), "Docker separation")
    if set(docker) != {"target", "agent_vm"}:
        raise KnownSiteProductionError("Docker separation fields are invalid")
    target_docker = _docker_authority(
        _mapping(docker.get("target"), "target Docker authority"), label="target"
    )
    agent_vm = _agent_vm_configuration(
        _mapping(docker.get("agent_vm"), "agent VM configuration"),
        campaign_id=campaign_id,
    )
    separation = DockerSeparationPolicy(target=target_docker.pin, agent_vm=agent_vm.pin)
    if (
        source.commit != system_pins["ravage"].commit
        or source.origin_url != system_pins["ravage"].origin_url
    ):
        raise KnownSiteProductionError(
            "known-site source must use the exact frozen Ravage commit and origin"
        )

    execution = _mapping(request.get("execution"), "execution configuration")
    if set(execution) != _EXECUTION_FIELDS:
        raise KnownSiteProductionError("execution configuration fields are invalid")
    trusted_path = _trusted_path(execution.get("trusted_path"))
    sandbox_executable = _absolute_path(execution.get("sandbox_executable"), "sandbox executable")
    sandbox_digest = _digest(execution.get("sandbox_executable_sha256"), "sandbox executable")
    environment_name = _text(
        execution.get("upstream_api_key_environment"), "API-key environment name"
    )
    if _ENVIRONMENT_RE.fullmatch(environment_name) is None:
        raise KnownSiteProductionError("API-key environment name is invalid")

    provider_raw = _mapping(request.get("isolation_provider"), "isolation provider")
    if set(provider_raw) != _PROVIDER_FIELDS:
        raise KnownSiteProductionError("isolation provider fields are invalid")
    provider = IsolationProviderPin(
        name=_text(provider_raw.get("name"), "isolation provider name"),
        implementation_path=_absolute_path(
            provider_raw.get("implementation_path"), "isolation provider implementation"
        ),
        implementation_sha256=_digest(
            provider_raw.get("implementation_sha256"), "isolation provider implementation"
        ),
        target_meter_exposure=_text(
            provider_raw.get("target_meter_exposure"), "target meter exposure"
        ),
        agent_visible_target_path=_text(
            provider_raw.get("agent_visible_target_path"), "agent-visible target path"
        ),
    )
    if (
        _SAFE_PROVIDER_RE.fullmatch(provider.name) is None
        or provider.target_meter_exposure != "target-host-loopback-only"
        or provider.agent_visible_target_path != "independently-enforced-metered-relay"
    ):
        raise KnownSiteProductionError("isolation provider policy is not fail-closed")

    adapter_path = Path(str(comparison_adapters_module.__file__)).resolve(strict=True)
    contract = FrozenKnownSiteContract(
        campaign_id=campaign_id,
        campaign_directory_sha256=_text_digest(
            canonical_campaign_directory.resolve(strict=False).as_posix()
        ),
        source=source,
        model_gateway_policy=model_policy.to_json(),
        model_gateway_policy_sha256=_json_digest(model_policy.to_json()),
        limits=limits,
        target_runtime=_mapping(request.get("target_runtime"), "target runtime"),
        system_pins=system_pins,
        adapter_source_sha256=_file_digest(adapter_path),
        docker_separation=separation,
        authenticated_arm_order=authenticated_order_source.pin,
    )
    contract.to_document()
    return KnownSiteProductionConfiguration(
        request_document=request,
        contract=contract,
        canonical_campaign_directory=canonical_campaign_directory,
        site_repository=site_repository,
        systems=runtime_configurations,
        target_docker=target_docker,
        agent_vm=agent_vm,
        trusted_path=trusted_path,
        sandbox_executable=sandbox_executable,
        sandbox_executable_sha256=sandbox_digest,
        upstream_api_key_environment=environment_name,
        isolation_provider=provider,
        authenticated_order_source=authenticated_order_source,
    )


def prepare_from_config(
    config_path: Path,
    output_dir: Path,
    *,
    isolation_provider: KnownSiteIsolationProvider | None = None,
    captured_at: str | None = None,
) -> tuple[dict[str, object], Path]:
    """Create one retained, no-live-action production preparation."""

    raw = _read_regular(config_path, "production request", _MAX_JSON_BYTES)
    request = _decode_json(raw, "production request")
    configuration = build_production_configuration(request)
    root = _claim_directory(output_dir)
    _write_exclusive(root / REQUEST_FILE, _canonical_json(configuration.request_document) + b"\n")
    contract_document = configuration.contract.to_document()
    _write_exclusive(root / DRAFT_CONTRACT_FILE, _canonical_json(contract_document) + b"\n")

    checks: dict[str, object] = {}
    blockers: list[str] = []
    try:
        _require_independently_trusted_order_verifier()
        checks.update(_validate_authenticated_order_source(configuration))
    except Exception as exc:  # noqa: BLE001 - retain a bounded blocked preparation.
        blockers.append("authenticated_external_order_source_unready")
        checks["authenticated_order_source"] = {
            "ready": False,
            "error": _safe_error(exc),
        }
    try:
        checks.update(_validate_configuration_pre_draw(configuration))
    except Exception as exc:  # noqa: BLE001 - retain a bounded blocked preparation.
        blockers.append("local_identity_or_package_runtime_unready")
        checks["local_pre_draw"] = {"ready": False, "error": _safe_error(exc)}
    if isolation_provider is None:
        blockers.append("dual_daemon_metered_relay_provider_unavailable")
        checks["isolation_provider"] = {
            "ready": False,
            "error": "reviewed isolation provider was not injected",
        }
    else:
        try:
            _validate_provider_identity(configuration, isolation_provider)
            isolation_provider.validate_pre_draw(
                contract=configuration.contract,
                configuration=configuration,
            )
            _validate_provider_plans(configuration, isolation_provider)
            checks["isolation_provider"] = {
                "ready": True,
                "implementation_sha256": configuration.isolation_provider.implementation_sha256,
                "no_target_or_agent_resource_created": True,
            }
        except Exception as exc:  # noqa: BLE001 - preparation stays visibly blocked.
            blockers.append("dual_daemon_metered_relay_provider_unready")
            checks["isolation_provider"] = {"ready": False, "error": _safe_error(exc)}

    # The retained paired-XBEN commitment/resolution must be copied into the
    # eventual one-shot campaign and reverified from those copied bytes before
    # website flag entropy is sampled.  That create-only handoff is not yet a
    # reviewed provider surface, so an otherwise valid source must not arm an
    # executor configuration.
    blockers.append("authenticated_order_source_retention_bridge_unavailable")
    checks["authenticated_order_retention"] = {
        "ready": False,
        "error": (
            "create-only paired-XBEN commitment/resolution retention and offline "
            "reverification bridge is not integrated"
        ),
    }

    ready = not blockers
    executor_document = _document(
        {
            "schema_version": EXECUTOR_CONFIGURATION_SCHEMA,
            "classification": KNOWN_SITE_CLASSIFICATION,
            "claim_boundary": KNOWN_SITE_CLAIM_BOUNDARY,
            "eligible_for_sota_claim": False,
            "eligible_for_unseen_claim": False,
            "contract_sha256": contract_document["document_sha256"],
            "request_sha256": _json_digest(configuration.request_document),
            "contract": contract_document,
            "request": configuration.request_document,
        }
    )
    if ready:
        _write_exclusive(root / RUN_CONTRACT_FILE, _canonical_json(contract_document) + b"\n")
        _write_exclusive(
            root / EXECUTOR_CONFIGURATION_FILE,
            _canonical_json(executor_document) + b"\n",
        )
    preparation = _document(
        {
            "schema_version": PRODUCTION_PREPARATION_SCHEMA,
            "captured_at": _timestamp(captured_at),
            "classification": KNOWN_SITE_CLASSIFICATION,
            "claim_boundary": KNOWN_SITE_CLAIM_BOUNDARY,
            "eligible_for_sota_claim": False,
            "eligible_for_unseen_claim": False,
            "ready": ready,
            "block_reasons": sorted(set(blockers)),
            "checks": checks,
            "contract_sha256": contract_document["document_sha256"],
            "request_sha256": _json_digest(configuration.request_document),
            "emitted": {
                "draft_contract": True,
                "run_contract": ready,
                "executor_configuration": ready,
            },
            "no_live_actions": {
                "randomness_or_entropy_request_performed": False,
                "model_gateway_started": False,
                "model_call_performed": False,
                "docker_build_performed": False,
                "docker_pull_performed": False,
                "target_started": False,
                "agent_started": False,
            },
        }
    )
    _write_exclusive(root / PREPARATION_FILE, _canonical_json(preparation) + b"\n")
    status = _status_markdown(preparation)
    _write_exclusive(root / STATUS_FILE, status.encode("utf-8"))
    manifest = _artifact_manifest(root)
    _write_exclusive(root / HASH_MANIFEST_FILE, manifest.encode("ascii"))
    return preparation, root / PREPARATION_FILE


def execute_from_config(
    campaign_dir: Path,
    *,
    executor_config_path: Path,
    isolation_provider: KnownSiteIsolationProvider | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Assemble and execute one campaign, with no permissive isolation fallback."""

    executor = _decode_json(
        _read_regular(executor_config_path, "executor configuration", _MAX_JSON_BYTES),
        "executor configuration",
    )
    expected_executor_fields = {
        "schema_version",
        "classification",
        "claim_boundary",
        "eligible_for_sota_claim",
        "eligible_for_unseen_claim",
        "contract_sha256",
        "request_sha256",
        "contract",
        "request",
        "document_sha256",
    }
    if (
        set(executor) != expected_executor_fields
        or executor.get("schema_version") != EXECUTOR_CONFIGURATION_SCHEMA
        or executor.get("classification") != KNOWN_SITE_CLASSIFICATION
        or executor.get("claim_boundary") != KNOWN_SITE_CLAIM_BOUNDARY
        or executor.get("eligible_for_sota_claim") is not False
        or executor.get("eligible_for_unseen_claim") is not False
        or executor.get("document_sha256")
        != _json_digest({key: value for key, value in executor.items() if key != "document_sha256"})
    ):
        raise KnownSiteProductionError("known-site executor configuration is invalid")
    configuration = build_production_configuration(
        _mapping(executor.get("request"), "executor production request")
    )
    contract_document = configuration.contract.to_document()
    if (
        _mapping(executor.get("contract"), "executor run contract") != contract_document
        or executor.get("contract_sha256") != contract_document["document_sha256"]
        or executor.get("request_sha256") != _json_digest(configuration.request_document)
    ):
        raise KnownSiteProductionError("executor contract does not recompute from its request")
    requested_campaign = campaign_dir.expanduser()
    if not requested_campaign.is_absolute():
        raise KnownSiteProductionError("known-site campaign directory must be absolute")
    if requested_campaign.resolve(strict=False) != (
        configuration.canonical_campaign_directory.resolve(strict=False)
    ):
        raise KnownSiteProductionError(
            "campaign directory differs from the canonical path frozen in the request"
        )
    if campaign_dir.expanduser().exists() or campaign_dir.expanduser().is_symlink():
        raise KnownSiteProductionError(
            "known-site campaign is already claimed; resume and replacement are forbidden"
        )
    # Never execute drandverify/cosign copied from the configured paired-XBEN
    # campaign.  Their hashes are campaign inputs, not an evaluator-owned trust
    # root, so reaching verify_campaign here would run operator-selected code
    # before the intentional production block (and before credential access).
    _require_independently_trusted_order_verifier()
    _validate_authenticated_order_source(configuration)
    _validate_configuration_pre_draw(configuration)
    if isolation_provider is None:
        raise KnownSiteProductionError(
            "reviewed dual-daemon metered relay provider is unavailable; refusing execution"
        )
    _validate_provider_identity(configuration, isolation_provider)
    isolation_provider.validate_pre_draw(
        contract=configuration.contract,
        configuration=configuration,
    )
    _validate_provider_plans(configuration, isolation_provider)
    # Provider validation happens before even reading the paid credential.  A
    # missing relay therefore cannot consume flags, create a campaign, or make
    # any model/target action observable.
    source_environment = os.environ if environment is None else environment
    upstream_api_key = source_environment.get(configuration.upstream_api_key_environment, "")
    if not upstream_api_key or len(upstream_api_key) > 10_000:
        raise KnownSiteProductionError("upstream API credential is absent or invalid")
    gateway = ComparisonModelGateway(
        policy=_model_policy(configuration.contract.model_gateway_policy),
        upstream_api_key=upstream_api_key,
    )
    target_backend = isolation_provider.build_target_backend(
        contract=configuration.contract,
        configuration=configuration,
        model_gateway=gateway,
    )
    agent_backend = _agent_backend(
        configuration=configuration,
        gateway=gateway,
        isolation_provider=isolation_provider,
    )
    return execute_known_site_regression(
        campaign_dir,
        contract=configuration.contract,
        gateway=gateway,
        target_backend=target_backend,
        agent_backend=agent_backend,
    )


def _agent_backend(
    *,
    configuration: KnownSiteProductionConfiguration,
    gateway: ComparisonModelGateway,
    isolation_provider: KnownSiteIsolationProvider,
) -> CanonicalKnownSiteAgentBackend:
    policy = _model_policy(configuration.contract.model_gateway_policy)
    pricing = GatewayPricing(
        input_per_million=str(policy.pricing.input_per_million),
        cached_input_per_million=str(policy.pricing.cached_input_per_million),
        output_per_million=str(policy.pricing.output_per_million),
    )
    boundaries: dict[str, AgentToolBoundary] = {}
    observed_daemon_identities: set[str] = set()

    def boundary(context: AgentArmContext) -> AgentToolBoundary:
        existing = boundaries.get(context.row_id)
        if existing is not None:
            return existing
        value = isolation_provider.agent_tool_boundary(
            row_id=context.row_id,
            system=context.system,
        )
        _validate_agent_boundary(configuration, context=context, boundary=value)
        if value.daemon_identity_sha256 in observed_daemon_identities:
            raise KnownSiteProductionError("agent Docker daemon identity was reused across rows")
        observed_daemon_identities.add(value.daemon_identity_sha256)
        boundaries[context.row_id] = value
        return value

    def row_gateway(context: AgentArmContext) -> RowModelGateway:
        daemon = boundary(context)
        return RowModelGateway(
            base_url=daemon.agent_visible_model_gateway_url,
            token=context.gateway_token,
            model=policy.model,
            reasoning_effort=policy.reasoning_effort,
            pricing=pricing,
            max_output_tokens=policy.max_completion_tokens_per_request,
        )

    def ravage_factory(context: AgentArmContext) -> ExternalAgentCommand:
        daemon = boundary(context)
        return build_ravage_agent(
            runtime=configuration.systems["ravage"].runtime,
            gateway=row_gateway(context),
            limits=context.limits,
            trusted_path=configuration.trusted_path,
            tool_image=configuration.contract.system_pins["ravage"].tool_image_reference,
            docker_host=daemon.docker_host,
        )

    def strix_factory(context: AgentArmContext) -> ExternalAgentCommand:
        daemon = boundary(context)
        return build_strix_agent(
            runtime=configuration.systems["strix"].runtime,
            gateway=row_gateway(context),
            limits=context.limits,
            trusted_path=configuration.trusted_path,
            sandbox_image=configuration.contract.system_pins["strix"].tool_image_reference,
            sandbox_network=daemon.agent_network,
            docker_host=daemon.docker_host,
        )

    def process_factory(
        context: AgentArmContext,
        agent: ExternalAgentCommand,
    ) -> ExternalProcessBackend:
        del agent
        daemon = boundary(context)
        return cast(
            "ExternalProcessBackend",
            ComparisonProcessBackend(
                gateway=gateway,
                row_id=context.row_id,
                expected_policy_sha256=context.gateway_policy_sha256,
                expected_row_token_sha256=_text_digest(context.gateway_token),
                sandbox_exec_sha256=configuration.sandbox_executable_sha256,
                runtime_read_roots=configuration.systems[context.system].runtime_read_roots,
                evidence_class=PAIRED_LOCAL,
                allow_docker_socket=True,
                sandbox_exec_path=configuration.sandbox_executable,
                docker_socket_path=daemon.docker_socket_path,
            ),
        )

    forbidden = tuple(
        path
        for path in (
            configuration.site_repository / KNOWN_SITE_SOURCE_PATH,
            configuration.systems["ravage"].repository / KNOWN_SITE_SOURCE_PATH,
        )
        if path.is_dir()
    )
    if not forbidden:
        # Static validation normally catches this first.  Retain the invariant
        # here so injected tests or future callers cannot omit the exclusion.
        raise KnownSiteProductionError("known-site source path is unavailable")
    return CanonicalKnownSiteAgentBackend(
        agent_factories={"ravage": ravage_factory, "strix": strix_factory},
        process_factory=process_factory,
        forbidden_target_source_paths=forbidden,
        pre_draw_validator=lambda contract: _validate_agent_pre_draw(
            configuration,
            contract=contract,
        ),
    )


def _validate_configuration_pre_draw(
    configuration: KnownSiteProductionConfiguration,
) -> dict[str, object]:
    """Revalidate all mutable local inputs without live Docker/model actions."""

    contract = configuration.contract
    contract.to_document()
    site_path = configuration.site_repository / KNOWN_SITE_SOURCE_PATH
    _validate_git_source(
        configuration.site_repository,
        expected_origin=contract.source.origin_url,
        expected_commit=contract.source.commit,
        expected_tree=contract.system_pins["ravage"].tree,
        label="site",
    )
    observed_site_tree = _git(
        configuration.site_repository,
        ("rev-parse", f"{contract.source.commit}:{KNOWN_SITE_SOURCE_PATH}"),
        trusted_path=configuration.trusted_path,
    )
    if observed_site_tree != contract.source.tree:
        raise KnownSiteProductionError("known-site subtree differs from its frozen tree")
    _validate_target_source_files(configuration, site_path=site_path)
    _validate_agent_pre_draw(configuration, contract=contract)
    _validate_docker_authority(configuration.target_docker, label="target")
    _validate_agent_vm_material(configuration)
    sandbox = _regular_executable(
        configuration.sandbox_executable,
        "sandbox executable",
    )
    if _file_digest(sandbox) != configuration.sandbox_executable_sha256:
        raise KnownSiteProductionError("sandbox executable differs from its frozen digest")
    provider_path = _regular_file(
        configuration.isolation_provider.implementation_path,
        "isolation provider implementation",
    )
    if _file_digest(provider_path) != configuration.isolation_provider.implementation_sha256:
        raise KnownSiteProductionError("isolation provider implementation differs from its pin")
    components = _validate_evaluator_sources(configuration, provider_path=provider_path)
    return {
        "local_pre_draw": {
            "ready": True,
            "site_source_clean_and_pinned": True,
            "package_only_noneditable_runtimes": True,
            "target_source_and_git_objects_excluded": True,
            "target_and_ephemeral_agent_authorities_precommitted": True,
            "sandbox_executable_pinned": True,
            "isolation_implementation_pinned": True,
            "evaluator_source_count": len(components),
            "evaluator_source_sha256": components,
        }
    }


def _validate_authenticated_order_source(
    configuration: KnownSiteProductionConfiguration,
) -> dict[str, object]:
    """Reverify the paired-XBEN future beacon and its frozen website inputs."""

    source = configuration.authenticated_order_source
    try:
        root = source.paired_campaign_directory.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise KnownSiteProductionError(
            "authenticated paired-XBEN campaign must be a real resolved directory"
        ) from exc
    if not root.is_dir() or root.is_symlink():
        raise KnownSiteProductionError(
            "authenticated paired-XBEN campaign must be a real resolved directory"
        )
    verification = paired_xben_protocol_module.verify_campaign(
        root,
        require_all_primary_attempts=False,
    )
    pin = source.pin
    expected_verification = {
        "phase": "resolved",
        "structurally_valid": True,
        "beacon_authenticity_verified": True,
        "publication_anchor_verified": True,
        "campaign_id": pin.paired_campaign_id,
        "commitment_digest": pin.commitment_document_sha256,
        "preflight_digest": pin.preflight_document_sha256,
        "beacon_digest": pin.beacon_document_sha256,
        "selection_digest": pin.selection_document_sha256,
    }
    if any(verification.get(name) != value for name, value in expected_verification.items()):
        raise KnownSiteProductionError(
            "paired-XBEN verification differs from the frozen authenticated order source"
        )

    commitment = _decode_json(
        _read_regular(
            root / paired_xben_protocol_module.COMMITMENT_FILE,
            "paired-XBEN commitment",
            _MAX_JSON_BYTES,
        ),
        "paired-XBEN commitment",
    )
    preflight = _decode_json(
        _read_regular(
            root / paired_xben_protocol_module.PREFLIGHT_SOURCE_FILE,
            "paired-XBEN preflight",
            _MAX_JSON_BYTES,
        ),
        "paired-XBEN preflight",
    )
    selection = _decode_json(
        _read_regular(
            root
            / paired_xben_protocol_module.RESOLUTION_DIRECTORY
            / paired_xben_protocol_module.SELECTION_FILE,
            "paired-XBEN selection",
            _MAX_JSON_BYTES,
        ),
        "paired-XBEN selection",
    )
    if selection.get("draw_key_sha256") != pin.draw_key_sha256:
        raise KnownSiteProductionError(
            "paired-XBEN beacon-derived draw key differs from its website pin"
        )

    contract = configuration.contract
    paired_contract = _mapping(commitment.get("run_contract"), "paired-XBEN run contract")
    try:
        known_site_harness_module._validate_precommitted_order_identity_inputs(
            paired_contract=paired_contract,
            paired_preflight=preflight,
            known_contract=contract.to_document(),
        )
    except EvidenceValidationError as exc:
        raise KnownSiteProductionError(
            "paired-XBEN commitment does not bind the complete website order identity"
        ) from exc
    observed_content, _count, _size = paired_xben_prepare_module._tree_digest(
        configuration.site_repository / KNOWN_SITE_SOURCE_PATH
    )
    if observed_content != pin.website_content_sha256:
        raise KnownSiteProductionError(
            "local website content differs from the paired-XBEN pre-draw reference"
        )
    return {
        "authenticated_order_source": {
            "ready": True,
            "paired_campaign_id": pin.paired_campaign_id,
            "commitment_document_sha256": pin.commitment_document_sha256,
            "beacon_document_sha256": pin.beacon_document_sha256,
            "selection_document_sha256": pin.selection_document_sha256,
            "draw_key_sha256": pin.draw_key_sha256,
            "website_identity_sha256": contract.website_order_identity_sha256,
            "derived_arm_order": list(contract.arm_order),
            "offline_cryptographic_reverification": True,
        }
    }


def _require_independently_trusted_order_verifier() -> None:
    """Block before campaign-retained verifier executables can be invoked."""

    raise KnownSiteProductionError(
        "independently trusted paired-XBEN verifier inputs are unavailable; "
        "configured campaign verifier binaries were not executed"
    )


def _validate_evaluator_sources(
    configuration: KnownSiteProductionConfiguration,
    *,
    provider_path: Path,
) -> dict[str, str]:
    """Bind every live coordinator component to the clean Ravage commit."""

    repository = configuration.site_repository.expanduser().resolve(strict=True)
    loaded = {
        "packages/ravage/src/ravage/xben_parts/comparison_adapters.py": Path(
            str(comparison_adapters_module.__file__)
        ),
        "packages/ravage/src/ravage/xben_parts/comparison_agent_vm.py": Path(
            str(comparison_agent_vm_module.__file__)
        ),
        "packages/ravage/src/ravage/xben_parts/comparison_model_gateway.py": Path(
            str(comparison_model_gateway_module.__file__)
        ),
        "packages/ravage/src/ravage/xben_parts/comparison_process_backend.py": Path(
            str(comparison_process_backend_module.__file__)
        ),
        "packages/ravage/src/ravage/xben_parts/external_comparison.py": Path(
            str(external_comparison_module.__file__)
        ),
        "packages/ravage/src/ravage/xben_parts/http_meter_gateway.py": Path(
            str(http_meter_gateway_module.__file__)
        ),
        "tools/known_site_regression/agent_backend.py": Path(
            str(known_site_agent_backend_module.__file__)
        ),
        "tools/known_site_regression/docker_target.py": Path(
            str(known_site_docker_target_module.__file__)
        ),
        "tools/known_site_regression/harness.py": Path(str(known_site_harness_module.__file__)),
        "tools/known_site_regression/production.py": Path(__file__),
    }
    result: dict[str, str] = {}
    for relative, observed in sorted(loaded.items()):
        expected = (repository / relative).resolve(strict=True)
        if observed.resolve(strict=True) != expected:
            raise KnownSiteProductionError(
                f"live evaluator component is outside the frozen source: {relative}"
            )
        _git(repository, ("ls-files", "--error-unmatch", relative))
        result[relative] = _file_digest(_regular_file(expected, relative))
    try:
        provider_relative = provider_path.relative_to(repository).as_posix()
    except ValueError as exc:
        raise KnownSiteProductionError(
            "isolation provider implementation is outside the frozen Ravage source"
        ) from exc
    _git(repository, ("ls-files", "--error-unmatch", provider_relative))
    result[provider_relative] = _file_digest(provider_path)
    return dict(sorted(result.items()))


def _validate_agent_pre_draw(
    configuration: KnownSiteProductionConfiguration,
    *,
    contract: object,
) -> None:
    if (
        contract is not configuration.contract
        and getattr(contract, "to_document", lambda: None)() != configuration.contract.to_document()
    ):
        raise KnownSiteProductionError("agent pre-draw contract differs from its configuration")
    forbidden: list[Path] = [configuration.site_repository / KNOWN_SITE_SOURCE_PATH]
    for system, runtime_configuration in configuration.systems.items():
        pin = configuration.contract.system_pins[system]
        _validate_git_source(
            runtime_configuration.repository,
            expected_origin=pin.origin_url,
            expected_commit=pin.commit,
            expected_tree=pin.tree,
            label=f"{system} runtime source",
        )
        verify_pinned_runtime(
            runtime_configuration.runtime,
            trusted_path=configuration.trusted_path,
        )
        manifest = _decode_json(
            _read_regular(
                runtime_configuration.runtime.runtime_environment_manifest,
                f"{system} runtime manifest",
                _MAX_JSON_BYTES,
            ),
            f"{system} runtime manifest",
        )
        editable = manifest.get("editable_source_roots")
        if editable != []:
            raise KnownSiteProductionError(
                f"{system} runtime is editable; a package-only runtime is required"
            )
        sibling_site = runtime_configuration.repository / KNOWN_SITE_SOURCE_PATH
        if sibling_site.is_dir():
            forbidden.append(sibling_site)
        _validate_forbidden_source_separation(
            runtime_configuration.runtime_read_roots,
            forbidden_paths=tuple(forbidden),
        )


def _validate_target_source_files(
    configuration: KnownSiteProductionConfiguration,
    *,
    site_path: Path,
) -> None:
    runtime = configuration.contract.target_runtime
    lock = _mapping(runtime.get("dependency_lock"), "dependency lock")
    proxy = _mapping(runtime.get("proxy_configuration"), "proxy configuration")
    checks = (
        (
            site_path / "web" / "package-lock.json",
            _text(lock.get("sha256"), "dependency lock digest"),
            "dependency lock",
        ),
        (
            site_path / "web" / "package.json",
            _text(lock.get("package_json_sha256"), "package manifest digest"),
            "package manifest",
        ),
        (
            site_path / "proxy" / "nginx.conf",
            _text(proxy.get("sha256"), "proxy configuration digest"),
            "proxy configuration",
        ),
    )
    for path, expected, label in checks:
        if _file_digest(_regular_file(path, label)) != expected:
            raise KnownSiteProductionError(f"{label} differs from its frozen digest")


def _validate_provider_identity(
    configuration: KnownSiteProductionConfiguration,
    provider: KnownSiteIsolationProvider,
) -> None:
    try:
        path = provider.implementation_path.expanduser().resolve(strict=True)
    except (AttributeError, OSError, RuntimeError) as exc:
        raise KnownSiteProductionError(
            "isolation provider has no canonical implementation"
        ) from exc
    expected = configuration.isolation_provider.implementation_path.expanduser().resolve(
        strict=True
    )
    if (
        path != expected
        or _file_digest(path) != configuration.isolation_provider.implementation_sha256
    ):
        raise KnownSiteProductionError("injected isolation provider differs from its frozen pin")


def _validate_provider_plans(
    configuration: KnownSiteProductionConfiguration,
    provider: KnownSiteIsolationProvider,
) -> None:
    """Require the injected controller to reproduce both frozen plans without I/O."""

    for row_id in ROW_IDS:
        expected = configuration.agent_vm.plans[row_id]
        try:
            observed = provider.planned_agent_vm(
                row_id=row_id,
                generation_id=expected.generation_id,
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise KnownSiteProductionError(
                "isolation provider cannot reproduce the frozen agent VM plans"
            ) from exc
        if observed != expected:
            raise KnownSiteProductionError(
                f"isolation provider plan differs from frozen row {row_id}"
            )


def _validate_agent_boundary(
    configuration: KnownSiteProductionConfiguration,
    *,
    context: AgentArmContext,
    boundary: AgentToolBoundary,
) -> None:
    socket_path = boundary.docker_socket_path.expanduser().resolve(strict=True)
    try:
        planned = configuration.agent_vm.plans[context.row_id]
    except KeyError as exc:
        raise KnownSiteProductionError("agent VM boundary has no precommitted row plan") from exc
    configured = planned.docker_socket.expanduser().resolve(strict=True)
    if not stat.S_ISSOCK(socket_path.stat().st_mode):
        raise KnownSiteProductionError("agent-tool Docker endpoint is not a Unix socket")
    if (
        socket_path != configured
        or boundary.docker_host != planned.docker_host
        or boundary.generation_id != planned.generation_id
        or boundary.profile_name != planned.profile_name
        or boundary.agent_network != planned.agent_network
        or context.agent_daemon_identity_sha256 is None
        or boundary.daemon_identity_sha256 != context.agent_daemon_identity_sha256
        or boundary.daemon_identity_sha256 == configuration.target_docker.pin.daemon_identity_sha256
    ):
        raise KnownSiteProductionError("live agent-tool boundary differs from its contract")
    if context.target_url != boundary.agent_visible_target_url:
        raise KnownSiteProductionError("agent-visible target relay differs from its live arm")
    _validated_http_endpoint(
        boundary.agent_visible_target_url,
        "agent-visible target relay",
    )
    _validated_http_endpoint(
        boundary.agent_visible_model_gateway_url,
        "agent-visible model relay",
    )
    if (
        context.agent_visible_model_gateway_url_sha256 is None
        or _text_digest(boundary.agent_visible_model_gateway_url)
        != context.agent_visible_model_gateway_url_sha256
    ):
        raise KnownSiteProductionError("agent-visible model relay differs from its arm receipt")
    if _SHA256_RE.fullmatch(boundary.daemon_identity_sha256) is None:
        raise KnownSiteProductionError("live agent Docker daemon identity is invalid")
    if _NETWORK_RE.fullmatch(boundary.agent_network) is None:
        raise KnownSiteProductionError("agent-tool network is invalid")


def _validate_git_source(
    repository: Path,
    *,
    expected_origin: str,
    expected_commit: str,
    expected_tree: str,
    label: str,
) -> None:
    root = repository.expanduser().resolve(strict=True)
    if _git(root, ("rev-parse", "--show-toplevel")) != str(root):
        raise KnownSiteProductionError(f"{label} repository is not an exact Git toplevel")
    if _git(root, ("rev-parse", "--verify", "HEAD")) != expected_commit:
        raise KnownSiteProductionError(f"{label} HEAD differs from its frozen commit")
    if _git(root, ("rev-parse", "--verify", "HEAD^{tree}")) != expected_tree:
        raise KnownSiteProductionError(f"{label} tree differs from its frozen tree")
    origin = _git(root, ("remote", "get-url", "origin"))
    if origin.rstrip("/").removesuffix(".git") != expected_origin.rstrip("/").removesuffix(".git"):
        raise KnownSiteProductionError(f"{label} origin differs from its frozen origin")
    if _git(root, ("status", "--porcelain=v1", "--untracked-files=all")):
        raise KnownSiteProductionError(f"{label} source worktree is dirty")


def _docker_authority(
    value: Mapping[str, object],
    *,
    label: str,
) -> DockerAuthorityConfiguration:
    if set(value) != _DAEMON_FIELDS:
        raise KnownSiteProductionError(f"{label} Docker authority fields are invalid")
    executable = _absolute_path(value.get("docker_executable"), f"{label} Docker executable")
    socket_path = _absolute_path(value.get("docker_socket_path"), f"{label} Docker socket")
    docker_host = _text(value.get("docker_host"), f"{label} Docker host")
    if docker_host != f"unix://{socket_path.as_posix()}":
        raise KnownSiteProductionError(f"{label} Docker host must bind its exact Unix socket")
    pin = DockerDaemonPin(
        docker_executable_sha256=_digest(
            value.get("docker_executable_sha256"), f"{label} Docker executable"
        ),
        docker_socket_path_sha256=_digest(
            value.get("docker_socket_path_sha256"), f"{label} Docker socket path"
        ),
        docker_host_sha256=_digest(value.get("docker_host_sha256"), f"{label} Docker host"),
        daemon_identity_sha256=_digest(
            value.get("daemon_identity_sha256"), f"{label} Docker daemon identity"
        ),
    )
    if pin.docker_socket_path_sha256 != _text_digest(
        socket_path.as_posix()
    ) or pin.docker_host_sha256 != _text_digest(docker_host):
        raise KnownSiteProductionError(f"{label} Docker endpoint text differs from its pin")
    pin.to_json()
    return DockerAuthorityConfiguration(
        docker_executable=executable,
        docker_socket_path=socket_path,
        docker_host=docker_host,
        pin=pin,
    )


def _agent_vm_configuration(
    value: Mapping[str, object],
    *,
    campaign_id: str,
) -> AgentVmProductionConfiguration:
    if set(value) != _AGENT_VM_FIELDS:
        raise KnownSiteProductionError("agent VM configuration fields are invalid")
    docker_executable = _absolute_path(
        value.get("docker_executable"),
        "agent VM Docker executable",
    )
    controller_implementation = _absolute_path(
        value.get("controller_implementation"),
        "agent VM controller implementation",
    )
    controller_policy_path = _absolute_path(
        value.get("controller_policy"),
        "agent VM controller policy",
    )
    supervisor_executable = _absolute_path(
        value.get("supervisor_executable"),
        "agent VM supervisor executable",
    )
    supervisor_runtime_manifest = _absolute_path(
        value.get("supervisor_runtime_manifest"),
        "agent VM supervisor runtime manifest",
    )
    vm_template = _absolute_path(value.get("vm_template"), "agent VM template")
    base_image = _absolute_path(value.get("base_image"), "agent VM base image")
    relay_implementation = _absolute_path(
        value.get("relay_implementation"),
        "agent VM relay implementation",
    )
    relay_policy_path = _absolute_path(value.get("relay_policy"), "agent VM relay policy")
    controller_policy = _digest(
        value.get("controller_policy_sha256"),
        "agent VM controller policy",
    )
    vm_template_digest = _digest(value.get("vm_template_sha256"), "agent VM template")
    base_image_digest = _digest(value.get("base_image_sha256"), "agent VM base image")
    relay_policy = _digest(value.get("relay_policy_sha256"), "agent VM relay policy")
    raw_plans = _mapping(value.get("plans"), "agent VM row plans")
    if set(raw_plans) != set(ROW_IDS):
        raise KnownSiteProductionError("agent VM plans must cover exactly both primary rows")
    plans: dict[str, PlannedAgentVm] = {}
    pins: dict[str, AgentVmPlanPin] = {}
    for row_id in ROW_IDS:
        raw = _mapping(raw_plans.get(row_id), f"{row_id} agent VM plan")
        if set(raw) != _AGENT_VM_PLAN_FIELDS:
            raise KnownSiteProductionError(f"{row_id} agent VM plan fields are invalid")
        socket = _absolute_path(raw.get("docker_socket_path"), f"{row_id} Docker socket")
        host = _text(raw.get("docker_host"), f"{row_id} Docker host")
        if host != f"unix://{socket.as_posix()}":
            raise KnownSiteProductionError(f"{row_id} Docker host differs from its socket")
        socket_digest = _digest(
            raw.get("docker_socket_path_sha256"),
            f"{row_id} Docker socket path",
        )
        host_digest = _digest(raw.get("docker_host_sha256"), f"{row_id} Docker host")
        if socket_digest != _text_digest(socket.as_posix()) or host_digest != _text_digest(host):
            raise KnownSiteProductionError(f"{row_id} Docker endpoint text differs from its pin")
        generation_id = derive_agent_vm_generation_id(
            campaign_id=campaign_id,
            row_id=row_id,
            controller_policy_sha256=controller_policy,
            vm_template_sha256=vm_template_digest,
            base_image_sha256=base_image_digest,
            relay_policy_sha256=relay_policy,
        )
        profile = f"ravage-agent-{row_id}-{generation_id[:16]}"
        network = f"ravage-agent-net-{row_id}-{generation_id[:16]}"
        plans[row_id] = PlannedAgentVm(
            row_id=row_id,
            profile_name=profile,
            generation_id=generation_id,
            docker_host=host,
            docker_socket=socket,
            agent_network=network,
        )
        pins[row_id] = AgentVmPlanPin(
            generation_id=generation_id,
            profile_name=profile,
            docker_socket_path_sha256=socket_digest,
            docker_host_sha256=host_digest,
            agent_network=network,
        )
    pin = AgentVmPolicyPin(
        docker_executable_sha256=_digest(
            value.get("docker_executable_sha256"),
            "agent VM Docker executable",
        ),
        controller_kind=_text(value.get("controller_kind"), "agent VM controller kind"),
        controller_implementation_sha256=_digest(
            value.get("controller_implementation_sha256"),
            "agent VM controller implementation",
        ),
        controller_policy_sha256=controller_policy,
        supervisor_executable_sha256=_digest(
            value.get("supervisor_executable_sha256"),
            "agent VM supervisor executable",
        ),
        supervisor_runtime_manifest_sha256=_digest(
            value.get("supervisor_runtime_manifest_sha256"),
            "agent VM supervisor runtime manifest",
        ),
        vm_template_sha256=vm_template_digest,
        base_image_sha256=base_image_digest,
        relay_implementation_sha256=_digest(
            value.get("relay_implementation_sha256"),
            "agent VM relay implementation",
        ),
        relay_policy_sha256=relay_policy,
        relay_enforcement_kind=_text(
            value.get("relay_enforcement_kind"),
            "agent VM relay enforcement kind",
        ),
        plans=pins,
    )
    pin.to_json(campaign_id=campaign_id)
    return AgentVmProductionConfiguration(
        docker_executable=docker_executable,
        controller_implementation=controller_implementation,
        controller_policy=controller_policy_path,
        supervisor_executable=supervisor_executable,
        supervisor_runtime_manifest=supervisor_runtime_manifest,
        vm_template=vm_template,
        base_image=base_image,
        relay_implementation=relay_implementation,
        relay_policy=relay_policy_path,
        plans=plans,
        pin=pin,
    )


def _validate_docker_authority(
    authority: DockerAuthorityConfiguration,
    *,
    label: str,
) -> None:
    executable = _regular_executable(authority.docker_executable, f"{label} Docker executable")
    if _file_digest(executable) != authority.pin.docker_executable_sha256:
        raise KnownSiteProductionError(f"{label} Docker executable differs from its pin")
    socket_path = authority.docker_socket_path.expanduser().resolve(strict=True)
    if not stat.S_ISSOCK(socket_path.stat().st_mode):
        raise KnownSiteProductionError(f"{label} Docker endpoint is not a Unix socket")


def _validate_agent_vm_material(configuration: KnownSiteProductionConfiguration) -> None:
    """Rehash immutable VM inputs while requiring all future row endpoints absent."""

    vm = configuration.agent_vm
    checks = (
        (
            _regular_executable(vm.docker_executable, "agent VM Docker executable"),
            vm.pin.docker_executable_sha256,
            "agent VM Docker executable",
        ),
        (
            _regular_file(vm.controller_implementation, "agent VM controller implementation"),
            vm.pin.controller_implementation_sha256,
            "agent VM controller implementation",
        ),
        (
            _regular_file(vm.controller_policy, "agent VM controller policy"),
            vm.pin.controller_policy_sha256,
            "agent VM controller policy",
        ),
        (
            _regular_executable(vm.supervisor_executable, "agent VM supervisor executable"),
            vm.pin.supervisor_executable_sha256,
            "agent VM supervisor executable",
        ),
        (
            _regular_file(
                vm.supervisor_runtime_manifest,
                "agent VM supervisor runtime manifest",
            ),
            vm.pin.supervisor_runtime_manifest_sha256,
            "agent VM supervisor runtime manifest",
        ),
        (
            _regular_file(vm.vm_template, "agent VM template"),
            vm.pin.vm_template_sha256,
            "agent VM template",
        ),
        (
            _regular_file(vm.base_image, "agent VM base image"),
            vm.pin.base_image_sha256,
            "agent VM base image",
        ),
        (
            _regular_file(vm.relay_implementation, "host relay implementation"),
            vm.pin.relay_implementation_sha256,
            "host relay implementation",
        ),
        (
            _regular_file(vm.relay_policy, "host relay policy"),
            vm.pin.relay_policy_sha256,
            "host relay policy",
        ),
    )
    for path, expected, label in checks:
        if _file_digest(path) != expected:
            raise KnownSiteProductionError(f"{label} differs from its frozen digest")
    target_socket = configuration.target_docker.docker_socket_path.resolve(strict=True)
    for row_id, plan in vm.plans.items():
        planned_socket = plan.docker_socket.expanduser()
        if planned_socket.exists() or planned_socket.is_symlink():
            raise KnownSiteProductionError(
                f"{row_id} agent VM socket exists before its one-shot row"
            )
        if planned_socket.resolve(strict=False) == target_socket:
            raise KnownSiteProductionError("target and planned agent VM sockets are shared")
        if len(os.fsencode(planned_socket.as_posix())) > 100:
            raise KnownSiteProductionError("agent VM Unix socket plan exceeds its safe byte limit")
    for system in _SYSTEMS:
        runtime = configuration.systems[system]
        pin = configuration.contract.system_pins[system]
        AgentToolArchivePin(
            image_reference=pin.tool_image_reference,
            expected_image_id=pin.tool_image_id,
            archive=runtime.tool_image_archive,
            archive_sha256=pin.tool_image_archive_sha256,
            platform=pin.platform,
        ).validate()


def _model_policy(value: Mapping[str, object]) -> ModelGatewayPolicy:
    pricing = _mapping(value.get("pricing_usd_per_million_tokens"), "model pricing")
    policy = ModelGatewayPolicy.build(
        model=_text(value.get("model"), "model name"),
        reasoning_effort=_text(value.get("reasoning_effort"), "reasoning effort"),
        pricing=ModelPricing.from_numbers(
            input_per_million=_text(pricing.get("input_per_million"), "input price"),
            cached_input_per_million=_text(
                pricing.get("cached_input_per_million"), "cached-input price"
            ),
            output_per_million=_text(pricing.get("output_per_million"), "output price"),
        ),
        campaign_max_cost_usd=_text(value.get("campaign_max_cost_usd"), "campaign model cost"),
        max_completion_tokens_per_request=_positive_int(
            value.get("max_completion_tokens_per_request"), "completion token cap"
        ),
        max_request_body_bytes=_positive_int(
            value.get("max_request_body_bytes"), "model request byte cap"
        ),
        max_upstream_response_bytes=_positive_int(
            value.get("max_upstream_response_bytes"), "model response byte cap"
        ),
        upstream_timeout_seconds=_positive_int(
            value.get("upstream_timeout_seconds"), "model upstream timeout"
        ),
        max_parallel_requests=_positive_int(
            value.get("max_parallel_requests"), "parallel model request cap"
        ),
    )
    if policy.to_json() != dict(value):
        raise KnownSiteProductionError("model gateway policy is not the exact canonical document")
    return policy


def _limits(value: Mapping[str, object]) -> KnownSiteLimits:
    if set(value) != {"per_arm", "campaign"}:
        raise KnownSiteProductionError("known-site limit fields are invalid")
    per_arm = _mapping(value.get("per_arm"), "per-arm limits")
    campaign = _mapping(value.get("campaign"), "campaign limits")
    if set(per_arm) != {
        "wall_seconds",
        "max_model_requests",
        "max_target_requests",
        "max_cost_usd",
    } or set(campaign) != {
        "wall_seconds",
        "max_model_requests",
        "max_target_requests",
        "max_cost_usd",
    }:
        raise KnownSiteProductionError("known-site limit entries are invalid")
    return KnownSiteLimits.build(
        wall_seconds_per_arm=_positive_int(per_arm.get("wall_seconds"), "arm wall limit"),
        max_model_requests_per_arm=_positive_int(
            per_arm.get("max_model_requests"), "arm model request limit"
        ),
        max_target_requests_per_arm=_positive_int(
            per_arm.get("max_target_requests"), "arm target request limit"
        ),
        max_cost_usd_per_arm=_money(per_arm.get("max_cost_usd"), "arm cost limit"),
        campaign_wall_seconds=_positive_int(campaign.get("wall_seconds"), "campaign wall limit"),
        campaign_max_model_requests=_positive_int(
            campaign.get("max_model_requests"), "campaign model request limit"
        ),
        campaign_max_target_requests=_positive_int(
            campaign.get("max_target_requests"), "campaign target request limit"
        ),
        campaign_max_cost_usd=_money(campaign.get("max_cost_usd"), "campaign cost limit"),
    )


def _git(
    repository: Path,
    arguments: Sequence[str],
    *,
    trusted_path: str = "/usr/bin:/bin",
) -> str:
    git = shutil.which("git", path=trusted_path)
    if git is None:
        raise KnownSiteProductionError("trusted Git executable is unavailable")
    try:
        result = subprocess.run(  # noqa: S603 - exact executable and argv.
            (git, "-C", str(repository), *arguments),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={
                "PATH": trusted_path,
                "HOME": "/nonexistent-known-site-home",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KnownSiteProductionError("Git identity command failed") from exc
    if len(result.stdout) > _MAX_GIT_OUTPUT_BYTES or len(result.stderr) > _MAX_GIT_OUTPUT_BYTES:
        raise KnownSiteProductionError("Git identity command exceeded its output bound")
    if result.returncode != 0:
        raise KnownSiteProductionError("Git identity command did not succeed")
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise KnownSiteProductionError("Git identity output is not UTF-8") from exc


def _artifact_manifest(root: Path) -> str:
    lines = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.name == HASH_MANIFEST_FILE or not path.is_file() or path.is_symlink():
            continue
        lines.append(f"{_file_digest(path).removeprefix('sha256:')}  {path.name}\n")
    return "".join(lines)


def _status_markdown(preparation: Mapping[str, object]) -> str:
    ready = preparation.get("ready") is True
    blockers = preparation.get("block_reasons")
    blocker_lines = (
        "\n".join(f"- `{item}`" for item in cast("list[str]", blockers))
        if isinstance(blockers, list) and blockers
        else "- None."
    )
    return (
        "# Known-site website production preparation\n\n"
        f"Status: **{'ready' if ready else 'blocked'}**.\n\n"
        "This is a public known-site regression. It is not SOTA, unseen, or holdout "
        "evidence.\n\n"
        "## Block reasons\n\n"
        f"{blocker_lines}\n\n"
        "Preparation performed no entropy draw, model call, Docker build/pull, target "
        "start, or agent start.\n"
    )


def _decode_json(body: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(body, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KnownSiteProductionError(f"{label} is invalid JSON") from exc
    return _mapping(value, label)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise KnownSiteProductionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    requested = path.expanduser()
    if requested.is_symlink():
        raise KnownSiteProductionError(f"{label} must not be a symlink")
    resolved = requested.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise KnownSiteProductionError(f"{label} is not a bounded regular file")
    body = resolved.read_bytes()
    if len(body) != metadata.st_size:
        raise KnownSiteProductionError(f"{label} changed while it was read")
    return body


def _regular_file(path: Path, label: str) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise KnownSiteProductionError(f"{label} must not be a symlink")
    resolved = requested.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_IDENTITY_FILE_BYTES:
        raise KnownSiteProductionError(f"{label} is not a bounded regular file")
    return resolved


def _regular_executable(path: Path, label: str) -> Path:
    resolved = _regular_file(path, label)
    if not os.access(resolved, os.X_OK):
        raise KnownSiteProductionError(f"{label} is not executable")
    return resolved


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _json_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _json_round_trip(value: object) -> dict[str, object]:
    return _mapping(json.loads(_canonical_json(value)), "production request")


def _document(body: Mapping[str, object]) -> dict[str, object]:
    result = dict(body)
    result["document_sha256"] = _json_digest(result)
    return result


def _claim_directory(path: Path) -> Path:
    requested = path.expanduser().absolute()
    try:
        requested.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise KnownSiteProductionError(
            "production preparation directory already exists; overwrite/resume is forbidden"
        ) from exc
    return requested.resolve(strict=True)


def _write_exclusive(path: Path, body: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise KnownSiteProductionError(f"{label} must be a JSON object")
    return dict(value)


def _text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value) > 4096
    ):
        raise KnownSiteProductionError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    text = _text(value, f"{label} digest")
    if _SHA256_RE.fullmatch(text) is None:
        raise KnownSiteProductionError(f"{label} digest is invalid")
    return text


def _git_object(value: object, label: str) -> str:
    text = _text(value, label)
    if _GIT_RE.fullmatch(text) is None:
        raise KnownSiteProductionError(f"{label} is not an exact lowercase Git object")
    return text


def _absolute_path(value: object, label: str) -> Path:
    text = _text(value, label)
    path = Path(text)
    if not path.is_absolute() or path != Path(os.path.normpath(text)):
        raise KnownSiteProductionError(f"{label} must be a normalized absolute path")
    return path


def _path_tuple(value: object, label: str) -> tuple[Path, ...]:
    if not isinstance(value, list) or not value or len(value) > 128:
        raise KnownSiteProductionError(f"{label} must be a nonempty bounded list")
    paths = tuple(_absolute_path(item, label) for item in value)
    if len(set(paths)) != len(paths):
        raise KnownSiteProductionError(f"{label} contains duplicates")
    return paths


def _validated_http_endpoint(value: str, label: str) -> str:
    split = urlsplit(value)
    if (
        split.scheme != "http"
        or not split.hostname
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
    ):
        raise KnownSiteProductionError(f"{label} is not a credential-free HTTP endpoint")
    try:
        port = split.port
    except ValueError as exc:
        raise KnownSiteProductionError(f"{label} has no exact TCP port") from exc
    if port is None:
        message = f"{label} has no exact TCP port"
        raise KnownSiteProductionError(message)
    return value


def _trusted_path(value: object) -> str:
    text = _text(value, "trusted PATH")
    entries = text.split(":")
    if not entries or len(entries) > 32:
        raise KnownSiteProductionError("trusted PATH is invalid")
    for entry in entries:
        path = Path(entry)
        if not path.is_absolute() or path != Path(os.path.normpath(entry)):
            raise KnownSiteProductionError("trusted PATH contains a noncanonical entry")
    return text


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise KnownSiteProductionError(f"{label} must be a positive integer")
    return value


def _money(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise KnownSiteProductionError(f"{label} must be an exact decimal string")
    try:
        decimal = Decimal(value)
    except Exception as exc:
        raise KnownSiteProductionError(f"{label} is invalid") from exc
    if not decimal.is_finite() or decimal <= 0 or str(decimal) != value:
        raise KnownSiteProductionError(f"{label} is not canonically encoded")
    return value


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise KnownSiteProductionError("preparation timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise KnownSiteProductionError("preparation timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _safe_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc)[:1500]}"


__all__ = [
    "DRAFT_CONTRACT_FILE",
    "EXECUTOR_CONFIGURATION_FILE",
    "EXECUTOR_CONFIGURATION_SCHEMA",
    "PRODUCTION_PREPARATION_SCHEMA",
    "PRODUCTION_REQUEST_SCHEMA",
    "AgentToolBoundary",
    "AgentVmProductionConfiguration",
    "DockerAuthorityConfiguration",
    "IsolationProviderPin",
    "KnownSiteIsolationProvider",
    "KnownSiteProductionConfiguration",
    "KnownSiteProductionError",
    "SystemRuntimeConfiguration",
    "build_production_configuration",
    "execute_from_config",
    "prepare_from_config",
]
