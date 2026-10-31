# ruff: noqa: BLE001,C416,C901,D202,D213,EM101,EM102,PLR0912,PLR0913,PLR0915,PLR2004,S108,SIM115,TC003,TRY003,TRY301
"""Concrete build-once Docker target for the known-site website regression.

The public market lab is useful as an end-to-end regression, not as an unseen
benchmark.  This backend implements the target-side boundary promised by
``harness.py`` without reading the repository worktree as benchmark input:

* an exact, clean Git commit/path is exported with ``git archive``;
* the public ``web`` and ``internal`` services are each built once, with a
  digest-pinned Node base and no fresh flags in the build command/environment;
* a digest-pinned stock nginx image is reused for ``proxy`` without a build;
* each arm starts new containers, named volumes, and an internal target
  network from the same three immutable local image IDs, with pulls/builds
  disabled and flags injected only through the Compose process environment;
* an evaluator-owned HTTP meter is the only route supplied to the agent; and
* stop seals the meter before removing and independently inventorying every
  owned runtime identity.

The receipts are operational evidence from a trusted Docker host.  They are
deliberately not described as cryptographic execution attestation.  The legacy
same-daemon Strix network path below is retained as unfinished implementation
scaffolding only: ``validate_pre_draw`` rejects execution until it is replaced
by a reviewed cross-daemon, meter-only bridge.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final, Literal, Protocol
from urllib.parse import urlsplit

import yaml  # type: ignore[import-untyped]
from ravage.xben_parts.comparison_target import (
    BoundedSubprocessRunner,
    CommandResult,
    CommandRunner,
)
from ravage.xben_parts.http_meter_gateway import (
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    HTTP_METER_PROTOCOL,
    HTTP_METER_SCHEMA_VERSION,
    MAX_BUFFERED_BODY_BYTES,
    MAX_CONCURRENT_REQUESTS,
    MAX_RECEIPT_BYTES,
    validate_receipt_payload,
)

from tools.known_site_regression.harness import (
    BUILT_SERVICES,
    FLAG_ENVIRONMENT,
    SERVICE_NAMES,
    FrozenKnownSiteContract,
    LiveKnownSiteArm,
    PreparedKnownSiteTarget,
    SiteArmTeardown,
    SystemId,
)

_DIGEST_REFERENCE_RE: Final = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_IMAGE_ID_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_RAW_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}")
_SAFE_NAME_RE: Final = re.compile(r"[a-z0-9][a-z0-9_.-]{2,127}")
_FLAG_RE: Final = re.compile(r"flag\{ravage_site_[0-9a-f]{64}\}")
_COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}")

_TARGET_LABEL: Final = "com.ravage.known-site.target"
_INSTANCE_LABEL: Final = "com.ravage.known-site.instance"
_GATEWAY_LABEL: Final = "com.ravage.known-site.gateway"
_AGENT_NETWORK_LABEL: Final = "com.ravage.evaluator.agent-network"
_AGENT_INSTANCE_LABEL: Final = "com.ravage.evaluator.instance"
_GATEWAY_ALIAS: Final = "ravage-known-site-target"
_METER_MODULE: Final = "ravage.xben_parts.http_meter_gateway"
_METER_ROOT: Final = "/run/ravage-http-meter"
_METER_CONFIG: Final = f"{_METER_ROOT}/listen.json"
_METER_RECEIPT: Final = f"{_METER_ROOT}/receipt.json"
_PLATFORM: Final = "linux/amd64"
_SERVICE_PORTS: Final = {"proxy": 80, "web": 8080, "internal": 9200}
_MAX_ARCHIVE_BYTES: Final = 512 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS: Final = 20_000
_MAX_COMMAND_STREAM_BYTES: Final = 64 * 1024


class KnownSiteDockerTargetError(RuntimeError):
    """The known-site Docker target could not preserve its frozen contract."""


@dataclass(frozen=True)
class PinnedDockerImage:
    """A registry digest plus the exact platform-local image ID it must resolve to."""

    reference: str
    expected_image_id: str

    def validate(self, *, label: str) -> None:
        if _DIGEST_REFERENCE_RE.fullmatch(self.reference) is None:
            raise KnownSiteDockerTargetError(f"{label} image is not digest-pinned")
        if _IMAGE_ID_RE.fullmatch(self.expected_image_id) is None:
            raise KnownSiteDockerTargetError(f"{label} expected image ID is invalid")


@dataclass(frozen=True)
class AgentNetworkPin:
    """Exact evaluator-created network used only between Strix and the meter."""

    name: str
    network_id: str

    def validate(self) -> None:
        if _SAFE_NAME_RE.fullmatch(self.name) is None:
            raise KnownSiteDockerTargetError("agent network name is invalid")
        if _RAW_SHA256_RE.fullmatch(self.network_id) is None:
            raise KnownSiteDockerTargetError("agent network ID is invalid")


class AgentNetworkResolver(Protocol):
    """Resolve an already-created, arm-unique Strix network."""

    def __call__(
        self,
        *,
        row_id: str,
        system: SystemId,
        instance_id: str,
    ) -> AgentNetworkPin | None: ...


@dataclass(frozen=True)
class KnownSiteDockerConfiguration:
    """Frozen source, image, network, and timeout inputs for the backend."""

    repository: Path
    docker_executable: Path
    docker_executable_sha256: str
    docker_host: str
    daemon_identity_sha256: str
    node_image: PinnedDockerImage
    proxy_image: PinnedDockerImage
    gateway_image: PinnedDockerImage
    probe_image: PinnedDockerImage
    gateway_program_sha256: str
    agent_network_resolver: AgentNetworkResolver
    platform: str = _PLATFORM
    gateway_port: int = 8080
    build_timeout_seconds: int = 900
    startup_timeout_seconds: int = 180
    inspect_timeout_seconds: int = 30
    teardown_timeout_seconds: int = 90
    probe_attempts: int = 20
    probe_timeout_seconds: int = 5
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    max_response_body_bytes: int = DEFAULT_MAX_RESPONSE_BODY_BYTES
    upstream_timeout_seconds: int = DEFAULT_UPSTREAM_TIMEOUT_SECONDS

    def validate(self) -> None:
        if self.platform != _PLATFORM:
            raise KnownSiteDockerTargetError("known-site platform must be linux/amd64")
        try:
            executable = self.docker_executable.expanduser().resolve(strict=True)
        except OSError as exc:
            raise KnownSiteDockerTargetError("pinned Docker executable is unavailable") from exc
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise KnownSiteDockerTargetError("pinned Docker executable is unavailable")
        if _file_digest(executable) != _prefixed_digest(
            self.docker_executable_sha256,
            "Docker executable",
        ):
            raise KnownSiteDockerTargetError("Docker executable differs from its frozen digest")
        _validated_docker_host(self.docker_host)
        _prefixed_digest(self.daemon_identity_sha256, "Docker daemon identity")
        for label, image in (
            ("node base", self.node_image),
            ("proxy", self.proxy_image),
            ("HTTP meter", self.gateway_image),
            ("readiness probe", self.probe_image),
        ):
            image.validate(label=label)
        if _RAW_SHA256_RE.fullmatch(self.gateway_program_sha256) is None:
            raise KnownSiteDockerTargetError("HTTP meter program digest is invalid")
        for label, value in (
            ("gateway port", self.gateway_port),
            ("build timeout", self.build_timeout_seconds),
            ("startup timeout", self.startup_timeout_seconds),
            ("inspect timeout", self.inspect_timeout_seconds),
            ("teardown timeout", self.teardown_timeout_seconds),
            ("probe attempts", self.probe_attempts),
            ("probe timeout", self.probe_timeout_seconds),
            ("upstream timeout", self.upstream_timeout_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise KnownSiteDockerTargetError(f"{label} must be a positive integer")
        if self.gateway_port > 65535:
            raise KnownSiteDockerTargetError("gateway port is outside the TCP range")
        for label, value in (
            ("request body", self.max_request_body_bytes),
            ("response body", self.max_response_body_bytes),
        ):
            if not 0 < value <= MAX_BUFFERED_BODY_BYTES:
                raise KnownSiteDockerTargetError(f"{label} limit is invalid")


@dataclass
class _PreparedState:
    campaign_id: str
    root: Path
    workspace: Path
    site_path: Path
    evidence_root: Path
    target_runtime: dict[str, object]
    image_ids: dict[str, str]
    image_references: dict[str, str]
    owned_references: tuple[str, ...]
    flag_commitments_sha256: str
    prepared_flag_sha256_by_environment: dict[str, str]
    started_rows: dict[str, str] = field(default_factory=dict)
    stopped_rows: set[str] = field(default_factory=set)
    released: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


@dataclass
class _LiveState:
    prepared: _PreparedState
    row_id: str
    system: SystemId
    instance_id: str
    project: str
    root: Path
    compose_path: Path
    target_network_name: str
    target_network_id: str
    target_container_ids: dict[str, str]
    volume_names: tuple[str, ...]
    gateway_name: str
    gateway_id: str
    gateway_listen_host: str
    target_url: str
    max_target_requests: int
    access_boundary: Literal["trusted-host-loopback", "evaluator-owned-docker-network"]
    agent_network: AgentNetworkPin | None
    flag_sha256_by_logical_name: dict[str, str]
    stopped: bool = False


@dataclass
class DockerKnownSiteTargetBackend:
    """Build once and serve two one-shot known-site arms through a hard meter."""

    configuration: KnownSiteDockerConfiguration
    runner: CommandRunner = field(default_factory=BoundedSubprocessRunner)
    _preparation_reserved: bool = field(default=False, init=False)
    _prepared: _PreparedState | None = field(default=None, init=False)
    _live: dict[str, _LiveState] = field(default_factory=dict, init=False)

    def validate_pre_draw(self, *, contract: FrozenKnownSiteContract) -> None:
        """Reject the unsafe shared-daemon topology before flags are sampled."""

        self.configuration.validate()
        _validate_docker_configuration_contract(
            contract=contract,
            configuration=self.configuration,
        )
        # The existing implementation can attach the Strix sandbox only to a
        # network on the target daemon. That would expose target-container
        # metadata (including runtime flags) through the agent's Docker API.
        # A concrete cross-daemon, meter-only bridge must replace that path.
        raise KnownSiteDockerTargetError(
            "dual-daemon metered bridge is required before known-site execution"
        )

    def prepare(
        self,
        *,
        contract: FrozenKnownSiteContract,
        flags_by_environment: Mapping[str, str],
        flag_commitments_sha256: str,
        private_root: Path,
    ) -> PreparedKnownSiteTarget:
        """Export exact source and create the three-image closure exactly once."""

        self.configuration.validate()
        _validate_docker_configuration_contract(
            contract=contract,
            configuration=self.configuration,
        )
        target_runtime = _validate_target_runtime_contract(
            contract.target_runtime,
            configuration=self.configuration,
        )
        if self._preparation_reserved:
            raise KnownSiteDockerTargetError("known-site target preparation is one-shot")
        # Reservation precedes every fallible operation.  A failed build cannot
        # be retried after observing a partial outcome.
        self._preparation_reserved = True
        flag_hashes = _validate_flags(flags_by_environment)
        _prefixed_digest(flag_commitments_sha256, "flag commitment document")
        root = _claim_directory(private_root, "target-backend")
        workspace = _claim_directory(root, "workspace")
        evidence_root = _claim_directory(root, "evidence")
        records: list[dict[str, object]] = []
        owned_references: tuple[str, ...] = ()
        try:
            site_path, source_receipt = self._materialize_source(
                contract=contract,
                target_runtime=target_runtime,
                workspace=workspace,
                records=records,
            )
            self._verify_target_daemon(cwd=workspace, records=records)
            generated = _write_build_inputs(
                site_path=site_path,
                node_reference=self.configuration.node_image.reference,
                output_root=workspace,
            )
            for service, path in sorted(generated.items()):
                _write_bytes_exclusive(
                    evidence_root / f"Dockerfile.{service}.pinned",
                    path.read_bytes(),
                )
            project = _project_name(contract.campaign_id, suffix="prepared")
            references = {
                "web": f"{project}-web:prepared",
                "internal": f"{project}-internal:prepared",
                "proxy": self.configuration.proxy_image.reference,
            }
            owned_references = (references["internal"], references["web"])
            self._assert_owned_references_unused(
                owned_references,
                cwd=workspace,
                records=records,
            )
            for label, image in (
                ("node base", self.configuration.node_image),
                ("proxy", self.configuration.proxy_image),
                ("HTTP meter", self.configuration.gateway_image),
                ("readiness probe", self.configuration.probe_image),
            ):
                self._pull_and_verify_image(
                    image,
                    label=label,
                    cwd=workspace,
                    records=records,
                )

            clean_environment = _docker_environment(self.configuration.platform)
            for service in sorted(BUILT_SERVICES):
                result = self._run(
                    (
                        "docker",
                        "build",
                        "--platform",
                        self.configuration.platform,
                        "--pull=false",
                        "--no-cache",
                        "--label",
                        f"{_TARGET_LABEL}=prepared",
                        "--label",
                        f"{_INSTANCE_LABEL}={contract.campaign_id}",
                        "--file",
                        str(generated[service]),
                        "--tag",
                        references[service],
                        str(site_path / service),
                    ),
                    cwd=workspace,
                    environment=clean_environment,
                    timeout=self.configuration.build_timeout_seconds,
                    operation=f"build {service} exactly once",
                    records=records,
                )
                _require_success(result, f"build {service}")

            image_ids = {
                service: self._inspect_exact_image(
                    reference,
                    expected_id=(
                        self.configuration.proxy_image.expected_image_id
                        if service == "proxy"
                        else None
                    ),
                    cwd=workspace,
                    records=records,
                    operation=f"inspect prepared {service} image",
                )
                for service, reference in sorted(references.items())
            }
            if set(image_ids) != SERVICE_NAMES:
                raise KnownSiteDockerTargetError("prepared service image set is incomplete")
            build_receipt = {
                "schema_version": "ravage.known-site.docker-preparation.v1",
                "campaign_id": contract.campaign_id,
                "created_at": datetime.now(UTC).isoformat(),
                "source": source_receipt,
                "target_runtime": target_runtime,
                "build": {
                    "count_by_service": {"internal": 1, "proxy": 0, "web": 1},
                    "fresh_flags_present_in_argv": False,
                    "fresh_flags_present_in_environment": False,
                    "runtime_flag_injection_only": True,
                    "dockerfile_base_rewritten_to_pinned_node": True,
                    "npm_dependency_resolution_is_lock_and_integrity_pinned": True,
                    "networkless_hermetic_build_claimed": False,
                    "same_post_build_image_ids_reused_by_both_arms": True,
                    "generated_input_sha256_by_service": {
                        service: _file_digest(path) for service, path in sorted(generated.items())
                    },
                },
                "images": {
                    "references": references,
                    "image_ids": image_ids,
                    "proxy_is_digest_pinned_unbuilt_image": True,
                },
                "flag_commitments_sha256": flag_commitments_sha256,
                "flag_sha256_by_environment": flag_hashes,
                "docker_boundary": {
                    **contract.docker_separation.target.to_json(),
                    "docker_host_bound_on_every_command": True,
                    "daemon_identity_verified_live": True,
                    "distinct_from_agent_tool_daemon": True,
                },
                "commands": records,
                "verification_kind": "operational-git-docker-inspection",
                "cryptographically_attested": False,
                "valid": True,
            }
            _ensure_no_plaintext_flags(build_receipt, flags_by_environment.values())
            _write_json_exclusive(evidence_root / "preparation.json", build_receipt)
            state = _PreparedState(
                campaign_id=contract.campaign_id,
                root=root,
                workspace=workspace,
                site_path=site_path,
                evidence_root=evidence_root,
                target_runtime=target_runtime,
                image_ids=image_ids,
                image_references=references,
                owned_references=owned_references,
                flag_commitments_sha256=flag_commitments_sha256,
                prepared_flag_sha256_by_environment=flag_hashes,
            )
            self._prepared = state
            return PreparedKnownSiteTarget(
                source_archive_sha256=str(source_receipt["archive_sha256"]),
                source_tree_sha256=str(source_receipt["snapshot_tree_sha256"]),
                image_ids_by_service=dict(image_ids),
                build_count_by_service={"internal": 1, "proxy": 0, "web": 1},
                clean_pinned_archive_verified=True,
                flags_used_during_build=False,
                runtime_flag_injection_only=True,
                source_mounted_into_agent=False,
                operator_material_mounted_into_agent=False,
                credential_material_mounted_into_agent=False,
                backend_handle=state,
            )
        except Exception as exc:
            cleanup_errors = self._best_effort_release_tags(
                owned_references,
                cwd=workspace,
                records=records,
            )
            try:
                shutil.rmtree(workspace)
            except OSError as cleanup_exc:
                cleanup_errors.append(_safe_error(cleanup_exc))
            if workspace.exists():
                cleanup_errors.append("private preparation workspace remains")
            failure = {
                "schema_version": "ravage.known-site.docker-preparation-failure.v1",
                "campaign_id": contract.campaign_id,
                "error": _safe_error(exc),
                "commands": records,
                "cleanup": {
                    "workspace_removed": not workspace.exists(),
                    "errors": cleanup_errors,
                    "complete": not cleanup_errors,
                },
                "one_shot_reservation_consumed": True,
                "valid_for_execution": False,
            }
            _ensure_no_plaintext_flags(failure, flags_by_environment.values())
            _write_json_exclusive(evidence_root / "preparation-failure.json", failure)
            raise

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
    ) -> LiveKnownSiteArm:
        """Launch one fresh, image-only arm and its evaluator HTTP meter."""

        state = self._prepared_state(prepared)
        if system not in {"ravage", "strix"}:
            raise KnownSiteDockerTargetError("known-site system ID is invalid")
        expected_schedule = {"primary-001": "ravage", "primary-002": "strix"}
        if expected_schedule.get(row_id) != system:
            raise KnownSiteDockerTargetError("known-site target arm differs from frozen schedule")
        _safe_name(row_id, "row ID")
        _safe_name(instance_id, "instance ID")
        if isinstance(max_target_requests, bool) or max_target_requests <= 0:
            raise KnownSiteDockerTargetError("target request limit must be positive")
        flag_hashes_by_environment = _validate_flags(flags_by_environment)
        if flag_hashes_by_environment != state.prepared_flag_sha256_by_environment:
            raise KnownSiteDockerTargetError("runtime flags differ from prepared commitments")
        with state.lock:
            if state.released:
                raise KnownSiteDockerTargetError("prepared target was already released")
            _validate_arm_sequence(
                row_id=row_id,
                system=system,
                instance_id=instance_id,
                started_rows=state.started_rows,
                stopped_rows=state.stopped_rows,
            )
            # Irreversible even when launch fails: there is no favorable retry.
            state.started_rows[row_id] = instance_id

        root = _claim_directory(private_arm_root, "target-runtime")
        records: list[dict[str, object]] = []
        project = _project_name(instance_id, suffix="site")
        network_name = f"{project}-target"
        gateway_name = f"{project}-meter"
        volume_names = (f"{project}-internal-state", f"{project}-web-state")
        compose_path = root / "compose.yml"
        _write_runtime_compose(
            compose_path,
            instance_id=instance_id,
            target_network=network_name,
            volume_names=volume_names,
            image_ids=state.image_ids,
            proxy_configuration=(state.site_path / "proxy" / "nginx.conf").read_bytes(),
            expected_proxy_sha256=str(
                _mapping(
                    state.target_runtime.get("proxy_configuration"),
                    "proxy configuration contract",
                )["sha256"]
            ),
        )
        agent_network = self.configuration.agent_network_resolver(
            row_id=row_id,
            system=system,
            instance_id=instance_id,
        )
        if system == "strix":
            if agent_network is None:
                raise KnownSiteDockerTargetError("Strix requires a separate pinned agent network")
            agent_network.validate()
            self._verify_empty_agent_network(
                agent_network,
                instance_id=instance_id,
                cwd=root,
                records=records,
                expected_container_ids=set(),
            )
        elif agent_network is not None:
            raise KnownSiteDockerTargetError("Ravage arm must use only trusted host loopback")

        runtime_environment = {
            **_docker_environment(self.configuration.platform),
            **{name: value for name, value in flags_by_environment.items()},
            "MARKET_JWT_SECRET": "market-dev-secret",
        }
        try:
            self._assert_project_unused(project=project, cwd=root, records=records)
            self._assert_runtime_names_unused(
                gateway_name=gateway_name,
                target_network=network_name,
                volume_names=volume_names,
                cwd=root,
                records=records,
            )
            up = self._run(
                (
                    "docker",
                    "compose",
                    "--file",
                    str(compose_path),
                    "--project-name",
                    project,
                    "up",
                    "--detach",
                    "--no-build",
                    "--pull",
                    "never",
                    "--remove-orphans",
                    "--wait",
                    "--wait-timeout",
                    str(self.configuration.startup_timeout_seconds),
                ),
                cwd=root,
                environment=runtime_environment,
                timeout=self.configuration.startup_timeout_seconds,
                operation="start image-only target arm",
                records=records,
            )
            _require_success(up, "start image-only target arm")
            target_network_id = self._inspect_target_network(
                name=network_name,
                instance_id=instance_id,
                cwd=root,
                records=records,
            )
            target_container_ids = self._inspect_target_containers(
                project=project,
                network_name=network_name,
                image_ids=state.image_ids,
                volume_names=volume_names,
                cwd=root,
                records=records,
                flags_by_environment=flags_by_environment,
            )
            self._probe_target(
                network_name=network_name,
                cwd=root,
                records=records,
            )
            gateway_id, listen_host, target_url = self._start_gateway(
                system=system,
                instance_id=instance_id,
                project=project,
                gateway_name=gateway_name,
                target_network=network_name,
                agent_network=agent_network,
                max_target_requests=max_target_requests,
                cwd=root,
                records=records,
            )
            logical_hashes = {
                logical: flag_hashes_by_environment[environment]
                for logical, environment in FLAG_ENVIRONMENT
            }
            live_state = _LiveState(
                prepared=state,
                row_id=row_id,
                system=system,
                instance_id=instance_id,
                project=project,
                root=root,
                compose_path=compose_path,
                target_network_name=network_name,
                target_network_id=target_network_id,
                target_container_ids=target_container_ids,
                volume_names=volume_names,
                gateway_name=gateway_name,
                gateway_id=gateway_id,
                gateway_listen_host=listen_host,
                target_url=target_url,
                max_target_requests=max_target_requests,
                access_boundary=(
                    "trusted-host-loopback"
                    if system == "ravage"
                    else "evaluator-owned-docker-network"
                ),
                agent_network=agent_network,
                flag_sha256_by_logical_name=logical_hashes,
            )
            receipt = {
                "schema_version": "ravage.known-site.docker-arm-start.v1",
                "row_id": row_id,
                "system": system,
                "instance_id": instance_id,
                "project": project,
                "target_network": {"name": network_name, "id": target_network_id},
                "agent_network": (
                    None
                    if agent_network is None
                    else {"name": agent_network.name, "id": agent_network.network_id}
                ),
                "container_ids_by_service": target_container_ids,
                "volume_names": list(volume_names),
                "image_ids_by_service": state.image_ids,
                "build_invocations": 0,
                "pull_invocations": 0,
                "source_mounts": [],
                "operator_material_mounts": [],
                "credential_material_mounts": [],
                "runtime_flag_sha256_by_name": logical_hashes,
                "request_meter": {
                    "protocol": HTTP_METER_PROTOCOL,
                    "hard_limit": max_target_requests,
                    "access_boundary": live_state.access_boundary,
                    "target_url_sha256": _text_digest(target_url),
                    "program_sha256": self.configuration.gateway_program_sha256,
                },
                "commands": records,
                "verification_kind": "operational-docker-inspection",
                "cryptographically_attested": False,
                "valid": True,
            }
            _ensure_no_plaintext_flags(receipt, flags_by_environment.values())
            _write_json_exclusive(root / "backend-start.json", receipt)
            self._live[instance_id] = live_state
            return LiveKnownSiteArm(
                row_id=row_id,
                system=system,
                instance_id=instance_id,
                target_url=target_url,
                project_id=project,
                network_id=target_network_id,
                container_ids_by_service=target_container_ids,
                volume_ids=volume_names,
                image_ids_by_service=dict(state.image_ids),
                runtime_flag_sha256_by_name=logical_hashes,
                build_invocations=0,
                pull_invocations=0,
                source_mounts=(),
                operator_material_mounts=(),
                credential_material_mounts=(),
                request_limit=max_target_requests,
                fresh=True,
                backend_handle=live_state,
            )
        except Exception:
            # Startup cleanup is mandatory, but the row remains permanently
            # reserved whether cleanup succeeds or fails.
            cleanup_complete = self._cleanup_failed_start(
                project=project,
                gateway_name=gateway_name,
                cwd=root,
                runtime_environment=runtime_environment,
                records=records,
            )
            if cleanup_complete:
                state.stopped_rows.add(row_id)
            raise

    def stop_arm(self, *, live: LiveKnownSiteArm) -> SiteArmTeardown:
        """Seal accounting, remove the arm, and prove all owned IDs absent."""

        state = live.backend_handle
        if not isinstance(state, _LiveState) or self._live.get(live.instance_id) is not state:
            raise KnownSiteDockerTargetError("live arm is not owned by this backend")
        if state.stopped:
            raise KnownSiteDockerTargetError("known-site target arm was already stopped")
        state.stopped = True
        records: list[dict[str, object]] = []
        errors: list[str] = []
        meter_receipt: dict[str, object] | None = None
        try:
            if state.agent_network is not None:
                self._verify_empty_agent_network(
                    state.agent_network,
                    instance_id=state.instance_id,
                    cwd=state.root,
                    records=records,
                    expected_container_ids={state.gateway_id},
                )
            signal_result = self._run(
                ("docker", "kill", "--signal", "USR1", state.gateway_id),
                cwd=state.root,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation="seal HTTP meter",
                records=records,
            )
            _require_success(signal_result, "seal HTTP meter")
            meter_receipt = self._read_meter_receipt(
                state,
                require_sealed=True,
                records=records,
            )
            _validate_meter_receipt(
                meter_receipt,
                state=state,
                configuration=self.configuration,
                require_sealed=True,
            )
            _write_json_exclusive(
                state.root / "request-count.json",
                {
                    "schema_version": "ravage.known-site.request-meter-stop.v1",
                    "status": "verified",
                    "terminal_admission_closed": True,
                    "receipt": meter_receipt,
                },
            )
        except Exception as exc:
            errors.append(_safe_error(exc))

        environment = _docker_environment(self.configuration.platform)
        for operation, command in (
            ("remove HTTP meter", ("docker", "rm", "--force", state.gateway_id)),
            (
                "remove target project",
                (
                    "docker",
                    "compose",
                    "--file",
                    str(state.compose_path),
                    "--project-name",
                    state.project,
                    "down",
                    "--remove-orphans",
                    "--volumes",
                ),
            ),
        ):
            try:
                result = self._run(
                    command,
                    cwd=state.root,
                    environment=environment,
                    timeout=self.configuration.teardown_timeout_seconds,
                    operation=operation,
                    records=records,
                )
                if result.returncode != 0:
                    errors.append(f"{operation} failed")
            except Exception as exc:
                errors.append(_safe_error(exc))

        remaining = self._inventory_known_runtime(state=state, records=records)
        if any(remaining.values()):
            errors.append("known Docker runtime identities remain after teardown")
        if state.agent_network is not None:
            try:
                self._verify_empty_agent_network(
                    state.agent_network,
                    instance_id=state.instance_id,
                    cwd=state.root,
                    records=records,
                    expected_container_ids=set(),
                )
            except Exception as exc:
                errors.append(_safe_error(exc))

        target_attempts = (
            _nonnegative_integer(
                meter_receipt.get("target_request_attempts"),
                "target request attempts",
            )
            if meter_receipt is not None
            else 0
        )
        stop_receipt = {
            "schema_version": "ravage.known-site.docker-arm-stop.v1",
            "row_id": state.row_id,
            "instance_id": state.instance_id,
            "request_meter": meter_receipt,
            "known_runtime_remaining": remaining,
            "removed": {
                "container_ids": sorted(state.target_container_ids.values()),
                "gateway_id": state.gateway_id,
                "volume_names": sorted(state.volume_names),
                "target_network_id": state.target_network_id,
            },
            "commands": records,
            "errors": errors,
            "verification_kind": "operational-docker-inspection-and-meter-receipt",
            "cryptographically_attested": False,
            "valid": not errors and meter_receipt is not None,
        }
        _write_json_exclusive(state.root / "backend-stop.json", stop_receipt)
        if errors or meter_receipt is None:
            raise KnownSiteDockerTargetError("; ".join(errors) or "meter receipt unavailable")
        state.prepared.stopped_rows.add(state.row_id)
        return SiteArmTeardown(
            row_id=state.row_id,
            instance_id=state.instance_id,
            observed_target_requests=target_attempts,
            request_limit=state.max_target_requests,
            request_meter_sealed=True,
            request_meter_complete=True,
            containers_remaining=(),
            volumes_remaining=(),
            networks_remaining=(),
            removed_container_ids=tuple(state.target_container_ids.values()),
            removed_volume_ids=state.volume_names,
            removed_network_ids=(state.target_network_id,),
        )

    def release(self, *, prepared: PreparedKnownSiteTarget) -> Mapping[str, object]:
        """Drop evaluator-owned tags after both one-shot arms are terminal."""

        state = self._prepared_state(prepared)
        with state.lock:
            if state.released:
                raise KnownSiteDockerTargetError("prepared target was already released")
            if set(state.started_rows) != {"primary-001", "primary-002"} or (
                state.stopped_rows != set(state.started_rows)
            ):
                raise KnownSiteDockerTargetError("both known-site arms must stop before release")
            state.released = True
        records: list[dict[str, object]] = []
        errors: list[str] = []
        for reference in state.owned_references:
            result = self._run(
                ("docker", "image", "rm", reference),
                cwd=state.root,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.teardown_timeout_seconds,
                operation="release prepared image tag",
                records=records,
            )
            if result.returncode != 0:
                errors.append(f"could not release prepared tag {reference}")
            inventory = self._run(
                ("docker", "image", "ls", "--quiet", "--no-trunc", reference),
                cwd=state.root,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation="verify prepared image tag absent",
                records=records,
            )
            if inventory.returncode != 0 or inventory.stdout.strip():
                errors.append(f"prepared tag remains {reference}")
        try:
            shutil.rmtree(state.workspace)
        except OSError as exc:
            errors.append(_safe_error(exc))
        receipt = {
            "schema_version": "ravage.known-site.docker-release.v1",
            "campaign_id": state.campaign_id,
            "both_arms_terminal": True,
            "owned_image_references": list(state.owned_references),
            "prepared_workspace_removed": not state.workspace.exists(),
            "evidence_retained": True,
            "commands": records,
            "errors": errors,
            "released": not errors,
        }
        _write_json_exclusive(state.evidence_root / "release.json", receipt)
        if errors:
            raise KnownSiteDockerTargetError("; ".join(errors))
        return receipt

    def _prepared_state(self, prepared: PreparedKnownSiteTarget) -> _PreparedState:
        state = prepared.backend_handle
        if not isinstance(state, _PreparedState) or self._prepared is not state:
            raise KnownSiteDockerTargetError("prepared target is not owned by this backend")
        if prepared.image_ids_by_service != state.image_ids:
            raise KnownSiteDockerTargetError("prepared target image binding drifted")
        return state

    def _verify_target_daemon(
        self,
        *,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        result = self._run(
            ("docker", "info", "--format", "{{json .ID}}"),
            cwd=cwd,
            environment=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            operation="verify target Docker daemon identity",
            records=records,
        )
        _require_success(result, "verify target Docker daemon identity")
        try:
            identity = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KnownSiteDockerTargetError("Docker daemon identity is malformed") from exc
        if (
            not isinstance(identity, str)
            or not identity.strip()
            or identity != identity.strip()
            or _text_digest(identity) != self.configuration.daemon_identity_sha256
        ):
            raise KnownSiteDockerTargetError("Docker daemon identity differs from its pin")

    def _materialize_source(
        self,
        *,
        contract: FrozenKnownSiteContract,
        target_runtime: Mapping[str, object],
        workspace: Path,
        records: list[dict[str, object]],
    ) -> tuple[Path, dict[str, object]]:
        source = contract.source
        source_json = source.to_json()
        if _COMMIT_RE.fullmatch(source.commit) is None or _COMMIT_RE.fullmatch(source.tree) is None:
            raise KnownSiteDockerTargetError("known-site Git pin must use 40-hex objects")
        repository = self.configuration.repository.expanduser().resolve(strict=True)
        if not repository.is_dir():
            raise KnownSiteDockerTargetError("known-site repository is not a directory")
        environment = _git_environment()

        def git(*arguments: str, operation: str) -> str:
            result = self._run(
                ("git", "-C", str(repository), *arguments),
                cwd=repository,
                environment=environment,
                timeout=self.configuration.inspect_timeout_seconds,
                operation=operation,
                records=records,
            )
            _require_success(result, operation)
            return result.stdout.decode("utf-8", errors="replace").strip()

        if (
            git("remote", "get-url", "origin", operation="inspect source origin")
            != source.origin_url
        ):
            raise KnownSiteDockerTargetError("known-site source origin differs from the contract")
        if git("rev-parse", "HEAD", operation="inspect source HEAD") != source.commit:
            raise KnownSiteDockerTargetError("known-site source HEAD differs from the contract")
        if git("rev-parse", f"{source.commit}^{{commit}}", operation="resolve source commit") != (
            source.commit
        ):
            raise KnownSiteDockerTargetError("known-site source commit is not exact")
        lock_contract = _mapping(
            target_runtime.get("dependency_lock"),
            "dependency lock contract",
        )
        lock_path = PurePosixPath(source.relative_path) / str(lock_contract["relative_path"])
        lock_exists = self._run(
            ("git", "-C", str(repository), "cat-file", "-e", f"{source.commit}:{lock_path}"),
            cwd=repository,
            environment=environment,
            timeout=self.configuration.inspect_timeout_seconds,
            operation="verify pinned dependency lock exists",
            records=records,
        )
        if lock_exists.returncode != 0:
            raise KnownSiteDockerTargetError("pinned dependency lock is unavailable")
        if git(
            "status", "--porcelain=v1", "--untracked-files=all", operation="inspect source status"
        ):
            raise KnownSiteDockerTargetError("known-site source checkout is dirty")
        tree_spec = f"{source.commit}:{source.relative_path}"
        if git("rev-parse", tree_spec, operation="resolve source tree") != source.tree:
            raise KnownSiteDockerTargetError("known-site source tree differs from the contract")
        archive = self._run(
            (
                "git",
                "-C",
                str(repository),
                "archive",
                "--format=tar",
                source.commit,
                source.relative_path,
            ),
            cwd=repository,
            environment=environment,
            timeout=self.configuration.inspect_timeout_seconds,
            operation="export exact known-site source",
            records=records,
        )
        _require_success(archive, "export exact known-site source")
        if len(archive.stdout) > _MAX_ARCHIVE_BYTES:
            raise KnownSiteDockerTargetError("known-site source archive is too large")
        extracted = _claim_directory(workspace, "source")
        _extract_safe_archive(archive.stdout, root=extracted)
        site_path = extracted.joinpath(*PurePosixPath(source.relative_path).parts)
        if not site_path.is_dir():
            raise KnownSiteDockerTargetError("known-site path is absent from its archive")
        proxy_contract = _mapping(
            target_runtime.get("proxy_configuration"),
            "proxy configuration contract",
        )
        source_files = {
            "dependency lock": (
                site_path / str(lock_contract["relative_path"]),
                str(lock_contract["sha256"]),
            ),
            "package manifest": (
                site_path / "web" / "package.json",
                str(lock_contract["package_json_sha256"]),
            ),
            "proxy configuration": (
                site_path / str(proxy_contract["relative_path"]),
                str(proxy_contract["sha256"]),
            ),
        }
        for label, (path, expected_digest) in source_files.items():
            if path.is_symlink() or not path.is_file():
                raise KnownSiteDockerTargetError(f"pinned {label} is unavailable")
            if _file_digest(path) != expected_digest:
                raise KnownSiteDockerTargetError(f"pinned {label} digest drifted")
        _validate_npm_lock(
            package_json=source_files["package manifest"][0],
            package_lock=source_files["dependency lock"][0],
        )
        final_head = git("rev-parse", "HEAD", operation="recheck source HEAD")
        final_status = git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            operation="recheck source status",
        )
        if final_head != source.commit or final_status:
            raise KnownSiteDockerTargetError("known-site checkout changed during export")
        tree_manifest = _tree_manifest(site_path)
        receipt = {
            **source_json,
            "archive_sha256": _bytes_digest(archive.stdout),
            "archive_size_bytes": len(archive.stdout),
            "snapshot_tree_sha256": tree_manifest["sha256"],
            "snapshot_file_count": tree_manifest["file_count"],
            "checkout_clean_before_and_after": True,
            "origin_verified": True,
            "commit_object_verified": True,
            "git_tree_verified": True,
        }
        return site_path, receipt

    def _assert_owned_references_unused(
        self,
        references: Sequence[str],
        *,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        for reference in references:
            result = self._run(
                ("docker", "image", "inspect", reference),
                cwd=cwd,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation="reserve prepared image reference",
                records=records,
            )
            if result.returncode == 0:
                raise KnownSiteDockerTargetError("prepared image reference already exists")

    def _pull_and_verify_image(
        self,
        image: PinnedDockerImage,
        *,
        label: str,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        result = self._run(
            ("docker", "image", "pull", "--platform", self.configuration.platform, image.reference),
            cwd=cwd,
            environment=_docker_environment(self.configuration.platform),
            timeout=self.configuration.build_timeout_seconds,
            operation=f"pull pinned {label} image during preparation",
            records=records,
        )
        _require_success(result, f"pull pinned {label} image")
        self._inspect_exact_image(
            image.reference,
            expected_id=image.expected_image_id,
            cwd=cwd,
            records=records,
            operation=f"verify pinned {label} image",
        )

    def _inspect_exact_image(
        self,
        reference: str,
        *,
        expected_id: str | None,
        cwd: Path,
        records: list[dict[str, object]],
        operation: str,
    ) -> str:
        payload = self._docker_json(
            ("docker", "image", "inspect", reference),
            cwd=cwd,
            records=records,
            operation=operation,
        )
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise KnownSiteDockerTargetError("Docker image inspection is incomplete")
        image_id = payload[0].get("Id")
        if not isinstance(image_id, str) or _IMAGE_ID_RE.fullmatch(image_id) is None:
            raise KnownSiteDockerTargetError("Docker image ID is invalid")
        if expected_id is not None and image_id != expected_id:
            raise KnownSiteDockerTargetError("Docker image ID differs from its frozen pin")
        if payload[0].get("Architecture") != "amd64" or payload[0].get("Os") != "linux":
            raise KnownSiteDockerTargetError("Docker image platform differs from linux/amd64")
        return image_id

    def _assert_project_unused(
        self,
        *,
        project: str,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        for resource, command in _project_inventory_commands(project).items():
            result = self._run(
                command,
                cwd=cwd,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation=f"preflight empty {resource} project inventory",
                records=records,
            )
            _require_success(result, f"preflight {resource} inventory")
            if result.stdout.strip():
                raise KnownSiteDockerTargetError("Docker project identity is already in use")

    def _assert_runtime_names_unused(
        self,
        *,
        gateway_name: str,
        target_network: str,
        volume_names: Sequence[str],
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        checks = [
            ("gateway container", ("docker", "container", "inspect", gateway_name)),
            ("target network", ("docker", "network", "inspect", target_network)),
            *[
                (f"target volume {index}", ("docker", "volume", "inspect", name))
                for index, name in enumerate(volume_names, start=1)
            ],
        ]
        for label, command in checks:
            result = self._run(
                command,
                cwd=cwd,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation=f"reserve unused {label} name",
                records=records,
            )
            if result.returncode == 0:
                raise KnownSiteDockerTargetError(f"{label} name is already occupied")

    def _inspect_target_network(
        self,
        *,
        name: str,
        instance_id: str,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> str:
        payload = self._docker_json(
            ("docker", "network", "inspect", name),
            cwd=cwd,
            records=records,
            operation="inspect target network",
        )
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise KnownSiteDockerTargetError("target network inspection is malformed")
        network = payload[0]
        labels = _string_mapping(network.get("Labels"))
        network_id = network.get("Id")
        if (
            network.get("Name") != name
            or network.get("Internal") is not True
            or labels.get(_INSTANCE_LABEL) != instance_id
            or not isinstance(network_id, str)
            or _RAW_SHA256_RE.fullmatch(network_id) is None
        ):
            raise KnownSiteDockerTargetError("target network boundary is invalid")
        return network_id

    def _inspect_target_containers(
        self,
        *,
        project: str,
        network_name: str,
        image_ids: Mapping[str, str],
        volume_names: tuple[str, str],
        cwd: Path,
        records: list[dict[str, object]],
        flags_by_environment: Mapping[str, str],
    ) -> dict[str, str]:
        listed = self._run(
            (
                "docker",
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ),
            cwd=cwd,
            environment=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            operation="inventory target containers",
            records=records,
        )
        _require_success(listed, "inventory target containers")
        identities = _decoded_lines(listed.stdout)
        if len(identities) != len(SERVICE_NAMES):
            raise KnownSiteDockerTargetError("target container count is incomplete")
        payload = self._docker_json(
            ("docker", "inspect", *identities),
            cwd=cwd,
            records=records,
            operation="inspect target containers",
        )
        if not isinstance(payload, list) or len(payload) != len(SERVICE_NAMES):
            raise KnownSiteDockerTargetError("target container inspection is incomplete")
        result: dict[str, str] = {}
        observed_volumes: set[str] = set()
        for item in payload:
            if not isinstance(item, dict):
                raise KnownSiteDockerTargetError("target container inspection is malformed")
            config = _mapping(item.get("Config"), "container config")
            host = _mapping(item.get("HostConfig"), "container host config")
            network_settings = _mapping(item.get("NetworkSettings"), "container network settings")
            labels = _string_mapping(config.get("Labels"))
            service = labels.get("com.docker.compose.service")
            container_id = item.get("Id")
            networks = _mapping(network_settings.get("Networks"), "container networks")
            container_state = _mapping(item.get("State"), "container state")
            mounts = item.get("Mounts")
            environment = config.get("Env")
            if (
                service not in SERVICE_NAMES
                or service in result
                or labels.get("com.docker.compose.project") != project
                or labels.get(_TARGET_LABEL) != "true"
                or not isinstance(container_id, str)
                or _RAW_SHA256_RE.fullmatch(container_id) is None
                or item.get("Image") != image_ids[service]
                or set(networks) != {network_name}
                or container_state.get("Running") is not True
                or host.get("Privileged") is not False
                or host.get("ReadonlyRootfs") is not True
                or _published_ports(network_settings.get("Ports"))
            ):
                raise KnownSiteDockerTargetError("target container isolation is invalid")
            if (
                service in BUILT_SERVICES
                and _mapping(container_state.get("Health"), "container health").get("Status")
                != "healthy"
            ):
                raise KnownSiteDockerTargetError("built target service is not healthy")
            _validate_target_hardening(service=service, host=host)
            if not isinstance(mounts, list) or not isinstance(environment, list):
                raise KnownSiteDockerTargetError("target container runtime metadata is malformed")
            service_volumes: set[str] = set()
            for mount in mounts:
                if not isinstance(mount, dict) or mount.get("Type") != "volume":
                    raise KnownSiteDockerTargetError("target contains a non-volume runtime mount")
                name = mount.get("Name")
                if not isinstance(name, str) or name not in set(volume_names):
                    raise KnownSiteDockerTargetError("target uses an unexpected volume")
                observed_volumes.add(name)
                service_volumes.add(name)
            expected_service_volumes = {
                "proxy": set(),
                "internal": {volume_names[0]},
                "web": {volume_names[1]},
            }
            if service_volumes != expected_service_volumes[service]:
                raise KnownSiteDockerTargetError("target service volume boundary drifted")
            expected_flag_names: set[str] = set()
            if service == "web":
                expected_flag_names = {
                    name for _logical, name in FLAG_ENVIRONMENT if name != "MARKET_FLAG_ROOT"
                }
            elif service == "internal":
                expected_flag_names = {"MARKET_FLAG_ROOT"}
            actual_env = _environment_mapping(environment)
            for name in expected_flag_names:
                if actual_env.get(name) != flags_by_environment[name]:
                    raise KnownSiteDockerTargetError("runtime flag injection is incomplete")
            forbidden_names = {name for _logical, name in FLAG_ENVIRONMENT} - expected_flag_names
            if any(name in actual_env for name in forbidden_names):
                raise KnownSiteDockerTargetError("runtime flag reached the wrong target service")
            result[service] = container_id
        if set(result) != SERVICE_NAMES or observed_volumes != set(volume_names):
            raise KnownSiteDockerTargetError("target service/volume set is incomplete")
        return result

    def _probe_target(
        self,
        *,
        network_name: str,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> None:
        for ordinal in range(1, self.configuration.probe_attempts + 1):
            result = self._run(
                (
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network",
                    network_name,
                    self.configuration.probe_image.reference,
                    "--silent",
                    "--show-error",
                    "--max-time",
                    str(self.configuration.probe_timeout_seconds),
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    "http://proxy:80/",
                ),
                cwd=cwd,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.probe_timeout_seconds + 5,
                operation=f"target readiness probe {ordinal}",
                records=records,
            )
            status = result.stdout.decode("ascii", errors="ignore").strip()
            if result.returncode == 0 and status.isdigit() and 100 <= int(status) < 500:
                return
        raise KnownSiteDockerTargetError("known-site target did not become ready")

    def _start_gateway(
        self,
        *,
        system: SystemId,
        instance_id: str,
        project: str,
        gateway_name: str,
        target_network: str,
        agent_network: AgentNetworkPin | None,
        max_target_requests: int,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> tuple[str, str, str]:
        initial_network = target_network if agent_network is None else agent_network.name
        access_boundary: Literal["trusted-host-loopback", "evaluator-owned-docker-network"] = (
            "trusted-host-loopback" if system == "ravage" else "evaluator-owned-docker-network"
        )
        publish = (
            ("--publish", f"127.0.0.1::{self.configuration.gateway_port}")
            if (system == "ravage")
            else ()
        )
        command = _meter_serve_command(
            instance_id=instance_id,
            port=self.configuration.gateway_port,
            max_target_requests=max_target_requests,
            access_boundary=access_boundary,
            configuration=self.configuration,
        )
        result = self._run(
            (
                "docker",
                "run",
                "--detach",
                "--pull=never",
                "--name",
                gateway_name,
                "--label",
                f"{_GATEWAY_LABEL}=true",
                "--label",
                f"{_INSTANCE_LABEL}={instance_id}",
                "--label",
                f"com.docker.compose.project={project}",
                "--network",
                initial_network,
                "--network-alias",
                _GATEWAY_ALIAS,
                *publish,
                "--read-only",
                "--tmpfs",
                f"{_METER_ROOT}:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65532,gid=65532",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--pids-limit=64",
                "--memory=256m",
                "--cpus=0.25",
                "--user",
                "65532:65532",
                "--entrypoint",
                "python3",
                self.configuration.gateway_image.reference,
                *command,
            ),
            cwd=cwd,
            environment=_docker_environment(self.configuration.platform),
            timeout=self.configuration.startup_timeout_seconds,
            operation="create evaluator HTTP meter",
            records=records,
        )
        _require_success(result, "create evaluator HTTP meter")
        gateway_id = result.stdout.decode("ascii", errors="ignore").strip()
        if _RAW_SHA256_RE.fullmatch(gateway_id) is None:
            raise KnownSiteDockerTargetError("HTTP meter container ID is invalid")
        if agent_network is not None:
            connected = self._run(
                ("docker", "network", "connect", target_network, gateway_id),
                cwd=cwd,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation="connect HTTP meter to target network",
                records=records,
            )
            _require_success(connected, "connect HTTP meter to target network")
        inspection = self._docker_json(
            ("docker", "inspect", gateway_id),
            cwd=cwd,
            records=records,
            operation="inspect evaluator HTTP meter",
        )
        if (
            not isinstance(inspection, list)
            or len(inspection) != 1
            or not isinstance(inspection[0], dict)
        ):
            raise KnownSiteDockerTargetError("HTTP meter inspection is malformed")
        raw = inspection[0]
        config = _mapping(raw.get("Config"), "HTTP meter config")
        host = _mapping(raw.get("HostConfig"), "HTTP meter host config")
        settings = _mapping(raw.get("NetworkSettings"), "HTTP meter network settings")
        labels = _string_mapping(config.get("Labels"))
        networks = _mapping(settings.get("Networks"), "HTTP meter networks")
        expected_networks = {target_network} | ({agent_network.name} if agent_network else set())
        if (
            raw.get("Id") != gateway_id
            or raw.get("Image") != self.configuration.gateway_image.expected_image_id
            or labels.get(_GATEWAY_LABEL) != "true"
            or labels.get(_INSTANCE_LABEL) != instance_id
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or set(networks) != expected_networks
            or any(mount.get("Source") == "/var/run/docker.sock" for mount in _mounts(raw))
        ):
            raise KnownSiteDockerTargetError("HTTP meter container boundary is invalid")
        selected_network = target_network if agent_network is None else agent_network.name
        selected = _mapping(networks[selected_network], "HTTP meter selected network")
        listen_host = selected.get("IPAddress")
        if not isinstance(listen_host, str) or not listen_host:
            raise KnownSiteDockerTargetError("HTTP meter has no selected-network address")
        configured = self._run(
            (
                "docker",
                "exec",
                gateway_id,
                "python3",
                "-m",
                _METER_MODULE,
                "configure",
                "--path",
                _METER_CONFIG,
                "--listen-host",
                listen_host,
            ),
            cwd=cwd,
            environment=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            operation="bind evaluator HTTP meter",
            records=records,
        )
        _require_success(configured, "bind evaluator HTTP meter")
        identity = self._docker_json(
            ("docker", "exec", gateway_id, "python3", "-m", _METER_MODULE, "identity"),
            cwd=cwd,
            records=records,
            operation="verify HTTP meter program identity",
        )
        if identity != {
            "schema_version": HTTP_METER_SCHEMA_VERSION,
            "program_sha256": self.configuration.gateway_program_sha256,
            "protocol": HTTP_METER_PROTOCOL,
        }:
            raise KnownSiteDockerTargetError("HTTP meter program identity drifted")
        provisional = _LiveState(
            prepared=self._prepared if self._prepared is not None else _unreachable_prepared(),
            row_id="provisional",
            system=system,
            instance_id=instance_id,
            project=project,
            root=cwd,
            compose_path=cwd / "compose.yml",
            target_network_name=target_network,
            target_network_id="0" * 64,
            target_container_ids={},
            volume_names=(),
            gateway_name=gateway_name,
            gateway_id=gateway_id,
            gateway_listen_host=listen_host,
            target_url="http://127.0.0.1:1",
            max_target_requests=max_target_requests,
            access_boundary=access_boundary,
            agent_network=agent_network,
            flag_sha256_by_logical_name={},
        )
        receipt = self._read_meter_receipt(provisional, require_sealed=False, records=records)
        _validate_meter_receipt(
            receipt,
            state=provisional,
            configuration=self.configuration,
            require_sealed=False,
        )
        if any(
            _nonnegative_integer(receipt.get(name), name) != 0
            for name in (
                "observed_requests",
                "accepted_requests",
                "target_request_attempts",
                "unsupported_requests",
                "rejected_over_limit",
                "upstream_errors",
                "oversize_responses",
                "in_flight_requests",
            )
        ):
            raise KnownSiteDockerTargetError("HTTP meter was nonzero before agent execution")
        if agent_network is not None:
            self._verify_empty_agent_network(
                agent_network,
                instance_id=instance_id,
                cwd=cwd,
                records=records,
                expected_container_ids={gateway_id},
            )
        if system == "ravage":
            bindings = _published_bindings(settings.get("Ports"), self.configuration.gateway_port)
            if len(bindings) != 1 or bindings[0][0] != "127.0.0.1":
                raise KnownSiteDockerTargetError("HTTP meter loopback binding is invalid")
            target_url = f"http://127.0.0.1:{bindings[0][1]}"
        else:
            if _published_ports(settings.get("Ports")):
                raise KnownSiteDockerTargetError("Strix HTTP meter unexpectedly publishes a port")
            target_url = f"http://{_GATEWAY_ALIAS}:{self.configuration.gateway_port}"
        return gateway_id, listen_host, target_url

    def _read_meter_receipt(
        self,
        state: _LiveState,
        *,
        require_sealed: bool,
        records: list[dict[str, object]],
    ) -> dict[str, object]:
        command = [
            "docker",
            "exec",
            state.gateway_id,
            "python3",
            "-m",
            _METER_MODULE,
            "receipt",
            "--path",
            _METER_RECEIPT,
            "--wait-seconds",
            str(self.configuration.upstream_timeout_seconds + 2),
            "--require-idle",
        ]
        if require_sealed:
            command.append("--require-sealed")
        result = self._run(
            command,
            cwd=state.root,
            environment=_docker_environment(self.configuration.platform),
            timeout=self.configuration.upstream_timeout_seconds + 7,
            operation="read terminal HTTP meter receipt"
            if require_sealed
            else ("read initial HTTP meter receipt"),
            records=records,
        )
        _require_success(result, "read HTTP meter receipt")
        if len(result.stdout) > MAX_RECEIPT_BYTES:
            raise KnownSiteDockerTargetError("HTTP meter receipt exceeds its fixed size")
        try:
            return validate_receipt_payload(json.loads(result.stdout))
        except (ValueError, json.JSONDecodeError) as exc:
            raise KnownSiteDockerTargetError("HTTP meter receipt is malformed") from exc

    def _verify_empty_agent_network(
        self,
        pin: AgentNetworkPin,
        *,
        instance_id: str,
        cwd: Path,
        records: list[dict[str, object]],
        expected_container_ids: set[str],
    ) -> None:
        payload = self._docker_json(
            ("docker", "network", "inspect", pin.name),
            cwd=cwd,
            records=records,
            operation="inspect evaluator agent network",
        )
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise KnownSiteDockerTargetError("agent network inspection is malformed")
        network = payload[0]
        labels = _string_mapping(network.get("Labels"))
        containers = network.get("Containers") or {}
        if (
            network.get("Id") != pin.network_id
            or network.get("Name") != pin.name
            or network.get("Internal") is not True
            or labels.get(_AGENT_NETWORK_LABEL) != "true"
            or labels.get(_AGENT_INSTANCE_LABEL) != instance_id
            or not isinstance(containers, dict)
            or set(containers) != expected_container_ids
        ):
            raise KnownSiteDockerTargetError("agent network membership/binding is invalid")

    def _inventory_known_runtime(
        self,
        *,
        state: _LiveState,
        records: list[dict[str, object]],
    ) -> dict[str, list[str]]:
        checks = {
            "containers": (
                ("docker", "container", "ls", "--all", "--quiet", "--no-trunc"),
                {*state.target_container_ids.values(), state.gateway_id},
            ),
            "volumes": (("docker", "volume", "ls", "--quiet"), set(state.volume_names)),
            "networks": (
                ("docker", "network", "ls", "--quiet", "--no-trunc"),
                {state.target_network_id},
            ),
        }
        remaining: dict[str, list[str]] = {}
        for name, (command, known) in checks.items():
            result = self._run(
                command,
                cwd=state.root,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation=f"post-teardown complete {name} inventory",
                records=records,
            )
            if result.returncode != 0:
                remaining[name] = ["inventory_unavailable"]
            else:
                remaining[name] = sorted(known.intersection(_decoded_lines(result.stdout)))
        project_keys = {
            "container": "containers",
            "volume": "volumes",
            "network": "networks",
        }
        for resource, command in _project_inventory_commands(state.project).items():
            key = project_keys[resource]
            result = self._run(
                command,
                cwd=state.root,
                environment=_docker_environment(self.configuration.platform),
                timeout=self.configuration.inspect_timeout_seconds,
                operation=f"post-teardown project {resource} inventory",
                records=records,
            )
            if result.returncode != 0:
                remaining[key] = sorted({*remaining[key], "inventory_unavailable"})
            else:
                remaining[key] = sorted({*remaining[key], *_decoded_lines(result.stdout)})
        return remaining

    def _cleanup_failed_start(
        self,
        *,
        project: str,
        gateway_name: str,
        cwd: Path,
        runtime_environment: Mapping[str, str],
        records: list[dict[str, object]],
    ) -> bool:
        # Deterministic names are owned only after their labels are verified in
        # the normal path.  Compose down is scoped by the fresh project label;
        # a gateway name is removed only if inspection proves our labels.
        errors: list[str] = []
        clean_environment = _docker_environment(self.configuration.platform)
        try:
            result = self._run(
                ("docker", "inspect", gateway_name),
                cwd=cwd,
                environment=clean_environment,
                timeout=self.configuration.inspect_timeout_seconds,
                operation="inspect failed-start HTTP meter identity",
                records=records,
            )
            if result.returncode == 0:
                try:
                    payload = json.loads(result.stdout)
                    raw = payload[0]
                    labels = _string_mapping(_mapping(raw.get("Config"), "config").get("Labels"))
                    owned = (
                        labels.get(_GATEWAY_LABEL) == "true"
                        and labels.get("com.docker.compose.project") == project
                    )
                except (IndexError, KeyError, TypeError, json.JSONDecodeError):
                    owned = False
                if not owned:
                    errors.append("failed-start gateway identity is occupied but not owned")
                else:
                    removed = self._run(
                        ("docker", "rm", "--force", gateway_name),
                        cwd=cwd,
                        environment=clean_environment,
                        timeout=self.configuration.teardown_timeout_seconds,
                        operation="remove failed-start HTTP meter",
                        records=records,
                    )
                    if removed.returncode != 0:
                        errors.append("failed-start HTTP meter removal failed")
        except Exception as exc:
            errors.append(_safe_error(exc))
        try:
            down = self._run(
                (
                    "docker",
                    "compose",
                    "--file",
                    str(cwd / "compose.yml"),
                    "--project-name",
                    project,
                    "down",
                    "--remove-orphans",
                    "--volumes",
                ),
                cwd=cwd,
                environment=runtime_environment,
                timeout=self.configuration.teardown_timeout_seconds,
                operation="clean failed-start target project",
                records=records,
            )
            if down.returncode != 0:
                errors.append("failed-start target project cleanup failed")
        except Exception as exc:
            errors.append(_safe_error(exc))
        for resource, command in _project_inventory_commands(project).items():
            try:
                inventory = self._run(
                    command,
                    cwd=cwd,
                    environment=clean_environment,
                    timeout=self.configuration.inspect_timeout_seconds,
                    operation=f"verify failed-start {resource} inventory empty",
                    records=records,
                )
                if inventory.returncode != 0 or inventory.stdout.strip():
                    errors.append(f"failed-start {resource} resources remain")
            except Exception as exc:
                errors.append(_safe_error(exc))
        try:
            gateway_inventory = self._run(
                ("docker", "inspect", gateway_name),
                cwd=cwd,
                environment=clean_environment,
                timeout=self.configuration.inspect_timeout_seconds,
                operation="verify failed-start gateway absent",
                records=records,
            )
            if gateway_inventory.returncode == 0:
                errors.append("failed-start gateway remains")
        except Exception as exc:
            errors.append(_safe_error(exc))
        receipt = {
            "schema_version": "ravage.known-site.docker-arm-start-failure.v1",
            "project": project,
            "gateway_name": gateway_name,
            "commands": records,
            "errors": errors,
            "cleanup_complete": not errors,
        }
        try:
            _write_json_exclusive(cwd / "backend-start-failure.json", receipt)
        except Exception:
            return False
        return not errors

    def _best_effort_release_tags(
        self,
        references: Sequence[str],
        *,
        cwd: Path,
        records: list[dict[str, object]],
    ) -> list[str]:
        errors: list[str] = []
        for reference in references:
            try:
                self._run(
                    ("docker", "image", "rm", reference),
                    cwd=cwd,
                    environment=_docker_environment(self.configuration.platform),
                    timeout=self.configuration.teardown_timeout_seconds,
                    operation="clean failed preparation tag",
                    records=records,
                )
                inventory = self._run(
                    ("docker", "image", "ls", "--quiet", "--no-trunc", reference),
                    cwd=cwd,
                    environment=_docker_environment(self.configuration.platform),
                    timeout=self.configuration.inspect_timeout_seconds,
                    operation="verify failed preparation tag absent",
                    records=records,
                )
                if inventory.returncode != 0 or inventory.stdout.strip():
                    errors.append(f"failed preparation tag remains {reference}")
            except Exception as cleanup_exc:
                errors.append(_safe_error(cleanup_exc))
        return errors

    def _docker_json(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        records: list[dict[str, object]],
        operation: str,
    ) -> object:
        result = self._run(
            command,
            cwd=cwd,
            environment=_docker_environment(self.configuration.platform),
            timeout=self.configuration.inspect_timeout_seconds,
            operation=operation,
            records=records,
        )
        _require_success(result, operation)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise KnownSiteDockerTargetError(f"{operation} returned malformed JSON") from exc

    def _run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout: int,
        operation: str,
        records: list[dict[str, object]],
    ) -> CommandResult:
        argv = tuple(command)
        clean_environment = dict(environment)
        if argv and argv[0] == "docker":
            argv = (
                str(self.configuration.docker_executable.expanduser().resolve(strict=True)),
                *argv[1:],
            )
            clean_environment["DOCKER_HOST"] = self.configuration.docker_host
        result = self.runner.run(
            argv,
            cwd=cwd,
            environment=clean_environment,
            timeout_seconds=timeout,
        )
        records.append(
            _command_receipt(
                result,
                operation=operation,
                timeout=timeout,
                docker_host_sha256=(
                    _text_digest(self.configuration.docker_host)
                    if command and command[0] == "docker"
                    else None
                ),
                docker_executable_sha256=(
                    self.configuration.docker_executable_sha256
                    if command and command[0] == "docker"
                    else None
                ),
            )
        )
        return result


def _validate_target_runtime_contract(
    value: Mapping[str, object],
    *,
    configuration: KnownSiteDockerConfiguration,
) -> dict[str, object]:
    expected_keys = {
        "platform",
        "images",
        "http_meter",
        "dependency_lock",
        "proxy_configuration",
    }
    if set(value) != expected_keys or value.get("platform") != configuration.platform:
        raise KnownSiteDockerTargetError("target runtime contract differs from configuration")
    images = _mapping(value.get("images"), "target runtime images")
    expected_images = {
        "node_base": configuration.node_image,
        "proxy": configuration.proxy_image,
        "http_meter": configuration.gateway_image,
        "readiness_probe": configuration.probe_image,
    }
    if set(images) != set(expected_images):
        raise KnownSiteDockerTargetError("target runtime image contract is incomplete")
    normalized_images: dict[str, object] = {}
    for name, expected in sorted(expected_images.items()):
        pin = _mapping(images.get(name), f"target runtime {name} image")
        normalized_pin = {
            "reference": expected.reference,
            "expected_image_id": expected.expected_image_id,
        }
        if set(pin) != set(normalized_pin) or dict(pin) != normalized_pin:
            raise KnownSiteDockerTargetError(f"target runtime {name} image pin drifted")
        normalized_images[name] = normalized_pin
    meter = _mapping(value.get("http_meter"), "target runtime HTTP meter")
    expected_meter = {
        "program_sha256": configuration.gateway_program_sha256,
        "protocol": HTTP_METER_PROTOCOL,
    }
    if set(meter) != set(expected_meter) or dict(meter) != expected_meter:
        raise KnownSiteDockerTargetError("target runtime HTTP meter pin drifted")
    lock = _mapping(value.get("dependency_lock"), "target runtime dependency lock")
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
        raise KnownSiteDockerTargetError("target dependency-lock contract is invalid")
    _prefixed_digest(lock.get("sha256"), "dependency lock")
    _prefixed_digest(lock.get("package_json_sha256"), "package manifest")
    proxy = _mapping(value.get("proxy_configuration"), "target proxy configuration")
    if set(proxy) != {"relative_path", "sha256"} or proxy.get("relative_path") != (
        "proxy/nginx.conf"
    ):
        raise KnownSiteDockerTargetError("target proxy-configuration contract is invalid")
    _prefixed_digest(proxy.get("sha256"), "proxy configuration")
    # Copy every nested mapping so caller-owned containers cannot be mutated
    # across the commitment/execution boundary.
    normalized_runtime: dict[str, object] = {
        "platform": configuration.platform,
        "images": normalized_images,
        "http_meter": expected_meter,
        "dependency_lock": dict(lock),
        "proxy_configuration": dict(proxy),
    }
    return normalized_runtime


def _validate_docker_configuration_contract(
    *,
    contract: FrozenKnownSiteContract,
    configuration: KnownSiteDockerConfiguration,
) -> None:
    target = contract.docker_separation.target.to_json()
    host, socket_path = _validated_docker_host(configuration.docker_host)
    observed = {
        "docker_executable_sha256": configuration.docker_executable_sha256,
        "docker_socket_path_sha256": _text_digest(socket_path.as_posix()),
        "docker_host_sha256": _text_digest(host),
        "daemon_identity_sha256": configuration.daemon_identity_sha256,
    }
    if observed != target:
        raise KnownSiteDockerTargetError(
            "target Docker executable, endpoint, or daemon differs from the pre-draw contract"
        )
    # Re-evaluate the pair here so a caller cannot bypass the contract's
    # distinct-daemon validation by handing the backend only its target half.
    contract.docker_separation.to_json(campaign_id=contract.campaign_id)


def _validated_docker_host(value: str) -> tuple[str, Path]:
    if not isinstance(value, str) or value != value.strip() or len(value.encode()) > 4096:
        raise KnownSiteDockerTargetError("Docker host must be a canonical local Unix URL")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise KnownSiteDockerTargetError("Docker host must be a canonical local Unix URL") from exc
    path = Path(parsed.path)
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.startswith("//")
        or not path.is_absolute()
        or path == Path("/")
        or path.as_posix() != parsed.path
        or any(part in {".", ".."} for part in path.parts)
        or "%" in parsed.path
        or "\\" in parsed.path
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in parsed.path
        )
        or value != f"unix://{parsed.path}"
    ):
        raise KnownSiteDockerTargetError("Docker host must be a canonical local Unix URL")
    return value, path


def _validate_arm_sequence(
    *,
    row_id: str,
    system: SystemId,
    instance_id: str,
    started_rows: Mapping[str, str],
    stopped_rows: set[str],
) -> None:
    schedule: dict[str, SystemId] = {
        "primary-001": "ravage",
        "primary-002": "strix",
    }
    if schedule.get(row_id) != system:
        raise KnownSiteDockerTargetError("known-site arm differs from the frozen schedule")
    if row_id in started_rows or instance_id in started_rows.values():
        raise KnownSiteDockerTargetError("known-site target arm is not fresh")
    predecessors = set()
    if row_id == "primary-002":
        predecessors = {"primary-001"}
    if set(started_rows) != predecessors or stopped_rows != predecessors:
        raise KnownSiteDockerTargetError("prior known-site target arm did not complete teardown")


def _validate_npm_lock(*, package_json: Path, package_lock: Path) -> None:
    try:
        manifest = json.loads(package_json.read_bytes())
        lock = json.loads(package_lock.read_bytes())
    except json.JSONDecodeError as exc:
        raise KnownSiteDockerTargetError("npm dependency metadata is malformed") from exc
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        raise KnownSiteDockerTargetError("npm dependency metadata must be JSON objects")
    if lock.get("lockfileVersion") != 3 or lock.get("requires") is not True:
        raise KnownSiteDockerTargetError("npm dependency lock must use complete lockfile v3")
    root = lock.get("packages")
    if not isinstance(root, dict) or not isinstance(root.get(""), dict):
        raise KnownSiteDockerTargetError("npm dependency lock has no root package record")
    root_package = root[""]
    for field_name in ("name", "version", "dependencies"):
        if root_package.get(field_name) != manifest.get(field_name):
            raise KnownSiteDockerTargetError("npm lock root differs from package.json")
    for path, package in root.items():
        if path == "":
            continue
        if not isinstance(path, str) or not isinstance(package, dict):
            raise KnownSiteDockerTargetError("npm dependency lock package record is malformed")
        if package.get("link") is True:
            continue
        integrity = package.get("integrity")
        resolved = package.get("resolved")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            raise KnownSiteDockerTargetError("npm dependency lacks a sha512 integrity pin")
        if not isinstance(resolved, str) or not resolved.startswith("https://"):
            raise KnownSiteDockerTargetError("npm dependency lacks a pinned HTTPS source")


def _write_build_inputs(
    *,
    site_path: Path,
    node_reference: str,
    output_root: Path,
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    package_json = site_path / "web" / "package.json"
    package_lock = site_path / "web" / "package-lock.json"
    if package_json.is_symlink() or not package_json.is_file():
        raise KnownSiteDockerTargetError("web package manifest is unavailable")
    if package_lock.is_symlink() or not package_lock.is_file():
        raise KnownSiteDockerTargetError(
            "web dependency lock is absent; mutable npm resolution is forbidden"
        )
    for service in sorted(BUILT_SERVICES):
        source = site_path / service / "Dockerfile"
        if source.is_symlink() or not source.is_file():
            raise KnownSiteDockerTargetError(f"{service} Dockerfile is unavailable")
        body = source.read_text(encoding="utf-8")
        lines = body.splitlines(keepends=True)
        if not lines or lines[0].strip() != "FROM node:20-alpine":
            raise KnownSiteDockerTargetError(f"{service} Dockerfile base declaration drifted")
        if service == "web" and (
            "COPY package.json package-lock.json ./" not in body
            or "RUN npm ci --omit=dev" not in body
            or "RUN npm install" in body
        ):
            raise KnownSiteDockerTargetError(
                "web Dockerfile must consume the committed lock with npm ci --omit=dev"
            )
        generated = output_root / f"Dockerfile.{service}.pinned"
        _write_bytes_exclusive(
            generated,
            (f"FROM {node_reference}\n" + "".join(lines[1:])).encode("utf-8"),
        )
        result[service] = generated
    return result


def _write_runtime_compose(
    path: Path,
    *,
    instance_id: str,
    target_network: str,
    volume_names: tuple[str, str],
    image_ids: Mapping[str, str],
    proxy_configuration: bytes,
    expected_proxy_sha256: str,
) -> None:
    if set(image_ids) != SERVICE_NAMES or any(
        _IMAGE_ID_RE.fullmatch(value) is None for value in image_ids.values()
    ):
        raise KnownSiteDockerTargetError("runtime image closure is invalid")
    if _bytes_digest(proxy_configuration) != expected_proxy_sha256:
        raise KnownSiteDockerTargetError("public proxy configuration drifted")
    encoded_proxy = base64.b64encode(proxy_configuration).decode("ascii")
    common = {
        "pull_policy": "never",
        "read_only": True,
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "pids_limit": 128,
        "mem_limit": "512m",
        "cpus": 1.0,
        "networks": ["target"],
        "restart": "no",
    }
    document = {
        "services": {
            "proxy": {
                **common,
                "image": image_ids["proxy"],
                "cap_add": ["NET_BIND_SERVICE"],
                "command": [
                    "/bin/sh",
                    "-eu",
                    "-c",
                    (
                        f"printf %s {encoded_proxy} | base64 -d > /tmp/nginx.conf; "
                        "exec nginx -c /tmp/nginx.conf -g 'daemon off;'"
                    ),
                ],
                "tmpfs": [
                    "/tmp:rw,noexec,nosuid,nodev,size=1m",
                    "/var/cache/nginx:rw,noexec,nosuid,nodev,size=16m",
                    "/var/run:rw,noexec,nosuid,nodev,size=1m",
                ],
                "depends_on": {
                    "web": {"condition": "service_healthy"},
                    "internal": {"condition": "service_healthy"},
                },
                "labels": {_TARGET_LABEL: "true", _INSTANCE_LABEL: instance_id},
            },
            "web": {
                **common,
                "image": image_ids["web"],
                "environment": {
                    "MARKET_FLAG_IDOR": "${MARKET_FLAG_IDOR:-__RUNTIME_FLAG_MISSING__}",
                    "MARKET_FLAG_SQLI": "${MARKET_FLAG_SQLI:-__RUNTIME_FLAG_MISSING__}",
                    "MARKET_FLAG_JWT": "${MARKET_FLAG_JWT:-__RUNTIME_FLAG_MISSING__}",
                    "MARKET_FLAG_PROTO": "${MARKET_FLAG_PROTO:-__RUNTIME_FLAG_MISSING__}",
                    "MARKET_JWT_SECRET": "${MARKET_JWT_SECRET:-market-dev-secret}",
                },
                "volumes": ["web-state:/var/lib/ravage-known-site"],
                "healthcheck": {
                    "test": ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/health"],
                    "interval": "2s",
                    "timeout": "2s",
                    "retries": 30,
                },
                "labels": {_TARGET_LABEL: "true", _INSTANCE_LABEL: instance_id},
            },
            "internal": {
                **common,
                "image": image_ids["internal"],
                "networks": {"target": {"aliases": ["market-internal"]}},
                "environment": {
                    "MARKET_FLAG_ROOT": "${MARKET_FLAG_ROOT:-__RUNTIME_FLAG_MISSING__}"
                },
                "volumes": ["internal-state:/var/lib/ravage-known-site"],
                "healthcheck": {
                    "test": ["CMD", "wget", "-qO-", "http://127.0.0.1:9200/health"],
                    "interval": "2s",
                    "timeout": "2s",
                    "retries": 30,
                },
                "labels": {_TARGET_LABEL: "true", _INSTANCE_LABEL: instance_id},
            },
        },
        "networks": {
            "target": {
                "name": target_network,
                "internal": True,
                "labels": {_INSTANCE_LABEL: instance_id},
            }
        },
        "volumes": {
            "internal-state": {
                "name": volume_names[0],
                "labels": {_INSTANCE_LABEL: instance_id},
            },
            "web-state": {
                "name": volume_names[1],
                "labels": {_INSTANCE_LABEL: instance_id},
            },
        },
    }
    _write_bytes_exclusive(
        path,
        yaml.safe_dump(document, sort_keys=True, default_flow_style=False).encode("utf-8"),
    )


def _meter_serve_command(
    *,
    instance_id: str,
    port: int,
    max_target_requests: int,
    access_boundary: str,
    configuration: KnownSiteDockerConfiguration,
) -> tuple[str, ...]:
    return (
        "-m",
        _METER_MODULE,
        "serve",
        "--listen-config",
        _METER_CONFIG,
        "--receipt",
        _METER_RECEIPT,
        "--instance-id",
        instance_id,
        "--listen-port",
        str(port),
        "--upstream-host",
        "proxy",
        "--upstream-port",
        "80",
        "--max-target-requests",
        str(max_target_requests),
        "--access-boundary",
        access_boundary,
        "--max-request-body-bytes",
        str(configuration.max_request_body_bytes),
        "--max-response-body-bytes",
        str(configuration.max_response_body_bytes),
        "--upstream-timeout-seconds",
        str(configuration.upstream_timeout_seconds),
    )


def _validate_meter_receipt(
    receipt: Mapping[str, object],
    *,
    state: _LiveState,
    configuration: KnownSiteDockerConfiguration,
    require_sealed: bool,
) -> None:
    expected = {
        "schema_version": HTTP_METER_SCHEMA_VERSION,
        "program_sha256": configuration.gateway_program_sha256,
        "protocol": HTTP_METER_PROTOCOL,
        "instance_id": state.instance_id,
        "ready": True,
        "sealed": require_sealed,
        "access_boundary": state.access_boundary,
        "caller_authentication": "none",
        "trusted_host_no_concurrent_local_adversary": state.system == "ravage",
        "listen_host": state.gateway_listen_host,
        "listen_port": configuration.gateway_port,
        "upstream_host": "proxy",
        "upstream_port": 80,
        "max_target_requests": state.max_target_requests,
        "max_request_body_bytes": configuration.max_request_body_bytes,
        "max_response_body_bytes": configuration.max_response_body_bytes,
        "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
    }
    for name, value in expected.items():
        if receipt.get(name) != value:
            raise KnownSiteDockerTargetError(f"HTTP meter receipt field {name!r} drifted")
    if require_sealed and receipt.get("in_flight_requests") != 0:
        raise KnownSiteDockerTargetError("HTTP meter receipt is not terminally idle")


def _extract_safe_archive(payload: bytes, *, root: Path) -> None:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
    except tarfile.TarError as exc:
        raise KnownSiteDockerTargetError("known-site Git archive is malformed") from exc
    with archive:
        members = archive.getmembers()
        if len(members) > _MAX_ARCHIVE_MEMBERS:
            raise KnownSiteDockerTargetError("known-site Git archive has too many members")
        total = 0
        for member in members:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                raise KnownSiteDockerTargetError("known-site Git archive path is unsafe")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise KnownSiteDockerTargetError("known-site Git archive contains special entries")
            if member.isfile():
                total += member.size
                if total > _MAX_ARCHIVE_BYTES:
                    raise KnownSiteDockerTargetError("known-site Git archive expands too large")
            destination = root.joinpath(*relative.parts)
            if not _within(destination, root):
                raise KnownSiteDockerTargetError("known-site Git archive escapes its root")
        for member in members:
            destination = root.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise KnownSiteDockerTargetError("known-site Git archive file is unavailable")
            _write_bytes_exclusive(destination, source.read())
            destination.chmod(0o700 if member.mode & 0o111 else 0o600)


def _tree_manifest(root: Path) -> dict[str, object]:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise KnownSiteDockerTargetError("known-site snapshot contains a special file")
        body = path.read_bytes()
        files.append(
            {
                "path": relative,
                "size": len(body),
                "mode": stat.S_IMODE(metadata.st_mode),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "file_count": len(files),
        "sha256": _bytes_digest(canonical),
    }


def _validate_flags(flags: Mapping[str, str]) -> dict[str, str]:
    expected = {environment for _logical, environment in FLAG_ENVIRONMENT}
    if set(flags) != expected:
        raise KnownSiteDockerTargetError("known-site runtime flag environment set is incomplete")
    values = list(flags.values())
    if any(not isinstance(value, str) or _FLAG_RE.fullmatch(value) is None for value in values):
        raise KnownSiteDockerTargetError("known-site runtime flag format is invalid")
    if len(set(values)) != len(values):
        raise KnownSiteDockerTargetError("known-site runtime flags are not unique")
    return {name: _text_digest(value) for name, value in sorted(flags.items())}


def _environment_mapping(values: object) -> dict[str, str]:
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise KnownSiteDockerTargetError("container environment is malformed")
    result: dict[str, str] = {}
    for entry in values:
        name, separator, value = entry.partition("=")
        if separator and name not in result:
            result[name] = value
    return result


def _validate_target_hardening(
    *,
    service: str,
    host: Mapping[str, object],
) -> None:
    cap_add = host.get("CapAdd") or []
    cap_drop = host.get("CapDrop") or []
    security = host.get("SecurityOpt") or []
    expected_add = {"NET_BIND_SERVICE", "CAP_NET_BIND_SERVICE"} if service == "proxy" else set()
    if not isinstance(cap_add, list) or not isinstance(cap_drop, list):
        raise KnownSiteDockerTargetError("target capability inspection is malformed")
    normalized_add = {str(value).upper() for value in cap_add}
    if service == "proxy":
        if len(normalized_add) != 1 or normalized_add.isdisjoint(expected_add):
            raise KnownSiteDockerTargetError("proxy capability set exceeds NET_BIND_SERVICE")
    elif normalized_add:
        raise KnownSiteDockerTargetError("non-proxy target has added Linux capabilities")
    if [str(value).upper() for value in cap_drop] != ["ALL"]:
        raise KnownSiteDockerTargetError("target does not drop all ambient capabilities")
    if not isinstance(security, list) or {str(value) for value in security} not in (
        {"no-new-privileges"},
        {"no-new-privileges:true"},
    ):
        raise KnownSiteDockerTargetError("target no-new-privileges policy drifted")
    if (
        host.get("PidMode") not in {None, ""}
        or host.get("IpcMode") not in {None, "", "private"}
        or host.get("UTSMode") not in {None, ""}
        or host.get("UsernsMode") not in {None, ""}
        or (host.get("Devices") or []) != []
        or (host.get("DeviceRequests") or []) != []
        or host.get("PidsLimit") != 128
        or host.get("Memory") != 512 * 1024 * 1024
        or host.get("NanoCpus") != 1_000_000_000
    ):
        raise KnownSiteDockerTargetError("target host-resource hardening drifted")
    tmpfs = host.get("Tmpfs") or {}
    if not isinstance(tmpfs, dict):
        raise KnownSiteDockerTargetError("target tmpfs inspection is malformed")
    expected_tmpfs_paths = {"/tmp", "/var/cache/nginx", "/var/run"} if service == "proxy" else set()
    if set(tmpfs) != expected_tmpfs_paths:
        raise KnownSiteDockerTargetError("target tmpfs boundary drifted")
    for options in tmpfs.values():
        if not isinstance(options, str) or not {
            "rw",
            "noexec",
            "nosuid",
            "nodev",
        }.issubset(options.split(",")):
            raise KnownSiteDockerTargetError("target tmpfs hardening drifted")


def _published_ports(value: object) -> list[tuple[str, str]]:
    if value in (None, {}):
        return []
    if not isinstance(value, dict):
        raise KnownSiteDockerTargetError("published port inspection is malformed")
    result: list[tuple[str, str]] = []
    for bindings in value.values():
        if bindings is None:
            continue
        if not isinstance(bindings, list):
            raise KnownSiteDockerTargetError("published port binding is malformed")
        for binding in bindings:
            if not isinstance(binding, dict):
                raise KnownSiteDockerTargetError("published port binding is malformed")
            result.append((str(binding.get("HostIp") or ""), str(binding.get("HostPort") or "")))
    return result


def _published_bindings(value: object, container_port: int) -> list[tuple[str, int]]:
    if not isinstance(value, dict):
        raise KnownSiteDockerTargetError("gateway port inspection is malformed")
    bindings = value.get(f"{container_port}/tcp")
    if not isinstance(bindings, list):
        raise KnownSiteDockerTargetError("gateway port binding is unavailable")
    result: list[tuple[str, int]] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            raise KnownSiteDockerTargetError("gateway port binding is malformed")
        host = binding.get("HostIp")
        port = binding.get("HostPort")
        if host not in {"127.0.0.1", "::1"} or not isinstance(port, str) or not port.isdigit():
            raise KnownSiteDockerTargetError("gateway port escaped loopback")
        parsed = int(port)
        if not 1 <= parsed <= 65535:
            raise KnownSiteDockerTargetError("gateway host port is invalid")
        result.append((host, parsed))
    return result


def _mounts(raw: Mapping[str, object]) -> list[Mapping[str, object]]:
    mounts = raw.get("Mounts")
    if not isinstance(mounts, list):
        raise KnownSiteDockerTargetError("container mount inspection is malformed")
    if not all(isinstance(item, dict) for item in mounts):
        raise KnownSiteDockerTargetError("container mount inspection is malformed")
    return [item for item in mounts if isinstance(item, dict)]


def _project_inventory_commands(project: str) -> dict[str, tuple[str, ...]]:
    label = f"label=com.docker.compose.project={project}"
    return {
        "container": ("docker", "container", "ls", "--all", "--quiet", "--filter", label),
        "network": ("docker", "network", "ls", "--quiet", "--filter", label),
        "volume": ("docker", "volume", "ls", "--quiet", "--filter", label),
    }


def _docker_environment(platform: str) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
        "DOCKER_DEFAULT_PLATFORM": platform,
        "LC_ALL": "C",
        "LANG": "C",
    }


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _project_name(value: str, *, suffix: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    candidate = f"rks-{normalized[:40]}-{digest}-{suffix}"
    return _safe_name(candidate, "Docker project")


def _safe_name(value: str, label: str) -> str:
    if not isinstance(value, str) or _SAFE_NAME_RE.fullmatch(value) is None:
        raise KnownSiteDockerTargetError(f"{label} is invalid")
    return value


def _prefixed_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or (_RAW_SHA256_RE.fullmatch(value.removeprefix("sha256:")) is None)
    ):
        raise KnownSiteDockerTargetError(f"{label} digest is invalid")
    return value


def _text_digest(value: str) -> str:
    return _bytes_digest(value.encode("utf-8"))


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _file_digest(path: Path) -> str:
    return _bytes_digest(path.read_bytes())


def _claim_directory(parent: Path, name: str) -> Path:
    root = parent.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise KnownSiteDockerTargetError("private evidence root is unavailable")
    path = root / name
    try:
        path.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise KnownSiteDockerTargetError(f"private target path {name!r} already exists") from exc
    return path


def _write_bytes_exclusive(path: Path, body: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(body)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("exclusive write made no progress")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json_exclusive(path: Path, payload: Mapping[str, object]) -> None:
    body = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _write_bytes_exclusive(path, body)


def _ensure_no_plaintext_flags(payload: object, flags: Sequence[str] | object) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    for flag in flags:  # type: ignore[union-attr]
        if str(flag) in encoded:
            raise KnownSiteDockerTargetError("refusing to persist a plaintext runtime flag")


def _command_receipt(
    result: CommandResult,
    *,
    operation: str,
    timeout: int,
    docker_host_sha256: str | None,
    docker_executable_sha256: str | None,
) -> dict[str, object]:
    stdout = result.stdout[:_MAX_COMMAND_STREAM_BYTES]
    stderr = result.stderr[:_MAX_COMMAND_STREAM_BYTES]
    return {
        "operation": operation,
        "argv": list(result.command),
        "returncode": result.returncode,
        "elapsed_seconds": result.elapsed_seconds,
        "timeout_seconds": timeout,
        "docker_host_sha256": docker_host_sha256,
        "docker_executable_sha256": docker_executable_sha256,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stdout_size": len(result.stdout),
        "stderr_size": len(result.stderr),
        "stdout_truncated": len(result.stdout) > len(stdout),
        "stderr_truncated": len(result.stderr) > len(stderr),
    }


def _require_success(result: CommandResult, operation: str) -> None:
    if result.returncode != 0:
        raise KnownSiteDockerTargetError(f"{operation} failed with status {result.returncode}")


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise KnownSiteDockerTargetError(f"{label} is not a nonnegative integer")
    return value


def _decoded_lines(value: bytes) -> set[str]:
    return {line for line in value.decode("ascii", errors="ignore").splitlines() if line}


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise KnownSiteDockerTargetError(f"{label} is malformed")
    return value


def _string_mapping(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise KnownSiteDockerTargetError("Docker labels are malformed")
    return dict(value)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _safe_error(exc: BaseException) -> str:
    value = str(exc).strip() or type(exc).__name__
    return _FLAG_RE.sub("[REDACTED]", value)[:1000]


def _unreachable_prepared() -> _PreparedState:
    raise AssertionError("gateway cannot start before target preparation")


__all__ = [
    "AgentNetworkPin",
    "AgentNetworkResolver",
    "DockerKnownSiteTargetBackend",
    "KnownSiteDockerConfiguration",
    "KnownSiteDockerTargetError",
    "PinnedDockerImage",
]
