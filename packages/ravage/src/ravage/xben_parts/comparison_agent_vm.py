"""Fail-closed lifecycle for a per-row agent Docker authority.

The XBEN target daemon is deliberately *not* the daemon handed to Ravage or
Strix.  This module owns the mechanically verifiable part of that separation:

* a controller must create a never-before-used Colima/Lima VM for one row;
* the VM's Docker daemon must have an empty mutable inventory before loading;
* a live label canary on the target daemon must be absent from the agent daemon;
* only the row's digest-pinned tool archive may be loaded; and
* the VM, socket, and controller profile must be absent after teardown.

Network mediation is intentionally an injected, independently validated
boundary.  Ordinary Colima/Lima NAT is not sufficient: Docker access is
root-equivalent inside the guest and a guest firewall can be changed by an
agent.  A relay controller is accepted only when it supplies the exact
host-enforced contract below (for example QEMU slirp ``restrict=on`` with only
explicit guest forwards, or a source-bound macOS PF anchor) and its active
negative canaries all pass.  No permissive or "trust me" fallback exists.

This module does not install Colima/Lima, pull images, or create randomness.
Concrete controller implementations may perform those actions only when the
campaign executor explicitly invokes them after the frozen contract is valid.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import urlsplit

from ravage.xben_parts.comparison_target import CommandResult, CommandRunner

AGENT_DAEMON_PROVISION_SCHEMA: Final = "ravage.xben.agent-daemon-provision.v2"
AGENT_DAEMON_TEARDOWN_SCHEMA: Final = "ravage.xben.agent-daemon-teardown.v2"
HOST_RELAY_RECEIPT_SCHEMA: Final = "ravage.xben.host-relay-receipt.v2"
HOST_RELAY_PROBE_SCHEMA: Final = "ravage.xben.host-relay-active-probes.v2"
AGENT_DAEMON_PROVISION_FILE: Final = "agent-daemon-provision.json"
AGENT_DAEMON_TEARDOWN_FILE: Final = "agent-daemon-teardown.json"
HOST_RELAY_PROBE_FILE: Final = "host-relay-active-probes.json"

CONTROLLER_KIND: Final = "colima-lima-ephemeral-v1"
HOST_ENFORCEMENT_KINDS: Final = frozenset(
    {
        "qemu-slirp-restrict-on-guestfwd-v1",
        "macos-pf-vm-source-anchor-v1",
    }
)
TARGET_CANARY_LABEL: Final = "com.ravage.evaluator.target-metadata-canary"
ROW_LABEL: Final = "com.ravage.evaluator.primary-row"
DEFAULT_NETWORKS: Final = frozenset({"bridge", "host", "none"})
DEFAULT_NETWORK_DRIVERS: Final = {
    "bridge": "bridge",
    "host": "host",
    "none": "null",
}
_RELAY_PROBE_EXPECTATIONS: Final = {
    "target_meter_path": ("agent-vm", "allowed"),
    "outer_model_gateway_path": ("outer-macos-sandbox", "allowed"),
    "default_ipv4_egress": ("agent-vm", "denied"),
    "dns_egress": ("agent-vm", "denied"),
    "direct_target_path": ("agent-vm", "denied"),
    "direct_model_provider_path": ("agent-vm", "denied"),
}

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_RAW_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ROW_ID_RE = re.compile(r"primary-(?:00[1-9]|0[1-9][0-9]|[1-9][0-9]{2})")
_PROFILE_RE = re.compile(r"ravage-agent-primary-[0-9]{3}-[0-9a-f]{16,64}")
_NETWORK_RE = re.compile(r"ravage-agent-net-primary-[0-9]{3}-[0-9a-f]{16,64}")
_IMAGE_REFERENCE_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_SAFE_LABEL_VALUE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{15,127}")
_MAX_RECEIPT_BYTES = 8 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024 * 1024


class AgentVmIsolationError(RuntimeError):
    """The per-row agent VM cannot prove its frozen isolation contract."""


@dataclass(frozen=True)
class DockerAuthorityPin:
    """One live Docker endpoint and the precommitted daemon identity digest."""

    docker_executable: Path
    docker_executable_sha256: str
    docker_host: str
    daemon_identity_sha256: str

    def validate(self) -> None:
        executable = _regular_executable(self.docker_executable, "Docker executable")
        if _sha256_file(executable, maximum_bytes=2 * 1024 * 1024 * 1024) != _digest(
            self.docker_executable_sha256,
            "Docker executable digest",
        ):
            raise AgentVmIsolationError("Docker executable differs from its frozen digest")
        _unix_socket_from_host(self.docker_host, require_live=True)
        _digest(self.daemon_identity_sha256, "Docker daemon identity digest")


@dataclass(frozen=True)
class AgentToolArchivePin:
    """Offline OCI input admitted to a pristine row daemon."""

    image_reference: str
    expected_image_id: str
    archive: Path
    archive_sha256: str
    platform: str = "linux/amd64"

    def validate(self) -> Path:
        if _IMAGE_REFERENCE_RE.fullmatch(self.image_reference) is None:
            raise AgentVmIsolationError("agent tool image is not digest-pinned")
        _digest(self.expected_image_id, "agent tool image ID")
        if self.platform != "linux/amd64":
            raise AgentVmIsolationError("agent tool platform must be linux/amd64")
        archive = _regular_file(self.archive, "agent tool OCI archive")
        if archive.stat().st_size > _MAX_ARCHIVE_BYTES:
            raise AgentVmIsolationError("agent tool OCI archive exceeds its fixed byte limit")
        if _sha256_file(archive, maximum_bytes=_MAX_ARCHIVE_BYTES) != _digest(
            self.archive_sha256,
            "agent tool OCI archive digest",
        ):
            raise AgentVmIsolationError("agent tool OCI archive differs from its frozen digest")
        return archive


@dataclass(frozen=True)
class AgentVmStaticPin:
    """Rehashable local inputs that define every future agent VM authority."""

    agent_docker_executable: Path
    agent_docker_executable_sha256: str
    controller_implementation: Path
    controller_implementation_sha256: str
    controller_policy: Path
    controller_policy_sha256: str
    supervisor_runtime_manifest: Path
    supervisor_runtime_manifest_sha256: str
    vm_template: Path
    vm_template_sha256: str
    base_image: Path
    base_image_sha256: str
    relay_implementation: Path
    relay_implementation_sha256: str
    relay_policy: Path
    relay_policy_sha256: str
    relay_enforcement_kind: str
    platform: str = "linux/amd64"

    def validate(self) -> dict[str, object]:
        """Rehash every mutable input and return its exact receipt projection."""

        if self.platform != "linux/amd64":
            raise AgentVmIsolationError("agent VM static platform must be linux/amd64")
        if self.relay_enforcement_kind not in HOST_ENFORCEMENT_KINDS:
            raise AgentVmIsolationError("agent VM relay enforcement kind is unsupported")
        paths = (
            (
                _regular_executable(
                    self.agent_docker_executable,
                    "agent Docker executable",
                ),
                self.agent_docker_executable_sha256,
                "agent Docker executable",
                2 * 1024 * 1024 * 1024,
            ),
            (
                _regular_file(
                    self.controller_implementation,
                    "agent VM controller implementation",
                ),
                self.controller_implementation_sha256,
                "agent VM controller implementation",
                2 * 1024 * 1024 * 1024,
            ),
            (
                _regular_file(self.controller_policy, "agent VM controller policy"),
                self.controller_policy_sha256,
                "agent VM controller policy",
                _MAX_RECEIPT_BYTES,
            ),
            (
                _regular_file(
                    self.supervisor_runtime_manifest,
                    "agent VM supervisor runtime manifest",
                ),
                self.supervisor_runtime_manifest_sha256,
                "agent VM supervisor runtime manifest",
                _MAX_RECEIPT_BYTES,
            ),
            (
                _regular_file(self.vm_template, "agent VM template"),
                self.vm_template_sha256,
                "agent VM template",
                _MAX_RECEIPT_BYTES,
            ),
            (
                _regular_file(self.base_image, "agent VM base image"),
                self.base_image_sha256,
                "agent VM base image",
                _MAX_ARCHIVE_BYTES,
            ),
            (
                _regular_file(self.relay_implementation, "host relay implementation"),
                self.relay_implementation_sha256,
                "host relay implementation",
                2 * 1024 * 1024 * 1024,
            ),
            (
                _regular_file(self.relay_policy, "host relay policy"),
                self.relay_policy_sha256,
                "host relay policy",
                _MAX_RECEIPT_BYTES,
            ),
        )
        for path, expected, label, maximum in paths:
            if _sha256_file(path, maximum_bytes=maximum) != _digest(expected, f"{label} digest"):
                raise AgentVmIsolationError(f"{label} differs from its frozen digest")
        return {
            "agent_docker_executable_sha256": self.agent_docker_executable_sha256,
            "controller_implementation_sha256": self.controller_implementation_sha256,
            "controller_policy_sha256": self.controller_policy_sha256,
            "supervisor_runtime_manifest_sha256": self.supervisor_runtime_manifest_sha256,
            "vm_template_sha256": self.vm_template_sha256,
            "base_image_sha256": self.base_image_sha256,
            "base_image_platform": self.platform,
            "base_image_local_only": True,
            "download_or_update_performed": False,
            "relay_implementation_sha256": self.relay_implementation_sha256,
            "relay_policy_sha256": self.relay_policy_sha256,
            "relay_enforcement_kind": self.relay_enforcement_kind,
        }


@dataclass(frozen=True)
class PlannedAgentVm:
    """Side-effect-free address reserved for one future VM generation."""

    row_id: str
    profile_name: str
    generation_id: str
    docker_host: str
    docker_socket: Path
    agent_network: str


@dataclass(frozen=True)
class LiveAgentVm:
    """Controller handle returned only after the VM and daemon are live."""

    plan: PlannedAgentVm
    controller_kind: str
    controller_start_receipt: Mapping[str, object]


@dataclass(frozen=True)
class HostRelayLease:
    """Host-enforced target relay attached to one agent VM generation."""

    receipt: Mapping[str, object]
    probe_transcript_path: Path
    agent_visible_target_url: str
    agent_visible_model_gateway_url: str


class EphemeralAgentVmController(Protocol):
    """A narrow interface implementable by a pinned Colima/Lima supervisor."""

    @property
    def kind(self) -> str: ...

    @property
    def policy_sha256(self) -> str: ...

    def plan(self, *, row_id: str, generation_id: str) -> PlannedAgentVm: ...

    def profile_absent(self, plan: PlannedAgentVm) -> bool: ...

    def start(self, plan: PlannedAgentVm) -> LiveAgentVm: ...

    def cleanup_failed_start(self, plan: PlannedAgentVm) -> Mapping[str, object]: ...

    def stop_and_delete(self, live: LiveAgentVm) -> Mapping[str, object]: ...


class HostEnforcedRelayController(Protocol):
    """Host-owned network boundary; guest-admin policy is never accepted."""

    @property
    def policy_sha256(self) -> str: ...

    def start(
        self,
        *,
        live: LiveAgentVm,
        target_meter_url: str,
        model_gateway_url: str,
        evidence_dir: Path,
    ) -> HostRelayLease: ...

    def verify(self, *, live: LiveAgentVm, lease: HostRelayLease) -> Mapping[str, object]: ...

    def stop(self, *, live: LiveAgentVm, lease: HostRelayLease) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class AgentDaemonLease:
    """All state required to bind an adapter and later prove destruction."""

    live: LiveAgentVm
    relay: HostRelayLease
    tool: AgentToolArchivePin
    target_daemon_identity_sha256: str
    agent_daemon_identity_sha256: str
    provision_receipt_path: Path
    provision_receipt_sha256: str
    agent_authority: DockerAuthorityPin
    target_canary_selector: str
    target_canary_inventory: Mapping[str, Sequence[str]]

    @property
    def docker_host(self) -> str:
        return self.live.plan.docker_host

    @property
    def agent_network(self) -> str:
        return self.live.plan.agent_network

    @property
    def agent_visible_target_url(self) -> str:
        return self.relay.agent_visible_target_url

    @property
    def agent_visible_model_gateway_url(self) -> str:
        return self.relay.agent_visible_model_gateway_url


@dataclass(frozen=True)
class AgentVmPlanExpectation:
    """Secret-free precommitment to a future row VM endpoint."""

    row_id: str
    profile_name: str
    generation_id: str
    docker_host_sha256: str
    docker_socket_path_sha256: str
    agent_network: str

    @classmethod
    def from_plan(cls, plan: PlannedAgentVm) -> AgentVmPlanExpectation:
        return cls(
            row_id=plan.row_id,
            profile_name=plan.profile_name,
            generation_id=plan.generation_id,
            docker_host_sha256=_sha256_text(plan.docker_host),
            docker_socket_path_sha256=_sha256_text(str(plan.docker_socket)),
            agent_network=plan.agent_network,
        )


@dataclass(frozen=True)
class AgentDaemonLifecycleExpectation:
    """Frozen values an offline verifier must bind to one lifecycle pair."""

    row_id: str
    plan: AgentVmPlanExpectation
    static_inputs: Mapping[str, object]
    target_daemon_identity_sha256: str
    target_canary_selector_sha256: str
    target_meter_url_sha256: str
    model_gateway_url_sha256: str
    agent_visible_target_url_sha256: str
    agent_visible_model_gateway_url_sha256: str
    tool_image_reference: str
    tool_image_id: str
    tool_archive_sha256: str
    tool_platform: str = "linux/amd64"


@dataclass
class EphemeralAgentDaemonManager:
    """Provision and destroy exactly one pristine Docker authority per row."""

    target_authority: DockerAuthorityPin
    static_pin: AgentVmStaticPin
    controller: EphemeralAgentVmController
    relay_controller: HostEnforcedRelayController
    runner: CommandRunner
    trusted_path: str
    inspect_timeout_seconds: int = 30
    lifecycle_timeout_seconds: int = 180
    _active: dict[str, AgentDaemonLease] = field(default_factory=dict, init=False)
    _seen_generations: set[str] = field(default_factory=set, init=False)
    _seen_agent_daemon_identities: set[str] = field(default_factory=set, init=False)
    _poisoned: bool = field(default=False, init=False)

    def planned_vm(self, *, row_id: str, generation_id: str) -> PlannedAgentVm:
        """Return a deterministic endpoint without starting or inspecting a VM."""

        if self._poisoned:
            raise AgentVmIsolationError("agent VM manager is poisoned by an unproven teardown")
        _validate_row_and_generation(row_id, generation_id)
        if self.controller.kind != CONTROLLER_KIND:
            raise AgentVmIsolationError("agent VM controller kind is unsupported")
        if _digest(
            self.static_pin.controller_policy_sha256,
            "agent VM controller policy digest",
        ) != _digest(
            self.controller.policy_sha256,
            "live agent VM controller policy digest",
        ):
            raise AgentVmIsolationError("agent VM controller policy differs from its pin")
        if _digest(self.static_pin.relay_policy_sha256, "host relay policy digest") != _digest(
            self.relay_controller.policy_sha256,
            "live host relay policy digest",
        ):
            raise AgentVmIsolationError("host relay policy differs from its pin")
        plan = self.controller.plan(row_id=row_id, generation_id=generation_id)
        _validate_plan(plan, row_id=row_id, generation_id=generation_id)
        return plan

    def provision(  # noqa: PLR0913
        self,
        *,
        plan: PlannedAgentVm,
        target_canary_value: str,
        target_meter_url: str,
        model_gateway_url: str,
        tool: AgentToolArchivePin,
        evidence_dir: Path,
    ) -> AgentDaemonLease:
        """Create, attest, and populate one fresh row daemon.

        The target metadata canary must already exist on the target daemon.
        The method never creates it: the target/evaluator owns that lifecycle.
        """

        if self._poisoned:
            raise AgentVmIsolationError("agent VM manager is poisoned by an unproven teardown")
        row_id = plan.row_id
        generation_id = plan.generation_id
        _validate_row_and_generation(row_id, generation_id)
        if generation_id in self._seen_generations or row_id in self._active:
            raise AgentVmIsolationError("agent VM generation was already used")
        if _SAFE_LABEL_VALUE_RE.fullmatch(target_canary_value) is None:
            raise AgentVmIsolationError("target metadata canary value is invalid")
        target_url = _loopback_http_url(target_meter_url, "target meter URL")
        model_url = _loopback_http_url(model_gateway_url, "model gateway URL")
        archive = tool.validate()
        output = _empty_owned_directory(evidence_dir, "agent daemon evidence directory")
        provision_path = output / AGENT_DAEMON_PROVISION_FILE
        teardown_path = output / AGENT_DAEMON_TEARDOWN_FILE
        if provision_path.exists() or teardown_path.exists():
            raise AgentVmIsolationError("agent daemon evidence was already claimed")

        self.target_authority.validate()
        target_identity = _live_daemon_identity(
            self.target_authority,
            runner=self.runner,
            trusted_path=self.trusted_path,
            timeout_seconds=self.inspect_timeout_seconds,
        )
        if target_identity != self.target_authority.daemon_identity_sha256:
            raise AgentVmIsolationError("target Docker daemon identity drifted")
        selector = f"{TARGET_CANARY_LABEL}={target_canary_value}"
        target_canary_ids = _label_inventory(
            self.target_authority,
            selector=selector,
            runner=self.runner,
            trusted_path=self.trusted_path,
            timeout_seconds=self.inspect_timeout_seconds,
        )
        if not any(target_canary_ids.values()):
            raise AgentVmIsolationError("target metadata canary is not live on the target daemon")

        reproduced_plan = self.planned_vm(row_id=row_id, generation_id=generation_id)
        if reproduced_plan != plan:
            raise AgentVmIsolationError("controller plan differs from the exact frozen VM plan")
        if not self.controller.profile_absent(plan):
            self._poisoned = True
            raise AgentVmIsolationError("agent VM profile existed before its primary row")

        live: LiveAgentVm | None = None
        relay: HostRelayLease | None = None
        try:
            # Close the preflight-to-provision mutation window immediately
            # before the controller is allowed to create anything.
            static_inputs = self.static_pin.validate()
            live = self.controller.start(plan)
            _validate_live_vm(
                live,
                plan=plan,
                expected_static_inputs=static_inputs,
            )
            if not _socket_matches_plan(plan):
                raise AgentVmIsolationError("agent Docker socket is not the planned live socket")
            agent_pin = DockerAuthorityPin(
                docker_executable=self.static_pin.agent_docker_executable,
                docker_executable_sha256=self.static_pin.agent_docker_executable_sha256,
                docker_host=plan.docker_host,
                daemon_identity_sha256=_live_daemon_identity_unpinned(
                    docker_executable=self.static_pin.agent_docker_executable,
                    docker_host=plan.docker_host,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                ),
            )
            agent_identity = agent_pin.daemon_identity_sha256
            _require_distinct_authorities(self.target_authority, agent_pin)
            if agent_identity in self._seen_agent_daemon_identities:
                raise AgentVmIsolationError("agent Docker daemon identity was already used")
            # Burn the live authority as soon as it is observed. A controller
            # may not recycle a partially provisioned daemon under a new plan.
            self._seen_agent_daemon_identities.add(agent_identity)
            pristine = _daemon_inventory(
                agent_pin,
                runner=self.runner,
                trusted_path=self.trusted_path,
                timeout_seconds=self.inspect_timeout_seconds,
            )
            _require_pristine_inventory(pristine)
            invisible = _label_inventory(
                agent_pin,
                selector=selector,
                runner=self.runner,
                trusted_path=self.trusted_path,
                timeout_seconds=self.inspect_timeout_seconds,
            )
            if any(invisible.values()):
                raise AgentVmIsolationError(
                    "target metadata canary is visible through the agent Docker authority"
                )

            relay = self.relay_controller.start(
                live=live,
                target_meter_url=target_url,
                model_gateway_url=model_url,
                evidence_dir=output,
            )
            relay_receipt = validate_host_relay_receipt(
                self.relay_controller.verify(live=live, lease=relay),
                plan=plan,
                target_meter_url=target_url,
                model_gateway_url=model_url,
                probe_transcript_path=relay.probe_transcript_path,
                evidence_dir=output,
                expected_relay_policy_sha256=self.static_pin.relay_policy_sha256,
                expected_relay_implementation_sha256=(self.static_pin.relay_implementation_sha256),
                expected_enforcement_kind=self.static_pin.relay_enforcement_kind,
                agent_visible_target_url=relay.agent_visible_target_url,
                agent_visible_model_gateway_url=relay.agent_visible_model_gateway_url,
            )
            agent_network_inspection = _create_agent_network(
                agent_pin,
                plan=plan,
                runner=self.runner,
                trusted_path=self.trusted_path,
                timeout_seconds=self.inspect_timeout_seconds,
            )
            # The archive is a mutable local file. Rehash it again at the last
            # possible point before Docker is allowed to ingest its bytes.
            archive = tool.validate()
            _load_and_verify_tool(
                agent_pin,
                tool=tool,
                archive=archive,
                runner=self.runner,
                trusted_path=self.trusted_path,
                timeout_seconds=self.lifecycle_timeout_seconds,
            )
            populated = _daemon_inventory(
                agent_pin,
                runner=self.runner,
                trusted_path=self.trusted_path,
                timeout_seconds=self.inspect_timeout_seconds,
            )
            _require_populated_inventory(populated, plan=plan, tool=tool)
            if any(
                _label_inventory(
                    agent_pin,
                    selector=selector,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                ).values()
            ):
                raise AgentVmIsolationError(
                    "target metadata canary became visible through the agent Docker authority"
                )
            if (
                _label_inventory(
                    self.target_authority,
                    selector=selector,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                )
                != target_canary_ids
            ):
                raise AgentVmIsolationError("target metadata canary changed during provisioning")
            if (
                _live_daemon_identity_unpinned(
                    docker_executable=self.static_pin.agent_docker_executable,
                    docker_host=plan.docker_host,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                )
                != agent_identity
            ):
                raise AgentVmIsolationError("agent Docker daemon changed during provisioning")
            if (
                _live_daemon_identity(
                    self.target_authority,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                )
                != target_identity
            ):
                raise AgentVmIsolationError("target Docker daemon changed during provisioning")
            receipt = _document(
                {
                    "schema_version": AGENT_DAEMON_PROVISION_SCHEMA,
                    "row_id": row_id,
                    "profile_name": plan.profile_name,
                    "generation_id": generation_id,
                    "controller_kind": live.controller_kind,
                    "static_inputs": static_inputs,
                    "controller_start_receipt": dict(live.controller_start_receipt),
                    "controller_policy_sha256": self.static_pin.controller_policy_sha256,
                    "relay_policy_sha256": self.static_pin.relay_policy_sha256,
                    "docker_host_sha256": _sha256_text(plan.docker_host),
                    "docker_socket_path_sha256": _sha256_text(str(plan.docker_socket)),
                    "target_daemon_identity_sha256": target_identity,
                    "agent_daemon_identity_sha256": agent_identity,
                    "live_daemon_identities_distinct": True,
                    "target_canary_selector_sha256": _sha256_text(selector),
                    "target_canary_present_on_target": True,
                    "target_canary_stable_on_target": True,
                    "target_canary_absent_from_agent": True,
                    "target_canary_absent_from_populated_agent": True,
                    "pristine_inventory": pristine,
                    "tool_image": {
                        "reference": tool.image_reference,
                        "image_id": tool.expected_image_id,
                        "archive_sha256": tool.archive_sha256,
                        "platform": tool.platform,
                        "pull_performed": False,
                    },
                    "populated_inventory": populated,
                    "agent_network": plan.agent_network,
                    "agent_network_inspection": agent_network_inspection,
                    "relay_receipt": relay_receipt,
                    "relay_probe_transcript_path": HOST_RELAY_PROBE_FILE,
                    "relay_probe_transcript_sha256": _sha256_file(
                        relay.probe_transcript_path,
                        maximum_bytes=_MAX_RECEIPT_BYTES,
                    ),
                    "no_reuse": True,
                    "valid": True,
                }
            )
            _write_json_exclusive(provision_path, receipt)
            lease = AgentDaemonLease(
                live=live,
                relay=relay,
                tool=tool,
                target_daemon_identity_sha256=target_identity,
                agent_daemon_identity_sha256=agent_identity,
                provision_receipt_path=provision_path,
                provision_receipt_sha256=_sha256_file(
                    provision_path,
                    maximum_bytes=_MAX_RECEIPT_BYTES,
                ),
                agent_authority=agent_pin,
                target_canary_selector=selector,
                target_canary_inventory=target_canary_ids,
            )
            self._seen_generations.add(generation_id)
            self._active[row_id] = lease
            return lease
        except BaseException:
            # Provisioning has no terminal deletion receipt. Even if best-effort
            # cleanup appears to work, this manager may not advance another row.
            self._poisoned = True
            if live is not None:
                _best_effort_destroy(
                    controller=self.controller,
                    relay_controller=self.relay_controller,
                    live=live,
                    relay=relay,
                )
            else:
                _best_effort_cleanup_failed_start(
                    controller=self.controller,
                    plan=plan,
                )
            # Failed generations are burned as well. Reusing one after partial
            # provisioning would make "pristine" dependent on hidden history.
            self._seen_generations.add(generation_id)
            raise

    def teardown(self, lease: AgentDaemonLease, *, evidence_dir: Path) -> Mapping[str, object]:
        """Delete the relay and entire VM, then prove its authority is gone."""

        row_id = lease.live.plan.row_id
        if self._active.get(row_id) is not lease:
            raise AgentVmIsolationError("agent VM lease is not active or was already torn down")
        output = _owned_directory(evidence_dir, "agent daemon evidence directory")
        if lease.provision_receipt_path.parent != output:
            raise AgentVmIsolationError("agent daemon teardown escaped its evidence directory")
        teardown_path = output / AGENT_DAEMON_TEARDOWN_FILE
        if teardown_path.exists():
            raise AgentVmIsolationError("agent daemon teardown evidence already exists")

        errors: list[str] = []
        relay_stop: Mapping[str, object] | None = None
        controller_stop: Mapping[str, object] | None = None
        target_identity_stable = False
        agent_identity_stable = False
        target_canary_stable = False
        target_canary_absent_from_agent = False
        try:
            self.static_pin.validate()
            target_identity_stable = (
                _live_daemon_identity(
                    self.target_authority,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                )
                == lease.target_daemon_identity_sha256
            )
            agent_identity_stable = (
                _live_daemon_identity(
                    lease.agent_authority,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                )
                == lease.agent_daemon_identity_sha256
            )
            target_canary_stable = (
                _label_inventory(
                    self.target_authority,
                    selector=lease.target_canary_selector,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                )
                == lease.target_canary_inventory
            )
            target_canary_absent_from_agent = not any(
                _label_inventory(
                    lease.agent_authority,
                    selector=lease.target_canary_selector,
                    runner=self.runner,
                    trusted_path=self.trusted_path,
                    timeout_seconds=self.inspect_timeout_seconds,
                ).values()
            )
        except Exception:
            errors.append("pre-teardown authority/canary recheck failed")
        if not target_identity_stable:
            errors.append("target Docker daemon changed before teardown")
        if not agent_identity_stable:
            errors.append("agent Docker daemon changed before teardown")
        if not target_canary_stable:
            errors.append("target metadata canary changed before teardown")
        if not target_canary_absent_from_agent:
            errors.append("target metadata canary was visible from agent before teardown")
        try:
            relay_stop = self.relay_controller.stop(live=lease.live, lease=lease.relay)
            if not _valid_relay_stop_receipt(relay_stop, plan=lease.live.plan):
                errors.append("host relay stop receipt is invalid")
        except Exception:
            errors.append("host relay teardown failed")
        try:
            controller_stop = self.controller.stop_and_delete(lease.live)
            if not _valid_controller_stop_receipt(controller_stop, plan=lease.live.plan):
                errors.append("agent VM stop receipt is invalid")
        except Exception:
            errors.append("agent VM teardown failed")

        endpoint_dead = not _docker_endpoint_responds(
            docker_executable=self.static_pin.agent_docker_executable,
            docker_host=lease.docker_host,
            runner=self.runner,
            trusted_path=self.trusted_path,
            timeout_seconds=self.inspect_timeout_seconds,
        )
        profile_absent = self.controller.profile_absent(lease.live.plan)
        socket_absent = not lease.live.plan.docker_socket.exists()
        if not endpoint_dead:
            errors.append("agent Docker endpoint still responds after VM deletion")
        if not profile_absent:
            errors.append("agent VM profile remains after deletion")
        if not socket_absent:
            errors.append("agent Docker socket remains after VM deletion")
        receipt = _document(
            {
                "schema_version": AGENT_DAEMON_TEARDOWN_SCHEMA,
                "row_id": row_id,
                "profile_name": lease.live.plan.profile_name,
                "generation_id": lease.live.plan.generation_id,
                "controller_kind": lease.live.controller_kind,
                "controller_policy_sha256": self.static_pin.controller_policy_sha256,
                "relay_policy_sha256": self.static_pin.relay_policy_sha256,
                "provision_receipt_sha256": lease.provision_receipt_sha256,
                "pre_teardown_checks": {
                    "target_daemon_identity_stable": target_identity_stable,
                    "agent_daemon_identity_stable": agent_identity_stable,
                    "target_canary_stable_on_target": target_canary_stable,
                    "target_canary_absent_from_agent": target_canary_absent_from_agent,
                },
                "relay_stop_receipt": dict(relay_stop or {}),
                "controller_stop_receipt": dict(controller_stop or {}),
                "docker_endpoint_absent": endpoint_dead,
                "profile_absent": profile_absent,
                "socket_absent": socket_absent,
                "generation_reusable": False,
                "errors": errors,
                "valid": not errors,
            }
        )
        _write_json_exclusive(teardown_path, receipt)
        self._active.pop(row_id, None)
        if errors:
            self._poisoned = True
            raise AgentVmIsolationError("; ".join(errors))
        return receipt


def validate_host_relay_receipt(
    payload: object,
    *,
    plan: PlannedAgentVm,
    target_meter_url: str,
    model_gateway_url: str,
    probe_transcript_path: Path,
    evidence_dir: Path,
    expected_relay_policy_sha256: str,
    expected_relay_implementation_sha256: str,
    expected_enforcement_kind: str,
    agent_visible_target_url: str,
    agent_visible_model_gateway_url: str,
) -> dict[str, object]:
    """Independently reject guest-controlled or incompletely probed relays."""

    if not isinstance(payload, dict):
        raise AgentVmIsolationError("host relay receipt is not a JSON object")
    expected_fields = {
        "schema_version",
        "controller_kind",
        "relay_implementation_sha256",
        "relay_policy_sha256",
        "profile_name",
        "generation_id",
        "agent_network",
        "enforcement_kind",
        "enforced_outside_guest",
        "guest_admin_can_modify_policy",
        "default_egress_denied",
        "dns_egress_denied",
        "direct_target_path_denied",
        "direct_model_provider_path_denied",
        "target_meter_path_allowed",
        "outer_model_gateway_path_allowed",
        "target_meter_url_sha256",
        "model_gateway_url_sha256",
        "agent_visible_target_url_sha256",
        "agent_visible_model_gateway_url_sha256",
        "active_probe_transcript_sha256",
        "valid",
        "document_sha256",
    }
    if (
        set(payload) != expected_fields
        or payload.get("schema_version") != HOST_RELAY_RECEIPT_SCHEMA
    ):
        raise AgentVmIsolationError("host relay receipt fields are invalid")
    body = {key: value for key, value in payload.items() if key != "document_sha256"}
    if payload.get("document_sha256") != _sha256_bytes(_canonical_json(body)):
        raise AgentVmIsolationError("host relay receipt digest is invalid")
    if (
        payload.get("controller_kind") != CONTROLLER_KIND
        or payload.get("relay_implementation_sha256")
        != _digest(
            expected_relay_implementation_sha256,
            "expected host relay implementation digest",
        )
        or payload.get("relay_policy_sha256")
        != _digest(expected_relay_policy_sha256, "expected host relay policy digest")
        or payload.get("profile_name") != plan.profile_name
        or payload.get("generation_id") != plan.generation_id
        or payload.get("agent_network") != plan.agent_network
        or payload.get("enforcement_kind") != expected_enforcement_kind
        or expected_enforcement_kind not in HOST_ENFORCEMENT_KINDS
        or payload.get("enforced_outside_guest") is not True
        or payload.get("guest_admin_can_modify_policy") is not False
        or payload.get("default_egress_denied") is not True
        or payload.get("dns_egress_denied") is not True
        or payload.get("direct_target_path_denied") is not True
        or payload.get("direct_model_provider_path_denied") is not True
        or payload.get("target_meter_path_allowed") is not True
        or payload.get("outer_model_gateway_path_allowed") is not True
        or payload.get("valid") is not True
    ):
        raise AgentVmIsolationError("host relay is not an enforced two-gateway boundary")
    if payload.get("target_meter_url_sha256") != _sha256_text(target_meter_url):
        raise AgentVmIsolationError("host relay target-meter binding differs")
    if payload.get("model_gateway_url_sha256") != _sha256_text(model_gateway_url):
        raise AgentVmIsolationError("host relay model-gateway binding differs")
    visible_target = _agent_visible_http_url(
        agent_visible_target_url,
        "agent-visible target URL",
    )
    visible_model = _agent_visible_http_url(
        agent_visible_model_gateway_url,
        "agent-visible model gateway URL",
    )
    if (
        visible_target == target_meter_url
        or visible_model == model_gateway_url
        or visible_target == visible_model
    ):
        raise AgentVmIsolationError("host relay endpoints are not independently addressed")
    if payload.get("agent_visible_target_url_sha256") != _sha256_text(visible_target):
        raise AgentVmIsolationError("host relay agent-visible target binding differs")
    if payload.get("agent_visible_model_gateway_url_sha256") != _sha256_text(visible_model):
        raise AgentVmIsolationError("host relay agent-visible model binding differs")
    transcript_digest = _digest(
        payload.get("active_probe_transcript_sha256"),
        "relay probe transcript digest",
    )
    _digest(payload.get("relay_policy_sha256"), "host relay policy digest")
    transcript = _regular_file(probe_transcript_path, "host relay active-probe transcript")
    transcript_metadata = transcript.stat()
    if (
        transcript.parent != _owned_directory(evidence_dir, "agent daemon evidence directory")
        or transcript.name != HOST_RELAY_PROBE_FILE
        or transcript_metadata.st_uid != os.getuid()
        or stat.S_IMODE(transcript_metadata.st_mode) != 0o600
        or transcript_metadata.st_nlink != 1
        or _sha256_file(transcript, maximum_bytes=_MAX_RECEIPT_BYTES) != transcript_digest
    ):
        raise AgentVmIsolationError("host relay active-probe transcript differs")
    _validate_relay_probe_transcript(
        transcript,
        profile_name=plan.profile_name,
        generation_id=plan.generation_id,
        agent_network=plan.agent_network,
        enforcement_kind=str(payload["enforcement_kind"]),
    )
    return dict(payload)


def validate_agent_daemon_lifecycle(
    *,
    provision_path: Path,
    teardown_path: Path,
    expectation: AgentDaemonLifecycleExpectation,
) -> dict[str, object]:
    """Validate and bind a create-only lifecycle to every frozen campaign pin."""

    provision = _read_document(provision_path, AGENT_DAEMON_PROVISION_SCHEMA)
    teardown = _read_document(teardown_path, AGENT_DAEMON_TEARDOWN_SCHEMA)
    expected_row_id = expectation.row_id
    _validate_plan_expectation(expectation.plan, expected_row_id=expected_row_id)
    expected_provision_fields = {
        "schema_version",
        "row_id",
        "profile_name",
        "generation_id",
        "controller_kind",
        "static_inputs",
        "controller_start_receipt",
        "controller_policy_sha256",
        "relay_policy_sha256",
        "docker_host_sha256",
        "docker_socket_path_sha256",
        "target_daemon_identity_sha256",
        "agent_daemon_identity_sha256",
        "live_daemon_identities_distinct",
        "target_canary_selector_sha256",
        "target_canary_present_on_target",
        "target_canary_stable_on_target",
        "target_canary_absent_from_agent",
        "target_canary_absent_from_populated_agent",
        "pristine_inventory",
        "tool_image",
        "populated_inventory",
        "agent_network",
        "agent_network_inspection",
        "relay_receipt",
        "relay_probe_transcript_path",
        "relay_probe_transcript_sha256",
        "no_reuse",
        "valid",
        "document_sha256",
    }
    expected_teardown_fields = {
        "schema_version",
        "row_id",
        "profile_name",
        "generation_id",
        "controller_kind",
        "controller_policy_sha256",
        "relay_policy_sha256",
        "provision_receipt_sha256",
        "pre_teardown_checks",
        "relay_stop_receipt",
        "controller_stop_receipt",
        "docker_endpoint_absent",
        "profile_absent",
        "socket_absent",
        "generation_reusable",
        "errors",
        "valid",
        "document_sha256",
    }
    if set(provision) != expected_provision_fields or set(teardown) != expected_teardown_fields:
        raise AgentVmIsolationError("agent daemon lifecycle receipt fields are invalid")
    if provision.get("row_id") != expected_row_id or teardown.get("row_id") != expected_row_id:
        raise AgentVmIsolationError("agent daemon lifecycle row binding differs")
    if (
        provision.get("valid") is not True
        or provision.get("live_daemon_identities_distinct") is not True
        or provision.get("target_canary_present_on_target") is not True
        or provision.get("target_canary_stable_on_target") is not True
        or provision.get("target_canary_absent_from_agent") is not True
        or provision.get("target_canary_absent_from_populated_agent") is not True
        or provision.get("no_reuse") is not True
    ):
        raise AgentVmIsolationError("agent daemon provision receipt is not comparison-safe")
    _digest(provision.get("controller_policy_sha256"), "agent VM controller policy digest")
    _digest(provision.get("relay_policy_sha256"), "host relay policy digest")
    expected_static = dict(expectation.static_inputs)
    static_inputs = provision.get("static_inputs")
    if (
        not isinstance(static_inputs, dict)
        or static_inputs != expected_static
        or provision.get("controller_policy_sha256")
        != expected_static.get("controller_policy_sha256")
        or provision.get("relay_policy_sha256") != expected_static.get("relay_policy_sha256")
    ):
        raise AgentVmIsolationError("agent VM static input binding differs")
    _validate_static_input_receipt(static_inputs)
    controller_start = provision.get("controller_start_receipt")
    if not isinstance(controller_start, Mapping):
        raise AgentVmIsolationError("agent VM controller start receipt is absent")
    _validate_controller_start_receipt(
        controller_start,
        plan=expectation.plan,
        expected_static_inputs=expected_static,
    )
    if (
        provision.get("controller_kind") != CONTROLLER_KIND
        or provision.get("generation_id") != expectation.plan.generation_id
        or provision.get("profile_name") != expectation.plan.profile_name
        or provision.get("docker_host_sha256") != expectation.plan.docker_host_sha256
        or provision.get("docker_socket_path_sha256") != expectation.plan.docker_socket_path_sha256
        or provision.get("agent_network") != expectation.plan.agent_network
    ):
        raise AgentVmIsolationError("agent daemon provision differs from its frozen plan")
    target_identity = _digest(
        provision.get("target_daemon_identity_sha256"),
        "target Docker daemon identity digest",
    )
    agent_identity = _digest(
        provision.get("agent_daemon_identity_sha256"),
        "agent Docker daemon identity digest",
    )
    if target_identity == agent_identity:
        raise AgentVmIsolationError("agent daemon lifecycle authorities are not distinct")
    if target_identity != _digest(
        expectation.target_daemon_identity_sha256,
        "expected target Docker daemon identity digest",
    ):
        raise AgentVmIsolationError("agent daemon lifecycle target authority differs")
    if provision.get("target_canary_selector_sha256") != _digest(
        expectation.target_canary_selector_sha256,
        "expected target canary selector digest",
    ):
        raise AgentVmIsolationError("agent daemon lifecycle target canary differs")
    pristine = provision.get("pristine_inventory")
    if not isinstance(pristine, dict):
        raise AgentVmIsolationError("agent daemon pristine inventory is absent")
    _require_pristine_inventory(pristine)
    tool = provision.get("tool_image")
    if (
        not isinstance(tool, dict)
        or set(tool) != {"reference", "image_id", "archive_sha256", "platform", "pull_performed"}
        or not isinstance(tool.get("reference"), str)
        or _IMAGE_REFERENCE_RE.fullmatch(tool["reference"]) is None
        or tool.get("platform") != "linux/amd64"
        or tool.get("pull_performed") is not False
    ):
        raise AgentVmIsolationError("agent daemon tool-image evidence is invalid")
    _digest(tool.get("image_id"), "agent tool image ID")
    _digest(tool.get("archive_sha256"), "agent tool archive digest")
    if tool != {
        "reference": expectation.tool_image_reference,
        "image_id": expectation.tool_image_id,
        "archive_sha256": expectation.tool_archive_sha256,
        "platform": expectation.tool_platform,
        "pull_performed": False,
    }:
        raise AgentVmIsolationError("agent daemon tool image differs from its frozen row")
    populated = provision.get("populated_inventory")
    if not isinstance(populated, dict):
        raise AgentVmIsolationError("agent daemon populated inventory is absent")
    _require_populated_inventory(
        populated,
        plan=expectation.plan,
        tool=AgentToolArchivePin(
            image_reference=expectation.tool_image_reference,
            expected_image_id=expectation.tool_image_id,
            archive=Path("/offline-verifier-does-not-open-archive"),
            archive_sha256=expectation.tool_archive_sha256,
            platform=expectation.tool_platform,
        ),
    )
    agent_network = provision.get("agent_network")
    row_id = provision.get("row_id")
    network_inspection = provision.get("agent_network_inspection")
    if (
        not isinstance(agent_network, str)
        or not isinstance(row_id, str)
        or not isinstance(network_inspection, dict)
    ):
        raise AgentVmIsolationError("agent daemon internal-network evidence is absent")
    _validate_network_inspection(
        network_inspection,
        expected_name=agent_network,
        expected_row_id=row_id,
        inventory=populated,
    )
    relay = provision.get("relay_receipt")
    if not isinstance(relay, dict):
        raise AgentVmIsolationError("agent daemon host-relay receipt is absent")
    _validate_embedded_relay_receipt(relay, provision=provision)
    if (
        relay.get("relay_implementation_sha256")
        != expected_static.get("relay_implementation_sha256")
        or relay.get("relay_policy_sha256") != expected_static.get("relay_policy_sha256")
        or relay.get("enforcement_kind") != expected_static.get("relay_enforcement_kind")
        or relay.get("target_meter_url_sha256")
        != _digest(expectation.target_meter_url_sha256, "expected target meter URL digest")
        or relay.get("model_gateway_url_sha256")
        != _digest(expectation.model_gateway_url_sha256, "expected model gateway URL digest")
        or relay.get("agent_visible_target_url_sha256")
        != _digest(
            expectation.agent_visible_target_url_sha256,
            "expected agent-visible target URL digest",
        )
        or relay.get("agent_visible_model_gateway_url_sha256")
        != _digest(
            expectation.agent_visible_model_gateway_url_sha256,
            "expected agent-visible model URL digest",
        )
    ):
        raise AgentVmIsolationError("agent daemon host relay differs from frozen endpoints")
    transcript_path = provision_path.parent / HOST_RELAY_PROBE_FILE
    if (
        provision.get("relay_probe_transcript_path") != HOST_RELAY_PROBE_FILE
        or provision.get("relay_probe_transcript_sha256")
        != _sha256_file(transcript_path, maximum_bytes=_MAX_RECEIPT_BYTES)
        or relay.get("active_probe_transcript_sha256")
        != provision.get("relay_probe_transcript_sha256")
    ):
        raise AgentVmIsolationError("agent daemon relay probe transcript is invalid")
    profile_name = provision.get("profile_name")
    generation_id = provision.get("generation_id")
    agent_network = provision.get("agent_network")
    enforcement_kind = relay.get("enforcement_kind")
    if (
        not isinstance(profile_name, str)
        or not isinstance(generation_id, str)
        or not isinstance(agent_network, str)
        or not isinstance(enforcement_kind, str)
    ):
        raise AgentVmIsolationError("agent daemon relay probe binding is invalid")
    _validate_relay_probe_transcript(
        transcript_path,
        profile_name=profile_name,
        generation_id=generation_id,
        agent_network=agent_network,
        enforcement_kind=enforcement_kind,
    )
    if teardown.get("provision_receipt_sha256") != _sha256_file(
        provision_path,
        maximum_bytes=_MAX_RECEIPT_BYTES,
    ):
        raise AgentVmIsolationError("agent daemon teardown is not bound to its provision")
    if (
        teardown.get("generation_id") != provision.get("generation_id")
        or teardown.get("profile_name") != provision.get("profile_name")
        or teardown.get("controller_kind") != provision.get("controller_kind")
        or teardown.get("controller_policy_sha256") != provision.get("controller_policy_sha256")
        or teardown.get("relay_policy_sha256") != provision.get("relay_policy_sha256")
        or teardown.get("pre_teardown_checks")
        != {
            "target_daemon_identity_stable": True,
            "agent_daemon_identity_stable": True,
            "target_canary_stable_on_target": True,
            "target_canary_absent_from_agent": True,
        }
        or not _valid_relay_stop_receipt(
            teardown.get("relay_stop_receipt"),
            plan=expectation.plan,
        )
        or not _valid_controller_stop_receipt(
            teardown.get("controller_stop_receipt"),
            plan=expectation.plan,
        )
        or teardown.get("docker_endpoint_absent") is not True
        or teardown.get("profile_absent") is not True
        or teardown.get("socket_absent") is not True
        or teardown.get("generation_reusable") is not False
        or teardown.get("errors") != []
        or teardown.get("valid") is not True
    ):
        raise AgentVmIsolationError("agent daemon teardown did not prove VM destruction")
    return {
        "row_id": expected_row_id,
        "provision_document_sha256": provision["document_sha256"],
        "provision_file_sha256": _sha256_file(
            provision_path,
            maximum_bytes=_MAX_RECEIPT_BYTES,
        ),
        "teardown_document_sha256": teardown["document_sha256"],
        "teardown_file_sha256": _sha256_file(
            teardown_path,
            maximum_bytes=_MAX_RECEIPT_BYTES,
        ),
        "valid": True,
    }


def relay_receipt_document(
    *,
    plan: PlannedAgentVm,
    target_meter_url: str,
    model_gateway_url: str,
    enforcement_kind: str,
    active_probe_transcript_sha256: str,
    relay_policy_sha256: str,
    relay_implementation_sha256: str,
    agent_visible_target_url: str,
    agent_visible_model_gateway_url: str,
) -> dict[str, object]:
    """Build the only relay receipt shape accepted by the independent verifier.

    Controllers should call this *after* active positive and negative probes.
    It is public to keep fake-backed tests and future pinned supervisors byte
    compatible; calling it does not itself prove that probes occurred.
    """

    if enforcement_kind not in HOST_ENFORCEMENT_KINDS:
        raise AgentVmIsolationError("host relay enforcement kind is unsupported")
    transcript = _digest(active_probe_transcript_sha256, "relay probe transcript digest")
    policy = _digest(relay_policy_sha256, "host relay policy digest")
    implementation = _digest(
        relay_implementation_sha256,
        "host relay implementation digest",
    )
    visible_target = _agent_visible_http_url(
        agent_visible_target_url,
        "agent-visible target URL",
    )
    visible_model = _agent_visible_http_url(
        agent_visible_model_gateway_url,
        "agent-visible model gateway URL",
    )
    if (
        visible_target == target_meter_url
        or visible_model == model_gateway_url
        or visible_target == visible_model
    ):
        raise AgentVmIsolationError("host relay endpoints are not independently addressed")
    return _document(
        {
            "schema_version": HOST_RELAY_RECEIPT_SCHEMA,
            "controller_kind": CONTROLLER_KIND,
            "relay_implementation_sha256": implementation,
            "relay_policy_sha256": policy,
            "profile_name": plan.profile_name,
            "generation_id": plan.generation_id,
            "agent_network": plan.agent_network,
            "enforcement_kind": enforcement_kind,
            "enforced_outside_guest": True,
            "guest_admin_can_modify_policy": False,
            "default_egress_denied": True,
            "dns_egress_denied": True,
            "direct_target_path_denied": True,
            "direct_model_provider_path_denied": True,
            "target_meter_path_allowed": True,
            "outer_model_gateway_path_allowed": True,
            "target_meter_url_sha256": _sha256_text(target_meter_url),
            "model_gateway_url_sha256": _sha256_text(model_gateway_url),
            "agent_visible_target_url_sha256": _sha256_text(visible_target),
            "agent_visible_model_gateway_url_sha256": _sha256_text(visible_model),
            "active_probe_transcript_sha256": transcript,
            "valid": True,
        }
    )


def relay_probe_transcript_document(
    *,
    plan: PlannedAgentVm,
    enforcement_kind: str,
    target_meter_challenge_sha256: str,
    model_gateway_challenge_sha256: str,
) -> dict[str, object]:
    """Build the retained transcript after all six active probes match policy."""

    if enforcement_kind not in HOST_ENFORCEMENT_KINDS:
        raise AgentVmIsolationError("host relay enforcement kind is unsupported")
    target_challenge = _digest(
        target_meter_challenge_sha256,
        "target meter relay challenge digest",
    )
    model_challenge = _digest(
        model_gateway_challenge_sha256,
        "model gateway relay challenge digest",
    )
    if target_challenge == model_challenge:
        raise AgentVmIsolationError("relay gateway challenges must be distinct")
    probes = [
        {
            "name": name,
            "execution_boundary": boundary,
            "expected": expected,
            "matched": True,
        }
        for name, (boundary, expected) in sorted(_RELAY_PROBE_EXPECTATIONS.items())
    ]
    return _document(
        {
            "schema_version": HOST_RELAY_PROBE_SCHEMA,
            "controller_kind": CONTROLLER_KIND,
            "profile_name": plan.profile_name,
            "generation_id": plan.generation_id,
            "agent_network": plan.agent_network,
            "enforcement_kind": enforcement_kind,
            "target_meter_challenge_sha256": target_challenge,
            "model_gateway_challenge_sha256": model_challenge,
            "probes": probes,
            "all_expectations_matched": True,
        }
    )


def _validate_relay_probe_transcript(
    path: Path,
    *,
    profile_name: str,
    generation_id: str,
    agent_network: str,
    enforcement_kind: str,
) -> dict[str, object]:
    transcript = _read_document(path, HOST_RELAY_PROBE_SCHEMA)
    expected_fields = {
        "schema_version",
        "controller_kind",
        "profile_name",
        "generation_id",
        "agent_network",
        "enforcement_kind",
        "target_meter_challenge_sha256",
        "model_gateway_challenge_sha256",
        "probes",
        "all_expectations_matched",
        "document_sha256",
    }
    if set(transcript) != expected_fields:
        raise AgentVmIsolationError("host relay active-probe transcript fields are invalid")
    if (
        transcript.get("controller_kind") != CONTROLLER_KIND
        or transcript.get("profile_name") != profile_name
        or transcript.get("generation_id") != generation_id
        or transcript.get("agent_network") != agent_network
        or transcript.get("enforcement_kind") != enforcement_kind
        or enforcement_kind not in HOST_ENFORCEMENT_KINDS
        or transcript.get("all_expectations_matched") is not True
    ):
        raise AgentVmIsolationError("host relay active-probe transcript binding is invalid")
    target_challenge = _digest(
        transcript.get("target_meter_challenge_sha256"),
        "target meter relay challenge digest",
    )
    model_challenge = _digest(
        transcript.get("model_gateway_challenge_sha256"),
        "model gateway relay challenge digest",
    )
    if target_challenge == model_challenge:
        raise AgentVmIsolationError("relay gateway challenges must be distinct")

    probes = transcript.get("probes")
    if not isinstance(probes, list) or len(probes) != len(_RELAY_PROBE_EXPECTATIONS):
        raise AgentVmIsolationError("host relay active-probe set is incomplete")
    expected_probes = [
        {
            "name": name,
            "execution_boundary": boundary,
            "expected": expected,
            "matched": True,
        }
        for name, (boundary, expected) in sorted(_RELAY_PROBE_EXPECTATIONS.items())
    ]
    if probes != expected_probes:
        raise AgentVmIsolationError("host relay active-probe result is invalid")
    return transcript


def _validate_row_and_generation(row_id: str, generation_id: str) -> None:
    if _ROW_ID_RE.fullmatch(row_id) is None:
        raise AgentVmIsolationError("agent VM row ID is invalid")
    if _RAW_SHA256_RE.fullmatch(generation_id) is None:
        raise AgentVmIsolationError("agent VM generation ID must be 256-bit lowercase hex")


def _validate_plan(plan: PlannedAgentVm, *, row_id: str, generation_id: str) -> None:
    if (
        plan.row_id != row_id
        or plan.generation_id != generation_id
        or _PROFILE_RE.fullmatch(plan.profile_name) is None
        or _NETWORK_RE.fullmatch(plan.agent_network) is None
    ):
        raise AgentVmIsolationError("agent VM plan is not bound to its primary row")
    socket_path = _unix_socket_from_host(plan.docker_host, require_live=False)
    if socket_path != plan.docker_socket or not plan.docker_socket.is_absolute():
        raise AgentVmIsolationError("agent VM Docker endpoint differs from its socket plan")


def _validate_plan_expectation(
    plan: AgentVmPlanExpectation,
    *,
    expected_row_id: str,
) -> None:
    _validate_row_and_generation(plan.row_id, plan.generation_id)
    if (
        plan.row_id != expected_row_id
        or _PROFILE_RE.fullmatch(plan.profile_name) is None
        or _NETWORK_RE.fullmatch(plan.agent_network) is None
    ):
        raise AgentVmIsolationError("agent VM plan expectation is not row-bound")
    _digest(plan.docker_host_sha256, "agent VM expected Docker host digest")
    _digest(plan.docker_socket_path_sha256, "agent VM expected Docker socket digest")


def _validate_live_vm(
    live: LiveAgentVm,
    *,
    plan: PlannedAgentVm,
    expected_static_inputs: Mapping[str, object],
) -> None:
    if live.plan != plan or live.controller_kind != CONTROLLER_KIND:
        raise AgentVmIsolationError("agent VM controller returned a foreign generation")
    _validate_controller_start_receipt(
        live.controller_start_receipt,
        plan=plan,
        expected_static_inputs=expected_static_inputs,
    )


def _validate_controller_start_receipt(
    receipt: Mapping[str, object],
    *,
    plan: PlannedAgentVm | AgentVmPlanExpectation,
    expected_static_inputs: Mapping[str, object],
) -> None:
    expected_fields = {
        "kind",
        "controller_kind",
        "controller_policy_sha256",
        "controller_implementation_sha256",
        "supervisor_runtime_manifest_sha256",
        "vm_template_sha256",
        "base_image_sha256",
        "base_image_platform",
        "base_image_local_only",
        "download_or_update_performed",
        "profile_name",
        "generation_id",
        "started",
        "reused",
        "vm_platform",
        "fresh_writable_disk",
        "host_filesystem_mounts",
        "host_credential_forwarding",
        "host_docker_socket_forwarding",
        "network_policy_owner",
    }
    if (
        set(receipt) != expected_fields
        or receipt.get("kind") != "agent-vm"
        or receipt.get("controller_kind") != CONTROLLER_KIND
        or receipt.get("controller_policy_sha256")
        != expected_static_inputs.get("controller_policy_sha256")
        or receipt.get("controller_implementation_sha256")
        != expected_static_inputs.get("controller_implementation_sha256")
        or receipt.get("supervisor_runtime_manifest_sha256")
        != expected_static_inputs.get("supervisor_runtime_manifest_sha256")
        or receipt.get("vm_template_sha256") != expected_static_inputs.get("vm_template_sha256")
        or receipt.get("base_image_sha256") != expected_static_inputs.get("base_image_sha256")
        or receipt.get("base_image_platform") != "linux/amd64"
        or receipt.get("base_image_local_only") is not True
        or receipt.get("download_or_update_performed") is not False
        or receipt.get("profile_name") != plan.profile_name
        or receipt.get("generation_id") != plan.generation_id
        or receipt.get("started") is not True
        or receipt.get("reused") is not False
        or receipt.get("vm_platform") != "linux/amd64"
        or receipt.get("fresh_writable_disk") is not True
        or receipt.get("host_filesystem_mounts") != []
        or receipt.get("host_credential_forwarding") is not False
        or receipt.get("host_docker_socket_forwarding") is not False
        or receipt.get("network_policy_owner") != "outer-host-hypervisor"
    ):
        raise AgentVmIsolationError("agent VM start receipt is invalid")


def _validate_static_input_receipt(value: Mapping[str, object]) -> None:
    expected_fields = {
        "agent_docker_executable_sha256",
        "controller_implementation_sha256",
        "controller_policy_sha256",
        "supervisor_runtime_manifest_sha256",
        "vm_template_sha256",
        "base_image_sha256",
        "base_image_platform",
        "base_image_local_only",
        "download_or_update_performed",
        "relay_implementation_sha256",
        "relay_policy_sha256",
        "relay_enforcement_kind",
    }
    if (
        set(value) != expected_fields
        or value.get("base_image_platform") != "linux/amd64"
        or value.get("base_image_local_only") is not True
        or value.get("download_or_update_performed") is not False
        or value.get("relay_enforcement_kind") not in HOST_ENFORCEMENT_KINDS
    ):
        raise AgentVmIsolationError("agent VM static input receipt is invalid")
    for name in (
        "agent_docker_executable_sha256",
        "controller_implementation_sha256",
        "controller_policy_sha256",
        "supervisor_runtime_manifest_sha256",
        "vm_template_sha256",
        "base_image_sha256",
        "relay_implementation_sha256",
        "relay_policy_sha256",
    ):
        _digest(value.get(name), f"agent VM static {name}")


def _require_distinct_authorities(
    target: DockerAuthorityPin,
    agent: DockerAuthorityPin,
) -> None:
    target_socket = _unix_socket_from_host(target.docker_host, require_live=True)
    agent_socket = _unix_socket_from_host(agent.docker_host, require_live=True)
    same_socket = target_socket == agent_socket
    with _suppress_os_error():
        same_socket = same_socket or target_socket.samefile(agent_socket)
    if (
        same_socket
        or target.docker_host == agent.docker_host
        or target.daemon_identity_sha256 == agent.daemon_identity_sha256
    ):
        raise AgentVmIsolationError("target and agent Docker authorities are not distinct")


def _live_daemon_identity(
    authority: DockerAuthorityPin,
    *,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> str:
    return _live_daemon_identity_unpinned(
        docker_executable=authority.docker_executable,
        docker_host=authority.docker_host,
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )


def _live_daemon_identity_unpinned(
    *,
    docker_executable: Path,
    docker_host: str,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> str:
    result = _docker_run(
        docker_executable,
        docker_host,
        ("info", "--format", "{{json .ID}}"),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    _require_success(result, "Docker daemon identity inspection")
    try:
        identity = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentVmIsolationError("Docker daemon identity response is malformed") from exc
    if not isinstance(identity, str) or not identity or identity != identity.strip():
        raise AgentVmIsolationError("Docker daemon identity is invalid")
    return _sha256_text(identity)


def _daemon_inventory(
    authority: DockerAuthorityPin,
    *,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> dict[str, object]:
    images = _quiet_ids(
        authority,
        ("image", "ls", "--no-trunc", "--quiet"),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    containers = _quiet_ids(
        authority,
        ("container", "ls", "--all", "--no-trunc", "--quiet"),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    volumes = _quiet_names(
        authority,
        ("volume", "ls", "--quiet"),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    result = _docker_run(
        authority.docker_executable,
        authority.docker_host,
        ("network", "ls", "--no-trunc", "--format", "{{json .}}"),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    _require_success(result, "Docker network inventory")
    networks: list[dict[str, str]] = []
    try:
        lines = result.stdout.decode("utf-8").splitlines()
        for line in lines:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError
            name = item.get("Name")
            identifier = item.get("ID")
            driver = item.get("Driver")
            scope = item.get("Scope")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(identifier, str)
                or not identifier
                or not isinstance(driver, str)
                or not driver
                or not isinstance(scope, str)
                or not scope
            ):
                raise ValueError
            networks.append({"name": name, "id": identifier, "driver": driver, "scope": scope})
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentVmIsolationError("Docker network inventory is malformed") from exc
    networks.sort(key=lambda item: item["name"])
    return {
        "images": images,
        "containers": containers,
        "volumes": volumes,
        "networks": networks,
    }


def _require_pristine_inventory(value: Mapping[str, object]) -> None:
    if value.get("images") != [] or value.get("containers") != [] or value.get("volumes") != []:
        raise AgentVmIsolationError("agent Docker daemon is not pristine before row loading")
    networks = value.get("networks")
    if (
        not isinstance(networks, list)
        or {item.get("name") for item in networks if isinstance(item, dict)} != DEFAULT_NETWORKS
    ):
        raise AgentVmIsolationError("agent Docker daemon has non-default networks before loading")
    for item in networks:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "id", "driver", "scope"}
            or item.get("scope") != "local"
            or item.get("driver") != DEFAULT_NETWORK_DRIVERS.get(str(item.get("name")))
            or not isinstance(item.get("id"), str)
            or not item["id"]
        ):
            raise AgentVmIsolationError("agent Docker default-network inventory is invalid")


def _require_populated_inventory(
    value: Mapping[str, object],
    *,
    plan: PlannedAgentVm | AgentVmPlanExpectation,
    tool: AgentToolArchivePin,
) -> None:
    if (
        value.get("images") != [tool.expected_image_id]
        or value.get("containers") != []
        or value.get("volumes") != []
    ):
        raise AgentVmIsolationError("agent Docker daemon contains unexpected mutable resources")
    networks = value.get("networks")
    if (
        not isinstance(networks, list)
        or any(not isinstance(item, dict) for item in networks)
        or {item.get("name") for item in networks} != {*DEFAULT_NETWORKS, plan.agent_network}
    ):
        raise AgentVmIsolationError("agent Docker network inventory differs after provisioning")
    for item in networks:
        name = item.get("name")
        expected_driver = (
            "bridge" if name == plan.agent_network else DEFAULT_NETWORK_DRIVERS.get(str(name))
        )
        if (
            set(item) != {"name", "id", "driver", "scope"}
            or item.get("scope") != "local"
            or item.get("driver") != expected_driver
            or not isinstance(item.get("id"), str)
            or not item["id"]
        ):
            raise AgentVmIsolationError("agent Docker network inventory differs after provisioning")


def _validate_embedded_relay_receipt(
    receipt: Mapping[str, object],
    *,
    provision: Mapping[str, object],
) -> None:
    body = {key: value for key, value in receipt.items() if key != "document_sha256"}
    expected_fields = {
        "schema_version",
        "controller_kind",
        "relay_implementation_sha256",
        "relay_policy_sha256",
        "profile_name",
        "generation_id",
        "agent_network",
        "enforcement_kind",
        "enforced_outside_guest",
        "guest_admin_can_modify_policy",
        "default_egress_denied",
        "dns_egress_denied",
        "direct_target_path_denied",
        "direct_model_provider_path_denied",
        "target_meter_path_allowed",
        "outer_model_gateway_path_allowed",
        "target_meter_url_sha256",
        "model_gateway_url_sha256",
        "agent_visible_target_url_sha256",
        "agent_visible_model_gateway_url_sha256",
        "active_probe_transcript_sha256",
        "valid",
        "document_sha256",
    }
    static_inputs = provision.get("static_inputs")
    if (
        set(receipt) != expected_fields
        or not isinstance(static_inputs, Mapping)
        or receipt.get("schema_version") != HOST_RELAY_RECEIPT_SCHEMA
        or receipt.get("document_sha256") != _sha256_bytes(_canonical_json(body))
        or receipt.get("controller_kind") != provision.get("controller_kind")
        or receipt.get("relay_implementation_sha256")
        != static_inputs.get("relay_implementation_sha256")
        or receipt.get("relay_policy_sha256") != provision.get("relay_policy_sha256")
        or receipt.get("profile_name") != provision.get("profile_name")
        or receipt.get("generation_id") != provision.get("generation_id")
        or receipt.get("agent_network") != provision.get("agent_network")
        or receipt.get("enforcement_kind") != static_inputs.get("relay_enforcement_kind")
        or receipt.get("enforcement_kind") not in HOST_ENFORCEMENT_KINDS
        or receipt.get("enforced_outside_guest") is not True
        or receipt.get("guest_admin_can_modify_policy") is not False
        or receipt.get("default_egress_denied") is not True
        or receipt.get("dns_egress_denied") is not True
        or receipt.get("direct_target_path_denied") is not True
        or receipt.get("direct_model_provider_path_denied") is not True
        or receipt.get("target_meter_path_allowed") is not True
        or receipt.get("outer_model_gateway_path_allowed") is not True
        or receipt.get("valid") is not True
    ):
        raise AgentVmIsolationError("embedded host-relay receipt is invalid")
    for name in (
        "target_meter_url_sha256",
        "model_gateway_url_sha256",
        "agent_visible_target_url_sha256",
        "agent_visible_model_gateway_url_sha256",
        "active_probe_transcript_sha256",
    ):
        _digest(receipt.get(name), f"host relay {name}")


def _label_inventory(
    authority: DockerAuthorityPin,
    *,
    selector: str,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for resource, arguments in (
        ("images", ("image", "ls", "--no-trunc", "--quiet", "--filter", f"label={selector}")),
        (
            "containers",
            ("container", "ls", "--all", "--no-trunc", "--quiet", "--filter", f"label={selector}"),
        ),
        ("networks", ("network", "ls", "--no-trunc", "--quiet", "--filter", f"label={selector}")),
        ("volumes", ("volume", "ls", "--quiet", "--filter", f"label={selector}")),
    ):
        result[resource] = _quiet_names(
            authority,
            arguments,
            runner=runner,
            trusted_path=trusted_path,
            timeout_seconds=timeout_seconds,
        )
    return result


def _create_agent_network(
    authority: DockerAuthorityPin,
    *,
    plan: PlannedAgentVm,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> dict[str, object]:
    result = _docker_run(
        authority.docker_executable,
        authority.docker_host,
        (
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--label",
            f"{ROW_LABEL}={plan.row_id}",
            plan.agent_network,
        ),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    _require_success(result, "agent Docker internal-network creation")
    identifier = result.stdout.decode("utf-8", errors="replace").strip()
    if _RAW_SHA256_RE.fullmatch(identifier) is None:
        raise AgentVmIsolationError("agent Docker network creation returned no identity")
    inspected = _docker_run(
        authority.docker_executable,
        authority.docker_host,
        ("network", "inspect", plan.agent_network),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    _require_success(inspected, "agent Docker internal-network inspection")
    try:
        payload = json.loads(inspected.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentVmIsolationError(
            "agent Docker internal-network inspection is malformed"
        ) from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise AgentVmIsolationError("agent Docker internal-network inspection is ambiguous")
    item = payload[0]
    evidence: dict[str, object] = {
        "id": item.get("Id"),
        "name": item.get("Name"),
        "driver": item.get("Driver"),
        "scope": item.get("Scope"),
        "internal": item.get("Internal"),
        "attachable": item.get("Attachable"),
        "ingress": item.get("Ingress"),
        "labels": item.get("Labels"),
    }
    _validate_network_inspection(
        evidence,
        expected_name=plan.agent_network,
        expected_row_id=plan.row_id,
        expected_id=identifier,
    )
    return evidence


def _validate_network_inspection(
    value: Mapping[str, object],
    *,
    expected_name: str,
    expected_row_id: str,
    expected_id: str | None = None,
    inventory: Mapping[str, object] | None = None,
) -> None:
    identifier = value.get("id")
    if (
        set(value)
        != {"id", "name", "driver", "scope", "internal", "attachable", "ingress", "labels"}
        or not isinstance(identifier, str)
        or _RAW_SHA256_RE.fullmatch(identifier) is None
        or (expected_id is not None and identifier != expected_id)
        or value.get("name") != expected_name
        or value.get("driver") != "bridge"
        or value.get("scope") != "local"
        or value.get("internal") is not True
        or value.get("attachable") is not False
        or value.get("ingress") is not False
        or value.get("labels") != {ROW_LABEL: expected_row_id}
    ):
        raise AgentVmIsolationError("agent Docker internal-network evidence is invalid")
    if inventory is None:
        return
    networks = inventory.get("networks")
    if not isinstance(networks, list):
        raise AgentVmIsolationError("agent Docker internal-network inventory is absent")
    matches = [
        item for item in networks if isinstance(item, dict) and item.get("name") == expected_name
    ]
    if len(matches) != 1 or matches[0].get("id") != identifier:
        raise AgentVmIsolationError("agent Docker internal-network identity differs")


def _load_and_verify_tool(
    authority: DockerAuthorityPin,
    *,
    tool: AgentToolArchivePin,
    archive: Path,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> None:
    loaded = _docker_run(
        authority.docker_executable,
        authority.docker_host,
        ("image", "load", "--input", str(archive)),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    _require_success(loaded, "offline agent tool image load")
    inspected = _docker_run(
        authority.docker_executable,
        authority.docker_host,
        ("image", "inspect", tool.image_reference),
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    _require_success(inspected, "agent tool image inspection")
    try:
        payload = json.loads(inspected.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentVmIsolationError("agent tool image inspection is malformed") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise AgentVmIsolationError("agent tool image inspection is ambiguous")
    item = payload[0]
    repo_digests = item.get("RepoDigests")
    if (
        item.get("Id") != tool.expected_image_id
        or item.get("Os") != "linux"
        or item.get("Architecture") != "amd64"
        or not isinstance(repo_digests, list)
        or tool.image_reference not in repo_digests
    ):
        raise AgentVmIsolationError("loaded agent tool image differs from its frozen identity")


def _docker_endpoint_responds(
    *,
    docker_executable: Path,
    docker_host: str,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> bool:
    try:
        result = _docker_run(
            docker_executable,
            docker_host,
            ("info", "--format", "{{json .ID}}"),
            runner=runner,
            trusted_path=trusted_path,
            timeout_seconds=timeout_seconds,
        )
    except Exception:
        return False
    return result.returncode == 0


def _docker_run(
    executable: Path,
    docker_host: str,
    arguments: Sequence[str],
    *,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> CommandResult:
    environment = {
        "PATH": _trusted_path(trusted_path),
        "LC_ALL": "C",
        "LANG": "C",
        "DOCKER_HOST": docker_host,
    }
    return runner.run(
        (str(executable), "--host", docker_host, *arguments),
        cwd=Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp"),
        environment=environment,
        timeout_seconds=timeout_seconds,
    )


def _quiet_ids(
    authority: DockerAuthorityPin,
    arguments: Sequence[str],
    *,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> list[str]:
    values = _quiet_names(
        authority,
        arguments,
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    if any(_SHA256_RE.fullmatch(value) is None for value in values):
        raise AgentVmIsolationError("Docker resource inventory contains an invalid ID")
    return values


def _quiet_names(
    authority: DockerAuthorityPin,
    arguments: Sequence[str],
    *,
    runner: CommandRunner,
    trusted_path: str,
    timeout_seconds: int,
) -> list[str]:
    result = _docker_run(
        authority.docker_executable,
        authority.docker_host,
        arguments,
        runner=runner,
        trusted_path=trusted_path,
        timeout_seconds=timeout_seconds,
    )
    _require_success(result, "Docker resource inventory")
    try:
        values = result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AgentVmIsolationError("Docker resource inventory is malformed") from exc
    if any(not value or value != value.strip() or "\x00" in value for value in values):
        raise AgentVmIsolationError("Docker resource inventory contains an invalid value")
    return sorted(set(values))


def _socket_matches_plan(plan: PlannedAgentVm) -> bool:
    try:
        actual = _unix_socket_from_host(plan.docker_host, require_live=True)
    except AgentVmIsolationError:
        return False
    return actual == plan.docker_socket


def _unix_socket_from_host(value: str, *, require_live: bool) -> Path:
    try:
        split = urlsplit(value)
    except ValueError as exc:
        raise AgentVmIsolationError("Docker host is malformed") from exc
    if (
        split.scheme != "unix"
        or split.netloc
        or not split.path
        or split.query
        or split.fragment
        or "\x00" in value
    ):
        raise AgentVmIsolationError("Docker host must be a credential-free Unix socket URL")
    path = Path(split.path)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise AgentVmIsolationError("Docker socket path must be canonical and absolute")
    try:
        if path.resolve(strict=False) != path:
            raise AgentVmIsolationError("Docker socket path must be canonical and absolute")
    except OSError as exc:
        raise AgentVmIsolationError("Docker socket path is unavailable") from exc
    if not require_live:
        return path
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise AgentVmIsolationError("Docker socket is unavailable") from exc
    if not stat.S_ISSOCK(metadata.st_mode):
        raise AgentVmIsolationError("Docker endpoint is not a Unix socket")
    return path


def _loopback_http_url(value: str, label: str) -> str:
    try:
        split = urlsplit(value)
        port = split.port
    except ValueError as exc:
        raise AgentVmIsolationError(f"{label} is malformed") from exc
    if (
        split.scheme != "http"
        or split.hostname not in {"127.0.0.1", "localhost", "::1"}
        or port is None
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
    ):
        raise AgentVmIsolationError(f"{label} must use an exact evaluator loopback endpoint")
    return value.rstrip("/")


def _agent_visible_http_url(value: str, label: str) -> str:
    try:
        split = urlsplit(value)
        port = split.port
    except ValueError as exc:
        raise AgentVmIsolationError(f"{label} is malformed") from exc
    if (
        split.scheme != "http"
        or not split.hostname
        or port is None
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
    ):
        raise AgentVmIsolationError(f"{label} must be an exact credential-free HTTP endpoint")
    normalized = value.rstrip("/")
    if normalized != value:
        raise AgentVmIsolationError(f"{label} must not contain a trailing slash")
    return normalized


def _valid_relay_stop_receipt(
    value: object,
    *,
    plan: PlannedAgentVm | AgentVmPlanExpectation,
) -> bool:
    expected_fields = {
        "kind",
        "profile_name",
        "generation_id",
        "agent_network",
        "stopped",
        "deleted",
        "agent_visible_target_endpoint_absent",
        "agent_visible_model_endpoint_absent",
    }
    return bool(
        isinstance(value, Mapping)
        and set(value) == expected_fields
        and value.get("kind") == "host-relay"
        and value.get("profile_name") == plan.profile_name
        and value.get("generation_id") == plan.generation_id
        and value.get("agent_network") == plan.agent_network
        and value.get("stopped") is True
        and value.get("deleted") is True
        and value.get("agent_visible_target_endpoint_absent") is True
        and value.get("agent_visible_model_endpoint_absent") is True
    )


def _valid_controller_stop_receipt(
    value: object,
    *,
    plan: PlannedAgentVm | AgentVmPlanExpectation,
) -> bool:
    expected_fields = {
        "kind",
        "profile_name",
        "generation_id",
        "stopped",
        "deleted",
    }
    return bool(
        isinstance(value, Mapping)
        and set(value) == expected_fields
        and value.get("kind") == "agent-vm"
        and value.get("profile_name") == plan.profile_name
        and value.get("generation_id") == plan.generation_id
        and value.get("stopped") is True
        and value.get("deleted") is True
    )


def _best_effort_destroy(
    *,
    controller: EphemeralAgentVmController,
    relay_controller: HostEnforcedRelayController,
    live: LiveAgentVm,
    relay: HostRelayLease | None,
) -> None:
    if relay is not None:
        try:
            relay_controller.stop(live=live, lease=relay)
        except Exception:
            pass
    try:
        controller.stop_and_delete(live)
    except Exception:
        pass


def _best_effort_cleanup_failed_start(
    *,
    controller: EphemeralAgentVmController,
    plan: PlannedAgentVm,
) -> None:
    """Ask the pinned supervisor to remove resources created before start raised."""

    try:
        controller.cleanup_failed_start(plan)
    except Exception:
        pass


def _read_document(path: Path, schema: str) -> dict[str, object]:
    raw = _regular_file(path, "agent daemon lifecycle receipt").read_bytes()
    if len(raw) > _MAX_RECEIPT_BYTES:
        raise AgentVmIsolationError("agent daemon lifecycle receipt is too large")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentVmIsolationError("agent daemon lifecycle receipt is malformed") from exc
    if not isinstance(value, dict) or value.get("schema_version") != schema:
        raise AgentVmIsolationError("agent daemon lifecycle receipt schema is invalid")
    document_digest = value.get("document_sha256")
    body = {key: item for key, item in value.items() if key != "document_sha256"}
    if document_digest != _sha256_bytes(_canonical_json(body)):
        raise AgentVmIsolationError("agent daemon lifecycle receipt digest is invalid")
    if raw != _canonical_json(value) + b"\n":
        raise AgentVmIsolationError("agent daemon lifecycle receipt is not canonical JSON")
    return value


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _document(value: Mapping[str, object]) -> dict[str, object]:
    body = dict(value)
    body["document_sha256"] = _sha256_bytes(_canonical_json(body))
    return body


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentVmIsolationError("agent VM evidence is not canonical JSON") from exc


def _write_json_exclusive(path: Path, value: Mapping[str, object]) -> None:
    body = _canonical_json(value) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _regular_file(path: Path, label: str) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise AgentVmIsolationError(f"{label} must not be a symlink")
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise AgentVmIsolationError(f"{label} is unavailable") from exc
    if not resolved.is_file():
        raise AgentVmIsolationError(f"{label} is not a regular file")
    return resolved


def _regular_executable(path: Path, label: str) -> Path:
    resolved = _regular_file(path, label)
    if not os.access(resolved, os.X_OK):
        raise AgentVmIsolationError(f"{label} is not executable")
    return resolved


def _owned_directory(path: Path, label: str) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise AgentVmIsolationError(f"{label} must not be a symlink")
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise AgentVmIsolationError(f"{label} is unavailable") from exc
    metadata = resolved.stat()
    if (
        not resolved.is_dir()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AgentVmIsolationError(f"{label} must be evaluator-owned mode 0700")
    return resolved


def _empty_owned_directory(path: Path, label: str) -> Path:
    resolved = _owned_directory(path, label)
    if any(resolved.iterdir()):
        raise AgentVmIsolationError(f"{label} must be empty")
    return resolved


def _sha256_file(path: Path, *, maximum_bytes: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise AgentVmIsolationError("hashed file exceeds its fixed byte limit")
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AgentVmIsolationError(f"{label} is invalid")
    return value


def _trusted_path(value: str) -> str:
    if not value or "\x00" in value:
        raise AgentVmIsolationError("trusted PATH is invalid")
    parts = value.split(os.pathsep)
    if any(not part or not Path(part).is_absolute() for part in parts):
        raise AgentVmIsolationError("trusted PATH entries must be absolute")
    return value


def _require_success(result: CommandResult, label: str) -> None:
    if result.returncode != 0:
        raise AgentVmIsolationError(f"{label} failed")


class _suppress_os_error:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> bool:
        return isinstance(exception, OSError)


__all__ = [
    "AGENT_DAEMON_PROVISION_FILE",
    "AGENT_DAEMON_PROVISION_SCHEMA",
    "AGENT_DAEMON_TEARDOWN_FILE",
    "AGENT_DAEMON_TEARDOWN_SCHEMA",
    "AgentDaemonLease",
    "AgentDaemonLifecycleExpectation",
    "AgentToolArchivePin",
    "AgentVmIsolationError",
    "AgentVmPlanExpectation",
    "AgentVmStaticPin",
    "CONTROLLER_KIND",
    "DockerAuthorityPin",
    "EphemeralAgentDaemonManager",
    "EphemeralAgentVmController",
    "HOST_ENFORCEMENT_KINDS",
    "HOST_RELAY_PROBE_FILE",
    "HOST_RELAY_PROBE_SCHEMA",
    "HOST_RELAY_RECEIPT_SCHEMA",
    "HostEnforcedRelayController",
    "HostRelayLease",
    "LiveAgentVm",
    "PlannedAgentVm",
    "TARGET_CANARY_LABEL",
    "relay_probe_transcript_document",
    "relay_receipt_document",
    "validate_agent_daemon_lifecycle",
    "validate_host_relay_receipt",
]
