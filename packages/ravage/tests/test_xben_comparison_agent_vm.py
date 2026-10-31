from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import ravage.xben_parts.comparison_agent_vm as agent_vm
from ravage.xben_parts.comparison_agent_vm import (
    CONTROLLER_KIND,
    TARGET_CANARY_LABEL,
    AgentDaemonLease,
    AgentDaemonLifecycleExpectation,
    AgentToolArchivePin,
    AgentVmPlanExpectation,
    AgentVmStaticPin,
    AgentVmIsolationError,
    DockerAuthorityPin,
    EphemeralAgentDaemonManager,
    HOST_RELAY_PROBE_FILE,
    HostRelayLease,
    LiveAgentVm,
    PlannedAgentVm,
    relay_probe_transcript_document,
    relay_receipt_document,
    validate_agent_daemon_lifecycle,
    validate_host_relay_receipt,
)
from ravage.xben_parts.comparison_target import CommandResult

ROW_ID = "primary-001"
GENERATION = "1" * 64
TOOL_ID = "sha256:" + "2" * 64
TOOL_REFERENCE = "registry.invalid/tool@sha256:" + "3" * 64
TARGET_URL = "http://127.0.0.1:49161"
MODEL_URL = "http://127.0.0.1:49162/v1"
AGENT_TARGET_URL = "http://target-relay.agent.internal:18080"
AGENT_MODEL_URL = "http://model-relay.agent.internal:18081/v1"
CANARY_VALUE = "row-canary-0123456789abcdef"
CONTROLLER_POLICY = "sha256:" + hashlib.sha256(b"{}\n").hexdigest()
RELAY_POLICY = "sha256:" + hashlib.sha256(b'{"relay":true}\n').hexdigest()
RELAY_IMPLEMENTATION = "sha256:" + hashlib.sha256(b"# pinned relay\n").hexdigest()
NETWORK_ID = "c" * 64


def _digest(value: bytes | str) -> str:
    body = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _rewrite_document(path: Path, value: Mapping[str, object]) -> None:
    body = {key: item for key, item in value.items() if key != "document_sha256"}
    body["document_sha256"] = _digest(
        json.dumps(
            body,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    path.write_bytes(json.dumps(body, separators=(",", ":"), sort_keys=True).encode() + b"\n")
    path.chmod(0o600)


def _write_probe_transcript(path: Path, plan: PlannedAgentVm) -> None:
    document = relay_probe_transcript_document(
        plan=plan,
        enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
        target_meter_challenge_sha256="sha256:" + "a" * 64,
        model_gateway_challenge_sha256="sha256:" + "b" * 64,
    )
    path.write_bytes(
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    path.chmod(0o600)


@pytest.fixture(autouse=True)
def _fake_unix_socket_stat(monkeypatch: pytest.MonkeyPatch) -> None:
    def socket_path(value: str, *, require_live: bool) -> Path:
        path = Path(value.removeprefix("unix://"))
        if require_live and not path.exists():
            raise AgentVmIsolationError("Docker socket is unavailable")
        return path

    monkeypatch.setattr(agent_vm, "_unix_socket_from_host", socket_path)


@dataclass
class _Controller:
    socket_path: Path
    static_inputs: Mapping[str, object]
    started: bool = False
    unsafe_host_mount: bool = False
    raise_after_partial_start: bool = False
    failed_start_cleanup_calls: int = 0
    generations: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return CONTROLLER_KIND

    @property
    def policy_sha256(self) -> str:
        return str(self.static_inputs["controller_policy_sha256"])

    def plan(self, *, row_id: str, generation_id: str) -> PlannedAgentVm:
        suffix = row_id.removeprefix("primary-")
        return PlannedAgentVm(
            row_id=row_id,
            profile_name=f"ravage-agent-primary-{suffix}-{generation_id}",
            generation_id=generation_id,
            docker_host=f"unix://{self.socket_path}",
            docker_socket=self.socket_path,
            agent_network=f"ravage-agent-net-primary-{suffix}-{generation_id}",
        )

    def profile_absent(self, plan: PlannedAgentVm) -> bool:
        del plan
        return not self.started and not self.socket_path.exists()

    def start(self, plan: PlannedAgentVm) -> LiveAgentVm:
        assert not self.started
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.touch()
        self.started = True
        self.generations.append(plan.generation_id)
        if self.raise_after_partial_start:
            raise RuntimeError("controller failed after creating its profile")
        return LiveAgentVm(
            plan=plan,
            controller_kind=CONTROLLER_KIND,
            controller_start_receipt={
                "kind": "agent-vm",
                "controller_kind": CONTROLLER_KIND,
                "controller_policy_sha256": self.policy_sha256,
                "controller_implementation_sha256": self.static_inputs[
                    "controller_implementation_sha256"
                ],
                "supervisor_runtime_manifest_sha256": self.static_inputs[
                    "supervisor_runtime_manifest_sha256"
                ],
                "vm_template_sha256": self.static_inputs["vm_template_sha256"],
                "base_image_sha256": self.static_inputs["base_image_sha256"],
                "base_image_platform": "linux/amd64",
                "base_image_local_only": True,
                "download_or_update_performed": False,
                "profile_name": plan.profile_name,
                "generation_id": plan.generation_id,
                "started": True,
                "reused": False,
                "vm_platform": "linux/amd64",
                "fresh_writable_disk": True,
                "host_filesystem_mounts": ["/Users"] if self.unsafe_host_mount else [],
                "host_credential_forwarding": False,
                "host_docker_socket_forwarding": False,
                "network_policy_owner": "outer-host-hypervisor",
            },
        )

    def cleanup_failed_start(self, plan: PlannedAgentVm) -> Mapping[str, object]:
        self.failed_start_cleanup_calls += 1
        self.started = False
        self.socket_path.unlink(missing_ok=True)
        return {
            "kind": "agent-vm-failed-start-cleanup",
            "profile_name": plan.profile_name,
            "generation_id": plan.generation_id,
            "deleted": True,
        }

    def stop_and_delete(self, live: LiveAgentVm) -> Mapping[str, object]:
        self.started = False
        self.socket_path.unlink(missing_ok=True)
        return {
            "kind": "agent-vm",
            "profile_name": live.plan.profile_name,
            "generation_id": live.plan.generation_id,
            "stopped": True,
            "deleted": True,
        }


@dataclass
class _Relay:
    mutate: str | None = None
    stopped: bool = False
    policy_digest: str = RELAY_POLICY
    implementation_digest: str = RELAY_IMPLEMENTATION
    receipt_target_url: str = AGENT_TARGET_URL
    stop_profile_override: str | None = None

    @property
    def policy_sha256(self) -> str:
        return self.policy_digest

    def start(
        self,
        *,
        live: LiveAgentVm,
        target_meter_url: str,
        model_gateway_url: str,
        evidence_dir: Path,
    ) -> HostRelayLease:
        transcript_path = evidence_dir / HOST_RELAY_PROBE_FILE
        _write_probe_transcript(transcript_path, live.plan)
        receipt = relay_receipt_document(
            plan=live.plan,
            target_meter_url=target_meter_url,
            model_gateway_url=model_gateway_url,
            enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            active_probe_transcript_sha256=_digest(transcript_path.read_bytes()),
            relay_policy_sha256=self.policy_digest,
            relay_implementation_sha256=self.implementation_digest,
            agent_visible_target_url=self.receipt_target_url,
            agent_visible_model_gateway_url=AGENT_MODEL_URL,
        )
        if self.mutate is not None:
            receipt[self.mutate] = not bool(receipt[self.mutate])
        return HostRelayLease(
            receipt=receipt,
            probe_transcript_path=transcript_path,
            agent_visible_target_url=AGENT_TARGET_URL,
            agent_visible_model_gateway_url=AGENT_MODEL_URL,
        )

    def verify(self, *, live: LiveAgentVm, lease: HostRelayLease) -> Mapping[str, object]:
        del live
        return lease.receipt

    def stop(self, *, live: LiveAgentVm, lease: HostRelayLease) -> Mapping[str, object]:
        del lease
        self.stopped = True
        return {
            "kind": "host-relay",
            "profile_name": self.stop_profile_override or live.plan.profile_name,
            "generation_id": live.plan.generation_id,
            "agent_network": live.plan.agent_network,
            "stopped": True,
            "deleted": True,
            "agent_visible_target_endpoint_absent": True,
            "agent_visible_model_endpoint_absent": True,
        }


@dataclass
class _DockerRunner:
    target_host: str
    agent_host: str
    tool: AgentToolArchivePin
    controller: _Controller
    same_daemon: bool = False
    dirty_agent: bool = False
    leak_canary: bool = False
    tool_leaks_canary_after_load: bool = False
    wrong_loaded_image: bool = False
    network_not_internal: bool = False
    endpoint_survives: bool = False
    network_created: bool = False
    image_loaded: bool = False
    commands: list[tuple[str, ...]] = field(default_factory=list)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        del cwd, timeout_seconds
        argv = tuple(command)
        self.commands.append(argv)
        assert argv[1] == "--host"
        host = argv[2]
        assert environment["DOCKER_HOST"] == host
        args = argv[3:]
        is_target = host == self.target_host
        if args == ("info", "--format", "{{json .ID}}"):
            if not is_target and not self.controller.started and not self.endpoint_survives:
                return CommandResult(argv, 1, stderr=b"gone")
            identity = "target-daemon" if is_target or self.same_daemon else "agent-daemon"
            return CommandResult(argv, 0, json.dumps(identity).encode())

        label_filter = next(
            (item for item in args if item.startswith(f"label={TARGET_CANARY_LABEL}=")),
            None,
        )
        if label_filter is not None:
            resource = args[0]
            visible = is_target and resource == "network"
            if (
                not is_target
                and (self.leak_canary or (self.tool_leaks_canary_after_load and self.image_loaded))
                and resource == "network"
            ):
                visible = True
            return CommandResult(argv, 0, b"canary-id\n" if visible else b"")

        if args == ("image", "ls", "--no-trunc", "--quiet"):
            images: list[str] = []
            if not is_target and self.dirty_agent and not self.image_loaded:
                images.append("sha256:" + "9" * 64)
            if not is_target and self.image_loaded:
                images.append(self.tool.expected_image_id)
            return CommandResult(argv, 0, ("\n".join(images) + ("\n" if images else "")).encode())
        if args == ("container", "ls", "--all", "--no-trunc", "--quiet"):
            return CommandResult(argv, 0)
        if args == ("volume", "ls", "--quiet"):
            return CommandResult(argv, 0)
        if args == ("network", "ls", "--no-trunc", "--format", "{{json .}}"):
            names = ["bridge", "host", "none"]
            if self.network_created:
                names.append(
                    self.controller.plan(row_id=ROW_ID, generation_id=GENERATION).agent_network
                )
            body = b"".join(
                json.dumps(
                    {
                        "Name": name,
                        "ID": NETWORK_ID
                        if name.startswith("ravage-agent-net-")
                        else f"network-{index}",
                        "Driver": (
                            "bridge"
                            if name not in {"host", "none"}
                            else "null"
                            if name == "none"
                            else "host"
                        ),
                        "Scope": "local",
                    }
                ).encode()
                + b"\n"
                for index, name in enumerate(names)
            )
            return CommandResult(argv, 0, body)
        if args[:2] == ("network", "create"):
            self.network_created = True
            return CommandResult(argv, 0, (NETWORK_ID + "\n").encode())
        if args[:2] == ("network", "inspect"):
            plan = self.controller.plan(row_id=ROW_ID, generation_id=GENERATION)
            payload = [
                {
                    "Id": NETWORK_ID,
                    "Name": plan.agent_network,
                    "Driver": "bridge",
                    "Scope": "local",
                    "Internal": not self.network_not_internal,
                    "Attachable": False,
                    "Ingress": False,
                    "Labels": {agent_vm.ROW_LABEL: ROW_ID},
                }
            ]
            return CommandResult(argv, 0, json.dumps(payload).encode())
        if args[:3] == ("image", "load", "--input"):
            self.image_loaded = True
            return CommandResult(argv, 0, b"Loaded image\n")
        if args == ("image", "inspect", self.tool.image_reference):
            image_id = (
                "sha256:" + "8" * 64 if self.wrong_loaded_image else self.tool.expected_image_id
            )
            payload = [
                {
                    "Id": image_id,
                    "Os": "linux",
                    "Architecture": "amd64",
                    "RepoDigests": [self.tool.image_reference],
                }
            ]
            return CommandResult(argv, 0, json.dumps(payload).encode())
        raise AssertionError(f"unexpected Docker command: {args!r}")


@dataclass
class _Fixture:
    manager: EphemeralAgentDaemonManager
    controller: _Controller
    relay: _Relay
    runner: _DockerRunner
    tool: AgentToolArchivePin
    static_pin: AgentVmStaticPin
    plan: PlannedAgentVm
    target_socket_path: Path
    evidence: Path

    def close(self) -> None:
        self.target_socket_path.unlink(missing_ok=True)


def _fixture(tmp_path: Path, *, relay: _Relay | None = None) -> _Fixture:
    target_docker = tmp_path / "docker-target"
    target_docker.write_text("#!/bin/sh\n# target\n", encoding="utf-8")
    target_docker.chmod(0o700)
    agent_docker = tmp_path / "docker-agent"
    agent_docker.write_text("#!/bin/sh\n# agent\n", encoding="utf-8")
    agent_docker.chmod(0o700)
    controller_implementation = tmp_path / "controller.py"
    controller_implementation.write_text("# pinned controller\n", encoding="utf-8")
    controller_policy = tmp_path / "controller-policy.json"
    controller_policy.write_text("{}\n", encoding="utf-8")
    supervisor_manifest = tmp_path / "supervisor-runtime.json"
    supervisor_manifest.write_text("{}\n", encoding="utf-8")
    vm_template = tmp_path / "template.yaml"
    vm_template.write_text("arch: x86_64\n", encoding="utf-8")
    base_image = tmp_path / "base.qcow2"
    base_image.write_bytes(b"frozen base image")
    relay_implementation = tmp_path / "relay.py"
    relay_implementation.write_text("# pinned relay\n", encoding="utf-8")
    relay_policy = tmp_path / "relay-policy.json"
    relay_policy.write_text('{"relay":true}\n', encoding="utf-8")
    static_pin = AgentVmStaticPin(
        agent_docker_executable=agent_docker,
        agent_docker_executable_sha256=_digest(agent_docker.read_bytes()),
        controller_implementation=controller_implementation,
        controller_implementation_sha256=_digest(controller_implementation.read_bytes()),
        controller_policy=controller_policy,
        controller_policy_sha256=CONTROLLER_POLICY,
        supervisor_runtime_manifest=supervisor_manifest,
        supervisor_runtime_manifest_sha256=_digest(supervisor_manifest.read_bytes()),
        vm_template=vm_template,
        vm_template_sha256=_digest(vm_template.read_bytes()),
        base_image=base_image,
        base_image_sha256=_digest(base_image.read_bytes()),
        relay_implementation=relay_implementation,
        relay_implementation_sha256=RELAY_IMPLEMENTATION,
        relay_policy=relay_policy,
        relay_policy_sha256=RELAY_POLICY,
        relay_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
    )
    target_socket_path = tmp_path / "target.sock"
    target_socket_path.touch()
    agent_socket_path = tmp_path / "agent.sock"
    archive = tmp_path / "tool.tar"
    archive.write_bytes(b"frozen OCI archive")
    tool = AgentToolArchivePin(
        image_reference=TOOL_REFERENCE,
        expected_image_id=TOOL_ID,
        archive=archive,
        archive_sha256=_digest(archive.read_bytes()),
    )
    target_host = f"unix://{target_socket_path}"
    agent_host = f"unix://{agent_socket_path}"
    controller = _Controller(agent_socket_path, static_pin.validate())
    selected_relay = relay or _Relay()
    runner = _DockerRunner(
        target_host=target_host,
        agent_host=agent_host,
        tool=tool,
        controller=controller,
    )
    authority = DockerAuthorityPin(
        docker_executable=target_docker,
        docker_executable_sha256=_digest(target_docker.read_bytes()),
        docker_host=target_host,
        daemon_identity_sha256=_digest("target-daemon"),
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    manager = EphemeralAgentDaemonManager(
        target_authority=authority,
        static_pin=static_pin,
        controller=controller,
        relay_controller=selected_relay,
        runner=runner,
        trusted_path="/usr/bin:/bin",
    )
    plan = controller.plan(row_id=ROW_ID, generation_id=GENERATION)
    return _Fixture(
        manager,
        controller,
        selected_relay,
        runner,
        tool,
        static_pin,
        plan,
        target_socket_path,
        evidence,
    )


def _provision(fixture: _Fixture) -> AgentDaemonLease:
    return fixture.manager.provision(
        plan=fixture.plan,
        target_canary_value=CANARY_VALUE,
        target_meter_url=TARGET_URL,
        model_gateway_url=MODEL_URL,
        tool=fixture.tool,
        evidence_dir=fixture.evidence,
    )


def _expectation(fixture: _Fixture) -> AgentDaemonLifecycleExpectation:
    return AgentDaemonLifecycleExpectation(
        row_id=ROW_ID,
        plan=AgentVmPlanExpectation.from_plan(fixture.plan),
        static_inputs=fixture.static_pin.validate(),
        target_daemon_identity_sha256=_digest("target-daemon"),
        target_canary_selector_sha256=_digest(f"{TARGET_CANARY_LABEL}={CANARY_VALUE}"),
        target_meter_url_sha256=_digest(TARGET_URL),
        model_gateway_url_sha256=_digest(MODEL_URL),
        agent_visible_target_url_sha256=_digest(AGENT_TARGET_URL),
        agent_visible_model_gateway_url_sha256=_digest(AGENT_MODEL_URL),
        tool_image_reference=TOOL_REFERENCE,
        tool_image_id=TOOL_ID,
        tool_archive_sha256=fixture.tool.archive_sha256,
    )


def test_ephemeral_agent_daemon_proves_pristine_load_and_terminal_deletion(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    try:
        lease = _provision(fixture)
        assert lease.docker_host == fixture.runner.agent_host
        assert lease.agent_visible_target_url == AGENT_TARGET_URL
        assert lease.agent_visible_model_gateway_url == AGENT_MODEL_URL
        provision = json.loads(lease.provision_receipt_path.read_bytes())
        assert provision["target_canary_absent_from_agent"] is True
        assert provision["pristine_inventory"]["images"] == []
        assert provision["tool_image"]["reference"] == TOOL_REFERENCE
        assert provision["controller_start_receipt"]["fresh_writable_disk"] is True
        assert provision["static_inputs"] == fixture.static_pin.validate()
        agent_commands = [
            command
            for command in fixture.runner.commands
            if command[2] == fixture.runner.agent_host
        ]
        assert agent_commands
        assert all(
            command[0] == str(fixture.static_pin.agent_docker_executable)
            for command in agent_commands
        )

        teardown = fixture.manager.teardown(lease, evidence_dir=fixture.evidence)
        assert teardown["docker_endpoint_absent"] is True
        assert teardown["profile_absent"] is True
        assert teardown["socket_absent"] is True
        joined = validate_agent_daemon_lifecycle(
            provision_path=fixture.evidence / "agent-daemon-provision.json",
            teardown_path=fixture.evidence / "agent-daemon-teardown.json",
            expectation=_expectation(fixture),
        )
        assert joined["valid"] is True
        with pytest.raises(AgentVmIsolationError, match="already used"):
            _provision(fixture)
    finally:
        fixture.close()


def test_provision_rejects_endpoint_plan_not_exactly_precommitted(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        foreign = PlannedAgentVm(
            **{
                **fixture.plan.__dict__,
                "docker_host": f"unix://{tmp_path / 'foreign.sock'}",
                "docker_socket": tmp_path / "foreign.sock",
            }
        )
        with pytest.raises(AgentVmIsolationError, match="exact frozen VM plan"):
            fixture.manager.provision(
                plan=foreign,
                target_canary_value=CANARY_VALUE,
                target_meter_url=TARGET_URL,
                model_gateway_url=MODEL_URL,
                tool=fixture.tool,
                evidence_dir=fixture.evidence,
            )
        assert fixture.controller.generations == []
    finally:
        fixture.close()


def test_provision_rehashes_static_inputs_immediately_before_start(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        fixture.static_pin.vm_template.write_text("mutated: true\n", encoding="utf-8")
        with pytest.raises(AgentVmIsolationError, match="template differs"):
            _provision(fixture)
        assert fixture.controller.generations == []
    finally:
        fixture.close()


def test_partial_controller_start_is_cleaned_and_generation_is_poisoned(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    fixture.controller.raise_after_partial_start = True
    try:
        with pytest.raises(RuntimeError, match="failed after creating"):
            _provision(fixture)
        assert fixture.controller.failed_start_cleanup_calls == 1
        assert fixture.controller.started is False
        assert not fixture.plan.docker_socket.exists()
        with pytest.raises(AgentVmIsolationError, match="poisoned"):
            fixture.manager.planned_vm(row_id="primary-002", generation_id="4" * 64)
    finally:
        fixture.close()


def test_provision_binds_actual_agent_visible_relay_endpoint(tmp_path: Path) -> None:
    relay = _Relay(receipt_target_url="http://unrelated-relay.agent.internal:19000")
    fixture = _fixture(tmp_path, relay=relay)
    try:
        with pytest.raises(AgentVmIsolationError, match="agent-visible target binding"):
            _provision(fixture)
        assert fixture.controller.started is False
        assert fixture.relay.stopped is True
    finally:
        fixture.close()


def test_manager_rejects_agent_daemon_identity_reused_by_a_later_row(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        lease = _provision(fixture)
        fixture.manager.teardown(lease, evidence_dir=fixture.evidence)
        second_evidence = tmp_path / "evidence-second"
        second_evidence.mkdir(mode=0o700)
        second_plan = fixture.manager.planned_vm(
            row_id="primary-002",
            generation_id="4" * 64,
        )
        with pytest.raises(AgentVmIsolationError, match="daemon identity was already used"):
            fixture.manager.provision(
                plan=second_plan,
                target_canary_value=CANARY_VALUE,
                target_meter_url=TARGET_URL,
                model_gateway_url=MODEL_URL,
                tool=fixture.tool,
                evidence_dir=second_evidence,
            )
        assert fixture.controller.started is False
    finally:
        fixture.close()


def test_manager_rejects_agent_vm_with_host_filesystem_mount(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.controller.unsafe_host_mount = True
    try:
        with pytest.raises(AgentVmIsolationError, match="start receipt is invalid"):
            _provision(fixture)
        assert fixture.controller.started is False
        with pytest.raises(AgentVmIsolationError, match="poisoned by an unproven teardown"):
            fixture.manager.planned_vm(row_id="primary-002", generation_id="4" * 64)
    finally:
        fixture.close()


@pytest.mark.parametrize(
    ("option", "message"),
    [
        ("same_daemon", "authorities are not distinct"),
        ("dirty_agent", "not pristine"),
        ("leak_canary", "canary is visible"),
        ("tool_leaks_canary_after_load", "canary became visible"),
        ("wrong_loaded_image", "differs from its frozen identity"),
        ("network_not_internal", "internal-network evidence is invalid"),
    ],
)
def test_provision_rejects_adversarial_authority_states(
    tmp_path: Path,
    option: str,
    message: str,
) -> None:
    fixture = _fixture(tmp_path)
    setattr(fixture.runner, option, True)
    try:
        with pytest.raises(AgentVmIsolationError, match=message):
            _provision(fixture)
        assert fixture.controller.started is False
        assert GENERATION in fixture.controller.generations
        with pytest.raises(AgentVmIsolationError, match="poisoned by an unproven teardown"):
            fixture.manager.planned_vm(row_id="primary-002", generation_id="4" * 64)
    finally:
        fixture.close()


def test_relay_receipt_rejects_guest_controlled_policy_even_with_stale_digest(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    try:
        plan = fixture.controller.plan(row_id=ROW_ID, generation_id=GENERATION)
        transcript = fixture.evidence / HOST_RELAY_PROBE_FILE
        _write_probe_transcript(transcript, plan)
        receipt = relay_receipt_document(
            plan=plan,
            target_meter_url=TARGET_URL,
            model_gateway_url=MODEL_URL,
            enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            active_probe_transcript_sha256=_digest(transcript.read_bytes()),
            relay_policy_sha256=RELAY_POLICY,
            relay_implementation_sha256=RELAY_IMPLEMENTATION,
            agent_visible_target_url=AGENT_TARGET_URL,
            agent_visible_model_gateway_url=AGENT_MODEL_URL,
        )
        assert (
            validate_host_relay_receipt(
                receipt,
                plan=plan,
                target_meter_url=TARGET_URL,
                model_gateway_url=MODEL_URL,
                probe_transcript_path=transcript,
                evidence_dir=fixture.evidence,
                expected_relay_policy_sha256=RELAY_POLICY,
                expected_relay_implementation_sha256=RELAY_IMPLEMENTATION,
                expected_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
                agent_visible_target_url=AGENT_TARGET_URL,
                agent_visible_model_gateway_url=AGENT_MODEL_URL,
            )["valid"]
            is True
        )
        forged = dict(receipt)
        forged["guest_admin_can_modify_policy"] = True
        with pytest.raises(AgentVmIsolationError, match="digest is invalid"):
            validate_host_relay_receipt(
                forged,
                plan=plan,
                target_meter_url=TARGET_URL,
                model_gateway_url=MODEL_URL,
                probe_transcript_path=transcript,
                evidence_dir=fixture.evidence,
                expected_relay_policy_sha256=RELAY_POLICY,
                expected_relay_implementation_sha256=RELAY_IMPLEMENTATION,
                expected_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
                agent_visible_target_url=AGENT_TARGET_URL,
                agent_visible_model_gateway_url=AGENT_MODEL_URL,
            )
    finally:
        fixture.close()


def test_manager_rejects_relay_negative_canary_failure(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, relay=_Relay(mutate="default_egress_denied"))
    try:
        with pytest.raises(AgentVmIsolationError, match="digest is invalid"):
            _provision(fixture)
        assert fixture.relay.stopped is True
        assert fixture.controller.started is False
    finally:
        fixture.close()


def test_relay_validator_rejects_forged_active_probe_transcript(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        plan = fixture.controller.plan(row_id=ROW_ID, generation_id=GENERATION)
        transcript = fixture.evidence / HOST_RELAY_PROBE_FILE
        document = relay_probe_transcript_document(
            plan=plan,
            enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            target_meter_challenge_sha256="sha256:" + "a" * 64,
            model_gateway_challenge_sha256="sha256:" + "b" * 64,
        )
        probes = document["probes"]
        assert isinstance(probes, list)
        first_probe = probes[0]
        assert isinstance(first_probe, dict)
        first_probe["matched"] = False
        body = {key: value for key, value in document.items() if key != "document_sha256"}
        document["document_sha256"] = _digest(
            json.dumps(
                body,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        transcript.write_bytes(
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        )
        transcript.chmod(0o600)
        receipt = relay_receipt_document(
            plan=plan,
            target_meter_url=TARGET_URL,
            model_gateway_url=MODEL_URL,
            enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            active_probe_transcript_sha256=_digest(transcript.read_bytes()),
            relay_policy_sha256=RELAY_POLICY,
            relay_implementation_sha256=RELAY_IMPLEMENTATION,
            agent_visible_target_url=AGENT_TARGET_URL,
            agent_visible_model_gateway_url=AGENT_MODEL_URL,
        )
        with pytest.raises(AgentVmIsolationError, match="active-probe result is invalid"):
            validate_host_relay_receipt(
                receipt,
                plan=plan,
                target_meter_url=TARGET_URL,
                model_gateway_url=MODEL_URL,
                probe_transcript_path=transcript,
                evidence_dir=fixture.evidence,
                expected_relay_policy_sha256=RELAY_POLICY,
                expected_relay_implementation_sha256=RELAY_IMPLEMENTATION,
                expected_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
                agent_visible_target_url=AGENT_TARGET_URL,
                agent_visible_model_gateway_url=AGENT_MODEL_URL,
            )
    finally:
        fixture.close()


def test_relay_validator_rejects_noncanonical_probe_transcript(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        plan = fixture.controller.plan(row_id=ROW_ID, generation_id=GENERATION)
        transcript = fixture.evidence / HOST_RELAY_PROBE_FILE
        document = relay_probe_transcript_document(
            plan=plan,
            enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            target_meter_challenge_sha256="sha256:" + "a" * 64,
            model_gateway_challenge_sha256="sha256:" + "b" * 64,
        )
        transcript.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        transcript.chmod(0o600)
        receipt = relay_receipt_document(
            plan=plan,
            target_meter_url=TARGET_URL,
            model_gateway_url=MODEL_URL,
            enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            active_probe_transcript_sha256=_digest(transcript.read_bytes()),
            relay_policy_sha256=RELAY_POLICY,
            relay_implementation_sha256=RELAY_IMPLEMENTATION,
            agent_visible_target_url=AGENT_TARGET_URL,
            agent_visible_model_gateway_url=AGENT_MODEL_URL,
        )
        with pytest.raises(AgentVmIsolationError, match="not canonical JSON"):
            validate_host_relay_receipt(
                receipt,
                plan=plan,
                target_meter_url=TARGET_URL,
                model_gateway_url=MODEL_URL,
                probe_transcript_path=transcript,
                evidence_dir=fixture.evidence,
                expected_relay_policy_sha256=RELAY_POLICY,
                expected_relay_implementation_sha256=RELAY_IMPLEMENTATION,
                expected_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
                agent_visible_target_url=AGENT_TARGET_URL,
                agent_visible_model_gateway_url=AGENT_MODEL_URL,
            )
    finally:
        fixture.close()


@pytest.mark.parametrize("policy", ["controller", "relay"])
def test_manager_rejects_unpinned_vm_or_relay_policy(tmp_path: Path, policy: str) -> None:
    fixture = _fixture(tmp_path)
    try:
        if policy == "controller":
            fixture.manager.static_pin = AgentVmStaticPin(
                **{
                    **fixture.static_pin.__dict__,
                    "controller_policy_sha256": "sha256:" + "7" * 64,
                }
            )
        else:
            fixture.manager.static_pin = AgentVmStaticPin(
                **{
                    **fixture.static_pin.__dict__,
                    "relay_policy_sha256": "sha256:" + "7" * 64,
                }
            )
        with pytest.raises(AgentVmIsolationError, match="policy differs from its pin"):
            fixture.manager.planned_vm(row_id=ROW_ID, generation_id=GENERATION)
        assert fixture.controller.generations == []
    finally:
        fixture.close()


def test_teardown_receipt_is_invalid_if_agent_endpoint_survives(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        lease = _provision(fixture)
        fixture.runner.endpoint_survives = True
        with pytest.raises(AgentVmIsolationError, match="still responds"):
            fixture.manager.teardown(lease, evidence_dir=fixture.evidence)
        payload = json.loads((fixture.evidence / "agent-daemon-teardown.json").read_bytes())
        assert payload["valid"] is False
        with pytest.raises(AgentVmIsolationError, match="did not prove VM destruction"):
            validate_agent_daemon_lifecycle(
                provision_path=fixture.evidence / "agent-daemon-provision.json",
                teardown_path=fixture.evidence / "agent-daemon-teardown.json",
                expectation=_expectation(fixture),
            )
    finally:
        fixture.close()


def test_teardown_rechecks_canary_separation_after_agent_workload(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        lease = _provision(fixture)
        fixture.runner.leak_canary = True
        with pytest.raises(AgentVmIsolationError, match="visible from agent before teardown"):
            fixture.manager.teardown(lease, evidence_dir=fixture.evidence)
        payload = json.loads((fixture.evidence / "agent-daemon-teardown.json").read_bytes())
        assert payload["pre_teardown_checks"]["target_canary_absent_from_agent"] is False
        assert fixture.controller.started is False
    finally:
        fixture.close()


def test_offline_validator_rejects_extra_populated_image_even_if_rehashed(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    try:
        lease = _provision(fixture)
        fixture.manager.teardown(lease, evidence_dir=fixture.evidence)
        provision_path = fixture.evidence / "agent-daemon-provision.json"
        teardown_path = fixture.evidence / "agent-daemon-teardown.json"
        provision = json.loads(provision_path.read_bytes())
        provision["populated_inventory"]["images"].append("sha256:" + "9" * 64)
        _rewrite_document(provision_path, provision)
        teardown = json.loads(teardown_path.read_bytes())
        teardown["provision_receipt_sha256"] = _digest(provision_path.read_bytes())
        _rewrite_document(teardown_path, teardown)

        with pytest.raises(AgentVmIsolationError, match="unexpected mutable resources"):
            validate_agent_daemon_lifecycle(
                provision_path=provision_path,
                teardown_path=teardown_path,
                expectation=_expectation(fixture),
            )
    finally:
        fixture.close()


def test_strict_relay_stop_receipt_must_bind_exact_generation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, relay=_Relay(stop_profile_override="foreign-profile"))
    try:
        lease = _provision(fixture)
        with pytest.raises(AgentVmIsolationError, match="stop receipt is invalid"):
            fixture.manager.teardown(lease, evidence_dir=fixture.evidence)
        payload = json.loads((fixture.evidence / "agent-daemon-teardown.json").read_bytes())
        assert payload["valid"] is False
    finally:
        fixture.close()


def test_relay_validator_rejects_normal_unrestricted_colima_nat(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        plan = fixture.controller.plan(row_id=ROW_ID, generation_id=GENERATION)
        transcript = fixture.evidence / HOST_RELAY_PROBE_FILE
        _write_probe_transcript(transcript, plan)
        receipt = relay_receipt_document(
            plan=plan,
            target_meter_url=TARGET_URL,
            model_gateway_url=MODEL_URL,
            enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            active_probe_transcript_sha256=_digest(transcript.read_bytes()),
            relay_policy_sha256=RELAY_POLICY,
            relay_implementation_sha256=RELAY_IMPLEMENTATION,
            agent_visible_target_url=AGENT_TARGET_URL,
            agent_visible_model_gateway_url=AGENT_MODEL_URL,
        )
        body = dict(receipt)
        body.pop("document_sha256")
        body["enforcement_kind"] = "colima-default-nat"
        body["document_sha256"] = _digest(
            json.dumps(
                body,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        with pytest.raises(AgentVmIsolationError, match="two-gateway boundary"):
            validate_host_relay_receipt(
                body,
                plan=plan,
                target_meter_url=TARGET_URL,
                model_gateway_url=MODEL_URL,
                probe_transcript_path=transcript,
                evidence_dir=fixture.evidence,
                expected_relay_policy_sha256=RELAY_POLICY,
                expected_relay_implementation_sha256=RELAY_IMPLEMENTATION,
                expected_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
                agent_visible_target_url=AGENT_TARGET_URL,
                agent_visible_model_gateway_url=AGENT_MODEL_URL,
            )
    finally:
        fixture.close()
