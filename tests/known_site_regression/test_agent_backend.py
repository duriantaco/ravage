# ruff: noqa: ANN001,ANN201,ARG002,ARG005,EM101,FBT001,PLR0913,PLR2004,SLF001,TRY003
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from ravage.xben_parts.external_comparison import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    TARGET_URL_ENV,
    ExternalAgentCommand,
    ExternalExecutionLimits,
    ExternalProcessReceiptContract,
    ExternalProcessResult,
    ProcessIsolation,
)

from tools.known_site_regression import agent_backend as backend_module
from tools.known_site_regression.agent_backend import CanonicalKnownSiteAgentBackend
from tools.known_site_regression.harness import (
    AgentArmContext,
    AgentVmPlanPin,
    AgentVmPolicyPin,
    DockerDaemonPin,
    DockerSeparationPolicy,
    KnownSiteSystemPin,
)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _system_pin() -> KnownSiteSystemPin:
    return KnownSiteSystemPin(
        origin_url="https://github.com/duriantaco/ravage.git",
        commit="a" * 40,
        tree="b" * 40,
        runtime_manifest_sha256="sha256:" + "c" * 64,
        executable_sha256="sha256:" + "d" * 64,
        tool_image_reference="registry.example/ravage@sha256:" + "e" * 64,
        tool_image_id="sha256:" + "f" * 64,
        tool_image_archive_sha256="sha256:" + "0" * 64,
    )


def _docker_policy() -> DockerSeparationPolicy:
    return DockerSeparationPolicy(
        target=DockerDaemonPin(
            docker_executable_sha256="sha256:" + "1" * 64,
            docker_socket_path_sha256="sha256:" + "2" * 64,
            docker_host_sha256="sha256:" + "3" * 64,
            daemon_identity_sha256="sha256:" + "4" * 64,
        ),
        agent_vm=AgentVmPolicyPin(
            docker_executable_sha256="sha256:" + "5" * 64,
            controller_kind="colima-lima-ephemeral-v1",
            controller_implementation_sha256="sha256:" + "6" * 64,
            controller_policy_sha256="sha256:" + "7" * 64,
            supervisor_executable_sha256="sha256:" + "8" * 64,
            supervisor_runtime_manifest_sha256="sha256:" + "0" * 64,
            vm_template_sha256="sha256:" + "9" * 64,
            base_image_sha256="sha256:" + "a" * 64,
            relay_implementation_sha256="sha256:" + "b" * 64,
            relay_policy_sha256="sha256:" + "c" * 64,
            relay_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
            plans={
                "primary-001": AgentVmPlanPin(
                    generation_id="1" * 64,
                    profile_name="ravage-agent-primary-001-" + "1" * 16,
                    docker_socket_path_sha256=_digest("/var/run/docker.sock"),
                    docker_host_sha256=_digest("unix:///var/run/docker.sock"),
                    agent_network="ravage-agent-net-primary-001-" + "1" * 16,
                ),
                "primary-002": AgentVmPlanPin(
                    generation_id="2" * 64,
                    profile_name="ravage-agent-primary-002-" + "2" * 16,
                    docker_socket_path_sha256=_digest("/var/run/docker-2.sock"),
                    docker_host_sha256=_digest("unix:///var/run/docker-2.sock"),
                    agent_network="ravage-agent-net-primary-002-" + "2" * 16,
                ),
            },
        ),
    )


class FakeProcess:
    isolation = ProcessIsolation(
        kind="fake-paired-local",
        filesystem_isolated=False,
        target_network_only=False,
        wall_timeout_enforced=True,
        model_request_limit_enforced=True,
        target_request_limit_enforced=False,
        cost_limit_enforced=True,
    )

    def __init__(self, context: AgentArmContext) -> None:
        self.context = context
        self.environments: list[dict[str, str]] = []
        self.receipt_contract = ExternalProcessReceiptContract(
            row_id=context.row_id,
            model_gateway_policy_sha256=context.gateway_policy_sha256,
            model_gateway_row_token_sha256=_digest(context.gateway_token),
            sandbox_executable_sha256="sha256:" + "a" * 64,
            runtime_read_roots=(Path("/usr/bin"),),
            evidence_class="paired_local",
            docker_socket_path=Path("/var/run/docker.sock"),
        )

    def run(self, command, *, cwd, environment, limits):
        self.environments.append(dict(environment))
        (cwd / backend_module.ADAPTER_RECEIPT_FILE).write_text("{}", encoding="utf-8")
        return ExternalProcessResult(
            returncode=0,
            process_receipt_path=backend_module.PROCESS_RECEIPT_FILE,
            model_gateway_receipt_path=backend_module.MODEL_GATEWAY_RECEIPT_FILE,
            sandbox_profile_path=backend_module.SANDBOX_PROFILE_FILE,
        )

    def seal_unstarted(self, command, *, cwd, environment, limits, reason):
        raise AssertionError("happy path must not terminalize as unstarted")


def test_canonical_bridge_adds_only_target_and_description_to_adapter_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    token = "row-token-" + "z" * 64
    limits = ExternalExecutionLimits(60, 4, 30, "1")
    adapter_source = Path(backend_module.comparison_adapters_module.__file__).read_bytes()
    context = AgentArmContext(
        row_id="primary-001",
        system="ravage",
        target_url="http://127.0.0.1:9001",
        agent_daemon_identity_sha256="sha256:" + "d" * 64,
        agent_visible_model_gateway_url_sha256=_digest("http://127.0.0.1:8999/v1"),
        description="one normalized description",
        system_pin=_system_pin(),
        adapter_source_sha256="sha256:" + hashlib.sha256(adapter_source).hexdigest(),
        docker_separation=_docker_policy(),
        gateway_token=token,
        gateway_policy_sha256="sha256:" + "b" * 64,
        limits=limits,
        evidence_dir=tmp_path / "primary-001",
        native_output_dir=tmp_path / "primary-001" / "native-output",
    )
    context.native_output_dir.mkdir(parents=True)
    agent = ExternalAgentCommand(
        name="Ravage",
        system_id="ravage",
        command=("/usr/bin/true",),
        artifact_path="flag-candidates.txt",
        limits=limits,
        reasoning_effort="high",
        provider="paired-row-gateway",
        model="gpt-test",
        adapter_version=backend_module.ADAPTER_VERSION,
        environment={
            COMPARISON_GATEWAY_TOKEN_ENV: token,
            "RAVAGE_COMPARISON_GATEWAY_BASE_URL": "http://127.0.0.1:8999/v1",
            "RAVAGE_COMPARISON_OUTER_PROCESS_GROUP": "joined_evaluator_group_v1",
        },
        environment_allowlist=(
            COMPARISON_GATEWAY_TOKEN_ENV,
            "RAVAGE_COMPARISON_GATEWAY_BASE_URL",
            "RAVAGE_COMPARISON_OUTER_PROCESS_GROUP",
        ),
    )
    process = FakeProcess(context)
    monkeypatch.setattr(
        backend_module,
        "validate_pinned_adapter_agent",
        lambda _agent: SimpleNamespace(
            system_id="ravage",
            docker_host="unix:///var/run/docker.sock",
            tool_image=_system_pin().tool_image_reference,
            runtime=SimpleNamespace(
                to_json=lambda: {
                    "source_origin_url": _system_pin().origin_url,
                    "source_commit": _system_pin().commit,
                    "source_tree": _system_pin().tree,
                    "runtime_environment_manifest_sha256": (_system_pin().runtime_manifest_sha256),
                    "executable_sha256": _system_pin().executable_sha256,
                }
            ),
        ),
    )
    monkeypatch.setattr(
        CanonicalKnownSiteAgentBackend,
        "_validate_started_evidence",
        lambda self, context, **kwargs: {
            "public_contract": {"validated": True},
            "semantic_prompt_sha256": "sha256:" + "c" * 64,
            "elapsed_seconds": 2.5,
            "artifact_sha256": _digest(""),
        },
    )
    forbidden_source = tmp_path / "repository" / "examples" / "labs" / "ravage-node-market-box"
    forbidden_source.mkdir(parents=True)
    backend = CanonicalKnownSiteAgentBackend(
        agent_factories={"ravage": lambda _context: agent, "strix": lambda _context: agent},
        process_factory=lambda _context, _agent: process,
        forbidden_target_source_paths=(forbidden_source,),
    )

    terminal = backend.run_arm(context)

    assert terminal.status == "completed"
    assert terminal.error is None
    assert terminal.artifact_sha256 == _digest("")
    assert process.environments == [
        {
            **dict(agent.environment),
            TARGET_URL_ENV: context.target_url,
            DESCRIPTION_ENV: context.description,
        }
    ]
    serialized = repr(process.environments)
    assert "OPERATOR_NOTES" not in serialized
    assert "examples/labs" not in serialized
    assert "ravage_site_" not in serialized


@pytest.mark.parametrize(
    ("returncode", "adapter_timed_out", "expected_status", "expected_timeout"),
    [
        (7, False, "failed", False),
        (124, True, "timed_out", True),
    ],
)
def test_canonical_bridge_preserves_nonzero_and_inner_timeout_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    adapter_timed_out: bool,
    expected_status: str,
    expected_timeout: bool,
) -> None:
    evidence_dir = tmp_path / "primary-001"
    native = evidence_dir / "native-output"
    native.mkdir(parents=True)
    (native / backend_module.ADAPTER_RECEIPT_FILE).write_text("{}", encoding="utf-8")
    limits = ExternalExecutionLimits(60, 4, 30, "1")
    context = AgentArmContext(
        row_id="primary-001",
        system="ravage",
        target_url="http://127.0.0.1:9001",
        agent_daemon_identity_sha256="sha256:" + "d" * 64,
        agent_visible_model_gateway_url_sha256=_digest("http://127.0.0.1:8999/v1"),
        description="one normalized description",
        system_pin=_system_pin(),
        adapter_source_sha256="sha256:" + "a" * 64,
        docker_separation=_docker_policy(),
        gateway_token="token-" + "z" * 64,
        gateway_policy_sha256="sha256:" + "b" * 64,
        limits=limits,
        evidence_dir=evidence_dir,
        native_output_dir=native,
    )
    agent = SimpleNamespace(command=("/usr/bin/true",))
    process = SimpleNamespace(
        run=lambda *args, **kwargs: ExternalProcessResult(
            returncode=returncode,
            timed_out=False,
            process_receipt_path=backend_module.PROCESS_RECEIPT_FILE,
            model_gateway_receipt_path=backend_module.MODEL_GATEWAY_RECEIPT_FILE,
            sandbox_profile_path=backend_module.SANDBOX_PROFILE_FILE,
        )
    )
    forbidden = tmp_path / "repository/examples/labs/ravage-node-market-box"
    forbidden.mkdir(parents=True)
    backend = CanonicalKnownSiteAgentBackend(
        agent_factories={"ravage": lambda _context: agent, "strix": lambda _context: agent},
        process_factory=lambda _context, _agent: process,
        forbidden_target_source_paths=(forbidden,),
    )
    monkeypatch.setattr(
        CanonicalKnownSiteAgentBackend,
        "_prepare",
        lambda self, context, **kwargs: (agent, process, {}),
    )
    monkeypatch.setattr(
        CanonicalKnownSiteAgentBackend,
        "_validate_started_evidence",
        lambda self, context, **kwargs: {
            "public_contract": {"bound": True},
            "semantic_prompt_sha256": "sha256:" + "c" * 64,
            "elapsed_seconds": 3.25,
            "artifact_sha256": None,
            "adapter_timed_out": adapter_timed_out,
        },
    )

    terminal = backend.run_arm(context)

    assert terminal.status == expected_status
    assert terminal.timed_out is expected_timeout
    assert terminal.elapsed_seconds == 3.25
    assert terminal.error is not None


@pytest.mark.parametrize(
    ("status", "inner_returncode", "outer_returncode", "inner_timed_out", "outer_timed_out"),
    [
        ("agent_nonzero", 7, 0, False, False),
        ("agent_nonzero", 7, 8, False, False),
        ("timed_out", 0, 124, True, False),
        ("timed_out", -9, 124, True, True),
    ],
)
def test_adapter_receipt_rejects_contradictory_inner_outer_outcomes(
    status: str,
    inner_returncode: int,
    outer_returncode: int,
    inner_timed_out: bool,
    outer_timed_out: bool,
) -> None:
    target_url = "http://127.0.0.1:9001"
    gateway_url = "http://127.0.0.1:8999/v1"
    context = SimpleNamespace(system="ravage", target_url=target_url)
    agent = SimpleNamespace(environment={backend_module.GATEWAY_BASE_URL_ENV: gateway_url})
    receipt = {
        "schema_version": backend_module.ADAPTER_SCHEMA_VERSION,
        "adapter_version": backend_module.ADAPTER_VERSION,
        "system_id": "ravage",
        "status": status,
        "returncode": inner_returncode,
        "wrapper_returncode": outer_returncode,
        "process_group_policy": "joined_evaluator_outer_group",
        "timed_out": inner_timed_out,
        "command_sha256": _digest("command"),
        "target_url_sha256": _digest(target_url),
        "gateway_base_url_sha256": _digest(gateway_url),
        "docker_host_sha256": _digest("docker"),
        "gateway": {},
        "limits": {},
        "tool_image": "unused",
        "input_contract": {},
        "runtime": {},
        "capture": {},
        "candidate_extraction": {},
        "environment_policy": {},
    }

    with pytest.raises(
        backend_module.AdapterConfigurationError,
        match="outcome is internally inconsistent",
    ):
        backend_module._validate_adapter_receipt(
            receipt,
            context=context,
            agent=agent,
            candidate_body=None,
            wrapper_returncode=outer_returncode,
            wrapper_timed_out=outer_timed_out,
        )


def test_adapter_receipt_rejects_incomplete_non_timeout_extraction() -> None:
    target_url = "http://127.0.0.1:9001"
    gateway_url = "http://127.0.0.1:8999/v1"
    context = SimpleNamespace(system="ravage", target_url=target_url)
    agent = SimpleNamespace(environment={backend_module.GATEWAY_BASE_URL_ENV: gateway_url})
    receipt = {
        "schema_version": backend_module.ADAPTER_SCHEMA_VERSION,
        "adapter_version": backend_module.ADAPTER_VERSION,
        "system_id": "ravage",
        "status": "completed",
        "returncode": 0,
        "wrapper_returncode": 125,
        "process_group_policy": "joined_evaluator_outer_group",
        "timed_out": False,
        "command_sha256": _digest("command"),
        "target_url_sha256": _digest(target_url),
        "gateway_base_url_sha256": _digest(gateway_url),
        "docker_host_sha256": _digest("docker"),
        "gateway": {},
        "limits": {},
        "tool_image": "unused",
        "input_contract": {},
        "runtime": {},
        "capture": {},
        "candidate_extraction": {
            "complete": False,
            "candidate_count": 0,
            "artifact_path": None,
            "expected_flag_used": False,
        },
        "environment_policy": {},
    }

    with pytest.raises(
        backend_module.AdapterConfigurationError,
        match="non-timeout adapter candidate extraction is incomplete",
    ):
        backend_module._validate_adapter_receipt(
            receipt,
            context=context,
            agent=agent,
            candidate_body=None,
            wrapper_returncode=125,
            wrapper_timed_out=False,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("complete", False, "capture is incomplete"),
        ("truncated", True, "capture is incomplete"),
        ("sha256", _digest("wrong"), "does not reproduce retained bytes"),
        ("total_bytes", 99, "does not reproduce retained bytes"),
    ],
)
def test_live_adapter_capture_requires_complete_reproducible_files(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    bodies = {"stdout": b"stdout bytes\n", "stderr": b"stderr bytes\n"}
    capture: dict[str, dict[str, object]] = {}
    for stream, filename in (
        ("stdout", backend_module.ADAPTER_STDOUT_PATH),
        ("stderr", backend_module.ADAPTER_STDERR_PATH),
    ):
        body = bodies[stream]
        (tmp_path / filename).write_bytes(body)
        capture[stream] = {
            "sha256": _digest(body.decode()),
            "total_bytes": len(body),
            "retained_bytes": len(body),
            "truncated": False,
            "complete": True,
        }
    backend_module._validate_adapter_capture(capture, output_directory=tmp_path)
    capture["stdout"][field] = value

    with pytest.raises(backend_module.AdapterConfigurationError, match=message):
        backend_module._validate_adapter_capture(capture, output_directory=tmp_path)


def test_agent_runtime_read_root_cannot_contain_known_site_source(tmp_path: Path) -> None:
    checkout = tmp_path / "agent-checkout"
    target_source = checkout / "examples" / "labs" / "ravage-node-market-box"
    target_source.mkdir(parents=True)
    git_metadata = checkout / ".git"
    git_metadata.mkdir()

    with pytest.raises(
        backend_module.ComparisonProcessError,
        match="expose known-site source or Git objects",
    ):
        backend_module._validate_forbidden_source_separation(
            (checkout,),
            forbidden_paths=(target_source,),
        )

    with pytest.raises(
        backend_module.ComparisonProcessError,
        match="expose known-site source or Git objects",
    ):
        backend_module._validate_forbidden_source_separation(
            (git_metadata,),
            forbidden_paths=(target_source,),
        )

    package_only = checkout / "packages" / "ravage" / "src"
    package_only.mkdir(parents=True)
    backend_module._validate_forbidden_source_separation(
        (package_only,),
        forbidden_paths=(target_source,),
    )


def test_agent_runtime_read_root_cannot_contain_sibling_arm_evidence(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    first = private / "primary-001"
    second = private / "primary-002"
    first.mkdir(parents=True)
    second.mkdir()

    with pytest.raises(
        backend_module.ComparisonProcessError,
        match="current or sibling campaign evidence",
    ):
        backend_module._validate_evidence_root_separation(
            (first,),
            private_campaign_root=private,
        )

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    backend_module._validate_evidence_root_separation(
        (runtime,),
        private_campaign_root=private,
    )
