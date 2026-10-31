# ruff: noqa: ARG002,C901,PLR0912,PLR2004,S108,SIM114,TC003
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from collections.abc import Mapping, Sequence
from decimal import Decimal
from pathlib import Path

import pytest
import yaml
from ravage.xben_parts.comparison_model_gateway import ModelGatewayPolicy, ModelPricing
from ravage.xben_parts.comparison_target import CommandResult

from tools.known_site_regression import harness
from tools.known_site_regression.docker_target import (
    DockerKnownSiteTargetBackend,
    KnownSiteDockerConfiguration,
    KnownSiteDockerTargetError,
    PinnedDockerImage,
    _validate_arm_sequence,
    _validate_target_hardening,
    _write_runtime_compose,
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _agent_vm_policy(campaign_id: str) -> harness.AgentVmPolicyPin:
    controller = "sha256:" + "b" * 64
    template = "sha256:" + "c" * 64
    base = "sha256:" + "d" * 64
    relay = "sha256:" + "e" * 64
    plans: dict[str, harness.AgentVmPlanPin] = {}
    for index, row_id in enumerate(harness.ROW_IDS, start=1):
        generation = harness.derive_agent_vm_generation_id(
            campaign_id=campaign_id,
            row_id=row_id,
            controller_policy_sha256=controller,
            vm_template_sha256=template,
            base_image_sha256=base,
            relay_policy_sha256=relay,
        )
        socket = f"/private/tmp/known-site-agent-{index}.sock"
        plans[row_id] = harness.AgentVmPlanPin(
            generation_id=generation,
            profile_name=f"ravage-agent-{row_id}-{generation[:16]}",
            docker_socket_path_sha256=_digest(socket.encode()),
            docker_host_sha256=_digest(f"unix://{socket}".encode()),
            agent_network=f"ravage-agent-net-{row_id}-{generation[:16]}",
        )
    return harness.AgentVmPolicyPin(
        docker_executable_sha256="sha256:" + "a" * 64,
        controller_kind="colima-lima-ephemeral-v1",
        controller_implementation_sha256="sha256:" + "f" * 64,
        controller_policy_sha256=controller,
        supervisor_executable_sha256="sha256:" + "0" * 64,
        supervisor_runtime_manifest_sha256="sha256:" + "2" * 64,
        vm_template_sha256=template,
        base_image_sha256=base,
        relay_implementation_sha256="sha256:" + "1" * 64,
        relay_policy_sha256=relay,
        relay_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
        plans=plans,
    )


def _fixture_files(*, with_lock: bool = True) -> dict[str, bytes]:
    prefix = f"{harness.KNOWN_SITE_SOURCE_PATH}/"
    package = json.dumps(
        {
            "name": "known-site-test",
            "version": "1.0.0",
            "dependencies": {},
        },
        sort_keys=True,
    ).encode()
    lock = json.dumps(
        {
            "name": "known-site-test",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "known-site-test",
                    "version": "1.0.0",
                    "dependencies": {},
                }
            },
        },
        sort_keys=True,
    ).encode()
    files = {
        prefix + "web/Dockerfile": (
            b"FROM node:20-alpine\nWORKDIR /app\n"
            b"COPY package.json package-lock.json ./\n"
            b'RUN npm ci --omit=dev\nCOPY server.js ./\nCMD ["node","server.js"]\n'
        ),
        prefix + "web/package.json": package,
        prefix + "web/server.js": b"console.log('web')\n",
        prefix + "internal/Dockerfile": (
            b'FROM node:20-alpine\nWORKDIR /app\nCOPY internal.js ./\nCMD ["node","internal.js"]\n'
        ),
        prefix + "internal/internal.js": b"console.log('internal')\n",
        prefix + "proxy/nginx.conf": b"events {}\nhttp { server { listen 80; } }\n",
    }
    if with_lock:
        files[prefix + "web/package-lock.json"] = lock
    return files


def _archive(files: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        directories: set[str] = set()
        for path in files:
            parts = Path(path).parts
            directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        for directory in sorted(directories):
            info = tarfile.TarInfo(directory + "/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for path, body in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


class FakePrepareRunner:
    def __init__(self, *, archive: bytes, commit: str, tree: str, origin: str) -> None:
        self.archive = archive
        self.commit = commit
        self.tree = tree
        self.origin = origin
        self.has_lock = (
            f"{harness.KNOWN_SITE_SOURCE_PATH}/web/package-lock.json".encode() in archive
        )
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.built: set[str] = set()

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        argv = tuple(command)
        self.calls.append((argv, dict(environment)))
        stdout = b""
        returncode = 0
        executable = Path(argv[0]).name
        if executable == "git":
            arguments = argv[3:]
            if arguments == ("remote", "get-url", "origin"):
                stdout = (self.origin + "\n").encode()
            elif arguments == ("rev-parse", "HEAD"):
                stdout = (self.commit + "\n").encode()
            elif arguments == ("rev-parse", f"{self.commit}^{{commit}}"):
                stdout = (self.commit + "\n").encode()
            elif arguments == (
                "rev-parse",
                f"{self.commit}:{harness.KNOWN_SITE_SOURCE_PATH}",
            ):
                stdout = (self.tree + "\n").encode()
            elif arguments == ("status", "--porcelain=v1", "--untracked-files=all"):
                stdout = b""
            elif arguments[:2] == ("cat-file", "-e"):
                returncode = 0 if self.has_lock else 1
            elif arguments[:3] == ("archive", "--format=tar", self.commit):
                stdout = self.archive
            else:  # pragma: no cover - catches backend command drift.
                raise AssertionError(argv)
        elif executable == "fake-docker" and argv[1:3] == ("info", "--format"):
            stdout = json.dumps("fake-target-daemon").encode()
        elif executable == "fake-docker" and argv[1:3] == ("image", "inspect"):
            reference = argv[3]
            if reference.endswith(":prepared") and reference not in self.built:
                returncode = 1
            else:
                image_id = _image_id_for_reference(reference)
                stdout = json.dumps(
                    [{"Id": image_id, "Architecture": "amd64", "Os": "linux"}]
                ).encode()
        elif executable == "fake-docker" and argv[1:3] == ("image", "pull"):
            pass
        elif executable == "fake-docker" and argv[1] == "build":
            self.built.add(argv[argv.index("--tag") + 1])
        elif executable == "fake-docker" and argv[1:3] == ("image", "rm"):
            self.built.discard(argv[3])
        else:  # pragma: no cover - catches backend command drift.
            raise AssertionError(argv)
        return CommandResult(command=argv, returncode=returncode, stdout=stdout)


def _image_id_for_reference(reference: str) -> str:
    return "sha256:" + hashlib.sha256(reference.encode()).hexdigest()


def _configuration(repository: Path) -> KnownSiteDockerConfiguration:
    docker_executable = repository / "fake-docker"
    docker_executable.write_bytes(b"#!/bin/sh\nexit 1\n")
    docker_executable.chmod(0o700)
    docker_host = f"unix://{repository / 'target-docker.sock'}"
    references = {
        "node": "registry.example/node@sha256:" + "1" * 64,
        "proxy": "registry.example/proxy@sha256:" + "2" * 64,
        "gateway": "registry.example/gateway@sha256:" + "3" * 64,
        "probe": "registry.example/probe@sha256:" + "4" * 64,
    }
    return KnownSiteDockerConfiguration(
        repository=repository,
        docker_executable=docker_executable,
        docker_executable_sha256=_digest(docker_executable.read_bytes()),
        docker_host=docker_host,
        daemon_identity_sha256=_digest(b"fake-target-daemon"),
        node_image=PinnedDockerImage(
            references["node"], _image_id_for_reference(references["node"])
        ),
        proxy_image=PinnedDockerImage(
            references["proxy"], _image_id_for_reference(references["proxy"])
        ),
        gateway_image=PinnedDockerImage(
            references["gateway"], _image_id_for_reference(references["gateway"])
        ),
        probe_image=PinnedDockerImage(
            references["probe"], _image_id_for_reference(references["probe"])
        ),
        gateway_program_sha256="5" * 64,
        agent_network_resolver=lambda **_kwargs: None,
    )


def _contract(
    configuration: KnownSiteDockerConfiguration,
    files: Mapping[str, bytes],
) -> harness.FrozenKnownSiteContract:
    policy = ModelGatewayPolicy.build(
        model="gpt-test-snapshot-2026-09-01",
        reasoning_effort="high",
        pricing=ModelPricing.from_numbers(
            input_per_million="0.75",
            cached_input_per_million="0.075",
            output_per_million="4.5",
        ),
        campaign_max_cost_usd="2",
        max_completion_tokens_per_request=100,
        max_request_body_bytes=1024,
        max_upstream_response_bytes=4096,
        upstream_timeout_seconds=10,
        max_parallel_requests=2,
    ).to_json()
    policy_sha256 = _digest(
        json.dumps(
            policy, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode()
    )
    prefix = f"{harness.KNOWN_SITE_SOURCE_PATH}/"
    lock = files.get(prefix + "web/package-lock.json", b"missing-lock")
    package = files[prefix + "web/package.json"]
    proxy = files[prefix + "proxy/nginx.conf"]
    target_runtime = {
        "platform": configuration.platform,
        "images": {
            "node_base": {
                "reference": configuration.node_image.reference,
                "expected_image_id": configuration.node_image.expected_image_id,
            },
            "proxy": {
                "reference": configuration.proxy_image.reference,
                "expected_image_id": configuration.proxy_image.expected_image_id,
            },
            "http_meter": {
                "reference": configuration.gateway_image.reference,
                "expected_image_id": configuration.gateway_image.expected_image_id,
            },
            "readiness_probe": {
                "reference": configuration.probe_image.reference,
                "expected_image_id": configuration.probe_image.expected_image_id,
            },
        },
        "http_meter": {
            "program_sha256": configuration.gateway_program_sha256,
            "protocol": harness.HTTP_METER_PROTOCOL,
        },
        "dependency_lock": {
            "required": True,
            "relative_path": "web/package-lock.json",
            "sha256": _digest(lock),
            "package_json_sha256": _digest(package),
            "installer": "npm-ci-omit-dev",
        },
        "proxy_configuration": {
            "relative_path": "proxy/nginx.conf",
            "sha256": _digest(proxy),
        },
    }
    return harness.FrozenKnownSiteContract(
        campaign_id="known-site-docker-test",
        campaign_directory_sha256="sha256:" + "9" * 64,
        source=harness.SiteSourcePin(
            origin_url="https://github.com/duriantaco/ravage.git",
            commit="a" * 40,
            tree="b" * 40,
        ),
        model_gateway_policy=policy,
        model_gateway_policy_sha256=policy_sha256,
        limits=harness.KnownSiteLimits(
            wall_seconds_per_arm=60,
            max_model_requests_per_arm=4,
            max_target_requests_per_arm=30,
            max_cost_usd_per_arm=Decimal(1),
            campaign_wall_seconds=130,
            campaign_max_model_requests=8,
            campaign_max_target_requests=60,
            campaign_max_cost_usd=Decimal(2),
        ),
        target_runtime=target_runtime,
        system_pins={
            "ravage": harness.KnownSiteSystemPin(
                origin_url="https://github.com/duriantaco/ravage.git",
                commit="c" * 40,
                tree="d" * 40,
                runtime_manifest_sha256="sha256:" + "1" * 64,
                executable_sha256="sha256:" + "2" * 64,
                tool_image_reference="registry.example/ravage@sha256:" + "3" * 64,
                tool_image_id="sha256:" + "4" * 64,
                tool_image_archive_sha256="sha256:" + "9" * 64,
            ),
            "strix": harness.KnownSiteSystemPin(
                origin_url="https://github.com/usestrix/strix.git",
                commit="e" * 40,
                tree="f" * 40,
                runtime_manifest_sha256="sha256:" + "5" * 64,
                executable_sha256="sha256:" + "6" * 64,
                tool_image_reference="registry.example/strix@sha256:" + "7" * 64,
                tool_image_id="sha256:" + "8" * 64,
                tool_image_archive_sha256="sha256:" + "0" * 64,
            ),
        },
        adapter_source_sha256="sha256:" + "9" * 64,
        authenticated_arm_order=harness.AuthenticatedArmOrderPin(
            paired_campaign_id="paired-xben-docker-test",
            commitment_document_sha256="sha256:" + "1" * 64,
            preflight_document_sha256="sha256:" + "2" * 64,
            beacon_document_sha256="sha256:" + "3" * 64,
            selection_document_sha256="sha256:" + "4" * 64,
            draw_key_sha256="sha256:" + "5" * 64,
            website_content_sha256="sha256:" + "7" * 64,
            website_reference_sha256="sha256:" + "6" * 64,
        ),
        docker_separation=harness.DockerSeparationPolicy(
            target=harness.DockerDaemonPin(
                docker_executable_sha256=configuration.docker_executable_sha256,
                docker_socket_path_sha256=_digest(
                    str(configuration.repository / "target-docker.sock").encode()
                ),
                docker_host_sha256=_digest(configuration.docker_host.encode()),
                daemon_identity_sha256=configuration.daemon_identity_sha256,
            ),
            agent_vm=_agent_vm_policy("known-site-docker-test"),
        ),
    )


def _flags() -> dict[str, str]:
    return {
        environment: f"flag{{ravage_site_{index:064x}}}"
        for index, (_logical, environment) in enumerate(harness.FLAG_ENVIRONMENT, start=1)
    }


def test_prepare_uses_clean_archive_pins_and_builds_only_twice(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    files = _fixture_files()
    configuration = _configuration(repository)
    contract = _contract(configuration, files)
    runner = FakePrepareRunner(
        archive=_archive(files),
        commit=contract.source.commit,
        tree=contract.source.tree,
        origin=contract.source.origin_url,
    )
    backend = DockerKnownSiteTargetBackend(configuration=configuration, runner=runner)
    flags = _flags()

    prepared = backend.prepare(
        contract=contract,
        flags_by_environment=flags,
        flag_commitments_sha256="sha256:" + "9" * 64,
        private_root=private,
    )

    builds = [
        (command, environment)
        for command, environment in runner.calls
        if Path(command[0]).name == "fake-docker" and command[1] == "build"
    ]
    assert len(builds) == 2
    assert {command[command.index("--tag") + 1].rsplit("-", 1)[-1] for command, _env in builds} == {
        "internal:prepared",
        "web:prepared",
    }
    for command, environment in builds:
        assert "--no-cache" in command
        assert "--pull=false" in command
        assert command[0] == str(configuration.docker_executable.resolve())
        assert environment["DOCKER_HOST"] == configuration.docker_host
        assert not set(flags).intersection(environment)
        assert not any(flag in command for flag in flags.values())
    assert prepared.build_count_by_service == {"internal": 1, "proxy": 0, "web": 1}
    assert prepared.image_ids_by_service["proxy"] == configuration.proxy_image.expected_image_id
    receipt = (private / "target-backend/evidence/preparation.json").read_text()
    assert not any(flag in receipt for flag in flags.values())
    assert json.loads(receipt)["target_runtime"] == contract.target_runtime
    docker_boundary = json.loads(receipt)["docker_boundary"]
    assert docker_boundary["daemon_identity_verified_live"] is True
    assert docker_boundary["distinct_from_agent_tool_daemon"] is True
    assert all(
        environment["DOCKER_HOST"] == configuration.docker_host
        for command, environment in runner.calls
        if Path(command[0]).name == "fake-docker"
    )
    with pytest.raises(KnownSiteDockerTargetError, match="one-shot"):
        backend.prepare(
            contract=contract,
            flags_by_environment=flags,
            flag_commitments_sha256="sha256:" + "9" * 64,
            private_root=private,
        )


def test_missing_lock_in_pinned_snapshot_blocks_before_any_docker(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    files = _fixture_files(with_lock=False)
    configuration = _configuration(repository)
    contract = _contract(configuration, files)
    runner = FakePrepareRunner(
        archive=_archive(files),
        commit=contract.source.commit,
        tree=contract.source.tree,
        origin=contract.source.origin_url,
    )
    backend = DockerKnownSiteTargetBackend(configuration=configuration, runner=runner)

    with pytest.raises(KnownSiteDockerTargetError, match=r"dependency lock.*unavailable"):
        backend.prepare(
            contract=contract,
            flags_by_environment=_flags(),
            flag_commitments_sha256="sha256:" + "9" * 64,
            private_root=private,
        )

    assert not any(Path(command[0]).name == "fake-docker" for command, _environment in runner.calls)
    assert not (private / "target-backend/workspace").exists()
    failure = json.loads((private / "target-backend/evidence/preparation-failure.json").read_text())
    assert failure["cleanup"] == {
        "workspace_removed": True,
        "errors": [],
        "complete": True,
    }


def test_contract_image_drift_blocks_before_runner_call(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    files = _fixture_files()
    configuration = _configuration(repository)
    contract = _contract(configuration, files)
    contract.target_runtime["images"]["proxy"]["reference"] = (  # type: ignore[index]
        "registry.example/other@sha256:" + "f" * 64
    )
    runner = FakePrepareRunner(
        archive=_archive(files),
        commit=contract.source.commit,
        tree=contract.source.tree,
        origin=contract.source.origin_url,
    )

    with pytest.raises(KnownSiteDockerTargetError, match="proxy image pin drifted"):
        DockerKnownSiteTargetBackend(configuration=configuration, runner=runner).prepare(
            contract=contract,
            flags_by_environment=_flags(),
            flag_commitments_sha256="sha256:" + "9" * 64,
            private_root=private,
        )

    assert runner.calls == []


def test_runtime_compose_contains_only_placeholders_and_image_ids(tmp_path: Path) -> None:
    path = tmp_path / "compose.yml"
    proxy = b"events {}\nhttp { server { listen 80; } }\n"
    images = {
        name: "sha256:" + str(index) * 64
        for index, name in enumerate(sorted(harness.SERVICE_NAMES), 1)
    }

    _write_runtime_compose(
        path,
        instance_id="site-arm-001",
        target_network="rks-project-target",
        volume_names=("rks-project-internal", "rks-project-web"),
        image_ids=images,
        proxy_configuration=proxy,
        expected_proxy_sha256=_digest(proxy),
    )

    body = path.read_text()
    assert "flag{ravage_site_" not in body
    document = yaml.safe_load(body)
    assert {service: config["image"] for service, config in document["services"].items()} == images
    assert all("build" not in service for service in document["services"].values())
    assert document["services"]["proxy"].get("volumes") is None
    assert document["services"]["proxy"]["cap_add"] == ["NET_BIND_SERVICE"]
    assert document["services"]["proxy"]["cap_drop"] == ["ALL"]
    assert document["services"]["proxy"]["pids_limit"] == 128
    assert document["services"]["proxy"]["mem_limit"] == "512m"
    assert document["services"]["proxy"]["cpus"] == 1.0
    assert document["services"]["proxy"]["tmpfs"] == [
        "/tmp:rw,noexec,nosuid,nodev,size=1m",
        "/var/cache/nginx:rw,noexec,nosuid,nodev,size=16m",
        "/var/run:rw,noexec,nosuid,nodev,size=1m",
    ]
    assert document["services"]["web"]["environment"]["MARKET_FLAG_IDOR"] == (
        "${MARKET_FLAG_IDOR:-__RUNTIME_FLAG_MISSING__}"
    )
    assert document["networks"]["target"]["internal"] is True


def test_mutable_registry_reference_is_rejected(tmp_path: Path) -> None:
    configuration = _configuration(tmp_path)
    invalid = KnownSiteDockerConfiguration(
        repository=tmp_path,
        docker_executable=configuration.docker_executable,
        docker_executable_sha256=configuration.docker_executable_sha256,
        docker_host=configuration.docker_host,
        daemon_identity_sha256=configuration.daemon_identity_sha256,
        node_image=PinnedDockerImage("node:20-alpine", "sha256:" + "1" * 64),
        proxy_image=configuration.proxy_image,
        gateway_image=configuration.gateway_image,
        probe_image=configuration.probe_image,
        gateway_program_sha256=configuration.gateway_program_sha256,
        agent_network_resolver=lambda **_kwargs: None,
    )

    with pytest.raises(KnownSiteDockerTargetError, match="not digest-pinned"):
        invalid.validate()


def test_bundled_backend_blocks_before_draw_without_cross_daemon_meter_bridge(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    files = _fixture_files()
    configuration = _configuration(repository)
    contract = _contract(configuration, files)
    backend = DockerKnownSiteTargetBackend(configuration=configuration)

    with pytest.raises(KnownSiteDockerTargetError, match="dual-daemon metered bridge"):
        backend.validate_pre_draw(contract=contract)


def test_arm_two_requires_arm_one_complete_teardown() -> None:
    with pytest.raises(KnownSiteDockerTargetError, match="complete teardown"):
        _validate_arm_sequence(
            row_id="primary-002",
            system="strix",
            instance_id="site-arm-002",
            started_rows={"primary-001": "site-arm-001"},
            stopped_rows=set(),
        )

    _validate_arm_sequence(
        row_id="primary-002",
        system="strix",
        instance_id="site-arm-002",
        started_rows={"primary-001": "site-arm-001"},
        stopped_rows={"primary-001"},
    )


def test_target_hardening_requires_exact_capabilities_and_tmpfs() -> None:
    host = {
        "CapAdd": ["CAP_NET_BIND_SERVICE"],
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "PidMode": "",
        "IpcMode": "private",
        "UTSMode": "",
        "UsernsMode": "",
        "Devices": [],
        "DeviceRequests": [],
        "PidsLimit": 128,
        "Memory": 512 * 1024 * 1024,
        "NanoCpus": 1_000_000_000,
        "Tmpfs": {
            "/tmp": "rw,noexec,nosuid,nodev,size=1m",
            "/var/cache/nginx": "rw,noexec,nosuid,nodev,size=16m",
            "/var/run": "rw,noexec,nosuid,nodev,size=1m",
        },
    }
    _validate_target_hardening(service="proxy", host=host)

    host["CapAdd"] = ["CAP_NET_ADMIN"]
    with pytest.raises(KnownSiteDockerTargetError, match="exceeds NET_BIND_SERVICE"):
        _validate_target_hardening(service="proxy", host=host)
