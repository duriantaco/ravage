from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from ravage.runtime import DockerToolRuntime
from ravage.runtime.scoped_network import (
    FORWARDER_CONFIG_MOUNT,
    SCOPED_TARGET_ALIAS,
    SESSION_LABEL,
    ScopedDockerNetwork,
    cleanup_scoped_network_session,
)


class _FakeDocker:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.gateway_exists = False
        self.network_exists = False
        self.config_source = ""

    def __call__(self, argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        if command[:3] == ("docker", "network", "create"):
            self.network_exists = True
            return _completed(command, stdout="network-id\n")
        if command[:3] == ("docker", "run", "--detach"):
            self.gateway_exists = True
            mount = command[command.index("--mount") + 1]
            self.config_source = mount.split("src=", 1)[1].split(",dst=", 1)[0]
            return _completed(command, stdout="gateway-id\n")
        if command[:3] == ("docker", "network", "connect"):
            return _completed(command)
        if command[:3] == ("docker", "network", "inspect"):
            return _completed(command, stdout=json.dumps([{"Internal": True}]))
        if command[:2] == ("docker", "inspect"):
            return _completed(command, stdout=json.dumps([self._gateway_inspect()]))
        if command[:3] == ("docker", "run", "--rm"):
            return _completed(command, stdout="tool-output\n")
        if command[:3] == ("docker", "ps", "--all"):
            return _completed(command, stdout="gateway-id\n" if self.gateway_exists else "")
        if command[:3] == ("docker", "network", "ls"):
            return _completed(command, stdout="network-id\n" if self.network_exists else "")
        if command[:3] == ("docker", "rm", "--force"):
            self.gateway_exists = False
            return _completed(command, stdout="gateway-id\n")
        if command[:3] == ("docker", "network", "rm"):
            self.network_exists = False
            return _completed(command, stdout="network-id\n")
        raise AssertionError(f"unexpected Docker command: {command!r}")

    def _gateway_inspect(self) -> dict[str, object]:
        connect = next(
            (call for call in self.calls if call[:3] == ("docker", "network", "connect")),
            (),
        )
        aliases = [
            connect[index + 1]
            for index, value in enumerate(connect)
            if value == "--alias"
        ]
        networks = {
            "bridge": {"Aliases": []},
            self._network_name(): {"Aliases": aliases or [SCOPED_TARGET_ALIAS]},
        }
        return {
            "State": {"Running": self.gateway_exists},
            "NetworkSettings": {"Networks": networks},
            "Mounts": [
                {
                    "Destination": FORWARDER_CONFIG_MOUNT,
                    "Source": self.config_source,
                    "Type": "bind",
                }
            ],
        }

    def _network_name(self) -> str:
        create = next(call for call in self.calls if call[:3] == ("docker", "network", "create"))
        return create[-1]


def _completed(
    argv: tuple[str, ...],
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def _patch_docker(monkeypatch: object, fake: _FakeDocker) -> None:
    monkeypatch.setattr(subprocess, "run", fake)  # type: ignore[attr-defined]


def test_docker_runtime_uses_internal_network_and_fixed_gateway(monkeypatch, tmp_path: Path) -> None:
    fake = _FakeDocker()
    _patch_docker(monkeypatch, fake)
    evidence_path = tmp_path / "network-evidence.json"
    scope = SimpleNamespace(
        in_scope=["http://localhost:18080", "http://127.0.0.1:19090"],
        out_of_scope=[],
    )
    runtime = DockerToolRuntime(
        image="sha256:pinned-tool-image",
        scope=scope,
        session_id="engagement-123",
        cleanup_evidence_path=evidence_path,
    )

    result = runtime.run_command(
        command="curl http://localhost:18080/a && nc 127.0.0.1 19090",
        target_url="http://localhost:18080",
    )

    assert result.ok is True
    network_create = next(call for call in fake.calls if call[:3] == ("docker", "network", "create"))
    assert "--internal" in network_create
    assert f"{SESSION_LABEL}={runtime.scoped_network.session_key}" in network_create

    gateway_run = next(call for call in fake.calls if call[:3] == ("docker", "run", "--detach"))
    assert "--pull=never" in gateway_run
    assert gateway_run[gateway_run.index("--network") + 1] == "bridge"
    assert ("--cap-drop", "ALL") == _option_pair(gateway_run, "--cap-drop")
    assert ("--security-opt", "no-new-privileges") == _option_pair(
        gateway_run, "--security-opt"
    )
    assert ("--user", "65534:65534") == _option_pair(gateway_run, "--user")
    assert ("--sysctl", "net.ipv4.ip_forward=0") == _option_pair(gateway_run, "--sysctl")
    assert gateway_run.count("--mount") == 1
    assert f"dst={FORWARDER_CONFIG_MOUNT}" in gateway_run[gateway_run.index("--mount") + 1]
    assert str(runtime.workdir) not in " ".join(gateway_run)

    connect = next(call for call in fake.calls if call[:3] == ("docker", "network", "connect"))
    assert ("--alias", SCOPED_TARGET_ALIAS) == _option_pair(connect, "--alias")

    tool_run = next(call for call in fake.calls if call[:3] == ("docker", "run", "--rm"))
    assert "--pull=never" in tool_run
    assert tool_run[tool_run.index("--network") + 1] == runtime.scoped_network.network_name
    assert ("--cap-drop", "ALL") == _option_pair(tool_run, "--cap-drop")
    assert ("--security-opt", "no-new-privileges") == _option_pair(tool_run, "--security-opt")
    assert tool_run.count("--mount") == 1
    assert str(runtime.workdir) in tool_run[tool_run.index("--mount") + 1]
    assert "docker.sock" not in " ".join(tool_run)
    assert f"RAVAGE_TARGET_URL={SCOPED_TARGET_ALIAS}:" not in " ".join(tool_run)
    assert f"RAVAGE_TARGET_URL=http://{SCOPED_TARGET_ALIAS}:18080" in tool_run
    assert f"curl http://{SCOPED_TARGET_ALIAS}:18080/a" in tool_run[-1]
    assert f"nc {SCOPED_TARGET_ALIAS} 19090" in tool_run[-1]

    runtime.close()
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["setup"]["status"] == "succeeded"
    assert evidence["cleanup"]["verified"] is True
    assert not Path(fake.config_source).exists()
    assert not runtime.workdir.exists()


def test_default_docker_runtime_provisions_image_before_network_start(
    monkeypatch,
) -> None:
    fake = _FakeDocker()
    _patch_docker(monkeypatch, fake)
    provisioned: list[str] = []
    monkeypatch.setattr(
        "ravage.runtime.docker.ensure_tool_image",
        lambda image: provisioned.append(image),
    )

    runtime = DockerToolRuntime(
        scope={"in_scope": ["http://localhost:18080"]},
        session_id="default-image-provisioning",
    )

    assert provisioned == ["ravage-kali:latest"]
    assert any(call[:3] == ("docker", "network", "create") for call in fake.calls)
    runtime.close()


def test_low_ports_are_forwarded_on_unprivileged_listener() -> None:
    network = ScopedDockerNetwork(
        image="sha256:pinned",
        scope={"in_scope": ["http://localhost", "https://localhost"]},
        session_id="low-ports",
    )

    http_url = network.container_url("http://localhost/path")
    https_url = network.container_url("https://localhost/secure")

    assert http_url == f"http://{SCOPED_TARGET_ALIAS}:40000/path"
    assert https_url == f"https://{SCOPED_TARGET_ALIAS}:40001/secure"


def test_authorized_remote_runtime_pins_dns_and_preserves_hostname(
    monkeypatch,
    tmp_path: Path,
) -> None:
    fake = _FakeDocker()
    _patch_docker(monkeypatch, fake)
    monkeypatch.setattr(
        "ravage.runtime.scoped_network._resolve_addresses",
        lambda host, port: ["203.0.113.25"] if (host, port) == ("staging.example.test", 443) else [],
    )
    evidence_path = tmp_path / "remote-network-evidence.json"
    runtime = DockerToolRuntime(
        image="sha256:pinned-tool-image",
        scope={"in_scope": ["https://staging.example.test/app"]},
        session_id="authorized-remote",
        cleanup_evidence_path=evidence_path,
        allow_remote_target=True,
    )

    result = runtime.run_command(
        command="curl -k $RAVAGE_TARGET_URL",
        target_url="https://staging.example.test/app",
    )

    assert result.ok is True
    connect = next(call for call in fake.calls if call[:3] == ("docker", "network", "connect"))
    assert "staging.example.test" in connect
    tool_run = next(call for call in fake.calls if call[:3] == ("docker", "run", "--rm"))
    assert "RAVAGE_TARGET_URL=https://staging.example.test:443/app" in tool_run
    routes = json.loads(
        (Path(fake.config_source) / "routes.json").read_text(encoding="utf-8")
    )["routes"]
    assert routes == [
        {
            "destination_host": "203.0.113.25",
            "destination_port": 443,
            "listen_port": 443,
            "remote": True,
            "target_host": "staging.example.test",
        }
    ]

    runtime.close()


def test_parent_cleanup_by_session_removes_labeled_resources(monkeypatch, tmp_path: Path) -> None:
    fake = _FakeDocker()
    _patch_docker(monkeypatch, fake)
    evidence_path = tmp_path / "parent-cleanup.json"
    network = ScopedDockerNetwork(
        image="sha256:pinned",
        scope={"in_scope": ["http://localhost:18080"]},
        session_id="parent-timeout-session",
        evidence_path=evidence_path,
    )
    network.ensure_started()
    config_source = Path(fake.config_source)

    evidence = cleanup_scoped_network_session(
        "parent-timeout-session",
        evidence_path=evidence_path,
    )

    assert evidence["setup"]["status"] == "succeeded"
    assert evidence["cleanup"]["status"] == "verified"
    assert evidence["cleanup"]["verified"] is True
    assert fake.gateway_exists is False
    assert fake.network_exists is False
    assert not config_source.exists()


def _option_pair(argv: tuple[str, ...], option: str) -> tuple[str, str]:
    index = argv.index(option)
    return (argv[index], argv[index + 1])
