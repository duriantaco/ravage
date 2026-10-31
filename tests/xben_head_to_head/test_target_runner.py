# ruff: noqa: PLR2004,SLF001
from __future__ import annotations

import hashlib
import json
import subprocess
from base64 import b64encode
from pathlib import Path
from urllib.parse import quote

import pytest
import yaml

from tools.xben_head_to_head import target_runner


def _case(tmp_path: Path, compose: dict[str, object]) -> Path:
    case = tmp_path / "XBEN-001-24"
    case.mkdir()
    (case / "docker-compose.yml").write_text(
        yaml.safe_dump(compose, sort_keys=False), encoding="utf-8"
    )
    return case


def test_rewrite_compose_randomizes_only_loopback_ports(tmp_path: Path) -> None:
    case = _case(
        tmp_path,
        {
            "services": {
                "db": {"image": "db:fixed", "expose": [3306]},
                "web": {
                    "build": "./app",
                    "ports": ["5003:5000", 8080],
                    "environment": {"MODE": "test"},
                },
            }
        },
    )

    path, service, port = target_runner._rewrite_compose(case)
    rewritten = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert service == "web"
    assert port == 5000
    assert rewritten["services"]["web"]["ports"] == [
        "127.0.0.1::5000",
        "127.0.0.1::8080",
    ]
    assert rewritten["services"]["db"]["platform"] == "linux/amd64"
    assert rewritten["services"]["web"]["platform"] == "linux/amd64"


@pytest.mark.parametrize("key", ["privileged", "network_mode", "volumes", "devices"])
def test_rewrite_rejects_host_authority(tmp_path: Path, key: str) -> None:
    value: object = True if key == "privileged" else ["/tmp:/host"]
    case = _case(
        tmp_path,
        {"services": {"web": {"image": "x", "ports": [80], key: value}}},
    )

    with pytest.raises(target_runner.TargetRunnerError, match="forbidden host authority"):
        target_runner._rewrite_compose(case)


def test_target_urls_require_active_target(tmp_path: Path) -> None:
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag="flag{abcdefghijklmnop}",
        buildx_builder=target_runner.BuildxBuilder(
            name="ravage_xben_cmp_" + "a" * 32, _created=True
        ),
    )
    with pytest.raises(target_runner.TargetRunnerError, match="not active"):
        _ = target.codex_target_url
    target.active = True
    target.host_port = 49152
    assert target.codex_target_url == "http://127.0.0.1:49152"
    assert target.strix_target_url == "http://host.docker.internal:49152"


def test_compose_receipt_hashes_output_without_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag="flag{abcdefghijklmnop}",
        buildx_builder=target_runner.BuildxBuilder(
            name="ravage_xben_cmp_" + "a" * 32, _created=True
        ),
    )
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["env"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, stdout="built\n", stderr="")

    monkeypatch.setenv("DOCKER_BUILDKIT", "0")
    monkeypatch.setenv("COMPOSE_DOCKER_CLI_BUILD", "0")
    monkeypatch.setenv("BUILDX_BUILDER", "unrelated-builder")
    monkeypatch.setenv("COMPOSE_BAKE", "true")
    monkeypatch.setattr(target_runner.subprocess, "run", fake_run)
    result, receipt = target_runner._run_compose(
        target,
        "build",
        ("build", "--builder", target.buildx_builder.name),
        timeout_seconds=30,
    )

    assert result.returncode == 0
    assert observed["env"]["FLAG"] == "flag{abcdefghijklmnop}"  # type: ignore[index]
    assert observed["env"]["DOCKER_BUILDKIT"] == "1"  # type: ignore[index]
    assert observed["env"]["COMPOSE_DOCKER_CLI_BUILD"] == "1"  # type: ignore[index]
    assert observed["env"]["BUILDX_BUILDER"] == target.buildx_builder.name  # type: ignore[index]
    assert observed["env"]["COMPOSE_BAKE"] == "false"  # type: ignore[index]
    assert receipt.stdout_sha256 == hashlib.sha256(b"built\n").hexdigest()
    assert "flag{abcdefghijklmnop}" not in json.dumps(receipt.to_json())


def test_compose_build_refuses_missing_explicit_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag="flag{abcdefghijklmnop}",
        buildx_builder=target_runner.BuildxBuilder(
            name="ravage_xben_cmp_" + "a" * 32, _created=True
        ),
    )
    monkeypatch.setattr(
        target_runner.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("unscoped build must not invoke Docker"),
    )

    with pytest.raises(target_runner.TargetRunnerError, match="dedicated Buildx builder"):
        target_runner._run_compose(target, "build", ("build",), timeout_seconds=30)


def test_case_metadata_normalizes_string_level(tmp_path: Path) -> None:
    root = tmp_path / "source"
    path = root / "benchmarks" / "XBEN-009-24"
    path.mkdir(parents=True)
    (path / "benchmark.json").write_text(
        json.dumps({"description": "  Find the target-origin proof.  ", "level": "2"}),
        encoding="utf-8",
    )

    assert target_runner.read_case_metadata(root, "XBEN-009-24") == {
        "description": "Find the target-origin proof.",
        "level": 2,
    }


def test_pair_flag_has_private_randomized_shape() -> None:
    first = target_runner.make_pair_flag()
    second = target_runner.make_pair_flag()
    assert first.startswith("flag{ravage_cmp_") and first.endswith("}")
    assert len(first) == len("flag{ravage_cmp_" + "0" * 64 + "}")
    assert first != second


def test_dedicated_builder_build_prune_and_removal_are_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []
    builder_name = "ravage_xben_cmp_" + "a" * 32
    monkeypatch.setattr(target_runner.secrets, "token_hex", lambda count: "a" * (count * 2))
    removed = False

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal removed
        commands.append(command)
        if command[:3] == ["docker", "buildx", "inspect"]:
            if removed:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="not found")
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    f"Name: {builder_name}\nDriver: docker-container\n"
                    f"Nodes:\nName: {builder_name}0\n"
                ),
                stderr="",
            )
        if command[:3] == ["docker", "buildx", "rm"]:
            removed = True
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(target_runner.subprocess, "run", fake_run)
    builder = target_runner.BuildxBuilder.create()
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag="flag{abcdefghijklmnop}",
        buildx_builder=builder,
    )

    target.build()
    prune = target_runner.cleanup_build_cache(builder)
    removal = builder.destroy()

    assert commands[0] == [
        "docker", "buildx", "create", "--name", builder_name, "--driver", "docker-container"
    ]
    assert ["docker", "buildx", "prune", "--builder", builder_name, "-f"] in commands
    assert ["docker", "buildx", "rm", builder_name] in commands
    assert not any(command[:3] == ["docker", "builder", "prune"] for command in commands)
    compose_build = next(
        command for command in commands if command[:3] == ["docker", "compose", "-f"]
    )
    assert compose_build[-5:-3] == ["build", "--builder"]
    assert compose_build[-3] == builder_name
    assert prune["returncode"] == 0
    assert removal["verified"] is True
    assert "flag{abcdefghijklmnop}" not in json.dumps(prune) + json.dumps(removal)


def test_builder_identity_mismatch_prevents_prune_or_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []
    builder = target_runner.BuildxBuilder(name="ravage_xben_cmp_" + "b" * 32, _created=True)

    def fake_buildx(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        commands.append(arguments)
        return subprocess.CompletedProcess(
            arguments, 0, stdout="Name: another-builder\nDriver: docker-container\n", stderr=""
        )

    monkeypatch.setattr(target_runner, "_run_buildx", fake_buildx)
    with pytest.raises(target_runner.TargetRunnerError, match="identity changed"):
        target_runner.cleanup_build_cache(builder)
    with pytest.raises(target_runner.TargetRunnerError, match="identity changed"):
        builder.destroy()
    assert commands == [("inspect", builder.name), ("inspect", builder.name)]


@pytest.mark.parametrize("binding", ["0.0.0.0:49152", "[::]:49152"])
def test_start_rejects_non_loopback_compose_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, binding: str
) -> None:
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag="flag{abcdefghijklmnop}",
        build_receipt=target_runner.CommandReceipt("build", 0, "", "", 0, 0, 0.0),
    )

    def fake_compose(
        _target: target_runner.XbenTarget,
        operation: str,
        _arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> tuple[target_runner._CommandResult, target_runner.CommandReceipt]:
        output = binding if operation == "port" else ""
        return (
            target_runner._CommandResult(0, output, ""),
            target_runner.CommandReceipt(operation, 0, "", "", 0, 0, 0.0),
        )

    monkeypatch.setattr(target_runner, "_run_compose", fake_compose)
    with pytest.raises(target_runner.TargetRunnerError, match="exact loopback"):
        target.start()
    assert target.active is False


def test_destroy_runs_down_when_logs_fail_and_marks_teardown_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag="flag{abcdefghijklmnop}",
        active=True,
        host_port=49152,
    )
    operations: list[str] = []

    def fake_compose(
        _target: target_runner.XbenTarget,
        operation: str,
        _arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> tuple[target_runner._CommandResult, target_runner.CommandReceipt]:
        operations.append(operation)
        if operation == "logs":
            raise subprocess.TimeoutExpired("docker compose logs", 60)
        return (
            target_runner._CommandResult(0, "", ""),
            target_runner.CommandReceipt(operation, 0, "", "", 0, 0, 0.0),
        )

    monkeypatch.setattr(target_runner, "_run_compose", fake_compose)
    monkeypatch.setattr(target_runner, "_project_container_ids", lambda _project: [])

    payload = target.destroy(evidence_dir=tmp_path / "evidence")

    assert operations == ["logs", "destroy"]
    assert payload["verified"] is False
    assert payload["errors"] == ["compose logs raised TimeoutExpired"]
    assert payload["remaining_container_ids"] == []
    assert target.active is False and target.host_port is None


def test_destroy_redacts_encoded_flags_and_cleans_before_writing_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flag = "flag{abcdefghijklmnop}"
    variants = (flag, b64encode(flag.encode()).decode(), flag.encode().hex(), quote(flag, safe=""))
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag=flag,
    )
    operations: list[str] = []

    def fake_compose(
        _target: target_runner.XbenTarget,
        operation: str,
        _arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> tuple[target_runner._CommandResult, target_runner.CommandReceipt]:
        operations.append(operation)
        output = "\n".join(variants) if operation == "logs" else ""
        return (
            target_runner._CommandResult(0, output, ""),
            target_runner.CommandReceipt(operation, 0, "", "", 0, 0, 0.0),
        )

    monkeypatch.setattr(target_runner, "_run_compose", fake_compose)
    monkeypatch.setattr(target_runner, "_project_container_ids", lambda _project: [])

    payload = target.destroy(evidence_dir=tmp_path / "evidence")
    retained = (tmp_path / "evidence" / "target.log").read_text(encoding="utf-8")

    assert operations == ["logs", "destroy"]
    assert payload["verified"] is True
    assert all(variant not in retained for variant in variants)
    assert retained.count("[REDACTED_FLAG]") == len(variants)


def test_destroy_removes_containers_before_evidence_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = target_runner.XbenTarget(
        case_id="XBEN-001-24",
        case_dir=tmp_path,
        compose_path=tmp_path / "compose.yml",
        project="xben_cmp_test",
        primary_service="web",
        primary_container_port=80,
        expected_flag="flag{abcdefghijklmnop}",
    )
    operations: list[str] = []
    verified: list[str] = []

    def fake_compose(
        _target: target_runner.XbenTarget,
        operation: str,
        _arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> tuple[target_runner._CommandResult, target_runner.CommandReceipt]:
        operations.append(operation)
        return (
            target_runner._CommandResult(0, "", ""),
            target_runner.CommandReceipt(operation, 0, "", "", 0, 0, 0.0),
        )

    def fake_verify(project: str) -> list[str]:
        verified.append(project)
        return []

    original_write_text = Path.write_text

    def fail_log_write(path: Path, data: str, **kwargs: object) -> int:
        if path.name == "target.log":
            raise OSError("evidence unavailable")
        return original_write_text(path, data, **kwargs)

    monkeypatch.setattr(target_runner, "_run_compose", fake_compose)
    monkeypatch.setattr(target_runner, "_project_container_ids", fake_verify)
    monkeypatch.setattr(Path, "write_text", fail_log_write)

    with pytest.raises(OSError, match="evidence unavailable"):
        target.destroy(evidence_dir=tmp_path / "evidence")

    assert operations == ["logs", "destroy"]
    assert verified == [target.project]
