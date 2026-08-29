from __future__ import annotations

import json
import subprocess
from io import StringIO
from typing import TYPE_CHECKING

import pytest
from ravage.xben_parts.models import XbenSettings
from ravage.xben_parts.runner import (
    _docker_image_inventory_health,
    run_xben,
)

if TYPE_CHECKING:
    from pathlib import Path

DOCKER_PREFLIGHT_TIMEOUT_SECONDS = 30


def _write_case(root: Path) -> None:
    case_dir = root / "XBEN-001-24"
    case_dir.mkdir(parents=True)
    case_dir.joinpath("benchmark.yaml").write_text(
        """
name: XBEN-001-24 Docker Health Gate
level: 1
tags:
  - infrastructure
content:
  - kind: description
    content_type: text/markdown
    content: Test challenge description.
main-service: web
main-service-port: 80
""".lstrip(),
        encoding="utf-8",
    )
    case_dir.joinpath("docker-compose.yml").write_text(
        """
services:
  web:
    image: nginx
    ports:
      - "8080:80"
""".lstrip(),
        encoding="utf-8",
    )


def test_docker_image_inventory_health_uses_read_only_inventory_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == DOCKER_PREFLIGHT_TIMEOUT_SECONDS
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="sha256:one\nsha256:two\nsha256:one\n",
            stderr="",
        )

    monkeypatch.setattr("ravage.xben_parts.runner.subprocess.run", fake_run)

    health = _docker_image_inventory_health()

    assert calls == [["docker", "image", "ls", "--quiet", "--no-trunc"]]
    assert health == {
        "healthy": True,
        "command": ["docker", "image", "ls", "--quiet", "--no-trunc"],
        "failure_kind": None,
        "exit_code": 0,
        "image_count": 2,
        "error": None,
    }


@pytest.mark.parametrize(
    "diagnostic",
    [
        "failed to read image metadata: content digest is unavailable",
        "image inventory database is corrupt",
    ],
)
def test_docker_image_inventory_health_rejects_any_command_failure(
    monkeypatch: pytest.MonkeyPatch,
    diagnostic: str,
) -> None:
    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr=diagnostic)

    monkeypatch.setattr("ravage.xben_parts.runner.subprocess.run", fake_run)

    health = _docker_image_inventory_health()

    assert health["healthy"] is False
    assert health["failure_kind"] == "command_failed"
    assert health["exit_code"] == 1
    assert diagnostic in str(health["error"])


@pytest.mark.parametrize(
    ("failure", "failure_kind", "error"),
    [
        (FileNotFoundError(), "command_not_found", "docker command was not found"),
        (
            subprocess.TimeoutExpired(["docker", "image", "ls"], DOCKER_PREFLIGHT_TIMEOUT_SECONDS),
            "timeout",
            "timed out after 30 seconds",
        ),
    ],
)
def test_docker_image_inventory_health_reports_unavailable_runtime(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    failure_kind: str,
    error: str,
) -> None:
    def fail_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise failure

    monkeypatch.setattr("ravage.xben_parts.runner.subprocess.run", fail_run)

    health = _docker_image_inventory_health()

    assert health["healthy"] is False
    assert health["failure_kind"] == failure_kind
    assert error in str(health["error"])


def test_xben_blocks_unhealthy_docker_inventory_before_case_work(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    benchmarks_root = tmp_path / "benchmarks"
    output_dir = tmp_path / "runs"
    _write_case(benchmarks_root)
    case_work_started = False

    monkeypatch.setattr(
        "ravage.xben_parts.runner._docker_image_inventory_health",
        lambda: {
            "healthy": False,
            "command": ["docker", "image", "ls", "--quiet", "--no-trunc"],
            "failure_kind": "command_failed",
            "exit_code": 1,
            "error": "docker image inventory command exited with status 1: store unavailable",
        },
    )

    def fail_if_case_starts(**_kwargs: object) -> None:
        nonlocal case_work_started
        case_work_started = True
        pytest.fail("case target/model work must not start after a blocked preflight")

    def fail_if_tool_image_is_inspected(_image: str) -> None:
        pytest.fail("tool-image inspection must not follow an unhealthy inventory check")

    monkeypatch.setattr("ravage.xben_parts.runner.run_xben_case", fail_if_case_starts)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._docker_image_provenance",
        fail_if_tool_image_is_inspected,
    )

    with pytest.raises(ValueError, match="Docker image inventory health check failed"):
        run_xben(
            XbenSettings(
                benchmarks_root=benchmarks_root,
                output_dir=output_dir,
                ids=("XBEN-001-24",),
                min_free_gib=0,
                tool_runtime="docker",
            ),
            stdout=StringIO(),
        )

    assert case_work_started is False
    preflight = json.loads((output_dir / "preflight.json").read_text(encoding="utf-8"))
    assert preflight["blocked"] is True
    assert preflight["docker_image_inventory"]["failure_kind"] == "command_failed"
    assert any(
        "Docker image inventory health check failed" in reason
        for reason in preflight["block_reasons"]
    )
