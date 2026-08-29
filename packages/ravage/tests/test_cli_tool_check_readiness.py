from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from ravage import cli_tool_check
from ravage.cli_tools import TOOL_RUNTIME_BINARIES

if TYPE_CHECKING:
    from pathlib import Path


def _tool_status(*, missing: set[str] | None = None) -> dict[str, dict[str, object]]:
    missing = missing or set()
    return {
        name: {
            "available": name not in missing,
            "path": "" if name in missing else f"/usr/bin/{name}",
        }
        for name in TOOL_RUNTIME_BINARIES
    }


def _unavailable_host() -> dict[str, dict[str, object]]:
    return {
        name: {"available": False, "path": "", "source": "", "error": ""}
        for name in TOOL_RUNTIME_BINARIES
    }


def _checked_host_status(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, dict[str, object]]:
    monkeypatch.setattr(
        cli_tool_check,
        "_docker_tool_status",
        lambda *, image: {
            "available": False,
            "image": image,
            "tools": {},
            "error": "not installed",
        },
    )
    report = cli_tool_check.tool_check_report(image="ravage-tools:test")
    host = report["host"]
    assert isinstance(host, dict)
    return {str(name): item for name, item in host.items() if isinstance(item, dict)}


def test_tool_check_recommends_only_a_ready_docker_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_tool_check, "_host_tool_status", _unavailable_host)
    monkeypatch.setattr(
        cli_tool_check,
        "_docker_tool_status",
        lambda *, image: {
            "available": True,
            "image": image,
            "tools": _tool_status(),
            "error": "",
        },
    )

    report = cli_tool_check.tool_check_report(image="ravage-tools:test")

    docker = report["docker"]
    assert isinstance(docker, dict)
    assert docker["available"] is True
    assert docker["ready"] is True
    assert report["recommendation"] == ("use --tool-runtime auto or --tool-runtime docker")


def test_tool_check_does_not_recommend_docker_after_probe_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_tool_check, "_host_tool_status", _unavailable_host)
    monkeypatch.setattr(
        cli_tool_check,
        "_docker_tool_status",
        lambda *, image: {
            "available": True,
            "image": image,
            "tools": {},
            "error": "Docker tool probe timed out",
        },
    )

    report = cli_tool_check.tool_check_report(image="ravage-tools:test")

    docker = report["docker"]
    assert isinstance(docker, dict)
    assert docker["available"] is True
    assert docker["ready"] is False
    assert report["recommendation"] == (
        "fix the Docker runtime check (Docker tool probe timed out), then rerun ravage tools check"
    )


def test_tool_check_explains_incomplete_docker_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_tool_check, "_host_tool_status", _unavailable_host)
    monkeypatch.setattr(
        cli_tool_check,
        "_docker_tool_status",
        lambda *, image: {
            "available": True,
            "image": image,
            "tools": _tool_status(missing={"nuclei"}),
            "error": "",
        },
    )

    report = cli_tool_check.tool_check_report(image="ravage-tools:test")

    docker = report["docker"]
    assert isinstance(docker, dict)
    assert docker["ready"] is False
    recommendation = report["recommendation"]
    assert isinstance(recommendation, str)
    assert "missing nuclei" in recommendation
    assert "ravage tools install --method docker --execute" in recommendation


@pytest.mark.parametrize("missing_alternative", ["nc", "ncat"])
def test_docker_runtime_accepts_either_netcat_binary(
    monkeypatch: pytest.MonkeyPatch,
    missing_alternative: str,
) -> None:
    monkeypatch.setattr(cli_tool_check, "_host_tool_status", _unavailable_host)
    monkeypatch.setattr(
        cli_tool_check,
        "_docker_tool_status",
        lambda *, image: {
            "available": True,
            "image": image,
            "tools": _tool_status(missing={missing_alternative}),
            "error": "",
        },
    )

    report = cli_tool_check.tool_check_report(image="ravage-tools:test")

    docker = report["docker"]
    assert isinstance(docker, dict)
    assert docker["ready"] is True
    assert report["recommendation"] == ("use --tool-runtime auto or --tool-runtime docker")


def test_host_status_rejects_directory_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    override = tmp_path / "nmap"
    override.mkdir()
    monkeypatch.setenv("RAVAGE_NMAP_BIN", str(override))
    monkeypatch.setattr(cli_tool_check.shutil, "which", lambda _tool: None)

    status = _checked_host_status(monkeypatch)["nmap"]

    assert status["available"] is False
    assert status["path"] == str(override)
    assert status["source"] == "RAVAGE_NMAP_BIN"
    assert status["error"] == "configured path is not a regular file"


def test_host_status_rejects_non_executable_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    override = tmp_path / "nmap"
    override.write_text("not executable", encoding="utf-8")
    override.chmod(0o644)
    monkeypatch.setenv("RAVAGE_NMAP_BIN", str(override))
    monkeypatch.setattr(cli_tool_check.shutil, "which", lambda _tool: None)

    status = _checked_host_status(monkeypatch)["nmap"]

    assert status["available"] is False
    assert status["error"] == "configured file is not executable"


def test_host_status_rejects_non_executable_project_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tool = tmp_path / ".tools" / "bin" / "ffuf"
    tool.parent.mkdir(parents=True)
    tool.write_text("not executable", encoding="utf-8")
    tool.chmod(0o644)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("RAVAGE_FFUF_BIN", raising=False)
    monkeypatch.setattr(cli_tool_check.shutil, "which", lambda _tool: None)

    status = _checked_host_status(monkeypatch)["ffuf"]

    assert status["available"] is False
    assert status["path"] == str(tool)
    assert status["source"] == ".tools/bin"
    assert status["error"] == "configured file is not executable"


def test_host_status_accepts_executable_project_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tool = tmp_path / ".tools" / "bin" / "ffuf"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("RAVAGE_FFUF_BIN", raising=False)
    monkeypatch.setattr(cli_tool_check.shutil, "which", lambda _tool: None)

    status = _checked_host_status(monkeypatch)["ffuf"]

    assert status["available"] is True
    assert status["path"] == str(tool)
    assert status["source"] == ".tools/bin"
    assert status["error"] == ""
