from __future__ import annotations

import subprocess
from types import SimpleNamespace
from typing import TYPE_CHECKING

from ravage import setup_checks
from ravage.setup_checks import (
    discover_brief,
    discover_env_file,
    docker_compose_diagnostic,
    labs_diagnostic,
    local_model_diagnostic,
    playwright_diagnostic,
    run_location_diagnostic,
    target_reachability_diagnostic,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

MODEL_CHECK_TIMEOUT_SECONDS = 3


def test_discovers_init_files_next_to_each_other(tmp_path: Path) -> None:
    brief = tmp_path / "ravage-brief.yaml"
    env = tmp_path / ".env.ravage"
    brief.write_text("scope: {}\n", encoding="utf-8")
    env.write_text("OPENAI_API_KEY=\n", encoding="utf-8")

    assert discover_brief(directory=tmp_path) == brief
    assert discover_env_file(brief_path=brief) == env


def test_run_location_rejects_a_regular_file(tmp_path: Path) -> None:
    output = tmp_path / "runs"
    output.write_text("occupied", encoding="utf-8")

    diagnostic = run_location_diagnostic(output)

    assert diagnostic.status == "fail"
    assert "not a directory" in diagnostic.detail
    assert "--run-root" in diagnostic.fix


def test_browser_diagnostic_distinguishes_missing_chromium(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        setup_checks,
        "_playwright_executable",
        lambda: tmp_path / "missing-chromium",
    )

    diagnostic = playwright_diagnostic(required=True)

    assert diagnostic.status == "fail"
    assert "Chromium browser is missing" in diagnostic.detail
    assert "--install-browser" in diagnostic.fix


def test_browser_diagnostic_treats_optional_browser_as_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing() -> Path:
        message = "No module named 'playwright'"
        raise ModuleNotFoundError(message)

    monkeypatch.setattr(setup_checks, "_playwright_executable", missing)

    diagnostic = playwright_diagnostic(required=False)

    assert diagnostic.status == "warn"
    assert "Playwright is not installed" in diagnostic.detail


def test_browser_diagnostic_accepts_existing_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "chromium"
    executable.write_bytes(b"browser")
    executable.chmod(0o755)
    monkeypatch.setattr(setup_checks, "_playwright_executable", lambda: executable)

    diagnostic = playwright_diagnostic(required=True)

    assert diagnostic.status == "ok"
    assert str(executable) in diagnostic.detail


def test_browser_diagnostic_rejects_non_executable_chromium(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "chromium"
    executable.write_bytes(b"browser")
    executable.chmod(0o644)
    monkeypatch.setattr(setup_checks, "_playwright_executable", lambda: executable)

    diagnostic = playwright_diagnostic(required=True)

    assert diagnostic.status == "fail"
    assert "not executable" in diagnostic.detail


def test_docker_diagnostic_optional_when_command_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_checks.shutil, "which", lambda _name: None)

    diagnostic = docker_compose_diagnostic(required=False)

    assert diagnostic.status == "warn"
    assert "core localhost scans still work" in diagnostic.detail


def test_docker_diagnostic_checks_daemon_and_compose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replies = iter(
        (
            subprocess.CompletedProcess([], 0, "27.1.0\n", ""),
            subprocess.CompletedProcess([], 0, "2.30.0\n", ""),
        )
    )
    monkeypatch.setattr(setup_checks.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(setup_checks.subprocess, "run", lambda *_args, **_kwargs: next(replies))

    diagnostic = docker_compose_diagnostic(required=True)

    assert diagnostic.status == "ok"
    assert "27.1.0" in diagnostic.detail
    assert "2.30.0" in diagnostic.detail


def test_labs_diagnostic_is_required_only_for_lab_workflow(tmp_path: Path) -> None:
    optional = labs_diagnostic(required=False, labs_dir=tmp_path)
    required = labs_diagnostic(required=True, labs_dir=tmp_path)

    assert optional.status == "warn"
    assert required.status == "fail"


def test_labs_diagnostic_reports_malformed_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def malformed(*_args: object, **_kwargs: object) -> object:
        message = "lab manifest must be a YAML object"
        raise ValueError(message)

    monkeypatch.setattr(setup_checks, "list_labs", malformed)

    diagnostic = labs_diagnostic(required=True, labs_dir=tmp_path)

    assert diagnostic.status == "fail"
    assert "could not be loaded" in diagnostic.detail
    assert "RAVAGE_LABS_DIR" in diagnostic.fix


def test_target_diagnostic_rejects_server_error_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Session:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, _url: str) -> object:
            return SimpleNamespace(status=503, final_url="http://127.0.0.1:3000/", error="")

    monkeypatch.setattr(setup_checks, "ProbeSession", Session)

    diagnostic = target_reachability_diagnostic(
        "http://127.0.0.1:3000",
        in_scope=("http://127.0.0.1:3000",),
        out_of_scope=(),
        max_rps=5,
        allow_remote_target=False,
        required=True,
    )

    assert diagnostic.status == "fail"
    assert "HTTP 503" in diagnostic.detail


def test_target_diagnostic_redacts_redirect_credentials_and_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Session:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, _url: str) -> object:
            return SimpleNamespace(
                status=200,
                final_url="http://operator:password@127.0.0.1:3000/private?token=secret",
                error="",
            )

    monkeypatch.setattr(setup_checks, "ProbeSession", Session)

    diagnostic = target_reachability_diagnostic(
        "http://127.0.0.1:3000/private?token=secret",
        in_scope=("http://127.0.0.1:3000",),
        out_of_scope=(),
        max_rps=5,
        allow_remote_target=False,
        required=True,
    )

    assert diagnostic.status == "ok"
    assert diagnostic.detail.endswith("http://127.0.0.1:3000")
    assert "password" not in diagnostic.detail
    assert "secret" not in diagnostic.detail


def test_target_diagnostic_reports_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Session:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, _url: str) -> object:
            return SimpleNamespace(
                status=None,
                final_url="",
                error="[Errno 61] Connection refused",
            )

    monkeypatch.setattr(setup_checks, "ProbeSession", Session)

    diagnostic = target_reachability_diagnostic(
        "http://127.0.0.1:3000",
        in_scope=("http://127.0.0.1:3000",),
        out_of_scope=(),
        max_rps=5,
        allow_remote_target=False,
        required=True,
    )

    assert diagnostic.status == "fail"
    assert "Connection refused" in diagnostic.detail
    assert "Start the application" in diagnostic.fix


def test_target_diagnostic_does_not_contact_remote_without_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError

    monkeypatch.setattr(setup_checks, "ProbeSession", forbidden)

    diagnostic = target_reachability_diagnostic(
        "https://staging.example.test",
        in_scope=("https://staging.example.test",),
        out_of_scope=(),
        max_rps=5,
        allow_remote_target=False,
        required=False,
    )

    assert diagnostic.status == "warn"
    assert "not contacted" in diagnostic.detail
    assert "--authorized-remote-target" in diagnostic.fix


def test_local_model_diagnostic_lists_models_without_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    class Session:
        def __init__(self, endpoint: str, **kwargs: object) -> None:
            calls.append(("init", (endpoint, kwargs)))

        def get(self, endpoint: str) -> object:
            calls.append(("get", endpoint))
            return SimpleNamespace(
                status=200,
                body='{"data":[{"id":"qwen2.5-coder:14b"}]}',
                truncated=False,
                error="",
            )

    monkeypatch.setattr(setup_checks, "ProbeSession", Session)

    diagnostic = local_model_diagnostic(
        provider="ollama",
        model="qwen2.5-coder:14b",
        base_url="http://localhost:11434/v1",
    )

    assert diagnostic.status == "ok"
    assert calls[0][0] == "init"
    endpoint, kwargs = calls[0][1]
    assert endpoint == "http://localhost:11434/v1/models"
    assert kwargs["timeout_seconds"] == MODEL_CHECK_TIMEOUT_SECONDS
    assert calls[1] == ("get", "http://localhost:11434/v1/models")


def test_local_model_diagnostic_requires_selected_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Session:
        def __init__(self, _endpoint: str, **_kwargs: object) -> None:
            pass

        def get(self, _endpoint: str) -> object:
            return SimpleNamespace(
                status=200,
                body='{"models":[{"name":"different-model"}]}',
                truncated=False,
                error="",
            )

    monkeypatch.setattr(setup_checks, "ProbeSession", Session)

    diagnostic = local_model_diagnostic(
        provider="ollama",
        model="qwen2.5-coder:14b",
        base_url="http://localhost:11434/v1",
    )

    assert diagnostic.status == "fail"
    assert "is not available" in diagnostic.detail
    assert "install or load" in diagnostic.fix
