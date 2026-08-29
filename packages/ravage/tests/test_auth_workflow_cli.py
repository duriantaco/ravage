from __future__ import annotations

import json
import os
import stat
from typing import TYPE_CHECKING

import pytest
import yaml
from ravage import __main__ as cli
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

if TYPE_CHECKING:
    from pathlib import Path

_TARGET = "http://127.0.0.1:18752/"
_PRIVATE_FILE_MODE = 0o600
_ARGPARSE_ERROR = 2


def _write_brief(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "engagement_id": "22222222-2222-4222-8222-222222222222",
                "scope": {"in_scope": [_TARGET], "out_of_scope": []},
                "roe": {"max_rps": 5},
                "objectives": ["web_application_assessment"],
                "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
                "context": {"description": "Authorized local auth workflow test."},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _add_form_identity(brief: Path, env_file: Path) -> None:
    cli.main(
        [
            "auth",
            "add",
            str(brief),
            "--identity",
            "alice",
            "--login",
            "/login",
            "--health",
            "/account",
            "--marker",
            "Logout",
            "--env-file",
            str(env_file),
        ]
    )


def test_auth_add_generates_brief_private_env_and_next_commands(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    _write_brief(brief)

    _add_form_identity(brief, env_file)

    payload = yaml.safe_load(brief.read_text(encoding="utf-8"))
    identity = payload["authentication"]["identities"][0]
    assert identity["alias"] == "alice"
    assert identity["flow"]["endpoint"]["url"] == f"{_TARGET}login"
    assert identity["health_check"]["endpoint"]["url"] == f"{_TARGET}account"
    assert identity["health_check"]["authenticated_marker"] == "Logout"
    assert env_file.read_text(encoding="utf-8").splitlines()[-2:] == [
        "RAVAGE_ALICE_USERNAME=",
        "RAVAGE_ALICE_PASSWORD=",
    ]
    assert stat.S_IMODE(env_file.stat().st_mode) == _PRIVATE_FILE_MODE
    output = capsys.readouterr().out
    assert "RAVAGE // AUTH" in output
    assert "[added] alice · form" in output
    assert "ravage auth check" in output
    assert "ravage scan" in output
    assert "ravage attack" in output
    assert "--env-file" in output


def test_auth_list_and_empty_secret_check_are_clear_and_create_no_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    _write_brief(brief)
    _add_form_identity(brief, env_file)
    capsys.readouterr()
    monkeypatch.chdir(tmp_path)

    cli.main(["auth", "list", str(brief)])
    listed = capsys.readouterr().out
    assert "[alice] form" in listed
    assert "health=http://127.0.0.1:18752/account" in listed
    assert "login=http://127.0.0.1:18752/login" in listed
    assert "roles     authenticated" in listed
    assert "markers   present=Logout" in listed
    assert "secrets   RAVAGE_ALICE_USERNAME, RAVAGE_ALICE_PASSWORD" in listed

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "auth",
                "check",
                str(brief),
                "--identity",
                "alice",
                "--env-file",
                str(env_file),
            ]
        )
    assert exc_info.value.code == 1
    checked = capsys.readouterr().out
    assert "secret_unset" in checked
    assert "RAVAGE_ALICE_USERNAME" in checked
    assert not (tmp_path / "runs").exists()


def test_auth_check_verifies_real_configured_login_stages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    _write_brief(brief)
    _add_form_identity(brief, env_file)
    capsys.readouterr()
    env_file.write_text(
        "RAVAGE_ALICE_USERNAME=alice\nRAVAGE_ALICE_PASSWORD=correct-horse\n",
        encoding="utf-8",
    )
    seen: list[tuple[str, str]] = []

    def request(  # noqa: PLR0913
        session: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        del session, headers, timeout_seconds
        seen.append((method, url))
        if method == "GET" and url.endswith("/login"):
            return ProbeResponse(
                method=method,
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=1,
                body=(
                    '<form method="post" action="/login">'
                    '<input name="username"><input name="password" type="password">'
                    "</form>"
                ),
            )
        if method == "POST" and url.endswith("/login"):
            assert data == b"username=alice&password=correct-horse"
            return ProbeResponse(
                method=method,
                url=url,
                status=302,
                final_url=url,
                elapsed_ms=1,
            )
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="Account Logout",
        )

    monkeypatch.setattr(ProbeSession, "request", request)

    cli.main(
        [
            "auth",
            "check",
            str(brief),
            "--env-file",
            str(env_file),
        ]
    )

    output = capsys.readouterr().out
    observed_stages = [
        stage for stage in ("configuration", "secrets", "login", "health") if stage in output
    ]
    assert observed_stages == [
        "configuration",
        "secrets",
        "login",
        "health",
    ]
    assert "[ready] authenticated scan can start" in output
    assert "correct-horse" not in output
    assert seen == [
        ("GET", f"{_TARGET}login"),
        ("POST", f"{_TARGET}login"),
        ("GET", f"{_TARGET}account"),
    ]


def test_init_can_create_an_authenticated_scan_ready_project(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "nested" / "brief.yaml"
    env_file = tmp_path / "nested" / ".env.ravage"

    cli.main(
        [
            "init",
            "--target-url",
            _TARGET,
            "--brief",
            str(brief),
            "--env-file",
            str(env_file),
            "--description",
            "Authorized authenticated localhost test.",
            "--auth",
            "form",
            "--auth-identity",
            "alice",
            "--auth-username-field",
            "email",
            "--auth-health",
            "/account",
            "--auth-marker",
            "Logout",
        ]
    )

    payload = yaml.safe_load(brief.read_text(encoding="utf-8"))
    assert payload["authentication"]["identities"][0]["alias"] == "alice"
    assert "email" in payload["authentication"]["identities"][0]["flow"]["secret_refs"]
    env_text = env_file.read_text(encoding="utf-8")
    assert "RAVAGE_ALICE_USERNAME=" in env_text
    assert "OPENAI_API_KEY" not in env_text
    assert stat.S_IMODE(env_file.stat().st_mode) == _PRIVATE_FILE_MODE
    output = capsys.readouterr().out
    assert "[auth:added] alice · form" in output
    assert "ravage auth check" in output
    assert "ravage scan" in output
    assert "ravage attack" in output
    assert "--identity alice" in output
    assert "ravage setup check" not in output
    assert "source " not in output


def test_init_auth_rejects_path_collision_without_creating_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "ravage.yaml"

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "init",
                "--target-url",
                _TARGET,
                "--brief",
                str(output),
                "--env-file",
                str(output),
                "--auth",
                "form",
                "--auth-health",
                "/account",
                "--auth-marker",
                "Logout",
            ]
        )

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert "must be different paths" in capsys.readouterr().err
    assert not output.exists()


def test_init_auth_validation_failure_preserves_forced_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    brief.write_text("operator-owned brief\n", encoding="utf-8")
    env_file.write_text("OPERATOR_SECRET=keep\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "init",
                "--target-url",
                _TARGET,
                "--brief",
                str(brief),
                "--env-file",
                str(env_file),
                "--force",
                "--auth",
                "form",
                "--auth-identity",
                "!!!",
                "--auth-health",
                "/account",
                "--auth-marker",
                "Logout",
            ]
        )

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert "could not configure authentication" in capsys.readouterr().err
    assert brief.read_text(encoding="utf-8") == "operator-owned brief\n"
    assert env_file.read_text(encoding="utf-8") == "OPERATOR_SECRET=keep\n"


def test_scan_loads_env_file_and_labels_authenticated_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    run_dir = tmp_path / "run"
    _write_brief(brief)
    cli.main(
        [
            "auth",
            "add",
            str(brief),
            "--identity",
            "api",
            "--type",
            "bearer",
            "--health",
            "/api/me",
            "--marker",
            "api-user",
            "--env-file",
            str(env_file),
        ]
    )
    capsys.readouterr()
    env_file.write_text(
        'export RAVAGE_API_TOKEN="runtime-token" # prefer this file\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("RAVAGE_API_TOKEN", "stale-inherited-token")

    def request(
        session: ProbeSession,
        method: str,
        url: str,
        **kwargs: object,
    ) -> ProbeResponse:
        del kwargs
        assert session.default_headers["Authorization"] == "Bearer runtime-token"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="api-user",
        )

    def run_probe(*args: object, **kwargs: object) -> ProbeRunResult:
        del args
        assert isinstance(kwargs.get("session"), ProbeSession)
        return ProbeRunResult(ok=True, probe="surface_map", summary="protected surface reached")

    monkeypatch.setattr(ProbeSession, "request", request)
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)

    cli.main(
        [
            "scan",
            str(brief),
            "--identity",
            "api",
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
        ]
    )

    output = capsys.readouterr().out
    assert f"[auth:env] {env_file}" in output
    assert "[auth:check] identity=api" in output
    assert "[auth:ok] identity=api" in output
    assert "[scan:ok] [api] surface_map" in output
    assert "runtime-token" not in output
    assert os.environ["RAVAGE_API_TOKEN"] == "stale-inherited-token"  # noqa: S105


def test_auth_env_discovery_stays_beside_brief_and_prefers_ravage_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    elsewhere = tmp_path / "elsewhere"
    project.mkdir()
    elsewhere.mkdir()
    brief = project / "brief.yaml"
    monkeypatch.chdir(elsewhere)
    (elsewhere / ".env.ravage").write_text("IGNORED=value\n", encoding="utf-8")

    assert cli._discover_auth_env_file(brief) is None  # noqa: SLF001

    legacy = project / ".env"
    legacy.write_text("LEGACY=value\n", encoding="utf-8")
    assert cli._discover_auth_env_file(brief) == legacy  # noqa: SLF001

    preferred = project / ".env.ravage"
    preferred.write_text("PREFERRED=value\n", encoding="utf-8")
    assert cli._discover_auth_env_file(brief) == preferred  # noqa: SLF001


def test_invalid_brief_is_a_concise_cli_error_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "invalid.yaml"
    brief.write_text("[]\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", str(brief), "--probe", "surface_map"])

    assert exc_info.value.code == _ARGPARSE_ERROR
    error = capsys.readouterr().err
    assert "invalid engagement brief" in error
    assert "YAML mapping" in error
    assert "Traceback" not in error


def test_attack_fails_closed_when_configured_authentication_has_no_secrets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    _write_brief(brief)
    _add_form_identity(brief, env_file)
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "attack",
                str(brief),
                "--model-profile",
                "local-ollama",
                "--no-tool-recon",
            ]
        )

    assert exc_info.value.code != 0
    error = capsys.readouterr().err
    assert "cannot authenticate identity 'alice'" in error
    assert "secret" in error.lower()


def test_auth_check_json_is_machine_readable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    _write_brief(brief)
    _add_form_identity(brief, env_file)
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "auth",
                "check",
                str(brief),
                "--env-file",
                str(env_file),
                "--json",
            ]
        )

    assert exc_info.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason_code"] == "secret_unset"
    assert [stage["name"] for stage in payload["stages"]] == [
        "configuration",
        "secrets",
        "login",
        "health",
    ]
