from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
import yaml
from ravage import __main__ as cli
from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

if TYPE_CHECKING:
    from pathlib import Path

_TARGET_URL = "http://127.0.0.1:18762/"
_ARGPARSE_ERROR = 2
_SERVICE_ENV = "RAVAGE_ATTACK_SERVICE_TOKEN"
_OPERATOR_ENV = "RAVAGE_ATTACK_OPERATOR_TOKEN"


def _write_bearer_brief(path: Path, *aliases: str) -> None:
    identities = []
    for alias in aliases:
        identities.append(  # noqa: PERF401 - keep the nested identity fixture readable
            {
                "alias": alias,
                "roles": ["api"],
                "flow": {
                    "kind": "bearer",
                    "secret_refs": {
                        "token": {
                            "provider": "environment",
                            "key": f"RAVAGE_ATTACK_{alias.upper()}_TOKEN",
                        }
                    },
                },
                "health_check": {
                    "endpoint": {
                        "url": f"{_TARGET_URL}api/me",
                        "scope": "target",
                    },
                    "success_statuses": [200],
                    "authenticated_marker": f"{alias}-account",
                },
            }
        )
    path.write_text(
        yaml.safe_dump(
            {
                "engagement_id": "33333333-3333-4333-8333-333333333333",
                "scope": {"in_scope": [_TARGET_URL], "out_of_scope": []},
                "roe": {"max_rps": 10},
                "objectives": ["web_application_assessment"],
                "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
                "context": {"description": "Authorized authenticated attack test."},
                "authentication": {"identities": identities},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "selection_args",
    [("--identity", "service"), ()],
    ids=["explicit", "only-identity"],
)
def test_attack_forwards_selected_identity_and_private_auth_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selection_args: tuple[str, ...],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    run_dir = tmp_path / "run"
    _write_bearer_brief(brief, "service")
    env_file.write_text(f"{_SERVICE_ENV}=file-value\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        commands.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)
    args = [
        "attack",
        str(brief),
        "--env-file",
        str(env_file),
        "--run-dir",
        str(run_dir),
        "--model-profile",
        "local-ollama",
        "--no-tool-recon",
    ]
    args.extend(selection_args)

    cli.main(args)

    assert len(commands) == 1
    command = commands[0]
    assert command[command.index("--identity") + 1] == "service"
    assert command[command.index("--auth-env-file") + 1] == str(env_file)


def test_attack_requires_identity_when_brief_configures_multiple_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_bearer_brief(brief, "service", "operator")

    def unexpected_run(_argv: list[str], _stdout_path: Path) -> int:
        pytest.fail("the inner attack must not start until an identity is selected")

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", unexpected_run)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "attack",
                str(brief),
                "--run-dir",
                str(run_dir),
                "--model-profile",
                "local-ollama",
                "--no-tool-recon",
            ]
        )

    assert exc_info.value.code == _ARGPARSE_ERROR
    error = capsys.readouterr().err
    assert "choose --identity" in error
    assert "service" in error
    assert "operator" in error
    assert not run_dir.exists()


def test_attack_auth_env_file_overlays_without_mutating_process_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    run_dir = tmp_path / "run"
    _write_bearer_brief(brief, "service", "operator")
    env_file.write_text(
        f"{_SERVICE_ENV}=file-service-value\n{_OPERATOR_ENV}=file-operator-value\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(_SERVICE_ENV, "inherited-service-value")
    monkeypatch.delenv(_OPERATOR_ENV, raising=False)
    observed_authorization: list[str] = []
    observed_settings: list[cli.AIWebAgentSettings] = []

    def request(
        session: ProbeSession,
        method: str,
        url: str,
        **kwargs: object,
    ) -> ProbeResponse:
        del kwargs
        authorization = session.default_headers.get("Authorization", "")
        observed_authorization.append(authorization)
        healthy = authorization == "Bearer file-service-value"
        return ProbeResponse(
            method=method,
            url=url,
            status=200 if healthy else 401,
            final_url=url,
            elapsed_ms=1,
            body="service-account" if healthy else "Sign in",
        )

    def run_agent(
        *,
        brief_path: Path,
        target_url: str,
        settings: cli.AIWebAgentSettings,
    ) -> Path:
        assert brief_path == brief
        assert target_url == _TARGET_URL
        observed_settings.append(settings)
        return tmp_path / "audit.db"

    monkeypatch.setattr(ProbeSession, "request", request)
    monkeypatch.setattr(cli, "run_ai_web_agent", run_agent)

    cli.main(
        [
            "attack",
            str(brief),
            "--identity",
            "service",
            "--env-file",
            str(env_file),
            "--run-dir",
            str(run_dir),
            "--model-profile",
            "local-ollama",
            "--display",
            "quiet",
            "--no-tool-recon",
        ]
    )

    assert observed_authorization == ["Bearer file-service-value"]
    assert len(observed_settings) == 1
    authentication = observed_settings[0].authentication
    assert authentication is not None
    assert authentication.identity == "service"
    assert os.environ[_SERVICE_ENV] == "inherited-service-value"
    assert _OPERATOR_ENV not in os.environ


def test_attack_auth_failure_happens_before_agent_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    run_dir = tmp_path / "run"
    _write_bearer_brief(brief, "service")
    env_file.write_text(f"{_SERVICE_ENV}=\n", encoding="utf-8")
    monkeypatch.delenv(_SERVICE_ENV, raising=False)
    agent_calls = 0

    def unexpected_agent(**_kwargs: object) -> Path:
        nonlocal agent_calls
        agent_calls += 1
        pytest.fail("authentication must succeed before the agent is invoked")

    monkeypatch.setattr(cli, "run_ai_web_agent", unexpected_agent)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "attack",
                str(brief),
                "--identity",
                "service",
                "--env-file",
                str(env_file),
                "--run-dir",
                str(run_dir),
                "--model-profile",
                "local-ollama",
                "--no-tool-recon",
            ]
        )

    assert exc_info.value.code != 0
    assert agent_calls == 0
    error = capsys.readouterr().err
    assert "cannot authenticate identity 'service'" in error
    assert "secret" in error.lower()
    assert "unrecognized arguments" not in error


def test_inner_authenticated_attack_without_identity_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env_file = tmp_path / ".env.ravage"
    _write_bearer_brief(brief, "service")
    env_file.write_text(f"{_SERVICE_ENV}=file-value\n", encoding="utf-8")
    agent_calls = 0

    def unexpected_agent(**_kwargs: object) -> Path:
        nonlocal agent_calls
        agent_calls += 1
        pytest.fail("the inner CLI must reject an authenticated brief without an identity")

    monkeypatch.setattr(cli, "run_ai_web_agent", unexpected_agent)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "--brief",
                str(brief),
                "--target-url",
                _TARGET_URL,
                "--auth-env-file",
                str(env_file),
                "--model-profile",
                "local-ollama",
                "--display",
                "quiet",
            ]
        )

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert agent_calls == 0
    error = capsys.readouterr().err
    assert "--identity" in error
    assert "unrecognized arguments" not in error


def test_resume_identity_mismatch_is_rejected_before_authentication_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    state_path = tmp_path / "working_state.json"
    _write_bearer_brief(brief, "service", "operator")
    save_agent_state(
        state_path,
        target_url=_TARGET_URL,
        state=AgentState(surface={"authenticated_identity": "operator"}),
    )
    authentication_calls = 0

    def unexpected_authentication(**_kwargs: object) -> object:
        nonlocal authentication_calls
        authentication_calls += 1
        pytest.fail("resume identity validation must run before login or health traffic")

    monkeypatch.setattr(cli, "build_authenticated_attack_runtime", unexpected_authentication)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "--brief",
                str(brief),
                "--target-url",
                _TARGET_URL,
                "--identity",
                "service",
                "--resume-from",
                str(state_path),
                "--model-profile",
                "local-ollama",
                "--display",
                "quiet",
            ]
        )

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert authentication_calls == 0
    assert "different identity" in capsys.readouterr().err
