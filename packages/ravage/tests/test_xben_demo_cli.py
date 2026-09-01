from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml
from ravage import __main__ as cli
from ravage.run_data.brief import load_engagement_brief
from ravage.xben_parts import demo

if TYPE_CHECKING:
    from ravage.xben_parts.models import XbenSettings


DEMO_CASE_ID = "XBEN-009-24"
DEMO_MODEL_PROFILE = "hosted-openai-gpt-5.4-high"
DEMO_MAX_TURNS = 10
DEMO_MAX_MODEL_REQUESTS = 10
DEMO_TIMEOUT_SECONDS = 600
DEMO_MAX_COST_USD = 1.50
DEMO_INPUT_TOKEN_CEILING = 20_000
DEMO_MIN_FREE_GIB = 10
TESTFIRE_TARGET_URL = "https://demo.testfire.net/login.jsp?mode=demo"
TESTFIRE_MAX_TURNS = 6
TESTFIRE_MAX_REQUESTS = 24
TESTFIRE_MAX_BODY_BYTES = 1_024
TESTFIRE_MAX_RPS = 0.5
TWO_RUNS = 2
ARGPARSE_ERROR_EXIT = 2


def _benchmark_root(tmp_path: Path) -> Path:
    root = tmp_path / "benchmarks"
    root.joinpath(DEMO_CASE_ID).mkdir(parents=True)
    return root


def _successful_report() -> dict[str, object]:
    return {
        "run_status": "complete",
        "summary": {"solved": 1, "total": 1},
        "cases": [{"benchmark_id": DEMO_CASE_ID, "solved": True}],
    }


def _failed_report() -> dict[str, object]:
    return {
        "run_status": "complete",
        "summary": {"solved": 0, "total": 1},
        "cases": [{"benchmark_id": DEMO_CASE_ID, "solved": False}],
    }


def _capture_runs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    report: dict[str, object] | None = None,
) -> list[XbenSettings]:
    captured: list[XbenSettings] = []

    def run(settings: XbenSettings) -> dict[str, object]:
        captured.append(settings)
        return report or _successful_report()

    monkeypatch.setattr(demo, "run_xben", run)
    return captured


def _configure_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Path:
    root = _benchmark_root(tmp_path)
    monkeypatch.setenv("XBEN_ROOT", str(root))
    monkeypatch.chdir(tmp_path)
    return root


def test_top_level_cli_dispatches_demo_xben(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _configure_root(monkeypatch, tmp_path)
    captured = _capture_runs(monkeypatch)

    cli.main(["demo", "xben"])

    assert len(captured) == 1
    assert captured[0].benchmarks_root == root
    assert captured[0].ids == (DEMO_CASE_ID,)


def test_demo_help_exposes_both_live_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as top_level:
        cli.main(["--help"])

    assert top_level.value.code == 0
    top_level_output = capsys.readouterr().out
    assert "ravage demo xben" in top_level_output
    assert "ravage demo testfire --authorized-remote-target" in top_level_output

    with pytest.raises(SystemExit) as captured:
        cli.main(["demo", "--help"])

    assert captured.value.code == 0
    output = capsys.readouterr().out
    assert "{xben,testfire}" in output
    assert "build, attack, score, and remove one local XBEN target" in output
    assert "deliberately vulnerable" in output
    assert "banking demo" in output


def test_demo_testfire_requires_explicit_remote_authorization(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    called = False

    def attack(_args: list[str]) -> None:
        nonlocal called
        called = True

    with pytest.raises(SystemExit) as captured:
        demo.handle_demo_command(
            ["testfire", "--output-dir", str(tmp_path / "run")],
            attack_runner=attack,
        )

    assert captured.value.code == ARGPARSE_ERROR_EXIT
    assert called is False
    error = capsys.readouterr().err
    assert "--authorized-remote-target" in error
    assert demo.TESTFIRE_AUTHORIZATION_URL in error


def test_demo_testfire_uses_immutable_scope_and_enforced_request_profile(
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []
    run_dir = tmp_path / "testfire-run"

    def attack(args: list[str]) -> None:
        commands.append(args)

    demo.handle_demo_command(
        [
            "testfire",
            "--authorized-remote-target",
            "--output-dir",
            str(run_dir),
        ],
        attack_runner=attack,
    )

    [command] = commands
    brief_path = Path(command[0])
    brief = yaml.safe_load(brief_path.read_text(encoding="utf-8"))
    loaded_brief = load_engagement_brief(brief_path)
    assert command[command.index("--target-url") + 1] == TESTFIRE_TARGET_URL
    assert command[command.index("--run-dir") + 1] == str(run_dir)
    assert command[command.index("--model-profile") + 1] == DEMO_MODEL_PROFILE
    assert command[command.index("--model-tier") + 1] == "high"
    assert command[command.index("--max-turns") + 1] == str(TESTFIRE_MAX_TURNS)
    assert command[command.index("--traffic-policy") + 1] == "low-noise"
    assert command[command.index("--max-physical-requests") + 1] == str(
        TESTFIRE_MAX_REQUESTS
    )
    assert command[command.index("--traffic-max-rps") + 1] == str(TESTFIRE_MAX_RPS)
    assert command[command.index("--traffic-request-profile") + 1] == (
        "testfire-login-demo"
    )
    assert "--authorized-remote-target" in command
    assert "--tool-runtime" in command
    assert command[command.index("--tool-runtime") + 1] == "docker"
    assert "--no-tool-recon" in command
    assert "--show-agent-actions" in command
    assert "--allow-paid-models" in command
    assert "--report" in command
    assert brief["scope"] == {
        "in_scope": list(demo.TESTFIRE_SCOPE_URLS),
        "out_of_scope": [],
    }
    assert brief["roe"]["max_rps"] == demo.TESTFIRE_ROE_MAX_RPS
    assert loaded_brief.roe.max_rps == demo.TESTFIRE_ROE_MAX_RPS
    assert brief["roe"]["no_destructive_actions"] is True
    assert brief["context"]["authorization_reference"] == (
        demo.TESTFIRE_AUTHORIZATION_URL
    )
    assert brief["context"]["stop_after_first_finding"] is True


def test_top_level_cli_dispatches_demo_testfire_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def run(argv: list[str], _stdout_path: Path) -> int:
        commands.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", run)

    cli.main(
        [
            "demo",
            "testfire",
            "--authorized-remote-target",
            "--output-dir",
            str(tmp_path / "run"),
        ]
    )

    assert len(commands) == 1
    assert commands[0][commands[0].index("--target-url") + 1] == TESTFIRE_TARGET_URL
    assert commands[0][commands[0].index("--traffic-request-profile") + 1] == (
        "testfire-login-demo"
    )


def test_demo_testfire_rejects_target_override_without_running(
    tmp_path: Path,
) -> None:
    called = False

    def attack(_args: list[str]) -> None:
        nonlocal called
        called = True

    with pytest.raises(SystemExit) as captured:
        demo.handle_demo_command(
            [
                "testfire",
                "--authorized-remote-target",
                "--target-url",
                "https://example.com",
                "--output-dir",
                str(tmp_path / "run"),
            ],
            attack_runner=attack,
        )

    assert captured.value.code == ARGPARSE_ERROR_EXIT
    assert called is False


def test_testfire_request_profile_is_code_owned_and_route_locked() -> None:
    config = cli._traffic_policy_config(  # noqa: SLF001 - verify the CLI safety boundary.
        argparse.Namespace(
            traffic_policy="low-noise",
            max_physical_requests=TESTFIRE_MAX_REQUESTS,
            traffic_max_rps=TESTFIRE_MAX_RPS,
            traffic_request_profile="testfire-login-demo",
        )
    )

    assert config.allowed_request_routes == (
        "GET /bank/main.jsp",
        "GET /login.jsp",
        "HEAD /bank/main.jsp",
        "HEAD /login.jsp",
        "POST /doLogin",
    )
    assert config.allowed_query_fields == ("mode",)
    assert config.allowed_form_fields == ("btnsubmit", "passw", "uid")
    assert config.max_request_body_bytes == TESTFIRE_MAX_BODY_BYTES
    assert config.request_value_profile == "testfire-login-demo"
    assert config.require_public_addresses is True


@pytest.mark.parametrize(
    ("autonomous_route", "recovery_profile"),
    [(True, "off"), (False, "recovery-v1")],
)
def test_testfire_request_profile_rejects_expansive_agent_routes(
    autonomous_route: bool,  # noqa: FBT001 - parametrized safety-boundary input.
    recovery_profile: str,
) -> None:
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy="low-noise",
        max_physical_requests=TESTFIRE_MAX_REQUESTS,
        traffic_max_rps=TESTFIRE_MAX_RPS,
        traffic_request_profile="testfire-login-demo",
        autonomous_route=autonomous_route,
        recovery_profile=recovery_profile,
    )

    with pytest.raises(SystemExit):
        cli._resolve_traffic_policy_args(  # noqa: SLF001 - verify the CLI safety boundary.
            parser,
            parsed,
            default_mode="low-noise",
            roe_max_rps=demo.TESTFIRE_ROE_MAX_RPS,
        )


def test_demo_xben_captures_the_exact_safe_preset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _configure_root(monkeypatch, tmp_path)
    captured = _capture_runs(monkeypatch)

    demo.handle_demo_command(["xben"])

    [settings] = captured
    assert settings.benchmarks_root == root
    assert settings.ids == (DEMO_CASE_ID,)
    assert settings.all_cases is False
    assert settings.mode == "black-box"
    assert settings.comparison_profile == "none"
    assert settings.agent_mode == "ctf-free-roam"
    assert settings.recovery_profile == "off"
    assert settings.autonomous_route is False
    assert settings.model_config is None
    assert settings.model_profile == DEMO_MODEL_PROFILE
    assert settings.model_tier == "high"
    assert settings.max_turns == DEMO_MAX_TURNS
    assert settings.max_model_requests_per_case == DEMO_MAX_MODEL_REQUESTS
    assert settings.case_timeout_seconds == DEMO_TIMEOUT_SECONDS
    assert settings.max_cost_usd == DEMO_MAX_COST_USD
    assert settings.input_token_ceiling_per_model_call == DEMO_INPUT_TOKEN_CEILING
    assert settings.min_free_gib == DEMO_MIN_FREE_GIB
    assert settings.allow_paid_models is True
    assert settings.concurrency == 1
    assert settings.docker_platform == "linux/amd64"
    assert settings.tool_runtime == "host"
    assert settings.flag_mode == "exact"
    assert settings.resume is False
    assert settings.retry_failed is False
    assert settings.stream_agent_output is True
    assert settings.cockpit is False
    assert settings.keep_target is False
    assert settings.prune_case_images is True
    assert settings.operator_log_root == settings.output_dir / "operator-logs"
    assert settings.output_dir.parent == Path("runs/demo")


def test_demo_xben_uses_a_fresh_output_directory_for_every_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_root(monkeypatch, tmp_path)
    captured = _capture_runs(monkeypatch)

    demo.handle_demo_command(["xben"])
    demo.handle_demo_command(["xben"])

    assert len(captured) == TWO_RUNS
    assert captured[0].output_dir != captured[1].output_dir
    assert all(settings.resume is False for settings in captured)


def test_demo_xben_missing_benchmark_root_is_actionable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("XBEN_ROOT", raising=False)
    monkeypatch.delenv("RAVAGE_XBEN_ROOT", raising=False)
    monkeypatch.setattr(demo, "DEFAULT_BENCHMARKS_ROOT", tmp_path / "missing")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as captured:
        demo.handle_demo_command(["xben"])

    assert captured.value.code == ARGPARSE_ERROR_EXIT
    error = capsys.readouterr().err
    assert "XBEN_ROOT" in error
    assert "benchmark" in error.lower()
    assert "Traceback" not in error


def test_demo_xben_exits_nonzero_when_the_live_case_is_not_solved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_root(monkeypatch, tmp_path)
    captured = _capture_runs(monkeypatch, report=_failed_report())

    with pytest.raises(SystemExit) as failed:
        demo.handle_demo_command(["xben"])

    assert failed.value.code == 1
    assert len(captured) == 1
    assert captured[0].keep_target is False
    assert captured[0].prune_case_images is True
