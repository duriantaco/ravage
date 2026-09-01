from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from ravage import __main__ as cli
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


def test_demo_help_exposes_the_single_live_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as top_level:
        cli.main(["--help"])

    assert top_level.value.code == 0
    assert "ravage demo xben" in capsys.readouterr().out

    with pytest.raises(SystemExit) as captured:
        cli.main(["demo", "--help"])

    assert captured.value.code == 0
    output = capsys.readouterr().out
    assert "{xben}" in output
    assert "build, attack, score, and remove one local XBEN target" in output


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
