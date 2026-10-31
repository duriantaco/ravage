# ruff: noqa: SLF001
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tools.xben_head_to_head import cli


SECRET = "sk-paid-secret-that-must-not-be-logged"


class FakeConfig:
    def __init__(self, **values: object) -> None:
        self.values = values


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _arguments(tmp_path: Path, mode: str) -> list[str]:
    return [
        mode,
        "--project-root",
        str(tmp_path),
        "--source-repo",
        str(tmp_path / "xben"),
        "--skill-dir",
        str(tmp_path / "skill"),
        "--codex-executable",
        str(_executable(tmp_path / "codex")),
        "--strix-executable",
        str(_executable(tmp_path / "strix")),
        "--output-dir",
        str(tmp_path / "output"),
    ]


def _fake_api(
    *,
    preflight: Any = None,
    campaign: Any = None,
) -> cli._CampaignApi:
    return cli._CampaignApi(
        config_type=FakeConfig,
        run_preflight=preflight or (lambda _config: {"ready": True}),
        run_campaign=campaign or (lambda _config: {"completed": True}),
    )


def test_preflight_uses_fixed_cases_and_exact_model_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def preflight(config: FakeConfig) -> dict[str, object]:
        observed.update(config.values)
        return {"ready": True, "checked": 20}

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(cli, "_load_campaign_api", lambda: _fake_api(preflight=preflight))

    status = cli.main(_arguments(tmp_path, "preflight"))

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert status == 0
    assert captured.err == ""
    assert tuple(observed["case_ids"]) == cli.FIXED_CASE_IDS
    assert cli.FIXED_CASE_IDS == (
        "XBEN-009-24",
        "XBEN-021-24",
        "XBEN-027-24",
        "XBEN-032-24",
        "XBEN-038-24",
        "XBEN-053-24",
        "XBEN-057-24",
        "XBEN-058-24",
        "XBEN-064-24",
        "XBEN-066-24",
        "XBEN-068-24",
        "XBEN-071-24",
        "XBEN-075-24",
        "XBEN-078-24",
        "XBEN-079-24",
        "XBEN-081-24",
        "XBEN-082-24",
        "XBEN-090-24",
        "XBEN-091-24",
        "XBEN-096-24",
    )
    assert len(set(cli.FIXED_CASE_IDS)) == 20
    assert observed["model"] == "gpt-5.4-2026-03-05"
    assert observed["reasoning_effort"] == "high"
    assert observed["selection_seed"] == 20260916
    assert observed["timeout_seconds"] == 600.0
    assert observed["codex_max_http_requests"] == 64
    assert observed["strix_max_budget_usd"] == 3.0
    assert observed["strix_max_turns"] == 160
    assert observed["strix_image"] == (
        "ghcr.io/usestrix/strix-sandbox@"
        "sha256:f6906c3114e504fd1a218fcf028d7a0e46851118403a438b63956de6ea7c4331"
    )
    assert observed["api_key"] == ""
    assert payload["mode"] == "preflight"
    assert payload["result"] == {"checked": 20, "ready": True}
    expected_digest = hashlib.sha256((tmp_path / "codex").read_bytes()).hexdigest()
    assert observed["codex_executable_sha256"] == expected_digest


def test_failed_preflight_returns_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_load_campaign_api",
        lambda: _fake_api(preflight=lambda _config: {"ready": False, "issues": ["docker"]}),
    )

    assert cli.main(_arguments(tmp_path, "preflight")) == 2


def test_paid_full_run_is_guarded_before_loading_campaign_or_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def forbidden() -> cli._CampaignApi:
        raise AssertionError("campaign API must not load before paid confirmation")

    monkeypatch.setattr(cli, "_load_campaign_api", forbidden)

    status = cli.main(_arguments(tmp_path, "full"))

    captured = capsys.readouterr()
    assert status == 2
    assert captured.out == ""
    assert json.loads(captured.err)["error"] == "paid_execution_confirmation_required"


def test_full_run_passes_exact_twenty_and_redacts_secret_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def campaign(config: FakeConfig) -> dict[str, object]:
        observed.update(config.values)
        return {
            "completed": True,
            "nested": [f"provider accidentally echoed {SECRET}"],
        }

    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    monkeypatch.setattr(cli, "_load_campaign_api", lambda: _fake_api(campaign=campaign))
    arguments = [*_arguments(tmp_path, "full"), "--execute-paid"]

    status = cli.main(arguments)

    captured = capsys.readouterr()
    assert status == 0
    assert SECRET not in captured.out
    assert SECRET not in captured.err
    assert "[REDACTED]" in captured.out
    assert observed["api_key"] == SECRET
    assert tuple(observed["case_ids"]) == cli.FIXED_CASE_IDS
    assert json.loads(captured.out)["case_ids"] == list(cli.FIXED_CASE_IDS)


def test_canary_is_one_fixed_case_and_requires_paid_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    observed: dict[str, object] = {}

    def campaign(config: FakeConfig) -> dict[str, object]:
        observed.update(config.values)
        return {"completed": True}

    monkeypatch.setattr(cli, "_load_campaign_api", lambda: _fake_api(campaign=campaign))
    base = _arguments(tmp_path, "canary")
    assert cli.main(base) == 2
    capsys.readouterr()

    selected = cli.FIXED_CASE_IDS[7]
    status = cli.main([*base, "--case", selected, "--execute-paid"])

    captured = capsys.readouterr()
    assert status == 0
    assert tuple(observed["case_ids"]) == (selected,)
    assert json.loads(captured.out)["case_ids"] == [selected]


def test_campaign_error_never_logs_the_api_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def campaign(_config: FakeConfig) -> dict[str, object]:
        raise RuntimeError(f"provider rejected credential {SECRET}")

    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    monkeypatch.setattr(cli, "_load_campaign_api", lambda: _fake_api(campaign=campaign))

    status = cli.main([*_arguments(tmp_path, "full"), "--execute-paid"])

    captured = capsys.readouterr()
    assert status == 2
    assert captured.out == ""
    assert SECRET not in captured.err
    assert "[REDACTED]" in captured.err
