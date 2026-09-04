from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage import __main__ as cli
from ravage.agent_core import ai_agent
from ravage.agent_core.ai_agent import AIWebAgentSettings, resolve_source_root

if TYPE_CHECKING:
    from pathlib import Path


TARGET_URL = "http://127.0.0.1:8765"
ARGPARSE_ERROR = 2


def _write_brief(path: Path, *, context: dict[str, object] | None = None) -> None:
    path.write_text(
        json.dumps(
            {
                "engagement_id": "88888888-8888-4888-8888-888888888888",
                "scope": {"in_scope": [TARGET_URL], "out_of_scope": []},
                "roe": {
                    "max_rps": 5,
                    "no_destructive_actions": True,
                    "data_handling": "placeholders_only",
                },
                "objectives": ["capture_flag"],
                "budget": {"max_cost_usd": 1.0, "max_runtime_min": 10},
                "context": context
                or {
                    "description": "Local source-root plumbing test.",
                    "win_condition": "Exercise the configured source-root handoff.",
                },
            }
        ),
        encoding="utf-8",
    )


def test_source_root_is_opt_in_and_black_box_context_stays_none() -> None:
    assert AIWebAgentSettings().source_root is None
    assert resolve_source_root(explicit=None) is None


def test_explicit_source_root_is_resolved(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()

    resolved = resolve_source_root(explicit=source_root)

    assert resolved == source_root.resolve()


def test_source_root_rejects_missing_paths_and_files(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(ValueError, match=r"source root does not exist: .*missing"):
        resolve_source_root(explicit=missing)

    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"source root is not a directory: .*app\.py"):
        resolve_source_root(explicit=source_file)


def test_explicit_source_root_rejects_symbolic_link(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(ValueError, match="source root must not be a symbolic link"):
        resolve_source_root(explicit=linked_root)


def test_attack_cli_does_not_trust_source_access_claimed_by_brief(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    attacker_chosen_root = tmp_path / "attacker-chosen-source"
    attacker_chosen_root.mkdir()
    brief_path = tmp_path / "downloaded-brief.yaml"
    _write_brief(
        brief_path,
        context={
            "description": "Downloaded engagement brief.",
            "win_condition": "Exercise source analysis.",
            "source_root": str(attacker_chosen_root),
            "allowed_source_roots": [str(tmp_path)],
        },
    )
    calls: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(["attack", str(brief_path), "--run-dir", str(tmp_path / "run")])

    assert len(calls) == 1
    assert "--source-root" not in calls[0]


def test_attack_cli_forwards_explicit_source_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    source_root = tmp_path / "source"
    source_root.mkdir()
    _write_brief(brief_path)
    calls: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(
        [
            "attack",
            str(brief_path),
            "--run-dir",
            str(tmp_path / "run"),
            "--source-root",
            str(source_root),
            "--no-tool-recon",
        ]
    )

    command = calls[0]
    assert command[command.index("--source-root") + 1] == str(source_root.resolve())


def test_legacy_cli_does_not_trust_source_access_claimed_by_brief(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    benchmarks_root = tmp_path / "benchmarks"
    case_root = benchmarks_root / "XBEN-001-24"
    case_root.mkdir(parents=True)
    brief_path = tmp_path / "brief.yaml"
    _write_brief(
        brief_path,
        context={
            "description": "White-box XBEN case.",
            "win_condition": "Capture the proof string.",
            "source_root": str(case_root),
            "allowed_source_roots": [str(benchmarks_root)],
        },
    )
    captured: dict[str, AIWebAgentSettings] = {}

    def fake_run_ai_web_agent(
        *,
        brief_path: Path,
        target_url: str,
        settings: AIWebAgentSettings,
    ) -> None:
        assert brief_path.is_file()
        assert target_url == TARGET_URL
        captured["settings"] = settings

    monkeypatch.setattr(cli, "run_ai_web_agent", fake_run_ai_web_agent)

    cli.main(
        [
            "--brief",
            str(brief_path),
            "--target-url",
            TARGET_URL,
            "--workspace-dir",
            str(tmp_path / "workspace"),
        ]
    )

    assert captured["settings"].source_root is None


def test_attack_cli_rejects_missing_source_before_starting_child(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    child_started = False

    def unexpected_child(_argv: list[str], _stdout_path: Path) -> int:
        nonlocal child_started
        child_started = True
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", unexpected_child)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "attack",
                str(brief_path),
                "--source-root",
                str(tmp_path / "missing"),
            ]
        )

    assert exc_info.value.code == ARGPARSE_ERROR
    assert child_started is False
    assert "source root does not exist" in capsys.readouterr().err


def test_agent_rejects_missing_source_before_opening_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    workspace_opened = False

    def unexpected_workspace_open(*_args: object, **_kwargs: object) -> None:
        nonlocal workspace_opened
        workspace_opened = True

    monkeypatch.setattr(ai_agent.AgentWorkspace, "open", unexpected_workspace_open)

    with pytest.raises(ValueError, match="source root does not exist"):
        ai_agent.run_ai_web_agent(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=AIWebAgentSettings(source_root=tmp_path / "missing"),
        )

    assert workspace_opened is False
