from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
import yaml
from ravage import __main__ as cli
from ravage.agent_core.agent_methodology import methodology_context
from ravage.agent_core.agent_state import (
    AgentState,
    resolve_agent_state_path,
    save_agent_state,
)
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _focus_authenticated_prompt,
    _initial_state,
)
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path

_RESTORED_TURN = 7
_ARGPARSE_ERROR = 2


@dataclass(frozen=True)
class _Authentication:
    identity: str = "service"

    @staticmethod
    def redact(value: object) -> object:
        return value

    @staticmethod
    def redact_text(value: str) -> str:
        return value


def test_authenticated_prompt_prunes_only_unavailable_leaves_and_rewrites_methodology() -> None:
    user: dict[str, object] = {
        "action_schema": {
            "run_probe": {},
            "run_command": {},
            "run_python": {},
            "validate_poc": {},
            "final": {},
        },
        "tool_guidance": ["Use curl after run_probe surface_map."],
        "methodology": methodology_context(AgentState()),
        "active_tasks": [
            {
                "id": "input-reflection",
                "title": "Test reflected input",
                "next_steps": [
                    "run_probe input_reflection",
                    "run_probe dom_execution",
                ],
            },
            {"id": "captcha_form_state", "title": "Unavailable process probe"},
        ],
        "execution_recipes": [
            {
                "task_id": "input-reflection",
                "good_first_actions": [
                    "run_probe input_reflection",
                    "run_probe dom_execution",
                    "Use curl with a cookie jar.",
                ],
            }
        ],
        "active_strategy_cards": [
            {
                "name": "mixed-reflection",
                "next_actions": [
                    "run_probe input_reflection",
                    "run_probe dom_execution",
                ],
            }
        ],
        "planner_directives": [
            (
                "Use run_probe reflection_value_boundary, then run_probe dom_execution "
                "if browser confirmation is still needed."
            )
        ],
        "available_probes": [
            {"name": "input_reflection"},
            {"name": "dom_execution"},
        ],
        "available_specialists": [
            {"probe": "input_reflection"},
            {"probe": "dom_execution"},
        ],
        "recommended_specialists": [{"probe": "input_reflection"}],
        "locked_primitive": None,
    }

    _focus_authenticated_prompt(user, authentication=_Authentication())  # type: ignore[arg-type]

    action_schema = user["action_schema"]
    assert isinstance(action_schema, dict)
    assert list(action_schema) == ["run_probe", "validate_poc", "final"]
    methodology = json.dumps(user["methodology"]).casefold()
    assert "run_probe" in methodology
    assert "validate_poc" in methodology
    for unavailable in ("curl", "python", "scanner", "scoped command or script"):
        assert unavailable not in methodology

    tasks = user["active_tasks"]
    assert isinstance(tasks, list)
    assert [task["id"] for task in tasks] == ["input-reflection"]
    assert tasks[0]["next_steps"] == ["run_probe input_reflection"]

    recipes = user["execution_recipes"]
    assert isinstance(recipes, list)
    assert recipes[0]["good_first_actions"] == ["run_probe input_reflection"]

    cards = user["active_strategy_cards"]
    assert isinstance(cards, list)
    assert cards[0]["next_actions"] == ["run_probe input_reflection"]
    directives = user["planner_directives"]
    assert isinstance(directives, list)
    assert directives == [
        "Continue this evidence path with an available managed specialist: "
        "run_probe reflection_value_boundary."
    ]
    assert user["managed_http_identity"] == {
        "mode": "identity:service",
        "identity_alias": "service",
        "request_lane": "managed_http",
        "managed_http_actions": ["run_probe", "validate_poc"],
        "control_actions": ["final"],
    }


@pytest.mark.parametrize("resume_kind", ["state", "workspace", "run", "report"])
def test_resume_forms_resolve_to_canonical_working_state(
    tmp_path: Path,
    resume_kind: str,
) -> None:
    run_dir = tmp_path / "run"
    workspace_dir = run_dir / "workspace"
    workspace = AgentWorkspace.open(workspace_dir)
    state = AgentState(turn=_RESTORED_TURN, surface={"authenticated_identity": "service"})
    save_agent_state(workspace.state_path, target_url="http://127.0.0.1:18762/", state=state)
    report_path = run_dir / "custom-assessment.md"
    report_path.write_text("{}\n", encoding="utf-8")
    resume_from = {
        "state": workspace.state_path,
        "workspace": workspace_dir,
        "run": run_dir,
        "report": report_path,
    }[resume_kind]

    resolved = resolve_agent_state_path(
        resume_from,
        workspace_state_path=workspace.state_path,
    )
    restored, resumed = _initial_state(
        AIWebAgentSettings(resume_from=resume_from),
        workspace,
    )

    assert resolved == workspace.state_path
    assert resumed is True
    assert restored.turn == _RESTORED_TURN
    assert restored.surface["authenticated_identity"] == "service"


def test_resume_run_directory_identity_mismatch_is_checked_on_canonical_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    workspace_dir = run_dir / "workspace"
    workspace_dir.mkdir(parents=True)
    save_agent_state(
        workspace_dir / "working_state.json",
        target_url="http://127.0.0.1:18762/",
        state=AgentState(surface={"authenticated_identity": "operator"}),
    )

    with pytest.raises(SystemExit) as exc_info:
        cli._validate_attack_resume_identity_before_authentication(  # noqa: SLF001
            argparse.ArgumentParser(prog="ravage"),
            resume_from=run_dir,
            workspace_dir=None,
            requested_identity="service",
        )

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert "different identity" in capsys.readouterr().err


def test_missing_canonical_resume_state_fails_closed(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    workspace = AgentWorkspace.open(run_dir / "new-workspace")

    with pytest.raises(ValueError, match="canonical agent state does not exist"):
        _initial_state(AIWebAgentSettings(resume_from=run_dir), workspace)


@pytest.mark.parametrize("directory_form", ["workspace", "run"])
def test_public_attack_resume_directory_reuses_canonical_workspace_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    directory_form: str,
) -> None:
    brief = tmp_path / "brief.yaml"
    brief.write_text(
        yaml.safe_dump(
            {
                "engagement_id": "44444444-4444-4444-8444-444444444444",
                "scope": {
                    "in_scope": ["http://127.0.0.1:18762/"],
                    "out_of_scope": [],
                },
                "roe": {"max_rps": 5},
                "objectives": ["web_application_assessment"],
                "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
                "context": {"description": "Resume the authorized local attack."},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    run_dir = tmp_path / "previous-run"
    workspace_dir = run_dir / "workspace"
    workspace_dir.mkdir(parents=True)
    save_agent_state(
        workspace_dir / "working_state.json",
        target_url="http://127.0.0.1:18762/",
        state=AgentState(turn=1),
    )
    resume_from = workspace_dir if directory_form == "workspace" else run_dir
    commands: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        commands.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(
        [
            "attack",
            str(brief),
            "--resume-from",
            str(resume_from),
            "--model-profile",
            "local-ollama",
            "--no-tool-recon",
        ]
    )

    assert len(commands) == 1
    command = commands[0]
    assert command[command.index("--db-path") + 1] == str(run_dir / "audit.db")
    assert command[command.index("--workspace-dir") + 1] == str(workspace_dir)
    assert command[command.index("--resume-from") + 1] == str(resume_from)


def test_attack_help_distinguishes_managed_http_from_process_runtime(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["attack", "--help"])

    output = capsys.readouterr().out
    normalized = " ".join(output.split())
    assert exc_info.value.code == 0
    assert "Unauthenticated process-capable remote runs" in normalized
    assert "selected managed identity uses HTTP-only" in normalized
    assert "blocks command, Python, and process lanes" in normalized
    assert "authenticated attacks use the managed HTTP-only lane" in normalized
