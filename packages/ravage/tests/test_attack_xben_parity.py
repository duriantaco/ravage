from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from io import StringIO
from typing import TYPE_CHECKING, cast
from uuid import uuid4

import pytest
from ai_agent_fixtures import BRIEF_YAML
from ravage import __main__ as cli
from ravage.agent_core.action_executor import execute_action
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import AIWebAgentSettings
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import FakeToolRuntime, ToolResult
from ravage.xben_parts.agent import _run_agent_subprocess, _styled_live_output_line
from ravage.xben_parts.logs import (
    _case_solution_route,
    _count_case_model_routes,
    _find_flag,
)
from ravage.xben_parts.models import XbenSettings

if TYPE_CHECKING:
    from pathlib import Path


TARGET_URL = "http://127.0.0.1:8765"
BASE_TURN_BUDGET = 40
ROUTE_REQUEST_BUDGET = 12
DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 1_800


class _TTYStringIO(StringIO):
    def isatty(self) -> bool:
        return True


def _capture_flag_brief(tmp_path: Path) -> Path:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace('  - "sql_injection"', '  - "capture_flag"')
        + "context:\n"
        + '  description: "Local parity test target exposing a proof string."\n',
        encoding="utf-8",
    )
    return brief_path


def _score_exact_flag(
    *, flag: str, db_path: Path, workspace_path: Path, stdout_path: Path
) -> str | None:
    workspace_path.mkdir(parents=True, exist_ok=True)
    stdout_path.touch()
    return _find_flag(
        flag=flag,
        db_path=db_path,
        workspace_path=workspace_path,
        stdout_path=stdout_path,
        flag_mode="exact",
    )


def _write_captured_flag_event(db_path: Path, payload: dict[str, object]) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT, payload_json TEXT)")
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?)",
            ("flag_captured", json.dumps(payload)),
        )


def test_xben_accounting_separates_base_and_autonomous_route_requests(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT, payload_json TEXT)")
        conn.executemany(
            "INSERT INTO audit_log VALUES (?, ?)",
            [
                (
                    "model_request_started",
                    json.dumps({"model_request_id": "base-1"}),
                ),
                ("frontier_route_started", "{}"),
                (
                    "model_request_started",
                    json.dumps(
                        {
                            "model_request_id": "route-1",
                            "execution_route": "autonomous_escalation",
                        }
                    ),
                ),
                ("flag_captured", json.dumps({"flag": "flag{route-proof}"})),
            ],
        )

    assert _count_case_model_routes(db_path) == (1, 1)
    assert _case_solution_route(db_path, solved=True) == "autonomous_route"


def test_xben_accounting_recognizes_agent_graph_route(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT, payload_json TEXT)")
        conn.executemany(
            "INSERT INTO audit_log VALUES (?, ?)",
            [
                ("model_request_started", json.dumps({"model_request_id": "base-1"})),
                ("autonomous_graph_started", "{}"),
                (
                    "model_request_started",
                    json.dumps(
                        {
                            "model_request_id": "graph-1",
                            "execution_route": "autonomous_agent_graph",
                        }
                    ),
                ),
                ("flag_captured", json.dumps({"flag": "flag{graph-proof}"})),
            ],
        )

    assert _count_case_model_routes(db_path) == (1, 1)
    assert _case_solution_route(db_path, solved=True) == "autonomous_route"


def test_xben_child_invokes_the_public_attack_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["timeout"] = kwargs["timeout"]
        stdout = cast("StringIO", kwargs["stdout"])
        stdout.write("ok\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("ravage.xben_parts.agent.subprocess.run", fake_run)
    brief_path = tmp_path / "brief.yaml"

    _run_agent_subprocess(
        settings=XbenSettings(
            output_dir=tmp_path / "runs",
            model_profile="parity-profile",
            model_tier="high",
            max_turns=7,
            allow_degraded=True,
        ),
        brief_path=brief_path,
        target_url=TARGET_URL,
        db_path=tmp_path / "audit.db",
        workspace_path=tmp_path / "workspace",
        stdout=StringIO(),
    )

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:5] == [sys.executable, "-m", "ravage", "attack", str(brief_path)]
    assert cmd[cmd.index("--target-url") + 1] == TARGET_URL
    assert cmd[cmd.index("--model-profile") + 1] == "parity-profile"
    assert cmd[cmd.index("--model-tier") + 1] == "high"
    assert cmd[cmd.index("--max-turns") + 1] == "7"
    assert "--allow-degraded" in cmd
    assert "--source-root" not in cmd
    assert "--benchmark-proof-recognition" not in cmd
    assert captured["timeout"] == DEFAULT_SUBPROCESS_TIMEOUT_SECONDS


def test_xben_child_forwards_trusted_source_root_as_cli_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("ravage.xben_parts.agent.subprocess.run", fake_run)
    source_root = tmp_path / "benchmarks" / "XBEN-001-24"
    source_root.mkdir(parents=True)

    _run_agent_subprocess(
        settings=XbenSettings(mode="white-box"),
        brief_path=tmp_path / "brief.yaml",
        target_url=TARGET_URL,
        db_path=tmp_path / "audit.db",
        workspace_path=tmp_path / "workspace",
        stdout=StringIO(),
        source_root=source_root,
    )

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[cmd.index("--source-root") + 1] == str(source_root)


def test_xben_child_live_output_is_streamed_and_captured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = StringIO("[run] Mapping the target\n[ok] Flag found\n")

        def wait(self, timeout: int | None = None) -> int:
            captured["timeout"] = timeout
            return 0

        def poll(self) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("successful child must not be killed")

    def fake_popen(cmd: list[str], **kwargs: object) -> FakeProcess:
        captured["cmd"] = cmd
        captured["popen"] = kwargs
        return FakeProcess()

    monkeypatch.setattr("ravage.xben_parts.agent.subprocess.Popen", fake_popen)
    artifact = StringIO()
    terminal = StringIO()

    _run_agent_subprocess(
        settings=XbenSettings(
            output_dir=tmp_path / "runs",
            stream_agent_output=True,
        ),
        brief_path=tmp_path / "brief.yaml",
        target_url=TARGET_URL,
        db_path=tmp_path / "audit.db",
        workspace_path=tmp_path / "workspace",
        stdout=artifact,
        live_stdout=terminal,
    )

    expected = "[run] Mapping the target\n[ok] Flag found\n"
    assert artifact.getvalue() == expected
    assert terminal.getvalue() == expected
    assert captured["timeout"] == DEFAULT_SUBPROCESS_TIMEOUT_SECONDS
    popen = cast("dict[str, object]", captured["popen"])
    assert popen["stdout"] == subprocess.PIPE
    assert popen["stderr"] == subprocess.STDOUT
    cmd = cast("list[str]", captured["cmd"])
    assert "--show-agent-actions" in cmd


@pytest.mark.parametrize(
    ("line", "color"),
    [
        ("[agent] Now I'm testing the reflected input.\n", "\x1b[33;1m"),
        ("[ok] Flag found · value masked\n", "\x1b[32;1m"),
        ("[fail] Model request failed\n", "\x1b[31;1m"),
        ("[warn] Response · 500\n", "\x1b[31;1m"),
    ],
)
def test_xben_live_agent_output_uses_semantic_colors(
    line: str,
    color: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("RAVAGE_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")

    rendered = _styled_live_output_line(line, stream=_TTYStringIO())

    assert rendered.startswith(color)
    assert rendered.endswith("\x1b[0m\n")
    assert line.strip() in rendered


def test_xben_child_live_output_kills_the_agent_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimedOutProcess:
        def __init__(self) -> None:
            self.stdout = StringIO()
            self.killed = False

        def wait(self, timeout: int | None = None) -> int:
            if not self.killed:
                raise subprocess.TimeoutExpired(cmd="ravage", timeout=timeout)
            return -9

        def poll(self) -> int | None:
            return None if not self.killed else -9

        def kill(self) -> None:
            self.killed = True

    process = TimedOutProcess()
    monkeypatch.setattr(
        "ravage.xben_parts.agent.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )

    with pytest.raises(subprocess.TimeoutExpired):
        _run_agent_subprocess(
            settings=XbenSettings(output_dir=tmp_path / "runs"),
            brief_path=tmp_path / "brief.yaml",
            target_url=TARGET_URL,
            db_path=tmp_path / "audit.db",
            workspace_path=tmp_path / "workspace",
            stdout=StringIO(),
            live_stdout=StringIO(),
        )

    assert process.killed is True


def test_xben_cli_enables_live_output_and_cockpit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, XbenSettings] = {}

    def capture_settings(settings: XbenSettings) -> dict[str, object]:
        captured["settings"] = settings
        return {}

    monkeypatch.setattr(cli, "run_xben", capture_settings)

    cli.main(["xben", "--stream-agent-output", "--cockpit"])

    settings = captured["settings"]
    assert settings.stream_agent_output is True
    assert settings.cockpit is True
    assert settings.keep_target is True


def test_xben_child_forwards_the_opt_in_autonomous_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("ravage.xben_parts.agent.subprocess.run", fake_run)

    _run_agent_subprocess(
        settings=XbenSettings(
            output_dir=tmp_path / "runs",
            autonomous_route=True,
            autonomous_route_engine="agent-graph",
            autonomous_route_max_requests=ROUTE_REQUEST_BUDGET,
        ),
        brief_path=tmp_path / "brief.yaml",
        target_url=TARGET_URL,
        db_path=tmp_path / "audit.db",
        workspace_path=tmp_path / "workspace",
        stdout=StringIO(),
    )

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert "--autonomous-route" in cmd
    assert cmd[cmd.index("--autonomous-route-engine") + 1] == "agent-graph"
    assert cmd[cmd.index("--autonomous-route-max-requests") + 1] == str(ROUTE_REQUEST_BUDGET)
    assert captured["timeout"] == 2_100


def test_public_attack_derives_proof_recognition_from_capture_objective(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = _capture_flag_brief(tmp_path)
    captured: dict[str, object] = {}

    def fake_run_ai_web_agent(
        *,
        brief_path: Path,
        target_url: str,
        settings: AIWebAgentSettings,
    ) -> Path:
        captured["brief_path"] = brief_path
        captured["target_url"] = target_url
        captured["settings"] = settings
        return settings.db_path or tmp_path / "audit.db"

    monkeypatch.setattr(cli, "run_ai_web_agent", fake_run_ai_web_agent)
    argv = ["attack", str(brief_path), "--run-dir", str(tmp_path / "run")]

    assert "--benchmark-proof-recognition" not in argv
    cli.main(argv)

    settings = captured["settings"]
    assert isinstance(settings, AIWebAgentSettings)
    assert captured["brief_path"] == brief_path
    assert captured["target_url"] == TARGET_URL
    assert settings.proof_recognition_enabled is True


def test_public_attack_wires_the_opt_in_autonomous_route_without_changing_base_turns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = _capture_flag_brief(tmp_path)
    captured: dict[str, object] = {}

    def fake_autonomous_route(**kwargs: object) -> None:
        captured.update(kwargs)

    def fail_base_runner(**_kwargs: object) -> None:
        message = "direct base runner must not be selected"
        raise AssertionError(message)

    monkeypatch.setattr(cli, "run_selected_autonomous_route", fake_autonomous_route)
    monkeypatch.setattr(cli, "run_ai_web_agent", fail_base_runner)

    cli.main(
        [
            "attack",
            str(brief_path),
            "--run-dir",
            str(tmp_path / "run"),
            "--max-turns",
            str(BASE_TURN_BUDGET),
            "--autonomous-route",
            "--autonomous-route-max-requests",
            str(ROUTE_REQUEST_BUDGET),
        ]
    )

    settings = captured["settings"]
    assert isinstance(settings, AIWebAgentSettings)
    assert captured["engine"] == "frontier"
    assert captured["max_model_requests"] == ROUTE_REQUEST_BUDGET
    assert settings.max_turns == BASE_TURN_BUDGET
    assert settings.recovery_profile == "off"


def test_public_attack_selects_agent_graph_without_changing_base_turns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = _capture_flag_brief(tmp_path)
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        cli,
        "run_selected_autonomous_route",
        lambda **kwargs: captured.update(kwargs),
    )
    monkeypatch.setattr(
        cli,
        "run_ai_web_agent",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError(kwargs)),
    )

    cli.main(
        [
            "attack",
            str(brief_path),
            "--run-dir",
            str(tmp_path / "run"),
            "--max-turns",
            str(BASE_TURN_BUDGET),
            "--autonomous-route",
            "--autonomous-route-engine",
            "agent-graph",
            "--autonomous-route-max-requests",
            str(ROUTE_REQUEST_BUDGET),
        ]
    )

    settings = captured["settings"]
    assert isinstance(settings, AIWebAgentSettings)
    assert captured["engine"] == "agent-graph"
    assert captured["max_model_requests"] == ROUTE_REQUEST_BUDGET
    assert settings.max_turns == BASE_TURN_BUDGET


def test_normal_attack_capture_is_accepted_by_exact_xben_scoring(tmp_path: Path) -> None:
    flag = "flag{ordinary_attack_tool_evidence}"
    db_path = tmp_path / "audit.db"
    workspace_path = tmp_path / "workspace"
    state = AgentState()
    workspace = AgentWorkspace.open(workspace_path)
    audit = AuditStore(db_path)
    tools = FakeToolRuntime(
        {
            "run_command": ToolResult(
                ok=True,
                tool="run_command",
                command=("sh", "-lc", "printf proof"),
                exit_code=0,
                stdout=flag,
                stderr="",
            )
        }
    )
    engagement_id = uuid4()
    try:
        observed = execute_action(
            {"action": "run_command", "command": "printf proof"},
            target_url=TARGET_URL,
            runtime=tools,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
        )
        captured = execute_action(
            {
                "action": "capture_flag",
                "flag": flag,
                "evidence": "tool_run_command observation",
            },
            target_url=TARGET_URL,
            runtime=tools,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
        )
    finally:
        audit.close()

    assert observed.stop is False
    assert captured.ok is True
    assert (
        _score_exact_flag(
            flag=flag,
            db_path=db_path,
            workspace_path=workspace_path,
            stdout_path=tmp_path / "agent.stdout",
        )
        == flag
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"flag": "flag{forged_event}", "evidence": "model said so"},
        {"flag": "flag{forged_event}", "evidence": "flag{forged_event}"},
        {
            "flag": "flag{forged_event}",
            "evidence": "tool_run_command observation",
            "recognizer": "executor_tool_observation",
            "capture_method": "agent_submission",
            "source_observation_id": "forged-observation",
            "source_kind": "tool_run_command",
        },
    ],
)
def test_exact_xben_scoring_rejects_forged_or_model_only_capture_events(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    db_path = tmp_path / "audit.db"
    _write_captured_flag_event(db_path, payload)

    assert (
        _score_exact_flag(
            flag="flag{forged_event}",
            db_path=db_path,
            workspace_path=tmp_path / "workspace",
            stdout_path=tmp_path / "agent.stdout",
        )
        is None
    )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "flag": "flag{legacy_recognizer}",
            "evidence": "tool_run_probe",
            "recognizer": "benchmark_terminal_fallback",
        },
        {
            "flag": "flag{legacy_recognizer}",
            "evidence": "scan result",
            "recognizer": "scan_probe_output",
        },
    ],
)
def test_exact_xben_scoring_keeps_legacy_recognizers(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    db_path = tmp_path / "audit.db"
    _write_captured_flag_event(db_path, payload)

    assert (
        _score_exact_flag(
            flag="flag{legacy_recognizer}",
            db_path=db_path,
            workspace_path=tmp_path / "workspace",
            stdout_path=tmp_path / "agent.stdout",
        )
        == "flag{legacy_recognizer}"
    )
