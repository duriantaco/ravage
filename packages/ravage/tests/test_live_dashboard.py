from __future__ import annotations

import json
from typing import TYPE_CHECKING
from uuid import UUID

from ravage.live_dashboard import (
    DashboardSettings,
    build_dashboard_state,
    settings_from_run_dir,
)
from ravage.run_data.audit import AuditStore

if TYPE_CHECKING:
    from pathlib import Path


def test_settings_from_attack_run_uses_plain_stdout_log(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    stdout_path = tmp_path / "stdout.log"
    stdout_path.write_text("[run] started\n", encoding="utf-8")

    settings = settings_from_run_dir(tmp_path)

    assert settings.workspace_dir == workspace
    assert settings.stdout_path == stdout_path


def test_live_dashboard_state_reads_workspace_audit_stdout_and_terminal(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    terminal_dir = workspace / "terminal"
    terminal_dir.mkdir(parents=True)
    events_path = workspace / "events.jsonl"
    events_path.write_text(
        json.dumps({"timestamp": "2026-05-25T00:00:00Z", "kind": "tool_call", "payload": {}})
        + "\n"
        + json.dumps(
            {
                "timestamp": "2026-05-25T00:00:01Z",
                "kind": "run_completed",
                "payload": {"captured_flags": []},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (workspace / "transcript.jsonl").write_text(
        json.dumps({"timestamp": "2026-05-25T00:00:00Z", "role": "assistant", "content": "{}"})
        + "\n",
        encoding="utf-8",
    )
    (workspace / "working_state.json").write_text(
        json.dumps(
            {
                "status": "running",
                "phase": "reconnaissance",
                "progress": {"route_count": 2, "captured_flag_count": 0},
                "planner": {"recommended_actions": [{"action": "http_get"}]},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (terminal_dir / "nmap.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-05-25T00:00:00Z",
                "session": "nmap",
                "stream": "stdout",
                "content": "open",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    stdout_path = tmp_path / "agent.stdout"
    stdout_path.write_text("[ai:turn] 1 action=discover_attack_surface\n", encoding="utf-8")
    docker_log_path = tmp_path / "docker.log"
    docker_log_path.write_text("Building web\nContainer healthy\n", encoding="utf-8")
    db_path = tmp_path / "audit.db"
    audit = AuditStore(db_path)
    try:
        audit.record(
            engagement_id=UUID("33333333-3333-4333-8333-333333333333"),
            actor="ai_web_agent",
            action="kill_chain_stage",
            payload={
                "stage_id": "reconnaissance",
                "name": "Reconnaissance",
                "detail": "running tool recon",
            },
        )
        audit.record(
            engagement_id=UUID("33333333-3333-4333-8333-333333333333"),
            actor="ai_web_agent",
            action="model_reply_received",
            payload={"turn": 1, "route": {"provider": "custom_openai", "model": "test-model"}},
        )
        audit.record(
            engagement_id=UUID("33333333-3333-4333-8333-333333333333"),
            actor="orchestrator",
            action="tool_capability_preflight",
            payload={
                "runtime_mode": "host",
                "tool_image": "ravage-kali:latest",
                "missing_required": [],
                "missing_optional": ["template_scan"],
                "capabilities": {
                    "port_scan": {
                        "available": True,
                        "selected_provider": {
                            "action": "nmap_scan",
                            "binary": "nmap",
                            "selected_runtime": "host",
                        },
                    }
                },
            },
        )
        audit.record(
            engagement_id=UUID("33333333-3333-4333-8333-333333333333"),
            actor="ai_web_agent",
            action="flag_captured",
            payload={"flag": "flag{secret}", "source": "test"},
        )
        audit.record(
            engagement_id=UUID("33333333-3333-4333-8333-333333333333"),
            actor="dast_scan",
            action="max_actions_reached",
            payload={"max_actions": 5},
        )
        audit.record(
            engagement_id=UUID("33333333-3333-4333-8333-333333333333"),
            actor="orchestrator",
            action="run_completed",
            payload={
                "completed": False,
                "status": "max_actions_reached",
                "actions_run": 5,
                "captured_flags": [],
                "confirmed_evidence": 0,
            },
        )
        audit.record_finding_payload(
            finding_id="finding-1",
            engagement_id=UUID("33333333-3333-4333-8333-333333333333"),
            vuln_class="sql_injection",
            status="confirmed",
            validator_vote="true_positive",
            payload={
                "finding_id": "finding-1",
                "engagement_id": "33333333-3333-4333-8333-333333333333",
                "vuln_class": "sql_injection",
                "endpoint": {
                    "url": "http://127.0.0.1:8088/search",
                    "method": "GET",
                    "params": [{"name": "q", "location": "query"}],
                },
                "hypothesis": "Parameter q is injectable.",
                "exploit_steps": [
                    {
                        "http_request": "GET /search?q=%27 HTTP/1.1",
                        "response_snippet": "SQL syntax error",
                        "indicator": "sql_error_marker",
                    }
                ],
                "proof": {
                    "http_request_final": "GET /search?q=%27 HTTP/1.1",
                    "response_final": "SQL syntax error",
                    "impact_description": "Controlled SQL error proved injection.",
                },
                "status": "confirmed",
                "validator_vote": "true_positive",
            },
        )
    finally:
        audit.close()
    lab_manifest = tmp_path / "ravage-lab.yaml"
    lab_manifest.write_text(
        """
id: demo-lab
name: Demo Lab
difficulty: medium
default_url: http://127.0.0.1:8088
flags:
  - id: low
    name: low flag
vulnerabilities:
  - id: sqli
    title: SQL injection
    class: sql_injection
    summary: injectable search
attack_chain:
  - Find route
""".lstrip(),
        encoding="utf-8",
    )

    state = build_dashboard_state(
        DashboardSettings(
            workspace_dir=workspace,
            db_path=db_path,
            stdout_path=stdout_path,
            docker_log_path=docker_log_path,
            lab_manifest_path=lab_manifest,
        )
    )

    assert state["exists"]["events"] is True
    assert state["exists"]["working_state"] is True
    assert state["working_state"]["phase"] == "reconnaissance"
    assert state["exists"]["lab_manifest"] is True
    assert state["metrics"]["completed"] is True
    assert state["metrics"]["run_success"] is False
    assert state["metrics"]["run_label"] == "Stopped: action limit"
    assert state["metrics"]["model_replies"] == 1
    assert state["metrics"]["findings"] == 1
    assert state["metrics"]["terminal_sessions"] == 1
    assert state["selection"]["tool_runtime_mode"] == "host"
    assert state["selection"]["last_model_route"]["model"] == "test-model"
    assert state["selection"]["selected_tools"] == ["nmap (host)"]
    assert state["warnings"][0]["title"] == "Run stopped at action limit"
    assert state["lab"]["id"] == "demo-lab"
    assert state["flags"]["masked"] == ["flag{REDACTED}"]
    assert "values" not in state["flags"]
    assert state["stage_flow"][1]["status"] == "done"
    assert state["kill_chain_breakdown"][1]["label"] == "Recon"
    assert state["kill_chain_breakdown"][1]["actions"] == ["Stage updated"]
    assert state["kill_chain_breakdown"][5]["flags"] == 1
    assert state["agents"][0]["label"] == "AI web agent"
    assert state["activity"]
    assert state["charts"]["work"]
    assert state["findings"][0]["vuln_class"] == "sql_injection"
    assert state["stdout"] == ["[ai:turn] 1 action=discover_attack_surface"]
    assert state["docker_log"] == ["Building web", "Container healthy"]


def test_live_dashboard_reads_xben_manifest_compose_without_tags(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = tmp_path / "benchmark.yaml"
    manifest.write_text(
        """
name: XBEN-001-24 IDOR
level: 2
tags:
  - idor
content:
  - kind: description
    content: try nearby IDs
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        """
services:
  web:
    build: ./app
    ports:
      - 80
  db:
    image: mysql:8
""".lstrip(),
        encoding="utf-8",
    )

    state = build_dashboard_state(
        DashboardSettings(workspace_dir=workspace, lab_manifest_path=manifest)
    )

    assert "tags" not in state["lab"]
    assert state["lab"]["compose"]["exists"] is True
    assert [service["name"] for service in state["viewer"]["target"]["services"]] == [
        "web",
        "db",
    ]
