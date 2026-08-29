from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from ai_agent_fixtures import BRIEF_YAML
from ravage import __main__ as cli
from ravage.run_data.audit import AuditStore

if TYPE_CHECKING:
    from pathlib import Path


def test_autonomous_route_writes_one_final_report_after_route_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML
        + "context:\n"
        + '  description: "Authorized local route report test."\n',
        encoding="utf-8",
    )
    workspace_dir = tmp_path / "run" / "workspace"
    audit_path = tmp_path / "run" / "audit.db"
    report_path = tmp_path / "run" / "report.json"
    phases: list[str] = []

    def fake_route(**kwargs: object) -> object:
        phases.append("route")
        settings = kwargs["settings"]
        assert isinstance(settings, cli.AIWebAgentSettings)
        assert settings.report_agent is False
        assert settings.report_path is None
        assert not report_path.exists()

        route_workspace = workspace_dir / "autonomous-route"
        route_workspace.mkdir(parents=True)
        (route_workspace / "events.jsonl").write_text(
            json.dumps({"kind": "frontier_route_finished", "payload": {"status": "solved"}})
            + "\n",
            encoding="utf-8",
        )
        audit = AuditStore(audit_path)
        try:
            audit.record_finding_payload(
                finding_id="route-finding-1",
                engagement_id=UUID("77777777-7777-4777-8777-777777777777"),
                vuln_class="sql_injection",
                status="confirmed",
                validator_vote="confirm",
                payload={
                    "finding_id": "route-finding-1",
                    "vuln_class": "sql_injection",
                    "status": "confirmed",
                    "severity": "high",
                    "endpoint": {
                        "url": "http://127.0.0.1:8765/search",
                        "method": "GET",
                        "params": [{"name": "q", "location": "query"}],
                    },
                    "hypothesis": "The route confirmed SQL injection.",
                    "exploit_steps": [{"indicator": "paired route replay"}],
                    "proof": {
                        "http_request_final": "GET /search?q=%27 HTTP/1.1",
                        "response_final": "SQLite syntax error",
                        "impact_description": "Query structure was altered.",
                    },
                },
            )
        finally:
            audit.close()
        return SimpleNamespace(route=SimpleNamespace(status="solved"))

    monkeypatch.setattr(cli, "run_selected_autonomous_route", fake_route)
    monkeypatch.setattr(
        "ravage.report._run_hosting_layer_report_agent",
        lambda **_kwargs: None,
    )

    original_writer = cli.write_pentest_report

    def recording_writer(**kwargs: object) -> dict[str, object]:
        phases.append("report")
        return original_writer(**kwargs)

    monkeypatch.setattr(cli, "write_pentest_report", recording_writer)

    cli.main(
        [
            "--brief",
            str(brief_path),
            "--target-url",
            "http://127.0.0.1:8765",
            "--db-path",
            str(audit_path),
            "--workspace-dir",
            str(workspace_dir),
            "--autonomous-route",
            "--report",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert phases == ["route", "report"]
    assert report["status"] == "completed"
    assert report["executive_summary"]["finding_count"] == 1
    assert report["findings"][0]["finding_id"] == "route-finding-1"


def test_non_route_report_generation_remains_owned_by_the_base_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML
        + "context:\n"
        + '  description: "Authorized local report behavior test."\n',
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli, "run_ai_web_agent", lambda **kwargs: captured.update(kwargs))

    cli.main(
        [
            "--brief",
            str(brief_path),
            "--target-url",
            "http://127.0.0.1:8765",
            "--report",
            "--report-path",
            str(report_path),
        ]
    )

    settings = captured["settings"]
    assert isinstance(settings, cli.AIWebAgentSettings)
    assert settings.report_agent is True
    assert settings.report_path == report_path


def test_authenticated_autonomous_error_is_redacted_before_final_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Authentication:
        identity = "alice"

        @staticmethod
        def contains_secret(value: str) -> bool:
            return "FLAG{alice}" in value

        @staticmethod
        def redact_text(value: str) -> str:
            return value.replace("FLAG{alice}", "[REDACTED]")

    captured: dict[str, object] = {}

    def fail_route(**_kwargs: object) -> object:
        raise RuntimeError("graph exposed FLAG{alice}")

    monkeypatch.setattr(cli, "run_selected_autonomous_route", fail_route)
    monkeypatch.setattr(
        cli,
        "write_pentest_report",
        lambda **kwargs: captured.update(kwargs),
    )
    settings = cli.AIWebAgentSettings(
        db_path=tmp_path / "audit.db",
        workspace_dir=tmp_path / "workspace",
        report_path=tmp_path / "report.json",
        authentication=Authentication(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="graph exposed"):
        cli._run_autonomous_route_with_final_report(  # noqa: SLF001
            brief_path=tmp_path / "brief.yaml",
            target_url="http://127.0.0.1:8765",
            settings=settings,
            engine="agent-graph",
            max_model_requests=1,
            operational_profile=cli.GraphOperationalProfileName.STANDARD,
        )

    assert captured["error"] == "RuntimeError: [REDACTED]"
