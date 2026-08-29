from __future__ import annotations

import json
import sqlite3
from io import StringIO
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from ai_agent_fixtures import BRIEF_YAML, VulnerableOpenApiHttpClient
from ravage.dast_scan import DastScanSettings, run_dast_scan
from ravage.runtime import FakeToolRuntime, TerminalResult, ToolResult
from ravage.tool_capabilities import MissingToolCapabilitiesError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path


class _SqlDocumentationClient:
    def get(self, _url: str) -> object:
        return SimpleNamespace(body="SQL documentation and query examples")


def test_dast_scan_confirms_sqli_and_writes_report(tmp_path: Path) -> None:
    brief_path = _write_brief(tmp_path)
    db_path = tmp_path / "audit.db"
    report_path = tmp_path / "report.json"
    stdout = StringIO()

    written_report = run_dast_scan(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=DastScanSettings(
            db_path=db_path,
            report_path=report_path,
            workspace_dir=tmp_path / "workspace",
            stdout=stdout,
            http_client=VulnerableOpenApiHttpClient(),
            tool_runtime=FakeToolRuntime({}),
            max_actions=4,
        ),
    )

    assert written_report == report_path
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert isinstance(report, dict)
    run = report["run"]
    assert isinstance(run, dict)
    summary = report["summary"]
    assert isinstance(summary, dict)
    assert report["status"] == "completed"
    assert run["mode"] == "deterministic-dast"
    assert run["scan_profile"] == "web-basic"
    confirmed_vuln_classes = summary["confirmed_vuln_classes"]
    assert isinstance(confirmed_vuln_classes, list)
    assert "sql_injection" in confirmed_vuln_classes
    assert summary["finding_count"] == 1
    assert summary["scan_actions_run"] >= 1
    finding = report["findings"][0]
    assert finding["engagement_id"]
    assert "[doing] turn=1 source=deterministic_scan" in stdout.getvalue()
    assert "[cost] model_requests=0 estimate=0" in stdout.getvalue()
    assert "[next] review report=" in stdout.getvalue()

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT vuln_class, payload_json FROM findings").fetchall()
        actions = [row[0] for row in conn.execute("SELECT action FROM audit_log")]
    finally:
        conn.close()
    assert [row[0] for row in rows] == ["sql_injection"]
    assert actions.count("finding_confirmed") == 1

    events = _read_events(tmp_path / "workspace" / "events.jsonl")
    assert [event["kind"] for event in events if "finding" in event["kind"]] == [
        "finding_confirmed"
    ]


def test_dast_scan_refuses_remote_targets_by_default(tmp_path: Path) -> None:
    remote_url = "https://staging.example.test"
    brief_path = _write_brief(
        tmp_path,
        BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url),
    )

    with pytest.raises(ValueError, match="only runs against localhost"):
        run_dast_scan(
            brief_path=brief_path,
            target_url=remote_url,
            settings=DastScanSettings(
                stdout=StringIO(),
                http_client=VulnerableOpenApiHttpClient(),
                tool_runtime=FakeToolRuntime({}),
            ),
        )


def test_dast_scan_does_not_confirm_generic_sql_text_without_a_differential(
    tmp_path: Path,
) -> None:
    brief_path = _write_brief(tmp_path)
    report_path = tmp_path / "report.json"

    run_dast_scan(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=DastScanSettings(
            db_path=tmp_path / "audit.db",
            report_path=report_path,
            workspace_dir=tmp_path / "workspace",
            stdout=StringIO(),
            http_client=_SqlDocumentationClient(),
            tool_runtime=FakeToolRuntime({}),
            max_actions=4,
        ),
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["finding_count"] == 0
    assert not any(
        event["kind"] == "finding_confirmed"
        for event in _read_events(tmp_path / "workspace" / "events.jsonl")
    )


def test_dast_scan_blocks_missing_required_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("ravage.tool_capabilities.shutil.which", lambda _binary: None)
    brief_path = _write_brief(
        tmp_path,
        BRIEF_YAML.replace(
            "budget:",
            "context:\n  required_capabilities:\n    - port_scan\nbudget:",
        ),
    )
    report_path = tmp_path / "report.json"

    with pytest.raises(MissingToolCapabilitiesError, match="port_scan"):
        run_dast_scan(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            settings=DastScanSettings(
                db_path=tmp_path / "audit.db",
                report_path=report_path,
                workspace_dir=tmp_path / "workspace",
                stdout=StringIO(),
                http_client=VulnerableOpenApiHttpClient(),
                tool_runtime=FakeToolRuntime({}),
                tool_runtime_mode="host",
            ),
        )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert isinstance(report, dict)
    tool_capabilities = report["tool_capabilities"]
    assert isinstance(tool_capabilities, dict)
    assert report["status"] == "errored"
    assert tool_capabilities["missing_required"] == ["port_scan"]
    assert (tmp_path / "workspace" / "capabilities.json").exists()


def test_dast_scan_allow_degraded_continues_with_missing_required_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("ravage.tool_capabilities.shutil.which", lambda _binary: None)
    brief_path = _write_brief(
        tmp_path,
        BRIEF_YAML.replace(
            "budget:",
            "context:\n  required_capabilities:\n    - port_scan\nbudget:",
        ),
    )
    report_path = tmp_path / "report.json"

    run_dast_scan(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=DastScanSettings(
            db_path=tmp_path / "audit.db",
            report_path=report_path,
            workspace_dir=tmp_path / "workspace",
            stdout=StringIO(),
            http_client=VulnerableOpenApiHttpClient(),
            tool_runtime=FakeToolRuntime({}),
            tool_runtime_mode="host",
            allow_degraded=True,
            max_actions=1,
        ),
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert isinstance(report, dict)
    tool_capabilities = report["tool_capabilities"]
    assert isinstance(tool_capabilities, dict)
    assert report["status"] == "max_actions_reached"
    assert tool_capabilities["missing_required"] == ["port_scan"]


def test_dast_scan_runs_optional_local_tool_recon(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "ravage.tool_capabilities.shutil.which",
        lambda binary: f"/usr/bin/{binary}",
    )
    brief_path = _write_brief(tmp_path)
    fake_tools = FakeToolRuntime(_tool_results(("nmap", "whatweb", "katana", "ffuf")))

    run_dast_scan(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=DastScanSettings(
            db_path=tmp_path / "audit.db",
            report_path=tmp_path / "report.json",
            workspace_dir=tmp_path / "workspace",
            stdout=StringIO(),
            http_client=VulnerableOpenApiHttpClient(),
            tool_runtime=fake_tools,
            tool_recon=True,
            max_actions=0,
        ),
    )

    assert [call[0] for call in fake_tools.calls] == [
        "nmap_scan",
        "whatweb_scan",
        "katana_crawl",
        "ffuf_dir",
    ]


def test_dast_scan_resume_uses_prior_run_to_avoid_repeating_tested_probe(
    tmp_path: Path,
) -> None:
    brief_path = _write_brief(tmp_path)
    run_dir = tmp_path / "run"
    workspace_dir = run_dir / "workspace"
    first_settings = DastScanSettings(
        db_path=run_dir / "audit.db",
        report_path=run_dir / "report.json",
        workspace_dir=workspace_dir,
        stdout=StringIO(),
        http_client=VulnerableOpenApiHttpClient(),
        tool_runtime=FakeToolRuntime({}),
        max_actions=1,
    )

    run_dast_scan(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=first_settings,
    )
    run_dast_scan(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=DastScanSettings(
            db_path=run_dir / "audit.db",
            report_path=run_dir / "report.json",
            resume_from=run_dir,
            workspace_dir=workspace_dir,
            stdout=StringIO(),
            http_client=VulnerableOpenApiHttpClient(),
            tool_runtime=FakeToolRuntime({}),
            max_actions=1,
        ),
    )

    actions = [
        _event_payload(event)["action"]
        for event in _read_events(workspace_dir / "events.jsonl")
        if event.get("kind") == "agent_action"
    ]
    assert actions.count("test_sqli_param") == 1
    assert "test_xss_param" in actions


def _write_brief(tmp_path: Path, body: str = BRIEF_YAML) -> Path:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(body, encoding="utf-8")
    return brief_path


def _tool_results(keys: Iterable[str]) -> dict[str, ToolResult | TerminalResult]:
    return {
        key: ToolResult(
            ok=True,
            tool=key,
            command=(key,),
            exit_code=0,
            stdout=f"{key} ok",
            stderr="",
        )
        for key in keys
    }


def _read_events(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _event_payload(event: dict[str, object]) -> dict[str, object]:
    payload = event.get("payload")
    assert isinstance(payload, dict)
    return {str(key): value for key, value in payload.items()}
