from __future__ import annotations

import json
from typing import TYPE_CHECKING

import ravage.report as report_module
from ravage.hosting_layer import (
    HOSTING_LAYER_EVENT_KIND,
    HostingCommandResult,
    run_configured_hosting_layer_agent,
)
from ravage.report import write_pentest_report
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


EXPECTED_HOSTING_CHECKS = 4
EXPECTED_TIMEOUT_SECONDS = 15


BRIEF_YAML = """
engagement_id: "88888888-8888-4888-8888-888888888888"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "web_application_assessment"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
context:
  description: "Local test app with a separate live hosting endpoint."
  hosting_check:
    live_site: "https://www.hatchpoint.sg"
""".lstrip()


def test_hosting_layer_agent_runs_curl_head_matrix_from_brief_config(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace_dir = tmp_path / "run" / "workspace"
    commands: list[tuple[str, ...]] = []

    def fake_runner(
        command: tuple[str, ...],
        *,
        timeout_seconds: int,
    ) -> HostingCommandResult:
        commands.append(command)
        assert timeout_seconds == EXPECTED_TIMEOUT_SECONDS
        url = command[-1]
        if url.startswith("http://"):
            return HostingCommandResult(
                exit_code=0,
                stdout=(
                    "HTTP/1.1 301 Moved Permanently\r\n"
                    f"Location: https://{url.removeprefix('http://')}/\r\n"
                    "Server: cloudflare\r\n"
                    "\r\n"
                ),
                stderr="",
            )
        return HostingCommandResult(
            exit_code=0,
            stdout="HTTP/2 200\r\nServer: cloudflare\r\nCF-Ray: unit-test\r\n\r\n",
            stderr="",
        )

    payload = run_configured_hosting_layer_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace_dir,
        runner=fake_runner,
    )

    assert commands == [
        ("curl", "-I", "https://hatchpoint.sg"),
        ("curl", "-I", "https://www.hatchpoint.sg"),
        ("curl", "-I", "http://hatchpoint.sg"),
        ("curl", "-I", "http://www.hatchpoint.sg"),
    ]
    assert payload is not None
    assert payload["agent"] == "hosting-layer"
    checks = payload["checks"]
    assert isinstance(checks, list)
    assert len(checks) == EXPECTED_HOSTING_CHECKS
    findings = payload["findings"]
    assert isinstance(findings, list)
    assert any("Cloudflare response headers" in str(item) for item in findings)

    events = _events(workspace_dir / "events.jsonl")
    assert events[-1]["kind"] == HOSTING_LAYER_EVENT_KIND
    event_payload = events[-1]["payload"]
    assert isinstance(event_payload, dict)
    event_checks = event_payload["checks"]
    assert isinstance(event_checks, list)
    first_check = event_checks[0]
    assert isinstance(first_check, dict)
    assert first_check["command"] == "curl -I https://hatchpoint.sg"


def test_pentest_report_appends_live_hosting_layer_section(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    output_path = tmp_path / "run" / "report.md"

    def fake_hosting_agent(
        *,
        brief_path: Path,
        target_url: str,
        workspace_dir: Path,
    ) -> dict[str, object]:
        assert target_url == "http://127.0.0.1:8765"
        assert brief_path.exists()
        payload = {
            "agent": "hosting-layer",
            "mode": "curl_head_matrix",
            "configured_live_sites": ["https://hatchpoint.sg"],
            "summary": "Ran 4 curl -I hosting check(s); successful commands=4.",
            "findings": [
                "https://hatchpoint.sg returned HTTP 200.",
                "Cloudflare response headers were observed on at least one live endpoint.",
            ],
            "checks": [
                {
                    "command": "curl -I https://hatchpoint.sg",
                    "url": "https://hatchpoint.sg",
                    "ok": True,
                    "exit_code": 0,
                    "status_code": 200,
                    "status_line": "HTTP/2 200",
                    "elapsed_ms": 12,
                    "headers": {"server": "cloudflare", "cf-ray": "unit-test"},
                    "server": "cloudflare",
                    "cloudflare": True,
                }
            ],
        }
        AgentWorkspace.open(workspace_dir).record_event(
            kind=HOSTING_LAYER_EVENT_KIND,
            payload=payload,
        )
        return payload

    monkeypatch.setattr(report_module, "run_configured_hosting_layer_agent", fake_hosting_agent)

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    markdown = output_path.read_text(encoding="utf-8")
    hosting_layer = report["hosting_layer"]
    assert isinstance(hosting_layer, dict)
    assert hosting_layer["enabled"] is True
    assert hosting_layer["agent"] == "hosting-layer"
    assert "## Live Hosting Layer" in markdown
    assert "curl -I" in markdown
    assert "https://hatchpoint.sg" in markdown
    assert "Cloudflare response headers" in markdown


def _brief(tmp_path: Path) -> Path:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    return brief_path


def _events(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
