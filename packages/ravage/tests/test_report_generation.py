from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path
from types import ModuleType
from uuid import UUID

import pytest
import ravage.report as report_module
from ravage import __main__ as cli
from ravage import report_io
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.ai_agent import AIWebAgentSettings
from ravage.agent_core.autonomous_graph.evidence import EvidenceBlackboard
from ravage.report import ProFeatureRequiredError, build_pentest_report, write_pentest_report
from ravage.report_artifact import write_json_report_artifact
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.scan_coverage import (
    PlannerProbeDecision,
    ProbeCoverageOutcome,
    ProbeDisposition,
    ScanCoverageRecorder,
    write_scan_coverage_certificate,
)
from ravage.traffic.contracts import build_captured_http_exchange
from ravage.traffic.manifest import TrafficRunManifest, write_traffic_manifest
from ravage.traffic.policy import (
    RequestIntent,
    TrafficOutcome,
    TrafficPolicyConfig,
    TrafficPolicyController,
)
from ravage.traffic.provenance import TrafficProvenanceError
from ravage.traffic.store import TrafficStore

BRIEF_YAML = """
engagement_id: "88888888-8888-4888-8888-888888888888"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope:
    - "http://127.0.0.1:9999"
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "redacted"
objectives:
  - "capture_flag"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
context:
  description: "Local test app for report generation."
""".lstrip()

_AGENT_HTTP_SECRET = "flag{report-agent-http-secret}"  # noqa: S105 - redaction fixture.
_AGENT_HTTP_OBSERVATION_ID = "http:obs-report-agent-1"
_ARGPARSE_ERROR = 2
_PRIVATE_ARTIFACT_MODE = 0o600
_DUAL_TRAFFIC_REQUEST_COUNT = 2
_REPORT_IN_SCOPE = ("http://127.0.0.1:8765",)
_REPORT_OUT_OF_SCOPE = ("http://127.0.0.1:9999",)


@pytest.mark.parametrize("source_state", ["missing", "corrupt", "wrong_schema", "directory"])
def test_report_marks_unavailable_expected_audit_evidence_incomplete(
    tmp_path: Path, source_state: str
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = workspace.root.parent / "audit.db"
    if source_state == "corrupt":
        audit_path.write_bytes(b"corrupt database containing token=do-not-expose")
    elif source_state == "wrong_schema":
        with closing(sqlite3.connect(audit_path)) as connection:
            connection.execute("CREATE TABLE unrelated (id INTEGER)")
    elif source_state == "directory":
        audit_path.mkdir()

    report = write_json_report_artifact(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=workspace.root.parent / "report.json",
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert report["status"] == "completed"  # Run state remains distinct from evidence health.
    assert report["source_quality"]["status"] == "incomplete"
    source = report["source_quality"]["audit_source"]
    assert source["expected"] is True
    assert source["status"] == ("missing" if source_state == "missing" else "unreadable")
    assert report["executive_summary"]["overall_risk"] == "Unknown"
    assert (
        "missing findings cannot be interpreted as a clean assessment"
        in (report["executive_summary"]["summary"])
    )
    markdown = report_module.render_markdown_report(report)
    assert "Overall Risk: Unknown" in markdown
    assert "Evidence completeness: incomplete" in markdown
    assert "does not establish the absence of vulnerabilities" in markdown
    assert "do-not-expose" not in json.dumps(report)
    if source_state == "missing":
        assert not audit_path.exists()


@pytest.mark.parametrize("payload", ["{broken", "[]", '{"status":"confirmed"}'])
def test_report_marks_rejected_audit_rows_incomplete(tmp_path: Path, payload: str) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = workspace.root.parent / "audit.db"
    AuditStore(audit_path).close()
    with closing(sqlite3.connect(audit_path)) as connection:
        connection.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?)",
            (
                "malformed",
                "88888888-8888-4888-8888-888888888888",
                "information_disclosure",
                "confirmed",
                "confirm",
                payload,
            ),
        )
        connection.commit()

    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert report["findings"] == []
    assert report["source_quality"]["status"] == "incomplete"
    assert report["source_quality"]["audit_source"] == {
        "expected": True,
        "status": "invalid_records",
        "confirmed_rows_loaded": 1,
        "accepted_findings": 0,
        "rejected_rows": 1,
    }
    assert report["executive_summary"]["overall_risk"] == "Unknown"


def test_report_keeps_valid_findings_when_expected_audit_is_missing(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=workspace.root.parent / "missing.db",
    )

    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["finding_count"] == 1
    assert report["executive_summary"]["overall_risk"] == "High"
    assert (
        "Available evidence retains 1 confirmed finding(s)"
        in (report["executive_summary"]["summary"])
    )
    assert report["findings"][0]["recommendation"]


def test_report_marks_unreadable_expected_audit_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = workspace.root.parent / "audit.db"
    AuditStore(audit_path).close()

    def deny_database_access(*_args: object, **_kwargs: object) -> None:
        message = "simulated permission denial"
        raise PermissionError(message)

    monkeypatch.setattr(report_module.sqlite3, "connect", deny_database_access)
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert report["source_quality"]["audit_source"]["status"] == "unreadable"
    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["overall_risk"] == "Unknown"


def test_report_retains_valid_audit_findings_alongside_rejected_rows(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = workspace.root.parent / "audit.db"
    AuditStore(audit_path).close()
    valid = _confirmed_finding_payload(
        finding_id="valid-finding", vuln_class="xss", severity="Medium"
    )
    with closing(sqlite3.connect(audit_path)) as connection:
        for finding_id, raw in (("valid-finding", json.dumps(valid)), ("broken", "{broken")):
            connection.execute(
                "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?)",
                (finding_id, valid["engagement_id"], "xss", "confirmed", "confirm", raw),
            )
        connection.commit()
    original_database = audit_path.read_bytes()

    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert [finding["finding_id"] for finding in report["findings"]] == ["valid-finding"]
    assert report["source_quality"]["audit_source"]["rejected_rows"] == 1
    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["overall_risk"] == "Medium"
    assert audit_path.read_bytes() == original_database


@pytest.mark.parametrize("audit_requested", [False, True])
def test_report_distinguishes_empty_audit_from_optional_events_only_source(
    tmp_path: Path, *, audit_requested: bool
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = workspace.root.parent / "audit?literal#name.db" if audit_requested else None
    if audit_path is not None:
        AuditStore(audit_path).close()
    else:
        workspace.events_path.touch()
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert report["source_quality"]["status"] == "complete"
    source = report["source_quality"]["audit_source"]
    assert source["expected"] is audit_requested
    assert source["status"] == ("available" if audit_requested else "not_requested")
    assert report["executive_summary"]["overall_risk"] == "Low"


def test_report_without_any_evidence_is_incomplete(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
    )
    assert report["source_quality"]["status"] == "incomplete"
    assert report["source_quality"]["event_sources"][0] == {
        "events_path": str(workspace.events_path),
        "expected": True,
        "status": "missing",
        "events_loaded": 0,
        "parse_errors": 0,
    }
    assert report["executive_summary"]["overall_risk"] == "Unknown"


@pytest.mark.parametrize("persisted_state", [False, True])
def test_cli_report_does_not_turn_lost_event_evidence_into_a_clean_assessment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, persisted_state: bool
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    if persisted_state:
        workspace.write_state({"status": "completed"})
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)
    command = ["report", str(workspace.root.parent), "--brief", str(brief_path)]
    cli.main(command)
    output = workspace.root.parent / "report.json"
    before = json.loads(output.read_text(encoding="utf-8"))
    assert before["executive_summary"]["overall_risk"] == "High"
    assert before["executive_summary"]["finding_count"] == 1

    saved_events = workspace.events_path.with_suffix(".saved")
    workspace.events_path.rename(saved_events)
    try:
        cli.main(command)
        after = json.loads(output.read_text(encoding="utf-8"))
        assert after["source_quality"]["event_paths"] == []
        assert after["source_quality"]["status"] == "incomplete"
        assert after["executive_summary"]["overall_risk"] == "Unknown"
        assert after["executive_summary"]["finding_count"] == 0
        markdown = output.with_suffix(".md").read_text(encoding="utf-8")
        assert f"Event source: {workspace.events_path} (missing)" in markdown
        assert "does not establish the absence of vulnerabilities" in markdown
    finally:
        saved_events.rename(workspace.events_path)
    cli.main(command)
    restored = json.loads(output.read_text(encoding="utf-8"))
    assert restored["source_quality"]["status"] == "complete"
    assert restored["executive_summary"]["overall_risk"] == "High"
    assert restored["executive_summary"]["finding_count"] == 1


@pytest.mark.parametrize("marker", ["working_state.json", "transcript.jsonl", "scan-summary.json"])
def test_report_marks_expected_event_log_missing_even_with_a_healthy_audit(
    tmp_path: Path, marker: str
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    (workspace.root / marker).write_text("{}\n", encoding="utf-8")
    audit_path = workspace.root.parent / "audit.db"
    AuditStore(audit_path).close()
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )
    assert report["source_quality"]["audit_source"]["status"] == "available"
    assert report["source_quality"]["event_sources"][0]["status"] == "missing"
    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["overall_risk"] == "Unknown"


@pytest.mark.parametrize("damage", ["directory", "broken_symlink", "utf8", "permission", "race"])
def test_report_marks_unreadable_or_disappearing_event_sources_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = workspace.root.parent / "audit.db"
    AuditStore(audit_path).close()
    if damage == "directory":
        workspace.events_path.mkdir()
    elif damage == "broken_symlink":
        workspace.events_path.symlink_to(workspace.root / "absent-events")
    elif damage == "utf8":
        workspace.events_path.write_bytes(b"\xff\xfe\n")
    else:
        workspace.events_path.touch()
        read_text = Path.read_text

        def unavailable_events(
            path: Path, encoding: str | None = None, errors: str | None = None
        ) -> str:
            if path == workspace.events_path:
                error = PermissionError if damage == "permission" else FileNotFoundError
                raise error
            return read_text(path, encoding=encoding, errors=errors)

        monkeypatch.setattr(Path, "read_text", unavailable_events)
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )
    expected_status = "missing" if damage in {"broken_symlink", "race"} else "unreadable"
    assert report["source_quality"]["event_sources"][0]["status"] == expected_status
    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["overall_risk"] == "Unknown"


def test_report_retains_available_findings_when_a_nested_event_log_is_missing(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    nested = workspace.root / "autonomous-route" / "agent-graph"
    nested.mkdir(parents=True)
    (nested / "working_state.json").write_text("{}\n", encoding="utf-8")
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
    )
    assert report["source_quality"]["status"] == "incomplete"
    assert report["source_quality"]["event_sources"][-1]["status"] == "missing"
    assert report["executive_summary"]["finding_count"] == 1
    assert report["executive_summary"]["overall_risk"] == "High"


def test_report_accepts_nested_events_without_an_optional_primary_log(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    nested = AgentWorkspace.open(workspace.root / "autonomous-route" / "agent-graph")
    nested.record_event(
        kind="finding_confirmed",
        payload=_confirmed_finding_payload(
            finding_id="nested-finding", vuln_class="information_disclosure", severity="High"
        ),
    )
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
    )
    assert report["source_quality"]["event_sources"][0]["status"] == "not_requested"
    assert report["source_quality"]["status"] == "complete"
    assert report["executive_summary"]["finding_count"] == 1


@pytest.mark.parametrize("event_line", ["{broken", "[]"])
def test_report_does_not_label_malformed_event_sources_clean(
    tmp_path: Path, event_line: str
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.events_path.write_text(event_line + "\n", encoding="utf-8")
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
    )
    assert report["source_quality"]["event_parse_errors"] == 1
    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["overall_risk"] == "Unknown"


@pytest.mark.parametrize("invalid_field", ["proof", "engagement_id", "status"])
def test_report_marks_rejected_confirmed_events_incomplete(
    tmp_path: Path, invalid_field: str
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    finding = _confirmed_finding_payload(
        finding_id="incomplete-event", vuln_class="xss", severity="Medium"
    )
    finding.pop(invalid_field)
    workspace.record_event(kind="finding_confirmed", payload=finding)
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
    )
    assert report["source_quality"]["rejected_confirmed_events"] == 1
    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["overall_risk"] == "Unknown"
    assert "Rejected confirmed events: 1" in report_module.render_markdown_report(report)


def test_report_excludes_other_engagement_events_without_marking_source_incomplete(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.record_event(
        kind="finding_confirmed",
        payload={"engagement_id": "99999999-9999-4999-8999-999999999999", "status": "confirmed"},
    )
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
    )
    assert report["source_quality"]["rejected_confirmed_events"] == 0
    assert report["source_quality"]["status"] == "complete"


@pytest.mark.parametrize(
    "damage", ["missing_table", "wrong_columns", "malformed_row", "nontext_row"]
)
def test_report_marks_damaged_audit_log_incomplete_with_valid_findings_table(
    tmp_path: Path, damage: str
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = workspace.root.parent / "audit.db"
    _seed_audit_only_proof(audit_path)
    with closing(sqlite3.connect(audit_path)) as connection:
        if damage == "malformed_row":
            connection.execute("UPDATE audit_log SET payload_json = '{broken'")
        elif damage == "nontext_row":
            connection.execute("UPDATE audit_log SET payload_json = ?", (b"{}",))
        else:
            connection.execute("DROP TABLE audit_log")
            if damage == "wrong_columns":
                connection.execute("CREATE TABLE audit_log (id INTEGER)")
        connection.commit()
    original_database = audit_path.read_bytes()

    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert report["source_quality"]["audit_source"]["status"] == "available"
    assert report["source_quality"]["audit_log_source"]["status"] == (
        "invalid_records" if damage in {"malformed_row", "nontext_row"} else "unreadable"
    )
    assert report["source_quality"]["status"] == "incomplete"
    assert report["executive_summary"]["overall_risk"] == "Unknown"
    assert audit_path.read_bytes() == original_database


def _seed_audit_only_proof(audit_path: Path) -> None:
    proof = "flag{report-source-health-fixture}"
    with closing(AuditStore(audit_path)) as audit:
        for action, payload in (
            (
                "tool_run_probe",
                {
                    "observation_id": "recorded-observation",
                    "action_id": "recorded-action",
                    "recognized_proofs": [proof],
                },
            ),
            (
                "flag_captured",
                {
                    "flag": proof,
                    "source_observation_id": "recorded-observation",
                    "source_kind": "tool_run_probe",
                    "action_id": "recorded-action",
                },
            ),
        ):
            audit.record(
                engagement_id=UUID("88888888-8888-4888-8888-888888888888"),
                actor="report-test",
                action=action,
                payload=payload,
            )


@pytest.mark.parametrize("suffix", [".md", ".json", ""])
def test_explicit_reports_are_private_complete_atomic_and_redact_late_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    output_path = tmp_path / "token=artifact-secret-value" / f"report{suffix}"
    output_path.parent.mkdir()
    markdown_path = output_path if suffix != ".json" else output_path.with_suffix(".md")
    json_path = output_path.with_suffix(".json")
    for path in (markdown_path, json_path):
        path.write_text("old complete output", encoding="utf-8")
        path.chmod(0o644)
    synced_files: list[str] = []
    replaced_files: list[Path] = []
    original_fsync = os.fsync
    original_replace = Path.replace

    def record_fsync(descriptor: int) -> None:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            synced_files.append("synced")
        original_fsync(descriptor)

    def inspect_replace(path: Path, target: Path) -> Path:
        assert stat.S_IMODE(path.stat().st_mode) == _PRIVATE_ARTIFACT_MODE
        assert len(synced_files) > len(replaced_files)
        assert target.read_text(encoding="utf-8") == "old complete output"
        assert "artifact-secret-value" not in path.read_text(encoding="utf-8")
        replaced_files.append(target)
        return original_replace(path, target)

    monkeypatch.setattr(report_io.os, "fsync", record_fsync)
    monkeypatch.setattr(Path, "replace", inspect_replace)
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)
    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    assert replaced_files == [markdown_path, json_path]
    assert json.loads(json_path.read_text(encoding="utf-8")) == report
    assert report["artifacts"]["json_report_path"].endswith("token=<SECRET_REDACTED>/report.json")
    for path in (markdown_path, json_path):
        assert stat.S_IMODE(path.stat().st_mode) == _PRIVATE_ARTIFACT_MODE
        assert not list(path.parent.glob(f".{path.name}.*.tmp"))


def test_report_write_failure_preserves_existing_output_and_removes_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    output_path = workspace.root.parent / "report.md"
    output_path.write_text("previous complete report", encoding="utf-8")

    def fail_fsync(_: int) -> None:
        message = "simulated persistence failure"
        raise OSError(message)

    monkeypatch.setattr(report_io.os, "fsync", fail_fsync)
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)
    with pytest.raises(OSError, match="simulated persistence failure"):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert output_path.read_text(encoding="utf-8") == "previous complete report"
    assert not list(output_path.parent.glob(f".{output_path.name}.*.tmp"))


def test_json_report_artifact_is_private_atomic_and_has_no_report_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    output_path = tmp_path / "run" / "report.json"
    output_path.write_text("stale\n", encoding="utf-8")

    def unexpected_hosting_agent(**_: object) -> None:
        message = "JSON-only artifact must not run the hosting-layer agent"
        raise AssertionError(message)

    monkeypatch.setattr(
        "ravage.report.run_configured_hosting_layer_agent",
        unexpected_hosting_agent,
    )

    report = write_json_report_artifact(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="incomplete",
        completed=False,
        termination_reason="max_turns_reached",
    )

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved == report
    assert saved["status"] == "incomplete"
    assert saved["completed"] is False
    assert saved["executive_summary"]["finding_count"] == 1
    assert saved["run"]["termination_reason"] == "max_turns_reached"
    assert saved["artifacts"] == {
        "json_report_path": str(output_path),
        "markdown_report_path": "",
        "professional_report_path": "",
    }
    assert stat.S_IMODE(output_path.stat().st_mode) == _PRIVATE_ARTIFACT_MODE
    assert not output_path.with_suffix(".md").exists()
    assert not list(output_path.parent.glob(f".{output_path.name}.*.tmp"))


def test_json_report_artifact_redacts_late_metadata_and_preserves_existing_report_paths(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    secret_path_component = "token=artifact-secret-value"  # noqa: S105 - redaction fixture.
    secret_termination_reason = "token=termination-secret-value"  # noqa: S105 - redaction fixture.
    output_path = tmp_path / secret_path_component / "report.json"
    markdown_path = tmp_path / "human-report.md"
    markdown_path.write_text("# Existing human report\n", encoding="utf-8")

    report = write_json_report_artifact(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="incomplete",
        completed=False,
        termination_reason=secret_termination_reason,
        markdown_report_path=markdown_path,
    )

    serialized = json.dumps(report, sort_keys=True)
    assert secret_path_component not in serialized
    assert secret_termination_reason not in serialized
    assert report["artifacts"]["json_report_path"].endswith("token=<SECRET_REDACTED>/report.json")
    assert report["artifacts"]["markdown_report_path"] == str(markdown_path)
    assert report["run"]["termination_reason"] == "token=<SECRET_REDACTED>"


def test_json_report_artifact_does_not_promote_stale_manifest_proof_status(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    (workspace.root.parent / "run.json").write_text(
        json.dumps({"run_id": "stale-manifest", "flag_found": True}),
        encoding="utf-8",
    )

    report = write_json_report_artifact(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=workspace.root.parent / "report.json",
        status="completed",
        completed=True,
    )

    assert report["captured_proofs"]["count"] == 0
    assert report["executive_summary"]["captured_proof_count"] == 0
    assert report["executive_summary"]["overall_risk"] == "Unknown"
    assert report["source_quality"]["status"] == "incomplete"
    assert report["run"]["flag_found"] is False
    assert report["run"]["manifest_flag_found"] is True


def test_write_pentest_report_generates_redacted_markdown_and_json(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    traffic_policy = TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url="http://127.0.0.1:8765",
        config=TrafficPolicyConfig(),
    )
    decision = traffic_policy.acquire(
        RequestIntent(method="GET", url="http://127.0.0.1:8765/report")
    )
    assert decision.lease is not None
    traffic_policy.begin_dispatch(decision.lease)
    traffic_policy.complete(decision.lease, TrafficOutcome(status=200))
    output_path = tmp_path / "run" / "pentest-report.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    markdown = output_path.read_text(encoding="utf-8")
    saved = json.loads(output_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert report["executive_summary"]["overall_risk"] == "High"
    assert saved["executive_summary"]["finding_count"] == 1
    assert saved["captured_proofs"]["masked"] == ["flag{REDACTED}"]
    assert saved["work_performed"][0]["outcome"] == "ok"
    assert saved["traffic_accounting"]["status"] == "exact"
    assert saved["traffic_accounting"]["physical_request_count"] == 1
    assert "parameterized queries" in saved["findings"][0]["recommendation"]
    assert "# Web Application Penetration Test Report" in markdown
    assert "Sql Injection" in markdown
    assert "Recommendation:" in markdown
    assert "Physical target requests: 1" in markdown
    assert "Request accounting status: exact" in markdown
    assert "flag{REDACTED}" in markdown
    assert "flag{unit_report_secret}" not in markdown
    assert "sk-ABCDEF1234567890ABCDEF" not in markdown
    assert "api_key=<SECRET_REDACTED>" in markdown


def test_report_rejects_traffic_accounting_from_another_target(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url="http://127.0.0.1:8766",
        config=TrafficPolicyConfig(),
    )
    output_path = tmp_path / "run" / "wrong-target-accounting.md"

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic accounting does not match the report target",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()
    assert not output_path.with_suffix(".json").exists()


def test_report_accepts_the_policy_writers_unicode_host_normalization(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    target_url = "http://faß.de/path"
    TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url=target_url,
        config=TrafficPolicyConfig(),
    )
    output_path = tmp_path / "run" / "unicode-policy-origin.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url=target_url,
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    assert report["traffic_accounting"]["status"] == "exact"
    assert output_path.exists()


def test_report_includes_path_free_scan_coverage_without_overclaiming(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    traffic_policy = TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url="http://127.0.0.1:8765",
        config=TrafficPolicyConfig(),
    )
    recorder = ScanCoverageRecorder()
    private_surface = "http://127.0.0.1:8765/private/admin?token=secret"
    recorder.record_planner_decision(
        PlannerProbeDecision(
            probe_id="surface_map",
            family="discovery",
            rank=0,
            surface_key=private_surface,
            reason_codes=("required_default",),
        )
    )
    recorder.record_probe_outcome(
        ProbeCoverageOutcome(
            probe_id="surface_map",
            disposition=ProbeDisposition.COMPLETED_NO_FINDING,
        )
    )
    write_scan_coverage_certificate(
        workspace.root.parent / "scan-coverage.json",
        recorder.finalize(
            planner_frontier_exhausted=True,
            traffic_snapshot=traffic_policy.snapshot(),
            traffic_config=traffic_policy.config,
        ),
    )

    output_path = workspace.root.parent / "coverage-report.md"
    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    markdown = output_path.read_text(encoding="utf-8")
    assert report["scan_coverage"]["status"] == "complete"
    assert report["scan_coverage"]["completion_basis"] == "planner_frontier_exhausted"
    assert "## Deterministic Scan Coverage" in markdown
    assert "does not claim that the application" in markdown
    assert private_surface not in json.dumps(report)
    assert private_surface not in markdown


def test_report_summarizes_deterministic_scan_work_recon_and_recorded_traffic(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.record_event(
        kind="scan_started",
        payload={"target_url": "http://127.0.0.1:8765/search?token=private"},
    )
    surface_payload = {
        "probe": "surface_map",
        "ok": True,
        "summary": "received 2/3 HTTP response(s), notable=1",
        "findings": [
            {
                "type": "interesting_response",
                "url": "http://127.0.0.1:8765/admin",
                "status": 403,
            }
        ],
        "requests": [
            {"url": "http://127.0.0.1:8765/", "status": 200},
            {"url": "http://127.0.0.1:8765/admin", "status": 403},
            {
                "url": "http://127.0.0.1:8765/missing",
                "status": None,
                "error": "connection reset",
            },
        ],
        "errors": [],
    }
    workspace.record_event(
        kind="tool_run_probe",
        payload={
            "action_id": "scan-001-surface_map",
            "observation_id": "scan-observation-1",
            "ok": True,
            "timed_out": False,
            "result": json.dumps(surface_payload),
        },
    )
    workspace.record_event(
        kind="scan_probe",
        payload={
            **surface_payload,
            "action_id": "scan-001-surface_map",
            "source_observation_id": "scan-observation-1",
        },
    )
    workspace.record_event(
        kind="scan_probe",
        payload={
            "probe": "input_reflection",
            "ok": False,
            "summary": "checked 1 input, findings=0",
            "findings": [],
            "requests": [],
            "errors": [],
        },
    )
    _add_deterministic_scan_traffic(workspace.root)
    _add_agent_http_provenance(workspace.root)
    output_path = tmp_path / "run" / "deterministic-report.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    assert report["work_performed"] == [
        {
            "turn": "",
            "action": "run_probe",
            "detail": "surface_map: received 2/3 HTTP response(s), notable=1",
            "outcome": "ok",
        },
        {
            "turn": "",
            "action": "run_probe",
            "detail": "input_reflection: checked 1 input, findings=0",
            "outcome": "not confirmed",
        },
    ]
    assert report["reconnaissance"] == {
        "target_url": "http://127.0.0.1:8765/search?token=<SECRET_REDACTED>",
        "origin": "http://127.0.0.1:8765",
        "page_count": 2,
        "form_count": 0,
        "query_parameter_names": [],
        "interesting_markers": ["interesting_response"],
        "errors": [],
        "source_kinds": ["scan_probe:surface_map"],
        "surface_request_count": 3,
        "surface_response_count": 2,
        "surface_status_counts": {"200": 1, "403": 1},
        "surface_finding_count": 1,
        "surface_finding_types": ["interesting_response"],
    }
    assert report["traffic_accounting"] == {
        "status": "lower_bound",
        "provenance": "validated_workspace_traffic_store",
        "mode": "recorded_scan_traffic",
        "physical_request_count": 2,
        "max_physical_requests": None,
        "remaining_physical_requests": None,
        "recorded_exchange_count": 2,
        "blocked_count": 0,
        "capture_completed": True,
    }
    markdown = output_path.read_text(encoding="utf-8")
    assert "Physical target requests: 2" in markdown
    assert "Request accounting status: lower_bound" in markdown
    assert "Surface-map HTTP responses: 2/3 requests" in markdown
    assert "surface_map: received 2/3 HTTP response(s)" in markdown


def test_report_revalidates_scan_lane_attribution_after_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.record_event(
        kind="scan_probe",
        payload={"probe": "surface_map", "requests": [], "findings": [], "errors": []},
    )
    _add_deterministic_scan_traffic(workspace.root)
    graph_workspace = workspace.root / "autonomous-route" / "agent-graph"
    TrafficStore.create(graph_workspace)
    write_traffic_manifest(
        graph_workspace,
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:8765",
            capture_session_id="scan-graph-session",
            in_scope=_REPORT_IN_SCOPE,
            out_of_scope=_REPORT_OUT_OF_SCOPE,
        ).complete(),
    )
    original_resolver = report_module.resolve_workspaces

    def resolve_then_tamper(supplied: Path) -> tuple[Path, ...]:
        resolved = original_resolver(supplied)
        manifest_path = graph_workspace / "traffic" / "run.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["target_url"] = "http://127.0.0.1:8765/different-target"
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        manifest_path.chmod(_PRIVATE_ARTIFACT_MODE)
        return resolved

    monkeypatch.setattr(
        report_module,
        "_agent_http_evidence_summary",
        lambda *_args, **_kwargs: report_module._empty_agent_http_evidence_summary(),  # noqa: SLF001
    )
    monkeypatch.setattr(report_module, "resolve_workspaces", resolve_then_tamper)
    output_path = tmp_path / "run" / "tampered-scan-lanes.md"

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic history does not match the report target or scope",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()
    assert not output_path.with_suffix(".json").exists()


def test_report_summarizes_orphan_tool_probe_without_duplicating_agent_actions(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.record_event(
        kind="tool_run_probe",
        payload={
            "ok": True,
            "timed_out": False,
            "result": json.dumps(
                {
                    "probe": "surface_map",
                    "ok": True,
                    "summary": "fetched 1 URL(s), notable=1",
                    "findings": [{"type": "interesting_response"}],
                    "requests": [{"url": "http://127.0.0.1:8765/", "status": 200}],
                    "errors": [],
                }
            ),
        },
    )
    output_path = tmp_path / "run" / "tool-probe-report.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    assert report["work_performed"] == [
        {
            "turn": "",
            "action": "run_probe",
            "detail": "surface_map: fetched 1 URL(s), notable=1",
            "outcome": "ok",
        }
    ]
    assert report["reconnaissance"]["source_kinds"] == ["tool_run_probe:surface_map"]
    assert report["reconnaissance"]["page_count"] == 1
    assert report["traffic_accounting"] == {
        "status": "unavailable",
        "provenance": "traffic_policy_ledger_missing",
    }


def test_report_links_nested_agent_http_traffic_to_identifier_only_evidence(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    graph_workspace, request_id, evidence_ids, material_evidence_ids = _add_agent_http_provenance(
        workspace.root
    )
    output_path = tmp_path / "run" / "agent-http-report.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    provenance = report["agent_http_evidence"]
    assert provenance == {
        "status": "available",
        "request_count": 1,
        "linked_request_count": 1,
        "observation_only_request_count": 0,
        "evidence_count": len(evidence_ids),
        "material_evidence_count": len(material_evidence_ids),
        "links": [
            {
                "lane": "autonomous_graph",
                "request_id": f"autonomous_graph:{request_id}",
                "local_request_id": request_id,
                "status": "linked",
                "observation_id": _AGENT_HTTP_OBSERVATION_ID,
                "evidence_ids": list(evidence_ids),
                "material_evidence_ids": list(material_evidence_ids),
            }
        ],
    }
    assert graph_workspace == workspace.root / "autonomous-route" / "agent-graph"
    saved_text = output_path.with_suffix(".json").read_text(encoding="utf-8")
    markdown = output_path.read_text(encoding="utf-8")
    assert "## Agent HTTP Evidence" in markdown
    for identifier in (
        request_id,
        _AGENT_HTTP_OBSERVATION_ID,
        *evidence_ids,
        *material_evidence_ids,
    ):
        assert identifier in markdown
        assert identifier in saved_text
    assert _AGENT_HTTP_SECRET not in markdown
    assert _AGENT_HTTP_SECRET not in saved_text
    assert "response_body" not in json.dumps(provenance)
    assert "request_headers" not in json.dumps(provenance)
    assert "route_fingerprint" not in json.dumps(provenance)
    assert "evidence_records" not in json.dumps(provenance)
    assert "payload" not in json.dumps(provenance)


def test_report_aggregates_valid_base_and_graph_agent_http_histories(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    base_session_id = "base-agent-http-report-session"
    base_observation_id = "http:obs-report-base-1"
    base_store = TrafficStore.create(workspace.root)
    write_traffic_manifest(
        workspace.root,
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:8765",
            capture_session_id=base_session_id,
            in_scope=_REPORT_IN_SCOPE,
            out_of_scope=_REPORT_OUT_OF_SCOPE,
        ).complete(),
    )
    base_blackboard = EvidenceBlackboard(
        target_url="http://127.0.0.1:8765",
        state_path=workspace.root / "evidence-blackboard.json",
    )
    base_blackboard.record_action_result(
        producer_node_id="base-agent",
        action={"action": "http_request", "method": "GET", "url": "/base-proof"},
        result=ActionResult(
            ok=True,
            observation="base target response",
            outcome="http_response_observed",
            evidence_source_kind="tool_http_request",
            evidence_observation="base target response",
        ),
        observation_id=base_observation_id,
    )
    base_store.append_exchange(
        build_captured_http_exchange(
            capture_session_id=base_session_id,
            source="agent_http",
            source_observation_id=base_observation_id,
            method="GET",
            url="http://127.0.0.1:8765/base-proof",
            request_sent=True,
            response_status=200,
            response_final_url="http://127.0.0.1:8765/base-proof",
            response_body="base target response",
            scope_decision="allowed",
        )
    )
    _add_agent_http_provenance(workspace.root)
    output_path = tmp_path / "run" / "dual-agent-http-report.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    provenance = report["agent_http_evidence"]
    assert provenance["status"] == "available"
    assert provenance["request_count"] == _DUAL_TRAFFIC_REQUEST_COUNT
    assert provenance["linked_request_count"] == _DUAL_TRAFFIC_REQUEST_COUNT
    assert len(provenance["links"]) == _DUAL_TRAFFIC_REQUEST_COUNT
    assert [link["lane"] for link in provenance["links"]] == [
        "base",
        "autonomous_graph",
    ]
    assert [link["local_request_id"] for link in provenance["links"]] == [
        "rq_0001",
        "rq_0001",
    ]
    assert [link["request_id"] for link in provenance["links"]] == [
        "base:rq_0001",
        "autonomous_graph:rq_0001",
    ]
    assert output_path.exists()
    assert _AGENT_HTTP_SECRET not in output_path.read_text(encoding="utf-8")


def test_report_rejects_agent_http_evidence_from_another_target(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    other_target = "http://127.0.0.1:8766"
    _add_agent_http_provenance(
        workspace.root,
        target_url=other_target,
        in_scope=(other_target,),
    )
    output_path = tmp_path / "run" / "spliced-target-evidence.md"

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic history does not match the report target or scope",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()
    assert not output_path.with_suffix(".json").exists()


def test_report_rejects_agent_http_evidence_from_a_broader_scope(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    _add_agent_http_provenance(
        workspace.root,
        in_scope=(*_REPORT_IN_SCOPE, "http://127.0.0.1:8765/admin"),
    )
    output_path = tmp_path / "run" / "spliced-scope-evidence.md"

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic history does not match the report target or scope",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()
    assert not output_path.with_suffix(".json").exists()


def test_report_binds_unredacted_target_identity_when_url_shapes_match(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    TrafficStore.create(workspace.root)
    write_traffic_manifest(
        workspace.root,
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:8765/private?token=first",
            capture_session_id="raw-target-identity",
            in_scope=_REPORT_IN_SCOPE,
            out_of_scope=_REPORT_OUT_OF_SCOPE,
        ).complete(),
    )
    output_path = tmp_path / "run" / "wrong-raw-target.md"

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic history does not match the report target or scope",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765/private?token=second",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()
    assert not output_path.with_suffix(".json").exists()


@pytest.mark.parametrize(
    ("raw_target", "reported_target"),
    [
        (
            "http://127.0.0.1:8765/private?token=first",
            "http://127.0.0.1:8765/private?token=%5BREDACTED%5D",
        ),
        (
            "http://127.0.0.1:8765/users/123456",
            "http://127.0.0.1:8765/users/:id",
        ),
        ("http://127.0.0.1:8765", "http://127.0.0.1:8765/"),
    ],
)
def test_report_accepts_a_matching_persisted_safe_target(
    tmp_path: Path,
    raw_target: str,
    reported_target: str,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    TrafficStore.create(workspace.root)
    write_traffic_manifest(
        workspace.root,
        TrafficRunManifest.create(
            target_url=raw_target,
            capture_session_id="redacted-target-identity",
            in_scope=_REPORT_IN_SCOPE,
            out_of_scope=_REPORT_OUT_OF_SCOPE,
        ).complete(),
    )
    output_path = tmp_path / "run" / "redacted-target.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url=reported_target,
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    assert report["agent_http_evidence"]["status"] == "not_available"
    assert output_path.exists()


def test_report_marks_agent_http_evidence_not_available_without_traffic(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    output_path = tmp_path / "run" / "no-agent-http-report.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    assert report["agent_http_evidence"] == {
        "status": "not_available",
        "request_count": 0,
        "linked_request_count": 0,
        "observation_only_request_count": 0,
        "evidence_count": 0,
        "material_evidence_count": 0,
        "links": [],
    }
    assert "No agent HTTP traffic provenance was available" in output_path.read_text(
        encoding="utf-8"
    )


def test_report_loads_confirmed_findings_from_nested_graph_events_without_audit_db(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    graph_events = workspace.root / "autonomous-route" / "agent-graph" / "events.jsonl"
    graph_events.parent.mkdir(parents=True)
    workspace.events_path.replace(graph_events)

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=tmp_path / "run" / "nested-report.md",
        status="completed",
        completed=True,
    )

    assert report["executive_summary"]["finding_count"] == 1
    assert report["findings"][0]["vuln_class"] == "sql_injection"
    assert str(graph_events) in report["source_quality"]["event_paths"]


def test_report_fails_closed_when_new_graph_http_state_loses_traffic(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    graph_workspace, _request_id, _evidence_ids, _material_ids = _add_agent_http_provenance(
        workspace.root
    )
    state_path = graph_workspace / "graph-http-state.json"
    state_path.write_text('{"version":2,"target_identity":"target:marker"}\n', encoding="utf-8")
    state_path.chmod(0o600)
    shutil.rmtree(graph_workspace / "traffic")

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic artifacts are present but could not be validated",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=tmp_path / "run" / "missing-agent-http-traffic.md",
            status="completed",
            completed=True,
        )


def test_report_fails_closed_when_base_agent_http_state_loses_traffic(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    state_path = workspace.root / "agent-http-state.json"
    state_path.write_text('{"version":2,"target_identity":"target:marker"}\n', encoding="utf-8")
    state_path.chmod(0o600)
    EvidenceBlackboard(
        target_url="http://127.0.0.1:8765",
        state_path=workspace.root / "evidence-blackboard.json",
    )

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic artifacts are present but could not be validated",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=tmp_path / "run" / "missing-base-agent-http-traffic.md",
            status="completed",
            completed=True,
        )


def test_report_fails_closed_for_tampered_agent_http_blackboard(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    graph_workspace, _request_id, _evidence_ids, _material_ids = _add_agent_http_provenance(
        workspace.root
    )
    blackboard_path = graph_workspace / "evidence-blackboard.json"
    payload = json.loads(blackboard_path.read_text(encoding="utf-8"))
    payload["records"][0]["payload"]["outcome"] = _AGENT_HTTP_SECRET
    blackboard_path.write_text(json.dumps(payload), encoding="utf-8")
    output_path = tmp_path / "run" / "tampered-agent-http-report.md"

    with pytest.raises(TrafficProvenanceError, match="invalid evidence blackboard") as raised:
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert _AGENT_HTTP_SECRET not in str(raised.value)
    assert not output_path.exists()
    assert not output_path.with_suffix(".json").exists()


def test_report_fails_closed_when_agent_http_blackboard_is_missing(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    graph_workspace, _request_id, _evidence_ids, _material_ids = _add_agent_http_provenance(
        workspace.root
    )
    (graph_workspace / "evidence-blackboard.json").unlink()

    with pytest.raises(
        TrafficProvenanceError,
        match="without its canonical evidence blackboard",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=tmp_path / "run" / "missing-agent-http-blackboard.md",
            status="completed",
            completed=True,
        )


def test_report_fails_closed_for_ambiguous_agent_http_provenance(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    graph_workspace, _request_id, _evidence_ids, _material_ids = _add_agent_http_provenance(
        workspace.root
    )
    evidence = graph_workspace / "evidence-blackboard.json"
    (graph_workspace / "remote-evidence-blackboard.json").write_bytes(evidence.read_bytes())
    output_path = tmp_path / "run" / "ambiguous-agent-http-report.md"

    with pytest.raises(
        TrafficProvenanceError,
        match="multiple canonical evidence blackboards",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()


def test_report_fails_closed_for_unvalidated_or_mismatched_traffic_roots(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    malformed = workspace.root / "autonomous-route" / "agent-graph" / "traffic"
    malformed.mkdir(parents=True)

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic artifacts are present but could not be validated",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=tmp_path / "run" / "malformed-traffic.md",
            status="completed",
            completed=True,
        )

    malformed.rmdir()
    _add_agent_http_provenance(workspace.root)
    base_store = TrafficStore.create(workspace.root)
    write_traffic_manifest(
        workspace.root,
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:9998",
            capture_session_id="agent-http-report-base",
        ),
    )
    assert base_store.exchanges() == ()
    with pytest.raises(
        TrafficProvenanceError,
        match="traffic artifacts are present but could not be validated",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=tmp_path / "run" / "ambiguous-traffic.md",
            status="completed",
            completed=True,
        )


def test_report_fails_closed_for_malformed_declared_traffic_workspace(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    declared_workspace = workspace.root / "legacy-http-workspace"
    (declared_workspace / "traffic").mkdir(parents=True)
    workspace.root.joinpath("run.json").write_text(
        json.dumps({"workspace_dir": "legacy-http-workspace"}),
        encoding="utf-8",
    )
    output_path = tmp_path / "run" / "malformed-declared-traffic.md"

    with pytest.raises(
        TrafficProvenanceError,
        match="traffic artifacts are present but could not be validated",
    ):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()
    assert not output_path.with_suffix(".json").exists()


def test_cli_report_surfaces_malformed_agent_http_store_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    graph_workspace, _request_id, _evidence_ids, _material_ids = _add_agent_http_provenance(
        workspace.root
    )
    (graph_workspace / "traffic" / "exchanges.jsonl").write_text(
        f'{{"unsafe":"{_AGENT_HTTP_SECRET}"',
        encoding="utf-8",
    )
    output_path = tmp_path / "run" / "malformed-cli-report.md"

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "report",
                str(workspace.root.parent),
                "--brief",
                str(brief_path),
                "--output",
                str(output_path),
            ]
        )

    assert raised.value.code == _ARGPARSE_ERROR
    error = capsys.readouterr().err
    assert "traffic artifacts are present but could not be validated" in error
    assert "Traceback" not in error
    assert _AGENT_HTTP_SECRET not in error
    assert not output_path.exists()


def test_report_does_not_promote_unvalidated_workspace_event(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    workspace.record_event(
        kind="finding_confirmed",
        payload={
            "finding_id": "model-claim-without-proof",
            "status": "confirmed",
            "vuln_class": "xss",
            "severity": "critical",
        },
    )

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=tmp_path / "run" / "filtered-report.md",
        status="completed",
        completed=True,
    )

    assert report["executive_summary"]["finding_count"] == 1
    assert [finding["vuln_class"] for finding in report["findings"]] == ["sql_injection"]


def test_report_prefers_authoritative_audit_finding_over_workspace_copy(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    audit_path = tmp_path / "run" / "audit.db"
    audit = AuditStore(audit_path)
    try:
        audit.record_finding_payload(
            finding_id="finding-1",
            engagement_id=UUID("88888888-8888-4888-8888-888888888888"),
            vuln_class="sql_injection",
            status="confirmed",
            validator_vote="confirm",
            payload={
                "finding_id": "finding-1",
                "vuln_class": "sql_injection",
                "status": "confirmed",
                "endpoint": {
                    "url": "http://127.0.0.1:8765/search",
                    "method": "GET",
                    "params": [{"name": "q", "location": "query"}],
                },
                "hypothesis": "Authoritative audit finding.",
                "exploit_steps": [{"indicator": "paired executor replay"}],
                "proof": {
                    "http_request_final": "GET /search?q=%27 HTTP/1.1",
                    "response_final": "SQLite syntax error",
                    "impact_description": "Database error behavior was confirmed.",
                },
            },
        )
    finally:
        audit.close()

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=tmp_path / "run" / "audit-first-report.md",
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert len(report["findings"]) == 1
    assert report["findings"][0]["hypothesis"] == "Authoritative audit finding."


def test_report_ignores_same_scope_findings_from_other_engagements(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = tmp_path / "run" / "audit.db"
    current_engagement_id = UUID("88888888-8888-4888-8888-888888888888")
    other_engagement_id = UUID("99999999-9999-4999-8999-999999999999")
    audit = AuditStore(audit_path)
    try:
        for finding_id, engagement_id, hypothesis in (
            ("finding-current", current_engagement_id, "Current engagement finding."),
            ("finding-other", other_engagement_id, "Other engagement finding."),
        ):
            audit.record_finding_payload(
                finding_id=finding_id,
                engagement_id=engagement_id,
                vuln_class="sql_injection",
                status="confirmed",
                validator_vote="confirm",
                payload={
                    "finding_id": finding_id,
                    "vuln_class": "sql_injection",
                    "status": "confirmed",
                    "endpoint": {
                        "url": "http://127.0.0.1:8765/search",
                        "method": "GET",
                        "params": [{"name": "q", "location": "query"}],
                    },
                    "hypothesis": hypothesis,
                    "exploit_steps": [{"indicator": "paired executor replay"}],
                    "proof": {
                        "http_request_final": "GET /search?q=%27 HTTP/1.1",
                        "response_final": "SQLite syntax error",
                        "impact_description": "Database error behavior was confirmed.",
                    },
                },
            )
    finally:
        audit.close()

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=tmp_path / "run" / "engagement-filtered-report.md",
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert [finding["finding_id"] for finding in report["findings"]] == ["finding-current"]
    assert report["findings"][0]["hypothesis"] == "Current engagement finding."


def test_report_only_uses_current_in_scope_workspace_findings(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    current = _confirmed_finding_payload(
        finding_id="finding-current",
        vuln_class="sql_injection",
        severity="High",
    )
    stale = _confirmed_finding_payload(
        finding_id="finding-stale",
        vuln_class="sql_injection",
        severity="High",
    )
    stale["engagement_id"] = "99999999-9999-4999-8999-999999999999"
    legacy = _confirmed_finding_payload(
        finding_id="finding-legacy-unscoped",
        vuln_class="sql_injection",
        severity="High",
    )
    legacy.pop("engagement_id")
    outside = _confirmed_finding_payload(
        finding_id="finding-outside-scope",
        vuln_class="sql_injection",
        severity="High",
    )
    outside["endpoint"] = {
        "url": "http://127.0.0.1:9999/debug",
        "method": "GET",
        "params": [],
    }
    for payload in (current, stale, legacy, outside):
        workspace.record_event(kind="finding_confirmed", payload=payload)

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=tmp_path / "run" / "scope-filtered-report.md",
        status="completed",
        completed=True,
    )

    assert [finding["finding_id"] for finding in report["findings"]] == ["finding-current"]
    assert "parameterized queries" in report["findings"][0]["recommendation"]


def test_incomplete_report_retains_confirmed_finding_and_remediation(
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.record_event(
        kind="finding_confirmed",
        payload=_confirmed_finding_payload(
            finding_id="finding-before-budget-stop",
            vuln_class="xss",
            severity="Medium",
        ),
    )
    output_path = tmp_path / "run" / "incomplete-report.md"

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="incomplete",
        completed=False,
    )

    assert report["status"] == "incomplete"
    assert report["completed"] is False
    assert report["executive_summary"]["finding_count"] == 1
    assert "output encoding" in report["findings"][0]["recommendation"]
    markdown = output_path.read_text(encoding="utf-8")
    assert "Results should be treated as partial" in markdown
    assert "Recommendation:" in markdown


def test_write_pentest_report_pdf_suffix_requires_pro_package(tmp_path: Path) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    output_path = tmp_path / "run" / "pentest-report.pdf"

    with pytest.raises(ProFeatureRequiredError):
        write_pentest_report(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            workspace_dir=workspace.root,
            output_path=output_path,
            status="completed",
            completed=True,
        )

    assert not output_path.exists()


def test_write_pentest_report_pdf_suffix_delegates_to_pro_renderer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    output_path = tmp_path / "run" / "pentest-report.pdf"
    pro_package = ModuleType("ravage_pro")
    pro_report = ModuleType("ravage_pro.report")

    def write_professional_report(
        *,
        report: dict[str, object],
        markdown: str,
        output_path: Path,
    ) -> dict[str, str]:
        assert report["schema_version"]
        assert "# Web Application Penetration Test Report" in markdown
        output_path.write_bytes(b"%PDF-1.4\n% pro renderer\n")
        return {"professional_report_path": str(output_path), "report_tier": "pro"}

    pro_report.__dict__["write_professional_report"] = write_professional_report
    monkeypatch.setitem(sys.modules, "ravage_pro", pro_package)
    monkeypatch.setitem(sys.modules, "ravage_pro.report", pro_report)

    report = write_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        workspace_dir=workspace.root,
        output_path=output_path,
        status="completed",
        completed=True,
    )

    assert output_path.read_bytes().startswith(b"%PDF-1.4")
    assert output_path.with_suffix(".md").exists()
    assert output_path.with_suffix(".json").exists()
    assert report["artifacts"]["report_tier"] == "pro"


def test_cli_report_command_writes_report_for_existing_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    output_path = tmp_path / "run" / "cli-report.md"

    cli.main(
        [
            "report",
            str(workspace.root.parent),
            "--brief",
            str(brief_path),
            "--output",
            str(output_path),
        ]
    )

    assert output_path.exists()
    assert "report written" in capsys.readouterr().out


@pytest.mark.parametrize("location", ["run", "workspace", "manifest", "manifest_relative"])
@pytest.mark.parametrize("workspace_argument", [False, True])
def test_cli_report_resolves_audit_only_evidence_without_mutating_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
    *,
    workspace_argument: bool,
) -> None:
    brief_path = _brief(tmp_path)
    workspace_dir = tmp_path / "run" / "workspace"
    workspace_dir.mkdir(parents=True)
    run_dir = workspace_dir.parent
    if location == "run":
        audit_path = run_dir / "audit.db"
    elif location == "workspace":
        audit_path = workspace_dir / "audit.db"
    else:
        # Literal URI-reserved characters must not hide audit-only captured proofs.
        audit_path = tmp_path / "custom" / "audit?literal#source.db"
        if location == "manifest_relative":
            monkeypatch.chdir(tmp_path)
            audit_path = audit_path.relative_to(tmp_path)
        (run_dir / "run.json").write_text(
            json.dumps({"run_id": "custom-audit", "db_path": str(audit_path)}),
            encoding="utf-8",
        )
        # A healthy default cannot take precedence over the declared source.
        AuditStore(run_dir / "audit.db").close()
    _seed_audit_only_proof(audit_path)
    original_database = audit_path.read_bytes()
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)
    output_path = run_dir / "report.json"

    cli.main(
        [
            "report",
            str(workspace_dir if workspace_argument else run_dir),
            "--brief",
            str(brief_path),
            "--output",
            str(output_path),
        ]
    )

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["source_quality"]["audit_db_path"] == str(audit_path)
    assert report["source_quality"]["status"] == "complete"
    assert report["source_quality"]["audit_log_source"]["status"] == "available"
    assert report["captured_proofs"]["count"] == 1
    assert report["outcome"]["stage"] == "flag_captured"
    assert report["executive_summary"]["overall_risk"] == "High"
    assert audit_path.read_bytes() == original_database


def test_cli_report_does_not_fallback_from_declared_missing_audit_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    brief_path = _brief(tmp_path)
    workspace_dir = tmp_path / "run" / "workspace"
    workspace_dir.mkdir(parents=True)
    run_dir = workspace_dir.parent
    missing_path = tmp_path / "declared-but-missing.db"
    (run_dir / "run.json").write_text(
        json.dumps({"run_id": "missing-audit", "db_path": str(missing_path)}),
        encoding="utf-8",
    )
    _seed_audit_only_proof(run_dir / "audit.db")
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)

    cli.main(["report", str(run_dir), "--brief", str(brief_path)])

    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["source_quality"]["audit_db_path"] == str(missing_path)
    assert report["source_quality"]["status"] == "incomplete"
    assert report["source_quality"]["audit_source"]["status"] == "missing"
    assert report["captured_proofs"]["count"] == 0
    assert report["executive_summary"]["overall_risk"] == "Unknown"
    assert not missing_path.exists()


@pytest.mark.parametrize("audit_location", ["run", "workspace"])
@pytest.mark.parametrize("recorded_absolute", [False, True])
@pytest.mark.parametrize("source_present", [False, True])
def test_cli_report_relocates_declared_internal_audit_paths_after_cwd_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_location: str,
    *,
    recorded_absolute: bool,
    source_present: bool,
) -> None:
    brief_path = _brief(tmp_path)
    run_dir = tmp_path / "relocated" / "run"
    workspace_dir = run_dir / "workspace"
    workspace_dir.mkdir(parents=True)
    recorded_workspace = Path("runs/original/workspace")
    if recorded_absolute:
        recorded_workspace = tmp_path / "original-cwd" / recorded_workspace
    recorded_root = (
        recorded_workspace if audit_location == "workspace" else recorded_workspace.parent
    )
    actual_root = workspace_dir if audit_location == "workspace" else run_dir
    audit_suffix = Path("state/evidence?literal#source.db")
    audit_path = actual_root / audit_suffix
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_id": "original",
                "workspace_dir": str(recorded_workspace),
                "db_path": str(recorded_root / audit_suffix),
            }
        ),
        encoding="utf-8",
    )
    # A default containing proof must never substitute for a declared missing source.
    _seed_audit_only_proof(run_dir / "audit.db")
    if source_present:
        _seed_audit_only_proof(audit_path)
    other_cwd = tmp_path / "unrelated-cwd"
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)

    cli.main(["report", str(run_dir), "--brief", str(brief_path)])

    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["source_quality"]["audit_db_path"] == str(audit_path)
    assert report["source_quality"]["status"] == ("complete" if source_present else "incomplete")
    assert report["captured_proofs"]["count"] == int(source_present)
    assert audit_path.exists() is source_present


def test_cli_report_keeps_missing_external_relative_audit_path_declared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    brief_path = _brief(tmp_path)
    run_dir = tmp_path / "relocated" / "run"
    workspace_dir = run_dir / "workspace"
    workspace_dir.mkdir(parents=True)
    declared_path = Path("external/custom-audit.db")
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_id": "original",
                "workspace_dir": "runs/original/workspace",
                "db_path": str(declared_path),
            }
        ),
        encoding="utf-8",
    )
    _seed_audit_only_proof(run_dir / "audit.db")
    other_cwd = tmp_path / "unrelated-cwd"
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)

    cli.main(["report", str(run_dir), "--brief", str(brief_path)])

    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["source_quality"]["audit_db_path"] == str(declared_path)
    assert report["source_quality"]["status"] == "incomplete"
    assert report["source_quality"]["audit_source"]["status"] == "missing"
    assert report["captured_proofs"]["count"] == 0
    assert not declared_path.exists()


def test_cli_report_preserves_legitimate_events_only_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    monkeypatch.setattr(report_module, "_run_hosting_layer_report_agent", lambda **_: None)

    cli.main(["report", str(workspace.root), "--brief", str(brief_path)])

    report = json.loads((workspace.root.parent / "report.json").read_text(encoding="utf-8"))
    assert report["source_quality"]["audit_source"]["status"] == "not_requested"
    assert report["source_quality"]["audit_log_source"]["status"] == "not_requested"
    assert report["source_quality"]["status"] == "complete"
    assert not (workspace.root.parent / "audit.db").exists()
    assert not (workspace.root / "audit.db").exists()


def test_cli_report_pdf_requires_pro_before_rendering(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _brief(tmp_path)
    workspace = _workspace_with_report_events(tmp_path)
    output_path = tmp_path / "run" / "cli-report.pdf"

    with pytest.raises(SystemExit):
        cli.main(
            [
                "report",
                str(workspace.root.parent),
                "--brief",
                str(brief_path),
                "--output",
                str(output_path),
            ]
        )

    assert "requires Ravage Pro" in capsys.readouterr().err
    assert not output_path.exists()


def test_cli_ai_web_report_flag_sets_report_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = _brief(tmp_path)
    report_path = tmp_path / "run" / "report.md"
    captured: dict[str, object] = {}

    def fake_run_ai_web_agent(
        *,
        brief_path: Path,
        target_url: str,
        settings: AIWebAgentSettings,
    ) -> None:
        captured["brief_path"] = brief_path
        captured["target_url"] = target_url
        captured["settings"] = settings

    monkeypatch.setattr(cli, "run_ai_web_agent", fake_run_ai_web_agent)

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
    assert isinstance(settings, AIWebAgentSettings)
    assert settings.report_agent is True
    assert settings.report_path == report_path


def _brief(tmp_path: Path) -> Path:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    return brief_path


def _add_agent_http_provenance(
    workspace: Path,
    *,
    target_url: str = "http://127.0.0.1:8765",
    in_scope: tuple[str, ...] = _REPORT_IN_SCOPE,
    out_of_scope: tuple[str, ...] = _REPORT_OUT_OF_SCOPE,
) -> tuple[Path, str, tuple[str, ...], tuple[str, ...]]:
    graph_workspace = workspace / "autonomous-route" / "agent-graph"
    capture_session_id = "agent-http-report-session"
    store = TrafficStore.create(graph_workspace)
    write_traffic_manifest(
        graph_workspace,
        TrafficRunManifest.create(
            target_url=target_url,
            capture_session_id=capture_session_id,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ).complete(),
    )
    blackboard = EvidenceBlackboard(
        target_url=target_url,
        state_path=graph_workspace / "evidence-blackboard.json",
    )
    blackboard.record_action_result(
        producer_node_id="node-http-report",
        action={"action": "http_request", "method": "GET", "url": "/proof"},
        result=ActionResult(
            ok=True,
            observation=f"target returned {_AGENT_HTTP_SECRET}",
            outcome="flag_candidate",
            flag=_AGENT_HTTP_SECRET,
            evidence_source_kind="tool_http_request",
            evidence_observation=f"target returned {_AGENT_HTTP_SECRET}",
        ),
        observation_id=_AGENT_HTTP_OBSERVATION_ID,
    )
    stored = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id=capture_session_id,
            source="agent_http",
            source_observation_id=_AGENT_HTTP_OBSERVATION_ID,
            method="GET",
            url=(f"{target_url}/proof?token={_AGENT_HTTP_SECRET}"),
            request_headers={"Authorization": f"Bearer {_AGENT_HTTP_SECRET}"},
            request_sent=True,
            response_status=200,
            response_final_url=f"{target_url}/proof",
            response_headers={"Set-Cookie": f"proof={_AGENT_HTTP_SECRET}"},
            response_body=f"target returned {_AGENT_HTTP_SECRET}",
            scope_decision="allowed",
            known_secrets=(_AGENT_HTTP_SECRET,),
        )
    )
    records = tuple(
        record
        for record in sorted(
            blackboard.state.records.values(),
            key=lambda item: item.sequence,
        )
        if record.observation_id == _AGENT_HTTP_OBSERVATION_ID
    )
    return (
        graph_workspace,
        stored.exchange_id,
        tuple(record.evidence_id for record in records),
        tuple(record.evidence_id for record in records if record.material),
    )


def _add_deterministic_scan_traffic(workspace: Path) -> None:
    capture_session_id = "deterministic-report-session"
    store = TrafficStore.create(workspace)
    manifest = TrafficRunManifest.create(
        target_url="http://127.0.0.1:8765",
        capture_session_id=capture_session_id,
        in_scope=_REPORT_IN_SCOPE,
        out_of_scope=_REPORT_OUT_OF_SCOPE,
    )
    write_traffic_manifest(workspace, manifest.complete())
    for path, status in (("/", 200), ("/admin", 403)):
        store.append_exchange(
            build_captured_http_exchange(
                capture_session_id=capture_session_id,
                source="probe_session",
                method="GET",
                url=f"http://127.0.0.1:8765{path}",
                request_sent=True,
                response_status=status,
                response_final_url=f"http://127.0.0.1:8765{path}",
                response_body="bounded response",
                scope_decision="allowed",
            )
        )


def _confirmed_finding_payload(
    *,
    finding_id: str,
    vuln_class: str,
    severity: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "finding_id": finding_id,
        "engagement_id": "88888888-8888-4888-8888-888888888888",
        "vuln_class": vuln_class,
        "severity": severity,
        "endpoint": {
            "url": "http://127.0.0.1:8765/test",
            "method": "POST",
            "params": [{"name": "input", "location": "body"}],
        },
        "hypothesis": f"Evidence-backed {vuln_class} behavior was reproduced.",
        "exploit_steps": [{"indicator": "executor-observed differential"}],
        "proof": {
            "http_request_final": "POST /test HTTP/1.1",
            "response_final": "executor-observed confirmation marker",
            "impact_description": "The vulnerable behavior was confirmed.",
        },
        "status": "confirmed",
        "validator_vote": "confirm",
    }
    return payload


def _workspace_with_report_events(tmp_path: Path) -> AgentWorkspace:
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.record_event(
        kind="agent_started",
        payload={"target_url": "http://127.0.0.1:8765"},
    )
    workspace.record_event(
        kind="recon_completed",
        payload={
            "target_url": "http://127.0.0.1:8765",
            "origin": "http://127.0.0.1:8765",
            "pages": [
                {
                    "url": "http://127.0.0.1:8765/search",
                    "status": 200,
                    "forms": [{"method": "GET", "action": "/search", "inputs": []}],
                }
            ],
            "query_parameter_names": ["q"],
            "interesting_markers": ["sql"],
            "errors": [],
        },
    )
    workspace.record_event(
        kind="action_started",
        payload={
            "action_id": "action-1",
            "turn": 1,
            "action_kind": "run_probe",
            "summary": "Run probe sqli",
            "detail": "sql injection validation",
            "params": {"probe": "sqli"},
        },
    )
    workspace.record_event(
        kind="tool_run_probe",
        payload={
            "action_id": "action-1",
            "observation_id": "observation-1",
            "ok": True,
            "recognized_proofs": ["flag{unit_report_secret}"],
            "timed_out": False,
            "result": json.dumps(
                {
                    "ok": True,
                    "probe": "sqli",
                    "summary": "found proof flag{unit_report_secret}",
                    "findings": [
                        {
                            "type": "direct_exposure_proof",
                            "proofs": ["flag{unit_report_secret}"],
                        }
                    ],
                }
            ),
        },
    )
    workspace.record_event(
        kind="finding_confirmed",
        payload={
            "finding_id": "finding-1",
            "engagement_id": "88888888-8888-4888-8888-888888888888",
            "vuln_class": "sql_injection",
            "endpoint": {
                "url": "http://127.0.0.1:8765/search?q=test",
                "method": "GET",
                "params": [],
            },
            "hypothesis": "Search parameter q changes SQL result shape.",
            "exploit_steps": [
                {
                    "http_request": "GET /search?q=' OR 1=1-- HTTP/1.1",
                    "response_snippet": (
                        "api_key=sk-ABCDEF1234567890ABCDEF flag{unit_report_secret}"
                    ),
                    "indicator": "expanded result set",
                }
            ],
            "proof": {
                "http_request_final": "GET /search?q=' OR 1=1-- HTTP/1.1",
                "response_final": "api_key=sk-ABCDEF1234567890ABCDEF flag{unit_report_secret}",
                "impact_description": "Unauthenticated SQL injection exposed data.",
            },
            "status": "confirmed",
            "validator_vote": "confirm",
        },
    )
    workspace.record_event(
        kind="flag_captured",
        payload={
            "flag": "flag{unit_report_secret}",
            "evidence": "response api_key=sk-ABCDEF1234567890ABCDEF",
            "engagement_id": "88888888-8888-4888-8888-888888888888",
            "source_observation_id": "observation-1",
            "source_kind": "tool_run_probe",
            "action_id": "action-1",
        },
    )
    return workspace
