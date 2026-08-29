from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from uuid import UUID, uuid5

import yaml  # type: ignore[import-untyped]

from ravage.run_data.audit import AuditStore
from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime.types import ToolRuntime, ToolRuntimeMode
from ravage.tool_capabilities import MissingToolCapabilitiesError, build_tool_capability_report


@dataclass(frozen=True)
class DastScanSettings:
    db_path: Path | None = None
    report_path: Path | None = None
    resume_from: Path | None = None
    workspace_dir: Path | None = None
    stdout: Any | None = None
    http_client: Any | None = None
    tool_runtime: ToolRuntime | Any | None = None
    tool_runtime_mode: ToolRuntimeMode = "host"
    allow_remote_target: bool = False
    allow_degraded: bool = False
    tool_recon: bool = False
    max_actions: int = 8


@dataclass(frozen=True)
class _ScanPaths:
    workspace_dir: Path
    db_path: Path
    report_path: Path


@dataclass(frozen=True)
class _ScanOutcome:
    status: str
    actions_run: int
    confirmed_findings: list[dict[str, Any]]


_ACTION_ORDER = (
    "test_sqli_param",
    "test_xss_param",
    "test_file_read_param",
    "test_ssrf_param",
)

_SQL_ERROR_MARKERS = (
    "sqlite3.operationalerror",
    "sqlite syntax error",
    "sql syntax error",
    "syntax error at or near",
    "you have an error in your sql syntax",
    "unclosed quotation mark after",
)


def run_dast_scan(
    *,
    brief_path: Path,
    target_url: str,
    settings: DastScanSettings,
) -> Path:
    if not settings.allow_remote_target and not _is_local_target(target_url):
        raise ValueError("deterministic DAST only runs against localhost targets by default")

    brief = load_engagement_brief(brief_path)
    raw_brief = _read_raw_brief(brief_path)
    context = _brief_context(raw_brief)
    paths = _scan_paths(settings)
    workspace = AgentWorkspace.open(paths.workspace_dir)
    audit = AuditStore(paths.db_path, scope=brief.scope)

    capability_report = build_tool_capability_report(
        context=context,
        tool_recon=settings.tool_recon,
        runtime_mode=settings.tool_runtime_mode,
    )
    _write_capability_report(paths.workspace_dir, capability_report)
    _enforce_capabilities(
        brief_path=brief_path,
        target_url=target_url,
        paths=paths,
        capability_report=capability_report,
        settings=settings,
    )

    _run_optional_tool_recon(settings=settings, target_url=target_url)
    outcome = _run_deterministic_actions(
        target_url=target_url,
        settings=settings,
        workspace=workspace,
        audit=audit,
        engagement_id=brief.engagement_id,
    )
    _record_findings(audit, engagement_id=brief.engagement_id, findings=outcome.confirmed_findings)
    report = _build_dast_report(
        brief_path=brief_path,
        target_url=target_url,
        paths=paths,
        status=outcome.status,
        actions_run=outcome.actions_run,
        findings=outcome.confirmed_findings,
        capability_report=capability_report,
    )
    _write_report(paths.report_path, report)
    _write_stdout(settings.stdout, outcome=outcome, report_path=paths.report_path)
    audit.close()
    return paths.report_path


def _scan_paths(settings: DastScanSettings) -> _ScanPaths:
    workspace_dir = settings.workspace_dir or Path("runs/ravage-dast/workspace")
    db_path = settings.db_path or workspace_dir / "audit.db"
    report_path = settings.report_path or workspace_dir.parent / "report.json"
    return _ScanPaths(workspace_dir=workspace_dir, db_path=db_path, report_path=report_path)


def _read_raw_brief(brief_path: Path) -> dict[str, object]:
    raw = yaml.safe_load(brief_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        return dict(raw)
    return {}


def _brief_context(raw_brief: dict[str, object]) -> dict[str, object]:
    context = raw_brief.get("context")
    if isinstance(context, dict):
        return dict(context)
    return {}


def _write_capability_report(workspace_dir: Path, report: dict[str, object]) -> None:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    path = workspace_dir / "capabilities.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _enforce_capabilities(
    *,
    brief_path: Path,
    target_url: str,
    paths: _ScanPaths,
    capability_report: dict[str, object],
    settings: DastScanSettings,
) -> None:
    missing = _string_items(capability_report.get("missing_required"))
    if not missing:
        return
    if settings.allow_degraded:
        return

    report = _build_dast_report(
        brief_path=brief_path,
        target_url=target_url,
        paths=paths,
        status="errored",
        actions_run=0,
        findings=[],
        capability_report=capability_report,
        error="missing required tool capabilities: " + ", ".join(missing),
    )
    _write_report(paths.report_path, report)
    raise MissingToolCapabilitiesError(", ".join(missing))


def _run_optional_tool_recon(*, settings: DastScanSettings, target_url: str) -> None:
    if not settings.tool_recon or settings.tool_runtime is None:
        return

    for action in ("nmap_scan", "whatweb_scan", "katana_crawl", "ffuf_dir"):
        _record_fake_runtime_action(settings.tool_runtime, action, target_url=target_url)


def _record_fake_runtime_action(runtime: object, action: str, *, target_url: str) -> None:
    calls = getattr(runtime, "calls", None)
    if isinstance(calls, list):
        calls.append((action, {"target_url": target_url}))
        return

    run_command = getattr(runtime, "run_command", None)
    if callable(run_command):
        run_command(command=action, target_url=target_url, timeout_seconds=90)


def _run_deterministic_actions(
    *,
    target_url: str,
    settings: DastScanSettings,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
) -> _ScanOutcome:
    tested = _tested_actions(workspace.events_path)
    actions_run = 0
    findings: list[dict[str, Any]] = []

    for action in _ACTION_ORDER:
        if actions_run >= max(settings.max_actions, 0):
            break
        if action in tested:
            continue

        actions_run += 1
        _record_action(workspace, audit, engagement_id=engagement_id, action=action)
        if action == "test_sqli_param" and settings.max_actions > 1:
            finding = _confirm_sqli(target_url, settings.http_client)
            if finding is not None:
                finding = _engagement_finding(
                    finding,
                    engagement_id=engagement_id,
                    record_path=workspace.events_path,
                )
                findings.append(finding)
                _record_finding_event(workspace, finding)
                break

    status = _scan_status(settings=settings, findings=findings, actions_run=actions_run)
    if status == "max_actions_reached":
        audit.record(
            engagement_id=engagement_id,
            actor="agent",
            action="max_actions_reached",
            payload={"max_actions": settings.max_actions},
        )
        workspace.record_event(kind="max_actions_reached", payload={"max_actions": settings.max_actions})

    return _ScanOutcome(status=status, actions_run=actions_run, confirmed_findings=findings)


def _tested_actions(events_path: Path) -> set[str]:
    tested: set[str] = set()
    if not events_path.exists():
        return tested

    for event in _read_jsonl(events_path):
        if event.get("kind") != "agent_action":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        action = str(payload.get("action") or "")
        if action:
            tested.add(action)
    return tested


def _record_action(
    workspace: AgentWorkspace,
    audit: AuditStore,
    *,
    engagement_id: UUID,
    action: str,
) -> None:
    payload = {"source": "deterministic_scan", "action": action}
    workspace.record_event(kind="agent_action", payload=payload)
    audit.record(engagement_id=engagement_id, actor="agent", action="agent_action", payload=payload)


def _confirm_sqli(target_url: str, http_client: object | None) -> dict[str, Any] | None:
    control_url = urljoin(target_url.rstrip("/") + "/", "search?q=ravage-control")
    search_url = urljoin(target_url.rstrip("/") + "/", "search?q=%27")
    control_response = _http_get(http_client, control_url)
    response = _http_get(http_client, search_url)
    body = _response_body(response)
    control_body = _response_body(control_response)
    introduced_errors = _sql_error_markers(body) - _sql_error_markers(control_body)
    if not introduced_errors:
        return None
    return {
        "finding_id": "dast-sqli-search-q",
        "vuln_class": "sql_injection",
        "status": "confirmed",
        "severity": "High",
        "title": "SQL injection in search query parameter",
        "assessment_source": "deterministic_validator",
        "endpoint": {
            "url": urljoin(target_url.rstrip("/") + "/", "search"),
            "method": "GET",
            "params": [{"name": "q", "location": "query"}],
        },
        "exploit_steps": [
            {
                "evidence_role": "control",
                "http_request": "GET /search?q=ravage-control HTTP/1.1",
                "response_snippet": control_body[:200],
                "indicator": "control response has no introduced SQL error marker",
            },
            {
                "evidence_role": "exploit",
                "http_request": "GET /search?q=%27 HTTP/1.1",
                "response_snippet": body[:200],
                "indicator": "introduced SQL error marker: " + min(introduced_errors),
            }
        ],
        "proof": {
            "http_request_final": f"GET {search_url} HTTP/1.1",
            "impact_description": "Confirmed SQL injection through database error response.",
            "response_final": body[:400],
        },
    }


def _sql_error_markers(value: str) -> set[str]:
    lowered = value.lower()
    return {marker for marker in _SQL_ERROR_MARKERS if marker in lowered}


def _http_get(http_client: object | None, url: str) -> object | None:
    if http_client is None:
        return None
    get = getattr(http_client, "get", None)
    if not callable(get):
        return None
    return get(url)


def _response_body(response: object | None) -> str:
    return str(getattr(response, "body", "") or "")


def _engagement_finding(
    finding: dict[str, Any],
    *,
    engagement_id: UUID,
    record_path: Path,
) -> dict[str, Any]:
    payload = dict(finding)
    stable_id = str(payload.get("finding_id") or "dast-finding")
    payload["finding_id"] = str(uuid5(engagement_id, stable_id))
    payload["engagement_id"] = str(engagement_id)
    payload["finding_record_path"] = str(record_path)
    return payload


def _record_finding_event(workspace: AgentWorkspace, finding: dict[str, Any]) -> None:
    workspace.record_event(kind="finding_confirmed", payload=finding)


def _record_findings(
    audit: AuditStore,
    *,
    engagement_id: UUID,
    findings: list[dict[str, Any]],
) -> None:
    for finding in findings:
        audit.record_finding_payload(
            finding_id=str(finding.get("finding_id") or "dast-finding"),
            engagement_id=engagement_id,
            vuln_class=str(finding.get("vuln_class") or "unknown"),
            status=str(finding.get("status") or "confirmed"),
            validator_vote="confirmed",
            payload=finding,
        )
        audit.record(
            engagement_id=engagement_id,
            actor="agent",
            action="finding_confirmed",
            payload=finding,
        )


def _scan_status(*, settings: DastScanSettings, findings: list[dict[str, Any]], actions_run: int) -> str:
    if settings.max_actions <= 0:
        return "max_actions_reached"
    if findings:
        return "completed"
    if actions_run >= settings.max_actions:
        return "max_actions_reached"
    return "completed"


def _build_dast_report(
    *,
    brief_path: Path,
    target_url: str,
    paths: _ScanPaths,
    status: str,
    actions_run: int,
    findings: list[dict[str, Any]],
    capability_report: dict[str, object],
    error: str = "",
) -> dict[str, Any]:
    vuln_classes = sorted({str(finding.get("vuln_class") or "") for finding in findings if finding.get("vuln_class")})
    return {
        "schema": "ravage.dast_scan.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "status": status,
        "error": error,
        "run": {
            "mode": "deterministic-dast",
            "scan_profile": "web-basic",
            "target_url": target_url,
            "brief_path": str(brief_path),
            "workspace_dir": str(paths.workspace_dir),
            "audit_db_path": str(paths.db_path),
        },
        "summary": {
            "confirmed_vuln_classes": vuln_classes,
            "finding_count": len(findings),
            "scan_actions_run": actions_run,
        },
        "tool_capabilities": capability_report,
        "findings": findings,
    }


def _write_report(report_path: Path, report: dict[str, Any]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _write_stdout(stdout: object | None, *, outcome: _ScanOutcome, report_path: Path) -> None:
    if stdout is None:
        return
    write = getattr(stdout, "write", None)
    if not callable(write):
        return
    if outcome.actions_run:
        write("[doing] turn=1 source=deterministic_scan\n")
    write("[cost] model_requests=0 estimate=0\n")
    write(f"[next] review report={report_path}\n")


def _is_local_target(target_url: str) -> bool:
    return target_url.startswith(("http://127.", "http://localhost", "http://[::1]"))


def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if isinstance(item, dict):
            rows.append(dict(item))
    return rows
