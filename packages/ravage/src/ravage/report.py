from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from datetime import UTC, datetime
from importlib import import_module
from typing import TYPE_CHECKING, Any, Self, cast

from ravage.finding_evidence import confirmed_finding_evidence_failures
from ravage.hosting_layer import HOSTING_LAYER_EVENT_KIND, run_configured_hosting_layer_agent
from ravage.outcome_evidence import load_run_outcome, load_validated_captured_flags
from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.run_manifest import read_manifest
from ravage.traffic.manifest import (
    TrafficRunError,
    read_traffic_manifest,
    resolve_workspace,
)
from ravage.traffic.policy import TrafficPolicyError, load_traffic_policy_snapshot
from ravage.traffic.provenance import TrafficProvenanceError, load_traffic_provenance
from ravage.traffic.store import TrafficStore, TrafficStoreError

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from pentest_schemas import EngagementBrief, Scope

REPORT_SCHEMA_VERSION = "2026-08-25"
PRO_REPORT_MODULE = "ravage_pro.report"
PRO_REPORT_SUFFIXES = frozenset({".pdf", ".docx"})
CORE_REPORT_SUFFIXES = frozenset({"", ".md", ".json"})

_PROOF_RE = re.compile(r"\b(?:flag|FLAG|HTB|CTF)\{[^}\r\n]{1,512}\}")
_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd)"
        r"(\s*[=:]\s*)(\"?)([^\"'&\s,;]+)(\"?)"
    ),
    re.compile(r"(?i)\b(authorization)(\s*:\s*)(\"?)(bearer\s+)?([^\"'\s,;]+)(\"?)"),
)

_MIN_SECRET_REPLACEMENT_GROUPS = 5
_GRAPH_MARKER_MAX_BYTES = 262_144
_PRIVATE_HTTP_STATE_VERSION = 2

_SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
}

_VULN_SEVERITY = {
    "auth_bypass": "Critical",
    "command_injection": "Critical",
    "insecure_deserialization": "Critical",
    "sql_injection": "High",
    "blind_sqli": "High",
    "file_upload": "High",
    "idor": "High",
    "jwt": "High",
    "lfi": "High",
    "path_traversal": "High",
    "ssrf": "High",
    "xxe": "High",
    "business_logic": "Medium",
    "graphql": "Medium",
    "http_request_smuggling": "Medium",
    "xss": "Medium",
    "information_disclosure": "Low",
}

_REMEDIATIONS = {
    "auth_bypass": (
        "Enforce server-side authorization checks on every protected action and "
        "remove trust in client-controlled identity signals."
    ),
    "command_injection": (
        "Avoid shell execution for user-controlled input; use allowlisted arguments, "
        "structured APIs, and strict escaping where execution is unavoidable."
    ),
    "file_upload": (
        "Validate uploaded file type and content, store uploads outside the web root, "
        "randomize names, and disable script execution in upload paths."
    ),
    "idor": (
        "Authorize every object access against the authenticated principal before "
        "returning or mutating data."
    ),
    "jwt": (
        "Use strong signing keys, reject algorithm confusion, validate all claims, "
        "and rotate exposed secrets."
    ),
    "lfi": (
        "Normalize paths, enforce an allowlist of readable files, and keep user input "
        "out of filesystem joins."
    ),
    "path_traversal": (
        "Normalize and constrain requested paths to an allowlisted base directory "
        "before file access."
    ),
    "sql_injection": (
        "Use parameterized queries or safe ORM bindings for every database call and "
        "remove string-concatenated SQL."
    ),
    "ssrf": (
        "Validate outbound destinations with allowlists, block private/link-local "
        "ranges, and isolate metadata or internal services."
    ),
    "ssti": (
        "Do not render user input as templates; sandbox the engine and pass untrusted "
        "data only as escaped variables."
    ),
    "xss": (
        "Apply context-aware output encoding, sanitize HTML input, and enforce a "
        "restrictive Content Security Policy."
    ),
    "xxe": "Disable external entity resolution and DTD processing in XML parsers.",
}


class ProFeatureRequiredError(RuntimeError):
    """Raised when a report output requires a separately licensed Pro package."""

    def __init__(
        self,
        message: str = (
            ".pdf/.docx professional report export requires Ravage Pro. "
            "Install the proprietary ravage-pro package or write .md/.json from core."
        ),
    ) -> None:
        super().__init__(message)

    @classmethod
    def package_missing(cls) -> Self:
        msg = "professional report export requires the proprietary ravage-pro package"
        return cls(msg)

    @classmethod
    def missing_writer(cls) -> Self:
        msg = f"{PRO_REPORT_MODULE}.write_professional_report is not available"
        return cls(msg)


def write_pentest_report(  # noqa: PLR0913
    *,
    brief_path: Path,
    target_url: str,
    workspace_dir: Path,
    output_path: Path,
    status: str,
    completed: bool,
    audit_db_path: Path | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """
    Build and write a deterministic pentest report for a completed run.

    The primary output is selected by ``output_path``:
    - ``.md`` or no suffix writes Markdown and a sibling JSON summary.
    - ``.json`` writes JSON and a sibling Markdown report.
    - ``.pdf``/``.docx`` delegates to the optional Ravage Pro report package.
    """
    ensure_report_output_supported(output_path)
    _run_hosting_layer_report_agent(
        brief_path=brief_path,
        target_url=target_url,
        workspace_dir=workspace_dir,
    )
    report = build_pentest_report(
        brief_path=brief_path,
        target_url=target_url,
        workspace_dir=workspace_dir,
        status=status,
        completed=completed,
        audit_db_path=audit_db_path,
        error=error,
    )
    markdown = render_markdown_report(report)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    suffix = output_path.suffix.lower()
    json_path = output_path.with_suffix(".json")
    markdown_path = output_path.with_suffix(".md")
    pro_path: Path | None = None

    if suffix == ".json":
        json_path = output_path
    elif suffix in PRO_REPORT_SUFFIXES:
        pro_path = output_path
    else:
        markdown_path = output_path if suffix in {"", ".md"} else output_path.with_suffix(".md")

    report["artifacts"] = {
        "json_report_path": str(json_path),
        "markdown_report_path": str(markdown_path),
        "professional_report_path": str(pro_path) if pro_path else "",
    }

    markdown_path.write_text(markdown, encoding="utf-8")
    if pro_path is not None:
        report["artifacts"].update(
            _write_professional_report(report=report, markdown=markdown, output_path=pro_path)
        )
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def ensure_report_output_supported(output_path: Path) -> None:
    suffix = output_path.suffix.lower()
    if suffix in CORE_REPORT_SUFFIXES:
        return
    if suffix not in PRO_REPORT_SUFFIXES:
        msg = (
            f"unsupported report output suffix {suffix!r}; use .md/.json in core "
            "or .pdf/.docx with Ravage Pro"
        )
        raise ValueError(msg)
    if pro_report_available():
        return
    raise ProFeatureRequiredError


def pro_report_available() -> bool:
    return _load_pro_report_module() is not None


def _run_hosting_layer_report_agent(
    *,
    brief_path: Path,
    target_url: str,
    workspace_dir: Path,
) -> None:
    try:
        run_configured_hosting_layer_agent(
            brief_path=brief_path,
            target_url=target_url,
            workspace_dir=workspace_dir,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        # Hosting checks are an informational report appendage; never let DNS,
        # curl, or filesystem failures block the primary localhost assessment report.
        return


def _write_professional_report(
    *,
    report: dict[str, Any],
    markdown: str,
    output_path: Path,
) -> dict[str, str]:
    module = _load_pro_report_module()
    if module is None:
        raise ProFeatureRequiredError.package_missing()
    writer = getattr(module, "write_professional_report", None)
    if not callable(writer):
        raise ProFeatureRequiredError.missing_writer()
    result = writer(report=report, markdown=markdown, output_path=output_path)
    if isinstance(result, dict):
        return {str(key): str(value) for key, value in result.items()}
    return {"professional_report_path": str(output_path)}


def _load_pro_report_module() -> object | None:
    try:
        return import_module(PRO_REPORT_MODULE)
    except ModuleNotFoundError as exc:
        missing = str(exc.name or "")
        if missing == "ravage_pro" or missing.startswith("ravage_pro."):
            return None
        raise


def build_pentest_report(  # noqa: PLR0913
    *,
    brief_path: Path,
    target_url: str,
    workspace_dir: Path,
    status: str,
    completed: bool,
    audit_db_path: Path | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    brief = load_engagement_brief(brief_path)
    events, parse_errors, event_paths = _load_run_events(workspace_dir)
    manifest = read_manifest(workspace_dir.parent)
    flags = load_validated_captured_flags(
        db_path=audit_db_path,
        workspace_path=workspace_dir,
        engagement_id=brief.engagement_id,
    )
    findings = (
        _audit_findings(
            audit_db_path,
            scope=brief.scope,
            engagement_id=brief.engagement_id,
        )
        if audit_db_path is not None
        else []
    )
    findings.extend(
        _confirmed_findings(
            events,
            scope=brief.scope,
            engagement_id=brief.engagement_id,
        )
    )
    findings = _dedupe_findings(findings)
    outcome = load_run_outcome(
        db_path=audit_db_path,
        workspace_path=workspace_dir,
        engagement_id=brief.engagement_id,
    ).to_json()
    work = _work_performed(events)
    recon = _recon_summary(events)
    hosting_layer = _hosting_layer_summary(events)
    proof_observations = _proof_observations(events)
    severity_counts = _severity_counts(findings)
    overall_risk = _overall_risk(findings=findings, flags=flags, status=status)
    recommendations = _recommendations(findings=findings, flags=flags)

    generated_at = datetime.now(UTC).isoformat()
    target = target_url or _target_from_events(events) or (manifest.target_url if manifest else "")
    agent_http_evidence = _agent_http_evidence_summary(workspace_dir)
    traffic_accounting = _traffic_accounting_summary(workspace_dir)
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "status": status,
        "completed": completed,
        "error": redact_sensitive(error or ""),
        "run": {
            "workspace_dir": str(workspace_dir),
            "manifest_path": str(workspace_dir.parent / "run.json") if manifest else "",
            "run_id": manifest.run_id if manifest else "",
            "flag_found": bool(flags),
            "manifest_flag_found": bool(manifest.flag_found if manifest else False),
        },
        "engagement": _engagement_payload(brief, brief_path=brief_path, target_url=target),
        "executive_summary": {
            "overall_risk": overall_risk,
            "finding_count": len(findings),
            "captured_proof_count": len(flags),
            "outcome_stage": outcome["stage"],
            "outcome_evidence_count": outcome["evidence_count"],
            "summary": _executive_summary_text(
                status=status,
                completed=completed,
                overall_risk=overall_risk,
                finding_count=len(findings),
                flag_count=len(flags),
                error=error,
            ),
        },
        "reconnaissance": recon,
        "hosting_layer": hosting_layer,
        "findings": findings,
        "outcome": outcome,
        "severity_counts": severity_counts,
        "captured_proofs": {
            "count": len(flags),
            "masked": [_mask_proof(flag) for flag in flags],
            "handling": (
                "Exact proof strings and secret-shaped values are redacted from report artifacts."
            ),
        },
        "proof_observations": proof_observations,
        "traffic_accounting": traffic_accounting,
        "agent_http_evidence": agent_http_evidence,
        "work_performed": work,
        "methodology": _methodology(),
        "recommendations": recommendations,
        "limitations": _limitations(brief),
        "evidence_handling": [
            "Report artifacts redact target proof strings and common secret formats.",
            "Evidence is derived from workspace events and the audit database when available.",
            "The report does not expand truncated artifacts into full response bodies.",
        ],
        "source_quality": {
            "events_path": str(workspace_dir / "events.jsonl"),
            "event_paths": [str(path) for path in event_paths],
            "events_loaded": len(events),
            "event_parse_errors": parse_errors,
            "audit_db_path": str(audit_db_path) if audit_db_path else "",
        },
    }
    return cast("dict[str, Any]", _redact_recursive(report))


def render_markdown_report(report: dict[str, Any]) -> str:  # noqa: PLR0915
    engagement = _dict(report.get("engagement"))
    summary = _dict(report.get("executive_summary"))
    proofs = _dict(report.get("captured_proofs"))
    scope = _dict(engagement.get("scope"))
    rules = _dict(engagement.get("rules_of_engagement"))
    outcome = _dict(report.get("outcome"))
    traffic_accounting = _dict(report.get("traffic_accounting"))
    traffic_status = str(traffic_accounting.get("status") or "unavailable")
    physical_requests = traffic_accounting.get("physical_request_count")
    traffic_count = (
        str(physical_requests)
        if isinstance(physical_requests, int) and not isinstance(physical_requests, bool)
        else "unavailable"
    )
    lines: list[str] = [
        "# Web Application Penetration Test Report",
        "",
        f"Generated: {report.get('generated_at', '')}",
        f"Target: {engagement.get('target_url', '')}",
        f"Engagement ID: {engagement.get('engagement_id', '')}",
        f"Status: {report.get('status', '')}",
        f"Overall Risk: {summary.get('overall_risk', 'Informational')}",
        "",
        "## Executive Summary",
        "",
        str(summary.get("summary") or ""),
        "",
        f"- Confirmed findings: {summary.get('finding_count', 0)}",
        f"- Captured proof strings: {summary.get('captured_proof_count', 0)}",
        f"- Highest evidence-backed outcome: {summary.get('outcome_stage', 'none')}",
        f"- Physical target requests: {traffic_count}",
        f"- Request accounting status: {traffic_status}",
        f"- Completion status: {report.get('status', '')}",
        "",
        "## Scope and Engagement",
        "",
        f"- In-scope assets: {_join(_list(scope.get('in_scope')))}",
        f"- Out-of-scope assets: {_join(_list(scope.get('out_of_scope')))}",
        f"- Objectives: {_join(_list(engagement.get('objectives')))}",
        f"- Data handling: {rules.get('data_handling', '')}",
        f"- Destructive actions prohibited: {rules.get('no_destructive_actions', '')}",
        "",
        "## Methodology",
        "",
    ]
    lines.extend(f"- {item}" for item in _list(report.get("methodology")))
    lines.extend(["", "## Reconnaissance", ""])
    recon = _dict(report.get("reconnaissance"))
    lines.extend(
        [
            f"- Pages observed: {recon.get('page_count', 0)}",
            f"- Forms observed: {recon.get('form_count', 0)}",
            f"- Query parameters observed: {_join(_list(recon.get('query_parameter_names')))}",
            f"- Interesting markers: {_join(_list(recon.get('interesting_markers')))}",
            "",
        ]
    )
    hosting = _dict(report.get("hosting_layer"))
    if bool(hosting.get("enabled")):
        lines.extend(_hosting_layer_markdown(hosting))
    lines.extend(["## Findings", ""])
    findings = _list(report.get("findings"))
    if not findings:
        lines.extend(
            [
                "No confirmed vulnerability findings were recorded in the run artifacts.",
                "",
            ]
        )
    for index, item in enumerate(findings, start=1):
        finding = _dict(item)
        lines.extend(_finding_markdown(index, finding))

    suspected = [
        _dict(item)
        for item in _list(outcome.get("evidence"))
        if _dict(item).get("stage") == "suspected_vulnerability"
    ]
    if suspected:
        lines.extend(["## Suspected Vulnerabilities", ""])
        lines.append(
            "These candidates were retained for follow-up but did not satisfy the "
            "fail-closed confirmation contract."
        )
        lines.append("")
        for item in suspected:
            missing = _join(_list(item.get("missing_evidence")))
            lines.append(
                f"- {item.get('vuln_class', 'unknown')} via "
                f"{item.get('finding_type', 'unknown')} at "
                f"{item.get('endpoint_url', '')}; missing: {missing or 'confirmation evidence'}"
            )
        lines.append("")

    lines.extend(["## Captured Proofs", ""])
    if int(proofs.get("count") or 0) > 0:
        lines.append(
            "The agent captured target proof material. Exact proof strings are "
            "redacted in this report."
        )
        lines.extend(f"- {proof}" for proof in _list(proofs.get("masked")))
    else:
        lines.append("No target proof string was captured.")
    lines.extend(["", "## Agent HTTP Evidence", ""])
    lines.extend(_agent_http_evidence_markdown(_dict(report.get("agent_http_evidence"))))
    lines.extend(["", "## Work Performed", ""])
    work = _list(report.get("work_performed"))
    if work:
        lines.extend(["| Turn | Action | Detail | Outcome |", "| --- | --- | --- | --- |"])
        for item in work[:40]:
            row = _dict(item)
            lines.append(
                "| "
                + " | ".join(
                    _table_cell(row.get(key, "")) for key in ("turn", "action", "detail", "outcome")
                )
                + " |"
            )
    else:
        lines.append("No action history was present in the workspace events.")
    lines.extend(["", "## Recommendations", ""])
    lines.extend(f"- {item}" for item in _list(report.get("recommendations")))
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in _list(report.get("limitations")))
    lines.extend(["", "## Evidence Handling", ""])
    lines.extend(f"- {item}" for item in _list(report.get("evidence_handling")))
    lines.append("")
    return "\n".join(lines)


def redact_sensitive(value: str) -> str:
    redacted = _PROOF_RE.sub(lambda match: _mask_proof(match.group(0)), str(value))
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(_secret_replacement, redacted)
    return redacted


def _traffic_accounting_summary(workspace_dir: Path) -> dict[str, object]:
    ledger_path = workspace_dir / "traffic-policy.json"
    if not ledger_path.exists():
        return {
            "status": "unavailable",
            "provenance": "traffic_policy_ledger_missing",
        }
    try:
        inspection = load_traffic_policy_snapshot(ledger_path)
    except (OSError, TrafficPolicyError, ValueError):
        return {
            "status": "unavailable",
            "provenance": "traffic_policy_ledger_unreadable",
        }
    snapshot = inspection.snapshot
    limit = inspection.config.max_physical_requests
    remaining = (
        None
        if limit is None
        else max(
            limit
            - snapshot.physical_request_count
            - snapshot.reservation_count,
            0,
        )
    )
    return {
        "status": snapshot.accounting_status,
        "provenance": "workspace_traffic_policy_ledger",
        "mode": inspection.config.mode.value,
        "physical_request_count": snapshot.physical_request_count,
        "completed_request_count": snapshot.completed_request_count,
        "incomplete_request_count": (
            snapshot.incomplete_request_count + snapshot.pending_dispatch_count
        ),
        "pending_dispatch_count": snapshot.pending_dispatch_count,
        "reservation_count": snapshot.reservation_count,
        "max_physical_requests": limit,
        "remaining_physical_requests": remaining,
        "cache_hit_count": snapshot.cache_hit_count,
        "deduplicated_count": snapshot.deduplicated_count,
        "retry_count": snapshot.retry_count,
        "blocked_count": snapshot.blocked_count,
        "circuit_open_count": snapshot.circuit_open_count,
        "unmetered_action_count": snapshot.unmetered_action_count,
    }


def _agent_http_evidence_summary(
    workspace_dir: Path,
) -> dict[str, object]:
    try:
        traffic_workspace = resolve_workspace(workspace_dir)
    except TrafficRunError as exc:
        if _canonical_traffic_artifacts_present(workspace_dir) or _graph_traffic_expected(
            workspace_dir
        ):
            message = "traffic artifacts are present but could not be validated"
            raise TrafficProvenanceError(message) from exc
        return _empty_agent_http_evidence_summary()

    try:
        traffic_manifest = read_traffic_manifest(traffic_workspace)
        store = TrafficStore.open(traffic_workspace)
        exchanges = store.exchanges()
    except (TrafficRunError, TrafficStoreError) as exc:
        message = "traffic artifacts are present but could not be validated"
        raise TrafficProvenanceError(message) from exc
    if any(
        exchange.capture_session_id != traffic_manifest.capture_session_id
        for exchange in exchanges
    ):
        message = "traffic capture session does not match its run manifest"
        raise TrafficProvenanceError(message)
    provenance = load_traffic_provenance(
        traffic_workspace,
        exchanges=exchanges,
        target_identity=traffic_manifest.target_identity,
    )
    agent_links = tuple(
        link
        for exchange, link in zip(exchanges, provenance.links, strict=True)
        if exchange.source == "agent_http"
    )
    invalid_statuses = {
        link.status
        for link in agent_links
        if link.status not in {"linked", "observation_only", "missing_observation"}
    }
    if invalid_statuses:
        message = "agent HTTP provenance has an invalid link status"
        raise TrafficProvenanceError(message)
    if any(link.status == "missing_observation" for link in agent_links):
        message = "agent HTTP traffic is missing its evidence observation identifier"
        raise TrafficProvenanceError(message)
    if not agent_links:
        return _empty_agent_http_evidence_summary()

    evidence_ids = tuple(
        dict.fromkeys(
            evidence_id
            for link in agent_links
            for evidence_id in link.evidence_refs
        )
    )
    material_evidence_ids = tuple(
        dict.fromkeys(
            evidence_id
            for link in agent_links
            for evidence_id in link.material_evidence_refs
        )
    )
    links = [
        {
            "request_id": link.request_id,
            "status": link.status,
            "observation_id": link.observation_id,
            "evidence_ids": list(link.evidence_refs),
            "material_evidence_ids": list(link.material_evidence_refs),
        }
        for link in agent_links
    ]
    return {
        "status": "available",
        "request_count": len(agent_links),
        "linked_request_count": sum(link.status == "linked" for link in agent_links),
        "observation_only_request_count": sum(
            link.status == "observation_only" for link in agent_links
        ),
        "evidence_count": len(evidence_ids),
        "material_evidence_count": len(material_evidence_ids),
        "links": links,
    }


def _empty_agent_http_evidence_summary() -> dict[str, object]:
    return {
        "status": "not_available",
        "request_count": 0,
        "linked_request_count": 0,
        "observation_only_request_count": 0,
        "evidence_count": 0,
        "material_evidence_count": 0,
        "links": [],
    }


def _canonical_traffic_artifacts_present(workspace_dir: Path) -> bool:
    for candidate in _traffic_workspace_candidates(workspace_dir):
        try:
            (candidate / "traffic").lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            message = "could not safely inspect traffic artifacts"
            raise TrafficProvenanceError(message) from exc
        else:
            return True
    return False


def _graph_traffic_expected(workspace_dir: Path) -> bool:
    """Detect new-version graph artifacts that require a traffic store."""
    for candidate in _traffic_workspace_candidates(workspace_dir):
        try:
            (candidate / "graph-http-state.json").lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            message = "could not safely inspect graph HTTP state"
            raise TrafficProvenanceError(message) from exc
        else:
            # Local graph HTTP persistence and automatic traffic capture shipped
            # together, so any such state file requires the paired store.
            return True

        remote_state = _read_bounded_json_object(candidate / "remote-http-state.json")
        if (
            remote_state.get("version") == _PRIVATE_HTTP_STATE_VERSION
            and remote_state.get("target_identity")
        ):
            return True
        for receipt_name in ("graph-route-receipt.json", "remote-graph-receipt.json"):
            receipt = _read_bounded_json_object(candidate / receipt_name)
            if "traffic" in receipt:
                return True
    return False


def _traffic_workspace_candidates(workspace_dir: Path) -> tuple[Path, ...]:
    return (
        workspace_dir,
        workspace_dir / "workspace",
        workspace_dir / "autonomous-route" / "agent-graph",
        workspace_dir / "workspace" / "autonomous-route" / "agent-graph",
    )


def _read_bounded_json_object(path: Path) -> dict[str, object]:  # noqa: PLR0911
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return {}
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _GRAPH_MARKER_MAX_BYTES:
            return {}
        chunks: list[bytes] = []
        remaining = _GRAPH_MARKER_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _GRAPH_MARKER_MAX_BYTES:
            return {}
    except OSError:
        return {}
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(key): value for key, value in payload.items()}


def _agent_http_evidence_markdown(summary: dict[str, Any]) -> list[str]:
    if summary.get("status") == "not_available":
        return [
            "No agent HTTP traffic provenance was available for this run.",
        ]

    lines = [
        "Only redacted identifiers are included; captured request and response content "
        "remains in the private traffic store.",
        "",
        f"- Status: {summary.get('status', '')}",
        f"- Captured agent requests: {summary.get('request_count', 0)}",
        f"- Requests linked to evidence: {summary.get('linked_request_count', 0)}",
        (
            "- Requests with an observation only: "
            f"{summary.get('observation_only_request_count', 0)}"
        ),
        f"- Evidence IDs: {summary.get('evidence_count', 0)}",
        f"- Material evidence IDs: {summary.get('material_evidence_count', 0)}",
        "",
    ]
    links = _list(summary.get("links"))
    if not links:
        return lines
    lines.extend(
        [
            "| Request ID | Status | Observation ID | Evidence IDs | Material evidence IDs |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for item in links:
        link = _dict(item)
        lines.append(
            "| "
            + " | ".join(
                _table_cell(value)
                for value in (
                    link.get("request_id", ""),
                    link.get("status", ""),
                    link.get("observation_id", ""),
                    _join(_list(link.get("evidence_ids"))),
                    _join(_list(link.get("material_evidence_ids"))),
                )
            )
            + " |"
        )
    return lines


def _load_events(path: Path) -> tuple[list[dict[str, Any]], int]:
    if not path.exists():
        return [], 0
    events: list[dict[str, Any]] = []
    parse_errors = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if isinstance(event, dict):
            events.append(event)
    return events, parse_errors


def _load_run_events(
    workspace_dir: Path,
) -> tuple[list[dict[str, Any]], int, tuple[Path, ...]]:
    candidates = (
        workspace_dir / "events.jsonl",
        workspace_dir / "autonomous-route" / "events.jsonl",
        workspace_dir / "autonomous-route" / "agent-graph" / "events.jsonl",
    )
    events: list[dict[str, Any]] = []
    parse_errors = 0
    present: list[Path] = []
    for path in candidates:
        if not path.is_file():
            continue
        loaded, errors = _load_events(path)
        events.extend(loaded)
        parse_errors += errors
        present.append(path)
    return events, parse_errors, tuple(present)


def _confirmed_findings(
    events: list[dict[str, Any]],
    *,
    engagement_id: UUID | str,
    scope: Scope | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for event in events:
        if event.get("kind") != "finding_confirmed":
            continue
        payload = _dict(event.get("payload"))
        if str(payload.get("engagement_id") or "") != str(engagement_id):
            continue
        if str(payload.get("status") or "") != "confirmed":
            continue
        if confirmed_finding_evidence_failures(payload, scope=scope):
            continue
        findings.append(_normalize_finding(payload))
    return findings


def _audit_findings(
    db_path: Path,
    *,
    scope: Scope | None = None,
    engagement_id: UUID | str | None = None,
) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            if engagement_id is None:
                rows = conn.execute(
                    """
                    SELECT payload_json
                    FROM findings
                    WHERE status = 'confirmed'
                    ORDER BY finding_id
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT payload_json
                    FROM findings
                    WHERE status = 'confirmed' AND engagement_id = ?
                    ORDER BY finding_id
                    """,
                    (str(engagement_id),),
                ).fetchall()
    except sqlite3.Error:
        return []
    findings: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(str(row[0]))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and not confirmed_finding_evidence_failures(
            payload,
            scope=scope,
        ):
            findings.append(_normalize_finding(payload))
    return findings


def _normalize_finding(raw: dict[str, Any]) -> dict[str, Any]:
    vuln_class = str(raw.get("vuln_class") or raw.get("type") or "unspecified")
    endpoint = _endpoint(raw.get("endpoint"))
    finding_input = _finding_input(raw.get("input"), endpoint=endpoint)
    proof = _dict(raw.get("proof"))
    impact = str(proof.get("impact_description") or raw.get("impact") or "")
    title = _title_for(vuln_class, endpoint)
    severity = _severity_for(vuln_class, raw)
    return {
        "finding_id": str(raw.get("finding_id") or ""),
        "title": title,
        "vuln_class": vuln_class,
        "severity": severity,
        "status": str(raw.get("status") or "confirmed"),
        "endpoint": endpoint,
        "input": finding_input,
        "hypothesis": str(raw.get("hypothesis") or ""),
        "impact": impact or _impact_for(vuln_class, severity),
        "evidence": _evidence_for(raw),
        "validator_vote": str(raw.get("validator_vote") or ""),
        "recommendation": _remediation_for(vuln_class),
    }


def _endpoint(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"method": "", "url": "", "params": []}
    return {
        "method": str(value.get("method") or ""),
        "url": str(value.get("url") or ""),
        "params": _list(value.get("params")),
    }


def _finding_input(value: object, *, endpoint: dict[str, Any]) -> dict[str, Any]:
    raw = _dict(value)
    parameters = _list(raw.get("parameters")) or _list(endpoint.get("params"))
    result: dict[str, Any] = {
        "method": str(raw.get("method") or endpoint.get("method") or "GET"),
        "parameters": parameters,
    }
    affected_parameters = _list(raw.get("affected_parameters"))
    if affected_parameters:
        result["affected_parameters"] = affected_parameters
    return result


def _evidence_for(raw: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for key in ("hypothesis", "summary", "description"):
        text = str(raw.get(key) or "").strip()
        if text:
            evidence.append(text)
    proof = _dict(raw.get("proof"))
    for key in ("http_request_final", "response_final", "impact_description"):
        text = str(proof.get(key) or "").strip()
        if text:
            evidence.append(_clip(text, 700))
    for step in _list(raw.get("exploit_steps"))[:5]:
        item = _dict(step)
        parts = [
            str(item.get("indicator") or "").strip(),
            str(item.get("http_request") or "").strip(),
            str(item.get("response_snippet") or "").strip(),
        ]
        text = " | ".join(part for part in parts if part)
        if text:
            evidence.append(_clip(text, 700))
    return _dedupe_strings(evidence)[:8]


def _proof_observations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for event in events:
        if event.get("kind") != "tool_run_probe":
            continue
        payload = _dict(event.get("payload"))
        result = str(payload.get("result") or "")
        try:
            parsed = json.loads(result)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        findings = [item for item in _list(parsed.get("findings")) if isinstance(item, dict)]
        proof_findings = [
            item
            for item in findings
            if _list(_dict(item).get("proofs")) or "proof" in str(_dict(item).get("type") or "")
        ]
        if proof_findings:
            observations.append(
                {
                    "probe": str(parsed.get("probe") or ""),
                    "summary": _clip(str(parsed.get("summary") or ""), 300),
                    "findings": _redact_recursive(proof_findings[:5]),
                }
            )
    return observations[:10]


def _work_performed(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    work: list[dict[str, Any]] = []
    outcomes_by_action_id = _outcomes_by_action_id(events)
    for event in events:
        if event.get("kind") != "action_started":
            continue
        payload = _dict(event.get("payload"))
        action_id = str(payload.get("action_id") or "")
        params = _dict(payload.get("params"))
        detail = str(payload.get("detail") or "")
        if not detail:
            detail = str(
                params.get("probe") or params.get("command") or payload.get("summary") or ""
            )
        work.append(
            {
                "turn": payload.get("turn", ""),
                "action": str(payload.get("action_kind") or ""),
                "detail": _clip(detail, 180),
                "outcome": outcomes_by_action_id.get(action_id, ""),
            }
        )
    return work[:80]


def _outcomes_by_action_id(events: list[dict[str, Any]]) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    tool_kinds = {
        "tool_run_command",
        "tool_run_python",
        "tool_run_probe",
        "tool_validate_poc",
    }
    for event in events:
        kind = str(event.get("kind") or "")
        if kind not in tool_kinds:
            continue
        payload = _dict(event.get("payload"))
        action_id = str(payload.get("action_id") or "")
        if not action_id:
            continue
        ok = payload.get("ok")
        if isinstance(ok, bool):
            outcomes[action_id] = "ok" if ok else "not confirmed"
        if payload.get("timed_out") is True:
            outcomes[action_id] = "timed out"
    return outcomes


def _recon_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for event in events:
        if event.get("kind") == "recon_completed":
            payload = _dict(event.get("payload"))
    pages = [_dict(item) for item in _list(payload.get("pages")) if isinstance(item, dict)]
    forms = sum(len(_list(page.get("forms"))) for page in pages)
    return {
        "target_url": str(payload.get("target_url") or ""),
        "origin": str(payload.get("origin") or ""),
        "page_count": len(pages),
        "form_count": forms,
        "query_parameter_names": _dedupe_strings(
            [str(item) for item in _list(payload.get("query_parameter_names"))]
        )[:20],
        "interesting_markers": _dedupe_strings(
            [str(item) for item in _list(payload.get("interesting_markers"))]
        )[:20],
        "errors": _dedupe_strings([str(item) for item in _list(payload.get("errors"))])[:10],
    }


def _hosting_layer_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for event in events:
        if event.get("kind") == HOSTING_LAYER_EVENT_KIND:
            payload = _dict(event.get("payload"))
    if not payload:
        return {
            "enabled": False,
            "agent": "hosting-layer",
            "configured_live_sites": [],
            "summary": "",
            "findings": [],
            "checks": [],
        }

    checks = [
        _hosting_check_summary(_dict(item))
        for item in _list(payload.get("checks"))
        if isinstance(item, dict)
    ]
    findings = _dedupe_strings(
        [_clip(str(item), 300) for item in _list(payload.get("findings")) if str(item)]
    )
    return {
        "enabled": True,
        "agent": str(payload.get("agent") or "hosting-layer"),
        "mode": str(payload.get("mode") or ""),
        "configured_live_sites": [
            str(item) for item in _list(payload.get("configured_live_sites")) if str(item)
        ],
        "summary": _clip(str(payload.get("summary") or ""), 500),
        "findings": findings[:20],
        "checks": checks,
    }


def _hosting_check_summary(raw: dict[str, Any]) -> dict[str, Any]:
    headers = _dict(raw.get("headers"))
    return {
        "command": str(raw.get("command") or ""),
        "url": str(raw.get("url") or ""),
        "ok": bool(raw.get("ok")),
        "exit_code": raw.get("exit_code"),
        "status_code": raw.get("status_code"),
        "status_line": str(raw.get("status_line") or ""),
        "elapsed_ms": raw.get("elapsed_ms"),
        "location": str(raw.get("location") or headers.get("location") or ""),
        "server": str(raw.get("server") or headers.get("server") or ""),
        "cloudflare": bool(raw.get("cloudflare")),
        "error": _clip(str(raw.get("error") or raw.get("stderr") or ""), 300),
    }


def _hosting_layer_markdown(hosting: dict[str, Any]) -> list[str]:
    lines = [
        "",
        "## Live Hosting Layer",
        "",
        str(hosting.get("summary") or "Configured live hosting checks were run."),
        "",
        (
            "These checks are limited to the configured public hosting endpoint(s) "
            "and are separate from localhost vulnerability testing."
        ),
        "",
    ]
    findings = _list(hosting.get("findings"))
    if findings:
        lines.extend(["Observations:", ""])
        lines.extend(f"- {item}" for item in findings)
        lines.append("")

    checks = [_dict(item) for item in _list(hosting.get("checks")) if isinstance(item, dict)]
    if checks:
        lines.extend(
            [
                "| Command | URL | Status | Redirect | Cloudflare | Outcome |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for check in checks:
            status = check.get("status_code")
            if isinstance(status, int):
                status_text = str(status)
            else:
                status_text = str(check.get("status_line") or "")
            if not status_text:
                status_text = "no response"
            outcome = "ok" if check.get("ok") is True else str(check.get("error") or "not ok")
            lines.append(
                "| "
                + " | ".join(
                    _table_cell(value)
                    for value in (
                        check.get("command", ""),
                        check.get("url", ""),
                        status_text,
                        check.get("location", ""),
                        check.get("cloudflare", False),
                        outcome,
                    )
                )
                + " |"
            )
        lines.append("")
    return lines


def _engagement_payload(
    brief: EngagementBrief,
    *,
    brief_path: Path,
    target_url: str,
) -> dict[str, Any]:
    return {
        "brief_path": str(brief_path),
        "engagement_id": str(brief.engagement_id),
        "target_url": target_url,
        "scope": {
            "in_scope": list(brief.scope.in_scope),
            "out_of_scope": list(brief.scope.out_of_scope),
        },
        "rules_of_engagement": {
            "max_rps": brief.roe.max_rps,
            "no_destructive_actions": brief.roe.no_destructive_actions,
            "data_handling": str(brief.roe.data_handling),
        },
        "objectives": list(brief.objectives),
        "budget": {
            "max_cost_usd": brief.budget.max_cost_usd,
            "max_runtime_min": brief.budget.max_runtime_min,
        },
    }


def _methodology() -> list[str]:
    return [
        "Reviewed the engagement brief, scope, rules of engagement, and objective constraints.",
        "Performed bounded attack-surface discovery against in-scope target URLs.",
        (
            "Executed targeted probes and custom validation steps for evidence-backed "
            "exploit hypotheses."
        ),
        "Captured and redacted proof material when observed in target output.",
        "Produced this report from persisted workspace events and audit artifacts.",
    ]


def _recommendations(*, findings: list[dict[str, Any]], flags: list[str]) -> list[str]:
    recommendations = [_remediation_for(str(item.get("vuln_class") or "")) for item in findings]
    if flags and not findings:
        recommendations.append(
            "Review the exploited path that exposed the captured proof, add regression "
            "coverage, and verify the fix with a focused retest."
        )
    recommendations.extend(
        [
            (
                "Retest all confirmed findings after remediation and preserve "
                "request/response evidence for closure."
            ),
            (
                "Monitor application logs around the assessed window for related "
                "exploitation indicators."
            ),
        ]
    )
    return _dedupe_strings(recommendations)


def _limitations(brief: EngagementBrief) -> list[str]:
    items = [
        (
            "Testing was limited to the in-scope assets and objectives defined in the "
            "engagement brief."
        ),
        (
            "Automated testing can miss vulnerabilities that require business context, "
            "privileged credentials, or long-running manual workflows."
        ),
        "No destructive actions were attempted where prohibited by the rules of engagement.",
    ]
    if brief.roe.data_handling != "full":
        items.append(
            "Sensitive values are redacted or summarized according to the configured "
            "data-handling policy."
        )
    return items


def _executive_summary_text(  # noqa: PLR0913
    *,
    status: str,
    completed: bool,
    overall_risk: str,
    finding_count: int,
    flag_count: int,
    error: str | None,
) -> str:
    if error:
        return (
            "The assessment ended with an error before normal completion. "
            "The report reflects evidence persisted before interruption."
        )
    if not completed and status != "completed":
        partial = (
            "The assessment did not reach normal completion. "
            "Results should be treated as partial."
        )
        if finding_count:
            partial += (
                f" Before interruption, Ravage recorded {finding_count} confirmed "
                f"finding(s); the highest observed risk level is {overall_risk}."
            )
        elif flag_count:
            partial += " Target proof material was captured before interruption."
        return partial
    if finding_count:
        return (
            f"The assessment completed with {finding_count} confirmed finding(s). "
            f"The highest observed risk level is {overall_risk}."
        )
    if flag_count:
        return (
            "The agent captured target proof material, indicating successful exploitation "
            "of an in-scope path. "
            "No structured confirmed finding record was present in the run artifacts."
        )
    if completed or status == "completed":
        return (
            "The assessment completed without a captured proof string or confirmed "
            "finding in the run artifacts."
        )
    return "The assessment did not reach normal completion. Results should be treated as partial."


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        severity = str(finding.get("severity") or "Informational")
        counts[severity if severity in counts else "Informational"] += 1
    return counts


def _overall_risk(
    *,
    findings: list[dict[str, Any]],
    flags: list[str],
    status: str,
) -> str:
    if findings:
        return max(
            (str(item.get("severity") or "Informational") for item in findings),
            key=lambda severity: _SEVERITY_ORDER.get(severity, 0),
        )
    if flags:
        return "High"
    if status not in {"completed", "max_turns_reached"}:
        return "Informational"
    return "Low"


def _severity_for(vuln_class: str, raw: dict[str, Any]) -> str:
    explicit = str(raw.get("severity") or "").title()
    if explicit in _SEVERITY_ORDER:
        return explicit
    normalized = vuln_class.lower().replace("-", "_")
    return _VULN_SEVERITY.get(normalized, "Informational")


def _remediation_for(vuln_class: str) -> str:
    normalized = vuln_class.lower().replace("-", "_")
    return _REMEDIATIONS.get(
        normalized,
        (
            "Address the vulnerable behavior at the root cause, add regression tests, "
            "and retest the affected endpoint."
        ),
    )


def _impact_for(vuln_class: str, severity: str) -> str:
    return (
        f"The observed {vuln_class or 'vulnerability'} condition is rated {severity} based on the "
        "available evidence and should be remediated according to business impact."
    )


def _title_for(vuln_class: str, endpoint: dict[str, Any]) -> str:
    label = vuln_class.replace("_", " ").strip().title() or "Security Finding"
    url = str(endpoint.get("url") or "").strip()
    if not url:
        return label
    return f"{label} at {url}"


def _target_from_events(events: list[dict[str, Any]]) -> str:
    for event in events:
        if event.get("kind") == "agent_started":
            payload = _dict(event.get("payload"))
            return str(payload.get("target_url") or "")
    return ""


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        key = str(finding.get("finding_id") or "")
        if not key:
            endpoint = _dict(finding.get("endpoint"))
            key = "|".join(
                [
                    str(finding.get("vuln_class") or ""),
                    str(endpoint.get("method") or ""),
                    str(endpoint.get("url") or ""),
                    str(finding.get("hypothesis") or ""),
                ]
            )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _finding_markdown(index: int, finding: dict[str, Any]) -> list[str]:
    endpoint = _dict(finding.get("endpoint"))
    lines = [
        f"### {index}. {finding.get('title', 'Security Finding')}",
        "",
        f"- Severity: {finding.get('severity', 'Informational')}",
        f"- Class: {finding.get('vuln_class', '')}",
        f"- Endpoint: {endpoint.get('method', '')} {endpoint.get('url', '')}".rstrip(),
        "",
        "Impact:",
        "",
        str(finding.get("impact") or ""),
        "",
        "Evidence:",
        "",
    ]
    evidence = _list(finding.get("evidence"))
    if evidence:
        lines.extend(f"- {item}" for item in evidence)
    else:
        lines.append(
            "- Evidence was recorded in the audit database without inline request/response detail."
        )
    lines.extend(
        [
            "",
            "Recommendation:",
            "",
            str(finding.get("recommendation") or ""),
            "",
        ]
    )
    return lines


def _redact_recursive(value: object) -> object:
    if isinstance(value, dict):
        return {redact_sensitive(str(key)): _redact_recursive(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_recursive(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_recursive(item) for item in value]
    if isinstance(value, str):
        return redact_sensitive(value)
    return value


def _secret_replacement(match: re.Match[str]) -> str:
    if match.re.pattern.lower().startswith("\\bsk-"):
        return "<SECRET_REDACTED>"
    groups = match.groups()
    if len(groups) >= _MIN_SECRET_REPLACEMENT_GROUPS:
        return f"{groups[0]}{groups[1]}{groups[2]}<SECRET_REDACTED>{groups[-1] or ''}"
    return "<SECRET_REDACTED>"


def _mask_proof(value: str) -> str:
    prefix = str(value).split("{", 1)[0] or "flag"
    return f"{prefix}{{REDACTED}}"


def _clip(value: str, limit: int) -> str:
    text = redact_sensitive(str(value))
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + " [truncated]"


def _dedupe_strings(items: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return deduped


def _dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _join(items: list[Any]) -> str:
    values = [str(item) for item in items if str(item)]
    return ", ".join(values) if values else "None recorded"


def _table_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()
