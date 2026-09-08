from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ravage.report import build_pentest_report, redact_report_payload
from ravage.report_io import atomic_write_private_report

if TYPE_CHECKING:
    from pathlib import Path


def write_json_report_artifact(  # noqa: PLR0913
    *,
    brief_path: Path,
    target_url: str,
    workspace_dir: Path,
    output_path: Path,
    status: str,
    completed: bool,
    audit_db_path: Path | None = None,
    error: str | None = None,
    termination_reason: str = "",
    markdown_report_path: Path | None = None,
    professional_report_path: Path | None = None,
) -> dict[str, Any]:
    """Persist the canonical redacted JSON report without running report-time agents."""
    report = build_pentest_report(
        brief_path=brief_path,
        target_url=target_url,
        workspace_dir=workspace_dir,
        status=status,
        completed=completed,
        audit_db_path=audit_db_path,
        error=error,
    )
    report["artifacts"] = {
        "json_report_path": str(output_path),
        "markdown_report_path": str(markdown_report_path) if markdown_report_path else "",
        "professional_report_path": (
            str(professional_report_path) if professional_report_path else ""
        ),
    }
    if termination_reason:
        run = report.get("run")
        if isinstance(run, dict):
            run["termination_reason"] = termination_reason
    report = redact_report_payload(report)
    atomic_write_private_report(output_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


__all__ = ["write_json_report_artifact"]
