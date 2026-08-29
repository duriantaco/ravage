from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ravage.run_trace import summarize_workspace_trace


@dataclass(frozen=True)
class TraceQualityReport:
    passed: bool
    findings: list[dict[str, object]]

    def to_json(self) -> dict[str, object]:
        return {"passed": self.passed, "findings": self.findings}


def grade_workspace_trace(workspace_dir: Path, *, require_trace: bool = False) -> TraceQualityReport:
    summary = summarize_workspace_trace(workspace_dir).to_json()
    findings: list[dict[str, object]] = []
    if require_trace and not summary.get("events_present"):
        findings.append({"code": "missing_trace_events", "severity": "error"})
    if summary.get("invalid_actions"):
        findings.append({"code": "invalid_action_burn_rate", "severity": "warn"})
    passed = not any(item.get("severity") == "error" for item in findings)
    return TraceQualityReport(passed=passed, findings=findings)
