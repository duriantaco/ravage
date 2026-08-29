from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


_STAGE_RANK = {
    "setup": 0,
    "recon": 1,
    "auth": 2,
    "probe": 3,
    "evidence": 4,
}


@dataclass(frozen=True)
class CaseSignals:
    deepest_stage: str = "setup"
    values: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CaseFailureClassification:
    case_id: str = ""
    primary_category: str = "setup"
    deepest_stage: str = "setup"
    terminated_by: str = "failed"
    solved: bool = False
    tags: tuple[str, ...] = ()
    model_request_count: int = 0
    http_request_count: int = 0
    elapsed_seconds: float = 0.0
    signals: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class FailureTaxonomyReport:
    cases: tuple[CaseFailureClassification, ...] = ()

    @property
    def total_cases(self) -> int:
        return len(self.cases)

    @property
    def solved(self) -> int:
        return sum(1 for case in self.cases if case.solved)

    @property
    def solve_rate(self) -> float:
        if not self.cases:
            return 0.0
        return self.solved / len(self.cases)

    @property
    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            if case.primary_category == "solved":
                continue
            counts[case.primary_category] = counts.get(case.primary_category, 0) + 1
        return counts

    @property
    def cost(self) -> dict[str, object]:
        return {
            "model_requests_total": sum(case.model_request_count for case in self.cases),
            "http_requests_total": sum(case.http_request_count for case in self.cases),
            "elapsed_seconds_total": sum(case.elapsed_seconds for case in self.cases),
        }

    @property
    def tag_solve_rates(self) -> dict[str, dict[str, int]]:
        rates: dict[str, dict[str, int]] = {}
        for case in self.cases:
            for tag in case.tags:
                bucket = rates.setdefault(tag, {"total": 0, "solved": 0})
                bucket["total"] += 1
                if case.solved:
                    bucket["solved"] += 1
        return rates

    def to_json(self) -> dict[str, object]:
        return {
            "total_cases": self.total_cases,
            "solved": self.solved,
            "solve_rate": self.solve_rate,
            "category_counts": self.category_counts,
            "cost": self.cost,
            "tag_solve_rates": self.tag_solve_rates,
            "cases": [_case_to_json(case) for case in self.cases],
        }


def signals_from_events(events: list[dict[str, object]]) -> CaseSignals:
    stage = "setup"
    values: dict[str, object] = {
        "events_present": bool(events),
        "finding_confirmed": False,
        "flag_captured": False,
        "budget_exhausted": False,
        "agent_final": False,
    }

    for event in events:
        kind = str(event.get("kind") or "")
        payload = _payload(event)
        action = str(payload.get("action") or payload.get("action_kind") or payload.get("tool") or "")
        command = _command_text(payload.get("command"))

        if kind == "flag_captured":
            values["flag_captured"] = True
            stage = _deeper_stage(stage, "evidence")
        elif kind == "finding_confirmed":
            values["finding_confirmed"] = True
            stage = _deeper_stage(stage, "evidence")
        elif kind in {"max_turns_reached", "max_actions_reached"}:
            values["budget_exhausted"] = True
        elif kind == "run_error":
            values["terminal_error_type"] = str(payload.get("type") or "")
            values["terminal_error_message"] = str(payload.get("message") or "")
        elif command:
            stage = _deeper_stage(stage, _stage_for_command(command))
        elif action:
            if action == "final":
                values["agent_final"] = True
            stage = _deeper_stage(stage, _stage_for_action(action))

    return CaseSignals(deepest_stage=stage, values=values)


def classify_case(
    case: dict[str, object],
    signals: CaseSignals | None = None,
) -> CaseFailureClassification:
    if signals is None:
        signals = signals_from_events([])

    case_id = str(case.get("benchmark_id") or case.get("id") or "")
    status = str(case.get("status") or "failed")
    solved = _case_is_solved(case, signals)
    deepest_stage = signals.deepest_stage
    primary_category = _primary_category(case, signals=signals, solved=solved)
    terminated_by = _termination(status=status, signals=signals, solved=solved)

    return CaseFailureClassification(
        case_id=case_id,
        primary_category=primary_category,
        deepest_stage=deepest_stage,
        terminated_by=terminated_by,
        solved=solved,
        tags=tuple(_string_items(case.get("tags"))),
        model_request_count=_int_value(case.get("model_request_count")),
        http_request_count=_int_value(case.get("http_request_count")),
        elapsed_seconds=_float_value(case.get("elapsed_seconds")),
        signals=signals.values,
    )


def build_failure_taxonomy(data: dict[str, object], *, base_dir: Path | None = None) -> FailureTaxonomyReport:
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list):
        raw_cases = []

    cases: list[CaseFailureClassification] = []
    for item in raw_cases:
        case = item if isinstance(item, dict) else {}
        events = _events_for_case(case, base_dir=base_dir)
        signals = signals_from_events(events)
        cases.append(classify_case(case, signals))
    return FailureTaxonomyReport(tuple(cases))


def load_failure_taxonomy(path: Path) -> FailureTaxonomyReport:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        data = {}
    return build_failure_taxonomy(data, base_dir=path.parent)


def render_markdown(report: FailureTaxonomyReport) -> str:
    lines = [
        "# XBEN Failure Taxonomy",
        "",
        f"- Cases: {report.total_cases}",
        f"- Solved: {report.solved}",
        f"- Solve rate: {report.solve_rate:.3f}",
        "",
        "## Categories",
    ]
    for category, count in sorted(report.category_counts.items()):
        lines.append(f"- {category}: {count}")
    lines.extend(["", "## Cases"])
    for case in report.cases:
        lines.append(f"- {case.case_id}: {case.primary_category} ({case.terminated_by})")
    return "\n".join(lines) + "\n"


def _case_to_json(case: CaseFailureClassification) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "primary_category": case.primary_category,
        "deepest_stage": case.deepest_stage,
        "terminated_by": case.terminated_by,
        "solved": case.solved,
        "tags": list(case.tags),
        "model_request_count": case.model_request_count,
        "http_request_count": case.http_request_count,
        "elapsed_seconds": case.elapsed_seconds,
        "signals": case.signals,
    }


def _events_for_case(case: dict[str, object], *, base_dir: Path | None) -> list[dict[str, object]]:
    path = _resolve_events_path(case.get("events_path"), base_dir=base_dir)
    if path is None or not path.exists():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(dict(item))
    return rows


def _resolve_events_path(value: object, *, base_dir: Path | None) -> Path | None:
    text = str(value or "")
    if not text:
        return None
    path = Path(text)
    if path.is_absolute():
        return path
    if base_dir is None:
        return path

    candidates: list[Path] = [base_dir / path]
    candidates.extend(parent / path for parent in base_dir.parents)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _primary_category(
    case: dict[str, object],
    *,
    signals: CaseSignals,
    solved: bool,
) -> str:
    if solved:
        return "solved"
    if _model_failure(case, signals):
        return "model"
    if signals.values.get("finding_confirmed"):
        return "evidence"
    return signals.deepest_stage


def _termination(*, status: str, signals: CaseSignals, solved: bool) -> str:
    if solved:
        return "solved"
    if signals.values.get("budget_exhausted"):
        return "budget_exhausted"
    if status == "errored" or signals.values.get("terminal_error_type"):
        return "errored"
    if status == "timeout":
        return "timeout"
    if signals.values.get("agent_final"):
        return "agent_final"
    return status or "failed"


def _case_is_solved(case: dict[str, object], signals: CaseSignals) -> bool:
    if bool(case.get("solved")):
        return True
    if str(case.get("status") or "") == "solved":
        return True
    if str(case.get("found_flag") or ""):
        return True
    return bool(signals.values.get("flag_captured"))


def _model_failure(case: dict[str, object], signals: CaseSignals) -> bool:
    if _int_value(case.get("model_request_count")) > 0:
        return False
    error_type = str(signals.values.get("terminal_error_type") or "")
    error_message = str(signals.values.get("terminal_error_message") or "")
    return "model" in f"{error_type} {error_message}".lower()


def _stage_for_action(action: str) -> str:
    lowered = action.lower()
    if lowered == "final":
        return "setup"
    if "login" in lowered or "auth" in lowered or "credential" in lowered:
        return "auth"
    if lowered.startswith("test_") or lowered.startswith("probe_"):
        return "probe"
    if lowered in {"source_guided_probe", "run_probe"}:
        return "probe"
    if lowered in {"report_finding", "capture_flag"}:
        return "setup"
    return "recon"


def _stage_for_command(command: str) -> str:
    lowered = command.lower()
    if "sqlmap" in lowered:
        return "probe"
    return "recon"


def _deeper_stage(current: str, candidate: str) -> str:
    if _STAGE_RANK.get(candidate, 0) > _STAGE_RANK.get(current, 0):
        return candidate
    return current


def _payload(event: dict[str, object]) -> dict[str, object]:
    payload = event.get("payload")
    if isinstance(payload, dict):
        return dict(payload)
    return {}


def _command_text(value: object) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return str(value or "")


def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _int_value(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float_value(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
