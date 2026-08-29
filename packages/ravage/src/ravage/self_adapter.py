from __future__ import annotations

import json
import math
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

RESULT_SCHEMA_VERSION = "ravage.competitor.result.v2"
MODEL_REPLY_EVENT_KINDS = frozenset({"model_reply", "model_reply_received"})
TOOL_CALL_EVENT_KINDS = frozenset(
    {
        "tool_call",
        "tool_run_command",
        "tool_run_probe",
        "tool_run_python",
        "tool_validate_poc",
    }
)


def build_ravage_competitor_result(
    *,
    benchmark_report_path: Path | str,
    case_id: str,
) -> dict[str, object]:
    benchmark_report_path = Path(benchmark_report_path)
    report = json.loads(benchmark_report_path.read_text(encoding="utf-8"))
    case = _case_payload(report, case_id)
    preflight_case = _preflight_case(report, case_id)
    db_path = Path(str(case.get("db_path") or ""))
    workspace_path = Path(str(case.get("workspace_path") or ""))
    events_path = Path(str(case.get("events_path") or workspace_path / "events.jsonl"))
    transcript_path = Path(str(case.get("transcript_path") or workspace_path / "transcript.jsonl"))
    artifacts_path = Path(str(case.get("artifacts_path") or workspace_path / "artifacts"))
    events = _read_events(events_path)
    flags = _flags(events, case)
    findings = _findings(db_path)
    cost_usd, cost_status, cost_provenance = _reported_cost(case, db_path, events)
    model_events = _events_with_kinds(events, MODEL_REPLY_EVENT_KINDS)
    actuals = {
        "turns_total": len(model_events),
        "model_calls": len(model_events),
        "tool_calls": len(_events_with_kinds(events, TOOL_CALL_EVENT_KINDS)),
        "input_tokens": _sum_payload_int(model_events, "input_tokens"),
        "cached_input_tokens": _sum_payload_int(model_events, "cached_input_tokens"),
        "output_tokens": _sum_payload_int(model_events, "output_tokens"),
        "http_requests": _int_value(case.get("request_count") or case.get("http_request_count")),
        "elapsed_seconds": _float_value(case.get("elapsed_seconds")),
    }
    budgets = {
        "max_turns": _int_value(preflight_case.get("max_turns")),
        "model_request_ceiling": _int_value(preflight_case.get("model_request_ceiling")),
        "estimated_input_tokens_ceiling": _int_value(
            preflight_case.get("estimated_input_tokens_ceiling")
        ),
        "estimated_output_tokens_ceiling": _int_value(
            preflight_case.get("estimated_output_tokens_ceiling")
        ),
        "estimated_cost_usd": _optional_float(preflight_case.get("estimated_cost_usd")),
    }
    budget = preflight_case.get("budget")
    if isinstance(budget, dict):
        budgets.update(budget)
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "mode": "ravage_benchmark",
        "cost_usd": cost_usd,
        "cost_status": cost_status,
        "cost_provenance": cost_provenance,
        "raw_flags": list(flags),
        "findings": findings,
        "actuals": actuals,
        "budgets": budgets,
        "artifacts": {
            "benchmark_report_path": str(benchmark_report_path),
            "db_path": str(db_path),
            "workspace_path": str(workspace_path),
            "events_path": str(events_path),
            "transcript_path": str(transcript_path),
            "artifacts_path": str(artifacts_path),
        },
        "termination": {
            "status": "completed" if bool(case.get("passed") or case.get("solved")) else "failed"
        },
        "phases": _phases(events),
        "trace_summary": case.get("trace_summary") or {},
        "adapter_metadata": {"adapter": "ravage_self_adapter"},
    }


def _case_payload(report: dict[str, object], case_id: str) -> dict[str, object]:
    for item in report.get("cases", []):
        if not isinstance(item, dict):
            continue
        if str(item.get("case_id") or item.get("benchmark_id") or "") == case_id:
            return item
    message = f"case not found in benchmark report: {case_id}"
    raise ValueError(message)


def _preflight_case(report: dict[str, object], case_id: str) -> dict[str, object]:
    preflight = report.get("preflight")
    if not isinstance(preflight, dict):
        return {}
    for item in preflight.get("cases", []):
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("case_id") or item.get("benchmark_id") or "")
        if item_id == case_id:
            return item
    return {}


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        if isinstance(raw, dict):
            events.append(raw)
    return events


def _flags(events: list[dict[str, object]], case: dict[str, object]) -> tuple[str, ...]:
    flags: list[str] = []
    found_flag = case.get("found_flag")
    if isinstance(found_flag, str) and found_flag.startswith("flag{"):
        flags.append(found_flag)
    for event in events:
        if event.get("kind") != "flag_captured":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        value = payload.get("flag") or payload.get("proof")
        if isinstance(value, str) and value.startswith("flag{"):
            flags.append(value)
    return _dedupe(flags)


def _findings(db_path: Path) -> list[dict[str, object]]:
    if not db_path.exists():
        return []
    findings: list[dict[str, object]] = []
    with sqlite3.connect(db_path) as conn:
        if not _table_exists(conn, "findings"):
            return []
        for (payload_json,) in conn.execute("SELECT payload_json FROM findings"):
            payload = json.loads(str(payload_json))
            if isinstance(payload, dict):
                findings.append(payload)
    return findings


def _legacy_audit_cost(  # noqa: C901, PLR0911, PLR0912 - legacy evidence fails closed.
    db_path: Path,
    events: list[dict[str, object]],
) -> float | None:
    if not db_path.exists():
        return None
    with sqlite3.connect(db_path) as conn:
        if not _table_exists(conn, "audit_log"):
            return None
        columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        required_columns = {"action", "payload_json", "cost_usd"}
        if not required_columns.issubset(columns):
            return None
        rows = conn.execute(
            "SELECT payload_json, cost_usd FROM audit_log "
            "WHERE action = 'model_reply_received'"
        ).fetchall()
    if not rows:
        return None

    request_attempts = _model_attempts(events, "model_request_started")
    event_replies = _model_attempts(events, "model_reply_received")
    if request_attempts is None or event_replies is None:
        return None
    if not request_attempts or request_attempts != event_replies:
        return None

    audit_replies: Counter[tuple[int, str, str]] = Counter()
    total = 0.0
    for payload_json, raw_cost in rows:
        try:
            payload = json.loads(str(payload_json))
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        if payload.get("usage_reported") is not True or payload.get("cost_known") is not True:
            return None
        attempt = _model_attempt(payload)
        if attempt is None:
            return None
        audit_replies[attempt] += 1
        cost = _optional_float(raw_cost)
        payload_cost = _optional_float(payload.get("cost_usd"))
        if (
            cost is None
            or payload_cost is None
            or not _valid_cost(cost)
            or not _valid_cost(payload_cost)
            or not math.isclose(cost, payload_cost, rel_tol=1e-9, abs_tol=1e-9)
        ):
            return None
        total += cost
    if audit_replies != request_attempts or total == 0.0 or not _valid_cost(total):
        return None
    return round(total, 6)


def _reported_cost(  # noqa: PLR0911 - status/provenance combinations fail closed explicitly.
    case: dict[str, object],
    db_path: Path,
    events: list[dict[str, object]],
) -> tuple[float | None, str, str]:
    if "cost_status" in case:
        reported_status = str(case.get("cost_status") or "").strip().lower()
        if reported_status == "unknown":
            return (None, "unknown", "unavailable")
        if reported_status == "invalid":
            return (None, "invalid", "ravage_benchmark_report")
        if reported_status not in {"known", "reported", "computed_from_tokens"}:
            return (None, "invalid", "ravage_benchmark_report")
        parsed = _optional_float(case.get("cost_usd"))
        if parsed is None or not _valid_cost(parsed):
            return (None, "invalid", "ravage_benchmark_report")
        return (parsed, "reported", "ravage_benchmark_report")

    if "cost_usd" in case:
        case_cost = case.get("cost_usd")
        if case_cost is None or (isinstance(case_cost, str) and not case_cost.strip()):
            return (None, "unknown", "unavailable")
        parsed = _optional_float(case_cost)
        if parsed is None or not _valid_cost(parsed):
            return (None, "invalid", "ravage_benchmark_report")
        return (parsed, "reported", "ravage_benchmark_report")

    audit_cost = _legacy_audit_cost(db_path, events)
    if audit_cost is None:
        return (None, "unknown", "unavailable")
    return (audit_cost, "reported", "ravage_audit_log_legacy")


def _model_attempts(
    events: list[dict[str, object]],
    kind: str,
) -> Counter[tuple[int, str, str]] | None:
    attempts: Counter[tuple[int, str, str]] = Counter()
    for event in events:
        if event.get("kind") != kind:
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            return None
        attempt = _model_attempt(payload)
        if attempt is None:
            return None
        attempts[attempt] += 1
    return attempts


def _model_attempt(payload: dict[str, object]) -> tuple[int, str, str] | None:
    turn = payload.get("turn")
    if isinstance(turn, bool):
        return None
    try:
        turn_number = int(str(turn))
    except (TypeError, ValueError):
        return None
    provider = str(payload.get("provider") or "").strip()
    model = str(payload.get("model") or "").strip()
    if turn_number < 1 or not provider or not model:
        return None
    return (turn_number, provider, model)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def _phases(events: list[dict[str, object]]) -> list[dict[str, object]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"events": 0, "turns": 0})
    seen_turns: set[tuple[str, int]] = set()
    for event in events:
        if event.get("kind") != "kill_chain_stage":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        stage_id = str(payload.get("stage_id") or "unknown")
        counts[stage_id]["events"] += 1
        turn = _int_value(payload.get("turn"))
        if turn and (stage_id, turn) not in seen_turns:
            seen_turns.add((stage_id, turn))
            counts[stage_id]["turns"] += 1
    return [
        {
            "name": f"ravage_kill_chain:{stage_id}",
            "stage_id": stage_id,
            "events": values["events"],
            "turns": values["turns"],
        }
        for stage_id, values in sorted(counts.items())
    ]


def _events_with_kinds(
    events: list[dict[str, object]],
    kinds: frozenset[str],
) -> list[dict[str, object]]:
    return [event for event in events if event.get("kind") in kinds]


def _sum_payload_int(events: list[dict[str, object]], key: str) -> int:
    total = 0
    for event in events:
        payload = event.get("payload")
        if isinstance(payload, dict):
            total += max(_int_value(payload.get(key)), 0)
    return total


def _int_value(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default


def _float_value(value: object, default: float = 0.0) -> float:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str) and value.strip():
        return float(value)
    return default


def _optional_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except (OverflowError, ValueError):
            return None
    return None


def _valid_cost(value: float) -> bool:
    return math.isfinite(value) and value >= 0.0


def _dedupe(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)
