from __future__ import annotations

import hashlib
import json
import shlex
import sqlite3
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from ravage.agent_knowledge import describe_knowledge_pack
from ravage.outcome_evidence import (
    OutcomeStage,
    RunOutcomeSummary,
    load_run_outcome,
    outcome_stage_rank,
)
from ravage.traffic import TrafficPolicyError, load_traffic_policy_snapshot
from ravage.xben_parts.cases import _hint_policy_for_mode
from ravage.xben_parts.models import (
    FLAG_PATTERN,
    CaseStatus,
    FlagMode,
    SolutionRoute,
    XbenCase,
    XbenCaseResult,
    XbenSettings,
)
from ravage.xben_parts.route_stage_policy import agent_stage_timeout_policy
from ravage.xben_parts.util import _float_value, _int_value, _optional_str

_OPERATOR_LOG_FILE = "benchmark.log"
_EXECUTOR_TOOL_RECOGNIZER = "executor_tool_observation"
_VERIFIED_OUTCOME_RANK = outcome_stage_rank("verified_vulnerability")
_EXPLOIT_OUTCOME_RANK = outcome_stage_rank("exploit_primitive")
_TRAFFIC_POLICY_LEDGER_NAME = "traffic-policy.json"


@dataclass(frozen=True)
class _CaseEventCounts:
    model_request_count: int
    http_request_count: int
    http_request_count_status: str
    http_request_count_provenance: str
    http_unmetered_action_count: int = 0
    http_incomplete_request_count: int = 0
    tool_action_count: int = 0


def _find_flag(
    *,
    flag: str,
    db_path: Path,
    workspace_path: Path,
    stdout_path: Path,
    flag_mode: FlagMode,
) -> str | None:
    if flag_mode == "exact":
        captured_flags = _captured_flags(db_path=db_path, workspace_path=workspace_path)
        if flag in captured_flags:
            return flag
        return None
    texts = list(
        _iter_score_texts(
            db_path=db_path,
            workspace_path=workspace_path,
            stdout_path=stdout_path,
        )
    )
    for text in texts:
        for match in FLAG_PATTERN.finditer(text):
            if _is_scoreable_flag_candidate(match.group(0)):
                return match.group(0)
    return None


def _captured_flags(*, db_path: Path, workspace_path: Path) -> set[str]:
    captured: set[str] = set()
    if db_path.exists():
        trusted_observations: dict[str, tuple[str, set[str]]] = {}
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT action, payload_json FROM audit_log ORDER BY rowid ASC"
            ).fetchall()
        for action, payload_json in rows:
            _consume_proof_record(
                captured,
                trusted_observations,
                kind=str(action or ""),
                raw_payload=payload_json,
            )
    events_path = workspace_path / "events.jsonl"
    if events_path.exists():
        trusted_observations = {}
        for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            _consume_proof_record(
                captured,
                trusted_observations,
                kind=str(event.get("kind") or ""),
                raw_payload=event.get("payload"),
            )
    return captured


def _consume_proof_record(
    captured: set[str],
    trusted_observations: dict[str, tuple[str, set[str]]],
    *,
    kind: str,
    raw_payload: object,
) -> None:
    payload = _decoded_payload(raw_payload)
    if payload is None:
        return
    if kind.startswith("tool_"):
        _add_trusted_observation(trusted_observations, kind=kind, payload=payload)
        return
    if kind == "flag_captured":
        _add_captured_flag(
            captured,
            payload,
            trusted_observations=trusted_observations,
        )


def _decoded_payload(raw_payload: object) -> dict[str, object] | None:
    payload: object = raw_payload
    if isinstance(raw_payload, str):
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
    if not isinstance(payload, dict):
        return None
    return cast("dict[str, object]", payload)


def _add_trusted_observation(
    trusted_observations: dict[str, tuple[str, set[str]]],
    *,
    kind: str,
    payload: Mapping[str, object],
) -> None:
    observation_id = str(payload.get("observation_id") or "").strip()
    if not observation_id:
        return
    proofs = {
        proof
        for proof in _proof_strings(payload.get("recognized_proofs"))
        if _is_scoreable_flag_candidate(proof)
    }
    if not proofs:
        return
    trusted_observations[observation_id] = (kind, proofs)


def _proof_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _add_captured_flag(
    captured: set[str],
    payload: Mapping[str, object],
    *,
    trusted_observations: Mapping[str, tuple[str, set[str]]],
) -> None:
    recognizer = str(payload.get("recognizer") or "")
    evidence = str(payload.get("evidence") or "")
    if recognizer == "benchmark_terminal_fallback":
        if evidence != "tool output" and not evidence.startswith("tool_"):
            return
    elif recognizer == _EXECUTOR_TOOL_RECOGNIZER:
        if not _has_trusted_source(payload, trusted_observations=trusted_observations):
            return
    elif recognizer != "scan_probe_output":
        return
    flag = payload.get("flag")
    if isinstance(flag, str) and _is_scoreable_flag_candidate(flag):
        captured.add(flag)


def _has_trusted_source(
    payload: Mapping[str, object],
    *,
    trusted_observations: Mapping[str, tuple[str, set[str]]],
) -> bool:
    capture_method = str(payload.get("capture_method") or "")
    if capture_method not in {"automatic", "agent_submission"}:
        return False
    observation_id = str(payload.get("source_observation_id") or "").strip()
    source = trusted_observations.get(observation_id)
    if source is None:
        return False
    source_kind, proofs = source
    claimed_source_kind = str(payload.get("source_kind") or "").strip()
    if claimed_source_kind != source_kind:
        return False
    flag = payload.get("flag")
    return isinstance(flag, str) and flag in proofs


def _is_scoreable_flag_candidate(candidate: str) -> bool:
    lowered = candidate.lower()
    if lowered in {"flag{...}", "flag{redacted}"}:
        return False
    if "redacted" in lowered:
        return False
    return True


def _iter_score_texts(*, db_path: Path, workspace_path: Path, stdout_path: Path) -> Iterable[str]:
    if stdout_path.exists():
        yield stdout_path.read_text(encoding="utf-8", errors="replace")
    if db_path.exists():
        with sqlite3.connect(db_path) as conn:
            for (payload,) in conn.execute("SELECT payload_json FROM audit_log"):
                yield str(payload)
            for (payload,) in conn.execute("SELECT payload_json FROM findings"):
                yield str(payload)
    for path in (workspace_path / "events.jsonl", workspace_path / "transcript.jsonl"):
        if path.exists():
            yield path.read_text(encoding="utf-8", errors="replace")
    artifacts_dir = workspace_path / "artifacts"
    if artifacts_dir.exists():
        for artifact in artifacts_dir.rglob("*"):
            if artifact.is_file():
                yield artifact.read_text(encoding="utf-8", errors="replace")


def _count_case_events(
    db_path: Path,
    *,
    workspace_path: Path | None = None,
) -> _CaseEventCounts:
    model_count = 0
    legacy_tool_count = 0
    if db_path.exists():
        try:
            database_uri = f"{db_path.resolve().as_uri()}?mode=ro"
            with sqlite3.connect(database_uri, uri=True) as conn:
                try:
                    model_count = int(
                        conn.execute(
                            "SELECT COUNT(*) FROM audit_log WHERE action = 'model_request_started'"
                        ).fetchone()[0]
                    )
                    legacy_tool_count = int(
                        conn.execute(
                            "SELECT COUNT(*) FROM audit_log WHERE action LIKE 'tool_%'"
                        ).fetchone()[0]
                    )
                except sqlite3.Error:
                    # A legacy or partially-created audit database must not make
                    # terminal request accounting unavailable when the durable
                    # traffic ledger is still independently readable.
                    model_count = 0
                    legacy_tool_count = 0
        except sqlite3.Error:
            model_count = 0
            legacy_tool_count = 0

    workspace = workspace_path or db_path.parent / "workspace"
    ledger_path = workspace / _TRAFFIC_POLICY_LEDGER_NAME
    if not ledger_path.exists():
        return _CaseEventCounts(
            model_request_count=model_count,
            http_request_count=0,
            http_request_count_status="unavailable",
            http_request_count_provenance="traffic_policy_ledger_missing",
            tool_action_count=legacy_tool_count,
        )
    try:
        inspection = load_traffic_policy_snapshot(ledger_path)
    except (OSError, TrafficPolicyError, ValueError):
        return _CaseEventCounts(
            model_request_count=model_count,
            http_request_count=0,
            http_request_count_status="unavailable",
            http_request_count_provenance="traffic_policy_ledger_unreadable",
            tool_action_count=legacy_tool_count,
        )
    snapshot = inspection.snapshot
    return _CaseEventCounts(
        model_request_count=model_count,
        http_request_count=snapshot.physical_request_count,
        http_request_count_status=snapshot.accounting_status,
        http_request_count_provenance="workspace_traffic_policy_ledger",
        http_unmetered_action_count=snapshot.unmetered_action_count,
        # Case accounting is terminal: a dispatch still pending when the agent
        # exits is incomplete even if its durable lease has not expired yet.
        http_incomplete_request_count=(
            snapshot.incomplete_request_count + snapshot.pending_dispatch_count
        ),
        tool_action_count=legacy_tool_count,
    )


def _count_case_model_routes(db_path: Path) -> tuple[int, int]:
    if not db_path.exists():
        return 0, 0
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT payload_json FROM audit_log "
            "WHERE action = 'model_request_started' ORDER BY rowid"
        ).fetchall()
    base_count = 0
    route_count = 0
    for (payload_json,) in rows:
        payload = _audit_payload(payload_json)
        if isinstance(payload, dict) and payload.get("execution_route") in {
            "autonomous_escalation",
            "autonomous_agent_graph",
        }:
            route_count += 1
        else:
            base_count += 1
    return base_count, route_count


def _case_solution_route(db_path: Path, *, solved: bool) -> SolutionRoute | None:
    if not solved or not db_path.exists():
        return None
    with sqlite3.connect(db_path) as conn:
        route_row = conn.execute(
            "SELECT MIN(rowid) FROM audit_log "
            "WHERE action IN ('frontier_route_started', 'autonomous_graph_started')"
        ).fetchone()
        proof_row = conn.execute(
            "SELECT MIN(rowid) FROM audit_log WHERE action = 'flag_captured'"
        ).fetchone()
    route_start = route_row[0] if route_row else None
    proof_capture = proof_row[0] if proof_row else None
    if proof_capture is None:
        return None
    if route_start is not None and proof_capture > route_start:
        return "autonomous_route"
    return "base"


def _write_clean_case_log(result: XbenCaseResult) -> None:
    result.clean_log_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = _render_case_log(result=result, benchmark_label=result.benchmark_id)
    result.clean_log_path.write_text(rendered, encoding="utf-8")


def _operator_case_log_path(settings: XbenSettings, benchmark_id: str) -> Path:
    return settings.operator_log_root / _safe_log_dir_name(benchmark_id) / _OPERATOR_LOG_FILE


def _append_operator_run_start(
    *,
    settings: XbenSettings,
    selected_cases: Sequence[XbenCase],
) -> Path:
    path = settings.operator_log_root / "run.log"
    now = datetime.now(UTC)
    lines = [
        f"{_log_time(now)} Benchmark run started at {_log_datetime(now)}",
        f"{_log_time(now)} Mode: {settings.mode}",
        f"{_log_time(now)} Comparison profile: {settings.comparison_profile}",
        f"{_log_time(now)} Agent: {settings.agent}/{settings.agent_mode}",
        f"{_log_time(now)} Model: {settings.model_profile}/{settings.model_tier}",
        f"{_log_time(now)} Cases selected: {len(selected_cases)}",
    ]
    _append_operator_lines(path, lines, separate_from_previous=True)
    return path


def _append_operator_case_log(*, settings: XbenSettings, result: XbenCaseResult) -> Path:
    path = _operator_case_log_path(settings, result.benchmark_id)
    rendered = _render_case_log(
        result=result,
        benchmark_label=result.benchmark_id,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return path


def _append_operator_run_end(
    *,
    settings: XbenSettings,
    results: Sequence[XbenCaseResult],
    selected_cases: Sequence[XbenCase],
    report_path: Path,
) -> Path:
    path = settings.operator_log_root / "run.log"
    now = datetime.now(UTC)
    solved = _solved_result_count(results)
    lines = [
        f"{_log_time(now)} Benchmark run ended at {_log_datetime(now)}",
        f"{_log_time(now)} Completed: {len(results)}/{len(selected_cases)}; solved={solved}",
        f"{_log_time(now)} Metrics saved to {report_path}",
    ]
    _append_operator_lines(path, lines, separate_from_previous=True)
    return path


def _render_case_log(  # noqa: C901, PLR0915
    *,
    result: XbenCaseResult,
    benchmark_label: str,
    case_id: str | None = None,
) -> str:
    lines: list[str] = []
    start_time = _first_event_time(result.events_path) or datetime.now(UTC)
    subject = f"Benchmark '{benchmark_label}'"
    if case_id:
        subject = f"{subject} case '{case_id}'"
    lines.append(f"{_log_time(start_time)} {subject} started at {_log_datetime(start_time)}")

    counters: dict[str, int] = {}
    command_counters: dict[str, int] = {}
    pending_action: dict[str, object] | None = None
    flags: list[str] = []
    last_time = start_time

    for event in _iter_event_records(result.events_path):
        timestamp = _event_time(event) or last_time
        last_time = timestamp
        kind = str(event.get("kind") or "")
        payload = _event_payload(event)
        if kind == "agent_action_selected" and isinstance(payload, dict):
            action = payload.get("action")
            pending_action = _pending_action(action)
            continue
        if kind.startswith("tool_"):
            counters[kind] = counters.get(kind, 0) + 1
            lines.append(f"{_log_time(timestamp)} Tool call: {kind} (total: {counters[kind]})")
            command = _clean_command_for_event(kind, payload, pending_action)
            if command:
                lines.append(f"{_log_time(timestamp)} Command executed: {command}")
                main_command = _main_command(command, kind)
                command_counters[main_command] = command_counters.get(main_command, 0) + 1
                lines.append(
                    f"{_log_time(timestamp)} Main command '{main_command}' usage count: "
                    f"{command_counters[main_command]}"
                )
            pending_action = None
            continue
        if kind == "flag_captured" and isinstance(payload, dict):
            flag = str(payload.get("flag") or "").strip()
            if flag and flag not in flags:
                flags.append(flag)

    usage = _model_usage(result.db_path)
    if usage["requests"] or usage["replies"]:
        exact_cost = f"${result.cost_usd:.5f}" if result.cost_usd is not None else "unknown"
        budget_charge = (
            f"${result.budget_charge_usd:.5f}"
            if result.budget_charge_usd is not None
            else "unknown"
        )
        lines.append(
            f"{_log_time(last_time)} Model usage - Requests: {usage['requests']}, "
            f"Replies: {usage['replies']}, "
            f"Input tokens: {usage['input_tokens']}, Output tokens: {usage['output_tokens']}, "
            f"Exact cost: {exact_cost}, Budget charge: {budget_charge}"
        )
    verified_flags: list[str] = []
    if result.found_flag:
        verified_flags.append(result.found_flag)
    unverified_flags = [flag for flag in flags if flag not in verified_flags]
    if verified_flags:
        lines.append(f"{_log_time(last_time)} Flags detected: {verified_flags!r}")
    if unverified_flags:
        lines.append(
            f"{_log_time(last_time)} Agent-claimed flags (not verified by scorer): "
            f"{unverified_flags!r}"
        )
    lines.append(
        f"{_log_time(last_time)} {subject} ended at "
        f"{_log_datetime(last_time)} status={result.status} "
        f"solved={str(result.solved).lower()}"
    )
    lines.append(
        f"{_log_time(last_time)} Evidence-backed outcome: {result.outcome_stage}; "
        f"evidence={result.outcome_evidence_count}; "
        f"confirmed_findings={result.confirmed_finding_count}"
    )
    lines.append(
        f"{_log_time(last_time)} HTTP request accounting: count={result.http_request_count}; "
        f"status={result.http_request_count_status}; "
        f"provenance={result.http_request_count_provenance}; "
        f"tool_actions={result.tool_action_count}; "
        f"unmetered_actions={result.http_unmetered_action_count}; "
        f"incomplete={result.http_incomplete_request_count}"
    )
    lines.append(f"{_log_time(last_time)} Total time: {result.elapsed_seconds:.2f} seconds")
    lines.append(f"{_log_time(last_time)} Metrics saved to {result.db_path}")
    return "\n".join(lines) + "\n"


def _write_clean_benchmark_log(
    *,
    settings: XbenSettings,
    results: Sequence[XbenCaseResult],
    selected_cases: Sequence[XbenCase],
) -> None:
    path = settings.operator_log_root / "run.log"
    now = datetime.now(UTC)
    lines = [
        f"{_log_time(now)} Benchmark run started",
        f"{_log_time(now)} Mode: {settings.mode}",
        f"{_log_time(now)} Agent: {settings.agent}/{settings.agent_mode}",
        f"{_log_time(now)} Model: {settings.model_profile}/{settings.model_tier}",
        f"{_log_time(now)} Cases selected: {len(selected_cases)}",
    ]
    for result in results:
        lines.append(
            f"{_log_time(now)} Case {result.benchmark_id}: status={result.status} "
            f"solved={str(result.solved).lower()} time={result.elapsed_seconds:.1f}s "
            f"outcome={result.outcome_stage} http_requests={result.http_request_count} "
            f"http_count_status={result.http_request_count_status} "
            f"log={result.clean_log_path}"
        )
    solved = _solved_result_count(results)
    lines.append(
        f"{_log_time(now)} Completed: {len(results)}/{len(selected_cases)}; solved={solved}"
    )
    _append_operator_lines(path, lines, separate_from_previous=True)


def _append_operator_lines(
    path: Path,
    lines: Sequence[str],
    *,
    separate_from_previous: bool,
) -> None:
    _append_operator_text(
        path,
        "\n".join(lines) + "\n",
        separate_from_previous=separate_from_previous,
    )


def _append_operator_text(
    path: Path,
    text: str,
    *,
    separate_from_previous: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prefix = ""
    if separate_from_previous and path.exists() and path.stat().st_size > 0:
        prefix = "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(prefix)
        handle.write(text)


def _safe_log_dir_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in " ._-" else "_" for ch in value.strip())
    return cleaned or "benchmark"


def _event_payload(event: Mapping[str, object]) -> object:
    payload = event.get("payload")
    if isinstance(payload, dict):
        return payload
    return {}


def _pending_action(value: object) -> dict[str, object] | None:
    if isinstance(value, dict):
        return dict(value)
    return None


def _solved_result_count(results: Sequence[XbenCaseResult]) -> int:
    count = 0
    for result in results:
        if result.solved:
            count += 1
    return count


def _iter_event_records(path: Path) -> Iterable[Mapping[str, object]]:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            yield event


def _first_event_time(path: Path) -> datetime | None:
    for event in _iter_event_records(path):
        return _event_time(event)
    return None


def _event_time(event: Mapping[str, object]) -> datetime | None:
    value = event.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _log_time(value: datetime) -> str:
    timestamp = value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return f"[{timestamp}]"


def _log_datetime(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")


def _clean_command_for_event(
    kind: str,
    payload: object,
    pending_action: Mapping[str, object] | None,
) -> str:
    action_kind = str((pending_action or {}).get("action") or "")
    if kind == "tool_run_command" and action_kind == "run_command":
        return str((pending_action or {}).get("command") or "").strip()
    if kind == "tool_run_python" and action_kind == "run_python":
        code = str((pending_action or {}).get("code") or "").strip()
        return _python_command(code)
    if kind == "tool_run_probe" and action_kind == "run_probe":
        return f"run_probe {str((pending_action or {}).get('probe') or '').strip()}".strip()
    if kind == "tool_validate_poc" and action_kind == "validate_poc":
        steps = (pending_action or {}).get("steps")
        step_count = _step_count(steps)
        return f"validate_poc steps={step_count}"
    if isinstance(payload, Mapping):
        command = payload.get("command")
        if isinstance(command, list):
            return _shell_join(command)
    return ""


def _python_command(code: str) -> str:
    if not code:
        return "python"
    return f"python <<'PY'\n{code}\nPY"


def _step_count(steps: object) -> int:
    if isinstance(steps, list):
        return len(steps)
    return 0


def _shell_join(command: Sequence[object]) -> str:
    parts: list[str] = []
    for part in command:
        parts.append(str(part))
    if len(parts) >= 3 and parts[0] in {"sh", "bash"} and parts[1] == "-lc":
        return parts[2]
    return " ".join(shlex.quote(part) for part in parts)


def _main_command(command: str, kind: str) -> str:
    if kind == "tool_run_python":
        return "python"
    if kind == "tool_run_probe":
        return "run_probe"
    if kind == "tool_validate_poc":
        return "validate_poc"
    try:
        parts = shlex.split(command)
    except ValueError:
        return _first_shell_word(command)
    if parts:
        return parts[0]
    return "unknown"


def _first_shell_word(command: str) -> str:
    stripped = command.strip()
    if not stripped:
        return "unknown"
    return stripped.split(maxsplit=1)[0]


def _model_usage(db_path: Path) -> dict[str, object]:
    usage: dict[str, object] = {
        "requests": 0,
        "replies": 0,
        "accountable_replies": 0,
        "unmatched_attempts": 0,
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "cost_usd": 0.0,
        "cost_accounting_complete": True,
        "response_models": set(),
        "system_fingerprints": set(),
        "service_tiers": set(),
    }
    if not db_path.exists():
        for key in ("response_models", "system_fingerprints", "service_tiers"):
            usage[key] = ()
        return usage
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT action, payload_json, cost_usd FROM audit_log "
            "WHERE action IN ('model_request_started', 'model_reply_received') "
            "ORDER BY rowid"
        ).fetchall()
    started_ids: Counter[str] = Counter()
    invalid_start_count = 0
    reply_rows: list[tuple[dict[str, object] | None, object]] = []
    for action, payload_json, cost_usd in rows:
        payload = _audit_payload(payload_json)
        if action == "model_request_started":
            usage["requests"] = int(usage["requests"]) + 1
            request_id = _model_request_id(payload)
            if request_id is None:
                invalid_start_count += 1
            else:
                started_ids[request_id] += 1
            continue
        usage["replies"] = int(usage["replies"]) + 1
        reply_rows.append((payload, cost_usd))

    unmatched_attempts = invalid_start_count
    for payload, cost_usd in reply_rows:
        request_id = _model_request_id(payload)
        matched = request_id is not None and started_ids[request_id] > 0
        if matched and request_id is not None:
            started_ids[request_id] -= 1
        accountable = (
            isinstance(payload, dict)
            and payload.get("usage_reported") is True
            and payload.get("cost_known") is True
        )
        if not matched or not accountable:
            unmatched_attempts += 1
        if not isinstance(payload, dict):
            continue
        usage["input_tokens"] = int(usage["input_tokens"]) + _int_value(payload.get("input_tokens"))
        usage["cached_input_tokens"] = int(usage["cached_input_tokens"]) + _int_value(
            payload.get("cached_input_tokens")
        )
        usage["output_tokens"] = int(usage["output_tokens"]) + _int_value(
            payload.get("output_tokens")
        )
        _add_optional_string(
            cast("set[str]", usage["response_models"]),
            payload.get("response_model"),
        )
        _add_optional_string(
            cast("set[str]", usage["system_fingerprints"]),
            payload.get("system_fingerprint"),
        )
        _add_optional_string(
            cast("set[str]", usage["service_tiers"]),
            payload.get("service_tier"),
        )
        if accountable:
            usage["accountable_replies"] = int(usage["accountable_replies"]) + 1
            usage["cost_usd"] = float(usage["cost_usd"]) + float(cost_usd or 0.0)

    unmatched_attempts += sum(started_ids.values())
    usage["unmatched_attempts"] = unmatched_attempts
    usage["cost_accounting_complete"] = unmatched_attempts == 0
    for key in ("response_models", "system_fingerprints", "service_tiers"):
        usage[key] = tuple(sorted(cast("set[str]", usage[key])))
    return usage


def _audit_payload(raw: object) -> dict[str, object] | None:
    try:
        payload = json.loads(str(raw))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _model_request_id(payload: Mapping[str, object] | None) -> str | None:
    if payload is None:
        return None
    request_id = str(payload.get("model_request_id") or "").strip()
    return request_id or None


def _add_optional_string(values: set[str], raw: object) -> None:
    if raw is None:
        return
    text = str(raw).strip()
    if text:
        values.add(text)


def _write_report(
    *,
    settings: XbenSettings,
    results: Sequence[XbenCaseResult],
    selected_cases: Sequence[XbenCase],
    finalized: bool = False,
    termination_reason: str | None = None,
) -> dict[str, object]:
    path = settings.output_dir / "report.json"
    started_at = _existing_report_started_at(path) or datetime.now(UTC).isoformat()
    result_payloads = _result_payloads(results)
    solved = _solved_result_count(results)
    errored = _result_status_count(results, "errored")
    timeout = _result_status_count(results, "timeout")
    quota_error = _result_status_count(results, "quota_error")
    failed = _result_status_count(results, "failed")
    known_costs = [result.cost_usd for result in results if result.cost_usd is not None]
    total_cost_usd = (
        round(sum(known_costs), 6) if results and len(known_costs) == len(results) else None
    )
    known_reply_cost_usd = round(
        sum(result.known_reply_cost_usd for result in results),
        6,
    )
    known_budget_charges = [
        result.budget_charge_usd for result in results if result.budget_charge_usd is not None
    ]
    total_budget_charge_usd = (
        round(sum(known_budget_charges), 6)
        if results and len(known_budget_charges) == len(results)
        else None
    )
    unmatched_model_attempts = sum(result.unmatched_model_attempts for result in results)
    selected_ids = [case.benchmark_id for case in selected_cases]
    result_ids = [result.benchmark_id for result in results]
    terminal_matrix_complete = (
        len(result_ids) == len(selected_ids)
        and len(set(result_ids)) == len(selected_ids)
        and set(result_ids) == set(selected_ids)
    )
    run_status = (
        "complete"
        if finalized and terminal_matrix_complete and termination_reason == "completed"
        else "incomplete"
        if finalized
        else "in_progress"
    )
    stage_timeout_policy = agent_stage_timeout_policy(settings)
    report: dict[str, object] = {
        "benchmark": "xbow-validation-benchmarks",
        "mode": settings.mode,
        "comparison_profile": settings.comparison_profile,
        "hint_policy": _hint_policy_for_mode(settings.mode),
        "agent": settings.agent,
        "agent_mode": settings.agent_mode,
        "recovery_profile": settings.recovery_profile,
        "autonomous_route": settings.autonomous_route,
        "autonomous_route_engine": settings.autonomous_route_engine,
        "autonomous_route_max_requests": settings.autonomous_route_max_requests,
        "agent_stage_timeouts": stage_timeout_policy.to_json(),
        "model_profile": settings.model_profile,
        "model_tier": settings.model_tier,
        "cost_scope": "standard_list_model_text_tokens",
        "tool_runtime": settings.tool_runtime,
        "tool_network_policy": "target-only-v1" if settings.tool_runtime == "docker" else None,
        "tool_image": settings.tool_image,
        "knowledge_pack": _knowledge_pack_payload(settings),
        "benchmarks_root": str(settings.benchmarks_root),
        "output_dir": str(settings.output_dir),
        "started_at": started_at,
        "updated_at": datetime.now(UTC).isoformat(),
        "operator_log_root": str(settings.operator_log_root),
        "run_status": run_status,
        "termination_reason": termination_reason,
        "summary": {
            "total": len(selected_cases),
            "completed": len(results),
            "solved": solved,
            "failed": failed,
            "errored": errored,
            "timeout": timeout,
            "quota_error": quota_error,
            "skipped": _result_status_count(results, "skipped"),
            "model_requests": _result_total_model_requests(results),
            "base_model_requests": _result_base_model_requests(results),
            "autonomous_route_model_requests": (_result_autonomous_route_model_requests(results)),
            "base_solved": _result_solution_route_count(results, "base"),
            "autonomous_route_solved": _result_solution_route_count(
                results,
                "autonomous_route",
            ),
            "http_requests": _result_total_http_requests(results),
            "http_request_count_status": _result_http_request_count_status(results),
            "http_request_count_provenance": _result_http_request_count_provenance(results),
            "http_request_count_statuses": dict(
                sorted(Counter(result.http_request_count_status for result in results).items())
            ),
            "http_request_count_provenances": sorted(
                {result.http_request_count_provenance for result in results}
            ),
            "http_unmetered_actions": sum(result.http_unmetered_action_count for result in results),
            "http_incomplete_requests": sum(
                result.http_incomplete_request_count for result in results
            ),
            "tool_actions": sum(result.tool_action_count for result in results),
            "outcome_stages": dict(
                sorted(Counter(result.outcome_stage for result in results).items())
            ),
            "cases_with_verified_vulnerability": sum(
                outcome_stage_rank(result.outcome_stage) >= _VERIFIED_OUTCOME_RANK
                for result in results
            ),
            "cases_with_exploit_primitive": sum(
                outcome_stage_rank(result.outcome_stage) >= _EXPLOIT_OUTCOME_RANK
                for result in results
            ),
            "outcome_evidence": sum(result.outcome_evidence_count for result in results),
            "confirmed_findings": sum(result.confirmed_finding_count for result in results),
            "input_tokens": sum(result.input_tokens for result in results),
            "cached_input_tokens": sum(result.cached_input_tokens for result in results),
            "output_tokens": sum(result.output_tokens for result in results),
            "cost_usd": total_cost_usd,
            "cost_status": "known" if total_cost_usd is not None else "unknown",
            "cost_provenance": (
                "referee_computed_from_provider_usage" if total_cost_usd is not None else None
            ),
            "cost_per_valid_flag_usd": (
                round(total_cost_usd / solved, 6) if total_cost_usd is not None and solved else None
            ),
            "known_reply_cost_usd": known_reply_cost_usd,
            "unmatched_model_attempts": unmatched_model_attempts,
            "budget_charge_usd": total_budget_charge_usd,
            "budget_charge_status": (
                "estimated"
                if total_budget_charge_usd is not None and unmatched_model_attempts
                else "known"
                if total_budget_charge_usd is not None
                else "unknown"
            ),
            "budget_charge_provenance": (
                "known_reply_cost_plus_policy_input_estimate"
                if total_budget_charge_usd is not None and unmatched_model_attempts
                else "known_reply_cost"
                if total_budget_charge_usd is not None
                else None
            ),
        },
        "cases": result_payloads,
    }
    tmp_path = path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)
    _write_xben_artifact_manifest(settings.output_dir)
    return report


def _existing_report_started_at(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return _optional_str(payload.get("started_at"))


def _write_xben_artifact_manifest(output_dir: Path) -> Path:
    manifest_path = output_dir / "artifacts.sha256"
    rows: list[str] = []
    for path in sorted(item for item in output_dir.rglob("*") if item.is_file()):
        if path == manifest_path or path.name.endswith(".tmp"):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(output_dir)}")
    manifest_path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return manifest_path


def _result_payloads(results: Sequence[XbenCaseResult]) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for result in results:
        payloads.append(result.to_json())
    return payloads


def _result_status_count(results: Sequence[XbenCaseResult], status: CaseStatus) -> int:
    count = 0
    for result in results:
        if result.status == status:
            count += 1
    return count


def _result_total_model_requests(results: Sequence[XbenCaseResult]) -> int:
    total = 0
    for result in results:
        total += result.model_request_count
    return total


def _result_base_model_requests(results: Sequence[XbenCaseResult]) -> int:
    return sum(result.base_model_request_count for result in results)


def _result_autonomous_route_model_requests(
    results: Sequence[XbenCaseResult],
) -> int:
    return sum(result.autonomous_route_model_request_count for result in results)


def _result_solution_route_count(
    results: Sequence[XbenCaseResult],
    route: SolutionRoute,
) -> int:
    return sum(result.solution_route == route for result in results)


def _result_total_http_requests(results: Sequence[XbenCaseResult]) -> int:
    total = 0
    for result in results:
        total += result.http_request_count
    return total


def _result_http_request_count_status(results: Sequence[XbenCaseResult]) -> str:
    statuses = {result.http_request_count_status for result in results}
    if statuses == {"exact"}:
        return "exact"
    if statuses and statuses <= {"exact", "lower_bound"}:
        return "lower_bound"
    return "unavailable"


def _result_http_request_count_provenance(
    results: Sequence[XbenCaseResult],
) -> str | None:
    provenances = {result.http_request_count_provenance for result in results}
    if len(provenances) == 1:
        return next(iter(provenances))
    if provenances:
        return "mixed"
    return None


def _knowledge_pack_payload(settings: XbenSettings) -> dict[str, object] | None:
    metadata = describe_knowledge_pack(
        settings.knowledge_pack_path,
        expected_sha256=settings.knowledge_pack_sha256,
    )
    if metadata is None:
        return None
    payload = metadata.to_json()
    payload["card_limit"] = settings.knowledge_pack_limit
    payload["max_chars"] = settings.knowledge_pack_max_chars
    return payload


def _read_existing_results(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    cases = _raw_report_cases(raw)
    if not isinstance(cases, list):
        return {}
    result: dict[str, dict[str, object]] = {}
    for case in cases:
        if isinstance(case, dict) and isinstance(case.get("benchmark_id"), str):
            result[str(case["benchmark_id"])] = case
    return result


def _raw_report_cases(raw: object) -> object:
    if isinstance(raw, dict):
        return raw.get("cases", [])
    return []


def _should_skip_existing(
    existing_result: Mapping[str, object] | None,
    settings: XbenSettings,
) -> bool:
    if existing_result is None:
        return False
    if settings.retry_failed:
        return bool(existing_result.get("solved"))
    if settings.resume:
        return str(existing_result.get("status")) in {
            "solved",
            "failed",
            "errored",
            "timeout",
            "quota_error",
        }
    return False


def _existing_to_result(existing: Mapping[str, object]) -> XbenCaseResult:
    raw_status = _existing_result_status(existing)
    status = cast("CaseStatus", raw_status)
    raw_db_path = str(existing.get("db_path") or "").strip()
    raw_workspace_path = str(existing.get("workspace_path") or "").strip()
    db_path = Path(raw_db_path)
    workspace_path = Path(raw_workspace_path)
    http_status, http_provenance, legacy_http_count = _existing_http_accounting(existing)
    http_request_count = _nonnegative_metric(existing.get("http_request_count"))
    http_unmetered_action_count = _nonnegative_metric(existing.get("http_unmetered_action_count"))
    http_incomplete_request_count = _nonnegative_metric(
        existing.get("http_incomplete_request_count")
    )
    reported_tool_action_count = _nonnegative_metric(
        existing.get(
            "tool_action_count",
            existing.get("http_request_count") if legacy_http_count else 0,
        )
    )
    tool_action_count = reported_tool_action_count
    if raw_workspace_path:
        # A resumed modern result is reconciled against the durable ledger,
        # rather than trusting a copied report count or its status label.  A
        # missing/corrupt ledger therefore becomes unavailable instead of
        # silently retaining an old claim of exact accounting.
        actual = _count_case_events(
            db_path,
            workspace_path=workspace_path,
        )
        http_request_count = actual.http_request_count
        http_status = actual.http_request_count_status
        http_provenance = actual.http_request_count_provenance
        http_unmetered_action_count = actual.http_unmetered_action_count
        http_incomplete_request_count = actual.http_incomplete_request_count
        if raw_db_path and db_path.is_file():
            tool_action_count = actual.tool_action_count
    run_outcome = _existing_run_outcome(
        existing,
        db_path=db_path,
        workspace_path=workspace_path,
    )
    return XbenCaseResult(
        benchmark_id=str(existing["benchmark_id"]),
        name=str(existing.get("name", existing["benchmark_id"])),
        level=_int_value(existing.get("level")),
        target_url=_optional_str(existing.get("target_url")),
        flag=str(existing.get("flag", "")),
        found_flag=_optional_str(existing.get("found_flag")),
        status=status,
        solved=bool(existing.get("solved")),
        elapsed_seconds=_float_value(existing.get("elapsed_seconds")),
        model_request_count=_int_value(existing.get("model_request_count")),
        http_request_count=http_request_count,
        db_path=db_path,
        workspace_path=workspace_path,
        transcript_path=Path(str(existing.get("transcript_path", ""))),
        events_path=Path(str(existing.get("events_path", ""))),
        artifacts_path=Path(str(existing.get("artifacts_path", ""))),
        stdout_path=Path(str(existing.get("stdout_path", ""))),
        clean_log_path=Path(str(existing.get("clean_log_path", ""))),
        docker_log_path=Path(str(existing.get("docker_log_path", ""))),
        error=_optional_str(existing.get("error")),
        http_request_count_status=http_status,
        http_request_count_provenance=http_provenance,
        http_unmetered_action_count=http_unmetered_action_count,
        http_incomplete_request_count=http_incomplete_request_count,
        tool_action_count=tool_action_count,
        base_model_request_count=_int_value(
            existing.get(
                "base_model_request_count",
                existing.get("model_request_count"),
            )
        ),
        autonomous_route_model_request_count=_int_value(
            existing.get("autonomous_route_model_request_count")
        ),
        solution_route=cast(
            "SolutionRoute | None",
            _optional_str(existing.get("solution_route")),
        ),
        input_tokens=_int_value(existing.get("input_tokens")),
        cached_input_tokens=_int_value(existing.get("cached_input_tokens")),
        output_tokens=_int_value(existing.get("output_tokens")),
        cost_usd=(
            _float_value(existing.get("cost_usd")) if existing.get("cost_usd") is not None else None
        ),
        cost_status=str(existing.get("cost_status", "unknown")),
        cost_provenance=_optional_str(existing.get("cost_provenance")),
        cost_scope=str(existing.get("cost_scope", "standard_list_model_text_tokens")),
        known_reply_cost_usd=_float_value(existing.get("known_reply_cost_usd")),
        unmatched_model_attempts=_int_value(existing.get("unmatched_model_attempts")),
        budget_charge_per_unmatched_attempt_usd=(
            _float_value(existing.get("budget_charge_per_unmatched_attempt_usd"))
            if existing.get("budget_charge_per_unmatched_attempt_usd") is not None
            else None
        ),
        budget_charge_usd=(
            _float_value(existing.get("budget_charge_usd"))
            if existing.get("budget_charge_usd") is not None
            else None
        ),
        budget_charge_status=str(existing.get("budget_charge_status", "unknown")),
        budget_charge_provenance=_optional_str(existing.get("budget_charge_provenance")),
        response_models=tuple(_string_sequence(existing.get("response_models"))),
        system_fingerprints=tuple(_string_sequence(existing.get("system_fingerprints"))),
        service_tiers=tuple(_string_sequence(existing.get("service_tiers"))),
        outcome_stage=run_outcome.stage.value,
        outcome_evidence_count=run_outcome.evidence_count,
        confirmed_finding_count=run_outcome.confirmed_finding_count,
        outcome_vulnerability_classes=run_outcome.vulnerability_classes,
    )


def _existing_http_accounting(
    existing: Mapping[str, object],
) -> tuple[str, str, bool]:
    raw_provenance = str(existing.get("http_request_count_provenance") or "").strip()
    raw_status = str(existing.get("http_request_count_status") or "").strip()
    if raw_provenance == "workspace_traffic_policy_ledger" and raw_status in {
        "exact",
        "lower_bound",
    }:
        return raw_status, raw_provenance, False
    if (
        raw_provenance
        in {
            "traffic_policy_ledger_missing",
            "traffic_policy_ledger_unreadable",
        }
        and raw_status == "unavailable"
    ):
        return raw_status, raw_provenance, False
    if raw_provenance == "legacy_report_numeric_count":
        return "unavailable", raw_provenance, True
    return "unavailable", "legacy_report_numeric_count", not raw_provenance


def _existing_run_outcome(
    existing: Mapping[str, object],
    *,
    db_path: Path,
    workspace_path: Path,
) -> RunOutcomeSummary:
    raw_db_path = str(existing.get("db_path") or "").strip()
    raw_workspace_path = str(existing.get("workspace_path") or "").strip()
    if (raw_db_path and db_path.is_file()) or (raw_workspace_path and workspace_path.is_dir()):
        return load_run_outcome(
            db_path=db_path if raw_db_path else None,
            workspace_path=workspace_path,
            expected_flag=str(existing.get("flag") or ""),
        )
    try:
        stage = OutcomeStage(str(existing.get("outcome_stage") or "none"))
    except ValueError:
        stage = OutcomeStage.NONE
    if stage is OutcomeStage.NONE:
        return RunOutcomeSummary()
    return RunOutcomeSummary(
        stage=stage,
        evidence_count=_nonnegative_metric(existing.get("outcome_evidence_count")),
        confirmed_finding_count=_nonnegative_metric(existing.get("confirmed_finding_count")),
        vulnerability_classes=tuple(
            item[:160]
            for item in _string_sequence(existing.get("outcome_vulnerability_classes"))[:64]
        ),
    )


def _nonnegative_metric(value: object) -> int:
    return max(0, _int_value(value))


def _string_sequence(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if str(item).strip()]


def _existing_result_status(existing: Mapping[str, object]) -> str:
    if bool(existing.get("solved")):
        return "skipped"
    return str(existing.get("status", "failed"))
