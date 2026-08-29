from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

TRACE_SCHEMA_VERSION = "ravage.trace.v1"

_MODEL_REPLY_KINDS = {"model_reply", "model_reply_received"}
_INVALID_ACTION_KINDS = {"invalid_action", "invalid_model_action"}


@dataclass(frozen=True)
class TraceSummary:
    payload: dict[str, object]

    def to_json(self) -> dict[str, object]:
        return dict(self.payload)


def summarize_workspace_trace(workspace_dir: Path) -> TraceSummary:
    events_path = workspace_dir / "events.jsonl"
    transcript_path = workspace_dir / "transcript.jsonl"
    events = _read_jsonl(events_path)
    transcript = _read_jsonl(transcript_path)
    events_present = events_path.exists()
    transcript_present = transcript_path.exists()

    payload: dict[str, object] = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "events_present": events_present,
        "transcript_present": transcript_present,
        "turns_total": _turns_total(events, events_present=events_present),
        "model_calls": _model_calls(events, events_present=events_present),
        "tool_calls": _event_count(
            events,
            events_present=events_present,
            predicate=lambda kind: kind.startswith("tool_"),
        ),
        "assistant_messages": _transcript_role_count(
            transcript,
            transcript_present=transcript_present,
            roles={"assistant"},
        ),
        "observations": _transcript_role_count(
            transcript,
            transcript_present=transcript_present,
            roles={"tool", "user"},
        ),
        "invalid_actions": _event_count(
            events,
            events_present=events_present,
            predicate=lambda kind: kind in _INVALID_ACTION_KINDS,
        ),
        "findings_confirmed": _event_count(
            events,
            events_present=events_present,
            predicate=lambda kind: kind == "finding_confirmed",
        ),
        "flags_captured": _event_count(
            events,
            events_present=events_present,
            predicate=lambda kind: kind == "flag_captured",
        ),
        "termination_status": _termination_status(events),
        "parse_errors": _parse_error_count(events) + _parse_error_count(transcript),
        "artifact_paths": _artifact_paths(workspace_dir),
    }
    return TraceSummary(payload)


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if not path.exists():
        return rows
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return [{"_parse_error": True}]
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            rows.append({"_parse_error": True})
            continue
        if isinstance(item, dict):
            rows.append(item)
        else:
            rows.append({"_parse_error": True})
    return rows


def _turns_total(events: list[dict[str, object]], *, events_present: bool) -> int | None:
    if not events_present or not events:
        return None
    turns = [_event_turn(event) for event in events]
    return max(turns, default=0)


def _event_turn(event: dict[str, object]) -> int:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return 0
    return _int(payload.get("turn"))


def _model_calls(events: list[dict[str, object]], *, events_present: bool) -> int | None:
    if not events_present:
        return None
    request_count = sum(1 for event in events if event.get("kind") == "model_request_started")
    if request_count:
        return request_count
    return sum(1 for event in events if event.get("kind") in _MODEL_REPLY_KINDS)


def _event_count(
    events: list[dict[str, object]],
    *,
    events_present: bool,
    predicate: Callable[[str], bool],
) -> int | None:
    if not events_present:
        return None
    return sum(1 for event in events if predicate(str(event.get("kind") or "")))


def _transcript_role_count(
    transcript: list[dict[str, object]],
    *,
    transcript_present: bool,
    roles: set[str],
) -> int | None:
    if not transcript_present:
        return None
    return sum(1 for item in transcript if str(item.get("role") or "") in roles)


def _termination_status(events: list[dict[str, object]]) -> str | None:
    for event in reversed(events):
        if event.get("kind") != "run_completed":
            continue
        payload = event.get("payload")
        if isinstance(payload, dict):
            status = str(payload.get("status") or "")
            if status:
                return status
        return "completed"
    return None


def _parse_error_count(rows: list[dict[str, object]]) -> int:
    return sum(1 for item in rows if item.get("_parse_error") is True)


def _artifact_paths(workspace_dir: Path) -> list[str]:
    artifacts_dir = workspace_dir / "artifacts"
    if not artifacts_dir.exists():
        return []
    paths: list[str] = []
    for path in artifacts_dir.glob("**/*"):
        if path.is_file():
            paths.append(  # noqa: PERF401 - explicit filtering is clearer.
                str(path.relative_to(workspace_dir))
            )
    paths.sort()
    return paths


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


__all__ = ["TRACE_SCHEMA_VERSION", "TraceSummary", "summarize_workspace_trace"]
