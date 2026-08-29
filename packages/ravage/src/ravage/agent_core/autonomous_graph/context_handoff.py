from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.sessions import (
    GraphSessionStore,
    SessionRole,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.autonomous_graph.models import GraphObjective
    from ravage.agent_core.autonomous_graph.sessions import SessionRecord

FROZEN_BASE_CONTEXT_MARKER = "FROZEN_BASE_CONTEXT_V1"
INHERITED_CONTEXT_MARKER = "BOUNDED_PARENT_CONTEXT_V1"
_MAX_BASE_STRING_CHARS = 1_500
_MAX_BASE_JSON_CHARS = 8_000
_MAX_INHERITED_RECORDS = 16
_MAX_INHERITED_CHARS = 30_000


def seed_frozen_base_context(
    sessions: GraphSessionStore,
    *,
    node_ids: Iterable[str],
    state: AgentState,
) -> str:
    """
    Seed a bounded, immutable projection of the frozen base into graph sessions.

    The complete base state is represented by a canonical digest. Only the
    bounded fields needed to continue an unfinished route are copied.
    """
    context = frozen_base_context(state)
    for node_id in tuple(dict.fromkeys(item.strip() for item in node_ids if item.strip())):
        if _session_has_marker(sessions, node_id, FROZEN_BASE_CONTEXT_MARKER):
            continue
        sessions.append(
            node_id,
            role=SessionRole.USER,
            content=context,
        )
    return context


def frozen_base_context(state: AgentState) -> str:
    canonical = json.dumps(
        state.to_json(),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    projection = {
        "base_state_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "phase": _clip(state.phase),
        "summary": _clip(state.summary),
        "facts": [_clip(item) for item in state.facts[-30:]],
        "hypotheses": [_clip(item) for item in state.hypotheses[-16:]],
        "confirmed_primitives": dict(sorted(state.primitives.items())),
        "surface_json": _json_clip(state.surface),
        "recent_tasks_json": _json_clip(state.tasks[-12:]),
        "recent_attempts_json": _json_clip(
            [_attempt_projection(item) for item in state.attempts[-10:]]
        ),
        "recent_signals": {
            str(key): [_clip(value) for value in values[-4:]]
            for key, values in sorted(state.signals.items())[-16:]
        },
        "last_observation_json": _json_clip(state.last_observation),
        "immutability": (
            "This is a read-only handoff from the frozen base. Continue from it; "
            "do not reinterpret it as fresh target evidence."
        ),
    }
    return f"{FROZEN_BASE_CONTEXT_MARKER}\n" + json.dumps(
        projection, ensure_ascii=False, indent=2, sort_keys=True
    )


def inherit_parent_context(  # noqa: PLR0913 - explicit bounded handoff.
    sessions: GraphSessionStore,
    *,
    parent_id: str,
    child_id: str,
    objective: GraphObjective,
    max_records: int = _MAX_INHERITED_RECORDS,
    max_chars: int = _MAX_INHERITED_CHARS,
) -> bool:
    """Give a child bounded parent history without sharing mutable sessions."""
    if max_records <= 0 or max_chars <= 0:
        message = "parent-context limits must be greater than zero"
        raise ValueError(message)
    if sessions.records(child_id):
        return False
    inherited = _bounded_records(
        sessions.records(parent_id),
        max_records=max_records,
        max_chars=max_chars,
    )
    payload = {
        "parent_node_id": parent_id,
        "child_node_id": child_id,
        "objective": objective.to_json(),
        "records": [
            {
                "role": record.role.value,
                "content": record.content,
            }
            for record in inherited
        ],
        "instruction": (
            "Treat these records as bounded inherited context. Preserve confirmed "
            "request contracts and negative evidence. Execute only the child objective."
        ),
    }
    sessions.append(
        child_id,
        role=SessionRole.USER,
        content=(
            f"{INHERITED_CONTEXT_MARKER}\n"
            + json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        ),
    )
    return True


def _bounded_records(
    records: Sequence[SessionRecord],
    *,
    max_records: int,
    max_chars: int,
) -> tuple[SessionRecord, ...]:
    selected: list[SessionRecord] = []
    used = 0
    for record in reversed(records[-max_records:]):
        remaining = max_chars - used
        if remaining <= 0:
            break
        content = record.content[-remaining:]
        selected.append(type(record)(role=record.role, content=content))
        used += len(content)
    return tuple(reversed(selected))


def _session_has_marker(
    sessions: GraphSessionStore,
    node_id: str,
    marker: str,
) -> bool:
    return any(marker in record.content for record in sessions.records(node_id))


def _attempt_projection(attempt: Mapping[str, object]) -> dict[str, object]:
    selected = attempt.get("selected_action")
    outcome = attempt.get("outcome")
    return {
        "turn": attempt.get("turn"),
        "action_id": _clip(str(attempt.get("action_id") or ""), limit=200),
        "selected_action_json": _json_clip(selected),
        "outcome_json": _json_clip(outcome),
    }


def _clip(value: str, *, limit: int = _MAX_BASE_STRING_CHARS) -> str:
    normalized = value.strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 20] + "...[context clipped]"


def _json_clip(value: object) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        encoded = repr(value)
    return _clip(encoded, limit=_MAX_BASE_JSON_CHARS)


__all__ = [
    "FROZEN_BASE_CONTEXT_MARKER",
    "INHERITED_CONTEXT_MARKER",
    "frozen_base_context",
    "inherit_parent_context",
    "seed_frozen_base_context",
]
