from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.frontier_route import FrontierObjective

_MAX_FACTS = 14
_MAX_HYPOTHESES = 8
_MAX_SIGNALS_PER_KEY = 12
_MAX_TASKS = 4
_MAX_ATTEMPTS = 6
_MAX_TEXT_CHARS = 2_400
_MAX_ACTION_TEXT_CHARS = 1_200

_FAMILY_TERMS: dict[str, tuple[str, ...]] = {
    "sql_injection": (
        "boolean",
        "database",
        "mysql",
        "oracle",
        "postgres",
        "query",
        "sql",
        "sqli",
    ),
    "xml_external_entity": ("doctype", "entity", "soap", "svg", "xml", "xxe"),
    "template_injection": ("freemarker", "jinja", "ssti", "template", "twig"),
    "path_traversal": ("file read", "path traversal", "traversal"),
    "server_side_request_forgery": ("fetch", "metadata", "ssrf", "url"),
}
_DIMENSION_TERMS: dict[str, tuple[str, ...]] = {
    "request_contract": (
        "ajax",
        "cookie",
        "field",
        "form",
        "get",
        "method",
        "parameter",
        "post",
        "request",
    ),
    "payload_semantics": (
        "encode",
        "filter",
        "oracle",
        "payload",
        "timing",
    ),
    "proof_channel": (
        "admin",
        "credential",
        "dashboard",
        "extract",
        "flag",
        "login",
        "password",
        "proof",
        "readback",
        "secret",
        "session",
        "upload",
    ),
}
_COMPETING_TERMS: dict[str, tuple[str, ...]] = {
    "sql_injection": (
        "backup",
        "direct exposure",
        "direct_exposure",
        "graphql",
        "ssti",
        "xxe",
    ),
    "xml_external_entity": ("backup", "direct exposure", "sqli", "ssti"),
    "template_injection": ("backup", "direct exposure", "sqli", "xxe"),
}
_FAMILY_SIGNAL_PREFIXES: dict[str, tuple[str, ...]] = {
    "sql_injection": ("sqli_", "sql_"),
    "xml_external_entity": ("xxe_", "xml_"),
    "template_injection": ("ssti_", "template_"),
}
_SHARED_SIGNAL_KEYS = frozenset(
    {
        "cookies",
        "endpoints",
        "forms",
        "markers",
        "pages",
        "parameters",
        "request_templates",
    }
)


def focused_frontier_context(
    state: AgentState,
    objective: FrontierObjective,
) -> dict[str, object]:
    """Project persistent state around one assignment without mutating base memory."""
    focus = _Focus.from_objective(objective)
    facts = _relevant_strings(state.facts, focus, limit=_MAX_FACTS)
    context_basis = "objective_focus"
    if not facts and state.facts:
        facts = [_clip_text(state.facts[-1])]
        context_basis = "objective_focus_with_continuity_tail"
    hypotheses = _relevant_strings(
        state.hypotheses,
        focus,
        limit=_MAX_HYPOTHESES,
    )
    signals = _focused_signals(state.signals, focus)
    tasks = _focused_tasks(state.tasks, focus)
    attempts = _focused_attempts(state.attempts, focus)
    actions = _focused_actions(state.actions, focus)
    surface = _focused_surface(state.surface, focus)
    last_observation = (
        _clip_mapping(state.last_observation)
        if focus.primary_relevant(state.last_observation)
        else {}
    )
    primitives = {key: value for key, value in state.primitives.items() if focus.relevant(key)}
    return {
        "phase": state.phase,
        "turn": state.turn,
        "context_basis": context_basis,
        "focus": {
            "family": objective.family,
            "endpoint": objective.endpoint,
            "inputs": list(objective.inputs),
            "dimension": focus.dimension,
        },
        "confirmed_primitives": primitives,
        "facts": facts,
        "hypotheses": hypotheses,
        "signals": signals,
        "surface": surface,
        "relevant_tasks": tasks,
        "recent_relevant_actions": actions,
        "recent_relevant_attempts": attempts,
        "last_relevant_observation": last_observation,
        "omitted_counts": {
            "facts": max(len(state.facts) - len(facts), 0),
            "hypotheses": max(len(state.hypotheses) - len(hypotheses), 0),
            "tasks": max(len(state.tasks) - len(tasks), 0),
            "attempts": max(len(state.attempts) - len(attempts), 0),
        },
    }


class _Focus:
    def __init__(
        self,
        *,
        family: str,
        endpoint: str,
        inputs: tuple[str, ...],
        dimension: str,
    ) -> None:
        self.family = family
        self.endpoint = endpoint
        self.inputs = inputs
        self.dimension = dimension
        self.family_terms = _FAMILY_TERMS.get(family, ())
        self.dimension_terms = _DIMENSION_TERMS.get(dimension, ())
        self.competing_terms = _COMPETING_TERMS.get(family, ())

    @classmethod
    def from_objective(cls, objective: FrontierObjective) -> _Focus:
        return cls(
            family=objective.family,
            endpoint=objective.endpoint,
            inputs=objective.inputs,
            dimension=objective.payload_class.rsplit(":", maxsplit=1)[-1],
        )

    def relevant(self, value: object) -> bool:
        text = _text(value).lower()
        if not text:
            return False
        endpoint_match = _endpoint_present(text, self.endpoint)
        input_match = any(_token_present(text, item) for item in self.inputs)
        family_match = any(_term_present(text, term) for term in self.family_terms)
        dimension_match = any(_term_present(text, term) for term in self.dimension_terms)
        competing = any(_term_present(text, term) for term in self.competing_terms)
        if competing:
            return False
        return endpoint_match or input_match or family_match or dimension_match

    def primary_relevant(self, value: object) -> bool:
        text = _text(value).lower()
        if not text:
            return False
        if any(_term_present(text, term) for term in self.competing_terms):
            return False
        return (
            _endpoint_present(text, self.endpoint)
            or any(_token_present(text, item) for item in self.inputs)
            or any(_term_present(text, term) for term in self.family_terms)
        )


def _focused_signals(
    signals: Mapping[str, Sequence[str]],
    focus: _Focus,
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    prefixes = _FAMILY_SIGNAL_PREFIXES.get(focus.family, ())
    for key, values in signals.items():
        if key.startswith("frontier_"):
            continue
        strong_key = any(key.startswith(prefix) for prefix in prefixes)
        if not strong_key and key not in _SHARED_SIGNAL_KEYS:
            continue
        selected = [
            _clip_text(str(value))
            for value in values
            if strong_key or _signal_value_relevant(key, value, focus)
        ][-_MAX_SIGNALS_PER_KEY:]
        if selected:
            result[key] = selected
    return result


def _signal_value_relevant(key: str, value: object, focus: _Focus) -> bool:
    text = _text(value).lower()
    if key == "endpoints":
        return _endpoint_present(text, focus.endpoint)
    if key == "parameters":
        return any(_token_present(text, item) for item in focus.inputs)
    if key == "cookies":
        return True
    return focus.relevant(text)


def _focused_surface(surface: Mapping[str, object], focus: _Focus) -> dict[str, object]:
    projected: dict[str, object] = {}
    for key in ("origin", "target_url", "cookies"):
        value = surface.get(key)
        if value:
            projected[key] = value
    for key in ("forms", "parameters", "endpoints", "pages"):
        value = surface.get(key)
        if not isinstance(value, list):
            continue
        selected = [
            _clip_mapping(item)
            for item in value
            if isinstance(item, Mapping) and _mapping_relevant(item, focus)
        ][-_MAX_SIGNALS_PER_KEY:]
        if selected:
            projected[key] = selected
    return projected


def _focused_tasks(
    tasks: Sequence[Mapping[str, object]],
    focus: _Focus,
) -> list[dict[str, object]]:
    selected: list[dict[str, object]] = []
    for task in tasks:
        identity = {key: task.get(key) for key in ("id", "title") if task.get(key)}
        if not focus.relevant(identity):
            continue
        projected = {
            key: task.get(key)
            for key in (
                "id",
                "title",
                "status",
                "priority",
                "last_outcome",
                "rationale",
            )
            if task.get(key) is not None
        }
        evidence = _relevant_strings(
            _strings(task.get("evidence")),
            focus,
            limit=6,
        )
        next_steps = _relevant_strings(
            _strings(task.get("next_steps")),
            focus,
            limit=5,
        )
        if evidence:
            projected["evidence"] = evidence
        if next_steps:
            projected["next_steps"] = next_steps
        selected.append(projected)
    return selected[-_MAX_TASKS:]


def _focused_actions(
    actions: Sequence[Mapping[str, object]],
    focus: _Focus,
) -> list[dict[str, object]]:
    return [_project_action(action) for action in actions if focus.relevant(action)][
        -_MAX_ATTEMPTS:
    ]


def _focused_attempts(
    attempts: Sequence[Mapping[str, object]],
    focus: _Focus,
) -> list[dict[str, object]]:
    selected: list[dict[str, object]] = []
    for attempt in attempts:
        action = attempt.get("selected_action")
        outcome = attempt.get("outcome")
        if not focus.relevant(action) and not focus.relevant(outcome):
            continue
        selected.append(
            {
                "turn": attempt.get("turn"),
                "selected_action": _project_action(action),
                "outcome": _project_outcome(outcome, focus),
                "objective_fingerprint": attempt.get("objective_fingerprint"),
            }
        )
    return selected[-_MAX_ATTEMPTS:]


def _relevant_strings(
    values: Sequence[str],
    focus: _Focus,
    *,
    limit: int,
) -> list[str]:
    return [_clip_text(value) for value in values if focus.relevant(value)][-limit:]


def _mapping_relevant(value: object, focus: _Focus) -> bool:
    return isinstance(value, Mapping) and focus.relevant(value)


def _project_action(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    projected = {
        key: value.get(key)
        for key in ("action", "probe", "task_id", "strategy", "repeat_count")
        if value.get(key) is not None
    }
    for key in ("command", "code"):
        item = value.get(key)
        if isinstance(item, str) and item:
            projected[key] = _clip_text(item, limit=_MAX_ACTION_TEXT_CHARS)
    return projected


def _project_outcome(value: object, focus: _Focus) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    projected = {
        key: value.get(key)
        for key in (
            "classification",
            "outcome",
            "ok",
            "repeat_count",
            "stop",
            "evidence_source_kind",
        )
        if value.get(key) is not None
    }
    observation = value.get("evidence_observation") or value.get("observation")
    if isinstance(observation, str) and focus.primary_relevant(observation):
        projected["observation"] = _clip_text(
            observation,
            limit=_MAX_ACTION_TEXT_CHARS,
        )
    return projected


def _clip_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    clipped: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(item, str):
            clipped[str(key)] = _clip_text(item)
        elif isinstance(item, Mapping):
            clipped[str(key)] = _clip_mapping(item)
        elif isinstance(item, list):
            clipped[str(key)] = [
                _clip_mapping(entry) if isinstance(entry, Mapping) else entry for entry in item[:20]
            ]
        else:
            clipped[str(key)] = item
    return clipped


def _clip_text(value: str, *, limit: int = _MAX_TEXT_CHARS) -> str:
    if len(value) <= limit:
        return value
    marker = "\n...[focused context clipped]...\n"
    remaining = limit - len(marker)
    head = remaining * 2 // 3
    return value[:head] + marker + value[-(remaining - head) :]


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except TypeError:
        return str(value)


def _endpoint_present(source: str, endpoint: str) -> bool:
    path = urlsplit(endpoint).path if "://" in endpoint else endpoint
    path = "/" + path.lstrip("/")
    if path in {"", "/"}:
        return False
    needle = re.escape(path.lstrip("/").lower())
    pattern = rf"(?<![a-z0-9_.~%-])/?{needle}(?=$|[/?#&=:'\"\s)\],+])"
    return re.search(pattern, source) is not None


def _token_present(source: str, token: str) -> bool:
    value = token.strip().lower()
    if not value:
        return False
    return re.search(rf"(?<![a-z0-9_-]){re.escape(value)}(?![a-z0-9_-])", source) is not None


def _term_present(source: str, term: str) -> bool:
    value = term.strip().lower()
    if not value:
        return False
    if re.fullmatch(r"[a-z0-9_-]+", value):
        return _token_present(source, value)
    return value in source


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


__all__ = ["focused_frontier_context"]
