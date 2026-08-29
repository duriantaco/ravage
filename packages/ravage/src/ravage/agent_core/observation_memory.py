from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.agent_tasks import mission_board_summary
from ravage.agent_core.attack_surface import compact_surface_for_prompt


def build_planner_memory(state: AgentState) -> dict[str, object]:
    return {
        "phase": state.phase,
        "summary": state.summary,
        "coverage": coverage_summary(state),
        "mission_board": mission_board_summary(state),
        "attack_surface": compact_surface_for_prompt(state.surface),
        "high_value_facts": state.facts[-20:],
        "active_hypotheses": state.hypotheses[-12:],
        "recent_actions": state.actions[-8:],
        "last_observation": state.last_observation,
        "flags": state.flags,
        "signals": _recent_signals(state, limit=12),
    }


def coverage_summary(state: AgentState) -> dict[str, int]:
    return {
        "pages": len(state.signals.get("pages", [])),
        "forms": len(state.signals.get("forms", [])),
        "parameters": len(state.signals.get("parameters", [])),
        "cookies": len(state.signals.get("cookies", [])),
        "markers": len(state.signals.get("markers", [])),
        "reflections": len(state.signals.get("reflections", [])),
        "endpoints": len(state.signals.get("endpoints", [])),
        "tasks_pending": _pending_task_count(state),
        "actions": len(state.actions),
    }


def summarize_state(state: AgentState) -> str:
    facts = "; ".join(state.facts[-8:])
    hypotheses = "; ".join(state.hypotheses[-5:])
    actions = _recent_action_names(state, limit=5)
    coverage = coverage_summary(state)
    return (
        f"phase={state.phase}; coverage={coverage}; recent_actions={actions}; "
        f"hypotheses={hypotheses}; facts={facts}"
    ).strip()


def should_shift_strategy(state: AgentState) -> bool:
    recent = state.actions[-3:]
    if len(recent) < 3:
        return False
    outcomes = _recent_outcomes(recent)
    repeats = _recent_repeat_counts(recent)
    return _all_outcomes_are_low_value(outcomes) or max(repeats) > 1


def _recent_signals(state: AgentState, *, limit: int) -> dict[str, list[str]]:
    recent: dict[str, list[str]] = {}
    for key, values in state.signals.items():
        recent[key] = values[-limit:]
    return recent


def _pending_task_count(state: AgentState) -> int:
    count = 0
    for task in state.tasks:
        if task.get("status") in {"pending", "in_progress"}:
            count += 1
    return count


def _recent_action_names(state: AgentState, *, limit: int) -> str:
    names: list[str] = []
    for action in state.actions[-limit:]:
        name = str(action.get("action") or "")
        if name:
            names.append(name)
    return ", ".join(names)


def _recent_outcomes(actions: list[dict[str, object]]) -> list[str]:
    outcomes: list[str] = []
    for action in actions:
        outcomes.append(str(action.get("outcome") or ""))
    return outcomes


def _recent_repeat_counts(actions: list[dict[str, object]]) -> list[int]:
    repeats: list[int] = []
    for action in actions:
        repeats.append(_int_value(action.get("repeat_count")))
    return repeats


def _all_outcomes_are_low_value(outcomes: list[str]) -> bool:
    for outcome in outcomes:
        if outcome not in {"blocked", "same_as_before", "observed"}:
            return False
    return True


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
