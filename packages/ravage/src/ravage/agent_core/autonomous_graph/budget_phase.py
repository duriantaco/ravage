# ruff: noqa: CPY001, EM101, EM102, FLY002

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.protocol import GraphActionKind

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.models import (
        GraphNode,
        GraphObjective,
        GraphState,
    )
    from ravage.agent_core.autonomous_graph.protocol import GraphWorkerAction


class GraphBudgetPhase(StrEnum):
    """Deterministic graph behavior as globally shared budgets are consumed."""

    EXPLORE = "explore"
    FOCUS = "focus"
    CLOSE = "close"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class GraphBudgetDirective:
    phase: GraphBudgetPhase
    pressure: float
    pressure_source: str
    allow_new_exploration: bool
    allow_evidence_backed_spawn: bool
    instruction: str

    def to_json(self) -> dict[str, object]:
        return {
            "phase": self.phase.value,
            "pressure": round(self.pressure, 6),
            "pressure_source": self.pressure_source,
            "allow_new_exploration": self.allow_new_exploration,
            "allow_evidence_backed_spawn": self.allow_evidence_backed_spawn,
            "instruction": self.instruction,
        }


class GraphBudgetPhaseError(ValueError):
    """Raised before a late-budget action can open an inadmissible branch."""


_FOCUS_THRESHOLD = 0.70
_CLOSE_THRESHOLD = 0.85
_EXHAUSTED_THRESHOLD = 1.0


def graph_budget_directive(
    state: GraphState,
    *,
    now_epoch: float | None = None,
) -> GraphBudgetDirective:
    """Resolve one graph-wide phase from the most constrained shared budget."""
    now = time.time() if now_epoch is None else now_epoch
    pressures = {
        "model_requests": _fraction(
            state.model_requests_started,
            state.limits.max_model_requests,
        ),
        "tool_calls": _fraction(
            state.tool_calls_started,
            state.limits.max_tool_calls,
        ),
        "wall_time": _fraction(
            max(now - state.created_at_epoch, 0.0),
            state.limits.max_wall_seconds,
        ),
    }
    if state.limits.max_cost_usd is not None:
        pressures["cost"] = _fraction(
            state.spent_cost_usd,
            state.limits.max_cost_usd,
        )
    source, pressure = max(
        pressures.items(),
        key=lambda item: (item[1], item[0]),
    )
    if pressure >= _EXHAUSTED_THRESHOLD:
        return GraphBudgetDirective(
            phase=GraphBudgetPhase.EXHAUSTED,
            pressure=pressure,
            pressure_source=source,
            allow_new_exploration=False,
            allow_evidence_backed_spawn=False,
            instruction=(
                "The graph budget is exhausted. Do not open work; settle in-flight "
                "accounting and finish or stop."
            ),
        )
    if pressure >= _CLOSE_THRESHOLD:
        return GraphBudgetDirective(
            phase=GraphBudgetPhase.CLOSE,
            pressure=pressure,
            pressure_source=source,
            allow_new_exploration=False,
            allow_evidence_backed_spawn=True,
            instruction=(
                "Close now. Use confirmed contracts, complete proof-bearing work, "
                "or finish with bounded exhaustion. A new child is admissible only "
                "for evidence-backed proof or closure work."
            ),
        )
    if pressure >= _FOCUS_THRESHOLD:
        return GraphBudgetDirective(
            phase=GraphBudgetPhase.FOCUS,
            pressure=pressure,
            pressure_source=source,
            allow_new_exploration=False,
            allow_evidence_backed_spawn=True,
            instruction=(
                "Narrow the graph. Stop broad reconnaissance, retain only the "
                "highest-information open route, and spend new work on a named "
                "evidence-backed dimension or closure obligation."
            ),
        )
    return GraphBudgetDirective(
        phase=GraphBudgetPhase.EXPLORE,
        pressure=pressure,
        pressure_source=source,
        allow_new_exploration=True,
        allow_evidence_backed_spawn=True,
        instruction=(
            "Explore within the assigned objective and finite campaign plan. "
            "Prefer material information gain over parallel breadth."
        ),
    )


def authorize_budget_phase_action(
    directive: GraphBudgetDirective,
    *,
    node: GraphNode,
    action: GraphWorkerAction,
) -> None:
    """Enforce late-budget branch control independently of model compliance."""
    if directive.phase is GraphBudgetPhase.EXHAUSTED:
        if action.kind not in {
            GraphActionKind.FINISH,
            GraphActionKind.SUBMIT_PROOF,
        }:
            raise GraphBudgetPhaseError("budget_phase_exhausted_allows_only_finish_or_submit_proof")
        return
    if action.kind is not GraphActionKind.SPAWN:
        return
    objective = action.spawn_objective()
    if directive.phase is GraphBudgetPhase.EXPLORE:
        return
    if not objective.evidence_refs:
        raise GraphBudgetPhaseError(f"budget_phase_{directive.phase.value}_blocks_unbacked_spawn")
    if directive.phase is GraphBudgetPhase.CLOSE and not _closure_objective(
        objective,
        parent=node.objective,
    ):
        raise GraphBudgetPhaseError("budget_phase_close_blocks_nonclosure_spawn")


def _closure_objective(
    objective: GraphObjective,
    *,
    parent: GraphObjective,
) -> bool:
    text = " ".join(
        (
            objective.family,
            objective.strategy,
            objective.instruction,
            objective.expected_signal,
        )
    ).lower()
    if any(
        marker in text
        for marker in (
            "proof",
            "closure",
            "validate",
            "verification",
            "confirm",
            "replay",
        )
    ):
        return True
    return (
        objective.family == parent.family
        and objective.endpoint == parent.endpoint
        and bool(objective.evidence_refs)
    )


def _fraction(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 1.0
    value = numerator / denominator
    if not math.isfinite(value):
        return 1.0
    return max(value, 0.0)


__all__ = [
    "GraphBudgetDirective",
    "GraphBudgetPhase",
    "GraphBudgetPhaseError",
    "authorize_budget_phase_action",
    "graph_budget_directive",
]
