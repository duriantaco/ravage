# ruff: noqa: CPY001

from __future__ import annotations

import pytest
from ravage.agent_core.autonomous_graph.budget_phase import (
    GraphBudgetPhase,
    GraphBudgetPhaseError,
    authorize_budget_phase_action,
    graph_budget_directive,
)
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.models import GraphLimits, GraphObjective
from ravage.agent_core.autonomous_graph.protocol import GraphWorkerAction


def _objective(
    instruction: str = "coordinate",
    *,
    evidence_refs: tuple[str, ...] = (),
    family: str = "sql_injection",
    endpoint: str = "/search",
) -> GraphObjective:
    return GraphObjective.create(
        family=family,
        instruction=instruction,
        endpoint=endpoint,
        inputs=("q",),
        strategy="differential",
        expected_signal="target-observed response",
        evidence_refs=evidence_refs,
    )


def _coordinator() -> GraphCoordinator:
    return GraphCoordinator.start(
        graph_id="budget-phase-test",
        root_objective=_objective(),
        limits=GraphLimits(
            max_model_requests=20,
            max_tool_calls=100,
            max_cost_usd=10.0,
            max_wall_seconds=1_000,
            proof_reserve_model_requests=4,
        ),
        clock=lambda: 100.0,
    )


def _action(kind: str, payload: dict[str, object]) -> GraphWorkerAction:
    return GraphWorkerAction.from_json(
        {
            "kind": kind,
            "payload": payload,
        }
    )


def _spawn(
    *,
    instruction: str,
    evidence_refs: tuple[str, ...] = (),
    family: str = "sql_injection",
    endpoint: str = "/search",
) -> GraphWorkerAction:
    objective = _objective(
        instruction,
        evidence_refs=evidence_refs,
        family=family,
        endpoint=endpoint,
    )
    return _action(
        "spawn",
        {
            "name": "specialist",
            "objective": objective.to_json(),
            "lease_limit": 2,
        },
    )


@pytest.mark.parametrize(
    ("requests", "expected"),
    [
        (13, GraphBudgetPhase.EXPLORE),
        (14, GraphBudgetPhase.FOCUS),
        (17, GraphBudgetPhase.CLOSE),
        (20, GraphBudgetPhase.EXHAUSTED),
    ],
)
def test_budget_phase_uses_graduated_global_pressure(
    requests: int,
    expected: GraphBudgetPhase,
) -> None:
    coordinator = _coordinator()
    coordinator.state.model_requests_started = requests

    directive = graph_budget_directive(
        coordinator.state,
        now_epoch=100.0,
    )

    assert directive.phase is expected
    assert directive.pressure_source == "model_requests"


def test_budget_phase_uses_most_constrained_shared_resource() -> None:
    coordinator = _coordinator()
    coordinator.state.model_requests_started = 2
    coordinator.state.tool_calls_started = 72
    coordinator.state.spent_cost_usd = 1.0

    directive = graph_budget_directive(
        coordinator.state,
        now_epoch=100.0,
    )

    assert directive.phase is GraphBudgetPhase.FOCUS
    assert directive.pressure_source == "tool_calls"


def test_focus_requires_evidence_for_new_child() -> None:
    coordinator = _coordinator()
    coordinator.state.model_requests_started = 14
    directive = graph_budget_directive(coordinator.state, now_epoch=100.0)
    node = coordinator.state.nodes["node-001"]

    with pytest.raises(
        GraphBudgetPhaseError,
        match="blocks_unbacked_spawn",
    ):
        authorize_budget_phase_action(
            directive,
            node=node,
            action=_spawn(instruction="try another broad idea"),
        )

    authorize_budget_phase_action(
        directive,
        node=node,
        action=_spawn(
            instruction="test the evidence-backed alternate encoding",
            evidence_refs=("evidence:one",),
        ),
    )


def test_close_allows_only_evidence_backed_closure_child() -> None:
    coordinator = _coordinator()
    coordinator.state.model_requests_started = 17
    directive = graph_budget_directive(coordinator.state, now_epoch=100.0)
    node = coordinator.state.nodes["node-001"]

    with pytest.raises(
        GraphBudgetPhaseError,
        match="blocks_nonclosure_spawn",
    ):
        authorize_budget_phase_action(
            directive,
            node=node,
            action=_spawn(
                instruction="explore an unrelated endpoint",
                evidence_refs=("evidence:one",),
                family="cross_site_scripting",
                endpoint="/comments",
            ),
        )

    authorize_budget_phase_action(
        directive,
        node=node,
        action=_spawn(
            instruction="validate and replay the proof contract",
            evidence_refs=("evidence:one",),
        ),
    )


def test_exhausted_phase_blocks_work_but_allows_finish() -> None:
    coordinator = _coordinator()
    coordinator.state.model_requests_started = 20
    directive = graph_budget_directive(coordinator.state, now_epoch=100.0)
    node = coordinator.state.nodes["node-001"]

    with pytest.raises(GraphBudgetPhaseError, match="allows_only"):
        authorize_budget_phase_action(
            directive,
            node=node,
            action=_action(
                "execute",
                {
                    "tool": "http_request",
                    "arguments": {"path": "/"},
                    "expected_signal": "response",
                },
            ),
        )

    authorize_budget_phase_action(
        directive,
        node=node,
        action=_action(
            "finish",
            {
                "summary": "bounded exhaustion",
                "evidence_refs": [],
            },
        ),
    )
