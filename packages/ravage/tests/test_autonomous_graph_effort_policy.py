# ruff: noqa: CPY001, PLR2004

from __future__ import annotations

from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.coverage_ledger import (
    CoverageCellState,
    CoverageStage,
    SurfaceCell,
)
from ravage.agent_core.autonomous_graph.effort_policy import (
    GRAPH_ROUTE_TARGET_REQUEST_LIMIT,
    grant_graph_effort,
)
from ravage.agent_core.autonomous_graph.investigation import InvestigationEngine
from ravage.agent_core.autonomous_graph.models import GraphObjective

if TYPE_CHECKING:
    from pathlib import Path


def _cell(stage: CoverageStage) -> CoverageCellState:
    return CoverageCellState(
        cell=SurfaceCell.create(
            family="sql_injection",
            endpoint="http://127.0.0.1:8765/search",
            inputs=("query",),
        ),
        stage=stage,
    )


def _objective(endpoint: str) -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction="Calibrate one target-observed query contract.",
        endpoint=endpoint,
        inputs=("query",),
        strategy="sqli_differential",
        expected_signal="typed differential or bounded disproof",
    )


def test_failure_alone_does_not_increase_target_request_grant() -> None:
    observed = _cell(CoverageStage.OBSERVED)
    observed.attempt_count = 3
    observed.no_progress_streak = 3

    initial = grant_graph_effort(
        _cell(CoverageStage.OBSERVED),
        route_committed=0,
    )
    after_failures = grant_graph_effort(observed, route_committed=0)

    assert initial.target_request_limit == 12
    assert after_failures.target_request_limit == initial.target_request_limit


def test_trusted_stage_progress_unlocks_larger_but_finite_grants() -> None:
    assert (
        grant_graph_effort(
            _cell(CoverageStage.CONTRACTED),
            route_committed=0,
        ).target_request_limit
        == 16
    )
    assert (
        grant_graph_effort(
            _cell(CoverageStage.CALIBRATED),
            route_committed=0,
        ).target_request_limit
        == 24
    )
    assert (
        grant_graph_effort(
            _cell(CoverageStage.PRIMITIVE),
            route_committed=0,
        ).target_request_limit
        == 32
    )
    assert (
        grant_graph_effort(
            _cell(CoverageStage.CLOSURE),
            route_committed=0,
        ).target_request_limit
        == 40
    )


def test_route_remaining_hard_caps_each_grant() -> None:
    grant = grant_graph_effort(
        _cell(CoverageStage.CLOSURE),
        route_committed=GRAPH_ROUTE_TARGET_REQUEST_LIMIT - 7,
    )

    assert grant.target_request_limit == 7
    assert grant.route_remaining == 7


def test_concurrent_investigation_reservations_count_against_route_cap(
    tmp_path: Path,
) -> None:
    first = _objective("http://127.0.0.1:8765/search-a")
    second = _objective("http://127.0.0.1:8765/search-b")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(first, second),
    )

    one = engine.authorize_action(
        node_id="one",
        objective=first,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    two = engine.authorize_action(
        node_id="two",
        objective=second,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    assert one.effort.target_request_limit == 12
    assert two.effort.target_request_limit == 12
    assert two.effort.route_committed == 12

    engine.cancel_action(one)
    engine.cancel_action(two)
