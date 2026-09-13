from __future__ import annotations

import pytest
from ravage.agent_core.autonomous_graph.cli_policy import (
    CLI_GRAPH_PLANNER_MODES,
    GRAPH_PLANNER_MODE_HELP,
    GraphPlannerCliPolicyError,
    resolve_cli_graph_planner_mode,
    validate_cli_graph_planner_target,
)
from ravage.agent_core.autonomous_graph.work_planner import InvestigationPlannerMode


@pytest.mark.parametrize("mode", list(InvestigationPlannerMode))
def test_local_agent_graph_accepts_every_published_planner_mode(
    mode: InvestigationPlannerMode,
) -> None:
    assert (
        resolve_cli_graph_planner_mode(
            autonomous_route=True,
            autonomous_route_engine="agent-graph",
            requested_mode=mode.value,
        )
        is mode
    )


def test_omitted_mode_preserves_legacy_default() -> None:
    assert (
        resolve_cli_graph_planner_mode(
            autonomous_route=False,
            autonomous_route_engine="deterministic",
            requested_mode=None,
        )
        is InvestigationPlannerMode.LEGACY
    )


@pytest.mark.parametrize("mode", ["shadow", "online"])
def test_nonlegacy_planners_fail_closed_for_remote_targets(mode: str) -> None:
    with pytest.raises(GraphPlannerCliPolicyError, match="unavailable for remote targets"):
        validate_cli_graph_planner_target(
            mode=InvestigationPlannerMode(mode),
            remote_target=True,
        )


@pytest.mark.parametrize("mode", list(InvestigationPlannerMode))
def test_every_planner_mode_is_valid_for_local_targets(mode: InvestigationPlannerMode) -> None:
    validate_cli_graph_planner_target(mode=mode, remote_target=False)


@pytest.mark.parametrize(
    ("autonomous_route", "engine"),
    [(False, "agent-graph"), (True, "deterministic")],
)
def test_explicit_mode_requires_the_agent_graph_route(
    autonomous_route: bool,  # noqa: FBT001 - parametrized policy input.
    engine: str,
) -> None:
    with pytest.raises(GraphPlannerCliPolicyError, match="requires --autonomous-route"):
        resolve_cli_graph_planner_mode(
            autonomous_route=autonomous_route,
            autonomous_route_engine=engine,
            requested_mode="online",
        )


def test_cli_contract_exports_all_modes_and_local_only_help() -> None:
    assert tuple(mode.value for mode in InvestigationPlannerMode) == CLI_GRAPH_PLANNER_MODES
    assert "shadow and online are available only for local targets" in GRAPH_PLANNER_MODE_HELP
