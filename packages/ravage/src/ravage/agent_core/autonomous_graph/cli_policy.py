"""Pure CLI admission policy for autonomous-graph planner modes."""

from __future__ import annotations

from ravage.agent_core.autonomous_graph.work_planner import InvestigationPlannerMode

CLI_GRAPH_PLANNER_MODES = tuple(mode.value for mode in InvestigationPlannerMode)
GRAPH_PLANNER_MODE_HELP = (
    "agent-graph planner mode: shadow records candidate rankings while legacy executes; "
    "online executes feedback rankings (shadow and online are available only for local targets; "
    "default: legacy); requires --autonomous-route "
    "--autonomous-route-engine agent-graph"
)


class GraphPlannerCliPolicyError(ValueError):
    """Raised when CLI route and target options cannot admit a planner mode."""


def resolve_cli_graph_planner_mode(
    *,
    autonomous_route: bool,
    autonomous_route_engine: str,
    requested_mode: str | None,
) -> InvestigationPlannerMode:
    """Resolve one planner mode after applying route admission rules."""
    if requested_mode is not None and (
        not autonomous_route or autonomous_route_engine != "agent-graph"
    ):
        message = (
            "--graph-planner-mode requires --autonomous-route --autonomous-route-engine agent-graph"
        )
        raise GraphPlannerCliPolicyError(message)
    try:
        mode = InvestigationPlannerMode(requested_mode or InvestigationPlannerMode.LEGACY.value)
    except ValueError as exc:
        message = "--graph-planner-mode is unsupported"
        raise GraphPlannerCliPolicyError(message) from exc
    return mode


def validate_cli_graph_planner_target(
    *,
    mode: InvestigationPlannerMode,
    remote_target: bool,
) -> None:
    """Reject planner modes whose traffic cannot be bounded for this target."""
    if remote_target and mode in {
        InvestigationPlannerMode.SHADOW,
        InvestigationPlannerMode.ONLINE,
    }:
        message = (
            f"--graph-planner-mode {mode.value} is unavailable for remote targets because "
            "its full target-traffic boundary is not yet evaluator-enforced"
        )
        raise GraphPlannerCliPolicyError(message)


__all__ = [
    "CLI_GRAPH_PLANNER_MODES",
    "GRAPH_PLANNER_MODE_HELP",
    "GraphPlannerCliPolicyError",
    "resolve_cli_graph_planner_mode",
    "validate_cli_graph_planner_target",
]
