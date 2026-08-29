# ruff: noqa: CPY001, PLR0913

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from ravage.agent_core.autonomous_graph.config import graph_config_for_budget
from ravage.agent_core.autonomous_graph.entrypoint import (
    BaseThenGraphResult,
    run_base_then_autonomous_graph_route,
)
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
)
from ravage.agent_core.autonomous_route import (
    AutonomousRouteResult,
    run_base_then_autonomous_route,
)
from ravage.agent_core.frontier_route import frontier_config_for_budget

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.ai_agent import AIWebAgentSettings

AutonomousRouteEngine = Literal["frontier", "agent-graph"]
AUTONOMOUS_ROUTE_ENGINES: tuple[AutonomousRouteEngine, ...] = (
    "frontier",
    "agent-graph",
)


def run_selected_autonomous_route(
    *,
    engine: AutonomousRouteEngine,
    max_model_requests: int,
    brief_path: Path,
    target_url: str,
    settings: AIWebAgentSettings,
    operational_profile: GraphOperationalProfileName = (GraphOperationalProfileName.STANDARD),
) -> AutonomousRouteResult | BaseThenGraphResult:
    """Dispatch one explicitly selected post-base route under the same hard ceiling."""
    if engine == "agent-graph":
        return run_base_then_autonomous_graph_route(
            brief_path=brief_path,
            target_url=target_url,
            settings=settings,
            config=graph_config_for_budget(
                max_model_requests,
                operational_profile=operational_profile,
            ),
        )
    if engine == "frontier":
        return run_base_then_autonomous_route(
            brief_path=brief_path,
            target_url=target_url,
            settings=settings,
            config=frontier_config_for_budget(max_model_requests),
        )
    message = f"unsupported autonomous route engine: {engine}"
    raise ValueError(message)


__all__ = [
    "AUTONOMOUS_ROUTE_ENGINES",
    "AutonomousRouteEngine",
    "run_selected_autonomous_route",
]
