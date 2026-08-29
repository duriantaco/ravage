# ruff: noqa: CPY001

from __future__ import annotations

from ravage.agent_core.autonomous_graph.adapter import GraphRouteConfig
from ravage.agent_core.autonomous_graph.models import GraphLimits
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
)


def graph_config_for_budget(
    max_model_requests: int,
    *,
    max_cost_usd: float | None = None,
    operational_profile: GraphOperationalProfileName = (GraphOperationalProfileName.STANDARD),
) -> GraphRouteConfig:
    """Build one graph configuration without changing the frozen base budget."""
    if max_model_requests <= 0:
        message = "max_model_requests must be greater than zero"
        raise ValueError(message)
    return GraphRouteConfig(
        limits=GraphLimits(
            max_model_requests=max_model_requests,
            max_tool_calls=max(4, max_model_requests * 4),
            max_cost_usd=max_cost_usd,
            proof_reserve_model_requests=min(4, max_model_requests - 1),
        ),
        operational_profile=operational_profile,
    )


__all__ = ["graph_config_for_budget"]
