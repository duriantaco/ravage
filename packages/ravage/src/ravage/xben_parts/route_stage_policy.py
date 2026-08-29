# ruff: noqa: CPY001

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

_MIN_ROUTE_STAGE_SECONDS = 120
_SECONDS_PER_ROUTE_MODEL_REQUEST = 25


class _RouteStageSettings(Protocol):
    case_timeout_seconds: int
    autonomous_route: bool
    autonomous_route_max_requests: int


@dataclass(frozen=True)
class AgentStageTimeoutPolicy:
    """Bounded wall-clock allowances for the frozen base and opt-in route."""

    base_seconds: int
    autonomous_route_seconds: int
    subprocess_seconds: int

    def to_json(self) -> dict[str, int]:
        return {
            "base_stage_seconds": self.base_seconds,
            "autonomous_route_stage_seconds": self.autonomous_route_seconds,
            "subprocess_seconds": self.subprocess_seconds,
        }


def agent_stage_timeout_policy(
    settings: _RouteStageSettings,
) -> AgentStageTimeoutPolicy:
    """
    Reserve route time without changing the frozen base's own request budget.

    The parent used to give the combined base-plus-route child only the base
    case timeout. A slow base could therefore consume the entire wall clock
    before the bounded route was entered. The route allowance scales with its
    model-request ceiling, is never larger than the base allowance, and remains
    zero when the route is disabled.
    """
    base_seconds = max(int(settings.case_timeout_seconds), 1)
    route_seconds = 0
    if settings.autonomous_route:
        scaled = max(
            int(settings.autonomous_route_max_requests) * _SECONDS_PER_ROUTE_MODEL_REQUEST,
            _MIN_ROUTE_STAGE_SECONDS,
        )
        route_seconds = min(base_seconds, scaled)
    return AgentStageTimeoutPolicy(
        base_seconds=base_seconds,
        autonomous_route_seconds=route_seconds,
        subprocess_seconds=base_seconds + route_seconds,
    )


__all__ = [
    "AgentStageTimeoutPolicy",
    "agent_stage_timeout_policy",
]
