# Target-request escalation is graph-only and evidence gated.
# ruff: noqa: CPY001

from __future__ import annotations

from dataclasses import dataclass

from ravage.agent_core.autonomous_graph.coverage_ledger import (
    CoverageCellState,
    CoverageStage,
)

GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT = "_graph_target_request_limit"
GRAPH_ROUTE_TARGET_REQUEST_LIMIT = 96

_STAGE_LIMITS = {
    CoverageStage.OBSERVED: 12,
    CoverageStage.CONTRACTED: 16,
    CoverageStage.CALIBRATED: 24,
    CoverageStage.PRIMITIVE: 32,
    CoverageStage.CLOSURE: 40,
    CoverageStage.PROOF: 0,
}


@dataclass(frozen=True)
class GraphEffortGrant:
    target_request_limit: int
    stage: CoverageStage
    route_limit: int
    route_committed: int

    @property
    def route_remaining(self) -> int:
        return max(self.route_limit - self.route_committed, 0)

    def to_json(self) -> dict[str, object]:
        return {
            "target_request_limit": self.target_request_limit,
            "stage": self.stage.value,
            "route_limit": self.route_limit,
            "route_committed": self.route_committed,
            "route_remaining_before_grant": self.route_remaining,
            "escalation_basis": "trusted_coverage_stage",
        }


def grant_graph_effort(
    cell: CoverageCellState,
    *,
    route_committed: int,
) -> GraphEffortGrant:
    committed = max(int(route_committed), 0)
    remaining = max(GRAPH_ROUTE_TARGET_REQUEST_LIMIT - committed, 0)
    stage_limit = _STAGE_LIMITS[cell.stage]
    return GraphEffortGrant(
        target_request_limit=min(stage_limit, remaining),
        stage=cell.stage,
        route_limit=GRAPH_ROUTE_TARGET_REQUEST_LIMIT,
        route_committed=committed,
    )


def effort_policy_projection() -> dict[str, object]:
    return {
        "route_target_request_limit": GRAPH_ROUTE_TARGET_REQUEST_LIMIT,
        "per_campaign_stage_limits": {stage.value: limit for stage, limit in _STAGE_LIMITS.items()},
        "escalation_rule": (
            "larger target-request grants require a trusted typed receipt that "
            "advances the coverage stage; failure alone never increases the grant"
        ),
    }


__all__ = [
    "GRAPH_ROUTE_TARGET_REQUEST_LIMIT",
    "GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT",
    "GraphEffortGrant",
    "effort_policy_projection",
    "grant_graph_effort",
]
