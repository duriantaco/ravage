from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.branch_search import BRANCH_SEARCH_POLICY_VERSION
from ravage.agent_core.autonomous_graph.campaigns import (
    CampaignSpec,
    campaigns_for_objective,
)

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.branch_search import (
        BranchOutcomeIndex,
        BranchScoreAdjustment,
    )
    from ravage.agent_core.autonomous_graph.coverage_ledger import CoverageCellState
    from ravage.agent_core.autonomous_graph.failure_memory import (
        InvestigationFailureMemory,
    )
    from ravage.agent_core.autonomous_graph.models import GraphObjective

_MAX_BELIEF_BASIS_POINTS = 10_000
ONLINE_PLANNER_POLICY_VERSION = f"branch-search-v{BRANCH_SEARCH_POLICY_VERSION}"


class InvestigationPlannerMode(StrEnum):
    """Rollout mode for feedback-driven campaign ordering."""

    LEGACY = "legacy"
    SHADOW = "shadow"
    ONLINE = "online"


@dataclass(frozen=True)
class PlannedCampaign:
    campaign: CampaignSpec
    score: int
    reason: str
    policy: str = "legacy-v1"
    search_adjustment: BranchScoreAdjustment | None = None

    def to_json(self) -> dict[str, object]:
        payload = self.campaign.to_json(score=self.score)
        payload["reason"] = self.reason
        return payload


class InvestigationWorkPlanner:
    """Rank finite campaigns by information gain, proof proximity, and novelty."""

    def __init__(self, failure_memory: InvestigationFailureMemory) -> None:
        self.failure_memory = failure_memory

    def rank(  # noqa: PLR0913 - policy inputs remain explicit for replay.
        self,
        *,
        objective: GraphObjective,
        cell: CoverageCellState,
        belief_basis_points: int = 2500,
        limit: int = 4,
        outcome_index: BranchOutcomeIndex | None = None,
        max_attempts: int = 8,
        planner_cell_id: str | None = None,
    ) -> tuple[PlannedCampaign, ...]:
        if limit <= 0 or cell.exhausted:
            return ()
        if max_attempts <= 0:
            message = "max_attempts must be greater than zero"
            raise ValueError(message)
        if not 0 <= belief_basis_points <= _MAX_BELIEF_BASIS_POINTS:
            message = "belief basis points must be between 0 and 10000"
            raise ValueError(message)
        scoring_cell_id = planner_cell_id or cell.cell.cell_id
        planner_attempts = cell.attempt_count
        if planner_attempts >= max_attempts:
            return ()
        planned: list[PlannedCampaign] = []
        seen_dimensions: set[str] = set()
        for campaign in campaigns_for_objective(objective, stage=cell.stage):
            if campaign.dimension in seen_dimensions:
                continue
            blocking = self.failure_memory.blocking_certificate(
                cell_id=cell.cell.cell_id,
                strategy=campaign.name,
                dimension=campaign.dimension,
                evidence_version=cell.evidence_version,
            )
            if blocking is not None:
                continue
            attempted_key = (
                f"{_token(campaign.name)}:{_token(campaign.dimension)}"
                if outcome_index is not None
                else f"{campaign.name}:{campaign.dimension}"
            )
            attempted_at = cell.attempted_dimensions.get(attempted_key)
            if attempted_at == cell.evidence_version:
                continue
            score, reason = _campaign_score(
                campaign,
                objective=objective,
                cell=cell,
                belief_basis_points=belief_basis_points,
            )
            adjustment = (
                outcome_index.score(
                    cell_id=scoring_cell_id,
                    strategy=campaign.name,
                    dimension=campaign.dimension,
                    proof_proximity=campaign.proof_proximity,
                    attempts_used=planner_attempts,
                    max_attempts=max_attempts,
                )
                if outcome_index is not None
                else None
            )
            if adjustment is not None:
                score += adjustment.total_adjustment
            planned.append(
                PlannedCampaign(
                    campaign=campaign,
                    score=score,
                    reason=reason,
                    policy=(
                        ONLINE_PLANNER_POLICY_VERSION if outcome_index is not None else "legacy-v1"
                    ),
                    search_adjustment=adjustment,
                )
            )
            seen_dimensions.add(campaign.dimension)
        planned.sort(
            key=lambda item: (
                -item.score,
                item.campaign.name,
            )
        )
        return tuple(planned[:limit])


def _campaign_score(
    campaign: CampaignSpec,
    *,
    objective: GraphObjective,
    cell: CoverageCellState,
    belief_basis_points: int,
) -> tuple[int, str]:
    score = campaign.information_gain + campaign.proof_proximity
    uncertainty_basis_points = _MAX_BELIEF_BASIS_POINTS - abs(
        2 * belief_basis_points - _MAX_BELIEF_BASIS_POINTS
    )
    exploitation_value = belief_basis_points * campaign.proof_proximity // _MAX_BELIEF_BASIS_POINTS
    learning_value = (
        uncertainty_basis_points * campaign.information_gain // _MAX_BELIEF_BASIS_POINTS
    )
    score += exploitation_value + learning_value
    reasons = [
        f"information_gain={campaign.information_gain}",
        f"proof_proximity={campaign.proof_proximity}",
        f"executor_belief_bp={belief_basis_points}",
        f"exploitation_value={exploitation_value}",
        f"learning_value={learning_value}",
    ]
    strategy = objective.strategy.lower()
    objective_text = (f"{objective.instruction} {objective.expected_signal} {strategy}").lower()
    if campaign.probe == strategy or campaign.probe in objective_text:
        score += 80
        reasons.append("matches_assigned_strategy=80")
    if cell.stage.value in {"calibrated", "primitive", "closure"}:
        closure_bonus = campaign.proof_proximity // 2
        score += closure_bonus
        reasons.append(f"closure_stage={closure_bonus}")
    if cell.no_progress_streak:
        diversity_bonus = min(cell.no_progress_streak, 3) * 12
        score += diversity_bonus
        reasons.append(f"plateau_diversity={diversity_bonus}")
    return score, ", ".join(reasons)


def _token(value: str) -> str:
    return "_".join(value.strip().lower().replace("-", " ").split())


__all__ = [
    "ONLINE_PLANNER_POLICY_VERSION",
    "InvestigationPlannerMode",
    "InvestigationWorkPlanner",
    "PlannedCampaign",
]
