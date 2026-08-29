from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.coverage_ledger import CoverageCellState
    from ravage.agent_core.autonomous_graph.work_planner import PlannedCampaign


class LoopDisposition(StrEnum):
    CONTINUE = "continue"
    PIVOT = "pivot"
    CLOSE = "close"
    PROVE = "prove"
    EXHAUST = "exhaust"
    RETRY_TRANSPORT = "retry_transport"


@dataclass(frozen=True)
class LoopObservation:
    trusted_progress_kinds: tuple[str, ...] = ()
    hypothesis_disproved: bool = False
    repeated_observation: bool = False
    tool_failed: bool = False


@dataclass(frozen=True)
class LoopDecision:
    disposition: LoopDisposition
    reason: str
    cell_id: str
    stage: str
    evidence_version: int
    required_dimension: str = ""
    recommended_campaign: str = ""
    recommended_probe: str = ""
    recommended_additional_model_requests: int = 0

    @property
    def terminal_for_cell(self) -> bool:
        return self.disposition is LoopDisposition.EXHAUST

    def to_json(self) -> dict[str, object]:
        return {
            "disposition": self.disposition.value,
            "reason": self.reason,
            "cell_id": self.cell_id,
            "stage": self.stage,
            "evidence_version": self.evidence_version,
            "required_dimension": self.required_dimension,
            "recommended_campaign": self.recommended_campaign,
            "recommended_probe": self.recommended_probe,
            "recommended_additional_model_requests": (self.recommended_additional_model_requests),
        }


@dataclass(frozen=True)
class LoopPolicyConfig:
    plateau_limit: int = 2
    max_campaigns_per_cell: int = 8

    def __post_init__(self) -> None:
        if self.plateau_limit <= 0:
            message = "plateau_limit must be greater than zero"
            raise ValueError(message)
        if self.max_campaigns_per_cell <= 0:
            message = "max_campaigns_per_cell must be greater than zero"
            raise ValueError(message)


class InvestigationLoopPolicy:
    """
    Convert typed deltas into bounded continuation, strategy change, or closure.

    This policy never grants budget itself. Its budget recommendation mirrors
    what ProgressiveGraphScheduler may authorize from trusted receipts.
    """

    def __init__(self, config: LoopPolicyConfig | None = None) -> None:
        self.config = config or LoopPolicyConfig()

    def decide(  # noqa: C901, PLR0911 - explicit state-machine exits.
        self,
        *,
        cell: CoverageCellState,
        observation: LoopObservation,
        campaigns: tuple[PlannedCampaign, ...],
    ) -> LoopDecision:
        kinds = set(observation.trusted_progress_kinds)
        if "proof_confirmed" in kinds:
            return self._decision(
                cell,
                LoopDisposition.PROVE,
                reason="trusted_proof_requires_immediate_proof_gate_submission",
            )
        if kinds.intersection(
            {
                "primitive_confirmed",
                "auth_state_changed",
                "extraction_checkpoint",
            }
        ):
            return self._decision(
                cell,
                LoopDisposition.CLOSE,
                reason="confirmed_primitive_requires_shortest_proof_closure",
                campaigns=campaigns,
                additional=2,
            )
        if observation.tool_failed:
            return self._decision(
                cell,
                LoopDisposition.RETRY_TRANSPORT,
                reason="tool_transport_failed_without_disproving_the_strategy",
                campaigns=campaigns,
            )
        if observation.hypothesis_disproved:
            if campaigns:
                return self._decision(
                    cell,
                    LoopDisposition.PIVOT,
                    reason="typed_disproof_requires_one_materially_distinct_counterfactual",
                    campaigns=campaigns,
                    additional=1,
                )
            if cell.attempt_count < self.config.max_campaigns_per_cell:
                return self._decision(
                    cell,
                    LoopDisposition.PIVOT,
                    reason=("typed_disproof_requires_a_model_declared_material_counterfactual"),
                    required_dimension="model_declared_material_counterfactual",
                    additional=1,
                )
            return self._decision(
                cell,
                LoopDisposition.EXHAUST,
                reason="typed_disproof_closed_the_last_available_strategy_dimension",
            )
        if kinds:
            return self._decision(
                cell,
                LoopDisposition.CONTINUE,
                reason="novel_trusted_delta_advances_the_current_investigation",
                campaigns=campaigns,
                additional=2,
            )
        if cell.attempt_count >= self.config.max_campaigns_per_cell:
            return self._decision(
                cell,
                LoopDisposition.EXHAUST,
                reason="per_surface_campaign_ceiling_reached",
            )
        if campaigns:
            reason = (
                "observation_plateau_requires_strategy_rotation"
                if (
                    observation.repeated_observation
                    or cell.no_progress_streak >= self.config.plateau_limit
                )
                else "no_typed_delta_requires_a_new_material_dimension"
            )
            return self._decision(
                cell,
                LoopDisposition.PIVOT,
                reason=reason,
                campaigns=campaigns,
            )
        if (
            cell.no_progress_streak < self.config.plateau_limit
            and cell.attempt_count < self.config.max_campaigns_per_cell
        ):
            return self._decision(
                cell,
                LoopDisposition.PIVOT,
                reason="no_catalog_campaign_remains_require_one_creative_counterfactual",
                required_dimension="model_declared_material_counterfactual",
            )
        return self._decision(
            cell,
            LoopDisposition.EXHAUST,
            reason="no_untried_campaign_dimension_remains_at_this_evidence_version",
        )

    @staticmethod
    def _decision(  # noqa: PLR0913 - complete immutable decision fields.
        cell: CoverageCellState,
        disposition: LoopDisposition,
        *,
        reason: str,
        campaigns: tuple[PlannedCampaign, ...] = (),
        required_dimension: str = "",
        additional: int = 0,
    ) -> LoopDecision:
        next_campaign = campaigns[0] if campaigns else None
        return LoopDecision(
            disposition=disposition,
            reason=reason,
            cell_id=cell.cell.cell_id,
            stage=cell.stage.value,
            evidence_version=cell.evidence_version,
            required_dimension=(
                next_campaign.campaign.dimension
                if next_campaign is not None
                else required_dimension
            ),
            recommended_campaign=(next_campaign.campaign.name if next_campaign is not None else ""),
            recommended_probe=(next_campaign.campaign.probe if next_campaign is not None else ""),
            recommended_additional_model_requests=additional,
        )


__all__ = [
    "InvestigationLoopPolicy",
    "LoopDecision",
    "LoopDisposition",
    "LoopObservation",
    "LoopPolicyConfig",
]
