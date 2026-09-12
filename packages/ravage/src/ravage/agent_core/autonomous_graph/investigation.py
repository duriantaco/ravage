# The investigation engine is additive and owns no frozen-base state.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.beliefs import BeliefLedger
from ravage.agent_core.autonomous_graph.branch_search import (
    MAX_PLANNER_ATTEMPTS_PER_CELL,
    MAX_PLANNER_OUTCOMES,
    BranchOutcomeIndex,
    BranchSearchError,
)
from ravage.agent_core.autonomous_graph.campaigns import (
    CampaignSpec,
    campaign_for_probe,
    initial_stage_for_objective,
)
from ravage.agent_core.autonomous_graph.coverage_ledger import (
    CampaignReservation,
    CoverageCellState,
    CoverageStage,
    InvestigationCoverageError,
    InvestigationCoverageLedger,
    PlannerFeedbackError,
    SurfaceCell,
    canonical_family,
)
from ravage.agent_core.autonomous_graph.effort_policy import (
    GRAPH_ROUTE_TARGET_REQUEST_LIMIT,
    GraphEffortGrant,
    effort_policy_projection,
    grant_graph_effort,
)
from ravage.agent_core.autonomous_graph.failure_memory import (
    FailureCertificate,
    InvestigationFailureMemory,
)
from ravage.agent_core.autonomous_graph.loop_policy import (
    InvestigationLoopPolicy,
    LoopDecision,
    LoopDisposition,
    LoopObservation,
)
from ravage.agent_core.autonomous_graph.routing import GraphActionRejectedError
from ravage.agent_core.autonomous_graph.scheduler import (
    GraphProgressBinding,
    ProgressBatchClass,
    ProgressEvidenceValidator,
    ProgressKind,
    ProgressReceiptValidationError,
    ValidatedProgressBatch,
    require_validated_progress_batch,
    validate_progress_receipt_batch,
)
from ravage.agent_core.autonomous_graph.work_planner import (
    ONLINE_PLANNER_POLICY_VERSION,
    InvestigationPlannerMode,
    InvestigationWorkPlanner,
    PlannedCampaign,
)
from ravage.agent_core.semantic_routes import semantic_action_route
from ravage.probe_suite import probe_requires_external_process

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.autonomous_graph.models import (
        AgentSpec,
        GraphObjective,
        Hypothesis,
    )
    from ravage.agent_core.autonomous_graph.scheduler import (
        ObservationDecision,
        ProgressReceipt,
    )
    from ravage.agent_core.autonomous_graph.worker import GraphToolResult

_AD_HOC_LOOP_TOOLS = frozenset({"run_command", "run_python"})
_METERED_TARGET_REQUEST_TOOLS = frozenset({"http_request", "run_probe"})
_UNMETERED_TARGET_REQUEST_TOOLS = frozenset(
    {
        "process_start",
        "process_write",
        "run_command",
        "run_python",
        "validate_poc",
    }
)
_TARGET_CAPABLE_TOOLS = _METERED_TARGET_REQUEST_TOOLS | _UNMETERED_TARGET_REQUEST_TOOLS
_PLANNER_STATE_TOOLS = _METERED_TARGET_REQUEST_TOOLS | frozenset({"capture_flag"})
_PLANNER_DECISION_SCHEMA_VERSION = 1
_MAX_PLANNER_DECISION_RECORDS = 2_000
_MAX_PLANNER_DECISION_BYTES = 16 * 1024 * 1024
_SHA256_HEX_LENGTH = 64
_MAX_HYPOTHESIS_PATH = 64
_MAX_PLANNER_TEXT_LENGTH = 4_096
_PLANNER_DECISION_POINTS = frozenset(
    {
        "context_projection",
        "action_authorized",
        "result_ranked",
        "result_committed",
    }
)
_PLANNER_DEGRADATION_REASONS = frozenset(
    {
        "candidate_evaluation_failed",
        "decision_log_invalid",
        "decision_record_failed",
        "feedback_record_failed",
    }
)
_LOOP_DECISION_FIELDS = frozenset(
    {
        "disposition",
        "reason",
        "cell_id",
        "stage",
        "evidence_version",
        "required_dimension",
        "recommended_campaign",
        "recommended_probe",
        "recommended_additional_model_requests",
    }
)
_PLANNER_DECISION_FIELDS = frozenset(
    {
        "active_ranking_policy",
        "attempt_count",
        "authorized_action",
        "candidate",
        "candidate_changed_top",
        "cell_id",
        "comparison_digest",
        "coverage_stage",
        "decision_point",
        "degradation_reasons",
        "evidence_version",
        "legacy",
        "node_id",
        "objective_fingerprint",
        "outcome_index_digest",
        "planner_cell_id",
        "planner_mode",
        "planner_policy_version",
        "previous_record_digest",
        "record_digest",
        "schema_version",
        "sequence",
        "committed_loop_decision",
        "settled_reservation_id",
        "top_ranked_campaign",
    }
)


class InvestigationActionRejectedError(GraphActionRejectedError):
    """Raised before target/tool accounting when loop policy forbids an action."""


@dataclass(frozen=True)
class InvestigationTicket:
    reservation: CampaignReservation
    cell: SurfaceCell
    planner_cell_id: str
    objective_fingerprint: str
    hypothesis_fingerprint: str
    strategy: str
    dimension: str
    effort: GraphEffortGrant
    campaign: CampaignSpec | None = None
    planner_state_attributed: bool = False


class InvestigationEngine:
    """
    Coverage-guided strategy and loop controller for the experimental graph route.

    Existing Ravage probes remain the execution units. This layer chooses and
    remembers finite campaigns; it never writes or executes model-authored loops.
    """

    def __init__(  # noqa: C901, PLR0913 - dependencies are explicit.
        self,
        *,
        coverage: InvestigationCoverageLedger,
        failures: InvestigationFailureMemory,
        decision_path: Path,
        beliefs: BeliefLedger | None = None,
        evidence_validator: ProgressEvidenceValidator | None = None,
        policy: InvestigationLoopPolicy | None = None,
        planner_mode: InvestigationPlannerMode = InvestigationPlannerMode.LEGACY,
        planner_policy_version: str = ONLINE_PLANNER_POLICY_VERSION,
    ) -> None:
        if not isinstance(planner_mode, InvestigationPlannerMode):
            message = "planner mode must be an InvestigationPlannerMode"
            raise InvestigationCoverageError(message)
        if planner_policy_version != ONLINE_PLANNER_POLICY_VERSION:
            message = "planner policy version is unsupported"
            raise InvestigationCoverageError(message)
        self.coverage = coverage
        self.failures = failures
        self.beliefs = beliefs
        self.evidence_validator = evidence_validator
        self.planner = InvestigationWorkPlanner(failures)
        self.policy = policy or InvestigationLoopPolicy()
        if (
            planner_mode is not InvestigationPlannerMode.LEGACY
            and self.policy.config.max_campaigns_per_cell
            != MAX_PLANNER_ATTEMPTS_PER_CELL
        ):
            raise InvestigationCoverageError(
                "non-legacy planner campaign limit does not match its policy version"
            )
        self.planner_mode = planner_mode
        self.planner_policy_version = planner_policy_version
        self.decision_path = decision_path
        self.planner_decision_path = decision_path.with_name(
            "investigation-planner-decisions.jsonl"
        )
        self._lock = threading.RLock()
        self._last_decisions: dict[str, LoopDecision] = {}
        self._reserved_target_requests: dict[str, int] = {}
        self._reserved_planner_feedback: set[str] = set()
        self._reserved_planner_cells: dict[str, str] = {}
        self._planner_decision_records: list[dict[str, object]] = []
        self._planner_comparison_digests: set[str] = set()
        self._planner_degradation_reasons: set[str] = set()
        self._planner_candidate_enabled = True
        self._planner_recording_enabled = True
        if planner_mode is not InvestigationPlannerMode.LEGACY:
            try:
                BranchOutcomeIndex.from_attempts(self.coverage.snapshot().attempts)
            except Exception as exc:
                if planner_mode is InvestigationPlannerMode.ONLINE:
                    if isinstance(exc, BranchSearchError):
                        raise InvestigationCoverageError(
                            f"planner feedback history is invalid: {exc}"
                        ) from exc
                    raise InvestigationCoverageError(
                        "cannot validate planner feedback history"
                    ) from exc
                self._degrade_planner("candidate_evaluation_failed")
            try:
                self._planner_decision_records = self._load_planner_decision_records()
                self._planner_comparison_digests = {
                    str(record["comparison_digest"]) for record in self._planner_decision_records
                }
                for record in self._planner_decision_records:
                    for reason in record["degradation_reasons"]:  # type: ignore[union-attr]
                        self._degrade_planner(str(reason))
            except Exception:
                self._degrade_planner("decision_log_invalid")

    @classmethod
    def open(
        cls,
        *,
        workspace_dir: Path,
        objectives: Sequence[GraphObjective] = (),
        evidence_validator: ProgressEvidenceValidator | None = None,
        planner_mode: InvestigationPlannerMode = InvestigationPlannerMode.LEGACY,
        planner_policy_version: str = ONLINE_PLANNER_POLICY_VERSION,
    ) -> InvestigationEngine:
        engine = cls(
            coverage=InvestigationCoverageLedger.open(
                workspace_dir / "investigation-coverage.json"
            ),
            failures=InvestigationFailureMemory.open(workspace_dir / "investigation-failures.json"),
            decision_path=workspace_dir / "investigation-decisions.jsonl",
            evidence_validator=evidence_validator,
            planner_mode=planner_mode,
            planner_policy_version=planner_policy_version,
            beliefs=(
                BeliefLedger.open(
                    workspace_dir / "investigation-beliefs.json",
                    evidence_validator=evidence_validator,
                )
                if evidence_validator is not None
                else None
            ),
        )
        for objective in objectives:
            cell = SurfaceCell.from_objective(objective)
            engine.coverage.ensure_cell(
                cell,
                initial_stage=initial_stage_for_objective(objective),
            )
        return engine

    def context_projection(
        self,
        *,
        node_id: str,
        objective: GraphObjective,
        hypothesis: Hypothesis | None = None,
    ) -> dict[str, object]:
        with self._lock:
            cell = SurfaceCell.from_objective(objective)
            current = self.coverage.ensure_cell(
                cell,
                initial_stage=initial_stage_for_objective(objective),
            )
            policy_current = current
            if (
                self.planner_mode is InvestigationPlannerMode.ONLINE
                and self._planner_candidate_enabled
            ):
                policy_current = self._candidate_coverage_cell(
                    execution_cell=current,
                    planner_cell_id=cell.cell_id,
                    index=BranchOutcomeIndex.from_attempts(
                        self.coverage.snapshot().attempts
                    ),
                    root_stage=initial_stage_for_objective(objective),
                )
            failures = self.failures.recent_for_cell(cell.cell_id)
            decision = self._last_decisions.get(cell.cell_id)
            belief = (
                self.beliefs.projection(hypothesis.fingerprint)
                if self.beliefs is not None and hypothesis is not None
                else {
                    "status": "proposed",
                    "belief_basis_points": 2500,
                    "revision": None,
                }
            )
            raw_belief_basis_points = belief.get("belief_basis_points")
            if isinstance(raw_belief_basis_points, bool) or not isinstance(
                raw_belief_basis_points,
                int,
            ):
                message = "belief projection has invalid basis points"
                raise InvestigationCoverageError(message)
            campaigns = self._rank_campaigns(
                node_id=node_id,
                decision_point="context_projection",
                objective=objective,
                cell=current,
                belief_basis_points=raw_belief_basis_points,
                record_decision=True,
            )
            return {
                "mode": "coverage_guided_finite_campaigns",
                "hypothesis": (hypothesis.to_json() if hypothesis is not None else None),
                "belief": belief,
                "coverage_cell": _coverage_projection(policy_current),
                "recommended_campaigns": [item.to_json() for item in campaigns],
                "failure_certificates": [certificate.to_json() for certificate in failures],
                "last_loop_decision": (decision.to_json() if decision is not None else None),
                "loop_contract": {
                    "allowed_transitions": [
                        "continue_on_novel_typed_delta",
                        "pivot_on_disproof_or_no_delta",
                        "close_immediately_on_confirmed_primitive",
                        "submit_immediately_on_confirmed_proof",
                        "finish_when_no_untried_dimension_remains",
                    ],
                    "requirements": [
                        (
                            "Treat the hypothesis as falsifiable: seek both its support "
                            "signal and its falsification signal."
                        ),
                        (
                            "A critic accepts only a distinct, testable candidate; critic "
                            "text never confirms a vulnerability."
                        ),
                        "Prefer the first recommended finite run_probe campaign.",
                        "After a failed campaign, change the declared material dimension.",
                        "Do not implement a cosmetic payload loop in run_command/run_python.",
                        "Do not request more turns without target-observed typed progress.",
                    ],
                },
                "target_request_effort": {
                    **effort_policy_projection(),
                    "next_grant": grant_graph_effort(
                        policy_current,
                        route_committed=self._route_committed_requests(),
                    ).to_json(),
                },
            }

    def summary(self) -> dict[str, object]:
        coverage = self.coverage.snapshot()
        failures = self.failures.snapshot()
        stages = Counter(cell.stage.value for cell in coverage.cells.values())
        return {
            "enabled": True,
            "planner": {
                "mode": self.planner_mode.value,
                "policy_version": self.planner_policy_version,
                "candidate_controls_recommendations": (
                    self.planner_mode is InvestigationPlannerMode.ONLINE
                    and self._planner_candidate_enabled
                ),
                "action_authorization_remains_policy_gated": True,
                "decision_records": len(self._planner_decision_records),
                "degraded": bool(self._planner_degradation_reasons),
                "degradation_reasons": sorted(self._planner_degradation_reasons),
            },
            "coverage_cells": len(coverage.cells),
            "stage_counts": dict(sorted(stages.items())),
            "exhausted_cells": sum(cell.exhausted for cell in coverage.cells.values()),
            "campaign_attempts": len(coverage.attempts),
            "target_requests_observed": coverage.total_target_requests,
            "target_requests_pessimistic_charges": (
                coverage.pessimistic_target_request_charges
            ),
            "target_requests_charged": (
                coverage.total_target_requests
                + coverage.pessimistic_target_request_charges
            ),
            "target_request_effort": effort_policy_projection(),
            "failure_certificates": len(failures.certificates),
            "belief_revisions": (
                len(self.beliefs.snapshot().revisions) if self.beliefs is not None else 0
            ),
            "artifacts": {
                "coverage": self.coverage.state_path.name,
                "failures": self.failures.state_path.name,
                "decisions": self.decision_path.name,
                "planner_decisions": (
                    self.planner_decision_path.name
                    if self.planner_mode is not InvestigationPlannerMode.LEGACY
                    else None
                ),
                "beliefs": (self.beliefs.state_path.name if self.beliefs is not None else None),
            },
        }

    def authorize_action(
        self,
        *,
        node_id: str,
        objective: GraphObjective,
        tool: str,
        arguments: Mapping[str, object],
        hypothesis: Hypothesis | None = None,
    ) -> InvestigationTicket:
        with self._lock:
            objective_cell = SurfaceCell.from_objective(objective)
            objective_current = (
                self.coverage.ensure_cell(
                    objective_cell,
                    initial_stage=initial_stage_for_objective(objective),
                )
                if self.planner_mode is not InvestigationPlannerMode.LEGACY
                else None
            )
            route = _material_route(
                objective=objective,
                tool=tool,
                arguments=arguments,
            )
            cell = SurfaceCell.from_objective(objective, route=route)
            current = self.coverage.ensure_cell(
                cell,
                initial_stage=initial_stage_for_objective(objective),
            )
            policy_current = current
            candidate_current: CoverageCellState | None = None
            candidate_campaigns: tuple[PlannedCampaign, ...] = ()
            candidate_index: BranchOutcomeIndex | None = None
            if (
                self.planner_mode is not InvestigationPlannerMode.LEGACY
                and self._planner_candidate_enabled
                and objective_current is not None
            ):
                try:
                    candidate_index = BranchOutcomeIndex.from_attempts(
                        self.coverage.snapshot().attempts
                    )
                    candidate_current = self._candidate_coverage_cell(
                        execution_cell=current,
                        planner_cell_id=objective_cell.cell_id,
                        index=candidate_index,
                        root_stage=initial_stage_for_objective(objective),
                    )
                    candidate_campaigns = self.planner.rank(
                        objective=objective,
                        cell=candidate_current,
                        belief_basis_points=self._belief_basis_points(hypothesis),
                        outcome_index=candidate_index,
                        max_attempts=self.policy.config.max_campaigns_per_cell,
                        planner_cell_id=objective_cell.cell_id,
                    )
                    candidate_campaigns = self._actionable_candidate_campaigns(
                        objective=objective,
                        campaigns=candidate_campaigns,
                    )
                except Exception as exc:
                    if self.planner_mode is InvestigationPlannerMode.SHADOW:
                        self._degrade_planner("candidate_evaluation_failed")
                    elif isinstance(exc, BranchSearchError):
                        raise InvestigationActionRejectedError(
                            f"planner feedback history is invalid: {exc}"
                        ) from exc
                    else:
                        raise
            if (
                self.planner_mode is InvestigationPlannerMode.ONLINE
                and self._planner_candidate_enabled
                and candidate_current is not None
            ):
                policy_current = candidate_current
                if policy_current.exhausted:
                    raise InvestigationActionRejectedError(
                        "coverage_cell_exhausted_without_new_evidence"
                    )
                if policy_current.stage is CoverageStage.PROOF:
                    raise InvestigationActionRejectedError(
                        "coverage_cell_proof_complete"
                    )
            campaign = (
                campaign_for_probe(
                    str(arguments.get("probe") or ""),
                    objective=objective,
                    stage=policy_current.stage,
                )
                if tool == "run_probe"
                else None
            )
            if campaign is not None:
                strategy = campaign.name
                dimension = campaign.dimension
                self._require_campaign_preconditions(
                    campaign,
                    objective=objective,
                    current_stage=policy_current.stage,
                )
            else:
                strategy = _token(str(arguments.get("strategy") or tool))
                dimension = _generic_dimension(tool=tool, route=route)

            campaigns = self._rank_campaigns(
                node_id=node_id,
                decision_point="action_authorization",
                objective=objective,
                cell=current,
                belief_basis_points=self._belief_basis_points(hypothesis),
                planner_cell_id=objective_cell.cell_id,
            )
            if (
                tool in _AD_HOC_LOOP_TOOLS
                and policy_current.cell.family not in {"graph_coordination", "unknown"}
                and policy_current.attempt_count == 0
                and campaigns
                and objective.family != "credential_recovery"
                and "credential_representation" not in objective.strategy
            ):
                recommended = campaigns[0].campaign
                raise InvestigationActionRejectedError(
                    "bounded_campaign_required_before_ad_hoc_loop:"
                    f"run_probe/{recommended.probe}/dimension={recommended.dimension}"
                )

            blocking = self.failures.blocking_certificate(
                cell_id=cell.cell_id,
                strategy=strategy,
                dimension=dimension,
                evidence_version=current.evidence_version,
            )
            if (
                blocking is not None
                and campaign is not None
                and self.planner_mode is InvestigationPlannerMode.ONLINE
                and self._planner_candidate_enabled
                and candidate_current is not None
                and candidate_current.evidence_version > blocking.evidence_version
            ):
                # Evidence learned on another concrete route can materially change
                # this objective-wide campaign. The candidate may retry it once at
                # the new virtual evidence version; its branch receipt prevents a
                # same-version loop.
                blocking = None
            if blocking is not None:
                next_dimension = next(
                    (
                        planned.campaign.dimension
                        for planned in campaigns
                        if (
                            _token(planned.campaign.name),
                            _token(planned.campaign.dimension),
                        )
                        != (strategy, dimension)
                    ),
                    "none",
                )
                raise InvestigationActionRejectedError(
                    "failure_certificate_blocks_equivalent_campaign:"
                    f"{blocking.certificate_id};required_new_dimension={next_dimension}"
                )
            if (
                campaign is not None
                and policy_current.attempted_dimensions.get(
                    f"{_token(campaign.name)}:{_token(campaign.dimension)}"
                )
                == policy_current.evidence_version
                and self.planner_mode is InvestigationPlannerMode.ONLINE
                and self._planner_candidate_enabled
            ):
                raise InvestigationActionRejectedError(
                    "planner_feedback_blocks_equivalent_campaign_at_current_evidence"
                )
            if policy_current.exhausted:
                raise InvestigationActionRejectedError(
                    "coverage_cell_exhausted_without_new_evidence"
                )
            if policy_current.stage is CoverageStage.PROOF:
                raise InvestigationActionRejectedError(
                    "coverage_cell_proof_complete"
                )
            effort = grant_graph_effort(
                policy_current,
                route_committed=self._route_committed_requests(),
            )
            if tool not in _TARGET_CAPABLE_TOOLS:
                effort = GraphEffortGrant(
                    target_request_limit=0,
                    stage=effort.stage,
                    route_limit=effort.route_limit,
                    route_committed=effort.route_committed,
                )
            if tool in _TARGET_CAPABLE_TOOLS and effort.target_request_limit <= 0:
                raise InvestigationActionRejectedError(
                    "graph_route_target_request_budget_exhausted"
                )
            if (
                self.planner_mode is InvestigationPlannerMode.ONLINE
                and tool in _UNMETERED_TARGET_REQUEST_TOOLS
            ):
                raise InvestigationActionRejectedError(
                    "online_planner_requires_metered_target_request_tool"
                )
            if (
                self.planner_mode is InvestigationPlannerMode.ONLINE
                and tool == "run_probe"
                and probe_requires_external_process(
                    str(arguments.get("probe") or "").strip()
                )
            ):
                raise InvestigationActionRejectedError(
                    "online_planner_requires_metered_run_probe"
                )
            planner_state_attributed = bool(
                self.planner_mode is not InvestigationPlannerMode.LEGACY
                and self._planner_candidate_enabled
                and tool not in _UNMETERED_TARGET_REQUEST_TOOLS
                and (
                    campaign is not None
                    or tool in _PLANNER_STATE_TOOLS
                    or (
                        tool in _AD_HOC_LOOP_TOOLS
                        and candidate_current is not None
                        and not candidate_campaigns
                        and not candidate_current.exhausted
                        and candidate_current.attempt_count
                        < self.policy.config.max_campaigns_per_cell
                        and (
                            candidate_current.last_outcome == "hypothesis_disproved"
                            or candidate_current.no_progress_streak
                            < self.policy.config.plateau_limit
                        )
                    )
                )
            )
            if planner_state_attributed:
                indexed = (
                    candidate_index
                    if candidate_index is not None
                    else BranchOutcomeIndex.from_attempts(
                        self.coverage.snapshot().attempts
                    )
                )
                if (
                    len(indexed.outcome_ids) + len(self._reserved_planner_feedback)
                    >= MAX_PLANNER_OUTCOMES
                ):
                    if self.planner_mode is InvestigationPlannerMode.ONLINE:
                        raise InvestigationActionRejectedError(
                            "planner_feedback_history_capacity_reached"
                        )
                    self._degrade_planner("candidate_evaluation_failed")
                    planner_state_attributed = False
                reserved_for_cell = sum(
                    reserved_cell_id == objective_cell.cell_id
                    for reserved_cell_id in self._reserved_planner_cells.values()
                )
                if (
                    planner_state_attributed
                    and (
                        candidate_current.attempt_count
                        if candidate_current is not None
                        else indexed.cell_stats(objective_cell.cell_id).attempt_count
                    )
                    + reserved_for_cell
                    >= self.policy.config.max_campaigns_per_cell
                ):
                    if self.planner_mode is InvestigationPlannerMode.ONLINE:
                        raise InvestigationActionRejectedError(
                            "planner_cell_attempt_capacity_reached"
                        )
                    planner_state_attributed = False
            try:
                reservation = self.coverage.reserve(
                    node_id=node_id,
                    cell=cell,
                    strategy=strategy,
                    dimension=dimension,
                )
            except InvestigationCoverageError as exc:
                raise InvestigationActionRejectedError(str(exc)) from exc
            if self.planner_mode is not InvestigationPlannerMode.LEGACY:
                try:
                    self._rank_campaigns(
                        node_id=node_id,
                        decision_point="action_authorized",
                        objective=objective,
                        cell=current,
                        belief_basis_points=self._belief_basis_points(hypothesis),
                        record_decision=True,
                        authorized_reservation=reservation,
                        planner_cell_id=objective_cell.cell_id,
                    )
                except Exception:
                    self.coverage.cancel(reservation)
                    raise
            if effort.target_request_limit:
                self._reserved_target_requests[reservation.reservation_id] = (
                    effort.target_request_limit
                )
            if planner_state_attributed:
                self._reserved_planner_feedback.add(reservation.reservation_id)
                self._reserved_planner_cells[reservation.reservation_id] = (
                    objective_cell.cell_id
                )
            return InvestigationTicket(
                reservation=reservation,
                cell=cell,
                planner_cell_id=objective_cell.cell_id,
                objective_fingerprint=objective.fingerprint,
                hypothesis_fingerprint=(
                    hypothesis.fingerprint if hypothesis is not None else ""
                ),
                strategy=strategy,
                dimension=dimension,
                effort=effort,
                campaign=campaign,
                planner_state_attributed=planner_state_attributed,
            )

    def cancel_action(self, ticket: InvestigationTicket) -> None:
        with self._lock:
            self.coverage.cancel(ticket.reservation)
            self._release_effort(ticket)

    def record_tool_failure(
        self,
        ticket: InvestigationTicket,
        *,
        reason: str,
    ) -> LoopDecision:
        with self._lock:
            self._settle_failed_action(ticket)
            current = self.coverage.cell_state(ticket.cell.cell_id)
            campaigns = self._rank_campaigns(
                node_id=ticket.reservation.node_id,
                decision_point="tool_failure",
                objective=_TicketObjective(ticket),  # type: ignore[arg-type]
                cell=current,
                planner_cell_id=ticket.planner_cell_id,
                post_commit=True,
            )
            decision = self.policy.decide(
                cell=current,
                observation=LoopObservation(tool_failed=True),
                campaigns=campaigns,
            )
            decision = LoopDecision(
                disposition=decision.disposition,
                reason=f"{decision.reason}:{_text(reason)}",
                cell_id=decision.cell_id,
                stage=decision.stage,
                evidence_version=decision.evidence_version,
                required_dimension=decision.required_dimension,
                recommended_campaign=decision.recommended_campaign,
                recommended_probe=decision.recommended_probe,
                recommended_additional_model_requests=(
                    decision.recommended_additional_model_requests
                ),
            )
            self._remember_decision(ticket.reservation.node_id, decision)
            return decision

    def record_discarded_execution(self, ticket: InvestigationTicket) -> None:
        """Settle an executed result that cannot be applied to graph state."""

        with self._lock:
            self._settle_failed_action(ticket)

    def record_result(  # noqa: PLR0913 - receipt identity is explicit.
        self,
        ticket: InvestigationTicket,
        *,
        objective: GraphObjective,
        result: GraphToolResult,
        observation_decision: ObservationDecision | None = None,
        hypothesis: Hypothesis | None = None,
        agent_spec: AgentSpec | None = None,
        evidence_epoch: int | None = None,
        progress_batch: ValidatedProgressBatch | None = None,
        hypothesis_path: Sequence[str] = (),
    ) -> LoopDecision:
        try:
            if ticket.objective_fingerprint != objective.fingerprint:
                raise ProgressReceiptValidationError(
                    "investigation result objective does not match the authorized ticket"
                )
            result_hypothesis_fingerprint = (
                hypothesis.fingerprint if hypothesis is not None else ""
            )
            if ticket.hypothesis_fingerprint != result_hypothesis_fingerprint:
                raise ProgressReceiptValidationError(
                    "investigation result hypothesis does not match the authorized ticket"
                )
            target_requests = _target_request_count(result)
            if target_requests > ticket.effort.target_request_limit:
                raise ProgressReceiptValidationError(
                    "investigation result exceeds the authorized target-request grant"
                )
            validated_batch = self._resolve_progress_batch(
                ticket,
                objective=objective,
                result=result,
                hypothesis=hypothesis,
                agent_spec=agent_spec,
                progress_batch=progress_batch,
            )
        except Exception:
            with self._lock:
                self._settle_failed_action(ticket)
            raise
        with self._lock:
            trusted = validated_batch.trusted_receipts if validated_batch is not None else ()
            planner_state_attributed = bool(
                ticket.planner_state_attributed
                and (ticket.campaign is not None or trusted)
            )
            progress_kinds = tuple(sorted({receipt.kind.value for receipt in trusted}))
            policy_progress_kinds = (
                ()
                if (
                    validated_batch is not None
                    and validated_batch.classification is ProgressBatchClass.PIVOT
                )
                else progress_kinds
            )
            disproved = any(
                receipt.kind is ProgressKind.HYPOTHESIS_DISPROVED for receipt in trusted
            )
            stage = _advanced_stage(
                self.coverage.cell_state(ticket.cell.cell_id).stage,
                trusted,
            )
            material_progress = bool(trusted)
            evidence_changed = bool(trusted)
            repeated = bool(
                observation_decision is not None and observation_decision.watchdog_triggered
            )
            outcome = _attempt_outcome(
                progress_kinds=progress_kinds,
                disproved=disproved,
                repeated=repeated,
            )
            planner_feedback_enabled = self.planner_mode is not InvestigationPlannerMode.LEGACY
            planner_state: CoverageCellState | None = None
            planner_previous_feedback_digest = ""
            stale_planner_disposition: LoopDisposition | None = None
            if planner_feedback_enabled:
                try:
                    index_before = BranchOutcomeIndex.from_attempts(
                        self.coverage.snapshot().attempts
                    )
                    planner_state = self._candidate_coverage_cell(
                        execution_cell=self.coverage.cell_state(ticket.cell.cell_id),
                        planner_cell_id=ticket.planner_cell_id,
                        index=index_before,
                        root_stage=initial_stage_for_objective(objective),
                    )
                    planner_previous_feedback_digest = index_before.cell_head_digest(
                        ticket.planner_cell_id
                    )
                    if planner_state.stage is CoverageStage.PROOF:
                        if self.planner_mode is InvestigationPlannerMode.ONLINE:
                            stale_planner_disposition = LoopDisposition.PROVE
                        planner_feedback_enabled = False
                    elif (
                        planner_state.exhausted
                        or planner_state.attempt_count
                        >= self.policy.config.max_campaigns_per_cell
                    ):
                        if self.planner_mode is InvestigationPlannerMode.ONLINE:
                            stale_planner_disposition = LoopDisposition.EXHAUST
                        # A concurrently authorized action may settle after another
                        # action closes the virtual cell. Preserve its execution
                        # result without adding an impossible post-terminal branch.
                        planner_feedback_enabled = False
                except Exception:
                    self._degrade_planner("feedback_record_failed")
                    planner_feedback_enabled = False
            try:
                normalized_hypothesis_path = _canonical_hypothesis_path(
                    hypothesis_path
                    or ((hypothesis.fingerprint,) if hypothesis is not None else ())
                )
                if (
                    planner_feedback_enabled
                    and planner_state_attributed
                    and trusted
                    and planner_state is not None
                    and not {
                        receipt.evidence_ref for receipt in trusted
                    }.difference(planner_state.evidence_refs)
                ):
                    if self.planner_mode is InvestigationPlannerMode.ONLINE:
                        raise ProgressReceiptValidationError(
                            "planner progress reuses evidence already known to this cell"
                        )
                    self._degrade_planner("feedback_record_failed")
                    planner_feedback_enabled = False
            except Exception:
                self._settle_failed_action(ticket)
                raise
            try:
                prepared_belief = (
                    self.beliefs.prepare_from_validated_batch(
                        hypothesis=hypothesis,
                        agent_spec=agent_spec,
                        batch=validated_batch,
                        evidence_epoch=(
                            evidence_epoch
                            if evidence_epoch is not None
                            else self.coverage.cell_state(
                                ticket.cell.cell_id
                            ).evidence_version
                        ),
                    )
                    if (
                        self.beliefs is not None
                        and hypothesis is not None
                        and agent_spec is not None
                        and validated_batch is not None
                        and validated_batch.classification is not ProgressBatchClass.PIVOT
                    )
                    else None
                )
                belief_revision = (
                    prepared_belief.revision if prepared_belief is not None else None
                )
            except Exception:
                self._settle_failed_action(ticket)
                raise
            completion_arguments = {
                "stage": stage,
                "material_progress": material_progress,
                "evidence_changed": evidence_changed,
                "outcome": outcome,
                "planner_cell_id": ticket.planner_cell_id,
                "evidence_refs": result.evidence_refs,
                "target_requests": target_requests,
                "hypothesis_fingerprint": (
                    hypothesis.fingerprint if hypothesis is not None else ""
                ),
                "agent_spec_fingerprint": (
                    agent_spec.fingerprint if agent_spec is not None else ""
                ),
                "belief_revision_id": (
                    belief_revision.revision_id if belief_revision is not None else ""
                ),
                "belief_disposition": (
                    belief_revision.disposition.value if belief_revision is not None else ""
                ),
                "executor_receipt_digest": (
                    belief_revision.executor_receipt_digest if belief_revision is not None else ""
                ),
                "progress_class": (
                    validated_batch.classification.value if validated_batch is not None else "empty"
                ),
                "progress_kinds": progress_kinds,
                "validated_batch_digest": (
                    validated_batch.validation_digest if validated_batch is not None else ""
                ),
                "hypothesis_path": normalized_hypothesis_path,
                "repeated_observation": repeated,
                "planner_attributed": (
                    ticket.campaign is not None and planner_state_attributed
                ),
                "planner_state_attributed": planner_state_attributed,
                "planner_attempt_count_before": (
                    planner_state.attempt_count if planner_state is not None else 0
                ),
                "planner_evidence_version_before": (
                    planner_state.evidence_version if planner_state is not None else 0
                ),
                "planner_evidence_refs_before": (
                    planner_state.evidence_refs if planner_state is not None else ()
                ),
                "planner_no_progress_streak_before": (
                    planner_state.no_progress_streak if planner_state is not None else 0
                ),
                "planner_previous_feedback_digest": planner_previous_feedback_digest,
                "planner_stage_before": (
                    planner_state.stage if planner_state is not None else CoverageStage.OBSERVED
                ),
                "planner_stage_after": (
                    _advanced_stage(planner_state.stage, trusted)
                    if planner_state is not None
                    else CoverageStage.OBSERVED
                ),
                "planner_target_requests_before": (
                    planner_state.target_requests if planner_state is not None else 0
                ),
            }
            try:
                try:
                    prepared_completion = self.coverage.prepare_completion(
                        ticket.reservation,
                        planner_feedback_enabled=planner_feedback_enabled,
                        **completion_arguments,  # type: ignore[arg-type]
                    )
                except PlannerFeedbackError:
                    self._degrade_planner("feedback_record_failed")
                    prepared_completion = self.coverage.prepare_completion(
                        ticket.reservation,
                        planner_feedback_enabled=False,
                        **completion_arguments,  # type: ignore[arg-type]
                    )
            except Exception:
                self._settle_failed_action(ticket)
                raise
            belief_committed = False
            try:
                if prepared_belief is not None and self.beliefs is not None:
                    self.beliefs.commit_prepared(prepared_belief)
                    belief_committed = True
                current = self.coverage.commit_prepared(prepared_completion)
            except Exception as commit_exc:
                rollback_exc: Exception | None = None
                if (
                    belief_committed
                    and prepared_belief is not None
                    and self.beliefs is not None
                ):
                    try:
                        self.beliefs.revert_prepared(prepared_belief)
                    except Exception as exc:
                        rollback_exc = exc
                self._settle_failed_action(ticket)
                if rollback_exc is not None:
                    raise InvestigationCoverageError(
                        "coverage commit failed and belief rollback was not durable"
                    ) from commit_exc
                raise
            self._release_effort(ticket)
            if stale_planner_disposition is None and (
                disproved or repeated or not trusted
            ):
                reason = (
                    "typed_hypothesis_disproved"
                    if disproved
                    else (
                        "repeated_observation_plateau"
                        if repeated
                        else "campaign_produced_no_typed_material_delta"
                    )
                )
                self.failures.remember(
                    FailureCertificate.create(
                        cell_id=current.cell.cell_id,
                        family=current.cell.family,
                        strategy=ticket.strategy,
                        dimension=ticket.dimension,
                        evidence_version=current.evidence_version,
                        reason=reason,
                        evidence_refs=result.evidence_refs,
                    )
                )
            campaigns = self._rank_campaigns(
                node_id=ticket.reservation.node_id,
                decision_point="result_ranked",
                objective=objective,
                cell=current,
                belief_basis_points=self._belief_basis_points(hypothesis),
                record_decision=True,
                planner_cell_id=ticket.planner_cell_id,
                post_commit=True,
            )
            decision_cell = current
            if stale_planner_disposition is not None and planner_state is not None:
                decision_cell = planner_state
            elif (
                self.planner_mode is InvestigationPlannerMode.ONLINE
                and self._planner_candidate_enabled
            ):
                try:
                    decision_cell = self._candidate_coverage_cell(
                        execution_cell=current,
                        planner_cell_id=ticket.planner_cell_id,
                        index=BranchOutcomeIndex.from_attempts(
                            self.coverage.snapshot().attempts
                        ),
                        root_stage=initial_stage_for_objective(objective),
                    )
                except Exception:
                    self._degrade_planner("candidate_evaluation_failed")
                    campaigns = self.planner.rank(
                        objective=objective,
                        cell=current,
                        belief_basis_points=self._belief_basis_points(hypothesis),
                    )
            decision = (
                LoopDecision(
                    disposition=stale_planner_disposition,
                    reason=(
                        "planner_cell_already_proof_complete"
                        if stale_planner_disposition is LoopDisposition.PROVE
                        else "planner_cell_already_exhausted"
                    ),
                    cell_id=ticket.planner_cell_id,
                    stage=decision_cell.stage.value,
                    evidence_version=decision_cell.evidence_version,
                )
                if stale_planner_disposition is not None
                else self.policy.decide(
                    cell=decision_cell,
                    observation=LoopObservation(
                        trusted_progress_kinds=policy_progress_kinds,
                        hypothesis_disproved=disproved,
                        repeated_observation=repeated,
                    ),
                    campaigns=campaigns,
                )
            )
            if decision.terminal_for_cell:
                exhausted_cell_id = (
                    ticket.planner_cell_id
                    if (
                        self.planner_mode is InvestigationPlannerMode.ONLINE
                        and self._planner_candidate_enabled
                    )
                    else current.cell.cell_id
                )
                self.coverage.mark_exhausted(exhausted_cell_id)
                decision = LoopDecision(
                    disposition=decision.disposition,
                    reason=decision.reason,
                    cell_id=decision.cell_id,
                    stage=decision_cell.stage.value,
                    evidence_version=decision_cell.evidence_version,
                    required_dimension=decision.required_dimension,
                    recommended_campaign=decision.recommended_campaign,
                    recommended_probe=decision.recommended_probe,
                    recommended_additional_model_requests=(
                        decision.recommended_additional_model_requests
                    ),
                )
            self._remember_decision(ticket.reservation.node_id, decision)
            self._rank_campaigns(
                node_id=ticket.reservation.node_id,
                decision_point="result_committed",
                objective=objective,
                cell=current,
                belief_basis_points=self._belief_basis_points(hypothesis),
                record_decision=True,
                planner_cell_id=ticket.planner_cell_id,
                post_commit=True,
                committed_loop_decision=decision,
                settled_reservation_id=ticket.reservation.reservation_id,
            )
            return decision

    def _rank_campaigns(  # noqa: PLR0913 - shadow comparison inputs are explicit.
        self,
        *,
        node_id: str,
        decision_point: str,
        objective: GraphObjective,
        cell: CoverageCellState,
        belief_basis_points: int = 2500,
        record_decision: bool = False,
        authorized_reservation: CampaignReservation | None = None,
        planner_cell_id: str | None = None,
        post_commit: bool = False,
        committed_loop_decision: LoopDecision | None = None,
        settled_reservation_id: str = "",
    ) -> tuple[PlannedCampaign, ...]:
        legacy = self.planner.rank(
            objective=objective,
            cell=cell,
            belief_basis_points=belief_basis_points,
        )
        if self.planner_mode is InvestigationPlannerMode.LEGACY:
            return legacy
        try:
            index = BranchOutcomeIndex.from_attempts(self.coverage.snapshot().attempts)
        except Exception as exc:
            if self.planner_mode is InvestigationPlannerMode.SHADOW or post_commit:
                self._degrade_planner("candidate_evaluation_failed")
                return legacy
            if isinstance(exc, BranchSearchError):
                message = f"planner feedback history is invalid: {exc}"
                raise InvestigationCoverageError(message) from exc
            raise
        candidate: tuple[PlannedCampaign, ...] = ()
        if self._planner_candidate_enabled:
            try:
                candidate_cell = self._candidate_coverage_cell(
                    execution_cell=cell,
                    planner_cell_id=planner_cell_id or cell.cell.cell_id,
                    index=index,
                    root_stage=initial_stage_for_objective(objective),
                )
                candidate = self.planner.rank(
                    objective=objective,
                    cell=candidate_cell,
                    belief_basis_points=belief_basis_points,
                    outcome_index=index,
                    max_attempts=self.policy.config.max_campaigns_per_cell,
                    planner_cell_id=planner_cell_id,
                )
                candidate = self._actionable_candidate_campaigns(
                    objective=objective,
                    campaigns=candidate,
                )
            except Exception as exc:
                if self.planner_mode is InvestigationPlannerMode.SHADOW or post_commit:
                    self._degrade_planner("candidate_evaluation_failed")
                    candidate = ()
                elif isinstance(exc, BranchSearchError):
                    message = f"planner feedback history is invalid: {exc}"
                    raise InvestigationCoverageError(message) from exc
                else:
                    raise
        if record_decision:
            try:
                self._remember_planner_ranking(
                    node_id=node_id,
                    decision_point=decision_point,
                    objective=objective,
                    cell=cell,
                    index=index,
                    legacy=legacy,
                    candidate=candidate,
                    authorized_reservation=authorized_reservation,
                    planner_cell_id=planner_cell_id or cell.cell.cell_id,
                    committed_loop_decision=committed_loop_decision,
                    settled_reservation_id=settled_reservation_id,
                )
            except Exception:
                self._degrade_planner("decision_record_failed")
                return (
                    candidate
                    if (
                        self.planner_mode is InvestigationPlannerMode.ONLINE
                        and self._planner_candidate_enabled
                    )
                    else legacy
                )
        return (
            candidate
            if (
                self.planner_mode is InvestigationPlannerMode.ONLINE
                and self._planner_candidate_enabled
            )
            else legacy
        )

    def _actionable_candidate_campaigns(
        self,
        *,
        objective: GraphObjective,
        campaigns: Sequence[PlannedCampaign],
    ) -> tuple[PlannedCampaign, ...]:
        """Filter candidate output through the same concrete route gates as execution."""
        if self._route_committed_requests() >= GRAPH_ROUTE_TARGET_REQUEST_LIMIT:
            return ()
        snapshot = self.coverage.snapshot()
        actionable: list[PlannedCampaign] = []
        for planned in campaigns:
            route = _material_route(
                objective=objective,
                tool="run_probe",
                arguments={"probe": planned.campaign.probe},
            )
            cell = SurfaceCell.from_objective(objective, route=route)
            state = snapshot.cells.get(cell.cell_id)
            evidence_version = state.evidence_version if state is not None else 0
            route_key = "|".join(
                (
                    cell.cell_id,
                    _token(planned.campaign.name),
                    _token(planned.campaign.dimension),
                    str(evidence_version),
                )
            )
            if route_key in snapshot.reservations:
                continue
            if state is not None and (
                state.exhausted or state.stage is CoverageStage.PROOF
            ):
                continue
            actionable.append(planned)
        return tuple(actionable)

    def _candidate_coverage_cell(
        self,
        *,
        execution_cell: CoverageCellState,
        planner_cell_id: str,
        index: BranchOutcomeIndex,
        root_stage: CoverageStage,
    ) -> CoverageCellState:
        try:
            base = self.coverage.cell_state(planner_cell_id)
        except InvestigationCoverageError:
            base = execution_cell
        stats = index.cell_stats(planner_cell_id)
        if not any(item.cell_id == planner_cell_id for item in index.cells):
            return CoverageCellState(cell=base.cell, stage=root_stage)
        if stats.root_stage != root_stage.value:
            raise BranchSearchError(
                "planner feedback root stage does not match the objective"
            )
        stage = CoverageStage(stats.stage)
        return CoverageCellState(
            cell=base.cell,
            stage=stage,
            evidence_version=stats.evidence_version,
            attempt_count=stats.attempt_count,
            no_progress_streak=stats.no_progress_streak,
            target_requests=stats.target_requests,
            attempted_dimensions=dict(stats.attempted_dimensions),
            last_dimension=stats.last_dimension,
            last_outcome=stats.last_outcome,
            evidence_refs=stats.evidence_refs,
            exhausted=(
                base.exhausted
                or stats.attempt_count >= self.policy.config.max_campaigns_per_cell
            ),
        )

    def _remember_planner_ranking(  # noqa: PLR0913 - audit fields are explicit.
        self,
        *,
        node_id: str,
        decision_point: str,
        objective: GraphObjective,
        cell: CoverageCellState,
        index: BranchOutcomeIndex,
        legacy: tuple[PlannedCampaign, ...],
        candidate: tuple[PlannedCampaign, ...],
        authorized_reservation: CampaignReservation | None,
        planner_cell_id: str,
        committed_loop_decision: LoopDecision | None,
        settled_reservation_id: str,
    ) -> None:
        if not self._planner_recording_enabled:
            return
        candidate_active = (
            self.planner_mode is InvestigationPlannerMode.ONLINE
            and self._planner_candidate_enabled
        )
        active = candidate if candidate_active else legacy
        top = active[0] if active else None
        authorized_action = None
        if authorized_reservation is not None:
            authorized_action = {
                "reservation_id": authorized_reservation.reservation_id,
                "strategy": authorized_reservation.strategy,
                "dimension": authorized_reservation.dimension,
                "matches_top_ranked": bool(
                    top is not None
                    and _token(top.campaign.name) == authorized_reservation.strategy
                    and _token(top.campaign.dimension) == authorized_reservation.dimension
                ),
            }
        payload: dict[str, object] = {
            "schema_version": _PLANNER_DECISION_SCHEMA_VERSION,
            "planner_mode": self.planner_mode.value,
            "planner_policy_version": self.planner_policy_version,
            "decision_point": _token(decision_point),
            "node_id": node_id,
            "objective_fingerprint": objective.fingerprint,
            "cell_id": cell.cell.cell_id,
            "planner_cell_id": planner_cell_id,
            "coverage_stage": cell.stage.value,
            "evidence_version": cell.evidence_version,
            "attempt_count": cell.attempt_count,
            "degradation_reasons": sorted(self._planner_degradation_reasons),
            "outcome_index_digest": index.source_digest,
            "legacy": [_planner_row(item) for item in legacy],
            "candidate": [_planner_row(item) for item in candidate],
            "active_ranking_policy": (
                self.planner_policy_version if candidate_active else "legacy-v1"
            ),
            "top_ranked_campaign": (top.campaign.name if top is not None else ""),
            "authorized_action": authorized_action,
            "committed_loop_decision": (
                committed_loop_decision.to_json()
                if committed_loop_decision is not None
                else None
            ),
            "settled_reservation_id": _text(settled_reservation_id),
            "candidate_changed_top": (
                bool(legacy or candidate)
                and (
                    not legacy
                    or not candidate
                    or (
                        legacy[0].campaign.name,
                        legacy[0].campaign.dimension,
                    )
                    != (
                        candidate[0].campaign.name,
                        candidate[0].campaign.dimension,
                    )
                )
            ),
        }
        comparison_digest = "planner-comparison:" + _digest_json(payload)
        if comparison_digest in self._planner_comparison_digests:
            return
        if len(self._planner_decision_records) >= _MAX_PLANNER_DECISION_RECORDS:
            raise InvestigationCoverageError("planner decision record limit reached")
        previous = (
            str(self._planner_decision_records[-1]["record_digest"])
            if self._planner_decision_records
            else ""
        )
        record_without_digest = {
            **payload,
            "sequence": len(self._planner_decision_records) + 1,
            "previous_record_digest": previous,
            "comparison_digest": comparison_digest,
        }
        record = {
            **record_without_digest,
            "record_digest": "planner-record:" + _digest_json(record_without_digest),
        }
        _validate_planner_decision_record(
            record,
            expected_mode=self.planner_mode,
            expected_policy=self.planner_policy_version,
            expected_sequence=len(self._planner_decision_records) + 1,
            expected_previous=previous,
        )
        records = [*self._planner_decision_records, record]
        self._persist_planner_decision_records(records)
        self._planner_decision_records = records
        self._planner_comparison_digests.add(comparison_digest)

    def _load_planner_decision_records(self) -> list[dict[str, object]]:
        if not self.planner_decision_path.exists():
            return []
        if self.planner_decision_path.stat().st_size > _MAX_PLANNER_DECISION_BYTES:
            raise InvestigationCoverageError("planner decision file exceeds its size limit")
        lines = self.planner_decision_path.read_text(encoding="utf-8").splitlines()
        if len(lines) > _MAX_PLANNER_DECISION_RECORDS:
            raise InvestigationCoverageError("planner decision record limit exceeded")
        records: list[dict[str, object]] = []
        comparisons: set[str] = set()
        previous = ""
        observed_online = False
        for sequence, line in enumerate(lines, start=1):
            if not line.strip():
                raise InvestigationCoverageError("planner decision record cannot be empty")
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                message = f"cannot read planner decision record: {exc}"
                raise InvestigationCoverageError(message) from exc
            if not isinstance(raw, Mapping):
                message = "planner decision record must be an object"
                raise InvestigationCoverageError(message)
            record = dict(raw)
            try:
                recorded_mode = InvestigationPlannerMode(str(record.get("planner_mode") or ""))
            except ValueError as exc:
                raise InvestigationCoverageError(
                    "planner decision mode is unsupported"
                ) from exc
            if self.planner_mode is InvestigationPlannerMode.SHADOW:
                if recorded_mode is not InvestigationPlannerMode.SHADOW:
                    raise InvestigationCoverageError(
                        "planner decision mode does not match this route"
                    )
            elif self.planner_mode is InvestigationPlannerMode.ONLINE:
                if recorded_mode is InvestigationPlannerMode.LEGACY:
                    raise InvestigationCoverageError(
                        "legacy decisions cannot enter the candidate trace"
                    )
                if observed_online and recorded_mode is InvestigationPlannerMode.SHADOW:
                    raise InvestigationCoverageError(
                        "planner decision mode transition is not monotonic"
                    )
                observed_online = observed_online or recorded_mode is InvestigationPlannerMode.ONLINE
            _validate_planner_decision_record(
                record,
                expected_mode=recorded_mode,
                expected_policy=self.planner_policy_version,
                expected_sequence=sequence,
                expected_previous=previous,
            )
            comparison = str(record["comparison_digest"])
            if comparison in comparisons:
                raise InvestigationCoverageError("planner comparison record is duplicated")
            comparisons.add(comparison)
            previous = str(record["record_digest"])
            records.append(record)
        return records

    def _persist_planner_decision_records(
        self,
        records: Sequence[Mapping[str, object]],
    ) -> None:
        content = "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records
        )
        if len(content.encode()) > _MAX_PLANNER_DECISION_BYTES:
            raise InvestigationCoverageError("planner decision file exceeds its size limit")
        self.planner_decision_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.planner_decision_path.with_name(
            f".{self.planner_decision_path.name}.{os.getpid()}.tmp"
        )
        try:
            temporary.write_text(content, encoding="utf-8")
            temporary.replace(self.planner_decision_path)
        except OSError:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise

    def _require_settled_online_result_receipt(self) -> None:
        attempts = self.coverage.snapshot().attempts
        authorized_sequences: dict[str, int] = {}
        for record in self._planner_decision_records:
            authorized = record["authorized_action"]
            if isinstance(authorized, Mapping):
                authorized_sequences[str(authorized["reservation_id"])] = int(
                    record["sequence"]
                )
        sealed_ids = {
            str(item.get("reservation_id") or "")
            for item in attempts
            if "planner_feedback_schema_version" in item
        }
        if sealed_ids - authorized_sequences.keys():
            raise InvestigationCoverageError(
                "online planner feedback has no authorization receipt; resume requires review"
            )
        completed = [
            item
            for item in attempts
            if str(item.get("reservation_id") or "") in authorized_sequences
        ]
        if not completed:
            return
        committed: dict[str, list[Mapping[str, object]]] = {}
        for record in self._planner_decision_records:
            if record["decision_point"] == "result_committed":
                committed.setdefault(str(record["settled_reservation_id"]), []).append(record)
        completed_ids = {str(item["reservation_id"]) for item in completed}
        missing = sorted(completed_ids - committed.keys())
        if missing:
            raise InvestigationCoverageError(
                "online planner result has no final decision receipt; resume requires review"
            )
        for reservation_id in completed_ids:
            receipts = committed[reservation_id]
            if len(receipts) != 1 or int(receipts[0]["sequence"]) <= authorized_sequences[
                reservation_id
            ]:
                raise InvestigationCoverageError(
                    "online planner result receipt is ambiguous; resume requires review"
                )
        final_digest = BranchOutcomeIndex.from_attempts(attempts).source_digest
        latest_reservation = str(completed[-1]["reservation_id"])
        latest_receipt = committed[latest_reservation][0]
        if latest_receipt["outcome_index_digest"] == final_digest:
            return
        raise InvestigationCoverageError(
            "online planner final receipt does not match feedback state; resume requires review"
        )

    def _degrade_planner(self, reason: str) -> None:
        self._planner_degradation_reasons.add(reason)
        if reason not in _PLANNER_DEGRADATION_REASONS:
            raise InvestigationCoverageError("planner degradation reason is unsupported")
        if reason in {"candidate_evaluation_failed", "feedback_record_failed"}:
            self._planner_candidate_enabled = False
        if reason in {"decision_log_invalid", "decision_record_failed"}:
            self._planner_recording_enabled = False

    def _resolve_progress_batch(  # noqa: PLR0913 - subject identity is explicit.
        self,
        ticket: InvestigationTicket,
        *,
        objective: GraphObjective,
        result: GraphToolResult,
        hypothesis: Hypothesis | None,
        agent_spec: AgentSpec | None,
        progress_batch: ValidatedProgressBatch | None,
    ) -> ValidatedProgressBatch | None:
        if hypothesis is not None and hypothesis.objective_fingerprint != objective.fingerprint:
            message = "investigation hypothesis is bound to another objective"
            raise ProgressReceiptValidationError(message)
        expected_spec = (
            agent_spec.fingerprint
            if agent_spec is not None
            else (
                f"investigation-direct-agent-spec:{objective.fingerprint}"
                if progress_batch is None
                else ""
            )
        )
        batch = progress_batch
        supplied_batch = batch is not None
        if batch is None and result.progress_receipts:
            validator = self.evidence_validator
            if validator is None:
                message = "direct investigation progress requires an evidence validator"
                raise ProgressReceiptValidationError(message)
            target_identity = str(getattr(validator, "target_identity", "")).strip()
            if not target_identity:
                message = "direct investigation progress requires a bound evidence target"
                raise ProgressReceiptValidationError(message)
            reservation_id = ticket.reservation.reservation_id
            batch = validate_progress_receipt_batch(
                result.progress_receipts,
                result_evidence_refs=result.evidence_refs,
                evidence_validator=validator,
                binding=GraphProgressBinding(
                    graph_id=f"investigation-direct:{reservation_id}",
                    target_identity=target_identity,
                    tool_call_id=f"investigation-direct-tool:{reservation_id}",
                    runtime_binding_id=(f"investigation-direct-runtime:{expected_spec}"),
                    node_id=ticket.reservation.node_id,
                    objective_fingerprint=objective.fingerprint,
                    hypothesis_fingerprint=(
                        hypothesis.fingerprint if hypothesis is not None else ""
                    ),
                    agent_spec_fingerprint=expected_spec,
                ),
            )
        if batch is None:
            return None
        batch = require_validated_progress_batch(batch)
        if supplied_batch:
            if any(receipt.binding != batch.binding for receipt in result.progress_receipts):
                raise ProgressReceiptValidationError(
                    "validated progress batch is not bound to this executor result"
                )
            replayed_batch = validate_progress_receipt_batch(
                result.progress_receipts,
                result_evidence_refs=result.evidence_refs,
                evidence_validator=self.evidence_validator,
                binding=batch.binding,
                counterfactual_objective_fingerprint=(
                    result.counterfactual_objective_fingerprint
                ),
                allow_routed_pivot=batch.classification is ProgressBatchClass.PIVOT,
            )
            if replayed_batch != batch:
                raise ProgressReceiptValidationError(
                    "validated progress batch does not match this executor result"
                )
        expected_binding = {
            "node_id": ticket.reservation.node_id,
            "objective_fingerprint": objective.fingerprint,
            "hypothesis_fingerprint": (hypothesis.fingerprint if hypothesis is not None else ""),
            "agent_spec_fingerprint": expected_spec,
        }
        actual_binding = batch.binding.to_json()
        mismatch = tuple(
            field
            for field, expected in expected_binding.items()
            if actual_binding[field] != expected
        )
        if mismatch:
            raise ProgressReceiptValidationError(
                "validated progress batch is bound to another investigation subject: "
                + ",".join(mismatch)
            )
        return batch

    def _belief_basis_points(
        self,
        hypothesis: Hypothesis | None,
    ) -> int:
        if self.beliefs is None or hypothesis is None:
            return 2500
        revision = self.beliefs.head(hypothesis.fingerprint)
        return revision.disposition.belief_basis_points if revision is not None else 2500

    def _route_committed_requests(self) -> int:
        coverage = self.coverage.snapshot()
        charged = (
            coverage.total_target_requests
            + coverage.pessimistic_target_request_charges
        )
        reserved = sum(self._reserved_target_requests.values())
        return charged + reserved

    def _settle_failed_action(self, ticket: InvestigationTicket) -> None:
        if (
            self.planner_mode is InvestigationPlannerMode.ONLINE
            and ticket.effort.target_request_limit > 0
        ):
            self.coverage.charge_failed_reservation(
                ticket.reservation,
                authorized_grant=ticket.effort.target_request_limit,
            )
        else:
            self.coverage.cancel(ticket.reservation)
        self._release_effort(ticket)

    def _release_effort(self, ticket: InvestigationTicket) -> None:
        self._reserved_planner_feedback.discard(ticket.reservation.reservation_id)
        self._reserved_planner_cells.pop(ticket.reservation.reservation_id, None)
        self._reserved_target_requests.pop(
            ticket.reservation.reservation_id,
            None,
        )

    def _require_campaign_preconditions(
        self,
        campaign: CampaignSpec,
        *,
        objective: GraphObjective,
        current_stage: CoverageStage,
    ) -> None:
        family = canonical_family(objective.family)
        if family not in campaign.families:
            raise InvestigationActionRejectedError(
                f"campaign_family_mismatch:{campaign.name}/{family}"
            )
        if current_stage not in campaign.eligible_stages:
            raise InvestigationActionRejectedError(
                f"campaign_stage_precondition_failed:{campaign.name}/current={current_stage.value}"
            )
        if campaign.supports(objective, current_stage) or objective.strategy == campaign.probe:
            return
        raise InvestigationActionRejectedError(
            f"campaign_evidence_precondition_failed:{campaign.name}"
        )

    def _remember_decision(self, node_id: str, decision: LoopDecision) -> None:
        self._last_decisions[decision.cell_id] = decision
        self.decision_path.parent.mkdir(parents=True, exist_ok=True)
        with self.decision_path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "node_id": node_id,
                        **decision.to_json(),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )


def _material_route(
    *,
    objective: GraphObjective,
    tool: str,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    action = {"action": tool, **dict(arguments)}
    route = semantic_action_route(action, context=objective.fingerprint)
    family = canonical_family(str(route.get("family") or ""))
    if family == "unknown":
        route["family"] = canonical_family(objective.family)
    return route


def _generic_dimension(
    *,
    tool: str,
    route: Mapping[str, object],
) -> str:
    payload_class = _token(str(route.get("payload_class") or "generic"))
    method = _token(str(route.get("method") or "any"))
    identity = _token(str(route.get("identity") or "anonymous"))
    return _token(f"{tool}_{payload_class}_{method}_{identity}")


def _coverage_projection(cell: CoverageCellState) -> dict[str, object]:
    return {
        **cell.cell.to_json(),
        "stage": cell.stage.value,
        "evidence_version": cell.evidence_version,
        "attempt_count": cell.attempt_count,
        "no_progress_streak": cell.no_progress_streak,
        "target_requests": cell.target_requests,
        "attempted_dimensions": dict(sorted(cell.attempted_dimensions.items())),
        "last_dimension": cell.last_dimension,
        "last_outcome": cell.last_outcome,
        "evidence_refs": list(cell.evidence_refs),
        "exhausted": cell.exhausted,
    }


def _canonical_hypothesis_path(values: Sequence[str]) -> tuple[str, ...]:
    path = tuple(_text(str(value)) for value in values)
    if len(set(path)) != len(path):
        raise InvestigationCoverageError("hypothesis path contains a duplicate identity")
    if len(path) > _MAX_HYPOTHESIS_PATH or any(
        not value or len(value) > _MAX_PLANNER_TEXT_LENGTH for value in path
    ):
        raise InvestigationCoverageError("hypothesis path is empty or exceeds its bound")
    return path


def _advanced_stage(
    current: CoverageStage,
    receipts: Sequence[ProgressReceipt],
) -> CoverageStage:
    stages = [current]
    kinds = {receipt.kind for receipt in receipts if receipt.trusted}
    if ProgressKind.REQUEST_TEMPLATE_VALIDATED in kinds:
        stages.append(CoverageStage.CONTRACTED)
    if kinds.intersection(
        {
            ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
            ProgressKind.SQL_ORACLE_CALIBRATED,
            ProgressKind.HYPOTHESIS_CONFIRMED,
        }
    ):
        stages.append(CoverageStage.CALIBRATED)
    if ProgressKind.PRIMITIVE_CONFIRMED in kinds:
        stages.append(CoverageStage.PRIMITIVE)
    if kinds.intersection(
        {
            ProgressKind.AUTH_STATE_CHANGED,
            ProgressKind.EXTRACTION_CHECKPOINT,
        }
    ):
        stages.append(CoverageStage.CLOSURE)
    if ProgressKind.PROOF_CONFIRMED in kinds:
        stages.append(CoverageStage.PROOF)
    order = {
        CoverageStage.OBSERVED: 0,
        CoverageStage.CONTRACTED: 1,
        CoverageStage.CALIBRATED: 2,
        CoverageStage.PRIMITIVE: 3,
        CoverageStage.CLOSURE: 4,
        CoverageStage.PROOF: 5,
    }
    return max(stages, key=order.__getitem__)


def _attempt_outcome(
    *,
    progress_kinds: tuple[str, ...],
    disproved: bool,
    repeated: bool,
) -> str:
    if "proof_confirmed" in progress_kinds:
        return "proof_confirmed"
    if disproved:
        return "hypothesis_disproved"
    if progress_kinds:
        return "typed_progress:" + ",".join(progress_kinds)
    if repeated:
        return "repeated_observation"
    return "no_typed_progress"


def _target_request_count(result: GraphToolResult) -> int:
    if result.target_requests is not None:
        return result.target_requests
    try:
        envelope = json.loads(result.output)
    except (TypeError, json.JSONDecodeError):
        return 0
    if not isinstance(envelope, Mapping):
        return 0
    observation = envelope.get("observation")
    if isinstance(observation, str):
        try:
            observation = json.loads(observation)
        except json.JSONDecodeError:
            return 0
    if not isinstance(observation, Mapping):
        return 0
    requests = observation.get("requests")
    return len(requests) if isinstance(requests, list) else 0


def _token(value: str) -> str:
    return "_".join(value.strip().lower().replace("-", " ").split()) or "unspecified"


def _text(value: str) -> str:
    return " ".join(value.strip().split())


def _validate_planner_decision_record(  # noqa: C901, PLR0912 - strict chain boundary.
    record: Mapping[str, object],
    *,
    expected_mode: InvestigationPlannerMode,
    expected_policy: str,
    expected_sequence: int,
    expected_previous: str,
) -> None:
    if frozenset(record) != _PLANNER_DECISION_FIELDS:
        raise InvestigationCoverageError("planner decision fields do not match schema")
    if record["schema_version"] != _PLANNER_DECISION_SCHEMA_VERSION:
        raise InvestigationCoverageError("planner decision schema version is unsupported")
    if record["planner_mode"] != expected_mode.value:
        raise InvestigationCoverageError("planner decision mode does not match this route")
    if record["planner_policy_version"] != expected_policy:
        raise InvestigationCoverageError("planner decision policy does not match this route")
    sequence = record["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence != expected_sequence:
        raise InvestigationCoverageError("planner decision sequence is invalid")
    if record["previous_record_digest"] != expected_previous:
        raise InvestigationCoverageError("planner decision chain is invalid")
    for field in (
        "decision_point",
        "node_id",
        "objective_fingerprint",
        "cell_id",
        "planner_cell_id",
        "coverage_stage",
        "outcome_index_digest",
        "active_ranking_policy",
    ):
        value = record[field]
        if not isinstance(value, str) or not value.strip():
            raise InvestigationCoverageError(f"planner decision {field} is invalid")
    decision_point = str(record["decision_point"])
    if decision_point not in _PLANNER_DECISION_POINTS:
        raise InvestigationCoverageError("planner decision point is unsupported")
    try:
        CoverageStage(str(record["coverage_stage"]))
    except ValueError as exc:
        raise InvestigationCoverageError("planner decision coverage stage is invalid") from exc
    _planner_record_non_negative_int(record, "evidence_version")
    _planner_record_non_negative_int(record, "attempt_count")
    degradation_reasons = record["degradation_reasons"]
    if (
        not isinstance(degradation_reasons, list)
        or degradation_reasons != sorted(set(degradation_reasons))
        or any(reason not in _PLANNER_DEGRADATION_REASONS for reason in degradation_reasons)
    ):
        raise InvestigationCoverageError("planner degradation reasons are invalid")
    expected_active_policy = (
        expected_policy
        if expected_mode is InvestigationPlannerMode.ONLINE and not degradation_reasons
        else "legacy-v1"
    )
    if record["active_ranking_policy"] != expected_active_policy:
        raise InvestigationCoverageError("planner active ranking policy is invalid")
    if not isinstance(record["candidate_changed_top"], bool):
        raise InvestigationCoverageError("planner decision divergence marker is invalid")
    top = record["top_ranked_campaign"]
    if not isinstance(top, str):
        raise InvestigationCoverageError("planner decision top-ranked campaign is invalid")
    _validate_planner_rows(record["legacy"])
    _validate_planner_rows(record["candidate"])
    active_rows = (
        record["candidate"]
        if record["active_ranking_policy"] == expected_policy
        else record["legacy"]
    )
    if not isinstance(active_rows, list):  # Defensive narrowing after strict row validation.
        raise InvestigationCoverageError("planner active ranking rows are invalid")
    expected_top = str(active_rows[0]["name"]) if active_rows else ""  # type: ignore[index]
    if top != expected_top:
        raise InvestigationCoverageError("planner top-ranked campaign does not match ranking")
    legacy_rows = record["legacy"]
    candidate_rows = record["candidate"]
    if not isinstance(legacy_rows, list) or not isinstance(candidate_rows, list):
        raise InvestigationCoverageError("planner ranking rows are invalid")
    legacy_top = (
        (str(legacy_rows[0]["name"]), str(legacy_rows[0]["dimension"]))  # type: ignore[index]
        if legacy_rows
        else None
    )
    candidate_top = (
        (str(candidate_rows[0]["name"]), str(candidate_rows[0]["dimension"]))  # type: ignore[index]
        if candidate_rows
        else None
    )
    expected_changed = bool(legacy_rows or candidate_rows) and legacy_top != candidate_top
    if record["candidate_changed_top"] is not expected_changed:
        raise InvestigationCoverageError("planner divergence marker does not match rankings")
    authorized = record["authorized_action"]
    if authorized is not None:
        if not isinstance(authorized, Mapping) or set(authorized) != {
            "reservation_id",
            "strategy",
            "dimension",
            "matches_top_ranked",
        }:
            raise InvestigationCoverageError("planner authorized-action receipt is invalid")
        if not all(
            isinstance(authorized[field], str) and bool(str(authorized[field]).strip())
            for field in ("reservation_id", "strategy", "dimension")
        ) or not isinstance(authorized["matches_top_ranked"], bool):
            raise InvestigationCoverageError("planner authorized-action fields are invalid")
        expected_match = bool(
            top
            and _token(top) == authorized["strategy"]
            and active_rows
            and active_rows[0]["dimension"] == authorized["dimension"]  # type: ignore[index]
        )
        if authorized["matches_top_ranked"] is not expected_match:
            raise InvestigationCoverageError(
                "planner authorized-action match does not match ranking"
            )
    if (decision_point == "action_authorized") != (authorized is not None):
        raise InvestigationCoverageError(
            "planner authorized-action receipt is bound to the wrong decision point"
        )

    committed = record["committed_loop_decision"]
    settled_reservation_id = record["settled_reservation_id"]
    if decision_point == "result_committed":
        if not isinstance(settled_reservation_id, str) or not settled_reservation_id.strip():
            raise InvestigationCoverageError("planner settled reservation ID is invalid")
        expected_decision_cell = (
            str(record["planner_cell_id"])
            if record["active_ranking_policy"] == expected_policy
            else str(record["cell_id"])
        )
        _validate_committed_loop_decision(committed, expected_cell_id=expected_decision_cell)
    elif committed is not None or settled_reservation_id != "":
        raise InvestigationCoverageError(
            "planner final decision fields are bound to the wrong decision point"
        )

    comparison = record["comparison_digest"]
    if not _planner_digest(comparison, "planner-comparison:"):
        raise InvestigationCoverageError("planner comparison digest is invalid")
    base_payload = {
        key: value
        for key, value in record.items()
        if key
        not in {
            "comparison_digest",
            "previous_record_digest",
            "record_digest",
            "sequence",
        }
    }
    if comparison != "planner-comparison:" + _digest_json(base_payload):
        raise InvestigationCoverageError("planner comparison digest does not match")
    record_digest = record["record_digest"]
    if not _planner_digest(record_digest, "planner-record:"):
        raise InvestigationCoverageError("planner record digest is invalid")
    chained_payload = {key: value for key, value in record.items() if key != "record_digest"}
    if record_digest != "planner-record:" + _digest_json(chained_payload):
        raise InvestigationCoverageError("planner record digest does not match")


def _validate_planner_rows(value: object) -> None:
    if not isinstance(value, list):
        raise InvestigationCoverageError("planner ranking rows must be a list")
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {
            "name",
            "probe",
            "dimension",
            "score",
            "search_adjustment",
        }:
            raise InvestigationCoverageError("planner ranking row is invalid")
        if not all(
            isinstance(row[field], str) and bool(str(row[field]).strip())
            for field in ("name", "probe", "dimension")
        ):
            raise InvestigationCoverageError("planner ranking identity is invalid")
        if isinstance(row["score"], bool) or not isinstance(row["score"], int):
            raise InvestigationCoverageError("planner ranking score is invalid")
        if row["search_adjustment"] is not None and not isinstance(
            row["search_adjustment"], Mapping
        ):
            raise InvestigationCoverageError("planner ranking adjustment is invalid")


def _validate_committed_loop_decision(
    value: object,
    *,
    expected_cell_id: str,
) -> None:
    if not isinstance(value, Mapping) or frozenset(value) != _LOOP_DECISION_FIELDS:
        raise InvestigationCoverageError("planner committed loop decision is invalid")
    try:
        LoopDisposition(str(value["disposition"]))
        CoverageStage(str(value["stage"]))
    except ValueError as exc:
        raise InvestigationCoverageError(
            "planner committed loop decision enum is invalid"
        ) from exc
    for field in ("reason", "cell_id", "stage"):
        item = value[field]
        if not isinstance(item, str) or not item.strip():
            raise InvestigationCoverageError(
                f"planner committed loop decision {field} is invalid"
            )
    for field in ("required_dimension", "recommended_campaign", "recommended_probe"):
        if not isinstance(value[field], str):
            raise InvestigationCoverageError(
                f"planner committed loop decision {field} is invalid"
            )
    if value["cell_id"] != expected_cell_id:
        raise InvestigationCoverageError(
            "planner committed loop decision cell does not match active state"
        )
    _planner_record_non_negative_int(value, "evidence_version")
    _planner_record_non_negative_int(value, "recommended_additional_model_requests")


def _planner_record_non_negative_int(record: Mapping[str, object], field: str) -> int:
    value = record[field]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvestigationCoverageError(f"planner decision {field} is invalid")
    return value


def _planner_digest(value: object, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    hexadecimal = value[len(prefix) :]
    return len(hexadecimal) == _SHA256_HEX_LENGTH and all(
        character in "0123456789abcdef" for character in hexadecimal
    )


def _planner_row(item: PlannedCampaign) -> dict[str, object]:
    return {
        "name": item.campaign.name,
        "probe": item.campaign.probe,
        "dimension": item.campaign.dimension,
        "score": item.score,
        "search_adjustment": (
            item.search_adjustment.to_json() if item.search_adjustment is not None else None
        ),
    }


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


class _TicketObjective:
    """Minimal objective view used only for transport-failure planning."""

    def __init__(self, ticket: InvestigationTicket) -> None:
        self.family = ticket.cell.family
        self.strategy = ticket.campaign.probe if ticket.campaign is not None else ticket.strategy
        self.instruction = ""
        self.expected_signal = ""
        self.endpoint = ticket.cell.endpoint
        self.inputs = ticket.cell.inputs


__all__ = [
    "InvestigationActionRejectedError",
    "InvestigationEngine",
    "InvestigationTicket",
]
