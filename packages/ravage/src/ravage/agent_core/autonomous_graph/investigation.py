# The investigation engine is additive and owns no frozen-base state.
# ruff: noqa: EM101, EM102

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.beliefs import BeliefLedger
from ravage.agent_core.autonomous_graph.campaigns import (
    CampaignSpec,
    campaign_for_probe,
    initial_stage_for_objective,
)
from ravage.agent_core.autonomous_graph.coverage_ledger import (
    CampaignReservation,
    CoverageStage,
    InvestigationCoverageError,
    InvestigationCoverageLedger,
    SurfaceCell,
    canonical_family,
)
from ravage.agent_core.autonomous_graph.effort_policy import (
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
    InvestigationWorkPlanner,
)
from ravage.agent_core.semantic_routes import semantic_action_route

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


class InvestigationActionRejectedError(GraphActionRejectedError):
    """Raised before target/tool accounting when loop policy forbids an action."""


@dataclass(frozen=True)
class InvestigationTicket:
    reservation: CampaignReservation
    cell: SurfaceCell
    strategy: str
    dimension: str
    effort: GraphEffortGrant
    campaign: CampaignSpec | None = None


class InvestigationEngine:
    """
    Coverage-guided strategy and loop controller for the experimental graph route.

    Existing Ravage probes remain the execution units. This layer chooses and
    remembers finite campaigns; it never writes or executes model-authored loops.
    """

    def __init__(  # noqa: PLR0913 - dependencies are explicit.
        self,
        *,
        coverage: InvestigationCoverageLedger,
        failures: InvestigationFailureMemory,
        decision_path: Path,
        beliefs: BeliefLedger | None = None,
        evidence_validator: ProgressEvidenceValidator | None = None,
        policy: InvestigationLoopPolicy | None = None,
    ) -> None:
        self.coverage = coverage
        self.failures = failures
        self.beliefs = beliefs
        self.evidence_validator = evidence_validator
        self.planner = InvestigationWorkPlanner(failures)
        self.policy = policy or InvestigationLoopPolicy()
        self.decision_path = decision_path
        self._lock = threading.RLock()
        self._last_decisions: dict[str, LoopDecision] = {}
        self._reserved_target_requests: dict[str, int] = {}

    @classmethod
    def open(
        cls,
        *,
        workspace_dir: Path,
        objectives: Sequence[GraphObjective] = (),
        evidence_validator: ProgressEvidenceValidator | None = None,
    ) -> InvestigationEngine:
        engine = cls(
            coverage=InvestigationCoverageLedger.open(
                workspace_dir / "investigation-coverage.json"
            ),
            failures=InvestigationFailureMemory.open(workspace_dir / "investigation-failures.json"),
            decision_path=workspace_dir / "investigation-decisions.jsonl",
            evidence_validator=evidence_validator,
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
        del node_id
        with self._lock:
            cell = SurfaceCell.from_objective(objective)
            current = self.coverage.ensure_cell(
                cell,
                initial_stage=initial_stage_for_objective(objective),
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
            campaigns = self.planner.rank(
                objective=objective,
                cell=current,
                belief_basis_points=raw_belief_basis_points,
            )
            return {
                "mode": "coverage_guided_finite_campaigns",
                "hypothesis": (hypothesis.to_json() if hypothesis is not None else None),
                "belief": belief,
                "coverage_cell": self.coverage.projection(cell.cell_id),
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
                        current,
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
            "coverage_cells": len(coverage.cells),
            "stage_counts": dict(sorted(stages.items())),
            "exhausted_cells": sum(cell.exhausted for cell in coverage.cells.values()),
            "campaign_attempts": len(coverage.attempts),
            "target_requests_observed": coverage.total_target_requests,
            "target_request_effort": effort_policy_projection(),
            "failure_certificates": len(failures.certificates),
            "belief_revisions": (
                len(self.beliefs.snapshot().revisions) if self.beliefs is not None else 0
            ),
            "artifacts": {
                "coverage": self.coverage.state_path.name,
                "failures": self.failures.state_path.name,
                "decisions": self.decision_path.name,
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
            campaign = (
                campaign_for_probe(
                    str(arguments.get("probe") or ""),
                    objective=objective,
                    stage=current.stage,
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
                    current_stage=current.stage,
                )
            else:
                strategy = _token(str(arguments.get("strategy") or tool))
                dimension = _generic_dimension(tool=tool, route=route)

            campaigns = self.planner.rank(
                objective=objective,
                cell=current,
                belief_basis_points=self._belief_basis_points(hypothesis),
            )
            if (
                tool in _AD_HOC_LOOP_TOOLS
                and current.cell.family not in {"graph_coordination", "unknown"}
                and current.attempt_count == 0
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
            if blocking is not None:
                next_dimension = campaigns[0].campaign.dimension if campaigns else "none"
                raise InvestigationActionRejectedError(
                    "failure_certificate_blocks_equivalent_campaign:"
                    f"{blocking.certificate_id};required_new_dimension={next_dimension}"
                )
            if current.exhausted:
                raise InvestigationActionRejectedError(
                    "coverage_cell_exhausted_without_new_evidence"
                )
            effort = grant_graph_effort(
                current,
                route_committed=self._route_committed_requests(),
            )
            if tool == "run_probe" and effort.target_request_limit <= 0:
                raise InvestigationActionRejectedError(
                    "graph_route_target_request_budget_exhausted"
                )
            try:
                reservation = self.coverage.reserve(
                    node_id=node_id,
                    cell=cell,
                    strategy=strategy,
                    dimension=dimension,
                )
            except InvestigationCoverageError as exc:
                raise InvestigationActionRejectedError(str(exc)) from exc
            if tool == "run_probe":
                self._reserved_target_requests[reservation.reservation_id] = (
                    effort.target_request_limit
                )
            return InvestigationTicket(
                reservation=reservation,
                cell=cell,
                strategy=strategy,
                dimension=dimension,
                effort=effort,
                campaign=campaign,
            )

    def cancel_action(self, ticket: InvestigationTicket) -> None:
        with self._lock:
            self._release_effort(ticket)
            self.coverage.cancel(ticket.reservation)

    def record_tool_failure(
        self,
        ticket: InvestigationTicket,
        *,
        reason: str,
    ) -> LoopDecision:
        with self._lock:
            self._release_effort(ticket)
            self.coverage.cancel(ticket.reservation)
            current = self.coverage.cell_state(ticket.cell.cell_id)
            campaigns = self.planner.rank(
                objective=_TicketObjective(ticket),  # type: ignore[arg-type]
                cell=current,
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
    ) -> LoopDecision:
        try:
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
                self._release_effort(ticket)
                self.coverage.cancel(ticket.reservation)
            raise
        with self._lock:
            self._release_effort(ticket)
            trusted = validated_batch.trusted_receipts if validated_batch is not None else ()
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
            belief_revision = (
                self.beliefs.record_from_validated_batch(
                    hypothesis=hypothesis,
                    agent_spec=agent_spec,
                    batch=validated_batch,
                    evidence_epoch=(
                        evidence_epoch
                        if evidence_epoch is not None
                        else self.coverage.cell_state(ticket.cell.cell_id).evidence_version
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
            outcome = _attempt_outcome(
                progress_kinds=progress_kinds,
                disproved=disproved,
                repeated=repeated,
            )
            current = self.coverage.complete(
                ticket.reservation,
                stage=stage,
                material_progress=material_progress,
                evidence_changed=evidence_changed,
                outcome=outcome,
                evidence_refs=result.evidence_refs,
                target_requests=_target_request_count(result),
                hypothesis_fingerprint=(hypothesis.fingerprint if hypothesis is not None else ""),
                agent_spec_fingerprint=(agent_spec.fingerprint if agent_spec is not None else ""),
                belief_revision_id=(
                    belief_revision.revision_id if belief_revision is not None else ""
                ),
                belief_disposition=(
                    belief_revision.disposition.value if belief_revision is not None else ""
                ),
                executor_receipt_digest=(
                    belief_revision.executor_receipt_digest if belief_revision is not None else ""
                ),
            )
            if disproved or repeated or not trusted:
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
            campaigns = self.planner.rank(
                objective=objective,
                cell=current,
                belief_basis_points=self._belief_basis_points(hypothesis),
            )
            decision = self.policy.decide(
                cell=current,
                observation=LoopObservation(
                    trusted_progress_kinds=policy_progress_kinds,
                    hypothesis_disproved=disproved,
                    repeated_observation=repeated,
                ),
                campaigns=campaigns,
            )
            if decision.terminal_for_cell:
                current = self.coverage.mark_exhausted(current.cell.cell_id)
                decision = LoopDecision(
                    disposition=decision.disposition,
                    reason=decision.reason,
                    cell_id=decision.cell_id,
                    stage=current.stage.value,
                    evidence_version=current.evidence_version,
                    required_dimension=decision.required_dimension,
                    recommended_campaign=decision.recommended_campaign,
                    recommended_probe=decision.recommended_probe,
                    recommended_additional_model_requests=(
                        decision.recommended_additional_model_requests
                    ),
                )
            self._remember_decision(ticket.reservation.node_id, decision)
            return decision

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
        observed = self.coverage.snapshot().total_target_requests
        reserved = sum(self._reserved_target_requests.values())
        return observed + reserved

    def _release_effort(self, ticket: InvestigationTicket) -> None:
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
