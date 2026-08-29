from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from ravage.agent_core.recovery_evidence import (
    RecoveryEvidenceAssessment,
    RecoveryLead,
    assess_recovery_evidence,
)
from ravage.agent_core.recovery_objectives import (
    RecoveryAttempt,
    RecoveryHandoff,
    RecoveryObjective,
    build_recovery_role_context,
    plan_recovery_objective,
    recovery_handoff_from_final,
)
from ravage.agent_core.recovery_policy import (
    RecoveryBudgetExceededError,
    RecoveryConfig,
    RecoveryDecision,
    RecoveryLeaseExceededError,
    RecoveryRole,
    RecoveryScheduler,
    RecoverySchedulerStoppedError,
    RecoveryStatus,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from ravage.agent_core.action_executor import ActionResult

_STATE_VERSION = 1
_PROFILE = "recovery-v1"
_MAX_LEADS = 64
_MAX_ATTEMPTS = 200
_MAX_HANDOFFS = 32
_MIN_MODEL_REQUESTS = 2


class InvalidRecoveryCampaignStateError(ValueError):
    def __init__(self, field_name: str, reason: str) -> None:
        super().__init__(f"{field_name} {reason}")


class RecoveryRequestAccountingError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)


class PendingRecoveryRequestError(RecoveryRequestAccountingError):
    def __init__(self) -> None:
        super().__init__("cannot begin a model request while another request is pending")


class MissingInterruptedRecoveryRequestError(RecoveryRequestAccountingError):
    def __init__(self) -> None:
        super().__init__("no interrupted model request is pending")


class UnstartedRecoveryRequestError(RecoveryRequestAccountingError):
    def __init__(self) -> None:
        super().__init__("model request must be started before recording its action result")


class InvalidRecoveryBudgetError(ValueError):
    def __init__(self) -> None:
        super().__init__("recovery-v1 requires at least two model requests")


class _CampaignField(StrEnum):
    ACTIVE_OBJECTIVE = "active_objective"
    VERSION_PROFILE = "version/profile"
    TARGET_URL = "target_url"
    MAX_MODEL_REQUESTS = "max_model_requests"
    RECOVERY_STATE = "recovery state"
    STARTED_MODEL_REQUESTS = "started_model_requests"


@dataclass(frozen=True)
class RecoveryTurnResult:
    assessment: RecoveryEvidenceAssessment
    decision: RecoveryDecision
    branch_changed: bool
    active_objective: RecoveryObjective | None


@dataclass
class RecoveryCampaign:
    """Durable parent state for one opt-in sequential recovery campaign."""

    target_url: str
    scheduler: RecoveryScheduler
    started_model_requests: int = 0
    interrupted_model_requests: int = 0
    leads: list[RecoveryLead] = field(default_factory=list)
    attempts: list[RecoveryAttempt] = field(default_factory=list)
    active_objective: RecoveryObjective | None = None
    handoffs: list[RecoveryHandoff] = field(default_factory=list)

    @classmethod
    def create(cls, *, target_url: str, max_model_requests: int) -> RecoveryCampaign:
        scheduler = RecoveryScheduler(recovery_config_for_budget(max_model_requests))
        return cls(target_url=target_url, scheduler=scheduler)

    @property
    def has_pending_model_request(self) -> bool:
        return self.started_model_requests > self.scheduler.total_model_requests

    @property
    def next_turn(self) -> int:
        return self.scheduler.total_model_requests + 1

    def begin_model_request(self) -> None:
        if self.has_pending_model_request:
            raise PendingRecoveryRequestError
        if self.scheduler.status is not RecoveryStatus.RUNNING:
            raise RecoverySchedulerStoppedError(self.scheduler.status)
        if self.scheduler.total_model_requests >= self.scheduler.config.max_model_requests:
            raise RecoveryBudgetExceededError
        if self.scheduler.lease_used >= self.scheduler.lease_limit:
            raise RecoveryLeaseExceededError(self.scheduler.role)
        self.started_model_requests += 1

    def account_interrupted_request(
        self,
        *,
        recommended_specialists: Sequence[Mapping[str, object]] = (),
    ) -> RecoveryDecision:
        if not self.has_pending_model_request:
            raise MissingInterruptedRecoveryRequestError
        planned_counterfactual = self._next_counterfactual(
            recommended_specialists=recommended_specialists
        )
        previous_branch = self.scheduler.active_branch_id
        decision = self.scheduler.record_model_turn(
            self.scheduler.last_snapshot,
            observation_digest=f"interrupted-request:{self.started_model_requests}",
            next_objective_fingerprint=(
                planned_counterfactual.fingerprint if planned_counterfactual else ""
            ),
        )
        self.interrupted_model_requests += 1
        self._advance_objective(
            decision,
            previous_branch=previous_branch,
            planned_counterfactual=planned_counterfactual,
            recommended_specialists=recommended_specialists,
        )
        return decision

    def record_action_result(
        self,
        *,
        action: Mapping[str, object],
        outcome: ActionResult,
        recommended_specialists: Sequence[Mapping[str, object]] = (),
        branch_handoff: bool = False,
    ) -> RecoveryTurnResult:
        if not self.has_pending_model_request:
            raise UnstartedRecoveryRequestError
        assessment = assess_recovery_evidence(
            self.scheduler.last_snapshot,
            action=action,
            outcome=outcome.to_json(),
            source_kind=outcome.evidence_source_kind,
            raw_observation=outcome.evidence_observation or None,
        )
        self._remember_leads(assessment.leads)
        self.attempts.append(RecoveryAttempt.from_assessment(action=action, assessment=assessment))
        del self.attempts[:-_MAX_ATTEMPTS]

        planned_counterfactual = self._next_counterfactual(
            recommended_specialists=recommended_specialists
        )
        previous_branch = self.scheduler.active_branch_id
        decision = self.scheduler.record_model_turn(
            assessment.snapshot,
            route_fingerprint=assessment.route_fingerprint,
            low_value_route=assessment.low_value_route,
            observation_digest=assessment.observation_digest,
            next_objective_fingerprint=(
                planned_counterfactual.fingerprint if planned_counterfactual else ""
            ),
            branch_handoff=branch_handoff,
        )
        self._advance_objective(
            decision,
            previous_branch=previous_branch,
            planned_counterfactual=planned_counterfactual,
            recommended_specialists=recommended_specialists,
        )
        return RecoveryTurnResult(
            assessment=assessment,
            decision=decision,
            branch_changed=previous_branch != decision.next_branch_id,
            active_objective=self.active_objective,
        )

    def ensure_objective(
        self,
        *,
        recommended_specialists: Sequence[Mapping[str, object]] = (),
    ) -> RecoveryObjective | None:
        if self.scheduler.status is not RecoveryStatus.RUNNING:
            self.active_objective = None
            return None
        if self.scheduler.role is RecoveryRole.CORE:
            self.active_objective = None
            return None
        if self.active_objective is not None and self.active_objective.role is self.scheduler.role:
            return self.active_objective
        self.active_objective = plan_recovery_objective(
            self.scheduler.role,
            leads=self.leads,
            recommended_specialists=recommended_specialists,
            attempts=self.attempts,
            attempted_objective_fingerprints=(self.scheduler.attempted_objective_fingerprints),
        )
        return self.active_objective

    def role_context(
        self,
        *,
        recommended_specialists: Sequence[Mapping[str, object]] = (),
    ) -> dict[str, object] | None:
        objective = self.ensure_objective(recommended_specialists=recommended_specialists)
        branch_id = self.scheduler.active_branch_id
        if objective is None or not branch_id:
            return None
        return build_recovery_role_context(
            branch_id=branch_id,
            objective=objective,
            lease_budget=self.scheduler.lease_limit,
            lease_used=self.scheduler.lease_used,
            evidence_epoch=self.scheduler.evidence_epoch,
            leads=self.leads,
            attempts=self.attempts,
        )

    def create_handoff(self, action: Mapping[str, object]) -> RecoveryHandoff:
        if self.active_objective is None or not self.scheduler.active_branch_id:
            raise InvalidRecoveryCampaignStateError(
                _CampaignField.ACTIVE_OBJECTIVE,
                "is required before a handoff",
            )
        handoff = recovery_handoff_from_final(
            branch_id=self.scheduler.active_branch_id,
            objective=self.active_objective,
            action=action,
        )
        self.handoffs.append(handoff)
        del self.handoffs[:-_MAX_HANDOFFS]
        return handoff

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "profile": _PROFILE,
            "target_url": self.target_url,
            "started_model_requests": self.started_model_requests,
            "interrupted_model_requests": self.interrupted_model_requests,
            "scheduler": self.scheduler.to_json(),
            "leads": [lead.to_json() for lead in self.leads],
            "attempts": [attempt.to_json() for attempt in self.attempts],
            "active_objective": (
                self.active_objective.to_json() if self.active_objective else None
            ),
            "handoffs": [handoff.to_json() for handoff in self.handoffs],
        }

    @classmethod
    def from_json(
        cls,
        payload: Mapping[str, object],
        *,
        target_url: str,
        max_model_requests: int,
    ) -> RecoveryCampaign:
        if payload.get("version") != _STATE_VERSION or payload.get("profile") != _PROFILE:
            raise InvalidRecoveryCampaignStateError(
                _CampaignField.VERSION_PROFILE,
                "is unsupported",
            )
        if payload.get("target_url") != target_url:
            raise InvalidRecoveryCampaignStateError(
                _CampaignField.TARGET_URL,
                "does not match the requested target",
            )
        scheduler_payload = _mapping(payload.get("scheduler"), field_name="scheduler")
        scheduler = RecoveryScheduler.from_json(scheduler_payload)
        if scheduler.config.max_model_requests != max_model_requests:
            raise InvalidRecoveryCampaignStateError(
                _CampaignField.MAX_MODEL_REQUESTS,
                "does not match the recovery state budget",
            )
        campaign = cls(
            target_url=target_url,
            scheduler=scheduler,
            started_model_requests=_integer(
                payload.get("started_model_requests"),
                field_name="started_model_requests",
            ),
            interrupted_model_requests=_integer(
                payload.get("interrupted_model_requests"),
                field_name="interrupted_model_requests",
            ),
            leads=[
                RecoveryLead.from_json(item)
                for item in _mapping_list(payload.get("leads"), field_name="leads")
            ],
            attempts=[
                RecoveryAttempt.from_json(item)
                for item in _mapping_list(payload.get("attempts"), field_name="attempts")
            ],
            active_objective=_optional_objective(payload.get("active_objective")),
            handoffs=[
                RecoveryHandoff.from_json(item)
                for item in _mapping_list(payload.get("handoffs"), field_name="handoffs")
            ],
        )
        campaign._validate_request_accounting()
        return campaign

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    @classmethod
    def load_or_create(
        cls,
        path: Path,
        *,
        target_url: str,
        max_model_requests: int,
    ) -> RecoveryCampaign:
        if not path.exists():
            return cls.create(
                target_url=target_url,
                max_model_requests=max_model_requests,
            )
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise InvalidRecoveryCampaignStateError(
                _CampaignField.RECOVERY_STATE,
                "must be an object",
            )
        return cls.from_json(
            payload,
            target_url=target_url,
            max_model_requests=max_model_requests,
        )

    def _next_counterfactual(
        self,
        *,
        recommended_specialists: Sequence[Mapping[str, object]],
    ) -> RecoveryObjective | None:
        return plan_recovery_objective(
            RecoveryRole.COUNTERFACTUAL,
            leads=self.leads,
            recommended_specialists=recommended_specialists,
            attempts=self.attempts,
            attempted_objective_fingerprints=(self.scheduler.attempted_objective_fingerprints),
        )

    def _advance_objective(
        self,
        decision: RecoveryDecision,
        *,
        previous_branch: str | None,
        planned_counterfactual: RecoveryObjective | None,
        recommended_specialists: Sequence[Mapping[str, object]],
    ) -> None:
        if decision.status is not RecoveryStatus.RUNNING:
            self.active_objective = None
            return
        if previous_branch == decision.next_branch_id:
            return
        if (
            decision.next_role is RecoveryRole.COUNTERFACTUAL
            and planned_counterfactual is not None
            and decision.next_objective_fingerprint == planned_counterfactual.fingerprint
        ):
            self.active_objective = planned_counterfactual
            return
        self.active_objective = None
        self.ensure_objective(recommended_specialists=recommended_specialists)

    def _remember_leads(self, leads: Sequence[RecoveryLead]) -> None:
        for lead in leads:
            self.leads = [item for item in self.leads if item.fingerprint != lead.fingerprint]
            self.leads.append(lead)
        del self.leads[:-_MAX_LEADS]

    def _validate_request_accounting(self) -> None:
        completed = self.scheduler.total_model_requests
        if self.started_model_requests not in {completed, completed + 1}:
            raise InvalidRecoveryCampaignStateError(
                _CampaignField.STARTED_MODEL_REQUESTS,
                "must equal completed requests or have one pending",
            )


def recovery_config_for_budget(max_model_requests: int) -> RecoveryConfig:
    if max_model_requests < _MIN_MODEL_REQUESTS:
        raise InvalidRecoveryBudgetError
    proof_reserve = min(6, max(1, (max_model_requests * 15 + 99) // 100))
    exploration_budget = max_model_requests - proof_reserve
    return RecoveryConfig(
        max_model_requests=max_model_requests,
        initial_core_lease=min(4, exploration_budget),
        closure_lease=min(6, exploration_budget),
        counterfactual_lease=min(8, exploration_budget),
        progress_lease=min(8, max_model_requests),
        proof_reserve=proof_reserve,
    )


def _mapping(value: object, *, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise InvalidRecoveryCampaignStateError(field_name, "must be an object")
    return {str(key): item for key, item in value.items()}


def _mapping_list(value: object, *, field_name: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise InvalidRecoveryCampaignStateError(field_name, "must be a list of objects")
    return [{str(key): item_value for key, item_value in item.items()} for item in value]


def _integer(value: object, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidRecoveryCampaignStateError(
            field_name,
            "must be a non-negative integer",
        )
    return value


def _optional_objective(value: object) -> RecoveryObjective | None:
    if value is None:
        return None
    return RecoveryObjective.from_json(_mapping(value, field_name="active_objective"))
