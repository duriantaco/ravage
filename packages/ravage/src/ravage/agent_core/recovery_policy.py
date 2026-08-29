from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

_STATE_VERSION = 2


class RecoveryRole(StrEnum):
    CORE = "core"
    CLOSURE = "closure"
    COUNTERFACTUAL = "counterfactual"


class RecoveryStatus(StrEnum):
    RUNNING = "running"
    SOLVED = "solved"
    BUDGET_EXHAUSTED = "budget_exhausted"
    EXPLORATION_EXHAUSTED = "exploration_exhausted"


class MaterialProgressKind(StrEnum):
    PROOF_CONFIRMED = "proof_confirmed"
    PRIMITIVE_CONFIRMED = "primitive_confirmed"
    AUTH_STATE_CHANGED = "auth_state_changed"
    REQUEST_TEMPLATE_VALIDATED = "request_template_validated"
    RESPONSE_DIFFERENTIAL_VALIDATED = "response_differential_validated"
    HYPOTHESIS_CONFIRMED = "hypothesis_confirmed"
    HYPOTHESIS_DISPROVED = "hypothesis_disproved"


_PROOF_CLOSEABLE_PROGRESS = frozenset(
    {
        MaterialProgressKind.PRIMITIVE_CONFIRMED,
        MaterialProgressKind.AUTH_STATE_CHANGED,
        MaterialProgressKind.REQUEST_TEMPLATE_VALIDATED,
        MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
        MaterialProgressKind.HYPOTHESIS_CONFIRMED,
    }
)


class InvalidRecoveryConfigError(ValueError):
    def __init__(self, field_name: str, reason: str) -> None:
        super().__init__(f"{field_name} {reason}")


class InvalidRecoveryStateError(ValueError):
    def __init__(self, field_name: str, reason: str) -> None:
        super().__init__(f"{field_name} {reason}")


class InvalidRecoveryStateTypeError(TypeError):
    def __init__(self, field_name: str, expected: str) -> None:
        super().__init__(f"{field_name} must be {expected}")


class RecoverySchedulerStoppedError(RuntimeError):
    def __init__(self, status: RecoveryStatus) -> None:
        super().__init__(f"cannot record a turn after scheduler status {status.value}")


class RecoveryBudgetExceededError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("cannot exceed the global model-request budget")


class RecoveryLeaseExceededError(RuntimeError):
    def __init__(self, role: RecoveryRole) -> None:
        super().__init__(f"cannot exceed the active {role.value} lease")


@dataclass(frozen=True)
class RecoveryConfig:
    """Progressive leases under one globally-accounted request budget."""

    max_model_requests: int = 40
    initial_core_lease: int = 4
    closure_lease: int = 6
    counterfactual_lease: int = 8
    progress_lease: int = 8
    proof_reserve: int = 6
    low_value_route_limit: int = 2
    repeated_observation_limit: int = 2
    max_counterfactual_leases_per_epoch: int = 3

    def __post_init__(self) -> None:
        positive_fields = {
            "max_model_requests": self.max_model_requests,
            "initial_core_lease": self.initial_core_lease,
            "closure_lease": self.closure_lease,
            "counterfactual_lease": self.counterfactual_lease,
            "progress_lease": self.progress_lease,
            "proof_reserve": self.proof_reserve,
            "low_value_route_limit": self.low_value_route_limit,
            "repeated_observation_limit": self.repeated_observation_limit,
            "max_counterfactual_leases_per_epoch": (self.max_counterfactual_leases_per_epoch),
        }
        for name, value in positive_fields.items():
            if value <= 0:
                raise InvalidRecoveryConfigError(name, "must be greater than zero")

        if self.proof_reserve >= self.max_model_requests:
            field_name = "proof_reserve"
            raise InvalidRecoveryConfigError(
                field_name,
                "must be smaller than max_model_requests",
            )

        exploration_budget = self.exploration_budget
        exploration_leases = {
            "initial_core_lease": self.initial_core_lease,
            "closure_lease": self.closure_lease,
            "counterfactual_lease": self.counterfactual_lease,
        }
        for name, value in exploration_leases.items():
            if value > exploration_budget:
                raise InvalidRecoveryConfigError(
                    name,
                    "cannot exceed the unreserved exploration budget",
                )
        if self.progress_lease > self.max_model_requests:
            field_name = "progress_lease"
            raise InvalidRecoveryConfigError(
                field_name,
                "cannot exceed max_model_requests",
            )

    @property
    def exploration_budget(self) -> int:
        return self.max_model_requests - self.proof_reserve

    def to_json(self) -> dict[str, object]:
        return {
            "max_model_requests": self.max_model_requests,
            "initial_core_lease": self.initial_core_lease,
            "closure_lease": self.closure_lease,
            "counterfactual_lease": self.counterfactual_lease,
            "progress_lease": self.progress_lease,
            "proof_reserve": self.proof_reserve,
            "low_value_route_limit": self.low_value_route_limit,
            "repeated_observation_limit": self.repeated_observation_limit,
            "max_counterfactual_leases_per_epoch": (self.max_counterfactual_leases_per_epoch),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RecoveryConfig:
        return cls(
            max_model_requests=_required_int(payload, "max_model_requests"),
            initial_core_lease=_required_int(payload, "initial_core_lease"),
            closure_lease=_required_int(payload, "closure_lease"),
            counterfactual_lease=_required_int(payload, "counterfactual_lease"),
            progress_lease=_required_int(payload, "progress_lease"),
            proof_reserve=_required_int(payload, "proof_reserve"),
            low_value_route_limit=_required_int(payload, "low_value_route_limit"),
            repeated_observation_limit=_required_int(
                payload,
                "repeated_observation_limit",
            ),
            max_counterfactual_leases_per_epoch=_required_int(
                payload,
                "max_counterfactual_leases_per_epoch",
            ),
        )


@dataclass(frozen=True)
class ProgressSnapshot:
    """Only target-observed, proof-gated fields can constitute material progress."""

    confirmed_proofs: frozenset[str] = field(default_factory=frozenset)
    confirmed_primitives: frozenset[str] = field(default_factory=frozenset)
    authenticated_states: frozenset[str] = field(default_factory=frozenset)
    validated_request_templates: frozenset[str] = field(default_factory=frozenset)
    validated_response_differentials: frozenset[str] = field(default_factory=frozenset)
    confirmed_hypotheses: frozenset[str] = field(default_factory=frozenset)
    disproved_hypotheses: frozenset[str] = field(default_factory=frozenset)
    weak_signals: frozenset[str] = field(default_factory=frozenset)

    def material_delta(self, previous: ProgressSnapshot) -> tuple[MaterialProgressKind, ...]:
        fields = (
            (
                MaterialProgressKind.PROOF_CONFIRMED,
                self.confirmed_proofs,
                previous.confirmed_proofs,
            ),
            (
                MaterialProgressKind.PRIMITIVE_CONFIRMED,
                self.confirmed_primitives,
                previous.confirmed_primitives,
            ),
            (
                MaterialProgressKind.AUTH_STATE_CHANGED,
                self.authenticated_states,
                previous.authenticated_states,
            ),
            (
                MaterialProgressKind.REQUEST_TEMPLATE_VALIDATED,
                self.validated_request_templates,
                previous.validated_request_templates,
            ),
            (
                MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
                self.validated_response_differentials,
                previous.validated_response_differentials,
            ),
            (
                MaterialProgressKind.HYPOTHESIS_CONFIRMED,
                self.confirmed_hypotheses,
                previous.confirmed_hypotheses,
            ),
            (
                MaterialProgressKind.HYPOTHESIS_DISPROVED,
                self.disproved_hypotheses,
                previous.disproved_hypotheses,
            ),
        )
        return tuple(kind for kind, current, old in fields if current - old)

    def to_json(self) -> dict[str, object]:
        return {
            "confirmed_proofs": sorted(self.confirmed_proofs),
            "confirmed_primitives": sorted(self.confirmed_primitives),
            "authenticated_states": sorted(self.authenticated_states),
            "validated_request_templates": sorted(self.validated_request_templates),
            "validated_response_differentials": sorted(self.validated_response_differentials),
            "confirmed_hypotheses": sorted(self.confirmed_hypotheses),
            "disproved_hypotheses": sorted(self.disproved_hypotheses),
            "weak_signals": sorted(self.weak_signals),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> ProgressSnapshot:
        return cls(
            confirmed_proofs=_string_set(payload, "confirmed_proofs"),
            confirmed_primitives=_string_set(payload, "confirmed_primitives"),
            authenticated_states=_string_set(payload, "authenticated_states"),
            validated_request_templates=_string_set(payload, "validated_request_templates"),
            validated_response_differentials=_string_set(
                payload,
                "validated_response_differentials",
            ),
            confirmed_hypotheses=_string_set(payload, "confirmed_hypotheses"),
            disproved_hypotheses=_string_set(payload, "disproved_hypotheses"),
            weak_signals=_string_set(payload, "weak_signals"),
        )


@dataclass(frozen=True)
class RecoveryDecision:
    executed_role: RecoveryRole
    next_role: RecoveryRole | None
    status: RecoveryStatus
    reason: str
    total_model_requests: int
    remaining_model_requests: int
    remaining_exploration_requests: int
    proof_reserve_remaining: int
    evidence_epoch: int
    material_progress: tuple[MaterialProgressKind, ...]
    executed_branch_id: str | None
    next_branch_id: str | None
    executed_lease_budget: int
    executed_lease_used: int
    next_lease_budget: int | None
    next_lease_used: int | None
    next_objective_fingerprint: str | None
    route_exhausted: bool
    observation_watchdog_triggered: bool
    branch_handoff_triggered: bool


@dataclass
class RecoveryScheduler:
    """Issues small leases and escalates only on pivots or material target evidence."""

    config: RecoveryConfig = field(default_factory=RecoveryConfig)
    role: RecoveryRole = RecoveryRole.CORE
    status: RecoveryStatus = RecoveryStatus.RUNNING
    total_model_requests: int = 0
    lease_limit: int = 0
    lease_used: int = 0
    evidence_epoch: int = 0
    branches_started_in_epoch: list[RecoveryRole] = field(default_factory=list)
    low_value_route_attempts: dict[str, int] = field(default_factory=dict)
    active_branch_id: str | None = None
    next_branch_sequence: int = 1
    branch_uses_proof_reserve: bool = False
    last_observation_digest: str = ""
    repeated_observation_count: int = 0
    attempted_objective_fingerprints: set[str] = field(default_factory=set)
    active_objective_fingerprint: str | None = None
    last_snapshot: ProgressSnapshot = field(default_factory=ProgressSnapshot)

    def __post_init__(self) -> None:
        if self.lease_limit == 0:
            self.lease_limit = self.config.initial_core_lease
        if self.lease_limit < 0:
            field_name = "lease_limit"
            raise InvalidRecoveryStateError(field_name, "cannot be negative")
        if self.lease_used < 0 or self.lease_used > self.lease_limit:
            field_name = "lease_used"
            raise InvalidRecoveryStateError(field_name, "must fit within the active lease")

    @property
    def exploration_ceiling(self) -> int:
        return self.config.exploration_budget

    @property
    def remaining_exploration_requests(self) -> int:
        return max(0, self.exploration_ceiling - self.total_model_requests)

    @property
    def proof_reserve_remaining(self) -> int:
        reserve_spent = max(0, self.total_model_requests - self.exploration_ceiling)
        return max(0, self.config.proof_reserve - reserve_spent)

    @property
    def counterfactual_leases_started(self) -> int:
        return sum(role is RecoveryRole.COUNTERFACTUAL for role in self.branches_started_in_epoch)

    def route_is_available(self, fingerprint: str) -> bool:
        if not fingerprint:
            return True
        return self.low_value_route_attempts.get(fingerprint, 0) < self.config.low_value_route_limit

    def record_model_turn(  # noqa: PLR0913 - one turn boundary carries explicit evidence.
        self,
        snapshot: ProgressSnapshot,
        *,
        route_fingerprint: str = "",
        low_value_route: bool = False,
        observation_digest: str = "",
        next_objective_fingerprint: str = "",
        branch_handoff: bool = False,
    ) -> RecoveryDecision:
        """Account for one request and deterministically allocate the next lease."""
        self._assert_request_is_allowed()
        executed_role = self.role
        executed_branch_id = self.active_branch_id
        executed_lease_budget = self.lease_limit
        executed_lease_used = self.lease_used + 1
        self.total_model_requests += 1
        self.lease_used += 1

        material_progress = snapshot.material_delta(self.last_snapshot)
        self.last_snapshot = snapshot
        watchdog_triggered = False

        if snapshot.confirmed_proofs:
            self.status = RecoveryStatus.SOLVED
            reason = "proof_confirmed"
        elif material_progress:
            reason = self._grant_material_progress_lease(material_progress)
        else:
            if route_fingerprint and low_value_route:
                self.low_value_route_attempts[route_fingerprint] = (
                    self.low_value_route_attempts.get(route_fingerprint, 0) + 1
                )
            watchdog_triggered = self._record_observation(observation_digest)
            reason = self._advance_without_progress(
                watchdog_triggered=watchdog_triggered,
                next_objective_fingerprint=next_objective_fingerprint,
                branch_handoff=branch_handoff,
            )

        route_exhausted = bool(route_fingerprint) and not self.route_is_available(route_fingerprint)
        running = self.status is RecoveryStatus.RUNNING
        return RecoveryDecision(
            executed_role=executed_role,
            next_role=self.role if running else None,
            status=self.status,
            reason=reason,
            total_model_requests=self.total_model_requests,
            remaining_model_requests=(self.config.max_model_requests - self.total_model_requests),
            remaining_exploration_requests=self.remaining_exploration_requests,
            proof_reserve_remaining=self.proof_reserve_remaining,
            evidence_epoch=self.evidence_epoch,
            material_progress=material_progress,
            executed_branch_id=executed_branch_id,
            next_branch_id=self.active_branch_id if running else None,
            executed_lease_budget=executed_lease_budget,
            executed_lease_used=executed_lease_used,
            next_lease_budget=self.lease_limit if running else None,
            next_lease_used=self.lease_used if running else None,
            next_objective_fingerprint=(self.active_objective_fingerprint if running else None),
            route_exhausted=route_exhausted,
            observation_watchdog_triggered=watchdog_triggered,
            branch_handoff_triggered=branch_handoff,
        )

    def _assert_request_is_allowed(self) -> None:
        if self.status is not RecoveryStatus.RUNNING:
            raise RecoverySchedulerStoppedError(self.status)
        if self.total_model_requests >= self.config.max_model_requests:
            raise RecoveryBudgetExceededError
        if self.lease_used >= self.lease_limit:
            raise RecoveryLeaseExceededError(self.role)

    def _grant_material_progress_lease(
        self,
        material_progress: tuple[MaterialProgressKind, ...],
    ) -> str:
        self.evidence_epoch += 1
        self.branches_started_in_epoch.clear()
        self.low_value_route_attempts.clear()
        self.attempted_objective_fingerprints.clear()
        self.active_objective_fingerprint = None
        self._reset_observation_watchdog()
        if self.total_model_requests >= self.config.max_model_requests:
            self.status = RecoveryStatus.BUDGET_EXHAUSTED
            return "global_model_budget_exhausted"
        proof_closeable = any(kind in _PROOF_CLOSEABLE_PROGRESS for kind in material_progress)
        if proof_closeable:
            role = RecoveryRole.CLOSURE
            requested_budget = self.config.progress_lease
        else:
            role = RecoveryRole.COUNTERFACTUAL
            requested_budget = self.config.counterfactual_lease
        started = self._start_branch(
            role,
            requested_budget=requested_budget,
            use_proof_reserve=proof_closeable,
        )
        if not started:
            if proof_closeable:
                self.status = RecoveryStatus.BUDGET_EXHAUSTED
                return "global_model_budget_exhausted"
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            return "proof_reserve_preserved"
        if proof_closeable:
            return "material_progress_lease_granted"
        return "disproved_hypothesis_counterfactual_lease_granted"

    def _advance_without_progress(
        self,
        *,
        watchdog_triggered: bool,
        next_objective_fingerprint: str,
        branch_handoff: bool,
    ) -> str:
        if self.total_model_requests >= self.config.max_model_requests:
            self.status = RecoveryStatus.BUDGET_EXHAUSTED
            return "global_model_budget_exhausted"
        if (
            not self.branch_uses_proof_reserve
            and self.total_model_requests >= self.exploration_ceiling
        ):
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            return "proof_reserve_preserved"
        should_pivot_for_handoff = branch_handoff and self.role is not RecoveryRole.CORE
        if (
            not watchdog_triggered
            and not should_pivot_for_handoff
            and self.lease_used < self.lease_limit
        ):
            return f"continue_{self.role.value}"
        return self._pivot_after_lease(
            watchdog_triggered=watchdog_triggered,
            next_objective_fingerprint=next_objective_fingerprint,
        )

    def _pivot_after_lease(
        self,
        *,
        watchdog_triggered: bool,
        next_objective_fingerprint: str,
    ) -> str:
        if self.role is RecoveryRole.CORE:
            return self._pivot_from_core(watchdog_triggered=watchdog_triggered)
        if self.role is RecoveryRole.CLOSURE:
            return self._pivot_from_closure(
                watchdog_triggered=watchdog_triggered,
                next_objective_fingerprint=next_objective_fingerprint,
            )
        return self._pivot_from_counterfactual(
            watchdog_triggered=watchdog_triggered,
            next_objective_fingerprint=next_objective_fingerprint,
        )

    def _pivot_from_core(self, *, watchdog_triggered: bool) -> str:
        started = self._start_branch(
            RecoveryRole.CLOSURE,
            requested_budget=self.config.closure_lease,
            use_proof_reserve=False,
        )
        if not started:
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            return "proof_reserve_preserved"
        if watchdog_triggered:
            return "core_observation_watchdog_pivot"
        return "initial_core_lease_exhausted"

    def _pivot_from_closure(
        self,
        *,
        watchdog_triggered: bool,
        next_objective_fingerprint: str,
    ) -> str:
        objective = next_objective_fingerprint.strip()
        if objective and not self.objective_is_available(objective):
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            return "duplicate_counterfactual_objective_rejected"
        started = self._start_branch(
            RecoveryRole.COUNTERFACTUAL,
            requested_budget=self.config.counterfactual_lease,
            use_proof_reserve=False,
            objective_fingerprint=objective,
        )
        if not started:
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            return "proof_reserve_preserved"
        if watchdog_triggered:
            return "closure_observation_watchdog_pivot"
        return "closure_lease_exhausted"

    def _pivot_from_counterfactual(
        self,
        *,
        watchdog_triggered: bool,
        next_objective_fingerprint: str,
    ) -> str:
        objective = next_objective_fingerprint.strip()
        if not objective:
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            if watchdog_triggered:
                reason = "counterfactual_observation_watchdog_exhausted"
            else:
                reason = "unchanged_evidence_epoch_exhausted"
        elif not self.objective_is_available(objective):
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            reason = "duplicate_counterfactual_objective_rejected"
        elif self.counterfactual_leases_started >= (
            self.config.max_counterfactual_leases_per_epoch
        ):
            self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
            reason = "counterfactual_lease_limit_reached"
        else:
            started = self._start_branch(
                RecoveryRole.COUNTERFACTUAL,
                requested_budget=self.config.counterfactual_lease,
                use_proof_reserve=False,
                objective_fingerprint=objective,
            )
            if not started:
                self.status = RecoveryStatus.EXPLORATION_EXHAUSTED
                reason = "proof_reserve_preserved"
            elif watchdog_triggered:
                reason = "counterfactual_observation_watchdog_pivot"
            else:
                reason = "novel_counterfactual_lease_granted"
        return reason

    def objective_is_available(self, fingerprint: str) -> bool:
        return bool(fingerprint) and fingerprint not in self.attempted_objective_fingerprints

    def _start_branch(
        self,
        role: RecoveryRole,
        *,
        requested_budget: int,
        use_proof_reserve: bool,
        objective_fingerprint: str = "",
    ) -> bool:
        if role is RecoveryRole.CORE:
            field_name = "role"
            raise InvalidRecoveryConfigError(
                field_name,
                "cannot be core for a recovery branch",
            )
        if use_proof_reserve:
            available = self.config.max_model_requests - self.total_model_requests
        else:
            available = self.remaining_exploration_requests
        if available <= 0:
            return False

        self.role = role
        self.lease_limit = min(requested_budget, available)
        self.lease_used = 0
        self.branches_started_in_epoch.append(role)
        self.active_branch_id = f"recovery-{self.next_branch_sequence}-{role.value}"
        self.next_branch_sequence += 1
        self.branch_uses_proof_reserve = use_proof_reserve
        objective = objective_fingerprint.strip()
        self.active_objective_fingerprint = objective or None
        if objective:
            self.attempted_objective_fingerprints.add(objective)
        self._reset_observation_watchdog()
        return True

    def _record_observation(self, digest: str) -> bool:
        if not digest:
            return False
        if digest == self.last_observation_digest:
            self.repeated_observation_count += 1
        else:
            self.last_observation_digest = digest
            self.repeated_observation_count = 1
        return self.repeated_observation_count >= self.config.repeated_observation_limit

    def _reset_observation_watchdog(self) -> None:
        self.last_observation_digest = ""
        self.repeated_observation_count = 0

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "config": self.config.to_json(),
            "role": self.role.value,
            "status": self.status.value,
            "total_model_requests": self.total_model_requests,
            "lease_limit": self.lease_limit,
            "lease_used": self.lease_used,
            "evidence_epoch": self.evidence_epoch,
            "branches_started_in_epoch": [role.value for role in self.branches_started_in_epoch],
            "low_value_route_attempts": dict(self.low_value_route_attempts),
            "active_branch_id": self.active_branch_id,
            "next_branch_sequence": self.next_branch_sequence,
            "branch_uses_proof_reserve": self.branch_uses_proof_reserve,
            "last_observation_digest": self.last_observation_digest,
            "repeated_observation_count": self.repeated_observation_count,
            "attempted_objective_fingerprints": sorted(self.attempted_objective_fingerprints),
            "active_objective_fingerprint": self.active_objective_fingerprint,
            "last_snapshot": self.last_snapshot.to_json(),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RecoveryScheduler:
        if _required_int(payload, "version") != _STATE_VERSION:
            field_name = "version"
            raise InvalidRecoveryStateError(field_name, "is unsupported")
        config_payload = _required_mapping(payload, "config")
        snapshot_payload = _required_mapping(payload, "last_snapshot")
        return cls(
            config=RecoveryConfig.from_json(config_payload),
            role=RecoveryRole(_required_str(payload, "role")),
            status=RecoveryStatus(_required_str(payload, "status")),
            total_model_requests=_required_int(payload, "total_model_requests"),
            lease_limit=_required_int(payload, "lease_limit"),
            lease_used=_required_int(payload, "lease_used"),
            evidence_epoch=_required_int(payload, "evidence_epoch"),
            branches_started_in_epoch=[
                RecoveryRole(value) for value in _string_list(payload, "branches_started_in_epoch")
            ],
            low_value_route_attempts=_int_mapping(payload, "low_value_route_attempts"),
            active_branch_id=_optional_str(payload, "active_branch_id"),
            next_branch_sequence=_required_int(payload, "next_branch_sequence"),
            branch_uses_proof_reserve=_required_bool(
                payload,
                "branch_uses_proof_reserve",
            ),
            last_observation_digest=_required_str(payload, "last_observation_digest"),
            repeated_observation_count=_required_int(
                payload,
                "repeated_observation_count",
            ),
            attempted_objective_fingerprints=set(
                _string_list(payload, "attempted_objective_fingerprints")
            ),
            active_objective_fingerprint=_optional_str(
                payload,
                "active_objective_fingerprint",
            ),
            last_snapshot=ProgressSnapshot.from_json(snapshot_payload),
        )


def _required_mapping(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise InvalidRecoveryStateTypeError(key, "an object")
    if not all(isinstance(item_key, str) for item_key in value):
        raise InvalidRecoveryStateTypeError(key, "an object with string keys")
    return {str(item_key): item_value for item_key, item_value in value.items()}


def _required_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidRecoveryStateTypeError(key, "an integer")
    return value


def _required_bool(payload: Mapping[str, object], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise InvalidRecoveryStateTypeError(key, "a boolean")
    return value


def _required_str(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise InvalidRecoveryStateTypeError(key, "a string")
    return value


def _optional_str(payload: Mapping[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None or isinstance(value, str):
        return value
    raise InvalidRecoveryStateTypeError(key, "a string or null")


def _string_list(payload: Mapping[str, object], key: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise InvalidRecoveryStateTypeError(key, "a list of strings")
    return [item for item in value if isinstance(item, str)]


def _string_set(payload: Mapping[str, object], key: str) -> frozenset[str]:
    return frozenset(_string_list(payload, key))


def _int_mapping(payload: Mapping[str, object], key: str) -> dict[str, int]:
    value = _required_mapping(payload, key)
    output: dict[str, int] = {}
    for item_key, item_value in value.items():
        if isinstance(item_value, bool) or not isinstance(item_value, int):
            raise InvalidRecoveryStateTypeError(key, "an object with integer values")
        output[item_key] = item_value
    return output
