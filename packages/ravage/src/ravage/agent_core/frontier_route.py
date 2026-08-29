# Validation errors carry field-specific context at their call sites.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

if TYPE_CHECKING:
    from pathlib import Path

_STATE_VERSION = 1
DEFAULT_SEEDED_OBJECTIVE_LIMIT = 4
_MAX_WORKERS_PER_SEEDED_OBJECTIVE = 2
_TRUSTED_SOURCE_KINDS = frozenset(
    {
        "tool_run_command",
        "tool_run_python",
        "tool_run_probe",
        "tool_validate_poc",
    }
)


class BaseRouteTermination(StrEnum):
    SOLVED = "solved"
    REQUEST_BUDGET_EXHAUSTED = "request_budget_exhausted"
    EXPLORATION_EXHAUSTED = "exploration_exhausted"
    COST_BUDGET_EXHAUSTED = "cost_budget_exhausted"
    INTERRUPTED = "interrupted"
    ERROR = "error"


class FrontierRouteStatus(StrEnum):
    RUNNING = "running"
    SOLVED = "solved"
    FRONTIER_EXHAUSTED = "frontier_exhausted"
    REQUEST_BUDGET_EXHAUSTED = "request_budget_exhausted"
    COST_BUDGET_EXHAUSTED = "cost_budget_exhausted"


class FrontierWorkerRole(StrEnum):
    SCOUT = "scout"
    COUNTERFACTUAL = "counterfactual"
    PROOF_CLOSURE = "proof_closure"


class FrontierWorkerStatus(StrEnum):
    ACTIVE = "active"
    HANDED_OFF = "handed_off"
    EXHAUSTED = "exhausted"
    SOLVED = "solved"


class FrontierObjectiveBasis(StrEnum):
    BASE_FRONTIER = "base_frontier"
    NOVEL_COUNTERFACTUAL = "novel_counterfactual"
    MATERIAL_PROGRESS = "material_progress"


class InvalidFrontierRouteConfigError(ValueError):
    pass


class InvalidFrontierRouteStateError(ValueError):
    pass


class DuplicateFrontierObjectiveError(ValueError):
    pass


class OutOfScopeFrontierObjectiveError(ValueError):
    pass


class PendingFrontierRequestError(RuntimeError):
    pass


@dataclass(frozen=True)
class FrontierRouteConfig:
    """Code-enforced limits for one post-base autonomous route."""

    max_model_requests: int = 24
    scout_lease: int = 4
    counterfactual_lease: int = 8
    proof_lease: int = 12
    max_workers: int = 4
    repeated_observation_limit: int = 2
    repeated_low_value_route_limit: int = 2
    max_cost_usd: float | None = None

    def __post_init__(self) -> None:
        positive = {
            "max_model_requests": self.max_model_requests,
            "scout_lease": self.scout_lease,
            "counterfactual_lease": self.counterfactual_lease,
            "proof_lease": self.proof_lease,
            "max_workers": self.max_workers,
            "repeated_observation_limit": self.repeated_observation_limit,
            "repeated_low_value_route_limit": self.repeated_low_value_route_limit,
        }
        for name, value in positive.items():
            if value <= 0:
                raise InvalidFrontierRouteConfigError(f"{name} must be greater than zero")
        for name, value in (
            ("scout_lease", self.scout_lease),
            ("counterfactual_lease", self.counterfactual_lease),
            ("proof_lease", self.proof_lease),
        ):
            if value > self.max_model_requests:
                raise InvalidFrontierRouteConfigError(f"{name} cannot exceed max_model_requests")
        if self.max_cost_usd is not None and self.max_cost_usd <= 0:
            raise InvalidFrontierRouteConfigError(
                "max_cost_usd must be greater than zero when configured"
            )

    def to_json(self) -> dict[str, object]:
        return {
            "max_model_requests": self.max_model_requests,
            "scout_lease": self.scout_lease,
            "counterfactual_lease": self.counterfactual_lease,
            "proof_lease": self.proof_lease,
            "max_workers": self.max_workers,
            "repeated_observation_limit": self.repeated_observation_limit,
            "repeated_low_value_route_limit": self.repeated_low_value_route_limit,
            "max_cost_usd": self.max_cost_usd,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> FrontierRouteConfig:
        max_cost = payload.get("max_cost_usd")
        return cls(
            max_model_requests=_required_int(payload, "max_model_requests"),
            scout_lease=_required_int(payload, "scout_lease"),
            counterfactual_lease=_required_int(payload, "counterfactual_lease"),
            proof_lease=_required_int(payload, "proof_lease"),
            max_workers=_required_int(payload, "max_workers"),
            repeated_observation_limit=_required_int(
                payload,
                "repeated_observation_limit",
            ),
            repeated_low_value_route_limit=_required_int(
                payload,
                "repeated_low_value_route_limit",
            ),
            max_cost_usd=None if max_cost is None else _float(max_cost),
        )


def frontier_config_for_budget(
    max_model_requests: int,
    *,
    max_cost_usd: float | None = None,
) -> FrontierRouteConfig:
    if max_model_requests <= 0:
        raise InvalidFrontierRouteConfigError("max_model_requests must be greater than zero")
    return FrontierRouteConfig(
        max_model_requests=max_model_requests,
        scout_lease=min(4, max_model_requests),
        counterfactual_lease=min(8, max_model_requests),
        proof_lease=min(12, max_model_requests),
        max_workers=min(
            DEFAULT_SEEDED_OBJECTIVE_LIMIT * _MAX_WORKERS_PER_SEEDED_OBJECTIVE,
            max_model_requests,
        ),
        max_cost_usd=max_cost_usd,
    )


@dataclass(frozen=True)
class BaseRouteOutcome:
    target_url: str
    termination: BaseRouteTermination
    model_requests: int
    state_digest: str
    state_ref: str = ""
    proof_confirmed: bool = False
    cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if not self.target_url.strip():
            raise InvalidFrontierRouteStateError("base target_url is required")
        if self.model_requests < 0:
            raise InvalidFrontierRouteStateError("base model_requests cannot be negative")
        if self.cost_usd < 0:
            raise InvalidFrontierRouteStateError("base cost_usd cannot be negative")

    def to_json(self) -> dict[str, object]:
        return {
            "target_url": self.target_url,
            "termination": self.termination.value,
            "model_requests": self.model_requests,
            "state_digest": self.state_digest,
            "state_ref": self.state_ref,
            "proof_confirmed": self.proof_confirmed,
            "cost_usd": self.cost_usd,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> BaseRouteOutcome:
        return cls(
            target_url=str(payload.get("target_url") or ""),
            termination=BaseRouteTermination(str(payload.get("termination") or "")),
            model_requests=_required_int(payload, "model_requests"),
            state_digest=str(payload.get("state_digest") or ""),
            state_ref=str(payload.get("state_ref") or ""),
            proof_confirmed=payload.get("proof_confirmed") is True,
            cost_usd=_float(payload.get("cost_usd")),
        )


@dataclass(frozen=True)
class FrontierRouteEligibility:
    enter: bool
    resume: bool
    reason: str


def route_eligibility(
    base: BaseRouteOutcome,
    *,
    route_state_exists: bool = False,
) -> FrontierRouteEligibility:
    if base.proof_confirmed:
        return FrontierRouteEligibility(
            enter=False,
            resume=False,
            reason="base_proof_confirmed",
        )
    if base.termination in {
        BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        BaseRouteTermination.EXPLORATION_EXHAUSTED,
    }:
        if route_state_exists:
            return FrontierRouteEligibility(
                enter=False,
                resume=True,
                reason="existing_route_state",
            )
        return FrontierRouteEligibility(
            enter=True,
            resume=False,
            reason="terminal_base_unsolved",
        )
    return FrontierRouteEligibility(
        enter=False,
        resume=False,
        reason=f"base_stop_not_eligible:{base.termination.value}",
    )


@dataclass(frozen=True)
class FrontierObjective:
    fingerprint: str
    basis: FrontierObjectiveBasis
    family: str
    probe: str
    endpoint: str
    inputs: tuple[str, ...]
    payload_class: str
    expected_signal: str
    evidence_refs: tuple[str, ...]

    @classmethod
    def create(  # noqa: PLR0913 - structured fields define objective identity.
        cls,
        *,
        family: str,
        probe: str,
        endpoint: str = "",
        inputs: tuple[str, ...] = (),
        payload_class: str = "",
        expected_signal: str,
        evidence_refs: tuple[str, ...] = (),
        basis: FrontierObjectiveBasis = FrontierObjectiveBasis.BASE_FRONTIER,
    ) -> FrontierObjective:
        normalized = {
            "basis": basis.value,
            "family": family.strip().lower() or "unknown",
            "probe": probe.strip(),
            "endpoint": endpoint.strip(),
            "inputs": _clean_strings(inputs),
            "payload_class": payload_class.strip().lower() or "unknown",
            "expected_signal": expected_signal.strip(),
            "evidence_refs": _clean_strings(evidence_refs),
        }
        if not normalized["probe"] and not normalized["endpoint"]:
            raise InvalidFrontierRouteStateError("frontier objective requires a probe or endpoint")
        if not normalized["expected_signal"]:
            raise InvalidFrontierRouteStateError("frontier objective requires an expected_signal")
        fingerprint = _stable_digest(normalized)
        return cls(
            fingerprint=fingerprint,
            basis=basis,
            family=str(normalized["family"]),
            probe=str(normalized["probe"]),
            endpoint=str(normalized["endpoint"]),
            inputs=tuple(normalized["inputs"]),
            payload_class=str(normalized["payload_class"]),
            expected_signal=str(normalized["expected_signal"]),
            evidence_refs=tuple(normalized["evidence_refs"]),
        )

    def proof_closure(self, *, material_refs: tuple[str, ...]) -> FrontierObjective:
        return FrontierObjective.create(
            family=self.family,
            probe=self.probe,
            endpoint=self.endpoint,
            inputs=self.inputs,
            payload_class=self.payload_class,
            expected_signal=(
                "produce the shortest replayable target-observed objective proof or "
                "a concrete access transition that directly enables it for the "
                f"confirmed {self.family} route; reconfirming the same vulnerability "
                "signal is not closure"
            ),
            evidence_refs=tuple(dict.fromkeys((*self.evidence_refs, *material_refs))),
            basis=FrontierObjectiveBasis.MATERIAL_PROGRESS,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "basis": self.basis.value,
            "endpoint": self.endpoint,
            "evidence_refs": list(self.evidence_refs),
            "expected_signal": self.expected_signal,
            "family": self.family,
            "fingerprint": self.fingerprint,
            "inputs": list(self.inputs),
            "payload_class": self.payload_class,
            "probe": self.probe,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> FrontierObjective:
        objective = cls.create(
            family=str(payload.get("family") or "unknown"),
            probe=str(payload.get("probe") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            inputs=_string_tuple(payload.get("inputs")),
            payload_class=str(payload.get("payload_class") or "unknown"),
            expected_signal=str(payload.get("expected_signal") or ""),
            evidence_refs=_string_tuple(payload.get("evidence_refs")),
            basis=FrontierObjectiveBasis(str(payload.get("basis") or "")),
        )
        stored = str(payload.get("fingerprint") or "")
        if stored != objective.fingerprint:
            raise InvalidFrontierRouteStateError(
                "frontier objective fingerprint does not match its fields"
            )
        return objective


@dataclass(frozen=True)
class FrontierObservation:
    source_kind: str
    observation_digest: str
    route_fingerprint: str
    material_progress: tuple[str, ...] = ()
    proofs: tuple[str, ...] = ()
    next_objective: FrontierObjective | None = None
    cost_usd: float = 0.0
    low_value_route: bool = False

    def __post_init__(self) -> None:
        if self.cost_usd < 0:
            raise InvalidFrontierRouteStateError("observation cost_usd cannot be negative")

    @property
    def trusted(self) -> bool:
        return self.source_kind in _TRUSTED_SOURCE_KINDS


@dataclass
class FrontierWorker:
    worker_id: str
    role: FrontierWorkerRole
    objective: FrontierObjective
    lease_limit: int
    status: FrontierWorkerStatus = FrontierWorkerStatus.ACTIVE
    requests_started: int = 0
    requests_completed: int = 0
    handoff_from: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "worker_id": self.worker_id,
            "role": self.role.value,
            "objective": self.objective.to_json(),
            "lease_limit": self.lease_limit,
            "status": self.status.value,
            "requests_started": self.requests_started,
            "requests_completed": self.requests_completed,
            "handoff_from": self.handoff_from,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> FrontierWorker:
        objective = payload.get("objective")
        if not isinstance(objective, dict):
            raise InvalidFrontierRouteStateError("worker objective must be an object")
        return cls(
            worker_id=str(payload.get("worker_id") or ""),
            role=FrontierWorkerRole(str(payload.get("role") or "")),
            objective=FrontierObjective.from_json(objective),
            lease_limit=_required_int(payload, "lease_limit"),
            status=FrontierWorkerStatus(str(payload.get("status") or "")),
            requests_started=_required_int(payload, "requests_started"),
            requests_completed=_required_int(payload, "requests_completed"),
            handoff_from=_optional_string(payload.get("handoff_from")),
        )


@dataclass(frozen=True)
class FrontierHandoff:
    worker_id: str
    summary_digest: str
    next_objective_fingerprint: str
    model_request_number: int

    def to_json(self) -> dict[str, object]:
        return {
            "worker_id": self.worker_id,
            "summary_digest": self.summary_digest,
            "next_objective_fingerprint": self.next_objective_fingerprint,
            "model_request_number": self.model_request_number,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> FrontierHandoff:
        return cls(
            worker_id=str(payload.get("worker_id") or ""),
            summary_digest=str(payload.get("summary_digest") or ""),
            next_objective_fingerprint=str(payload.get("next_objective_fingerprint") or ""),
            model_request_number=_required_int(payload, "model_request_number"),
        )


@dataclass(frozen=True)
class FrontierDecision:
    status: FrontierRouteStatus
    reason: str
    model_requests_started: int
    remaining_model_requests: int
    active_worker_id: str | None


@dataclass
class FrontierRoute:
    """
    Persistent, bounded coordinator for the autonomous escalation route.

    The coordinator is deterministic. Models work inside short specialist leases;
    model-authored summaries never count as progress or proof.
    """

    base: BaseRouteOutcome
    scope: tuple[str, ...]
    config: FrontierRouteConfig = field(default_factory=FrontierRouteConfig)
    status: FrontierRouteStatus = FrontierRouteStatus.RUNNING
    workers: list[FrontierWorker] = field(default_factory=list)
    active_worker_id: str | None = None
    model_requests_started: int = 0
    model_requests_completed: int = 0
    interrupted_model_requests: int = 0
    pending_worker_id: str | None = None
    spent_cost_usd: float = 0.0
    attempted_objective_fingerprints: set[str] = field(default_factory=set)
    observation_counts: dict[str, int] = field(default_factory=dict)
    low_value_route_counts: dict[str, int] = field(default_factory=dict)
    material_evidence_digests: set[str] = field(default_factory=set)
    proof_digests: set[str] = field(default_factory=set)
    handoffs: list[FrontierHandoff] = field(default_factory=list)
    last_reason: str = "route_started"

    @classmethod
    def start(
        cls,
        *,
        base: BaseRouteOutcome,
        initial_objective: FrontierObjective,
        scope: tuple[str, ...],
        config: FrontierRouteConfig | None = None,
    ) -> FrontierRoute:
        eligibility = route_eligibility(base)
        if not eligibility.enter:
            raise InvalidFrontierRouteStateError(
                f"base route is not eligible: {eligibility.reason}"
            )
        normalized_scope = _normalized_scope(scope, target_url=base.target_url)
        route = cls(
            base=base,
            scope=normalized_scope,
            config=config or FrontierRouteConfig(),
        )
        route._validate_objective_scope(initial_objective)
        route._spawn_worker(
            role=FrontierWorkerRole.SCOUT,
            objective=initial_objective,
            requested_lease=route.config.scout_lease,
            handoff_from=None,
        )
        return route

    @property
    def active_worker(self) -> FrontierWorker | None:
        if self.active_worker_id is None:
            return None
        return next(
            (worker for worker in self.workers if worker.worker_id == self.active_worker_id),
            None,
        )

    @property
    def remaining_model_requests(self) -> int:
        return max(self.config.max_model_requests - self.model_requests_started, 0)

    @property
    def total_model_requests_including_base(self) -> int:
        return self.base.model_requests + self.model_requests_started

    def begin_model_request(self) -> FrontierWorker:
        if self.status is not FrontierRouteStatus.RUNNING:
            if self.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED:
                raise RuntimeError("cannot begin model request: global request budget exhausted")
            raise RuntimeError(f"cannot begin model request after route status {self.status.value}")
        if self.pending_worker_id is not None:
            raise PendingFrontierRequestError(
                "cannot begin a model request while another request is pending"
            )
        if self.model_requests_started >= self.config.max_model_requests:
            self._stop(
                FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED,
                "global_request_budget_exhausted",
            )
            raise RuntimeError("cannot begin model request: global request budget exhausted")
        worker = self.active_worker
        if worker is None or worker.status is not FrontierWorkerStatus.ACTIVE:
            raise InvalidFrontierRouteStateError("running route requires one active worker")
        if worker.requests_started >= worker.lease_limit:
            raise RuntimeError("cannot begin model request: active worker lease exhausted")
        worker.requests_started += 1
        self.model_requests_started += 1
        self.pending_worker_id = worker.worker_id
        return worker

    def account_interrupted_request(self) -> FrontierDecision:
        worker = self._complete_pending_request(cost_usd=0.0)
        self.interrupted_model_requests += 1
        if self._stop_for_global_limit():
            return self._decision()
        if worker.requests_started >= worker.lease_limit:
            worker.status = FrontierWorkerStatus.EXHAUSTED
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "interrupted_request_exhausted_lease",
            )
            return self._decision()
        self.last_reason = "interrupted_request_charged"
        return self._decision()

    def record_observation(  # noqa: C901, PLR0911 - explicit state-machine exits.
        self,
        observation: FrontierObservation,
    ) -> FrontierDecision:
        worker = self._complete_pending_request(cost_usd=observation.cost_usd)
        if observation.observation_digest:
            self.observation_counts[observation.observation_digest] = (
                self.observation_counts.get(observation.observation_digest, 0) + 1
            )
        if observation.low_value_route and observation.route_fingerprint:
            self.low_value_route_counts[observation.route_fingerprint] = (
                self.low_value_route_counts.get(observation.route_fingerprint, 0) + 1
            )

        if observation.trusted and observation.proofs:
            self.proof_digests.update(_secret_digest(item) for item in observation.proofs)
            worker.status = FrontierWorkerStatus.SOLVED
            self._stop(FrontierRouteStatus.SOLVED, "trusted_proof_confirmed")
            return self._decision()

        if self._stop_for_global_limit():
            return self._decision()

        trusted_progress = (
            _clean_strings(observation.material_progress) if observation.trusted else ()
        )
        if trusted_progress:
            refs = tuple(f"material:{_secret_digest(item)}" for item in trusted_progress)
            new_refs = tuple(ref for ref in refs if ref not in self.material_evidence_digests)
            self.material_evidence_digests.update(new_refs)
            if new_refs and worker.role is not FrontierWorkerRole.PROOF_CLOSURE:
                objective = worker.objective.proof_closure(material_refs=new_refs)
                if len(self.workers) >= self.config.max_workers:
                    return self._renew_worker_for_proof_closure(
                        worker=worker,
                        objective=objective,
                    )
                worker.status = FrontierWorkerStatus.HANDED_OFF
                return self._spawn_transition(
                    role=FrontierWorkerRole.PROOF_CLOSURE,
                    objective=objective,
                    requested_lease=self.config.proof_lease,
                    handoff_from=worker.worker_id,
                    success_reason="trusted_progress_proof_lease_granted",
                )

        watchdog = self._watchdog_reason(observation)
        if watchdog:
            worker.status = FrontierWorkerStatus.EXHAUSTED
            if observation.next_objective is not None:
                return self._spawn_counterfactual_transition(
                    observation.next_objective,
                    handoff_from=worker.worker_id,
                    success_reason=f"{watchdog}_counterfactual_lease_granted",
                )
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                f"{watchdog}_without_novel_objective",
            )
            return self._decision()

        if worker.requests_started >= worker.lease_limit:
            worker.status = FrontierWorkerStatus.EXHAUSTED
            if observation.next_objective is not None:
                return self._spawn_counterfactual_transition(
                    observation.next_objective,
                    handoff_from=worker.worker_id,
                    success_reason="novel_counterfactual_lease_granted",
                )
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "lease_exhausted_without_novel_objective",
            )
            return self._decision()

        self.last_reason = "worker_continues"
        return self._decision()

    def record_handoff(
        self,
        *,
        summary: str,
        next_objective: FrontierObjective | None,
        cost_usd: float = 0.0,
    ) -> FrontierDecision:
        worker = self._complete_pending_request(cost_usd=cost_usd)
        worker.status = FrontierWorkerStatus.HANDED_OFF
        self.handoffs.append(
            FrontierHandoff(
                worker_id=worker.worker_id,
                summary_digest=_secret_digest(summary),
                next_objective_fingerprint=(
                    next_objective.fingerprint if next_objective is not None else ""
                ),
                model_request_number=self.model_requests_started,
            )
        )
        if self._stop_for_global_limit():
            return self._decision()
        if next_objective is None:
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "explicit_handoff_without_novel_objective",
            )
            return self._decision()
        return self._spawn_counterfactual_transition(
            next_objective,
            handoff_from=worker.worker_id,
            success_reason="explicit_handoff_counterfactual_lease_granted",
        )

    def spawn_counterfactual(self, objective: FrontierObjective) -> FrontierWorker:
        self._validate_spawn(objective)
        previous = self.active_worker
        if previous is not None and previous.status is FrontierWorkerStatus.ACTIVE:
            previous.status = FrontierWorkerStatus.HANDED_OFF
        return self._spawn_worker(
            role=FrontierWorkerRole.COUNTERFACTUAL,
            objective=objective,
            requested_lease=self.config.counterfactual_lease,
            handoff_from=previous.worker_id if previous is not None else None,
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "base": self.base.to_json(),
            "scope": list(self.scope),
            "config": self.config.to_json(),
            "status": self.status.value,
            "workers": [worker.to_json() for worker in self.workers],
            "active_worker_id": self.active_worker_id,
            "model_requests_started": self.model_requests_started,
            "model_requests_completed": self.model_requests_completed,
            "interrupted_model_requests": self.interrupted_model_requests,
            "pending_worker_id": self.pending_worker_id,
            "spent_cost_usd": self.spent_cost_usd,
            "attempted_objective_fingerprints": sorted(self.attempted_objective_fingerprints),
            "observation_counts": dict(sorted(self.observation_counts.items())),
            "low_value_route_counts": dict(sorted(self.low_value_route_counts.items())),
            "material_evidence_digests": sorted(self.material_evidence_digests),
            "proof_digests": sorted(self.proof_digests),
            "handoffs": [handoff.to_json() for handoff in self.handoffs],
            "last_reason": self.last_reason,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> FrontierRoute:
        if _required_int(payload, "version") != _STATE_VERSION:
            raise InvalidFrontierRouteStateError("unsupported frontier route state version")
        base_payload = payload.get("base")
        config_payload = payload.get("config")
        if not isinstance(base_payload, dict) or not isinstance(config_payload, dict):
            raise InvalidFrontierRouteStateError("base and config must be objects")
        route = cls(
            base=BaseRouteOutcome.from_json(base_payload),
            scope=_string_tuple(payload.get("scope")),
            config=FrontierRouteConfig.from_json(config_payload),
            status=FrontierRouteStatus(str(payload.get("status") or "")),
            workers=[
                FrontierWorker.from_json(item) for item in _mapping_list(payload.get("workers"))
            ],
            active_worker_id=_optional_string(payload.get("active_worker_id")),
            model_requests_started=_required_int(payload, "model_requests_started"),
            model_requests_completed=_required_int(payload, "model_requests_completed"),
            interrupted_model_requests=_required_int(
                payload,
                "interrupted_model_requests",
            ),
            pending_worker_id=_optional_string(payload.get("pending_worker_id")),
            spent_cost_usd=_float(payload.get("spent_cost_usd")),
            attempted_objective_fingerprints=set(
                _string_tuple(payload.get("attempted_objective_fingerprints"))
            ),
            observation_counts=_string_int_mapping(payload.get("observation_counts")),
            low_value_route_counts=_string_int_mapping(payload.get("low_value_route_counts")),
            material_evidence_digests=set(_string_tuple(payload.get("material_evidence_digests"))),
            proof_digests=set(_string_tuple(payload.get("proof_digests"))),
            handoffs=[
                FrontierHandoff.from_json(item) for item in _mapping_list(payload.get("handoffs"))
            ],
            last_reason=str(payload.get("last_reason") or ""),
        )
        route._validate_loaded_state()
        return route

    @classmethod
    def load(cls, path: Path) -> FrontierRoute:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise InvalidFrontierRouteStateError("frontier route state must be an object")
        return cls.from_json(payload)

    @classmethod
    def load_or_start(
        cls,
        path: Path,
        *,
        base: BaseRouteOutcome,
        initial_objective: FrontierObjective,
        scope: tuple[str, ...],
        config: FrontierRouteConfig | None = None,
    ) -> FrontierRoute:
        expected_config = config or FrontierRouteConfig()
        expected_scope = _normalized_scope(scope, target_url=base.target_url)
        if path.exists():
            route = cls.load(path)
            if route.base != base:
                raise InvalidFrontierRouteStateError(
                    "existing frontier route belongs to a different base outcome"
                )
            if route.config != expected_config:
                raise InvalidFrontierRouteStateError(
                    "existing frontier route config does not match"
                )
            if route.scope != expected_scope:
                raise InvalidFrontierRouteStateError("existing frontier route scope does not match")
            return route
        route = cls.start(
            base=base,
            initial_objective=initial_objective,
            scope=expected_scope,
            config=expected_config,
        )
        route.save(path)
        return route

    def _complete_pending_request(self, *, cost_usd: float) -> FrontierWorker:
        if self.pending_worker_id is None:
            raise PendingFrontierRequestError(
                "model request must be started before recording its result"
            )
        worker = self.active_worker
        if worker is None or worker.worker_id != self.pending_worker_id:
            raise InvalidFrontierRouteStateError(
                "pending request does not belong to the active worker"
            )
        if cost_usd < 0:
            raise InvalidFrontierRouteStateError("request cost_usd cannot be negative")
        worker.requests_completed += 1
        self.model_requests_completed += 1
        self.spent_cost_usd += cost_usd
        self.pending_worker_id = None
        return worker

    def _watchdog_reason(self, observation: FrontierObservation) -> str:
        if (
            observation.observation_digest
            and self.observation_counts.get(observation.observation_digest, 0)
            >= self.config.repeated_observation_limit
        ):
            return "observation_watchdog"
        if (
            observation.low_value_route
            and observation.route_fingerprint
            and self.low_value_route_counts.get(observation.route_fingerprint, 0)
            >= self.config.repeated_low_value_route_limit
        ):
            return "low_value_route_watchdog"
        return ""

    def _spawn_counterfactual_transition(
        self,
        objective: FrontierObjective,
        *,
        handoff_from: str,
        success_reason: str,
    ) -> FrontierDecision:
        try:
            self._validate_objective_scope(objective)
        except OutOfScopeFrontierObjectiveError:
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "out_of_scope_objective_rejected",
            )
            return self._decision()
        if objective.fingerprint in self.attempted_objective_fingerprints:
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "duplicate_objective_rejected",
            )
            return self._decision()
        return self._spawn_transition(
            role=FrontierWorkerRole.COUNTERFACTUAL,
            objective=objective,
            requested_lease=self.config.counterfactual_lease,
            handoff_from=handoff_from,
            success_reason=success_reason,
        )

    def _spawn_transition(
        self,
        *,
        role: FrontierWorkerRole,
        objective: FrontierObjective,
        requested_lease: int,
        handoff_from: str,
        success_reason: str,
    ) -> FrontierDecision:
        if len(self.workers) >= self.config.max_workers:
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "worker_limit_reached",
            )
            return self._decision()
        if self.remaining_model_requests <= 0:
            self._stop(
                FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED,
                "global_request_budget_exhausted",
            )
            return self._decision()
        self._validate_objective_scope(objective)
        if objective.fingerprint in self.attempted_objective_fingerprints:
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "duplicate_objective_rejected",
            )
            return self._decision()
        self._spawn_worker(
            role=role,
            objective=objective,
            requested_lease=requested_lease,
            handoff_from=handoff_from,
        )
        self.last_reason = success_reason
        return self._decision()

    def _renew_worker_for_proof_closure(
        self,
        *,
        worker: FrontierWorker,
        objective: FrontierObjective,
    ) -> FrontierDecision:
        """Keep trusted progress alive when a new worker slot is unavailable."""
        self._validate_objective_scope(objective)
        previous_fingerprint = worker.objective.fingerprint
        if (
            objective.fingerprint in self.attempted_objective_fingerprints
            and objective.fingerprint != previous_fingerprint
        ):
            worker.status = FrontierWorkerStatus.EXHAUSTED
            self._stop(
                FrontierRouteStatus.FRONTIER_EXHAUSTED,
                "duplicate_objective_rejected",
            )
            return self._decision()
        additional_lease = min(
            self.config.proof_lease,
            self.remaining_model_requests,
        )
        worker.role = FrontierWorkerRole.PROOF_CLOSURE
        worker.objective = objective
        worker.lease_limit = min(
            self.config.max_model_requests,
            worker.requests_started + additional_lease,
        )
        worker.status = FrontierWorkerStatus.ACTIVE
        self.active_worker_id = worker.worker_id
        self.attempted_objective_fingerprints.discard(previous_fingerprint)
        self.attempted_objective_fingerprints.add(objective.fingerprint)
        self.last_reason = "trusted_progress_proof_lease_renewed_at_worker_cap"
        return self._decision()

    def _validate_spawn(self, objective: FrontierObjective) -> None:
        if self.status is not FrontierRouteStatus.RUNNING:
            raise RuntimeError(f"cannot spawn worker after route status {self.status.value}")
        self._validate_objective_scope(objective)
        if objective.fingerprint in self.attempted_objective_fingerprints:
            raise DuplicateFrontierObjectiveError("frontier objective was already attempted")
        if len(self.workers) >= self.config.max_workers:
            raise RuntimeError("frontier worker limit reached")

    def _spawn_worker(
        self,
        *,
        role: FrontierWorkerRole,
        objective: FrontierObjective,
        requested_lease: int,
        handoff_from: str | None,
    ) -> FrontierWorker:
        remaining = self.remaining_model_requests
        if remaining <= 0:
            raise RuntimeError("cannot spawn worker: global request budget exhausted")
        worker = FrontierWorker(
            worker_id=f"worker-{len(self.workers) + 1:03d}",
            role=role,
            objective=objective,
            lease_limit=min(requested_lease, remaining),
            handoff_from=handoff_from,
        )
        self.workers.append(worker)
        self.active_worker_id = worker.worker_id
        self.attempted_objective_fingerprints.add(objective.fingerprint)
        return worker

    def _validate_objective_scope(self, objective: FrontierObjective) -> None:
        if not _endpoint_is_in_scope(
            objective.endpoint,
            target_url=self.base.target_url,
            scope=self.scope,
        ):
            raise OutOfScopeFrontierObjectiveError(
                f"frontier objective endpoint is out of scope: {objective.endpoint}"
            )

    def _stop_for_global_limit(self) -> bool:
        if self.config.max_cost_usd is not None and self.spent_cost_usd >= self.config.max_cost_usd:
            self._stop(
                FrontierRouteStatus.COST_BUDGET_EXHAUSTED,
                "route_cost_budget_exhausted",
            )
            return True
        if self.model_requests_started >= self.config.max_model_requests:
            self._stop(
                FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED,
                "global_request_budget_exhausted",
            )
            return True
        return False

    def _stop(self, status: FrontierRouteStatus, reason: str) -> None:
        self.status = status
        self.last_reason = reason
        self.active_worker_id = None

    def _decision(self) -> FrontierDecision:
        return FrontierDecision(
            status=self.status,
            reason=self.last_reason,
            model_requests_started=self.model_requests_started,
            remaining_model_requests=self.remaining_model_requests,
            active_worker_id=self.active_worker_id,
        )

    def _validate_loaded_state(self) -> None:
        if not self.scope:
            raise InvalidFrontierRouteStateError("frontier route scope cannot be empty")
        if self.scope != _normalized_scope(self.scope, target_url=self.base.target_url):
            raise InvalidFrontierRouteStateError(
                "frontier route scope is not normalized for its base target"
            )
        self._validate_loaded_workers()
        self._validate_loaded_accounting()
        self._validate_loaded_lifecycle()

    def _validate_loaded_workers(self) -> None:
        if len(self.workers) > self.config.max_workers:
            raise InvalidFrontierRouteStateError(
                "frontier route worker count exceeds the configured limit"
            )
        for worker in self.workers:
            if not worker.worker_id:
                raise InvalidFrontierRouteStateError("frontier worker id cannot be empty")
            if worker.lease_limit <= 0:
                raise InvalidFrontierRouteStateError("frontier worker lease must be positive")
            if not 0 <= worker.requests_completed <= worker.requests_started:
                raise InvalidFrontierRouteStateError(
                    "frontier worker request counters are inconsistent"
                )
            if worker.requests_started > worker.lease_limit:
                raise InvalidFrontierRouteStateError("frontier worker requests exceed its lease")
            self._validate_objective_scope(worker.objective)
        worker_ids = [worker.worker_id for worker in self.workers]
        if len(worker_ids) != len(set(worker_ids)):
            raise InvalidFrontierRouteStateError("frontier worker ids must be unique")
        attempted = {worker.objective.fingerprint for worker in self.workers}
        if attempted != self.attempted_objective_fingerprints:
            raise InvalidFrontierRouteStateError(
                "attempted objective ledger does not match workers"
            )

    def _validate_loaded_accounting(self) -> None:
        counters = (
            self.model_requests_started,
            self.model_requests_completed,
            self.interrupted_model_requests,
        )
        if any(value < 0 for value in counters) or self.spent_cost_usd < 0:
            raise InvalidFrontierRouteStateError(
                "frontier route accounting fields cannot be negative"
            )
        if self.model_requests_started > self.config.max_model_requests:
            raise InvalidFrontierRouteStateError(
                "started model requests exceed the configured global limit"
            )
        if self.model_requests_started < self.model_requests_completed:
            raise InvalidFrontierRouteStateError(
                "completed model requests cannot exceed started requests"
            )
        if self.interrupted_model_requests > self.model_requests_completed:
            raise InvalidFrontierRouteStateError(
                "interrupted model requests cannot exceed completed requests"
            )
        if sum(worker.requests_started for worker in self.workers) != (self.model_requests_started):
            raise InvalidFrontierRouteStateError(
                "global started-request count does not match worker accounting"
            )
        if sum(worker.requests_completed for worker in self.workers) != (
            self.model_requests_completed
        ):
            raise InvalidFrontierRouteStateError(
                "global completed-request count does not match worker accounting"
            )

    def _validate_loaded_lifecycle(self) -> None:
        pending = self.model_requests_started - self.model_requests_completed
        if pending not in {0, 1}:
            raise InvalidFrontierRouteStateError(
                "frontier route can have at most one pending model request"
            )
        if bool(pending) != bool(self.pending_worker_id):
            raise InvalidFrontierRouteStateError(
                "pending request accounting does not match pending_worker_id"
            )
        worker_ids = [worker.worker_id for worker in self.workers]
        if self.pending_worker_id is not None and self.pending_worker_id not in worker_ids:
            raise InvalidFrontierRouteStateError(
                "pending request belongs to an unknown frontier worker"
            )
        if self.status is FrontierRouteStatus.RUNNING:
            active = self.active_worker
            if active is None or active.status is not FrontierWorkerStatus.ACTIVE:
                raise InvalidFrontierRouteStateError(
                    "running frontier route requires an active worker"
                )
        elif self.active_worker_id is not None:
            raise InvalidFrontierRouteStateError(
                "terminal frontier route cannot retain an active worker"
            )
        if self.status is FrontierRouteStatus.SOLVED and not self.proof_digests:
            raise InvalidFrontierRouteStateError(
                "solved frontier route requires trusted proof provenance"
            )


def _normalized_scope(scope: tuple[str, ...], *, target_url: str) -> tuple[str, ...]:
    values = tuple(dict.fromkeys((target_url, *_clean_strings(scope))))
    if not values:
        raise InvalidFrontierRouteStateError("frontier route scope cannot be empty")
    return values


def _endpoint_is_in_scope(
    endpoint: str,
    *,
    target_url: str,
    scope: tuple[str, ...],
) -> bool:
    if not endpoint.strip():
        return True
    candidate = urlsplit(urljoin(target_url.rstrip("/") + "/", endpoint))
    if not candidate.scheme or not candidate.netloc:
        return False
    for raw_scope in scope:
        allowed = urlsplit(raw_scope)
        if (candidate.scheme, candidate.hostname, candidate.port) != (
            allowed.scheme,
            allowed.hostname,
            allowed.port,
        ):
            continue
        allowed_path = (allowed.path or "/").rstrip("/") or "/"
        candidate_path = candidate.path or "/"
        if allowed_path in {"/", candidate_path}:
            return True
        if candidate_path.startswith(allowed_path + "/"):
            return True
    return False


def _stable_digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _secret_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _clean_strings(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ()
    cleaned: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return tuple(cleaned)


def _string_tuple(value: object) -> tuple[str, ...]:
    return _clean_strings(value)


def _mapping_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _string_int_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(key): _int(item) for key, item in value.items()}


def _required_int(payload: dict[str, object], name: str) -> int:
    if name not in payload:
        raise InvalidFrontierRouteStateError(f"missing frontier route field: {name}")
    return _int(payload[name])


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError) as exc:
        raise InvalidFrontierRouteStateError("frontier route integer field is invalid") from exc


def _float(value: object) -> float:
    try:
        return float(str(value or 0.0))
    except (TypeError, ValueError) as exc:
        raise InvalidFrontierRouteStateError("frontier route numeric field is invalid") from exc


def _optional_string(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


__all__ = [
    "BaseRouteOutcome",
    "BaseRouteTermination",
    "DuplicateFrontierObjectiveError",
    "FrontierDecision",
    "FrontierObjective",
    "FrontierObjectiveBasis",
    "FrontierObservation",
    "FrontierRoute",
    "FrontierRouteConfig",
    "FrontierRouteEligibility",
    "FrontierRouteStatus",
    "FrontierWorker",
    "FrontierWorkerRole",
    "OutOfScopeFrontierObjectiveError",
    "frontier_config_for_budget",
    "route_eligibility",
]
