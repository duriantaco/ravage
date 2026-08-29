# Validation errors carry invariant-specific context at their call sites.
# ruff: noqa: EM101, EM102, TRY003


from __future__ import annotations

import hashlib
import json
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_STATE_VERSION = 4
_SUPPORTED_STATE_VERSIONS = frozenset({2, 3, _STATE_VERSION})
_TYPED_STATE_VERSION = 3

MIN_RACE_LANES = 2
MAX_RACE_LANES = 3


class GraphStateError(ValueError):
    """Raised when persisted graph state violates a code-enforced invariant."""


class GraphStatus(StrEnum):
    RUNNING = "running"
    SOLVED = "solved"
    EXHAUSTED = "exhausted"
    EXPLORATION_EXHAUSTED = "exploration_exhausted"
    REQUEST_BUDGET_EXHAUSTED = "request_budget_exhausted"
    TOOL_BUDGET_EXHAUSTED = "tool_budget_exhausted"
    COST_BUDGET_EXHAUSTED = "cost_budget_exhausted"
    WALL_TIME_EXHAUSTED = "wall_time_exhausted"
    STOPPED = "stopped"
    FAILED = "failed"


class GraphNodeStatus(StrEnum):
    READY = "ready"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    STOPPED = "stopped"
    CRASHED = "crashed"
    FAILED = "failed"


class GraphMessageKind(StrEnum):
    INFORMATION = "information"
    QUERY = "query"
    INSTRUCTION = "instruction"
    EVIDENCE = "evidence"
    COMPLETION = "completion"
    CRASH = "crash"


class GraphAgentRole(StrEnum):
    """Trusted control-plane role for one graph worker."""

    COORDINATOR = "coordinator"
    DISCOVERY = "discovery"
    CRITIC = "critic"
    EXPLOITATION = "exploitation"
    VALIDATOR = "validator"
    SPECIALIST = "specialist"


class RaceClaimStatus(StrEnum):
    """Persisted outcome of an evidence-gated race claim."""

    WON = "won"
    ALREADY_WON = "already_won"
    LOST = "lost"


ACTIVE_NODE_STATUSES = frozenset(
    {
        GraphNodeStatus.READY,
        GraphNodeStatus.RUNNING,
        GraphNodeStatus.WAITING,
    }
)
TERMINAL_NODE_STATUSES = frozenset(set(GraphNodeStatus) - ACTIVE_NODE_STATUSES)
TERMINAL_GRAPH_STATUSES = frozenset(set(GraphStatus) - {GraphStatus.RUNNING})


@dataclass(frozen=True)
class GraphLimits:
    """Global limits for one post-base graph route."""

    max_nodes: int = 6
    max_concurrent_nodes: int = 2
    max_model_requests: int = 24
    max_tool_calls: int = 96
    max_cost_usd: float | None = None
    max_wall_seconds: int = 1200
    proof_reserve_model_requests: int = 4
    progress_lease_extension: int = 2
    counterfactual_lease_extension: int = 1
    max_node_lease: int = 8
    max_lease_extensions_per_node: int = 3
    max_semantic_action_repeats: int = 1
    repeated_observation_limit: int = 2

    def __post_init__(self) -> None:
        positive = {
            "max_nodes": self.max_nodes,
            "max_concurrent_nodes": self.max_concurrent_nodes,
            "max_model_requests": self.max_model_requests,
            "max_tool_calls": self.max_tool_calls,
            "max_wall_seconds": self.max_wall_seconds,
            "progress_lease_extension": self.progress_lease_extension,
            "counterfactual_lease_extension": (self.counterfactual_lease_extension),
            "max_node_lease": self.max_node_lease,
            "max_lease_extensions_per_node": (self.max_lease_extensions_per_node),
            "max_semantic_action_repeats": self.max_semantic_action_repeats,
            "repeated_observation_limit": self.repeated_observation_limit,
        }
        for name, value in positive.items():
            if value <= 0:
                raise GraphStateError(f"{name} must be greater than zero")
        if self.max_concurrent_nodes > self.max_nodes:
            raise GraphStateError("max_concurrent_nodes cannot exceed max_nodes")
        if not 0 <= self.proof_reserve_model_requests < self.max_model_requests:
            raise GraphStateError(
                "proof_reserve_model_requests must be non-negative and smaller "
                "than max_model_requests"
            )
        if self.max_cost_usd is not None and (
            not math.isfinite(self.max_cost_usd) or self.max_cost_usd <= 0
        ):
            raise GraphStateError("max_cost_usd must be finite and greater than zero")

    def to_json(self) -> dict[str, object]:
        return {
            "max_nodes": self.max_nodes,
            "max_concurrent_nodes": self.max_concurrent_nodes,
            "max_model_requests": self.max_model_requests,
            "max_tool_calls": self.max_tool_calls,
            "max_cost_usd": self.max_cost_usd,
            "max_wall_seconds": self.max_wall_seconds,
            "proof_reserve_model_requests": (self.proof_reserve_model_requests),
            "progress_lease_extension": self.progress_lease_extension,
            "counterfactual_lease_extension": (self.counterfactual_lease_extension),
            "max_node_lease": self.max_node_lease,
            "max_lease_extensions_per_node": (self.max_lease_extensions_per_node),
            "max_semantic_action_repeats": self.max_semantic_action_repeats,
            "repeated_observation_limit": self.repeated_observation_limit,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> GraphLimits:
        max_cost = payload.get("max_cost_usd")
        return cls(
            max_nodes=_required_int(payload, "max_nodes"),
            max_concurrent_nodes=_required_int(
                payload,
                "max_concurrent_nodes",
            ),
            max_model_requests=_required_int(payload, "max_model_requests"),
            max_tool_calls=_required_int(payload, "max_tool_calls"),
            max_cost_usd=None if max_cost is None else _float(max_cost),
            max_wall_seconds=_required_int(payload, "max_wall_seconds"),
            proof_reserve_model_requests=_required_int(
                payload,
                "proof_reserve_model_requests",
            ),
            progress_lease_extension=_required_int(
                payload,
                "progress_lease_extension",
            ),
            counterfactual_lease_extension=_required_int(
                payload,
                "counterfactual_lease_extension",
            ),
            max_node_lease=_required_int(payload, "max_node_lease"),
            max_lease_extensions_per_node=_required_int(
                payload,
                "max_lease_extensions_per_node",
            ),
            max_semantic_action_repeats=_required_int(
                payload,
                "max_semantic_action_repeats",
            ),
            repeated_observation_limit=_required_int(
                payload,
                "repeated_observation_limit",
            ),
        )


@dataclass(frozen=True)
class GraphObjective:
    """Canonical task identity independent of the requesting parent."""

    fingerprint: str
    family: str
    instruction: str
    endpoint: str
    inputs: tuple[str, ...]
    strategy: str
    expected_signal: str
    evidence_refs: tuple[str, ...]

    @classmethod
    def create(  # noqa: PLR0913 - explicit canonical task identity fields.
        cls,
        *,
        family: str,
        instruction: str,
        endpoint: str = "",
        inputs: tuple[str, ...] = (),
        strategy: str = "",
        expected_signal: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> GraphObjective:
        normalized = {
            "family": _normalized_token(family) or "unknown",
            "instruction": _normalized_text(instruction),
            "endpoint": endpoint.strip(),
            "inputs": _clean_strings(inputs),
            "strategy": _normalized_token(strategy) or "unspecified",
            "expected_signal": _normalized_text(expected_signal),
        }
        if not normalized["instruction"]:
            raise GraphStateError("graph objective instruction is required")
        if not normalized["expected_signal"]:
            raise GraphStateError("graph objective expected_signal is required")
        return cls(
            fingerprint=_stable_digest(normalized),
            family=str(normalized["family"]),
            instruction=str(normalized["instruction"]),
            endpoint=str(normalized["endpoint"]),
            inputs=tuple(normalized["inputs"]),
            strategy=str(normalized["strategy"]),
            expected_signal=str(normalized["expected_signal"]),
            evidence_refs=_clean_strings(evidence_refs),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "family": self.family,
            "instruction": self.instruction,
            "endpoint": self.endpoint,
            "inputs": list(self.inputs),
            "strategy": self.strategy,
            "expected_signal": self.expected_signal,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> GraphObjective:
        objective = cls.create(
            family=str(payload.get("family") or ""),
            instruction=str(payload.get("instruction") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            inputs=_string_tuple(payload.get("inputs")),
            strategy=str(payload.get("strategy") or ""),
            expected_signal=str(payload.get("expected_signal") or ""),
            evidence_refs=_string_tuple(payload.get("evidence_refs")),
        )
        if str(payload.get("fingerprint") or "") != objective.fingerprint:
            raise GraphStateError("graph objective fingerprint does not match its canonical fields")
        return objective


@dataclass(frozen=True)
class AgentSpec:
    """Immutable policy identity resolved to concrete runtimes outside graph state."""

    fingerprint: str
    role: GraphAgentRole
    model_policy_key: str
    tool_policy_key: str
    runtime_profile_key: str
    session_policy_key: str
    skill_ids: tuple[str, ...] = ()

    @classmethod
    def create(  # noqa: PLR0913 - immutable policy identity is explicit.
        cls,
        *,
        role: GraphAgentRole | str,
        model_policy_key: str = "inherit",
        tool_policy_key: str = "inherit",
        runtime_profile_key: str = "inherit",
        session_policy_key: str = "node_isolated",
        skill_ids: tuple[str, ...] = (),
    ) -> AgentSpec:
        try:
            parsed_role = role if isinstance(role, GraphAgentRole) else GraphAgentRole(str(role))
        except ValueError as exc:
            raise GraphStateError(f"unknown graph agent role: {role}") from exc
        canonical = {
            "role": parsed_role.value,
            "model_policy_key": _required_policy_key(
                model_policy_key,
                "model_policy_key",
            ),
            "tool_policy_key": _required_policy_key(
                tool_policy_key,
                "tool_policy_key",
            ),
            "runtime_profile_key": _required_policy_key(
                runtime_profile_key,
                "runtime_profile_key",
            ),
            "session_policy_key": _required_policy_key(
                session_policy_key,
                "session_policy_key",
            ),
            "skill_ids": _clean_strings(skill_ids),
        }
        return cls(
            fingerprint=f"agent-spec:{_stable_digest(canonical)}",
            role=parsed_role,
            model_policy_key=str(canonical["model_policy_key"]),
            tool_policy_key=str(canonical["tool_policy_key"]),
            runtime_profile_key=str(canonical["runtime_profile_key"]),
            session_policy_key=str(canonical["session_policy_key"]),
            skill_ids=tuple(canonical["skill_ids"]),
        )

    @classmethod
    def for_objective(
        cls,
        objective: GraphObjective,
        *,
        is_root: bool = False,
    ) -> AgentSpec:
        text = (
            f"{objective.family} {objective.strategy} "
            f"{objective.instruction} {objective.expected_signal}"
        ).lower()
        if is_root or objective.family == "graph_coordination":
            role = GraphAgentRole.COORDINATOR
        elif "critic" in text or "falsif" in text:
            role = GraphAgentRole.CRITIC
        elif "proof" in text or "validat" in text:
            role = GraphAgentRole.VALIDATOR
        elif "closure" in text or "exploit" in text:
            role = GraphAgentRole.EXPLOITATION
        elif "recon" in text or "discover" in text:
            role = GraphAgentRole.DISCOVERY
        else:
            role = GraphAgentRole.SPECIALIST
        return cls.create(
            role=role,
            session_policy_key=(
                "fresh_typed" if role is GraphAgentRole.CRITIC else "node_isolated"
            ),
            skill_ids=(objective.family, objective.strategy),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "role": self.role.value,
            "model_policy_key": self.model_policy_key,
            "tool_policy_key": self.tool_policy_key,
            "runtime_profile_key": self.runtime_profile_key,
            "session_policy_key": self.session_policy_key,
            "skill_ids": list(self.skill_ids),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> AgentSpec:
        spec = cls.create(
            role=str(payload.get("role") or ""),
            model_policy_key=str(payload.get("model_policy_key") or ""),
            tool_policy_key=str(payload.get("tool_policy_key") or ""),
            runtime_profile_key=str(payload.get("runtime_profile_key") or ""),
            session_policy_key=str(payload.get("session_policy_key") or ""),
            skill_ids=_string_tuple(payload.get("skill_ids")),
        )
        if str(payload.get("fingerprint") or "") != spec.fingerprint:
            raise GraphStateError("agent spec fingerprint does not match its canonical fields")
        return spec


@dataclass(frozen=True)
class Hypothesis:
    """One falsifiable security claim bound to a canonical graph objective."""

    fingerprint: str
    objective_fingerprint: str
    claim: str
    support_signal: str
    falsification_signal: str
    next_discriminating_test: str
    required_capabilities: tuple[str, ...] = ()
    basis_evidence_refs: tuple[str, ...] = ()
    parent_hypothesis_fingerprint: str = ""

    @classmethod
    def create(  # noqa: PLR0913 - explicit hypothesis identity fields.
        cls,
        *,
        objective_fingerprint: str,
        claim: str,
        support_signal: str,
        falsification_signal: str,
        next_discriminating_test: str,
        required_capabilities: tuple[str, ...] = (),
        basis_evidence_refs: tuple[str, ...] = (),
        parent_hypothesis_fingerprint: str = "",
    ) -> Hypothesis:
        objective_identity = objective_fingerprint.strip()
        normalized_claim = _normalized_text(claim)
        normalized_support = _normalized_text(support_signal)
        normalized_falsification = _normalized_text(falsification_signal)
        normalized_test = _normalized_text(next_discriminating_test)
        if not objective_identity:
            raise GraphStateError("hypothesis objective_fingerprint is required")
        if not normalized_claim:
            raise GraphStateError("hypothesis claim is required")
        if not normalized_support:
            raise GraphStateError("hypothesis support_signal is required")
        if not normalized_falsification:
            raise GraphStateError("hypothesis falsification_signal is required")
        if not normalized_test:
            raise GraphStateError("hypothesis next_discriminating_test is required")
        canonical = {
            "objective_fingerprint": objective_identity,
            "claim": normalized_claim,
            "support_signal": normalized_support,
            "falsification_signal": normalized_falsification,
            "next_discriminating_test": normalized_test,
            "required_capabilities": _clean_strings(required_capabilities),
            "parent_hypothesis_fingerprint": parent_hypothesis_fingerprint.strip(),
        }
        return cls(
            fingerprint=f"hypothesis:{_stable_digest(canonical)}",
            objective_fingerprint=objective_identity,
            claim=normalized_claim,
            support_signal=normalized_support,
            falsification_signal=normalized_falsification,
            next_discriminating_test=normalized_test,
            required_capabilities=tuple(canonical["required_capabilities"]),
            basis_evidence_refs=_clean_strings(basis_evidence_refs),
            parent_hypothesis_fingerprint=str(canonical["parent_hypothesis_fingerprint"]),
        )

    @classmethod
    def from_objective(
        cls,
        objective: GraphObjective,
        *,
        parent_hypothesis_fingerprint: str = "",
    ) -> Hypothesis:
        route = objective.strategy or objective.instruction
        return cls.create(
            objective_fingerprint=objective.fingerprint,
            claim=objective.instruction,
            support_signal=objective.expected_signal,
            falsification_signal=(
                f"A bounded, correctly controlled test fails to produce {objective.expected_signal}"
            ),
            next_discriminating_test=route,
            required_capabilities=(objective.family, objective.strategy),
            basis_evidence_refs=objective.evidence_refs,
            parent_hypothesis_fingerprint=parent_hypothesis_fingerprint,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "objective_fingerprint": self.objective_fingerprint,
            "claim": self.claim,
            "support_signal": self.support_signal,
            "falsification_signal": self.falsification_signal,
            "next_discriminating_test": self.next_discriminating_test,
            "required_capabilities": list(self.required_capabilities),
            "basis_evidence_refs": list(self.basis_evidence_refs),
            "parent_hypothesis_fingerprint": self.parent_hypothesis_fingerprint,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> Hypothesis:
        hypothesis = cls.create(
            objective_fingerprint=str(payload.get("objective_fingerprint") or ""),
            claim=str(payload.get("claim") or ""),
            support_signal=str(payload.get("support_signal") or ""),
            falsification_signal=str(payload.get("falsification_signal") or ""),
            next_discriminating_test=str(payload.get("next_discriminating_test") or ""),
            required_capabilities=_string_tuple(payload.get("required_capabilities")),
            basis_evidence_refs=_string_tuple(payload.get("basis_evidence_refs")),
            parent_hypothesis_fingerprint=str(payload.get("parent_hypothesis_fingerprint") or ""),
        )
        if str(payload.get("fingerprint") or "") != hypothesis.fingerprint:
            raise GraphStateError("hypothesis fingerprint does not match its canonical fields")
        return hypothesis


@dataclass(frozen=True)
class GraphRaceLane:
    """Trusted runtime lane used to atomically create one bounded race group."""

    lane_id: str
    name: str
    agent_spec: AgentSpec

    def __post_init__(self) -> None:
        if not _normalized_token(self.lane_id):
            raise GraphStateError("race lane id is required")
        if not _normalized_text(self.name):
            raise GraphStateError("race lane name is required")
        if not isinstance(self.agent_spec, AgentSpec):
            raise GraphStateError("race lane agent spec is invalid")


@dataclass
class GraphRaceGroup:
    """Durable winner-takes-one group adjudicated only by validated evidence."""

    group_id: str
    parent_id: str
    objective_fingerprint: str
    hypothesis_fingerprint: str
    member_node_ids: tuple[str, ...]
    winner_node_id: str = ""
    winning_validation_digest: str = ""
    winning_evidence_refs: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "parent_id": self.parent_id,
            "objective_fingerprint": self.objective_fingerprint,
            "hypothesis_fingerprint": self.hypothesis_fingerprint,
            "member_node_ids": list(self.member_node_ids),
            "winner_node_id": self.winner_node_id,
            "winning_validation_digest": self.winning_validation_digest,
            "winning_evidence_refs": list(self.winning_evidence_refs),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> GraphRaceGroup:
        return cls(
            group_id=str(payload.get("group_id") or ""),
            parent_id=str(payload.get("parent_id") or ""),
            objective_fingerprint=str(payload.get("objective_fingerprint") or ""),
            hypothesis_fingerprint=str(payload.get("hypothesis_fingerprint") or ""),
            member_node_ids=_string_tuple(payload.get("member_node_ids")),
            winner_node_id=str(payload.get("winner_node_id") or ""),
            winning_validation_digest=str(payload.get("winning_validation_digest") or ""),
            winning_evidence_refs=_string_tuple(payload.get("winning_evidence_refs")),
        )


@dataclass(frozen=True)
class RaceClaimDecision:
    group_id: str
    node_id: str
    status: RaceClaimStatus
    winner_node_id: str
    evidence_refs: tuple[str, ...]


@dataclass
class GraphNode:
    node_id: str
    parent_id: str | None
    name: str
    objective: GraphObjective
    status: GraphNodeStatus
    lease_limit: int
    agent_spec: AgentSpec
    hypothesis: Hypothesis | None
    lease_used: int = 0
    model_requests_started: int = 0
    model_requests_completed: int = 0
    interrupted_model_requests: int = 0
    provider_continuity_retries: int = 0
    stall_review_grants: int = 0
    pending_model_request_id: str | None = None
    tool_calls_started: int = 0
    tool_calls_completed: int = 0
    interrupted_tool_calls: int = 0
    pending_tool_call_id: str | None = None
    spent_cost_usd: float = 0.0
    lease_extensions: int = 0
    proof_eligible: bool = False
    last_progress_epoch: int = 0
    last_observation_digest: str = ""
    repeated_observation_count: int = 0
    completion_summary: str = ""
    completion_evidence_refs: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "objective": self.objective.to_json(),
            "status": self.status.value,
            "lease_limit": self.lease_limit,
            "agent_spec": self.agent_spec.to_json(),
            "hypothesis": self.hypothesis.to_json() if self.hypothesis is not None else None,
            "lease_used": self.lease_used,
            "model_requests_started": self.model_requests_started,
            "model_requests_completed": self.model_requests_completed,
            "interrupted_model_requests": self.interrupted_model_requests,
            "provider_continuity_retries": self.provider_continuity_retries,
            "stall_review_grants": self.stall_review_grants,
            "pending_model_request_id": self.pending_model_request_id,
            "tool_calls_started": self.tool_calls_started,
            "tool_calls_completed": self.tool_calls_completed,
            "interrupted_tool_calls": self.interrupted_tool_calls,
            "pending_tool_call_id": self.pending_tool_call_id,
            "spent_cost_usd": self.spent_cost_usd,
            "lease_extensions": self.lease_extensions,
            "proof_eligible": self.proof_eligible,
            "last_progress_epoch": self.last_progress_epoch,
            "last_observation_digest": self.last_observation_digest,
            "repeated_observation_count": self.repeated_observation_count,
            "completion_summary": self.completion_summary,
            "completion_evidence_refs": list(self.completion_evidence_refs),
        }

    @classmethod
    def from_json(
        cls,
        payload: Mapping[str, object],
        *,
        legacy: bool = False,
    ) -> GraphNode:
        raw_objective = payload.get("objective")
        if not isinstance(raw_objective, Mapping):
            raise GraphStateError("graph node objective must be an object")
        objective = GraphObjective.from_json(raw_objective)
        parent_id = _optional_string(payload.get("parent_id"))
        raw_agent_spec = payload.get("agent_spec")
        if "agent_spec" not in payload:
            if not legacy:
                raise GraphStateError("graph node agent spec field is required")
            agent_spec = AgentSpec.for_objective(
                objective,
                is_root=parent_id is None,
            )
        elif isinstance(raw_agent_spec, Mapping):
            agent_spec = AgentSpec.from_json(raw_agent_spec)
        else:
            raise GraphStateError("graph node agent_spec must be an object")
        raw_hypothesis = payload.get("hypothesis")
        if "hypothesis" not in payload:
            if not legacy:
                raise GraphStateError("graph node hypothesis field is required")
            hypothesis = None if parent_id is None else Hypothesis.from_objective(objective)
        elif raw_hypothesis is None:
            hypothesis = None
        elif isinstance(raw_hypothesis, Mapping):
            hypothesis = Hypothesis.from_json(raw_hypothesis)
        else:
            raise GraphStateError("graph node hypothesis must be an object or null")
        return cls(
            node_id=str(payload.get("node_id") or ""),
            parent_id=parent_id,
            name=str(payload.get("name") or ""),
            objective=objective,
            status=GraphNodeStatus(str(payload.get("status") or "")),
            lease_limit=_required_int(payload, "lease_limit"),
            agent_spec=agent_spec,
            hypothesis=hypothesis,
            lease_used=_required_int(payload, "lease_used"),
            model_requests_started=_required_int(
                payload,
                "model_requests_started",
            ),
            model_requests_completed=_required_int(
                payload,
                "model_requests_completed",
            ),
            interrupted_model_requests=_required_int(
                payload,
                "interrupted_model_requests",
            ),
            provider_continuity_retries=_optional_non_negative_int(
                payload,
                "provider_continuity_retries",
            ),
            stall_review_grants=_optional_non_negative_int(
                payload,
                "stall_review_grants",
            ),
            pending_model_request_id=_optional_string(payload.get("pending_model_request_id")),
            tool_calls_started=_required_int(payload, "tool_calls_started"),
            tool_calls_completed=_required_int(payload, "tool_calls_completed"),
            interrupted_tool_calls=_required_int(
                payload,
                "interrupted_tool_calls",
            ),
            pending_tool_call_id=_optional_string(payload.get("pending_tool_call_id")),
            spent_cost_usd=_float(payload.get("spent_cost_usd")),
            lease_extensions=_required_int(payload, "lease_extensions"),
            proof_eligible=_required_bool(payload, "proof_eligible"),
            last_progress_epoch=_required_int(payload, "last_progress_epoch"),
            last_observation_digest=str(payload.get("last_observation_digest") or ""),
            repeated_observation_count=_required_int(
                payload,
                "repeated_observation_count",
            ),
            completion_summary=str(payload.get("completion_summary") or ""),
            completion_evidence_refs=_string_tuple(payload.get("completion_evidence_refs")),
        )


@dataclass
class GraphMessage:
    message_id: str
    sender_id: str
    target_id: str
    kind: GraphMessageKind
    body: dict[str, object]
    evidence_refs: tuple[str, ...] = ()
    consumed: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "target_id": self.target_id,
            "kind": self.kind.value,
            "body": _json_mapping(self.body),
            "evidence_refs": list(self.evidence_refs),
            "consumed": self.consumed,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> GraphMessage:
        raw_body = payload.get("body")
        if not isinstance(raw_body, Mapping):
            raise GraphStateError("graph message body must be an object")
        return cls(
            message_id=str(payload.get("message_id") or ""),
            sender_id=str(payload.get("sender_id") or ""),
            target_id=str(payload.get("target_id") or ""),
            kind=GraphMessageKind(str(payload.get("kind") or "")),
            body=_json_mapping(raw_body),
            evidence_refs=_string_tuple(payload.get("evidence_refs")),
            consumed=payload.get("consumed") is True,
        )


@dataclass
class GraphState:
    graph_id: str
    root_node_id: str
    limits: GraphLimits
    created_at_epoch: float
    status: GraphStatus = GraphStatus.RUNNING
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    messages: list[GraphMessage] = field(default_factory=list)
    race_groups: dict[str, GraphRaceGroup] = field(default_factory=dict)
    next_node_sequence: int = 1
    next_message_sequence: int = 1
    next_race_sequence: int = 1
    model_requests_started: int = 0
    model_requests_completed: int = 0
    interrupted_model_requests: int = 0
    tool_calls_started: int = 0
    tool_calls_completed: int = 0
    interrupted_tool_calls: int = 0
    spent_cost_usd: float = 0.0
    evidence_epoch: int = 0
    trusted_progress_tokens: tuple[str, ...] = ()
    disproved_hypothesis_tokens: tuple[str, ...] = ()
    counterfactual_objective_fingerprints: tuple[str, ...] = ()
    stall_review_tokens: tuple[str, ...] = ()
    semantic_action_counts: dict[str, int] = field(default_factory=dict)
    last_reason: str = "graph_started"
    proof_evidence_refs: tuple[str, ...] = ()

    @property
    def running_nodes(self) -> tuple[GraphNode, ...]:
        return tuple(node for node in self.nodes.values() if node.status is GraphNodeStatus.RUNNING)

    @property
    def active_nodes(self) -> tuple[GraphNode, ...]:
        return tuple(node for node in self.nodes.values() if node.status in ACTIVE_NODE_STATUSES)

    def children_of(self, node_id: str) -> tuple[GraphNode, ...]:
        return tuple(node for node in self.nodes.values() if node.parent_id == node_id)

    def descendants_of(self, node_id: str) -> tuple[GraphNode, ...]:
        descendants: list[GraphNode] = []
        pending = [node_id]
        while pending:
            parent = pending.pop()
            children = list(self.children_of(parent))
            descendants.extend(children)
            pending.extend(child.node_id for child in children)
        return tuple(descendants)

    def pending_messages(self, node_id: str) -> tuple[GraphMessage, ...]:
        return tuple(
            message
            for message in self.messages
            if message.target_id == node_id and not message.consumed
        )

    def race_group_for(self, node_id: str) -> GraphRaceGroup | None:
        return next(
            (group for group in self.race_groups.values() if node_id in group.member_node_ids),
            None,
        )

    def race_lost(self, node_id: str) -> bool:
        group = self.race_group_for(node_id)
        return bool(group is not None and group.winner_node_id and group.winner_node_id != node_id)

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "graph_id": self.graph_id,
            "root_node_id": self.root_node_id,
            "limits": self.limits.to_json(),
            "created_at_epoch": self.created_at_epoch,
            "status": self.status.value,
            "nodes": [self.nodes[node_id].to_json() for node_id in sorted(self.nodes)],
            "messages": [message.to_json() for message in self.messages],
            "race_groups": [
                self.race_groups[group_id].to_json() for group_id in sorted(self.race_groups)
            ],
            "next_node_sequence": self.next_node_sequence,
            "next_message_sequence": self.next_message_sequence,
            "next_race_sequence": self.next_race_sequence,
            "model_requests_started": self.model_requests_started,
            "model_requests_completed": self.model_requests_completed,
            "interrupted_model_requests": self.interrupted_model_requests,
            "tool_calls_started": self.tool_calls_started,
            "tool_calls_completed": self.tool_calls_completed,
            "interrupted_tool_calls": self.interrupted_tool_calls,
            "spent_cost_usd": self.spent_cost_usd,
            "evidence_epoch": self.evidence_epoch,
            "trusted_progress_tokens": list(self.trusted_progress_tokens),
            "disproved_hypothesis_tokens": list(self.disproved_hypothesis_tokens),
            "counterfactual_objective_fingerprints": list(
                self.counterfactual_objective_fingerprints
            ),
            "stall_review_tokens": list(self.stall_review_tokens),
            "semantic_action_counts": {
                fingerprint: self.semantic_action_counts[fingerprint]
                for fingerprint in sorted(self.semantic_action_counts)
            },
            "last_reason": self.last_reason,
            "proof_evidence_refs": list(self.proof_evidence_refs),
        }

    @classmethod
    def from_json(  # noqa: C901, PLR0912 - versioned state parsing is explicit.
        cls,
        payload: Mapping[str, object],
    ) -> GraphState:
        state_version = _required_int(payload, "version")
        if state_version not in _SUPPORTED_STATE_VERSIONS:
            raise GraphStateError("unsupported autonomous graph state version")
        raw_limits = payload.get("limits")
        raw_nodes = payload.get("nodes")
        raw_messages = payload.get("messages")
        raw_race_groups = payload.get("race_groups", [])
        if not isinstance(raw_limits, Mapping):
            raise GraphStateError("graph limits must be an object")
        if not isinstance(raw_nodes, list):
            raise GraphStateError("graph nodes must be a list")
        if not isinstance(raw_messages, list):
            raise GraphStateError("graph messages must be a list")
        if not isinstance(raw_race_groups, list):
            raise GraphStateError("graph race groups must be a list")
        nodes: dict[str, GraphNode] = {}
        for raw_node in raw_nodes:
            if not isinstance(raw_node, Mapping):
                raise GraphStateError("graph node entry must be an object")
            node = GraphNode.from_json(
                raw_node,
                legacy=state_version < _TYPED_STATE_VERSION,
            )
            if node.node_id in nodes:
                raise GraphStateError(f"duplicate graph node id: {node.node_id}")
            nodes[node.node_id] = node
        messages: list[GraphMessage] = []
        for raw_message in raw_messages:
            if not isinstance(raw_message, Mapping):
                raise GraphStateError("graph message entry must be an object")
            messages.append(GraphMessage.from_json(raw_message))
        race_groups: dict[str, GraphRaceGroup] = {}
        for raw_group in raw_race_groups:
            if not isinstance(raw_group, Mapping):
                raise GraphStateError("graph race group entry must be an object")
            group = GraphRaceGroup.from_json(raw_group)
            if group.group_id in race_groups:
                raise GraphStateError(f"duplicate graph race group id: {group.group_id}")
            race_groups[group.group_id] = group
        state = cls(
            graph_id=str(payload.get("graph_id") or ""),
            root_node_id=str(payload.get("root_node_id") or ""),
            limits=GraphLimits.from_json(raw_limits),
            created_at_epoch=_float(payload.get("created_at_epoch")),
            status=GraphStatus(str(payload.get("status") or "")),
            nodes=nodes,
            messages=messages,
            race_groups=race_groups,
            next_node_sequence=_required_int(payload, "next_node_sequence"),
            next_message_sequence=_required_int(
                payload,
                "next_message_sequence",
            ),
            next_race_sequence=(
                _required_int(payload, "next_race_sequence")
                if state_version >= _STATE_VERSION
                else 1
            ),
            model_requests_started=_required_int(
                payload,
                "model_requests_started",
            ),
            model_requests_completed=_required_int(
                payload,
                "model_requests_completed",
            ),
            interrupted_model_requests=_required_int(
                payload,
                "interrupted_model_requests",
            ),
            tool_calls_started=_required_int(payload, "tool_calls_started"),
            tool_calls_completed=_required_int(payload, "tool_calls_completed"),
            interrupted_tool_calls=_required_int(
                payload,
                "interrupted_tool_calls",
            ),
            spent_cost_usd=_float(payload.get("spent_cost_usd")),
            evidence_epoch=_required_int(payload, "evidence_epoch"),
            trusted_progress_tokens=_string_tuple(payload.get("trusted_progress_tokens")),
            disproved_hypothesis_tokens=_string_tuple(payload.get("disproved_hypothesis_tokens")),
            counterfactual_objective_fingerprints=_string_tuple(
                payload.get("counterfactual_objective_fingerprints")
            ),
            stall_review_tokens=_string_tuple(payload.get("stall_review_tokens")),
            semantic_action_counts=_positive_int_mapping(
                payload,
                "semantic_action_counts",
            ),
            last_reason=str(payload.get("last_reason") or ""),
            proof_evidence_refs=_string_tuple(payload.get("proof_evidence_refs")),
        )
        state.validate()
        return state

    @classmethod
    def load(cls, path: Path) -> GraphState:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GraphStateError(f"cannot read autonomous graph state: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise GraphStateError("autonomous graph state must be an object")
        return cls.from_json(payload)

    def save(self, path: Path) -> None:
        self.validate()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    def validate(self) -> None:  # noqa: C901, PLR0912 - explicit invariant audit.
        if not self.graph_id.strip():
            raise GraphStateError("graph_id is required")
        if not math.isfinite(self.created_at_epoch) or self.created_at_epoch < 0:
            raise GraphStateError("created_at_epoch must be a non-negative finite number")
        if self.root_node_id not in self.nodes:
            raise GraphStateError("root_node_id does not reference a graph node")
        root = self.nodes[self.root_node_id]
        if root.parent_id is not None:
            raise GraphStateError("root graph node cannot have a parent")
        if len(self.nodes) > self.limits.max_nodes:
            raise GraphStateError("graph node count exceeds max_nodes")
        if len(self.running_nodes) > self.limits.max_concurrent_nodes:
            raise GraphStateError("running node count exceeds max_concurrent_nodes")
        if (
            self.next_node_sequence <= 0
            or self.next_message_sequence <= 0
            or self.next_race_sequence <= 0
        ):
            raise GraphStateError("graph sequence counters must be positive")
        if self.evidence_epoch < 0:
            raise GraphStateError("evidence_epoch cannot be negative")
        canonical_sets = (
            self.trusted_progress_tokens,
            self.disproved_hypothesis_tokens,
            self.counterfactual_objective_fingerprints,
            self.stall_review_tokens,
        )
        if any(_clean_strings(values) != values for values in canonical_sets):
            raise GraphStateError("graph progress and counterfactual tokens must be canonical")
        if any(
            not fingerprint or count <= 0 or count > self.limits.max_semantic_action_repeats
            for fingerprint, count in self.semantic_action_counts.items()
        ):
            raise GraphStateError("semantic action accounting is invalid")

        for node in self.nodes.values():
            self._validate_node(node)
        self._validate_race_groups()
        self._validate_acyclic()
        self._validate_messages()
        self._validate_accounting()

        if self.status in TERMINAL_GRAPH_STATUSES and self.active_nodes:
            raise GraphStateError("terminal graph cannot retain active nodes")
        if self.status is GraphStatus.SOLVED and not self.proof_evidence_refs:
            raise GraphStateError("solved graph requires trusted proof evidence refs")

    def _validate_node(  # noqa: C901, PLR0912, PLR0915 - invariant audit is explicit.
        self,
        node: GraphNode,
    ) -> None:
        if not node.node_id:
            raise GraphStateError("graph node id is required")
        if not node.name.strip():
            raise GraphStateError(f"graph node {node.node_id} name is required")
        if node.parent_id is not None and node.parent_id not in self.nodes:
            raise GraphStateError(f"graph node {node.node_id} references an unknown parent")
        if node.parent_id == node.node_id:
            raise GraphStateError(f"graph node {node.node_id} cannot parent itself")
        if not isinstance(node.agent_spec, AgentSpec):
            raise GraphStateError(f"graph node {node.node_id} agent spec is invalid")
        if node.parent_id is None:
            if node.agent_spec.role is not GraphAgentRole.COORDINATOR:
                raise GraphStateError("root graph node must use the coordinator role")
        elif node.hypothesis is None:
            raise GraphStateError(f"graph node {node.node_id} requires a hypothesis")
        if node.hypothesis is not None:
            if not isinstance(node.hypothesis, Hypothesis):
                raise GraphStateError(f"graph node {node.node_id} hypothesis is invalid")
            if node.hypothesis.objective_fingerprint != node.objective.fingerprint:
                raise GraphStateError(
                    f"graph node {node.node_id} hypothesis does not bind its objective"
                )
            parent_hypothesis = node.hypothesis.parent_hypothesis_fingerprint
            if parent_hypothesis and not any(
                candidate.hypothesis is not None
                and candidate.hypothesis.fingerprint == parent_hypothesis
                for candidate in self.nodes.values()
            ):
                raise GraphStateError(
                    f"graph node {node.node_id} hypothesis references an unknown parent"
                )
        if node.lease_limit <= 0:
            raise GraphStateError(f"graph node {node.node_id} lease must be positive")
        if node.lease_limit > self.limits.max_node_lease:
            raise GraphStateError(f"graph node {node.node_id} lease exceeds max_node_lease")
        if not 0 <= node.lease_used <= node.lease_limit:
            raise GraphStateError(f"graph node {node.node_id} lease usage is inconsistent")
        if not 0 <= node.lease_extensions <= (self.limits.max_lease_extensions_per_node):
            raise GraphStateError(f"graph node {node.node_id} lease extension count is invalid")
        if not 0 <= node.last_progress_epoch <= self.evidence_epoch:
            raise GraphStateError(f"graph node {node.node_id} progress epoch is invalid")
        if node.repeated_observation_count < 0:
            raise GraphStateError(
                f"graph node {node.node_id} repeated observation count is invalid"
            )
        if bool(node.last_observation_digest) != bool(node.repeated_observation_count):
            raise GraphStateError(f"graph node {node.node_id} observation watchdog is inconsistent")
        counters = (
            node.model_requests_started,
            node.model_requests_completed,
            node.interrupted_model_requests,
            node.provider_continuity_retries,
            node.stall_review_grants,
            node.tool_calls_started,
            node.tool_calls_completed,
            node.interrupted_tool_calls,
        )
        if any(value < 0 for value in counters) or node.spent_cost_usd < 0:
            raise GraphStateError(f"graph node {node.node_id} accounting cannot be negative")
        if node.model_requests_completed > node.model_requests_started:
            raise GraphStateError(
                f"graph node {node.node_id} completed model requests exceed starts"
            )
        if node.interrupted_model_requests > node.model_requests_completed:
            raise GraphStateError(
                f"graph node {node.node_id} interrupted model requests are invalid"
            )
        if node.tool_calls_completed > node.tool_calls_started:
            raise GraphStateError(f"graph node {node.node_id} completed tool calls exceed starts")
        if node.interrupted_tool_calls > node.tool_calls_completed:
            raise GraphStateError(f"graph node {node.node_id} interrupted tool calls are invalid")
        pending_models = node.model_requests_started - node.model_requests_completed
        pending_tools = node.tool_calls_started - node.tool_calls_completed
        if pending_models not in {0, 1} or bool(pending_models) != bool(
            node.pending_model_request_id
        ):
            raise GraphStateError(
                f"graph node {node.node_id} pending model accounting is inconsistent"
            )
        if pending_tools not in {0, 1} or bool(pending_tools) != bool(node.pending_tool_call_id):
            raise GraphStateError(
                f"graph node {node.node_id} pending tool accounting is inconsistent"
            )
        pending_terminal_settlement = (
            self.status in TERMINAL_GRAPH_STATUSES and node.status is GraphNodeStatus.STOPPED
        )
        if (
            (node.pending_model_request_id is not None or node.pending_tool_call_id is not None)
            and node.status is not GraphNodeStatus.RUNNING
            and not pending_terminal_settlement
        ):
            raise GraphStateError(f"graph node {node.node_id} has pending work while not running")
        if node.lease_used + node.provider_continuity_retries != node.model_requests_started:
            raise GraphStateError(
                f"graph node {node.node_id} lease plus continuity retries must equal model starts"
            )
        if node.status in TERMINAL_NODE_STATUSES and self.children_of(node.node_id):
            active_children = [
                child.node_id
                for child in self.children_of(node.node_id)
                if child.status in ACTIVE_NODE_STATUSES
            ]
            if active_children:
                raise GraphStateError(f"terminal graph node {node.node_id} has active children")

    def _validate_race_groups(  # noqa: C901, PLR0912 - invariant audit is explicit.
        self,
    ) -> None:
        memberships: dict[str, str] = {}
        grouped_objectives: dict[str, set[str]] = {}
        for group_id, group in self.race_groups.items():
            if group.group_id != group_id or not group_id.strip():
                raise GraphStateError("graph race group identity is invalid")
            if group.parent_id not in self.nodes:
                raise GraphStateError(f"race group {group_id} references an unknown parent")
            if not MIN_RACE_LANES <= len(group.member_node_ids) <= MAX_RACE_LANES:
                raise GraphStateError(f"race group {group_id} has an invalid lane count")
            if _clean_strings(group.member_node_ids) != group.member_node_ids:
                raise GraphStateError(f"race group {group_id} members are not canonical")
            specs: set[str] = set()
            model_policies: set[str] = set()
            for node_id in group.member_node_ids:
                previous_group = memberships.setdefault(node_id, group_id)
                if previous_group != group_id:
                    raise GraphStateError(f"race node {node_id} belongs to multiple groups")
                node = self.nodes.get(node_id)
                if node is None:
                    raise GraphStateError(f"race group {group_id} references an unknown node")
                if node.parent_id != group.parent_id:
                    raise GraphStateError(f"race group {group_id} lanes must share one parent")
                if node.objective.fingerprint != group.objective_fingerprint:
                    raise GraphStateError(f"race group {group_id} objective binding mismatch")
                if node.hypothesis is None or (
                    node.hypothesis.fingerprint != group.hypothesis_fingerprint
                ):
                    raise GraphStateError(f"race group {group_id} hypothesis binding mismatch")
                if node.agent_spec.model_policy_key == "inherit":
                    raise GraphStateError(f"race group {group_id} requires explicit model policies")
                specs.add(node.agent_spec.fingerprint)
                model_policies.add(node.agent_spec.model_policy_key)
            if len(specs) != len(group.member_node_ids) or len(model_policies) != len(
                group.member_node_ids
            ):
                raise GraphStateError(f"race group {group_id} lanes are not heterogeneous")
            grouped_objectives[group.objective_fingerprint] = set(group.member_node_ids)
            won = bool(group.winner_node_id)
            if won != bool(group.winning_validation_digest) or won != bool(
                group.winning_evidence_refs
            ):
                raise GraphStateError(f"race group {group_id} winner receipt is incomplete")
            if won and group.winner_node_id not in group.member_node_ids:
                raise GraphStateError(f"race group {group_id} winner is not a member")

        objective_nodes: dict[str, set[str]] = {}
        for node in self.nodes.values():
            objective_nodes.setdefault(node.objective.fingerprint, set()).add(node.node_id)
        for fingerprint, node_ids in objective_nodes.items():
            if len(node_ids) == 1:
                continue
            if grouped_objectives.get(fingerprint) != node_ids:
                raise GraphStateError(f"duplicate objective fingerprint: {fingerprint}")

    def _validate_acyclic(self) -> None:
        for node_id in self.nodes:
            seen: set[str] = set()
            current: str | None = node_id
            while current is not None:
                if current in seen:
                    raise GraphStateError("graph parent relation contains a cycle")
                seen.add(current)
                current = self.nodes[current].parent_id

    def _validate_messages(self) -> None:
        message_ids: set[str] = set()
        for message in self.messages:
            if not message.message_id:
                raise GraphStateError("graph message id is required")
            if message.message_id in message_ids:
                raise GraphStateError(f"duplicate graph message id: {message.message_id}")
            message_ids.add(message.message_id)
            if message.sender_id not in self.nodes:
                raise GraphStateError(f"graph message {message.message_id} has unknown sender")
            if message.target_id not in self.nodes:
                raise GraphStateError(f"graph message {message.message_id} has unknown target")

    def _validate_accounting(self) -> None:
        node_model_starts = sum(node.model_requests_started for node in self.nodes.values())
        node_model_completed = sum(node.model_requests_completed for node in self.nodes.values())
        node_model_interrupted = sum(
            node.interrupted_model_requests for node in self.nodes.values()
        )
        node_tool_starts = sum(node.tool_calls_started for node in self.nodes.values())
        node_tool_completed = sum(node.tool_calls_completed for node in self.nodes.values())
        node_tool_interrupted = sum(node.interrupted_tool_calls for node in self.nodes.values())
        if (
            self.model_requests_started,
            self.model_requests_completed,
            self.interrupted_model_requests,
        ) != (
            node_model_starts,
            node_model_completed,
            node_model_interrupted,
        ):
            raise GraphStateError("global model accounting does not match graph nodes")
        if (
            self.tool_calls_started,
            self.tool_calls_completed,
            self.interrupted_tool_calls,
        ) != (
            node_tool_starts,
            node_tool_completed,
            node_tool_interrupted,
        ):
            raise GraphStateError("global tool accounting does not match graph nodes")
        if self.model_requests_started > self.limits.max_model_requests:
            raise GraphStateError("model requests exceed max_model_requests")
        if self.tool_calls_started > self.limits.max_tool_calls:
            raise GraphStateError("tool calls exceed max_tool_calls")
        node_cost = sum(node.spent_cost_usd for node in self.nodes.values())
        if not math.isclose(node_cost, self.spent_cost_usd, abs_tol=1e-9):
            raise GraphStateError("global cost does not match graph nodes")


def _stable_digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _normalized_text(value: str) -> str:
    return " ".join(value.strip().split())


def _normalized_token(value: str) -> str:
    return _normalized_text(value).lower().replace(" ", "_")


def _required_policy_key(value: str, label: str) -> str:
    key = _normalized_token(value)
    if not key:
        raise GraphStateError(f"{label} is required")
    return key


def _clean_strings(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ()
    cleaned = {_normalized_text(str(value)) for value in values}
    return tuple(sorted(value for value in cleaned if value))


def _string_tuple(value: object) -> tuple[str, ...]:
    return _clean_strings(value)


def _required_int(payload: Mapping[str, object], name: str) -> int:
    value = payload.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise GraphStateError(f"{name} must be an integer")
    return value


def _optional_non_negative_int(
    payload: Mapping[str, object],
    name: str,
) -> int:
    value = payload.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GraphStateError(f"{name} must be a non-negative integer")
    return value


def _required_bool(payload: Mapping[str, object], name: str) -> bool:
    value = payload.get(name)
    if not isinstance(value, bool):
        raise GraphStateError(f"{name} must be a boolean")
    return value


def _positive_int_mapping(
    payload: Mapping[str, object],
    name: str,
) -> dict[str, int]:
    raw = payload.get(name)
    if not isinstance(raw, Mapping):
        raise GraphStateError(f"{name} must be an object")
    output: dict[str, int] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            raise GraphStateError(f"{name} keys must be non-empty strings")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise GraphStateError(f"{name} values must be positive integers")
        output[key] = value
    return output


def _float(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GraphStateError("expected a number")
    result = float(value)
    if not math.isfinite(result):
        raise GraphStateError("expected a finite number")
    return result


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _json_mapping(value: Mapping[str, object]) -> dict[str, object]:
    try:
        encoded = json.dumps(dict(value), sort_keys=True)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise GraphStateError(f"message body must be JSON serializable: {exc}") from exc
    if not isinstance(decoded, dict):
        raise GraphStateError("message body must encode to an object")
    return dict(decoded)


__all__ = [
    "ACTIVE_NODE_STATUSES",
    "MAX_RACE_LANES",
    "MIN_RACE_LANES",
    "TERMINAL_GRAPH_STATUSES",
    "TERMINAL_NODE_STATUSES",
    "AgentSpec",
    "GraphAgentRole",
    "GraphLimits",
    "GraphMessage",
    "GraphMessageKind",
    "GraphNode",
    "GraphNodeStatus",
    "GraphObjective",
    "GraphRaceGroup",
    "GraphRaceLane",
    "GraphState",
    "GraphStateError",
    "GraphStatus",
    "Hypothesis",
    "RaceClaimDecision",
    "RaceClaimStatus",
]
