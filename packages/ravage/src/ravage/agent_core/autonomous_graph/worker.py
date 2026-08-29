from __future__ import annotations

import asyncio
import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from ravage.agent_core.autonomous_graph.budget_phase import (
    GraphBudgetDirective,
    GraphBudgetPhaseError,
    authorize_budget_phase_action,
    graph_budget_directive,
)
from ravage.agent_core.autonomous_graph.context_handoff import (
    inherit_parent_context,
)
from ravage.agent_core.autonomous_graph.coordinator import (
    GraphBudgetExceededError,
    GraphCoordinator,
    GraphCoordinatorError,
    GraphLeaseExhaustedError,
    GraphLeaseGrantError,
    RepeatedGraphActionError,
)
from ravage.agent_core.autonomous_graph.dispatch import (
    GraphDispatchPlanner,
)
from ravage.agent_core.autonomous_graph.effort_policy import (
    GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT,
)
from ravage.agent_core.autonomous_graph.mission import (
    GraphMission,
    graph_mission_from_state,
)
from ravage.agent_core.autonomous_graph.models import (
    ACTIVE_NODE_STATUSES,
    AgentSpec,
    GraphAgentRole,
    GraphMessageKind,
    GraphNode,
    GraphNodeStatus,
    GraphObjective,
    GraphStatus,
    Hypothesis,
    RaceClaimStatus,
)
from ravage.agent_core.autonomous_graph.protocol import (
    GraphActionKind,
    GraphProtocolError,
    GraphWorkerAction,
    parse_worker_action,
)
from ravage.agent_core.autonomous_graph.provider_continuity import (
    GraphModelContinuityRequiredError,
)
from ravage.agent_core.autonomous_graph.routing import (
    GraphActionRejectedError,
)
from ravage.agent_core.autonomous_graph.run_store import (
    ActionLifecycle,
    RunStoreError,
)
from ravage.agent_core.autonomous_graph.runtime_binding import (
    GraphRuntimeBindingError,
    GraphRuntimeResolver,
)
from ravage.agent_core.autonomous_graph.scheduler import (
    GraphProgressBinding,
    LeaseDecision,
    ObservationDecision,
    ProgressBatchClass,
    ProgressEvidenceValidator,
    ProgressiveGraphScheduler,
    ProgressReceipt,
    ValidatedProgressBatch,
    validate_progress_receipt_batch,
)
from ravage.agent_core.autonomous_graph.session_projection import (
    project_session_records,
)
from ravage.agent_core.autonomous_graph.sessions import (
    GraphSessionStore,
    SessionRole,
)
from ravage.agent_core.autonomous_graph.specialists import (
    specialist_system_guidance,
)
from ravage.agent_core.autonomous_graph.stall_review import (
    select_stall_review,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from ravage.agent_core.autonomous_graph.investigation import (
        InvestigationEngine,
        InvestigationTicket,
    )
    from ravage.agent_core.autonomous_graph.loop_policy import LoopDecision
    from ravage.agent_core.autonomous_graph.routing import (
        GraphActionGuard,
        GraphRoutingDirective,
    )
    from ravage.agent_core.autonomous_graph.run_store import RunLease, RunStore


@dataclass(frozen=True)
class GraphModelReply:
    content: str
    cost_usd: float = 0.0
    artifact_content: str | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.cost_usd) or self.cost_usd < 0:
            message = "graph model reply cost must be finite and non-negative"
            raise ValueError(message)


@dataclass(frozen=True)
class GraphToolResult:
    output: str
    observation_digest: str = ""
    progress_receipts: tuple[ProgressReceipt, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    target_requests: int | None = None
    counterfactual_objective_fingerprint: str = ""
    routing_directive: GraphRoutingDirective | None = None

    def __post_init__(self) -> None:
        if self.target_requests is not None and (
            isinstance(self.target_requests, bool)
            or not isinstance(self.target_requests, int)
            or self.target_requests < 0
        ):
            message = "graph target request count must be a non-negative integer"
            raise ValueError(message)


@dataclass(frozen=True)
class ProofGateResult:
    accepted: bool
    evidence_refs: tuple[str, ...] = ()
    reason: str = ""


class GraphComplete(Protocol):
    def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> Awaitable[GraphModelReply]: ...


class GraphExecute(Protocol):
    def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> Awaitable[GraphToolResult]: ...


class GraphProofGate(Protocol):
    def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> Awaitable[ProofGateResult]: ...


class WorkerStepKind(StrEnum):
    EXECUTED = "executed"
    SPAWNED = "spawned"
    MESSAGED = "messaged"
    WAITED = "waited"
    HANDED_OFF = "handed_off"
    ROUTED = "routed"
    FINISHED = "finished"
    PROOF_ACCEPTED = "proof_accepted"
    PROOF_REJECTED = "proof_rejected"
    LEASE_EXHAUSTED = "lease_exhausted"
    ACTION_REJECTED = "action_rejected"
    INVALID_ACTION = "invalid_action"
    TOOL_FAILED = "tool_failed"
    RACE_LOST = "race_lost"
    CRASHED = "crashed"
    TERMINAL = "terminal"


class GraphDurabilityError(RuntimeError):
    """Raised when durable execution can no longer be proven safe."""


@dataclass(frozen=True)
class WorkerStepResult:
    node_id: str
    kind: WorkerStepKind
    reason: str
    action_kind: GraphActionKind | None = None
    spawned_node_id: str | None = None
    lease_decision: LeaseDecision | None = None
    observation_decision: ObservationDecision | None = None
    loop_decision: LoopDecision | None = None


@dataclass(frozen=True)
class GraphRunResult:
    status: GraphStatus
    reason: str
    steps: tuple[WorkerStepResult, ...]


class GraphWorker:
    """Execute one accounted, structured action for one addressable node."""

    def __init__(  # noqa: PLR0913 - explicit worker dependency boundary.
        self,
        *,
        coordinator: GraphCoordinator,
        scheduler: ProgressiveGraphScheduler,
        sessions: GraphSessionStore,
        complete: GraphComplete,
        execute: GraphExecute,
        proof_gate: GraphProofGate,
        runtime_resolver: GraphRuntimeResolver | None = None,
        evidence_validator: ProgressEvidenceValidator | None = None,
        action_guard: GraphActionGuard | None = None,
        investigation_engine: InvestigationEngine | None = None,
        context_provider: object | None = None,
        run_store: RunStore | None = None,
        run_lease: RunLease | None = None,
        assert_run_owned: Callable[[], None] | None = None,
        idle_wait_seconds: float = 0.25,
    ) -> None:
        if idle_wait_seconds <= 0:
            message = "idle_wait_seconds must be greater than zero"
            raise ValueError(message)
        if (run_store is None) != (run_lease is None):
            message = "run_store and run_lease must be configured together"
            raise ValueError(message)
        self.coordinator = coordinator
        self.scheduler = scheduler
        self.sessions = sessions
        self.complete = complete
        self.execute = execute
        self.runtime_resolver = runtime_resolver or GraphRuntimeResolver(
            default_complete=complete,
            default_execute=execute,
        )
        self.proof_gate = proof_gate
        self.evidence_validator = evidence_validator
        self.action_guard = action_guard
        self.investigation_engine = investigation_engine
        self.context_provider = context_provider or evidence_validator
        self.run_store = run_store
        self.run_lease = run_lease
        self.assert_run_owned = assert_run_owned
        self.idle_wait_seconds = idle_wait_seconds
        # Runtime profiles may wrap different tool clients, but mutations of the
        # graph-wide AgentState and blackboard still require one global arbiter.
        self._execution_lock = asyncio.Lock()

    async def step(  # noqa: C901, PLR0911, PLR0912, PLR0915 - explicit lifecycle.
        self,
        node_id: str,
    ) -> WorkerStepResult:
        self.assert_owned("worker_step_start")
        state = self.coordinator.state
        if state.status is not GraphStatus.RUNNING:
            return self._result(
                node_id,
                WorkerStepKind.TERMINAL,
                reason=f"graph_{state.status.value}",
            )
        node = state.nodes[node_id]
        if node.status is GraphNodeStatus.READY:
            await self.coordinator.start_node(node_id)
            node = state.nodes[node_id]
        if node.status is not GraphNodeStatus.RUNNING:
            return self._result(
                node_id,
                WorkerStepKind.TERMINAL,
                reason=f"node_{node.status.value}",
            )
        try:
            runtime = self.runtime_resolver.resolve(node)
        except GraphRuntimeBindingError as exc:
            await self.coordinator.mark_crashed(
                node_id,
                reason=f"runtime_binding_failed:{exc}",
            )
            return self._result(
                node_id,
                WorkerStepKind.CRASHED,
                reason="runtime_binding_failed",
            )

        await self._extend_for_trusted_inbox(node_id)
        self.assert_owned("model_request_start")
        try:
            request_id = await self.coordinator.begin_model_request(node_id)
        except GraphLeaseExhaustedError:
            owned_work = await self._owned_work(node_id)
            if owned_work:
                await self._fail_owned_work(
                    node_id,
                    reason="progressive_lease_exhausted_without_closure",
                )
                await self.coordinator.finish_node(
                    node_id,
                    summary="Routed closure lease exhausted without conclusive evidence.",
                )
            else:
                await self.coordinator.park_node(node_id)
            return self._result(
                node_id,
                WorkerStepKind.LEASE_EXHAUSTED,
                reason=(
                    "routed_closure_lease_exhausted"
                    if owned_work
                    else "node_progressive_lease_exhausted"
                ),
            )
        except GraphBudgetExceededError as exc:
            if (
                self.coordinator.state.status is GraphStatus.RUNNING
                and self.coordinator.state.nodes[node_id].status is GraphNodeStatus.RUNNING
            ):
                await self.coordinator.park_node(node_id)
                kind = WorkerStepKind.LEASE_EXHAUSTED
            else:
                kind = WorkerStepKind.TERMINAL
            return self._result(node_id, kind, reason=str(exc))

        inbox = await self.coordinator.consume_messages(node_id)
        evidence_context = await self._evidence_context()
        investigation_context = (
            await asyncio.to_thread(
                self.investigation_engine.context_projection,
                node_id=node_id,
                objective=node.objective,
                hypothesis=node.hypothesis,
            )
            if self.investigation_engine is not None
            else {}
        )
        context = _worker_context(
            coordinator=self.coordinator,
            node_id=node_id,
            inbox=tuple(message.to_json() for message in inbox),
            evidence_context=evidence_context,
            investigation_context=investigation_context,
            budget_directive=graph_budget_directive(
                self.coordinator.state,
            ),
        )
        await asyncio.to_thread(
            self.sessions.append,
            node_id,
            role=SessionRole.USER,
            content=context,
        )
        session_records = await asyncio.to_thread(
            self.sessions.records,
            node_id,
        )
        projection = project_session_records(
            session_records,
            authoritative_context=context,
        )
        messages = [
            {
                "role": "system",
                "content": _worker_system_prompt(
                    node.objective,
                    agent_spec=node.agent_spec,
                    hypothesis=node.hypothesis,
                    investigation_enabled=self.investigation_engine is not None,
                    flag_objective=(
                        graph_mission_from_state(self.coordinator.state)
                        is GraphMission.FLAG_CAPTURE
                    ),
                ),
            },
            *projection.messages,
        ]
        try:
            reply, request_id = await self._complete_model_turn(
                node_id,
                messages=messages,
                request_id=request_id,
                complete=runtime.complete,
            )
        except GraphDurabilityError:
            raise
        except Exception as exc:  # noqa: BLE001 - crash receipt owns provider errors.
            self.assert_owned("model_failure_application")
            await self._fail_owned_work(
                node_id,
                reason=f"model_request_failed:{type(exc).__name__}",
            )
            await self.coordinator.mark_crashed(
                node_id,
                reason=f"model_request_failed:{type(exc).__name__}:{exc}",
            )
            return self._result(
                node_id,
                WorkerStepKind.CRASHED,
                reason=f"model_request_failed:{type(exc).__name__}",
            )

        self.assert_owned("model_reply_application")
        await self.coordinator.complete_model_request(
            node_id,
            request_id=request_id,
            cost_usd=reply.cost_usd,
        )
        await asyncio.to_thread(
            self.sessions.append,
            node_id,
            role=SessionRole.ASSISTANT,
            content=reply.artifact_content or reply.content,
        )
        race_loser = await self._retire_if_race_loser(node_id)
        if race_loser is not None:
            return race_loser
        if self.coordinator.state.status is not GraphStatus.RUNNING:
            return self._result(
                node_id,
                WorkerStepKind.TERMINAL,
                reason=self.coordinator.state.last_reason,
            )

        try:
            action = parse_worker_action(reply.content)
        except GraphProtocolError as exc:
            await self._append_feedback(node_id, f"action_rejected:{exc}")
            return self._result(
                node_id,
                WorkerStepKind.INVALID_ACTION,
                reason=str(exc),
            )
        race_group = self.coordinator.state.race_group_for(node_id)
        if (
            race_group is not None
            and not race_group.winner_node_id
            and action.kind
            not in {
                GraphActionKind.EXECUTE,
                GraphActionKind.FINISH,
                GraphActionKind.WAIT,
            }
        ):
            reason = f"open_race_action_rejected:{action.kind.value}"
            await self._append_feedback(node_id, reason)
            return self._result(
                node_id,
                WorkerStepKind.ACTION_REJECTED,
                reason=reason,
                action_kind=action.kind,
            )
        self.assert_owned("worker_dispatch")
        try:
            authorize_budget_phase_action(
                graph_budget_directive(self.coordinator.state),
                node=self.coordinator.state.nodes[node_id],
                action=action,
            )
            return await self._dispatch(node_id, action)
        except GraphDurabilityError:
            raise
        except GraphBudgetPhaseError as exc:
            self._raise_if_settled_unapplied(exc)
            await self._append_feedback(node_id, f"budget_phase_rejected:{exc}")
            return self._result(
                node_id,
                WorkerStepKind.ACTION_REJECTED,
                reason=str(exc),
                action_kind=action.kind,
            )
        except RepeatedGraphActionError as exc:
            self._raise_if_settled_unapplied(exc)
            await self._append_feedback(node_id, f"action_rejected:{exc}")
            return self._result(
                node_id,
                WorkerStepKind.ACTION_REJECTED,
                reason=str(exc),
                action_kind=action.kind,
            )
        except (GraphCoordinatorError, GraphProtocolError) as exc:
            self._raise_if_settled_unapplied(exc)
            await self._append_feedback(node_id, f"lifecycle_rejected:{exc}")
            return self._result(
                node_id,
                WorkerStepKind.ACTION_REJECTED,
                reason=str(exc),
                action_kind=action.kind,
            )
        except Exception as exc:
            self._raise_if_settled_unapplied(exc)
            raise

    async def _dispatch(  # noqa: PLR0911 - closed action union.
        self,
        node_id: str,
        action: GraphWorkerAction,
    ) -> WorkerStepResult:
        if action.kind is GraphActionKind.EXECUTE:
            return await self._execute_action(node_id, action)
        if action.kind is GraphActionKind.SPAWN:
            objective = action.spawn_objective()
            parent = self.coordinator.state.nodes[node_id]
            hypothesis = action.spawn_hypothesis(
                parent_hypothesis_fingerprint=(
                    parent.hypothesis.fingerprint if parent.hypothesis is not None else ""
                )
            )
            self._validate_evidence_refs(
                tuple(
                    sorted(
                        {
                            *objective.evidence_refs,
                            *hypothesis.basis_evidence_refs,
                        }
                    )
                ),
                require_trusted=True,
            )
            lease_limit = _validated_spawn_lease_limit(action.payload.get("lease_limit", 2))
            child = await self.coordinator.spawn_node(
                parent_id=node_id,
                name=str(action.payload["name"]),
                objective=objective,
                lease_limit=lease_limit,
                hypothesis=hypothesis,
            )
            if child.agent_spec.session_policy_key != "fresh_typed":
                await asyncio.to_thread(
                    inherit_parent_context,
                    self.sessions,
                    parent_id=node_id,
                    child_id=child.node_id,
                    objective=objective,
                )
            return self._result(
                node_id,
                WorkerStepKind.SPAWNED,
                reason="child_registered",
                action_kind=action.kind,
                spawned_node_id=child.node_id,
            )
        if action.kind is GraphActionKind.MESSAGE:
            await self._send_action_message(node_id, action)
            return self._result(
                node_id,
                WorkerStepKind.MESSAGED,
                reason="structured_message_delivered",
                action_kind=action.kind,
            )
        if action.kind is GraphActionKind.WAIT:
            timeout = _bounded_wait_timeout(
                action.payload.get("timeout_seconds"),
                maximum=self.idle_wait_seconds,
            )
            messages = await self.coordinator.wait_for_messages(
                node_id,
                timeout_seconds=timeout,
            )
            if messages:
                await self._append_feedback(
                    node_id,
                    "graph_inbox:"
                    + json.dumps(
                        [message.to_json() for message in messages],
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                )
            return self._result(
                node_id,
                WorkerStepKind.WAITED,
                reason=("wait_woke_with_messages" if messages else "wait_parked_without_message"),
                action_kind=action.kind,
            )
        if action.kind is GraphActionKind.HANDOFF:
            await self._send_action_message(node_id, action)
            await self.coordinator.park_node(node_id)
            return self._result(
                node_id,
                WorkerStepKind.HANDED_OFF,
                reason="work_handed_off_and_sender_parked",
                action_kind=action.kind,
            )
        if action.kind is GraphActionKind.FINISH:
            evidence_refs = _evidence_refs(action.payload)
            self._validate_evidence_refs(
                evidence_refs,
                require_trusted=False,
            )
            await self._complete_owned_work(
                node_id,
                evidence_refs=evidence_refs,
            )
            await self.coordinator.finish_node(
                node_id,
                summary=str(action.payload["summary"]),
                evidence_refs=evidence_refs,
            )
            return self._result(
                node_id,
                WorkerStepKind.FINISHED,
                reason="node_finished",
                action_kind=action.kind,
            )
        if action.kind is GraphActionKind.SUBMIT_PROOF:
            if (
                graph_mission_from_state(self.coordinator.state)
                is GraphMission.VULNERABILITY_ASSESSMENT
            ):
                reason = "proof_submission_unavailable_for_vulnerability_assessment"
                await self._append_feedback(node_id, reason)
                return self._result(
                    node_id,
                    WorkerStepKind.ACTION_REJECTED,
                    reason=reason,
                    action_kind=action.kind,
                )
            return await self._submit_proof(node_id, action)
        message = f"unsupported worker action: {action.kind.value}"
        raise GraphProtocolError(message)

    async def _execute_action(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        node_id: str,
        action: GraphWorkerAction,
    ) -> WorkerStepResult:
        self.assert_owned("execute_action_start")
        tool = str(action.payload["tool"])
        raw_arguments = action.payload["arguments"]
        if not isinstance(raw_arguments, Mapping):
            message = "validated execute arguments unexpectedly changed type"
            raise GraphProtocolError(message)
        arguments = {str(key): value for key, value in raw_arguments.items()}
        runtime = self.runtime_resolver.resolve(self.coordinator.state.nodes[node_id])
        if not runtime.allows_tool(tool):
            await self._append_feedback(
                node_id,
                f"action_rejected_before_tool:tool_policy_denied:{tool}",
            )
            return self._result(
                node_id,
                WorkerStepKind.ACTION_REJECTED,
                reason=f"tool_policy_denied:{tool}",
                action_kind=action.kind,
            )
        try:
            if self.action_guard is not None:
                self.action_guard(node_id, tool, arguments)
        except GraphActionRejectedError as exc:
            await self._append_feedback(
                node_id,
                f"action_rejected_before_tool:{exc}",
            )
            return self._result(
                node_id,
                WorkerStepKind.ACTION_REJECTED,
                reason=str(exc),
                action_kind=action.kind,
            )

        semantic_fingerprint = self.scheduler.action_fingerprint(node_id, action)
        durable_action_key = ""
        if self.run_store is not None and self.run_lease is not None:
            durable_action_key = _durable_action_key(
                graph_id=self.coordinator.state.graph_id,
                node_id=node_id,
                semantic_fingerprint=semantic_fingerprint,
            )
            self.assert_owned("durable_action_reservation")
            try:
                reservation = await asyncio.to_thread(
                    self.run_store.reserve_action,
                    self.run_lease,
                    action_key=durable_action_key,
                    node_id=node_id,
                    request=_durable_action_request(
                        graph_id=self.coordinator.state.graph_id,
                        node_id=node_id,
                        semantic_fingerprint=semantic_fingerprint,
                        tool=tool,
                        arguments=arguments,
                        runtime_binding_id=runtime.binding_id,
                        expected_signal=str(action.payload["expected_signal"]),
                    ),
                )
            except RunStoreError as exc:
                message = f"durable_action_reservation_failed:{type(exc).__name__}"
                raise GraphDurabilityError(message) from exc
            if reservation.action.lifecycle is not ActionLifecycle.RESERVED:
                raise GraphDurabilityError(_durable_replay_rejection(reservation.action.lifecycle))

        ticket: InvestigationTicket | None = None
        try:
            if self.investigation_engine is not None:
                self.assert_owned("investigation_authorization")
                ticket = await asyncio.to_thread(
                    self.investigation_engine.authorize_action,
                    node_id=node_id,
                    objective=self.coordinator.state.nodes[node_id].objective,
                    tool=tool,
                    arguments=arguments,
                    hypothesis=self.coordinator.state.nodes[node_id].hypothesis,
                )
        except GraphActionRejectedError as exc:
            await self._cancel_durable_reservation(
                durable_action_key,
                reason="investigation_authorization_rejected",
            )
            await self._append_feedback(
                node_id,
                f"action_rejected_before_tool:{exc}",
            )
            return self._result(
                node_id,
                WorkerStepKind.ACTION_REJECTED,
                reason=str(exc),
                action_kind=action.kind,
            )
        except BaseException as exc:
            await self._cancel_prestart_reservation_after_failure(
                durable_action_key,
                reason="investigation_authorization_failed",
                cause=exc,
            )
            raise
        try:
            self.assert_owned("scheduler_action_registration")
            registered_fingerprint = await self.scheduler.register_action(node_id, action)
            _assert_matching_action_fingerprint(
                expected=semantic_fingerprint,
                registered=registered_fingerprint,
            )
            self.assert_owned("tool_call_registration")
            call_id = await self.coordinator.begin_tool_call(node_id)
        except BaseException as exc:
            await self._cancel_prestart_reservation_after_failure(
                durable_action_key,
                reason="pre_execution_control_plane_failed",
                cause=exc,
            )
            if ticket is not None and self.investigation_engine is not None:
                await asyncio.to_thread(
                    self.investigation_engine.cancel_action,
                    ticket,
                )
            if (
                isinstance(exc, Exception)
                and not isinstance(exc, GraphDurabilityError)
                and self.coordinator.state.race_lost(node_id)
            ):
                group = self.coordinator.state.race_group_for(node_id)
                if group is not None:
                    await self.coordinator.retire_settled_race_losers(group.group_id)
                await self._append_feedback(node_id, "race_lost_before_external_execution")
                return self._result(
                    node_id,
                    WorkerStepKind.RACE_LOST,
                    reason="validated_evidence_race_lost",
                    action_kind=action.kind,
                )
            raise
        execution_arguments = dict(arguments)
        if ticket is not None and tool == "run_probe":
            execution_arguments[GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT] = (
                ticket.effort.target_request_limit
            )
        progress_batch: ValidatedProgressBatch | None = None
        race_claim_status: RaceClaimStatus | None = None
        race_group_id = ""
        race_lost = False
        result: GraphToolResult | None = None
        durable_started = False
        durable_settled = False
        try:
            async with self._execution_lock:
                race_lost = self.coordinator.state.race_lost(node_id)
                if not race_lost:
                    self.assert_owned("external_effect")
                    if (
                        self.run_store is not None
                        and self.run_lease is not None
                        and durable_action_key
                    ):
                        try:
                            durable_start = await asyncio.to_thread(
                                self.run_store.start_action,
                                self.run_lease,
                                action_key=durable_action_key,
                            )
                        except RunStoreError as exc:
                            message = f"durable_action_start_failed:{type(exc).__name__}"
                            raise GraphDurabilityError(message) from exc
                        else:
                            durable_started = durable_start.should_execute
                            if not durable_start.should_execute:
                                raise GraphDurabilityError(
                                    _durable_replay_rejection(durable_start.action.lifecycle)
                                    or "durable_action_start_rejected"
                                )
                    if durable_started or self.run_store is None:
                        result = _validated_tool_result(
                            await runtime.execute(
                                node_id,
                                tool,
                                execution_arguments,
                            )
                        )
                        allow_routed_pivot = _validate_routed_counterfactual(result)
                        if result.progress_receipts:
                            node = self.coordinator.state.nodes[node_id]
                            target_identity = str(
                                getattr(self.evidence_validator, "target_identity", "")
                            ).strip()
                            binding = GraphProgressBinding(
                                graph_id=self.coordinator.state.graph_id,
                                target_identity=target_identity or "unavailable-target",
                                tool_call_id=call_id,
                                runtime_binding_id=runtime.binding_id,
                                node_id=node_id,
                                objective_fingerprint=node.objective.fingerprint,
                                hypothesis_fingerprint=(
                                    node.hypothesis.fingerprint
                                    if node.hypothesis is not None
                                    else ""
                                ),
                                agent_spec_fingerprint=node.agent_spec.fingerprint,
                            )
                            progress_batch = validate_progress_receipt_batch(
                                result.progress_receipts,
                                result_evidence_refs=result.evidence_refs,
                                evidence_validator=self.evidence_validator,
                                binding=binding,
                                counterfactual_objective_fingerprint=(
                                    result.counterfactual_objective_fingerprint
                                ),
                                allow_routed_pivot=allow_routed_pivot,
                            )
                            result = replace(
                                result,
                                progress_receipts=(
                                    *progress_batch.trusted_receipts,
                                    *progress_batch.ignored_untrusted_receipts,
                                ),
                            )
                        if (
                            self.run_store is not None
                            and self.run_lease is not None
                            and durable_action_key
                        ):
                            await asyncio.to_thread(
                                self.run_store.settle_action,
                                self.run_lease,
                                action_key=durable_action_key,
                                result=_durable_tool_result_payload(
                                    result,
                                    progress_batch=progress_batch,
                                ),
                            )
                            durable_settled = True
                            self.assert_owned("settled_tool_result_application")
                        if progress_batch is not None:
                            race_group = self.coordinator.state.race_group_for(node_id)
                            if (
                                race_group is not None
                                and not race_group.winner_node_id
                                and progress_batch.trusted_receipts
                                and progress_batch.classification is not ProgressBatchClass.PROOF
                            ):
                                claim = await self.coordinator.claim_race_progress(
                                    node_id=node_id,
                                    validation_digest=progress_batch.validation_digest,
                                    evidence_refs=progress_batch.evidence_refs,
                                )
                                race_group_id = claim.group_id
                                race_claim_status = claim.status
                                race_lost = claim.status is RaceClaimStatus.LOST
        except asyncio.CancelledError:
            if (
                durable_started
                and not durable_settled
                and self.run_store is not None
                and self.run_lease is not None
            ):
                try:
                    await asyncio.shield(
                        asyncio.to_thread(
                            self.run_store.mark_unknown_outcome,
                            self.run_lease,
                            action_key=durable_action_key,
                            reason="worker_cancelled_after_external_action_started",
                        )
                    )
                except RunStoreError as recovery_exc:
                    message = f"durable_unknown_transition_failed:{type(recovery_exc).__name__}"
                    raise GraphDurabilityError(message) from recovery_exc
            raise
        except Exception as exc:
            if durable_settled:
                message = "durable_action_settled_but_unapplied"
                raise GraphDurabilityError(message) from exc
            if (
                durable_started
                and not durable_settled
                and self.run_store is not None
                and self.run_lease is not None
            ):
                try:
                    await asyncio.to_thread(
                        self.run_store.mark_unknown_outcome,
                        self.run_lease,
                        action_key=durable_action_key,
                        reason="executor_or_validation_failed",
                    )
                except RunStoreError as recovery_exc:
                    message = f"durable_unknown_transition_failed:{type(recovery_exc).__name__}"
                    raise GraphDurabilityError(message) from recovery_exc
                message = "durable_action_outcome_unknown"
                raise GraphDurabilityError(message) from exc
            if isinstance(exc, GraphDurabilityError):
                raise
            await self.coordinator.complete_tool_call(
                node_id,
                call_id=call_id,
            )
            loop_decision = None
            if ticket is not None and self.investigation_engine is not None:
                loop_decision = await asyncio.to_thread(
                    self.investigation_engine.record_tool_failure,
                    ticket,
                    reason=f"{type(exc).__name__}:{exc}",
                )
            await self._append_feedback(
                node_id,
                f"tool_failed:{type(exc).__name__}:{exc}",
            )
            return self._result(
                node_id,
                WorkerStepKind.TOOL_FAILED,
                reason=f"tool_failed:{type(exc).__name__}",
                action_kind=action.kind,
                loop_decision=loop_decision,
            )
        self.assert_owned("tool_call_completion")
        await self.coordinator.complete_tool_call(node_id, call_id=call_id)
        if race_lost:
            if result is None:
                await self._cancel_durable_reservation(
                    durable_action_key,
                    reason="race_lost_before_external_execution",
                )
            if ticket is not None and self.investigation_engine is not None:
                await asyncio.to_thread(
                    self.investigation_engine.cancel_action,
                    ticket,
                )
            group = self.coordinator.state.race_group_for(node_id)
            if group is not None:
                await self.coordinator.retire_settled_race_losers(group.group_id)
            await self._append_feedback(node_id, "race_lost_before_state_mutation")
            race_result = self._result(
                node_id,
                WorkerStepKind.RACE_LOST,
                reason="validated_evidence_race_lost",
                action_kind=action.kind,
            )
            if result is not None:
                await self._mark_durable_action_applied(
                    durable_action_key,
                    result=result,
                    disposition=race_result.kind.value,
                )
            return race_result
        if result is None:
            message = "graph tool result missing after settled execution"
            raise RuntimeError(message)
        await asyncio.to_thread(
            self.sessions.append,
            node_id,
            role=SessionRole.TOOL,
            content=result.output,
        )
        if race_claim_status in {RaceClaimStatus.WON, RaceClaimStatus.ALREADY_WON}:
            await self.coordinator.retire_settled_race_losers(race_group_id)
        if self.coordinator.state.status is not GraphStatus.RUNNING:
            if ticket is not None and self.investigation_engine is not None:
                await asyncio.to_thread(
                    self.investigation_engine.cancel_action,
                    ticket,
                )
            terminal_result = self._result(
                node_id,
                WorkerStepKind.TERMINAL,
                reason=f"graph_{self.coordinator.state.status.value}_after_tool_settlement",
                action_kind=action.kind,
            )
            await self._mark_durable_action_applied(
                durable_action_key,
                result=result,
                disposition=terminal_result.kind.value,
            )
            return terminal_result

        observation_decision = None
        if result.observation_digest.strip():
            observation_decision = await self.scheduler.record_observation(
                node_id,
                digest=result.observation_digest,
            )
        lease_decision = None
        if progress_batch is not None:
            lease_decision = await self.scheduler.apply_progress(
                node_id,
                progress_batch,
            )
        loop_decision = None
        if ticket is not None and self.investigation_engine is not None:
            loop_decision = await asyncio.to_thread(
                self.investigation_engine.record_result,
                ticket,
                objective=self.coordinator.state.nodes[node_id].objective,
                result=result,
                observation_decision=observation_decision,
                hypothesis=self.coordinator.state.nodes[node_id].hypothesis,
                agent_spec=self.coordinator.state.nodes[node_id].agent_spec,
                evidence_epoch=self.coordinator.state.evidence_epoch,
                progress_batch=progress_batch,
            )
            await self._append_feedback(
                node_id,
                "investigation_loop_decision:"
                + json.dumps(
                    loop_decision.to_json(),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
        if (
            lease_decision is not None
            and lease_decision.proof_eligible
            and lease_decision.proof_evidence_refs
            and graph_mission_from_state(self.coordinator.state)
            is GraphMission.FLAG_CAPTURE
        ):
            proof_result = await self._gate_proof(
                node_id,
                lease_decision.proof_evidence_refs,
                action_kind=action.kind,
            )
            await self._mark_durable_action_applied(
                durable_action_key,
                result=result,
                disposition=proof_result.kind.value,
            )
            return proof_result
        await self._notify_parent_progress(
            node_id,
            result.progress_receipts,
        )
        if result.routing_directive is not None:
            routing_result = await self._apply_routing_directive(
                node_id,
                action=action,
                directive=result.routing_directive,
                lease_decision=lease_decision,
                observation_decision=observation_decision,
                loop_decision=loop_decision,
            )
            await self._mark_durable_action_applied(
                durable_action_key,
                result=result,
                disposition=routing_result.kind.value,
            )
            return routing_result
        executed_result = self._result(
            node_id,
            WorkerStepKind.EXECUTED,
            reason="tool_observation_recorded",
            action_kind=action.kind,
            lease_decision=lease_decision,
            observation_decision=observation_decision,
            loop_decision=loop_decision,
        )
        await self._mark_durable_action_applied(
            durable_action_key,
            result=result,
            disposition=executed_result.kind.value,
        )
        return executed_result

    async def _complete_model_turn(
        self,
        node_id: str,
        *,
        messages: list[dict[str, str]],
        request_id: str,
        complete: GraphComplete,
    ) -> tuple[GraphModelReply, str]:
        continuity_retries = 0
        current_request_id = request_id
        while True:
            try:
                reply = _validated_model_reply(await complete(node_id, messages))
            except GraphModelContinuityRequiredError as exc:
                if continuity_retries >= 1:
                    raise
                await self.coordinator.interrupt_model_request(
                    node_id,
                    request_id=current_request_id,
                    reason=str(exc),
                )
                await asyncio.to_thread(
                    self.sessions.append,
                    node_id,
                    role=SessionRole.TOOL,
                    content=(
                        "provider_continuity_receipt:"
                        f"{exc.failure.kind.value}:{exc.from_route}->{exc.to_route}"
                    ),
                )
                current_request_id = await self.coordinator.begin_model_continuity_retry(node_id)
                continuity_retries += 1
            else:
                return reply, current_request_id

    async def try_stall_review(
        self,
        steps: Sequence[WorkerStepResult],
    ) -> bool:
        """Wake one parked worker with a replay-safe, materially distinct bump."""
        self.assert_owned("stall_review")
        directive = select_stall_review(
            self.coordinator.state,
            steps,
        )
        if directive is None:
            return False
        try:
            await self.coordinator.apply_stall_review_lease(
                directive.node_id,
                review_token=directive.token,
                reason=directive.reason,
            )
        except GraphLeaseGrantError:
            return False
        await asyncio.to_thread(
            self.sessions.append,
            directive.node_id,
            role=SessionRole.USER,
            content=directive.prompt(),
        )
        return True

    async def _apply_routing_directive(  # noqa: PLR0913 - explicit route result state.
        self,
        node_id: str,
        *,
        action: GraphWorkerAction,
        directive: GraphRoutingDirective,
        lease_decision: LeaseDecision | None,
        observation_decision: ObservationDecision | None,
        loop_decision: LoopDecision | None,
    ) -> WorkerStepResult:
        self._validate_evidence_refs(
            directive.evidence_refs,
            require_trusted=True,
        )
        child = await self.coordinator.spawn_node(
            parent_id=node_id,
            name=directive.name,
            objective=directive.objective,
            lease_limit=directive.lease_limit,
        )
        if child.agent_spec.session_policy_key != "fresh_typed":
            await asyncio.to_thread(
                inherit_parent_context,
                self.sessions,
                parent_id=node_id,
                child_id=child.node_id,
                objective=directive.objective,
            )
        try:
            await self._claim_work(
                directive.work_id,
                owner_node_id=child.node_id,
            )
        except Exception:
            await self.coordinator.stop_node(
                child.node_id,
                reason="closure_work_claim_failed",
            )
            raise
        if directive.park_source:
            await self.coordinator.park_node(node_id)
        return self._result(
            node_id,
            WorkerStepKind.ROUTED,
            reason=directive.reason,
            action_kind=action.kind,
            spawned_node_id=child.node_id,
            lease_decision=lease_decision,
            observation_decision=observation_decision,
            loop_decision=loop_decision,
        )

    async def _send_action_message(
        self,
        node_id: str,
        action: GraphWorkerAction,
    ) -> None:
        raw_body = action.payload["body"]
        if not isinstance(raw_body, Mapping):
            message = "validated message body unexpectedly changed type"
            raise GraphProtocolError(message)
        evidence_refs = _evidence_refs(action.payload)
        self._validate_evidence_refs(
            evidence_refs,
            require_trusted=False,
        )
        await self.coordinator.send_message(
            sender_id=node_id,
            target_id=str(action.payload["target_id"]),
            kind=action.message_kind(),
            body={str(key): value for key, value in raw_body.items()},
            evidence_refs=evidence_refs,
        )

    async def _notify_parent_progress(
        self,
        node_id: str,
        receipts: tuple[ProgressReceipt, ...],
    ) -> None:
        trusted = tuple(receipt for receipt in receipts if receipt.trusted)
        node = self.coordinator.state.nodes[node_id]
        parent_id = node.parent_id
        if not trusted or parent_id is None:
            return
        parent = self.coordinator.state.nodes[parent_id]
        if parent.status not in ACTIVE_NODE_STATUSES:
            return
        evidence_refs = tuple(sorted({receipt.evidence_ref.strip() for receipt in trusted}))
        try:
            await self.coordinator.send_message(
                sender_id=node_id,
                target_id=parent_id,
                kind=GraphMessageKind.EVIDENCE,
                body={
                    "source_node_id": node_id,
                    "progress_kinds": sorted({receipt.kind.value for receipt in trusted}),
                    "summary": "trusted executor progress is available",
                },
                evidence_refs=evidence_refs,
            )
        except GraphCoordinatorError:
            # Parent lifecycle may close concurrently with sibling tool work.
            return

    async def _extend_for_trusted_inbox(self, node_id: str) -> None:
        """
        Buy one coordination turn only when new executor-owned evidence arrived.

        Messages are deliberately left pending until a model request has been
        secured, so an unavailable lease never discards evidence. Existing node,
        graph, cost, wall-time, and extension limits remain authoritative.
        """
        node = self.coordinator.state.nodes[node_id]
        if node.lease_used < node.lease_limit or self.evidence_validator is None:
            return
        progress_tokens: list[str] = []
        for message in self.coordinator.state.pending_messages(node_id):
            if (
                message.kind
                not in {
                    GraphMessageKind.EVIDENCE,
                    GraphMessageKind.COMPLETION,
                }
                or not message.evidence_refs
            ):
                continue
            try:
                self._validate_evidence_refs(
                    message.evidence_refs,
                    require_trusted=True,
                )
            except GraphProtocolError:
                continue
            progress_tokens.append(f"trusted-inbox:{message.message_id}")
        if not progress_tokens:
            return
        try:
            await self.coordinator.apply_progress_lease(
                node_id,
                progress_tokens=tuple(progress_tokens),
                additional_requests=1,
                proof_eligible=False,
                reason="trusted_inbox_coordination",
            )
        except GraphLeaseGrantError:
            # Normal lease exhaustion handling below remains the terminal arbiter.
            return

    def _validate_evidence_refs(
        self,
        evidence_refs: tuple[str, ...],
        *,
        require_trusted: bool,
    ) -> None:
        if self.evidence_validator is None or not evidence_refs:
            return
        try:
            self.evidence_validator.validate_references(
                evidence_refs,
                require_trusted=require_trusted,
            )
        except Exception as exc:
            message = f"invalid evidence reference: {exc}"
            raise GraphProtocolError(message) from exc

    async def _evidence_context(self) -> dict[str, object]:
        method = getattr(self.context_provider, "context_projection", None)
        if not callable(method):
            return {}
        value = await asyncio.to_thread(method)
        if not isinstance(value, Mapping):
            message = "graph evidence context provider must return a mapping"
            raise TypeError(message)
        return {str(key): item for key, item in value.items()}

    async def _owned_work(self, node_id: str) -> tuple[object, ...]:
        method = getattr(self.evidence_validator, "owned_work_items", None)
        if not callable(method):
            return ()
        value = await asyncio.to_thread(
            method,
            owner_node_id=node_id,
        )
        return tuple(value or ())

    async def _claim_work(
        self,
        work_id: str,
        *,
        owner_node_id: str,
    ) -> None:
        if not work_id:
            return
        method = getattr(self.evidence_validator, "claim_work", None)
        if not callable(method):
            message = "routed closure work requires an ownership ledger"
            raise GraphProtocolError(message)
        try:
            await asyncio.to_thread(
                method,
                work_id=work_id,
                owner_node_id=owner_node_id,
            )
        except Exception as exc:
            message = f"closure work claim failed: {exc}"
            raise GraphProtocolError(message) from exc

    async def _complete_owned_work(
        self,
        node_id: str,
        *,
        evidence_refs: tuple[str, ...],
    ) -> None:
        method = getattr(self.evidence_validator, "complete_owned_work", None)
        if not callable(method):
            return
        try:
            await asyncio.to_thread(
                method,
                owner_node_id=node_id,
                result_evidence_refs=evidence_refs,
            )
        except Exception as exc:
            message = f"closure work settlement failed: {exc}"
            raise GraphProtocolError(message) from exc

    async def _fail_owned_work(
        self,
        node_id: str,
        *,
        reason: str,
    ) -> None:
        method = getattr(self.evidence_validator, "fail_owned_work", None)
        if callable(method):
            await asyncio.to_thread(
                method,
                owner_node_id=node_id,
                reason=reason,
            )

    async def _submit_proof(
        self,
        node_id: str,
        action: GraphWorkerAction,
    ) -> WorkerStepResult:
        return await self._gate_proof(
            node_id,
            _evidence_refs(action.payload),
            action_kind=action.kind,
        )

    async def _gate_proof(
        self,
        node_id: str,
        candidate_refs: tuple[str, ...],
        *,
        action_kind: GraphActionKind,
    ) -> WorkerStepResult:
        verdict = await self.proof_gate(node_id, candidate_refs)
        if not isinstance(verdict, ProofGateResult):
            message = "graph proof gate must return ProofGateResult"
            raise TypeError(message)
        accepted_refs = tuple(
            sorted({item.strip() for item in verdict.evidence_refs if item.strip()})
        )
        if verdict.accepted and accepted_refs:
            await self.coordinator.solve(
                proof_evidence_refs=accepted_refs,
            )
            return self._result(
                node_id,
                WorkerStepKind.PROOF_ACCEPTED,
                reason=verdict.reason or "trusted_proof_accepted",
                action_kind=action_kind,
            )
        await self._append_feedback(
            node_id,
            f"proof_rejected:{verdict.reason or 'proof_gate_rejected'}",
        )
        return self._result(
            node_id,
            WorkerStepKind.PROOF_REJECTED,
            reason=verdict.reason or "proof_gate_rejected",
            action_kind=action_kind,
        )

    async def _append_feedback(self, node_id: str, content: str) -> None:
        await asyncio.to_thread(
            self.sessions.append,
            node_id,
            role=SessionRole.TOOL,
            content=content,
        )

    async def _retire_if_race_loser(
        self,
        node_id: str,
    ) -> WorkerStepResult | None:
        group = self.coordinator.state.race_group_for(node_id)
        if group is None or not self.coordinator.state.race_lost(node_id):
            return None
        await self.coordinator.retire_settled_race_losers(group.group_id)
        return self._result(
            node_id,
            WorkerStepKind.RACE_LOST,
            reason="race_loser_drained_after_model_settlement",
        )

    def assert_owned(self, boundary: str) -> None:
        """Translate ownership uncertainty into a fatal graph durability error."""
        if self.assert_run_owned is None:
            return
        try:
            self.assert_run_owned()
        except GraphDurabilityError:
            raise
        except Exception as exc:
            message = f"run_ownership_unproven:{boundary}:{type(exc).__name__}"
            raise GraphDurabilityError(message) from exc

    def _raise_if_settled_unapplied(self, cause: Exception) -> None:
        if self.run_store is None or self.run_lease is None:
            return
        try:
            gaps = self.run_store.unreconciled_actions(self.run_lease.run_id)
        except RunStoreError as exc:
            message = f"durable_reconciliation_check_failed:{type(exc).__name__}"
            raise GraphDurabilityError(message) from exc
        if any(action.lifecycle is ActionLifecycle.SETTLED for action in gaps):
            message = "durable_action_settled_but_unapplied"
            raise GraphDurabilityError(message) from cause

    async def _cancel_durable_reservation(
        self,
        action_key: str,
        *,
        reason: str,
    ) -> None:
        if self.run_store is None or self.run_lease is None or not action_key:
            return
        self.assert_owned("durable_reservation_cancellation")
        try:
            await asyncio.to_thread(
                self.run_store.cancel_reserved_action,
                self.run_lease,
                action_key=action_key,
                reason=reason,
            )
        except RunStoreError as exc:
            message = f"durable_reservation_cancellation_failed:{type(exc).__name__}"
            raise GraphDurabilityError(message) from exc

    async def _cancel_prestart_reservation_after_failure(
        self,
        action_key: str,
        *,
        reason: str,
        cause: BaseException,
    ) -> None:
        if self.run_store is None or self.run_lease is None or not action_key:
            return
        cleanup = asyncio.create_task(self._cancel_durable_reservation(action_key, reason=reason))
        try:
            await asyncio.shield(cleanup)
        except GraphDurabilityError as exc:
            raise exc from cause
        except asyncio.CancelledError:
            message = "durable_reservation_cancellation_interrupted"
            raise GraphDurabilityError(message) from cause

    async def _mark_durable_action_applied(
        self,
        action_key: str,
        *,
        result: GraphToolResult,
        disposition: str,
    ) -> None:
        if self.run_store is None or self.run_lease is None or not action_key:
            return
        self.assert_owned("durable_action_application")
        investigation = (
            await asyncio.to_thread(self.investigation_engine.summary)
            if self.investigation_engine is not None
            else None
        )
        state_digest = _canonical_digest(
            {
                "graph": self.coordinator.state.to_json(),
                "investigation": investigation,
            }
        )
        try:
            await asyncio.to_thread(
                self.run_store.mark_action_applied,
                self.run_lease,
                action_key=action_key,
                state_digest=state_digest,
                evidence_refs=result.evidence_refs,
                disposition=disposition,
            )
        except RunStoreError as exc:
            message = f"durable_action_application_failed:{type(exc).__name__}"
            raise GraphDurabilityError(message) from exc

    @staticmethod
    def _result(  # noqa: PLR0913 - explicit immutable result construction.
        node_id: str,
        kind: WorkerStepKind,
        *,
        reason: str,
        action_kind: GraphActionKind | None = None,
        spawned_node_id: str | None = None,
        lease_decision: LeaseDecision | None = None,
        observation_decision: ObservationDecision | None = None,
        loop_decision: LoopDecision | None = None,
    ) -> WorkerStepResult:
        return WorkerStepResult(
            node_id=node_id,
            kind=kind,
            reason=reason,
            action_kind=action_kind,
            spawned_node_id=spawned_node_id,
            lease_decision=lease_decision,
            observation_decision=observation_decision,
            loop_decision=loop_decision,
        )


class GraphRunner:
    """Schedule independent node turns under coordinator concurrency limits."""

    def __init__(
        self,
        worker: GraphWorker,
        *,
        dispatch_planner: GraphDispatchPlanner | None = None,
    ) -> None:
        self.worker = worker
        self.coordinator = worker.coordinator
        beliefs = (
            worker.investigation_engine.beliefs if worker.investigation_engine is not None else None
        )
        self.dispatch_planner = dispatch_planner or GraphDispatchPlanner(beliefs)

    async def run(self) -> GraphRunResult:  # noqa: C901 - explicit failure arbitration.
        tasks: dict[str, asyncio.Task[WorkerStepResult]] = {}
        steps: list[WorkerStepResult] = []
        try:
            while self.coordinator.state.status is GraphStatus.RUNNING:
                self.worker.assert_owned("graph_runner_iteration")
                await self._start_ready_nodes()
                for node in self.coordinator.state.running_nodes:
                    if node.node_id not in tasks:
                        tasks[node.node_id] = asyncio.create_task(self.worker.step(node.node_id))
                if not tasks:
                    if await self.worker.try_stall_review(tuple(steps)):
                        continue
                    await self.coordinator.stop_graph(
                        status=GraphStatus.EXHAUSTED,
                        reason="graph_deadlock_no_runnable_nodes",
                    )
                    break

                done, _ = await asyncio.wait(
                    tuple(tasks.values()),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    node_id = next(
                        identifier for identifier, candidate in tasks.items() if candidate is task
                    )
                    del tasks[node_id]
                    try:
                        steps.append(task.result())
                        await self._yield_settled_turn(node_id)
                    except asyncio.CancelledError:
                        raise
                    except GraphDurabilityError:
                        raise
                    except Exception as exc:  # noqa: BLE001 - graph crash receipt.
                        node = self.coordinator.state.nodes[node_id]
                        if (
                            self.coordinator.state.status is GraphStatus.RUNNING
                            and node.status in ACTIVE_NODE_STATUSES
                        ):
                            await self.coordinator.mark_crashed(
                                node_id,
                                reason=(f"unhandled_worker_error:{type(exc).__name__}:{exc}"),
                            )
                        steps.append(
                            WorkerStepResult(
                                node_id=node_id,
                                kind=WorkerStepKind.CRASHED,
                                reason=f"unhandled_worker_error:{type(exc).__name__}",
                            )
                        )
        finally:
            await self._settle_remaining_tasks(tasks, steps)
        return GraphRunResult(
            status=self.coordinator.state.status,
            reason=self.coordinator.state.last_reason,
            steps=tuple(steps),
        )

    async def _settle_remaining_tasks(
        self,
        tasks: dict[str, asyncio.Task[WorkerStepResult]],
        steps: list[WorkerStepResult],
    ) -> None:
        if not tasks:
            return
        if self.coordinator.state.status is GraphStatus.SOLVED:
            settled = await asyncio.gather(
                *tasks.values(),
                return_exceptions=True,
            )
            durability_failure = next(
                (outcome for outcome in settled if isinstance(outcome, GraphDurabilityError)),
                None,
            )
            if durability_failure is not None:
                raise durability_failure
            steps.extend(outcome for outcome in settled if isinstance(outcome, WorkerStepResult))
            await self.coordinator.reconcile_interrupted_work()
            return
        for task in tasks.values():
            task.cancel()
        settled = await asyncio.gather(
            *tasks.values(),
            return_exceptions=True,
        )
        durability_failure = next(
            (outcome for outcome in settled if isinstance(outcome, GraphDurabilityError)),
            None,
        )
        if durability_failure is not None:
            raise durability_failure

    async def _yield_settled_turn(self, node_id: str) -> None:
        """Make dispatch priority effective after every accounted worker turn."""
        state = self.coordinator.state
        if state.status is not GraphStatus.RUNNING:
            return
        node = state.nodes[node_id]
        if (
            node.status is GraphNodeStatus.RUNNING
            and node.pending_model_request_id is None
            and node.pending_tool_call_id is None
        ):
            await self.coordinator.yield_node_turn(node_id)

    async def _start_ready_nodes(self) -> None:
        state = self.coordinator.state
        ready = tuple(node for node in state.nodes.values() if node.status is GraphNodeStatus.READY)
        available = self.coordinator.state.limits.max_concurrent_nodes - len(
            self.coordinator.state.running_nodes
        )
        if available <= 0:
            return

        # An admitted race is one scheduling unit: when all lanes are initially
        # ready, do not let an unrelated high-utility node consume one of the
        # slots and turn the race into sequential execution. Once any lane is
        # already running or terminal, fill whatever capacity remains normally.
        selected: list[GraphNode] = []
        selected_ids: set[str] = set()
        deferred_race_ids: set[str] = set()
        for group in sorted(state.race_groups.values(), key=lambda item: item.group_id):
            if group.winner_node_id:
                continue
            members = tuple(state.nodes[node_id] for node_id in group.member_node_ids)
            ready_members = tuple(node for node in members if node.status is GraphNodeStatus.READY)
            if not ready_members:
                continue
            race_started = any(node.status is not GraphNodeStatus.READY for node in members)
            if not race_started and len(ready_members) > available:
                deferred_race_ids.update(node.node_id for node in ready_members)
                continue
            admitted = self.dispatch_planner.rank(ready_members)[:available]
            selected.extend(admitted)
            selected_ids.update(node.node_id for node in admitted)
            available -= len(admitted)
            if available == 0:
                break

        if available:
            ordinary = self.dispatch_planner.rank(
                node
                for node in ready
                if node.node_id not in selected_ids and node.node_id not in deferred_race_ids
            )
            selected.extend(ordinary[:available])
        for node in selected:
            await self.coordinator.start_node(node.node_id)


def _worker_context(  # noqa: PLR0913 - explicit typed context sections.
    *,
    coordinator: GraphCoordinator,
    node_id: str,
    inbox: Sequence[dict[str, object]],
    evidence_context: Mapping[str, object],
    investigation_context: Mapping[str, object],
    budget_directive: GraphBudgetDirective,
) -> str:
    state = coordinator.state
    node = state.nodes[node_id]
    exploration_ceiling = (
        state.limits.max_model_requests - state.limits.proof_reserve_model_requests
    )
    payload = {
        "node": {
            "node_id": node.node_id,
            "parent_id": node.parent_id,
            "name": node.name,
            "objective": node.objective.to_json(),
            "agent_spec": node.agent_spec.to_json(),
            "hypothesis": (node.hypothesis.to_json() if node.hypothesis is not None else None),
            "lease_remaining": node.lease_limit - node.lease_used,
            "proof_eligible": node.proof_eligible,
        },
        "graph": {
            "status": state.status.value,
            "model_requests_remaining": (
                state.limits.max_model_requests - state.model_requests_started
            ),
            "exploration_requests_remaining": max(
                exploration_ceiling - state.model_requests_started,
                0,
            ),
            "proof_reserve": state.limits.proof_reserve_model_requests,
            "active_nodes": [
                {
                    "node_id": candidate.node_id,
                    "parent_id": candidate.parent_id,
                    "name": candidate.name,
                    "status": candidate.status.value,
                }
                for candidate in state.active_nodes
            ],
            "evidence_epoch": state.evidence_epoch,
            "budget_phase": budget_directive.to_json(),
        },
        "inbox": list(inbox),
        "evidence_blackboard": dict(evidence_context),
        "investigation": dict(investigation_context),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _worker_system_prompt(
    objective: GraphObjective,
    *,
    agent_spec: AgentSpec,
    hypothesis: Hypothesis | None,
    investigation_enabled: bool = False,
    flag_objective: bool = True,
) -> str:
    investigation = (
        " The investigation controller supplies ranked finite campaigns, coverage "
        "gaps, and failure certificates in each user context. Prefer its first "
        "campaign. After failure, change the required material dimension; do not "
        "rephrase the same payload loop."
        if investigation_enabled
        else ""
    )
    role_guidance = {
        GraphAgentRole.COORDINATOR: (
            "Coordinate distinct hypotheses, critics, and closure owners; do not "
            "duplicate a child campaign."
            if flag_objective
            else "Coordinate distinct vulnerability hypotheses and validation owners. "
            "Finish after every seeded route has a confirmed finding or bounded "
            "negative coverage; do not duplicate a child campaign."
        ),
        GraphAgentRole.DISCOVERY: (
            "Generate a small number of distinct, falsifiable vulnerability "
            "hypotheses and choose the cheapest discriminating test."
        ),
        GraphAgentRole.CRITIC: (
            "Try to falsify the assigned hypothesis from authoritative evidence. "
            + (
                "Critic approval means testable, not true, and cannot create proof."
                if flag_objective
                else "Critic approval means testable, not true, and cannot create a finding."
            )
        ),
        GraphAgentRole.EXPLOITATION: (
            "Convert an evidence-supported primitive into the shortest bounded "
            "exploit and protected readback."
        ),
        GraphAgentRole.VALIDATOR: (
            "Independently replay the claimed transition with controls and produce "
            "executor-owned confirmation or disproof."
        ),
        GraphAgentRole.SPECIALIST: (
            "Work depth-first on the assigned falsifiable hypothesis and change a "
            "material dimension after counter-evidence."
        ),
    }[agent_spec.role]
    hypothesis_guidance = (
        " The authoritative context contains a typed hypothesis. Seek both "
        f"support ({hypothesis.support_signal}) and falsification "
        f"({hypothesis.falsification_signal}); never turn model confidence into evidence."
        if hypothesis is not None
        else ""
    )
    action_kinds = "execute|spawn|message|wait|handoff|finish"
    proof_contract = ""
    if flag_objective:
        action_kinds += "|submit_proof"
        proof_contract = (
            'submit_proof={"evidence_refs":[str]}. '
            "Model statements are not evidence. submit_proof must reference "
            "target-observed evidence that the proof gate can replay. "
        )
    else:
        proof_contract = (
            "Model statements are not evidence. Confirmed findings must come from "
            "executor-owned validation. Finish with finding evidence refs or bounded "
            "coverage evidence refs. "
        )
    return (
        "You are one bounded worker in an authorized security-testing graph. "
        f"Trusted role: {agent_spec.role.value}. {role_guidance}" + hypothesis_guidance + " "
        "Return exactly one JSON object and no prose. The object must use "
        f'{{"kind":"{action_kinds}",'
        '"payload":{...},"rationale":"..."}. '
        "Payload contracts are exact: "
        'execute={"tool":str,"arguments":object,"expected_signal":str}; '
        'spawn={"name":str,"lease_limit":positive_int,"objective":object,'
        '"hypothesis":{"claim":str,"support_signal":str,'
        '"falsification_signal":str,"next_discriminating_test":str,'
        '"required_capabilities":[str],"basis_evidence_refs":[str]}}; '
        'message={"target_id":"node-NNN","body":object,'
        '"evidence_refs":[str],"message_kind":"information|query|instruction|evidence"}; '
        "handoff uses the message fields plus summary=str; "
        'wait={"timeout_seconds":non_negative_number}; '
        'finish={"summary":str,"evidence_refs":[str]}; '
        "A message target_id is a graph node ID from active_nodes, never the "
        "blackboard target_identity. "
        "Do not repeat a tool effect. Spawn only a materially distinct task. "
        + proof_contract
        + specialist_system_guidance(objective)
        + investigation
    )


def _evidence_refs(payload: Mapping[str, object]) -> tuple[str, ...]:
    raw = payload.get("evidence_refs", ())
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(sorted({item.strip() for item in raw if isinstance(item, str) and item.strip()}))


def _validated_spawn_lease_limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        message = "validated spawn lease unexpectedly changed type"
        raise GraphProtocolError(message)
    return value


def _bounded_wait_timeout(value: object, *, maximum: float) -> float:
    if value is None:
        return maximum
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        message = "validated wait timeout unexpectedly changed type"
        raise GraphProtocolError(message)
    return min(float(value), maximum)


def _validated_model_reply(value: object) -> GraphModelReply:
    if not isinstance(value, GraphModelReply):
        message = "graph model callable must return GraphModelReply"
        raise TypeError(message)
    return value


def _validate_routed_counterfactual(result: GraphToolResult) -> bool:
    directive = result.routing_directive
    if directive is None:
        return False
    routed_objective = directive.objective.fingerprint
    supplied_counterfactual = " ".join(result.counterfactual_objective_fingerprint.strip().split())
    if supplied_counterfactual != routed_objective:
        message = "routing directive does not match its counterfactual objective"
        raise GraphProtocolError(message)
    return True


def _validated_tool_result(value: object) -> GraphToolResult:
    if not isinstance(value, GraphToolResult):
        message = "graph tool callable must return GraphToolResult"
        raise TypeError(message)
    return value


def _assert_matching_action_fingerprint(*, expected: str, registered: str) -> None:
    if registered != expected:
        message = "scheduler_action_fingerprint_changed"
        raise GraphDurabilityError(message)


def _durable_action_key(
    *,
    graph_id: str,
    node_id: str,
    semantic_fingerprint: str,
) -> str:
    """Identify one node-local external effect independently of process lifetime."""
    return f"tool:{graph_id}:{node_id}:{semantic_fingerprint}"


def _durable_action_request(  # noqa: PLR0913 - persisted effect identity is explicit.
    *,
    graph_id: str,
    node_id: str,
    semantic_fingerprint: str,
    tool: str,
    arguments: Mapping[str, object],
    runtime_binding_id: str,
    expected_signal: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "graph_id": graph_id,
        "node_id": node_id,
        "semantic_fingerprint": semantic_fingerprint,
        "tool": tool,
        "arguments_sha256": _canonical_digest(dict(arguments)),
        "runtime_binding_id": runtime_binding_id,
        "expected_signal_sha256": _canonical_digest(expected_signal),
    }


def _durable_replay_rejection(lifecycle: ActionLifecycle) -> str:
    return {
        ActionLifecycle.RESERVED: "",
        ActionLifecycle.STARTED: "durable_action_in_flight",
        ActionLifecycle.SETTLED: "durable_action_already_settled",
        ActionLifecycle.UNKNOWN_OUTCOME: "durable_action_unknown_outcome",
        ActionLifecycle.CANCELLED: "durable_action_cancelled",
    }[lifecycle]


def _durable_tool_result_payload(
    result: GraphToolResult,
    *,
    progress_batch: ValidatedProgressBatch | None,
) -> dict[str, object]:
    directive = result.routing_directive
    return {
        "schema_version": 1,
        "status": "settled",
        "output_sha256": _canonical_digest(result.output),
        "output_chars": len(result.output),
        "observation_sha256": _canonical_digest(result.observation_digest),
        "evidence_refs": list(result.evidence_refs),
        "target_requests": result.target_requests,
        "counterfactual_objective_fingerprint": (result.counterfactual_objective_fingerprint),
        "progress_receipts": [
            {
                "kind": receipt.kind.value,
                "evidence_ref": receipt.evidence_ref,
                "source": receipt.source.value,
                "binding_sha256": (
                    _canonical_digest(receipt.binding.to_json())
                    if receipt.binding is not None
                    else ""
                ),
            }
            for receipt in result.progress_receipts
        ],
        "progress_validation_digest": (
            progress_batch.validation_digest if progress_batch is not None else ""
        ),
        "routing_directive": (
            {
                "objective_fingerprint": directive.objective.fingerprint,
                "evidence_refs": list(directive.evidence_refs),
                "work_id": directive.work_id,
                "lease_limit": directive.lease_limit,
                "park_source": directive.park_source,
            }
            if directive is not None
            else None
        ),
    }


def _canonical_digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        message = "durable action value must be canonical JSON"
        raise ValueError(message) from exc
    return hashlib.sha256(payload.encode()).hexdigest()


__all__ = [
    "GraphComplete",
    "GraphDurabilityError",
    "GraphExecute",
    "GraphModelReply",
    "GraphProofGate",
    "GraphRunResult",
    "GraphRunner",
    "GraphToolResult",
    "GraphWorker",
    "ProofGateResult",
    "WorkerStepKind",
    "WorkerStepResult",
]
