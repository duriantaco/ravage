# Invariant-specific lifecycle errors deliberately carry their call-site context.
# ruff: noqa: EM101, EM102, TRY003


from __future__ import annotations

import asyncio
import json
import math
import time
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.models import (
    ACTIVE_NODE_STATUSES,
    MAX_RACE_LANES,
    MIN_RACE_LANES,
    TERMINAL_GRAPH_STATUSES,
    AgentSpec,
    GraphAgentRole,
    GraphLimits,
    GraphMessage,
    GraphMessageKind,
    GraphNode,
    GraphNodeStatus,
    GraphObjective,
    GraphRaceGroup,
    GraphRaceLane,
    GraphState,
    GraphStatus,
    Hypothesis,
    RaceClaimDecision,
    RaceClaimStatus,
)
from ravage.agent_core.autonomous_graph.mission import (
    GraphMission,
    graph_mission_from_state,
)
from ravage.agent_core.autonomous_graph.objective_ownership import (
    exclusive_objective_owner_key,
)
from ravage.agent_core.autonomous_graph.provider_continuity import (
    MAX_PROVIDER_CONTINUITY_RETRIES_PER_NODE,
)
from ravage.agent_core.autonomous_graph.stall_review import (
    MAX_STALL_REVIEWS_PER_GRAPH,
    MAX_STALL_REVIEWS_PER_NODE,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path


class GraphCoordinatorError(RuntimeError):
    """Base error for graph coordination failures."""


class DuplicateGraphObjectiveError(GraphCoordinatorError):
    """Raised before spending budget on a duplicate route-wide objective."""


class GraphNodeLimitError(GraphCoordinatorError):
    """Raised when the route-wide node cap has been reached."""


class GraphConcurrencyLimitError(GraphCoordinatorError):
    """Raised when no graph execution slot is available."""


class GraphLifecycleError(GraphCoordinatorError):
    """Raised when an operation violates the graph lifecycle."""


class GraphBudgetExceededError(GraphCoordinatorError):
    """Raised when a code-enforced route budget blocks new work."""


class GraphLeaseExhaustedError(GraphBudgetExceededError):
    """Raised when a node has consumed its current progressive lease."""


class GraphLeaseGrantError(GraphCoordinatorError):
    """Raised when evidence cannot authorize a bounded lease extension."""


class RepeatedGraphActionError(GraphCoordinatorError):
    """Raised before a semantically repeated tool action can spend budget."""


class UnknownGraphNodeError(GraphCoordinatorError):
    """Raised when an operation references a node outside this graph."""


class GraphCoordinator:
    """Own graph mutation, accounting, inboxes, snapshots, and resume."""

    def __init__(
        self,
        state: GraphState,
        *,
        state_path: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        state.validate()
        self.state = state
        self.state_path = state_path
        self._clock = clock
        self._lock = asyncio.Lock()
        self._wake_events = {node_id: asyncio.Event() for node_id in self.state.nodes}

    @classmethod
    def start(  # noqa: PLR0913 - explicit durable graph construction boundary.
        cls,
        *,
        graph_id: str,
        root_objective: GraphObjective,
        limits: GraphLimits | None = None,
        root_name: str = "coordinator",
        root_lease_limit: int = 2,
        root_agent_spec: AgentSpec | None = None,
        root_hypothesis: Hypothesis | None = None,
        state_path: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> GraphCoordinator:
        graph_limits = limits or GraphLimits()
        if not 0 < root_lease_limit <= graph_limits.max_node_lease:
            message = "root_lease_limit must be positive and no larger than max_node_lease"
            raise GraphLifecycleError(message)
        root = GraphNode(
            node_id="node-001",
            parent_id=None,
            name=root_name,
            objective=root_objective,
            status=GraphNodeStatus.RUNNING,
            lease_limit=root_lease_limit,
            agent_spec=(
                root_agent_spec
                if root_agent_spec is not None
                else AgentSpec.for_objective(root_objective, is_root=True)
            ),
            hypothesis=root_hypothesis,
        )
        state = GraphState(
            graph_id=graph_id,
            root_node_id=root.node_id,
            limits=graph_limits,
            created_at_epoch=clock(),
            nodes={root.node_id: root},
            next_node_sequence=2,
        )
        coordinator = cls(state, state_path=state_path, clock=clock)
        coordinator._persist_unlocked()
        return coordinator

    @classmethod
    def load(
        cls,
        state_path: Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> GraphCoordinator:
        """Load a snapshot and charge any work interrupted by process loss."""
        coordinator = cls(
            GraphState.load(state_path),
            state_path=state_path,
            clock=clock,
        )
        has_pending_work = any(
            node.pending_model_request_id is not None or node.pending_tool_call_id is not None
            for node in coordinator.state.nodes.values()
        )
        if coordinator.state.status is GraphStatus.RUNNING or has_pending_work:
            changed = coordinator._reconcile_interrupted_work_unlocked()
            if changed:
                if coordinator.state.status is GraphStatus.RUNNING:
                    coordinator.state.last_reason = "interrupted_work_reconciled_on_resume"
                coordinator._persist_unlocked()
        return coordinator

    async def snapshot(self) -> GraphState:
        """Return a validated detached copy of current state."""
        async with self._lock:
            return GraphState.from_json(self.state.to_json())

    async def bind_state_path(self, state_path: Path) -> None:
        """Publish a fully constructed in-memory graph as one atomic snapshot."""
        async with self._lock:
            if self.state_path is not None:
                raise GraphLifecycleError("graph coordinator already has a state path")
            if state_path.exists():  # noqa: ASYNC240 - one atomic publication boundary.
                raise GraphLifecycleError("graph state path already exists")
            self.state_path = state_path
            self._persist_unlocked()

    async def spawn_node(  # noqa: PLR0913 - trusted identity fields are explicit.
        self,
        *,
        parent_id: str,
        name: str,
        objective: GraphObjective,
        lease_limit: int = 2,
        agent_spec: AgentSpec | None = None,
        hypothesis: Hypothesis | None = None,
    ) -> GraphNode:
        async with self._lock:
            self._require_running_graph_unlocked()
            parent = self._node_unlocked(parent_id)
            if parent.status not in ACTIVE_NODE_STATUSES:
                message = f"cannot spawn from terminal node {parent_id}"
                raise GraphLifecycleError(message)
            if not 0 < lease_limit <= self.state.limits.max_node_lease:
                message = "lease_limit must be positive and no larger than max_node_lease"
                raise GraphLifecycleError(message)
            if len(self.state.nodes) >= self.state.limits.max_nodes:
                message = "graph node limit reached"
                raise GraphNodeLimitError(message)
            if any(
                node.objective.fingerprint == objective.fingerprint
                for node in self.state.nodes.values()
            ):
                message = (
                    "duplicate graph objective rejected before model execution: "
                    f"{objective.fingerprint}"
                )
                raise DuplicateGraphObjectiveError(message)
            owner_key = exclusive_objective_owner_key(objective)
            if owner_key is not None and any(
                node.status in ACTIVE_NODE_STATUSES
                and exclusive_objective_owner_key(node.objective) == owner_key
                for node in self.state.nodes.values()
            ):
                message = (
                    "active semantic objective owner already exists before model "
                    f"execution: {owner_key}"
                )
                raise DuplicateGraphObjectiveError(message)

            node_id = f"node-{self.state.next_node_sequence:03d}"
            resolved_spec = agent_spec or AgentSpec.for_objective(objective)
            parent_hypothesis_fingerprint = (
                parent.hypothesis.fingerprint if parent.hypothesis is not None else ""
            )
            resolved_hypothesis = hypothesis or Hypothesis.from_objective(
                objective,
                parent_hypothesis_fingerprint=parent_hypothesis_fingerprint,
            )
            if resolved_hypothesis.objective_fingerprint != objective.fingerprint:
                message = "spawn hypothesis must bind the spawned objective"
                raise GraphLifecycleError(message)
            self.state.next_node_sequence += 1
            node = GraphNode(
                node_id=node_id,
                parent_id=parent_id,
                name=name,
                objective=objective,
                status=GraphNodeStatus.READY,
                lease_limit=lease_limit,
                agent_spec=resolved_spec,
                hypothesis=resolved_hypothesis,
            )
            self.state.nodes[node_id] = node
            self._wake_events[node_id] = asyncio.Event()
            self.state.last_reason = f"node_spawned:{node_id}"
            self._persist_unlocked()
            return _copy_node(node)

    async def spawn_race_group(  # noqa: C901, PLR0912, PLR0915
        self,
        *,
        parent_id: str,
        objective: GraphObjective,
        lanes: Sequence[GraphRaceLane],
        hypothesis: Hypothesis | None = None,
        lease_limit: int = 1,
    ) -> GraphRaceGroup:
        """Atomically create heterogeneous lanes for one evidence-gated objective."""
        async with self._lock:
            self._require_running_graph_unlocked()
            parent = self._node_unlocked(parent_id)
            if parent.status not in ACTIVE_NODE_STATUSES:
                raise GraphLifecycleError(f"cannot race from terminal node {parent_id}")
            lane_items = tuple(sorted(lanes, key=lambda lane: lane.lane_id))
            if not MIN_RACE_LANES <= len(lane_items) <= MAX_RACE_LANES:
                raise GraphLifecycleError("race groups require between two and three lanes")
            if lease_limit != 1:
                raise GraphLifecycleError("race lanes require an initial lease of one")
            if len(self.state.nodes) + len(lane_items) > self.state.limits.max_nodes:
                raise GraphNodeLimitError("race group exceeds the graph node limit")
            if self.state.limits.max_concurrent_nodes < len(lane_items):
                raise GraphConcurrencyLimitError("race group exceeds the graph concurrency limit")
            exploration_ceiling = (
                self.state.limits.max_model_requests
                - self.state.limits.proof_reserve_model_requests
            )
            if exploration_ceiling - self.state.model_requests_started < len(lane_items):
                raise GraphBudgetExceededError("race group lacks exploration request capacity")
            if any(
                node.objective.fingerprint == objective.fingerprint
                for node in self.state.nodes.values()
            ):
                raise DuplicateGraphObjectiveError(
                    "race objective already exists before lane creation"
                )
            owner_key = exclusive_objective_owner_key(objective)
            if owner_key is not None and any(
                node.status in ACTIVE_NODE_STATUSES
                and exclusive_objective_owner_key(node.objective) == owner_key
                for node in self.state.nodes.values()
            ):
                raise DuplicateGraphObjectiveError(
                    f"active semantic objective owner already exists: {owner_key}"
                )
            lane_ids = {lane.lane_id for lane in lane_items}
            specs = {lane.agent_spec.fingerprint for lane in lane_items}
            model_policies = {lane.agent_spec.model_policy_key for lane in lane_items}
            if len(lane_ids) != len(lane_items):
                raise GraphLifecycleError("race lane ids must be distinct")
            if len(specs) != len(lane_items) or len(model_policies) != len(lane_items):
                raise GraphLifecycleError("race lanes must use distinct agent/model policies")
            if "inherit" in model_policies:
                raise GraphLifecycleError("race lanes require explicit model policies")
            if any(lane.agent_spec.role is GraphAgentRole.COORDINATOR for lane in lane_items):
                raise GraphLifecycleError("race lanes cannot use the coordinator role")

            parent_hypothesis_fingerprint = (
                parent.hypothesis.fingerprint if parent.hypothesis is not None else ""
            )
            resolved_hypothesis = hypothesis or Hypothesis.from_objective(
                objective,
                parent_hypothesis_fingerprint=parent_hypothesis_fingerprint,
            )
            if resolved_hypothesis.objective_fingerprint != objective.fingerprint:
                raise GraphLifecycleError("race hypothesis must bind the raced objective")

            member_ids: list[str] = []
            for lane in lane_items:
                node_id = f"node-{self.state.next_node_sequence:03d}"
                self.state.next_node_sequence += 1
                node = GraphNode(
                    node_id=node_id,
                    parent_id=parent_id,
                    name=lane.name,
                    objective=objective,
                    status=GraphNodeStatus.READY,
                    lease_limit=1,
                    agent_spec=lane.agent_spec,
                    hypothesis=resolved_hypothesis,
                )
                self.state.nodes[node_id] = node
                self._wake_events[node_id] = asyncio.Event()
                member_ids.append(node_id)
            group_id = f"race-{self.state.next_race_sequence:03d}"
            self.state.next_race_sequence += 1
            group = GraphRaceGroup(
                group_id=group_id,
                parent_id=parent_id,
                objective_fingerprint=objective.fingerprint,
                hypothesis_fingerprint=resolved_hypothesis.fingerprint,
                member_node_ids=tuple(sorted(member_ids)),
            )
            self.state.race_groups[group_id] = group
            self.state.last_reason = f"race_group_spawned:{group_id}"
            self._persist_unlocked()
            return _copy_race_group(group)

    async def claim_race_progress(
        self,
        *,
        node_id: str,
        validation_digest: str,
        evidence_refs: Sequence[str],
    ) -> RaceClaimDecision:
        """Persist the first validated material result without cancelling billed work."""
        async with self._lock:
            self._require_running_graph_unlocked()
            self._node_unlocked(node_id)
            group = self.state.race_group_for(node_id)
            if group is None:
                raise GraphLifecycleError(f"node {node_id} is not a race lane")
            digest = " ".join(validation_digest.strip().split())
            refs = _clean_refs(evidence_refs)
            if not digest or not refs:
                raise GraphLifecycleError("race claims require a validated digest and evidence")
            if not group.winner_node_id:
                group.winner_node_id = node_id
                group.winning_validation_digest = digest
                group.winning_evidence_refs = refs
                status = RaceClaimStatus.WON
                self.state.last_reason = f"race_group_won:{group.group_id}:{node_id}"
                self._persist_unlocked()
            elif group.winner_node_id == node_id:
                if group.winning_validation_digest != digest or group.winning_evidence_refs != refs:
                    raise GraphLifecycleError("race winner cannot overwrite its winning receipt")
                status = RaceClaimStatus.ALREADY_WON
            else:
                status = RaceClaimStatus.LOST
            return RaceClaimDecision(
                group_id=group.group_id,
                node_id=node_id,
                status=status,
                winner_node_id=group.winner_node_id,
                evidence_refs=group.winning_evidence_refs,
            )

    async def retire_settled_race_losers(self, group_id: str) -> tuple[str, ...]:
        """Stop idle losers while in-flight provider/tool calls drain normally."""
        async with self._lock:
            group = self.state.race_groups.get(group_id)
            if group is None:
                raise GraphLifecycleError(f"unknown race group: {group_id}")
            if not group.winner_node_id:
                return ()
            retired: list[str] = []
            for node_id in group.member_node_ids:
                if node_id == group.winner_node_id:
                    continue
                node = self.state.nodes[node_id]
                if node.status not in ACTIVE_NODE_STATUSES:
                    continue
                if node.pending_model_request_id or node.pending_tool_call_id:
                    continue
                if any(
                    child.status in ACTIVE_NODE_STATUSES
                    for child in self.state.descendants_of(node_id)
                ):
                    continue
                self._stop_node_unlocked(node, reason=f"race_lost:{group.group_id}")
                retired.append(node_id)
            if retired:
                self.state.last_reason = f"race_losers_retired:{group_id}"
                self._persist_unlocked()
            return tuple(retired)

    async def yield_node_turn(self, node_id: str) -> GraphNode:
        """Return one settled running worker to READY for utility re-ranking."""
        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            if node.status is not GraphNodeStatus.RUNNING:
                message = f"node {node_id} must be running before yielding its turn"
                raise GraphLifecycleError(message)
            if node.pending_model_request_id is not None or node.pending_tool_call_id is not None:
                message = f"node {node_id} cannot yield with pending accounted work"
                raise GraphLifecycleError(message)
            node.status = GraphNodeStatus.READY
            self.state.last_reason = f"node_turn_yielded:{node_id}"
            self._persist_unlocked()
            return _copy_node(node)

    async def start_node(self, node_id: str) -> GraphNode:
        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            if node.status is not GraphNodeStatus.READY:
                message = f"node {node_id} must be ready before start; status={node.status.value}"
                raise GraphLifecycleError(message)
            if len(self.state.running_nodes) >= self.state.limits.max_concurrent_nodes:
                message = "graph concurrency limit reached"
                raise GraphConcurrencyLimitError(message)
            node.status = GraphNodeStatus.RUNNING
            self.state.last_reason = f"node_started:{node_id}"
            self._persist_unlocked()
            return _copy_node(node)

    async def park_node(self, node_id: str) -> GraphNode:
        async with self._lock:
            node = self._node_unlocked(node_id)
            self._park_node_unlocked(node)
            self.state.last_reason = f"node_waiting:{node_id}"
            self._persist_unlocked()
            return _copy_node(node)

    async def send_message(
        self,
        *,
        sender_id: str,
        target_id: str,
        kind: GraphMessageKind,
        body: Mapping[str, object],
        evidence_refs: Sequence[str] = (),
    ) -> GraphMessage:
        async with self._lock:
            self._require_running_graph_unlocked()
            self._node_unlocked(sender_id)
            target = self._node_unlocked(target_id)
            if target.status not in ACTIVE_NODE_STATUSES:
                message = f"cannot message terminal node {target_id}"
                raise GraphLifecycleError(message)
            graph_message = self._append_message_unlocked(
                sender_id=sender_id,
                target_id=target_id,
                kind=kind,
                body=body,
                evidence_refs=evidence_refs,
            )
            self.state.last_reason = f"message_sent:{graph_message.message_id}:{target_id}"
            self._persist_unlocked()
            return _copy_message(graph_message)

    async def consume_messages(self, node_id: str) -> tuple[GraphMessage, ...]:
        async with self._lock:
            self._node_unlocked(node_id)
            messages = self._consume_messages_unlocked(node_id)
            if messages:
                self.state.last_reason = f"messages_consumed:{node_id}"
                self._persist_unlocked()
            return tuple(_copy_message(message) for message in messages)

    async def wait_for_messages(  # noqa: C901 - lifecycle branches are explicit.
        self,
        node_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[GraphMessage, ...]:
        """Park a worker without polling, then wake it on inbox delivery."""
        if timeout_seconds is not None and timeout_seconds < 0:
            message = "timeout_seconds cannot be negative"
            raise GraphLifecycleError(message)

        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            pending = self.state.pending_messages(node_id)
            if pending:
                consumed = self._consume_messages_unlocked(node_id)
                self.state.last_reason = f"messages_consumed:{node_id}"
                self._persist_unlocked()
                return tuple(_copy_message(item) for item in consumed)
            if node.status is GraphNodeStatus.RUNNING:
                self._park_node_unlocked(node)
            elif node.status is not GraphNodeStatus.WAITING:
                message = f"node {node_id} cannot wait from status {node.status.value}"
                raise GraphLifecycleError(message)
            wake_event = self._wake_events[node_id]
            wake_event.clear()
            self.state.last_reason = f"node_waiting:{node_id}"
            self._persist_unlocked()

        try:
            if timeout_seconds is None:
                await wake_event.wait()
            else:
                await asyncio.wait_for(
                    wake_event.wait(),
                    timeout=timeout_seconds,
                )
        except TimeoutError:
            pass

        async with self._lock:
            node = self._node_unlocked(node_id)
            if (
                self.state.status is not GraphStatus.RUNNING
                or node.status not in ACTIVE_NODE_STATUSES
            ):
                return ()
            pending = self.state.pending_messages(node_id)
            if not pending:
                node.status = GraphNodeStatus.WAITING
                self.state.last_reason = f"node_wait_timeout:{node_id}"
                self._persist_unlocked()
                return ()
            if node.status in {
                GraphNodeStatus.READY,
                GraphNodeStatus.WAITING,
            }:
                if len(self.state.running_nodes) < self.state.limits.max_concurrent_nodes:
                    node.status = GraphNodeStatus.RUNNING
                else:
                    node.status = GraphNodeStatus.READY
            consumed = self._consume_messages_unlocked(node_id)
            self.state.last_reason = (
                f"node_woke:{node_id}"
                if node.status is GraphNodeStatus.RUNNING
                else f"node_wake_queued:{node_id}"
            )
            self._persist_unlocked()
            return tuple(_copy_message(item) for item in consumed)

    async def finish_node(
        self,
        node_id: str,
        *,
        summary: str,
        evidence_refs: Sequence[str] = (),
    ) -> GraphNode:
        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            if node.status not in ACTIVE_NODE_STATUSES:
                message = f"node {node_id} is already terminal"
                raise GraphLifecycleError(message)
            self._require_no_pending_work_unlocked(node)
            active_descendants = [
                child.node_id
                for child in self.state.descendants_of(node_id)
                if child.status in ACTIVE_NODE_STATUSES
            ]
            if active_descendants:
                message = (
                    f"node {node_id} cannot finish with active descendants: "
                    f"{', '.join(active_descendants)}"
                )
                raise GraphLifecycleError(message)

            node.status = GraphNodeStatus.COMPLETED
            node.completion_summary = " ".join(summary.strip().split())
            node.completion_evidence_refs = _clean_refs(evidence_refs)
            self.state.last_reason = f"node_completed:{node_id}"
            if node.parent_id is not None:
                parent = self.state.nodes[node.parent_id]
                if parent.status in ACTIVE_NODE_STATUSES:
                    self._append_message_unlocked(
                        sender_id=node.node_id,
                        target_id=parent.node_id,
                        kind=GraphMessageKind.COMPLETION,
                        body={
                            "node_id": node.node_id,
                            "summary": node.completion_summary,
                        },
                        evidence_refs=node.completion_evidence_refs,
                    )
            else:
                reason = (
                    "root_completed_after_findings_or_bounded_coverage"
                    if graph_mission_from_state(self.state)
                    is GraphMission.VULNERABILITY_ASSESSMENT
                    else "root_completed_without_proof"
                )
                self._terminate_graph_unlocked(
                    status=GraphStatus.EXHAUSTED,
                    reason=reason,
                )
            self._persist_unlocked()
            return _copy_node(node)

    async def mark_crashed(self, node_id: str, *, reason: str) -> GraphNode:
        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            if node.status not in ACTIVE_NODE_STATUSES:
                message = f"node {node_id} is already terminal"
                raise GraphLifecycleError(message)
            for descendant in reversed(self.state.descendants_of(node_id)):
                if descendant.status in ACTIVE_NODE_STATUSES:
                    self._stop_node_unlocked(
                        descendant,
                        reason=f"ancestor_crashed:{node_id}",
                    )
            self._interrupt_pending_work_unlocked(node)
            node.status = GraphNodeStatus.CRASHED
            node.completion_summary = " ".join(reason.strip().split())
            self.state.last_reason = f"node_crashed:{node_id}"
            if node.parent_id is None:
                self._terminate_graph_unlocked(
                    status=GraphStatus.FAILED,
                    reason=f"root_crashed:{reason}",
                )
            else:
                parent = self.state.nodes[node.parent_id]
                if parent.status in ACTIVE_NODE_STATUSES:
                    self._append_message_unlocked(
                        sender_id=node.node_id,
                        target_id=parent.node_id,
                        kind=GraphMessageKind.CRASH,
                        body={
                            "node_id": node.node_id,
                            "reason": node.completion_summary,
                        },
                    )
            self._persist_unlocked()
            return _copy_node(node)

    async def stop_node(
        self,
        node_id: str,
        *,
        reason: str,
        cascade: bool = True,
    ) -> GraphNode:
        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            if node.status not in ACTIVE_NODE_STATUSES:
                message = f"node {node_id} is already terminal"
                raise GraphLifecycleError(message)
            active_descendants = [
                descendant
                for descendant in self.state.descendants_of(node_id)
                if descendant.status in ACTIVE_NODE_STATUSES
            ]
            if active_descendants and not cascade:
                message = f"node {node_id} has active descendants"
                raise GraphLifecycleError(message)
            if node.parent_id is None:
                self._terminate_graph_unlocked(
                    status=GraphStatus.STOPPED,
                    reason=reason,
                )
            else:
                for descendant in reversed(active_descendants):
                    self._stop_node_unlocked(
                        descendant,
                        reason=f"ancestor_stopped:{node_id}",
                    )
                self._stop_node_unlocked(node, reason=reason)
                self.state.last_reason = f"node_stopped:{node_id}:{reason}"
            self._persist_unlocked()
            return _copy_node(node)

    async def solve(self, *, proof_evidence_refs: Sequence[str]) -> None:
        async with self._lock:
            self._require_running_graph_unlocked()
            proof_refs = _clean_refs(proof_evidence_refs)
            if not proof_refs:
                message = "trusted proof evidence refs are required"
                raise GraphLifecycleError(message)
            self.state.proof_evidence_refs = proof_refs
            self._terminate_graph_unlocked(
                status=GraphStatus.SOLVED,
                reason="trusted_proof_confirmed",
                preserve_pending_work=True,
            )
            self._persist_unlocked()

    async def stop_graph(
        self,
        *,
        status: GraphStatus = GraphStatus.STOPPED,
        reason: str,
    ) -> None:
        async with self._lock:
            self._require_running_graph_unlocked()
            if status not in TERMINAL_GRAPH_STATUSES or status is GraphStatus.SOLVED:
                message = "stop_graph requires a non-proof terminal status"
                raise GraphLifecycleError(message)
            self._terminate_graph_unlocked(status=status, reason=reason)
            self._persist_unlocked()

    async def begin_model_request(
        self,
        node_id: str,
        *,
        request_id: str | None = None,
    ) -> str:
        async with self._lock:
            self._require_running_graph_unlocked()
            self._enforce_wall_budget_unlocked()
            node = self._require_running_node_unlocked(node_id)
            if node.pending_model_request_id is not None:
                message = f"node {node_id} already has a pending model request"
                raise GraphLifecycleError(message)
            if node.lease_used >= node.lease_limit:
                message = f"node {node_id} request lease exhausted"
                raise GraphLeaseExhaustedError(message)
            if self.state.model_requests_started >= self.state.limits.max_model_requests:
                self._terminate_graph_unlocked(
                    status=GraphStatus.REQUEST_BUDGET_EXHAUSTED,
                    reason="global_model_request_budget_exhausted",
                )
                self._persist_unlocked()
                message = "global model request budget exhausted"
                raise GraphBudgetExceededError(message)
            exploration_ceiling = (
                self.state.limits.max_model_requests
                - self.state.limits.proof_reserve_model_requests
            )
            if self.state.model_requests_started >= exploration_ceiling and not node.proof_eligible:
                proof_worker_available = any(
                    candidate.proof_eligible and candidate.status in ACTIVE_NODE_STATUSES
                    for candidate in self.state.nodes.values()
                )
                if not proof_worker_available:
                    self._terminate_graph_unlocked(
                        status=GraphStatus.EXPLORATION_EXHAUSTED,
                        reason="proof_reserve_preserved",
                    )
                    self._persist_unlocked()
                message = "proof reserve cannot be consumed by reconnaissance work"
                raise GraphBudgetExceededError(message)
            if (
                self.state.limits.max_cost_usd is not None
                and self.state.spent_cost_usd >= self.state.limits.max_cost_usd
            ):
                self._terminate_graph_unlocked(
                    status=GraphStatus.COST_BUDGET_EXHAUSTED,
                    reason="global_cost_budget_exhausted",
                )
                self._persist_unlocked()
                message = "global cost budget exhausted"
                raise GraphBudgetExceededError(message)

            identifier = request_id or (f"model-{self.state.model_requests_started + 1:06d}")
            if not identifier.strip():
                message = "model request id is required"
                raise GraphLifecycleError(message)
            node.model_requests_started += 1
            node.lease_used += 1
            node.pending_model_request_id = identifier
            self.state.model_requests_started += 1
            self.state.last_reason = f"model_request_started:{node_id}:{identifier}"
            self._persist_unlocked()
            return identifier

    async def complete_model_request(
        self,
        node_id: str,
        *,
        request_id: str,
        cost_usd: float,
    ) -> None:
        async with self._lock:
            node = self._node_unlocked(node_id)
            if node.pending_model_request_id != request_id:
                message = f"model request completion mismatch for node {node_id}: {request_id}"
                raise GraphLifecycleError(message)
            if not math.isfinite(cost_usd) or cost_usd < 0:
                message = "model request cost must be finite and non-negative"
                raise GraphLifecycleError(message)
            node.pending_model_request_id = None
            node.model_requests_completed += 1
            node.spent_cost_usd += cost_usd
            self.state.model_requests_completed += 1
            self.state.spent_cost_usd += cost_usd
            if self.state.status is GraphStatus.RUNNING:
                self.state.last_reason = f"model_request_completed:{node_id}:{request_id}"
            if (
                self.state.status is GraphStatus.RUNNING
                and self.state.limits.max_cost_usd is not None
                and self.state.spent_cost_usd >= self.state.limits.max_cost_usd
            ):
                self._terminate_graph_unlocked(
                    status=GraphStatus.COST_BUDGET_EXHAUSTED,
                    reason="global_cost_budget_exhausted",
                )
            self._persist_unlocked()

    async def interrupt_model_request(
        self,
        node_id: str,
        *,
        request_id: str,
        reason: str,
    ) -> None:
        """Settle a provider-rejected request without crashing its worker."""
        async with self._lock:
            node = self._node_unlocked(node_id)
            if node.pending_model_request_id != request_id:
                message = f"model request interruption mismatch for node {node_id}: {request_id}"
                raise GraphLifecycleError(message)
            node.pending_model_request_id = None
            node.model_requests_completed += 1
            node.interrupted_model_requests += 1
            self.state.model_requests_completed += 1
            self.state.interrupted_model_requests += 1
            self.state.last_reason = (
                f"model_request_interrupted:{node_id}:{request_id}:"
                f"{' '.join(reason.strip().split())}"
            )
            self._persist_unlocked()

    async def begin_model_continuity_retry(
        self,
        node_id: str,
        *,
        request_id: str | None = None,
    ) -> str:
        """Spend one globally accounted provider retry without enlarging exploration."""
        async with self._lock:
            self._require_running_graph_unlocked()
            self._enforce_wall_budget_unlocked()
            node = self._require_running_node_unlocked(node_id)
            if node.pending_model_request_id is not None:
                message = f"node {node_id} already has a pending model request"
                raise GraphLifecycleError(message)
            if node.provider_continuity_retries >= MAX_PROVIDER_CONTINUITY_RETRIES_PER_NODE:
                message = f"node {node_id} provider continuity retry limit reached"
                raise GraphBudgetExceededError(message)
            if self.state.model_requests_started >= self.state.limits.max_model_requests:
                self._terminate_graph_unlocked(
                    status=GraphStatus.REQUEST_BUDGET_EXHAUSTED,
                    reason="global_model_request_budget_exhausted",
                )
                self._persist_unlocked()
                message = "global model request budget exhausted"
                raise GraphBudgetExceededError(message)
            exploration_ceiling = (
                self.state.limits.max_model_requests
                - self.state.limits.proof_reserve_model_requests
            )
            if self.state.model_requests_started >= exploration_ceiling and not node.proof_eligible:
                message = "provider continuity cannot consume the proof reserve"
                raise GraphBudgetExceededError(message)
            if (
                self.state.limits.max_cost_usd is not None
                and self.state.spent_cost_usd >= self.state.limits.max_cost_usd
            ):
                self._terminate_graph_unlocked(
                    status=GraphStatus.COST_BUDGET_EXHAUSTED,
                    reason="global_cost_budget_exhausted",
                )
                self._persist_unlocked()
                message = "global cost budget exhausted"
                raise GraphBudgetExceededError(message)

            identifier = request_id or (f"model-{self.state.model_requests_started + 1:06d}")
            if not identifier.strip():
                message = "model request id is required"
                raise GraphLifecycleError(message)
            node.model_requests_started += 1
            node.provider_continuity_retries += 1
            node.pending_model_request_id = identifier
            self.state.model_requests_started += 1
            self.state.last_reason = f"provider_continuity_request_started:{node_id}:{identifier}"
            self._persist_unlocked()
            return identifier

    async def begin_tool_call(
        self,
        node_id: str,
        *,
        call_id: str | None = None,
    ) -> str:
        async with self._lock:
            self._require_running_graph_unlocked()
            self._enforce_wall_budget_unlocked()
            node = self._require_running_node_unlocked(node_id)
            if node.pending_tool_call_id is not None:
                message = f"node {node_id} already has a pending tool call"
                raise GraphLifecycleError(message)
            if self.state.tool_calls_started >= self.state.limits.max_tool_calls:
                self._terminate_graph_unlocked(
                    status=GraphStatus.TOOL_BUDGET_EXHAUSTED,
                    reason="global_tool_call_budget_exhausted",
                )
                self._persist_unlocked()
                message = "global tool call budget exhausted"
                raise GraphBudgetExceededError(message)
            identifier = call_id or f"tool-{self.state.tool_calls_started + 1:06d}"
            if not identifier.strip():
                message = "tool call id is required"
                raise GraphLifecycleError(message)
            node.tool_calls_started += 1
            node.pending_tool_call_id = identifier
            self.state.tool_calls_started += 1
            self.state.last_reason = f"tool_call_started:{node_id}:{identifier}"
            self._persist_unlocked()
            return identifier

    async def complete_tool_call(
        self,
        node_id: str,
        *,
        call_id: str,
    ) -> None:
        async with self._lock:
            node = self._node_unlocked(node_id)
            if node.pending_tool_call_id != call_id:
                message = f"tool call completion mismatch for node {node_id}: {call_id}"
                raise GraphLifecycleError(message)
            node.pending_tool_call_id = None
            node.tool_calls_completed += 1
            self.state.tool_calls_completed += 1
            if self.state.status is GraphStatus.RUNNING:
                self.state.last_reason = f"tool_call_completed:{node_id}:{call_id}"
            self._persist_unlocked()

    async def reconcile_interrupted_work(self) -> bool:
        async with self._lock:
            changed = self._reconcile_interrupted_work_unlocked()
            if changed:
                self.state.last_reason = "interrupted_work_reconciled"
                self._persist_unlocked()
            return changed

    async def apply_progress_lease(  # noqa: PLR0913 - explicit trust boundary.
        self,
        node_id: str,
        *,
        progress_tokens: Sequence[str],
        disproved_hypothesis_tokens: Sequence[str] = (),
        additional_requests: int,
        proof_eligible: bool,
        counterfactual_objective_fingerprint: str = "",
        reason: str,
    ) -> GraphNode:
        """Atomically record novel trusted progress and extend one node lease."""
        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            if node.status not in ACTIVE_NODE_STATUSES:
                message = f"cannot extend terminal node {node_id}"
                raise GraphLeaseGrantError(message)
            if additional_requests <= 0:
                message = "lease extension must be greater than zero"
                raise GraphLeaseGrantError(message)
            if node.lease_extensions >= self.state.limits.max_lease_extensions_per_node:
                message = f"node {node_id} lease extension limit reached"
                raise GraphLeaseGrantError(message)

            progress = _clean_refs(progress_tokens)
            known_progress = set(self.state.trusted_progress_tokens)
            novel_progress = tuple(token for token in progress if token not in known_progress)
            if not novel_progress:
                message = "lease extension requires novel trusted progress"
                raise GraphLeaseGrantError(message)

            counterfactual = " ".join(counterfactual_objective_fingerprint.strip().split())
            if counterfactual:
                if counterfactual == node.objective.fingerprint:
                    message = "counterfactual objective must differ from current task"
                    raise GraphLeaseGrantError(message)
                if counterfactual in (self.state.counterfactual_objective_fingerprints):
                    message = "counterfactual objective was already granted"
                    raise GraphLeaseGrantError(message)

            available_node = self.state.limits.max_node_lease - node.lease_limit
            available_global = (
                self.state.limits.max_model_requests - self.state.model_requests_started
            )
            granted = min(
                additional_requests,
                available_node,
                available_global,
            )
            if granted <= 0:
                message = f"no request capacity remains for node {node_id}"
                raise GraphLeaseGrantError(message)

            self.state.evidence_epoch += 1
            self.state.trusted_progress_tokens = _clean_refs(
                (*self.state.trusted_progress_tokens, *novel_progress)
            )
            disproved = _clean_refs(disproved_hypothesis_tokens)
            self.state.disproved_hypothesis_tokens = _clean_refs(
                (*self.state.disproved_hypothesis_tokens, *disproved)
            )
            if counterfactual:
                self.state.counterfactual_objective_fingerprints = _clean_refs(
                    (
                        *self.state.counterfactual_objective_fingerprints,
                        counterfactual,
                    )
                )
            node.lease_limit += granted
            node.lease_extensions += 1
            node.proof_eligible = node.proof_eligible or proof_eligible
            node.last_progress_epoch = self.state.evidence_epoch
            node.last_observation_digest = ""
            node.repeated_observation_count = 0
            self.state.last_reason = f"lease_extended:{node_id}:{granted}:{reason}"
            self._persist_unlocked()
            return _copy_node(node)

    async def apply_stall_review_lease(
        self,
        node_id: str,
        *,
        review_token: str,
        reason: str,
    ) -> GraphNode:
        """Grant one replay-safe model turn for a typed strategy plateau."""
        async with self._lock:
            self._require_running_graph_unlocked()
            self._enforce_wall_budget_unlocked()
            node = self._node_unlocked(node_id)
            if node.status is not GraphNodeStatus.WAITING:
                message = f"stall review requires a waiting node; status={node.status.value}"
                raise GraphLeaseGrantError(message)
            self._require_no_pending_work_unlocked(node)
            token = " ".join(review_token.strip().split())
            if not token:
                message = "stall review token is required"
                raise GraphLeaseGrantError(message)
            if token in self.state.stall_review_tokens:
                message = "stall review token was already granted"
                raise GraphLeaseGrantError(message)
            if len(self.state.stall_review_tokens) >= MAX_STALL_REVIEWS_PER_GRAPH:
                message = "graph stall review limit reached"
                raise GraphLeaseGrantError(message)
            if node.stall_review_grants >= MAX_STALL_REVIEWS_PER_NODE:
                message = f"node {node_id} stall review limit reached"
                raise GraphLeaseGrantError(message)
            if node.lease_limit >= self.state.limits.max_node_lease:
                message = f"node {node_id} has no stall review lease capacity"
                raise GraphLeaseGrantError(message)
            exploration_ceiling = (
                self.state.limits.max_model_requests
                - self.state.limits.proof_reserve_model_requests
            )
            if self.state.model_requests_started >= exploration_ceiling:
                message = "stall review cannot consume the proof reserve"
                raise GraphLeaseGrantError(message)
            if (
                self.state.limits.max_cost_usd is not None
                and self.state.spent_cost_usd >= self.state.limits.max_cost_usd
            ):
                message = "global cost budget exhausted"
                raise GraphLeaseGrantError(message)

            node.lease_limit += 1
            node.stall_review_grants += 1
            node.status = GraphNodeStatus.READY
            self.state.stall_review_tokens = tuple(sorted((*self.state.stall_review_tokens, token)))
            self.state.last_reason = (
                f"stall_review_granted:{node_id}:{' '.join(reason.strip().split())}"
            )
            self._wake_events[node_id].set()
            self._persist_unlocked()
            return _copy_node(node)

    async def register_semantic_action(
        self,
        node_id: str,
        *,
        fingerprint: str,
    ) -> int:
        """Reserve a semantic action slot before any tool call begins."""
        async with self._lock:
            self._require_running_graph_unlocked()
            self._require_running_node_unlocked(node_id)
            canonical = fingerprint.strip()
            if not canonical:
                message = "semantic action fingerprint is required"
                raise GraphLifecycleError(message)
            count = self.state.semantic_action_counts.get(canonical, 0)
            if count >= self.state.limits.max_semantic_action_repeats:
                message = f"semantic action repeat limit reached before tool spend: {canonical}"
                raise RepeatedGraphActionError(message)
            count += 1
            self.state.semantic_action_counts[canonical] = count
            self.state.last_reason = f"semantic_action_registered:{node_id}:{canonical}"
            self._persist_unlocked()
            return count

    async def record_observation(
        self,
        node_id: str,
        *,
        digest: str,
    ) -> bool:
        """Update the no-progress watchdog from a target observation digest."""
        async with self._lock:
            self._require_running_graph_unlocked()
            node = self._node_unlocked(node_id)
            if node.status not in ACTIVE_NODE_STATUSES:
                message = f"cannot record observation for terminal node {node_id}"
                raise GraphLifecycleError(message)
            canonical = digest.strip()
            if not canonical:
                message = "observation digest is required"
                raise GraphLifecycleError(message)
            if canonical == node.last_observation_digest:
                node.repeated_observation_count += 1
            else:
                node.last_observation_digest = canonical
                node.repeated_observation_count = 1
            triggered = (
                node.repeated_observation_count >= self.state.limits.repeated_observation_limit
            )
            self.state.last_reason = (
                f"observation_watchdog:{node_id}:{node.repeated_observation_count}"
            )
            self._persist_unlocked()
            return triggered

    def _reconcile_interrupted_work_unlocked(self) -> bool:
        changed = False
        for node in self.state.nodes.values():
            if node.pending_model_request_id is not None:
                node.pending_model_request_id = None
                node.model_requests_completed += 1
                node.interrupted_model_requests += 1
                self.state.model_requests_completed += 1
                self.state.interrupted_model_requests += 1
                changed = True
            if node.pending_tool_call_id is not None:
                node.pending_tool_call_id = None
                node.tool_calls_completed += 1
                node.interrupted_tool_calls += 1
                self.state.tool_calls_completed += 1
                self.state.interrupted_tool_calls += 1
                changed = True
            if node.status is GraphNodeStatus.RUNNING:
                node.status = GraphNodeStatus.READY
                changed = True
        return changed

    def _require_running_graph_unlocked(self) -> None:
        if self.state.status is not GraphStatus.RUNNING:
            message = f"graph is terminal: {self.state.status.value}"
            raise GraphLifecycleError(message)

    def _node_unlocked(self, node_id: str) -> GraphNode:
        node = self.state.nodes.get(node_id)
        if node is None:
            message = f"unknown graph node: {node_id}"
            raise UnknownGraphNodeError(message)
        return node

    def _require_running_node_unlocked(self, node_id: str) -> GraphNode:
        node = self._node_unlocked(node_id)
        if node.status is not GraphNodeStatus.RUNNING:
            message = f"node {node_id} must be running; status={node.status.value}"
            raise GraphLifecycleError(message)
        return node

    def _park_node_unlocked(self, node: GraphNode) -> None:
        if node.status is not GraphNodeStatus.RUNNING:
            message = f"node {node.node_id} must be running before wait; status={node.status.value}"
            raise GraphLifecycleError(message)
        self._require_no_pending_work_unlocked(node)
        node.status = GraphNodeStatus.WAITING

    @staticmethod
    def _require_no_pending_work_unlocked(node: GraphNode) -> None:
        if node.pending_model_request_id is not None or node.pending_tool_call_id is not None:
            message = f"node {node.node_id} has pending accounted work"
            raise GraphLifecycleError(message)

    def _append_message_unlocked(
        self,
        *,
        sender_id: str,
        target_id: str,
        kind: GraphMessageKind,
        body: Mapping[str, object],
        evidence_refs: Sequence[str] = (),
    ) -> GraphMessage:
        normalized_body = _json_body(body)
        message = GraphMessage(
            message_id=f"message-{self.state.next_message_sequence:06d}",
            sender_id=sender_id,
            target_id=target_id,
            kind=kind,
            body=normalized_body,
            evidence_refs=_clean_refs(evidence_refs),
        )
        self.state.next_message_sequence += 1
        self.state.messages.append(message)
        target = self.state.nodes[target_id]
        if target.status is GraphNodeStatus.WAITING:
            target.status = GraphNodeStatus.READY
        self._wake_events[target_id].set()
        return message

    def _consume_messages_unlocked(
        self,
        node_id: str,
    ) -> tuple[GraphMessage, ...]:
        messages = self.state.pending_messages(node_id)
        for message in messages:
            message.consumed = True
        if not self.state.pending_messages(node_id):
            self._wake_events[node_id].clear()
        return messages

    def _interrupt_pending_work_unlocked(self, node: GraphNode) -> None:
        if node.pending_model_request_id is not None:
            node.pending_model_request_id = None
            node.model_requests_completed += 1
            node.interrupted_model_requests += 1
            self.state.model_requests_completed += 1
            self.state.interrupted_model_requests += 1
        if node.pending_tool_call_id is not None:
            node.pending_tool_call_id = None
            node.tool_calls_completed += 1
            node.interrupted_tool_calls += 1
            self.state.tool_calls_completed += 1
            self.state.interrupted_tool_calls += 1

    def _stop_node_unlocked(
        self,
        node: GraphNode,
        *,
        reason: str,
        preserve_pending_work: bool = False,
    ) -> None:
        if not preserve_pending_work:
            self._interrupt_pending_work_unlocked(node)
        node.status = GraphNodeStatus.STOPPED
        node.completion_summary = " ".join(reason.strip().split())
        self._wake_events[node.node_id].set()

    def _terminate_graph_unlocked(
        self,
        *,
        status: GraphStatus,
        reason: str,
        preserve_pending_work: bool = False,
    ) -> None:
        if status not in TERMINAL_GRAPH_STATUSES:
            message = f"graph termination requires terminal status: {status.value}"
            raise GraphLifecycleError(message)
        for node in self.state.nodes.values():
            if node.status in ACTIVE_NODE_STATUSES:
                self._stop_node_unlocked(
                    node,
                    reason=reason,
                    preserve_pending_work=preserve_pending_work,
                )
        self.state.status = status
        self.state.last_reason = " ".join(reason.strip().split()) or status.value

    def _enforce_wall_budget_unlocked(self) -> None:
        elapsed = self._clock() - self.state.created_at_epoch
        if elapsed < self.state.limits.max_wall_seconds:
            return
        self._terminate_graph_unlocked(
            status=GraphStatus.WALL_TIME_EXHAUSTED,
            reason="global_wall_time_budget_exhausted",
        )
        self._persist_unlocked()
        message = "global wall time budget exhausted"
        raise GraphBudgetExceededError(message)

    def _persist_unlocked(self) -> None:
        self.state.validate()
        if self.state_path is not None:
            self.state.save(self.state_path)


def _copy_node(node: GraphNode) -> GraphNode:
    return GraphNode.from_json(node.to_json())


def _copy_message(message: GraphMessage) -> GraphMessage:
    return GraphMessage.from_json(message.to_json())


def _copy_race_group(group: GraphRaceGroup) -> GraphRaceGroup:
    return GraphRaceGroup.from_json(group.to_json())


def _clean_refs(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        sorted({" ".join(str(value).strip().split()) for value in values if str(value).strip()})
    )


def _json_body(body: Mapping[str, object]) -> dict[str, object]:
    try:
        encoded = json.dumps(dict(body), sort_keys=True)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        message = f"message body must be JSON serializable: {exc}"
        raise GraphLifecycleError(message) from exc
    if not isinstance(decoded, dict):
        message = "message body must encode to an object"
        raise GraphLifecycleError(message)
    return dict(decoded)


__all__ = [
    "DuplicateGraphObjectiveError",
    "GraphBudgetExceededError",
    "GraphConcurrencyLimitError",
    "GraphCoordinator",
    "GraphCoordinatorError",
    "GraphLeaseExhaustedError",
    "GraphLeaseGrantError",
    "GraphLifecycleError",
    "GraphNodeLimitError",
    "RepeatedGraphActionError",
    "UnknownGraphNodeError",
]
