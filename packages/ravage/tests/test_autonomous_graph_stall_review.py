# ruff: noqa: CPY001

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.loop_policy import (
    LoopDecision,
    LoopDisposition,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphLimits,
    GraphNodeStatus,
    GraphObjective,
    GraphState,
)
from ravage.agent_core.autonomous_graph.scheduler import ProgressiveGraphScheduler
from ravage.agent_core.autonomous_graph.sessions import (
    GraphSessionStore,
    SessionRole,
)
from ravage.agent_core.autonomous_graph.stall_review import select_stall_review
from ravage.agent_core.autonomous_graph.worker import (
    GraphModelReply,
    GraphRunner,
    GraphToolResult,
    GraphWorker,
    ProofGateResult,
    WorkerStepKind,
    WorkerStepResult,
)

if TYPE_CHECKING:
    from pathlib import Path

REVIEWED_LEASE = 2
REVIEWED_MODEL_REQUESTS = 2


class UnusedModel:
    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        del node_id, messages
        message = "stall selection must not spend a model request"
        raise AssertionError(message)


class UnusedExecutor:
    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        del node_id, tool, arguments
        message = "stall selection must not spend a tool call"
        raise AssertionError(message)


class UnusedProofGate:
    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        del node_id, evidence_refs
        message = "stall selection must not invoke the proof gate"
        raise AssertionError(message)


class ScriptedStallWorker(GraphWorker):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.steps_completed = 0

    async def step(self, node_id: str) -> WorkerStepResult:
        request_id = await self.coordinator.begin_model_request(node_id)
        await self.coordinator.complete_model_request(
            node_id,
            request_id=request_id,
            cost_usd=0.0,
        )
        self.steps_completed += 1
        if self.steps_completed == 1:
            await self.coordinator.park_node(node_id)
            return _plateau_step()
        await self.coordinator.finish_node(
            node_id,
            summary="bounded review closed the route",
        )
        return WorkerStepResult(
            node_id=node_id,
            kind=WorkerStepKind.FINISHED,
            reason="node_finished",
        )


def _objective() -> GraphObjective:
    return GraphObjective.create(
        family="template_injection",
        instruction="close one observed rendering form",
        endpoint="/generate",
        inputs=("sentence", "number"),
        strategy="template_form_closure",
        expected_signal="target-observed proof or bounded disproof",
    )


def _plateau_step() -> WorkerStepResult:
    return WorkerStepResult(
        node_id="node-001",
        kind=WorkerStepKind.EXECUTED,
        reason="tool_observation_recorded",
        loop_decision=LoopDecision(
            disposition=LoopDisposition.PIVOT,
            reason="observation_plateau_requires_strategy_rotation",
            cell_id="cell:template",
            stage="observed",
            evidence_version=2,
            required_dimension="template_dialect",
            recommended_campaign="ssti-bounded-form-closure",
            recommended_probe="template_form_closure",
        ),
    )


async def _park_after_one_request(coordinator: GraphCoordinator) -> None:
    request_id = await coordinator.begin_model_request("node-001")
    await coordinator.complete_model_request(
        "node-001",
        request_id=request_id,
        cost_usd=0.0,
    )
    await coordinator.park_node("node-001")


def _worker(
    coordinator: GraphCoordinator,
    *,
    session_root: Path,
) -> GraphWorker:
    return GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(session_root),
        complete=UnusedModel(),
        execute=UnusedExecutor(),
        proof_gate=UnusedProofGate(),
    )


def _scripted_worker(
    coordinator: GraphCoordinator,
    *,
    session_root: Path,
) -> ScriptedStallWorker:
    return ScriptedStallWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(session_root),
        complete=UnusedModel(),
        execute=UnusedExecutor(),
        proof_gate=UnusedProofGate(),
    )


@pytest.mark.asyncio
async def test_plateau_gets_one_replay_safe_targeted_review_turn(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "graph.json"
    coordinator = GraphCoordinator.start(
        graph_id="stall-review",
        root_objective=_objective(),
        limits=GraphLimits(
            max_model_requests=4,
            proof_reserve_model_requests=1,
        ),
        root_lease_limit=1,
        state_path=state_path,
    )
    await _park_after_one_request(coordinator)
    worker = _worker(
        coordinator,
        session_root=tmp_path / "sessions",
    )
    steps = (_plateau_step(),)

    selected_before = select_stall_review(coordinator.state, steps)
    granted = await worker.try_stall_review(steps)
    selected_after = select_stall_review(coordinator.state, steps)
    granted_twice = await worker.try_stall_review(steps)
    persisted = GraphState.load(state_path)
    node = persisted.nodes["node-001"]
    records = worker.sessions.records("node-001")

    assert selected_before is not None
    assert selected_before.required_dimension == "template_dialect"
    assert granted is True
    assert selected_after is None
    assert granted_twice is False
    assert node.status is GraphNodeStatus.READY
    assert node.lease_limit == REVIEWED_LEASE
    assert node.lease_used == 1
    assert node.stall_review_grants == 1
    assert len(persisted.stall_review_tokens) == 1
    assert records[-1].role is SessionRole.USER
    assert records[-1].content.startswith("BOUNDED_STALL_REVIEW")
    assert "only stall-review grant" in records[-1].content
    assert persisted.model_requests_started == 1
    assert persisted.tool_calls_started == 0


@pytest.mark.asyncio
async def test_stall_review_cannot_consume_proof_reserve(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="stall-review-proof-reserve",
        root_objective=_objective(),
        limits=GraphLimits(
            max_model_requests=2,
            proof_reserve_model_requests=1,
        ),
        root_lease_limit=1,
        state_path=tmp_path / "graph.json",
    )
    await _park_after_one_request(coordinator)
    worker = _worker(
        coordinator,
        session_root=tmp_path / "sessions",
    )

    granted = await worker.try_stall_review((_plateau_step(),))

    node = coordinator.state.nodes["node-001"]
    assert granted is False
    assert node.status is GraphNodeStatus.WAITING
    assert node.lease_limit == 1
    assert node.stall_review_grants == 0
    assert coordinator.state.stall_review_tokens == ()


@pytest.mark.asyncio
async def test_stall_review_requires_a_typed_material_pivot(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="stall-review-no-pivot",
        root_objective=_objective(),
        limits=GraphLimits(
            max_model_requests=4,
            proof_reserve_model_requests=1,
        ),
        root_lease_limit=1,
        state_path=tmp_path / "graph.json",
    )
    await _park_after_one_request(coordinator)
    worker = _worker(
        coordinator,
        session_root=tmp_path / "sessions",
    )
    untyped = WorkerStepResult(
        node_id="node-001",
        kind=WorkerStepKind.LEASE_EXHAUSTED,
        reason="node_progressive_lease_exhausted",
    )

    granted = await worker.try_stall_review((untyped,))

    assert granted is False
    assert coordinator.state.stall_review_tokens == ()


@pytest.mark.asyncio
async def test_graph_runner_uses_review_once_before_declaring_deadlock(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="stall-review-runner",
        root_objective=_objective(),
        limits=GraphLimits(
            max_model_requests=4,
            proof_reserve_model_requests=1,
        ),
        root_lease_limit=1,
        state_path=tmp_path / "graph.json",
    )
    worker = _scripted_worker(
        coordinator,
        session_root=tmp_path / "sessions",
    )

    result = await GraphRunner(worker).run()

    assert result.reason == "root_completed_without_proof"
    assert worker.steps_completed == REVIEWED_MODEL_REQUESTS
    assert coordinator.state.model_requests_started == REVIEWED_MODEL_REQUESTS
    assert len(coordinator.state.stall_review_tokens) == 1
