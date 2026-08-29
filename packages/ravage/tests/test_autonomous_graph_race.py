from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.coordinator import (
    GraphConcurrencyLimitError,
    GraphCoordinator,
    GraphLifecycleError,
)
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphAgentRole,
    GraphLimits,
    GraphNodeStatus,
    GraphObjective,
    GraphRaceLane,
    GraphState,
    GraphStateError,
    RaceClaimStatus,
)
from ravage.agent_core.autonomous_graph.run_store import ActionLifecycle, RunStore
from ravage.agent_core.autonomous_graph.runtime_binding import GraphRuntimeResolver
from ravage.agent_core.autonomous_graph.scheduler import (
    ProgressiveGraphScheduler,
    ProgressKind,
    ProgressReceipt,
    ProgressSource,
)
from ravage.agent_core.autonomous_graph.sessions import GraphSessionStore
from ravage.agent_core.autonomous_graph.worker import (
    GraphModelReply,
    GraphRunner,
    GraphToolResult,
    GraphWorker,
    ProofGateResult,
    WorkerStepKind,
)

if TYPE_CHECKING:
    from pathlib import Path

TWO_LANES = 2


def _objective(instruction: str) -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction=instruction,
        endpoint="/search",
        inputs=("query",),
        strategy="differential",
        expected_signal="target-observed response differential",
    )


def _lanes() -> tuple[GraphRaceLane, GraphRaceLane]:
    return (
        GraphRaceLane(
            lane_id="lane-a",
            name="racer-a",
            agent_spec=AgentSpec.create(
                role=GraphAgentRole.SPECIALIST,
                model_policy_key="lane_a",
            ),
        ),
        GraphRaceLane(
            lane_id="lane-b",
            name="racer-b",
            agent_spec=AgentSpec.create(
                role=GraphAgentRole.CRITIC,
                model_policy_key="lane_b",
            ),
        ),
    )


async def _coordinator(path: Path | None = None) -> GraphCoordinator:
    return GraphCoordinator.start(
        graph_id="race-test",
        root_objective=_objective("coordinate racers"),
        limits=GraphLimits(max_concurrent_nodes=3),
        root_lease_limit=2,
        state_path=path,
    )


@pytest.mark.asyncio
async def test_race_group_is_atomic_durable_and_first_claim_wins(tmp_path: Path) -> None:
    state_path = tmp_path / "graph.json"
    coordinator = await _coordinator(state_path)
    group = await coordinator.spawn_race_group(
        parent_id="node-001",
        objective=_objective("race one bounded oracle test"),
        lanes=_lanes(),
    )

    assert len(group.member_node_ids) == TWO_LANES
    loaded = GraphState.load(state_path)
    assert loaded.race_groups[group.group_id].member_node_ids == group.member_node_ids

    winner, loser = group.member_node_ids
    won = await coordinator.claim_race_progress(
        node_id=winner,
        validation_digest="validated:one",
        evidence_refs=("evidence:winner",),
    )
    repeated = await coordinator.claim_race_progress(
        node_id=winner,
        validation_digest="validated:one",
        evidence_refs=("evidence:winner",),
    )
    lost = await coordinator.claim_race_progress(
        node_id=loser,
        validation_digest="validated:two",
        evidence_refs=("evidence:loser",),
    )

    assert won.status is RaceClaimStatus.WON
    assert repeated.status is RaceClaimStatus.ALREADY_WON
    assert lost.status is RaceClaimStatus.LOST
    assert lost.winner_node_id == winner
    with pytest.raises(GraphLifecycleError, match="cannot overwrite"):
        await coordinator.claim_race_progress(
            node_id=winner,
            validation_digest="validated:changed",
            evidence_refs=("evidence:changed",),
        )


@pytest.mark.asyncio
async def test_duplicate_objectives_require_a_valid_race_group() -> None:
    coordinator = await _coordinator()
    group = await coordinator.spawn_race_group(
        parent_id="node-001",
        objective=_objective("race bounded variants"),
        lanes=_lanes(),
    )
    payload = coordinator.state.to_json()
    payload["race_groups"] = []

    with pytest.raises(GraphStateError, match="duplicate objective fingerprint"):
        GraphState.from_json(payload)

    assert coordinator.state.race_groups[group.group_id].winner_node_id == ""


@pytest.mark.asyncio
async def test_race_admission_requires_capacity_for_every_lane() -> None:
    coordinator = GraphCoordinator.start(
        graph_id="race-capacity-test",
        root_objective=_objective("coordinate capacity test"),
        limits=GraphLimits(max_concurrent_nodes=2),
    )
    lanes = (
        *_lanes(),
        GraphRaceLane(
            lane_id="lane-c",
            name="racer-c",
            agent_spec=AgentSpec.create(
                role=GraphAgentRole.DISCOVERY,
                model_policy_key="lane_c",
            ),
        ),
    )

    with pytest.raises(GraphConcurrencyLimitError, match="concurrency"):
        await coordinator.spawn_race_group(
            parent_id="node-001",
            objective=_objective("three lanes cannot fit"),
            lanes=lanes,
        )


@pytest.mark.asyncio
async def test_runner_starts_an_admitted_race_as_one_scheduling_unit(tmp_path: Path) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="race-scheduling-test",
        root_objective=_objective("coordinate scheduled racers"),
        limits=GraphLimits(max_concurrent_nodes=2),
        root_lease_limit=2,
    )
    group = await coordinator.spawn_race_group(
        parent_id="node-001",
        objective=_objective("race before unrelated work"),
        lanes=_lanes(),
    )
    ordinary = await coordinator.spawn_node(
        parent_id="node-001",
        name="ordinary-high-utility-specialist",
        objective=_objective("run unrelated specialist work"),
        lease_limit=1,
    )
    await coordinator.yield_node_turn(coordinator.state.root_node_id)

    async def complete(
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        del node_id, messages
        return GraphModelReply(content='{"kind":"wait","payload":{}}')

    async def execute(
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        del node_id, tool, arguments
        return GraphToolResult(output="unused")

    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "scheduled-sessions"),
        complete=complete,
        execute=execute,
        proof_gate=_RejectProof(),
    )
    runner = GraphRunner(worker)

    assert coordinator.state.race_groups[group.group_id].winner_node_id == ""
    assert {coordinator.state.nodes[node_id].status for node_id in group.member_node_ids} == {
        GraphNodeStatus.READY
    }
    await runner._start_ready_nodes()  # noqa: SLF001 - focused scheduling invariant.

    assert {node.node_id for node in coordinator.state.running_nodes} == set(group.member_node_ids)
    assert coordinator.state.nodes[ordinary.node_id].status is GraphNodeStatus.READY
    assert coordinator.state.nodes["node-001"].status is GraphNodeStatus.READY


@dataclass(frozen=True)
class _EvidenceRecord:
    evidence_id: str
    target_identity: str
    producer_node_id: str
    kind: str = "primitive_confirmed"
    source: str = "tool_http_request"
    material: bool = True


class _EvidenceValidator:
    target_identity = "target:race"

    def __init__(self, records: dict[str, _EvidenceRecord]) -> None:
        self.records = records

    def validate_references(
        self,
        evidence_refs: tuple[str, ...],
        *,
        require_trusted: bool = False,
    ) -> tuple[_EvidenceRecord, ...]:
        del require_trusted
        return tuple(self.records[ref] for ref in evidence_refs)


class _RejectProof:
    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        del node_id, evidence_refs
        return ProofGateResult(accepted=False, reason="not proof")


@pytest.mark.asyncio
async def test_worker_drains_billed_loser_before_second_executor_call(tmp_path: Path) -> None:
    coordinator = await _coordinator(tmp_path / "graph.json")
    group = await coordinator.spawn_race_group(
        parent_id="node-001",
        objective=_objective("race a material primitive"),
        lanes=_lanes(),
    )
    winner, loser = group.member_node_ids
    loser_model_started = asyncio.Event()
    winner_executor_returning = asyncio.Event()

    async def complete(
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        del messages
        if node_id == loser:
            loser_model_started.set()
            await winner_executor_returning.wait()
        else:
            await loser_model_started.wait()
        return GraphModelReply(
            content=json.dumps(
                {
                    "kind": "execute",
                    "payload": {
                        "tool": "probe",
                        "arguments": {"lane": node_id},
                        "expected_signal": "material primitive",
                    },
                }
            ),
            cost_usd=0.01,
        )

    executor_calls: list[str] = []

    async def execute(
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        del tool, arguments
        executor_calls.append(node_id)
        winner_executor_returning.set()
        evidence_ref = f"evidence:{node_id}"
        return GraphToolResult(
            output="material primitive",
            evidence_refs=(evidence_ref,),
            progress_receipts=(
                ProgressReceipt(
                    kind=ProgressKind.PRIMITIVE_CONFIRMED,
                    value="bounded primitive",
                    evidence_ref=evidence_ref,
                    source=ProgressSource.TARGET_OBSERVATION,
                ),
            ),
        )

    validator = _EvidenceValidator(
        {
            f"evidence:{winner}": _EvidenceRecord(
                evidence_id=f"evidence:{winner}",
                target_identity="target:race",
                producer_node_id=winner,
            ),
            f"evidence:{loser}": _EvidenceRecord(
                evidence_id=f"evidence:{loser}",
                target_identity="target:race",
                producer_node_id=loser,
            ),
        }
    )
    resolver = GraphRuntimeResolver(
        default_complete=complete,
        default_execute=execute,
        model_policies={"lane_a": complete, "lane_b": complete},
    )
    run_store = RunStore.open(tmp_path / "run-store.sqlite3")
    run_lease = run_store.acquire_lease(
        run_id="race-workspace",
        owner_id="race-worker",
        ttl_seconds=3600,
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=complete,
        execute=execute,
        proof_gate=_RejectProof(),
        runtime_resolver=resolver,
        evidence_validator=validator,
        run_store=run_store,
        run_lease=run_lease,
    )

    loser_task = asyncio.create_task(worker.step(loser))
    await asyncio.wait_for(loser_model_started.wait(), timeout=2)
    winner_result = await asyncio.wait_for(worker.step(winner), timeout=2)
    assert winner_result.kind is WorkerStepKind.EXECUTED, winner_result
    loser_result = await asyncio.wait_for(loser_task, timeout=2)
    results = (winner_result, loser_result)

    assert {result.kind for result in results} == {
        WorkerStepKind.EXECUTED,
        WorkerStepKind.RACE_LOST,
    }
    assert executor_calls == [winner]
    assert coordinator.state.model_requests_started == TWO_LANES
    assert coordinator.state.model_requests_completed == TWO_LANES
    assert coordinator.state.spent_cost_usd == pytest.approx(0.02)
    assert coordinator.state.race_groups[group.group_id].winner_node_id == winner
    assert coordinator.state.nodes[loser].status is GraphNodeStatus.STOPPED
    actions = run_store.actions("race-workspace")
    assert {action.node_id: action.lifecycle for action in actions} == {
        winner: ActionLifecycle.SETTLED,
        loser: ActionLifecycle.CANCELLED,
    }
    assert run_store.unreconciled_actions("race-workspace") == ()
