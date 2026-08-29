from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.coordinator import (
    DuplicateGraphObjectiveError,
    GraphBudgetExceededError,
    GraphConcurrencyLimitError,
    GraphCoordinator,
    GraphLifecycleError,
    GraphNodeLimitError,
)
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphAgentRole,
    GraphLimits,
    GraphMessageKind,
    GraphNodeStatus,
    GraphObjective,
    GraphState,
    GraphStateError,
    GraphStatus,
    Hypothesis,
)

if TYPE_CHECKING:
    from pathlib import Path

EXPECTED_ROOT_AND_CHILD_COUNT = 2
CURRENT_GRAPH_STATE_VERSION = 4


def _objective(
    instruction: str,
    *,
    evidence_refs: tuple[str, ...] = ("evidence:base",),
) -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction=instruction,
        endpoint="/search",
        inputs=("query",),
        strategy="differential",
        expected_signal=f"target-observed result for {instruction}",
        evidence_refs=evidence_refs,
    )


def _coordinator(
    *,
    state_path: Path | None = None,
    limits: GraphLimits | None = None,
    clock: object | None = None,
) -> GraphCoordinator:
    kwargs: dict[str, object] = {
        "graph_id": "graph-test",
        "root_objective": _objective("coordinate route"),
        "limits": limits or GraphLimits(),
        "root_lease_limit": 3,
        "state_path": state_path,
    }
    if clock is not None:
        kwargs["clock"] = clock
    return GraphCoordinator.start(**kwargs)  # type: ignore[arg-type]


def test_graph_starts_with_durable_root_snapshot(tmp_path: Path) -> None:
    state_path = tmp_path / "graph.json"

    coordinator = _coordinator(state_path=state_path)

    assert coordinator.state.status is GraphStatus.RUNNING
    assert coordinator.state.root_node_id == "node-001"
    assert coordinator.state.nodes["node-001"].status is GraphNodeStatus.RUNNING
    assert state_path.exists()
    loaded = GraphState.load(state_path)
    assert loaded.to_json() == coordinator.state.to_json()
    assert not tuple(tmp_path.glob(".*.tmp"))


@pytest.mark.asyncio
async def test_graph_snapshot_persists_agent_specs_and_hypotheses(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "graph.json"
    coordinator = _coordinator(state_path=state_path)
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="critic",
        objective=_objective("falsify the response differential"),
        agent_spec=AgentSpec.create(role=GraphAgentRole.CRITIC),
    )

    loaded = GraphState.load(state_path)
    loaded_root = loaded.nodes["node-001"]
    loaded_child = loaded.nodes[child.node_id]

    assert loaded.to_json()["version"] == CURRENT_GRAPH_STATE_VERSION
    assert loaded_root.agent_spec.role is GraphAgentRole.COORDINATOR
    assert loaded_root.hypothesis is None
    assert loaded_child.agent_spec.role is GraphAgentRole.CRITIC
    assert loaded_child.hypothesis is not None
    assert loaded_child.hypothesis.objective_fingerprint == loaded_child.objective.fingerprint


@pytest.mark.asyncio
async def test_graph_state_v2_migrates_to_typed_v3_defaults() -> None:
    coordinator = _coordinator()
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="legacy-specialist",
        objective=_objective("test a legacy route"),
    )
    payload = coordinator.state.to_json()
    payload["version"] = 2
    raw_nodes = payload["nodes"]
    assert isinstance(raw_nodes, list)
    for raw_node in raw_nodes:
        assert isinstance(raw_node, dict)
        raw_node.pop("agent_spec")
        raw_node.pop("hypothesis")

    migrated = GraphState.from_json(payload)

    assert migrated.to_json()["version"] == CURRENT_GRAPH_STATE_VERSION
    assert migrated.nodes["node-001"].agent_spec.role is GraphAgentRole.COORDINATOR
    migrated_child = migrated.nodes[child.node_id]
    assert migrated_child.agent_spec.role is GraphAgentRole.SPECIALIST
    assert migrated_child.hypothesis is not None
    assert migrated_child.hypothesis.objective_fingerprint == migrated_child.objective.fingerprint


@pytest.mark.parametrize("missing_field", ["agent_spec", "hypothesis"])
def test_graph_state_v3_rejects_missing_typed_identity_field(
    missing_field: str,
) -> None:
    payload = _coordinator().state.to_json()
    raw_nodes = payload["nodes"]
    assert isinstance(raw_nodes, list)
    raw_root = raw_nodes[0]
    assert isinstance(raw_root, dict)
    raw_root.pop(missing_field)

    with pytest.raises(GraphStateError, match=missing_field.replace("_", " ")):
        GraphState.from_json(payload)


@pytest.mark.asyncio
async def test_spawn_rejects_hypothesis_objective_mismatch_before_mutation() -> None:
    coordinator = _coordinator()
    objective = _objective("test a bounded response differential")
    mismatched = Hypothesis.from_objective(_objective("test a different response differential"))
    next_sequence = coordinator.state.next_node_sequence

    with pytest.raises(GraphLifecycleError, match="bind the spawned objective"):
        await coordinator.spawn_node(
            parent_id="node-001",
            name="mismatched",
            objective=objective,
            hypothesis=mismatched,
        )

    assert len(coordinator.state.nodes) == 1
    assert coordinator.state.next_node_sequence == next_sequence


@pytest.mark.asyncio
async def test_settled_turn_can_yield_for_global_redispatch() -> None:
    coordinator = _coordinator()

    yielded = await coordinator.yield_node_turn("node-001")

    assert yielded.status is GraphNodeStatus.READY
    restarted = await coordinator.start_node("node-001")
    assert restarted.status is GraphNodeStatus.RUNNING


@pytest.mark.asyncio
async def test_spawn_rejects_duplicate_objective_route_wide() -> None:
    coordinator = _coordinator()
    first = await coordinator.spawn_node(
        parent_id="node-001",
        name="first",
        objective=_objective(
            "test quote boundary",
            evidence_refs=("evidence:first",),
        ),
    )

    with pytest.raises(DuplicateGraphObjectiveError):
        await coordinator.spawn_node(
            parent_id=first.node_id,
            name="duplicate",
            objective=_objective(
                "test quote boundary",
                evidence_refs=("evidence:different",),
            ),
        )

    assert len(coordinator.state.nodes) == EXPECTED_ROOT_AND_CHILD_COUNT
    assert coordinator.state.model_requests_started == 0


@pytest.mark.asyncio
async def test_spawn_rejects_second_active_auth_transition_owner() -> None:
    coordinator = _coordinator()
    first = await coordinator.spawn_node(
        parent_id="node-001",
        name="auth-owner",
        objective=GraphObjective.create(
            family="authentication",
            instruction="Own the finite SQL authentication transition.",
            endpoint="https://target.test/login/",
            inputs=("username", "password"),
            strategy="sqli_auth_transition",
            expected_signal="protected same-session access or finite exhaustion",
        ),
    )

    with pytest.raises(
        DuplicateGraphObjectiveError,
        match="active semantic objective owner",
    ):
        await coordinator.spawn_node(
            parent_id="node-001",
            name="duplicate-auth-owner",
            objective=GraphObjective.create(
                family="Authentication",
                instruction="Try a differently worded auth closure objective.",
                endpoint="https://TARGET.test/login",
                inputs=("password", "username"),
                strategy="SQLI AUTH TRANSITION",
                expected_signal="authenticated dashboard access or typed disproof",
            ),
        )

    assert first.status is GraphNodeStatus.READY
    assert len(coordinator.state.nodes) == EXPECTED_ROOT_AND_CHILD_COUNT
    assert coordinator.state.model_requests_started == 0


@pytest.mark.asyncio
async def test_terminal_auth_owner_allows_new_material_owner() -> None:
    coordinator = _coordinator()
    first = await coordinator.spawn_node(
        parent_id="node-001",
        name="auth-owner",
        objective=GraphObjective.create(
            family="authentication",
            instruction="Own the first finite SQL authentication transition.",
            endpoint="/login",
            inputs=("username", "password"),
            strategy="sqli_auth_transition",
            expected_signal="protected same-session access or finite exhaustion",
        ),
    )
    await coordinator.finish_node(first.node_id, summary="first matrix exhausted")

    second = await coordinator.spawn_node(
        parent_id="node-001",
        name="new-auth-owner",
        objective=GraphObjective.create(
            family="authentication",
            instruction="Own a materially changed authentication transition.",
            endpoint="/login/",
            inputs=("password", "username"),
            strategy="sqli_auth_transition",
            expected_signal="new protected transition or typed disproof",
        ),
    )

    assert second.status is GraphNodeStatus.READY


@pytest.mark.asyncio
async def test_node_and_concurrency_caps_are_enforced() -> None:
    coordinator = _coordinator(
        limits=GraphLimits(max_nodes=3, max_concurrent_nodes=2),
    )
    first = await coordinator.spawn_node(
        parent_id="node-001",
        name="first",
        objective=_objective("first task"),
    )
    second = await coordinator.spawn_node(
        parent_id="node-001",
        name="second",
        objective=_objective("second task"),
    )

    with pytest.raises(GraphNodeLimitError):
        await coordinator.spawn_node(
            parent_id="node-001",
            name="third",
            objective=_objective("third task"),
        )

    await coordinator.start_node(first.node_id)
    with pytest.raises(GraphConcurrencyLimitError):
        await coordinator.start_node(second.node_id)

    await coordinator.park_node("node-001")
    started = await coordinator.start_node(second.node_id)
    assert started.status is GraphNodeStatus.RUNNING


@pytest.mark.asyncio
async def test_waiting_node_wakes_on_structured_message() -> None:
    coordinator = _coordinator()
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="observer",
        objective=_objective("inspect response shape"),
    )
    await coordinator.start_node(child.node_id)
    wait_task = asyncio.create_task(
        coordinator.wait_for_messages(child.node_id, timeout_seconds=1),
    )
    await asyncio.sleep(0)

    sent = await coordinator.send_message(
        sender_id="node-001",
        target_id=child.node_id,
        kind=GraphMessageKind.INSTRUCTION,
        body={"action": "compare", "endpoint": "/search"},
        evidence_refs=("evidence:request-1",),
    )
    received = await wait_task

    assert [message.message_id for message in received] == [sent.message_id]
    assert received[0].body == {"action": "compare", "endpoint": "/search"}
    assert received[0].evidence_refs == ("evidence:request-1",)
    assert coordinator.state.nodes[child.node_id].status is GraphNodeStatus.RUNNING
    assert not coordinator.state.pending_messages(child.node_id)


@pytest.mark.asyncio
async def test_wait_timeout_keeps_node_parked_until_real_message() -> None:
    coordinator = _coordinator()

    received = await coordinator.wait_for_messages(
        "node-001",
        timeout_seconds=0,
    )

    assert received == ()
    assert coordinator.state.nodes["node-001"].status is GraphNodeStatus.WAITING
    assert coordinator.state.last_reason == "node_wait_timeout:node-001"


@pytest.mark.asyncio
async def test_parent_cannot_finish_while_child_is_active() -> None:
    coordinator = _coordinator()
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="specialist",
        objective=_objective("test integer coercion"),
    )

    with pytest.raises(GraphLifecycleError, match="active descendants"):
        await coordinator.finish_node("node-001", summary="premature")

    await coordinator.finish_node(
        child.node_id,
        summary="integer coercion was disproved",
        evidence_refs=("evidence:negative-1",),
    )
    messages = await coordinator.consume_messages("node-001")
    assert len(messages) == 1
    assert messages[0].kind is GraphMessageKind.COMPLETION
    assert messages[0].evidence_refs == ("evidence:negative-1",)

    await coordinator.finish_node("node-001", summary="route exhausted")
    assert coordinator.state.status is GraphStatus.EXHAUSTED
    assert not coordinator.state.active_nodes


@pytest.mark.asyncio
async def test_stop_node_cascades_without_leaving_orphans() -> None:
    coordinator = _coordinator()
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="child",
        objective=_objective("child task"),
    )
    grandchild = await coordinator.spawn_node(
        parent_id=child.node_id,
        name="grandchild",
        objective=_objective("grandchild task"),
    )

    await coordinator.stop_node(child.node_id, reason="route superseded")

    assert coordinator.state.nodes[child.node_id].status is GraphNodeStatus.STOPPED
    assert coordinator.state.nodes[grandchild.node_id].status is GraphNodeStatus.STOPPED
    assert coordinator.state.nodes["node-001"].status is GraphNodeStatus.RUNNING


@pytest.mark.asyncio
async def test_resume_charges_interrupted_request_once(tmp_path: Path) -> None:
    state_path = tmp_path / "graph.json"
    coordinator = _coordinator(state_path=state_path)
    request_id = await coordinator.begin_model_request(
        "node-001",
        request_id="request-before-crash",
    )
    assert request_id == "request-before-crash"

    resumed = GraphCoordinator.load(state_path)

    root = resumed.state.nodes["node-001"]
    assert root.pending_model_request_id is None
    assert root.model_requests_started == 1
    assert root.model_requests_completed == 1
    assert root.interrupted_model_requests == 1
    assert root.lease_used == 1
    assert root.status is GraphNodeStatus.READY
    assert resumed.state.interrupted_model_requests == 1

    loaded_again = GraphCoordinator.load(state_path)
    assert loaded_again.state.interrupted_model_requests == 1
    assert loaded_again.state.model_requests_completed == 1


@pytest.mark.asyncio
async def test_global_model_budget_stops_every_active_node() -> None:
    coordinator = _coordinator(
        limits=GraphLimits(
            max_model_requests=1,
            proof_reserve_model_requests=0,
        ),
    )
    request_id = await coordinator.begin_model_request("node-001")
    await coordinator.complete_model_request(
        "node-001",
        request_id=request_id,
        cost_usd=0.01,
    )

    with pytest.raises(GraphBudgetExceededError, match="request budget"):
        await coordinator.begin_model_request("node-001")

    assert coordinator.state.status is GraphStatus.REQUEST_BUDGET_EXHAUSTED
    assert not coordinator.state.active_nodes
    assert coordinator.state.model_requests_started == 1


@pytest.mark.asyncio
async def test_cost_budget_is_enforced_after_accounted_completion() -> None:
    coordinator = _coordinator(
        limits=GraphLimits(max_cost_usd=0.1),
    )
    request_id = await coordinator.begin_model_request("node-001")

    await coordinator.complete_model_request(
        "node-001",
        request_id=request_id,
        cost_usd=0.1,
    )

    assert coordinator.state.status is GraphStatus.COST_BUDGET_EXHAUSTED
    assert coordinator.state.spent_cost_usd == pytest.approx(0.1)
    assert not coordinator.state.active_nodes


@pytest.mark.asyncio
async def test_global_tool_budget_stops_graph_before_extra_call() -> None:
    coordinator = _coordinator(
        limits=GraphLimits(max_tool_calls=1),
    )
    call_id = await coordinator.begin_tool_call("node-001")
    await coordinator.complete_tool_call("node-001", call_id=call_id)

    with pytest.raises(GraphBudgetExceededError, match="tool call budget"):
        await coordinator.begin_tool_call("node-001")

    assert coordinator.state.status is GraphStatus.TOOL_BUDGET_EXHAUSTED
    assert coordinator.state.tool_calls_started == 1
    assert not coordinator.state.active_nodes


@pytest.mark.asyncio
async def test_wall_budget_is_checked_before_spending() -> None:
    now = [100.0]
    coordinator = _coordinator(
        limits=GraphLimits(max_wall_seconds=5),
        clock=lambda: now[0],
    )
    now[0] = 105.0

    with pytest.raises(GraphBudgetExceededError, match="wall time"):
        await coordinator.begin_model_request("node-001")

    assert coordinator.state.status is GraphStatus.WALL_TIME_EXHAUSTED
    assert coordinator.state.model_requests_started == 0


@pytest.mark.asyncio
async def test_solve_requires_proof_and_stops_all_nodes() -> None:
    coordinator = _coordinator()
    await coordinator.spawn_node(
        parent_id="node-001",
        name="proof-worker",
        objective=_objective("close proof"),
    )

    with pytest.raises(GraphLifecycleError, match="proof evidence"):
        await coordinator.solve(proof_evidence_refs=())

    await coordinator.solve(proof_evidence_refs=("evidence:flag-response",))
    assert coordinator.state.status is GraphStatus.SOLVED
    assert coordinator.state.proof_evidence_refs == ("evidence:flag-response",)
    assert not coordinator.state.active_nodes


@pytest.mark.asyncio
async def test_non_flag_root_finishes_after_findings_or_bounded_coverage() -> None:
    root = GraphObjective.create(
        family="graph_coordination",
        instruction="Coordinate ordinary vulnerability assessment coverage",
        strategy="evidence_gated_finding_graph",
        expected_signal="confirmed findings or bounded coverage",
    )
    coordinator = GraphCoordinator.start(
        graph_id="graph-finding-mission",
        root_objective=root,
    )

    await coordinator.finish_node(
        coordinator.state.root_node_id,
        summary="all finite routes covered; confirmed findings preserved",
    )

    assert coordinator.state.status is GraphStatus.EXHAUSTED
    assert coordinator.state.last_reason == (
        "root_completed_after_findings_or_bounded_coverage"
    )
    assert coordinator.state.proof_evidence_refs == ()


@pytest.mark.asyncio
async def test_solve_preserves_inflight_request_until_cost_settlement(
    tmp_path: Path,
) -> None:
    coordinator = _coordinator(state_path=tmp_path / "graph.json")
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="inflight-worker",
        objective=_objective("inflight sibling"),
    )
    await coordinator.start_node(child.node_id)
    request_id = await coordinator.begin_model_request(child.node_id)

    await coordinator.solve(proof_evidence_refs=("evidence:flag-response",))

    pending = coordinator.state.nodes[child.node_id]
    assert coordinator.state.status is GraphStatus.SOLVED
    assert pending.status is GraphNodeStatus.STOPPED
    assert pending.pending_model_request_id == request_id
    assert pending.model_requests_completed == 0
    assert pending.interrupted_model_requests == 0

    await coordinator.complete_model_request(
        child.node_id,
        request_id=request_id,
        cost_usd=0.25,
    )

    settled = coordinator.state.nodes[child.node_id]
    assert settled.pending_model_request_id is None
    assert settled.model_requests_completed == 1
    assert settled.interrupted_model_requests == 0
    assert settled.spent_cost_usd == pytest.approx(0.25)
    assert coordinator.state.last_reason == "trusted_proof_confirmed"


@pytest.mark.asyncio
async def test_solved_snapshot_reconciles_interrupted_settlement_on_load(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "graph.json"
    coordinator = _coordinator(state_path=state_path)
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="inflight-worker",
        objective=_objective("inflight sibling"),
    )
    await coordinator.start_node(child.node_id)
    await coordinator.begin_model_request(child.node_id)
    await coordinator.solve(proof_evidence_refs=("evidence:flag-response",))

    resumed = GraphCoordinator.load(state_path)

    settled = resumed.state.nodes[child.node_id]
    assert resumed.state.status is GraphStatus.SOLVED
    assert resumed.state.last_reason == "trusted_proof_confirmed"
    assert settled.pending_model_request_id is None
    assert settled.model_requests_completed == 1
    assert settled.interrupted_model_requests == 1


def test_load_rejects_corrupt_global_accounting(tmp_path: Path) -> None:
    state_path = tmp_path / "graph.json"
    _coordinator(state_path=state_path)
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["model_requests_started"] = 1
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(GraphStateError, match="global model accounting"):
        GraphCoordinator.load(state_path)
