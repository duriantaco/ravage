from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphAgentRole,
    GraphLimits,
    GraphMessageKind,
    GraphObjective,
    GraphStatus,
)
from ravage.agent_core.autonomous_graph.run_store import (
    ActionLifecycle,
    RunStore,
)
from ravage.agent_core.autonomous_graph.runtime_binding import (
    GraphRuntimeResolver,
)
from ravage.agent_core.autonomous_graph.scheduler import (
    ProgressiveGraphScheduler,
    ProgressKind,
    ProgressReceipt,
    ProgressSource,
)
from ravage.agent_core.autonomous_graph.sessions import (
    GraphSessionStore,
    SessionRole,
)
from ravage.agent_core.autonomous_graph.worker import (
    GraphDurabilityError,
    GraphModelReply,
    GraphRunner,
    GraphToolResult,
    GraphWorker,
    ProofGateResult,
    WorkerStepKind,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from ravage.agent_core.autonomous_graph.run_store import RunLease

EXTENDED_LEASE = 3
TWO_REQUESTS = 2
GRAPH_RUN_REQUESTS = 4
SHA256_HEX_CHARS = 64


def _objective(instruction: str = "coordinate route") -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction=instruction,
        endpoint="/search",
        inputs=("query",),
        strategy="differential",
        expected_signal=f"target-observed result for {instruction}",
        evidence_refs=("evidence:base",),
    )


def _action(kind: str, payload: dict[str, object]) -> str:
    return json.dumps({"kind": kind, "payload": payload})


class QueuedModel:
    def __init__(self, replies: dict[str, list[str]]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, list[dict[str, str]]]] = []

    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        self.calls.append((node_id, messages))
        return GraphModelReply(
            content=self.replies[node_id].pop(0),
            cost_usd=0.01,
        )


class RecordingExecutor:
    def __init__(self, results: list[GraphToolResult] | None = None) -> None:
        self.results = list(results or [GraphToolResult(output="ok")])
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        self.calls.append((node_id, tool, arguments))
        return self.results.pop(0)


class RaisingExecutor(RecordingExecutor):
    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        self.calls.append((node_id, tool, arguments))
        message = "executor connection dropped after dispatch"
        raise RuntimeError(message)


class BlockingExecutor(RecordingExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        self.calls.append((node_id, tool, arguments))
        self.entered.set()
        await self.release.wait()
        return GraphToolResult(output="blocking executor completed")


class StaticProofGate:
    def __init__(self, result: ProofGateResult | None = None) -> None:
        self.result = result or ProofGateResult(
            accepted=False,
            reason="not verified",
        )
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        self.calls.append((node_id, evidence_refs))
        return self.result


@dataclass(frozen=True)
class StaticEvidenceRecord:
    evidence_id: str
    target_identity: str
    producer_node_id: str
    kind: str
    source: str
    material: bool = True


class StaticEvidenceValidator:
    target_identity = "target:test"

    def __init__(
        self,
        trusted_refs: tuple[str, ...],
        *,
        kind: str = "response_differential",
        kinds: Mapping[str, str] | None = None,
        producer_node_id: str = "node-001",
        source: str = "tool_http_request",
    ) -> None:
        self.trusted_refs = frozenset(trusted_refs)
        self.calls: list[tuple[tuple[str, ...], bool]] = []
        self.records = {
            evidence_ref: StaticEvidenceRecord(
                evidence_id=evidence_ref,
                target_identity=self.target_identity,
                producer_node_id=producer_node_id,
                kind=(kinds or {}).get(evidence_ref, kind),
                source=source,
            )
            for evidence_ref in trusted_refs
        }

    def validate_references(
        self,
        evidence_refs: tuple[str, ...],
        *,
        require_trusted: bool = False,
    ) -> tuple[StaticEvidenceRecord, ...]:
        self.calls.append((evidence_refs, require_trusted))
        if require_trusted and not set(evidence_refs) <= self.trusted_refs:
            message = "reference is not trusted"
            raise ValueError(message)
        return tuple(self.records[evidence_ref] for evidence_ref in evidence_refs)


def _worker(  # noqa: PLR0913 - focused test fixture boundary.
    tmp_path: Path,
    *,
    model: QueuedModel,
    executor: RecordingExecutor | None = None,
    proof_gate: StaticProofGate | None = None,
    evidence_validator: StaticEvidenceValidator | None = None,
    limits: GraphLimits | None = None,
    root_lease_limit: int = 3,
    idle_wait_seconds: float = 0.01,
    run_store: RunStore | None = None,
    run_lease: RunLease | None = None,
    assert_run_owned: Callable[[], None] | None = None,
    root_objective: GraphObjective | None = None,
) -> GraphWorker:
    coordinator = GraphCoordinator.start(
        graph_id="worker-test",
        root_objective=root_objective or _objective(),
        limits=limits,
        root_lease_limit=root_lease_limit,
        state_path=tmp_path / "graph.json",
    )
    return GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=model,
        execute=executor or RecordingExecutor(),
        proof_gate=proof_gate or StaticProofGate(),
        evidence_validator=evidence_validator,
        run_store=run_store,
        run_lease=run_lease,
        assert_run_owned=assert_run_owned,
        idle_wait_seconds=idle_wait_seconds,
    )


def _scheduler_progress_state(worker: GraphWorker) -> dict[str, object]:
    state = worker.coordinator.state
    node = state.nodes["node-001"]
    return {
        "lease_limit": node.lease_limit,
        "lease_extensions": node.lease_extensions,
        "evidence_epoch": state.evidence_epoch,
        "trusted_progress_tokens": state.trusted_progress_tokens,
        "disproved_hypothesis_tokens": state.disproved_hypothesis_tokens,
        "proof_eligible": node.proof_eligible,
    }


def test_sessions_are_separate_bounded_and_crash_tolerant(tmp_path: Path) -> None:
    store = GraphSessionStore.open(
        tmp_path / "sessions",
        max_records=2,
        max_content_chars=12,
    )
    store.append("node-001", role=SessionRole.USER, content="first")
    store.append("node-001", role=SessionRole.ASSISTANT, content="second")
    store.append("node-001", role=SessionRole.TOOL, content="third")
    store.append("node-002", role=SessionRole.USER, content="other")
    (tmp_path / "sessions" / "node-001.jsonl").write_text(
        (tmp_path / "sessions" / "node-001.jsonl").read_text(encoding="utf-8") + "{partial",
        encoding="utf-8",
    )

    resumed = GraphSessionStore.open(
        tmp_path / "sessions",
        max_records=2,
        max_content_chars=12,
    )

    assert [item.content for item in resumed.records("node-001")] == [
        "second",
        "third",
    ]
    assert [item.content for item in resumed.records("node-002")] == ["other"]


@pytest.mark.asyncio
async def test_invalid_model_action_spends_no_tool_call(tmp_path: Path) -> None:
    model = QueuedModel({"node-001": ["this is not JSON"]})
    worker = _worker(tmp_path, model=model)

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.INVALID_ACTION
    assert worker.coordinator.state.model_requests_started == 1
    assert worker.coordinator.state.model_requests_completed == 1
    assert worker.coordinator.state.tool_calls_started == 0


@pytest.mark.asyncio
async def test_spawned_discovery_is_typed_but_runtime_policy_stays_trusted(
    tmp_path: Path,
) -> None:
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "spawn",
                    {
                        "name": "filtered-query-critic",
                        "lease_limit": 1,
                        "objective": {
                            "family": "sql_injection",
                            "instruction": "Falsify the filtered-query mechanism",
                            "endpoint": "/search",
                            "inputs": ["query"],
                            "strategy": "critic_counterfactual",
                            "expected_signal": (
                                "controlled response divergence or bounded disproof"
                            ),
                            "evidence_refs": ["evidence:base"],
                        },
                        "hypothesis": {
                            "claim": "The filter changes backend parser semantics",
                            "support_signal": (
                                "one controlled encoding produces stable divergence"
                            ),
                            "falsification_signal": (
                                "all paired controls remain response-equivalent"
                            ),
                            "next_discriminating_test": ("run a bounded paired encoding campaign"),
                            "required_capabilities": ["http_differential"],
                            "basis_evidence_refs": ["evidence:base"],
                        },
                    },
                )
            ]
        }
    )
    worker = _worker(
        tmp_path,
        model=model,
        evidence_validator=StaticEvidenceValidator(("evidence:base",)),
    )

    result = await worker.step("node-001")
    child = worker.coordinator.state.nodes[str(result.spawned_node_id)]

    assert result.kind is WorkerStepKind.SPAWNED
    assert child.hypothesis is not None
    assert child.hypothesis.claim == ("The filter changes backend parser semantics")
    assert child.hypothesis.falsification_signal == (
        "all paired controls remain response-equivalent"
    )
    assert child.hypothesis.objective_fingerprint == child.objective.fingerprint
    assert child.agent_spec.runtime_profile_key == "inherit"
    assert child.agent_spec.tool_policy_key == "inherit"
    assert child.agent_spec.session_policy_key == "fresh_typed"
    assert worker.sessions.records(child.node_id) == ()


@pytest.mark.asyncio
async def test_trusted_agent_spec_selects_sticky_model_executor_and_tool_policy(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="heterogeneous-runtime",
        root_objective=_objective("coordinate heterogeneous workers"),
        limits=GraphLimits(max_concurrent_nodes=2),
        state_path=tmp_path / "graph.json",
    )
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="critic-runtime",
        objective=_objective("falsify the parser hypothesis"),
        lease_limit=1,
        agent_spec=AgentSpec.create(
            role=GraphAgentRole.CRITIC,
            model_policy_key="critic-model",
            runtime_profile_key="isolated-executor",
            tool_policy_key="http-only",
        ),
    )
    default_model = QueuedModel({})
    critic_model = QueuedModel(
        {
            child.node_id: [
                _action(
                    "execute",
                    {
                        "tool": "http_request",
                        "arguments": {"path": "/search?q=control"},
                        "expected_signal": "controlled response",
                    },
                )
            ]
        }
    )
    default_executor = RecordingExecutor()
    isolated_executor = RecordingExecutor()
    resolver = GraphRuntimeResolver(
        default_complete=default_model,
        default_execute=default_executor,
        model_policies={"critic-model": critic_model},
        runtime_profiles={"isolated-executor": isolated_executor},
        tool_policies={"http-only": frozenset({"http_request"})},
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=default_model,
        execute=default_executor,
        proof_gate=StaticProofGate(),
        runtime_resolver=resolver,
    )

    result = await worker.step(child.node_id)

    assert result.kind is WorkerStepKind.EXECUTED
    assert [call[0] for call in critic_model.calls] == [child.node_id]
    assert default_model.calls == []
    assert [call[1] for call in isolated_executor.calls] == ["http_request"]
    assert default_executor.calls == []


@pytest.mark.asyncio
async def test_execute_turn_records_observation_and_progress_lease(
    tmp_path: Path,
) -> None:
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "execute",
                    {
                        "tool": "http_request",
                        "arguments": {"path": "/search?q=%27"},
                        "expected_signal": "SQL differential",
                    },
                )
            ]
        }
    )
    receipt = ProgressReceipt(
        kind=ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
        value="true/false responses diverge",
        evidence_ref="evidence:http-1",
        source=ProgressSource.TARGET_OBSERVATION,
    )
    executor = RecordingExecutor(
        [
            GraphToolResult(
                output="200 true != 200 false",
                observation_digest="digest:http-1",
                progress_receipts=(receipt,),
                evidence_refs=("evidence:http-1",),
            )
        ]
    )
    worker = _worker(
        tmp_path,
        model=model,
        executor=executor,
        evidence_validator=StaticEvidenceValidator(("evidence:http-1",)),
        root_lease_limit=1,
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.EXECUTED
    assert result.lease_decision is not None
    assert result.lease_decision.granted is True
    assert result.observation_decision is not None
    assert result.observation_decision.repeated_count == 1
    assert worker.coordinator.state.nodes["node-001"].lease_limit == EXTENDED_LEASE
    assert worker.coordinator.state.tool_calls_completed == 1


@pytest.mark.asyncio
async def test_incompatible_receipt_evidence_fails_before_scheduler_mutation(
    tmp_path: Path,
) -> None:
    evidence_ref = "evidence:raw-observation"
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "execute",
                    {
                        "tool": "http_request",
                        "arguments": {"path": "/search?q=1"},
                        "expected_signal": "typed hypothesis confirmation",
                    },
                )
            ]
        }
    )
    executor = RecordingExecutor(
        [
            GraphToolResult(
                output="ordinary target response",
                progress_receipts=(
                    ProgressReceipt(
                        kind=ProgressKind.HYPOTHESIS_CONFIRMED,
                        value="claimed confirmation",
                        evidence_ref=evidence_ref,
                        source=ProgressSource.TARGET_OBSERVATION,
                    ),
                ),
                evidence_refs=(evidence_ref,),
            )
        ]
    )
    worker = _worker(
        tmp_path,
        model=model,
        executor=executor,
        evidence_validator=StaticEvidenceValidator(
            (evidence_ref,),
            kind="raw_observation",
        ),
    )
    progress_before = _scheduler_progress_state(worker)

    result = await worker.step("node-001")

    state = worker.coordinator.state
    node = state.nodes["node-001"]
    assert result.kind is WorkerStepKind.TOOL_FAILED
    assert result.reason == "tool_failed:ProgressReceiptValidationError"
    assert _scheduler_progress_state(worker) == progress_before
    assert state.tool_calls_started == 1
    assert state.tool_calls_completed == 1
    assert node.tool_calls_started == 1
    assert node.tool_calls_completed == 1
    assert node.pending_tool_call_id is None


@pytest.mark.asyncio
async def test_support_and_disproof_without_routed_counterfactual_fail_atomically(
    tmp_path: Path,
) -> None:
    support_ref = "evidence:support"
    disproof_ref = "evidence:disproof"
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "execute",
                    {
                        "tool": "http_request",
                        "arguments": {"path": "/search?q=control"},
                        "expected_signal": "support or disproof",
                    },
                )
            ]
        }
    )
    executor = RecordingExecutor(
        [
            GraphToolResult(
                output="internally contradictory progress batch",
                progress_receipts=(
                    ProgressReceipt(
                        kind=ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
                        value="controlled responses differ",
                        evidence_ref=support_ref,
                        source=ProgressSource.TARGET_OBSERVATION,
                    ),
                    ProgressReceipt(
                        kind=ProgressKind.HYPOTHESIS_DISPROVED,
                        value="the same hypothesis was disproved",
                        evidence_ref=disproof_ref,
                        source=ProgressSource.TARGET_OBSERVATION,
                    ),
                ),
                evidence_refs=(support_ref, disproof_ref),
            )
        ]
    )
    worker = _worker(
        tmp_path,
        model=model,
        executor=executor,
        evidence_validator=StaticEvidenceValidator(
            (support_ref, disproof_ref),
            kinds={
                support_ref: "response_differential",
                disproof_ref: "hypothesis_disproved",
            },
        ),
    )
    progress_before = _scheduler_progress_state(worker)

    result = await worker.step("node-001")

    state = worker.coordinator.state
    node = state.nodes["node-001"]
    assert result.kind is WorkerStepKind.TOOL_FAILED
    assert result.reason == "tool_failed:ProgressReceiptValidationError"
    assert _scheduler_progress_state(worker) == progress_before
    assert state.tool_calls_started == 1
    assert state.tool_calls_completed == 1
    assert node.tool_calls_started == 1
    assert node.tool_calls_completed == 1
    assert node.pending_tool_call_id is None


@pytest.mark.asyncio
async def test_trusted_tool_proof_closes_without_spending_a_restatement_turn(
    tmp_path: Path,
) -> None:
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "execute",
                    {
                        "tool": "run_probe",
                        "arguments": {"probe": "bounded_closure"},
                        "expected_signal": "target-returned exact proof",
                    },
                )
            ]
        }
    )
    proof_ref = "evidence:proof-confirmed"
    executor = RecordingExecutor(
        [
            GraphToolResult(
                output="target returned exact proof",
                progress_receipts=(
                    ProgressReceipt(
                        kind=ProgressKind.PROOF_CONFIRMED,
                        value="exact target proof",
                        evidence_ref=proof_ref,
                        source=ProgressSource.TARGET_OBSERVATION,
                    ),
                ),
                evidence_refs=(proof_ref,),
            )
        ]
    )
    gate = StaticProofGate(
        ProofGateResult(
            accepted=True,
            evidence_refs=(proof_ref,),
            reason="executor-owned proof replay passed",
        )
    )
    worker = _worker(
        tmp_path,
        model=model,
        executor=executor,
        proof_gate=gate,
        evidence_validator=StaticEvidenceValidator(
            (proof_ref,),
            kind="proof_confirmed",
        ),
        root_lease_limit=1,
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.PROOF_ACCEPTED
    assert worker.coordinator.state.status is GraphStatus.SOLVED
    assert worker.coordinator.state.proof_evidence_refs == (proof_ref,)
    assert worker.coordinator.state.model_requests_started == 1
    assert gate.calls == [("node-001", (proof_ref,))]


@pytest.mark.asyncio
async def test_trusted_child_progress_notifies_parent_without_model_message(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="automatic-progress-handoff",
        root_objective=_objective("coordinate specialists"),
        limits=GraphLimits(max_concurrent_nodes=2),
        state_path=tmp_path / "graph.json",
    )
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="template-specialist",
        objective=_objective("close template route"),
        lease_limit=1,
    )
    evidence_ref = "evidence:target-progress"
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=QueuedModel(
            {
                child.node_id: [
                    _action(
                        "execute",
                        {
                            "tool": "run_probe",
                            "arguments": {"probe": "bounded_specialist"},
                            "expected_signal": "typed target progress",
                        },
                    )
                ]
            }
        ),
        execute=RecordingExecutor(
            [
                GraphToolResult(
                    output="typed target progress",
                    progress_receipts=(
                        ProgressReceipt(
                            kind=ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
                            value="target branches differ",
                            evidence_ref=evidence_ref,
                            source=ProgressSource.TARGET_OBSERVATION,
                        ),
                    ),
                    evidence_refs=(evidence_ref,),
                )
            ]
        ),
        proof_gate=StaticProofGate(),
        evidence_validator=StaticEvidenceValidator(
            (evidence_ref,),
            producer_node_id=child.node_id,
        ),
    )

    result = await worker.step(child.node_id)
    messages = coordinator.state.pending_messages("node-001")

    assert result.kind is WorkerStepKind.EXECUTED
    assert len(messages) == 1
    assert messages[0].kind.value == "evidence"
    assert messages[0].evidence_refs == (evidence_ref,)
    assert messages[0].body["source_node_id"] == child.node_id


@pytest.mark.asyncio
async def test_trusted_inbox_earns_one_bounded_coordination_turn(
    tmp_path: Path,
) -> None:
    evidence_ref = "evidence:trusted-child-result"
    validator = StaticEvidenceValidator((evidence_ref,))
    model = QueuedModel(
        {
            "node-001": [
                _action("wait", {"timeout_seconds": 0.01}),
                _action("wait", {"timeout_seconds": 0.01}),
            ]
        }
    )
    worker = _worker(
        tmp_path,
        model=model,
        evidence_validator=validator,
        limits=GraphLimits(max_concurrent_nodes=2),
        root_lease_limit=1,
    )
    child = await worker.coordinator.spawn_node(
        parent_id="node-001",
        name="bounded-specialist",
        objective=_objective("produce a trusted child result"),
        lease_limit=1,
    )

    first = await worker.step("node-001")
    await worker.coordinator.send_message(
        sender_id=child.node_id,
        target_id="node-001",
        kind=GraphMessageKind.EVIDENCE,
        body={"summary": "executor-owned progress"},
        evidence_refs=(evidence_ref,),
    )
    second = await worker.step("node-001")

    node = worker.coordinator.state.nodes["node-001"]
    assert first.kind is WorkerStepKind.WAITED
    assert second.kind is WorkerStepKind.WAITED
    assert node.lease_limit == TWO_REQUESTS
    assert node.lease_extensions == 1
    assert node.model_requests_started == TWO_REQUESTS
    assert worker.coordinator.state.pending_messages("node-001") == ()
    assert evidence_ref in json.dumps(model.calls[-1][1])
    assert validator.calls[-1] == ((evidence_ref,), True)


@pytest.mark.asyncio
async def test_untrusted_inbox_cannot_extend_or_consume_exhausted_lease(
    tmp_path: Path,
) -> None:
    evidence_ref = "evidence:model-only-claim"
    model = QueuedModel({"node-001": [_action("wait", {"timeout_seconds": 0.01})]})
    worker = _worker(
        tmp_path,
        model=model,
        evidence_validator=StaticEvidenceValidator(()),
        limits=GraphLimits(max_concurrent_nodes=2),
        root_lease_limit=1,
    )
    child = await worker.coordinator.spawn_node(
        parent_id="node-001",
        name="untrusted-specialist",
        objective=_objective("produce an untrusted child claim"),
        lease_limit=1,
    )

    first = await worker.step("node-001")
    await worker.coordinator.send_message(
        sender_id=child.node_id,
        target_id="node-001",
        kind=GraphMessageKind.EVIDENCE,
        body={"summary": "model-only claim"},
        evidence_refs=(evidence_ref,),
    )
    second = await worker.step("node-001")

    node = worker.coordinator.state.nodes["node-001"]
    assert first.kind is WorkerStepKind.WAITED
    assert second.kind is WorkerStepKind.LEASE_EXHAUSTED
    assert node.lease_limit == 1
    assert node.lease_extensions == 0
    assert node.model_requests_started == 1
    assert len(worker.coordinator.state.pending_messages("node-001")) == 1


@pytest.mark.asyncio
async def test_duplicate_tool_effect_is_rejected_before_second_execution(
    tmp_path: Path,
) -> None:
    execute_action = _action(
        "execute",
        {
            "tool": "http_request",
            "arguments": {"path": "/same"},
            "expected_signal": "response",
        },
    )
    model = QueuedModel({"node-001": [execute_action, execute_action]})
    executor = RecordingExecutor(
        [
            GraphToolResult(output="first", observation_digest="first"),
            GraphToolResult(output="must not run"),
        ]
    )
    worker = _worker(tmp_path, model=model, executor=executor)

    first = await worker.step("node-001")
    second = await worker.step("node-001")

    assert first.kind is WorkerStepKind.EXECUTED
    assert second.kind is WorkerStepKind.ACTION_REJECTED
    assert len(executor.calls) == 1
    assert worker.coordinator.state.tool_calls_started == 1
    assert worker.coordinator.state.model_requests_started == TWO_REQUESTS


@pytest.mark.asyncio
async def test_proof_submission_can_only_solve_through_gate(
    tmp_path: Path,
) -> None:
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "submit_proof",
                    {"evidence_refs": ["evidence:candidate"]},
                )
            ]
        }
    )
    gate = StaticProofGate(
        ProofGateResult(
            accepted=True,
            evidence_refs=("evidence:replayed-proof",),
            reason="proof replay passed",
        )
    )
    worker = _worker(tmp_path, model=model, proof_gate=gate)

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.PROOF_ACCEPTED
    assert worker.coordinator.state.status is GraphStatus.SOLVED
    assert worker.coordinator.state.proof_evidence_refs == ("evidence:replayed-proof",)
    assert gate.calls == [("node-001", ("evidence:candidate",))]


@pytest.mark.asyncio
async def test_non_flag_graph_rejects_proof_submission_and_keeps_running(
    tmp_path: Path,
) -> None:
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "submit_proof",
                    {"evidence_refs": ["evidence:candidate"]},
                )
            ]
        }
    )
    gate = StaticProofGate(
        ProofGateResult(
            accepted=True,
            evidence_refs=("evidence:replayed-proof",),
        )
    )
    root = GraphObjective.create(
        family="graph_coordination",
        instruction="Coordinate vulnerability findings",
        strategy="evidence_gated_finding_graph",
        expected_signal="confirmed findings or bounded coverage",
    )
    worker = _worker(
        tmp_path,
        model=model,
        proof_gate=gate,
        root_objective=root,
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.ACTION_REJECTED
    assert result.reason == "proof_submission_unavailable_for_vulnerability_assessment"
    assert worker.coordinator.state.status is GraphStatus.RUNNING
    assert gate.calls == []


@pytest.mark.asyncio
async def test_model_failure_creates_crash_receipt_and_accounts_request(
    tmp_path: Path,
) -> None:
    class FailingModel:
        async def __call__(
            self,
            node_id: str,
            messages: list[dict[str, str]],
        ) -> GraphModelReply:
            del node_id, messages
            message = "provider disconnected"
            raise RuntimeError(message)

    coordinator = GraphCoordinator.start(
        graph_id="worker-crash",
        root_objective=_objective(),
        state_path=tmp_path / "graph.json",
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=FailingModel(),
        execute=RecordingExecutor(),
        proof_gate=StaticProofGate(),
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.CRASHED
    assert coordinator.state.status is GraphStatus.FAILED
    assert coordinator.state.model_requests_started == 1
    assert coordinator.state.model_requests_completed == 1
    assert coordinator.state.interrupted_model_requests == 1


@pytest.mark.asyncio
async def test_runner_schedules_child_and_parent_until_explicit_exhaustion(
    tmp_path: Path,
) -> None:
    child_objective = _objective("inspect quote boundary")
    model = QueuedModel(
        {
            "node-001": [
                _action(
                    "spawn",
                    {
                        "name": "quote-specialist",
                        "lease_limit": 2,
                        "objective": {
                            "family": child_objective.family,
                            "instruction": child_objective.instruction,
                            "endpoint": child_objective.endpoint,
                            "inputs": list(child_objective.inputs),
                            "strategy": child_objective.strategy,
                            "expected_signal": child_objective.expected_signal,
                            "evidence_refs": list(child_objective.evidence_refs),
                        },
                    },
                ),
                _action("wait", {"timeout_seconds": 0.01}),
                _action("finish", {"summary": "no proof found"}),
            ],
            "node-002": [
                _action(
                    "finish",
                    {
                        "summary": "quote boundary disproved",
                        "evidence_refs": ["evidence:negative"],
                    },
                )
            ],
        }
    )
    worker = _worker(
        tmp_path,
        model=model,
        limits=GraphLimits(max_concurrent_nodes=2),
        root_lease_limit=3,
        idle_wait_seconds=0.5,
    )

    result = await GraphRunner(worker).run()

    assert result.status is GraphStatus.EXHAUSTED
    assert worker.coordinator.state.model_requests_started == GRAPH_RUN_REQUESTS
    assert any(step.kind is WorkerStepKind.SPAWNED for step in result.steps)
    assert any(
        step.node_id == "node-002" and step.kind is WorkerStepKind.FINISHED for step in result.steps
    )
    assert result.reason == "root_completed_without_proof"


@pytest.mark.asyncio
async def test_runner_terminates_when_all_leases_are_parked(
    tmp_path: Path,
) -> None:
    model = QueuedModel({"node-001": [_action("wait", {"timeout_seconds": 0})]})
    worker = _worker(tmp_path, model=model, root_lease_limit=1)

    result = await GraphRunner(worker).run()

    assert result.status is GraphStatus.EXHAUSTED
    assert result.reason == "graph_deadlock_no_runnable_nodes"
    assert worker.coordinator.state.model_requests_started == 1
    assert any(step.kind is WorkerStepKind.WAITED for step in result.steps)
    assert worker.coordinator.state.nodes["node-001"].status.value == "stopped"


@pytest.mark.asyncio
async def test_runner_drains_inflight_model_receipt_after_proof(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="proof-settlement",
        root_objective=_objective("submit trusted proof"),
        limits=GraphLimits(max_concurrent_nodes=2),
        root_lease_limit=2,
        state_path=tmp_path / "graph.json",
    )
    child = await coordinator.spawn_node(
        parent_id="node-001",
        name="inflight-sibling",
        objective=_objective("inflight sibling"),
        lease_limit=2,
    )
    child_started = asyncio.Event()
    graph_solved = asyncio.Event()
    original_solve = coordinator.solve

    async def solve_and_signal(
        *,
        proof_evidence_refs: tuple[str, ...],
    ) -> None:
        await original_solve(proof_evidence_refs=proof_evidence_refs)
        graph_solved.set()

    coordinator.solve = solve_and_signal  # type: ignore[method-assign]

    class ConcurrentProofModel:
        async def __call__(
            self,
            node_id: str,
            messages: list[dict[str, str]],
        ) -> GraphModelReply:
            del messages
            if node_id == "node-001":
                await child_started.wait()
                content = _action(
                    "submit_proof",
                    {"evidence_refs": ["evidence:candidate"]},
                )
            else:
                child_started.set()
                await graph_solved.wait()
                content = _action("wait", {"timeout_seconds": 0})
            return GraphModelReply(content=content, cost_usd=0.01)

    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=ConcurrentProofModel(),
        execute=RecordingExecutor(),
        proof_gate=StaticProofGate(
            ProofGateResult(
                accepted=True,
                evidence_refs=("evidence:replayed-proof",),
                reason="proof replay passed",
            )
        ),
    )

    result = await GraphRunner(worker).run()

    assert result.status is GraphStatus.SOLVED
    assert coordinator.state.model_requests_started == TWO_REQUESTS
    assert coordinator.state.model_requests_completed == TWO_REQUESTS
    assert coordinator.state.interrupted_model_requests == 0
    assert coordinator.state.spent_cost_usd == pytest.approx(0.02)
    assert coordinator.state.nodes[child.node_id].pending_model_request_id is None
    assert any(
        step.node_id == child.node_id and step.kind is WorkerStepKind.TERMINAL
        for step in result.steps
    )


def _durable_execute_action() -> str:
    return _action(
        "execute",
        {
            "tool": "http_request",
            "arguments": {"path": "/durable"},
            "expected_signal": "one durable target response",
        },
    )


def _durable_store_and_lease(tmp_path: Path) -> tuple[RunStore, RunLease]:
    store = RunStore.open(tmp_path / "run-store.sqlite3")
    lease = store.acquire_lease(
        run_id="workspace-test",
        owner_id="worker-process-1",
        ttl_seconds=3600,
    )
    return store, lease


@pytest.mark.asyncio
async def test_durable_action_settles_and_duplicate_never_reexecutes(
    tmp_path: Path,
) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    executor = RecordingExecutor([GraphToolResult(output="durably observed")])
    ownership_states: list[ActionLifecycle] = []

    def assert_owned() -> None:
        actions = store.actions("workspace-test")
        if actions:
            ownership_states.append(actions[0].lifecycle)

    first = _worker(
        tmp_path / "first",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=executor,
        run_store=store,
        run_lease=lease,
        assert_run_owned=assert_owned,
    )
    first_result = await first.step("node-001")

    action = store.actions("workspace-test")[0]
    assert first_result.kind is WorkerStepKind.EXECUTED
    assert ActionLifecycle.RESERVED in ownership_states
    assert action.lifecycle is ActionLifecycle.SETTLED
    assert action.action_key.startswith("tool:worker-test:node-001:")
    assert "output" not in action.result  # type: ignore[operator]
    assert len(action.result["output_sha256"]) == SHA256_HEX_CHARS  # type: ignore[index,arg-type]
    assert store.unreconciled_actions("workspace-test") == ()

    duplicate_executor = RecordingExecutor()
    second = _worker(
        tmp_path / "second",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=duplicate_executor,
        run_store=store,
        run_lease=lease,
    )
    with pytest.raises(GraphDurabilityError, match="durable_action_already_settled"):
        await second.step("node-001")

    assert duplicate_executor.calls == []
    assert second.coordinator.state.tool_calls_started == 0


@pytest.mark.asyncio
async def test_ownership_assertion_fails_before_durable_start_and_external_effect(
    tmp_path: Path,
) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    executor = RecordingExecutor()

    def reject_ownership() -> None:
        message = "ownership heartbeat failed"
        raise RuntimeError(message)

    worker = _worker(
        tmp_path / "ownership-failure",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=executor,
        run_store=store,
        run_lease=lease,
        assert_run_owned=reject_ownership,
    )

    with pytest.raises(GraphDurabilityError, match="worker_step_start"):
        await worker.step("node-001")

    assert executor.calls == []
    assert store.actions("workspace-test") == ()


@pytest.mark.asyncio
async def test_executor_failure_becomes_unknown_and_cannot_be_retried(
    tmp_path: Path,
) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    failing_executor = RaisingExecutor()
    first = _worker(
        tmp_path / "failure-first",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=failing_executor,
        run_store=store,
        run_lease=lease,
    )

    with pytest.raises(GraphDurabilityError, match="durable_action_outcome_unknown"):
        await first.step("node-001")
    action = store.actions("workspace-test")[0]

    assert action.lifecycle is ActionLifecycle.UNKNOWN_OUTCOME
    assert action.unknown_reason == "executor_or_validation_failed"

    retry_executor = RecordingExecutor()
    second = _worker(
        tmp_path / "failure-second",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=retry_executor,
        run_store=store,
        run_lease=lease,
    )
    with pytest.raises(GraphDurabilityError, match="durable_action_unknown_outcome"):
        await second.step("node-001")

    assert retry_executor.calls == []


@pytest.mark.asyncio
async def test_inflight_durable_action_blocks_a_concurrent_duplicate(
    tmp_path: Path,
) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    blocking_executor = BlockingExecutor()
    first = _worker(
        tmp_path / "inflight-first",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=blocking_executor,
        run_store=store,
        run_lease=lease,
    )
    first_task = asyncio.create_task(first.step("node-001"))
    await blocking_executor.entered.wait()

    duplicate_executor = RecordingExecutor()
    second = _worker(
        tmp_path / "inflight-second",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=duplicate_executor,
        run_store=store,
        run_lease=lease,
    )
    with pytest.raises(GraphDurabilityError, match="durable_action_in_flight"):
        await second.step("node-001")

    assert duplicate_executor.calls == []
    blocking_executor.release.set()
    completed = await first_task
    assert completed.kind is WorkerStepKind.EXECUTED
    assert store.actions("workspace-test")[0].lifecycle is ActionLifecycle.SETTLED
    assert store.unreconciled_actions("workspace-test") == ()


@pytest.mark.asyncio
async def test_durable_records_persist_digests_not_raw_effect_data(tmp_path: Path) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    secret = "secret-token-and-body-7f90"  # noqa: S105 - synthetic leak sentinel.
    action = _action(
        "execute",
        {
            "tool": "http_request",
            "arguments": {
                "headers": {"Authorization": f"Bearer {secret}"},
                "body": secret,
            },
            "expected_signal": secret,
        },
    )
    worker = _worker(
        tmp_path / "sanitized",
        model=QueuedModel({"node-001": [action]}),
        executor=RecordingExecutor([GraphToolResult(output=secret)]),
        run_store=store,
        run_lease=lease,
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.EXECUTED
    durable_action = store.actions("workspace-test")[0]
    persisted = json.dumps(
        {
            "request": durable_action.request,
            "result": durable_action.result,
            "events": [event.payload for event in store.events("workspace-test")],
            "projections": [
                projection.payload
                for projection in store.recovery_snapshot("workspace-test").projections
            ],
        },
        sort_keys=True,
    )
    assert secret not in persisted
    assert "Authorization" not in persisted
    assert "arguments_sha256" in persisted
    assert "output_sha256" in persisted


@pytest.mark.asyncio
async def test_post_settlement_failure_is_fatal_and_remains_unapplied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    worker = _worker(
        tmp_path / "post-settlement-failure",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=RecordingExecutor(
            [GraphToolResult(output="settled", observation_digest="observation-1")]
        ),
        run_store=store,
        run_lease=lease,
    )

    async def fail_observation(_node_id: str, *, digest: str) -> None:
        del digest
        message = "projection write failed"
        raise RuntimeError(message)

    monkeypatch.setattr(worker.scheduler, "record_observation", fail_observation)

    with pytest.raises(GraphDurabilityError, match="settled_but_unapplied"):
        await worker.step("node-001")

    action = store.actions("workspace-test")[0]
    assert action.lifecycle is ActionLifecycle.SETTLED
    assert store.unreconciled_actions("workspace-test") == (action,)


@pytest.mark.asyncio
async def test_graph_runner_propagates_durability_failure(tmp_path: Path) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    worker = _worker(
        tmp_path / "runner-fatal",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        executor=RaisingExecutor(),
        run_store=store,
        run_lease=lease,
    )

    with pytest.raises(GraphDurabilityError, match="durable_action_outcome_unknown"):
        await GraphRunner(worker).run()

    assert store.actions("workspace-test")[0].lifecycle is ActionLifecycle.UNKNOWN_OUTCOME


@pytest.mark.asyncio
async def test_prestart_scheduler_cancellation_closes_durable_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    worker = _worker(
        tmp_path / "scheduler-cancelled",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        run_store=store,
        run_lease=lease,
    )

    async def cancel_registration(_node_id: str, _action: object) -> str:
        raise asyncio.CancelledError

    monkeypatch.setattr(worker.scheduler, "register_action", cancel_registration)

    with pytest.raises(asyncio.CancelledError):
        await worker.step("node-001")

    action = store.actions("workspace-test")[0]
    assert action.lifecycle is ActionLifecycle.CANCELLED
    assert store.unreconciled_actions("workspace-test") == ()


@pytest.mark.asyncio
async def test_investigation_failure_closes_prestart_durable_reservation(
    tmp_path: Path,
) -> None:
    store, lease = _durable_store_and_lease(tmp_path)
    worker = _worker(
        tmp_path / "investigation-failed",
        model=QueuedModel({"node-001": [_durable_execute_action()]}),
        run_store=store,
        run_lease=lease,
    )

    class FailingInvestigation:
        def context_projection(self, **_kwargs: object) -> dict[str, object]:
            return {}

        def authorize_action(self, **_kwargs: object) -> None:
            message = "authorization backend failed"
            raise RuntimeError(message)

    worker.investigation_engine = FailingInvestigation()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="authorization backend failed"):
        await worker.step("node-001")

    action = store.actions("workspace-test")[0]
    assert action.lifecycle is ActionLifecycle.CANCELLED
    assert store.unreconciled_actions("workspace-test") == ()
