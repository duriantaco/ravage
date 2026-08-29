from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.action_bridge import (
    ActionExecution,
    EvidenceGraphExecutor,
)
from ravage.agent_core.autonomous_graph.closure_routing import (
    GraphClosureRouter,
)
from ravage.agent_core.autonomous_graph.context_handoff import (
    FROZEN_BASE_CONTEXT_MARKER,
    INHERITED_CONTEXT_MARKER,
    seed_frozen_base_context,
)
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.evidence import (
    EvidenceBlackboard,
    EvidenceKind,
    EvidenceWorkStatus,
)
from ravage.agent_core.autonomous_graph.models import GraphObjective, GraphStatus
from ravage.agent_core.autonomous_graph.routing import GraphActionRejectedError
from ravage.agent_core.autonomous_graph.scheduler import ProgressiveGraphScheduler
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

TARGET_URL = "http://127.0.0.1:8765"
STORED_HASH = "7d39307ae824e70052c0aa16816a9b16"
ROUTED_TOOL_CALLS = 2
TOTAL_TOOL_CALLS = 3
EXPECTED_NODE_COUNT = 2


def _objective() -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction="Close the confirmed Boolean SQL primitive on the login workflow.",
        endpoint="/index.php",
        inputs=("username", "password"),
        strategy="sqli_exploit",
        expected_signal="authenticated protected access or bounded counter-evidence",
    )


def _execute(tool: str, arguments: dict[str, object]) -> str:
    return json.dumps(
        {
            "kind": "execute",
            "payload": {
                "tool": tool,
                "arguments": arguments,
                "expected_signal": "target-observed closure evidence",
            },
        }
    )


def _calibration_observation() -> str:
    def request(expr: str, body: str, digest: str) -> dict[str, object]:
        return {
            "phase": "boolean_probe",
            "expr": expr,
            "status": 200,
            "body_sha_hint": digest,
            "body_snippet": body,
            "method": "POST",
            "target": {
                "url": "http://target/index.php",
                "input": "username",
                "method": "POST",
            },
        }

    return json.dumps(
        {
            "ok": True,
            "requests": [
                request("1=1", "password", "true"),
                request("1=0", "username", "false"),
                request("2=2", "password", "true"),
                request("2=1", "username", "false"),
            ],
        }
    )


def _run27_observation() -> str:
    stdout = json.dumps(
        {
            "extracted": [
                {
                    "table": "users",
                    "row": 0,
                    "column": "password",
                    "value": STORED_HASH,
                }
            ],
            "login_replay": {
                "username": "admin",
                "password": STORED_HASH,
                "body": '{"response":"password"}',
                "headers": {"Set-Cookie": "PHPSESSID=fresh; path=/"},
            },
        },
        indent=2,
    )
    return json.dumps(
        {
            "command": ["python3", "agent.py"],
            "exit_code": 0,
            "stdout": stdout,
        }
    )


def _auth_observation() -> str:
    return json.dumps(
        {
            "ok": True,
            "probe": "sqli_auth_transition",
            "findings": [
                {
                    "type": "sqli_auth_bypass_session",
                    "capability": "sqli_auth_transition",
                    "username": "admin",
                    "protected_url": "/upload.php",
                    "authenticated": True,
                    "same_session": True,
                }
            ],
        }
    )


def _bounded_extractor_code() -> str:
    return (
        "import requests\n"
        "prefix=''\n"
        "for pos in range(1,33):\n"
        "    expr=f'ascii(substring((select password from users),{pos},1))>64'\n"
        "    requests.post('http://target/index.php', data={'username':expr})\n"
        "    print(f'PREFIX[{pos}]={prefix}')\n"
        "password=extract_with_boolean_oracle()\n"
        "body=requests.post('http://target/index.php', "
        "data={'username':'admin','password':password}).text\n"
        "print('LOGIN_RESPONSE='+body)\n"
    )


class Xben029ActionCall:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        *,
        node_id: str,
        action: dict[str, object],
        action_id: str,
    ) -> ActionExecution:
        del node_id, action_id
        self.calls.append(action)
        if len(self.calls) == 1:
            observation = _calibration_observation()
            source = "tool_run_probe"
        elif len(self.calls) == ROUTED_TOOL_CALLS:
            observation = _run27_observation()
            source = "tool_run_python"
        elif len(self.calls) == TOTAL_TOOL_CALLS:
            observation = _auth_observation()
            source = "tool_run_probe"
        else:
            message = "anti-loop guard failed; unexpected target/tool execution"
            raise AssertionError(message)
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation=observation,
                outcome="observed",
                evidence_source_kind=source,
                evidence_observation=observation,
            ),
            observation_id=f"executor-observation-{len(self.calls)}",
        )


class RepeatingClosureActionCall:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, **_kwargs: object) -> ActionExecution:
        self.calls += 1
        calibration = self.calls == 1
        observation = _calibration_observation() if calibration else _run27_observation()
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation=observation,
                evidence_source_kind=("tool_run_probe" if calibration else "tool_run_python"),
                evidence_observation=observation,
            ),
            observation_id=f"canonical-observation-{self.calls}",
        )


class Xben029Model:
    def __init__(self) -> None:
        self.calls: dict[str, int] = {}
        self.messages: list[tuple[str, list[dict[str, str]]]] = []

    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        self.messages.append((node_id, messages))
        turn = self.calls.get(node_id, 0)
        self.calls[node_id] = turn + 1
        if node_id == "node-001":
            replies = (
                _execute(
                    "run_probe",
                    {"probe": "sqli_differential"},
                ),
                _execute("run_python", {"code": _bounded_extractor_code()}),
            )
            return GraphModelReply(content=replies[turn])
        if turn == 0:
            return GraphModelReply(
                content=_execute("run_python", {"code": _bounded_extractor_code()})
            )
        if turn == 1:
            return GraphModelReply(
                content=_execute(
                    "run_probe",
                    {"probe": "sqli_auth_transition"},
                )
            )

        context = _latest_worker_context(messages)
        auth_refs = [
            item["evidence_id"]
            for item in context["evidence_blackboard"]["material_evidence"]
            if item["kind"] == EvidenceKind.AUTH_STATE_CHANGED.value
        ]
        return GraphModelReply(
            content=json.dumps(
                {
                    "kind": "finish",
                    "payload": {
                        "summary": "Protected same-session authentication transition verified.",
                        "evidence_refs": auth_refs,
                    },
                }
            )
        )


class RejectProof:
    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        del node_id, evidence_refs
        return ProofGateResult(accepted=False, reason="no proof in closure fixture")


class ExhaustingCredentialModel:
    def __init__(self) -> None:
        self.calls: dict[str, int] = {}

    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        del messages
        turn = self.calls.get(node_id, 0)
        self.calls[node_id] = turn + 1
        if node_id == "node-001":
            if turn == 0:
                content = _execute(
                    "run_probe",
                    {"probe": "sqli_differential"},
                )
            elif turn == 1:
                content = _execute(
                    "run_python",
                    {"code": _bounded_extractor_code()},
                )
            else:
                content = json.dumps(
                    {
                        "kind": "finish",
                        "payload": {
                            "summary": "Credential route exhausted without proof.",
                            "evidence_refs": [],
                        },
                    }
                )
            return GraphModelReply(content=content)
        return GraphModelReply(
            content=_execute(
                "run_python",
                {"code": _bounded_extractor_code()},
            )
        )


def _latest_worker_context(messages: list[dict[str, str]]) -> dict[str, object]:
    for message in reversed(messages):
        if message["role"] != "user" or not message["content"].startswith("{"):
            continue
        payload = json.loads(message["content"])
        if isinstance(payload, dict) and "node" in payload:
            return payload
    message = "worker context not found"
    raise AssertionError(message)


@pytest.mark.asyncio
async def test_run27_hash_replay_routes_once_and_forbids_the_same_loop(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="xben-029-closure",
        root_objective=_objective(),
        root_lease_limit=2,
        state_path=tmp_path / "graph.json",
    )
    sessions = GraphSessionStore.open(tmp_path / "sessions")
    base_state = AgentState(
        phase="exploit",
        facts=["Boolean SQL behavior was observed on /index.php."],
        primitives={"sql_injection": 37},
    )
    base_before = base_state.to_json()
    seed_frozen_base_context(
        sessions,
        node_ids=("node-001",),
        state=base_state,
    )
    blackboard = EvidenceBlackboard(
        target_url=TARGET_URL,
        state_path=tmp_path / "evidence.json",
    )
    router = GraphClosureRouter(
        blackboard=blackboard,
        objective_for_node=lambda node_id: coordinator.state.nodes[node_id].objective,
    )
    action_call = Xben029ActionCall()
    executor = EvidenceGraphExecutor(
        blackboard=blackboard,
        action_call=action_call,
        closure_router=router,
    )
    model = Xben029Model()
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=sessions,
        complete=model,
        execute=executor,
        proof_gate=RejectProof(),
        evidence_validator=blackboard,
        action_guard=executor.guard,
        context_provider=blackboard,
    )

    calibrated = await worker.step("node-001")
    routed = await worker.step("node-001")

    assert calibrated.kind is WorkerStepKind.EXECUTED
    assert routed.kind is WorkerStepKind.ROUTED
    assert routed.spawned_node_id == "node-002"
    assert len(action_call.calls) == ROUTED_TOOL_CALLS
    assert base_state.to_json() == base_before
    assert coordinator.state.nodes["node-001"].status.value == "waiting"
    child_records = sessions.records("node-002")
    inherited = "\n".join(record.content for record in child_records)
    assert FROZEN_BASE_CONTEXT_MARKER in inherited
    assert INHERITED_CONTEXT_MARKER in inherited
    assert STORED_HASH in inherited

    blocked = await worker.step("node-002")

    assert blocked.kind is WorkerStepKind.ACTION_REJECTED
    assert "may not be extracted again" in blocked.reason
    assert len(action_call.calls) == ROUTED_TOOL_CALLS
    assert coordinator.state.tool_calls_started == ROUTED_TOOL_CALLS

    with pytest.raises(GraphActionRejectedError, match="replayed unchanged"):
        executor.guard(
            "node-002",
            "run_python",
            {
                "code": (
                    "import requests\n"
                    "requests.post('http://target/index.php', "
                    f"data={{'username':'admin','password':'{STORED_HASH}'}})"
                )
            },
        )

    authenticated = await worker.step("node-002")
    finished = await worker.step("node-002")

    assert authenticated.kind is WorkerStepKind.EXECUTED
    assert authenticated.lease_decision is not None
    assert authenticated.lease_decision.granted is True
    assert finished.kind is WorkerStepKind.FINISHED
    assert len(action_call.calls) == TOTAL_TOOL_CALLS
    assert len(coordinator.state.nodes) == EXPECTED_NODE_COUNT
    assert any(
        record.kind is EvidenceKind.SQL_ORACLE_CALIBRATED
        for record in blackboard.state.records.values()
    )
    assert any(
        record.kind is EvidenceKind.EXTRACTION_CHECKPOINT
        for record in blackboard.state.records.values()
    )
    assert any(
        record.kind is EvidenceKind.CREDENTIAL_REPLAY_REJECTED
        for record in blackboard.state.records.values()
    )
    assert any(
        record.kind is EvidenceKind.AUTH_STATE_CHANGED
        for record in blackboard.state.records.values()
    )
    work_items = tuple(blackboard.state.work_items.values())
    assert len(work_items) == 1
    assert work_items[0].owner_node_id == "node-002"
    assert work_items[0].status is EvidenceWorkStatus.COMPLETED
    assert STORED_HASH not in json.dumps(blackboard.state.to_json())

    child_system_prompts = [
        messages[0]["content"] for node_id, messages in model.messages if node_id == "node-002"
    ]
    assert child_system_prompts
    assert all(
        "credential-representation-and-auth-closure" in item for item in child_system_prompts
    )
    assert all(
        "do not extract or submit that same value again" in item for item in child_system_prompts
    )


@pytest.mark.asyncio
async def test_extraction_without_repeated_oracle_is_quarantined(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="xben-029-no-oracle",
        root_objective=_objective(),
    )
    blackboard = EvidenceBlackboard(
        target_url=TARGET_URL,
        state_path=tmp_path / "evidence.json",
    )
    router = GraphClosureRouter(
        blackboard=blackboard,
        objective_for_node=lambda node_id: coordinator.state.nodes[node_id].objective,
    )

    def action_call(**_kwargs: object) -> ActionExecution:
        observation = _run27_observation()
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation=observation,
                evidence_source_kind="tool_run_python",
                evidence_observation=observation,
            ),
            observation_id="uncalibrated-extraction",
        )

    executor = EvidenceGraphExecutor(
        blackboard=blackboard,
        action_call=action_call,
        closure_router=router,
    )
    result: GraphToolResult = await executor(
        "node-001",
        "run_python",
        {"code": _bounded_extractor_code()},
    )
    visible = json.loads(result.output)

    assert visible["closure_routing"]["extraction_checkpoint"]["status"] == "quarantined"
    assert result.routing_directive is None
    assert not any(
        record.kind is EvidenceKind.EXTRACTION_CHECKPOINT
        for record in blackboard.state.records.values()
    )
    assert blackboard.state.work_items == {}


@pytest.mark.asyncio
async def test_model_authored_python_controls_cannot_create_sql_oracle(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="xben-029-forged-oracle",
        root_objective=_objective(),
    )
    blackboard = EvidenceBlackboard(
        target_url=TARGET_URL,
        state_path=tmp_path / "evidence.json",
    )
    router = GraphClosureRouter(
        blackboard=blackboard,
        objective_for_node=lambda node_id: coordinator.state.nodes[node_id].objective,
    )

    def action_call(**_kwargs: object) -> ActionExecution:
        observation = _calibration_observation()
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation=observation,
                evidence_source_kind="tool_run_python",
                evidence_observation=observation,
            ),
            observation_id="model-authored-controls",
        )

    executor = EvidenceGraphExecutor(
        blackboard=blackboard,
        action_call=action_call,
        closure_router=router,
    )
    result = await executor(
        "node-001",
        "run_python",
        {"code": "print(model_authored_control_json)"},
    )

    assert result.progress_receipts == ()
    assert (
        blackboard.trusted_sql_oracle_refs(
            family="sql_injection",
            endpoint="/index.php",
        )
        == ()
    )
    assert not any(
        record.kind is EvidenceKind.SQL_ORACLE_CALIBRATED
        for record in blackboard.state.records.values()
    )


@pytest.mark.asyncio
async def test_repeated_checkpoint_and_rejection_are_route_wide_canonical(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="xben-029-canonical-closure",
        root_objective=_objective(),
    )
    blackboard = EvidenceBlackboard(
        target_url=TARGET_URL,
        state_path=tmp_path / "evidence.json",
    )
    router = GraphClosureRouter(
        blackboard=blackboard,
        objective_for_node=lambda node_id: coordinator.state.nodes[node_id].objective,
    )
    action_call = RepeatingClosureActionCall()
    executor = EvidenceGraphExecutor(
        blackboard=blackboard,
        action_call=action_call,
        closure_router=router,
    )

    await executor(
        "node-001",
        "run_probe",
        {"probe": "sqli_differential"},
    )
    first = await executor(
        "node-001",
        "run_python",
        {"code": _bounded_extractor_code()},
    )
    repeated = await executor(
        "node-001",
        "run_python",
        {"code": _bounded_extractor_code() + "\n# semantically irrelevant rerun"},
    )

    assert first.routing_directive is not None
    assert repeated.routing_directive is None
    assert repeated.progress_receipts == ()
    assert (
        len(
            [
                record
                for record in blackboard.state.records.values()
                if record.kind is EvidenceKind.EXTRACTION_CHECKPOINT
            ]
        )
        == 1
    )
    assert (
        len(
            [
                record
                for record in blackboard.state.records.values()
                if record.kind is EvidenceKind.CREDENTIAL_REPLAY_REJECTED
            ]
        )
        == 1
    )
    assert len(blackboard.state.work_items) == 1
    directive = first.routing_directive
    assert directive is not None
    blackboard.claim_work(
        work_id=directive.work_id,
        owner_node_id="node-002",
    )
    settled = blackboard.complete_owned_work(
        owner_node_id="node-002",
        result_evidence_refs=directive.evidence_refs,
    )
    assert len(settled) == 1
    assert settled[0].status is EvidenceWorkStatus.FAILED
    assert settled[0].last_reason == "closure_finished_without_conclusive_target_evidence"


@pytest.mark.asyncio
async def test_routed_worker_exhaustion_returns_control_instead_of_deadlocking(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="xben-029-bounded-exhaustion",
        root_objective=_objective(),
        root_lease_limit=2,
        state_path=tmp_path / "graph.json",
    )
    sessions = GraphSessionStore.open(tmp_path / "sessions")
    blackboard = EvidenceBlackboard(
        target_url=TARGET_URL,
        state_path=tmp_path / "evidence.json",
    )
    router = GraphClosureRouter(
        blackboard=blackboard,
        objective_for_node=lambda node_id: coordinator.state.nodes[node_id].objective,
    )
    action_call = Xben029ActionCall()
    executor = EvidenceGraphExecutor(
        blackboard=blackboard,
        action_call=action_call,
        closure_router=router,
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=sessions,
        complete=ExhaustingCredentialModel(),
        execute=executor,
        proof_gate=RejectProof(),
        evidence_validator=blackboard,
        action_guard=executor.guard,
        context_provider=blackboard,
        idle_wait_seconds=0.01,
    )

    result = await GraphRunner(worker).run()

    assert result.status is GraphStatus.EXHAUSTED
    assert result.reason == "root_completed_without_proof"
    assert len(action_call.calls) == ROUTED_TOOL_CALLS
    assert coordinator.state.tool_calls_started == ROUTED_TOOL_CALLS
    assert any(step.kind is WorkerStepKind.LEASE_EXHAUSTED for step in result.steps)
    assert not any("deadlock" in step.reason for step in result.steps)
    work_items = tuple(blackboard.state.work_items.values())
    assert len(work_items) == 1
    assert work_items[0].status is EvidenceWorkStatus.FAILED
    assert work_items[0].last_reason == "progressive_lease_exhausted_without_closure"
