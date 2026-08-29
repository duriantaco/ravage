from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.models import GraphObjective
from ravage.agent_core.autonomous_graph.protocol import GraphWorkerAction
from ravage.agent_core.autonomous_graph.runtime import (
    HostGraphProcessBackend,
    PersistentGraphRuntime,
    ProcessStatus,
)
from ravage.agent_core.autonomous_graph.runtime_tools import (
    GraphRuntimeExecutor,
    RuntimeToolError,
)
from ravage.agent_core.autonomous_graph.scheduler import (
    ProgressiveGraphScheduler,
)
from ravage.agent_core.autonomous_graph.sessions import GraphSessionStore
from ravage.agent_core.autonomous_graph.worker import (
    GraphModelReply,
    GraphWorker,
    ProofGateResult,
    WorkerStepKind,
)

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
EXPECTED_TOOL_CALLS = 3
EXPECTED_READ_ACTIONS = 2
PROCESS_SETTLE_ATTEMPTS = 200


def _objective() -> GraphObjective:
    return GraphObjective.create(
        family="runtime",
        instruction="operate a persistent scoped process",
        strategy="interactive_process",
        expected_signal="bounded process observation",
    )


def _execute(tool: str, arguments: dict[str, object]) -> str:
    return json.dumps(
        {
            "kind": "execute",
            "payload": {
                "tool": tool,
                "arguments": arguments,
                "expected_signal": "persistent process state",
            },
        }
    )


class QueuedModel:
    def __init__(self, replies: list[str]) -> None:
        self.replies = replies

    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        del node_id, messages
        return GraphModelReply(content=self.replies.pop(0))


class RejectProof:
    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        del node_id, evidence_refs
        return ProofGateResult(accepted=False, reason="not proof")


def _runtime(tmp_path: Path) -> PersistentGraphRuntime:
    return PersistentGraphRuntime(
        backend=HostGraphProcessBackend(tmp_path / "tool-workspace"),
        target_url=TARGET_URL,
        manifest_path=tmp_path / "runtime.json",
    )


def test_runtime_executor_requires_isolation_by_default(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        with pytest.raises(RuntimeToolError, match="network isolation"):
            GraphRuntimeExecutor(runtime)
    finally:
        runtime.close()


@pytest.mark.asyncio
async def test_worker_uses_same_named_process_across_model_turns(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    executor = GraphRuntimeExecutor(
        runtime,
        require_network_isolation=False,
    )
    model = QueuedModel(
        [
            _execute(
                "process_start",
                {
                    "name": "shell",
                    "command": (
                        "python3 -u -c 'import sys; "
                        'print("ready", flush=True); '
                        "line=sys.stdin.readline(); "
                        'print("echo:"+line.strip(), flush=True)\''
                    ),
                },
            ),
            _execute(
                "process_write",
                {"name": "shell", "data": "hello\n"},
            ),
            _execute("process_read", {"name": "shell"}),
        ]
    )
    coordinator = GraphCoordinator.start(
        graph_id="runtime-tools-test",
        root_objective=_objective(),
        root_lease_limit=3,
    )
    sessions = GraphSessionStore.open(tmp_path / "sessions")
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=sessions,
        complete=model,
        execute=executor,
        proof_gate=RejectProof(),
    )
    try:
        started = await worker.step("node-001")
        written = await worker.step("node-001")
        for _ in range(PROCESS_SETTLE_ATTEMPTS):
            process = runtime.state.sessions["shell"]
            if process.status is ProcessStatus.EXITED and process.stdout_bytes > 0:
                break
            await asyncio.sleep(0.01)
        else:
            message = "interactive process did not persist its output"
            raise AssertionError(message)
        read = await worker.step("node-001")

        assert started.kind is WorkerStepKind.EXECUTED
        assert written.kind is WorkerStepKind.EXECUTED
        assert read.kind is WorkerStepKind.EXECUTED
        tool_records = [
            record.content for record in sessions.records("node-001") if record.role.value == "tool"
        ]
        read_payload = json.loads(tool_records[-1])
        assert read_payload["operation"] == "process_read"
        assert "ready" in read_payload["stdout"]
        assert "echo:hello" in read_payload["stdout"]
        assert coordinator.state.tool_calls_completed == EXPECTED_TOOL_CALLS
    finally:
        runtime.close()


@pytest.mark.asyncio
async def test_multiple_process_reads_are_bounded_by_watchdog_not_dedup() -> None:
    coordinator = GraphCoordinator.start(
        graph_id="runtime-read-test",
        root_objective=_objective(),
    )
    scheduler = ProgressiveGraphScheduler(coordinator)
    action_payload = {
        "kind": "execute",
        "payload": {
            "tool": "process_read",
            "arguments": {"name": "shell"},
            "expected_signal": "new output",
        },
    }
    action = GraphWorkerAction.from_json(action_payload)
    first = await scheduler.register_action("node-001", action)
    call_id = await coordinator.begin_tool_call("node-001")
    await coordinator.complete_tool_call("node-001", call_id=call_id)
    second = await scheduler.register_action("node-001", action)

    assert first != second
    assert len(coordinator.state.semantic_action_counts) == EXPECTED_READ_ACTIONS
