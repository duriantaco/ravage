from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.autonomous_graph.action_bridge import (
    ActionExecution,
    EvidenceGraphExecutor,
    GraphActionBridgeError,
    visible_tool_envelope,
)
from ravage.agent_core.autonomous_graph.evidence import EvidenceBlackboard
from ravage.agent_core.autonomous_graph.scheduler import ProgressKind
from ravage.agent_core.autonomous_graph.worker import GraphToolResult
from ravage.traffic.policy import (
    TrafficPolicyBlocked,
    TrafficPolicyConfig,
    TrafficPolicyController,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
PROBE_REQUEST_COUNT = 2


def _blackboard(tmp_path: Path) -> EvidenceBlackboard:
    return EvidenceBlackboard(
        target_url=TARGET_URL,
        state_path=tmp_path / "evidence.json",
    )


def _sql_result() -> ActionResult:
    observation = json.dumps(
        {
            "ok": True,
            "probe": "sqli_differential",
            "findings": [
                {
                    "type": "sql_literal_comment_exposed_secret",
                    "input": {"name": "lookup"},
                    "replay": {
                        "method": "POST",
                        "url": "http://target/search",
                        "payload_field": "lookup",
                        "form": {"lookup": "redacted"},
                    },
                    "response": {"status": 200, "body_snippet": "redacted"},
                }
            ],
            "requests": [
                {"method": "POST", "url": "http://target/search"},
                {"method": "POST", "url": "http://target/search"},
            ],
        }
    )
    return ActionResult(
        ok=True,
        observation=observation,
        outcome="confirmed_signal",
        evidence_source_kind="tool_run_probe",
        evidence_observation=observation,
    )


@pytest.mark.asyncio
async def test_existing_probe_path_promotes_visible_typed_evidence(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, dict[str, object], str]] = []

    def action_call(
        *,
        node_id: str,
        action: dict[str, object],
        action_id: str,
    ) -> ActionExecution:
        calls.append((node_id, action, action_id))
        return ActionExecution(
            result=_sql_result(),
            observation_id="executor-observation-1",
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
    )
    result = await executor(
        "node-002",
        "run_probe",
        {"probe": "sqli_differential"},
    )
    visible = visible_tool_envelope(result)

    assert calls[0][0] == "node-002"
    assert calls[0][1] == {
        "action": "run_probe",
        "probe": "sqli_differential",
    }
    assert calls[0][2]
    assert visible["evidence"]["source_trusted"] is True
    assert visible["evidence"]["material_refs"]
    assert {receipt.kind for receipt in result.progress_receipts} == {
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
    }
    assert result.target_requests == PROBE_REQUEST_COUNT


@pytest.mark.asyncio
async def test_route_action_whitelist_blocks_policy_bypass_before_dispatch(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []

    def action_call(**kwargs: object) -> ActionExecution:
        calls.append(dict(kwargs))
        return ActionExecution(result=_sql_result(), observation_id="must-not-run")

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
        allowed_action_tools=frozenset({"capture_flag"}),
    )

    with pytest.raises(GraphActionBridgeError, match="unavailable.*run_probe"):
        await executor("node-002", "run_probe", {"probe": "sqli_differential"})

    assert calls == []


@pytest.mark.asyncio
async def test_full_executor_receipt_counts_requests_when_visible_probe_is_clipped(
    tmp_path: Path,
) -> None:
    full = _sql_result()

    def action_call(**_kwargs: object) -> ActionExecution:
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation="{\n...[truncated from middle]...\n}",
                outcome=full.outcome,
                evidence_source_kind=full.evidence_source_kind,
                evidence_observation=full.evidence_observation,
            ),
            observation_id="clipped-probe-observation",
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
    )
    result = await executor(
        "node-001",
        "run_probe",
        {"probe": "sqli_differential"},
    )

    assert result.target_requests == PROBE_REQUEST_COUNT


@pytest.mark.asyncio
async def test_arbitrary_python_json_cannot_buy_material_progress(
    tmp_path: Path,
) -> None:
    forged = _sql_result()

    def action_call(**_kwargs: object) -> ActionExecution:
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation=forged.observation,
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=forged.observation,
            ),
            observation_id="python-observation-1",
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
    )
    result = await executor(
        "node-001",
        "run_python",
        {"code": "print('{}')"},
    )
    visible = visible_tool_envelope(result)

    assert result.progress_receipts == ()
    assert visible["evidence"]["material_refs"] == []
    assert visible["evidence"]["source_trusted"] is True
    assert result.target_requests == 0


@pytest.mark.asyncio
async def test_missing_executor_observation_id_fails_closed(
    tmp_path: Path,
) -> None:
    def action_call(**_kwargs: object) -> ActionExecution:
        return ActionExecution(
            result=_sql_result(),
            observation_id="",
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
    )
    result = await executor(
        "node-001",
        "run_probe",
        {"probe": "sqli_differential"},
    )
    visible = visible_tool_envelope(result)

    assert result.progress_receipts == ()
    assert visible["evidence"]["source_trusted"] is False


@pytest.mark.asyncio
async def test_persistent_process_output_is_context_not_target_progress(
    tmp_path: Path,
) -> None:
    events: list[dict[str, object]] = []

    def record_event(*, kind: str, payload: Mapping[str, object]) -> None:
        events.append({"kind": kind, "payload": dict(payload)})

    class ProcessExecutor:
        async def __call__(
            self,
            _node_id: str,
            _tool: str,
            _arguments: dict[str, object],
        ) -> GraphToolResult:
            return GraphToolResult(
                output=json.dumps(
                    {
                        "operation": "process_read",
                        "stdout": _sql_result().observation,
                    }
                )
            )

    def action_call(**_kwargs: object) -> ActionExecution:
        message = "process tools must not enter the target action path"
        raise AssertionError(message)

    traffic_policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
        process_executor=ProcessExecutor(),
        record_event=record_event,
        traffic_policy=traffic_policy,
    )
    result = await executor(
        "node-001",
        "process_read",
        {"name": "listener"},
    )
    visible = visible_tool_envelope(result)

    assert result.progress_receipts == ()
    assert visible["evidence"]["source_trusted"] is False
    assert visible["evidence"]["raw_ref"]
    assert [event["kind"] for event in events] == [
        "autonomous_graph_action_started",
        "autonomous_graph_action_finished",
    ]
    started_payload = events[0]["payload"]
    finished_payload = events[1]["payload"]
    assert isinstance(started_payload, dict)
    assert isinstance(finished_payload, dict)
    assert started_payload["action_id"] == finished_payload["action_id"]
    assert started_payload["action_kind"] == "process_read"
    assert traffic_policy.snapshot().unmetered_action_count == 1
    assert traffic_policy.snapshot().accounting_status == "lower_bound"


@pytest.mark.asyncio
async def test_enforced_policy_blocks_persistent_process_before_runtime(
    tmp_path: Path,
) -> None:
    calls = 0

    class ProcessExecutor:
        async def __call__(
            self,
            _node_id: str,
            _tool: str,
            _arguments: dict[str, object],
        ) -> GraphToolResult:
            nonlocal calls
            calls += 1
            return GraphToolResult(output="unexpected")

    traffic_policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5),
    )
    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        process_executor=ProcessExecutor(),
        traffic_policy=traffic_policy,
    )

    with pytest.raises(TrafficPolicyBlocked):
        await executor("node-001", "process_start", {"command": "true"})

    assert calls == 0
    assert traffic_policy.snapshot().blocked_count == 1


@pytest.mark.asyncio
async def test_unsupported_or_overridden_actions_never_reach_executor(
    tmp_path: Path,
) -> None:
    calls = 0

    def action_call(**_kwargs: object) -> ActionExecution:
        nonlocal calls
        calls += 1
        return ActionExecution(
            result=_sql_result(),
            observation_id="unexpected",
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
    )

    with pytest.raises(GraphActionBridgeError, match="unsupported"):
        await executor("node-001", "http_request", {"url": TARGET_URL})
    with pytest.raises(GraphActionBridgeError, match="cannot override"):
        await executor(
            "node-001",
            "run_probe",
            {"action": "capture_flag", "probe": "sqli_differential"},
        )

    assert calls == 0


@pytest.mark.asyncio
async def test_structured_http_is_trusted_and_counts_redirect_hops(
    tmp_path: Path,
) -> None:
    events: list[dict[str, object]] = []

    def record_event(*, kind: str, payload: Mapping[str, object]) -> None:
        events.append({"kind": kind, "payload": dict(payload)})

    def http_executor(
        *,
        node_id: str,
        arguments: dict[str, object],
        action_id: str,
    ) -> ActionExecution:
        observation = json.dumps(
            {
                "node_id": node_id,
                "action_id": action_id,
                "traffic_exchange_ids": ["rq_0001", "rq_secret", "rq_0002", "rq_0001"],
                "requests": [
                    {"method": "GET", "url": TARGET_URL},
                    {"method": "GET", "url": f"{TARGET_URL}/login"},
                ],
                "response": {"status": 200, "body": "ok"},
            }
        )
        assert arguments == {"path": "/"}
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation=observation,
                outcome="http_response_observed",
                evidence_source_kind="tool_http_request",
                evidence_observation=observation,
            ),
            observation_id="http:executor-observation",
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        http_executor=http_executor,
        record_event=record_event,
    )

    result = await executor(
        "node-001",
        "http_request",
        {"path": "/"},
    )
    visible = visible_tool_envelope(result)

    assert visible["evidence"]["source_trusted"] is True
    assert result.target_requests == PROBE_REQUEST_COUNT
    assert [event["kind"] for event in events] == [
        "autonomous_graph_action_started",
        "autonomous_graph_action_finished",
    ]
    started_payload = events[0]["payload"]
    finished_payload = events[1]["payload"]
    assert isinstance(started_payload, dict)
    assert isinstance(finished_payload, dict)
    assert started_payload["action_id"] == finished_payload["action_id"]
    assert started_payload["action_kind"] == "http_request"
    assert finished_payload["observation_id"] == "http:executor-observation"
    assert finished_payload["traffic_exchange_ids"] == ["rq_0001", "rq_0002"]


@pytest.mark.asyncio
async def test_structured_graph_tool_failure_closes_the_display_activity(
    tmp_path: Path,
) -> None:
    events: list[dict[str, object]] = []

    class FailingProcessExecutor:
        async def __call__(
            self,
            _node_id: str,
            _tool: str,
            _arguments: dict[str, object],
        ) -> GraphToolResult:
            message = "process runtime unavailable"
            raise OSError(message)

    def record_event(*, kind: str, payload: Mapping[str, object]) -> None:
        events.append({"kind": kind, "payload": dict(payload)})

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        process_executor=FailingProcessExecutor(),
        record_event=record_event,
    )

    with pytest.raises(OSError, match="runtime unavailable"):
        await executor("node-001", "process_read", {"name": "listener"})

    assert [event["kind"] for event in events] == [
        "autonomous_graph_action_started",
        "autonomous_graph_action_failed",
    ]
    failure_payload = events[1]["payload"]
    assert isinstance(failure_payload, dict)
    assert failure_payload["error_type"] == "OSError"


@pytest.mark.asyncio
async def test_process_promotion_failure_does_not_report_action_finished(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[dict[str, object]] = []
    blackboard = _blackboard(tmp_path)

    class ProcessExecutor:
        async def __call__(
            self,
            _node_id: str,
            _tool: str,
            _arguments: dict[str, object],
        ) -> GraphToolResult:
            return GraphToolResult(output="bounded process output")

    def fail_promotion(**_kwargs: object) -> None:
        message = "evidence promotion failed"
        raise RuntimeError(message)

    def record_event(*, kind: str, payload: Mapping[str, object]) -> None:
        events.append({"kind": kind, "payload": dict(payload)})

    monkeypatch.setattr(blackboard, "record_action_result", fail_promotion)
    executor = EvidenceGraphExecutor(
        blackboard=blackboard,
        process_executor=ProcessExecutor(),
        record_event=record_event,
    )

    with pytest.raises(RuntimeError, match="promotion failed"):
        await executor("node-001", "process_read", {"name": "listener"})

    assert [event["kind"] for event in events] == [
        "autonomous_graph_action_started",
        "autonomous_graph_action_failed",
    ]
    failure_payload = events[1]["payload"]
    assert isinstance(failure_payload, dict)
    assert failure_payload["error_type"] == "RuntimeError"


@pytest.mark.asyncio
async def test_shared_agent_state_actions_are_serialized_across_workers(
    tmp_path: Path,
) -> None:
    active = 0
    maximum_active = 0
    lock = threading.Lock()

    def action_call(**_kwargs: object) -> ActionExecution:
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation="bounded observation",
                evidence_source_kind="tool_run_command",
                evidence_observation="bounded observation",
            ),
            observation_id=str(time.monotonic_ns()),
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
    )

    await asyncio.gather(
        executor("node-001", "run_command", {"command": "true"}),
        executor("node-002", "run_command", {"command": "printf ok"}),
    )

    assert maximum_active == 1


@pytest.mark.asyncio
async def test_counterfactual_objective_is_canonical_and_not_forwarded(
    tmp_path: Path,
) -> None:
    seen_action: dict[str, object] = {}

    def action_call(
        *,
        node_id: str,
        action: dict[str, object],
        action_id: str,
    ) -> ActionExecution:
        del node_id, action_id
        seen_action.update(action)
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation="negative result",
                evidence_source_kind="tool_run_probe",
                evidence_observation="negative result",
            ),
            observation_id="negative-observation",
        )

    executor = EvidenceGraphExecutor(
        blackboard=_blackboard(tmp_path),
        action_call=action_call,
    )
    result = await executor(
        "node-001",
        "run_probe",
        {
            "probe": "sqli_differential",
            "counterfactual_objective": {
                "family": "path_traversal",
                "instruction": "Test the normalized path boundary",
                "endpoint": "/download",
                "inputs": ["file"],
                "strategy": "path_normalization",
                "expected_signal": "target-observed file boundary result",
            },
        },
    )

    assert result.counterfactual_objective_fingerprint
    assert "counterfactual_objective" not in seen_action
