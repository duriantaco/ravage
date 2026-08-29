# Bridge errors carry operation-specific fail-closed context.
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.autonomous_graph.evidence import (
    EvidenceBlackboard,
    graph_tool_result_from_promotion,
)
from ravage.agent_core.autonomous_graph.models import GraphObjective

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.closure_routing import (
        GraphClosureRouter,
    )
    from ravage.agent_core.autonomous_graph.runtime_tools import (
        GraphRuntimeExecutor,
    )
    from ravage.agent_core.autonomous_graph.worker import GraphToolResult
    from ravage.traffic.policy import TrafficPolicyController

_ACTION_TOOLS = frozenset(
    {
        "run_command",
        "run_python",
        "run_probe",
        "validate_poc",
        "capture_flag",
    }
)
_PROCESS_TOOLS = frozenset(
    {
        "process_start",
        "process_read",
        "process_write",
        "process_stop",
    }
)
_TRAFFIC_EXCHANGE_ID = re.compile(r"^rq_[0-9]{4,}$")
_HTTP_TOOLS = frozenset({"http_request"})


class GraphActionBridgeError(ValueError):
    """Raised when a graph tool cannot be safely routed to Ravage."""


@dataclass(frozen=True)
class ActionExecution:
    """Executor result plus the immutable target-observation provenance ID."""

    result: ActionResult
    observation_id: str


class GraphActionCall(Protocol):
    def __call__(
        self,
        *,
        node_id: str,
        action: dict[str, object],
        action_id: str,
    ) -> ActionExecution: ...


class GraphHttpCall(Protocol):
    def __call__(
        self,
        *,
        node_id: str,
        arguments: dict[str, object],
        action_id: str,
    ) -> ActionExecution: ...


class GraphEventRecorder(Protocol):
    def __call__(
        self,
        *,
        kind: str,
        payload: Mapping[str, object],
    ) -> object: ...


class EvidenceGraphExecutor:
    """
    Route graph actions through existing Ravage executors and typed evidence.

    Existing AgentState/AgentWorkspace mutation is serialized because those
    objects are intentionally shared across graph workers. Model requests can
    still run concurrently; target state writes cannot race.
    """

    def __init__(  # noqa: PLR0913 - graph execution boundaries are explicit.
        self,
        *,
        blackboard: EvidenceBlackboard,
        action_call: GraphActionCall | None = None,
        http_executor: GraphHttpCall | None = None,
        process_executor: GraphRuntimeExecutor | None = None,
        closure_router: GraphClosureRouter | None = None,
        record_event: GraphEventRecorder | None = None,
        allowed_action_tools: frozenset[str] | None = None,
        traffic_policy: TrafficPolicyController | None = None,
    ) -> None:
        self.blackboard = blackboard
        self.action_call = action_call
        self.http_executor = http_executor
        self.process_executor = process_executor
        self.closure_router = closure_router
        self.record_event = record_event
        self.traffic_policy = traffic_policy
        self.allowed_action_tools = (
            _ACTION_TOOLS if allowed_action_tools is None else frozenset(allowed_action_tools)
        )
        if not self.allowed_action_tools.issubset(_ACTION_TOOLS):
            raise GraphActionBridgeError("allowed graph action tools contain an unknown action")
        self._action_lock = asyncio.Lock()

    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        if tool in _PROCESS_TOOLS:
            return await self._execute_process(node_id, tool, arguments)
        if tool in _HTTP_TOOLS:
            return await self._execute_http(node_id, tool, arguments)
        if tool not in _ACTION_TOOLS:
            message = f"unsupported graph execution tool: {tool}"
            raise GraphActionBridgeError(message)
        if tool not in self.allowed_action_tools:
            raise GraphActionBridgeError(f"graph action tool is unavailable for this route: {tool}")
        if "action" in arguments:
            raise GraphActionBridgeError("graph tool arguments cannot override the routed action")

        routed_arguments = dict(arguments)
        counterfactual = _counterfactual_fingerprint(
            routed_arguments.pop("counterfactual_objective", None)
        )
        action = {"action": tool, **routed_arguments}
        action_id = str(uuid4())
        update = None
        async with self._action_lock:
            if self.action_call is None:
                raise GraphActionBridgeError(
                    "local graph action tools are unavailable for this graph route"
                )
            execution = await asyncio.to_thread(
                self.action_call,
                node_id=node_id,
                action=action,
                action_id=action_id,
            )
            if not isinstance(execution, ActionExecution):
                raise TypeError("graph action bridge must return ActionExecution")
            promotion = await asyncio.to_thread(
                self.blackboard.record_action_result,
                producer_node_id=node_id,
                action=action,
                result=execution.result,
                observation_id=execution.observation_id,
            )
            if self.closure_router is not None:
                update = await asyncio.to_thread(
                    self.closure_router.observe,
                    node_id=node_id,
                    action=action,
                    result=execution.result,
                    promotion=promotion,
                )
        tool_result = graph_tool_result_from_promotion(
            result=execution.result,
            promotion=promotion,
            counterfactual_objective_fingerprint=counterfactual,
        )
        if self.closure_router is None:
            return tool_result
        from ravage.agent_core.autonomous_graph.closure_routing import (  # noqa: PLC0415
            merge_closure_update,
        )

        if update is None:
            raise RuntimeError("closure router did not produce an update")
        return merge_closure_update(tool_result, update)

    async def _execute_http(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        if self.http_executor is None:
            raise GraphActionBridgeError(
                "unsupported graph execution tool: http_request; "
                "structured HTTP is unavailable for this graph route"
            )
        if "action" in arguments:
            raise GraphActionBridgeError("graph tool arguments cannot override the routed action")
        routed_arguments = dict(arguments)
        counterfactual = _counterfactual_fingerprint(
            routed_arguments.pop("counterfactual_objective", None)
        )
        action = {"action": tool, **routed_arguments}
        action_id = str(uuid4())
        update = None
        self._record_action_started(node_id=node_id, action_id=action_id, tool=tool)
        try:
            async with self._action_lock:
                execution = _require_action_execution(
                    await asyncio.to_thread(
                        self.http_executor,
                        node_id=node_id,
                        arguments=routed_arguments,
                        action_id=action_id,
                    ),
                    boundary="HTTP",
                )
                promotion = await asyncio.to_thread(
                    self.blackboard.record_action_result,
                    producer_node_id=node_id,
                    action=action,
                    result=execution.result,
                    observation_id=execution.observation_id,
                )
                if self.closure_router is not None:
                    update = await asyncio.to_thread(
                        self.closure_router.observe,
                        node_id=node_id,
                        action=action,
                        result=execution.result,
                        promotion=promotion,
                    )
        except BaseException as exc:
            self._record_action_failed(
                node_id=node_id,
                action_id=action_id,
                tool=tool,
                error=exc,
            )
            raise
        self._record_action_finished(
            node_id=node_id,
            action_id=action_id,
            tool=tool,
            result=execution.result,
            observation_id=execution.observation_id,
        )
        tool_result = graph_tool_result_from_promotion(
            result=execution.result,
            promotion=promotion,
            counterfactual_objective_fingerprint=counterfactual,
        )
        if self.closure_router is None:
            return tool_result
        from ravage.agent_core.autonomous_graph.closure_routing import (  # noqa: PLC0415
            merge_closure_update,
        )

        if update is None:
            raise RuntimeError("closure router did not produce an update")
        return merge_closure_update(tool_result, update)

    def guard(
        self,
        node_id: str,
        tool: str,
        arguments: Mapping[str, object],
    ) -> None:
        if self.closure_router is not None:
            self.closure_router.guard(node_id, tool, arguments)

    async def _execute_process(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        if self.process_executor is None:
            raise GraphActionBridgeError(
                "persistent process tools are unavailable for this graph route"
            )
        if self.traffic_policy is not None:
            # Persistent tools are opaque to physical-request accounting. OBSERVE
            # may run them but must make the ledger explicitly lower-bound.
            self.traffic_policy.record_unmetered_action()
        action_id = str(uuid4())
        self._record_action_started(node_id=node_id, action_id=action_id, tool=tool)
        try:
            runtime_result = await self.process_executor(node_id, tool, arguments)
            action_result = ActionResult(
                ok=True,
                observation=runtime_result.output,
                outcome="persistent_runtime_observation",
                evidence_source_kind="graph_process_runtime",
                evidence_observation=runtime_result.output,
            )
            promotion = await asyncio.to_thread(
                self.blackboard.record_action_result,
                producer_node_id=node_id,
                action={"action": tool, **arguments},
                result=action_result,
                observation_id=f"process:{uuid4()}",
            )
        except BaseException as exc:
            self._record_action_failed(
                node_id=node_id,
                action_id=action_id,
                tool=tool,
                error=exc,
            )
            raise
        self._record_action_finished(
            node_id=node_id,
            action_id=action_id,
            tool=tool,
            result=action_result,
        )
        return graph_tool_result_from_promotion(
            result=action_result,
            promotion=promotion,
        )

    def _record_action_started(self, *, node_id: str, action_id: str, tool: str) -> None:
        self._record_event(
            "autonomous_graph_action_started",
            {
                "node_id": node_id,
                "action_id": action_id,
                "action_kind": tool,
            },
        )

    def _record_action_finished(
        self,
        *,
        node_id: str,
        action_id: str,
        tool: str,
        result: ActionResult,
        observation_id: str = "",
    ) -> None:
        payload: dict[str, object] = {
            "node_id": node_id,
            "action_id": action_id,
            "action_kind": tool,
            "outcome": result.outcome,
            "ok": result.ok,
            "timed_out": result.timed_out,
        }
        if observation_id:
            payload["observation_id"] = observation_id
        traffic_exchange_ids = _traffic_exchange_ids(result)
        if traffic_exchange_ids:
            payload["traffic_exchange_ids"] = list(traffic_exchange_ids)
        self._record_event(
            "autonomous_graph_action_finished",
            payload,
        )

    def _record_action_failed(
        self,
        *,
        node_id: str,
        action_id: str,
        tool: str,
        error: BaseException,
    ) -> None:
        self._record_event(
            "autonomous_graph_action_failed",
            {
                "node_id": node_id,
                "action_id": action_id,
                "action_kind": tool,
                "error_type": type(error).__name__,
            },
        )

    def _record_event(self, kind: str, payload: Mapping[str, object]) -> None:
        if self.record_event is not None:
            with suppress(Exception):
                self.record_event(kind=kind, payload=payload)


def _counterfactual_fingerprint(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, Mapping):
        raise GraphActionBridgeError("counterfactual_objective must be an object")
    objective = GraphObjective.create(
        family=str(value.get("family") or ""),
        instruction=str(value.get("instruction") or ""),
        endpoint=str(value.get("endpoint") or ""),
        inputs=_string_tuple(value.get("inputs")),
        strategy=str(value.get("strategy") or ""),
        expected_signal=str(value.get("expected_signal") or ""),
    )
    return str(objective.fingerprint)


def _traffic_exchange_ids(result: ActionResult) -> tuple[str, ...]:
    if result.evidence_source_kind != "tool_http_request":
        return ()
    try:
        payload = json.loads(result.evidence_observation)
    except (TypeError, json.JSONDecodeError):
        return ()
    if not isinstance(payload, Mapping):
        return ()
    raw_ids = payload.get("traffic_exchange_ids")
    if not isinstance(raw_ids, list):
        return ()
    return tuple(
        dict.fromkeys(
            item
            for item in raw_ids
            if isinstance(item, str) and _TRAFFIC_EXCHANGE_ID.fullmatch(item)
        )
    )


def _require_action_execution(value: object, *, boundary: str) -> ActionExecution:
    if not isinstance(value, ActionExecution):
        message = f"graph {boundary} bridge must return ActionExecution"
        raise TypeError(message)
    return value


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        sorted({str(item).strip() for item in value if isinstance(item, str) and item.strip()})
    )


def visible_tool_envelope(result: GraphToolResult) -> dict[str, object]:
    """Decode the bounded worker-visible envelope for diagnostics and replay."""
    try:
        payload = json.loads(result.output)
    except json.JSONDecodeError as exc:
        raise GraphActionBridgeError("graph tool envelope is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise GraphActionBridgeError("graph tool envelope must be an object")
    return payload


__all__ = [
    "ActionExecution",
    "EvidenceGraphExecutor",
    "GraphActionBridgeError",
    "GraphActionCall",
    "GraphHttpCall",
    "visible_tool_envelope",
]
