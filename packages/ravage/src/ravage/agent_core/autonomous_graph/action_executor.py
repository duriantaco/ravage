# Autonomous-graph action execution is additive; non-probe tools delegate unchanged.
# ruff: noqa: PLR0913

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.action_executor import (
    ActionResult,
    _decode_probe_runner_payload,
    _probe_failure_text,
    _probe_wall_timeout,
    _timeout,
    execute_action,
    record_probe_result,
    record_verified_probe_findings,
)
from ravage.agent_core.autonomous_graph.effort_policy import (
    GRAPH_ROUTE_TARGET_REQUEST_LIMIT,
    GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT,
)
from ravage.probe_suite import probe_requires_external_process

if TYPE_CHECKING:
    from uuid import UUID

    from ravage.agent_core.agent_state import AgentState
    from ravage.auth.runtime import ManagedAttackAuthentication
    from ravage.run_data.audit import AuditStore
    from ravage.run_data.workspace import AgentWorkspace
    from ravage.runtime import ToolRuntime
    from ravage.traffic.policy import TrafficPolicyController

_DEFAULT_OBSERVED_REQUEST_GRANT = 12


@dataclass(frozen=True)
class _BoundedProbeResult:
    text: str
    ok: bool
    timed_out: bool = False


def execute_graph_action(
    action: dict[str, object],
    *,
    target_url: str,
    runtime: ToolRuntime,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    repeat_count: int,
    max_observation_chars: int,
    max_transcript_chars: int,
    proof_recognition_enabled: bool = False,
    action_id: str = "",
    authentication: ManagedAttackAuthentication | None = None,
    traffic_policy: TrafficPolicyController | None = None,
) -> ActionResult:
    routed = dict(action)
    raw_limit = routed.pop(GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT, None)
    if str(routed.get("action") or "") != "run_probe":
        return execute_action(
            routed,
            target_url=target_url,
            runtime=runtime,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=repeat_count,
            max_observation_chars=max_observation_chars,
            max_transcript_chars=max_transcript_chars,
            proof_recognition_enabled=proof_recognition_enabled,
            action_id=action_id,
            authentication=authentication,
            traffic_policy=traffic_policy,
        )

    target_request_limit = _request_limit(raw_limit)
    probe = str(routed.get("probe") or "").strip()
    # Managed identities must remain inside the owner-controlled in-process
    # session. Opaque probes must also cross the common guard so OBSERVE marks
    # accounting lower-bound and ENFORCE blocks before a subprocess starts.
    if authentication is not None or probe_requires_external_process(probe):
        return execute_action(
            routed,
            target_url=target_url,
            runtime=runtime,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=repeat_count,
            max_observation_chars=max_observation_chars,
            max_transcript_chars=max_transcript_chars,
            proof_recognition_enabled=proof_recognition_enabled,
            action_id=action_id,
            authentication=authentication,
            traffic_policy=traffic_policy,
        )
    timeout_seconds = _timeout(routed.get("timeout_seconds")) or 10
    probe_result = _run_bounded_probe_action(
        probe,
        target_url=target_url,
        state=state,
        timeout_seconds=timeout_seconds,
        target_request_limit=target_request_limit,
        traffic_policy_reference=(
            traffic_policy.to_reference() if traffic_policy is not None else None
        ),
    )
    result = record_probe_result(
        probe_result.text,
        ok=probe_result.ok,
        kind="tool_run_probe",
        state=state,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
        proof_recognition_enabled=proof_recognition_enabled,
        action_id=action_id,
        repeat_count=repeat_count,
        timed_out=probe_result.timed_out,
        max_observation_chars=max_observation_chars,
        max_transcript_chars=max_transcript_chars,
    )
    return record_verified_probe_findings(
        probe=probe,
        probe_text=probe_result.text,
        result=result,
        target_url=target_url,
        state=state,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
        action_id=action_id,
    )


def _run_bounded_probe_action(
    probe: str,
    *,
    target_url: str,
    state: AgentState,
    timeout_seconds: int,
    target_request_limit: int,
    traffic_policy_reference: dict[str, object] | None = None,
) -> _BoundedProbeResult:
    wall_timeout = _probe_wall_timeout(timeout_seconds, probe=probe)
    request = json.dumps(
        {
            "probe": probe,
            "target_url": target_url,
            "state": state.to_json(),
            "timeout_seconds": timeout_seconds,
            "target_request_limit": target_request_limit,
            "traffic_policy_reference": traffic_policy_reference,
        },
        sort_keys=True,
    )
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "ravage.agent_core.autonomous_graph.probe_runner",
            ],
            input=request,
            capture_output=True,
            text=True,
            timeout=wall_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _BoundedProbeResult(
            text=_probe_failure_text(
                probe=probe,
                summary=(
                    f"graph probe timed out after {timeout_seconds}s request "
                    "timeout and wall-clock guard"
                ),
                errors=[f"run_probe {probe} exceeded {wall_timeout}s wall-clock limit"],
            ),
            ok=False,
            timed_out=True,
        )
    payload = _decode_probe_runner_payload(
        completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )
    if payload.get("status") == "ok":
        return _BoundedProbeResult(
            text=str(payload.get("text") or ""),
            ok=bool(payload.get("ok")),
        )
    return _BoundedProbeResult(
        text=_probe_failure_text(
            probe=probe,
            summary="bounded graph probe raised before producing observations",
            errors=[str(payload.get("error") or "graph probe runner failed")],
        ),
        ok=False,
    )


def _request_limit(value: object) -> int:
    if value is None:
        return _DEFAULT_OBSERVED_REQUEST_GRANT
    if isinstance(value, bool):
        message = "graph target request limit must be an integer"
        raise TypeError(message)
    parsed = int(str(value))
    if not 1 <= parsed <= GRAPH_ROUTE_TARGET_REQUEST_LIMIT:
        message = (
            f"graph target request limit must be between 1 and {GRAPH_ROUTE_TARGET_REQUEST_LIMIT}"
        )
        raise ValueError(message)
    return parsed


__all__ = ["execute_graph_action"]
