from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ravage.agent_core.frontier_shared_runtime import (
    SharedToolRuntime,
    make_shared_tool_runtime,
    reverify_tool_runtime_cleanup,
    shared_tool_session_id,
)
from ravage.runtime import DockerFallbackToolRuntime, DockerToolRuntime, ToolRuntime
from ravage.runtime.scoped_network import cleanup_scoped_network_session

if TYPE_CHECKING:
    from pentest_schemas import EngagementBrief

    from ravage.agent_core.ai_agent import AIWebAgentSettings


_HANDOFF_SCHEMA_VERSION = 1
_HANDOFF_RECEIPT_NAME = "runtime-handoff.json"


@dataclass(frozen=True)
class FrontierRuntimeHandoff:
    runtime: SharedToolRuntime | None
    verified: bool
    rotated: bool
    reason: str


def prepare_frontier_runtime(
    *,
    settings: AIWebAgentSettings,
    brief: EngagementBrief,
    workspace_dir: Path,
    base_runtime: SharedToolRuntime | None,
) -> FrontierRuntimeHandoff:
    """Create a clean route runtime without changing the frozen base runtime."""
    if base_runtime is not None and not _should_rotate(base_runtime):
        return FrontierRuntimeHandoff(
            runtime=base_runtime,
            verified=True,
            rotated=False,
            reason="runtime_rotation_not_owned_or_not_scoped_docker",
        )

    if base_runtime is not None:
        return _rotate_factory_runtime(
            settings=settings,
            brief=brief,
            workspace_dir=workspace_dir,
            base_runtime=base_runtime,
        )

    _prepare_frontier_evidence(settings=settings, brief=brief)
    runtime = make_shared_tool_runtime(
        settings,
        brief,
        session_role="frontier",
    )
    _write_handoff_receipt(
        workspace_dir,
        {
            "schema_version": _HANDOFF_SCHEMA_VERSION,
            "status": "frontier_runtime_created",
            "reason": "resumed_from_completed_base_artifacts",
            "recorded_at": _now_iso(),
            "rotated": False,
            "base_cleanup": [],
            "frontier_session_id": shared_tool_session_id(
                str(brief.engagement_id),
                role="frontier",
            ),
            "persistent_workdir_preserved": True,
        },
    )
    return FrontierRuntimeHandoff(
        runtime=runtime,
        verified=True,
        rotated=False,
        reason="fresh_frontier_runtime_for_completed_base",
    )


def cleanup_autonomous_runtime_sessions(
    engagement_id: str,
    *,
    evidence_path: str | Path,
) -> dict[str, object]:
    """Parent-side cleanup for either active autonomous-route runtime generation."""
    path = Path(evidence_path)
    expected = (
        shared_tool_session_id(engagement_id, role="base"),
        shared_tool_session_id(engagement_id, role="frontier"),
    )
    current = _read_json_object(path)
    recorded_session = current.get("session_id")
    active_session = str(recorded_session) if recorded_session in expected else expected[0]
    if recorded_session not in expected:
        _write_json_object(
            path,
            {
                "session_id": active_session,
                "setup": {
                    "status": "unknown",
                    "recorded_at": _now_iso(),
                    "error": "active autonomous runtime setup was not recorded",
                },
            },
        )

    summaries: list[dict[str, object]] = []
    active_evidence: dict[str, object] | None = None
    for session_id in (*[item for item in expected if item != active_session], active_session):
        receipt = cleanup_scoped_network_session(
            session_id,
            evidence_path=path if session_id == active_session else None,
        )
        summaries.append(_safe_cleanup_summary(receipt, expected_session_id=session_id))
        if session_id == active_session:
            active_evidence = receipt

    if active_evidence is None:  # pragma: no cover - guarded by non-empty expected tuple.
        message = "active autonomous runtime cleanup was not attempted"
        raise RuntimeError(message)
    all_verified = all(_summary_verified(summary) for summary in summaries)
    active_evidence["autonomous_route_cleanup"] = {
        "status": "verified" if all_verified else "error",
        "verified": all_verified,
        "recorded_at": _now_iso(),
        "active_session_id": active_session,
        "sessions": summaries,
    }
    _write_json_object(path, active_evidence)
    return active_evidence


def _rotate_factory_runtime(
    *,
    settings: AIWebAgentSettings,
    brief: EngagementBrief,
    workspace_dir: Path,
    base_runtime: SharedToolRuntime,
) -> FrontierRuntimeHandoff:
    cleanup_error: str | None = None
    receipts: tuple[dict[str, object], ...] = ()
    try:
        base_runtime.shutdown()
        receipts = reverify_tool_runtime_cleanup(base_runtime)
    except Exception as exc:  # noqa: BLE001 - route entry must fail closed.
        cleanup_error = str(exc)

    summaries = tuple(_safe_cleanup_summary(item) for item in receipts)
    verified = (
        cleanup_error is None
        and bool(summaries)
        and all(_summary_verified(item) for item in summaries)
    )
    receipt: dict[str, object] = {
        "schema_version": _HANDOFF_SCHEMA_VERSION,
        "status": "base_cleanup_verified" if verified else "blocked",
        "reason": (
            "base_runtime_cleanup_verified" if verified else "base_runtime_cleanup_unverified"
        ),
        "recorded_at": _now_iso(),
        "rotated": verified,
        "base_session_role": base_runtime.session_role,
        "base_cleanup": list(summaries),
        "cleanup_error": cleanup_error,
        "frontier_session_id": shared_tool_session_id(
            str(brief.engagement_id),
            role="frontier",
        ),
        "persistent_workdir_preserved": False,
    }
    _write_handoff_receipt(workspace_dir, receipt)
    if not verified:
        return FrontierRuntimeHandoff(
            runtime=None,
            verified=False,
            rotated=False,
            reason="route_handoff_hygiene_unverified",
        )

    _prepare_frontier_evidence(settings=settings, brief=brief)
    frontier_runtime = make_shared_tool_runtime(
        settings,
        brief,
        session_role="frontier",
    )
    workdir_preserved = (
        base_runtime.persistent_workdir is not None
        and frontier_runtime.persistent_workdir == base_runtime.persistent_workdir
    )
    if not workdir_preserved:
        frontier_runtime.shutdown()
        receipt.update(
            {
                "status": "blocked",
                "reason": "persistent_tool_workdir_was_not_preserved",
                "recorded_at": _now_iso(),
            }
        )
        _write_handoff_receipt(workspace_dir, receipt)
        return FrontierRuntimeHandoff(
            runtime=None,
            verified=False,
            rotated=False,
            reason="route_handoff_workdir_not_preserved",
        )

    receipt.update(
        {
            "status": "frontier_runtime_created",
            "reason": "base_runtime_cleanup_verified",
            "recorded_at": _now_iso(),
            "persistent_workdir_preserved": True,
        }
    )
    _write_handoff_receipt(workspace_dir, receipt)
    return FrontierRuntimeHandoff(
        runtime=frontier_runtime,
        verified=True,
        rotated=True,
        reason="frontier_runtime_rotated",
    )


def _should_rotate(runtime: SharedToolRuntime) -> bool:
    return runtime.factory_owned and _scoped_docker_runtime(runtime.inner) is not None


def _scoped_docker_runtime(runtime: ToolRuntime) -> DockerToolRuntime | None:
    if isinstance(runtime, DockerToolRuntime):
        return runtime
    if isinstance(runtime, DockerFallbackToolRuntime) and isinstance(
        runtime.docker_runtime,
        DockerToolRuntime,
    ):
        return runtime.docker_runtime
    return None


def _prepare_frontier_evidence(
    *,
    settings: AIWebAgentSettings,
    brief: EngagementBrief,
) -> None:
    if settings.tool_runtime is not None or settings.tool_runtime_mode not in {
        "docker",
        "auto",
    }:
        return
    raw_path = os.environ.get("RAVAGE_TOOL_NETWORK_EVIDENCE_PATH")
    if not raw_path:
        return
    _write_json_object(
        Path(raw_path),
        {
            "session_id": shared_tool_session_id(
                str(brief.engagement_id),
                role="frontier",
            ),
            "setup": {
                "status": "unknown",
                "recorded_at": _now_iso(),
                "error": "frontier runtime setup has not completed",
            },
        },
    )


def _safe_cleanup_summary(
    receipt: dict[str, object],
    *,
    expected_session_id: str | None = None,
) -> dict[str, object]:
    cleanup = receipt.get("cleanup")
    payload = cleanup if isinstance(cleanup, dict) else {}
    session_id = expected_session_id or str(receipt.get("session_id") or "")
    return {
        "session_id": session_id,
        "status": str(payload.get("status") or "missing"),
        "verified": payload.get("verified") is True,
        "recorded_at": payload.get("recorded_at"),
        "containers_before": _string_list(payload.get("containers_before")),
        "networks_before": _string_list(payload.get("networks_before")),
        "containers_after": _string_list(payload.get("containers_after")),
        "networks_after": _string_list(payload.get("networks_after")),
        "error_count": len(payload.get("errors") or [])
        if isinstance(payload.get("errors"), list)
        else 0,
    }


def _summary_verified(summary: dict[str, object]) -> bool:
    return summary.get("status") == "verified" and summary.get("verified") is True


def _string_list(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _write_handoff_receipt(workspace_dir: Path, payload: dict[str, object]) -> None:
    _write_json_object(workspace_dir / _HANDOFF_RECEIPT_NAME, payload)


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json_object(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "FrontierRuntimeHandoff",
    "cleanup_autonomous_runtime_sessions",
    "prepare_frontier_runtime",
]
