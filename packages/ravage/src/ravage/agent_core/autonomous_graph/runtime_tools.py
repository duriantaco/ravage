from __future__ import annotations

import asyncio
import hashlib
import json
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.worker import GraphToolResult

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ravage.agent_core.autonomous_graph.runtime import (
        PersistentGraphRuntime,
        ProcessRead,
    )


class RuntimeToolError(ValueError):
    """Raised when a structured runtime tool action is invalid."""


class GraphRuntimeExecutor:
    """Expose named persistent processes as graph worker tools."""

    def __init__(
        self,
        runtime: PersistentGraphRuntime,
        *,
        require_network_isolation: bool = True,
    ) -> None:
        if require_network_isolation and not runtime.network_isolation_verified:
            message = "autonomous graph runtime requires verified target-only network isolation"
            raise RuntimeToolError(message)
        self.runtime = runtime

    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        handlers = {
            "process_start": self._start,
            "process_read": self._read,
            "process_write": self._write,
            "process_stop": self._stop,
        }
        handler = handlers.get(tool)
        if handler is None:
            message = f"unknown persistent runtime tool: {tool}"
            raise RuntimeToolError(message)
        payload = await handler(node_id, arguments)
        output = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        return GraphToolResult(
            output=output,
            observation_digest=hashlib.sha256(output.encode()).hexdigest(),
        )

    async def _start(
        self,
        node_id: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        name = _required_text(arguments, "name")
        command = _required_text(arguments, "command")
        timeout = _optional_number(arguments, "timeout_seconds")
        session = await asyncio.to_thread(
            self.runtime.start_process,
            name=name,
            owner_node_id=node_id,
            command=command,
            timeout_seconds=timeout,
        )
        return {"operation": "process_start", "session": session.to_json()}

    async def _read(
        self,
        node_id: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        name = _required_text(arguments, "name")
        max_bytes = _optional_integer(arguments, "max_bytes")
        result = await asyncio.to_thread(
            self.runtime.read_process,
            name=name,
            owner_node_id=node_id,
            max_bytes=max_bytes,
        )
        return {"operation": "process_read", **_read_json(result)}

    async def _write(
        self,
        node_id: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        name = _required_text(arguments, "name")
        data = str(arguments.get("data") or "")
        written = await asyncio.to_thread(
            self.runtime.write_process,
            name=name,
            owner_node_id=node_id,
            data=data,
        )
        return {
            "operation": "process_write",
            "name": name,
            "bytes_written": written,
        }

    async def _stop(
        self,
        node_id: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        name = _required_text(arguments, "name")
        reason = str(arguments.get("reason") or "worker_requested_stop")
        session = await asyncio.to_thread(
            self.runtime.stop_process,
            name=name,
            owner_node_id=node_id,
            reason=reason,
        )
        return {"operation": "process_stop", "session": session.to_json()}


def _read_json(result: ProcessRead) -> dict[str, object]:
    return {
        "name": result.name,
        "status": result.status.value,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "stdout_bytes_total": result.stdout_bytes_total,
        "stderr_bytes_total": result.stderr_bytes_total,
        "reason": result.reason,
    }


def _required_text(arguments: Mapping[str, object], key: str) -> str:
    value = " ".join(str(arguments.get(key) or "").strip().split())
    if not value:
        message = f"{key} is required"
        raise RuntimeToolError(message)
    return value


def _optional_number(
    arguments: Mapping[str, object],
    key: str,
) -> float | None:
    value = arguments.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        message = f"{key} must be a number"
        raise RuntimeToolError(message)
    return float(value)


def _optional_integer(
    arguments: Mapping[str, object],
    key: str,
) -> int | None:
    value = arguments.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{key} must be an integer"
        raise RuntimeToolError(message)
    return value


__all__ = [
    "GraphRuntimeExecutor",
    "RuntimeToolError",
]
