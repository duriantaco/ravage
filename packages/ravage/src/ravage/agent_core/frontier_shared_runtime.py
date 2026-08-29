from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ravage.runtime import (
    DockerFallbackToolRuntime,
    DockerToolRuntime,
    ExternalToolRuntime,
    NoProcessToolRuntime,
    ToolResult,
    ToolRuntime,
)
from ravage.runtime.scoped_network import cleanup_scoped_network_session

if TYPE_CHECKING:
    from pentest_schemas import EngagementBrief

    from ravage.agent_core.ai_agent import AIWebAgentSettings


SharedRuntimeRole = Literal["shared", "base", "frontier"]


class SharedToolRuntime(ToolRuntime):
    """Keep one scoped tool workspace alive across base and frontier routes."""

    def __init__(
        self,
        inner: ToolRuntime,
        *,
        persistent_workdir: Path | None = None,
        factory_owned: bool = False,
        session_role: SharedRuntimeRole = "shared",
    ) -> None:
        self.inner = inner
        self.persistent_workdir = persistent_workdir
        self.factory_owned = factory_owned
        self.session_role = session_role
        self.close_requests = 0
        self._shutdown = False
        if persistent_workdir is not None:
            _bind_persistent_workdir(inner, persistent_workdir)

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        return self.inner.run_command(
            command=command,
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        return self.inner.run_python(
            code=code,
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )

    def write_free_roam_context(self, text: str) -> None:
        self.inner.write_free_roam_context(text)

    def close(self) -> None:
        self.close_requests += 1

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        if self.persistent_workdir is None:
            self.inner.close()
        else:
            _close_preserving_workdir(self.inner)


def make_shared_tool_runtime(
    settings: AIWebAgentSettings,
    brief: EngagementBrief,
    *,
    session_role: SharedRuntimeRole = "shared",
) -> SharedToolRuntime:
    if settings.traffic_policy_mode == "low-noise":
        current: object = settings.tool_runtime
        if isinstance(current, SharedToolRuntime):
            if isinstance(current.inner, NoProcessToolRuntime):
                return current
            current = current.inner
        if isinstance(current, NoProcessToolRuntime):
            return SharedToolRuntime(
                current,
                factory_owned=False,
                session_role=session_role,
            )
        return SharedToolRuntime(
            NoProcessToolRuntime(
                reason="low-noise traffic policy exposes metered native actions only"
            ),
            factory_owned=True,
            session_role=session_role,
        )
    if isinstance(settings.tool_runtime, SharedToolRuntime):
        return settings.tool_runtime
    if settings.tool_runtime is not None:
        return SharedToolRuntime(settings.tool_runtime)
    if settings.authentication is not None:
        return SharedToolRuntime(
            NoProcessToolRuntime(
                reason="managed authenticated sessions expose HTTP probes and PoC replay only"
            ),
            factory_owned=True,
            session_role=session_role,
        )
    persistent_workdir = (
        (settings.workspace_dir or Path("runs/ravage-agent/workspace"))
        / "autonomous-route"
        / "tool-workspace"
    )
    runtime_kwargs = {
        "image": settings.tool_image,
        "scope": brief.scope,
        "session_id": shared_tool_session_id(
            str(brief.engagement_id),
            role=session_role,
        ),
        "cleanup_evidence_path": os.environ.get("RAVAGE_TOOL_NETWORK_EVIDENCE_PATH"),
        "allow_remote_target": settings.allow_remote_target,
    }
    if settings.allow_remote_target or settings.tool_runtime_mode == "docker":
        inner: ToolRuntime = DockerToolRuntime(**runtime_kwargs)
    elif settings.tool_runtime_mode == "auto":
        inner = DockerFallbackToolRuntime(**runtime_kwargs)
    else:
        inner = ExternalToolRuntime()
    return SharedToolRuntime(
        inner,
        persistent_workdir=persistent_workdir,
        factory_owned=True,
        session_role=session_role,
    )


def shared_tool_session_id(
    engagement_id: str,
    *,
    role: SharedRuntimeRole,
) -> str:
    suffix = {
        "shared": "autonomous-route",
        "base": "autonomous-route-base",
        "frontier": "autonomous-route-frontier",
    }[role]
    return f"{engagement_id}-{suffix}"


def _bind_persistent_workdir(runtime: ToolRuntime, path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if isinstance(runtime, DockerFallbackToolRuntime):
        _bind_persistent_workdir(runtime.host_runtime, path)
        _bind_persistent_workdir(runtime.docker_runtime, path)
        return
    if isinstance(runtime, ExternalToolRuntime):
        previous = runtime.workdir
        runtime.workdir = path
        if previous != path:
            with contextlib.suppress(OSError):
                previous.rmdir()


def _close_preserving_workdir(runtime: ToolRuntime) -> None:
    if isinstance(runtime, DockerFallbackToolRuntime):
        _close_preserving_workdir(runtime.host_runtime)
        _close_preserving_workdir(runtime.docker_runtime)
        return
    if isinstance(runtime, DockerToolRuntime):
        runtime.scoped_network.close()
        return
    if not isinstance(runtime, ExternalToolRuntime):
        runtime.close()


def reverify_tool_runtime_cleanup(
    runtime: ToolRuntime,
) -> tuple[dict[str, object], ...]:
    """Repeat scoped cleanup after route-owned late-container reaping."""
    if isinstance(runtime, SharedToolRuntime):
        return reverify_tool_runtime_cleanup(runtime.inner)
    if isinstance(runtime, DockerFallbackToolRuntime):
        return reverify_tool_runtime_cleanup(runtime.docker_runtime)
    if not isinstance(runtime, DockerToolRuntime):
        return ()
    scoped_network = runtime.scoped_network
    evidence = cleanup_scoped_network_session(
        scoped_network.session_id,
        evidence_path=scoped_network.evidence_path,
    )
    scoped_network.cleanup_evidence = evidence
    return (evidence,)


__all__ = [
    "SharedRuntimeRole",
    "SharedToolRuntime",
    "make_shared_tool_runtime",
    "reverify_tool_runtime_cleanup",
    "shared_tool_session_id",
]
