from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from urllib.parse import urlparse, urlunparse

from ravage.runtime.common import assert_local_url as _assert_local_url
from ravage.runtime.common import docker_target_url as _runtime_docker_target_url
from ravage.runtime.docker import DockerToolRuntime
from ravage.runtime.fallback import DockerFallbackToolRuntime
from ravage.runtime.host import ExternalToolRuntime
from ravage.runtime.iptables import render_rules
from ravage.runtime.scoped_network import (
    SCOPED_TARGET_ALIAS,
    cleanup_scoped_network_session,
)
from ravage.runtime.types import (
    DEFAULT_PUBLISHED_TOOL_IMAGE,
    DEFAULT_TOOL_IMAGE,
    NoProcessToolRuntime,
    ToolResult,
    ToolRuntime,
    ToolRuntimeMode,
)
from ravage.web_core.scope_policy import url_in_scope_entries

if TYPE_CHECKING:
    from pentest_schemas import Scope


@dataclass(frozen=True)
class TerminalResult:
    ok: bool
    session: str
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    running: bool = False
    timed_out: bool = False
    action: str = ""
    command: tuple[str, ...] = ()
    exit_code: int | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "session": self.session,
            "action": self.action,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
            "running": self.running,
            "timed_out": self.timed_out,
        }


class FakeToolRuntime(ToolRuntime):
    def __init__(self, results: dict[str, ToolResult | TerminalResult] | None = None) -> None:
        self.results = results or {}
        self.calls: list[tuple[str, dict[str, object]]] = []

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        self.calls.append(
            (
                "run_command",
                {
                    "command": command,
                    "target_url": target_url,
                    "timeout_seconds": timeout_seconds,
                },
            )
        )
        result = self.results.get("run_command")
        if isinstance(result, ToolResult):
            return result
        return ToolResult(
            ok=True,
            tool="run_command",
            command=("sh", "-lc", command),
            exit_code=0,
            stdout="",
            stderr="",
        )

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        self.calls.append(
            (
                "run_python",
                {
                    "code": code,
                    "target_url": target_url,
                    "timeout_seconds": timeout_seconds,
                },
            )
        )
        result = self.results.get("run_python")
        if isinstance(result, ToolResult):
            return result
        return ToolResult(
            ok=True,
            tool="run_python",
            command=("python", "-c", code),
            exit_code=0,
            stdout="",
            stderr="",
        )

    def terminal_start(self, **kwargs: object) -> TerminalResult:
        self.calls.append(("terminal_start", dict(kwargs)))
        result = self.results.get("terminal_start")
        if isinstance(result, TerminalResult):
            return result
        return TerminalResult(
            ok=True, session=str(kwargs.get("session") or "default"), running=True
        )

    def terminal_send(self, **kwargs: object) -> TerminalResult:
        self.calls.append(("terminal_send", dict(kwargs)))
        result = self.results.get("terminal_send")
        if isinstance(result, TerminalResult):
            return result
        return TerminalResult(
            ok=True, session=str(kwargs.get("session") or "default"), running=True
        )

    def terminal_read(self, **kwargs: object) -> TerminalResult:
        self.calls.append(("terminal_read", dict(kwargs)))
        result = self.results.get("terminal_read")
        if isinstance(result, TerminalResult):
            return result
        return TerminalResult(
            ok=True, session=str(kwargs.get("session") or "default"), running=True
        )

    def terminal_stop(self, **kwargs: object) -> TerminalResult:
        self.calls.append(("terminal_stop", dict(kwargs)))
        result = self.results.get("terminal_stop")
        if isinstance(result, TerminalResult):
            return result
        return TerminalResult(
            ok=True, session=str(kwargs.get("session") or "default"), running=False
        )


@dataclass(frozen=True)
class ScopeFirewall:
    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...] = ()

    @classmethod
    def from_scope(cls, scope: Scope) -> ScopeFirewall:
        return cls(
            in_scope=tuple(str(value) for value in scope.in_scope),
            out_of_scope=tuple(str(value) for value in scope.out_of_scope),
        )

    def allows(self, url: str) -> bool:
        return url_in_scope_entries(
            url,
            in_scope=self.in_scope,
            out_of_scope=self.out_of_scope,
        )

    @property
    def script_lines(self) -> tuple[str, ...]:
        return tuple(render_rules(cast("Scope", self)))


def _current_python_binary() -> str:
    return sys.executable


def _rewrite_container_local_target_literals(command: str, target_url: str) -> str:
    replacement = _docker_target_url(target_url).rstrip("/")
    parsed = urlparse(target_url)
    port = f":{parsed.port}" if parsed.port is not None else ""
    local_hosts = ("127.0.0.1", "localhost", "0.0.0.0")
    rewritten = command
    for host in local_hosts:
        pattern = re.compile(rf"http://{re.escape(host)}{re.escape(port)}(?=[/?#\\s]|$)")
        rewritten = pattern.sub(replacement, rewritten)
    return rewritten


def _docker_target_url_compat(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.hostname is None:
        return target_url
    try:
        _assert_local_url(target_url)
    except ValueError:
        return _runtime_docker_target_url(target_url)
    port = f":{parsed.port}" if parsed.port is not None else ""
    netloc = f"host.docker.internal{port}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


_docker_target_url = _docker_target_url_compat

__all__ = [
    "DEFAULT_PUBLISHED_TOOL_IMAGE",
    "DEFAULT_TOOL_IMAGE",
    "DockerFallbackToolRuntime",
    "DockerToolRuntime",
    "ExternalToolRuntime",
    "FakeToolRuntime",
    "NoProcessToolRuntime",
    "SCOPED_TARGET_ALIAS",
    "ScopeFirewall",
    "TerminalResult",
    "ToolResult",
    "ToolRuntime",
    "ToolRuntimeMode",
    "_assert_local_url",
    "_current_python_binary",
    "_docker_target_url",
    "_rewrite_container_local_target_literals",
    "cleanup_scoped_network_session",
]
