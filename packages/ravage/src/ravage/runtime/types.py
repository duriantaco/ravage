from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ToolRuntimeMode = Literal["host", "docker", "auto"]

DEFAULT_TIMEOUT_SECONDS = 90
DEFAULT_TOOL_IMAGE = "ravage-kali:latest"
DEFAULT_PUBLISHED_TOOL_IMAGE = "ghcr.io/duriantaco/ravage-kali:latest"
MAX_OUTPUT_CHARS = 12000
MAX_COMMAND_CHARS = 16000
MAX_CODE_CHARS = 64000
CONTAINER_WORKDIR = "/workspace"
COMMAND_NOT_FOUND_EXIT_CODE = 127


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    tool: str
    command: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    error: str | None = None
    timed_out: bool = False
    action: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "tool": self.tool,
            "action": self.action or self.tool,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
            "timed_out": self.timed_out,
        }


class ToolRuntime:
    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        raise NotImplementedError

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        raise NotImplementedError

    def write_free_roam_context(self, text: str) -> None:
        del text

    def close(self) -> None:
        return None


class NoProcessToolRuntime(ToolRuntime):
    """A deliberate runtime boundary for managed-HTTP-only agent sessions."""

    def __init__(self, *, reason: str = "process actions are unavailable") -> None:
        self.reason = reason

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del target_url, timeout_seconds
        return ToolResult(
            ok=False,
            tool="run_command",
            command=("blocked",),
            exit_code=None,
            stdout="",
            stderr="",
            error=self.reason,
            action="run_command",
        )

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del code, target_url, timeout_seconds
        return ToolResult(
            ok=False,
            tool="run_python",
            command=("blocked",),
            exit_code=None,
            stdout="",
            stderr="",
            error=self.reason,
            action="run_python",
        )
