from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ravage.tool_paths import (
    command_with_executable_path,
    prepend_executable_path,
    project_tool_bin,
)

from .common import (
    assert_local_url,
    child_process_environment,
    cleanup_path,
    clip,
    safe_code,
    safe_command,
    timeout_or_default,
)
from .types import DEFAULT_TIMEOUT_SECONDS, MAX_OUTPUT_CHARS, ToolResult, ToolRuntime


class ExternalToolRuntime(ToolRuntime):
    def __init__(
        self,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_output_chars: int = MAX_OUTPUT_CHARS,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self._project_tool_bin = project_tool_bin()
        self.workdir = Path(tempfile.mkdtemp(prefix="ravage-agent-"))
        self._script_index = 0
        shutil.copyfile(
            Path(__file__).with_name("requests_shim.py"),
            self.workdir / "requests.py",
        )

    def write_free_roam_context(self, text: str) -> None:
        (self.workdir / "ravage_context.json").write_text(text, encoding="utf-8")

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        try:
            assert_local_url(target_url)
            command = safe_command(command)
        except ValueError as exc:
            return ToolResult(
                ok=False,
                tool="run_command",
                command=("sh", "-lc", clip(command, 200)),
                exit_code=None,
                stdout="",
                stderr="",
                error=str(exc),
            )
        return self._run(
            tool="run_command",
            argv=("sh", "-lc", command),
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
        try:
            assert_local_url(target_url)
            code = safe_code(code)
        except ValueError as exc:
            return ToolResult(
                ok=False,
                tool="run_python",
                command=("python3",),
                exit_code=None,
                stdout="",
                stderr="",
                error=str(exc),
            )
        self._script_index += 1
        script = self.workdir / f"agent_{self._script_index}.py"
        script.write_text(code, encoding="utf-8")
        return self._run(
            tool="run_python",
            argv=(sys.executable, script.name),
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )

    def close(self) -> None:
        cleanup_path(self.workdir)

    def _run(
        self,
        *,
        tool: str,
        argv: tuple[str, ...],
        target_url: str,
        timeout_seconds: int | None,
    ) -> ToolResult:
        env = child_process_environment(
            home=self.workdir,
            overrides={
                "RAVAGE_TARGET_URL": target_url,
                "PYTHONUNBUFFERED": "1",
            },
        )
        prepend_executable_path(env, self._project_tool_bin)
        timeout = timeout_or_default(timeout_seconds, default=self.timeout_seconds)
        execution_argv = _argv_with_project_tool_path(argv, self._project_tool_bin)
        try:
            completed = subprocess.run(  # noqa: S603
                execution_argv,
                cwd=self.workdir,
                env=env,
                text=False,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                ok=False,
                tool=tool,
                command=argv,
                exit_code=None,
                stdout=clip(_decode_process_output(exc.stdout), self.max_output_chars),
                stderr=clip(_decode_process_output(exc.stderr), self.max_output_chars),
                error=f"timed out after {timeout}s",
                timed_out=True,
            )
        except OSError as exc:
            return ToolResult(
                ok=False,
                tool=tool,
                command=argv,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                error=str(exc),
            )
        return ToolResult(
            ok=completed.returncode == 0,
            tool=tool,
            command=argv,
            exit_code=completed.returncode,
            stdout=clip(_decode_process_output(completed.stdout), self.max_output_chars),
            stderr=clip(_decode_process_output(completed.stderr), self.max_output_chars),
        )


def _argv_with_project_tool_path(argv: tuple[str, ...], path: Path) -> tuple[str, ...]:
    if argv[:2] != ("sh", "-lc") or not argv[2:]:
        return argv
    command = command_with_executable_path(argv[2], path)
    return (*argv[:2], command, *argv[3:])


def _decode_process_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")
