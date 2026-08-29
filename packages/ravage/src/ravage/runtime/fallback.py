from __future__ import annotations

from pathlib import Path

from ravage.web_core.scope_policy import is_local_url

from .docker import DockerToolRuntime
from .host import ExternalToolRuntime
from .types import (
    COMMAND_NOT_FOUND_EXIT_CODE,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOOL_IMAGE,
    MAX_OUTPUT_CHARS,
    ToolResult,
    ToolRuntime,
)


class DockerFallbackToolRuntime(ToolRuntime):
    def __init__(
        self,
        *,
        host_runtime: ToolRuntime | None = None,
        docker_runtime: ToolRuntime | None = None,
        image: str = DEFAULT_TOOL_IMAGE,
        scope: object | None = None,
        session_id: str | None = None,
        cleanup_evidence_path: str | Path | None = None,
        allow_remote_target: bool = False,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_output_chars: int = MAX_OUTPUT_CHARS,
    ) -> None:
        self.host_runtime = host_runtime or ExternalToolRuntime(
            timeout_seconds=timeout_seconds,
            max_output_chars=max_output_chars,
        )
        self.allow_remote_target = allow_remote_target
        try:
            self.docker_runtime = docker_runtime or DockerToolRuntime(
                image=image,
                scope=scope,
                session_id=session_id,
                cleanup_evidence_path=cleanup_evidence_path,
                allow_remote_target=allow_remote_target,
                timeout_seconds=timeout_seconds,
                max_output_chars=max_output_chars,
            )
        except Exception:
            self.host_runtime.close()
            raise

    def write_free_roam_context(self, text: str) -> None:
        self.host_runtime.write_free_roam_context(text)
        self.docker_runtime.write_free_roam_context(text)

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        if self.allow_remote_target and not is_local_url(target_url):
            return self.docker_runtime.run_command(
                command=command,
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )
        result = self.host_runtime.run_command(
            command=command,
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )
        if _should_try_docker(result):
            return self.docker_runtime.run_command(
                command=command,
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )
        return result

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        if self.allow_remote_target and not is_local_url(target_url):
            return self.docker_runtime.run_python(
                code=code,
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )
        result = self.host_runtime.run_python(
            code=code,
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )
        if _should_try_docker(result):
            return self.docker_runtime.run_python(
                code=code,
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )
        return result

    def close(self) -> None:
        self.host_runtime.close()
        self.docker_runtime.close()


def _should_try_docker(result: ToolResult) -> bool:
    if result.exit_code == COMMAND_NOT_FOUND_EXIT_CODE:
        return True
    text = f"{result.stdout}\n{result.stderr}\n{result.error or ''}".lower()
    if "modulenotfounderror: no module named" in text or "importerror: no module named" in text:
        return True
    if result.tool == "run_python" and "no module named" in text:
        return True
    return "not found" in text and result.exit_code in {1, 2, 126, 127}
