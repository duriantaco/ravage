from __future__ import annotations

import os
import subprocess
from pathlib import Path
from uuid import uuid4

from .common import assert_tool_target_url, safe_code, safe_command, timeout_or_default
from .host import ExternalToolRuntime
from .image import ToolImageError, ensure_tool_image
from .scoped_network import ScopedDockerNetwork, ScopedNetworkError
from .types import (
    CONTAINER_WORKDIR,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOOL_IMAGE,
    MAX_OUTPUT_CHARS,
    ToolResult,
)


class DockerToolRuntime(ExternalToolRuntime):
    def __init__(
        self,
        *,
        image: str = DEFAULT_TOOL_IMAGE,
        scope: object | None = None,
        session_id: str | None = None,
        cleanup_evidence_path: str | Path | None = None,
        allow_remote_target: bool = False,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_output_chars: int = MAX_OUTPUT_CHARS,
    ) -> None:
        if scope is None:
            raise ValueError("Docker tool runtime requires an explicit scope")
        super().__init__(
            timeout_seconds=timeout_seconds,
            max_output_chars=max_output_chars,
        )
        self.image = image
        self.session_id = str(session_id or uuid4())
        self.allow_remote_target = allow_remote_target
        self.scoped_network = ScopedDockerNetwork(
            image=image,
            scope=scope,
            session_id=self.session_id,
            evidence_path=cleanup_evidence_path,
            allow_remote_target=allow_remote_target,
        )
        try:
            ensure_tool_image(image)
            self.scoped_network.ensure_started()
        except ToolImageError as exc:
            super().close()
            raise ScopedNetworkError(str(exc)) from exc
        except Exception:
            super().close()
            raise

    @property
    def cleanup_evidence(self) -> dict[str, object] | None:
        return self.scoped_network.cleanup_evidence

    def write_free_roam_context(self, text: str) -> None:
        super().write_free_roam_context(self.scoped_network.rewrite_for_container(text))

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        try:
            assert_tool_target_url(
                target_url,
                allow_remote_target=self.allow_remote_target,
            )
            command = self.scoped_network.rewrite_for_container(safe_command(command))
        except ValueError as exc:
            return ToolResult(
                ok=False,
                tool="run_command",
                command=("sh", "-lc", command[:200]),
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
            assert_tool_target_url(
                target_url,
                allow_remote_target=self.allow_remote_target,
            )
            code = self.scoped_network.rewrite_for_container(safe_code(code))
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
            argv=("python3", script.name),
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )

    def _run(
        self,
        *,
        tool: str,
        argv: tuple[str, ...],
        target_url: str,
        timeout_seconds: int | None,
    ) -> ToolResult:
        timeout = timeout_or_default(timeout_seconds, default=self.timeout_seconds)
        try:
            self.scoped_network.ensure_started()
            docker_url = self.scoped_network.container_url(target_url)
        except (ScopedNetworkError, ValueError) as exc:
            return ToolResult(
                ok=False,
                tool=tool,
                command=argv,
                exit_code=None,
                stdout="",
                stderr="",
                error=str(exc),
            )
        container_name = self.scoped_network.next_tool_container_name()
        rewritten_argv = tuple(self.scoped_network.rewrite_for_container(item) for item in argv)
        workdir_mount = f"type=bind,src={self.workdir},dst={CONTAINER_WORKDIR}"
        docker_argv = (
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--name",
            container_name,
            *self.scoped_network.tool_labels(),
            "--network",
            self.scoped_network.network_name,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",
            "-e",
            f"RAVAGE_TARGET_URL={docker_url}",
            "-e",
            "PYTHONUNBUFFERED=1",
            "--mount",
            workdir_mount,
            "-w",
            CONTAINER_WORKDIR,
            self.image,
            *rewritten_argv,
        )
        try:
            completed = subprocess.run(  # noqa: S603
                docker_argv,
                cwd=self.workdir,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                ok=False,
                tool=tool,
                command=docker_argv,
                exit_code=None,
                stdout=str(exc.stdout or "")[: self.max_output_chars],
                stderr=str(exc.stderr or "")[: self.max_output_chars],
                error=f"timed out after {timeout}s",
                timed_out=True,
            )
        except OSError as exc:
            return ToolResult(
                ok=False,
                tool=tool,
                command=docker_argv,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                error=str(exc),
            )
        return ToolResult(
            ok=completed.returncode == 0,
            tool=tool,
            command=docker_argv,
            exit_code=completed.returncode,
            stdout=(completed.stdout or "")[: self.max_output_chars],
            stderr=(completed.stderr or "")[: self.max_output_chars],
        )

    def close(self) -> None:
        try:
            self.scoped_network.close()
        finally:
            super().close()
