from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from ravage.agent_knowledge import describe_knowledge_pack
from ravage.cli_ui import tone
from ravage.xben_parts.route_stage_policy import agent_stage_timeout_policy
from ravage.xben_parts.util import _agent_env

if TYPE_CHECKING:
    from typing import TextIO

    from ravage.xben_parts.models import XbenSettings


def _run_agent_subprocess(  # noqa: C901, PLR0913 - explicit subprocess boundary.
    *,
    settings: XbenSettings,
    brief_path: Path,
    target_url: str,
    db_path: Path,
    workspace_path: Path,
    stdout: TextIO,
    source_root: Path | None = None,
    live_stdout: TextIO | None = None,
    tool_network_evidence_path: Path | None = None,
) -> None:
    cmd = [
        sys.executable,
        "-m",
        "ravage",
        "attack",
        str(brief_path),
        "--run-dir",
        str(db_path.parent),
        "--agent-mode",
        settings.agent_mode,
        "--target-url",
        target_url,
        "--db-path",
        str(db_path),
        "--workspace-dir",
        str(workspace_path),
        "--model-profile",
        settings.model_profile,
        "--model-tier",
        settings.model_tier,
        "--max-turns",
        str(settings.max_turns),
        "--tool-runtime",
        settings.tool_runtime,
        "--tool-image",
        settings.tool_image,
    ]
    if source_root is not None:
        cmd.extend(["--source-root", str(source_root)])
    if settings.knowledge_pack_path is not None:
        metadata = describe_knowledge_pack(
            settings.knowledge_pack_path,
            expected_sha256=settings.knowledge_pack_sha256,
        )
        if metadata is None:
            message = "knowledge pack metadata is unavailable"
            raise ValueError(message)
        cmd.extend(["--knowledge-pack", str(settings.knowledge_pack_path)])
        cmd.extend(["--knowledge-pack-sha256", metadata.sha256])
        cmd.extend(["--knowledge-pack-limit", str(settings.knowledge_pack_limit)])
        cmd.extend(["--knowledge-pack-max-chars", str(settings.knowledge_pack_max_chars)])
    if settings.model_config is not None:
        cmd.extend(["--model-config", str(settings.model_config)])
    if settings.recovery_profile != "off":
        cmd.extend(["--recovery-profile", settings.recovery_profile])
    if settings.autonomous_route:
        cmd.append("--autonomous-route")
        cmd.extend(
            [
                "--autonomous-route-engine",
                settings.autonomous_route_engine,
                "--autonomous-route-max-requests",
                str(settings.autonomous_route_max_requests),
            ]
        )
    if settings.allow_degraded:
        cmd.append("--allow-degraded")
    if settings.allow_paid_models:
        cmd.append("--allow-paid-models")
    if settings.stream_agent_output:
        cmd.append("--show-agent-actions")

    env = _agent_env(settings)
    if tool_network_evidence_path is not None:
        env["RAVAGE_TOOL_NETWORK_EVIDENCE_PATH"] = str(tool_network_evidence_path)

    timeout_policy = agent_stage_timeout_policy(settings)
    returncode = _run_agent_process(
        cmd=cmd,
        env=env,
        captured_stdout=stdout,
        live_stdout=live_stdout,
        timeout_seconds=timeout_policy.subprocess_seconds,
    )
    if returncode != 0:
        message = f"agent exited with code {returncode}"
        raise RuntimeError(message)


def _run_agent_process(
    *,
    cmd: list[str],
    env: dict[str, str],
    captured_stdout: TextIO,
    live_stdout: TextIO | None,
    timeout_seconds: int,
) -> int:
    if live_stdout is None:
        result = subprocess.run(  # noqa: S603
            cmd,
            cwd=Path.cwd(),
            env=env,
            stdout=captured_stdout,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return result.returncode
    return _run_agent_with_live_tee(
        cmd=cmd,
        env=env,
        captured_stdout=captured_stdout,
        live_stdout=live_stdout,
        timeout_seconds=timeout_seconds,
    )


def _run_agent_with_live_tee(
    *,
    cmd: list[str],
    env: dict[str, str],
    captured_stdout: TextIO,
    live_stdout: TextIO,
    timeout_seconds: int,
) -> int:
    """Stream a child attack to the operator while preserving the scoring log."""
    process = subprocess.Popen(  # noqa: S603
        cmd,
        cwd=Path.cwd(),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    pipe = process.stdout
    if pipe is None:  # pragma: no cover - PIPE above guarantees a reader.
        process.kill()
        process.wait()
        message = "agent live output pipe was not created"
        raise RuntimeError(message)

    capture_errors: list[Exception] = []
    pump = threading.Thread(
        target=_pump_agent_output,
        args=(pipe, captured_stdout, live_stdout, capture_errors),
        name="ravage-xben-agent-output",
        daemon=True,
    )
    pump.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        pump.join()

    if capture_errors:
        message = "could not capture streamed agent output"
        raise RuntimeError(message) from capture_errors[0]
    return returncode


def _pump_agent_output(
    pipe: TextIO,
    captured_stdout: TextIO,
    live_stdout: TextIO,
    capture_errors: list[Exception],
) -> None:
    live_output_available = True
    try:
        for line in pipe:
            if not capture_errors:
                try:
                    captured_stdout.write(line)
                    captured_stdout.flush()
                except Exception as exc:  # noqa: BLE001 - report after draining the child.
                    capture_errors.append(exc)
            if live_output_available:
                try:
                    live_stdout.write(_styled_live_output_line(line, stream=live_stdout))
                    live_stdout.flush()
                except (BrokenPipeError, OSError, ValueError):
                    # Losing the viewer must not lose the benchmark artifact.
                    live_output_available = False
    finally:
        pipe.close()


_HARD_FAILURE_MARKERS = (
    "blocked",
    "failed",
    "invalid",
    "out of scope",
    "rejected",
    "timed out",
    "response · 5",
)

_CONFIRMED_RESULT_MARKERS = (
    "[redacted-proof]",
    "flag found",
    "vulnerability confirmed",
)


def _styled_live_output_line(line: str, *, stream: TextIO) -> str:
    """Color the operator's live tee without contaminating the scoring artifact."""
    ending = "\n" if line.endswith("\n") else ""
    value = line.removesuffix("\n")
    lowered = value.casefold()
    style = ""
    if value.startswith("[agent]"):
        style = "agent"
    elif value.startswith("[fail]") or (
        value.startswith("[warn]")
        and any(marker in lowered for marker in _HARD_FAILURE_MARKERS)
    ):
        style = "fail"
    elif value.startswith("[ok]") and any(
        marker in lowered for marker in _CONFIRMED_RESULT_MARKERS
    ):
        style = "ok"
    return (tone(value, style, stream=stream) if style else value) + ending
