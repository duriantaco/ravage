from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ravage.agent_knowledge import describe_knowledge_pack
from ravage.xben_parts.route_stage_policy import agent_stage_timeout_policy
from ravage.xben_parts.util import _agent_env

if TYPE_CHECKING:
    from typing import TextIO

    from ravage.xben_parts.models import XbenSettings


def _run_agent_subprocess(  # noqa: PLR0913 - subprocess boundary needs explicit paths.
    *,
    settings: XbenSettings,
    brief_path: Path,
    target_url: str,
    db_path: Path,
    workspace_path: Path,
    stdout: TextIO,
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

    env = _agent_env(settings)
    if tool_network_evidence_path is not None:
        env["RAVAGE_TOOL_NETWORK_EVIDENCE_PATH"] = str(tool_network_evidence_path)

    timeout_policy = agent_stage_timeout_policy(settings)
    result = subprocess.run(  # noqa: S603
        cmd,
        cwd=Path.cwd(),
        env=env,
        stdout=stdout,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_policy.subprocess_seconds,
        check=False,
    )
    if result.returncode != 0:
        message = f"agent exited with code {result.returncode}"
        raise RuntimeError(message)
