from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING
from urllib.parse import ParseResult, urlparse, urlunparse

from ravage.web_core.scope_policy import is_local_host

from .types import MAX_CODE_CHARS, MAX_COMMAND_CHARS, MAX_OUTPUT_CHARS, ToolResult

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_CHILD_PROCESS_ENVIRONMENT_KEYS = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "WINDIR",
)


def assert_http_url(target_url: str) -> ParseResult:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        msg = "target URL must use http or https"
        raise ValueError(msg)
    if parsed.hostname is None:
        msg = "target URL must include a host"
        raise ValueError(msg)
    try:
        _ = parsed.port
    except ValueError as exc:
        msg = "target URL contains an invalid TCP port"
        raise ValueError(msg) from exc
    return parsed


def assert_tool_target_url(
    target_url: str,
    *,
    allow_remote_target: bool = False,
) -> ParseResult:
    parsed = assert_http_url(target_url)
    if not is_local_host(parsed.hostname) and not allow_remote_target:
        msg = "tool runtime is restricted to localhost benchmark targets"
        raise ValueError(msg)
    return parsed


def assert_local_url(target_url: str) -> ParseResult:
    return assert_tool_target_url(target_url, allow_remote_target=False)


def clip(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


def safe_command(command: str) -> str:
    if len(command) > MAX_COMMAND_CHARS:
        msg = f"command too large ({len(command)} chars)"
        raise ValueError(msg)
    if "\x00" in command:
        msg = "command contains NUL byte"
        raise ValueError(msg)
    return command


def safe_code(code: str) -> str:
    if len(code) > MAX_CODE_CHARS:
        msg = f"python code too large ({len(code)} chars)"
        raise ValueError(msg)
    if "\x00" in code:
        msg = "python code contains NUL byte"
        raise ValueError(msg)
    return code


def child_process_environment(
    *,
    home: Path,
    overrides: Mapping[str, str] | None = None,
    parent: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimal environment for model-selected host processes."""
    source = os.environ if parent is None else parent
    environment = {
        key: value
        for key in _CHILD_PROCESS_ENVIRONMENT_KEYS
        if (value := source.get(key)) is not None
    }
    environment.setdefault("PATH", os.defpath)
    environment["HOME"] = str(home)
    if os.name == "nt":
        environment["USERPROFILE"] = str(home)
    if overrides is not None:
        environment.update({str(key): str(value) for key, value in overrides.items()})
    return environment


def timeout_or_default(timeout_seconds: int | None, *, default: int) -> int:
    if timeout_seconds is None:
        return default
    return max(1, min(int(timeout_seconds), 180))


def unavailable(tool: str) -> ToolResult:
    return ToolResult(
        ok=False,
        tool=tool,
        command=(tool,),
        exit_code=127,
        stdout="",
        stderr=f"{tool} not found",
        error=f"{tool} not found",
    )


def cleanup_path(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def docker_target_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    host = parsed.hostname or "127.0.0.1"
    if host not in {"127.0.0.1", "localhost", "0.0.0.0"}:
        return target_url
    netloc = "host.docker.internal"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )
