from __future__ import annotations

import os
import shlex
from pathlib import Path


def project_tool_bin(*, root: Path | None = None) -> Path:
    """Return the absolute project-local scanner directory."""
    project_root = root if root is not None else Path.cwd()
    return project_root.absolute() / ".tools" / "bin"


def is_executable_file(path: Path) -> bool:
    """Return whether *path* is a regular file the current user can execute."""
    return path.is_file() and os.access(path, os.X_OK)


def prepend_executable_path(env: dict[str, str], path: Path) -> None:
    """Prepend an absolute directory to PATH once."""
    entry = str(path.absolute())
    current = env.get("PATH", "")
    entries = current.split(os.pathsep) if current else []
    if entry in entries:
        return
    env["PATH"] = os.pathsep.join((entry, *entries))


def command_with_executable_path(command: str, path: Path) -> str:
    """Reapply a PATH entry after a login shell has loaded its profile."""
    entry = shlex.quote(str(path.absolute()))
    return f"export PATH={entry}${{PATH:+:$PATH}}; {command}"
