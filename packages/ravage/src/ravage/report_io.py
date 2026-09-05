from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path

_PRIVATE_FILE_MODE = 0o600


def atomic_write_private_report(path: Path, content: str) -> None:
    """Publish a complete report with owner-only permissions, preserving old output on failure."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), _PRIVATE_FILE_MODE)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(path)
        _fsync_directory(path.parent)
    finally:
        with suppress(FileNotFoundError):
            temporary_path.unlink()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    with suppress(OSError):
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
