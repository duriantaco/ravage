from __future__ import annotations

import json
import os
import re
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from ravage.report import build_pentest_report, redact_sensitive

_PRIVATE_FILE_MODE = 0o600
_PATH_SEPARATOR_RE = re.compile(r"([/\\\\]+)")


def write_json_report_artifact(  # noqa: PLR0913
    *,
    brief_path: Path,
    target_url: str,
    workspace_dir: Path,
    output_path: Path,
    status: str,
    completed: bool,
    audit_db_path: Path | None = None,
    error: str | None = None,
    termination_reason: str = "",
    markdown_report_path: Path | None = None,
    professional_report_path: Path | None = None,
) -> dict[str, Any]:
    """Persist the canonical redacted JSON report without running report-time agents."""
    report = build_pentest_report(
        brief_path=brief_path,
        target_url=target_url,
        workspace_dir=workspace_dir,
        status=status,
        completed=completed,
        audit_db_path=audit_db_path,
        error=error,
    )
    report["artifacts"] = {
        "json_report_path": str(output_path),
        "markdown_report_path": str(markdown_report_path) if markdown_report_path else "",
        "professional_report_path": (
            str(professional_report_path) if professional_report_path else ""
        ),
    }
    if termination_reason:
        run = report.get("run")
        if isinstance(run, dict):
            run["termination_reason"] = termination_reason
    report = _redact_report_payload(report)
    _atomic_write_private_json(output_path, report)
    return report


def _redact_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact metadata added after ``build_pentest_report`` performed its own pass."""

    def redact(value: object, *, path_context: bool = False) -> object:
        if isinstance(value, dict):
            redacted: dict[str, object] = {}
            for key, item in value.items():
                safe_key = redact_sensitive(str(key))
                redacted[safe_key] = redact(
                    item,
                    path_context=safe_key.endswith(("_path", "_paths")),
                )
            return redacted
        if isinstance(value, (list, tuple)):
            return [redact(item, path_context=path_context) for item in value]
        if isinstance(value, str):
            if path_context:
                return "".join(
                    part if _PATH_SEPARATOR_RE.fullmatch(part) else redact_sensitive(part)
                    for part in _PATH_SEPARATOR_RE.split(value)
                )
            return redact_sensitive(value)
        return value

    return cast("dict[str, Any]", redact(payload))


def _atomic_write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.chmod(_PRIVATE_FILE_MODE)
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


__all__ = ["write_json_report_artifact"]
