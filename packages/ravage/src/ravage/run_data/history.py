"""Read-only index of saved run reports for an operator-selected directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from ravage.report import REPORT_SCHEMA_VERSION, redact_sensitive
from ravage.traffic.redaction import sanitize_url

_MAX_REPORT_BYTES = 8 * 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_REPORT_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_RUN_STATUSES = ("completed", "incomplete", "interrupted", "error")


def build_run_history(run_root: Path) -> dict[str, object]:
    """Group finalized reports by recorded engagement, origin, and scope."""
    assets: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    skipped_reports: list[str] = []
    root_fd = os.open(run_root, _DIRECTORY_FLAGS)
    try:
        with os.scandir(root_fd) as entries:
            names = sorted(entry.name for entry in entries if entry.is_dir(follow_symlinks=False))
        for name in names:
            relative_report = f"{name}/report.json"
            try:
                document, digest = _read_report(root_fd, name)
                asset, run = _summarize_report(document)
            except FileNotFoundError:
                continue
            except (OSError, RecursionError, TypeError, ValueError):
                skipped_reports.append(relative_report)
                continue
            assets[asset].append({"report": relative_report, "report_sha256": digest, **run})
    finally:
        os.close(root_fd)

    return {
        "schema": "ravage.run-history.v1",
        "assets": [
            {
                "engagement_id": redact_sensitive(engagement),
                "origin": origin,
                "scope_sha256": scope,
                "runs": runs,
            }
            for (engagement, origin, scope), runs in sorted(assets.items())
        ],
        "runs_indexed": sum(len(runs) for runs in assets.values()),
        "skipped_reports": skipped_reports,
    }


def _read_report(root_fd: int, name: str) -> tuple[object, str]:
    run_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=root_fd)
    try:
        report_fd = os.open("report.json", _REPORT_FLAGS, dir_fd=run_fd)
        with os.fdopen(report_fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_REPORT_BYTES:
                message = "report must be a bounded regular file"
                raise ValueError(message)
            data = stream.read(opened.st_size + 1)
            after = os.fstat(stream.fileno())
            if (
                len(data) != opened.st_size
                or opened.st_mtime_ns != after.st_mtime_ns
                or opened.st_ctime_ns != after.st_ctime_ns
            ):
                message = "report changed while being read"
                raise ValueError(message)
    finally:
        os.close(run_fd)
    return json.loads(data, object_pairs_hook=_unique_keys), _sha256(data)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "report has duplicate keys"
            raise ValueError(message)
        result[key] = value
    return result


def _summarize_report(document: object) -> tuple[tuple[str, str, str], dict[str, object]]:
    if not isinstance(document, dict) or document.get("schema_version") != REPORT_SCHEMA_VERSION:
        message = "expected a canonical Ravage report"
        raise ValueError(message)
    status = document.get("status")
    completed = document.get("completed")
    findings = document.get("findings")
    if (
        status not in _RUN_STATUSES
        or type(completed) is not bool
        or completed != (status == "completed")
        or not isinstance(findings, list)
        or not all(isinstance(finding, dict) for finding in findings)
    ):
        message = "expected a finalized run with structured findings"
        raise ValueError(message)
    engagement = document.get("engagement")
    if not isinstance(engagement, dict):
        message = "report has no engagement"
        raise TypeError(message)
    asset = _asset_key(engagement)
    run = {
        "status": status,
        "completed": completed,
        "finding_count": len(findings),
        "evidence_status": _recorded_status(
            document.get("source_quality"), "complete", "incomplete"
        ),
        "traffic_accounting": _recorded_status(
            document.get("traffic_accounting"), "exact", "lower_bound"
        ),
        "assessment_coverage": _recorded_status(
            document.get("assessment_coverage"),
            "known_tasks_exhausted",
            "objective_limited",
            "partial",
            "not_available",
        ),
        "scan_coverage": _recorded_status(
            document.get("scan_coverage"), "complete", "partial", "not_available"
        ),
    }
    return asset, run


def _asset_key(engagement: dict[str, object]) -> tuple[str, str, str]:
    identifier = engagement.get("engagement_id")
    target = engagement.get("target_url")
    scope = engagement.get("scope")
    if (
        not isinstance(identifier, str)
        or not identifier.strip()
        or not isinstance(target, str)
        or not isinstance(scope, dict)
    ):
        message = "report has incomplete engagement metadata"
        raise ValueError(message)
    parsed = urlsplit(sanitize_url(target))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        message = "report target has no HTTP origin"
        raise ValueError(message)
    default_port = 443 if parsed.scheme == "https" else 80
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    port = parsed.port
    authority = f"{host}:{port}" if port is not None and port != default_port else host
    scope_bytes = json.dumps(scope, sort_keys=True, allow_nan=False).encode("utf-8")
    return identifier, f"{parsed.scheme}://{authority}", _sha256(scope_bytes)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _recorded_status(value: object, *accepted: str) -> str:
    status = value.get("status") if isinstance(value, dict) else None
    return status if isinstance(status, str) and status in accepted else "unavailable"


def handle_run_history_command(args: list[str]) -> None:
    """Print the index without writing to the run archive."""
    parser = argparse.ArgumentParser(
        prog="ravage history",
        description="Index saved report.json files in direct child run directories.",
    )
    parser.add_argument("run_root", type=Path, help="directory containing saved runs")
    parsed = parser.parse_args(args)
    try:
        history = build_run_history(parsed.run_root)
    except OSError as exc:
        parser.exit(1, f"{parser.prog}: cannot read run directory: {exc}\n")
    sys.stdout.write(json.dumps(history, indent=2) + "\n")
