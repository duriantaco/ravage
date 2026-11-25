"""Regression coverage for the saved-run history command."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from ravage import __main__ as cli
from ravage.report import REPORT_SCHEMA_VERSION
from ravage.run_data.history import build_run_history

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _write_report(directory: Path, *, scope: str, status: str = "completed") -> Path:
    directory.mkdir()
    report = directory / "report.json"
    report.write_text(
        json.dumps(
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "status": status,
                "completed": status == "completed",
                "engagement": {
                    "engagement_id": "example-project",
                    "target_url": "https://example.test:443/private?token=private-value",
                    "scope": {"in_scope": [scope], "out_of_scope": []},
                },
                "findings": [{"title": "private-finding-text"}],
                "source_quality": {"status": "complete"},
                "assessment_coverage": {
                    "status": "known_tasks_exhausted" if status == "completed" else "partial"
                },
                "traffic_accounting": {"status": "lower_bound"},
            }
        ),
        encoding="utf-8",
    )
    return report


def test_history_cli_groups_finalized_runs_by_recorded_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = _write_report(tmp_path / "run-a", scope="/group-a")
    _write_report(tmp_path / "run-b", scope="/group-a", status="incomplete")
    _write_report(tmp_path / "run-c", scope="/group-b")

    cli.main(["history", str(tmp_path)])
    output = capsys.readouterr().out
    history = json.loads(output)
    assert history["runs_indexed"] == 3  # noqa: PLR2004
    assert {asset["origin"] for asset in history["assets"]} == {"https://example.test"}
    assert len({asset["scope_sha256"] for asset in history["assets"]}) == 2  # noqa: PLR2004
    indexed = next(asset["runs"] for asset in history["assets"] if len(asset["runs"]) > 1)
    assert [run["report"] for run in indexed] == ["run-a/report.json", "run-b/report.json"]
    assert [run["completed"] for run in indexed] == [True, False]
    assert indexed[0]["report_sha256"] == "sha256:" + hashlib.sha256(first.read_bytes()).hexdigest()
    assert indexed[0]["assessment_coverage"] == "known_tasks_exhausted"
    assert indexed[1]["assessment_coverage"] == "partial"
    assert indexed[1]["traffic_accounting"] == "lower_bound"
    assert "private" not in output
    assert "/group-" not in output


def test_history_skips_invalid_reports_and_symlinks(tmp_path: Path) -> None:
    outside = _write_report(tmp_path / "outside", scope="/group-a")
    root = tmp_path / "project"
    root.mkdir()
    (root / "linked-run").symlink_to(outside.parent, target_is_directory=True)
    linked = root / "linked-report"
    linked.mkdir()
    (linked / "report.json").symlink_to(outside)
    malformed = root / "malformed"
    malformed.mkdir()
    (malformed / "report.json").write_text('{"status":"completed","status":"error"}')
    (root / "report-pending").mkdir()
    _write_report(root / "running", scope="/group-a", status="running")

    history = build_run_history(root)
    assert history["runs_indexed"] == 0
    assert history["skipped_reports"] == [
        "linked-report/report.json",
        "malformed/report.json",
        "running/report.json",
    ]
