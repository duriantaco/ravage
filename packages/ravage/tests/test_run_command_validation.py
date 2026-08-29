from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage import __main__ as cli

if TYPE_CHECKING:
    from pathlib import Path

_ARGPARSE_ERROR = 2


def test_audit_verify_rejects_missing_path_without_creating_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing-run"

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["audit", "verify", str(missing)])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert not missing.exists()
    error = capsys.readouterr().err
    assert "does not exist" in error
    assert "existing RUN_DIR or audit.db" in error
    assert "Traceback" not in error


def test_audit_verify_rejects_non_ravage_database_without_modifying_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invalid = tmp_path / "audit.db"
    invalid.write_text("not a sqlite database\n", encoding="utf-8")
    original = invalid.read_bytes()

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["audit", "verify", str(invalid)])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert invalid.read_bytes() == original
    error = capsys.readouterr().err
    assert "invalid Ravage audit database" in error
    assert "Traceback" not in error


def test_observe_rejects_missing_run_without_building_dashboard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing-run"

    def unexpected_build(_settings: object) -> dict[str, object]:
        pytest.fail("dashboard should not be built")

    monkeypatch.setattr(cli, "build_dashboard_state", unexpected_build)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["observe", str(missing), "--json"])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert not missing.exists()
    error = capsys.readouterr().err
    assert "run path does not exist" in error
    assert "Traceback" not in error


def test_observe_accepts_existing_workspace_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    workspace = run_dir / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "events.jsonl").write_text(
        json.dumps({"kind": "agent_finished", "payload": {"status": "completed"}}) + "\n",
        encoding="utf-8",
    )

    cli.main(["observe", str(run_dir), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["exists"]["workspace"] is True
    assert payload["exists"]["events"] is True


def test_report_rejects_missing_run_before_creating_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing-run"

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["report", str(missing), "--brief", str(tmp_path / "missing.yaml")])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert not missing.exists()
    assert not (missing / "report.md").exists()
    error = capsys.readouterr().err
    assert "run path does not exist" in error
    assert "Traceback" not in error


def test_report_rejects_empty_directory_before_creating_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    empty_run = tmp_path / "empty-run"
    empty_run.mkdir()

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["report", str(empty_run), "--brief", str(tmp_path / "missing.yaml")])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert not (empty_run / "report.md").exists()
    error = capsys.readouterr().err
    assert "no Ravage run artifacts found" in error
    assert "Traceback" not in error
