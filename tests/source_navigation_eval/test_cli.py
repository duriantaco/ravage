from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from scripts.eval import run_source_navigation_eval as cli

if TYPE_CHECKING:
    from pathlib import Path


def test_offline_command_works_from_another_directory(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(cli.ROOT / "scripts/eval/run_source_navigation_eval.py"),
            "offline",
            "--output",
            str(output),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(output.read_text())
    assert report["passed"]
    assert report["revision"] == report["post_revision"]
    assert report["toolchain_sha256"]
    assert report["corpus_sha256"]
    assert report["false_negatives"] == report["false_positives"] == 0


def test_existing_report_is_preserved(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    output.write_text("previous evidence\n")
    with pytest.raises(SystemExit, match="2"):
        cli.main(["offline", "--output", str(output)])
    assert output.read_text() == "previous evidence\n"


@pytest.mark.parametrize(
    "args",
    [
        ["canary", "--driver", "gpt54"],
        ["offline", "--driver", "gpt54", "--allow-paid-models"],
    ],
)
def test_no_implicit_paid_runs(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main(args)
    assert "model" in capsys.readouterr().err


def test_paid_run_rejects_uncommitted_changes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "revision", lambda: {"head": "before", "clean": False})
    monkeypatch.setattr(cli, "toolchain_digest", lambda: "unchanged")
    with pytest.raises(SystemExit, match="2"):
        cli.main(["canary", "--driver", "gpt54", "--allow-paid-models"])
    assert "clean committed revision" in capsys.readouterr().err


def test_toolchain_change_invalidates_an_otherwise_passing_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.json"
    hashes = iter(("before", "after"))
    monkeypatch.setattr(cli, "revision", lambda: {"head": "unchanged", "clean": True})
    monkeypatch.setattr(cli, "toolchain_digest", lambda: next(hashes))
    monkeypatch.setattr(cli, "evaluate_corpus", lambda: {"passed": True})
    assert cli.main(["offline", "--output", str(output)]) == 1
    report = json.loads(output.read_text())
    assert not report["passed"]
    assert report["integrity_error"]
