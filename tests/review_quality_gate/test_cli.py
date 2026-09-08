"""The CI entry point must fail closed before spending on invalid inputs."""

# ruff: noqa: PLR2004 - conventional CLI exit codes.

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tools.review_quality_gate import cli
from tools.review_quality_gate.gate import (
    BASELINE_PATH,
    POLICY_PATH,
    ROOT,
    _git,
    protect_baseline,
    read_json,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    destination = tmp_path / "repository"
    (destination / POLICY_PATH).parent.mkdir(parents=True)
    shutil.copyfile(ROOT / POLICY_PATH, destination / POLICY_PATH)
    return destination


def test_missing_baseline_is_a_red_gate_without_paid_calls(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    measure = Mock()
    monkeypatch.setattr(cli, "measure", measure)
    output = tmp_path / "missing-baseline"
    status = cli.main(
        [
            "check",
            "--repository-root",
            str(root),
            "--output-dir",
            str(output),
            "--allow-paid-models",
        ]
    )
    assert status == 1
    assert not read_json(output / "verdict.json")["passed"]
    measure.assert_not_called()


def test_record_cannot_overwrite_a_baseline(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = root / BASELINE_PATH
    baseline.write_text('{"retained": true}')
    measure = Mock()
    monkeypatch.setattr(cli, "measure", measure)
    assert (
        cli.main(
            [
                "record",
                "--repository-root",
                str(root),
                "--output-dir",
                str(tmp_path / "record"),
            ]
        )
        == 1
    )
    assert read_json(baseline) == {"retained": True}
    measure.assert_not_called()


def test_retry_requires_a_new_evidence_directory(root: Path, tmp_path: Path) -> None:
    output = tmp_path / "old-result"
    output.mkdir()
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--repository-root", str(root), "--output-dir", str(output)])
    assert exc.value.code == 2


def test_baseline_or_policy_edits_on_the_same_pr_are_rejected(root: Path) -> None:
    (root / BASELINE_PATH).write_text('{"frozen": true}')
    _git(root, "init", "--quiet")
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "test: freeze fixture baseline",
    )
    base = _git(root, "rev-parse", "HEAD").decode().strip()
    protect_baseline(root, base)
    (root / BASELINE_PATH).write_text('{"frozen": false}')
    with pytest.raises(ValueError, match=r"frozen.*changed"):
        protect_baseline(root, base)


def test_required_aggregate_cannot_ignore_quality_failure() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    quality = jobs["review_quality"]
    assert "review_quality" in jobs["fast_checks"]["needs"]
    aggregate = jobs["fast_checks"]["steps"][-1]
    assert aggregate["env"]["REVIEW_QUALITY_RESULT"] == "${{ needs.review_quality.result }}"
    assert 'test "${REVIEW_QUALITY_RESULT}" = success' in aggregate["run"]
    assert "if" not in quality
    assert "continue-on-error" not in quality
    execution = next(step for step in quality["steps"] if "--base-revision" in step.get("run", ""))
    assert " check " in execution["run"]
    assert " record " not in execution["run"]
    assert "continue-on-error" not in execution
    upload = quality["steps"][-1]
    assert upload["if"] == "${{ always() }}"
    assert upload["with"]["if-no-files-found"] == "error"


@pytest.mark.parametrize("quality", ["failure", "skipped", "cancelled", "", "success"])
def test_actual_aggregate_script_requires_a_successful_quality_run(quality: str) -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    step = jobs["fast_checks"]["steps"][-1]
    environment = dict.fromkeys(step["env"], "success")
    environment["REVIEW_QUALITY_RESULT"] = quality
    result = subprocess.run(  # noqa: S603 - execute the checked-in CI assertion script.
        ["bash", "-e", "-c", step["run"]],  # noqa: S607 - system shell, no external commands.
        env=environment,
        check=False,
        capture_output=True,
    )
    assert (result.returncode == 0) == (quality == "success")
