from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from ravage.memory_eval import MemoryEvalUnavailableError, run_memory_eval

if TYPE_CHECKING:
    from collections.abc import Mapping

_REPO_ROOT = Path(__file__).resolve().parents[3]
_UNAVAILABLE_EXIT_CODE = 2


def test_memory_eval_is_unavailable_without_inputs() -> None:
    with pytest.raises(MemoryEvalUnavailableError, match="No evaluation was run"):
        run_memory_eval()


def test_memory_eval_does_not_call_models_or_write_reports(tmp_path: Path) -> None:
    class UnexpectedModelClient:
        @staticmethod
        def complete(**_kwargs: object) -> None:
            pytest.fail("unavailable evaluation must never invoke models")

    clients: Mapping[str, object] = {"offline-case": UnexpectedModelClient()}
    output_dir = tmp_path / "reports"
    memory_db = tmp_path / "memory.db"

    with pytest.raises(MemoryEvalUnavailableError, match="no benchmark evaluator"):
        run_memory_eval(
            manifest_path=tmp_path / "missing.yaml",
            output_dir=output_dir,
            memory_db_path=memory_db,
            off_ai_model_clients=clients,
            read_ai_model_clients=clients,
        )

    assert not output_dir.exists()
    assert not memory_db.exists()


def test_memory_eval_preserves_existing_artifacts(tmp_path: Path) -> None:
    report_path = tmp_path / "memory-eval-report.json"
    previous_result = '{"provenance": "previous independent evaluation"}\n'
    report_path.write_text(previous_result, encoding="utf-8")

    with pytest.raises(MemoryEvalUnavailableError):
        run_memory_eval(output_dir=tmp_path)

    assert report_path.read_text(encoding="utf-8") == previous_result


@pytest.mark.parametrize("script", ["run_memory_eval.py", "eval/run_memory_eval.py"])
def test_memory_eval_cli_help_and_unavailable(script: str, tmp_path: Path) -> None:
    command = [sys.executable, str(_REPO_ROOT / "scripts" / script)]
    help_result = subprocess.run(  # noqa: S603 - fixed local script, no shell.
        [*command, "--help"], capture_output=True, text=True, check=False, timeout=15
    )
    assert help_result.returncode == 0
    assert "unavailable" in help_result.stdout
    output_dir = tmp_path / "reports"
    result = subprocess.run(  # noqa: S603 - fixed local script, no shell.
        [*command, "--benchmark", str(tmp_path / "missing.yaml"), "--output-dir", str(output_dir)],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == _UNAVAILABLE_EXIT_CODE
    assert "[memory-eval:unavailable]" in result.stderr
    assert "No evaluation was run" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output_dir.exists()
