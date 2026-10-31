from __future__ import annotations

from pathlib import Path


def test_checked_in_execution_workflow_is_secretless_and_mechanically_blocked() -> None:
    repository = Path(__file__).resolve().parents[2]
    path = repository / ".github/workflows/paired-xben-execution.yml"
    source = path.read_text(encoding="utf-8")

    assert "runs-on: ubuntu-24.04" in source
    assert "github.ref_protected != true" in source
    assert "github.run_attempt != 1" in source
    assert "run: exit 2" in source
    assert "cancel-in-progress: false" in source
    assert "tools.paired_xben.github_runner assessment" in source
    assert "persist-credentials: false" in source
    assert "environment:" not in source
    assert "OPENAI_API_KEY" not in source
    assert "secrets:" not in source
    assert "contents: write" not in source
    assert "id-token: write" not in source
    assert "docker " not in source.lower()
    assert "strategy:" not in source
    assert "matrix:" not in source


def test_execution_workflow_has_no_operator_selected_run_or_matrix_input() -> None:
    repository = Path(__file__).resolve().parents[2]
    source = (repository / ".github/workflows/paired-xben-execution.yml").read_text(
        encoding="utf-8"
    )

    assert "source_run_id:" not in source
    assert "source_artifact_name:" not in source
    assert "workflow_run_id:" not in source
    assert "matrix_json:" not in source
    assert "pair_indexes:" not in source
    assert "retry:" not in source
    assert "resume:" not in source
    assert "replacement:" not in source
