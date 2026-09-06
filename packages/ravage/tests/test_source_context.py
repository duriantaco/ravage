from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.agent_strategy import action_fingerprint
from ravage.agent_core.source_context import (
    SOURCE_CONTEXT_OBSERVATION_SCHEMA,
    SOURCE_CONTEXT_RECEIPT_SCHEMA,
    SourceContextExecutor,
    sanitize_source_context_action,
    source_context_action_error,
    source_context_action_schema,
)
from ravage.repository_context import capture_repository

if TYPE_CHECKING:
    from pathlib import Path

_RESUMED_OBSERVATION_CHARS = 123


def _action(operation: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "action": "source_context",
        "task_id": "surface-map",
        "operation": operation,
        "args": arguments,
    }


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_source_context_reads_only_the_captured_snapshot_after_disk_mutation(
    tmp_path: Path,
) -> None:
    source_path = _write(
        tmp_path,
        "src/handler.py",
        "def handler():\n    return 'captured-marker'\n",
    )
    context = capture_repository(tmp_path)
    executor = SourceContextExecutor(context)
    source_path.write_text("def handler():\n    return 'changed-marker'\n", encoding="utf-8")

    search = executor.execute(_action("search", {"query": "captured-marker"}))
    excerpt = executor.execute(
        _action(
            "excerpt",
            {"path": "src/handler.py", "start_line": 1, "end_line": 20},
        )
    )
    changed = executor.execute(_action("search", {"query": "changed-marker"}))

    assert search.ok is True
    assert search.observation["schema"] == SOURCE_CONTEXT_OBSERVATION_SCHEMA
    assert search.observation["trust"] == "untrusted_repository_content"
    assert search.observation["proof_eligible"] is False
    assert search.observation["provenance"] == {
        "kind": "source_code",
        "snapshot_id": context.snapshot_id,
    }
    assert search.observation["matches"][0]["text"].endswith("captured-marker'")
    assert excerpt.observation["text"] == "def handler():\n    return 'captured-marker'\n"
    assert excerpt.observation["clamped_to_eof"] is True
    assert changed.observation["matches"] == []


def test_source_context_lists_files_and_omissions_with_snapshot_provenance(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "src/app.py", "APP = True\n")
    _write(tmp_path, ".env", "SECRET=excluded\n")
    executor = SourceContextExecutor(capture_repository(tmp_path))

    files = executor.execute(_action("list_files", {"prefix": "src/", "limit": 1}))
    omissions = executor.execute(_action("list_omissions", {"limit": 10}))

    assert files.ok is True
    assert files.observation["files"] == [
        {
            "path": "src/app.py",
            "size_bytes": 11,
            "line_count": 1,
            "file_digest": files.observation["files"][0]["file_digest"],
        }
    ]
    assert omissions.ok is True
    assert omissions.observation["omissions"] == [{"path": ".env", "reason": "sensitive_file"}]
    assert files.receipt["snapshot_id"] == executor.snapshot_id
    assert omissions.receipt["snapshot_id"] == executor.snapshot_id


@pytest.mark.parametrize(
    "action",
    [
        {
            **_action("search", {"query": "needle"}),
            "memory_updates": ["persist repository text"],
        },
        _action("search", {"query": "needle", "regex": True}),
        _action("shell", {}),
        _action("search", {"query": "line one\nline two"}),
        _action("search", {"query": "needle", "max_matches": 21}),
        _action("list_files", {"limit": 101}),
        _action("excerpt", {"path": "app.py", "start_line": 1, "end_line": 81}),
        _action("excerpt", {"path": "app.py", "start_line": 3, "end_line": 2}),
    ],
)
def test_source_context_rejects_unknown_fields_and_out_of_bounds_values(
    tmp_path: Path,
    action: dict[str, object],
) -> None:
    _write(tmp_path, "app.py", "VALUE = 1\n")
    executor = SourceContextExecutor(capture_repository(tmp_path))

    result = executor.execute(action)

    assert result.ok is False
    assert result.observation["type"] == "error"
    assert result.receipt["error_code"] == "source_context_action_failed"
    assert source_context_action_error(action)


def test_source_context_enforces_a_cumulative_observation_budget(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "marker = '" + ("x" * 100) + "'\n")
    context = capture_repository(tmp_path)
    action = _action("excerpt", {"path": "app.py", "start_line": 1, "end_line": 1})
    baseline = SourceContextExecutor(context).execute(action)
    observation_chars = baseline.receipt["observation_chars"]
    assert isinstance(observation_chars, int)
    executor = SourceContextExecutor(
        context,
        max_observation_chars=(observation_chars * 2) - 1,
    )

    first = executor.execute(action)
    result = executor.execute(action)

    assert first.ok is True
    assert result.ok is False
    assert result.observation["type"] == "error"
    assert result.receipt["error_code"] == "observation_budget_exhausted"
    assert result.receipt["observation_chars"] == 0
    assert result.receipt["cumulative_observation_chars"] == observation_chars
    assert executor.observation_chars_used == observation_chars


def test_source_context_receipts_exclude_source_query_and_error_text(tmp_path: Path) -> None:
    source_canary = "repository-only-canary-71b0ea"
    _write(tmp_path, "nested/app.py", f"VALUE = '{source_canary}'\n")
    executor = SourceContextExecutor(capture_repository(tmp_path))

    search = executor.execute(_action("search", {"query": source_canary}))
    excerpt = executor.execute(
        _action(
            "excerpt",
            {"path": "nested/app.py", "start_line": 1, "end_line": 1},
        )
    )
    invalid_path = "missing-repository-only-canary.py"
    failed = executor.execute(
        _action("excerpt", {"path": invalid_path, "start_line": 1, "end_line": 1})
    )

    assert source_canary in json.dumps(search.observation)
    assert source_canary in json.dumps(excerpt.observation)
    assert source_canary not in json.dumps(search.receipt)
    assert source_canary not in json.dumps(excerpt.receipt)
    assert invalid_path in json.dumps(failed.observation)
    assert invalid_path not in json.dumps(failed.receipt)
    assert search.receipt["schema"] == SOURCE_CONTEXT_RECEIPT_SCHEMA
    for receipt in (search.receipt, excerpt.receipt, failed.receipt):
        serialized = json.dumps(receipt)
        assert '"text"' not in serialized
        assert '"query"' not in serialized
        assert '"error"' not in serialized
        assert '"file_digest"' not in serialized
        assert '"text_digest"' not in serialized
        assert '"observation_digest"' not in serialized


def test_source_context_contract_accepts_only_the_isolated_schema() -> None:
    payload = _action(
        "excerpt",
        {"path": "src/app.py", "start_line": 4, "end_line": 9},
    )

    assert source_context_action_error(payload) == ""
    assert source_context_action_schema() == source_context_action_schema()
    assert source_context_action_schema() is not source_context_action_schema()


def test_source_context_resume_budget_and_action_receipt_exclude_lookup_literals(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "app.py", "NEEDLE = 'source-only-literal'\n")
    context = capture_repository(tmp_path)
    executor = SourceContextExecutor(
        context,
        observation_chars_used=_RESUMED_OBSERVATION_CHARS,
    )
    action = _action("search", {"query": "source-only-literal", "max_matches": 2})

    result = executor.execute(action)
    durable_action = sanitize_source_context_action(action)

    assert result.receipt["cumulative_observation_chars"] > _RESUMED_OBSERVATION_CHARS
    assert durable_action == {
        "action": "source_context",
        "operation": "search",
        "args": {"query_chars": 19, "max_matches": 2},
    }
    serialized = json.dumps(durable_action)
    assert "source-only-literal" not in serialized
    assert "query_digest" not in serialized


def test_excerpt_action_receipt_excludes_model_lookup_path() -> None:
    copied_source = "SOURCE_LINE_COPIED_AS_PATH_8a21"
    action = _action(
        "excerpt",
        {"path": copied_source, "start_line": 1, "end_line": 2},
    )

    durable_action = sanitize_source_context_action(action)

    assert durable_action == {
        "action": "source_context",
        "operation": "excerpt",
        "args": {"path_chars": len(copied_source), "start_line": 1, "end_line": 2},
    }
    assert copied_source not in json.dumps(durable_action)


def test_source_context_repeat_identity_ignores_task_lifecycle() -> None:
    first = _action("search", {"query": "two  spaces", "max_matches": 2})
    second = {**first, "task_id": "another-task"}
    different = _action("search", {"query": "two spaces", "max_matches": 2})

    assert action_fingerprint(first) == action_fingerprint(second)
    assert action_fingerprint(first) != action_fingerprint(different)
