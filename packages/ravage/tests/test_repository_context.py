"""Offline retrieval regressions; fixtures contain no security assessments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from ravage import repository_context
from ravage.repository_context import (
    ContextLimitError,
    ContextLimits,
    ContextReadError,
    capture_repository,
)

if TYPE_CHECKING:
    import os

    from ravage.repository_context import RepositoryContext


_PROJECT = json.loads(
    (Path(__file__).parent / "fixtures" / "repository_context" / "project.json").read_text(
        encoding="utf-8"
    )
)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    for relative, content in _PROJECT["files"].items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


@pytest.fixture
def context(project: Path) -> RepositoryContext:
    return capture_repository(project)


def test_inventory_includes_source_configuration_and_documentation(
    context: RepositoryContext,
) -> None:
    assert {file.path for file in context.files} == set(_PROJECT["files"])
    assert context.omissions == ()


@pytest.mark.parametrize(
    ("query", "expected"),
    [(case["text"], case["locations"]) for case in _PROJECT["queries"]],
    ids=[case["name"] for case in _PROJECT["queries"]],
)
def test_retrieval_cases(
    context: RepositoryContext, query: str, expected: list[list[str | int]]
) -> None:
    result = context.search(query)
    assert [[match.path, match.line] for match in result.matches] == expected
    assert result.truncated is False
    assert result.snapshot_id == context.snapshot_id
    for match in result.matches:
        text = _PROJECT["files"][match.path]
        assert match.text == text.splitlines()[match.line - 1]
        assert match.file_digest == "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def test_excerpt_preserves_exact_lines_and_content_identity(context: RepositoryContext) -> None:
    first_line, last_line = 3, 5
    excerpt = context.excerpt("frontend/welcome.tsx", start_line=first_line, end_line=last_line)
    assert excerpt.text == (
        "export function Welcome({ name }: { name: string }) {\n"
        "  return <h1>{formatGreeting(name)}</h1>;\n}\n"
    )
    assert excerpt.start_line == first_line
    assert excerpt.end_line == last_line
    assert excerpt.snapshot_id == context.snapshot_id
    assert excerpt.file_digest == context.search("formatGreeting").matches[1].file_digest


def test_match_limit_explicitly_marks_additional_results(context: RepositoryContext) -> None:
    limited = context.search("greet_user", max_matches=1)
    assert len(limited.matches) == 1
    assert limited.truncated is True
    expected_count = 5
    exact = context.search("greet_user", max_matches=expected_count)
    assert len(exact.matches) == expected_count
    assert exact.truncated is False


def test_existing_snapshot_stays_consistent_after_source_changes(
    context: RepositoryContext, project: Path
) -> None:
    original = context.excerpt("backend/greetings.py", start_line=1, end_line=2)
    (project / "backend/greetings.py").write_text("def changed():\n    return 'changed'\n")
    assert context.excerpt("backend/greetings.py", start_line=1, end_line=2) == original
    refreshed = capture_repository(project)
    assert refreshed.snapshot_id != context.snapshot_id
    assert refreshed.search("def greet_user").matches == ()


def test_snapshot_identity_ignores_root_location_and_creation_order(
    project: Path, tmp_path: Path
) -> None:
    second = tmp_path.parent / f"{tmp_path.name}-copy"
    second.mkdir()
    for relative, content in reversed(list(_PROJECT["files"].items())):
        path = second / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    assert capture_repository(project).snapshot_id == capture_repository(second).snapshot_id


def test_exclusions_are_recorded_without_reading_their_content(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("export const greeting = 'hello';\n")
    for relative in (".git/config", "node_modules/package/index.js", ".env", "private.pem"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("excluded_fixture_marker\n")
    (tmp_path / "image.bin").write_bytes(b"binary\x00fixture")
    (tmp_path / "legacy.txt").write_bytes(b"\xff")
    (tmp_path / "linked.ts").symlink_to(tmp_path / "app.ts")

    result = capture_repository(tmp_path)
    assert [file.path for file in result.files] == ["app.ts"]
    assert {(item.path, item.reason) for item in result.omissions} == {
        (".git", "excluded_directory"),
        ("node_modules", "excluded_directory"),
        (".env", "sensitive_file"),
        ("private.pem", "sensitive_file"),
        ("image.bin", "binary"),
        ("legacy.txt", "non_utf8"),
        ("linked.ts", "symlink"),
    }
    assert result.search("excluded_fixture_marker").matches == ()


def test_project_dotfiles_and_unfamiliar_text_extensions_remain_available(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "checks.yaml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: example\n")
    (tmp_path / ".gitignore").write_text("dist/\n")
    (tmp_path / "component.custom").write_text("greeting component\n")
    assert {file.path for file in capture_repository(tmp_path).files} == {
        ".github/workflows/checks.yaml",
        ".gitignore",
        "component.custom",
    }


def test_oversized_files_are_explicit_omissions(tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_text("a" * 20)
    result = capture_repository(tmp_path, limits=ContextLimits(max_file_bytes=10))
    assert result.files == ()
    assert [(item.path, item.reason) for item in result.omissions] == [
        ("large.txt", "file_too_large")
    ]


@pytest.mark.parametrize("limit", ["max_files", "max_entries", "max_total_bytes", "max_depth"])
def test_repository_limits_fail_without_returning_a_partial_context(
    project: Path, limit: str
) -> None:
    with pytest.raises(ContextLimitError):
        capture_repository(project, limits=ContextLimits(**{limit: 1}))


@pytest.mark.parametrize("query", ["", " ", "greet\nuser"])
def test_search_rejects_empty_or_multiline_queries(context: RepositoryContext, query: str) -> None:
    with pytest.raises(ValueError, match="query must be"):
        context.search(query)


@pytest.mark.parametrize(("start", "end"), [(0, 2), (3, 2), (1, 99)])
def test_invalid_excerpt_ranges_are_rejected(
    context: RepositoryContext, start: int, end: int
) -> None:
    with pytest.raises(ValueError, match=r"positive integer|outside the captured file"):
        context.excerpt("backend/greetings.py", start_line=start, end_line=end)


def test_unknown_excerpt_paths_are_not_read_from_disk(context: RepositoryContext) -> None:
    with pytest.raises(KeyError):
        context.excerpt("../unavailable.py", start_line=1, end_line=1)


def test_unicode_and_crlf_preserve_exact_source_references(
    tmp_path: Path,
) -> None:
    content = "label = 'café\u0085unchanged'\r\ngreeting = '你好'\r\nlast_line"
    (tmp_path / "挨拶.py").write_bytes(content.encode("utf-8"))
    context = capture_repository(tmp_path)
    result = context.search("你好")
    expected_line, expected_column = 2, 13
    assert result.matches[0].path == "挨拶.py"
    assert result.matches[0].line == expected_line
    assert result.matches[0].column == expected_column
    assert context.excerpt("挨拶.py", start_line=1, end_line=3).text == content


def test_queries_are_literal_and_case_sensitive(tmp_path: Path) -> None:
    (tmp_path / "example.txt").write_text("config[name]\nconfigN\nCONFIG[name]\n")
    result = capture_repository(tmp_path).search("config[name]")
    assert [(match.path, match.line) for match in result.matches] == [("example.txt", 1)]


def test_long_line_search_keeps_the_match_visible_and_declares_truncation(tmp_path: Path) -> None:
    prefix = "a" * 5_000
    content = prefix + "needle" + "z" * 5_000
    (tmp_path / "long.txt").write_text(content)
    match = capture_repository(tmp_path).search("needle").matches[0]
    assert match.column == len(prefix) + 1
    assert match.text_truncated is True
    assert "needle" in match.text
    assert content[match.text_start_column - 1 :].startswith(match.text)


@pytest.mark.parametrize(
    ("content", "end", "reason"),
    [
        ("line\n" * 101, 101, "100 lines"),
        ("a" * 20_001, 1, "20000 characters"),
    ],
)
def test_excerpts_do_not_silently_truncate_large_requests(
    tmp_path: Path, content: str, end: int, reason: str
) -> None:
    (tmp_path / "long.txt").write_text(content)
    with pytest.raises(ContextLimitError, match=reason):
        capture_repository(tmp_path).excerpt("long.txt", start_line=1, end_line=end)


def test_binary_input_still_consumes_the_read_budget(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"\x00" * 8)
    (tmp_path / "b.txt").write_text("12345")
    with pytest.raises(ContextLimitError, match="total byte limit"):
        capture_repository(tmp_path, limits=ContextLimits(max_total_bytes=10))


def test_file_replacement_during_capture_rejects_mixed_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "app.txt"
    path.write_text("original\n")
    read_file = repository_context._read_file  # noqa: SLF001 - inject a deterministic file replacement.

    def replace_before_read(parent: int, name: str, expected: os.stat_result, limit: int) -> bytes:
        replacement = tmp_path / "replacement.txt"
        replacement.write_text("modified\n")
        replacement.replace(path)
        return read_file(parent, name, expected, limit)

    monkeypatch.setattr(repository_context, "_read_file", replace_before_read)
    with pytest.raises(ContextReadError, match="changed while opening"):
        capture_repository(tmp_path)


def test_nonexistent_file_and_symlink_roots_are_rejected(tmp_path: Path) -> None:
    regular = tmp_path / "file"
    regular.write_text("fixture")
    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path, target_is_directory=True)
    for path in (tmp_path / "missing", regular, linked):
        with pytest.raises(ContextReadError, match="non-symlink directory"):
            capture_repository(path)


@pytest.mark.parametrize("value", [0, -1, False])
def test_invalid_limits_are_rejected(context: RepositoryContext, value: int) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        ContextLimits(max_files=value)
    with pytest.raises(ValueError, match="positive integer"):
        context.search("greet_user", max_matches=value)


def test_query_and_result_bounds_cannot_be_bypassed(context: RepositoryContext) -> None:
    with pytest.raises(ValueError, match="at most 256"):
        context.search("x" * 257)
    with pytest.raises(ContextLimitError, match="max_matches exceeds"):
        context.search("greet_user", max_matches=1_001)


def test_empty_files_remain_in_inventory_without_invented_lines(tmp_path: Path) -> None:
    (tmp_path / "empty.txt").touch()
    context = capture_repository(tmp_path)
    assert [file.path for file in context.files] == ["empty.txt"]
    assert context.search("anything").matches == ()
    with pytest.raises(ValueError, match="outside the captured file"):
        context.excerpt("empty.txt", start_line=1, end_line=1)
