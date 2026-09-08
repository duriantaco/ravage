"""
Read-only, offline text context for a supplied repository.

This module does not execute project code, call a model, or classify findings.
Search is literal text lookup; results do not establish semantic relationships.
Captured file contents remain immutable even if the working tree later changes.
"""

# Local validation errors give callers precise, bounded diagnostics.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from pathspec import GitIgnoreSpec
from pathspec.patterns.gitignore import GitIgnorePatternError

if TYPE_CHECKING:
    from pathspec.patterns.gitignore.spec import GitIgnoreSpecPattern

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".agents",
        ".codex",
        ".ssh",
        ".aws",
        ".azure",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".next",
        "dist",
        "build",
        "target",
    }
)
_SENSITIVE_NAMES = frozenset({".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials"})
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_MAX_QUERY_CHARS = 256
_MAX_MATCHES = 1_000
_MAX_MATCH_TEXT_CHARS = 1_000
_MATCH_LEADING_CONTEXT = 250
_MAX_EXCERPT_LINES = 100
_MAX_EXCERPT_CHARS = 20_000


class ContextLimitError(ValueError):
    """The requested capture or excerpt cannot fit its declared bounds."""


class ContextReadError(OSError):
    """A repository cannot be read consistently within the supplied root."""


class ContextIgnorePolicy(StrEnum):
    """Select whether project-local Git ignore files constrain capture."""

    GITIGNORE = "gitignore"
    NONE = "none"


@dataclass(frozen=True)
class ContextLimits:
    max_files: int = 10_000
    max_file_bytes: int = 512 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_entries: int = 100_000
    max_depth: int = 32

    def __post_init__(self) -> None:
        for name, value in (
            ("max_files", self.max_files),
            ("max_file_bytes", self.max_file_bytes),
            ("max_total_bytes", self.max_total_bytes),
            ("max_entries", self.max_entries),
            ("max_depth", self.max_depth),
        ):
            _require_positive_int(value, name)


@dataclass(frozen=True)
class ContextFile:
    path: str
    digest: str
    size_bytes: int
    text: str = field(repr=False)


@dataclass(frozen=True)
class ContextOmission:
    path: str
    reason: str


@dataclass(frozen=True)
class ContextMatch:
    path: str
    line: int
    column: int
    text: str
    text_start_column: int
    text_truncated: bool
    file_digest: str


@dataclass(frozen=True)
class ContextSearch:
    snapshot_id: str
    matches: tuple[ContextMatch, ...]
    truncated: bool


@dataclass(frozen=True)
class ContextExcerpt:
    path: str
    start_line: int
    end_line: int
    text: str
    file_digest: str
    snapshot_id: str


@dataclass(frozen=True)
class RepositoryContext:
    files: tuple[ContextFile, ...]
    omissions: tuple[ContextOmission, ...]
    snapshot_id: str

    def search(self, query: str, *, max_matches: int = 50) -> ContextSearch:
        """Find matching lines using case-sensitive literal text, in path/line order."""
        if (
            not isinstance(query, str)
            or not query.strip()
            or len(query) > _MAX_QUERY_CHARS
            or any(character in query for character in "\r\n\x00")
        ):
            raise ValueError("query must be nonempty, single-line text of at most 256 characters")
        _require_positive_int(max_matches, "max_matches")
        if max_matches > _MAX_MATCHES:
            raise ContextLimitError("max_matches exceeds 1000")
        matches: list[ContextMatch] = []
        for source in self.files:
            for number, raw in enumerate(_source_lines(source.text), start=1):
                line = raw.removesuffix("\n").removesuffix("\r")
                column = line.find(query)
                if column < 0:
                    continue
                if len(matches) == max_matches:
                    return ContextSearch(self.snapshot_id, tuple(matches), truncated=True)
                matches.append(_match(source, number, line, column))
        return ContextSearch(self.snapshot_id, tuple(matches), truncated=False)

    def excerpt(self, path: str, *, start_line: int, end_line: int) -> ContextExcerpt:
        """Return exact captured lines; this method performs no filesystem access."""
        _require_positive_int(start_line, "start_line")
        _require_positive_int(end_line, "end_line")
        source = next((source for source in self.files if source.path == path), None)
        if source is None:
            raise KeyError(path)
        lines = _source_lines(source.text)
        if end_line < start_line or end_line > len(lines):
            raise ValueError("excerpt range is outside the captured file")
        if end_line - start_line + 1 > _MAX_EXCERPT_LINES:
            raise ContextLimitError("excerpt exceeds 100 lines")
        text = "".join(lines[start_line - 1 : end_line])
        if len(text) > _MAX_EXCERPT_CHARS:
            raise ContextLimitError("excerpt exceeds 20000 characters")
        return ContextExcerpt(path, start_line, end_line, text, source.digest, self.snapshot_id)


@dataclass
class _Capture:
    limits: ContextLimits
    ignore_policy: ContextIgnorePolicy
    files: list[ContextFile] = field(default_factory=list)
    omissions: list[ContextOmission] = field(default_factory=list)
    entries_seen: int = 0
    files_seen: int = 0
    bytes_read: int = 0


@dataclass(frozen=True)
class _IgnoreScope:
    prefix: str
    spec: GitIgnoreSpec


@dataclass(frozen=True)
class _WalkPosition:
    depth: int
    ignore_scopes: tuple[_IgnoreScope, ...]


def capture_repository(
    root: Path,
    *,
    limits: ContextLimits | None = None,
    ignore_policy: ContextIgnorePolicy = ContextIgnorePolicy.GITIGNORE,
) -> RepositoryContext:
    """
    Capture bounded UTF-8 text files from a local directory on POSIX.

    Directory descriptors and no-follow opens keep traversal inside the opened
    tree. Files are checked for changes while read. This freezes captured text;
    it does not claim an atomic Git revision or a secret-free export.
    """
    if not isinstance(ignore_policy, ContextIgnorePolicy):
        raise TypeError("ignore_policy must be a ContextIgnorePolicy")
    state = _Capture(limits or ContextLimits(), ignore_policy)
    try:
        descriptor = os.open(Path(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ContextReadError("cannot open repository root as a non-symlink directory") from exc
    try:
        _walk(descriptor, "", position=_WalkPosition(1, ()), state=state)
    except ContextReadError:
        raise
    except OSError as exc:
        raise ContextReadError("repository could not be read consistently") from exc
    finally:
        os.close(descriptor)
    files = tuple(sorted(state.files, key=lambda source: source.path))
    omissions = tuple(sorted(state.omissions, key=lambda omission: omission.path))
    identity = json.dumps(
        {
            "format": "ravage.repository-context.v1",
            "files": [(source.path, source.digest) for source in files],
            "omissions": [(omission.path, omission.reason) for omission in omissions],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return RepositoryContext(files, omissions, _digest(identity))


def _walk(
    descriptor: int,
    prefix: str,
    *,
    position: _WalkPosition,
    state: _Capture,
) -> None:
    if position.depth > state.limits.max_depth:
        raise ContextLimitError("repository exceeds directory depth limit (root counts as one)")
    names = _read_directory_names(descriptor, state=state)
    local_scopes = _load_local_ignore_scope(
        descriptor,
        prefix,
        names,
        inherited=position.ignore_scopes,
        state=state,
    )
    local_position = _WalkPosition(position.depth, local_scopes)
    for name in sorted(names):
        _capture_entry(descriptor, name, prefix, position=local_position, state=state)


def _read_directory_names(descriptor: int, *, state: _Capture) -> list[str]:
    names: list[str] = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            state.entries_seen += 1
            if state.entries_seen > state.limits.max_entries:
                raise ContextLimitError("repository exceeds directory entry limit")
            names.append(entry.name)
    return names


def _load_local_ignore_scope(
    descriptor: int,
    prefix: str,
    names: list[str],
    *,
    inherited: tuple[_IgnoreScope, ...],
    state: _Capture,
) -> tuple[_IgnoreScope, ...]:
    ignore_name = ".gitignore"
    if state.ignore_policy is not ContextIgnorePolicy.GITIGNORE or ignore_name not in names:
        return inherited
    metadata = os.stat(ignore_name, dir_fd=descriptor, follow_symlinks=False)
    return (
        *inherited,
        _capture_gitignore(descriptor, ignore_name, prefix, metadata, state=state),
    )


def _capture_entry(
    descriptor: int,
    name: str,
    prefix: str,
    *,
    position: _WalkPosition,
    state: _Capture,
) -> None:
    relative = f"{prefix}/{name}" if prefix else name
    if not all(character.isprintable() for character in name):
        state.omissions.append(ContextOmission(relative, "unsupported_path"))
        return
    if state.ignore_policy is ContextIgnorePolicy.GITIGNORE and name == ".gitignore":
        return
    metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    reason = _omission_reason(name, metadata, state.limits)
    if reason is None and _is_gitignored(relative, metadata, position.ignore_scopes):
        reason = "gitignored_directory" if stat.S_ISDIR(metadata.st_mode) else "gitignored_file"
    if reason is not None:
        state.omissions.append(ContextOmission(relative, reason))
        return
    if stat.S_ISDIR(metadata.st_mode):
        _walk_child(descriptor, relative, metadata, position=position, state=state)
        return
    _capture_file(descriptor, name, relative, metadata, state=state)


def _walk_child(
    parent: int,
    relative: str,
    expected: os.stat_result,
    *,
    position: _WalkPosition,
    state: _Capture,
) -> None:
    name = relative.rsplit("/", 1)[-1]
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        opened = os.fstat(child)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise ContextReadError("repository directory changed while opening it")
        _walk(
            child,
            relative,
            position=_WalkPosition(position.depth + 1, position.ignore_scopes),
            state=state,
        )
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
            raise ContextReadError("repository directory changed during traversal")
    finally:
        os.close(child)


def _omission_reason(name: str, metadata: os.stat_result, limits: ContextLimits) -> str | None:
    lowered = name.casefold()
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    if stat.S_ISDIR(metadata.st_mode):
        return "excluded_directory" if lowered in _EXCLUDED_DIRECTORIES else None
    if not stat.S_ISREG(metadata.st_mode):
        return "non_regular_file"
    if (
        lowered in _SENSITIVE_NAMES
        or lowered.startswith((".env.", "id_rsa", "id_ed25519", "id_ecdsa"))
        or lowered.endswith(_SENSITIVE_SUFFIXES)
    ):
        return "sensitive_file"
    return "file_too_large" if metadata.st_size > limits.max_file_bytes else None


def _capture_gitignore(
    descriptor: int,
    name: str,
    prefix: str,
    expected: os.stat_result,
    *,
    state: _Capture,
) -> _IgnoreScope:
    relative = f"{prefix}/{name}" if prefix else name
    if not stat.S_ISREG(expected.st_mode):
        raise ContextReadError(f"{relative} is not a regular ignore file")
    if expected.st_size > state.limits.max_file_bytes:
        raise ContextLimitError(f"{relative} exceeds the per-file byte limit")
    data = _read_captured_file(descriptor, name, expected, state=state)
    if b"\x00" in data:
        raise ContextReadError(f"{relative} contains invalid NUL bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContextReadError(f"{relative} is not valid UTF-8") from exc
    try:
        spec = _compile_gitignore(text)
    except (TypeError, ValueError) as exc:
        raise ContextReadError(f"{relative} contains an invalid Git ignore pattern") from exc
    state.files.append(ContextFile(relative, _digest(data), len(data), text))
    return _IgnoreScope(prefix, spec)


def _compile_gitignore(text: str) -> GitIgnoreSpec:
    patterns: list[GitIgnoreSpecPattern] = []
    for line in text.splitlines():
        try:
            patterns.extend(
                GitIgnoreSpec.from_lines([_normalize_recursive_ignore_pattern(line)]).patterns
            )
        except GitIgnorePatternError:
            # Git treats malformed individual patterns as no-ops rather than
            # rejecting the entire ignore file.
            continue
    return GitIgnoreSpec(patterns)


def _normalize_recursive_ignore_pattern(pattern: str) -> str:
    """Preserve Git's descendant-only meaning for trailing recursive wildcards."""
    normalized = pattern if pattern.endswith("\\ ") else pattern.rstrip()
    if normalized.endswith("/**/"):
        return normalized[:-1] + "/*/"
    if normalized.endswith("/**"):
        return normalized + "/*"
    return normalized


def _is_gitignored(
    relative: str,
    metadata: os.stat_result,
    scopes: tuple[_IgnoreScope, ...],
) -> bool:
    ignored: bool | None = None
    for scope in scopes:
        if scope.prefix:
            scope_prefix = scope.prefix + "/"
            if not relative.startswith(scope_prefix):
                continue
            candidate = relative[len(scope_prefix) :]
        else:
            candidate = relative
        result = _entry_ignore_result(
            candidate,
            is_directory=stat.S_ISDIR(metadata.st_mode),
            spec=scope.spec,
        )
        if result is not None:
            ignored = result
    return ignored is True


def _entry_ignore_result(
    candidate: str,
    *,
    is_directory: bool,
    spec: GitIgnoreSpec,
) -> bool | None:
    """Match this entry; traversal already accounted for every visible parent."""
    path = candidate + "/" if is_directory else candidate
    ignored: bool | None = None
    for pattern in spec.patterns:
        if pattern.include is None:
            continue
        if not _pattern_matches_current_entry(
            pattern,
            path=path,
            basename=candidate.rsplit("/", 1)[-1],
            is_directory=is_directory,
        ):
            continue
        ignored = pattern.include
    return ignored


def _pattern_matches_current_entry(
    pattern: GitIgnoreSpecPattern,
    *,
    path: str,
    basename: str,
    is_directory: bool,
) -> bool:
    match = pattern.match_file(path)
    if match is not None:
        directory_mark = match.match.groupdict().get("ps_d")
        if not directory_mark:
            return True
        if is_directory and match.match.end("ps_d") == len(path):
            return True

    raw_pattern = pattern.pattern
    if not (
        is_directory
        and isinstance(raw_pattern, str)
        and _needs_basename_directory_retry(raw_pattern)
    ):
        # Traversal already accounted for any directory-ancestor match.
        return False
    basename_path = basename + "/"
    basename_match = pattern.match_file(basename_path)
    return bool(
        basename_match is not None
        and basename_match.match.groupdict().get("ps_d")
        and basename_match.match.end("ps_d") == len(basename_path)
    )


def _needs_basename_directory_retry(pattern: str) -> bool:
    normalized = pattern.removeprefix("!")
    return normalized.endswith("/") and (
        "/" not in normalized[:-1]
        or normalized.startswith(("**/", "/**/"))
    )


def _capture_file(
    descriptor: int,
    name: str,
    relative: str,
    expected: os.stat_result,
    *,
    state: _Capture,
) -> None:
    data = _read_captured_file(descriptor, name, expected, state=state)
    if b"\x00" in data:
        state.omissions.append(ContextOmission(relative, "binary"))
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        state.omissions.append(ContextOmission(relative, "non_utf8"))
        return
    state.files.append(ContextFile(relative, _digest(data), len(data), text))


def _read_captured_file(
    descriptor: int,
    name: str,
    expected: os.stat_result,
    *,
    state: _Capture,
) -> bytes:
    state.files_seen += 1
    if state.files_seen > state.limits.max_files:
        raise ContextLimitError("repository exceeds file limit")
    if state.bytes_read + expected.st_size > state.limits.max_total_bytes:
        raise ContextLimitError("repository exceeds total byte limit")
    data = _read_file(descriptor, name, expected, state.limits.max_file_bytes)
    state.bytes_read += len(data)
    return data


def _read_file(parent: int, name: str, expected: os.stat_result, limit: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or _signature(opened) != _signature(expected):
            raise ContextReadError("repository file changed while opening it")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _signature(opened) != _signature(after)
            or _signature(after) != _signature(current)
            or len(data) != expected.st_size
        ):
            raise ContextReadError("repository file changed while reading it")
    return data


def _match(source: ContextFile, number: int, line: str, column: int) -> ContextMatch:
    start = max(0, column - _MATCH_LEADING_CONTEXT) if len(line) > _MAX_MATCH_TEXT_CHARS else 0
    end = min(len(line), start + _MAX_MATCH_TEXT_CHARS)
    return ContextMatch(
        source.path,
        number,
        column + 1,
        line[start:end],
        start + 1,
        start > 0 or end < len(line),
        source.digest,
    )


def _source_lines(text: str) -> tuple[str, ...]:
    """Split on LF, preserving CRLF and final-newline bytes in excerpts."""
    parts = text.split("\n")
    return (*[part + "\n" for part in parts[:-1]], *([parts[-1]] if parts[-1] else []))


def _signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_positive_int(value: int, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
