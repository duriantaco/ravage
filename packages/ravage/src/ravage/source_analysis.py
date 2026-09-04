# ruff: noqa: C901, EM101, EM102, PLR0911, PLR0912, PLR0913, PLR2004, SIM102, TRY003
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import stat
import tokenize
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

SOURCE_MAP_SCHEMA = "ravage.source-map.v1"
SOURCE_ANALYZER_CONTRACT = "ravage.python-web-direct-flows.v2"
DEFAULT_MAX_FILES = 2_000
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 512 * 1024
DEFAULT_MAX_DIRECTORIES = 4_096
DEFAULT_MAX_DIRECTORY_ENTRIES = 100_000
MAX_AST_NODES_PER_FILE = 200_000
MAX_SOURCE_CANDIDATES = 4_096

_EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        ".cache",
        ".eggs",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "__pypackages__",
        "build",
        "coverage",
        "dist",
        "env",
        "htmlcov",
        "node_modules",
        "out",
        "playwright-report",
        "site",
        "site-packages",
        "target",
        "test-results",
        "vendor",
        "venv",
    }
)

_HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_ROUTE_METHODS = {
    "get": "GET",
    "head": "HEAD",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "options": "OPTIONS",
}
_INPUT_LOCATIONS = {
    "args": "query",
    "query_params": "query",
    "form": "form",
    "json": "body",
    "headers": "header",
    "cookies": "cookie",
    "values": "unknown",
}
_FASTAPI_MARKERS = {
    "body": "body",
    "cookie": "cookie",
    "form": "form",
    "header": "header",
    "path": "path",
    "query": "query",
}
_FASTAPI_NON_INPUT_MARKERS = frozenset({"depends", "security"})
_FASTAPI_TRANSPORT_ANNOTATIONS = frozenset({"request", "response", "websocket"})
_FASTAPI_SCALAR_KINDS = {
    "bool": "boolean",
    "float": "number",
    "int": "integer",
    "str": "string",
    "uuid": "uuid",
}
_LIVE_VALIDATION_AUTOMATIC = "automatic_get_query"
_LIVE_VALIDATION_HINT_ONLY = "hint_only"
_SQL_EXECUTION_METHODS = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "fetch",
        "fetchrow",
        "fetchval",
        "from_statement",
        "prepare",
        "raw",
    }
)
_SQL_EXECUTION_QUALIFIERS = frozenset(
    {
        "aiomysql",
        "asyncpg",
        "asyncsession",
        "async_session",
        "con",
        "conn",
        "connect",
        "connection",
        "cur",
        "cursor",
        "database",
        "db",
        "engine",
        "mariadb",
        "mysql",
        "oracledb",
        "pg",
        "pool",
        "postgres",
        "psycopg",
        "psycopg2",
        "pymssql",
        "pymysql",
        "pyodbc",
        "sa",
        "session",
        "sql",
        "sqlalchemy",
        "sqlite",
        "sqlite3",
    }
)
_SQL_RAW_QUALIFIERS = frozenset({"manager", "objects", "queryset"})
_SQL_STATEMENT_QUALIFIERS = frozenset({"query", "select", "statement"})
_SAFE_INPUT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:\[\]-]{0,127}$")
_SAFE_FILE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.@+\-\[\]()$]+$")
_FLASK_ROUTE_PARAMETER_RE = re.compile(r"<(?:(?:[^:<>]+):)?([A-Za-z_][A-Za-z0-9_]*)>")
_SAFE_ROUTE_PARAMETER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class SourceAnalysisError(ValueError):
    """Base error for bounded local source analysis."""


class SourceRootError(SourceAnalysisError):
    """Raised when the requested source root is missing or unsafe."""


class SourceLimitError(SourceAnalysisError):
    """Raised instead of silently returning a partial source map."""


class SourceChangedError(SourceAnalysisError):
    """Raised when source metadata changes during or between scans."""


@dataclass(frozen=True, slots=True, order=True)
class SourceQueryField:
    name: str
    value_kind: str
    required: bool

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value_kind": self.value_kind,
            "required": self.required,
        }


@dataclass(frozen=True, slots=True, order=True)
class SourceCandidate:
    candidate_id: str
    family: str
    method: str
    route: str
    input_name: str
    input_location: str
    framework: str
    route_binding: str
    relative_file: str
    line: int
    sink_kind: str
    reason: str
    live_validation: str = _LIVE_VALIDATION_HINT_ONLY
    query_fields: tuple[SourceQueryField, ...] = ()
    status: str = "hypothesis"

    def to_json(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "family": self.family,
            "method": self.method,
            "route": self.route,
            "input_name": self.input_name,
            "input_location": self.input_location,
            "framework": self.framework,
            "route_binding": self.route_binding,
            "relative_file": self.relative_file,
            "line": self.line,
            "sink_kind": self.sink_kind,
            "reason": self.reason,
            "live_validation": self.live_validation,
            "query_fields": [field.to_json() for field in self.query_fields],
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class SourceMap:
    source_digest: str
    candidate_digest: str
    files_scanned: int
    bytes_scanned: int
    files_parsed: int
    parse_failures: int
    routes_discovered: int
    route_patterns_skipped: int
    flow_patterns_skipped: int
    candidates: tuple[SourceCandidate, ...]
    symlinks_skipped: int
    directories_scanned: int
    directory_entries_scanned: int
    excluded_directories: int

    def to_json(self) -> dict[str, object]:
        return {
            "schema": SOURCE_MAP_SCHEMA,
            "analyzer_contract": SOURCE_ANALYZER_CONTRACT,
            "source_digest": self.source_digest,
            "candidate_digest": self.candidate_digest,
            "counts": {
                "files_scanned": self.files_scanned,
                "bytes_scanned": self.bytes_scanned,
                "files_parsed": self.files_parsed,
                "parse_failures": self.parse_failures,
                "routes_discovered": self.routes_discovered,
                "route_patterns_skipped": self.route_patterns_skipped,
                "flow_patterns_skipped": self.flow_patterns_skipped,
                "candidates_found": len(self.candidates),
                "symlinks_skipped": self.symlinks_skipped,
                "directories_scanned": self.directories_scanned,
                "directory_entries_scanned": self.directory_entries_scanned,
                "excluded_directories": self.excluded_directories,
            },
            "candidates": [candidate.to_json() for candidate in self.candidates],
        }


@dataclass(frozen=True, slots=True, order=True)
class _InputRef:
    name: str
    location: str


@dataclass(frozen=True, slots=True)
class _RouteHandler:
    framework: str
    method: str
    route: str
    function: ast.FunctionDef | ast.AsyncFunctionDef
    bindings: _AnalysisBindings
    route_binding: str


@dataclass(frozen=True, slots=True)
class _FrameworkOwner:
    framework: str
    prefix: str = ""
    kind: str = ""
    route_binding: str = "relative"


@dataclass(frozen=True, slots=True)
class _RouteRegistration:
    parent_name: str
    child_name: str
    prefix: str
    prefix_supplied: bool


@dataclass(frozen=True, slots=True, order=True)
class _RequestField:
    name: str
    location: str
    value_kind: str
    required: bool


@dataclass(frozen=True, slots=True)
class _HandlerInputs:
    taints: Mapping[str, frozenset[_InputRef]]
    request_fields: tuple[_RequestField, ...]
    request_names: frozenset[str]
    live_shape_complete: bool
    patterns_skipped: int


@dataclass(frozen=True, slots=True)
class _FastAPIParameter:
    input_ref: _InputRef | None
    request_field: _RequestField | None
    request_name: bool
    live_shape_supported: bool


@dataclass(frozen=True, slots=True)
class _AnalysisBindings:
    framework_owners: Mapping[str, _FrameworkOwner]
    unresolved_framework_owners: frozenset[str]
    request_names: frozenset[str]
    fastapi_markers: Mapping[str, str]
    fastapi_non_input_markers: frozenset[str]
    fastapi_transport_annotations: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    relative_file: str
    data: bytes


@dataclass(slots=True)
class _SourceWalk:
    files: list[Path]
    symlinks_skipped: int = 0
    directories_scanned: int = 1
    directory_entries_scanned: int = 0
    excluded_directories: int = 0


def analyze_source_root(
    root: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_directories: int = DEFAULT_MAX_DIRECTORIES,
    max_directory_entries: int = DEFAULT_MAX_DIRECTORY_ENTRIES,
) -> SourceMap:
    """Return a deterministic, value-free map of direct Python web-handler flows."""
    limits = _validated_limits(
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        max_file_bytes=max_file_bytes,
        max_directories=max_directories,
        max_directory_entries=max_directory_entries,
    )
    source_root = _validated_root(root)
    walk = _walk_python_files(
        source_root,
        max_files=limits[0],
        max_directories=limits[3],
        max_directory_entries=limits[4],
    )
    snapshots = _read_snapshots(
        source_root,
        walk.files,
        max_total_bytes=limits[1],
        max_file_bytes=limits[2],
    )

    candidates: list[SourceCandidate] = []
    files_parsed = 0
    parse_failures = 0
    routes_discovered = 0
    route_patterns_skipped = 0
    flow_patterns_skipped = 0
    for snapshot in snapshots:
        tree = _parse_python(snapshot.data, filename=snapshot.relative_file)
        if tree is None:
            parse_failures += 1
            continue
        node_count = sum(1 for _node in ast.walk(tree))
        if node_count > MAX_AST_NODES_PER_FILE:
            raise SourceLimitError(
                f"Python AST exceeds {MAX_AST_NODES_PER_FILE} nodes: {snapshot.relative_file}"
            )
        files_parsed += 1
        handlers, skipped_patterns = _route_handlers(tree)
        routes_discovered += len(handlers)
        route_patterns_skipped += skipped_patterns
        for handler in handlers:
            handler_candidates, handler_skipped = _handler_candidates(
                handler,
                relative_file=snapshot.relative_file,
            )
            candidates.extend(handler_candidates)
            flow_patterns_skipped += handler_skipped
            if len(candidates) > MAX_SOURCE_CANDIDATES:
                raise SourceLimitError(f"source candidate count exceeds {MAX_SOURCE_CANDIDATES}")

    unique = {candidate.candidate_id: candidate for candidate in candidates}
    ordered = tuple(sorted(unique.values(), key=_candidate_sort_key))
    return SourceMap(
        source_digest=_source_digest(snapshots),
        candidate_digest=_candidate_digest(ordered),
        files_scanned=len(snapshots),
        bytes_scanned=sum(len(snapshot.data) for snapshot in snapshots),
        files_parsed=files_parsed,
        parse_failures=parse_failures,
        routes_discovered=routes_discovered,
        route_patterns_skipped=route_patterns_skipped,
        flow_patterns_skipped=flow_patterns_skipped,
        candidates=ordered,
        symlinks_skipped=walk.symlinks_skipped,
        directories_scanned=walk.directories_scanned,
        directory_entries_scanned=walk.directory_entries_scanned,
        excluded_directories=walk.excluded_directories,
    )


def _validated_limits(
    *,
    max_files: int,
    max_total_bytes: int,
    max_file_bytes: int,
    max_directories: int,
    max_directory_entries: int,
) -> tuple[int, int, int, int, int]:
    limits = (
        max_files,
        max_total_bytes,
        max_file_bytes,
        max_directories,
        max_directory_entries,
    )
    if any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in limits):
        raise SourceLimitError("source limits must be positive integers")
    if max_file_bytes > max_total_bytes:
        raise SourceLimitError("per-file source limit cannot exceed the total-byte limit")
    return limits


def _validated_root(root: Path) -> Path:
    path = Path(root)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceRootError(f"cannot access source root {path}: {exc}") from None
    if stat.S_ISLNK(metadata.st_mode):
        raise SourceRootError("source root must not be a symbolic link")
    if not stat.S_ISDIR(metadata.st_mode):
        raise SourceRootError(f"source root is not a directory: {path}")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SourceRootError(f"cannot resolve source root {path}: {exc}") from None
    return resolved


def _walk_python_files(
    root: Path,
    *,
    max_files: int,
    max_directories: int,
    max_directory_entries: int,
) -> _SourceWalk:
    result = _SourceWalk(files=[])
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries: list[os.DirEntry[str]] = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    result.directory_entries_scanned += 1
                    if result.directory_entries_scanned > max_directory_entries:
                        raise SourceLimitError(
                            f"source directory entry count exceeds {max_directory_entries}"
                        )
                    entries.append(entry)
            entries.sort(key=lambda item: item.name)
        except OSError as exc:
            raise SourceRootError(f"cannot read source directory {directory}: {exc}") from None
        for entry in entries:
            try:
                if entry.is_symlink():
                    result.symlinks_skipped += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if _directory_is_excluded(entry.name):
                        result.excluded_directories += 1
                        continue
                    result.directories_scanned += 1
                    if result.directories_scanned > max_directories:
                        raise SourceLimitError(f"source directory count exceeds {max_directories}")
                    pending.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".py"):
                    continue
            except OSError as exc:
                raise SourceChangedError(f"source entry changed during scan: {entry.name}") from exc
            result.files.append(Path(entry.path))
            if len(result.files) > max_files:
                raise SourceLimitError(f"Python source file count exceeds {max_files}")
    result.files.sort(key=lambda path: path.relative_to(root).as_posix())
    return result


def _directory_is_excluded(name: str) -> bool:
    normalized = name.casefold()
    return (
        normalized in _EXCLUDED_DIRECTORY_NAMES
        or normalized.startswith(".")
        or normalized.endswith((".egg-info", ".temp", ".tmp"))
    )


def _read_snapshots(
    root: Path,
    files: Sequence[Path],
    *,
    max_total_bytes: int,
    max_file_bytes: int,
) -> tuple[_FileSnapshot, ...]:
    snapshots: list[_FileSnapshot] = []
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        before = _lstat_regular_file(path, relative=relative)
        if before.st_size > max_file_bytes:
            raise SourceLimitError(f"Python source file exceeds {max_file_bytes} bytes: {relative}")
        data, opened, after = _read_file_no_follow(path, limit=max_file_bytes)
        if not _same_file_snapshot(before, opened, after) or len(data) != before.st_size:
            raise SourceChangedError(f"source file changed during scan: {relative}")
        total_bytes += len(data)
        if total_bytes > max_total_bytes:
            raise SourceLimitError(f"Python source tree exceeds {max_total_bytes} bytes")
        snapshots.append(_FileSnapshot(relative_file=relative, data=data))
    return tuple(snapshots)


def _lstat_regular_file(path: Path, *, relative: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceChangedError(f"source file changed during scan: {relative}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SourceChangedError(f"source file changed during scan: {relative}")
    return metadata


def _read_file_no_follow(
    path: Path,
    *,
    limit: int,
) -> tuple[bytes, os.stat_result, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceChangedError(f"cannot safely open source file {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > limit:
        raise SourceLimitError(f"Python source file exceeds {limit} bytes: {path.name}")
    return data, opened, after


def _same_file_snapshot(
    before: os.stat_result,
    opened: os.stat_result,
    after: os.stat_result,
) -> bool:
    keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    return all(
        getattr(before, key, None) == getattr(opened, key, None) == getattr(after, key, None)
        for key in keys
    )


def _parse_python(data: bytes, *, filename: str) -> ast.Module | None:
    try:
        encoding, _lines = tokenize.detect_encoding(io.BytesIO(data).readline)
        text = data.decode(encoding)
        return ast.parse(text, filename=filename)
    except (LookupError, SyntaxError, UnicodeDecodeError, ValueError):
        return None


def _source_digest(snapshots: Sequence[_FileSnapshot]) -> str:
    digest = hashlib.sha256()
    for snapshot in snapshots:
        path_bytes = snapshot.relative_file.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(snapshot.data).to_bytes(8, "big"))
        digest.update(snapshot.data)
    return f"sha256:{digest.hexdigest()}"


def _candidate_digest(candidates: Sequence[SourceCandidate]) -> str:
    encoded = json.dumps(
        [candidate.to_json() for candidate in candidates],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _route_handlers(tree: ast.Module) -> tuple[tuple[_RouteHandler, ...], int]:
    bindings = _analysis_bindings(tree)
    handlers: list[_RouteHandler] = []
    skipped_patterns = 0
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            parsed = _parse_route_decorator(
                decorator,
                framework_owners=bindings.framework_owners,
            )
            if parsed is None:
                if _recognized_route_decorator(
                    decorator,
                    framework_owners=bindings.framework_owners,
                    unresolved_framework_owners=bindings.unresolved_framework_owners,
                ):
                    skipped_patterns += 1
                continue
            framework, route, methods, route_binding = parsed
            if route_binding not in {"direct", "mounted"}:
                skipped_patterns += 1
            handlers.extend(
                _RouteHandler(
                    framework=framework,
                    method=method,
                    route=route,
                    function=node,
                    bindings=bindings,
                    route_binding=route_binding,
                )
                for method in methods
            )
    return tuple(handlers), skipped_patterns


def _analysis_bindings(tree: ast.Module) -> _AnalysisBindings:
    request_names = {"request"}
    fastapi_markers = dict(_FASTAPI_MARKERS)
    fastapi_non_input_markers = set(_FASTAPI_NON_INPUT_MARKERS)
    fastapi_transport_annotations = {
        annotation: annotation for annotation in _FASTAPI_TRANSPORT_ANNOTATIONS
    }
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        module = str(node.module or "")
        if module == "starlette.requests":
            for alias in node.names:
                if alias.name == "Request":
                    fastapi_transport_annotations[(alias.asname or alias.name).casefold()] = (
                        "request"
                    )
            continue
        if module == "flask":
            request_names.update(
                alias.asname or alias.name for alias in node.names if alias.name == "request"
            )
            continue
        if module != "fastapi":
            continue
        for alias in node.names:
            imported = alias.name.casefold()
            local = (alias.asname or alias.name).casefold()
            if imported in _FASTAPI_MARKERS:
                fastapi_markers[local] = _FASTAPI_MARKERS[imported]
            elif imported in _FASTAPI_NON_INPUT_MARKERS:
                fastapi_non_input_markers.add(local)
            elif imported in _FASTAPI_TRANSPORT_ANNOTATIONS:
                fastapi_transport_annotations[local] = imported
    framework_owners, unresolved_framework_owners = _framework_owners(tree)
    return _AnalysisBindings(
        framework_owners=framework_owners,
        unresolved_framework_owners=unresolved_framework_owners,
        request_names=frozenset(request_names),
        fastapi_markers=fastapi_markers,
        fastapi_non_input_markers=frozenset(fastapi_non_input_markers),
        fastapi_transport_annotations=fastapi_transport_annotations,
    )


def _framework_owners(
    tree: ast.Module,
) -> tuple[dict[str, _FrameworkOwner], frozenset[str]]:
    known_constructors: dict[str, tuple[str, str]] = {
        "APIRouter": ("fastapi", "api_router"),
        "FastAPI": ("fastapi", "fastapi"),
        "Blueprint": ("flask", "blueprint"),
        "Flask": ("flask", "flask"),
    }
    constructors: dict[str, tuple[str, str]] = {}
    module_aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                framework = (
                    "fastapi"
                    if alias.name == "fastapi"
                    else "flask"
                    if alias.name == "flask"
                    else ""
                )
                if framework:
                    module_aliases[alias.asname or alias.name] = framework
            continue
        if isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            framework = "fastapi" if module == "fastapi" else "flask" if module == "flask" else ""
            if not framework:
                continue
            for alias in node.names:
                known = known_constructors.get(alias.name)
                if known is not None and known[0] == framework:
                    constructors[alias.asname or alias.name] = known
    owners: dict[str, _FrameworkOwner] = {}
    unresolved_owners: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        resolved = _resolved_framework_constructor(
            value.func,
            constructors=constructors,
            module_aliases=module_aliases,
            known_constructors=known_constructors,
        )
        if not resolved:
            continue
        framework, constructor_kind = resolved
        prefix = _constructor_prefix(value, constructor_kind=constructor_kind)
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                if prefix is None:
                    unresolved_owners.add(target.id)
                else:
                    owners[target.id] = _FrameworkOwner(
                        framework=framework,
                        prefix=prefix,
                        kind=constructor_kind,
                        route_binding=(
                            "direct" if constructor_kind in {"fastapi", "flask"} else "relative"
                        ),
                    )
    owners = _apply_registered_route_prefixes(
        tree,
        owners=owners,
        unresolved_owners=unresolved_owners,
    )
    return owners, frozenset(unresolved_owners)


def _resolved_framework_constructor(
    function: ast.expr,
    *,
    constructors: Mapping[str, tuple[str, str]],
    module_aliases: Mapping[str, str],
    known_constructors: Mapping[str, tuple[str, str]],
) -> tuple[str, str] | None:
    if isinstance(function, ast.Name):
        return constructors.get(function.id)
    if not isinstance(function, ast.Attribute):
        return None
    framework = module_aliases.get(_root_name(function.value))
    known = known_constructors.get(function.attr)
    if framework and known is not None and known[0] == framework:
        return known
    return None


def _apply_registered_route_prefixes(
    tree: ast.Module,
    *,
    owners: dict[str, _FrameworkOwner],
    unresolved_owners: set[str],
) -> dict[str, _FrameworkOwner]:
    registrations: dict[str, list[_RouteRegistration]] = {}
    for statement in tree.body:
        node = statement.value if isinstance(statement, ast.Expr) else None
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        registration = node.func.attr.casefold()
        if registration not in {"include_router", "register_blueprint"}:
            continue
        parent = owners.get(_root_name(node.func.value))
        if parent is None or not node.args or not isinstance(node.args[0], ast.Name):
            continue
        child_name = node.args[0].id
        child = owners.get(child_name)
        expected_framework = "fastapi" if registration == "include_router" else "flask"
        if (
            child is None
            or parent.framework != expected_framework
            or child.framework != expected_framework
        ):
            continue
        keyword_name = "prefix" if expected_framework == "fastapi" else "url_prefix"
        supplied, registered_prefix = _static_keyword_prefix(node, keyword_name=keyword_name)
        if registered_prefix is None:
            unresolved_owners.add(child_name)
            continue
        registrations.setdefault(child_name, []).append(
            _RouteRegistration(
                parent_name=_root_name(node.func.value),
                child_name=child_name,
                prefix=registered_prefix,
                prefix_supplied=supplied,
            )
        )

    resolved: dict[str, _FrameworkOwner] = {}

    def resolve(name: str, *, trail: frozenset[str] = frozenset()) -> _FrameworkOwner | None:
        if name in resolved:
            return resolved[name]
        owner = owners.get(name)
        if owner is None or name in unresolved_owners or name in trail:
            unresolved_owners.add(name)
            return None
        if owner.route_binding == "direct":
            resolved[name] = owner
            return owner
        mounts = registrations.get(name, [])
        if not mounts:
            resolved[name] = owner
            return owner
        if len(mounts) != 1:
            unresolved_owners.add(name)
            return None
        mount = mounts[0]
        parent = resolve(mount.parent_name, trail=trail | {name})
        if parent is None:
            unresolved_owners.add(name)
            return None
        local_prefix = (
            mount.prefix
            if owner.framework == "flask" and mount.prefix_supplied
            else _join_prefix(mount.prefix, owner.prefix)
        )
        binding = _FrameworkOwner(
            framework=owner.framework,
            prefix=_join_prefix(parent.prefix, local_prefix),
            kind=owner.kind,
            route_binding=(
                "mounted" if parent.route_binding in {"direct", "mounted"} else "relative"
            ),
        )
        resolved[name] = binding
        return binding

    for name, owner in owners.items():
        binding = resolve(name)
        if binding is not None:
            resolved[name] = binding
        elif owner.route_binding == "relative":
            # Preserve a local route hint, but never treat an ambiguous or
            # dynamically mounted router as a live URL.
            resolved[name] = owner
    return resolved


def _static_keyword_prefix(
    call: ast.Call,
    *,
    keyword_name: str,
) -> tuple[bool, str | None]:
    for keyword in call.keywords:
        if keyword.arg != keyword_name:
            continue
        if not isinstance(keyword.value, ast.Constant) or not isinstance(keyword.value.value, str):
            return True, None
        return True, _normalized_route_prefix(keyword.value.value)
    return False, ""


def _join_prefix(first: str, second: str) -> str:
    if not first:
        return second
    if not second:
        return first
    joined = _join_route(first, second)
    normalized = _normalized_route_prefix(joined)
    return normalized or ""


def _constructor_prefix(call: ast.Call, *, constructor_kind: str) -> str | None:
    keyword_name = {
        "api_router": "prefix",
        "blueprint": "url_prefix",
    }.get(constructor_kind)
    if keyword_name is None:
        return ""
    for keyword in call.keywords:
        if keyword.arg != keyword_name:
            continue
        if not isinstance(keyword.value, ast.Constant) or not isinstance(keyword.value.value, str):
            return None
        return _normalized_route_prefix(keyword.value.value)
    return ""


def _parse_route_decorator(
    decorator: ast.expr,
    *,
    framework_owners: Mapping[str, _FrameworkOwner],
) -> tuple[str, str, tuple[str, ...], str] | None:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return None
    decorator_name = decorator.func.attr.lower()
    if decorator_name not in {*_ROUTE_METHODS, "route", "api_route"}:
        return None
    if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
        return None
    raw_route = decorator.args[0].value
    if not isinstance(raw_route, str):
        return None
    route = _normalized_route(raw_route)
    if not route:
        return None
    owner = _root_name(decorator.func.value)
    binding = framework_owners.get(owner)
    if binding is None:
        return None
    route = _join_route(binding.prefix, route)
    if not route:
        return None
    methods: tuple[str, ...]
    if decorator_name in _ROUTE_METHODS:
        methods = (_ROUTE_METHODS[decorator_name],)
    else:
        parsed_methods = _decorator_methods(decorator)
        if parsed_methods is None:
            return None
        methods = parsed_methods or ("GET",)
    return binding.framework, route, methods, binding.route_binding


def _recognized_route_decorator(
    decorator: ast.expr,
    *,
    framework_owners: Mapping[str, _FrameworkOwner],
    unresolved_framework_owners: frozenset[str],
) -> bool:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return False
    if decorator.func.attr.casefold() not in {*_ROUTE_METHODS, "route", "api_route"}:
        return False
    owner = _root_name(decorator.func.value)
    return owner in framework_owners or owner in unresolved_framework_owners


def _decorator_methods(decorator: ast.Call) -> tuple[str, ...] | None:
    for keyword in decorator.keywords:
        if keyword.arg != "methods" or not isinstance(
            keyword.value, (ast.List, ast.Tuple, ast.Set)
        ):
            if keyword.arg == "methods":
                return None
            continue
        methods: set[str] = set()
        for item in keyword.value.elts:
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                return None
            method = item.value.upper()
            if method not in _HTTP_METHODS:
                return None
            methods.add(method)
        if not methods:
            return None
        return tuple(sorted(methods))
    return ()


def _normalized_route(value: str) -> str:
    route = _FLASK_ROUTE_PARAMETER_RE.sub(lambda match: "{" + match.group(1) + "}", value)
    if (
        not route.startswith("/")
        or route.startswith("//")
        or len(route) > 1_024
        or "\\" in route
        or "?" in route
        or "#" in route
        or "//" in route
        or any(part in {".", ".."} for part in route.split("/"))
        or any(character.isspace() or ord(character) < 32 for character in route)
    ):
        return ""
    without_parameters = _SAFE_ROUTE_PARAMETER_RE.sub("parameter", route)
    if "{" in without_parameters or "}" in without_parameters:
        return ""
    return route


def _normalized_route_prefix(value: str) -> str | None:
    if not value:
        return ""
    route = _normalized_route(value)
    if not route:
        return None
    return "" if route == "/" else route.rstrip("/")


def _join_route(prefix: str, route: str) -> str:
    if not prefix:
        return route
    combined = f"{prefix}/" if route == "/" else f"{prefix}{route}"
    return _normalized_route(combined)


def _handler_candidates(
    handler: _RouteHandler,
    *,
    relative_file: str,
) -> tuple[list[SourceCandidate], int]:
    if not _candidate_safe_relative_file(relative_file):
        return [], 1
    handler_inputs = _handler_parameter_inputs(handler)
    analyzer = _HandlerFlowAnalyzer(
        initial_inputs=handler_inputs.taints,
        request_names=handler_inputs.request_names,
    )
    analyzer.analyze(handler.function.body)
    request_fields, fields_complete = _merged_request_fields(
        handler_inputs.request_fields,
        analyzer.request_fields,
    )
    live_shape_complete = (
        handler_inputs.live_shape_complete and analyzer.live_shape_complete and fields_complete
    )
    candidates: list[SourceCandidate] = []
    for family, sink_kind, line, input_ref in analyzer.sinks:
        if not _SAFE_INPUT_RE.fullmatch(input_ref.name):
            continue
        live_validation, query_fields = _candidate_live_validation(
            handler,
            family=family,
            input_ref=input_ref,
            request_fields=request_fields,
            live_shape_complete=live_shape_complete,
        )
        structural = {
            "family": family,
            "method": handler.method,
            "route": handler.route,
            "input_name": input_ref.name,
            "input_location": input_ref.location,
            "framework": handler.framework,
            "route_binding": handler.route_binding,
            "relative_file": relative_file,
            "line": line,
            "sink_kind": sink_kind,
            "live_validation": live_validation,
            "query_fields": query_fields,
        }
        candidates.append(
            SourceCandidate(
                candidate_id=_candidate_id(_candidate_id_payload(structural)),
                reason=_candidate_reason(family),
                **structural,  # type: ignore[arg-type]
            )
        )
    skipped = handler_inputs.patterns_skipped + analyzer.patterns_skipped
    if not fields_complete:
        skipped += 1
    return candidates, skipped


def _handler_parameter_inputs(handler: _RouteHandler) -> _HandlerInputs:
    inputs: dict[str, frozenset[_InputRef]] = {}
    request_fields: list[_RequestField] = []
    request_names = set(handler.bindings.request_names)
    live_shape_complete = True
    patterns_skipped = 0
    positional = [*handler.function.args.posonlyargs, *handler.function.args.args]
    missing_defaults = len(positional) - len(handler.function.args.defaults)
    arguments: list[tuple[ast.arg, ast.expr | None, bool]] = [
        (argument, None, False) for argument in positional[:missing_defaults]
    ]
    arguments.extend(
        (argument, default, True)
        for argument, default in zip(
            positional[missing_defaults:],
            handler.function.args.defaults,
            strict=True,
        )
    )
    arguments.extend(
        (argument, default, default is not None)
        for argument, default in zip(
            handler.function.args.kwonlyargs,
            handler.function.args.kw_defaults,
            strict=True,
        )
    )
    route_parameters = set(_SAFE_ROUTE_PARAMETER_RE.findall(handler.route))
    for argument, default, default_present in arguments:
        name = argument.arg
        if name in {"self", "cls"} or not _SAFE_INPUT_RE.fullmatch(name):
            continue
        if name in route_parameters:
            value_kind = _fastapi_scalar_kind(argument.annotation) or "string"
            input_ref = _InputRef(name=name, location="path")
            inputs[name] = frozenset({input_ref})
            request_fields.append(
                _RequestField(
                    name=name,
                    location="path",
                    value_kind=value_kind,
                    required=True,
                )
            )
            continue
        if handler.framework != "fastapi":
            continue
        parameter = _fastapi_parameter(
            name=name,
            default=default,
            default_present=default_present,
            annotation=argument.annotation,
            bindings=handler.bindings,
        )
        if parameter.request_name:
            request_names.add(name)
        if parameter.input_ref is not None:
            inputs[name] = frozenset({parameter.input_ref})
        if parameter.request_field is not None:
            request_fields.append(parameter.request_field)
        if not parameter.live_shape_supported:
            live_shape_complete = False
            patterns_skipped += 1
    if handler.function.args.vararg is not None or handler.function.args.kwarg is not None:
        live_shape_complete = False
        patterns_skipped += 1
    return _HandlerInputs(
        taints=inputs,
        request_fields=tuple(sorted(set(request_fields))),
        request_names=frozenset(request_names),
        live_shape_complete=live_shape_complete,
        patterns_skipped=patterns_skipped,
    )


def _fastapi_parameter(
    *,
    name: str,
    default: ast.expr | None,
    default_present: bool,
    annotation: ast.expr | None,
    bindings: _AnalysisBindings,
) -> _FastAPIParameter:
    base_annotation, metadata = _annotated_parts(annotation)
    marker_calls = [
        item
        for item in (default, *metadata)
        if isinstance(item, ast.Call)
        and (
            _call_name(item.func).casefold() in bindings.fastapi_markers
            or _call_name(item.func).casefold() in bindings.fastapi_non_input_markers
        )
    ]
    if len(marker_calls) > 1:
        return _FastAPIParameter(
            input_ref=None,
            request_field=None,
            request_name=False,
            live_shape_supported=False,
        )
    marker_call = marker_calls[0] if marker_calls else None
    marker = _call_name(marker_call.func).casefold() if marker_call is not None else ""
    annotation_name = _call_name(base_annotation).casefold()
    transport_kind = bindings.fastapi_transport_annotations.get(annotation_name, "")
    if transport_kind:
        return _FastAPIParameter(
            input_ref=None,
            request_field=None,
            request_name=transport_kind == "request",
            live_shape_supported=transport_kind in {"request", "response"},
        )
    if marker in bindings.fastapi_non_input_markers:
        return _FastAPIParameter(
            input_ref=None,
            request_field=None,
            request_name=False,
            live_shape_supported=False,
        )

    value_kind = _fastapi_scalar_kind(base_annotation)
    if marker in bindings.fastapi_markers:
        location = bindings.fastapi_markers[marker]
    elif value_kind:
        location = "query"
    else:
        # Unmarked Pydantic models and other complex annotations are body
        # shapes whose wire fields cannot be recovered from this function
        # signature alone. Do not mislabel the local variable as a query key.
        return _FastAPIParameter(
            input_ref=None,
            request_field=None,
            request_name=False,
            live_shape_supported=False,
        )
    wire_name = _fastapi_alias(marker_call, fallback=name)
    if not wire_name:
        return _FastAPIParameter(
            input_ref=None,
            request_field=None,
            request_name=False,
            live_shape_supported=False,
        )
    required = _fastapi_parameter_required(
        default=default,
        default_present=default_present,
        marker_call=marker_call,
    )
    field = _RequestField(
        name=wire_name,
        location=location,
        value_kind=value_kind or "unknown",
        required=required,
    )
    return _FastAPIParameter(
        input_ref=_InputRef(name=wire_name, location=location),
        request_field=field,
        request_name=False,
        live_shape_supported=bool(value_kind),
    )


def _annotated_parts(annotation: ast.expr | None) -> tuple[ast.expr | None, tuple[ast.expr, ...]]:
    if not isinstance(annotation, ast.Subscript):
        return annotation, ()
    if _dotted_name(annotation.value).casefold() not in {
        "annotated",
        "typing.annotated",
        "typing_extensions.annotated",
    }:
        return annotation, ()
    values = (
        annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
    )
    if not values:
        return annotation, ()
    return values[0], tuple(values[1:])


def _fastapi_alias(call: ast.Call | None, *, fallback: str) -> str:
    if call is None:
        return fallback
    alias_keyword = next((item for item in call.keywords if item.arg == "alias"), None)
    if alias_keyword is None:
        return fallback
    alias = _constant_string(alias_keyword.value)
    return alias if _SAFE_INPUT_RE.fullmatch(alias) else ""


def _fastapi_parameter_required(
    *,
    default: ast.expr | None,
    default_present: bool,
    marker_call: ast.Call | None,
) -> bool:
    if marker_call is not None and marker_call is default:
        marker_default = _fastapi_marker_default(marker_call)
        return marker_default is None or _is_ellipsis(marker_default)
    if default_present:
        return default is None or _is_ellipsis(default)
    if marker_call is not None:
        marker_default = _fastapi_marker_default(marker_call)
        if marker_default is not None:
            return _is_ellipsis(marker_default)
    return True


def _fastapi_marker_default(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    return next((item.value for item in call.keywords if item.arg == "default"), None)


def _is_ellipsis(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is Ellipsis


def _fastapi_scalar_kind(annotation: ast.expr | None) -> str:
    annotation, _metadata = _annotated_parts(annotation)
    members = _optional_annotation_members(annotation)
    if members is not None:
        non_none = [item for item in members if not _is_none_annotation(item)]
        if len(non_none) != 1:
            return ""
        annotation = non_none[0]
    if annotation is None:
        return "string"
    return _FASTAPI_SCALAR_KINDS.get(_call_name(annotation).casefold(), "")


def _optional_annotation_members(annotation: ast.expr | None) -> list[ast.expr] | None:
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        members: list[ast.expr] = []
        for side in (annotation.left, annotation.right):
            nested = _optional_annotation_members(side)
            members.extend(nested if nested is not None else [side])
        return members
    if isinstance(annotation, ast.Subscript) and _call_name(annotation.value).casefold() in {
        "optional",
        "union",
    }:
        if isinstance(annotation.slice, ast.Tuple):
            return list(annotation.slice.elts)
        return [annotation.slice]
    return None


def _is_none_annotation(annotation: ast.expr) -> bool:
    return (isinstance(annotation, ast.Constant) and annotation.value is None) or (
        isinstance(annotation, ast.Name) and annotation.id == "None"
    )


def _merged_request_fields(
    declared: Sequence[_RequestField],
    observed: Sequence[_RequestField],
) -> tuple[tuple[_RequestField, ...], bool]:
    fields: dict[tuple[str, str], _RequestField] = {}
    locations_by_name: dict[str, set[str]] = {}
    complete = True
    for field in (*declared, *observed):
        locations_by_name.setdefault(field.name, set()).add(field.location)
        key = (field.location, field.name)
        previous = fields.get(key)
        if previous is None:
            fields[key] = field
            continue
        if previous.value_kind != field.value_kind:
            complete = False
        fields[key] = _RequestField(
            name=field.name,
            location=field.location,
            value_kind=(
                previous.value_kind if previous.value_kind == field.value_kind else "unknown"
            ),
            required=previous.required or field.required,
        )
    if any(len(locations) != 1 for locations in locations_by_name.values()):
        complete = False
    return tuple(sorted(fields.values())), complete


def _candidate_live_validation(
    handler: _RouteHandler,
    *,
    family: str,
    input_ref: _InputRef,
    request_fields: Sequence[_RequestField],
    live_shape_complete: bool,
) -> tuple[str, tuple[SourceQueryField, ...]]:
    supported_kinds = set(_FASTAPI_SCALAR_KINDS.values())
    if (
        family != "sql_injection"
        or handler.method != "GET"
        or handler.route_binding not in {"direct", "mounted"}
        or input_ref.location != "query"
        or "{" in handler.route
        or "}" in handler.route
        or not live_shape_complete
        or not request_fields
        or any(field.location != "query" for field in request_fields)
        or any(field.value_kind not in supported_kinds for field in request_fields)
        or not _route_safe_for_automatic_get(handler.route)
    ):
        return _LIVE_VALIDATION_HINT_ONLY, ()
    query_fields = tuple(
        SourceQueryField(
            name=field.name,
            value_kind=field.value_kind,
            required=field.required,
        )
        for field in request_fields
    )
    target_field = next(
        (field for field in query_fields if field.name == input_ref.name),
        None,
    )
    if target_field is None or target_field.value_kind != "string":
        return _LIVE_VALIDATION_HINT_ONLY, ()
    return _LIVE_VALIDATION_AUTOMATIC, query_fields


def _route_safe_for_automatic_get(route: str) -> bool:
    mutating_segments = {
        "activate",
        "approve",
        "archive",
        "ban",
        "change",
        "clear",
        "close",
        "confirm",
        "create",
        "deactivate",
        "delete",
        "destroy",
        "disable",
        "drop",
        "edit",
        "enable",
        "execute",
        "flush",
        "generate",
        "import",
        "invite",
        "lock",
        "logout",
        "merge",
        "migrate",
        "remove",
        "reset",
        "restore",
        "revoke",
        "rotate",
        "run",
        "send",
        "set",
        "signout",
        "start",
        "stop",
        "suspend",
        "sync",
        "terminate",
        "toggle",
        "truncate",
        "unlock",
        "update",
        "upload",
        "write",
    }
    route_tokens: set[str] = set()
    for segment in route.split("/"):
        if not segment:
            continue
        snake_case = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", segment).casefold()
        route_tokens.update(token for token in re.split(r"[-_.]+", snake_case) if token)
    return not (route_tokens & mutating_segments)


def _candidate_id_payload(structural: Mapping[str, object]) -> dict[str, object]:
    payload = dict(structural)
    query_fields = payload.get("query_fields")
    if isinstance(query_fields, tuple):
        payload["query_fields"] = [
            field.to_json() if isinstance(field, SourceQueryField) else field
            for field in query_fields
        ]
    return payload


class _HandlerFlowAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        *,
        initial_inputs: Mapping[str, frozenset[_InputRef]],
        request_names: frozenset[str],
    ) -> None:
        self.taints: dict[str, frozenset[_InputRef]] = dict(initial_inputs)
        self.sinks: list[tuple[str, str, int, _InputRef]] = []
        self.request_names = request_names
        self.container_locations: dict[str, str] = {}
        self.http_client_names: set[str] = set()
        self._request_fields: set[_RequestField] = set()
        self._skipped_patterns: set[tuple[str, int, int]] = set()

    @property
    def request_fields(self) -> tuple[_RequestField, ...]:
        return tuple(sorted(self._request_fields))

    @property
    def live_shape_complete(self) -> bool:
        return not self._skipped_patterns

    @property
    def patterns_skipped(self) -> int:
        return len(self._skipped_patterns)

    def analyze(self, statements: Sequence[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)

    def visit_Assign(self, node: ast.Assign) -> None:
        container_location = self._container_location(node.value)
        is_http_client = _is_http_client_constructor(node.value)
        refs = self._expr_taints(
            node.value,
            allow_whole_container=bool(container_location),
        )
        for target in node.targets:
            self._assign_target(target, refs)
            self._assign_container(target, container_location)
            self._assign_http_client(target, is_http_client=is_http_client)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        container_location = self._container_location(node.value)
        is_http_client = _is_http_client_constructor(node.value)
        refs = (
            self._expr_taints(
                node.value,
                allow_whole_container=bool(container_location),
            )
            if node.value is not None
            else frozenset()
        )
        self._assign_target(node.target, refs)
        self._assign_container(node.target, container_location)
        self._assign_http_client(node.target, is_http_client=is_http_client)
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        refs = self._expr_taints(node.target) | self._expr_taints(node.value)
        self._assign_target(node.target, refs)
        self._assign_container(node.target, "")
        self._assign_http_client(node.target, is_http_client=False)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        container_location = self._container_location(node.value)
        is_http_client = _is_http_client_constructor(node.value)
        refs = self._expr_taints(
            node.value,
            allow_whole_container=bool(container_location),
        )
        self._assign_target(node.target, refs)
        self._assign_container(node.target, container_location)
        self._assign_http_client(node.target, is_http_client=is_http_client)
        self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        if not self._container_location(node):
            self._expr_taints(node)
        sink = _sink_contract(node, http_client_names=frozenset(self.http_client_names))
        if sink is not None:
            family, sink_kind, argument = sink
            for input_ref in sorted(self._expr_taints(argument)):
                self.sinks.append((family, sink_kind, node.lineno, input_ref))
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self._visit_context_manager(node.items)
        self.analyze(node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_context_manager(node.items)
        self.analyze(node.body)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self._expr_taints(node)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before_taints = dict(self.taints)
        before_containers = dict(self.container_locations)
        before_http_clients = set(self.http_client_names)

        self.analyze(node.body)
        body_taints = dict(self.taints)
        body_containers = dict(self.container_locations)
        body_http_clients = set(self.http_client_names)

        self.taints = dict(before_taints)
        self.container_locations = dict(before_containers)
        self.http_client_names = set(before_http_clients)
        self.analyze(node.orelse)
        else_taints = dict(self.taints)
        else_containers = dict(self.container_locations)
        else_http_clients = set(self.http_client_names)

        self.taints = _merge_taint_branches(body_taints, else_taints)
        self.container_locations = {
            name: location
            for name, location in body_containers.items()
            if else_containers.get(name) == location
        }
        self.http_client_names = body_http_clients & else_http_clients

    def visit_For(self, node: ast.For) -> None:
        self._mark_skipped("for", node)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._mark_skipped("async_for", node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._mark_skipped("while", node)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._mark_skipped("try", node)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self._mark_skipped("match", node)
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def _assign_target(self, target: ast.expr, refs: frozenset[_InputRef]) -> None:
        if isinstance(target, ast.Name):
            if refs:
                self.taints[target.id] = refs
            else:
                self.taints.pop(target.id, None)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign_target(item, refs)

    def _assign_container(self, target: ast.expr, location: str) -> None:
        if isinstance(target, ast.Name):
            if location:
                self.container_locations[target.id] = location
            else:
                self.container_locations.pop(target.id, None)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign_container(item, location)

    def _assign_http_client(self, target: ast.expr, *, is_http_client: bool) -> None:
        if isinstance(target, ast.Name):
            if is_http_client:
                self.http_client_names.add(target.id)
            else:
                self.http_client_names.discard(target.id)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign_http_client(item, is_http_client=is_http_client)

    def _visit_context_manager(self, items: Sequence[ast.withitem]) -> None:
        for item in items:
            is_http_client = _is_http_client_constructor(item.context_expr)
            if item.optional_vars is not None:
                self._assign_http_client(
                    item.optional_vars,
                    is_http_client=is_http_client,
                )
            self.visit(item.context_expr)

    def _container_location(self, node: ast.AST | None) -> str:
        if isinstance(node, ast.Await):
            node = node.value
        if node is None:
            return ""
        return _request_container_location(
            node,
            request_names=self.request_names,
            container_locations=self.container_locations,
        )

    def _expr_taints(
        self,
        node: ast.AST | None,
        *,
        allow_whole_container: bool = False,
    ) -> frozenset[_InputRef]:
        if node is None:
            return frozenset()
        walked = list(ast.walk(node))
        consumed_containers: set[int] = set()
        for item in walked:
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute):
                if item.func.attr in {"get", "getlist", "pop"}:
                    consumed_containers.add(id(item.func.value))
            elif isinstance(item, ast.Subscript):
                consumed_containers.add(id(item.value))

        refs: set[_InputRef] = set()
        for item in walked:
            if isinstance(item, ast.Name):
                refs.update(self.taints.get(item.id, ()))
            direct, recognized = _request_input(
                item,
                request_names=self.request_names,
                container_locations=self.container_locations,
            )
            refs.update(direct)
            self._request_fields.update(
                _RequestField(
                    name=input_ref.name,
                    location=input_ref.location,
                    value_kind="string",
                    required=True,
                )
                for input_ref in direct
            )
            if recognized and not direct:
                self._mark_skipped("dynamic_request_key", item)
            location = self._container_location(item)
            if (
                location
                and id(item) not in consumed_containers
                and not (allow_whole_container and item is node)
                and not isinstance(item, ast.Name)
            ):
                self._mark_skipped("whole_request_container", item)
            if isinstance(item, ast.comprehension):
                self._mark_skipped("comprehension", item)
        return frozenset(refs)

    def _mark_skipped(self, kind: str, node: ast.AST) -> None:
        self._skipped_patterns.add(
            (
                kind,
                int(getattr(node, "lineno", 0) or 0),
                int(getattr(node, "col_offset", 0) or 0),
            )
        )


def _merge_taint_branches(
    first: Mapping[str, frozenset[_InputRef]],
    second: Mapping[str, frozenset[_InputRef]],
) -> dict[str, frozenset[_InputRef]]:
    return {
        name: frozenset(first.get(name, frozenset()) | second.get(name, frozenset()))
        for name in set(first) | set(second)
        if first.get(name) or second.get(name)
    }


def _request_input(
    node: ast.AST,
    *,
    request_names: frozenset[str],
    container_locations: Mapping[str, str],
) -> tuple[frozenset[_InputRef], bool]:
    location = ""
    name = ""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get", "pop", "getlist"} and node.args:
            location = _request_container_location(
                node.func.value,
                request_names=request_names,
                container_locations=container_locations,
            )
            name = _constant_string(node.args[0])
    elif isinstance(node, ast.Subscript):
        location = _request_container_location(
            node.value,
            request_names=request_names,
            container_locations=container_locations,
        )
        name = _constant_string(node.slice)
    if not location:
        return frozenset(), False
    if not name or not _SAFE_INPUT_RE.fullmatch(name):
        return frozenset(), True
    return frozenset({_InputRef(name=name, location=location)}), True


def _request_container_location(
    node: ast.AST,
    *,
    request_names: frozenset[str],
    container_locations: Mapping[str, str],
) -> str:
    if isinstance(node, ast.Await):
        node = node.value
    if isinstance(node, ast.Name):
        return container_locations.get(node.id, "")
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id in request_names:
            return _INPUT_LOCATIONS.get(node.attr, "")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id in request_names
            and node.func.attr in {"form", "get_json", "json"}
        ):
            return "form" if node.func.attr == "form" else "body"
    return ""


def _sink_contract(
    node: ast.Call,
    *,
    http_client_names: frozenset[str] = frozenset(),
) -> tuple[str, str, ast.expr] | None:
    name = _call_name(node.func)
    lowered = name.lower()
    sql_argument = _sql_statement_argument(node)
    if sql_argument is not None and _is_sql_execution_sink(node, lowered=lowered):
        return "sql_injection", f"sql_{lowered}", sql_argument
    if lowered in {"render_template_string", "from_string", "template"}:
        argument = _call_argument(node, keywords={"source", "string", "template"})
        if argument is not None:
            return "ssti", f"template_{lowered}", argument
    if _is_shell_sink(node, lowered=lowered):
        argument = _call_argument(node, keywords={"args", "command"})
        if argument is not None:
            return "command_injection", f"shell_{lowered}", argument
    if lowered == "open" and _open_reads_file(node):
        argument = _call_argument(node, keywords={"file"})
        if argument is not None:
            return "path_traversal", "file_open", argument
    if lowered in {"send_file", "fileresponse"}:
        argument = _call_argument(node, keywords={"path", "path_or_file"})
        if argument is not None:
            return "path_traversal", f"file_{lowered}", argument
    if lowered in {"read_text", "read_bytes"} and isinstance(node.func, ast.Attribute):
        constructor = node.func.value
        if (
            isinstance(constructor, ast.Call)
            and _call_name(constructor.func).lower()
            in {
                "path",
                "purepath",
            }
            and constructor.args
        ):
            return "path_traversal", f"file_{lowered}", constructor.args[0]
    if _is_outbound_url_sink(
        node,
        lowered=lowered,
        http_client_names=http_client_names,
    ):
        argument = _outbound_url_argument(node, lowered=lowered)
        if argument is not None:
            return "ssrf", f"outbound_{lowered}", argument
    return None


def _call_argument(
    node: ast.Call,
    *,
    keywords: set[str],
    position: int = 0,
) -> ast.expr | None:
    if len(node.args) > position:
        return node.args[position]
    return next(
        (keyword.value for keyword in node.keywords if keyword.arg in keywords),
        None,
    )


def _is_sql_execution_sink(node: ast.Call, *, lowered: str) -> bool:
    if lowered not in _SQL_EXECUTION_METHODS or not isinstance(node.func, ast.Attribute):
        return False
    qualifiers = _sql_receiver_qualifiers(node.func.value)
    if qualifiers & _SQL_EXECUTION_QUALIFIERS:
        return True
    if lowered == "raw":
        return bool(qualifiers & _SQL_RAW_QUALIFIERS)
    if lowered == "from_statement":
        return bool(qualifiers & _SQL_STATEMENT_QUALIFIERS)
    return False


def _sql_statement_argument(node: ast.Call) -> ast.expr | None:
    if node.args:
        return node.args[0]
    return next(
        (
            keyword.value
            for keyword in node.keywords
            if keyword.arg
            in {
                "command",
                "operation",
                "query",
                "raw_query",
                "sql",
                "statement",
            }
        ),
        None,
    )


def _sql_receiver_qualifiers(node: ast.expr) -> frozenset[str]:
    """Return names on the receiver spine without inspecting call arguments."""
    if isinstance(node, ast.Name):
        return frozenset({_normalized_sql_qualifier(node.id)})
    if isinstance(node, ast.Attribute):
        return _sql_receiver_qualifiers(node.value) | {_normalized_sql_qualifier(node.attr)}
    if isinstance(node, ast.Call):
        return _sql_receiver_qualifiers(node.func)
    if isinstance(node, ast.Subscript):
        return _sql_receiver_qualifiers(node.value)
    return frozenset()


def _normalized_sql_qualifier(value: str) -> str:
    return value.casefold().strip("_")


def _is_shell_sink(node: ast.Call, *, lowered: str) -> bool:
    dotted = _dotted_name(node.func).lower()
    if dotted in {"os.system", "os.popen"}:
        return True
    if lowered not in {"call", "check_call", "check_output", "popen", "run"}:
        return False
    if not dotted.startswith("subprocess."):
        return False
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _open_reads_file(node: ast.Call) -> bool:
    mode_node: ast.expr | None = node.args[1] if len(node.args) >= 2 else None
    if mode_node is None:
        mode_node = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "mode"),
            None,
        )
    if mode_node is None:
        return True
    mode = _constant_string(mode_node)
    return not mode or "r" in mode or "+" in mode


def _is_outbound_url_sink(
    node: ast.Call,
    *,
    lowered: str,
    http_client_names: frozenset[str],
) -> bool:
    dotted = _dotted_name(node.func).lower()
    if dotted in {"urllib.request.urlopen", "urlopen"}:
        return True
    if lowered not in {"get", "post", "put", "patch", "delete", "request", "stream"}:
        return False
    if dotted.startswith(("requests.", "httpx.")):
        return True
    receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
    return (
        isinstance(receiver, ast.Name) and receiver.id in http_client_names
    ) or _is_http_client_constructor(receiver)


def _is_http_client_constructor(node: ast.AST | None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _dotted_name(node.func).casefold() in {
        "aiohttp.clientsession",
        "httpx.asyncclient",
        "httpx.client",
        "requests.session",
    }


def _outbound_url_argument(node: ast.Call, *, lowered: str) -> ast.expr | None:
    for keyword in node.keywords:
        if keyword.arg in {"url", "uri"}:
            return keyword.value
    if lowered == "request" and len(node.args) >= 2:
        return node.args[1]
    if lowered == "request":
        return None
    if node.args:
        return node.args[0]
    return None


def _candidate_id(structural: Mapping[str, object]) -> str:
    encoded = json.dumps(
        structural,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"src-{hashlib.sha256(encoded).hexdigest()[:24]}"


def _candidate_reason(family: str) -> str:
    return {
        "sql_injection": "request input reaches the SQL text argument",
        "ssti": "request input reaches a dynamic template source",
        "command_injection": "request input reaches a shell command argument",
        "path_traversal": "request input reaches a local file-read path",
        "ssrf": "request input reaches an outbound URL argument",
    }[family]


def _candidate_sort_key(candidate: SourceCandidate) -> tuple[object, ...]:
    return (
        candidate.relative_file,
        candidate.line,
        candidate.route,
        candidate.method,
        candidate.family,
        candidate.input_name,
        candidate.sink_kind,
    )


def _candidate_safe_relative_file(value: str) -> bool:
    if not value or len(value) > 240 or "\\" in value:
        return False
    path = PurePosixPath(value)
    parts = value.split("/")
    return (
        not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in parts)
        and all(_SAFE_FILE_SEGMENT_RE.fullmatch(part) for part in parts)
    )


def _constant_string(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _call_name(node: ast.expr | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _dotted_name(node: ast.expr) -> str:
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _root_name(node: ast.expr) -> str:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else ""


__all__ = [
    "SOURCE_ANALYZER_CONTRACT",
    "SOURCE_MAP_SCHEMA",
    "SourceAnalysisError",
    "SourceCandidate",
    "SourceChangedError",
    "SourceLimitError",
    "SourceMap",
    "SourceRootError",
    "analyze_source_root",
]
