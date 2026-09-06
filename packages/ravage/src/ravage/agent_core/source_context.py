"""
Bounded, read-only source navigation over one immutable repository snapshot.

This module never opens repository paths, executes project code, calls a model,
or writes observations to disk. Callers own the short-lived raw observation;
the accompanying receipt excludes file contents, lookup literals, and
content-derived digests. Repository paths and coordinates remain as structural
navigation metadata.
"""

# Model-facing validation errors are deliberately concise and specific.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field

from ravage.repository_context import ContextLimitError, RepositoryContext

SOURCE_CONTEXT_ACTION = "source_context"
SOURCE_CONTEXT_OBSERVATION_SCHEMA = "ravage.source-context-observation.v1"
SOURCE_CONTEXT_RECEIPT_SCHEMA = "ravage.source-context-receipt.v1"
SOURCE_CONTEXT_TRUST = "untrusted_repository_content"
SOURCE_CONTEXT_PROVENANCE = "source_code"

MAX_SOURCE_CONTEXT_OBSERVATION_CHARS = 80_000
MAX_SOURCE_CONTEXT_FILE_PAGE = 100
MAX_SOURCE_CONTEXT_SEARCH_MATCHES = 20
MAX_SOURCE_CONTEXT_EXCERPT_LINES = 80

_MAX_LITERAL_CHARS = 256
_MAX_PATH_CHARS = 1_000
_MAX_TASK_ID_CHARS = 256
_MAX_INTEGER = 2**31 - 1
_OPERATIONS = frozenset({"list_files", "list_omissions", "search", "excerpt"})
_TOP_LEVEL_KEYS = frozenset({"action", "task_id", "operation", "args"})
_ARGUMENT_KEYS: dict[str, frozenset[str]] = {
    "list_files": frozenset({"prefix", "cursor", "limit"}),
    "list_omissions": frozenset({"cursor", "limit"}),
    "search": frozenset({"query", "max_matches"}),
    "excerpt": frozenset({"path", "start_line", "end_line"}),
}
_RAW_RECEIPT_KEYS = frozenset({"error", "file_digest", "text", "text_digest"})


@dataclass(frozen=True, slots=True)
class SourceContextExecution:
    """One transient model observation plus its text-free durable receipt."""

    ok: bool
    observation: dict[str, object] = field(repr=False, compare=False)
    receipt: dict[str, object]


class SourceContextExecutor:
    """Execute bounded navigation against captured bytes without rereading disk."""

    __slots__ = ("_context", "_max_observation_chars", "_observation_chars_used")

    def __init__(
        self,
        context: RepositoryContext,
        *,
        max_observation_chars: int = MAX_SOURCE_CONTEXT_OBSERVATION_CHARS,
        observation_chars_used: int = 0,
    ) -> None:
        if not isinstance(context, RepositoryContext):
            raise TypeError("context must be a RepositoryContext")
        _require_int(
            max_observation_chars,
            "max_observation_chars",
            minimum=1,
            maximum=MAX_SOURCE_CONTEXT_OBSERVATION_CHARS,
        )
        _require_int(
            observation_chars_used,
            "observation_chars_used",
            minimum=0,
            maximum=max_observation_chars,
        )
        self._context = context
        self._max_observation_chars = max_observation_chars
        self._observation_chars_used = observation_chars_used

    @property
    def snapshot_id(self) -> str:
        return str(self._context.snapshot_id)

    @property
    def observation_chars_used(self) -> int:
        return self._observation_chars_used

    @property
    def max_observation_chars(self) -> int:
        return self._max_observation_chars

    def execute(self, action: Mapping[str, object]) -> SourceContextExecution:
        """Return raw content only in-memory and a separate text-free receipt."""
        try:
            operation, arguments = _validated_action(action)
            payload = _execute_operation(self._context, operation, arguments)
        except (ContextLimitError, KeyError, TypeError, ValueError) as exc:
            return self._error(
                operation=_safe_operation(
                    action.get("operation") if isinstance(action, Mapping) else None
                ),
                message=_bounded_error(exc),
            )

        observation = _observation(self.snapshot_id, operation, payload)
        observation_chars = len(_canonical_json(observation))
        if self._observation_chars_used + observation_chars > self._max_observation_chars:
            return self._error(
                operation=operation,
                message="source context observation budget exhausted",
                error_code="observation_budget_exhausted",
            )
        self._observation_chars_used += observation_chars
        return SourceContextExecution(
            ok=True,
            observation=observation,
            receipt=_receipt(
                observation,
                ok=True,
                operation=operation,
                observation_chars=observation_chars,
                cumulative_chars=self._observation_chars_used,
            ),
        )

    def reject_repeated(
        self,
        action: Mapping[str, object],
        *,
        repeat_count: int,
    ) -> SourceContextExecution:
        """Reject an identical lookup without consuming the source text budget."""
        _require_int(repeat_count, "repeat_count", minimum=1)
        return self._error(
            operation=_safe_operation(action.get("operation")),
            message=f"identical source context action blocked at repeat {repeat_count}",
            error_code="identical_action_limit",
        )

    def _error(
        self,
        *,
        operation: str,
        message: str,
        error_code: str = "source_context_action_failed",
    ) -> SourceContextExecution:
        observation = _observation(
            self.snapshot_id,
            operation,
            {"type": "error", "error": message[:1_000]},
        )
        return SourceContextExecution(
            ok=False,
            observation=observation,
            receipt=_receipt(
                observation,
                ok=False,
                operation=operation,
                observation_chars=0,
                cumulative_chars=self._observation_chars_used,
                error_code=error_code,
            ),
        )


def source_context_action_schema() -> dict[str, object]:
    """Return a fresh prompt schema for the isolated action contract."""
    return {
        "action": SOURCE_CONTEXT_ACTION,
        "task_id": "one active task id",
        "operation": "choose exactly one: list_files, list_omissions, search, excerpt",
        "args": "copy the flat args object from the matching valid example",
        "valid_examples": [
            {
                "action": SOURCE_CONTEXT_ACTION,
                "task_id": "surface-map",
                "operation": "list_files",
                "args": {"prefix": "", "cursor": 0, "limit": 50},
            },
            {
                "action": SOURCE_CONTEXT_ACTION,
                "task_id": "surface-map",
                "operation": "list_omissions",
                "args": {"cursor": 0, "limit": 50},
            },
            {
                "action": SOURCE_CONTEXT_ACTION,
                "task_id": "surface-map",
                "operation": "search",
                "args": {"query": "case-sensitive literal", "max_matches": 10},
            },
            {
                "action": SOURCE_CONTEXT_ACTION,
                "task_id": "surface-map",
                "operation": "excerpt",
                "args": {"path": "relative/path", "start_line": 1, "end_line": 40},
            },
        ],
        "constraint": "args is flat; never place the operation name inside args",
    }


def normalize_source_context_action(action: Mapping[str, object]) -> dict[str, object]:
    """Canonicalize the one harmless operation wrapper models commonly emit."""
    normalized = {str(key): value for key, value in action.items()}
    operation = normalized.get("operation")
    arguments = normalized.get("args")
    if (
        isinstance(operation, str)
        and isinstance(arguments, Mapping)
        and set(arguments) == {operation}
        and isinstance(arguments.get(operation), Mapping)
    ):
        nested = arguments[operation]
        assert isinstance(nested, Mapping)
        normalized["args"] = {str(key): value for key, value in nested.items()}
    return normalized


def source_context_action_error(action: Mapping[str, object]) -> str:
    """Return an empty string for a valid action or one bounded diagnostic."""
    try:
        _validated_action(action)
    except (TypeError, ValueError) as exc:
        return _bounded_error(exc)
    return ""


def sanitize_source_context_action(action: Mapping[str, object]) -> dict[str, object]:
    """Return a durable action shape without repository lookup literals."""
    operation = _safe_operation(action.get("operation"))
    sanitized: dict[str, object] = {
        "action": SOURCE_CONTEXT_ACTION,
        "operation": operation,
    }
    arguments = action.get("args")
    if not isinstance(arguments, Mapping):
        return sanitized
    safe_arguments: dict[str, object] = {}
    if operation == "list_files":
        prefix = arguments.get("prefix")
        if isinstance(prefix, str):
            safe_arguments["prefix_chars"] = len(prefix)
        _copy_int_arguments(arguments, safe_arguments, "cursor", "limit")
    elif operation == "list_omissions":
        _copy_int_arguments(arguments, safe_arguments, "cursor", "limit")
    elif operation == "search":
        query = arguments.get("query")
        if isinstance(query, str):
            safe_arguments["query_chars"] = len(query)
        _copy_int_arguments(arguments, safe_arguments, "max_matches")
    elif operation == "excerpt":
        path = arguments.get("path")
        if isinstance(path, str):
            safe_arguments["path_chars"] = len(path)
        _copy_int_arguments(arguments, safe_arguments, "start_line", "end_line")
    sanitized["args"] = safe_arguments
    return sanitized


def _copy_int_arguments(
    source: Mapping[str, object], destination: dict[str, object], *keys: str
) -> None:
    for key in keys:
        value = source.get(key)
        if type(value) is int:
            destination[key] = value


def _validated_action(
    action: Mapping[str, object],
) -> tuple[str, Mapping[str, object]]:
    if not isinstance(action, Mapping):
        raise TypeError("source_context action must be an object")
    _reject_keys(action, _TOP_LEVEL_KEYS, label="source_context action")
    if action.get("action") != SOURCE_CONTEXT_ACTION:
        raise ValueError("source_context action must use action=source_context")
    if "task_id" in action:
        _require_text(
            action["task_id"],
            "source_context task_id",
            max_chars=_MAX_TASK_ID_CHARS,
            allow_empty=False,
        )
    operation = action.get("operation")
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise ValueError(
            "source_context operation must be list_files, list_omissions, search, or excerpt"
        )
    arguments = action.get("args")
    if not isinstance(arguments, Mapping):
        raise TypeError("source_context args must be an object")
    _reject_keys(arguments, _ARGUMENT_KEYS[operation], label="source_context args")
    _validate_arguments(operation, arguments)
    return operation, arguments


def _validate_arguments(  # noqa: C901
    operation: str,
    arguments: Mapping[str, object],
) -> None:
    if operation == "list_files" and "prefix" in arguments:
        _require_text(
            arguments["prefix"],
            "source_context prefix",
            max_chars=_MAX_LITERAL_CHARS,
            allow_empty=True,
        )
    if operation in {"list_files", "list_omissions"}:
        if "cursor" in arguments:
            _require_int(arguments["cursor"], "source_context cursor", minimum=0)
        if "limit" in arguments:
            _require_int(
                arguments["limit"],
                "source_context limit",
                minimum=1,
                maximum=MAX_SOURCE_CONTEXT_FILE_PAGE,
            )
    elif operation == "search":
        if "query" not in arguments:
            raise ValueError("source_context query is required")
        _require_text(
            arguments["query"],
            "source_context query",
            max_chars=_MAX_LITERAL_CHARS,
            allow_empty=False,
        )
        if "max_matches" in arguments:
            _require_int(
                arguments["max_matches"],
                "source_context max_matches",
                minimum=1,
                maximum=MAX_SOURCE_CONTEXT_SEARCH_MATCHES,
            )
    elif operation == "excerpt":
        for key in ("path", "start_line", "end_line"):
            if key not in arguments:
                raise ValueError(f"source_context {key} is required")
        _require_text(
            arguments["path"],
            "source_context path",
            max_chars=_MAX_PATH_CHARS,
            allow_empty=False,
        )
        start = _require_int(arguments["start_line"], "source_context start_line", minimum=1)
        end = _require_int(arguments["end_line"], "source_context end_line", minimum=1)
        if end < start:
            raise ValueError("source_context end_line must be greater than or equal to start_line")
        if end - start + 1 > MAX_SOURCE_CONTEXT_EXCERPT_LINES:
            raise ValueError("source_context excerpt is limited to 80 lines")


def _execute_operation(
    context: RepositoryContext,
    operation: str,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    if operation == "list_files":
        return _list_files(context, arguments)
    if operation == "list_omissions":
        return _list_omissions(context, arguments)
    if operation == "search":
        return _search(context, arguments)
    if operation == "excerpt":
        return _excerpt(context, arguments)
    raise ValueError("unsupported source context operation")


def _list_files(
    context: RepositoryContext,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    prefix = str(arguments.get("prefix") or "")
    cursor = _int_argument(arguments, "cursor", default=0)
    limit = _int_argument(arguments, "limit", default=50)
    matching = [source for source in context.files if source.path.startswith(prefix)]
    if cursor > len(matching):
        raise ValueError("source_context cursor is outside the matching file list")
    page = matching[cursor : cursor + limit]
    next_cursor = cursor + len(page)
    return {
        "type": "file_list",
        "files": [
            {
                "path": source.path,
                "size_bytes": source.size_bytes,
                "line_count": _line_count(source.text),
                "file_digest": source.digest,
            }
            for source in page
        ],
        "cursor": cursor,
        "next_cursor": next_cursor if next_cursor < len(matching) else None,
        "total_matching": len(matching),
    }


def _list_omissions(
    context: RepositoryContext,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    cursor = _int_argument(arguments, "cursor", default=0)
    limit = _int_argument(arguments, "limit", default=50)
    if cursor > len(context.omissions):
        raise ValueError("source_context cursor is outside the omission list")
    page = context.omissions[cursor : cursor + limit]
    next_cursor = cursor + len(page)
    return {
        "type": "omission_list",
        "omissions": [{"path": item.path, "reason": item.reason} for item in page],
        "cursor": cursor,
        "next_cursor": next_cursor if next_cursor < len(context.omissions) else None,
        "total": len(context.omissions),
    }


def _search(
    context: RepositoryContext,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    result = context.search(
        str(arguments["query"]),
        max_matches=_int_argument(arguments, "max_matches", default=10),
    )
    return {
        "type": "search_results",
        "matches": [
            {
                "path": match.path,
                "line": match.line,
                "column": match.column,
                "text": match.text,
                "text_start_column": match.text_start_column,
                "text_truncated": match.text_truncated,
                "file_digest": match.file_digest,
            }
            for match in result.matches
        ],
        "truncated": result.truncated,
    }


def _excerpt(
    context: RepositoryContext,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    path = str(arguments["path"])
    start = _int_argument(arguments, "start_line")
    requested_end = _int_argument(arguments, "end_line")
    source = next((item for item in context.files if item.path == path), None)
    if source is None:
        raise KeyError(path)
    end = min(requested_end, _line_count(source.text))
    excerpt = context.excerpt(path, start_line=start, end_line=end)
    return {
        "type": "excerpt",
        "path": excerpt.path,
        "start_line": excerpt.start_line,
        "end_line": excerpt.end_line,
        "requested_end_line": requested_end,
        "clamped_to_eof": requested_end != end,
        "text": excerpt.text,
        "text_digest": _digest(excerpt.text),
        "file_digest": excerpt.file_digest,
    }


def _observation(
    snapshot_id: str,
    operation: str,
    payload: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": SOURCE_CONTEXT_OBSERVATION_SCHEMA,
        "trust": SOURCE_CONTEXT_TRUST,
        "proof_eligible": False,
        "provenance": {"kind": SOURCE_CONTEXT_PROVENANCE, "snapshot_id": snapshot_id},
        "snapshot_id": snapshot_id,
        "operation": operation,
        **payload,
    }


def _receipt(  # noqa: PLR0913
    observation: Mapping[str, object],
    *,
    ok: bool,
    operation: str,
    observation_chars: int,
    cumulative_chars: int,
    error_code: str = "",
) -> dict[str, object]:
    snapshot_id = str(observation["snapshot_id"])
    receipt: dict[str, object] = {
        "schema": SOURCE_CONTEXT_RECEIPT_SCHEMA,
        "ok": ok,
        "operation": operation,
        "proof_eligible": False,
        "provenance": {"kind": SOURCE_CONTEXT_PROVENANCE, "snapshot_id": snapshot_id},
        "snapshot_id": snapshot_id,
        "observation_chars": observation_chars,
        "cumulative_observation_chars": cumulative_chars,
    }
    if not ok:
        receipt["error_code"] = error_code
        return receipt
    receipt["result"] = _text_free_result(observation)
    return receipt


def _text_free_result(observation: Mapping[str, object]) -> dict[str, object]:
    excluded = {
        "schema",
        "trust",
        "proof_eligible",
        "provenance",
        "snapshot_id",
        "operation",
        *_RAW_RECEIPT_KEYS,
    }
    return {
        str(key): _text_free_receipt_value(item)
        for key, item in observation.items()
        if key not in excluded
    }


def _text_free_receipt_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _text_free_receipt_value(item)
            for key, item in value.items()
            if str(key) not in _RAW_RECEIPT_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_text_free_receipt_value(item) for item in value]
    return value


def _reject_keys(
    value: Mapping[str, object],
    allowed: frozenset[str],
    *,
    label: str,
) -> None:
    unexpected = sorted(str(key) for key in value if key not in allowed)
    if unexpected:
        raise ValueError(f"{label} contains unsupported fields: {', '.join(unexpected)}")


def _require_text(
    value: object,
    label: str,
    *,
    max_chars: int,
    allow_empty: bool,
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise TypeError(f"{label} must be {'text' if allow_empty else 'nonempty text'}")
    if len(value) > max_chars or any(character in value for character in "\r\n\x00"):
        raise ValueError(f"{label} must be single-line text of at most {max_chars} characters")
    return value


def _require_int(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int = _MAX_INTEGER,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ValueError(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _int_argument(
    value: Mapping[str, object],
    key: str,
    *,
    default: int | None = None,
) -> int:
    item = value.get(key, default)
    assert isinstance(item, int)
    assert not isinstance(item, bool)
    return item


def _safe_operation(value: object) -> str:
    return str(value) if isinstance(value, str) and value in _OPERATIONS else "invalid"


def _line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _bounded_error(exc: BaseException) -> str:
    return (str(exc).strip() or type(exc).__name__)[:1_000]


def _canonical_json(value: Mapping[str, object]) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "MAX_SOURCE_CONTEXT_EXCERPT_LINES",
    "MAX_SOURCE_CONTEXT_FILE_PAGE",
    "MAX_SOURCE_CONTEXT_OBSERVATION_CHARS",
    "MAX_SOURCE_CONTEXT_SEARCH_MATCHES",
    "SOURCE_CONTEXT_ACTION",
    "SOURCE_CONTEXT_OBSERVATION_SCHEMA",
    "SOURCE_CONTEXT_PROVENANCE",
    "SOURCE_CONTEXT_RECEIPT_SCHEMA",
    "SOURCE_CONTEXT_TRUST",
    "SourceContextExecution",
    "SourceContextExecutor",
    "normalize_source_context_action",
    "sanitize_source_context_action",
    "source_context_action_error",
    "source_context_action_schema",
]
