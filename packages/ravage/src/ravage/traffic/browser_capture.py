"""Secret-safe Playwright network lifecycle capture."""

from __future__ import annotations

import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from ravage.traffic.redaction import (
    body_metadata,
    redact_headers,
    redact_text,
    safe_identifier,
    sanitize_url,
)

BROWSER_EVENT_SCHEMA_VERSION = "ravage.browser_event.v1"
DEFAULT_CAPTURED_RESOURCE_TYPES = frozenset({"document", "xhr", "fetch"})
DEFAULT_MAX_CAPTURE_REQUESTS = 5_000
MAX_CAPTURE_BODY_BYTES = 1_048_576

_ROUTE_PATTERN = "**/*"
_MAX_ERROR_CHARS = 2_000
_MAX_RECORDER_ERRORS = 20
_MAX_TERMINAL_STATES = 1_024
_MAX_CONTENT_LENGTH_DIGITS = 20


class BrowserTrafficRecorder(Protocol):
    """A non-persistent sink for sanitized Playwright lifecycle events."""

    def record_browser_event(self, event: Mapping[str, object], /) -> None: ...


class BrowserContextLike(Protocol):
    """The small Playwright BrowserContext surface used by the adapter."""

    def route(self, url: str, handler: Callable[[object], None]) -> None: ...

    def route_web_socket(self, url: str, handler: Callable[[object], None]) -> None: ...

    def on(self, event: str, handler: Callable[[object], None]) -> None: ...


class ScopeDecisionLike(Protocol):
    allowed: bool
    reason: str


ScopePredicate = Callable[[str], bool | ScopeDecisionLike]


@dataclass(slots=True)
class _RequestState:
    correlation_id: str
    sequence: int
    captured: bool
    parent_correlation_id: str = ""
    scope_allowed: bool | None = None
    request_seen: bool = False
    request_emitted: bool = False
    terminal: bool = False
    limit_exceeded: bool = False


def playwright_context_options(**options: object) -> dict[str, object]:
    """
    Return BrowserContext options that preserve the capture boundary.

    Playwright cannot reliably observe or route traffic owned by a service
    worker. Callers must create the context with this result before attaching a
    :class:`BrowserTrafficCapture`.
    """
    service_workers = options.get("service_workers")
    if service_workers is not None and service_workers != "block":
        message = "browser traffic capture requires service_workers='block'"
        raise ValueError(message)
    accept_downloads = options.get("accept_downloads")
    if accept_downloads not in {None, False}:
        message = "browser traffic capture requires accept_downloads=False"
        raise ValueError(message)
    return {**options, "service_workers": "block", "accept_downloads": False}


class BrowserTrafficCapture:
    """
    Scope and observe Playwright traffic without owning persistence.

    The adapter deliberately emits sanitized event dictionaries instead of
    importing a concrete traffic store. A store can implement
    :class:`BrowserTrafficRecorder` directly or provide a small adapter sink.
    """

    def __init__(
        self,
        *,
        recorder: BrowserTrafficRecorder,
        scope_predicate: ScopePredicate,
        capture_all_resources: bool = False,
        capture_session_id: str | None = None,
        max_requests: int = DEFAULT_MAX_CAPTURE_REQUESTS,
    ) -> None:
        if isinstance(max_requests, bool) or max_requests <= 0:
            message = "browser capture max_requests must be a positive integer"
            raise ValueError(message)
        self._recorder = recorder
        self._scope_predicate = scope_predicate
        self._capture_all_resources = capture_all_resources
        default_session_id = f"browser-{uuid.uuid4().hex}"
        safe_session_id = safe_identifier(capture_session_id or default_session_id)
        self._capture_session_id = safe_session_id or default_session_id
        self._max_requests = max_requests
        self._states: dict[int, _RequestState] = {}
        self._terminal_states: OrderedDict[int, tuple[object, _RequestState]] = OrderedDict()
        self._next_request_sequence = 0
        self._websocket_count = 0
        self._next_event_sequence = 0
        self._attached = False
        self._recorder_errors: list[str] = []

    @staticmethod
    def context_options(**options: object) -> dict[str, object]:
        return playwright_context_options(**options)

    @property
    def recorder_errors(self) -> tuple[str, ...]:
        return tuple(self._recorder_errors)

    def attach(self, context: BrowserContextLike) -> None:
        """Attach one capture instance to one fully configured context."""
        if self._attached:
            message = "browser traffic capture is already attached"
            raise RuntimeError(message)
        self._attached = True
        context.route(_ROUTE_PATTERN, self._on_route)
        try:
            context.route_web_socket(_ROUTE_PATTERN, self._on_web_socket)
        except AttributeError as exc:
            message = "browser traffic capture requires Playwright 1.48 or newer"
            raise RuntimeError(message) from exc
        context.on("request", self._on_request)
        context.on("response", self._on_response)
        context.on("requestfinished", self._on_request_finished)
        context.on("requestfailed", self._on_request_failed)

    def _on_web_socket(self, route: object) -> None:
        self._websocket_count += 1
        if self._next_request_sequence + self._websocket_count > self._max_requests:
            self._record_limit_error()
            self._close_websocket(route, "capture request limit reached")
            return
        url = _text_member(route, "url")
        allowed, reason = self._scope_decision(_http_equivalent_websocket_url(url))
        if allowed:
            _call_member(route, "connect_to_server")
            return
        self._close_websocket(route, reason or "outside authorized scope")

    @staticmethod
    def _close_websocket(route: object, reason: str) -> None:
        close = getattr(route, "close")  # noqa: B009 - object is a Playwright protocol.
        try:
            close(code=1008, reason=reason)
        except TypeError:
            close()

    def _on_route(self, route: object) -> None:
        request = _read_member(route, "request")
        state = self._state_for(request)
        if state.terminal:
            return
        if state.limit_exceeded:
            state.scope_allowed = False
            _call_member(route, "abort")
            state.terminal = True
            self._record_limit_error()
            self._finish_state(request, state)
            return
        url = _request_url(request)
        allowed, reason = self._scope_decision(url)
        state.scope_allowed = allowed

        # Scope is decided before either route action. Recorder failures cannot
        # prevent the route from being continued or aborted.
        if allowed:
            _call_member(route, "continue_")
            self._emit_request_if_ready(request, state)
            return

        _call_member(route, "abort")
        if state.captured and not state.terminal:
            self._emit(
                state,
                event_type="request_blocked",
                request=_minimal_request_metadata(request),
                scope={"allowed": False, "reason": reason or "outside authorized scope"},
            )
        state.terminal = True
        self._finish_state(request, state)

    def _on_request(self, request: object) -> None:
        state = self._state_for(request)
        if state.terminal:
            return
        state.request_seen = True
        self._emit_request_if_ready(request, state)

    def _on_response(self, response: object) -> None:
        request = _read_member(response, "request")
        state = self._state_for(request)
        if state.scope_allowed is not True or state.terminal or not state.captured:
            return
        state.request_seen = True
        self._emit_request_if_ready(request, state)
        self._emit(
            state,
            event_type="response",
            response=_response_metadata(response),
            scope={"allowed": True},
        )

    def _on_request_finished(self, request: object) -> None:
        state = self._state_for(request)
        if state.terminal:
            return
        if state.scope_allowed is True and state.captured:
            state.request_seen = True
            self._emit_request_if_ready(request, state)
            self._emit(state, event_type="requestfinished", scope={"allowed": True})
        state.terminal = True
        self._finish_state(request, state)

    def _on_request_failed(self, request: object) -> None:
        state = self._state_for(request)
        if state.terminal:
            return
        if state.scope_allowed is True and state.captured:
            state.request_seen = True
            self._emit_request_if_ready(request, state)
            failure = redact_text(_text_member(request, "failure"), max_chars=_MAX_ERROR_CHARS)
            self._emit(
                state,
                event_type="requestfailed",
                failure=failure or "request failed",
                scope={"allowed": True},
            )
        state.terminal = True
        self._finish_state(request, state)

    def _emit_request_if_ready(self, request: object, state: _RequestState) -> None:
        if (
            not state.request_seen
            or state.request_emitted
            or state.terminal
            or not state.captured
            or state.scope_allowed is not True
        ):
            return
        self._emit(
            state,
            event_type="request",
            request=_request_metadata(request),
            scope={"allowed": True},
        )
        state.request_emitted = True

    def _scope_decision(self, url: str) -> tuple[bool, str]:
        try:
            decision = self._scope_predicate(url)
        except Exception as exc:  # noqa: BLE001 - scope errors fail closed.
            return False, f"scope predicate failed: {redact_text(exc, max_chars=300)}"
        if isinstance(decision, bool):
            return decision, "" if decision else "outside authorized scope"
        try:
            allowed = bool(decision.allowed)
            reason = str(decision.reason or "")
        except Exception as exc:  # noqa: BLE001 - malformed decisions fail closed.
            return False, f"invalid scope decision: {redact_text(exc, max_chars=300)}"
        return allowed, redact_text(reason, max_chars=300)

    def _state_for(self, request: object) -> _RequestState:
        key = id(request)
        existing = self._states.get(key)
        if existing is not None:
            return existing
        terminal = self._terminal_states.get(key)
        if terminal is not None and terminal[0] is request:
            return terminal[1]

        parent_correlation_id = ""
        redirected_from = _read_member(request, "redirected_from", default=None)
        if redirected_from is not None and redirected_from is not request:
            parent_correlation_id = self._state_for(redirected_from).correlation_id

        self._next_request_sequence += 1
        sequence = self._next_request_sequence
        resource_type = _text_member(request, "resource_type").lower() or "other"
        state = _RequestState(
            correlation_id=f"{self._capture_session_id}:{sequence:06d}",
            sequence=sequence,
            captured=self._capture_all_resources
            or resource_type in DEFAULT_CAPTURED_RESOURCE_TYPES,
            parent_correlation_id=parent_correlation_id,
            limit_exceeded=sequence + self._websocket_count > self._max_requests,
        )
        self._states[key] = state
        return state

    def _finish_state(self, request: object, state: _RequestState) -> None:
        key = id(request)
        self._states.pop(key, None)
        self._terminal_states[key] = (request, state)
        self._terminal_states.move_to_end(key)
        while len(self._terminal_states) > _MAX_TERMINAL_STATES:
            self._terminal_states.popitem(last=False)

    def _record_limit_error(self) -> None:
        message = (
            f"browser capture reached its {self._max_requests}-request safety limit; "
            "additional requests were blocked"
        )
        if (
            message not in self._recorder_errors
            and len(self._recorder_errors) < _MAX_RECORDER_ERRORS
        ):
            self._recorder_errors.append(message)

    def _emit(self, state: _RequestState, *, event_type: str, **fields: object) -> None:
        self._next_event_sequence += 1
        event: dict[str, object] = {
            "schema_version": BROWSER_EVENT_SCHEMA_VERSION,
            "capture_session_id": self._capture_session_id,
            "event_sequence": self._next_event_sequence,
            "event_type": event_type,
            "correlation_id": state.correlation_id,
            "request_sequence": state.sequence,
            "parent_correlation_id": state.parent_correlation_id or None,
            **fields,
        }
        try:
            self._recorder.record_browser_event(event)
        except Exception as exc:  # noqa: BLE001 - observation must not break browsing.
            if len(self._recorder_errors) < _MAX_RECORDER_ERRORS:
                self._recorder_errors.append(redact_text(exc, max_chars=300))


def _request_metadata(request: object) -> dict[str, object]:
    headers = _raw_headers(request)
    declared_size = _request_body_size(request, headers)
    raw_body, body_size = (
        (None, declared_size)
        if declared_size is not None and declared_size > MAX_CAPTURE_BODY_BYTES
        else _request_body(request)
    )
    metadata = body_metadata(
        raw_body,
        media_type=_header_value(headers, "content-type"),
        byte_length=body_size,
    )
    return {
        **_minimal_request_metadata(request),
        "is_navigation_request": _bool_member(request, "is_navigation_request"),
        "headers": dict(redact_headers(headers)),
        "body": {
            "media_type": metadata.media_type,
            "byte_length": metadata.byte_length,
            "sha256": metadata.sha256,
            "field_names": list(metadata.field_names),
            "truncated": raw_body is None and metadata.byte_length > 0,
        },
    }


def _minimal_request_metadata(request: object) -> dict[str, object]:
    return {
        "method": _text_member(request, "method").upper() or "GET",
        "url": sanitize_url(_request_url(request)),
        "resource_type": _text_member(request, "resource_type").lower() or "other",
    }


def _response_metadata(response: object) -> dict[str, object]:
    status = _read_member(response, "status", default=None)
    return {
        "url": sanitize_url(_text_member(response, "url")),
        "status": status if isinstance(status, int) else None,
        "status_text": redact_text(_text_member(response, "status_text"), max_chars=300),
        "headers": dict(redact_headers(_raw_headers(response), response=True)),
        "from_service_worker": _bool_member(response, "from_service_worker"),
    }


def _raw_headers(value: object) -> dict[str, str]:
    headers = _read_member(value, "all_headers", default=None)
    if not isinstance(headers, Mapping):
        headers = _read_member(value, "headers", default={})
    if not isinstance(headers, Mapping):
        return {}
    return {str(key): str(item) for key, item in headers.items()}


def _request_body(request: object) -> tuple[bytes | None, int]:
    post_data = _read_member(request, "post_data", default=None)
    if isinstance(post_data, bytes):
        return (
            (post_data, len(post_data))
            if len(post_data) <= MAX_CAPTURE_BODY_BYTES
            else (None, len(post_data))
        )
    if isinstance(post_data, str):
        return _bounded_text_body(post_data)
    post_data_buffer = _read_member(request, "post_data_buffer", default=None)
    if isinstance(post_data_buffer, bytes):
        return (
            (post_data_buffer, len(post_data_buffer))
            if len(post_data_buffer) <= MAX_CAPTURE_BODY_BYTES
            else (None, len(post_data_buffer))
        )
    if isinstance(post_data_buffer, str):
        return _bounded_text_body(post_data_buffer)
    return b"", 0


def _bounded_text_body(value: str) -> tuple[bytes | None, int]:
    if len(value) <= MAX_CAPTURE_BODY_BYTES:
        encoded = value.encode("utf-8", errors="replace")
        return (
            (encoded, len(encoded))
            if len(encoded) <= MAX_CAPTURE_BODY_BYTES
            else (None, len(encoded))
        )
    byte_length = 0
    for offset in range(0, len(value), 65_536):
        byte_length += len(value[offset : offset + 65_536].encode("utf-8", errors="replace"))
    return None, byte_length


def _request_body_size(request: object, headers: Mapping[str, str]) -> int | None:
    content_length = _header_value(headers, "content-length").strip()
    if (
        len(content_length) <= _MAX_CONTENT_LENGTH_DIGITS
        and content_length.isascii()
        and content_length.isdigit()
    ):
        return int(content_length)
    sizes = _read_member(request, "sizes", default={})
    if isinstance(sizes, Mapping):
        value = sizes.get("requestBodySize")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _header_value(headers: Mapping[str, str], wanted: str) -> str:
    wanted_lower = wanted.lower()
    for name, value in headers.items():
        if str(name).lower() == wanted_lower:
            return str(value)
    return ""


def _request_url(request: object) -> str:
    return _text_member(request, "url")


def _bool_member(value: object, name: str) -> bool:
    return bool(_read_member(value, name, default=False))


def _text_member(value: object, name: str) -> str:
    result = _read_member(value, name, default="")
    return "" if result is None else str(result)


def _read_member(value: object, name: str, *, default: object = "") -> object:
    try:
        member = getattr(value, name)
    except Exception:  # noqa: BLE001 - stale Playwright handles degrade to metadata defaults.
        return default
    if callable(member):
        try:
            return member()
        except Exception:  # noqa: BLE001 - capture must survive a stale handle.
            return default
    return member


def _call_member(value: object, name: str) -> None:
    member = getattr(value, name)
    member()


def _http_equivalent_websocket_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme.casefold())
    if scheme is None:
        return value
    return urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


__all__ = [
    "BROWSER_EVENT_SCHEMA_VERSION",
    "DEFAULT_CAPTURED_RESOURCE_TYPES",
    "DEFAULT_MAX_CAPTURE_REQUESTS",
    "BrowserTrafficCapture",
    "BrowserTrafficRecorder",
    "ScopePredicate",
    "playwright_context_options",
]
