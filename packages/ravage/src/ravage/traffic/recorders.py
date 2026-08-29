"""Adapters from live browser/probe events into redacted traffic contracts."""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from .contracts import (
    CapturedHttpExchange,
    build_captured_http_exchange,
    header_requires_replay_binding,
)
from .redaction import body_metadata, redact_headers, redact_text, safe_identifier, sanitize_url

if TYPE_CHECKING:
    from .store import TrafficStore

ExchangeSink = Callable[[CapturedHttpExchange], None]

_MAX_RECORDER_ERRORS = 20
_MIN_CONTEXT_FREE_SECRET_CHARS = 12
_AUTH_COOKIE_NAME_TOKENS = frozenset(
    {"auth", "credential", "jwt", "login", "session", "sid", "token"}
)


class TrafficRecorderError(RuntimeError):
    """Raised when strict capture cannot preserve executor provenance."""


class ProbeTrafficRecorder:
    """Persist each trusted in-process ``ProbeSession`` observation safely."""

    def __init__(  # noqa: PLR0913 - recorder policy inputs stay explicit.
        self,
        store: TrafficStore,
        *,
        capture_session_id: str,
        identity_alias: str = "",
        known_secrets: Iterable[object] = (),
        on_exchange: ExchangeSink | None = None,
        error_sink: list[str] | None = None,
        source: str = "probe_session",
        strict: bool = False,
    ) -> None:
        self._store = store
        self._capture_session_id = safe_identifier(capture_session_id)
        self._identity_alias = safe_identifier(identity_alias)
        self._known_secrets: tuple[str, ...] = tuple(
            str(secret) for secret in known_secrets if str(secret)
        )
        self._url_segment_secrets: tuple[str, ...] = ()
        self._lock = threading.RLock()
        self._on_exchange = on_exchange
        self._error_sink = error_sink if error_sink is not None else []
        self._source = safe_identifier(source)
        self._strict = strict
        if not self._source:
            message = "traffic recorder source is required"
            raise TrafficRecorderError(message)

    @property
    def errors(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._error_sink)

    def set_exchange_sink(self, sink: ExchangeSink | None) -> None:
        """Bind a trusted consumer after lifecycle/state initialization."""
        with self._lock:
            self._on_exchange = sink

    def register_secret_values(self, values: Iterable[object]) -> None:
        """Add runtime-issued values before the next exchange is serialized."""
        with self._lock:
            secrets = {str(value) for value in self._known_secrets if str(value)}
            secrets.update(str(value) for value in values if str(value))
            self._known_secrets = tuple(sorted(secrets, key=len, reverse=True))

    def register_url_segment_secret_values(self, values: Iterable[object]) -> None:
        """Add short credentials that are safe to redact only as whole URL segments."""
        with self._lock:
            secrets = {str(value) for value in self._url_segment_secrets if str(value)}
            secrets.update(str(value) for value in values if str(value))
            self._url_segment_secrets = tuple(sorted(secrets, key=len, reverse=True))

    def __call__(self, event: dict[str, object]) -> CapturedHttpExchange | None:
        try:
            with self._lock:
                return self._record(event)
        except Exception as exc:  # Probes must finish and surface capture loss.
            with self._lock:
                detail = redact_text(exc, known_secrets=self._known_secrets, max_chars=300)
                if len(self._error_sink) < _MAX_RECORDER_ERRORS:
                    self._error_sink.append(detail)
            if self._strict:
                raise TrafficRecorderError(detail) from exc
            return None

    def _record(self, event: dict[str, object]) -> CapturedHttpExchange:
        disposition = str(event.get("disposition") or "blocked")
        sent = disposition == "sent"
        reason = str(event.get("reason") or "")
        request_headers = _mapping(event.get("request_headers")) if sent else {}
        request_body = event.get("request_body") if sent else None
        response_headers = _mapping(event.get("response_headers"))
        # A response can issue a credential and reflect it into Location or the
        # final URL in the very same observation. Learn cookie values before any
        # field from that exchange is made durable.
        issued_cookies = _response_cookie_values(response_headers)
        issued_contextual = tuple(
            value for name, value in issued_cookies if _cookie_name_is_auth_material(name)
        )
        issued_context_free = tuple(
            value for _name, value in issued_cookies if len(value) >= _MIN_CONTEXT_FREE_SECRET_CHARS
        )
        response_url_secrets = (*self._url_segment_secrets, *issued_contextual)
        response_url = _redact_url_segment_secrets(
            str(event.get("response_url") or ""),
            secrets=response_url_secrets,
        )
        response_error = redact_text(
            event.get("error") or (reason if not sent else ""),
            known_secrets=(*self._known_secrets, *issued_context_free),
        )
        response_error = _redact_contextual_secret_tokens(
            response_error,
            secrets=response_url_secrets,
        )
        safe_response_headers = dict(response_headers)
        for name, value in response_headers.items():
            if str(name).casefold() == "location":
                safe_response_headers[str(name)] = _redact_url_segment_secrets(
                    sanitize_url(value, known_secrets=issued_context_free),
                    secrets=response_url_secrets,
                )
        metadata = body_metadata(
            request_body,
            media_type=_header(request_headers, "content-type"),
        )
        url = _redact_url_segment_secrets(
            str(event.get("url") or ""),
            secrets=self._url_segment_secrets,
        )
        unresolved = unresolved_slots(
            url=url,
            headers=request_headers,
            body_bytes=metadata.byte_length,
            body_fields=metadata.field_names,
        )
        exchange = build_captured_http_exchange(
            capture_session_id=self._capture_session_id,
            source=self._source,
            source_observation_id=str(event.get("source_observation_id") or ""),
            identity_alias=(
                safe_identifier(str(event.get("identity_alias") or ""))
                if "identity_alias" in event
                else self._identity_alias
            ),
            method=str(event.get("method") or "GET"),
            url=url,
            resource_type=str(event.get("resource_type") or "http"),
            request_headers=request_headers,
            request_body=request_body,
            request_sent=sent,
            response_status=_optional_int(event.get("response_status")),
            response_final_url=sanitize_url(
                response_url,
                known_secrets=issued_context_free,
            ),
            response_headers=safe_response_headers,
            response_body=event.get("response_body") if sent else None,
            response_error=response_error,
            response_elapsed_ms=_optional_int(event.get("elapsed_ms")),
            scope_decision="allowed" if sent else "blocked",
            scope_reason=str(event.get("scope_reason") or reason),
            unresolved_slots=unresolved,
            known_secrets=self._known_secrets,
        )
        self.register_secret_values(issued_context_free)
        self.register_url_segment_secret_values(issued_contextual)
        stored = self._store.append_exchange(exchange)
        if self._on_exchange is not None:
            self._on_exchange(stored)
        return stored


def _response_cookie_values(headers: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    values: list[tuple[str, str]] = []
    for name, raw_value in headers.items():
        if str(name).casefold() != "set-cookie":
            continue
        for cookie_line in str(raw_value).splitlines():
            parsed = SimpleCookie()
            try:
                parsed.load(cookie_line)
            except CookieError:
                continue
            values.extend(
                (str(morsel.key), morsel.value) for morsel in parsed.values() if morsel.value
            )
    return tuple(values)


def _cookie_name_is_auth_material(name: str) -> bool:
    tokens = frozenset(part for part in re.split(r"[^a-z0-9]+", name.casefold()) if part)
    compact = "".join(tokens)
    return bool(tokens & _AUTH_COOKIE_NAME_TOKENS) or compact.endswith(
        ("auth", "jwt", "sessionid", "sessid", "sid", "token")
    )


def _redact_url_segment_secrets(value: str, *, secrets: Iterable[str]) -> str:
    if not value:
        return ""
    exact = frozenset(secret for secret in secrets if secret)
    if not exact:
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    path = "/".join(
        ":redacted" if unquote(segment) in exact else segment for segment in parsed.path.split("/")
    )
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def _redact_contextual_secret_tokens(value: str, *, secrets: Iterable[str]) -> str:
    redacted = value
    for secret in sorted({secret for secret in secrets if secret}, key=len, reverse=True):
        redacted = re.sub(
            rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
            "[REDACTED]",
            redacted,
        )
    return redacted


@dataclass(slots=True)
class _BrowserExchangeState:
    source_observation_id: str
    request: dict[str, object] = field(default_factory=dict)
    response: dict[str, object] = field(default_factory=dict)
    scope: dict[str, object] = field(default_factory=dict)
    terminal: str = ""
    failure: str = ""


class BrowserExchangeRecorder:
    """Correlate sanitized Playwright lifecycle events and persist once."""

    def __init__(
        self,
        store: TrafficStore,
        *,
        identity_alias: str = "",
        on_exchange: ExchangeSink | None = None,
    ) -> None:
        self._store = store
        self._identity_alias = safe_identifier(identity_alias)
        self._on_exchange = on_exchange
        self._states: dict[str, _BrowserExchangeState] = {}
        self._lock = threading.RLock()

    def record_browser_event(self, event: Mapping[str, object], /) -> None:
        event_type = str(event.get("event_type") or "")
        source_id = str(event.get("correlation_id") or "")
        if not source_id:
            return
        with self._lock:
            state = self._states.setdefault(source_id, _BrowserExchangeState(source_id))
            if event_type in {"request", "request_blocked"}:
                state.request = dict(_mapping(event.get("request")))
            if event_type == "response":
                state.response = dict(_mapping(event.get("response")))
            state.scope = dict(_mapping(event.get("scope"))) or state.scope
            if event_type == "request_blocked":
                state.terminal = event_type
                self._persist(event, state)
            elif event_type in {"requestfinished", "requestfailed"}:
                state.terminal = event_type
                state.failure = str(event.get("failure") or "")
                self._persist(event, state)

    def finalize_pending(self) -> int:
        """Persist requests left incomplete when the operator closes the browser."""
        with self._lock:
            pending = list(self._states.items())
            for source_id, state in pending:
                if state.request:
                    state.terminal = "capture_closed"
                    self._persist({}, state)
                else:
                    self._states.pop(source_id, None)
            return len(pending)

    def _persist(
        self,
        event: Mapping[str, object],
        state: _BrowserExchangeState,
    ) -> None:
        request = state.request
        body = _mapping(request.get("body"))
        headers = _mapping(request.get("headers"))
        response = state.response
        response_body = _mapping(response.get("body"))
        allowed = bool(state.scope.get("allowed"))
        sent = state.terminal != "request_blocked" and allowed
        url = str(request.get("url") or "")
        capture_session_id = str(event.get("capture_session_id") or "")
        if not capture_session_id:
            capture_session_id = state.source_observation_id.partition(":")[0]
        exchange = CapturedHttpExchange.create(
            capture_session_id=capture_session_id or "browser",
            source="browser",
            source_observation_id=state.source_observation_id,
            identity_alias=self._identity_alias,
            method=str(request.get("method") or "GET"),
            url=url,
            resource_type=str(request.get("resource_type") or "other"),
            navigation=bool(request.get("is_navigation_request")),
            request_headers=headers,
            request_body_media_type=str(body.get("media_type") or ""),
            request_body_bytes=_int(body.get("byte_length")),
            request_body_sha256=str(body.get("sha256") or ""),
            request_body_field_names=_strings(body.get("field_names")),
            request_sent=sent,
            response_status=_optional_int(response.get("status")),
            response_final_url=str(response.get("url") or ""),
            response_headers=_mapping(response.get("headers")),
            response_body_observed=False,
            response_body_bytes=_int(response_body.get("byte_length")),
            response_body_sha256=str(response_body.get("sha256") or ""),
            response_error=state.failure or ("capture closed before completion" if sent else ""),
            scope_decision="allowed" if allowed else "blocked",
            scope_reason=str(state.scope.get("reason") or ""),
            unresolved_slots=unresolved_slots(
                url=url,
                headers=headers,
                body_bytes=_int(body.get("byte_length")),
                body_fields=_strings(body.get("field_names")),
            ),
        )
        stored = self._store.append_exchange(exchange)
        self._states.pop(state.source_observation_id, None)
        if self._on_exchange is not None:
            self._on_exchange(stored)


def unresolved_slots(
    *,
    url: str,
    headers: Mapping[str, object],
    body_bytes: int,
    body_fields: Iterable[object],
) -> tuple[str, ...]:
    """Name values deliberately omitted from a durable request template."""
    slots: set[str] = set()
    parsed = urlsplit(url)
    for index, segment in enumerate(parsed.path.split("/")):
        if unquote(segment) in {":id", ":redacted"}:
            slots.add(f"path.{index}")
    query_names = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
    totals = {name: query_names.count(name) for name in set(query_names)}
    seen: dict[str, int] = {}
    for name in query_names:
        index = seen.get(name, 0)
        seen[name] = index + 1
        suffix = f"[{index}]" if totals[name] > 1 else ""
        slots.add(f"query.{name}{suffix}")
    for name, value in redact_headers(headers):
        if header_requires_replay_binding(name, value):
            slots.add(f"header.{name}")
    del body_fields
    if body_bytes:
        # Field names remain useful structural metadata, but values, order,
        # duplicate keys, JSON types, nesting, and binary bytes were omitted.
        # Only a caller-provided opaque body can preserve request semantics.
        slots.add("body")
    return tuple(sorted(slots))


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items()}


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value if str(item))


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _header(headers: Mapping[str, object], wanted: str) -> str:
    for name, value in headers.items():
        if name.casefold() == wanted.casefold():
            return str(value)
    return ""


__all__ = [
    "BrowserExchangeRecorder",
    "ExchangeSink",
    "ProbeTrafficRecorder",
    "TrafficRecorderError",
    "unresolved_slots",
]
