# ruff: noqa: EM101, EM102, TRY003
"""Immutable, versioned contracts for safe HTTP capture and replay metadata."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from urllib.parse import parse_qsl, unquote, urlsplit

from .redaction import (
    REDACTED,
    HeaderInput,
    body_metadata,
    redact_headers,
    redact_text,
    safe_field_names,
    safe_identifier,
    sanitize_url,
    semantic_url_shape,
)

CAPTURED_HTTP_EXCHANGE_SCHEMA = "ravage.captured-http-exchange.v1"
REQUEST_CONTRACT_SCHEMA = "ravage.request-contract.v1"
REPLAY_RECEIPT_SCHEMA = "ravage.replay-receipt.v1"
TRAFFIC_SCHEMA_VERSION = 1

type HeaderPairs = tuple[tuple[str, str], ...]

_HTTP_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")
_EXCHANGE_ID_RE = re.compile(r"^rq_[0-9]{4,}$")
_REPLAY_ID_RE = re.compile(r"^rp_[0-9]{4,}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPLAYABILITY = frozenset({"safe", "requires_authorization", "not_replayable"})
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_REQUIRED_REPLAY_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "idempotency-key",
        "if-match",
        "if-none-match",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-http-method-override",
    }
)
_AUTOMATIC_REPLAY_HEADERS = frozenset(
    {
        "accept-encoding",
        "accept-language",
        "connection",
        "content-length",
        "dnt",
        "host",
        "priority",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "upgrade-insecure-requests",
        "user-agent",
    }
)
_ROUTING_OVERRIDE_HEADERS = frozenset(
    {
        "destination",
        "forwarded",
        "if",
        "x-host",
        "x-http-host-override",
        "x-original-uri",
        "x-original-url",
        "x-request-uri",
        "x-rewrite-uri",
        "x-rewrite-url",
    }
)
_STATE_OVERRIDE_HEADERS = frozenset(
    {
        "x-http-method",
        "x-http-method-override",
        "x-method-override",
    }
)
_SLOT_NAME_RE = re.compile(
    r"^(?:path\.[0-9]+|query\.[A-Za-z0-9_.\[\]-]+|"
    r"header\.[A-Za-z0-9-]+|body)$"
)
_MAX_REASON_CHARS = 1_024
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599


class TrafficContractError(ValueError):
    """Raised when a persisted traffic contract is invalid or has been altered."""


@dataclass(frozen=True, slots=True)
class CapturedHttpExchange:
    """One redacted HTTP exchange suitable for private durable run artifacts."""

    exchange_id: str
    sequence: int
    capture_session_id: str
    source: str
    source_observation_id: str
    identity_alias: str
    request_method: str
    request_url: str
    request_resource_type: str
    request_navigation: bool
    request_headers: HeaderPairs
    request_body_media_type: str
    request_body_bytes: int
    request_body_sha256: str
    request_body_field_names: tuple[str, ...]
    request_sent: bool
    response_status: int | None
    response_final_url: str
    response_headers: HeaderPairs
    response_body_observed: bool
    response_body_bytes: int
    response_body_sha256: str
    response_error: str
    response_elapsed_ms: int | None
    scope_decision: str
    scope_reason: str
    captured_at: str
    replayability: str
    unresolved_slots: tuple[str, ...]
    semantic_fingerprint: str
    schema_version: int = TRAFFIC_SCHEMA_VERSION

    def __post_init__(self) -> None:  # noqa: C901, PLR0912, PLR0915 - centralized invariants.
        _validate_schema_version(self.schema_version)
        _validate_store_identity(
            value=self.exchange_id,
            sequence=self.sequence,
            pattern=_EXCHANGE_ID_RE,
            label="exchange",
        )
        _validate_method(self.request_method)
        _validate_status(self.response_status)
        _validate_non_negative(self.request_body_bytes, "request body bytes")
        _validate_non_negative(self.response_body_bytes, "response body bytes")
        _validate_optional_non_negative(self.response_elapsed_ms, "response elapsed milliseconds")
        _validate_digest(self.request_body_sha256, byte_length=self.request_body_bytes)
        _validate_digest(self.response_body_sha256, byte_length=self.response_body_bytes)
        _require_canonical(
            self.capture_session_id
            == _required_identifier(self.capture_session_id, "capture session ID"),
            "capture session ID",
        )
        _require_canonical(
            self.source == _required_identifier(self.source, "capture source"),
            "capture source",
        )
        _require_canonical(
            self.source_observation_id == safe_identifier(self.source_observation_id),
            "source observation ID",
        )
        _require_canonical(
            self.identity_alias == safe_identifier(self.identity_alias),
            "identity alias",
        )
        _require_canonical(
            self.request_resource_type == safe_identifier(self.request_resource_type, max_chars=64),
            "request resource type",
        )
        _require_canonical(
            isinstance(self.request_navigation, bool),
            "request navigation",
        )
        _require_canonical(isinstance(self.request_sent, bool), "request sent")
        _require_canonical(isinstance(self.response_body_observed, bool), "response body observed")
        if not self.response_body_observed and self.response_body_bytes:
            raise TrafficContractError("an unobserved response body cannot have a byte length")
        _require_canonical(
            self.request_headers == redact_headers(self.request_headers),
            "request headers",
        )
        _require_canonical(
            self.response_headers == redact_headers(self.response_headers, response=True),
            "response headers",
        )
        _require_canonical(
            self.request_body_media_type == _media_type(self.request_body_media_type),
            "request body media type",
        )
        _require_canonical(
            self.request_body_field_names == safe_field_names(self.request_body_field_names),
            "request body field names",
        )
        _require_canonical(
            self.response_error == redact_text(self.response_error, max_chars=_MAX_REASON_CHARS),
            "response error",
        )
        _require_canonical(
            self.scope_decision == _required_identifier(self.scope_decision, "scope decision"),
            "scope decision",
        )
        _require_canonical(
            self.scope_reason == redact_text(self.scope_reason, max_chars=_MAX_REASON_CHARS),
            "scope reason",
        )
        _require_canonical(self.captured_at == _timestamp(self.captured_at), "capture timestamp")
        _require_canonical(
            self.unresolved_slots == _slot_names(self.unresolved_slots),
            "unresolved slots",
        )
        required_slots = _derived_unresolved_slots(
            url=self.request_url,
            headers=self.request_headers,
            body_bytes=self.request_body_bytes,
            replayability=self.replayability,
        )
        if required_slots != self.unresolved_slots:
            raise TrafficContractError("captured replay slots do not match the request template")
        if self.replayability not in _REPLAYABILITY:
            raise TrafficContractError("invalid replayability")
        if self.replayability == "safe" and self.request_method not in _SAFE_METHODS:
            raise TrafficContractError("side-effecting requests cannot be marked safe to replay")
        if (
            not _is_anonymous_identity(self.identity_alias)
            and self.replayability != "not_replayable"
        ):
            raise TrafficContractError(
                "identity-bound requests cannot be replayed without managed authentication"
            )
        if (
            self.request_body_bytes
            and not _body_can_bind_as_text(self.request_body_media_type)
            and self.replayability != "not_replayable"
        ):
            raise TrafficContractError("opaque or multipart bodies cannot be replayed safely")
        if (
            self.request_body_bytes
            and _has_content_encoding(self.request_headers)
            and self.replayability != "not_replayable"
        ):
            raise TrafficContractError("content-encoded bodies cannot be replayed safely")
        if (
            any(_is_routing_override_header(name) and value for name, value in self.request_headers)
            and self.replayability != "not_replayable"
        ):
            raise TrafficContractError("routing override headers cannot be replayed safely")
        if (
            any(_is_state_override_header(name) and value for name, value in self.request_headers)
            and self.replayability == "safe"
        ):
            raise TrafficContractError("method override headers require state-change authorization")
        if self.scope_decision == "blocked" and self.request_sent:
            raise TrafficContractError("a scope-blocked request cannot be marked sent")
        if self.response_status is not None and not self.request_sent:
            raise TrafficContractError("a response status requires a sent request")
        if self.request_url != sanitize_url(self.request_url):
            raise TrafficContractError("request URL is not in persisted-safe form")
        if self.response_final_url and self.response_final_url != sanitize_url(
            self.response_final_url
        ):
            raise TrafficContractError("response URL is not in persisted-safe form")
        expected = _request_fingerprint(
            method=self.request_method,
            url=self.request_url,
            header_names=(name for name, _value in self.request_headers),
            body_media_type=self.request_body_media_type,
            body_field_names=self.request_body_field_names,
        )
        if self.semantic_fingerprint != expected:
            raise TrafficContractError("captured exchange semantic fingerprint mismatch")

    @classmethod
    def create(  # noqa: PLR0913 - capture schema mirrors the request boundary.
        cls,
        *,
        capture_session_id: str,
        source: str,
        method: str,
        url: str,
        source_observation_id: str = "",
        identity_alias: str = "",
        resource_type: str = "",
        navigation: bool = False,
        request_headers: HeaderInput | None = None,
        request_body_media_type: str = "",
        request_body_bytes: int = 0,
        request_body_sha256: str = "",
        request_body_field_names: Iterable[object] = (),
        request_sent: bool = False,
        response_status: int | None = None,
        response_final_url: str = "",
        response_headers: HeaderInput | None = None,
        response_body_observed: bool = True,
        response_body_bytes: int = 0,
        response_body_sha256: str = "",
        response_error: str = "",
        response_elapsed_ms: int | None = None,
        scope_decision: str = "not_evaluated",
        scope_reason: str = "",
        captured_at: str | datetime | None = None,
        replayability: str = "",
        unresolved_slots: Iterable[object] = (),
        known_secrets: Iterable[object] = (),
        exchange_id: str = "",
        sequence: int = 0,
    ) -> CapturedHttpExchange:
        secrets = tuple(known_secrets)
        normalized_method = _method(method)
        normalized_url = sanitize_url(url, known_secrets=secrets)
        normalized_request_headers = redact_headers(
            request_headers,
            known_secrets=secrets,
        )
        custom_host = _has_custom_host_header(request_headers, normalized_url)
        # urllib generates Host from the already scope-checked URL. Persisting or
        # accepting a replacement Host would let replay cross virtual-host scope.
        normalized_request_headers = tuple(
            (name, value) for name, value in normalized_request_headers if name != "host"
        )
        normalized_response_headers = redact_headers(
            response_headers,
            response=True,
            known_secrets=secrets,
        )
        normalized_body_fields = safe_field_names(
            request_body_field_names,
            known_secrets=secrets,
        )
        normalized_media_type = _media_type(request_body_media_type)
        normalized_identity_alias = safe_identifier(identity_alias, known_secrets=secrets)
        fingerprint = _request_fingerprint(
            method=normalized_method,
            url=normalized_url,
            header_names=(name for name, _value in normalized_request_headers),
            body_media_type=normalized_media_type,
            body_field_names=normalized_body_fields,
        )
        normalized_replayability = replayability.strip().casefold() or _default_replayability(
            normalized_method,
            request_sent=request_sent,
            scope_decision=scope_decision,
        )
        if request_body_bytes and not _body_can_bind_as_text(normalized_media_type):
            normalized_replayability = "not_replayable"
        if request_body_bytes and _has_content_encoding(normalized_request_headers):
            normalized_replayability = "not_replayable"
        if custom_host or any(
            _is_routing_override_header(name) and value
            for name, value in normalized_request_headers
        ):
            normalized_replayability = "not_replayable"
        elif not _is_anonymous_identity(normalized_identity_alias):
            # Live credentials are deliberately absent from captures. Sending
            # this template through an anonymous replay lane would silently
            # change identity, so require a future managed-auth replay path.
            normalized_replayability = "not_replayable"
        elif normalized_replayability != "not_replayable" and any(
            _is_state_override_header(name) and value for name, value in normalized_request_headers
        ):
            normalized_replayability = "requires_authorization"
        del unresolved_slots
        normalized_slots = _slot_names(
            _derived_unresolved_slots(
                url=normalized_url,
                headers=normalized_request_headers,
                body_bytes=request_body_bytes,
                replayability=normalized_replayability,
            ),
            known_secrets=secrets,
        )
        return cls(
            exchange_id=exchange_id,
            sequence=sequence,
            capture_session_id=_required_identifier(
                capture_session_id,
                "capture session ID",
                known_secrets=secrets,
            ),
            source=_required_identifier(source, "capture source", known_secrets=secrets),
            source_observation_id=safe_identifier(
                source_observation_id,
                known_secrets=secrets,
            ),
            identity_alias=normalized_identity_alias,
            request_method=normalized_method,
            request_url=normalized_url,
            request_resource_type=safe_identifier(
                resource_type,
                max_chars=64,
                known_secrets=secrets,
            ),
            request_navigation=bool(navigation),
            request_headers=normalized_request_headers,
            request_body_media_type=normalized_media_type,
            request_body_bytes=request_body_bytes,
            request_body_sha256=_normalized_digest(
                request_body_sha256,
                byte_length=request_body_bytes,
            ),
            request_body_field_names=normalized_body_fields,
            request_sent=bool(request_sent),
            response_status=response_status,
            response_final_url=(
                sanitize_url(response_final_url, known_secrets=secrets)
                if response_final_url
                else ""
            ),
            response_headers=normalized_response_headers,
            response_body_observed=bool(response_body_observed),
            response_body_bytes=response_body_bytes,
            response_body_sha256=_normalized_digest(
                response_body_sha256,
                byte_length=response_body_bytes,
            ),
            response_error=redact_text(
                response_error,
                known_secrets=secrets,
                max_chars=_MAX_REASON_CHARS,
            ),
            response_elapsed_ms=response_elapsed_ms,
            scope_decision=_required_identifier(scope_decision, "scope decision"),
            scope_reason=redact_text(
                scope_reason,
                known_secrets=secrets,
                max_chars=_MAX_REASON_CHARS,
            ),
            captured_at=_timestamp(captured_at),
            replayability=normalized_replayability,
            unresolved_slots=normalized_slots,
            semantic_fingerprint=fingerprint,
        )

    def with_store_identity(self, *, exchange_id: str, sequence: int) -> CapturedHttpExchange:
        """Return the same immutable exchange with its store-assigned identity."""
        return replace(self, exchange_id=exchange_id, sequence=sequence)

    def to_json(self) -> dict[str, object]:
        return {
            "schema": CAPTURED_HTTP_EXCHANGE_SCHEMA,
            "version": self.schema_version,
            "exchange_id": self.exchange_id,
            "sequence": self.sequence,
            "capture_session_id": self.capture_session_id,
            "source": self.source,
            "source_observation_id": self.source_observation_id,
            "identity_alias": self.identity_alias,
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "resource_type": self.request_resource_type,
                "navigation": self.request_navigation,
                "headers": _headers_json(self.request_headers),
                "body": {
                    "media_type": self.request_body_media_type,
                    "bytes": self.request_body_bytes,
                    "sha256": self.request_body_sha256,
                    "field_names": list(self.request_body_field_names),
                },
                "sent": self.request_sent,
            },
            "response": {
                "status": self.response_status,
                "final_url": self.response_final_url,
                "headers": _headers_json(self.response_headers),
                "body": {
                    "observed": self.response_body_observed,
                    "bytes": self.response_body_bytes,
                    "sha256": self.response_body_sha256,
                },
                "error": self.response_error,
                "elapsed_ms": self.response_elapsed_ms,
            },
            "scope": {"decision": self.scope_decision, "reason": self.scope_reason},
            "captured_at": self.captured_at,
            "replayability": self.replayability,
            "unresolved_slots": list(self.unresolved_slots),
            "semantic_fingerprint": self.semantic_fingerprint,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> CapturedHttpExchange:
        _require_schema(payload, CAPTURED_HTTP_EXCHANGE_SCHEMA)
        request = _mapping(payload.get("request"), "request")
        response = _mapping(payload.get("response"), "response")
        request_body = _mapping(request.get("body"), "request body")
        response_body = _mapping(response.get("body"), "response body")
        scope = _mapping(payload.get("scope"), "scope")
        raw_unresolved_slots = _string_sequence(payload.get("unresolved_slots"))
        exchange = cls.create(
            exchange_id=str(payload.get("exchange_id") or ""),
            sequence=_integer(payload.get("sequence"), "sequence"),
            capture_session_id=str(payload.get("capture_session_id") or ""),
            source=str(payload.get("source") or ""),
            source_observation_id=str(payload.get("source_observation_id") or ""),
            identity_alias=str(payload.get("identity_alias") or ""),
            method=str(request.get("method") or ""),
            url=str(request.get("url") or ""),
            resource_type=str(request.get("resource_type") or ""),
            navigation=_boolean(request.get("navigation"), "request navigation"),
            request_headers=_headers_from_json(request.get("headers")),
            request_body_media_type=str(request_body.get("media_type") or ""),
            request_body_bytes=_integer(request_body.get("bytes"), "request body bytes"),
            request_body_sha256=str(request_body.get("sha256") or ""),
            request_body_field_names=_string_sequence(request_body.get("field_names")),
            request_sent=_boolean(request.get("sent"), "request sent"),
            response_status=_optional_integer(response.get("status"), "response status"),
            response_final_url=str(response.get("final_url") or ""),
            response_headers=_headers_from_json(response.get("headers")),
            response_body_observed=_boolean(
                response_body.get("observed"),
                "response body observed",
            ),
            response_body_bytes=_integer(response_body.get("bytes"), "response body bytes"),
            response_body_sha256=str(response_body.get("sha256") or ""),
            response_error=str(response.get("error") or ""),
            response_elapsed_ms=_optional_integer(
                response.get("elapsed_ms"),
                "response elapsed milliseconds",
            ),
            scope_decision=str(scope.get("decision") or ""),
            scope_reason=str(scope.get("reason") or ""),
            captured_at=str(payload.get("captured_at") or ""),
            replayability=str(payload.get("replayability") or ""),
            unresolved_slots=raw_unresolved_slots,
        )
        if raw_unresolved_slots != exchange.unresolved_slots:
            raise TrafficContractError("captured replay slots are not in canonical form")
        if str(payload.get("semantic_fingerprint") or "") != exchange.semantic_fingerprint:
            raise TrafficContractError("captured exchange semantic fingerprint mismatch")
        return exchange


@dataclass(frozen=True, slots=True)
class RequestContract:
    """Aggregated request shape learned from one or more safe captures."""

    semantic_fingerprint: str
    method: str
    url_shape: str
    request_header_names: tuple[str, ...]
    request_body_media_type: str
    request_body_field_names: tuple[str, ...]
    resource_types: tuple[str, ...]
    navigation_observed: bool
    replayability: str
    unresolved_slots: tuple[str, ...]
    observation_count: int
    sources: tuple[str, ...]
    status_codes: tuple[int, ...]
    scope_decisions: tuple[str, ...]
    first_seen_at: str
    last_seen_at: str
    schema_version: int = TRAFFIC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        _validate_method(self.method)
        _validate_non_negative(self.observation_count, "observation count")
        if self.observation_count == 0:
            raise TrafficContractError("request contract must have at least one observation")
        if self.replayability not in _REPLAYABILITY:
            raise TrafficContractError("invalid replayability")
        _require_canonical(self.url_shape == semantic_url_shape(self.url_shape), "URL shape")
        _require_canonical(
            self.request_header_names == _header_name_sequence(self.request_header_names),
            "request header names",
        )
        _require_canonical(
            self.request_body_media_type == _media_type(self.request_body_media_type),
            "request body media type",
        )
        _require_canonical(
            self.request_body_field_names == safe_field_names(self.request_body_field_names),
            "request body field names",
        )
        _require_canonical(
            self.resource_types == _safe_identifier_sequence(self.resource_types, max_chars=64),
            "resource types",
        )
        _require_canonical(
            isinstance(self.navigation_observed, bool),
            "navigation observed",
        )
        _require_canonical(
            self.unresolved_slots == _slot_names(self.unresolved_slots),
            "unresolved slots",
        )
        _require_canonical(
            self.sources == _safe_identifier_sequence(self.sources),
            "capture sources",
        )
        _require_canonical(
            self.status_codes == tuple(sorted(set(self.status_codes))),
            "status codes",
        )
        for status in self.status_codes:
            _validate_status(status)
        _require_canonical(
            self.scope_decisions == _safe_identifier_sequence(self.scope_decisions),
            "scope decisions",
        )
        _require_canonical(
            self.first_seen_at == _timestamp(self.first_seen_at),
            "first-seen timestamp",
        )
        _require_canonical(
            self.last_seen_at == _timestamp(self.last_seen_at),
            "last-seen timestamp",
        )
        if self.first_seen_at > self.last_seen_at:
            raise TrafficContractError("request contract timestamps are out of order")
        expected = _request_fingerprint(
            method=self.method,
            url=self.url_shape,
            header_names=self.request_header_names,
            body_media_type=self.request_body_media_type,
            body_field_names=self.request_body_field_names,
        )
        if self.semantic_fingerprint != expected:
            raise TrafficContractError("request contract semantic fingerprint mismatch")

    @classmethod
    def from_exchange(cls, exchange: CapturedHttpExchange) -> RequestContract:
        return cls(
            semantic_fingerprint=exchange.semantic_fingerprint,
            method=exchange.request_method,
            url_shape=semantic_url_shape(exchange.request_url),
            request_header_names=_header_names(exchange.request_headers),
            request_body_media_type=exchange.request_body_media_type,
            request_body_field_names=exchange.request_body_field_names,
            resource_types=_nonempty_sorted((exchange.request_resource_type,)),
            navigation_observed=exchange.request_navigation,
            replayability=exchange.replayability,
            unresolved_slots=exchange.unresolved_slots,
            observation_count=1,
            sources=(exchange.source,),
            status_codes=(() if exchange.response_status is None else (exchange.response_status,)),
            scope_decisions=(exchange.scope_decision,),
            first_seen_at=exchange.captured_at,
            last_seen_at=exchange.captured_at,
        )

    def merge(self, other: RequestContract) -> RequestContract:
        """Combine observations of the same semantic request shape."""
        if self.semantic_fingerprint != other.semantic_fingerprint:
            raise TrafficContractError("cannot merge different request contracts")
        return replace(
            self,
            resource_types=_nonempty_sorted((*self.resource_types, *other.resource_types)),
            navigation_observed=self.navigation_observed or other.navigation_observed,
            replayability=_most_restrictive_replayability(
                self.replayability,
                other.replayability,
            ),
            unresolved_slots=_slot_names((*self.unresolved_slots, *other.unresolved_slots)),
            observation_count=self.observation_count + other.observation_count,
            sources=_nonempty_sorted((*self.sources, *other.sources)),
            status_codes=tuple(sorted({*self.status_codes, *other.status_codes})),
            scope_decisions=_nonempty_sorted((*self.scope_decisions, *other.scope_decisions)),
            first_seen_at=min(self.first_seen_at, other.first_seen_at),
            last_seen_at=max(self.last_seen_at, other.last_seen_at),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "schema": REQUEST_CONTRACT_SCHEMA,
            "version": self.schema_version,
            "semantic_fingerprint": self.semantic_fingerprint,
            "method": self.method,
            "url_shape": self.url_shape,
            "request_header_names": list(self.request_header_names),
            "request_body": {
                "media_type": self.request_body_media_type,
                "field_names": list(self.request_body_field_names),
            },
            "resource_types": list(self.resource_types),
            "navigation_observed": self.navigation_observed,
            "replayability": self.replayability,
            "unresolved_slots": list(self.unresolved_slots),
            "observation_count": self.observation_count,
            "sources": list(self.sources),
            "status_codes": list(self.status_codes),
            "scope_decisions": list(self.scope_decisions),
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RequestContract:
        _require_schema(payload, REQUEST_CONTRACT_SCHEMA)
        body = _mapping(payload.get("request_body"), "request body")
        contract = cls(
            semantic_fingerprint=str(payload.get("semantic_fingerprint") or ""),
            method=_method(str(payload.get("method") or "")),
            url_shape=semantic_url_shape(payload.get("url_shape") or ""),
            request_header_names=_header_name_sequence(
                _string_sequence(payload.get("request_header_names"))
            ),
            request_body_media_type=_media_type(body.get("media_type") or ""),
            request_body_field_names=safe_field_names(_string_sequence(body.get("field_names"))),
            resource_types=_nonempty_sorted(_string_sequence(payload.get("resource_types"))),
            navigation_observed=_boolean(
                payload.get("navigation_observed"),
                "navigation observed",
            ),
            replayability=str(payload.get("replayability") or "").casefold(),
            unresolved_slots=_slot_names(_string_sequence(payload.get("unresolved_slots"))),
            observation_count=_integer(payload.get("observation_count"), "observation count"),
            sources=_nonempty_sorted(_string_sequence(payload.get("sources"))),
            status_codes=tuple(
                sorted(
                    {
                        _integer(value, "status code")
                        for value in _object_sequence(payload.get("status_codes"))
                    }
                )
            ),
            scope_decisions=_nonempty_sorted(_string_sequence(payload.get("scope_decisions"))),
            first_seen_at=_timestamp(str(payload.get("first_seen_at") or "")),
            last_seen_at=_timestamp(str(payload.get("last_seen_at") or "")),
        )
        for status in contract.status_codes:
            _validate_status(status)
        return contract


@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    """Secret-free receipt proving how a captured request was replayed."""

    replay_id: str
    sequence: int
    source_exchange_id: str
    capture_session_id: str
    identity_alias: str
    request_semantic_fingerprint: str
    request_method: str
    request_url: str
    mutation_slots: tuple[str, ...]
    side_effect_authorized: bool
    request_sent: bool
    response_status: int | None
    response_final_url: str
    response_body_bytes: int
    response_body_sha256: str
    response_error: str
    response_elapsed_ms: int | None
    scope_decision: str
    scope_reason: str
    outcome: str
    replayed_at: str
    unresolved_slots: tuple[str, ...]
    semantic_fingerprint: str
    schema_version: int = TRAFFIC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version)
        _validate_store_identity(
            value=self.replay_id,
            sequence=self.sequence,
            pattern=_REPLAY_ID_RE,
            label="replay",
        )
        if not _EXCHANGE_ID_RE.fullmatch(self.source_exchange_id):
            raise TrafficContractError("replay source exchange ID is invalid")
        _validate_fingerprint(self.request_semantic_fingerprint)
        _validate_method(self.request_method)
        _validate_status(self.response_status)
        _validate_non_negative(self.response_body_bytes, "response body bytes")
        _validate_digest(self.response_body_sha256, byte_length=self.response_body_bytes)
        _validate_optional_non_negative(self.response_elapsed_ms, "response elapsed milliseconds")
        _require_canonical(
            self.capture_session_id
            == _required_identifier(self.capture_session_id, "capture session ID"),
            "capture session ID",
        )
        _require_canonical(
            self.identity_alias == safe_identifier(self.identity_alias),
            "identity alias",
        )
        _require_canonical(self.request_url == sanitize_url(self.request_url), "request URL")
        _require_canonical(
            self.mutation_slots == _slot_names(self.mutation_slots),
            "mutation slots",
        )
        _require_canonical(
            isinstance(self.side_effect_authorized, bool),
            "side-effect authorization",
        )
        _require_canonical(isinstance(self.request_sent, bool), "request sent")
        if self.response_final_url:
            _require_canonical(
                self.response_final_url == sanitize_url(self.response_final_url),
                "response URL",
            )
        _require_canonical(
            self.response_error == redact_text(self.response_error, max_chars=_MAX_REASON_CHARS),
            "response error",
        )
        _require_canonical(
            self.scope_decision == _required_identifier(self.scope_decision, "scope decision"),
            "scope decision",
        )
        _require_canonical(
            self.scope_reason == redact_text(self.scope_reason, max_chars=_MAX_REASON_CHARS),
            "scope reason",
        )
        _require_canonical(
            self.outcome == _required_identifier(self.outcome, "replay outcome"),
            "replay outcome",
        )
        _require_canonical(self.replayed_at == _timestamp(self.replayed_at), "replay timestamp")
        _require_canonical(
            self.unresolved_slots == _slot_names(self.unresolved_slots),
            "unresolved slots",
        )
        if self.scope_decision == "blocked" and self.request_sent:
            raise TrafficContractError("a scope-blocked replay cannot be marked sent")
        if self.response_status is not None and not self.request_sent:
            raise TrafficContractError("a replay response status requires a sent request")
        if (
            self.request_sent
            and self.request_method not in _SAFE_METHODS
            and not self.side_effect_authorized
        ):
            raise TrafficContractError(
                "a side-effecting replay requires explicit authorization before send"
            )
        expected = _replay_fingerprint(
            request_fingerprint=self.request_semantic_fingerprint,
            method=self.request_method,
            url=self.request_url,
            mutation_slots=self.mutation_slots,
            side_effect_authorized=self.side_effect_authorized,
        )
        if self.semantic_fingerprint != expected:
            raise TrafficContractError("replay receipt semantic fingerprint mismatch")

    @classmethod
    def create(  # noqa: PLR0913 - replay receipt mirrors the policy boundary.
        cls,
        *,
        source_exchange_id: str,
        capture_session_id: str,
        request_semantic_fingerprint: str,
        method: str,
        url: str,
        identity_alias: str = "",
        mutation_slots: Iterable[object] = (),
        side_effect_authorized: bool = False,
        request_sent: bool = False,
        response_status: int | None = None,
        response_final_url: str = "",
        response_body_bytes: int = 0,
        response_body_sha256: str = "",
        response_error: str = "",
        response_elapsed_ms: int | None = None,
        scope_decision: str = "not_evaluated",
        scope_reason: str = "",
        outcome: str = "unknown",
        replayed_at: str | datetime | None = None,
        unresolved_slots: Iterable[object] = (),
        known_secrets: Iterable[object] = (),
        replay_id: str = "",
        sequence: int = 0,
    ) -> ReplayReceipt:
        secrets = tuple(known_secrets)
        normalized_method = _method(method)
        normalized_url = sanitize_url(url, known_secrets=secrets)
        normalized_mutations = _slot_names(mutation_slots, known_secrets=secrets)
        fingerprint = _replay_fingerprint(
            request_fingerprint=request_semantic_fingerprint,
            method=normalized_method,
            url=normalized_url,
            mutation_slots=normalized_mutations,
            side_effect_authorized=side_effect_authorized,
        )
        return cls(
            replay_id=replay_id,
            sequence=sequence,
            source_exchange_id=source_exchange_id,
            capture_session_id=_required_identifier(
                capture_session_id,
                "capture session ID",
                known_secrets=secrets,
            ),
            identity_alias=safe_identifier(identity_alias, known_secrets=secrets),
            request_semantic_fingerprint=request_semantic_fingerprint,
            request_method=normalized_method,
            request_url=normalized_url,
            mutation_slots=normalized_mutations,
            side_effect_authorized=bool(side_effect_authorized),
            request_sent=bool(request_sent),
            response_status=response_status,
            response_final_url=(
                sanitize_url(response_final_url, known_secrets=secrets)
                if response_final_url
                else ""
            ),
            response_body_bytes=response_body_bytes,
            response_body_sha256=_normalized_digest(
                response_body_sha256,
                byte_length=response_body_bytes,
            ),
            response_error=redact_text(
                response_error,
                known_secrets=secrets,
                max_chars=_MAX_REASON_CHARS,
            ),
            response_elapsed_ms=response_elapsed_ms,
            scope_decision=_required_identifier(scope_decision, "scope decision"),
            scope_reason=redact_text(
                scope_reason,
                known_secrets=secrets,
                max_chars=_MAX_REASON_CHARS,
            ),
            outcome=_required_identifier(outcome, "replay outcome"),
            replayed_at=_timestamp(replayed_at),
            unresolved_slots=_slot_names(unresolved_slots, known_secrets=secrets),
            semantic_fingerprint=fingerprint,
        )

    def with_store_identity(self, *, replay_id: str, sequence: int) -> ReplayReceipt:
        return replace(self, replay_id=replay_id, sequence=sequence)

    def to_json(self) -> dict[str, object]:
        return {
            "schema": REPLAY_RECEIPT_SCHEMA,
            "version": self.schema_version,
            "replay_id": self.replay_id,
            "sequence": self.sequence,
            "source_exchange_id": self.source_exchange_id,
            "capture_session_id": self.capture_session_id,
            "identity_alias": self.identity_alias,
            "request_semantic_fingerprint": self.request_semantic_fingerprint,
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "mutation_slots": list(self.mutation_slots),
                "side_effect_authorized": self.side_effect_authorized,
                "sent": self.request_sent,
            },
            "response": {
                "status": self.response_status,
                "final_url": self.response_final_url,
                "body": {
                    "bytes": self.response_body_bytes,
                    "sha256": self.response_body_sha256,
                },
                "error": self.response_error,
                "elapsed_ms": self.response_elapsed_ms,
            },
            "scope": {"decision": self.scope_decision, "reason": self.scope_reason},
            "outcome": self.outcome,
            "replayed_at": self.replayed_at,
            "unresolved_slots": list(self.unresolved_slots),
            "semantic_fingerprint": self.semantic_fingerprint,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> ReplayReceipt:
        _require_schema(payload, REPLAY_RECEIPT_SCHEMA)
        request = _mapping(payload.get("request"), "request")
        response = _mapping(payload.get("response"), "response")
        response_body = _mapping(response.get("body"), "response body")
        scope = _mapping(payload.get("scope"), "scope")
        receipt = cls.create(
            replay_id=str(payload.get("replay_id") or ""),
            sequence=_integer(payload.get("sequence"), "sequence"),
            source_exchange_id=str(payload.get("source_exchange_id") or ""),
            capture_session_id=str(payload.get("capture_session_id") or ""),
            identity_alias=str(payload.get("identity_alias") or ""),
            request_semantic_fingerprint=str(payload.get("request_semantic_fingerprint") or ""),
            method=str(request.get("method") or ""),
            url=str(request.get("url") or ""),
            mutation_slots=_string_sequence(request.get("mutation_slots")),
            side_effect_authorized=_boolean(
                request.get("side_effect_authorized"),
                "side effect authorized",
            ),
            request_sent=_boolean(request.get("sent"), "request sent"),
            response_status=_optional_integer(response.get("status"), "response status"),
            response_final_url=str(response.get("final_url") or ""),
            response_body_bytes=_integer(response_body.get("bytes"), "response body bytes"),
            response_body_sha256=str(response_body.get("sha256") or ""),
            response_error=str(response.get("error") or ""),
            response_elapsed_ms=_optional_integer(
                response.get("elapsed_ms"),
                "response elapsed milliseconds",
            ),
            scope_decision=str(scope.get("decision") or ""),
            scope_reason=str(scope.get("reason") or ""),
            outcome=str(payload.get("outcome") or ""),
            replayed_at=str(payload.get("replayed_at") or ""),
            unresolved_slots=_string_sequence(payload.get("unresolved_slots")),
        )
        if str(payload.get("semantic_fingerprint") or "") != receipt.semantic_fingerprint:
            raise TrafficContractError("replay receipt semantic fingerprint mismatch")
        return receipt


def build_captured_http_exchange(  # noqa: PLR0913 - public adapter boundary is explicit.
    *,
    capture_session_id: str,
    source: str,
    method: str,
    url: str,
    source_observation_id: str = "",
    identity_alias: str = "",
    resource_type: str = "",
    navigation: bool = False,
    request_headers: HeaderInput | None = None,
    request_body: object | None = None,
    request_body_media_type: str = "",
    request_body_bytes: int | None = None,
    request_body_sha256: str = "",
    request_sent: bool = False,
    response_status: int | None = None,
    response_final_url: str = "",
    response_headers: HeaderInput | None = None,
    response_body: object | None = None,
    response_body_observed: bool | None = None,
    response_body_bytes: int | None = None,
    response_body_sha256: str = "",
    response_error: str = "",
    response_elapsed_ms: int | None = None,
    scope_decision: str = "not_evaluated",
    scope_reason: str = "",
    captured_at: str | datetime | None = None,
    replayability: str = "",
    unresolved_slots: Iterable[object] = (),
    known_secrets: Iterable[object] = (),
) -> CapturedHttpExchange:
    """Build a persisted-safe capture from raw adapter request/response values."""
    secrets = tuple(known_secrets)
    request_media_type = request_body_media_type or _content_type(request_headers)
    request_body_meta = body_metadata(
        request_body,
        media_type=request_media_type,
        byte_length=request_body_bytes,
        sha256=request_body_sha256,
        known_secrets=secrets,
    )
    response_body_meta = body_metadata(
        response_body,
        media_type=_content_type(response_headers),
        byte_length=response_body_bytes,
        sha256=response_body_sha256,
        known_secrets=secrets,
    )
    return CapturedHttpExchange.create(
        capture_session_id=capture_session_id,
        source=source,
        source_observation_id=source_observation_id,
        identity_alias=identity_alias,
        method=method,
        url=url,
        resource_type=resource_type,
        navigation=navigation,
        request_headers=request_headers,
        request_body_media_type=request_body_meta.media_type,
        request_body_bytes=request_body_meta.byte_length,
        request_body_sha256=request_body_meta.sha256,
        request_body_field_names=request_body_meta.field_names,
        request_sent=request_sent,
        response_status=response_status,
        response_final_url=response_final_url,
        response_headers=response_headers,
        response_body_observed=(
            response_body is not None or response_body_bytes is not None
            if response_body_observed is None
            else response_body_observed
        ),
        response_body_bytes=response_body_meta.byte_length,
        response_body_sha256=response_body_meta.sha256,
        response_error=response_error,
        response_elapsed_ms=response_elapsed_ms,
        scope_decision=scope_decision,
        scope_reason=scope_reason,
        captured_at=captured_at,
        replayability=replayability,
        unresolved_slots=unresolved_slots,
        known_secrets=secrets,
    )


def build_replay_receipt(  # noqa: PLR0913 - public adapter boundary is explicit.
    *,
    source_exchange: CapturedHttpExchange,
    method: str | None = None,
    url: str | None = None,
    identity_alias: str = "",
    mutation_slots: Iterable[object] = (),
    side_effect_authorized: bool = False,
    request_sent: bool = False,
    response_status: int | None = None,
    response_final_url: str = "",
    response_body: object | None = None,
    response_body_bytes: int | None = None,
    response_body_sha256: str = "",
    response_error: str = "",
    response_elapsed_ms: int | None = None,
    scope_decision: str = "not_evaluated",
    scope_reason: str = "",
    outcome: str = "unknown",
    replayed_at: str | datetime | None = None,
    unresolved_slots: Iterable[object] = (),
    known_secrets: Iterable[object] = (),
) -> ReplayReceipt:
    """Build a receipt from a stored capture without copying raw credentials."""
    secrets = tuple(known_secrets)
    body = body_metadata(
        response_body,
        byte_length=response_body_bytes,
        sha256=response_body_sha256,
        known_secrets=secrets,
    )
    return ReplayReceipt.create(
        source_exchange_id=source_exchange.exchange_id,
        capture_session_id=source_exchange.capture_session_id,
        identity_alias=identity_alias or source_exchange.identity_alias,
        request_semantic_fingerprint=source_exchange.semantic_fingerprint,
        method=method or source_exchange.request_method,
        url=url or source_exchange.request_url,
        mutation_slots=mutation_slots,
        side_effect_authorized=side_effect_authorized,
        request_sent=request_sent,
        response_status=response_status,
        response_final_url=response_final_url,
        response_body_bytes=body.byte_length,
        response_body_sha256=body.sha256,
        response_error=response_error,
        response_elapsed_ms=response_elapsed_ms,
        scope_decision=scope_decision,
        scope_reason=scope_reason,
        outcome=outcome,
        replayed_at=replayed_at,
        unresolved_slots=unresolved_slots,
        known_secrets=secrets,
    )


def aggregate_request_contracts(
    exchanges: Iterable[CapturedHttpExchange],
) -> tuple[RequestContract, ...]:
    """Aggregate safe captures into deterministic semantic request contracts."""
    contracts: dict[str, RequestContract] = {}
    for exchange in exchanges:
        observed = RequestContract.from_exchange(exchange)
        previous = contracts.get(observed.semantic_fingerprint)
        contracts[observed.semantic_fingerprint] = (
            observed if previous is None else previous.merge(observed)
        )
    return tuple(contracts[key] for key in sorted(contracts))


def semantic_fingerprint(payload: Mapping[str, object]) -> str:
    """Return the stable SHA-256 identity for a semantic JSON object."""
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _request_fingerprint(
    *,
    method: str,
    url: str,
    header_names: Iterable[str],
    body_media_type: str,
    body_field_names: Iterable[str],
) -> str:
    return semantic_fingerprint(
        {
            "schema": REQUEST_CONTRACT_SCHEMA,
            "method": method,
            "url_shape": semantic_url_shape(url),
            "request_header_names": list(_header_name_sequence(header_names)),
            "body_media_type": _media_type(body_media_type),
            "body_field_names": list(safe_field_names(body_field_names)),
        }
    )


def _replay_fingerprint(
    *,
    request_fingerprint: str,
    method: str,
    url: str,
    mutation_slots: Iterable[str],
    side_effect_authorized: bool,
) -> str:
    _validate_fingerprint(request_fingerprint)
    return semantic_fingerprint(
        {
            "schema": REPLAY_RECEIPT_SCHEMA,
            "request_semantic_fingerprint": request_fingerprint,
            "method": method,
            "url_shape": semantic_url_shape(url),
            "mutation_slots": list(_slot_names(mutation_slots)),
            "side_effect_authorized": bool(side_effect_authorized),
        }
    )


def _content_type(headers: HeaderInput | None) -> str:
    if headers is None:
        return ""
    items = headers.items() if isinstance(headers, Mapping) else headers
    for raw_name, raw_value in items:
        if str(raw_name).strip().casefold() == "content-type":
            return str(raw_value)
    return ""


def _headers_json(headers: HeaderPairs) -> list[dict[str, str]]:
    return [{"name": name, "value": value} for name, value in headers]


def _headers_from_json(value: object) -> HeaderPairs:
    headers: list[tuple[object, object]] = []
    for item in _object_sequence(value):
        if not isinstance(item, Mapping):
            raise TrafficContractError("header record must be an object")
        headers.append((item.get("name", ""), item.get("value", "")))
    return tuple((str(name), str(item)) for name, item in headers)


def _header_names(headers: HeaderPairs) -> tuple[str, ...]:
    return _header_name_sequence(name for name, _value in headers)


def _header_name_sequence(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value.strip().casefold() for value in values if value.strip()}))


def _slot_names(
    values: Iterable[object],
    *,
    known_secrets: Iterable[object] = (),
) -> tuple[str, ...]:
    secrets = tuple(known_secrets)
    slots: set[str] = set()
    for raw in values:
        value = redact_text(
            raw,
            max_chars=160,
            known_secrets=secrets,
        ).strip()
        if value and _SLOT_NAME_RE.fullmatch(value):
            slots.add(value)
    return tuple(sorted(slots))


def _nonempty_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))


def _safe_identifier_sequence(
    values: Iterable[object],
    *,
    max_chars: int = 128,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                normalized
                for value in values
                if (normalized := safe_identifier(value, max_chars=max_chars))
            }
        )
    )


def _method(value: object) -> str:
    method = str(value).strip().upper()
    _validate_method(method)
    return method


def _validate_method(value: str) -> None:
    if not _HTTP_METHOD_RE.fullmatch(value):
        raise TrafficContractError("invalid HTTP method")


def _media_type(value: object) -> str:
    media_type = str(value).split(";", 1)[0].strip().casefold()
    if not media_type:
        return ""
    if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
        raise TrafficContractError("invalid body media type")
    return media_type[:128]


def _body_can_bind_as_text(media_type: str) -> bool:
    return bool(
        media_type
        in {
            "application/json",
            "application/x-www-form-urlencoded",
            "application/xml",
        }
        or media_type.startswith("text/")
        or media_type.endswith(("+json", "+xml"))
    )


def _has_content_encoding(headers: HeaderPairs) -> bool:
    return any(name == "content-encoding" and value for name, value in headers)


def _derived_unresolved_slots(
    *,
    url: str,
    headers: HeaderPairs,
    body_bytes: int,
    replayability: str,
) -> tuple[str, ...]:
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
    for name, value in headers:
        if (name in _REQUIRED_REPLAY_HEADERS and value) or header_requires_replay_binding(
            name, value
        ):
            slots.add(f"header.{name}")
    if body_bytes and replayability != "not_replayable":
        slots.add("body")
    return tuple(sorted(slots))


def header_requires_replay_binding(name: str, value: str) -> bool:
    """Return whether an omitted application-header value must be supplied."""
    normalized = name.casefold()
    return bool(
        value == REDACTED
        and normalized not in _AUTOMATIC_REPLAY_HEADERS
        and not normalized.startswith(("sec-ch-", "sec-fetch-"))
    )


def _is_routing_override_header(name: str) -> bool:
    normalized = name.casefold()
    return normalized in _ROUTING_OVERRIDE_HEADERS or normalized.startswith("x-forwarded-")


def _is_state_override_header(name: str) -> bool:
    return name.casefold() in _STATE_OVERRIDE_HEADERS


def _has_custom_host_header(headers: HeaderInput | None, url: str) -> bool:
    values = tuple(
        str(value).strip()
        for name, value in _header_input_items(headers)
        if str(name).strip().casefold() == "host"
    )
    if not values:
        return False
    return len(values) != 1 or not _host_header_matches_url(values[0], url)


def _header_input_items(headers: HeaderInput | None) -> tuple[tuple[object, object], ...]:
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        items: list[tuple[object, object]] = []
        for name, value in headers.items():
            if isinstance(value, (list, tuple)):
                items.extend((name, item) for item in value)
            else:
                items.append((name, value))
        return tuple(items)
    return tuple(headers)


def _host_header_matches_url(value: str, url: str) -> bool:
    if not value or any(character in value for character in "\r\n\x00/@"):
        return False
    try:
        expected = urlsplit(url)
        candidate = urlsplit(f"//{value}")
        expected_port = expected.port or (443 if expected.scheme == "https" else 80)
        candidate_port = candidate.port or expected_port
    except ValueError:
        return False
    expected_host = (expected.hostname or "").rstrip(".").casefold()
    candidate_host = (candidate.hostname or "").rstrip(".").casefold()
    return bool(
        expected_host and candidate_host == expected_host and candidate_port == expected_port
    )


def _default_replayability(method: str, *, request_sent: bool, scope_decision: str) -> str:
    if not request_sent or scope_decision.strip().casefold() == "blocked":
        return "not_replayable"
    return "safe" if method in _SAFE_METHODS else "requires_authorization"


def _is_anonymous_identity(identity_alias: str) -> bool:
    return identity_alias.strip().casefold() in {"", "anon", "anonymous"}


def _most_restrictive_replayability(left: str, right: str) -> str:
    order = {"safe": 0, "requires_authorization": 1, "not_replayable": 2}
    return max((left, right), key=order.__getitem__)


def _required_identifier(
    value: object,
    label: str,
    *,
    known_secrets: Iterable[object] = (),
) -> str:
    normalized = safe_identifier(value, known_secrets=known_secrets)
    if not normalized:
        raise TrafficContractError(f"{label} is required")
    return normalized


def _timestamp(value: str | datetime | None) -> str:
    if value is None:
        moment = datetime.now(UTC)
    elif isinstance(value, datetime):
        moment = value
    else:
        text = value.strip()
        if not text:
            raise TrafficContractError("timestamp is required")
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise TrafficContractError("invalid timestamp") from exc
    if moment.tzinfo is None:
        raise TrafficContractError("timestamp must include a timezone")
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalized_digest(value: object, *, byte_length: int) -> str:
    # Durable traffic artifacts deliberately retain no digest of a raw body.
    # A digest is still an offline oracle for low-entropy passwords, OTPs,
    # flags, and other values that Ravage promises not to persist.
    del value
    return "" if byte_length == 0 else "unavailable"


def _validate_digest(value: str, *, byte_length: int) -> None:
    expected = "" if byte_length == 0 else "unavailable"
    if value != expected:
        raise TrafficContractError("body digest must not be persisted")


def _validate_fingerprint(value: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise TrafficContractError("invalid semantic fingerprint")


def _validate_status(value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not _MIN_HTTP_STATUS <= value <= _MAX_HTTP_STATUS:
        raise TrafficContractError("invalid HTTP response status")


def _validate_non_negative(value: int, label: str) -> None:
    if isinstance(value, bool) or value < 0:
        raise TrafficContractError(f"{label} must be non-negative")


def _validate_optional_non_negative(value: int | None, label: str) -> None:
    if value is not None:
        _validate_non_negative(value, label)


def _validate_store_identity(
    *,
    value: str,
    sequence: int,
    pattern: re.Pattern[str],
    label: str,
) -> None:
    _validate_non_negative(sequence, f"{label} sequence")
    if not value and sequence == 0:
        return
    if sequence == 0 or not pattern.fullmatch(value):
        raise TrafficContractError(f"invalid {label} store identity")
    expected = f"{'rq' if label == 'exchange' else 'rp'}_{sequence:04d}"
    if value != expected:
        raise TrafficContractError(f"{label} ID does not match sequence")


def _validate_schema_version(value: int) -> None:
    if value != TRAFFIC_SCHEMA_VERSION:
        raise TrafficContractError("unsupported traffic schema version")


def _require_canonical(condition: object, label: str) -> None:
    if condition is not True:
        raise TrafficContractError(f"{label} is not in persisted-safe canonical form")


def _require_schema(payload: Mapping[str, object], expected: str) -> None:
    if str(payload.get("schema") or "") != expected:
        raise TrafficContractError("unexpected traffic schema")
    if _integer(payload.get("version"), "schema version") != TRAFFIC_SCHEMA_VERSION:
        raise TrafficContractError("unsupported traffic schema version")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TrafficContractError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _object_sequence(value: object) -> Sequence[object]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise TrafficContractError("expected a JSON array")
    return value


def _string_sequence(value: object) -> tuple[str, ...]:
    return tuple(str(item) for item in _object_sequence(value))


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TrafficContractError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise TrafficContractError(f"{label} must be a boolean")
    return value


__all__ = [
    "CAPTURED_HTTP_EXCHANGE_SCHEMA",
    "REPLAY_RECEIPT_SCHEMA",
    "REQUEST_CONTRACT_SCHEMA",
    "TRAFFIC_SCHEMA_VERSION",
    "CapturedHttpExchange",
    "ReplayReceipt",
    "RequestContract",
    "TrafficContractError",
    "aggregate_request_contracts",
    "build_captured_http_exchange",
    "build_replay_receipt",
    "header_requires_replay_binding",
    "semantic_fingerprint",
]
