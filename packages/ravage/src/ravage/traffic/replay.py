# ruff: noqa: EM101, EM102, TRY003
"""One-shot, scope-checked replay of redacted request templates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ravage.web_core.http_probe import ProbeSession

from .contracts import (
    CapturedHttpExchange,
    ReplayReceipt,
    build_replay_receipt,
    header_requires_replay_binding,
)
from .redaction import REDACTED, redact_text
from .scope import TrafficScope
from .store import TrafficStoreError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from .manifest import TrafficRunManifest
    from .store import TrafficStore

SAFE_REPLAY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_VALUE_HEADERS = frozenset({"accept", "content-encoding", "content-language", "content-type"})


@dataclass(frozen=True, slots=True)
class ReplayResult:
    receipt: ReplayReceipt
    error: str = ""

    @property
    def sent(self) -> bool:
        return self.receipt.request_sent


def replay_exchange(  # noqa: C901, PLR0911, PLR0913 - explicit policy boundary.
    *,
    store: TrafficStore,
    manifest: TrafficRunManifest,
    exchange: CapturedHttpExchange,
    allow_remote_target: bool,
    allow_state_change: bool = False,
    bindings: dict[str, str] | None = None,
    timeout_seconds: int = 10,
) -> ReplayResult:
    """Replay exactly once, or persist a fail-closed receipt without sending."""
    replacements = dict(bindings or {})
    method = exchange.request_method
    mutation_slots = tuple(sorted(replacements))

    if exchange.capture_session_id != manifest.capture_session_id:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=exchange.request_url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason="captured request does not belong to this traffic run",
            unresolved=exchange.unresolved_slots,
            known_secrets=replacements.values(),
        )

    if exchange.replayability == "not_replayable":
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=exchange.request_url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason="captured request was not sent and is not replayable",
            unresolved=exchange.unresolved_slots,
            known_secrets=replacements.values(),
        )

    if (
        method not in SAFE_REPLAY_METHODS or exchange.replayability == "requires_authorization"
    ) and not allow_state_change:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=exchange.request_url,
            mutation_slots=mutation_slots,
            side_effect_authorized=False,
            reason=(
                f"{method} or one of its override headers may change target state; "
                "rerun this one request with "
                "--allow-state-change"
            ),
            unresolved=exchange.unresolved_slots,
            known_secrets=replacements.values(),
        )

    missing = tuple(slot for slot in exchange.unresolved_slots if not replacements.get(slot))
    unknown = tuple(sorted(set(replacements).difference(exchange.unresolved_slots)))
    if unknown:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=exchange.request_url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=f"unknown replacement slot(s): {', '.join(unknown)}",
            unresolved=missing,
            known_secrets=replacements.values(),
        )
    if missing:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=exchange.request_url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=f"request still needs value(s): {', '.join(missing)}",
            unresolved=missing,
            known_secrets=replacements.values(),
        )

    try:
        url = _resolved_url(exchange.request_url, replacements)
        headers = _resolved_headers(exchange, replacements)
        body = _resolved_body(exchange, replacements)
    except ValueError as exc:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=exchange.request_url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=redact_text(exc, known_secrets=replacements.values(), max_chars=500),
            unresolved=(),
            known_secrets=replacements.values(),
        )

    try:
        scope = TrafficScope(
            url,
            allow_remote_target=allow_remote_target,
            in_scope=manifest.in_scope,
            out_of_scope=manifest.out_of_scope,
        )
    except ValueError as exc:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=str(exc),
            unresolved=(),
            known_secrets=replacements.values(),
        )
    decision = scope.decide(url)
    if not decision.allowed:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=decision.reason or "outside authorized scope",
            unresolved=(),
            known_secrets=replacements.values(),
        )

    approved_addresses = scope.pinned_addresses(url)
    approved_resolver = (
        _approved_address_resolver(url, approved_addresses) if approved_addresses else None
    )

    try:
        session = ProbeSession(
            url,
            timeout_seconds=max(1, min(timeout_seconds, 60)),
            allow_remote_target=allow_remote_target,
            in_scope=manifest.in_scope,
            out_of_scope=manifest.out_of_scope,
            resolver=approved_resolver,
        )
    except (TypeError, ValueError) as exc:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=str(exc),
            unresolved=(),
            known_secrets=replacements.values(),
        )
    dispatch = build_replay_receipt(
        source_exchange=exchange,
        method=method,
        url=url,
        mutation_slots=mutation_slots,
        side_effect_authorized=allow_state_change,
        request_sent=False,
        scope_decision="allowed",
        scope_reason="network dispatch durably reserved; outcome pending",
        outcome="dispatch_reserved",
        known_secrets=replacements.values(),
    )
    reserved, created = store.reserve_replay_dispatch(dispatch)
    if not created:
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=(
                f"request already has durable dispatch reservation {reserved.replay_id}; "
                "capture a fresh request before replaying again"
            ),
            unresolved=(),
            known_secrets=replacements.values(),
        )
    try:
        response = session.request(method, url, data=body, headers=headers)
    except (TypeError, ValueError) as exc:
        reason = redact_text(exc, known_secrets=replacements.values(), max_chars=500)
        return _blocked(
            store=store,
            exchange=exchange,
            method=method,
            url=url,
            mutation_slots=mutation_slots,
            side_effect_authorized=allow_state_change,
            reason=f"request rejected before send: {reason}",
            unresolved=(),
            known_secrets=replacements.values(),
        )
    sent = not (
        response.status is None
        and response.elapsed_ms == 0
        and response.error.startswith(("URL is outside", "remote target DNS"))
    )
    receipt = build_replay_receipt(
        source_exchange=exchange,
        method=method,
        url=url,
        mutation_slots=mutation_slots,
        side_effect_authorized=allow_state_change,
        request_sent=sent,
        response_status=response.status,
        response_final_url=response.final_url,
        response_body=response.body,
        response_error=response.error,
        response_elapsed_ms=response.elapsed_ms,
        scope_decision="allowed" if sent else "blocked",
        scope_reason="" if sent else response.error,
        outcome=("response" if response.status is not None else "transport_error"),
        known_secrets=replacements.values(),
    )
    try:
        stored = store.append_replay(receipt)
    except TrafficStoreError as exc:
        detail = redact_text(exc, known_secrets=replacements.values(), max_chars=300)
        message = (
            f"dispatch {reserved.replay_id} may have reached the target, but its final "
            f"receipt could not be persisted: {detail}; do not retry this request ID"
        )
        raise TrafficStoreError(message) from exc
    return ReplayResult(receipt=stored, error="" if sent else response.error)


def diff_records(store: TrafficStore, left_id: str, right_id: str) -> dict[str, object]:
    """Return an offline, deterministic comparison of two capture/replay records."""
    left = _record_view(store, left_id)
    right = _record_view(store, right_id)
    changes: dict[str, dict[str, object]] = {}
    for field in (
        "method",
        "url",
        "request_sent",
        "response_status",
        "response_body_bytes",
        "error",
        "scope_decision",
    ):
        if field == "response_body_bytes" and (
            left.get("response_body_observed") is not True
            or right.get("response_body_observed") is not True
        ):
            continue
        if left.get(field) != right.get(field):
            changes[field] = {"left": left.get(field), "right": right.get(field)}
    left_elapsed = left.get("elapsed_ms")
    right_elapsed = right.get("elapsed_ms")
    if (
        isinstance(left_elapsed, int)
        and isinstance(right_elapsed, int)
        and left_elapsed != right_elapsed
    ):
        changes["elapsed_ms"] = {
            "left": left_elapsed,
            "right": right_elapsed,
            "delta": right_elapsed - left_elapsed,
        }
    return {"left": left, "right": right, "changes": changes}


def _blocked(  # noqa: PLR0913
    *,
    store: TrafficStore,
    exchange: CapturedHttpExchange,
    method: str,
    url: str,
    mutation_slots: tuple[str, ...],
    side_effect_authorized: bool,
    reason: str,
    unresolved: tuple[str, ...],
    known_secrets: Iterable[object] = (),
) -> ReplayResult:
    secrets = tuple(known_secrets)
    safe_reason = redact_text(reason, known_secrets=secrets, max_chars=500)
    receipt = build_replay_receipt(
        source_exchange=exchange,
        method=method,
        url=url,
        mutation_slots=mutation_slots,
        side_effect_authorized=side_effect_authorized,
        request_sent=False,
        response_error=safe_reason,
        scope_decision="blocked",
        scope_reason=safe_reason,
        outcome="blocked",
        unresolved_slots=unresolved,
        known_secrets=secrets,
    )
    stored = store.append_replay(receipt)
    return ReplayResult(receipt=stored, error=safe_reason)


def _resolved_url(url: str, bindings: dict[str, str]) -> str:
    parsed = urlsplit(url)
    segments = parsed.path.split("/")
    for index, _segment in enumerate(segments):
        slot = f"path.{index}"
        if slot in bindings:
            value = bindings[slot]
            if not value or "/" in value:
                raise ValueError(f"{slot} must be one non-empty URL path segment")
            segments[index] = quote(value, safe="!$&'()*+,;=:@-._~")
    original_query = parse_qsl(parsed.query, keep_blank_values=True)
    query_names = [name for name, _value in original_query]
    totals = {name: query_names.count(name) for name in set(query_names)}
    seen: dict[str, int] = {}
    query = []
    for name, value in original_query:
        index = seen.get(name, 0)
        seen[name] = index + 1
        suffix = f"[{index}]" if totals[name] > 1 else ""
        slot = f"query.{name}{suffix}"
        replacement = bindings.get(slot, value)
        if replacement == REDACTED:
            raise ValueError(f"request still needs value: {slot}")
        query.append((name, replacement))
    result = urlunsplit(
        (parsed.scheme, parsed.netloc, "/".join(segments) or "/", urlencode(query), "")
    )
    if REDACTED in result or ":redacted" in result or ":id" in result:
        raise ValueError("request URL still contains a redacted value")
    return result


def _resolved_headers(
    exchange: CapturedHttpExchange,
    bindings: dict[str, str],
) -> dict[str, str]:
    headers = {
        name: value
        for name, value in exchange.request_headers
        if name in _VALUE_HEADERS and value and value != REDACTED
    }
    for slot, value in bindings.items():
        if slot.startswith("header."):
            name = slot.removeprefix("header.")
            if name in {
                "destination",
                "forwarded",
                "host",
                "if",
                "proxy-authorization",
                "x-host",
                "x-http-host-override",
                "x-original-uri",
                "x-original-url",
                "x-request-uri",
                "x-rewrite-uri",
                "x-rewrite-url",
            } or name.startswith("x-forwarded-"):
                raise ValueError(f"{slot} is transport-owned and cannot be replayed")
            if any(character in "\r\n\x00" or not character.isprintable() for character in value):
                raise ValueError(f"{slot} contains a forbidden control character")
            headers[name] = value
    unresolved_headers = tuple(
        name
        for name, value in exchange.request_headers
        if header_requires_replay_binding(name, value) and name not in headers
    )
    if unresolved_headers:
        names = ", ".join(f"header.{name}" for name in unresolved_headers)
        raise ValueError(f"request still needs header value(s): {names}")
    return headers


def _resolved_body(
    exchange: CapturedHttpExchange,
    bindings: dict[str, str],
) -> bytes | None:
    if exchange.request_body_bytes == 0:
        return None
    if any(name == "content-encoding" and value for name, value in exchange.request_headers):
        raise ValueError("content-encoded request bodies cannot be reconstructed safely")
    if "body" in bindings:
        return bindings["body"].encode("utf-8")
    raise ValueError("captured body cannot be reconstructed safely; bind the opaque `body` slot")


def _approved_address_resolver(
    url: str,
    addresses: tuple[str, ...],
) -> Callable[[str, int], tuple[str, ...]]:
    parsed = urlsplit(url)
    expected_host = (parsed.hostname or "").rstrip(".").casefold()
    expected_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def resolve(host: str, port: int) -> tuple[str, ...]:
        if host.rstrip(".").casefold() != expected_host or port != expected_port:
            raise OSError("connection host does not match the approved DNS pin")
        return addresses

    return resolve


def _record_view(store: TrafficStore, record_id: str) -> dict[str, object]:
    if record_id.startswith("rq_"):
        exchange = store.exchange(record_id)
        if exchange is None:
            raise KeyError(record_id)
        return {
            "id": exchange.exchange_id,
            "kind": "capture",
            "method": exchange.request_method,
            "url": exchange.request_url,
            "request_sent": exchange.request_sent,
            "response_status": exchange.response_status,
            "response_body_observed": exchange.response_body_observed,
            "response_body_bytes": exchange.response_body_bytes,
            "elapsed_ms": exchange.response_elapsed_ms,
            "error": exchange.response_error,
            "scope_decision": exchange.scope_decision,
        }
    if record_id.startswith("rp_"):
        receipt = next(
            (item for item in store.replay_receipts() if item.replay_id == record_id),
            None,
        )
        if receipt is None:
            raise KeyError(record_id)
        return {
            "id": receipt.replay_id,
            "kind": "replay",
            "method": receipt.request_method,
            "url": receipt.request_url,
            "request_sent": receipt.request_sent,
            "response_status": receipt.response_status,
            "response_body_observed": receipt.response_status is not None,
            "response_body_bytes": receipt.response_body_bytes,
            "elapsed_ms": receipt.response_elapsed_ms,
            "error": receipt.response_error,
            "scope_decision": receipt.scope_decision,
        }
    raise KeyError(record_id)


__all__ = [
    "SAFE_REPLAY_METHODS",
    "ReplayResult",
    "diff_records",
    "replay_exchange",
]
