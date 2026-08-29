# ruff: noqa: C901, D213, EM101, EM102, N818, PLR0912, PLR0913, PLR2004, PTH105, PTH108, SIM105, SLF001, TRY003, TRY004, TRY300
"""Durable, process-safe policy for target HTTP traffic.

The controller deliberately separates a scheduled reservation from a physical
dispatch.  A reservation participates in the whole-run cap and global pacing,
but the durable physical count is incremented only by :meth:`begin_dispatch`,
immediately before the caller enters its HTTP transport.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC
from email.utils import parsedate_to_datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


TRAFFIC_POLICY_SCHEMA = "ravage.traffic-policy"
TRAFFIC_POLICY_VERSION = 1
_MAX_LEDGER_BYTES = 8_000_000
_CACHE_FILE_SUFFIX = ".json"
_OVERLOAD_STATUSES = frozenset({429, 502, 503, 504})
_SENSITIVE_REQUEST_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
    }
)
_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {
        "authentication-info",
        "proxy-authentication-info",
        "set-cookie",
    }
)


class TrafficPolicyError(RuntimeError):
    """The durable policy is invalid, unavailable, or unsafe to use."""


class TrafficPolicyBlocked(TrafficPolicyError):
    """A request was stopped before a physical transport dispatch."""


class TrafficPolicyMode(StrEnum):
    """Policy behavior while retaining truthful accounting."""

    OBSERVE = "observe"
    ENFORCE = "enforce"


class TrafficDecisionKind(StrEnum):
    DISPATCH = "dispatch"
    CACHE_HIT = "cache_hit"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class TrafficPolicyConfig:
    """Whole-run traffic constraints.

    ``observe`` records physical dispatches without changing request behavior.
    ``enforce`` activates the cap, pacing, cache/deduplication, retries, backoff,
    and circuit breaker.
    """

    mode: TrafficPolicyMode = TrafficPolicyMode.OBSERVE
    max_rps: float | None = None
    max_physical_requests: int | None = None
    cache_enabled: bool = False
    cache_ttl_seconds: float = 30.0
    cache_max_body_bytes: int = 600_000
    deduplicate: bool = True
    max_retries: int = 0
    retry_statuses: tuple[int, ...] = (429, 502, 503, 504)
    backoff_initial_seconds: float = 1.0
    backoff_max_seconds: float = 30.0
    circuit_failure_threshold: int = 4
    circuit_open_seconds: float = 30.0
    lease_timeout_seconds: float = 120.0
    dedupe_wait_timeout_seconds: float = 30.0
    cacheable_lanes: tuple[str, ...] = ("agent_http", "baseline", "recon")

    def __post_init__(self) -> None:
        try:
            mode = TrafficPolicyMode(self.mode)
        except ValueError as exc:
            raise ValueError("traffic policy mode must be observe or enforce") from exc
        object.__setattr__(self, "mode", mode)
        if self.max_rps is not None:
            _positive_number(self.max_rps, "max_rps")
            if not math.isfinite(1.0 / float(self.max_rps)):
                raise ValueError("max_rps must yield a finite pacing interval")
        if self.max_physical_requests is not None:
            _positive_int(self.max_physical_requests, "max_physical_requests")
        _positive_number(self.cache_ttl_seconds, "cache_ttl_seconds")
        _positive_int(self.cache_max_body_bytes, "cache_max_body_bytes")
        _non_negative_int(self.max_retries, "max_retries")
        if not self.retry_statuses or any(
            isinstance(status, bool) or not 100 <= status <= 599 for status in self.retry_statuses
        ):
            raise ValueError("retry_statuses must contain HTTP status integers")
        object.__setattr__(self, "retry_statuses", tuple(sorted(set(self.retry_statuses))))
        _positive_number(self.backoff_initial_seconds, "backoff_initial_seconds")
        _positive_number(self.backoff_max_seconds, "backoff_max_seconds")
        if self.backoff_initial_seconds > self.backoff_max_seconds:
            raise ValueError("backoff_initial_seconds cannot exceed backoff_max_seconds")
        _positive_int(self.circuit_failure_threshold, "circuit_failure_threshold")
        _positive_number(self.circuit_open_seconds, "circuit_open_seconds")
        _positive_number(self.lease_timeout_seconds, "lease_timeout_seconds")
        _positive_number(self.dedupe_wait_timeout_seconds, "dedupe_wait_timeout_seconds")
        lanes = tuple(
            sorted({str(item).strip() for item in self.cacheable_lanes if str(item).strip()})
        )
        if not lanes:
            raise ValueError("cacheable_lanes cannot be empty")
        object.__setattr__(self, "cacheable_lanes", lanes)

    @classmethod
    def low_noise(
        cls,
        *,
        max_physical_requests: int,
        max_rps: float = 0.5,
    ) -> Self:
        """Return the conservative whole-run policy preset."""
        return cls(
            mode=TrafficPolicyMode.ENFORCE,
            max_rps=max_rps,
            max_physical_requests=max_physical_requests,
            cache_enabled=True,
            deduplicate=True,
            max_retries=2,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "max_rps": self.max_rps,
            "max_physical_requests": self.max_physical_requests,
            "cache_enabled": self.cache_enabled,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "cache_max_body_bytes": self.cache_max_body_bytes,
            "deduplicate": self.deduplicate,
            "max_retries": self.max_retries,
            "retry_statuses": list(self.retry_statuses),
            "backoff_initial_seconds": self.backoff_initial_seconds,
            "backoff_max_seconds": self.backoff_max_seconds,
            "circuit_failure_threshold": self.circuit_failure_threshold,
            "circuit_open_seconds": self.circuit_open_seconds,
            "lease_timeout_seconds": self.lease_timeout_seconds,
            "dedupe_wait_timeout_seconds": self.dedupe_wait_timeout_seconds,
            "cacheable_lanes": list(self.cacheable_lanes),
        }

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> Self:
        allowed = {
            "mode",
            "max_rps",
            "max_physical_requests",
            "cache_enabled",
            "cache_ttl_seconds",
            "cache_max_body_bytes",
            "deduplicate",
            "max_retries",
            "retry_statuses",
            "backoff_initial_seconds",
            "backoff_max_seconds",
            "circuit_failure_threshold",
            "circuit_open_seconds",
            "lease_timeout_seconds",
            "dedupe_wait_timeout_seconds",
            "cacheable_lanes",
        }
        unknown = set(value).difference(allowed)
        if unknown:
            raise TrafficPolicyError(f"unknown traffic policy fields: {sorted(unknown)!r}")
        defaults = cls()
        return cls(
            mode=TrafficPolicyMode(str(value.get("mode", defaults.mode.value))),
            max_rps=_optional_float(value.get("max_rps", defaults.max_rps)),
            max_physical_requests=_optional_int(
                value.get("max_physical_requests", defaults.max_physical_requests)
            ),
            cache_enabled=_bool(value.get("cache_enabled", defaults.cache_enabled)),
            cache_ttl_seconds=_float(value.get("cache_ttl_seconds", defaults.cache_ttl_seconds)),
            cache_max_body_bytes=_int(
                value.get("cache_max_body_bytes", defaults.cache_max_body_bytes)
            ),
            deduplicate=_bool(value.get("deduplicate", defaults.deduplicate)),
            max_retries=_int(value.get("max_retries", defaults.max_retries)),
            retry_statuses=tuple(
                _int(item)
                for item in _list(value.get("retry_statuses", list(defaults.retry_statuses)))
            ),
            backoff_initial_seconds=_float(
                value.get("backoff_initial_seconds", defaults.backoff_initial_seconds)
            ),
            backoff_max_seconds=_float(
                value.get("backoff_max_seconds", defaults.backoff_max_seconds)
            ),
            circuit_failure_threshold=_int(
                value.get("circuit_failure_threshold", defaults.circuit_failure_threshold)
            ),
            circuit_open_seconds=_float(
                value.get("circuit_open_seconds", defaults.circuit_open_seconds)
            ),
            lease_timeout_seconds=_float(
                value.get("lease_timeout_seconds", defaults.lease_timeout_seconds)
            ),
            dedupe_wait_timeout_seconds=_float(
                value.get("dedupe_wait_timeout_seconds", defaults.dedupe_wait_timeout_seconds)
            ),
            cacheable_lanes=tuple(
                str(item)
                for item in _list(value.get("cacheable_lanes", list(defaults.cacheable_lanes)))
            ),
        )


@dataclass(frozen=True)
class RequestIntent:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None
    lane: str = "probe"
    identity_alias: str = "anonymous"
    identity_generation: int | None = 0
    cacheable: bool = False
    retryable: bool = False
    timing_sensitive: bool = False

    def __post_init__(self) -> None:
        method = self.method.strip().upper()
        if not method:
            raise ValueError("request method cannot be empty")
        object.__setattr__(self, "method", method)
        parsed = urlsplit(self.url)
        if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("request intent URL must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("request intent URL cannot contain userinfo")
        object.__setattr__(self, "headers", {str(k): str(v) for k, v in self.headers.items()})
        if self.body is not None and not isinstance(self.body, bytes):
            raise TypeError("request intent body must be bytes")
        lane = self.lane.strip()
        if not lane:
            raise ValueError("request lane cannot be empty")
        object.__setattr__(self, "lane", lane)
        alias = self.identity_alias.strip() or "anonymous"
        object.__setattr__(self, "identity_alias", alias)
        if self.identity_generation is not None:
            _non_negative_int(self.identity_generation, "identity_generation")

    @property
    def fingerprint(self) -> str:
        payload = {
            "method": self.method,
            "url": self.url,
            "headers": [
                (
                    str(name).casefold(),
                    hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest(),
                )
                for name, value in sorted(self.headers.items(), key=lambda item: item[0].casefold())
            ],
            "body_sha256": hashlib.sha256(self.body or b"").hexdigest(),
            "lane": self.lane,
            "identity_alias": self.identity_alias,
            "identity_generation": self.identity_generation,
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class TrafficCacheRecord:
    status: int
    final_url: str
    headers: dict[str, str]
    body: str
    truncated: bool = False
    body_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if self.body_bytes is None:
            object.__setattr__(self, "body_bytes", self.body.encode("utf-8"))

    def to_json(self) -> dict[str, object]:
        return {
            "status": self.status,
            "final_url": self.final_url,
            "headers": dict(self.headers),
            "body_b64": base64.b64encode(self.body_bytes or b"").decode("ascii"),
            "truncated": self.truncated,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> Self:
        try:
            raw_body = base64.b64decode(str(value["body_b64"]), validate=True)
            body = raw_body.decode("utf-8", errors="replace")
        except (KeyError, ValueError) as exc:
            raise TrafficPolicyError("traffic cache record body is invalid") from exc
        raw_headers = value.get("headers")
        if not isinstance(raw_headers, dict):
            raise TrafficPolicyError("traffic cache record headers are invalid")
        return cls(
            status=_int(value.get("status")),
            final_url=str(value.get("final_url") or ""),
            headers={str(k): str(v) for k, v in raw_headers.items()},
            body=body,
            truncated=_bool(value.get("truncated", False)),
            body_bytes=raw_body,
        )


@dataclass(frozen=True)
class TrafficOutcome:
    status: int | None
    headers: Mapping[str, str] = field(default_factory=dict)
    transport_error: bool = False
    cache_record: TrafficCacheRecord | None = None


@dataclass(frozen=True)
class DispatchLease:
    lease_id: str
    sequence: int
    not_before: float
    intent_fingerprint: str
    cache_key: str


@dataclass(frozen=True)
class TrafficDecision:
    kind: TrafficDecisionKind
    lease: DispatchLease | None = None
    cached: TrafficCacheRecord | None = None
    reason: str = ""


@dataclass(frozen=True)
class TrafficPolicySnapshot:
    physical_request_count: int
    completed_request_count: int
    incomplete_request_count: int
    pending_dispatch_count: int
    reservation_count: int
    cache_hit_count: int
    deduplicated_count: int
    retry_count: int
    blocked_count: int
    circuit_open_count: int
    unmetered_action_count: int
    accounting_status: str

    def to_json(self) -> dict[str, object]:
        return {
            "physical_request_count": self.physical_request_count,
            "completed_request_count": self.completed_request_count,
            "incomplete_request_count": self.incomplete_request_count,
            "pending_dispatch_count": self.pending_dispatch_count,
            "reservation_count": self.reservation_count,
            "cache_hit_count": self.cache_hit_count,
            "deduplicated_count": self.deduplicated_count,
            "retry_count": self.retry_count,
            "blocked_count": self.blocked_count,
            "circuit_open_count": self.circuit_open_count,
            "unmetered_action_count": self.unmetered_action_count,
            "accounting_status": self.accounting_status,
        }


@dataclass(frozen=True)
class TrafficPolicyInspection:
    state_path: str
    target_origin: str
    config: TrafficPolicyConfig
    snapshot: TrafficPolicySnapshot

    def to_json(self) -> dict[str, object]:
        return {
            "state_path": self.state_path,
            "target_origin": self.target_origin,
            "config": self.config.to_json(),
            "snapshot": self.snapshot.to_json(),
        }


class TrafficPolicyController:
    """Coordinate one target's physical HTTP traffic across processes."""

    def __init__(
        self,
        state_path: Path,
        target_origin: str,
        config: TrafficPolicyConfig,
        *,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.state_path = state_path
        self.lock_path = state_path.with_name(f"{state_path.name}.lock")
        self.cache_path = state_path.with_name(f"{state_path.name}.cache")
        self.target_origin = target_origin
        self.config = config
        self._clock = clock
        self._sleep = sleep

    @classmethod
    def open(
        cls,
        state_path: str | Path,
        *,
        target_url: str,
        config: TrafficPolicyConfig,
        require_existing: bool = False,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Self:
        path = Path(state_path).expanduser().absolute()
        target_origin = _target_origin(target_url)
        path.parent.mkdir(parents=True, exist_ok=True)
        controller = cls(path, target_origin, config, clock=clock, sleep=sleep)
        with controller._locked_state(create=not require_existing) as state:
            controller._validate_state(state)
        return controller

    @classmethod
    def from_reference(
        cls,
        reference: Mapping[str, object],
        *,
        require_existing: bool = True,
    ) -> Self:
        if reference.get("schema") != TRAFFIC_POLICY_SCHEMA:
            raise TrafficPolicyError("traffic policy reference schema is invalid")
        if reference.get("version") != TRAFFIC_POLICY_VERSION:
            raise TrafficPolicyError("traffic policy reference version is unsupported")
        path = str(reference.get("state_path") or "")
        target_url = str(reference.get("target_url") or "")
        raw_config = reference.get("config")
        if not path or not target_url or not isinstance(raw_config, dict):
            raise TrafficPolicyError("traffic policy reference is incomplete")
        return cls.open(
            path,
            target_url=target_url,
            config=TrafficPolicyConfig.from_json(raw_config),
            require_existing=require_existing,
        )

    def to_reference(self) -> dict[str, object]:
        return {
            "schema": TRAFFIC_POLICY_SCHEMA,
            "version": TRAFFIC_POLICY_VERSION,
            "state_path": str(self.state_path),
            "target_url": self.target_origin,
            "config": self.config.to_json(),
        }

    def acquire(self, intent: RequestIntent, *, retry: bool = False) -> TrafficDecision:
        """Return a cache hit, a scheduled dispatch lease, or a preflight block."""
        self._validate_intent_origin(intent)
        wait_started = self._now()
        dedupe_observed = False
        while True:
            decision, wait_until = self._acquire_once(intent, retry=retry)
            if decision is not None:
                return decision
            if not dedupe_observed:
                self._record_deduplicated()
                dedupe_observed = True
            now = self._now()
            if now - wait_started >= self.config.dedupe_wait_timeout_seconds:
                self._record_blocked()
                return TrafficDecision(
                    TrafficDecisionKind.BLOCKED,
                    reason="traffic deduplication wait timed out",
                )
            self._sleep(max(0.001, min(wait_until - now, 0.05)))

    def begin_dispatch(self, lease: DispatchLease) -> int:
        """Commit a lease as a physical request immediately before transport."""
        while True:
            blocked_reason = ""
            with self._locked_state() as state:
                self._prune_state(state)
                reservations = _dict_value(state, "reservations")
                raw = reservations.get(lease.lease_id)
                if not isinstance(raw, dict):
                    raise TrafficPolicyBlocked("traffic dispatch lease is no longer valid")
                self._validate_lease(raw, lease)
                now = self._now()
                if self.config.mode is TrafficPolicyMode.ENFORCE:
                    open_until = _number(state.get("circuit_open_until"))
                    half_open_lease = str(state.get("half_open_lease") or "")
                    failures = _counter(state, "circuit_failures")
                    if open_until > now:
                        self._cancel_reservation(state, lease.lease_id)
                        state["blocked_count"] = _counter(state, "blocked_count") + 1
                        blocked_reason = "traffic circuit is open"
                        ready_at = now
                    elif failures >= self.config.circuit_failure_threshold:
                        if half_open_lease and half_open_lease != lease.lease_id:
                            self._cancel_reservation(state, lease.lease_id)
                            state["blocked_count"] = _counter(state, "blocked_count") + 1
                            blocked_reason = "traffic circuit half-open trial is already active"
                            ready_at = now
                        else:
                            state["half_open_lease"] = lease.lease_id
                            raw["half_open"] = True
                            ready_at = max(
                                _number(raw.get("not_before")),
                                _number(state.get("backoff_until")),
                                _number(state.get("next_physical_dispatch_at")),
                            )
                    else:
                        ready_at = max(
                            _number(raw.get("not_before")),
                            _number(state.get("backoff_until")),
                            _number(state.get("next_physical_dispatch_at")),
                        )
                else:
                    ready_at = _number(raw.get("not_before"))
                if not blocked_reason:
                    raw["expires_at"] = max(
                        _number(raw.get("expires_at")),
                        ready_at + self.config.lease_timeout_seconds,
                    )
                if not blocked_reason and ready_at <= now:
                    if (
                        self.config.mode is TrafficPolicyMode.ENFORCE
                        and self.config.max_rps is not None
                    ):
                        state["next_physical_dispatch_at"] = now + (1.0 / self.config.max_rps)
                    reservations.pop(lease.lease_id, None)
                    dispatched = _dict_value(state, "dispatched")
                    raw["dispatched_at"] = now
                    raw["expires_at"] = now + self.config.lease_timeout_seconds
                    dispatched[lease.lease_id] = raw
                    state["physical_request_count"] = _counter(state, "physical_request_count") + 1
                    return _counter(state, "physical_request_count")
            if blocked_reason:
                raise TrafficPolicyBlocked(blocked_reason)
            self._sleep(max(0.001, ready_at - self._now()))

    def complete(self, lease: DispatchLease, outcome: TrafficOutcome) -> None:
        """Record the result, release dedupe waiters, and update adaptive policy."""
        with self._locked_state() as state:
            dispatched = _dict_value(state, "dispatched")
            raw = dispatched.get(lease.lease_id)
            if not isinstance(raw, dict):
                raise TrafficPolicyError("traffic dispatch completion has no committed lease")
            cache_key = self._validate_lease(raw, lease)
            dispatched.pop(lease.lease_id, None)
            state["completed_request_count"] = _counter(state, "completed_request_count") + 1
            self._release_in_flight(state, lease.lease_id, cache_key)
            self._update_adaptive_state(state, lease, outcome)
            if self._cache_outcome_allowed(raw, outcome):
                record = outcome.cache_record
                if record is not None:
                    self._write_cache_record(cache_key, record)
                    cache = _dict_value(state, "cache")
                    cache[cache_key] = {
                        "file": f"{cache_key}{_CACHE_FILE_SUFFIX}",
                        "expires_at": self._now() + self.config.cache_ttl_seconds,
                    }

    def cancel(self, lease: DispatchLease) -> None:
        """Cancel a reservation that never reached a physical dispatch."""
        with self._locked_state() as state:
            self._cancel_reservation(state, lease.lease_id)

    def should_retry(self, intent: RequestIntent, outcome: TrafficOutcome, attempt: int) -> bool:
        if self.config.mode is not TrafficPolicyMode.ENFORCE:
            return False
        if attempt >= self.config.max_retries:
            return False
        if not intent.retryable or intent.timing_sensitive or intent.method not in {"GET", "HEAD"}:
            return False
        return outcome.transport_error or outcome.status in self.config.retry_statuses

    def record_unmetered_action(self) -> None:
        """Mark an opaque network-capable lane or block it in enforce mode."""
        blocked = False
        with self._locked_state() as state:
            if self.config.mode is TrafficPolicyMode.ENFORCE:
                state["blocked_count"] = _counter(state, "blocked_count") + 1
                blocked = True
            else:
                state["unmetered_action_count"] = _counter(state, "unmetered_action_count") + 1
        if blocked:
            raise TrafficPolicyBlocked(
                "unmetered network-capable actions are blocked by traffic policy"
            )

    def snapshot(self) -> TrafficPolicySnapshot:
        with self._locked_state() as state:
            self._prune_state(state)
            return _snapshot_from_state(state)

    def budget_snapshot(self) -> dict[str, object]:
        """Return the path-free live budget/status view used by planners."""
        with self._locked_state() as state:
            self._prune_state(state)
            snapshot = _snapshot_from_state(state)
            limit = self.config.max_physical_requests
            remaining = (
                None
                if limit is None
                else max(
                    limit - snapshot.physical_request_count - snapshot.reservation_count,
                    0,
                )
            )
            now = self._now()
            if _number(state.get("circuit_open_until")) > now:
                circuit_state = "open"
            elif state.get("half_open_lease"):
                circuit_state = "half_open"
            else:
                circuit_state = "closed"
            return {
                "mode": self.config.mode.value,
                "physical_request_count": snapshot.physical_request_count,
                "max_physical_requests": limit,
                "remaining_physical_requests": remaining,
                "blocked_count": snapshot.blocked_count,
                "circuit_state": circuit_state,
                "circuit_open_count": snapshot.circuit_open_count,
                "cache_hit_count": snapshot.cache_hit_count,
                "retry_count": snapshot.retry_count,
                "accounting_status": snapshot.accounting_status,
            }

    def _acquire_once(
        self,
        intent: RequestIntent,
        *,
        retry: bool,
    ) -> tuple[TrafficDecision | None, float]:
        with self._locked_state() as state:
            self._prune_state(state)
            now = self._now()
            cache_key = intent.fingerprint if self._cache_intent_allowed(intent) else ""
            if self.config.mode is TrafficPolicyMode.ENFORCE and cache_key:
                cached = self._cached_record(state, cache_key)
                if cached is not None:
                    state["cache_hit_count"] = _counter(state, "cache_hit_count") + 1
                    return TrafficDecision(TrafficDecisionKind.CACHE_HIT, cached=cached), now
                owner = str(_dict_value(state, "in_flight").get(cache_key) or "")
                if self.config.deduplicate and owner:
                    reservation = _dict_value(state, "reservations").get(owner)
                    wait_until = now + 0.05
                    if isinstance(reservation, dict):
                        wait_until = min(
                            _number(reservation.get("expires_at"), default=wait_until),
                            wait_until,
                        )
                    return None, wait_until

            half_open = False
            reservations = _dict_value(state, "reservations")
            if self.config.mode is TrafficPolicyMode.ENFORCE:
                open_until = _number(state.get("circuit_open_until"))
                failures = _counter(state, "circuit_failures")
                if open_until > now:
                    state["blocked_count"] = _counter(state, "blocked_count") + 1
                    return (
                        TrafficDecision(
                            TrafficDecisionKind.BLOCKED,
                            reason="traffic circuit is open",
                        ),
                        now,
                    )
                if failures >= self.config.circuit_failure_threshold:
                    if state.get("half_open_lease"):
                        state["blocked_count"] = _counter(state, "blocked_count") + 1
                        return (
                            TrafficDecision(
                                TrafficDecisionKind.BLOCKED,
                                reason="traffic circuit half-open trial is already active",
                            ),
                            now,
                        )
                    half_open = True

                limit = self.config.max_physical_requests
                if limit is not None and (
                    _counter(state, "physical_request_count") + len(reservations) >= limit
                ):
                    state["blocked_count"] = _counter(state, "blocked_count") + 1
                    return (
                        TrafficDecision(
                            TrafficDecisionKind.BLOCKED,
                            reason="whole-run physical request limit reached",
                        ),
                        now,
                    )

            sequence = _counter(state, "sequence") + 1
            state["sequence"] = sequence
            lease_id = f"{os.getpid()}-{sequence}-{secrets.token_hex(8)}"
            if self.config.mode is TrafficPolicyMode.ENFORCE:
                not_before = max(
                    now,
                    _number(state.get("backoff_until")),
                )
                planned_ready = max(
                    not_before,
                    _number(state.get("next_physical_dispatch_at")),
                )
                if self.config.max_rps is not None:
                    planned_ready += len(reservations) / self.config.max_rps
            else:
                not_before = now
                planned_ready = now
            expires_at = planned_ready + self.config.lease_timeout_seconds
            reservation = {
                "sequence": sequence,
                "fingerprint": intent.fingerprint,
                "cache_key": cache_key,
                "created_at": now,
                "not_before": not_before,
                "expires_at": expires_at,
                "half_open": half_open,
                "cacheable": bool(cache_key),
            }
            reservations[lease_id] = reservation
            if cache_key and self.config.deduplicate:
                _dict_value(state, "in_flight")[cache_key] = lease_id
            if half_open:
                state["half_open_lease"] = lease_id
            if retry:
                state["retry_count"] = _counter(state, "retry_count") + 1
            return (
                TrafficDecision(
                    TrafficDecisionKind.DISPATCH,
                    lease=DispatchLease(
                        lease_id=lease_id,
                        sequence=sequence,
                        not_before=not_before,
                        intent_fingerprint=intent.fingerprint,
                        cache_key=cache_key,
                    ),
                ),
                now,
            )

    def _update_adaptive_state(
        self,
        state: dict[str, object],
        lease: DispatchLease,
        outcome: TrafficOutcome,
    ) -> None:
        if self.config.mode is not TrafficPolicyMode.ENFORCE:
            return
        failed = outcome.transport_error or outcome.status in _OVERLOAD_STATUSES
        if not failed:
            state["circuit_failures"] = 0
            state["circuit_open_until"] = 0.0
            state["half_open_lease"] = ""
            return

        failures = _counter(state, "circuit_failures") + 1
        state["circuit_failures"] = failures
        retry_after = _retry_after_seconds(outcome.headers, now=self._now())
        exponential = self.config.backoff_initial_seconds * (2 ** max(0, failures - 1))
        delay = min(self.config.backoff_max_seconds, max(retry_after, exponential))
        state["backoff_until"] = max(
            _number(state.get("backoff_until")),
            self._now() + delay,
        )
        if failures >= self.config.circuit_failure_threshold:
            state["circuit_open_until"] = self._now() + self.config.circuit_open_seconds
            state["circuit_open_count"] = _counter(state, "circuit_open_count") + 1
        if str(state.get("half_open_lease") or "") == lease.lease_id:
            state["half_open_lease"] = ""

    def _cache_intent_allowed(self, intent: RequestIntent) -> bool:
        if not self.config.cache_enabled or not intent.cacheable:
            return False
        if intent.method not in {"GET", "HEAD"} or intent.body:
            return False
        if intent.lane not in self.config.cacheable_lanes:
            return False
        if intent.identity_alias.casefold() not in {"anonymous", "anon"}:
            return False
        if intent.identity_generation not in {None, 0}:
            return False
        names = {str(name).casefold() for name in intent.headers}
        return not names.intersection(_SENSITIVE_REQUEST_HEADERS)

    def _cache_outcome_allowed(
        self,
        reservation: Mapping[str, object],
        outcome: TrafficOutcome,
    ) -> bool:
        record = outcome.cache_record
        if not reservation.get("cacheable") or record is None or outcome.transport_error:
            return False
        if not 200 <= record.status < 300 or record.truncated:
            return False
        if len(record.body_bytes or b"") > self.config.cache_max_body_bytes:
            return False
        lowered = {str(name).casefold(): str(value) for name, value in record.headers.items()}
        if set(lowered).intersection(_SENSITIVE_RESPONSE_HEADERS):
            return False
        cache_control = lowered.get("cache-control", "").casefold()
        if any(
            directive in cache_control
            for directive in ("no-store", "no-cache", "private", "max-age=0")
        ):
            return False
        vary = {item.strip().casefold() for item in lowered.get("vary", "").split(",")}
        return not vary.intersection({"authorization", "cookie", "*"})

    def _cached_record(
        self,
        state: dict[str, object],
        cache_key: str,
    ) -> TrafficCacheRecord | None:
        raw = _dict_value(state, "cache").get(cache_key)
        if not isinstance(raw, dict):
            return None
        if _number(raw.get("expires_at")) <= self._now():
            self._drop_cache_entry(state, cache_key, raw)
            return None
        try:
            return self._read_cache_record(cache_key)
        except TrafficPolicyError:
            self._drop_cache_entry(state, cache_key, raw)
            return None

    def _prune_state(self, state: dict[str, object]) -> None:
        now = self._now()
        reservations = _dict_value(state, "reservations")
        for lease_id, raw in list(reservations.items()):
            if not isinstance(raw, dict) or _number(raw.get("expires_at")) <= now:
                self._cancel_reservation(state, lease_id)
        dispatched = _dict_value(state, "dispatched")
        for lease_id, raw in list(dispatched.items()):
            if isinstance(raw, dict) and _number(raw.get("expires_at")) > now:
                continue
            dispatched.pop(lease_id, None)
            if isinstance(raw, dict):
                self._release_in_flight(
                    state,
                    lease_id,
                    str(raw.get("cache_key") or ""),
                )
            if str(state.get("half_open_lease") or "") == lease_id:
                state["half_open_lease"] = ""
            state["incomplete_request_count"] = _counter(state, "incomplete_request_count") + 1
        cache = _dict_value(state, "cache")
        for key, raw in list(cache.items()):
            if not isinstance(raw, dict) or _number(raw.get("expires_at")) <= now:
                self._drop_cache_entry(state, key, raw if isinstance(raw, dict) else {})

    def _cancel_reservation(self, state: dict[str, object], lease_id: str) -> None:
        raw = _dict_value(state, "reservations").pop(lease_id, None)
        if not isinstance(raw, dict):
            return
        self._release_in_flight(state, lease_id, str(raw.get("cache_key") or ""))
        if str(state.get("half_open_lease") or "") == lease_id:
            state["half_open_lease"] = ""

    @staticmethod
    def _release_in_flight(state: dict[str, object], lease_id: str, cache_key: str) -> None:
        if not cache_key:
            return
        in_flight = _dict_value(state, "in_flight")
        if str(in_flight.get(cache_key) or "") == lease_id:
            in_flight.pop(cache_key, None)

    def _record_blocked(self) -> None:
        with self._locked_state() as state:
            state["blocked_count"] = _counter(state, "blocked_count") + 1

    def _record_deduplicated(self) -> None:
        with self._locked_state() as state:
            state["deduplicated_count"] = _counter(state, "deduplicated_count") + 1

    def _validate_intent_origin(self, intent: RequestIntent) -> None:
        if _target_origin(intent.url) != self.target_origin:
            raise TrafficPolicyBlocked("traffic intent belongs to a different target origin")

    @staticmethod
    def _validate_lease(raw: Mapping[str, object], lease: DispatchLease) -> str:
        if _counter(raw, "sequence") != lease.sequence:
            raise TrafficPolicyError("traffic dispatch lease sequence mismatch")
        fingerprint = _sha256_key(raw.get("fingerprint"), allow_empty=False)
        if fingerprint != lease.intent_fingerprint:
            raise TrafficPolicyError("traffic dispatch lease fingerprint mismatch")
        cache_key = _sha256_key(raw.get("cache_key"), allow_empty=True)
        if cache_key != lease.cache_key:
            raise TrafficPolicyError("traffic dispatch lease cache key mismatch")
        return cache_key

    def _now(self) -> float:
        try:
            return _number(self._clock())
        except TrafficPolicyError as exc:
            raise TrafficPolicyError("traffic policy clock timestamp is invalid") from exc

    def _initial_state(self) -> dict[str, object]:
        now = self._now()
        return {
            "schema": TRAFFIC_POLICY_SCHEMA,
            "version": TRAFFIC_POLICY_VERSION,
            "target_origin": self.target_origin,
            "config": self.config.to_json(),
            "created_at": now,
            "updated_at": now,
            "sequence": 0,
            "physical_request_count": 0,
            "completed_request_count": 0,
            "incomplete_request_count": 0,
            "cache_hit_count": 0,
            "deduplicated_count": 0,
            "retry_count": 0,
            "blocked_count": 0,
            "circuit_open_count": 0,
            "unmetered_action_count": 0,
            "next_physical_dispatch_at": 0.0,
            "backoff_until": 0.0,
            "circuit_failures": 0,
            "circuit_open_until": 0.0,
            "half_open_lease": "",
            "reservations": {},
            "dispatched": {},
            "in_flight": {},
            "cache": {},
        }

    def _validate_state(self, state: Mapping[str, object]) -> None:
        if state.get("schema") != TRAFFIC_POLICY_SCHEMA:
            raise TrafficPolicyError("traffic policy ledger schema is invalid")
        if state.get("version") != TRAFFIC_POLICY_VERSION:
            raise TrafficPolicyError("traffic policy ledger version is unsupported")
        if state.get("target_origin") != self.target_origin:
            raise TrafficPolicyError("traffic policy ledger belongs to a different target")
        if state.get("config") != self.config.to_json():
            raise TrafficPolicyError("traffic policy ledger configuration changed")
        for name in ("reservations", "dispatched", "in_flight", "cache"):
            if not isinstance(state.get(name), dict):
                raise TrafficPolicyError(f"traffic policy ledger {name} is invalid")
        for name in (
            "sequence",
            "physical_request_count",
            "completed_request_count",
            "incomplete_request_count",
            "cache_hit_count",
            "deduplicated_count",
            "retry_count",
            "blocked_count",
            "circuit_open_count",
            "unmetered_action_count",
            "circuit_failures",
        ):
            _counter(state, name)
        for name in (
            "created_at",
            "updated_at",
            "next_physical_dispatch_at",
            "backoff_until",
            "circuit_open_until",
        ):
            _number(state.get(name))
        for collection_name in ("reservations", "dispatched"):
            collection = state.get(collection_name)
            assert isinstance(collection, dict)
            for lease_id, raw in collection.items():
                if not isinstance(lease_id, str) or not lease_id or not isinstance(raw, dict):
                    raise TrafficPolicyError(
                        f"traffic policy ledger {collection_name} lease is invalid"
                    )
                for name in ("created_at", "not_before", "expires_at"):
                    _number(raw.get(name))
                if _counter(raw, "sequence") == 0:
                    raise TrafficPolicyError(
                        f"traffic policy ledger {collection_name} sequence is invalid"
                    )
                _sha256_key(raw.get("fingerprint"), allow_empty=False)
                _sha256_key(raw.get("cache_key"), allow_empty=True)
                if collection_name == "dispatched":
                    _number(raw.get("dispatched_at"))
        cache = state.get("cache")
        assert isinstance(cache, dict)
        for key, raw in cache.items():
            if not isinstance(key, str) or not key or not isinstance(raw, dict):
                raise TrafficPolicyError("traffic policy ledger cache entry is invalid")
            _sha256_key(key, allow_empty=False)
            if raw.get("file") != f"{key}{_CACHE_FILE_SUFFIX}":
                raise TrafficPolicyError("traffic policy ledger cache filename is invalid")
            _number(raw.get("expires_at"))

    def _locked_state(self, *, create: bool = False) -> _LockedTrafficState:
        return _LockedTrafficState(self, create=create)

    def _read_state(self, *, create: bool) -> dict[str, object]:
        if self.state_path.is_symlink():
            raise TrafficPolicyError("traffic policy ledger cannot be a symlink")
        if not self.state_path.exists():
            if not create:
                raise TrafficPolicyError("traffic policy ledger does not exist")
            state = self._initial_state()
            self._write_state(state)
            return state
        _validate_private_regular_file(self.state_path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.state_path, flags)
        try:
            _validate_private_regular_fd(fd, self.state_path)
            raw = os.read(fd, _MAX_LEDGER_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > _MAX_LEDGER_BYTES:
            raise TrafficPolicyError("traffic policy ledger is too large")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrafficPolicyError("traffic policy ledger is malformed") from exc
        if not isinstance(value, dict):
            raise TrafficPolicyError("traffic policy ledger must be a JSON object")
        self._validate_state(value)
        return value

    def _write_state(self, state: dict[str, object]) -> None:
        state["updated_at"] = self._now()
        payload = _canonical_json(state)
        if len(payload) > _MAX_LEDGER_BYTES:
            raise TrafficPolicyError("traffic policy ledger exceeded its size limit")
        _atomic_private_write(self.state_path, payload)

    def _write_cache_record(self, key: str, record: TrafficCacheRecord) -> None:
        self._ensure_cache_directory()
        _atomic_private_write(
            self.cache_path / f"{key}{_CACHE_FILE_SUFFIX}",
            _canonical_json(record.to_json()),
        )

    def _read_cache_record(self, key: str) -> TrafficCacheRecord:
        self._ensure_cache_directory()
        path = self.cache_path / f"{key}{_CACHE_FILE_SUFFIX}"
        _validate_private_regular_file(path)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _validate_private_regular_fd(fd, path)
            raw = os.read(fd, (self.config.cache_max_body_bytes * 2) + 100_001)
        finally:
            os.close(fd)
        if len(raw) > (self.config.cache_max_body_bytes * 2) + 100_000:
            raise TrafficPolicyError("traffic cache record is too large")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrafficPolicyError("traffic cache record is malformed") from exc
        if not isinstance(value, dict):
            raise TrafficPolicyError("traffic cache record must be a JSON object")
        return TrafficCacheRecord.from_json(value)

    def _drop_cache_entry(
        self,
        state: dict[str, object],
        key: str,
        raw: Mapping[str, object],
    ) -> None:
        _dict_value(state, "cache").pop(key, None)
        filename = str(raw.get("file") or "")
        if filename != f"{key}{_CACHE_FILE_SUFFIX}":
            return
        path = self.cache_path / filename
        try:
            if path.is_file() and not path.is_symlink():
                path.unlink()
        except OSError:
            return

    def _ensure_cache_directory(self) -> None:
        if self.cache_path.is_symlink():
            raise TrafficPolicyError("traffic cache path cannot be a symlink")
        if self.cache_path.exists():
            info = self.cache_path.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise TrafficPolicyError("traffic cache path is not a real directory")
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise TrafficPolicyError("traffic cache directory is not private")
            return
        try:
            self.cache_path.mkdir(mode=0o700)
        except FileExistsError:
            self._ensure_cache_directory()


class _LockedTrafficState:
    def __init__(self, controller: TrafficPolicyController, *, create: bool) -> None:
        self._controller = controller
        self._create = create
        self._fd = -1
        self._state: dict[str, object] | None = None

    def __enter__(self) -> dict[str, object]:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            self._fd = os.open(self._controller.lock_path, flags, 0o600)
        except OSError as exc:
            raise TrafficPolicyError("traffic policy lock file is unsafe") from exc
        try:
            _validate_private_regular_fd(self._fd, self._controller.lock_path)
            fcntl.flock(self._fd, fcntl.LOCK_EX)
            self._state = self._controller._read_state(create=self._create)
            return self._state
        except BaseException:
            os.close(self._fd)
            self._fd = -1
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del traceback
        try:
            if exc_type is None and self._state is not None:
                self._controller._write_state(self._state)
        finally:
            if self._fd >= 0:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
                self._fd = -1


def _target_origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("traffic policy target must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("traffic policy target cannot contain userinfo")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    default = 443 if parsed.scheme.lower() == "https" else 80
    netloc = host if port in {None, default} else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


def _retry_after_seconds(headers: Mapping[str, str], *, now: float) -> float:
    value = next(
        (str(item) for name, item in headers.items() if str(name).casefold() == "retry-after"),
        "",
    ).strip()
    if not value:
        return 0.0
    try:
        seconds = float(value)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            seconds = parsed.timestamp() - now
        except (OverflowError, TypeError, ValueError):
            return 0.0
    if not math.isfinite(seconds):
        return 0.0
    return max(0.0, seconds)


def _validate_private_regular_file(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise TrafficPolicyError(f"private traffic file does not exist: {path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise TrafficPolicyError(f"private traffic file is not regular: {path.name}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise TrafficPolicyError(f"private traffic file has unsafe ownership or mode: {path.name}")


def _validate_private_regular_fd(fd: int, path: Path) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise TrafficPolicyError(f"private traffic file is not regular: {path.name}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise TrafficPolicyError(f"private traffic file has unsafe ownership or mode: {path.name}")


def _atomic_private_write(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise TrafficPolicyError(f"private traffic file cannot be a symlink: {path.name}")
    if path.exists():
        _validate_private_regular_file(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _dict_value(state: dict[str, object], name: str) -> dict[str, Any]:
    value = state.get(name)
    if not isinstance(value, dict):
        raise TrafficPolicyError(f"traffic policy ledger {name} is invalid")
    return value


def _counter(state: Mapping[str, object], name: str) -> int:
    value = state.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TrafficPolicyError(f"traffic policy ledger counter {name} is invalid")
    return value


def _sha256_key(value: object, *, allow_empty: bool) -> str:
    if allow_empty and value == "":
        return ""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrafficPolicyError("traffic policy ledger digest is invalid")
    return value


def _number(value: object, *, default: float = 0.0) -> float:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TrafficPolicyError("traffic policy ledger timestamp is invalid")
    try:
        number = float(value)
    except OverflowError as exc:
        raise TrafficPolicyError("traffic policy ledger timestamp is invalid") from exc
    if not math.isfinite(number):
        raise TrafficPolicyError("traffic policy ledger timestamp is invalid")
    return number


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TrafficPolicyError("traffic policy configuration list is invalid")
    return value


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise TrafficPolicyError("traffic policy configuration boolean is invalid")
    return value


def _int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TrafficPolicyError("traffic policy configuration integer is invalid")
    return value


def _float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TrafficPolicyError("traffic policy configuration number is invalid")
    try:
        number = float(value)
    except OverflowError as exc:
        raise TrafficPolicyError("traffic policy configuration number is invalid") from exc
    if not math.isfinite(number):
        raise TrafficPolicyError("traffic policy configuration number is invalid")
    return number


def _optional_int(value: object) -> int | None:
    return None if value is None else _int(value)


def _optional_float(value: object) -> float | None:
    return None if value is None else _float(value)


def _positive_number(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be positive and finite")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be positive and finite") from exc
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be positive and finite")


def _positive_int(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _non_negative_int(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


TrafficController = TrafficPolicyController


def load_traffic_policy_snapshot(state_path: str | Path) -> TrafficPolicyInspection:
    """Read and validate a durable ledger without mutating terminal state."""
    path = Path(state_path).expanduser().absolute()
    lock_path = path.with_name(f"{path.name}.lock")
    if path.is_symlink() or lock_path.is_symlink():
        raise TrafficPolicyError("traffic policy inspection path cannot be a symlink")
    _validate_private_regular_file(path)
    _validate_private_regular_file(lock_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(lock_path, flags)
    except OSError as exc:
        raise TrafficPolicyError("traffic policy inspection lock is unsafe") from exc
    try:
        _validate_private_regular_fd(lock_fd, lock_path)
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        state = _read_private_json(path, maximum_bytes=_MAX_LEDGER_BYTES)
        raw_config = state.get("config")
        if not isinstance(raw_config, dict):
            raise TrafficPolicyError("traffic policy ledger configuration is invalid")
        config = TrafficPolicyConfig.from_json(raw_config)
        target_origin = str(state.get("target_origin") or "")
        try:
            canonical_origin = _target_origin(target_origin)
        except ValueError as exc:
            raise TrafficPolicyError("traffic policy ledger target is invalid") from exc
        if canonical_origin != target_origin:
            raise TrafficPolicyError("traffic policy ledger target is not canonical")
        controller = TrafficPolicyController(path, target_origin, config)
        controller._validate_state(state)
        snapshot = _snapshot_from_state(state)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return TrafficPolicyInspection(
        state_path=str(path),
        target_origin=target_origin,
        config=config,
        snapshot=snapshot,
    )


def _snapshot_from_state(state: dict[str, object]) -> TrafficPolicySnapshot:
    unmetered = _counter(state, "unmetered_action_count")
    return TrafficPolicySnapshot(
        physical_request_count=_counter(state, "physical_request_count"),
        completed_request_count=_counter(state, "completed_request_count"),
        incomplete_request_count=_counter(state, "incomplete_request_count"),
        pending_dispatch_count=len(_dict_value(state, "dispatched")),
        reservation_count=len(_dict_value(state, "reservations")),
        cache_hit_count=_counter(state, "cache_hit_count"),
        deduplicated_count=_counter(state, "deduplicated_count"),
        retry_count=_counter(state, "retry_count"),
        blocked_count=_counter(state, "blocked_count"),
        circuit_open_count=_counter(state, "circuit_open_count"),
        unmetered_action_count=unmetered,
        accounting_status="lower_bound" if unmetered else "exact",
    )


def _read_private_json(path: Path, *, maximum_bytes: int) -> dict[str, object]:
    _validate_private_regular_file(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _validate_private_regular_fd(fd, path)
        raw = os.read(fd, maximum_bytes + 1)
    finally:
        os.close(fd)
    if len(raw) > maximum_bytes:
        raise TrafficPolicyError(f"private traffic file is too large: {path.name}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrafficPolicyError(f"private traffic file is malformed: {path.name}") from exc
    if not isinstance(value, dict):
        raise TrafficPolicyError(f"private traffic file must be a JSON object: {path.name}")
    return value


__all__ = [
    "TRAFFIC_POLICY_SCHEMA",
    "TRAFFIC_POLICY_VERSION",
    "DispatchLease",
    "RequestIntent",
    "TrafficCacheRecord",
    "TrafficController",
    "TrafficDecision",
    "TrafficDecisionKind",
    "TrafficOutcome",
    "TrafficPolicyBlocked",
    "TrafficPolicyConfig",
    "TrafficPolicyController",
    "TrafficPolicyError",
    "TrafficPolicyInspection",
    "TrafficPolicyMode",
    "TrafficPolicySnapshot",
    "load_traffic_policy_snapshot",
]
