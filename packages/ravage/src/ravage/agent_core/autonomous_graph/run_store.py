# Durable autonomous-graph coordination state is committed through one SQLite log.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence
    from pathlib import Path

_SCHEMA_VERSION = 1
_DEFAULT_BUSY_TIMEOUT_SECONDS = 5.0
_MAX_IDENTITY_CHARS = 512
_SHA256_HEX_CHARS = 64
_ACTION_APPLIED_PREFIX = "action-applied:"


class RunStoreError(RuntimeError):
    """Base class for durable run-store invariant failures."""


class RunStoreSchemaError(RunStoreError):
    """Raised when a database has an unsupported or malformed schema."""


class UnknownRunError(RunStoreError):
    """Raised when a run has not been created by lease acquisition."""


class UnknownActionError(RunStoreError):
    """Raised when an action key has not been reserved for a run."""


class RunLeaseConflictError(RunStoreError):
    """Raised when another live owner currently holds a run lease."""


class RunLeaseLostError(RunStoreError):
    """Raised when a stale, expired, or fenced lease attempts a write."""


class RunStoreIdempotencyError(RunStoreError):
    """Raised when an idempotency key is reused for different content."""


class ProjectionConflictError(RunStoreError):
    """Raised when a projection compare-and-swap revision is stale."""


class ActionTransitionError(RunStoreError):
    """Raised when an action lifecycle transition is unsafe."""


class ActionLifecycle(StrEnum):
    RESERVED = "reserved"
    STARTED = "started"
    SETTLED = "settled"
    UNKNOWN_OUTCOME = "unknown_outcome"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class RunLease:
    run_id: str
    owner_id: str
    token: str
    epoch: int
    expires_at: float

    def active_at(self, now: float) -> bool:
        return self.expires_at > now


@dataclass(frozen=True)
class ProjectionUpdate:
    """One compare-and-swap projection update within an event commit."""

    name: str
    payload: object
    expected_revision: int


@dataclass(frozen=True)
class ProjectionRecord:
    run_id: str
    name: str
    revision: int
    payload: object
    payload_digest: str
    updated_at: float


@dataclass(frozen=True)
class RunEvent:
    run_id: str
    sequence: int
    event_id: str
    idempotency_key: str
    kind: str
    action_key: str
    payload: object
    commit_digest: str
    projection_revisions: Mapping[str, int]
    created_at: float


@dataclass(frozen=True)
class EventCommit:
    event: RunEvent
    replayed: bool


@dataclass(frozen=True)
class ActionRecord:
    run_id: str
    action_id: str
    action_key: str
    node_id: str
    lifecycle: ActionLifecycle
    request: object
    request_digest: str
    result: object | None
    settlement_digest: str
    reservation_epoch: int
    started_epoch: int | None
    settled_epoch: int | None
    attempt: int
    unknown_reason: str
    created_at: float
    updated_at: float


@dataclass(frozen=True)
class ActionReservation:
    action: ActionRecord
    replayed: bool


@dataclass(frozen=True)
class ActionStart:
    action: ActionRecord
    should_execute: bool


@dataclass(frozen=True)
class RecoveryReport:
    """Fail-closed classification after a new owner takes over a run."""

    marked_unknown: tuple[ActionRecord, ...]
    retryable_reserved: tuple[ActionRecord, ...]
    unknown_outcomes: tuple[ActionRecord, ...]
    settled: tuple[ActionRecord, ...]


@dataclass(frozen=True)
class RecoverySnapshot:
    run_id: str
    lease: RunLease | None
    last_event_sequence: int
    actions: tuple[ActionRecord, ...]
    projections: tuple[ProjectionRecord, ...]


@dataclass(frozen=True)
class RunStore:
    """
    Transactional write-ahead state for autonomous graph runs.

    Every mutating API is fenced by a durable ownership lease. Action keys are
    idempotent, and a started action from an expired ownership epoch is never
    silently retried: recovery first moves it to ``unknown_outcome``. Event and
    projection writes share one ``BEGIN IMMEDIATE`` transaction.
    """

    path: Path
    busy_timeout_seconds: float = _DEFAULT_BUSY_TIMEOUT_SECONDS

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        busy_timeout_seconds: float = _DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> RunStore:
        if not math.isfinite(busy_timeout_seconds) or busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be finite and greater than zero")
        path.parent.mkdir(parents=True, exist_ok=True)
        store = cls(path=path, busy_timeout_seconds=busy_timeout_seconds)
        store._initialize()
        store._secure_database_files()
        return store

    def acquire_lease(
        self,
        *,
        run_id: str,
        owner_id: str,
        ttl_seconds: float,
        now: float | None = None,
    ) -> RunLease:
        run = _identity(run_id, "run_id")
        owner = _identity(owner_id, "owner_id")
        timestamp = _timestamp(now)
        ttl = _ttl(ttl_seconds)
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM graph_runs WHERE run_id = ?",
                (run,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO graph_runs(
                        run_id, owner_id, lease_token, lease_epoch,
                        lease_expires_at, created_at, updated_at
                    ) VALUES (?, NULL, NULL, 0, NULL, ?, ?)
                    """,
                    (run, timestamp, timestamp),
                )
                row = connection.execute(
                    "SELECT * FROM graph_runs WHERE run_id = ?",
                    (run,),
                ).fetchone()
            assert row is not None
            current_owner = str(row["owner_id"] or "")
            current_expiry = _optional_float(row["lease_expires_at"])
            if current_owner and current_expiry is not None and current_expiry > timestamp:
                if current_owner != owner:
                    raise RunLeaseConflictError(f"run {run!r} is leased by another live owner")
                return _lease_from_row(row)

            epoch = int(row["lease_epoch"]) + 1
            token = secrets.token_urlsafe(32)
            expires_at = timestamp + ttl
            connection.execute(
                """
                UPDATE graph_runs
                SET owner_id = ?, lease_token = ?, lease_epoch = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (owner, token, epoch, expires_at, timestamp, run),
            )
            return RunLease(
                run_id=run,
                owner_id=owner,
                token=token,
                epoch=epoch,
                expires_at=expires_at,
            )

    def renew_lease(
        self,
        lease: RunLease,
        *,
        ttl_seconds: float,
        now: float | None = None,
    ) -> RunLease:
        timestamp = _timestamp(now)
        ttl = _ttl(ttl_seconds)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            expires_at = timestamp + ttl
            connection.execute(
                """
                UPDATE graph_runs
                SET lease_expires_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (expires_at, timestamp, lease.run_id),
            )
            return RunLease(
                run_id=lease.run_id,
                owner_id=lease.owner_id,
                token=lease.token,
                epoch=lease.epoch,
                expires_at=expires_at,
            )

    def release_lease(
        self,
        lease: RunLease,
        *,
        now: float | None = None,
    ) -> None:
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            connection.execute(
                """
                UPDATE graph_runs
                SET owner_id = NULL, lease_token = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE run_id = ?
                """,
                (timestamp, lease.run_id),
            )

    def reserve_action(
        self,
        lease: RunLease,
        *,
        action_key: str,
        node_id: str,
        request: object,
        now: float | None = None,
    ) -> ActionReservation:
        key = _identity(action_key, "action_key")
        node = _identity(node_id, "node_id")
        request_json = _canonical_json(request)
        request_digest = _digest_text(request_json)
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            row = self._action_row(connection, lease.run_id, key)
            if row is not None:
                action = _action_from_row(row)
                if action.request_digest != request_digest or action.node_id != node:
                    raise RunStoreIdempotencyError(
                        "action key is already reserved for a different request or node"
                    )
                return ActionReservation(action=action, replayed=True)

            action_id = f"action:{_digest_text(f'{lease.run_id}\u0000{key}')}"
            connection.execute(
                """
                INSERT INTO graph_actions(
                    run_id, action_id, action_key, node_id, lifecycle,
                    request_json, request_digest, result_json, settlement_digest,
                    reservation_epoch, started_epoch, settled_epoch, attempt,
                    unknown_reason, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, '', ?, NULL, NULL, 0, '', ?, ?)
                """,
                (
                    lease.run_id,
                    action_id,
                    key,
                    node,
                    ActionLifecycle.RESERVED.value,
                    request_json,
                    request_digest,
                    lease.epoch,
                    timestamp,
                    timestamp,
                ),
            )
            payload = {
                "action_id": action_id,
                "action_key": key,
                "node_id": node,
                "request_digest": request_digest,
                "reservation_epoch": lease.epoch,
            }
            self._insert_event(
                connection,
                run_id=lease.run_id,
                idempotency_key=f"{action_id}:reserved",
                kind="action_reserved",
                action_key=key,
                payload_json=_canonical_json(payload),
                commit_digest=_digest_json(payload),
                projection_revisions={},
                created_at=timestamp,
            )
            return ActionReservation(
                action=self._required_action(connection, lease.run_id, key),
                replayed=False,
            )

    def start_action(
        self,
        lease: RunLease,
        *,
        action_key: str,
        now: float | None = None,
    ) -> ActionStart:
        key = _identity(action_key, "action_key")
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            action = self._required_action(connection, lease.run_id, key)
            if action.lifecycle is not ActionLifecycle.RESERVED:
                return ActionStart(action=action, should_execute=False)
            attempt = action.attempt + 1
            connection.execute(
                """
                UPDATE graph_actions
                SET lifecycle = ?, started_epoch = ?, attempt = ?,
                    unknown_reason = '', updated_at = ?
                WHERE run_id = ? AND action_key = ? AND lifecycle = ?
                """,
                (
                    ActionLifecycle.STARTED.value,
                    lease.epoch,
                    attempt,
                    timestamp,
                    lease.run_id,
                    key,
                    ActionLifecycle.RESERVED.value,
                ),
            )
            payload = {
                "action_id": action.action_id,
                "action_key": key,
                "attempt": attempt,
                "lease_epoch": lease.epoch,
            }
            self._insert_event(
                connection,
                run_id=lease.run_id,
                idempotency_key=f"{action.action_id}:started:{attempt}",
                kind="action_started",
                action_key=key,
                payload_json=_canonical_json(payload),
                commit_digest=_digest_json(payload),
                projection_revisions={},
                created_at=timestamp,
            )
            return ActionStart(
                action=self._required_action(connection, lease.run_id, key),
                should_execute=True,
            )

    def settle_action(
        self,
        lease: RunLease,
        *,
        action_key: str,
        result: object,
        projections: Sequence[ProjectionUpdate] = (),
        now: float | None = None,
    ) -> ActionRecord:
        return self._settle_action(
            lease,
            action_key=action_key,
            result=result,
            projections=projections,
            reconciliation_reason="",
            now=now,
        )

    def mark_unknown_outcome(
        self,
        lease: RunLease,
        *,
        action_key: str,
        reason: str,
        now: float | None = None,
    ) -> ActionRecord:
        key = _identity(action_key, "action_key")
        explanation = _identity(reason, "reason")
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            action = self._required_action(connection, lease.run_id, key)
            if action.lifecycle is ActionLifecycle.UNKNOWN_OUTCOME:
                return action
            if action.lifecycle is not ActionLifecycle.STARTED:
                raise ActionTransitionError(
                    "only a started action can become unknown_outcome; "
                    f"got {action.lifecycle.value}"
                )
            return self._mark_action_unknown(
                connection,
                action=action,
                reason=explanation,
                created_at=timestamp,
            )

    def cancel_reserved_action(
        self,
        lease: RunLease,
        *,
        action_key: str,
        reason: str,
        now: float | None = None,
    ) -> ActionRecord:
        """Idempotently close a reservation proven not to have executed."""
        key = _identity(action_key, "action_key")
        explanation = _identity(reason, "reason")
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            action = self._required_action(connection, lease.run_id, key)
            if action.lifecycle is ActionLifecycle.CANCELLED:
                return action
            if action.lifecycle is not ActionLifecycle.RESERVED:
                raise ActionTransitionError(
                    f"only a reserved action can be cancelled; got {action.lifecycle.value}"
                )
            connection.execute(
                """
                UPDATE graph_actions
                SET lifecycle = ?, updated_at = ?
                WHERE run_id = ? AND action_key = ? AND lifecycle = ?
                """,
                (
                    ActionLifecycle.CANCELLED.value,
                    timestamp,
                    lease.run_id,
                    key,
                    ActionLifecycle.RESERVED.value,
                ),
            )
            payload = {
                "action_id": action.action_id,
                "action_key": key,
                "reason_digest": _digest_text(explanation),
            }
            self._insert_event(
                connection,
                run_id=lease.run_id,
                idempotency_key=f"{action.action_id}:cancelled",
                kind="action_cancelled",
                action_key=key,
                payload_json=_canonical_json(payload),
                commit_digest=_digest_json(payload),
                projection_revisions={},
                created_at=timestamp,
            )
            return self._required_action(connection, lease.run_id, key)

    def mark_action_applied(  # noqa: PLR0913 - application identity is explicit.
        self,
        lease: RunLease,
        *,
        action_key: str,
        state_digest: str,
        evidence_refs: Sequence[str] = (),
        disposition: str,
        now: float | None = None,
    ) -> EventCommit:
        """Atomically append the post-settlement application marker and projection."""
        key = _identity(action_key, "action_key")
        state = _sha256_digest(state_digest, "state_digest")
        resolution = _identity(disposition, "disposition")
        refs = tuple(sorted({str(item).strip() for item in evidence_refs if str(item).strip()}))
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            action = self._required_action(connection, lease.run_id, key)
            if action.lifecycle is not ActionLifecycle.SETTLED:
                raise ActionTransitionError(
                    f"only a settled action can be marked applied; got {action.lifecycle.value}"
                )
            payload = {
                "action_id": action.action_id,
                "action_key": key,
                "state_digest": state,
                "evidence_refs": list(refs),
                "disposition": resolution,
            }
            payload_json = _canonical_json(payload)
            commit_digest = _digest_text(payload_json)
            idempotency_key = f"{action.action_id}:applied"
            prior = connection.execute(
                """
                SELECT * FROM graph_events
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (lease.run_id, idempotency_key),
            ).fetchone()
            if prior is not None:
                event = _event_from_row(prior)
                if event.commit_digest != commit_digest:
                    raise RunStoreIdempotencyError(
                        "action application marker already has different content"
                    )
                return EventCommit(event=event, replayed=True)
            projection_name = _application_projection_name(action.action_id)
            revisions = self._apply_projection_updates(
                connection,
                run_id=lease.run_id,
                updates=(
                    _NormalizedProjectionUpdate(
                        name=projection_name,
                        payload_json=payload_json,
                        payload_digest=commit_digest,
                        expected_revision=0,
                    ),
                ),
                updated_at=timestamp,
            )
            event = self._insert_event(
                connection,
                run_id=lease.run_id,
                idempotency_key=idempotency_key,
                kind="action_applied",
                action_key=key,
                payload_json=payload_json,
                commit_digest=commit_digest,
                projection_revisions=revisions,
                created_at=timestamp,
            )
            return EventCommit(event=event, replayed=False)

    def recover_interrupted_actions(
        self,
        lease: RunLease,
        *,
        now: float | None = None,
    ) -> RecoveryReport:
        """Fence started work from prior lease epochs without silently retrying it."""
        timestamp = _timestamp(now)
        marked: list[ActionRecord] = []
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            rows = connection.execute(
                """
                SELECT * FROM graph_actions
                WHERE run_id = ? AND lifecycle = ? AND started_epoch != ?
                ORDER BY created_at, action_key
                """,
                (lease.run_id, ActionLifecycle.STARTED.value, lease.epoch),
            ).fetchall()
            marked.extend(
                self._mark_action_unknown(
                    connection,
                    action=_action_from_row(row),
                    reason="lease_epoch_changed_before_settlement",
                    created_at=timestamp,
                )
                for row in rows
            )
            actions = self._list_actions(connection, lease.run_id)
            return RecoveryReport(
                marked_unknown=tuple(marked),
                retryable_reserved=tuple(
                    action for action in actions if action.lifecycle is ActionLifecycle.RESERVED
                ),
                unknown_outcomes=tuple(
                    action
                    for action in actions
                    if action.lifecycle is ActionLifecycle.UNKNOWN_OUTCOME
                ),
                settled=tuple(
                    action for action in actions if action.lifecycle is ActionLifecycle.SETTLED
                ),
            )

    def reconcile_unknown_as_retryable(
        self,
        lease: RunLease,
        *,
        action_key: str,
        reason: str,
        now: float | None = None,
    ) -> ActionRecord:
        key = _identity(action_key, "action_key")
        explanation = _identity(reason, "reason")
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            action = self._required_action(connection, lease.run_id, key)
            if action.lifecycle is not ActionLifecycle.UNKNOWN_OUTCOME:
                raise ActionTransitionError(
                    "only an unknown_outcome action can be reconciled as retryable"
                )
            connection.execute(
                """
                UPDATE graph_actions
                SET lifecycle = ?, started_epoch = NULL, unknown_reason = '', updated_at = ?
                WHERE run_id = ? AND action_key = ?
                """,
                (ActionLifecycle.RESERVED.value, timestamp, lease.run_id, key),
            )
            payload = {
                "action_id": action.action_id,
                "action_key": key,
                "attempt": action.attempt,
                "reason": explanation,
                "resolution": "not_applied_retryable",
            }
            self._insert_event(
                connection,
                run_id=lease.run_id,
                idempotency_key=f"{action.action_id}:retryable:{action.attempt}",
                kind="action_reconciled",
                action_key=key,
                payload_json=_canonical_json(payload),
                commit_digest=_digest_json(payload),
                projection_revisions={},
                created_at=timestamp,
            )
            return self._required_action(connection, lease.run_id, key)

    def reconcile_unknown_as_settled(  # noqa: PLR0913 - transaction inputs are explicit.
        self,
        lease: RunLease,
        *,
        action_key: str,
        result: object,
        reason: str,
        projections: Sequence[ProjectionUpdate] = (),
        now: float | None = None,
    ) -> ActionRecord:
        return self._settle_action(
            lease,
            action_key=action_key,
            result=result,
            projections=projections,
            reconciliation_reason=_identity(reason, "reason"),
            now=now,
        )

    def commit_event_and_projections(  # noqa: PLR0913 - event identity is explicit.
        self,
        lease: RunLease,
        *,
        idempotency_key: str,
        kind: str,
        payload: object,
        projections: Sequence[ProjectionUpdate],
        action_key: str = "",
        now: float | None = None,
    ) -> EventCommit:
        """Atomically append one event and compare-and-swap its projections."""
        key = _identity(idempotency_key, "idempotency_key")
        event_kind = _identity(kind, "kind")
        linked_action = action_key.strip()
        payload_json = _canonical_json(payload)
        normalized = _normalize_projection_updates(projections)
        digest = _event_commit_digest(
            idempotency_key=key,
            kind=event_kind,
            action_key=linked_action,
            payload_json=payload_json,
            projections=normalized,
        )
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            prior = connection.execute(
                """
                SELECT * FROM graph_events
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (lease.run_id, key),
            ).fetchone()
            if prior is not None:
                event = _event_from_row(prior)
                if event.commit_digest != digest:
                    raise RunStoreIdempotencyError(
                        "event idempotency key is already committed with different content"
                    )
                return EventCommit(event=event, replayed=True)

            revisions = self._apply_projection_updates(
                connection,
                run_id=lease.run_id,
                updates=normalized,
                updated_at=timestamp,
            )
            event = self._insert_event(
                connection,
                run_id=lease.run_id,
                idempotency_key=key,
                kind=event_kind,
                action_key=linked_action,
                payload_json=payload_json,
                commit_digest=digest,
                projection_revisions=revisions,
                created_at=timestamp,
            )
            return EventCommit(event=event, replayed=False)

    def action(self, run_id: str, action_key: str) -> ActionRecord | None:
        run = _identity(run_id, "run_id")
        key = _identity(action_key, "action_key")
        with self._connection() as connection:
            row = self._action_row(connection, run, key)
            return _action_from_row(row) if row is not None else None

    def actions(
        self,
        run_id: str,
        *,
        lifecycle: ActionLifecycle | None = None,
    ) -> tuple[ActionRecord, ...]:
        run = _identity(run_id, "run_id")
        with self._connection() as connection:
            if lifecycle is None:
                return tuple(self._list_actions(connection, run))
            rows = connection.execute(
                """
                SELECT * FROM graph_actions
                WHERE run_id = ? AND lifecycle = ?
                ORDER BY created_at, action_key
                """,
                (run, lifecycle.value),
            ).fetchall()
            return tuple(_action_from_row(row) for row in rows)

    def unreconciled_actions(self, run_id: str) -> tuple[ActionRecord, ...]:
        """
        Return actions that make a successful run handoff unsafe.

        A cancelled reservation is known not to have executed. A settled action
        is safe only after the worker atomically records its post-settlement
        application marker. Every other lifecycle remains fail-closed.
        """
        run = _identity(run_id, "run_id")
        with self._connection() as connection:
            actions = self._list_actions(connection, run)
            applied_names = {
                str(row["name"])
                for row in connection.execute(
                    """
                    SELECT name FROM graph_projections
                    WHERE run_id = ? AND name LIKE ?
                    """,
                    (run, f"{_ACTION_APPLIED_PREFIX}%"),
                ).fetchall()
            }
            return tuple(
                action
                for action in actions
                if not (
                    action.lifecycle is ActionLifecycle.CANCELLED
                    or (
                        action.lifecycle is ActionLifecycle.SETTLED
                        and _application_projection_name(action.action_id) in applied_names
                    )
                )
            )

    def projection(self, run_id: str, name: str) -> ProjectionRecord | None:
        run = _identity(run_id, "run_id")
        projection_name = _identity(name, "projection name")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM graph_projections
                WHERE run_id = ? AND name = ?
                """,
                (run, projection_name),
            ).fetchone()
            return _projection_from_row(row) if row is not None else None

    def events(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 1_000,
    ) -> tuple[RunEvent, ...]:
        run = _identity(run_id, "run_id")
        if after_sequence < 0:
            raise ValueError("after_sequence cannot be negative")
        if limit <= 0:
            raise ValueError("event limit must be greater than zero")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM graph_events
                WHERE run_id = ? AND sequence > ?
                ORDER BY sequence LIMIT ?
                """,
                (run, after_sequence, limit),
            ).fetchall()
            return tuple(_event_from_row(row) for row in rows)

    def recovery_snapshot(self, run_id: str) -> RecoverySnapshot:
        run = _identity(run_id, "run_id")
        with self._connection() as connection:
            run_row = connection.execute(
                "SELECT * FROM graph_runs WHERE run_id = ?",
                (run,),
            ).fetchone()
            if run_row is None:
                raise UnknownRunError(f"unknown run: {run}")
            projection_rows = connection.execute(
                "SELECT * FROM graph_projections WHERE run_id = ? ORDER BY name",
                (run,),
            ).fetchall()
            sequence_row = connection.execute(
                """
                SELECT COALESCE(MAX(sequence), 0) AS sequence
                FROM graph_events WHERE run_id = ?
                """,
                (run,),
            ).fetchone()
            lease = (
                _lease_from_row(run_row)
                if run_row["owner_id"] is not None
                and run_row["lease_token"] is not None
                and run_row["lease_expires_at"] is not None
                else None
            )
            return RecoverySnapshot(
                run_id=run,
                lease=lease,
                last_event_sequence=int(sequence_row["sequence"]),
                actions=tuple(self._list_actions(connection, run)),
                projections=tuple(_projection_from_row(row) for row in projection_rows),
            )

    def _settle_action(  # noqa: PLR0913 - shared settlement inputs are explicit.
        self,
        lease: RunLease,
        *,
        action_key: str,
        result: object,
        projections: Sequence[ProjectionUpdate],
        reconciliation_reason: str,
        now: float | None,
    ) -> ActionRecord:
        key = _identity(action_key, "action_key")
        result_json = _canonical_json(result)
        normalized = _normalize_projection_updates(projections)
        settlement_digest = _settlement_digest(
            result_json=result_json,
            projections=normalized,
            reconciliation_reason=reconciliation_reason,
        )
        timestamp = _timestamp(now)
        with self._write_transaction() as connection:
            self._require_lease(connection, lease, now=timestamp)
            action = self._required_action(connection, lease.run_id, key)
            if action.lifecycle is ActionLifecycle.SETTLED:
                if action.settlement_digest != settlement_digest:
                    raise RunStoreIdempotencyError(
                        "action is already settled with a different result or projection commit"
                    )
                return action
            expected = (
                ActionLifecycle.UNKNOWN_OUTCOME
                if reconciliation_reason
                else ActionLifecycle.STARTED
            )
            if action.lifecycle is not expected:
                raise ActionTransitionError(
                    f"cannot settle {action.lifecycle.value} action; expected {expected.value}"
                )
            revisions = self._apply_projection_updates(
                connection,
                run_id=lease.run_id,
                updates=normalized,
                updated_at=timestamp,
            )
            connection.execute(
                """
                UPDATE graph_actions
                SET lifecycle = ?, result_json = ?, settlement_digest = ?,
                    settled_epoch = ?, unknown_reason = '', updated_at = ?
                WHERE run_id = ? AND action_key = ?
                """,
                (
                    ActionLifecycle.SETTLED.value,
                    result_json,
                    settlement_digest,
                    lease.epoch,
                    timestamp,
                    lease.run_id,
                    key,
                ),
            )
            payload = {
                "action_id": action.action_id,
                "action_key": key,
                "attempt": action.attempt,
                "result": _decode_json(result_json),
                "reconciliation_reason": reconciliation_reason,
            }
            self._insert_event(
                connection,
                run_id=lease.run_id,
                idempotency_key=f"{action.action_id}:settled",
                kind=("action_reconciled_settled" if reconciliation_reason else "action_settled"),
                action_key=key,
                payload_json=_canonical_json(payload),
                commit_digest=settlement_digest,
                projection_revisions=revisions,
                created_at=timestamp,
            )
            return self._required_action(connection, lease.run_id, key)

    def _mark_action_unknown(
        self,
        connection: sqlite3.Connection,
        *,
        action: ActionRecord,
        reason: str,
        created_at: float,
    ) -> ActionRecord:
        connection.execute(
            """
            UPDATE graph_actions
            SET lifecycle = ?, unknown_reason = ?, updated_at = ?
            WHERE run_id = ? AND action_key = ? AND lifecycle = ?
            """,
            (
                ActionLifecycle.UNKNOWN_OUTCOME.value,
                reason,
                created_at,
                action.run_id,
                action.action_key,
                ActionLifecycle.STARTED.value,
            ),
        )
        payload = {
            "action_id": action.action_id,
            "action_key": action.action_key,
            "attempt": action.attempt,
            "reason": reason,
        }
        self._insert_event(
            connection,
            run_id=action.run_id,
            idempotency_key=f"{action.action_id}:unknown:{action.attempt}",
            kind="action_outcome_unknown",
            action_key=action.action_key,
            payload_json=_canonical_json(payload),
            commit_digest=_digest_json(payload),
            projection_revisions={},
            created_at=created_at,
        )
        return self._required_action(connection, action.run_id, action.action_key)

    def _apply_projection_updates(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        updates: Sequence[_NormalizedProjectionUpdate],
        updated_at: float,
    ) -> dict[str, int]:
        revisions: dict[str, int] = {}
        for update in updates:
            row = connection.execute(
                """
                SELECT revision FROM graph_projections
                WHERE run_id = ? AND name = ?
                """,
                (run_id, update.name),
            ).fetchone()
            actual_revision = int(row["revision"]) if row is not None else 0
            if actual_revision != update.expected_revision:
                raise ProjectionConflictError(
                    f"projection {update.name!r} expected revision "
                    f"{update.expected_revision}, found {actual_revision}"
                )
            next_revision = actual_revision + 1
            connection.execute(
                """
                INSERT INTO graph_projections(
                    run_id, name, revision, payload_json, payload_digest, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, name) DO UPDATE SET
                    revision = excluded.revision,
                    payload_json = excluded.payload_json,
                    payload_digest = excluded.payload_digest,
                    updated_at = excluded.updated_at
                """,
                (
                    run_id,
                    update.name,
                    next_revision,
                    update.payload_json,
                    update.payload_digest,
                    updated_at,
                ),
            )
            revisions[update.name] = next_revision
        return revisions

    def _insert_event(  # noqa: PLR0913 - durable event identity is explicit.
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        idempotency_key: str,
        kind: str,
        action_key: str,
        payload_json: str,
        commit_digest: str,
        projection_revisions: Mapping[str, int],
        created_at: float,
    ) -> RunEvent:
        sequence_row = connection.execute(
            """
            SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence
            FROM graph_events WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        sequence = int(sequence_row["next_sequence"])
        event_id = f"event:{_digest_text(f'{run_id}\u0000{sequence}\u0000{idempotency_key}')}"
        connection.execute(
            """
            INSERT INTO graph_events(
                run_id, sequence, event_id, idempotency_key, kind, action_key,
                payload_json, commit_digest, projection_revisions_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                sequence,
                event_id,
                idempotency_key,
                kind,
                action_key,
                payload_json,
                commit_digest,
                _canonical_json(dict(sorted(projection_revisions.items()))),
                created_at,
            ),
        )
        row = connection.execute(
            """
            SELECT * FROM graph_events
            WHERE run_id = ? AND sequence = ?
            """,
            (run_id, sequence),
        ).fetchone()
        assert row is not None
        return _event_from_row(row)

    def _require_lease(
        self,
        connection: sqlite3.Connection,
        lease: RunLease,
        *,
        now: float,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM graph_runs WHERE run_id = ?",
            (lease.run_id,),
        ).fetchone()
        if row is None:
            raise RunLeaseLostError("lease references an unknown run")
        matches = (
            str(row["owner_id"] or "") == lease.owner_id
            and str(row["lease_token"] or "") == lease.token
            and int(row["lease_epoch"]) == lease.epoch
        )
        expiry = _optional_float(row["lease_expires_at"])
        if not matches or expiry is None or expiry <= now:
            raise RunLeaseLostError(
                f"lease for run {lease.run_id!r} is expired, released, or fenced"
            )

    def _action_row(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        action_key: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM graph_actions
            WHERE run_id = ? AND action_key = ?
            """,
            (run_id, action_key),
        ).fetchone()

    def _required_action(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        action_key: str,
    ) -> ActionRecord:
        row = self._action_row(connection, run_id, action_key)
        if row is None:
            raise UnknownActionError(f"unknown action key: {action_key}")
        return _action_from_row(row)

    def _list_actions(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> list[ActionRecord]:
        rows = connection.execute(
            """
            SELECT * FROM graph_actions
            WHERE run_id = ? ORDER BY created_at, action_key
            """,
            (run_id,),
        ).fetchall()
        return [_action_from_row(row) for row in rows]

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS graph_run_store_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graph_runs(
                    run_id TEXT PRIMARY KEY,
                    owner_id TEXT,
                    lease_token TEXT,
                    lease_epoch INTEGER NOT NULL DEFAULT 0 CHECK(lease_epoch >= 0),
                    lease_expires_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    CHECK(
                        (owner_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
                        OR
                        (owner_id IS NOT NULL AND lease_token IS NOT NULL
                            AND lease_expires_at IS NOT NULL)
                    )
                );

                CREATE TABLE IF NOT EXISTS graph_actions(
                    run_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    action_key TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    lifecycle TEXT NOT NULL CHECK(lifecycle IN (
                        'reserved', 'started', 'settled', 'unknown_outcome', 'cancelled'
                    )),
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_json TEXT,
                    settlement_digest TEXT NOT NULL DEFAULT '',
                    reservation_epoch INTEGER NOT NULL CHECK(reservation_epoch > 0),
                    started_epoch INTEGER,
                    settled_epoch INTEGER,
                    attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt >= 0),
                    unknown_reason TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(run_id, action_key),
                    UNIQUE(action_id),
                    FOREIGN KEY(run_id) REFERENCES graph_runs(run_id) ON DELETE RESTRICT
                );

                CREATE TABLE IF NOT EXISTS graph_events(
                    run_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    event_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    action_key TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL,
                    commit_digest TEXT NOT NULL,
                    projection_revisions_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    PRIMARY KEY(run_id, sequence),
                    UNIQUE(run_id, event_id),
                    UNIQUE(run_id, idempotency_key),
                    FOREIGN KEY(run_id) REFERENCES graph_runs(run_id) ON DELETE RESTRICT
                );

                CREATE TABLE IF NOT EXISTS graph_projections(
                    run_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(run_id, name),
                    FOREIGN KEY(run_id) REFERENCES graph_runs(run_id) ON DELETE RESTRICT
                );

                CREATE INDEX IF NOT EXISTS graph_actions_lifecycle_idx
                    ON graph_actions(run_id, lifecycle, created_at);
                CREATE INDEX IF NOT EXISTS graph_events_kind_idx
                    ON graph_events(run_id, kind, sequence);
                """
            )
            row = connection.execute(
                "SELECT value FROM graph_run_store_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO graph_run_store_meta(key, value)
                    VALUES ('schema_version', ?)
                    """,
                    (str(_SCHEMA_VERSION),),
                )
            elif str(row["value"]) != str(_SCHEMA_VERSION):
                raise RunStoreSchemaError(f"unsupported run-store schema version: {row['value']}")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1_000)}")
        self._secure_database_files()
        try:
            yield connection
        finally:
            connection.close()
            self._secure_database_files()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._secure_database_files()
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def _secure_database_files(self) -> None:
        """Keep the database and SQLite sidecars readable only by their owner."""
        if os.name != "posix":
            return
        for candidate in (
            self.path,
            self.path.with_name(f"{self.path.name}-wal"),
            self.path.with_name(f"{self.path.name}-shm"),
        ):
            try:
                candidate.chmod(0o600)
            except FileNotFoundError:
                continue


@dataclass(frozen=True)
class _NormalizedProjectionUpdate:
    name: str
    payload_json: str
    payload_digest: str
    expected_revision: int


def _normalize_projection_updates(
    updates: Sequence[ProjectionUpdate],
) -> tuple[_NormalizedProjectionUpdate, ...]:
    normalized: list[_NormalizedProjectionUpdate] = []
    names: set[str] = set()
    for update in updates:
        name = _identity(update.name, "projection name")
        if name in names:
            raise ValueError(f"duplicate projection update: {name}")
        if isinstance(update.expected_revision, bool) or update.expected_revision < 0:
            raise ValueError("projection expected_revision cannot be negative")
        payload_json = _canonical_json(update.payload)
        normalized.append(
            _NormalizedProjectionUpdate(
                name=name,
                payload_json=payload_json,
                payload_digest=_digest_text(payload_json),
                expected_revision=update.expected_revision,
            )
        )
        names.add(name)
    return tuple(normalized)


def _action_from_row(row: sqlite3.Row) -> ActionRecord:
    result_json = row["result_json"]
    return ActionRecord(
        run_id=str(row["run_id"]),
        action_id=str(row["action_id"]),
        action_key=str(row["action_key"]),
        node_id=str(row["node_id"]),
        lifecycle=ActionLifecycle(str(row["lifecycle"])),
        request=_decode_json(str(row["request_json"])),
        request_digest=str(row["request_digest"]),
        result=_decode_json(str(result_json)) if result_json is not None else None,
        settlement_digest=str(row["settlement_digest"]),
        reservation_epoch=int(row["reservation_epoch"]),
        started_epoch=(int(row["started_epoch"]) if row["started_epoch"] is not None else None),
        settled_epoch=(int(row["settled_epoch"]) if row["settled_epoch"] is not None else None),
        attempt=int(row["attempt"]),
        unknown_reason=str(row["unknown_reason"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


def _event_from_row(row: sqlite3.Row) -> RunEvent:
    raw_revisions = _decode_json(str(row["projection_revisions_json"]))
    if not isinstance(raw_revisions, dict):
        raise RunStoreSchemaError("event projection revisions are malformed")
    revisions: dict[str, int] = {}
    for name, raw_revision in raw_revisions.items():
        if isinstance(raw_revision, bool) or not isinstance(raw_revision, int):
            raise RunStoreSchemaError("event projection revision is malformed")
        revisions[str(name)] = raw_revision
    return RunEvent(
        run_id=str(row["run_id"]),
        sequence=int(row["sequence"]),
        event_id=str(row["event_id"]),
        idempotency_key=str(row["idempotency_key"]),
        kind=str(row["kind"]),
        action_key=str(row["action_key"]),
        payload=_decode_json(str(row["payload_json"])),
        commit_digest=str(row["commit_digest"]),
        projection_revisions=revisions,
        created_at=float(row["created_at"]),
    )


def _projection_from_row(row: sqlite3.Row) -> ProjectionRecord:
    payload_json = str(row["payload_json"])
    payload_digest = str(row["payload_digest"])
    if _digest_text(payload_json) != payload_digest:
        raise RunStoreSchemaError("projection payload digest mismatch")
    return ProjectionRecord(
        run_id=str(row["run_id"]),
        name=str(row["name"]),
        revision=int(row["revision"]),
        payload=_decode_json(payload_json),
        payload_digest=payload_digest,
        updated_at=float(row["updated_at"]),
    )


def _lease_from_row(row: sqlite3.Row) -> RunLease:
    return RunLease(
        run_id=str(row["run_id"]),
        owner_id=str(row["owner_id"]),
        token=str(row["lease_token"]),
        epoch=int(row["lease_epoch"]),
        expires_at=float(row["lease_expires_at"]),
    )


def _event_commit_digest(
    *,
    idempotency_key: str,
    kind: str,
    action_key: str,
    payload_json: str,
    projections: Sequence[_NormalizedProjectionUpdate],
) -> str:
    return _digest_json(
        {
            "idempotency_key": idempotency_key,
            "kind": kind,
            "action_key": action_key,
            "payload_digest": _digest_text(payload_json),
            "projections": [
                {
                    "name": update.name,
                    "payload_digest": update.payload_digest,
                    "expected_revision": update.expected_revision,
                }
                for update in projections
            ],
        }
    )


def _settlement_digest(
    *,
    result_json: str,
    projections: Sequence[_NormalizedProjectionUpdate],
    reconciliation_reason: str,
) -> str:
    return _digest_json(
        {
            "result_digest": _digest_text(result_json),
            "reconciliation_reason": reconciliation_reason,
            "projections": [
                {
                    "name": update.name,
                    "payload_digest": update.payload_digest,
                    "expected_revision": update.expected_revision,
                }
                for update in projections
            ],
        }
    )


def _identity(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} is required")
    if len(normalized) > _MAX_IDENTITY_CHARS:
        raise ValueError(f"{label} is too long")
    return normalized


def _timestamp(value: float | None) -> float:
    parsed = time.time() if value is None else value
    if isinstance(parsed, bool) or not math.isfinite(parsed) or parsed < 0:
        raise ValueError("timestamp must be finite and non-negative")
    return float(parsed)


def _ttl(value: float) -> float:
    if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ValueError("lease TTL must be finite and greater than zero")
    return float(value)


def _optional_float(value: object) -> float | None:
    return float(value) if value is not None else None


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("run-store payload must be canonical JSON") from exc


def _decode_json(value: str) -> object:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise RunStoreSchemaError("persisted run-store JSON is malformed") from exc


def _digest_json(value: object) -> str:
    return _digest_text(_canonical_json(value))


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sha256_digest(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != _SHA256_HEX_CHARS or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _application_projection_name(action_id: str) -> str:
    return f"{_ACTION_APPLIED_PREFIX}{action_id}"


__all__ = [
    "ActionLifecycle",
    "ActionRecord",
    "ActionReservation",
    "ActionStart",
    "ActionTransitionError",
    "EventCommit",
    "ProjectionConflictError",
    "ProjectionRecord",
    "ProjectionUpdate",
    "RecoveryReport",
    "RecoverySnapshot",
    "RunEvent",
    "RunLease",
    "RunLeaseConflictError",
    "RunLeaseLostError",
    "RunStore",
    "RunStoreError",
    "RunStoreIdempotencyError",
    "RunStoreSchemaError",
    "UnknownActionError",
    "UnknownRunError",
]
