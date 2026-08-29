"""Authoritative resource and command-id persistence ports for authorization."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from ravage.control_plane.identity import OrganizationId, TenantId, UserId

if TYPE_CHECKING:
    from ravage.control_plane.authorization_contracts import CommandAuthorizationReceipt

_RESOURCE_KIND_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_RESOURCE_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_COMMAND_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class ResourceLifecycleState(StrEnum):
    """Minimal authoritative states required by cross-resource policy checks."""

    ABSENT = "absent"
    ACTIVE = "active"
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ResourceScope:
    """Authoritatively resolved location of one control-plane resource."""

    tenant_id: TenantId
    organization_id: OrganizationId
    resource_kind: str
    resource_id: str

    def __post_init__(self) -> None:
        if type(self.tenant_id) is not TenantId:
            message = "resource tenant_id must be a TenantId"
            raise TypeError(message)
        if type(self.organization_id) is not OrganizationId:
            message = "resource organization_id must be an OrganizationId"
            raise TypeError(message)
        _require_pattern(self.resource_kind, _RESOURCE_KIND_PATTERN, "resource_kind")
        _require_pattern(self.resource_id, _RESOURCE_ID_PATTERN, "resource_id")


@dataclass(frozen=True, slots=True)
class AuthoritativeResourceState:
    """Immutable authorization projection loaded from authoritative storage."""

    scope: ResourceScope
    revision: int
    lifecycle: ResourceLifecycleState
    requested_by_user_id: UserId | None = None
    approved_by_user_id: UserId | None = None

    def __post_init__(self) -> None:
        if type(self.scope) is not ResourceScope:
            message = "scope must be a ResourceScope"
            raise TypeError(message)
        if type(self.revision) is not int or self.revision < 0:
            message = "resource revision must be a non-negative integer"
            raise ValueError(message)
        if type(self.lifecycle) is not ResourceLifecycleState:
            message = "resource lifecycle must be a ResourceLifecycleState"
            raise TypeError(message)
        for field_name, value in (
            ("requested_by_user_id", self.requested_by_user_id),
            ("approved_by_user_id", self.approved_by_user_id),
        ):
            if value is not None and type(value) is not UserId:
                message = f"{field_name} must be a UserId or None"
                raise TypeError(message)

    @property
    def state_sha256(self) -> str:
        body = {
            "approved_by_user_id": (
                self.approved_by_user_id.value if self.approved_by_user_id is not None else None
            ),
            "lifecycle": self.lifecycle.value,
            "requested_by_user_id": (
                self.requested_by_user_id.value if self.requested_by_user_id is not None else None
            ),
            "resource_id": self.scope.resource_id,
            "resource_kind": self.scope.resource_kind,
            "revision": self.revision,
            "scope": {
                "organization_id": self.scope.organization_id.value,
                "tenant_id": self.scope.tenant_id.value,
            },
        }
        encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()


class ResourceScopeResolver(Protocol):
    """
    Resolve resource state using authenticated scope as the lookup partition.

    Implementations must query by the complete ``(tenant, organization, kind,
    resource_id)`` key. They must return ``None`` rather than falling back to an
    unscoped resource-ID lookup.
    """

    def resolve(
        self,
        *,
        tenant_id: TenantId,
        organization_id: OrganizationId,
        command_name: str,
        resource_kind: str,
        resource_id: str,
    ) -> AuthoritativeResourceState | None: ...


@dataclass(frozen=True, slots=True)
class CommandReplayClaim:
    """Exact actor-and-command identity reserved before policy evaluation."""

    tenant_id: TenantId
    organization_id: OrganizationId
    command_id: str
    request_sha256: str

    def __post_init__(self) -> None:
        if type(self.tenant_id) is not TenantId:
            message = "command tenant_id must be a TenantId"
            raise TypeError(message)
        if type(self.organization_id) is not OrganizationId:
            message = "command organization_id must be an OrganizationId"
            raise TypeError(message)
        _require_pattern(self.command_id, _COMMAND_ID_PATTERN, "command_id")
        _require_pattern(self.request_sha256, _DIGEST_PATTERN, "request_sha256")


@dataclass(frozen=True, slots=True)
class CommandReplayReservation:
    """Opaque ownership token for one pending command-id claim."""

    claim: CommandReplayClaim
    reservation_id: str

    def __post_init__(self) -> None:
        if type(self.claim) is not CommandReplayClaim:
            message = "claim must be a CommandReplayClaim"
            raise TypeError(message)
        _require_pattern(self.reservation_id, _DIGEST_PATTERN, "reservation_id")


class CommandReplayConflictError(RuntimeError):
    """Raised when a command ID is reused for a different exact request."""


class CommandReplayInProgressError(RuntimeError):
    """Raised when an identical command is already being evaluated."""


class CommandReplayReservationLostError(RuntimeError):
    """Raised when a caller no longer owns a command reservation."""


class CommandReplayCapacityError(RuntimeError):
    """Raised instead of evicting authorization idempotency state."""


class CommandReplayRegistry(Protocol):
    """Persistence port; production must implement these operations durably."""

    def reserve(
        self,
        claim: CommandReplayClaim,
    ) -> CommandReplayReservation | CommandAuthorizationReceipt: ...

    def commit(
        self,
        reservation: CommandReplayReservation,
        receipt: CommandAuthorizationReceipt,
    ) -> CommandAuthorizationReceipt: ...

    def abandon(self, reservation: CommandReplayReservation) -> None: ...


@dataclass(slots=True)
class _ProcessLocalEntry:
    claim: CommandReplayClaim
    reservation_id: str
    receipt: CommandAuthorizationReceipt | None = None
    abandoned: bool = False


class ProcessLocalCommandReplayRegistry:
    """
    Thread-safe development implementation with no durability guarantees.

    This class deliberately never evicts entries. It is unsuitable for a
    multi-process or production deployment; implement ``CommandReplayRegistry``
    transactionally in the control-plane database instead.
    """

    def __init__(self, *, max_entries: int = 10_000) -> None:
        if type(max_entries) is not int or max_entries <= 0:
            message = "max_entries must be a positive integer"
            raise ValueError(message)
        self._max_entries = max_entries
        self._entries: dict[
            tuple[TenantId, OrganizationId, str],
            _ProcessLocalEntry,
        ] = {}
        self._lock = threading.Lock()

    def reserve(
        self,
        claim: CommandReplayClaim,
    ) -> CommandReplayReservation | CommandAuthorizationReceipt:
        if type(claim) is not CommandReplayClaim:
            message = "claim must be a CommandReplayClaim"
            raise TypeError(message)
        key = (claim.tenant_id, claim.organization_id, claim.command_id)
        with self._lock:
            existing = self._entries.get(key)
            if existing is not None:
                if existing.claim != claim:
                    message = "command ID was reused for a different request"
                    raise CommandReplayConflictError(message)
                if existing.receipt is not None:
                    return existing.receipt
                if existing.abandoned:
                    reservation_id = secrets.token_hex(32)
                    existing.reservation_id = reservation_id
                    existing.abandoned = False
                    return CommandReplayReservation(
                        claim=claim,
                        reservation_id=reservation_id,
                    )
                message = "identical command authorization is already in progress"
                raise CommandReplayInProgressError(message)
            if len(self._entries) >= self._max_entries:
                message = "command replay registry capacity reached"
                raise CommandReplayCapacityError(message)
            reservation_id = secrets.token_hex(32)
            self._entries[key] = _ProcessLocalEntry(
                claim=claim,
                reservation_id=reservation_id,
            )
            return CommandReplayReservation(
                claim=claim,
                reservation_id=reservation_id,
            )

    def commit(
        self,
        reservation: CommandReplayReservation,
        receipt: CommandAuthorizationReceipt,
    ) -> CommandAuthorizationReceipt:
        key = (
            reservation.claim.tenant_id,
            reservation.claim.organization_id,
            reservation.claim.command_id,
        )
        with self._lock:
            entry = self._entries.get(key)
            if (
                entry is None
                or entry.abandoned
                or entry.reservation_id != reservation.reservation_id
            ):
                message = "command replay reservation was lost"
                raise CommandReplayReservationLostError(message)
            if entry.claim != reservation.claim:
                message = "command replay reservation claim changed"
                raise CommandReplayConflictError(message)
            if entry.receipt is not None:
                if entry.receipt != receipt:
                    message = "command replay reservation already has another receipt"
                    raise CommandReplayConflictError(message)
                return entry.receipt
            if (
                receipt.command_id != reservation.claim.command_id
                or receipt.command_claim_sha256 != reservation.claim.request_sha256
                or receipt.actor_tenant_id != reservation.claim.tenant_id
                or receipt.actor_organization_id != reservation.claim.organization_id
            ):
                message = "authorization receipt does not match the exact command claim"
                raise CommandReplayConflictError(message)
            entry.receipt = receipt
            return receipt

    def abandon(self, reservation: CommandReplayReservation) -> None:
        key = (
            reservation.claim.tenant_id,
            reservation.claim.organization_id,
            reservation.claim.command_id,
        )
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            if entry.reservation_id != reservation.reservation_id or entry.receipt is not None:
                return
            entry.abandoned = True


def _require_pattern(value: object, pattern: re.Pattern[str], field_name: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        message = f"{field_name} is not canonical"
        raise ValueError(message)
    return value
