"""Canonical authenticated identities for the Ravage control plane."""
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar

_IDENTIFIER_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?::[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*\Z"
)
_AUTHENTICATION_EVENT_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_ROLE_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_MAX_IDENTITY_LENGTH = 64


def _require_canonical_identifier(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    if len(value) > _MAX_IDENTITY_LENGTH or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{field_name} must be 1-64 lowercase ASCII letters, digits, underscores, "
            "hyphens, or non-empty colon-delimited segments, and every segment must "
            "start and end with a letter or digit"
        )
    return value


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class _CanonicalIdentity:
    """Runtime-distinct, validated opaque identifier."""

    value: str
    _field_name: ClassVar[str] = "identity"

    def __post_init__(self) -> None:
        _require_canonical_identifier(self.value, field_name=self._field_name)

    def __str__(self) -> str:
        return self.value


class TenantId(_CanonicalIdentity):
    """Canonical identifier for one hard data-isolation boundary."""

    __slots__ = ()
    _field_name = "tenant_id"


class OrganizationId(_CanonicalIdentity):
    """Canonical identifier for one organization inside a tenant."""

    __slots__ = ()
    _field_name = "organization_id"


class UserId(_CanonicalIdentity):
    """Canonical internal identifier for one human user."""

    __slots__ = ()
    _field_name = "user_id"


class AuthenticationMethod(StrEnum):
    """Authentication mechanism verified before constructing an actor context."""

    OIDC = "oidc"
    SAML = "saml"


@dataclass(frozen=True, slots=True)
class ActorContext:
    """
    An authenticated, organization-scoped principal.

    The OIDC/SAML adapter is responsible for authenticating the credential and
    mapping external claims to these internal identities and roles. Raw tokens
    and external claims deliberately do not cross this boundary.
    """

    tenant_id: TenantId
    organization_id: OrganizationId
    user_id: UserId
    roles: frozenset[str]
    authentication_method: AuthenticationMethod
    authentication_event_id: str
    authenticated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:  # noqa: C901
        if type(self.tenant_id) is not TenantId:
            raise TypeError("tenant_id must be a TenantId")
        if type(self.organization_id) is not OrganizationId:
            raise TypeError("organization_id must be an OrganizationId")
        if type(self.user_id) is not UserId:
            raise TypeError("user_id must be a UserId")
        if type(self.roles) is not frozenset:
            raise TypeError("roles must be a frozenset")
        if any(not isinstance(role, str) for role in self.roles):
            raise TypeError("roles must contain only string role identifiers")
        if any(_ROLE_ID_PATTERN.fullmatch(role) is None for role in self.roles):
            raise ValueError("roles must contain only canonical role identifiers")
        if type(self.authentication_method) is not AuthenticationMethod:
            raise TypeError("authentication_method must be an AuthenticationMethod")
        if type(self.authentication_event_id) is not str:
            raise TypeError("authentication_event_id must be a string")
        if _AUTHENTICATION_EVENT_PATTERN.fullmatch(self.authentication_event_id) is None:
            raise ValueError(
                "authentication_event_id must be 1-128 canonical lowercase ASCII characters"
            )

        authenticated_at = _require_utc_datetime(
            self.authenticated_at,
            field_name="authenticated_at",
        )
        expires_at = _require_utc_datetime(self.expires_at, field_name="expires_at")
        if expires_at <= authenticated_at:
            raise ValueError("expires_at must be later than authenticated_at")
        object.__setattr__(self, "authenticated_at", authenticated_at)
        object.__setattr__(self, "expires_at", expires_at)

    def is_active_at(self, when: datetime) -> bool:
        """Return whether the authenticated session is valid at ``when``."""
        canonical_when = _require_utc_datetime(when, field_name="when")
        return self.authenticated_at <= canonical_when < self.expires_at


__all__ = [
    "ActorContext",
    "AuthenticationMethod",
    "OrganizationId",
    "TenantId",
    "UserId",
]
