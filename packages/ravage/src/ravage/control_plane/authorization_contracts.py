"""
Versioned, policy-neutral authorization contracts.

This module is safe for public runners, clients, and persistence adapters. It
contains no enterprise role catalogue, grants, command bindings, or transition
policy. Those belong to the enterprise policy module.
"""
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from ravage.control_plane.authorization_attestation import (
    AUTHORIZATION_ATTESTATION_DOMAIN,
    AuthorizationReceiptAuthenticityError,
    AuthorizationReceiptSigner,
    AuthorizationReceiptVerifier,
)
from ravage.control_plane.authorization_state import (
    AuthoritativeResourceState,
    ResourceLifecycleState,
    ResourceScope,
)
from ravage.control_plane.identity import (
    AuthenticationMethod,
    OrganizationId,
    TenantId,
    UserId,
)

AUTHORIZATION_REQUEST_SCHEMA = "ravage.control-plane.authorization-request.v1"
AUTHORIZATION_RECEIPT_SCHEMA = "ravage.control-plane.authorization-receipt.v2"

_COMMAND_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_COMMAND_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")
_RESOURCE_KIND_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_RESOURCE_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_ROLE_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}\Z")


class AuthorizationDecision(StrEnum):
    """Transport-stable authorization outcome."""

    ALLOW = "allow"
    DENY = "deny"


class AuthorizationReason(StrEnum):
    """Transport-stable reason vocabulary; policy chooses which reason applies."""

    ALLOWED = "allowed"
    AUTHENTICATION_NOT_YET_VALID = "authentication_not_yet_valid"
    AUTHENTICATION_EXPIRED = "authentication_expired"
    TENANT_MISMATCH = "tenant_mismatch"
    ORGANIZATION_MISMATCH = "organization_mismatch"
    UNKNOWN_COMMAND = "unknown_command"
    RESOURCE_KIND_MISMATCH = "resource_kind_mismatch"
    RESOURCE_NOT_FOUND = "resource_not_found"
    RESOURCE_SCOPE_MISMATCH = "resource_scope_mismatch"
    PERMISSION_NOT_GRANTED = "permission_not_granted"
    RESOURCE_STATE_INVALID = "resource_state_invalid"
    FOUR_EYES_REQUIRED = "four_eyes_required"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def canonical_command_payload_sha256(payload: object) -> str:
    """Digest a JSON-compatible command body without retaining the raw payload."""
    return _sha256_json(payload)


def _require_pattern(
    value: object,
    *,
    field_name: str,
    pattern: re.Pattern[str],
    allow_string_subclass: bool = False,
) -> str:
    valid_type = isinstance(value, str) if allow_string_subclass else type(value) is str
    if not valid_type:
        raise TypeError(f"{field_name} must be a string")
    text = str(value)
    if pattern.fullmatch(text) is None:
        raise ValueError(f"{field_name} is not canonical")
    return text


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class CommandAuthorizationRequest:
    """Policy-neutral command intent with an explicit wire schema version."""

    command_id: str
    command_name: str
    tenant_id: TenantId
    organization_id: OrganizationId
    resource_kind: str
    resource_id: str
    payload_sha256: str
    schema_version: str = AUTHORIZATION_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        _require_pattern(self.command_id, field_name="command_id", pattern=_COMMAND_ID_PATTERN)
        command_name = _require_pattern(
            self.command_name,
            field_name="command_name",
            pattern=_COMMAND_NAME_PATTERN,
            allow_string_subclass=True,
        )
        object.__setattr__(self, "command_name", command_name)
        if type(self.tenant_id) is not TenantId:
            raise TypeError("tenant_id must be a TenantId")
        if type(self.organization_id) is not OrganizationId:
            raise TypeError("organization_id must be an OrganizationId")
        _require_pattern(
            self.resource_kind,
            field_name="resource_kind",
            pattern=_RESOURCE_KIND_PATTERN,
        )
        _require_pattern(
            self.resource_id,
            field_name="resource_id",
            pattern=_RESOURCE_ID_PATTERN,
        )
        _require_pattern(
            self.payload_sha256,
            field_name="payload_sha256",
            pattern=_SHA256_PATTERN,
        )
        if self.schema_version != AUTHORIZATION_REQUEST_SCHEMA:
            raise ValueError("unsupported authorization request schema")

    def to_json(self) -> dict[str, object]:
        return {
            "schema": self.schema_version,
            "command_id": self.command_id,
            "command_name": self.command_name,
            "tenant_id": self.tenant_id.value,
            "organization_id": self.organization_id.value,
            "resource_kind": self.resource_kind,
            "resource_id": self.resource_id,
            "payload_sha256": self.payload_sha256,
        }


@dataclass(frozen=True, slots=True)
class CommandAuthorizationReceipt:
    """Immutable, structurally validated, server-attested decision evidence."""

    receipt_id: str
    receipt_sha256: str
    schema_version: str
    policy_version: str
    policy_sha256: str
    issuer_id: str
    issuer_key_id: str
    attestation_algorithm: str
    attestation_signature: str
    evaluated_at: datetime
    decision: AuthorizationDecision
    reason: AuthorizationReason
    command_id: str
    command_claim_sha256: str
    command_name: str
    payload_sha256: str
    resource_kind: str
    resource_id: str
    target_tenant_id: TenantId
    target_organization_id: OrganizationId
    resource_revision: int | None
    resource_lifecycle: ResourceLifecycleState | None
    resource_state_sha256: str | None
    requested_by_user_id: UserId | None
    approved_by_user_id: UserId | None
    actor_tenant_id: TenantId
    actor_organization_id: OrganizationId
    actor_user_id: UserId
    authentication_method: AuthenticationMethod
    authentication_event_id: str
    actor_authenticated_at: datetime
    actor_expires_at: datetime
    actor_roles: tuple[str, ...]
    granting_roles: tuple[str, ...]
    required_permission: str | None

    def __post_init__(self) -> None:  # noqa: C901, PLR0912
        evaluated_at = _require_utc_datetime(self.evaluated_at, field_name="evaluated_at")
        authenticated_at = _require_utc_datetime(
            self.actor_authenticated_at,
            field_name="actor_authenticated_at",
        )
        expires_at = _require_utc_datetime(
            self.actor_expires_at,
            field_name="actor_expires_at",
        )
        object.__setattr__(self, "evaluated_at", evaluated_at)
        object.__setattr__(self, "actor_authenticated_at", authenticated_at)
        object.__setattr__(self, "actor_expires_at", expires_at)

        for field_name, value, expected_type in (
            ("target_tenant_id", self.target_tenant_id, TenantId),
            ("target_organization_id", self.target_organization_id, OrganizationId),
            ("actor_tenant_id", self.actor_tenant_id, TenantId),
            ("actor_organization_id", self.actor_organization_id, OrganizationId),
            ("actor_user_id", self.actor_user_id, UserId),
        ):
            if type(value) is not expected_type:
                raise TypeError(f"{field_name} has the wrong identity type")
        for field_name, optional_user_id in (
            ("requested_by_user_id", self.requested_by_user_id),
            ("approved_by_user_id", self.approved_by_user_id),
        ):
            if optional_user_id is not None and type(optional_user_id) is not UserId:
                raise TypeError(f"{field_name} must be a UserId or None")
        if type(self.decision) is not AuthorizationDecision:
            raise TypeError("decision must be an AuthorizationDecision")
        if type(self.reason) is not AuthorizationReason:
            raise TypeError("reason must be an AuthorizationReason")
        if type(self.authentication_method) is not AuthenticationMethod:
            raise TypeError("authentication_method must be an AuthenticationMethod")
        if self.required_permission is not None:
            _require_pattern(
                self.required_permission,
                field_name="required_permission",
                pattern=_COMMAND_NAME_PATTERN,
                allow_string_subclass=True,
            )
        if (
            self.resource_lifecycle is not None
            and type(self.resource_lifecycle) is not ResourceLifecycleState
        ):
            raise TypeError("resource_lifecycle must be a ResourceLifecycleState or None")
        if self.resource_revision is not None and (
            type(self.resource_revision) is not int or self.resource_revision < 0
        ):
            raise ValueError("resource_revision must be a non-negative integer or None")

        _require_pattern(
            self.schema_version,
            field_name="schema_version",
            pattern=_IDENTIFIER_PATTERN,
        )
        _require_pattern(
            self.policy_version,
            field_name="policy_version",
            pattern=_IDENTIFIER_PATTERN,
        )
        _require_pattern(self.policy_sha256, field_name="policy_sha256", pattern=_SHA256_PATTERN)
        _require_pattern(self.issuer_id, field_name="issuer_id", pattern=_IDENTIFIER_PATTERN)
        _require_pattern(
            self.issuer_key_id,
            field_name="issuer_key_id",
            pattern=_IDENTIFIER_PATTERN,
        )
        _require_pattern(
            self.attestation_signature,
            field_name="attestation_signature",
            pattern=_SIGNATURE_PATTERN,
        )
        _require_pattern(self.command_id, field_name="command_id", pattern=_COMMAND_ID_PATTERN)
        _require_pattern(
            self.command_claim_sha256,
            field_name="command_claim_sha256",
            pattern=_SHA256_PATTERN,
        )
        _require_pattern(
            self.command_name,
            field_name="command_name",
            pattern=_COMMAND_NAME_PATTERN,
        )
        _require_pattern(self.payload_sha256, field_name="payload_sha256", pattern=_SHA256_PATTERN)
        _require_pattern(
            self.resource_kind,
            field_name="resource_kind",
            pattern=_RESOURCE_KIND_PATTERN,
        )
        _require_pattern(
            self.resource_id,
            field_name="resource_id",
            pattern=_RESOURCE_ID_PATTERN,
        )
        if self.resource_state_sha256 is not None:
            _require_pattern(
                self.resource_state_sha256,
                field_name="resource_state_sha256",
                pattern=_SHA256_PATTERN,
            )
        self._validate_resource_state()
        _require_sorted_role_ids(self.actor_roles, "actor_roles")
        _require_sorted_role_ids(self.granting_roles, "granting_roles")
        if len(self.actor_roles) != len(set(self.actor_roles)):
            raise ValueError("actor_roles cannot contain duplicates")
        if len(self.granting_roles) != len(set(self.granting_roles)):
            raise ValueError("granting_roles cannot contain duplicates")
        if not set(self.granting_roles).issubset(self.actor_roles):
            raise ValueError("granting_roles must be a subset of actor_roles")
        self._validate_decision_semantics(evaluated_at, authenticated_at, expires_at)

        if self.receipt_id != f"azr_{self.receipt_sha256}":
            raise ValueError("receipt_id does not match receipt_sha256")
        if not self.verify_integrity():
            raise ValueError("receipt integrity check failed")

    def _validate_resource_state(self) -> None:
        state_presence = (
            self.resource_revision is not None,
            self.resource_lifecycle is not None,
            self.resource_state_sha256 is not None,
        )
        if any(state_presence) and not all(state_presence):
            raise ValueError("receipt contains partial authoritative resource state")
        if not any(state_presence) and (
            self.requested_by_user_id is not None or self.approved_by_user_id is not None
        ):
            raise ValueError("receipt principals require authoritative resource state")
        if not all(state_presence):
            return
        assert self.resource_revision is not None
        assert self.resource_lifecycle is not None
        assert self.resource_state_sha256 is not None
        reconstructed_state = AuthoritativeResourceState(
            scope=ResourceScope(
                tenant_id=self.target_tenant_id,
                organization_id=self.target_organization_id,
                resource_kind=self.resource_kind,
                resource_id=self.resource_id,
            ),
            revision=self.resource_revision,
            lifecycle=self.resource_lifecycle,
            requested_by_user_id=self.requested_by_user_id,
            approved_by_user_id=self.approved_by_user_id,
        )
        if reconstructed_state.state_sha256 != self.resource_state_sha256:
            raise ValueError("receipt resource-state digest is inconsistent")

    def _validate_decision_semantics(
        self,
        evaluated_at: datetime,
        authenticated_at: datetime,
        expires_at: datetime,
    ) -> None:
        if self.decision is AuthorizationDecision.DENY:
            if self.reason is AuthorizationReason.ALLOWED:
                raise ValueError("deny receipts cannot have the allowed reason")
            if self.granting_roles:
                raise ValueError("deny receipts cannot name granting roles")
            return
        if self.reason is not AuthorizationReason.ALLOWED:
            raise ValueError("allow receipts must have the allowed reason")
        if self.required_permission is None or not self.granting_roles:
            raise ValueError("allow receipts must name a permission and granting role")
        if self.target_tenant_id != self.actor_tenant_id:
            raise ValueError("allow receipt crosses a tenant boundary")
        if self.target_organization_id != self.actor_organization_id:
            raise ValueError("allow receipt crosses an organization boundary")
        if not authenticated_at <= evaluated_at < expires_at:
            raise ValueError("allow receipt was issued outside authentication validity")
        if (
            self.resource_revision is None
            or self.resource_lifecycle is None
            or self.resource_state_sha256 is None
        ):
            raise ValueError("allow receipt lacks authoritative resource state")

    def _body(self) -> dict[str, object]:
        return {
            "actor": {
                "authentication_event_id": self.authentication_event_id,
                "authentication_method": self.authentication_method.value,
                "authenticated_at": self.actor_authenticated_at.isoformat(),
                "expires_at": self.actor_expires_at.isoformat(),
                "organization_id": self.actor_organization_id.value,
                "roles": [str(role) for role in self.actor_roles],
                "tenant_id": self.actor_tenant_id.value,
                "user_id": self.actor_user_id.value,
            },
            "command": {
                "command_id": self.command_id,
                "command_claim_sha256": self.command_claim_sha256,
                "command_name": self.command_name,
                "payload_sha256": self.payload_sha256,
                "required_permission": (
                    str(self.required_permission) if self.required_permission is not None else None
                ),
                "resource_id": self.resource_id,
                "resource_kind": self.resource_kind,
            },
            "decision": self.decision.value,
            "evaluated_at": self.evaluated_at.isoformat(),
            "granting_roles": [str(role) for role in self.granting_roles],
            "issuer": {
                "algorithm": self.attestation_algorithm,
                "issuer_id": self.issuer_id,
                "key_id": self.issuer_key_id,
            },
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "reason": self.reason.value,
            "resource_state": {
                "approved_by_user_id": (
                    self.approved_by_user_id.value if self.approved_by_user_id is not None else None
                ),
                "lifecycle": (
                    self.resource_lifecycle.value if self.resource_lifecycle is not None else None
                ),
                "requested_by_user_id": (
                    self.requested_by_user_id.value
                    if self.requested_by_user_id is not None
                    else None
                ),
                "revision": self.resource_revision,
                "state_sha256": self.resource_state_sha256,
            },
            "schema": self.schema_version,
            "target": {
                "organization_id": self.target_organization_id.value,
                "tenant_id": self.target_tenant_id.value,
            },
        }

    def verify_integrity(self) -> bool:
        """Check accidental corruption only; this does not prove authenticity."""
        expected = _sha256_json(self._body())
        return hmac.compare_digest(self.receipt_sha256, expected)

    def assert_authentic(self, verifier: AuthorizationReceiptVerifier) -> None:
        """Require canonical integrity and a trusted server attestation."""
        if not self.verify_integrity():
            raise ValueError("authorization receipt integrity check failed")
        verifier.verify(
            issuer_id=self.issuer_id,
            key_id=self.issuer_key_id,
            algorithm=self.attestation_algorithm,
            evaluated_at=self.evaluated_at,
            content=self.attestation_content(),
            signature=self.attestation_signature,
        )

    def attestation_content(self) -> bytes:
        """Return the domain-separated canonical bytes covered by the attestation."""
        return AUTHORIZATION_ATTESTATION_DOMAIN + _canonical_json(self._body()).encode()

    def to_json(self) -> dict[str, object]:
        payload = self._body()
        payload["attestation_signature"] = self.attestation_signature
        payload["receipt_id"] = self.receipt_id
        payload["receipt_sha256"] = self.receipt_sha256
        return payload


class AuthorizationDeniedError(PermissionError):
    """Raised with the immutable denial receipt when authorization is denied."""

    def __init__(self, receipt: CommandAuthorizationReceipt) -> None:
        self.receipt = receipt
        super().__init__(f"command authorization denied: {receipt.reason.value}")


def _require_sorted_role_ids(roles: object, field_name: str) -> None:
    if type(roles) is not tuple or any(not isinstance(role, str) for role in roles):
        raise TypeError(f"{field_name} must be a tuple of string role identifiers")
    if any(_ROLE_ID_PATTERN.fullmatch(str(role)) is None for role in roles):
        raise ValueError(f"{field_name} contains a non-canonical role identifier")
    if tuple(sorted(roles, key=str)) != roles:
        raise ValueError(f"{field_name} must be sorted")


__all__ = [
    "AUTHORIZATION_RECEIPT_SCHEMA",
    "AUTHORIZATION_REQUEST_SCHEMA",
    "AuthorizationDecision",
    "AuthorizationDeniedError",
    "AuthorizationReason",
    "AuthorizationReceiptAuthenticityError",
    "AuthorizationReceiptSigner",
    "AuthorizationReceiptVerifier",
    "CommandAuthorizationReceipt",
    "CommandAuthorizationRequest",
    "canonical_command_payload_sha256",
]
