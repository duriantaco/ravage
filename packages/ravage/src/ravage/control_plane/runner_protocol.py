"""
Authenticated wire contracts for outbound customer runners.

The module intentionally owns no socket, HTTP, or persistence concerns. A
confidential transport can carry these canonical envelopes, while a durable
adapter can implement the same lease and idempotency rules transactionally.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar, Final, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ravage.control_plane.identity import OrganizationId, TenantId

_PROTOCOL_VERSION: Final = 1
_ALGORITHM: Final = "Ed25519"
_SIGNATURE_DOMAIN: Final = b"ravage.outbound-runner-envelope.v1\x00"
_MAX_WIRE_BYTES: Final = 1_048_576
_MAX_PAYLOAD_BYTES: Final = 262_144
_MAX_JSON_DEPTH: Final = 16
_MAX_JSON_ITEMS: Final = 4_096
_MAX_ACTIVE_LEASES: Final = 256
_MAX_INT: Final = (1 << 63) - 1
_MIN_INT: Final = -(1 << 63)
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"\A[A-Za-z0-9_-]{86}\Z")
_NONCE = re.compile(r"\A[0-9a-f]{32}\Z")


class ProtocolError(ValueError):
    """Raised for malformed or semantically invalid runner messages."""


class AuthenticationError(ProtocolError):
    """Raised when a wire envelope cannot be authenticated."""


class ReplayError(AuthenticationError):
    """Raised when a valid message ID or nonce has already been observed."""


class LeaseFenceError(ProtocolError):
    """Raised when work is presented under a stale or expired lease."""


class DispatchAuthorizationError(ProtocolError):
    """Raised when a request is outside its signed authorization window."""


class ResultConflictError(ProtocolError):
    """Raised when one result identity is reused for different content."""


class RegistryCapacityError(ProtocolError):
    """Raised instead of evicting security or idempotency state."""


@dataclass(frozen=True, slots=True)
class CanonicalPayload:
    """An immutable, bounded JSON object and its content digest."""

    _json: str = field(repr=False)
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self._json, str):
            message = "canonical payload storage must be text"
            raise ProtocolError(message)
        value = _loads_json(self._json.encode("utf-8"))
        if not isinstance(value, Mapping):
            message = "canonical payload must contain an object"
            raise ProtocolError(message)
        normalized = _validate_json_object(value)
        encoded = _canonical_json(normalized)
        if encoded.decode("utf-8") != self._json:
            message = "payload storage is not canonical JSON"
            raise ProtocolError(message)
        if len(encoded) > _MAX_PAYLOAD_BYTES:
            message = f"payload exceeds {_MAX_PAYLOAD_BYTES} bytes"
            raise ProtocolError(message)
        expected = hashlib.sha256(encoded).hexdigest()
        if not _DIGEST.fullmatch(self.digest) or self.digest != expected:
            message = "canonical payload digest mismatch"
            raise ProtocolError(message)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        normalized = _validate_json_object(value)
        encoded = _canonical_json(normalized)
        if len(encoded) > _MAX_PAYLOAD_BYTES:
            message = f"payload exceeds {_MAX_PAYLOAD_BYTES} bytes"
            raise ProtocolError(message)
        return cls(
            _json=encoded.decode("utf-8"),
            digest=hashlib.sha256(encoded).hexdigest(),
        )

    @classmethod
    def from_wire(cls, value: object, digest: object) -> Self:
        if not isinstance(value, Mapping):
            msg = "payload must be a JSON object"
            raise ProtocolError(msg)
        payload = cls.from_mapping(value)
        expected = _require_digest(digest, "payload_digest")
        if payload.digest != expected:
            msg = "payload digest mismatch"
            raise ProtocolError(msg)
        return payload

    def to_mapping(self) -> dict[str, object]:
        value = _loads_json(self._json.encode("utf-8"))
        if not isinstance(value, dict):  # pragma: no cover - guarded at construction
            msg = "canonical payload is not an object"
            raise ProtocolError(msg)
        return value


@dataclass(frozen=True, slots=True, order=True)
class JobIdentity:
    """Immutable organization-scoped identity for one logical unit of work."""

    tenant_id: str
    organization_id: str
    engagement_id: str
    job_id: str

    def __post_init__(self) -> None:
        _require_tenant_identifier(self.tenant_id, "tenant_id")
        _require_organization_identifier(self.organization_id, "organization_id")
        _require_identifier(self.engagement_id, "engagement_id")
        _require_identifier(self.job_id, "job_id")

    @classmethod
    def from_wire(cls, value: object) -> Self:
        body = _require_object(value, "job")
        _expect_keys(
            body,
            {"engagement_id", "job_id", "organization_id", "tenant_id"},
            "job",
        )
        return cls(
            tenant_id=_require_string(body["tenant_id"], "tenant_id"),
            organization_id=_require_string(body["organization_id"], "organization_id"),
            engagement_id=_require_string(body["engagement_id"], "engagement_id"),
            job_id=_require_string(body["job_id"], "job_id"),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "job_id": self.job_id,
            "organization_id": self.organization_id,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True, slots=True, order=True)
class LeaseFence:
    """A runner-bound epoch fence that prevents stale work from committing."""

    job: JobIdentity
    runner_id: str
    lease_id: str
    epoch: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.job, JobIdentity):
            message = "lease job must be a JobIdentity"
            raise ProtocolError(message)
        _require_identifier(self.runner_id, "runner_id")
        _require_identifier(self.lease_id, "lease_id")
        _require_positive_int(self.epoch, "epoch")
        _require_positive_int(self.expires_at_ms, "expires_at_ms")

    @classmethod
    def from_wire(cls, value: object) -> Self:
        body = _require_object(value, "lease")
        _expect_keys(
            body,
            {"epoch", "expires_at_ms", "job", "lease_id", "runner_id"},
            "lease",
        )
        return cls(
            job=JobIdentity.from_wire(body["job"]),
            runner_id=_require_string(body["runner_id"], "runner_id"),
            lease_id=_require_string(body["lease_id"], "lease_id"),
            epoch=_require_positive_int(body["epoch"], "epoch"),
            expires_at_ms=_require_positive_int(body["expires_at_ms"], "expires_at_ms"),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "epoch": self.epoch,
            "expires_at_ms": self.expires_at_ms,
            "job": self.job.to_wire(),
            "lease_id": self.lease_id,
            "runner_id": self.runner_id,
        }

    def assert_allows(self, presented: LeaseFence, *, now_ms: int) -> None:
        """Fence a presented lease against an authoritative current grant."""
        _require_nonnegative_int(now_ms, "now_ms")
        if presented.job != self.job:
            msg = "lease job identity does not match authority"
            raise LeaseFenceError(msg)
        if presented.runner_id != self.runner_id:
            msg = "lease runner does not match authority"
            raise LeaseFenceError(msg)
        if presented.epoch != self.epoch:
            msg = "lease epoch is stale"
            raise LeaseFenceError(msg)
        if presented.lease_id != self.lease_id:
            msg = "lease ID does not match current epoch"
            raise LeaseFenceError(msg)
        if presented.expires_at_ms != self.expires_at_ms:
            msg = "lease expiry does not match authority"
            raise LeaseFenceError(msg)
        if now_ms >= self.expires_at_ms:
            msg = "lease has expired"
            raise LeaseFenceError(msg)


class JobStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class AuthorizationLineage:
    """Signed provenance linking dispatch to an authorization decision."""

    receipt_digest: str
    policy_digest: str
    actor_digest: str
    authorized_at_ms: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        _require_digest(self.receipt_digest, "authorization.receipt_digest")
        _require_digest(self.policy_digest, "authorization.policy_digest")
        _require_digest(self.actor_digest, "authorization.actor_digest")
        _require_nonnegative_int(self.authorized_at_ms, "authorization.authorized_at_ms")
        _require_positive_int(self.expires_at_ms, "authorization.expires_at_ms")
        if self.expires_at_ms <= self.authorized_at_ms:
            message = "authorization validity window is empty"
            raise ProtocolError(message)

    @classmethod
    def from_wire(cls, value: object) -> Self:
        body = _require_object(value, "authorization lineage")
        _expect_keys(
            body,
            {
                "actor_digest",
                "authorized_at_ms",
                "expires_at_ms",
                "policy_digest",
                "receipt_digest",
            },
            "authorization lineage",
        )
        return cls(
            receipt_digest=_require_digest(body["receipt_digest"], "receipt_digest"),
            policy_digest=_require_digest(body["policy_digest"], "policy_digest"),
            actor_digest=_require_digest(body["actor_digest"], "actor_digest"),
            authorized_at_ms=_require_nonnegative_int(body["authorized_at_ms"], "authorized_at_ms"),
            expires_at_ms=_require_positive_int(body["expires_at_ms"], "expires_at_ms"),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "actor_digest": self.actor_digest,
            "authorized_at_ms": self.authorized_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "policy_digest": self.policy_digest,
            "receipt_digest": self.receipt_digest,
        }

    def assert_valid_at(self, *, now_ms: int) -> None:
        """Check the lineage against authoritative dispatch time."""
        _require_nonnegative_int(now_ms, "now_ms")
        if now_ms < self.authorized_at_ms:
            message = "job authorization is not active yet"
            raise DispatchAuthorizationError(message)
        if now_ms >= self.expires_at_ms:
            message = "job authorization has expired"
            raise DispatchAuthorizationError(message)


class WireMessage:
    """Structural base class for signed protocol messages."""

    MESSAGE_TYPE: ClassVar[str]
    message_id: str

    def to_wire(self) -> dict[str, object]:
        raise NotImplementedError

    def tenant_scope(self) -> str:
        raise NotImplementedError

    def organization_scope(self) -> str:
        raise NotImplementedError

    def authenticated_sender_id(self) -> str | None:
        """Return the body principal that must match the signing key identity."""
        return None

    def intended_recipient_id(self) -> str | None:
        """Return the body recipient that must match the signed envelope audience."""
        return None


@dataclass(frozen=True, slots=True)
class JobRequest(WireMessage):
    """Control-plane request authorizing one runner to execute one lease."""

    MESSAGE_TYPE: ClassVar[str] = "job.request.v1"

    message_id: str
    job: JobIdentity
    runner_id: str
    lease: LeaseFence
    policy_digest: str
    authorization: AuthorizationLineage
    workload: CanonicalPayload

    def __post_init__(self) -> None:
        _require_identifier(self.message_id, "message_id")
        _require_identifier(self.runner_id, "runner_id")
        _require_digest(self.policy_digest, "policy_digest")
        if not isinstance(self.job, JobIdentity) or not isinstance(self.lease, LeaseFence):
            message = "request job and lease must be protocol identities"
            raise ProtocolError(message)
        if not isinstance(self.workload, CanonicalPayload):
            message = "request workload must be a CanonicalPayload"
            raise ProtocolError(message)
        if not isinstance(self.authorization, AuthorizationLineage):
            message = "request authorization must be an AuthorizationLineage"
            raise ProtocolError(message)
        if self.authorization.policy_digest != self.policy_digest:
            message = "request policy is not bound to authorization lineage"
            raise ProtocolError(message)
        if self.lease.job != self.job or self.lease.runner_id != self.runner_id:
            msg = "request identity is not bound to its lease"
            raise ProtocolError(msg)

    @property
    def tenant_id(self) -> str:
        return self.job.tenant_id

    def tenant_scope(self) -> str:
        return self.tenant_id

    def organization_scope(self) -> str:
        return self.job.organization_id

    def intended_recipient_id(self) -> str:
        return self.runner_id

    @classmethod
    def from_wire(cls, value: object) -> Self:
        body = _require_object(value, "job request")
        _expect_keys(
            body,
            {
                "job",
                "lease",
                "message_id",
                "authorization",
                "policy_digest",
                "runner_id",
                "workload",
                "workload_digest",
            },
            "job request",
        )
        return cls(
            message_id=_require_string(body["message_id"], "message_id"),
            job=JobIdentity.from_wire(body["job"]),
            runner_id=_require_string(body["runner_id"], "runner_id"),
            lease=LeaseFence.from_wire(body["lease"]),
            policy_digest=_require_digest(body["policy_digest"], "policy_digest"),
            authorization=AuthorizationLineage.from_wire(body["authorization"]),
            workload=CanonicalPayload.from_wire(body["workload"], body["workload_digest"]),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "authorization": self.authorization.to_wire(),
            "job": self.job.to_wire(),
            "lease": self.lease.to_wire(),
            "message_id": self.message_id,
            "policy_digest": self.policy_digest,
            "runner_id": self.runner_id,
            "workload": self.workload.to_mapping(),
            "workload_digest": self.workload.digest,
        }

    @property
    def request_digest(self) -> str:
        return _content_digest(self.to_wire())

    def assert_dispatchable(
        self,
        *,
        authoritative_lease: LeaseFence,
        now_ms: int,
    ) -> None:
        """Fence the lease and authorization immediately before runner dispatch."""
        authoritative_lease.assert_allows(self.lease, now_ms=now_ms)
        self.authorization.assert_valid_at(now_ms=now_ms)


@dataclass(frozen=True, slots=True)
class JobResponse(WireMessage):
    """Runner result bound to the exact request and lease that produced it."""

    MESSAGE_TYPE: ClassVar[str] = "job.response.v1"

    message_id: str
    request_message_id: str
    request_digest: str
    job: JobIdentity
    runner_id: str
    lease: LeaseFence
    status: JobStatus
    started_at_ms: int
    completed_at_ms: int
    result: CanonicalPayload

    def __post_init__(self) -> None:
        _require_identifier(self.message_id, "message_id")
        _require_identifier(self.request_message_id, "request_message_id")
        _require_digest(self.request_digest, "request_digest")
        _require_identifier(self.runner_id, "runner_id")
        if not isinstance(self.job, JobIdentity) or not isinstance(self.lease, LeaseFence):
            message = "response job and lease must be protocol identities"
            raise ProtocolError(message)
        if not isinstance(self.status, JobStatus):
            message = "response status must be a JobStatus"
            raise ProtocolError(message)
        if not isinstance(self.result, CanonicalPayload):
            message = "response result must be a CanonicalPayload"
            raise ProtocolError(message)
        _require_nonnegative_int(self.started_at_ms, "started_at_ms")
        _require_nonnegative_int(self.completed_at_ms, "completed_at_ms")
        if self.completed_at_ms < self.started_at_ms:
            msg = "completed_at_ms precedes started_at_ms"
            raise ProtocolError(msg)
        if self.lease.job != self.job or self.lease.runner_id != self.runner_id:
            msg = "response identity is not bound to its lease"
            raise ProtocolError(msg)

    @property
    def tenant_id(self) -> str:
        return self.job.tenant_id

    def tenant_scope(self) -> str:
        return self.tenant_id

    def organization_scope(self) -> str:
        return self.job.organization_id

    def authenticated_sender_id(self) -> str:
        return self.runner_id

    @classmethod
    def from_wire(cls, value: object) -> Self:
        body = _require_object(value, "job response")
        _expect_keys(
            body,
            {
                "completed_at_ms",
                "job",
                "lease",
                "message_id",
                "request_digest",
                "request_message_id",
                "result",
                "result_digest",
                "runner_id",
                "started_at_ms",
                "status",
            },
            "job response",
        )
        try:
            status = JobStatus(_require_string(body["status"], "status"))
        except ValueError as exc:
            msg = "unknown job response status"
            raise ProtocolError(msg) from exc
        return cls(
            message_id=_require_string(body["message_id"], "message_id"),
            request_message_id=_require_string(body["request_message_id"], "request_message_id"),
            request_digest=_require_digest(body["request_digest"], "request_digest"),
            job=JobIdentity.from_wire(body["job"]),
            runner_id=_require_string(body["runner_id"], "runner_id"),
            lease=LeaseFence.from_wire(body["lease"]),
            status=status,
            started_at_ms=_require_nonnegative_int(body["started_at_ms"], "started_at_ms"),
            completed_at_ms=_require_nonnegative_int(body["completed_at_ms"], "completed_at_ms"),
            result=CanonicalPayload.from_wire(body["result"], body["result_digest"]),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "completed_at_ms": self.completed_at_ms,
            "job": self.job.to_wire(),
            "lease": self.lease.to_wire(),
            "message_id": self.message_id,
            "request_digest": self.request_digest,
            "request_message_id": self.request_message_id,
            "result": self.result.to_mapping(),
            "result_digest": self.result.digest,
            "runner_id": self.runner_id,
            "started_at_ms": self.started_at_ms,
            "status": self.status.value,
        }

    @property
    def response_digest(self) -> str:
        return _content_digest(self.to_wire())

    @property
    def logical_result_digest(self) -> str:
        """Digest one logical request outcome, independent of retry message IDs."""
        body = self.to_wire()
        del body["message_id"]
        return _content_digest(body)


@dataclass(frozen=True, slots=True)
class Heartbeat(WireMessage):
    """Monotonic runner liveness observation with its active lease set."""

    MESSAGE_TYPE: ClassVar[str] = "runner.heartbeat.v1"

    message_id: str
    tenant_id: str
    organization_id: str
    runner_id: str
    sequence: int
    observed_at_ms: int
    active_leases: tuple[LeaseFence, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.message_id, "message_id")
        _require_tenant_identifier(self.tenant_id, "tenant_id")
        _require_organization_identifier(self.organization_id, "organization_id")
        _require_identifier(self.runner_id, "runner_id")
        _require_positive_int(self.sequence, "sequence")
        _require_nonnegative_int(self.observed_at_ms, "observed_at_ms")
        if not isinstance(self.active_leases, tuple):
            message = "heartbeat active_leases must be an immutable tuple"
            raise ProtocolError(message)
        if len(self.active_leases) > _MAX_ACTIVE_LEASES:
            message = f"heartbeat exceeds {_MAX_ACTIVE_LEASES} active leases"
            raise ProtocolError(message)
        keys: list[JobIdentity] = []
        for lease in self.active_leases:
            if (
                lease.job.tenant_id != self.tenant_id
                or lease.job.organization_id != self.organization_id
                or lease.runner_id != self.runner_id
            ):
                msg = "heartbeat lease crosses tenant, organization, or runner boundary"
                raise ProtocolError(msg)
            keys.append(lease.job)
        if len(keys) != len(set(keys)):
            msg = "heartbeat contains duplicate job leases"
            raise ProtocolError(msg)
        if keys != sorted(keys):
            msg = "heartbeat leases must be sorted by job identity"
            raise ProtocolError(msg)

    @classmethod
    def from_wire(cls, value: object) -> Self:
        body = _require_object(value, "heartbeat")
        _expect_keys(
            body,
            {
                "active_leases",
                "message_id",
                "observed_at_ms",
                "organization_id",
                "runner_id",
                "sequence",
                "tenant_id",
            },
            "heartbeat",
        )
        leases = body["active_leases"]
        if not isinstance(leases, list):
            msg = "active_leases must be a list"
            raise ProtocolError(msg)
        return cls(
            message_id=_require_string(body["message_id"], "message_id"),
            tenant_id=_require_string(body["tenant_id"], "tenant_id"),
            organization_id=_require_string(body["organization_id"], "organization_id"),
            runner_id=_require_string(body["runner_id"], "runner_id"),
            sequence=_require_positive_int(body["sequence"], "sequence"),
            observed_at_ms=_require_nonnegative_int(body["observed_at_ms"], "observed_at_ms"),
            active_leases=tuple(LeaseFence.from_wire(item) for item in leases),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "active_leases": [lease.to_wire() for lease in self.active_leases],
            "message_id": self.message_id,
            "observed_at_ms": self.observed_at_ms,
            "organization_id": self.organization_id,
            "runner_id": self.runner_id,
            "sequence": self.sequence,
            "tenant_id": self.tenant_id,
        }

    def tenant_scope(self) -> str:
        return self.tenant_id

    def organization_scope(self) -> str:
        return self.organization_id

    def authenticated_sender_id(self) -> str:
        return self.runner_id


@dataclass(frozen=True, slots=True)
class ResultReceipt(WireMessage):
    """Stable acknowledgement for exactly one accepted result body."""

    MESSAGE_TYPE: ClassVar[str] = "job.result-receipt.v1"

    message_id: str
    job: JobIdentity
    request_message_id: str
    response_message_id: str
    response_digest: str
    logical_result_digest: str
    runner_id: str
    lease_id: str
    lease_epoch: int
    accepted_at_ms: int

    def __post_init__(self) -> None:
        _require_identifier(self.message_id, "message_id")
        _require_identifier(self.request_message_id, "request_message_id")
        _require_identifier(self.response_message_id, "response_message_id")
        _require_digest(self.response_digest, "response_digest")
        _require_digest(self.logical_result_digest, "logical_result_digest")
        _require_identifier(self.runner_id, "runner_id")
        _require_identifier(self.lease_id, "lease_id")
        _require_positive_int(self.lease_epoch, "lease_epoch")
        _require_nonnegative_int(self.accepted_at_ms, "accepted_at_ms")
        if not isinstance(self.job, JobIdentity):
            message = "receipt job must be a JobIdentity"
            raise ProtocolError(message)

    @property
    def tenant_id(self) -> str:
        return self.job.tenant_id

    def tenant_scope(self) -> str:
        return self.tenant_id

    def organization_scope(self) -> str:
        return self.job.organization_id

    def intended_recipient_id(self) -> str:
        return self.runner_id

    @classmethod
    def from_wire(cls, value: object) -> Self:
        body = _require_object(value, "result receipt")
        _expect_keys(
            body,
            {
                "accepted_at_ms",
                "job",
                "lease_epoch",
                "lease_id",
                "message_id",
                "logical_result_digest",
                "request_message_id",
                "response_digest",
                "response_message_id",
                "runner_id",
            },
            "result receipt",
        )
        return cls(
            message_id=_require_string(body["message_id"], "message_id"),
            job=JobIdentity.from_wire(body["job"]),
            request_message_id=_require_string(body["request_message_id"], "request_message_id"),
            response_message_id=_require_string(body["response_message_id"], "response_message_id"),
            response_digest=_require_digest(body["response_digest"], "response_digest"),
            logical_result_digest=_require_digest(
                body["logical_result_digest"], "logical_result_digest"
            ),
            runner_id=_require_string(body["runner_id"], "runner_id"),
            lease_id=_require_string(body["lease_id"], "lease_id"),
            lease_epoch=_require_positive_int(body["lease_epoch"], "lease_epoch"),
            accepted_at_ms=_require_nonnegative_int(body["accepted_at_ms"], "accepted_at_ms"),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "accepted_at_ms": self.accepted_at_ms,
            "job": self.job.to_wire(),
            "lease_epoch": self.lease_epoch,
            "lease_id": self.lease_id,
            "message_id": self.message_id,
            "logical_result_digest": self.logical_result_digest,
            "request_message_id": self.request_message_id,
            "response_digest": self.response_digest,
            "response_message_id": self.response_message_id,
            "runner_id": self.runner_id,
        }


_MESSAGE_DECODERS = {
    Heartbeat.MESSAGE_TYPE: Heartbeat.from_wire,
    JobRequest.MESSAGE_TYPE: JobRequest.from_wire,
    JobResponse.MESSAGE_TYPE: JobResponse.from_wire,
    ResultReceipt.MESSAGE_TYPE: ResultReceipt.from_wire,
}


class VerificationKeyStatus(StrEnum):
    """Authoritative verification-key lifecycle state."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"
    COMPROMISED = "compromised"


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """Public key bound to one tenant, organization, sender, and purpose set."""

    key_id: str
    tenant_id: str
    organization_id: str
    sender_id: str
    public_key_bytes: bytes = field(repr=False)
    allowed_message_types: frozenset[str]
    not_before_ms: int = 0
    expires_at_ms: int | None = None
    status: VerificationKeyStatus = VerificationKeyStatus.ACTIVE
    status_changed_at_ms: int | None = None

    def __post_init__(self) -> None:  # noqa: C901 - lifecycle invariants are centralized
        _require_identifier(self.key_id, "key_id")
        _require_tenant_identifier(self.tenant_id, "tenant_id")
        _require_organization_identifier(self.organization_id, "organization_id")
        _require_identifier(self.sender_id, "sender_id")
        if not isinstance(self.public_key_bytes, bytes) or len(self.public_key_bytes) != 32:  # noqa: PLR2004
            msg = "Ed25519 public key must be 32 bytes"
            raise ProtocolError(msg)
        if not isinstance(self.allowed_message_types, frozenset):
            message = "verification key message types must be an immutable frozenset"
            raise ProtocolError(message)
        if not self.allowed_message_types:
            msg = "verification key requires an allowed message type"
            raise ProtocolError(msg)
        unknown = self.allowed_message_types - _MESSAGE_DECODERS.keys()
        if unknown:
            msg = "verification key allows unknown message types"
            raise ProtocolError(msg)
        _require_nonnegative_int(self.not_before_ms, "not_before_ms")
        if not isinstance(self.status, VerificationKeyStatus):
            message = "verification key status must be a VerificationKeyStatus"
            raise ProtocolError(message)
        if self.expires_at_ms is not None:
            _require_positive_int(self.expires_at_ms, "expires_at_ms")
            if self.expires_at_ms <= self.not_before_ms:
                msg = "verification key validity window is empty"
                raise ProtocolError(msg)
        if self.status is VerificationKeyStatus.ACTIVE:
            if self.status_changed_at_ms is not None:
                message = "active verification key cannot have a status transition time"
                raise ProtocolError(message)
        else:
            if self.status_changed_at_ms is None:
                message = "non-active verification key requires a status transition time"
                raise ProtocolError(message)
            _require_nonnegative_int(self.status_changed_at_ms, "status_changed_at_ms")
            if self.status is VerificationKeyStatus.RETIRED and self.expires_at_ms is None:
                message = "retired verification key requires a verification expiry"
                raise ProtocolError(message)


class MessageSigner(Protocol):
    """Port for local, KMS, or HSM-backed Ed25519 signing identities."""

    @property
    def key_id(self) -> str: ...

    @property
    def tenant_id(self) -> str: ...

    @property
    def organization_id(self) -> str: ...

    @property
    def sender_id(self) -> str: ...

    def sign(
        self,
        content: bytes,
        *,
        message_type: str,
        tenant_id: str,
        organization_id: str,
    ) -> bytes: ...


class Ed25519Signer:
    """Signing identity whose private material is never serialized or repr'd."""

    __slots__ = (
        "_allowed_message_types",
        "_key",
        "_key_id",
        "_organization_id",
        "_sender_id",
        "_tenant_id",
    )

    def __init__(  # noqa: PLR0913 - signing identity binds every isolation dimension
        self,
        *,
        key_id: str,
        tenant_id: str,
        organization_id: str,
        sender_id: str,
        private_key: Ed25519PrivateKey,
        allowed_message_types: Iterable[str],
    ) -> None:
        self._key_id = _require_identifier(key_id, "key_id")
        self._tenant_id = _require_tenant_identifier(tenant_id, "tenant_id")
        self._organization_id = _require_organization_identifier(organization_id, "organization_id")
        self._sender_id = _require_identifier(sender_id, "sender_id")
        allowed = frozenset(allowed_message_types)
        if not allowed or allowed - _MESSAGE_DECODERS.keys():
            msg = "signer message type allowlist is empty or invalid"
            raise ProtocolError(msg)
        self._allowed_message_types = allowed
        if not isinstance(private_key, Ed25519PrivateKey):
            message = "private_key must be an Ed25519 private key"
            raise ProtocolError(message)
        self._key = private_key

    @classmethod
    def generate(
        cls,
        *,
        key_id: str,
        tenant_id: str,
        organization_id: str,
        sender_id: str,
        allowed_message_types: Iterable[str],
    ) -> Self:
        return cls(
            key_id=key_id,
            tenant_id=tenant_id,
            organization_id=organization_id,
            sender_id=sender_id,
            private_key=Ed25519PrivateKey.generate(),
            allowed_message_types=allowed_message_types,
        )

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def sender_id(self) -> str:
        return self._sender_id

    def verification_key(
        self,
        *,
        not_before_ms: int = 0,
        expires_at_ms: int | None = None,
        status: VerificationKeyStatus = VerificationKeyStatus.ACTIVE,
        status_changed_at_ms: int | None = None,
    ) -> VerificationKey:
        raw = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return VerificationKey(
            key_id=self.key_id,
            tenant_id=self.tenant_id,
            organization_id=self.organization_id,
            sender_id=self.sender_id,
            public_key_bytes=raw,
            allowed_message_types=self._allowed_message_types,
            not_before_ms=not_before_ms,
            expires_at_ms=expires_at_ms,
            status=status,
            status_changed_at_ms=status_changed_at_ms,
        )

    def sign(
        self,
        content: bytes,
        *,
        message_type: str,
        tenant_id: str,
        organization_id: str,
    ) -> bytes:
        if tenant_id != self.tenant_id:
            msg = "signer cannot cross tenant boundary"
            raise AuthenticationError(msg)
        if organization_id != self.organization_id:
            msg = "signer cannot cross organization boundary"
            raise AuthenticationError(msg)
        if message_type not in self._allowed_message_types:
            msg = "signer is not authorized for this message type"
            raise AuthenticationError(msg)
        return self._key.sign(content)


class VerificationKeyring:
    """Immutable key-ID resolver that rejects ambiguous rotation state."""

    def __init__(self, keys: Iterable[VerificationKey]) -> None:
        by_id: dict[str, VerificationKey] = {}
        for key in keys:
            if key.key_id in by_id:
                msg = f"duplicate verification key ID: {key.key_id}"
                raise ProtocolError(msg)
            by_id[key.key_id] = key
        if not by_id:
            msg = "verification keyring cannot be empty"
            raise ProtocolError(msg)
        self._by_id = by_id

    def resolve(self, key_id: str) -> VerificationKey:
        try:
            return self._by_id[key_id]
        except KeyError as exc:
            msg = "unknown verification key"
            raise AuthenticationError(msg) from exc


class VerificationKeyResolver(Protocol):
    """Port for a key registry or tenant-aware KMS-backed resolver."""

    def resolve(self, key_id: str) -> VerificationKey: ...


@dataclass(frozen=True, slots=True)
class ReplayClaim:
    """Authenticated replay identity suitable for an atomic durable commit."""

    deployment_id: str
    environment: str
    tenant_id: str
    organization_id: str
    sender_id: str
    recipient_id: str
    audience: str
    message_id: str
    nonce: str
    expires_at_ms: int

    def __post_init__(self) -> None:
        _require_identifier(self.deployment_id, "deployment_id")
        _require_identifier(self.environment, "environment")
        _require_tenant_identifier(self.tenant_id, "tenant_id")
        _require_organization_identifier(self.organization_id, "organization_id")
        _require_identifier(self.sender_id, "sender_id")
        _require_identifier(self.recipient_id, "recipient_id")
        _require_identifier(self.audience, "audience")
        _require_identifier(self.message_id, "message_id")
        _require_nonce(self.nonce)
        _require_positive_int(self.expires_at_ms, "expires_at_ms")


@dataclass(frozen=True, slots=True)
class VerifiedMessage:
    """Signature-verified message not yet committed to replay state."""

    message: WireMessage
    replay_claim: ReplayClaim
    key_id: str
    issued_at_ms: int
    wire_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.key_id, "key_id")
        _require_nonnegative_int(self.issued_at_ms, "issued_at_ms")
        _require_digest(self.wire_digest, "wire_digest")
        if (
            self.message.message_id != self.replay_claim.message_id
            or self.message.tenant_scope() != self.replay_claim.tenant_id
            or self.message.organization_scope() != self.replay_claim.organization_id
        ):
            message = "verified message is not bound to its replay claim"
            raise ProtocolError(message)


class ReplayProtector(Protocol):
    """Port whose production implementation atomically persists replay claims."""

    def accept(self, claim: ReplayClaim, *, now_ms: int) -> None: ...


class InMemoryReplayProtector:
    """Atomic bounded replay cache; production adapters must persist this state."""

    def __init__(self, *, max_entries: int = 100_000) -> None:
        self._max_entries = _require_positive_int(max_entries, "max_entries")
        self._messages: dict[tuple[str, str, str, str, str, str], tuple[str, int]] = {}
        self._nonces: dict[tuple[str, str, str, str, str, str], tuple[str, int]] = {}
        self._lock = threading.Lock()

    def accept(self, claim: ReplayClaim, *, now_ms: int) -> None:
        _require_nonnegative_int(now_ms, "now_ms")
        if claim.expires_at_ms <= now_ms:
            message = "replay claim has already expired"
            raise AuthenticationError(message)
        message_key = (
            claim.deployment_id,
            claim.environment,
            claim.tenant_id,
            claim.organization_id,
            claim.sender_id,
            claim.message_id,
        )
        nonce_key = (
            claim.deployment_id,
            claim.environment,
            claim.tenant_id,
            claim.organization_id,
            claim.sender_id,
            claim.nonce,
        )
        with self._lock:
            self._purge_expired(now_ms)
            if message_key in self._messages:
                msg = "message ID has already been accepted"
                raise ReplayError(msg)
            if nonce_key in self._nonces:
                msg = "message nonce has already been accepted"
                raise ReplayError(msg)
            if len(self._messages) >= self._max_entries:
                msg = "replay registry capacity reached"
                raise RegistryCapacityError(msg)
            self._messages[message_key] = (claim.nonce, claim.expires_at_ms)
            self._nonces[nonce_key] = (claim.message_id, claim.expires_at_ms)

    def _purge_expired(self, now_ms: int) -> None:
        expired_messages = [key for key, (_, expiry) in self._messages.items() if expiry <= now_ms]
        for key in expired_messages:
            nonce, _ = self._messages.pop(key)
            self._nonces.pop((key[0], key[1], key[2], key[3], key[4], nonce), None)


class InMemoryHeartbeatRegistry:
    """Rejects reordered heartbeats even when they use fresh envelope IDs."""

    def __init__(self, *, max_runners: int = 10_000) -> None:
        self._max_runners = _require_positive_int(max_runners, "max_runners")
        self._latest: dict[tuple[str, str, str], Heartbeat] = {}
        self._lock = threading.Lock()

    def accept(self, heartbeat: Heartbeat) -> Heartbeat:
        key = (heartbeat.tenant_id, heartbeat.organization_id, heartbeat.runner_id)
        with self._lock:
            previous = self._latest.get(key)
            if previous is not None and heartbeat.sequence <= previous.sequence:
                message = "heartbeat sequence is stale or replayed"
                raise ReplayError(message)
            if previous is None and len(self._latest) >= self._max_runners:
                message = "heartbeat registry capacity reached"
                raise RegistryCapacityError(message)
            self._latest[key] = heartbeat
            return heartbeat


class ProtocolCodec:
    """Environment-bound Ed25519 encoder and authentication boundary."""

    def __init__(  # noqa: PLR0913 - protocol policy is explicit at construction
        self,
        *,
        keyring: VerificationKeyResolver,
        replay_protector: ReplayProtector,
        deployment_id: str,
        environment: str,
        max_ttl_ms: int = 300_000,
        clock_skew_ms: int = 30_000,
    ) -> None:
        self._keyring = keyring
        self._replay = replay_protector
        self._deployment_id = _require_identifier(deployment_id, "deployment_id")
        self._environment = _require_identifier(environment, "environment")
        self._max_ttl_ms = _require_positive_int(max_ttl_ms, "max_ttl_ms")
        self._clock_skew_ms = _require_nonnegative_int(clock_skew_ms, "clock_skew_ms")

    def encode(  # noqa: PLR0913 - every signed routing dimension is explicit
        self,
        message: WireMessage,
        *,
        signer: MessageSigner,
        nonce: str,
        recipient_id: str,
        audience: str,
        issued_at_ms: int,
        expires_at_ms: int,
    ) -> bytes:
        nonce = _require_nonce(nonce)
        recipient_id = _require_identifier(recipient_id, "recipient_id")
        audience = _require_identifier(audience, "audience")
        signer_key_id = _require_identifier(signer.key_id, "signer.key_id")
        signer_tenant_id = _require_tenant_identifier(signer.tenant_id, "signer.tenant_id")
        signer_organization_id = _require_organization_identifier(
            signer.organization_id, "signer.organization_id"
        )
        signer_sender_id = _require_identifier(signer.sender_id, "signer.sender_id")
        if signer_tenant_id != message.tenant_scope():
            msg = "signing identity cannot cross tenant boundary"
            raise AuthenticationError(msg)
        if signer_organization_id != message.organization_scope():
            msg = "signing identity cannot cross organization boundary"
            raise AuthenticationError(msg)
        self._validate_window(issued_at_ms=issued_at_ms, expires_at_ms=expires_at_ms)
        body_sender = message.authenticated_sender_id()
        if body_sender is not None and body_sender != signer_sender_id:
            msg = "message body principal does not match signing identity"
            raise AuthenticationError(msg)
        required_recipient = message.intended_recipient_id()
        if required_recipient is not None and required_recipient != recipient_id:
            msg = "message body recipient does not match signed recipient"
            raise AuthenticationError(msg)
        unsigned = {
            "algorithm": _ALGORITHM,
            "audience": audience,
            "body": message.to_wire(),
            "deployment_id": self._deployment_id,
            "environment": self._environment,
            "expires_at_ms": expires_at_ms,
            "issued_at_ms": issued_at_ms,
            "key_id": signer_key_id,
            "message_id": message.message_id,
            "message_type": message.MESSAGE_TYPE,
            "nonce": nonce,
            "organization_id": message.organization_scope(),
            "protocol_version": _PROTOCOL_VERSION,
            "recipient_id": recipient_id,
            "sender_id": signer_sender_id,
            "tenant_id": message.tenant_scope(),
        }
        signing_input = _signature_input(unsigned)
        signature = signer.sign(
            signing_input,
            message_type=message.MESSAGE_TYPE,
            tenant_id=message.tenant_scope(),
            organization_id=message.organization_scope(),
        )
        if not isinstance(signature, bytes) or len(signature) != 64:  # noqa: PLR2004
            msg = "Ed25519 signer returned an invalid signature"
            raise AuthenticationError(msg)
        envelope = {**unsigned, "signature": _b64url_encode(signature)}
        encoded = _canonical_json(envelope)
        if len(encoded) > _MAX_WIRE_BYTES:
            msg = "wire envelope exceeds maximum size"
            raise ProtocolError(msg)
        return encoded

    def decode_ephemeral(  # noqa: PLR0913 - every expected route binding is explicit
        self,
        raw: bytes,
        *,
        expected_tenant_id: str,
        expected_organization_id: str,
        expected_recipient_id: str,
        expected_audience: str,
        expected_sender_id: str,
        now_ms: int,
        expected_message_type: str | None = None,
    ) -> WireMessage:
        """Authenticate then claim in process-local state; never use for mutations."""
        verified = self.authenticate(
            raw,
            expected_tenant_id=expected_tenant_id,
            expected_organization_id=expected_organization_id,
            expected_recipient_id=expected_recipient_id,
            expected_audience=expected_audience,
            now_ms=now_ms,
            expected_sender_id=expected_sender_id,
            expected_message_type=expected_message_type,
        )
        self._replay.accept(verified.replay_claim, now_ms=now_ms)
        return verified.message

    def authenticate(  # noqa: C901, PLR0912, PLR0913, PLR0915
        self,
        raw: bytes,
        *,
        expected_tenant_id: str,
        expected_organization_id: str,
        expected_recipient_id: str,
        expected_audience: str,
        expected_sender_id: str,
        now_ms: int,
        expected_message_type: str | None = None,
    ) -> VerifiedMessage:
        """Verify for an atomic transaction; ``now_ms`` must be authoritative server time."""
        _require_tenant_identifier(expected_tenant_id, "expected_tenant_id")
        _require_organization_identifier(expected_organization_id, "expected_organization_id")
        _require_identifier(expected_recipient_id, "expected_recipient_id")
        _require_identifier(expected_audience, "expected_audience")
        _require_identifier(expected_sender_id, "expected_sender_id")
        _require_nonnegative_int(now_ms, "now_ms")
        if not isinstance(raw, bytes) or len(raw) > _MAX_WIRE_BYTES:
            msg = "wire envelope must be bounded bytes"
            raise ProtocolError(msg)
        envelope = _require_object(_loads_json(raw), "wire envelope")
        if _canonical_json(envelope) != raw:
            msg = "wire envelope is not canonical JSON"
            raise ProtocolError(msg)
        signature_value = envelope.get("signature")
        _expect_keys(
            envelope,
            {
                "algorithm",
                "audience",
                "body",
                "deployment_id",
                "environment",
                "expires_at_ms",
                "issued_at_ms",
                "key_id",
                "message_id",
                "message_type",
                "nonce",
                "organization_id",
                "protocol_version",
                "recipient_id",
                "sender_id",
                "signature",
                "tenant_id",
            },
            "wire envelope",
        )
        protocol_version = _require_positive_int(envelope["protocol_version"], "protocol_version")
        if protocol_version != _PROTOCOL_VERSION:
            msg = "unsupported protocol version"
            raise AuthenticationError(msg)
        if envelope["algorithm"] != _ALGORITHM:
            msg = "unsupported signature algorithm"
            raise AuthenticationError(msg)
        deployment_id = _require_identifier(envelope["deployment_id"], "deployment_id")
        environment = _require_identifier(envelope["environment"], "environment")
        tenant_id = _require_tenant_identifier(envelope["tenant_id"], "tenant_id")
        organization_id = _require_organization_identifier(
            envelope["organization_id"], "organization_id"
        )
        sender_id = _require_identifier(envelope["sender_id"], "sender_id")
        recipient_id = _require_identifier(envelope["recipient_id"], "recipient_id")
        audience = _require_identifier(envelope["audience"], "audience")
        key_id = _require_identifier(envelope["key_id"], "key_id")
        message_id = _require_identifier(envelope["message_id"], "message_id")
        nonce = _require_nonce(envelope["nonce"])
        message_type = _require_string(envelope["message_type"], "message_type")
        issued_at_ms = _require_nonnegative_int(envelope["issued_at_ms"], "issued_at_ms")
        expires_at_ms = _require_positive_int(envelope["expires_at_ms"], "expires_at_ms")
        self._validate_window(issued_at_ms=issued_at_ms, expires_at_ms=expires_at_ms)
        if deployment_id != self._deployment_id:
            msg = "message deployment does not match verifier deployment"
            raise AuthenticationError(msg)
        if environment != self._environment:
            msg = "message environment does not match verifier environment"
            raise AuthenticationError(msg)
        if tenant_id != expected_tenant_id:
            msg = "message tenant does not match authenticated route"
            raise AuthenticationError(msg)
        if organization_id != expected_organization_id:
            msg = "message organization does not match authenticated route"
            raise AuthenticationError(msg)
        if recipient_id != expected_recipient_id:
            msg = "message recipient does not match authenticated route"
            raise AuthenticationError(msg)
        if audience != expected_audience:
            msg = "message audience does not match authenticated route"
            raise AuthenticationError(msg)
        if sender_id != expected_sender_id:
            msg = "message sender does not match authenticated route"
            raise AuthenticationError(msg)
        if expected_message_type is not None and message_type != expected_message_type:
            msg = "unexpected message type"
            raise AuthenticationError(msg)
        if issued_at_ms > now_ms + self._clock_skew_ms:
            msg = "message issue time is too far in the future"
            raise AuthenticationError(msg)
        if expires_at_ms <= now_ms:
            msg = "message has expired"
            raise AuthenticationError(msg)
        key = self._keyring.resolve(key_id)
        self._validate_key(
            key,
            tenant_id=tenant_id,
            organization_id=organization_id,
            sender_id=sender_id,
            message_type=message_type,
            issued_at_ms=issued_at_ms,
            now_ms=now_ms,
        )
        signature = _b64url_decode(signature_value)
        unsigned = dict(envelope)
        del unsigned["signature"]
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key_bytes).verify(
                signature,
                _signature_input(unsigned),
            )
        except InvalidSignature as exc:
            msg = "invalid message signature"
            raise AuthenticationError(msg) from exc
        decoder = _MESSAGE_DECODERS.get(message_type)
        if decoder is None:
            msg = "unknown message type"
            raise AuthenticationError(msg)
        message = decoder(envelope["body"])
        if (
            message.message_id != message_id
            or message.tenant_scope() != tenant_id
            or message.organization_scope() != organization_id
        ):
            msg = "envelope identity is not bound to message body"
            raise AuthenticationError(msg)
        body_sender = message.authenticated_sender_id()
        if body_sender is not None and body_sender != sender_id:
            msg = "message body principal does not match authenticated sender"
            raise AuthenticationError(msg)
        required_recipient = message.intended_recipient_id()
        if required_recipient is not None and required_recipient != recipient_id:
            msg = "message body recipient does not match signed recipient"
            raise AuthenticationError(msg)
        replay_claim = ReplayClaim(
            deployment_id=deployment_id,
            environment=environment,
            tenant_id=tenant_id,
            organization_id=organization_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            audience=audience,
            message_id=message_id,
            nonce=nonce,
            expires_at_ms=expires_at_ms,
        )
        return VerifiedMessage(
            message=message,
            replay_claim=replay_claim,
            key_id=key_id,
            issued_at_ms=issued_at_ms,
            wire_digest=hashlib.sha256(raw).hexdigest(),
        )

    def _validate_window(self, *, issued_at_ms: int, expires_at_ms: int) -> None:
        _require_nonnegative_int(issued_at_ms, "issued_at_ms")
        _require_positive_int(expires_at_ms, "expires_at_ms")
        if expires_at_ms <= issued_at_ms:
            msg = "message validity window is empty"
            raise ProtocolError(msg)
        if expires_at_ms - issued_at_ms > self._max_ttl_ms:
            msg = "message validity window exceeds maximum TTL"
            raise ProtocolError(msg)

    @staticmethod
    def _validate_key(  # noqa: PLR0913 - complete key context is required
        key: VerificationKey,
        *,
        tenant_id: str,
        organization_id: str,
        sender_id: str,
        message_type: str,
        issued_at_ms: int,
        now_ms: int,
    ) -> None:
        if (
            key.tenant_id != tenant_id
            or key.organization_id != organization_id
            or key.sender_id != sender_id
        ):
            msg = "verification key identity mismatch"
            raise AuthenticationError(msg)
        if message_type not in key.allowed_message_types:
            msg = "verification key is not authorized for message type"
            raise AuthenticationError(msg)
        if key.status in {
            VerificationKeyStatus.REVOKED,
            VerificationKeyStatus.COMPROMISED,
        }:
            msg = f"verification key is {key.status.value}"
            raise AuthenticationError(msg)
        if key.status_changed_at_ms is not None and key.status_changed_at_ms > now_ms:
            msg = "verification key lifecycle state is not yet effective"
            raise AuthenticationError(msg)
        if issued_at_ms < key.not_before_ms:
            msg = "message predates verification key"
            raise AuthenticationError(msg)
        if now_ms < key.not_before_ms:
            msg = "verification key is not active yet"
            raise AuthenticationError(msg)
        if key.expires_at_ms is not None and issued_at_ms >= key.expires_at_ms:
            msg = "message postdates verification key"
            raise AuthenticationError(msg)
        if key.expires_at_ms is not None and now_ms >= key.expires_at_ms:
            msg = "verification key has expired"
            raise AuthenticationError(msg)
        if (
            key.status is VerificationKeyStatus.RETIRED
            and key.status_changed_at_ms is not None
            and issued_at_ms >= key.status_changed_at_ms
        ):
            msg = "message was issued after verification key retirement"
            raise AuthenticationError(msg)


class InMemoryResultReceiptRegistry:
    """Thread-safe reference implementation of idempotent result acceptance."""

    def __init__(self, *, max_entries: int = 100_000) -> None:
        self._max_entries = _require_positive_int(max_entries, "max_entries")
        self._receipts: dict[tuple[JobIdentity, str], ResultReceipt] = {}
        self._lock = threading.Lock()

    def accept(
        self,
        response: JobResponse,
        *,
        authoritative_request: JobRequest,
        authoritative_lease: LeaseFence,
        accepted_at_ms: int,
    ) -> ResultReceipt:
        _require_nonnegative_int(accepted_at_ms, "accepted_at_ms")
        _assert_response_request_binding(response, authoritative_request)
        key = (response.job, response.request_message_id)
        response_digest = response.response_digest
        logical_result_digest = response.logical_result_digest
        with self._lock:
            existing = self._receipts.get(key)
            if existing is not None:
                if existing.logical_result_digest != logical_result_digest:
                    msg = "logical request already has a different result"
                    raise ResultConflictError(msg)
                return existing
            authoritative_lease.assert_allows(
                authoritative_request.lease,
                now_ms=accepted_at_ms,
            )
            if len(self._receipts) >= self._max_entries:
                msg = "result receipt registry capacity reached"
                raise RegistryCapacityError(msg)
            receipt = ResultReceipt(
                message_id=_receipt_id(response, logical_result_digest),
                job=response.job,
                request_message_id=response.request_message_id,
                response_message_id=response.message_id,
                response_digest=response_digest,
                logical_result_digest=logical_result_digest,
                runner_id=response.runner_id,
                lease_id=response.lease.lease_id,
                lease_epoch=response.lease.epoch,
                accepted_at_ms=accepted_at_ms,
            )
            self._receipts[key] = receipt
            return receipt


def _assert_response_request_binding(
    response: JobResponse,
    authoritative_request: JobRequest,
) -> None:
    bound = (
        response.request_message_id == authoritative_request.message_id
        and response.request_digest == authoritative_request.request_digest
        and response.job == authoritative_request.job
        and response.runner_id == authoritative_request.runner_id
        and response.lease == authoritative_request.lease
    )
    if not bound:
        message = "result is not bound to the authoritative request"
        raise ResultConflictError(message)


def _receipt_id(response: JobResponse, logical_result_digest: str) -> str:
    content = {
        "job": response.job.to_wire(),
        "logical_result_digest": logical_result_digest,
        "request_message_id": response.request_message_id,
    }
    return f"receipt:{_content_digest(content)}"


def _validate_json_tree(  # noqa: C901 - explicit recursive JSON type boundary
    value: object,
) -> object:
    item_count = [0]

    def visit(item: object, depth: int) -> object:
        if depth > _MAX_JSON_DEPTH:
            msg = "value exceeds maximum JSON depth"
            raise ProtocolError(msg)
        item_count[0] += 1
        if item_count[0] > _MAX_JSON_ITEMS:
            msg = "value exceeds maximum JSON item count"
            raise ProtocolError(msg)
        if item is None or type(item) in {bool, str}:
            return item
        if type(item) is int:
            if not _MIN_INT <= item <= _MAX_INT:
                msg = "JSON integer exceeds signed 64-bit range"
                raise ProtocolError(msg)
            return item
        if isinstance(item, Mapping):
            normalized: dict[str, object] = {}
            for key, nested in item.items():
                if not isinstance(key, str):
                    msg = "JSON object keys must be strings"
                    raise ProtocolError(msg)
                normalized[key] = visit(nested, depth + 1)
            return normalized
        if isinstance(item, (list, tuple)):
            return [visit(nested, depth + 1) for nested in item]
        msg = "value contains a non-JSON type"
        raise ProtocolError(msg)

    return visit(value, 0)


def _validate_json_object(value: Mapping[str, object]) -> dict[str, object]:
    result = _validate_json_tree(value)
    if not isinstance(result, dict):  # pragma: no cover - input type guarantees this
        msg = "payload must be an object"
        raise ProtocolError(msg)
    return result


def _loads_json(raw: bytes) -> object:  # noqa: C901 - one normalized parser boundary
    if len(raw) > _MAX_WIRE_BYTES:
        msg = "JSON input exceeds maximum size"
        raise ProtocolError(msg)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                msg = f"duplicate JSON key: {key}"
                raise ProtocolError(msg)
            result[key] = value
        return result

    def parse_integer(raw_integer: str) -> int:
        digits = raw_integer.removeprefix("-")
        if len(digits) > 19:  # noqa: PLR2004 - signed 64-bit decimal width
            message = "JSON integer exceeds signed 64-bit range"
            raise ProtocolError(message)
        parsed = int(raw_integer)
        if not _MIN_INT <= parsed <= _MAX_INT:
            message = "JSON integer exceeds signed 64-bit range"
            raise ProtocolError(message)
        return parsed

    def reject_float(_raw_float: str) -> object:
        message = "floating-point JSON values are not supported"
        raise ProtocolError(message)

    def reject_constant(_raw_constant: str) -> object:
        message = "non-finite JSON values are not supported"
        raise ProtocolError(message)

    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
            parse_float=reject_float,
            parse_int=parse_integer,
        )
        return _validate_json_tree(parsed)
    except ProtocolError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        OverflowError,
        RecursionError,
        ValueError,
    ) as exc:
        msg = "invalid or structurally excessive UTF-8 JSON"
        raise ProtocolError(msg) from exc


def _canonical_json(value: object) -> bytes:
    try:
        normalized = _validate_json_tree(value)
        return json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except ProtocolError:
        raise
    except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        msg = "value is not canonical JSON"
        raise ProtocolError(msg) from exc


def _signature_input(unsigned_envelope: object) -> bytes:
    return _SIGNATURE_DOMAIN + _canonical_json(unsigned_envelope)


def _content_digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _expect_keys(body: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(body)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        msg = f"{label} fields mismatch; missing={missing}, unknown={unknown}"
        raise ProtocolError(msg)


def _require_object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        msg = f"{label} must be an object"
        raise ProtocolError(msg)
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        msg = f"{label} must be a string"
        raise ProtocolError(msg)
    return value


def _require_identifier(value: object, label: str) -> str:
    text = _require_string(value, label)
    if not _IDENTIFIER.fullmatch(text):
        msg = f"{label} is not a valid identifier"
        raise ProtocolError(msg)
    return text


def generate_nonce() -> str:
    """Generate the required 128-bit lowercase hexadecimal envelope nonce."""
    return secrets.token_hex(16)


def _require_nonce(value: object) -> str:
    text = _require_string(value, "nonce")
    if not _NONCE.fullmatch(text):
        msg = "nonce must encode exactly 128 bits as 32 lowercase hexadecimal characters"
        raise ProtocolError(msg)
    return text


def _require_tenant_identifier(value: object, label: str) -> str:
    text = _require_string(value, label)
    try:
        TenantId(text)
    except (TypeError, ValueError) as exc:
        message = f"{label} is not a canonical tenant identifier"
        raise ProtocolError(message) from exc
    return text


def _require_organization_identifier(value: object, label: str) -> str:
    text = _require_string(value, label)
    try:
        OrganizationId(text)
    except (TypeError, ValueError) as exc:
        message = f"{label} is not a canonical organization identifier"
        raise ProtocolError(message) from exc
    return text


def _require_digest(value: object, label: str) -> str:
    text = _require_string(value, label)
    if not _DIGEST.fullmatch(text):
        msg = f"{label} must be a lowercase SHA-256 digest"
        raise ProtocolError(msg)
    return text


def _require_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INT:
        msg = f"{label} must be a non-negative signed 64-bit integer"
        raise ProtocolError(msg)
    return value


def _require_positive_int(value: object, label: str) -> int:
    result = _require_nonnegative_int(value, label)
    if result == 0:
        msg = f"{label} must be positive"
        raise ProtocolError(msg)
    return result


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: object) -> bytes:
    text = _require_string(value, "signature")
    if not _SIGNATURE.fullmatch(text):
        msg = "signature encoding is invalid"
        raise AuthenticationError(msg)
    try:
        decoded = base64.b64decode(text + "==", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = "signature encoding is invalid"
        raise AuthenticationError(msg) from exc
    if len(decoded) != 64:  # noqa: PLR2004
        msg = "signature length is invalid"
        raise AuthenticationError(msg)
    return decoded
