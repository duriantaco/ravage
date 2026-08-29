"""Authenticity boundary for issued control-plane authorization receipts."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AUTHORIZATION_ATTESTATION_ALGORITHM = "Ed25519"
AUTHORIZATION_ATTESTATION_DOMAIN = b"ravage.authorization-receipt.v1\0"

_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}\Z")


class AuthorizationReceiptAuthenticityError(ValueError):
    """Raised when a receipt lacks a valid server attestation."""


class AuthorizationReceiptSigner(Protocol):
    """Port implemented by a server key, KMS, or durable receipt issuer."""

    @property
    def issuer_id(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def sign(self, content: bytes) -> str: ...


class AuthorizationReceiptVerifier(Protocol):
    """Port for authenticating a server-issued authorization receipt."""

    def verify(  # noqa: PLR0913
        self,
        *,
        issuer_id: str,
        key_id: str,
        algorithm: str,
        evaluated_at: datetime,
        content: bytes,
        signature: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class AuthorizationReceiptVerificationKey:
    """One Ed25519 verification key with an issuance validity window."""

    issuer_id: str
    key_id: str
    public_key_bytes: bytes = field(repr=False)
    not_before: datetime
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.issuer_id, "issuer_id")
        _require_identifier(self.key_id, "key_id")
        if type(self.public_key_bytes) is not bytes or len(self.public_key_bytes) != 32:  # noqa: PLR2004
            message = "Ed25519 public key must be exactly 32 bytes"
            raise ValueError(message)
        not_before = _require_utc(self.not_before, "not_before")
        expires_at = (
            _require_utc(self.expires_at, "expires_at") if self.expires_at is not None else None
        )
        if expires_at is not None and expires_at <= not_before:
            message = "verification-key validity window is empty"
            raise ValueError(message)
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "expires_at", expires_at)


class Ed25519AuthorizationReceiptSigner:
    """In-process signer; production may replace it with a KMS implementation."""

    __slots__ = ("_issuer_id", "_key", "_key_id")

    def __init__(
        self,
        *,
        issuer_id: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
    ) -> None:
        self._issuer_id = _require_identifier(issuer_id, "issuer_id")
        self._key_id = _require_identifier(key_id, "key_id")
        if not isinstance(private_key, Ed25519PrivateKey):
            message = "private_key must be an Ed25519 private key"
            raise TypeError(message)
        self._key = private_key

    @classmethod
    def generate(cls, *, issuer_id: str, key_id: str) -> Self:
        """Generate an in-process key for tests or local development."""
        return cls(
            issuer_id=issuer_id,
            key_id=key_id,
            private_key=Ed25519PrivateKey.generate(),
        )

    @property
    def issuer_id(self) -> str:
        return self._issuer_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return AUTHORIZATION_ATTESTATION_ALGORITHM

    def sign(self, content: bytes) -> str:
        if type(content) is not bytes:
            message = "receipt signing input must be bytes"
            raise TypeError(message)
        return _encode_signature(self._key.sign(content))

    def verification_key(
        self,
        *,
        not_before: datetime,
        expires_at: datetime | None = None,
    ) -> AuthorizationReceiptVerificationKey:
        public_bytes = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return AuthorizationReceiptVerificationKey(
            issuer_id=self.issuer_id,
            key_id=self.key_id,
            public_key_bytes=public_bytes,
            not_before=not_before,
            expires_at=expires_at,
        )


class AuthorizationReceiptKeyring:
    """Immutable issuer/key resolver for Ed25519 receipt attestations."""

    def __init__(self, keys: tuple[AuthorizationReceiptVerificationKey, ...]) -> None:
        if type(keys) is not tuple or not keys:
            message = "authorization receipt keyring requires an immutable non-empty tuple"
            raise ValueError(message)
        resolved: dict[tuple[str, str], AuthorizationReceiptVerificationKey] = {}
        for key in keys:
            if type(key) is not AuthorizationReceiptVerificationKey:
                message = "authorization receipt keyring contains an invalid key"
                raise TypeError(message)
            identity = (key.issuer_id, key.key_id)
            if identity in resolved:
                message = "duplicate authorization receipt verification key"
                raise ValueError(message)
            resolved[identity] = key
        self._keys = MappingProxyType(resolved)

    def verify(  # noqa: PLR0913
        self,
        *,
        issuer_id: str,
        key_id: str,
        algorithm: str,
        evaluated_at: datetime,
        content: bytes,
        signature: str,
    ) -> None:
        if algorithm != AUTHORIZATION_ATTESTATION_ALGORITHM:
            message = "unsupported authorization receipt attestation algorithm"
            raise AuthorizationReceiptAuthenticityError(message)
        try:
            key = self._keys[(issuer_id, key_id)]
        except KeyError as error:
            message = "unknown authorization receipt issuer key"
            raise AuthorizationReceiptAuthenticityError(message) from error
        issued_at = _require_utc(evaluated_at, "evaluated_at")
        if issued_at < key.not_before:
            message = "authorization receipt predates issuer key"
            raise AuthorizationReceiptAuthenticityError(message)
        if key.expires_at is not None and issued_at >= key.expires_at:
            message = "authorization receipt postdates issuer key"
            raise AuthorizationReceiptAuthenticityError(message)
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key_bytes).verify(
                _decode_signature(signature),
                content,
            )
        except InvalidSignature as error:
            message = "invalid authorization receipt attestation"
            raise AuthorizationReceiptAuthenticityError(message) from error


def _require_identifier(value: object, field_name: str) -> str:
    if type(value) is not str or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        message = f"{field_name} is not a canonical identifier"
        raise ValueError(message)
    return value


def _require_utc(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        message = f"{field_name} must be a datetime"
        raise TypeError(message)
    if value.tzinfo is None or value.utcoffset() is None:
        message = f"{field_name} must be timezone-aware"
        raise ValueError(message)
    return value.astimezone(UTC)


def _encode_signature(signature: bytes) -> str:
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def _decode_signature(signature: object) -> bytes:
    if type(signature) is not str or _SIGNATURE_PATTERN.fullmatch(signature) is None:
        message = "authorization receipt attestation encoding is invalid"
        raise AuthorizationReceiptAuthenticityError(message)
    try:
        decoded = base64.b64decode(signature + "==", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        message = "authorization receipt attestation encoding is invalid"
        raise AuthorizationReceiptAuthenticityError(message) from error
    if len(decoded) != 64:  # noqa: PLR2004
        message = "authorization receipt attestation length is invalid"
        raise AuthorizationReceiptAuthenticityError(message)
    return decoded
