"""Ed25519-signed bindings for trusted improvement evaluation receipts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tools.improvement_lab.evaluation import EvaluationReceipt, canonical_json

if TYPE_CHECKING:
    from pathlib import Path

# Attestation errors are bounded trust-boundary diagnostics.
# ruff: noqa: EM101, EM102, TRY003

SIGNED_EVALUATION_SCHEMA_VERSION: Final = "ravage.improvement-signed-evaluation.v2"
_ID_RE = re.compile(r"(?:campaign|candidate)_[0-9a-f]{24}")
_GIT_RE = re.compile(r"[0-9a-f]{40,64}")
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_REF_RE = re.compile(r"(?:source:[0-9a-f]{40,64}|candidate:candidate_[0-9a-f]{24})")
_IMAGE_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
_KEY_BYTES = 32
_MAX_SIGNED_BYTES = 16 * 1024 * 1024
_MAX_TEXT_CHARS = 1024


class AttestationError(ValueError):
    """Raised when a referee identity or signed evaluation is invalid."""


@dataclass(frozen=True)
class EvaluationBinding:
    campaign_id: str
    candidate_id: str
    candidate_parent_ref: str
    champion_commit: str
    champion_tree: str
    candidate_patch_object: str
    candidate_config_object: str
    evaluation_config_object: str
    evaluation_suite_object: str
    runner_image: str
    champion_receipts_object: str
    candidate_receipts_object: str

    def __post_init__(self) -> None:
        if _ID_RE.fullmatch(self.campaign_id) is None or not self.campaign_id.startswith(
            "campaign_"
        ):
            raise AttestationError("evaluation campaign identity is invalid")
        if _ID_RE.fullmatch(self.candidate_id) is None or not self.candidate_id.startswith(
            "candidate_"
        ):
            raise AttestationError("evaluation candidate identity is invalid")
        if _REF_RE.fullmatch(self.candidate_parent_ref) is None:
            raise AttestationError("evaluation candidate parent is invalid")
        if _GIT_RE.fullmatch(self.champion_commit) is None:
            raise AttestationError("evaluation champion commit is invalid")
        if _GIT_RE.fullmatch(self.champion_tree) is None:
            raise AttestationError("evaluation champion tree is invalid")
        for value in (
            self.candidate_patch_object,
            self.candidate_config_object,
            self.evaluation_config_object,
            self.evaluation_suite_object,
            self.champion_receipts_object,
            self.candidate_receipts_object,
        ):
            if _SHA256_RE.fullmatch(value) is None:
                raise AttestationError("evaluation binding contains an invalid digest")
        if _IMAGE_RE.fullmatch(self.runner_image) is None:
            raise AttestationError("evaluation runner image must be pinned by sha256")

    def to_json(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "candidate_id": self.candidate_id,
            "candidate_parent_ref": self.candidate_parent_ref,
            "champion_commit": self.champion_commit,
            "champion_tree": self.champion_tree,
            "candidate_patch_object": self.candidate_patch_object,
            "candidate_config_object": self.candidate_config_object,
            "evaluation_config_object": self.evaluation_config_object,
            "evaluation_suite_object": self.evaluation_suite_object,
            "runner_image": self.runner_image,
            "champion_receipts_object": self.champion_receipts_object,
            "candidate_receipts_object": self.candidate_receipts_object,
        }

    @classmethod
    def from_mapping(cls, payload: object) -> EvaluationBinding:
        if not isinstance(payload, dict):
            raise AttestationError("evaluation binding must be an object")
        expected = {
            "campaign_id",
            "candidate_id",
            "candidate_parent_ref",
            "champion_commit",
            "champion_tree",
            "candidate_patch_object",
            "candidate_config_object",
            "evaluation_config_object",
            "evaluation_suite_object",
            "runner_image",
            "champion_receipts_object",
            "candidate_receipts_object",
        }
        if set(payload) != expected:
            raise AttestationError("evaluation binding fields do not match the canonical schema")
        return cls(**{name: _text(payload[name], name) for name in expected})


@dataclass(frozen=True)
class SignedEvaluation:
    binding: EvaluationBinding
    receipt: EvaluationReceipt
    signing_key_id: str
    signature: str

    def unsigned_json(self) -> dict[str, object]:
        return {
            "schema_version": SIGNED_EVALUATION_SCHEMA_VERSION,
            "binding": self.binding.to_json(),
            "receipt": self.receipt.to_json(),
            "signing_key_id": self.signing_key_id,
        }

    def to_json(self) -> dict[str, object]:
        return {**self.unsigned_json(), "signature": self.signature}


def generate_referee_keypair() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    return _private_bytes(private), _public_bytes(private.public_key())


def public_key_from_private(private_key: bytes) -> bytes:
    return _public_bytes(_load_private_key(private_key).public_key())


def referee_key_id(public_key: bytes) -> str:
    validated = _load_public_key(public_key)
    return f"sha256:{hashlib.sha256(_public_bytes(validated)).hexdigest()}"


def sign_evaluation(
    receipt: EvaluationReceipt,
    binding: EvaluationBinding,
    *,
    private_key: bytes,
) -> SignedEvaluation:
    private = _load_private_key(private_key)
    public = _public_bytes(private.public_key())
    key_id = referee_key_id(public)
    unsigned = {
        "schema_version": SIGNED_EVALUATION_SCHEMA_VERSION,
        "binding": binding.to_json(),
        "receipt": receipt.to_json(),
        "signing_key_id": key_id,
    }
    signature = private.sign(canonical_json(unsigned).encode()).hex()
    return SignedEvaluation(
        binding=binding,
        receipt=receipt,
        signing_key_id=key_id,
        signature=signature,
    )


def verify_signed_evaluation(payload: object, *, public_key: bytes) -> SignedEvaluation:
    if not isinstance(payload, dict):
        raise AttestationError("signed evaluation must be an object")
    expected = {"schema_version", "binding", "receipt", "signing_key_id", "signature"}
    if set(payload) != expected:
        raise AttestationError("signed evaluation fields do not match the canonical schema")
    if payload.get("schema_version") != SIGNED_EVALUATION_SCHEMA_VERSION:
        raise AttestationError("signed evaluation schema is unsupported")
    public = _load_public_key(public_key)
    key_id = _text(payload.get("signing_key_id"), "signing_key_id")
    if key_id != referee_key_id(_public_bytes(public)):
        raise AttestationError("signed evaluation uses the wrong referee key")
    signature = _text(payload.get("signature"), "signature").lower()
    if _SIGNATURE_RE.fullmatch(signature) is None:
        raise AttestationError("signed evaluation signature is invalid")
    raw_receipt = payload.get("receipt")
    if not isinstance(raw_receipt, dict):
        raise AttestationError("signed evaluation receipt must be an object")
    try:
        receipt = EvaluationReceipt.from_mapping(raw_receipt)
    except ValueError as exc:
        raise AttestationError("signed evaluation receipt is invalid") from exc
    binding = EvaluationBinding.from_mapping(payload.get("binding"))
    unsigned = {
        "schema_version": SIGNED_EVALUATION_SCHEMA_VERSION,
        "binding": binding.to_json(),
        "receipt": receipt.to_json(),
        "signing_key_id": key_id,
    }
    try:
        public.verify(bytes.fromhex(signature), canonical_json(unsigned).encode())
    except InvalidSignature as exc:
        raise AttestationError("signed evaluation signature verification failed") from exc
    return SignedEvaluation(binding, receipt, key_id, signature)


def write_referee_key(path: Path, content: bytes, *, public: bool) -> None:
    expected = (
        _public_bytes(_load_public_key(content))
        if public
        else _private_bytes(_load_private_key(content))
    )
    _private_atomic_write(path, expected, mode=0o600 if not public else 0o644)


def read_private_key(path: Path) -> bytes:
    return _read_bounded(
        path,
        label="referee private key",
        expected_size=_KEY_BYTES,
        require_private=True,
    )


def read_public_key(path: Path) -> bytes:
    return _read_bounded(path, label="referee public key", expected_size=_KEY_BYTES)


def write_signed_evaluation(path: Path, signed: SignedEvaluation) -> None:
    encoded = (canonical_json(signed.to_json()) + "\n").encode()
    _private_atomic_write(path, encoded, mode=0o600)


def load_signed_evaluation(path: Path, *, public_key: bytes) -> SignedEvaluation:
    raw = _read_bounded(path, label="signed evaluation", maximum=_MAX_SIGNED_BYTES)
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AttestationError("signed evaluation JSON is invalid") from exc
    return verify_signed_evaluation(payload, public_key=public_key)


def _load_private_key(content: bytes) -> Ed25519PrivateKey:
    if not isinstance(content, bytes) or len(content) != _KEY_BYTES:
        raise AttestationError("referee private key must contain 32 raw bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(content)
    except ValueError as exc:
        raise AttestationError("referee private key is invalid") from exc


def _load_public_key(content: bytes) -> Ed25519PublicKey:
    if not isinstance(content, bytes) or len(content) != _KEY_BYTES:
        raise AttestationError("referee public key must contain 32 raw bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(content)
    except ValueError as exc:
        raise AttestationError("referee public key is invalid") from exc


def _private_bytes(key: Ed25519PrivateKey) -> bytes:
    return bytes(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return bytes(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_CHARS:
        raise AttestationError(f"{label} is invalid")
    return value.strip().lower() if label != "runner_image" else value.strip()


def _read_bounded(
    path: Path,
    *,
    label: str,
    expected_size: int | None = None,
    maximum: int | None = None,
    require_private: bool = False,
) -> bytes:
    candidate = path.expanduser()
    try:
        stat_result = candidate.lstat()
        if candidate.is_symlink() or not candidate.is_file() or stat_result.st_nlink != 1:
            raise AttestationError(f"{label} must be a regular unlinked file")
        if require_private and stat.S_IMODE(stat_result.st_mode) & 0o077:
            raise AttestationError(f"{label} must not grant group or other permissions")
        if expected_size is not None and stat_result.st_size != expected_size:
            raise AttestationError(f"{label} has the wrong size")
        if maximum is not None and stat_result.st_size > maximum:
            raise AttestationError(f"{label} exceeds the byte cap")
        return candidate.read_bytes()
    except OSError as exc:
        raise AttestationError(f"cannot read {label}") from exc


def _private_atomic_write(path: Path, content: bytes, *, mode: int) -> None:
    target = path.expanduser()
    if target.exists() or target.is_symlink():
        raise AttestationError("attestation output already exists")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.parent.is_symlink():
        raise AttestationError("attestation output parent must not be a symlink")
    temporary = target.with_name(f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
        target.chmod(mode)
    except OSError as exc:
        raise AttestationError("cannot write attestation output") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError("signed evaluation contains a duplicate JSON key")
        result[key] = value
    return result


__all__ = [
    "SIGNED_EVALUATION_SCHEMA_VERSION",
    "AttestationError",
    "EvaluationBinding",
    "SignedEvaluation",
    "generate_referee_keypair",
    "load_signed_evaluation",
    "public_key_from_private",
    "read_private_key",
    "read_public_key",
    "referee_key_id",
    "sign_evaluation",
    "verify_signed_evaluation",
    "write_referee_key",
    "write_signed_evaluation",
]
