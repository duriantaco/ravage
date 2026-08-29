# Failure certificates are durable loop-control inputs, not vulnerability proof.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_STATE_VERSION = 1
_MAX_CERTIFICATES = 500


class FailureMemoryError(RuntimeError):
    """Raised when investigation failure memory cannot be trusted."""


@dataclass(frozen=True)
class FailureCertificate:
    """Canonical evidence-versioned record of one exhausted strategy dimension."""

    certificate_id: str
    cell_id: str
    family: str
    strategy: str
    dimension: str
    evidence_version: int
    reason: str
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def create(  # noqa: PLR0913 - explicit certificate identity.
        cls,
        *,
        cell_id: str,
        family: str,
        strategy: str,
        dimension: str,
        evidence_version: int,
        reason: str,
        evidence_refs: Sequence[str] = (),
    ) -> FailureCertificate:
        if evidence_version < 0:
            raise FailureMemoryError("failure evidence version cannot be negative")
        canonical = {
            "cell_id": cell_id.strip(),
            "family": _token(family),
            "strategy": _token(strategy),
            "dimension": _token(dimension),
            "evidence_version": evidence_version,
        }
        if not all(
            (
                canonical["cell_id"],
                canonical["family"],
                canonical["strategy"],
                canonical["dimension"],
            )
        ):
            raise FailureMemoryError("failure certificate identity is incomplete")
        normalized_reason = _text(reason)
        if not normalized_reason:
            raise FailureMemoryError("failure certificate reason is required")
        return cls(
            certificate_id=f"failure:{_digest_json(canonical)[:24]}",
            cell_id=str(canonical["cell_id"]),
            family=str(canonical["family"]),
            strategy=str(canonical["strategy"]),
            dimension=str(canonical["dimension"]),
            evidence_version=evidence_version,
            reason=normalized_reason,
            evidence_refs=_strings(evidence_refs),
        )

    @property
    def route_key(self) -> str:
        return "|".join(
            (
                self.cell_id,
                self.strategy,
                self.dimension,
                str(self.evidence_version),
            )
        )

    def to_json(self) -> dict[str, object]:
        return {
            "certificate_id": self.certificate_id,
            "cell_id": self.cell_id,
            "family": self.family,
            "strategy": self.strategy,
            "dimension": self.dimension,
            "evidence_version": self.evidence_version,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> FailureCertificate:
        certificate = cls.create(
            cell_id=str(payload.get("cell_id") or ""),
            family=str(payload.get("family") or ""),
            strategy=str(payload.get("strategy") or ""),
            dimension=str(payload.get("dimension") or ""),
            evidence_version=_version(payload.get("evidence_version")),
            reason=str(payload.get("reason") or ""),
            evidence_refs=_string_tuple(payload.get("evidence_refs")),
        )
        if str(payload.get("certificate_id") or "") != certificate.certificate_id:
            raise FailureMemoryError("failure certificate ID mismatch")
        return certificate


@dataclass
class FailureMemoryState:
    certificates: dict[str, FailureCertificate] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "certificates": {
                certificate_id: certificate.to_json()
                for certificate_id, certificate in sorted(self.certificates.items())
            },
            "order": list(self.order),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> FailureMemoryState:
        if payload.get("version") != _STATE_VERSION:
            raise FailureMemoryError("unsupported investigation failure-memory version")
        raw_certificates = payload.get("certificates")
        raw_order = payload.get("order")
        if not isinstance(raw_certificates, Mapping) or not isinstance(raw_order, list):
            raise FailureMemoryError("failure-memory certificates/order are malformed")
        certificates: dict[str, FailureCertificate] = {}
        for certificate_id, raw in raw_certificates.items():
            if not isinstance(raw, Mapping):
                raise FailureMemoryError("failure certificate must be an object")
            certificate = FailureCertificate.from_json(raw)
            if str(certificate_id) != certificate.certificate_id:
                raise FailureMemoryError("failure certificate map key mismatch")
            certificates[certificate.certificate_id] = certificate
        order = [str(item) for item in raw_order]
        if len(order) != len(set(order)) or any(item not in certificates for item in order):
            raise FailureMemoryError("failure certificate order is inconsistent")
        return cls(certificates=certificates, order=order[-_MAX_CERTIFICATES:])


class InvestigationFailureMemory:
    """Persist and query semantic failures across workers and route resumes."""

    def __init__(self, state_path: Path, state: FailureMemoryState) -> None:
        self.state_path = state_path
        self.state = state
        self._lock = threading.RLock()

    @classmethod
    def open(cls, state_path: Path) -> InvestigationFailureMemory:
        if state_path.exists():
            try:
                raw = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise FailureMemoryError(f"cannot read investigation failures: {exc}") from exc
            if not isinstance(raw, Mapping):
                raise FailureMemoryError("investigation failure memory must be an object")
            state = FailureMemoryState.from_json(raw)
        else:
            state = FailureMemoryState()
        memory = cls(state_path, state)
        memory._persist()
        return memory

    def remember(self, certificate: FailureCertificate) -> FailureCertificate:
        with self._lock:
            existing = self.state.certificates.get(certificate.certificate_id)
            if existing is not None:
                merged_refs = _strings((*existing.evidence_refs, *certificate.evidence_refs))
                merged = FailureCertificate.create(
                    cell_id=existing.cell_id,
                    family=existing.family,
                    strategy=existing.strategy,
                    dimension=existing.dimension,
                    evidence_version=existing.evidence_version,
                    reason=existing.reason,
                    evidence_refs=merged_refs,
                )
                self.state.certificates[existing.certificate_id] = merged
                self._persist()
                return merged
            self.state.certificates[certificate.certificate_id] = certificate
            self.state.order.append(certificate.certificate_id)
            while len(self.state.order) > _MAX_CERTIFICATES:
                removed = self.state.order.pop(0)
                self.state.certificates.pop(removed, None)
            self._persist()
            return certificate

    def blocking_certificate(
        self,
        *,
        cell_id: str,
        strategy: str,
        dimension: str,
        evidence_version: int,
    ) -> FailureCertificate | None:
        route = "|".join(
            (
                cell_id.strip(),
                _token(strategy),
                _token(dimension),
                str(evidence_version),
            )
        )
        with self._lock:
            for certificate_id in reversed(self.state.order):
                certificate = self.state.certificates[certificate_id]
                if certificate.route_key == route:
                    return copy.deepcopy(certificate)
        return None

    def recent_for_cell(
        self,
        cell_id: str,
        *,
        limit: int = 8,
    ) -> tuple[FailureCertificate, ...]:
        if limit <= 0:
            return ()
        with self._lock:
            matches = [
                self.state.certificates[certificate_id]
                for certificate_id in reversed(self.state.order)
                if self.state.certificates[certificate_id].cell_id == cell_id
            ]
            return tuple(copy.deepcopy(matches[:limit]))

    def snapshot(self) -> FailureMemoryState:
        with self._lock:
            return copy.deepcopy(self.state)

    def _persist(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.state.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.state_path)


def _token(value: str) -> str:
    return "_".join(value.strip().lower().replace("-", " ").split())


def _text(value: str) -> str:
    return " ".join(value.strip().split())


def _strings(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({_text(str(item)) for item in values if str(item).strip()}))


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return _strings(tuple(str(item) for item in value))


def _version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FailureMemoryError("failure evidence version must be non-negative")
    return value


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "FailureCertificate",
    "FailureMemoryError",
    "FailureMemoryState",
    "InvestigationFailureMemory",
]
