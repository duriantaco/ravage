# ruff: noqa: EM101, EM102, TRY003
"""Shared contracts and limits for passive SATCOM analysis."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

SATCOM_PASSIVE_REPORT_SCHEMA = "ravage.satcom-passive-report.v1"
SATCOM_SURFACE_GRAPH_SCHEMA = "ravage.satcom-surface.v1"
SATCOM_SCHEMA_VERSION = 1

# Artifact parsers operate in memory in phase one.  Keep both memory use and
# report cardinality explicitly bounded before accepting hostile artifacts.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_CCSDS_PACKETS = 8_192
MAX_TLE_RECORDS = 1_024
_CCSDS_APID_COUNT = 1 << 11
# One artifact, one shared node per APID, and one operation node for each
# telemetry/telecommand + APID pair. Each operation has exactly two edges.
MAX_SURFACE_NODES = 1 + _CCSDS_APID_COUNT + (2 * _CCSDS_APID_COUNT)
MAX_SURFACE_EDGES = 2 * (2 * _CCSDS_APID_COUNT)
MAX_SECURITY_SIGNALS = 1_024
MAX_EVIDENCE_REFS = 32
MAX_SAFE_TEXT_CHARS = 160

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_UNSAFE_TEXT_RE = re.compile(r"[\x00-\x1f\x7f]")


class SatcomError(ValueError):
    """Base error for malformed or unsafe SATCOM input."""


class SatcomArtifactError(SatcomError):
    """Raised when an artifact cannot be read through the passive boundary."""


class SatcomFormatError(SatcomError):
    """Raised when artifact bytes do not satisfy the selected strict format."""


class SatcomSurfaceError(SatcomError):
    """Raised when a SATCOM surface graph contract is malformed."""


class SatcomArtifactKind(StrEnum):
    TLE = "tle"
    CCSDS_SPACE_PACKETS = "ccsds-space-packets"


class SatcomDirection(StrEnum):
    TELEMETRY = "telemetry"
    TELECOMMAND = "telecommand"


class SatcomSignalStatus(StrEnum):
    CANDIDATE = "candidate"
    INFORMATIONAL = "informational"


@dataclass(frozen=True, slots=True)
class SatcomArtifactReference:
    """Content identity for an artifact, without its path or raw bytes."""

    kind: SatcomArtifactKind
    sha256: str
    size_bytes: int

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        kind: SatcomArtifactKind | str,
    ) -> SatcomArtifactReference:
        if not isinstance(data, bytes):
            raise SatcomArtifactError("SATCOM artifact content must be immutable bytes")
        resolved_kind = artifact_kind(kind)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise SatcomArtifactError("SATCOM artifact exceeds the byte limit")
        digest = hashlib.sha256(data).hexdigest()
        return cls(
            kind=resolved_kind,
            sha256=f"sha256:{digest}",
            size_bytes=len(data),
        )

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SatcomArtifactKind):
            raise SatcomArtifactError("SATCOM artifact kind must be canonical")
        if not _SHA256_RE.fullmatch(self.sha256):
            raise SatcomArtifactError("SATCOM artifact digest must be canonical SHA-256")
        if not 0 <= self.size_bytes <= MAX_ARTIFACT_BYTES:
            raise SatcomArtifactError("SATCOM artifact size is outside the supported range")

    @property
    def artifact_id(self) -> str:
        return f"artifact_{self.sha256.removeprefix('sha256:')[:24]}"

    def evidence_ref(self, *, offset: int | None = None, length: int | None = None) -> str:
        reference = self.artifact_id
        if offset is None and length is None:
            return reference
        if offset is None or length is None or offset < 0 or length <= 0:
            raise SatcomArtifactError("artifact evidence range must be complete and positive")
        if offset + length > self.size_bytes:
            raise SatcomArtifactError("artifact evidence range exceeds the artifact")
        return f"{reference}:offset={offset}:length={length}"

    def to_json(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind.value,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


def artifact_kind(value: SatcomArtifactKind | str) -> SatcomArtifactKind:
    if isinstance(value, SatcomArtifactKind):
        return value
    try:
        return SatcomArtifactKind(str(value).strip().casefold())
    except ValueError as exc:
        raise SatcomFormatError("unsupported SATCOM artifact format") from exc


def safe_identifier(value: object, *, label: str) -> str:
    text = str(value or "").strip().casefold()
    if not _SAFE_IDENTIFIER_RE.fullmatch(text):
        raise SatcomSurfaceError(f"invalid {label}")
    return text


def safe_text(value: object, *, label: str, allow_empty: bool = False) -> str:
    text = str(value or "").strip()
    if (
        (not text and not allow_empty)
        or len(text) > MAX_SAFE_TEXT_CHARS
        or _UNSAFE_TEXT_RE.search(text)
    ):
        raise SatcomFormatError(f"invalid {label}")
    return text


def stable_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256("\x00".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:24]}"


__all__ = [
    "MAX_ARTIFACT_BYTES",
    "MAX_CCSDS_PACKETS",
    "MAX_EVIDENCE_REFS",
    "MAX_SECURITY_SIGNALS",
    "MAX_SURFACE_EDGES",
    "MAX_SURFACE_NODES",
    "MAX_TLE_RECORDS",
    "SATCOM_PASSIVE_REPORT_SCHEMA",
    "SATCOM_SCHEMA_VERSION",
    "SATCOM_SURFACE_GRAPH_SCHEMA",
    "SatcomArtifactError",
    "SatcomArtifactKind",
    "SatcomArtifactReference",
    "SatcomDirection",
    "SatcomError",
    "SatcomFormatError",
    "SatcomSignalStatus",
    "SatcomSurfaceError",
    "artifact_kind",
    "safe_identifier",
    "safe_text",
    "stable_id",
]
