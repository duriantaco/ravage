# ruff: noqa: EM101, EM102, TRY003
"""Read-only joins between agent HTTP captures and durable evidence records."""

from __future__ import annotations

import importlib
import json
import os
import stat
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from .redaction import safe_identifier

if TYPE_CHECKING:
    from .contracts import CapturedHttpExchange

_AGENT_HTTP_SOURCE = "agent_http"
_BLACKBOARD_NAMES = (
    "evidence-blackboard.json",
    "remote-evidence-blackboard.json",
)
_MAX_BLACKBOARD_BYTES = 64 * 1_024 * 1_024
_READ_CHUNK_BYTES = 65_536


class TrafficProvenanceError(ValueError):
    """Raised when evidence provenance is ambiguous, unsafe, or invalid."""


class _EvidenceValue(Protocol):
    value: str


class _EvidenceRecord(Protocol):
    evidence_id: str
    sequence: int
    kind: _EvidenceValue
    source: _EvidenceValue
    producer_node_id: str
    observation_id: str
    material: bool


class _EvidenceBlackboardState(Protocol):
    target_identity: str
    records: Mapping[str, _EvidenceRecord]


@dataclass(frozen=True, slots=True)
class EvidenceLinkRecord:
    """The non-secret identifiers exposed for one joined evidence record."""

    evidence_id: str
    kind: str
    source: str
    producer_node_id: str
    material: bool

    def to_json(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "source": self.source,
            "producer_node_id": self.producer_node_id,
            "material": self.material,
        }


@dataclass(frozen=True, slots=True)
class AgentHttpEvidenceLink:
    """Read-only provenance for one captured exchange."""

    request_id: str
    status: str
    observation_id: str
    evidence_records: tuple[EvidenceLinkRecord, ...] = ()
    blackboard_path: str = ""

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        return tuple(record.evidence_id for record in self.evidence_records)

    @property
    def material_evidence_refs(self) -> tuple[str, ...]:
        return tuple(
            record.evidence_id for record in self.evidence_records if record.material
        )

    def summary_json(self) -> dict[str, object]:
        return {
            "status": self.status,
            "observation_id": self.observation_id,
            "evidence_refs": list(self.evidence_refs),
            "material_evidence_refs": list(self.material_evidence_refs),
        }

    def to_json(self) -> dict[str, object]:
        return {
            **self.summary_json(),
            "evidence_records": [record.to_json() for record in self.evidence_records],
            "blackboard_path": self.blackboard_path,
        }


@dataclass(frozen=True, slots=True)
class TrafficProvenanceIndex:
    """Validated evidence links in traffic-store sequence order."""

    links: tuple[AgentHttpEvidenceLink, ...]
    blackboard_path: str = ""

    def for_exchange_id(self, request_id: str) -> AgentHttpEvidenceLink:
        for link in self.links:
            if link.request_id == request_id:
                return link
        raise KeyError(request_id)

    def exchange_ids_for_evidence(self, evidence_id: str) -> tuple[str, ...]:
        return tuple(
            link.request_id for link in self.links if evidence_id in link.evidence_refs
        )


def load_traffic_provenance(
    workspace_dir: Path,
    *,
    exchanges: Sequence[CapturedHttpExchange],
    target_identity: str,
) -> TrafficProvenanceIndex:
    """Build a validated, identifier-only join without mutating either artifact."""
    workspace = Path(workspace_dir)
    has_agent_http = any(exchange.source == _AGENT_HTTP_SOURCE for exchange in exchanges)
    selected = _select_blackboard(workspace) if has_agent_http else None
    if has_agent_http and selected is None:
        raise TrafficProvenanceError(
            "agent HTTP traffic exists without its canonical evidence blackboard"
        )
    state: _EvidenceBlackboardState | None = None
    if selected is not None:
        state = _read_blackboard(selected, target_identity=target_identity)
        if _select_blackboard(workspace) != selected:
            raise TrafficProvenanceError(
                "evidence blackboard selection changed during inspection"
            )

    records_by_observation: dict[str, list[EvidenceLinkRecord]] = defaultdict(list)
    if state is not None:
        for record in sorted(state.records.values(), key=lambda item: item.sequence):
            if not record.observation_id:
                continue
            records_by_observation[record.observation_id].append(
                EvidenceLinkRecord(
                    # The state validator recomputes this canonical digest-backed ID.
                    # Redacting it would destroy the join key itself.
                    evidence_id=record.evidence_id,
                    kind=record.kind.value,
                    source=record.source.value,
                    producer_node_id=safe_identifier(record.producer_node_id),
                    material=record.material,
                )
            )

    blackboard_path = str(selected) if selected is not None else ""
    links: list[AgentHttpEvidenceLink] = []
    for exchange in exchanges:
        records: tuple[EvidenceLinkRecord, ...] = ()
        if exchange.source != _AGENT_HTTP_SOURCE:
            status = "not_applicable"
            observation_id = ""
        else:
            observation_id = exchange.source_observation_id
            if not observation_id:
                status = "missing_observation"
            else:
                joined_records = records_by_observation.get(observation_id)
                records = tuple(joined_records) if joined_records is not None else ()
                status = "linked" if records else "observation_only"
        links.append(
            AgentHttpEvidenceLink(
                request_id=exchange.exchange_id,
                status=status,
                observation_id=observation_id,
                evidence_records=records,
                blackboard_path=blackboard_path,
            )
        )
    return TrafficProvenanceIndex(
        links=tuple(links),
        blackboard_path=blackboard_path,
    )


def _select_blackboard(workspace_dir: Path) -> Path | None:
    candidates: list[Path] = []
    for name in _BLACKBOARD_NAMES:
        path = workspace_dir / name
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise TrafficProvenanceError(
                f"could not inspect evidence blackboard: {name}"
            ) from exc
        candidates.append(path)
    if len(candidates) > 1:
        raise TrafficProvenanceError(
            "multiple canonical evidence blackboards found: "
            + ", ".join(path.name for path in candidates)
        )
    return candidates[0] if candidates else None


def _read_blackboard(path: Path, *, target_identity: str) -> _EvidenceBlackboardState:
    raw = _read_blackboard_bytes(path)
    state = _decode_blackboard_state(raw, path=path)
    if state.target_identity != target_identity:
        raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}")
    return state


def _read_blackboard_bytes(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}")
        if before.st_nlink != 1:
            raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}")
        if before.st_size > _MAX_BLACKBOARD_BYTES:
            raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}")
        raw = _read_bounded(descriptor)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or current.st_dev != after.st_dev
            or current.st_ino != after.st_ino
        ):
            raise TrafficProvenanceError(
                "evidence blackboard changed during inspection"
            )
    except OSError as exc:
        raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}") from exc
    finally:
        os.close(descriptor)
    return raw


def _decode_blackboard_state(raw: bytes, *, path: Path) -> _EvidenceBlackboardState:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}") from exc
    if not isinstance(payload, Mapping):
        raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}")
    # Resolve dynamically so the small standalone traffic package does not pull
    # the whole autonomous-agent implementation into static traffic checks.
    evidence_module = importlib.import_module(
        "ravage.agent_core.autonomous_graph.evidence"
    )
    state_type = evidence_module.EvidenceBlackboardState

    try:
        state = state_type.from_json(payload)
    except (TypeError, ValueError, RuntimeError, RecursionError) as exc:
        raise TrafficProvenanceError(f"invalid evidence blackboard: {path.name}") from exc
    return cast("_EvidenceBlackboardState", state)


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = _MAX_BLACKBOARD_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > _MAX_BLACKBOARD_BYTES:
        raise TrafficProvenanceError("invalid evidence blackboard: size limit exceeded")
    return raw


__all__ = [
    "AgentHttpEvidenceLink",
    "EvidenceLinkRecord",
    "TrafficProvenanceError",
    "TrafficProvenanceIndex",
    "load_traffic_provenance",
]
