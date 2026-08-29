# ruff: noqa: EM101, TRY003
"""Passive SATCOM artifact analysis and deterministic report construction."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.satcom.artifacts import read_regular_artifact
from ravage.satcom.ccsds import (
    CCSDS_IDLE_APID,
    CcsdsSpacePacket,
    parse_ccsds_space_packets,
)
from ravage.satcom.contracts import (
    MAX_EVIDENCE_REFS,
    MAX_SECURITY_SIGNALS,
    SATCOM_PASSIVE_REPORT_SCHEMA,
    SATCOM_SCHEMA_VERSION,
    SatcomArtifactKind,
    SatcomArtifactReference,
    SatcomDirection,
    SatcomFormatError,
    SatcomSignalStatus,
    artifact_kind,
    safe_identifier,
    safe_text,
    stable_id,
)
from ravage.satcom.surface import (
    SatcomNodeKind,
    SatcomProvenance,
    SatcomRelation,
    SatcomSurfaceGraph,
    SatcomSurfaceNode,
)
from ravage.satcom.tle import TleRecord, parse_tle_catalog

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_MIN_REPEATED_OBSERVATIONS = 2


@dataclass(frozen=True, slots=True)
class SatcomSecuritySignal:
    signal_id: str
    kind: str
    status: SatcomSignalStatus
    severity: str
    summary: str
    affected_node_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    details: tuple[tuple[str, str | int | bool], ...] = ()

    @classmethod
    def create(  # noqa: PLR0913 - evidence contract is deliberately explicit.
        cls,
        *,
        namespace: str,
        kind: object,
        identity_parts: tuple[object, ...],
        status: SatcomSignalStatus,
        severity: object,
        summary: object,
        affected_node_ids: tuple[str, ...],
        evidence_refs: tuple[str, ...],
        details: Mapping[str, str | int | bool] | None = None,
    ) -> SatcomSecuritySignal:
        canonical_kind = safe_identifier(kind, label="SATCOM signal kind")
        canonical_severity = safe_identifier(severity, label="SATCOM signal severity")
        canonical_summary = safe_text(summary, label="SATCOM signal summary")
        canonical_status = (
            status if isinstance(status, SatcomSignalStatus) else SatcomSignalStatus(status)
        )
        refs = tuple(
            sorted(
                {
                    safe_text(value, label="SATCOM signal evidence reference")
                    for value in evidence_refs
                }
            )
        )[:MAX_EVIDENCE_REFS]
        nodes = tuple(
            sorted(
                {
                    safe_text(value, label="SATCOM signal node reference")
                    for value in affected_node_ids
                }
            )
        )
        detail_items = _signal_details(details or {})
        return cls(
            signal_id=stable_id("ss", namespace, canonical_kind, *identity_parts),
            kind=canonical_kind,
            status=canonical_status,
            severity=canonical_severity,
            summary=canonical_summary,
            affected_node_ids=nodes,
            evidence_refs=refs,
            details=detail_items,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "signal_id": self.signal_id,
            "kind": self.kind,
            "status": self.status.value,
            "severity": self.severity,
            "summary": self.summary,
            "affected_node_ids": list(self.affected_node_ids),
            "evidence_refs": list(self.evidence_refs),
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class SatcomPassiveReport:
    artifact: SatcomArtifactReference
    surface_graph: SatcomSurfaceGraph
    observations: tuple[dict[str, object], ...]
    security_signals: tuple[SatcomSecuritySignal, ...]
    capabilities: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": SATCOM_PASSIVE_REPORT_SCHEMA,
            "schema_version": SATCOM_SCHEMA_VERSION,
            "mode": "passive_offline",
            "status": "completed",
            "artifact": self.artifact.to_json(),
            "capabilities": list(self.capabilities),
            "surface_graph": self.surface_graph.to_json(),
            "observations": [dict(item) for item in self.observations],
            "security_signals": [item.to_json() for item in self.security_signals],
            # Phase one has no trusted active validator.  Candidate observations
            # are retained above but can never be promoted by this analyzer.
            "confirmed_findings": [],
            "flags": [],
            "limitations": list(self.limitations),
        }
        canonical = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload["analysis_sha256"] = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        return payload


def analyze_satcom_artifact(
    path: Path,
    *,
    kind: SatcomArtifactKind | str,
    expected_direction: SatcomDirection | str | None = None,
) -> SatcomPassiveReport:
    artifact = read_regular_artifact(path, kind=kind)
    return _analyze(
        artifact.data,
        reference=artifact.reference,
        expected_direction=expected_direction,
    )


def analyze_satcom_bytes(
    data: bytes,
    *,
    kind: SatcomArtifactKind | str,
    expected_direction: SatcomDirection | str | None = None,
) -> SatcomPassiveReport:
    resolved_kind = artifact_kind(kind)
    reference = SatcomArtifactReference.from_bytes(data, kind=resolved_kind)
    return _analyze(data, reference=reference, expected_direction=expected_direction)


def _analyze(
    data: bytes,
    *,
    reference: SatcomArtifactReference,
    expected_direction: SatcomDirection | str | None,
) -> SatcomPassiveReport:
    if reference.kind is SatcomArtifactKind.CCSDS_SPACE_PACKETS:
        packets = parse_ccsds_space_packets(
            data,
            expected_direction=expected_direction,
        )
        return _ccsds_report(reference, packets)
    direction_text = str(expected_direction or "").strip().casefold()
    if direction_text not in {"", "auto"}:
        raise SatcomFormatError("packet direction applies only to CCSDS packet artifacts")
    if reference.kind is SatcomArtifactKind.TLE:
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SatcomFormatError("TLE artifact must contain ASCII text") from exc
        return _tle_report(reference, parse_tle_catalog(text))
    raise SatcomFormatError("unsupported SATCOM artifact format")


def _artifact_graph(
    reference: SatcomArtifactReference,
) -> tuple[SatcomSurfaceGraph, SatcomSurfaceNode]:
    graph = SatcomSurfaceGraph.create(reference.artifact_id)
    artifact_node = graph.node(
        kind=SatcomNodeKind.ARTIFACT,
        selector=reference.artifact_id,
        attributes={
            "kind": reference.kind.value,
            "sha256": reference.sha256,
            "size_bytes": reference.size_bytes,
        },
        provenance=(
            SatcomProvenance.TLE
            if reference.kind is SatcomArtifactKind.TLE
            else SatcomProvenance.CCSDS_SPACE_PACKET,
        ),
    )
    return graph, artifact_node


def _tle_report(
    reference: SatcomArtifactReference,
    records: tuple[TleRecord, ...],
) -> SatcomPassiveReport:
    graph, artifact_node = _artifact_graph(reference)
    observations: list[dict[str, object]] = []
    for record in records:
        evidence_ref = f"{reference.artifact_id}:tle-record={record.record_index}"
        spacecraft = graph.node(
            kind=SatcomNodeKind.SPACECRAFT,
            selector=f"catalog:{record.catalog_id.casefold()}",
            attributes={
                "catalog_id": record.catalog_id,
                "classification": record.classification,
            },
            provenance=(SatcomProvenance.TLE,),
        )
        graph.edge(
            source=artifact_node,
            relation=SatcomRelation.DESCRIBES,
            target=spacecraft,
            provenance=(SatcomProvenance.TLE,),
            evidence_refs=(evidence_ref,),
        )
        observations.append(record.to_json(evidence_ref=evidence_ref))
    return SatcomPassiveReport(
        artifact=reference,
        surface_graph=graph,
        observations=tuple(observations),
        security_signals=(),
        capabilities=("artifact_hashing", "tle_checksum_validation", "tle_inventory"),
        limitations=(
            "No network lookup or orbital propagation was performed.",
            "TLE metadata identifies cataloged spacecraft but does not establish a live RF link.",
            "This passive analyzer cannot confirm a vulnerability or capture a flag.",
        ),
    )


def _ccsds_report(
    reference: SatcomArtifactReference,
    packets: tuple[CcsdsSpacePacket, ...],
) -> SatcomPassiveReport:
    graph, artifact_node = _artifact_graph(reference)
    grouped: dict[tuple[SatcomDirection, int], list[CcsdsSpacePacket]] = defaultdict(list)
    observations: list[dict[str, object]] = []
    evidence_by_index: dict[int, str] = {}
    for packet in packets:
        evidence_ref = reference.evidence_ref(
            offset=packet.offset,
            length=packet.total_length,
        )
        evidence_by_index[packet.packet_index] = evidence_ref
        observations.append(packet.to_json(evidence_ref=evidence_ref))
        grouped[(packet.direction, packet.apid)].append(packet)

    operation_nodes: dict[tuple[SatcomDirection, int], SatcomSurfaceNode] = {}
    for (direction, apid), members in sorted(
        grouped.items(), key=lambda item: (item[0][0].value, item[0][1])
    ):
        provenance = (SatcomProvenance.CCSDS_SPACE_PACKET,)
        apid_node = graph.node(
            kind=SatcomNodeKind.CCSDS_APID,
            selector=f"apid:{apid}",
            attributes={"apid": apid, "idle": apid == CCSDS_IDLE_APID},
            provenance=provenance,
        )
        operation = graph.node(
            kind=(
                SatcomNodeKind.TELECOMMAND
                if direction is SatcomDirection.TELECOMMAND
                else SatcomNodeKind.TELEMETRY
            ),
            selector=f"{direction.value}:apid:{apid}",
            attributes={
                "apid": apid,
                "packet_count": len(members),
                "secondary_header_observed": any(
                    member.secondary_header_present for member in members
                ),
            },
            provenance=provenance,
        )
        operation_nodes[(direction, apid)] = operation
        refs = tuple(evidence_by_index[item.packet_index] for item in members[:MAX_EVIDENCE_REFS])
        graph.edge(
            source=artifact_node,
            relation=SatcomRelation.CONTAINS,
            target=operation,
            provenance=provenance,
            evidence_refs=refs,
            observation_count=len(members),
        )
        graph.edge(
            source=operation,
            relation=SatcomRelation.USES_APID,
            target=apid_node,
            provenance=provenance,
            evidence_refs=refs,
            observation_count=len(members),
        )

    signals = _ccsds_signals(
        reference,
        packets,
        operation_nodes=operation_nodes,
        evidence_by_index=evidence_by_index,
    )
    return SatcomPassiveReport(
        artifact=reference,
        surface_graph=graph,
        observations=tuple(observations),
        security_signals=signals,
        capabilities=(
            "artifact_hashing",
            "ccsds_primary_header_decode",
            "ccsds_apid_inventory",
            "ccsds_sequence_observation",
        ),
        limitations=(
            "Input was treated as an exact concatenation of CCSDS Space Packets; "
            "no framing resynchronization was attempted.",
            "Secondary headers and packet data were not interpreted, and payload bytes "
            "were not copied into the report.",
            "The Space Packet primary header alone cannot establish encryption, "
            "authentication, transmitter identity, or command acceptance.",
            "Repeated packets can be legitimate retransmissions; replay signals remain "
            "candidates until a trusted simulator validator proves impact.",
            "No RF, network, subprocess, replay, or transmission action was performed.",
            "This passive analyzer cannot confirm a vulnerability or capture a flag.",
        ),
    )


def _ccsds_signals(
    reference: SatcomArtifactReference,
    packets: tuple[CcsdsSpacePacket, ...],
    *,
    operation_nodes: Mapping[tuple[SatcomDirection, int], SatcomSurfaceNode],
    evidence_by_index: Mapping[int, str],
) -> tuple[SatcomSecuritySignal, ...]:
    signals: list[SatcomSecuritySignal] = []
    identical_commands: dict[tuple[int, str], list[CcsdsSpacePacket]] = defaultdict(list)
    counter_uses: dict[tuple[SatcomDirection, int, int], list[CcsdsSpacePacket]] = defaultdict(list)
    for packet in packets:
        counter_uses[(packet.direction, packet.apid, packet.sequence_count)].append(packet)
        if packet.direction is SatcomDirection.TELECOMMAND and not packet.idle:
            identical_commands[(packet.apid, packet.packet_sha256)].append(packet)

    for (apid, packet_digest), members in sorted(identical_commands.items()):
        if len(members) < _MIN_REPEATED_OBSERVATIONS:
            continue
        operation = operation_nodes[(SatcomDirection.TELECOMMAND, apid)]
        signals.append(
            SatcomSecuritySignal.create(
                namespace=reference.artifact_id,
                kind="byte_identical_telecommand_repeat",
                identity_parts=(apid, packet_digest),
                status=SatcomSignalStatus.CANDIDATE,
                severity="informational",
                summary=(
                    "A byte-identical telecommand appears more than once; this may be a "
                    "legitimate retransmission and is not proof of replay acceptance."
                ),
                affected_node_ids=(operation.node_id,),
                evidence_refs=tuple(
                    evidence_by_index[item.packet_index] for item in members[:MAX_EVIDENCE_REFS]
                ),
                details={"apid": apid, "occurrences": len(members)},
            )
        )
        if len(signals) >= MAX_SECURITY_SIGNALS:
            return tuple(signals)

    for (direction, apid, sequence_count), members in sorted(
        counter_uses.items(), key=lambda item: (item[0][0].value, item[0][1], item[0][2])
    ):
        distinct_packets = {member.packet_sha256 for member in members}
        if len(distinct_packets) < _MIN_REPEATED_OBSERVATIONS:
            continue
        operation = operation_nodes[(direction, apid)]
        signals.append(
            SatcomSecuritySignal.create(
                namespace=reference.artifact_id,
                kind="sequence_counter_reuse",
                identity_parts=(direction.value, apid, sequence_count),
                status=SatcomSignalStatus.INFORMATIONAL,
                severity="informational",
                summary=(
                    "The same APID and sequence counter were observed with different packet "
                    "bytes; wraparound, reset, or capture composition may explain the reuse."
                ),
                affected_node_ids=(operation.node_id,),
                evidence_refs=tuple(
                    evidence_by_index[item.packet_index] for item in members[:MAX_EVIDENCE_REFS]
                ),
                details={
                    "apid": apid,
                    "direction": direction.value,
                    "sequence_count": sequence_count,
                    "distinct_packets": len(distinct_packets),
                },
            )
        )
        if len(signals) >= MAX_SECURITY_SIGNALS:
            break
    return tuple(sorted(signals, key=lambda item: item.signal_id))


def _signal_details(
    values: Mapping[str, str | int | bool],
) -> tuple[tuple[str, str | int | bool], ...]:
    details: dict[str, str | int | bool] = {}
    for key, value in values.items():
        canonical_key = safe_identifier(key, label="SATCOM signal detail name")
        if canonical_key in details:
            raise SatcomFormatError("SATCOM signal contains duplicate detail names")
        if isinstance(value, bool | int):
            canonical_value: str | int | bool = value
        elif isinstance(value, str):
            canonical_value = safe_text(
                value,
                label="SATCOM signal detail value",
                allow_empty=True,
            )
        else:
            raise SatcomFormatError("SATCOM signal detail value is not a scalar")
        details[canonical_key] = canonical_value
    return tuple((key, details[key]) for key in sorted(details))


__all__ = [
    "SatcomPassiveReport",
    "SatcomSecuritySignal",
    "analyze_satcom_artifact",
    "analyze_satcom_bytes",
]
