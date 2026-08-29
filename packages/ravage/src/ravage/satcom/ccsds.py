# ruff: noqa: C901, EM101, EM102, TRY003
"""Strict CCSDS Space Packet primary-header stream parsing."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ravage.satcom.contracts import (
    MAX_ARTIFACT_BYTES,
    MAX_CCSDS_PACKETS,
    SatcomDirection,
    SatcomFormatError,
)

CCSDS_PRIMARY_HEADER_BYTES = 6
CCSDS_VERSION = 0
CCSDS_IDLE_APID = 0x7FF

_SEQUENCE_FLAG_NAMES = {
    0: "continuation",
    1: "first",
    2: "last",
    3: "unsegmented",
}


@dataclass(frozen=True, slots=True)
class CcsdsSpacePacket:
    packet_index: int
    offset: int
    total_length: int
    version: int
    direction: SatcomDirection
    secondary_header_present: bool
    apid: int
    sequence_flags: int
    sequence_count: int
    data_length: int
    packet_sha256: str
    data_sha256: str

    @property
    def sequence_flag_name(self) -> str:
        return _SEQUENCE_FLAG_NAMES[self.sequence_flags]

    @property
    def idle(self) -> bool:
        return self.apid == CCSDS_IDLE_APID

    def to_json(self, *, evidence_ref: str) -> dict[str, object]:
        return {
            "kind": "ccsds_space_packet",
            "packet_index": self.packet_index,
            "offset": self.offset,
            "total_length": self.total_length,
            "version": self.version,
            "direction": self.direction.value,
            "secondary_header_present": self.secondary_header_present,
            "apid": self.apid,
            "idle": self.idle,
            "sequence_flags": self.sequence_flags,
            "sequence_flag": self.sequence_flag_name,
            "sequence_count": self.sequence_count,
            "data_length": self.data_length,
            "packet_sha256": self.packet_sha256,
            "data_sha256": self.data_sha256,
            "evidence_ref": evidence_ref,
        }


def parse_ccsds_space_packets(
    data: bytes,
    *,
    max_packets: int = MAX_CCSDS_PACKETS,
    expected_direction: SatcomDirection | str | None = None,
) -> tuple[CcsdsSpacePacket, ...]:
    """Parse a strict concatenated stream of complete CCSDS Space Packets."""
    if not isinstance(data, bytes):
        raise SatcomFormatError("CCSDS artifact must be bytes")
    if not data:
        raise SatcomFormatError("CCSDS packet stream is empty")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise SatcomFormatError("CCSDS packet stream exceeds the byte limit")
    if not 0 < max_packets <= MAX_CCSDS_PACKETS:
        raise SatcomFormatError("CCSDS packet limit is invalid")
    required_direction = _optional_direction(expected_direction)

    packets: list[CcsdsSpacePacket] = []
    offset = 0
    while offset < len(data):
        packet_index = len(packets)
        if packet_index >= max_packets:
            raise SatcomFormatError("CCSDS packet stream exceeds the packet limit")
        remaining = len(data) - offset
        if remaining < CCSDS_PRIMARY_HEADER_BYTES:
            raise SatcomFormatError(f"truncated CCSDS primary header at byte offset {offset}")

        packet_id = int.from_bytes(data[offset : offset + 2], "big")
        sequence_control = int.from_bytes(data[offset + 2 : offset + 4], "big")
        encoded_length = int.from_bytes(data[offset + 4 : offset + 6], "big")
        version = (packet_id >> 13) & 0b111
        if version != CCSDS_VERSION:
            raise SatcomFormatError(
                f"unsupported CCSDS Space Packet version {version} at byte offset {offset}"
            )
        direction = (
            SatcomDirection.TELECOMMAND if (packet_id >> 12) & 0b1 else SatcomDirection.TELEMETRY
        )
        if required_direction is not None and direction is not required_direction:
            raise SatcomFormatError(f"CCSDS packet direction mismatch at byte offset {offset}")

        data_length = encoded_length + 1
        total_length = CCSDS_PRIMARY_HEADER_BYTES + data_length
        if total_length > remaining:
            raise SatcomFormatError(
                f"truncated CCSDS packet at byte offset {offset}: "
                f"declared {total_length} bytes, found {remaining}"
            )

        packet_bytes = data[offset : offset + total_length]
        packet_data = packet_bytes[CCSDS_PRIMARY_HEADER_BYTES:]
        packets.append(
            CcsdsSpacePacket(
                packet_index=packet_index,
                offset=offset,
                total_length=total_length,
                version=version,
                direction=direction,
                secondary_header_present=bool((packet_id >> 11) & 0b1),
                apid=packet_id & 0x7FF,
                sequence_flags=(sequence_control >> 14) & 0b11,
                sequence_count=sequence_control & 0x3FFF,
                data_length=data_length,
                packet_sha256=f"sha256:{hashlib.sha256(packet_bytes).hexdigest()}",
                data_sha256=f"sha256:{hashlib.sha256(packet_data).hexdigest()}",
            )
        )
        offset += total_length

    return tuple(packets)


def _optional_direction(value: SatcomDirection | str | None) -> SatcomDirection | None:
    if value is None or str(value).strip().casefold() == "auto":
        return None
    if isinstance(value, SatcomDirection):
        return value
    try:
        return SatcomDirection(str(value).strip().casefold())
    except ValueError as exc:
        raise SatcomFormatError("unsupported CCSDS packet direction") from exc


__all__ = [
    "CCSDS_IDLE_APID",
    "CCSDS_PRIMARY_HEADER_BYTES",
    "CcsdsSpacePacket",
    "parse_ccsds_space_packets",
]
