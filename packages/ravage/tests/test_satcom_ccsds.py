# ruff: noqa: PLR0913, PLR2004
from __future__ import annotations

import pytest
from ravage.satcom.ccsds import parse_ccsds_space_packets
from ravage.satcom.contracts import SatcomDirection, SatcomFormatError


def _packet(
    payload: bytes,
    *,
    apid: int = 42,
    telecommand: bool = False,
    secondary_header: bool = True,
    sequence_flags: int = 3,
    sequence_count: int = 7,
    version: int = 0,
) -> bytes:
    assert payload
    packet_id = (version << 13) | (int(telecommand) << 12) | (int(secondary_header) << 11) | apid
    sequence = (sequence_flags << 14) | sequence_count
    return (
        packet_id.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + (len(payload) - 1).to_bytes(2, "big")
        + payload
    )


def test_parses_concatenated_ccsds_space_packets_exactly() -> None:
    first = _packet(b"abc", apid=3, sequence_count=8)
    second = _packet(
        b"command",
        apid=9,
        telecommand=True,
        secondary_header=False,
        sequence_flags=1,
        sequence_count=12,
    )

    packets = parse_ccsds_space_packets(first + second)

    assert len(packets) == 2
    assert packets[0].offset == 0
    assert packets[0].total_length == len(first)
    assert packets[0].direction is SatcomDirection.TELEMETRY
    assert packets[0].apid == 3
    assert packets[0].sequence_count == 8
    assert packets[0].sequence_flag_name == "unsegmented"
    assert packets[1].offset == len(first)
    assert packets[1].direction is SatcomDirection.TELECOMMAND
    assert not packets[1].secondary_header_present
    assert packets[1].sequence_flag_name == "first"
    assert packets[1].data_length == len(b"command")
    assert packets[1].packet_sha256.startswith("sha256:")
    assert packets[1].data_sha256.startswith("sha256:")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "empty"),
        (b"\x00" * 5, "primary header"),
        (_packet(b"abc")[:-1], "truncated CCSDS packet"),
        (_packet(b"abc", version=1), "unsupported CCSDS Space Packet version"),
    ],
)
def test_rejects_malformed_or_truncated_packet_streams(data: bytes, message: str) -> None:
    with pytest.raises(SatcomFormatError, match=message):
        parse_ccsds_space_packets(data)


def test_direction_requirement_is_fail_closed() -> None:
    command = _packet(b"command", telecommand=True)

    with pytest.raises(SatcomFormatError, match="direction mismatch"):
        parse_ccsds_space_packets(command, expected_direction="telemetry")

    parsed = parse_ccsds_space_packets(command, expected_direction="telecommand")
    assert parsed[0].direction is SatcomDirection.TELECOMMAND


def test_packet_count_limit_is_enforced_without_resynchronizing() -> None:
    stream = _packet(b"a") + _packet(b"b", sequence_count=8)

    with pytest.raises(SatcomFormatError, match="packet limit"):
        parse_ccsds_space_packets(stream, max_packets=1)


def test_parser_requires_immutable_bytes() -> None:
    with pytest.raises(SatcomFormatError, match="must be bytes"):
        parse_ccsds_space_packets(bytearray(_packet(b"abc")))  # type: ignore[arg-type]
