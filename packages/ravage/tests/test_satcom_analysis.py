# ruff: noqa: PLR2004
from __future__ import annotations

import json

import pytest
from ravage.satcom.analysis import analyze_satcom_bytes
from ravage.satcom.contracts import SatcomArtifactError


def _packet(
    payload: bytes,
    *,
    apid: int,
    telecommand: bool,
    sequence_count: int,
) -> bytes:
    packet_id = (int(telecommand) << 12) | (1 << 11) | apid
    sequence = (3 << 14) | sequence_count
    return (
        packet_id.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + (len(payload) - 1).to_bytes(2, "big")
        + payload
    )


def test_ccsds_report_retains_all_observations_without_payload_or_promotion() -> None:
    secret = b"SUPER_SECRET_COMMAND_VALUE"
    repeated = _packet(secret, apid=17, telecommand=True, sequence_count=4)
    changed = _packet(b"different-command", apid=17, telecommand=True, sequence_count=4)
    telemetry = _packet(b"telemetry", apid=2, telecommand=False, sequence_count=9)
    artifact = repeated + repeated + changed + telemetry

    first = analyze_satcom_bytes(artifact, kind="ccsds-space-packets").to_json()
    second = analyze_satcom_bytes(artifact, kind="ccsds-space-packets").to_json()

    assert first == second
    assert first["analysis_sha256"] == second["analysis_sha256"]
    assert len(first["observations"]) == 4
    assert first["confirmed_findings"] == []
    assert first["flags"] == []
    rendered = json.dumps(first, sort_keys=True)
    assert secret.decode() not in rendered
    assert secret.hex() not in rendered

    signals = first["security_signals"]
    assert isinstance(signals, list)
    assert {signal["kind"] for signal in signals} == {
        "byte_identical_telecommand_repeat",
        "sequence_counter_reuse",
    }
    assert all(signal["status"] in {"candidate", "informational"} for signal in signals)

    graph = first["surface_graph"]
    assert isinstance(graph, dict)
    nodes = graph["nodes"]
    assert isinstance(nodes, list)
    kinds = {node["kind"] for node in nodes}
    assert {"artifact", "ccsds_apid", "telecommand", "telemetry"} <= kinds
    assert not {"spacecraft", "ground_station", "rf_link", "virtual_channel"} & kinds


def test_tle_report_builds_only_evidence_backed_spacecraft_nodes() -> None:
    line1, line2 = _tle_pair()
    payload = f"0 TEST SAT\n{line1}\n{line2}\n".encode("ascii")

    report = analyze_satcom_bytes(payload, kind="tle").to_json()

    assert report["confirmed_findings"] == []
    assert report["security_signals"] == []
    graph = report["surface_graph"]
    assert isinstance(graph, dict)
    nodes = graph["nodes"]
    assert isinstance(nodes, list)
    assert {node["kind"] for node in nodes} == {"artifact", "spacecraft"}
    assert "No network lookup" in " ".join(report["limitations"])


def test_analysis_rejects_mutable_artifact_buffers() -> None:
    with pytest.raises(SatcomArtifactError, match="immutable bytes"):
        analyze_satcom_bytes(  # type: ignore[arg-type]
            bytearray(_packet(b"x", apid=1, telecommand=False, sequence_count=1)),
            kind="ccsds-space-packets",
        )


def test_ccsds_report_accepts_every_direction_and_apid_pair() -> None:
    artifact = b"".join(
        _packet(
            b"x",
            apid=apid,
            telecommand=telecommand,
            sequence_count=apid,
        )
        for telecommand in (False, True)
        for apid in range(1 << 11)
    )

    report = analyze_satcom_bytes(artifact, kind="ccsds-space-packets")

    assert len(report.observations) == 4_096
    assert len(report.surface_graph.nodes) == 6_145
    assert len(report.surface_graph.edges) == 8_192
    assert report.security_signals == ()


def _tle_pair() -> tuple[str, str]:
    line1 = [" "] * 68
    line1[0:2] = "1 "
    line1[2:7] = "25544"
    line1[7] = "U"
    line1[9:17] = "98067A  "
    line1[18:20] = "24"
    line1[20:32] = "001.50000000"

    line2 = [" "] * 68
    line2[0:2] = "2 "
    line2[2:7] = "25544"
    line2[8:16] = " 51.6416"
    line2[17:25] = " 50.0000"
    line2[26:33] = "0005000"
    line2[34:42] = "100.0000"
    line2[43:51] = "260.0000"
    line2[52:63] = "15.50000000"
    line2[63:68] = "43000"
    return _checksum("".join(line1)), _checksum("".join(line2))


def _checksum(body: str) -> str:
    checksum = sum(int(char) if char.isdecimal() else 1 if char == "-" else 0 for char in body)
    return f"{body}{checksum % 10}"
