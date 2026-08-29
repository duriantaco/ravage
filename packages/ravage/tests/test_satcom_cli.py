# ruff: noqa: EM101, PLR2004, TC003, TRY003
from __future__ import annotations

import io
import json
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest
import ravage.satcom.artifacts as satcom_artifacts_module
import ravage.satcom.cli as satcom_cli_module
from ravage import __main__ as cli
from ravage.satcom.artifacts import read_regular_artifact
from ravage.satcom.cli import handle_satcom_command
from ravage.satcom.contracts import SatcomArtifactError


def _packet(payload: bytes = b"telemetry") -> bytes:
    packet_id = (1 << 11) | 3
    sequence = (3 << 14) | 1
    return (
        packet_id.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + (len(payload) - 1).to_bytes(2, "big")
        + payload
    )


def test_cli_inspects_offline_without_network_or_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "capture.bin"
    artifact.write_bytes(_packet())
    output = io.StringIO()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("active capability was constructed")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    payload = handle_satcom_command(
        ["inspect", str(artifact), "--format", "ccsds-space-packets"],
        stdout=output,
    )

    rendered = json.loads(output.getvalue())
    assert rendered == payload
    assert rendered["mode"] == "passive_offline"
    assert rendered["confirmed_findings"] == []
    assert str(artifact) not in output.getvalue()


def test_top_level_cli_dispatches_satcom_inspect(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifact = tmp_path / "capture.bin"
    artifact.write_bytes(_packet())

    cli.main(["satcom", "inspect", str(artifact), "--format", "ccsds-space-packets"])

    rendered = json.loads(capsys.readouterr().out)
    assert rendered["mode"] == "passive_offline"
    assert rendered["artifact"]["kind"] == "ccsds-space-packets"


def test_cli_writes_private_report_and_refuses_implicit_overwrite(tmp_path: Path) -> None:
    artifact = tmp_path / "capture.bin"
    artifact.write_bytes(_packet())
    report = tmp_path / "report.json"
    args = [
        "inspect",
        str(artifact),
        "--format",
        "ccsds-space-packets",
        "--output",
        str(report),
    ]

    handle_satcom_command(args)

    assert report.is_file()
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    with pytest.raises(SystemExit) as exc:
        handle_satcom_command(args)
    assert exc.value.code == 2
    handle_satcom_command([*args, "--force"])


def test_cli_non_force_publish_never_clobbers_a_concurrent_creator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "capture.bin"
    artifact.write_bytes(_packet())
    report = tmp_path / "report.json"
    real_link = satcom_cli_module.os.link

    def racing_link(source: object, destination: object, **kwargs: object) -> None:
        destination_descriptor = kwargs.get("dst_dir_fd")
        assert isinstance(destination_descriptor, int)
        descriptor = os.open(
            str(destination),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=destination_descriptor,
        )
        try:
            os.write(descriptor, b"CONCURRENT\n")
        finally:
            os.close(descriptor)
        real_link(source, destination, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(satcom_cli_module.os, "link", racing_link)

    with pytest.raises(SystemExit) as exc:
        handle_satcom_command(
            [
                "inspect",
                str(artifact),
                "--format",
                "ccsds-space-packets",
                "--output",
                str(report),
            ]
        )

    assert exc.value.code == 2
    assert report.read_bytes() == b"CONCURRENT\n"
    assert not tuple(tmp_path.glob(".ravage-satcom-*.staging"))


def test_cli_never_replaces_input_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "capture.bin"
    original = _packet()
    artifact.write_bytes(original)

    with pytest.raises(SystemExit) as exc:
        handle_satcom_command(
            [
                "inspect",
                str(artifact),
                "--format",
                "ccsds-space-packets",
                "--output",
                str(artifact),
                "--force",
            ]
        )

    assert exc.value.code == 2
    assert artifact.read_bytes() == original


def test_artifact_reader_rejects_symlinks_and_fifos(tmp_path: Path) -> None:
    artifact = tmp_path / "capture.bin"
    artifact.write_bytes(_packet())
    link = tmp_path / "capture-link.bin"
    link.symlink_to(artifact)

    with pytest.raises(SatcomArtifactError, match=r"read.*safely|symlink"):
        read_regular_artifact(link, kind="ccsds-space-packets")

    fifo = tmp_path / "capture.fifo"
    os.mkfifo(fifo)
    with pytest.raises(SatcomArtifactError, match="regular file"):
        read_regular_artifact(fifo, kind="ccsds-space-packets")


def test_artifact_reader_detects_same_size_rewrite_with_restored_mtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "capture.bin"
    original = _packet()
    artifact.write_bytes(original)
    before = artifact.stat()
    real_read = satcom_artifacts_module.os.read
    raced = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        chunk = real_read(descriptor, size)
        if chunk and not raced:
            raced = True
            with artifact.open("r+b") as stream:
                stream.write(b"X" * len(original))
                stream.flush()
                os.fsync(stream.fileno())
            os.utime(artifact, ns=(before.st_atime_ns, before.st_mtime_ns))
        return chunk

    monkeypatch.setattr(satcom_artifacts_module.os, "read", racing_read)

    with pytest.raises(SatcomArtifactError, match="changed while it was being read"):
        read_regular_artifact(artifact, kind="ccsds-space-packets")


def test_cli_rejects_direction_for_tle_before_analysis(tmp_path: Path) -> None:
    artifact = tmp_path / "orbit.tle"
    artifact.write_text("not parsed", encoding="ascii")

    with pytest.raises(SystemExit) as exc:
        handle_satcom_command(
            [
                "inspect",
                str(artifact),
                "--format",
                "tle",
                "--direction",
                "telemetry",
            ]
        )
    assert exc.value.code == 2
