# ruff: noqa: EM101, TRY003, TRY301
"""CLI handler for passive, offline SATCOM artifact inspection."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from ravage.satcom.analysis import analyze_satcom_artifact
from ravage.satcom.contracts import SatcomArtifactKind, SatcomError

if TYPE_CHECKING:
    from typing import TextIO

_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIRECTORY_MODE = 0o700
_MAX_STAGING_ATTEMPTS = 32


def handle_satcom_command(
    args: list[str],
    *,
    stdout: TextIO | None = None,
) -> dict[str, object]:
    """Handle ``ravage satcom`` arguments without constructing an active runtime."""
    parser = argparse.ArgumentParser(
        prog="ravage satcom",
        description="Inspect local SATCOM artifacts without network or transmit capability.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser(
        "inspect",
        help="decode one bounded local artifact into a passive JSON report",
    )
    inspect.add_argument("artifact", type=Path)
    inspect.add_argument(
        "--format",
        required=True,
        choices=[item.value for item in SatcomArtifactKind],
        dest="artifact_format",
        help="explicit artifact framing; phase one does not guess or resynchronize",
    )
    inspect.add_argument(
        "--direction",
        choices=("auto", "telemetry", "telecommand"),
        default="auto",
        help="optionally require every CCSDS packet to have this primary-header type",
    )
    inspect.add_argument("--output", type=Path, help="private JSON report path")
    inspect.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output file (never the input artifact)",
    )
    parsed = parser.parse_args(args)

    if parsed.artifact_format != SatcomArtifactKind.CCSDS_SPACE_PACKETS.value:
        if parsed.direction != "auto":
            parser.error("--direction is valid only with --format ccsds-space-packets")
        expected_direction = None
    else:
        expected_direction = parsed.direction
    try:
        report = analyze_satcom_artifact(
            parsed.artifact,
            kind=parsed.artifact_format,
            expected_direction=expected_direction,
        )
        payload = report.to_json()
        rendered = (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        if parsed.output is None:
            (stdout or sys.stdout).write(rendered)
        else:
            _write_private_report(
                parsed.output,
                rendered,
                input_path=parsed.artifact,
                force=parsed.force,
            )
    except SatcomError as exc:
        parser.error(str(exc))
    return payload


def _write_private_report(  # noqa: C901, PLR0912, PLR0915
    output_path: Path,
    rendered: str,
    *,
    input_path: Path,
    force: bool,
) -> None:
    output = Path(output_path)
    if output.resolve(strict=False) == Path(input_path).resolve(strict=False):
        raise SatcomError("SATCOM report output must not replace the input artifact")
    try:
        output.parent.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIRECTORY_MODE)
    except OSError as exc:
        raise SatcomError("unable to create the SATCOM report output directory") from exc

    parent_descriptor = -1
    staging_descriptor = -1
    report_descriptor = -1
    staging_name = ""
    try:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        parent_descriptor = os.open(output.parent, directory_flags)
        parent_metadata = os.fstat(parent_descriptor)
        path_metadata = output.parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or (parent_metadata.st_dev, parent_metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise SatcomError("SATCOM report output directory is unsafe")
        _validate_output_entry(parent_descriptor, output.name, force=force)

        staging_name, staging_descriptor = _create_private_staging_directory(
            parent_descriptor,
            directory_flags=directory_flags,
        )

        file_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        report_descriptor = os.open(
            "report.tmp",
            file_flags,
            _PRIVATE_FILE_MODE,
            dir_fd=staging_descriptor,
        )
        with os.fdopen(report_descriptor, "w", encoding="utf-8") as stream:
            report_descriptor = -1
            os.fchmod(stream.fileno(), _PRIVATE_FILE_MODE)
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
            prepared = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(prepared.st_mode)
                or prepared.st_nlink != 1
                or stat.S_IMODE(prepared.st_mode) != _PRIVATE_FILE_MODE
            ):
                raise SatcomError("SATCOM report staging file is unsafe")

            os.fsync(staging_descriptor)
            if force:
                os.replace(
                    "report.tmp",
                    output.name,
                    src_dir_fd=staging_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
            else:
                try:
                    os.link(
                        "report.tmp",
                        output.name,
                        src_dir_fd=staging_descriptor,
                        dst_dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    raise SatcomError(
                        "SATCOM report output already exists; pass --force to replace it"
                    ) from None
                os.unlink("report.tmp", dir_fd=staging_descriptor)

            published = os.stat(
                output.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (published.st_dev, published.st_ino) != (prepared.st_dev, prepared.st_ino):
                raise SatcomError("SATCOM report output changed during publication")
            os.fsync(parent_descriptor)
    except SatcomError:
        raise
    except OSError as exc:
        raise SatcomError("unable to write the SATCOM report safely") from exc
    finally:
        if report_descriptor >= 0:
            with suppress(OSError):
                os.close(report_descriptor)
        if staging_descriptor >= 0:
            with suppress(OSError):
                os.unlink("report.tmp", dir_fd=staging_descriptor)
            with suppress(OSError):
                os.close(staging_descriptor)
        if parent_descriptor >= 0:
            if staging_name:
                with suppress(OSError):
                    os.rmdir(staging_name, dir_fd=parent_descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)


def _validate_output_entry(parent_descriptor: int, name: str, *, force: bool) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise SatcomError("SATCOM report output must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise SatcomError("SATCOM report output must be a regular file")
    if not force:
        raise SatcomError("SATCOM report output already exists; pass --force to replace it")


def _create_private_staging_directory(
    parent_descriptor: int,
    *,
    directory_flags: int,
) -> tuple[str, int]:
    for _attempt in range(_MAX_STAGING_ATTEMPTS):
        name = f".ravage-satcom-{secrets.token_hex(12)}.staging"
        try:
            os.mkdir(name, _PRIVATE_DIRECTORY_MODE, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            os.fchmod(descriptor, _PRIVATE_DIRECTORY_MODE)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
            ):
                raise SatcomError("SATCOM report staging directory is unsafe")
        except (OSError, SatcomError):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            with suppress(OSError):
                os.rmdir(name, dir_fd=parent_descriptor)
            raise
        else:
            return name, descriptor
    raise SatcomError("unable to allocate a private SATCOM report staging directory")


__all__ = ["handle_satcom_command"]
