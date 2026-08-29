# ruff: noqa: C901, EM101, PLR0912, TRY003
"""Fail-closed local artifact reader for passive SATCOM analysis."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from ravage.satcom.contracts import (
    MAX_ARTIFACT_BYTES,
    SatcomArtifactError,
    SatcomArtifactKind,
    SatcomArtifactReference,
    artifact_kind,
)


@dataclass(frozen=True, slots=True)
class SatcomArtifact:
    reference: SatcomArtifactReference
    data: bytes


def read_regular_artifact(
    path: Path,
    *,
    kind: SatcomArtifactKind | str,
    max_bytes: int = MAX_ARTIFACT_BYTES,
) -> SatcomArtifact:
    """
    Read one bounded regular file without following a final-component symlink.

    FIFOs and devices are rejected before reads, avoiding blocking or unbounded
    streams.  Metadata is checked again after the read so a concurrently
    replaced or resized file cannot silently acquire the original identity.
    """
    if not 0 < max_bytes <= MAX_ARTIFACT_BYTES:
        raise SatcomArtifactError("SATCOM artifact byte limit is invalid")
    resolved_kind = artifact_kind(kind)
    candidate = Path(path)
    # O_NONBLOCK is harmless for regular files and prevents a hostile FIFO from
    # blocking before fstat can reject it.
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow
    else:
        with suppress(OSError):
            if candidate.is_symlink():
                raise SatcomArtifactError("SATCOM artifact must not be a symlink")

    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SatcomArtifactError("SATCOM artifact must be a regular file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise SatcomArtifactError("SATCOM artifact exceeds the byte limit")

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise SatcomArtifactError("SATCOM artifact exceeds the byte limit")

        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or len(data) != after.st_size:
            raise SatcomArtifactError("SATCOM artifact changed while it was being read")
    except OSError as exc:
        raise SatcomArtifactError("unable to read SATCOM artifact safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    reference = SatcomArtifactReference.from_bytes(data, kind=resolved_kind)
    return SatcomArtifact(reference=reference, data=data)


__all__ = ["SatcomArtifact", "read_regular_artifact"]
