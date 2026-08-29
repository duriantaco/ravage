# ruff: noqa: EM101, EM102, TRY003
"""Versioned metadata for a Ravage traffic-capture run."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from .redaction import safe_identifier, sanitize_url

TRAFFIC_RUN_SCHEMA = "ravage.traffic-run.v1"
TRAFFIC_RUN_MANIFEST = "run.json"
_MAX_MANIFEST_BYTES = 262_144
_TARGET_IDENTITY_RE = re.compile(r"^target:[0-9a-f]{64}$")


class TrafficRunError(RuntimeError):
    """Raised when traffic-run metadata is missing or invalid."""


@dataclass(frozen=True, slots=True)
class TrafficRunManifest:
    """The redacted authorization boundary needed to inspect and replay a run."""

    target_url: str
    target_identity: str
    origin: str
    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...]
    capture_session_id: str
    created_at: str
    completed_at: str = ""
    schema: str = TRAFFIC_RUN_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        target_url: str,
        capture_session_id: str,
        in_scope: tuple[str, ...] = (),
        out_of_scope: tuple[str, ...] = (),
    ) -> TrafficRunManifest:
        raw_target = target_url.strip()
        safe_target = sanitize_url(raw_target)
        parsed = urlsplit(safe_target)
        scheme = parsed.scheme.casefold()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise TrafficRunError("traffic target must be an HTTP(S) URL with a host")
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        safe_in_scope = _safe_scope_entries(in_scope, label="in-scope") or (f"{origin}/",)
        safe_out_of_scope = _safe_scope_entries(out_of_scope, label="out-of-scope")
        safe_capture_session_id = safe_identifier(capture_session_id)
        if not safe_capture_session_id or safe_capture_session_id != capture_session_id:
            raise TrafficRunError("capture session ID must be a non-secret identifier")
        now = datetime.now(UTC).isoformat()
        return cls(
            target_url=safe_target,
            target_identity=_target_identity(raw_target),
            origin=origin,
            in_scope=safe_in_scope,
            out_of_scope=safe_out_of_scope,
            capture_session_id=safe_capture_session_id,
            created_at=now,
        )

    def complete(self) -> TrafficRunManifest:
        return TrafficRunManifest(
            target_url=self.target_url,
            target_identity=self.target_identity,
            origin=self.origin,
            in_scope=self.in_scope,
            out_of_scope=self.out_of_scope,
            capture_session_id=self.capture_session_id,
            created_at=self.created_at,
            completed_at=datetime.now(UTC).isoformat(),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "target_url": self.target_url,
            "target_identity": self.target_identity,
            "origin": self.origin,
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "capture_session_id": self.capture_session_id,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_json(cls, payload: object) -> TrafficRunManifest:
        if not isinstance(payload, dict) or payload.get("schema") != TRAFFIC_RUN_SCHEMA:
            raise TrafficRunError("unsupported or invalid traffic run manifest")
        try:
            target_url = str(payload["target_url"])
            manifest = cls(
                target_url=target_url,
                target_identity=(
                    # Legacy v1 manifests lack the raw-target hash. Their
                    # redacted stored URL is the only safe derivation source.
                    _target_identity(target_url)
                    if "target_identity" not in payload
                    else str(payload["target_identity"])
                ),
                origin=str(payload["origin"]),
                in_scope=_string_tuple(payload.get("in_scope")),
                out_of_scope=_string_tuple(payload.get("out_of_scope")),
                capture_session_id=str(payload["capture_session_id"]),
                created_at=str(payload["created_at"]),
                completed_at=str(payload.get("completed_at") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TrafficRunError("traffic run manifest is incomplete") from exc
        expected = cls.create(
            target_url=manifest.target_url,
            capture_session_id=manifest.capture_session_id,
            in_scope=manifest.in_scope,
            out_of_scope=manifest.out_of_scope,
        )
        if (
            manifest.origin != expected.origin
            or manifest.target_url != expected.target_url
            or manifest.in_scope != expected.in_scope
            or manifest.out_of_scope != expected.out_of_scope
        ):
            raise TrafficRunError("traffic run manifest contains an unsafe target URL")
        if not _TARGET_IDENTITY_RE.fullmatch(manifest.target_identity):
            raise TrafficRunError("traffic run manifest target identity is invalid")
        if not manifest.capture_session_id or not manifest.created_at:
            raise TrafficRunError("traffic run manifest is incomplete")
        return manifest


def write_traffic_manifest(workspace_dir: Path, manifest: TrafficRunManifest) -> Path:
    _require_posix_traffic_artifacts()
    root = Path(workspace_dir) / "traffic"
    if root.is_symlink():
        raise TrafficRunError("traffic manifest directory cannot be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        root_metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise TrafficRunError(f"could not inspect traffic manifest directory: {exc}") from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise TrafficRunError("traffic manifest path is not a directory")
    root.chmod(0o700)
    path = root / TRAFFIC_RUN_MANIFEST
    validated = TrafficRunManifest.from_json(manifest.to_json())
    if path.exists():
        existing = read_traffic_manifest(workspace_dir)
        if existing.capture_session_id != validated.capture_session_id:
            raise TrafficRunError("traffic manifest belongs to a different capture session")
        if (
            existing.target_url != validated.target_url
            or existing.target_identity != validated.target_identity
            or existing.origin != validated.origin
            or existing.in_scope != validated.in_scope
            or existing.out_of_scope != validated.out_of_scope
            or existing.created_at != validated.created_at
        ):
            raise TrafficRunError("traffic manifest cannot change within a capture session")
    encoded = (json.dumps(validated.to_json(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = root / f".{TRAFFIC_RUN_MANIFEST}.{uuid4().hex}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        _write_all(descriptor, encoded)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        temporary.replace(path)
    except OSError as exc:
        raise TrafficRunError(f"could not write traffic run manifest: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()
    path.chmod(0o600)
    return path


def read_traffic_manifest(workspace_dir: Path) -> TrafficRunManifest:
    _require_posix_traffic_artifacts()
    root = Path(workspace_dir) / "traffic"
    if root.is_symlink():
        raise TrafficRunError("traffic manifest directory cannot be a symlink")
    try:
        root_metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise TrafficRunError(f"no traffic history found at {root}") from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise TrafficRunError("traffic manifest path is not a directory")
    if root_metadata.st_mode & 0o077:
        raise TrafficRunError("traffic manifest directory permissions must be owner-only")
    path = root / TRAFFIC_RUN_MANIFEST
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise TrafficRunError(f"no traffic history found at {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TrafficRunError("traffic run manifest is not a regular file")
        if metadata.st_mode & 0o077:
            raise TrafficRunError("traffic run manifest permissions must be owner-only")
        raw = os.read(descriptor, _MAX_MANIFEST_BYTES + 1)
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise TrafficRunError("traffic run manifest exceeds the size limit")
    finally:
        os.close(descriptor)
    try:
        return TrafficRunManifest.from_json(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TrafficRunError("traffic run manifest is not valid JSON") from exc


def resolve_workspace(run_dir: Path) -> Path:
    """Resolve an explicit run directory without guessing a latest run."""
    supplied = Path(run_dir)
    found: list[Path] = []
    for candidate in (
        supplied,
        supplied / "workspace",
        supplied / "autonomous-route" / "agent-graph",
        supplied / "workspace" / "autonomous-route" / "agent-graph",
    ):
        resolved = _contained_workspace(supplied, candidate)
        if resolved is not None and resolved not in found:
            found.append(resolved)

    # A normal scan can store a workspace below its run directory. Never follow
    # an arbitrary external pointer from an untrusted run bundle; an operator
    # can pass an external workspace explicitly instead.
    run_manifest = supplied / "run.json"
    payload = _read_bounded_json(run_manifest)
    if isinstance(payload, dict) and payload.get("workspace_dir"):
        declared = Path(str(payload["workspace_dir"]))
        declared_candidates = (
            (declared,) if declared.is_absolute() else (supplied / declared, Path.cwd() / declared)
        )
        for declared_candidate in declared_candidates:
            for possible in (
                declared_candidate,
                declared_candidate / "autonomous-route" / "agent-graph",
            ):
                resolved = _contained_workspace(supplied, possible)
                if resolved is not None and resolved not in found:
                    found.append(resolved)
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        choices = ", ".join(str(path) for path in found)
        raise TrafficRunError(
            "multiple traffic histories found; pass the exact workspace path: " + choices
        )
    raise TrafficRunError(f"no traffic history found in run directory {supplied}")


def _require_posix_traffic_artifacts() -> None:
    if os.name != "posix":
        raise TrafficRunError("traffic artifacts require a POSIX filesystem; on Windows, use WSL")


def _contained_workspace(root: Path, candidate: Path) -> Path | None:
    """Return a real workspace path only when it stays below the supplied root."""
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
    except (OSError, ValueError):
        return None
    manifest = resolved_candidate / "traffic" / TRAFFIC_RUN_MANIFEST
    return resolved_candidate if manifest.is_file() else None


def _read_bounded_json(path: Path) -> object | None:
    """Read an untrusted auxiliary manifest without following links or growing unbounded."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_MANIFEST_BYTES:
            return None
        chunks: list[bytes] = []
        remaining = _MAX_MANIFEST_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_MANIFEST_BYTES:
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)
    try:
        payload: object = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return payload


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if str(item))


def _safe_scope_entries(entries: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    safe_entries: list[str] = []
    for entry in entries:
        try:
            parsed = urlsplit(str(entry).strip())
            port = parsed.port
        except ValueError as exc:
            raise TrafficRunError(f"{label} traffic entry is invalid") from exc
        scheme = parsed.scheme.casefold()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise TrafficRunError(f"{label} traffic entries must be absolute HTTP(S) URLs")
        if parsed.username is not None or parsed.password is not None:
            raise TrafficRunError(f"{label} traffic entries cannot contain userinfo")
        host = parsed.hostname.casefold()
        if ":" in host:
            host = f"[{host}]"
        netloc = f"{host}:{port}" if port is not None else host
        # Scope matching is origin/path based. Queries and fragments never
        # affect authorization, so omit them rather than persisting values.
        candidate = urlunsplit((scheme, netloc, parsed.path or "/", "", ""))
        sanitized_path = urlsplit(sanitize_url(candidate)).path
        if sanitized_path != (parsed.path or "/") and any(
            segment in {":id", ":redacted"} for segment in sanitized_path.split("/")
        ):
            raise TrafficRunError(
                f"{label} traffic entries cannot persist dynamic or secret-like path segments; "
                "scope a stable parent path instead"
            )
        safe_entries.append(candidate)
    return tuple(safe_entries)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("traffic run manifest write was incomplete")
        offset += written


def _target_identity(target_url: str) -> str:
    digest = hashlib.sha256(target_url.strip().encode()).hexdigest()
    return f"target:{digest}"


__all__ = [
    "TRAFFIC_RUN_MANIFEST",
    "TRAFFIC_RUN_SCHEMA",
    "TrafficRunError",
    "TrafficRunManifest",
    "read_traffic_manifest",
    "resolve_workspace",
    "write_traffic_manifest",
]
