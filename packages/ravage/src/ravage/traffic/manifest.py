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
_PRIVATE_HTTP_STATE_VERSION = 2


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
    explicit = _canonical_workspace(supplied, supplied)
    if explicit is not None:
        return explicit

    found = resolve_workspaces(supplied)
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        choices = ", ".join(str(path) for path in found)
        raise TrafficRunError(
            "multiple traffic histories found; pass the exact workspace path: " + choices
        )
    raise TrafficRunError(f"no traffic history found in run directory {supplied}")


def resolve_workspaces(run_dir: Path) -> tuple[Path, ...]:
    """
    Return every valid canonical traffic workspace below an explicit run path.

    Discovery is deliberately non-recursive. A run can contain one base lane and
    one autonomous-graph lane, and their order is always base before graph. An
    existing canonical ``traffic`` directory is treated as an asserted artifact:
    if its manifest is missing or invalid, discovery fails closed instead of
    silently selecting another lane.
    """
    supplied = Path(run_dir)
    candidates: list[Path] = [
        supplied,
        supplied / "workspace",
        supplied / "autonomous-route" / "agent-graph",
        supplied / "workspace" / "autonomous-route" / "agent-graph",
    ]
    # Preserve custom/legacy run layouts declared by the ordinary run manifest,
    # while subjecting them to the same containment and canonical-child rules.
    for declared in _declared_workspace_candidates(supplied):
        candidates.extend((declared, declared / "autonomous-route" / "agent-graph"))
    _require_expected_traffic_roots(supplied, candidates)
    found: list[tuple[str, Path, TrafficRunManifest]] = []
    for candidate in candidates:
        resolved = _canonical_workspace(supplied, candidate)
        if resolved is None or any(resolved == item[1] for item in found):
            continue
        manifest = read_traffic_manifest(resolved)
        lane = _workspace_lane(resolved)
        if any(lane == item[0] for item in found):
            raise TrafficRunError(f"multiple canonical {lane} traffic histories found")
        found.append((lane, resolved, manifest))

    found.sort(key=lambda item: 0 if item[0] == "base" else 1)
    if found:
        expected = _manifest_boundary(found[0][2])
        if any(_manifest_boundary(item[2]) != expected for item in found[1:]):
            raise TrafficRunError("traffic histories disagree on target or scope")
    return tuple(item[1] for item in found)


def _require_posix_traffic_artifacts() -> None:
    if os.name != "posix":
        raise TrafficRunError("traffic artifacts require a POSIX filesystem; on Windows, use WSL")


def _canonical_workspace(root: Path, candidate: Path) -> Path | None:
    """Return a manifested canonical workspace contained below the supplied root."""
    resolved_candidate = _contained_candidate(root, candidate)
    if resolved_candidate is None:
        return None
    traffic_root = resolved_candidate / "traffic"
    try:
        os.lstat(traffic_root)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TrafficRunError("could not inspect canonical traffic workspace") from exc
    # The caller reads and validates the manifest. Returning a workspace as soon
    # as its canonical traffic root exists ensures malformed roots are not
    # skipped in favour of another valid lane.
    read_traffic_manifest(resolved_candidate)
    return resolved_candidate


def _workspace_lane(workspace: Path) -> str:
    if workspace.name == "agent-graph" and workspace.parent.name == "autonomous-route":
        return "autonomous_graph"
    return "base"


def _manifest_boundary(manifest: TrafficRunManifest) -> tuple[object, ...]:
    return (
        manifest.target_url,
        manifest.target_identity,
        manifest.origin,
        manifest.in_scope,
        manifest.out_of_scope,
    )


def _require_expected_traffic_roots(root: Path, candidates: list[Path]) -> None:
    """Reject durable HTTP state whose adjacent canonical traffic lane is missing."""
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = _contained_candidate(root, candidate)
        if resolved is None or resolved in seen:
            continue
        seen.add(resolved)
        if not _traffic_expected_at(resolved):
            continue
        try:
            os.lstat(resolved / "traffic")
        except FileNotFoundError as exc:
            raise TrafficRunError(
                "durable HTTP state exists without its canonical traffic history"
            ) from exc
        except OSError as exc:
            raise TrafficRunError("could not inspect canonical traffic workspace") from exc


def _contained_candidate(root: Path, candidate: Path) -> Path | None:
    try:
        resolved_root = root.resolve(strict=True)
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError) as exc:
        raise TrafficRunError("could not resolve traffic run directory") from exc
    try:
        resolved_candidate = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError) as exc:
        raise TrafficRunError("could not resolve canonical traffic workspace") from exc
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError:
        return None
    return resolved_candidate


def _traffic_expected_at(workspace: Path) -> bool:
    if any(
        _artifact_path_present(workspace / name)
        for name in ("agent-http-state.json", "graph-http-state.json")
    ):
        return True
    remote_state = _read_bounded_json(workspace / "remote-http-state.json")
    if (
        isinstance(remote_state, dict)
        and remote_state.get("version") == _PRIVATE_HTTP_STATE_VERSION
        and remote_state.get("target_identity")
    ):
        return True
    for receipt_name in ("graph-route-receipt.json", "remote-graph-receipt.json"):
        receipt = _read_bounded_json(workspace / receipt_name)
        if isinstance(receipt, dict) and "traffic" in receipt:
            return True
    return False


def _artifact_path_present(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise TrafficRunError("could not inspect durable HTTP state") from exc
    return True


def _declared_workspace_candidates(run_dir: Path) -> tuple[Path, ...]:
    payload = _read_bounded_json(run_dir / "run.json")
    if not isinstance(payload, dict) or not payload.get("workspace_dir"):
        return ()
    declared = Path(str(payload["workspace_dir"]))
    if declared.is_absolute():
        return (declared,)
    # Older manifests have used both run-relative and process-relative paths.
    # `_canonical_workspace` later rejects either interpretation if it escapes
    # the explicitly supplied run directory.
    return (run_dir / declared, Path.cwd() / declared)


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
    "resolve_workspaces",
    "write_traffic_manifest",
]
