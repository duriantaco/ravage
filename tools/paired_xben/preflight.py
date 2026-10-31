"""Secret-safe, create-only preflight for paired XBEN comparisons."""

# ruff: noqa: D202,D213,EM101,EM102,TRY003,TRY300

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from stat import S_ISREG, S_ISSOCK
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

PREFLIGHT_SCHEMA: Final = "ravage.paired-xben.preflight.v1"
PREFLIGHT_FILENAME: Final = "preflight.json"
DEFAULT_REQUIRED_FREE_GIB: Final = 20
DEFAULT_DOCKER_TIMEOUT_SECONDS: Final = 5.0
DEFAULT_XBEN_CASE_COUNT: Final = 104
DEFAULT_PROVIDER_ENV_NAMES: Final = ("OPENAI_API_KEY",)
DEFAULT_GIT_EXECUTABLE: Final = Path("/usr/bin/git")
DEFAULT_TRUSTED_PATH: Final = "/usr/bin:/bin"
MAX_PREFLIGHT_JSON_BYTES: Final = 64 * 1024
REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]
XBEN_CANONICAL_ORIGIN_URL: Final = "https://github.com/xbow-engineering/validation-benchmarks.git"
STRIX_CANONICAL_ORIGIN_URL: Final = "https://github.com/usestrix/strix.git"

_GIB: Final = 1024**3
_ENV_NAME_RE: Final = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_HEAD_RE: Final = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_SHA256_RE: Final = re.compile(r"(?:sha256:)?([0-9a-fA-F]{64})")
_XBEN_ID_RE: Final = re.compile(r"XBEN-(\d{3})-24")
_SCP_GIT_URL_RE: Final = re.compile(r"(?:[^@/:\s]+@)?([^/:\s]+):([^\s]+)")
_WEBSITE_CLASSIFICATIONS: Final = frozenset({"unresolved", "known_site", "sealed_holdout"})
_MAX_PROVIDER_ENV_NAMES: Final = 16
_MAX_XBEN_DIRECTORY_ENTRIES: Final = 256
_MAX_PROBE_TIMEOUT_SECONDS: Final = 60
_MAX_TIMESTAMP_LENGTH: Final = 128
_MAX_EXECUTABLE_BYTES: Final = 512 * 1024 * 1024
_MAX_GIT_OUTPUT_BYTES: Final = 4 * 1024 * 1024
_MAX_GIT_REMOTE_LENGTH: Final = 4096
_MAX_TRUSTED_PATH_LENGTH: Final = 8192
_MAX_TRUSTED_PATH_ENTRIES: Final = 32
_SHA1_HEX_LENGTH: Final = 40
_GIT_LS_TREE_METADATA_FIELDS: Final = 3
_PROBE_CLEANUP_SECONDS: Final = 1.0


class PreflightConfigurationError(ValueError):
    """Raised when a preflight request is malformed."""


def collect_preflight(  # noqa: C901, PLR0912, PLR0913
    *,
    evidence_dir: Path,
    benchmarks_root: Path,
    strix_repo_root: Path | None,
    ravage_repo_root: Path = REPOSITORY_ROOT,
    xben_repo_root: Path | None = None,
    required_free_gib: int = DEFAULT_REQUIRED_FREE_GIB,
    required_provider_env: Sequence[str] = DEFAULT_PROVIDER_ENV_NAMES,
    environment: Mapping[str, str] | None = None,
    trusted_path: str = DEFAULT_TRUSTED_PATH,
    git_executable: str | Path = DEFAULT_GIT_EXECUTABLE,
    docker_executable: str | Path | None = None,
    docker_socket: str | Path | None = None,
    strix_executable: str | Path | None = None,
    expected_strix_executable_sha256: str | None = None,
    expected_ravage_head: str | None = None,
    expected_strix_head: str | None = None,
    expected_xben_head: str | None = None,
    expected_xben_case_count: int = DEFAULT_XBEN_CASE_COUNT,
    require_clean_sources: bool = True,
    require_website_target: bool = True,
    website_target: str | None = None,
    website_classification: str = "unresolved",
    docker_timeout_seconds: float = DEFAULT_DOCKER_TIMEOUT_SECONDS,
    captured_at: str | None = None,
) -> dict[str, object]:
    """Collect bounded readiness metadata without loading any dotenv file.

    ``environment`` is consulted only for the presence of explicitly named
    provider variables. Values are never copied into the returned object.
    ``website_target`` is likewise represented by a digest, never by its raw
    value, so a private target reference does not leak into public evidence.
    """

    _validate_positive_int("required_free_gib", required_free_gib, allow_zero=True)
    _validate_positive_int("expected_xben_case_count", expected_xben_case_count)
    if expected_xben_case_count > _MAX_XBEN_DIRECTORY_ENTRIES:
        raise PreflightConfigurationError("expected_xben_case_count exceeds the pool limit")
    if (
        isinstance(docker_timeout_seconds, bool)
        or not isinstance(docker_timeout_seconds, int | float)
        or not math.isfinite(docker_timeout_seconds)
        or docker_timeout_seconds <= 0
        or docker_timeout_seconds > _MAX_PROBE_TIMEOUT_SECONDS
    ):
        raise PreflightConfigurationError(
            "docker_timeout_seconds must be greater than zero and at most 60"
        )
    provider_names = _provider_env_names(required_provider_env)
    probe_path = _trusted_probe_path(trusted_path)
    classification = _website_classification(website_classification)
    expected_heads = {
        "ravage": _expected_head(expected_ravage_head),
        "strix": _expected_head(expected_strix_head),
        "xben": _expected_head(expected_xben_head),
    }
    expected_strix_binary = _expected_sha256(expected_strix_executable_sha256)

    resolved_xben_repo = xben_repo_root or _nearest_git_root(benchmarks_root)
    git = {
        "ravage": _git_state(
            ravage_repo_root,
            expected_heads["ravage"],
            git_executable=git_executable,
            trusted_path=probe_path,
        ),
        "strix": _git_state(
            strix_repo_root,
            expected_heads["strix"],
            git_executable=git_executable,
            trusted_path=probe_path,
        ),
        "xben": _git_state(
            resolved_xben_repo,
            expected_heads["xben"],
            git_executable=git_executable,
            trusted_path=probe_path,
        ),
    }
    disk = _disk_status(evidence_dir, required_free_gib=required_free_gib)
    docker = _docker_status(
        executable=docker_executable,
        socket_path=docker_socket,
        trusted_path=probe_path,
        timeout_seconds=docker_timeout_seconds,
    )
    xben = _xben_status(
        benchmarks_root,
        xben_repo_root=resolved_xben_repo,
        expected_head=expected_heads["xben"],
        expected_case_count=expected_xben_case_count,
        git_executable=git_executable,
        trusted_path=probe_path,
    )
    strix = _strix_runtime_status(
        strix_repo_root=strix_repo_root,
        executable=strix_executable,
        expected_source_head=expected_heads["strix"],
        expected_executable_sha256=expected_strix_binary,
        timeout_seconds=docker_timeout_seconds,
        git_executable=git_executable,
        trusted_path=probe_path,
    )
    provider = _provider_status(
        provider_names,
        os.environ if environment is None else environment,
    )
    website = _website_status(
        target=website_target,
        classification=classification,
        required=require_website_target,
    )

    block_reasons: list[str] = []
    if not disk["ready"]:
        block_reasons.append(
            "disk_status_unavailable"
            if disk["status"] == "unavailable"
            else "disk_free_below_required"
        )
    if not docker["ready"]:
        block_reasons.append("docker_daemon_unhealthy")
    if not xben["exact_case_set"]:
        block_reasons.append("xben_case_pool_incomplete")
    xben_source_binding = xben.get("source_binding")
    if not isinstance(xben_source_binding, dict) or xben_source_binding.get("ready") is not True:
        block_reasons.append("xben_benchmark_source_unbound")
    if not strix["ready"]:
        block_reasons.append("strix_runtime_unready")
    if not provider["ready"]:
        block_reasons.append("provider_environment_missing")
    if require_website_target and not website["resolved"]:
        block_reasons.append("website_target_unresolved")

    for repository in ("ravage", "strix", "xben"):
        state = git[repository]
        if not state["available"]:
            block_reasons.append(f"{repository}_git_state_unavailable")
            continue
        if require_clean_sources and state["dirty"]:
            block_reasons.append(f"{repository}_source_dirty")
        if state["pin_status"] == "unresolved":
            block_reasons.append(f"{repository}_pin_unresolved")
        elif state["pin_status"] == "mismatch":
            block_reasons.append(f"{repository}_head_mismatch")

    return {
        "schema_version": PREFLIGHT_SCHEMA,
        "captured_at": _timestamp(captured_at),
        "blocked": bool(block_reasons),
        "block_reasons": block_reasons,
        "policy": {
            "require_clean_sources": require_clean_sources,
            "require_source_pins": True,
            "require_website_target": require_website_target,
        },
        "disk": disk,
        "docker": docker,
        "git": git,
        "xben": xben,
        "strix": strix,
        "provider_environment": provider,
        "website": website,
    }


def canonical_json_bytes(payload: Mapping[str, object]) -> bytes:
    """Encode one report using the campaign's stable JSON representation."""

    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def write_preflight(
    evidence_dir: Path,
    payload: Mapping[str, object],
) -> Path:
    """Create ``preflight.json`` exactly once and never replace prior evidence."""

    requested = evidence_dir.expanduser()
    if requested.is_symlink():
        raise PreflightConfigurationError("evidence directory must not be a symlink")
    directory = requested.resolve(strict=False)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        if not directory.is_dir() or any(directory.iterdir()):
            raise PreflightConfigurationError("evidence directory must be new or empty") from None
    path = directory / PREFLIGHT_FILENAME
    body = canonical_json_bytes(payload)
    if len(body) > MAX_PREFLIGHT_JSON_BYTES:
        raise PreflightConfigurationError("preflight report exceeds the byte limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("preflight artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def collect_and_write_preflight(**kwargs: object) -> tuple[dict[str, object], Path]:
    """Collect a report and create its evidence artifact."""

    report = collect_preflight(**kwargs)  # type: ignore[arg-type]
    evidence_dir = kwargs.get("evidence_dir")
    if not isinstance(evidence_dir, Path):
        raise PreflightConfigurationError("evidence_dir must be a Path")
    return report, write_preflight(evidence_dir, report)


def preflight_exit_code(report: Mapping[str, object]) -> int:
    """Return a non-zero process status for a blocked report."""

    return 2 if report.get("blocked") is True else 0


def _disk_status(path: Path, *, required_free_gib: int) -> dict[str, object]:
    required_bytes = required_free_gib * _GIB
    probe_path = _nearest_existing_path(path)
    try:
        usage = shutil.disk_usage(probe_path)
    except OSError:
        return {
            "ready": False,
            "status": "unavailable",
            "free_bytes": None,
            "free_gib": None,
            "required_free_bytes": required_bytes,
            "required_free_gib": required_free_gib,
        }
    free_bytes = int(usage.free)
    return {
        "ready": free_bytes >= required_bytes,
        "status": "ready" if free_bytes >= required_bytes else "insufficient",
        "free_bytes": free_bytes,
        "free_gib": round(free_bytes / _GIB, 3),
        "required_free_bytes": required_bytes,
        "required_free_gib": required_free_gib,
    }


def _docker_status(
    *,
    executable: str | Path | None,
    socket_path: str | Path | None,
    trusted_path: str,
    timeout_seconds: float,
) -> dict[str, object]:
    resolved_executable = _resolve_explicit_executable(executable)
    if resolved_executable is None:
        return {
            "ready": False,
            "executable_present": False,
            "daemon_responsive": False,
            "status": "executable_missing",
            "timeout_seconds": timeout_seconds,
        }
    resolved_socket = _resolve_explicit_socket(socket_path)
    if resolved_socket is None:
        return {
            "ready": False,
            "executable_present": True,
            "daemon_responsive": False,
            "status": "socket_unavailable",
            "timeout_seconds": timeout_seconds,
        }
    with tempfile.TemporaryDirectory(prefix="ravage-preflight-docker-") as temporary:
        isolation_root = Path(temporary)
        home = isolation_root / "home"
        work = isolation_root / "work"
        docker_config = home / ".docker"
        for directory in (home, work, docker_config):
            directory.mkdir(mode=0o700)
        environment = _minimal_probe_environment(
            trusted_path=trusted_path,
            home=home,
            temporary=isolation_root,
        )
        environment.update(
            {
                "DOCKER_CONFIG": str(docker_config),
                "DOCKER_HOST": f"unix://{resolved_socket}",
            }
        )
        status, returncode = _run_bounded(
            (str(resolved_executable), "info", "--format", "{{.ServerVersion}}"),
            cwd=work,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
    responsive = status == "completed" and returncode == 0
    return {
        "ready": responsive,
        "executable_present": True,
        "daemon_responsive": responsive,
        "status": "ready" if responsive else status,
        "timeout_seconds": timeout_seconds,
    }


def _xben_status(  # noqa: PLR0913
    root: Path,
    *,
    xben_repo_root: Path | None,
    expected_head: str | None,
    expected_case_count: int,
    git_executable: str | Path = DEFAULT_GIT_EXECUTABLE,
    trusted_path: str = DEFAULT_TRUSTED_PATH,
) -> dict[str, object]:
    location = root.expanduser().resolve(strict=False)
    source_binding = _repository_binding_status(
        root=xben_repo_root,
        expected_head=expected_head,
        expected_origin_url=XBEN_CANONICAL_ORIGIN_URL,
        tracked_tree="benchmarks",
        required_location=location,
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    expected_ids = {f"XBEN-{number:03d}-24" for number in range(1, expected_case_count + 1)}
    if not location.is_dir():
        return {
            "ready": False,
            "status": "pool_missing",
            "pool_location": str(location),
            "case_count": 0,
            "eligible_case_count": 0,
            "expected_case_count": expected_case_count,
            "exact_case_set": False,
            "eligible_case_ids": [],
            "eligible_case_ids_sha256": _case_ids_digest(()),
            "eligibility_basis": "canonical_directory_with_metadata_and_compose",
            "source_binding": source_binding,
        }

    case_ids: list[str] = []
    eligible_ids: list[str] = []
    case_count = 0
    eligible_case_count = 0
    overflow = False
    try:
        for entry in location.iterdir():
            if not entry.is_dir() or _XBEN_ID_RE.fullmatch(entry.name) is None:
                continue
            case_count += 1
            if len(case_ids) >= _MAX_XBEN_DIRECTORY_ENTRIES:
                overflow = True
                continue
            case_ids.append(entry.name)
            has_metadata = (entry / "benchmark.json").is_file() or (
                entry / "benchmark.yaml"
            ).is_file()
            has_compose = (entry / "docker-compose.yml").is_file() or (
                entry / "docker-compose.yaml"
            ).is_file()
            if has_metadata and has_compose:
                eligible_case_count += 1
                eligible_ids.append(entry.name)
    except OSError:
        return {
            "ready": False,
            "status": "pool_unreadable",
            "pool_location": str(location),
            "case_count": 0,
            "eligible_case_count": 0,
            "expected_case_count": expected_case_count,
            "exact_case_set": False,
            "eligible_case_ids": [],
            "eligible_case_ids_sha256": _case_ids_digest(()),
            "eligibility_basis": "canonical_directory_with_metadata_and_compose",
            "source_binding": source_binding,
        }

    case_ids.sort()
    eligible_ids.sort()
    exact = not overflow and set(case_ids) == expected_ids and set(eligible_ids) == expected_ids
    ready = exact and source_binding["ready"] is True
    status = (
        "ready"
        if ready
        else (
            "source_unbound"
            if exact and source_binding["ready"] is not True
            else ("pool_too_large" if overflow else "incomplete")
        )
    )
    return {
        "ready": ready,
        "status": status,
        "pool_location": str(location),
        "case_count": case_count,
        "eligible_case_count": eligible_case_count,
        "expected_case_count": expected_case_count,
        "exact_case_set": exact,
        "eligible_case_ids": eligible_ids,
        "eligible_case_ids_sha256": _case_ids_digest(eligible_ids),
        "eligibility_basis": "canonical_directory_with_metadata_and_compose",
        "source_binding": source_binding,
    }


def _git_state(
    root: Path | None,
    expected_head: str | None,
    *,
    git_executable: str | Path = DEFAULT_GIT_EXECUTABLE,
    trusted_path: str = DEFAULT_TRUSTED_PATH,
) -> dict[str, object]:
    if root is None:
        return _unavailable_git_state("root_unresolved", expected_head=expected_head)
    location = root.expanduser().resolve(strict=False)
    if not location.is_dir():
        return _unavailable_git_state("root_missing", expected_head=expected_head)
    head = _run_git(
        location,
        ("rev-parse", "--verify", "HEAD"),
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    status = _run_git(
        location,
        ("status", "--porcelain=v1", "--untracked-files=normal"),
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    if head is None or status is None:
        return _unavailable_git_state("git_probe_failed", expected_head=expected_head)
    normalized_head = head.strip().lower()
    if _HEAD_RE.fullmatch(normalized_head) is None:
        return _unavailable_git_state("invalid_head", expected_head=expected_head)
    return {
        "available": True,
        "head": normalized_head,
        "dirty": bool(status.strip()),
        "pin_status": _pin_status(normalized_head, expected_head),
        "expected_head": expected_head,
    }


def _unavailable_git_state(status: str, *, expected_head: str | None) -> dict[str, object]:
    return {
        "available": False,
        "head": None,
        "dirty": None,
        "pin_status": "unavailable",
        "expected_head": expected_head,
        "status": status,
    }


def _strix_runtime_status(  # noqa: PLR0913
    *,
    strix_repo_root: Path | None,
    executable: str | Path | None,
    expected_source_head: str | None,
    expected_executable_sha256: str | None,
    timeout_seconds: float,
    git_executable: str | Path = DEFAULT_GIT_EXECUTABLE,
    trusted_path: str = DEFAULT_TRUSTED_PATH,
) -> dict[str, object]:
    source_binding = _repository_binding_status(
        root=strix_repo_root,
        expected_head=expected_source_head,
        expected_origin_url=STRIX_CANONICAL_ORIGIN_URL,
        tracked_tree=None,
        required_location=None,
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    resolved_source_root = (
        strix_repo_root.expanduser().resolve(strict=False) if strix_repo_root is not None else None
    )
    source_present = bool(
        resolved_source_root is not None
        and (resolved_source_root / "pyproject.toml").is_file()
        and (resolved_source_root / "strix").is_dir()
    )
    resolved, source = _resolve_executable(executable)
    if resolved is None:
        return {
            "ready": False,
            "source_present": source_present,
            "executable_present": False,
            "dependency_probe_ok": False,
            "executable_source": source,
            "executable_sha256": None,
            "expected_executable_sha256": expected_executable_sha256,
            "identity_mode": "unresolved",
            "identity_verified": False,
            "source_relative_executable": None,
            "source_blob_object": None,
            "source_blob_algorithm": None,
            "source_binding": source_binding,
            "status": "executable_missing",
        }
    before_digest = _sha256_file(Path(resolved))
    source_executable = _tracked_executable_status(
        executable=Path(resolved),
        source_root=resolved_source_root,
        expected_head=expected_source_head,
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    binary_digest_match = bool(
        before_digest is not None
        and expected_executable_sha256 is not None
        and before_digest == expected_executable_sha256
    )
    source_identity_match = bool(
        source_binding["ready"] is True and source_executable["matches_pinned_blob"] is True
    )
    if source_identity_match:
        identity_mode = "pinned_source_blob"
    elif binary_digest_match:
        identity_mode = "binary_sha256"
    else:
        identity_mode = "unverified"
    with tempfile.TemporaryDirectory(prefix="ravage-preflight-strix-") as temporary:
        isolation_root = Path(temporary)
        home = isolation_root / "home"
        work = isolation_root / "work"
        for directory in (home, work):
            directory.mkdir(mode=0o700)
        environment = _minimal_probe_environment(
            trusted_path=trusted_path,
            home=home,
            temporary=isolation_root,
        )
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
            }
        )
        status, returncode = _run_bounded(
            (resolved, "--version"),
            cwd=work,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
    after_digest = _sha256_file(Path(resolved))
    stable_digest = before_digest is not None and before_digest == after_digest
    identity_verified = stable_digest and (source_identity_match or binary_digest_match)
    healthy = status == "completed" and returncode == 0
    ready = source_present and source_binding["ready"] is True and healthy and identity_verified
    return {
        "ready": ready,
        "source_present": source_present,
        "executable_present": True,
        "dependency_probe_ok": healthy,
        "executable_source": source,
        "executable_sha256": before_digest,
        "expected_executable_sha256": expected_executable_sha256,
        "identity_mode": identity_mode,
        "identity_verified": identity_verified,
        "source_relative_executable": source_executable["relative_path"],
        "source_blob_object": source_executable["blob_object"],
        "source_blob_algorithm": source_executable["blob_algorithm"],
        "source_binding": source_binding,
        "status": (
            "ready"
            if ready
            else (
                "source_missing"
                if not source_present
                else (
                    "source_unbound"
                    if source_binding["ready"] is not True
                    else ("identity_unverified" if healthy else status)
                )
            )
        ),
    }


def _repository_binding_status(  # noqa: C901, PLR0912, PLR0913,PLR0915
    *,
    root: Path | None,
    expected_head: str | None,
    expected_origin_url: str,
    tracked_tree: str | None,
    required_location: Path | None,
    git_executable: str | Path = DEFAULT_GIT_EXECUTABLE,
    trusted_path: str = DEFAULT_TRUSTED_PATH,
) -> dict[str, object]:
    """Bind a working tree to one canonical remote, commit, and Git tree object."""

    expected_origin_identity = _git_remote_identity(expected_origin_url)
    tree_path = tracked_tree or "."
    base: dict[str, object] = {
        "ready": False,
        "status": "root_unresolved",
        "repository_root_verified": False,
        "expected_head": expected_head,
        "expected_origin_url": expected_origin_url,
        "origin_url": None,
        "origin_matches_expected": False,
        "origin_observed_sha256": None,
        "tree_path": tree_path,
        "tree_object": None,
        "tree_object_algorithm": None,
        "tree_matches_worktree": False,
        "location_is_canonical": False,
    }
    if root is None:
        return base
    location = root.expanduser().resolve(strict=False)
    if not location.is_dir():
        return {**base, "status": "root_missing"}

    raw_toplevel = _run_git(
        location,
        ("rev-parse", "--show-toplevel"),
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    if raw_toplevel is None:
        return {**base, "status": "git_probe_failed"}
    try:
        actual_toplevel = Path(raw_toplevel.strip()).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return {**base, "status": "git_toplevel_invalid"}
    repository_root_verified = actual_toplevel == location

    canonical_location = (location / tree_path).resolve(strict=False)
    location_is_canonical = required_location is None or required_location == canonical_location
    raw_origin = _run_git(
        location,
        ("remote", "get-url", "origin"),
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    normalized_origin = raw_origin.strip() if raw_origin is not None else ""
    origin_digest = (
        "sha256:" + hashlib.sha256(normalized_origin.encode("utf-8")).hexdigest()
        if normalized_origin
        else None
    )
    origin_identity = _git_remote_identity(normalized_origin)
    origin_matches = bool(
        origin_identity is not None and origin_identity == expected_origin_identity
    )

    head = _run_git(
        location,
        ("rev-parse", "--verify", "HEAD"),
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    normalized_head = head.strip().lower() if head is not None else None
    head_matches = bool(expected_head is not None and normalized_head == expected_head)
    tree_spec = (
        f"{expected_head}:{tracked_tree}"
        if expected_head is not None and tracked_tree is not None
        else (f"{expected_head}^{{tree}}" if expected_head is not None else None)
    )
    tree_object: str | None = None
    tree_object_algorithm: str | None = None
    tree_is_tree = False
    if tree_spec is not None:
        raw_tree_object = _run_git(
            location,
            ("rev-parse", "--verify", tree_spec),
            git_executable=git_executable,
            trusted_path=trusted_path,
        )
        candidate = raw_tree_object.strip().lower() if raw_tree_object is not None else ""
        if _HEAD_RE.fullmatch(candidate) is not None:
            tree_object = candidate
            tree_object_algorithm = "sha1" if len(candidate) == _SHA1_HEX_LENGTH else "sha256"
            tree_type = _run_git(
                location,
                ("cat-file", "-t", candidate),
                git_executable=git_executable,
                trusted_path=trusted_path,
            )
            tree_is_tree = tree_type is not None and tree_type.strip() == "tree"

    status_args: tuple[str, ...] = (
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if tracked_tree is not None:
        status_args = (*status_args, "--", tracked_tree)
    subtree_status = _run_git(
        location,
        status_args,
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    tree_matches_worktree = bool(
        head_matches and tree_is_tree and subtree_status is not None and not subtree_status.strip()
    )

    ready = bool(
        repository_root_verified
        and location_is_canonical
        and origin_matches
        and tree_matches_worktree
    )
    if ready:
        status = "ready"
    elif not repository_root_verified:
        status = "repository_root_mismatch"
    elif not location_is_canonical:
        status = "noncanonical_tree_location"
    elif not origin_matches:
        status = "origin_mismatch"
    elif expected_head is None:
        status = "pin_unresolved"
    elif not head_matches:
        status = "head_mismatch"
    elif not tree_is_tree:
        status = "tracked_tree_missing"
    else:
        status = "worktree_mismatch"
    return {
        **base,
        "ready": ready,
        "status": status,
        "repository_root_verified": repository_root_verified,
        "origin_url": expected_origin_url if origin_matches else None,
        "origin_matches_expected": origin_matches,
        "origin_observed_sha256": origin_digest,
        "tree_object": tree_object,
        "tree_object_algorithm": tree_object_algorithm,
        "tree_matches_worktree": tree_matches_worktree,
        "location_is_canonical": location_is_canonical,
    }


def _tracked_executable_status(  # noqa: PLR0911
    *,
    executable: Path,
    source_root: Path | None,
    expected_head: str | None,
    git_executable: str | Path = DEFAULT_GIT_EXECUTABLE,
    trusted_path: str = DEFAULT_TRUSTED_PATH,
) -> dict[str, object]:
    result: dict[str, object] = {
        "matches_pinned_blob": False,
        "relative_path": None,
        "blob_object": None,
        "blob_algorithm": None,
    }
    if source_root is None or expected_head is None:
        return result
    try:
        resolved = executable.expanduser().resolve(strict=True)
        relative = resolved.relative_to(source_root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return result
    relative_path = relative.as_posix()
    if not relative_path or relative_path == ".":
        return result
    raw_entry = _run_git(
        source_root,
        ("ls-tree", expected_head, "--", relative_path),
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    if raw_entry is None:
        return {**result, "relative_path": relative_path}
    fields = raw_entry.rstrip("\n").partition("\t")
    metadata = fields[0].split()
    if fields[1] != "\t" or len(metadata) != _GIT_LS_TREE_METADATA_FIELDS or metadata[1] != "blob":
        return {**result, "relative_path": relative_path}
    blob_object = metadata[2].lower()
    if _HEAD_RE.fullmatch(blob_object) is None:
        return {**result, "relative_path": relative_path}
    actual_blob = _run_git(
        source_root,
        ("hash-object", "--no-filters", "--", str(resolved)),
        git_executable=git_executable,
        trusted_path=trusted_path,
    )
    normalized_actual = actual_blob.strip().lower() if actual_blob is not None else None
    return {
        "matches_pinned_blob": normalized_actual == blob_object,
        "relative_path": relative_path,
        "blob_object": blob_object,
        "blob_algorithm": ("sha1" if len(blob_object) == _SHA1_HEX_LENGTH else "sha256"),
    }


def _sha256_file(path: Path) -> str | None:
    try:
        resolved = path.expanduser().resolve(strict=True)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved, flags)
    except (OSError, RuntimeError):
        return None
    try:
        file_status = os.fstat(descriptor)
        if not S_ISREG(file_status.st_mode) or file_status.st_size > _MAX_EXECUTABLE_BYTES:
            return None
        digest = hashlib.sha256()
        remaining = _MAX_EXECUTABLE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                return "sha256:" + digest.hexdigest()
            digest.update(chunk)
            remaining -= len(chunk)
        return None
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _git_remote_identity(value: str) -> str | None:
    candidate = value.strip()
    if not candidate or len(candidate) > _MAX_GIT_REMOTE_LENGTH or "\n" in candidate:
        return None
    host: str | None
    path: str
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"https", "ssh"} or parsed.query or parsed.fragment:
            return None
        host = parsed.hostname
        path = parsed.path
    else:
        match = _SCP_GIT_URL_RE.fullmatch(candidate)
        if match is None:
            return None
        host, path = match.groups()
    normalized_path = path.strip("/")
    normalized_path = normalized_path.removesuffix(".git")
    if not host or not normalized_path or ".." in normalized_path.split("/"):
        return None
    return f"{host.casefold()}/{normalized_path.casefold()}"


def _provider_status(
    required_names: Sequence[str],
    environment: Mapping[str, str],
) -> dict[str, object]:
    presence = {name: bool(str(environment.get(name, "")).strip()) for name in required_names}
    missing = [name for name in required_names if not presence[name]]
    return {
        "ready": not missing,
        "required": [{"name": name, "present": presence[name]} for name in required_names],
        "missing": missing,
        "source": "process_environment_only",
        "dotenv_loaded": False,
    }


def _website_status(
    *,
    target: str | None,
    classification: str,
    required: bool,
) -> dict[str, object]:
    normalized = str(target or "").strip()
    configured = bool(normalized)
    resolved = configured and classification != "unresolved"
    return {
        "required": required,
        "configured": configured,
        "resolved": resolved,
        "classification": classification if configured else "unresolved",
        "reference_sha256": (
            "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            if configured
            else None
        ),
        "raw_reference_emitted": False,
    }


def _resolve_executable(value: str | Path | None) -> tuple[str | None, str]:
    if value is None:
        return None, "missing"
    resolved = _resolve_explicit_executable(value)
    return (str(resolved), "explicit") if resolved is not None else (None, "explicit_missing")


def _resolve_explicit_executable(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    try:
        path = Path(value).expanduser()
        if not path.is_absolute() or path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, TypeError):
        return None
    if resolved != path or not resolved.is_file() or not os.access(resolved, os.X_OK):
        return None
    return resolved


def _resolve_explicit_socket(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    try:
        path = Path(value).expanduser()
        if not path.is_absolute() or path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError, TypeError):
        return None
    if resolved != path or not S_ISSOCK(metadata.st_mode):
        return None
    return resolved


def _minimal_probe_environment(
    *,
    trusted_path: str,
    home: Path,
    temporary: Path,
) -> dict[str, str]:
    return {
        "PATH": trusted_path,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "TMPDIR": str(temporary),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "NO_COLOR": "1",
    }


def _run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> tuple[str, int | None]:
    try:
        process = subprocess.Popen(  # noqa: S603
            tuple(command),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return "probe_failed", None
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
    cleanup_ok = _terminate_probe_process_group(process)
    if not cleanup_ok:
        return "probe_failed", None
    if timed_out:
        return "timeout", None
    if process.returncode == 0:
        return "completed", 0
    return "probe_failed", int(process.returncode) if process.returncode is not None else None


def _run_git(
    root: Path,
    args: Sequence[str],
    *,
    git_executable: str | Path = DEFAULT_GIT_EXECUTABLE,
    trusted_path: str = DEFAULT_TRUSTED_PATH,
) -> str | None:
    git = _resolve_explicit_executable(git_executable)
    if git is None:
        return None
    environment = {
        "PATH": trusted_path,
        "HOME": "/nonexistent-paired-xben-home",
        "XDG_CONFIG_HOME": "/nonexistent-paired-xben-home/.config",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    command = (
        str(git),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "submodule.recurse=false",
        "-C",
        str(root),
        *args,
    )
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(  # noqa: S603
                command,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            timed_out = False
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                timed_out = True
            cleanup_ok = _terminate_probe_process_group(process)
            if timed_out or not cleanup_ok or process.returncode != 0:
                return None
            size = output.tell()
            if size > _MAX_GIT_OUTPUT_BYTES:
                return None
            output.seek(0)
            encoded = output.read()
    except OSError:
        return None
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _terminate_probe_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Kill descendants in the evaluator-created group and verify teardown."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        return False
    try:
        process.wait(timeout=_PROBE_CLEANUP_SECONDS)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        try:
            process.wait(timeout=_PROBE_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            return False
    deadline = time.monotonic() + _PROBE_CLEANUP_SECONDS
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.01)
    return False


def _nearest_git_root(path: Path) -> Path | None:
    candidate = path.expanduser().resolve(strict=False)
    if candidate.is_file():
        candidate = candidate.parent
    for location in (candidate, *candidate.parents):
        if (location / ".git").exists():
            return location
    return None


def _nearest_existing_path(path: Path) -> Path:
    candidate = path.expanduser().resolve(strict=False)
    for location in (candidate, *candidate.parents):
        if location.exists():
            return location
    return Path.cwd()


def _provider_env_names(values: Sequence[str]) -> tuple[str, ...]:
    names = tuple(dict.fromkeys(str(value).strip() for value in values))
    if not names:
        raise PreflightConfigurationError("at least one provider environment name is required")
    if len(names) > _MAX_PROVIDER_ENV_NAMES:
        raise PreflightConfigurationError(
            f"at most {_MAX_PROVIDER_ENV_NAMES} provider environment names are allowed"
        )
    if any(_ENV_NAME_RE.fullmatch(name) is None for name in names):
        raise PreflightConfigurationError(
            "provider environment names must be uppercase identifiers"
        )
    return names


def _trusted_probe_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TRUSTED_PATH_LENGTH
        or "\x00" in value
    ):
        raise PreflightConfigurationError("trusted_path must be a bounded explicit PATH")
    entries = value.split(os.pathsep)
    if not entries or len(entries) > _MAX_TRUSTED_PATH_ENTRIES:
        raise PreflightConfigurationError("trusted_path has an invalid entry count")
    for entry in entries:
        path = Path(entry)
        if not entry or not path.is_absolute() or not path.is_dir():
            raise PreflightConfigurationError(
                "trusted_path entries must be existing absolute directories"
            )
    return value


def _expected_head(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().lower()
    if _HEAD_RE.fullmatch(normalized) is None:
        raise PreflightConfigurationError("expected git heads must be hexadecimal commit ids")
    return normalized


def _expected_sha256(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    match = _SHA256_RE.fullmatch(value.strip())
    if match is None:
        raise PreflightConfigurationError(
            "expected Strix executable digest must be a SHA-256 digest"
        )
    return "sha256:" + match.group(1).lower()


def _pin_status(head: str, expected_head: str | None) -> str:
    if expected_head is None:
        return "unresolved"
    return "match" if head == expected_head else "mismatch"


def _website_classification(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    if normalized not in _WEBSITE_CLASSIFICATIONS:
        allowed = ", ".join(sorted(_WEBSITE_CLASSIFICATIONS))
        raise PreflightConfigurationError(f"website classification must be one of: {allowed}")
    return normalized


def _case_ids_digest(case_ids: Sequence[str]) -> str:
    encoded = json.dumps(
        sorted(case_ids),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if not isinstance(value, str) or len(value) > _MAX_TIMESTAMP_LENGTH:
        raise PreflightConfigurationError("captured_at must be a bounded ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PreflightConfigurationError(
            "captured_at must be a timezone-aware ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PreflightConfigurationError("captured_at must be a timezone-aware ISO-8601 timestamp")
    return parsed.isoformat()


def _validate_positive_int(name: str, value: int, *, allow_zero: bool = False) -> None:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise PreflightConfigurationError(f"{name} must be a {qualifier} integer")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Preflight a no-cheat paired XBEN campaign.")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--benchmarks-root", type=Path, required=True)
    parser.add_argument("--xben-repo-root", type=Path)
    parser.add_argument("--strix-repo-root", type=Path, required=True)
    parser.add_argument("--ravage-repo-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--trusted-path", default=DEFAULT_TRUSTED_PATH)
    parser.add_argument("--git-executable", type=Path, default=DEFAULT_GIT_EXECUTABLE)
    parser.add_argument("--docker-executable", type=Path)
    parser.add_argument("--docker-socket", type=Path)
    parser.add_argument("--strix-executable")
    parser.add_argument("--expected-strix-executable-sha256")
    parser.add_argument("--required-free-gib", type=int, default=DEFAULT_REQUIRED_FREE_GIB)
    parser.add_argument("--required-provider-env", action="append")
    parser.add_argument("--expected-ravage-head")
    parser.add_argument("--expected-strix-head")
    parser.add_argument("--expected-xben-head")
    parser.add_argument("--expected-xben-case-count", type=int, default=DEFAULT_XBEN_CASE_COUNT)
    parser.add_argument("--allow-dirty-sources", action="store_true")
    parser.add_argument("--no-require-website", action="store_true")
    parser.add_argument("--website-target")
    parser.add_argument(
        "--website-classification",
        choices=sorted(_WEBSITE_CLASSIFICATIONS),
        default="unresolved",
    )
    parser.add_argument(
        "--docker-timeout-seconds",
        type=float,
        default=DEFAULT_DOCKER_TIMEOUT_SECONDS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Write preflight evidence before returning readiness as an exit status."""

    args = _parser().parse_args(argv)
    provider_names = tuple(args.required_provider_env or DEFAULT_PROVIDER_ENV_NAMES)
    report = collect_preflight(
        evidence_dir=args.evidence_dir,
        benchmarks_root=args.benchmarks_root,
        xben_repo_root=args.xben_repo_root,
        strix_repo_root=args.strix_repo_root,
        ravage_repo_root=args.ravage_repo_root,
        trusted_path=args.trusted_path,
        git_executable=args.git_executable,
        docker_executable=args.docker_executable,
        docker_socket=args.docker_socket,
        strix_executable=args.strix_executable,
        expected_strix_executable_sha256=args.expected_strix_executable_sha256,
        required_free_gib=args.required_free_gib,
        required_provider_env=provider_names,
        expected_ravage_head=args.expected_ravage_head,
        expected_strix_head=args.expected_strix_head,
        expected_xben_head=args.expected_xben_head,
        expected_xben_case_count=args.expected_xben_case_count,
        require_clean_sources=not args.allow_dirty_sources,
        require_website_target=not args.no_require_website,
        website_target=args.website_target,
        website_classification=args.website_classification,
        docker_timeout_seconds=args.docker_timeout_seconds,
    )
    path = write_preflight(args.evidence_dir, report)
    state = "blocked" if report["blocked"] else "ready"
    sys.stdout.write(f"[paired-xben:preflight] {state} evidence={path}\n")
    return preflight_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
