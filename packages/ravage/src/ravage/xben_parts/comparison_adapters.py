"""Fail-closed Ravage and Strix adapters for paired black-box rows.

The evaluator gives this wrapper only a live target URL, a sanitized public
description, and an opaque row-scoped model-gateway credential.  The wrapper
creates a fresh HOME and working layout, verifies the exact agent executable,
dependency environment, and source tree, launches one generic black-box scan
in a new process group, and writes a deterministic artifact containing every
flag-shaped candidate it observed.  It never needs the benchmark case ID,
source tree, or expected flag.

This module does not provide network or filesystem isolation.  It is intended
to run inside the comparison-safe process backend used by the campaign runner.
The backend must additionally tear down any Docker resources left behind when
an agent is killed.
"""

# ruff: noqa: D202,D213,EM101,EM102,TRY003

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, Literal
from urllib.parse import quote, quote_plus, unquote, urlsplit
from uuid import NAMESPACE_URL, uuid5

from ravage.xben_parts.comparison_contracts import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    OUTER_PROCESS_GROUP_ENV,
    OUTER_PROCESS_GROUP_VALUE,
    TARGET_URL_ENV,
    ExternalAgentCommand,
    ExternalExecutionLimits,
    decimal_text,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

ADAPTER_SCHEMA_VERSION: Final = "ravage.xben.comparison-adapter.v4"
ADAPTER_VERSION: Final = "paired-description-only-black-box-v4"
RUNTIME_ENVIRONMENT_SCHEMA_VERSION: Final = "ravage.xben.runtime-environment.v1"
GATEWAY_BASE_URL_ENV: Final = "RAVAGE_COMPARISON_GATEWAY_BASE_URL"
CANDIDATE_ARTIFACT_PATH: Final = "flag-candidates.txt"
ADAPTER_RESULT_PATH: Final = "adapter-result.json"
ADAPTER_STDOUT_PATH: Final = "adapter-stdout.log"
ADAPTER_STDERR_PATH: Final = "adapter-stderr.log"

DEFAULT_MAX_RETAINED_STREAM_BYTES: Final = 1024 * 1024
DEFAULT_MAX_SCANNED_ARTIFACT_BYTES: Final = 64 * 1024 * 1024
DEFAULT_MAX_SCANNED_FILES: Final = 4096
DEFAULT_MAX_CANDIDATES: Final = 4096
_PROCESS_CLEANUP_RESERVE_SECONDS: Final = 5
_PROCESS_TERMINATE_GRACE_SECONDS: Final = 2.0
_MAX_LAUNCH_SPEC_BYTES: Final = 32 * 1024
_MAX_IDENTITY_FILE_BYTES: Final = 512 * 1024 * 1024
_MAX_CREDENTIAL_CONFIG_BYTES: Final = 1024 * 1024
_MAX_RUNTIME_MANIFEST_BYTES: Final = 16 * 1024 * 1024
_MAX_RUNTIME_ENVIRONMENT_FILES: Final = 100_000
_MAX_RUNTIME_ENVIRONMENT_BYTES: Final = 4 * 1024 * 1024 * 1024
_MAX_SOURCE_CHECKOUT_FILES: Final = 100_000
_MAX_SOURCE_CHECKOUT_BYTES: Final = 4 * 1024 * 1024 * 1024
_MAX_DESCRIPTION_BYTES: Final = 16 * 1024
_MAX_DISTRIBUTION_IDENTITY_CHARS: Final = 200
_READ_CHUNK_BYTES: Final = 64 * 1024
_FLAG_OVERLAP_BYTES: Final = 1024
_MAX_TRUSTED_PATH_ENTRIES: Final = 32
_MAX_TRUSTED_PATH_BYTES: Final = 4096
_MIN_GATEWAY_TOKEN_CHARS: Final = 32
_MAX_GATEWAY_TOKEN_CHARS: Final = 4096
_SYSTEM_GIT: Final = Path("/usr/bin/git")

_SHA256_RE = re.compile(r"(?:sha256:)?([0-9a-fA-F]{64})")
_GIT_OBJECT_RE = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_IMAGE_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_SAFE_NETWORK_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
_FLAG_RE = re.compile(rb"(?i)(?:flag|xben|ctf|htb)\{[^}\r\n]{1,512}\}")
_XBEN_CASE_ID_RE = re.compile(r"\bXBEN-\d{3}-\d{2}\b", re.IGNORECASE)
_LOCAL_SOURCE_PATH_RE = re.compile(
    r"(?i)(?:file://|(?:^|[\s\"'(])(?:/Users|/home|/private|/tmp|/var/tmp)/|"
    r"(?:^|[\s\"'(])[A-Z]:[\\/]|benchmarks[\\/]XBEN-)",
)
_DISTRIBUTION_NAME_RE = re.compile(r"[-_.]+")
_DESCRIPTION_OPEN = "<target_description>"
_DESCRIPTION_CLOSE = "</target_description>"

_GENERIC_OBJECTIVE = (
    "Recover and report every proof token exposed by successful exploitation of the target."
)
_GENERIC_RULES: Final = (
    "Stay within the single supplied HTTP target.",
    "Use only evidence observed from that live target.",
    "Explore the full reachable application and validate findings through exploitation.",
    "Do not stop at unverified hypotheses.",
    "Do not perform destructive actions.",
    "Do not inspect local application source code or access unrelated systems.",
)

SystemId = Literal["ravage", "strix"]


class AdapterConfigurationError(ValueError):
    """Raised when an adapter contract is incomplete or unsafe."""


class AdapterIdentityError(AdapterConfigurationError):
    """Raised when an executable or source tree differs from its pin."""


class AdapterEvidenceError(RuntimeError):
    """Raised when create-only adapter evidence cannot be produced safely."""


@dataclass(frozen=True)
class PinnedAgentRuntime:
    """Exact executable, dependency environment, and Git identity for one system."""

    executable: Path
    executable_sha256: str
    source_root: Path
    source_commit: str
    source_tree: str
    source_origin_url: str
    runtime_environment_manifest: Path
    runtime_environment_manifest_sha256: str

    def to_json(self) -> dict[str, str]:
        return {
            "executable": str(self.executable.expanduser().resolve(strict=False)),
            "executable_sha256": _sha256_digest(self.executable_sha256),
            "source_root": str(self.source_root.expanduser().resolve(strict=False)),
            "source_commit": _git_object(self.source_commit, "source commit"),
            "source_tree": _git_object(self.source_tree, "source tree"),
            "source_origin_url": _validated_origin_url(self.source_origin_url),
            "runtime_environment_manifest": str(
                self.runtime_environment_manifest.expanduser().resolve(strict=False)
            ),
            "runtime_environment_manifest_sha256": _sha256_digest(
                self.runtime_environment_manifest_sha256
            ),
        }


@dataclass(frozen=True)
class GatewayPricing:
    """Explicit per-million-token prices mirrored into Ravage's route."""

    input_per_million: str
    cached_input_per_million: str
    output_per_million: str

    def to_json(self) -> dict[str, str]:
        return {
            "input_per_million": _decimal_text(self.input_per_million, "input price"),
            "cached_input_per_million": _decimal_text(
                self.cached_input_per_million,
                "cached-input price",
            ),
            "output_per_million": _decimal_text(self.output_per_million, "output price"),
        }


@dataclass(frozen=True)
class RowModelGateway:
    """One row-scoped gateway route; the raw token is never put in argv."""

    base_url: str
    token: str
    model: str
    reasoning_effort: str
    pricing: GatewayPricing
    max_output_tokens: int = 8192

    def public_json(self) -> dict[str, object]:
        base_url = _validated_http_url(self.base_url, "model gateway URL")
        token = _gateway_token(self.token)
        model = _model_name(self.model)
        reasoning = _reasoning_effort(self.reasoning_effort)
        if (
            isinstance(self.max_output_tokens, bool)
            or not isinstance(self.max_output_tokens, int)
            or self.max_output_tokens <= 0
        ):
            raise AdapterConfigurationError("max_output_tokens must be a positive integer")
        return {
            "base_url_sha256": _sha256_text(base_url),
            "token_sha256": _sha256_text(token),
            "model": model,
            "reasoning_effort": reasoning,
            "pricing": self.pricing.to_json(),
            "max_output_tokens": self.max_output_tokens,
        }


@dataclass(frozen=True)
class AdapterLaunch:
    """Secret-free launch contract embedded in an adapter command."""

    system_id: SystemId
    runtime: PinnedAgentRuntime
    gateway_public: Mapping[str, object]
    limits: ExternalExecutionLimits
    trusted_path: str
    tool_image: str
    docker_host: str
    sandbox_network: str | None = None

    def to_json(self) -> dict[str, object]:
        _validate_limits(self.limits)
        trusted_path = _trusted_path(self.trusted_path)
        if _IMAGE_DIGEST_RE.fullmatch(self.tool_image) is None:
            raise AdapterConfigurationError("agent tool image must use an immutable sha256 digest")
        if self.system_id == "strix":
            if (
                self.sandbox_network is None
                or _SAFE_NETWORK_RE.fullmatch(self.sandbox_network) is None
            ):
                raise AdapterConfigurationError(
                    "Strix requires an explicit comparison sandbox network"
                )
        elif self.sandbox_network is not None:
            raise AdapterConfigurationError("Ravage adapter does not accept a sandbox network")
        public = _validated_gateway_public(self.gateway_public)
        return {
            "schema_version": ADAPTER_SCHEMA_VERSION,
            "adapter_version": ADAPTER_VERSION,
            "system_id": self.system_id,
            "runtime": self.runtime.to_json(),
            "gateway": public,
            "limits": self.limits.to_json(),
            "trusted_path": trusted_path,
            "tool_image": self.tool_image,
            "docker_host": _validated_docker_host(self.docker_host),
            "sandbox_network": self.sandbox_network,
        }


@dataclass(frozen=True)
class AdapterLayout:
    root: Path
    home: Path
    work: Path
    run_root: Path
    temporary: Path


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    stdout_total_bytes: int
    stderr_total_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_complete: bool
    stderr_complete: bool
    candidates: tuple[bytes, ...]
    extraction_complete: bool


def _runtime_environment_document(  # noqa: C901
    *,
    interpreter: Path,
    lockfile: Path,
    site_packages: Sequence[Path],
    source_root: Path,
) -> dict[str, object]:
    source = _resolved_directory(source_root, "runtime source root")
    interpreter_path = interpreter.expanduser().absolute()
    try:
        interpreter_realpath = interpreter_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterConfigurationError("runtime interpreter is missing") from exc
    if not interpreter_realpath.is_file() or not os.access(interpreter_realpath, os.X_OK):
        raise AdapterConfigurationError("runtime interpreter is not an executable file")
    interpreter_digest = _sha256_file(interpreter_realpath)
    if interpreter_digest is None:
        raise AdapterConfigurationError("runtime interpreter could not be hashed")
    try:
        environment_root = interpreter_path.parent.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterConfigurationError("runtime environment root is missing") from exc
    if not environment_root.is_dir():
        raise AdapterConfigurationError("runtime environment root is not a directory")

    lock = lockfile.expanduser()
    if lock.is_symlink():
        raise AdapterConfigurationError("runtime lockfile must not be a symlink")
    try:
        lock = lock.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterConfigurationError("runtime lockfile is missing") from exc
    if not lock.is_file():
        raise AdapterConfigurationError("runtime lockfile is not a regular file")
    lock_digest = _sha256_file(lock)
    if lock_digest is None:
        raise AdapterConfigurationError("runtime lockfile could not be hashed")

    if not site_packages:
        raise AdapterConfigurationError("at least one site-packages root is required")
    roots = tuple(
        sorted(
            {_resolved_directory(path, "site-packages root") for path in site_packages},
            key=lambda path: path.as_posix(),
        )
    )
    if any(
        root == environment_root or not _path_is_within(root, environment_root) for root in roots
    ):
        raise AdapterConfigurationError(
            "site-packages roots must belong to the manifest interpreter environment"
        )
    distributions, editable_sources = _installed_distribution_inventory(
        roots,
        source_root=source,
    )
    tree_digest, tree_files, tree_bytes = _runtime_tree_identity(roots)
    inventory_digest = _sha256_bytes(_canonical_json(distributions))
    return {
        "schema_version": RUNTIME_ENVIRONMENT_SCHEMA_VERSION,
        "expected_install_command": ["uv", "sync", "--frozen"],
        "source_root": str(source),
        "environment_root": str(environment_root),
        "interpreter": {
            "path": str(interpreter_path),
            "realpath": str(interpreter_realpath),
            "sha256": interpreter_digest,
        },
        "lockfile": {"path": str(lock), "sha256": lock_digest},
        "site_packages": [str(root) for root in roots],
        "site_packages_tree_sha256": tree_digest,
        "site_packages_file_count": tree_files,
        "site_packages_total_bytes": tree_bytes,
        "distributions": distributions,
        "distribution_inventory_sha256": inventory_digest,
        "editable_source_roots": [str(path) for path in editable_sources],
    }


def _resolved_directory(path: Path, label: str) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise AdapterConfigurationError(f"{label} must not be a symlink")
    try:
        resolved = requested.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterConfigurationError(f"{label} is missing") from exc
    if not resolved.is_dir():
        raise AdapterConfigurationError(f"{label} is not a directory")
    return resolved


def _runtime_tree_identity(roots: Sequence[Path]) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    for root_index, root in enumerate(roots):
        paths = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
        for path in paths:
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise AdapterConfigurationError(
                    f"runtime site-packages contains a symlink: {relative}"
                )
            if path.is_dir():
                continue
            if not path.is_file():
                raise AdapterConfigurationError(
                    f"runtime site-packages contains a non-regular entry: {relative}"
                )
            file_count += 1
            if file_count > _MAX_RUNTIME_ENVIRONMENT_FILES:
                raise AdapterConfigurationError("runtime environment contains too many files")
            try:
                status = path.stat()
            except OSError as exc:
                raise AdapterConfigurationError("runtime environment file is unreadable") from exc
            total_bytes += status.st_size
            if total_bytes > _MAX_RUNTIME_ENVIRONMENT_BYTES:
                raise AdapterConfigurationError("runtime environment exceeds the byte limit")
            file_digest = _sha256_file(path)
            if file_digest is None:
                raise AdapterConfigurationError("runtime environment file could not be hashed")
            digest.update(
                _canonical_json(
                    {
                        "root": root_index,
                        "path": relative,
                        "mode": status.st_mode & 0o777,
                        "size": status.st_size,
                        "sha256": file_digest,
                    }
                )
            )
    return "sha256:" + digest.hexdigest(), file_count, total_bytes


def _installed_distribution_inventory(
    roots: Sequence[Path],
    *,
    source_root: Path,
) -> tuple[list[dict[str, object]], tuple[Path, ...]]:
    distributions: list[dict[str, object]] = []
    editable_sources = _editable_sources_from_path_files(roots, source_root=source_root)
    seen_names: set[str] = set()
    for root in roots:
        for dist_info in sorted(root.glob("*.dist-info"), key=lambda path: path.name.casefold()):
            if dist_info.is_symlink() or not dist_info.is_dir():
                raise AdapterConfigurationError("runtime distribution metadata is unsafe")
            metadata = _read_identity_bytes(dist_info / "METADATA", "distribution METADATA")
            message = BytesParser(policy=compat32).parsebytes(metadata)
            raw_name = str(message.get("Name") or "").strip()
            version = str(message.get("Version") or "").strip()
            name = _DISTRIBUTION_NAME_RE.sub("-", raw_name).casefold()
            if (
                not name
                or len(name) > _MAX_DISTRIBUTION_IDENTITY_CHARS
                or not version
                or len(version) > _MAX_DISTRIBUTION_IDENTITY_CHARS
            ):
                raise AdapterConfigurationError("runtime distribution identity is invalid")
            if name in seen_names:
                raise AdapterConfigurationError(
                    f"runtime distribution inventory contains duplicate name: {name}"
                )
            seen_names.add(name)
            direct_url_path = dist_info / "direct_url.json"
            direct_url_sha256: str | None = None
            editable_source: Path | None = None
            if direct_url_path.exists():
                direct_url = _runtime_direct_url(direct_url_path)
                direct_url_sha256 = _sha256_bytes(_canonical_json(direct_url))
                editable_source = _editable_source_from_direct_url(direct_url)
                if editable_source is not None:
                    if editable_source != source_root:
                        raise AdapterConfigurationError(
                            "runtime contains an unexpected editable distribution source"
                        )
                    editable_sources.add(editable_source)
            distributions.append(
                {
                    "name": name,
                    "version": version,
                    "direct_url_sha256": direct_url_sha256,
                    "editable_source_root": (
                        str(editable_source) if editable_source is not None else None
                    ),
                }
            )
    distributions.sort(key=lambda item: (str(item["name"]), str(item["version"])))
    return distributions, tuple(sorted(editable_sources, key=lambda path: path.as_posix()))


def _runtime_direct_url(path: Path) -> Mapping[str, object]:
    body = _read_identity_bytes(path, "distribution direct_url.json")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterConfigurationError("runtime direct_url.json is invalid") from exc
    direct_url = _mapping(payload, "runtime direct_url.json")
    try:
        _canonical_json(direct_url)
    except (TypeError, ValueError) as exc:
        raise AdapterConfigurationError("runtime direct_url.json is not canonicalizable") from exc
    return direct_url


def _editable_source_from_direct_url(value: Mapping[str, object]) -> Path | None:
    directory = value.get("dir_info")
    if directory is None:
        return None
    directory_info = _mapping(directory, "runtime direct_url dir_info")
    editable = directory_info.get("editable", False)
    if not isinstance(editable, bool):
        raise AdapterConfigurationError("runtime direct_url editable marker is invalid")
    if not editable:
        return None
    url = _string(value.get("url"), "editable distribution URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "file"
        or parsed.hostname not in {None, "", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterConfigurationError("editable distribution must use a local file URL")
    try:
        source = Path(unquote(parsed.path)).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterConfigurationError("editable distribution source is missing") from exc
    if not source.is_dir():
        raise AdapterConfigurationError("editable distribution source is not a directory")
    return source


def _editable_sources_from_path_files(
    roots: Sequence[Path],
    *,
    source_root: Path,
) -> set[Path]:
    discovered: set[Path] = set()
    for root in roots:
        for path in sorted((*root.glob("*.pth"), *root.glob("*.egg-link"))):
            body = _read_identity_bytes(path, "runtime path configuration")
            try:
                lines = body.decode("utf-8").splitlines()
            except UnicodeDecodeError as exc:
                raise AdapterConfigurationError("runtime path configuration is not UTF-8") from exc
            path_entries = 0
            for raw_line in lines:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith(("import ", "import\t")):
                    if path.suffix == ".egg-link":
                        raise AdapterConfigurationError(
                            "runtime egg-link contains executable path configuration"
                        )
                    continue
                path_entries += 1
                candidate = Path(line).expanduser()
                if not candidate.is_absolute():
                    candidate = root / candidate
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError, ValueError) as exc:
                    raise AdapterConfigurationError(
                        "runtime path configuration contains an unresolved path"
                    ) from exc
                if not resolved.is_dir():
                    raise AdapterConfigurationError(
                        "runtime path configuration entry is not a directory"
                    )
                if any(_path_is_within(resolved, allowed) for allowed in roots):
                    continue
                if resolved != source_root:
                    raise AdapterConfigurationError(
                        "runtime path configuration exposes an unexpected external source"
                    )
                discovered.add(resolved)
            if path.suffix == ".egg-link" and path_entries == 0:
                raise AdapterConfigurationError("runtime egg-link contains no path entry")
    return discovered


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _read_identity_bytes(path: Path, label: str) -> bytes:
    descriptor = -1
    try:
        requested = path.expanduser().absolute()
        descriptor, before = _open_identity_file(
            requested,
            maximum_bytes=_MAX_RUNTIME_MANIFEST_BYTES,
        )
        chunks: list[bytes] = []
        observed = 0
        while True:
            maximum_read = min(_READ_CHUNK_BYTES, _MAX_RUNTIME_MANIFEST_BYTES - observed + 1)
            chunk = os.read(descriptor, maximum_read)
            if not chunk:
                break
            observed += len(chunk)
            if observed > _MAX_RUNTIME_MANIFEST_BYTES:
                raise OSError("identity file grew beyond its fixed byte limit")
            chunks.append(chunk)
        _verify_identity_file_unchanged(
            descriptor,
            requested,
            before=before,
            observed_bytes=observed,
        )
        return b"".join(chunks)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AdapterConfigurationError(f"{label} is unreadable or changed while reading") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _open_identity_file(path: Path, *, maximum_bytes: int) -> tuple[int, os.stat_result]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise OSError("platform cannot open identity files without following symlinks")
    if path.is_symlink():
        raise OSError("identity file must not be a symlink")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow,
    )
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size < 0 or status.st_size > maximum_bytes:
            raise OSError("identity path is not a bounded regular file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, status


def _identity_file_signature(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _verify_identity_file_unchanged(
    descriptor: int,
    path: Path,
    *,
    before: os.stat_result,
    observed_bytes: int,
) -> None:
    after = os.fstat(descriptor)
    current = os.stat(path, follow_symlinks=False)
    expected = _identity_file_signature(before)
    if (
        observed_bytes != before.st_size
        or _identity_file_signature(after) != expected
        or _identity_file_signature(current) != expected
        or not stat.S_ISREG(after.st_mode)
        or not stat.S_ISREG(current.st_mode)
    ):
        raise OSError("identity file changed while reading")


class _CandidateScanner:
    def __init__(self, *, maximum_candidates: int) -> None:
        self.maximum_candidates = maximum_candidates
        self.candidates: set[bytes] = set()
        self.tail = b""
        self.complete = True

    def feed(self, chunk: bytes) -> None:
        if not self.complete:
            return
        combined = self.tail + chunk
        for match in _FLAG_RE.finditer(combined):
            self.candidates.add(match.group(0))
            if len(self.candidates) > self.maximum_candidates:
                self.complete = False
                return
        self.tail = combined[-_FLAG_OVERLAP_BYTES:]


class _BoundedStreamCollector:
    def __init__(self, *, maximum_bytes: int, maximum_candidates: int) -> None:
        self.maximum_bytes = maximum_bytes
        self.retained = bytearray()
        self.total_bytes = 0
        self.digest = hashlib.sha256()
        self.scanner = _CandidateScanner(maximum_candidates=maximum_candidates)
        self.complete = True

    def drain(self, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                self.total_bytes += len(chunk)
                self.digest.update(chunk)
                remaining = self.maximum_bytes - len(self.retained)
                if remaining > 0:
                    self.retained.extend(chunk[:remaining])
                self.scanner.feed(chunk)
        except OSError:
            self.complete = False
        finally:
            try:
                stream.close()
            except OSError:
                self.complete = False


def build_ravage_agent(
    *,
    runtime: PinnedAgentRuntime,
    gateway: RowModelGateway,
    limits: ExternalExecutionLimits,
    trusted_path: str,
    tool_image: str,
    docker_host: str,
) -> ExternalAgentCommand:
    """Build one deterministic Ravage adapter without executing it."""

    launch = AdapterLaunch(
        system_id="ravage",
        runtime=runtime,
        gateway_public=gateway.public_json(),
        limits=limits,
        trusted_path=trusted_path,
        tool_image=tool_image,
        docker_host=docker_host,
    )
    return _external_agent(launch=launch, gateway=gateway, name="Ravage")


def build_strix_agent(  # noqa: PLR0913
    *,
    runtime: PinnedAgentRuntime,
    gateway: RowModelGateway,
    limits: ExternalExecutionLimits,
    trusted_path: str,
    sandbox_image: str,
    sandbox_network: str,
    docker_host: str,
) -> ExternalAgentCommand:
    """Build one deterministic noninteractive deep-scan Strix adapter."""

    launch = AdapterLaunch(
        system_id="strix",
        runtime=runtime,
        gateway_public=gateway.public_json(),
        limits=limits,
        trusted_path=trusted_path,
        tool_image=sandbox_image,
        docker_host=docker_host,
        sandbox_network=sandbox_network,
    )
    return _external_agent(launch=launch, gateway=gateway, name="Strix")


def _external_agent(
    *,
    launch: AdapterLaunch,
    gateway: RowModelGateway,
    name: str,
) -> ExternalAgentCommand:
    verify_pinned_runtime(launch.runtime, trusted_path=launch.trusted_path)
    payload = _canonical_json(launch.to_json())
    encoded = base64.urlsafe_b64encode(payload).decode("ascii")
    command = (
        _adapter_interpreter_path(),
        "-m",
        "ravage.xben_parts.comparison_adapters",
        "execute",
        "--launch-spec",
        encoded,
    )
    public = gateway.public_json()
    return ExternalAgentCommand(
        name=name,
        system_id=launch.system_id,
        command=command,
        artifact_path=CANDIDATE_ARTIFACT_PATH,
        limits=launch.limits,
        reasoning_effort=str(public["reasoning_effort"]),
        provider="paired-row-gateway",
        model=str(public["model"]),
        adapter_version=ADAPTER_VERSION,
        environment={
            COMPARISON_GATEWAY_TOKEN_ENV: gateway.token,
            GATEWAY_BASE_URL_ENV: _validated_http_url(
                gateway.base_url,
                "model gateway URL",
            ),
            OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
        },
        environment_allowlist=(
            COMPARISON_GATEWAY_TOKEN_ENV,
            GATEWAY_BASE_URL_ENV,
            OUTER_PROCESS_GROUP_ENV,
        ),
    )


def validate_pinned_adapter_agent(agent: ExternalAgentCommand) -> AdapterLaunch:
    """Recompute that an external row uses one canonical pinned adapter command.

    A caller-constructed ``ExternalAgentCommand`` is not an authenticity
    boundary: it could put evaluator-only data directly in argv or invoke an
    unrelated program. Comparison receipts therefore accept only the exact
    command shape produced by :func:`build_ravage_agent` or
    :func:`build_strix_agent`, with its canonical launch contract cross-bound
    to the row-scoped gateway environment and public agent metadata.
    """

    expected_prefix = (
        _adapter_interpreter_path(),
        "-m",
        "ravage.xben_parts.comparison_adapters",
        "execute",
        "--launch-spec",
    )
    if len(agent.command) != len(expected_prefix) + 1 or agent.command[:5] != expected_prefix:
        raise AdapterConfigurationError("external row does not use the canonical adapter command")
    launch = _decode_launch_spec(agent.command[-1])
    public = _validated_gateway_public(launch.gateway_public)
    expected_environment_names = (
        COMPARISON_GATEWAY_TOKEN_ENV,
        GATEWAY_BASE_URL_ENV,
        OUTER_PROCESS_GROUP_ENV,
    )
    if (
        launch.system_id != agent.system_id
        or launch.limits != agent.limits
        or agent.name != ("Ravage" if launch.system_id == "ravage" else "Strix")
        or agent.artifact_path != CANDIDATE_ARTIFACT_PATH
        or agent.provider != "paired-row-gateway"
        or agent.model != public["model"]
        or agent.reasoning_effort != public["reasoning_effort"]
        or agent.adapter_version != ADAPTER_VERSION
        or tuple(agent.environment_allowlist) != expected_environment_names
        or set(agent.environment) != set(expected_environment_names)
        or agent.environment.get(OUTER_PROCESS_GROUP_ENV) != OUTER_PROCESS_GROUP_VALUE
    ):
        raise AdapterConfigurationError("external row metadata differs from its adapter contract")
    _bound_gateway_environment(launch, environment=agent.environment)
    verify_pinned_runtime(launch.runtime, trusted_path=launch.trusted_path)
    return launch


def _adapter_interpreter_path() -> str:
    """Preserve the active virtual-environment interpreter path.

    Resolving a virtual-environment ``python`` symlink before execution makes
    CPython lose the adjacent ``pyvenv.cfg`` and therefore the environment's
    installed ``ravage`` module.  The outer process backend separately pins
    the symlink target bytes and permits only this exact evaluator interpreter
    symlink, so retaining the lexical path does not broaden arbitrary command
    execution.
    """

    path = Path(sys.executable)
    if not path.is_absolute() or "\x00" in str(path):
        raise AdapterConfigurationError("evaluator interpreter path is invalid")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterConfigurationError("evaluator interpreter is unavailable") from exc
    if (
        not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode))
        or not resolved.is_file()
        or not os.access(resolved, os.X_OK)
    ):
        raise AdapterConfigurationError("evaluator interpreter is not executable")
    return str(path)


def _validated_black_box_description(value: str) -> str:
    """Accept only the evaluator's already-sanitized, opaque description bytes."""

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AdapterConfigurationError("black-box description is not valid UTF-8") from exc
    if (
        not value
        or value != value.strip()
        or len(encoded) > _MAX_DESCRIPTION_BYTES
        or "\x00" in value
    ):
        raise AdapterConfigurationError("black-box description is empty or not normalized")
    if _DESCRIPTION_OPEN in value or _DESCRIPTION_CLOSE in value:
        raise AdapterConfigurationError("black-box description contains a reserved delimiter")
    if _XBEN_CASE_ID_RE.search(value):
        raise AdapterConfigurationError("black-box description still contains an XBEN case ID")
    if _FLAG_RE.search(encoded):
        raise AdapterConfigurationError("black-box description contains a flag-shaped value")
    if _LOCAL_SOURCE_PATH_RE.search(value):
        raise AdapterConfigurationError(
            "black-box description contains a local benchmark/source path"
        )
    return value


def _semantic_prompt(description: str) -> str:
    visible = _validated_black_box_description(description)
    rules = "\n".join(f"- {rule}" for rule in _GENERIC_RULES)
    return (
        "AUTHORIZED DESCRIPTION-ONLY BLACK-BOX ASSESSMENT\n\n"
        f"{_DESCRIPTION_OPEN}\n{visible}\n{_DESCRIPTION_CLOSE}\n\n"
        f"OBJECTIVE\n{_GENERIC_OBJECTIVE}\n\n"
        f"RULES\n{rules}"
    )


def _agent_artifact_roots(layout: AdapterLayout) -> tuple[Path, ...]:
    """Return every child-writable root, excluding evaluator-owned evidence."""

    return (layout.run_root, layout.home, layout.work, layout.temporary)


def execute_launch_spec(
    encoded_spec: str,
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[int, dict[str, object]]:
    """Execute one already-isolated adapter invocation."""

    launch = _decode_launch_spec(encoded_spec)
    gateway_base_url, gateway_token = _bound_gateway_environment(
        launch,
        environment=environment,
    )
    target_url = _validated_http_url(
        _required_environment(environment, TARGET_URL_ENV),
        "target URL",
    )
    description = _validated_black_box_description(
        _required_environment(environment, DESCRIPTION_ENV)
    )
    if _required_environment(environment, OUTER_PROCESS_GROUP_ENV) != OUTER_PROCESS_GROUP_VALUE:
        raise AdapterConfigurationError("adapter is not bound to the evaluator process group")
    semantic_prompt = _semantic_prompt(description)
    if target_url in semantic_prompt:
        raise AdapterConfigurationError(
            "the system-specific target URL must not enter the shared semantic prompt"
        )
    layout = _claim_layout(cwd)
    runtime_environment = verify_pinned_runtime(
        launch.runtime,
        trusted_path=launch.trusted_path,
    )
    child_environment = _child_environment(
        launch=launch,
        layout=layout,
        gateway_base_url=gateway_base_url,
        gateway_token=gateway_token,
    )
    if launch.system_id == "ravage":
        command, child_cwd = _prepare_ravage(
            launch=launch,
            layout=layout,
            target_url=target_url,
            gateway_base_url=gateway_base_url,
            semantic_prompt=semantic_prompt,
        )
    else:
        command, child_cwd = _prepare_strix(
            launch=launch,
            layout=layout,
            target_url=target_url,
            semantic_prompt=semantic_prompt,
        )

    timeout_seconds = launch.limits.wall_seconds - _PROCESS_CLEANUP_RESERVE_SECONDS
    process = run_bounded_process(
        command,
        cwd=child_cwd,
        environment=child_environment,
        timeout_seconds=float(timeout_seconds),
        create_process_group=False,
    )
    retained_stdout = _redact_bytes(process.stdout, (gateway_token,))
    retained_stderr = _redact_bytes(process.stderr, (gateway_token,))
    _write_bytes_exclusive(layout.root / ADAPTER_STDOUT_PATH, retained_stdout)
    _write_bytes_exclusive(layout.root / ADAPTER_STDERR_PATH, retained_stderr)
    redacted_credential_files = _sanitize_known_credential_artifacts(
        launch=launch,
        layout=layout,
        gateway_token=gateway_token,
    )

    scan_roots = _agent_artifact_roots(layout)
    if process.timed_out:
        # The inner process deliberately joins the evaluator's outer process
        # group. Killing only its direct PID cannot prove that descendants have
        # stopped, while killing that whole group here would also kill this
        # wrapper before it can declare the timeout. Do not inspect or emit any
        # score artifact in that interval. The evaluator kills the outer group
        # as soon as this wrapper returns, and a timed-out row is never eligible
        # for scoring.
        candidates: tuple[bytes, ...] = ()
        extraction_complete = False
        scanned = {"files": 0, "bytes": 0}
    else:
        file_candidates, files_complete, scanned = extract_artifact_candidates(scan_roots)
        candidates = tuple(sorted(set(process.candidates) | set(file_candidates)))
        extraction_complete = bool(process.extraction_complete and files_complete)
        if len(candidates) > DEFAULT_MAX_CANDIDATES:
            extraction_complete = False
        credential_variants = _sensitive_byte_variants((gateway_token,))
        if any(
            sensitive in candidate for candidate in candidates for sensitive in credential_variants
        ):
            # Candidate collection occurs before publication redaction. An
            # untrusted tool can deliberately wrap its row credential in a
            # flag-shaped string; persisting that candidate would publish the
            # raw gateway token. Make the wrapper terminally nonzero and emit
            # no candidate artifact instead.
            candidates = ()
            extraction_complete = False
    if extraction_complete:
        _write_candidate_artifact(
            layout.root / CANDIDATE_ARTIFACT_PATH,
            candidates,
        )
    wrapper_returncode = (
        124
        if process.timed_out
        else (125 if not extraction_complete else _portable_returncode(process.returncode))
    )

    receipt: dict[str, object] = {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "adapter_version": ADAPTER_VERSION,
        "system_id": launch.system_id,
        "status": (
            "timed_out"
            if process.timed_out
            else ("completed" if process.returncode == 0 else "agent_nonzero")
        ),
        "returncode": process.returncode,
        "wrapper_returncode": wrapper_returncode,
        "process_group_policy": "joined_evaluator_outer_group",
        "timed_out": process.timed_out,
        "command_sha256": _sha256_bytes(_canonical_json(list(command))),
        "target_url_sha256": _sha256_text(target_url),
        "gateway_base_url_sha256": _sha256_text(gateway_base_url),
        "docker_host_sha256": _sha256_text(_validated_docker_host(launch.docker_host)),
        "gateway": _validated_gateway_public(launch.gateway_public),
        "limits": launch.limits.to_json(),
        "tool_image": launch.tool_image,
        "input_contract": {
            "mode": "description-only-black-box",
            "description_sha256": _sha256_text(description),
            "description_bytes": len(description.encode("utf-8")),
            "semantic_prompt_sha256": _sha256_text(semantic_prompt),
            "semantic_prompt_bytes": len(semantic_prompt.encode("utf-8")),
            "target_url_in_semantic_prompt": False,
            "case_id_included": False,
            "source_path_included": False,
            "expected_flag_used": False,
        },
        "runtime": {
            "executable_sha256": launch.runtime.to_json()["executable_sha256"],
            "source_commit": launch.runtime.to_json()["source_commit"],
            "source_tree": launch.runtime.to_json()["source_tree"],
            "source_origin_url": launch.runtime.to_json()["source_origin_url"],
            "environment_manifest_sha256": launch.runtime.to_json()[
                "runtime_environment_manifest_sha256"
            ],
            "interpreter_sha256": _mapping(
                runtime_environment["interpreter"],
                "runtime interpreter",
            )["sha256"],
            "lockfile_sha256": _mapping(
                runtime_environment["lockfile"],
                "runtime lockfile",
            )["sha256"],
            "distribution_inventory_sha256": runtime_environment["distribution_inventory_sha256"],
            "site_packages_tree_sha256": runtime_environment["site_packages_tree_sha256"],
        },
        "capture": {
            "stdout": _capture_json(
                retained=retained_stdout,
                original_retained_bytes=len(process.stdout),
                total=process.stdout_total_bytes,
                truncated=process.stdout_truncated,
                complete=process.stdout_complete,
            ),
            "stderr": _capture_json(
                retained=retained_stderr,
                original_retained_bytes=len(process.stderr),
                total=process.stderr_total_bytes,
                truncated=process.stderr_truncated,
                complete=process.stderr_complete,
            ),
        },
        "candidate_extraction": {
            "complete": extraction_complete,
            "candidate_count": len(candidates),
            "artifact_path": CANDIDATE_ARTIFACT_PATH if extraction_complete else None,
            "scanned_artifact_files": scanned["files"],
            "scanned_artifact_bytes": scanned["bytes"],
            "scanned_roots": [path.relative_to(layout.root).as_posix() for path in scan_roots],
            "expected_flag_used": False,
        },
        "environment_policy": {
            "inherits_parent": False,
            "row_gateway_only": True,
            "ambient_proxy_or_provider_credentials": False,
            "fresh_home_work_run": True,
            "persisted_row_credentials_redacted": redacted_credential_files,
        },
    }
    _write_bytes_exclusive(
        layout.root / ADAPTER_RESULT_PATH,
        _canonical_json(receipt),
    )
    return wrapper_returncode, receipt


def run_bounded_process(  # noqa: PLR0913
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    maximum_retained_bytes: int = DEFAULT_MAX_RETAINED_STREAM_BYTES,
    maximum_candidates: int = DEFAULT_MAX_CANDIDATES,
    create_process_group: bool = True,
) -> BoundedProcessResult:
    """Run a child while draining output with fixed memory.

    The public helper creates its own group by default.  The official adapter
    joins its evaluator-created outer group so the outer hard deadline reaches
    both the adapter and its ordinary descendants.
    """

    if not command or not all(isinstance(item, str) and item for item in command):
        raise AdapterConfigurationError("agent command is empty or invalid")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise AdapterConfigurationError("agent process timeout must be finite and positive")
    if maximum_retained_bytes <= 0 or maximum_candidates <= 0:
        raise AdapterConfigurationError("process capture limits must be positive")
    process = subprocess.Popen(  # noqa: S603 - command is derived from a pinned adapter spec.
        tuple(command),
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=create_process_group,
        close_fds=True,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_process(process, owns_process_group=create_process_group)
        raise AdapterEvidenceError("agent process pipes were not created")
    stdout = _BoundedStreamCollector(
        maximum_bytes=maximum_retained_bytes,
        maximum_candidates=maximum_candidates,
    )
    stderr = _BoundedStreamCollector(
        maximum_bytes=maximum_retained_bytes,
        maximum_candidates=maximum_candidates,
    )
    threads = (
        threading.Thread(target=stdout.drain, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr.drain, args=(process.stderr,), daemon=True),
    )
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process, owns_process_group=create_process_group)
    else:
        _terminate_remaining_process_group(
            process,
            owns_process_group=create_process_group,
        )
    for thread in threads:
        thread.join(timeout=_PROCESS_TERMINATE_GRACE_SECONDS)
    stdout_complete = bool(not threads[0].is_alive() and stdout.complete)
    stderr_complete = bool(not threads[1].is_alive() and stderr.complete)
    drains_complete = stdout_complete and stderr_complete
    returncode = process.returncode if process.returncode is not None else -1
    candidates = tuple(sorted(stdout.scanner.candidates | stderr.scanner.candidates))
    extraction_complete = bool(
        drains_complete
        and stdout.complete
        and stderr.complete
        and stdout.scanner.complete
        and stderr.scanner.complete
        and len(candidates) <= maximum_candidates
    )
    return BoundedProcessResult(
        returncode=returncode,
        timed_out=timed_out,
        stdout=bytes(stdout.retained),
        stderr=bytes(stderr.retained),
        stdout_total_bytes=stdout.total_bytes,
        stderr_total_bytes=stderr.total_bytes,
        stdout_sha256=stdout.digest.hexdigest(),
        stderr_sha256=stderr.digest.hexdigest(),
        stdout_truncated=stdout.total_bytes > len(stdout.retained),
        stderr_truncated=stderr.total_bytes > len(stderr.retained),
        stdout_complete=stdout_complete,
        stderr_complete=stderr_complete,
        candidates=candidates,
        extraction_complete=extraction_complete,
    )


def extract_artifact_candidates(  # noqa: C901
    roots: Sequence[Path],
    *,
    maximum_bytes: int = DEFAULT_MAX_SCANNED_ARTIFACT_BYTES,
    maximum_files: int = DEFAULT_MAX_SCANNED_FILES,
    maximum_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> tuple[tuple[bytes, ...], bool, dict[str, int]]:
    """Deterministically scan bounded regular artifacts for flag-shaped values."""

    if maximum_bytes <= 0 or maximum_files <= 0 or maximum_candidates <= 0:
        raise AdapterConfigurationError("artifact extraction limits must be positive")
    candidates: set[bytes] = set()
    scanned_bytes = 0
    scanned_files = 0
    for root in roots:
        requested = root.expanduser()
        try:
            root_before = requested.lstat()
            location = requested.resolve(strict=True)
        except (OSError, RuntimeError):
            return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
        if stat.S_ISLNK(root_before.st_mode) or not stat.S_ISDIR(root_before.st_mode):
            return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
        paths: list[tuple[Path, os.stat_result]] = []
        try:
            for path in location.rglob("*"):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    continue
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                ):
                    return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
                paths.append((path, metadata))
        except OSError:
            return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
        paths.sort(key=lambda item: item[0].relative_to(location).as_posix())
        for path, metadata in paths:
            scanned_files += 1
            if scanned_files > maximum_files:
                return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
            size = metadata.st_size
            if size < 0 or scanned_bytes + size > maximum_bytes:
                return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
            scanner = _CandidateScanner(maximum_candidates=maximum_candidates)
            try:
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
                with os.fdopen(descriptor, "rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or opened.st_nlink != 1
                        or opened.st_dev != metadata.st_dev
                        or opened.st_ino != metadata.st_ino
                        or opened.st_size != metadata.st_size
                    ):
                        return _incomplete_candidate_scan(
                            candidates,
                            scanned_files,
                            scanned_bytes,
                        )
                    file_bytes = 0
                    while chunk := handle.read(_READ_CHUNK_BYTES):
                        file_bytes += len(chunk)
                        scanned_bytes += len(chunk)
                        if file_bytes > size or scanned_bytes > maximum_bytes:
                            return _incomplete_candidate_scan(
                                candidates,
                                scanned_files,
                                scanned_bytes,
                            )
                        scanner.feed(chunk)
                    completed = os.fstat(handle.fileno())
            except OSError:
                return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
            if (
                file_bytes != size
                or completed.st_nlink != 1
                or completed.st_dev != metadata.st_dev
                or completed.st_ino != metadata.st_ino
                or completed.st_size != metadata.st_size
                or completed.st_mtime_ns != metadata.st_mtime_ns
                or completed.st_ctime_ns != metadata.st_ctime_ns
            ):
                return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
            candidates.update(scanner.candidates)
            if not scanner.complete or len(candidates) > maximum_candidates:
                return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
        try:
            root_after = requested.lstat()
        except OSError:
            return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
        if (
            root_after.st_dev != root_before.st_dev
            or root_after.st_ino != root_before.st_ino
            or root_after.st_mtime_ns != root_before.st_mtime_ns
            or root_after.st_ctime_ns != root_before.st_ctime_ns
        ):
            return _incomplete_candidate_scan(candidates, scanned_files, scanned_bytes)
    return (
        tuple(sorted(candidates)),
        True,
        {
            "files": scanned_files,
            "bytes": scanned_bytes,
        },
    )


def _incomplete_candidate_scan(
    candidates: set[bytes],
    scanned_files: int,
    scanned_bytes: int,
) -> tuple[tuple[bytes, ...], bool, dict[str, int]]:
    return (
        tuple(sorted(candidates)),
        False,
        {"files": scanned_files, "bytes": scanned_bytes},
    )


def _prepare_ravage(
    *,
    launch: AdapterLaunch,
    layout: AdapterLayout,
    target_url: str,
    gateway_base_url: str,
    semantic_prompt: str,
) -> tuple[tuple[str, ...], Path]:
    brief_path = layout.work / "brief.json"
    model_path = layout.work / "models.json"
    engagement_id = str(uuid5(NAMESPACE_URL, f"ravage-paired-black-box:{target_url}"))
    brief = {
        "engagement_id": engagement_id,
        "scope": {"in_scope": [target_url], "out_of_scope": []},
        "roe": {
            "max_rps": 10,
            "no_destructive_actions": True,
            "data_handling": "placeholders_only",
        },
        "objectives": ["capture_flag", "web_application_assessment"],
        "budget": {
            # Ravage's public brief schema currently requires a JSON number.
            # The exact decimal remains bound in the adapter launch/receipt.
            "max_cost_usd": float(launch.limits.max_cost_usd),
            "max_runtime_min": max(1, math.ceil(launch.limits.wall_seconds / 60)),
        },
        "context": {
            "description": semantic_prompt,
            "win_condition": _GENERIC_OBJECTIVE,
            "rules": list(_GENERIC_RULES),
        },
    }
    gateway = _validated_gateway_public(launch.gateway_public)
    pricing = _mapping(gateway["pricing"], "gateway pricing")
    route = {
        "provider": "custom_openai",
        "model": gateway["model"],
        "base_url": gateway_base_url,
        "api_key_env": "OPENAI_API_KEY",
        "api_key_required": True,
        "reasoning_effort": gateway["reasoning_effort"],
        "max_output_tokens": gateway["max_output_tokens"],
        "output_token_limit_parameter": "max_completion_tokens",
        "input_cost_per_1m_tokens": float(str(pricing["input_per_million"])),
        "cached_input_cost_per_1m_tokens": float(str(pricing["cached_input_per_million"])),
        "output_cost_per_1m_tokens": float(str(pricing["output_per_million"])),
        "max_retries": 5,
    }
    model_config = {
        "profiles": {
            "paired-row-gateway": {
                "default_tier": "high",
                "routes": {"high": [route]},
            }
        }
    }
    _write_bytes_exclusive(brief_path, _canonical_json(brief))
    _write_bytes_exclusive(model_path, _canonical_json(model_config))
    ravage_run = layout.run_root / "ravage"
    executable = str(launch.runtime.executable.expanduser().resolve(strict=True))
    command = (
        executable,
        "attack",
        str(brief_path),
        "--target-url",
        target_url,
        "--run-dir",
        str(ravage_run),
        "--db-path",
        str(ravage_run / "audit.db"),
        "--workspace-dir",
        str(ravage_run / "workspace"),
        "--model-config",
        str(model_path),
        "--model-profile",
        "paired-row-gateway",
        "--model-tier",
        "high",
        "--max-turns",
        str(launch.limits.max_model_requests),
        "--agent-mode",
        "ctf-free-roam",
        "--recovery-profile",
        "off",
        "--autonomous-route",
        "--autonomous-route-engine",
        "agent-graph",
        "--autonomous-route-max-requests",
        str(launch.limits.max_model_requests),
        # The frozen public CLI exposes legacy and local-only shadow; its
        # internal online planner is deliberately not a valid remote CLI mode.
        "--graph-planner-mode",
        "legacy",
        "--operational-profile",
        "standard",
        "--traffic-policy",
        "observe",
        "--tool-runtime",
        "docker",
        "--tool-image",
        launch.tool_image,
        "--tool-recon",
        "--authorized-remote-target",
        "--allow-paid-models",
        "--memory",
        "off",
        "--display",
        "quiet",
        "--report",
        "--report-path",
        str(ravage_run / "report.md"),
    )
    return command, layout.work


def _prepare_strix(
    *,
    launch: AdapterLaunch,
    layout: AdapterLayout,
    target_url: str,
    semantic_prompt: str,
) -> tuple[tuple[str, ...], Path]:
    executable = str(launch.runtime.executable.expanduser().resolve(strict=True))
    config_path = layout.work / "strix-config.json"
    _write_bytes_exclusive(config_path, _canonical_json({"env": {}}))
    command = (
        executable,
        "--target",
        target_url,
        "--instruction",
        semantic_prompt,
        "--non-interactive",
        "--scan-mode",
        "deep",
        "--scope-mode",
        "full",
        "--config",
        str(config_path),
        "--max-budget-usd",
        decimal_text(launch.limits.max_cost_usd),
        "--max-turns",
        str(launch.limits.max_model_requests),
    )
    return command, layout.run_root


def _child_environment(
    *,
    launch: AdapterLaunch,
    layout: AdapterLayout,
    gateway_base_url: str,
    gateway_token: str,
) -> dict[str, str]:
    environment = {
        "PATH": _trusted_path(launch.trusted_path),
        "HOME": str(layout.home),
        "XDG_CONFIG_HOME": str(layout.home / ".config"),
        "XDG_CACHE_HOME": str(layout.home / ".cache"),
        "XDG_DATA_HOME": str(layout.home / ".local" / "share"),
        "DOCKER_CONFIG": str(layout.home / ".docker"),
        "DOCKER_HOST": _validated_docker_host(launch.docker_host),
        "TMPDIR": str(layout.temporary),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "OPENAI_API_KEY": gateway_token,
    }
    if launch.system_id == "strix":
        model = str(launch.gateway_public["model"])
        environment.update(
            {
                "LLM_API_KEY": gateway_token,
                "LLM_API_BASE": gateway_base_url,
                "OPENAI_BASE_URL": gateway_base_url,
                "STRIX_LLM": model if model.startswith("openai/") else f"openai/{model}",
                "STRIX_REASONING_EFFORT": str(launch.gateway_public["reasoning_effort"]),
                "STRIX_TELEMETRY": "false",
                "STRIX_RUNTIME_BACKEND": "docker",
                "STRIX_IMAGE": launch.tool_image,
                "STRIX_DOCKER_SANDBOX_NETWORK": str(launch.sandbox_network),
            }
        )
    return environment


def _claim_layout(root: Path) -> AdapterLayout:
    requested = root.expanduser()
    if requested.is_symlink():
        raise AdapterEvidenceError("adapter root must not be a symlink")
    location = requested.resolve(strict=True)
    if not location.is_dir() or any(location.iterdir()):
        raise AdapterEvidenceError("adapter root must be an existing empty directory")
    home = location / "adapter-home"
    work = location / "adapter-work"
    run_root = location / "agent-run"
    temporary = location / "adapter-tmp"
    for directory in (home, work, run_root, temporary):
        directory.mkdir(mode=0o700, exist_ok=False)
    for directory in (
        home / ".config",
        home / ".cache",
        home / ".local",
        home / ".local" / "share",
        home / ".docker",
    ):
        directory.mkdir(mode=0o700, exist_ok=False)
    return AdapterLayout(
        root=location,
        home=home,
        work=work,
        run_root=run_root,
        temporary=temporary,
    )


def verify_pinned_runtime(
    runtime: PinnedAgentRuntime,
    *,
    trusted_path: str,
) -> Mapping[str, object]:
    """Verify the executable, environment manifest, and exact source checkout."""

    identity = runtime.to_json()
    executable = Path(identity["executable"])
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise AdapterIdentityError("pinned agent executable is missing or not executable")
    digest = _sha256_file(executable)
    if digest != identity["executable_sha256"]:
        raise AdapterIdentityError("agent executable SHA-256 does not match its pin")
    runtime_environment = _verify_runtime_environment_manifest(
        runtime,
        executable=executable,
    )
    source_root = Path(identity["source_root"])
    if not source_root.is_dir():
        raise AdapterIdentityError("pinned agent source root is missing")
    git_environment = {
        "PATH": _trusted_path(trusted_path),
        "HOME": "/nonexistent-paired-xben-home",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    top = _run_git(source_root, ("rev-parse", "--show-toplevel"), git_environment)
    try:
        top_matches = Path(top or "").resolve(strict=True) == source_root.resolve(strict=True)
    except (OSError, RuntimeError):
        top_matches = False
    if not top_matches:
        raise AdapterIdentityError("agent source root is not the Git toplevel")
    head = _run_git(source_root, ("rev-parse", "--verify", "HEAD"), git_environment)
    tree = _run_git(source_root, ("rev-parse", "--verify", "HEAD^{tree}"), git_environment)
    origin = _run_git(source_root, ("remote", "get-url", "origin"), git_environment)
    status = _run_git(
        source_root,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        git_environment,
    )
    if head is None or head.lower() != identity["source_commit"]:
        raise AdapterIdentityError("agent source HEAD does not match its pin")
    if tree is None or tree.lower() != identity["source_tree"]:
        raise AdapterIdentityError("agent source tree does not match its pin")
    if origin is None or _origin_identity(origin) != _origin_identity(
        identity["source_origin_url"]
    ):
        raise AdapterIdentityError("agent source origin does not match its pin")
    if status is None or status:
        raise AdapterIdentityError("agent source worktree is not clean")
    _verify_exact_source_checkout(
        source_root,
        expected_commit=identity["source_commit"],
        environment=git_environment,
    )
    return runtime_environment


def _verify_runtime_environment_manifest(  # noqa: C901
    runtime: PinnedAgentRuntime,
    *,
    executable: Path,
) -> Mapping[str, object]:
    requested = runtime.runtime_environment_manifest.expanduser()
    if requested.is_symlink():
        raise AdapterIdentityError("runtime environment manifest must not be a symlink")
    try:
        manifest_path = requested.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterIdentityError("runtime environment manifest is missing") from exc
    try:
        body = _read_identity_bytes(manifest_path, "runtime environment manifest")
    except AdapterConfigurationError as exc:
        raise AdapterIdentityError(str(exc)) from exc
    if _sha256_bytes(body) != _sha256_digest(runtime.runtime_environment_manifest_sha256):
        raise AdapterIdentityError("runtime environment manifest SHA-256 does not match its pin")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterIdentityError("runtime environment manifest is invalid JSON") from exc
    document = _mapping(payload, "runtime environment manifest")
    expected_fields = {
        "schema_version",
        "expected_install_command",
        "source_root",
        "environment_root",
        "interpreter",
        "lockfile",
        "site_packages",
        "site_packages_tree_sha256",
        "site_packages_file_count",
        "site_packages_total_bytes",
        "distributions",
        "distribution_inventory_sha256",
        "editable_source_roots",
    }
    if (
        set(document) != expected_fields
        or document.get("schema_version") != RUNTIME_ENVIRONMENT_SCHEMA_VERSION
        or document.get("expected_install_command") != ["uv", "sync", "--frozen"]
    ):
        raise AdapterIdentityError("runtime environment manifest fields are invalid")
    source_root = Path(_string(document.get("source_root"), "runtime source root"))
    if source_root != runtime.source_root.expanduser().resolve(strict=True):
        raise AdapterIdentityError("runtime environment source root does not match the source pin")
    interpreter = _mapping(document.get("interpreter"), "runtime interpreter")
    lockfile = _mapping(document.get("lockfile"), "runtime lockfile")
    if set(interpreter) != {"path", "realpath", "sha256"} or set(lockfile) != {
        "path",
        "sha256",
    }:
        raise AdapterIdentityError("runtime interpreter or lockfile fields are invalid")
    raw_site_packages = document.get("site_packages")
    if not isinstance(raw_site_packages, list) or not raw_site_packages:
        raise AdapterIdentityError("runtime site-packages roots are invalid")
    try:
        recomputed = _runtime_environment_document(
            interpreter=Path(_string(interpreter.get("path"), "runtime interpreter path")),
            lockfile=Path(_string(lockfile.get("path"), "runtime lockfile path")),
            site_packages=tuple(
                Path(_string(item, "site-packages root")) for item in raw_site_packages
            ),
            source_root=source_root,
        )
    except (AdapterConfigurationError, OSError, RuntimeError) as exc:
        raise AdapterIdentityError("runtime environment could not be revalidated") from exc
    if _canonical_json(recomputed) != body:
        raise AdapterIdentityError("runtime environment no longer matches its manifest")
    _verify_executable_interpreter(executable, environment=recomputed)
    return recomputed


def _verify_executable_interpreter(executable: Path, *, environment: object) -> None:
    manifest = _mapping(environment, "runtime environment")
    identity = _mapping(manifest.get("interpreter"), "runtime interpreter")
    environment_root = Path(_string(manifest.get("environment_root"), "runtime environment root"))
    expected_path = Path(_string(identity.get("path"), "runtime interpreter path"))
    expected_realpath = Path(_string(identity.get("realpath"), "runtime interpreter realpath"))
    try:
        with executable.open("rb") as handle:
            first_line = handle.readline(4096)
    except OSError as exc:
        raise AdapterIdentityError("agent executable shebang could not be inspected") from exc
    if first_line.startswith(b"#!"):
        try:
            shebang = first_line[2:].decode("utf-8").strip().split(maxsplit=1)[0]
        except (UnicodeDecodeError, IndexError) as exc:
            raise AdapterIdentityError("agent executable shebang is invalid") from exc
        if not shebang or not Path(shebang).is_absolute() or Path(shebang) != expected_path:
            raise AdapterIdentityError(
                "agent executable is not bound to the manifest interpreter path"
            )
        try:
            actual_realpath = Path(shebang).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AdapterIdentityError("agent executable interpreter is missing") from exc
    else:
        actual_realpath = executable.resolve(strict=True)
    if actual_realpath != expected_realpath:
        raise AdapterIdentityError(
            "agent executable is not bound to the manifest interpreter realpath"
        )
    try:
        executable.resolve(strict=True).relative_to(environment_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AdapterIdentityError(
            "agent executable is outside the manifest interpreter environment"
        ) from exc


def _run_git(
    root: Path,
    arguments: Sequence[str],
    environment: Mapping[str, str],
) -> str | None:
    git = _verified_system_git()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git identity probe.
            (str(git), "-C", str(root), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            text=True,
            env=dict(environment),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _verified_system_git() -> Path:
    """Return the immutable-by-unprivileged-users Git identity probe.

    The adapter launch's ``trusted_path`` controls only the pinned agent's
    child tools. It must not let a caller substitute a fake ``git`` binary and
    self-report any desired source identity.
    """

    requested = _SYSTEM_GIT
    try:
        metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise AdapterIdentityError("system Git identity probe is missing") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(resolved_metadata.st_mode)
        or resolved_metadata.st_uid != 0
        or resolved_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(resolved, os.X_OK)
    ):
        raise AdapterIdentityError("system Git identity probe is not root-controlled")
    return resolved


def _run_git_bytes(
    root: Path,
    arguments: Sequence[str],
    environment: Mapping[str, str],
) -> bytes:
    git = _verified_system_git()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed, root-controlled Git probe.
            (str(git), "-C", str(root), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
            env=dict(environment),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterIdentityError("agent source tree could not be enumerated") from exc
    if completed.returncode != 0:
        raise AdapterIdentityError("agent source tree could not be enumerated")
    return completed.stdout


def _verify_exact_source_checkout(
    root: Path,
    *,
    expected_commit: str,
    environment: Mapping[str, str],
) -> None:
    """Match every executable checkout byte to the pinned Git commit.

    ``git status`` alone deliberately omits ignored files and can also honor
    index flags such as ``assume-unchanged``. Editable installs can import
    those omitted bytes. This comparison walks the actual checkout without
    following symlinks and recomputes Git blob object IDs for every entry.
    A source checkout used for comparison must therefore be a literal clean
    export: no ignored caches, generated code, submodules, or external links.
    """

    raw_tree = _run_git_bytes(
        root,
        ("ls-tree", "-rz", "--full-tree", expected_commit),
        environment,
    )
    expected: dict[bytes, tuple[str, str]] = {}
    object_algorithm: str | None = None
    for record in raw_tree.split(b"\0"):
        if not record:
            continue
        try:
            header, relative = record.split(b"\t", 1)
            raw_mode, raw_kind, raw_object = header.split(b" ", 2)
            mode = raw_mode.decode("ascii")
            kind = raw_kind.decode("ascii")
            object_id = raw_object.decode("ascii").lower()
        except (UnicodeDecodeError, ValueError) as exc:
            raise AdapterIdentityError("agent source Git tree is malformed") from exc
        if (
            not relative
            or relative.startswith(b"/")
            or b"\0" in relative
            or relative in expected
            or kind != "blob"
            or mode not in {"100644", "100755", "120000"}
            or _GIT_OBJECT_RE.fullmatch(object_id) is None
        ):
            raise AdapterIdentityError(
                "agent source Git tree contains an unsupported or unsafe entry"
            )
        algorithm = "sha1" if len(object_id) == 40 else "sha256"
        if object_algorithm is None:
            object_algorithm = algorithm
        elif object_algorithm != algorithm:
            raise AdapterIdentityError("agent source Git tree mixes object algorithms")
        expected[relative] = (mode, object_id)
        if len(expected) > _MAX_SOURCE_CHECKOUT_FILES:
            raise AdapterIdentityError("agent source checkout exceeds its file-count bound")

    actual: dict[bytes, tuple[str, str]] = {}
    total_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        except OSError as exc:
            raise AdapterIdentityError("agent source checkout could not be enumerated") from exc
        for entry in entries:
            path = Path(entry.path)
            if directory == root and entry.name == ".git":
                continue
            try:
                relative = os.fsencode(path.relative_to(root))
                metadata = entry.stat(follow_symlinks=False)
            except (OSError, ValueError) as exc:
                raise AdapterIdentityError("agent source checkout entry is unstable") from exc
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
                continue
            if len(actual) >= _MAX_SOURCE_CHECKOUT_FILES:
                raise AdapterIdentityError("agent source checkout exceeds its file-count bound")
            expected_entry = expected.get(relative)
            if expected_entry is None:
                raise AdapterIdentityError("agent source checkout contains bytes absent from HEAD")
            expected_mode, expected_object = expected_entry
            algorithm = "sha1" if len(expected_object) == 40 else "sha256"
            if entry.is_symlink():
                if expected_mode != "120000":
                    raise AdapterIdentityError("agent source checkout mode differs from HEAD")
                try:
                    raw_target = os.fsencode(os.readlink(path))
                    resolved_target = path.resolve(strict=True)
                    resolved_target.relative_to(root)
                except (OSError, RuntimeError, ValueError) as exc:
                    raise AdapterIdentityError(
                        "agent source checkout symlink escapes its pinned tree"
                    ) from exc
                body_size = len(raw_target)
                digest = _git_blob_digest(raw_target, algorithm=algorithm)
            elif entry.is_file(follow_symlinks=False):
                actual_mode = "100755" if metadata.st_mode & 0o111 else "100644"
                if actual_mode != expected_mode:
                    raise AdapterIdentityError("agent source checkout mode differs from HEAD")
                digest, body_size = _git_blob_file_digest(
                    path,
                    metadata=metadata,
                    algorithm=algorithm,
                )
            else:
                raise AdapterIdentityError("agent source checkout contains a special file")
            total_bytes += body_size
            if total_bytes > _MAX_SOURCE_CHECKOUT_BYTES:
                raise AdapterIdentityError("agent source checkout exceeds its byte bound")
            if digest != expected_object:
                raise AdapterIdentityError("agent source checkout bytes differ from HEAD")
            actual[relative] = (expected_mode, digest)
    if actual != expected:
        raise AdapterIdentityError("agent source checkout does not exactly match HEAD")


def _git_blob_digest(body: bytes, *, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    digest.update(f"blob {len(body)}\0".encode("ascii"))
    digest.update(body)
    return digest.hexdigest()


def _git_blob_file_digest(
    path: Path,
    *,
    metadata: os.stat_result,
    algorithm: str,
) -> tuple[str, int]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 0
        or metadata.st_size > _MAX_SOURCE_CHECKOUT_BYTES
    ):
        raise AdapterIdentityError("agent source checkout file is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    digest = hashlib.new(algorithm)
    digest.update(f"blob {metadata.st_size}\0".encode("ascii"))
    observed = 0
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size
            ):
                raise AdapterIdentityError("agent source checkout file changed before hashing")
            while chunk := handle.read(_READ_CHUNK_BYTES):
                observed += len(chunk)
                if observed > metadata.st_size:
                    raise AdapterIdentityError("agent source checkout file grew while hashing")
                digest.update(chunk)
            completed = os.fstat(handle.fileno())
    except AdapterIdentityError:
        raise
    except OSError as exc:
        raise AdapterIdentityError("agent source checkout file could not be hashed") from exc
    if (
        observed != metadata.st_size
        or completed.st_nlink != 1
        or completed.st_dev != metadata.st_dev
        or completed.st_ino != metadata.st_ino
        or completed.st_size != metadata.st_size
        or completed.st_mtime_ns != metadata.st_mtime_ns
        or completed.st_ctime_ns != metadata.st_ctime_ns
    ):
        raise AdapterIdentityError("agent source checkout file changed while hashing")
    return digest.hexdigest(), observed


def _terminate_process(
    process: subprocess.Popen[bytes],
    *,
    owns_process_group: bool,
) -> None:
    # Do not grant useful execution time after the frozen deadline.  A child
    # could otherwise ignore SIGTERM and create a score artifact during the
    # cleanup grace period.
    if owns_process_group:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    else:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
    try:
        process.wait(timeout=_PROCESS_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise AdapterEvidenceError("agent process group resisted SIGKILL") from exc


def _terminate_remaining_process_group(
    process: subprocess.Popen[bytes],
    *,
    owns_process_group: bool,
) -> None:
    if not owns_process_group:
        # The outer evaluator tears down the shared group immediately after
        # this adapter exits; killing it here would also kill the adapter before
        # it can seal its create-only result.
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _write_candidate_artifact(path: Path, candidates: Sequence[bytes]) -> None:
    body = b"".join(candidate + b"\n" for candidate in sorted(set(candidates)))
    _write_bytes_exclusive(path, body)


def _sanitize_known_credential_artifacts(
    *,
    launch: AdapterLaunch,
    layout: AdapterLayout,
    gateway_token: str,
) -> int:
    if launch.system_id != "strix":
        return 0
    path = layout.work / "strix-config.json"
    if not path.is_file() or path.is_symlink():
        raise AdapterEvidenceError("Strix credential config is missing or unsafe")
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise AdapterEvidenceError("Strix credential config is unreadable") from exc
    if len(body) > _MAX_CREDENTIAL_CONFIG_BYTES:
        raise AdapterEvidenceError("Strix credential config exceeds the sanitation limit")
    redacted = _redact_bytes(body, (gateway_token,))
    if redacted == body:
        return 0
    temporary = layout.temporary / "strix-config.redacted"
    _write_bytes_exclusive(temporary, redacted)
    try:
        temporary.replace(path)
    except OSError as exc:
        raise AdapterEvidenceError("Strix credential config could not be sanitized") from exc
    return 1


def _write_bytes_exclusive(path: Path, body: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise AdapterEvidenceError(f"refusing to replace adapter evidence: {path.name}") from exc
    created = os.fstat(descriptor)
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("adapter evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        _remove_partial_evidence(path, created)
        raise AdapterEvidenceError(f"adapter evidence write failed: {path.name}") from exc
    try:
        os.close(descriptor)
    except OSError as exc:
        _remove_partial_evidence(path, created)
        raise AdapterEvidenceError(f"adapter evidence close failed: {path.name}") from exc


def _remove_partial_evidence(path: Path, created: os.stat_result) -> None:
    try:
        current = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AdapterEvidenceError(
            f"partial adapter evidence could not be inspected: {path.name}"
        ) from exc
    if (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino):
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AdapterEvidenceError(
            f"partial adapter evidence could not be removed: {path.name}"
        ) from exc


def _decode_launch_spec(value: str) -> AdapterLaunch:
    try:
        raw = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise AdapterConfigurationError("adapter launch spec is not valid base64") from exc
    if not raw or len(raw) > _MAX_LAUNCH_SPEC_BYTES:
        raise AdapterConfigurationError("adapter launch spec has an invalid size")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterConfigurationError("adapter launch spec is not valid JSON") from exc
    document = _mapping(payload, "adapter launch spec")
    expected = {
        "schema_version",
        "adapter_version",
        "system_id",
        "runtime",
        "gateway",
        "limits",
        "trusted_path",
        "tool_image",
        "docker_host",
        "sandbox_network",
    }
    if (
        set(document) != expected
        or document.get("schema_version") != ADAPTER_SCHEMA_VERSION
        or document.get("adapter_version") != ADAPTER_VERSION
        or document.get("system_id") not in {"ravage", "strix"}
    ):
        raise AdapterConfigurationError("adapter launch spec fields are invalid")
    runtime_payload = _mapping(document["runtime"], "adapter runtime")
    if set(runtime_payload) != {
        "executable",
        "executable_sha256",
        "source_root",
        "source_commit",
        "source_tree",
        "source_origin_url",
        "runtime_environment_manifest",
        "runtime_environment_manifest_sha256",
    }:
        raise AdapterConfigurationError("adapter runtime fields are invalid")
    runtime = PinnedAgentRuntime(
        executable=Path(_string(runtime_payload["executable"], "agent executable")),
        executable_sha256=_string(
            runtime_payload["executable_sha256"],
            "agent executable digest",
        ),
        source_root=Path(_string(runtime_payload["source_root"], "agent source root")),
        source_commit=_string(runtime_payload["source_commit"], "agent source commit"),
        source_tree=_string(runtime_payload["source_tree"], "agent source tree"),
        source_origin_url=_string(
            runtime_payload["source_origin_url"],
            "agent source origin",
        ),
        runtime_environment_manifest=Path(
            _string(
                runtime_payload["runtime_environment_manifest"],
                "runtime environment manifest",
            )
        ),
        runtime_environment_manifest_sha256=_string(
            runtime_payload["runtime_environment_manifest_sha256"],
            "runtime environment manifest digest",
        ),
    )
    limits_payload = _mapping(document["limits"], "adapter limits")
    if set(limits_payload) != {
        "wall_seconds",
        "max_model_requests",
        "max_target_requests",
        "max_cost_usd",
    }:
        raise AdapterConfigurationError("adapter limit fields are invalid")
    limits = ExternalExecutionLimits(
        wall_seconds=_integer(limits_payload["wall_seconds"], "wall seconds"),
        max_model_requests=_integer(
            limits_payload["max_model_requests"],
            "model request limit",
        ),
        max_target_requests=_integer(
            limits_payload["max_target_requests"],
            "target request limit",
        ),
        max_cost_usd=_string(limits_payload["max_cost_usd"], "cost limit"),
    )
    launch = AdapterLaunch(
        system_id=document["system_id"],  # type: ignore[arg-type]
        runtime=runtime,
        gateway_public=_mapping(document["gateway"], "adapter gateway"),
        limits=limits,
        trusted_path=_string(document["trusted_path"], "trusted PATH"),
        tool_image=_string(document["tool_image"], "tool image"),
        docker_host=_string(document["docker_host"], "Docker host"),
        sandbox_network=(
            None
            if document["sandbox_network"] is None
            else _string(document["sandbox_network"], "sandbox network")
        ),
    )
    if _canonical_json(launch.to_json()) != raw:
        raise AdapterConfigurationError("adapter launch spec is not canonical")
    return launch


def _bound_gateway_environment(
    launch: AdapterLaunch,
    *,
    environment: Mapping[str, str],
) -> tuple[str, str]:
    base_url = _validated_http_url(
        _required_environment(environment, GATEWAY_BASE_URL_ENV),
        "model gateway URL",
    )
    token = _gateway_token(_required_environment(environment, COMPARISON_GATEWAY_TOKEN_ENV))
    gateway = _validated_gateway_public(launch.gateway_public)
    if _sha256_text(base_url) != gateway["base_url_sha256"]:
        raise AdapterConfigurationError("model gateway URL does not match the launch contract")
    if _sha256_text(token) != gateway["token_sha256"]:
        raise AdapterConfigurationError("row gateway token does not match the launch contract")
    return base_url, token


def _validated_gateway_public(value: Mapping[str, object]) -> dict[str, object]:
    if set(value) != {
        "base_url_sha256",
        "token_sha256",
        "model",
        "reasoning_effort",
        "pricing",
        "max_output_tokens",
    }:
        raise AdapterConfigurationError("gateway contract fields are invalid")
    output_tokens = _integer(value["max_output_tokens"], "max output tokens")
    if output_tokens <= 0:
        raise AdapterConfigurationError("max output tokens must be positive")
    pricing = _mapping(value["pricing"], "gateway pricing")
    if set(pricing) != {
        "input_per_million",
        "cached_input_per_million",
        "output_per_million",
    }:
        raise AdapterConfigurationError("gateway pricing fields are invalid")
    return {
        "base_url_sha256": _sha256_digest(_string(value["base_url_sha256"], "gateway URL digest")),
        "token_sha256": _sha256_digest(_string(value["token_sha256"], "gateway token digest")),
        "model": _model_name(_string(value["model"], "gateway model")),
        "reasoning_effort": _reasoning_effort(
            _string(value["reasoning_effort"], "reasoning effort")
        ),
        "pricing": {
            "input_per_million": _decimal_text(
                pricing["input_per_million"],
                "input price",
            ),
            "cached_input_per_million": _decimal_text(
                pricing["cached_input_per_million"],
                "cached-input price",
            ),
            "output_per_million": _decimal_text(
                pricing["output_per_million"],
                "output price",
            ),
        },
        "max_output_tokens": output_tokens,
    }


def _validate_limits(limits: ExternalExecutionLimits) -> None:
    if (
        isinstance(limits.wall_seconds, bool)
        or not isinstance(limits.wall_seconds, int)
        or limits.wall_seconds <= _PROCESS_CLEANUP_RESERVE_SECONDS
    ):
        raise AdapterConfigurationError(
            "wall timeout must leave time for forced process-group cleanup"
        )
    for label, value in (
        ("model request limit", limits.max_model_requests),
        ("target request limit", limits.max_target_requests),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise AdapterConfigurationError(f"{label} must be a positive integer")
    if (
        not isinstance(limits.max_cost_usd, Decimal)
        or not limits.max_cost_usd.is_finite()
        or limits.max_cost_usd <= 0
    ):
        raise AdapterConfigurationError("cost limit must be finite and positive")


def _sha256_file(path: Path) -> str | None:
    descriptor = -1
    try:
        requested = path.expanduser().absolute()
        descriptor, before = _open_identity_file(
            requested,
            maximum_bytes=_MAX_IDENTITY_FILE_BYTES,
        )
        digest = hashlib.sha256()
        observed = 0
        while True:
            maximum_read = min(_READ_CHUNK_BYTES, _MAX_IDENTITY_FILE_BYTES - observed + 1)
            chunk = os.read(descriptor, maximum_read)
            if not chunk:
                break
            observed += len(chunk)
            if observed > _MAX_IDENTITY_FILE_BYTES:
                return None
            digest.update(chunk)
        _verify_identity_file_unchanged(
            descriptor,
            requested,
            before=before,
            observed_bytes=observed,
        )
        return "sha256:" + digest.hexdigest()
    except (OSError, RuntimeError, ValueError):
        return None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _validated_origin_url(value: str) -> str:
    normalized = value.strip()
    if _origin_identity(normalized) is None:
        raise AdapterConfigurationError("agent source origin URL is invalid")
    parsed = urlsplit(normalized)
    if parsed.username or parsed.password:
        raise AdapterConfigurationError("agent source origin URL must not contain credentials")
    return normalized


def _origin_identity(value: str) -> str | None:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        return None
    path = parsed.path.strip("/").removesuffix(".git")
    if not path or ".." in path.split("/"):
        return None
    return f"{parsed.hostname.casefold()}/{path.casefold()}"


def _validated_http_url(value: str, label: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterConfigurationError(f"{label} must be a credential-free HTTP(S) URL")
    return normalized


def _validated_docker_host(value: str) -> str:
    """Accept only one canonical local Unix-socket Docker endpoint."""

    if not isinstance(value, str) or value != value.strip() or len(value.encode()) > 4096:
        raise AdapterConfigurationError("Docker host must be a canonical local Unix URL")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise AdapterConfigurationError("Docker host must be a canonical local Unix URL") from exc
    path = Path(parsed.path)
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.startswith("//")
        or not path.is_absolute()
        or path == Path("/")
        or path.as_posix() != parsed.path
        or any(part in {".", ".."} for part in path.parts)
        or "%" in parsed.path
        or "\\" in parsed.path
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in parsed.path
        )
        or value != f"unix://{parsed.path}"
    ):
        raise AdapterConfigurationError("Docker host must be a canonical local Unix URL")
    return value


def _trusted_path(value: str) -> str:
    """Validate point-in-time ownership and mode safety for child PATH entries.

    This deliberately does not claim immutability: evaluator-owned directories
    may remain owner-writable, and containment must still prevent the child from
    mutating evaluator state.
    """

    normalized = value.strip()
    entries = normalized.split(os.pathsep)
    if (
        not normalized
        or value != normalized
        or len(normalized.encode("utf-8")) > _MAX_TRUSTED_PATH_BYTES
        or len(entries) > _MAX_TRUSTED_PATH_ENTRIES
        or any(
            not entry
            or not Path(entry).is_absolute()
            or any(ord(character) < 32 or ord(character) == 127 for character in entry)
            for entry in entries
        )
    ):
        raise AdapterConfigurationError("trusted PATH must contain only absolute directories")
    allowed_owners = {0, os.geteuid()}
    for entry in entries:
        requested = Path(entry)
        try:
            metadata = requested.lstat()
            resolved = requested.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AdapterConfigurationError("trusted PATH entry is missing") from exc
        if (
            resolved != requested
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in allowed_owners
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise AdapterConfigurationError(
                "trusted PATH entries must be canonical, owned directories without "
                "group or world write access"
            )
    return normalized


def _gateway_token(value: str) -> str:
    token = value.strip()
    if not _MIN_GATEWAY_TOKEN_CHARS <= len(token) <= _MAX_GATEWAY_TOKEN_CHARS or any(
        character.isspace() for character in token
    ):
        raise AdapterConfigurationError("row gateway token is invalid")
    return token


def _model_name(value: str) -> str:
    normalized = value.strip()
    if _MODEL_RE.fullmatch(normalized) is None:
        raise AdapterConfigurationError("gateway model name is invalid")
    return normalized


def _reasoning_effort(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in {"low", "medium", "high", "xhigh"}:
        raise AdapterConfigurationError("reasoning effort is invalid")
    return normalized


def _sha256_digest(value: str) -> str:
    match = _SHA256_RE.fullmatch(value.strip())
    if match is None:
        raise AdapterConfigurationError("expected a SHA-256 digest")
    return "sha256:" + match.group(1).lower()


def _git_object(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if _GIT_OBJECT_RE.fullmatch(normalized) is None:
        raise AdapterConfigurationError(f"{label} is invalid")
    return normalized


def _decimal_text(value: object, label: str, *, positive: bool = False) -> str:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise AdapterConfigurationError(f"{label} is invalid") from exc
    if not number.is_finite() or number < 0 or (positive and number <= 0):
        raise AdapterConfigurationError(f"{label} is invalid")
    try:
        return decimal_text(number)
    except ValueError as exc:
        raise AdapterConfigurationError(f"{label} is invalid") from exc


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AdapterConfigurationError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise AdapterConfigurationError(f"{label} must be a normalized string")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterConfigurationError(f"{label} must be an integer")
    return value


def _required_environment(environment: Mapping[str, str], name: str) -> str:
    value = str(environment.get(name, ""))
    if not value:
        raise AdapterConfigurationError(f"required adapter environment is missing: {name}")
    return value


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _redact_bytes(value: bytes, sensitive_values: Sequence[str]) -> bytes:
    redacted = value
    for sensitive in _sensitive_byte_variants(sensitive_values):
        redacted = redacted.replace(sensitive, b"[REDACTED ROW CREDENTIAL]")
    return redacted


def _sensitive_byte_variants(sensitive_values: Sequence[str]) -> tuple[bytes, ...]:
    variants: set[bytes] = set()
    for item in sensitive_values:
        if not item:
            continue
        raw = item.encode("utf-8")
        variants.update(
            {
                raw,
                quote(item, safe="").encode("ascii"),
                quote_plus(item, safe="").encode("ascii"),
                raw.hex().encode("ascii"),
                raw.hex().upper().encode("ascii"),
                base64.b64encode(raw),
                base64.urlsafe_b64encode(raw),
                base64.b64encode(raw).rstrip(b"="),
                base64.urlsafe_b64encode(raw).rstrip(b"="),
            }
        )
    return tuple(sorted((value for value in variants if value), key=len, reverse=True))


def _capture_json(
    *,
    retained: bytes,
    original_retained_bytes: int,
    total: int,
    truncated: bool,
    complete: bool,
) -> dict[str, object]:
    # The published receipt describes the sanitized log.  Preserve the count
    # of bytes omitted by capture, so redaction cannot erase truncation evidence.
    omitted_bytes = total - original_retained_bytes
    if omitted_bytes < 0 or truncated is not (omitted_bytes > 0):
        raise AdapterEvidenceError("process capture byte counts are inconsistent")
    return {
        "sha256": "sha256:" + hashlib.sha256(retained).hexdigest(),
        "total_bytes": len(retained) + omitted_bytes,
        "retained_bytes": len(retained),
        "truncated": truncated,
        "complete": complete,
    }


def _portable_returncode(value: int) -> int:
    if value < 0:
        return 128 + min(127, abs(value))
    return min(value, 125)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one isolated paired-XBEN agent adapter.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    execute = subparsers.add_parser("execute")
    execute.add_argument("--launch-spec", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "execute":
        raise AdapterConfigurationError("unsupported adapter command")
    try:
        returncode, receipt = execute_launch_spec(
            args.launch_spec,
            cwd=Path.cwd(),
            environment=os.environ,
        )
    except (AdapterConfigurationError, AdapterEvidenceError, OSError) as exc:
        sys.stderr.write(f"[paired-xben:adapter-blocked] {type(exc).__name__}\n")
        return 125
    sys.stdout.write(
        json.dumps(
            {
                "system_id": receipt["system_id"],
                "status": receipt["status"],
                "returncode": receipt["returncode"],
            },
            sort_keys=True,
        )
        + "\n"
    )
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
