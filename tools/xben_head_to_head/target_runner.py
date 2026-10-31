"""Fresh-target lifecycle for the exploratory Codex-versus-Strix XBEN run.

The target source is materialized from one exact Git commit into a private
temporary directory.  A case is built once with an evaluator-generated flag,
then each comparison arm receives a fresh Compose deployment (containers and
volumes are removed between arms).  Only loopback ports are published.

This is intentionally a local diagnostic backend.  It does not claim that the
agent and target have separate Docker authorities.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import stat
import subprocess
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import yaml

PINNED_XBEN_COMMIT = "a16cb1ba0701b20d63913846536fc7b0672082af"
_CASE_RE = re.compile(r"XBEN-(?:00[1-9]|0[1-9][0-9]|10[0-4])-24")
_SAFE_PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_BUILDER_NAME_RE = re.compile(r"ravage_xben_cmp_[0-9a-f]{32}")
_PORT_OUTPUT_RE = re.compile(r"127\.0\.0\.1:([0-9]{1,5})")
_FORBIDDEN_SERVICE_KEYS = frozenset(
    {"privileged", "network_mode", "pid", "ipc", "devices", "volumes", "cap_add"}
)
_MAX_COMMAND_OUTPUT = 4 * 1024 * 1024


class TargetRunnerError(RuntimeError):
    """A target could not be prepared without weakening the run contract."""


@dataclass(frozen=True)
class CommandReceipt:
    operation: str
    returncode: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    elapsed_seconds: float

    def to_json(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "returncode": self.returncode,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "elapsed_seconds": self.elapsed_seconds,
        }


@dataclass
class BuildxBuilder:
    """A randomly named BuildKit builder created and owned by this process."""

    name: str
    _created: bool = field(default=False, repr=False)

    @classmethod
    def create(cls) -> BuildxBuilder:
        name = f"ravage_xben_cmp_{secrets.token_hex(16)}"
        completed = _run_buildx(("create", "--name", name, "--driver", "docker-container"))
        if completed.returncode != 0:
            raise TargetRunnerError("could not create dedicated campaign Buildx builder")
        # Successful creation is the ownership proof. Do not adopt an existing
        # builder by name, and never change the user's selected builder.
        return cls(name=name, _created=True)

    def verify_owned(self) -> None:
        if not self._created or _BUILDER_NAME_RE.fullmatch(self.name) is None:
            raise TargetRunnerError("Buildx builder is not owned by this campaign")
        completed = _run_buildx(("inspect", self.name))
        if completed.returncode != 0:
            raise TargetRunnerError("campaign Buildx builder is unavailable")
        fields: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            if line.startswith("Nodes:"):
                break
            if match := re.fullmatch(r"(Name|Driver):\s*(\S+)\s*", line):
                fields.setdefault(*match.groups())
        if fields.get("Name") != self.name or fields.get("Driver") != "docker-container":
            raise TargetRunnerError("campaign Buildx builder identity changed")

    def destroy(self) -> dict[str, object]:
        """Remove only this verified builder, then prove it no longer exists."""
        self.verify_owned()
        started = time.monotonic()
        completed = _run_buildx(("rm", self.name))
        remaining = _run_buildx(("inspect", self.name)) if completed.returncode == 0 else None
        verified = completed.returncode == 0 and remaining is not None and remaining.returncode != 0
        if verified:
            self._created = False
        return {
            "builder_name_sha256": hashlib.sha256(self.name.encode()).hexdigest(),
            "returncode": completed.returncode,
            "verified": verified,
            "stdout_sha256": hashlib.sha256((completed.stdout or "").encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256((completed.stderr or "").encode()).hexdigest(),
            "elapsed_seconds": round(time.monotonic() - started, 6),
        }


@dataclass
class XbenTarget:
    """One prepared case whose deployment can be reset between two arms."""

    case_id: str
    case_dir: Path
    compose_path: Path
    project: str
    primary_service: str
    primary_container_port: int
    expected_flag: str = field(repr=False)
    buildx_builder: BuildxBuilder | None = field(default=None, repr=False)
    source_commit: str = PINNED_XBEN_COMMIT
    build_receipt: CommandReceipt | None = None
    start_receipts: list[CommandReceipt] = field(default_factory=list)
    reset_receipts: list[CommandReceipt] = field(default_factory=list)
    active: bool = False
    host_port: int | None = None

    @property
    def codex_target_url(self) -> str:
        if not self.active or self.host_port is None:
            raise TargetRunnerError("target is not active")
        return f"http://127.0.0.1:{self.host_port}"

    @property
    def strix_target_url(self) -> str:
        if not self.active or self.host_port is None:
            raise TargetRunnerError("target is not active")
        return f"http://host.docker.internal:{self.host_port}"

    def build(self, *, timeout_seconds: int = 900) -> CommandReceipt:
        if self.build_receipt is not None:
            raise TargetRunnerError("target image has already been built")
        if self.buildx_builder is None:
            raise TargetRunnerError("target has no dedicated campaign Buildx builder")
        self.buildx_builder.verify_owned()
        result, receipt = _run_compose(
            self,
            "build",
            (
                "build",
                "--builder",
                self.buildx_builder.name,
                "--build-arg",
                f"FLAG={self.expected_flag}",
            ),
            timeout_seconds=timeout_seconds,
        )
        self.build_receipt = receipt
        _require_success(result, operation="compose build", secret=self.expected_flag)
        return receipt

    def start(self, *, timeout_seconds: int = 240) -> str:
        if self.build_receipt is None:
            raise TargetRunnerError("target must be built before start")
        if self.active:
            raise TargetRunnerError("target is already active")
        result, receipt = _run_compose(
            self,
            "up",
            ("up", "-d", "--wait", "--wait-timeout", str(timeout_seconds), "--no-build"),
            timeout_seconds=timeout_seconds + 30,
        )
        self.start_receipts.append(receipt)
        _require_success(result, operation="compose up", secret=self.expected_flag)
        port_result, _ = _run_compose(
            self,
            "port",
            ("port", self.primary_service, str(self.primary_container_port)),
            timeout_seconds=30,
        )
        _require_success(port_result, operation="compose port", secret=self.expected_flag)
        match = _PORT_OUTPUT_RE.fullmatch(port_result.stdout.strip())
        if match is None:
            raise TargetRunnerError("Compose did not return an exact loopback port binding")
        port = int(match.group(1))
        if not 1 <= port <= 65535:
            raise TargetRunnerError("Compose returned an invalid host port")
        self.host_port = port
        self.active = True
        _wait_until_reachable(port=port, timeout_seconds=min(timeout_seconds, 120))
        return self.codex_target_url

    def reset(self, *, timeout_seconds: int = 180) -> CommandReceipt:
        """Remove this arm's containers/volumes while retaining built images."""

        result, receipt = _run_compose(
            self,
            "reset",
            ("down", "--remove-orphans", "--volumes"),
            timeout_seconds=timeout_seconds,
        )
        self.reset_receipts.append(receipt)
        self.active = False
        self.host_port = None
        _require_success(result, operation="compose reset", secret=self.expected_flag)
        _verify_no_project_containers(self.project)
        return receipt

    def destroy(self, *, evidence_dir: Path, timeout_seconds: int = 240) -> dict[str, Any]:
        """Retain redacted logs, remove all case resources, and verify teardown."""

        logs_receipt: CommandReceipt | None = None
        down_receipt: CommandReceipt | None = None
        redacted_logs = ""
        errors: list[str] = []
        down_returncode: int | None = None
        remaining: list[str] | None = None
        try:
            try:
                logs, logs_receipt = _run_compose(
                    self,
                    "logs",
                    ("logs", "--no-color"),
                    timeout_seconds=60,
                )
                redacted_logs = _redact_flag_variants(logs.stdout + logs.stderr, self.expected_flag)
                if logs.returncode != 0:
                    errors.append("compose logs returned nonzero")
            except Exception as exc:  # noqa: BLE001 - teardown must still run.
                errors.append(f"compose logs raised {type(exc).__name__}")
        finally:
            try:
                down, down_receipt = _run_compose(
                    self,
                    "destroy",
                    ("down", "--remove-orphans", "--volumes", "--rmi", "local"),
                    timeout_seconds=timeout_seconds,
                )
                down_returncode = down.returncode
                if down.returncode != 0:
                    errors.append("compose down returned nonzero")
            except Exception as exc:  # noqa: BLE001 - verify even after a down error.
                errors.append(f"compose down raised {type(exc).__name__}")
            finally:
                self.active = False
                self.host_port = None
                try:
                    remaining = _project_container_ids(self.project)
                except Exception as exc:  # noqa: BLE001 - an unverified teardown is invalid.
                    errors.append(f"container verification raised {type(exc).__name__}")
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "target.log").write_text(redacted_logs, encoding="utf-8")
        payload: dict[str, Any] = {
            "logs": logs_receipt.to_json() if logs_receipt else None,
            "down": down_receipt.to_json() if down_receipt else None,
            "remaining_container_ids": remaining,
            "errors": errors,
            "verified": not errors and down_returncode == 0 and remaining == [],
        }
        _write_json_atomic(evidence_dir / "teardown.json", payload)
        return payload

    def public_receipt(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source_commit": self.source_commit,
            "project_sha256": hashlib.sha256(self.project.encode()).hexdigest(),
            "primary_service": self.primary_service,
            "primary_container_port": self.primary_container_port,
            "expected_flag_sha256": hashlib.sha256(self.expected_flag.encode()).hexdigest(),
            "build": self.build_receipt.to_json() if self.build_receipt else None,
            "starts": [receipt.to_json() for receipt in self.start_receipts],
            "resets": [receipt.to_json() for receipt in self.reset_receipts],
        }


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: str
    stderr: str


def prepare_target(
    *,
    source_repo: Path,
    case_id: str,
    expected_flag: str,
    destination: Path,
    buildx_builder: BuildxBuilder,
    source_commit: str = PINNED_XBEN_COMMIT,
) -> XbenTarget:
    """Materialize and rewrite one pinned XBEN case for local paired use."""

    if _CASE_RE.fullmatch(case_id) is None:
        raise TargetRunnerError("invalid canonical XBEN case ID")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise TargetRunnerError("source commit must be a full lowercase Git object ID")
    if not re.fullmatch(r"flag\{[A-Za-z0-9_-]{16,200}\}", expected_flag):
        raise TargetRunnerError("expected flag has an invalid evaluator format")
    source_repo = source_repo.expanduser().resolve(strict=True)
    _verify_source(source_repo, source_commit=source_commit, case_id=case_id)
    if destination.exists() and any(destination.iterdir()):
        raise TargetRunnerError("target destination must be empty")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    case_dir = _materialize_case(
        source_repo=source_repo,
        source_commit=source_commit,
        case_id=case_id,
        destination=destination,
    )
    compose_path, primary_service, primary_port = _rewrite_compose(case_dir)
    project = f"xben_cmp_{case_id.lower().replace('-', '_')}_{secrets.token_hex(4)}"
    if _SAFE_PROJECT_RE.fullmatch(project) is None:
        raise TargetRunnerError("derived Compose project name is unsafe")
    return XbenTarget(
        case_id=case_id,
        case_dir=case_dir,
        compose_path=compose_path,
        project=project,
        primary_service=primary_service,
        primary_container_port=primary_port,
        expected_flag=expected_flag,
        buildx_builder=buildx_builder,
        source_commit=source_commit,
    )


def _verify_source(source_repo: Path, *, source_commit: str, case_id: str) -> None:
    head = _git(source_repo, "rev-parse", "HEAD")
    if head != source_commit:
        raise TargetRunnerError("XBEN worktree HEAD differs from the pinned source commit")
    resolved = _git(source_repo, "rev-parse", f"{source_commit}^{{commit}}")
    if resolved != source_commit:
        raise TargetRunnerError("pinned XBEN commit did not resolve exactly")
    tree = _git(source_repo, "rev-parse", f"{source_commit}:benchmarks/{case_id}")
    if re.fullmatch(r"[0-9a-f]{40,64}", tree) is None:
        raise TargetRunnerError("pinned case tree is unavailable")


def _git(source_repo: Path, *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603
        ["git", *arguments],
        cwd=source_repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise TargetRunnerError("could not verify pinned XBEN source")
    return completed.stdout.strip()


def _materialize_case(
    *,
    source_repo: Path,
    source_commit: str,
    case_id: str,
    destination: Path,
) -> Path:
    git_path = f"benchmarks/{case_id}"
    archive_path = destination / "case.tar"
    with archive_path.open("wb") as archive:
        completed = subprocess.run(  # noqa: S603
            ["git", "archive", "--format=tar", source_commit, git_path],
            cwd=source_repo,
            stdout=archive,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
        )
    if completed.returncode != 0:
        raise TargetRunnerError("could not materialize the pinned XBEN case")
    extraction = destination / "source"
    extraction.mkdir(mode=0o700)
    with tarfile.open(archive_path, "r:") as archive:
        members = archive.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                raise TargetRunnerError("pinned XBEN archive contains an unsafe member")
        archive.extractall(extraction, members=members, filter="data")
    archive_path.unlink()
    case_dir = extraction / git_path
    for required in ("benchmark.json", "docker-compose.yml", ".env"):
        path = case_dir / required
        if not path.is_file() or path.is_symlink():
            raise TargetRunnerError(f"materialized XBEN case lacks {required}")
    return case_dir


def _rewrite_compose(case_dir: Path) -> tuple[Path, str, int]:  # noqa: C901
    source_path = case_dir / "docker-compose.yml"
    raw = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("services"), dict):
        raise TargetRunnerError("XBEN Compose document has no services mapping")
    services = raw["services"]
    primary: tuple[str, int] | None = None
    for service_name, raw_service in services.items():
        if not isinstance(service_name, str) or not isinstance(raw_service, dict):
            raise TargetRunnerError("XBEN Compose service is malformed")
        forbidden = _FORBIDDEN_SERVICE_KEYS & set(raw_service)
        if forbidden:
            raise TargetRunnerError(
                "XBEN Compose requests forbidden host authority: " + ", ".join(sorted(forbidden))
            )
        raw_service["platform"] = "linux/amd64"
        ports = raw_service.get("ports")
        if ports is None:
            continue
        if not isinstance(ports, list):
            raise TargetRunnerError("XBEN Compose ports must be a list")
        rewritten: list[str] = []
        for raw_port in ports:
            container_port = _container_port(raw_port)
            if primary is None:
                primary = (service_name, container_port)
            rewritten.append(f"127.0.0.1::{container_port}")
        raw_service["ports"] = rewritten
    if primary is None:
        raise TargetRunnerError("XBEN case has no published HTTP port")
    runtime_path = case_dir / "compose.head-to-head.yml"
    runtime_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return runtime_path, primary[0], primary[1]


def _container_port(value: object) -> int:
    if isinstance(value, bool):
        raise TargetRunnerError("invalid boolean Compose port")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str):
        text = value.strip().split("/", 1)[0]
        final = text.rsplit(":", 1)[-1]
        if not final.isdigit():
            raise TargetRunnerError("unsupported Compose port syntax")
        port = int(final)
    else:
        raise TargetRunnerError("unsupported Compose port entry")
    if not 1 <= port <= 65535:
        raise TargetRunnerError("Compose container port is out of range")
    return port


def _compose_argv(target: XbenTarget, arguments: tuple[str, ...]) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(target.compose_path),
        "-p",
        target.project,
        *arguments,
    ]


def _run_compose(
    target: XbenTarget,
    operation: str,
    arguments: tuple[str, ...],
    *,
    timeout_seconds: int,
    check_output_limit: bool = True,
) -> tuple[_CommandResult, CommandReceipt]:
    environment = dict(os.environ)
    environment["FLAG"] = target.expected_flag
    if operation == "build":
        if target.buildx_builder is None or arguments[:3] != (
            "build",
            "--builder",
            target.buildx_builder.name,
        ):
            raise TargetRunnerError("compose build requires a dedicated Buildx builder")
        environment["DOCKER_BUILDKIT"] = "1"
        environment["COMPOSE_DOCKER_CLI_BUILD"] = "1"
        environment["COMPOSE_BAKE"] = "false"
        environment["BUILDX_BUILDER"] = target.buildx_builder.name
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603
        _compose_argv(target, arguments),
        cwd=target.case_dir,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
    )
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if check_output_limit and len(stdout.encode()) + len(stderr.encode()) > _MAX_COMMAND_OUTPUT:
        raise TargetRunnerError(f"{operation} output exceeded its evaluator bound")
    result = _CommandResult(completed.returncode, stdout, stderr)
    receipt = CommandReceipt(
        operation=operation,
        returncode=completed.returncode,
        stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
        stdout_bytes=len(stdout.encode()),
        stderr_bytes=len(stderr.encode()),
        elapsed_seconds=round(time.monotonic() - started, 6),
    )
    return result, receipt


def _redact_flag_variants(value: str, flag: str) -> str:
    encoded = flag.encode()
    quoted = quote(flag, safe="")
    encoded_b64 = base64.b64encode(encoded).decode()
    encoded_urlsafe_b64 = base64.urlsafe_b64encode(encoded).decode()
    variants = {
        flag,
        encoded_b64,
        encoded_b64.rstrip("="),
        encoded_urlsafe_b64,
        encoded_urlsafe_b64.rstrip("="),
        encoded.hex(),
        encoded.hex().upper(),
        quoted,
        re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match.group().lower(), quoted),
    }
    for variant in sorted(variants, key=len, reverse=True):
        value = value.replace(variant, "[REDACTED_FLAG]")
    return value


def _require_success(result: _CommandResult, *, operation: str, secret: str) -> None:
    if result.returncode == 0:
        return
    detail = (result.stderr.strip() or result.stdout.strip() or "no diagnostic output")[-4000:]
    raise TargetRunnerError(f"{operation} failed: {detail.replace(secret, '[REDACTED_FLAG]')}")


def _wait_until_reachable(*, port: int, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "no response"
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            response.read(64 * 1024)
            if 100 <= response.status <= 599:
                return
            last_error = f"HTTP {response.status}"
        except (OSError, http.client.HTTPException) as exc:
            last_error = type(exc).__name__
        finally:
            connection.close()
        time.sleep(0.5)
    raise TargetRunnerError(f"target did not become HTTP-reachable: {last_error}")


def _project_container_ids(project: str) -> list[str]:
    completed = subprocess.run(  # noqa: S603
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise TargetRunnerError("could not verify Compose teardown")
    return completed.stdout.split()


def _verify_no_project_containers(project: str) -> None:
    if remaining := _project_container_ids(project):
        raise TargetRunnerError(f"Compose teardown left {len(remaining)} project container(s)")


def _write_json_atomic(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def executable_sha256(path: Path) -> str:
    """Return the SHA-256 of a regular executable for campaign pinning."""

    resolved = path.expanduser().resolve(strict=True)
    metadata = resolved.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise TargetRunnerError("pinned executable is not an executable regular file")
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run_buildx(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["docker", "buildx", *arguments],
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )


def cleanup_build_cache(builder: BuildxBuilder) -> dict[str, object]:
    """Prune cache belonging only to the verified campaign builder."""

    builder.verify_owned()
    started = time.monotonic()
    completed = _run_buildx(("prune", "--builder", builder.name, "-f"))
    return {
        "builder_name_sha256": hashlib.sha256(builder.name.encode()).hexdigest(),
        "returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256((completed.stdout or "").encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256((completed.stderr or "").encode()).hexdigest(),
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }


def make_pair_flag() -> str:
    return f"flag{{ravage_cmp_{secrets.token_hex(32)}}}"


def read_case_metadata(source_repo: Path, case_id: str) -> dict[str, Any]:
    """Read only public benchmark metadata from the pinned sparse checkout."""

    if _CASE_RE.fullmatch(case_id) is None:
        raise TargetRunnerError("invalid canonical XBEN case ID")
    path = source_repo.expanduser().resolve(strict=True) / "benchmarks" / case_id / "benchmark.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TargetRunnerError("benchmark metadata is malformed")
    description = payload.get("description")
    level = payload.get("level")
    if not isinstance(description, str) or not description.strip():
        raise TargetRunnerError("benchmark description is missing")
    try:
        normalized_level = int(level)
    except (TypeError, ValueError) as exc:
        raise TargetRunnerError("benchmark level is invalid") from exc
    if normalized_level not in {1, 2, 3}:
        raise TargetRunnerError("benchmark level is invalid")
    return {"description": description.strip(), "level": normalized_level}


__all__ = [
    "BuildxBuilder",
    "PINNED_XBEN_COMMIT",
    "TargetRunnerError",
    "XbenTarget",
    "cleanup_build_cache",
    "executable_sha256",
    "make_pair_flag",
    "prepare_target",
    "read_case_metadata",
]
