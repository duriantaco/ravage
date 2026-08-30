# Runtime errors carry operation-specific process/session context.
# ruff: noqa: EM101, EM102, S607, TRY003

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from ravage.runtime.common import (
    assert_http_url,
    assert_local_url,
    assert_tool_target_url,
    child_process_environment,
    safe_command,
)
from ravage.runtime.scoped_network import ScopedDockerNetwork
from ravage.runtime.types import CONTAINER_WORKDIR, DEFAULT_TOOL_IMAGE

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path
    from typing import BinaryIO

_MANIFEST_VERSION = 1
_SESSION_NAME = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z")
_ACTIVE_PROCESS_STATUSES = frozenset({"running", "starting"})


class ProcessRuntimeError(RuntimeError):
    """Base error for persistent graph process runtime failures."""


class ProcessSessionNotFoundError(ProcessRuntimeError):
    """Raised when a process name is outside the route manifest."""


class ProcessOwnershipError(ProcessRuntimeError):
    """Raised when one worker addresses another worker's process."""


class ProcessLimitError(ProcessRuntimeError):
    """Raised before a process would exceed a configured resource cap."""


class ProcessLifecycleError(ProcessRuntimeError):
    """Raised when a named process operation is invalid for its status."""


class ProcessStatus(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    EXITED = "exited"
    STOPPED = "stopped"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT = "output_limit"
    LOST = "lost"
    FAILED = "failed"


@dataclass(frozen=True)
class PersistentRuntimeLimits:
    max_processes: int = 8
    max_processes_per_worker: int = 3
    max_process_seconds: float = 120.0
    max_output_bytes: int = 256_000
    max_read_bytes: int = 32_000
    max_input_bytes: int = 64_000
    max_command_chars: int = 16_000
    stop_grace_seconds: float = 1.0
    docker_cpus: float = 1.0
    docker_memory: str = "768m"
    docker_pids_limit: int = 256

    def __post_init__(self) -> None:
        positive = {
            "max_processes": self.max_processes,
            "max_processes_per_worker": self.max_processes_per_worker,
            "max_process_seconds": self.max_process_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_read_bytes": self.max_read_bytes,
            "max_input_bytes": self.max_input_bytes,
            "max_command_chars": self.max_command_chars,
            "stop_grace_seconds": self.stop_grace_seconds,
            "docker_cpus": self.docker_cpus,
            "docker_pids_limit": self.docker_pids_limit,
        }
        for name, value in positive.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.max_processes_per_worker > self.max_processes:
            raise ValueError("max_processes_per_worker cannot exceed max_processes")
        if not self.docker_memory.strip():
            raise ValueError("docker_memory is required")


class ProcessBackend(Protocol):
    workspace: Path
    network_isolation_verified: bool

    def ensure_started(self, target_url: str) -> None: ...

    def command_argv(
        self,
        command: str,
        session_name: str,
    ) -> tuple[str, ...]: ...

    def terminate_process(self, session_name: str) -> None: ...

    def process_cwd(self) -> Path | None: ...

    def process_env(self) -> Mapping[str, str]: ...

    def close(self) -> dict[str, object]: ...


@dataclass
class ProcessSession:
    name: str
    owner_node_id: str
    command_digest: str
    status: ProcessStatus
    started_at_epoch: float
    timeout_seconds: float
    pid: int | None = None
    exit_code: int | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdin_bytes: int = 0
    last_reason: str = "process_starting"

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "owner_node_id": self.owner_node_id,
            "command_digest": self.command_digest,
            "status": self.status.value,
            "started_at_epoch": self.started_at_epoch,
            "timeout_seconds": self.timeout_seconds,
            "pid": self.pid,
            "exit_code": self.exit_code,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdin_bytes": self.stdin_bytes,
            "last_reason": self.last_reason,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> ProcessSession:
        return cls(
            name=str(payload.get("name") or ""),
            owner_node_id=str(payload.get("owner_node_id") or ""),
            command_digest=str(payload.get("command_digest") or ""),
            status=ProcessStatus(str(payload.get("status") or "")),
            started_at_epoch=_number(payload, "started_at_epoch"),
            timeout_seconds=_number(payload, "timeout_seconds"),
            pid=_optional_int(payload, "pid"),
            exit_code=_optional_int(payload, "exit_code"),
            stdout_bytes=_integer(payload, "stdout_bytes"),
            stderr_bytes=_integer(payload, "stderr_bytes"),
            stdin_bytes=_integer(payload, "stdin_bytes"),
            last_reason=str(payload.get("last_reason") or ""),
        )


@dataclass
class PersistentRuntimeState:
    target_url: str
    sessions: dict[str, ProcessSession] = field(default_factory=dict)
    cleanup_receipts: list[dict[str, object]] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        return {
            "version": _MANIFEST_VERSION,
            "target_url": self.target_url,
            "sessions": [self.sessions[name].to_json() for name in sorted(self.sessions)],
            "cleanup_receipts": list(self.cleanup_receipts),
        }

    @classmethod
    def from_json(
        cls,
        payload: Mapping[str, object],
    ) -> PersistentRuntimeState:
        if _integer(payload, "version") != _MANIFEST_VERSION:
            raise ProcessRuntimeError("unsupported process manifest version")
        raw_sessions = payload.get("sessions")
        raw_receipts = payload.get("cleanup_receipts")
        if not isinstance(raw_sessions, list):
            raise ProcessRuntimeError("process manifest sessions must be a list")
        if not isinstance(raw_receipts, list):
            raise ProcessRuntimeError("process manifest cleanup_receipts must be a list")
        sessions: dict[str, ProcessSession] = {}
        for raw in raw_sessions:
            if not isinstance(raw, dict):
                raise ProcessRuntimeError("process manifest session must be an object")
            session = ProcessSession.from_json(raw)
            if session.name in sessions:
                raise ProcessRuntimeError(f"duplicate process session name: {session.name}")
            sessions[session.name] = session
        receipts = [dict(item) for item in raw_receipts if isinstance(item, dict)]
        state = cls(
            target_url=str(payload.get("target_url") or ""),
            sessions=sessions,
            cleanup_receipts=receipts,
        )
        state.validate()
        return state

    def validate(self) -> None:
        assert_http_url(self.target_url)
        for name, session in self.sessions.items():
            if name != session.name or not _SESSION_NAME.fullmatch(name):
                raise ProcessRuntimeError(f"invalid process session name: {name}")
            if not session.owner_node_id.strip():
                raise ProcessRuntimeError(f"process {name} owner_node_id is required")
            if not session.command_digest:
                raise ProcessRuntimeError(f"process {name} command digest is required")
            if session.timeout_seconds <= 0:
                raise ProcessRuntimeError(f"process {name} timeout must be positive")
            counts = (
                session.stdout_bytes,
                session.stderr_bytes,
                session.stdin_bytes,
            )
            if any(value < 0 for value in counts):
                raise ProcessRuntimeError(f"process {name} byte accounting cannot be negative")


@dataclass(frozen=True)
class ProcessRead:
    name: str
    status: ProcessStatus
    stdout: str
    stderr: str
    exit_code: int | None
    stdout_bytes_total: int
    stderr_bytes_total: int
    reason: str


@dataclass(frozen=True)
class RuntimeCleanupReceipt:
    verified: bool
    processes_before: tuple[str, ...]
    processes_after: tuple[str, ...]
    backend: dict[str, object]

    def to_json(self) -> dict[str, object]:
        return {
            "verified": self.verified,
            "processes_before": list(self.processes_before),
            "processes_after": list(self.processes_after),
            "backend": dict(self.backend),
        }


@dataclass
class _LiveProcess:
    process: subprocess.Popen[bytes]
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    stdout_cursor: int = 0
    stderr_cursor: int = 0
    output_limit_hit: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)
    readers: tuple[threading.Thread, ...] = ()
    monitor: threading.Thread | None = None


class PersistentGraphRuntime:
    """
    One route-owned process runtime with named worker sessions.

    Process handles stay live between model turns. The manifest is durable, and
    process handles that cannot be safely reattached after restart are marked
    lost rather than silently replayed.
    """

    def __init__(
        self,
        *,
        backend: ProcessBackend,
        target_url: str,
        manifest_path: Path,
        limits: PersistentRuntimeLimits | None = None,
        clock: Callable[[], float] = time.time,
        allow_remote_target: bool = False,
    ) -> None:
        assert_tool_target_url(
            target_url,
            allow_remote_target=allow_remote_target,
        )
        self.backend = backend
        self.target_url = target_url
        self.allow_remote_target = allow_remote_target
        self.manifest_path = manifest_path
        self.limits = limits or PersistentRuntimeLimits()
        self._clock = clock
        self._lock = threading.RLock()
        self._live: dict[str, _LiveProcess] = {}
        self._closed = False
        self.state = self._load_or_start()
        self._resume_lost_names = self._mark_unreattachable_processes_lost()
        self._persist()

    @property
    def workspace(self) -> Path:
        return self.backend.workspace

    @property
    def network_isolation_verified(self) -> bool:
        return self.backend.network_isolation_verified

    def start_process(
        self,
        *,
        name: str,
        owner_node_id: str,
        command: str,
        timeout_seconds: float | None = None,
    ) -> ProcessSession:
        with self._lock:
            self._require_open()
            if self._resume_lost_names:
                names = ", ".join(self._resume_lost_names)
                raise ProcessLifecycleError(
                    "runtime resume contains unreattachable processes; "
                    f"cleanup is required before new work: {names}"
                )
            _validate_session_name(name)
            if not owner_node_id.strip():
                raise ProcessLifecycleError("owner_node_id is required")
            if name in self.state.sessions:
                raise ProcessLifecycleError(f"process session name cannot be reused: {name}")
            if len(self.state.sessions) >= self.limits.max_processes:
                raise ProcessLimitError("route process session limit reached")
            owner_count = sum(
                session.owner_node_id == owner_node_id for session in self.state.sessions.values()
            )
            if owner_count >= self.limits.max_processes_per_worker:
                raise ProcessLimitError(f"worker process session limit reached: {owner_node_id}")
            canonical_command = safe_command(command)
            if len(canonical_command) > self.limits.max_command_chars:
                raise ProcessLimitError("process command exceeds character cap")
            timeout = (
                self.limits.max_process_seconds if timeout_seconds is None else timeout_seconds
            )
            if timeout <= 0 or timeout > self.limits.max_process_seconds:
                raise ProcessLimitError("process timeout exceeds the route process cap")

            self.backend.ensure_started(self.target_url)
            session = ProcessSession(
                name=name,
                owner_node_id=owner_node_id,
                command_digest=_digest(canonical_command),
                status=ProcessStatus.STARTING,
                started_at_epoch=self._clock(),
                timeout_seconds=timeout,
            )
            self.state.sessions[name] = session
            self._persist()
            try:
                process = subprocess.Popen(  # noqa: S603
                    self.backend.command_argv(canonical_command, name),
                    cwd=self.backend.process_cwd(),
                    env=dict(self.backend.process_env()),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except OSError as exc:
                session.status = ProcessStatus.FAILED
                session.last_reason = f"process_start_failed:{exc}"
                self._persist()
                raise ProcessLifecycleError(f"cannot start process {name}: {exc}") from exc
            live = _LiveProcess(process=process)
            session.pid = process.pid
            session.status = ProcessStatus.RUNNING
            session.last_reason = "process_running"
            self._live[name] = live
            live.readers = self._start_readers(name, live)
            live.monitor = threading.Thread(
                target=self._monitor_process,
                args=(name,),
                daemon=True,
                name=f"ravage-{name}-watchdog",
            )
            live.monitor.start()
            self._persist()
            return ProcessSession.from_json(session.to_json())

    def read_process(
        self,
        *,
        name: str,
        owner_node_id: str,
        max_bytes: int | None = None,
    ) -> ProcessRead:
        with self._lock:
            session = self._owned_session(name, owner_node_id)
            self._refresh(name)
            limit = max_bytes or self.limits.max_read_bytes
            if limit <= 0 or limit > self.limits.max_read_bytes:
                raise ProcessLimitError("process read exceeds per-read cap")
            live = self._live.get(name)
            stdout = b""
            stderr = b""
            if live is not None:
                with live.lock:
                    stdout_end = min(
                        len(live.stdout),
                        live.stdout_cursor + limit,
                    )
                    stdout = bytes(live.stdout[live.stdout_cursor : stdout_end])
                    live.stdout_cursor = stdout_end
                    remaining = max(limit - len(stdout), 0)
                    stderr_end = min(
                        len(live.stderr),
                        live.stderr_cursor + remaining,
                    )
                    stderr = bytes(live.stderr[live.stderr_cursor : stderr_end])
                    live.stderr_cursor = stderr_end
            self._persist()
            return ProcessRead(
                name=name,
                status=session.status,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=session.exit_code,
                stdout_bytes_total=session.stdout_bytes,
                stderr_bytes_total=session.stderr_bytes,
                reason=session.last_reason,
            )

    def write_process(
        self,
        *,
        name: str,
        owner_node_id: str,
        data: str,
    ) -> int:
        with self._lock:
            session = self._owned_session(name, owner_node_id)
            self._refresh(name)
            if session.status is not ProcessStatus.RUNNING:
                raise ProcessLifecycleError(
                    f"process {name} is not running: {session.status.value}"
                )
            encoded = data.encode()
            if (
                len(encoded) > self.limits.max_input_bytes
                or session.stdin_bytes + len(encoded) > self.limits.max_input_bytes
            ):
                raise ProcessLimitError("process stdin exceeds byte cap")
            live = self._live[name]
            stream = live.process.stdin
            if stream is None:
                raise ProcessLifecycleError(f"process {name} stdin is unavailable")
            try:
                stream.write(encoded)
                stream.flush()
            except (BrokenPipeError, OSError) as exc:
                self._refresh(name)
                raise ProcessLifecycleError(f"cannot write process {name}: {exc}") from exc
            session.stdin_bytes += len(encoded)
            session.last_reason = "process_input_written"
            self._persist()
            return len(encoded)

    def stop_process(
        self,
        *,
        name: str,
        owner_node_id: str,
        reason: str = "worker_requested_stop",
    ) -> ProcessSession:
        with self._lock:
            session = self._owned_session(name, owner_node_id)
            self._terminate_live(
                name,
                terminal_status=ProcessStatus.STOPPED,
                reason=reason,
            )
            self._persist()
            return ProcessSession.from_json(session.to_json())

    def close(self) -> RuntimeCleanupReceipt:
        with self._lock:
            if self._closed:
                receipt = self.state.cleanup_receipts[-1]
                return RuntimeCleanupReceipt(
                    verified=receipt.get("verified") is True,
                    processes_before=tuple(
                        str(item) for item in receipt.get("processes_before", [])
                    ),
                    processes_after=tuple(str(item) for item in receipt.get("processes_after", [])),
                    backend=(
                        dict(receipt.get("backend", {}))
                        if isinstance(receipt.get("backend"), dict)
                        else {}
                    ),
                )
            before = tuple(sorted(self._live))
            for name in tuple(self._live):
                self._terminate_live(
                    name,
                    terminal_status=ProcessStatus.STOPPED,
                    reason="runtime_cleanup",
                )
            backend_receipt = self.backend.close()
            after = tuple(sorted(self._live))
            backend_verified = backend_receipt.get("verified") is True
            stale_cleanup_verified = (
                not self._resume_lost_names
                or backend_receipt.get("stale_process_cleanup_verified") is True
            )
            receipt = RuntimeCleanupReceipt(
                verified=(not after and backend_verified and stale_cleanup_verified),
                processes_before=before,
                processes_after=after,
                backend=backend_receipt,
            )
            self.state.cleanup_receipts.append(receipt.to_json())
            self._closed = True
            self._persist()
            return receipt

    def _load_or_start(self) -> PersistentRuntimeState:
        if not self.manifest_path.exists():
            return PersistentRuntimeState(target_url=self.target_url)
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProcessRuntimeError(f"cannot read persistent runtime manifest: {exc}") from exc
        if not isinstance(payload, dict):
            raise ProcessRuntimeError("persistent runtime manifest must be an object")
        state = PersistentRuntimeState.from_json(payload)
        if state.target_url != self.target_url:
            raise ProcessRuntimeError("persistent runtime target does not match requested target")
        return state

    def _mark_unreattachable_processes_lost(self) -> tuple[str, ...]:
        lost: list[str] = []
        for session in self.state.sessions.values():
            if session.status.value in _ACTIVE_PROCESS_STATUSES:
                session.status = ProcessStatus.LOST
                session.exit_code = None
                session.last_reason = "process_handle_not_reattachable_after_resume"
                lost.append(session.name)
        return tuple(sorted(lost))

    def _start_readers(
        self,
        name: str,
        live: _LiveProcess,
    ) -> tuple[threading.Thread, ...]:
        streams = (
            ("stdout", live.process.stdout),
            ("stderr", live.process.stderr),
        )
        readers: list[threading.Thread] = []
        for stream_name, stream in streams:
            if stream is None:
                continue
            reader = threading.Thread(
                target=self._pump_output,
                args=(name, live, stream_name, stream),
                daemon=True,
                name=f"ravage-{name}-{stream_name}",
            )
            reader.start()
            readers.append(reader)
        return tuple(readers)

    def _pump_output(
        self,
        name: str,
        live: _LiveProcess,
        stream_name: str,
        stream: BinaryIO,
    ) -> None:
        while True:
            try:
                chunk = os.read(stream.fileno(), 4096)
            except OSError:
                break
            if not chunk:
                break
            with live.lock:
                total = len(live.stdout) + len(live.stderr)
                remaining = max(self.limits.max_output_bytes - total, 0)
                accepted = chunk[:remaining]
                target = live.stdout if stream_name == "stdout" else live.stderr
                target.extend(accepted)
                if len(chunk) > remaining:
                    live.output_limit_hit = True
                    with suppress(OSError):
                        live.process.terminate()
                    break
            with self._lock:
                session = self.state.sessions.get(name)
                if session is not None:
                    session.stdout_bytes = len(live.stdout)
                    session.stderr_bytes = len(live.stderr)

    def _monitor_process(self, name: str) -> None:
        while True:
            time.sleep(0.02)
            with self._lock:
                if name not in self._live:
                    return
                self._refresh(name)
                session = self.state.sessions[name]
                if session.status is not ProcessStatus.RUNNING:
                    self._persist()
                    return

    def _refresh(self, name: str) -> None:
        session = self.state.sessions[name]
        live = self._live.get(name)
        if live is None:
            return
        if (
            session.status is ProcessStatus.RUNNING
            and self._clock() - session.started_at_epoch >= session.timeout_seconds
        ):
            self._terminate_live(
                name,
                terminal_status=ProcessStatus.TIMED_OUT,
                reason="process_wall_time_limit_reached",
            )
            return
        if live.output_limit_hit:
            self._terminate_live(
                name,
                terminal_status=ProcessStatus.OUTPUT_LIMIT,
                reason="process_output_limit_reached",
            )
            return
        exit_code = live.process.poll()
        if exit_code is not None and session.status is ProcessStatus.RUNNING:
            for reader in live.readers:
                reader.join(timeout=0.1)
            session.status = ProcessStatus.EXITED
            session.exit_code = exit_code
            session.stdout_bytes = len(live.stdout)
            session.stderr_bytes = len(live.stderr)
            session.last_reason = "process_exited"

    def _terminate_live(
        self,
        name: str,
        *,
        terminal_status: ProcessStatus,
        reason: str,
    ) -> None:
        session = self.state.sessions[name]
        live = self._live.get(name)
        if live is None:
            if session.status in {
                ProcessStatus.STARTING,
                ProcessStatus.RUNNING,
            }:
                session.status = ProcessStatus.LOST
                session.last_reason = "process_handle_missing"
            return
        process = live.process
        if process.poll() is None:
            with suppress(OSError, ProcessRuntimeError):
                self.backend.terminate_process(name)
            with suppress(OSError):
                process.terminate()
            try:
                process.wait(timeout=self.limits.stop_grace_seconds)
            except subprocess.TimeoutExpired:
                with suppress(OSError):
                    process.kill()
                with suppress(OSError):
                    process.wait(timeout=self.limits.stop_grace_seconds)
        for reader in live.readers:
            reader.join(timeout=0.2)
        session.status = terminal_status
        session.exit_code = process.poll()
        session.stdout_bytes = len(live.stdout)
        session.stderr_bytes = len(live.stderr)
        session.last_reason = " ".join(reason.strip().split())
        self._live.pop(name, None)

    def _owned_session(
        self,
        name: str,
        owner_node_id: str,
    ) -> ProcessSession:
        session = self.state.sessions.get(name)
        if session is None:
            raise ProcessSessionNotFoundError(f"unknown process session: {name}")
        if session.owner_node_id != owner_node_id:
            raise ProcessOwnershipError(f"process {name} belongs to {session.owner_node_id}")
        return session

    def _require_open(self) -> None:
        if self._closed:
            raise ProcessLifecycleError("persistent runtime is closed")

    def _persist(self) -> None:
        self.state.validate()
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.manifest_path.with_name(f".{self.manifest_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.state.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.manifest_path)


class HostGraphProcessBackend:
    """Local deterministic backend; never claim network isolation."""

    network_isolation_verified = False

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._target_url = ""

    def ensure_started(self, target_url: str) -> None:
        assert_local_url(target_url)
        if self._target_url and self._target_url != target_url:
            raise ProcessRuntimeError("host process backend target changed")
        self._target_url = target_url

    def command_argv(
        self,
        command: str,
        session_name: str,
    ) -> tuple[str, ...]:
        del session_name
        return ("sh", "-lc", safe_command(command))

    def terminate_process(self, session_name: str) -> None:
        del session_name

    def process_cwd(self) -> Path | None:
        return self.workspace

    def process_env(self) -> Mapping[str, str]:
        return child_process_environment(
            home=self.workspace,
            overrides={
                "RAVAGE_TARGET_URL": self._target_url,
                "PYTHONUNBUFFERED": "1",
            },
        )

    def close(self) -> dict[str, object]:
        return {
            "verified": True,
            "kind": "host_process_backend",
            "network_isolation_verified": False,
            "stale_process_cleanup_verified": False,
        }


class DockerGraphProcessBackend:
    """One bounded container attached only to Ravage's scoped target network."""

    network_isolation_verified = True

    def __init__(  # noqa: PLR0913 - explicit sandbox construction boundary.
        self,
        *,
        workspace: Path,
        scope: object,
        session_id: str,
        image: str = DEFAULT_TOOL_IMAGE,
        cleanup_evidence_path: str | Path | None = None,
        limits: PersistentRuntimeLimits | None = None,
        allow_remote_target: bool = False,
    ) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.image = image
        self.limits = limits or PersistentRuntimeLimits()
        self.session_id = session_id
        self.allow_remote_target = allow_remote_target
        self.container_name = f"ravage-graph-{hashlib.sha256(session_id.encode()).hexdigest()[:16]}"
        self.scoped_network = ScopedDockerNetwork(
            image=image,
            scope=scope,
            session_id=session_id,
            evidence_path=cleanup_evidence_path,
            allow_remote_target=allow_remote_target,
        )
        self._target_url = ""
        self._docker_target_url = ""
        self._started = False

    def ensure_started(self, target_url: str) -> None:
        if self._started:
            if target_url != self._target_url:
                raise ProcessRuntimeError("Docker process backend target changed")
            return
        assert_tool_target_url(
            target_url,
            allow_remote_target=self.allow_remote_target,
        )
        self.scoped_network.ensure_started()
        self._target_url = target_url
        self._docker_target_url = self.scoped_network.container_url(target_url)
        mount = f"type=bind,src={self.workspace},dst={CONTAINER_WORKDIR}"
        argv = (
            "docker",
            "run",
            "--detach",
            "--name",
            self.container_name,
            *self.scoped_network.tool_labels(),
            "--network",
            self.scoped_network.network_name,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",  # noqa: S108 - container tmpfs.
            "--cpus",
            str(self.limits.docker_cpus),
            "--memory",
            self.limits.docker_memory,
            "--pids-limit",
            str(self.limits.docker_pids_limit),
            "--mount",
            mount,
            "-w",
            CONTAINER_WORKDIR,
            "-e",
            f"RAVAGE_TARGET_URL={self._docker_target_url}",
            "-e",
            "PYTHONUNBUFFERED=1",
            self.image,
            "sh",
            "-lc",
            "while :; do sleep 3600; done",
        )
        try:
            _run_checked(argv, operation="start persistent graph container")
        except Exception:
            self.scoped_network.close()
            raise
        self._started = True

    def command_argv(
        self,
        command: str,
        session_name: str,
    ) -> tuple[str, ...]:
        if not self._started:
            raise ProcessLifecycleError("Docker process backend is not started")
        rewritten = self.scoped_network.rewrite_for_container(safe_command(command))
        pid_path = f"/tmp/ravage-process-{session_name}.pid"  # noqa: S108
        wrapper = (
            f"setsid sh -lc {shlex.quote(rewritten)} & child=$!; "
            f'echo "$child" > {pid_path}; wait "$child"'
        )
        return (
            "docker",
            "exec",
            "-i",
            "-e",
            f"RAVAGE_TARGET_URL={self._docker_target_url}",
            "-e",
            "PYTHONUNBUFFERED=1",
            "-w",
            CONTAINER_WORKDIR,
            self.container_name,
            "sh",
            "-lc",
            wrapper,
        )

    def terminate_process(self, session_name: str) -> None:
        if not self._started:
            return
        pid_path = f"/tmp/ravage-process-{session_name}.pid"  # noqa: S108
        script = (
            f"if [ -f {pid_path} ]; then "
            f"pid=$(cat {pid_path}); "
            'kill -TERM -- "-$pid" 2>/dev/null || '
            'kill -TERM "$pid" 2>/dev/null || true; '
            "sleep 0.1; "
            'kill -KILL -- "-$pid" 2>/dev/null || '
            'kill -KILL "$pid" 2>/dev/null || true; '
            f"rm -f {pid_path}; fi"
        )
        completed = subprocess.run(  # noqa: S603
            (
                "docker",
                "exec",
                self.container_name,
                "sh",
                "-lc",
                script,
            ),
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0 and "No such container" not in (completed.stderr or ""):
            detail = (completed.stderr or completed.stdout or "").strip()
            raise ProcessRuntimeError(f"cannot terminate Docker process {session_name}: {detail}")

    def process_cwd(self) -> Path | None:
        return self.workspace

    def process_env(self) -> Mapping[str, str]:
        return dict(os.environ)

    def close(self) -> dict[str, object]:
        removal_error = ""
        completed = subprocess.run(  # noqa: S603
            ("docker", "rm", "--force", self.container_name),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0 and "No such container" not in (completed.stderr or ""):
            removal_error = completed.stderr or completed.stdout or ("container removal failed")
        network_receipt = self.scoped_network.close()
        cleanup = network_receipt.get("cleanup")
        network_verified = isinstance(cleanup, dict) and cleanup.get("verified") is True
        self._started = False
        return {
            "verified": not removal_error and network_verified,
            "kind": "docker_process_backend",
            "network_isolation_verified": True,
            "stale_process_cleanup_verified": not removal_error,
            "container_name": self.container_name,
            "container_removal_error": removal_error,
            "network_cleanup": cleanup if isinstance(cleanup, dict) else {},
        }


def _run_checked(argv: tuple[str, ...], *, operation: str) -> None:
    completed = subprocess.run(  # noqa: S603
        argv,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ProcessRuntimeError(f"{operation} failed with exit {completed.returncode}: {detail}")


def _validate_session_name(name: str) -> None:
    if not _SESSION_NAME.fullmatch(name):
        raise ProcessLifecycleError(
            "process name must be 1-64 alphanumeric, underscore, or hyphen "
            "characters and start with an alphanumeric character"
        )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _integer(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProcessRuntimeError(f"{key} must be an integer")
    return value


def _optional_int(payload: Mapping[str, object], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProcessRuntimeError(f"{key} must be an integer or null")
    return value


def _number(payload: Mapping[str, object], key: str) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProcessRuntimeError(f"{key} must be a number")
    return float(value)


__all__ = [
    "DockerGraphProcessBackend",
    "HostGraphProcessBackend",
    "PersistentGraphRuntime",
    "PersistentRuntimeLimits",
    "PersistentRuntimeState",
    "ProcessBackend",
    "ProcessLifecycleError",
    "ProcessLimitError",
    "ProcessOwnershipError",
    "ProcessRead",
    "ProcessRuntimeError",
    "ProcessSession",
    "ProcessSessionNotFoundError",
    "ProcessStatus",
    "RuntimeCleanupReceipt",
]
