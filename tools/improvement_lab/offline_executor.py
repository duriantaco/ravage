"""Bounded host-side execution for trusted offline candidate jobs."""

# These messages are the fail-closed operator diagnostics for the executor.
# ruff: noqa: C901, EM101, EM102, PLR0913, S108, TRY003

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Protocol

from tools.improvement_lab.workspace import (
    CandidateWorkspace,
    CandidateWorkspaceError,
    GitSourceState,
    OfflineContainerJob,
    _decode_canonical_json_object,
    _verify_candidate_marker,
    _verify_candidate_view,
    directory_tree_digest,
)

if TYPE_CHECKING:
    from typing import IO


_IMAGE_RE: Final = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_NAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
_OBJECT_RE: Final = re.compile(r"[0-9a-f]{40,64}")
_SHA256_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_HEX_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}")

DEFAULT_TIMEOUT_SECONDS = 900.0
MAX_TIMEOUT_SECONDS = 3600.0
_CLEANUP_TIMEOUT_SECONDS = 30.0
_STOP_TIMEOUT_SECONDS = 5.0
_STREAM_LIMIT_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_MAX_MARKER_BYTES = 4096
_MIN_JOB_ARGV = 35

# These are deliberately module-level so evaluator deployments can lower them,
# but the executor never accepts caller-supplied values that raise the bounds.
_MAX_OUTPUT_ENTRIES = 4096
_MAX_OUTPUT_DEPTH = 16
_MAX_OUTPUT_FILE_BYTES = 16 * 1024 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


class OfflineExecutionError(RuntimeError):
    """Raised when an offline job cannot be executed or frozen safely."""


@dataclass(frozen=True)
class FrozenOutputTree:
    """A deterministic description of a validated output tree."""

    digest: str
    file_count: int
    total_bytes: int


@dataclass(frozen=True)
class OfflineExecutionResult:
    """Externally recordable execution and output evidence without raw logs."""

    status: Literal["exited", "timed_out"]
    exit_code: int | None
    output_digest: str
    output_file_count: int
    output_bytes: int
    stdout_digest: str
    stderr_digest: str


class RunningProcess(Protocol):
    @property
    def stdout(self) -> IO[bytes] | None: ...

    @property
    def stderr(self) -> IO[bytes] | None: ...

    @property
    def returncode(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


class ProcessRunner(Protocol):
    """A Popen-compatible injectable process launcher."""

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        stdin: int,
        stdout: int,
        stderr: int,
        shell: bool,
        close_fds: bool,
    ) -> RunningProcess: ...


@dataclass
class _StreamCapture:
    stream: IO[bytes]
    digest: hashlib._Hash
    captured_bytes: int = 0
    truncated: bool = False
    error: BaseException | None = None
    thread: threading.Thread | None = None

    @classmethod
    def start(cls, stream: IO[bytes]) -> _StreamCapture:
        digest = hashlib.sha256(b"ravage-offline-stream-v1\0")
        capture = cls(stream=stream, digest=digest)
        thread = threading.Thread(target=capture._consume, daemon=True)
        capture.thread = thread
        thread.start()
        return capture

    def _consume(self) -> None:
        try:
            while chunk := self.stream.read(_READ_CHUNK_BYTES):
                remaining = _STREAM_LIMIT_BYTES - self.captured_bytes
                if remaining > 0:
                    accepted = chunk[:remaining]
                    self.digest.update(accepted)
                    self.captured_bytes += len(accepted)
                if len(chunk) > remaining:
                    self.truncated = True
        except (OSError, ValueError) as exc:  # pragma: no cover - defensive I/O boundary
            self.error = exc

    def finish(self) -> str:
        if self.thread is None:  # pragma: no cover - construction invariant
            raise OfflineExecutionError("process output stream was not started")
        self.thread.join(timeout=_STOP_TIMEOUT_SECONDS)
        if self.thread.is_alive():
            raise OfflineExecutionError("process output stream did not close")
        if self.error is not None:
            raise OfflineExecutionError("process output stream could not be read") from self.error
        digest = self.digest.copy()
        digest.update(b"\0truncated" if self.truncated else b"\0complete")
        return f"sha256:{digest.hexdigest()}"


def execute_offline_job(
    job: OfflineContainerJob,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    runner: ProcessRunner | None = None,
) -> OfflineExecutionResult:
    """Revalidate, execute, stop if needed, and freeze one offline job."""
    timeout = _validated_timeout(timeout_seconds)
    container_name = _revalidate_job(job)
    launch = runner or _default_runner
    process = _launch(
        launch,
        job.argv,
        cwd=job.candidate_workspace,
        capture_streams=True,
    )
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise OfflineExecutionError("process runner did not provide output streams")
    stdout = _StreamCapture.start(process.stdout)
    stderr = _StreamCapture.start(process.stderr)

    status: Literal["exited", "timed_out"] = "exited"
    exit_code: int | None
    try:
        exit_code = process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, TimeoutError):
        status = "timed_out"
        exit_code = None
        try:
            _clean_timed_out_container(launch, container_name, cwd=job.output_root)
        finally:
            _stop_process(process)

    stdout_digest = stdout.finish()
    stderr_digest = stderr.finish()
    frozen = freeze_output_tree(job.output_root)
    return OfflineExecutionResult(
        status=status,
        exit_code=exit_code,
        output_digest=frozen.digest,
        output_file_count=frozen.file_count,
        output_bytes=frozen.total_bytes,
        stdout_digest=stdout_digest,
        stderr_digest=stderr_digest,
    )


def freeze_output_tree(root: Path) -> FrozenOutputTree:
    """Validate and hash a bounded, stable, symlink-free output tree."""
    directory = _canonical_directory(root, label="job output")
    records: list[dict[str, object]] = []
    state = {"entries": 0, "files": 0, "bytes": 0}
    try:
        _freeze_directory(
            directory,
            root=directory,
            depth=0,
            records=records,
            state=state,
        )
    except OfflineExecutionError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OfflineExecutionError("cannot freeze job output") from exc
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return FrozenOutputTree(
        digest=f"sha256:{hashlib.sha256(encoded).hexdigest()}",
        file_count=state["files"],
        total_bytes=state["bytes"],
    )


def _validated_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OfflineExecutionError("offline timeout must be a finite number")
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise OfflineExecutionError("offline timeout is outside the allowed bound")
    return timeout


def _revalidate_job(job: OfflineContainerJob) -> str:
    if not isinstance(job, OfflineContainerJob):
        raise OfflineExecutionError("offline job has an unsupported type")
    if _IMAGE_RE.fullmatch(job.image) is None:
        raise OfflineExecutionError("offline image is not pinned by sha256 digest")
    if (
        _NAME_RE.fullmatch(job.candidate_id) is None
        or _OBJECT_RE.fullmatch(job.candidate_tree_digest) is None
        or _SHA256_RE.fullmatch(job.candidate_content_digest) is None
        or _SHA256_RE.fullmatch(job.trusted_tests_digest) is None
    ):
        raise OfflineExecutionError("offline job identity is invalid")

    roots = {
        "candidate workspace": _canonical_directory(
            job.candidate_workspace, label="candidate workspace"
        ),
        "episode directory": _canonical_directory(job.episodes_root, label="episode directory"),
        "trusted test directory": _canonical_directory(
            job.trusted_tests_root, label="trusted test directory"
        ),
        "job output": _canonical_directory(job.output_root, label="job output"),
    }
    _require_disjoint_roots(roots)
    if any(job.output_root.iterdir()):
        raise OfflineExecutionError("job output must be empty before launch")

    container_name = _validate_argv(job, roots)
    try:
        marker = _read_candidate_marker(job.candidate_workspace)
        expected = CandidateWorkspace(
            candidate_id=job.candidate_id,
            path=job.candidate_workspace,
            base_commit=str(marker["base_commit"]),
            patch_sha256=str(marker["patch_sha256"]),
            candidate_tree_digest=job.candidate_tree_digest,
            candidate_content_digest=job.candidate_content_digest,
            source_state=GitSourceState(
                root=job.candidate_workspace,
                head_commit=str(marker["base_commit"]),
                tree_digest=job.candidate_tree_digest,
                status_digest="",
                dirty_entries=0,
            ),
        )
        _verify_candidate_marker(job.candidate_workspace, expected=expected)
        _verify_candidate_view(job.episodes_root)
        if directory_tree_digest(job.trusted_tests_root) != job.trusted_tests_digest:
            raise OfflineExecutionError("trusted test tree changed before launch")
    except CandidateWorkspaceError as exc:
        raise OfflineExecutionError("offline job inputs changed before launch") from exc
    return container_name


def _read_candidate_marker(root: Path) -> dict[str, object]:
    marker = root / ".improvement-candidate.json"
    try:
        marker_stat = marker.lstat()
        if (
            stat.S_ISLNK(marker_stat.st_mode)
            or not stat.S_ISREG(marker_stat.st_mode)
            or marker_stat.st_nlink != 1
            or marker_stat.st_size > _MAX_MARKER_BYTES
        ):
            raise OfflineExecutionError("candidate marker is unsafe")
        payload = _decode_canonical_json_object(marker.read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise OfflineExecutionError("candidate marker is unreadable") from exc
    if (
        _OBJECT_RE.fullmatch(str(payload.get("base_commit") or "")) is None
        or _HEX_SHA256_RE.fullmatch(str(payload.get("patch_sha256") or "")) is None
    ):
        raise OfflineExecutionError("candidate marker identity is invalid")
    return payload


def _validate_argv(job: OfflineContainerJob, roots: dict[str, Path]) -> str:
    argv = job.argv
    invalid_item = any(
        not isinstance(item, str) or not item or "\0" in item for item in argv
    )
    if len(argv) < _MIN_JOB_ARGV or invalid_item:
        raise OfflineExecutionError("offline argv is invalid")
    container_name = argv[5]
    if _NAME_RE.fullmatch(container_name) is None:
        raise OfflineExecutionError("offline container name is invalid")
    uid = os.getuid() or 65532
    gid = os.getgid() or 65532
    expected = (
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--name",
        container_name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--pids-limit",
        "256",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--user",
        f"{uid}:{gid}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=512m",
        "--mount",
        f"type=bind,src={roots['candidate workspace']},dst=/candidate,readonly",
        "--mount",
        f"type=bind,src={roots['episode directory']},dst=/episodes,readonly",
        "--mount",
        f"type=bind,src={roots['trusted test directory']},dst=/trusted-tests,readonly",
        "--mount",
        f"type=bind,src={roots['job output']},dst=/out",
        "--workdir",
        "/candidate",
        job.image,
    )
    if argv[: len(expected)] != expected or len(argv) == len(expected):
        raise OfflineExecutionError("offline argv differs from the hardened job contract")
    return container_name


def _canonical_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise OfflineExecutionError(f"{label} must be an absolute directory")
    try:
        item_stat = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise OfflineExecutionError(f"cannot inspect {label}") from exc
    if (
        resolved != path
        or stat.S_ISLNK(item_stat.st_mode)
        or not stat.S_ISDIR(item_stat.st_mode)
    ):
        raise OfflineExecutionError(f"{label} must not use symlinks")
    return resolved


def _require_disjoint_roots(roots: dict[str, Path]) -> None:
    entries = list(roots.items())
    for index, (first_label, first) in enumerate(entries):
        for second_label, second in entries[index + 1 :]:
            if first == second or first.is_relative_to(second) or second.is_relative_to(first):
                raise OfflineExecutionError(
                    f"{first_label} and {second_label} must be disjoint"
                )


def _launch(
    runner: ProcessRunner,
    argv: tuple[str, ...],
    *,
    cwd: Path,
    capture_streams: bool,
) -> RunningProcess:
    stdout = subprocess.PIPE if capture_streams else subprocess.DEVNULL
    stderr = subprocess.PIPE if capture_streams else subprocess.DEVNULL
    try:
        return runner(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            close_fds=True,
        )
    except OSError as exc:
        raise OfflineExecutionError("offline process could not be started") from exc


def _default_runner(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    stdin: int,
    stdout: int,
    stderr: int,
    shell: bool,
    close_fds: bool,
) -> RunningProcess:
    return subprocess.Popen(  # noqa: S603
        argv,
        cwd=cwd,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        shell=shell,
        close_fds=close_fds,
        text=False,
    )


def _clean_timed_out_container(
    runner: ProcessRunner,
    container_name: str,
    *,
    cwd: Path,
) -> None:
    cleanup_argv = ("docker", "rm", "--force", "--", container_name)
    cleanup = _launch(runner, cleanup_argv, cwd=cwd, capture_streams=False)
    try:
        exit_code = cleanup.wait(timeout=_CLEANUP_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, TimeoutError) as exc:
        _stop_process(cleanup)
        raise OfflineExecutionError("timed-out container cleanup did not finish") from exc
    if exit_code != 0:
        raise OfflineExecutionError("timed-out container cleanup failed")


def _stop_process(process: RunningProcess) -> None:
    if process.returncode is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=_STOP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired, TimeoutError):
        try:
            process.kill()
            process.wait(timeout=_STOP_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired, TimeoutError):
            pass


def _freeze_directory(
    directory: Path,
    *,
    root: Path,
    depth: int,
    records: list[dict[str, object]],
    state: dict[str, int],
) -> None:
    before = directory.lstat()
    if not stat.S_ISDIR(before.st_mode):
        raise OfflineExecutionError("output directory changed while being frozen")
    entries = sorted(os.scandir(directory), key=lambda item: item.name)
    for entry in entries:
        item_depth = depth + 1
        state["entries"] += 1
        if state["entries"] > _MAX_OUTPUT_ENTRIES:
            raise OfflineExecutionError("job output contains too many entries")
        if item_depth > _MAX_OUTPUT_DEPTH:
            raise OfflineExecutionError("job output exceeds the depth bound")
        path = Path(entry.path)
        relative = path.relative_to(root).as_posix()
        item_stat = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(item_stat.st_mode):
            raise OfflineExecutionError("job output must not contain symlinks")
        if stat.S_ISDIR(item_stat.st_mode):
            records.append({"kind": "directory", "path": relative})
            _freeze_directory(
                path,
                root=root,
                depth=item_depth,
                records=records,
                state=state,
            )
            continue
        if not stat.S_ISREG(item_stat.st_mode):
            raise OfflineExecutionError("job output contains a non-regular file")
        if item_stat.st_nlink != 1:
            raise OfflineExecutionError("job output must not contain hardlinks")
        if item_stat.st_size > _MAX_OUTPUT_FILE_BYTES:
            raise OfflineExecutionError("job output file exceeds the byte bound")
        if item_stat.st_size and item_stat.st_blocks * 512 < item_stat.st_size:
            raise OfflineExecutionError("job output must not contain sparse files")
        state["bytes"] += item_stat.st_size
        if state["bytes"] > _MAX_OUTPUT_BYTES:
            raise OfflineExecutionError("job output exceeds the total byte bound")
        content_digest = _read_stable_file(path, expected=item_stat)
        state["files"] += 1
        records.append(
            {
                "kind": "file",
                "mode": stat.S_IMODE(item_stat.st_mode),
                "path": relative,
                "sha256": content_digest,
                "size": item_stat.st_size,
            }
        )
    after = directory.lstat()
    if not _same_stat(before, after, include_size=False):
        raise OfflineExecutionError("job output mutated while being frozen")


def _read_stable_file(path: Path, *, expected: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not _same_stat(expected, opened, include_size=True):
            raise OfflineExecutionError("job output mutated before it could be frozen")
        digest = hashlib.sha256()
        actual_bytes = 0
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            actual_bytes += len(chunk)
            if actual_bytes > expected.st_size or actual_bytes > _MAX_OUTPUT_FILE_BYTES:
                raise OfflineExecutionError("job output mutated while being frozen")
            digest.update(chunk)
        final = os.fstat(descriptor)
        if actual_bytes != expected.st_size or not _same_stat(expected, final, include_size=True):
            raise OfflineExecutionError("job output mutated while being frozen")
        return digest.hexdigest()
    except OSError as exc:
        raise OfflineExecutionError("job output file could not be frozen") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _same_stat(first: os.stat_result, second: os.stat_result, *, include_size: bool) -> bool:
    common = (
        first.st_dev == second.st_dev,
        first.st_ino == second.st_ino,
        first.st_mode == second.st_mode,
        first.st_nlink == second.st_nlink,
        first.st_mtime_ns == second.st_mtime_ns,
        first.st_ctime_ns == second.st_ctime_ns,
    )
    return all(common) and (not include_size or first.st_size == second.st_size)


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_TIMEOUT_SECONDS",
    "FrozenOutputTree",
    "OfflineExecutionError",
    "OfflineExecutionResult",
    "ProcessRunner",
    "execute_offline_job",
    "freeze_output_tree",
]
