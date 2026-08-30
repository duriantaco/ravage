from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

import tools.improvement_lab.offline_executor as executor
from tools.improvement_lab.offline_executor import (
    MAX_TIMEOUT_SECONDS,
    OfflineExecutionError,
    execute_offline_job,
    freeze_output_tree,
)
from tools.improvement_lab.workspace import (
    CandidateWorkspace,
    OfflineContainerJob,
    build_offline_container_job,
    capture_source_state,
    directory_tree_digest,
    materialize_candidate,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _git(root: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ("git", "-C", str(root), *args),  # noqa: S607
        check=True,
        capture_output=True,
    )


def _candidate(tmp_path: Path) -> CandidateWorkspace:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init")
    _git(source, "config", "user.email", "executor@example.invalid")
    _git(source, "config", "user.name", "Executor Test")
    (source / "app.txt").write_text("candidate\n", encoding="utf-8")
    _git(source, "add", "app.txt")
    _git(source, "commit", "-m", "candidate")
    state = capture_source_state(source)
    return materialize_candidate(
        source_root=source,
        lab_root=tmp_path / "lab",
        candidate_id="candidate-1",
        base_commit=state.head_commit,
        patch=b"",
    )


def _candidate_view(root: Path) -> None:
    content = b'{"capsules":[],"schema_version":"ravage.improvement-corpus.v1"}\n'
    artifact_id = f"artifact_{'c' * 24}"
    filename = f"{artifact_id}-development_corpus.json"
    (root / filename).write_bytes(content)
    (root / ".improvement-candidate-view.json").write_text(
        json.dumps(
            {
                "archive_id": f"archive_{'d' * 24}",
                "entries": [
                    {
                        "artifact_id": artifact_id,
                        "content_object": f"sha256:{hashlib.sha256(content).hexdigest()}",
                        "filename": filename,
                        "kind": "development_corpus",
                    }
                ],
                "schema_version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def _job(tmp_path: Path) -> OfflineContainerJob:
    candidate = _candidate(tmp_path)
    episodes = tmp_path / "episodes"
    trusted_tests = tmp_path / "trusted-tests"
    episodes.mkdir()
    trusted_tests.mkdir()
    _candidate_view(episodes)
    return build_offline_container_job(
        image=f"example.invalid/evaluator@sha256:{'a' * 64}",
        candidate=candidate,
        episodes_root=episodes,
        trusted_tests_root=trusted_tests,
        expected_trusted_tests_digest=directory_tree_digest(trusted_tests),
        output_root=tmp_path / "output",
        command=("python", "-m", "pytest", "-q"),
    )


class _FakeProcess:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        timed_out: bool = False,
        on_wait: Callable[[], None] | None = None,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = None
        self._exit_code = exit_code
        self._timed_out = timed_out
        self._on_wait = on_wait
        self.terminated = False
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        if self._timed_out:
            raise subprocess.TimeoutExpired(("docker", "run"), timeout or 0.0)
        if self._on_wait is not None:
            self._on_wait()
            self._on_wait = None
        self.returncode = self._exit_code
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self._timed_out = False
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self._timed_out = False
        self.returncode = -9


class _FakeRunner:
    def __init__(self, *processes: _FakeProcess) -> None:
        self.processes = list(processes)
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def __call__(self, argv: tuple[str, ...], **kwargs: object) -> _FakeProcess:
        self.calls.append((argv, kwargs))
        return self.processes.pop(0)


def test_execute_records_exit_and_frozen_output_without_raw_logs(tmp_path: Path) -> None:
    job = _job(tmp_path)
    expected_exit_code = 7

    def write_output() -> None:
        (job.output_root / "report.json").write_text('{"passed":true}\n', encoding="utf-8")

    runner = _FakeRunner(
        _FakeProcess(
            exit_code=expected_exit_code,
            stdout=b"bounded stdout",
            stderr=b"bounded stderr",
            on_wait=write_output,
        )
    )

    result = execute_offline_job(job, timeout_seconds=20, runner=runner)

    assert result.status == "exited"
    assert result.exit_code == expected_exit_code
    assert result.output_file_count == 1
    assert result.output_bytes == len(b'{"passed":true}\n')
    assert result.output_digest == freeze_output_tree(job.output_root).digest
    assert result.stdout_digest.startswith("sha256:")
    assert result.stderr_digest.startswith("sha256:")
    assert not hasattr(result, "stdout")
    assert runner.calls[0][0] == job.argv
    assert runner.calls[0][1]["shell"] is False


def test_timeout_cleans_only_the_validated_container_name(tmp_path: Path) -> None:
    job = _job(tmp_path)
    primary = _FakeProcess(timed_out=True, stdout=b"before timeout")
    runner = _FakeRunner(primary, _FakeProcess(exit_code=0))

    result = execute_offline_job(job, timeout_seconds=1, runner=runner)

    assert result.status == "timed_out"
    assert result.exit_code is None
    assert primary.terminated
    assert runner.calls[1][0] == (
        "docker",
        "rm",
        "--force",
        "--",
        "ravage-improvement-check",
    )
    assert runner.calls[1][1]["shell"] is False


def test_executor_rejects_tampered_job_before_calling_runner(tmp_path: Path) -> None:
    job = _job(tmp_path)
    argv = list(job.argv)
    argv[argv.index("--network") + 1] = "bridge"
    runner = _FakeRunner()

    with pytest.raises(OfflineExecutionError, match="hardened job contract"):
        execute_offline_job(replace(job, argv=tuple(argv)), runner=runner)

    assert runner.calls == []


def test_executor_revalidates_candidate_identity_before_launch(tmp_path: Path) -> None:
    job = _job(tmp_path)
    (job.candidate_workspace / "app.txt").write_text("substituted\n", encoding="utf-8")
    runner = _FakeRunner()

    with pytest.raises(OfflineExecutionError, match="inputs changed"):
        execute_offline_job(job, runner=runner)

    assert runner.calls == []


def test_executor_refuses_overlapping_and_symlink_roots(tmp_path: Path) -> None:
    job = _job(tmp_path)
    runner = _FakeRunner()

    with pytest.raises(OfflineExecutionError, match="disjoint"):
        execute_offline_job(replace(job, output_root=job.episodes_root), runner=runner)

    linked = tmp_path / "linked-episodes"
    linked.symlink_to(job.episodes_root, target_is_directory=True)
    with pytest.raises(OfflineExecutionError, match="symlinks"):
        execute_offline_job(replace(job, episodes_root=linked), runner=runner)

    assert runner.calls == []


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "sparse"])
def test_freeze_rejects_unsafe_output_entries(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "output"
    root.mkdir()
    source = root / "source"
    source.write_bytes(b"safe")
    unsafe = root / "unsafe"
    if kind == "symlink":
        unsafe.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, unsafe)
    elif kind == "fifo":
        os.mkfifo(unsafe)
    else:
        with unsafe.open("wb") as stream:
            stream.seek(1024 * 1024)
            stream.write(b"x")

    with pytest.raises(OfflineExecutionError):
        freeze_output_tree(root)


def test_freeze_enforces_entry_depth_and_byte_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "output"
    root.mkdir()
    (root / "one").write_bytes(b"1")
    (root / "two").write_bytes(b"2")
    monkeypatch.setattr(executor, "_MAX_OUTPUT_ENTRIES", 1)
    with pytest.raises(OfflineExecutionError, match="too many"):
        freeze_output_tree(root)

    monkeypatch.setattr(executor, "_MAX_OUTPUT_ENTRIES", 10)
    nested = root / "nested"
    nested.mkdir()
    (nested / "deep").write_bytes(b"3")
    monkeypatch.setattr(executor, "_MAX_OUTPUT_DEPTH", 1)
    with pytest.raises(OfflineExecutionError, match="depth"):
        freeze_output_tree(root)

    monkeypatch.setattr(executor, "_MAX_OUTPUT_DEPTH", 16)
    monkeypatch.setattr(executor, "_MAX_OUTPUT_FILE_BYTES", 0)
    with pytest.raises(OfflineExecutionError, match="file exceeds"):
        freeze_output_tree(root)


def test_timeout_and_stream_capture_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job(tmp_path)
    monkeypatch.setattr(executor, "_STREAM_LIMIT_BYTES", 4)
    runner = _FakeRunner(_FakeProcess(stdout=b"longer than four bytes"))

    result = execute_offline_job(job, runner=runner)

    expected = hashlib.sha256(b"ravage-offline-stream-v1\0long\0truncated").hexdigest()
    assert result.stdout_digest == f"sha256:{expected}"
    with pytest.raises(OfflineExecutionError, match="timeout"):
        execute_offline_job(job, timeout_seconds=MAX_TIMEOUT_SECONDS + 1, runner=_FakeRunner())
