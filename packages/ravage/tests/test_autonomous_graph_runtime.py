from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.runtime import (
    DockerGraphProcessBackend,
    HostGraphProcessBackend,
    PersistentGraphRuntime,
    PersistentRuntimeLimits,
    PersistentRuntimeState,
    ProcessLifecycleError,
    ProcessLimitError,
    ProcessOwnershipError,
    ProcessSession,
    ProcessStatus,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
OUTPUT_CAP = 128
CONTAINER_PID_PATH = "/tmp/ravage-process-scanner.pid"  # noqa: S108


def _runtime(
    tmp_path: Path,
    *,
    limits: PersistentRuntimeLimits | None = None,
) -> PersistentGraphRuntime:
    return PersistentGraphRuntime(
        backend=HostGraphProcessBackend(tmp_path / "workspace"),
        target_url=TARGET_URL,
        manifest_path=tmp_path / "process-manifest.json",
        limits=limits,
    )


def _read_until(
    runtime: PersistentGraphRuntime,
    *,
    name: str,
    owner_node_id: str,
    predicate: Callable[[ProcessStatus, str, str], bool],
    timeout_seconds: float = 3.0,
) -> tuple[ProcessStatus, str, str]:
    deadline = time.monotonic() + timeout_seconds
    stdout = ""
    stderr = ""
    status = ProcessStatus.RUNNING
    while time.monotonic() < deadline:
        result = runtime.read_process(
            name=name,
            owner_node_id=owner_node_id,
        )
        status = result.status
        stdout += result.stdout
        stderr += result.stderr
        if predicate(status, stdout, stderr):
            return status, stdout, stderr
        time.sleep(0.01)
    message = (
        f"process {name} did not reach expected state; "
        f"status={status.value}, stdout={stdout!r}, stderr={stderr!r}"
    )
    raise AssertionError(message)


def test_named_process_survives_turns_and_accepts_input(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    try:
        session = runtime.start_process(
            name="interactive",
            owner_node_id="node-001",
            command=(
                "python3 -u -c 'import sys; "
                'print("ready", flush=True); '
                "line=sys.stdin.readline(); "
                'print("echo:"+line.strip(), flush=True)\''
            ),
        )
        assert session.status is ProcessStatus.RUNNING
        _, initial, _ = _read_until(
            runtime,
            name="interactive",
            owner_node_id="node-001",
            predicate=lambda _status, stdout, _stderr: "ready" in stdout,
        )
        assert "ready" in initial

        written = runtime.write_process(
            name="interactive",
            owner_node_id="node-001",
            data="hello\n",
        )
        status, output, _ = _read_until(
            runtime,
            name="interactive",
            owner_node_id="node-001",
            predicate=lambda current, stdout, _stderr: (
                "echo:hello" in stdout and current is ProcessStatus.EXITED
            ),
        )

        assert written == len("hello\n")
        assert status is ProcessStatus.EXITED
        assert "echo:hello" in output
    finally:
        assert runtime.close().verified is True


def test_workers_share_files_but_not_process_namespaces(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        runtime.start_process(
            name="writer",
            owner_node_id="node-001",
            command=(
                "python3 -c 'from pathlib import Path; "
                'Path("shared.txt").write_text("cookie=abc")\''
            ),
        )
        _read_until(
            runtime,
            name="writer",
            owner_node_id="node-001",
            predicate=lambda status, _stdout, _stderr: status is ProcessStatus.EXITED,
        )
        runtime.start_process(
            name="reader",
            owner_node_id="node-002",
            command="python3 -c 'print(open(\"shared.txt\").read())'",
        )
        _, output, _ = _read_until(
            runtime,
            name="reader",
            owner_node_id="node-002",
            predicate=lambda status, stdout, _stderr: (
                status is ProcessStatus.EXITED and "cookie=abc" in stdout
            ),
        )

        assert output.strip() == "cookie=abc"
        with pytest.raises(ProcessOwnershipError):
            runtime.read_process(
                name="reader",
                owner_node_id="node-001",
            )
    finally:
        runtime.close()


def test_process_and_worker_session_caps_are_enforced(
    tmp_path: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        limits=PersistentRuntimeLimits(
            max_processes=2,
            max_processes_per_worker=1,
        ),
    )
    try:
        runtime.start_process(
            name="one",
            owner_node_id="node-001",
            command="sleep 1",
        )
        with pytest.raises(ProcessLimitError, match="worker"):
            runtime.start_process(
                name="two",
                owner_node_id="node-001",
                command="true",
            )
        runtime.start_process(
            name="other",
            owner_node_id="node-002",
            command="sleep 1",
        )
        with pytest.raises(ProcessLimitError, match="route"):
            runtime.start_process(
                name="third",
                owner_node_id="node-003",
                command="true",
            )
    finally:
        runtime.close()


def test_watchdog_enforces_timeout_without_agent_polling(
    tmp_path: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        limits=PersistentRuntimeLimits(max_process_seconds=0.2),
    )
    try:
        runtime.start_process(
            name="slow",
            owner_node_id="node-001",
            command="sleep 5",
            timeout_seconds=0.05,
        )
        time.sleep(0.15)
        result = runtime.read_process(
            name="slow",
            owner_node_id="node-001",
        )

        assert result.status is ProcessStatus.TIMED_OUT
        assert result.reason == "process_wall_time_limit_reached"
    finally:
        runtime.close()


def test_watchdog_enforces_output_cap(tmp_path: Path) -> None:
    runtime = _runtime(
        tmp_path,
        limits=PersistentRuntimeLimits(max_output_bytes=OUTPUT_CAP),
    )
    try:
        runtime.start_process(
            name="noisy",
            owner_node_id="node-001",
            command="python3 -c 'print(\"x\" * 10000)'",
        )
        status, stdout, _ = _read_until(
            runtime,
            name="noisy",
            owner_node_id="node-001",
            predicate=lambda current, _stdout, _stderr: current is ProcessStatus.OUTPUT_LIMIT,
        )

        assert status is ProcessStatus.OUTPUT_LIMIT
        assert len(stdout.encode()) <= OUTPUT_CAP
    finally:
        runtime.close()


def test_cleanup_stops_live_processes_and_writes_receipt(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.start_process(
        name="live",
        owner_node_id="node-001",
        command="sleep 5",
    )

    receipt = runtime.close()
    repeated = runtime.close()

    assert receipt.verified is True
    assert receipt.processes_before == ("live",)
    assert receipt.processes_after == ()
    assert repeated == receipt
    assert runtime.state.sessions["live"].status is ProcessStatus.STOPPED
    manifest = json.loads((tmp_path / "process-manifest.json").read_text(encoding="utf-8"))
    assert manifest["cleanup_receipts"][-1]["verified"] is True


def test_resume_marks_unreattachable_process_lost_and_fails_closed(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "process-manifest.json"
    state = PersistentRuntimeState(
        target_url=TARGET_URL,
        sessions={
            "orphan": ProcessSession(
                name="orphan",
                owner_node_id="node-001",
                command_digest="digest",
                status=ProcessStatus.RUNNING,
                started_at_epoch=1.0,
                timeout_seconds=30.0,
                pid=1234,
            )
        },
    )
    manifest_path.write_text(
        json.dumps(state.to_json()),
        encoding="utf-8",
    )

    resumed = PersistentGraphRuntime(
        backend=HostGraphProcessBackend(tmp_path / "workspace"),
        target_url=TARGET_URL,
        manifest_path=manifest_path,
    )

    assert resumed.state.sessions["orphan"].status is ProcessStatus.LOST
    with pytest.raises(ProcessLifecycleError, match="cleanup is required"):
        resumed.start_process(
            name="new",
            owner_node_id="node-001",
            command="true",
        )
    assert resumed.close().verified is False


def test_host_backend_never_claims_target_network_isolation(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        assert runtime.network_isolation_verified is False
    finally:
        runtime.close()


def test_host_backend_process_environment_scrubs_parent_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-secret")
    monkeypatch.setenv("RAVAGE_ARBITRARY_PARENT_SECRET", "fake-parent-secret")
    workspace = tmp_path / "workspace"
    backend = HostGraphProcessBackend(workspace)

    backend.ensure_started(TARGET_URL)
    environment = backend.process_env()

    assert "OPENAI_API_KEY" not in environment
    assert "ANTHROPIC_API_KEY" not in environment
    assert "RAVAGE_ARBITRARY_PARENT_SECRET" not in environment
    assert environment["RAVAGE_TARGET_URL"] == TARGET_URL
    assert environment["PYTHONUNBUFFERED"] == "1"
    assert environment["HOME"] == str(workspace)
    assert environment["PATH"]


def test_docker_backend_builds_resource_capped_process_group_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = DockerGraphProcessBackend(
        workspace=tmp_path / "workspace",
        scope={"in_scope": [TARGET_URL]},
        session_id="runtime-test",
    )
    captured: list[tuple[str, ...]] = []

    def capture_checked(
        argv: tuple[str, ...],
        *,
        operation: str,
    ) -> None:
        assert operation
        captured.append(argv)

    monkeypatch.setattr(
        backend.scoped_network,
        "ensure_started",
        lambda: None,
    )
    monkeypatch.setattr(
        backend.scoped_network,
        "container_url",
        lambda target_url: target_url.replace(
            "127.0.0.1:8765",
            "ravage-target:40000",
        ),
    )
    monkeypatch.setattr(
        "ravage.agent_core.autonomous_graph.runtime._run_checked",
        capture_checked,
    )

    backend.ensure_started(TARGET_URL)
    process_argv = backend.command_argv("sleep 5", "scanner")

    container_argv = captured[0]
    assert "--network" in container_argv
    assert "--cpus" in container_argv
    assert "--memory" in container_argv
    assert "--pids-limit" in container_argv
    assert container_argv[container_argv.index("--read-only")] == "--read-only"
    assert process_argv[:3] == ("docker", "exec", "-i")
    assert "setsid sh -lc" in process_argv[-1]
    assert CONTAINER_PID_PATH in process_argv[-1]
    assert backend.network_isolation_verified is True
