from __future__ import annotations

import subprocess

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_timeout_hygiene import (
    FrontierTimeoutHygieneRuntime,
    TimeoutCleanupRecord,
    cleanup_timed_out_container,
    pending_timeout_recovery,
    remember_timeout_recovery,
    resolve_timeout_recoveries,
    timeout_recovery_context,
    timeout_recovery_message,
)
from ravage.runtime import FakeToolRuntime, ToolResult

TARGET_URL = "http://127.0.0.1:8765"
SESSION_KEY = "0123456789abcdef"
CONTAINER_NAME = f"ravage-tool-{SESSION_KEY}-7"


class ClosingRuntime(FakeToolRuntime):
    def __init__(self, result: ToolResult) -> None:
        super().__init__({"run_command": result})
        self.closed = False

    def close(self) -> None:
        self.closed = True


class SequenceCommandRuntime(FakeToolRuntime):
    def __init__(self, results: list[ToolResult]) -> None:
        super().__init__()
        self.sequence = list(results)

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        self.calls.append(
            (
                "run_command",
                {
                    "command": command,
                    "target_url": target_url,
                    "timeout_seconds": timeout_seconds,
                },
            )
        )
        return self.sequence.pop(0)


def _docker_command(
    *,
    container_name: str = CONTAINER_NAME,
    session_key: str = SESSION_KEY,
) -> tuple[str, ...]:
    return (
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--label",
        f"io.ravage.tool-session={session_key}",
        "--label",
        "io.ravage.tool-kind=tool",
        "example-image",
        "sh",
        "-lc",
        "bounded command",
    )


def _timed_out_result(command: tuple[str, ...] | None = None) -> ToolResult:
    return ToolResult(
        ok=False,
        tool="run_command",
        command=command or _docker_command(),
        exit_code=None,
        stdout="",
        stderr="",
        error="timed out after 20s",
        timed_out=True,
    )


def test_route_runtime_removes_only_the_verified_timed_out_container() -> None:
    cleanup_calls: list[tuple[str, ...]] = []
    records: list[TimeoutCleanupRecord] = []

    def cleanup_runner(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        cleanup_calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=f"{CONTAINER_NAME}\n", stderr="")

    inner = ClosingRuntime(_timed_out_result())
    runtime = FrontierTimeoutHygieneRuntime(
        inner,
        cleanup_runner=cleanup_runner,
        on_cleanup=records.append,
    )

    result = runtime.run_command(
        command="bounded command",
        target_url=TARGET_URL,
        timeout_seconds=20,
    )
    runtime.close()

    expected_cleanup = ("docker", "rm", "--force", CONTAINER_NAME)
    assert cleanup_calls == [expected_cleanup, expected_cleanup, expected_cleanup]
    assert len(records) == len(cleanup_calls)
    assert all(record.status == "removed" for record in records)
    assert all(record.verified is True for record in records)
    assert all(record.container_name == CONTAINER_NAME for record in records)
    assert result.timed_out is True
    assert "cleanup_status=removed" in str(result.error)
    assert "one cheap, previously terminating liveness/calibration control" in str(result.error)
    assert inner.closed is True


def test_unverified_docker_identity_is_never_passed_to_docker_rm() -> None:
    cleanup_calls: list[tuple[str, ...]] = []

    def cleanup_runner(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        cleanup_calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    command = _docker_command(session_key="fedcba9876543210")
    record = cleanup_timed_out_container(
        command,
        cleanup_runner=cleanup_runner,
    )

    assert cleanup_calls == []
    assert record.status == "identity_unverified"
    assert record.verified is False
    assert "Do not launch another tool workload" in timeout_recovery_message(record)


def test_unverified_docker_identity_blocks_later_tool_workloads() -> None:
    cleanup_calls: list[tuple[str, ...]] = []
    invalid_timeout = _timed_out_result(_docker_command(session_key="fedcba9876543210"))
    inner = ClosingRuntime(invalid_timeout)

    def cleanup_runner(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        cleanup_calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    runtime = FrontierTimeoutHygieneRuntime(
        inner,
        cleanup_runner=cleanup_runner,
    )

    first = runtime.run_command(command="first", target_url=TARGET_URL)
    second = runtime.run_command(command="second", target_url=TARGET_URL)

    assert first.timed_out is True
    assert second.ok is False
    assert second.command == ("frontier-timeout-hygiene",)
    assert "blocked a new workload" in str(second.error)
    assert len(inner.calls) == 1
    assert cleanup_calls == []


def test_late_container_name_is_reaped_again_before_the_next_tool_action() -> None:
    cleanup_calls: list[tuple[str, ...]] = []
    cleanup_results = [
        subprocess.CompletedProcess(
            (),
            1,
            stdout="",
            stderr=f"No such container: {CONTAINER_NAME}",
        ),
        subprocess.CompletedProcess((), 0, stdout=CONTAINER_NAME, stderr=""),
    ]
    inner = SequenceCommandRuntime(
        [
            _timed_out_result(),
            ToolResult(
                ok=True,
                tool="run_command",
                command=("sh", "-lc", "liveness"),
                exit_code=0,
                stdout="target responded",
                stderr="",
            ),
        ]
    )

    def cleanup_runner(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        cleanup_calls.append(argv)
        completed = cleanup_results.pop(0)
        return subprocess.CompletedProcess(
            argv,
            completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    runtime = FrontierTimeoutHygieneRuntime(
        inner,
        cleanup_runner=cleanup_runner,
    )

    first = runtime.run_command(command="timed action", target_url=TARGET_URL)
    second = runtime.run_command(command="liveness", target_url=TARGET_URL)

    assert first.timed_out is True
    assert second.ok is True
    assert len(inner.calls) == len(cleanup_calls)
    assert cleanup_calls == [
        ("docker", "rm", "--force", CONTAINER_NAME),
        ("docker", "rm", "--force", CONTAINER_NAME),
    ]
    assert [record.status for record in runtime.cleanup_records] == [
        "already_absent",
        "removed",
    ]


def test_non_docker_timeout_requires_no_container_cleanup() -> None:
    cleanup_calls: list[tuple[str, ...]] = []

    def cleanup_runner(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        cleanup_calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    record = cleanup_timed_out_container(
        ("sh", "-lc", "bounded command"),
        cleanup_runner=cleanup_runner,
    )

    assert cleanup_calls == []
    assert record.status == "not_applicable"
    assert record.verified is True


def test_already_absent_container_is_a_verified_cleanup_outcome() -> None:
    def cleanup_runner(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="",
            stderr=f"Error: No such container: {CONTAINER_NAME}",
        )

    record = cleanup_timed_out_container(
        _docker_command(),
        cleanup_runner=cleanup_runner,
    )

    assert record.status == "already_absent"
    assert record.verified is True


def test_non_timeout_result_is_unchanged_and_does_not_run_cleanup() -> None:
    original = ToolResult(
        ok=True,
        tool="run_command",
        command=_docker_command(),
        exit_code=0,
        stdout="target response",
        stderr="",
    )

    def unexpected_cleanup(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        message = f"cleanup must not run for {argv}"
        raise AssertionError(message)

    runtime = FrontierTimeoutHygieneRuntime(
        FakeToolRuntime({"run_command": original}),
        cleanup_runner=unexpected_cleanup,
    )

    result = runtime.run_command(
        command="bounded command",
        target_url=TARGET_URL,
    )

    assert result is original


def test_timeout_recovery_memory_survives_handoff_until_resolved() -> None:
    state = AgentState()
    record = TimeoutCleanupRecord.create(
        container_name=CONTAINER_NAME,
        session_key=SESSION_KEY,
        status="removed",
        verified=True,
        returncode=0,
    )

    remember_timeout_recovery(state, record)

    assert pending_timeout_recovery(state) == record
    assert timeout_recovery_context(state) == {
        "cleanup_status": "removed",
        "cleanup_verified": True,
        "requirement": (
            "Before another extraction or multi-payload batch, run one cheap, previously "
            "terminating liveness/calibration control with a smaller explicit timeout. "
            "Resume only after a fresh target response."
        ),
    }

    assert resolve_timeout_recoveries(state) == (record.fingerprint,)
    assert pending_timeout_recovery(state) is None
    assert resolve_timeout_recoveries(state) == ()
