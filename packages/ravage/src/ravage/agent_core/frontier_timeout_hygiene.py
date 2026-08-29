from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from ravage.agent_core.agent_state import append_unique
from ravage.runtime import ToolResult, ToolRuntime
from ravage.runtime.scoped_network import KIND_LABEL, SESSION_LABEL

if TYPE_CHECKING:
    from collections.abc import Callable

    from ravage.agent_core.agent_state import AgentState

_TIMEOUT_SIGNAL = "frontier_timeout_recoveries"
_RESOLVED_SIGNAL = "frontier_timeout_recoveries_resolved"
_MAX_SIGNAL_ITEMS = 30
_CLEANUP_TIMEOUT_SECONDS = 15
_DETAIL_CHARS = 500
_CONTAINER_NAME = re.compile(
    r"^ravage-tool-(?P<session_key>[0-9a-f]{16})-(?P<tool_index>[1-9][0-9]*)$"
)


class CleanupRunner(Protocol):
    def __call__(self, argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True)
class TimeoutCleanupRecord:
    container_name: str
    session_key: str
    status: str
    verified: bool
    returncode: int | None
    detail: str
    fingerprint: str

    @classmethod
    def create(  # noqa: PLR0913 - cleanup evidence fields stay explicit.
        cls,
        *,
        container_name: str = "",
        session_key: str = "",
        status: str,
        verified: bool,
        returncode: int | None = None,
        detail: str = "",
    ) -> TimeoutCleanupRecord:
        payload = {
            "container_name": container_name,
            "session_key": session_key,
            "status": status,
            "verified": verified,
            "returncode": returncode,
            "detail": detail[:_DETAIL_CHARS],
        }
        fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return cls(fingerprint=fingerprint, **payload)

    def to_json(self) -> dict[str, object]:
        return {
            "container_name": self.container_name,
            "session_key": self.session_key,
            "status": self.status,
            "verified": self.verified,
            "returncode": self.returncode,
            "detail": self.detail,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> TimeoutCleanupRecord:
        return cls.create(
            container_name=str(payload.get("container_name") or ""),
            session_key=str(payload.get("session_key") or ""),
            status=str(payload.get("status") or ""),
            verified=payload.get("verified") is True,
            returncode=_optional_int(payload.get("returncode")),
            detail=str(payload.get("detail") or ""),
        )


class FrontierTimeoutHygieneRuntime(ToolRuntime):
    """Reap only the route tool container named by a timed-out Docker action."""

    def __init__(
        self,
        inner: ToolRuntime,
        *,
        cleanup_runner: CleanupRunner | None = None,
        on_cleanup: Callable[[TimeoutCleanupRecord], None] | None = None,
    ) -> None:
        self.inner = inner
        self.cleanup_runner = cleanup_runner or _run_cleanup
        self.on_cleanup = on_cleanup
        self.cleanup_records: list[TimeoutCleanupRecord] = []
        self._pending_commands: dict[str, tuple[str, ...]] = {}
        self._unsafe_cleanup: TimeoutCleanupRecord | None = None

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        blocked = self._prepare_next_action(tool="run_command")
        if blocked is not None:
            return blocked
        return self._after_result(
            self.inner.run_command(
                command=command,
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )
        )

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        blocked = self._prepare_next_action(tool="run_python")
        if blocked is not None:
            return blocked
        return self._after_result(
            self.inner.run_python(
                code=code,
                target_url=target_url,
                timeout_seconds=timeout_seconds,
            )
        )

    def write_free_roam_context(self, text: str) -> None:
        self.inner.write_free_roam_context(text)

    def close(self) -> None:
        self.finalize_cleanup()
        try:
            self.inner.close()
        finally:
            self.finalize_cleanup()

    def finalize_cleanup(self) -> tuple[TimeoutCleanupRecord, ...]:
        records: list[TimeoutCleanupRecord] = []
        for command in self._pending_commands.values():
            record = cleanup_timed_out_container(
                command,
                cleanup_runner=self.cleanup_runner,
            )
            self._record_cleanup(record)
            records.append(record)
        return tuple(records)

    def _after_result(self, result: ToolResult) -> ToolResult:
        if not result.timed_out:
            return result
        identity = _docker_tool_identity(result.command)
        if identity is not None:
            self._pending_commands[identity[0]] = result.command
        record = cleanup_timed_out_container(
            result.command,
            cleanup_runner=self.cleanup_runner,
        )
        if result.command[:2] == ("docker", "run") and identity is None:
            self._unsafe_cleanup = record
        self._record_cleanup(record)
        return replace(
            result,
            error=_timeout_error(result.error, record),
        )

    def _prepare_next_action(self, *, tool: str) -> ToolResult | None:
        if self._unsafe_cleanup is not None:
            return _blocked_cleanup_result(tool, self._unsafe_cleanup)
        for record in self.finalize_cleanup():
            if not record.verified:
                return _blocked_cleanup_result(tool, record)
        return None

    def _record_cleanup(self, record: TimeoutCleanupRecord) -> None:
        self.cleanup_records.append(record)
        if self.on_cleanup is not None:
            self.on_cleanup(record)


def cleanup_timed_out_container(  # noqa: PLR0911 - cleanup exits preserve exact status.
    command: tuple[str, ...],
    *,
    cleanup_runner: CleanupRunner | None = None,
) -> TimeoutCleanupRecord:
    runner = cleanup_runner or _run_cleanup
    identity = _docker_tool_identity(command)
    if identity is None:
        if command[:2] == ("docker", "run"):
            return TimeoutCleanupRecord.create(
                status="identity_unverified",
                verified=False,
                detail="timed-out Docker command did not contain one valid Ravage tool identity",
            )
        return TimeoutCleanupRecord.create(
            status="not_applicable",
            verified=True,
            detail="timed-out action was not a Docker tool container",
        )

    container_name, session_key = identity
    try:
        completed = runner(("docker", "rm", "--force", container_name))
    except subprocess.TimeoutExpired as exc:
        return TimeoutCleanupRecord.create(
            container_name=container_name,
            session_key=session_key,
            status="cleanup_timed_out",
            verified=False,
            detail=str(exc)[:_DETAIL_CHARS],
        )
    except OSError as exc:
        return TimeoutCleanupRecord.create(
            container_name=container_name,
            session_key=session_key,
            status="cleanup_error",
            verified=False,
            detail=f"{type(exc).__name__}: {exc}"[:_DETAIL_CHARS],
        )

    detail = _completed_detail(completed)
    if "no such container" in detail.lower():
        return TimeoutCleanupRecord.create(
            container_name=container_name,
            session_key=session_key,
            status="already_absent",
            verified=True,
            returncode=completed.returncode,
            detail=detail,
        )
    if completed.returncode == 0:
        return TimeoutCleanupRecord.create(
            container_name=container_name,
            session_key=session_key,
            status="removed",
            verified=True,
            returncode=completed.returncode,
            detail=detail,
        )
    return TimeoutCleanupRecord.create(
        container_name=container_name,
        session_key=session_key,
        status="cleanup_failed",
        verified=False,
        returncode=completed.returncode,
        detail=detail,
    )


def remember_timeout_recovery(
    state: AgentState,
    record: TimeoutCleanupRecord,
) -> None:
    append_unique(
        state.signals.setdefault(_TIMEOUT_SIGNAL, []),
        json.dumps(record.to_json(), sort_keys=True),
        limit=_MAX_SIGNAL_ITEMS,
    )


def pending_timeout_recovery(state: AgentState) -> TimeoutCleanupRecord | None:
    resolved = set(state.signals.get(_RESOLVED_SIGNAL, []))
    for record in reversed(_remembered_timeout_recoveries(state)):
        if record.fingerprint not in resolved:
            return record
    return None


def resolve_timeout_recoveries(state: AgentState) -> tuple[str, ...]:
    resolved = set(state.signals.get(_RESOLVED_SIGNAL, []))
    newly_resolved = tuple(
        record.fingerprint
        for record in _remembered_timeout_recoveries(state)
        if record.fingerprint not in resolved
    )
    for fingerprint in newly_resolved:
        append_unique(
            state.signals.setdefault(_RESOLVED_SIGNAL, []),
            fingerprint,
            limit=_MAX_SIGNAL_ITEMS,
        )
    return newly_resolved


def timeout_recovery_context(state: AgentState) -> dict[str, object] | None:
    record = pending_timeout_recovery(state)
    if record is None:
        return None
    return {
        "cleanup_status": record.status,
        "cleanup_verified": record.verified,
        "requirement": _recovery_requirement(record),
    }


def timeout_recovery_message(record: TimeoutCleanupRecord) -> str:
    return (
        "COORDINATOR_TIMEOUT_RECOVERY_GATE\n"
        f"cleanup_status={record.status}; cleanup_verified={str(record.verified).lower()}. "
        f"{_recovery_requirement(record)} The timed-out model request remains charged; "
        "worker leases, repeated-observation watchdogs, global request/cost limits, and "
        "scope enforcement remain active."
    )


def timeout_recovery_resolved_message() -> str:
    return (
        "COORDINATOR_TIMEOUT_RECOVERY_RESOLVED\n"
        "A subsequent scoped tool action completed without timing out. Continue from "
        "preserved target evidence and checkpoints; do not restart discovery."
    )


def _recovery_requirement(record: TimeoutCleanupRecord) -> str:
    if not record.verified:
        return (
            "Container cleanup is unverified. Do not launch another tool workload; "
            "return control to the coordinator."
        )
    return (
        "Before another extraction or multi-payload batch, run one cheap, previously "
        "terminating liveness/calibration control with a smaller explicit timeout. "
        "Resume only after a fresh target response."
    )


def _timeout_error(
    existing: str | None,
    record: TimeoutCleanupRecord,
) -> str:
    prefix = f"{existing.rstrip()}; " if existing else ""
    return (
        f"{prefix}frontier timeout hygiene: cleanup_status={record.status}; "
        f"cleanup_verified={str(record.verified).lower()}. "
        f"{_recovery_requirement(record)}"
    )


def _blocked_cleanup_result(
    tool: str,
    record: TimeoutCleanupRecord,
) -> ToolResult:
    return ToolResult(
        ok=False,
        tool=tool,
        command=("frontier-timeout-hygiene",),
        exit_code=None,
        stdout="",
        stderr="",
        error=(
            "frontier timeout hygiene blocked a new workload because exact cleanup "
            f"is unverified: status={record.status}"
        ),
    )


def _docker_tool_identity(command: tuple[str, ...]) -> tuple[str, str] | None:
    if command[:2] != ("docker", "run"):
        return None
    names = _option_values(command, "--name")
    labels = set(_option_values(command, "--label"))
    if len(names) != 1:
        return None
    match = _CONTAINER_NAME.fullmatch(names[0])
    if match is None:
        return None
    session_key = match.group("session_key")
    if f"{SESSION_LABEL}={session_key}" not in labels:
        return None
    if f"{KIND_LABEL}=tool" not in labels:
        return None
    return names[0], session_key


def _option_values(command: tuple[str, ...], option: str) -> tuple[str, ...]:
    values: list[str] = []
    for index, item in enumerate(command[:-1]):
        if item == option:
            values.append(command[index + 1])
    return tuple(values)


def _run_cleanup(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv is fixed after strict identity validation.
        argv,
        text=True,
        capture_output=True,
        timeout=_CLEANUP_TIMEOUT_SECONDS,
        check=False,
    )


def _completed_detail(completed: subprocess.CompletedProcess[str]) -> str:
    return "\n".join(
        item.strip() for item in (completed.stdout or "", completed.stderr or "") if item.strip()
    )[:_DETAIL_CHARS]


def _remembered_timeout_recoveries(
    state: AgentState,
) -> list[TimeoutCleanupRecord]:
    records: list[TimeoutCleanupRecord] = []
    for raw in state.signals.get(_TIMEOUT_SIGNAL, [])[-12:]:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        record = TimeoutCleanupRecord.from_json(payload)
        if record.fingerprint == str(payload.get("fingerprint") or ""):
            records.append(record)
    return records


def _optional_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


__all__ = [
    "FrontierTimeoutHygieneRuntime",
    "TimeoutCleanupRecord",
    "cleanup_timed_out_container",
    "pending_timeout_recovery",
    "remember_timeout_recovery",
    "resolve_timeout_recoveries",
    "timeout_recovery_context",
    "timeout_recovery_message",
    "timeout_recovery_resolved_message",
]
