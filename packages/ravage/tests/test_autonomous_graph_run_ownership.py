from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.run_ownership import (
    RunOwnershipGuard,
    RunOwnershipInactiveError,
    RunOwnershipReconciliationError,
)
from ravage.agent_core.autonomous_graph.run_store import (
    ActionLifecycle,
    RunLeaseLostError,
    RunStore,
)

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class _Clock:
    value: float = 100.0

    def __call__(self) -> float:
        return self.value


@dataclass
class _ControlledSleep:
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    proceed: asyncio.Event = field(default_factory=asyncio.Event)

    async def __call__(self, _delay: float) -> None:
        self.entered.set()
        await self.proceed.wait()
        self.proceed.clear()


def _store(tmp_path: Path) -> RunStore:
    return RunStore.open(tmp_path / "graph-run.sqlite3")


@pytest.mark.asyncio
async def test_guard_acquires_recovers_heartbeats_and_releases(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = store.acquire_lease(
        run_id="run-1",
        owner_id="dead-owner",
        ttl_seconds=2,
        now=100,
    )
    store.reserve_action(
        original,
        action_key="started-action",
        node_id="node-1",
        request={"tool": "http_request"},
        now=100.5,
    )
    store.start_action(original, action_key="started-action", now=101)

    clock = _Clock(103)
    controlled_sleep = _ControlledSleep()
    guard = RunOwnershipGuard(
        store=store,
        run_id="run-1",
        owner_id="replacement-owner",
        ttl_seconds=6,
        heartbeat_interval_seconds=2,
        clock=clock,
        sleep=controlled_sleep,
    )
    async with guard:
        assert guard.lease.epoch == original.epoch + 1
        assert [item.action_key for item in guard.recovery.marked_unknown] == ["started-action"]
        assert (
            store.action("run-1", "started-action").lifecycle  # type: ignore[union-attr]
            is ActionLifecycle.UNKNOWN_OUTCOME
        )

        await controlled_sleep.entered.wait()
        clock.value = 105
        controlled_sleep.proceed.set()
        for _ in range(100):
            if guard.lease.expires_at == 111:  # noqa: PLR2004
                break
            await asyncio.sleep(0.001)
        assert guard.lease.expires_at == 111  # noqa: PLR2004

    assert store.recovery_snapshot("run-1").lease is None
    with pytest.raises(RunOwnershipInactiveError):
        guard.assert_owned()


@pytest.mark.asyncio
async def test_guard_cancels_work_and_surfaces_fenced_heartbeat_loss(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    clock = _Clock()
    controlled_sleep = _ControlledSleep()
    guard = RunOwnershipGuard(
        store=store,
        run_id="run-1",
        owner_id="owner-a",
        ttl_seconds=4,
        heartbeat_interval_seconds=1,
        clock=clock,
        sleep=controlled_sleep,
    )
    workload_started = asyncio.Event()
    workload_cancelled = asyncio.Event()

    async def workload() -> None:
        workload_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            workload_cancelled.set()

    async def run_until_fenced() -> None:
        async with guard:
            guarded_work = asyncio.create_task(guard.run(workload()))
            await workload_started.wait()
            await controlled_sleep.entered.wait()
            clock.value = 105
            store.acquire_lease(
                run_id="run-1",
                owner_id="owner-b",
                ttl_seconds=4,
                now=clock.value,
            )
            controlled_sleep.proceed.set()
            await guarded_work

    with pytest.raises(RunLeaseLostError):
        await run_until_fenced()

    assert workload_cancelled.is_set()
    assert store.recovery_snapshot("run-1").lease.owner_id == "owner-b"  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_exit_does_not_mask_the_workload_error_when_release_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    guard = RunOwnershipGuard(
        store=store,
        run_id="run-1",
        owner_id="owner-a",
        ttl_seconds=4,
        heartbeat_interval_seconds=1,
    )

    class WorkloadError(Exception):
        pass

    def broken_release(*_args: object, **_kwargs: object) -> None:
        message = "cleanup failed"
        raise RuntimeError(message)

    async def fail_inside_guard() -> None:
        async with guard:
            message = "original failure"
            raise WorkloadError(message)

    monkeypatch.setattr(RunStore, "release_lease", broken_release)
    with pytest.raises(WorkloadError, match="original failure"):
        await fail_inside_guard()


def test_heartbeat_interval_must_leave_renewal_margin(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot exceed half"):
        RunOwnershipGuard(
            store=_store(tmp_path),
            run_id="run-1",
            owner_id="owner-a",
            ttl_seconds=4,
            heartbeat_interval_seconds=3,
        )


@pytest.mark.asyncio
async def test_guard_reconciliation_accepts_only_cancelled_or_applied_actions(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    guard = RunOwnershipGuard(
        store=store,
        run_id="run-1",
        owner_id="owner-a",
        ttl_seconds=30,
        heartbeat_interval_seconds=5,
    )

    async with guard:
        guard.assert_reconciled()
        store.reserve_action(
            guard.lease,
            action_key="cancelled",
            node_id="node-1",
            request={"request_sha256": "a" * 64},
        )
        with pytest.raises(RunOwnershipReconciliationError, match="reserved"):
            guard.assert_reconciled()
        store.cancel_reserved_action(
            guard.lease,
            action_key="cancelled",
            reason="not executed",
        )
        guard.assert_reconciled()

        store.reserve_action(
            guard.lease,
            action_key="effect",
            node_id="node-1",
            request={"request_sha256": "b" * 64},
        )
        store.start_action(guard.lease, action_key="effect")
        with pytest.raises(RunOwnershipReconciliationError, match="started"):
            guard.assert_reconciled()
        store.mark_unknown_outcome(
            guard.lease,
            action_key="effect",
            reason="outcome unknown",
        )
        with pytest.raises(RunOwnershipReconciliationError, match="unknown_outcome"):
            guard.assert_reconciled()
        store.reconcile_unknown_as_settled(
            guard.lease,
            action_key="effect",
            result={"result_sha256": "c" * 64},
            reason="operator verified outcome",
        )
        with pytest.raises(RunOwnershipReconciliationError, match="settled"):
            guard.assert_reconciled()
        store.mark_action_applied(
            guard.lease,
            action_key="effect",
            state_digest="d" * 64,
            disposition="operator_reconciled",
        )
        guard.assert_reconciled()


@pytest.mark.asyncio
async def test_guard_run_rejects_new_unreconciled_action_before_success(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    guard = RunOwnershipGuard(
        store=store,
        run_id="run-1",
        owner_id="owner-a",
        ttl_seconds=30,
        heartbeat_interval_seconds=5,
    )

    async def leave_reservation() -> str:
        store.reserve_action(
            guard.lease,
            action_key="unfinished",
            node_id="node-1",
            request={"request_sha256": "a" * 64},
        )
        return "would-have-succeeded"

    async with guard:
        with pytest.raises(RunOwnershipReconciliationError, match="unfinished:reserved"):
            await guard.run(leave_reservation())
