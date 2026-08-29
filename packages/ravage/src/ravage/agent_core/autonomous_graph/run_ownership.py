"""Async fenced ownership for one production autonomous-graph run."""
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import asyncio
import math
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self, TypeVar

from .run_store import RecoveryReport, RunLease, RunLeaseLostError, RunStore

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from types import TracebackType

_ResultT = TypeVar("_ResultT")


class RunOwnershipInactiveError(RuntimeError):
    """Raised when guarded work is attempted outside an active ownership scope."""


class RunOwnershipReconciliationError(RuntimeError):
    """Raised when durable action state is unsafe for a successful handoff."""


@dataclass(slots=True)
class RunOwnershipGuard:
    """
    Keep one fenced ``RunStore`` lease alive while production work executes.

    The intended integration is::

        async with RunOwnershipGuard(store, run_id, owner_id) as ownership:
            result = await ownership.run(runner.run())

    ``run`` races the workload against heartbeat failure. If ownership can no
    longer be proven, the workload is cancelled and the lease error is raised.
    Callers performing several separately awaited operations may instead call
    ``assert_owned`` at each external-effect boundary.
    """

    store: RunStore
    run_id: str
    owner_id: str
    ttl_seconds: float = 30.0
    heartbeat_interval_seconds: float | None = None
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    _lease: RunLease | None = field(default=None, init=False, repr=False)
    _recovery: RecoveryReport | None = field(default=None, init=False, repr=False)
    _heartbeat_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _failure: Exception | None = field(default=None, init=False, repr=False)
    _loss_event: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)
    _active: bool = field(default=False, init=False, repr=False)
    _closing: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not math.isfinite(self.ttl_seconds) or self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be finite and greater than zero")
        interval = self.heartbeat_interval_seconds
        if interval is None:
            interval = min(10.0, self.ttl_seconds / 3.0)
            self.heartbeat_interval_seconds = interval
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("heartbeat_interval_seconds must be finite and greater than zero")
        if interval > self.ttl_seconds / 2.0:
            raise ValueError("heartbeat_interval_seconds cannot exceed half the lease TTL")

    @property
    def lease(self) -> RunLease:
        """Return the latest renewed lease while the guard is active."""
        if not self._active or self._lease is None:
            raise RunOwnershipInactiveError("run ownership is not active")
        return self._lease

    @property
    def recovery(self) -> RecoveryReport:
        """Return the fail-closed recovery classification made on entry."""
        if not self._active or self._recovery is None:
            raise RunOwnershipInactiveError("run ownership is not active")
        return self._recovery

    async def __aenter__(self) -> Self:
        if self._active or self._lease is not None:
            raise RuntimeError("run ownership guard cannot be entered more than once")

        lease = await asyncio.to_thread(
            self.store.acquire_lease,
            run_id=self.run_id,
            owner_id=self.owner_id,
            ttl_seconds=self.ttl_seconds,
            now=self.clock(),
        )
        self._lease = lease
        try:
            self._recovery = await asyncio.to_thread(
                self.store.recover_interrupted_actions,
                lease,
                now=self.clock(),
            )
        except BaseException:
            # Recovery is part of acquisition. Best-effort release must never
            # replace the error that made ownership unsafe to use.
            with suppress(BaseException):
                await asyncio.to_thread(
                    self.store.release_lease,
                    lease,
                    now=self.clock(),
                )
            self._lease = None
            raise

        self._active = True
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat(),
            name=f"run-lease-heartbeat:{self.run_id}",
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        del exc_type, traceback
        self._closing = True
        heartbeat = self._heartbeat_task
        if heartbeat is not None:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat

        release_failure: BaseException | None = None
        lease = self._lease
        if lease is not None:
            try:
                await asyncio.to_thread(
                    self.store.release_lease,
                    lease,
                    now=self.clock(),
                )
            except BaseException as error:  # noqa: BLE001 - never mask body failure
                release_failure = error

        self._active = False
        self._heartbeat_task = None

        # Never replace a workload exception with heartbeat or cleanup failure.
        if exc is not None:
            return False
        if self._failure is not None:
            raise self._failure
        if release_failure is not None:
            raise release_failure
        return False

    def assert_owned(self) -> None:
        """Fail closed unless the guard still has a locally live fenced lease."""
        if not self._active or self._lease is None:
            raise RunOwnershipInactiveError("run ownership is not active")
        if self._failure is not None:
            raise self._failure
        now = self.clock()
        if not self._lease.active_at(now):
            failure = RunLeaseLostError(
                f"run {self.run_id!r} lease expired before the next heartbeat"
            )
            self._record_failure(failure)
            raise failure

    def assert_reconciled(self) -> None:
        """Fail closed unless every durable action has a terminal application proof."""
        self.assert_owned()
        gaps = self.store.unreconciled_actions(self.lease.run_id)
        self.assert_owned()
        if not gaps:
            return
        summary = ", ".join(f"{action.action_key}:{action.lifecycle.value}" for action in gaps)
        message = f"run {self.run_id!r} has unreconciled durable actions: {summary}"
        raise RunOwnershipReconciliationError(message)

    async def run(self, workload: Awaitable[_ResultT]) -> _ResultT:
        """Run a workload until it completes or ownership becomes unprovable."""
        try:
            self.assert_reconciled()
        except BaseException:
            if asyncio.iscoroutine(workload):
                workload.close()
            raise

        work_task = asyncio.ensure_future(workload)
        loss_task = asyncio.create_task(self._loss_event.wait())
        try:
            done, _ = await asyncio.wait(
                (work_task, loss_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if work_task in done:
                result = await work_task
                self.assert_reconciled()
                return result

            work_task.cancel()
            with suppress(asyncio.CancelledError):
                await work_task
            self.assert_owned()
            raise AssertionError("ownership loss was signalled without a failure")
        finally:
            loss_task.cancel()
            with suppress(asyncio.CancelledError):
                await loss_task
            if not work_task.done():
                work_task.cancel()
                with suppress(asyncio.CancelledError):
                    await work_task

    async def _heartbeat(self) -> None:
        assert self.heartbeat_interval_seconds is not None
        while not self._closing:
            try:
                await self.sleep(self.heartbeat_interval_seconds)
                if self._closing:
                    return
                lease = self.lease
                renewed = await asyncio.to_thread(
                    self.store.renew_lease,
                    lease,
                    ttl_seconds=self.ttl_seconds,
                    now=self.clock(),
                )
                self._lease = renewed
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - uncertainty loses ownership
                self._record_failure(error)
                return

    def _record_failure(self, error: Exception) -> None:
        if self._failure is None:
            self._failure = error
            self._loss_event.set()
