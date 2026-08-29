from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.run_store import (
    ActionLifecycle,
    ActionTransitionError,
    ProjectionConflictError,
    ProjectionUpdate,
    RunLease,
    RunLeaseConflictError,
    RunLeaseLostError,
    RunStore,
    RunStoreIdempotencyError,
)

if TYPE_CHECKING:
    from pathlib import Path

OWNER_ONLY_MODE = 0o600


def _store(tmp_path: Path) -> RunStore:
    return RunStore.open(tmp_path / "graph-run.sqlite3")


def _lease(store: RunStore, *, now: float = 100.0) -> RunLease:
    return store.acquire_lease(
        run_id="run-001",
        owner_id="worker-a",
        ttl_seconds=10,
        now=now,
    )


def test_lease_is_durable_renewable_and_fences_stale_owners(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = _lease(store)

    assert _lease(store, now=101) == first
    with pytest.raises(RunLeaseConflictError):
        store.acquire_lease(
            run_id="run-001",
            owner_id="worker-b",
            ttl_seconds=10,
            now=101,
        )

    renewed = store.renew_lease(first, ttl_seconds=20, now=105)
    assert renewed.epoch == first.epoch
    assert renewed.expires_at == 125  # noqa: PLR2004

    replacement = store.acquire_lease(
        run_id="run-001",
        owner_id="worker-b",
        ttl_seconds=10,
        now=126,
    )
    assert replacement.epoch == first.epoch + 1
    with pytest.raises(RunLeaseLostError):
        store.reserve_action(
            first,
            action_key="stale-action",
            node_id="node-a",
            request={"tool": "run_probe"},
            now=127,
        )


def test_released_lease_can_be_reacquired_with_a_new_fencing_epoch(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    first = _lease(store)
    store.release_lease(first, now=101)

    second = store.acquire_lease(
        run_id="run-001",
        owner_id="worker-b",
        ttl_seconds=10,
        now=102,
    )

    assert second.epoch == 2  # noqa: PLR2004
    with pytest.raises(RunLeaseLostError):
        store.renew_lease(first, ttl_seconds=10, now=103)


def test_action_reservation_and_start_are_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    lease = _lease(store)
    request = {"tool": "run_probe", "arguments": {"probe": "sqli"}}

    created = store.reserve_action(
        lease,
        action_key="node-1:turn-1:tool-1",
        node_id="node-1",
        request=request,
        now=101,
    )
    replay = store.reserve_action(
        lease,
        action_key="node-1:turn-1:tool-1",
        node_id="node-1",
        request=request,
        now=102,
    )
    first_start = store.start_action(
        lease,
        action_key="node-1:turn-1:tool-1",
        now=103,
    )
    replayed_start = store.start_action(
        lease,
        action_key="node-1:turn-1:tool-1",
        now=104,
    )

    assert created.replayed is False
    assert replay.replayed is True
    assert replay.action.action_id == created.action.action_id
    assert first_start.should_execute is True
    assert first_start.action.lifecycle is ActionLifecycle.STARTED
    assert first_start.action.attempt == 1
    assert replayed_start.should_execute is False
    with pytest.raises(RunStoreIdempotencyError):
        store.reserve_action(
            lease,
            action_key="node-1:turn-1:tool-1",
            node_id="node-1",
            request={"tool": "run_command"},
            now=105,
        )


def test_reserved_action_cancellation_is_terminal_and_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    lease = _lease(store)
    store.reserve_action(
        lease,
        action_key="race-loser",
        node_id="node-1",
        request={"request_sha256": "a" * 64},
        now=101,
    )

    cancelled = store.cancel_reserved_action(
        lease,
        action_key="race-loser",
        reason="race_lost_before_external_execution",
        now=102,
    )
    replay = store.cancel_reserved_action(
        lease,
        action_key="race-loser",
        reason="same semantic result",
        now=103,
    )

    assert cancelled.lifecycle is ActionLifecycle.CANCELLED
    assert replay == cancelled
    start = store.start_action(lease, action_key="race-loser", now=104)
    assert start.should_execute is False
    assert start.action.lifecycle is ActionLifecycle.CANCELLED
    assert store.unreconciled_actions("run-001") == ()
    with pytest.raises(ActionTransitionError):
        store.settle_action(
            lease,
            action_key="race-loser",
            result={"status": "impossible"},
            now=105,
        )


def test_action_application_marker_closes_settled_reconciliation_gap(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    lease = _lease(store)
    store.reserve_action(
        lease,
        action_key="tool-1",
        node_id="node-1",
        request={"request_sha256": "a" * 64},
        now=101,
    )
    store.start_action(lease, action_key="tool-1", now=102)
    settled = store.settle_action(
        lease,
        action_key="tool-1",
        result={"result_sha256": "b" * 64},
        now=103,
    )

    assert store.unreconciled_actions("run-001") == (settled,)
    first = store.mark_action_applied(
        lease,
        action_key="tool-1",
        state_digest="c" * 64,
        evidence_refs=("evidence:2", "evidence:1", "evidence:1"),
        disposition="executed",
        now=104,
    )
    replay = store.mark_action_applied(
        lease,
        action_key="tool-1",
        state_digest="c" * 64,
        evidence_refs=("evidence:1", "evidence:2"),
        disposition="executed",
        now=105,
    )

    assert first.replayed is False
    assert replay.replayed is True
    assert store.unreconciled_actions("run-001") == ()
    assert store.events("run-001")[-1].kind == "action_applied"
    with pytest.raises(RunStoreIdempotencyError):
        store.mark_action_applied(
            lease,
            action_key="tool-1",
            state_digest="d" * 64,
            disposition="executed",
            now=106,
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
def test_database_and_sidecar_permissions_are_owner_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    sidecars = (
        store.path.with_name(f"{store.path.name}-wal"),
        store.path.with_name(f"{store.path.name}-shm"),
    )
    for sidecar in sidecars:
        sidecar.touch()
        sidecar.chmod(0o666)

    store._secure_database_files()  # noqa: SLF001 - focused filesystem invariant.

    assert store.path.stat().st_mode & 0o777 == OWNER_ONLY_MODE
    assert all(sidecar.stat().st_mode & 0o777 == OWNER_ONLY_MODE for sidecar in sidecars)


def test_settlement_atomically_updates_action_event_and_projections(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    lease = _lease(store)
    store.reserve_action(
        lease,
        action_key="tool-1",
        node_id="node-1",
        request={"tool": "run_probe"},
        now=101,
    )
    store.start_action(lease, action_key="tool-1", now=102)
    updates = (
        ProjectionUpdate(
            name="coverage",
            expected_revision=0,
            payload={"stage": "primitive", "version": 1},
        ),
        ProjectionUpdate(
            name="beliefs",
            expected_revision=0,
            payload={"hypothesis": "supported"},
        ),
    )

    settled = store.settle_action(
        lease,
        action_key="tool-1",
        result={"ok": True, "evidence_refs": ["evidence:1"]},
        projections=updates,
        now=103,
    )
    replay = store.settle_action(
        lease,
        action_key="tool-1",
        result={"ok": True, "evidence_refs": ["evidence:1"]},
        projections=updates,
        now=104,
    )

    assert settled.lifecycle is ActionLifecycle.SETTLED
    assert replay == settled
    assert store.projection("run-001", "coverage").revision == 1  # type: ignore[union-attr]
    assert store.projection("run-001", "beliefs").payload == {  # type: ignore[union-attr]
        "hypothesis": "supported"
    }
    assert [event.kind for event in store.events("run-001")] == [
        "action_reserved",
        "action_started",
        "action_settled",
    ]


def test_projection_conflict_rolls_back_entire_settlement(tmp_path: Path) -> None:
    store = _store(tmp_path)
    lease = _lease(store)
    store.commit_event_and_projections(
        lease,
        idempotency_key="seed-coverage",
        kind="coverage_seeded",
        payload={},
        projections=(ProjectionUpdate(name="coverage", expected_revision=0, payload={"v": 1}),),
        now=101,
    )
    store.reserve_action(
        lease,
        action_key="tool-1",
        node_id="node-1",
        request={"tool": "run_probe"},
        now=102,
    )
    store.start_action(lease, action_key="tool-1", now=103)
    event_count = len(store.events("run-001"))

    with pytest.raises(ProjectionConflictError):
        store.settle_action(
            lease,
            action_key="tool-1",
            result={"ok": True},
            projections=(
                ProjectionUpdate(name="beliefs", expected_revision=0, payload={"v": 1}),
                ProjectionUpdate(name="coverage", expected_revision=0, payload={"v": 2}),
            ),
            now=104,
        )

    assert store.action("run-001", "tool-1").lifecycle is ActionLifecycle.STARTED  # type: ignore[union-attr]
    assert store.projection("run-001", "beliefs") is None
    assert store.projection("run-001", "coverage").payload == {"v": 1}  # type: ignore[union-attr]
    assert len(store.events("run-001")) == event_count


def test_event_projection_commit_is_idempotent_and_revision_checked(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    lease = _lease(store)
    updates = (ProjectionUpdate(name="graph", expected_revision=0, payload={"status": "running"}),)

    first = store.commit_event_and_projections(
        lease,
        idempotency_key="graph-created",
        kind="graph_created",
        payload={"graph_id": "g-1"},
        projections=updates,
        now=101,
    )
    replay = store.commit_event_and_projections(
        lease,
        idempotency_key="graph-created",
        kind="graph_created",
        payload={"graph_id": "g-1"},
        projections=updates,
        now=102,
    )

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.event.event_id == first.event.event_id
    assert replay.event.projection_revisions == {"graph": 1}
    assert store.projection("run-001", "graph").revision == 1  # type: ignore[union-attr]
    with pytest.raises(RunStoreIdempotencyError):
        store.commit_event_and_projections(
            lease,
            idempotency_key="graph-created",
            kind="graph_created",
            payload={"graph_id": "different"},
            projections=updates,
            now=103,
        )


def test_takeover_recovery_marks_started_unknown_but_keeps_reserved_retryable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    first = _lease(store)
    for action_key in ("started", "reserved"):
        store.reserve_action(
            first,
            action_key=action_key,
            node_id="node-1",
            request={"tool": action_key},
            now=101,
        )
    store.start_action(first, action_key="started", now=102)

    replacement = store.acquire_lease(
        run_id="run-001",
        owner_id="worker-b",
        ttl_seconds=10,
        now=111,
    )
    report = store.recover_interrupted_actions(replacement, now=112)

    assert [action.action_key for action in report.marked_unknown] == ["started"]
    assert [action.action_key for action in report.retryable_reserved] == ["reserved"]
    assert report.unknown_outcomes[0].unknown_reason == ("lease_epoch_changed_before_settlement")
    assert (
        store.start_action(
            replacement,
            action_key="started",
            now=113,
        ).should_execute
        is False
    )


def test_unknown_outcome_requires_explicit_reconciliation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    lease = _lease(store)
    store.reserve_action(
        lease,
        action_key="tool-1",
        node_id="node-1",
        request={"tool": "run_probe"},
        now=101,
    )
    store.start_action(lease, action_key="tool-1", now=102)
    unknown = store.mark_unknown_outcome(
        lease,
        action_key="tool-1",
        reason="process lost executor response",
        now=103,
    )

    assert unknown.lifecycle is ActionLifecycle.UNKNOWN_OUTCOME
    with pytest.raises(ActionTransitionError):
        store.settle_action(
            lease,
            action_key="tool-1",
            result={"ok": True},
            now=104,
        )

    retryable = store.reconcile_unknown_as_retryable(
        lease,
        action_key="tool-1",
        reason="target audit proves the operation was not applied",
        now=105,
    )
    restarted = store.start_action(lease, action_key="tool-1", now=106)
    assert retryable.lifecycle is ActionLifecycle.RESERVED
    assert restarted.should_execute is True
    assert restarted.action.attempt == 2  # noqa: PLR2004


def test_recovery_snapshot_survives_store_reopen(tmp_path: Path) -> None:
    path = tmp_path / "graph-run.sqlite3"
    store = RunStore.open(path)
    lease = _lease(store)
    store.commit_event_and_projections(
        lease,
        idempotency_key="checkpoint-1",
        kind="checkpoint",
        payload={"reason": "turn complete"},
        projections=(ProjectionUpdate(name="graph", expected_revision=0, payload={"turn": 1}),),
        now=101,
    )

    reopened = RunStore.open(path)
    snapshot = reopened.recovery_snapshot("run-001")

    assert snapshot.lease == lease
    assert snapshot.last_event_sequence == 1
    assert snapshot.projections[0].payload == {"turn": 1}
    assert reopened.events("run-001", after_sequence=0)[0].kind == "checkpoint"
