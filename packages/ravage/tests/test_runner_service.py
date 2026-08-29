"""Adversarial tests for the public runner execution boundary."""
# ruff: noqa: PLR0913, PLR2004

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace

import pytest
from ravage.control_plane.runner_protocol import (
    AuthorizationLineage,
    CanonicalPayload,
    DispatchAuthorizationError,
    JobIdentity,
    JobStatus,
    LeaseFence,
    LeaseFenceError,
    ProtocolError,
    RegistryCapacityError,
    ResultConflictError,
)
from ravage.control_plane.runner_service import (
    InProcessRunnerEngine,
    RunnerCompatibilityError,
    RunnerExecutionOutcome,
    RunnerExecutorContractError,
    RunnerResultV1,
    RunnerScopeError,
    RunnerWorkloadV1,
)

_NOW_MS = 1_000_000
_DIGEST = hashlib.sha256(b"policy").hexdigest()


def _job(
    *,
    tenant_id: str = "tenant-1",
    organization_id: str = "org-1",
    job_id: str = "job-1",
) -> JobIdentity:
    return JobIdentity(
        tenant_id=tenant_id,
        organization_id=organization_id,
        engagement_id="engagement-1",
        job_id=job_id,
    )


def _lease(
    *,
    job: JobIdentity | None = None,
    runner_id: str = "runner-1",
    lease_id: str = "lease-3",
    epoch: int = 3,
    expires_at_ms: int = _NOW_MS + 120_000,
) -> LeaseFence:
    return LeaseFence(
        job=job or _job(),
        runner_id=runner_id,
        lease_id=lease_id,
        epoch=epoch,
        expires_at_ms=expires_at_ms,
    )


def _authorization(
    *,
    authorized_at_ms: int = _NOW_MS - 60_000,
    expires_at_ms: int = _NOW_MS + 60_000,
) -> AuthorizationLineage:
    return AuthorizationLineage(
        receipt_digest=hashlib.sha256(b"receipt").hexdigest(),
        policy_digest=_DIGEST,
        actor_digest=hashlib.sha256(b"actor").hexdigest(),
        authorized_at_ms=authorized_at_ms,
        expires_at_ms=expires_at_ms,
    )


def _workload(
    *,
    job: JobIdentity | None = None,
    lease: LeaseFence | None = None,
    authorization: AuthorizationLineage | None = None,
    idempotency_key: str = "execution-1",
    required_capabilities: tuple[str, ...] = ("browser",),
    payload: CanonicalPayload | None = None,
) -> RunnerWorkloadV1:
    identity = job or _job()
    return RunnerWorkloadV1(
        job=identity,
        lease=lease or _lease(job=identity),
        authorization=authorization or _authorization(),
        idempotency_key=idempotency_key,
        required_capabilities=required_capabilities,
        payload=payload or CanonicalPayload.from_mapping({"objective": "validate scope"}),
    )


class _RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[RunnerWorkloadV1] = []

    async def __call__(self, workload: RunnerWorkloadV1) -> RunnerExecutionOutcome:
        self.calls.append(workload)
        await asyncio.sleep(0)
        return RunnerExecutionOutcome(
            status=JobStatus.SUCCEEDED,
            payload=CanonicalPayload.from_mapping({"finding_count": 2}),
        )


def _engine(
    executor: _RecordingExecutor,
    *,
    capabilities: tuple[str, ...] = ("browser", "docker"),
    max_cached_results: int = 16,
) -> InProcessRunnerEngine:
    return InProcessRunnerEngine(
        tenant_id="tenant-1",
        organization_id="org-1",
        runner_id="runner-1",
        capabilities=capabilities,
        executor=executor,
        max_cached_results=max_cached_results,
        clock_ms=lambda: _NOW_MS + 5_000,
    )


def test_v1_workload_and_result_round_trip_exact_wire_objects() -> None:
    workload = _workload(required_capabilities=("browser", "docker"))

    assert RunnerWorkloadV1.from_wire(workload.to_wire()) == workload

    result = RunnerResultV1(
        job=workload.job,
        lease=workload.lease,
        authorization=workload.authorization,
        idempotency_key=workload.idempotency_key,
        workload_digest=workload.workload_digest,
        status=JobStatus.SUCCEEDED,
        started_at_ms=_NOW_MS,
        completed_at_ms=_NOW_MS + 1,
        payload=CanonicalPayload.from_mapping({"ok": True}),
    )
    assert RunnerResultV1.from_wire(result.to_wire()) == result
    assert len(result.logical_result_digest) == 64


@pytest.mark.parametrize("field", ["schema", "version", "payload_digest"])
def test_workload_parser_rejects_tampered_schema_version_or_digest(field: str) -> None:
    wire = _workload().to_wire()
    replacements: dict[str, object] = {
        "schema": "ravage.runner.workload.v2",
        "version": 2,
        "payload_digest": "0" * 64,
    }
    wire[field] = replacements[field]

    with pytest.raises(ProtocolError):
        RunnerWorkloadV1.from_wire(wire)


def test_parsers_fail_closed_on_unknown_missing_and_wrong_container_fields() -> None:
    wire = _workload().to_wire()
    wire["future_field"] = True
    with pytest.raises(ProtocolError, match="fields mismatch"):
        RunnerWorkloadV1.from_wire(wire)

    del wire["future_field"]
    del wire["authorization"]
    with pytest.raises(ProtocolError, match="fields mismatch"):
        RunnerWorkloadV1.from_wire(wire)

    with pytest.raises(ProtocolError, match="must be an object"):
        RunnerWorkloadV1.from_wire([])


def test_workload_rejects_mutable_unsorted_duplicate_or_excessive_capabilities() -> None:
    wire = _workload().to_wire()
    wire["required_capabilities"] = ["docker", "browser"]
    with pytest.raises(ProtocolError, match="sorted"):
        RunnerWorkloadV1.from_wire(wire)

    wire["required_capabilities"] = ["browser", "browser"]
    with pytest.raises(ProtocolError, match="duplicate"):
        RunnerWorkloadV1.from_wire(wire)

    wire["required_capabilities"] = [f"capability.{index:02d}" for index in range(65)]
    with pytest.raises(ProtocolError, match="64"):
        RunnerWorkloadV1.from_wire(wire)

    with pytest.raises(ProtocolError, match="immutable tuple"):
        _workload(required_capabilities=["browser"])  # type: ignore[arg-type]


def test_workload_constructor_rejects_job_lease_substitution() -> None:
    with pytest.raises(ProtocolError, match="not bound"):
        _workload(job=_job(job_id="job-1"), lease=_lease(job=_job(job_id="job-2")))


def test_negotiation_is_explicit_and_fails_closed() -> None:
    engine = _engine(_RecordingExecutor())

    negotiation = engine.negotiate(
        workload_version=1,
        required_capabilities=("browser", "docker"),
    )
    assert negotiation.workload_version == 1
    assert negotiation.capabilities == ("browser", "docker")

    with pytest.raises(RunnerCompatibilityError, match="version"):
        engine.negotiate(workload_version=2, required_capabilities=("browser",))
    with pytest.raises(RunnerCompatibilityError, match="lacks"):
        engine.negotiate(workload_version=1, required_capabilities=("shell",))


@pytest.mark.asyncio
async def test_engine_binds_executor_outcome_to_validated_security_context() -> None:
    executor = _RecordingExecutor()
    engine = _engine(executor)
    workload = _workload()

    result = await engine.execute(
        workload,
        authoritative_lease=workload.lease,
        now_ms=_NOW_MS,
    )

    assert executor.calls == [workload]
    assert result.job == workload.job
    assert result.lease == workload.lease
    assert result.authorization == workload.authorization
    assert result.idempotency_identity == workload.idempotency_identity
    assert result.workload_digest == workload.workload_digest
    assert result.started_at_ms == _NOW_MS
    assert result.completed_at_ms == _NOW_MS + 5_000


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("workload", "reason"),
    [
        (_workload(job=_job(tenant_id="tenant-2")), "tenant"),
        (_workload(job=_job(organization_id="org-2")), "organization"),
        (
            _workload(
                lease=_lease(runner_id="runner-2"),
            ),
            "different runner",
        ),
    ],
)
async def test_engine_rejects_cross_scope_work_before_executor(
    workload: RunnerWorkloadV1,
    reason: str,
) -> None:
    executor = _RecordingExecutor()
    engine = _engine(executor)

    with pytest.raises(RunnerScopeError, match=reason):
        await engine.execute(
            workload,
            authoritative_lease=workload.lease,
            now_ms=_NOW_MS,
        )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_engine_rejects_stale_lease_and_expired_authorization() -> None:
    executor = _RecordingExecutor()
    engine = _engine(executor)
    workload = _workload()
    newer_lease = _lease(job=workload.job, lease_id="lease-4", epoch=4)

    with pytest.raises(LeaseFenceError, match="epoch"):
        await engine.execute(
            workload,
            authoritative_lease=newer_lease,
            now_ms=_NOW_MS,
        )

    expired = _workload(
        authorization=_authorization(
            authorized_at_ms=_NOW_MS - 2_000,
            expires_at_ms=_NOW_MS,
        ),
    )
    with pytest.raises(DispatchAuthorizationError, match="expired"):
        await engine.execute(
            expired,
            authoritative_lease=expired.lease,
            now_ms=_NOW_MS,
        )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_same_logical_work_is_exact_once_for_repeated_and_concurrent_calls() -> None:
    executor = _RecordingExecutor()
    engine = _engine(executor)
    workload = _workload()

    first, second = await asyncio.gather(
        engine.execute(workload, authoritative_lease=workload.lease, now_ms=_NOW_MS),
        engine.execute(workload, authoritative_lease=workload.lease, now_ms=_NOW_MS),
    )
    third = await engine.execute(
        workload,
        authoritative_lease=workload.lease,
        now_ms=_NOW_MS,
    )

    assert len(executor.calls) == 1
    assert first is second is third


@pytest.mark.asyncio
async def test_legitimate_re_lease_does_not_relabel_the_execution_fence() -> None:
    executor = _RecordingExecutor()
    engine = _engine(executor)
    original = _workload()
    first = await engine.execute(
        original,
        authoritative_lease=original.lease,
        now_ms=_NOW_MS,
    )
    renewed_lease = _lease(
        job=original.job,
        lease_id="lease-4",
        epoch=4,
        expires_at_ms=_NOW_MS + 180_000,
    )
    renewed = replace(original, lease=renewed_lease)

    assert renewed.workload_digest == original.workload_digest
    second = await engine.execute(
        renewed,
        authoritative_lease=renewed_lease,
        now_ms=_NOW_MS + 1,
    )

    assert len(executor.calls) == 1
    assert second is first
    assert second.lease == original.lease
    assert second.lease != renewed_lease
    assert second.workload_digest == first.workload_digest
    assert second.logical_result_digest == first.logical_result_digest


@pytest.mark.asyncio
async def test_idempotency_conflict_is_detected_without_second_execution() -> None:
    executor = _RecordingExecutor()
    engine = _engine(executor)
    original = _workload()
    await engine.execute(
        original,
        authoritative_lease=original.lease,
        now_ms=_NOW_MS,
    )
    conflicting = replace(
        original,
        payload=CanonicalPayload.from_mapping({"objective": "different"}),
    )

    with pytest.raises(ResultConflictError, match="different work"):
        await engine.execute(
            conflicting,
            authoritative_lease=conflicting.lease,
            now_ms=_NOW_MS,
        )
    assert len(executor.calls) == 1


@pytest.mark.asyncio
async def test_bounded_registry_fails_closed_without_eviction() -> None:
    executor = _RecordingExecutor()
    engine = _engine(executor, max_cached_results=1)
    first = _workload()
    await engine.execute(first, authoritative_lease=first.lease, now_ms=_NOW_MS)
    second = _workload(job=_job(job_id="job-2"), idempotency_key="execution-2")

    with pytest.raises(RegistryCapacityError, match="capacity"):
        await engine.execute(second, authoritative_lease=second.lease, now_ms=_NOW_MS)

    cached = await engine.execute(first, authoritative_lease=first.lease, now_ms=_NOW_MS)
    assert cached.idempotency_key == first.idempotency_key
    assert len(executor.calls) == 1


@pytest.mark.asyncio
async def test_unrelated_identities_are_not_serialized_behind_one_global_lock() -> None:
    both_entered = asyncio.Event()
    entered = 0

    async def concurrent_executor(workload: RunnerWorkloadV1) -> RunnerExecutionOutcome:
        nonlocal entered
        del workload
        entered += 1
        if entered == 2:
            both_entered.set()
        await asyncio.wait_for(both_entered.wait(), timeout=1)
        return RunnerExecutionOutcome(
            status=JobStatus.SUCCEEDED,
            payload=CanonicalPayload.from_mapping({"ok": True}),
        )

    engine = InProcessRunnerEngine(
        tenant_id="tenant-1",
        organization_id="org-1",
        runner_id="runner-1",
        capabilities=("browser",),
        executor=concurrent_executor,
        clock_ms=lambda: _NOW_MS,
    )
    first = _workload()
    second = _workload(job=_job(job_id="job-2"), idempotency_key="execution-2")

    await asyncio.gather(
        engine.execute(first, authoritative_lease=first.lease, now_ms=_NOW_MS),
        engine.execute(second, authoritative_lease=second.lease, now_ms=_NOW_MS),
    )
    assert entered == 2


@pytest.mark.asyncio
async def test_executor_must_return_declared_outcome_type() -> None:
    async def invalid_executor(workload: RunnerWorkloadV1) -> object:
        del workload
        return {"ok": True}

    engine = InProcessRunnerEngine(
        tenant_id="tenant-1",
        organization_id="org-1",
        runner_id="runner-1",
        capabilities=("browser",),
        executor=invalid_executor,  # type: ignore[arg-type]
    )
    workload = _workload()
    with pytest.raises(RunnerExecutorContractError, match="invalid outcome"):
        await engine.execute(
            workload,
            authoritative_lease=workload.lease,
            now_ms=_NOW_MS,
        )


def test_result_parser_rejects_unknown_status_and_extra_fields() -> None:
    workload = _workload()
    result = RunnerResultV1(
        job=workload.job,
        lease=workload.lease,
        authorization=workload.authorization,
        idempotency_key=workload.idempotency_key,
        workload_digest=workload.workload_digest,
        status=JobStatus.SUCCEEDED,
        started_at_ms=_NOW_MS,
        completed_at_ms=_NOW_MS,
        payload=CanonicalPayload.from_mapping({"ok": True}),
    )
    wire = result.to_wire()
    wire["status"] = "partially_succeeded"
    with pytest.raises(ProtocolError, match="unknown"):
        RunnerResultV1.from_wire(wire)

    wire = result.to_wire()
    wire["debug"] = "secret"
    with pytest.raises(ProtocolError, match="fields mismatch"):
        RunnerResultV1.from_wire(wire)
