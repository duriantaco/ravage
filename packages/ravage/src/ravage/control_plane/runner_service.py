"""
Versioned execution boundary between a control plane and a Ravage runner.

The service types deliberately know nothing about graph state, SQLite, HTTP, or
queue transports.  A runner adapter supplies an executor and the authoritative
lease; this module validates the portable security boundary before invoking it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass
from itertools import islice
from typing import TYPE_CHECKING, ClassVar, Final, Protocol

from ravage.control_plane.identity import OrganizationId, TenantId
from ravage.control_plane.runner_protocol import (
    AuthorizationLineage,
    CanonicalPayload,
    JobIdentity,
    JobStatus,
    LeaseFence,
    ProtocolError,
    RegistryCapacityError,
    ResultConflictError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping


RUNNER_WORKLOAD_SCHEMA_V1: Final = "ravage.runner.workload.v1"
RUNNER_RESULT_SCHEMA_V1: Final = "ravage.runner.result.v1"

_WORKLOAD_VERSION: Final = 1
_MAX_CAPABILITIES: Final = 64
_MAX_CACHED_RESULTS: Final = 65_536
_MAX_INT: Final = (1 << 63) - 1
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CAPABILITY = re.compile(r"\A[a-z][a-z0-9_.-]{0,63}\Z")
_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")


class RunnerCompatibilityError(ProtocolError):
    """Raised when a runner cannot safely execute a workload version or capability set."""


class RunnerScopeError(ProtocolError):
    """Raised when work crosses the runner's configured identity boundary."""


class RunnerExecutorContractError(ProtocolError):
    """Raised when an injected executor violates the public result contract."""


@dataclass(frozen=True, slots=True)
class RunnerWorkloadV1:
    """A bounded, versioned unit of work presented to a runner engine."""

    SCHEMA: ClassVar[str] = RUNNER_WORKLOAD_SCHEMA_V1
    VERSION: ClassVar[int] = _WORKLOAD_VERSION

    job: JobIdentity
    lease: LeaseFence
    authorization: AuthorizationLineage
    idempotency_key: str
    required_capabilities: tuple[str, ...]
    payload: CanonicalPayload

    def __post_init__(self) -> None:
        if not isinstance(self.job, JobIdentity):
            message = "runner workload job must be a JobIdentity"
            raise ProtocolError(message)
        if not isinstance(self.lease, LeaseFence):
            message = "runner workload lease must be a LeaseFence"
            raise ProtocolError(message)
        if not isinstance(self.authorization, AuthorizationLineage):
            message = "runner workload authorization must be an AuthorizationLineage"
            raise ProtocolError(message)
        if not isinstance(self.payload, CanonicalPayload):
            message = "runner workload payload must be a CanonicalPayload"
            raise ProtocolError(message)
        _require_identifier(self.idempotency_key, "idempotency_key")
        _require_capabilities(self.required_capabilities, "required_capabilities")
        if self.lease.job != self.job:
            message = "runner workload job is not bound to its lease"
            raise ProtocolError(message)

    @property
    def workload_digest(self) -> str:
        """Digest logical work independently of renewable lease-fence metadata."""
        body = self.to_wire()
        del body["lease"]
        return _content_digest(body)

    @property
    def idempotency_identity(self) -> tuple[JobIdentity, str]:
        """Identify exactly one logical execution inside its tenant-scoped job."""
        return (self.job, self.idempotency_key)

    def to_wire(self) -> dict[str, object]:
        """Return the strict V1 JSON object carried by a transport adapter."""
        return {
            "authorization": self.authorization.to_wire(),
            "idempotency_key": self.idempotency_key,
            "job": self.job.to_wire(),
            "lease": self.lease.to_wire(),
            "payload": self.payload.to_mapping(),
            "payload_digest": self.payload.digest,
            "required_capabilities": list(self.required_capabilities),
            "schema": self.SCHEMA,
            "version": self.VERSION,
        }

    @classmethod
    def from_wire(cls, value: object) -> RunnerWorkloadV1:
        """Parse an exact-key V1 object, rejecting unknown or malformed input."""
        body = _require_object(value, "runner workload")
        _expect_keys(
            body,
            {
                "authorization",
                "idempotency_key",
                "job",
                "lease",
                "payload",
                "payload_digest",
                "required_capabilities",
                "schema",
                "version",
            },
            "runner workload",
        )
        _require_schema(body["schema"], cls.SCHEMA, "runner workload")
        _require_version(body["version"], cls.VERSION, "runner workload")
        capabilities = _capabilities_from_wire(body["required_capabilities"])
        return cls(
            job=JobIdentity.from_wire(body["job"]),
            lease=LeaseFence.from_wire(body["lease"]),
            authorization=AuthorizationLineage.from_wire(body["authorization"]),
            idempotency_key=_require_identifier(body["idempotency_key"], "idempotency_key"),
            required_capabilities=capabilities,
            payload=CanonicalPayload.from_wire(body["payload"], body["payload_digest"]),
        )


@dataclass(frozen=True, slots=True)
class RunnerExecutionOutcome:
    """Minimal executor-owned outcome; the engine binds all security metadata."""

    status: JobStatus
    payload: CanonicalPayload

    def __post_init__(self) -> None:
        if not isinstance(self.status, JobStatus):
            message = "runner execution status must be a JobStatus"
            raise RunnerExecutorContractError(message)
        if not isinstance(self.payload, CanonicalPayload):
            message = "runner execution payload must be a CanonicalPayload"
            raise RunnerExecutorContractError(message)


@dataclass(frozen=True, slots=True)
class RunnerResultV1:
    """A result bound to one workload, lease, and authorization lineage."""

    SCHEMA: ClassVar[str] = RUNNER_RESULT_SCHEMA_V1
    VERSION: ClassVar[int] = _WORKLOAD_VERSION

    job: JobIdentity
    lease: LeaseFence
    authorization: AuthorizationLineage
    idempotency_key: str
    workload_digest: str
    status: JobStatus
    started_at_ms: int
    completed_at_ms: int
    payload: CanonicalPayload

    def __post_init__(self) -> None:
        if not isinstance(self.job, JobIdentity):
            message = "runner result job must be a JobIdentity"
            raise ProtocolError(message)
        if not isinstance(self.lease, LeaseFence):
            message = "runner result lease must be a LeaseFence"
            raise ProtocolError(message)
        if not isinstance(self.authorization, AuthorizationLineage):
            message = "runner result authorization must be an AuthorizationLineage"
            raise ProtocolError(message)
        if not isinstance(self.status, JobStatus):
            message = "runner result status must be a JobStatus"
            raise ProtocolError(message)
        if not isinstance(self.payload, CanonicalPayload):
            message = "runner result payload must be a CanonicalPayload"
            raise ProtocolError(message)
        _require_identifier(self.idempotency_key, "idempotency_key")
        _require_digest(self.workload_digest, "workload_digest")
        _require_nonnegative_int(self.started_at_ms, "started_at_ms")
        _require_nonnegative_int(self.completed_at_ms, "completed_at_ms")
        if self.completed_at_ms < self.started_at_ms:
            message = "runner result completed_at_ms precedes started_at_ms"
            raise ProtocolError(message)
        if self.lease.job != self.job:
            message = "runner result job is not bound to its lease"
            raise ProtocolError(message)

    @property
    def idempotency_identity(self) -> tuple[JobIdentity, str]:
        """Identify the logical result independently of transport retries."""
        return (self.job, self.idempotency_key)

    @property
    def logical_result_digest(self) -> str:
        """Digest the logical result independently of renewable lease metadata."""
        body = self.to_wire()
        del body["lease"]
        return _content_digest(body)

    def to_wire(self) -> dict[str, object]:
        """Return the strict V1 JSON object carried by a transport adapter."""
        return {
            "authorization": self.authorization.to_wire(),
            "completed_at_ms": self.completed_at_ms,
            "idempotency_key": self.idempotency_key,
            "job": self.job.to_wire(),
            "lease": self.lease.to_wire(),
            "payload": self.payload.to_mapping(),
            "payload_digest": self.payload.digest,
            "schema": self.SCHEMA,
            "started_at_ms": self.started_at_ms,
            "status": self.status.value,
            "version": self.VERSION,
            "workload_digest": self.workload_digest,
        }

    @classmethod
    def from_wire(cls, value: object) -> RunnerResultV1:
        """Parse an exact-key V1 result, rejecting unknown or malformed input."""
        body = _require_object(value, "runner result")
        _expect_keys(
            body,
            {
                "authorization",
                "completed_at_ms",
                "idempotency_key",
                "job",
                "lease",
                "payload",
                "payload_digest",
                "schema",
                "started_at_ms",
                "status",
                "version",
                "workload_digest",
            },
            "runner result",
        )
        _require_schema(body["schema"], cls.SCHEMA, "runner result")
        _require_version(body["version"], cls.VERSION, "runner result")
        try:
            status = JobStatus(_require_string(body["status"], "status"))
        except ValueError as exc:
            message = "unknown runner result status"
            raise ProtocolError(message) from exc
        return cls(
            job=JobIdentity.from_wire(body["job"]),
            lease=LeaseFence.from_wire(body["lease"]),
            authorization=AuthorizationLineage.from_wire(body["authorization"]),
            idempotency_key=_require_identifier(body["idempotency_key"], "idempotency_key"),
            workload_digest=_require_digest(body["workload_digest"], "workload_digest"),
            status=status,
            started_at_ms=_require_nonnegative_int(body["started_at_ms"], "started_at_ms"),
            completed_at_ms=_require_nonnegative_int(
                body["completed_at_ms"],
                "completed_at_ms",
            ),
            payload=CanonicalPayload.from_wire(body["payload"], body["payload_digest"]),
        )


@dataclass(frozen=True, slots=True)
class RunnerNegotiation:
    """Successful agreement on one workload version and its required capabilities."""

    workload_version: int
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_positive_int(self.workload_version, "workload_version")
        _require_capabilities(self.capabilities, "capabilities")


class RunnerExecutor(Protocol):
    """Injected adapter that performs work after boundary validation succeeds."""

    async def __call__(self, workload: RunnerWorkloadV1) -> RunnerExecutionOutcome: ...


class RunnerEngine(Protocol):
    """Portable runner execution port consumed by a transport adapter."""

    @property
    def runner_id(self) -> str: ...

    @property
    def supported_workload_versions(self) -> tuple[int, ...]: ...

    @property
    def capabilities(self) -> tuple[str, ...]: ...

    def negotiate(
        self,
        *,
        workload_version: int,
        required_capabilities: tuple[str, ...],
    ) -> RunnerNegotiation: ...

    async def execute(
        self,
        workload: RunnerWorkloadV1,
        *,
        authoritative_lease: LeaseFence,
        now_ms: int,
    ) -> RunnerResultV1: ...


class InProcessRunnerEngine:
    """
    Bounded reference engine with process-local completed-result deduplication.

    The explicit ``idempotency_key`` is passed through to the executor, allowing
    a production adapter to make external effects durable.  This reference
    implementation additionally guarantees that concurrent or repeated calls
    for the same exact workload invoke the executor once while the completed
    result remains in its bounded registry. Unrelated identities execute
    concurrently. A replay preserves the lease that actually authorized the
    execution, even when accepted under a renewed lease. It never evicts
    registry or conflict-detection entries.
    """

    def __init__(  # noqa: PLR0913 - security boundary dependencies stay explicit.
        self,
        *,
        tenant_id: str,
        organization_id: str,
        runner_id: str,
        capabilities: Iterable[str],
        executor: RunnerExecutor,
        max_cached_results: int = 4096,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        try:
            TenantId(tenant_id)
        except (TypeError, ValueError) as exc:
            message = "runner tenant_id is not canonical"
            raise ProtocolError(message) from exc
        try:
            OrganizationId(organization_id)
        except (TypeError, ValueError) as exc:
            message = "runner organization_id is not canonical"
            raise ProtocolError(message) from exc
        self._runner_id = _require_identifier(runner_id, "runner_id")
        self._tenant_id = tenant_id
        self._organization_id = organization_id
        self._capabilities = _normalize_capabilities(capabilities, "capabilities")
        if not callable(executor):
            message = "runner executor must be callable"
            raise RunnerExecutorContractError(message)
        self._executor = executor
        if (
            type(max_cached_results) is not int
            or not 1 <= max_cached_results <= _MAX_CACHED_RESULTS
        ):
            message = f"max_cached_results must be an integer between 1 and {_MAX_CACHED_RESULTS}"
            raise ProtocolError(message)
        self._max_cached_results = max_cached_results
        self._clock_ms = clock_ms or _system_clock_ms
        self._results: dict[
            tuple[JobIdentity, str],
            tuple[str, RunnerResultV1],
        ] = {}
        self._execution_locks: dict[
            tuple[JobIdentity, str],
            tuple[str, asyncio.Lock],
        ] = {}
        self._registry_lock = asyncio.Lock()

    @property
    def runner_id(self) -> str:
        return self._runner_id

    @property
    def supported_workload_versions(self) -> tuple[int, ...]:
        return (_WORKLOAD_VERSION,)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self._capabilities

    def negotiate(
        self,
        *,
        workload_version: int,
        required_capabilities: tuple[str, ...],
    ) -> RunnerNegotiation:
        """Fail closed unless both the schema version and every capability match."""
        _require_positive_int(workload_version, "workload_version")
        requested = _require_capabilities(required_capabilities, "required_capabilities")
        if workload_version not in self.supported_workload_versions:
            message = f"unsupported runner workload version: {workload_version}"
            raise RunnerCompatibilityError(message)
        missing = tuple(sorted(set(requested) - set(self._capabilities)))
        if missing:
            message = f"runner lacks required capabilities: {list(missing)}"
            raise RunnerCompatibilityError(message)
        return RunnerNegotiation(
            workload_version=workload_version,
            capabilities=requested,
        )

    async def execute(  # noqa: C901 - validation and idempotency are one boundary.
        self,
        workload: RunnerWorkloadV1,
        *,
        authoritative_lease: LeaseFence,
        now_ms: int,
    ) -> RunnerResultV1:
        """Validate and execute one fenced, authorized, idempotent workload."""
        if not isinstance(workload, RunnerWorkloadV1):
            message = "runner engine requires a RunnerWorkloadV1"
            raise ProtocolError(message)
        if not isinstance(authoritative_lease, LeaseFence):
            message = "authoritative_lease must be a LeaseFence"
            raise ProtocolError(message)
        _require_nonnegative_int(now_ms, "now_ms")
        self._assert_scope(workload)
        self.negotiate(
            workload_version=workload.VERSION,
            required_capabilities=workload.required_capabilities,
        )
        authoritative_lease.assert_allows(workload.lease, now_ms=now_ms)
        workload.authorization.assert_valid_at(now_ms=now_ms)

        identity = workload.idempotency_identity
        workload_digest = workload.workload_digest
        async with self._registry_lock:
            previous = self._results.get(identity)
            if previous is not None:
                previous_digest, previous_result = previous
                if previous_digest != workload_digest:
                    message = "runner idempotency identity was reused for different work"
                    raise ResultConflictError(message)
                return previous_result
            slot = self._execution_locks.get(identity)
            if slot is None:
                if len(self._execution_locks) >= self._max_cached_results:
                    message = "runner completed-result registry capacity reached"
                    raise RegistryCapacityError(message)
                execution_lock = asyncio.Lock()
                self._execution_locks[identity] = (workload_digest, execution_lock)
            else:
                reserved_digest, execution_lock = slot
                if reserved_digest != workload_digest:
                    message = "runner idempotency identity was reused for different work"
                    raise ResultConflictError(message)

        async with execution_lock:
            async with self._registry_lock:
                previous = self._results.get(identity)
                if previous is not None:
                    previous_digest, previous_result = previous
                    if previous_digest != workload_digest:  # pragma: no cover - slot fences this
                        message = "runner idempotency identity was reused for different work"
                        raise ResultConflictError(message)
                    return previous_result
            started_at_ms = now_ms
            outcome = await self._executor(workload)
            if not isinstance(outcome, RunnerExecutionOutcome):
                message = "runner executor returned an invalid outcome"
                raise RunnerExecutorContractError(message)
            completed_at_ms = max(started_at_ms, _clock_value(self._clock_ms))
            result = RunnerResultV1(
                job=workload.job,
                lease=workload.lease,
                authorization=workload.authorization,
                idempotency_key=workload.idempotency_key,
                workload_digest=workload_digest,
                status=outcome.status,
                started_at_ms=started_at_ms,
                completed_at_ms=completed_at_ms,
                payload=outcome.payload,
            )
            async with self._registry_lock:
                self._results[identity] = (workload_digest, result)
            return result

    def _assert_scope(self, workload: RunnerWorkloadV1) -> None:
        if workload.job.tenant_id != self._tenant_id:
            message = "runner workload crosses tenant boundary"
            raise RunnerScopeError(message)
        if workload.job.organization_id != self._organization_id:
            message = "runner workload crosses organization boundary"
            raise RunnerScopeError(message)
        if workload.lease.runner_id != self._runner_id:
            message = "runner workload is assigned to a different runner"
            raise RunnerScopeError(message)


def _system_clock_ms() -> int:
    return time.time_ns() // 1_000_000


def _clock_value(clock: Callable[[], int]) -> int:
    value = clock()
    return _require_nonnegative_int(value, "clock_ms result")


def _require_object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        message = f"{label} must be an object"
        raise ProtocolError(message)
    return value


def _expect_keys(body: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(body)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        message = f"{label} fields mismatch; missing={missing}, unknown={unknown}"
        raise ProtocolError(message)


def _require_string(value: object, label: str) -> str:
    if type(value) is not str:
        message = f"{label} must be a string"
        raise ProtocolError(message)
    return value


def _require_identifier(value: object, label: str) -> str:
    text = _require_string(value, label)
    if _IDENTIFIER.fullmatch(text) is None:
        message = f"{label} is not a valid identifier"
        raise ProtocolError(message)
    return text


def _require_digest(value: object, label: str) -> str:
    text = _require_string(value, label)
    if _DIGEST.fullmatch(text) is None:
        message = f"{label} must be a lowercase SHA-256 digest"
        raise ProtocolError(message)
    return text


def _require_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INT:
        message = f"{label} must be a non-negative signed 64-bit integer"
        raise ProtocolError(message)
    return value


def _require_positive_int(value: object, label: str) -> int:
    parsed = _require_nonnegative_int(value, label)
    if parsed == 0:
        message = f"{label} must be positive"
        raise ProtocolError(message)
    return parsed


def _require_schema(value: object, expected: str, label: str) -> None:
    actual = _require_string(value, f"{label} schema")
    if actual != expected:
        message = f"unsupported {label} schema: {actual}"
        raise RunnerCompatibilityError(message)


def _require_version(value: object, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        message = f"unsupported {label} version"
        raise RunnerCompatibilityError(message)


def _require_capabilities(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not tuple:
        message = f"{label} must be an immutable tuple"
        raise ProtocolError(message)
    capabilities = value
    if len(capabilities) > _MAX_CAPABILITIES:
        message = f"{label} exceeds {_MAX_CAPABILITIES} entries"
        raise ProtocolError(message)
    for capability in capabilities:
        if type(capability) is not str or _CAPABILITY.fullmatch(capability) is None:
            message = f"{label} contains an invalid capability"
            raise ProtocolError(message)
    if len(capabilities) != len(set(capabilities)):
        message = f"{label} contains duplicate capabilities"
        raise ProtocolError(message)
    if capabilities != tuple(sorted(capabilities)):
        message = f"{label} must be sorted"
        raise ProtocolError(message)
    return capabilities


def _normalize_capabilities(value: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        message = f"{label} must be an iterable of capability names"
        raise ProtocolError(message)
    try:
        bounded = tuple(islice(value, _MAX_CAPABILITIES + 1))
        capabilities = tuple(sorted(bounded))
    except (TypeError, ValueError) as exc:
        message = f"{label} must contain comparable strings"
        raise ProtocolError(message) from exc
    return _require_capabilities(capabilities, label)


def _capabilities_from_wire(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        message = "required_capabilities must be a list"
        raise ProtocolError(message)
    if len(value) > _MAX_CAPABILITIES:
        message = f"required_capabilities exceeds {_MAX_CAPABILITIES} entries"
        raise ProtocolError(message)
    return _require_capabilities(tuple(value), "required_capabilities")


def _content_digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        message = "runner service value is not canonical JSON"
        raise ProtocolError(message) from exc
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "RUNNER_RESULT_SCHEMA_V1",
    "RUNNER_WORKLOAD_SCHEMA_V1",
    "InProcessRunnerEngine",
    "RunnerCompatibilityError",
    "RunnerEngine",
    "RunnerExecutionOutcome",
    "RunnerExecutor",
    "RunnerExecutorContractError",
    "RunnerNegotiation",
    "RunnerResultV1",
    "RunnerScopeError",
    "RunnerWorkloadV1",
]
