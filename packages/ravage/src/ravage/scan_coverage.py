"""Deterministic, path-free coverage certificates for finite scan plans."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicySnapshot

SCAN_COVERAGE_SCHEMA = "ravage.scan-coverage"
SCAN_COVERAGE_VERSION = 1
MAX_PROBE_RECORDS = 512
MAX_CERTIFICATE_BYTES = 256_000

_MAX_TOKEN_CHARS = 96
_MAX_REASON_CODES = 8
_MAX_SURFACE_KEY_CHARS = 4_096
_MAX_FINDINGS_PER_PROBE = 10_000
_MAX_COUNTER_VALUE = 1_000_000_000_000
_TOKEN_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,94}[a-z0-9])?\Z")


class ScanCoverageError(ValueError):
    """A coverage input cannot be represented truthfully and safely."""


class ProbeDisposition(StrEnum):
    """Final, non-overlapping disposition for one planner decision."""

    COMPLETED_FINDING = "completed_finding"
    COMPLETED_NO_FINDING = "completed_no_finding"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    BLOCKED_BUDGET = "blocked_budget"
    TRANSPORT_INCOMPLETE = "transport_incomplete"


class RequestAccountingStatus(StrEnum):
    """How completely a request count represents physical target traffic."""

    EXACT = "exact"
    LOWER_BOUND = "lower_bound"
    UNAVAILABLE = "unavailable"


class ScanCoverageStatus(StrEnum):
    """Whether the finite recorded plan completed without known limitations."""

    COMPLETE = "complete"
    PARTIAL = "partial"


_PLANNER_TERMINAL_DISPOSITIONS = frozenset(
    {
        ProbeDisposition.NOT_APPLICABLE,
        ProbeDisposition.UNSUPPORTED,
        ProbeDisposition.BLOCKED_BUDGET,
    }
)


@dataclass(frozen=True, slots=True)
class PlannerProbeDecision:
    """One bounded planner decision, without emitting its raw target surface."""

    probe_id: str
    family: str
    rank: int
    surface_key: str = field(default="global", repr=False)
    reason_codes: tuple[str, ...] = ()
    terminal_disposition: ProbeDisposition | None = None

    def __post_init__(self) -> None:
        _require_token(self.probe_id, "probe_id")
        _require_token(self.family, "family")
        _require_non_negative_count(self.rank, "rank")
        if not isinstance(self.surface_key, str):
            message = "surface_key must be a string"
            raise TypeError(message)
        if len(self.surface_key) > _MAX_SURFACE_KEY_CHARS:
            message = "surface_key is too long"
            raise ScanCoverageError(message)
        normalized_reasons = _normalize_reason_codes(self.reason_codes)
        object.__setattr__(self, "reason_codes", normalized_reasons)
        if self.terminal_disposition is not None:
            try:
                disposition = ProbeDisposition(self.terminal_disposition)
            except ValueError as exc:
                message = "terminal_disposition is invalid"
                raise ScanCoverageError(message) from exc
            if disposition not in _PLANNER_TERMINAL_DISPOSITIONS:
                message = (
                    "planner decisions may terminate only as inapplicable, unsupported, or blocked"
                )
                raise ScanCoverageError(message)
            object.__setattr__(self, "terminal_disposition", disposition)

    @property
    def surface_ref(self) -> str:
        """Return a deterministic reference without disclosing a URL or path."""
        digest = hashlib.sha256(self.surface_key.encode("utf-8")).hexdigest()[:24]
        return f"sha256:{digest}"


@dataclass(frozen=True, slots=True)
class ProbeCoverageOutcome:
    """Bounded result supplied after one selected probe finishes or stops."""

    probe_id: str
    disposition: ProbeDisposition
    finding_count: int = 0
    physical_request_count: int = 0
    request_accounting_status: RequestAccountingStatus = RequestAccountingStatus.EXACT
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_token(self.probe_id, "probe_id")
        try:
            disposition = ProbeDisposition(self.disposition)
        except ValueError as exc:
            message = "probe disposition is invalid"
            raise ScanCoverageError(message) from exc
        object.__setattr__(self, "disposition", disposition)
        _require_non_negative_count(
            self.finding_count,
            "finding_count",
            maximum=_MAX_FINDINGS_PER_PROBE,
        )
        _require_non_negative_count(self.physical_request_count, "physical_request_count")
        try:
            accounting = RequestAccountingStatus(self.request_accounting_status)
        except ValueError as exc:
            message = "request_accounting_status is invalid"
            raise ScanCoverageError(message) from exc
        object.__setattr__(self, "request_accounting_status", accounting)
        object.__setattr__(self, "reason_codes", _normalize_reason_codes(self.reason_codes))
        if disposition is ProbeDisposition.COMPLETED_FINDING and not self.finding_count:
            message = "completed_finding requires at least one finding"
            raise ScanCoverageError(message)
        if disposition is not ProbeDisposition.COMPLETED_FINDING and self.finding_count:
            message = "only completed_finding may carry findings"
            raise ScanCoverageError(message)


@dataclass(frozen=True, slots=True)
class ProbeCoverageRecord:
    """Final certificate record for one planner decision."""

    probe_id: str
    family: str
    planner_rank: int
    surface_ref: str
    disposition: ProbeDisposition
    finding_count: int
    physical_request_count: int
    request_accounting_status: RequestAccountingStatus
    reason_codes: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        """Return a stable, path-free JSON value."""
        return {
            "disposition": self.disposition.value,
            "family": self.family,
            "finding_count": self.finding_count,
            "physical_request_count": self.physical_request_count,
            "planner_rank": self.planner_rank,
            "probe_id": self.probe_id,
            "reason_codes": list(self.reason_codes),
            "request_accounting_status": self.request_accounting_status.value,
            "surface_ref": self.surface_ref,
        }


@dataclass(frozen=True, slots=True)
class ScanTrafficCoverage:
    """Path-free traffic policy and whole-run accounting projection."""

    accounting_status: RequestAccountingStatus
    policy_mode: str
    max_rps: float | None
    max_physical_requests: int | None
    cache_enabled: bool | None
    deduplicate: bool | None
    max_retries: int | None
    physical_request_count: int | None
    completed_request_count: int | None
    incomplete_request_count: int | None
    pending_dispatch_count: int | None
    reservation_count: int | None
    cache_hit_count: int | None
    deduplicated_count: int | None
    retry_count: int | None
    blocked_count: int | None
    circuit_open_count: int | None
    unmetered_action_count: int | None

    def to_json(self) -> dict[str, object]:
        """Return the fixed-size traffic projection."""
        return {
            "accounting_status": self.accounting_status.value,
            "blocked_count": self.blocked_count,
            "cache_enabled": self.cache_enabled,
            "cache_hit_count": self.cache_hit_count,
            "circuit_open_count": self.circuit_open_count,
            "completed_request_count": self.completed_request_count,
            "deduplicate": self.deduplicate,
            "deduplicated_count": self.deduplicated_count,
            "incomplete_request_count": self.incomplete_request_count,
            "max_physical_requests": self.max_physical_requests,
            "max_retries": self.max_retries,
            "max_rps": self.max_rps,
            "pending_dispatch_count": self.pending_dispatch_count,
            "physical_request_count": self.physical_request_count,
            "policy_mode": self.policy_mode,
            "reservation_count": self.reservation_count,
            "retry_count": self.retry_count,
            "unmetered_action_count": self.unmetered_action_count,
        }


@dataclass(frozen=True, slots=True)
class ScanCoverageCertificate:
    """Immutable versioned result of a finite planner run."""

    status: ScanCoverageStatus
    completion_basis: str
    limitations: tuple[str, ...]
    probes: tuple[ProbeCoverageRecord, ...]
    traffic: ScanTrafficCoverage

    def to_json(self) -> dict[str, object]:
        """Return the deterministic certificate document."""
        disposition_counts = {
            disposition.value: sum(record.disposition is disposition for record in self.probes)
            for disposition in ProbeDisposition
        }
        return {
            "completion_basis": self.completion_basis,
            "limitations": list(self.limitations),
            "probes": [record.to_json() for record in self.probes],
            "schema": SCAN_COVERAGE_SCHEMA,
            "status": self.status.value,
            "summary": {
                "completed_probe_count": sum(
                    record.disposition
                    in {
                        ProbeDisposition.COMPLETED_FINDING,
                        ProbeDisposition.COMPLETED_NO_FINDING,
                    }
                    for record in self.probes
                ),
                "disposition_counts": disposition_counts,
                "finding_count": sum(record.finding_count for record in self.probes),
                "planner_decision_count": len(self.probes),
            },
            "traffic": self.traffic.to_json(),
            "version": SCAN_COVERAGE_VERSION,
        }

    def to_json_text(self) -> str:
        """Serialize reproducibly with a trailing newline."""
        encoded = json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n"
        if len(encoded.encode("utf-8")) > MAX_CERTIFICATE_BYTES:
            message = "scan coverage certificate exceeds its size limit"
            raise ScanCoverageError(message)
        return encoded


class ScanCoverageRecorder:
    """Collect planner decisions and outcomes without performing file I/O."""

    def __init__(self, *, max_probe_records: int = MAX_PROBE_RECORDS) -> None:
        _require_non_negative_count(max_probe_records, "max_probe_records")
        if not max_probe_records or max_probe_records > MAX_PROBE_RECORDS:
            message = f"max_probe_records must be between 1 and {MAX_PROBE_RECORDS}"
            raise ScanCoverageError(message)
        self._max_probe_records = max_probe_records
        self._decisions: dict[str, PlannerProbeDecision] = {}
        self._outcomes: dict[str, ProbeCoverageOutcome] = {}

    def record_planner_decision(self, decision: PlannerProbeDecision) -> None:
        """Record exactly one planner decision for a probe identifier."""
        if not isinstance(decision, PlannerProbeDecision):
            message = "decision must be a PlannerProbeDecision"
            raise TypeError(message)
        if decision.probe_id in self._decisions:
            message = f"duplicate planner decision: {decision.probe_id}"
            raise ScanCoverageError(message)
        if len(self._decisions) >= self._max_probe_records:
            message = "scan coverage planner decision limit reached"
            raise ScanCoverageError(message)
        self._decisions[decision.probe_id] = decision

    def record_probe_outcome(self, outcome: ProbeCoverageOutcome) -> None:
        """Attach one final outcome to a previously selected decision."""
        if not isinstance(outcome, ProbeCoverageOutcome):
            message = "outcome must be a ProbeCoverageOutcome"
            raise TypeError(message)
        decision = self._decisions.get(outcome.probe_id)
        if decision is None:
            message = f"probe outcome has no planner decision: {outcome.probe_id}"
            raise ScanCoverageError(message)
        if decision.terminal_disposition is not None:
            message = f"terminal planner decision cannot accept an outcome: {outcome.probe_id}"
            raise ScanCoverageError(message)
        if outcome.probe_id in self._outcomes:
            message = f"duplicate probe outcome: {outcome.probe_id}"
            raise ScanCoverageError(message)
        self._outcomes[outcome.probe_id] = outcome

    def finalize(
        self,
        *,
        planner_frontier_exhausted: bool,
        traffic_snapshot: TrafficPolicySnapshot | None,
        traffic_config: TrafficPolicyConfig | None,
    ) -> ScanCoverageCertificate:
        """Build a deterministic certificate from the recorded finite plan."""
        if type(planner_frontier_exhausted) is not bool:
            message = "planner_frontier_exhausted must be a boolean"
            raise TypeError(message)
        records, missing_outcome = self._build_records()
        traffic = _traffic_coverage(traffic_snapshot, traffic_config)
        limitations = _limitations(
            records=records,
            traffic=traffic,
            planner_frontier_exhausted=planner_frontier_exhausted,
            missing_outcome=missing_outcome,
            traffic_config_available=traffic_config is not None,
        )
        certificate = ScanCoverageCertificate(
            status=(ScanCoverageStatus.PARTIAL if limitations else ScanCoverageStatus.COMPLETE),
            completion_basis=(
                "planner_frontier_exhausted"
                if planner_frontier_exhausted
                else "planner_frontier_open"
            ),
            limitations=limitations,
            probes=records,
            traffic=traffic,
        )
        certificate.to_json_text()
        return certificate

    def _build_records(self) -> tuple[tuple[ProbeCoverageRecord, ...], bool]:
        records: list[ProbeCoverageRecord] = []
        missing_outcome = False
        ordered = sorted(
            self._decisions.values(),
            key=lambda item: (item.rank, item.probe_id, item.family, item.surface_ref),
        )
        for decision in ordered:
            outcome = self._outcomes.get(decision.probe_id)
            if decision.terminal_disposition is not None:
                disposition = decision.terminal_disposition
                outcome = None
            elif outcome is None:
                disposition = ProbeDisposition.TRANSPORT_INCOMPLETE
                missing_outcome = True
            else:
                disposition = outcome.disposition
            reason_codes = set(decision.reason_codes)
            if outcome is not None:
                reason_codes.update(outcome.reason_codes)
            elif decision.terminal_disposition is None:
                reason_codes.add("probe_outcome_missing")
            normalized_reasons = _normalize_reason_codes(tuple(reason_codes))
            records.append(
                ProbeCoverageRecord(
                    probe_id=decision.probe_id,
                    family=decision.family,
                    planner_rank=decision.rank,
                    surface_ref=decision.surface_ref,
                    disposition=disposition,
                    finding_count=outcome.finding_count if outcome is not None else 0,
                    physical_request_count=(
                        outcome.physical_request_count if outcome is not None else 0
                    ),
                    request_accounting_status=(
                        outcome.request_accounting_status
                        if outcome is not None
                        else (
                            RequestAccountingStatus.EXACT
                            if decision.terminal_disposition is not None
                            else RequestAccountingStatus.UNAVAILABLE
                        )
                    ),
                    reason_codes=normalized_reasons,
                )
            )
        return tuple(records), missing_outcome


def write_scan_coverage_certificate(
    path: str | Path,
    certificate: ScanCoverageCertificate,
) -> Path:
    """Atomically persist a private, deterministic coverage certificate."""
    if not isinstance(certificate, ScanCoverageCertificate):
        message = "certificate must be a ScanCoverageCertificate"
        raise TypeError(message)
    output_path = Path(path).expanduser().absolute()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = certificate.to_json_text()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.chmod(0o600)
        temporary_path.replace(output_path)
        _fsync_directory(output_path.parent)
    finally:
        with suppress(FileNotFoundError):
            temporary_path.unlink()
    return output_path


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    with suppress(OSError):
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _traffic_coverage(
    snapshot: TrafficPolicySnapshot | None,
    config: TrafficPolicyConfig | None,
) -> ScanTrafficCoverage:
    if snapshot is None:
        accounting_status = RequestAccountingStatus.UNAVAILABLE
        counts: tuple[int | None, ...] = (None,) * 11
    else:
        if not isinstance(snapshot, TrafficPolicySnapshot):
            message = "traffic_snapshot must be a TrafficPolicySnapshot or None"
            raise TypeError(message)
        try:
            accounting_status = RequestAccountingStatus(snapshot.accounting_status)
        except ValueError as exc:
            message = "traffic snapshot accounting_status is invalid"
            raise ScanCoverageError(message) from exc
        counts = (
            snapshot.physical_request_count,
            snapshot.completed_request_count,
            snapshot.incomplete_request_count,
            snapshot.pending_dispatch_count,
            snapshot.reservation_count,
            snapshot.cache_hit_count,
            snapshot.deduplicated_count,
            snapshot.retry_count,
            snapshot.blocked_count,
            snapshot.circuit_open_count,
            snapshot.unmetered_action_count,
        )
        for value in counts:
            _require_non_negative_count(value, "traffic snapshot counter")
    if config is not None and not isinstance(config, TrafficPolicyConfig):
        message = "traffic_config must be a TrafficPolicyConfig or None"
        raise TypeError(message)
    if config is not None and config.max_physical_requests is not None:
        _require_non_negative_count(config.max_physical_requests, "max_physical_requests")
    if config is not None:
        _finite_optional_number(config.max_rps, "max_rps")
    (
        physical_request_count,
        completed_request_count,
        incomplete_request_count,
        pending_dispatch_count,
        reservation_count,
        cache_hit_count,
        deduplicated_count,
        retry_count,
        blocked_count,
        circuit_open_count,
        unmetered_action_count,
    ) = counts
    return ScanTrafficCoverage(
        accounting_status=accounting_status,
        policy_mode=config.mode.value if config is not None else "unavailable",
        max_rps=config.max_rps if config is not None else None,
        max_physical_requests=config.max_physical_requests if config is not None else None,
        cache_enabled=config.cache_enabled if config is not None else None,
        deduplicate=config.deduplicate if config is not None else None,
        max_retries=config.max_retries if config is not None else None,
        physical_request_count=physical_request_count,
        completed_request_count=completed_request_count,
        incomplete_request_count=incomplete_request_count,
        pending_dispatch_count=pending_dispatch_count,
        reservation_count=reservation_count,
        cache_hit_count=cache_hit_count,
        deduplicated_count=deduplicated_count,
        retry_count=retry_count,
        blocked_count=blocked_count,
        circuit_open_count=circuit_open_count,
        unmetered_action_count=unmetered_action_count,
    )


def _limitations(  # noqa: C901, PLR0912
    *,
    records: tuple[ProbeCoverageRecord, ...],
    traffic: ScanTrafficCoverage,
    planner_frontier_exhausted: bool,
    missing_outcome: bool,
    traffic_config_available: bool,
) -> tuple[str, ...]:
    limitations: set[str] = set()
    if not planner_frontier_exhausted:
        limitations.add("planner_frontier_open")
    if not records:
        limitations.add("planner_decisions_empty")
    if missing_outcome:
        limitations.add("probe_outcome_missing")
    completed = {
        ProbeDisposition.COMPLETED_FINDING,
        ProbeDisposition.COMPLETED_NO_FINDING,
    }
    if records and not any(record.disposition in completed for record in records):
        limitations.add("no_completed_probes")
    if any(record.disposition is ProbeDisposition.UNSUPPORTED for record in records):
        limitations.add("unsupported_probe")
    if any(record.disposition is ProbeDisposition.BLOCKED_BUDGET for record in records):
        limitations.add("budget_blocked")
    if any(record.disposition is ProbeDisposition.TRANSPORT_INCOMPLETE for record in records):
        limitations.add("transport_incomplete")
    if any(
        record.request_accounting_status is RequestAccountingStatus.LOWER_BOUND
        for record in records
    ):
        limitations.add("probe_request_accounting_lower_bound")
    if any(
        record.request_accounting_status is RequestAccountingStatus.UNAVAILABLE
        for record in records
    ):
        limitations.add("probe_request_accounting_unavailable")
    if traffic.accounting_status is RequestAccountingStatus.LOWER_BOUND:
        limitations.add("traffic_accounting_lower_bound")
    elif traffic.accounting_status is RequestAccountingStatus.UNAVAILABLE:
        limitations.add("traffic_accounting_unavailable")
    if not traffic_config_available:
        limitations.add("traffic_config_unavailable")
    if any(
        (value or 0) > 0
        for value in (
            traffic.incomplete_request_count,
            traffic.pending_dispatch_count,
            traffic.reservation_count,
        )
    ):
        limitations.add("traffic_incomplete")
    if (traffic.blocked_count or 0) > 0:
        limitations.add("traffic_policy_blocked")
    if (traffic.circuit_open_count or 0) > 0:
        limitations.add("traffic_circuit_open")
    if (traffic.unmetered_action_count or 0) > 0:
        limitations.add("unmetered_actions")
    return tuple(sorted(limitations))


def _normalize_reason_codes(reason_codes: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(reason_codes, tuple):
        message = "reason_codes must be a tuple"
        raise TypeError(message)
    if len(reason_codes) > _MAX_REASON_CODES:
        message = f"reason_codes cannot contain more than {_MAX_REASON_CODES} values"
        raise ScanCoverageError(message)
    for reason_code in reason_codes:
        _require_token(reason_code, "reason_code")
    return tuple(sorted(set(reason_codes)))


def _require_token(value: str, label: str) -> None:
    if not isinstance(value, str):
        message = f"{label} must be a string"
        raise TypeError(message)
    if len(value) > _MAX_TOKEN_CHARS or _TOKEN_PATTERN.fullmatch(value) is None:
        message = f"{label} must be a bounded lowercase identifier"
        raise ScanCoverageError(message)


def _require_non_negative_count(
    value: int,
    label: str,
    *,
    maximum: int = _MAX_COUNTER_VALUE,
) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        message = f"{label} must be an integer between 0 and {maximum}"
        raise ScanCoverageError(message)


def _finite_optional_number(value: float | None, label: str) -> None:
    """Validate an optional serialized float when extending the certificate."""
    if value is not None and (isinstance(value, bool) or not math.isfinite(float(value))):
        message = f"{label} must be finite or None"
        raise ScanCoverageError(message)


__all__ = [
    "MAX_CERTIFICATE_BYTES",
    "MAX_PROBE_RECORDS",
    "SCAN_COVERAGE_SCHEMA",
    "SCAN_COVERAGE_VERSION",
    "PlannerProbeDecision",
    "ProbeCoverageOutcome",
    "ProbeDisposition",
    "RequestAccountingStatus",
    "ScanCoverageCertificate",
    "ScanCoverageError",
    "ScanCoverageRecorder",
    "ScanCoverageStatus",
    "ScanTrafficCoverage",
    "write_scan_coverage_certificate",
]
