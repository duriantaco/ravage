"""
Offline referee for champion-versus-candidate improvement experiments.

The referee consumes small, aggregate run receipts.  It deliberately does not
read prompts, target responses, benchmark metadata, proof values, or the live
Ravage runtime.  This keeps the evaluator usable as a bolt-on and prevents a
candidate from changing the code that decides whether it won.

``evidence_backed_vulnerability_count`` means a distinct vulnerability matched
to evaluator-owned ground truth or accepted target-origin evidence.  Suspected
vulnerabilities are retained as telemetry but never count as improvement.
"""

# Receipt validation is intentionally explicit and returns bounded operator errors.
# ruff: noqa: C901, EM101, EM102, PLR0912, TRY003, TRY004, TRY301

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

EVALUATION_SCHEMA_VERSION: Final = "ravage.improvement-evaluation.v1"
RUN_RECEIPT_SCHEMA_VERSION: Final = "ravage.improvement-run.v2"
RUN_RECEIPT_SET_SCHEMA_VERSION: Final = "ravage.improvement-run-set.v2"
_LEGACY_RUN_RECEIPT_SCHEMA_VERSION: Final = "ravage.improvement-run.v1"
_LEGACY_RUN_RECEIPT_SET_SCHEMA_VERSION: Final = "ravage.improvement-run-set.v1"
EVALUATION_SUITE_SCHEMA_VERSION: Final = "ravage.improvement-suite.v1"

_PROMOTABLE_EXECUTION_KINDS = ("fixture", "live")
_HISTORICAL_EXECUTION_KIND = "historical_replay"
_MIN_REPEATS = 3
_GATES = (
    "input_and_matching",
    "execution_evidence",
    "safety_and_accounting",
    "controls",
    "reliability",
    "detection_stability",
    "efficiency",
)
_ZERO_TOLERANCE_METRICS: tuple[tuple[str, str, str], ...] = (
    (
        "proof_integrity_failure_count",
        "candidate_proof_integrity_failure",
        "candidate produced proof-integrity failures",
    ),
    (
        "false_proof_count",
        "candidate_false_proof",
        "candidate produced false proofs",
    ),
    (
        "request_accounting_mismatch_count",
        "candidate_request_accounting_mismatch",
        "candidate produced request-accounting mismatches",
    ),
    (
        "loop_violation_count",
        "candidate_loop_violation",
        "candidate produced loop-safety violations",
    ),
    (
        "provenance_violation_count",
        "candidate_provenance_violation",
        "candidate produced evidence-provenance violations",
    ),
    (
        "secret_leak_violation_count",
        "candidate_secret_leak_violation",
        "candidate produced secret-leak violations",
    ),
)
_ACCOUNTING_STATUS_RANK = {
    "invalid": -1,
    "unavailable": 0,
    "unspecified": 0,
    "lower_bound": 1,
    "reported": 1,
    "exact": 2,
}
_MISSING = object()
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_MAX_SUITE_BYTES = 4 * 1024 * 1024
_MAX_SUITE_CASES = 2048
_MAX_SUITE_REPEATS = 100
_MAX_COMMAND_ARG_CHARS = 1024


@dataclass(frozen=True)
class EvaluationConfig:
    """Frozen promotion policy for one candidate tournament."""

    min_repeats: int = _MIN_REPEATS
    min_case_win_rate: float = 2 / 3
    min_global_decisive_win_rate: float = 2 / 3
    min_win_rate_lower_bound: float = 0.30
    confidence_z: float = 1.281551565545
    max_efficiency_regression: float = 0.15
    require_control_receipts: bool = True
    required_cohorts: tuple[str, ...] = ()
    promotable_execution_kinds: tuple[str, ...] = _PROMOTABLE_EXECUTION_KINDS

    def __post_init__(self) -> None:
        if self.min_repeats < _MIN_REPEATS:
            raise ValueError("improvement evaluation requires at least three repeats")
        for name, value in (
            ("min_case_win_rate", self.min_case_win_rate),
            ("min_global_decisive_win_rate", self.min_global_decisive_win_rate),
            ("min_win_rate_lower_bound", self.min_win_rate_lower_bound),
        ):
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be between zero and one")
        if not math.isfinite(self.confidence_z) or self.confidence_z <= 0:
            raise ValueError("confidence_z must be positive and finite")
        if not math.isfinite(self.max_efficiency_regression) or self.max_efficiency_regression < 0:
            raise ValueError("max_efficiency_regression must be finite and non-negative")
        if not self.promotable_execution_kinds:
            raise ValueError("at least one promotable execution kind is required")
        if _HISTORICAL_EXECUTION_KIND in self.promotable_execution_kinds:
            raise ValueError("historical replay cannot be a promotable execution kind")

    def to_json(self) -> dict[str, object]:
        return {
            "min_repeats": self.min_repeats,
            "min_case_win_rate": self.min_case_win_rate,
            "min_global_decisive_win_rate": self.min_global_decisive_win_rate,
            "min_win_rate_lower_bound": self.min_win_rate_lower_bound,
            "confidence_z": self.confidence_z,
            "max_efficiency_regression": self.max_efficiency_regression,
            "require_control_receipts": self.require_control_receipts,
            "required_cohorts": sorted(set(self.required_cohorts)),
            "promotable_execution_kinds": sorted(set(self.promotable_execution_kinds)),
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> EvaluationConfig:
        required = {
            "min_repeats",
            "min_case_win_rate",
            "min_global_decisive_win_rate",
            "min_win_rate_lower_bound",
            "confidence_z",
            "max_efficiency_regression",
            "require_control_receipts",
            "required_cohorts",
            "promotable_execution_kinds",
        }
        if set(payload) != required:
            raise ValueError("evaluation config fields do not match the canonical schema")
        return cls(
            min_repeats=_non_negative_int(payload["min_repeats"], "min_repeats"),
            min_case_win_rate=_finite_float(
                payload["min_case_win_rate"],
                "min_case_win_rate",
            ),
            min_global_decisive_win_rate=_finite_float(
                payload["min_global_decisive_win_rate"],
                "min_global_decisive_win_rate",
            ),
            min_win_rate_lower_bound=_finite_float(
                payload["min_win_rate_lower_bound"],
                "min_win_rate_lower_bound",
            ),
            confidence_z=_finite_float(payload["confidence_z"], "confidence_z"),
            max_efficiency_regression=_finite_float(
                payload["max_efficiency_regression"],
                "max_efficiency_regression",
            ),
            require_control_receipts=_boolean(
                payload["require_control_receipts"],
                "require_control_receipts",
            ),
            required_cohorts=_string_tuple(
                payload["required_cohorts"],
                "required_cohorts",
            ),
            promotable_execution_kinds=_string_tuple(
                payload["promotable_execution_kinds"],
                "promotable_execution_kinds",
            ),
        )


@dataclass(frozen=True)
class EvaluationSuiteCase:
    """One evaluator-owned case group and its exact repeat matrix."""

    case_id: str
    cohort: str
    execution_kind: str
    repeats: int
    is_control: bool
    expected_vulnerability_count: int | None
    target_snapshot_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        if _OPAQUE_ID_RE.fullmatch(self.case_id) is None:
            raise ValueError("suite case_id must be a bounded opaque identifier")
        if _OPAQUE_ID_RE.fullmatch(self.cohort) is None:
            raise ValueError("suite cohort must be a bounded opaque identifier")
        if self.execution_kind not in _PROMOTABLE_EXECUTION_KINDS:
            raise ValueError("suite execution kind must be fixture or live")
        if isinstance(self.repeats, bool) or not _MIN_REPEATS <= self.repeats <= _MAX_SUITE_REPEATS:
            raise ValueError("suite repeats must be between three and one hundred")
        if self.expected_vulnerability_count is not None and (
            isinstance(self.expected_vulnerability_count, bool)
            or self.expected_vulnerability_count < 0
        ):
            raise ValueError("suite expected vulnerability count must be non-negative")
        if len(self.target_snapshot_digests) != self.repeats:
            raise ValueError("suite target snapshots must match the repeat count")
        for digest in self.target_snapshot_digests:
            _required_sha256(digest, "target_snapshot_digest")

    @property
    def group_key(self) -> tuple[str, str, str]:
        return (self.cohort, self.case_id, self.execution_kind)

    @property
    def keys(self) -> tuple[tuple[str, str, str, int], ...]:
        return tuple((*self.group_key, repeat) for repeat in range(1, self.repeats + 1))

    def to_json(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "cohort": self.cohort,
            "execution_kind": self.execution_kind,
            "repeats": self.repeats,
            "is_control": self.is_control,
            "expected_vulnerability_count": self.expected_vulnerability_count,
            "target_snapshot_digests": list(self.target_snapshot_digests),
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> EvaluationSuiteCase:
        expected = {
            "case_id",
            "cohort",
            "execution_kind",
            "repeats",
            "is_control",
            "expected_vulnerability_count",
            "target_snapshot_digests",
        }
        if set(payload) != expected:
            raise ValueError("evaluation suite case fields do not match the canonical schema")
        raw_expected = payload["expected_vulnerability_count"]
        expected_count = (
            None
            if raw_expected is None
            else _non_negative_int(raw_expected, "expected_vulnerability_count")
        )
        raw_snapshots = payload["target_snapshot_digests"]
        if not isinstance(raw_snapshots, list | tuple):
            raise ValueError("target_snapshot_digests must be a list")
        return cls(
            case_id=_opaque_id(payload["case_id"], "case_id"),
            cohort=_opaque_id(payload["cohort"], "cohort"),
            execution_kind=_execution_kind(
                _required_text(payload["execution_kind"], "execution_kind")
            ),
            repeats=_non_negative_int(payload["repeats"], "repeats", minimum=3),
            is_control=_boolean(payload["is_control"], "is_control"),
            expected_vulnerability_count=expected_count,
            target_snapshot_digests=tuple(
                _required_sha256(item, "target_snapshot_digest") for item in raw_snapshots
            ),
        )


@dataclass(frozen=True)
class EvaluationSuite:
    """Campaign-pinned evaluator matrix and execution identities."""

    cases: tuple[EvaluationSuiteCase, ...]
    model_fingerprint: str
    trusted_tests_digest: str
    runner_command: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.cases or len(self.cases) > _MAX_SUITE_CASES:
            raise ValueError("evaluation suite case count is outside the supported bounds")
        groups = [case.group_key for case in self.cases]
        if len(groups) != len(set(groups)):
            raise ValueError("evaluation suite contains duplicate case groups")
        _required_sha256(self.model_fingerprint, "model_fingerprint")
        _required_sha256(self.trusted_tests_digest, "trusted_tests_digest")
        if not self.runner_command or any(
            not item or len(item) > _MAX_COMMAND_ARG_CHARS or "\0" in item
            for item in self.runner_command
        ):
            raise ValueError("evaluation suite runner command is invalid")
        if not Path(self.runner_command[0]).is_absolute():
            raise ValueError("evaluation suite runner executable must be absolute")

    @property
    def expected_keys(self) -> frozenset[tuple[str, str, str, int]]:
        return frozenset(key for case in self.cases for key in case.keys)

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": EVALUATION_SUITE_SCHEMA_VERSION,
            "model_fingerprint": self.model_fingerprint,
            "trusted_tests_digest": self.trusted_tests_digest,
            "runner_command": list(self.runner_command),
            "cases": [
                case.to_json() for case in sorted(self.cases, key=lambda item: item.group_key)
            ],
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> EvaluationSuite:
        expected = {
            "schema_version",
            "model_fingerprint",
            "trusted_tests_digest",
            "runner_command",
            "cases",
        }
        if (
            set(payload) != expected
            or payload.get("schema_version") != EVALUATION_SUITE_SCHEMA_VERSION
        ):
            raise ValueError("evaluation suite fields or schema version are invalid")
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list):
            raise ValueError("evaluation suite cases must be a list")
        cases = tuple(
            EvaluationSuiteCase.from_mapping(item)
            if isinstance(item, Mapping)
            else _raise_invalid_suite_case()
            for item in raw_cases
        )
        command = _string_tuple(payload.get("runner_command"), "runner_command")
        return cls(
            cases=cases,
            model_fingerprint=_required_sha256(
                payload.get("model_fingerprint"),
                "model_fingerprint",
            ),
            trusted_tests_digest=_required_sha256(
                payload.get("trusted_tests_digest"),
                "trusted_tests_digest",
            ),
            runner_command=command,
        )

    @classmethod
    def from_bytes(cls, content: bytes) -> EvaluationSuite:
        if not isinstance(content, bytes) or not content or len(content) > _MAX_SUITE_BYTES:
            raise ValueError("evaluation suite bytes are empty or exceed the byte cap")
        try:
            payload = json.loads(content, object_pairs_hook=_reject_duplicate_json_keys)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("evaluation suite JSON is invalid") from exc
        if not isinstance(payload, Mapping):
            raise ValueError("evaluation suite must be an object")
        return cls.from_mapping(payload)


@dataclass(frozen=True)
class RunReceipt:
    """Secret-free metrics for one case, execution kind, and repeat."""

    case_id: str
    cohort: str
    repeat: int
    execution_kind: str
    status: str
    is_control: bool
    case_success: bool | None
    expected_vulnerability_count: int | None
    evidence_backed_vulnerability_count: int
    verified_vulnerability_count: int
    confirmed_finding_count: int
    suspected_vulnerability_count: int
    proof_integrity_failure_count: int
    false_proof_count: int
    request_accounting_mismatch_count: int
    loop_violation_count: int
    provenance_violation_count: int
    secret_leak_violation_count: int
    unmetered_action_count: int
    incomplete_request_count: int
    physical_request_count: int | None
    model_request_count: int | None
    cost_usd: float | None
    request_accounting_status: str = "unspecified"
    run_id: str = ""
    execution_attestation_digest: str | None = None
    pair_seed_digest: str = ""
    target_snapshot_digest: str = ""
    model_fingerprint: str = ""
    prompt_fingerprint: str = ""

    def __post_init__(self) -> None:
        for name in (
            "run_id",
            "pair_seed_digest",
            "target_snapshot_digest",
            "model_fingerprint",
            "prompt_fingerprint",
        ):
            _required_sha256(getattr(self, name), name)
        if (
            self.execution_kind in _PROMOTABLE_EXECUTION_KINDS
            or self.execution_attestation_digest is not None
        ):
            _required_sha256(
                self.execution_attestation_digest,
                "execution_attestation_digest",
            )
        if not (
            self.confirmed_finding_count
            <= self.verified_vulnerability_count
            <= self.evidence_backed_vulnerability_count
        ):
            raise ValueError("finding stages must satisfy confirmed <= verified <= evidence-backed")

    @property
    def key(self) -> tuple[str, str, str, int]:
        return (self.cohort, self.case_id, self.execution_kind, self.repeat)

    @property
    def group_key(self) -> tuple[str, str, str]:
        return (self.cohort, self.case_id, self.execution_kind)

    @property
    def timed_out(self) -> bool:
        return self.status == "timeout"

    @property
    def errored(self) -> bool:
        return self.status == "error"

    @property
    def failed(self) -> bool:
        return self.status == "failed"

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> RunReceipt:
        metrics = payload.get("metrics")
        metric_payload = metrics if isinstance(metrics, Mapping) else {}

        case_id = _required_text(_lookup(payload, metric_payload, "case_id"), "case_id")
        cohort = _required_text(_lookup(payload, metric_payload, "cohort"), "cohort")
        repeat = _non_negative_int(
            _lookup(payload, metric_payload, "repeat"),
            "repeat",
            minimum=1,
        )
        execution_kind = _execution_kind(
            _required_text(
                _lookup(payload, metric_payload, "execution_kind", "source_kind"),
                "execution_kind",
            )
        )
        status = _status(_required_text(_lookup(payload, metric_payload, "status"), "status"))
        explicit_control = _lookup(payload, metric_payload, "is_control", default=_MISSING)
        is_control = (
            _boolean(explicit_control, "is_control")
            if explicit_control is not _MISSING
            else "control" in cohort.casefold()
        )
        raw_success = _lookup(
            payload,
            metric_payload,
            "case_success",
            "passed",
            "solved",
            default=_MISSING,
        )
        case_success = (
            None
            if raw_success is _MISSING or raw_success is None
            else _boolean(raw_success, "case_success")
        )
        raw_expected = _lookup(
            payload,
            metric_payload,
            "expected_vulnerability_count",
            default=_MISSING,
        )
        expected = (
            None
            if raw_expected is _MISSING or raw_expected is None
            else _non_negative_int(raw_expected, "expected_vulnerability_count")
        )

        return cls(
            case_id=case_id,
            cohort=cohort,
            repeat=repeat,
            execution_kind=execution_kind,
            status=status,
            is_control=is_control,
            case_success=case_success,
            expected_vulnerability_count=expected,
            evidence_backed_vulnerability_count=_required_count(
                payload,
                metric_payload,
                "evidence_backed_vulnerability_count",
            ),
            verified_vulnerability_count=_required_count(
                payload,
                metric_payload,
                "verified_vulnerability_count",
            ),
            confirmed_finding_count=_required_count(
                payload,
                metric_payload,
                "confirmed_finding_count",
            ),
            suspected_vulnerability_count=_required_count(
                payload,
                metric_payload,
                "suspected_vulnerability_count",
            ),
            proof_integrity_failure_count=_required_count(
                payload,
                metric_payload,
                "proof_integrity_failure_count",
            ),
            false_proof_count=_required_count(payload, metric_payload, "false_proof_count"),
            request_accounting_mismatch_count=_required_count(
                payload,
                metric_payload,
                "request_accounting_mismatch_count",
            ),
            loop_violation_count=_required_count(
                payload,
                metric_payload,
                "loop_violation_count",
            ),
            provenance_violation_count=_required_count(
                payload,
                metric_payload,
                "provenance_violation_count",
            ),
            secret_leak_violation_count=_required_count(
                payload,
                metric_payload,
                "secret_leak_violation_count",
            ),
            unmetered_action_count=_required_count(
                payload,
                metric_payload,
                "unmetered_action_count",
                "http_unmetered_action_count",
            ),
            incomplete_request_count=_required_count(
                payload,
                metric_payload,
                "incomplete_request_count",
                "http_incomplete_request_count",
            ),
            physical_request_count=_optional_non_negative_int(
                _lookup(
                    payload,
                    metric_payload,
                    "physical_request_count",
                    "http_request_count",
                    default=None,
                ),
                "physical_request_count",
            ),
            model_request_count=_optional_non_negative_int(
                _lookup(payload, metric_payload, "model_request_count", default=None),
                "model_request_count",
            ),
            cost_usd=_optional_non_negative_float(
                _lookup(payload, metric_payload, "cost_usd", default=None),
                "cost_usd",
            ),
            request_accounting_status=_accounting_status(
                _required_text(
                    _lookup(
                        payload,
                        metric_payload,
                        "request_accounting_status",
                        "http_request_count_status",
                    ),
                    "request_accounting_status",
                )
            ),
            run_id=_required_sha256(
                _lookup(payload, metric_payload, "run_id"),
                "run_id",
            ),
            execution_attestation_digest=_optional_sha256(
                _lookup(
                    payload,
                    metric_payload,
                    "execution_attestation_digest",
                    default=None,
                ),
                "execution_attestation_digest",
            ),
            pair_seed_digest=_required_sha256(
                _lookup(payload, metric_payload, "pair_seed_digest"),
                "pair_seed_digest",
            ),
            target_snapshot_digest=_required_sha256(
                _lookup(payload, metric_payload, "target_snapshot_digest"),
                "target_snapshot_digest",
            ),
            model_fingerprint=_required_sha256(
                _lookup(payload, metric_payload, "model_fingerprint"),
                "model_fingerprint",
            ),
            prompt_fingerprint=_required_sha256(
                _lookup(payload, metric_payload, "prompt_fingerprint"),
                "prompt_fingerprint",
            ),
        )

    def to_json(self) -> dict[str, object]:
        """Return only the bounded metrics used by the referee."""
        return {
            "schema_version": RUN_RECEIPT_SCHEMA_VERSION,
            "case_id": self.case_id,
            "cohort": self.cohort,
            "repeat": self.repeat,
            "execution_kind": self.execution_kind,
            "status": self.status,
            "is_control": self.is_control,
            "case_success": self.case_success,
            "expected_vulnerability_count": self.expected_vulnerability_count,
            "run_id": self.run_id,
            "execution_attestation_digest": self.execution_attestation_digest,
            "pair_seed_digest": self.pair_seed_digest,
            "target_snapshot_digest": self.target_snapshot_digest,
            "model_fingerprint": self.model_fingerprint,
            "prompt_fingerprint": self.prompt_fingerprint,
            "metrics": {
                name: getattr(self, name)
                for name in (
                    "evidence_backed_vulnerability_count",
                    "verified_vulnerability_count",
                    "confirmed_finding_count",
                    "suspected_vulnerability_count",
                    "proof_integrity_failure_count",
                    "false_proof_count",
                    "request_accounting_mismatch_count",
                    "loop_violation_count",
                    "provenance_violation_count",
                    "secret_leak_violation_count",
                    "unmetered_action_count",
                    "incomplete_request_count",
                    "physical_request_count",
                    "model_request_count",
                    "cost_usd",
                    "request_accounting_status",
                )
            },
        }


def evaluation_suite_from_receipts(
    receipts: Sequence[RunReceipt],
    *,
    trusted_tests_digest: str,
    runner_command: Sequence[str],
) -> EvaluationSuite:
    """Build a suite once from an evaluator-owned reviewed champion matrix."""
    if not receipts:
        raise ValueError("cannot build an evaluation suite without receipts")
    models = {item.model_fingerprint for item in receipts}
    if len(models) != 1:
        raise ValueError("suite receipts must use exactly one model fingerprint")
    grouped: dict[tuple[str, str, str], list[RunReceipt]] = {}
    for receipt in receipts:
        grouped.setdefault(receipt.group_key, []).append(receipt)
    cases: list[EvaluationSuiteCase] = []
    for group_key, items in sorted(grouped.items()):
        ordered = sorted(items, key=lambda item: item.repeat)
        if [item.repeat for item in ordered] != list(range(1, len(ordered) + 1)):
            raise ValueError("suite receipt repeats must be contiguous and start at one")
        first = ordered[0]
        if any(
            item.is_control != first.is_control
            or item.expected_vulnerability_count != first.expected_vulnerability_count
            for item in ordered
        ):
            raise ValueError("suite receipt metadata must be stable across repeats")
        cases.append(
            EvaluationSuiteCase(
                case_id=group_key[1],
                cohort=group_key[0],
                execution_kind=group_key[2],
                repeats=len(ordered),
                is_control=first.is_control,
                expected_vulnerability_count=first.expected_vulnerability_count,
                target_snapshot_digests=tuple(item.target_snapshot_digest for item in ordered),
            )
        )
    return EvaluationSuite(
        cases=tuple(cases),
        model_fingerprint=next(iter(models)),
        trusted_tests_digest=_required_sha256(
            trusted_tests_digest,
            "trusted_tests_digest",
        ),
        runner_command=tuple(runner_command),
    )


@dataclass(frozen=True)
class Rejection:
    gate: str
    code: str
    message: str
    details: dict[str, object] = field(default_factory=dict)

    def to_json(self) -> dict[str, object]:
        return {
            "gate": self.gate,
            "code": self.code,
            "message": self.message,
            "details": _canonical_value(self.details),
        }


@dataclass(frozen=True)
class EvaluationReceipt:
    accepted: bool
    config: EvaluationConfig
    matching: dict[str, object]
    aggregate: dict[str, object]
    stability: dict[str, object]
    rejections: tuple[Rejection, ...]

    @property
    def decision(self) -> str:
        return "promote" if self.accepted else "reject"

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "decision": self.decision,
            "accepted": self.accepted,
            "promotable": self.accepted,
            "config": self.config.to_json(),
            "matching": _canonical_value(self.matching),
            "aggregate": _canonical_value(self.aggregate),
            "stability": _canonical_value(self.stability),
            "gates": _gate_results(self.rejections),
            "rejections": [item.to_json() for item in self.rejections],
        }
        payload["receipt_digest"] = f"sha256:{_digest_json(payload)}"
        return payload

    def canonical_json(self) -> str:
        return canonical_json(self.to_json())

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> EvaluationReceipt:
        expected_fields = {
            "schema_version",
            "decision",
            "accepted",
            "promotable",
            "config",
            "matching",
            "aggregate",
            "stability",
            "gates",
            "rejections",
            "receipt_digest",
        }
        if set(payload) != expected_fields:
            raise ValueError("evaluation receipt fields do not match the canonical schema")
        if payload.get("schema_version") != EVALUATION_SCHEMA_VERSION:
            raise ValueError("unsupported evaluation receipt schema")
        raw_digest = _required_text(payload.get("receipt_digest"), "receipt_digest")
        unsigned = {key: value for key, value in payload.items() if key != "receipt_digest"}
        expected_digest = f"sha256:{_digest_json(unsigned)}"
        if raw_digest != expected_digest:
            raise ValueError("evaluation receipt digest mismatch")
        accepted = _boolean(payload.get("accepted"), "accepted")
        if _boolean(payload.get("promotable"), "promotable") != accepted:
            raise ValueError("evaluation promotable status disagrees with accepted status")
        if payload.get("decision") != ("promote" if accepted else "reject"):
            raise ValueError("evaluation decision disagrees with accepted status")
        raw_config = payload.get("config")
        raw_matching = payload.get("matching")
        raw_aggregate = payload.get("aggregate")
        raw_stability = payload.get("stability")
        raw_rejections = payload.get("rejections")
        if not isinstance(raw_config, Mapping):
            raise ValueError("evaluation config must be an object")
        if not isinstance(raw_matching, Mapping):
            raise ValueError("evaluation matching summary must be an object")
        if not isinstance(raw_aggregate, Mapping):
            raise ValueError("evaluation aggregate must be an object")
        if not isinstance(raw_stability, Mapping):
            raise ValueError("evaluation stability summary must be an object")
        if not isinstance(raw_rejections, list):
            raise ValueError("evaluation rejections must be a list")
        rejections: list[Rejection] = []
        for raw in raw_rejections:
            if not isinstance(raw, Mapping):
                raise ValueError("evaluation rejection must be an object")
            details = raw.get("details")
            if not isinstance(details, Mapping):
                raise ValueError("evaluation rejection details must be an object")
            rejections.append(
                Rejection(
                    gate=_required_text(raw.get("gate"), "rejection.gate"),
                    code=_required_text(raw.get("code"), "rejection.code"),
                    message=_required_text(raw.get("message"), "rejection.message"),
                    details={str(key): value for key, value in details.items()},
                )
            )
        if accepted == bool(rejections):
            raise ValueError("evaluation acceptance must be the inverse of rejection presence")
        expected_gates = _gate_results(rejections)
        if payload.get("gates") != expected_gates:
            raise ValueError("evaluation gate summary does not match its rejections")
        return cls(
            accepted=accepted,
            config=EvaluationConfig.from_mapping(raw_config),
            matching={str(key): value for key, value in raw_matching.items()},
            aggregate={str(key): value for key, value in raw_aggregate.items()},
            stability={str(key): value for key, value in raw_stability.items()},
            rejections=tuple(rejections),
        )


def evaluate_candidate(
    champion_receipts: Sequence[Mapping[str, object] | RunReceipt],
    candidate_receipts: Sequence[Mapping[str, object] | RunReceipt],
    *,
    config: EvaluationConfig | None = None,
    suite: EvaluationSuite | None = None,
) -> EvaluationReceipt:
    """Evaluate one candidate without importing or executing the live runtime."""
    selected = config or EvaluationConfig()
    rejections: list[Rejection] = []
    champion = _parse_receipts(champion_receipts, side="champion", rejections=rejections)
    candidate = _parse_receipts(candidate_receipts, side="candidate", rejections=rejections)
    champion_by_key = _index_receipts(champion, side="champion", rejections=rejections)
    candidate_by_key = _index_receipts(candidate, side="candidate", rejections=rejections)

    champion_keys = set(champion_by_key)
    candidate_keys = set(candidate_by_key)
    missing_candidate = sorted(champion_keys - candidate_keys)
    extra_candidate = sorted(candidate_keys - champion_keys)
    if missing_candidate or extra_candidate:
        _reject(
            rejections,
            gate="input_and_matching",
            code="unmatched_run_receipts",
            message="champion and candidate receipts do not form an exact matched matrix",
            details={
                "missing_candidate": [_key_json(key) for key in missing_candidate],
                "extra_candidate": [_key_json(key) for key in extra_candidate],
            },
        )

    matched_keys = sorted(champion_keys & candidate_keys)
    matched = [(champion_by_key[key], candidate_by_key[key]) for key in matched_keys]
    if suite is not None:
        _validate_suite_matrix(
            champion_by_key,
            candidate_by_key,
            suite=suite,
            config=selected,
            rejections=rejections,
        )
    _validate_matched_metadata(matched, rejections=rejections)
    _validate_execution_attestations(
        champion,
        candidate,
        matched,
        rejections=rejections,
    )
    promotable_kinds = set(selected.promotable_execution_kinds)
    promotable_pairs = [pair for pair in matched if pair[0].execution_kind in promotable_kinds]
    historical_pairs = [
        pair for pair in matched if pair[0].execution_kind == _HISTORICAL_EXECUTION_KIND
    ]

    _validate_repetition_matrix(
        promotable_pairs,
        min_repeats=selected.min_repeats,
        rejections=rejections,
    )
    if not promotable_pairs:
        _reject(
            rejections,
            gate="execution_evidence",
            code="historical_replay_only",
            message=(
                "historical replay is diagnostic only; promotion requires matched live or "
                "controlled-fixture receipts"
            ),
            details={"historical_pairs": len(historical_pairs)},
        )

    promotable_cohorts = {pair[0].cohort for pair in promotable_pairs}
    missing_cohorts = sorted(set(selected.required_cohorts) - promotable_cohorts)
    if missing_cohorts:
        _reject(
            rejections,
            gate="input_and_matching",
            code="required_cohort_missing",
            message="the promotable matched matrix is missing required cohorts",
            details={"missing_cohorts": missing_cohorts},
        )

    control_pairs = [pair for pair in promotable_pairs if pair[0].is_control]
    non_control_pairs = [pair for pair in promotable_pairs if not pair[0].is_control]
    if selected.require_control_receipts and not control_pairs:
        _reject(
            rejections,
            gate="controls",
            code="control_receipts_missing",
            message="promotion requires a matched control cohort",
        )
    if promotable_pairs and not non_control_pairs:
        _reject(
            rejections,
            gate="detection_stability",
            code="improvement_receipts_missing",
            message="promotion requires at least one non-control capability cohort",
        )

    champion_promotable = [pair[0] for pair in promotable_pairs]
    candidate_promotable = [pair[1] for pair in promotable_pairs]
    champion_aggregate = _aggregate(champion)
    candidate_aggregate = _aggregate(candidate)
    champion_live_aggregate = _aggregate(champion_promotable)
    candidate_live_aggregate = _aggregate(candidate_promotable)

    _evaluate_safety_and_accounting(
        champion_promotable,
        candidate_promotable,
        promotable_pairs,
        rejections=rejections,
    )
    _evaluate_ground_truth_precision(promotable_pairs, rejections=rejections)
    _evaluate_controls(control_pairs, rejections=rejections)
    _evaluate_reliability(
        champion_live_aggregate,
        candidate_live_aggregate,
        rejections=rejections,
    )
    stability = _evaluate_detection_stability(
        non_control_pairs,
        config=selected,
        rejections=rejections,
    )
    efficiency = _evaluate_efficiency(
        champion_live_aggregate,
        candidate_live_aggregate,
        max_regression=selected.max_efficiency_regression,
        rejections=rejections,
    )

    aggregate = {
        "all_receipts": {
            "champion": champion_aggregate,
            "candidate": candidate_aggregate,
            "delta": _aggregate_delta(champion_aggregate, candidate_aggregate),
        },
        "promotable_receipts": {
            "champion": champion_live_aggregate,
            "candidate": candidate_live_aggregate,
            "delta": _aggregate_delta(champion_live_aggregate, candidate_live_aggregate),
        },
        "efficiency": efficiency,
    }
    matching = {
        "champion_receipts": len(champion),
        "candidate_receipts": len(candidate),
        "matched_pairs": len(matched),
        "promotable_pairs": len(promotable_pairs),
        "historical_replay_pairs": len(historical_pairs),
        "control_pairs": len(control_pairs),
        "non_control_pairs": len(non_control_pairs),
        "cohorts": sorted({pair[0].cohort for pair in matched}),
        "execution_kinds": sorted({pair[0].execution_kind for pair in matched}),
    }
    ordered_rejections = tuple(
        sorted(
            _dedupe_rejections(rejections),
            key=lambda item: (item.gate, item.code, canonical_json(item.details)),
        )
    )
    return EvaluationReceipt(
        accepted=not ordered_rejections,
        config=selected,
        matching=matching,
        aggregate=aggregate,
        stability=stability,
        rejections=ordered_rejections,
    )


def write_evaluation_receipt(path: Path, receipt: EvaluationReceipt) -> None:
    """Atomically persist the byte-canonical receipt."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(receipt.canonical_json() + "\n", encoding="utf-8")
    temporary.replace(path)


def load_evaluation_receipt(path: Path) -> EvaluationReceipt:
    """Load a persisted receipt and fail closed on schema or digest drift."""
    payload = _load_json(path)
    if not isinstance(payload, Mapping):
        raise ValueError("evaluation receipt must be a JSON object")
    return EvaluationReceipt.from_mapping(payload)


def load_run_receipts(path: Path) -> tuple[RunReceipt, ...]:
    """Load a JSON receipt list without accepting implicit metric defaults."""
    payload = _load_json(path)
    if isinstance(payload, Mapping):
        payload = payload.get("receipts")
    if not isinstance(payload, list):
        raise ValueError("run receipt file must contain a list or a receipts list")
    receipts: list[RunReceipt] = []
    for index, item in enumerate(payload):
        if not isinstance(item, Mapping):
            raise ValueError(f"run receipt at index {index} must be an object")
        receipts.append(RunReceipt.from_mapping(item))
    if not receipts:
        raise ValueError("run receipt file contains no receipts")
    return tuple(receipts)


def run_receipts_digest(receipts: Sequence[RunReceipt]) -> str:
    """Digest the exact canonical receipt set, including execution attestations."""
    return f"sha256:{hashlib.sha256(canonical_run_receipts_bytes(receipts)).hexdigest()}"


def canonical_run_receipts_bytes(receipts: Sequence[RunReceipt]) -> bytes:
    """Serialize a strict receipt set for evaluator-only CAS retention."""
    if not receipts:
        raise ValueError("run receipt set cannot be empty")
    ordered = sorted(receipts, key=lambda item: (item.key, item.run_id))
    payload = {
        "schema_version": RUN_RECEIPT_SET_SCHEMA_VERSION,
        "receipts": [item.to_json() for item in ordered],
    }
    return canonical_json(payload).encode()


def load_canonical_run_receipts(content: bytes) -> tuple[RunReceipt, ...]:
    """Strictly load and byte-verify a retained evaluator receipt set."""
    if not isinstance(content, bytes) or not content or len(content) > _MAX_SUITE_BYTES * 4:
        raise ValueError("retained run receipt set is empty or exceeds the byte cap")
    try:
        payload = json.loads(content, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("retained run receipt set JSON is invalid") from exc
    if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "receipts"}:
        raise ValueError("retained run receipt set fields are invalid")
    schema_version = payload.get("schema_version")
    if schema_version not in {
        RUN_RECEIPT_SET_SCHEMA_VERSION,
        _LEGACY_RUN_RECEIPT_SET_SCHEMA_VERSION,
    }:
        raise ValueError("retained run receipt set schema is unsupported")
    raw_receipts = payload.get("receipts")
    if not isinstance(raw_receipts, list):
        raise ValueError("retained run receipts must be a list")
    receipts = tuple(
        RunReceipt.from_mapping(item) if isinstance(item, Mapping) else _raise_invalid_run_receipt()
        for item in raw_receipts
    )
    if not receipts:
        raise ValueError("retained run receipt set cannot be empty")
    if schema_version == _LEGACY_RUN_RECEIPT_SET_SCHEMA_VERSION:
        if any(item.execution_kind != _HISTORICAL_EXECUTION_KIND for item in receipts):
            raise ValueError("legacy promotable run receipts lack execution attestations")
        if any(item.execution_attestation_digest is not None for item in receipts):
            raise ValueError("legacy historical receipts cannot add v2 attestation fields")
        if content != _legacy_canonical_run_receipts_bytes(receipts):
            raise ValueError("retained legacy run receipt set is not byte-canonical")
        return receipts
    if content != canonical_run_receipts_bytes(receipts):
        raise ValueError("retained run receipt set is not byte-canonical")
    return receipts


def canonical_json(value: object) -> str:
    return json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _legacy_canonical_run_receipts_bytes(receipts: Sequence[RunReceipt]) -> bytes:
    ordered = sorted(receipts, key=lambda item: (item.key, item.run_id))
    legacy_receipts: list[dict[str, object]] = []
    for receipt in ordered:
        payload = receipt.to_json()
        payload["schema_version"] = _LEGACY_RUN_RECEIPT_SCHEMA_VERSION
        del payload["execution_attestation_digest"]
        legacy_receipts.append(payload)
    return canonical_json(
        {
            "schema_version": _LEGACY_RUN_RECEIPT_SET_SCHEMA_VERSION,
            "receipts": legacy_receipts,
        }
    ).encode()


def _parse_receipts(
    values: Sequence[Mapping[str, object] | RunReceipt],
    *,
    side: str,
    rejections: list[Rejection],
) -> list[RunReceipt]:
    parsed: list[RunReceipt] = []
    for index, value in enumerate(values):
        try:
            if isinstance(value, RunReceipt):
                parsed.append(value)
            elif isinstance(value, Mapping):
                parsed.append(RunReceipt.from_mapping(value))
            else:
                raise ValueError("receipt must be an object")
        except (TypeError, ValueError) as exc:
            _reject(
                rejections,
                gate="input_and_matching",
                code="invalid_run_receipt",
                message=f"{side} run receipt is invalid",
                details={"side": side, "index": index, "reason": str(exc)},
            )
    if not parsed:
        _reject(
            rejections,
            gate="input_and_matching",
            code="run_receipts_missing",
            message=f"{side} supplied no valid run receipts",
            details={"side": side},
        )
    return parsed


def _index_receipts(
    receipts: Sequence[RunReceipt],
    *,
    side: str,
    rejections: list[Rejection],
) -> dict[tuple[str, str, str, int], RunReceipt]:
    indexed: dict[tuple[str, str, str, int], RunReceipt] = {}
    for receipt in receipts:
        if receipt.key in indexed:
            _reject(
                rejections,
                gate="input_and_matching",
                code="duplicate_run_receipt",
                message=f"{side} contains a duplicate case/repeat receipt",
                details={"side": side, "key": _key_json(receipt.key)},
            )
            continue
        indexed[receipt.key] = receipt
    return indexed


def _validate_matched_metadata(
    pairs: Sequence[tuple[RunReceipt, RunReceipt]],
    *,
    rejections: list[Rejection],
) -> None:
    for champion, candidate in pairs:
        if champion.is_control != candidate.is_control:
            _reject(
                rejections,
                gate="input_and_matching",
                code="control_classification_mismatch",
                message="matched receipts disagree about control classification",
                details={"key": _key_json(champion.key)},
            )
        if champion.expected_vulnerability_count != candidate.expected_vulnerability_count:
            _reject(
                rejections,
                gate="input_and_matching",
                code="expected_vulnerability_count_mismatch",
                message="matched receipts use different evaluator-owned vulnerability totals",
                details={"key": _key_json(champion.key)},
            )


def _validate_suite_matrix(
    champion: Mapping[tuple[str, str, str, int], RunReceipt],
    candidate: Mapping[tuple[str, str, str, int], RunReceipt],
    *,
    suite: EvaluationSuite,
    config: EvaluationConfig,
    rejections: list[Rejection],
) -> None:
    expected_keys = suite.expected_keys
    champion_keys = frozenset(champion)
    candidate_keys = frozenset(candidate)
    if champion_keys != expected_keys or candidate_keys != expected_keys:
        _reject(
            rejections,
            gate="input_and_matching",
            code="evaluation_suite_matrix_mismatch",
            message="receipt sets do not match the campaign-pinned evaluation suite",
            details={
                "expected": len(expected_keys),
                "champion": len(champion_keys),
                "candidate": len(candidate_keys),
                "champion_missing": len(expected_keys - champion_keys),
                "champion_extra": len(champion_keys - expected_keys),
                "candidate_missing": len(expected_keys - candidate_keys),
                "candidate_extra": len(candidate_keys - expected_keys),
            },
        )
    deficient = [
        {"cohort": item.cohort, "case_id": item.case_id, "repeats": item.repeats}
        for item in suite.cases
        if item.repeats < config.min_repeats
    ]
    if deficient:
        _reject(
            rejections,
            gate="input_and_matching",
            code="evaluation_suite_repeat_policy_mismatch",
            message="the campaign suite does not satisfy its pinned repeat policy",
            details={"cases": deficient, "minimum": config.min_repeats},
        )
    metadata_mismatches: list[dict[str, object]] = []
    for suite_case in suite.cases:
        for key in suite_case.keys:
            for side, receipt in (
                ("champion", champion.get(key)),
                ("candidate", candidate.get(key)),
            ):
                if receipt is None:
                    continue
                expected_snapshot = suite_case.target_snapshot_digests[key[3] - 1]
                if (
                    receipt.is_control != suite_case.is_control
                    or receipt.expected_vulnerability_count
                    != suite_case.expected_vulnerability_count
                    or receipt.target_snapshot_digest != expected_snapshot
                    or receipt.model_fingerprint != suite.model_fingerprint
                ):
                    metadata_mismatches.append({"side": side, "key": _key_json(key)})
    if metadata_mismatches:
        _reject(
            rejections,
            gate="input_and_matching",
            code="evaluation_suite_metadata_mismatch",
            message="run metadata differs from the campaign-pinned evaluation suite",
            details={"receipts": metadata_mismatches},
        )


def _validate_execution_attestations(
    champion: Sequence[RunReceipt],
    candidate: Sequence[RunReceipt],
    pairs: Sequence[tuple[RunReceipt, RunReceipt]],
    *,
    rejections: list[Rejection],
) -> None:
    for side, receipts in (("champion", champion), ("candidate", candidate)):
        seen_runs: set[str] = set()
        seen_seeds: set[tuple[tuple[str, str, str], str]] = set()
        seen_attestations: set[str] = set()
        duplicate_runs: list[dict[str, object]] = []
        duplicate_seeds: list[dict[str, object]] = []
        duplicate_attestations: list[dict[str, object]] = []
        for receipt in receipts:
            if receipt.run_id in seen_runs:
                duplicate_runs.append({"key": _key_json(receipt.key)})
            seen_runs.add(receipt.run_id)
            seed_key = (receipt.group_key, receipt.pair_seed_digest)
            if seed_key in seen_seeds:
                duplicate_seeds.append({"key": _key_json(receipt.key)})
            seen_seeds.add(seed_key)
            attestation = receipt.execution_attestation_digest
            if attestation is not None:
                if attestation in seen_attestations:
                    duplicate_attestations.append({"key": _key_json(receipt.key)})
                seen_attestations.add(attestation)
        if duplicate_runs or duplicate_seeds or duplicate_attestations:
            _reject(
                rejections,
                gate="input_and_matching",
                code="duplicate_execution_attestation",
                message="repeat receipts must come from distinct attested executions and seeds",
                details={
                    "side": side,
                    "duplicate_runs": duplicate_runs,
                    "duplicate_pair_seeds": duplicate_seeds,
                    "duplicate_execution_envelopes": duplicate_attestations,
                },
            )

    mismatches: list[dict[str, object]] = []
    reused_sessions: list[dict[str, object]] = []
    for champion_item, candidate_item in pairs:
        if (
            champion_item.pair_seed_digest != candidate_item.pair_seed_digest
            or champion_item.target_snapshot_digest != candidate_item.target_snapshot_digest
            or champion_item.model_fingerprint != candidate_item.model_fingerprint
        ):
            mismatches.append({"key": _key_json(champion_item.key)})
        if (
            champion_item.run_id == candidate_item.run_id
            or (
                champion_item.execution_attestation_digest is not None
                and champion_item.execution_attestation_digest
                == candidate_item.execution_attestation_digest
            )
        ):
            reused_sessions.append({"key": _key_json(champion_item.key)})
    if mismatches:
        _reject(
            rejections,
            gate="input_and_matching",
            code="paired_execution_mismatch",
            message="matched runs must share seed, target snapshot, and model identity",
            details={"pairs": mismatches},
        )
    if reused_sessions:
        _reject(
            rejections,
            gate="input_and_matching",
            code="execution_session_reused",
            message="champion and candidate receipts must come from distinct execution sessions",
            details={"pairs": reused_sessions},
        )


def _validate_repetition_matrix(
    pairs: Sequence[tuple[RunReceipt, RunReceipt]],
    *,
    min_repeats: int,
    rejections: list[Rejection],
) -> None:
    groups: dict[tuple[str, str, str], set[int]] = {}
    for champion, _candidate in pairs:
        groups.setdefault(champion.group_key, set()).add(champion.repeat)
    deficient = [
        {
            "cohort": cohort,
            "case_id": case_id,
            "execution_kind": execution_kind,
            "repeats": len(repeats),
        }
        for (cohort, case_id, execution_kind), repeats in sorted(groups.items())
        if len(repeats) < min_repeats
    ]
    if deficient:
        _reject(
            rejections,
            gate="input_and_matching",
            code="insufficient_repeats",
            message="every promotable case and execution kind needs the configured repeat count",
            details={"minimum": min_repeats, "groups": deficient},
        )


def _evaluate_safety_and_accounting(
    champion: Sequence[RunReceipt],
    candidate: Sequence[RunReceipt],
    pairs: Sequence[tuple[RunReceipt, RunReceipt]],
    *,
    rejections: list[Rejection],
) -> None:
    for metric, code, message in _ZERO_TOLERANCE_METRICS:
        candidate_total = sum(int(getattr(item, metric)) for item in candidate)
        champion_total = sum(int(getattr(item, metric)) for item in champion)
        if candidate_total:
            _reject(
                rejections,
                gate="safety_and_accounting",
                code=code,
                message=message,
                details={
                    "candidate": candidate_total,
                    "champion": champion_total,
                    "regression": candidate_total > champion_total,
                },
            )

    accounting_regressions: list[dict[str, object]] = []
    for champion_item, candidate_item in pairs:
        changes: dict[str, object] = {}
        if candidate_item.unmetered_action_count > champion_item.unmetered_action_count:
            changes["unmetered_action_count"] = {
                "champion": champion_item.unmetered_action_count,
                "candidate": candidate_item.unmetered_action_count,
            }
        if candidate_item.incomplete_request_count > champion_item.incomplete_request_count:
            changes["incomplete_request_count"] = {
                "champion": champion_item.incomplete_request_count,
                "candidate": candidate_item.incomplete_request_count,
            }
        champion_rank = _ACCOUNTING_STATUS_RANK.get(
            champion_item.request_accounting_status,
            0,
        )
        candidate_rank = _ACCOUNTING_STATUS_RANK.get(
            candidate_item.request_accounting_status,
            0,
        )
        if candidate_rank < champion_rank:
            changes["request_accounting_status"] = {
                "champion": champion_item.request_accounting_status,
                "candidate": candidate_item.request_accounting_status,
            }
        if changes:
            accounting_regressions.append({"key": _key_json(champion_item.key), "changes": changes})
    if accounting_regressions:
        _reject(
            rejections,
            gate="safety_and_accounting",
            code="request_accounting_regression",
            message="candidate request accounting is weaker than its matched champion run",
            details={"pairs": accounting_regressions},
        )


def _evaluate_ground_truth_precision(
    pairs: Sequence[tuple[RunReceipt, RunReceipt]],
    *,
    rejections: list[Rejection],
) -> None:
    exceeds_ground_truth: list[dict[str, object]] = []
    clean_control_false_positives: list[dict[str, object]] = []
    invalid_champion_controls: list[dict[str, object]] = []
    for champion, candidate in pairs:
        expected = champion.expected_vulnerability_count
        for side, receipt in (("champion", champion), ("candidate", candidate)):
            finding_counts = {
                "evidence_backed": receipt.evidence_backed_vulnerability_count,
                "verified": receipt.verified_vulnerability_count,
                "confirmed": receipt.confirmed_finding_count,
            }
            if expected is not None and any(value > expected for value in finding_counts.values()):
                exceeds_ground_truth.append(
                    {
                        "key": _key_json(receipt.key),
                        "side": side,
                        "expected": expected,
                        "finding_counts": finding_counts,
                    }
                )
        if champion.is_control and expected == 0:
            champion_count = champion.evidence_backed_vulnerability_count
            candidate_count = candidate.evidence_backed_vulnerability_count
            if champion_count:
                invalid_champion_controls.append({"key": _key_json(champion.key)})
            if candidate_count:
                clean_control_false_positives.append({"key": _key_json(candidate.key)})
    if exceeds_ground_truth:
        _reject(
            rejections,
            gate="input_and_matching",
            code="finding_count_exceeds_ground_truth",
            message="a finding-stage count exceeds evaluator-owned ground truth",
            details={"receipts": exceeds_ground_truth},
        )
    if invalid_champion_controls:
        _reject(
            rejections,
            gate="controls",
            code="champion_clean_control_invalid",
            message="champion reported evidence-backed findings on a known-clean control",
            details={"pairs": invalid_champion_controls},
        )
    if clean_control_false_positives:
        _reject(
            rejections,
            gate="controls",
            code="clean_control_false_positive",
            message="candidate reported evidence-backed findings on a known-clean control",
            details={"pairs": clean_control_false_positives},
        )


def _evaluate_controls(
    pairs: Sequence[tuple[RunReceipt, RunReceipt]],
    *,
    rejections: list[Rejection],
) -> None:
    detection_losses: list[dict[str, object]] = []
    suspected_regressions: list[dict[str, object]] = []
    missing_outcomes: list[dict[str, object]] = []
    for champion, candidate in pairs:
        if champion.case_success is None or candidate.case_success is None:
            missing_outcomes.append({"key": _key_json(champion.key)})
        comparison = _compare_detection(champion, candidate)
        if comparison == "loss" or (
            champion.case_success is True and candidate.case_success is not True
        ):
            detection_losses.append({"key": _key_json(champion.key)})
        if candidate.suspected_vulnerability_count > champion.suspected_vulnerability_count:
            suspected_regressions.append(
                {
                    "key": _key_json(champion.key),
                    "champion": champion.suspected_vulnerability_count,
                    "candidate": candidate.suspected_vulnerability_count,
                }
            )
    if missing_outcomes:
        _reject(
            rejections,
            gate="controls",
            code="control_outcome_missing",
            message="control receipts require an explicit case_success outcome",
            details={"pairs": missing_outcomes},
        )
    if detection_losses:
        _reject(
            rejections,
            gate="controls",
            code="control_regression",
            message="candidate regressed at least one matched control observation",
            details={"pairs": detection_losses},
        )
    if suspected_regressions:
        _reject(
            rejections,
            gate="controls",
            code="control_suspected_signal_regression",
            message="candidate increased unverified suspected findings on controls",
            details={"pairs": suspected_regressions},
        )


def _evaluate_reliability(
    champion: Mapping[str, object],
    candidate: Mapping[str, object],
    *,
    rejections: list[Rejection],
) -> None:
    candidate_timeouts = _aggregate_count(candidate, "timeouts")
    candidate_errors = _aggregate_count(candidate, "errors")
    if candidate_timeouts:
        _reject(
            rejections,
            gate="reliability",
            code="candidate_timeout",
            message="candidate produced timed-out promotable runs",
            details={"count": candidate_timeouts},
        )
    if candidate_errors:
        _reject(
            rejections,
            gate="reliability",
            code="candidate_error",
            message="candidate produced errored promotable runs",
            details={"count": candidate_errors},
        )
    candidate_failed = _aggregate_count(candidate, "failed_runs")
    champion_failed = _aggregate_count(champion, "failed_runs")
    if candidate_failed > champion_failed:
        _reject(
            rejections,
            gate="reliability",
            code="failed_run_regression",
            message="candidate increased terminal failed runs",
            details={
                "champion": champion["failed_runs"],
                "candidate": candidate["failed_runs"],
            },
        )


def _evaluate_detection_stability(
    pairs: Sequence[tuple[RunReceipt, RunReceipt]],
    *,
    config: EvaluationConfig,
    rejections: list[Rejection],
) -> dict[str, object]:
    groups: dict[tuple[str, str, str], list[tuple[RunReceipt, RunReceipt]]] = {}
    for pair in pairs:
        groups.setdefault(pair[0].group_key, []).append(pair)

    per_case: list[dict[str, object]] = []
    total_wins = 0
    total_ties = 0
    total_losses = 0
    stable_improvements = 0
    persistent_regressions: list[dict[str, object]] = []
    case_outcome_regressions = [
        {"key": _key_json(champion.key)}
        for champion, candidate in pairs
        if champion.case_success is True and candidate.case_success is not True
    ]
    for (cohort, case_id, execution_kind), group_pairs in sorted(groups.items()):
        outcomes = [_compare_detection(champion, candidate) for champion, candidate in group_pairs]
        wins = outcomes.count("win")
        ties = outcomes.count("tie")
        losses = outcomes.count("loss")
        repeats = len(outcomes)
        win_rate = wins / repeats if repeats else 0.0
        lower_bound = _wilson_lower_bound(wins, repeats, z=config.confidence_z)
        stable = (
            repeats >= config.min_repeats
            and win_rate >= config.min_case_win_rate
            and wins > losses
            and lower_bound >= config.min_win_rate_lower_bound
        )
        persistent_regression = bool(repeats and losses / repeats >= config.min_case_win_rate)
        stable_improvements += int(stable)
        total_wins += wins
        total_ties += ties
        total_losses += losses
        case_payload = {
            "cohort": cohort,
            "case_id": case_id,
            "execution_kind": execution_kind,
            "repeats": repeats,
            "wins": wins,
            "ties": ties,
            "losses": losses,
            "win_rate": _rounded(win_rate),
            "win_rate_lower_bound": _rounded(lower_bound),
            "stable_improvement": stable,
            "persistent_regression": persistent_regression,
        }
        per_case.append(case_payload)
        if persistent_regression:
            persistent_regressions.append(case_payload)

    decisive = total_wins + total_losses
    decisive_win_rate = total_wins / decisive if decisive else 0.0
    decisive_lower_bound = _wilson_lower_bound(
        total_wins,
        decisive,
        z=config.confidence_z,
    )
    if pairs and stable_improvements == 0:
        _reject(
            rejections,
            gate="detection_stability",
            code="no_stable_detection_improvement",
            message="candidate did not improve a case repeatably enough for promotion",
            details={
                "minimum_case_win_rate": config.min_case_win_rate,
                "minimum_lower_bound": config.min_win_rate_lower_bound,
            },
        )
    if decisive and (
        decisive_win_rate < config.min_global_decisive_win_rate
        or decisive_lower_bound < config.min_win_rate_lower_bound
    ):
        _reject(
            rejections,
            gate="detection_stability",
            code="global_win_rate_unstable",
            message="candidate improvement is not stable across decisive matched runs",
            details={
                "wins": total_wins,
                "losses": total_losses,
                "win_rate": _rounded(decisive_win_rate),
                "lower_bound": _rounded(decisive_lower_bound),
            },
        )
    if persistent_regressions:
        _reject(
            rejections,
            gate="detection_stability",
            code="persistent_detection_regression",
            message="candidate persistently regressed a non-control capability case",
            details={"cases": persistent_regressions},
        )
    if case_outcome_regressions:
        _reject(
            rejections,
            gate="detection_stability",
            code="case_outcome_regression",
            message=(
                "candidate lost a matched case outcome; case success is a non-regression "
                "signal, never promotion utility"
            ),
            details={"pairs": case_outcome_regressions},
        )

    champion_totals = _detection_totals([pair[0] for pair in pairs])
    candidate_totals = _detection_totals([pair[1] for pair in pairs])
    deltas = {key: candidate_totals[key] - champion_totals[key] for key in champion_totals}
    if any(value < 0 for value in deltas.values()):
        _reject(
            rejections,
            gate="detection_stability",
            code="aggregate_detection_regression",
            message="candidate traded away an evidence-backed detection metric",
            details={"delta": deltas},
        )
    if pairs and not any(value > 0 for value in deltas.values()):
        _reject(
            rejections,
            gate="detection_stability",
            code="aggregate_detection_did_not_improve",
            message="candidate did not improve evidence-backed detection totals",
            details={"delta": deltas},
        )

    return {
        "wins": total_wins,
        "ties": total_ties,
        "losses": total_losses,
        "decisive_pairs": decisive,
        "decisive_win_rate": _rounded(decisive_win_rate),
        "decisive_win_rate_lower_bound": _rounded(decisive_lower_bound),
        "stable_improved_cases": stable_improvements,
        "detection_delta": deltas,
        "per_case": per_case,
    }


def _evaluate_efficiency(
    champion: Mapping[str, object],
    candidate: Mapping[str, object],
    *,
    max_regression: float,
    rejections: list[Rejection],
) -> dict[str, object]:
    champion_units = _utility_units(champion)
    candidate_units = _utility_units(candidate)
    result: dict[str, object] = {
        "utility_units": {
            "champion": champion_units,
            "candidate": candidate_units,
        },
        "maximum_regression": max_regression,
        "metrics": {},
    }
    metric_output = result["metrics"]
    assert isinstance(metric_output, dict)
    for field_name, code, label in (
        ("physical_request_count", "physical_request_efficiency_regression", "physical requests"),
        ("model_request_count", "model_request_efficiency_regression", "model requests"),
        ("cost_usd", "cost_efficiency_regression", "cost"),
    ):
        champion_value = champion.get(field_name)
        candidate_value = candidate.get(field_name)
        if not isinstance(champion_value, int | float) or not isinstance(
            candidate_value,
            int | float,
        ):
            metric_output[field_name] = {
                "status": "unknown",
                "champion": champion_value,
                "candidate": candidate_value,
            }
            _reject(
                rejections,
                gate="efficiency",
                code="efficiency_metric_missing",
                message="promotion requires complete cost and request metrics",
                details={"metric": field_name},
            )
            continue
        champion_per_unit = float(champion_value) / champion_units
        candidate_per_unit = float(candidate_value) / candidate_units
        threshold = champion_per_unit * (1 + max_regression)
        regressed = (
            candidate_per_unit > 0 if champion_per_unit == 0 else candidate_per_unit > threshold
        )
        metric_output[field_name] = {
            "status": "regressed" if regressed else "passed",
            "champion_total": _rounded(float(champion_value)),
            "candidate_total": _rounded(float(candidate_value)),
            "champion_per_utility": _rounded(champion_per_unit),
            "candidate_per_utility": _rounded(candidate_per_unit),
            "maximum_candidate_per_utility": _rounded(threshold),
        }
        if regressed:
            _reject(
                rejections,
                gate="efficiency",
                code=code,
                message=f"candidate {label} per evidence-backed result exceeded the bound",
                details={
                    "champion_per_utility": _rounded(champion_per_unit),
                    "candidate_per_utility": _rounded(candidate_per_unit),
                    "maximum_regression": max_regression,
                },
            )
    return result


def _aggregate(receipts: Sequence[RunReceipt]) -> dict[str, object]:
    expected_known = all(item.expected_vulnerability_count is not None for item in receipts)
    expected = (
        sum(int(item.expected_vulnerability_count or 0) for item in receipts)
        if expected_known
        else None
    )
    evidence_count = sum(item.evidence_backed_vulnerability_count for item in receipts)
    recall = (
        min(evidence_count, expected) / expected
        if isinstance(expected, int) and expected > 0
        else None
    )
    physical_complete = all(item.physical_request_count is not None for item in receipts)
    model_complete = all(item.model_request_count is not None for item in receipts)
    cost_complete = all(item.cost_usd is not None for item in receipts)
    success_known = [item.case_success for item in receipts if item.case_success is not None]
    return {
        "receipts": len(receipts),
        "live_receipts": sum(item.execution_kind == "live" for item in receipts),
        "fixture_receipts": sum(item.execution_kind == "fixture" for item in receipts),
        "historical_replay_receipts": sum(
            item.execution_kind == _HISTORICAL_EXECUTION_KIND for item in receipts
        ),
        "control_receipts": sum(item.is_control for item in receipts),
        "case_successes": sum(value is True for value in success_known),
        "case_success_outcomes_known": len(success_known),
        "expected_vulnerability_count": expected,
        "evidence_backed_vulnerability_count": evidence_count,
        "evidence_backed_vulnerability_recall": _optional_rounded(recall),
        "verified_vulnerability_count": sum(item.verified_vulnerability_count for item in receipts),
        "confirmed_finding_count": sum(item.confirmed_finding_count for item in receipts),
        "suspected_vulnerability_count": sum(
            item.suspected_vulnerability_count for item in receipts
        ),
        "proof_integrity_failure_count": sum(
            item.proof_integrity_failure_count for item in receipts
        ),
        "false_proof_count": sum(item.false_proof_count for item in receipts),
        "request_accounting_mismatch_count": sum(
            item.request_accounting_mismatch_count for item in receipts
        ),
        "loop_violation_count": sum(item.loop_violation_count for item in receipts),
        "provenance_violation_count": sum(item.provenance_violation_count for item in receipts),
        "secret_leak_violation_count": sum(item.secret_leak_violation_count for item in receipts),
        "unmetered_action_count": sum(item.unmetered_action_count for item in receipts),
        "incomplete_request_count": sum(item.incomplete_request_count for item in receipts),
        "timeouts": sum(item.timed_out for item in receipts),
        "errors": sum(item.errored for item in receipts),
        "failed_runs": sum(item.failed for item in receipts),
        "physical_request_count": (
            sum(int(item.physical_request_count or 0) for item in receipts)
            if physical_complete
            else None
        ),
        "model_request_count": (
            sum(int(item.model_request_count or 0) for item in receipts) if model_complete else None
        ),
        "cost_usd": (
            _rounded(sum(float(item.cost_usd or 0.0) for item in receipts))
            if cost_complete
            else None
        ),
    }


def _aggregate_delta(
    champion: Mapping[str, object],
    candidate: Mapping[str, object],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name in (
        "case_successes",
        "evidence_backed_vulnerability_count",
        "evidence_backed_vulnerability_recall",
        "verified_vulnerability_count",
        "confirmed_finding_count",
        "suspected_vulnerability_count",
        "proof_integrity_failure_count",
        "false_proof_count",
        "request_accounting_mismatch_count",
        "loop_violation_count",
        "provenance_violation_count",
        "secret_leak_violation_count",
        "unmetered_action_count",
        "incomplete_request_count",
        "timeouts",
        "errors",
        "failed_runs",
        "physical_request_count",
        "model_request_count",
        "cost_usd",
    ):
        champion_value = champion.get(name)
        candidate_value = candidate.get(name)
        result[name] = (
            _rounded(float(candidate_value) - float(champion_value))
            if isinstance(champion_value, int | float) and isinstance(candidate_value, int | float)
            else None
        )
    return result


def _detection_totals(receipts: Sequence[RunReceipt]) -> dict[str, int]:
    return {
        "evidence_backed_vulnerability_count": sum(
            item.evidence_backed_vulnerability_count for item in receipts
        ),
        "verified_vulnerability_count": sum(item.verified_vulnerability_count for item in receipts),
        "confirmed_finding_count": sum(item.confirmed_finding_count for item in receipts),
    }


def _compare_detection(champion: RunReceipt, candidate: RunReceipt) -> str:
    deltas: list[float] = []
    if (
        champion.expected_vulnerability_count is not None
        and champion.expected_vulnerability_count > 0
        and champion.expected_vulnerability_count == candidate.expected_vulnerability_count
    ):
        denominator = champion.expected_vulnerability_count
        deltas.append(
            min(candidate.evidence_backed_vulnerability_count, denominator) / denominator
            - min(champion.evidence_backed_vulnerability_count, denominator) / denominator
        )
    deltas.extend(
        (
            float(
                candidate.evidence_backed_vulnerability_count
                - champion.evidence_backed_vulnerability_count
            ),
            float(candidate.verified_vulnerability_count - champion.verified_vulnerability_count),
            float(candidate.confirmed_finding_count - champion.confirmed_finding_count),
        )
    )
    if any(value < 0 for value in deltas):
        return "loss"
    if any(value > 0 for value in deltas):
        return "win"
    return "tie"


def _utility_units(aggregate: Mapping[str, object]) -> int:
    values = (
        _aggregate_count(aggregate, "evidence_backed_vulnerability_count"),
        _aggregate_count(aggregate, "verified_vulnerability_count"),
        _aggregate_count(aggregate, "confirmed_finding_count"),
    )
    return max(*values, 1)


def _aggregate_count(aggregate: Mapping[str, object], name: str) -> int:
    value = aggregate.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"internal aggregate {name} must be an integer")
    return value


def _wilson_lower_bound(successes: int, observations: int, *, z: float) -> float:
    if observations <= 0:
        return 0.0
    rate = successes / observations
    z_squared = z * z
    denominator = 1 + z_squared / observations
    centre = rate + z_squared / (2 * observations)
    margin = z * math.sqrt((rate * (1 - rate) + z_squared / (4 * observations)) / observations)
    return max(0.0, (centre - margin) / denominator)


def _gate_results(rejections: Sequence[Rejection]) -> list[dict[str, object]]:
    by_gate: dict[str, list[str]] = {gate: [] for gate in _GATES}
    for rejection in rejections:
        by_gate.setdefault(rejection.gate, []).append(rejection.code)
    return [
        {
            "gate": gate,
            "passed": not by_gate[gate],
            "rejection_codes": sorted(set(by_gate[gate])),
        }
        for gate in _GATES
    ]


def _dedupe_rejections(rejections: Sequence[Rejection]) -> list[Rejection]:
    deduped: dict[tuple[str, str, str, str], Rejection] = {}
    for rejection in rejections:
        identity = (
            rejection.gate,
            rejection.code,
            rejection.message,
            canonical_json(rejection.details),
        )
        deduped[identity] = rejection
    return list(deduped.values())


def _reject(
    rejections: list[Rejection],
    *,
    gate: str,
    code: str,
    message: str,
    details: Mapping[str, object] | None = None,
) -> None:
    rejections.append(
        Rejection(
            gate=gate,
            code=code,
            message=message,
            details=dict(details or {}),
        )
    )


def _key_json(key: tuple[str, str, str, int]) -> dict[str, object]:
    cohort, case_id, execution_kind, repeat = key
    return {
        "cohort": cohort,
        "case_id": case_id,
        "execution_kind": execution_kind,
        "repeat": repeat,
    }


def _lookup(
    payload: Mapping[str, object],
    metrics: Mapping[object, object],
    *names: str,
    default: object = _MISSING,
) -> object:
    for name in names:
        if name in metrics:
            return metrics[name]
        if name in payload:
            return payload[name]
    if default is not _MISSING:
        return default
    raise ValueError(f"missing required field: {names[0]}")


def _required_count(
    payload: Mapping[str, object],
    metrics: Mapping[object, object],
    *names: str,
) -> int:
    return _non_negative_int(
        _lookup(payload, metrics, *names),
        names[0],
    )


def _required_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    return text


def _opaque_id(value: object, label: str) -> str:
    text = _required_text(value, label)
    if _OPAQUE_ID_RE.fullmatch(text) is None:
        raise ValueError(f"{label} must be a bounded opaque identifier")
    return text


def _required_sha256(value: object, label: str) -> str:
    digest = _required_text(value, label).lower()
    if _SHA256_RE.fullmatch(digest) is None:
        raise ValueError(f"{label} must be a sha256 digest")
    return digest


def _optional_sha256(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _required_sha256(value, label)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _non_negative_int(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer") from exc
    if parsed < minimum:
        raise ValueError(f"{label} must be at least {minimum}")
    return parsed


def _optional_non_negative_int(value: object, label: str) -> int | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return _non_negative_int(value, label)


def _optional_non_negative_float(value: object, label: str) -> float | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        raise ValueError(f"{label} must be numeric")
    if not isinstance(value, str | int | float):
        raise ValueError(f"{label} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return parsed


def _finite_float(value: object, label: str) -> float:
    parsed = _optional_non_negative_float(value, label)
    if parsed is None:
        raise ValueError(f"{label} must be numeric")
    return parsed


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{label} must be a list")
    result = tuple(_required_text(item, label) for item in value)
    if len(result) != len(set(result)):
        raise ValueError(f"{label} cannot contain duplicates")
    return result


def _execution_kind(value: str) -> str:
    normalized = value.strip().casefold().replace("-", "_")
    aliases = {
        "controlled_fixture": "fixture",
        "historical": _HISTORICAL_EXECUTION_KIND,
        "offline_replay": _HISTORICAL_EXECUTION_KIND,
        "replay": _HISTORICAL_EXECUTION_KIND,
        "live_run": "live",
    }
    selected = aliases.get(normalized, normalized)
    if selected not in {"fixture", "live", _HISTORICAL_EXECUTION_KIND}:
        raise ValueError("execution_kind must be live, fixture, or historical_replay")
    return selected


def _status(value: str) -> str:
    normalized = value.strip().casefold().replace("-", "_")
    aliases = {
        "completed": "completed",
        "passed": "completed",
        "solved": "completed",
        "timed_out": "timeout",
        "timeout": "timeout",
        "errored": "error",
        "error": "error",
        "failed": "failed",
    }
    selected = aliases.get(normalized)
    if selected is None:
        raise ValueError("status must be completed, failed, timeout, or error")
    return selected


def _accounting_status(value: str) -> str:
    normalized = value.strip().casefold().replace("-", "_")
    if normalized not in _ACCOUNTING_STATUS_RANK:
        raise ValueError("request_accounting_status is not recognized")
    return normalized


def _load_json(path: Path) -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read JSON receipt: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON receipt: {exc}") from exc


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("JSON contains duplicate object keys")
        output[key] = value
    return output


def _raise_invalid_suite_case() -> EvaluationSuiteCase:
    raise ValueError("evaluation suite case must be an object")


def _raise_invalid_run_receipt() -> RunReceipt:
    raise ValueError("retained run receipt must be an object")


def _rounded(value: float) -> float:
    return round(value, 9)


def _optional_rounded(value: float | None) -> float | None:
    return None if value is None else _rounded(value)


def _canonical_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple | list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, set | frozenset):
        return [_canonical_value(item) for item in sorted(value, key=str)]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical JSON cannot encode non-finite numbers")
    return value


def _digest_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


__all__ = [
    "EVALUATION_SCHEMA_VERSION",
    "EVALUATION_SUITE_SCHEMA_VERSION",
    "RUN_RECEIPT_SCHEMA_VERSION",
    "RUN_RECEIPT_SET_SCHEMA_VERSION",
    "EvaluationConfig",
    "EvaluationReceipt",
    "EvaluationSuite",
    "EvaluationSuiteCase",
    "Rejection",
    "RunReceipt",
    "canonical_json",
    "canonical_run_receipts_bytes",
    "evaluate_candidate",
    "evaluation_suite_from_receipts",
    "load_canonical_run_receipts",
    "load_evaluation_receipt",
    "load_run_receipts",
    "run_receipts_digest",
    "write_evaluation_receipt",
]
