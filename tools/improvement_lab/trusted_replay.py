"""
Trusted, offline replay of checksum-covered Ravage run artifacts.

This module is evaluator-side code.  It may read raw prior-run artifacts, but it
returns only opaque identifiers and aggregate structural metrics.  Historical
replay is deliberately never sufficient to promote a candidate: it validates
how recorded observations are processed, not counterfactual discovery.
"""

# Replay errors describe deliberate trust-boundary failures.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ravage.agent_core.autonomous_graph.replay import (
    GraphReplayError,
    ReplayReport,
    replay_case_artifacts,
    verify_checksum_manifest,
)

_SCHEMA_VERSION = 1
_MIN_HMAC_KEY_BYTES = 32
_MAX_CATEGORY_CHARS = 80


class TrustedReplayError(RuntimeError):
    """Raised when a prior run cannot be replayed without crossing trust bounds."""


class _ReplayFunction(Protocol):
    def __call__(
        self,
        *,
        run_root: Path,
        case_id: str,
        blackboard_path: Path,
    ) -> ReplayReport: ...


@dataclass(frozen=True)
class HistoricalCaseReplay:
    """Secret-free summary for one historical case."""

    case_id: str
    status: str
    error_code: str
    observations: int
    trusted_observations: int
    unique_raw_records: int
    duplicate_raw_records: int
    material_records: int
    proof_records: int
    source_counts: dict[str, int]
    progress_counts: dict[str, int]

    def to_json(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "status": self.status,
            "error_code": self.error_code,
            "observations": self.observations,
            "trusted_observations": self.trusted_observations,
            "unique_raw_records": self.unique_raw_records,
            "duplicate_raw_records": self.duplicate_raw_records,
            "material_records": self.material_records,
            "proof_records": self.proof_records,
            "source_counts": dict(sorted(self.source_counts.items())),
            "progress_counts": dict(sorted(self.progress_counts.items())),
        }


@dataclass(frozen=True)
class HistoricalReplayReceipt:
    """Aggregate replay receipt that cannot authorize promotion."""

    run_id: str
    cases: tuple[HistoricalCaseReplay, ...]
    receipt_digest: str

    def to_json(self) -> dict[str, object]:
        case_payloads = [case.to_json() for case in self.cases]
        totals: Counter[str] = Counter()
        for case in self.cases:
            totals["completed_cases"] += int(case.status == "completed")
            totals["errored_cases"] += int(case.status != "completed")
            totals["observations"] += case.observations
            totals["trusted_observations"] += case.trusted_observations
            totals["unique_raw_records"] += case.unique_raw_records
            totals["duplicate_raw_records"] += case.duplicate_raw_records
            totals["material_records"] += case.material_records
            totals["proof_records"] += case.proof_records
        return {
            "schema_version": _SCHEMA_VERSION,
            "execution_kind": "historical_replay",
            "promotable": False,
            "promotion_block_reason": "historical_replay_is_not_counterfactual_discovery",
            "run_id": self.run_id,
            "cases": case_payloads,
            "totals": dict(sorted(totals.items())),
            "receipt_digest": self.receipt_digest,
        }


def replay_previous_run(
    run_root: Path,
    *,
    hmac_key: bytes,
    scratch_root: Path | None = None,
    replay: _ReplayFunction = replay_case_artifacts,
) -> HistoricalReplayReceipt:
    """
    Replay each checksum-covered case and return a secret-free receipt.

    Raw observations and the temporary evidence blackboard remain inside an
    owner-only scratch directory.  Error messages are converted to categorical
    codes because exception text may contain case names or artifact paths.
    """
    _validate_hmac_key(hmac_key)
    root = _safe_directory(run_root, label="run root")
    manifest = root / "artifacts.sha256"
    try:
        checksum = verify_checksum_manifest(manifest)
    except GraphReplayError as exc:
        raise TrustedReplayError("historical run failed checksum verification") from exc

    case_dirs = _discover_case_dirs(root)
    if not case_dirs:
        raise TrustedReplayError("historical run contains no replayable case directories")

    scratch_parent = None
    if scratch_root is not None:
        scratch_parent = _safe_directory(scratch_root, label="scratch root")
    summaries: list[HistoricalCaseReplay] = []
    with tempfile.TemporaryDirectory(prefix="ravage-replay-", dir=scratch_parent) as temporary:
        temporary_root = Path(temporary)
        temporary_root.chmod(0o700)
        for index, case_dir in enumerate(case_dirs):
            opaque_case_id = _opaque_id(hmac_key, "case", case_dir.name)
            try:
                report = replay(
                    run_root=root,
                    case_id=case_dir.name,
                    blackboard_path=temporary_root / f"case-{index}.json",
                )
            except Exception as exc:  # noqa: BLE001 - receipt records a sealed category only.
                summaries.append(_failed_case(opaque_case_id, exc))
                continue
            summaries.append(
                HistoricalCaseReplay(
                    case_id=opaque_case_id,
                    status="completed",
                    error_code="",
                    observations=_non_negative(report.observations),
                    trusted_observations=_non_negative(report.trusted_observations),
                    unique_raw_records=_non_negative(report.unique_raw_records),
                    duplicate_raw_records=_non_negative(report.duplicate_raw_records),
                    material_records=_non_negative(report.material_records),
                    proof_records=_non_negative(report.proof_records),
                    source_counts=_safe_counter(report.source_counts),
                    progress_counts=_safe_counter(report.progress_counts),
                )
            )

    run_id = _opaque_id(hmac_key, "run", checksum.manifest_sha256)
    body = {
        "schema_version": _SCHEMA_VERSION,
        "execution_kind": "historical_replay",
        "promotable": False,
        "run_id": run_id,
        "cases": [case.to_json() for case in summaries],
    }
    return HistoricalReplayReceipt(
        run_id=run_id,
        cases=tuple(summaries),
        receipt_digest=f"sha256:{_digest_json(body)}",
    )


def _discover_case_dirs(root: Path) -> tuple[Path, ...]:
    cases: list[Path] = []
    for child in sorted(root.iterdir(), key=lambda path: path.name):
        if child.is_symlink() or not child.is_dir():
            continue
        workspace = child / "workspace"
        if (workspace / "working_state.json").is_file() and (workspace / "events.jsonl").is_file():
            cases.append(child)
    return tuple(cases)


def _failed_case(case_id: str, exc: Exception) -> HistoricalCaseReplay:
    if isinstance(exc, GraphReplayError):
        error_code = "invalid_or_incomplete_replay_artifact"
    elif isinstance(exc, (OSError, ValueError, TypeError)):
        error_code = "unreadable_replay_artifact"
    else:
        error_code = "evaluator_internal_error"
    return HistoricalCaseReplay(
        case_id=case_id,
        status="errored",
        error_code=error_code,
        observations=0,
        trusted_observations=0,
        unique_raw_records=0,
        duplicate_raw_records=0,
        material_records=0,
        proof_records=0,
        source_counts={},
        progress_counts={},
    )


def _safe_directory(path: Path, *, label: str) -> Path:
    candidate = path.expanduser()
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            raise TrustedReplayError(f"{label} must be a real directory")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise TrustedReplayError(f"cannot inspect {label}") from exc
    return resolved


def _validate_hmac_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < _MIN_HMAC_KEY_BYTES:
        raise TrustedReplayError("replay HMAC key must contain at least 32 bytes")


def _opaque_id(key: bytes, domain: str, value: str) -> str:
    digest = hmac.new(key, f"{domain}\0{value}".encode(), hashlib.sha256).hexdigest()
    return f"{domain}_{digest[:24]}"


def _safe_counter(value: dict[str, int]) -> dict[str, int]:
    output: dict[str, int] = {}
    for raw_key, raw_count in value.items():
        key = str(raw_key)
        if (
            not key
            or len(key) > _MAX_CATEGORY_CHARS
            or not all(char.isalnum() or char in "_-" for char in key)
        ):
            key = "other"
        output[key] = output.get(key, 0) + _non_negative(raw_count)
    return output


def _non_negative(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TrustedReplayError("replay report contains an invalid counter")
    return value


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "HistoricalCaseReplay",
    "HistoricalReplayReceipt",
    "TrustedReplayError",
    "replay_previous_run",
]
