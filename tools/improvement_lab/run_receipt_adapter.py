"""
Derive promotion receipts from externally attested Ravage executions.

Candidate output is evidence nomination, never the source of truth.  This
adapter counts only finding verdicts and resource observations signed by the
trusted executor, then cross-checks the candidate report and traffic ledger for
inconsistencies.  The resulting :class:`RunReceipt` contains no target paths,
URLs, finding identities, response bodies, or proof values.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from tools.improvement_lab.evaluation import (
    RunReceipt,
    canonical_run_receipts_bytes,
)
from tools.improvement_lab.execution_attestation import (
    ExecutionAttestationError,
    verify_signed_execution_envelope,
)
from tools.improvement_lab.offline_executor import freeze_output_tree

# These errors are safe trust-boundary diagnostics and deliberately omit paths
# and candidate-controlled values.
# ruff: noqa: C901, EM101, EM102, PLR0913, PLR2004, TRY003, TRY301

if TYPE_CHECKING:
    from pathlib import Path

    from tools.improvement_lab.execution_attestation import SignedExecutionEnvelope

_MAX_JSON_BYTES: Final = 16 * 1024 * 1024
_MAX_FINDINGS: Final = 10_000
_MAX_FINDING_ID_CHARS: Final = 512
_STAGE_RANK: Final = {
    "suspected_vulnerability": 1,
    "evidence_backed_vulnerability": 2,
    "verified_vulnerability": 3,
    "confirmed_finding": 4,
}


class RunReceiptAdapterError(RuntimeError):
    """Raised when a run cannot produce a trustworthy bounded receipt."""


def finding_reference_digest(finding_id: str) -> str:
    """Return the opaque identifier shared by reports and evaluator verdicts."""
    if (
        not isinstance(finding_id, str)
        or not finding_id.strip()
        or len(finding_id) > _MAX_FINDING_ID_CHARS
        or "\0" in finding_id
    ):
        raise RunReceiptAdapterError("report contains an invalid finding identity")
    encoded = f"ravage.finding-reference.v1\0{finding_id.strip()}".encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def derive_run_receipt(
    artifact_root: Path,
    *,
    envelope: SignedExecutionEnvelope,
    executor_public_key: bytes,
) -> RunReceipt:
    """Build one fail-closed receipt from a signed execution and frozen output."""
    try:
        envelope = verify_signed_execution_envelope(
            envelope.to_json(),
            public_key=executor_public_key,
        )
    except ExecutionAttestationError as exc:
        raise RunReceiptAdapterError("signed execution envelope is invalid") from exc
    frozen = freeze_output_tree(artifact_root)
    binding = envelope.binding
    observations = envelope.observations
    if frozen.digest != binding.artifact_tree_digest:
        raise RunReceiptAdapterError("artifact tree differs from the signed execution")

    case_root = _contained_case_root(artifact_root, binding.artifact_case_path)
    report = _load_json_object(case_root / "report.json", label="Ravage report")
    traffic = _load_json_object(
        case_root / "workspace" / "traffic-policy.json",
        label="traffic ledger",
    )
    nominations, confirmed_claims = _report_finding_references(report)
    verdicts = envelope.finding_verdicts
    verdict_references = {item.finding_digest for item in verdicts}
    unknown = verdict_references - nominations
    if unknown:
        raise RunReceiptAdapterError(
            "signed finding verdict does not match a nominated report finding"
        )

    ranks = [_STAGE_RANK[item.stage] for item in verdicts]
    evidence_backed = sum(
        rank >= _STAGE_RANK["evidence_backed_vulnerability"] for rank in ranks
    )
    verified = sum(rank >= _STAGE_RANK["verified_vulnerability"] for rank in ranks)
    confirmed = sum(rank >= _STAGE_RANK["confirmed_finding"] for rank in ranks)
    suspected = sum(rank == _STAGE_RANK["suspected_vulnerability"] for rank in ranks)

    unsupported_confirmed = confirmed_claims - verdict_references
    accounting_mismatches = _accounting_mismatches(
        report,
        traffic,
        physical_request_count=observations.physical_request_count,
        incomplete_request_count=observations.incomplete_request_count,
        unmetered_action_count=observations.unmetered_action_count,
        accounting_status=observations.request_accounting_status,
    )
    if (
        observations.physical_request_count is None
        or observations.request_accounting_status in {"unavailable", "unspecified", "invalid"}
    ):
        accounting_mismatches.add("external_accounting_unavailable")

    receipt = RunReceipt(
        case_id=binding.case_id,
        cohort=binding.cohort,
        repeat=binding.repeat,
        execution_kind=binding.execution_kind,
        status=observations.status,
        is_control=binding.is_control,
        case_success=observations.case_success,
        expected_vulnerability_count=binding.expected_vulnerability_count,
        evidence_backed_vulnerability_count=evidence_backed,
        verified_vulnerability_count=verified,
        confirmed_finding_count=confirmed,
        suspected_vulnerability_count=suspected,
        proof_integrity_failure_count=(
            observations.proof_integrity_failure_count + len(unsupported_confirmed)
        ),
        false_proof_count=observations.false_proof_count,
        request_accounting_mismatch_count=(
            observations.request_accounting_mismatch_count + len(accounting_mismatches)
        ),
        loop_violation_count=observations.loop_violation_count,
        provenance_violation_count=observations.provenance_violation_count,
        secret_leak_violation_count=observations.secret_leak_violation_count,
        unmetered_action_count=observations.unmetered_action_count,
        incomplete_request_count=observations.incomplete_request_count,
        physical_request_count=observations.physical_request_count,
        model_request_count=observations.model_request_count,
        cost_usd=observations.cost_usd,
        request_accounting_status=observations.request_accounting_status,
        run_id=binding.run_id,
        pair_seed_digest=binding.pair_seed_digest,
        target_snapshot_digest=binding.target_snapshot_digest,
        model_fingerprint=binding.model_fingerprint,
        prompt_fingerprint=binding.prompt_fingerprint,
    )
    if freeze_output_tree(artifact_root).digest != binding.artifact_tree_digest:
        raise RunReceiptAdapterError("artifact tree changed while deriving the receipt")
    return receipt


def write_run_receipt(path: Path, receipt: RunReceipt) -> None:
    """Atomically write a private, byte-canonical one-receipt set."""
    content = canonical_run_receipts_bytes((receipt,))
    target = path.expanduser()
    if target.exists() or target.is_symlink():
        raise RunReceiptAdapterError("refusing to overwrite an existing receipt")
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.parent.is_symlink():
            raise RunReceiptAdapterError("receipt parent must be a real directory")
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(target)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
    except OSError as exc:
        raise RunReceiptAdapterError("cannot write canonical run receipt") from exc


def _contained_case_root(root: Path, relative: str) -> Path:
    try:
        resolved_root = root.expanduser().resolve(strict=True)
        candidate = (resolved_root / relative).resolve(strict=True)
    except OSError as exc:
        raise RunReceiptAdapterError("cannot inspect signed artifact case") from exc
    if (
        not candidate.is_relative_to(resolved_root)
        or candidate.is_symlink()
        or not candidate.is_dir()
    ):
        raise RunReceiptAdapterError("signed artifact case is not a contained directory")
    return candidate


def _load_json_object(path: Path, *, label: str) -> dict[str, object]:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > _MAX_JSON_BYTES
        ):
            raise RunReceiptAdapterError(f"{label} is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_version(before) != _file_version(opened):
            raise RunReceiptAdapterError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            content = stream.read(_MAX_JSON_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (
            len(content) > _MAX_JSON_BYTES
            or len(content) != before.st_size
            or _file_version(opened) != _file_version(after)
        ):
            raise RunReceiptAdapterError(f"{label} changed while it was read")
        payload = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except RunReceiptAdapterError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise RunReceiptAdapterError(f"{label} is invalid JSON") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise RunReceiptAdapterError(f"{label} must be a JSON object")
    _validate_json_bounds(payload)
    return {str(key): value for key, value in payload.items()}


def _file_version(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _report_finding_references(
    report: Mapping[str, object],
) -> tuple[set[str], set[str]]:
    raw_findings = report.get("findings")
    outcome = report.get("outcome")
    if not isinstance(raw_findings, list) or not isinstance(outcome, Mapping):
        raise RunReceiptAdapterError("Ravage report lacks canonical finding sections")
    raw_evidence = outcome.get("evidence")
    if not isinstance(raw_evidence, list):
        raise RunReceiptAdapterError("Ravage report lacks canonical outcome evidence")
    if len(raw_findings) + len(raw_evidence) > _MAX_FINDINGS:
        raise RunReceiptAdapterError("Ravage report exceeds the finding cap")

    nominations: set[str] = set()
    confirmed: set[str] = set()
    for item in raw_findings:
        if not isinstance(item, Mapping):
            raise RunReceiptAdapterError("Ravage report contains a malformed finding")
        reference = finding_reference_digest(_required_finding_id(item))
        nominations.add(reference)
        if str(item.get("status") or "").strip().casefold() == "confirmed":
            confirmed.add(reference)
    for item in raw_evidence:
        if not isinstance(item, Mapping):
            raise RunReceiptAdapterError("Ravage report contains malformed outcome evidence")
        reference = finding_reference_digest(_required_finding_id(item))
        nominations.add(reference)
        if item.get("confirmed_finding") is True:
            confirmed.add(reference)
    return nominations, confirmed


def _required_finding_id(item: Mapping[str, object]) -> str:
    value = item.get("finding_id")
    if not isinstance(value, str):
        raise RunReceiptAdapterError("Ravage report finding lacks an identity")
    return value


def _accounting_mismatches(
    report: Mapping[str, object],
    traffic: Mapping[str, object],
    *,
    physical_request_count: int | None,
    incomplete_request_count: int,
    unmetered_action_count: int,
    accounting_status: str,
) -> set[str]:
    report_accounting = report.get("traffic_accounting")
    if not isinstance(report_accounting, Mapping):
        return {"report_accounting_missing"}
    mismatches: set[str] = set()
    expected = {
        "physical_request_count": physical_request_count,
        "incomplete_request_count": incomplete_request_count,
        "unmetered_action_count": unmetered_action_count,
    }
    for field, external_value in expected.items():
        ledger_value = _optional_count(traffic.get(field))
        report_value = _optional_count(report_accounting.get(field))
        if ledger_value != report_value:
            mismatches.add(f"{field}_report_ledger")
        if external_value is not None and ledger_value != external_value:
            mismatches.add(f"{field}_external_ledger")
        if external_value is not None and report_value != external_value:
            mismatches.add(f"{field}_external_report")
    report_status = str(report_accounting.get("status") or "").strip().casefold()
    if report_status != accounting_status:
        mismatches.add("accounting_status_external_report")
    if traffic.get("schema") != "ravage.traffic-policy":
        mismatches.add("traffic_schema")
    return mismatches


def _optional_count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate JSON key")
        payload[key] = value
    return payload


def _reject_non_finite(_value: str) -> object:
    raise ValueError("non-finite JSON value")


def _validate_json_bounds(value: object, *, depth: int = 0) -> None:
    if depth > 40:
        raise RunReceiptAdapterError("JSON artifact exceeds the nesting cap")
    if isinstance(value, Mapping):
        if len(value) > 50_000:
            raise RunReceiptAdapterError("JSON artifact exceeds the member cap")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 1024:
                raise RunReceiptAdapterError("JSON artifact contains an invalid key")
            _validate_json_bounds(item, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 100_000:
            raise RunReceiptAdapterError("JSON artifact exceeds the list cap")
        for item in value:
            _validate_json_bounds(item, depth=depth + 1)
        return
    if isinstance(value, str) and len(value) > _MAX_JSON_BYTES:
        raise RunReceiptAdapterError("JSON artifact contains an oversized string")
    if isinstance(value, float) and not math.isfinite(value):
        raise RunReceiptAdapterError("JSON artifact contains a non-finite number")
    if isinstance(value, int) and value.bit_length() > 256:
        raise RunReceiptAdapterError("JSON artifact contains an oversized integer")


__all__ = [
    "RunReceiptAdapterError",
    "derive_run_receipt",
    "finding_reference_digest",
    "write_run_receipt",
]
