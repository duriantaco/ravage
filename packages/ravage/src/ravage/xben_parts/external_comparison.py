"""One-shot, evaluator-owned XBEN row execution for an external agent.

This module intentionally does not know how to launch Ravage or any competitor.
It owns the parts that must be identical for both: a pair-scoped proof
commitment, a minimal black-box input envelope, digest-based exact scoring, and
create-only row evidence. Concrete target and process isolation live behind
injected backends so a comparison tool can use containers while unit tests use
fakes.

This is a row primitive, not a runnable comparison campaign.  A campaign must
also bind a frozen schedule, provide real isolated target/process backends, and
maintain a no-replacement ledger across all rows.  This module fails closed when
the process boundary and independently sealed target meter do not jointly prove
the required isolation and budget controls.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, quote_plus, unquote, urlparse

from ravage.xben_parts.cases import _visible_description
from ravage.xben_parts.comparison_contracts import (
    COMPARISON_GATEWAY_TOKEN_ENV as COMPARISON_GATEWAY_TOKEN_ENV,
)
from ravage.xben_parts.comparison_contracts import (
    DESCRIPTION_ENV as DESCRIPTION_ENV,
)
from ravage.xben_parts.comparison_contracts import (
    OUTER_PROCESS_GROUP_ENV as OUTER_PROCESS_GROUP_ENV,
)
from ravage.xben_parts.comparison_contracts import (
    OUTER_PROCESS_GROUP_VALUE as OUTER_PROCESS_GROUP_VALUE,
)
from ravage.xben_parts.comparison_contracts import (
    TARGET_URL_ENV as TARGET_URL_ENV,
)
from ravage.xben_parts.comparison_contracts import (
    ExternalAgentCommand as ExternalAgentCommand,
)
from ravage.xben_parts.comparison_contracts import (
    ExternalExecutionLimits as ExternalExecutionLimits,
)
from ravage.xben_parts.comparison_contracts import (
    ExternalTarget as ExternalTarget,
)
from ravage.xben_parts.models import XbenCase

ROW_RESULT_SCHEMA_VERSION = "ravage.xben.external-comparison-row.v3"
FLAG_COMMITMENT_SCHEMA_VERSION = "ravage.xben.flag-commitment.v2"
FLAG_COMMITMENT_FILE = "flag-commitment.json"
DEFAULT_ROW_TIMEOUT_SECONDS = 600
DEFAULT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_LOG_BYTES = 1024 * 1024
DEFAULT_MAX_EVIDENCE_FILES = 4096
DEFAULT_MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_EVIDENCE_TOTAL_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_FLAG_CANDIDATES = 4096
DEFAULT_MAX_PROVENANCE_BYTES = 8 * 1024 * 1024
CAMPAIGN_INTEGRATION_REQUIREMENTS = (
    "independently_verified_frozen_schedule",
    "fresh_xben_target_backend",
    "isolated_agent_process_backend",
    "campaign_no_replacement_ledger",
)

_SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_CAMPAIGN_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
_PRIMARY_SLOT_ID_RE = re.compile(r"primary-(\d{3})")
_SYSTEM_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_ROW_INSTANCE_ID_RE = re.compile(r"xben-row-[0-9a-f]{32}")
_EXPECTED_FLAG_RE = re.compile(r"flag\{ravage_cmp_[0-9a-f]{64}\}")
_ACCOUNT_CREDENTIAL_ENV_RE = re.compile(
    r"(?:API_?KEY|ACCESS_?KEY|SECRET|PASSWORD|PRIVATE_?KEY|AUTH_?TOKEN|BEARER_?TOKEN)$",
    re.IGNORECASE,
)

_RESERVED_EVIDENCE_NAMES = (
    "row-result.json",
    "stdout.log",
    "stderr.log",
    "target-build.json",
    "target-teardown.json",
    FLAG_COMMITMENT_FILE,
    "model-gateway-receipt.json",
    "process-receipt.json",
    "sandbox-profile.sb",
    "artifacts.sha256",
)


class ExternalComparisonError(RuntimeError):
    """Base class for a row contract failure."""


class RowAlreadyExistsError(ExternalComparisonError):
    """Raised when a row would replace earlier evidence."""


class UnsafeProcessBackendError(ExternalComparisonError):
    """Raised when a backend lacks required comparison isolation or controls."""


class AgentEnvironmentError(ExternalComparisonError):
    """Raised when benchmark or undeclared state would reach an agent process."""


class ComparisonBindingError(ExternalComparisonError):
    """Raised when a row is not bound to a valid frozen-schedule identity."""


@dataclass(frozen=True)
class ProcessIsolation:
    """Capabilities a process backend must provide for comparable rows."""

    kind: str
    filesystem_isolated: bool
    target_network_only: bool
    inherits_parent_environment: bool = False
    wall_timeout_enforced: bool = False
    model_request_limit_enforced: bool = False
    target_request_limit_enforced: bool = False
    cost_limit_enforced: bool = False

    @property
    def black_box_safe(self) -> bool:
        return (
            self.filesystem_isolated
            and self.target_network_only
            and not self.inherits_parent_environment
        )

    @property
    def budget_safe(self) -> bool:
        return (
            self.wall_timeout_enforced
            and self.model_request_limit_enforced
            and self.target_request_limit_enforced
            and self.cost_limit_enforced
        )

    @property
    def comparison_safe(self) -> bool:
        return self.black_box_safe and self.budget_safe

    def to_json(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "filesystem_isolated": self.filesystem_isolated,
            "target_network_only": self.target_network_only,
            "inherits_parent_environment": self.inherits_parent_environment,
            "black_box_safe": self.black_box_safe,
            "budget_enforcement": {
                "wall_timeout": self.wall_timeout_enforced,
                "model_requests": self.model_request_limit_enforced,
                "target_requests": self.target_request_limit_enforced,
                "cost": self.cost_limit_enforced,
                "all_required": self.budget_safe,
            },
            "comparison_safe": self.comparison_safe,
        }


@dataclass(frozen=True)
class ComparisonRowBinding:
    """Evaluator-only identity tying a row to one committed primary slot."""

    campaign_id: str
    commitment_digest: str
    selection_digest: str
    primary_slot_id: str

    def to_json(self) -> dict[str, str]:
        return {
            "campaign_id": self.campaign_id,
            "commitment_digest": self.commitment_digest,
            "selection_digest": self.selection_digest,
            "primary_slot_id": self.primary_slot_id,
        }


@dataclass(frozen=True)
class ExternalProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    process_receipt_path: str | None = None
    model_gateway_receipt_path: str | None = None
    sandbox_profile_path: str | None = None


@dataclass(frozen=True)
class ExternalProcessReceiptContract:
    """Frozen evaluator inputs used to verify process evidence independently."""

    row_id: str
    model_gateway_policy_sha256: str
    model_gateway_row_token_sha256: str
    sandbox_executable_sha256: str
    runtime_read_roots: tuple[Path, ...]
    evidence_class: str
    docker_socket_path: Path | None = None


class ExternalProcessBackend(Protocol):
    isolation: ProcessIsolation
    receipt_contract: ExternalProcessReceiptContract

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: ExternalExecutionLimits,
    ) -> ExternalProcessResult: ...

    def seal_unstarted(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: ExternalExecutionLimits,
        reason: str,
    ) -> ExternalProcessResult: ...


class ExternalTargetBackend(Protocol):
    def start(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        instance_id: str,
    ) -> ExternalTarget: ...

    def stop(self, *, target: ExternalTarget) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class SubprocessBackend:
    """Minimal host backend, explicitly unsafe for a black-box comparison.

    It does not inherit the parent environment.  Host filesystem and network
    access still make it unsuitable for a scored comparison, so the row runner
    rejects it unless the caller explicitly requests a non-comparable diagnostic.
    """

    isolation: ProcessIsolation = field(
        default_factory=lambda: ProcessIsolation(
            kind="host-subprocess",
            filesystem_isolated=False,
            target_network_only=False,
            inherits_parent_environment=False,
            wall_timeout_enforced=True,
        )
    )

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: ExternalExecutionLimits,
    ) -> ExternalProcessResult:
        completed = subprocess.run(  # noqa: S603 - caller owns the explicit adapter command.
            list(command),
            cwd=cwd,
            env=dict(environment),
            text=True,
            capture_output=True,
            timeout=limits.wall_seconds,
            check=False,
        )
        return ExternalProcessResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    def seal_unstarted(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: ExternalExecutionLimits,
        reason: str,
    ) -> ExternalProcessResult:
        del command, cwd, environment, limits, reason
        return ExternalProcessResult(returncode=-1)


def record_unstarted_external_xben_row(
    *,
    case: XbenCase,
    agent: ExternalAgentCommand,
    binding: ComparisonRowBinding,
    row_dir: Path,
    process_backend: ExternalProcessBackend,
    expected_flag: str,
    reason: str,
    row_instance_id: str | None = None,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> dict[str, object]:
    """Create terminal row evidence after pair preparation fails before launch.

    Campaign coordinators must call this once for each reserved arm so the
    shared model gateway can seal an exact forty-row ledger even when no target
    or process was started. The row is always invalid for scoring.
    """

    _validate_agent(agent)
    _validate_binding(binding)
    _validate_agent_environment_for_case(agent, case=case)
    isolation = _process_isolation(process_backend)
    _validate_process_receipt_contract(
        process_backend,
        binding=binding,
        required=True,
    )
    if _EXPECTED_FLAG_RE.fullmatch(expected_flag) is None:
        raise ValueError("pair-scoped comparison flag has an invalid format")
    if not reason.strip():
        raise ValueError("unstarted comparison row requires a terminal reason")
    instance_id = _row_instance_id(row_instance_id)
    claimed_row_dir, native_output_dir = _claim_row_dir(row_dir)
    expected_flag_sha256 = hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
    _write_json_exclusive(
        claimed_row_dir / FLAG_COMMITMENT_FILE,
        {
            "schema_version": FLAG_COMMITMENT_SCHEMA_VERSION,
            "created_at": _now(),
            "schedule_binding": binding.to_json(),
            "instance_id": instance_id,
            "algorithm": "sha256-utf8",
            "expected_flag_sha256": expected_flag_sha256,
            "scope": "pair",
        },
    )
    redacted_reason = (
        _redact_text(
            reason,
            sensitive_values=(
                expected_flag,
                *_sensitive_environment_values(agent.environment),
            ),
        )
        or "pair preparation failed"
    )
    return _finish_without_target(
        row_dir=claimed_row_dir,
        case=case,
        agent=agent,
        binding=binding,
        isolation=isolation,
        process_backend=process_backend,
        native_output_dir=native_output_dir,
        expected_flag=expected_flag,
        pair_scoped_flag=True,
        instance_id=instance_id,
        max_artifact_bytes=max_artifact_bytes,
        error=redacted_reason,
    )


def run_external_xben_row(  # noqa: PLR0915 - the complete one-shot lifecycle stays auditable.
    *,
    case: XbenCase,
    agent: ExternalAgentCommand,
    binding: ComparisonRowBinding,
    row_dir: Path,
    process_backend: ExternalProcessBackend,
    target_backend: ExternalTargetBackend,
    require_comparison_safety: bool = True,
    expected_flag: str | None = None,
    row_instance_id: str | None = None,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    max_log_bytes: int = DEFAULT_MAX_LOG_BYTES,
) -> dict[str, object]:
    """Execute and exact-score one immutable ``(case, agent)`` row.

    There is deliberately no resume or retry parameter.  Once ``row_dir`` has
    been created, every outcome remains evidence and a second invocation must use
    another directory. A comparison campaign supplies the same evaluator-only
    256-bit flag to both prepared target arms. Only its commitment is retained;
    the raw expected or found flag is never written to ``row-result.json``.
    """

    _validate_agent(agent)
    _validate_binding(binding)
    _validate_agent_environment_for_case(agent, case=case)
    isolation = _process_isolation(process_backend)
    receipt_contract = _validate_process_receipt_contract(
        process_backend,
        binding=binding,
        required=False,
    )
    if require_comparison_safety and not _admissible_process_boundary(
        isolation,
        receipt_contract=receipt_contract,
    ):
        message = (
            f"process backend {isolation.kind!r} cannot provide comparison isolation "
            "and budget controls"
        )
        raise UnsafeProcessBackendError(message)
    if require_comparison_safety and receipt_contract is None:
        raise UnsafeProcessBackendError("process backend has no frozen receipt contract")
    if receipt_contract is not None:
        _validate_process_read_roots_for_case(receipt_contract, case=case)
    if receipt_contract is not None:
        # A comparison receipt is meaningful only for the canonical adapter
        # builders. A generic caller-created command could otherwise receive
        # the evaluator's answer in argv and still obtain a valid process
        # receipt from the concrete backend.
        from ravage.xben_parts.comparison_adapters import validate_pinned_adapter_agent

        validate_pinned_adapter_agent(agent)
    if not 0 < max_artifact_bytes <= DEFAULT_MAX_ARTIFACT_BYTES:
        raise ValueError("max_artifact_bytes exceeds the fixed evidence bound")
    if not 0 < max_log_bytes <= DEFAULT_MAX_LOG_BYTES:
        raise ValueError("max_log_bytes exceeds the fixed evidence bound")

    pair_scoped_flag = expected_flag is not None
    if expected_flag is not None and _EXPECTED_FLAG_RE.fullmatch(expected_flag) is None:
        raise ValueError("pair-scoped comparison flag has an invalid format")
    if expected_flag is None:
        expected_flag = f"flag{{ravage_cmp_{secrets.token_hex(32)}}}"
    _validate_agent_evaluator_separation(agent, case=case, expected_flag=expected_flag)
    instance_id = _row_instance_id(row_instance_id)
    claimed_row_dir, native_output_dir = _claim_row_dir(row_dir)
    row_sensitive_values = (
        expected_flag,
        *_sensitive_environment_values(agent.environment),
    )
    expected_flag_sha256 = hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
    _write_json_exclusive(
        claimed_row_dir / FLAG_COMMITMENT_FILE,
        {
            "schema_version": FLAG_COMMITMENT_SCHEMA_VERSION,
            "created_at": _now(),
            "schedule_binding": binding.to_json(),
            "instance_id": instance_id,
            "algorithm": "sha256-utf8",
            "expected_flag_sha256": expected_flag_sha256,
            "scope": "pair" if pair_scoped_flag else "legacy-row-diagnostic",
        },
    )
    description = _visible_description(case, "black-box")
    if not description:
        return _finish_without_target(
            row_dir=claimed_row_dir,
            case=case,
            agent=agent,
            binding=binding,
            isolation=isolation,
            process_backend=process_backend,
            native_output_dir=native_output_dir,
            expected_flag=expected_flag,
            pair_scoped_flag=pair_scoped_flag,
            instance_id=instance_id,
            max_artifact_bytes=max_artifact_bytes,
            error="selected XBEN case has no black-box description",
        )

    started_at = _now()
    started_monotonic = time.monotonic()
    target: ExternalTarget | None = None
    build_record: dict[str, object] = {
        "status": "not_started",
        "instance_id": instance_id,
    }
    teardown_record: dict[str, object] = {
        "status": "not_started",
        "instance_id": instance_id,
    }
    process_result = ExternalProcessResult(returncode=-1)
    execution_status = "not_started"
    execution_error: str | None = None
    execution_environment: dict[str, str] | None = None
    command_started_at: str | None = None
    command_completed_at: str | None = None

    try:
        target = target_backend.start(
            case=case,
            expected_flag=expected_flag,
            instance_id=instance_id,
        )
        _validate_target(target, instance_id=instance_id, expected_flag=expected_flag)
        build_record = {
            "status": "succeeded",
            "instance_id": instance_id,
            "provenance": _json_mapping(target.build_provenance),
        }
        environment = _agent_environment(
            agent,
            target_url=target.target_url,
            description=description,
            expected_flag=expected_flag,
            case=case,
        )
        execution_environment = environment
        command_started_at = _now()
        try:
            process_result = process_backend.run(
                agent.command,
                cwd=native_output_dir,
                environment=environment,
                limits=agent.limits,
            )
        except subprocess.TimeoutExpired as exc:
            process_result = ExternalProcessResult(
                returncode=-1,
                stdout=_stream_text(exc.stdout),
                stderr=_stream_text(exc.stderr),
                timed_out=True,
            )
            execution_status = "timed_out"
            execution_error = f"agent timed out after {agent.limits.wall_seconds} seconds"
        except TimeoutError as exc:
            process_result = ExternalProcessResult(
                returncode=-1,
                stderr=str(exc),
                timed_out=True,
            )
            execution_status = "timed_out"
            execution_error = (
                str(exc) or f"agent timed out after {agent.limits.wall_seconds} seconds"
            )
        except Exception as exc:  # noqa: BLE001 - a failed adapter remains a terminal row.
            process_result = ExternalProcessResult(returncode=-1, stderr=str(exc))
            execution_status = "errored"
            execution_error = _redacted_bounded_error(
                exc,
                sensitive_values=row_sensitive_values,
            )
        else:
            if process_result.timed_out:
                execution_status = "timed_out"
                execution_error = f"agent timed out after {agent.limits.wall_seconds} seconds"
            else:
                execution_status = "completed" if process_result.returncode == 0 else "errored"
            if process_result.returncode != 0 and not process_result.timed_out:
                execution_error = f"agent exited with status {process_result.returncode}"
        finally:
            command_completed_at = _now()
    except Exception as exc:  # noqa: BLE001 - setup/contract failures are retained as evidence.
        execution_status = "not_started"
        execution_error = _redacted_bounded_error(
            exc,
            sensitive_values=row_sensitive_values,
        )
        build_record = {
            "status": "errored",
            "instance_id": instance_id,
            "error": execution_error,
        }
    finally:
        if target is not None:
            try:
                provenance = target_backend.stop(target=target)
                retained_provenance = _json_mapping(provenance)
                serialized_provenance = json.dumps(retained_provenance, sort_keys=True)
                if expected_flag in serialized_provenance or expected_flag in unquote(
                    serialized_provenance
                ):
                    raise ExternalComparisonError(
                        "target teardown provenance exposed the expected flag"
                    )
                if require_comparison_safety:
                    _validate_comparison_target_evidence(
                        target=target,
                        teardown=retained_provenance,
                        case=case,
                        agent=agent,
                        expected_flag=expected_flag,
                    )
                teardown_record = {
                    "status": "succeeded",
                    "instance_id": instance_id,
                    "provenance": retained_provenance,
                }
            except Exception as exc:  # noqa: BLE001 - cleanup failure invalidates, but retains, row.
                teardown_record = {
                    "status": "errored",
                    "instance_id": instance_id,
                    "error": _redacted_bounded_error(
                        exc,
                        sensitive_values=row_sensitive_values,
                    ),
                }

    if execution_status == "not_started":
        terminal_reason = (
            _redact_text(
                execution_error or "agent process was not started",
                sensitive_values=row_sensitive_values,
            )
            or "agent process was not started"
        )
        process_result = _seal_unstarted_process(
            process_backend=process_backend,
            command=agent.command,
            cwd=native_output_dir,
            environment=agent.environment,
            limits=agent.limits,
            reason=terminal_reason,
            sensitive_values=row_sensitive_values,
        )

    unsafe_native_output = _purge_unsafe_native_output(
        native_output_dir,
        sensitive_values=_sensitive_environment_values(agent.environment),
    )
    if unsafe_native_output is not None:
        if execution_status == "completed":
            execution_status = "errored"
        execution_error = unsafe_native_output

    receipt_validation = _validate_execution_receipts(
        row_dir=claimed_row_dir,
        native_output_dir=native_output_dir,
        process_backend=process_backend,
        process_result=process_result,
        binding=binding,
        agent=agent,
        environment=execution_environment,
        require_official_safety=bool(
            require_comparison_safety
            and receipt_contract is not None
            and receipt_contract.evidence_class == "strict_official"
        ),
        sensitive_values=row_sensitive_values,
    )
    receipt_validation["error"] = _redact_text(
        (str(receipt_validation["error"]) if receipt_validation.get("error") is not None else None),
        sensitive_values=row_sensitive_values,
    )
    if unsafe_native_output is not None:
        receipt_validation.update(
            {
                "valid": False,
                "official_attestation_eligible": False,
                "error": unsafe_native_output,
            }
        )
    artifact_record = _score_declared_artifact(
        native_output_dir=native_output_dir,
        artifact_path=agent.artifact_path,
        expected_flag=expected_flag,
        max_artifact_bytes=max_artifact_bytes,
    )
    sensitive_values = row_sensitive_values
    stdout_log, stdout_record = _sanitized_bounded_log(
        process_result.stdout,
        sensitive_values=sensitive_values,
        maximum_bytes=max_log_bytes,
    )
    stderr_log, stderr_record = _sanitized_bounded_log(
        process_result.stderr,
        sensitive_values=sensitive_values,
        maximum_bytes=max_log_bytes,
    )
    execution_error = _redact_text(execution_error, sensitive_values=sensitive_values)
    _write_text_exclusive(claimed_row_dir / "stdout.log", stdout_log)
    _write_text_exclusive(claimed_row_dir / "stderr.log", stderr_log)
    _write_json_exclusive(claimed_row_dir / "target-build.json", build_record)
    _write_json_exclusive(claimed_row_dir / "target-teardown.json", teardown_record)

    target_ready = build_record.get("status") == "succeeded"
    teardown_complete = teardown_record.get("status") == "succeeded"
    artifact_valid = artifact_record.get("status") == "scored"
    exact_match = artifact_record.get("exact_match") is True
    receipt_valid = receipt_validation.get("valid") is True
    process_official_eligible = bool(
        receipt_validation.get("official_attestation_eligible") is True
    )
    # Evidence validity and solve success are deliberately separate.  A
    # started agent that times out or exits nonzero is a valid *unsuccessful*
    # primary observation when its receipts and target teardown are intact.
    # It must remain in the denominator rather than invite a replacement run.
    terminal_observation_valid = bool(target_ready and teardown_complete and receipt_valid)
    execution_succeeded = bool(
        execution_status == "completed"
        and process_result.returncode == 0
        and not process_result.timed_out
    )
    official_attestation_eligible = bool(
        process_official_eligible
        and receipt_valid
        and target_ready
        and teardown_complete
        and pair_scoped_flag
        and require_comparison_safety
    )
    valid_for_comparison = bool(
        terminal_observation_valid
        and official_attestation_eligible
        and pair_scoped_flag
        and require_comparison_safety
    )
    valid_for_paired_local_comparison = bool(
        terminal_observation_valid
        and receipt_validation.get("evidence_class") == "paired_local"
        and pair_scoped_flag
        and require_comparison_safety
    )
    # In particular, a flag-shaped artifact written before teardown cannot
    # rescue a timed-out or nonzero adapter.
    solved = bool(
        exact_match
        and execution_succeeded
        and (valid_for_comparison or valid_for_paired_local_comparison)
    )
    status = _row_status(
        solved=solved,
        target_ready=target_ready,
        teardown_complete=teardown_complete,
        artifact_valid=artifact_valid,
        execution_status=execution_status,
    )
    result: dict[str, object] = {
        "schema_version": ROW_RESULT_SCHEMA_VERSION,
        "created_at": started_at,
        "completed_at": _now(),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 6),
        "status": status,
        "valid_for_comparison": valid_for_comparison,
        "valid_for_paired_local_comparison": valid_for_paired_local_comparison,
        "official_attestation_eligible": official_attestation_eligible,
        "case": {
            "benchmark_id": case.benchmark_id,
            "description_sha256": hashlib.sha256(description.encode("utf-8")).hexdigest(),
        },
        "agent": {
            "name": agent.name,
            "system_id": agent.system_id,
            "provider": agent.provider,
            "model": agent.model,
            "reasoning_effort": agent.reasoning_effort,
            "adapter_version": agent.adapter_version,
            "command_sha256": _command_sha256(agent.command),
            "environment_names": sorted(agent.environment),
        },
        "schedule_binding": binding.to_json(),
        "isolation": isolation.to_json(),
        "limits": agent.limits.to_json(),
        "policy": {
            "attempt": 1,
            "retry_allowed": False,
            "replacement_allowed": False,
            "fresh_target_per_row": True,
            "pair_scoped_flag": pair_scoped_flag,
        },
        "target": {
            "instance_id": instance_id,
            "target_url": target.target_url if target is not None else None,
            "build_provenance_path": "target-build.json",
            "teardown_provenance_path": "target-teardown.json",
        },
        "execution": {
            "status": execution_status,
            "returncode": process_result.returncode,
            "timeout_seconds": agent.limits.wall_seconds,
            "started_at": command_started_at,
            "completed_at": command_completed_at,
            "error": execution_error,
            "stdout_path": "stdout.log",
            "stderr_path": "stderr.log",
            "stdout_capture": stdout_record,
            "stderr_capture": stderr_record,
            "receipts": receipt_validation,
        },
        "score": {
            "mode": "committed_flag_candidate_sha256",
            "max_artifact_bytes": max_artifact_bytes,
            "expected_flag_sha256": expected_flag_sha256,
            "exact_match": exact_match,
            "solved": solved,
            "artifact": artifact_record,
        },
    }
    _write_json_exclusive(claimed_row_dir / "row-result.json", result)
    _write_manifest_exclusive(claimed_row_dir)
    return result


def _seal_unstarted_process(
    *,
    process_backend: ExternalProcessBackend,
    command: Sequence[str],
    cwd: Path,
    environment: Mapping[str, str],
    limits: ExternalExecutionLimits,
    reason: str,
    sensitive_values: Sequence[str],
) -> ExternalProcessResult:
    try:
        return process_backend.seal_unstarted(
            command,
            cwd=cwd,
            environment=environment,
            limits=limits,
            reason=reason,
        )
    except Exception as exc:  # noqa: BLE001 - a failed seal remains an invalid row.
        return ExternalProcessResult(
            returncode=-1,
            stderr=_redacted_bounded_error(exc, sensitive_values=sensitive_values),
        )


def _validate_execution_receipts(  # noqa: PLR0913
    *,
    row_dir: Path,
    native_output_dir: Path,
    process_backend: ExternalProcessBackend,
    process_result: ExternalProcessResult,
    binding: ComparisonRowBinding,
    agent: ExternalAgentCommand,
    environment: Mapping[str, str] | None,
    require_official_safety: bool,
    sensitive_values: Sequence[str],
) -> dict[str, object]:
    """Read and recompute evaluator receipts without trusting backend booleans."""

    record: dict[str, object] = {
        "valid": False,
        "official_attestation_eligible": False,
        "evidence_class": None,
        "process_receipt_path": process_result.process_receipt_path,
        "process_receipt_document_sha256": None,
        "process_receipt_file_sha256": None,
        "model_gateway_receipt_path": process_result.model_gateway_receipt_path,
        "model_gateway_receipt_document_sha256": None,
        "model_gateway_receipt_file_sha256": None,
        "model_gateway_policy_sha256": None,
        "sandbox_profile_path": process_result.sandbox_profile_path,
        "sandbox_profile_sha256": None,
        "public_validation_contract": None,
        "error": None,
    }
    try:
        from ravage.xben_parts.comparison_model_gateway import (
            validate_model_gateway_receipt,
        )
        from ravage.xben_parts.comparison_process_backend import (
            MODEL_GATEWAY_RECEIPT_FILE,
            PROCESS_RECEIPT_FILE,
            SANDBOX_PROFILE_FILE,
            read_bounded_json_receipt,
            validate_comparison_process_receipt,
            validate_unstarted_comparison_process_receipt,
        )

        contract = getattr(process_backend, "receipt_contract", None)
        if not isinstance(contract, ExternalProcessReceiptContract):
            raise ExternalComparisonError("process backend has no frozen receipt contract")
        if contract.row_id != binding.primary_slot_id:
            raise ExternalComparisonError("process backend row reservation is invalid")
        if contract.evidence_class not in {"strict_official", "paired_local"}:
            raise ExternalComparisonError("process receipt evidence class is invalid")
        if _SHA256_DIGEST_RE.fullmatch(contract.model_gateway_row_token_sha256) is None:
            raise ExternalComparisonError("model gateway row-token digest is invalid")
        if (
            process_result.process_receipt_path != PROCESS_RECEIPT_FILE
            or process_result.model_gateway_receipt_path != MODEL_GATEWAY_RECEIPT_FILE
            or process_result.sandbox_profile_path != SANDBOX_PROFILE_FILE
        ):
            raise ExternalComparisonError("process backend returned unexpected receipt paths")

        process_path = row_dir / PROCESS_RECEIPT_FILE
        model_path = row_dir / MODEL_GATEWAY_RECEIPT_FILE
        profile_path = row_dir / SANDBOX_PROFILE_FILE
        process_payload = read_bounded_json_receipt(process_path)
        model_payload = read_bounded_json_receipt(model_path)
        profile = _read_bounded_regular_file(profile_path, maximum_bytes=1024 * 1024)
        model_receipt = validate_model_gateway_receipt(
            model_payload,
            expected_row_id=binding.primary_slot_id,
            expected_policy_sha256=contract.model_gateway_policy_sha256,
            expected_max_requests=agent.limits.max_model_requests,
            expected_max_cost_usd=agent.limits.max_cost_usd,
        )
        if model_receipt.get("valid") is not True:
            raise ExternalComparisonError("model gateway receipt is not valid")
        if model_receipt.get("row_token_sha256") != contract.model_gateway_row_token_sha256:
            raise ExternalComparisonError("model gateway receipt token binding is invalid")
        model_file_digest = _sha256_file_prefixed(model_path)
        model_document_digest = str(model_receipt["document_sha256"])
        process_file_digest = _sha256_file_prefixed(process_path)
        profile_digest = "sha256:" + hashlib.sha256(profile).hexdigest()
        if not isinstance(process_payload, dict):
            raise ExternalComparisonError("process receipt is not an object")
        process_document_digest = process_payload.get("document_sha256")
        if (
            not isinstance(process_document_digest, str)
            or _SHA256_DIGEST_RE.fullmatch(process_document_digest) is None
        ):
            raise ExternalComparisonError("process receipt document digest is invalid")
        record.update(
            {
                "evidence_class": contract.evidence_class,
                "process_receipt_document_sha256": process_document_digest,
                "process_receipt_file_sha256": process_file_digest,
                "model_gateway_receipt_document_sha256": model_document_digest,
                "model_gateway_receipt_file_sha256": model_file_digest,
                "model_gateway_policy_sha256": contract.model_gateway_policy_sha256,
                "sandbox_profile_sha256": profile_digest,
            }
        )
        if environment is None:
            declaration = validate_unstarted_comparison_process_receipt(
                process_payload,
                expected_row_id=binding.primary_slot_id,
                expected_limits=agent.limits,
                expected_policy_sha256=contract.model_gateway_policy_sha256,
                expected_evidence_class=contract.evidence_class,
                model_receipt_file_sha256=model_file_digest,
                model_receipt_document_sha256=model_document_digest,
                sandbox_profile=profile,
            )
            record["process_receipt_document_sha256"] = declaration["document_sha256"]
            raise ExternalComparisonError("agent process was never started")
        if require_official_safety and contract.evidence_class != "strict_official":
            raise ExternalComparisonError("paired-local process evidence is not official-safe")
        row_token = environment.get(COMPARISON_GATEWAY_TOKEN_ENV)
        if not row_token:
            raise ExternalComparisonError("row-scoped model gateway token is absent")
        expected_token_digest = "sha256:" + hashlib.sha256(row_token.encode()).hexdigest()
        if expected_token_digest != contract.model_gateway_row_token_sha256:
            raise ExternalComparisonError("row environment differs from frozen token binding")
        process_receipt = validate_comparison_process_receipt(
            process_payload,
            expected_row_id=binding.primary_slot_id,
            expected_command=agent.command,
            expected_environment=environment,
            expected_limits=agent.limits,
            expected_policy_sha256=contract.model_gateway_policy_sha256,
            expected_sandbox_exec_sha256=contract.sandbox_executable_sha256,
            expected_runtime_read_roots=contract.runtime_read_roots,
            expected_output_directory=native_output_dir,
            expected_docker_socket_path=contract.docker_socket_path,
            model_receipt_file_sha256=model_file_digest,
            model_receipt_document_sha256=model_document_digest,
            sandbox_profile=profile,
            require_official_safety=require_official_safety,
        )
        if process_receipt.get("evidence_class") != contract.evidence_class:
            raise ExternalComparisonError("process receipt class differs from frozen contract")
        process_execution = process_receipt.get("execution")
        if not isinstance(process_execution, Mapping):
            raise ExternalComparisonError("process receipt execution is not an object")
        if process_execution.get("returncode") != process_result.returncode:
            raise ExternalComparisonError("process result return code differs from its receipt")
        if process_execution.get("timed_out") is not process_result.timed_out:
            raise ExternalComparisonError("process result timeout differs from its receipt")
        public_contract = {
            "row_id": binding.primary_slot_id,
            "command": process_receipt["command"],
            "environment": process_receipt["environment"],
            "limits": agent.limits.to_json(),
            "model_gateway_policy_sha256": contract.model_gateway_policy_sha256,
            "model_gateway_row_token_sha256": contract.model_gateway_row_token_sha256,
            "sandbox_executable_sha256": contract.sandbox_executable_sha256,
            "sandbox": process_receipt["sandbox"],
        }
        record.update(
            {
                "valid": True,
                "official_attestation_eligible": process_receipt.get(
                    "official_attestation_eligible"
                )
                is True,
                "evidence_class": contract.evidence_class,
                "process_receipt_document_sha256": process_receipt["document_sha256"],
                "public_validation_contract": public_contract,
            }
        )
    except Exception as exc:  # noqa: BLE001 - malformed evidence must fail closed.
        record["error"] = _redacted_bounded_error(
            exc,
            sensitive_values=sensitive_values,
        )
    return record


def _finish_without_target(
    *,
    row_dir: Path,
    case: XbenCase,
    agent: ExternalAgentCommand,
    binding: ComparisonRowBinding,
    isolation: ProcessIsolation,
    process_backend: ExternalProcessBackend,
    native_output_dir: Path,
    expected_flag: str,
    pair_scoped_flag: bool,
    instance_id: str,
    max_artifact_bytes: int,
    error: str,
) -> dict[str, object]:
    sensitive_values = (
        expected_flag,
        *_sensitive_environment_values(agent.environment),
    )
    error = _redacted_bounded_text(error, sensitive_values=sensitive_values) or (
        "comparison row could not be started"
    )
    build = {"status": "errored", "instance_id": instance_id, "error": error}
    teardown = {"status": "not_started", "instance_id": instance_id}
    _write_text_exclusive(row_dir / "stdout.log", "")
    _write_text_exclusive(row_dir / "stderr.log", "")
    _write_json_exclusive(row_dir / "target-build.json", build)
    _write_json_exclusive(row_dir / "target-teardown.json", teardown)
    process_result = _seal_unstarted_process(
        process_backend=process_backend,
        command=agent.command,
        cwd=native_output_dir,
        environment=agent.environment,
        limits=agent.limits,
        reason=error,
        sensitive_values=sensitive_values,
    )
    receipt_validation = _validate_execution_receipts(
        row_dir=row_dir,
        native_output_dir=native_output_dir,
        process_backend=process_backend,
        process_result=process_result,
        binding=binding,
        agent=agent,
        environment=None,
        require_official_safety=True,
        sensitive_values=sensitive_values,
    )
    receipt_validation["error"] = _redact_text(
        (str(receipt_validation["error"]) if receipt_validation.get("error") is not None else None),
        sensitive_values=sensitive_values,
    )
    result: dict[str, object] = {
        "schema_version": ROW_RESULT_SCHEMA_VERSION,
        "created_at": _now(),
        "completed_at": _now(),
        "elapsed_seconds": 0.0,
        "status": "infrastructure_error",
        "valid_for_comparison": False,
        "valid_for_paired_local_comparison": False,
        "official_attestation_eligible": False,
        "case": {"benchmark_id": case.benchmark_id, "description_sha256": None},
        "agent": {
            "name": agent.name,
            "system_id": agent.system_id,
            "provider": agent.provider,
            "model": agent.model,
            "reasoning_effort": agent.reasoning_effort,
            "adapter_version": agent.adapter_version,
            "command_sha256": _command_sha256(agent.command),
            "environment_names": sorted(agent.environment),
        },
        "schedule_binding": binding.to_json(),
        "isolation": isolation.to_json(),
        "limits": agent.limits.to_json(),
        "policy": {
            "attempt": 1,
            "retry_allowed": False,
            "replacement_allowed": False,
            "fresh_target_per_row": True,
            "pair_scoped_flag": pair_scoped_flag,
        },
        "target": {
            "instance_id": instance_id,
            "target_url": None,
            "build_provenance_path": "target-build.json",
            "teardown_provenance_path": "target-teardown.json",
        },
        "execution": {
            "status": "not_started",
            "returncode": process_result.returncode,
            "timeout_seconds": agent.limits.wall_seconds,
            "started_at": None,
            "completed_at": None,
            "error": error,
            "stdout_path": "stdout.log",
            "stderr_path": "stderr.log",
            "stdout_capture": _empty_capture_record(),
            "stderr_capture": _empty_capture_record(),
            "receipts": receipt_validation,
        },
        "score": {
            "mode": "committed_flag_candidate_sha256",
            "max_artifact_bytes": max_artifact_bytes,
            "expected_flag_sha256": hashlib.sha256(expected_flag.encode("utf-8")).hexdigest(),
            "exact_match": False,
            "solved": False,
            "artifact": {
                "path": agent.artifact_path,
                "status": "not_scored",
                "sha256": None,
                "size_bytes": None,
                "exact_match": False,
            },
        },
    }
    _write_json_exclusive(row_dir / "row-result.json", result)
    _write_manifest_exclusive(row_dir)
    return result


def _validate_agent(agent: ExternalAgentCommand) -> None:
    if not agent.name.strip():
        raise ValueError("external agent name must not be empty")
    if _SYSTEM_ID_RE.fullmatch(agent.system_id) is None:
        raise ValueError("external agent system_id is invalid")
    if (
        not agent.reasoning_effort
        or agent.reasoning_effort != agent.reasoning_effort.strip()
        or len(agent.reasoning_effort) > 200
    ):
        raise ValueError("external agent reasoning_effort must be nonempty and normalized")
    if not agent.command or not all(
        isinstance(item, str) and item.strip() and "\x00" not in item for item in agent.command
    ):
        raise ValueError("external agent command must contain non-empty arguments")
    if any(_EXPECTED_FLAG_RE.search(item) is not None for item in agent.command):
        raise AgentEnvironmentError("external agent command contains a comparison flag")
    _validate_limits(agent.limits)
    _artifact_relative_path(agent.artifact_path)
    if _EXPECTED_FLAG_RE.search(agent.artifact_path) is not None:
        raise AgentEnvironmentError("external agent artifact path contains a comparison flag")
    allowlist = set(agent.environment_allowlist)
    undeclared = sorted(set(agent.environment) - allowlist)
    if undeclared:
        raise AgentEnvironmentError(
            f"agent environment contains non-allowlisted names: {', '.join(undeclared)}"
        )
    forbidden = sorted(name for name in allowlist if _forbidden_agent_environment_name(name))
    if forbidden:
        raise AgentEnvironmentError(
            f"agent environment allowlist contains benchmark-sensitive names: {', '.join(forbidden)}"
        )


def _validate_agent_evaluator_separation(
    agent: ExternalAgentCommand,
    *,
    case: XbenCase,
    expected_flag: str,
) -> None:
    """Reject direct or common encoded benchmark ground truth in agent inputs."""

    source = case.path.expanduser().resolve()
    sensitive = [expected_flag, str(source)]
    if source.parent != Path("/"):
        sensitive.append(str(source.parent))
    serialized = json.dumps(
        {
            "name": agent.name,
            "system_id": agent.system_id,
            "command": list(agent.command),
            "artifact_path": agent.artifact_path,
            "provider": agent.provider,
            "model": agent.model,
            "reasoning_effort": agent.reasoning_effort,
            "adapter_version": agent.adapter_version,
            "environment": dict(agent.environment),
            "environment_allowlist": list(agent.environment_allowlist),
        },
        ensure_ascii=True,
        sort_keys=True,
    )
    for value in sensitive:
        raw = value.encode("utf-8")
        variants = {
            value,
            quote(value, safe=""),
            quote_plus(value, safe=""),
            raw.hex(),
            base64.b64encode(raw).decode("ascii"),
            base64.urlsafe_b64encode(raw).decode("ascii"),
            base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        }
        if any(variant and variant in serialized for variant in variants):
            raise AgentEnvironmentError(
                "external agent inputs contain evaluator-only benchmark state"
            )


def _validate_binding(binding: ComparisonRowBinding) -> None:
    if _CAMPAIGN_ID_RE.fullmatch(binding.campaign_id) is None:
        raise ComparisonBindingError("comparison campaign_id is invalid")
    for label, value in (
        ("commitment_digest", binding.commitment_digest),
        ("selection_digest", binding.selection_digest),
    ):
        if _SHA256_DIGEST_RE.fullmatch(value) is None:
            raise ComparisonBindingError(f"comparison {label} must be a sha256 digest")
    match = _PRIMARY_SLOT_ID_RE.fullmatch(binding.primary_slot_id)
    if match is None or not 1 <= int(match.group(1)) <= 40:
        raise ComparisonBindingError("comparison primary_slot_id is invalid")


def _row_instance_id(value: str | None) -> str:
    if value is None:
        return f"xben-row-{secrets.token_hex(16)}"
    if _ROW_INSTANCE_ID_RE.fullmatch(value) is None:
        raise ComparisonBindingError(
            "comparison row_instance_id must be xben-row- plus 32 lowercase hex characters"
        )
    return value


def _validate_limits(limits: ExternalExecutionLimits) -> None:
    if not isinstance(limits, ExternalExecutionLimits):
        raise ValueError("external agent execution limits must use the shared contract")
    for label, value in (
        ("wall_seconds", limits.wall_seconds),
        ("max_model_requests", limits.max_model_requests),
        ("max_target_requests", limits.max_target_requests),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"external agent {label} limit must be a positive integer")
    if (
        not isinstance(limits.max_cost_usd, Decimal)
        or not limits.max_cost_usd.is_finite()
        or limits.max_cost_usd <= 0
    ):
        raise ValueError("external agent max_cost_usd limit must be finite and positive")


def _process_isolation(process_backend: ExternalProcessBackend) -> ProcessIsolation:
    isolation = getattr(process_backend, "isolation", None)
    if not isinstance(isolation, ProcessIsolation):
        raise UnsafeProcessBackendError("process backend does not declare its isolation contract")
    return isolation


def _validate_process_receipt_contract(
    process_backend: ExternalProcessBackend,
    *,
    binding: ComparisonRowBinding,
    required: bool,
) -> ExternalProcessReceiptContract | None:
    contract = getattr(process_backend, "receipt_contract", None)
    if contract is None and not required:
        return None
    if not isinstance(contract, ExternalProcessReceiptContract):
        raise UnsafeProcessBackendError("process backend has no frozen receipt contract")
    if contract.row_id != binding.primary_slot_id:
        raise ComparisonBindingError("process backend is reserved for a different primary slot")
    if (
        _SHA256_DIGEST_RE.fullmatch(contract.model_gateway_policy_sha256) is None
        or _SHA256_DIGEST_RE.fullmatch(contract.model_gateway_row_token_sha256) is None
        or _SHA256_DIGEST_RE.fullmatch(contract.sandbox_executable_sha256) is None
    ):
        raise UnsafeProcessBackendError("process backend receipt contract contains invalid digests")
    if contract.evidence_class not in {"strict_official", "paired_local"}:
        raise UnsafeProcessBackendError("process backend receipt contract class is invalid")
    if contract.evidence_class == "strict_official" and contract.docker_socket_path is not None:
        raise UnsafeProcessBackendError("strict process receipt contract exposes Docker")
    if contract.evidence_class == "paired_local" and contract.docker_socket_path is None:
        raise UnsafeProcessBackendError("paired-local process receipt contract omits Docker")
    return contract


def _admissible_process_boundary(
    isolation: ProcessIsolation,
    *,
    receipt_contract: ExternalProcessReceiptContract | None,
) -> bool:
    """Validate only capabilities the process boundary can itself enforce.

    Target request accounting belongs to the separately verified target meter,
    so the concrete process backend must declare that capability false. The
    two receipts are joined after teardown. Generic diagnostic backends have no
    such receipt join and retain the older all-capabilities requirement.
    """

    if receipt_contract is None:
        return isolation.comparison_safe
    common = bool(
        not isolation.inherits_parent_environment
        and isolation.wall_timeout_enforced
        and isolation.model_request_limit_enforced
        and not isolation.target_request_limit_enforced
        and isolation.cost_limit_enforced
    )
    if receipt_contract.evidence_class == "strict_official":
        return bool(
            common
            and isolation.filesystem_isolated
            and isolation.target_network_only
            and isolation.kind == "macos-sandbox-exec-strict"
        )
    return bool(
        common
        and not isolation.filesystem_isolated
        and not isolation.target_network_only
        and isolation.kind == "macos-sandbox-exec-trusted-host-docker"
    )


def _validate_process_read_roots_for_case(
    contract: ExternalProcessReceiptContract,
    *,
    case: XbenCase,
) -> None:
    """Keep every approved runtime root disjoint from withheld XBEN source."""

    sensitive = (
        case.path.expanduser().resolve(),
        case.path.expanduser().resolve().parent,
    )
    for raw_root in contract.runtime_read_roots:
        root = raw_root.expanduser().resolve(strict=False)
        if not root.is_absolute() or root == Path("/"):
            raise UnsafeProcessBackendError("process runtime read root is unsafe")
        for withheld in sensitive:
            try:
                root.relative_to(withheld)
            except ValueError:
                pass
            else:
                raise UnsafeProcessBackendError(
                    "process runtime read root overlaps withheld benchmark source"
                )
            try:
                withheld.relative_to(root)
            except ValueError:
                continue
            raise UnsafeProcessBackendError(
                "process runtime read root contains withheld benchmark source"
            )


def _claim_row_dir(row_dir: Path) -> tuple[Path, Path]:
    requested = row_dir.expanduser()
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    parent = requested.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    claimed = parent / requested.name
    try:
        claimed.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise RowAlreadyExistsError(f"comparison row already exists: {claimed}") from exc
    native_output = claimed / "native-output"
    native_output.mkdir(mode=0o700, exist_ok=False)
    return claimed, native_output


def _validate_target(target: ExternalTarget, *, instance_id: str, expected_flag: str) -> None:
    if target.instance_id != instance_id:
        raise ExternalComparisonError("target backend returned a different instance_id")
    parsed = urlparse(target.target_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ExternalComparisonError("target backend returned an invalid HTTP(S) URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ExternalComparisonError("target backend returned an invalid HTTP(S) URL")
    provenance = _json_mapping(target.build_provenance)
    serialized = json.dumps(provenance, sort_keys=True)
    if (
        expected_flag in target.target_url
        or expected_flag in unquote(target.target_url)
        or expected_flag in serialized
        or expected_flag in unquote(serialized)
    ):
        raise ExternalComparisonError("target backend exposed expected flag in public metadata")


def _validate_comparison_target_evidence(
    *,
    target: ExternalTarget,
    teardown: Mapping[str, object],
    case: XbenCase,
    agent: ExternalAgentCommand,
    expected_flag: str,
) -> None:
    """Join a prepared target arm to its independently sealed HTTP meter.

    A process sandbox cannot attest how many HTTP requests reached the target.
    Comparison validity therefore requires the concrete prepared-target and
    request-meter validators, not opaque backend booleans.
    """

    from ravage.xben_parts.comparison_target import (
        validate_prepared_target_arm_provenance,
        validate_request_meter_stop_provenance,
    )

    build = _json_mapping(target.build_provenance)
    raw_evidence_dir = build.get("evidence_dir")
    if not isinstance(raw_evidence_dir, str) or not raw_evidence_dir:
        raise ExternalComparisonError("target arm evidence directory is absent")
    evidence_dir = Path(raw_evidence_dir)
    try:
        validated_arm = validate_prepared_target_arm_provenance(
            build,
            evidence_dir=evidence_dir,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExternalComparisonError("prepared target arm evidence is invalid") from exc
    expected_flag_sha256 = hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
    if (
        validated_arm.get("benchmark_id") != case.benchmark_id
        or validated_arm.get("arm") != agent.system_id
        or validated_arm.get("target_url") != target.target_url
        or validated_arm.get("pair_flag_sha256") != expected_flag_sha256
        or validated_arm.get("max_target_requests") != agent.limits.max_target_requests
    ):
        raise ExternalComparisonError("prepared target arm differs from the row contract")

    raw_meter = teardown.get("request_meter")
    try:
        validated_meter = validate_request_meter_stop_provenance(
            raw_meter,
            evidence_dir=evidence_dir,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExternalComparisonError("target request-meter evidence is invalid") from exc
    if (
        validated_meter.get("instance_id") != target.instance_id
        or validated_meter.get("hard_limit") != agent.limits.max_target_requests
        or validated_meter.get("endpoint_mode") != validated_arm.get("gateway_endpoint_mode")
        or teardown.get("removed") is not True
        or teardown.get("verified") is not True
        or teardown.get("project") != validated_arm.get("project")
        or teardown.get("request_count_receipt_path") != validated_meter.get("receipt_path")
        or teardown.get("request_count_receipt_sha256") != validated_meter.get("receipt_sha256")
    ):
        raise ExternalComparisonError("target meter or teardown differs from the row contract")


def _agent_environment(
    agent: ExternalAgentCommand,
    *,
    target_url: str,
    description: str,
    expected_flag: str,
    case: XbenCase,
) -> dict[str, str]:
    environment = {str(key): str(value) for key, value in agent.environment.items()}
    sensitive_values = {
        expected_flag,
        str(case.path.expanduser().resolve()),
        str(case.path.expanduser().resolve().parent),
    }
    for name, value in environment.items():
        if name not in agent.environment_allowlist:
            raise AgentEnvironmentError(f"agent environment name is not allowlisted: {name}")
        if _forbidden_agent_environment_name(name):
            raise AgentEnvironmentError(
                f"benchmark-sensitive environment name is forbidden: {name}"
            )
        for sensitive in sensitive_values:
            if sensitive and sensitive in value:
                raise AgentEnvironmentError(
                    f"agent environment {name} contains evaluator-only benchmark state"
                )
    environment[TARGET_URL_ENV] = target_url
    environment[DESCRIPTION_ENV] = description
    return environment


def _validate_agent_environment_for_case(
    agent: ExternalAgentCommand,
    *,
    case: XbenCase,
) -> None:
    sensitive_paths = {
        str(case.path.expanduser().resolve()),
        str(case.path.expanduser().resolve().parent),
    }
    for name, raw_value in agent.environment.items():
        value = str(raw_value)
        for sensitive in sensitive_paths:
            if sensitive and sensitive in value:
                raise AgentEnvironmentError(
                    f"agent environment {name} contains evaluator-only benchmark state"
                )


def _forbidden_agent_environment_name(name: str) -> bool:
    normalized = name.strip().upper()
    if not normalized:
        return True
    if normalized in {TARGET_URL_ENV, DESCRIPTION_ENV}:
        return True
    if normalized != COMPARISON_GATEWAY_TOKEN_ENV and _ACCOUNT_CREDENTIAL_ENV_RE.search(normalized):
        return True
    return (
        "XBEN" in normalized
        or "BENCHMARK" in normalized
        or "SOURCE_ROOT" in normalized
        or "EXPECTED_FLAG" in normalized
        or normalized == "FLAG"
        or normalized.endswith("_FLAG")
    )


def _sensitive_environment_values(environment: Mapping[str, str]) -> tuple[str, ...]:
    values = {
        str(value)
        for name, value in environment.items()
        if name.strip().upper() == COMPARISON_GATEWAY_TOKEN_ENV
        or _ACCOUNT_CREDENTIAL_ENV_RE.search(name.strip().upper())
        if str(value)
    }
    return tuple(sorted(values, key=len, reverse=True))


def _purge_unsafe_native_output(
    root: Path,
    *,
    sensitive_values: Sequence[str],
) -> str | None:
    """Keep credentials and structurally unsafe agent output out of evidence.

    The outer process backend has already killed its process group before this
    runs. If an agent persisted a row credential (including common reversible
    encodings), a symlink, a hard link, a special file, or an unbounded tree,
    atomically move the entire child-writable tree out of the row and replace it
    with an empty directory. The row remains terminal and aggregatable, but can
    never score or validate.

    This is a publication hygiene gate, not proof against an agent that escapes
    the evaluator process group; strict public claims still require a stronger
    execution attestation.
    """

    variants = _sensitive_byte_variants(sensitive_values)
    unsafe = False
    total_size = 0
    entry_count = 0
    try:
        for path in root.rglob("*"):
            entry_count += 1
            if entry_count > DEFAULT_MAX_EVIDENCE_FILES:
                unsafe = True
                break
            relative = path.relative_to(root).as_posix().encode("utf-8", errors="surrogateescape")
            if any(value in relative for value in variants):
                unsafe = True
                break
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                unsafe = True
                break
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size < 0
                or metadata.st_size > DEFAULT_MAX_EVIDENCE_FILE_BYTES
            ):
                unsafe = True
                break
            total_size += metadata.st_size
            if total_size > DEFAULT_MAX_EVIDENCE_TOTAL_BYTES:
                unsafe = True
                break
            body = _read_bounded_regular_file(
                path,
                maximum_bytes=DEFAULT_MAX_EVIDENCE_FILE_BYTES,
            )
            if any(value in body for value in variants):
                unsafe = True
                break
    except (OSError, RuntimeError, UnicodeError, ExternalComparisonError):
        unsafe = True
    if not unsafe:
        return None

    row_dir = root.parent
    quarantine = row_dir.parent / f".{row_dir.name}.discard-{secrets.token_hex(16)}"
    try:
        root.rename(quarantine)
        root.mkdir(mode=0o700, exist_ok=False)
        shutil.rmtree(quarantine)
    except OSError as exc:
        raise ExternalComparisonError(
            "unsafe agent output could not be removed from publication evidence"
        ) from exc
    return "agent output contained sensitive or structurally unsafe retained evidence"


def _sensitive_byte_variants(sensitive_values: Sequence[str]) -> tuple[bytes, ...]:
    return tuple(variant.encode("utf-8") for variant in _sensitive_text_variants(sensitive_values))


def _sensitive_text_variants(sensitive_values: Sequence[str]) -> tuple[str, ...]:
    variants: set[str] = set()
    for value in sensitive_values:
        if not value:
            continue
        raw = value.encode("utf-8")
        variants.update(
            {
                value,
                quote(value, safe=""),
                quote_plus(value, safe=""),
                raw.hex(),
                raw.hex().upper(),
                base64.b64encode(raw).decode("ascii"),
                base64.urlsafe_b64encode(raw).decode("ascii"),
                base64.b64encode(raw).rstrip(b"=").decode("ascii"),
                base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
            }
        )
    return tuple(sorted((item for item in variants if item), key=len, reverse=True))


def _redact_text(value: str | None, *, sensitive_values: Sequence[str]) -> str | None:
    if value is None:
        return None
    redacted = value
    for variant in _sensitive_text_variants(sensitive_values):
        redacted = redacted.replace(variant, "[REDACTED]")
    return redacted


def _redacted_bounded_text(
    value: str | None,
    *,
    sensitive_values: Sequence[str],
) -> str | None:
    """Redact complete secrets before bounding retained diagnostic text."""

    redacted = _redact_text(value, sensitive_values=sensitive_values)
    if redacted is None:
        return None
    return redacted[:2_000]


def _redacted_bounded_error(
    exc: BaseException,
    *,
    sensitive_values: Sequence[str],
) -> str:
    text = str(exc).strip() or type(exc).__name__
    return _redacted_bounded_text(text, sensitive_values=sensitive_values) or type(exc).__name__


def _sanitized_bounded_log(
    value: str,
    *,
    sensitive_values: Sequence[str],
    maximum_bytes: int,
) -> tuple[str, dict[str, object]]:
    raw = value.encode("utf-8", errors="replace")
    sanitized = _redact_text(value, sensitive_values=sensitive_values) or ""
    encoded = sanitized.encode("utf-8", errors="replace")
    truncated = len(encoded) > maximum_bytes
    if truncated:
        marker = b"\n[TRUNCATED BY EVALUATOR]\n"
        prefix_length = max(0, maximum_bytes - len(marker))
        prefix = encoded[:prefix_length].decode("utf-8", errors="ignore")
        suffix = marker[: maximum_bytes - len(prefix.encode("utf-8"))].decode("ascii")
        sanitized = prefix + suffix
        encoded = sanitized.encode("utf-8")
    return sanitized, {
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_size_bytes": len(raw),
        "retained_size_bytes": len(encoded),
        "redacted": any(variant in value for variant in _sensitive_text_variants(sensitive_values)),
        "truncated": truncated,
        "max_retained_bytes": maximum_bytes,
    }


def _empty_capture_record() -> dict[str, object]:
    return {
        "raw_sha256": hashlib.sha256(b"").hexdigest(),
        "raw_size_bytes": 0,
        "retained_size_bytes": 0,
        "redacted": False,
        "truncated": False,
        "max_retained_bytes": DEFAULT_MAX_LOG_BYTES,
    }


def _score_declared_artifact(
    *,
    native_output_dir: Path,
    artifact_path: str,
    expected_flag: str,
    max_artifact_bytes: int,
) -> dict[str, object]:
    relative = _artifact_relative_path(artifact_path)
    path = native_output_dir / relative
    record: dict[str, object] = {
        "path": relative.as_posix(),
        "status": "missing",
        "sha256": None,
        "size_bytes": None,
        "exact_match": False,
    }
    if path.is_symlink():
        record["status"] = "invalid_symlink"
        return record
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return record
    try:
        resolved.relative_to(native_output_dir.resolve())
    except ValueError:
        record["status"] = "invalid_escape"
        return record
    if not resolved.is_file():
        record["status"] = "invalid_not_file"
        return record
    size = resolved.stat().st_size
    record["size_bytes"] = size
    if size > max_artifact_bytes:
        record["status"] = "invalid_too_large"
        return record
    try:
        content = _read_bounded_regular_file(
            resolved,
            maximum_bytes=max_artifact_bytes,
        )
    except ExternalComparisonError:
        record["status"] = "invalid_changed_or_unreadable"
        return record
    expected_digest = hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
    candidate_digest_set: set[str] = set()
    for match in re.finditer(rb"flag\{[^\r\n\x00]{1,4096}\}", content):
        candidate_digest_set.add(hashlib.sha256(match.group(0)).hexdigest())
        if len(candidate_digest_set) > DEFAULT_MAX_FLAG_CANDIDATES:
            record.update(
                {
                    "status": "invalid_too_many_candidates",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "candidate_count": len(candidate_digest_set),
                }
            )
            return record
    candidate_digests = sorted(candidate_digest_set)
    record.update(
        {
            "status": "scored",
            "sha256": hashlib.sha256(content).hexdigest(),
            "candidate_count": len(candidate_digests),
            "candidate_sha256": candidate_digests,
            "exact_match": expected_digest in candidate_digests,
        }
    )
    return record


def _artifact_relative_path(value: str) -> Path:
    text = value.strip()
    path = Path(text)
    if (
        not text
        or len(text.encode("utf-8")) > 1024
        or "\\" in text
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
        or path.is_absolute()
        or path == Path(".")
        or ".." in path.parts
    ):
        raise ValueError("artifact_path must be a contained relative file path")
    if path.parts[0] in _RESERVED_EVIDENCE_NAMES:
        raise ValueError("artifact_path collides with evaluator-owned evidence")
    return path


def _row_status(
    *,
    solved: bool,
    target_ready: bool,
    teardown_complete: bool,
    artifact_valid: bool,
    execution_status: str,
) -> str:
    if not target_ready or not teardown_complete:
        return "infrastructure_error"
    if solved:
        return "solved"
    if execution_status == "timed_out":
        return "timed_out"
    if execution_status == "errored":
        return "errored"
    if not artifact_valid:
        return "failed"
    return "failed"


def _command_sha256(command: Sequence[str]) -> str:
    payload = json.dumps(list(command), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _json_mapping(value: Mapping[str, object]) -> dict[str, object]:
    copied = dict(value)
    try:
        serialized = json.dumps(copied, sort_keys=True)
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise ExternalComparisonError("backend provenance must be JSON serializable") from exc
    if len(serialized.encode("utf-8")) > DEFAULT_MAX_PROVENANCE_BYTES:
        raise ExternalComparisonError("backend provenance exceeds its fixed byte limit")
    loaded = json.loads(serialized)
    if not isinstance(loaded, dict):
        raise ExternalComparisonError("backend provenance must be a JSON object")
    return loaded


def _write_json_exclusive(path: Path, payload: Mapping[str, object]) -> None:
    _write_text_exclusive(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_text_exclusive(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = value.encode("utf-8")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ExternalComparisonError(f"refusing to replace row evidence: {path}") from exc
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("row evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        with contextlib.suppress(OSError):
            path.unlink()
        raise
    finally:
        os.close(descriptor)


def _write_manifest_exclusive(row_dir: Path) -> Path:
    manifest_path = row_dir / "artifacts.sha256"
    files: list[tuple[Path, int, int, int]] = []
    total_size = 0
    entry_count = 0
    for path in row_dir.rglob("*"):
        entry_count += 1
        if entry_count > DEFAULT_MAX_EVIDENCE_FILES:
            raise ExternalComparisonError("row evidence contains too many entries")
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ExternalComparisonError("row evidence contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ExternalComparisonError("row evidence contains a non-regular entry")
        if metadata.st_nlink != 1:
            raise ExternalComparisonError("row evidence contains a multiply-linked file")
        size = metadata.st_size
        if size < 0 or size > DEFAULT_MAX_EVIDENCE_FILE_BYTES:
            raise ExternalComparisonError("row evidence file exceeds its fixed bound")
        total_size += size
        if total_size > DEFAULT_MAX_EVIDENCE_TOTAL_BYTES:
            raise ExternalComparisonError("row evidence exceeds its fixed total bound")
        relative_text = path.relative_to(row_dir).as_posix()
        if (
            len(relative_text.encode("utf-8")) > 1024
            or "\\" in relative_text
            or any(ord(character) < 32 or ord(character) == 127 for character in relative_text)
        ):
            raise ExternalComparisonError("row evidence path is not manifest-safe")
        files.append((path, size, metadata.st_dev, metadata.st_ino))
    rows: list[str] = []
    for path, expected_size, expected_device, expected_inode in sorted(files):
        if path == manifest_path:
            continue
        digest = hashlib.sha256()
        observed_size = 0
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size != expected_size
                or opened.st_dev != expected_device
                or opened.st_ino != expected_inode
            ):
                raise ExternalComparisonError("row evidence changed before hashing")
            while chunk := handle.read(64 * 1024):
                observed_size += len(chunk)
                if observed_size > expected_size:
                    raise ExternalComparisonError("row evidence changed while hashing")
                digest.update(chunk)
            completed = os.fstat(handle.fileno())
        if (
            observed_size != expected_size
            or completed.st_size != expected_size
            or completed.st_nlink != 1
            or completed.st_dev != expected_device
            or completed.st_ino != expected_inode
        ):
            raise ExternalComparisonError("row evidence changed while hashing")
        rows.append(f"{digest.hexdigest()}  {path.relative_to(row_dir)}")
    _write_text_exclusive(manifest_path, "\n".join(rows) + ("\n" if rows else ""))
    return manifest_path


def _read_bounded_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    if maximum_bytes <= 0:
        raise ValueError("file byte limit must be positive")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ExternalComparisonError(f"row evidence is missing: {path.name}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ExternalComparisonError(f"row evidence cannot be a symlink: {path.name}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 0
        or metadata.st_size > maximum_bytes
    ):
        raise ExternalComparisonError(f"row evidence is not a bounded file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExternalComparisonError(f"row evidence is unreadable: {path.name}") from exc
    chunks: list[bytes] = []
    observed_size = 0
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            raise ExternalComparisonError(f"row evidence changed before reading: {path.name}")
        while chunk := handle.read(min(64 * 1024, maximum_bytes + 1 - observed_size)):
            observed_size += len(chunk)
            if observed_size > maximum_bytes:
                raise ExternalComparisonError(f"row evidence exceeded its bound: {path.name}")
            chunks.append(chunk)
        completed = os.fstat(handle.fileno())
    if (
        observed_size != metadata.st_size
        or completed.st_dev != metadata.st_dev
        or completed.st_nlink != 1
        or completed.st_ino != metadata.st_ino
        or completed.st_size != metadata.st_size
    ):
        raise ExternalComparisonError(f"row evidence changed while reading: {path.name}")
    return b"".join(chunks)


def _sha256_file_prefixed(path: Path) -> str:
    body = _read_bounded_regular_file(path, maximum_bytes=8 * 1024 * 1024)
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _stream_text(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _now() -> str:
    return datetime.now(UTC).isoformat()
