"""Evaluator-owned process containment and receipts for paired XBEN rows.

This backend deliberately has two evidence classes.  ``strict_official`` is
available only when the outer process can be confined to an evaluator-owned
output directory and exact loopback gateway ports without exposing a Docker
socket.  ``paired_local`` permits the pinned orchestrator to control Docker,
but records that the Docker daemon and host are trusted and can never claim an
official or cryptographically attested isolation boundary.

``sandbox-exec`` is deprecated and is not available on every macOS host.  The
backend probes the exact generated profile before launching the agent and
fails closed, while still writing terminal evidence, when the profile cannot
be applied.  No non-macOS fallback is labelled isolated.

The hard deadline tears down the evaluator-created process group.  macOS does
not provide a cgroup/job-object equivalent here, so a descendant that
deliberately creates a new session can escape that group.  Consequently the
receipt is only *eligible* for a later public execution attestation; it is not
itself cryptographic proof of whole-machine containment.  Docker descendants
in ``paired_local`` are an even broader trusted-host boundary and are never
official-eligible.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal
from urllib.parse import urlparse

from ravage.xben_parts.comparison_contracts import ComparisonContractError
from ravage.xben_parts.comparison_model_gateway import (
    ComparisonModelGateway,
    validate_model_gateway_receipt,
)
from ravage.xben_parts.external_comparison import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    OUTER_PROCESS_GROUP_ENV,
    OUTER_PROCESS_GROUP_VALUE,
    TARGET_URL_ENV,
    ExternalExecutionLimits,
    ExternalProcessReceiptContract,
    ExternalProcessResult,
    ProcessIsolation,
)

PROCESS_RECEIPT_SCHEMA_VERSION: Final = "ravage.xben.comparison-process-receipt.v2"
PROCESS_RECEIPT_FILE: Final = "process-receipt.json"
MODEL_GATEWAY_RECEIPT_FILE: Final = "model-gateway-receipt.json"
SANDBOX_PROFILE_FILE: Final = "sandbox-profile.sb"
GATEWAY_BASE_URL_ENV: Final = "RAVAGE_COMPARISON_GATEWAY_BASE_URL"

STRICT_OFFICIAL: Final = "strict_official"
PAIRED_LOCAL: Final = "paired_local"
EvidenceClass = Literal["strict_official", "paired_local"]

DEFAULT_MAX_CAPTURE_BYTES: Final = 1024 * 1024
DEFAULT_TERMINATION_GRACE_SECONDS: Final = 5.0
DEFAULT_MODEL_GATEWAY_DRAIN_TIMEOUT_SECONDS: Final = 5.0
DEFAULT_SANDBOX_PROBE_TIMEOUT_SECONDS: Final = 5.0
MAX_RECEIPT_BYTES: Final = 8 * 1024 * 1024
MAX_HASHED_FILE_BYTES: Final = 2 * 1024 * 1024 * 1024
MAX_COMMAND_ARGUMENTS: Final = 1024
MAX_COMMAND_BYTES: Final = 1024 * 1024
MAX_ENVIRONMENT_ENTRIES: Final = 128
MAX_ENVIRONMENT_BYTES: Final = 1024 * 1024
MAX_RUNTIME_READ_ROOTS: Final = 128

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_ROW_ID_RE = re.compile(r"primary-(?:00[1-9]|0[1-9][0-9]|[1-9][0-9]{2})")
_SAFE_ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_SYSTEM_READ_ROOTS = (
    Path("/System"),
    Path("/usr/bin"),
    Path("/usr/lib"),
    Path("/bin"),
    Path("/sbin"),
    Path("/Library/Apple"),
    Path("/private/var/db/timezone"),
)
_SYSTEM_READ_FILES = (Path("/dev/null"), Path("/dev/random"), Path("/dev/urandom"))
_SANDBOX_PROCESS_RULES = (
    # The adapter must be able to exec and supervise its pinned child, but it
    # must not receive the broad ``process*`` or unfiltered ``signal`` grants:
    # those permit inspection/signalling of unrelated evaluator processes.
    "(allow process-fork)",
    "(allow process-exec*)",
    "(allow process-info* (target self))",
    "(allow signal (target self))",
    "(allow signal (target children))",
)


class ComparisonProcessError(RuntimeError):
    """Raised when process evidence is missing, malformed, or unsafe."""


@dataclass(frozen=True)
class _Capture:
    retained: bytes
    total_bytes: int
    sha256: str
    complete: bool

    @property
    def truncated(self) -> bool:
        return self.total_bytes > len(self.retained)


class _BoundedCollector:
    def __init__(self, maximum_bytes: int) -> None:
        self.maximum_bytes = maximum_bytes
        self.retained = bytearray()
        self.total_bytes = 0
        self.digest = hashlib.sha256()
        self.complete = True

    def drain(self, stream: object) -> None:
        try:
            reader = getattr(stream, "read")
            while True:
                chunk = reader(64 * 1024)
                if not chunk:
                    return
                if not isinstance(chunk, bytes):
                    self.complete = False
                    return
                self.total_bytes += len(chunk)
                self.digest.update(chunk)
                remaining = self.maximum_bytes - len(self.retained)
                if remaining > 0:
                    self.retained.extend(chunk[:remaining])
        except OSError:
            self.complete = False
        finally:
            with contextlib.suppress(OSError):
                getattr(stream, "close")()

    def result(self) -> _Capture:
        return _Capture(
            retained=bytes(self.retained),
            total_bytes=self.total_bytes,
            sha256="sha256:" + self.digest.hexdigest(),
            complete=self.complete,
        )


@dataclass
class ComparisonProcessBackend:
    """Run one registered model-gateway row under an outer macOS sandbox.

    The gateway must already be running and ``row_id`` must already have been
    registered.  The row-scoped token and base URL in the adapter environment
    are cross-checked against the sealed gateway receipt.
    """

    gateway: ComparisonModelGateway
    row_id: str
    expected_policy_sha256: str
    expected_row_token_sha256: str
    sandbox_exec_sha256: str
    runtime_read_roots: tuple[Path, ...]
    evidence_class: EvidenceClass = STRICT_OFFICIAL
    allow_docker_socket: bool = False
    sandbox_exec_path: Path = Path("/usr/bin/sandbox-exec")
    docker_socket_path: Path = Path("/var/run/docker.sock")
    maximum_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    termination_grace_seconds: float = DEFAULT_TERMINATION_GRACE_SECONDS
    sandbox_probe_timeout_seconds: float = DEFAULT_SANDBOX_PROBE_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if _ROW_ID_RE.fullmatch(self.row_id) is None:
            raise ValueError("comparison process row_id is invalid")
        _sha256_digest(self.expected_policy_sha256, "model gateway policy digest")
        _sha256_digest(self.expected_row_token_sha256, "model gateway row-token digest")
        _sha256_digest(self.sandbox_exec_sha256, "sandbox-exec digest")
        if self.expected_policy_sha256 != self.gateway.policy_digest:
            raise ValueError("model gateway policy does not match its frozen digest")
        if self.evidence_class not in {STRICT_OFFICIAL, PAIRED_LOCAL}:
            raise ValueError("comparison process evidence class is invalid")
        if self.evidence_class == STRICT_OFFICIAL and self.allow_docker_socket:
            raise ValueError("strict official isolation cannot expose a Docker socket")
        if self.evidence_class == PAIRED_LOCAL and not self.allow_docker_socket:
            raise ValueError("paired-local mode must explicitly record Docker socket access")
        if (
            isinstance(self.maximum_capture_bytes, bool)
            or not isinstance(self.maximum_capture_bytes, int)
            or not 0 < self.maximum_capture_bytes <= DEFAULT_MAX_CAPTURE_BYTES
        ):
            raise ValueError("maximum process capture bytes exceed the fixed bound")
        if len(self.runtime_read_roots) > MAX_RUNTIME_READ_ROOTS:
            raise ValueError("comparison runtime read-root count exceeds its fixed bound")
        for value, label in (
            (self.termination_grace_seconds, "termination grace"),
            (self.sandbox_probe_timeout_seconds, "sandbox probe timeout"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 < value <= 30
            ):
                raise ValueError(f"{label} must be finite and between zero and 30 seconds")
        _resolved_read_roots(self.runtime_read_roots)

    @property
    def model_gateway_policy_sha256(self) -> str:
        return self.expected_policy_sha256

    @property
    def sandbox_executable_sha256(self) -> str:
        return self.sandbox_exec_sha256

    @property
    def receipt_contract(self) -> ExternalProcessReceiptContract:
        return ExternalProcessReceiptContract(
            row_id=self.row_id,
            model_gateway_policy_sha256=self.expected_policy_sha256,
            model_gateway_row_token_sha256=self.expected_row_token_sha256,
            sandbox_executable_sha256=self.sandbox_exec_sha256,
            runtime_read_roots=self.runtime_read_roots,
            evidence_class=self.evidence_class,
            docker_socket_path=self.docker_socket_path if self.allow_docker_socket else None,
        )

    @property
    def isolation(self) -> ProcessIsolation:
        strict = self.evidence_class == STRICT_OFFICIAL and not self.allow_docker_socket
        return ProcessIsolation(
            kind=(
                "macos-sandbox-exec-strict" if strict else "macos-sandbox-exec-trusted-host-docker"
            ),
            # Docker-created descendants are outside sandbox-exec's filesystem
            # boundary, so paired-local must not claim end-to-end isolation.
            filesystem_isolated=strict,
            target_network_only=strict,
            inherits_parent_environment=False,
            wall_timeout_enforced=True,
            model_request_limit_enforced=True,
            # Target requests are enforced and attested by the separate HTTP
            # meter/target backend. A process sandbox cannot truthfully claim
            # that capability on its own; external_comparison joins the two
            # receipts before declaring a row comparable.
            target_request_limit_enforced=False,
            cost_limit_enforced=True,
        )

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: ExternalExecutionLimits,
    ) -> ExternalProcessResult:
        """Run exactly one command and terminally seal both evaluator receipts."""

        output_dir, row_dir = _validated_output_directory(cwd)
        profile_path = row_dir / SANDBOX_PROFILE_FILE
        started_at = _now()
        started_monotonic = time.monotonic()
        deadline = started_monotonic + float(limits.wall_seconds)
        argv = tuple(command)
        clean_environment: dict[str, str] = {}
        network_rules: tuple[tuple[str, int], ...] = ()
        sandbox_path = self.sandbox_exec_path.expanduser().resolve(strict=False)
        read_roots: tuple[Path, ...] = ()
        executable_sha256: str | None = None
        docker_socket: Path | None = None
        profile = b""
        returncode = -1
        timed_out = False
        spawn_succeeded = False
        profile_probe_succeeded = False
        process_group_created = False
        process_group_teardown_complete = False
        process: subprocess.Popen[bytes] | None = None
        execution_error: str | None = None
        stdout = _Capture(b"", 0, _sha256_bytes(b""), True)
        stderr = _Capture(b"", 0, _sha256_bytes(b""), True)
        model_receipt: dict[str, object] | None = None
        model_receipt_error: str | None = None
        model_receipt_valid = False
        model_path = row_dir / MODEL_GATEWAY_RECEIPT_FILE

        try:
            argv = _validated_command(command)
            executable_sha256 = _command_executable_sha256(Path(argv[0]))
            if executable_sha256 is None:
                raise ComparisonProcessError("comparison process executable cannot be hashed")
            clean_environment = _validated_environment(environment)
            if (
                _sha256_bytes(clean_environment[COMPARISON_GATEWAY_TOKEN_ENV].encode("utf-8"))
                != self.expected_row_token_sha256
            ):
                raise ComparisonProcessError(
                    "model gateway token differs from the frozen row binding"
                )
            network_rules = _network_rules(
                clean_environment,
                evidence_class=self.evidence_class,
            )
            sandbox_path = _verified_sandbox_executable(
                self.sandbox_exec_path,
                expected_sha256=self.sandbox_exec_sha256,
            )
            read_roots = _resolved_read_roots(
                (*self.runtime_read_roots, *_command_runtime_paths(Path(argv[0])))
            )
            _validate_campaign_read_separation(
                read_roots,
                campaign_evidence_root=row_dir.parent,
            )
            docker_socket = _resolved_docker_socket(
                self.docker_socket_path,
                required=self.allow_docker_socket,
            )
            profile = _sandbox_profile(
                output_dir=output_dir,
                read_roots=read_roots,
                network_rules=network_rules,
                docker_socket=docker_socket,
            )
            _write_exclusive(profile_path, profile)
            probe_remaining = _remaining_seconds(deadline)
            if probe_remaining <= 0:
                timed_out = True
                raise ComparisonProcessError("sandbox preparation exhausted the wall deadline")
            profile_probe_succeeded = _probe_sandbox_profile(
                sandbox_path,
                profile_path,
                timeout_seconds=min(
                    self.sandbox_probe_timeout_seconds,
                    probe_remaining,
                ),
            )
            if not profile_probe_succeeded:
                raise ComparisonProcessError("sandbox-exec rejected the generated profile")
            launch = (str(sandbox_path), "-f", str(profile_path), *argv)
            process = subprocess.Popen(  # noqa: S603 - explicit argv, never a shell.
                launch,
                cwd=output_dir,
                env=clean_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
            spawn_succeeded = True
            process_group_created = True
            remaining = _remaining_seconds(deadline)
            if remaining <= 0:
                timed_out = True
                _terminate_process_group(
                    process,
                    grace_seconds=self.termination_grace_seconds,
                )
                raise ComparisonProcessError("outer process exhausted its wall deadline")
            stdout, stderr, timed_out = _wait_bounded_process(
                process,
                timeout_seconds=remaining,
                maximum_capture_bytes=self.maximum_capture_bytes,
                termination_grace_seconds=self.termination_grace_seconds,
            )
            returncode = process.returncode if process.returncode is not None else -1
            if _command_executable_sha256(Path(argv[0])) != executable_sha256:
                execution_error = "comparison process executable changed during execution"
            process_group_teardown_complete = _process_group_absent(process.pid)
            if not process_group_teardown_complete:
                execution_error = "outer process group remained after terminal teardown"
        except Exception as exc:  # noqa: BLE001 - every launch failure becomes terminal evidence.
            execution_error = _bounded_error(exc)
        finally:
            if process is not None:
                try:
                    _terminate_process_group(
                        process,
                        grace_seconds=self.termination_grace_seconds,
                    )
                except Exception as exc:  # noqa: BLE001 - teardown failure invalidates the row.
                    teardown_error = _bounded_error(exc)
                    execution_error = (
                        f"{execution_error}; {teardown_error}"
                        if execution_error
                        else teardown_error
                    )
                process_group_teardown_complete = _process_group_absent(process.pid)
            if not profile_path.exists():
                try:
                    _write_exclusive(profile_path, profile)
                except Exception as exc:  # noqa: BLE001 - model sealing must still happen.
                    profile_error = _bounded_error(exc)
                    execution_error = (
                        f"{execution_error}; {profile_error}" if execution_error else profile_error
                    )
            try:
                raw_receipt = self.gateway.close_row_and_seal(
                    self.row_id,
                    model_path,
                    drain_timeout_seconds=DEFAULT_MODEL_GATEWAY_DRAIN_TIMEOUT_SECONDS,
                )
                model_receipt = validate_model_gateway_receipt(
                    raw_receipt,
                    expected_row_id=self.row_id,
                    expected_policy_sha256=self.expected_policy_sha256,
                    expected_max_requests=limits.max_model_requests,
                    expected_max_cost_usd=limits.max_cost_usd,
                )
                token = clean_environment.get(COMPARISON_GATEWAY_TOKEN_ENV, "")
                token_digest = _sha256_bytes(token.encode("utf-8"))
                if (
                    token_digest != self.expected_row_token_sha256
                    or model_receipt.get("row_token_sha256") != token_digest
                ):
                    raise ComparisonProcessError(
                        "model receipt token does not match the row environment"
                    )
                model_receipt_valid = model_receipt.get("valid") is True
            except Exception as exc:  # noqa: BLE001 - sealing failures remain evidence.
                model_receipt_error = _bounded_error(exc)

        completed_at = _now()
        elapsed_seconds = round(max(0.0, time.monotonic() - started_monotonic), 6)
        model_file_digest = _sha256_regular_file(model_path)
        model_document_digest = (
            str(model_receipt.get("document_sha256")) if model_receipt is not None else None
        )
        strict = self.evidence_class == STRICT_OFFICIAL
        # ``valid`` records whether the terminal observation is independently
        # usable evidence, not whether the agent exited successfully.  A
        # budget-enforced timeout or a nonzero agent exit is a real benchmark
        # loss when the process group is gone and every evaluator receipt was
        # sealed intact.  Keep those outcomes distinct from containment or
        # receipt failures so a losing row cannot be discarded and rerun.
        official_eligible = bool(
            strict
            and not self.allow_docker_socket
            and profile_probe_succeeded
            and spawn_succeeded
            and process_group_teardown_complete
        )
        receipt_valid = bool(
            profile_probe_succeeded
            and spawn_succeeded
            and process_group_created
            and process_group_teardown_complete
            and (not timed_out or returncode != 0)
            and stdout.complete
            and stderr.complete
            and model_receipt_valid
            and model_file_digest is not None
            and execution_error is None
        )
        receipt = _process_receipt(
            row_id=self.row_id,
            evidence_class=self.evidence_class,
            argv=argv,
            executable_sha256=executable_sha256,
            environment=clean_environment,
            limits=limits,
            sandbox_path=sandbox_path,
            profile=profile,
            read_roots=read_roots,
            network_rules=network_rules,
            docker_socket=docker_socket,
            profile_probe_succeeded=profile_probe_succeeded,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_seconds=elapsed_seconds,
            returncode=returncode,
            timed_out=timed_out,
            spawn_succeeded=spawn_succeeded,
            process_group_created=process_group_created,
            process_group_teardown_complete=process_group_teardown_complete,
            stdout=stdout,
            stderr=stderr,
            maximum_capture_bytes=self.maximum_capture_bytes,
            execution_error=execution_error,
            model_file_digest=model_file_digest,
            model_document_digest=model_document_digest,
            expected_policy_sha256=self.expected_policy_sha256,
            model_receipt_valid=model_receipt_valid,
            model_receipt_error=model_receipt_error,
            official_eligible=official_eligible,
            receipt_valid=receipt_valid,
        )
        process_path = row_dir / PROCESS_RECEIPT_FILE
        _write_exclusive(process_path, _canonical_json(receipt) + b"\n")
        return ExternalProcessResult(
            returncode=returncode,
            stdout=stdout.retained.decode("utf-8", errors="replace"),
            stderr=stderr.retained.decode("utf-8", errors="replace"),
            timed_out=timed_out,
            process_receipt_path=PROCESS_RECEIPT_FILE,
            model_gateway_receipt_path=(
                MODEL_GATEWAY_RECEIPT_FILE if model_file_digest is not None else None
            ),
            sandbox_profile_path=SANDBOX_PROFILE_FILE,
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
        """Terminally seal a registered row whose agent could not be started."""

        output_dir, row_dir = _validated_output_directory(cwd)
        del output_dir
        started_at = _now()
        raw_argv = tuple(command)
        try:
            argv = _validated_command(command)
        except ComparisonProcessError:
            argv = raw_argv
        clean_environment = {
            name: value
            for name, value in environment.items()
            if isinstance(name, str)
            and isinstance(value, str)
            and _SAFE_ENVIRONMENT_NAME_RE.fullmatch(name) is not None
            and "\x00" not in value
        }
        sandbox_path = self.sandbox_exec_path.expanduser().resolve(strict=False)
        try:
            read_roots = _resolved_read_roots(
                (*self.runtime_read_roots, *_command_runtime_paths(Path(argv[0])))
            )
        except (ComparisonProcessError, IndexError):
            read_roots = ()
        profile = b""
        profile_path = row_dir / SANDBOX_PROFILE_FILE
        evidence_error: str | None = None
        try:
            _write_exclusive(profile_path, profile)
        except Exception as exc:  # noqa: BLE001 - the model ledger must still be sealed.
            evidence_error = _bounded_error(exc)
        model_path = row_dir / MODEL_GATEWAY_RECEIPT_FILE
        model_receipt, model_error, model_valid = _seal_model_gateway_receipt(
            gateway=self.gateway,
            row_id=self.row_id,
            output_path=model_path,
            expected_policy_sha256=self.expected_policy_sha256,
            expected_row_token_sha256=self.expected_row_token_sha256,
            limits=limits,
            environment=clean_environment,
        )
        model_file_digest = _sha256_regular_file(model_path)
        model_document_digest = (
            str(model_receipt.get("document_sha256")) if model_receipt is not None else None
        )
        completed_at = _now()
        empty = _Capture(b"", 0, _sha256_bytes(b""), True)
        receipt = _process_receipt(
            row_id=self.row_id,
            evidence_class=self.evidence_class,
            argv=argv,
            executable_sha256=(_command_executable_sha256(Path(argv[0])) if argv else None),
            environment=clean_environment,
            limits=limits,
            sandbox_path=sandbox_path,
            profile=profile,
            read_roots=read_roots,
            network_rules=(),
            docker_socket=None,
            profile_probe_succeeded=False,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_seconds=0.0,
            returncode=-1,
            timed_out=False,
            spawn_succeeded=False,
            process_group_created=False,
            process_group_teardown_complete=True,
            stdout=empty,
            stderr=empty,
            maximum_capture_bytes=self.maximum_capture_bytes,
            execution_error=(
                (
                    f"{reason.strip() or 'agent process was not started'}; {evidence_error}"
                    if evidence_error
                    else reason.strip() or "agent process was not started"
                )[:2000]
            ),
            model_file_digest=model_file_digest,
            model_document_digest=model_document_digest,
            expected_policy_sha256=self.expected_policy_sha256,
            model_receipt_valid=model_valid,
            model_receipt_error=model_error,
            official_eligible=False,
            receipt_valid=False,
        )
        _write_exclusive(row_dir / PROCESS_RECEIPT_FILE, _canonical_json(receipt) + b"\n")
        return ExternalProcessResult(
            returncode=-1,
            process_receipt_path=PROCESS_RECEIPT_FILE,
            model_gateway_receipt_path=(
                MODEL_GATEWAY_RECEIPT_FILE if model_file_digest is not None else None
            ),
            sandbox_profile_path=SANDBOX_PROFILE_FILE,
        )


def validate_comparison_process_receipt(  # noqa: C901, PLR0913, PLR0915
    payload: object,
    *,
    expected_row_id: str,
    expected_command: Sequence[str],
    expected_environment: Mapping[str, str],
    expected_limits: ExternalExecutionLimits,
    expected_policy_sha256: str,
    expected_sandbox_exec_sha256: str,
    expected_runtime_read_roots: Sequence[Path],
    expected_output_directory: Path,
    expected_docker_socket_path: Path | None,
    model_receipt_file_sha256: str,
    model_receipt_document_sha256: str,
    sandbox_profile: bytes,
    require_official_safety: bool,
) -> dict[str, object]:
    """Recompute all portable process-receipt bindings.

    This is intentionally independent of ``ProcessIsolation`` declarations.
    Live host properties are recorded by the evaluator; offline validation can
    bind them but cannot turn a trusted-host/Docker run into official evidence.
    """

    if not isinstance(payload, dict):
        raise ComparisonProcessError("comparison process receipt must be an object")
    required = {
        "schema_version",
        "created_at",
        "row_id",
        "evidence_class",
        "command",
        "environment",
        "cwd",
        "limits",
        "sandbox",
        "execution",
        "model_gateway",
        "official_attestation_eligible",
        "valid",
        "document_sha256",
    }
    if set(payload) != required or payload.get("schema_version") != PROCESS_RECEIPT_SCHEMA_VERSION:
        raise ComparisonProcessError("comparison process receipt fields are invalid")
    body = {key: value for key, value in payload.items() if key != "document_sha256"}
    if payload.get("document_sha256") != _sha256_bytes(_canonical_json(body)):
        raise ComparisonProcessError("comparison process receipt document digest is invalid")
    _timestamp(payload.get("created_at"), "receipt creation time")
    if payload.get("row_id") != expected_row_id or _ROW_ID_RE.fullmatch(expected_row_id) is None:
        raise ComparisonProcessError("comparison process row binding is invalid")

    evidence_class = payload.get("evidence_class")
    if evidence_class not in {STRICT_OFFICIAL, PAIRED_LOCAL}:
        raise ComparisonProcessError("comparison process evidence class is invalid")
    command = _mapping(payload.get("command"), "command")
    argv = _validated_command(expected_command)
    expected_command_record = {
        "argv_sha256": _sha256_bytes(_canonical_json(list(argv))),
        "argument_count": len(argv),
        "shell": False,
        "executable_sha256": _command_executable_sha256(Path(argv[0])),
    }
    if command != expected_command_record:
        raise ComparisonProcessError("comparison process command binding is invalid")
    clean_environment = _validated_environment(expected_environment)
    expected_environment_record = {
        "inherits_parent": False,
        "names": sorted(clean_environment),
        "value_sha256": {
            name: _sha256_bytes(value.encode("utf-8"))
            for name, value in sorted(clean_environment.items())
        },
        "contract_sha256": _sha256_bytes(_canonical_json(clean_environment)),
    }
    if _mapping(payload.get("environment"), "environment") != expected_environment_record:
        raise ComparisonProcessError("comparison process environment binding is invalid")
    if payload.get("cwd") != {"mode": "row_native_output", "relative_path": "native-output"}:
        raise ComparisonProcessError("comparison process cwd binding is invalid")
    if _validated_limits_payload(payload.get("limits")) != expected_limits.to_json():
        raise ComparisonProcessError("comparison process limits binding is invalid")

    sandbox = _mapping(payload.get("sandbox"), "sandbox")
    sandbox_fields = {
        "platform",
        "backend",
        "executable_path",
        "executable_sha256",
        "executable_root_owned",
        "executable_mode_safe",
        "profile_path",
        "profile_sha256",
        "profile_probe_succeeded",
        "filesystem_policy",
        "network_policy",
        "outbound_tcp",
        "runtime_read_roots",
        "runtime_read_roots_sha256",
        "runtime_read_root_count",
        "docker_socket_access",
        "docker_socket_path",
        "trusted_host_required",
        "network_scope_verified",
    }
    if set(sandbox) != sandbox_fields:
        raise ComparisonProcessError("comparison process sandbox fields are invalid")
    sandbox_executable_path = sandbox.get("executable_path")
    if not isinstance(sandbox_executable_path, str):
        raise ComparisonProcessError("comparison process sandbox executable path is invalid")
    verified_sandbox_executable = _verified_sandbox_executable(
        Path(sandbox_executable_path),
        expected_sha256=expected_sandbox_exec_sha256,
    )
    if str(verified_sandbox_executable) != sandbox_executable_path:
        raise ComparisonProcessError("comparison process sandbox executable path is not canonical")
    expected_roots = _resolved_read_roots(
        (*expected_runtime_read_roots, *_command_runtime_paths(Path(argv[0])))
    )
    resolved_output = expected_output_directory.resolve(strict=True)
    _validate_campaign_read_separation(
        expected_roots,
        campaign_evidence_root=resolved_output.parent.parent,
    )
    expected_rules = _network_rules(
        clean_environment,
        evidence_class=str(payload.get("evidence_class")),
    )
    expected_docker_socket = _resolved_docker_socket(
        expected_docker_socket_path or Path("/definitely-absent-docker.sock"),
        required=expected_docker_socket_path is not None,
    )
    expected_profile = _sandbox_profile(
        output_dir=resolved_output,
        read_roots=expected_roots,
        network_rules=expected_rules,
        docker_socket=expected_docker_socket,
    )
    if sandbox_profile != expected_profile:
        raise ComparisonProcessError("comparison sandbox profile grants unexpected access")
    if (
        sandbox.get("platform") != "darwin"
        or sandbox.get("backend") != "sandbox-exec"
        or sandbox.get("profile_path") != SANDBOX_PROFILE_FILE
        or sandbox.get("profile_sha256") != _sha256_bytes(sandbox_profile)
        or sandbox.get("executable_sha256")
        != _sha256_digest(expected_sandbox_exec_sha256, "sandbox executable digest")
        or sandbox.get("profile_probe_succeeded") is not True
        or sandbox.get("filesystem_policy") != "explicit_read_roots_row_write_only"
        or sandbox.get("executable_root_owned") is not True
        or sandbox.get("executable_mode_safe") is not True
        or sandbox.get("outbound_tcp") != _network_rules_json(expected_rules)
        or sandbox.get("runtime_read_roots") != [str(path) for path in expected_roots]
        or sandbox.get("runtime_read_roots_sha256")
        != _sha256_bytes(_canonical_json([str(path) for path in expected_roots]))
        or sandbox.get("runtime_read_root_count") != len(expected_roots)
        or sandbox.get("docker_socket_path")
        != (str(expected_docker_socket) if expected_docker_socket is not None else None)
    ):
        raise ComparisonProcessError("comparison process sandbox enforcement is invalid")
    _sha256_digest(sandbox.get("executable_sha256"), "sandbox executable digest")
    _sha256_digest(sandbox.get("runtime_read_roots_sha256"), "runtime roots digest")
    _validated_network_rule_payload(sandbox.get("outbound_tcp"))

    docker_access = sandbox.get("docker_socket_access") is True
    trusted_host = sandbox.get("trusted_host_required") is True
    network_verified = sandbox.get("network_scope_verified") is True
    any_host = any(host == "*" for host, _port in expected_rules)
    expected_network_policy = _network_policy(
        docker_access=docker_access,
        any_host=any_host,
    )
    if sandbox.get("network_policy") != expected_network_policy:
        raise ComparisonProcessError("comparison process network policy is invalid")
    if evidence_class == STRICT_OFFICIAL:
        class_consistent = not docker_access and not trusted_host and network_verified
    else:
        class_consistent = docker_access and trusted_host and not network_verified
    if not class_consistent:
        raise ComparisonProcessError("comparison process evidence class is inconsistent")

    execution = _mapping(payload.get("execution"), "execution")
    execution_fields = {
        "started_at",
        "completed_at",
        "elapsed_seconds",
        "returncode",
        "timed_out",
        "spawn_succeeded",
        "wall_timeout_enforced",
        "process_group_created",
        "process_group_teardown_complete",
        "stdout",
        "stderr",
        "error",
    }
    if set(execution) != execution_fields:
        raise ComparisonProcessError("comparison process execution fields are invalid")
    started = _timestamp(execution.get("started_at"), "process start time")
    completed = _timestamp(execution.get("completed_at"), "process completion time")
    if completed < started:
        raise ComparisonProcessError("comparison process timestamps are reversed")
    elapsed = execution.get("elapsed_seconds")
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, (int, float))
        or not math.isfinite(elapsed)
        or elapsed < 0
    ):
        raise ComparisonProcessError("comparison process elapsed time is invalid")
    for field in (
        "spawn_succeeded",
        "wall_timeout_enforced",
        "process_group_created",
        "process_group_teardown_complete",
        "timed_out",
    ):
        if not isinstance(execution.get(field), bool):
            raise ComparisonProcessError(f"comparison process {field} is invalid")
    _validated_returncode(execution.get("returncode"))
    if execution.get("error") is not None and (
        not isinstance(execution.get("error"), str)
        or not str(execution.get("error")).strip()
        or len(str(execution.get("error"))) > 2_000
    ):
        raise ComparisonProcessError("comparison process execution error is invalid")
    if execution.get("wall_timeout_enforced") is not True:
        raise ComparisonProcessError("comparison process wall timeout was not enforced")
    captures_valid = all(
        _validate_capture(execution.get(name), name) for name in ("stdout", "stderr")
    )

    model = _mapping(payload.get("model_gateway"), "model gateway")
    expected_model = {
        "receipt_path": MODEL_GATEWAY_RECEIPT_FILE,
        "receipt_file_sha256": _sha256_digest(
            model_receipt_file_sha256, "model receipt file digest"
        ),
        "receipt_document_sha256": _sha256_digest(
            model_receipt_document_sha256, "model receipt document digest"
        ),
        "policy_sha256": _sha256_digest(expected_policy_sha256, "model policy digest"),
        "sealed_in_finally": True,
        "validator_passed": True,
        "error": None,
    }
    if model != expected_model:
        raise ComparisonProcessError("comparison process model receipt binding is invalid")

    if execution.get("timed_out") is True and execution.get("returncode") == 0:
        raise ComparisonProcessError("timed-out process receipt claims a successful exit")
    official = bool(
        evidence_class == STRICT_OFFICIAL
        and class_consistent
        and execution.get("spawn_succeeded") is True
        and execution.get("process_group_created") is True
        and execution.get("process_group_teardown_complete") is True
    )
    if payload.get("official_attestation_eligible") is not official:
        raise ComparisonProcessError("comparison process official verdict is inconsistent")
    expected_valid = bool(
        class_consistent
        and execution.get("spawn_succeeded") is True
        and execution.get("process_group_created") is True
        and execution.get("process_group_teardown_complete") is True
        and (execution.get("timed_out") is False or execution.get("returncode") != 0)
        and execution.get("error") is None
        and captures_valid
    )
    if payload.get("valid") is not expected_valid or payload.get("valid") is not True:
        raise ComparisonProcessError("comparison process validity verdict is invalid")
    if require_official_safety and not official:
        raise ComparisonProcessError("process receipt is paired-local, not official-safe")
    return dict(payload)


def validate_comparison_process_receipt_public(  # noqa: C901, PLR0913, PLR0915
    payload: object,
    *,
    expected_row_id: str,
    public_contract: object,
    model_receipt_file_sha256: str,
    model_receipt_document_sha256: str,
    sandbox_profile: bytes,
    expected_output_directory: Path,
    require_official_safety: bool,
) -> dict[str, object]:
    """Validate a process receipt from retained, secret-free row evidence.

    The public contract is emitted only after the live validator has checked
    the raw command, row token, environment, runtime roots, and generated
    profile.  A campaign attestation must bind that contract; this function
    never interprets a receipt's own ``valid`` field as proof.
    """

    receipt = _mapping(payload, "receipt")
    contract = _mapping(public_contract, "public validation contract")
    if set(contract) != {
        "row_id",
        "command",
        "environment",
        "limits",
        "model_gateway_policy_sha256",
        "model_gateway_row_token_sha256",
        "sandbox_executable_sha256",
        "sandbox",
    }:
        raise ComparisonProcessError("comparison process public contract is invalid")
    if contract.get("row_id") != expected_row_id:
        raise ComparisonProcessError("comparison process public row binding is invalid")
    required = {
        "schema_version",
        "created_at",
        "row_id",
        "evidence_class",
        "command",
        "environment",
        "cwd",
        "limits",
        "sandbox",
        "execution",
        "model_gateway",
        "official_attestation_eligible",
        "valid",
        "document_sha256",
    }
    if set(receipt) != required or receipt.get("schema_version") != PROCESS_RECEIPT_SCHEMA_VERSION:
        raise ComparisonProcessError("comparison process public receipt fields are invalid")
    body = {key: value for key, value in receipt.items() if key != "document_sha256"}
    if receipt.get("document_sha256") != _sha256_bytes(_canonical_json(body)):
        raise ComparisonProcessError("comparison process public receipt digest is invalid")
    _timestamp(receipt.get("created_at"), "receipt creation time")
    if receipt.get("row_id") != expected_row_id:
        raise ComparisonProcessError("comparison process public receipt row is invalid")
    if receipt.get("command") != contract.get("command"):
        raise ComparisonProcessError("comparison process public command binding is invalid")
    if receipt.get("environment") != contract.get("environment"):
        raise ComparisonProcessError("comparison process public environment binding is invalid")
    if receipt.get("limits") != contract.get("limits"):
        raise ComparisonProcessError("comparison process public limits binding is invalid")
    _validated_limits_payload(receipt.get("limits"))
    if receipt.get("cwd") != {"mode": "row_native_output", "relative_path": "native-output"}:
        raise ComparisonProcessError("comparison process public cwd binding is invalid")

    command = _mapping(receipt.get("command"), "public command")
    if (
        set(command) != {"argv_sha256", "argument_count", "shell", "executable_sha256"}
        or _SHA256_RE.fullmatch(str(command.get("argv_sha256"))) is None
        or _positive_integer(command.get("argument_count"), "command argument count") <= 0
        or command.get("shell") is not False
        or _SHA256_RE.fullmatch(str(command.get("executable_sha256"))) is None
    ):
        raise ComparisonProcessError("comparison process public command is malformed")
    environment = _mapping(receipt.get("environment"), "public environment")
    names = environment.get("names")
    if (
        set(environment) != {"inherits_parent", "names", "value_sha256", "contract_sha256"}
        or environment.get("inherits_parent") is not False
        or not isinstance(names, list)
        or names
        != sorted(
            {
                TARGET_URL_ENV,
                DESCRIPTION_ENV,
                COMPARISON_GATEWAY_TOKEN_ENV,
                GATEWAY_BASE_URL_ENV,
                OUTER_PROCESS_GROUP_ENV,
            }
        )
        or names != sorted(set(names))
        or any(
            not isinstance(name, str) or _SAFE_ENVIRONMENT_NAME_RE.fullmatch(name) is None
            for name in names
        )
        or _SHA256_RE.fullmatch(str(environment.get("contract_sha256"))) is None
    ):
        raise ComparisonProcessError("comparison process public environment is malformed")
    value_digests = environment.get("value_sha256")
    if (
        not isinstance(value_digests, dict)
        or sorted(value_digests) != names
        or any(_SHA256_RE.fullmatch(str(value)) is None for value in value_digests.values())
    ):
        raise ComparisonProcessError("comparison process public environment digests are invalid")
    expected_row_token_sha256 = _sha256_digest(
        contract.get("model_gateway_row_token_sha256"),
        "public model row-token digest",
    )
    if value_digests.get(COMPARISON_GATEWAY_TOKEN_ENV) != expected_row_token_sha256:
        raise ComparisonProcessError("comparison process public row-token binding is invalid")
    if value_digests.get(OUTER_PROCESS_GROUP_ENV) != _sha256_bytes(
        OUTER_PROCESS_GROUP_VALUE.encode("utf-8")
    ):
        raise ComparisonProcessError("comparison process public process-group binding is invalid")

    sandbox = _mapping(receipt.get("sandbox"), "public sandbox")
    if sandbox != _mapping(contract.get("sandbox"), "contract sandbox"):
        raise ComparisonProcessError("comparison process public sandbox binding is invalid")
    if sandbox.get("executable_sha256") != contract.get("sandbox_executable_sha256"):
        raise ComparisonProcessError("comparison process public sandbox pin is invalid")
    _validate_public_sandbox(
        sandbox,
        profile=sandbox_profile,
        expected_output_directory=expected_output_directory,
    )

    evidence_class = receipt.get("evidence_class")
    docker_access = sandbox.get("docker_socket_access") is True
    trusted_host = sandbox.get("trusted_host_required") is True
    network_verified = sandbox.get("network_scope_verified") is True
    if evidence_class == STRICT_OFFICIAL:
        class_consistent = not docker_access and not trusted_host and network_verified
    elif evidence_class == PAIRED_LOCAL:
        class_consistent = docker_access and trusted_host and not network_verified
    else:
        raise ComparisonProcessError("comparison process public evidence class is invalid")
    if not class_consistent:
        raise ComparisonProcessError("comparison process public evidence class is inconsistent")

    execution = _mapping(receipt.get("execution"), "public execution")
    execution_fields = {
        "started_at",
        "completed_at",
        "elapsed_seconds",
        "returncode",
        "timed_out",
        "spawn_succeeded",
        "wall_timeout_enforced",
        "process_group_created",
        "process_group_teardown_complete",
        "stdout",
        "stderr",
        "error",
    }
    if set(execution) != execution_fields:
        raise ComparisonProcessError("comparison process public execution is malformed")
    started = _timestamp(execution.get("started_at"), "process start time")
    completed = _timestamp(execution.get("completed_at"), "process completion time")
    elapsed = execution.get("elapsed_seconds")
    if (
        completed < started
        or isinstance(elapsed, bool)
        or not isinstance(elapsed, (int, float))
        or not math.isfinite(elapsed)
        or elapsed < 0
    ):
        raise ComparisonProcessError("comparison process public timing is invalid")
    for name in (
        "timed_out",
        "spawn_succeeded",
        "wall_timeout_enforced",
        "process_group_created",
        "process_group_teardown_complete",
    ):
        if not isinstance(execution.get(name), bool):
            raise ComparisonProcessError("comparison process public lifecycle is invalid")
    _validated_returncode(execution.get("returncode"))
    if execution.get("error") is not None and (
        not isinstance(execution.get("error"), str)
        or not str(execution.get("error")).strip()
        or len(str(execution.get("error"))) > 2_000
    ):
        raise ComparisonProcessError("comparison process public error is invalid")
    captures_valid = all(
        _validate_capture(execution.get(name), name) for name in ("stdout", "stderr")
    )

    policy_digest = _sha256_digest(
        contract.get("model_gateway_policy_sha256"),
        "public model policy digest",
    )
    model = _mapping(receipt.get("model_gateway"), "public model gateway")
    expected_model = {
        "receipt_path": MODEL_GATEWAY_RECEIPT_FILE,
        "receipt_file_sha256": _sha256_digest(
            model_receipt_file_sha256,
            "model receipt file digest",
        ),
        "receipt_document_sha256": _sha256_digest(
            model_receipt_document_sha256,
            "model receipt document digest",
        ),
        "policy_sha256": policy_digest,
        "sealed_in_finally": True,
        "validator_passed": True,
        "error": None,
    }
    if model != expected_model:
        raise ComparisonProcessError("comparison process public model binding is invalid")

    if execution.get("timed_out") is True and execution.get("returncode") == 0:
        raise ComparisonProcessError("timed-out process receipt claims a successful exit")
    lifecycle_valid = bool(
        execution.get("spawn_succeeded") is True
        and execution.get("wall_timeout_enforced") is True
        and execution.get("process_group_created") is True
        and execution.get("process_group_teardown_complete") is True
        and (execution.get("timed_out") is False or execution.get("returncode") != 0)
        and execution.get("error") is None
        and captures_valid
    )
    official = bool(evidence_class == STRICT_OFFICIAL and class_consistent and lifecycle_valid)
    if receipt.get("official_attestation_eligible") is not official:
        raise ComparisonProcessError("comparison process public official verdict is invalid")
    if receipt.get("valid") is not bool(class_consistent and lifecycle_valid):
        raise ComparisonProcessError("comparison process public validity verdict is inconsistent")
    if receipt.get("valid") is not True:
        raise ComparisonProcessError("comparison process public receipt is invalid")
    if require_official_safety and not official:
        raise ComparisonProcessError("paired-local evidence cannot satisfy official safety")
    return dict(receipt)


def validate_unstarted_comparison_process_receipt(  # noqa: C901, PLR0913
    payload: object,
    *,
    expected_row_id: str,
    expected_limits: ExternalExecutionLimits,
    expected_policy_sha256: str,
    expected_evidence_class: str,
    model_receipt_file_sha256: str,
    model_receipt_document_sha256: str,
    sandbox_profile: bytes,
) -> dict[str, object]:
    """Validate terminal evidence for a row that never launched an agent.

    An unstarted receipt is deliberately invalid for scoring, but it still has
    to be a coherent, create-only declaration bound to the independently valid
    zero-request model receipt.  Campaign accounting may include that model
    receipt without pretending a process ran.
    """

    receipt = _mapping(payload, "unstarted receipt")
    required = {
        "schema_version",
        "created_at",
        "row_id",
        "evidence_class",
        "command",
        "environment",
        "cwd",
        "limits",
        "sandbox",
        "execution",
        "model_gateway",
        "official_attestation_eligible",
        "valid",
        "document_sha256",
    }
    if set(receipt) != required or receipt.get("schema_version") != PROCESS_RECEIPT_SCHEMA_VERSION:
        raise ComparisonProcessError("unstarted process receipt fields are invalid")
    body = {key: value for key, value in receipt.items() if key != "document_sha256"}
    if receipt.get("document_sha256") != _sha256_bytes(_canonical_json(body)):
        raise ComparisonProcessError("unstarted process receipt digest is invalid")
    _timestamp(receipt.get("created_at"), "unstarted receipt creation time")
    if receipt.get("row_id") != expected_row_id or _ROW_ID_RE.fullmatch(expected_row_id) is None:
        raise ComparisonProcessError("unstarted process row binding is invalid")
    if (
        expected_evidence_class not in {STRICT_OFFICIAL, PAIRED_LOCAL}
        or receipt.get("evidence_class") != expected_evidence_class
    ):
        raise ComparisonProcessError("unstarted process evidence class is invalid")

    command = _mapping(receipt.get("command"), "unstarted command")
    if (
        set(command) != {"argv_sha256", "argument_count", "shell", "executable_sha256"}
        or _SHA256_RE.fullmatch(str(command.get("argv_sha256"))) is None
        or _positive_integer(command.get("argument_count"), "unstarted argument count") <= 0
        or command.get("shell") is not False
        or (
            command.get("executable_sha256") is not None
            and _SHA256_RE.fullmatch(str(command.get("executable_sha256"))) is None
        )
    ):
        raise ComparisonProcessError("unstarted process command is malformed")
    environment = _mapping(receipt.get("environment"), "unstarted environment")
    names = environment.get("names")
    value_digests = environment.get("value_sha256")
    if (
        set(environment) != {"inherits_parent", "names", "value_sha256", "contract_sha256"}
        or environment.get("inherits_parent") is not False
        or not isinstance(names, list)
        or names != sorted(set(names))
        or any(
            not isinstance(name, str) or _SAFE_ENVIRONMENT_NAME_RE.fullmatch(name) is None
            for name in names
        )
        or not isinstance(value_digests, dict)
        or sorted(value_digests) != names
        or any(_SHA256_RE.fullmatch(str(value)) is None for value in value_digests.values())
        or _SHA256_RE.fullmatch(str(environment.get("contract_sha256"))) is None
    ):
        raise ComparisonProcessError("unstarted process environment is malformed")
    if receipt.get("cwd") != {"mode": "row_native_output", "relative_path": "native-output"}:
        raise ComparisonProcessError("unstarted process cwd binding is invalid")
    if _validated_limits_payload(receipt.get("limits")) != expected_limits.to_json():
        raise ComparisonProcessError("unstarted process limits binding is invalid")

    sandbox = _mapping(receipt.get("sandbox"), "unstarted sandbox")
    sandbox_fields = {
        "platform",
        "backend",
        "executable_path",
        "executable_sha256",
        "executable_root_owned",
        "executable_mode_safe",
        "profile_path",
        "profile_sha256",
        "profile_probe_succeeded",
        "filesystem_policy",
        "network_policy",
        "outbound_tcp",
        "runtime_read_roots",
        "runtime_read_roots_sha256",
        "runtime_read_root_count",
        "docker_socket_access",
        "docker_socket_path",
        "trusted_host_required",
        "network_scope_verified",
    }
    if set(sandbox) != sandbox_fields:
        raise ComparisonProcessError("unstarted process sandbox fields are invalid")
    executable_digest = sandbox.get("executable_sha256")
    if executable_digest is not None:
        _sha256_digest(executable_digest, "unstarted sandbox executable digest")
    unstarted_roots = _validated_public_read_roots(sandbox.get("runtime_read_roots"))
    if sandbox.get("runtime_read_roots_sha256") != _sha256_bytes(
        _canonical_json([str(path) for path in unstarted_roots])
    ) or sandbox.get("runtime_read_root_count") != len(unstarted_roots):
        raise ComparisonProcessError("unstarted runtime roots binding is invalid")
    if (
        sandbox_profile != b""
        or sandbox.get("profile_path") != SANDBOX_PROFILE_FILE
        or sandbox.get("profile_sha256") != _sha256_bytes(sandbox_profile)
        or sandbox.get("profile_probe_succeeded") is not False
        or sandbox.get("outbound_tcp") != []
        or sandbox.get("docker_socket_access") is not False
        or sandbox.get("docker_socket_path") is not None
        or sandbox.get("trusted_host_required") is not False
        or sandbox.get("network_scope_verified") is not False
    ):
        raise ComparisonProcessError("unstarted process sandbox declaration is inconsistent")

    execution = _mapping(receipt.get("execution"), "unstarted execution")
    if set(execution) != {
        "started_at",
        "completed_at",
        "elapsed_seconds",
        "returncode",
        "timed_out",
        "spawn_succeeded",
        "wall_timeout_enforced",
        "process_group_created",
        "process_group_teardown_complete",
        "stdout",
        "stderr",
        "error",
    }:
        raise ComparisonProcessError("unstarted process lifecycle fields are invalid")
    started = _timestamp(execution.get("started_at"), "unstarted process start time")
    completed = _timestamp(execution.get("completed_at"), "unstarted process completion time")
    if completed < started:
        raise ComparisonProcessError("unstarted process timestamps are reversed")
    if (
        execution.get("elapsed_seconds") != 0.0
        or execution.get("returncode") != -1
        or execution.get("timed_out") is not False
        or execution.get("spawn_succeeded") is not False
        or execution.get("wall_timeout_enforced") is not True
        or execution.get("process_group_created") is not False
        or execution.get("process_group_teardown_complete") is not True
        or not isinstance(execution.get("error"), str)
        or not str(execution.get("error")).strip()
    ):
        raise ComparisonProcessError("unstarted process lifecycle is inconsistent")
    _validate_capture(execution.get("stdout"), "unstarted stdout")
    _validate_capture(execution.get("stderr"), "unstarted stderr")

    expected_model = {
        "receipt_path": MODEL_GATEWAY_RECEIPT_FILE,
        "receipt_file_sha256": _sha256_digest(
            model_receipt_file_sha256,
            "unstarted model receipt file digest",
        ),
        "receipt_document_sha256": _sha256_digest(
            model_receipt_document_sha256,
            "unstarted model receipt document digest",
        ),
        "policy_sha256": _sha256_digest(
            expected_policy_sha256,
            "unstarted model policy digest",
        ),
        "sealed_in_finally": True,
        "validator_passed": True,
        "error": None,
    }
    if receipt.get("model_gateway") != expected_model:
        raise ComparisonProcessError("unstarted process model receipt binding is invalid")
    if (
        receipt.get("official_attestation_eligible") is not False
        or receipt.get("valid") is not False
    ):
        raise ComparisonProcessError("unstarted process validity declaration is inconsistent")
    return dict(receipt)


def read_bounded_json_receipt(path: Path, *, maximum_bytes: int = MAX_RECEIPT_BYTES) -> object:
    """Read one non-symlink regular receipt with a fixed upper bound."""

    if maximum_bytes <= 0:
        raise ValueError("receipt byte limit must be positive")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ComparisonProcessError(f"receipt is missing: {path.name}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ComparisonProcessError(f"receipt is a symlink: {path.name}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 0
        or metadata.st_size > maximum_bytes
    ):
        raise ComparisonProcessError(f"receipt is not a bounded regular file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
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
                raise ComparisonProcessError(f"receipt changed before reading: {path.name}")
            while chunk := handle.read(min(64 * 1024, maximum_bytes + 1 - observed_size)):
                observed_size += len(chunk)
                if observed_size > maximum_bytes:
                    raise ComparisonProcessError(f"receipt exceeds its byte limit: {path.name}")
                chunks.append(chunk)
            completed = os.fstat(handle.fileno())
        if (
            observed_size != metadata.st_size
            or completed.st_nlink != 1
            or completed.st_dev != metadata.st_dev
            or completed.st_ino != metadata.st_ino
            or completed.st_size != metadata.st_size
        ):
            raise ComparisonProcessError(f"receipt changed while reading: {path.name}")
        body = b"".join(chunks)
        return json.loads(body)
    except ComparisonProcessError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ComparisonProcessError(f"receipt is invalid JSON: {path.name}") from exc


def _seal_model_gateway_receipt(
    *,
    gateway: ComparisonModelGateway,
    row_id: str,
    output_path: Path,
    expected_policy_sha256: str,
    expected_row_token_sha256: str,
    limits: ExternalExecutionLimits,
    environment: Mapping[str, str],
) -> tuple[dict[str, object] | None, str | None, bool]:
    try:
        # No process was started, so any admitted request is foreign to this
        # terminal row and must be conservatively closed without waiting.
        raw_receipt = gateway.close_row_and_seal(
            row_id,
            output_path,
            drain_timeout_seconds=0.0,
        )
        receipt = validate_model_gateway_receipt(
            raw_receipt,
            expected_row_id=row_id,
            expected_policy_sha256=expected_policy_sha256,
            expected_max_requests=limits.max_model_requests,
            expected_max_cost_usd=limits.max_cost_usd,
        )
        token = environment.get(COMPARISON_GATEWAY_TOKEN_ENV)
        if token is not None and _sha256_bytes(token.encode("utf-8")) != expected_row_token_sha256:
            raise ComparisonProcessError(
                "unstarted row environment differs from the frozen token binding"
            )
        if receipt.get("row_token_sha256") != expected_row_token_sha256:
            raise ComparisonProcessError("model receipt token binding is invalid")
        return receipt, None, receipt.get("valid") is True
    except Exception as exc:  # noqa: BLE001 - receipt failures are retained, never hidden.
        return None, _bounded_error(exc), False


def _validate_public_sandbox(
    sandbox: Mapping[str, object],
    *,
    profile: bytes,
    expected_output_directory: Path,
) -> None:
    fields = {
        "platform",
        "backend",
        "executable_path",
        "executable_sha256",
        "executable_root_owned",
        "executable_mode_safe",
        "profile_path",
        "profile_sha256",
        "profile_probe_succeeded",
        "filesystem_policy",
        "network_policy",
        "outbound_tcp",
        "runtime_read_roots",
        "runtime_read_roots_sha256",
        "runtime_read_root_count",
        "docker_socket_access",
        "docker_socket_path",
        "trusted_host_required",
        "network_scope_verified",
    }
    if set(sandbox) != fields:
        raise ComparisonProcessError("comparison process public sandbox fields are invalid")
    if (
        sandbox.get("platform") != "darwin"
        or sandbox.get("backend") != "sandbox-exec"
        or sandbox.get("profile_path") != SANDBOX_PROFILE_FILE
        or sandbox.get("profile_sha256") != _sha256_bytes(profile)
        or sandbox.get("profile_probe_succeeded") is not True
        or sandbox.get("filesystem_policy") != "explicit_read_roots_row_write_only"
        or sandbox.get("executable_root_owned") is not True
        or sandbox.get("executable_mode_safe") is not True
    ):
        raise ComparisonProcessError("comparison process public sandbox verdict is invalid")
    _sha256_digest(sandbox.get("executable_sha256"), "sandbox executable digest")
    runtime_roots = _validated_public_read_roots(sandbox.get("runtime_read_roots"))
    if sandbox.get("runtime_read_roots_sha256") != _sha256_bytes(
        _canonical_json([str(path) for path in runtime_roots])
    ) or sandbox.get("runtime_read_root_count") != len(runtime_roots):
        raise ComparisonProcessError("comparison sandbox runtime roots binding is invalid")
    network_rules = _validated_network_rule_payload(sandbox.get("outbound_tcp"))
    try:
        lines = profile.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ComparisonProcessError("comparison sandbox profile is not UTF-8") from exc
    fixed = [
        "(version 1)",
        "(deny default)",
        *_SANDBOX_PROCESS_RULES,
    ]
    if lines[: len(fixed)] != fixed or len(lines) <= len(fixed):
        raise ComparisonProcessError("comparison sandbox profile prelude is invalid")
    remaining = lines[len(fixed) :]
    read_prefix = "(allow file-read* (subpath "
    write_prefix = "(allow file-write* (subpath "
    reads = [line for line in remaining if line.startswith(read_prefix)]
    writes = [line for line in remaining if line.startswith(write_prefix)]
    if len(writes) != 1:
        raise ComparisonProcessError("comparison sandbox filesystem profile is invalid")
    read_paths = [_profile_path(line, prefix=read_prefix) for line in reads]
    if any(not path.is_absolute() or path == Path("/") for path in read_paths):
        raise ComparisonProcessError("comparison sandbox readable root is unsafe")
    write_path = _profile_path(writes[0], prefix=write_prefix)
    try:
        expected_write_path = expected_output_directory.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ComparisonProcessError("comparison public output directory is unavailable") from exc
    if (
        not write_path.is_absolute()
        or write_path == Path("/")
        or write_path.name != "native-output"
        or write_path != expected_write_path
    ):
        raise ComparisonProcessError("comparison sandbox writable root is invalid")
    campaign_root = write_path.parent.parent
    expected_read_paths = set((*_SYSTEM_READ_ROOTS, *runtime_roots, write_path))
    if set(read_paths) != expected_read_paths:
        raise ComparisonProcessError("comparison sandbox readable roots differ from their contract")
    for read_path in read_paths:
        if read_path != write_path and _paths_overlap(read_path, campaign_root):
            raise ComparisonProcessError(
                "comparison sandbox can read another campaign evidence path"
            )
    expected_network = {
        f'(allow network-outbound (remote tcp "{host}:{port}"))' for host, port in network_rules
    }
    actual_network = {line for line in remaining if "network-outbound" in line}
    docker_access = sandbox.get("docker_socket_access") is True
    docker_path_value = sandbox.get("docker_socket_path")
    if docker_access:
        if not isinstance(docker_path_value, str):
            raise ComparisonProcessError("comparison Docker socket path is invalid")
        docker_path = Path(docker_path_value)
        if not docker_path.is_absolute() or docker_path == Path("/"):
            raise ComparisonProcessError("comparison Docker socket path is unsafe")
        expected_network.add(f"(allow network-outbound (literal {_sandbox_string(docker_path)}))")
    elif docker_path_value is not None:
        raise ComparisonProcessError("strict sandbox unexpectedly names a Docker socket")
    any_host = any(host == "*" for host, _port in network_rules)
    if sandbox.get("network_policy") != _network_policy(
        docker_access=docker_access,
        any_host=any_host,
    ):
        raise ComparisonProcessError("comparison process public network policy is invalid")
    trusted_host = sandbox.get("trusted_host_required") is True
    network_verified = sandbox.get("network_scope_verified") is True
    if docker_access:
        if not trusted_host or network_verified:
            raise ComparisonProcessError(
                "paired-local public sandbox trust boundary is inconsistent"
            )
    elif trusted_host or not network_verified:
        raise ComparisonProcessError("strict public sandbox trust boundary is inconsistent")
    if actual_network != expected_network:
        raise ComparisonProcessError("comparison sandbox network profile is broader than declared")
    allowed = (
        set(fixed)
        | set(reads)
        | set(writes)
        | expected_network
        | {'(allow file-write* (literal "/dev/null"))'}
    )
    allowed.update(
        f"(allow file-read* (literal {_sandbox_string(path)}))" for path in _SYSTEM_READ_FILES
    )
    if docker_access:
        docker_path = Path(str(docker_path_value))
        allowed.update(
            {
                f"(allow file-read* (literal {_sandbox_string(docker_path)}))",
                f"(allow file-write* (literal {_sandbox_string(docker_path)}))",
            }
        )
    if set(lines) != allowed or len(lines) != len(allowed):
        raise ComparisonProcessError("comparison sandbox profile contains undeclared rules")


def _profile_path(line: str, *, prefix: str) -> Path:
    if not line.endswith("))"):
        raise ComparisonProcessError("comparison sandbox path rule is malformed")
    encoded = line[len(prefix) : -2]
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError as exc:
        raise ComparisonProcessError("comparison sandbox path rule is invalid") from exc
    if not isinstance(value, str):
        raise ComparisonProcessError("comparison sandbox path rule is not a string")
    path = Path(value)
    if (
        not path.is_absolute()
        or path == Path("/")
        or path.as_posix() != value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ComparisonProcessError("comparison sandbox path rule is not canonical")
    return path


def _process_receipt(  # noqa: PLR0913
    *,
    row_id: str,
    evidence_class: EvidenceClass,
    argv: tuple[str, ...],
    executable_sha256: str | None,
    environment: Mapping[str, str],
    limits: ExternalExecutionLimits,
    sandbox_path: Path,
    profile: bytes,
    read_roots: tuple[Path, ...],
    network_rules: tuple[tuple[str, int], ...],
    docker_socket: Path | None,
    profile_probe_succeeded: bool,
    started_at: str,
    completed_at: str,
    elapsed_seconds: float,
    returncode: int,
    timed_out: bool,
    spawn_succeeded: bool,
    process_group_created: bool,
    process_group_teardown_complete: bool,
    stdout: _Capture,
    stderr: _Capture,
    maximum_capture_bytes: int,
    execution_error: str | None,
    model_file_digest: str | None,
    model_document_digest: str | None,
    expected_policy_sha256: str,
    model_receipt_valid: bool,
    model_receipt_error: str | None,
    official_eligible: bool,
    receipt_valid: bool,
) -> dict[str, object]:
    try:
        sandbox_stat = sandbox_path.stat()
    except OSError:
        sandbox_stat = None
    docker_access = docker_socket is not None
    body: dict[str, object] = {
        "schema_version": PROCESS_RECEIPT_SCHEMA_VERSION,
        "created_at": completed_at,
        "row_id": row_id,
        "evidence_class": evidence_class,
        "command": {
            "argv_sha256": _sha256_bytes(_canonical_json(list(argv))),
            "argument_count": len(argv),
            "shell": False,
            "executable_sha256": executable_sha256,
        },
        "environment": {
            "inherits_parent": False,
            "names": sorted(environment),
            "value_sha256": {
                name: _sha256_bytes(value.encode("utf-8"))
                for name, value in sorted(environment.items())
            },
            "contract_sha256": _sha256_bytes(_canonical_json(environment)),
        },
        "cwd": {"mode": "row_native_output", "relative_path": "native-output"},
        "limits": limits.to_json(),
        "sandbox": {
            "platform": "darwin" if sys.platform == "darwin" else sys.platform,
            "backend": "sandbox-exec",
            "executable_path": str(sandbox_path),
            "executable_sha256": _sha256_regular_file(sandbox_path),
            "executable_root_owned": sandbox_stat is not None and sandbox_stat.st_uid == 0,
            "executable_mode_safe": sandbox_stat is not None
            and not bool(stat.S_IMODE(sandbox_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)),
            "profile_path": SANDBOX_PROFILE_FILE,
            "profile_sha256": _sha256_bytes(profile),
            "profile_probe_succeeded": profile_probe_succeeded,
            "filesystem_policy": "explicit_read_roots_row_write_only",
            "network_policy": _network_policy(
                docker_access=docker_access,
                any_host=any(host == "*" for host, _port in network_rules),
            ),
            "outbound_tcp": _network_rules_json(network_rules),
            "runtime_read_roots": [str(path) for path in read_roots],
            "runtime_read_roots_sha256": _sha256_bytes(
                _canonical_json([str(path) for path in read_roots])
            ),
            "runtime_read_root_count": len(read_roots),
            "docker_socket_access": docker_access,
            "docker_socket_path": str(docker_socket) if docker_socket is not None else None,
            "trusted_host_required": docker_access,
            # Docker-created descendants are outside the outer sandbox.  Never
            # turn the paired-local trust boundary into a verified network claim.
            "network_scope_verified": profile_probe_succeeded and not docker_access,
        },
        "execution": {
            "started_at": started_at,
            "completed_at": completed_at,
            "elapsed_seconds": elapsed_seconds,
            "returncode": returncode,
            "timed_out": timed_out,
            "spawn_succeeded": spawn_succeeded,
            "wall_timeout_enforced": True,
            "process_group_created": process_group_created,
            "process_group_teardown_complete": process_group_teardown_complete,
            "stdout": _capture_json(stdout, maximum_bytes=maximum_capture_bytes),
            "stderr": _capture_json(stderr, maximum_bytes=maximum_capture_bytes),
            "error": execution_error,
        },
        "model_gateway": {
            "receipt_path": MODEL_GATEWAY_RECEIPT_FILE,
            "receipt_file_sha256": model_file_digest,
            "receipt_document_sha256": model_document_digest,
            "policy_sha256": _sha256_digest(
                expected_policy_sha256,
                "model policy digest",
            ),
            "sealed_in_finally": True,
            "validator_passed": model_receipt_valid,
            "error": model_receipt_error,
        },
        "official_attestation_eligible": official_eligible,
        "valid": receipt_valid,
    }
    body["document_sha256"] = _sha256_bytes(_canonical_json(body))
    return body


def _wait_bounded_process(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    maximum_capture_bytes: int,
    termination_grace_seconds: float,
) -> tuple[_Capture, _Capture, bool]:
    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process, grace_seconds=termination_grace_seconds)
        raise ComparisonProcessError("outer process pipes were not created")
    out = _BoundedCollector(maximum_capture_bytes)
    err = _BoundedCollector(maximum_capture_bytes)
    threads = (
        threading.Thread(target=out.drain, args=(process.stdout,), daemon=True),
        threading.Thread(target=err.drain, args=(process.stderr,), daemon=True),
    )
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        _terminate_process_group(process, grace_seconds=termination_grace_seconds)
    for thread in threads:
        thread.join(timeout=termination_grace_seconds)
    if any(thread.is_alive() for thread in threads):
        raise ComparisonProcessError("outer process output drains did not terminate")
    return out.result(), err.result(), timed_out


def _terminate_process_group(process: subprocess.Popen[bytes], *, grace_seconds: float) -> None:
    # A SIGTERM grace period would let a timed-out agent keep computing and
    # write a winning artifact after the frozen wall deadline.  Kill the whole
    # evaluator-created group immediately; ``grace_seconds`` is only the bound
    # for observing kernel teardown/reaping after SIGKILL.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        raise ComparisonProcessError(
            "outer process group could not be killed by the evaluator"
        ) from exc
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=grace_seconds)
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline and not _process_group_absent(process.pid):
        time.sleep(0.02)
    if not _process_group_absent(process.pid):
        raise ComparisonProcessError("outer process group resisted SIGKILL")


def _process_group_absent(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _remaining_seconds(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _probe_sandbox_profile(
    sandbox_path: Path,
    profile_path: Path,
    *,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    try:
        profile = profile_path.read_bytes()
        positive = _run_sandbox_probe(
            (str(sandbox_path), "-f", str(profile_path), "/usr/bin/true"),
            deadline=deadline,
        )
        # The profile itself is evaluator evidence outside the sole writable
        # native-output directory. A successful read would demonstrate that
        # the claimed filesystem boundary is not actually active.
        forbidden_read = _run_sandbox_probe(
            (str(sandbox_path), "-f", str(profile_path), "/bin/cat", str(profile_path)),
            deadline=deadline,
        )
        if positive.returncode != 0 or forbidden_read.returncode == 0:
            return False
        return _probe_sandbox_network_deny(
            sandbox_path=sandbox_path,
            profile=profile,
            deadline=deadline,
        )
    except (OSError, subprocess.SubprocessError):
        return False


def _run_sandbox_probe(
    command: Sequence[str],
    *,
    deadline: float,
) -> subprocess.CompletedProcess[bytes]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(tuple(command), 0)
    return subprocess.run(  # noqa: S603 - fixed evaluator-owned probes, no shell.
        tuple(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"},
        check=False,
        timeout=remaining,
    )


def _probe_sandbox_network_deny(
    *,
    sandbox_path: Path,
    profile: bytes,
    deadline: float,
) -> bool:
    try:
        profile_text = profile.decode("utf-8")
    except UnicodeDecodeError:
        return False
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    accepted: list[int] = []
    stop = threading.Event()
    thread: threading.Thread | None = None
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.05)
        port = int(listener.getsockname()[1])
        if f':{port}"' in profile_text:
            return False

        def accept_connections() -> None:
            while not stop.is_set():
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                accepted.append(1)
                with connection:
                    pass

        thread = threading.Thread(target=accept_connections, daemon=True)
        thread.start()
        positive_profile = (
            profile_text + f'(allow network-outbound (remote tcp "localhost:{port}"))\n'
        )
        positive = _run_sandbox_probe(
            (
                str(sandbox_path),
                "-p",
                positive_profile,
                "/usr/bin/nc",
                "-z",
                "-w",
                "1",
                "127.0.0.1",
                str(port),
            ),
            deadline=deadline,
        )
        if positive.returncode != 0:
            return False
        observation_deadline = min(deadline, time.monotonic() + 0.1)
        while not accepted and time.monotonic() < observation_deadline:
            time.sleep(0.005)
        positive_count = len(accepted)
        if positive_count == 0:
            return False
        denied = _run_sandbox_probe(
            (
                str(sandbox_path),
                "-p",
                profile_text,
                "/usr/bin/nc",
                "-z",
                "-w",
                "1",
                "127.0.0.1",
                str(port),
            ),
            deadline=deadline,
        )
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        return denied.returncode != 0 and len(accepted) == positive_count
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        stop.set()
        with contextlib.suppress(OSError):
            listener.close()
        if thread is not None:
            thread.join(timeout=0.2)


def _sandbox_profile(
    *,
    output_dir: Path,
    read_roots: Sequence[Path],
    network_rules: Sequence[tuple[str, int]],
    docker_socket: Path | None,
) -> bytes:
    lines = [
        "(version 1)",
        "(deny default)",
        *_SANDBOX_PROCESS_RULES,
    ]
    for root in sorted(set((*_SYSTEM_READ_ROOTS, *read_roots, output_dir))):
        lines.append(f"(allow file-read* (subpath {_sandbox_string(root)}))")
    for path in _SYSTEM_READ_FILES:
        lines.append(f"(allow file-read* (literal {_sandbox_string(path)}))")
    lines.append(f"(allow file-write* (subpath {_sandbox_string(output_dir)}))")
    lines.append('(allow file-write* (literal "/dev/null"))')
    for host, port in sorted(set(network_rules)):
        lines.append(f'(allow network-outbound (remote tcp "{host}:{port}"))')
    if docker_socket is not None:
        lines.append(f"(allow file-read* (literal {_sandbox_string(docker_socket)}))")
        lines.append(f"(allow file-write* (literal {_sandbox_string(docker_socket)}))")
        lines.append(f"(allow network-outbound (literal {_sandbox_string(docker_socket)}))")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _validated_command(command: Sequence[str]) -> tuple[str, ...]:
    if not command or not all(
        isinstance(item, str) and item and "\x00" not in item for item in command
    ):
        raise ComparisonProcessError("comparison process command is invalid")
    argv = tuple(command)
    if (
        len(argv) > MAX_COMMAND_ARGUMENTS
        or sum(len(item.encode("utf-8")) for item in argv) > MAX_COMMAND_BYTES
    ):
        raise ComparisonProcessError("comparison process command exceeds its fixed bound")
    executable = Path(argv[0])
    if (
        not executable.is_absolute()
        or any(part in {".", ".."} for part in executable.parts)
        or (executable != Path(sys.executable) and executable.is_symlink())
    ):
        raise ComparisonProcessError("comparison process executable path is unsafe")
    try:
        metadata = executable.lstat()
        resolved = executable.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ComparisonProcessError("comparison process executable is missing") from exc
    if (
        not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode))
        or not resolved.is_file()
        or not os.access(resolved, os.X_OK)
    ):
        raise ComparisonProcessError("comparison process executable is not executable")
    # CPython must see the lexical virtual-environment path beside pyvenv.cfg.
    # Only this evaluator's exact interpreter may remain a symlink; every
    # caller-supplied executable is still canonicalized to a regular file.
    launch_path = executable if stat.S_ISLNK(metadata.st_mode) else resolved
    return (str(launch_path), *argv[1:])


def _command_runtime_paths(executable: Path) -> tuple[Path, ...]:
    """Return the minimum read roots needed to launch a validated executable."""

    try:
        metadata = executable.lstat()
        resolved = executable.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ComparisonProcessError("comparison process executable is missing") from exc
    if stat.S_ISLNK(metadata.st_mode):
        if executable != Path(sys.executable):
            raise ComparisonProcessError("comparison process executable symlink is not trusted")
        # The venv root contains pyvenv.cfg; the real binary's directory holds
        # the standard-library layout used during interpreter bootstrap.
        return (executable.parent.parent, resolved)
    return (resolved,)


def _validated_output_directory(cwd: Path) -> tuple[Path, Path]:
    if cwd.is_symlink():
        raise ComparisonProcessError("comparison process cwd cannot be a symlink")
    try:
        output = cwd.resolve(strict=True)
    except OSError as exc:
        raise ComparisonProcessError("comparison process cwd is missing") from exc
    if not output.is_dir() or output.name != "native-output":
        raise ComparisonProcessError("comparison process cwd is not a row native-output directory")
    row_dir = output.parent
    if row_dir.is_symlink() or not row_dir.is_dir():
        raise ComparisonProcessError("comparison row directory is invalid")
    return output, row_dir


def _validated_environment(environment: Mapping[str, str]) -> dict[str, str]:
    if len(environment) > MAX_ENVIRONMENT_ENTRIES:
        raise ComparisonProcessError("comparison process environment has too many entries")
    clean: dict[str, str] = {}
    total_bytes = 0
    for raw_name, raw_value in environment.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise ComparisonProcessError("comparison process environment must contain strings")
        if _SAFE_ENVIRONMENT_NAME_RE.fullmatch(raw_name) is None or "\x00" in raw_value:
            raise ComparisonProcessError("comparison process environment is invalid")
        total_bytes += len(raw_name.encode("utf-8")) + len(raw_value.encode("utf-8"))
        if total_bytes > MAX_ENVIRONMENT_BYTES:
            raise ComparisonProcessError("comparison process environment exceeds its fixed bound")
        clean[raw_name] = raw_value
    required = {
        TARGET_URL_ENV,
        DESCRIPTION_ENV,
        COMPARISON_GATEWAY_TOKEN_ENV,
        GATEWAY_BASE_URL_ENV,
        OUTER_PROCESS_GROUP_ENV,
    }
    if set(clean) != required:
        missing = ", ".join(sorted(required - set(clean))) or "none"
        unexpected = ", ".join(sorted(set(clean) - required)) or "none"
        raise ComparisonProcessError(
            "comparison process environment must contain only the five row inputs "
            f"(missing: {missing}; unexpected: {unexpected})"
        )
    if clean[OUTER_PROCESS_GROUP_ENV] != OUTER_PROCESS_GROUP_VALUE:
        raise ComparisonProcessError("comparison process group contract is invalid")
    return clean


def _network_rules(
    environment: Mapping[str, str],
    *,
    evidence_class: str,
) -> tuple[tuple[str, int], ...]:
    if evidence_class not in {STRICT_OFFICIAL, PAIRED_LOCAL}:
        raise ComparisonProcessError("comparison process evidence class is invalid")
    rules: set[tuple[str, int]] = set()
    for name in (TARGET_URL_ENV, GATEWAY_BASE_URL_ENV):
        parsed = urlparse(environment[name])
        host = (parsed.hostname or "").lower()
        loopback = host in {"127.0.0.1", "localhost", "::1"}
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ComparisonProcessError(f"{name} must use a normalized HTTP gateway URL")
        if name == GATEWAY_BASE_URL_ENV and not loopback:
            raise ComparisonProcessError("model gateway must use an exact loopback URL")
        if name == TARGET_URL_ENV and not loopback and evidence_class == STRICT_OFFICIAL:
            raise ComparisonProcessError("strict target gateway must use an exact loopback URL")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ComparisonProcessError(f"{name} contains an invalid port") from exc
        rules.add(("localhost" if loopback else "*", port))
    return tuple(sorted(rules))


def _network_rules_json(rules: Sequence[tuple[str, int]]) -> list[dict[str, object]]:
    return [
        {"host_scope": "loopback" if host == "localhost" else "any", "port": port}
        for host, port in sorted(set(rules))
    ]


def _validated_network_rule_payload(value: object) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, list) or not value:
        raise ComparisonProcessError("comparison process outbound TCP rules are invalid")
    rules: list[tuple[str, int]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"host_scope", "port"}:
            raise ComparisonProcessError("comparison process outbound TCP rule is malformed")
        scope = item.get("host_scope")
        port = item.get("port")
        if (
            scope not in {"loopback", "any"}
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ComparisonProcessError("comparison process outbound TCP rule is invalid")
        rules.append(("localhost" if scope == "loopback" else "*", port))
    normalized = tuple(sorted(set(rules)))
    if list(value) != _network_rules_json(normalized):
        raise ComparisonProcessError("comparison process outbound TCP rules are not canonical")
    return normalized


def _validated_public_read_roots(value: object) -> tuple[Path, ...]:
    if not isinstance(value, list) or len(value) > MAX_RUNTIME_READ_ROOTS:
        raise ComparisonProcessError("comparison sandbox runtime roots are invalid")
    roots: list[Path] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
        ):
            raise ComparisonProcessError("comparison sandbox runtime root is malformed")
        path = Path(item)
        if (
            not path.is_absolute()
            or path == Path("/")
            or path.as_posix() != item
            or any(part in {".", ".."} for part in item.split("/"))
        ):
            raise ComparisonProcessError("comparison sandbox runtime root is unsafe")
        roots.append(path)
    normalized = tuple(sorted(set(roots)))
    if roots != list(normalized):
        raise ComparisonProcessError("comparison sandbox runtime roots are not canonical")
    return normalized


def _network_policy(*, docker_access: bool, any_host: bool) -> str:
    if not docker_access:
        if any_host:
            raise ComparisonProcessError("strict sandbox cannot grant any-host network access")
        return "loopback_exact_ports"
    if any_host:
        return "loopback_model_and_target_port_scoped_plus_docker_unix_socket"
    return "loopback_exact_ports_plus_docker_unix_socket"


def _verified_sandbox_executable(path: Path, *, expected_sha256: str) -> Path:
    if sys.platform != "darwin":
        raise ComparisonProcessError("strict process containment requires macOS sandbox-exec")
    if path.is_symlink() or not path.is_absolute():
        raise ComparisonProcessError("sandbox-exec path must be absolute and not symlinked")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ComparisonProcessError("sandbox-exec is unavailable") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ComparisonProcessError("sandbox-exec is not executable")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise ComparisonProcessError("sandbox-exec ownership or mode is unsafe")
    if _sha256_regular_file(resolved) != _sha256_digest(expected_sha256, "sandbox-exec digest"):
        raise ComparisonProcessError("sandbox-exec does not match its frozen digest")
    return resolved


def _resolved_read_roots(paths: Sequence[Path]) -> tuple[Path, ...]:
    roots: set[Path] = set()
    for raw in paths:
        if raw.is_symlink():
            raise ComparisonProcessError("runtime read root cannot be a symlink")
        try:
            path = raw.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ComparisonProcessError("runtime read root is missing") from exc
        root = path if path.is_dir() else path.parent
        if root == Path("/"):
            raise ComparisonProcessError("runtime read root cannot grant the filesystem root")
        roots.add(root)
    return tuple(sorted(roots))


def _validate_campaign_read_separation(
    read_roots: Sequence[Path],
    *,
    campaign_evidence_root: Path,
) -> None:
    campaign_root = campaign_evidence_root.resolve(strict=True)
    for root in read_roots:
        if _paths_overlap(root, campaign_root):
            raise ComparisonProcessError(
                "runtime read roots overlap the campaign evidence directory"
            )


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        first.relative_to(second)
    except ValueError:
        pass
    else:
        return True
    try:
        second.relative_to(first)
    except ValueError:
        return False
    return True


def _resolved_docker_socket(path: Path, *, required: bool) -> Path | None:
    if not required:
        return None
    try:
        resolved = path.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ComparisonProcessError("paired-local Docker socket is unavailable") from exc
    if not stat.S_ISSOCK(metadata.st_mode):
        raise ComparisonProcessError("paired-local Docker path is not a socket")
    return resolved


def _capture_json(capture: _Capture, *, maximum_bytes: int) -> dict[str, object]:
    return {
        "raw_sha256": capture.sha256,
        "raw_size_bytes": capture.total_bytes,
        "retained_size_bytes": len(capture.retained),
        "max_retained_bytes": maximum_bytes,
        "truncated": capture.truncated,
        "complete": capture.complete,
    }


def _validate_capture(value: object, label: str) -> bool:
    capture = _mapping(value, f"{label} capture")
    if set(capture) != {
        "raw_sha256",
        "raw_size_bytes",
        "retained_size_bytes",
        "max_retained_bytes",
        "truncated",
        "complete",
    }:
        raise ComparisonProcessError(f"comparison process {label} capture fields are invalid")
    _sha256_digest(capture.get("raw_sha256"), f"{label} digest")
    raw = _nonnegative_integer(capture.get("raw_size_bytes"), f"{label} raw size")
    retained = _nonnegative_integer(capture.get("retained_size_bytes"), f"{label} retained size")
    maximum = _positive_integer(capture.get("max_retained_bytes"), f"{label} maximum size")
    expected_truncated = raw > retained
    if (
        maximum > DEFAULT_MAX_CAPTURE_BYTES
        or retained > raw
        or retained > maximum
        or capture.get("truncated") is not expected_truncated
    ):
        raise ComparisonProcessError(f"comparison process {label} bounds are invalid")
    if capture.get("complete") is not True:
        raise ComparisonProcessError(f"comparison process {label} capture is incomplete")
    return True


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComparisonProcessError(f"comparison process {label} must be an object")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ComparisonProcessError(f"comparison process {label} is invalid")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ComparisonProcessError(f"comparison process {label} is invalid")
    return value


def _validated_returncode(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -(2**31) <= value < 2**31:
        raise ComparisonProcessError("comparison process return code is invalid")
    return value


def _validated_limits_payload(value: object) -> dict[str, object]:
    limits = _mapping(value, "limits")
    if set(limits) != {
        "wall_seconds",
        "max_model_requests",
        "max_target_requests",
        "max_cost_usd",
    }:
        raise ComparisonProcessError("comparison process limits are malformed")
    cost = limits.get("max_cost_usd")
    if not isinstance(cost, str):
        raise ComparisonProcessError("comparison process cost limit is invalid")
    try:
        normalized = ExternalExecutionLimits(
            wall_seconds=limits.get("wall_seconds"),  # type: ignore[arg-type]
            max_model_requests=limits.get("max_model_requests"),  # type: ignore[arg-type]
            max_target_requests=limits.get("max_target_requests"),  # type: ignore[arg-type]
            max_cost_usd=cost,
        ).to_json()
    except ComparisonContractError as exc:
        raise ComparisonProcessError("comparison process limits are invalid") from exc
    if dict(limits) != normalized:
        raise ComparisonProcessError("comparison process limits are not canonical")
    return dict(limits)


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ComparisonProcessError(f"comparison process {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ComparisonProcessError(f"comparison process {label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ComparisonProcessError(f"comparison process {label} lacks a timezone")
    return parsed.astimezone(UTC)


def _sha256_regular_file(path: Path) -> str | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > MAX_HASHED_FILE_BYTES
    ):
        return None
    digest = hashlib.sha256()
    observed_size = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size
            ):
                return None
            while chunk := handle.read(64 * 1024):
                observed_size += len(chunk)
                if observed_size > MAX_HASHED_FILE_BYTES:
                    return None
                digest.update(chunk)
            completed = os.fstat(handle.fileno())
    except OSError:
        return None
    if (
        observed_size != metadata.st_size
        or completed.st_dev != metadata.st_dev
        or completed.st_ino != metadata.st_ino
        or completed.st_size != metadata.st_size
    ):
        return None
    return "sha256:" + digest.hexdigest()


def _command_executable_sha256(path: Path) -> str | None:
    """Hash the regular target of the sole permitted interpreter symlink."""

    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            if path != Path(sys.executable):
                return None
            path = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return _sha256_regular_file(path)


def _sha256_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ComparisonProcessError(f"comparison process {label} is invalid")
    return value


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ComparisonProcessError("comparison process evidence is not canonical JSON") from exc


def _sandbox_string(path: Path) -> str:
    return json.dumps(str(path), ensure_ascii=False)


def _write_exclusive(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise ComparisonProcessError(f"refusing to replace process evidence: {path.name}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            written = handle.write(body)
            if written != len(body):
                raise OSError("short process evidence write")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _bounded_error(exc: BaseException) -> str:
    return (str(exc).strip() or type(exc).__name__)[:2000]


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "MODEL_GATEWAY_RECEIPT_FILE",
    "PAIRED_LOCAL",
    "PROCESS_RECEIPT_FILE",
    "PROCESS_RECEIPT_SCHEMA_VERSION",
    "SANDBOX_PROFILE_FILE",
    "STRICT_OFFICIAL",
    "ComparisonProcessBackend",
    "ComparisonProcessError",
    "read_bounded_json_receipt",
    "validate_comparison_process_receipt",
    "validate_comparison_process_receipt_public",
    "validate_unstarted_comparison_process_receipt",
]
