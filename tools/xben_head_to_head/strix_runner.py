"""Bounded adapter for one pinned Strix CLI benchmark row.

This module owns the Strix process, its run-labelled sandbox cleanup, and report
parsing. A caller remains responsible for starting and stopping the target. The model and
credential are injected into the child environment; neither is placed in the
Strix command or the generated empty config file.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
_IMMUTABLE_IMAGE_RE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}")
_SANDBOX_RUN_ID_RE = re.compile(r"[0-9a-f]{32}")
_SANDBOX_RUN_LABEL = "strix-run-id"
_FLAG_RE = re.compile(rb"(?i)(?:flag|xben|ctf|htb)\{[^}\r\n]{1,512}\}")
_VULNERABILITY_REPORT_RE = re.compile(r"vuln-[0-9]{4,}\.md")
_ACCEPTED_EXIT_CODES = frozenset({0, 2})
_MAX_RUN_RECORD_BYTES = 16 * 1024 * 1024
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_REPORT_FILES = 2048
_MAX_TOTAL_REPORT_BYTES = 128 * 1024 * 1024
_MAX_DOCKER_OUTPUT_BYTES = 1024 * 1024
_DOCKER_TIMEOUT_SECONDS = 30.0
_INHERITED_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
    }
)


class StrixRunnerError(ValueError):
    """Raised when a runner request is unsafe or internally inconsistent."""


@dataclass(frozen=True)
class StrixRunRequest:
    """Inputs for one non-interactive, deep Strix scan.

    ``executable_sha256`` pins the exact CLI launcher bytes.  A campaign should
    separately record the source commit and dependency lock used to build that
    launcher; this adapter cannot infer those identities from a console script.
    The pinned runtime must honor ``STRIX_RUN_ID`` with the ``strix-run-id``
    container label. Unattributed leftovers are preserved and invalidate cleanup.
    """

    executable: Path
    executable_sha256: str
    target_url: str
    instruction_file: Path
    working_directory: Path
    model: str
    sandbox_image: str
    api_key: str = field(repr=False)
    timeout_seconds: float = 600.0
    termination_grace_seconds: float = 5.0
    reasoning_effort: str = "high"
    max_budget_usd: float | None = None
    max_turns: int | None = None
    result_path: Path | None = None
    environment: Mapping[str, str] | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class _ValidatedRequest:
    executable: Path
    executable_sha256: str
    target_url: str
    instruction_file: Path
    instruction_text: str
    instruction_sha256: str
    working_directory: Path
    model: str
    sandbox_image: str
    api_key: str = field(repr=False)
    timeout_seconds: float
    termination_grace_seconds: float
    reasoning_effort: str
    max_budget_usd: float | None
    max_turns: int | None
    result_path: Path | None
    environment: Mapping[str, str] | None = field(repr=False, compare=False)


@dataclass(frozen=True)
class _ProcessOutcome:
    returncode: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class _RunRecordIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def run_strix(request: StrixRunRequest) -> dict[str, Any]:  # noqa: C901
    """Run one pinned Strix scan and return a JSON-serializable receipt.

    Exit code 0 (no filed findings) and Strix's documented CI exit code 2
    (findings filed) are eligible for completion only when the matched
    ``run.json`` also says ``"completed"``.  A budget-stopped scan can exit 0
    without finishing.  Report candidates are retained for diagnostics after
    the process group has been stopped; callers must only score completed rows.
    """

    validated = _validate_request(request)
    runs_dir = validated.working_directory / "strix_runs"
    before = _snapshot_run_records(runs_dir)
    config_path = _write_empty_config(validated.working_directory)
    try:
        mcp_config_path = _write_empty_mcp_config(validated.working_directory)
    except Exception:
        config_path.unlink(missing_ok=True)
        raise
    command = _build_command(
        validated,
        config_path=config_path,
        mcp_config_path=mcp_config_path,
    )
    sandbox_run_id = uuid4().hex
    environment = _build_environment(validated, sandbox_run_id=sandbox_run_id)
    docker_environment = _docker_environment(environment)

    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    launch_error: str | None = None
    outcome = _ProcessOutcome(
        returncode=None,
        timed_out=False,
        stdout=b"",
        stderr=b"",
    )
    container_cleanup = _new_container_cleanup_receipt(
        validated.sandbox_image, sandbox_run_id=sandbox_run_id
    )
    try:
        before_ids, before_receipt = _docker_container_ids(
            validated.sandbox_image,
            environment=docker_environment,
        )
        container_cleanup["before"] = before_receipt
        if before_ids is None:
            container_cleanup["error"] = "sandbox_container_inspection_failed_before_launch"
        else:
            container_cleanup["before_container_ids"] = sorted(before_ids)
            owned_before_ids, owned_before = _docker_container_ids(
                validated.sandbox_image,
                environment=docker_environment,
                sandbox_run_id=sandbox_run_id,
            )
            container_cleanup["ownership_before"] = owned_before
            if owned_before_ids is None or owned_before_ids:
                container_cleanup["error"] = "sandbox_container_ownership_namespace_not_empty"
            else:
                container_cleanup["launch_attempted"] = True
                try:
                    try:
                        outcome = _run_process(
                            command,
                            cwd=validated.working_directory,
                            environment=environment,
                            timeout_seconds=validated.timeout_seconds,
                            termination_grace_seconds=validated.termination_grace_seconds,
                        )
                    except OSError as exc:
                        launch_error = _redact(str(exc), validated.api_key)
                finally:
                    container_cleanup = _cleanup_new_sandbox_containers(
                        image=validated.sandbox_image,
                        before_ids=before_ids,
                        sandbox_run_id=sandbox_run_id,
                        environment=docker_environment,
                        receipt=container_cleanup,
                    )
    finally:
        config_path.unlink(missing_ok=True)
        mcp_config_path.unlink(missing_ok=True)
    duration_seconds = round(max(0.0, time.monotonic() - started), 6)

    run_dir, run_record, locator_error = _locate_specific_run(
        runs_dir,
        before=before,
        target_url=validated.target_url,
        instruction_text=validated.instruction_text,
    )
    report_artifacts: list[str] = []
    flag_candidates: list[str] = []
    usage: dict[str, int | float | None] | None = None
    strix_run_status: str | None = None
    if run_dir is not None and run_record is not None:
        strix_run_status = _optional_string(run_record.get("status"))
        report_paths = _declared_report_paths(run_dir)
        report_artifacts = [path.relative_to(run_dir).as_posix() for path in report_paths]
        flag_candidates = _extract_flag_candidates(
            report_paths,
            secret=validated.api_key,
        )
        usage = _parse_usage(run_record)

    if container_cleanup.get("verified") is not True:
        status = "error"
        error = str(container_cleanup.get("error") or "strix_sandbox_cleanup_unverified")
    elif launch_error is not None:
        status = "error"
        error = f"launch_failed: {launch_error}"
    elif outcome.timed_out:
        status = "timed_out"
        error = "strix_timeout"
    elif outcome.returncode not in _ACCEPTED_EXIT_CODES:
        status = "error"
        error = f"strix_exit_{outcome.returncode}"
    elif run_dir is None:
        status = "error"
        error = locator_error or "strix_run_output_not_found"
    elif strix_run_status != "completed":
        status = "error"
        error = "strix_run_status_not_completed"
    else:
        status = "completed"
        error = None

    result: dict[str, Any] = {
        "schema_version": 1,
        "system": "strix",
        "status": status,
        "valid": status == "completed" and container_cleanup.get("verified") is True,
        "error": error,
        "started_at": started_at,
        "duration_seconds": duration_seconds,
        "timed_out": outcome.timed_out,
        "exit_code": outcome.returncode,
        "completion_kind": (
            "findings_filed"
            if status == "completed" and outcome.returncode == 2
            else (
                "no_filed_findings" if status == "completed" and outcome.returncode == 0 else None
            )
        ),
        "target_url": validated.target_url,
        "instruction_sha256": validated.instruction_sha256,
        "model": validated.model,
        "reasoning_effort": validated.reasoning_effort,
        "sandbox_image": validated.sandbox_image,
        "executable": str(validated.executable),
        "executable_sha256": validated.executable_sha256,
        "command": list(command),
        "credential_transport": "environment:LLM_API_KEY",
        "model_transport": "environment:STRIX_LLM",
        "stdout_bytes": len(outcome.stdout),
        "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
        "stderr_bytes": len(outcome.stderr),
        "stderr_sha256": hashlib.sha256(outcome.stderr).hexdigest(),
        "run_directory": str(run_dir) if run_dir is not None else None,
        "strix_run_status": strix_run_status,
        "run_locator_error": locator_error,
        "container_cleanup": container_cleanup,
        "report_artifacts": report_artifacts,
        "flag_candidates": flag_candidates,
        "usage": usage,
    }
    # This is both an assertion and a stable conversion check for callers that
    # append receipts to a larger campaign document.
    json.dumps(result, allow_nan=False)
    if validated.result_path is not None:
        _write_json_atomic(validated.result_path, result)
    return result


def _validate_request(request: StrixRunRequest) -> _ValidatedRequest:  # noqa: C901
    requested_executable = request.executable.expanduser()
    try:
        executable = requested_executable.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise StrixRunnerError("Strix executable does not exist") from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise StrixRunnerError("Strix executable is not an executable regular file")

    expected_digest = request.executable_sha256.strip().lower()
    if _SHA256_RE.fullmatch(expected_digest) is None:
        raise StrixRunnerError("Strix executable SHA-256 is invalid")
    actual_digest = _sha256_file(executable)
    if actual_digest != expected_digest:
        raise StrixRunnerError("Strix executable does not match its SHA-256 pin")

    target_url = request.target_url.strip()
    parsed_target = urlsplit(target_url)
    if (
        parsed_target.scheme not in {"http", "https"}
        or not parsed_target.hostname
        or parsed_target.username is not None
        or parsed_target.password is not None
        or "\x00" in target_url
    ):
        raise StrixRunnerError("target URL must be an HTTP(S) URL without credentials")

    requested_instruction = request.instruction_file.expanduser()
    try:
        instruction_file = requested_instruction.resolve(strict=True)
        instruction_metadata = instruction_file.lstat()
    except (OSError, RuntimeError) as exc:
        raise StrixRunnerError("instruction file does not exist") from exc
    if not stat.S_ISREG(instruction_metadata.st_mode):
        raise StrixRunnerError("instruction path is not a regular file")
    if instruction_metadata.st_size > _MAX_REPORT_BYTES:
        raise StrixRunnerError("instruction file is too large")
    try:
        instruction_text = instruction_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise StrixRunnerError("instruction file is not readable UTF-8") from exc
    if not instruction_text or "\x00" in instruction_text:
        raise StrixRunnerError("instruction file is empty or invalid")

    working_directory = request.working_directory.expanduser()
    working_directory.mkdir(parents=True, exist_ok=True)
    try:
        working_metadata = working_directory.lstat()
        working_directory = working_directory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise StrixRunnerError("working directory is unavailable") from exc
    if not stat.S_ISDIR(working_metadata.st_mode) or stat.S_ISLNK(working_metadata.st_mode):
        raise StrixRunnerError("working directory must be a real directory, not a symlink")

    model = request.model.strip()
    if _MODEL_RE.fullmatch(model) is None:
        raise StrixRunnerError("Strix model name is invalid")
    sandbox_image = request.sandbox_image.strip()
    if _IMMUTABLE_IMAGE_RE.fullmatch(sandbox_image) is None:
        raise StrixRunnerError("Strix sandbox image must use an immutable sha256 digest")
    if not request.api_key or "\x00" in request.api_key:
        raise StrixRunnerError("LLM API key is empty or invalid")
    if not math.isfinite(request.timeout_seconds) or request.timeout_seconds <= 0:
        raise StrixRunnerError("timeout must be a finite positive number")
    if (
        not math.isfinite(request.termination_grace_seconds)
        or request.termination_grace_seconds < 0
    ):
        raise StrixRunnerError("termination grace must be a finite non-negative number")
    if request.reasoning_effort not in {
        "none",
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    }:
        raise StrixRunnerError("reasoning effort is invalid")
    if request.max_budget_usd is not None:
        if isinstance(request.max_budget_usd, bool) or not isinstance(
            request.max_budget_usd, int | float
        ):
            raise StrixRunnerError("maximum budget must be a finite positive number")
        if not math.isfinite(request.max_budget_usd) or request.max_budget_usd <= 0:
            raise StrixRunnerError("maximum budget must be a finite positive number")
    if request.max_turns is not None and (
        isinstance(request.max_turns, bool)
        or not isinstance(request.max_turns, int)
        or request.max_turns <= 0
    ):
        raise StrixRunnerError("maximum turns must be a positive integer")

    return _ValidatedRequest(
        executable=executable,
        executable_sha256=actual_digest,
        target_url=target_url,
        instruction_file=instruction_file,
        instruction_text=instruction_text,
        instruction_sha256=hashlib.sha256(instruction_text.encode("utf-8")).hexdigest(),
        working_directory=working_directory,
        model=model,
        sandbox_image=sandbox_image,
        api_key=request.api_key,
        timeout_seconds=float(request.timeout_seconds),
        termination_grace_seconds=float(request.termination_grace_seconds),
        reasoning_effort=request.reasoning_effort,
        max_budget_usd=request.max_budget_usd,
        max_turns=request.max_turns,
        result_path=request.result_path,
        environment=request.environment,
    )


def _write_empty_config(working_directory: Path) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=".strix-head-to-head-",
        suffix=".json",
        dir=working_directory,
        text=True,
    )
    path = Path(raw_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write('{"env":{}}\n')
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _write_empty_mcp_config(working_directory: Path) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=".strix-head-to-head-mcp-",
        suffix=".json",
        dir=working_directory,
        text=True,
    )
    path = Path(raw_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("[]\n")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _build_command(
    request: _ValidatedRequest,
    *,
    config_path: Path,
    mcp_config_path: Path,
) -> tuple[str, ...]:
    command = [
        str(request.executable),
        "--target",
        request.target_url,
        "--instruction-file",
        str(request.instruction_file),
        "--non-interactive",
        "--scan-mode",
        "deep",
        "--scope-mode",
        "full",
        "--config",
        str(config_path),
        "--mcp-config",
        str(mcp_config_path),
    ]
    if request.max_budget_usd is not None:
        command.extend(("--max-budget-usd", format(request.max_budget_usd, ".12g")))
    if request.max_turns is not None:
        command.extend(("--max-turns", str(request.max_turns)))
    return tuple(command)


def _build_environment(request: _ValidatedRequest, *, sandbox_run_id: str) -> dict[str, str]:
    source = os.environ if request.environment is None else request.environment
    environment = {
        str(name): str(value)
        for name, value in source.items()
        if name in _INHERITED_ENVIRONMENT_NAMES or name.startswith("LC_")
    }
    environment["LLM_API_KEY"] = request.api_key
    environment["STRIX_LLM"] = request.model
    environment["STRIX_REASONING_EFFORT"] = request.reasoning_effort
    environment["STRIX_TELEMETRY"] = "false"
    environment["STRIX_NO_UPDATE_CHECK"] = "1"
    environment["STRIX_RUNTIME_BACKEND"] = "docker"
    environment["STRIX_IMAGE"] = request.sandbox_image
    environment["STRIX_RUN_ID"] = sandbox_run_id
    environment["STRIX_RUN_TYPE"] = "ravage-xben-head-to-head"
    environment["STRIX_SANDBOX_LOG_MAX_SIZE"] = "10m"
    environment["STRIX_SANDBOX_LOG_MAX_FILE"] = "2"
    environment["NO_COLOR"] = "1"
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


def _docker_environment(environment: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in environment.items()
        if name in _INHERITED_ENVIRONMENT_NAMES or name.startswith("LC_")
    }


def _run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    termination_grace_seconds: float,
) -> _ProcessOutcome:
    process = subprocess.Popen(  # noqa: S603
        list(command),
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    previous_handlers: dict[signal.Signals, Any] = {}
    try:
        previous_handlers = _install_interrupt_handlers()
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
            return _ProcessOutcome(
                returncode=process.returncode,
                timed_out=False,
                stdout=stdout or b"",
                stderr=stderr or b"",
            )
        except subprocess.TimeoutExpired:
            _signal_process_group(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=termination_grace_seconds)
            except subprocess.TimeoutExpired:
                _signal_process_group(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
            else:
                # The direct process may honor TERM while a detached worker in
                # the same group ignores it and closes inherited pipes.
                _signal_process_group(process.pid, signal.SIGKILL)
            return _ProcessOutcome(
                returncode=process.returncode,
                timed_out=True,
                stdout=stdout or b"",
                stderr=stderr or b"",
            )
    except BaseException:
        _kill_and_reap_process_group(process)
        raise
    finally:
        _restore_interrupt_handlers(previous_handlers)


def _install_interrupt_handlers() -> dict[signal.Signals, Any]:
    if threading.current_thread() is not threading.main_thread():
        return {}
    previous: dict[signal.Signals, Any] = {}

    def raise_interrupt(received: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"received signal {received}")

    candidates = [signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        candidates.append(signal.SIGHUP)
    try:
        for requested_signal in candidates:
            previous[requested_signal] = signal.getsignal(requested_signal)
            signal.signal(requested_signal, raise_interrupt)
    except BaseException:
        _restore_interrupt_handlers(previous)
        raise
    return previous


def _restore_interrupt_handlers(previous: Mapping[signal.Signals, Any]) -> None:
    for requested_signal, handler in previous.items():
        signal.signal(requested_signal, handler)


def _kill_and_reap_process_group(process: subprocess.Popen[bytes]) -> None:
    _signal_process_group(process.pid, signal.SIGKILL)
    try:
        process.communicate(timeout=5.0)
    except subprocess.TimeoutExpired:
        _signal_process_group(process.pid, signal.SIGKILL)
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.communicate()
    except OSError:
        try:
            process.wait(timeout=5.0)
        except (OSError, subprocess.TimeoutExpired):
            return


def _signal_process_group(process_group_id: int, requested_signal: signal.Signals) -> None:
    try:
        os.killpg(process_group_id, requested_signal)
    except ProcessLookupError:
        return


def _new_container_cleanup_receipt(image: str, *, sandbox_run_id: str) -> dict[str, Any]:
    return {
        "sandbox_image": image,
        "sandbox_run_id": sandbox_run_id,
        "ownership_label": _SANDBOX_RUN_LABEL,
        "ownership_before": None,
        "ownership_inspection": None,
        "foreign_new_container_ids": [],
        "unattributed_new_container_ids": [],
        "launch_attempted": False,
        "before": None,
        "before_container_ids": [],
        "after_process": None,
        "after_process_container_ids": [],
        "new_leftover_container_ids": [],
        "remove": None,
        "after_cleanup": None,
        "remaining_new_container_ids": [],
        "verified": False,
        "error": None,
    }


def _cleanup_new_sandbox_containers(
    *,
    image: str,
    before_ids: set[str],
    sandbox_run_id: str,
    environment: Mapping[str, str],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    after_ids, after_receipt = _docker_container_ids(image, environment=environment)
    receipt["after_process"] = after_receipt
    if after_ids is None:
        receipt["error"] = "sandbox_container_inspection_failed_after_process"
        return receipt
    receipt["after_process_container_ids"] = sorted(after_ids)
    observed_new_ids = after_ids - before_ids
    owners, ownership_receipt = _docker_container_owners(observed_new_ids, environment=environment)
    receipt["ownership_inspection"] = ownership_receipt
    if owners is None:
        receipt["unattributed_new_container_ids"] = sorted(observed_new_ids)
        receipt["error"] = "sandbox_container_ownership_unverified"
        return receipt
    owned_ids = {container_id for container_id, owner in owners.items() if owner == sandbox_run_id}
    unattributed_ids = {container_id for container_id, owner in owners.items() if owner is None}
    receipt["new_leftover_container_ids"] = sorted(owned_ids)
    receipt["unattributed_new_container_ids"] = sorted(unattributed_ids)
    receipt["foreign_new_container_ids"] = sorted(observed_new_ids - owned_ids - unattributed_ids)

    remove_receipt = None
    if owned_ids:
        remove_receipt = _docker_remove_containers(owned_ids, environment=environment)
        receipt["remove"] = remove_receipt
    final_ids, final_receipt = _docker_container_ids(
        image, environment=environment, sandbox_run_id=sandbox_run_id
    )
    receipt["after_cleanup"] = final_receipt
    if final_ids is None:
        receipt["remaining_new_container_ids"] = sorted(owned_ids)
        receipt["error"] = "sandbox_container_inspection_failed_after_cleanup"
        return receipt
    remaining = final_ids
    receipt["remaining_new_container_ids"] = sorted(remaining)
    if (remove_receipt is not None and remove_receipt.get("returncode") != 0) or remaining:
        receipt["error"] = "sandbox_container_cleanup_failed"
        return receipt
    if unattributed_ids:
        # Older runtimes may ignore STRIX_RUN_ID.  Their leftovers cannot be
        # distinguished safely from another workload, so preserve them and fail.
        receipt["error"] = "sandbox_container_ownership_unverified"
        return receipt
    receipt["verified"] = True
    return receipt


def _docker_container_ids(
    image: str,
    *,
    environment: Mapping[str, str],
    sandbox_run_id: str | None = None,
) -> tuple[set[str] | None, dict[str, Any]]:
    command = ("docker", "ps", "--all", "--quiet", "--no-trunc", "--filter", f"ancestor={image}")
    if sandbox_run_id is not None:
        if _SANDBOX_RUN_ID_RE.fullmatch(sandbox_run_id) is None:
            raise StrixRunnerError("sandbox cleanup received an invalid run ID")
        command += ("--filter", f"label={_SANDBOX_RUN_LABEL}={sandbox_run_id}")
    outcome, receipt = _run_docker_command(
        command,
        operation="inspect_sandbox_containers",
        environment=environment,
    )
    if outcome is None or outcome.returncode != 0:
        return None, receipt
    try:
        lines = outcome.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError:
        receipt["valid_output"] = False
        return None, receipt
    if any(_CONTAINER_ID_RE.fullmatch(line) is None for line in lines):
        receipt["valid_output"] = False
        return None, receipt
    receipt["valid_output"] = True
    return set(lines), receipt


def _docker_container_owners(
    container_ids: set[str],
    *,
    environment: Mapping[str, str],
) -> tuple[dict[str, str | None] | None, dict[str, Any] | None]:
    if not container_ids:
        return {}, None
    ordered = sorted(container_ids)
    if any(_CONTAINER_ID_RE.fullmatch(value) is None for value in ordered):
        raise StrixRunnerError("sandbox ownership inspection received an invalid container ID")
    outcome, receipt = _run_docker_command(
        ("docker", "inspect", "--type", "container", *ordered),
        operation="inspect_sandbox_container_ownership",
        environment=environment,
    )
    if outcome is None or outcome.returncode != 0:
        return None, receipt
    try:
        records = json.loads(outcome.stdout)
    except (ValueError, UnicodeError):
        return None, receipt
    if not isinstance(records, list) or len(records) != len(ordered):
        return None, receipt
    owners: dict[str, str | None] = {}
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("Id"), str)
            or record["Id"] not in container_ids
        ):
            return None, receipt
        container_id = record["Id"]
        if container_id in owners:
            return None, receipt
        config = record.get("Config")
        if not isinstance(config, dict):
            return None, receipt
        labels = config.get("Labels")
        if labels is None:
            labels = {}
        if not isinstance(labels, dict):
            return None, receipt
        owner = labels.get(_SANDBOX_RUN_LABEL)
        if owner is not None and not isinstance(owner, str):
            return None, receipt
        owners[container_id] = owner or None
    return owners, receipt


def _docker_remove_containers(
    container_ids: set[str],
    *,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    ordered = sorted(container_ids)
    if not ordered or any(_CONTAINER_ID_RE.fullmatch(value) is None for value in ordered):
        raise StrixRunnerError("sandbox cleanup received an invalid container ID")
    _outcome, receipt = _run_docker_command(
        ("docker", "rm", "--force", *ordered),
        operation="force_remove_owned_sandbox_containers",
        environment=environment,
    )
    receipt["container_ids"] = ordered
    return receipt


def _run_docker_command(
    command: Sequence[str],
    *,
    operation: str,
    environment: Mapping[str, str],
) -> tuple[subprocess.CompletedProcess[bytes] | None, dict[str, Any]]:
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603
            list(command),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=_DOCKER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, {
            "operation": operation,
            "returncode": None,
            "stdout_bytes": 0,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "elapsed_seconds": round(max(0.0, time.monotonic() - started), 6),
            "error": type(exc).__name__,
        }
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    receipt: dict[str, Any] = {
        "operation": operation,
        "returncode": completed.returncode,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "elapsed_seconds": round(max(0.0, time.monotonic() - started), 6),
        "error": None,
    }
    if len(stdout) > _MAX_DOCKER_OUTPUT_BYTES or len(stderr) > _MAX_DOCKER_OUTPUT_BYTES:
        receipt["error"] = "docker_command_output_limit_exceeded"
        return None, receipt
    return completed, receipt


def _snapshot_run_records(runs_dir: Path) -> dict[Path, _RunRecordIdentity]:
    snapshot: dict[Path, _RunRecordIdentity] = {}
    if not runs_dir.is_dir() or runs_dir.is_symlink():
        return snapshot
    try:
        children = sorted(runs_dir.iterdir(), key=lambda path: path.name)
    except OSError:
        return snapshot
    for child in children:
        record_path = child / "run.json"
        identity = _run_record_identity(record_path)
        if identity is not None:
            snapshot[record_path] = identity
    return snapshot


def _run_record_identity(path: Path) -> _RunRecordIdentity | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return None
    return _RunRecordIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _locate_specific_run(
    runs_dir: Path,
    *,
    before: Mapping[Path, _RunRecordIdentity],
    target_url: str,
    instruction_text: str,
) -> tuple[Path | None, dict[str, Any] | None, str | None]:
    after = _snapshot_run_records(runs_dir)
    changed = [path for path, identity in after.items() if before.get(path) != identity]
    matches: list[tuple[Path, dict[str, Any]]] = []
    for record_path in changed:
        record = _read_run_record(record_path)
        if record is None:
            continue
        if _run_record_matches(
            record_path,
            record,
            target_url=target_url,
            instruction_text=instruction_text,
        ):
            matches.append((record_path.parent, record))
    if len(matches) == 1:
        return matches[0][0], matches[0][1], None
    if len(matches) > 1:
        return None, None, "multiple_matching_strix_run_outputs"
    if changed:
        return None, None, "changed_strix_outputs_did_not_match_this_invocation"
    return None, None, "strix_run_output_not_found"


def _read_run_record(path: Path) -> dict[str, Any] | None:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_RUN_RECORD_BYTES
        ):
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _run_record_matches(
    record_path: Path,
    record: Mapping[str, Any],
    *,
    target_url: str,
    instruction_text: str,
) -> bool:
    run_name = record.get("run_name") or record.get("run_id")
    if not isinstance(run_name, str) or run_name != record_path.parent.name:
        return False
    targets = record.get("targets_info")
    if not isinstance(targets, list) or len(targets) != 1:
        return False
    target = targets[0]
    if not isinstance(target, dict) or target.get("original") != target_url:
        return False
    if record.get("scan_mode") != "deep" or record.get("non_interactive") is not True:
        return False
    instruction = record.get("user_instruction")
    if not isinstance(instruction, str) or not instruction.strip():
        instruction = record.get("instruction")
    return isinstance(instruction, str) and instruction.strip() == instruction_text


def _declared_report_paths(run_dir: Path) -> list[Path]:
    fixed_names = (
        "penetration_test_report.md",
        "vulnerabilities.json",
        "vulnerabilities.csv",
        "coverage.json",
        "findings.sarif",
    )
    paths = [path for name in fixed_names if _is_safe_report(path := run_dir / name, run_dir)]
    vulnerability_dir = run_dir / "vulnerabilities"
    if vulnerability_dir.is_dir() and not vulnerability_dir.is_symlink():
        try:
            children = sorted(vulnerability_dir.iterdir(), key=lambda path: path.name)
        except OSError:
            children = []
        paths.extend(
            path
            for path in children
            if _VULNERABILITY_REPORT_RE.fullmatch(path.name) and _is_safe_report(path, run_dir)
        )
    return paths[:_MAX_REPORT_FILES]


def _is_safe_report(path: Path, run_dir: Path) -> bool:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(run_dir.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_size <= _MAX_REPORT_BYTES
    )


def _extract_flag_candidates(paths: Sequence[Path], *, secret: str) -> list[str]:
    candidates: set[bytes] = set()
    scanned_bytes = 0
    secret_bytes = secret.encode("utf-8")
    for path in paths:
        try:
            size = path.stat().st_size
            if scanned_bytes + size > _MAX_TOTAL_REPORT_BYTES:
                break
            payload = path.read_bytes()
        except OSError:
            continue
        scanned_bytes += len(payload)
        for match in _FLAG_RE.finditer(payload):
            candidate = match.group(0)
            if secret_bytes and secret_bytes in candidate:
                continue
            candidates.add(candidate)
    return sorted(candidate.decode("utf-8", errors="replace") for candidate in candidates)


def _parse_usage(run_record: Mapping[str, Any]) -> dict[str, int | float | None] | None:
    raw = run_record.get("llm_usage")
    if not isinstance(raw, dict):
        return None
    input_details = raw.get("input_tokens_details")
    if isinstance(input_details, dict):
        cached_tokens = _non_negative_int(input_details.get("cached_tokens"))
    elif isinstance(input_details, list) and input_details:
        counts = [
            _non_negative_int(detail.get("cached_tokens")) if isinstance(detail, dict) else None
            for detail in input_details
        ]
        cached_tokens = (
            sum(count for count in counts if count is not None)
            if all(count is not None for count in counts)
            else None
        )
    else:
        cached_tokens = None
    usage: dict[str, int | float | None] = {
        "requests": _non_negative_int(raw.get("requests")),
        "input_tokens": _non_negative_int(raw.get("input_tokens")),
        "cached_input_tokens": cached_tokens,
        "output_tokens": _non_negative_int(raw.get("output_tokens")),
        "total_tokens": _non_negative_int(raw.get("total_tokens")),
        "cost_usd": _non_negative_float(raw.get("cost")),
    }
    return usage


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    converted = int(value)
    return converted if converted >= 0 and converted == value else None


def _non_negative_float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    converted = float(value)
    return converted if math.isfinite(converted) and converted >= 0 else None


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _redact(value: str, secret: str) -> str:
    return value.replace(secret, "[REDACTED]") if secret else value


def _write_json_atomic(path: Path, document: Mapping[str, Any]) -> None:
    destination = path.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        text=True,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
