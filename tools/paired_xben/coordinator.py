# ruff: noqa: C901,D202,D213,E501,EM101,EM102,PLR0913,PLR0915,PLR2004,RET504,S108,TC002,TRY003
"""One-shot coordinator for an already resolved paired-XBEN primary matrix.

This module deliberately cannot draw cases, reserve individual rows, resume an
interrupted campaign, or create diagnostic reruns.  Its production entry point
accepts only the operational ``paired_local`` evidence class; that mode is
useful for an honest same-host comparison but is not a cryptographic SOTA
attestation.
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
import socket
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Final, Literal, Protocol, cast
from urllib.parse import quote, quote_plus, urlsplit

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PACKAGE_SOURCE = (_REPOSITORY_ROOT / "packages" / "ravage" / "src").resolve(strict=True)
if str(_PACKAGE_SOURCE) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SOURCE))

from ravage.xben_parts.cases import load_xben_cases  # noqa: E402
from ravage.xben_parts.comparison_adapters import (  # noqa: E402
    ADAPTER_VERSION,
    CANDIDATE_ARTIFACT_PATH,
    GATEWAY_BASE_URL_ENV,
    GatewayPricing,
    PinnedAgentRuntime,
    RowModelGateway,
    build_ravage_agent,
    build_strix_agent,
)
from ravage.xben_parts.comparison_model_gateway import (  # noqa: E402
    ComparisonModelGateway,
    ModelGatewayPolicy,
    ModelPricing,
)
from ravage.xben_parts.comparison_process_backend import (  # noqa: E402
    PAIRED_LOCAL,
    ComparisonProcessBackend,
)
from ravage.xben_parts.comparison_target import (  # noqa: E402
    BoundedSubprocessRunner,
    CommandResult,
    CommandRunner,
    CompatibilityPatchCatalog,
    DockerComparisonTargetBackend,
    DockerTargetConfiguration,
    GatewayConfiguration,
    PinnedGitCaseMaterializer,
    PinnedXbenSource,
    PreparedCase,
    PreparedTargetArmBackend,
    ProbeConfiguration,
)
from ravage.xben_parts.external_comparison import (  # noqa: E402
    COMPARISON_GATEWAY_TOKEN_ENV,
    OUTER_PROCESS_GROUP_ENV,
    OUTER_PROCESS_GROUP_VALUE,
    ComparisonRowBinding,
    ExternalAgentCommand,
    ExternalExecutionLimits,
    ExternalProcessBackend,
    ExternalTargetBackend,
    record_unstarted_external_xben_row,
    run_external_xben_row,
)
from ravage.xben_parts.http_meter_gateway import program_sha256  # noqa: E402
from ravage.xben_parts.models import XbenCase  # noqa: E402

from tools.paired_xben.protocol import (  # noqa: E402
    PairedXbenProtocolError,
    validate_run_contract,
    verify_campaign,
)

EXECUTOR_CONFIG_SCHEMA: Final = "ravage.paired-xben.executor-config.v1"
EXECUTION_START_SCHEMA: Final = "ravage.paired-xben.execution-start.v1"
EXECUTION_TERMINAL_SCHEMA: Final = "ravage.paired-xben.execution-terminal.v1"
PRIMARY_RESULTS_SCHEMA: Final = "ravage.paired-xben.primary-results.v1"
MODEL_CAMPAIGN_RECEIPT_FILE: Final = "campaign-model-gateway.json"
PRIMARY_RESULTS_FILE: Final = "primary-results.json"
EXECUTION_DIRECTORY: Final = "execution"
ROW_DIRECTORY: Final = "row"
EXPECTED_ROWS: Final = 40
EXPECTED_PAIRS: Final = 20
SYSTEMS: Final = ("ravage", "strix")
_ROW_RE = re.compile(r"primary-(\d{3})")
_CASE_RE = re.compile(r"XBEN-\d{3}-24")
_INSTANCE_RE = re.compile(r"xben-row-[0-9a-f]{32}")
_GATEWAY_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,256}")
_PAIR_FLAG_RE = re.compile(r"flag\{ravage_cmp_([0-9a-f]{64})\}")
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_RAW_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SAFE_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_TERMINAL_STATUSES = frozenset({"solved", "failed", "timed_out", "errored", "infrastructure_error"})
_AGENT_NETWORK_LABEL = "com.ravage.evaluator.agent-network"
_INSTANCE_LABEL = "com.ravage.evaluator.instance"
_MAX_JSON_BYTES = 1024 * 1024
_UNSTARTED_GATEWAY_BASE_URL = "http://127.0.0.1:1/v1"


class CampaignCoordinatorError(RuntimeError):
    """A resolved campaign cannot be executed without weakening its contract."""


class CampaignAlreadyStartedError(CampaignCoordinatorError):
    """The one-shot campaign execution namespace already exists."""


@dataclass(frozen=True)
class ScheduledRow:
    """One immutable row from the verified selection schedule."""

    slot_id: str
    case_id: str
    system: Literal["ravage", "strix"]
    pair_index: int
    position_within_pair: int
    artifact_root: Path


@dataclass(frozen=True)
class ResolvedCampaignPlan:
    """The minimum verified state the one-shot executor is permitted to use."""

    campaign_root: Path
    campaign_id: str
    commitment_digest: str
    selection_digest: str
    primary_matrix_digest: str
    run_contract: Mapping[str, object]
    schedule: tuple[ScheduledRow, ...]


class CampaignGateway(Protocol):
    """Narrow gateway surface needed by the coordinator."""

    @property
    def base_url(self) -> str: ...

    @property
    def policy_digest(self) -> str: ...

    def register_row(
        self,
        row_id: str,
        *,
        max_requests: int,
        max_cost_usd: Decimal | str | int,
    ) -> str: ...

    def start(self) -> None: ...

    def close(self) -> None: ...

    def seal_primary_campaign(self, output_path: Path) -> dict[str, object]: ...


@dataclass(frozen=True)
class AgentNetworkLease:
    """Exact evaluator-created Docker network identity for one target arm."""

    instance_id: str
    name: str
    network_id: str


@dataclass(frozen=True)
class RowExecutionContext:
    """All secret-bearing row state, kept only in evaluator memory."""

    row: ScheduledRow
    instance_id: str
    network_name: str
    agent: ExternalAgentCommand
    process_backend: object
    setup_error: str | None = None


class PreparedHandle(Protocol):
    pair_id: str
    benchmark_id: str
    evidence_dir: Path


class CampaignExecutionRuntime(Protocol):
    """Injectable side-effect boundary; production and fakes share one scheduler."""

    def validate_plan(self, plan: ResolvedCampaignPlan) -> None: ...

    def load_selected_cases(self, plan: ResolvedCampaignPlan) -> Mapping[str, XbenCase]: ...

    def create_gateway(self, plan: ResolvedCampaignPlan) -> CampaignGateway: ...

    def build_row_context(
        self,
        *,
        plan: ResolvedCampaignPlan,
        row: ScheduledRow,
        gateway: CampaignGateway,
        row_token: str,
        gateway_base_url: str,
        instance_id: str,
        network_name: str,
    ) -> RowExecutionContext: ...

    def build_unstarted_row_context(
        self,
        *,
        plan: ResolvedCampaignPlan,
        row: ScheduledRow,
        gateway: CampaignGateway,
        row_token: str,
        gateway_base_url: str,
        instance_id: str,
        network_name: str,
    ) -> RowExecutionContext: ...

    def create_agent_network(self, context: RowExecutionContext) -> AgentNetworkLease: ...

    def create_target_backend(
        self,
        *,
        plan: ResolvedCampaignPlan,
        context: RowExecutionContext,
        lease: AgentNetworkLease,
    ) -> DockerComparisonTargetBackend: ...

    def prepare_pair(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        pair_id: str,
        backend: DockerComparisonTargetBackend,
    ) -> PreparedHandle: ...

    def arm_target_backend(
        self,
        *,
        prepared: PreparedHandle,
        context: RowExecutionContext,
        backend: DockerComparisonTargetBackend,
    ) -> ExternalTargetBackend: ...

    def run_row(
        self,
        *,
        plan: ResolvedCampaignPlan,
        context: RowExecutionContext,
        case: XbenCase,
        expected_flag: str,
        target_backend: ExternalTargetBackend,
    ) -> Mapping[str, object]: ...

    def record_unstarted(
        self,
        *,
        plan: ResolvedCampaignPlan,
        context: RowExecutionContext,
        case: XbenCase,
        expected_flag: str,
        reason: str,
    ) -> Mapping[str, object]: ...

    def release_pair(
        self,
        *,
        prepared: PreparedHandle,
        backend: DockerComparisonTargetBackend,
    ) -> Mapping[str, object]: ...

    def terminalize_prepared_arm(
        self,
        *,
        prepared: PreparedHandle,
        context: RowExecutionContext,
        backend: DockerComparisonTargetBackend,
    ) -> Mapping[str, object]: ...

    def remove_agent_network(self, lease: AgentNetworkLease) -> None: ...


@dataclass(frozen=True)
class _PairEvidence:
    pair_index: int
    case_id: str
    pair_id: str | None
    prepared_path: Path | None
    release_path: Path | None


def load_verified_execution_plan(campaign_dir: Path) -> ResolvedCampaignPlan:
    """Load a complete reserved matrix only after protocol verification succeeds."""

    root = _resolved_directory(campaign_dir, "campaign directory")
    try:
        verification = verify_campaign(root, require_all_primary_attempts=True)
    except (OSError, PairedXbenProtocolError) as exc:
        raise CampaignCoordinatorError(f"campaign verification failed: {exc}") from exc
    if (
        verification.get("phase") != "resolved"
        or verification.get("structurally_valid") is not True
        or verification.get("primary_matrix_reserved") is not True
        or verification.get("recorded_primary_attempts") != EXPECTED_ROWS
        or verification.get("missing_primary_attempts") != 0
        or verification.get("scheduled_primary_attempts") != EXPECTED_ROWS
        or verification.get("diagnostic_reruns") != 0
    ):
        raise CampaignCoordinatorError(
            "campaign must be resolved with one complete untouched 40-row primary matrix"
        )

    commitment = _load_json(root / "commitment.json", "campaign commitment")
    selection = _load_json(root / "resolution" / "selection.json", "selection")
    reservation = _load_json(
        root / "attempts" / "primary-reservation.json",
        "primary matrix reservation",
    )
    campaign_id = _required_text(commitment.get("campaign_id"), "campaign ID")
    commitment_digest = _digest(commitment.get("document_digest"), "commitment digest")
    selection_digest = _digest(selection.get("document_digest"), "selection digest")
    matrix_digest = _digest(reservation.get("document_digest"), "matrix digest")
    if (
        verification.get("campaign_id") != campaign_id
        or verification.get("commitment_digest") != commitment_digest
        or verification.get("selection_digest") != selection_digest
        or verification.get("primary_matrix_digest") != matrix_digest
        or selection.get("campaign_id") != campaign_id
        or selection.get("commitment_digest") != commitment_digest
        or reservation.get("campaign_id") != campaign_id
        or reservation.get("commitment_digest") != commitment_digest
        or reservation.get("selection_digest") != selection_digest
    ):
        raise CampaignCoordinatorError("verified campaign bindings disagree")
    raw_contract = commitment.get("run_contract")
    if not isinstance(raw_contract, Mapping):
        raise CampaignCoordinatorError("commitment has no frozen run contract")
    try:
        contract = validate_run_contract(raw_contract)
    except PairedXbenProtocolError as exc:
        raise CampaignCoordinatorError(f"frozen run contract is invalid: {exc}") from exc
    _validate_contract_for_local_execution(contract, root=root)
    schedule = _load_exact_schedule(selection, root=root)
    _assert_execution_unclaimed(root)
    return ResolvedCampaignPlan(
        campaign_root=root,
        campaign_id=campaign_id,
        commitment_digest=commitment_digest,
        selection_digest=selection_digest,
        primary_matrix_digest=matrix_digest,
        run_contract=contract,
        schedule=schedule,
    )


def execute_paired_campaign(
    campaign_dir: Path,
    *,
    runtime: CampaignExecutionRuntime,
) -> dict[str, object]:
    """Execute all forty reserved primaries once, in their exact adjacent order.

    The caller cannot provide a subset, order, retry policy, seed, or flag.  A
    second invocation is refused as soon as the create-only execution namespace
    exists.  Individual failures are terminal observations and never alter the
    remaining schedule.
    """

    plan = load_verified_execution_plan(campaign_dir)
    execution_root = _claim_execution_root(plan.campaign_root)
    try:
        cases = _load_exact_runtime_cases(plan, runtime=runtime)
    except BaseException as exc:  # noqa: BLE001 - an admitted campaign is permanently terminal.
        _write_claimed_failure_terminal(
            plan,
            execution_root=execution_root,
            stage="runtime_preflight",
            failure=exc,
        )
        raise
    return _execute_claimed_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        execution_root=execution_root,
        flag_hex=secrets.token_hex,
        instance_hex=secrets.token_hex,
    )


def _load_exact_runtime_cases(
    plan: ResolvedCampaignPlan,
    *,
    runtime: CampaignExecutionRuntime,
) -> dict[str, XbenCase]:
    """Run every runtime-controlled preflight only after one-shot admission."""

    runtime.validate_plan(plan)
    cases = dict(runtime.load_selected_cases(plan))
    expected_case_ids = {row.case_id for row in plan.schedule}
    if set(cases) != expected_case_ids or any(
        case.benchmark_id != case_id for case_id, case in cases.items()
    ):
        raise CampaignCoordinatorError("runtime did not load exactly the 20 selected XBEN cases")
    return cases


def _execute_loaded_campaign(
    plan: ResolvedCampaignPlan,
    *,
    runtime: CampaignExecutionRuntime,
    cases: Mapping[str, XbenCase],
    flag_hex: Callable[[int], str] = secrets.token_hex,
    instance_hex: Callable[[int], str] = secrets.token_hex,
) -> dict[str, object]:
    """Run the deterministic internal seam used only by fake-backed tests."""

    _validate_loaded_plan(plan)
    expected_case_ids = {row.case_id for row in plan.schedule}
    if set(cases) != expected_case_ids or any(
        case.benchmark_id != case_id for case_id, case in cases.items()
    ):
        raise CampaignCoordinatorError("loaded cases differ from the verified schedule")
    execution_root = _claim_execution_root(plan.campaign_root)
    return _execute_claimed_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        execution_root=execution_root,
        flag_hex=flag_hex,
        instance_hex=instance_hex,
    )


def _execute_claimed_campaign(  # noqa: PLR0912
    plan: ResolvedCampaignPlan,
    *,
    runtime: CampaignExecutionRuntime,
    cases: Mapping[str, XbenCase],
    execution_root: Path,
    flag_hex: Callable[[int], str],
    instance_hex: Callable[[int], str],
) -> dict[str, object]:
    """Execute only after the caller has atomically claimed this campaign."""

    errors: list[dict[str, object]] = []
    pair_evidence: list[_PairEvidence] = []
    terminal_slots: set[str] = set()
    gateway: CampaignGateway | None = None
    pair_flags: tuple[str, ...] = ()
    tokens: dict[str, str] = {}
    try:
        # The create-only claim is deliberately earlier than every evaluator
        # entropy draw and runtime hook.  A failing source or setup boundary can
        # therefore never be repaired and redrawn under the same campaign.
        row_instances = _new_row_instances(plan.schedule, instance_hex=instance_hex)
        pair_flags = _new_pair_flags(flag_hex=flag_hex)
        gateway = runtime.create_gateway(plan)
        tokens = _register_complete_gateway(plan, gateway=gateway)
        # These contexts are the sole trusted way to seal registered rows that
        # never launch.  If construction fails, retain a campaign-level failure
        # because a complete forty-row terminal seal is no longer possible.
        unstarted_contexts = _build_complete_unstarted_contexts(
            plan,
            runtime=runtime,
            gateway=gateway,
            tokens=tokens,
            row_instances=row_instances,
        )
    except BaseException as exc:  # noqa: BLE001 - admission must survive every setup failure.
        errors.append(
            _error_record(
                "campaign_setup",
                exc,
                sensitive_values=(*pair_flags, *tokens.values()),
            )
        )
        if gateway is not None:
            try:
                gateway.close()
            except BaseException as close_exc:  # noqa: BLE001 - still retain the poison receipt.
                errors.append(
                    _error_record(
                        "gateway_close",
                        close_exc,
                        sensitive_values=(*pair_flags, *tokens.values()),
                    )
                )
        _write_incomplete_execution_terminal(
            plan,
            execution_root=execution_root,
            terminal_slots=terminal_slots,
            pair_evidence=pair_evidence,
            errors=errors,
        )
        raise

    assert gateway is not None  # assigned by the successful setup block above
    contexts: dict[str, RowExecutionContext] = {}
    prepared_terminal_slots: set[str] = set()
    gateway_started = False
    gateway_close_failed = False
    resource_cleanup_failed = False
    scheduler_failure: BaseException | None = None
    gateway_base_url = _UNSTARTED_GATEWAY_BASE_URL
    try:
        _write_execution_start(
            plan,
            execution_root=execution_root,
            row_instances=row_instances,
        )
        try:
            gateway.start()
            gateway_base_url = _validated_loopback_gateway_url(gateway.base_url)
            gateway_started = True
        except Exception as exc:  # noqa: BLE001 - all reserved rows still become terminal.
            errors.append(
                _error_record(
                    "gateway_start",
                    exc,
                    sensitive_values=(*pair_flags, *tokens.values()),
                )
            )

        for row in plan.schedule:
            network_name = _network_name(row_instances[row.slot_id])
            try:
                context = runtime.build_row_context(
                    plan=plan,
                    row=row,
                    gateway=gateway,
                    row_token=tokens[row.slot_id],
                    gateway_base_url=gateway_base_url,
                    instance_id=row_instances[row.slot_id],
                    network_name=network_name,
                )
                _validate_row_context(context, expected=row)
            except Exception as exc:  # noqa: BLE001 - retain a zero-launch fallback receipt.
                errors.append(
                    _error_record(
                        "row_context",
                        exc,
                        row=row,
                        sensitive_values=(*pair_flags, *tokens.values()),
                    )
                )
                context = unstarted_contexts[row.slot_id]
            contexts[row.slot_id] = context

        for pair_offset in range(0, EXPECTED_ROWS, 2):
            first, second = plan.schedule[pair_offset : pair_offset + 2]
            pair_contexts = tuple(
                contexts[row.slot_id] for row in (first, second) if row.slot_id in contexts
            )
            case = cases[first.case_id]
            pair_index = first.pair_index
            pair_id = f"pair-{pair_index:03d}"
            expected_flag = pair_flags[pair_index - 1]
            leases: dict[str, AgentNetworkLease] = {}
            backends: dict[str, DockerComparisonTargetBackend] = {}
            prepared: PreparedHandle | None = None
            setup_reason: str | None = None

            if len(pair_contexts) != 2:
                setup_reason = "paired row context construction failed"
            elif not gateway_started:
                setup_reason = "campaign model gateway did not start"
            elif any(context.setup_error for context in pair_contexts):
                setup_reason = "paired row setup failed before target preparation"

            if setup_reason is None:
                for context in pair_contexts:
                    try:
                        lease = runtime.create_agent_network(context)
                        # Retain the lease before validating it so a malformed
                        # runtime response still receives one cleanup attempt.
                        leases[context.row.slot_id] = lease
                        _validate_network_lease(lease, context=context)
                        backends[context.row.slot_id] = runtime.create_target_backend(
                            plan=plan,
                            context=context,
                            lease=lease,
                        )
                    except Exception as exc:  # noqa: BLE001 - both arms are terminalized.
                        errors.append(
                            _error_record(
                                "pair_provision",
                                exc,
                                row=context.row,
                                sensitive_values=_row_sensitive_values(
                                    context,
                                    expected_flag=expected_flag,
                                ),
                            )
                        )
                        setup_reason = "paired target network provisioning failed"
                        break

            if setup_reason is None:
                try:
                    prepared = runtime.prepare_pair(
                        case=case,
                        expected_flag=expected_flag,
                        pair_id=pair_id,
                        backend=backends[first.slot_id],
                    )
                    _validate_prepared_handle(prepared, pair_id=pair_id, case_id=case.benchmark_id)
                except Exception as exc:  # noqa: BLE001 - failed build is the pair outcome.
                    errors.append(
                        _error_record(
                            "pair_prepare",
                            exc,
                            row=first,
                            sensitive_values=(expected_flag,),
                        )
                    )
                    setup_reason = "paired target preparation failed"

            if setup_reason is not None:
                for context in pair_contexts:
                    try:
                        result = runtime.record_unstarted(
                            plan=plan,
                            context=context,
                            case=case,
                            expected_flag=expected_flag,
                            reason=setup_reason,
                        )
                        _validate_terminal_result(result, context.row)
                        terminal_slots.add(context.row.slot_id)
                    except Exception as exc:  # noqa: BLE001 - never retry a failed evidence write.
                        errors.append(
                            _error_record(
                                "row_terminalize",
                                exc,
                                row=context.row,
                                sensitive_values=_row_sensitive_values(
                                    context,
                                    expected_flag=expected_flag,
                                ),
                            )
                        )
                        if _recover_retained_terminal_result(context.row):
                            terminal_slots.add(context.row.slot_id)
                pair_evidence.append(_PairEvidence(pair_index, case.benchmark_id, None, None, None))
                for lease in leases.values():
                    if not _remove_network_once(runtime, lease, errors=errors):
                        resource_cleanup_failed = True
                continue

            assert prepared is not None  # narrowed by setup_reason
            for context in pair_contexts:
                row = context.row
                try:
                    target = runtime.arm_target_backend(
                        prepared=prepared,
                        context=context,
                        backend=backends[row.slot_id],
                    )
                    result = runtime.run_row(
                        plan=plan,
                        context=context,
                        case=case,
                        expected_flag=expected_flag,
                        target_backend=target,
                    )
                    prepared_terminal_slots.add(row.slot_id)
                    _validate_terminal_result(result, row)
                    terminal_slots.add(row.slot_id)
                except Exception as exc:  # noqa: BLE001 - one attempt only; continue exact order.
                    sensitive_values = _row_sensitive_values(
                        context,
                        expected_flag=expected_flag,
                    )
                    errors.append(
                        _error_record(
                            "row_execute",
                            exc,
                            row=row,
                            sensitive_values=sensitive_values,
                        )
                    )
                    # Validation failures before the row directory is claimed can
                    # still receive an explicit unstarted terminal receipt.  A
                    # partially written directory is never replaced or retried.
                    if _recover_retained_terminal_result(row):
                        terminal_slots.add(row.slot_id)
                    elif not _row_output_path(row).exists():
                        try:
                            result = runtime.record_unstarted(
                                plan=plan,
                                context=context,
                                case=case,
                                expected_flag=expected_flag,
                                reason="row execution failed before launch",
                            )
                            _validate_terminal_result(result, row)
                            terminal_slots.add(row.slot_id)
                        except Exception as terminal_exc:  # noqa: BLE001
                            errors.append(
                                _error_record(
                                    "row_terminalize",
                                    terminal_exc,
                                    row=row,
                                    sensitive_values=sensitive_values,
                                )
                            )
                            if _recover_retained_terminal_result(row):
                                terminal_slots.add(row.slot_id)
                    try:
                        prepared_terminal = runtime.terminalize_prepared_arm(
                            prepared=prepared,
                            context=context,
                            backend=backends[first.slot_id],
                        )
                        _validate_prepared_terminalization(
                            prepared_terminal,
                            prepared=prepared,
                            context=context,
                            expected_flag=expected_flag,
                        )
                        prepared_terminal_slots.add(row.slot_id)
                    except Exception as terminalize_exc:  # noqa: BLE001
                        errors.append(
                            _error_record(
                                "prepared_arm_terminalize",
                                terminalize_exc,
                                row=row,
                                sensitive_values=sensitive_values,
                            )
                        )
                finally:
                    cleanup_lease = leases.get(row.slot_id)
                    if cleanup_lease is not None and not _remove_network_once(
                        runtime,
                        cleanup_lease,
                        errors=errors,
                    ):
                        resource_cleanup_failed = True

            release_path: Path | None = None
            if {first.slot_id, second.slot_id} <= prepared_terminal_slots:
                try:
                    release = runtime.release_pair(
                        prepared=prepared,
                        backend=backends[first.slot_id],
                    )
                    _validate_pair_release(release, prepared=prepared)
                    release_path = _validated_pair_release_path(prepared)
                except Exception as exc:  # noqa: BLE001 - terminal rows are never rerun.
                    resource_cleanup_failed = True
                    errors.append(
                        _error_record(
                            "pair_release",
                            exc,
                            row=second,
                            sensitive_values=(expected_flag,),
                        )
                    )
            else:
                resource_cleanup_failed = True
                errors.append(
                    {
                        "stage": "pair_release",
                        "slot_id": second.slot_id,
                        "case_id": second.case_id,
                        "exception_type": "PairNotTerminalError",
                        "message": "prepared pair retained because both target arms did not terminalize",
                    }
                )
            pair_evidence.append(
                _PairEvidence(
                    pair_index=pair_index,
                    case_id=case.benchmark_id,
                    pair_id=prepared.pair_id,
                    prepared_path=prepared.evidence_dir / "prepared.json",
                    release_path=release_path,
                )
            )
    except BaseException as exc:  # noqa: BLE001 - interrupts must terminalize the one-shot claim.
        scheduler_failure = exc
        errors.append(
            _error_record(
                "scheduler_internal",
                exc,
                sensitive_values=(*pair_flags, *tokens.values()),
            )
        )
        _terminalize_remaining_registered_rows(
            plan,
            runtime=runtime,
            cases=cases,
            contexts=contexts,
            unstarted_contexts=unstarted_contexts,
            pair_flags=pair_flags,
            terminal_slots=terminal_slots,
            errors=errors,
        )
    finally:
        try:
            gateway.close()
        except Exception as exc:  # noqa: BLE001 - retain terminalization attempt.
            gateway_close_failed = True
            errors.append(
                _error_record(
                    "gateway_close",
                    exc,
                    sensitive_values=(*pair_flags, *tokens.values()),
                )
            )

    campaign_gateway_path = plan.campaign_root / MODEL_CAMPAIGN_RECEIPT_FILE
    if (
        scheduler_failure is not None
        or gateway_close_failed
        or resource_cleanup_failed
        or len(terminal_slots) != EXPECTED_ROWS
        or len(pair_evidence) != EXPECTED_PAIRS
    ):
        if len(terminal_slots) != EXPECTED_ROWS or len(pair_evidence) != EXPECTED_PAIRS:
            errors.append(
                {
                    "stage": "campaign_terminalization",
                    "slot_id": None,
                    "case_id": None,
                    "exception_type": "IncompletePrimaryMatrixError",
                    "message": "not every reserved primary row produced terminal evidence",
                }
            )
        _write_incomplete_execution_terminal(
            plan,
            execution_root=execution_root,
            terminal_slots=terminal_slots,
            pair_evidence=pair_evidence,
            errors=errors,
        )
        message = "campaign stopped without terminal seals because execution did not close cleanly"
        raise CampaignCoordinatorError(message) from scheduler_failure
    try:
        gateway_receipt = gateway.seal_primary_campaign(campaign_gateway_path)
        gateway_receipt = _validate_gateway_campaign_seal(
            campaign_gateway_path,
            returned=gateway_receipt,
        )
    except Exception as exc:
        errors.append(
            _error_record(
                "gateway_seal",
                exc,
                sensitive_values=(*pair_flags, *tokens.values()),
            )
        )
        _write_incomplete_execution_terminal(
            plan,
            execution_root=execution_root,
            terminal_slots=terminal_slots,
            pair_evidence=pair_evidence,
            errors=errors,
        )
        raise CampaignCoordinatorError("model gateway campaign seal failed") from exc
    try:
        primary_path = _write_primary_results(plan, pair_evidence=pair_evidence)
    except Exception as exc:
        errors.append(
            _error_record(
                "primary_results_seal",
                exc,
                sensitive_values=(*pair_flags, *tokens.values()),
            )
        )
        _write_incomplete_execution_terminal(
            plan,
            execution_root=execution_root,
            terminal_slots=terminal_slots,
            pair_evidence=pair_evidence,
            errors=errors,
            gateway_receipt=gateway_receipt,
        )
        raise CampaignCoordinatorError("primary results seal failed") from exc
    terminal = _document(
        {
            "schema_version": EXECUTION_TERMINAL_SCHEMA,
            "created_at": _now(),
            "campaign_id": plan.campaign_id,
            "commitment_digest": plan.commitment_digest,
            "selection_digest": plan.selection_digest,
            "evidence_class": PAIRED_LOCAL,
            "official_attestation_eligible": False,
            "rows_terminal": EXPECTED_ROWS,
            "pairs_terminal": EXPECTED_PAIRS,
            "model_gateway_receipt_sha256": _file_digest(campaign_gateway_path),
            "model_gateway_document_sha256": gateway_receipt.get("document_sha256"),
            "primary_results_sha256": _file_digest(primary_path),
            "errors": errors,
            "complete": True,
            "claim_scope": "paired-local-operational-only",
        }
    )
    terminal_path = execution_root / "terminal.json"
    _write_json_exclusive(terminal_path, terminal)
    return {
        "campaign_id": plan.campaign_id,
        "mode": PAIRED_LOCAL,
        "official_attestation_eligible": False,
        "rows_terminal": EXPECTED_ROWS,
        "model_gateway_receipt": str(campaign_gateway_path),
        "primary_results": str(primary_path),
        "execution_terminal": str(terminal_path),
        "recorded_errors": len(errors),
    }


def _register_complete_gateway(
    plan: ResolvedCampaignPlan,
    *,
    gateway: CampaignGateway,
) -> dict[str, str]:
    gateway_contract = _mapping(plan.run_contract["model_gateway"], "model gateway contract")
    budgets = _mapping(plan.run_contract["budgets"], "budget contract")
    row_budget = _mapping(budgets["per_row"], "per-row budget")
    expected_policy = _digest(gateway_contract["policy_sha256"], "model policy digest")
    if gateway.policy_digest != expected_policy:
        raise CampaignCoordinatorError("runtime gateway policy differs from the commitment")

    # Registration is deliberately a separate complete pass before start() or
    # any row-dependent work. This is the in-process no-selective-start gate.
    tokens: dict[str, str] = {}
    for row in plan.schedule:
        token = gateway.register_row(
            row.slot_id,
            max_requests=_positive_int(row_budget["max_model_requests"], "row model cap"),
            max_cost_usd=_money_text(row_budget["max_cost_usd"], "row cost cap"),
        )
        if not isinstance(token, str) or _GATEWAY_TOKEN_RE.fullmatch(token) is None:
            raise CampaignCoordinatorError("model gateway returned an invalid row token")
        if token in tokens.values():
            raise CampaignCoordinatorError("model gateway repeated a row token")
        tokens[row.slot_id] = token
    if tuple(tokens) != tuple(row.slot_id for row in plan.schedule):
        raise CampaignCoordinatorError("model gateway did not reserve the exact schedule")
    return tokens


def _build_complete_unstarted_contexts(
    plan: ResolvedCampaignPlan,
    *,
    runtime: CampaignExecutionRuntime,
    gateway: CampaignGateway,
    tokens: Mapping[str, str],
    row_instances: Mapping[str, str],
) -> dict[str, RowExecutionContext]:
    """Preflight one zero-launch sealing context for every registered row."""

    contexts: dict[str, RowExecutionContext] = {}
    for row in plan.schedule:
        instance_id = row_instances[row.slot_id]
        context = runtime.build_unstarted_row_context(
            plan=plan,
            row=row,
            gateway=gateway,
            row_token=tokens[row.slot_id],
            gateway_base_url=_UNSTARTED_GATEWAY_BASE_URL,
            instance_id=instance_id,
            network_name=_network_name(instance_id),
        )
        _validate_unstarted_row_context(context, expected=row)
        contexts[row.slot_id] = context
    if tuple(contexts) != tuple(row.slot_id for row in plan.schedule):
        raise CampaignCoordinatorError(
            "unstarted row contexts do not cover the exact registered schedule"
        )
    return contexts


def _terminalize_remaining_registered_rows(
    plan: ResolvedCampaignPlan,
    *,
    runtime: CampaignExecutionRuntime,
    cases: Mapping[str, XbenCase],
    contexts: Mapping[str, RowExecutionContext],
    unstarted_contexts: Mapping[str, RowExecutionContext],
    pair_flags: Sequence[str],
    terminal_slots: set[str],
    errors: list[dict[str, object]],
) -> None:
    """Best-effort terminal sealing after an unexpected scheduler exception.

    This is not a retry: already retained terminal evidence is only recognized,
    and an untouched registered row receives its sole zero-launch outcome.  A
    partially claimed row directory remains immutable and therefore makes the
    campaign incomplete rather than being replaced.
    """

    for row in plan.schedule:
        if row.slot_id in terminal_slots:
            continue
        if _recover_retained_terminal_result(row):
            terminal_slots.add(row.slot_id)
            continue
        if _row_output_path(row).exists() or _row_output_path(row).is_symlink():
            continue
        context = contexts.get(row.slot_id, unstarted_contexts[row.slot_id])
        expected_flag = pair_flags[row.pair_index - 1]
        try:
            result = runtime.record_unstarted(
                plan=plan,
                context=context,
                case=cases[row.case_id],
                expected_flag=expected_flag,
                reason="campaign scheduler failed before this row could launch",
            )
            _validate_terminal_result(result, row)
            terminal_slots.add(row.slot_id)
        except Exception as exc:  # noqa: BLE001 - retain one terminalization attempt.
            errors.append(
                _error_record(
                    "scheduler_row_terminalize",
                    exc,
                    row=row,
                    sensitive_values=_row_sensitive_values(
                        context,
                        expected_flag=expected_flag,
                    ),
                )
            )
            if _recover_retained_terminal_result(row):
                terminal_slots.add(row.slot_id)


def _write_execution_start(
    plan: ResolvedCampaignPlan,
    *,
    execution_root: Path,
    row_instances: Mapping[str, str],
) -> None:
    _write_json_exclusive(
        execution_root / "start.json",
        _document(
            {
                "schema_version": EXECUTION_START_SCHEMA,
                "created_at": _now(),
                "campaign_id": plan.campaign_id,
                "commitment_digest": plan.commitment_digest,
                "selection_digest": plan.selection_digest,
                "primary_matrix_digest": plan.primary_matrix_digest,
                "evidence_class": PAIRED_LOCAL,
                "official_attestation_eligible": False,
                "registered_row_count": EXPECTED_ROWS,
                "registered_row_ids": [row.slot_id for row in plan.schedule],
                "row_instances": [
                    {"slot_id": row.slot_id, "instance_id": row_instances[row.slot_id]}
                    for row in plan.schedule
                ],
                "policy": {
                    "resume_allowed": False,
                    "row_retry_allowed": False,
                    "row_replacement_allowed": False,
                    "adjacent_pair_schedule": True,
                },
            }
        ),
    )


def _write_incomplete_execution_terminal(
    plan: ResolvedCampaignPlan,
    *,
    execution_root: Path,
    terminal_slots: set[str],
    pair_evidence: Sequence[_PairEvidence],
    errors: Sequence[Mapping[str, object]],
    gateway_receipt: Mapping[str, object] | None = None,
) -> None:
    gateway_path = plan.campaign_root / MODEL_CAMPAIGN_RECEIPT_FILE
    primary_path = plan.campaign_root / PRIMARY_RESULTS_FILE
    gateway_digest = _optional_file_digest(gateway_path)
    primary_digest = _optional_file_digest(primary_path)
    terminal = _document(
        {
            "schema_version": EXECUTION_TERMINAL_SCHEMA,
            "created_at": _now(),
            "campaign_id": plan.campaign_id,
            "commitment_digest": plan.commitment_digest,
            "selection_digest": plan.selection_digest,
            "evidence_class": PAIRED_LOCAL,
            "official_attestation_eligible": False,
            "rows_terminal": len(terminal_slots),
            "pairs_terminal": sum(
                1
                for offset in range(0, EXPECTED_ROWS, 2)
                if {
                    plan.schedule[offset].slot_id,
                    plan.schedule[offset + 1].slot_id,
                }
                <= terminal_slots
            ),
            "scheduler_pairs_reached": len(pair_evidence),
            "model_gateway_receipt_sha256": gateway_digest,
            "model_gateway_document_sha256": (
                gateway_receipt.get("document_sha256") if gateway_receipt is not None else None
            ),
            "primary_results_sha256": primary_digest,
            "errors": [dict(error) for error in errors],
            "complete": False,
            "claim_scope": "paired-local-operational-only",
        }
    )
    _write_json_exclusive(execution_root / "terminal.json", terminal)


def _write_claimed_failure_terminal(
    plan: ResolvedCampaignPlan,
    *,
    execution_root: Path,
    stage: str,
    failure: BaseException,
) -> None:
    """Retain an explicit terminal poison receipt for a post-admission failure."""

    _write_incomplete_execution_terminal(
        plan,
        execution_root=execution_root,
        terminal_slots=set(),
        pair_evidence=(),
        errors=(_error_record(stage, failure),),
    )


@dataclass(frozen=True)
class SystemExecutorConfiguration:
    """Machine-local paths whose identities are frozen by the run contract."""

    executable: Path
    runtime_environment_manifest: Path
    runtime_read_roots: tuple[Path, ...]


@dataclass(frozen=True)
class ExecutorTimeouts:
    build_seconds: int = 900
    startup_seconds: int = 180
    inspect_seconds: int = 30
    teardown_seconds: int = 90


@dataclass(frozen=True)
class ExecutorConfiguration:
    """Non-secret machine-local configuration for the paired-local executor."""

    mode: str
    upstream_api_key_environment: str
    xben_repository: Path
    compatibility_catalog: Path
    private_target_root: Path
    trusted_path: str
    docker_executable: Path
    docker_socket: Path
    ravage_target_listen_port: int
    systems: Mapping[str, SystemExecutorConfiguration]
    timeouts: ExecutorTimeouts


def load_executor_configuration(path: Path) -> ExecutorConfiguration:
    """Load the exact local-path configuration; no credential value is accepted."""

    payload = _load_json(path.expanduser().resolve(strict=True), "executor configuration")
    fields = {
        "schema_version",
        "mode",
        "upstream_api_key_environment",
        "xben_repository",
        "compatibility_catalog",
        "private_target_root",
        "trusted_path",
        "docker_executable",
        "docker_socket",
        "ravage_target_listen_port",
        "systems",
        "timeouts",
    }
    if set(payload) != fields or payload.get("schema_version") != EXECUTOR_CONFIG_SCHEMA:
        raise CampaignCoordinatorError("executor configuration fields are invalid")
    if payload.get("mode") != PAIRED_LOCAL:
        raise CampaignCoordinatorError("executor configuration mode must be paired_local")
    api_environment = _required_text(
        payload.get("upstream_api_key_environment"), "API-key environment name"
    )
    if _SAFE_ENV_NAME_RE.fullmatch(api_environment) is None:
        raise CampaignCoordinatorError("API-key environment name is invalid")
    trusted_path = _required_text(payload.get("trusted_path"), "trusted PATH")
    if "\x00" in trusted_path or any(not component for component in trusted_path.split(os.pathsep)):
        raise CampaignCoordinatorError("trusted PATH is malformed")
    if any(not Path(component).is_absolute() for component in trusted_path.split(os.pathsep)):
        raise CampaignCoordinatorError("trusted PATH entries must be absolute")
    port = _positive_int(payload.get("ravage_target_listen_port"), "Ravage target port")
    if not 1024 <= port <= 65535:
        raise CampaignCoordinatorError("Ravage target port must be between 1024 and 65535")

    raw_systems = _mapping(payload.get("systems"), "executor systems")
    if set(raw_systems) != set(SYSTEMS):
        raise CampaignCoordinatorError("executor must configure exactly Ravage and Strix")
    systems: dict[str, SystemExecutorConfiguration] = {}
    for system in SYSTEMS:
        raw = _mapping(raw_systems[system], f"{system} executor")
        if set(raw) != {
            "executable",
            "runtime_environment_manifest",
            "runtime_read_roots",
        }:
            raise CampaignCoordinatorError(f"{system} executor fields are invalid")
        raw_roots = raw.get("runtime_read_roots")
        if (
            not isinstance(raw_roots, list)
            or not raw_roots
            or len(raw_roots) > 128
            or any(not isinstance(item, str) for item in raw_roots)
        ):
            raise CampaignCoordinatorError(f"{system} runtime read roots are invalid")
        roots = tuple(_absolute_path(item, f"{system} runtime read root") for item in raw_roots)
        systems[system] = SystemExecutorConfiguration(
            executable=_absolute_path(raw.get("executable"), f"{system} executable"),
            runtime_environment_manifest=_absolute_path(
                raw.get("runtime_environment_manifest"),
                f"{system} runtime manifest",
            ),
            runtime_read_roots=roots,
        )

    raw_timeouts = _mapping(payload.get("timeouts"), "executor timeouts")
    if set(raw_timeouts) != {
        "build_seconds",
        "startup_seconds",
        "inspect_seconds",
        "teardown_seconds",
    }:
        raise CampaignCoordinatorError("executor timeout fields are invalid")
    timeouts = ExecutorTimeouts(
        build_seconds=_positive_int(raw_timeouts["build_seconds"], "build timeout"),
        startup_seconds=_positive_int(raw_timeouts["startup_seconds"], "startup timeout"),
        inspect_seconds=_positive_int(raw_timeouts["inspect_seconds"], "inspect timeout"),
        teardown_seconds=_positive_int(raw_timeouts["teardown_seconds"], "teardown timeout"),
    )
    if timeouts.teardown_seconds <= 35:
        raise CampaignCoordinatorError("teardown timeout must exceed the target gateway deadline")
    return ExecutorConfiguration(
        mode=PAIRED_LOCAL,
        upstream_api_key_environment=api_environment,
        xben_repository=_absolute_path(payload.get("xben_repository"), "XBEN repository"),
        compatibility_catalog=_absolute_path(
            payload.get("compatibility_catalog"), "compatibility catalog"
        ),
        private_target_root=_absolute_path(
            payload.get("private_target_root"), "private target root"
        ),
        trusted_path=trusted_path,
        docker_executable=_absolute_path(payload.get("docker_executable"), "Docker executable"),
        docker_socket=_absolute_path(payload.get("docker_socket"), "Docker socket"),
        ravage_target_listen_port=port,
        systems=systems,
        timeouts=timeouts,
    )


def execute_paired_campaign_from_config(
    campaign_dir: Path,
    *,
    executor_config_path: Path,
) -> dict[str, object]:
    """Concrete CLI boundary whose config and secret reads follow admission."""

    plan = load_verified_execution_plan(campaign_dir)
    execution_root = _claim_execution_root(plan.campaign_root)
    try:
        configuration = load_executor_configuration(executor_config_path)
        api_key = os.environ.get(configuration.upstream_api_key_environment, "")
        if not api_key:
            raise CampaignCoordinatorError(
                f"upstream credential environment {configuration.upstream_api_key_environment!r} "
                "is absent"
            )
        runtime = ProductionCampaignRuntime(configuration, upstream_api_key=api_key)
        cases = _load_exact_runtime_cases(plan, runtime=runtime)
    except BaseException as exc:  # noqa: BLE001 - config/credential failure consumes admission.
        _write_claimed_failure_terminal(
            plan,
            execution_root=execution_root,
            stage="runtime_preflight",
            failure=exc,
        )
        raise
    return _execute_claimed_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        execution_root=execution_root,
        flag_hex=secrets.token_hex,
        instance_hex=secrets.token_hex,
    )


@dataclass
class DockerAgentNetworkManager:
    """Create and destroy exact labelled internal networks without retrying."""

    docker_executable: Path
    docker_socket: Path
    trusted_path: str
    timeout_seconds: int
    runner: CommandRunner

    def create(self, *, instance_id: str, name: str) -> AgentNetworkLease:
        if not _INSTANCE_RE.fullmatch(instance_id) or name != _network_name(instance_id):
            raise CampaignCoordinatorError("agent network request is misbound")
        result = self._run(
            (
                str(self.docker_executable),
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--label",
                f"{_AGENT_NETWORK_LABEL}=true",
                "--label",
                f"{_INSTANCE_LABEL}={instance_id}",
                name,
            )
        )
        if result.returncode != 0:
            raise CampaignCoordinatorError("Docker agent-network creation failed")
        network_id = result.stdout.decode("utf-8", errors="replace").strip()
        if _RAW_SHA256_RE.fullmatch(network_id) is None:
            self._discard_created_network_by_name(
                name=name,
                instance_id=instance_id,
            )
            raise CampaignCoordinatorError("Docker returned an invalid agent-network ID")
        lease = AgentNetworkLease(instance_id=instance_id, name=name, network_id=network_id)
        try:
            self._inspect(lease, expected_members=set())
        except Exception:
            self._discard_created_network(network_id)
            raise
        return lease

    def remove(self, lease: AgentNetworkLease) -> None:
        self._inspect(lease, expected_members=set())
        removed = self._run((str(self.docker_executable), "network", "rm", lease.network_id))
        if removed.returncode != 0:
            raise CampaignCoordinatorError("Docker agent-network removal failed")
        self._verify_network_absent(lease.network_id)

    def inspect_image(self, reference: str, *, expected_id: str | None) -> None:
        result = self._run((str(self.docker_executable), "image", "inspect", reference))
        if result.returncode != 0:
            raise CampaignCoordinatorError(f"required local OCI image is absent: {reference}")
        try:
            payload = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CampaignCoordinatorError("Docker image inspection was malformed") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise CampaignCoordinatorError("Docker image inspection was ambiguous")
        image_id = payload[0].get("Id")
        if expected_id is not None and image_id != expected_id:
            raise CampaignCoordinatorError(f"local OCI image identity drifted: {reference}")

    def _inspect(self, lease: AgentNetworkLease, *, expected_members: set[str]) -> None:
        result = self._run((str(self.docker_executable), "network", "inspect", lease.network_id))
        if result.returncode != 0:
            raise CampaignCoordinatorError("Docker agent-network inspection failed")
        network = self._network_inspect_payload(result)
        self._validate_network_payload(
            network,
            lease=lease,
            expected_members=expected_members,
        )

    @staticmethod
    def _network_inspect_payload(result: CommandResult) -> Mapping[str, object]:
        try:
            payload = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CampaignCoordinatorError("Docker agent-network inspection was malformed") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise CampaignCoordinatorError("Docker agent-network inspection was ambiguous")
        return payload[0]

    @staticmethod
    def _validate_network_payload(
        network: Mapping[str, object],
        *,
        lease: AgentNetworkLease,
        expected_members: set[str],
    ) -> None:
        labels = network.get("Labels")
        members = network.get("Containers") or {}
        if (
            network.get("Id") != lease.network_id
            or network.get("Name") != lease.name
            or network.get("Internal") is not True
            or not isinstance(labels, dict)
            or labels.get(_AGENT_NETWORK_LABEL) != "true"
            or labels.get(_INSTANCE_LABEL) != lease.instance_id
            or not isinstance(members, dict)
            or set(members) != expected_members
        ):
            raise CampaignCoordinatorError("Docker agent-network identity or membership drifted")

    def _run(self, command: Sequence[str]) -> CommandResult:
        return self.runner.run(
            command,
            cwd=Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp"),
            environment={
                "PATH": self.trusted_path,
                "LC_ALL": "C",
                "LANG": "C",
                "DOCKER_HOST": f"unix://{self.docker_socket.resolve(strict=True)}",
            },
            timeout_seconds=self.timeout_seconds,
        )

    def _discard_created_network(self, identifier: str) -> None:
        """Make one best-effort cleanup pass for a just-created invalid lease."""

        removed = self._run((str(self.docker_executable), "network", "rm", identifier))
        if removed.returncode != 0:
            raise CampaignCoordinatorError(
                "invalid Docker agent network could not be removed and verified absent"
            )
        self._verify_network_absent(identifier)

    def _discard_created_network_by_name(self, *, name: str, instance_id: str) -> None:
        inspected = self._run((str(self.docker_executable), "network", "inspect", name))
        if inspected.returncode != 0:
            raise CampaignCoordinatorError(
                "malformed Docker create response could not be bound for safe cleanup"
            )
        network = self._network_inspect_payload(inspected)
        network_id = network.get("Id")
        if not isinstance(network_id, str) or _RAW_SHA256_RE.fullmatch(network_id) is None:
            raise CampaignCoordinatorError(
                "malformed Docker create response had no safely removable network identity"
            )
        lease = AgentNetworkLease(instance_id=instance_id, name=name, network_id=network_id)
        self._validate_network_payload(network, lease=lease, expected_members=set())
        self._discard_created_network(network_id)

    def _verify_network_absent(self, network_id: str) -> None:
        result = self._run(
            (
                str(self.docker_executable),
                "network",
                "ls",
                "--no-trunc",
                "--quiet",
                "--filter",
                f"id={network_id}",
            )
        )
        try:
            retained = result.stdout.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise CampaignCoordinatorError("Docker network absence check was malformed") from exc
        if (
            result.returncode != 0
            or any(_RAW_SHA256_RE.fullmatch(item) is None for item in retained)
            or retained
        ):
            raise CampaignCoordinatorError("Docker agent network absence was not verified")


@dataclass(frozen=True)
class FrozenCampaignCommandRunner:
    """Force target/materializer subprocesses onto the preflighted tool path and daemon."""

    delegate: CommandRunner
    docker_executable: Path
    docker_socket: Path
    trusted_path: str

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        argv = tuple(str(part) for part in command)
        if not argv:
            raise CampaignCoordinatorError("refusing an empty campaign subprocess")
        clean_environment = dict(environment)
        clean_environment["PATH"] = self.trusted_path
        if argv[0] in {"docker", str(self.docker_executable)}:
            for name in (
                "DOCKER_CONTEXT",
                "DOCKER_CONFIG",
                "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH",
            ):
                clean_environment.pop(name, None)
            clean_environment["DOCKER_HOST"] = f"unix://{self.docker_socket.resolve(strict=True)}"
        elif argv[0] == "git":
            clean_environment.update(
                {
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0",
                }
            )
        return self.delegate.run(
            argv,
            cwd=cwd,
            environment=clean_environment,
            timeout_seconds=timeout_seconds,
        )


class ProductionCampaignRuntime:
    """Concrete paired-local runtime built only from frozen identities."""

    def __init__(self, configuration: ExecutorConfiguration, *, upstream_api_key: str) -> None:
        if not upstream_api_key or len(upstream_api_key) > 10_000:
            raise CampaignCoordinatorError("upstream API credential is absent or invalid")
        self.configuration = configuration
        self._upstream_api_key = upstream_api_key
        self._runner: CommandRunner = FrozenCampaignCommandRunner(
            delegate=BoundedSubprocessRunner(),
            docker_executable=configuration.docker_executable,
            docker_socket=configuration.docker_socket,
            trusted_path=configuration.trusted_path,
        )
        self._network_manager = DockerAgentNetworkManager(
            docker_executable=configuration.docker_executable,
            docker_socket=configuration.docker_socket,
            trusted_path=configuration.trusted_path,
            timeout_seconds=configuration.timeouts.inspect_seconds,
            runner=self._runner,
        )
        self._runtimes: dict[str, PinnedAgentRuntime] = {}
        self._runtime_read_roots: dict[str, tuple[Path, ...]] = {}
        self._materializer: PinnedGitCaseMaterializer | None = None

    def validate_plan(self, plan: ResolvedCampaignPlan) -> None:  # noqa: PLR0912
        if self.configuration.mode != PAIRED_LOCAL:
            raise CampaignCoordinatorError("production runtime is not paired_local")
        contract = plan.run_contract
        execution = _mapping(contract["execution_policy"], "execution policy")
        host = _mapping(execution["evaluator_host"], "evaluator host")
        if sys.platform != "darwin" or host.get("platform") != "darwin":
            raise CampaignCoordinatorError("frozen paired-local containment requires macOS")
        sandbox_path = Path(_required_text(host["sandbox_executable_path"], "sandbox path"))
        if sandbox_path != Path("/usr/bin/sandbox-exec"):
            raise CampaignCoordinatorError("unsupported sandbox executable path")
        if _file_digest(sandbox_path) != _digest(
            host["sandbox_executable_sha256"], "sandbox executable digest"
        ):
            raise CampaignCoordinatorError("sandbox-exec differs from the frozen digest")
        docker_socket = self.configuration.docker_socket.resolve(strict=True)
        if not stat.S_ISSOCK(docker_socket.stat().st_mode):
            raise CampaignCoordinatorError("configured Docker path is not a Unix socket")
        # Docker socket access is root-equivalent over every container on that
        # daemon.  The current executor configuration has only one endpoint, so
        # granting it to an agent would also grant control of the private target.
        # Refuse execution until those authorities are actually separated.
        _require_distinct_docker_authorities(
            target_socket=docker_socket,
            agent_socket=docker_socket,
        )
        docker_executable = self.configuration.docker_executable.resolve(strict=True)
        trusted_docker = shutil.which("docker", path=self.configuration.trusted_path)
        if (
            not docker_executable.is_file()
            or not os.access(docker_executable, os.X_OK)
            or trusted_docker is None
            or Path(trusted_docker).resolve(strict=True) != docker_executable
        ):
            raise CampaignCoordinatorError(
                "configured Docker executable differs from the target backend command"
            )
        if _paths_overlap(plan.campaign_root, self.configuration.private_target_root):
            raise CampaignCoordinatorError("private target root overlaps campaign evidence")
        private_target_root = _resolved_directory(
            self.configuration.private_target_root,
            "private target root",
        )
        private_metadata = private_target_root.stat()
        if (
            private_target_root != self.configuration.private_target_root
            or private_metadata.st_uid != os.getuid()
            or stat.S_IMODE(private_metadata.st_mode) != 0o700
            or any(private_target_root.iterdir())
        ):
            raise CampaignCoordinatorError(
                "private target root must be canonical, empty, evaluator-owned, and mode 0700"
            )

        sources = _mapping(contract["sources"], "sources")
        runtime_bindings = _mapping(contract["runtime_manifests"], "runtime manifests")
        host_systems = _mapping(host["systems"], "host systems")
        limits = _external_limits(contract)
        gateway_contract = _mapping(contract["model_gateway"], "model gateway")
        policy = _mapping(gateway_contract["policy"], "model policy")
        pricing = _mapping(policy["pricing_usd_per_million_tokens"], "model pricing")
        dummy_gateway = RowModelGateway(
            base_url="http://127.0.0.1:1/v1",
            token="x" * 48,
            model=_required_text(policy["model"], "model"),
            reasoning_effort=_required_text(policy["reasoning_effort"], "reasoning effort"),
            pricing=GatewayPricing(
                input_per_million=_required_text(pricing["input_per_million"], "input price"),
                cached_input_per_million=_required_text(
                    pricing["cached_input_per_million"], "cached input price"
                ),
                output_per_million=_required_text(pricing["output_per_million"], "output price"),
            ),
            max_output_tokens=_positive_int(
                policy["max_completion_tokens_per_request"], "completion cap"
            ),
        )
        for system in SYSTEMS:
            local = self.configuration.systems[system]
            source = _mapping(sources[system], f"{system} source")
            manifest_binding = _mapping(runtime_bindings[system], f"{system} runtime binding")
            manifest = _load_json(
                local.runtime_environment_manifest.resolve(strict=True),
                f"{system} runtime manifest",
            )
            source_root = _resolved_directory(
                Path(_required_text(manifest.get("source_root"), "runtime source root")),
                f"{system} source root",
            )
            runtime = PinnedAgentRuntime(
                executable=local.executable,
                executable_sha256=_digest(
                    manifest_binding["executable_sha256"], f"{system} executable digest"
                ),
                source_root=source_root,
                source_commit=_required_text(source["commit_sha"], f"{system} source commit"),
                source_tree=_required_text(source["tree_object"], f"{system} source tree"),
                source_origin_url=_required_text(source["origin_url"], f"{system} source origin"),
                runtime_environment_manifest=local.runtime_environment_manifest,
                runtime_environment_manifest_sha256=_digest(
                    manifest_binding["sha256"], f"{system} runtime manifest digest"
                ),
            )
            roots = _normalized_read_roots(local.runtime_read_roots)
            if Path(sys.executable).resolve(strict=True).parent not in roots:
                raise CampaignCoordinatorError(
                    f"{system} runtime roots omit the outer adapter interpreter"
                )
            if any(
                _paths_overlap(root, protected)
                for root in roots
                for protected in (plan.campaign_root, private_target_root)
            ):
                raise CampaignCoordinatorError(
                    f"{system} runtime roots expose campaign or private target evidence"
                )
            system_host = _mapping(host_systems[system], f"{system} host policy")
            if (
                system_host.get("evidence_class") != PAIRED_LOCAL
                or system_host.get("docker_socket_access") is not True
                or system_host.get("runtime_read_root_count") != len(roots)
                or system_host.get("runtime_read_roots_sha256")
                != _json_list_digest([str(root) for root in roots])
                or system_host.get("docker_socket_path_sha256") != _text_digest(str(docker_socket))
                or system_host.get("docker_host_sha256") != _text_digest(f"unix://{docker_socket}")
            ):
                raise CampaignCoordinatorError(
                    f"{system} runtime roots or Docker socket differ from commitment"
                )
            self._runtimes[system] = runtime
            self._runtime_read_roots[system] = roots
            if system == "ravage":
                build_ravage_agent(
                    runtime=runtime,
                    gateway=dummy_gateway,
                    limits=limits,
                    trusted_path=self.configuration.trusted_path,
                    tool_image=_image_reference(contract, "ravage_tool"),
                    docker_host=f"unix://{docker_socket}",
                )
            else:
                build_strix_agent(
                    runtime=runtime,
                    gateway=dummy_gateway,
                    limits=limits,
                    trusted_path=self.configuration.trusted_path,
                    sandbox_image=_image_reference(contract, "strix_sandbox"),
                    sandbox_network="ravage-agent-preflight",
                    docker_host=f"unix://{docker_socket}",
                )

        self._validate_xben_source(plan)
        self._validate_local_images(contract)
        _require_loopback_port_free(self.configuration.ravage_target_listen_port)
        xben_source = _mapping(sources["xben"], "XBEN source")
        catalog = _mapping(contract["compatibility_catalog"], "compatibility catalog")
        self._materializer = PinnedGitCaseMaterializer(
            source=PinnedXbenSource(
                repository=self.configuration.xben_repository,
                commit=_required_text(xben_source["commit_sha"], "XBEN commit"),
                compatibility_patch_catalog=CompatibilityPatchCatalog(
                    path=self.configuration.compatibility_catalog,
                    sha256=_digest(catalog["sha256"], "compatibility catalog digest").removeprefix(
                        "sha256:"
                    ),
                ),
            ),
            private_root=self.configuration.private_target_root,
            runner=self._runner,
        )

    def load_selected_cases(self, plan: ResolvedCampaignPlan) -> Mapping[str, XbenCase]:
        root = self.configuration.xben_repository / "benchmarks"
        selected = {row.case_id for row in plan.schedule}
        cases = {case.benchmark_id: case for case in load_xben_cases(root)}
        missing = selected - set(cases)
        if missing:
            raise CampaignCoordinatorError(f"selected XBEN metadata is absent: {sorted(missing)}")
        return {case_id: cases[case_id] for case_id in sorted(selected)}

    def create_gateway(self, plan: ResolvedCampaignPlan) -> CampaignGateway:
        policy = _model_policy(plan.run_contract)
        return ComparisonModelGateway(
            policy=policy,
            upstream_api_key=self._upstream_api_key,
        )

    def build_row_context(
        self,
        *,
        plan: ResolvedCampaignPlan,
        row: ScheduledRow,
        gateway: CampaignGateway,
        row_token: str,
        gateway_base_url: str,
        instance_id: str,
        network_name: str,
    ) -> RowExecutionContext:
        limits, row_gateway, process = self._row_scaffolding(
            plan=plan,
            row=row,
            gateway=gateway,
            row_token=row_token,
            gateway_base_url=gateway_base_url,
        )
        setup_error: str | None = None
        try:
            if row.system == "ravage":
                agent = build_ravage_agent(
                    runtime=self._runtimes["ravage"],
                    gateway=row_gateway,
                    limits=limits,
                    trusted_path=self.configuration.trusted_path,
                    tool_image=_image_reference(plan.run_contract, "ravage_tool"),
                    docker_host=(f"unix://{self.configuration.docker_socket.resolve(strict=True)}"),
                )
            else:
                agent = build_strix_agent(
                    runtime=self._runtimes["strix"],
                    gateway=row_gateway,
                    limits=limits,
                    trusted_path=self.configuration.trusted_path,
                    sandbox_image=_image_reference(plan.run_contract, "strix_sandbox"),
                    sandbox_network=network_name,
                    docker_host=(f"unix://{self.configuration.docker_socket.resolve(strict=True)}"),
                )
        except Exception as exc:  # noqa: BLE001 - preserve a sealable zero-run context.
            setup_error = f"canonical adapter setup failed: {type(exc).__name__}"
            agent = _unstarted_agent(
                row=row,
                gateway=row_gateway,
                limits=limits,
            )
        return RowExecutionContext(
            row=row,
            instance_id=instance_id,
            network_name=network_name,
            agent=agent,
            process_backend=process,
            setup_error=setup_error,
        )

    def build_unstarted_row_context(
        self,
        *,
        plan: ResolvedCampaignPlan,
        row: ScheduledRow,
        gateway: CampaignGateway,
        row_token: str,
        gateway_base_url: str,
        instance_id: str,
        network_name: str,
    ) -> RowExecutionContext:
        """Build only enough trusted state to terminally seal a registered row."""

        limits, row_gateway, process = self._row_scaffolding(
            plan=plan,
            row=row,
            gateway=gateway,
            row_token=row_token,
            gateway_base_url=gateway_base_url,
        )
        return RowExecutionContext(
            row=row,
            instance_id=instance_id,
            network_name=network_name,
            agent=_unstarted_agent(row=row, gateway=row_gateway, limits=limits),
            process_backend=process,
            setup_error="registered row context failed before target preparation",
        )

    def _row_scaffolding(
        self,
        *,
        plan: ResolvedCampaignPlan,
        row: ScheduledRow,
        gateway: CampaignGateway,
        row_token: str,
        gateway_base_url: str,
    ) -> tuple[ExternalExecutionLimits, RowModelGateway, ComparisonProcessBackend]:
        if not isinstance(gateway, ComparisonModelGateway):
            raise CampaignCoordinatorError("production runtime received a foreign model gateway")
        limits = _external_limits(plan.run_contract)
        policy = _mapping(
            _mapping(plan.run_contract["model_gateway"], "gateway")["policy"],
            "gateway policy",
        )
        pricing = _mapping(policy["pricing_usd_per_million_tokens"], "pricing")
        row_gateway = RowModelGateway(
            base_url=gateway_base_url,
            token=row_token,
            model=_required_text(policy["model"], "model"),
            reasoning_effort=_required_text(policy["reasoning_effort"], "reasoning effort"),
            pricing=GatewayPricing(
                input_per_million=_required_text(pricing["input_per_million"], "input price"),
                cached_input_per_million=_required_text(
                    pricing["cached_input_per_million"], "cached input price"
                ),
                output_per_million=_required_text(pricing["output_per_million"], "output price"),
            ),
            max_output_tokens=_positive_int(
                policy["max_completion_tokens_per_request"], "completion cap"
            ),
        )
        execution = _mapping(plan.run_contract["execution_policy"], "execution policy")
        host = _mapping(execution["evaluator_host"], "evaluator host")
        process = ComparisonProcessBackend(
            gateway=gateway,
            row_id=row.slot_id,
            expected_policy_sha256=gateway.policy_digest,
            expected_row_token_sha256=_text_digest(row_token),
            sandbox_exec_sha256=_digest(
                host["sandbox_executable_sha256"], "sandbox executable digest"
            ),
            runtime_read_roots=self._runtime_read_roots[row.system],
            evidence_class=PAIRED_LOCAL,
            allow_docker_socket=True,
            sandbox_exec_path=Path(
                _required_text(host["sandbox_executable_path"], "sandbox executable")
            ),
            docker_socket_path=self.configuration.docker_socket,
        )
        return limits, row_gateway, process

    def create_agent_network(self, context: RowExecutionContext) -> AgentNetworkLease:
        return self._network_manager.create(
            instance_id=context.instance_id,
            name=context.network_name,
        )

    def create_target_backend(
        self,
        *,
        plan: ResolvedCampaignPlan,
        context: RowExecutionContext,
        lease: AgentNetworkLease,
    ) -> DockerComparisonTargetBackend:
        if self._materializer is None:
            raise CampaignCoordinatorError("production target materializer was not validated")
        limits = _external_limits(plan.run_contract)
        endpoint: Literal["host_loopback", "docker_alias"] = (
            "host_loopback" if context.row.system == "ravage" else "docker_alias"
        )
        gateway_image = _image_reference(plan.run_contract, "target_gateway")
        probe_image = _image_reference(plan.run_contract, "target_probe")
        gateway_id = _target_helper_image_id(plan.run_contract, "target_gateway")
        probe_id = _target_helper_image_id(plan.run_contract, "target_probe")
        listen_port = (
            self.configuration.ravage_target_listen_port if context.row.system == "ravage" else 8080
        )
        return DockerComparisonTargetBackend(
            materializer=self._materializer,
            evidence_root=plan.campaign_root / EXECUTION_DIRECTORY / "targets",
            configuration=DockerTargetConfiguration(
                gateway=GatewayConfiguration(
                    image=gateway_image,
                    expected_image_id=gateway_id,
                    agent_network=lease.name,
                    expected_agent_network_id="sha256:" + lease.network_id,
                    expected_program_sha256=program_sha256(),
                    max_target_requests=limits.max_target_requests,
                    endpoint_mode=endpoint,
                    listen_port=listen_port,
                ),
                probe=ProbeConfiguration(
                    image=probe_image,
                    expected_image_id=probe_id,
                ),
                platform="linux/amd64",
                build_timeout_seconds=self.configuration.timeouts.build_seconds,
                startup_timeout_seconds=self.configuration.timeouts.startup_seconds,
                inspect_timeout_seconds=self.configuration.timeouts.inspect_seconds,
                teardown_timeout_seconds=self.configuration.timeouts.teardown_seconds,
            ),
            runner=self._runner,
        )

    def prepare_pair(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        pair_id: str,
        backend: DockerComparisonTargetBackend,
    ) -> PreparedHandle:
        return backend.prepare_case(case=case, expected_flag=expected_flag, pair_id=pair_id)

    def arm_target_backend(
        self,
        *,
        prepared: PreparedHandle,
        context: RowExecutionContext,
        backend: DockerComparisonTargetBackend,
    ) -> ExternalTargetBackend:
        if not isinstance(prepared, PreparedCase):
            raise CampaignCoordinatorError("production runtime received a foreign prepared target")
        return PreparedTargetArmBackend(
            backend=backend,
            prepared=prepared,
            arm=context.row.system,
        )

    def run_row(
        self,
        *,
        plan: ResolvedCampaignPlan,
        context: RowExecutionContext,
        case: XbenCase,
        expected_flag: str,
        target_backend: ExternalTargetBackend,
    ) -> Mapping[str, object]:
        return run_external_xben_row(
            case=case,
            agent=context.agent,
            binding=_row_binding(plan, context.row),
            row_dir=_row_output_path(context.row),
            process_backend=cast("ExternalProcessBackend", context.process_backend),
            target_backend=target_backend,
            require_comparison_safety=True,
            expected_flag=expected_flag,
            row_instance_id=context.instance_id,
        )

    def record_unstarted(
        self,
        *,
        plan: ResolvedCampaignPlan,
        context: RowExecutionContext,
        case: XbenCase,
        expected_flag: str,
        reason: str,
    ) -> Mapping[str, object]:
        safe_reason = reason.replace(expected_flag, "[REDACTED]")[:1000]
        return record_unstarted_external_xben_row(
            case=case,
            agent=context.agent,
            binding=_row_binding(plan, context.row),
            row_dir=_row_output_path(context.row),
            process_backend=cast("ExternalProcessBackend", context.process_backend),
            expected_flag=expected_flag,
            reason=safe_reason,
            row_instance_id=context.instance_id,
        )

    def release_pair(
        self,
        *,
        prepared: PreparedHandle,
        backend: DockerComparisonTargetBackend,
    ) -> Mapping[str, object]:
        if not isinstance(prepared, PreparedCase):
            raise CampaignCoordinatorError("production runtime received a foreign prepared target")
        return backend.release_prepared(prepared=prepared)

    def terminalize_prepared_arm(
        self,
        *,
        prepared: PreparedHandle,
        context: RowExecutionContext,
        backend: DockerComparisonTargetBackend,
    ) -> Mapping[str, object]:
        if not isinstance(prepared, PreparedCase):
            raise CampaignCoordinatorError("production runtime received a foreign prepared target")
        return backend.terminalize_prepared_arm(
            prepared=prepared,
            arm=context.row.system,
            instance_id=context.instance_id,
            reason_code="prelaunch_failure",
        )

    def remove_agent_network(self, lease: AgentNetworkLease) -> None:
        self._network_manager.remove(lease)

    def _validate_xben_source(self, plan: ResolvedCampaignPlan) -> None:
        repository = _resolved_directory(self.configuration.xben_repository, "XBEN repository")
        source = _mapping(_mapping(plan.run_contract["sources"], "sources")["xben"], "XBEN")
        environment = {"PATH": self.configuration.trusted_path, "LC_ALL": "C", "LANG": "C"}
        for arguments, expected in (
            (("rev-parse", "--show-toplevel"), str(repository)),
            (("rev-parse", "--verify", "HEAD"), source["commit_sha"]),
            (("rev-parse", "--verify", "HEAD:benchmarks"), source["tree_object"]),
            (("status", "--porcelain=v1", "--untracked-files=all"), ""),
        ):
            result = self._runner.run(
                ("git", "-C", str(repository), *arguments),
                cwd=repository,
                environment=environment,
                timeout_seconds=self.configuration.timeouts.inspect_seconds,
            )
            observed = result.stdout.decode("utf-8", errors="replace").strip()
            if result.returncode != 0 or observed != expected:
                raise CampaignCoordinatorError("XBEN checkout differs from its frozen source")
        catalog = _mapping(plan.run_contract["compatibility_catalog"], "catalog")
        if _file_digest(self.configuration.compatibility_catalog) != _digest(
            catalog["sha256"], "compatibility catalog digest"
        ):
            raise CampaignCoordinatorError("compatibility catalog differs from commitment")

    def _validate_local_images(self, contract: Mapping[str, object]) -> None:
        for role in ("ravage_tool", "strix_sandbox", "target_gateway", "target_probe"):
            expected = (
                _target_helper_image_id(contract, role)
                if role in {"target_gateway", "target_probe"}
                else None
            )
            self._network_manager.inspect_image(
                _image_reference(contract, role),
                expected_id=expected,
            )


def _model_policy(contract: Mapping[str, object]) -> ModelGatewayPolicy:
    gateway = _mapping(contract["model_gateway"], "model gateway")
    value = _mapping(gateway["policy"], "model policy")
    pricing = _mapping(value["pricing_usd_per_million_tokens"], "model pricing")
    policy = ModelGatewayPolicy.build(
        model=_required_text(value["model"], "model"),
        reasoning_effort=_required_text(value["reasoning_effort"], "reasoning effort"),
        pricing=ModelPricing.from_numbers(
            input_per_million=_required_text(pricing["input_per_million"], "input price"),
            cached_input_per_million=_required_text(
                pricing["cached_input_per_million"], "cached input price"
            ),
            output_per_million=_required_text(pricing["output_per_million"], "output price"),
        ),
        campaign_max_cost_usd=_required_text(value["campaign_max_cost_usd"], "campaign cost cap"),
        max_completion_tokens_per_request=_positive_int(
            value["max_completion_tokens_per_request"], "completion cap"
        ),
        max_request_body_bytes=_positive_int(value["max_request_body_bytes"], "request cap"),
        max_upstream_response_bytes=_positive_int(
            value["max_upstream_response_bytes"], "response cap"
        ),
        upstream_timeout_seconds=_positive_int(
            value["upstream_timeout_seconds"], "upstream timeout"
        ),
        max_parallel_requests=_positive_int(value["max_parallel_requests"], "parallel cap"),
    )
    if policy.to_json() != dict(value) or policy.to_json() != gateway.get("policy"):
        raise CampaignCoordinatorError("model gateway policy does not reproduce exactly")
    policy_digest = gateway.get("policy_sha256")
    if policy_digest is not None and _json_digest(policy.to_json()) != policy_digest:
        raise CampaignCoordinatorError("model gateway policy digest does not reproduce")
    return policy


def _external_limits(contract: Mapping[str, object]) -> ExternalExecutionLimits:
    row = _mapping(_mapping(contract["budgets"], "budgets")["per_row"], "row budget")
    return ExternalExecutionLimits(
        wall_seconds=_positive_int(row["wall_seconds"], "row wall cap"),
        max_model_requests=_positive_int(row["max_model_requests"], "row model cap"),
        max_target_requests=_positive_int(row["max_target_requests"], "row target cap"),
        max_cost_usd=Decimal(_money_text(row["max_cost_usd"], "row cost cap")),
    )


def _unstarted_agent(
    *, row: ScheduledRow, gateway: RowModelGateway, limits: ExternalExecutionLimits
) -> ExternalAgentCommand:
    return ExternalAgentCommand(
        name="Ravage" if row.system == "ravage" else "Strix",
        system_id=row.system,
        command=(str(Path(sys.executable).resolve(strict=True)), "-c", "raise SystemExit(127)"),
        artifact_path=CANDIDATE_ARTIFACT_PATH,
        limits=limits,
        reasoning_effort=gateway.reasoning_effort,
        provider="paired-row-gateway",
        model=gateway.model,
        adapter_version=ADAPTER_VERSION,
        environment={
            COMPARISON_GATEWAY_TOKEN_ENV: gateway.token,
            GATEWAY_BASE_URL_ENV: gateway.base_url,
            OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
        },
        environment_allowlist=(
            COMPARISON_GATEWAY_TOKEN_ENV,
            GATEWAY_BASE_URL_ENV,
            OUTER_PROCESS_GROUP_ENV,
        ),
    )


def _row_binding(plan: ResolvedCampaignPlan, row: ScheduledRow) -> ComparisonRowBinding:
    return ComparisonRowBinding(
        campaign_id=plan.campaign_id,
        commitment_digest=plan.commitment_digest,
        selection_digest=plan.selection_digest,
        primary_slot_id=row.slot_id,
    )


def _image_reference(contract: Mapping[str, object], role: str) -> str:
    images = _mapping(contract["oci_images"], "OCI images")
    value = images.get(role)
    if isinstance(value, str):
        return _required_text(value, f"{role} image")
    if isinstance(value, Mapping):
        return _required_text(value.get("reference"), f"{role} image")
    raise CampaignCoordinatorError(f"{role} image contract is invalid")


def _target_helper_image_id(contract: Mapping[str, object], role: str) -> str:
    helpers = _mapping(contract.get("target_helper_image_ids"), "target helper image IDs")
    value = _digest(helpers.get(role), f"{role} image ID")
    return value


def _normalized_read_roots(paths: Sequence[Path]) -> tuple[Path, ...]:
    roots: set[Path] = set()
    for raw in paths:
        if raw.is_symlink():
            raise CampaignCoordinatorError("runtime read root cannot be a symlink")
        try:
            path = raw.expanduser().resolve(strict=True)
        except OSError as exc:
            raise CampaignCoordinatorError("runtime read root is unavailable") from exc
        root = path if path.is_dir() else path.parent
        if root == Path("/"):
            raise CampaignCoordinatorError("runtime read root cannot be filesystem root")
        roots.add(root)
    return tuple(sorted(roots))


def _json_list_digest(values: list[str]) -> str:
    body = json.dumps(values, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _absolute_path(value: object, label: str) -> Path:
    text = _required_text(value, label)
    path = Path(text)
    if not path.is_absolute() or "\x00" in text or any(part in {".", ".."} for part in path.parts):
        raise CampaignCoordinatorError(f"{label} must be a canonical absolute path")
    return path


def _paths_overlap(first: Path, second: Path) -> bool:
    first = first.expanduser().resolve(strict=False)
    second = second.expanduser().resolve(strict=False)
    with contextlib.suppress(ValueError):
        first.relative_to(second)
        return True
    with contextlib.suppress(ValueError):
        second.relative_to(first)
        return True
    return False


def _require_distinct_docker_authorities(
    *,
    target_socket: Path,
    agent_socket: Path,
) -> None:
    """Fail closed when the agent can control the target's Docker daemon."""

    target = target_socket.resolve(strict=True)
    agent = agent_socket.resolve(strict=True)
    if target == agent or target.samefile(agent):
        raise CampaignCoordinatorError(
            "agent and target share Docker authority; use distinct daemons or a "
            "capability-filtered agent proxy"
        )


def _require_loopback_port_free(port: int) -> None:
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        first.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        first.bind(("127.0.0.1", port))
    except OSError as exc:
        raise CampaignCoordinatorError("frozen Ravage target loopback port is unavailable") from exc
    finally:
        first.close()


def _validate_contract_for_local_execution(contract: Mapping[str, object], *, root: Path) -> None:
    if contract.get("mode") != "description-only-black-box":
        raise CampaignCoordinatorError("only description-only black-box campaigns can execute")
    execution = _mapping(contract.get("execution_policy"), "execution policy")
    host = _mapping(execution.get("evaluator_host"), "evaluator host")
    systems = _mapping(host.get("systems"), "evaluator host systems")
    for system in SYSTEMS:
        policy = _mapping(systems.get(system), f"{system} host policy")
        if policy.get("evidence_class") != PAIRED_LOCAL:
            raise CampaignCoordinatorError(
                "this executor currently supports paired_local evidence only"
            )
        if policy.get("docker_socket_access") is not True:
            raise CampaignCoordinatorError("paired_local must explicitly freeze Docker access")
    components = _mapping(contract.get("evaluator_components"), "evaluator components")
    for relative, expected in components.items():
        if not isinstance(relative, str) or not relative or ".." in Path(relative).parts:
            raise CampaignCoordinatorError("evaluator component path is unsafe")
        path = _REPOSITORY_ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise CampaignCoordinatorError(f"frozen evaluator component is absent: {relative}")
        if _file_digest(path) != _digest(expected, f"evaluator component {relative}"):
            raise CampaignCoordinatorError(f"frozen evaluator component drifted: {relative}")
    if (root / MODEL_CAMPAIGN_RECEIPT_FILE).exists() or (root / PRIMARY_RESULTS_FILE).exists():
        raise CampaignAlreadyStartedError("campaign already contains terminal execution seals")


def _load_exact_schedule(
    selection: Mapping[str, object], *, root: Path
) -> tuple[ScheduledRow, ...]:
    raw_schedule = selection.get("schedule")
    selected = selection.get("selected_case_ids")
    if (
        not isinstance(raw_schedule, list)
        or len(raw_schedule) != EXPECTED_ROWS
        or not isinstance(selected, list)
        or len(selected) != EXPECTED_PAIRS
        or any(
            not isinstance(value, str) or _CASE_RE.fullmatch(value) is None for value in selected
        )
        or len(set(selected)) != EXPECTED_PAIRS
    ):
        raise CampaignCoordinatorError("selection is not an exact 20-case/40-row matrix")
    rows: list[ScheduledRow] = []
    for index, value in enumerate(raw_schedule, start=1):
        if not isinstance(value, Mapping):
            raise CampaignCoordinatorError("schedule row is not an object")
        slot_id = value.get("slot_id")
        match = _ROW_RE.fullmatch(slot_id) if isinstance(slot_id, str) else None
        case_id = value.get("case_id")
        system = value.get("system")
        pair_index = value.get("pair_index")
        position = value.get("position_within_pair")
        if (
            match is None
            or int(match.group(1)) != index
            or value.get("slot") != index
            or not isinstance(case_id, str)
            or case_id not in selected
            or system not in SYSTEMS
            or isinstance(pair_index, bool)
            or not isinstance(pair_index, int)
            or not 1 <= pair_index <= EXPECTED_PAIRS
            or position not in {1, 2}
            or value.get("purpose") != "primary"
            or value.get("score_eligible") is not True
        ):
            raise CampaignCoordinatorError(f"invalid scheduled primary row at position {index}")
        assert isinstance(slot_id, str)
        assert isinstance(case_id, str)
        assert isinstance(pair_index, int)
        artifact_root = root / "attempts" / "primary" / slot_id / "artifacts"
        if artifact_root.is_symlink() or not artifact_root.is_dir():
            raise CampaignCoordinatorError(f"reserved artifact root is invalid: {slot_id}")
        if any(artifact_root.iterdir()):
            raise CampaignAlreadyStartedError(f"reserved row already has evidence: {slot_id}")
        rows.append(
            ScheduledRow(
                slot_id=slot_id,
                case_id=case_id,
                system=cast("Literal['ravage', 'strix']", system),
                pair_index=pair_index,
                position_within_pair=cast("int", position),
                artifact_root=artifact_root,
            )
        )
    _validate_adjacent_pairs(rows)
    return tuple(rows)


def _validate_loaded_plan(plan: ResolvedCampaignPlan) -> None:
    if len(plan.schedule) != EXPECTED_ROWS:
        raise CampaignCoordinatorError("loaded campaign does not contain exactly 40 rows")
    if any(
        row.slot_id != f"primary-{index:03d}" for index, row in enumerate(plan.schedule, start=1)
    ):
        raise CampaignCoordinatorError("loaded campaign row IDs are not exact and ordered")
    _validate_adjacent_pairs(plan.schedule)
    validate_run_contract(plan.run_contract)
    execution = _mapping(plan.run_contract.get("execution_policy"), "execution policy")
    host = _mapping(execution.get("evaluator_host"), "evaluator host")
    host_systems = _mapping(host.get("systems"), "evaluator host systems")
    if any(
        _mapping(host_systems.get(system), f"{system} host policy").get("evidence_class")
        != PAIRED_LOCAL
        for system in SYSTEMS
    ):
        raise CampaignCoordinatorError("loaded executor supports paired_local evidence only")
    budgets = _mapping(plan.run_contract.get("budgets"), "budgets")
    row_budget = _mapping(budgets.get("per_row"), "row budget")
    campaign_budget = _mapping(budgets.get("campaign"), "campaign budget")
    for name in ("wall_seconds", "max_model_requests", "max_target_requests"):
        if _positive_int(campaign_budget.get(name), f"campaign {name}") != (
            EXPECTED_ROWS * _positive_int(row_budget.get(name), f"row {name}")
        ):
            raise CampaignCoordinatorError(f"campaign {name} is not forty row reservations")
    row_cost = Decimal(_money_text(row_budget.get("max_cost_usd"), "row cost"))
    with localcontext() as context:
        context.prec = max(context.prec, len(row_cost.as_tuple().digits) + len(str(EXPECTED_ROWS)))
        reserved_cost = EXPECTED_ROWS * row_cost
    if Decimal(_money_text(campaign_budget.get("max_cost_usd"), "campaign cost")) != reserved_cost:
        raise CampaignCoordinatorError("campaign cost cap is not forty row reservations")


def _validate_adjacent_pairs(rows: Sequence[ScheduledRow]) -> None:
    seen_cases: set[str] = set()
    for offset in range(0, len(rows), 2):
        pair = rows[offset : offset + 2]
        expected_pair = offset // 2 + 1
        if (
            len(pair) != 2
            or pair[0].pair_index != expected_pair
            or pair[1].pair_index != expected_pair
            or pair[0].position_within_pair != 1
            or pair[1].position_within_pair != 2
            or pair[0].case_id != pair[1].case_id
            or {pair[0].system, pair[1].system} != set(SYSTEMS)
            or pair[0].case_id in seen_cases
        ):
            raise CampaignCoordinatorError(
                "schedule is not 20 exact adjacent counterbalanced pairs"
            )
        seen_cases.add(pair[0].case_id)
    if len(seen_cases) != EXPECTED_PAIRS:
        raise CampaignCoordinatorError("schedule does not cover 20 distinct cases")


def _validate_row_context(context: RowExecutionContext, *, expected: ScheduledRow) -> None:
    receipt_contract = getattr(context.process_backend, "receipt_contract", None)
    if (
        context.row != expected
        or not _INSTANCE_RE.fullmatch(context.instance_id)
        or context.network_name != _network_name(context.instance_id)
        or context.agent.system_id != expected.system
        or getattr(receipt_contract, "row_id", None) != expected.slot_id
    ):
        raise CampaignCoordinatorError(f"row runtime is misbound: {expected.slot_id}")


def _validate_unstarted_row_context(
    context: RowExecutionContext, *, expected: ScheduledRow
) -> None:
    _validate_row_context(context, expected=expected)
    if not context.setup_error:
        raise CampaignCoordinatorError("registration-only fallback context lacks its setup failure")


def _validate_network_lease(lease: AgentNetworkLease, *, context: RowExecutionContext) -> None:
    if (
        lease.instance_id != context.instance_id
        or lease.name != context.network_name
        or _RAW_SHA256_RE.fullmatch(lease.network_id) is None
    ):
        raise CampaignCoordinatorError(f"agent network is misbound: {context.row.slot_id}")


def _validate_prepared_handle(prepared: PreparedHandle, *, pair_id: str, case_id: str) -> None:
    if prepared.pair_id != pair_id or prepared.benchmark_id != case_id:
        raise CampaignCoordinatorError("prepared target differs from its adjacent pair")
    path = prepared.evidence_dir / "prepared.json"
    if path.is_symlink() or not path.is_file():
        raise CampaignCoordinatorError("prepared target has no retained provenance")


def _validate_prepared_terminalization(
    result: Mapping[str, object],
    *,
    prepared: PreparedHandle,
    context: RowExecutionContext,
    expected_flag: str,
) -> None:
    if (
        result.get("pair_id") != prepared.pair_id
        or result.get("benchmark_id") != prepared.benchmark_id
        or result.get("arm") != context.row.system
        or result.get("instance_id") != context.instance_id
        or result.get("pair_flag_sha256")
        != hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
        or result.get("row_terminal") is not True
        or result.get("valid") is not True
    ):
        raise CampaignCoordinatorError(
            f"prepared target arm did not terminalize exactly: {context.row.slot_id}"
        )


def _validate_pair_release(result: Mapping[str, object], *, prepared: PreparedHandle) -> None:
    if result.get("valid") is not True:
        raise CampaignCoordinatorError(f"prepared target release is invalid: {prepared.pair_id}")
    if result.get("pair_id") not in {None, prepared.pair_id}:
        raise CampaignCoordinatorError(f"prepared target release is misbound: {prepared.pair_id}")
    if result.get("benchmark_id") not in {None, prepared.benchmark_id}:
        raise CampaignCoordinatorError(
            f"prepared target release case is misbound: {prepared.pair_id}"
        )


def _validated_pair_release_path(prepared: PreparedHandle) -> Path:
    candidate = prepared.evidence_dir / "release.json"
    if candidate.is_symlink() or not candidate.is_file():
        raise CampaignCoordinatorError("prepared pair release has no retained evidence")
    return candidate


def _validate_terminal_result(result: Mapping[str, object], row: ScheduledRow) -> None:
    _validate_terminal_payload(result, row)
    output = _row_output_path(row)
    if output.is_symlink() or not output.is_dir():
        raise CampaignCoordinatorError(f"row terminal evidence is missing: {row.slot_id}")
    retained = _load_json(output / "row-result.json", f"{row.slot_id} row result")
    _validate_terminal_payload(retained, row)
    if retained != dict(result):
        raise CampaignCoordinatorError(
            f"returned row result differs from retained evidence: {row.slot_id}"
        )
    _validate_terminal_files(output, row=row)


def _validate_terminal_payload(result: Mapping[str, object], row: ScheduledRow) -> None:
    binding = result.get("schedule_binding")
    case = result.get("case")
    agent = result.get("agent")
    if (
        result.get("status") not in _TERMINAL_STATUSES
        or not isinstance(binding, Mapping)
        or binding.get("primary_slot_id") != row.slot_id
        or not isinstance(case, Mapping)
        or case.get("benchmark_id") != row.case_id
        or not isinstance(agent, Mapping)
        or agent.get("system_id") != row.system
    ):
        raise CampaignCoordinatorError(f"row did not return bound terminal evidence: {row.slot_id}")


def _validate_terminal_files(output: Path, *, row: ScheduledRow) -> None:
    for name in (
        "artifacts.sha256",
        "process-receipt.json",
        "model-gateway-receipt.json",
        "sandbox-profile.sb",
        "target-build.json",
        "target-teardown.json",
    ):
        path = output / name
        if path.is_symlink() or not path.is_file():
            raise CampaignCoordinatorError(
                f"row terminal evidence {name} is missing: {row.slot_id}"
            )


def _recover_retained_terminal_result(row: ScheduledRow) -> bool:
    """Recognize a row that terminalized before its runtime raised to us."""

    output = _row_output_path(row)
    try:
        if output.is_symlink() or not output.is_dir():
            return False
        retained = _load_json(output / "row-result.json", f"{row.slot_id} row result")
        _validate_terminal_payload(retained, row)
        _validate_terminal_files(output, row=row)
    except (OSError, CampaignCoordinatorError):
        return False
    return True


def _write_primary_results(
    plan: ResolvedCampaignPlan, *, pair_evidence: Sequence[_PairEvidence]
) -> Path:
    if len(pair_evidence) != EXPECTED_PAIRS:
        raise CampaignCoordinatorError("not every adjacent pair reached a terminal scheduler state")
    rows: list[dict[str, object]] = []
    for row in plan.schedule:
        root = _row_output_path(row)
        if root.is_symlink() or not root.is_dir():
            raise CampaignCoordinatorError(f"row evidence directory is absent: {row.slot_id}")
        rows.append(
            {
                "slot_id": row.slot_id,
                "row_manifest_sha256": _required_file_digest(root / "artifacts.sha256"),
                "row_result_sha256": _required_file_digest(root / "row-result.json"),
                "adapter_result_sha256": _optional_file_digest(
                    root / "native-output" / "adapter-result.json"
                ),
                "process_receipt_sha256": _required_file_digest(root / "process-receipt.json"),
                "model_gateway_receipt_sha256": _required_file_digest(
                    root / "model-gateway-receipt.json"
                ),
                "sandbox_profile_sha256": _required_file_digest(root / "sandbox-profile.sb"),
                "target_build_sha256": _required_file_digest(root / "target-build.json"),
                "target_teardown_sha256": _required_file_digest(root / "target-teardown.json"),
            }
        )
    pairs: list[dict[str, object]] = []
    for expected_index, pair in enumerate(pair_evidence, start=1):
        scheduled_first = plan.schedule[(expected_index - 1) * 2]
        if pair.pair_index != expected_index or pair.case_id != scheduled_first.case_id:
            raise CampaignCoordinatorError("pair evidence is not in frozen schedule order")
        pair_id, prepared_path, release_path = _sealed_pair_from_first_row(
            plan,
            row=scheduled_first,
            scheduler_evidence=pair,
        )
        pairs.append(
            {
                "pair_index": pair.pair_index,
                "case_id": pair.case_id,
                "pair_id": pair_id,
                "prepared_target_sha256": (
                    _required_file_digest(prepared_path) if prepared_path is not None else None
                ),
                "release_sha256": (
                    _required_file_digest(release_path) if release_path is not None else None
                ),
            }
        )
    body: dict[str, object] = {
        "schema_version": PRIMARY_RESULTS_SCHEMA,
        "created_at": _now(),
        "campaign_id": plan.campaign_id,
        "commitment_digest": plan.commitment_digest,
        "selection_digest": plan.selection_digest,
        "row_count": EXPECTED_ROWS,
        "rows": rows,
        "paired_targets": pairs,
        "all_terminal": True,
    }
    body["document_sha256"] = _json_digest(body)
    path = plan.campaign_root / PRIMARY_RESULTS_FILE
    _write_json_exclusive(path, body)
    return path


def _validate_gateway_campaign_seal(
    path: Path,
    *,
    returned: Mapping[str, object],
) -> dict[str, object]:
    retained = _load_json(path, "model gateway campaign seal")
    body = {key: value for key, value in retained.items() if key != "document_sha256"}
    if retained != dict(returned) or retained.get("document_sha256") != _json_digest(body):
        raise CampaignCoordinatorError(
            "model gateway returned a campaign seal that differs from retained evidence"
        )
    return retained


def _sealed_pair_from_first_row(
    plan: ResolvedCampaignPlan,
    *,
    row: ScheduledRow,
    scheduler_evidence: _PairEvidence,
) -> tuple[str | None, Path | None, Path | None]:
    """Reproduce the report's first-arm rule for its paired-target seal.

    A pair can have been prepared even though its first arm never produced
    independently usable target evidence.  The report deliberately treats such
    a pair as unavailable, so the coordinator must derive this field from the
    first scheduled row rather than from its private in-memory handle.
    """

    row_root = _row_output_path(row)
    build = _load_json(row_root / "target-build.json", f"{row.slot_id} target build")
    teardown = _load_json(
        row_root / "target-teardown.json",
        f"{row.slot_id} target teardown",
    )
    provenance = build.get("provenance")
    if (
        build.get("status") != "succeeded"
        or teardown.get("status") != "succeeded"
        or not isinstance(provenance, Mapping)
    ):
        return None, None, None
    pair_id = provenance.get("pair_id")
    raw_prepared_path = provenance.get("prepared_provenance_path")
    if not isinstance(pair_id, str) or not isinstance(raw_prepared_path, str):
        raise CampaignCoordinatorError(
            f"first-arm prepared provenance is incomplete: {row.slot_id}"
        )
    prepared_path = Path(raw_prepared_path)
    if not prepared_path.is_absolute() or prepared_path.is_symlink():
        raise CampaignCoordinatorError(
            f"first-arm prepared provenance is not canonical: {row.slot_id}"
        )
    try:
        resolved_prepared = prepared_path.resolve(strict=True)
        resolved_campaign = plan.campaign_root.resolve(strict=True)
        resolved_prepared.relative_to(resolved_campaign)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CampaignCoordinatorError(
            f"first-arm prepared provenance escapes the campaign: {row.slot_id}"
        ) from exc
    if (
        prepared_path != resolved_prepared
        or prepared_path.name != "prepared.json"
        or not prepared_path.is_file()
        or scheduler_evidence.prepared_path is None
        or scheduler_evidence.prepared_path.resolve(strict=True) != prepared_path
    ):
        raise CampaignCoordinatorError(
            f"first-arm prepared provenance differs from scheduler state: {row.slot_id}"
        )
    if pair_id != scheduler_evidence.pair_id or scheduler_evidence.case_id != row.case_id:
        raise CampaignCoordinatorError(
            f"first-arm pair identity differs from scheduler state: {row.slot_id}"
        )
    release_path = prepared_path.parent / "release.json"
    if release_path.is_symlink():
        raise CampaignCoordinatorError(f"pair release evidence is a symlink: {row.slot_id}")
    if release_path.exists() and not release_path.is_file():
        raise CampaignCoordinatorError(f"pair release evidence is not a file: {row.slot_id}")
    return pair_id, prepared_path, release_path if release_path.is_file() else None


def _new_row_instances(
    schedule: Sequence[ScheduledRow], *, instance_hex: Callable[[int], str]
) -> dict[str, str]:
    result: dict[str, str] = {}
    seen: set[str] = set()
    for row in schedule:
        nonce = instance_hex(16)
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
            raise CampaignCoordinatorError("instance entropy source returned an invalid nonce")
        instance = f"xben-row-{nonce}"
        if instance in seen:
            raise CampaignCoordinatorError("instance entropy source repeated a nonce")
        seen.add(instance)
        result[row.slot_id] = instance
    return result


def _new_pair_flags(*, flag_hex: Callable[[int], str]) -> tuple[str, ...]:
    flags = tuple(_new_pair_flag(flag_hex) for _ in range(EXPECTED_PAIRS))
    if len(set(flags)) != EXPECTED_PAIRS:
        raise CampaignCoordinatorError("flag entropy source repeated a pair nonce")
    return flags


def _new_pair_flag(flag_hex: Callable[[int], str]) -> str:
    nonce = flag_hex(32)
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise CampaignCoordinatorError("flag entropy source returned an invalid 256-bit nonce")
    return f"flag{{ravage_cmp_{nonce}}}"


def _network_name(instance_id: str) -> str:
    if _INSTANCE_RE.fullmatch(instance_id) is None:
        raise CampaignCoordinatorError("row instance ID is invalid")
    return f"ravage-agent-{instance_id.removeprefix('xben-row-')}"


def _validated_loopback_gateway_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        port = None
        parsed = None
    if parsed is None:
        raise CampaignCoordinatorError("model gateway returned a non-loopback URL")
    valid = bool(
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None
        and 1 <= port <= 65535
        and parsed.path == "/v1"
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )
    if not valid:
        raise CampaignCoordinatorError("model gateway returned a non-loopback URL")
    return value


def _row_output_path(row: ScheduledRow) -> Path:
    return row.artifact_root / ROW_DIRECTORY


def _remove_network_once(
    runtime: CampaignExecutionRuntime,
    lease: AgentNetworkLease,
    *,
    errors: list[dict[str, object]],
) -> bool:
    try:
        runtime.remove_agent_network(lease)
    except Exception as exc:  # noqa: BLE001 - a teardown failure is retained, never retried.
        errors.append(_error_record("agent_network_remove", exc))
        return False
    return True


def _error_record(
    stage: str,
    exc: BaseException,
    *,
    row: ScheduledRow | None = None,
    sensitive_values: Sequence[str] = (),
) -> dict[str, object]:
    message = str(exc)
    variants: set[str] = set()
    for sensitive in sensitive_values:
        if sensitive:
            secrets_to_remove = {sensitive}
            flag_match = _PAIR_FLAG_RE.fullmatch(sensitive)
            if flag_match is not None:
                secrets_to_remove.add(flag_match.group(1))
        else:
            secrets_to_remove = set()
        for secret in secrets_to_remove:
            raw = secret.encode("utf-8")
            variants.update(
                {
                    secret,
                    quote(secret, safe=""),
                    quote_plus(secret, safe=""),
                    raw.hex(),
                    base64.b64encode(raw).decode("ascii"),
                    base64.urlsafe_b64encode(raw).decode("ascii"),
                    base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
                }
            )
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            message = message.replace(variant, "[REDACTED]")
    message = message.replace("\n", " ").replace("\r", " ")[:500]
    return {
        "stage": stage,
        "slot_id": row.slot_id if row is not None else None,
        "case_id": row.case_id if row is not None else None,
        "exception_type": type(exc).__name__,
        "message": message,
    }


def _row_sensitive_values(context: RowExecutionContext, *, expected_flag: str) -> tuple[str, ...]:
    environment = getattr(context.agent, "environment", {})
    retained = [expected_flag]
    if isinstance(environment, Mapping):
        token = environment.get(COMPARISON_GATEWAY_TOKEN_ENV)
        if isinstance(token, str) and token:
            retained.append(token)
    return tuple(retained)


def _assert_execution_unclaimed(campaign_root: Path) -> None:
    path = campaign_root / EXECUTION_DIRECTORY
    if path.exists() or path.is_symlink():
        raise CampaignAlreadyStartedError(
            "campaign execution namespace already exists; resume is forbidden"
        )


def _claim_execution_root(campaign_root: Path) -> Path:
    path = campaign_root / EXECUTION_DIRECTORY
    try:
        path.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise CampaignAlreadyStartedError(
            "campaign execution namespace already exists; resume is forbidden"
        ) from exc
    return path


def _document(body: Mapping[str, object]) -> dict[str, object]:
    if "document_sha256" in body:
        raise CampaignCoordinatorError("document body already contains a digest")
    copied = dict(body)
    return {**copied, "document_sha256": _json_digest(copied)}


def _json_digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _write_json_exclusive(path: Path, value: Mapping[str, object]) -> None:
    body = json.dumps(value, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _write_bytes_exclusive(path, body)


def _write_bytes_exclusive(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _required_file_digest(path: Path | None) -> str:
    if path is None or path.is_symlink() or not path.is_file():
        raise CampaignCoordinatorError(f"required terminal evidence is absent: {path}")
    return _file_digest(path)


def _optional_file_digest(path: Path) -> str | None:
    if path.is_symlink():
        raise CampaignCoordinatorError(f"optional evidence is a symlink: {path}")
    return _file_digest(path) if path.is_file() else None


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise CampaignCoordinatorError(f"evidence is not a regular file: {path}")
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise CampaignCoordinatorError(f"{label} is unavailable")
    raw = path.read_bytes()
    if not raw or len(raw) > _MAX_JSON_BYTES:
        raise CampaignCoordinatorError(f"{label} has an invalid size")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignCoordinatorError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise CampaignCoordinatorError(f"{label} must be a JSON object")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CampaignCoordinatorError("JSON document contains a duplicate key")
        result[key] = value
    return result


def _resolved_directory(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise CampaignCoordinatorError(f"{label} cannot be a symlink")
    try:
        result = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise CampaignCoordinatorError(f"{label} is unavailable") from exc
    if not result.is_dir():
        raise CampaignCoordinatorError(f"{label} is not a directory")
    return result


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CampaignCoordinatorError(f"{label} is not an object")
    return value


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise CampaignCoordinatorError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CampaignCoordinatorError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CampaignCoordinatorError(f"{label} must be positive")
    return value


def _money_text(value: object, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise CampaignCoordinatorError(f"{label} is invalid")
    try:
        decimal = Decimal(str(value))
    except Exception as exc:
        raise CampaignCoordinatorError(f"{label} is invalid") from exc
    if not decimal.is_finite() or decimal <= 0:
        raise CampaignCoordinatorError(f"{label} must be finite and positive")
    normalized = format(decimal, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized


def _now() -> str:
    return datetime.now(UTC).isoformat()
