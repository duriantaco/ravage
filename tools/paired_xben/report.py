# ruff: noqa: C901,EM101,EM102,PLR0912,PLR0915,SIM113,TRY003
"""Fail-closed aggregation for one completed paired-XBEN-20 campaign."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import ModuleType
from typing import Final, cast
from urllib.parse import urlsplit

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PACKAGE_SOURCE = (_REPOSITORY_ROOT / "packages" / "ravage" / "src").resolve(strict=True)
sys.path.insert(0, str(_PACKAGE_SOURCE))

import ravage as _ravage_package  # noqa: E402
from ravage.xben_parts import comparison_adapters as _adapter_module  # noqa: E402
from ravage.xben_parts import comparison_model_gateway as _model_module  # noqa: E402
from ravage.xben_parts import comparison_process_backend as _process_module  # noqa: E402
from ravage.xben_parts import comparison_target as _target_module  # noqa: E402
from ravage.xben_parts import external_comparison as _external_module  # noqa: E402


def _require_fixed_module(module: ModuleType, relative: str) -> None:
    raw_path = getattr(module, "__file__", None)
    expected = _PACKAGE_SOURCE / relative
    if not isinstance(raw_path, str):
        raise RuntimeError(f"comparison validator module {relative} has no source file")
    candidate = Path(raw_path)
    if candidate.is_symlink() or candidate.resolve(strict=True) != expected.resolve(strict=True):
        raise RuntimeError(f"comparison validator module {relative} is not workspace-bound")


_require_fixed_module(_ravage_package, "ravage/__init__.py")
_require_fixed_module(_adapter_module, "ravage/xben_parts/comparison_adapters.py")
_require_fixed_module(_model_module, "ravage/xben_parts/comparison_model_gateway.py")
_require_fixed_module(_process_module, "ravage/xben_parts/comparison_process_backend.py")
_require_fixed_module(_target_module, "ravage/xben_parts/comparison_target.py")
_require_fixed_module(_external_module, "ravage/xben_parts/external_comparison.py")

from ravage.xben_parts.comparison_adapters import extract_artifact_candidates  # noqa: E402
from ravage.xben_parts.comparison_contracts import decimal_text  # noqa: E402
from ravage.xben_parts.comparison_model_gateway import (  # noqa: E402
    ModelGatewayError,
    validate_model_gateway_campaign_receipt,
    validate_model_gateway_receipt,
)
from ravage.xben_parts.comparison_process_backend import (  # noqa: E402
    ComparisonProcessError,
    validate_comparison_process_receipt_public,
    validate_unstarted_comparison_process_receipt,
)
from ravage.xben_parts.comparison_target import (  # noqa: E402
    DockerEvidenceError,
    validate_prepared_target_arm_provenance,
    validate_prepared_target_provenance,
    validate_request_meter_stop_provenance,
)
from ravage.xben_parts.external_comparison import ExternalExecutionLimits  # noqa: E402

from tools.paired_xben.protocol import (
    PairedXbenProtocolError,
    validate_run_contract,
    verify_campaign,
)

REPORT_SCHEMA: Final = "ravage.paired-xben.report.v3"
ROW_RESULT_SCHEMA: Final = "ravage.xben.external-comparison-row.v3"
FLAG_COMMITMENT_SCHEMA: Final = "ravage.xben.flag-commitment.v2"
FLAG_COMMITMENT_FILE: Final = "flag-commitment.json"
ADAPTER_RESULT_FILE: Final = "native-output/adapter-result.json"
MODEL_GATEWAY_RECEIPT_FILE: Final = "model-gateway-receipt.json"
PROCESS_RECEIPT_FILE: Final = "process-receipt.json"
SANDBOX_PROFILE_FILE: Final = "sandbox-profile.sb"
MODEL_GATEWAY_CAMPAIGN_RECEIPT_FILE: Final = "campaign-model-gateway.json"
PRIMARY_RESULTS_SEAL_FILE: Final = "primary-results.json"
PRIMARY_RESULTS_SEAL_SCHEMA: Final = "ravage.paired-xben.primary-results.v1"
PUBLIC_EXECUTION_ATTESTATION_FILE: Final = "public-execution-attestation.json"
REPORT_FILE: Final = "report.json"
REPORT_MANIFEST_FILE: Final = "artifacts.sha256"
EXPECTED_SYSTEMS: Final = ("ravage", "strix")
EXPECTED_CASES: Final = 20
EXPECTED_ROWS: Final = 40
OUTER_PROCESS_GROUP_ENV: Final = "RAVAGE_COMPARISON_OUTER_PROCESS_GROUP"
TERMINAL_STATUSES: Final = (
    "solved",
    "failed",
    "timed_out",
    "errored",
    "infrastructure_error",
)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_HEX_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_SLOT_RE = re.compile(r"primary-(\d{3})")
_EXPECTED_FLAG_RE = re.compile(r"flag\{ravage_cmp_[0-9a-f]{64}\}")
_EXPECTED_FLAG_BYTES_RE = re.compile(rb"flag\{ravage_cmp_[0-9a-f]{64}\}")
_FLAG_CANDIDATE_BYTES_RE = re.compile(rb"(?i)(?:flag|xben|ctf|htb)\{[^}\r\n]{1,512}\}")
_PRODUCER_FLAG_CANDIDATE_BYTES_RE = re.compile(rb"flag\{[^\r\n\x00]{1,4096}\}")
_INSTANCE_ID_RE = re.compile(r"xben-row-[0-9a-f]{32}")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_ROW_FILE_BYTES = 128 * 1024 * 1024
_MAX_ROW_FILES = 10_000


class PairedXbenReportError(ValueError):
    """A campaign cannot produce a trustworthy paired report."""


class IncompleteCampaignError(PairedXbenReportError):
    """One or more scheduled primary rows are not terminal."""


class EvidenceIntegrityError(PairedXbenReportError):
    """Retained evidence is ambiguous, unbound, or has changed."""


class ReportAlreadyExistsError(PairedXbenReportError):
    """The requested create-only report directory already exists."""


def aggregate_campaign(
    campaign_dir: Path,
    *,
    generated_at: str | None = None,
) -> dict[str, object]:
    """
    Validate all retained primaries and return one complete paired report.

    There is no partial-score mode. Diagnostic reruns are reported but never
    scored. Missing rows, duplicate result artifacts, and rows lacking a direct
    frozen-schedule binding all stop aggregation.
    """
    root = _directory(campaign_dir, "campaign directory")
    try:
        protocol = verify_campaign(root, require_all_primary_attempts=True)
    except (OSError, PairedXbenProtocolError) as exc:
        raise EvidenceIntegrityError(f"campaign protocol verification failed: {exc}") from exc
    if protocol.get("phase") != "resolved" or protocol.get("structurally_valid") is not True:
        raise EvidenceIntegrityError("campaign is not a structurally valid resolved campaign")

    selection = _load_json(root / "resolution" / "selection.json", "selection manifest")
    schedule = _validated_schedule(selection)
    selection_digest = _digest(selection.get("document_digest"), "selection digest")
    if protocol.get("selection_digest") != selection_digest:
        raise EvidenceIntegrityError("protocol verification and selection digest differ")
    campaign_id = _nonempty(selection.get("campaign_id"), "selection campaign_id")
    commitment_digest = _digest(selection.get("commitment_digest"), "selection commitment digest")
    commitment = _load_json(root / "commitment.json", "campaign commitment")
    run_contract = _frozen_run_contract(
        commitment,
        campaign_id=campaign_id,
        commitment_digest=commitment_digest,
    )
    rerun_count = _nonnegative_int(
        protocol.get("diagnostic_reruns"), "verified diagnostic rerun count"
    )

    primary_root = _directory(root / "attempts" / "primary", "primary attempts")
    expected_slots = {cast("str", row["slot_id"]) for row in schedule}
    actual_slots = _child_directory_names(primary_root, "primary attempts")
    missing = sorted(expected_slots - actual_slots)
    unexpected = sorted(actual_slots - expected_slots)
    if missing:
        raise IncompleteCampaignError(f"missing scheduled primary attempts: {missing}")
    if unexpected:
        raise EvidenceIntegrityError(f"unexpected primary attempt directories: {unexpected}")

    rows: list[dict[str, object]] = []
    row_roots: dict[str, Path] = {}
    independent_rows: list[dict[str, object]] = []
    for scheduled in schedule:
        slot_id = cast("str", scheduled["slot_id"])
        attempt_root = primary_root / slot_id
        attempt = _load_json(attempt_root / "attempt.json", f"attempt {slot_id}")
        _validate_attempt(
            attempt,
            scheduled=scheduled,
            campaign_id=campaign_id,
            commitment_digest=commitment_digest,
            selection_digest=selection_digest,
        )
        artifact_root = _directory(attempt_root / "artifacts", f"artifacts for {slot_id}")
        result_path = _one_row_result(artifact_root, slot_id=slot_id)
        _verify_row_manifest(result_path.parent)
        result = _load_json(result_path, f"row result {slot_id}")
        _validate_row_result(
            result,
            scheduled=scheduled,
            campaign_id=campaign_id,
            commitment_digest=commitment_digest,
            selection_digest=selection_digest,
        )
        _verify_declared_native_artifact(result, row_root=result_path.parent, slot_id=slot_id)
        _verify_row_lifecycle(result, row_root=result_path.parent, slot_id=slot_id)
        rows.append(result)
        row_roots[slot_id] = result_path.parent
        independent_rows.append(
            _verify_independent_row_evidence(
                result,
                scheduled=scheduled,
                row_root=result_path.parent,
                campaign_root=root,
                run_contract=run_contract,
            )
        )

    provider, model, reasoning_effort, limits = _common_execution_contract(
        rows, run_contract=run_contract
    )
    _validate_unique_row_state(schedule, rows)
    _validate_schedule_execution_order(rows)
    paired_targets_verified = _verify_paired_target_reuse(
        schedule,
        rows,
        independent_rows,
    )
    primary_results = _verify_primary_results_seal(
        root,
        schedule=schedule,
        rows=rows,
        row_roots=row_roots,
        independent_rows=independent_rows,
        campaign_id=campaign_id,
        commitment_digest=commitment_digest,
        selection_digest=selection_digest,
    )
    model_campaign = _verify_model_gateway_campaign_seal(
        root,
        independent_rows=independent_rows,
        run_contract=run_contract,
    )
    evaluator_components_verified = _verify_evaluator_component_sources(run_contract)
    public_execution_verified = _verify_public_execution_attestation(
        root,
        campaign_id=campaign_id,
        commitment_digest=commitment_digest,
        selection_digest=selection_digest,
        primary_results=primary_results,
        model_campaign=model_campaign,
    )
    status_counts = _status_counts(schedule, rows)
    elapsed = _elapsed_summary(schedule, rows)
    invalid_rows = sum(row.get("valid_for_comparison") is not True for row in rows)
    invalid_for_any_comparison_rows = sum(
        row.get("valid_for_comparison") is not True
        and row.get("valid_for_paired_local_comparison") is not True
        for row in rows
    )
    beacon_verified = protocol.get("beacon_authenticity_verified") is True
    publication_verified = protocol.get("publication_anchor_verified") is True
    namespace_verified = protocol.get("canonical_namespace_first_entry_verified") is True
    row_receipts_verified = all(
        evidence.get("adapter_verified") is True
        and evidence.get("model_gateway_verified") is True
        and evidence.get("process_verified") is True
        and evidence.get("target_verified") is True
        for evidence in independent_rows
    )
    # Pairwise rates are all-or-nothing. A valid terminal timeout/nonzero row
    # remains in the matrix as an unsolved observation, while infrastructure or
    # receipt failures withhold the whole matrix instead of becoming system losses.
    paired_results_available = bool(
        invalid_for_any_comparison_rows == 0
        and row_receipts_verified
        and len(rows) == EXPECTED_ROWS
    )
    result_summary = _paired_results(schedule, rows) if paired_results_available else None
    official_rows_verified = all(
        evidence.get("official_attestation_eligible") is True for evidence in independent_rows
    )
    execution_receipts_verified = bool(
        row_receipts_verified
        and official_rows_verified
        and paired_targets_verified
        and primary_results.get("verified") is True
        and model_campaign.get("verified") is True
        and evaluator_components_verified
    )
    # Child-writable agent trees are necessary to reproduce extraction, but an
    # untrusted agent can persist its raw row gateway token in an arbitrary
    # file.  The public report has only the token digest and therefore cannot
    # prove those trees publication-safe.  A future evaluator-owned allowlist
    # export must establish this independently before a public claim is ready.
    raw_agent_output_publication_verified = False
    claim_ready = (
        beacon_verified
        and publication_verified
        and namespace_verified
        and public_execution_verified
        and execution_receipts_verified
        and raw_agent_output_publication_verified
        and paired_results_available
        and invalid_rows == 0
        and len(rows) == EXPECTED_ROWS
    )
    timestamp = _timestamp(generated_at)
    withheld_reasons = []
    if not beacon_verified:
        withheld_reasons.append("drand_bls_authenticity_unverified")
    if not publication_verified:
        withheld_reasons.append("predraw_publication_timestamp_unverified")
    if not namespace_verified:
        withheld_reasons.append("canonical_public_namespace_unverified")
    if not public_execution_verified:
        withheld_reasons.append("public_execution_attestation_unverified")
    if primary_results.get("verified") is not True:
        withheld_reasons.append("primary_results_seal_unverified")
    if model_campaign.get("verified") is not True:
        withheld_reasons.append("campaign_model_seal_unverified")
    if not paired_targets_verified:
        withheld_reasons.append("paired_target_reuse_unverified")
    if not evaluator_components_verified:
        withheld_reasons.append("evaluator_component_sources_unverified")
    if not execution_receipts_verified:
        withheld_reasons.append("execution_receipts_unverified")
    if not raw_agent_output_publication_verified:
        withheld_reasons.append("raw_agent_output_publication_safety_unverified")
    if invalid_rows:
        withheld_reasons.append("invalid_primary_rows")
    paired_results_withheld_reasons = []
    if invalid_for_any_comparison_rows:
        paired_results_withheld_reasons.append("invalid_primary_rows")
    if not row_receipts_verified:
        paired_results_withheld_reasons.append("independent_row_evidence_unverified")
    return {
        "schema_version": REPORT_SCHEMA,
        "generated_at": timestamp,
        "claim_ready": claim_ready,
        "campaign": {
            "campaign_id": campaign_id,
            "commitment_digest": commitment_digest,
            "selection_digest": selection_digest,
        },
        "evidence_classification": {
            "kind": "exploratory_public_regression",
            "benchmark": "XBEN",
            "benchmark_visibility": "public",
            "paired_case_count": EXPECTED_CASES,
            "sota_claim_supported": False,
            "statement": (
                "This n=20 paired public-regression result is exploratory evidence, "
                "not a state-of-the-art claim."
            ),
            "raw_agent_output_publication_safe": raw_agent_output_publication_verified,
        },
        "integrity": {
            "complete": True,
            "scheduled_primary_rows": EXPECTED_ROWS,
            "terminal_primary_rows": EXPECTED_ROWS,
            "verified_row_manifests": EXPECTED_ROWS,
            "diagnostic_reruns": rerun_count,
            "diagnostic_reruns_present": rerun_count > 0,
            "diagnostic_reruns_scored": False,
            "invalid_for_comparison_rows": invalid_rows,
            "all_rows_valid_for_comparison": invalid_rows == 0,
            "beacon_bls_signature_verified": beacon_verified,
            "publication_anchor_verified": publication_verified,
            "canonical_namespace_first_entry_verified": namespace_verified,
            "public_execution_attestation_verified": public_execution_verified,
            "primary_results_seal_verified": primary_results.get("verified") is True,
            "campaign_model_seal_verified": model_campaign.get("verified") is True,
            "paired_target_reuse_verified": paired_targets_verified,
            "evaluator_component_sources_verified": evaluator_components_verified,
            "verified_adapter_receipts": sum(
                item.get("adapter_verified") is True for item in independent_rows
            ),
            "verified_model_gateway_row_receipts": sum(
                item.get("model_gateway_verified") is True for item in independent_rows
            ),
            "verified_process_receipts": sum(
                item.get("process_verified") is True for item in independent_rows
            ),
            "verified_unstarted_process_receipts": sum(
                item.get("unstarted_process_verified") is True for item in independent_rows
            ),
            "verified_target_receipts": sum(
                item.get("target_verified") is True for item in independent_rows
            ),
            "execution_receipts_verified": execution_receipts_verified,
            "raw_agent_output_publication_safety_verified": (raw_agent_output_publication_verified),
            "claim_ready": claim_ready,
        },
        "execution_contract": {
            "provider": provider,
            "model": model,
            "reasoning_effort": reasoning_effort,
            "service_tier": cast("Mapping[str, object]", run_contract["model_gateway"])[
                "service_tier"
            ],
            "store": cast("Mapping[str, object]", run_contract["model_gateway"])["store"],
            "model_gateway_policy_sha256": cast(
                "Mapping[str, object]", run_contract["model_gateway"]
            )["policy_sha256"],
            "pricing_usd_per_million_tokens": cast(
                "Mapping[str, object]",
                cast("Mapping[str, object]", run_contract["model_gateway"])["policy"],
            )["pricing_usd_per_million_tokens"],
            "max_completion_tokens_per_request": cast(
                "Mapping[str, object]",
                cast("Mapping[str, object]", run_contract["model_gateway"])["policy"],
            )["max_completion_tokens_per_request"],
            "target_platform": cast("Mapping[str, object]", run_contract["execution_policy"])[
                "platform"
            ],
            "evaluator_host": cast("Mapping[str, object]", run_contract["execution_policy"])[
                "evaluator_host"
            ],
            "limits_per_row": limits,
            "limits_campaign": cast("Mapping[str, object]", run_contract["budgets"])["campaign"],
        },
        "results": (
            result_summary
            if claim_ready
            else {
                "available": False,
                "withheld": True,
                "reasons": withheld_reasons,
            }
        ),
        "diagnostics": {
            "unverified_paired_results": (
                result_summary
                if paired_results_available
                else {
                    "available": False,
                    "withheld": True,
                    "reasons": paired_results_withheld_reasons,
                }
            ),
            "not_for_comparison_claims": not claim_ready,
        },
        "status_counts": status_counts,
        "elapsed_seconds": elapsed,
        "cost_usd": model_campaign.get("cost_usd"),
    }


def write_report(
    campaign_dir: Path,
    output_dir: Path,
    *,
    generated_at: str | None = None,
) -> tuple[Path, Path]:
    """Exclusively create ``report.json`` and its non-self-referential manifest."""
    report = aggregate_campaign(campaign_dir, generated_at=generated_at)
    requested = Path(output_dir).expanduser()
    parent = requested.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / requested.name
    try:
        destination.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise ReportAlreadyExistsError(
            f"refusing to replace report directory: {destination}"
        ) from exc
    report_path = destination / REPORT_FILE
    report_bytes = canonical_json_bytes(report)
    _write_exclusive(report_path, report_bytes)
    digest = hashlib.sha256(report_bytes).hexdigest()
    manifest_path = destination / REPORT_MANIFEST_FILE
    _write_exclusive(manifest_path, f"{digest}  {REPORT_FILE}\n".encode("ascii"))
    return report_path, manifest_path


def canonical_json_bytes(value: object) -> bytes:
    """Encode evidence deterministically without accepting NaN or infinity."""
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise PairedXbenReportError("report is not canonical JSON") from exc
    return (encoded + "\n").encode("ascii")


def exact_two_sided_mcnemar_p_value(ravage_only: int, strix_only: int) -> float:
    """Return the exact two-sided sign/McNemar p-value for discordant pairs."""
    if (
        isinstance(ravage_only, bool)
        or isinstance(strix_only, bool)
        or not isinstance(ravage_only, int)
        or not isinstance(strix_only, int)
        or ravage_only < 0
        or strix_only < 0
    ):
        raise ValueError("discordant counts must be non-negative integers")
    discordant = ravage_only + strix_only
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(ravage_only, strix_only) + 1))
    return float(min(1.0, 2.0 * tail / (2**discordant)))


def _validated_schedule(selection: Mapping[str, object]) -> list[Mapping[str, object]]:
    raw = selection.get("schedule")
    selected = selection.get("selected_case_ids")
    if not isinstance(raw, list) or len(raw) != EXPECTED_ROWS:
        raise EvidenceIntegrityError("selection must contain exactly 40 scheduled rows")
    if (
        not isinstance(selected, list)
        or len(selected) != EXPECTED_CASES
        or any(not isinstance(case_id, str) for case_id in selected)
        or len(set(selected)) != EXPECTED_CASES
    ):
        raise EvidenceIntegrityError("selection must contain exactly 20 distinct case IDs")
    selected_ids = cast("list[str]", selected)
    rows: list[Mapping[str, object]] = []
    slots: set[str] = set()
    pair_members: dict[int, dict[str, str]] = {}
    for position, candidate in enumerate(raw, start=1):
        if not isinstance(candidate, Mapping):
            raise EvidenceIntegrityError("selection schedule contains a non-object row")
        slot_id = candidate.get("slot_id")
        match = _SLOT_RE.fullmatch(slot_id) if isinstance(slot_id, str) else None
        if match is None or int(match.group(1)) != position or candidate.get("slot") != position:
            raise EvidenceIntegrityError("selection primary slots are not exactly 001 through 040")
        case_id = candidate.get("case_id")
        system = candidate.get("system")
        pair_index = candidate.get("pair_index")
        within_pair = candidate.get("position_within_pair")
        if (
            case_id not in selected_ids
            or system not in EXPECTED_SYSTEMS
            or not isinstance(pair_index, int)
            or isinstance(pair_index, bool)
            or not 1 <= pair_index <= EXPECTED_CASES
            or within_pair not in (1, 2)
            or candidate.get("purpose") != "primary"
            or candidate.get("score_eligible") is not True
        ):
            raise EvidenceIntegrityError(f"scheduled row {slot_id} is invalid")
        normalized_slot_id = cast("str", slot_id)
        if normalized_slot_id in slots:
            raise EvidenceIntegrityError(f"duplicate scheduled slot: {normalized_slot_id}")
        slots.add(normalized_slot_id)
        members = pair_members.setdefault(pair_index, {})
        if system in members:
            raise EvidenceIntegrityError(f"pair {pair_index} repeats system {system}")
        members[cast("str", system)] = cast("str", case_id)
        rows.append(candidate)
    if set(pair_members) != set(range(1, EXPECTED_CASES + 1)):
        raise EvidenceIntegrityError("selection does not contain exactly 20 pairs")
    paired_cases: set[str] = set()
    for pair_index, members in pair_members.items():
        if set(members) != set(EXPECTED_SYSTEMS) or len(set(members.values())) != 1:
            raise EvidenceIntegrityError(f"pair {pair_index} does not compare the same case")
        paired_cases.update(members.values())
    if paired_cases != set(selected_ids):
        raise EvidenceIntegrityError("scheduled pairs differ from selected cases")
    return rows


def _validate_attempt(
    attempt: Mapping[str, object],
    *,
    scheduled: Mapping[str, object],
    campaign_id: str,
    commitment_digest: str,
    selection_digest: str,
) -> None:
    expected = {
        "campaign_id": campaign_id,
        "commitment_digest": commitment_digest,
        "selection_digest": selection_digest,
        "attempt_id": scheduled["slot_id"],
        "purpose": "primary",
        "score_eligible": True,
        "primary_slot_id": scheduled["slot_id"],
        "case_id": scheduled["case_id"],
        "system": scheduled["system"],
        "pair_index": scheduled["pair_index"],
        "position_within_pair": scheduled["position_within_pair"],
        "parent_primary_slot_id": None,
        "artifact_directory": "artifacts",
    }
    for key, value in expected.items():
        if attempt.get(key) != value:
            raise EvidenceIntegrityError(f"attempt {scheduled['slot_id']} has mismatched {key}")


def _validate_row_result(
    result: Mapping[str, object],
    *,
    scheduled: Mapping[str, object],
    campaign_id: str,
    commitment_digest: str,
    selection_digest: str,
) -> None:
    slot_id = cast("str", scheduled["slot_id"])
    expected_result_fields = {
        "schema_version",
        "created_at",
        "completed_at",
        "elapsed_seconds",
        "status",
        "valid_for_comparison",
        "valid_for_paired_local_comparison",
        "official_attestation_eligible",
        "case",
        "agent",
        "schedule_binding",
        "isolation",
        "limits",
        "policy",
        "target",
        "execution",
        "score",
    }
    if set(result) != expected_result_fields or result.get("schema_version") != ROW_RESULT_SCHEMA:
        raise EvidenceIntegrityError(f"row {slot_id} has an unsupported result schema")
    binding = result.get("schedule_binding")
    if not isinstance(binding, Mapping):
        raise EvidenceIntegrityError(f"row {slot_id} lacks required campaign/slot schedule_binding")
    expected_binding = {
        "campaign_id": campaign_id,
        "commitment_digest": commitment_digest,
        "selection_digest": selection_digest,
        "primary_slot_id": slot_id,
    }
    if dict(binding) != expected_binding:
        raise EvidenceIntegrityError(f"row {slot_id} schedule_binding does not match its slot")
    case = result.get("case")
    agent = result.get("agent")
    if (
        not isinstance(case, Mapping)
        or set(case) != {"benchmark_id", "description_sha256"}
        or case.get("benchmark_id") != scheduled["case_id"]
        or (
            case.get("description_sha256") is not None
            and (
                not isinstance(case.get("description_sha256"), str)
                or _HEX_DIGEST_RE.fullmatch(cast("str", case["description_sha256"])) is None
            )
        )
    ):
        raise EvidenceIntegrityError(f"row {slot_id} benchmark ID differs from its schedule")
    if (
        not isinstance(agent, Mapping)
        or set(agent)
        != {
            "name",
            "system_id",
            "provider",
            "model",
            "reasoning_effort",
            "adapter_version",
            "command_sha256",
            "environment_names",
        }
        or agent.get("system_id") != scheduled["system"]
        or not isinstance(agent.get("command_sha256"), str)
        or _HEX_DIGEST_RE.fullmatch(cast("str", agent["command_sha256"])) is None
        or agent.get("environment_names")
        != [
            "RAVAGE_COMPARISON_GATEWAY_BASE_URL",
            "RAVAGE_COMPARISON_GATEWAY_TOKEN",
            OUTER_PROCESS_GROUP_ENV,
        ]
    ):
        raise EvidenceIntegrityError(f"row {slot_id} system ID differs from its schedule")
    status = result.get("status")
    if status not in TERMINAL_STATUSES:
        raise IncompleteCampaignError(f"row {slot_id} is not in a recognized terminal state")
    valid_for_comparison = result.get("valid_for_comparison")
    valid_for_local = result.get("valid_for_paired_local_comparison")
    official_eligible = result.get("official_attestation_eligible")
    if (
        not isinstance(valid_for_comparison, bool)
        or not isinstance(valid_for_local, bool)
        or not isinstance(official_eligible, bool)
        or (valid_for_comparison and valid_for_local)
        or (valid_for_comparison and not official_eligible)
        or (valid_for_local and official_eligible)
    ):
        raise EvidenceIntegrityError(f"row {slot_id} comparison validity fields conflict")
    score = result.get("score")
    if not isinstance(score, Mapping) or not isinstance(score.get("solved"), bool):
        raise EvidenceIntegrityError(f"row {slot_id} has no boolean exact score")
    if score.get("mode") != "committed_flag_candidate_sha256":
        raise EvidenceIntegrityError(f"row {slot_id} was not exact-scored")
    max_artifact_bytes = _nonnegative_int(
        score.get("max_artifact_bytes"), f"row {slot_id} maximum artifact bytes"
    )
    if max_artifact_bytes == 0 or max_artifact_bytes > _MAX_ROW_FILE_BYTES:
        raise EvidenceIntegrityError(f"row {slot_id} maximum artifact bytes is invalid")
    exact_match = score.get("exact_match")
    if not isinstance(exact_match, bool):
        raise EvidenceIntegrityError(f"row {slot_id} has no boolean exact_match")
    if set(score) != {
        "mode",
        "max_artifact_bytes",
        "expected_flag_sha256",
        "exact_match",
        "solved",
        "artifact",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} exact score fields are invalid")
    expected_flag_sha256 = score.get("expected_flag_sha256")
    if (
        not isinstance(expected_flag_sha256, str)
        or _HEX_DIGEST_RE.fullmatch(expected_flag_sha256) is None
    ):
        raise EvidenceIntegrityError(f"row {slot_id} expected-flag commitment is invalid")
    artifact = score.get("artifact")
    if not isinstance(artifact, Mapping) or not isinstance(artifact.get("exact_match"), bool):
        raise EvidenceIntegrityError(f"row {slot_id} has no artifact score evidence")
    if artifact["exact_match"] is not exact_match:
        raise EvidenceIntegrityError(f"row {slot_id} artifact and row exact_match disagree")
    artifact_status = artifact.get("status")
    if artifact_status not in {
        "scored",
        "missing",
        "invalid_symlink",
        "invalid_escape",
        "invalid_not_file",
        "invalid_too_large",
        "invalid_changed_or_unreadable",
        "invalid_too_many_candidates",
        "not_scored",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} artifact status is invalid")
    _nonempty(artifact.get("path"), f"row {slot_id} artifact path")
    if exact_match and artifact.get("status") != "scored":
        raise EvidenceIntegrityError(f"row {slot_id} exact match lacks a scored artifact")
    if artifact.get("status") == "scored":
        artifact_digest = artifact.get("sha256")
        if (
            not isinstance(artifact_digest, str)
            or _HEX_DIGEST_RE.fullmatch(artifact_digest) is None
        ):
            raise EvidenceIntegrityError(f"row {slot_id} scored artifact digest is invalid")
        _nonnegative_int(artifact.get("size_bytes"), f"row {slot_id} artifact size")
    execution = result.get("execution")
    clean_exit = bool(
        isinstance(execution, Mapping)
        and execution.get("status") == "completed"
        and execution.get("returncode") == 0
    )
    solved = score["solved"]
    if solved is not (exact_match and clean_exit and (valid_for_comparison or valid_for_local)):
        raise EvidenceIntegrityError(f"row {slot_id} solved value is inconsistent")
    if (status == "solved") is not solved:
        raise EvidenceIntegrityError(f"row {slot_id} status and exact score disagree")
    if status == "infrastructure_error" and (valid_for_comparison or valid_for_local):
        raise EvidenceIntegrityError(f"row {slot_id} infrastructure status is inconsistent")
    isolation = result.get("isolation")
    if not isinstance(isolation, Mapping):
        raise EvidenceIntegrityError(f"row {slot_id} lacks comparison isolation evidence")
    budget_enforcement = isolation.get("budget_enforcement")
    if (
        set(isolation)
        != {
            "kind",
            "filesystem_isolated",
            "target_network_only",
            "inherits_parent_environment",
            "black_box_safe",
            "budget_enforcement",
            "comparison_safe",
        }
        or not isinstance(isolation.get("kind"), str)
        or not cast("str", isolation["kind"]).strip()
        or not isinstance(budget_enforcement, Mapping)
        or set(budget_enforcement)
        != {"wall_timeout", "model_requests", "target_requests", "cost", "all_required"}
    ):
        raise EvidenceIntegrityError(f"row {slot_id} comparison isolation is malformed")
    filesystem_isolated = isolation.get("filesystem_isolated")
    target_network_only = isolation.get("target_network_only")
    inherits_parent = isolation.get("inherits_parent_environment")
    if any(
        not isinstance(value, bool)
        for value in (
            filesystem_isolated,
            target_network_only,
            inherits_parent,
            isolation.get("black_box_safe"),
            isolation.get("comparison_safe"),
            *budget_enforcement.values(),
        )
    ):
        raise EvidenceIntegrityError(f"row {slot_id} isolation verdicts are not booleans")
    black_box_safe = bool(filesystem_isolated and target_network_only and not inherits_parent)
    budget_safe = all(
        budget_enforcement.get(name) is True
        for name in ("wall_timeout", "model_requests", "target_requests", "cost")
    )
    if (
        isolation.get("black_box_safe") is not black_box_safe
        or budget_enforcement.get("all_required") is not budget_safe
        or isolation.get("comparison_safe") is not (black_box_safe and budget_safe)
    ):
        raise EvidenceIntegrityError(f"row {slot_id} isolation verdicts are inconsistent")
    policy = result.get("policy")
    if not isinstance(policy, Mapping) or any(
        policy.get(key) != value
        for key, value in {
            "attempt": 1,
            "retry_allowed": False,
            "replacement_allowed": False,
            "fresh_target_per_row": True,
            "pair_scoped_flag": True,
        }.items()
    ):
        raise EvidenceIntegrityError(f"row {slot_id} violates the one-shot policy")
    _finite_nonnegative(result.get("elapsed_seconds"), f"row {slot_id} elapsed_seconds")
    _evidence_timestamp(result.get("created_at"), f"row {slot_id} creation")
    _evidence_timestamp(result.get("completed_at"), f"row {slot_id} completion")


def _verify_declared_native_artifact(
    result: Mapping[str, object],
    *,
    row_root: Path,
    slot_id: str,
) -> None:
    """Recompute the exact score from retained bytes instead of trusting JSON."""

    score = cast("Mapping[str, object]", result["score"])
    artifact = cast("Mapping[str, object]", score["artifact"])
    expected_flag_sha256 = cast("str", score["expected_flag_sha256"])
    max_artifact_bytes = _nonnegative_int(
        score.get("max_artifact_bytes"), f"row {slot_id} maximum artifact bytes"
    )
    flag_commitment = _load_json(row_root / FLAG_COMMITMENT_FILE, f"row {slot_id} flag commitment")
    target = cast("Mapping[str, object]", result["target"])
    schedule_binding = cast("Mapping[str, object]", result["schedule_binding"])
    flag_committed_at = flag_commitment.get("created_at")
    if (
        set(flag_commitment)
        != {
            "schema_version",
            "created_at",
            "schedule_binding",
            "instance_id",
            "algorithm",
            "expected_flag_sha256",
            "scope",
        }
        or flag_commitment.get("schema_version") != FLAG_COMMITMENT_SCHEMA
        or flag_commitment.get("algorithm") != "sha256-utf8"
        or flag_commitment.get("scope") != "pair"
        or flag_commitment.get("schedule_binding") != dict(schedule_binding)
        or flag_commitment.get("instance_id") != target.get("instance_id")
        or flag_commitment.get("expected_flag_sha256") != expected_flag_sha256
        or not isinstance(flag_committed_at, str)
    ):
        raise EvidenceIntegrityError(f"row {slot_id} flag commitment does not match its result")
    _timestamp(flag_committed_at)
    relative = _artifact_relative_path(artifact.get("path"), slot_id=slot_id)
    native_output = row_root / "native-output"
    if native_output.is_symlink() or not native_output.is_dir():
        raise EvidenceIntegrityError(f"row {slot_id} native-output is missing or unsafe")
    native_root = native_output.resolve()
    candidate = native_output / relative
    status = cast("str", artifact["status"])

    if status in {"missing", "not_scored"}:
        if candidate.is_symlink() or candidate.exists():
            raise EvidenceIntegrityError(
                f"row {slot_id} claims a missing artifact that is actually present"
            )
        if artifact.get("sha256") is not None or artifact.get("size_bytes") is not None:
            raise EvidenceIntegrityError(
                f"row {slot_id} missing artifact has invented byte metadata"
            )
        return

    if status in {"invalid_symlink", "invalid_escape"}:
        # The enclosing row manifest already rejects every symlink. Retaining
        # one of these statuses without the unsafe object is not reproducible.
        raise EvidenceIntegrityError(
            f"row {slot_id} unsafe artifact status cannot be independently reproduced"
        )

    if candidate.is_symlink():
        raise EvidenceIntegrityError(f"row {slot_id} declared artifact is a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise EvidenceIntegrityError(f"row {slot_id} declared artifact is missing") from exc
    try:
        resolved.relative_to(native_root)
    except ValueError as exc:
        raise EvidenceIntegrityError(
            f"row {slot_id} declared artifact escapes native-output"
        ) from exc

    if status == "invalid_not_file":
        if resolved.is_file():
            raise EvidenceIntegrityError(f"row {slot_id} claims a regular artifact is not a file")
        if artifact.get("sha256") is not None or artifact.get("size_bytes") is not None:
            raise EvidenceIntegrityError(
                f"row {slot_id} non-file artifact has invented byte metadata"
            )
        return
    if not resolved.is_file():
        raise EvidenceIntegrityError(f"row {slot_id} declared artifact is not a regular file")

    size = resolved.stat().st_size
    if size > _MAX_ROW_FILE_BYTES:
        raise EvidenceIntegrityError(f"row {slot_id} declared artifact exceeds the size limit")
    recorded_size = _nonnegative_int(artifact.get("size_bytes"), f"row {slot_id} artifact size")
    if status == "invalid_changed_or_unreadable":
        # The size was sampled before the failed bounded read and may differ
        # from the stable bytes retained by the later row manifest.
        if artifact.get("sha256") is not None or artifact.get("exact_match") is not False:
            raise EvidenceIntegrityError(
                f"row {slot_id} changed artifact has invented score metadata"
            )
        return
    if recorded_size != size:
        raise EvidenceIntegrityError(f"row {slot_id} artifact size does not match retained bytes")
    if status == "invalid_too_large":
        if size <= max_artifact_bytes or artifact.get("sha256") is not None:
            raise EvidenceIntegrityError(
                f"row {slot_id} oversized artifact status does not reproduce"
            )
        return
    if status == "invalid_too_many_candidates":
        if size > max_artifact_bytes:
            raise EvidenceIntegrityError(
                f"row {slot_id} excessive-candidate artifact exceeds its frozen limit"
            )
        content = resolved.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        expected_count = _external_module.DEFAULT_MAX_FLAG_CANDIDATES + 1
        candidates: set[str] = set()
        for match in _PRODUCER_FLAG_CANDIDATE_BYTES_RE.finditer(content):
            candidates.add(hashlib.sha256(match.group(0)).hexdigest())
            if len(candidates) >= expected_count:
                break
        if (
            len(candidates) != expected_count
            or artifact.get("candidate_count") != expected_count
            or artifact.get("sha256") != digest
            or artifact.get("exact_match") is not False
            or "candidate_sha256" in artifact
        ):
            raise EvidenceIntegrityError(
                f"row {slot_id} excessive-candidate status does not reproduce"
            )
        return
    if status != "scored":
        raise EvidenceIntegrityError(f"row {slot_id} artifact status is not reproducible")
    if size > max_artifact_bytes:
        raise EvidenceIntegrityError(f"row {slot_id} scored artifact exceeds its frozen limit")

    content = resolved.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if artifact.get("sha256") != digest:
        raise EvidenceIntegrityError(f"row {slot_id} artifact digest does not match retained bytes")
    exact_match = any(
        hashlib.sha256(candidate.group(0)).hexdigest() == expected_flag_sha256
        for candidate in _EXPECTED_FLAG_BYTES_RE.finditer(content)
    )
    if artifact.get("exact_match") is not exact_match:
        raise EvidenceIntegrityError(f"row {slot_id} artifact flag match does not reproduce")
    if score.get("exact_match") is not exact_match:
        raise EvidenceIntegrityError(f"row {slot_id} row score does not reproduce from artifact")


def _artifact_relative_path(value: object, *, slot_id: str) -> Path:
    if not isinstance(value, str) or value != value.strip():
        raise EvidenceIntegrityError(f"row {slot_id} artifact path is invalid")
    relative = Path(value)
    if (
        not value
        or relative.is_absolute()
        or relative == Path(".")
        or ".." in relative.parts
        or relative.parts[0]
        in {
            "row-result.json",
            "stdout.log",
            "stderr.log",
            "target-build.json",
            "target-teardown.json",
            FLAG_COMMITMENT_FILE,
            "artifacts.sha256",
        }
    ):
        raise EvidenceIntegrityError(f"row {slot_id} artifact path is unsafe")
    return relative


def _verify_row_lifecycle(
    result: Mapping[str, object],
    *,
    row_root: Path,
    slot_id: str,
) -> None:
    """Recompute row status from retained build, process, and teardown evidence."""

    target = result.get("target")
    if not isinstance(target, Mapping) or set(target) != {
        "instance_id",
        "target_url",
        "build_provenance_path",
        "teardown_provenance_path",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} target evidence is incomplete")
    instance_id = _nonempty(target.get("instance_id"), f"row {slot_id} target instance ID")
    if (
        target.get("build_provenance_path") != "target-build.json"
        or target.get("teardown_provenance_path") != "target-teardown.json"
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target receipt paths are invalid")

    build = _load_json(row_root / "target-build.json", f"row {slot_id} target build receipt")
    teardown = _load_json(
        row_root / "target-teardown.json", f"row {slot_id} target teardown receipt"
    )
    _validate_target_receipt(build, instance_id=instance_id, label=f"row {slot_id} build")
    _validate_target_receipt(
        teardown,
        instance_id=instance_id,
        label=f"row {slot_id} teardown",
        allow_not_started=True,
    )
    target_ready = build["status"] == "succeeded"
    teardown_complete = teardown["status"] == "succeeded"
    target_url = target.get("target_url")
    if target_ready is not (isinstance(target_url, str) and bool(target_url.strip())):
        raise EvidenceIntegrityError(f"row {slot_id} target URL and build receipt disagree")
    if target_ready:
        parsed_target = urlsplit(cast("str", target_url))
        if (
            parsed_target.scheme not in {"http", "https"}
            or not parsed_target.hostname
            or _EXPECTED_FLAG_RE.search(cast("str", target_url)) is not None
        ):
            raise EvidenceIntegrityError(f"row {slot_id} target URL is unsafe")

    execution = result.get("execution")
    if not isinstance(execution, Mapping) or set(execution) != {
        "status",
        "returncode",
        "timeout_seconds",
        "started_at",
        "completed_at",
        "error",
        "stdout_path",
        "stderr_path",
        "stdout_capture",
        "stderr_capture",
        "receipts",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} execution evidence is incomplete")
    execution_status = execution.get("status")
    if execution_status not in {"completed", "timed_out", "errored", "not_started"}:
        raise EvidenceIntegrityError(f"row {slot_id} execution status is invalid")
    returncode = execution.get("returncode")
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise EvidenceIntegrityError(f"row {slot_id} execution returncode is invalid")
    limits = cast("Mapping[str, object]", result["limits"])
    if execution.get("timeout_seconds") != limits.get("wall_seconds"):
        raise EvidenceIntegrityError(f"row {slot_id} execution timeout differs from its limit")
    if execution.get("stdout_path") != "stdout.log" or execution.get("stderr_path") != "stderr.log":
        raise EvidenceIntegrityError(f"row {slot_id} execution log paths are invalid")
    _validate_log_capture(
        row_root / "stdout.log",
        execution.get("stdout_capture"),
        label=f"row {slot_id} stdout",
    )
    _validate_log_capture(
        row_root / "stderr.log",
        execution.get("stderr_capture"),
        label=f"row {slot_id} stderr",
    )

    execution_started: datetime | None = None
    execution_completed: datetime | None = None
    if execution_status == "not_started":
        if execution.get("started_at") is not None or execution.get("completed_at") is not None:
            raise EvidenceIntegrityError(f"row {slot_id} unstarted execution has timestamps")
    else:
        execution_started = _evidence_timestamp(execution.get("started_at"), f"row {slot_id} start")
        execution_completed = _evidence_timestamp(
            execution.get("completed_at"), f"row {slot_id} execution completion"
        )
        if execution_completed < execution_started:
            raise EvidenceIntegrityError(f"row {slot_id} execution completed before it started")
    receipts = execution.get("receipts")
    if not isinstance(receipts, Mapping):
        raise EvidenceIntegrityError(f"row {slot_id} execution receipts are missing")
    receipt_valid = receipts.get("valid") is True
    process_official = receipts.get("official_attestation_eligible") is True
    receipt_class = receipts.get("evidence_class")
    pair_scoped_flag = (
        cast("Mapping[str, object]", result["policy"]).get("pair_scoped_flag") is True
    )
    official_eligible = bool(
        process_official
        and receipt_valid
        and target_ready
        and teardown_complete
        and pair_scoped_flag
    )
    valid_for_comparison = bool(
        target_ready
        and teardown_complete
        and receipt_valid
        and official_eligible
        and pair_scoped_flag
    )
    valid_for_local = bool(
        target_ready
        and teardown_complete
        and receipt_valid
        and receipt_class == "paired_local"
        and pair_scoped_flag
    )
    if (
        result.get("valid_for_comparison") is not valid_for_comparison
        or result.get("valid_for_paired_local_comparison") is not valid_for_local
        or result.get("official_attestation_eligible") is not official_eligible
    ):
        raise EvidenceIntegrityError(f"row {slot_id} comparison validity does not reproduce")
    score = cast("Mapping[str, object]", result["score"])
    artifact = cast("Mapping[str, object]", score["artifact"])
    solved = score.get("solved") is True
    clean_exit = execution_status == "completed" and returncode == 0
    if solved is not bool(
        score.get("exact_match") is True
        and clean_exit
        and (valid_for_comparison or valid_for_local)
    ):
        raise EvidenceIntegrityError(f"row {slot_id} solved value does not reproduce")
    artifact_valid = artifact.get("status") == "scored"
    if not target_ready or not teardown_complete:
        expected_status = "infrastructure_error"
    elif solved:
        expected_status = "solved"
    elif execution_status == "timed_out":
        expected_status = "timed_out"
    elif execution_status == "errored":
        expected_status = "errored"
    elif not artifact_valid:
        expected_status = "failed"
    else:
        expected_status = "failed"
    if result.get("status") != expected_status:
        raise EvidenceIntegrityError(f"row {slot_id} terminal status does not reproduce")

    created = _evidence_timestamp(result.get("created_at"), f"row {slot_id} creation")
    completed = _evidence_timestamp(result.get("completed_at"), f"row {slot_id} completion")
    if completed < created:
        raise EvidenceIntegrityError(f"row {slot_id} completed before it was created")
    if execution_started is not None and (
        execution_started < created
        or execution_completed is None
        or execution_completed > completed
    ):
        raise EvidenceIntegrityError(f"row {slot_id} execution timestamps escape row lifetime")
    commitment = _load_json(row_root / FLAG_COMMITMENT_FILE, f"row {slot_id} flag commitment")
    committed = _evidence_timestamp(
        commitment.get("created_at"), f"row {slot_id} flag commitment time"
    )
    if committed > created:
        raise EvidenceIntegrityError(f"row {slot_id} flag was committed after row execution began")


def _validate_target_receipt(
    receipt: Mapping[str, object],
    *,
    instance_id: str,
    label: str,
    allow_not_started: bool = False,
) -> None:
    allowed_statuses = {"succeeded", "errored"}
    if allow_not_started:
        allowed_statuses.add("not_started")
    status = receipt.get("status")
    if status not in allowed_statuses or receipt.get("instance_id") != instance_id:
        raise EvidenceIntegrityError(f"{label} receipt is invalid")
    expected_keys = {"status", "instance_id"}
    if status == "succeeded":
        expected_keys.add("provenance")
        if not isinstance(receipt.get("provenance"), Mapping):
            raise EvidenceIntegrityError(f"{label} provenance is missing")
    elif status == "errored":
        expected_keys.add("error")
        _nonempty(receipt.get("error"), f"{label} error")
    if set(receipt) != expected_keys:
        raise EvidenceIntegrityError(f"{label} receipt fields are invalid")


def _validate_log_capture(path: Path, value: object, *, label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "raw_sha256",
        "raw_size_bytes",
        "retained_size_bytes",
        "redacted",
        "truncated",
        "max_retained_bytes",
    }:
        raise EvidenceIntegrityError(f"{label} capture record is invalid")
    raw_digest = value.get("raw_sha256")
    if not isinstance(raw_digest, str) or _HEX_DIGEST_RE.fullmatch(raw_digest) is None:
        raise EvidenceIntegrityError(f"{label} raw digest is invalid")
    raw_size = _nonnegative_int(value.get("raw_size_bytes"), f"{label} raw size")
    retained_size = _nonnegative_int(value.get("retained_size_bytes"), f"{label} retained size")
    maximum = _nonnegative_int(value.get("max_retained_bytes"), f"{label} maximum size")
    if (
        maximum == 0
        or not isinstance(value.get("redacted"), bool)
        or not isinstance(value.get("truncated"), bool)
    ):
        raise EvidenceIntegrityError(f"{label} capture policy is invalid")
    content = _read_regular(path, label, maximum)
    if retained_size != len(content):
        raise EvidenceIntegrityError(f"{label} retained size does not match its file")
    if value["truncated"] is True:
        if retained_size != maximum or b"TRUNCATED BY EVALUATOR" not in content:
            raise EvidenceIntegrityError(f"{label} truncation record does not reproduce")
    elif value["redacted"] is False:
        if raw_size != retained_size or hashlib.sha256(content).hexdigest() != raw_digest:
            raise EvidenceIntegrityError(f"{label} raw capture digest does not reproduce")


def _validate_schedule_execution_order(rows: list[dict[str, object]]) -> None:
    previous_completed: datetime | None = None
    for row in rows:
        binding = cast("Mapping[str, object]", row["schedule_binding"])
        slot_id = cast("str", binding["primary_slot_id"])
        created = _evidence_timestamp(row.get("created_at"), f"row {slot_id} creation")
        completed = _evidence_timestamp(row.get("completed_at"), f"row {slot_id} completion")
        if previous_completed is not None and created < previous_completed:
            raise EvidenceIntegrityError("primary rows were not executed in committed order")
        previous_completed = completed


def _evidence_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceIntegrityError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EvidenceIntegrityError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceIntegrityError(f"{label} must include a UTC offset")
    return parsed


def _common_execution_contract(
    rows: list[dict[str, object]],
    *,
    run_contract: Mapping[str, object],
) -> tuple[str, str, str, Mapping[str, object]]:
    gateway_contract = run_contract["model_gateway"]
    budgets = run_contract["budgets"]
    if not isinstance(gateway_contract, Mapping) or not isinstance(budgets, Mapping):
        raise EvidenceIntegrityError("frozen run contract gateway or budgets are invalid")
    model_contract = gateway_contract.get("policy")
    row_budget = budgets.get("per_row")
    if not isinstance(model_contract, Mapping) or not isinstance(row_budget, Mapping):
        raise EvidenceIntegrityError("frozen model policy or per-row budget is invalid")
    expected_provider = _nonempty(gateway_contract.get("provider"), "contract provider")
    expected_agent_provider = _nonempty(
        gateway_contract.get("agent_provider"), "contract agent provider"
    )
    expected_model = _nonempty(model_contract.get("model"), "contract model")
    expected_reasoning = _nonempty(
        model_contract.get("reasoning_effort"), "contract reasoning effort"
    )
    expected_limits: dict[str, object] = {
        "wall_seconds": row_budget.get("wall_seconds"),
        "max_model_requests": row_budget.get("max_model_requests"),
        "max_target_requests": row_budget.get("max_target_requests"),
        "max_cost_usd": row_budget.get("max_cost_usd"),
    }
    for row in rows:
        agent = cast("Mapping[str, object]", row["agent"])
        provider = _nonempty(agent.get("provider"), "row provider")
        model = _nonempty(agent.get("model"), "row model")
        reasoning = _nonempty(agent.get("reasoning_effort"), "row reasoning effort")
        limits = row.get("limits")
        if not isinstance(limits, Mapping):
            raise EvidenceIntegrityError("row lacks enforced execution limits")
        if (
            provider != expected_agent_provider
            or model != expected_model
            or reasoning != expected_reasoning
            or limits.get("wall_seconds") != expected_limits["wall_seconds"]
            or limits.get("max_model_requests") != expected_limits["max_model_requests"]
            or limits.get("max_target_requests") != expected_limits["max_target_requests"]
            or _money(limits.get("max_cost_usd"), "row cost cap") != expected_limits["max_cost_usd"]
            or agent.get("adapter_version")
            != cast("Mapping[str, object]", run_contract["adapter"])["adapter_version"]
        ):
            raise EvidenceIntegrityError(
                "row provider, model, reasoning, or limits differ from frozen run contract"
            )
    return expected_provider, expected_model, expected_reasoning, expected_limits


def _frozen_run_contract(
    commitment: Mapping[str, object],
    *,
    campaign_id: str,
    commitment_digest: str,
) -> Mapping[str, object]:
    if commitment.get("campaign_id") != campaign_id:
        raise EvidenceIntegrityError("commitment campaign differs from selection")
    if commitment.get("document_digest") != commitment_digest:
        raise EvidenceIntegrityError("commitment digest differs from selection")
    contract = commitment.get("run_contract")
    if not isinstance(contract, Mapping):
        raise EvidenceIntegrityError("commitment has no frozen run contract")
    try:
        return validate_run_contract(contract)
    except PairedXbenProtocolError as exc:
        raise EvidenceIntegrityError(f"frozen run contract is invalid: {exc}") from exc


def _verify_independent_row_evidence(  # noqa: PLR0914
    result: Mapping[str, object],
    *,
    scheduled: Mapping[str, object],
    row_root: Path,
    campaign_root: Path,
    run_contract: Mapping[str, object],
) -> dict[str, object]:
    """Rebuild one row's trust decision from retained component receipts."""

    slot_id = cast("str", scheduled["slot_id"])
    record: dict[str, object] = {
        "slot_id": slot_id,
        "adapter_verified": False,
        "model_gateway_verified": False,
        "process_verified": False,
        "unstarted_process_verified": False,
        "target_verified": False,
        "official_attestation_eligible": False,
        "process_official_attestation_eligible": False,
        "model_receipt": None,
        "model_receipt_file_sha256": None,
        "prepared_target": None,
        "semantic_prompt_sha256": None,
        "description_bytes": None,
        "semantic_prompt_bytes": None,
        "adapter_target_url_sha256": None,
        "adapter_gateway_base_url_sha256": None,
        "adapter_gateway_token_sha256": None,
        "adapter_description_sha256": None,
    }

    adapter_path = row_root / ADAPTER_RESULT_FILE
    if adapter_path.exists() or adapter_path.is_symlink():
        _require_unique_file_location(
            row_root,
            expected=adapter_path,
            basename="adapter-result.json",
            label=f"row {slot_id} adapter result",
        )
        adapter = _load_json(adapter_path, f"row {slot_id} adapter result")
        adapter_complete = _validate_adapter_result(
            adapter,
            result=result,
            scheduled=scheduled,
            row_root=row_root,
            run_contract=run_contract,
        )
        record["adapter_verified"] = adapter_complete
        adapter_input = cast("Mapping[str, object]", adapter["input_contract"])
        record["semantic_prompt_sha256"] = adapter_input["semantic_prompt_sha256"]
        record["description_bytes"] = adapter_input["description_bytes"]
        record["semantic_prompt_bytes"] = adapter_input["semantic_prompt_bytes"]
        record["adapter_target_url_sha256"] = adapter["target_url_sha256"]
        record["adapter_gateway_base_url_sha256"] = adapter["gateway_base_url_sha256"]
        record["adapter_gateway_token_sha256"] = cast("Mapping[str, object]", adapter["gateway"])[
            "token_sha256"
        ]
        record["adapter_description_sha256"] = adapter_input["description_sha256"]

    execution = cast("Mapping[str, object]", result["execution"])
    declaration = _validated_execution_receipt_declaration(
        execution.get("receipts"),
        slot_id=slot_id,
    )
    gateway_contract = cast("Mapping[str, object]", run_contract["model_gateway"])
    budgets = cast("Mapping[str, object]", run_contract["budgets"])
    row_budget = cast("Mapping[str, object]", budgets["per_row"])
    model_path = row_root / MODEL_GATEWAY_RECEIPT_FILE
    model_receipt: dict[str, object] | None = None
    model_file_digest: str | None = None
    if model_path.exists() or model_path.is_symlink():
        _require_unique_file_location(
            row_root,
            expected=model_path,
            basename=MODEL_GATEWAY_RECEIPT_FILE,
            label=f"row {slot_id} model gateway receipt",
        )
        model_payload = _load_json(model_path, f"row {slot_id} model gateway receipt")
        model_file_digest = _prefixed_file_digest(model_path)
        try:
            model_receipt = validate_model_gateway_receipt(
                model_payload,
                expected_row_id=slot_id,
                expected_policy_sha256=cast("str", gateway_contract["policy_sha256"]),
                expected_max_requests=cast("int", row_budget["max_model_requests"]),
                expected_max_cost_usd=cast("str", row_budget["max_cost_usd"]),
            )
        except (ModelGatewayError, ValueError) as exc:
            raise EvidenceIntegrityError(
                f"row {slot_id} model gateway receipt is invalid: {exc}"
            ) from exc
        if model_receipt.get("policy") != gateway_contract.get("policy"):
            raise EvidenceIntegrityError(f"row {slot_id} model policy differs from commitment")
        if record.get("adapter_gateway_token_sha256") is not None and model_receipt.get(
            "row_token_sha256"
        ) != record.get("adapter_gateway_token_sha256"):
            raise EvidenceIntegrityError(
                f"row {slot_id} adapter gateway token differs from its model receipt"
            )
        _cross_bind_declared_receipt(
            declaration,
            prefix="model_gateway",
            expected_path=MODEL_GATEWAY_RECEIPT_FILE,
            file_digest=model_file_digest,
            document_digest=cast("str", model_receipt["document_sha256"]),
            slot_id=slot_id,
        )
        record["model_gateway_verified"] = model_receipt.get("valid") is True
        record["model_receipt"] = model_receipt
        record["model_receipt_file_sha256"] = model_file_digest
    elif declaration.get("model_gateway_receipt_path") is not None:
        raise EvidenceIntegrityError(f"row {slot_id} declares a missing model gateway receipt")

    process_path = row_root / PROCESS_RECEIPT_FILE
    profile_path = row_root / SANDBOX_PROFILE_FILE
    if process_path.exists() or process_path.is_symlink():
        _require_unique_file_location(
            row_root,
            expected=process_path,
            basename=PROCESS_RECEIPT_FILE,
            label=f"row {slot_id} process receipt",
        )
        if model_receipt is None or model_file_digest is None:
            raise EvidenceIntegrityError(f"row {slot_id} process receipt lacks its model receipt")
        process_payload = _load_json(process_path, f"row {slot_id} process receipt")
        process_file_digest = _prefixed_file_digest(process_path)
        process_document_digest = _prefixed_document_digest(
            process_payload,
            label=f"row {slot_id} process receipt",
        )
        _cross_bind_declared_receipt(
            declaration,
            prefix="process",
            expected_path=PROCESS_RECEIPT_FILE,
            file_digest=process_file_digest,
            document_digest=process_document_digest,
            slot_id=slot_id,
        )
        _require_unique_file_location(
            row_root,
            expected=profile_path,
            basename=SANDBOX_PROFILE_FILE,
            label=f"row {slot_id} sandbox profile",
        )
        profile = _read_regular(profile_path, f"row {slot_id} sandbox profile", _MAX_JSON_BYTES)
        profile_digest = "sha256:" + hashlib.sha256(profile).hexdigest()
        if (
            declaration.get("sandbox_profile_path") != SANDBOX_PROFILE_FILE
            or declaration.get("sandbox_profile_sha256") != profile_digest
        ):
            raise EvidenceIntegrityError(f"row {slot_id} sandbox profile binding is invalid")
        public_contract = declaration.get("public_validation_contract")
        if declaration.get("valid") is True:
            try:
                process_receipt = validate_comparison_process_receipt_public(
                    process_payload,
                    expected_row_id=slot_id,
                    public_contract=public_contract,
                    model_receipt_file_sha256=model_file_digest,
                    model_receipt_document_sha256=cast("str", model_receipt["document_sha256"]),
                    sandbox_profile=profile,
                    expected_output_directory=row_root / "native-output",
                    require_official_safety=False,
                )
            except (ComparisonProcessError, ValueError) as exc:
                raise EvidenceIntegrityError(
                    f"row {slot_id} process receipt is invalid: {exc}"
                ) from exc
            public = cast("Mapping[str, object]", public_contract)
            if public.get("model_gateway_policy_sha256") != gateway_contract.get(
                "policy_sha256"
            ) or public.get("limits") != _row_limits_json(row_budget):
                raise EvidenceIntegrityError(
                    f"row {slot_id} process receipt differs from the run contract"
                )
            _verify_process_host_contract(
                public,
                process_receipt=process_receipt,
                system=cast("str", scheduled["system"]),
                declared_evidence_class=declaration.get("evidence_class"),
                execution_policy=cast("Mapping[str, object]", run_contract["execution_policy"]),
                slot_id=slot_id,
            )
            public_command = cast("Mapping[str, object]", public["command"])
            agent = cast("Mapping[str, object]", result["agent"])
            if public_command.get("argv_sha256") != "sha256:" + cast(
                "str", agent["command_sha256"]
            ):
                raise EvidenceIntegrityError(
                    f"row {slot_id} process command differs from the adapter launch"
                )
            public_environment = cast("Mapping[str, object]", public["environment"])
            value_digests = public_environment.get("value_sha256")
            frozen_execution_policy = cast("Mapping[str, object]", run_contract["execution_policy"])
            expected_environment_names = {
                "RAVAGE_COMPARISON_GATEWAY_BASE_URL",
                "RAVAGE_COMPARISON_GATEWAY_TOKEN",
                OUTER_PROCESS_GROUP_ENV,
                "RAVAGE_XBEN_DESCRIPTION",
                "RAVAGE_XBEN_TARGET_URL",
            }
            if (
                not isinstance(value_digests, Mapping)
                or set(value_digests) != expected_environment_names
                or set(cast("list[object]", public_environment.get("names")))
                != expected_environment_names
                or value_digests.get("RAVAGE_COMPARISON_GATEWAY_TOKEN")
                != model_receipt.get("row_token_sha256")
                or value_digests.get("RAVAGE_XBEN_TARGET_URL")
                != record.get("adapter_target_url_sha256")
                or value_digests.get("RAVAGE_COMPARISON_GATEWAY_BASE_URL")
                != record.get("adapter_gateway_base_url_sha256")
                or value_digests.get("RAVAGE_XBEN_DESCRIPTION")
                != record.get("adapter_description_sha256")
                or value_digests.get(OUTER_PROCESS_GROUP_ENV)
                != _sha256_text(
                    cast("str", frozen_execution_policy["outer_process_group_environment"])
                )
            ):
                raise EvidenceIntegrityError(
                    f"row {slot_id} public process environment is not cross-bound"
                )
            process_execution = cast("Mapping[str, object]", process_receipt["execution"])
            if process_execution.get("returncode") != execution.get("returncode"):
                raise EvidenceIntegrityError(f"row {slot_id} process and row return codes differ")
            record["process_verified"] = _verify_process_row_lifecycle(
                process_execution,
                row_execution=execution,
                row_elapsed=result.get("elapsed_seconds"),
                slot_id=slot_id,
            )
            record["process_official_attestation_eligible"] = (
                process_receipt.get("official_attestation_eligible") is True
            )
        elif execution.get("status") == "not_started":
            try:
                unstarted = validate_unstarted_comparison_process_receipt(
                    process_payload,
                    expected_row_id=slot_id,
                    expected_limits=ExternalExecutionLimits(
                        wall_seconds=cast("int", row_budget["wall_seconds"]),
                        max_model_requests=cast("int", row_budget["max_model_requests"]),
                        max_target_requests=cast("int", row_budget["max_target_requests"]),
                        max_cost_usd=_money(row_budget["max_cost_usd"], "row cost cap"),
                    ),
                    expected_policy_sha256=cast("str", gateway_contract["policy_sha256"]),
                    expected_evidence_class=cast("str", declaration["evidence_class"]),
                    model_receipt_file_sha256=model_file_digest,
                    model_receipt_document_sha256=cast("str", model_receipt["document_sha256"]),
                    sandbox_profile=profile,
                )
            except (ComparisonProcessError, ValueError) as exc:
                raise EvidenceIntegrityError(
                    f"row {slot_id} unstarted process receipt is invalid: {exc}"
                ) from exc
            if (
                unstarted.get("valid") is not False
                or unstarted.get("official_attestation_eligible") is not False
            ):
                raise EvidenceIntegrityError(
                    f"row {slot_id} unstarted process receipt invents eligibility"
                )
            record["unstarted_process_verified"] = True
    elif declaration.get("process_receipt_path") is not None:
        raise EvidenceIntegrityError(f"row {slot_id} declares a missing process receipt")

    target = _verify_target_evidence(
        result,
        scheduled=scheduled,
        row_root=row_root,
        campaign_root=campaign_root,
        row_budget=row_budget,
        execution_policy=cast("Mapping[str, object]", run_contract["execution_policy"]),
        sources=cast("Mapping[str, object]", run_contract["sources"]),
        compatibility_catalog=cast("Mapping[str, object]", run_contract["compatibility_catalog"]),
        oci_images=cast("Mapping[str, object]", run_contract["oci_images"]),
        target_helper_image_ids=cast(
            "Mapping[str, object]", run_contract["target_helper_image_ids"]
        ),
    )
    record.update(target)
    policy = cast("Mapping[str, object]", result["policy"])
    composite_official = bool(
        record.get("process_official_attestation_eligible") is True
        and declaration.get("valid") is True
        and record.get("target_verified") is True
        and policy.get("pair_scoped_flag") is True
    )
    if result.get("official_attestation_eligible") is not composite_official:
        raise EvidenceIntegrityError(f"row {slot_id} official eligibility does not reproduce")
    record["official_attestation_eligible"] = composite_official
    return record


def _validated_execution_receipt_declaration(
    value: object,
    *,
    slot_id: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise EvidenceIntegrityError(f"row {slot_id} receipt declaration is missing")
    receipt = dict(value)
    compact_fields = {
        "valid",
        "official_attestation_eligible",
        "evidence_class",
        "error",
    }
    if set(receipt) == compact_fields:
        if (
            receipt.get("valid") is not False
            or receipt.get("official_attestation_eligible") is not False
            or receipt.get("evidence_class") is not None
            or not isinstance(receipt.get("error"), str)
        ):
            raise EvidenceIntegrityError(f"row {slot_id} compact receipt failure is invalid")
        for name in (
            "process_receipt_path",
            "process_receipt_document_sha256",
            "process_receipt_file_sha256",
            "model_gateway_receipt_path",
            "model_gateway_receipt_document_sha256",
            "model_gateway_receipt_file_sha256",
            "model_gateway_policy_sha256",
            "sandbox_profile_path",
            "sandbox_profile_sha256",
            "public_validation_contract",
        ):
            receipt[name] = None
        return receipt
    fields = {
        "valid",
        "official_attestation_eligible",
        "evidence_class",
        "process_receipt_path",
        "process_receipt_document_sha256",
        "process_receipt_file_sha256",
        "model_gateway_receipt_path",
        "model_gateway_receipt_document_sha256",
        "model_gateway_receipt_file_sha256",
        "model_gateway_policy_sha256",
        "sandbox_profile_path",
        "sandbox_profile_sha256",
        "public_validation_contract",
        "error",
    }
    if set(receipt) != fields:
        raise EvidenceIntegrityError(f"row {slot_id} receipt declaration fields are invalid")
    if not isinstance(receipt.get("valid"), bool) or not isinstance(
        receipt.get("official_attestation_eligible"), bool
    ):
        raise EvidenceIntegrityError(f"row {slot_id} receipt verdicts are invalid")
    evidence_class = receipt.get("evidence_class")
    if evidence_class not in {None, "strict_official", "paired_local"}:
        raise EvidenceIntegrityError(f"row {slot_id} receipt evidence class is invalid")
    if receipt.get("valid") is True:
        for name in (
            "process_receipt_document_sha256",
            "process_receipt_file_sha256",
            "model_gateway_receipt_document_sha256",
            "model_gateway_receipt_file_sha256",
            "model_gateway_policy_sha256",
            "sandbox_profile_sha256",
        ):
            _digest(receipt.get(name), f"row {slot_id} {name}")
        if not isinstance(receipt.get("public_validation_contract"), Mapping):
            raise EvidenceIntegrityError(f"row {slot_id} has no public process contract")
    return receipt


def _cross_bind_declared_receipt(
    declaration: Mapping[str, object],
    *,
    prefix: str,
    expected_path: str,
    file_digest: str,
    document_digest: str,
    slot_id: str,
) -> None:
    if (
        declaration.get(f"{prefix}_receipt_path") != expected_path
        or declaration.get(f"{prefix}_receipt_file_sha256") != file_digest
        or declaration.get(f"{prefix}_receipt_document_sha256") != document_digest
    ):
        raise EvidenceIntegrityError(f"row {slot_id} {prefix} receipt binding is invalid")


def _verify_process_row_lifecycle(
    process_execution: Mapping[str, object],
    *,
    row_execution: Mapping[str, object],
    row_elapsed: object,
    slot_id: str,
) -> bool:
    """Cross-bind the outer process lifetime and captures to the row receipt."""
    process_started = _evidence_timestamp(
        process_execution.get("started_at"), f"row {slot_id} process start"
    )
    process_completed = _evidence_timestamp(
        process_execution.get("completed_at"), f"row {slot_id} process completion"
    )
    row_started = _evidence_timestamp(
        row_execution.get("started_at"), f"row {slot_id} execution start"
    )
    row_completed = _evidence_timestamp(
        row_execution.get("completed_at"), f"row {slot_id} execution completion"
    )
    process_elapsed = _finite_nonnegative(
        process_execution.get("elapsed_seconds"), f"row {slot_id} process elapsed time"
    )
    total_row_elapsed = _finite_nonnegative(row_elapsed, f"row {slot_id} elapsed time")
    if (
        process_started < row_started
        or process_completed > row_completed
        or process_completed < process_started
        or process_elapsed > total_row_elapsed
        or process_execution.get("timed_out") is not (row_execution.get("status") == "timed_out")
    ):
        raise EvidenceIntegrityError(f"row {slot_id} process lifetime differs from its row")
    captures_complete = True
    for stream in ("stdout", "stderr"):
        process_capture = process_execution.get(stream)
        row_capture = row_execution.get(f"{stream}_capture")
        if not isinstance(process_capture, Mapping) or not isinstance(row_capture, Mapping):
            raise EvidenceIntegrityError(f"row {slot_id} process capture binding is missing")
        reproducible = bool(
            process_capture.get("complete") is True
            and process_capture.get("truncated") is False
            and row_capture.get("redacted") is False
            and row_capture.get("truncated") is False
            and isinstance(process_capture.get("raw_sha256"), str)
            and cast("str", process_capture["raw_sha256"]).removeprefix("sha256:")
            == row_capture.get("raw_sha256")
            and process_capture.get("raw_size_bytes") == row_capture.get("raw_size_bytes")
            and process_capture.get("retained_size_bytes") == row_capture.get("retained_size_bytes")
        )
        captures_complete = captures_complete and reproducible
    return captures_complete


def _verify_process_host_contract(
    public_contract: Mapping[str, object],
    *,
    process_receipt: Mapping[str, object],
    system: str,
    declared_evidence_class: object,
    execution_policy: Mapping[str, object],
    slot_id: str,
) -> None:
    """Cross-bind retained host containment to the pre-draw run contract."""

    evaluator_host = execution_policy.get("evaluator_host")
    if not isinstance(evaluator_host, Mapping):
        raise EvidenceIntegrityError(f"row {slot_id} lacks a frozen evaluator host policy")
    systems = evaluator_host.get("systems")
    if not isinstance(systems, Mapping) or not isinstance(systems.get(system), Mapping):
        raise EvidenceIntegrityError(f"row {slot_id} lacks its frozen evaluator system policy")
    system_policy = cast("Mapping[str, object]", systems[system])
    sandbox = public_contract.get("sandbox")
    if not isinstance(sandbox, Mapping):
        raise EvidenceIntegrityError(f"row {slot_id} public process sandbox is missing")
    docker_socket_path = sandbox.get("docker_socket_path")
    docker_socket_path_sha256 = (
        _sha256_text(docker_socket_path) if isinstance(docker_socket_path, str) else None
    )
    if (
        process_receipt.get("evidence_class") != declared_evidence_class
        or declared_evidence_class != system_policy.get("evidence_class")
        or sandbox.get("platform") != evaluator_host.get("platform")
        or sandbox.get("backend") != evaluator_host.get("containment_backend")
        or sandbox.get("executable_path") != evaluator_host.get("sandbox_executable_path")
        or sandbox.get("executable_sha256") != evaluator_host.get("sandbox_executable_sha256")
        or public_contract.get("sandbox_executable_sha256")
        != evaluator_host.get("sandbox_executable_sha256")
        or sandbox.get("runtime_read_roots_sha256")
        != system_policy.get("runtime_read_roots_sha256")
        or sandbox.get("runtime_read_root_count") != system_policy.get("runtime_read_root_count")
        or sandbox.get("docker_socket_access") is not system_policy.get("docker_socket_access")
        or docker_socket_path_sha256 != system_policy.get("docker_socket_path_sha256")
    ):
        raise EvidenceIntegrityError(
            f"row {slot_id} evaluator host containment differs from commitment"
        )


def _validate_adapter_result(
    adapter: Mapping[str, object],
    *,
    result: Mapping[str, object],
    scheduled: Mapping[str, object],
    row_root: Path,
    run_contract: Mapping[str, object],
) -> bool:
    slot_id = cast("str", scheduled["slot_id"])
    adapter_contract = cast("Mapping[str, object]", run_contract["adapter"])
    fields = {
        "schema_version",
        "adapter_version",
        "system_id",
        "status",
        "returncode",
        "wrapper_returncode",
        "timed_out",
        "command_sha256",
        "target_url_sha256",
        "gateway_base_url_sha256",
        "docker_host_sha256",
        "gateway",
        "limits",
        "tool_image",
        "process_group_policy",
        "input_contract",
        "runtime",
        "capture",
        "candidate_extraction",
        "environment_policy",
    }
    if (
        set(adapter) != fields
        or adapter.get("schema_version") != adapter_contract.get("schema_version")
        or adapter.get("adapter_version") != adapter_contract.get("adapter_version")
        or adapter.get("system_id") != scheduled["system"]
        or adapter.get("status") not in {"completed", "timed_out", "agent_nonzero"}
        or isinstance(adapter.get("returncode"), bool)
        or not isinstance(adapter.get("returncode"), int)
        or isinstance(adapter.get("wrapper_returncode"), bool)
        or not isinstance(adapter.get("wrapper_returncode"), int)
        or not isinstance(adapter.get("timed_out"), bool)
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter result identity is invalid")
    for name in (
        "command_sha256",
        "target_url_sha256",
        "gateway_base_url_sha256",
        "docker_host_sha256",
    ):
        _digest(adapter.get(name), f"row {slot_id} adapter {name}")
    target = cast("Mapping[str, object]", result["target"])
    target_url = target.get("target_url")
    if not isinstance(target_url, str) or adapter.get("target_url_sha256") != _sha256_text(
        target_url
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter target binding is invalid")
    image_role = "ravage_tool" if scheduled["system"] == "ravage" else "strix_sandbox"
    images = cast("Mapping[str, object]", run_contract["oci_images"])
    if adapter.get("tool_image") != images.get(image_role):
        raise EvidenceIntegrityError(f"row {slot_id} adapter tool image differs from commitment")
    execution_policy = cast("Mapping[str, object]", run_contract["execution_policy"])
    evaluator_host = cast("Mapping[str, object]", execution_policy["evaluator_host"])
    host_systems = cast("Mapping[str, object]", evaluator_host["systems"])
    system_host = cast("Mapping[str, object]", host_systems[cast("str", scheduled["system"])])
    if adapter.get("docker_host_sha256") != system_host.get("docker_host_sha256"):
        raise EvidenceIntegrityError(f"row {slot_id} adapter Docker host differs from commitment")
    if adapter.get("process_group_policy") != execution_policy.get("process_group_policy"):
        raise EvidenceIntegrityError(
            f"row {slot_id} adapter process-group policy differs from commitment"
        )
    gateway_snapshot = adapter.get("gateway")
    gateway_contract = cast("Mapping[str, object]", run_contract["model_gateway"])
    gateway_policy = cast("Mapping[str, object]", gateway_contract["policy"])
    if not isinstance(gateway_snapshot, Mapping) or set(gateway_snapshot) != {
        "base_url_sha256",
        "token_sha256",
        "model",
        "reasoning_effort",
        "pricing",
        "max_output_tokens",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} adapter gateway snapshot is invalid")
    _digest(gateway_snapshot.get("base_url_sha256"), f"row {slot_id} gateway base URL")
    _digest(gateway_snapshot.get("token_sha256"), f"row {slot_id} gateway token")
    if (
        gateway_snapshot.get("base_url_sha256") != adapter.get("gateway_base_url_sha256")
        or gateway_snapshot.get("model") != gateway_policy.get("model")
        or gateway_snapshot.get("reasoning_effort") != gateway_policy.get("reasoning_effort")
        or gateway_snapshot.get("pricing") != gateway_policy.get("pricing_usd_per_million_tokens")
        or gateway_snapshot.get("max_output_tokens")
        != gateway_policy.get("max_completion_tokens_per_request")
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter gateway differs from commitment")
    budgets = cast("Mapping[str, object]", run_contract["budgets"])
    row_budget = cast("Mapping[str, object]", budgets["per_row"])
    if adapter.get("limits") != _row_limits_json(row_budget):
        raise EvidenceIntegrityError(f"row {slot_id} adapter limits differ from commitment")

    case = cast("Mapping[str, object]", result["case"])
    input_contract = adapter.get("input_contract")
    if not isinstance(input_contract, Mapping) or set(input_contract) != {
        "mode",
        "description_sha256",
        "description_bytes",
        "semantic_prompt_sha256",
        "semantic_prompt_bytes",
        "target_url_in_semantic_prompt",
        "case_id_included",
        "source_path_included",
        "expected_flag_used",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} adapter input contract is invalid")
    if (
        input_contract.get("mode") != "description-only-black-box"
        or input_contract.get("description_sha256")
        != "sha256:" + cast("str", case["description_sha256"])
        or input_contract.get("target_url_in_semantic_prompt") is not False
        or input_contract.get("case_id_included") is not False
        or input_contract.get("source_path_included") is not False
        or input_contract.get("expected_flag_used") is not False
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter input was not black-box safe")
    for name in ("description_bytes", "semantic_prompt_bytes"):
        if (
            isinstance(input_contract.get(name), bool)
            or not isinstance(input_contract.get(name), int)
            or cast("int", input_contract[name]) <= 0
        ):
            raise EvidenceIntegrityError(f"row {slot_id} adapter input size is invalid")
    _digest(input_contract.get("semantic_prompt_sha256"), f"row {slot_id} prompt digest")

    runtime = adapter.get("runtime")
    manifests = cast("Mapping[str, object]", run_contract["runtime_manifests"])
    runtime_contract = cast("Mapping[str, object]", manifests[cast("str", scheduled["system"])])
    source_contract = cast(
        "Mapping[str, object]",
        cast("Mapping[str, object]", run_contract["sources"])[cast("str", scheduled["system"])],
    )
    expected_runtime = {
        "executable_sha256": runtime_contract["executable_sha256"],
        "source_commit": source_contract["commit_sha"],
        "source_tree": source_contract["tree_object"],
        "source_origin_url": source_contract["origin_url"],
        "environment_manifest_sha256": runtime_contract["sha256"],
        "interpreter_sha256": runtime_contract["interpreter_sha256"],
        "lockfile_sha256": runtime_contract["lockfile_sha256"],
        "distribution_inventory_sha256": runtime_contract["distribution_inventory_sha256"],
        "site_packages_tree_sha256": runtime_contract["site_packages_tree_sha256"],
    }
    if runtime != expected_runtime:
        raise EvidenceIntegrityError(f"row {slot_id} adapter runtime differs from commitment")

    capture = adapter.get("capture")
    if not isinstance(capture, Mapping) or set(capture) != {"stdout", "stderr"}:
        raise EvidenceIntegrityError(f"row {slot_id} adapter capture is invalid")
    capture_states = [
        _validate_adapter_capture(
            capture.get(stream),
            path=row_root / "native-output" / f"adapter-{stream}.log",
            label=f"row {slot_id} adapter {stream}",
        )
        for stream in ("stdout", "stderr")
    ]
    capture_complete = all(capture_states)

    extraction = adapter.get("candidate_extraction")
    if not isinstance(extraction, Mapping) or set(extraction) != {
        "complete",
        "candidate_count",
        "artifact_path",
        "scanned_artifact_files",
        "scanned_artifact_bytes",
        "scanned_roots",
        "expected_flag_used",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} adapter extraction is invalid")
    if (
        not isinstance(extraction.get("complete"), bool)
        or extraction.get("scanned_roots")
        != ["agent-run", "adapter-home", "adapter-work", "adapter-tmp"]
        or extraction.get("expected_flag_used") is not False
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter extraction contract is invalid")
    extraction_complete = extraction["complete"] is True
    if extraction.get("artifact_path") != ("flag-candidates.txt" if extraction_complete else None):
        raise EvidenceIntegrityError(f"row {slot_id} adapter extraction artifact is invalid")
    inner_returncode = cast("int", adapter["returncode"])
    portable_returncode = (
        128 + min(127, abs(inner_returncode))
        if inner_returncode < 0
        else min(inner_returncode, 125)
    )
    expected_wrapper_returncode = (
        124
        if adapter["timed_out"] is True
        else (125 if not extraction_complete else portable_returncode)
    )
    expected_adapter_status = (
        "timed_out"
        if adapter["timed_out"] is True
        else ("completed" if inner_returncode == 0 else "agent_nonzero")
    )
    execution = cast("Mapping[str, object]", result["execution"])
    if (
        adapter.get("status") != expected_adapter_status
        or adapter.get("wrapper_returncode") != expected_wrapper_returncode
        or execution.get("status") == "not_started"
        or execution.get("returncode") != expected_wrapper_returncode
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter lifecycle does not match its row")
    candidate_count = _nonnegative_int(
        extraction.get("candidate_count"), f"row {slot_id} candidate count"
    )
    scanned_artifact_files = _nonnegative_int(
        extraction.get("scanned_artifact_files"), f"row {slot_id} scanned files"
    )
    scanned_artifact_bytes = _nonnegative_int(
        extraction.get("scanned_artifact_bytes"), f"row {slot_id} scanned bytes"
    )
    terminal_timeout = adapter["timed_out"] is True
    if terminal_timeout and (
        inner_returncode == 0
        or extraction_complete
        or candidate_count != 0
        or scanned_artifact_files != 0
        or scanned_artifact_bytes != 0
    ):
        raise EvidenceIntegrityError(
            f"row {slot_id} timed-out adapter invented post-timeout extraction"
        )
    candidate_path = row_root / "native-output" / "flag-candidates.txt"
    score = cast("Mapping[str, object]", result["score"])
    artifact = cast("Mapping[str, object]", score["artifact"])
    if artifact.get("path") != "flag-candidates.txt":
        raise EvidenceIntegrityError(f"row {slot_id} did not score the adapter artifact")
    lines: list[bytes] = []
    if extraction_complete:
        candidates = _read_regular(
            candidate_path,
            f"row {slot_id} candidates",
            _MAX_ROW_FILE_BYTES,
        )
        lines = candidates.splitlines()
        if (
            len(lines) != candidate_count
            or lines != sorted(set(lines))
            or any(
                re.fullmatch(rb"(?i)(?:flag|xben|ctf|htb)\{[^}\r\n]{1,512}\}", line) is None
                for line in lines
            )
        ):
            raise EvidenceIntegrityError(f"row {slot_id} adapter candidate artifact is invalid")
    elif candidate_path.exists() or candidate_path.is_symlink():
        raise EvidenceIntegrityError(
            f"row {slot_id} incomplete adapter extraction retained a candidate artifact"
        )

    environment = adapter.get("environment_policy")
    if not isinstance(environment, Mapping) or set(environment) != {
        "inherits_parent",
        "row_gateway_only",
        "ambient_proxy_or_provider_credentials",
        "fresh_home_work_run",
        "persisted_row_credentials_redacted",
    }:
        raise EvidenceIntegrityError(f"row {slot_id} adapter environment policy is invalid")
    if (
        environment.get("inherits_parent") is not False
        or environment.get("row_gateway_only") is not True
        or environment.get("ambient_proxy_or_provider_credentials") is not False
        or environment.get("fresh_home_work_run") is not True
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter environment is unsafe")
    _nonnegative_int(
        environment.get("persisted_row_credentials_redacted"),
        f"row {slot_id} redacted credential files",
    )
    scan_roots = [
        row_root / "native-output" / "agent-run",
        row_root / "native-output" / "adapter-home",
        row_root / "native-output" / "adapter-work",
        row_root / "native-output" / "adapter-tmp",
    ]
    file_candidates, files_complete, scanned = extract_artifact_candidates(scan_roots)
    if not terminal_timeout and (
        extraction.get("scanned_artifact_files") != scanned["files"]
        or extraction.get("scanned_artifact_bytes") != scanned["bytes"]
    ):
        raise EvidenceIntegrityError(f"row {slot_id} adapter artifact scan does not reproduce")
    retained_candidates: set[bytes] = set(file_candidates)
    for stream in ("stdout", "stderr"):
        stream_bytes = _read_regular(
            row_root / "native-output" / f"adapter-{stream}.log",
            f"row {slot_id} adapter {stream}",
            _MAX_JSON_BYTES,
        )
        retained_candidates.update(_FLAG_CANDIDATE_BYTES_RE.findall(stream_bytes))
    retained_lines = set(lines)
    if extraction_complete and (
        not retained_candidates.issubset(retained_lines)
        or (capture_complete and retained_lines != retained_candidates)
    ):
        raise EvidenceIntegrityError(
            f"row {slot_id} adapter candidate extraction does not reproduce"
        )
    # A timed-out adapter intentionally emits no score artifact: its joined
    # process group is not inspected until the outer evaluator has torn it
    # down.  The intact timeout receipt is still a valid losing observation.
    # For every other outcome, extraction must be complete and independently
    # reproducible.  A truncated stream remains evidence-incomplete because it
    # can hide candidates outside the retained prefix.
    return bool(capture_complete and (terminal_timeout or (extraction_complete and files_complete)))


def _validate_adapter_capture(value: object, *, path: Path, label: str) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "sha256",
        "total_bytes",
        "retained_bytes",
        "truncated",
        "complete",
    }:
        raise EvidenceIntegrityError(f"{label} capture is invalid")
    _digest(value.get("sha256"), f"{label} digest")
    total = _nonnegative_int(value.get("total_bytes"), f"{label} total bytes")
    retained = _nonnegative_int(value.get("retained_bytes"), f"{label} retained bytes")
    body = _read_regular(path, f"{label} log", _MAX_JSON_BYTES)
    if (
        retained != len(body)
        or retained > total
        or value.get("truncated") is not (total > retained)
    ):
        raise EvidenceIntegrityError(f"{label} capture does not match retained bytes")
    if value.get("truncated") is False and value.get("sha256") != (
        "sha256:" + hashlib.sha256(body).hexdigest()
    ):
        raise EvidenceIntegrityError(f"{label} capture digest does not match retained bytes")
    if not isinstance(value.get("complete"), bool):
        raise EvidenceIntegrityError(f"{label} capture completeness is invalid")
    return value.get("truncated") is False and value.get("complete") is True


def _verify_target_evidence(  # noqa: PLR0912, PLR0914, PLR0915
    result: Mapping[str, object],
    *,
    scheduled: Mapping[str, object],
    row_root: Path,
    campaign_root: Path,
    row_budget: Mapping[str, object],
    execution_policy: Mapping[str, object],
    sources: Mapping[str, object],
    compatibility_catalog: Mapping[str, object],
    oci_images: Mapping[str, object],
    target_helper_image_ids: Mapping[str, object],
) -> dict[str, object]:
    slot_id = cast("str", scheduled["slot_id"])
    unverified: dict[str, object] = {
        "target_verified": False,
        "prepared_target": None,
        "target_request_attempts": None,
    }
    build_wrapper = _load_json(
        row_root / "target-build.json", f"row {slot_id} target build receipt"
    )
    teardown_wrapper = _load_json(
        row_root / "target-teardown.json", f"row {slot_id} target teardown receipt"
    )
    if build_wrapper.get("status") != "succeeded" or teardown_wrapper.get("status") != "succeeded":
        return unverified
    build_provenance = build_wrapper.get("provenance")
    teardown_provenance = teardown_wrapper.get("provenance")
    if not isinstance(build_provenance, Mapping) or not isinstance(teardown_provenance, Mapping):
        return unverified
    if "backend" not in build_provenance and "request_meter" not in teardown_provenance:
        return unverified

    evidence_dir = _bound_external_directory(
        build_provenance.get("evidence_dir"),
        campaign_root=campaign_root,
        label=f"row {slot_id} target evidence",
    )
    try:
        arm = validate_prepared_target_arm_provenance(
            dict(build_provenance),
            evidence_dir=evidence_dir,
        )
    except (DockerEvidenceError, ValueError, OSError) as exc:
        raise EvidenceIntegrityError(
            f"row {slot_id} prepared target arm receipt is invalid: {exc}"
        ) from exc
    endpoint_modes = execution_policy.get("target_endpoint_modes")
    expected_endpoint = (
        endpoint_modes.get(scheduled["system"]) if isinstance(endpoint_modes, Mapping) else None
    )
    score = cast("Mapping[str, object]", result["score"])
    row_target = cast("Mapping[str, object]", result["target"])
    if (
        arm.get("arm") != scheduled["system"]
        or arm.get("benchmark_id") != scheduled["case_id"]
        or arm.get("pair_flag_sha256") != score["expected_flag_sha256"]
        or arm.get("target_url") != row_target.get("target_url")
        or arm.get("max_target_requests") != row_budget["max_target_requests"]
        or arm.get("gateway_endpoint_mode") != expected_endpoint
        or arm.get("platform") != execution_policy.get("platform")
        or arm.get("build_once_per_case_pair")
        is not execution_policy.get("build_once_per_case_pair")
        or arm.get("runtime_build_allowed") is not execution_policy.get("runtime_build_allowed")
        or arm.get("runtime_pull_allowed") is not execution_policy.get("runtime_pull_allowed")
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target build policy differs from contract")
    source_path = evidence_dir / "source.json"
    source_payload = _load_json(source_path, f"row {slot_id} target source evidence")
    build_payload = _load_json(evidence_dir / "build.json", f"row {slot_id} target build evidence")
    _verify_target_infrastructure_images(
        build_payload,
        oci_images=oci_images,
        target_helper_image_ids=target_helper_image_ids,
        slot_id=slot_id,
    )
    xben_source = cast("Mapping[str, object]", sources["xben"])
    catalog = source_payload.get("compatibility_patch_catalog")
    catalog_source = catalog.get("source") if isinstance(catalog, Mapping) else None
    if (
        source_payload.get("commit") != xben_source.get("commit_sha")
        or source_payload.get("checkout_clean_before_and_after") is not True
        or not isinstance(catalog, Mapping)
        or not isinstance(catalog_source, Mapping)
        or catalog.get("schema_version") != compatibility_catalog.get("schema_version")
        or "sha256:" + str(catalog.get("catalog_sha256")) != compatibility_catalog.get("sha256")
        or catalog_source.get("origin") != xben_source.get("origin_url")
        or catalog_source.get("commit_sha") != xben_source.get("commit_sha")
        or catalog_source.get("benchmarks_tree_sha") != xben_source.get("tree_object")
        or catalog.get("source_tree_verified") is not True
        or catalog.get("complete_case_set_verified") is not True
        or catalog.get("selected_case_id") != scheduled["case_id"]
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target source closure is invalid")
    prepared_path = _bound_external_file(
        arm.get("prepared_provenance_path"),
        campaign_root=campaign_root,
        expected_name="prepared.json",
        label=f"row {slot_id} prepared target",
    )
    prepared_digest = _raw_file_digest(prepared_path)
    if prepared_digest != arm.get("prepared_provenance_sha256"):
        raise EvidenceIntegrityError(f"row {slot_id} prepared target digest is invalid")
    prepared_payload = _load_json(prepared_path, f"row {slot_id} prepared target")
    try:
        prepared = validate_prepared_target_provenance(
            prepared_payload,
            evidence_dir=prepared_path.parent,
        )
    except (DockerEvidenceError, ValueError, OSError) as exc:
        raise EvidenceIntegrityError(
            f"row {slot_id} prepared target receipt is invalid: {exc}"
        ) from exc
    if (
        prepared.get("pair_id") != arm.get("pair_id")
        or prepared.get("benchmark_id") != scheduled["case_id"]
        or prepared.get("pair_flag_sha256") != score["expected_flag_sha256"]
        or prepared.get("build_input_boundary")
        != execution_policy.get("target_build_input_boundary")
    ):
        raise EvidenceIntegrityError(f"row {slot_id} prepared target is misbound")
    prepared_image_ids = prepared.get("image_ids_by_service")
    if not isinstance(prepared_image_ids, Mapping) or prepared_image_ids != arm.get(
        "target_image_ids_by_service"
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target images differ from preparation")
    runtime_identities = _target_runtime_identities(build_payload, arm=arm, slot_id=slot_id)

    teardown_fields = {
        "removed",
        "verified",
        "project",
        "evidence_path",
        "evidence_sha256",
        "request_count",
        "request_meter",
        "request_count_receipt_path",
        "request_count_receipt_sha256",
    }
    if set(teardown_provenance) != teardown_fields:
        raise EvidenceIntegrityError(f"row {slot_id} target teardown provenance fields are invalid")
    teardown_path = _bound_external_file(
        teardown_provenance.get("evidence_path"),
        campaign_root=campaign_root,
        expected_name="teardown.json",
        label=f"row {slot_id} target teardown evidence",
    )
    if (
        teardown_path.parent != evidence_dir
        or teardown_provenance.get("evidence_sha256") != _raw_file_digest(teardown_path)
        or teardown_provenance.get("removed") is not True
        or teardown_provenance.get("verified") is not True
        or teardown_provenance.get("project") != arm.get("project")
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target teardown binding is invalid")
    meter = teardown_provenance.get("request_meter")
    try:
        validated_meter = validate_request_meter_stop_provenance(
            meter,
            evidence_dir=evidence_dir,
        )
    except (DockerEvidenceError, ValueError, OSError) as exc:
        raise EvidenceIntegrityError(
            f"row {slot_id} target request meter is invalid: {exc}"
        ) from exc
    if (
        validated_meter.get("instance_id") != row_target["instance_id"]
        or validated_meter.get("endpoint_mode") != expected_endpoint
        or validated_meter.get("hard_limit") != row_budget["max_target_requests"]
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target request meter is misbound")
    count_path = _bound_external_file(
        teardown_provenance.get("request_count_receipt_path"),
        campaign_root=campaign_root,
        expected_name="request-count.json",
        label=f"row {slot_id} target request receipt",
    )
    if count_path.parent != evidence_dir or teardown_provenance.get(
        "request_count_receipt_sha256"
    ) != _raw_file_digest(count_path):
        raise EvidenceIntegrityError(f"row {slot_id} target request receipt is misbound")
    teardown_payload = _load_json(teardown_path, f"row {slot_id} target teardown evidence")
    gateway_log_payload = _load_json(
        evidence_dir / "gateway-log.json",
        f"row {slot_id} target gateway log evidence",
    )
    if (
        teardown_payload.get("status") != "succeeded"
        or teardown_payload.get("errors") != []
        or teardown_payload.get("request_count") != teardown_provenance.get("request_count")
        or teardown_payload.get("request_meter") != validated_meter
        or teardown_payload.get("gateway_logs") != gateway_log_payload
        or teardown_payload.get("project") != arm.get("project")
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target teardown did not verify cleanup")
    return {
        "target_verified": True,
        "prepared_target": {
            "pair_id": arm["pair_id"],
            "benchmark_id": arm["benchmark_id"],
            "pair_flag_sha256": arm["pair_flag_sha256"],
            "prepared_path": str(prepared_path),
            "prepared_sha256": prepared_digest,
            "image_ids_by_service": dict(prepared_image_ids),
            **runtime_identities,
            "arm": scheduled["system"],
            "instance_id": row_target["instance_id"],
        },
        "target_request_attempts": validated_meter["target_request_attempt_count"],
    }


def _verify_target_infrastructure_images(
    build_payload: Mapping[str, object],
    *,
    oci_images: Mapping[str, object],
    target_helper_image_ids: Mapping[str, object],
    slot_id: str,
) -> None:
    """Cross-bind operational target helpers to the pre-draw OCI snapshot."""

    readiness = build_payload.get("readiness")
    gateway = build_payload.get("gateway")
    if (
        not isinstance(readiness, Mapping)
        or readiness.get("probe_image") != oci_images.get("target_probe")
        or readiness.get("probe_image_id") != target_helper_image_ids.get("target_probe")
        or not isinstance(gateway, Mapping)
        or gateway.get("image") != oci_images.get("target_gateway")
        or gateway.get("image_id") != target_helper_image_ids.get("target_gateway")
    ):
        raise EvidenceIntegrityError(
            f"row {slot_id} target infrastructure images differ from the run contract"
        )


def _target_runtime_identities(
    build_payload: Mapping[str, object],
    *,
    arm: Mapping[str, object],
    slot_id: str,
) -> dict[str, object]:
    """Extract operational Docker identities for cross-row freshness checks."""
    inspection = build_payload.get("target_inspection")
    containers = inspection.get("containers") if isinstance(inspection, Mapping) else None
    network = inspection.get("network") if isinstance(inspection, Mapping) else None
    gateway = build_payload.get("gateway")
    if (
        not isinstance(containers, list)
        or not containers
        or not isinstance(network, Mapping)
        or not isinstance(gateway, Mapping)
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target runtime identities are missing")
    container_ids: list[str] = []
    volume_names: list[str] = []
    for container in containers:
        if not isinstance(container, Mapping):
            raise EvidenceIntegrityError(f"row {slot_id} target container identity is invalid")
        container_id = container.get("container_id")
        volumes = container.get("volume_names")
        if (
            not isinstance(container_id, str)
            or not _docker_object_id(container_id)
            or not isinstance(volumes, list)
            or any(not isinstance(name, str) or not name for name in volumes)
        ):
            raise EvidenceIntegrityError(f"row {slot_id} target container identity is invalid")
        container_ids.append(container_id)
        volume_names.extend(cast("list[str]", volumes))
    gateway_id = gateway.get("container_id")
    network_id = network.get("id")
    if (
        not isinstance(gateway_id, str)
        or not _docker_object_id(gateway_id)
        or not isinstance(network_id, str)
        or not _docker_object_id(network_id)
        or network.get("name") != arm.get("target_network")
        or len(set(container_ids)) != len(container_ids)
        or gateway_id in container_ids
        or len(set(volume_names)) != len(volume_names)
    ):
        raise EvidenceIntegrityError(f"row {slot_id} target runtime identities are invalid")
    return {
        "project": arm["project"],
        "target_network_name": arm["target_network"],
        "target_network_id": network_id,
        "container_ids": sorted([*container_ids, gateway_id]),
        "volume_names": sorted(volume_names),
    }


def _docker_object_id(value: str) -> bool:
    return _HEX_DIGEST_RE.fullmatch(value) is not None or _DIGEST_RE.fullmatch(value) is not None


def _verify_paired_target_reuse(
    schedule: list[Mapping[str, object]],
    rows: list[dict[str, object]],
    independent_rows: list[dict[str, object]],
) -> bool:
    """Require one prepared image/flag closure and one semantic prompt per pair."""
    scalar_identities: dict[str, set[str]] = {
        "project": set(),
        "target_network_name": set(),
        "target_network_id": set(),
    }
    collection_identities: dict[str, set[str]] = {
        "container_ids": set(),
        "volume_names": set(),
    }

    for offset in range(0, EXPECTED_ROWS, 2):
        scheduled_pair = schedule[offset : offset + 2]
        row_pair = rows[offset : offset + 2]
        evidence_pair = independent_rows[offset : offset + 2]
        if len(scheduled_pair) != 2 or len(row_pair) != 2 or len(evidence_pair) != 2:
            return False
        prepared_values = [item.get("prepared_target") for item in evidence_pair]
        if any(not isinstance(item, Mapping) for item in prepared_values):
            return False
        first = cast("Mapping[str, object]", prepared_values[0])
        second = cast("Mapping[str, object]", prepared_values[1])
        shared_fields = (
            "pair_id",
            "benchmark_id",
            "pair_flag_sha256",
            "prepared_path",
            "prepared_sha256",
            "image_ids_by_service",
        )
        if any(first.get(name) != second.get(name) for name in shared_fields):
            raise EvidenceIntegrityError("paired arms do not share one prepared target closure")
        if {first.get("arm"), second.get("arm")} != set(EXPECTED_SYSTEMS):
            raise EvidenceIntegrityError("prepared target does not contain both system arms")
        if first.get("benchmark_id") != scheduled_pair[0]["case_id"]:
            raise EvidenceIntegrityError("prepared target benchmark differs from its pair")
        for prepared in (first, second):
            for name, seen in scalar_identities.items():
                identity = prepared.get(name)
                if not isinstance(identity, str) or not identity or identity in seen:
                    raise EvidenceIntegrityError(
                        f"prepared target reuses Docker {name} across arms"
                    )
                seen.add(identity)
            for name, seen in collection_identities.items():
                identities = prepared.get(name)
                if (
                    not isinstance(identities, list)
                    or (name == "container_ids" and not identities)
                    or any(not isinstance(item, str) or not item for item in identities)
                    or len(set(identities)) != len(identities)
                    or seen.intersection(cast("list[str]", identities))
                ):
                    raise EvidenceIntegrityError(
                        f"prepared target reuses Docker {name} across arms"
                    )
                seen.update(cast("list[str]", identities))
        expected_instances = {
            cast("str", prepared["arm"]): cast("str", prepared["instance_id"])
            for prepared in (first, second)
        }
        release_path = Path(cast("str", first["prepared_path"])).parent / "release.json"
        if not release_path.exists() and not release_path.is_symlink():
            return False
        release = _load_json(release_path, "prepared target release evidence")
        if (
            set(release)
            != {
                "schema_version",
                "pair_id",
                "benchmark_id",
                "arms",
                "both_arms_terminated",
                "prepared_source_removed",
                "owned_image_references_released",
                "owned_image_references_absent",
                "owned_image_reference_absence_verified",
                "commands",
                "errors",
                "valid",
            }
            or release.get("schema_version") != "ravage.xben.prepared-target-release.v1"
            or release.get("pair_id") != first["pair_id"]
            or release.get("benchmark_id") != first["benchmark_id"]
            or release.get("arms") != dict(sorted(expected_instances.items()))
            or release.get("both_arms_terminated") is not True
            or release.get("prepared_source_removed") is not True
            or not isinstance(release.get("owned_image_references_released"), list)
            or release.get("owned_image_references_absent")
            != release.get("owned_image_references_released")
            or release.get("owned_image_reference_absence_verified") is not True
            or not isinstance(release.get("commands"), list)
            or release.get("errors") != []
            or release.get("valid") is not True
        ):
            raise EvidenceIntegrityError("prepared target release evidence is invalid")
        prompt_fields = (
            "adapter_description_sha256",
            "semantic_prompt_sha256",
            "description_bytes",
            "semantic_prompt_bytes",
        )
        if any(
            evidence_pair[0].get(name) != evidence_pair[1].get(name)
            or evidence_pair[0].get(name) is None
            for name in prompt_fields
        ):
            raise EvidenceIntegrityError(
                "paired Ravage/Strix semantic prompt payloads are not byte-equivalent"
            )
    return True


def _verify_primary_results_seal(
    campaign_root: Path,
    *,
    schedule: list[Mapping[str, object]],
    rows: list[dict[str, object]],
    row_roots: Mapping[str, Path],
    independent_rows: list[dict[str, object]],
    campaign_id: str,
    commitment_digest: str,
    selection_digest: str,
) -> dict[str, object]:
    path = campaign_root / PRIMARY_RESULTS_SEAL_FILE
    if not path.exists() and not path.is_symlink():
        return {"verified": False, "reason": "missing"}
    seal = _load_json(path, "primary results seal")
    fields = {
        "schema_version",
        "created_at",
        "campaign_id",
        "commitment_digest",
        "selection_digest",
        "row_count",
        "rows",
        "paired_targets",
        "all_terminal",
        "document_sha256",
    }
    if set(seal) != fields or seal.get("schema_version") != PRIMARY_RESULTS_SEAL_SCHEMA:
        raise EvidenceIntegrityError("primary results seal fields are invalid")
    created_at = _evidence_timestamp(seal.get("created_at"), "primary results seal creation")
    latest_row_completion = max(
        _evidence_timestamp(row.get("completed_at"), "terminal row completion") for row in rows
    )
    if created_at < latest_row_completion:
        raise EvidenceIntegrityError("primary results were sealed before all rows terminated")
    expected_rows: list[dict[str, object]] = []
    for scheduled in schedule:
        slot_id = cast("str", scheduled["slot_id"])
        row_root = row_roots[slot_id]
        expected_rows.append(
            {
                "slot_id": slot_id,
                "row_manifest_sha256": _prefixed_file_digest(row_root / REPORT_MANIFEST_FILE),
                "row_result_sha256": _prefixed_file_digest(row_root / "row-result.json"),
                "adapter_result_sha256": _optional_prefixed_file_digest(
                    row_root / ADAPTER_RESULT_FILE
                ),
                "process_receipt_sha256": _prefixed_file_digest(row_root / PROCESS_RECEIPT_FILE),
                "model_gateway_receipt_sha256": _prefixed_file_digest(
                    row_root / MODEL_GATEWAY_RECEIPT_FILE
                ),
                "sandbox_profile_sha256": _prefixed_file_digest(row_root / SANDBOX_PROFILE_FILE),
                "target_build_sha256": _prefixed_file_digest(row_root / "target-build.json"),
                "target_teardown_sha256": _prefixed_file_digest(row_root / "target-teardown.json"),
            }
        )
    expected_pairs: list[dict[str, object]] = []
    for offset in range(0, EXPECTED_ROWS, 2):
        pair_rows = independent_rows[offset : offset + 2]
        prepared = [item.get("prepared_target") for item in pair_rows]
        first = prepared[0] if prepared and isinstance(prepared[0], Mapping) else None
        if first is None:
            expected_pairs.append(
                {
                    "pair_index": offset // 2 + 1,
                    "case_id": schedule[offset]["case_id"],
                    "pair_id": None,
                    "prepared_target_sha256": None,
                    "release_sha256": None,
                }
            )
            continue
        prepared_path = _bound_external_file(
            first.get("prepared_path"),
            campaign_root=campaign_root,
            expected_name="prepared.json",
            label=f"pair {offset // 2 + 1} prepared target",
        )
        release_path = prepared_path.parent / "release.json"
        expected_pairs.append(
            {
                "pair_index": offset // 2 + 1,
                "case_id": schedule[offset]["case_id"],
                "pair_id": first.get("pair_id"),
                "prepared_target_sha256": _prefixed_file_digest(prepared_path),
                "release_sha256": _optional_prefixed_file_digest(release_path),
            }
        )
    if (
        seal.get("campaign_id") != campaign_id
        or seal.get("commitment_digest") != commitment_digest
        or seal.get("selection_digest") != selection_digest
        or seal.get("row_count") != EXPECTED_ROWS
        or seal.get("rows") != expected_rows
        or seal.get("paired_targets") != expected_pairs
        or seal.get("all_terminal") is not True
        or seal.get("document_sha256")
        != _prefixed_document_digest(seal, label="primary results seal")
    ):
        raise EvidenceIntegrityError("primary results seal does not bind the terminal matrix")
    return {
        "verified": True,
        "file_sha256": _prefixed_file_digest(path),
        "document_sha256": seal["document_sha256"],
    }


def _verify_model_gateway_campaign_seal(
    campaign_root: Path,
    *,
    independent_rows: list[dict[str, object]],
    run_contract: Mapping[str, object],
) -> dict[str, object]:
    unavailable = {
        "verified": False,
        "cost_usd": {
            "available": False,
            "reason": "campaign model-gateway seal is absent or incomplete",
        },
    }
    path = campaign_root / MODEL_GATEWAY_CAMPAIGN_RECEIPT_FILE
    if not path.exists() and not path.is_symlink():
        return unavailable
    receipts: dict[str, object] = {}
    file_digests: dict[str, str] = {}
    for item in independent_rows:
        slot_id = cast("str", item["slot_id"])
        receipt = item.get("model_receipt")
        digest = item.get("model_receipt_file_sha256")
        if not isinstance(receipt, Mapping) or not isinstance(digest, str):
            return unavailable
        receipts[slot_id] = receipt
        file_digests[slot_id] = digest
    token_digests = [
        cast("Mapping[str, object]", receipts[slot_id]).get("row_token_sha256")
        for slot_id in sorted(receipts)
    ]
    if (
        any(
            not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
            for value in token_digests
        )
        or len(set(token_digests)) != EXPECTED_ROWS
    ):
        raise EvidenceIntegrityError("campaign model gateway row tokens are not unique")
    payload = _load_json(path, "campaign model-gateway seal")
    gateway = cast("Mapping[str, object]", run_contract["model_gateway"])
    budgets = cast("Mapping[str, object]", run_contract["budgets"])
    row_budget = cast("Mapping[str, object]", budgets["per_row"])
    campaign_budget = cast("Mapping[str, object]", budgets["campaign"])
    try:
        validated = validate_model_gateway_campaign_receipt(
            payload,
            expected_policy_sha256=cast("str", gateway["policy_sha256"]),
            expected_campaign_max_cost_usd=cast("str", campaign_budget["max_cost_usd"]),
            expected_max_requests_per_row=cast("int", row_budget["max_model_requests"]),
            expected_max_cost_usd_per_row=cast("str", row_budget["max_cost_usd"]),
            row_receipts=receipts,
            row_receipt_file_sha256=file_digests,
        )
    except (ModelGatewayError, ValueError) as exc:
        raise EvidenceIntegrityError(f"campaign model-gateway seal is invalid: {exc}") from exc
    if validated.get("policy") != gateway.get("policy"):
        raise EvidenceIntegrityError("campaign model policy differs from the commitment")
    totals = validated.get("totals")
    if not isinstance(totals, Mapping) or cast("int", totals.get("requests_started")) > cast(
        "int", campaign_budget["max_model_requests"]
    ):
        raise EvidenceIntegrityError("campaign model request total exceeds its frozen cap")
    return {
        "verified": validated.get("valid") is True,
        "file_sha256": _prefixed_file_digest(path),
        "document_sha256": validated["document_sha256"],
        "cost_usd": {
            "available": True,
            "charged": totals["charged_cost_usd"],
            "known_actual": totals["known_actual_cost_usd"],
            "ceiling": totals["campaign_max_cost_usd"],
            "source": "independently-validated sealed model-gateway campaign ledger",
            "pricing_provenance": (
                "precommitted operator-supplied pricing snapshot; not an independently "
                "verified provider invoice"
            ),
        },
    }


def _verify_evaluator_component_sources(run_contract: Mapping[str, object]) -> bool:
    components = cast("Mapping[str, object]", run_contract["evaluator_components"])
    repository_root = _REPOSITORY_ROOT
    for relative, expected in components.items():
        candidate = repository_root / relative
        if candidate.is_symlink() or not candidate.is_file():
            return False
        if "sha256:" + _raw_file_digest(candidate) != expected:
            return False
    catalog = cast("Mapping[str, object]", run_contract["compatibility_catalog"])
    catalog_path = repository_root / "tools/paired_xben/compatibility/catalog.json"
    if (
        catalog_path.is_symlink()
        or not catalog_path.is_file()
        or "sha256:" + _raw_file_digest(catalog_path) != catalog.get("sha256")
    ):
        return False
    return True


def _verify_public_execution_attestation(
    campaign_root: Path,
    *,
    campaign_id: str,
    commitment_digest: str,
    selection_digest: str,
    primary_results: Mapping[str, object],
    model_campaign: Mapping[str, object],
) -> bool:
    """Fail closed until a cryptographic public-execution validator is available."""

    path = campaign_root / PUBLIC_EXECUTION_ATTESTATION_FILE
    if not path.exists() and not path.is_symlink():
        return False
    payload = _load_json(path, "public execution attestation")
    bindings = payload.get("bindings")
    if not isinstance(bindings, Mapping) or bindings != {
        "campaign_id": campaign_id,
        "commitment_digest": commitment_digest,
        "selection_digest": selection_digest,
        "primary_results_file_sha256": primary_results.get("file_sha256"),
        "model_gateway_campaign_file_sha256": model_campaign.get("file_sha256"),
    }:
        raise EvidenceIntegrityError("public execution attestation bindings are invalid")
    # A JSON boolean cannot prove public execution or canonical publication.
    # A future authenticity module must provide signature/transparency-log and
    # canonical-namespace verification before this gate can return True.
    return False


def _validate_unique_row_state(
    schedule: list[Mapping[str, object]],
    rows: list[dict[str, object]],
) -> None:
    flags_by_pair: dict[int, set[str]] = {}
    instance_ids: set[str] = set()
    for scheduled, row in zip(schedule, rows, strict=True):
        binding = cast("Mapping[str, object]", row["schedule_binding"])
        slot_id = cast("str", binding["primary_slot_id"])
        score = cast("Mapping[str, object]", row["score"])
        expected_flag_sha256 = score.get("expected_flag_sha256")
        if (
            not isinstance(expected_flag_sha256, str)
            or _HEX_DIGEST_RE.fullmatch(expected_flag_sha256) is None
        ):
            raise EvidenceIntegrityError(f"row {slot_id} flag digest is invalid")
        target = row.get("target")
        if not isinstance(target, Mapping):
            raise EvidenceIntegrityError(f"row {slot_id} has no target evidence")
        instance_id = _nonempty(target.get("instance_id"), f"row {slot_id} target instance ID")
        if _INSTANCE_ID_RE.fullmatch(instance_id) is None:
            raise EvidenceIntegrityError(f"row {slot_id} target instance ID is invalid")
        if instance_id in instance_ids:
            raise EvidenceIntegrityError("target instance IDs are not unique across 40 primaries")
        pair_index = cast("int", scheduled["pair_index"])
        flags_by_pair.setdefault(pair_index, set()).add(expected_flag_sha256)
        instance_ids.add(instance_id)
    if any(len(values) != 1 for values in flags_by_pair.values()):
        raise EvidenceIntegrityError("both arms in a pair must share one expected flag commitment")
    pair_flags = {next(iter(values)) for values in flags_by_pair.values()}
    if len(pair_flags) != EXPECTED_CASES or len(instance_ids) != EXPECTED_ROWS:
        raise EvidenceIntegrityError("pair flag or target-instance uniqueness is incomplete")


def _paired_results(
    schedule: list[Mapping[str, object]], rows: list[dict[str, object]]
) -> dict[str, object]:
    by_case: dict[str, dict[str, bool]] = {}
    for scheduled, row in zip(schedule, rows, strict=True):
        by_case.setdefault(cast("str", scheduled["case_id"]), {})[
            cast("str", scheduled["system"])
        ] = cast("bool", cast("Mapping[str, object]", row["score"])["solved"])
    both = ravage_only = strix_only = neither = 0
    for outcomes in by_case.values():
        ravage = outcomes["ravage"]
        strix = outcomes["strix"]
        if ravage and strix:
            both += 1
        elif ravage:
            ravage_only += 1
        elif strix:
            strix_only += 1
        else:
            neither += 1
    ravage_solved = both + ravage_only
    strix_solved = both + strix_only
    discordant = ravage_only + strix_only
    return {
        "systems": {
            "ravage": {
                "solved": ravage_solved,
                "total": EXPECTED_CASES,
                "solve_rate": ravage_solved / EXPECTED_CASES,
            },
            "strix": {
                "solved": strix_solved,
                "total": EXPECTED_CASES,
                "solve_rate": strix_solved / EXPECTED_CASES,
            },
        },
        "paired_contingency": {
            "both_solved": both,
            "ravage_only": ravage_only,
            "strix_only": strix_only,
            "neither_solved": neither,
        },
        "solve_rate_delta_ravage_minus_strix": round(
            (ravage_solved - strix_solved) / EXPECTED_CASES, 12
        ),
        "discordant_pairs": discordant,
        "exact_two_sided_sign_mcnemar_p_value": exact_two_sided_mcnemar_p_value(
            ravage_only, strix_only
        ),
    }


def _status_counts(
    schedule: list[Mapping[str, object]], rows: list[dict[str, object]]
) -> dict[str, object]:
    by_system: dict[str, Counter[str]] = {system: Counter() for system in EXPECTED_SYSTEMS}
    overall: Counter[str] = Counter()
    for scheduled, row in zip(schedule, rows, strict=True):
        status = cast("str", row["status"])
        system = cast("str", scheduled["system"])
        by_system[system][status] += 1
        overall[status] += 1
    return {
        "overall": {status: overall[status] for status in TERMINAL_STATUSES},
        "by_system": {
            system: {status: by_system[system][status] for status in TERMINAL_STATUSES}
            for system in EXPECTED_SYSTEMS
        },
    }


def _elapsed_summary(
    schedule: list[Mapping[str, object]], rows: list[dict[str, object]]
) -> dict[str, object]:
    by_system = dict.fromkeys(EXPECTED_SYSTEMS, 0.0)
    total = 0.0
    for scheduled, row in zip(schedule, rows, strict=True):
        elapsed = _finite_nonnegative(row["elapsed_seconds"], "elapsed_seconds")
        total += elapsed
        by_system[cast("str", scheduled["system"])] += elapsed
    return {
        "available": True,
        "source": (
            "manifest-integrity-checked row-reported monotonic duration; "
            "independent clock attestation unavailable"
        ),
        "total": round(total, 6),
        "by_system": {system: round(value, 6) for system, value in by_system.items()},
    }


def _one_row_result(artifact_root: Path, *, slot_id: str) -> Path:
    candidates: list[Path] = []
    count = 0
    for path in artifact_root.rglob("*"):
        count += 1
        if count > _MAX_ROW_FILES:
            raise EvidenceIntegrityError(f"artifacts for {slot_id} contain too many entries")
        if path.is_symlink():
            raise EvidenceIntegrityError(f"artifacts for {slot_id} contain a symlink")
        if path.is_file() and path.name == "row-result.json":
            candidates.append(path)
    if not candidates:
        raise IncompleteCampaignError(f"scheduled row {slot_id} has no terminal row-result.json")
    if len(candidates) != 1:
        raise EvidenceIntegrityError(f"scheduled row {slot_id} has duplicate row results")
    result_path = candidates[0]
    row_root = result_path.parent
    for path in artifact_root.rglob("*"):
        if path.is_file() and not path.is_relative_to(row_root):
            raise EvidenceIntegrityError(f"scheduled row {slot_id} has ambiguous sibling evidence")
    return result_path


def _verify_row_manifest(row_root: Path) -> None:
    manifest_path = row_root / "artifacts.sha256"
    raw = _read_regular(manifest_path, "row SHA256 manifest", _MAX_MANIFEST_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceIntegrityError("row SHA256 manifest is not UTF-8") from exc
    declared: dict[str, str] = {}
    for line in text.splitlines():
        digest_text, separator, relative_text = line.partition("  ")
        if not separator or _HEX_DIGEST_RE.fullmatch(digest_text) is None:
            raise EvidenceIntegrityError("row SHA256 manifest contains an invalid line")
        relative = Path(relative_text)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise EvidenceIntegrityError("row SHA256 manifest contains an unsafe path")
        name = relative.as_posix()
        if name == REPORT_MANIFEST_FILE or name in declared:
            raise EvidenceIntegrityError("row SHA256 manifest is self-referential or duplicated")
        declared[name] = digest_text
    actual: dict[str, Path] = {}
    for path in row_root.rglob("*"):
        if path.is_symlink():
            raise EvidenceIntegrityError("row evidence contains a symlink")
        if path.is_file() and path != manifest_path:
            relative_name = path.relative_to(row_root).as_posix()
            actual[relative_name] = path
    if set(declared) != set(actual):
        raise EvidenceIntegrityError("row SHA256 manifest does not enumerate exact evidence files")
    if "row-result.json" not in declared:
        raise EvidenceIntegrityError("row SHA256 manifest omits row-result.json")
    for name, path in actual.items():
        if path.stat().st_size > _MAX_ROW_FILE_BYTES:
            raise EvidenceIntegrityError(f"row evidence file is too large: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != declared[name]:
            raise EvidenceIntegrityError(f"row evidence digest mismatch: {name}")


def _child_directory_names(path: Path, label: str) -> set[str]:
    names: set[str] = set()
    for child in path.iterdir():
        if child.is_symlink() or not child.is_dir():
            raise EvidenceIntegrityError(f"{label} contain a non-directory entry")
        if child.name in names:
            raise EvidenceIntegrityError(f"{label} contain duplicate entries")
        names.add(child.name)
    return names


def _directory(path: Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_symlink() or not candidate.is_dir():
        raise EvidenceIntegrityError(f"{label} is missing, unsafe, or not a directory")
    return candidate.resolve()


def _load_json(path: Path, label: str) -> dict[str, object]:
    raw = _read_regular(path, label, _MAX_JSON_BYTES)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceIntegrityError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicates)
    except EvidenceIntegrityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceIntegrityError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise EvidenceIntegrityError(f"{label} must be a JSON object")
    return payload


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise EvidenceIntegrityError(f"{label} is missing, unsafe, or not a regular file")
    size = candidate.stat().st_size
    if size > maximum:
        raise EvidenceIntegrityError(f"{label} exceeds the size limit")
    return candidate.read_bytes()


def _write_exclusive(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
        path.chmod(0o600)
    except FileExistsError as exc:
        raise ReportAlreadyExistsError(f"refusing to replace report evidence: {path}") from exc


def _raw_file_digest(path: Path) -> str:
    return hashlib.sha256(
        _read_regular(path, f"evidence file {path.name}", _MAX_ROW_FILE_BYTES)
    ).hexdigest()


def _prefixed_file_digest(path: Path) -> str:
    return "sha256:" + _raw_file_digest(path)


def _optional_prefixed_file_digest(path: Path) -> str | None:
    if path.is_symlink():
        raise EvidenceIntegrityError(f"optional evidence file is a symlink: {path.name}")
    if not path.exists():
        return None
    return _prefixed_file_digest(path)


def _prefixed_document_digest(
    payload: Mapping[str, object],
    *,
    label: str,
) -> str:
    declared = _digest(payload.get("document_sha256"), f"{label} document digest")
    body = {key: value for key, value in payload.items() if key != "document_sha256"}
    try:
        encoded = json.dumps(
            body,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceIntegrityError(f"{label} is not canonical JSON") from exc
    actual = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if declared != actual:
        raise EvidenceIntegrityError(f"{label} document digest does not reproduce")
    return actual


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _money(value: object, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise EvidenceIntegrityError(f"{label} must be a canonical non-negative decimal")
    try:
        decimal = Decimal(str(value))
    except InvalidOperation as exc:
        raise EvidenceIntegrityError(f"{label} must be a canonical non-negative decimal") from exc
    if not decimal.is_finite() or decimal < 0:
        raise EvidenceIntegrityError(f"{label} must be a canonical non-negative decimal")
    try:
        return decimal_text(decimal)
    except ValueError as exc:
        raise EvidenceIntegrityError(f"{label} is outside the supported decimal range") from exc


def _row_limits_json(row_budget: Mapping[str, object]) -> dict[str, object]:
    return {
        "wall_seconds": row_budget["wall_seconds"],
        "max_model_requests": row_budget["max_model_requests"],
        "max_target_requests": row_budget["max_target_requests"],
        "max_cost_usd": _money(row_budget["max_cost_usd"], "row cost cap"),
    }


def _bound_external_directory(
    value: object,
    *,
    campaign_root: Path,
    label: str,
) -> Path:
    if not isinstance(value, str) or not value:
        raise EvidenceIntegrityError(f"{label} path is invalid")
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise EvidenceIntegrityError(f"{label} path is not canonical")
    try:
        resolved = candidate.resolve(strict=True)
        root = campaign_root.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise EvidenceIntegrityError(f"{label} escaped the campaign evidence root") from exc
    if candidate != resolved or not resolved.is_dir():
        raise EvidenceIntegrityError(f"{label} is not a canonical regular directory")
    return resolved


def _bound_external_file(
    value: object,
    *,
    campaign_root: Path,
    expected_name: str,
    label: str,
) -> Path:
    if not isinstance(value, str) or not value:
        raise EvidenceIntegrityError(f"{label} path is invalid")
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise EvidenceIntegrityError(f"{label} path is not canonical")
    try:
        resolved = candidate.resolve(strict=True)
        root = campaign_root.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise EvidenceIntegrityError(f"{label} escaped the campaign evidence root") from exc
    if candidate != resolved or resolved.name != expected_name or not resolved.is_file():
        raise EvidenceIntegrityError(f"{label} is not the exact retained evidence file")
    return resolved


def _require_unique_file_location(
    root: Path,
    *,
    expected: Path,
    basename: str,
    label: str,
) -> None:
    matches = [path for path in root.rglob(basename) if path.is_file() or path.is_symlink()]
    if matches != [expected]:
        raise EvidenceIntegrityError(f"{label} path is missing, duplicated, or substituted")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise EvidenceIntegrityError(f"{label} is not a canonical SHA256 digest")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceIntegrityError(f"{label} must be a non-empty string")
    return value


def _expected_flag(value: object, *, slot_id: str) -> str:
    if not isinstance(value, str) or _EXPECTED_FLAG_RE.fullmatch(value) is None:
        raise EvidenceIntegrityError(f"row {slot_id} expected flag is missing or invalid")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceIntegrityError(f"{label} must be a non-negative integer")
    return value


def _finite_nonnegative(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceIntegrityError(f"{label} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise EvidenceIntegrityError(f"{label} must be a finite non-negative number")
    return result


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PairedXbenReportError("generated_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PairedXbenReportError("generated_at must include a UTC offset")
    return parsed.isoformat()


__all__ = [
    "REPORT_SCHEMA",
    "EvidenceIntegrityError",
    "IncompleteCampaignError",
    "PairedXbenReportError",
    "ReportAlreadyExistsError",
    "aggregate_campaign",
    "canonical_json_bytes",
    "exact_two_sided_mcnemar_p_value",
    "write_report",
]
