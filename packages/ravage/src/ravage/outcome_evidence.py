from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urljoin, urlsplit
from uuid import UUID, uuid5

from ravage.agent_core.surface_graph import SurfaceGraphError, canonical_operation_url
from ravage.finding_evidence import confirmed_finding_evidence_failures
from ravage.traffic.redaction import REDACTED_URL, sanitize_url
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
    from pathlib import Path

OUTCOME_EVIDENCE_SCHEMA_VERSION = 1


class OutcomeStage(StrEnum):
    NONE = "none"
    SUSPECTED_VULNERABILITY = "suspected_vulnerability"
    VERIFIED_VULNERABILITY = "verified_vulnerability"
    EXPLOIT_PRIMITIVE = "exploit_primitive"
    FLAG_CAPTURED = "flag_captured"


_STAGE_RANK = {
    OutcomeStage.NONE: 0,
    OutcomeStage.SUSPECTED_VULNERABILITY: 1,
    OutcomeStage.VERIFIED_VULNERABILITY: 2,
    OutcomeStage.EXPLOIT_PRIMITIVE: 3,
    OutcomeStage.FLAG_CAPTURED: 4,
}


def outcome_stage_rank(stage: OutcomeStage | str) -> int:
    try:
        resolved = OutcomeStage(stage)
    except ValueError:
        return 0
    return _STAGE_RANK[resolved]


@dataclass(frozen=True)
class ProbeFindingContract:
    finding_type: str
    probes: tuple[str, ...]
    vuln_class: str
    stage: OutcomeStage
    severity: str
    hypothesis: str
    impact: str
    request_keys: tuple[str, ...] = ("replay",)
    response_keys: tuple[str, ...] = ("response",)
    indicator_keys: tuple[str, ...] = ("signal", "indicator")
    control_keys: tuple[str, ...] = ()
    require_request: bool = True
    require_response: bool = True
    require_control: bool = False
    promotion_kind: str = "native"


@dataclass(frozen=True)
class QualifiedProbeFinding:
    contract: ProbeFindingContract
    probe: str
    finding_type: str
    endpoint: dict[str, object]
    request: dict[str, object]
    response: dict[str, object]
    indicator: dict[str, object]
    controls: tuple[dict[str, object], ...]
    stage: OutcomeStage
    promotable: bool
    missing_evidence: tuple[str, ...]
    contract_status: str = "registered"
    vuln_class_source: str = "registry"

    def finding_id(self, engagement_id: UUID) -> str:
        identity_parts: dict[str, object] = {
            "vuln_class": self.contract.vuln_class,
            "endpoint": self.endpoint,
        }
        affected_parameter = _affected_parameter(self.request)
        if affected_parameter:
            identity_parts["affected_parameters"] = [affected_parameter]
        identity = json.dumps(
            identity_parts,
            sort_keys=True,
            separators=(",", ":"),
        )
        return str(uuid5(engagement_id, identity))

    def evidence_id(self, engagement_id: UUID) -> str:
        identity_parts: dict[str, object] = {
            "finding_type": self.finding_type,
            "probe": self.probe,
            "endpoint": self.endpoint,
        }
        affected_parameter = _affected_parameter(self.request)
        if affected_parameter:
            identity_parts["affected_parameters"] = [affected_parameter]
        identity = json.dumps(
            identity_parts,
            sort_keys=True,
            separators=(",", ":"),
        )
        return str(uuid5(engagement_id, f"outcome-evidence:{identity}"))


@dataclass(frozen=True)
class RunOutcomeSummary:
    stage: OutcomeStage = OutcomeStage.NONE
    evidence_count: int = 0
    confirmed_finding_count: int = 0
    suspected_vulnerability_count: int = 0
    verified_vulnerability_count: int = 0
    exploit_primitive_count: int = 0
    vulnerability_classes: tuple[str, ...] = ()
    evidence: tuple[dict[str, object], ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "stage": self.stage.value,
            "stage_rank": outcome_stage_rank(self.stage),
            "evidence_count": self.evidence_count,
            "confirmed_finding_count": self.confirmed_finding_count,
            "suspected_vulnerability_count": self.suspected_vulnerability_count,
            "verified_vulnerability_count": self.verified_vulnerability_count,
            "exploit_primitive_count": self.exploit_primitive_count,
            "vulnerability_classes": list(self.vulnerability_classes),
            "evidence": list(self.evidence),
        }


_COMMAND_HYPOTHESIS = "Attacker-controlled input crosses an operating-system command boundary."
_COMMAND_IMPACT = (
    "The affected request can execute attacker-influenced operating-system commands in the "
    "application process context."
)
_SQL_HYPOTHESIS = "Attacker-controlled input changes database-query execution."
_SQL_IMPACT = (
    "The injectable query path can expose or modify data available to the application database "
    "identity, depending on query context and permissions."
)
_FILE_HYPOTHESIS = "Attacker-controlled input causes the server to read a local file."
_FILE_IMPACT = "The affected endpoint can disclose local files readable by the application process."
_SSTI_HYPOTHESIS = "Attacker-controlled input is evaluated by a server-side template engine."
_SSTI_IMPACT = (
    "Template evaluation can expose application data or enable deeper server compromise, depending "
    "on the engine and sandbox."
)
_SSRF_HYPOTHESIS = "Attacker-controlled input changes a server-side outbound request destination."
_SSRF_IMPACT = (
    "The affected endpoint can reach destinations from the server network context, including "
    "otherwise inaccessible internal services."
)
_IDOR_HYPOTHESIS = "Changing an object identifier crosses an authorization boundary."
_IDOR_IMPACT = "A user can access another principal's object without the required authorization."
_XXE_HYPOTHESIS = "The XML parser resolves an attacker-controlled external entity to a local file."
_XXE_IMPACT = "External entity resolution can disclose local files available to the parser process."
_XSS_HYPOTHESIS = "User-controlled input executes JavaScript in a browser context."
_XSS_IMPACT = (
    "An attacker can execute JavaScript in an affected user's browser in the application origin."
)
_REGISTERED_CONTRACT_STATUS = "registered"
_MISSING_CONTRACT_STATUS = "contract_missing"
_MISSING_CONTRACT_EVIDENCE = "finding_contract"
_UNKNOWN_FINDING_TYPE = "unclassified_probe_finding"
_UNKNOWN_VULN_CLASS = "unclassified"
_UNKNOWN_HYPOTHESIS = (
    "A native probe returned a structured security observation whose finding contract is not "
    "registered."
)
_UNKNOWN_IMPACT = (
    "The observation is retained for review, but impact is not established until a class-specific "
    "validator contract is registered and satisfied."
)
_IDENTIFIER_EXTRA = frozenset("_")
_REFERENCE_EXTRA = frozenset("-_:.")
_MIN_IDENTIFIER_LENGTH = 2
_MAX_IDENTIFIER_LENGTH = 80
_MAX_REFERENCE_LENGTH = 160
_MAX_INPUT_NAME_LENGTH = 120
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


def _safe_identifier(value: object) -> str:
    text = str(value or "").strip().lower()
    if (
        not _MIN_IDENTIFIER_LENGTH <= len(text) <= _MAX_IDENTIFIER_LENGTH
        or not text[0].isalpha()
        or not text[0].isascii()
    ):
        return ""
    if any(
        not (character.isascii() and (character.isalnum() or character in _IDENTIFIER_EXTRA))
        for character in text
    ):
        return ""
    return text


def _safe_reference(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > _MAX_REFERENCE_LENGTH:
        return ""
    if any(
        not (character.isascii() and (character.isalnum() or character in _REFERENCE_EXTRA))
        for character in text
    ):
        return ""
    return text


def _contract(  # noqa: PLR0913
    finding_type: str,
    probes: tuple[str, ...],
    vuln_class: str,
    stage: OutcomeStage,
    severity: str,
    *,
    hypothesis: str,
    impact: str,
    request_keys: tuple[str, ...] = ("replay",),
    response_keys: tuple[str, ...] = ("response",),
    indicator_keys: tuple[str, ...] = ("signal", "indicator"),
    control_keys: tuple[str, ...] = (),
    require_request: bool = True,
    require_response: bool = True,
    require_control: bool = False,
    promotion_kind: str = "native",
) -> ProbeFindingContract:
    return ProbeFindingContract(
        finding_type=finding_type,
        probes=probes,
        vuln_class=vuln_class,
        stage=stage,
        severity=severity,
        hypothesis=hypothesis,
        impact=impact,
        request_keys=request_keys,
        response_keys=response_keys,
        indicator_keys=indicator_keys,
        control_keys=control_keys,
        require_request=require_request,
        require_response=require_response,
        require_control=require_control,
        promotion_kind=promotion_kind,
    )


def _build_contract_registry(
    contracts: Iterable[ProbeFindingContract],
) -> dict[str, ProbeFindingContract]:
    registry: dict[str, ProbeFindingContract] = {}
    for contract in contracts:
        if not _safe_identifier(contract.finding_type):
            msg = f"invalid native finding contract type: {contract.finding_type!r}"
            raise ValueError(msg)
        if not _safe_identifier(contract.vuln_class):
            msg = f"invalid native finding vulnerability class: {contract.vuln_class!r}"
            raise ValueError(msg)
        if not contract.probes or any(not _safe_identifier(probe) for probe in contract.probes):
            msg = f"invalid native finding contract probes: {contract.probes!r}"
            raise ValueError(msg)
        if contract.finding_type in registry:
            msg = f"duplicate native finding contract type: {contract.finding_type}"
            raise ValueError(msg)
        registry[contract.finding_type] = contract
    return registry


_REGISTERED_CONTRACTS = (
    _contract(
        "client_side_execution",
        ("dom_execution",),
        "xss",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "Medium",
        hypothesis=_XSS_HYPOTHESIS,
        impact=_XSS_IMPACT,
        request_keys=("request_template",),
        response_keys=("evidence",),
        indicator_keys=("evidence",),
        promotion_kind="dom",
    ),
    _contract(
        "file_read_primitive",
        ("file_fetch_parser", "file_read_extract"),
        "path_traversal",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_FILE_HYPOTHESIS,
        impact=_FILE_IMPACT,
        control_keys=("control_response", "delta"),
    ),
    _contract(
        "file_read_extracted_content",
        ("file_fetch_parser", "file_read_extract"),
        "path_traversal",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_FILE_HYPOTHESIS,
        impact=_FILE_IMPACT,
        indicator_keys=("matches", "primitive"),
    ),
    _contract(
        "file_read_extracted_proof",
        ("file_fetch_parser", "file_read_extract"),
        "path_traversal",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_FILE_HYPOTHESIS,
        impact=_FILE_IMPACT,
        indicator_keys=("proofs",),
    ),
    _contract(
        "php_include_execution",
        ("file_fetch_parser", "file_read_extract"),
        "path_traversal",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "Critical",
        hypothesis="Attacker-controlled include input causes server-side PHP execution.",
        impact=(
            "The affected include path can execute attacker-influenced PHP in the "
            "application process."
        ),
        indicator_keys=("verification_token",),
    ),
    _contract(
        "php_include_extracted_proof",
        ("file_fetch_parser", "file_read_extract"),
        "path_traversal",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "Critical",
        hypothesis="Attacker-controlled include input causes server-side PHP execution.",
        impact=(
            "The affected include path can execute attacker-influenced PHP in the "
            "application process."
        ),
        indicator_keys=("proofs",),
    ),
    _contract(
        "ssti_engine_execution",
        ("ssti_fingerprint",),
        "ssti",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_SSTI_HYPOTHESIS,
        impact=_SSTI_IMPACT,
        indicator_keys=("signal", "oracle"),
    ),
    _contract(
        "ssti_extracted_proof",
        ("ssti_fingerprint",),
        "ssti",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_SSTI_HYPOTHESIS,
        impact=_SSTI_IMPACT,
        indicator_keys=("proofs",),
    ),
    _contract(
        "ssti_fingerprint_signal",
        ("ssti_fingerprint",),
        "ssti",
        OutcomeStage.VERIFIED_VULNERABILITY,
        "High",
        hypothesis=_SSTI_HYPOTHESIS,
        impact=_SSTI_IMPACT,
        control_keys=("baseline_replay", "delta"),
    ),
    _contract(
        "apache_traversal_file_read_signal",
        ("command_boundary",),
        "path_traversal",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_FILE_HYPOTHESIS,
        impact=_FILE_IMPACT,
        request_keys=("url",),
        indicator_keys=("expected",),
        control_keys=("control_response",),
        require_control=True,
    ),
    _contract(
        "command_boundary_signal",
        ("command_boundary",),
        "command_injection",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "Critical",
        hypothesis=_COMMAND_HYPOTHESIS,
        impact=_COMMAND_IMPACT,
        request_keys=("replay", "url"),
        indicator_keys=("expected", "delta"),
    ),
    _contract(
        "command_boundary_timing_signal",
        ("command_boundary",),
        "command_injection",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "Critical",
        hypothesis=_COMMAND_HYPOTHESIS,
        impact=_COMMAND_IMPACT,
        request_keys=("replay", "url"),
        indicator_keys=("elapsed_delta_ms",),
        control_keys=("control_response",),
        require_control=True,
    ),
    _contract(
        "sql_injection_error_signal",
        ("sqli_differential",),
        "sql_injection",
        OutcomeStage.VERIFIED_VULNERABILITY,
        "High",
        hypothesis=_SQL_HYPOTHESIS,
        impact=_SQL_IMPACT,
        indicator_keys=("markers", "delta"),
        control_keys=("baseline_replay",),
        require_control=True,
    ),
    _contract(
        "blind_sql_injection_boolean_signal",
        ("sqli_differential",),
        "sql_injection",
        OutcomeStage.VERIFIED_VULNERABILITY,
        "High",
        hypothesis=_SQL_HYPOTHESIS,
        impact=_SQL_IMPACT,
        request_keys=("true_replay",),
        response_keys=("true_response",),
        indicator_keys=("pair_delta", "indicator"),
        control_keys=("false_replay", "false_response"),
        require_control=True,
    ),
    _contract(
        "blind_sql_injection_timing_signal",
        ("sqli_differential",),
        "sql_injection",
        OutcomeStage.VERIFIED_VULNERABILITY,
        "High",
        hypothesis=_SQL_HYPOTHESIS,
        impact=_SQL_IMPACT,
        indicator_keys=("elapsed_delta_ms", "indicator"),
        response_keys=("response",),
        require_response=False,
        control_keys=("baseline_elapsed_ms",),
        require_control=True,
    ),
    _contract(
        "ssrf_boundary_signal",
        ("ssrf_boundary",),
        "ssrf",
        OutcomeStage.VERIFIED_VULNERABILITY,
        "High",
        hypothesis=_SSRF_HYPOTHESIS,
        impact=_SSRF_IMPACT,
        control_keys=("baseline_replay",),
        require_control=True,
    ),
    _contract(
        "idor_boundary_signal",
        ("idor_boundary",),
        "idor",
        OutcomeStage.VERIFIED_VULNERABILITY,
        "High",
        hypothesis=_IDOR_HYPOTHESIS,
        impact=_IDOR_IMPACT,
        control_keys=("baseline_replay", "baseline"),
        require_control=True,
    ),
    _contract(
        "idor_boundary_exposed_secret",
        ("idor_boundary",),
        "idor",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_IDOR_HYPOTHESIS,
        impact=_IDOR_IMPACT,
        indicator_keys=("signal", "matches"),
        control_keys=("baseline_replay", "baseline"),
        require_control=True,
    ),
    _contract(
        "idor_boundary_followup_signal",
        ("idor_boundary",),
        "idor",
        OutcomeStage.VERIFIED_VULNERABILITY,
        "High",
        hypothesis=_IDOR_HYPOTHESIS,
        impact=_IDOR_IMPACT,
        control_keys=("source_response",),
        require_control=True,
    ),
    _contract(
        "idor_boundary_followup_exposed_secret",
        ("idor_boundary",),
        "idor",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_IDOR_HYPOTHESIS,
        impact=_IDOR_IMPACT,
        indicator_keys=("signal", "matches"),
        control_keys=("source_response",),
        require_control=True,
    ),
    _contract(
        "xxe_file_read_signal",
        ("xxe_boundary",),
        "xxe",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_XXE_HYPOTHESIS,
        impact=_XXE_IMPACT,
        request_keys=("replay",),
        indicator_keys=("markers",),
        require_request=False,
    ),
    _contract(
        "xxe_extracted_proof",
        ("xxe_boundary",),
        "xxe",
        OutcomeStage.EXPLOIT_PRIMITIVE,
        "High",
        hypothesis=_XXE_HYPOTHESIS,
        impact=_XXE_IMPACT,
        indicator_keys=("proofs",),
    ),
)
_CONTRACTS = _build_contract_registry(_REGISTERED_CONTRACTS)


def _unregistered_contract(
    *,
    probe: str,
    finding_type: str,
    finding: Mapping[str, object],
) -> tuple[ProbeFindingContract, str]:
    safe_probe = _safe_identifier(probe) or "unknown_probe"
    safe_type = _safe_identifier(finding_type) or _UNKNOWN_FINDING_TYPE
    explicit_class = _safe_identifier(finding.get("vuln_class"))
    vuln_class = explicit_class or safe_probe or _UNKNOWN_VULN_CLASS
    vuln_class_source = "finding" if explicit_class else "probe"
    return (
        ProbeFindingContract(
            finding_type=safe_type,
            probes=(safe_probe,),
            vuln_class=vuln_class,
            stage=OutcomeStage.SUSPECTED_VULNERABILITY,
            severity="Informational",
            hypothesis=_UNKNOWN_HYPOTHESIS,
            impact=_UNKNOWN_IMPACT,
            request_keys=(
                "replay",
                "request_template",
                "request",
                "true_replay",
                "url",
                "replay_url",
                "followup_url",
                "final_url",
            ),
            response_keys=(
                "response",
                "true_response",
                "second",
                "first",
                "preflight",
                "evidence",
            ),
            indicator_keys=(
                "signal",
                "indicator",
                "detail",
                "matches",
                "proofs",
                "delta",
                "expected",
                "missing",
                "authenticated",
                "accepted",
            ),
            control_keys=("baseline_replay", "baseline", "control_response"),
            require_request=False,
            require_response=False,
            promotion_kind="contract_missing",
        ),
        vuln_class_source,
    )


def qualify_probe_findings(
    *,
    probe: str,
    probe_text: str,
    target_url: str,
) -> tuple[QualifiedProbeFinding, ...]:
    payload = _json_object(probe_text)
    if payload.get("ok") is not True or str(payload.get("probe") or "") != probe:
        return ()
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        return ()
    qualified: list[QualifiedProbeFinding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        finding = {str(key): value for key, value in raw.items()}
        finding_type = str(finding.get("type") or "").strip()
        contract = _CONTRACTS.get(finding_type)
        contract_status = _REGISTERED_CONTRACT_STATUS
        vuln_class_source = "registry"
        if contract is None or probe not in contract.probes:
            contract, vuln_class_source = _unregistered_contract(
                probe=probe,
                finding_type=finding_type,
                finding=finding,
            )
            contract_status = _MISSING_CONTRACT_STATUS
        item = _qualify_finding(
            contract,
            probe=probe,
            finding=finding,
            target_url=target_url,
            contract_status=contract_status,
            vuln_class_source=vuln_class_source,
        )
        qualified.append(item)
    return tuple(qualified)


def _qualify_finding(  # noqa: C901, PLR0913
    contract: ProbeFindingContract,
    *,
    probe: str,
    finding: dict[str, object],
    target_url: str,
    contract_status: str = _REGISTERED_CONTRACT_STATUS,
    vuln_class_source: str = "registry",
) -> QualifiedProbeFinding:
    request = _first_request(finding, contract.request_keys, target_url=target_url)
    if not request and contract_status == _MISSING_CONTRACT_STATUS:
        request = _unregistered_request_summary(finding, target_url=target_url)
    if contract.promotion_kind == "dom" and request:
        raw_request = finding.get("request_template")
        raw_request_map = raw_request if isinstance(raw_request, dict) else {}
        payload_field = str(raw_request_map.get("payload_field") or "").strip()[:120]
        method = str(request.get("method") or "GET").upper()
        request["params"] = (
            [
                {
                    "name": payload_field,
                    "location": "body" if method == "POST" else "query",
                }
            ]
            if payload_field
            else []
        )
    response = _first_response(finding, contract.response_keys, target_url=target_url)
    if not request and response and not contract.require_request:
        request = _request_from_response(response)
    endpoint = _endpoint(request=request, response=response, target_url=target_url)
    indicator = _indicator_summary(finding, contract.indicator_keys)
    controls = tuple(
        summary
        for key in contract.control_keys
        if (summary := _control_summary(key, finding.get(key), target_url=target_url))
    )
    missing: list[str] = []
    if contract_status == _MISSING_CONTRACT_STATUS:
        missing.append(_MISSING_CONTRACT_EVIDENCE)
    if contract.require_request and not request:
        missing.append("request_template")
    if contract.require_response and not response:
        missing.append("response_summary")
    if not indicator:
        missing.append("class_specific_indicator")
    if contract.require_control and not controls:
        missing.append("control_evidence")
    if not str(endpoint.get("url") or ""):
        missing.append("endpoint_url")
    if contract.finding_type == "ssti_fingerprint_signal" and not _evaluated_ssti(finding):
        missing.append("evaluated_expression")
    if contract.finding_type == "client_side_execution" and not _browser_execution(finding):
        missing.append("browser_execution")
    missing = list(dict.fromkeys(missing))
    promotable = not missing
    return QualifiedProbeFinding(
        contract=contract,
        probe=probe,
        finding_type=contract.finding_type,
        endpoint=endpoint,
        request=request,
        response=response,
        indicator=indicator,
        controls=controls,
        stage=contract.stage if promotable else OutcomeStage.SUSPECTED_VULNERABILITY,
        promotable=promotable,
        missing_evidence=tuple(missing),
        contract_status=contract_status,
        vuln_class_source=vuln_class_source,
    )


def outcome_evidence_payload(  # noqa: PLR0913
    qualified: QualifiedProbeFinding,
    *,
    engagement_id: UUID,
    source_observation_id: str,
    action_id: str,
    confirmed: bool,
    forced_stage: OutcomeStage | None = None,
) -> dict[str, object]:
    contract_missing = qualified.contract_status == _MISSING_CONTRACT_STATUS
    stage = (
        OutcomeStage.SUSPECTED_VULNERABILITY
        if contract_missing
        else forced_stage or qualified.stage
    )
    confirmed_finding = confirmed and not contract_missing
    missing_evidence = list(qualified.missing_evidence)
    if contract_missing and _MISSING_CONTRACT_EVIDENCE not in missing_evidence:
        missing_evidence.insert(0, _MISSING_CONTRACT_EVIDENCE)
    evidence_kind = (
        "native_probe_contract_missing" if contract_missing else "native_probe_validation"
    )
    payload: dict[str, object] = {
        "schema_version": OUTCOME_EVIDENCE_SCHEMA_VERSION,
        "evidence_id": qualified.evidence_id(engagement_id),
        "finding_id": qualified.finding_id(engagement_id),
        "engagement_id": str(engagement_id),
        "stage": stage.value,
        "stage_rank": outcome_stage_rank(stage),
        "vuln_class": qualified.contract.vuln_class,
        "finding_type": qualified.finding_type,
        "probe": qualified.probe,
        "endpoint": qualified.endpoint,
        "input": _input_identity(qualified.request, qualified.endpoint),
        "confirmed_finding": confirmed_finding,
        "contract_status": qualified.contract_status,
        "vuln_class_source": qualified.vuln_class_source,
        "evidence_checks": {
            "passed": 0 if stage is OutcomeStage.SUSPECTED_VULNERABILITY else 1,
            "required": 1,
        },
        "missing_evidence": missing_evidence,
        "source_kind": "tool_run_probe",
        "source_observation_id": source_observation_id,
        "action_id": action_id,
        "provenance": {
            "evidence_kind": evidence_kind,
            "source_kind": "tool_run_probe",
            "source_observation_id": source_observation_id,
            "action_id": action_id,
            "probe": qualified.probe,
            "finding_type": qualified.finding_type,
            "assessment_source": "executor_policy",
            "model_claims_used": False,
        },
    }
    return payload


def native_confirmed_finding_payload(
    qualified: QualifiedProbeFinding,
    *,
    engagement_id: UUID,
    source_observation_id: str,
    action_id: str,
    finding_record_path: str,
) -> dict[str, object]:
    if qualified.contract_status != _REGISTERED_CONTRACT_STATUS:
        msg = "unregistered native finding types cannot be promoted to confirmed findings"
        raise ValueError(msg)
    exploit_steps: list[dict[str, str]] = [
        {
            "evidence_role": "control",
            "http_request": _bounded_json(control.get("request") or qualified.request),
            "response_snippet": _bounded_json(control.get("response") or control),
            "indicator": "executor-owned native probe control",
        }
        for control in qualified.controls
    ]
    exploit_steps.append(
        {
            "evidence_role": "exploit",
            "http_request": _bounded_json(qualified.request),
            "response_snippet": _bounded_json(qualified.response),
            "indicator": _bounded_json(qualified.indicator),
        }
    )
    return {
        "finding_id": qualified.finding_id(engagement_id),
        "engagement_id": str(engagement_id),
        "vuln_class": qualified.contract.vuln_class,
        "severity": qualified.contract.severity,
        "hypothesis": qualified.contract.hypothesis,
        "impact": qualified.contract.impact,
        "assessment_source": "executor_policy",
        "endpoint": qualified.endpoint,
        "input": _input_identity(qualified.request, qualified.endpoint),
        "exploit_steps": exploit_steps,
        "proof": {
            "http_request_final": _bounded_json(qualified.request),
            "response_final": _bounded_json(
                {
                    "response": qualified.response,
                    "indicator": qualified.indicator,
                }
            ),
            "impact_description": qualified.contract.impact,
        },
        "status": "confirmed",
        "validator_vote": "confirm",
        "evidence_checks": {"passed": 1, "required": 1},
        "evidence_kind": "native_probe_validation",
        "outcome_stage": qualified.contract.stage.value,
        "source_kind": "tool_run_probe",
        "source_observation_id": source_observation_id,
        "action_id": action_id,
        "finding_record_path": finding_record_path,
        "provenance": {
            "evidence_kind": "native_probe_validation",
            "source_kind": "tool_run_probe",
            "source_observation_id": source_observation_id,
            "action_id": action_id,
            "probe": qualified.probe,
            "finding_type": qualified.finding_type,
            "assessment_source": "executor_policy",
            "model_claims_used": False,
        },
    }


def summarize_run_outcome(
    records: Iterable[tuple[str, Mapping[str, object]]],
    *,
    expected_flag: str = "",
) -> RunOutcomeSummary:
    materialized = tuple((kind, dict(payload)) for kind, payload in records)
    observations = _tool_observations(materialized)
    evidence_by_id: dict[str, dict[str, object]] = {}
    confirmed_ids: set[str] = set()
    confirmed_payloads: dict[str, dict[str, object]] = {}
    captured_flags = validated_captured_flags(
        materialized,
        expected_flag=expected_flag,
    )

    for kind, payload in materialized:
        if kind == "outcome_evidence_observed" and _valid_outcome_event(payload, observations):
            evidence_id = str(payload.get("evidence_id") or "")
            current = evidence_by_id.get(evidence_id)
            candidate_rank = outcome_stage_rank(str(payload.get("stage") or ""))
            current_rank = outcome_stage_rank(str(current.get("stage") or "")) if current else -1
            if current is None or candidate_rank > current_rank:
                evidence_by_id[evidence_id] = _public_evidence(payload)
        elif kind == "finding_confirmed" and _valid_confirmed_finding(payload, observations):
            finding_id = str(payload.get("finding_id") or "")
            if finding_id:
                confirmed_ids.add(finding_id)
                confirmed_payloads[finding_id] = dict(payload)
    evidenced_finding_ids = {
        str(payload.get("finding_id") or "") for payload in evidence_by_id.values()
    }
    for finding_id, payload in confirmed_payloads.items():
        if finding_id in evidenced_finding_ids:
            continue
        inferred = _confirmed_finding_evidence(payload)
        evidence_by_id[str(inferred["evidence_id"])] = inferred

    stage = OutcomeStage.FLAG_CAPTURED if captured_flags else OutcomeStage.NONE
    for payload in evidence_by_id.values():
        candidate = _outcome_stage(payload.get("stage"))
        if outcome_stage_rank(candidate) > outcome_stage_rank(stage):
            stage = candidate

    evidence = tuple(
        sorted(
            evidence_by_id.values(),
            key=lambda item: (
                -outcome_stage_rank(str(item.get("stage") or "")),
                str(item.get("vuln_class") or ""),
                str(item.get("endpoint_url") or ""),
            ),
        )
    )
    classes = tuple(
        sorted(
            {
                str(payload.get("vuln_class") or "")
                for payload in evidence
                if str(payload.get("vuln_class") or "")
            }
        )
    )
    return RunOutcomeSummary(
        stage=stage,
        evidence_count=len(evidence),
        confirmed_finding_count=len(confirmed_ids),
        suspected_vulnerability_count=sum(
            item.get("stage") == OutcomeStage.SUSPECTED_VULNERABILITY.value for item in evidence
        ),
        verified_vulnerability_count=sum(
            item.get("stage") == OutcomeStage.VERIFIED_VULNERABILITY.value for item in evidence
        ),
        exploit_primitive_count=sum(
            item.get("stage") == OutcomeStage.EXPLOIT_PRIMITIVE.value for item in evidence
        ),
        vulnerability_classes=classes,
        evidence=evidence,
    )


def load_run_outcome(
    *,
    db_path: Path | None,
    workspace_path: Path,
    engagement_id: UUID | str | None = None,
    expected_flag: str = "",
) -> RunOutcomeSummary:
    records = [
        *_workspace_records(workspace_path, engagement_id=engagement_id),
        *_audit_records(db_path, engagement_id),
    ]
    return summarize_run_outcome(records, expected_flag=expected_flag)


def validated_captured_flags(
    records: Iterable[tuple[str, Mapping[str, object]]],
    *,
    expected_flag: str = "",
    engagement_id: UUID | str | None = None,
) -> list[str]:
    """Return unique proof strings backed by executor-owned observation provenance."""
    materialized = tuple(
        (kind, dict(payload))
        for kind, payload in records
        if engagement_id is None
        or not str(payload.get("engagement_id") or "")
        or str(payload.get("engagement_id")) == str(engagement_id)
    )
    observations = _tool_observations(materialized)
    flags: list[str] = []
    for kind, payload in materialized:
        if kind != "flag_captured" or not _valid_flag_event(
            payload,
            observations,
            expected_flag=expected_flag,
        ):
            continue
        flag = str(payload.get("flag") or "").strip()
        if flag and flag not in flags:
            flags.append(flag)
    return flags


def load_validated_captured_flags(
    *,
    db_path: Path | None,
    workspace_path: Path,
    engagement_id: UUID | str | None = None,
    expected_flag: str = "",
) -> list[str]:
    """Load and validate captured proof events from canonical run evidence streams."""
    records = [
        *_workspace_records(workspace_path, engagement_id=engagement_id),
        *_audit_records(db_path, engagement_id),
    ]
    return validated_captured_flags(
        records,
        expected_flag=expected_flag,
        engagement_id=engagement_id,
    )


def _tool_observations(
    records: Sequence[tuple[str, Mapping[str, object]]],
) -> dict[str, dict[str, object]]:
    observations: dict[str, dict[str, object]] = {}
    for kind, payload in records:
        if not kind.startswith("tool_"):
            continue
        observation_id = str(payload.get("observation_id") or "").strip()
        if observation_id:
            observations[observation_id] = dict(payload) | {"__source_kind": kind}
    return observations


def _valid_outcome_event(  # noqa: C901, PLR0911, PLR0912
    payload: Mapping[str, object],
    observations: Mapping[str, Mapping[str, object]],
) -> bool:
    if payload.get("schema_version") != OUTCOME_EVIDENCE_SCHEMA_VERSION:
        return False
    evidence_id = str(payload.get("evidence_id") or "").strip()
    finding_type = str(payload.get("finding_type") or "").strip()
    probe = str(payload.get("probe") or "").strip()
    contract = _CONTRACTS.get(finding_type)
    stage = _outcome_stage(payload.get("stage"))
    contract_status = str(payload.get("contract_status") or _REGISTERED_CONTRACT_STATUS).strip()
    if not evidence_id:
        return False
    if contract_status == _MISSING_CONTRACT_STATUS:
        if (
            stage is not OutcomeStage.SUSPECTED_VULNERABILITY
            or payload.get("confirmed_finding") is True
            or _MISSING_CONTRACT_EVIDENCE not in _string_list(payload.get("missing_evidence"))
            or not _safe_identifier(finding_type)
            or not _safe_identifier(probe)
            or not _safe_identifier(payload.get("vuln_class"))
            or not _valid_missing_contract_provenance(payload)
        ):
            return False
    elif contract_status == _REGISTERED_CONTRACT_STATUS:
        if contract is None or probe not in contract.probes:
            return False
        if stage not in {OutcomeStage.SUSPECTED_VULNERABILITY, contract.stage}:
            return False
    else:
        return False
    if payload.get("source_kind") != "tool_run_probe":
        return False
    observation = observations.get(str(payload.get("source_observation_id") or ""))
    if observation is None:
        return False
    if observation.get("__source_kind") != "tool_run_probe":
        return False
    if payload.get("action_id") and observation.get("action_id") != payload.get("action_id"):
        return False
    display = observation.get("display_summary")
    if not isinstance(display, dict) or display.get("probe") != probe:
        return False
    if contract_status == _MISSING_CONTRACT_STATUS:
        finding_count = display.get("findings")
        return (
            isinstance(finding_count, int)
            and not isinstance(finding_count, bool)
            and finding_count > 0
        )
    return True


def _valid_missing_contract_provenance(payload: Mapping[str, object]) -> bool:
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        return False
    return (
        provenance.get("evidence_kind") == "native_probe_contract_missing"
        and provenance.get("source_kind") == "tool_run_probe"
        and provenance.get("probe") == payload.get("probe")
        and provenance.get("finding_type") == payload.get("finding_type")
        and provenance.get("model_claims_used") is False
    )


def _valid_confirmed_finding(
    payload: Mapping[str, object],
    observations: Mapping[str, Mapping[str, object]],
) -> bool:
    finding = dict(payload)
    if finding.get("status") != "confirmed" or confirmed_finding_evidence_failures(finding):
        return False
    source_kind = str(finding.get("source_kind") or "")
    if not source_kind.startswith("tool_"):
        return False
    observation = observations.get(str(finding.get("source_observation_id") or ""))
    if observation is None:
        return False
    if observation.get("__source_kind") != source_kind:
        return False
    action_id = str(finding.get("action_id") or "")
    return not action_id or observation.get("action_id") == action_id


def _valid_flag_event(
    payload: Mapping[str, object],
    observations: Mapping[str, Mapping[str, object]],
    *,
    expected_flag: str,
) -> bool:
    flag = str(payload.get("flag") or "").strip()
    if not flag or flag not in recognize_proofs(flag) or (expected_flag and flag != expected_flag):
        return False
    if payload.get("recognizer") == "scan_probe_output":
        return bool(str(payload.get("evidence") or "").strip())
    source_observation_id = str(payload.get("source_observation_id") or "")
    observation = observations.get(source_observation_id)
    if observation is None:
        return False
    source_kind = str(payload.get("source_kind") or "")
    if source_kind and observation.get("__source_kind") != source_kind:
        return False
    action_id = str(payload.get("action_id") or "")
    if action_id and observation.get("action_id") != action_id:
        return False
    recognized = observation.get("recognized_proofs")
    return isinstance(recognized, list) and flag in recognized


def _public_endpoint(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"method": "GET", "url": "", "params": []}
    method = str(value.get("method") or "GET").upper()
    if method not in _HTTP_METHODS:
        method = "GET"
    return {
        "method": method,
        "url": _canonical_url(str(value.get("url") or "")),
        "params": _safe_parameters(value.get("params")),
    }


def _public_input(value: object, *, endpoint: Mapping[str, object]) -> dict[str, object]:
    raw = value if isinstance(value, dict) else {}
    method = str(raw.get("method") or endpoint.get("method") or "GET").upper()
    if method not in _HTTP_METHODS:
        method = "GET"
    parameters = _safe_parameters(raw.get("parameters"))
    if not parameters:
        parameters = _safe_parameters(endpoint.get("params"))
    result: dict[str, object] = {"method": method, "parameters": parameters}
    affected_parameters = _safe_parameters(raw.get("affected_parameters"))
    if affected_parameters:
        result["affected_parameters"] = affected_parameters
    return result


def _public_provenance(value: object) -> dict[str, object]:
    raw = value if isinstance(value, dict) else {}
    return {
        "evidence_kind": _safe_identifier(raw.get("evidence_kind")),
        "source_kind": _safe_identifier(raw.get("source_kind")),
        "source_observation_id": _safe_reference(raw.get("source_observation_id")),
        "action_id": _safe_reference(raw.get("action_id")),
        "probe": _safe_identifier(raw.get("probe")),
        "finding_type": _safe_identifier(raw.get("finding_type")),
        "assessment_source": _safe_identifier(raw.get("assessment_source")),
        "model_claims_used": raw.get("model_claims_used") is True,
    }


def _public_evidence(payload: Mapping[str, object]) -> dict[str, object]:
    endpoint = _public_endpoint(payload.get("endpoint"))
    finding_type = _safe_identifier(payload.get("finding_type")) or _UNKNOWN_FINDING_TYPE
    probe = _safe_identifier(payload.get("probe")) or "unknown_probe"
    vuln_class = _safe_identifier(payload.get("vuln_class")) or _UNKNOWN_VULN_CLASS
    contract_status = str(payload.get("contract_status") or _REGISTERED_CONTRACT_STATUS)
    if contract_status not in {_REGISTERED_CONTRACT_STATUS, _MISSING_CONTRACT_STATUS}:
        contract_status = _MISSING_CONTRACT_STATUS
    return {
        "evidence_id": _safe_reference(payload.get("evidence_id")),
        "finding_id": _safe_reference(payload.get("finding_id")),
        "stage": str(payload.get("stage") or ""),
        "stage_rank": outcome_stage_rank(str(payload.get("stage") or "")),
        "vuln_class": vuln_class,
        "vuln_class_source": _safe_identifier(payload.get("vuln_class_source")) or "registry",
        "finding_type": finding_type,
        "probe": probe,
        "contract_status": contract_status,
        "endpoint": endpoint,
        "endpoint_url": str(endpoint.get("url") or ""),
        "input": _public_input(payload.get("input"), endpoint=endpoint),
        "provenance": _public_provenance(payload.get("provenance")),
        "confirmed_finding": payload.get("confirmed_finding") is True,
        "missing_evidence": _string_list(payload.get("missing_evidence")),
        "source_observation_id": _safe_reference(payload.get("source_observation_id")),
    }


def _confirmed_finding_evidence(payload: Mapping[str, object]) -> dict[str, object]:
    endpoint = _public_endpoint(payload.get("endpoint"))
    provenance = payload.get("provenance")
    provenance_map = provenance if isinstance(provenance, dict) else {}
    explicit_stage = _outcome_stage(payload.get("outcome_stage"))
    verified_rank = outcome_stage_rank(OutcomeStage.VERIFIED_VULNERABILITY)
    stage = (
        explicit_stage
        if outcome_stage_rank(explicit_stage) >= verified_rank
        else OutcomeStage.VERIFIED_VULNERABILITY
    )
    finding_id = _safe_reference(payload.get("finding_id"))
    finding_type = _safe_identifier(provenance_map.get("finding_type")) or "confirmed_finding"
    probe = _safe_identifier(provenance_map.get("probe")) or "validated_poc"
    return {
        "evidence_id": f"finding:{finding_id}",
        "finding_id": finding_id,
        "stage": stage.value,
        "stage_rank": outcome_stage_rank(stage),
        "vuln_class": _safe_identifier(payload.get("vuln_class")) or _UNKNOWN_VULN_CLASS,
        "vuln_class_source": "confirmed_finding",
        "finding_type": finding_type,
        "probe": probe,
        "contract_status": _REGISTERED_CONTRACT_STATUS,
        "endpoint": endpoint,
        "endpoint_url": str(endpoint.get("url") or ""),
        "input": _public_input(payload.get("input"), endpoint=endpoint),
        "provenance": _public_provenance(provenance),
        "confirmed_finding": True,
        "missing_evidence": [],
        "source_observation_id": _safe_reference(payload.get("source_observation_id")),
    }


def _workspace_records(
    workspace_path: Path,
    *,
    engagement_id: UUID | str | None,
) -> list[tuple[str, dict[str, object]]]:
    records: list[tuple[str, dict[str, object]]] = []
    for events_path in _workspace_event_paths(workspace_path):
        try:
            lines = events_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            value = _json_object(line)
            kind = str(value.get("kind") or "")
            payload = value.get("payload")
            if kind and isinstance(payload, dict):
                normalized = {str(key): item for key, item in payload.items()}
                payload_engagement_id = str(normalized.get("engagement_id") or "")
                if (
                    engagement_id is not None
                    and payload_engagement_id
                    and payload_engagement_id != str(engagement_id)
                ):
                    continue
                records.append((kind, normalized))
    return records


def _workspace_event_paths(workspace_path: Path) -> tuple[Path, ...]:
    """Return only the canonical base/route/graph streams for one attack run."""
    if workspace_path.name == "events.jsonl":
        return (workspace_path,)
    return (
        workspace_path / "events.jsonl",
        workspace_path / "autonomous-route" / "events.jsonl",
        workspace_path / "autonomous-route" / "agent-graph" / "events.jsonl",
    )


def _audit_records(  # noqa: C901 - legacy schemas are read fail-closed per table.
    db_path: Path | None,
    engagement_id: UUID | str | None,
) -> list[tuple[str, dict[str, object]]]:
    if db_path is None or not db_path.is_file():
        return []
    records: list[tuple[str, dict[str, object]]] = []
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            parameters: tuple[str, ...] = ()
            query = "SELECT action, payload_json FROM audit_log"
            if engagement_id is not None:
                query += " WHERE engagement_id = ?"
                parameters = (str(engagement_id),)
            query += " ORDER BY id ASC"
            try:
                audit_rows = connection.execute(query, parameters).fetchall()
            except sqlite3.Error:
                audit_rows = ()
            for action, raw_payload in audit_rows:
                payload = _json_object(str(raw_payload or ""))
                if payload:
                    records.append((str(action), payload))
            finding_query = "SELECT payload_json FROM findings"
            finding_parameters: tuple[str, ...] = ()
            if engagement_id is not None:
                finding_query += " WHERE engagement_id = ?"
                finding_parameters = (str(engagement_id),)
            try:
                finding_rows = connection.execute(
                    finding_query,
                    finding_parameters,
                ).fetchall()
            except sqlite3.Error:
                finding_rows = ()
            for (raw_payload,) in finding_rows:
                payload = _json_object(str(raw_payload or ""))
                if payload:
                    records.append(("finding_confirmed", payload))
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return []
    return records


def _unregistered_request_summary(
    finding: Mapping[str, object],
    *,
    target_url: str,
) -> dict[str, object]:
    form = finding.get("form")
    if isinstance(form, dict):
        raw_url = str(form.get("action") or form.get("url") or "").strip()
        if raw_url:
            return _request_summary(
                {
                    "method": form.get("method") or finding.get("method") or "GET",
                    "url": raw_url,
                    "payload_field": _input_name(finding),
                },
                target_url=target_url,
            )
    for key in ("url", "replay_url", "followup_url", "final_url"):
        raw_url = str(finding.get(key) or "").strip()
        if raw_url:
            return _request_summary(
                {
                    "method": finding.get("method") or "GET",
                    "url": raw_url,
                    "payload_field": _input_name(finding),
                },
                target_url=target_url,
            )
    return _request_summary(
        {
            "method": finding.get("method") or "GET",
            "url": target_url,
            "payload_field": _input_name(finding),
        },
        target_url=target_url,
    )


def _first_request(
    finding: Mapping[str, object],
    keys: Sequence[str],
    *,
    target_url: str,
) -> dict[str, object]:
    for key in keys:
        value = finding.get(key)
        if isinstance(value, dict):
            summary = _request_summary(value, target_url=target_url)
            if summary:
                return summary
        elif isinstance(value, str) and value.strip():
            response = finding.get("response")
            response_map = response if isinstance(response, dict) else {}
            summary = _request_summary(
                {
                    "method": response_map.get("method") or "GET",
                    "url": response_map.get("url") or value,
                    "payload_field": _input_name(finding),
                },
                target_url=target_url,
            )
            if summary:
                return summary
    return {}


def _request_summary(value: Mapping[str, object], *, target_url: str) -> dict[str, object]:
    raw_url = str(value.get("url") or "").strip()
    url = _canonical_url(urljoin(target_url, raw_url))
    if not url:
        return {}
    method = str(value.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return {}
    params: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    query_pairs = parse_qsl(
        urlsplit(urljoin(target_url, raw_url)).query,
        keep_blank_values=True,
    )
    for name, _raw in query_pairs:
        _append_param(params, seen, name=name, location="query")
    location = "query" if method in {"GET", "HEAD", "DELETE", "OPTIONS"} else "body"
    _append_param(
        params,
        seen,
        name=str(value.get("payload_field") or ""),
        location=location,
    )
    for container_key in ("form", "fields", "json", "body"):
        container = value.get(container_key)
        if isinstance(container, dict):
            for name in container:
                _append_param(params, seen, name=str(name), location="body")
    summary: dict[str, object] = {"method": method, "url": url, "params": params[:32]}
    affected_name = _safe_input_name(value.get("payload_field"))
    if affected_name:
        summary["affected_parameter"] = {
            "name": affected_name,
            "location": location,
        }
    encoding = str(value.get("encoding") or "").strip()[:120]
    if encoding:
        summary["encoding"] = encoding
    return summary


def _input_identity(
    request: Mapping[str, object],
    endpoint: Mapping[str, object],
) -> dict[str, object]:
    method = str(request.get("method") or endpoint.get("method") or "GET").upper()
    raw_params = request.get("params")
    if not isinstance(raw_params, list):
        raw_params = endpoint.get("params")
    identity: dict[str, object] = {
        "method": method if method in _HTTP_METHODS else "GET",
        "parameters": _safe_parameters(raw_params),
    }
    affected_parameter = _affected_parameter(request)
    if affected_parameter:
        identity["affected_parameters"] = [affected_parameter]
    return identity


def _affected_parameter(request: Mapping[str, object]) -> dict[str, str]:
    raw = request.get("affected_parameter")
    if not isinstance(raw, dict):
        return {}
    [parameter] = _safe_parameters([raw]) or [{}]
    return parameter


def _safe_parameters(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    parameters: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in value[:32]:
        if not isinstance(raw, dict):
            continue
        name = _safe_input_name(raw.get("name"))
        location = _safe_identifier(raw.get("location"))
        if not name or location not in {"query", "body", "header", "path", "cookie"}:
            continue
        key = (name, location)
        if key in seen:
            continue
        seen.add(key)
        parameters.append({"name": name, "location": location})
    return parameters


def _safe_input_name(value: object) -> str:
    text = str(value or "").strip()
    allowed_extra = "_-.[]:"
    if not text or len(text) > _MAX_INPUT_NAME_LENGTH:
        return ""
    if any(
        not (character.isascii() and (character.isalnum() or character in allowed_extra))
        for character in text
    ):
        return ""
    return text


def _first_response(
    finding: Mapping[str, object],
    keys: Sequence[str],
    *,
    target_url: str,
) -> dict[str, object]:
    for key in keys:
        value = finding.get(key)
        if not isinstance(value, dict):
            continue
        if key == "evidence":
            summary = _browser_response_summary(value, target_url=target_url)
        else:
            summary = _response_summary(value, target_url=target_url)
        if summary:
            return summary
    if "probe_elapsed_ms" in finding:
        return {
            "baseline_elapsed_ms": _bounded_int(finding.get("baseline_elapsed_ms")),
            "probe_elapsed_ms": _bounded_int(finding.get("probe_elapsed_ms")),
            "elapsed_delta_ms": _bounded_int(finding.get("elapsed_delta_ms")),
        }
    return {}


def _response_summary(value: Mapping[str, object], *, target_url: str) -> dict[str, object]:
    summary: dict[str, object] = {}
    method = str(value.get("method") or "").upper()
    if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        summary["method"] = method
    for key in ("status", "elapsed_ms", "body_len"):
        raw = value.get(key)
        if isinstance(raw, int) and not isinstance(raw, bool):
            summary[key] = _bounded_int(raw)
    for key in ("url", "final_url"):
        raw_url = str(value.get(key) or "").strip()
        url = _canonical_url(urljoin(target_url, raw_url)) if raw_url else ""
        if url:
            summary[key] = url
    body_hash = str(value.get("body_sha_hint") or "").strip()
    if body_hash:
        summary["body_sha_hint"] = body_hash[:64]
    summary["truncated"] = value.get("truncated") is True
    summary["error"] = bool(str(value.get("error") or "").strip())
    return summary if summary.get("url") or summary.get("final_url") or "status" in summary else {}


def _browser_response_summary(value: Mapping[str, object], *, target_url: str) -> dict[str, object]:
    executed = value.get("executed_values")
    dialogs = value.get("dialogs")
    summary: dict[str, object] = {
        "token_executed": value.get("token_executed") is True,
        "executed_value_count": len(executed) if isinstance(executed, list) else 0,
        "dialog_count": len(dialogs) if isinstance(dialogs, list) else 0,
    }
    final_url = str(value.get("final_url") or "").strip()
    if final_url:
        summary["final_url"] = _canonical_url(urljoin(target_url, final_url))
    return summary


def _request_from_response(response: Mapping[str, object]) -> dict[str, object]:
    url = str(response.get("url") or response.get("final_url") or "")
    if not url:
        return {}
    return {"method": str(response.get("method") or "GET"), "url": url, "params": []}


def _endpoint(
    *,
    request: Mapping[str, object],
    response: Mapping[str, object],
    target_url: str,
) -> dict[str, object]:
    url = str(request.get("url") or response.get("url") or response.get("final_url") or "")
    canonical = _canonical_url(urljoin(target_url, url))
    raw_params = request.get("params")
    return {
        "method": str(request.get("method") or "GET").upper(),
        "url": canonical,
        "params": list(raw_params) if isinstance(raw_params, list) else [],
    }


def _indicator_summary(
    finding: Mapping[str, object],
    keys: Sequence[str],
) -> dict[str, object]:
    summary: dict[str, object] = {}
    for key in keys:
        value = finding.get(key)
        if isinstance(value, dict) and value:
            kind = str(value.get("kind") or "").strip()[:120]
            summary[key] = {
                "kind": kind,
                "fields": sorted(str(name)[:80] for name in value)[:24],
            }
        elif isinstance(value, list) and value:
            summary[key] = {"count": len(value)}
        elif isinstance(value, bool):
            if value:
                summary[key] = True
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            summary[key] = _bounded_int(value)
        elif isinstance(value, str) and value.strip():
            summary[key] = {"present": True}
    return summary


def _control_summary(key: str, value: object, *, target_url: str) -> dict[str, object]:
    if isinstance(value, dict):
        if "method" in value or "url" in value:
            request = _request_summary(value, target_url=target_url)
            response = _response_summary(value, target_url=target_url)
            summary: dict[str, object] = {"kind": key}
            if request:
                summary["request"] = request
            if response:
                summary["response"] = response
            if not request and not response:
                summary["fields"] = sorted(str(name)[:80] for name in value)[:24]
            return summary
        return {"kind": key, "fields": sorted(str(name)[:80] for name in value)[:24]}
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return {"kind": key, "present": True}
    if isinstance(value, str) and value.strip():
        return {"kind": key, "present": True}
    return {}


def _evaluated_ssti(finding: Mapping[str, object]) -> bool:
    signal = finding.get("signal")
    if not isinstance(signal, dict):
        return False
    return signal.get("kind") == "evaluated_expression"


def _browser_execution(finding: Mapping[str, object]) -> bool:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return False
    executed = evidence.get("executed_values")
    dialogs = evidence.get("dialogs")
    if evidence.get("token_executed") is True:
        return True
    if isinstance(executed, list) and executed:
        return True
    return isinstance(dialogs, list) and bool(dialogs)


def _input_name(finding: Mapping[str, object]) -> str:
    value = finding.get("input")
    if isinstance(value, dict):
        return str(value.get("input") or value.get("name") or "")
    return str(value or "")


def _append_param(
    params: list[dict[str, str]],
    seen: set[tuple[str, str]],
    *,
    name: str,
    location: str,
) -> None:
    clean = name.strip()[:120]
    key = (clean, location)
    if clean and key not in seen:
        seen.add(key)
        params.append({"name": clean, "location": location})


def _canonical_url(url: str) -> str:
    safe_url = sanitize_url(url)
    if safe_url == REDACTED_URL:
        return ""
    try:
        origin, _protocol, route_shape = canonical_operation_url(safe_url)
    except SurfaceGraphError:
        return ""
    return f"{origin}{route_shape}"


def _bounded_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)[:1_200]


def _bounded_int(value: object) -> int:
    try:
        return max(-10_000_000, min(int(str(value)), 10_000_000))
    except (TypeError, ValueError):
        return 0


def _outcome_stage(value: object) -> OutcomeStage:
    try:
        return OutcomeStage(str(value or ""))
    except ValueError:
        return OutcomeStage.NONE


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:160] for item in value if str(item).strip()][:24]


def _json_object(text: str) -> dict[str, object]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    return {str(key): item for key, item in value.items()} if isinstance(value, dict) else {}
