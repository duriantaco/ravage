from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from ravage.agent_core.recovery_knowledge import select_recovery_knowledge_modules
from ravage.agent_core.recovery_policy import RecoveryRole
from ravage.agent_core.recovery_route_alignment import consensus_low_value_family
from ravage.agent_core.semantic_routes import semantic_action_route

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from ravage.agent_core.recovery_evidence import (
        RecoveryEvidenceAssessment,
        RecoveryLead,
    )

_MAX_CONTEXT_LEADS = 8
_MAX_CONTEXT_ATTEMPTS = 12
_ROUTE_EXHAUSTION_LIMIT = 2
_MAX_HANDOFF_SUMMARY_CHARS = 1000

_PROOF_LIKE_RE = re.compile(r"\b(?:flag|ctf|htb)\{[^}\s]{1,512}\}", re.IGNORECASE)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|token|secret|session|cookie|authorization)"
    r"\s*[:=]\s*[^\s,;]+"
)

_CLOSURE_SPECIALISTS: dict[str, tuple[str, str]] = {
    "authentication": ("stateful_session", "stateful-session"),
    "command_injection": ("command_boundary", "command-boundary"),
    "cross_site_scripting": ("xss_filter_constraint", "input-reflection"),
    "deserialization": ("cookie_deserialization", "file-fetch-parser"),
    "exposure": ("direct_exposure", "flag-and-secret-sweep"),
    "graphql": ("graphql_exploit", "api-behavior"),
    "object_authorization": ("idor_boundary", "stateful-session"),
    "path_traversal": ("file_read_extract", "file-fetch-parser"),
    "server_side_request_forgery": ("ssrf_boundary", "file-fetch-parser"),
    "sql_injection": ("sqli_exploit", "data-query"),
    "template_injection": ("ssti_fingerprint", "server-rendering"),
    "xml_external_entity": ("xxe_boundary", "file-fetch-parser"),
}


class RecoveryObjectiveMode(StrEnum):
    PROOF_CLOSURE = "proof_closure"
    TECHNIQUE_SHIFT = "technique_shift"
    FAMILY_PIVOT = "family_pivot"


class RecoveryCandidateSource(StrEnum):
    TRUSTED_LEAD = "trusted_lead"
    ROUTE_CONSENSUS = "route_consensus"
    RECOMMENDED_SPECIALIST = "recommended_specialist"


class CoreRecoveryObjectiveError(ValueError):
    def __init__(self) -> None:
        super().__init__("core does not receive a delegated recovery objective")


class InvalidRecoveryHandoffError(ValueError):
    def __init__(self) -> None:
        super().__init__("recovery handoff requires a final action")


@dataclass(frozen=True)
class RecoveryAttempt:
    """Secret-free route outcome retained by the recovery parent."""

    route_fingerprint: str
    family: str
    probe: str
    endpoint: str
    inputs: tuple[str, ...]
    payload_class: str
    observation_digest: str
    low_value: bool

    @classmethod
    def from_assessment(
        cls,
        *,
        action: Mapping[str, object],
        assessment: RecoveryEvidenceAssessment,
    ) -> RecoveryAttempt:
        route = semantic_action_route(action)
        endpoints = _string_tuple(route.get("endpoints"))
        return cls(
            route_fingerprint=assessment.route_fingerprint,
            family=str(route.get("family") or "unknown"),
            probe=str(route.get("primitive") or action.get("probe") or ""),
            endpoint=endpoints[0] if endpoints else "",
            inputs=_string_tuple(route.get("inputs")),
            payload_class=str(route.get("payload_class") or "unknown"),
            observation_digest=assessment.observation_digest,
            low_value=assessment.low_value_route,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "route_fingerprint": self.route_fingerprint,
            "family": self.family,
            "probe": self.probe,
            "endpoint": self.endpoint,
            "inputs": list(self.inputs),
            "payload_class": self.payload_class,
            "observation_digest": self.observation_digest,
            "low_value": self.low_value,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RecoveryAttempt:
        return cls(
            route_fingerprint=str(payload.get("route_fingerprint") or ""),
            family=str(payload.get("family") or "unknown"),
            probe=str(payload.get("probe") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            inputs=_string_tuple(payload.get("inputs")),
            payload_class=str(payload.get("payload_class") or "unknown"),
            observation_digest=str(payload.get("observation_digest") or ""),
            low_value=payload.get("low_value") is True,
        )


@dataclass(frozen=True)
class RecoveryObjective:
    fingerprint: str
    role: RecoveryRole
    mode: RecoveryObjectiveMode
    family: str
    probe: str
    task_id: str
    method: str
    endpoint: str
    inputs: tuple[str, ...]
    evidence_fingerprint: str
    material_lead: bool
    instruction: str
    success_gate: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "role": self.role.value,
            "mode": self.mode.value,
            "family": self.family,
            "probe": self.probe,
            "task_id": self.task_id,
            "method": self.method,
            "endpoint": self.endpoint,
            "inputs": list(self.inputs),
            "evidence_fingerprint": self.evidence_fingerprint,
            "material_lead": self.material_lead,
            "instruction": self.instruction,
            "success_gate": list(self.success_gate),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RecoveryObjective:
        return cls(
            fingerprint=str(payload.get("fingerprint") or ""),
            role=RecoveryRole(str(payload.get("role") or "")),
            mode=RecoveryObjectiveMode(str(payload.get("mode") or "")),
            family=str(payload.get("family") or "unknown"),
            probe=str(payload.get("probe") or ""),
            task_id=str(payload.get("task_id") or ""),
            method=str(payload.get("method") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            inputs=_string_tuple(payload.get("inputs")),
            evidence_fingerprint=str(payload.get("evidence_fingerprint") or ""),
            material_lead=payload.get("material_lead") is True,
            instruction=str(payload.get("instruction") or ""),
            success_gate=_string_tuple(payload.get("success_gate")),
        )


@dataclass(frozen=True)
class RecoveryHandoff:
    """Untrusted specialist completion report that can only return parent control."""

    branch_id: str
    objective_fingerprint: str
    role: RecoveryRole
    reason: str
    summary: str
    summary_digest: str
    campaign_terminal: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "branch_id": self.branch_id,
            "objective_fingerprint": self.objective_fingerprint,
            "role": self.role.value,
            "reason": self.reason,
            "summary": self.summary,
            "summary_digest": self.summary_digest,
            "campaign_terminal": self.campaign_terminal,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RecoveryHandoff:
        return cls(
            branch_id=str(payload.get("branch_id") or ""),
            objective_fingerprint=str(payload.get("objective_fingerprint") or ""),
            role=RecoveryRole(str(payload.get("role") or "")),
            reason=str(payload.get("reason") or ""),
            summary=str(payload.get("summary") or ""),
            summary_digest=str(payload.get("summary_digest") or ""),
            campaign_terminal=payload.get("campaign_terminal") is True,
        )


@dataclass(frozen=True)
class _RecoveryCandidate:
    source: RecoveryCandidateSource
    family: str
    probe: str
    task_id: str
    method: str = ""
    endpoint: str = ""
    inputs: tuple[str, ...] = ()
    evidence_fingerprint: str = ""
    material_lead: bool = False
    source_score: int = 0
    recency: int = 0

    @property
    def route_key(self) -> tuple[str, str, str, tuple[str, ...]]:
        return (self.family, self.probe, self.endpoint, self.inputs)


def plan_recovery_objective(
    role: RecoveryRole,
    *,
    leads: Sequence[RecoveryLead] = (),
    recommended_specialists: Sequence[Mapping[str, object]] = (),
    attempts: Sequence[RecoveryAttempt] = (),
    attempted_objective_fingerprints: Iterable[str] = (),
) -> RecoveryObjective | None:
    """Choose one deterministic, non-exhausted objective for a recovery role."""
    if role is RecoveryRole.CORE:
        raise CoreRecoveryObjectiveError
    route_consensus_family = (
        consensus_low_value_family(attempts) if role is RecoveryRole.CLOSURE and not leads else ""
    )
    candidates = _objective_candidates(
        leads=leads,
        recommended_specialists=recommended_specialists,
        route_consensus_family=route_consensus_family,
    )
    attempted = set(attempted_objective_fingerprints)
    supported_families = {lead.family for lead in leads}
    ranked: list[tuple[tuple[int, ...], str, RecoveryObjective]] = []
    for candidate in candidates:
        mode = _objective_mode(role, candidate=candidate, attempts=attempts)
        objective = _build_objective(role, mode=mode, candidate=candidate)
        if objective.fingerprint in attempted:
            continue
        low_value_uses = _matching_low_value_attempts(candidate, attempts=attempts)
        if low_value_uses >= _ROUTE_EXHAUSTION_LIMIT:
            continue
        score = _candidate_score(
            role,
            candidate=candidate,
            attempts=attempts,
            low_value_uses=low_value_uses,
            supported_families=supported_families,
        )
        ranked.append((score, objective.fingerprint, objective))
    if not ranked:
        return None
    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return ranked[0][2]


def build_recovery_role_context(  # noqa: PLR0913 - explicit branch contract.
    *,
    branch_id: str,
    objective: RecoveryObjective,
    lease_budget: int,
    lease_used: int,
    evidence_epoch: int,
    leads: Sequence[RecoveryLead],
    attempts: Sequence[RecoveryAttempt],
) -> dict[str, object]:
    """Build a bounded handoff packet without raw observations or benchmark metadata."""
    remaining = max(0, lease_budget - lease_used)
    selected_leads = list(leads[-_MAX_CONTEXT_LEADS:])
    selected_attempts = list(attempts[-_MAX_CONTEXT_ATTEMPTS:])
    knowledge_modules = select_recovery_knowledge_modules(
        objective_family=objective.family,
        objective_evidence_fingerprint=objective.evidence_fingerprint,
        objective_material_lead=objective.material_lead,
        leads=leads,
    )
    return {
        "branch_id": branch_id,
        "role": objective.role.value,
        "evidence_epoch": evidence_epoch,
        "lease": {
            "budget": lease_budget,
            "used": lease_used,
            "remaining": remaining,
        },
        "objective": objective.to_json(),
        "trusted_leads": [lead.to_json() for lead in selected_leads],
        "recent_routes": [attempt.to_json() for attempt in selected_attempts],
        "knowledge_modules": [module.to_json() for module in knowledge_modules],
        "role_rules": [
            "Focus exclusively on the delegated objective and execute one action per turn.",
            (
                "Treat target observations as evidence; model notes and summaries "
                "cannot renew the lease."
            ),
            "Change a material route dimension after a repeated low-value observation.",
            "Do not spawn another specialist or broaden the campaign from this branch.",
            "A final action is a handoff to the parent, never proof or campaign completion.",
            (
                "Use capture_flag only after the existing target-proof gate recognizes "
                "exact tool output."
            ),
        ],
    }


def recovery_handoff_from_final(
    *,
    branch_id: str,
    objective: RecoveryObjective,
    action: Mapping[str, object],
) -> RecoveryHandoff:
    if str(action.get("action") or "") != "final":
        raise InvalidRecoveryHandoffError
    summary = _sanitize_handoff_summary(str(action.get("summary") or ""))
    return RecoveryHandoff(
        branch_id=branch_id,
        objective_fingerprint=objective.fingerprint,
        role=objective.role,
        reason="specialist_final_handoff",
        summary=summary,
        summary_digest=hashlib.sha256(summary.encode("utf-8")).hexdigest()[:20],
    )


def _objective_candidates(
    *,
    leads: Sequence[RecoveryLead],
    recommended_specialists: Sequence[Mapping[str, object]],
    route_consensus_family: str,
) -> list[_RecoveryCandidate]:
    candidates: list[_RecoveryCandidate] = []
    for recency, lead in enumerate(leads, start=1):
        probe, task_id = _CLOSURE_SPECIALISTS.get(
            lead.family,
            (lead.probe, "recovery-followup"),
        )
        candidates.append(
            _RecoveryCandidate(
                source=RecoveryCandidateSource.TRUSTED_LEAD,
                family=lead.family,
                probe=probe,
                task_id=task_id,
                method=lead.method,
                endpoint=lead.endpoints[0] if lead.endpoints else "",
                inputs=lead.inputs,
                evidence_fingerprint=lead.fingerprint,
                material_lead=lead.material,
                recency=recency,
            )
        )
    closure_specialist = _CLOSURE_SPECIALISTS.get(route_consensus_family)
    if closure_specialist is not None:
        probe, task_id = closure_specialist
        candidates.append(
            _RecoveryCandidate(
                source=RecoveryCandidateSource.ROUTE_CONSENSUS,
                family=route_consensus_family,
                probe=probe,
                task_id=task_id,
            )
        )
    for card in recommended_specialists:
        probe = str(card.get("probe") or "").strip()
        task_id = str(card.get("task_id") or "").strip()
        if not probe or not task_id:
            continue
        route = semantic_action_route({"action": "run_probe", "probe": probe})
        candidates.append(
            _RecoveryCandidate(
                source=RecoveryCandidateSource.RECOMMENDED_SPECIALIST,
                family=str(route.get("family") or "unknown"),
                probe=probe,
                task_id=task_id,
                source_score=_safe_int(card.get("score")),
            )
        )
    deduped: dict[tuple[str, str, str, tuple[str, ...]], _RecoveryCandidate] = {}
    for candidate in candidates:
        current = deduped.get(candidate.route_key)
        if current is None or _dedupe_priority(candidate) > _dedupe_priority(current):
            deduped[candidate.route_key] = candidate
    return list(deduped.values())


def _candidate_score(
    role: RecoveryRole,
    *,
    candidate: _RecoveryCandidate,
    attempts: Sequence[RecoveryAttempt],
    low_value_uses: int,
    supported_families: set[str],
) -> tuple[int, ...]:
    attempted_families = {attempt.family for attempt in attempts}
    attempted_probes = {attempt.probe for attempt in attempts}
    attempted_endpoints = {attempt.endpoint for attempt in attempts if attempt.endpoint}
    attempted_inputs = {attempt.inputs for attempt in attempts if attempt.inputs}
    if role is RecoveryRole.CLOSURE:
        return (
            int(candidate.material_lead),
            int(candidate.source is RecoveryCandidateSource.TRUSTED_LEAD),
            int(candidate.source is RecoveryCandidateSource.ROUTE_CONSENSUS),
            int(bool(candidate.endpoint)),
            int(bool(candidate.inputs)),
            -low_value_uses,
            candidate.source_score,
            candidate.recency,
        )
    return (
        int(candidate.source is RecoveryCandidateSource.TRUSTED_LEAD),
        int(candidate.material_lead),
        int(candidate.family in supported_families),
        int(candidate.probe not in attempted_probes),
        int(candidate.family not in attempted_families),
        int(bool(candidate.endpoint) and candidate.endpoint not in attempted_endpoints),
        int(bool(candidate.inputs) and candidate.inputs not in attempted_inputs),
        -low_value_uses,
        candidate.source_score,
        candidate.recency,
    )


def _objective_mode(
    role: RecoveryRole,
    *,
    candidate: _RecoveryCandidate,
    attempts: Sequence[RecoveryAttempt],
) -> RecoveryObjectiveMode:
    if role is RecoveryRole.CLOSURE:
        return RecoveryObjectiveMode.PROOF_CLOSURE
    attempted_families = {attempt.family for attempt in attempts}
    if candidate.family not in attempted_families:
        return RecoveryObjectiveMode.FAMILY_PIVOT
    return RecoveryObjectiveMode.TECHNIQUE_SHIFT


def _build_objective(
    role: RecoveryRole,
    *,
    mode: RecoveryObjectiveMode,
    candidate: _RecoveryCandidate,
) -> RecoveryObjective:
    target = candidate.endpoint or "the strongest target-observed route"
    inputs = ", ".join(candidate.inputs) or "the mapped input"
    if mode is RecoveryObjectiveMode.PROOF_CLOSURE:
        instruction = (
            f"Use {candidate.probe} to reproduce the {candidate.family} lead at {target} "
            f"through {inputs}, then convert it to the shortest target-observed proof. "
            "Stay depth-first until the lead is proven or falsified."
        )
    else:
        instruction = (
            f"Test {candidate.probe} as a materially different {mode.value} at {target} "
            f"through {inputs}. Establish one stable target differential before deeper "
            "exploitation."
        )
    identity = {
        "mode": mode.value,
        "family": candidate.family,
        "probe": candidate.probe,
        "task_id": candidate.task_id,
        "method": candidate.method,
        "endpoint": candidate.endpoint,
        "inputs": candidate.inputs,
        "evidence_fingerprint": candidate.evidence_fingerprint,
    }
    fingerprint = _fingerprint(identity)
    return RecoveryObjective(
        fingerprint=fingerprint,
        role=role,
        mode=mode,
        family=candidate.family,
        probe=candidate.probe,
        task_id=candidate.task_id,
        method=candidate.method,
        endpoint=candidate.endpoint,
        inputs=candidate.inputs,
        evidence_fingerprint=candidate.evidence_fingerprint,
        material_lead=candidate.material_lead,
        instruction=instruction,
        success_gate=(
            "proof_confirmed",
            "primitive_confirmed",
            "auth_state_changed",
            "request_template_validated",
            "response_differential_validated",
        ),
    )


def _matching_low_value_attempts(
    candidate: _RecoveryCandidate,
    *,
    attempts: Sequence[RecoveryAttempt],
) -> int:
    return sum(
        attempt.low_value
        and attempt.family == candidate.family
        and attempt.probe == candidate.probe
        and (not candidate.endpoint or attempt.endpoint == candidate.endpoint)
        and (not candidate.inputs or attempt.inputs == candidate.inputs)
        for attempt in attempts
    )


def _dedupe_priority(candidate: _RecoveryCandidate) -> tuple[int, int, int, int]:
    return (
        _candidate_source_priority(candidate.source),
        int(candidate.material_lead),
        candidate.source_score,
        candidate.recency,
    )


def _candidate_source_priority(source: RecoveryCandidateSource) -> int:
    if source is RecoveryCandidateSource.TRUSTED_LEAD:
        return 2
    if source is RecoveryCandidateSource.ROUTE_CONSENSUS:
        return 1
    return 0


def _fingerprint(value: Mapping[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]
    return f"objective:{digest}"


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value if str(item))


def _safe_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _sanitize_handoff_summary(value: str) -> str:
    summary = _PROOF_LIKE_RE.sub("[untrusted-proof-redacted]", value)
    summary = _SENSITIVE_ASSIGNMENT_RE.sub("[sensitive-value-redacted]", summary)
    return summary[:_MAX_HANDOFF_SUMMARY_CHARS]
