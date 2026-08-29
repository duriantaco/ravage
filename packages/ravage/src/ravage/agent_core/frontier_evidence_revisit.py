from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import unquote_plus

from ravage.agent_core.frontier_replay_contract import (
    AuthoritativeReplayContract,
    authoritative_replay_for_family,
    replay_contract_expected_clause,
)
from ravage.agent_core.frontier_route import (
    FrontierObjective,
    FrontierObjectiveBasis,
)
from ravage.agent_core.frontier_sql_oracle import (
    SqlOracleContract,
    authoritative_sql_oracle_for_objective,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_SQL_FAMILY = "sql_injection"
_CONFIRMED_PREFIX = "confirmed_primitive:"
_CONTRACT_EPOCH_MARKER = ":evidence_revisit_contract_"
_ORACLE_EPOCH_MARKER = ":evidence_revisit_oracle_"
_MIN_CONFIRMED_PARTS = 3
_REPLAY_EVIDENCE_PREFIXES = ("replay-contract:", "base-replay:")
_EXECUTABLE_ACTIONS = frozenset({"run_command", "run_python"})
_REQUEST_MARKERS = ("curl", "http", "requests.", "urlopen", "urllib")
_STRUCTURED_OUTPUT_MARKERS = (
    "boolean_probe",
    "expr",
    "requests",
    "status",
    "target",
)
_BODY_SIGNATURE_MARKERS = ("body_sha_hint", "body_snippet")
_REPETITION = re.compile(r"(?i)(?:range\s*\(\s*[2-9]\d*|repeat(?:ed|s|ing)?\b)")
_QUOTED_DIGIT = re.compile(r"(['\"])(?P<digit>[0-2])\1")
_CONTROL_EXPRESSIONS = (
    re.compile(r"(?<!\d)1\s*=\s*1(?!\d)"),
    re.compile(r"(?<!\d)2\s*=\s*2(?!\d)"),
    re.compile(r"(?<!\d)1\s*=\s*0(?!\d)"),
    re.compile(r"(?<!\d)2\s*=\s*1(?!\d)"),
)


@dataclass(frozen=True)
class EvidenceRevisitIssue:
    code: str
    action_kind: str

    def to_json(self) -> dict[str, str]:
        return {"code": self.code, "action_kind": self.action_kind}


def next_evidence_revisit_objective(
    state: AgentState,
    objectives: Sequence[FrontierObjective],
    *,
    target_url: str,
    attempted_fingerprints: AbstractSet[str],
) -> FrontierObjective | None:
    """Return one evidence-keyed SQL revisit, or none for an unchanged epoch."""
    template = next(
        (
            objective
            for objective in objectives
            if objective.family == _SQL_FAMILY
            and objective.payload_class.startswith(_CONFIRMED_PREFIX)
        ),
        None,
    )
    if template is None:
        return None
    contract = authoritative_replay_for_family(
        state,
        family=template.family,
        target_url=target_url,
        preferred_inputs=template.inputs,
    )
    if contract is None or not contract.authoritative:
        return None

    calibration = _oracle_calibration_objective(template, contract)
    oracle = authoritative_sql_oracle_for_objective(state, calibration)
    candidate = (
        _oracle_proof_objective(template, contract, oracle) if oracle is not None else calibration
    )
    if candidate.fingerprint in attempted_fingerprints:
        return None
    return candidate


def objective_is_evidence_revisit(objective: FrontierObjective) -> bool:
    payload_class = objective.payload_class
    return _CONTRACT_EPOCH_MARKER in payload_class or _ORACLE_EPOCH_MARKER in payload_class


def objective_requires_oracle_revisit(objective: FrontierObjective) -> bool:
    return (
        objective.family == _SQL_FAMILY
        and _CONTRACT_EPOCH_MARKER in objective.payload_class
        and objective.payload_class.endswith(":payload_semantics")
    )


def detect_evidence_revisit_issue(
    objective: FrontierObjective,
    action: Mapping[str, object],
) -> EvidenceRevisitIssue | None:
    if not objective_requires_oracle_revisit(objective):
        return None
    action_kind = str(action.get("action") or "")
    if action_kind in {"final", "capture_flag"}:
        return None
    if action_attempts_oracle_revisit(action):
        return None
    return EvidenceRevisitIssue(
        code="bounded_repeated_sql_controls_required",
        action_kind=action_kind,
    )


def action_attempts_oracle_revisit(action: Mapping[str, object]) -> bool:
    action_kind = str(action.get("action") or "")
    if action_kind not in _EXECUTABLE_ACTIONS:
        return False
    raw = str(action.get("code") or action.get("command") or "").lower()
    source = f"{raw}\n{unquote_plus(raw)}"
    controls_source = _QUOTED_DIGIT.sub(r"\g<digit>", source)
    return (
        any(marker in source for marker in _REQUEST_MARKERS)
        and all(marker in source for marker in _STRUCTURED_OUTPUT_MARKERS)
        and any(marker in source for marker in _BODY_SIGNATURE_MARKERS)
        and all(pattern.search(controls_source) for pattern in _CONTROL_EXPRESSIONS)
        and _REPETITION.search(source) is not None
    )


def worker_attempted_oracle_revisit(
    attempts: Sequence[Mapping[str, object]],
    *,
    worker_id: str,
) -> bool:
    for attempt in attempts:
        if str(attempt.get("frontier_worker_id") or "") != worker_id:
            continue
        action = attempt.get("selected_action")
        if isinstance(action, Mapping) and action_attempts_oracle_revisit(action):
            return True
    return False


def evidence_revisit_constraints(
    objective: FrontierObjective,
) -> tuple[str, ...]:
    if objective_requires_oracle_revisit(objective):
        return (
            (
                "This is one evidence-gated revisit for the current target-observed request "
                "contract; it is not permission for broad rediscovery or an unchanged loop."
            ),
            (
                "Use one bounded request program with repeated 1=1 and 2=2 controls plus "
                "repeated 1=0 and 2=1 controls. Preserve every contract field and record "
                "the target status/body signature for each request."
            ),
            (
                "Emit one JSON object with a requests list. Every item must include "
                "phase='boolean_probe', expr, status, body_snippet (or body_sha_hint), "
                "method, and target={url,input,method}, so the coordinator can persist the "
                "oracle without trusting model prose."
            ),
            (
                "Do not enumerate data until both true controls agree, both false controls "
                "agree, and the two groups differ."
            ),
        )
    if objective_is_evidence_revisit(objective):
        return (
            (
                "This proof revisit is authorized by a new repeated target-observed SQL "
                "oracle. Preserve that exact mapping and request contract."
            ),
            (
                "Run finite checkpointed extraction or the shortest target-observed access "
                "transition; unchanged discovery does not authorize another revisit."
            ),
        )
    return ()


def evidence_revisit_guard_message(
    objective: FrontierObjective,
    issue: EvidenceRevisitIssue,
) -> str:
    return (
        "COORDINATOR_EVIDENCE_REVISIT_GUARD\n"
        "Action not executed. This bounded revisit must calibrate the current "
        "target-observed SQL request contract with repeated tautology and contradiction "
        f"controls. Reason: {issue.code}; action={issue.action_kind or 'invalid'}. Use "
        "one finite run_python or run_command action containing 1=1, 2=2, 1=0, and "
        "2=1 and emitting machine-readable boolean_probe request records on "
        f"endpoint={objective.endpoint}. The model request remains charged; "
        "global request, worker, repetition, scope, and cost limits remain enforced."
    )


def evidence_revisit_handoff_message(objective: FrontierObjective) -> str:
    return (
        "COORDINATOR_EVIDENCE_REVISIT_HANDOFF_GUARD\n"
        "Handoff rejected. Before returning control, execute one finite calibration "
        "program with repeated 1=1/2=2 and 1=0/2=1 requests under the authoritative "
        "contract, emitting a JSON requests list of boolean_probe records, on "
        f"endpoint={objective.endpoint}. The rejected model request remains "
        "charged; unchanged evidence cannot create another revisit, and all global "
        "request, worker, repetition, scope, and cost limits remain enforced."
    )


def evidence_revisit_kind(objective: FrontierObjective) -> str:
    if objective_requires_oracle_revisit(objective):
        return "oracle_calibration"
    if _ORACLE_EPOCH_MARKER in objective.payload_class:
        return "oracle_proof"
    return ""


def _oracle_calibration_objective(
    template: FrontierObjective,
    contract: AuthoritativeReplayContract,
) -> FrontierObjective:
    primitive = _primitive_name(template)
    return FrontierObjective.create(
        family=template.family,
        probe=template.probe,
        endpoint=contract.endpoint,
        inputs=(contract.payload_field,),
        payload_class=(
            f"confirmed_primitive:{primitive}{_CONTRACT_EPOCH_MARKER}"
            f"{contract.fingerprint[:16]}:payload_semantics"
        ),
        expected_signal=(
            "Evidence-gated bounded revisit: the target-observed request contract is "
            "authoritative, but the exhausted SQL stages did not establish a reusable "
            "Boolean oracle. Hold the contract fixed and execute repeated 1=1/2=2 "
            "tautology controls plus repeated 1=0/2=1 contradiction controls. Record "
            "target status/body signatures as a machine-readable JSON requests list of "
            "boolean_probe records; only proceed if both groups are stable and distinct."
            + replay_contract_expected_clause(contract)
        ),
        evidence_refs=tuple(
            dict.fromkeys(
                (
                    *_without_replay_refs(template.evidence_refs),
                    contract.evidence_ref,
                    f"evidence-revisit-contract:{contract.fingerprint}",
                )
            )
        ),
        basis=FrontierObjectiveBasis.NOVEL_COUNTERFACTUAL,
    )


def _oracle_proof_objective(
    template: FrontierObjective,
    contract: AuthoritativeReplayContract,
    oracle: SqlOracleContract,
) -> FrontierObjective:
    primitive = _primitive_name(template)
    return FrontierObjective.create(
        family=template.family,
        probe=template.probe,
        endpoint=contract.endpoint,
        inputs=(contract.payload_field,),
        payload_class=(
            f"confirmed_primitive:{primitive}{_ORACLE_EPOCH_MARKER}"
            f"{oracle.fingerprint[:16]}:proof_channel"
        ),
        expected_signal=(
            "Evidence-gated bounded proof revisit: repeated target controls established "
            f"true={oracle.true_body!r} for 1=1/2=2 and false={oracle.false_body!r} "
            "for 1=0/2=1. Preserve that mapping and the authoritative request contract; "
            "run finite checkpointed extraction or the shortest target-observed access "
            "transition to replayable proof." + replay_contract_expected_clause(contract)
        ),
        evidence_refs=tuple(
            dict.fromkeys(
                (
                    *_without_replay_refs(template.evidence_refs),
                    contract.evidence_ref,
                    f"sql-oracle:{oracle.fingerprint}",
                    f"evidence-revisit-oracle:{oracle.fingerprint}",
                )
            )
        ),
        basis=FrontierObjectiveBasis.NOVEL_COUNTERFACTUAL,
    )


def _primitive_name(template: FrontierObjective) -> str:
    parts = template.payload_class.split(":")
    return parts[1] if len(parts) >= _MIN_CONFIRMED_PARTS and parts[1] else "sqli_confirmed"


def _without_replay_refs(evidence_refs: Sequence[str]) -> tuple[str, ...]:
    return tuple(ref for ref in evidence_refs if not str(ref).startswith(_REPLAY_EVIDENCE_PREFIXES))


__all__ = [
    "EvidenceRevisitIssue",
    "action_attempts_oracle_revisit",
    "detect_evidence_revisit_issue",
    "evidence_revisit_constraints",
    "evidence_revisit_guard_message",
    "evidence_revisit_handoff_message",
    "evidence_revisit_kind",
    "next_evidence_revisit_objective",
    "objective_is_evidence_revisit",
    "objective_requires_oracle_revisit",
    "worker_attempted_oracle_revisit",
]
