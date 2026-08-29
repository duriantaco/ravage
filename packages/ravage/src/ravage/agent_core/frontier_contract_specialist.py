from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.agent_state import append_unique
from ravage.agent_core.frontier_replay_contract import (
    AuthoritativeReplayContract,
    replay_contract_expected_clause,
)
from ravage.agent_core.frontier_route import (
    FrontierObjective,
    FrontierObjectiveBasis,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_SUFFIX = ":contract_specialist"
_COMPLETION_SIGNAL = "frontier_contract_specialist_completions"
_MAX_COMPLETION_ITEMS = 30


@dataclass(frozen=True)
class ContractSpecialistIssue:
    code: str
    expected_probe: str
    action_kind: str

    def to_json(self) -> dict[str, str]:
        return {
            "code": self.code,
            "expected_probe": self.expected_probe,
            "action_kind": self.action_kind,
        }


def contract_specialist_objective(
    template: FrontierObjective,
    contract: AuthoritativeReplayContract,
) -> FrontierObjective:
    if not contract.authoritative:
        message = "contract-specialist stage requires target-observed authority"
        raise ValueError(message)
    prefix = template.payload_class.rsplit(":", maxsplit=1)[0]
    return FrontierObjective.create(
        family=template.family,
        probe=template.probe,
        endpoint=contract.endpoint,
        inputs=(contract.payload_field,),
        payload_class=f"{prefix}{_SUFFIX}",
        expected_signal=(
            f"Execute exactly one assigned run_probe {template.probe} under the newer "
            "target-observed request contract. This is a materially changed route from "
            "the exhausted base specialist attempt. Preserve its structured controls, "
            "extracted artifacts, and proof transitions; do not recreate the specialist "
            "manually first." + replay_contract_expected_clause(contract)
        ),
        evidence_refs=tuple(dict.fromkeys((*template.evidence_refs, contract.evidence_ref))),
        basis=FrontierObjectiveBasis.NOVEL_COUNTERFACTUAL,
    )


def queue_contract_specialist_objective(
    objectives: Sequence[FrontierObjective],
    contract: AuthoritativeReplayContract,
    *,
    attempted_stage_keys: set[tuple[str, str, str]],
) -> tuple[tuple[FrontierObjective, ...], FrontierObjective | None]:
    pending = [
        objective
        for objective in objectives
        if objective.family == contract.family
        and _stage_key(objective) not in attempted_stage_keys
        and not objective_requires_contract_specialist(objective)
    ]
    if contract.family != "sql_injection" or not pending:
        return tuple(objectives), None
    specialist = contract_specialist_objective(pending[0], contract)
    if _stage_key(specialist) in attempted_stage_keys:
        return tuple(objectives), None

    queued: list[FrontierObjective] = []
    inserted = False
    for objective in objectives:
        if (
            objective.family == contract.family
            and objective_requires_contract_specialist(objective)
            and _stage_key(objective) not in attempted_stage_keys
        ):
            continue
        if (
            not inserted
            and objective.family == contract.family
            and _stage_key(objective) not in attempted_stage_keys
        ):
            queued.append(specialist)
            inserted = True
        queued.append(objective)
    return tuple(queued), specialist if inserted else None


def objective_requires_contract_specialist(
    objective: FrontierObjective,
) -> bool:
    return objective.payload_class.endswith(_SUFFIX)


def detect_contract_specialist_issue(
    objective: FrontierObjective,
    action: Mapping[str, object],
    *,
    attempts: Sequence[Mapping[str, object]],
    worker_id: str,
    stage_completed: bool = False,
) -> ContractSpecialistIssue | None:
    if not objective_requires_contract_specialist(objective):
        return None
    action_kind = str(action.get("action") or "")
    if action_kind in {"final", "capture_flag"}:
        return None
    attempted = stage_completed or worker_attempted_contract_specialist(
        attempts,
        worker_id=worker_id,
        probe=objective.probe,
    )
    if attempted:
        if action_kind == "run_probe" and str(action.get("probe") or "") == (objective.probe):
            return ContractSpecialistIssue(
                code="contract_specialist_already_attempted",
                expected_probe=objective.probe,
                action_kind=action_kind,
            )
        return None
    if action_kind != "run_probe" or str(action.get("probe") or "") != objective.probe:
        return ContractSpecialistIssue(
            code="assigned_contract_specialist_required",
            expected_probe=objective.probe,
            action_kind=action_kind,
        )
    return None


def worker_attempted_contract_specialist(
    attempts: Sequence[Mapping[str, object]],
    *,
    worker_id: str,
    probe: str,
) -> bool:
    for attempt in attempts:
        if str(attempt.get("frontier_worker_id") or "") != worker_id:
            continue
        action = attempt.get("selected_action")
        if not isinstance(action, Mapping):
            continue
        if (
            str(action.get("action") or "") == "run_probe"
            and str(action.get("probe") or "") == probe
        ):
            return True
    return False


def contract_specialist_constraints(
    state: AgentState,
    objective: FrontierObjective,
    *,
    worker_id: str,
) -> tuple[str, ...]:
    if not objective_requires_contract_specialist(objective):
        return ()
    attempted = contract_specialist_completed(
        state,
        objective,
    ) or worker_attempted_contract_specialist(
        state.attempts,
        worker_id=worker_id,
        probe=objective.probe,
    )
    if attempted:
        return (
            (
                f"The one bounded run_probe {objective.probe} execution for this contract "
                "has completed; do not run it again. The specialist-first gate is now "
                "released: use its trusted result for one focused target-observed follow-up "
                "required by coordinator memory, or hand control back when no required "
                "transition remains."
            ),
        )
    return (
        (
            f"Your first executable action must be run_probe {objective.probe}. The newer "
            "target-observed contract makes this materially different from the exhausted "
            "base attempt."
        ),
        (
            "Exactly one specialist execution is allowed for this contract; do not replace "
            "it with a manually recreated probe or broad discovery."
        ),
    )


def remember_contract_specialist_completion(
    state: AgentState,
    objective: FrontierObjective,
) -> bool:
    if not objective_requires_contract_specialist(objective):
        return False
    key = _completion_key(objective)
    values = state.signals.setdefault(_COMPLETION_SIGNAL, [])
    if key in values:
        return False
    append_unique(values, key, limit=_MAX_COMPLETION_ITEMS)
    return True


def contract_specialist_completed(
    state: AgentState,
    objective: FrontierObjective,
) -> bool:
    if not objective_requires_contract_specialist(objective):
        return False
    return _completion_key(objective) in state.signals.get(_COMPLETION_SIGNAL, [])


def _completion_key(objective: FrontierObjective) -> str:
    replay_refs = sorted(
        ref
        for ref in objective.evidence_refs
        if ref.startswith(("replay-contract:", "base-replay:"))
    )
    payload = {
        "family": objective.family,
        "probe": objective.probe,
        "endpoint": objective.endpoint,
        "inputs": list(objective.inputs),
        "replay_refs": replay_refs,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def contract_specialist_guard_message(
    objective: FrontierObjective,
    issue: ContractSpecialistIssue,
) -> str:
    return (
        "COORDINATOR_CONTRACT_SPECIALIST_GUARD\n"
        "Action not executed. This route stage exists to run the assigned specialist "
        "exactly once under a materially newer target-observed request contract. "
        f"Reason: {issue.code}; required action=run_probe {objective.probe}. The model "
        "request remains charged and all global request, worker, scope, repetition, and "
        "cost limits remain enforced."
    )


def contract_specialist_handoff_message(objective: FrontierObjective) -> str:
    return (
        "COORDINATOR_CONTRACT_SPECIALIST_HANDOFF_GUARD\n"
        f"Handoff rejected. Execute one run_probe {objective.probe} under the persisted "
        "target-observed contract before returning control. This is the bounded "
        "materially changed specialist route, not an unchanged base rerun. The rejected "
        "model request remains charged; global request, worker, scope, repetition, and "
        "cost limits remain enforced."
    )


def _stage_key(objective: FrontierObjective) -> tuple[str, str, str]:
    return objective.family, objective.probe, objective.payload_class


__all__ = [
    "ContractSpecialistIssue",
    "contract_specialist_completed",
    "contract_specialist_constraints",
    "contract_specialist_guard_message",
    "contract_specialist_handoff_message",
    "contract_specialist_objective",
    "detect_contract_specialist_issue",
    "objective_requires_contract_specialist",
    "queue_contract_specialist_objective",
    "remember_contract_specialist_completion",
    "worker_attempted_contract_specialist",
]
