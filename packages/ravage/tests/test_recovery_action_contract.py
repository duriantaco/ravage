from __future__ import annotations

from dataclasses import replace

import pytest
from ravage.agent_core.recovery_action_contract import (
    RECOVERY_OBJECTIVE_ACTION_STRATEGY,
    select_recovery_branch_action,
)
from ravage.agent_core.recovery_objectives import (
    RecoveryObjective,
    RecoveryObjectiveMode,
)
from ravage.agent_core.recovery_policy import RecoveryRole


def _objective(*, probe: str = "xss_filter_constraint") -> RecoveryObjective:
    return RecoveryObjective(
        fingerprint="objective:test-xss-filter",
        role=RecoveryRole.CLOSURE,
        mode=RecoveryObjectiveMode.PROOF_CLOSURE,
        family="cross_site_scripting",
        probe=probe,
        task_id="input-reflection",
        method="GET",
        endpoint="/page",
        inputs=("name",),
        evidence_fingerprint="",
        material_lead=False,
        instruction="Execute the bounded XSS filter closer.",
        success_gate=("proof_confirmed", "response_differential_validated"),
    )


@pytest.mark.parametrize(
    "proposed_action",
    [
        {
            "action": "run_command",
            "command": "curl an unrelated route",
            "strategy": "manual_loop",
        },
        {
            "action": "run_probe",
            "probe": "command_boundary",
            "strategy": "unrelated_specialist",
        },
    ],
)
def test_first_specialist_action_executes_the_delegated_probe(
    proposed_action: dict[str, object],
) -> None:
    selected = select_recovery_branch_action(
        proposed_action,
        role=RecoveryRole.CLOSURE,
        lease_used=0,
        objective=_objective(),
    )

    assert selected["action"] == "run_probe"
    assert selected["probe"] == "xss_filter_constraint"
    assert selected["task_id"] == "input-reflection"
    assert selected["strategy"] == RECOVERY_OBJECTIVE_ACTION_STRATEGY
    assert "proof_confirmed" in str(selected["expected_signal"])
    assert "do not repeat" in str(selected["fallback"]).lower()


def test_first_specialist_final_remains_a_bounded_parent_handoff() -> None:
    proposed = {
        "action": "final",
        "summary": "Target evidence falsifies this delegated family.",
    }

    selected = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.CLOSURE,
        lease_used=0,
        objective=_objective(),
    )

    assert selected == proposed
    assert selected is not proposed


def test_contract_is_one_shot_within_each_specialist_lease() -> None:
    proposed = {
        "action": "run_command",
        "command": "materially different follow-up",
        "strategy": "adapted_follow_up",
    }

    selected = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.CLOSURE,
        lease_used=1,
        objective=_objective(),
    )

    assert selected == proposed
    assert selected is not proposed


def test_contract_does_not_change_core_or_unassigned_actions() -> None:
    proposed = {"action": "final", "summary": "core proposal"}

    core_selected = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.CORE,
        lease_used=0,
        objective=_objective(),
    )
    unassigned_selected = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.CLOSURE,
        lease_used=0,
        objective=None,
    )
    empty_probe_selected = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.CLOSURE,
        lease_used=0,
        objective=replace(_objective(), probe=""),
    )
    stale_objective_selected = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.COUNTERFACTUAL,
        lease_used=0,
        objective=_objective(),
    )

    assert core_selected == proposed
    assert unassigned_selected == proposed
    assert empty_probe_selected == proposed
    assert stale_objective_selected == proposed


def test_contract_action_is_deterministic() -> None:
    proposed = {
        "action": "run_command",
        "command": "unrelated manual route",
        "strategy": "manual_loop",
    }
    objective = replace(
        _objective(),
        role=RecoveryRole.COUNTERFACTUAL,
        mode=RecoveryObjectiveMode.TECHNIQUE_SHIFT,
    )

    first = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.COUNTERFACTUAL,
        lease_used=0,
        objective=objective,
    )
    second = select_recovery_branch_action(
        proposed,
        role=RecoveryRole.COUNTERFACTUAL,
        lease_used=0,
        objective=objective,
    )

    assert first == second
