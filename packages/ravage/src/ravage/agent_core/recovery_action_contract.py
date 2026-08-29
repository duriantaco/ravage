from __future__ import annotations

from typing import TYPE_CHECKING

from ravage.agent_core.recovery_policy import RecoveryRole

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ravage.agent_core.recovery_objectives import RecoveryObjective


RECOVERY_OBJECTIVE_ACTION_STRATEGY = "recovery_objective_contract"


def select_recovery_branch_action(
    proposed_action: Mapping[str, object],
    *,
    role: RecoveryRole,
    lease_used: int,
    objective: RecoveryObjective | None,
) -> dict[str, object]:
    """Execute a delegated probe once before allowing specialist variation."""
    if (
        role is RecoveryRole.CORE
        or lease_used != 0
        or objective is None
        or objective.role is not role
        or str(proposed_action.get("action") or "") == "final"
    ):
        return dict(proposed_action)

    probe = objective.probe.strip()
    if not probe:
        return dict(proposed_action)

    success_gates = ", ".join(objective.success_gate)
    selected: dict[str, object] = {
        "action": "run_probe",
        "probe": probe,
        "timeout_seconds": 10,
        "strategy": RECOVERY_OBJECTIVE_ACTION_STRATEGY,
        "notes": objective.instruction.strip()
        or f"Execute the delegated {role.value} recovery objective.",
        "expected_signal": (
            f"Satisfy one delegated success gate: {success_gates}."
            if success_gates
            else "Produce target-observed proof or a material route differential."
        ),
        "fallback": (
            "Do not repeat this probe unchanged. If it misses every success gate, "
            "change one material route dimension on the next turn or return parent control."
        ),
    }
    task_id = objective.task_id.strip()
    if task_id:
        selected["task_id"] = task_id
    return selected
