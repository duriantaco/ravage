from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_contract_specialist import (
    contract_specialist_completed,
    contract_specialist_constraints,
    contract_specialist_guard_message,
    contract_specialist_objective,
    detect_contract_specialist_issue,
    objective_requires_contract_specialist,
    remember_contract_specialist_completion,
    worker_attempted_contract_specialist,
)
from ravage.agent_core.frontier_replay_contract import AuthoritativeReplayContract
from ravage.agent_core.frontier_route import FrontierObjective


def _template() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal=(
            "The default run_probe sqli_exploit route is exhausted; do not rerun it unchanged."
        ),
    )


def _contract() -> AuthoritativeReplayContract:
    return AuthoritativeReplayContract.create(
        family="sql_injection",
        method="POST",
        endpoint="/index.php",
        observed_url="http://127.0.0.1:8765/index.php",
        payload_field="username",
        payload_location="body",
        required_fields=("username", "password", "submit"),
        fixed_parameters=(("submit", "submit"),),
        encoding="application/x-www-form-urlencoded",
        source="frontier_target_observation",
    )


def test_new_target_contract_creates_materially_changed_specialist_stage() -> None:
    objective = contract_specialist_objective(_template(), _contract())

    assert objective_requires_contract_specialist(objective)
    assert objective.endpoint == "/index.php"
    assert objective.inputs == ("username",)
    assert objective.probe == "sqli_exploit"
    assert "exactly one assigned run_probe" in objective.expected_signal.lower()
    assert "do not rerun it unchanged" not in objective.expected_signal.lower()
    assert _contract().evidence_ref in objective.evidence_refs


def test_stage_requires_assigned_probe_and_rejects_duplicate_execution() -> None:
    objective = contract_specialist_objective(_template(), _contract())
    wrong = {"action": "run_command", "command": "manual SQL probe"}

    issue = detect_contract_specialist_issue(
        objective,
        wrong,
        attempts=(),
        worker_id="worker-002",
    )

    assert issue is not None
    assert issue.code == "assigned_contract_specialist_required"
    assert "model request remains charged" in contract_specialist_guard_message(
        objective,
        issue,
    )

    action = {"action": "run_probe", "probe": "sqli_exploit"}
    assert (
        detect_contract_specialist_issue(
            objective,
            action,
            attempts=(),
            worker_id="worker-002",
        )
        is None
    )
    attempts = (
        {
            "frontier_worker_id": "worker-002",
            "selected_action": action,
        },
    )
    duplicate = detect_contract_specialist_issue(
        objective,
        action,
        attempts=attempts,
        worker_id="worker-002",
    )
    assert duplicate is not None
    assert duplicate.code == "contract_specialist_already_attempted"
    assert worker_attempted_contract_specialist(
        attempts,
        worker_id="worker-002",
        probe="sqli_exploit",
    )


def test_prompt_requires_one_specialist_before_manual_recreation() -> None:
    objective = contract_specialist_objective(_template(), _contract())
    constraints = " ".join(
        contract_specialist_constraints(
            AgentState(),
            objective,
            worker_id="worker-002",
        )
    )

    assert "first executable action" in constraints
    assert "exactly one specialist execution" in constraints.lower()


def test_completed_specialist_allows_focused_followup_but_not_a_duplicate() -> None:
    objective = contract_specialist_objective(_template(), _contract())
    specialist = {"action": "run_probe", "probe": "sqli_exploit"}
    attempts = (
        {
            "frontier_worker_id": "worker-002",
            "selected_action": specialist,
        },
    )
    focused_followup = {
        "action": "run_python",
        "code": (
            "for position in range(1, 33):\n"
            "    expr=f'ascii(substring((select password),{position},1))>64'\n"
            "    print(requests.post('/index.php', data={'username': expr, "
            "'password': 'x', 'submit': 'submit'}).text)"
        ),
    }

    assert (
        detect_contract_specialist_issue(
            objective,
            focused_followup,
            attempts=attempts,
            worker_id="worker-002",
        )
        is None
    )
    duplicate = detect_contract_specialist_issue(
        objective,
        specialist,
        attempts=attempts,
        worker_id="worker-002",
    )
    assert duplicate is not None
    assert duplicate.code == "contract_specialist_already_attempted"

    state = AgentState(attempts=list(attempts))
    constraints = " ".join(
        contract_specialist_constraints(
            state,
            objective,
            worker_id="worker-002",
        )
    )
    assert "focused target-observed follow-up" in constraints.lower()
    assert "do not run it again" in constraints.lower()


def test_completion_receipt_survives_proof_worker_handoff_for_same_contract() -> None:
    objective = contract_specialist_objective(_template(), _contract())
    proof_objective = objective.proof_closure(material_refs=("material:checkpoint",))
    state = AgentState()

    assert remember_contract_specialist_completion(state, objective)
    assert not remember_contract_specialist_completion(state, objective)
    assert contract_specialist_completed(state, proof_objective)
    constraints = " ".join(
        contract_specialist_constraints(
            state,
            proof_objective,
            worker_id="worker-003",
        )
    )
    assert "first executable action" not in constraints.lower()
    assert "specialist-first gate is now released" in constraints.lower()

    duplicate = detect_contract_specialist_issue(
        proof_objective,
        {"action": "run_probe", "probe": "sqli_exploit"},
        attempts=(),
        worker_id="worker-003",
        stage_completed=True,
    )
    assert duplicate is not None
    assert duplicate.code == "contract_specialist_already_attempted"
