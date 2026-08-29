from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_route import FrontierObjective
from ravage.agent_core.frontier_sql_oracle import (
    authoritative_sql_oracle_for_objective,
    detect_sql_oracle_assignment_issue,
    remember_sql_oracle_contracts,
    sql_oracle_constraints,
    sql_oracle_contracts_from_observation,
)

TARGET_URL = "http://127.0.0.1:8765/index.php"
TRUE_BODY = '{"response":"password"}'
FALSE_BODY = '{"response":"username"}'


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=TARGET_URL,
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract the paired secret through a calibrated oracle",
    )


def _request(expr: str, body: str, digest: str) -> dict[str, object]:
    return {
        "phase": "boolean_probe",
        "expr": expr,
        "status": 200,
        "body_sha_hint": digest,
        "body_snippet": body,
        "method": "POST",
        "target": {
            "url": TARGET_URL,
            "input": "username",
            "method": "POST",
        },
    }


def _specialist_observation() -> str:
    return json.dumps(
        {
            "ok": True,
            "probe": "sqli_exploit",
            "findings": [
                {
                    "type": "sql_boolean_primitive",
                    "true_payload": "ravage' OR (1=1)-- -",
                    "false_payload": "ravage' OR (1=0)-- -",
                }
            ],
            "requests": [
                _request("1=1", TRUE_BODY, "true-digest"),
                _request("1=0", FALSE_BODY, "false-digest"),
                _request("2=2", TRUE_BODY, "true-digest"),
                _request("2=1", FALSE_BODY, "false-digest"),
            ],
        }
    )


def test_repeated_specialist_controls_become_authoritative_oracle_memory() -> None:
    objective = _objective()
    state = AgentState()

    contracts = remember_sql_oracle_contracts(
        state,
        _specialist_observation(),
        objective=objective,
    )

    assert len(contracts) == 1
    contract = contracts[0]
    assert contract.true_body == TRUE_BODY
    assert contract.false_body == FALSE_BODY
    assert contract.method == "POST"
    assert contract.input_name == "username"
    assert authoritative_sql_oracle_for_objective(state, objective) == contract
    constraints = " ".join(sql_oracle_constraints(contract))
    assert "1=1 and 2=2" in constraints
    assert "UNION/error" in constraints


def test_single_or_unstable_controls_cannot_define_oracle_truth() -> None:
    payload = json.loads(_specialist_observation())
    payload["requests"] = payload["requests"][:2]

    assert (
        sql_oracle_contracts_from_observation(
            json.dumps(payload),
            objective=_objective(),
        )
        == ()
    )

    payload = json.loads(_specialist_observation())
    payload["requests"][2]["body_sha_hint"] = "different-true"
    assert (
        sql_oracle_contracts_from_observation(
            json.dumps(payload),
            objective=_objective(),
        )
        == ()
    )


def test_middle_clipped_specialist_output_recovers_complete_control_objects() -> None:
    controls = [
        _request("1=1", TRUE_BODY, "true-digest"),
        _request("1=0", FALSE_BODY, "false-digest"),
        _request("2=2", TRUE_BODY, "true-digest"),
        _request("2=1", FALSE_BODY, "false-digest"),
    ]
    clipped = (
        '{"ok":true,"requests":[{"phase":"union_probe"}\n'
        "...[truncated from middle]...\n" + ",\n".join(json.dumps(item) for item in controls) + "]}"
    )

    contracts = sql_oracle_contracts_from_observation(
        clipped,
        objective=_objective(),
    )

    assert len(contracts) == 1
    assert contracts[0].true_body == TRUE_BODY
    assert contracts[0].false_body == FALSE_BODY


def test_run24_inverted_true_false_assignments_are_rejected() -> None:
    objective = _objective()
    state = AgentState()
    contract = remember_sql_oracle_contracts(
        state,
        _specialist_observation(),
        objective=objective,
    )[0]
    inverted = {
        "action": "run_python",
        "code": (
            "TRUE='{" + '"response":"username"' + "}'\n"
            "FALSE='{" + '"response":"password"' + "}'\n"
            "result = body == TRUE"
        ),
    }
    correct = {
        "action": "run_python",
        "code": (
            "TRUE='{" + '"response":"password"' + "}'\n"
            "FALSE='{" + '"response":"username"' + "}'\n"
            "result = body == TRUE"
        ),
    }

    issue = detect_sql_oracle_assignment_issue(objective, inverted, contract)

    assert issue is not None
    assert issue.code == "confirmed_oracle_inverted"
    assert detect_sql_oracle_assignment_issue(objective, correct, contract) is None


def test_oracle_memory_is_scoped_to_endpoint_and_input() -> None:
    objective = _objective()
    state = AgentState()
    remember_sql_oracle_contracts(
        state,
        _specialist_observation(),
        objective=objective,
    )
    other = FrontierObjective.create(
        family=objective.family,
        probe=objective.probe,
        endpoint="/other.php",
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=objective.expected_signal,
    )

    assert authoritative_sql_oracle_for_objective(state, other) is None
