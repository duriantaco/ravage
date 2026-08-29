from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.adapter import graph_objective_from_frontier
from ravage.agent_core.autonomous_graph.campaigns import (
    campaigns_for_objective,
    initial_stage_for_objective,
)
from ravage.agent_core.autonomous_graph.transition_seeds import (
    augment_transition_objectives,
    sql_auth_transition_objective,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
    FrontierObjective,
)

TARGET_URL = "http://127.0.0.1:8765/"


def _base() -> BaseRouteOutcome:
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest="a" * 64,
        state_ref="frozen-state.json",
    )


def _login_form(*, action: str = "/login") -> str:
    return json.dumps(
        {
            "action": action,
            "method": "POST",
            "inputs": [
                {"name": "csrf", "type": "hidden", "value": "target-token"},
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
        },
        sort_keys=True,
    )


def _sqli_objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/login",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
        expected_signal="target-observed SQL closure or bounded disproof",
    )


def test_confirmed_sqli_login_contract_seeds_finite_auth_closure_first() -> None:
    state = AgentState(
        primitives={"sqli_confirmed": 6},
        signals={"forms": [_login_form()]},
    )

    objectives = augment_transition_objectives(
        state,
        base=_base(),
        objectives=(_sqli_objective(),),
        limit=4,
    )

    transition = objectives[0]
    assert transition.family == "authentication"
    assert transition.probe == "sqli_auth_transition"
    assert transition.endpoint == f"{TARGET_URL.rstrip('/')}/login"
    assert transition.inputs == ("csrf", "username", "password")
    assert "primitive:sqli_confirmed:turn:6" in transition.evidence_refs

    graph_objective = graph_objective_from_frontier(
        family=transition.family,
        probe=transition.probe,
        endpoint=transition.endpoint,
        inputs=transition.inputs,
        payload_class=transition.payload_class,
        expected_signal=transition.expected_signal,
    )
    stage = initial_stage_for_objective(graph_objective)
    campaigns = campaigns_for_objective(graph_objective, stage=stage)

    assert campaigns[0].probe == "sqli_auth_transition"


def test_transition_seed_requires_both_confirmed_sqli_and_login_contract() -> None:
    no_primitive = AgentState(signals={"forms": [_login_form()]})
    no_password = AgentState(
        primitives={"sqli_confirmed": 2},
        signals={
            "forms": [
                json.dumps(
                    {
                        "action": "/search",
                        "method": "POST",
                        "inputs": [{"name": "query", "type": "text"}],
                    }
                )
            ]
        },
    )

    assert sql_auth_transition_objective(no_primitive, base=_base()) is None
    assert sql_auth_transition_objective(no_password, base=_base()) is None


def test_transition_seed_rejects_cross_origin_form_and_respects_limit() -> None:
    state = AgentState(
        primitives={"sqli_confirmed": 1},
        signals={"forms": [_login_form(action="https://outside.example/login")]},
    )

    assert sql_auth_transition_objective(state, base=_base()) is None
    assert (
        augment_transition_objectives(
            AgentState(
                primitives={"sqli_confirmed": 1},
                signals={"forms": [_login_form()]},
            ),
            base=_base(),
            objectives=(_sqli_objective(),),
            limit=1,
        )[0].probe
        == "sqli_auth_transition"
    )
