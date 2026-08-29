# ruff: noqa: CPY001

from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.adapter import (
    graph_objective_from_frontier,
)
from ravage.agent_core.autonomous_graph.campaigns import (
    campaigns_for_objective,
    initial_stage_for_objective,
)
from ravage.agent_core.autonomous_graph.data_query_seed import (
    data_query_contract,
)
from ravage.agent_core.autonomous_graph.seed_portfolio import (
    build_seed_portfolio,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
)

TARGET_URL = "http://127.0.0.1:8765/"
BASE_DIGEST = "a" * 64


def _base() -> BaseRouteOutcome:
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest=BASE_DIGEST,
        state_ref="frozen-state.json",
    )


def _polluted_query_state() -> AgentState:
    return AgentState(
        turn=40,
        primitives={
            "direct_exposure_observed": 17,
            "xxe_surface_observed": 17,
        },
        surface={
            "endpoints": [
                {
                    "url": f"{TARGET_URL}login.php",
                    "hints": ["auth"],
                    "priority": 18,
                },
                {
                    "url": f"{TARGET_URL}search.php",
                    "hints": ["query"],
                    "priority": 18,
                },
            ]
        },
        signals={
            "endpoints": [
                f"{TARGET_URL}graphql/",
                f"{TARGET_URL}search.php",
            ],
            "forms": [
                '<form action=\\"login.php\\" method=\\"POST\\">',
                '<form action=\\"search.php\\" method=\\"POST\\">',
            ],
            "markers": ["sql", "mysql", "filtered", "xml", "graphql"],
            "parameters": [
                "name",
                "username",
                "EIO",
                "transport",
                "action",
                "wsdl",
                "email",
                "filter",
            ],
        },
        tasks=[
            {
                "id": "data-query",
                "status": "blocked",
                "priority": 100,
                "attempts": 13,
            },
            {
                "id": "flag-and-secret-sweep",
                "status": "blocked",
                "priority": 75,
                "attempts": 5,
            },
        ],
        actions=[
            {
                "action": "run_probe",
                "probe": "filtered_query_bypass",
                "task_id": "data-query",
                "repeat_count": 2,
                "outcome": "same_as_before",
            },
            {
                "action": "run_probe",
                "probe": "sqli_differential",
                "task_id": "data-query",
                "repeat_count": 3,
                "outcome": "same_as_before",
            },
        ],
    )


def test_polluted_base_state_seeds_observed_query_contract_not_graphql() -> None:
    state = _polluted_query_state()

    contract = data_query_contract(state, target_url=TARGET_URL)
    portfolio = build_seed_portfolio(state, base=_base(), limit=4)
    objective = portfolio.objectives[0]

    assert contract is not None
    assert contract.endpoint == f"{TARGET_URL}search.php"
    assert contract.inputs == ("filter", "email")
    assert objective.probe == "sqli_differential"
    assert objective.endpoint == f"{TARGET_URL}search.php"
    assert objective.inputs == contract.inputs
    assert "graphql" not in objective.endpoint
    assert "EIO" not in objective.inputs
    assert "transport" not in objective.inputs


def test_query_contract_enters_calibration_then_existing_finite_pivot() -> None:
    objective = build_seed_portfolio(
        _polluted_query_state(),
        base=_base(),
        limit=4,
    ).objectives[0]
    graph_objective = graph_objective_from_frontier(
        family=objective.family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=objective.expected_signal,
    )

    campaigns = campaigns_for_objective(
        graph_objective,
        stage=initial_stage_for_objective(graph_objective),
    )

    assert campaigns[0].probe == "sqli_differential"
    assert campaigns[1].probe == "filtered_query_bypass"


def test_query_seed_requires_live_task_scoped_endpoint_and_observed_inputs() -> None:
    state = _polluted_query_state()
    state.tasks[0]["status"] = "done"
    state.surface["endpoints"] = [
        {
            "url": "http://outside.invalid/search",
            "hints": ["query"],
            "priority": 100,
        }
    ]
    state.signals["endpoints"] = []
    state.signals["forms"] = []

    assert data_query_contract(state, target_url=TARGET_URL) is None


def test_auth_only_surface_does_not_become_a_generic_data_query_contract() -> None:
    state = AgentState(
        surface={
            "endpoints": [
                {
                    "url": f"{TARGET_URL}accounts/login/",
                    "hints": ["auth"],
                    "priority": 21,
                },
                {
                    "url": f"{TARGET_URL}accounts/register/step1/",
                    "hints": ["auth"],
                    "priority": 21,
                },
            ],
            "parameters": [
                {
                    "name": "username",
                    "locations": [f"{TARGET_URL}accounts/login/"],
                },
                {
                    "name": "name",
                    "locations": [f"{TARGET_URL}accounts/register/step1/"],
                },
            ],
        },
        signals={
            "endpoints": ["/css", "/0.2", "/accounts/login/"],
            "forms": [
                '<form action="accounts/login/" method="POST">',
                '<form action="accounts/register/step1/" method="POST">',
            ],
            "parameters": ["username", "name", "password"],
        },
        tasks=[
            {
                "id": "data-query",
                "status": "blocked",
                "priority": 100,
                "attempts": 13,
            }
        ],
    )

    assert data_query_contract(state, target_url=TARGET_URL) is None
