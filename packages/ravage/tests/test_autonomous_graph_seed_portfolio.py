# ruff: noqa: CPY001

from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.adapter import graph_objective_from_frontier
from ravage.agent_core.autonomous_graph.campaigns import (
    campaigns_for_objective,
    initial_stage_for_objective,
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
MINIMUM_STRONG_SEEDS = 1
MINIMUM_DIVERSE_FAMILIES = 3


def _base() -> BaseRouteOutcome:
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest=BASE_DIGEST,
        state_ref="frozen-state.json",
    )


def test_portfolio_caps_weak_surface_and_prefers_confirmed_primitive() -> None:
    state = AgentState(
        turn=40,
        facts=["XML endpoint observed", "stored template evaluation confirmed"],
        signals={
            "endpoints": ["/soap", "/register/step-three"],
            "parameters": ["xml", "name"],
        },
        primitives={
            "xxe_surface_observed": 17,
            "ssti_confirmed": 5,
        },
        tasks=[
            {
                "id": "server-rendering",
                "status": "blocked",
                "priority": 94,
                "attempts": 8,
            },
            {
                "id": "file-fetch-parser",
                "status": "blocked",
                "priority": 88,
                "attempts": 3,
            },
        ],
    )

    portfolio = build_seed_portfolio(state, base=_base(), limit=4)

    assert portfolio.objectives
    assert portfolio.objectives[0].probe == "ssti_fingerprint"
    assert sum(item.probe == "xxe_boundary" for item in portfolio.objectives) <= 1
    assert (
        sum(item.probe == "ssti_fingerprint" for item in portfolio.objectives)
        >= MINIMUM_STRONG_SEEDS
    )


def test_portfolio_adds_bounded_xss_constraint_from_exact_base_contract() -> None:
    state = AgentState(
        turn=40,
        surface={
            "visible_description": "Execute alert('EXPECTED') in the reflected page.",
            "reflections": [
                {
                    "name": "message",
                    "page": f"{TARGET_URL}render",
                    "source": "form",
                }
            ],
        },
        signals={
            "reflections": [
                json.dumps(
                    {
                        "input": "message",
                        "type": "reflection_value_delta",
                        "url": f"{TARGET_URL}render",
                    }
                )
            ]
        },
        tasks=[
            {
                "id": "input-reflection",
                "status": "blocked",
                "priority": 98,
                "attempts": 12,
            }
        ],
        actions=[
            {
                "action": "run_probe",
                "probe": "dom_execution",
                "task_id": "input-reflection",
                "repeat_count": 8,
            }
        ],
    )

    portfolio = build_seed_portfolio(state, base=_base(), limit=4)

    objective = portfolio.objectives[0]
    assert objective.family == "cross_site_scripting"
    assert objective.probe == "xss_filter_constraint"
    assert objective.endpoint == f"{TARGET_URL}render"
    assert objective.inputs == ("message",)

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
    assert campaigns[0].probe == "xss_filter_constraint"
    assert campaigns[0].dimension == ("element_name_filter_boundary_and_exact_dialog_value")


def test_sql_auth_transition_remains_first_after_portfolio_selection() -> None:
    state = AgentState(
        turn=40,
        primitives={
            "sqli_confirmed": 6,
            "xxe_surface_observed": 8,
        },
        signals={
            "forms": [
                json.dumps(
                    {
                        "action": "/login",
                        "method": "POST",
                        "inputs": [
                            {"name": "csrf", "type": "hidden"},
                            {"name": "username", "type": "text"},
                            {"name": "password", "type": "password"},
                        ],
                    }
                )
            ],
            "sqli_inputs": [json.dumps({"input": "username", "url": f"{TARGET_URL}login"})],
        },
    )

    portfolio = build_seed_portfolio(state, base=_base(), limit=4)

    assert portfolio.objectives[0].probe == "sqli_auth_transition"
    assert sum(item.probe == "xxe_boundary" for item in portfolio.objectives) <= 1
    assert sum(item.probe == "sqli_exploit" for item in portfolio.objectives) >= 1


def test_portfolio_is_deterministic_and_contains_no_answer_channel() -> None:
    state = AgentState(
        turn=40,
        facts=["A filtered search form returns stable row-count differences."],
        signals={"endpoints": ["/search"], "parameters": ["query"]},
        tasks=[
            {
                "id": "data-query",
                "status": "in_progress",
                "priority": 100,
                "attempts": 4,
            }
        ],
    )

    first = build_seed_portfolio(state, base=_base(), limit=4)
    second = build_seed_portfolio(state, base=_base(), limit=4)
    encoded = json.dumps(first.to_json()).lower()

    assert first == second
    assert "xben" not in encoded
    assert "benchmark" not in encoded
    assert "ground_truth" not in encoded
    assert "flag{" not in encoded


def test_ordinary_portfolio_targets_findings_or_bounded_coverage() -> None:
    state = AgentState(
        turn=40,
        facts=["Search responses show a stable query-dependent differential."],
        signals={"endpoints": ["/search"], "parameters": ["query"]},
        tasks=[
            {
                "id": "data-query",
                "status": "in_progress",
                "priority": 100,
                "attempts": 2,
            }
        ],
    )

    portfolio = build_seed_portfolio(
        state,
        base=_base(),
        limit=4,
        flag_objective=False,
    )

    assert portfolio.flag_objective is False
    assert portfolio.to_json()["mission"] == "vulnerability_assessment"
    assert portfolio.objectives
    assert all("persist a confirmed" in item.expected_signal for item in portfolio.objectives)
    assert all("bounded negative coverage" in item.expected_signal for item in portfolio.objectives)
    assert all("target-returned proof" not in item.expected_signal for item in portfolio.objectives)


def test_portfolio_does_not_let_one_unconfirmed_task_occupy_every_seed() -> None:
    state = AgentState(
        turn=40,
        facts=[
            "Filtered login checks were inconclusive.",
            "An admin path and a file-like route were also observed.",
        ],
        signals={
            "endpoints": ["/login", "/admin/", "/download"],
            "parameters": ["username", "password", "path"],
        },
        primitives={"direct_exposure_observed": 12},
        tasks=[
            {
                "id": "data-query",
                "status": "in_progress",
                "priority": 100,
                "attempts": 9,
            },
            {
                "id": "file-fetch-parser",
                "status": "blocked",
                "priority": 80,
                "attempts": 7,
            },
            {
                "id": "flag-and-secret-sweep",
                "status": "blocked",
                "priority": 83,
                "attempts": 3,
            },
        ],
    )

    portfolio = build_seed_portfolio(state, base=_base(), limit=4)

    families = {item.family for item in portfolio.objectives}
    assert "exposure" in families
    assert len(families) >= MINIMUM_DIVERSE_FAMILIES
    assert sum(item.family == "sql_injection" for item in portfolio.objectives) <= 1
