# ruff: noqa: CPY001

from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.models import GraphObjective
from ravage.agent_core.autonomous_graph.probe_scope import (
    scope_graph_probe_state,
)
from ravage.probe_suite_parts.sqli.sqli_targets import _sqli_targets

TARGET_URL = "http://127.0.0.1:8765/"
QUERY_URL = f"{TARGET_URL}search.php"
POLLUTED_URL = f"{TARGET_URL}graphql/"


def _state() -> AgentState:
    return AgentState(
        surface={
            "origin": TARGET_URL.rstrip("/"),
            "target_url": TARGET_URL,
            "endpoints": [
                {"url": POLLUTED_URL, "hints": ["query"], "priority": 100},
                {"url": QUERY_URL, "hints": ["query"], "priority": 18},
            ],
            "parameters": [
                {
                    "name": "transport",
                    "locations": [POLLUTED_URL],
                    "priority": 100,
                }
            ],
            "pages": [{"url": POLLUTED_URL}],
            "request_templates": [
                {
                    "url": POLLUTED_URL,
                    "method": "POST",
                    "payload_field": "transport",
                }
            ],
        },
        signals={
            "endpoints": [POLLUTED_URL, QUERY_URL],
            "parameters": ["transport", "filter", "email"],
            "forms": [
                '<form action=\\"search.php\\" method=\\"POST\\">',
            ],
            "sqli_inputs": [
                json.dumps(
                    {
                        "kind": "form",
                        "url": POLLUTED_URL,
                        "input": "transport",
                    }
                ),
            ],
            "sqli_replays": [
                json.dumps(
                    {
                        "url": POLLUTED_URL,
                        "method": "POST",
                        "payload_field": "transport",
                    }
                ),
            ],
        },
    )


def _objective() -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction="Calibrate the observed query contract",
        endpoint=QUERY_URL,
        inputs=("filter", "email"),
        strategy="sqli_differential",
        expected_signal="typed differential or bounded disproof",
    )


def test_sql_probe_is_bound_to_objective_without_mutating_inherited_state() -> None:
    state = _state()
    original = state.to_json()

    scope = scope_graph_probe_state(
        state,
        objective=_objective(),
        action={"action": "run_probe", "probe": "sqli_differential"},
    )
    targets = _sqli_targets(scope.state)
    leading = targets[:4]

    assert scope.applied is True
    assert scope.endpoint == QUERY_URL
    assert state.to_json() == original
    assert leading
    assert {str(item["url"]) for item in leading} == {QUERY_URL}
    assert {str(item["input"]) for item in leading}.issubset({"filter", "email"})
    assert any(item["kind"] == "form" for item in leading)
    assert POLLUTED_URL not in json.dumps(scope.state.to_json())


def test_wrong_target_replays_and_confirmed_inputs_are_removed() -> None:
    scope = scope_graph_probe_state(
        _state(),
        objective=_objective(),
        action={"action": "run_probe", "probe": "filtered_query_bypass"},
    )

    assert scope.state.signals["sqli_inputs"] == []
    assert scope.state.signals["sqli_replays"] == []
    assert scope.state.surface["request_templates"] == []


def test_non_sql_or_non_probe_action_keeps_original_state() -> None:
    state = _state()
    objective = GraphObjective.create(
        family="exposure",
        instruction="Inspect bounded exposure",
        endpoint=QUERY_URL,
        inputs=("filter",),
        strategy="direct_exposure",
        expected_signal="target observation",
    )

    scope = scope_graph_probe_state(
        state,
        objective=objective,
        action={"action": "run_probe", "probe": "direct_exposure"},
    )

    assert scope.applied is False
    assert scope.state is state
