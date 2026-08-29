from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_contract_memory import (
    ContractRouteContext,
    remember_observed_request_contracts,
    remembered_request_contracts,
)

TARGET_URL = "http://127.0.0.1:8765"
AJAX_CONTRACT = """
<script>
$.ajax({
  type: 'post',
  url: 'session/login.php',
  data: {
    username: username,
    password: password,
    submit: 'submit'
  }
});
</script>
"""
ROOT_DISCOVERED_CONTRACT = """
<script>
$.ajax({
  type: 'post',
  url: '/index.php',
  data: {
    username: username,
    password: password,
    submit: 'submit'
  }
});
</script>
"""


def test_target_contract_is_durable_and_supersedes_only_incompatible_sql_replay() -> None:
    stale = json.dumps(
        {
            "method": "GET",
            "url": f"{TARGET_URL}/?username=admin%27--",
            "payload_field": "username",
        },
        sort_keys=True,
    )
    unrelated = json.dumps(
        {
            "method": "GET",
            "url": f"{TARGET_URL}/items?id=1",
            "payload_field": "id",
        },
        sort_keys=True,
    )
    state = AgentState(signals={"sqli_replays": [stale, unrelated]})

    update = remember_observed_request_contracts(
        state,
        AJAX_CONTRACT,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint="/session/login.php",
            objective_inputs=("username",),
        ),
    )

    assert len(update.contracts) == 1
    assert update.superseded_sql_replays == 1
    remembered = remembered_request_contracts(state)
    assert remembered[0]["url"] == f"{TARGET_URL}/session/login.php"
    assert [item["name"] for item in remembered[0]["fields"]] == [
        "username",
        "password",
        "submit",
    ]

    active_replays = [json.loads(item) for item in state.signals["sqli_replays"]]
    assert any(item.get("payload_field") == "id" for item in active_replays)
    projected = next(item for item in active_replays if item.get("payload_field") == "username")
    assert projected["method"] == "POST"
    assert projected["form"] == {
        "username": "",
        "password": "",
        "submit": "submit",
    }
    assert projected["required_fields"] == ["username", "password", "submit"]
    assert projected["constant_fields"] == {"submit": "submit"}
    assert state.signals["frontier_superseded_sqli_replays"] == [stale]


def test_contract_memory_survives_agent_state_round_trip() -> None:
    state = AgentState()
    remember_observed_request_contracts(
        state,
        AJAX_CONTRACT,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint="session/login.php",
            objective_inputs=("username",),
        ),
    )

    restored = AgentState.from_json(state.to_json())

    assert remembered_request_contracts(restored) == remembered_request_contracts(state)
    assert restored.signals["sqli_replays"] == state.signals["sqli_replays"]


def test_unrelated_target_contract_does_not_change_active_route_state() -> None:
    state = AgentState(signals={"sqli_replays": ["preserve-me"]})

    update = remember_observed_request_contracts(
        state,
        AJAX_CONTRACT,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint="/different-handler",
            objective_inputs=("username",),
        ),
    )

    assert update.contracts == ()
    assert state.signals == {"sqli_replays": ["preserve-me"]}


def test_root_seed_accepts_same_origin_target_discovered_handler() -> None:
    stale = json.dumps(
        {
            "method": "GET",
            "url": f"{TARGET_URL}/?username=admin%27--",
            "payload_field": "username",
        },
        sort_keys=True,
    )
    state = AgentState(signals={"sqli_replays": [stale]})

    update = remember_observed_request_contracts(
        state,
        ROOT_DISCOVERED_CONTRACT,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint=f"{TARGET_URL}/?username=admin%27--",
            objective_inputs=("username",),
        ),
    )

    assert len(update.contracts) == 1
    assert update.superseded_sql_replays == 1
    remembered = remembered_request_contracts(state)
    assert remembered[0]["url"] == f"{TARGET_URL}/index.php"


def test_root_seed_rejects_cross_origin_target_contract() -> None:
    state = AgentState(signals={"sqli_replays": ["preserve-me"]})
    cross_origin = ROOT_DISCOVERED_CONTRACT.replace(
        "'/index.php'",
        "'https://outside.example/index.php'",
    )

    update = remember_observed_request_contracts(
        state,
        cross_origin,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint=TARGET_URL,
            objective_inputs=("username",),
        ),
    )

    assert update.contracts == ()
    assert state.signals == {"sqli_replays": ["preserve-me"]}
