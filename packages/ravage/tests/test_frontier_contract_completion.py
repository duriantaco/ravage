from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_contract_completion import (
    objective_has_observed_request_contract,
    objective_requires_observed_request_contract,
)
from ravage.agent_core.frontier_contract_memory import (
    ContractRouteContext,
    remember_observed_request_contracts,
)
from ravage.agent_core.frontier_replay_contract import (
    authoritative_replay_for_family,
)
from ravage.agent_core.frontier_route import FrontierObjective

TARGET_URL = "http://127.0.0.1:8765"
AJAX_CONTRACT = """
$.ajax({
  type: 'post',
  url: 'index.php',
  data: {username: username, password: password, submit: 'submit'}
});
"""


def _objective(*, family: str, payload_class: str) -> FrontierObjective:
    return FrontierObjective.create(
        family=family,
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class=payload_class,
        expected_signal="preserve the target-observed request contract",
    )


def test_only_confirmed_sql_request_contract_objectives_require_observation() -> None:
    required = _objective(
        family="sql_injection",
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
    )
    proof_channel = _objective(
        family="sql_injection",
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
    )
    other_family = _objective(
        family="template_injection",
        payload_class="confirmed_primitive:ssti_confirmed:request_contract",
    )
    unconfirmed = _objective(
        family="sql_injection",
        payload_class="specialist:request_contract",
    )

    assert objective_requires_observed_request_contract(required)
    assert not objective_requires_observed_request_contract(proof_channel)
    assert not objective_requires_observed_request_contract(other_family)
    assert not objective_requires_observed_request_contract(unconfirmed)


def test_matching_target_observed_contract_completes_objective_requirement() -> None:
    objective = _objective(
        family="sql_injection",
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
    )
    state = AgentState()

    assert not objective_has_observed_request_contract(
        state,
        objective,
        target_url=TARGET_URL,
    )

    remember_observed_request_contracts(
        state,
        AJAX_CONTRACT,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family=objective.family,
            objective_endpoint=objective.endpoint,
            objective_inputs=objective.inputs,
        ),
    )

    assert objective_has_observed_request_contract(
        state,
        objective,
        target_url=TARGET_URL,
    )


def test_base_replay_candidate_does_not_complete_observation_requirement() -> None:
    state = AgentState(
        signals={
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "source": "replay",
                        "url": f"{TARGET_URL}/?username=x",
                    }
                )
            ]
        }
    )
    contract = authoritative_replay_for_family(
        state,
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert contract is not None
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=contract.endpoint,
        inputs=(contract.payload_field,),
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
        expected_signal="validate the candidate against target-produced output",
        evidence_refs=(contract.evidence_ref,),
    )

    assert not objective_has_observed_request_contract(
        state,
        objective,
        target_url=TARGET_URL,
    )


def test_contract_for_different_endpoint_does_not_complete_requirement() -> None:
    objective = _objective(
        family="sql_injection",
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
    )
    state = AgentState()
    remember_observed_request_contracts(
        state,
        AJAX_CONTRACT,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family=objective.family,
            objective_endpoint="/",
            objective_inputs=objective.inputs,
        ),
    )
    different_endpoint = FrontierObjective.create(
        family=objective.family,
        probe=objective.probe,
        endpoint="/admin/login.php",
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=objective.expected_signal,
    )

    assert not objective_has_observed_request_contract(
        state,
        different_endpoint,
        target_url=TARGET_URL,
    )
