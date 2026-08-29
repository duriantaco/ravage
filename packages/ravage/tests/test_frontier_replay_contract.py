from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_replay_contract import (
    authoritative_replay_for_family,
    authoritative_replay_for_objective,
    detect_replay_contract_issue,
    rebase_frontier_objective,
    replay_contract_expected_clause,
)
from ravage.agent_core.frontier_route import FrontierObjective

TARGET_URL = "http://127.0.0.1:8765"


def _run22_state() -> AgentState:
    return AgentState(
        signals={
            "request_templates": [
                json.dumps(
                    {
                        "method": "POST",
                        "source": "jquery_ajax",
                        "url": "index.php",
                    }
                )
            ],
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "replay_hint": "GET request is fully encoded in url.",
                        "source": "replay",
                        "url": f"{TARGET_URL}/?username=admin%27--",
                    }
                )
            ],
        },
        primitives={"sqli_confirmed": 6},
    )


def _target_observed_state() -> AgentState:
    return AgentState(
        signals={
            "sqli_replays": [
                json.dumps(
                    {
                        "constant_fields": {"submit": "submit"},
                        "encoding": "application/x-www-form-urlencoded",
                        "form": {
                            "username": "",
                            "password": "",
                            "submit": "submit",
                        },
                        "method": "POST",
                        "payload_field": "username",
                        "required_fields": ["username", "password", "submit"],
                        "source": "frontier_target_observation",
                        "url": f"{TARGET_URL}/index.php",
                    }
                )
            ]
        },
        primitives={"sqli_confirmed": 6},
    )


def test_base_tool_replay_is_a_candidate_until_target_observation() -> None:
    contract = authoritative_replay_for_family(
        _run22_state(),
        family="sql_injection",
        target_url=TARGET_URL,
        preferred_inputs=("username",),
    )

    assert contract is not None
    assert contract.method == "GET"
    assert contract.endpoint == f"{TARGET_URL}/"
    assert contract.payload_field == "username"
    assert contract.payload_location == "query"
    assert contract.source == "replay"
    assert not contract.authoritative
    assert contract.to_json()["authority"] == "candidate"


def test_objective_can_only_claim_the_exact_replay_fingerprint() -> None:
    state = _run22_state()
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
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract target proof through the preserved replay",
        evidence_refs=(contract.evidence_ref,),
    )

    assert (
        authoritative_replay_for_objective(
            state,
            objective,
            target_url=TARGET_URL,
        )
        == contract
    )


def test_request_contract_stage_can_correct_a_candidate_transport() -> None:
    contract = authoritative_replay_for_family(
        _run22_state(),
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert contract is not None
    wrong = {
        "action": "run_python",
        "code": (
            f"base='{TARGET_URL}/index.php'\n"
            "data=urllib.parse.urlencode({'username': payload}).encode()\n"
            "urllib.request.Request(base, data=data, method='POST')"
        ),
    }
    correct = {
        "action": "run_python",
        "code": (
            f"base='{TARGET_URL}/'\n"
            "url=base+'?'+urllib.parse.urlencode({'username': payload})\n"
            "urllib.request.urlopen(url)"
        ),
    }

    issue = detect_replay_contract_issue(wrong, contract)

    assert issue is not None
    assert issue.code == "authoritative_get_replayed_as_post"
    assert (
        detect_replay_contract_issue(
            wrong,
            contract,
            allow_candidate_correction=True,
        )
        is None
    )
    assert detect_replay_contract_issue(correct, contract) is None


def test_target_observed_contract_enforces_transport_and_required_fields() -> None:
    contract = authoritative_replay_for_family(
        _target_observed_state(),
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert contract is not None
    assert contract.authoritative
    assert contract.required_fields == ("password", "submit", "username")
    assert contract.fixed_parameters == (("submit", "submit"),)

    wrong_get = {
        "action": "run_python",
        "code": f"requests.get('{TARGET_URL}/index.php', params={{'username': x}})",
    }
    missing_fields = {
        "action": "run_python",
        "code": (f"requests.post('{TARGET_URL}/index.php', data={{'username': payload}})"),
    }
    correct = {
        "action": "run_python",
        "code": (
            f"requests.post('{TARGET_URL}/index.php', data={{'username': payload, "
            "'password': '', 'submit': 'submit'}})"
        ),
    }

    assert detect_replay_contract_issue(wrong_get, contract).code == (
        "authoritative_post_replayed_as_get"
    )
    issue = detect_replay_contract_issue(missing_fields, contract)
    assert issue is not None
    assert issue.code == "authoritative_required_fields_omitted"
    assert issue.missing_fields == ("password", "submit")
    assert detect_replay_contract_issue(correct, contract) is None


def test_pending_objective_rebases_to_target_observed_contract() -> None:
    candidate = authoritative_replay_for_family(
        _run22_state(),
        family="sql_injection",
        target_url=TARGET_URL,
    )
    observed = authoritative_replay_for_family(
        _target_observed_state(),
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert candidate is not None
    assert observed is not None
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=candidate.endpoint,
        inputs=(candidate.payload_field,),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal=(
            "calibrate SQL payload semantics" + replay_contract_expected_clause(candidate)
        ),
        evidence_refs=("primitive:sqli_confirmed:turn:6", candidate.evidence_ref),
    )

    rebased = rebase_frontier_objective(objective, observed)

    assert rebased.endpoint == f"{TARGET_URL}/index.php"
    assert rebased.inputs == ("username",)
    assert rebased.evidence_refs == (
        "primitive:sqli_confirmed:turn:6",
        observed.evidence_ref,
    )
    assert "method=POST" in rebased.expected_signal
    assert "required_fields=password,submit,username" in rebased.expected_signal
    assert "fixed_parameters=submit=submit" in rebased.expected_signal
    assert "Candidate base-tool" not in rebased.expected_signal


def test_untrusted_or_cross_origin_state_cannot_become_authoritative() -> None:
    state = AgentState(
        signals={
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "source": "model_guess",
                        "url": f"{TARGET_URL}/?username=x",
                    }
                ),
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "source": "replay",
                        "url": "https://example.invalid/?username=x",
                    }
                ),
            ]
        }
    )

    assert (
        authoritative_replay_for_family(
            state,
            family="sql_injection",
            target_url=TARGET_URL,
        )
        is None
    )
