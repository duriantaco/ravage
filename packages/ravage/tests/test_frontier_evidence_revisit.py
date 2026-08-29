from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_contract_memory import (
    ContractRouteContext,
    remember_observed_request_contracts,
)
from ravage.agent_core.frontier_evidence_revisit import (
    action_attempts_oracle_revisit,
    detect_evidence_revisit_issue,
    evidence_revisit_constraints,
    next_evidence_revisit_objective,
    objective_is_evidence_revisit,
    objective_requires_oracle_revisit,
)
from ravage.agent_core.frontier_replay_contract import (
    authoritative_replay_for_objective,
)
from ravage.agent_core.frontier_route import FrontierObjective
from ravage.agent_core.frontier_sql_oracle import remember_sql_oracle_contracts

TARGET_URL = "http://127.0.0.1:8765"
ENDPOINT = f"{TARGET_URL}/index.php"
TRUE_BODY = '{"response":"password"}'
FALSE_BODY = '{"response":"username"}'


def _template(
    *,
    evidence_refs: tuple[str, ...] = ("base-state:test",),
) -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=TARGET_URL,
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="close the confirmed SQL route",
        evidence_refs=evidence_refs,
    )


def _state_with_contract() -> AgentState:
    state = AgentState()
    remember_observed_request_contracts(
        state,
        """
        $.ajax({
          type: 'post',
          url: 'index.php',
          data: {username: username, password: password, submit: 'submit'},
          success: handleResponse
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


def _request(expr: str, body: str, digest: str) -> dict[str, object]:
    return {
        "phase": "boolean_probe",
        "expr": expr,
        "status": 200,
        "body_sha_hint": digest,
        "body_snippet": body,
        "method": "POST",
        "target": {
            "url": ENDPOINT,
            "input": "username",
            "method": "POST",
        },
    }


def _oracle_observation() -> str:
    return json.dumps(
        {
            "requests": [
                _request("1=1", TRUE_BODY, "true-digest"),
                _request("1=0", FALSE_BODY, "false-digest"),
                _request("2=2", TRUE_BODY, "true-digest"),
                _request("2=1", FALSE_BODY, "false-digest"),
            ]
        }
    )


def _calibration_action() -> dict[str, object]:
    return {
        "action": "run_python",
        "code": (
            "controls=('1=1','1=0','2=2','2=1')\n"
            f"url='{ENDPOINT}'\n"
            "records=[]\n"
            "for repetition in range(2):\n"
            "  for expr in controls:\n"
            '    payload=f"x\' OR ({expr})-- -"\n'
            "    data={'username': payload, 'password': '', 'submit': 'submit'}\n"
            "    response=requests.post(url, data=data)\n"
            "    records.append({'phase':'boolean_probe','expr':expr,"
            "'status':response.status_code,'body_snippet':response.text[:2000],"
            "'method':'POST','target':{'url':url,'input':'username',"
            "'method':'POST'}})\n"
            "print(json.dumps({'requests':records}))"
        ),
    }


def test_contract_epoch_authorizes_one_bounded_oracle_revisit() -> None:
    state = _state_with_contract()
    template = _template(
        evidence_refs=("base-state:test", "replay-contract:stale-get"),
    )

    objective = next_evidence_revisit_objective(
        state,
        (template,),
        target_url=TARGET_URL,
        attempted_fingerprints=set(),
    )

    assert objective is not None
    assert objective_requires_oracle_revisit(objective)
    assert objective.endpoint == ENDPOINT
    assert objective.inputs == ("username",)
    assert "evidence-revisit-contract:" in " ".join(objective.evidence_refs)
    assert "replay-contract:stale-get" not in objective.evidence_refs
    replay = authoritative_replay_for_objective(
        state,
        objective,
        target_url=TARGET_URL,
    )
    assert replay is not None
    assert replay.authoritative
    assert replay.method == "POST"
    assert "unchanged loop" in " ".join(evidence_revisit_constraints(objective))
    assert (
        next_evidence_revisit_objective(
            state,
            (template,),
            target_url=TARGET_URL,
            attempted_fingerprints={objective.fingerprint},
        )
        is None
    )


def test_oracle_revisit_rejects_broad_action_and_accepts_repeated_controls() -> None:
    state = _state_with_contract()
    objective = next_evidence_revisit_objective(
        state,
        (_template(),),
        target_url=TARGET_URL,
        attempted_fingerprints=set(),
    )
    assert objective is not None
    broad = {"action": "run_probe", "probe": "sqli_exploit"}

    issue = detect_evidence_revisit_issue(objective, broad)

    assert issue is not None
    assert issue.code == "bounded_repeated_sql_controls_required"
    raw_controls = {
        "action": "run_python",
        "code": (
            "controls=(\"'1'='1'\",\"'1'='0'\",\"'2'='2'\",\"'2'='1'\")\n"
            "for repeat in range(2):\n"
            "  for expr in controls:\n"
            "    print(requests.post('/index.php', data={'username':expr}).text)"
        ),
    }
    assert not action_attempts_oracle_revisit(raw_controls)
    assert action_attempts_oracle_revisit(_calibration_action())
    assert detect_evidence_revisit_issue(objective, _calibration_action()) is None


def test_new_oracle_epoch_authorizes_one_bounded_proof_revisit() -> None:
    state = _state_with_contract()
    calibration = next_evidence_revisit_objective(
        state,
        (_template(),),
        target_url=TARGET_URL,
        attempted_fingerprints=set(),
    )
    assert calibration is not None
    remember_sql_oracle_contracts(
        state,
        _oracle_observation(),
        objective=calibration,
    )

    proof = next_evidence_revisit_objective(
        state,
        (_template(),),
        target_url=TARGET_URL,
        attempted_fingerprints={calibration.fingerprint},
    )

    assert proof is not None
    assert objective_is_evidence_revisit(proof)
    assert not objective_requires_oracle_revisit(proof)
    assert proof.payload_class.endswith(":proof_channel")
    assert "sql-oracle:" in " ".join(proof.evidence_refs)
    assert "finite checkpointed extraction" in proof.expected_signal
    assert (
        next_evidence_revisit_objective(
            state,
            (_template(),),
            target_url=TARGET_URL,
            attempted_fingerprints={calibration.fingerprint, proof.fingerprint},
        )
        is None
    )
