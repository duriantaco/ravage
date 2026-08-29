from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_closure_obligation import (
    action_advances_closure_obligation,
    closure_handoff_rejection_count,
    closure_objective_matches_obligation,
    closure_obligation_after_checkpoint,
    closure_obligation_completed_by_result,
    closure_obligation_context,
    closure_obligation_from_observation,
    closure_obligation_objective,
    closure_obligation_worker_attempted,
    mark_closure_obligation_attempted,
    pending_closure_obligation,
    record_closure_handoff_rejection,
    remember_closure_obligation,
)
from ravage.agent_core.frontier_extraction_memory import ExtractionCheckpoint
from ravage.agent_core.frontier_route import FrontierObjective


def _sql_result(
    extracted: list[dict[str, object]],
    *,
    proofs: list[str] | None = None,
    login_attempts: list[dict[str, object]] | None = None,
) -> str:
    return json.dumps(
        {
            "ok": True,
            "probe": "sqli_exploit",
            "findings": [
                {
                    "type": "sql_boolean_extraction_summary",
                    "extracted": extracted,
                    "proofs": proofs or [],
                    "login_attempts": login_attempts or [],
                    "auth_bypass_attempts": [],
                }
            ],
        }
    )


def test_partial_identifier_extraction_requires_focused_paired_secret_action() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "accounts", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )

    assert obligation is not None
    assert obligation.stage == "paired_secret"
    assert not action_advances_closure_obligation(
        {"action": "run_probe", "probe": "sqli_exploit"},
        obligation,
    )
    assert not action_advances_closure_obligation(
        {"action": "validate_poc", "steps": ["claim admin as proof"]},
        obligation,
    )
    assert action_advances_closure_obligation(
        {
            "action": "run_python",
            "code": (
                "# continue the existing HTTP boolean oracle\n"
                "expr='select password from accounts limit 1'\n"
                "urllib.request.urlopen(request)"
            ),
        },
        obligation,
    )
    assert action_advances_closure_obligation(
        {
            "action": "run_python",
            "code": (
                'payloads=["admin\' OR 1=1-- -", "x\')) OR 1=1-- -"]\n'
                "for payload in payloads:\n"
                "    post(login_url, {'username':'admin', 'password':payload})"
            ),
        },
        obligation,
    )
    assert not action_advances_closure_obligation(
        {
            "action": "run_command",
            "command": (
                "for password in admin password qwerty; do "
                "curl -d username=admin -d password=$password /index.php; done"
            ),
        },
        obligation,
    )


def test_paired_secret_stage_prefers_bounded_auth_bypass_before_extraction() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "users", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )

    assert obligation is not None
    assert "First run one finite" in obligation.required_transition
    assert "password-side SQL authentication-bypass matrix" in (obligation.required_transition)
    assert "Only if that bounded matrix" in obligation.required_transition


def test_successful_auth_bypass_completes_paired_secret_stage_without_extraction() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "users", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )
    assert obligation is not None
    action = {
        "action": "run_python",
        "code": (
            'payloads=["admin\' OR 1=1-- -", "x\')) OR 1=1-- -"]\n'
            "for payload in payloads:\n"
            "    response=post(login_url, {'username':'admin', 'password':payload})"
        ),
    }
    observation = json.dumps(
        {
            "stdout": (
                'LOGIN_RESPONSE={"response":"Success"}\n'
                "POST_LOGIN_URL=/dashboard.php\n"
                "POST_LOGIN_TITLE=Dashboard\n"
            )
        }
    )

    assert closure_obligation_completed_by_result(
        action,
        obligation,
        tool_ok=True,
        observation=observation,
    )


def test_run24_failed_extractor_does_not_release_paired_secret_obligation() -> None:
    state = AgentState()
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "users", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )
    assert obligation is not None
    action = {
        "action": "run_python",
        "code": (
            "expr='select password from users limit 0,1'\n"
            "value=extract_with_ascii_substring(expr)\n"
            "requests.post(login_url, data={'password': value})"
        ),
    }
    remember_closure_obligation(state, obligation)

    completed = closure_obligation_completed_by_result(
        action,
        obligation,
        tool_ok=False,
        observation="TimeoutError: timed out",
    )

    assert not completed
    assert pending_closure_obligation(state) == obligation


def test_structured_paired_secret_advances_to_authenticated_transition() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "users", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )
    assert obligation is not None
    action = {
        "action": "run_python",
        "code": (
            "expr='select password from users limit 0,1'\nvalue=extract_with_ascii_substring(expr)"
        ),
    }
    observation = _sql_result(
        [
            {"table": "users", "column": "username", "row": 0, "value": "admin"},
            {"table": "users", "column": "password", "row": 0, "value": "hash"},
        ]
    )

    assert closure_obligation_completed_by_result(
        action,
        obligation,
        tool_ok=True,
        observation=observation,
    )


def test_run26_checkpoint_advances_paired_secret_without_claiming_access() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "users", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )
    assert obligation is not None
    action = {
        "action": "run_python",
        "code": (
            "for position in range(1,33):\n"
            "    value += extract('select password from users limit 0,1')\n"
            "print(requests.post('/index.php', data={'password': value}).text)"
        ),
    }
    value = "7d39307ae824e70052c0aa16816a9b16"
    checkpoint = ExtractionCheckpoint.create(
        objective_fingerprint="proof-objective",
        family="sql_injection",
        endpoint="/index.php",
        candidate_kind="password",
        position=len(value),
        expected_length=len(value),
        prefix=value,
        complete=True,
    )

    advanced = closure_obligation_after_checkpoint(obligation, checkpoint)

    assert advanced is not None
    assert advanced.stage == "authenticated_transition"
    assert {artifact.column for artifact in advanced.artifacts} == {
        "username",
        "password",
    }
    assert closure_obligation_completed_by_result(
        action,
        obligation,
        tool_ok=True,
        observation='LOGIN_BODY={"response":"password"}',
        checkpoint=checkpoint,
    )


def test_closure_route_is_fingerprinted_once_per_evidence_epoch() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "users", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )
    assert obligation is not None
    template = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:contract_specialist",
        expected_signal="run the contract specialist",
        evidence_refs=("replay-contract:contract",),
    )

    routed = closure_obligation_objective(template, obligation)
    repeated = closure_obligation_objective(routed, obligation)
    different_parent = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal="change the payload semantics",
        evidence_refs=(
            "replay-contract:contract",
            "material:parent-specific-route-evidence",
        ),
    )
    routed_from_different_parent = closure_obligation_objective(
        different_parent,
        obligation,
    )

    assert routed == repeated
    assert routed == routed_from_different_parent
    assert closure_objective_matches_obligation(routed, obligation)
    assert not routed.payload_class.endswith("contract_specialist")
    assert "closure_paired_secret" in routed.payload_class
    assert obligation.required_transition in routed.expected_signal


def test_negative_access_markers_do_not_complete_authenticated_transition() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result(
            [
                {"table": "users", "column": "username", "row": 0, "value": "admin"},
                {"table": "users", "column": "password", "row": 0, "value": "hash"},
            ]
        ),
        family="sql_injection",
    )
    assert obligation is not None
    action = {
        "action": "run_python",
        "code": "login_response=post(login_url, credentials, cookies=session.cookies)",
    }
    rejected = json.dumps(
        {
            "stdout": (
                'LOGIN_RESPONSE={"response":"password"}\n'
                "POST_LOGIN_TITLE=Login\n"
                "POST_LOGIN_HAS_UPLOAD=False\n"
                "POST_LOGIN_HAS_INVALID=True\n"
                "COOKIEJAR=PHPSESSID=fresh\n"
            )
        }
    )

    assert not closure_obligation_completed_by_result(
        action,
        obligation,
        tool_ok=True,
        observation=rejected,
    )


def test_positive_protected_access_marker_completes_authenticated_transition() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result(
            [
                {"table": "users", "column": "username", "row": 0, "value": "admin"},
                {"table": "users", "column": "password", "row": 0, "value": "secret"},
            ]
        ),
        family="sql_injection",
    )
    assert obligation is not None
    action = {
        "action": "run_python",
        "code": "dashboard=post(login_url, credentials, cookies=session.cookies)",
    }
    accessed = json.dumps(
        {
            "stdout": (
                'LOGIN_RESPONSE={"response":"success"}\n'
                "POST_LOGIN_TITLE=Dashboard\n"
                "POST_LOGIN_HAS_UPLOAD=True\n"
            )
        }
    )

    assert closure_obligation_completed_by_result(
        action,
        obligation,
        tool_ok=True,
        observation=accessed,
    )


def test_closure_handoff_counter_and_worker_attempt_are_persistent() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "users", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )
    assert obligation is not None
    state = AgentState()

    assert (
        closure_handoff_rejection_count(
            state,
            obligation=obligation,
            worker_id="worker-001",
        )
        == 0
    )
    assert (
        record_closure_handoff_rejection(
            state,
            obligation=obligation,
            worker_id="worker-001",
        )
        == 1
    )
    restored = AgentState.from_json(state.to_json())
    assert (
        closure_handoff_rejection_count(
            restored,
            obligation=obligation,
            worker_id="worker-001",
        )
        == 1
    )

    action = {
        "action": "run_python",
        "code": (
            "expr='select password from users limit 0,1'\n"
            "print(requests.post('/index.php', data={'username':expr}).text)"
        ),
    }
    restored.attempts.append(
        {
            "frontier_worker_id": "worker-001",
            "selected_action": action,
        }
    )
    assert closure_obligation_worker_attempted(
        restored,
        obligation=obligation,
        worker_id="worker-001",
    )


def test_complete_credential_pair_requires_authenticated_transition() -> None:
    obligation = closure_obligation_from_observation(
        _sql_result(
            [
                {"table": "accounts", "column": "username", "row": 0, "value": "admin"},
                {"table": "accounts", "column": "password", "row": 0, "value": "hash"},
            ]
        ),
        family="sql_injection",
    )

    assert obligation is not None
    assert obligation.stage == "authenticated_transition"
    assert action_advances_closure_obligation(
        {
            "action": "run_python",
            "code": "requests.post(login_url, data=credentials, cookies=session.cookies)",
        },
        obligation,
    )


def test_proof_bearing_extraction_opens_no_obligation() -> None:
    observation = _sql_result(
        [{"table": "secrets", "column": "value", "row": 0, "value": "proof-value"}],
        proofs=["proof-value"],
    )

    assert closure_obligation_from_observation(observation, family="sql_injection") is None


def test_obligation_is_persistent_but_releases_after_one_focused_attempt() -> None:
    state = AgentState()
    obligation = closure_obligation_from_observation(
        _sql_result([{"table": "accounts", "column": "username", "row": 0, "value": "admin"}]),
        family="sql_injection",
    )
    assert obligation is not None

    remember_closure_obligation(state, obligation)
    restored = AgentState.from_json(state.to_json())

    assert pending_closure_obligation(restored) == obligation
    assert closure_obligation_context(restored) == obligation.to_json()

    mark_closure_obligation_attempted(restored, obligation)

    assert pending_closure_obligation(restored) is None
    assert closure_obligation_context(restored) is None


def test_complete_findings_survive_a_middle_clipped_request_trace() -> None:
    complete = _sql_result(
        [{"table": "accounts", "column": "username", "row": 0, "value": "admin"}]
    )
    findings = json.loads(complete)["findings"]
    clipped = (
        '{"ok":true,"findings":'
        + json.dumps(findings)
        + ',"requests":[{"body_len":581\n...[truncated from middle]...\n'
    )

    obligation = closure_obligation_from_observation(
        clipped,
        family="sql_injection",
    )

    assert obligation is not None
    assert obligation.stage == "paired_secret"
