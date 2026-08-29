from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_credential_replay import (
    detect_rejected_credential_replay,
    rejected_credential_replay_message,
    remember_rejected_credential_replay,
    remembered_rejected_credential_replays,
)
from ravage.agent_core.frontier_extraction_memory import ExtractionCheckpoint
from ravage.agent_core.frontier_route import FrontierObjective

HASH_LENGTH = 32


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract a replayable target value",
    )


def _checkpoint(value: str) -> ExtractionCheckpoint:
    objective = _objective()
    return ExtractionCheckpoint.create(
        objective_fingerprint=objective.fingerprint,
        family=objective.family,
        endpoint=objective.endpoint,
        candidate_kind="password",
        position=len(value),
        expected_length=len(value),
        prefix=value,
        complete=True,
    )


def test_rejected_hash_shaped_credential_becomes_durable_counterevidence() -> None:
    objective = _objective()
    value = "7d39307ae824e70052c0aa16816a9b16"
    replay = detect_rejected_credential_replay(
        objective=objective,
        checkpoint=_checkpoint(value),
        observation=json.dumps({"stdout": 'LOGIN_RESPONSE={"response":"password"}\n'}),
    )

    assert replay is not None
    assert replay.representation_hint == "hash_shaped"
    assert replay.candidate_length == HASH_LENGTH
    assert value not in json.dumps(replay.to_json())
    message = rejected_credential_replay_message(replay)
    assert "not a validated plaintext credential" in message
    assert "adjacent request field/sink" in message

    state = AgentState()
    assert remember_rejected_credential_replay(state, replay)
    assert not remember_rejected_credential_replay(state, replay)
    remembered = remembered_rejected_credential_replays(
        state,
        objective=objective,
    )
    assert len(remembered) == 1
    assert remembered[0]["candidate_digest"] == replay.candidate_digest


def test_successful_replay_does_not_open_representation_feedback() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"

    assert (
        detect_rejected_credential_replay(
            objective=_objective(),
            checkpoint=_checkpoint(value),
            observation='LOGIN_RESPONSE={"response":"Success"}',
        )
        is None
    )


def test_login_response_literal_in_docker_command_is_not_a_replay() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"
    observation = json.dumps(
        {
            "command": [
                "sh",
                "-lc",
                "body=post('admin',pw)\nprint('LOGIN_RESPONSE=',body)",
            ],
            "exit_code": 0,
            "stdout": "script completed without replay output\n",
        }
    )

    assert (
        detect_rejected_credential_replay(
            objective=_objective(),
            checkpoint=_checkpoint(value),
            observation=observation,
        )
        is None
    )


def test_run26_login_body_marker_rejects_hash_shaped_plaintext_replay() -> None:
    objective = _objective()
    value = "7d39307ae824e70052c0aa16816a9b16"
    action = {
        "action": "run_python",
        "code": (
            f"password='{value}'\n"
            "body=requests.post('/index.php', data={'username':'admin', "
            "'password':password}).text\n"
            "print('LOGIN_BODY='+body)"
        ),
    }

    replay = detect_rejected_credential_replay(
        objective=objective,
        checkpoint=_checkpoint(value),
        action=action,
        observation=json.dumps({"stdout": 'LOGIN_BODY={"response":"password"}\n'}),
    )

    assert replay is not None
    assert replay.representation_hint == "hash_shaped"
    assert replay.failure_marker == "password"


def test_run27_nested_login_replay_rejects_dynamically_extracted_hash() -> None:
    objective = _objective()
    value = "7d39307ae824e70052c0aa16816a9b16"
    action = {
        "action": "run_python",
        "code": (
            "password=extract_with_boolean_oracle()\n"
            "body=post_login('admin', password)\n"
            "print(json.dumps({'login_replay': {'password': password, "
            "'body': body}}))"
        ),
    }
    stdout = json.dumps(
        {
            "extracted": [
                {
                    "table": "users",
                    "row": 0,
                    "column": "password",
                    "value": value,
                }
            ],
            "login_replay": {
                "username": "admin",
                "password": value,
                "body": '{"response":"password"}',
                "headers": {"Set-Cookie": "PHPSESSID=fresh; path=/"},
            },
        },
        indent=2,
    )

    replay = detect_rejected_credential_replay(
        objective=objective,
        checkpoint=_checkpoint(value),
        action=action,
        observation=json.dumps(
            {
                "command": ["python3", "agent.py"],
                "stdout": stdout,
                "exit_code": 0,
            }
        ),
    )

    assert replay is not None
    assert replay.representation_hint == "hash_shaped"
    assert replay.failure_marker == "password"


def test_run27_nested_login_replay_in_command_only_is_not_detected() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"
    nested = json.dumps(
        {
            "login_replay": {
                "password": value,
                "body": '{"response":"password"}',
            }
        }
    )

    assert (
        detect_rejected_credential_replay(
            objective=_objective(),
            checkpoint=_checkpoint(value),
            action={"action": "run_python", "code": "print('no replay')"},
            observation=json.dumps(
                {
                    "command": ["python3", "-c", f"print({nested!r})"],
                    "stdout": "",
                    "exit_code": 0,
                }
            ),
        )
        is None
    )


def test_raw_target_failure_requires_action_to_replay_remembered_candidate() -> None:
    objective = _objective()
    value = "7d39307ae824e70052c0aa16816a9b16"
    observation = json.dumps(
        {
            "command": ["curl", "-d", "redacted"],
            "stdout": (
                "HTTP/1.1 200 OK\r\n"
                "Set-Cookie: PHPSESSID=new-session; path=/\r\n\r\n"
                '{"response":"password"}'
            ),
        }
    )
    unrelated = {"action": "run_command", "command": "curl /index.php"}
    replay = {
        "action": "run_command",
        "command": (
            f"curl /index.php --data-urlencode username=admin --data-urlencode password={value}"
        ),
    }

    assert (
        detect_rejected_credential_replay(
            objective=objective,
            checkpoint=_checkpoint(value),
            action=unrelated,
            observation=observation,
        )
        is None
    )
    detected = detect_rejected_credential_replay(
        objective=objective,
        checkpoint=_checkpoint(value),
        action=replay,
        observation=observation,
    )
    assert detected is not None
    assert detected.failure_marker == "password"
