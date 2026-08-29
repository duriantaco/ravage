from __future__ import annotations

import json

from ravage.agent_core.frontier_structured_observation import (
    structured_output_mappings,
)


def test_run27_nested_stdout_is_decoded_as_trusted_structured_output() -> None:
    value = "7d39307ae824e70052c0aa16816a9b16"
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
                "final_url": "http://target/index.php",
                "headers": {"Set-Cookie": "PHPSESSID=fresh; path=/"},
            },
        },
        indent=2,
    )
    observation = json.dumps(
        {
            "command": ["python3", "agent.py"],
            "exit_code": 0,
            "stdout": stdout,
            "tool": "run_python",
        }
    )

    mappings = structured_output_mappings(observation)

    assert any(isinstance(item.get("extracted"), list) for item in mappings)
    assert any(item.get("password") == value for item in mappings)
    assert any(item.get("response") == "password" for item in mappings)


def test_structured_json_in_command_source_is_not_decoded_as_output() -> None:
    source_only = json.dumps(
        {
            "extracted": [
                {
                    "table": "users",
                    "row": 0,
                    "column": "password",
                    "value": "source-only-secret",
                }
            ]
        }
    )
    observation = json.dumps(
        {
            "command": ["python3", "-c", f"print({source_only!r})"],
            "exit_code": 0,
            "stdout": "",
            "tool": "run_python",
        }
    )

    assert structured_output_mappings(observation) == ()


def test_embedded_json_response_in_output_marker_is_decoded() -> None:
    mappings = structured_output_mappings('LOGIN_RESPONSE={"response":"password"}\n')

    assert {"response": "password"} in mappings
