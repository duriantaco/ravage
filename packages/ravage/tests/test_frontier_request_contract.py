from __future__ import annotations

import json

from ravage.agent_core.frontier_request_contract import (
    action_satisfies_contract,
    detect_request_contract_issue,
    guard_message,
    observed_request_contracts,
    pending_contract_issue,
    resolved_message,
)

AJAX_CONTRACT = """
<script>
$.ajax({
  type: 'post',
  url: 'index.php',
  data: {
    username: username,
    password: password,
    submit: 'submit'
  },
  success: handleResponse
});
</script>
"""


def _post_action(*, include_submit: bool) -> dict[str, object]:
    fields = "{'username': username, 'password': password}"
    if include_submit:
        fields = "{'username': username, 'password': password, 'submit': 'submit'}"
    return {
        "action": "run_python",
        "code": (
            "data = urllib.parse.urlencode(" + fields + ").encode()\n"
            "urllib.request.Request(base + 'index.php', data=data, method='POST')"
        ),
    }


def test_guard_detects_constant_field_omitted_from_target_defined_ajax_replay() -> None:
    issue = detect_request_contract_issue(
        _post_action(include_submit=False),
        AJAX_CONTRACT,
    )

    assert issue is not None
    assert issue.endpoint == "index.php"
    assert issue.method == "POST"
    assert [field.name for field in issue.fields] == [
        "username",
        "password",
        "submit",
    ]
    assert issue.missing_fields == ("submit",)


def test_exact_target_defined_request_contract_resolves_guard() -> None:
    issue = detect_request_contract_issue(
        _post_action(include_submit=False),
        AJAX_CONTRACT,
    )

    assert issue is not None
    assert action_satisfies_contract(_post_action(include_submit=True), issue)


def test_discovery_fetch_is_not_misclassified_as_a_broken_replay() -> None:
    action = {
        "action": "run_python",
        "code": "print(urllib.request.urlopen(base).read().decode())",
    }

    assert detect_request_contract_issue(action, AJAX_CONTRACT) is None


def test_guard_state_round_trips_through_persistent_worker_messages() -> None:
    issue = detect_request_contract_issue(
        _post_action(include_submit=False),
        AJAX_CONTRACT,
    )
    assert issue is not None
    guarded = [{"role": "user", "content": guard_message(issue)}]

    assert pending_contract_issue(guarded) == issue

    resolved = [
        *guarded,
        {"role": "user", "content": resolved_message(issue)},
    ]
    assert pending_contract_issue(resolved) is None


def test_structured_tool_observation_yields_target_request_contract() -> None:
    observation = json.dumps(
        {
            "requests": [
                {
                    "method": "GET",
                    "url": "http://127.0.0.1:8765/",
                    "form": {
                        "action": "http://127.0.0.1:8765/index.php",
                        "method": "POST",
                        "inputs": ["username", "password"],
                    },
                }
            ]
        }
    )

    contracts = observed_request_contracts(observation)

    assert len(contracts) == 1
    assert contracts[0].endpoint == "http://127.0.0.1:8765/index.php"
    assert contracts[0].method == "POST"
    assert [field.name for field in contracts[0].fields] == [
        "username",
        "password",
    ]


def test_structured_field_constant_is_preserved() -> None:
    observation = json.dumps(
        {
            "form": {
                "action": "/index.php",
                "method": "POST",
                "inputs": [
                    {"name": "username", "value": ""},
                    {"name": "submit", "value": "submit"},
                ],
            }
        }
    )

    contracts = observed_request_contracts(observation)

    assert len(contracts) == 1
    assert contracts[0].fields[0].constant_value is None
    assert contracts[0].fields[1].constant_value == "submit"


def test_structured_contract_survives_raw_control_byte_in_tool_observation() -> None:
    observation = (
        '{"body_snippet":"target byte\u0000",'
        '"form":{"action":"/index.php","method":"POST",'
        '"inputs":["username","password"]}}'
    ).replace("\\u0000", "\x00")

    contracts = observed_request_contracts(observation)

    assert len(contracts) == 1
    assert contracts[0].endpoint == "/index.php"
    assert contracts[0].method == "POST"


def test_docker_wrapped_stdout_yields_embedded_client_contract() -> None:
    observation = json.dumps(
        {
            "command": ["docker", "run", "tool-image", "curl", "/index.php"],
            "exit_code": 0,
            "stdout": AJAX_CONTRACT,
            "stderr": "",
        }
    )

    contracts = observed_request_contracts(observation)

    assert len(contracts) == 1
    assert contracts[0].endpoint == "index.php"
    assert contracts[0].method == "POST"
    assert [field.name for field in contracts[0].fields] == [
        "username",
        "password",
        "submit",
    ]


def test_run25_partial_data_block_cannot_promote_callback_as_request_field() -> None:
    filtered_stdout = """
      type: 'post',
      url: 'index.php',
      data: {
        username: username,
        password: password,
      success: handleResponse
      } else if (response === "password") {
    """
    observation = json.dumps(
        {
            "command": ["python3", "print filtered target lines"],
            "exit_code": 0,
            "stdout": filtered_stdout,
        }
    )

    assert observed_request_contracts(observation) == ()


def test_agent_authored_command_cannot_define_target_request_contract() -> None:
    observation = json.dumps(
        {
            "command": ["python3", AJAX_CONTRACT],
            "exit_code": 0,
            "stdout": "target returned no client request contract",
        }
    )

    assert observed_request_contracts(observation) == ()
