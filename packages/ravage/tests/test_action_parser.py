from __future__ import annotations

import json

import pytest
from ravage.agent_core.action_parser import parse_action


def test_parse_action_repairs_two_json_objects_by_using_first_valid_action() -> None:
    text = (
        '{"action":"run_command","task_id":"surface-map","command":"curl -i $RAVAGE_TARGET_URL"}\n'
        '{"action":"final","summary":"extra object should not burn a turn"}'
    )

    action = parse_action(text)

    assert action["action"] == "run_command"
    assert action["command"] == "curl -i $RAVAGE_TARGET_URL"


def test_parse_action_ignores_braces_inside_json_strings() -> None:
    text = '{"action":"run_command","task_id":"surface-map","command":"printf \'{not-json}\'"}'

    action = parse_action(text)

    assert action["action"] == "run_command"
    assert action["command"] == "printf '{not-json}'"


def test_validate_poc_accepts_bounded_finding_metadata() -> None:
    action = parse_action(
        """{
          "action": "validate_poc",
          "steps": [{"method": "GET", "url": "/search?q=%27", "expect_status": 500}],
          "finding": {
            "vuln_class": "sql_injection",
            "severity": "high",
            "hypothesis": "The q parameter reaches an SQL query.",
            "impact": "An unauthenticated user can alter query execution.",
            "exploit_steps": ["Send an apostrophe in q and observe the database error."]
          }
        }"""
    )

    assert action["action"] == "validate_poc"
    assert isinstance(action["finding"], dict)


def test_validate_poc_rejects_model_authored_proof_fields() -> None:
    action = parse_action(
        """{
          "action": "validate_poc",
          "steps": [{"method": "GET", "url": "/", "expect_status": 200}],
          "finding": {
            "vuln_class": "information_disclosure",
            "severity": "low",
            "hypothesis": "Debug data is exposed.",
            "impact": "Internal implementation details are disclosed.",
            "exploit_steps": ["Fetch the debug route."],
            "proof": {"response_final": "model-authored evidence"}
          }
        }"""
    )

    assert action["action"] == "invalid"
    assert "executor-owned fields: proof" in str(action["error"])


def test_validate_poc_rejects_incomplete_finding_metadata() -> None:
    action = parse_action(
        '{"action":"validate_poc","steps":[{"url":"/"}],'
        '"finding":{"vuln_class":"ssrf","severity":"high"}}'
    )

    assert action["action"] == "invalid"
    assert action["error"] == "validate_poc finding requires hypothesis"


def test_validate_poc_accepts_url_or_path_steps_with_supported_body_shapes() -> None:
    action = parse_action(
        json.dumps(
            {
                "action": "validate_poc",
                "steps": [
                    {"method": "GET", "path": "/health", "expect_status": 200},
                    {
                        "method": "POST",
                        "url": "/login",
                        "form": {"username": "guest"},
                    },
                    {
                        "method": "PATCH",
                        "path": "/profile",
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"name":"guest"}',
                    },
                ],
            }
        )
    )

    assert action["action"] == "validate_poc"


def test_http_methods_are_canonicalized_after_validation() -> None:
    direct = parse_action(
        '{"action":"http_request","method":" get ","path":"/health"}'
    )
    replay = parse_action(
        '{"action":"validate_poc","steps":'
        '[{"method":" patch ","path":"/profile","body":"{}"}]}'
    )

    assert direct["method"] == "GET"
    assert replay["steps"] == [
        {"method": "PATCH", "path": "/profile", "body": "{}"}
    ]


@pytest.mark.parametrize(
    ("steps", "error"),
    [
        ([], "requires a non-empty steps list"),
        (["GET /"], "step 1 must be an object"),
        ([{"method": "GET"}], "step 1 requires url or path"),
        ([{"method": "GET", "path": 7}], "step 1 path must be a string"),
        (
            [{"method": "DELETE", "path": "/item"}],
            "step 1 method is not allowed",
        ),
        (
            [{"method": "GET", "path": "/item", "body": "payload"}],
            "step 1 GET request cannot include a body",
        ),
        (
            [{"method": "HEAD", "path": "/item", "form": {"key": "value"}}],
            "step 1 HEAD request cannot include a body",
        ),
        (
            [{"method": "OPTIONS", "path": "/item", "body": "payload"}],
            "step 1 OPTIONS request cannot include a body",
        ),
        (
            [{"method": "POST", "path": "/item", "json": {"key": "value"}}],
            "step 1 does not support json",
        ),
        (
            [{"method": "POST", "path": "/item", "headers": ["X-Test: value"]}],
            "step 1 headers must be an object",
        ),
        (
            [{"method": "POST", "path": "/item", "form": ["key=value"]}],
            "step 1 form must be an object",
        ),
        (
            [{"method": "POST", "path": "/item", "body": {"key": "value"}}],
            "step 1 body must be a string",
        ),
        (
            [
                {
                    "method": "POST",
                    "path": "/item",
                    "body": "raw",
                    "form": {"key": "value"},
                }
            ],
            "step 1 accepts only one of body or form",
        ),
        (
            [{"method": "GET", "path": f"/{index}"} for index in range(13)],
            "accepts at most 12 steps",
        ),
    ],
)
def test_validate_poc_rejects_invalid_step_shapes(
    steps: list[object],
    error: str,
) -> None:
    action = parse_action(json.dumps({"action": "validate_poc", "steps": steps}))

    assert action["action"] == "invalid"
    assert error in str(action["error"])
