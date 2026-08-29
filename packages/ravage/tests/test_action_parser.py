from __future__ import annotations

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
