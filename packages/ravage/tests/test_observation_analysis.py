from __future__ import annotations

import json

from ravage.agent_core.observation_analysis import (
    classify_action_result,
    extract_signals,
    observation_facts,
)
from ravage.agent_core.observation_sql import sqli_input_signals, sqli_replay_signals


def test_extract_signals_collects_form_input_names() -> None:
    html = (
        '<form action="login.php" method="POST">'
        '<input type="text" name="username">'
        '<input type="password" name="password">'
        "</form>"
    )

    signals = extract_signals(html)

    assert "login.php" in signals["endpoints"]
    assert {"username", "password"}.issubset(set(signals["parameters"]))


def test_extract_signals_ignores_local_tool_paths_as_endpoints() -> None:
    text = (
        "/Users/oha/.profile: line 3: pyenv: command not found\n"
        "/var/www/html/index.php: warning from server log\n"
        '<a href="/search.php?q=test">Search</a>'
    )

    signals = extract_signals(text)

    assert "/search.php?q=test" in signals["endpoints"]
    assert "q" in signals["parameters"]
    assert all("/Users/oha" not in endpoint for endpoint in signals["endpoints"])
    assert all("/var/www" not in endpoint for endpoint in signals["endpoints"])


def test_extract_signals_collects_fetch_endpoint_and_json_body_key() -> None:
    html = """
    <script>
      fetch('/jobs', {
        method: 'POST',
        body: JSON.stringify({ job_type: jobType })
      });
      const noisy = ['/jobs']:
    </script>
    """

    signals = extract_signals(html)

    assert "/jobs" in signals["endpoints"]
    assert "/jobs']:" not in signals["endpoints"]
    assert "job_type" in signals["parameters"]


def test_extract_signals_collects_jquery_ajax_endpoint_and_data_keys() -> None:
    html = """
    <script>
      $.ajax({
        url: '/total_loan_payments',
        type: 'GET',
        data: {
          principal: loanAmount,
          payment: monthlyPayment,
          term: loanTerm
        }
      });
    </script>
    """

    signals = extract_signals(html)

    assert "/total_loan_payments" in signals["endpoints"]
    assert "/total_loan_payments?principal=1&payment=1&term=1" in signals["endpoints"]
    assert {"principal", "payment", "term"}.issubset(set(signals["parameters"]))
    templates = [json.loads(value) for value in signals["request_templates"]]
    template = templates[0]
    assert template["source"] == "jquery_ajax"
    assert template["method"] == "GET"
    assert template["url"] == "/total_loan_payments"
    assert template["fields"] == {
        "principal": "1",
        "payment": "1",
        "term": "1",
    }


def test_extract_signals_collects_fetch_request_template() -> None:
    html = """
    <script>
      fetch('/api/accounts/update', {
        method: 'POST',
        headers: {'X-CSRF-Token': csrfToken},
        body: JSON.stringify({
          account_id: activeAccountId,
          role: 'admin',
          enabled: true
        })
      });
    </script>
    """

    signals = extract_signals(html)
    templates = [json.loads(value) for value in signals["request_templates"]]

    template = templates[0]
    assert "/api/accounts/update" in signals["endpoints"]
    assert {"account_id", "role", "enabled"}.issubset(set(signals["parameters"]))
    assert template["source"] == "fetch"
    assert template["method"] == "POST"
    assert template["url"] == "/api/accounts/update"
    assert template["fields"] == {
        "account_id": "1",
        "role": "admin",
        "enabled": "true",
    }


def test_low_delta_filtered_query_signal_does_not_confirm_sqli() -> None:
    payload = {
        "findings": [
            {
                "type": "filtered_query_bypass_signal",
                "blocked_payloads_seen": False,
                "delta": {
                    "status_changed": False,
                    "length_delta": 0,
                    "new_error_markers": [],
                },
                "input": {
                    "kind": "query_param",
                    "url": "http://localhost:64221/docs/oauth2-redirect",
                    "input": "EIO",
                },
                "replay": {
                    "method": "GET",
                    "url": "http://localhost:64221/docs/oauth2-redirect?EIO=%25",
                    "payload_field": "EIO",
                },
            }
        ]
    }

    assert sqli_input_signals(payload) == []
    assert sqli_replay_signals(payload) == []


def test_observation_facts_warn_about_missing_requests_and_shell_quoting() -> None:
    text = (
        "ModuleNotFoundError: No module named 'requests'\n"
        "unexpected EOF while looking for matching `\"'"
    )

    facts = observation_facts(text)

    assert "python requests module unavailable; use urllib from the standard library" in facts
    assert "shell quoting failed; use Python urllib encoding for quote-heavy payloads" in facts


def test_empty_secret_sweep_is_not_new_surface() -> None:
    outcome = classify_action_result(
        ok=True,
        repeat_count=1,
        text='{"ok": true, "probe": "secret_sweep", "findings": []}',
    )

    assert outcome == "observed"


def test_failed_local_traceback_is_not_target_error_evidence() -> None:
    outcome = classify_action_result(
        ok=False,
        repeat_count=1,
        text="Traceback (most recent call last):\nRuntimeError: local tool failed",
    )

    assert outcome == "blocked"


def test_failed_local_python_exception_is_not_target_error_evidence() -> None:
    outcome = classify_action_result(
        ok=False,
        repeat_count=1,
        text="ValueError: exception while constructing the local request",
    )

    assert outcome == "blocked"


def test_successful_target_sql_error_remains_confirmed() -> None:
    outcome = classify_action_result(
        ok=True,
        repeat_count=1,
        text="target response: SQL syntax error near the supplied value",
        trusted_target_evidence=True,
    )

    assert outcome == "confirmed_signal"


def test_structured_finding_retains_evidence_provenance_when_action_failed() -> None:
    outcome = classify_action_result(
        ok=False,
        repeat_count=1,
        text=json.dumps(
            {
                "ok": False,
                "probe": "sqli_differential",
                "findings": [{"type": "sql_injection_error_signal"}],
            }
        ),
        trusted_target_evidence=True,
    )

    assert outcome == "confirmed_signal"


def test_repeated_structured_finding_outweighs_repeat_classification() -> None:
    outcome = classify_action_result(
        ok=True,
        repeat_count=2,
        text=json.dumps(
            {
                "ok": True,
                "probe": "api_behavior",
                "findings": [{"type": "authorization_boundary_signal"}],
            }
        ),
        trusted_target_evidence=True,
    )

    assert outcome == "confirmed_signal"


def test_successful_untrusted_process_output_cannot_self_attest_target_evidence() -> None:
    for text in (
        "SQL syntax error printed by a local helper",
        "root:x:0:0: printed fixture",
        json.dumps(
            {
                "ok": True,
                "probe": "sqli_differential",
                "findings": [{"type": "sql_injection_error_signal"}],
            }
        ),
    ):
        outcome = classify_action_result(ok=True, repeat_count=1, text=text)

        assert outcome == "observed"


def test_extract_signals_records_confirmed_sqli_input() -> None:
    signals = extract_signals(
        """
        {
          "probe": "sqli_differential",
          "findings": [
            {
              "type": "sql_injection_error_signal",
              "input": {
                "kind": "form",
                "url": "http://127.0.0.1/send.php",
                "input": "fullname"
              }
            }
          ]
        }
        """
    )

    assert signals["sqli_inputs"] == [
        '{"input": "fullname", "kind": "form", "url": "http://127.0.0.1/send.php"}'
    ]


def test_extract_signals_records_confirmed_sqli_replay_template() -> None:
    replay = {
        "method": "POST",
        "url": "http://127.0.0.1/login",
        "payload_field": "username",
        "form": {
            "username": "1' OR SLEEP(2)-- -",
            "password": "RavagePass123!",
            "submit": "submit",
        },
        "required_fields": ["password", "submit", "username"],
    }

    signals = extract_signals(
        json.dumps(
            {
                "probe": "sqli_differential",
                "findings": [{"type": "blind_sql_injection_timing_signal", "replay": replay}],
            }
        )
    )

    payload = json.loads(signals["sqli_replays"][0])
    assert payload["payload_field"] == "username"
    assert payload["form"]["submit"] == "submit"
    assert payload["source"] == "replay"


def test_extract_signals_records_data_query_replay_template() -> None:
    replay = {
        "method": "POST",
        "url": "http://127.0.0.1/send.php",
        "payload_field": "fullname",
        "form": {"fullname": "'", "email": "a@example.test", "submit": "submit"},
        "required_fields": ["email", "fullname", "submit"],
    }

    signals = extract_signals(
        json.dumps(
            {
                "probe": "data_query",
                "findings": [
                    {
                        "type": "data_query_signal",
                        "input": "fullname",
                        "form": {"action": "http://127.0.0.1/send.php", "method": "POST"},
                        "expected": "sql",
                        "replay": replay,
                    }
                ],
            }
        )
    )

    assert "data_query_signal" in signals["markers"]
    assert json.loads(signals["sqli_inputs"][0]) == {
        "input": "fullname",
        "kind": "form",
        "url": "http://127.0.0.1/send.php",
    }
    payload = json.loads(signals["sqli_replays"][0])
    assert payload["payload_field"] == "fullname"
    assert payload["form"]["submit"] == "submit"


def test_extract_signals_promotes_sql_literal_comment_findings() -> None:
    signals = extract_signals(
        json.dumps(
            {
                "probe": "sqli_differential",
                "findings": [
                    {
                        "type": "sql_literal_comment_bypass_signal",
                        "input": {
                            "kind": "query_param",
                            "url": "http://127.0.0.1/",
                            "input": "category",
                        },
                        "payload": "premium'--",
                        "replay": {
                            "method": "GET",
                            "url": "http://127.0.0.1/?category=premium%27--",
                        },
                    }
                ],
            }
        )
    )

    assert "sql_literal_comment_bypass_signal" in signals["markers"]
    assert json.loads(signals["sqli_inputs"][0]) == {
        "input": "category",
        "kind": "query_param",
        "url": "http://127.0.0.1/",
    }


def test_extract_signals_records_openapi_routes_as_targets() -> None:
    signals = extract_signals(
        json.dumps(
            {
                "probe": "direct_exposure",
                "findings": [
                    {
                        "type": "openapi_route_signal",
                        "routes": [
                            {
                                "method": "POST",
                                "url": "http://127.0.0.1/profile",
                                "parameters": [
                                    {
                                        "name": "data_file",
                                        "location": "query",
                                        "type": "string",
                                    }
                                ],
                            }
                        ],
                        "forms": [
                            {
                                "action": "http://127.0.0.1/profile?data_file=ravage",
                                "method": "POST",
                                "enctype": "multipart/form-data",
                                "inputs": [{"name": "avatar", "type": "file"}],
                                "categories": ["api", "openapi", "upload", "file"],
                            }
                        ],
                    }
                ],
            }
        )
    )

    assert "http://127.0.0.1/profile" in signals["endpoints"]
    assert {"data_file", "avatar"}.issubset(set(signals["parameters"]))
    form = json.loads(signals["forms"][0])
    assert form["categories"] == ["api", "openapi", "upload", "file"]


def test_extract_signals_records_scoped_sqli_boolean_template() -> None:
    signals = extract_signals(
        json.dumps(
            {
                "probe": "sqli_differential",
                "findings": [
                    {
                        "type": "blind_sql_injection_boolean_signal",
                        "input": {
                            "kind": "query_param",
                            "url": "http://127.0.0.1/search?q=a",
                            "input": "q",
                        },
                        "true_payload": "a' OR 1=1-- -",
                    }
                ],
            }
        )
    )

    payload = json.loads(signals["sqli_boolean_templates"][0])
    assert payload == {
        "input": "q",
        "kind": "query_param",
        "template": "a' OR ({cond})-- -",
        "url": "http://127.0.0.1/search?q=a",
    }


def test_extract_signals_records_canonical_host_header() -> None:
    signals = extract_signals(
        json.dumps(
            {
                "probe": "surface_map",
                "findings": [
                    {
                        "type": "canonical_host_header_signal",
                        "headers": {"Host": "localhost"},
                    }
                ],
            }
        )
    )

    assert signals["canonical_hosts"] == ["localhost"]


def test_extract_signals_records_xss_contexts() -> None:
    signals = extract_signals(
        json.dumps(
            {
                "probe": "xss_context",
                "findings": [
                    {
                        "type": "xss_reflection_context",
                        "input": {"input": "name", "url": "http://127.0.0.1/page"},
                        "contexts": [
                            {
                                "context": "js_string_double",
                                "tag_name": "script",
                                "quote_char": '"',
                            }
                        ],
                    }
                ],
            }
        )
    )

    payload = json.loads(signals["xss_contexts"][0])
    assert payload["context"] == "js_string_double"
    assert payload["input"] == "name"
    assert payload["tag_name"] == "script"


def test_extract_signals_records_file_read_inputs() -> None:
    primitive = {
        "target": {
            "kind": "query_param",
            "url": "http://127.0.0.1/post.php?id=post.php",
            "input": "id",
        },
        "payload": "../../../../../proc/self/root/etc/passwd",
        "signal": {"kind": "local_file_read"},
    }
    signals = extract_signals(
        json.dumps(
            {
                "probe": "file_fetch_parser",
                "findings": [{"type": "file_read_primitive", "primitive": primitive}],
            }
        )
    )

    # The confirmation finding type is promoted into typed markers alongside the
    # derived file_read_confirmed marker.
    assert "file_read_confirmed" in signals["markers"]
    assert "file_read_primitive" in signals["markers"]
    assert signals["file_read_inputs"] == [json.dumps(primitive, sort_keys=True)]


def test_extract_signals_records_authenticated_followup_forms() -> None:
    form = {
        "action": "http://127.0.0.1/profile",
        "method": "POST",
        "enctype": "multipart/form-data",
        "inputs": [{"name": "loan_file", "type": "file"}],
        "categories": ["authenticated", "upload", "file"],
        "auth_headers": {"Cookie": "session=valid"},
    }
    signals = extract_signals(
        json.dumps(
            {
                "probe": "stateful_session",
                "findings": [
                    {
                        "type": "auth_session_followup_signal",
                        "forms": [form],
                    }
                ],
            }
        )
    )

    assert signals["forms"] == [json.dumps(form, sort_keys=True)]


def test_extract_signals_records_structured_cookie_candidates() -> None:
    signals = extract_signals(
        json.dumps(
            {
                "probe": "stateful_session",
                "findings": [
                    {
                        "type": "insecure_deserialization_cookie_signal",
                        "cookies": ["PHPSESSID=abc", "data=Tzo="],
                        "cookie_signal": "data=Tzo=",
                    }
                ],
            }
        )
    )

    assert "data=Tzo=" in signals["cookies"]
    assert "PHPSESSID=abc" in signals["cookies"]
