from __future__ import annotations

import json

import pytest
from ravage.agent_core.action_executor import _command_timeout
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.agent_strategy import ActionLedger, action_fingerprint
from ravage.agent_core.ai_agent import _model_action, _repeat_context
from ravage.agent_core.primitive_state import promote_primitives


def test_command_timeout_floors_at_ten_seconds() -> None:
    assert _command_timeout(1) == 10
    assert _command_timeout(3) == 10
    assert _command_timeout(None) == 10
    assert _command_timeout(30) == 30  # larger explicit values honored
    assert _command_timeout(999) == 120  # still capped


def test_action_fingerprint_changes_with_context() -> None:
    action = {"action": "run_probe", "probe": "cms_exposure"}
    assert action_fingerprint(action) != action_fingerprint(action, context="host:localhost")
    assert action_fingerprint(action, context="host:localhost") == action_fingerprint(
        action, context="host:localhost"
    )


def test_repeat_context_reflects_canonical_host() -> None:
    state = AgentState()
    assert _repeat_context(state) == ""
    state.signals["canonical_hosts"] = ["localhost"]
    assert _repeat_context(state) == "host:localhost"


def test_probe_repeat_is_unblocked_after_canonical_host_discovered() -> None:
    ledger = ActionLedger()
    action = {"action": "run_probe", "probe": "cms_exposure"}

    # Two runs before canonical host is known.
    assert ledger.remember(action, context="") == 1
    assert ledger.remember(action, context="") == 2
    # Canonical host discovered -> the same probe is a fresh action, not a repeat.
    assert ledger.remember(action, context="host:localhost") == 1


def test_locked_primitive_overrides_custom_model_loop() -> None:
    state = AgentState(turn=5)
    state.signals["markers"] = ["blind_sql_injection_boolean_signal"]
    promote_primitives(state)

    action = _model_action(
        '{"action":"run_python","task_id":"data-query","code":"print(1)","timeout_seconds":1}',
        state=state,
        turn=5,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "sqli_exploit"
    assert action["task_id"] == "data-query"


def test_locked_primitive_override_stops_after_two_specialist_attempts() -> None:
    state = AgentState(turn=5)
    state.signals["markers"] = ["sql_injection_error_signal"]
    promote_primitives(state)
    forced = {"action": "run_probe", "task_id": "data-query", "probe": "sqli_exploit"}
    state.ledger.remember(forced, context=_repeat_context(state))
    state.ledger.remember(forced, context=_repeat_context(state))

    action = _model_action(
        '{"action":"run_python","task_id":"data-query","code":"print(1)","timeout_seconds":1}',
        state=state,
        turn=5,
        max_turns=40,
    )

    assert action["action"] == "run_python"


def test_shadow_router_does_not_replace_model_selected_sqli_specialist_with_login_probe() -> None:
    state = AgentState(turn=1)
    state.signals = {
        "forms": [
            '{"action":"http://127.0.0.1/login","inputs":[{"name":"username"},{"name":"password","type":"password"}]}'
        ],
        "parameters": ["q", "username", "password"],
        "markers": ["login", "username", "password", "search", "query"],
    }
    state.surface = {
        "target_url": "http://127.0.0.1:8088",
        "forms": [
            {
                "action": "http://127.0.0.1:8088/catalog",
                "method": "GET",
                "inputs": [{"name": "q"}],
            },
            {
                "action": "http://127.0.0.1:8088/login",
                "method": "POST",
                "inputs": [{"name": "username"}, {"name": "password", "type": "password"}],
            },
        ],
    }

    action = _model_action(
        '{"action":"run_probe","task_id":"data-query","probe":"sqli_differential","strategy":"sql_differential_verifier"}',
        state=state,
        turn=1,
        max_turns=30,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "sqli_differential"
    assert action["strategy"] == "sql_differential_verifier"


def test_shadow_router_keeps_sqli_for_secret_category_filter_over_reflection() -> None:
    state = AgentState(turn=1)
    state.surface = {
        "visible_description": "Find the posts that belong to the secret category",
        "forms": [
            {
                "action": "http://127.0.0.1/",
                "method": "GET",
                "inputs": [{"name": "category"}],
            }
        ],
    }
    state.signals = {
        "forms": ['{"action":"http://127.0.0.1/","method":"GET","inputs":[{"name":"category"}]}'],
        "parameters": ["category"],
        "reflections": ["category value reflected in option text"],
        "markers": ["secret category", "hidden posts"],
    }

    action = _model_action(
        '{"action":"run_probe","task_id":"data-query","probe":"sqli_differential","strategy":"data_query"}',
        state=state,
        turn=1,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "sqli_differential"
    assert action["strategy"] == "data_query"


def test_apache_2450_surface_forces_file_read_before_noisy_auth_or_xss_routes() -> None:
    state = AgentState(turn=1)
    state.surface = {
        "target_url": "http://127.0.0.1:8088/",
        "origin": "http://127.0.0.1:8088",
        "server": "Apache/2.4.50 (Unix)",
        "forms": [
            {
                "action": "http://127.0.0.1:8088/",
                "method": "GET",
                "inputs": [{"name": "username"}, {"name": "password"}, {"name": "message"}],
            }
        ],
        "pages": [{"headers": {"server": "Apache/2.4.50 (Unix)"}}],
    }
    state.signals = {
        "markers": [
            "apache_2_4_path_traversal_surface",
            "login",
            "username",
            "password",
            "reflected",
        ],
        "reflections": ["message reflected"],
    }

    action = _model_action(
        '{"action":"run_probe","task_id":"stateful-session","probe":"default_credentials","strategy":"auth"}',
        state=state,
        turn=1,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "file_read_extract"
    assert action["strategy"] == "forced_evidence_apache_traversal"


def test_shadow_router_does_not_replace_password_change_idor_with_default_credentials() -> None:
    state = AgentState(turn=1)
    state.surface = {
        "visible_description": (
            "IDOR lets a low-privilege user change another user's password and log in as admin."
        )
    }
    state.signals = {
        "forms": [
            '{"action":"http://127.0.0.1/login.php","inputs":[{"name":"username"},{"name":"password","type":"password"}]}'
        ],
        "parameters": ["username", "password", "userId", "oldPassword", "newPassword"],
        "markers": ["idor", "password"],
    }

    action = _model_action(
        '{"action":"run_probe","task_id":"stateful-session","probe":"idor_boundary","strategy":"stateful-session"}',
        state=state,
        turn=1,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "idor_boundary"
    assert action["strategy"] == "stateful-session"


def test_description_evidence_does_not_override_live_primitive_closer() -> None:
    state = AgentState(
        turn=2,
        primitives={"default_credentials_confirmed": 1},
        surface={"visible_description": "Authenticated users can schedule reminder notifications."},
    )

    action = _model_action(
        '{"action":"run_probe","task_id":"stateful-session","probe":"idor_boundary","strategy":"close_authenticated_boundary"}',
        state=state,
        turn=2,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "idor_boundary"
    assert action["strategy"] == "close_authenticated_boundary"


def test_exhausted_tier_one_primitive_closer_does_not_suppress_fallback_route() -> None:
    state = AgentState(
        turn=3,
        primitives={"default_credentials_confirmed": 1},
        surface={"visible_description": "Authenticated users can schedule reminder notifications."},
        actions=[
            {
                "turn": 2,
                "action": "run_probe",
                "probe": "idor_boundary",
                "outcome": "same_as_before",
                "repeat_count": 3,
            }
        ],
    )

    action = _model_action(
        '{"action":"run_probe","task_id":"stateful-session","probe":"idor_boundary","strategy":"retry_closer"}',
        state=state,
        turn=3,
        max_turns=40,
    )

    assert action["probe"] == "ssti_fingerprint"
    assert action["strategy"] == "visible_reminder_template_flow"


def test_authenticated_unavailable_tier_one_closer_does_not_suppress_fallback_route() -> None:
    state = AgentState(
        turn=2,
        primitives={"cms_exposure_observed": 1},
        surface={
            "authenticated_identity": "managed-user",
            "visible_description": "Authenticated users can schedule reminder notifications.",
        },
    )

    action = _model_action(
        '{"action":"run_probe","task_id":"flag-and-secret-sweep","probe":"cms_exposure","strategy":"retry_closer"}',
        state=state,
        turn=2,
        max_turns=40,
    )

    assert action["probe"] == "ssti_fingerprint"
    assert action["strategy"] == "visible_reminder_template_flow"


def test_authenticated_unavailable_locked_closer_does_not_suppress_fallback_route() -> None:
    state = AgentState(
        turn=2,
        primitives={"browser_boundary_confirmed": 1},
        surface={
            "authenticated_identity": "managed-user",
            "visible_description": "Authenticated users can schedule reminder notifications.",
        },
    )

    action = _model_action(
        '{"action":"run_probe","task_id":"api-behavior","probe":"browser_boundary","strategy":"retry_closer"}',
        state=state,
        turn=2,
        max_turns=40,
    )

    assert action["probe"] == "ssti_fingerprint"
    assert action["strategy"] == "visible_reminder_template_flow"


def test_cookie_tamper_objective_does_not_force_xss_or_direct_exposure() -> None:
    state = AgentState(turn=5)
    state.surface = {
        "visible_description": (
            "This is a simple example of how to exploit a cookie that is encrypted "
            "with AES-CBC without a MAC. Change the username in the cookie to admin"
        ),
        "forms": [
            {
                "action": "http://127.0.0.1:8088/login",
                "method": "POST",
                "inputs": [{"name": "username"}, {"name": "password", "type": "password"}],
            }
        ],
    }
    state.signals = {
        "forms": [
            '{"action":"http://127.0.0.1:8088/login","inputs":[{"name":"username"},{"name":"password","type":"password"}]}'
        ],
        "markers": [
            "login",
            "username",
            "password",
            "reflected input reached an HTML sink with xss marker",
        ],
        "reflections": ["username reflected in login response"],
    }
    for probe in ("default_credentials", "xss_context", "reflection_value_boundary"):
        forced = {"action": "run_probe", "task_id": "stateful-session", "probe": probe}
        state.ledger.remember(forced, context=_repeat_context(state))
        state.ledger.remember(forced, context=_repeat_context(state))

    action = _model_action(
        (
            '{"action":"run_command","task_id":"stateful-session",'
            '"command":"curl -i -sS -c /tmp/c -b /tmp/c -d username=test1 -d password=test1 http://127.0.0.1:8088/login"}'
        ),
        state=state,
        turn=5,
        max_turns=40,
    )

    assert action["action"] == "run_command"


def test_xss_objective_keeps_model_selected_dom_execution() -> None:
    state = AgentState(turn=2)
    state.surface = {
        "visible_description": "Execute XSS with the string XSS, for example alert('XSS').",
        "forms": [
            {
                "action": "http://127.0.0.1:8088/page",
                "method": "POST",
                "inputs": [{"name": "solution"}],
            }
        ],
    }
    state.signals = {
        "forms": [
            '{"action":"http://127.0.0.1:8088/page","method":"POST","inputs":[{"name":"solution"}]}'
        ],
        "markers": ["login", "username", "password", "SQL syntax error", "SOAP XML parser", "xss"],
        "reflections": ["solution reflected in page"],
    }

    action = _model_action(
        '{"action":"run_probe","task_id":"input-reflection","probe":"dom_execution","strategy":"client_execution"}',
        state=state,
        turn=2,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "dom_execution"
    assert action["strategy"] == "client_execution"


def test_identity_cookie_object_route_evidence_forces_idor_boundary() -> None:
    state = AgentState(turn=8)
    state.signals["cookies"] = ['access_token="Bearer MQ=="']
    state.signals["endpoints"] = ["http://127.0.0.1/company/1/jobs"]

    action = _model_action(
        '{"action":"run_command","task_id":"stateful-session","command":"python3 manual_loop.py"}',
        state=state,
        turn=8,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "idor_boundary"
    assert action["strategy"] == "forced_cookie_identity_idor"


def test_authenticated_object_route_evidence_forces_idor_boundary() -> None:
    state = AgentState(turn=8)
    state.signals["auth_headers"] = ["Authorization: Bearer header.payload.signature"]
    state.signals["endpoints"] = ["http://127.0.0.1/company/1/jobs"]

    action = _model_action(
        '{"action":"run_command","task_id":"stateful-session","command":"python3 manual_loop.py"}',
        state=state,
        turn=8,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "idor_boundary"
    assert action["strategy"] == "forced_authenticated_object_idor"


def test_authenticated_object_idor_guard_stops_after_two_attempts() -> None:
    state = AgentState(turn=8)
    state.signals["auth_headers"] = ["Authorization: Bearer header.payload.signature"]
    state.signals["endpoints"] = ["http://127.0.0.1/company/1/jobs"]
    forced = _model_action(
        '{"action":"run_command","task_id":"stateful-session","command":"python3 manual_loop.py"}',
        state=state,
        turn=8,
        max_turns=40,
    )
    state.ledger.remember(forced, context=_repeat_context(state))
    state.ledger.remember(forced, context=_repeat_context(state))

    action = _model_action(
        '{"action":"run_command","task_id":"stateful-session","command":"python3 manual_loop.py"}',
        state=state,
        turn=9,
        max_turns=40,
    )

    assert action["action"] == "run_command"


def test_php_auth_cookie_surface_forces_cookie_deserialization_before_ssti() -> None:
    state = AgentState(turn=8)
    state.signals = {
        "forms": [
            '{"action":"http://127.0.0.1/sign-in.php","inputs":[{"name":"username"},{"name":"password","type":"password"}]}',
            '{"action":"http://127.0.0.1/sign-up.php","inputs":[{"name":"username"},{"name":"password","type":"password"}]}',
        ],
        "cookies": ["PHPSESSID=abc123; path=/"],
        "markers": ["set-cookie"],
    }
    state.surface = {
        "headers": {"x-powered-by": "PHP/7.1.33"},
        "forms": [
            {"action": "http://127.0.0.1/sign-in.php", "method": "POST"},
            {"action": "http://127.0.0.1/sign-up.php", "method": "POST"},
        ],
    }
    state.actions.append(
        {"action": "run_probe", "probe": "default_credentials", "outcome": "no_hit"}
    )

    action = _model_action(
        '{"action":"run_probe","task_id":"server-rendering","probe":"ssti_fingerprint","strategy":"ssti_fingerprint_verifier"}',
        state=state,
        turn=8,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "cookie_deserialization"
    assert action["strategy"] == "forced_evidence_php_auth_cookie_deserialization"


def test_identity_cookie_idor_guard_stops_after_two_attempts() -> None:
    state = AgentState(turn=8)
    state.signals["cookies"] = ['access_token="Bearer MQ=="']
    state.signals["endpoints"] = ["http://127.0.0.1/company/1/jobs"]
    forced = _model_action(
        '{"action":"run_command","task_id":"stateful-session","command":"python3 manual_loop.py"}',
        state=state,
        turn=8,
        max_turns=40,
    )
    state.ledger.remember(forced, context=_repeat_context(state))
    state.ledger.remember(forced, context=_repeat_context(state))

    action = _model_action(
        '{"action":"run_command","task_id":"stateful-session","command":"python3 manual_loop.py"}',
        state=state,
        turn=9,
        max_turns=40,
    )

    assert action["action"] == "run_command"


@pytest.mark.parametrize(
    ("marker", "expected_probe", "expected_strategy"),
    [
        (
            "TemplateSyntaxError in Jinja expression {{7*7}}",
            "ssti_fingerprint",
            "forced_evidence_ssti",
        ),
        (
            "reflected input reached an HTML sink with xss marker",
            "xss_context",
            "forced_evidence_xss_context",
        ),
        (
            "mapped xss_reflection_context in html_attribute",
            "reflection_value_boundary",
            "forced_evidence_xss_value_boundary",
        ),
        ("SQLite SQL syntax error near quote", "sqli_differential", "forced_evidence_sqli"),
        (
            "preg_match expects parameter 2 to be string, array given",
            "preg_match_subject",
            "forced_evidence_preg_match_subject",
        ),
        (
            "search response says some item is filtered by blocked keyword",
            "filtered_query_bypass",
            "forced_evidence_filtered_query",
        ),
        (
            "multipart/form-data avatar upload includes filename field",
            "file_fetch_parser",
            "forced_evidence_file_fetch_parser",
        ),
        ("SOAP WSDL XML parser endpoint exposes wsdl", "xxe_boundary", "forced_evidence_xxe"),
        (
            "host lookup field shells out to nslookup",
            "command_boundary",
            "forced_evidence_command_boundary",
        ),
        (
            "webhook callback url may fetch internal metadata",
            "ssrf_boundary",
            "forced_evidence_ssrf",
        ),
        (
            "csrf token plus SameSite cookie on logout form",
            "csrf_session",
            "forced_evidence_csrf_session",
        ),
        (
            "Access-Control-Allow-Origin reflects Origin with credentials",
            "browser_boundary",
            "forced_evidence_browser_boundary",
        ),
        (
            "Authorization: Bearer eyJhbGci token with JWT alg header",
            "jwt_exploit",
            "forced_evidence_jwt",
        ),
        (
            "GraphQL endpoint exposes __schema introspection",
            "graphql_exploit",
            "forced_evidence_graphql",
        ),
        (
            "wordpress wp-content backup-migration plugin detected",
            "cms_exposure",
            "forced_evidence_cms",
        ),
        (
            "Werkzeug debugger traceback console locked page",
            "werkzeug_console",
            "forced_evidence_werkzeug",
        ),
        (
            "base64 pickle serialized __reduce__ cookie deserialization",
            "cookie_deserialization",
            "forced_evidence_cookie_deserialization",
        ),
        (
            "admin config backup .env debug source exposed",
            "direct_exposure",
            "forced_evidence_direct_exposure",
        ),
    ],
)
def test_evidence_routes_force_matching_specialist(
    marker: str, expected_probe: str, expected_strategy: str
) -> None:
    state = AgentState(turn=6)
    state.signals["markers"] = [marker]

    action = _model_action(
        '{"action":"run_command","task_id":"manual","command":"python3 manual_loop.py"}',
        state=state,
        turn=6,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == expected_probe
    assert action["strategy"] == expected_strategy


def test_evidence_route_does_not_override_same_specialist_choice() -> None:
    state = AgentState(turn=6)
    state.signals["markers"] = ["TemplateSyntaxError in Jinja expression {{7*7}}"]

    action = _model_action(
        '{"action":"run_probe","task_id":"server-rendering","probe":"ssti_fingerprint"}',
        state=state,
        turn=6,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "ssti_fingerprint"


def test_multi_finding_observed_url_form_forces_ssrf_before_final() -> None:
    state = AgentState(
        turn=35,
        flags=["flag{first-branch}"],
        surface={
            "continue_after_proof": True,
            "target_url": "http://127.0.0.1:8088",
            "forms": [],
        },
    )
    state.signals["forms"] = [
        json.dumps(
            {
                "action": "http://127.0.0.1:8088/admin/preview",
                "auth_headers": {"Cookie": "auth=forged"},
                "inputs": [
                    {
                        "name": "url",
                        "type": "url",
                        "value": "http://127.0.0.1:9000/metadata",
                    }
                ],
                "method": "GET",
            },
            sort_keys=True,
        )
    ]

    action = _model_action(
        '{"action":"final","summary":"No remaining branches."}',
        state=state,
        turn=35,
        max_turns=40,
    )

    assert action["action"] == "run_probe"
    assert action["probe"] == "ssrf_boundary"
    assert action["strategy"] == "forced_multi_finding_observed_url_fetch"


def test_multi_finding_url_route_does_not_override_ssrf_specialist_choice() -> None:
    state = AgentState(
        turn=25,
        flags=["flag{first-branch}"],
        surface={
            "continue_after_proof": True,
            "forms": [
                {
                    "action": "http://127.0.0.1:8088/admin/preview",
                    "method": "GET",
                    "inputs": [
                        {
                            "name": "callback_url",
                            "value": "https://example.test/status",
                        }
                    ],
                }
            ],
        },
    )

    action = _model_action(
        '{"action":"run_probe","task_id":"file-fetch-parser",'
        '"probe":"ssrf_boundary","strategy":"model_selected_ssrf"}',
        state=state,
        turn=25,
        max_turns=40,
    )

    assert action["probe"] == "ssrf_boundary"
    assert action["strategy"] == "model_selected_ssrf"


def test_multi_finding_url_route_stops_after_ssrf_proof() -> None:
    state = AgentState(
        turn=37,
        flags=["flag{first-branch}", "flag{ssrf-branch}"],
        surface={
            "continue_after_proof": True,
            "forms": [
                {
                    "inputs": [
                        {
                            "name": "url",
                            "value": "http://127.0.0.1:9000/metadata",
                        }
                    ]
                }
            ],
        },
        actions=[
            {
                "action": "run_probe",
                "probe": "ssrf_boundary",
                "outcome": "flag_candidate",
            }
        ],
    )

    action = _model_action(
        '{"action":"final","summary":"SSRF branch already closed."}',
        state=state,
        turn=37,
        max_turns=40,
    )

    assert action["action"] == "final"


def test_single_finding_run_still_finishes_after_first_flag() -> None:
    state = AgentState(
        turn=8,
        flags=["flag{only-required-proof}"],
        surface={
            "continue_after_proof": False,
            "forms": [
                {
                    "inputs": [
                        {
                            "name": "url",
                            "value": "http://127.0.0.1:9000/metadata",
                        }
                    ]
                }
            ],
        },
    )

    action = _model_action(
        '{"action":"final","summary":"Required proof captured."}',
        state=state,
        turn=8,
        max_turns=40,
    )

    assert action["action"] == "final"
    assert "strategy" not in action


def test_evidence_route_stops_after_two_attempts() -> None:
    state = AgentState(turn=6)
    state.signals["markers"] = ["TemplateSyntaxError in Jinja expression {{7*7}}"]
    forced = _model_action(
        '{"action":"run_command","task_id":"manual","command":"python3 manual_loop.py"}',
        state=state,
        turn=6,
        max_turns=40,
    )
    state.ledger.remember(forced, context=_repeat_context(state))
    state.ledger.remember(forced, context=_repeat_context(state))

    action = _model_action(
        '{"action":"run_command","task_id":"manual","command":"python3 manual_loop.py"}',
        state=state,
        turn=7,
        max_turns=40,
    )

    assert action["action"] == "run_command"
