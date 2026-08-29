from __future__ import annotations

import json

from ravage.agent_core.agent_specialists import available_specialists, recommended_specialists
from ravage.agent_core.agent_state import AgentState


def test_available_specialists_include_bounded_handoffs() -> None:
    probes = {item["probe"] for item in available_specialists()}

    assert {
        "sqli_differential",
        "sqli_exploit",
        "filtered_query_bypass",
        "direct_exposure",
        "api_behavior",
        "xss_context",
        "dom_execution",
        "ssti_fingerprint",
        "idor_boundary",
        "csrf_session",
        "browser_boundary",
        "default_credentials",
        "file_fetch_parser",
    }.issubset(probes)


def test_sqli_differential_is_recommended_for_query_like_form_inputs() -> None:
    state = AgentState()
    state.signals = {
        "forms": ['{"action":"http://127.0.0.1/search.php","inputs":[{"name":"q"}]}'],
        "parameters": ["q"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "sqli_differential"


def test_sqli_differential_is_recommended_for_query_request_templates() -> None:
    state = AgentState()
    state.signals = {
        "request_templates": [
            json.dumps(
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/jobs",
                    "fields": {"job_type": "ravage"},
                },
                sort_keys=True,
            )
        ],
        "markers": ["xml", "websocket", "cors"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "sqli_differential"


def test_default_credentials_are_recommended_before_sqli_for_login_forms() -> None:
    state = AgentState()
    state.signals = {
        "forms": ['{"action":"http://127.0.0.1/login","inputs":[{"name":"username"},{"name":"password","type":"password"}]}'],
        "parameters": ["username", "password"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "default_credentials"


def test_cookie_deserialization_is_recommended_for_php_auth_cookie_surface() -> None:
    state = AgentState()
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

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "cookie_deserialization"


def test_sqli_differential_is_not_recommended_for_generic_answer_form() -> None:
    state = AgentState()
    state.signals = {
        "forms": ['{"action":"http://127.0.0.1/page","inputs":[{"name":"solution"}]}'],
        "parameters": ["solution"],
    }

    recommended = recommended_specialists(state)

    assert "sqli_differential" not in {item["probe"] for item in recommended[:3]}


def test_recommended_specialists_are_evidence_driven() -> None:
    state = AgentState()
    state.signals = {
        "markers": ["filtered", "user exists", "no results"],
        "endpoints": ["http://127.0.0.1/search.php"],
    }
    state.actions = [{"action": "run_probe", "probe": "sqli_differential"}]

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "filtered_query_bypass"


def test_xss_context_is_recommended_for_reflected_inputs() -> None:
    state = AgentState()
    state.signals = {
        "reflections": ["name reflected in html body with xss sink evidence"],
        "markers": ["xss", "script"],
        "parameters": ["name"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "xss_context"


def test_ssti_fingerprint_is_recommended_before_auth_for_reflected_username_only() -> None:
    state = AgentState()
    state.signals = {
        "reflections": ["username reflected in html body"],
        "parameters": ["username"],
        "endpoints": ["http://127.0.0.1/?username=ravage"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "ssti_fingerprint"
    assert "default_credentials" not in {item["probe"] for item in recommended[:3]}


def test_reflection_value_boundary_is_recommended_for_mapped_xss_context() -> None:
    state = AgentState()
    state.signals = {
        "xss_contexts": [
            '{"type":"xss_reflection_context","context":"html_body","url":"http://127.0.0.1/page","input":"solution"}'
        ],
        "parameters": ["solution"],
    }
    state.actions = [{"action": "run_probe", "probe": "xss_context"}]

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "reflection_value_boundary"


def test_ssti_fingerprint_is_recommended_for_template_evidence() -> None:
    state = AgentState()
    state.signals = {
        "markers": ["template syntax marker observed", "{{7*7}}"],
        "parameters": ["name"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "ssti_fingerprint"


def test_api_behavior_is_recommended_for_graphql_and_jwt_evidence() -> None:
    state = AgentState()
    state.signals = {
        "markers": ["graphql endpoint", "JWT bearer token observed"],
        "endpoints": ["http://127.0.0.1/graphql"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "api_behavior"


def test_csrf_session_is_recommended_for_csrf_form_and_cookie_evidence() -> None:
    state = AgentState()
    state.signals = {
        "forms": [
            '{"action":"http://127.0.0.1/transfer","method":"POST","inputs":[{"name":"csrf_token","type":"hidden"},{"name":"amount"}]}'
        ],
        "cookies": ["session=abc123"],
        "markers": ["csrf", "set-cookie", "samesite"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "csrf_session"


def test_browser_boundary_is_recommended_for_cors_and_storage_evidence() -> None:
    state = AgentState()
    state.signals = {
        "markers": ["access-control-allow-origin", "localStorage", "websocket"],
        "endpoints": ["http://127.0.0.1/api/profile", "ws://127.0.0.1/ws"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "browser_boundary"


def test_file_fetch_parser_is_recommended_for_deserialization_evidence() -> None:
    state = AgentState()
    state.signals = {
        "markers": ["unsafe yaml.load deserialization", "pickle parser"],
        "forms": ['{"action":"http://127.0.0.1/upload","inputs":[{"name":"file","type":"file"}]}'],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "file_fetch_parser"


def test_idor_boundary_is_recommended_for_object_ids() -> None:
    state = AgentState()
    state.signals = {
        "parameters": ["user_id"],
        "endpoints": ["http://127.0.0.1/profile.php?user_id=1"],
        "markers": ["authorization boundary"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "idor_boundary"


def test_idor_boundary_is_recommended_for_password_change_idor_description() -> None:
    state = AgentState()
    state.surface = {
        "visible_description": (
            "The target has an IDOR where a low-privilege user can change another user's password."
        )
    }
    state.signals = {
        "parameters": ["userId", "oldPassword", "newPassword"],
        "endpoints": [
            "http://127.0.0.1/api/login.php",
            "http://127.0.0.1/profile.php",
            "http://127.0.0.1/api/change_password.php",
        ],
        "markers": ["idor"],
    }

    recommended = recommended_specialists(state)

    assert recommended[0]["probe"] == "idor_boundary"


def test_repeated_empty_specialist_is_demoted() -> None:
    state = AgentState()
    state.signals = {
        "markers": ["wordpress wp-content backup plugin redirect url"],
        "endpoints": ["http://127.0.0.1/wp-login.php"],
    }
    state.actions = [
        {
            "action": "run_probe",
            "probe": "cms_exposure",
            "outcome": "same_as_before",
            "repeat_count": 5,
        }
    ]

    recommended = recommended_specialists(state)
    probes = [item["probe"] for item in recommended]

    assert probes
    assert probes[0] != "cms_exposure"
