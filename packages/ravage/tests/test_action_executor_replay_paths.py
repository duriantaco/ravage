from __future__ import annotations

from ravage.agent_core import action_executor
from ravage.web_core.poc_validator import ValidationResult


def test_path_based_paired_replay_preserves_location_and_changed_query_input() -> None:
    target_url = "https://target.example/"
    control = {
        "method": "GET",
        "path": "/search?q=control",
        "evidence_role": "control",
    }
    exploit = {
        "method": "GET",
        "path": "/search?q=%27%20OR%201%3D1--",
        "evidence_role": "exploit",
    }

    assert action_executor._replay_material(control) != action_executor._replay_material(  # noqa: SLF001
        exploit
    )
    assert "' OR 1=1--" in action_executor._decoded_replay_request_text(exploit)  # noqa: SLF001
    assert action_executor._replay_input_shape(  # noqa: SLF001
        control,
        target_url=target_url,
    ) == ("query:q",)
    assert action_executor._changed_replay_parameters(  # noqa: SLF001
        {"steps": [control, exploit]},
        target_url=target_url,
    ) == [{"name": "q", "location": "query"}]


def test_url_and_path_aliases_have_the_same_replay_material() -> None:
    path_step = {"method": "GET", "path": "/search?q=control"}
    url_step = {"method": "GET", "url": "/search?q=control"}

    assert action_executor._replay_material(path_step) == action_executor._replay_material(  # noqa: SLF001
        url_step
    )


def test_replay_shape_preserves_repeated_query_parameter_multiplicity() -> None:
    target_url = "https://target.example/"
    repeated = {"method": "GET", "path": "/search?q=one&q=two"}
    single = {"method": "GET", "path": "/search?q=one"}

    assert action_executor._replay_input_shape(  # noqa: SLF001
        repeated,
        target_url=target_url,
    ) == ("query:q", "query:q")
    assert action_executor._replay_input_shape(  # noqa: SLF001
        repeated,
        target_url=target_url,
    ) != action_executor._replay_input_shape(  # noqa: SLF001
        single,
        target_url=target_url,
    )


def test_typed_raw_bodies_use_their_physical_named_parameter_shape() -> None:
    target_url = "https://target.example/"
    raw_form = {
        "method": "POST",
        "path": "/search",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "q=one&q=two&submit=Search",
    }
    raw_json = {
        "method": "POST",
        "path": "/api/search",
        "headers": {"Content-Type": "application/problem+json"},
        "body": '{"q":"one","submit":"Search"}',
    }

    assert action_executor._replay_input_shape(  # noqa: SLF001
        raw_form,
        target_url=target_url,
    ) == (
        "body:q",
        "body:q",
        "body:submit",
        "header:content-type",
    )
    assert action_executor._replay_parameter_values(  # noqa: SLF001
        raw_form,
        target_url=target_url,
    )[("body", "q")] == ("one", "two")
    assert action_executor._replay_input_shape(  # noqa: SLF001
        raw_json,
        target_url=target_url,
    ) == ("body:q", "body:submit", "header:content-type")
    assert action_executor._endpoint_params(  # noqa: SLF001
        "https://target.example/search",
        raw_step=raw_form,
    ) == [
        {"name": "q", "location": "body"},
        {"name": "q", "location": "body"},
        {"name": "submit", "location": "body"},
    ]


def test_paired_replay_rejects_one_sided_empty_input_shape() -> None:
    action = {
        "action": "validate_poc",
        "steps": [
            {
                "method": "POST",
                "path": "/submit",
                "evidence_role": "control",
            },
            {
                "method": "POST",
                "path": "/submit",
                "headers": {"Content-Type": "application/json"},
                "body": "not-json",
                "evidence_role": "exploit",
            },
        ],
    }
    validation = ValidationResult(
        ok=True,
        summary="paired response",
        steps=[
            {
                "index": 1,
                "request": {"method": "POST", "url": "/submit"},
                "response": {"status": 200},
                "checks": [{"kind": "status", "passed": True}],
            },
            {
                "index": 2,
                "request": {"method": "POST", "url": "/submit"},
                "response": {"status": 500},
                "checks": [{"kind": "status", "passed": True}],
            },
        ],
    )

    _step, failures = action_executor._paired_replay_evidence(  # noqa: SLF001
        action,
        validation=validation,
        target_url="https://target.example/",
    )

    assert "control and exploit replays must vary the same input shape" in failures


def test_replay_policy_does_not_url_decode_json_or_logical_form_values() -> None:
    encoded_template = {
        "method": "POST",
        "path": "/render",
        "headers": {"Content-Type": "application/json"},
        "body": '{"q":"%7B%7B7*7%7D%7D"}',
    }
    encoded_sql = {
        **encoded_template,
        "body": '{"q":"%55NION%20SELECT"}',
    }
    logical_form = {
        "method": "POST",
        "path": "/render",
        "form": {"q": "%7B%7B7*7%7D%7D"},
    }

    template_text = action_executor._decoded_replay_request_text(encoded_template)  # noqa: SLF001
    sql_text = action_executor._decoded_replay_request_text(encoded_sql)  # noqa: SLF001
    form_text = action_executor._decoded_replay_request_text(logical_form)  # noqa: SLF001
    assert "{{7*7}}" not in template_text
    assert "%7B%7B7*7%7D%7D" in template_text
    assert "union_select" not in action_executor._sql_injection_input_markers(  # noqa: SLF001
        sql_text
    )
    assert "{{7*7}}" not in form_text
