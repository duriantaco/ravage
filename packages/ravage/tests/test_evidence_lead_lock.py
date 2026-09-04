from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core import evidence_lead_lock
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.evidence_lead_lock import (
    EvidenceLead,
    action_matches_lead,
    awaiting_session_lead,
    directive,
    lead_replay_generation,
    pending_lead,
    reactivate_for_session_change,
    record_aligned_outcome,
    release_for_session_reset,
    remember_from_probe_result,
    unresolved_lead,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def _ssti_probe_text(*, endpoint: str = "/generate") -> str:
    return json.dumps(
        {
            "probe": "ssti_fingerprint",
            "ok": True,
            "findings": [
                {
                    "type": "ssti_fingerprint_signal",
                    "signal": {"kind": "evaluated_expression", "observed": "49"},
                    "replay": {
                        "method": "POST",
                        "url": f"https://target.example{endpoint}",
                        "payload_field": "sentence",
                        "encoding": "application/x-www-form-urlencoded",
                        "form": {
                            "sentence": "<%= 7 * 7 %>",
                            "submit": "Render",
                        },
                    },
                    "baseline_replay": {
                        "method": "POST",
                        "url": f"https://target.example{endpoint}",
                        "payload_field": "sentence",
                        "encoding": "application/x-www-form-urlencoded",
                        "form": {"sentence": "lead-lock-secret", "submit": "Render"},
                    },
                    "response": {
                        "method": "POST",
                        "url": f"https://target.example{endpoint}",
                        "status": 200,
                        "body_len": 120,
                        "body_sha_hint": "abc123",
                    },
                    "delta": {"body_changed": True},
                }
            ],
            "requests": [],
            "errors": [],
        }
    )


def _open_ssti(state: AgentState | None = None) -> tuple[AgentState, EvidenceLead]:
    target = state or AgentState()
    lead = remember_from_probe_result(
        target,
        _ssti_probe_text(),
        {"action": "run_probe", "probe": "ssti_fingerprint"},
        "observation-1",
    )
    assert lead is not None
    return target, lead


def _aligned_action() -> dict[str, object]:
    return {
        "action": "http_request",
        "vuln_class": "ssti",
        "method": "POST",
        "url": "https://target.example/generate",
        "form": {"sentence": "<%= 8 * 8 %>", "submit": "Render"},
    }


def _confirmed_validate_payload() -> str:
    return json.dumps(
        {
            "finding_id": "finding-1",
            "vuln_class": "sql_injection",
            "assessment_source": "executor_policy",
            "endpoint": {
                "method": "GET",
                "url": "https://target.example/search",
                "params": [{"name": "q", "location": "query"}],
            },
            "input": {
                "method": "GET",
                "parameters": [{"name": "q", "location": "query"}],
                "affected_parameters": [{"name": "q", "location": "query"}],
            },
            "status": "confirmed",
            "validator_vote": "confirm",
            "evidence_checks": {"passed": 2, "required": 2},
            "evidence_kind": "http_poc_replay",
            "outcome_stage": "verified_vulnerability",
            "source_kind": "tool_validate_poc",
            "source_observation_id": "observation-poc",
            "provenance": {
                "source_kind": "tool_validate_poc",
                "source_observation_id": "observation-poc",
                "assessment_source": "executor_policy",
                "model_claims_used": False,
            },
        }
    )


def test_material_native_probe_opens_secret_free_exact_route_lock() -> None:
    state, lead = _open_ssti()

    assert lead.family == "template_injection"
    assert lead.method == "POST"
    assert lead.origin == "https://target.example"
    assert lead.endpoint == "/generate"
    assert lead.inputs == ("sentence",)
    assert lead.input_locations == (("body", "sentence"),)
    assert lead.request_inputs == (("body", "sentence"), ("body", "submit"))
    assert lead.body_encoding == "form"
    assert lead.source_kind == "tool_run_probe"
    assert lead.stage == "verified_vulnerability"
    assert pending_lead(state) == lead
    assert "lead-lock-secret" not in json.dumps(state.surface)
    assert "POST /generate" in directive(state)
    assert "sentence" in directive(state)


@pytest.mark.parametrize("kind", ["http_request", "run_command", "run_python"])
def test_untyped_tool_output_cannot_open_lock(kind: str) -> None:
    state = AgentState()

    opened = remember_from_probe_result(
        state,
        _ssti_probe_text(),
        {"action": kind, "probe": "ssti_fingerprint"},
        "observation-raw",
    )

    assert opened is None
    assert pending_lead(state) is None


def test_auth_state_only_finding_cannot_open_lock() -> None:
    text = json.dumps(
        {
            "probe": "default_credentials",
            "ok": True,
            "findings": [
                {
                    "type": "default_credentials_valid",
                    "url": "https://target.example/account",
                }
            ],
        }
    )

    opened = remember_from_probe_result(
        AgentState(),
        text,
        {"action": "run_probe", "probe": "default_credentials"},
        "observation-auth",
    )

    assert opened is None


def test_incomplete_native_candidate_cannot_open_lock() -> None:
    payload = json.loads(_ssti_probe_text())
    payload["findings"][0]["signal"] = {"kind": "template_error"}

    opened = remember_from_probe_result(
        AgentState(),
        json.dumps(payload),
        {"action": "run_probe", "probe": "ssti_fingerprint"},
        "observation-candidate",
    )

    assert opened is None


def test_confirmed_validate_poc_payload_opens_lock() -> None:
    state = AgentState()
    action = {
        "action": "validate_poc",
        "finding": {"vuln_class": "sql_injection"},
        "steps": [
            {
                "method": "GET",
                "url": "/search?q=%27",
                "evidence_role": "exploit",
            },
            {
                "method": "GET",
                "url": "/search?q=control",
                "evidence_role": "control",
            },
        ],
    }

    lead = remember_from_probe_result(
        state,
        _confirmed_validate_payload(),
        action,
        "observation-poc",
    )

    assert lead is not None
    assert lead.family == "sql_injection"
    assert lead.method == "GET"
    assert lead.endpoint == "/search"
    assert lead.inputs == ("q",)
    assert lead.source_kind == "tool_validate_poc"


def test_confirmed_raw_json_poc_opens_a_replayable_named_body_lock() -> None:
    state = AgentState()
    payload = json.loads(_confirmed_validate_payload())
    payload["endpoint"] = {
        "method": "POST",
        "url": "https://target.example/api/search",
        "params": [{"name": "query", "location": "body"}],
    }
    payload["input"] = {
        "method": "POST",
        "parameters": [{"name": "query", "location": "body"}],
        "affected_parameters": [{"name": "query", "location": "body"}],
    }
    action = {
        "action": "validate_poc",
        "finding": {"vuln_class": "sql_injection"},
        "steps": [
            {
                "method": "POST",
                "path": "/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": '{"query":"exploit","submit":true}',
                "evidence_role": "exploit",
            },
            {
                "method": "POST",
                "path": "/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": '{"query":"control","submit":true}',
                "evidence_role": "control",
            },
        ],
    }

    lead = remember_from_probe_result(
        state,
        json.dumps(payload),
        action,
        "observation-poc",
    )

    assert lead is not None
    assert lead.body_encoding == "json"
    assert lead.request_inputs == (("body", "query"), ("body", "submit"))
    assert (
        action_matches_lead(
            action,
            lead,
            primary_origin="https://target.example",
        )
        is True
    )
    assert action_matches_lead(
        {
            "action": "http_request",
            "vuln_class": "sql_injection",
            "method": "POST",
            "path": "/api/search",
            "json": ["query", "unmodelled-list"],
        },
        lead,
    ) is False


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("application/json", "not-json"),
        ("application/json", "7"),
        ("application/json", '["array"]'),
        ("application/x-www-form-urlencoded", "%"),
        ("application/x-www-form-urlencoded", "=missing-name"),
    ],
)
def test_unmodelled_typed_body_cannot_hide_drift_in_query_lock(
    content_type: str,
    body: str,
) -> None:
    payload = json.loads(_confirmed_validate_payload())
    payload["endpoint"]["method"] = "POST"
    payload["input"]["method"] = "POST"
    action = {
        "action": "validate_poc",
        "finding": {"vuln_class": "sql_injection"},
        "steps": [
            {
                "method": "POST",
                "path": "/search?q=exploit",
                "headers": {"Content-Type": content_type},
                "body": body,
                "evidence_role": "exploit",
            },
            {
                "method": "POST",
                "path": "/search?q=control",
                "headers": {"Content-Type": content_type},
                "body": body,
                "evidence_role": "control",
            },
        ],
    }

    assert (
        remember_from_probe_result(
            AgentState(),
            json.dumps(payload),
            action,
            "observation-poc",
        )
        is None
    )


def test_confirmed_poc_lock_preserves_duplicate_query_slots() -> None:
    state = AgentState()
    action = {
        "action": "validate_poc",
        "finding": {"vuln_class": "sql_injection"},
        "steps": [
            {
                "method": "GET",
                "path": "/search?q=exploit&q=second",
                "evidence_role": "exploit",
            },
            {
                "method": "GET",
                "path": "/search?q=control&q=second",
                "evidence_role": "control",
            },
        ],
    }

    lead = remember_from_probe_result(
        state,
        _confirmed_validate_payload(),
        action,
        "observation-poc",
    )

    assert lead is not None
    assert lead.request_inputs == (("query", "q"), ("query", "q"))
    assert (
        action_matches_lead(
            action,
            lead,
            primary_origin="https://target.example",
        )
        is True
    )
    drifted = {
        **action,
        "steps": [
            {**step, "path": "/search?q=only-one"}
            for step in action["steps"]
            if isinstance(step, dict)
        ],
    }
    assert action_matches_lead(drifted, lead) is False


def test_opaque_raw_body_does_not_open_exact_lock() -> None:
    payload = json.loads(_confirmed_validate_payload())
    payload["endpoint"] = {
        "method": "POST",
        "url": "https://target.example/search",
        "params": [{"name": "raw_body", "location": "body"}],
    }
    payload["input"] = {
        "method": "POST",
        "parameters": [{"name": "raw_body", "location": "body"}],
        "affected_parameters": [{"name": "raw_body", "location": "body"}],
    }
    raw_action = {
        "action": "validate_poc",
        "finding": {"vuln_class": "sql_injection"},
        "steps": [
            {
                "method": "POST",
                "path": "/search",
                "body": "opaque exploit bytes",
                "evidence_role": "exploit",
            },
            {
                "method": "POST",
                "path": "/search",
                "body": "opaque control bytes",
                "evidence_role": "control",
            },
        ],
    }

    assert (
        remember_from_probe_result(
            AgentState(),
            json.dumps(payload),
            raw_action,
            "observation-poc",
        )
        is None
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "/items/{id}",
        "/items/{int}",
        "/items/{uuid}",
        "/items/{segment}",
        "/items/:id",
        "/items/:redacted",
        "/items/%7Bid%7D",
        "/items/%3Aid",
        "/items/<int:id>",
    ],
)
def test_structural_endpoint_does_not_open_or_match_exact_lock(endpoint: str) -> None:
    assert (
        remember_from_probe_result(
            AgentState(),
            _ssti_probe_text(endpoint=endpoint),
            {"action": "run_probe", "probe": "ssti_fingerprint"},
            "observation-template",
        )
        is None
    )

    _state, concrete = _open_ssti()
    structural = replace(concrete, endpoint=endpoint, fingerprint="")
    structural = replace(
        structural,
        fingerprint=evidence_lead_lock._lead_fingerprint(structural),  # noqa: SLF001
    )
    candidate = {**_aligned_action(), "url": f"https://target.example{endpoint}"}
    assert action_matches_lead(candidate, structural) is False


def test_persisted_structural_endpoint_fails_closed_on_load() -> None:
    state, concrete = _open_ssti()
    structural = replace(concrete, endpoint="/items/{id}", fingerprint="")
    structural = replace(
        structural,
        fingerprint=evidence_lead_lock._lead_fingerprint(structural),  # noqa: SLF001
    )
    state.surface["evidence_lead_lock"] = structural.to_json()

    assert pending_lead(state) is None


def test_validate_poc_requires_matching_executor_provenance() -> None:
    payload = json.loads(_confirmed_validate_payload())
    payload["provenance"]["model_claims_used"] = True

    opened = remember_from_probe_result(
        AgentState(),
        json.dumps(payload),
        {"action": "validate_poc", "steps": []},
        "observation-poc",
    )

    assert opened is None


@pytest.mark.parametrize(
    "change",
    [
        {"vuln_class": "sql_injection"},
        {"method": "GET"},
        {"url": "https://target.example/preview"},
        {"form": {"name": "<%= 8 * 8 %>"}},
    ],
)
def test_action_match_requires_exact_family_method_endpoint_and_input(
    change: dict[str, object],
) -> None:
    _state, lead = _open_ssti()
    aligned = _aligned_action()
    aligned.update(change)

    assert action_matches_lead(aligned, lead) is False


def test_exact_http_route_matches_and_state_round_trips() -> None:
    state, lead = _open_ssti()
    restored = AgentState.from_json(state.to_json())

    assert pending_lead(restored) == lead
    assert action_matches_lead(_aligned_action(), lead) is True
    # Declarative metadata does not constrain what a native specialist will
    # physically request, so a run_probe action cannot satisfy an exact replay.
    assert action_matches_lead(
        {
            "action": "run_probe",
            "probe": "ssti_fingerprint",
            "method": "POST",
            "url": "https://target.example/generate",
            "field": "sentence",
        },
        lead,
    ) is False


def _aligned_validate_action() -> dict[str, object]:
    return {
        "action": "validate_poc",
        "vuln_class": "ssti",
        "steps": [
            {
                "method": "POST",
                "url": "https://target.example/generate",
                "evidence_role": "exploit",
                "form": {"sentence": "<%= 8 * 8 %>", "submit": "Render"},
            },
            {
                "method": "POST",
                "url": "https://target.example/generate",
                "evidence_role": "control",
                "form": {"sentence": "control", "submit": "Render"},
            },
        ],
    }


def test_validate_poc_exact_observed_request_shape_matches() -> None:
    _state, lead = _open_ssti()

    assert action_matches_lead(_aligned_validate_action(), lead) is True


@pytest.mark.parametrize(
    ("changed_key", "changed_value"),
    [("method", "GET"), ("url", "https://target.example/preview")],
)
def test_validate_poc_rejects_when_any_step_changes_transport(
    changed_key: str,
    changed_value: str,
) -> None:
    _state, lead = _open_ssti()
    action = _aligned_validate_action()
    steps = action["steps"]
    assert isinstance(steps, list)
    control = steps[1]
    assert isinstance(control, dict)
    control[changed_key] = changed_value

    assert action_matches_lead(action, lead) is False


def test_validate_poc_rejects_affected_input_moved_from_body_to_query() -> None:
    _state, lead = _open_ssti()
    action = _aligned_validate_action()
    steps = action["steps"]
    assert isinstance(steps, list)
    for index, step in enumerate(steps):
        assert isinstance(step, dict)
        value = "%3C%25%3D8%2A8%25%3E" if index == 0 else "control"
        step["url"] = f"https://target.example/generate?sentence={value}"
        step["form"] = {"submit": "Render"}

    assert action_matches_lead(action, lead) is False


@pytest.mark.parametrize(
    "form",
    [
        {"sentence": "<%= 8 * 8 %>"},
        {"sentence": "<%= 8 * 8 %>", "commit": "Render"},
        {"sentence": "<%= 8 * 8 %>", "submit": "Render", "unexpected": "1"},
    ],
)
def test_validate_poc_requires_exact_companion_input_names(
    form: dict[str, str],
) -> None:
    _state, lead = _open_ssti()
    action = _aligned_validate_action()
    steps = action["steps"]
    assert isinstance(steps, list)
    for step in steps:
        assert isinstance(step, dict)
        step["form"] = dict(form)

    assert action_matches_lead(action, lead) is False


def test_validate_poc_rejects_json_when_observed_body_was_form_encoded() -> None:
    _state, lead = _open_ssti()
    action = _aligned_validate_action()
    steps = action["steps"]
    assert isinstance(steps, list)
    for step in steps:
        assert isinstance(step, dict)
        form = step.pop("form")
        step["json"] = form

    assert action_matches_lead(action, lead) is False


def test_http_request_rejects_observed_body_shape_drift() -> None:
    _state, lead = _open_ssti()
    drifted = [
        {
            "action": "http_request",
            "vuln_class": "ssti",
            "method": "POST",
            "url": "https://target.example/generate?sentence=payload",
            "form": {"submit": "Render"},
        },
        {
            "action": "http_request",
            "vuln_class": "ssti",
            "method": "POST",
            "url": "https://target.example/generate",
            "form": {"sentence": "payload"},
        },
        {
            "action": "http_request",
            "vuln_class": "ssti",
            "method": "POST",
            "url": "https://target.example/generate",
            "form": {"sentence": "payload", "submit": "Render", "unexpected": "1"},
        },
        {
            "action": "http_request",
            "vuln_class": "ssti",
            "method": "POST",
            "url": "https://target.example/generate",
            "json": {"sentence": "payload", "submit": "Render"},
        },
    ]

    assert all(not action_matches_lead(action, lead) for action in drifted)


def test_http_request_rejects_origin_and_effective_encoding_drift() -> None:
    _state, lead = _open_ssti()
    other_origin = {
        **_aligned_action(),
        "url": "https://other-authorized.example/generate",
    }
    mislabeled_form = {
        **_aligned_action(),
        "headers": {"Content-Type": "application/json"},
    }

    assert action_matches_lead(other_origin, lead) is False
    assert action_matches_lead(mislabeled_form, lead) is False


def test_relative_http_request_requires_matching_primary_origin() -> None:
    _state, lead = _open_ssti()
    relative = {
        **_aligned_action(),
        "url": "/generate",
    }

    assert action_matches_lead(relative, lead) is False
    assert (
        action_matches_lead(
            relative,
            lead,
            primary_origin="https://target.example/app",
        )
        is True
    )
    assert (
        action_matches_lead(
            relative,
            lead,
            primary_origin="https://main.example/app",
        )
        is False
    )


@pytest.mark.parametrize(
    "header",
    [
        {"X-Debug-Mode": "1"},
        {"Authorization": "Bearer attacker-authored"},
        {"Cookie": "tenant=b; sid=attacker-authored"},
    ],
)
def test_http_request_rejects_unmodelled_authored_headers(
    header: dict[str, str],
) -> None:
    _state, lead = _open_ssti()
    explicit_content_type = {
        **_aligned_action(),
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    }
    added_header = {
        **explicit_content_type,
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            **header,
        },
    }

    assert action_matches_lead(explicit_content_type, lead) is True
    assert action_matches_lead(added_header, lead) is False


@pytest.mark.parametrize(
    "header",
    [
        {"X-Tenant": "tenant-a"},
        {"Cookie": "tenant=a; sid=source-cookie"},
    ],
)
def test_native_header_dependent_request_does_not_open_exact_lock(
    header: dict[str, str],
) -> None:
    payload = json.loads(_ssti_probe_text())
    finding = payload["findings"][0]
    assert isinstance(finding, dict)
    for key in ("replay", "baseline_replay"):
        replay = finding[key]
        assert isinstance(replay, dict)
        replay["headers"] = dict(header)

    assert (
        remember_from_probe_result(
            AgentState(),
            json.dumps(payload),
            {"action": "run_probe", "probe": "ssti_fingerprint"},
            "observation-header-dependent",
        )
        is None
    )


def test_header_only_mutation_cannot_open_a_named_input_lock() -> None:
    payload = json.loads(_confirmed_validate_payload())
    payload["input"] = {
        "method": "GET",
        "parameters": [{"name": "x-tenant", "location": "header"}],
        "affected_parameters": [{"name": "x-tenant", "location": "header"}],
    }
    action = {
        "action": "validate_poc",
        "finding": {"vuln_class": "sql_injection"},
        "steps": [
            {
                "method": "GET",
                "path": "/search",
                "headers": {"X-Tenant": "exploit"},
                "evidence_role": "exploit",
            },
            {
                "method": "GET",
                "path": "/search",
                "headers": {"X-Tenant": "control"},
                "evidence_role": "control",
            },
        ],
    }

    assert (
        remember_from_probe_result(
            AgentState(),
            json.dumps(payload),
            action,
            "observation-poc",
        )
        is None
    )


def test_unchanged_companion_header_prevents_false_query_lock() -> None:
    action = {
        "action": "validate_poc",
        "finding": {"vuln_class": "sql_injection"},
        "steps": [
            {
                "method": "GET",
                "path": "/search?q=exploit",
                "headers": {"X-Tenant": "tenant-a"},
                "evidence_role": "exploit",
            },
            {
                "method": "GET",
                "path": "/search?q=control",
                "headers": {"X-Tenant": "tenant-a"},
                "evidence_role": "control",
            },
        ],
    }

    assert (
        remember_from_probe_result(
            AgentState(),
            _confirmed_validate_payload(),
            action,
            "observation-poc",
        )
        is None
    )


@pytest.mark.parametrize("action_factory", [_aligned_action, _aligned_validate_action])
def test_locked_replay_rejects_case_insensitive_duplicate_headers(
    action_factory: Callable[[], dict[str, object]],
) -> None:
    _state, lead = _open_ssti()
    action = action_factory()
    if action["action"] == "validate_poc":
        requests = action["steps"]
        assert isinstance(requests, list)
    else:
        requests = [action]
    for request in requests:
        assert isinstance(request, dict)
        request["headers"] = {
            "Content-Type": "application/x-www-form-urlencoded",
            "content-type": "application/json",
        }

    assert action_matches_lead(action, lead) is False


def test_only_complete_aligned_no_progress_attempts_exhaust_lock() -> None:
    state, original = _open_ssti()
    aligned = _aligned_action()

    for ignored in (
        {"ok": False, "outcome": "blocked"},
        {"ok": False, "outcome": "observed", "timed_out": True},
        {"ok": False, "outcome": "same_as_before"},
    ):
        assert record_aligned_outcome(state, aligned, ignored) == original

    assert record_aligned_outcome(
        state,
        {**aligned, "url": "https://target.example/unrelated"},
        {"ok": True, "outcome": "observed"},
    ) == original

    after_first = record_aligned_outcome(
        state,
        aligned,
        {"ok": True, "outcome": "observed"},
    )
    assert after_first is not None
    assert after_first.aligned_no_progress == 1
    assert "1 complete aligned no-progress attempt(s) remain" in directive(state)

    assert record_aligned_outcome(
        state,
        aligned,
        {"ok": True, "outcome": "observed"},
    ) is None
    assert pending_lead(state) is None
    assert state.surface["evidence_lead_lock"]["status"] == "exhausted"


@pytest.mark.parametrize("status", [401, 403, 407])
def test_authentication_required_status_pauses_exact_lead(status: int) -> None:
    state, original = _open_ssti()
    state.last_observation = {"http_response": {"status": status}}

    remaining = record_aligned_outcome(
        state,
        _aligned_action(),
        {"ok": True, "outcome": "http_response_observed"},
    )

    assert remaining is None
    assert pending_lead(state) is None
    assert awaiting_session_lead(state) is not None
    assert unresolved_lead(state) is not None
    stored = state.surface["evidence_lead_lock"]
    assert isinstance(stored, dict)
    assert stored["status"] == "awaiting_session"
    assert stored["response_status"] == status
    assert "Establish authentication" in directive(state)

    state.last_observation = {"http_response": {"status": 200}}
    reactivated = record_aligned_outcome(
        state,
        _aligned_action(),
        {"ok": True, "outcome": "http_response_observed"},
    )
    assert reactivated is not None
    assert reactivated.fingerprint == original.fingerprint
    assert reactivated.aligned_no_progress == 1
    assert awaiting_session_lead(state) is None
    assert unresolved_lead(state) == reactivated
    assert lead_replay_generation(state) == 1


def test_only_waiting_lead_reactivation_advances_replay_generation() -> None:
    state, original = _open_ssti()

    assert lead_replay_generation(state) == 0
    assert reactivate_for_session_change(state) is None
    assert lead_replay_generation(state) == 0

    record_aligned_outcome(
        state,
        _aligned_action(),
        {
            "ok": True,
            "outcome": "http_response_observed",
            "_evidence_observation": json.dumps({"response": {"status": 401}}),
        },
    )
    active = reactivate_for_session_change(state)

    assert active is not None
    assert active.fingerprint == original.fingerprint
    assert active.status == "active"
    assert active.aligned_no_progress == 0
    assert lead_replay_generation(state) == 1
    assert reactivate_for_session_change(state) is None
    assert lead_replay_generation(state) == 1


def test_blocked_replay_cannot_reactivate_auth_paused_lead() -> None:
    state, _original = _open_ssti()
    action = _aligned_action()
    record_aligned_outcome(
        state,
        action,
        {
            "ok": True,
            "outcome": "http_response_observed",
            "_evidence_observation": json.dumps({"response": {"status": 401}}),
        },
    )

    assert record_aligned_outcome(
        state,
        action,
        {"ok": False, "outcome": "blocked"},
    ) is None
    stored = state.surface["evidence_lead_lock"]
    assert isinstance(stored, dict)
    assert stored["status"] == "awaiting_session"
    assert lead_replay_generation(state) == 0


def test_current_http_auth_response_with_rotated_cookie_still_pauses_lead() -> None:
    auth_status = 401
    state, _original = _open_ssti()
    state.last_observation = {"http_response": {"status": 200}}
    evidence = json.dumps(
        {
            "response": {
                "status": auth_status,
                "headers": {"Set-Cookie": "session=rotated; HttpOnly"},
            }
        }
    )

    remaining = record_aligned_outcome(
        state,
        _aligned_action(),
        {
            "ok": True,
            "outcome": "http_response_observed",
            "_evidence_observation": evidence,
        },
    )

    assert remaining is None
    stored = state.surface["evidence_lead_lock"]
    assert isinstance(stored, dict)
    assert stored["status"] == "awaiting_session"
    assert stored["response_status"] == auth_status


def test_pre_dispatch_block_does_not_reuse_stale_auth_response() -> None:
    state, original = _open_ssti()
    state.last_observation = {"http_response": {"status": 401}}

    remaining = record_aligned_outcome(
        state,
        _aligned_action(),
        {"ok": False, "outcome": "blocked"},
    )

    assert remaining == original
    assert state.surface["evidence_lead_lock"]["status"] == "active"


@pytest.mark.parametrize("status", [429, 500, 503])
def test_complete_server_response_counts_as_no_progress(status: int) -> None:
    state, _original = _open_ssti()
    state.last_observation = {"http_response": {"status": status}}

    remaining = record_aligned_outcome(
        state,
        _aligned_action(),
        {"ok": True, "outcome": "http_response_observed"},
    )

    assert remaining is not None
    assert remaining.aligned_no_progress == 1


def test_session_reset_releases_unreplayable_lead() -> None:
    state, original = _open_ssti()

    released = release_for_session_reset(state)

    assert released is not None
    assert released.fingerprint == original.fingerprint
    assert pending_lead(state) is None
    stored = state.surface["evidence_lead_lock"]
    assert isinstance(stored, dict)
    assert stored["status"] == "exhausted"
    assert stored["release_reason"] == "http_session_reset"


def test_completed_rejected_validate_poc_counts_as_no_progress() -> None:
    state, _original = _open_ssti()
    action = _aligned_validate_action()
    evidence = json.dumps(
        {
            "steps": [
                {"response": {"status": 200}},
                {"response": {"status": 200}},
            ]
        }
    )
    rejected = {
        "ok": False,
        "outcome": "blocked",
        "_evidence_observation": evidence,
    }

    first = record_aligned_outcome(state, action, rejected)
    assert first is not None
    assert first.aligned_no_progress == 1
    assert record_aligned_outcome(state, action, rejected) is None
    assert state.surface["evidence_lead_lock"]["status"] == "exhausted"


@pytest.mark.parametrize("status", [401, 403, 407])
def test_completed_validate_auth_responses_pause_without_consuming_attempt(
    status: int,
) -> None:
    state, _original = _open_ssti()
    outcome = {
        "ok": False,
        "outcome": "blocked",
        "_evidence_observation": json.dumps(
            {
                "steps": [
                    {"response": {"status": status}},
                    {"response": {"status": status}},
                ]
            }
        ),
    }

    assert record_aligned_outcome(state, _aligned_validate_action(), outcome) is None
    stored = state.surface["evidence_lead_lock"]
    assert isinstance(stored, dict)
    assert stored["status"] == "awaiting_session"
    assert stored["response_status"] == status
    assert stored["aligned_no_progress"] == 0


def test_mixed_validate_responses_count_as_completed_attempt_instead_of_auth_pause() -> None:
    state, _original = _open_ssti()
    outcome = {
        "ok": False,
        "outcome": "blocked",
        "_evidence_observation": json.dumps(
            {
                "steps": [
                    {"response": {"status": 200}},
                    {"response": {"status": 403}},
                ]
            }
        ),
    }

    remaining = record_aligned_outcome(state, _aligned_validate_action(), outcome)

    assert remaining is not None
    assert remaining.status == "active"
    assert remaining.aligned_no_progress == 1


def test_incomplete_validate_poc_does_not_consume_attempt() -> None:
    state, original = _open_ssti()
    outcome = {
        "ok": False,
        "outcome": "blocked",
        "_evidence_observation": json.dumps(
            {
                "steps": [
                    {"response": {"status": 200}},
                    {"response": {"status": None, "error": "request blocked"}},
                ]
            }
        ),
    }

    assert record_aligned_outcome(state, _aligned_validate_action(), outcome) == original


@pytest.mark.parametrize("outcome", ["flag_candidate", "lead_rejected"])
def test_proof_or_rejected_aligned_outcome_closes_lock(outcome: str) -> None:
    state, _lead = _open_ssti()

    assert record_aligned_outcome(
        state,
        _aligned_action(),
        {"ok": True, "outcome": outcome},
    ) is None
    assert pending_lead(state) is None
    assert state.surface["evidence_lead_lock"]["status"] in {"resolved", "rejected"}


def test_new_lead_does_not_preempt_unresolved_route() -> None:
    state, first = _open_ssti()

    returned = remember_from_probe_result(
        state,
        _ssti_probe_text(endpoint="/other"),
        {"action": "run_probe", "probe": "ssti_fingerprint"},
        "observation-2",
    )

    assert returned == first
    assert pending_lead(state) == first
