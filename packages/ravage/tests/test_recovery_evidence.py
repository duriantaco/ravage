from __future__ import annotations

import json

from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.recovery_action_contract import select_recovery_branch_action
from ravage.agent_core.recovery_evidence import assess_recovery_evidence
from ravage.agent_core.recovery_objectives import plan_recovery_objective
from ravage.agent_core.recovery_policy import MaterialProgressKind, ProgressSnapshot, RecoveryRole
from ravage.agent_core.recovery_runtime import RecoveryCampaign

EMPTY = ProgressSnapshot()


def _probe_outcome(payload: dict[str, object]) -> dict[str, object]:
    return {
        "ok": bool(payload.get("ok")),
        "observation": json.dumps(payload),
        "outcome": "confirmed_signal" if payload.get("findings") else "observed",
        "flag": "",
    }


def _server_fetch_reflection_payload() -> dict[str, object]:
    return {
        "ok": True,
        "probe": "reflection_value_boundary",
        "findings": [
            {
                "type": "reflection_value_delta",
                "input": {
                    "input": "url",
                    "method": "GET",
                    "url": "http://target/redirect.php",
                },
                "replay": {
                    "method": "GET",
                    "payload_field": "url",
                    "query": {"url": "http://127.0.0.1/internal"},
                    "url": "http://target/redirect.php",
                },
                "response": {
                    "status": 200,
                    "body_snippet": (
                        "Warning: file_get_contents(http://127.0.0.1/internal): "
                        "failed to open stream; Fetched Content"
                    ),
                },
                "delta": {"marker_reflected": True, "length_delta": 12},
            }
        ],
    }


def test_model_authored_structured_claim_cannot_create_progress() -> None:
    payload = {
        "ok": True,
        "probe": "custom",
        "findings": [{"type": "xxe_file_read_signal", "target": "/proof"}],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "final"},
        outcome=_probe_outcome(payload),
        source_kind="model_reply",
    )

    assert assessment.source_trusted is False
    assert assessment.material_progress == ()
    assert assessment.snapshot == EMPTY
    assert "untrusted_source" in assessment.reason_codes


def test_custom_python_printed_finding_is_context_not_material_progress() -> None:
    payload = {
        "ok": True,
        "probe": "custom",
        "findings": [{"type": "xxe_file_read_signal", "target": "/proof"}],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_python", "code": "print(fake_finding)"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_python",
    )

    assert assessment.source_trusted is True
    assert assessment.material_progress == ()
    assert assessment.low_value_route is True
    assert assessment.snapshot.weak_signals
    assert "untyped_tool_output" in assessment.reason_codes


def test_candidate_only_probe_finding_is_weak() -> None:
    payload = {
        "ok": True,
        "probe": "direct_exposure",
        "findings": [{"type": "direct_exposure_candidate", "url": "http://target/admin"}],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "direct_exposure"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.material_progress == ()
    assert assessment.snapshot.weak_signals
    assert assessment.low_value_route is True
    assert len(assessment.leads) == 1
    assert assessment.leads[0].family == "exposure"
    assert assessment.leads[0].material is False


def test_validated_replay_and_response_differential_are_material() -> None:
    payload = {
        "ok": True,
        "probe": "sqli_differential",
        "findings": [
            {
                "type": "sql_literal_comment_exposed_secret",
                "input": {"name": "lookup"},
                "replay": {
                    "method": "POST",
                    "url": "http://target/search",
                    "payload_field": "lookup",
                    "form": {"lookup": "redacted"},
                },
                "response": {"status": 200, "body_snippet": "redacted"},
            }
        ],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "sqli_differential"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.material_progress == (
        MaterialProgressKind.REQUEST_TEMPLATE_VALIDATED,
        MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
    )
    assert len(assessment.snapshot.validated_request_templates) == 1
    assert len(assessment.snapshot.validated_response_differentials) == 1
    assert assessment.low_value_route is False
    assert assessment.leads[0].family == "sql_injection"
    assert assessment.leads[0].method == "POST"
    assert assessment.leads[0].endpoints == ("/search",)
    assert assessment.leads[0].inputs == ("lookup",)
    assert assessment.leads[0].progress_kinds == assessment.material_progress
    assert "redacted" not in json.dumps(assessment.leads[0].to_json())


def test_reflection_inside_server_fetch_sink_is_attributed_to_ssrf() -> None:
    payload = _server_fetch_reflection_payload()

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "reflection_value_boundary"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.leads[0].family == "server_side_request_forgery"
    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        leads=assessment.leads,
    )
    assert objective is not None
    assert objective.probe == "ssrf_boundary"


def test_server_fetch_evidence_drives_the_campaign_to_the_ssrf_contract() -> None:
    payload = _server_fetch_reflection_payload()
    campaign = RecoveryCampaign.create(
        target_url="http://target",
        max_model_requests=40,
    )
    recommendations = [
        {"probe": "xss_filter_constraint", "task_id": "input-reflection", "score": 100}
    ]

    campaign.begin_model_request()
    result = campaign.record_action_result(
        action={"action": "run_probe", "probe": "reflection_value_boundary"},
        outcome=ActionResult(
            ok=True,
            observation=json.dumps(payload),
            evidence_source_kind="tool_run_probe",
            evidence_observation=json.dumps(payload),
        ),
        recommended_specialists=recommendations,
    )

    assert result.decision.reason == "material_progress_lease_granted"
    assert result.decision.next_role is RecoveryRole.CLOSURE
    assert result.active_objective is not None
    assert result.active_objective.family == "server_side_request_forgery"
    assert result.active_objective.probe == "ssrf_boundary"

    proposed = {
        "action": "run_probe",
        "probe": "xss_filter_constraint",
        "strategy": "misleading_recommendation",
    }
    selected = select_recovery_branch_action(
        proposed,
        role=campaign.scheduler.role,
        lease_used=campaign.scheduler.lease_used,
        objective=result.active_objective,
    )
    final = {"action": "final", "summary": "The delegated route is falsified."}
    handoff = select_recovery_branch_action(
        final,
        role=campaign.scheduler.role,
        lease_used=campaign.scheduler.lease_used,
        objective=result.active_objective,
    )

    assert selected["probe"] == "ssrf_boundary"
    assert handoff == final


def test_plain_html_reflection_remains_attributed_to_xss() -> None:
    payload = {
        "ok": True,
        "probe": "reflection_value_boundary",
        "findings": [
            {
                "type": "reflection_value_delta",
                "input": {
                    "input": "name",
                    "method": "GET",
                    "url": "http://target/page",
                },
                "replay": {
                    "method": "GET",
                    "payload_field": "name",
                    "query": {"name": "<svg onload=alert('XSS')>"},
                    "url": "http://target/page",
                },
                "response": {
                    "status": 200,
                    "body_snippet": "<main><svg onload=alert('XSS')></main>",
                },
                "delta": {"marker_reflected": True, "length_delta": 8},
            }
        ],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "reflection_value_boundary"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.leads[0].family == "cross_site_scripting"


def test_nested_trusted_source_finding_preserves_form_route() -> None:
    payload = {
        "ok": True,
        "probe": "ssti_fingerprint",
        "findings": [
            {
                "type": "ssti_stored_signal",
                "channel": "deferred_form_workflow",
                "source_finding": {
                    "type": "deferred_form_flow_signal",
                    "form": {
                        "action": "http://target/enrollment/start/",
                        "method": "POST",
                        "inputs": ["display_name", "passphrase"],
                    },
                    "signal": {"kind": "evaluated_expression", "observed": "redacted"},
                },
            }
        ],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "ssti_fingerprint"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.material_progress == (MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,)
    assert len(assessment.leads) == 1
    assert assessment.leads[0].method == "POST"
    assert assessment.leads[0].endpoints == ("/enrollment/start/",)
    assert assessment.leads[0].inputs == ("display_name", "passphrase")


def test_authenticated_followup_is_a_target_state_change() -> None:
    payload = {
        "ok": True,
        "probe": "default_credentials",
        "findings": [
            {
                "type": "default_credentials_valid",
                "url": "http://target/account/12345678",
            }
        ],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "default_credentials"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.material_progress == (MaterialProgressKind.AUTH_STATE_CHANGED,)
    assert len(assessment.snapshot.authenticated_states) == 1


def test_file_read_finding_confirms_a_primitive() -> None:
    payload = {
        "ok": True,
        "probe": "xxe_boundary",
        "findings": [
            {
                "type": "xxe_file_read_signal",
                "target": "/etc/example",
                "response": {"url": "http://target/parser", "status": 200},
            }
        ],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "xxe_boundary"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.material_progress == (MaterialProgressKind.PRIMITIVE_CONFIRMED,)
    assert len(assessment.snapshot.confirmed_primitives) == 1


def test_repeated_material_finding_does_not_renew_progress() -> None:
    payload = {
        "ok": True,
        "probe": "command_boundary",
        "findings": [
            {
                "type": "command_boundary_signal",
                "url": "http://target/run",
                "response": {"status": 200},
            }
        ],
    }
    first = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "command_boundary"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )
    repeated = assess_recovery_evidence(
        first.snapshot,
        action={"action": "run_probe", "probe": "command_boundary"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert first.material_progress == (MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,)
    assert repeated.material_progress == ()
    assert repeated.low_value_route is True


def test_zero_count_ssti_fingerprint_does_not_create_material_progress() -> None:
    payload = {
        "ok": True,
        "probe": "ssti_fingerprint",
        "findings": [
            {
                "type": "ssti_fingerprint_signal",
                "expected": ["49"],
                "signal": {"kind": "expression_repetition", "count": 0},
                "replay": {
                    "method": "GET",
                    "payload_field": "value",
                    "url": "http://target/static.js?value=7*7",
                },
            }
        ],
    }

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "ssti_fingerprint"},
        outcome=_probe_outcome(payload),
        source_kind="tool_run_probe",
    )

    assert assessment.material_progress == ()
    assert assessment.low_value_route is True


def test_finding_identity_ignores_response_values_and_variable_path_ids() -> None:
    first_payload = {
        "ok": True,
        "probe": "command_boundary",
        "findings": [
            {
                "type": "command_boundary_signal",
                "url": "http://target/jobs/12345678?input=one",
                "response": {"status": 200, "body_snippet": "first secret value"},
            }
        ],
    }
    second_payload = {
        "ok": True,
        "probe": "command_boundary",
        "findings": [
            {
                "type": "command_boundary_signal",
                "url": "http://target/jobs/abcdef12?input=two",
                "response": {"status": 500, "body_snippet": "different secret value"},
            }
        ],
    }
    first = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "command_boundary"},
        outcome=_probe_outcome(first_payload),
        source_kind="tool_run_probe",
    )
    second = assess_recovery_evidence(
        first.snapshot,
        action={"action": "run_probe", "probe": "command_boundary"},
        outcome=_probe_outcome(second_payload),
        source_kind="tool_run_probe",
    )

    assert first.observation_digest == second.observation_digest
    assert first.leads[0].fingerprint == second.leads[0].fingerprint
    assert second.material_progress == ()


def test_existing_tool_proof_gate_is_required_for_proof_progress() -> None:
    trusted = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_command", "command": "target request"},
        outcome={"ok": True, "flag_captured": True, "observation": "redacted"},
        source_kind="tool_run_command",
    )
    untrusted = assess_recovery_evidence(
        EMPTY,
        action={"action": "final"},
        outcome={"ok": True, "flag_captured": True, "observation": "redacted"},
        source_kind="model_reply",
    )

    assert trusted.material_progress == (MaterialProgressKind.PROOF_CONFIRMED,)
    assert len(trusted.snapshot.confirmed_proofs) == 1
    assert untrusted.material_progress == ()
    assert untrusted.snapshot.confirmed_proofs == frozenset()


def test_unescaped_control_characters_do_not_make_probe_evidence_unparseable() -> None:
    raw = '{"ok":true,"probe":"default_credentials","findings":['
    raw += '{"type":"default_credentials_valid","detail":"line\u0001break"}]}'

    assessment = assess_recovery_evidence(
        EMPTY,
        action={"action": "run_probe", "probe": "default_credentials"},
        outcome={"ok": True, "observation": raw},
        source_kind="tool_run_probe",
    )

    assert assessment.material_progress == (MaterialProgressKind.AUTH_STATE_CHANGED,)
