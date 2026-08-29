from __future__ import annotations

import json

import pytest
from ravage.agent_core.recovery_evidence import (
    RecoveryEvidenceAssessment,
    RecoveryLead,
)
from ravage.agent_core.recovery_objectives import (
    RecoveryAttempt,
    RecoveryObjectiveMode,
    build_recovery_role_context,
    plan_recovery_objective,
    recovery_handoff_from_final,
)
from ravage.agent_core.recovery_policy import (
    MaterialProgressKind,
    ProgressSnapshot,
    RecoveryRole,
)

MAX_CONTEXT_LEADS = 8
MAX_CONTEXT_ATTEMPTS = 12


def _lead(  # noqa: PLR0913 - compact test factory.
    *,
    family: str = "sql_injection",
    probe: str = "sqli_differential",
    endpoint: str = "/search",
    inputs: tuple[str, ...] = ("lookup",),
    material: bool = True,
    fingerprint: str = "lead:one",
) -> RecoveryLead:
    return RecoveryLead(
        fingerprint=fingerprint,
        finding_type="target_signal",
        family=family,
        probe=probe,
        method="POST",
        endpoints=(endpoint,) if endpoint else (),
        inputs=inputs,
        progress_kinds=(MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,) if material else (),
    )


def _attempt(
    *,
    family: str,
    probe: str,
    endpoint: str = "",
    inputs: tuple[str, ...] = (),
    low_value: bool = True,
) -> RecoveryAttempt:
    return RecoveryAttempt(
        route_fingerprint=f"route:{family}:{probe}:{endpoint}",
        family=family,
        probe=probe,
        endpoint=endpoint,
        inputs=inputs,
        payload_class="unknown",
        observation_digest=f"observation:{family}:{probe}",
        low_value=low_value,
    )


def _specialist(probe: str, task_id: str, *, score: int = 1) -> dict[str, object]:
    return {"probe": probe, "task_id": task_id, "score": score}


def test_material_sql_lead_delegates_depth_first_extraction() -> None:
    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        leads=[_lead()],
    )

    assert objective is not None
    assert objective.mode is RecoveryObjectiveMode.PROOF_CLOSURE
    assert objective.probe == "sqli_exploit"
    assert objective.task_id == "data-query"
    assert objective.endpoint == "/search"
    assert objective.inputs == ("lookup",)
    assert objective.material_lead is True
    assert "Stay depth-first" in objective.instruction


def test_candidate_lead_can_focus_a_branch_without_claiming_material_progress() -> None:
    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        leads=[
            _lead(
                family="exposure",
                probe="direct_exposure",
                endpoint="/admin",
                inputs=(),
                material=False,
            )
        ],
    )

    assert objective is not None
    assert objective.probe == "direct_exposure"
    assert objective.material_lead is False


def test_closure_prefers_consensus_executed_family_over_unrelated_recommendation() -> None:
    attempts = [
        _attempt(family="cross_site_scripting", probe="xss_context"),
        _attempt(family="cross_site_scripting", probe="dom_execution"),
        _attempt(family="cross_site_scripting", probe="reflection_value_boundary"),
        _attempt(family="cross_site_scripting", probe=""),
    ]

    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        recommended_specialists=[
            _specialist("command_boundary", "command-boundary", score=100),
        ],
        attempts=attempts,
    )

    assert objective is not None
    assert objective.family == "cross_site_scripting"
    assert objective.probe == "xss_filter_constraint"
    assert objective.task_id == "input-reflection"
    assert objective.material_lead is False


def test_one_low_value_family_attempt_cannot_override_recommendations() -> None:
    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        recommended_specialists=[
            _specialist("command_boundary", "command-boundary", score=100),
        ],
        attempts=[_attempt(family="cross_site_scripting", probe="xss_context")],
    )

    assert objective is not None
    assert objective.probe == "command_boundary"


def test_counterfactual_prefers_target_lead_with_a_new_technique() -> None:
    attempts = [
        _attempt(
            family="sql_injection",
            probe="sqli_differential",
            endpoint="/search",
            inputs=("lookup",),
        )
    ]
    objective = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        leads=[_lead()],
        recommended_specialists=[
            _specialist("xxe_boundary", "file-fetch-parser", score=50),
        ],
        attempts=attempts,
    )

    assert objective is not None
    assert objective.mode is RecoveryObjectiveMode.TECHNIQUE_SHIFT
    assert objective.probe == "sqli_exploit"
    assert objective.family == "sql_injection"


def test_exhausted_closer_uses_a_different_same_family_specialist() -> None:
    attempts = [
        _attempt(
            family="sql_injection",
            probe="sqli_exploit",
            endpoint="/search",
            inputs=("lookup",),
        ),
        _attempt(
            family="sql_injection",
            probe="sqli_exploit",
            endpoint="/search",
            inputs=("lookup",),
        ),
    ]
    objective = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        leads=[_lead()],
        recommended_specialists=[
            _specialist("filtered_query_bypass", "data-query", score=10),
            _specialist("xxe_boundary", "file-fetch-parser", score=100),
        ],
        attempts=attempts,
    )

    assert objective is not None
    assert objective.mode is RecoveryObjectiveMode.TECHNIQUE_SHIFT
    assert objective.probe == "filtered_query_bypass"


def test_counterfactual_uses_family_pivot_when_no_supported_family_route_remains() -> None:
    objective = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        recommended_specialists=[
            _specialist("xxe_boundary", "file-fetch-parser", score=4),
        ],
        attempts=[_attempt(family="sql_injection", probe="sqli_differential")],
    )

    assert objective is not None
    assert objective.mode is RecoveryObjectiveMode.FAMILY_PIVOT
    assert objective.family == "xml_external_entity"


def test_attempted_objective_fingerprint_cannot_be_selected_again() -> None:
    first = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        recommended_specialists=[
            _specialist("xxe_boundary", "file-fetch-parser", score=10),
            _specialist("ssrf_boundary", "file-fetch-parser", score=1),
        ],
    )
    assert first is not None

    second = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        recommended_specialists=[
            _specialist("xxe_boundary", "file-fetch-parser", score=10),
            _specialist("ssrf_boundary", "file-fetch-parser", score=1),
        ],
        attempted_objective_fingerprints=[first.fingerprint],
    )

    assert second is not None
    assert second.fingerprint != first.fingerprint
    assert second.probe == "ssrf_boundary"


def test_all_exhausted_routes_return_no_objective() -> None:
    attempts = [
        _attempt(family="xml_external_entity", probe="xxe_boundary"),
        _attempt(family="xml_external_entity", probe="xxe_boundary"),
    ]

    objective = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        recommended_specialists=[
            _specialist("xxe_boundary", "file-fetch-parser"),
        ],
        attempts=attempts,
    )

    assert objective is None


def test_objective_selection_is_deterministic_across_candidate_order() -> None:
    cards = [
        _specialist("xxe_boundary", "file-fetch-parser", score=3),
        _specialist("ssrf_boundary", "file-fetch-parser", score=3),
    ]

    first = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        recommended_specialists=cards,
    )
    second = plan_recovery_objective(
        RecoveryRole.COUNTERFACTUAL,
        recommended_specialists=list(reversed(cards)),
    )

    assert first is not None
    assert second is not None
    assert first == second


def test_role_context_is_bounded_secret_free_and_final_is_only_a_handoff() -> None:
    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        leads=[_lead()],
    )
    assert objective is not None
    leads = [
        _lead(fingerprint=f"lead:{index}", endpoint=f"/jobs/{index:08d}") for index in range(20)
    ]
    attempts = [_attempt(family="sql_injection", probe=f"probe-{index}") for index in range(30)]

    context = build_recovery_role_context(
        branch_id="recovery-1-closure",
        objective=objective,
        lease_budget=8,
        lease_used=2,
        evidence_epoch=3,
        leads=leads,
        attempts=attempts,
    )
    encoded = json.dumps(context, sort_keys=True).lower()

    assert context["lease"] == {"budget": 8, "used": 2, "remaining": 6}
    assert len(context["trusted_leads"]) == MAX_CONTEXT_LEADS
    assert len(context["recent_routes"]) == MAX_CONTEXT_ATTEMPTS
    assert "password=" not in encoded
    assert "cookie:" not in encoded
    assert "xben-" not in encoded
    assert "answer key" not in encoded
    assert "final action is a handoff" in encoded


def test_attempt_is_derived_from_executed_route_and_trusted_assessment() -> None:
    assessment = RecoveryEvidenceAssessment(
        snapshot=ProgressSnapshot(),
        material_progress=(),
        observation_digest="trusted-digest",
        route_fingerprint="template_injection:abc123",
        low_value_route=True,
        source_trusted=True,
        reason_codes=("weak_only",),
        leads=(),
    )

    attempt = RecoveryAttempt.from_assessment(
        action={
            "action": "run_probe",
            "probe": "ssti_fingerprint",
            "notes": "bounded template check",
        },
        assessment=assessment,
    )

    assert attempt.family == "template_injection"
    assert attempt.probe == "ssti_fingerprint"
    assert attempt.observation_digest == "trusted-digest"
    assert attempt.low_value is True


def test_specialist_final_is_redacted_handoff_not_campaign_completion() -> None:
    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        leads=[_lead()],
    )
    assert objective is not None

    handoff = recovery_handoff_from_final(
        branch_id="recovery-1-closure",
        objective=objective,
        action={
            "action": "final",
            "summary": "Solved with FLAG{model-written-fake}; password=do-not-forward",
        },
    )
    encoded = json.dumps(handoff.to_json())

    assert handoff.reason == "specialist_final_handoff"
    assert handoff.campaign_terminal is False
    assert "FLAG{" not in encoded
    assert "do-not-forward" not in encoded
    assert handoff.objective_fingerprint == objective.fingerprint


def test_non_final_action_cannot_create_a_specialist_handoff() -> None:
    objective = plan_recovery_objective(
        RecoveryRole.CLOSURE,
        leads=[_lead()],
    )
    assert objective is not None

    with pytest.raises(ValueError, match="final action"):
        recovery_handoff_from_final(
            branch_id="recovery-1-closure",
            objective=objective,
            action={"action": "run_probe", "probe": "sqli_exploit"},
        )


def test_core_cannot_receive_a_delegated_objective() -> None:
    with pytest.raises(ValueError, match="core"):
        plan_recovery_objective(RecoveryRole.CORE, leads=[_lead()])
