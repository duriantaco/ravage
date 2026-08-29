from __future__ import annotations

import json

import pytest
from ravage.agent_core.recovery_evidence import RecoveryLead
from ravage.agent_core.recovery_knowledge import select_recovery_knowledge_modules
from ravage.agent_core.recovery_objectives import (
    build_recovery_role_context,
    plan_recovery_objective,
)
from ravage.agent_core.recovery_policy import MaterialProgressKind, RecoveryRole
from ravage.agent_core.recovery_xss_filter_knowledge import (
    XSS_FILTER_CONSTRAINT_CLOSURE,
    is_xss_filter_constraint_closure_lead,
)

MAX_MODULE_JSON_CHARS = 3500


def _lead(  # noqa: PLR0913 - compact selection-contract fixture.
    *,
    fingerprint: str = "lead:xss-context",
    finding_type: str = "xss_reflection_context",
    family: str = "cross_site_scripting",
    material: bool = False,
    endpoint: str = "/search?query",
    inputs: tuple[str, ...] = ("query",),
) -> RecoveryLead:
    progress = (MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,) if material else ()
    return RecoveryLead(
        fingerprint=fingerprint,
        finding_type=finding_type,
        family=family,
        probe="xss_context",
        method="GET",
        endpoints=(endpoint,) if endpoint else (),
        inputs=inputs,
        progress_kinds=progress,
    )


def _select(
    lead: RecoveryLead,
    *,
    family: str | None = None,
    evidence_fingerprint: str | None = None,
    material_lead: bool | None = None,
) -> tuple[object, ...]:
    return select_recovery_knowledge_modules(
        objective_family=family if family is not None else lead.family,
        objective_evidence_fingerprint=(
            evidence_fingerprint if evidence_fingerprint is not None else lead.fingerprint
        ),
        objective_material_lead=(material_lead if material_lead is not None else lead.material),
        leads=[lead],
    )


def test_trusted_xss_context_selects_constraint_closure_without_buying_progress() -> None:
    lead = _lead(material=False)

    assert is_xss_filter_constraint_closure_lead(
        lead,
        objective_family=lead.family,
        objective_evidence_fingerprint=lead.fingerprint,
    )
    modules = _select(lead)

    assert [module.module_id for module in modules] == [
        "cross-site-scripting-filter-constraint-closure-v1"
    ]
    encoded = json.dumps(modules[0].to_json(), sort_keys=True).lower()
    assert "treat filter responses as constraints" in encoded
    assert "vary exactly one syntax dimension" in encoded
    assert "custom or unknown element" in encoded
    assert "closing syntax" in encoded
    assert "six constraint-derived variants" in encoded
    assert "grants no progress" in encoded


def test_material_reflection_delta_can_select_same_constraint_closure() -> None:
    lead = _lead(finding_type="reflection_value_delta", material=True)

    modules = _select(lead)

    assert [module.module_id for module in modules] == [
        "cross-site-scripting-filter-constraint-closure-v1"
    ]


@pytest.mark.parametrize(
    ("lead", "selection_overrides"),
    [
        (_lead(), {"evidence_fingerprint": "lead:someone-else"}),
        (_lead(finding_type="input_delta"), {}),
        (_lead(family="template_injection"), {}),
        (_lead(), {"family": "template_injection"}),
        (_lead(endpoint=""), {}),
        (_lead(inputs=()), {}),
    ],
)
def test_unscoped_or_non_matching_xss_evidence_selects_no_constraint_module(
    lead: RecoveryLead,
    selection_overrides: dict[str, object],
) -> None:
    assert _select(lead, **selection_overrides) == ()


def test_xss_constraint_module_is_static_bounded_and_not_an_answer_key() -> None:
    payload = XSS_FILTER_CONSTRAINT_CLOSURE.to_json()
    encoded = json.dumps(payload, sort_keys=True).lower()

    assert len(encoded) <= MAX_MODULE_JSON_CHARS
    for forbidden in (
        "xben",
        "answer key",
        "flag{",
        "/flag.txt",
        "/search",
        "query",
        "<z",
        "benchmark",
    ):
        assert forbidden not in encoded


def test_counterfactual_context_wires_xss_module_to_exact_trusted_objective() -> None:
    lead = _lead(material=False)
    objective = plan_recovery_objective(RecoveryRole.COUNTERFACTUAL, leads=[lead])
    assert objective is not None
    assert objective.probe == "xss_filter_constraint"
    assert objective.evidence_fingerprint == lead.fingerprint

    context = build_recovery_role_context(
        branch_id="recovery-1-counterfactual",
        objective=objective,
        lease_budget=8,
        lease_used=0,
        evidence_epoch=1,
        leads=[lead],
        attempts=[],
    )

    assert [module["module_id"] for module in context["knowledge_modules"]] == [
        "cross-site-scripting-filter-constraint-closure-v1"
    ]

    mismatched = build_recovery_role_context(
        branch_id="recovery-1-counterfactual",
        objective=objective,
        lease_budget=8,
        lease_used=0,
        evidence_epoch=1,
        leads=[_lead(fingerprint="lead:not-the-objective")],
        attempts=[],
    )

    assert mismatched["knowledge_modules"] == []
