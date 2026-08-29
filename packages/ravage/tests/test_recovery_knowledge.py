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

MAX_MODULE_JSON_CHARS = 3000


def _lead(  # noqa: PLR0913 - compact selection-contract fixture.
    *,
    fingerprint: str = "lead:stored-template",
    finding_type: str = "ssti_stored_signal",
    family: str = "template_injection",
    material: bool = True,
    endpoint: str = "/workflow/start",
    inputs: tuple[str, ...] = ("display_name", "confirmation"),
) -> RecoveryLead:
    progress = (MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,) if material else ()
    return RecoveryLead(
        fingerprint=fingerprint,
        finding_type=finding_type,
        family=family,
        probe="ssti_fingerprint",
        method="POST",
        endpoints=(endpoint,),
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


def test_trusted_material_stored_template_lead_selects_stateful_closure_module() -> None:
    modules = _select(_lead())

    assert [module.module_id for module in modules] == ["template-injection-stateful-closure-v1"]
    payload = modules[0].to_json()
    encoded = json.dumps(payload, sort_keys=True).lower()
    assert payload["family"] == "template_injection"
    assert "preserve one cookie/session jar" in encoded
    assert "submit every transition in order" in encoded
    assert "required post" in encoded
    assert "two low-value" in encoded


@pytest.mark.parametrize(
    ("lead", "selection_overrides"),
    [
        (_lead(material=False), {}),
        (_lead(), {"material_lead": False}),
        (_lead(), {"evidence_fingerprint": "lead:someone-else"}),
        (_lead(finding_type="ssti_fingerprint_signal"), {}),
        (_lead(family="sql_injection"), {}),
        (_lead(), {"family": "sql_injection"}),
    ],
)
def test_non_matching_or_non_material_evidence_selects_no_module(
    lead: RecoveryLead,
    selection_overrides: dict[str, object],
) -> None:
    assert _select(lead, **selection_overrides) == ()


def test_module_is_static_bounded_and_contains_no_target_or_answer_material() -> None:
    first = _select(
        _lead(
            endpoint="/private/target-route",
            inputs=("password", "secret_token"),
        )
    )[0].to_json()
    second = _select(
        _lead(
            endpoint="/different/route",
            inputs=("name", "email"),
        )
    )[0].to_json()
    encoded = json.dumps(first, sort_keys=True).lower()

    assert first == second
    assert len(encoded) <= MAX_MODULE_JSON_CHARS
    for forbidden in (
        "xben",
        "answer key",
        "flag{",
        "/flag.txt",
        "/private/target-route",
        "secret_token",
        "settings.secret_key",
        "{{",
    ):
        assert forbidden not in encoded


def test_recovery_context_includes_module_only_for_its_matching_trusted_objective() -> None:
    matching = _lead()
    objective = plan_recovery_objective(RecoveryRole.CLOSURE, leads=[matching])
    assert objective is not None

    context = build_recovery_role_context(
        branch_id="recovery-1-closure",
        objective=objective,
        lease_budget=8,
        lease_used=1,
        evidence_epoch=2,
        leads=[matching, _lead(fingerprint="lead:later-unrelated", family="sql_injection")],
        attempts=[],
    )

    modules = context["knowledge_modules"]
    assert isinstance(modules, list)
    assert [module["module_id"] for module in modules] == ["template-injection-stateful-closure-v1"]

    mismatched_context = build_recovery_role_context(
        branch_id="recovery-1-closure",
        objective=objective,
        lease_budget=8,
        lease_used=1,
        evidence_epoch=2,
        leads=[_lead(fingerprint="lead:not-the-objective")],
        attempts=[],
    )

    assert mismatched_context["knowledge_modules"] == []
