from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.recovery_xss_filter_knowledge import (
    XSS_FILTER_CONSTRAINT_CLOSURE,
    is_xss_filter_constraint_closure_lead,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ravage.agent_core.recovery_evidence import RecoveryLead

_STORED_TEMPLATE_FINDINGS = frozenset({"ssti_stored_signal"})


@dataclass(frozen=True)
class RecoveryKnowledgeModule:
    """Static technique guidance activated only by matching trusted evidence."""

    module_id: str
    family: str
    purpose: str
    workflow: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    constraints: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "module_id": self.module_id,
            "family": self.family,
            "purpose": self.purpose,
            "workflow": list(self.workflow),
            "stop_conditions": list(self.stop_conditions),
            "constraints": list(self.constraints),
        }


_STATEFUL_TEMPLATE_CLOSURE = RecoveryKnowledgeModule(
    module_id="template-injection-stateful-closure-v1",
    family="template_injection",
    purpose=(
        "Convert confirmed stored or deferred template evaluation into bounded proof closure "
        "without repeating discovery."
    ),
    workflow=(
        (
            "Treat confirmed stored or deferred template evaluation as the primitive; do not "
            "spend this lease rediscovering arithmetic evaluation."
        ),
        "Preserve one cookie/session jar and anti-CSRF state across the complete workflow.",
        (
            "Parse every response for the next form action, method, hidden fields, and required "
            "inputs; submit every transition in order. Never replace a required POST with a GET."
        ),
        (
            "Keep the proven sink input populated with the current test value and provide valid "
            "benign values for every companion input."
        ),
        (
            "Infer the template engine only from target-observed syntax, output, or errors, and "
            "change one payload class at a time."
        ),
        (
            "Inspect the complete response body, headers, redirect history, and resulting form "
            "after every transition."
        ),
        (
            "If relevant output is truncated or stored as an artifact, read that artifact or "
            "rerun one bounded exact extraction before changing techniques."
        ),
    ),
    stop_conditions=(
        (
            "After two low-value executions without changing a material route dimension such as "
            "state transition, endpoint, engine hypothesis, or payload class, hand control back."
        ),
        (
            "When exact target output satisfies the existing proof recognizer, use the existing "
            "capture gate immediately."
        ),
    ),
    constraints=(
        "This module grants no progress, proof status, lease renewal, or additional budget.",
        "Target observations and the existing proof gate remain authoritative.",
    ),
)

_XSS_FILTER_CONSTRAINT_CLOSURE = RecoveryKnowledgeModule(
    module_id=XSS_FILTER_CONSTRAINT_CLOSURE.module_id,
    family=XSS_FILTER_CONSTRAINT_CLOSURE.family,
    purpose=XSS_FILTER_CONSTRAINT_CLOSURE.purpose,
    workflow=XSS_FILTER_CONSTRAINT_CLOSURE.workflow,
    stop_conditions=XSS_FILTER_CONSTRAINT_CLOSURE.stop_conditions,
    constraints=XSS_FILTER_CONSTRAINT_CLOSURE.constraints,
)


def select_recovery_knowledge_modules(
    *,
    objective_family: str,
    objective_evidence_fingerprint: str,
    objective_material_lead: bool,
    leads: Sequence[RecoveryLead],
) -> tuple[RecoveryKnowledgeModule, ...]:
    """Select static guidance only from an exact matching trusted lead."""
    if not objective_evidence_fingerprint:
        return ()
    matching_lead = next(
        (lead for lead in leads if lead.fingerprint == objective_evidence_fingerprint),
        None,
    )
    if matching_lead is None or matching_lead.family != objective_family:
        return ()
    modules: list[RecoveryKnowledgeModule] = []
    if (
        objective_material_lead
        and matching_lead.material
        and matching_lead.family == _STATEFUL_TEMPLATE_CLOSURE.family
        and matching_lead.finding_type in _STORED_TEMPLATE_FINDINGS
    ):
        modules.append(_STATEFUL_TEMPLATE_CLOSURE)
    if is_xss_filter_constraint_closure_lead(
        matching_lead,
        objective_family=objective_family,
        objective_evidence_fingerprint=objective_evidence_fingerprint,
    ):
        modules.append(_XSS_FILTER_CONSTRAINT_CLOSURE)
    return tuple(modules)
