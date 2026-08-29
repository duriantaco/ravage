from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ravage.agent_core.recovery_evidence import RecoveryLead

_SUPPORTED_FINDINGS = frozenset(
    {
        "reflection_value_delta",
        "reflection_value_expected_signal",
        "xss_reflection_context",
    }
)


@dataclass(frozen=True)
class RecoveryKnowledgeBlueprint:
    """Static module content kept separate from the recovery registry."""

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


XSS_FILTER_CONSTRAINT_CLOSURE = RecoveryKnowledgeBlueprint(
    module_id="cross-site-scripting-filter-constraint-closure-v1",
    family="cross_site_scripting",
    purpose=(
        "Convert a trusted reflected-input or value-boundary lead into bounded client-side "
        "proof by solving target-observed filter constraints instead of replaying a fixed list."
    ),
    workflow=(
        (
            "Reuse the exact target-observed method, endpoint, input, companion fields, and "
            "session state. Do not restart surface discovery."
        ),
        (
            "Treat filter responses as constraints, not execution or proof. Record which syntax "
            "classes are reflected, encoded, removed, or rejected."
        ),
        (
            "Preserve one executable event skeleton and vary exactly one syntax dimension per "
            "attempt: element name, delimiter, event carrier, or required dialog value."
        ),
        (
            "When common element names are rejected but raw markup and event attributes still "
            "survive, sample boundary characters and custom or unknown element names rather "
            "than retrying equivalent common elements."
        ),
        (
            "If a delimiter or closing syntax is rejected, omit that optional syntax while "
            "keeping the opening element and event behavior intact."
        ),
        (
            "Take the required dialog or callback value from the visible target objective; do "
            "not substitute a generic marker when the target names an exact value."
        ),
        (
            "Submit one candidate at a time through the preserved request template and inspect "
            "the full response branch for target-returned proof before using a local browser."
        ),
    ),
    stop_conditions=(
        "Stop immediately when the existing proof recognizer confirms target-returned proof.",
        (
            "After at most six constraint-derived variants without a new allowed syntax class "
            "or execution signal, hand control back."
        ),
        (
            "After two indistinguishable blocked responses from the same syntax class, change "
            "one material dimension or hand control back."
        ),
    ),
    constraints=(
        "This module grants no progress, proof status, lease renewal, or additional budget.",
        "Use only target-observed behavior and the visible objective; do not consult source code.",
        "The existing scope guard, request accounting, and proof gate remain authoritative.",
    ),
)


def is_xss_filter_constraint_closure_lead(
    lead: RecoveryLead,
    *,
    objective_family: str,
    objective_evidence_fingerprint: str,
) -> bool:
    """Require one exact, replayable trusted lead before exposing this tactic."""
    return (
        objective_family == XSS_FILTER_CONSTRAINT_CLOSURE.family
        and lead.family == objective_family
        and bool(objective_evidence_fingerprint)
        and lead.fingerprint == objective_evidence_fingerprint
        and lead.finding_type in _SUPPORTED_FINDINGS
        and bool(lead.endpoints)
        and bool(lead.inputs)
    )
