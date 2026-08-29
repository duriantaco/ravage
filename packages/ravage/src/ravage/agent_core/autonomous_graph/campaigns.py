# ruff: noqa: CPY001

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.agent_specialists import available_specialists
from ravage.agent_core.autonomous_graph.coverage_ledger import (
    CoverageStage,
    canonical_family,
)
from ravage.agent_core.semantic_routes import semantic_action_route

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.models import GraphObjective


@dataclass(frozen=True)
class CampaignSpec:
    """One finite, deterministic investigation campaign already implemented by Ravage."""

    name: str
    families: tuple[str, ...]
    probe: str
    dimension: str
    eligible_stages: tuple[CoverageStage, ...]
    advances_to: CoverageStage
    information_gain: int
    proof_proximity: int
    purpose: str
    expected_signal: str
    evidence_markers: tuple[str, ...] = ()

    def supports(self, objective: GraphObjective, stage: CoverageStage) -> bool:
        family = canonical_family(objective.family)
        if family not in self.families or stage not in self.eligible_stages:
            return False
        if not self.evidence_markers:
            return True
        text = _objective_text(objective)
        return any(marker in text for marker in self.evidence_markers)

    def action(self) -> dict[str, object]:
        return {
            "tool": "run_probe",
            "arguments": {
                "probe": self.probe,
                "strategy": self.name,
                "expected_signal": self.expected_signal,
            },
            "expected_signal": self.expected_signal,
        }

    def to_json(self, *, score: int = 0) -> dict[str, object]:
        return {
            "name": self.name,
            "family": list(self.families),
            "probe": self.probe,
            "dimension": self.dimension,
            "eligible_stages": [stage.value for stage in self.eligible_stages],
            "advances_to": self.advances_to.value,
            "information_gain": self.information_gain,
            "proof_proximity": self.proof_proximity,
            "purpose": self.purpose,
            "expected_signal": self.expected_signal,
            "score": score,
            "action": self.action(),
        }


_EARLY = (
    CoverageStage.OBSERVED,
    CoverageStage.CONTRACTED,
)
_CALIBRATED_OR_LATER = (
    CoverageStage.CALIBRATED,
    CoverageStage.PRIMITIVE,
    CoverageStage.CLOSURE,
)
_ALL_OPEN = (
    CoverageStage.OBSERVED,
    CoverageStage.CONTRACTED,
    CoverageStage.CALIBRATED,
    CoverageStage.PRIMITIVE,
    CoverageStage.CLOSURE,
)


CAMPAIGN_BOOK: tuple[CampaignSpec, ...] = (
    CampaignSpec(
        name="sql-request-and-oracle-calibration",
        families=("sql_injection",),
        probe="sqli_differential",
        dimension="request_contract_and_query_oracle",
        eligible_stages=_EARLY,
        advances_to=CoverageStage.CALIBRATED,
        information_gain=100,
        proof_proximity=55,
        purpose=(
            "Run the existing paired syntax, Boolean, and timing matrix over the "
            "preserved query surface."
        ),
        expected_signal=(
            "a replayable request contract plus a repeated-control SQL differential, "
            "or bounded target-observed disproof"
        ),
    ),
    CampaignSpec(
        name="sql-form-state-calibration",
        families=("sql_injection", "authentication"),
        probe="captcha_form_state",
        dimension="csrf_captcha_and_form_state",
        eligible_stages=_EARLY,
        advances_to=CoverageStage.CONTRACTED,
        information_gain=82,
        proof_proximity=40,
        purpose="Resolve changing CSRF, captcha, and submit-field state before payload work.",
        expected_signal="a replayable fresh form contract or a bounded form-state disproof",
        evidence_markers=(
            "captcha",
            "challenge",
            "verification",
            "csrf",
            "security code",
            "invalid code",
        ),
    ),
    CampaignSpec(
        name="sql-filter-counterfactual",
        families=("sql_injection",),
        probe="filtered_query_bypass",
        dimension="filter_and_encoding_boundary",
        eligible_stages=_EARLY,
        advances_to=CoverageStage.CALIBRATED,
        information_gain=78,
        proof_proximity=50,
        purpose=(
            "Test the bounded filter/encoding strategy after ordinary SQL-shaped "
            "payloads are rejected or flattened."
        ),
        expected_signal="a stable filter-boundary differential or bounded disproof",
    ),
    CampaignSpec(
        name="sql-primitive-to-proof",
        families=("sql_injection",),
        probe="sqli_exploit",
        dimension="bounded_extraction_and_auth_closure",
        eligible_stages=_CALIBRATED_OR_LATER,
        advances_to=CoverageStage.CLOSURE,
        information_gain=62,
        proof_proximity=100,
        purpose=(
            "Reuse only the calibrated SQL contract for bounded extraction and "
            "authentication/proof closure."
        ),
        expected_signal="a validated primitive, extraction checkpoint, auth transition, or proof",
    ),
    CampaignSpec(
        name="sql-auth-transition-and-session-closure",
        families=("authentication",),
        probe="sqli_auth_transition",
        dimension="password_context_auth_transition_and_same_session_closure",
        eligible_stages=_CALIBRATED_OR_LATER,
        advances_to=CoverageStage.CLOSURE,
        information_gain=96,
        proof_proximity=100,
        purpose=(
            "After a rejected stored credential or confirmed login SQL sink, run one "
            "finite password/username transition matrix before more extraction. Require "
            "a protected same-session delta against an anonymous control and preserve "
            "that session through authenticated upload/readback closure."
        ),
        expected_signal=(
            "explicit login transition plus protected same-session access, exact proof, "
            "or target-observed bounded matrix exhaustion"
        ),
    ),
    CampaignSpec(
        name="auth-session-contract",
        families=("authentication",),
        probe="stateful_session",
        dimension="identity_and_session_contract",
        eligible_stages=_EARLY,
        advances_to=CoverageStage.CONTRACTED,
        information_gain=96,
        proof_proximity=50,
        purpose=(
            "Map login, registration, hidden fields, redirects, cookies, and protected "
            "follow-up behavior in one bounded session."
        ),
        expected_signal="a replayable identity/session contract or bounded auth-surface disproof",
    ),
    CampaignSpec(
        name="auth-bounded-credential-baseline",
        families=("authentication",),
        probe="default_credentials",
        dimension="bounded_credential_and_basic_auth_baseline",
        eligible_stages=_ALL_OPEN,
        advances_to=CoverageStage.CLOSURE,
        information_gain=68,
        proof_proximity=86,
        purpose=(
            "Run the existing finite credential baseline and require protected "
            "same-session readback before accepting authentication."
        ),
        expected_signal="an explicit authenticated transition and protected readback, or disproof",
    ),
    CampaignSpec(
        name="auth-session-boundary",
        families=("authentication",),
        probe="csrf_session",
        dimension="csrf_logout_fixation_and_cookie_boundary",
        eligible_stages=(
            CoverageStage.CONTRACTED,
            CoverageStage.CALIBRATED,
            CoverageStage.PRIMITIVE,
            CoverageStage.CLOSURE,
        ),
        advances_to=CoverageStage.CLOSURE,
        information_gain=74,
        proof_proximity=72,
        purpose=(
            "Test token omission/reuse, session fixation, logout invalidation, and "
            "protected session continuity."
        ),
        expected_signal="a validated session-boundary failure or bounded disproof",
    ),
    CampaignSpec(
        name="file-workflow-calibration",
        families=("file_handling",),
        probe="file_fetch_parser",
        dimension="path_fetch_upload_parser_and_readback",
        eligible_stages=_EARLY,
        advances_to=CoverageStage.CALIBRATED,
        information_gain=100,
        proof_proximity=60,
        purpose=(
            "Map file/path/upload/fetch/parser inputs and pair writes or side effects "
            "with explicit readback."
        ),
        expected_signal="a replayable file workflow, parser side effect, readback, or disproof",
    ),
    CampaignSpec(
        name="file-read-primitive-to-proof",
        families=("file_handling",),
        probe="file_read_extract",
        dimension="confirmed_file_read_closure",
        eligible_stages=_CALIBRATED_OR_LATER,
        advances_to=CoverageStage.CLOSURE,
        information_gain=64,
        proof_proximity=100,
        purpose=(
            "Reuse a confirmed file-read/include contract for bounded source and proof extraction."
        ),
        expected_signal="validated file content or proof readback through the preserved contract",
    ),
    CampaignSpec(
        name="xml-parser-counterfactual",
        families=("file_handling",),
        probe="xxe_boundary",
        dimension="xml_entity_and_svg_upload_boundary",
        eligible_stages=_ALL_OPEN,
        advances_to=CoverageStage.PRIMITIVE,
        information_gain=76,
        proof_proximity=78,
        purpose="Exercise the finite XML/SOAP/SVG entity matrix only on XML-shaped evidence.",
        expected_signal="a validated external-entity file read or bounded parser disproof",
        evidence_markers=("xml", "soap", "wsdl", "svg", "doctype", "entity", "xxe"),
    ),
    CampaignSpec(
        name="ssti-deferred-context-closure",
        families=("template_injection",),
        probe="ssti_deferred_context_closure",
        dimension="deferred_form_context_variable_and_session_workflow",
        eligible_stages=_ALL_OPEN,
        advances_to=CoverageStage.CLOSURE,
        information_gain=98,
        proof_proximity=100,
        purpose=(
            "Reuse a confirmed multi-step registration template sink, preserve "
            "its target-observed form/session contract, and try one finite "
            "context-variable proof matrix before any broader template work."
        ),
        expected_signal=(
            "target-returned proof through the preserved deferred template "
            "workflow, or bounded context-variable exhaustion"
        ),
        evidence_markers=(
            "deferred",
            "multi-step",
            "register",
            "registration",
            "ssti_stored_signal",
            "deferred_form_flow_signal",
        ),
    ),
    CampaignSpec(
        name="ssti-bounded-form-closure",
        families=("template_injection",),
        probe="template_form_closure",
        dimension="preserved_form_template_dialect_and_engine_proof",
        eligible_stages=_ALL_OPEN,
        advances_to=CoverageStage.CLOSURE,
        information_gain=100,
        proof_proximity=100,
        purpose=(
            "After a broad template probe stalls on an observed POST form, test "
            "one tiny dialect matrix and immediately run engine-specific proof "
            "extraction through the preserved form contract."
        ),
        expected_signal=(
            "harmless arithmetic evaluation followed by target-returned proof, "
            "or bounded dialect exhaustion"
        ),
        evidence_markers=(
            "form",
            "generate",
            "preview",
            "render",
            "repeat",
            "template",
        ),
    ),
    CampaignSpec(
        name="upload-include-template-counterfactual",
        families=("file_handling", "template_injection"),
        probe="ssti_fingerprint",
        dimension="upload_include_and_template_execution",
        eligible_stages=_ALL_OPEN,
        advances_to=CoverageStage.PRIMITIVE,
        information_gain=72,
        proof_proximity=84,
        purpose=(
            "Test upload-to-include or template evaluation only when the inherited "
            "surface contains rendering/include evidence."
        ),
        expected_signal="a harmless server-side evaluation primitive or bounded disproof",
        evidence_markers=(
            "template",
            "render",
            "include",
            "upload",
            "calculation",
            "expression",
        ),
    ),
    CampaignSpec(
        name="xss-filter-constraint-closure",
        families=("cross_site_scripting",),
        probe="xss_filter_constraint",
        dimension="element_name_filter_boundary_and_exact_dialog_value",
        eligible_stages=_ALL_OPEN,
        advances_to=CoverageStage.CLOSURE,
        information_gain=96,
        proof_proximity=100,
        purpose=(
            "Reuse an exact reflected request and visible dialog value, vary only "
            "the element-name boundary, and stop after the finite constraint matrix."
        ),
        expected_signal=(
            "target-returned proof from one constraint-derived reflected payload, "
            "or bounded element-name exhaustion"
        ),
        evidence_markers=("reflected", "reflection", "dialog", "alert", "xss"),
    ),
)

_TASK_FAMILIES = {
    "api-behavior": "api_behavior",
    "command-boundary": "command_injection",
    "data-query": "sql_injection",
    "file-fetch-parser": "file_handling",
    "flag-and-secret-sweep": "exposure",
    "input-reflection": "cross_site_scripting",
    "server-rendering": "template_injection",
    "stateful-session": "authentication",
}


def _generated_specialist_campaigns() -> tuple[CampaignSpec, ...]:
    """Lift the existing specialist book into graph-native finite campaigns."""
    explicit_probes = {campaign.probe for campaign in CAMPAIGN_BOOK}
    generated: list[CampaignSpec] = []
    for card in available_specialists():
        probe = str(card.get("probe") or "").strip()
        if not probe or probe in explicit_probes:
            continue
        route = semantic_action_route({"action": "run_probe", "probe": probe})
        family = canonical_family(str(route.get("family") or "unknown"))
        if family == "unknown":
            family = _TASK_FAMILIES.get(
                str(card.get("task_id") or ""),
                "unknown",
            )
        if family == "unknown":
            continue
        stage = str(card.get("stage") or "")
        purpose = str(card.get("purpose") or "").strip()
        handoff = str(card.get("handoff") or "").strip()
        generated.append(
            CampaignSpec(
                name=f"specialist-{probe.replace('_', '-')}",
                families=(family,),
                probe=probe,
                dimension=f"specialist_{family}_{probe}",
                eligible_stages=_ALL_OPEN,
                advances_to=(
                    CoverageStage.CALIBRATED if stage == "exploit" else CoverageStage.CONTRACTED
                ),
                information_gain=72 if stage == "exploit" else 82,
                proof_proximity=70 if stage == "exploit" else 28,
                purpose=purpose,
                expected_signal=(
                    f"{handoff} Return target-observed typed progress or bounded disproof."
                ),
                evidence_markers=tuple(
                    str(marker).lower()
                    for marker in card.get("triggers", [])
                    if str(marker).strip()
                ),
            )
        )
    return tuple(generated)


GENERATED_CAMPAIGNS = _generated_specialist_campaigns()
ALL_CAMPAIGNS = (*CAMPAIGN_BOOK, *GENERATED_CAMPAIGNS)


def campaigns_for_objective(
    objective: GraphObjective,
    *,
    stage: CoverageStage,
) -> tuple[CampaignSpec, ...]:
    family = canonical_family(objective.family)
    return tuple(
        campaign
        for campaign in ALL_CAMPAIGNS
        if campaign.supports(objective, stage)
        or (
            family in campaign.families
            and objective.strategy == campaign.probe
            and stage in campaign.eligible_stages
        )
    )


def campaign_for_probe(
    probe: str,
    *,
    objective: GraphObjective | None = None,
    stage: CoverageStage | None = None,
) -> CampaignSpec | None:
    normalized = probe.strip()
    matches = tuple(campaign for campaign in ALL_CAMPAIGNS if campaign.probe == normalized)
    if objective is not None and stage is not None:
        supported = next(
            (
                campaign
                for campaign in matches
                if campaign.supports(objective, stage)
                or (
                    canonical_family(objective.family) in campaign.families
                    and objective.strategy == normalized
                    and stage in campaign.eligible_stages
                )
            ),
            None,
        )
        if supported is not None:
            return supported
    return matches[0] if matches else None


def initial_stage_for_objective(objective: GraphObjective) -> CoverageStage:
    text = _objective_text(objective)
    strategy = objective.strategy.lower()
    if objective.family == "credential_recovery" or "credential_representation" in text:
        return CoverageStage.CLOSURE
    if strategy == "sqli_auth_transition":
        return CoverageStage.CLOSURE
    if strategy in {"sqli_exploit", "file_read_extract"}:
        return CoverageStage.CALIBRATED
    if any(
        marker in text
        for marker in (
            "primitive confirmed",
            "confirmed primitive",
            "sql_injection_confirmed",
            "file_read_confirmed",
        )
    ):
        return CoverageStage.PRIMITIVE
    if any(
        marker in text
        for marker in (
            "request template",
            "replayable contract",
            "session contract",
        )
    ):
        return CoverageStage.CONTRACTED
    return CoverageStage.OBSERVED


def _objective_text(objective: GraphObjective) -> str:
    return " ".join(
        (
            objective.family,
            objective.strategy,
            objective.instruction,
            objective.expected_signal,
            objective.endpoint,
            *objective.inputs,
        )
    ).lower()


__all__ = [
    "ALL_CAMPAIGNS",
    "CAMPAIGN_BOOK",
    "GENERATED_CAMPAIGNS",
    "CampaignSpec",
    "campaign_for_probe",
    "campaigns_for_objective",
    "initial_stage_for_objective",
]
