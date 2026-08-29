from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.mission import VULNERABILITY_ASSESSMENT_STRATEGY

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.models import GraphObjective


@dataclass(frozen=True)
class SpecialistProfile:
    name: str
    guidance: tuple[str, ...]

    def prompt(self) -> str:
        numbered = " ".join(
            f"{index}. {instruction}" for index, instruction in enumerate(self.guidance, start=1)
        )
        return f"Specialist profile: {self.name}. {numbered}"


def specialist_profile(objective: GraphObjective) -> SpecialistProfile:
    """Select deterministic skills from the assigned family and closure stage."""
    family = objective.family.lower()
    strategy = objective.strategy.lower()
    if family == "graph_coordination":
        if strategy == VULNERABILITY_ASSESSMENT_STRATEGY:
            return SpecialistProfile(
                name="finding-route-coordinator",
                guidance=(
                    "Coordinate existing workers and inbox evidence; do not duplicate probes.",
                    "Prefer class-aware validation of a candidate over fresh reconnaissance.",
                    "Treat a persisted confirmed finding as a legitimate route completion.",
                    "When no finding is confirmed, require finite materially distinct coverage.",
                ),
            )
        return SpecialistProfile(
            name="evidence-route-coordinator",
            guidance=(
                "Coordinate existing workers and inbox evidence; do not duplicate their probes.",
                "Prefer a pending closure obligation over fresh reconnaissance.",
                "Spawn only one owner for each canonical closure task and park while it works.",
                "Submit proof only through blackboard evidence references accepted by the gate.",
            ),
        )
    if family == "credential_recovery" or "credential_representation" in strategy:
        return SpecialistProfile(
            name="credential-representation-and-auth-closure",
            guidance=(
                (
                    "The inherited stored value was rejected as plaintext; do not extract or "
                    "submit that same value again."
                ),
                (
                    "First choose one bounded material alternative: offline representation "
                    "recovery, a finite credential transform/dictionary check, or an adjacent "
                    "username/password authentication-bypass sink using the preserved contract."
                ),
                (
                    "Prefer the finite run_probe sqli_auth_transition campaign when it is "
                    "recommended; it owns same-session verification and authenticated closure."
                ),
                (
                    "Keep offline recovery separate from target authentication so the rejected "
                    "stored value cannot accidentally be replayed."
                ),
                (
                    "Then verify an explicit successful login and protected same-session access; "
                    "a fresh cookie alone is not authentication."
                ),
                (
                    "If the bounded alternative fails, report target-observed counter-evidence "
                    "with its evidence refs instead of repeating the route."
                ),
            ),
        )
    if family == "sql_injection":
        return SpecialistProfile(
            name="calibrated-sql-closure",
            guidance=(
                "Preserve the known endpoint, method, fields, and session.",
                (
                    "Before extraction, use a coordinator-owned probe/validator to establish "
                    "a Boolean oracle with repeated controls: 1=1 and 2=2 must agree, 1=0 and "
                    "2=1 must agree, and the groups must differ."
                ),
                (
                    "Use one finite extractor with explicit bounds and emit TARGET_LEN, "
                    "PREFIX[position], and EXTRACTED_<KIND> markers."
                ),
                (
                    "Treat extracted database values as stored representations, not plaintext "
                    "credentials, until the target validates an authentication transition."
                ),
                (
                    "After a rejected replay, stop extraction and allow the coordinator to route "
                    "credential representation/auth closure."
                ),
            ),
        )
    if "proof" in family or "closure" in strategy:
        return SpecialistProfile(
            name="proof-closure",
            guidance=(
                "Use the shortest transition from confirmed primitive to protected readback.",
                "Preserve the target session and record exact target-observed evidence.",
                (
                    "Do not substitute an intermediate secret, model statement, or fresh cookie "
                    "for proof."
                ),
            ),
        )
    return SpecialistProfile(
        name=f"{family or 'generic'}-bounded-specialist",
        guidance=(
            "Work depth-first on the assigned endpoint and inputs.",
            "Change one material dimension after negative evidence.",
            "Do not repeat an equivalent tool effect or broaden to an unrelated family.",
            "Return target-observed evidence refs or finish with bounded exhaustion.",
        ),
    )


def specialist_system_guidance(objective: GraphObjective) -> str:
    return specialist_profile(objective).prompt()


__all__ = [
    "SpecialistProfile",
    "specialist_profile",
    "specialist_system_guidance",
]
