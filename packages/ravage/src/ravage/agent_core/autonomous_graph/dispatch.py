"""Evidence-grounded, deterministic node dispatch for one-turn graph quanta."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.beliefs import (
    BeliefDisposition,
    BeliefLedger,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphAgentRole,
    GraphNode,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

_ROLE_UTILITY = {
    GraphAgentRole.COORDINATOR: 1000,
    GraphAgentRole.DISCOVERY: 2200,
    GraphAgentRole.CRITIC: 3000,
    GraphAgentRole.EXPLOITATION: 4200,
    GraphAgentRole.VALIDATOR: 5000,
    GraphAgentRole.SPECIALIST: 2500,
}
_BELIEF_UTILITY = {
    BeliefDisposition.SUPPORTED: 6500,
    BeliefDisposition.CONFIRMED: 10_000,
    BeliefDisposition.DISPROVED: 500,
}


@dataclass(frozen=True)
class DispatchScore:
    node_id: str
    utility: int
    proof_priority: int
    belief_status: str
    reason: str

    @property
    def ordering_key(self) -> tuple[int, int, str]:
        return (-self.proof_priority, -self.utility, self.node_id)


class GraphDispatchPlanner:
    """
    Rank settled workers between turns using control-plane and evidence state.

    The score intentionally excludes model-authored confidence. A belief affects
    priority only after a trusted executor receipt has created a BeliefRevision.
    """

    def __init__(self, beliefs: BeliefLedger | None = None) -> None:
        self.beliefs = beliefs

    def score(self, node: GraphNode) -> DispatchScore:
        belief_status = "proposed"
        belief_utility = 2500
        if self.beliefs is not None and node.hypothesis is not None:
            revision = self.beliefs.head(node.hypothesis.fingerprint)
            if revision is not None:
                belief_status = revision.disposition.value
                belief_utility = _BELIEF_UTILITY[revision.disposition]
        role_utility = _ROLE_UTILITY[node.agent_spec.role]
        evidence_novelty = (
            min(
                len(node.hypothesis.basis_evidence_refs) if node.hypothesis is not None else 0,
                5,
            )
            * 100
        )
        repeated_penalty = node.repeated_observation_count * 1000
        turn_penalty = node.model_requests_started * 200
        utility = belief_utility + role_utility + evidence_novelty - repeated_penalty - turn_penalty
        return DispatchScore(
            node_id=node.node_id,
            utility=max(utility, 0),
            proof_priority=int(node.proof_eligible),
            belief_status=belief_status,
            reason=(
                f"belief={belief_status}:{belief_utility},"
                f"role={node.agent_spec.role.value}:{role_utility},"
                f"evidence_novelty={evidence_novelty},"
                f"repeated_penalty={repeated_penalty},"
                f"turn_penalty={turn_penalty}"
            ),
        )

    def rank(self, nodes: Iterable[GraphNode]) -> tuple[GraphNode, ...]:
        return tuple(
            sorted(
                nodes,
                key=lambda node: self.score(node).ordering_key,
            )
        )


__all__ = [
    "DispatchScore",
    "GraphDispatchPlanner",
]
