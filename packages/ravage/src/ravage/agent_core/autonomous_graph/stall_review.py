# ruff: noqa: CPY001

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.loop_policy import (
    LoopDecision,
    LoopDisposition,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphNodeStatus,
    GraphState,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

MAX_STALL_REVIEWS_PER_GRAPH = 1
MAX_STALL_REVIEWS_PER_NODE = 1


@dataclass(frozen=True)
class StallReviewDirective:
    node_id: str
    token: str
    reason: str
    evidence_version: int
    required_dimension: str
    recommended_campaign: str
    recommended_probe: str

    def prompt(self) -> str:
        packet = {
            "kind": "bounded_stall_review",
            "node_id": self.node_id,
            "trigger": self.reason,
            "evidence_version": self.evidence_version,
            "required_material_dimension": self.required_dimension,
            "recommended_campaign": self.recommended_campaign,
            "recommended_probe": self.recommended_probe,
            "constraints": [
                "This is the only stall-review grant for the graph.",
                "Do not repeat a prior semantic action or cosmetic payload variant.",
                (
                    "Choose the named untried campaign when supplied; otherwise "
                    "declare one materially different dimension."
                ),
                (
                    "Target work still requires ordinary campaign authorization "
                    "and target-request accounting."
                ),
                "If no materially distinct route exists, finish with bounded exhaustion.",
            ],
        }
        return "BOUNDED_STALL_REVIEW\n" + json.dumps(
            packet,
            ensure_ascii=False,
            sort_keys=True,
        )


def select_stall_review(
    state: GraphState,
    steps: Sequence[object],
) -> StallReviewDirective | None:
    """Select one replay-stable targeted bump from typed plateau decisions."""
    if len(state.stall_review_tokens) >= MAX_STALL_REVIEWS_PER_GRAPH:
        return None
    waiting = sorted(
        (
            node
            for node in state.nodes.values()
            if node.status is GraphNodeStatus.WAITING
            and node.lease_used >= node.lease_limit
            and node.stall_review_grants < MAX_STALL_REVIEWS_PER_NODE
        ),
        key=lambda node: node.node_id,
    )
    for node in waiting:
        decision = _latest_reviewable_decision(node.node_id, steps)
        if decision is None:
            continue
        payload = {
            "node_id": node.node_id,
            "objective": node.objective.fingerprint,
            "evidence_version": decision.evidence_version,
            "reason": decision.reason,
            "required_dimension": decision.required_dimension,
            "recommended_campaign": decision.recommended_campaign,
            "recommended_probe": decision.recommended_probe,
        }
        token = (
            "stall-review:"
            + hashlib.sha256(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            ).hexdigest()
        )
        if token in state.stall_review_tokens:
            continue
        return StallReviewDirective(
            node_id=node.node_id,
            token=token,
            reason=decision.reason,
            evidence_version=decision.evidence_version,
            required_dimension=decision.required_dimension,
            recommended_campaign=decision.recommended_campaign,
            recommended_probe=decision.recommended_probe,
        )
    return None


def _latest_reviewable_decision(
    node_id: str,
    steps: Sequence[object],
) -> LoopDecision | None:
    for step in reversed(steps):
        if str(getattr(step, "node_id", "")) != node_id:
            continue
        decision = getattr(step, "loop_decision", None)
        if not isinstance(decision, LoopDecision):
            continue
        if decision.disposition is not LoopDisposition.PIVOT:
            return None
        if not (
            decision.required_dimension
            or decision.recommended_campaign
            or decision.recommended_probe
        ):
            return None
        return decision
    return None


__all__ = [
    "MAX_STALL_REVIEWS_PER_GRAPH",
    "MAX_STALL_REVIEWS_PER_NODE",
    "StallReviewDirective",
    "select_stall_review",
]
