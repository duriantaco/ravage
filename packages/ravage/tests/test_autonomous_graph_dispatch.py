from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.beliefs import BeliefLedger
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.dispatch import GraphDispatchPlanner
from ravage.agent_core.autonomous_graph.models import GraphObjective
from ravage.agent_core.autonomous_graph.scheduler import (
    ProgressKind,
    ProgressReceipt,
    ProgressSource,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


@dataclass(frozen=True)
class _EvidenceRecord:
    evidence_id: str
    target_identity: str
    producer_node_id: str
    kind: str = "response_differential"
    source: str = "tool_http_request"
    material: bool = True


class _Validator:
    target_identity = "target:dispatch-test"

    def __init__(self, producer_node_id: str) -> None:
        self.producer_node_id = producer_node_id

    def validate_references(
        self,
        evidence_refs: Sequence[str],
        *,
        require_trusted: bool = False,
    ) -> tuple[object, ...]:
        assert require_trusted is True
        assert tuple(evidence_refs) == ("evidence:supported",)
        return (
            _EvidenceRecord(
                evidence_id="evidence:supported",
                target_identity=self.target_identity,
                producer_node_id=self.producer_node_id,
            ),
        )


def _objective(instruction: str) -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction=instruction,
        endpoint="/search",
        inputs=("query",),
        strategy="bounded differential",
        expected_signal=f"target-observed evidence for {instruction}",
    )


@pytest.mark.asyncio
async def test_verified_belief_can_outrank_earlier_proposed_node(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="dispatch-test",
        root_objective=_objective("coordinate the route"),
        root_lease_limit=3,
    )
    earlier = await coordinator.spawn_node(
        parent_id="node-001",
        name="earlier",
        objective=_objective("inspect the first bounded route"),
    )
    supported = await coordinator.spawn_node(
        parent_id="node-001",
        name="supported",
        objective=_objective("inspect the supported bounded route"),
    )
    assert supported.hypothesis is not None
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=_Validator(supported.node_id),
    )
    ledger.record_from_receipts(
        hypothesis=supported.hypothesis,
        agent_spec=supported.agent_spec,
        producer_node_id=supported.node_id,
        receipts=(
            ProgressReceipt(
                kind=ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
                value="stable response differential",
                evidence_ref="evidence:supported",
                source=ProgressSource.TARGET_OBSERVATION,
            ),
        ),
        evidence_epoch=1,
    )

    ranked = GraphDispatchPlanner(ledger).rank(
        (
            coordinator.state.nodes[earlier.node_id],
            coordinator.state.nodes[supported.node_id],
        )
    )

    assert tuple(node.node_id for node in ranked) == (
        supported.node_id,
        earlier.node_id,
    )
    assert GraphDispatchPlanner(ledger).score(ranked[0]).belief_status == "supported"


@pytest.mark.asyncio
async def test_proof_eligible_lane_preempts_higher_exploration_utility(
    tmp_path: Path,
) -> None:
    coordinator = GraphCoordinator.start(
        graph_id="dispatch-proof-test",
        root_objective=_objective("coordinate the route"),
        root_lease_limit=3,
    )
    proof_ready = await coordinator.spawn_node(
        parent_id="node-001",
        name="proof-ready",
        objective=_objective("validate the proof candidate"),
    )
    supported = await coordinator.spawn_node(
        parent_id="node-001",
        name="supported",
        objective=_objective("inspect the supported bounded route"),
    )
    coordinator.state.nodes[proof_ready.node_id].proof_eligible = True
    assert supported.hypothesis is not None
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=_Validator(supported.node_id),
    )
    ledger.record_from_receipts(
        hypothesis=supported.hypothesis,
        agent_spec=supported.agent_spec,
        producer_node_id=supported.node_id,
        receipts=(
            ProgressReceipt(
                kind=ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
                value="stable response differential",
                evidence_ref="evidence:supported",
                source=ProgressSource.TARGET_OBSERVATION,
            ),
        ),
        evidence_epoch=1,
    )

    ranked = GraphDispatchPlanner(ledger).rank(
        (
            coordinator.state.nodes[supported.node_id],
            coordinator.state.nodes[proof_ready.node_id],
        )
    )

    assert ranked[0].node_id == proof_ready.node_id
