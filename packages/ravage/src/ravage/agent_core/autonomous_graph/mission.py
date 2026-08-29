from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.models import GraphObjective, GraphState


class GraphMission(StrEnum):
    """Durable graph mission encoded by the manifest-bound root objective."""

    FLAG_CAPTURE = "flag_capture"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"


FLAG_CAPTURE_STRATEGY = "evidence_gated_specialist_graph"
VULNERABILITY_ASSESSMENT_STRATEGY = "evidence_gated_finding_graph"


def graph_mission_for_flag_objective(flag_objective: bool) -> GraphMission:
    return (
        GraphMission.FLAG_CAPTURE
        if flag_objective
        else GraphMission.VULNERABILITY_ASSESSMENT
    )


def graph_mission_from_objective(objective: GraphObjective) -> GraphMission:
    if objective.strategy == VULNERABILITY_ASSESSMENT_STRATEGY:
        return GraphMission.VULNERABILITY_ASSESSMENT
    # Old snapshots predate mission metadata and were exclusively proof-oriented.
    return GraphMission.FLAG_CAPTURE


def graph_mission_from_state(state: GraphState) -> GraphMission:
    return graph_mission_from_objective(state.nodes[state.root_node_id].objective)


__all__ = [
    "FLAG_CAPTURE_STRATEGY",
    "GraphMission",
    "VULNERABILITY_ASSESSMENT_STRATEGY",
    "graph_mission_for_flag_objective",
    "graph_mission_from_objective",
    "graph_mission_from_state",
]
