"""
Evidence-gated autonomous agent graph.

This package is additive. It does not alter the frozen base agent or the
existing serial frontier route.
"""

from ravage.agent_core.autonomous_graph.coordinator import (
    DuplicateGraphObjectiveError,
    GraphBudgetExceededError,
    GraphConcurrencyLimitError,
    GraphCoordinator,
    GraphCoordinatorError,
    GraphLeaseExhaustedError,
    GraphLeaseGrantError,
    GraphLifecycleError,
    GraphNodeLimitError,
    RepeatedGraphActionError,
    UnknownGraphNodeError,
)
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphAgentRole,
    GraphLimits,
    GraphMessage,
    GraphMessageKind,
    GraphNode,
    GraphNodeStatus,
    GraphObjective,
    GraphRaceGroup,
    GraphRaceLane,
    GraphState,
    GraphStatus,
    Hypothesis,
    RaceClaimDecision,
    RaceClaimStatus,
)
from ravage.agent_core.autonomous_graph.run_ownership import (
    RunOwnershipGuard,
    RunOwnershipInactiveError,
    RunOwnershipReconciliationError,
)
from ravage.agent_core.autonomous_graph.run_store import (
    ActionLifecycle,
    ActionRecord,
    ProjectionUpdate,
    RecoveryReport,
    RunLease,
    RunLeaseConflictError,
    RunLeaseLostError,
    RunStore,
    RunStoreError,
)
from ravage.agent_core.autonomous_graph.runtime_binding import (
    GraphRuntimeBindingError,
    GraphRuntimePolicyKeys,
    GraphRuntimeResolver,
    ResolvedGraphRuntime,
)
from ravage.agent_core.autonomous_graph.runtime_manifest import (
    GraphRuntimeManifest,
    GraphRuntimeManifestError,
)
from ravage.agent_core.autonomous_graph.worker import GraphDurabilityError

__all__ = [
    "ActionLifecycle",
    "ActionRecord",
    "AgentSpec",
    "DuplicateGraphObjectiveError",
    "GraphAgentRole",
    "GraphBudgetExceededError",
    "GraphConcurrencyLimitError",
    "GraphCoordinator",
    "GraphCoordinatorError",
    "GraphDurabilityError",
    "GraphLeaseExhaustedError",
    "GraphLeaseGrantError",
    "GraphLifecycleError",
    "GraphLimits",
    "GraphMessage",
    "GraphMessageKind",
    "GraphNode",
    "GraphNodeLimitError",
    "GraphNodeStatus",
    "GraphObjective",
    "GraphRaceGroup",
    "GraphRaceLane",
    "GraphRuntimeBindingError",
    "GraphRuntimeManifest",
    "GraphRuntimeManifestError",
    "GraphRuntimePolicyKeys",
    "GraphRuntimeResolver",
    "GraphState",
    "GraphStatus",
    "Hypothesis",
    "ProjectionUpdate",
    "RaceClaimDecision",
    "RaceClaimStatus",
    "RecoveryReport",
    "RepeatedGraphActionError",
    "ResolvedGraphRuntime",
    "RunLease",
    "RunLeaseConflictError",
    "RunLeaseLostError",
    "RunOwnershipGuard",
    "RunOwnershipInactiveError",
    "RunOwnershipReconciliationError",
    "RunStore",
    "RunStoreError",
    "UnknownGraphNodeError",
]
