from __future__ import annotations

import json

import pytest
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphAgentRole,
    GraphObjective,
)
from ravage.agent_core.autonomous_graph.runtime_binding import (
    GraphRuntimeBindingError,
    GraphRuntimePolicyKeys,
    GraphRuntimeResolver,
)
from ravage.agent_core.autonomous_graph.worker import (
    GraphModelReply,
    GraphToolResult,
)


async def _complete(
    node_id: str,
    messages: list[dict[str, str]],
) -> GraphModelReply:
    del node_id, messages
    return GraphModelReply(content='{"kind":"wait","payload":{}}')


async def _execute(
    node_id: str,
    tool: str,
    arguments: dict[str, object],
) -> GraphToolResult:
    del node_id, tool, arguments
    return GraphToolResult(output="ok")


def _objective() -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction="Coordinate a bounded route",
        strategy="differential",
        expected_signal="typed target observation",
    )


def test_runtime_binding_is_sticky_to_immutable_agent_spec() -> None:
    coordinator = GraphCoordinator.start(
        graph_id="runtime-binding-test",
        root_objective=_objective(),
    )
    resolver = GraphRuntimeResolver(
        default_complete=_complete,
        default_execute=_execute,
    )
    node = coordinator.state.nodes["node-001"]
    first = resolver.resolve(node)

    node.agent_spec = AgentSpec.create(role=GraphAgentRole.COORDINATOR)

    assert first.binding_id.startswith("runtime-binding:")
    with pytest.raises(GraphRuntimeBindingError, match="changed after runtime binding"):
        resolver.resolve(node)


def test_runtime_binding_fails_closed_on_unknown_policy_key() -> None:
    coordinator = GraphCoordinator.start(
        graph_id="runtime-binding-unknown",
        root_objective=_objective(),
        root_agent_spec=AgentSpec.create(
            role=GraphAgentRole.COORDINATOR,
            model_policy_key="unconfigured-model",
        ),
    )
    resolver = GraphRuntimeResolver(
        default_complete=_complete,
        default_execute=_execute,
    )

    with pytest.raises(GraphRuntimeBindingError, match="unknown graph model policy"):
        resolver.resolve(coordinator.state.nodes["node-001"])


def test_role_policy_selects_runtime_only_callbacks_and_tool_boundary() -> None:
    coordinator = GraphCoordinator.start(
        graph_id="runtime-binding-role-policy",
        root_objective=_objective(),
    )

    async def coordinator_complete(
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        del node_id, messages
        return GraphModelReply(content='{"kind":"finish","payload":{"summary":"ok"}}')

    async def isolated_execute(
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        del node_id, tool, arguments
        return GraphToolResult(output="isolated")

    resolver = GraphRuntimeResolver(
        default_complete=_complete,
        default_execute=_execute,
        model_policies={"coordinator-model": coordinator_complete},
        runtime_profiles={"coordinator-runtime": isolated_execute},
        tool_policies={"coordination-only": frozenset()},
        role_policies={
            GraphAgentRole.COORDINATOR: GraphRuntimePolicyKeys(
                model_policy_key="coordinator-model",
                runtime_profile_key="coordinator-runtime",
                tool_policy_key="coordination-only",
            )
        },
    )

    binding = resolver.resolve(coordinator.state.nodes["node-001"])

    assert binding.complete is coordinator_complete
    assert binding.execute is isolated_execute
    assert binding.model_policy_key == "coordinator-model"
    assert binding.runtime_profile_key == "coordinator-runtime"
    assert binding.tool_policy_key == "coordination-only"
    assert binding.allowed_tools == frozenset()


def test_role_policy_fails_closed_when_registry_entry_is_missing() -> None:
    coordinator = GraphCoordinator.start(
        graph_id="runtime-binding-missing-role-policy",
        root_objective=_objective(),
    )
    resolver = GraphRuntimeResolver(
        default_complete=_complete,
        default_execute=_execute,
        role_policies={
            GraphAgentRole.COORDINATOR: GraphRuntimePolicyKeys(
                model_policy_key="missing-coordinator-model",
            )
        },
    )

    with pytest.raises(
        GraphRuntimeBindingError,
        match="unknown graph model policy: missing-coordinator-model",
    ):
        resolver.resolve(coordinator.state.nodes["node-001"])


def test_runtime_registry_credentials_are_not_serialized_in_graph_state() -> None:
    coordinator = GraphCoordinator.start(
        graph_id="runtime-binding-no-secrets",
        root_objective=_objective(),
    )
    api_secret = "do-not-persist-this-api-secret"  # noqa: S105 - serialization sentinel.

    class CredentialedComplete:
        def __init__(self) -> None:
            self.api_key = api_secret

        async def __call__(
            self,
            node_id: str,
            messages: list[dict[str, str]],
        ) -> GraphModelReply:
            del node_id, messages
            return GraphModelReply(content='{"kind":"wait","payload":{}}')

    credentialed = CredentialedComplete()
    resolver = GraphRuntimeResolver(
        default_complete=_complete,
        default_execute=_execute,
        model_policies={"coordinator-model": credentialed},
        role_policies={
            GraphAgentRole.COORDINATOR: GraphRuntimePolicyKeys(
                model_policy_key="coordinator-model",
            )
        },
    )

    binding = resolver.resolve(coordinator.state.nodes["node-001"])
    serialized = json.dumps(coordinator.state.to_json(), sort_keys=True)

    assert binding.complete is credentialed
    assert api_secret not in serialized
    assert "CredentialedComplete" not in serialized
