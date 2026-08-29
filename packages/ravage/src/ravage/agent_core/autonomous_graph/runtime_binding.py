"""Trusted, sticky runtime resolution for heterogeneous graph workers."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.models import GraphAgentRole

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ravage.agent_core.autonomous_graph.models import GraphNode
    from ravage.agent_core.autonomous_graph.worker import GraphComplete, GraphExecute


class GraphRuntimeBindingError(RuntimeError):
    """Raised when a trusted agent specification has no safe runtime binding."""


@dataclass(frozen=True)
class GraphRuntimePolicyKeys:
    """Logical runtime policy selected for one trusted graph role."""

    model_policy_key: str = "inherit"
    runtime_profile_key: str = "inherit"
    tool_policy_key: str = "inherit"

    def __post_init__(self) -> None:
        for label, key in (
            ("model policy", self.model_policy_key),
            ("runtime profile", self.runtime_profile_key),
            ("tool policy", self.tool_policy_key),
        ):
            if not isinstance(key, str) or not key.strip():
                message = f"graph role {label} key must be a non-empty string"
                raise GraphRuntimeBindingError(message)


@dataclass(frozen=True)
class ResolvedGraphRuntime:
    """Concrete callbacks and tool boundary selected from an immutable AgentSpec."""

    binding_id: str
    agent_spec_fingerprint: str
    complete: GraphComplete
    execute: GraphExecute
    allowed_tools: frozenset[str] | None
    model_policy_key: str
    runtime_profile_key: str
    tool_policy_key: str

    def allows_tool(self, tool: str) -> bool:
        return self.allowed_tools is None or tool in self.allowed_tools


class GraphRuntimeResolver:
    """
    Resolve policy keys without placing clients, credentials, or tools in graph state.

    Bindings are sticky per node. A resumed or mutated node cannot silently switch
    model, executor, tool policy, or session policy under the same identity.
    """

    def __init__(  # noqa: PLR0913 - resolver registries are independent.
        self,
        *,
        default_complete: GraphComplete,
        default_execute: GraphExecute,
        model_policies: Mapping[str, GraphComplete] | None = None,
        runtime_profiles: Mapping[str, GraphExecute] | None = None,
        tool_policies: Mapping[str, frozenset[str]] | None = None,
        role_policies: Mapping[
            GraphAgentRole | str,
            GraphRuntimePolicyKeys,
        ]
        | None = None,
        allowed_session_policies: frozenset[str] = frozenset({"fresh_typed", "node_isolated"}),
    ) -> None:
        self.default_complete = default_complete
        self.default_execute = default_execute
        self.model_policies = dict(model_policies or {})
        self.runtime_profiles = dict(runtime_profiles or {})
        self.tool_policies = dict(tool_policies or {})
        self.role_policies = _normalize_role_policies(role_policies or {})
        self.allowed_session_policies = allowed_session_policies
        self._bindings: dict[str, ResolvedGraphRuntime] = {}
        self._lock = threading.RLock()

    def resolve(self, node: GraphNode) -> ResolvedGraphRuntime:
        with self._lock:
            existing = self._bindings.get(node.node_id)
            if existing is not None:
                if existing.agent_spec_fingerprint != node.agent_spec.fingerprint:
                    message = f"agent spec changed after runtime binding for {node.node_id}"
                    raise GraphRuntimeBindingError(message)
                return existing
            spec = node.agent_spec
            if spec.session_policy_key not in self.allowed_session_policies:
                message = f"unsupported graph session policy: {spec.session_policy_key}"
                raise GraphRuntimeBindingError(message)
            role_policy = self.role_policies.get(spec.role, GraphRuntimePolicyKeys())
            model_policy_key = _effective_policy_key(
                spec.model_policy_key,
                role_policy.model_policy_key,
            )
            runtime_profile_key = _effective_policy_key(
                spec.runtime_profile_key,
                role_policy.runtime_profile_key,
            )
            tool_policy_key = _effective_policy_key(
                spec.tool_policy_key,
                role_policy.tool_policy_key,
            )
            complete = _resolve_policy(
                model_policy_key,
                default=self.default_complete,
                policies=self.model_policies,
                label="model policy",
            )
            execute = _resolve_policy(
                runtime_profile_key,
                default=self.default_execute,
                policies=self.runtime_profiles,
                label="runtime profile",
            )
            allowed_tools = (
                None if tool_policy_key == "inherit" else self.tool_policies.get(tool_policy_key)
            )
            if tool_policy_key != "inherit" and allowed_tools is None:
                message = f"unknown graph tool policy: {tool_policy_key}"
                raise GraphRuntimeBindingError(message)
            identity = (
                f"{spec.fingerprint}|{model_policy_key}|"
                f"{runtime_profile_key}|{tool_policy_key}|"
                f"{spec.session_policy_key}"
            )
            binding = ResolvedGraphRuntime(
                binding_id=(f"runtime-binding:{hashlib.sha256(identity.encode()).hexdigest()}"),
                agent_spec_fingerprint=spec.fingerprint,
                complete=complete,
                execute=execute,
                allowed_tools=allowed_tools,
                model_policy_key=model_policy_key,
                runtime_profile_key=runtime_profile_key,
                tool_policy_key=tool_policy_key,
            )
            self._bindings[node.node_id] = binding
            return binding


def _resolve_policy[PolicyT](
    key: str,
    *,
    default: PolicyT,
    policies: Mapping[str, PolicyT],
    label: str,
) -> PolicyT:
    if key == "inherit":
        return default
    resolved = policies.get(key)
    if resolved is None:
        message = f"unknown graph {label}: {key}"
        raise GraphRuntimeBindingError(message)
    return resolved


def _effective_policy_key(explicit_key: str, role_key: str) -> str:
    return role_key if explicit_key == "inherit" else explicit_key


def _normalize_role_policies(
    policies: Mapping[GraphAgentRole | str, GraphRuntimePolicyKeys],
) -> dict[GraphAgentRole, GraphRuntimePolicyKeys]:
    normalized: dict[GraphAgentRole, GraphRuntimePolicyKeys] = {}
    for raw_role, policy in policies.items():
        try:
            role = (
                raw_role if isinstance(raw_role, GraphAgentRole) else GraphAgentRole(str(raw_role))
            )
        except ValueError as exc:
            message = f"unknown graph runtime role policy: {raw_role}"
            raise GraphRuntimeBindingError(message) from exc
        if not isinstance(policy, GraphRuntimePolicyKeys):
            message = f"graph runtime role policy for {role.value} is invalid"
            raise GraphRuntimeBindingError(message)
        normalized[role] = policy
    return normalized


__all__ = [
    "GraphRuntimeBindingError",
    "GraphRuntimePolicyKeys",
    "GraphRuntimeResolver",
    "ResolvedGraphRuntime",
]
