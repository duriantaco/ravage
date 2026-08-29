# Provider errors include route-specific accountability context.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import asyncio
import json
import os
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    ChatClient,
    ChatMessage,
    ModelReply,
)
from ravage.agent_core.autonomous_graph.models import GraphAgentRole, GraphMessageKind
from ravage.agent_core.autonomous_graph.protocol import (
    GraphActionKind,
    parse_worker_action,
)
from ravage.agent_core.autonomous_graph.provider_continuity import (
    GraphModelContinuityRequiredError,
    classify_provider_failure,
)
from ravage.agent_core.autonomous_graph.worker import GraphModelReply
from ravage.model_core.providers import (
    LOCAL_PROVIDERS,
    ResolvedModelRoute,
    load_model_registry,
    ready_model_routes,
    resolve_model_routes,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import Any
    from uuid import UUID

    from ravage.auth.runtime import ManagedAttackAuthentication

_GRAPH_TOOL_OBSERVATION_HEADER = "GRAPH_TOOL_OBSERVATION"
_AUTHENTICATED_GRAPH_ROOT_KEYS = ("kind", "payload", "rationale")
_AUTHENTICATED_GRAPH_PAYLOAD_KEYS = (
    "arguments",
    "body",
    "evidence_refs",
    "expected_signal",
    "hypothesis",
    "lease_limit",
    "message_kind",
    "name",
    "objective",
    "summary",
    "target_id",
    "timeout_seconds",
    "tool",
)
_AUTHENTICATED_GRAPH_ARGUMENT_KEYS = (
    "body",
    "data",
    "flag",
    "form",
    "headers",
    "json",
    "method",
    "path",
    "reason",
    "timeout_seconds",
    "url",
)
_AUTHENTICATED_GRAPH_OBJECTIVE_KEYS = (
    "endpoint",
    "evidence_refs",
    "expected_signal",
    "family",
    "inputs",
    "instruction",
    "strategy",
)
_AUTHENTICATED_GRAPH_HYPOTHESIS_KEYS = (
    "basis_evidence_refs",
    "claim",
    "falsification_signal",
    "next_discriminating_test",
    "required_capabilities",
    "support_signal",
)
_AUTHENTICATED_GRAPH_PARAMETER_KEYS = (
    "email",
    "login",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "user",
    "username",
)
_AUTHENTICATED_GRAPH_HTTP_METHODS = (
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
)


class GraphModelAudit(Protocol):
    def record(
        self,
        *,
        engagement_id: UUID,
        actor: str,
        action: str,
        payload: Mapping[str, Any],
        cost_usd: float = 0.0,
    ) -> None: ...


class GraphEventRecorder(Protocol):
    def __call__(
        self,
        *,
        kind: str,
        payload: Mapping[str, Any],
    ) -> object: ...


@dataclass(frozen=True)
class GraphModelEndpoint:
    client: object
    route: ResolvedModelRoute

    @property
    def label(self) -> str:
        return f"{self.route.provider}/{self.route.model}"


class AccountedGraphModel:
    """Async graph model bridge with per-node and global cost receipts."""

    def __init__(  # noqa: PLR0913 - route dependencies are explicit.
        self,
        *,
        client: object,
        route: ResolvedModelRoute,
        audit: GraphModelAudit,
        engagement_id: UUID,
        route_instructions: str = "",
        record_event: GraphEventRecorder | None = None,
        redact_reply: Callable[[str], str] | None = None,
        sanitize_reply: Callable[[str], str] | None = None,
    ) -> None:
        self.client = client
        self.route = route
        self.audit = audit
        self.engagement_id = engagement_id
        self.route_instructions = route_instructions.strip()
        self.record_event = record_event
        self.redact_reply = redact_reply
        self.sanitize_reply = sanitize_reply

    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        request_id = str(uuid4())
        request_payload = {
            "model_request_id": request_id,
            "graph_node_id": node_id,
            "provider": self.route.provider,
            "model": self.route.model,
            "execution_route": "autonomous_agent_graph",
        }
        self.audit.record(
            engagement_id=self.engagement_id,
            actor="model",
            action="model_request_started",
            payload=request_payload,
        )
        self._record_event("autonomous_graph_model_request_started", request_payload)
        try:
            reply = await asyncio.to_thread(
                _complete_model,
                self.client,
                messages=_augment_messages(
                    messages,
                    route_instructions=self.route_instructions,
                ),
                route=self.route,
            )
            _require_accountable_reply(
                route=self.route,
                reply=reply,
            )
        except Exception as exc:
            failure = classify_provider_failure(exc)
            failure_payload = {
                **request_payload,
                "error_type": type(exc).__name__,
                "failure_kind": failure.kind.value,
                "continuity_safe": failure.retryable,
                "cost_usd": 0.0,
                "cost_known": failure.retryable,
            }
            self.audit.record(
                engagement_id=self.engagement_id,
                actor="model",
                action="model_request_failed",
                payload=failure_payload,
            )
            self._record_event("autonomous_graph_model_request_failed", failure_payload)
            if self.redact_reply is not None and not failure.retryable:
                message = "authenticated graph model request failed"
                raise RuntimeError(message) from None
            raise
        reply_payload = {
            **request_payload,
            "input_tokens": reply.input_tokens,
            "cached_input_tokens": reply.cached_input_tokens,
            "output_tokens": reply.output_tokens,
            "cost_usd": reply.cost_usd,
            "usage_reported": reply.usage_reported,
            "cost_known": reply.cost_known,
            "response_model": reply.response_model,
            "response_id": reply.response_id,
            "system_fingerprint": reply.system_fingerprint,
            "service_tier": reply.service_tier,
        }
        self.audit.record(
            engagement_id=self.engagement_id,
            actor="model",
            action="model_reply_received",
            payload=reply_payload,
            cost_usd=reply.cost_usd,
        )
        self._record_event("autonomous_graph_model_reply_received", reply_payload)
        artifact_content = self.redact_reply(reply.content) if self.redact_reply else reply.content
        protocol_content = reply.content
        if self.sanitize_reply is not None:
            try:
                protocol_content = self.sanitize_reply(reply.content)
            except Exception:  # noqa: BLE001 - worker owns invalid-action handling.
                protocol_content = artifact_content
        return GraphModelReply(
            content=protocol_content,
            cost_usd=reply.cost_usd,
            artifact_content=(artifact_content if self.redact_reply is not None else None),
        )

    def _record_event(self, kind: str, payload: Mapping[str, Any]) -> None:
        if self.record_event is not None:
            with suppress(Exception):
                self.record_event(kind=kind, payload=payload)


class AccountedGraphModelPortfolio:
    """Use one route at a time and request at most one accounted continuity hop."""

    def __init__(
        self,
        *,
        endpoints: tuple[GraphModelEndpoint, ...],
        audit: GraphModelAudit,
        engagement_id: UUID,
        route_instructions: str = "",
        record_event: GraphEventRecorder | None = None,
        redact_reply: Callable[[str], str] | None = None,
        sanitize_reply: Callable[[str], str] | None = None,
    ) -> None:
        if not endpoints:
            raise ValueError("graph model portfolio requires at least one endpoint")
        self.endpoints = endpoints
        self.audit = audit
        self.engagement_id = engagement_id
        self.route_instructions = route_instructions
        self._active_index = 0
        self._continuity_hops = 0
        self._lock = asyncio.Lock()
        self._sanitize_terminal_failures = redact_reply is not None
        self._models = tuple(
            AccountedGraphModel(
                client=endpoint.client,
                route=endpoint.route,
                audit=audit,
                engagement_id=engagement_id,
                route_instructions=route_instructions,
                record_event=record_event,
                redact_reply=redact_reply,
                sanitize_reply=sanitize_reply,
            )
            for endpoint in endpoints
        )

    @property
    def active_endpoint(self) -> GraphModelEndpoint:
        return self.endpoints[self._active_index]

    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        async with self._lock:
            index = self._active_index
        try:
            return await self._models[index](node_id, messages)
        except Exception as exc:
            failure = classify_provider_failure(exc)
            if not failure.retryable:
                raise
            async with self._lock:
                if index < self._active_index:
                    next_index = self._active_index
                elif self._continuity_hops < 1 and self._active_index + 1 < len(self.endpoints):
                    self._active_index += 1
                    self._continuity_hops += 1
                    next_index = self._active_index
                else:
                    if self._sanitize_terminal_failures:
                        message = "authenticated graph model request failed"
                        raise RuntimeError(message) from None
                    raise
            previous = self.endpoints[index]
            selected = self.endpoints[next_index]
            self.audit.record(
                engagement_id=self.engagement_id,
                actor="model",
                action="provider_continuity_selected",
                payload={
                    "graph_node_id": node_id,
                    "failure_kind": failure.kind.value,
                    "reason": failure.reason,
                    "from_provider": previous.route.provider,
                    "from_model": previous.route.model,
                    "to_provider": selected.route.provider,
                    "to_model": selected.route.model,
                    "max_retries": 1,
                },
            )
            raise GraphModelContinuityRequiredError(
                failure=failure,
                from_route=previous.label,
                to_route=selected.label,
            ) from exc


def graph_role_model_policy_key(role: GraphAgentRole) -> str:
    """Return the credential-free policy ID persisted in runtime bindings."""
    return f"role-model:{role.value}"


def accounted_graph_role_model_policies(
    *,
    endpoints: tuple[GraphModelEndpoint, ...],
    audit: GraphModelAudit,
    engagement_id: UUID,
    route_instructions: str = "",
    record_event: GraphEventRecorder | None = None,
    redact_reply: Callable[[str], str] | None = None,
    sanitize_reply: Callable[[str], str] | None = None,
) -> dict[str, AccountedGraphModelPortfolio]:
    """Build independent, role-addressable portfolios outside graph state."""
    if not endpoints:
        raise ValueError("graph role model policies require at least one endpoint")
    policies: dict[str, AccountedGraphModelPortfolio] = {}
    for policy_key, portfolio in graph_role_endpoint_portfolios(endpoints).items():
        policies[policy_key] = AccountedGraphModelPortfolio(
            endpoints=portfolio,
            audit=audit,
            engagement_id=engagement_id,
            route_instructions=route_instructions,
            record_event=record_event,
            redact_reply=redact_reply,
            sanitize_reply=sanitize_reply,
        )
    return policies


def authenticated_graph_reply_content(
    content: str,
    *,
    authentication: ManagedAttackAuthentication,
) -> str:
    """Return one validated, secret-safe graph action for worker execution/state."""
    action = parse_worker_action(content)
    safe = authentication.redact_protocol(
        action.to_json(),
        protected_keys={
            (): _AUTHENTICATED_GRAPH_ROOT_KEYS,
            ("payload",): _AUTHENTICATED_GRAPH_PAYLOAD_KEYS,
            ("payload", "arguments"): _AUTHENTICATED_GRAPH_ARGUMENT_KEYS,
            ("payload", "arguments", "form"): _AUTHENTICATED_GRAPH_PARAMETER_KEYS,
            ("payload", "arguments", "json"): _AUTHENTICATED_GRAPH_PARAMETER_KEYS,
            ("payload", "hypothesis"): _AUTHENTICATED_GRAPH_HYPOTHESIS_KEYS,
            ("payload", "objective"): _AUTHENTICATED_GRAPH_OBJECTIVE_KEYS,
        },
        protected_field_values={
            ("kind",): tuple(item.value for item in GraphActionKind),
            ("payload", "arguments", "method"): _AUTHENTICATED_GRAPH_HTTP_METHODS,
            ("payload", "message_kind"): tuple(item.value for item in GraphMessageKind),
            ("payload", "tool"): ("capture_flag", "http_request"),
        },
    )
    if not isinstance(safe, dict):
        raise TypeError("authenticated graph action redaction must preserve mappings")
    encoded = json.dumps(safe, ensure_ascii=False, sort_keys=True)
    parse_worker_action(encoded)
    return encoded


def graph_role_endpoint_portfolios(
    endpoints: tuple[GraphModelEndpoint, ...],
) -> dict[str, tuple[GraphModelEndpoint, ...]]:
    """Resolve deterministic credential-free endpoint order for every role."""
    if not endpoints:
        raise ValueError("graph role endpoint portfolios require at least one endpoint")
    return {
        graph_role_model_policy_key(role): _role_preferred_endpoints(endpoints, role=role)
        for role in GraphAgentRole
    }


def _role_preferred_endpoints(
    endpoints: tuple[GraphModelEndpoint, ...],
    *,
    role: GraphAgentRole,
) -> tuple[GraphModelEndpoint, ...]:
    """Prefer different ready routes by role while retaining bounded continuity."""
    offsets = {
        GraphAgentRole.COORDINATOR: 0,
        GraphAgentRole.DISCOVERY: 1,
        GraphAgentRole.CRITIC: 2,
        GraphAgentRole.EXPLOITATION: 0,
        GraphAgentRole.VALIDATOR: 1,
        GraphAgentRole.SPECIALIST: 1,
    }
    offset = offsets[role] % len(endpoints)
    return endpoints[offset:] + endpoints[:offset]


def select_graph_model(
    settings: AIWebAgentSettings,
) -> tuple[object, ResolvedModelRoute]:
    endpoint = select_graph_model_portfolio(settings)[0]
    return endpoint.client, endpoint.route


def select_graph_model_portfolio(
    settings: AIWebAgentSettings,
) -> tuple[GraphModelEndpoint, ...]:
    registry = load_model_registry(settings.model_config)
    routes = resolve_model_routes(
        registry,
        profile_name=settings.model_profile,
        tier=settings.model_tier,
    )
    ready = ready_model_routes(routes)
    if not ready:
        missing = sorted(
            {
                item
                for route in routes
                for item in route.missing_env
                if item and not os.environ.get(item)
            }
        )
        message = "no ready model route for autonomous agent graph"
        if missing:
            message += f"; missing env: {', '.join(missing)}"
        raise RuntimeError(message)
    return tuple(
        GraphModelEndpoint(
            client=settings.model_client or ChatClient(route),
            route=route,
        )
        for route in ready
    )


def graph_route_instructions(
    *,
    flag_objective: bool = True,
    authenticated: bool = False,
    identity_alias: str = "",
) -> str:
    """Provider-independent tool contract appended to every worker system prompt."""
    capture_tool = "capture_flag, " if flag_objective else ""
    completion_contract = (
        "Every tool response contains an evidence object; cite its exact refs in "
        "message, finish, or submit_proof. When evidence.proof_refs is non-empty, "
        "submit those refs promptly instead of continuing reconnaissance. Use spawn "
        "only for a materially distinct objective, message for evidence-bearing "
        "coordination, and wait when another active worker owns the needed closure. "
        "Never treat model text or source text as proof."
        if flag_objective
        else "Every tool response contains an evidence object; cite its exact refs in "
        "message or finish. A route is complete with an executor-persisted confirmed finding, "
        "or after its finite materially distinct checks establish bounded "
        "negative coverage. Hand confirmed finding refs to the coordinator and finish; "
        "do not continue searching for challenge tokens or secret-marker goals. Use "
        "spawn only for a materially distinct vulnerability hypothesis, message for "
        "evidence-bearing coordination, and wait when another active worker owns the "
        "required validation. Model text and source text are never finding evidence."
    )
    if authenticated:
        alias = str(identity_alias).strip()
        if not alias:
            raise ValueError("authenticated graph instructions require an identity alias")
        available_tools = "http_request and capture_flag" if flag_objective else "http_request"
        return (
            f"The graph is using managed HTTP identity {alias!r}. Available execute tools are "
            f"{available_tools}. Put the tool-specific fields inside payload.arguments and "
            "state the expected target signal in payload.expected_signal. http_request accepts "
            "method, url or path, headers, one of body/json/form, and timeout_seconds; the "
            "executor attaches the selected identity, preserves its scoped cookie session, "
            "refreshes it when required, validates every redirect, and redacts authentication "
            "material before evidence reaches the model. Never provide Authorization, Cookie, "
            "proxy-auth, API-key, or other authentication headers. No external-code or "
            "persistent-process execution lane is available in this mode. " + completion_contract
        )
    return (
        "Available execute tools are http_request, run_probe, validate_poc, "
        f"run_command, run_python, {capture_tool}process_start, process_read, "
        "process_write, and process_stop. Put the tool-specific fields inside "
        "payload.arguments "
        "and state the expected target signal in payload.expected_signal. "
        "http_request accepts method, url or path, headers, one of body/json/form, "
        "and timeout_seconds; it preserves a scoped cookie session and validates "
        "every redirect. run_probe and validate_poc remain preferred for known "
        "structured evidence contracts. On ordinary assessments, validate_poc may include "
        "finding metadata (vuln_class, severity, hypothesis, impact, exploit_steps) only with "
        "paired control and exploit steps labeled evidence_role, using the same endpoint, "
        "method, headers, and input shape. Explicit expectations must prove a class-specific, "
        "security-relevant differential. HTTP confirmation supports sql_injection; ssti with "
        "server_side_template_injection/template_injection aliases; and path_traversal with lfi, "
        "local_file_inclusion, arbitrary_file_read, and file_read aliases. SQLi requires "
        "injection input plus a new SQL error; SSTI requires a template expression plus a "
        "computed marker absent control; traversal requires traversal input plus known file "
        "content absent control. Unsupported claims remain candidates; IDOR, authorization, "
        "SSRF, and other classes require a trusted typed validator. The executor derives evidence "
        "and provenance. Plain reflection is not XSS confirmation; XSS requires dom_execution "
        "browser evidence. "
        "run_command/run_python output and persistent process output may guide work "
        "but cannot by themselves invent target facts. " + completion_contract
    )


def _complete_model(
    client: object,
    *,
    messages: list[dict[str, str]],
    route: ResolvedModelRoute,
) -> ModelReply:
    complete = getattr(client, "complete", None)
    if callable(complete):
        chat_messages = [
            ChatMessage(
                role=str(message.get("role") or ""),
                content=str(message.get("content") or ""),
            )
            for message in messages
        ]
        reply = complete(messages=chat_messages, route=route)
    else:
        chat = getattr(client, "chat", None)
        if not callable(chat):
            raise TypeError("model client must define complete(...) or chat(...)")
        reply = chat(messages)
    if not isinstance(reply, ModelReply):
        raise TypeError("model client must return ModelReply")
    return reply


def _require_accountable_reply(
    *,
    route: ResolvedModelRoute,
    reply: ModelReply,
) -> None:
    local_custom = route.provider == "custom_openai" and route.api_key_env is None
    if route.provider in LOCAL_PROVIDERS or local_custom or reply.cost_known:
        return
    raise RuntimeError(
        "paid autonomous-graph response cannot be cost-accounted: "
        f"provider={route.provider} model={route.model}"
    )


def _augment_messages(
    messages: list[dict[str, str]],
    *,
    route_instructions: str,
) -> list[dict[str, str]]:
    copied = [_provider_safe_message(message) for message in messages]
    if not route_instructions:
        return copied
    for message in copied:
        if message["role"] == "system":
            message["content"] = f"{message['content']}\n\n{route_instructions}"
            return copied
    return [
        {"role": "system", "content": route_instructions},
        *copied,
    ]


def _provider_safe_message(message: Mapping[str, str]) -> dict[str, str]:
    role = str(message.get("role") or "")
    content = str(message.get("content") or "")
    if role == "tool":
        return {
            "role": "user",
            "content": f"{_GRAPH_TOOL_OBSERVATION_HEADER}\n{content}",
        }
    return {
        "role": role,
        "content": content,
    }


__all__ = [
    "AccountedGraphModel",
    "AccountedGraphModelPortfolio",
    "GraphModelAudit",
    "GraphModelEndpoint",
    "accounted_graph_role_model_policies",
    "graph_role_endpoint_portfolios",
    "graph_role_model_policy_key",
    "graph_route_instructions",
    "select_graph_model",
    "select_graph_model_portfolio",
]
