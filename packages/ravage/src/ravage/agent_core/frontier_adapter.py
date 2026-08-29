from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from ravage.agent_core.action_executor import ActionResult, execute_action
from ravage.agent_core.action_parser import parse_action
from ravage.agent_core.agent_state import AgentState, load_agent_state
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    ChatClient,
    ChatMessage,
    ModelReply,
    _assert_authenticated_restored_artifacts_safe,
    _assert_authenticated_state_artifacts_safe,
    _authenticated_model_action,
    _open_run_traffic_policy,
)
from ravage.agent_core.frontier_engine import FrontierEngine, FrontierModelReply
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    FrontierObjective,
    FrontierRoute,
    FrontierRouteConfig,
)
from ravage.agent_core.frontier_shared_runtime import (
    SharedToolRuntime,
    reverify_tool_runtime_cleanup,
)
from ravage.agent_core.frontier_timeout_hygiene import (
    FrontierTimeoutHygieneRuntime,
    TimeoutCleanupRecord,
    remember_timeout_recovery,
)
from ravage.agent_core.frontier_transition import seed_frontier_objectives
from ravage.model_core.providers import (
    LOCAL_PROVIDERS,
    ResolvedModelRoute,
    load_model_registry,
    ready_model_routes,
    resolve_model_routes,
)
from ravage.run_data.audit import AuditStore
from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import (
    DockerFallbackToolRuntime,
    DockerToolRuntime,
    ExternalToolRuntime,
    NoProcessToolRuntime,
    ToolRuntime,
)
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pentest_schemas import EngagementBrief

    from ravage.auth.runtime import ManagedAttackAuthentication

_MAX_OBSERVATION_CHARS = 10_000
_MAX_TRANSCRIPT_CHARS = 80_000


class FrontierBudgetUnavailableError(RuntimeError):
    pass


def run_frontier_route(  # noqa: C901, PLR0912, PLR0913, PLR0915
    *,
    brief_path: Path,
    target_url: str,
    base: BaseRouteOutcome,
    settings: AIWebAgentSettings,
    workspace_dir: Path,
    config: FrontierRouteConfig | None = None,
    objectives: tuple[FrontierObjective, ...] | None = None,
) -> FrontierRoute:
    brief = load_engagement_brief(brief_path)
    workspace = AgentWorkspace.open(workspace_dir, event_sink=settings.event_sink)
    traffic_policy = _frontier_traffic_policy(
        settings=settings,
        base=base,
        target_url=target_url,
        roe_max_rps=brief.roe.max_rps,
    )
    route_state_path = workspace.root / "frontier-route.json"
    route_state_existed = route_state_path.exists()
    state = _load_working_state(
        workspace=workspace,
        base=base,
        resume=route_state_existed,
    )
    if state is None:
        message = "cannot start autonomous route without the frozen base state"
        raise ValueError(message)
    if target_url != base.target_url:
        message = "autonomous route target does not match the frozen base target"
        raise ValueError(message)
    _assert_authenticated_state_identity(state, settings=settings)
    if settings.authentication is not None:
        _assert_authenticated_state_artifacts_safe(
            state,
            authentication=settings.authentication,
            state_label="frontier",
        )
    session_mode = _authentication_session_mode(settings)
    if settings.authentication is not None:
        state.surface["authenticated_identity"] = settings.authentication.identity
        state.surface["session_mode"] = session_mode

    route_config = _route_config_with_remaining_cost(
        config or FrontierRouteConfig(),
        engagement_max_cost_usd=brief.budget.max_cost_usd,
        base_cost_usd=base.cost_usd,
    )
    candidates = objectives or seed_frontier_objectives(state, base=base)
    if not candidates:
        message = "base state produced no autonomous route objectives"
        raise ValueError(message)

    if settings.authentication is not None:
        _assert_authenticated_frontier_sessions_safe(
            workspace.root / "frontier-sessions",
            authentication=settings.authentication,
        )
    route = FrontierRoute.load_or_start(
        route_state_path,
        base=base,
        initial_objective=candidates[0],
        scope=tuple(str(item) for item in brief.scope.in_scope),
        config=route_config,
    )
    if settings.authentication is not None:
        if route_state_existed:
            _assert_authenticated_restored_artifacts_safe(
                route.to_json(),
                authentication=settings.authentication,
                artifact_label="frontier route",
            )
    route_started_payload = {
        "base_model_requests": base.model_requests,
        "route_model_request_budget": route.config.max_model_requests,
        "route_cost_budget_usd": route.config.max_cost_usd,
        "resumed": route_state_existed,
    }
    if session_mode:
        route_started_payload["session_mode"] = session_mode
    audit: AuditStore | None = None
    route_runtime: ToolRuntime | None = None
    tool_runtime: ToolRuntime | None = None
    result: FrontierRoute | None = None
    route_finished_payload: dict[str, object] | None = None
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    audit_close_error: BaseException | None = None
    event_error: BaseException | None = None
    try:
        audit = AuditStore(settings.db_path or workspace.root / "audit.db", scope=brief.scope)
        route_runtime = _make_route_runtime(settings, brief)

        def record_timeout_cleanup(record: TimeoutCleanupRecord) -> None:
            payload = record.to_json()
            remember_timeout_recovery(state, record)
            workspace.record_event(kind="frontier_timeout_cleanup", payload=payload)
            assert audit is not None
            audit.record(
                engagement_id=brief.engagement_id,
                actor="tool",
                action="frontier_timeout_cleanup",
                payload=payload,
            )

        if isinstance(route_runtime, FrontierTimeoutHygieneRuntime):
            tool_runtime = route_runtime
        else:
            tool_runtime = FrontierTimeoutHygieneRuntime(
                route_runtime,
                on_cleanup=record_timeout_cleanup,
            )
        model_route = _select_model_route(settings)
        model_client = settings.model_client or ChatClient(model_route)

        def complete(messages: list[dict[str, str]]) -> FrontierModelReply:
            request_id = str(uuid4())
            assert audit is not None
            safe_messages = messages
            if settings.authentication is not None:
                safe_messages = [
                    {
                        "role": str(message.get("role") or ""),
                        "content": settings.authentication.redact_prompt_text(
                            str(message.get("content") or "")
                        ),
                    }
                    for message in messages
                ]
            request_payload: dict[str, object] = {
                "model_request_id": request_id,
                "provider": model_route.provider,
                "model": model_route.model,
                "execution_route": "autonomous_escalation",
            }
            if session_mode:
                request_payload["session_mode"] = session_mode
            audit.record(
                engagement_id=brief.engagement_id,
                actor="model",
                action="model_request_started",
                payload=request_payload,
            )
            try:
                reply = _complete_model(
                    model_client,
                    messages=safe_messages,
                    route=model_route,
                )
                _require_accountable_reply(route=model_route, reply=reply)
            except Exception:
                if settings.authentication is not None:
                    message = "authenticated frontier model request failed"
                    raise RuntimeError(message) from None
                raise
            reply_content = (
                settings.authentication.redact_text(reply.content)
                if settings.authentication is not None
                else reply.content
            )
            protocol_content = reply.content
            if settings.authentication is not None:
                protocol_content = json.dumps(
                    _authenticated_model_action(
                        settings.authentication,
                        parse_action(reply.content),
                    ),
                    sort_keys=True,
                )
            reply_payload: dict[str, object] = {
                "model_request_id": request_id,
                "provider": model_route.provider,
                "model": model_route.model,
                "execution_route": "autonomous_escalation",
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
            if session_mode:
                reply_payload["session_mode"] = session_mode
            audit.record(
                engagement_id=brief.engagement_id,
                actor="model",
                action="model_reply_received",
                payload=reply_payload,
                cost_usd=reply.cost_usd,
            )
            return FrontierModelReply(
                content=protocol_content,
                cost_usd=reply.cost_usd,
                artifact_content=reply_content,
            )

        def execute(
            action: dict[str, object],
            *,
            repeat_count: int,
            action_id: str,
        ) -> ActionResult:
            assert tool_runtime is not None
            assert audit is not None
            outcome = execute_action(
                action,
                target_url=target_url,
                runtime=tool_runtime,
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=brief.engagement_id,
                repeat_count=repeat_count,
                max_observation_chars=_MAX_OBSERVATION_CHARS,
                max_transcript_chars=_MAX_TRANSCRIPT_CHARS,
                proof_recognition_enabled=settings.proof_recognition_enabled,
                action_id=action_id,
                authentication=settings.authentication,
                traffic_policy=traffic_policy,
            )
            if settings.authentication is not None and not outcome.session_mode:
                return replace(outcome, session_mode=session_mode)
            return outcome

        free_roam_context: dict[str, object] = {
            "target_url": target_url,
            "scope": {
                "in_scope": list(brief.scope.in_scope),
                "out_of_scope": list(brief.scope.out_of_scope),
            },
            "route": "autonomous_escalation",
        }
        if settings.authentication is not None:
            free_roam_context["managed_http_identity"] = {
                "mode": session_mode,
                "identity_alias": settings.authentication.identity,
                "request_lane": "managed_http",
            }
        tool_runtime.write_free_roam_context(
            json.dumps(
                free_roam_context,
                indent=2,
                sort_keys=True,
            )
        )
        audit.record(
            engagement_id=brief.engagement_id,
            actor="agent",
            action="frontier_route_started",
            payload=route_started_payload,
        )
        workspace.record_event(kind="frontier_route_started", payload=route_started_payload)
        engine = FrontierEngine(
            route=route,
            state=state,
            objectives=candidates,
            workspace=workspace,
            complete=complete,
            execute=execute,
        )
        result = engine.run()
        route_finished_payload = _route_terminal_payload(
            route=result,
            base=base,
            error=None,
        )
        audit.record(
            engagement_id=brief.engagement_id,
            actor="agent",
            action="frontier_route_finished",
            payload=route_finished_payload,
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            _cleanup_route_runtime(
                tool_runtime=tool_runtime,
                route_runtime=route_runtime,
            )
        except BaseException as exc:  # noqa: BLE001 - cleanup must be accounted.
            cleanup_error = exc

        if audit is not None:
            try:
                audit.close()
            except BaseException as exc:  # noqa: BLE001 - preserve the primary failure.
                audit_close_error = exc

        terminal_error = primary_error or cleanup_error or audit_close_error
        terminal_kind = _route_terminal_kind(terminal_error)
        terminal_payload = (
            route_finished_payload
            if terminal_error is None and route_finished_payload is not None
            else _route_terminal_payload(
                route=route,
                base=base,
                error=terminal_error,
                cleanup_error=cleanup_error,
                audit_error=audit_close_error,
            )
        )
        try:
            workspace.record_event(kind=terminal_kind, payload=terminal_payload)
        except BaseException as exc:  # noqa: BLE001 - preserve the primary failure.
            event_error = exc

        if primary_error is None:
            for finalize_error in (
                cleanup_error,
                audit_close_error,
                event_error,
            ):
                if finalize_error is not None:
                    raise finalize_error

    if result is None:  # pragma: no cover - an error path above must have raised.
        message = "frontier route completed without a result"
        raise RuntimeError(message)
    return result


def _cleanup_route_runtime(
    *,
    tool_runtime: ToolRuntime | None,
    route_runtime: ToolRuntime | None,
) -> None:
    if route_runtime is None:
        return
    lifecycle_runtime = (
        route_runtime.inner
        if isinstance(route_runtime, FrontierTimeoutHygieneRuntime)
        else route_runtime
    )
    operations: list[Callable[[], object]] = []
    if isinstance(tool_runtime, FrontierTimeoutHygieneRuntime):
        operations.extend(
            (
                tool_runtime.finalize_cleanup,
                lifecycle_runtime.close,
                tool_runtime.finalize_cleanup,
            )
        )
    else:
        operations.append((tool_runtime or route_runtime).close)
    if isinstance(lifecycle_runtime, SharedToolRuntime):
        operations.append(lifecycle_runtime.shutdown)
    if isinstance(tool_runtime, FrontierTimeoutHygieneRuntime):
        operations.append(tool_runtime.finalize_cleanup)
    operations.append(lambda: reverify_tool_runtime_cleanup(lifecycle_runtime))

    first_error: BaseException | None = None
    for operation in operations:
        try:
            operation()
        except BaseException as exc:  # noqa: BLE001 - attempt every cleanup stage.
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def _route_terminal_kind(error: BaseException | None) -> str:
    if error is None:
        return "frontier_route_finished"
    if isinstance(error, KeyboardInterrupt):
        return "frontier_route_cancelled"
    return "frontier_route_failed"


def _route_terminal_payload(
    *,
    route: FrontierRoute,
    base: BaseRouteOutcome,
    error: BaseException | None,
    cleanup_error: BaseException | None = None,
    audit_error: BaseException | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": route.status.value if error is None else _route_terminal_status(error),
        "reason": route.last_reason,
        "base_model_requests": base.model_requests,
        "route_model_requests": route.model_requests_started,
        "total_model_requests": route.total_model_requests_including_base,
        "route_cost_usd": route.spent_cost_usd,
    }
    if error is not None:
        payload["error_type"] = type(error).__name__
    if cleanup_error is not None and cleanup_error is not error:
        payload["cleanup_error_type"] = type(cleanup_error).__name__
    if audit_error is not None and audit_error is not error:
        payload["audit_error_type"] = type(audit_error).__name__
    return payload


def _route_terminal_status(error: BaseException) -> str:
    return "cancelled" if isinstance(error, KeyboardInterrupt) else "failed"


def _base_state_path(base: BaseRouteOutcome) -> Path:
    return Path(base.state_ref)


def _load_working_state(
    *,
    workspace: AgentWorkspace,
    base: BaseRouteOutcome,
    resume: bool,
) -> AgentState | None:
    if resume:
        resumed = load_agent_state(workspace.state_path)
        if resumed is not None:
            return resumed
    return load_agent_state(_base_state_path(base))


def _authentication_session_mode(settings: AIWebAgentSettings) -> str:
    if settings.authentication is None:
        return ""
    return f"identity:{settings.authentication.identity}"


def _assert_authenticated_state_identity(
    state: AgentState,
    *,
    settings: AIWebAgentSettings,
) -> None:
    restored_identity = str(state.surface.get("authenticated_identity") or "").strip()
    if not restored_identity:
        if settings.authentication is not None:
            raise ValueError(
                "cannot enter authenticated frontier from state without an identity binding"
            )
        return
    if settings.authentication is None:
        raise ValueError(
            "cannot resume authenticated frontier state without managed authentication"
        )
    if restored_identity != settings.authentication.identity:
        raise ValueError(
            "cannot resume authenticated frontier state with a different identity: "
            f"state={restored_identity!r} requested={settings.authentication.identity!r}"
        )


def _assert_authenticated_frontier_sessions_safe(
    root: Path,
    *,
    authentication: ManagedAttackAuthentication,
) -> None:
    if not root.is_dir():
        return
    for path in sorted(root.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            _assert_authenticated_restored_artifacts_safe(
                payload,
                authentication=authentication,
                artifact_label="frontier session",
            )


def _route_config_with_remaining_cost(
    config: FrontierRouteConfig,
    *,
    engagement_max_cost_usd: float,
    base_cost_usd: float,
) -> FrontierRouteConfig:
    remaining = max(float(engagement_max_cost_usd) - max(base_cost_usd, 0.0), 0.0)
    if remaining <= 0:
        message = "no engagement cost budget remains for the autonomous route"
        raise FrontierBudgetUnavailableError(message)
    configured = config.max_cost_usd
    route_cost = remaining if configured is None else min(configured, remaining)
    return replace(config, max_cost_usd=route_cost)


def _make_route_runtime(
    settings: AIWebAgentSettings,
    brief: EngagementBrief,
) -> ToolRuntime:
    if settings.traffic_policy_mode == "low-noise":
        return NoProcessToolRuntime(
            reason="whole-run low-noise traffic policy exposes native metered HTTP lanes only"
        )
    if settings.tool_runtime is not None:
        return settings.tool_runtime
    runtime_kwargs = {
        "image": settings.tool_image,
        "scope": brief.scope,
        "session_id": f"{brief.engagement_id}-frontier",
        "cleanup_evidence_path": os.environ.get("RAVAGE_TOOL_NETWORK_EVIDENCE_PATH"),
        "allow_remote_target": settings.allow_remote_target,
    }
    if settings.allow_remote_target or settings.tool_runtime_mode == "docker":
        return DockerToolRuntime(**runtime_kwargs)
    if settings.tool_runtime_mode == "auto":
        return DockerFallbackToolRuntime(**runtime_kwargs)
    return ExternalToolRuntime()


def _frontier_traffic_policy(
    *,
    settings: AIWebAgentSettings,
    base: BaseRouteOutcome,
    target_url: str,
    roe_max_rps: float,
) -> TrafficPolicyController:
    base_workspace = AgentWorkspace.open(Path(base.state_ref).parent)
    ledger_path = base_workspace.root / "traffic-policy.json"
    reference = settings.traffic_policy_reference
    if settings.traffic_policy_mode == "low-noise" and reference is None:
        message = "cannot enter low-noise frontier route without the base traffic policy reference"
        raise TrafficPolicyError(message)
    if reference is not None:
        if not ledger_path.is_file():
            message = "frontier traffic policy reference has no base run ledger"
            raise TrafficPolicyError(message)
        run_owned = _open_run_traffic_policy(
            settings=replace(settings, traffic_policy_reference=None),
            workspace=base_workspace,
            target_url=target_url,
            roe_max_rps=roe_max_rps,
        )
        referenced = TrafficPolicyController.from_reference(
            reference,
            require_existing=True,
        )
        if _traffic_policy_binding(referenced) != _traffic_policy_binding(run_owned):
            message = "frontier traffic policy reference does not match the base run ledger"
            raise TrafficPolicyError(message)
        return run_owned
    if ledger_path.is_file():
        return _open_run_traffic_policy(
            settings=settings,
            workspace=base_workspace,
            target_url=target_url,
            roe_max_rps=roe_max_rps,
        )
    if settings.traffic_policy_mode != "observe":
        return _open_run_traffic_policy(
            settings=settings,
            workspace=base_workspace,
            target_url=target_url,
            roe_max_rps=roe_max_rps,
        )
    if (
        settings.traffic_policy_max_physical_requests is not None
        or settings.traffic_policy_max_rps is not None
    ):
        message = "traffic policy limits require low-noise mode"
        raise ValueError(message)
    controller = TrafficPolicyController.open(
        ledger_path,
        target_url=target_url,
        config=TrafficPolicyConfig(),
    )
    # A legacy base state without a ledger has unknown prior traffic. Preserve
    # truthful lower-bound accounting before metering every frontier action.
    controller.record_unmetered_action()
    return controller


def _traffic_policy_binding(
    controller: TrafficPolicyController,
) -> tuple[Path, TrafficPolicyConfig, str]:
    return (
        Path(controller.state_path).expanduser().resolve(strict=True),
        controller.config,
        str(controller.target_origin),
    )


def _select_model_route(settings: AIWebAgentSettings) -> ResolvedModelRoute:
    registry = load_model_registry(settings.model_config)
    routes = resolve_model_routes(
        registry,
        profile_name=settings.model_profile,
        tier=settings.model_tier,
    )
    ready = ready_model_routes(routes)
    if ready:
        return ready[0]
    missing = sorted(
        {
            route.api_key_env
            for route in routes
            if route.api_key_required
            and route.api_key_env
            and not os.environ.get(route.api_key_env)
        }
    )
    message = "no ready model route"
    if missing:
        message += f"; missing env: {', '.join(missing)}"
    raise RuntimeError(message)


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
            message = "model client must define complete(...) or chat(...)"
            raise TypeError(message)
        reply = chat(messages)
    if not isinstance(reply, ModelReply):
        message = "model client must return ModelReply"
        raise TypeError(message)
    return reply


def _require_accountable_reply(
    *,
    route: ResolvedModelRoute,
    reply: ModelReply,
) -> None:
    local_custom = route.provider == "custom_openai" and route.api_key_env is None
    if route.provider in LOCAL_PROVIDERS or local_custom or reply.cost_known:
        return
    message = (
        "paid autonomous-route response cannot be cost-accounted: "
        f"provider={route.provider} model={route.model}"
    )
    raise RuntimeError(message)


__all__ = [
    "FrontierBudgetUnavailableError",
    "run_frontier_route",
]
