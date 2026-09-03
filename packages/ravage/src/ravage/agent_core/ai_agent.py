from __future__ import annotations

import base64
import json
import math
import os
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypedDict
from urllib.parse import urlparse
from uuid import uuid4

from ravage.agent_core.action_executor import (
    MAX_IDENTICAL_ACTION_EXECUTIONS,
    ActionResult,
    execute_action,
)
from ravage.agent_core.action_parser import VALID_ACTIONS, parse_action
from ravage.agent_core.action_planner import planner_directives, ranked_strategy_cards, select_phase
from ravage.agent_core.agent_methodology import methodology_context
from ravage.agent_core.agent_recipes import recipes_for_active_tasks
from ravage.agent_core.agent_specialists import available_specialists, recommended_specialists
from ravage.agent_core.agent_state import (
    AgentState,
    append_unique,
    load_agent_state,
    resolve_agent_state_path,
    save_agent_state,
)
from ravage.agent_core.agent_strategy import observation_digest
from ravage.agent_core.agent_tasks import (
    active_tasks_for_prompt,
    refresh_mission_board,
    update_mission_from_action,
)
from ravage.agent_core.attack_surface import merge_surface_state, surface_from_recon
from ravage.agent_core.frontier_closure_obligation import pending_closure_obligation
from ravage.agent_core.harness_trace import (
    attempt_record_payload,
    sanitize_action,
    selection_trace_payload,
    state_trace_snapshot,
    turn_trace_payload,
)
from ravage.agent_core.live_events import describe_action
from ravage.agent_core.observation_analysis import (
    merge_recon_state,
    observation_facts,
)
from ravage.agent_core.observation_memory import build_planner_memory, summarize_state
from ravage.agent_core.primitive_state import (
    locked_primitive,
    primitive_rule,
    probe_recently_exhausted,
    promote_primitives,
    routed_probes,
)
from ravage.agent_core.recovery_action_contract import select_recovery_branch_action
from ravage.agent_core.recovery_policy import RecoveryDecision, RecoveryRole, RecoveryStatus
from ravage.agent_core.recovery_runtime import RecoveryCampaign, RecoveryTurnResult
from ravage.agent_core.semantic_routes import semantic_action_fingerprint
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.agent_core.surface_graph_ingest import ingest_recon_surface, project_surface_graph
from ravage.agent_knowledge import (
    KnowledgeCard,
    describe_knowledge_pack,
    select_knowledge_cards,
)
from ravage.agent_knowledge.selector import (
    DEFAULT_KNOWLEDGE_CARD_LIMIT,
    DEFAULT_KNOWLEDGE_MAX_CHARS,
)
from ravage.dry_run import RouteParam, RouteProbe
from ravage.model_core.providers import (
    ModelTier,
    ResolvedModelRoute,
    abliteration_standard_token_prices,
    anthropic_standard_token_prices,
    load_model_registry,
    model_route_transport_error,
    openai_standard_token_prices,
    ready_model_routes,
    resolve_model_routes,
    route_is_nonbillable_local,
)
from ravage.probe_suite import (
    authenticated_probe_unavailability,
    authenticated_unavailable_probes,
    available_probes,
    probe_requires_anonymous_session,
    probe_requires_external_process,
)
from ravage.report import write_pentest_report
from ravage.run_data.audit import AuditStore
from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import (
    DEFAULT_TOOL_IMAGE,
    DockerToolRuntime,
    ExternalToolRuntime,
    NoProcessToolRuntime,
    ToolRuntime,
    ToolRuntimeMode,
)
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyError,
    TrafficPolicyMode,
)
from ravage.web_core.recon import run_recon
from ravage.web_core.scope_policy import assert_authorized_target, is_local_url

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from uuid import UUID

    from pentest_schemas import EngagementBrief

    from ravage.auth.runtime import ManagedAttackAuthentication

MAX_OBSERVATION_CHARS = 10_000
MAX_TRANSCRIPT_CHARS = 80_000
MODEL_TIMEOUT_PADDING_SECONDS = 10
DOCKER_SCOPE_GATEWAY_HOST = "ravage-target"
_CONTEXT_PROOF_RE = re.compile(r"\b(?:flag|FLAG|HTB|CTF)\{[^}\s]{3,512}\}")
_AUTHENTICATED_ACTION_PROTOCOL_KEYS = (
    "action",
    "args",
    "body",
    "code",
    "command",
    "data",
    "error",
    "evidence",
    "evidence_role",
    "expect_contains",
    "expect_status",
    "expected_signal",
    "exploit_steps",
    "fallback",
    "finding",
    "flag",
    "form",
    "headers",
    "hypotheses",
    "hypothesis",
    "impact",
    "json",
    "memory_updates",
    "method",
    "notes",
    "path",
    "probe",
    "raw",
    "severity",
    "steps",
    "strategy",
    "summary",
    "task_id",
    "timeout_seconds",
    "url",
    "vuln_class",
)
_AUTHENTICATED_HTTP_STEP_KEYS = (
    "body",
    "data",
    "evidence_role",
    "expect_contains",
    "expect_status",
    "form",
    "headers",
    "json",
    "method",
    "path",
    "timeout_seconds",
    "url",
)
_AUTHENTICATED_HTTP_PARAMETER_KEYS = (
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
_AUTHENTICATED_FINDING_KEYS = (
    "evidence_role",
    "exploit_steps",
    "hypothesis",
    "impact",
    "severity",
    "vuln_class",
)
_AUTHENTICATED_HTTP_METHODS = (
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
_AUTHENTICATED_FINDING_CLASSES = (
    "arbitrary_file_read",
    "file_read",
    "lfi",
    "local_file_inclusion",
    "path_traversal",
    "server_side_template_injection",
    "sql_injection",
    "ssti",
    "template_injection",
)
_MULTI_PROOF_TEXT_MARKERS = (
    "as many",
    "all flags",
    "all findings",
    "multiple flags",
    "multiple findings",
    "comprehensive assessment",
)

AgentMode = Literal["ctf-free-roam", "hybrid"]
RecoveryProfile = Literal["off", "recovery-v1"]


class FreeRoamDriverRecommendation(TypedDict):
    driver: str
    mode: str
    run_command: str
    tool_actions: list[str]
    available: bool
    probe: str
    unavailable_reason: NotRequired[str]
    recommended_action: NotRequired[dict[str, object]]


class FreeRoamWorkflowLead(TypedDict):
    lead: str


FreeRoamClosureLead = TypedDict(
    "FreeRoamClosureLead",
    {
        "class": str,
        "closure_driver": str,
        "closure_chain": list[str],
    },
)


class FreeRoamSignalFocus(TypedDict):
    active_workflow_leads: list[FreeRoamWorkflowLead]
    driver_recommendations: list[FreeRoamDriverRecommendation]


class FreeRoamControllerVerdict(TypedDict):
    status: str
    driver_events: list[dict[str, object]]


@dataclass(frozen=True)
class AIWebAgentSettings:
    db_path: Path | None = None
    report_path: Path | None = None
    report_agent: bool = False
    resume_from: Path | None = None
    workspace_dir: Path | None = None
    model_config: Path | None = None
    model_profile: str = "local-ollama"
    model_tier: ModelTier = "mid"
    agent_mode: AgentMode = "ctf-free-roam"
    max_turns: int = 40
    skill_path: Path | None = None
    knowledge_pack_path: Path | None = None
    knowledge_pack_sha256: str | None = None
    knowledge_pack_limit: int = DEFAULT_KNOWLEDGE_CARD_LIMIT
    knowledge_pack_max_chars: int = DEFAULT_KNOWLEDGE_MAX_CHARS
    tool_runtime_mode: ToolRuntimeMode = "docker"
    tool_image: str = DEFAULT_TOOL_IMAGE
    allow_remote_target: bool = False
    allow_degraded: bool = False
    proof_recognition_enabled: bool = False
    event_sink: Callable[[Mapping[str, Any]], None] | None = None
    model_client: Any | None = None
    http_client: Any | None = None
    tool_runtime: Any | None = None
    browser_runtime: Any | None = None
    stdout: Any | None = None
    memory: Any | None = None
    memory_explicit: bool = False
    free_roam_after_deterministic: bool = True
    tool_recon: bool = False
    tool_recon_tools: tuple[str, ...] = ()
    tool_recon_ports: str = ""
    deterministic_attempt_budget: int | None = None
    free_roam_tool_budget: int | None = None
    recovery_profile: RecoveryProfile = "off"
    autonomous_route: bool = False
    authentication: ManagedAttackAuthentication | None = None
    traffic_policy_mode: Literal["observe", "low-noise"] = "observe"
    traffic_policy_max_physical_requests: int | None = None
    traffic_policy_max_rps: float | None = None
    traffic_policy_config: TrafficPolicyConfig | None = None
    traffic_policy_reference: dict[str, object] | None = None


@dataclass
class ChatMessage:
    role: str
    content: str


@dataclass
class ModelReply:
    content: str
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    usage_reported: bool | None = None
    cost_known: bool = True
    response_model: str | None = None
    response_id: str | None = None
    system_fingerprint: str | None = None
    service_tier: str | None = None
    route: object | None = None


class AIWebRuntime:
    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


class ProviderChatClient:
    def complete(
        self,
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        payload = [{"role": item.role, "content": item.content} for item in messages]
        return ChatClient(route).chat(payload)


def run_ai_web_agent(
    *,
    brief_path: Path,
    target_url: str,
    settings: AIWebAgentSettings,
) -> None:
    brief = load_engagement_brief(brief_path)
    flag_objective = _brief_has_flag_objective(brief)
    stop_after_first_finding = _brief_stops_after_first_finding(brief)
    assert_authorized_target(
        target_url,
        scope=brief.scope,
        allow_remote_target=settings.allow_remote_target,
        agent_name="ai-web",
    )
    workspace = AgentWorkspace.open(
        settings.workspace_dir or Path("runs/ravage-agent/workspace"),
        event_sink=settings.event_sink,
    )
    traffic_policy = _open_run_traffic_policy(
        settings=settings,
        workspace=workspace,
        target_url=target_url,
        roe_max_rps=brief.roe.max_rps,
    )
    state, resumed_state = _initial_state(settings, workspace)
    _assert_authenticated_state_identity(
        state,
        authentication=settings.authentication,
        resumed=resumed_state,
    )
    if resumed_state and settings.authentication is not None:
        _assert_authenticated_state_artifacts_safe(
            state,
            authentication=settings.authentication,
            state_label="agent",
        )
    audit = AuditStore(settings.db_path or workspace.root / "audit.db", scope=brief.scope)
    runtime = _make_tool_runtime(settings, brief, target_url=target_url)
    state.surface["flag_objective"] = flag_objective
    state.surface["stop_after_first_finding"] = stop_after_first_finding
    recovery_state_path = workspace.root / "recovery-state.json"
    recovery = _initial_recovery_campaign(
        settings=settings,
        state=state,
        target_url=target_url,
        state_path=recovery_state_path,
    )
    route = _select_model_route(settings)
    client = settings.model_client or ChatClient(route)
    run_error: BaseException | None = None
    spent_cost_usd = 0.0
    cost_accounting_complete = True
    termination_reason: str | None = None
    knowledge_pack_metadata = _knowledge_pack_metadata_payload(settings)
    knowledge_pack_sha256 = (
        str(knowledge_pack_metadata["sha256"]) if knowledge_pack_metadata is not None else None
    )

    started_payload: dict[str, object] = {
        "target_url": target_url,
        "model": route.model,
        "provider": route.provider,
        "agent_mode": settings.agent_mode,
        "reference_architecture": "planner-executor with working memory",
        "knowledge_pack": knowledge_pack_metadata,
        "flag_objective": flag_objective,
        "stop_after_first_finding": stop_after_first_finding,
        "traffic_policy": traffic_policy.config.to_json(),
        "traffic_policy_snapshot": traffic_policy.snapshot().to_json(),
    }
    session_mode = _authentication_session_mode(settings.authentication)
    if session_mode:
        started_payload["session_mode"] = session_mode
    if recovery is not None:
        started_payload["recovery_profile"] = settings.recovery_profile
        started_payload["global_model_request_budget"] = (
            recovery.scheduler.config.max_model_requests
        )
    _record(
        audit,
        brief.engagement_id,
        actor="agent",
        action="agent_started",
        payload=started_payload,
    )
    workspace_started_payload: dict[str, object] = {
        "target_url": target_url,
        "provider": route.provider,
        "model": route.model,
        "agent_mode": settings.agent_mode,
        "max_turns": settings.max_turns,
        "tool_runtime": settings.tool_runtime_mode,
        "autonomous_route": settings.autonomous_route,
        "flag_objective": flag_objective,
        "stop_after_first_finding": stop_after_first_finding,
    }
    if session_mode:
        workspace_started_payload["session_mode"] = session_mode
    if recovery is not None:
        workspace_started_payload["recovery_profile"] = settings.recovery_profile
    workspace.record_event(kind="agent_started", payload=workspace_started_payload)
    traffic_started_payload = {
        "state_path": str(traffic_policy.state_path),
        "config": traffic_policy.config.to_json(),
        "snapshot": traffic_policy.snapshot().to_json(),
    }
    _record(
        audit,
        brief.engagement_id,
        actor="agent",
        action="traffic_policy_started",
        payload=traffic_started_payload,
    )
    workspace.record_event(kind="traffic_policy_started", payload=traffic_started_payload)
    if knowledge_pack_metadata:
        workspace.record_event(kind="knowledge_pack_loaded", payload=knowledge_pack_metadata)

    try:
        safe_context = _safe_runtime_context(brief.context or {}, brief_path=brief_path)
        description = str(safe_context.get("description") or "")
        _write_runtime_context(
            runtime,
            brief=brief,
            brief_path=brief_path,
            target_url=target_url,
            workspace=workspace,
        )
        _seed_recon(
            target_url=target_url,
            description=description,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=brief.engagement_id,
            allow_remote_target=settings.allow_remote_target,
            in_scope=brief.scope.in_scope,
            out_of_scope=brief.scope.out_of_scope,
            max_rps=brief.roe.max_rps,
            flag_objective=flag_objective,
            session_mode=("anonymous:baseline" if settings.authentication is not None else ""),
            authentication=settings.authentication,
            traffic_policy=traffic_policy,
        )
        # Recon replaces the discovered-surface mapping. Reapply policy and mission
        # metadata afterward so both fresh runs and resumes retain their controls.
        state.surface["scope_in_scope"] = list(brief.scope.in_scope)
        state.surface["scope_out_of_scope"] = list(brief.scope.out_of_scope)
        state.surface["scope_max_rps"] = brief.roe.max_rps
        state.surface["allow_remote_target"] = settings.allow_remote_target
        state.surface["continue_after_proof"] = _brief_requests_multiple_proofs(brief)
        state.surface["stop_after_first_finding"] = stop_after_first_finding
        expected_proof_count = _brief_expected_proof_count(brief)
        if expected_proof_count is None:
            state.surface.pop("expected_proof_count", None)
        else:
            state.surface["expected_proof_count"] = expected_proof_count
        state.surface["flag_objective"] = flag_objective
        state.surface["scoped_service_ports"] = _scoped_service_ports(
            brief.scope.in_scope,
            target_url=target_url,
        )
        if settings.authentication is not None:
            state.surface["session_mode"] = session_mode
            state.surface["authenticated_identity"] = settings.authentication.identity
            _seed_authenticated_surface(
                target_url=target_url,
                runtime=runtime,
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=brief.engagement_id,
                proof_recognition_enabled=settings.proof_recognition_enabled,
                authentication=settings.authentication,
                traffic_policy=traffic_policy,
            )
        seed_credentials = safe_context.get("authorized_seed_credentials")
        if settings.authentication is not None:
            # Legacy operator-note credentials belong to unauthenticated tool
            # lanes. Managed mode neither uses nor persists a second plaintext
            # identity alongside its isolated session owner.
            state.surface.pop("authorized_seed_credentials", None)
        elif seed_credentials:
            state.surface["authorized_seed_credentials"] = seed_credentials
        if recovery is not None:
            _record_recovery_enabled(
                recovery,
                workspace=workspace,
                audit=audit,
                engagement_id=brief.engagement_id,
            )
            if recovery.has_pending_model_request:
                interrupted_decision = recovery.account_interrupted_request(
                    recommended_specialists=recommended_specialists(state, limit=6)
                )
                recovery.save(recovery_state_path)
                _record_recovery_decision(
                    interrupted_decision,
                    turn=recovery.scheduler.total_model_requests,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=brief.engagement_id,
                    interrupted=True,
                )
        # Make turn-zero discovery and the managed identity binding resumable
        # even when the first provider call is interrupted or fails.
        save_agent_state(
            workspace.state_path,
            target_url=target_url,
            state=state,
        )
        first_turn = recovery.next_turn if recovery is not None else max(state.turn + 1, 1)
        for turn in range(first_turn, max(settings.max_turns, 1) + 1):
            if recovery is not None and recovery.scheduler.status is not RecoveryStatus.RUNNING:
                termination_reason = f"recovery_{recovery.scheduler.status.value}"
                break
            state.turn = turn
            state.phase = select_phase(state)
            refresh_mission_board(
                state,
                description=description,
                surface=state.surface,
            )
            knowledge_cards = select_knowledge_cards(
                pack_path=settings.knowledge_pack_path,
                expected_sha256=knowledge_pack_sha256,
                state=state,
                description=description,
                limit=settings.knowledge_pack_limit,
                max_chars=settings.knowledge_pack_max_chars,
            )
            if knowledge_cards:
                workspace.record_event(
                    kind="knowledge_cards_selected",
                    payload={
                        "turn": turn,
                        "cards": [
                            {
                                "name": card.name,
                                "score": card.score,
                                "mapped_probes": list(card.mapped_probes),
                                "sha256": card.sha256,
                            }
                            for card in knowledge_cards
                        ],
                    },
                )
            recovery_specialists = (
                recommended_specialists(state, limit=6) if recovery is not None else []
            )
            recovery_context = (
                recovery.role_context(recommended_specialists=recovery_specialists)
                if recovery is not None
                else None
            )
            messages = _build_messages(
                brief=brief,
                brief_path=brief_path,
                target_url=target_url,
                state=state,
                settings=settings,
                route=route,
                knowledge_cards=knowledge_cards,
                knowledge_pack_metadata=knowledge_pack_metadata,
                recovery_context=recovery_context,
                traffic_budget=traffic_policy.budget_snapshot(),
            )
            model_request_id = str(uuid4())
            request_payload = {
                "model_request_id": model_request_id,
                "turn": turn,
                "provider": route.provider,
                "model": route.model,
                "phase": state.phase,
            }
            if session_mode:
                request_payload["session_mode"] = session_mode
            if recovery is not None:
                request_payload.update(_recovery_request_payload(recovery))
                recovery.begin_model_request()
                recovery.save(recovery_state_path)
            _record(
                audit,
                brief.engagement_id,
                actor="model",
                action="model_request_started",
                payload=request_payload,
            )
            workspace.record_event(kind="model_request_started", payload=request_payload)
            reply = _complete_model(client, messages=messages, route=route)
            reply_content = (
                settings.authentication.redact_text(reply.content)
                if settings.authentication is not None
                else reply.content
            )
            spent_cost_usd += max(reply.cost_usd, 0.0)
            cost_accounting_complete = cost_accounting_complete and reply.cost_known
            workspace.record_transcript(role="assistant", content=reply_content)
            workspace.record_event(
                kind="model_reply_received",
                payload={
                    "model_request_id": model_request_id,
                    "turn": turn,
                    "provider": route.provider,
                    "model": route.model,
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
                },
            )
            _record(
                audit,
                brief.engagement_id,
                actor="model",
                action="model_reply_received",
                payload={
                    "model_request_id": model_request_id,
                    "turn": turn,
                    "provider": route.provider,
                    "model": route.model,
                    "content": reply_content,
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
                },
                cost_usd=reply.cost_usd,
            )
            _require_accountable_paid_reply(route=route, reply=reply)

            proposed_action = parse_action(reply.content)
            if settings.authentication is not None:
                proposed_action = _authenticated_model_action(
                    settings.authentication,
                    proposed_action,
                )
            action_id = str(uuid4())
            allow_premature_final = settings.model_client is not None and recovery is None
            shadow_action, shadow_reason = _shadow_harness_action(
                state=state,
                proposed_action=proposed_action,
                turn=turn,
                max_turns=max(settings.max_turns, 1),
                allow_premature_final=allow_premature_final,
            )
            if recovery is not None and recovery.scheduler.role is not RecoveryRole.CORE:
                action = select_recovery_branch_action(
                    proposed_action,
                    role=recovery.scheduler.role,
                    lease_used=recovery.scheduler.lease_used,
                    objective=recovery.active_objective,
                )
            else:
                action = _model_action_from_parsed(
                    proposed_action,
                    state=state,
                    turn=turn,
                    max_turns=max(settings.max_turns, 1),
                    allow_premature_final=allow_premature_final,
                )
            if recovery is None:
                resolved_action, resolution_reason = _resolve_same_turn_harness_action(
                    state=state,
                    proposed_action=proposed_action,
                    selected_action=action,
                    turn=turn,
                    max_turns=max(settings.max_turns, 1),
                    settings=settings,
                )
                if resolution_reason is not None:
                    action = resolved_action
                    shadow_action = resolved_action
                    shadow_reason = resolution_reason
            selection_payload = selection_trace_payload(
                turn=turn,
                action_id=action_id,
                proposed_action=proposed_action,
                selected_action=action,
                shadow_action=shadow_action,
                shadow_reason=shadow_reason,
                repeat_context=_repeat_context(state),
            )
            selection_payload = _authenticated_artifact_mapping(
                settings.authentication,
                selection_payload,
            )
            workspace.record_event(kind="harness_selection", payload=selection_payload)
            _record(
                audit,
                brief.engagement_id,
                actor="agent",
                action="harness_selection",
                payload=selection_payload,
            )
            repeat_count = state.ledger.remember(action, context=_repeat_context(state))
            selected_action_payload = _authenticated_artifact_mapping(
                settings.authentication,
                {
                    "turn": turn,
                    "repeat_count": repeat_count,
                    "action": sanitize_action(action),
                },
            )
            _record(
                audit,
                brief.engagement_id,
                actor="agent",
                action="agent_action_selected",
                payload=selected_action_payload,
            )
            workspace.record_event(
                kind="agent_action_selected",
                payload=selected_action_payload,
            )

            action_started_payload = _authenticated_artifact_mapping(
                settings.authentication,
                {
                    "action_id": action_id,
                    "turn": turn,
                    "action_kind": str(action.get("action") or ""),
                    "strategy": str(action.get("strategy") or ""),
                    "notes": str(action.get("notes") or ""),
                    "expected_signal": str(action.get("expected_signal") or ""),
                    "fallback": str(action.get("fallback") or ""),
                    **describe_action(action),
                },
            )
            workspace.record_event(
                kind="action_started",
                payload=action_started_payload,
            )

            pre_state_trace = state_trace_snapshot(state)
            branch_handoff = False
            if recovery is not None:
                outcome, branch_handoff = _execute_recovery_action(
                    recovery=recovery,
                    action=action,
                    target_url=target_url,
                    runtime=runtime,
                    state=state,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=brief.engagement_id,
                    repeat_count=repeat_count,
                    proof_recognition_enabled=settings.proof_recognition_enabled,
                    action_id=action_id,
                    authentication=settings.authentication,
                    traffic_policy=traffic_policy,
                )
            else:
                outcome = execute_action(
                    action,
                    target_url=target_url,
                    runtime=runtime,
                    state=state,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=brief.engagement_id,
                    repeat_count=repeat_count,
                    max_observation_chars=MAX_OBSERVATION_CHARS,
                    max_transcript_chars=MAX_TRANSCRIPT_CHARS,
                    proof_recognition_enabled=settings.proof_recognition_enabled,
                    action_id=action_id,
                    authentication=settings.authentication,
                    traffic_policy=traffic_policy,
                )
            if settings.authentication is not None and not outcome.session_mode:
                outcome = replace(outcome, session_mode=session_mode)
            outcome = _continue_after_proof_outcome(state, outcome)
            outcome = _stop_after_finding_outcome(state, outcome)
            outcome_json = outcome.to_json()
            _update_state_from_action(state, action=action, outcome=outcome_json)
            post_action_state_trace = state_trace_snapshot(state)
            attempt_record = attempt_record_payload(
                turn=turn,
                action_id=action_id,
                proposed_action=proposed_action,
                selected_action=action,
                selection_reason=str(selection_payload.get("selection_reason") or ""),
                repeat_context=_repeat_context(state),
                pre_state=pre_state_trace,
                post_state=post_action_state_trace,
                outcome=outcome_json,
            )
            attempt_record = _authenticated_artifact_mapping(
                settings.authentication,
                attempt_record,
            )
            state.attempts.append(attempt_record)
            del state.attempts[:-200]
            workspace.record_event(kind="agent_attempt_recorded", payload=attempt_record)
            _record(
                audit,
                brief.engagement_id,
                actor="agent",
                action="agent_attempt_recorded",
                payload=attempt_record,
            )
            # Branch closure is derived from durable attempt provenance, so make
            # the current attempt visible before deciding whether another model
            # turn is necessary.
            synthesized_terminal = (
                recovery is None
                and not outcome.stop
                and _assessment_ready_for_terminal(
                    state,
                    turn=turn,
                    max_turns=max(settings.max_turns, 1),
                    settings=settings,
                )
            )
            if synthesized_terminal:
                state.phase = "done"
                state.summary = summarize_state(state)
            post_state_trace = state_trace_snapshot(state)
            trace_payload = turn_trace_payload(
                turn=turn,
                action_id=action_id,
                proposed_action=proposed_action,
                selected_action=action,
                pre_state=pre_state_trace,
                post_state=post_state_trace,
                outcome=outcome_json,
            )
            trace_payload = _authenticated_artifact_mapping(
                settings.authentication,
                trace_payload,
            )
            workspace.record_event(kind="harness_turn_trace", payload=trace_payload)
            _record(
                audit,
                brief.engagement_id,
                actor="agent",
                action="harness_turn_trace",
                payload=trace_payload,
            )
            if synthesized_terminal:
                _record_synthesized_terminal(
                    turn=turn,
                    action_id=action_id,
                    state=state,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=brief.engagement_id,
                    authentication=settings.authentication,
                )
            recovery_turn: RecoveryTurnResult | None = None
            if recovery is not None:
                recovery_turn = recovery.record_action_result(
                    action=action,
                    outcome=outcome,
                    recommended_specialists=recommended_specialists(state, limit=6),
                    branch_handoff=branch_handoff,
                )
                recovery.save(recovery_state_path)
                _record_recovery_turn(
                    recovery_turn,
                    turn=turn,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=brief.engagement_id,
                )
            save_agent_state(workspace.state_path, target_url=target_url, state=state)
            if outcome.stop:
                termination_reason = (
                    "agent_final" if outcome.outcome == "final" else "objective_met"
                )
                break
            if synthesized_terminal:
                termination_reason = "agent_final"
                break
            if spent_cost_usd >= brief.budget.max_cost_usd:
                cost_payload = {
                    "turn": turn,
                    "spent_cost_usd": round(spent_cost_usd, 6),
                    "max_cost_usd": brief.budget.max_cost_usd,
                }
                workspace.record_event(kind="cost_budget_exhausted", payload=cost_payload)
                _record(
                    audit,
                    brief.engagement_id,
                    actor="agent",
                    action="cost_budget_exhausted",
                    payload=cost_payload,
                )
                termination_reason = "cost_budget_exhausted"
                break
            if (
                recovery_turn is not None
                and recovery_turn.decision.status is not RecoveryStatus.RUNNING
            ):
                termination_reason = f"recovery_{recovery_turn.decision.status.value}"
                break
    except BaseException as exc:
        run_error = exc
        raise
    finally:
        cleanup_error: BaseException | None = None
        try:
            runtime.close()
        except BaseException as exc:  # noqa: BLE001 - cleanup must be reported.
            cleanup_error = exc
        finish_status = "completed"
        if isinstance(run_error, KeyboardInterrupt):
            finish_status = "cancelled"
            termination_reason = "keyboard_interrupt"
        elif run_error is not None:
            finish_status = "failed"
            termination_reason = "error"
        elif termination_reason is None:
            termination_reason = (
                "max_turns_reached" if state.turn >= max(settings.max_turns, 1) else "agent_final"
            )
        expected_proof_count = _state_expected_proof_count(state)
        captured_proof_count = _captured_proof_count(state)
        required_proof_count_unmet = (
            expected_proof_count is not None
            and captured_proof_count < expected_proof_count
        )
        completion_requirements_met = (
            not flag_objective
            or _proof_objective_completion_met(state, settings=settings)
        )
        if required_proof_count_unmet and termination_reason in {
            "agent_final",
            "objective_met",
        }:
            termination_reason = "required_proof_count_unmet"
        if termination_reason in {
            "max_turns_reached",
            "cost_budget_exhausted",
            "required_proof_count_unmet",
        } or (run_error is None and not completion_requirements_met):
            finish_status = "incomplete"
        finished_payload: dict[str, object] = {
            "status": finish_status,
            "termination_reason": termination_reason,
            "flags": state.flags,
            "flag_record_path": str(workspace.events_path),
            "finding_count": audit.count_findings(
                status="confirmed",
                engagement_id=brief.engagement_id,
            ),
            "finding_record_path": str(workspace.events_path),
            "audit_path": str(settings.db_path or workspace.root / "audit.db"),
            "flag_objective": flag_objective,
            "expected_proof_count": expected_proof_count,
            "captured_proof_count": captured_proof_count,
            "required_proof_count_unmet": required_proof_count_unmet,
            "completion_requirements_met": completion_requirements_met,
            "turns": state.turn,
            "phase": state.phase,
            "cost_usd": round(spent_cost_usd, 6),
            "cost_accounting_complete": cost_accounting_complete,
            "traffic_policy": traffic_policy.config.to_json(),
            "traffic_policy_snapshot": traffic_policy.snapshot().to_json(),
        }
        if settings.report_path is not None or settings.report_agent:
            finished_payload["report_path"] = str(
                settings.report_path or workspace.root.parent / "report.md"
            )
        if run_error is not None:
            finished_payload["error_type"] = type(run_error).__name__
        if recovery is not None:
            finished_payload.update(
                {
                    "recovery_profile": settings.recovery_profile,
                    "recovery_status": recovery.scheduler.status.value,
                    "global_model_requests": recovery.scheduler.total_model_requests,
                    "interrupted_model_requests": recovery.interrupted_model_requests,
                }
            )
        _record(
            audit,
            brief.engagement_id,
            actor="agent",
            action="agent_finished",
            payload=finished_payload,
        )
        workspace.record_event(kind="agent_finished", payload=finished_payload)
        traffic_finished_payload = {
            "state_path": str(traffic_policy.state_path),
            "config": traffic_policy.config.to_json(),
            "snapshot": traffic_policy.snapshot().to_json(),
        }
        _record(
            audit,
            brief.engagement_id,
            actor="agent",
            action="traffic_policy_finished",
            payload=traffic_finished_payload,
        )
        workspace.record_event(kind="traffic_policy_finished", payload=traffic_finished_payload)
        if run_error is None and cleanup_error is None:
            _handle_memory_after_run(
                settings=settings,
                route=route,
                client=client,
                audit_db_path=settings.db_path or workspace.root / "audit.db",
            )
        audit.close()
        _write_report_if_requested(
            brief_path=brief_path,
            target_url=target_url,
            settings=settings,
            workspace=workspace,
            state=state,
            error=run_error or cleanup_error,
            termination_reason=termination_reason,
        )
        if cleanup_error is not None and run_error is None:
            raise cleanup_error


def _model_action(
    content: str,
    *,
    state: AgentState,
    turn: int,
    max_turns: int,
) -> dict[str, object]:
    action = parse_action(content)
    return _model_action_from_parsed(action, state=state, turn=turn, max_turns=max_turns)


def _model_action_from_parsed(
    action: Mapping[str, object],
    *,
    state: AgentState,
    turn: int,
    max_turns: int,
    allow_premature_final: bool = False,
) -> dict[str, object]:
    if allow_premature_final and action.get("action") == "final":
        return dict(action)
    if not allow_premature_final and _final_is_premature(
        action=action, state=state, turn=turn, max_turns=max_turns
    ):
        return _forced_primitive_probe_action(
            state=state, proposed_action=action
        ) or _premature_final_action(action)
    forced = _forced_primitive_probe_action(state=state, proposed_action=action)
    if forced:
        return forced
    forced = _forced_cookie_identity_idor_action(state=state, proposed_action=action)
    if forced:
        return forced
    forced = _forced_authenticated_object_idor_action(state=state, proposed_action=action)
    if forced:
        return forced
    forced = _forced_evidence_probe_action(state=state, proposed_action=action)
    if forced:
        return forced
    return dict(action)


def _shadow_harness_action(
    *,
    state: AgentState,
    proposed_action: Mapping[str, object],
    turn: int,
    max_turns: int,
    allow_premature_final: bool = False,
) -> tuple[dict[str, object] | None, str]:
    if not allow_premature_final and _final_is_premature(
        action=proposed_action, state=state, turn=turn, max_turns=max_turns
    ):
        forced = _forced_primitive_probe_action(state=state, proposed_action=proposed_action)
        if forced:
            return forced, "premature_final_locked_primitive"
        return _premature_final_action(proposed_action), "premature_final_guard"
    for reason, route in (
        ("locked_primitive", _forced_primitive_probe_action),
        ("cookie_identity_idor", _forced_cookie_identity_idor_action),
        ("authenticated_object_idor", _forced_authenticated_object_idor_action),
        ("evidence_probe_route", _forced_evidence_probe_action),
    ):
        action = route(state=state, proposed_action=proposed_action)
        if action:
            return action, reason
    return None, "no_shadow_route"


_REPEAT_GUARDED_ACTIONS = frozenset({"run_command", "run_python", "run_probe", "validate_poc"})
_ACTIVE_TASK_STATUSES = frozenset({"pending", "in_progress"})


def _resolve_same_turn_harness_action(  # noqa: PLR0913 - explicit turn boundary contract.
    *,
    state: AgentState,
    proposed_action: Mapping[str, object],
    selected_action: Mapping[str, object],
    turn: int,
    max_turns: int,
    settings: AIWebAgentSettings,
) -> tuple[dict[str, object], str | None]:
    """Replace a known no-op selection before it consumes the current turn."""
    selected = dict(selected_action)
    if selected.get("action") == "final":
        if not _final_is_premature(
            action=selected,
            state=state,
            turn=turn,
            max_turns=max_turns,
            settings=settings,
        ):
            return selected, None
        fallback = _deterministic_harness_fallback(
            state=state,
            route_basis=proposed_action,
            settings=settings,
        )
        if fallback is not None:
            return fallback, "premature_final_required_work_fallback"
        return _premature_final_action(selected), "premature_final_required_work_guard"
    if _assessment_ready_for_terminal(
        state,
        turn=turn,
        max_turns=max_turns,
        settings=settings,
    ):
        return _synthesized_final_action(), "assessment_complete_terminal"

    premature_final = proposed_action.get("action") == "final" and _final_is_premature(
        action=proposed_action,
        state=state,
        turn=turn,
        max_turns=max_turns,
    )
    if premature_final and selected.get("action") == "invalid":
        reason = "premature_final_open_task_fallback"
        route_basis = proposed_action
    elif _would_hit_repeat_guard(state, selected):
        reason = "repeat_limit_open_task_fallback"
        route_basis = selected
    else:
        return selected, None

    fallback = _deterministic_harness_fallback(
        state=state,
        route_basis=route_basis,
        settings=settings,
    )
    if fallback is None:
        # Keep the existing guard visible when no evidence-backed executable route exists.
        return selected, None
    return fallback, reason


def _deterministic_harness_fallback(  # noqa: C901 - ordered safety gates are explicit.
    *,
    state: AgentState,
    route_basis: Mapping[str, object],
    settings: AIWebAgentSettings,
) -> dict[str, object] | None:
    locked = _forced_primitive_probe_action(state=state, proposed_action=route_basis)
    if locked is not None and _fallback_action_is_executable(
        state,
        locked,
        settings=settings,
    ):
        return locked

    for route in (
        _forced_cookie_identity_idor_action,
        _forced_authenticated_object_idor_action,
        _forced_evidence_probe_action,
    ):
        candidate = route(state=state, proposed_action=route_basis)
        if candidate is None or not _action_targets_active_task(state, candidate):
            continue
        if _fallback_action_is_executable(state, candidate, settings=settings):
            return candidate

    recommendations = recommended_specialists(state, limit=len(available_specialists()))
    for task in _active_tasks_by_priority(state):
        task_id = str(task.get("id") or "")
        for specialist in recommendations:
            if str(specialist.get("task_id") or "") != task_id:
                continue
            candidate = _recommended_specialist_action(task_id=task_id, specialist=specialist)
            if _fallback_action_is_executable(state, candidate, settings=settings):
                return candidate
        if task_id == "surface-map":
            candidate = _surface_map_fallback_action()
            if _fallback_action_is_executable(state, candidate, settings=settings):
                return candidate
    return None


def _recommended_specialist_action(
    *,
    task_id: str,
    specialist: Mapping[str, object],
) -> dict[str, object]:
    probe = str(specialist.get("probe") or "").strip()
    name = str(specialist.get("name") or probe).strip()
    purpose = str(specialist.get("purpose") or "").strip()
    return {
        "action": "run_probe",
        "task_id": task_id,
        "probe": probe,
        "strategy": f"harness_fallback_{name}",
        "notes": "Continue the highest-priority open task with its recommended bounded specialist.",
        "expected_signal": purpose or "new target evidence or a bounded exhausted result",
        "fallback": "If this specialist is exhausted, move to a materially different open route.",
        "memory_updates": [f"same-turn harness fallback selected {probe}"],
    }


def _surface_map_fallback_action() -> dict[str, object]:
    return {
        "action": "run_probe",
        "task_id": "surface-map",
        "probe": "surface_map",
        "strategy": "harness_fallback_surface_map",
        "notes": "Complete the open surface inventory with the bounded native mapper.",
        "expected_signal": "new reachable surface or a bounded exhausted inventory",
        "fallback": (
            "If the surface is exhausted, close the task and continue with evidence-backed work."
        ),
        "memory_updates": ["same-turn harness fallback selected surface_map"],
    }


def _fallback_action_is_executable(
    state: AgentState,
    action: Mapping[str, object],
    *,
    settings: AIWebAgentSettings,
) -> bool:
    if action.get("action") != "run_probe":
        return False
    probe = str(action.get("probe") or "").strip()
    if not probe or probe_recently_exhausted(state, probe):
        return False
    if settings.traffic_policy_mode == "low-noise" and probe_requires_external_process(probe):
        return False
    if settings.authentication is not None and authenticated_probe_unavailability(probe):
        return False
    return not _would_hit_repeat_guard(state, action)


def _would_hit_repeat_guard(state: AgentState, action: Mapping[str, object]) -> bool:
    if str(action.get("action") or "") not in _REPEAT_GUARDED_ACTIONS:
        return False
    return (
        state.ledger.count(action, context=_repeat_context(state))
        >= MAX_IDENTICAL_ACTION_EXECUTIONS
    )


def _action_targets_active_task(
    state: AgentState,
    action: Mapping[str, object],
) -> bool:
    task_id = str(action.get("task_id") or "").strip()
    return any(
        str(task.get("id") or "") == task_id
        and str(task.get("status") or "pending") in _ACTIVE_TASK_STATUSES
        for task in state.tasks
    )


def _active_tasks_by_priority(state: AgentState) -> list[dict[str, object]]:
    active = [
        task
        for task in state.tasks
        if str(task.get("status") or "pending") in _ACTIVE_TASK_STATUSES
    ]
    return sorted(
        active,
        key=lambda task: (
            -_task_int(task.get("priority")),
            0 if str(task.get("status") or "pending") == "in_progress" else 1,
            _task_int(task.get("attempts")),
            str(task.get("id") or ""),
        ),
    )


def _task_int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _assessment_ready_for_terminal(
    state: AgentState,
    *,
    turn: int,
    max_turns: int,
    settings: AIWebAgentSettings | None = None,
) -> bool:
    if not state.tasks or _has_open_assessment_tasks(state):
        return False
    if pending_closure_obligation(state) is not None:
        return False
    if _has_executable_live_primitive_route(state, settings=settings):
        return False
    return not _final_is_premature(
        action={"action": "final"},
        state=state,
        turn=turn,
        max_turns=max_turns,
        settings=settings,
    )


def _has_executable_live_primitive_route(
    state: AgentState,
    *,
    settings: AIWebAgentSettings | None,
) -> bool:
    routes = routed_probes(state)
    for probe, _score in sorted(routes.items(), key=lambda item: (-item[1], item[0])):
        action = {"action": "run_probe", "probe": probe}
        if settings is not None:
            if _fallback_action_is_executable(state, action, settings=settings):
                return True
            continue
        if not probe_recently_exhausted(state, probe) and not _would_hit_repeat_guard(
            state,
            action,
        ):
            return True
    return False


def _synthesized_final_action() -> dict[str, object]:
    return {
        "action": "final",
        "summary": "All in-scope assessment tasks and closure obligations are complete.",
        "strategy": "harness_assessment_complete",
        "memory_updates": ["assessment task and closure queues are complete"],
    }


def _record_synthesized_terminal(  # noqa: PLR0913 - event boundary needs explicit owners.
    *,
    turn: int,
    action_id: str,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    authentication: ManagedAttackAuthentication | None,
) -> None:
    task_counts = Counter(str(task.get("status") or "pending") for task in state.tasks)
    payload = _authenticated_artifact_mapping(
        authentication,
        {
            "turn": turn,
            "action_id": action_id,
            "reason": "assessment_tasks_and_closure_obligations_complete",
            "task_status_counts": dict(sorted(task_counts.items())),
            "synthesized": True,
        },
    )
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="harness_terminal_synthesized",
        payload=payload,
    )
    workspace.record_event(kind="harness_terminal_synthesized", payload=payload)
    workspace.record_event(
        kind="agent_final",
        payload={
            "action_id": action_id,
            "summary": "Assessment queues complete; final report synthesized by the harness.",
            "synthesized": True,
        },
    )


def _forced_primitive_probe_action(
    *,
    state: AgentState,
    proposed_action: Mapping[str, object],
) -> dict[str, object] | None:
    primitive_name = locked_primitive(state)
    rule = primitive_rule(primitive_name) if primitive_name else None
    if rule is None:
        return None
    if _authenticated_probe_unavailable_for_state(state, rule.probe):
        return None
    if probe_recently_exhausted(state, rule.probe):
        return None
    if (
        proposed_action.get("action") == "run_probe"
        and str(proposed_action.get("probe") or "") == rule.probe
    ):
        return None
    action: dict[str, object] = {
        "action": "run_probe",
        "task_id": rule.task_id,
        "probe": rule.probe,
        "strategy": f"locked_{primitive_name}",
        "notes": f"{primitive_name} is confirmed; run the deterministic closer before unrelated actions.",
        "expected_signal": "proof-bearing response or a bounded exhausted signal from the locked specialist",
        "fallback": "If the locked specialist exhausts this primitive twice, move to the next confirmed primitive or distinct evidence.",
        "memory_updates": [f"forced locked primitive probe: {primitive_name} -> {rule.probe}"],
    }
    if state.ledger.count(action, context=_repeat_context(state)) >= 2:
        return None
    return action


@dataclass(frozen=True)
class _EvidenceProbeRoute:
    name: str
    probe: str
    task_id: str
    markers: tuple[str, ...]
    signal_keys: tuple[str, ...] = ()
    notes: str = ""
    expected_signal: str = "specialist finding, proof, or bounded exhausted signal"


_EVIDENCE_PROBE_ROUTES: tuple[_EvidenceProbeRoute, ...] = (
    _EvidenceProbeRoute(
        name="apache_traversal",
        probe="file_read_extract",
        task_id="file-fetch-parser",
        markers=("apache_2_4_path_traversal_surface", "apache/2.4.49", "apache/2.4.50"),
        notes=(
            "Apache 2.4.49/2.4.50 traversal/RCE evidence is present; run the bounded "
            "file-read extractor so direct traversal GET paths are tried before unrelated auth, SQL, XML, or XSS workflows."
        ),
        expected_signal="Apache traversal file read, proof-bearing root file, or bounded exhausted signal",
    ),
    _EvidenceProbeRoute(
        name="php_auth_cookie_deserialization",
        probe="cookie_deserialization",
        task_id="file-fetch-parser",
        markers=(),
        notes=(
            "PHP sign-in/sign-up plus session-cookie evidence is present; run cookie_deserialization "
            "so the specialist can register/login, harvest serialized cookies, and test safe identity tampering."
        ),
        expected_signal="serialized auth cookie, cookie-tamper proof, or bounded no-serialized-cookie result",
    ),
    _EvidenceProbeRoute(
        name="password_change_idor",
        probe="idor_boundary",
        task_id="stateful-session",
        markers=(),
        notes=(
            "Password-change IDOR evidence is present; run the IDOR specialist to establish "
            "a low-privilege session, mutate user/account ids, and verify privileged login."
        ),
        expected_signal="password-change IDOR proof, privileged login, or bounded no-IDOR result",
    ),
    _EvidenceProbeRoute(
        name="first_user_object_idor",
        probe="idor_boundary",
        task_id="stateful-session",
        markers=(),
        notes=(
            "Visible objective mentions a first-user/profile workflow with a start timestamp; "
            "run the IDOR specialist to register, derive candidate object IDs, and fetch profile routes."
        ),
        expected_signal="first-user profile proof, concrete object-route access delta, or bounded no-IDOR result",
    ),
    _EvidenceProbeRoute(
        name="default_credentials",
        probe="default_credentials",
        task_id="stateful-session",
        markers=("login", "signin", "sign-in", "username", "password", "basic auth", "auth form"),
        notes="Login/password evidence is present without a confirmed session; try the bounded credential specialist before custom auth loops.",
        expected_signal="authenticated session, redirect, or exhausted default-credential result",
    ),
    _EvidenceProbeRoute(
        name="ssti",
        probe="ssti_fingerprint",
        task_id="server-rendering",
        markers=(
            "ssti",
            "ssti_fingerprint_signal",
            "template syntax",
            "templatesyntaxerror",
            "{{",
            "{%",
            "jinja",
            "twig",
            "freemarker",
            "mako",
            "velocity",
            "render_template",
            "server-side rendering",
        ),
        notes="Template/rendering evidence is present; run the SSTI specialist before handwritten template payload loops.",
        expected_signal="template engine fingerprint, execution proof, or bounded no-SSTI result",
    ),
    _EvidenceProbeRoute(
        name="xss_value_boundary",
        probe="reflection_value_boundary",
        task_id="input-reflection",
        markers=(
            "xss_reflection_context",
            "html_attribute",
            "html_body",
            "js_string",
            "expected dialog",
            "wrong value",
        ),
        signal_keys=("xss_contexts",),
        notes="A reflected XSS sink/context is mapped; run the value-boundary closer before custom payload loops.",
        expected_signal="client-side proof extraction, value-gated signal, or bounded exhausted signal",
    ),
    _EvidenceProbeRoute(
        name="xss_context",
        probe="xss_context",
        task_id="input-reflection",
        markers=("reflected", "reflection", "innerhtml", "html sink", "xss"),
        signal_keys=("reflections",),
        notes="Reflection/XSS evidence is present; map sink context with the XSS specialist before handwritten payload loops.",
        expected_signal="reflected sink context or bounded no-reflection result",
    ),
    _EvidenceProbeRoute(
        name="xss_reflection_value",
        probe="reflection_value_boundary",
        task_id="input-reflection",
        markers=(
            "xss_context exceeded",
            "run_probe xss_context exceeded",
            "reflected",
            "reflection",
        ),
        signal_keys=("reflections",),
        notes=(
            "Reflected input evidence remains after XSS context mapping; run the server-verified "
            "dialog/value closer before drifting to template, XML, or exposure probes."
        ),
        expected_signal="client-side dialog proof, value-gated response, or bounded exhausted signal",
    ),
    _EvidenceProbeRoute(
        name="preg_match_subject",
        probe="preg_match_subject",
        task_id="data-query",
        markers=("preg_match", "array given", "expects parameter 2"),
        notes="PHP preg_match/type-confusion evidence is present; run the dedicated subject-shape specialist.",
    ),
    _EvidenceProbeRoute(
        name="filtered_query",
        probe="filtered_query_bypass",
        task_id="data-query",
        markers=(
            "filtered",
            "some item is filtered",
            "no results",
            "user exists",
            "blocked keyword",
        ),
        notes="Filtered query/login evidence is present; run the bypass specialist before custom payload loops.",
    ),
    _EvidenceProbeRoute(
        name="sqli",
        probe="sqli_differential",
        task_id="data-query",
        markers=("sql", "sqlite", "mysql", "postgres", "sql syntax", "database error"),
        signal_keys=("sqli_inputs", "sqli_replays"),
        notes="SQL/query influence evidence is present; run paired SQLi differential checks before ad hoc extraction.",
        expected_signal="SQLi differential signal, SQL error signal, or bounded no-SQLi result",
    ),
    _EvidenceProbeRoute(
        name="file_fetch_parser",
        probe="file_fetch_parser",
        task_id="file-fetch-parser",
        markers=("filename", "upload", "multipart/form-data", "../", "lfi", "traversal", "include"),
        notes="File/path/upload/parser evidence is present; run the file/parser specialist before custom path guessing.",
    ),
    _EvidenceProbeRoute(
        name="xxe",
        probe="xxe_boundary",
        task_id="file-fetch-parser",
        markers=("xxe", "xml", "soap", "wsdl", "svg", "doctype", "entity"),
        notes="XML/SOAP/parser evidence is present; run the XXE specialist before unrelated probes.",
    ),
    _EvidenceProbeRoute(
        name="command_boundary",
        probe="command_boundary",
        task_id="command-boundary",
        markers=(
            "shell metacharacter",
            "shell injection",
            "ping",
            "nslookup",
            "traceroute",
            "host lookup",
            "command_boundary",
        ),
        notes="Command-like input evidence is present; run the command-boundary specialist before handwritten shell payloads.",
    ),
    _EvidenceProbeRoute(
        name="ssrf",
        probe="ssrf_boundary",
        task_id="file-fetch-parser",
        markers=(
            "ssrf",
            "webhook",
            "callback url",
            "fetch url",
            "proxy url",
            "redirect url",
            "metadata",
        ),
        notes="URL-fetch/SSRF evidence is present; run the SSRF specialist before custom curl-style loops.",
    ),
    _EvidenceProbeRoute(
        name="csrf_session",
        probe="csrf_session",
        task_id="stateful-session",
        markers=(
            "csrf",
            "xsrf",
            "authenticity_token",
            "samesite",
            "httponly",
            "logout",
            "session fixation",
        ),
        notes="CSRF/session lifecycle evidence is present; run csrf_session before only preserving tokens.",
    ),
    _EvidenceProbeRoute(
        name="browser_boundary",
        probe="browser_boundary",
        task_id="api-behavior",
        markers=(
            "cors",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "clickjack",
            "x-frame-options",
            "frame-ancestors",
            "websocket",
            "ws://",
            "wss://",
            "localstorage",
            "sessionstorage",
        ),
        notes="Browser trust-boundary evidence is present; run browser_boundary before custom Origin/storage checks.",
    ),
    _EvidenceProbeRoute(
        name="jwt",
        probe="jwt_exploit",
        task_id="api-behavior",
        markers=("jwt", "bearer eyj", "eyjhb", "jwt_observed", '"alg"'),
        notes="JWT/bearer-token evidence is present; run jwt_exploit before manually decoding or replaying tokens.",
    ),
    _EvidenceProbeRoute(
        name="graphql",
        probe="graphql_exploit",
        task_id="api-behavior",
        markers=("graphql", "graphiql", "__schema", "introspection", "graphql_schema"),
        notes="GraphQL/schema evidence is present; run graphql_exploit before manual query loops.",
    ),
    _EvidenceProbeRoute(
        name="cms",
        probe="cms_exposure",
        task_id="flag-and-secret-sweep",
        markers=(
            "wordpress",
            "wp-content",
            "wp-json",
            "wp-admin",
            "wp-login",
            "backup-migration",
            "plugin",
        ),
        notes="CMS/plugin/backup evidence is present; run cms_exposure before generic path guessing.",
    ),
    _EvidenceProbeRoute(
        name="werkzeug",
        probe="werkzeug_console",
        task_id="flag-and-secret-sweep",
        markers=(
            "werkzeug",
            "werkzeug debugger",
            "console locked",
            "console unlocked",
            "traceback (most recent call last)",
        ),
        notes="Werkzeug debugger evidence is present; run werkzeug_console before manually scraping debugger assets.",
    ),
    _EvidenceProbeRoute(
        name="cookie_deserialization",
        probe="cookie_deserialization",
        task_id="file-fetch-parser",
        markers=(
            "pickle",
            "serialized",
            "deserialize",
            "deserialization",
            "__reduce__",
            "!!python",
        ),
        notes="Serialized-cookie evidence is present; run cookie_deserialization before handwritten gadget loops.",
    ),
    _EvidenceProbeRoute(
        name="direct_exposure",
        probe="direct_exposure",
        task_id="flag-and-secret-sweep",
        markers=("admin", "config", "backup", ".env", "debug", "source", "direct_exposure"),
        notes="Admin/config/backup/debug evidence is present; run direct_exposure before broad manual path loops.",
    ),
)


def _forced_evidence_probe_action(
    *,
    state: AgentState,
    proposed_action: Mapping[str, object],
) -> dict[str, object] | None:
    live_routed_probes = routed_probes(state)
    if state.flags:
        multi_finding_action = _forced_multi_finding_url_fetch_action(
            state=state,
            proposed_action=proposed_action,
        )
        if multi_finding_action is not None:
            return multi_finding_action
        if not _continue_after_proof_enabled(state) or not live_routed_probes:
            return None
    proposed_probe = str(proposed_action.get("probe") or "")
    if (
        proposed_action.get("action") == "run_probe"
        and proposed_probe in live_routed_probes
        and not probe_recently_exhausted(state, proposed_probe)
        and not _authenticated_probe_unavailable_for_state(state, proposed_probe)
    ):
        # A model-selected closer for any live confirmed primitive, including a
        # tier-1 workflow, is stronger than description- or surface-only routing.
        return None
    locked_name = locked_primitive(state)
    locked_rule = primitive_rule(locked_name) if locked_name else None
    if locked_rule is not None and not _authenticated_probe_unavailable_for_state(
        state, locked_rule.probe
    ):
        return None
    if (
        _has_description_reminder_template_flow(state)
        and not probe_recently_exhausted(state, "ssti_fingerprint")
        and proposed_action.get("action") == "run_probe"
        and str(proposed_action.get("probe") or "")
        not in {"ssti_fingerprint", "default_credentials", "csrf_session"}
    ):
        return {
            "action": "run_probe",
            "task_id": "server-rendering",
            "probe": "ssti_fingerprint",
            "strategy": "visible_reminder_template_flow",
            "notes": (
                "Visible description mentions an authenticated reminder/schedule workflow; "
                "test bounded server-side rendering before debug/exposure detours."
            ),
            "expected_signal": "template expression signal, proof extraction, or bounded no-SSTI result",
            "fallback": "If ssti_fingerprint exhausts, resume model-driven exploration with a different evidence route.",
            "memory_updates": [
                "visible reminder workflow suggests server-rendered date/reminder input"
            ],
        }
    if proposed_action.get("action") == "run_probe":
        if (
            proposed_probe == "dom_execution"
            and _client_xss_objective(_state_evidence_text(state))
            and not probe_recently_exhausted(state, "dom_execution")
            and not _authenticated_probe_unavailable_for_state(state, proposed_probe)
        ):
            return None
        known_evidence_probes = {route.probe for route in _EVIDENCE_PROBE_ROUTES}
        if (
            proposed_probe in known_evidence_probes
            and not probe_recently_exhausted(state, proposed_probe)
            and not _authenticated_probe_unavailable_for_state(state, proposed_probe)
        ):
            if state.flags and live_routed_probes and proposed_probe not in live_routed_probes:
                pass
            elif (
                _has_apache_traversal_surface(_state_evidence_text(state))
                and not probe_recently_exhausted(state, "file_read_extract")
                and proposed_probe != "file_read_extract"
            ):
                pass
            elif (
                _has_php_auth_cookie_surface(state)
                and not probe_recently_exhausted(state, "cookie_deserialization")
                and proposed_probe not in {"cookie_deserialization", "default_credentials"}
            ):
                pass
            elif (
                _reflected_xss_pipeline_available(state)
                and not (
                    proposed_probe in {"sqli_differential", "sqli_exploit", "filtered_query_bypass"}
                    and _state_has_query_filter_evidence(state)
                )
                and proposed_probe
                not in {
                    "xss_context",
                    "reflection_value_boundary",
                    "dom_execution",
                }
            ):
                pass
            else:
                return None
    for route in _EVIDENCE_PROBE_ROUTES:
        if state.flags and live_routed_probes and route.probe not in live_routed_probes:
            continue
        if _authenticated_probe_unavailable_for_state(state, route.probe):
            continue
        if (
            proposed_action.get("action") == "run_probe"
            and str(proposed_action.get("probe") or "") == route.probe
        ):
            return None
        if probe_recently_exhausted(state, route.probe):
            continue
        if not _route_has_evidence(state, route):
            continue
        action = {
            "action": "run_probe",
            "task_id": route.task_id,
            "probe": route.probe,
            "strategy": f"forced_evidence_{route.name}",
            "notes": route.notes,
            "expected_signal": route.expected_signal,
            "fallback": (
                f"If {route.probe} exhausts twice, resume model-driven exploration with a materially different "
                "probe or closure method."
            ),
            "memory_updates": [f"forced evidence route: {route.name} -> {route.probe}"],
        }
        if state.ledger.count(action, context=_repeat_context(state)) >= 2:
            continue
        return action
    return None


def _authenticated_probe_unavailable_for_state(state: AgentState, probe: str) -> bool:
    return bool(
        str(state.surface.get("authenticated_identity") or "").strip()
        and authenticated_probe_unavailability(probe)
    )


def _forced_multi_finding_url_fetch_action(
    *,
    state: AgentState,
    proposed_action: Mapping[str, object],
) -> dict[str, object] | None:
    """Close a preserved URL-fetch branch before ending a multi-finding run."""
    proposed_ssrf = (
        proposed_action.get("action") == "run_probe"
        and str(proposed_action.get("probe") or "") == "ssrf_boundary"
    )
    ssrf_proof_recorded = any(
        action.get("action") == "run_probe"
        and action.get("probe") == "ssrf_boundary"
        and action.get("outcome") == "flag_candidate"
        for action in state.actions
    )
    if (
        not _continue_after_proof_enabled(state)
        or proposed_ssrf
        or ssrf_proof_recorded
        or probe_recently_exhausted(state, "ssrf_boundary")
        or not _has_observed_http_url_input(state)
    ):
        return None
    action: dict[str, object] = {
        "action": "run_probe",
        "task_id": "file-fetch-parser",
        "probe": "ssrf_boundary",
        "strategy": "forced_multi_finding_observed_url_fetch",
        "notes": (
            "A discovered form contains a URL-like input with an observed HTTP(S) default. "
            "Run the scoped SSRF specialist before closing this distinct assessment branch."
        ),
        "expected_signal": (
            "bounded internal-fetch differential, proof extraction, or explicit no-SSRF result"
        ),
        "fallback": (
            "If ssrf_boundary exhausts twice, resume model-driven exploration with a materially "
            "different untested vulnerability family."
        ),
        "memory_updates": [
            "preserved structured URL-fetch form requires SSRF closure after an earlier proof"
        ],
    }
    if state.ledger.count(action, context=_repeat_context(state)) >= 2:
        return None
    return action


def _has_observed_http_url_input(state: AgentState) -> bool:
    return any(
        _input_has_http_url_default(input_item)
        for form in _observed_structured_forms(state)
        for input_item in _list_of_dicts(form.get("inputs"))
    )


def _observed_structured_forms(state: AgentState) -> list[dict[str, object]]:
    forms = _list_of_dicts(state.surface.get("forms"))
    for raw_form in state.signals.get("forms", []):
        if isinstance(raw_form, dict):
            normalized_form: dict[str, object] = {
                str(key): value for key, value in raw_form.items()
            }
            forms.append(normalized_form)
        elif isinstance(raw_form, str):
            parsed = _json_object(raw_form)
            if parsed:
                forms.append(parsed)
    return forms


def _input_has_http_url_default(input_item: Mapping[str, object]) -> bool:
    name = str(input_item.get("name") or "").strip().lower()
    name_parts = {part for part in re.split(r"[^a-z0-9]+", name) if part}
    url_like_name = bool(name_parts & {"url", "uri"}) or name in {
        "callback",
        "destination",
        "endpoint",
        "webhook",
    }
    if not url_like_name:
        return False
    value = str(input_item.get("value") or input_item.get("default") or "").strip()
    parsed_url = urlparse(value)
    return parsed_url.scheme.lower() in {"http", "https"} and bool(parsed_url.hostname)


def _has_description_reminder_template_flow(state: AgentState) -> bool:
    description = str(state.surface.get("visible_description") or "").lower()
    if not description:
        return False
    if not _text_has_any(description, ("remind", "reminder", "notify", "notification", "schedule")):
        return False
    return _text_has_any(description, ("login", "log in", "authenticated", "user"))


def _route_has_evidence(state: AgentState, route: _EvidenceProbeRoute) -> bool:
    text = _state_evidence_text(state)
    if route.name != "apache_traversal" and _has_apache_traversal_surface(text):
        return False
    if route.name == "apache_traversal":
        return _has_apache_traversal_surface(text)
    if route.name == "php_auth_cookie_deserialization":
        return _has_php_auth_cookie_surface(state)
    if route.name == "password_change_idor":
        return _password_change_idor_evidence(text)
    if route.name == "first_user_object_idor":
        return _first_user_object_idor_evidence(text)
    if route.name == "default_credentials" and _state_has_authenticated_replay_context(state):
        return False
    if route.name == "default_credentials" and _password_change_idor_evidence(text):
        return False
    if _client_xss_objective(text) and route.name not in {
        "xss_context",
        "xss_reflection_value",
        "xss_value_boundary",
    }:
        return False
    if route.name in {
        "xss_context",
        "xss_reflection_value",
        "xss_value_boundary",
        "direct_exposure",
    }:
        if _auth_cookie_tamper_objective(text):
            return False
    if route.name == "ssti" and _reflected_xss_pipeline_available(state):
        return False
    if route.name in {"xss_context", "xss_reflection_value", "xss_value_boundary"}:
        if _state_has_query_filter_evidence(state) and not _explicit_xss_evidence(text):
            return False
    if route.name == "file_fetch_parser" and any(
        marker in text for marker in ("xml", "soap", "wsdl", "xxe")
    ):
        return False
    if route.name == "sqli" and _template_markers_dominate(text):
        return False
    if route.name == "ssrf" and not _url_fetch_evidence(text):
        return False
    return any(marker in text for marker in route.markers) or any(
        state.signals.get(key) for key in route.signal_keys
    )


def _has_apache_traversal_surface(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "apache_2_4_path_traversal_surface",
            "apache/2.4.49",
            "apache/2.4.50",
            "apache 2.4.49",
            "apache 2.4.50",
        )
    )


def _reflected_xss_pipeline_available(state: AgentState) -> bool:
    text = _state_evidence_text(state)
    has_reflection = bool(state.signals.get("reflections")) or any(
        marker in text
        for marker in ("reflected", "reflection", "html sink", "xss_context exceeded")
    )
    if not has_reflection:
        return False
    return not (
        probe_recently_exhausted(state, "xss_context")
        and probe_recently_exhausted(state, "reflection_value_boundary")
    )


def _password_change_idor_evidence(text: str) -> bool:
    idor_evidence = any(
        marker in text
        for marker in (
            "idor",
            "insecure direct object",
            "authorization",
            "user_id",
            "userid",
            "profile",
        )
    )
    password_evidence = any(
        marker in text
        for marker in (
            "change password",
            "password reset",
            "reset password",
            "another user's password",
            "change_password",
            "update_password",
            "oldpassword",
            "newpassword",
            "confirmpassword",
        )
    )
    return idor_evidence and password_evidence


def _first_user_object_idor_evidence(text: str) -> bool:
    return (
        any(marker in text for marker in ("first user", "1st user", "target user"))
        and any(
            marker in text
            for marker in ("start timestamp", "starttime", "unix timestamp", "created")
        )
        and any(marker in text for marker in ("profile", "register", "login"))
    )


def _auth_cookie_tamper_objective(text: str) -> bool:
    auth = any(marker in text for marker in ("login", "username", "password", "auth", "session"))
    cookie = "cookie" in text
    tamper = any(
        marker in text
        for marker in ("tamper", "change the username", "change username", "become admin")
    )
    crypto = any(
        marker in text
        for marker in ("aes-cbc", "cbc", "encrypted", "without a mac", "no mac", "missing mac")
    )
    return auth and cookie and (tamper or crypto)


def _client_xss_objective(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "xss",
            "cross-site scripting",
            "client-side script",
            "script execution",
            "alert(",
            "expected dialog",
        )
    )


def _has_php_auth_cookie_surface(state: AgentState) -> bool:
    text = _state_evidence_text(state)
    php_surface = any(
        marker in text
        for marker in (
            ".php",
            "x-powered-by': 'php",
            '"x-powered-by": "php',
            "x-powered-by: php",
            "phpsessid",
        )
    )
    if not php_surface:
        return False
    auth_surface = any(
        marker in text for marker in ("login", "signin", "sign-in", "username", "password")
    )
    registration_surface = any(
        marker in text for marker in ("register", "signup", "sign-up", "create a new account")
    )
    cookie_surface = any(
        marker in text for marker in ("set-cookie", "phpsessid", "session cookie", "cookie")
    )
    return auth_surface and registration_surface and cookie_surface


def _state_evidence_text(state: AgentState) -> str:
    parts: list[str] = []
    for values in state.signals.values():
        parts.extend(str(value) for value in values[-20:])
    parts.extend(state.facts[-30:])
    parts.extend(state.hypotheses[-20:])
    parts.extend(json.dumps(action, sort_keys=True) for action in state.actions[-8:])
    parts.append(json.dumps(state.surface, sort_keys=True))
    return " ".join(parts).lower()


def _template_markers_dominate(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "ssti",
            "templatesyntaxerror",
            "template syntax",
            "{{",
            "{%",
            "jinja",
            "twig",
        )
    )


def _state_has_query_filter_evidence(state: AgentState) -> bool:
    text = _state_evidence_text(state)
    query_input = any(
        marker in text
        for marker in (
            '"category"',
            "category=",
            "category ",
            "filter",
            "search",
            "query",
            "posts",
        )
    )
    data_objective = any(
        marker in text for marker in ("secret category", "hidden posts", "category parameter")
    )
    return query_input and data_objective


def _explicit_xss_evidence(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "xss",
            "cross-site scripting",
            "script execution",
            "alert(",
            "onerror",
            "onload",
            "innerhtml",
            "html sink",
            "xss_reflection_context",
        )
    )


def _url_fetch_evidence(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "ssrf",
            "webhook",
            "callback",
            "fetch url",
            "proxy url",
            "redirect url",
            "metadata",
        )
    )


def _forced_cookie_identity_idor_action(
    *,
    state: AgentState,
    proposed_action: Mapping[str, object],
) -> dict[str, object] | None:
    if state.flags:
        return None
    if (
        proposed_action.get("action") == "run_probe"
        and str(proposed_action.get("probe") or "") == "idor_boundary"
    ):
        return None
    if probe_recently_exhausted(state, "idor_boundary"):
        return None
    if not _has_cookie_identity_idor_evidence(state):
        return None
    action: dict[str, object] = {
        "action": "run_probe",
        "task_id": "stateful-session",
        "probe": "idor_boundary",
        "strategy": "forced_cookie_identity_idor",
        "notes": (
            "Authenticated identity-looking cookie plus object-route evidence is present; "
            "run the deterministic IDOR cookie/header/object mutation loop before custom commands."
        ),
        "expected_signal": "proof-bearing response or concrete cookie-identity/object-route access delta",
        "fallback": "If idor_boundary exhausts twice, resume model-driven exploration with a different primitive.",
        "memory_updates": ["forced cookie identity IDOR loop -> idor_boundary"],
    }
    if state.ledger.count(action, context=_repeat_context(state)) >= 2:
        return None
    return action


def _has_cookie_identity_idor_evidence(state: AgentState) -> bool:
    return _state_has_simple_identity_cookie(state) and _state_has_object_route_evidence(state)


def _forced_authenticated_object_idor_action(
    *,
    state: AgentState,
    proposed_action: Mapping[str, object],
) -> dict[str, object] | None:
    if state.flags:
        return None
    if (
        proposed_action.get("action") == "run_probe"
        and str(proposed_action.get("probe") or "") == "idor_boundary"
    ):
        return None
    if probe_recently_exhausted(state, "idor_boundary"):
        return None
    if not (
        _state_has_authenticated_replay_context(state) and _state_has_object_route_evidence(state)
    ):
        return None
    action: dict[str, object] = {
        "action": "run_probe",
        "task_id": "stateful-session",
        "probe": "idor_boundary",
        "strategy": "forced_authenticated_object_idor",
        "notes": (
            "Authenticated replay context plus object-route evidence is present; "
            "run deterministic path/header/form IDOR enumeration before unrelated custom commands."
        ),
        "expected_signal": "proof-bearing response or concrete authenticated object-route access delta",
        "fallback": "If idor_boundary exhausts twice, resume model-driven exploration with a different primitive.",
        "memory_updates": ["forced authenticated object-route IDOR loop -> idor_boundary"],
    }
    if state.ledger.count(action, context=_repeat_context(state)) >= 2:
        return None
    return action


def _state_has_authenticated_replay_context(state: AgentState) -> bool:
    values: list[str] = []
    values.extend(str(value) for value in state.signals.get("auth_headers", []))
    values.extend(str(value) for value in state.signals.get("cookies", []))
    values.extend(str(value) for value in state.signals.get("forms", []))
    payload = "\n".join(values).lower()
    if "auth_headers" in payload or "auth_replay_headers" in payload:
        return True
    if re.search(r"\b(?:authorization|cookie|x-access-token|x-auth-token)\s*:", payload):
        return True
    if re.search(r"\b(?:access_token|session|sessionid|auth_token|jwt|token)=", payload):
        return True
    markers = {str(marker) for marker in state.signals.get("markers", [])}
    return bool(
        markers
        & {
            "auth_session_followup_signal",
            "default_credentials_valid",
            "session_followup_proof",
            "auth_workflow_completed_signal",
        }
    ) and bool(values)


def _state_has_simple_identity_cookie(state: AgentState) -> bool:
    values: list[str] = []
    values.extend(str(value) for value in state.signals.get("cookies", []))
    values.extend(
        str(value)
        for value in state.signals.get("auth_headers", [])
        if "cookie" in str(value).lower()
    )
    for raw in values:
        for value in _cookie_identity_candidate_values(raw):
            if _simple_cookie_value_encodes_identity(value):
                return True
    return False


def _cookie_identity_candidate_values(raw: str) -> list[str]:
    values: list[str] = []
    text = re.sub(r"(?i)^\s*(?:set-cookie|cookie):\s*", "", raw).strip()
    for chunk in re.split(r",\s*(?=[A-Za-z0-9_.-]+=)", text):
        for part in chunk.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            lowered = name.strip().lower().replace("-", "_")
            if not any(
                token in lowered
                for token in (
                    "access",
                    "auth",
                    "session",
                    "token",
                    "user",
                    "account",
                    "company",
                    "tenant",
                    "org",
                    "uid",
                )
            ):
                continue
            values.append(value.strip().strip("'\""))
    return values


def _simple_cookie_value_encodes_identity(value: str) -> bool:
    text = value.strip()
    bearer = re.match(r"(?i)^bearer\s+(.+)$", text)
    if bearer:
        text = bearer.group(1).strip()
    if re.fullmatch(r"\d{1,12}", text):
        return True
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}={0,2}", text):
        return False
    padded = text + ("=" * (-len(text) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8").strip()
    except Exception:  # noqa: BLE001 - arbitrary cookie material.
        return False
    return bool(re.fullmatch(r"\d{1,12}", decoded))


def _state_has_object_route_evidence(state: AgentState) -> bool:
    payload = json.dumps(
        {
            "signals": {
                "endpoints": state.signals.get("endpoints", []),
                "forms": state.signals.get("forms", []),
                "parameters": state.signals.get("parameters", []),
                "markers": state.signals.get("markers", []),
            },
            "surface": state.surface,
        },
        sort_keys=True,
    ).lower()
    if re.search(
        r"/(?:edit_)?(?:profile|company|account|user|tenant|org|order|invoice|record|job)s?/\d{1,12}(?:/|\"|\\?|&|$)",
        payload,
    ):
        return True
    return any(
        token in payload
        for token in (
            "account_id",
            "company_id",
            "customer_id",
            "edit_profile",
            "object_id",
            "profile",
            "tenant_id",
            "user_id",
        )
    )


def _final_is_premature(
    *,
    action: Mapping[str, object],
    state: AgentState,
    turn: int,
    max_turns: int,
    settings: AIWebAgentSettings | None = None,
) -> bool:
    del turn, max_turns
    if action.get("action") != "final":
        return False
    if state.surface.get("flag_objective") is False:
        return (
            _has_open_assessment_tasks(state)
            or pending_closure_obligation(state) is not None
            or _has_executable_live_primitive_route(state, settings=settings)
        )
    return not _proof_objective_completion_met(state, settings=settings)


def _proof_objective_completion_met(
    state: AgentState,
    *,
    settings: AIWebAgentSettings | None = None,
) -> bool:
    if (
        _proof_count_requirement_unmet(state)
        or _captured_proof_count(state) == 0
        or pending_closure_obligation(state) is not None
    ):
        return False
    if not _continue_after_proof_enabled(state):
        return True
    return (
        not _has_open_assessment_tasks(state)
        and not _has_executable_live_primitive_route(state, settings=settings)
    )


def _proof_count_requirement_unmet(state: AgentState) -> bool:
    expected = _state_expected_proof_count(state)
    return expected is not None and _captured_proof_count(state) < expected


def _state_expected_proof_count(state: AgentState) -> int | None:
    expected = state.surface.get("expected_proof_count")
    if isinstance(expected, bool) or not isinstance(expected, int):
        return None
    return expected if expected > 0 else None


def _captured_proof_count(state: AgentState) -> int:
    return len({proof for item in state.flags if (proof := str(item).strip())})


def _premature_final_action(action: Mapping[str, object]) -> dict[str, object]:
    return {
        "action": "invalid",
        "error": "final is premature while required assessment work remains",
        "raw": str(action.get("summary") or "")[:2000],
    }


def _brief_requests_multiple_proofs(brief: EngagementBrief) -> bool:
    context = dict(brief.context or {})
    if context.get("stop_after_first_finding") is True:
        return False
    if context.get("continue_after_proof") is True:
        return True
    if context.get("stop_after_first_proof") is False:
        return True
    expected_count = _brief_expected_proof_count(brief)
    if expected_count is not None and expected_count > 1:
        return True
    objectives = {str(item).strip().lower() for item in brief.objectives}
    if objectives & {
        "web_application_assessment",
        "vulnerability_assessment",
        "report_findings",
    }:
        return True
    text = " ".join(
        str(context.get(key) or "")
        for key in ("description", "win_condition", "objective", "objectives")
    ).lower()
    return any(marker in text for marker in _MULTI_PROOF_TEXT_MARKERS)


def _brief_expected_proof_count(brief: EngagementBrief) -> int | None:
    expected_count = dict(brief.context or {}).get("expected_proof_count")
    if isinstance(expected_count, bool) or not isinstance(expected_count, int):
        return None
    return expected_count if expected_count > 0 else None


def _brief_stops_after_first_finding(brief: EngagementBrief) -> bool:
    return dict(brief.context or {}).get("stop_after_first_finding") is True


def _brief_has_flag_objective(brief: EngagementBrief) -> bool:
    if _brief_expected_proof_count(brief) is not None:
        return True
    objectives = {str(item).strip().lower().replace("-", "_") for item in brief.objectives}
    if "capture_flag" in objectives:
        return True
    context = dict(brief.context or {})
    explicit_mode = context.get("flag_objective")
    if isinstance(explicit_mode, bool):
        return explicit_mode
    win_condition = str(context.get("win_condition") or "").strip().lower()
    if not win_condition or win_condition.startswith("todo:"):
        return False
    return bool(
        re.search(
            r"\b(?:capture|recover|submit)\b.{0,80}\b(?:flags?|proof strings?|target proofs?)\b",
            win_condition,
        )
    )


def _continue_after_proof_enabled(state: AgentState) -> bool:
    return state.surface.get("continue_after_proof") is True


def _has_open_assessment_tasks(state: AgentState) -> bool:
    return any(
        str(task.get("status") or "pending") in {"pending", "in_progress"} for task in state.tasks
    )


def _continue_after_proof_outcome(state: AgentState, outcome: ActionResult) -> ActionResult:
    if not _continue_after_proof_enabled(state):
        return outcome
    if not outcome.stop or outcome.outcome != "flag_candidate":
        return outcome
    return replace(outcome, stop=False)


def _stop_after_finding_outcome(state: AgentState, outcome: ActionResult) -> ActionResult:
    if (
        state.surface.get("stop_after_first_finding") is True
        and outcome.outcome == "finding_confirmed"
    ):
        return replace(outcome, stop=True)
    return outcome


def _make_tool_runtime(
    settings: AIWebAgentSettings,
    brief: EngagementBrief,
    *,
    target_url: str,
) -> ToolRuntime:
    if settings.traffic_policy_mode == "low-noise":
        return NoProcessToolRuntime(
            reason="whole-run low-noise traffic policy exposes native metered HTTP lanes only"
        )
    injected_runtime = settings.tool_runtime
    if injected_runtime is not None:
        return injected_runtime
    if settings.authentication is not None:
        return NoProcessToolRuntime(
            reason="managed authenticated sessions expose HTTP probes and PoC replay only"
        )
    network_evidence_path = os.environ.get("RAVAGE_TOOL_NETWORK_EVIDENCE_PATH")
    runtime_kwargs = {
        "image": settings.tool_image,
        "scope": brief.scope,
        "session_id": str(brief.engagement_id),
        "cleanup_evidence_path": network_evidence_path,
        "allow_remote_target": settings.allow_remote_target,
    }
    if settings.allow_remote_target and not is_local_url(target_url):
        return DockerToolRuntime(**runtime_kwargs)
    if settings.tool_runtime_mode in {"docker", "auto"}:
        return DockerToolRuntime(**runtime_kwargs)
    return ExternalToolRuntime()


def _open_run_traffic_policy(
    *,
    settings: AIWebAgentSettings,
    workspace: AgentWorkspace,
    target_url: str,
    roe_max_rps: float,
) -> TrafficPolicyController:
    if settings.traffic_policy_mode == "observe":
        if (
            settings.traffic_policy_max_physical_requests is not None
            or settings.traffic_policy_max_rps is not None
        ):
            raise ValueError("traffic policy limits require low-noise mode")
        config = TrafficPolicyConfig(mode=TrafficPolicyMode.OBSERVE)
    elif settings.traffic_policy_mode == "low-noise":
        request_limit = (
            settings.traffic_policy_max_physical_requests
            if settings.traffic_policy_max_physical_requests is not None
            else 300
        )
        requested_rps = (
            settings.traffic_policy_max_rps if settings.traffic_policy_max_rps is not None else 0.5
        )
        if isinstance(request_limit, bool) or request_limit <= 0:
            raise ValueError("traffic policy physical-request limit must be positive")
        if not math.isfinite(float(requested_rps)) or requested_rps <= 0 or requested_rps >= 1:
            raise ValueError("low-noise traffic max RPS must be greater than zero and below one")
        if not math.isfinite(float(roe_max_rps)) or roe_max_rps <= 0:
            raise ValueError("engagement max RPS must be positive and finite")
        config = TrafficPolicyConfig.low_noise(
            max_physical_requests=request_limit,
            max_rps=min(float(requested_rps), float(roe_max_rps)),
        )
    else:
        raise ValueError(f"unsupported traffic policy mode: {settings.traffic_policy_mode}")
    if settings.traffic_policy_config is not None:
        configured = settings.traffic_policy_config
        baseline = replace(
            configured,
            allowed_request_routes=(),
            allowed_query_fields=None,
            allowed_explicit_headers=None,
            allowed_form_fields=None,
            max_request_body_bytes=None,
            request_value_profile=None,
            require_public_addresses=False,
        )
        if baseline != config:
            raise TrafficPolicyError(
                "traffic policy configuration does not match agent settings"
            )
        config = configured
    if settings.traffic_policy_reference is not None:
        referenced = TrafficPolicyController.from_reference(
            settings.traffic_policy_reference,
            require_existing=True,
        )
        if referenced.config != config:
            raise TrafficPolicyError(
                "traffic policy reference configuration does not match agent settings"
            )
        return TrafficPolicyController.open(
            referenced.state_path,
            target_url=target_url,
            config=config,
            require_existing=True,
        )
    return TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url=target_url,
        config=config,
        require_existing=settings.resume_from is not None or workspace.state_path.is_file(),
    )


def _initial_state(
    settings: AIWebAgentSettings,
    workspace: AgentWorkspace,
) -> tuple[AgentState, bool]:
    resume_path = resolve_agent_state_path(
        settings.resume_from,
        workspace_state_path=workspace.state_path,
    )
    if settings.resume_from is not None and not resume_path.is_file():
        message = f"cannot resume attack: canonical agent state does not exist: {resume_path}"
        raise ValueError(message)
    restored = load_agent_state(resume_path)
    if settings.resume_from is not None and restored is None:
        message = f"cannot resume attack: invalid agent state: {resume_path}"
        raise ValueError(message)
    return restored or AgentState(), resume_path.is_file()


def _initial_recovery_campaign(
    *,
    settings: AIWebAgentSettings,
    state: AgentState,
    target_url: str,
    state_path: Path,
) -> RecoveryCampaign | None:
    if settings.recovery_profile == "off":
        return None
    if settings.recovery_profile != "recovery-v1":
        message = f"unsupported recovery profile: {settings.recovery_profile}"
        raise ValueError(message)
    if state.turn > 0 and not state_path.exists():
        message = "cannot enable recovery-v1 while resuming baseline state without recovery state"
        raise ValueError(message)
    campaign = RecoveryCampaign.load_or_create(
        state_path,
        target_url=target_url,
        max_model_requests=max(settings.max_turns, 1),
    )
    completed_turns = campaign.scheduler.total_model_requests
    if state.turn != completed_turns:
        message = (
            "agent and recovery state disagree on completed turns: "
            f"agent={state.turn} recovery={completed_turns}"
        )
        raise ValueError(message)
    return campaign


def _record_recovery_enabled(
    recovery: RecoveryCampaign,
    *,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
) -> None:
    payload = {
        "profile": "recovery-v1",
        "status": recovery.scheduler.status.value,
        "role": recovery.scheduler.role.value,
        "total_model_requests": recovery.scheduler.total_model_requests,
        "started_model_requests": recovery.started_model_requests,
        "config": recovery.scheduler.config.to_json(),
    }
    workspace.record_event(kind="recovery_profile_enabled", payload=payload)
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="recovery_profile_enabled",
        payload=payload,
    )


def _recovery_request_payload(recovery: RecoveryCampaign) -> dict[str, object]:
    return {
        "recovery_role": recovery.scheduler.role.value,
        "recovery_branch_id": recovery.scheduler.active_branch_id,
        "recovery_evidence_epoch": recovery.scheduler.evidence_epoch,
        "recovery_lease_budget": recovery.scheduler.lease_limit,
        "recovery_lease_used": recovery.scheduler.lease_used,
        "global_model_requests_used": recovery.scheduler.total_model_requests,
        "global_model_request_budget": recovery.scheduler.config.max_model_requests,
    }


def _execute_recovery_action(  # noqa: PLR0913 - mirrors the executor boundary.
    *,
    recovery: RecoveryCampaign,
    action: dict[str, object],
    target_url: str,
    runtime: ToolRuntime,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    repeat_count: int,
    proof_recognition_enabled: bool,
    action_id: str,
    authentication: ManagedAttackAuthentication | None,
    traffic_policy: TrafficPolicyController,
) -> tuple[ActionResult, bool]:
    specialist = recovery.scheduler.role is not RecoveryRole.CORE
    if specialist and action.get("action") == "final":
        handoff = recovery.create_handoff(action)
        payload = handoff.to_json()
        workspace.record_event(kind="recovery_branch_handoff", payload=payload)
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="recovery_branch_handoff",
            payload=payload,
        )
        return (
            ActionResult(
                ok=True,
                observation=handoff.summary,
                stop=False,
                outcome="recovery_handoff",
            ),
            True,
        )

    route_fingerprint = semantic_action_fingerprint(action)
    if not recovery.scheduler.route_is_available(route_fingerprint):
        payload = {
            "turn": state.turn,
            "branch_id": recovery.scheduler.active_branch_id,
            "role": recovery.scheduler.role.value,
            "route_fingerprint": route_fingerprint,
            "reason": "semantic_route_exhausted",
        }
        workspace.record_event(kind="recovery_route_blocked", payload=payload)
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="recovery_route_blocked",
            payload=payload,
        )
        return (
            ActionResult(
                ok=False,
                observation=(
                    "Recovery route exhausted in the current evidence epoch. Change the "
                    "vulnerability family, endpoint, input, identity, or payload class."
                ),
                outcome="same_as_before",
                repeat_count=repeat_count,
            ),
            False,
        )

    return (
        execute_action(
            action,
            target_url=target_url,
            runtime=runtime,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=repeat_count,
            max_observation_chars=MAX_OBSERVATION_CHARS,
            max_transcript_chars=MAX_TRANSCRIPT_CHARS,
            proof_recognition_enabled=proof_recognition_enabled,
            action_id=action_id,
            authentication=authentication,
            traffic_policy=traffic_policy,
        ),
        False,
    )


def _record_recovery_turn(
    turn_result: RecoveryTurnResult,
    *,
    turn: int,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
) -> None:
    _record_recovery_decision(
        turn_result.decision,
        turn=turn,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
        interrupted=False,
    )
    if turn_result.assessment.material_progress:
        payload = {
            "turn": turn,
            "evidence_epoch": turn_result.decision.evidence_epoch,
            "kinds": [kind.value for kind in turn_result.assessment.material_progress],
            "lead_fingerprints": [lead.fingerprint for lead in turn_result.assessment.leads],
            "source_trusted": turn_result.assessment.source_trusted,
        }
        workspace.record_event(kind="recovery_material_progress", payload=payload)
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="recovery_material_progress",
            payload=payload,
        )


def _record_recovery_decision(  # noqa: PLR0913 - mirrors durable decision fields.
    decision: RecoveryDecision,
    *,
    turn: int,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    interrupted: bool,
) -> None:
    payload = {
        "turn": turn,
        "interrupted_request": interrupted,
        "executed_role": decision.executed_role.value,
        "next_role": decision.next_role.value if decision.next_role else None,
        "status": decision.status.value,
        "reason": decision.reason,
        "total_model_requests": decision.total_model_requests,
        "remaining_model_requests": decision.remaining_model_requests,
        "remaining_exploration_requests": decision.remaining_exploration_requests,
        "proof_reserve_remaining": decision.proof_reserve_remaining,
        "evidence_epoch": decision.evidence_epoch,
        "material_progress": [kind.value for kind in decision.material_progress],
        "executed_branch_id": decision.executed_branch_id,
        "next_branch_id": decision.next_branch_id,
        "executed_lease_budget": decision.executed_lease_budget,
        "executed_lease_used": decision.executed_lease_used,
        "next_lease_budget": decision.next_lease_budget,
        "next_lease_used": decision.next_lease_used,
        "next_objective_fingerprint": decision.next_objective_fingerprint,
        "route_exhausted": decision.route_exhausted,
        "observation_watchdog_triggered": decision.observation_watchdog_triggered,
        "branch_handoff_triggered": decision.branch_handoff_triggered,
    }
    workspace.record_event(kind="recovery_turn_accounted", payload=payload)
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="recovery_turn_accounted",
        payload=payload,
    )
    branch_changed = decision.executed_branch_id != decision.next_branch_id
    if branch_changed and decision.next_branch_id:
        workspace.record_event(kind="recovery_branch_started", payload=payload)
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="recovery_branch_started",
            payload=payload,
        )
    if decision.status is not RecoveryStatus.RUNNING:
        workspace.record_event(kind="recovery_campaign_stopped", payload=payload)
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="recovery_campaign_stopped",
            payload=payload,
        )


def _seed_recon(
    *,
    target_url: str,
    description: str,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    allow_remote_target: bool,
    in_scope: Iterable[str],
    out_of_scope: Iterable[str],
    max_rps: int,
    flag_objective: bool,
    session_mode: str = "",
    authentication: ManagedAttackAuthentication | None = None,
    traffic_policy: TrafficPolicyController | None = None,
) -> None:
    try:
        recon = run_recon(
            target_url,
            max_pages=12,
            timeout_seconds=8,
            allow_remote_target=allow_remote_target,
            in_scope=tuple(in_scope),
            out_of_scope=tuple(out_of_scope),
            max_rps=max_rps,
            traffic_policy=traffic_policy,
        )
    except Exception as exc:  # noqa: BLE001 - recon is helpful, not a run gate.
        safe_error = (
            authentication.redact_text(str(exc)) if authentication is not None else str(exc)
        )
        error_payload: dict[str, object] = {"error": safe_error}
        if session_mode:
            error_payload["session_mode"] = session_mode
        error_payload = _authenticated_artifact_mapping(authentication, error_payload)
        _record(audit, engagement_id, actor="agent", action="recon_failed", payload=error_payload)
        workspace.record_event(kind="recon_failed", payload=error_payload)
        append_unique(state.facts, f"initial recon failed: {safe_error}", limit=80)
        return
    recon_payload: dict[str, object] = recon.to_json()
    if session_mode:
        recon_payload["session_mode"] = session_mode
    recon_payload = _authenticated_artifact_mapping(authentication, recon_payload)
    _record(audit, engagement_id, actor="agent", action="recon_completed", payload=recon_payload)
    workspace.record_event(kind="recon_completed", payload=recon_payload)
    merge_recon_state(state, recon_payload)
    safe_description = (
        authentication.redact_text(description) if authentication is not None else description
    )
    surface = surface_from_recon(
        target_url=target_url,
        description=safe_description,
        recon_payload=recon_payload,
    )
    if not state.surface_graph.target_origin:
        state.surface_graph = SurfaceGraphState.for_target(target_url)
    ingest_recon_surface(
        state.surface_graph,
        recon_payload,
        identity_alias="anonymous",
    )
    surface = project_surface_graph(state.surface_graph, surface)
    merge_surface_state(state, surface)
    graph_payload = {
        "schema_version": state.surface_graph.schema_version,
        "operations": len(state.surface_graph.operations or {}),
        "identity_observations": len(state.surface_graph.observations or {}),
        "sources": sorted(
            {
                source
                for operation in (state.surface_graph.operations or {}).values()
                for source in operation.provenance
            }
        ),
    }
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="surface_graph_updated",
        payload=graph_payload,
    )
    workspace.record_event(kind="surface_graph_updated", payload=graph_payload)
    state.surface["visible_description"] = safe_description
    state.surface["flag_objective"] = flag_objective
    if session_mode:
        state.surface["recon_session_mode"] = session_mode
    refresh_mission_board(state, description=safe_description, surface=state.surface)


def _seed_authenticated_surface(
    *,
    target_url: str,
    runtime: ToolRuntime,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    proof_recognition_enabled: bool,
    authentication: ManagedAttackAuthentication,
    traffic_policy: TrafficPolicyController,
) -> None:
    """Seed protected routes before the first model request, failing auth closed."""
    execute_action(
        {"action": "run_probe", "probe": "surface_map"},
        target_url=target_url,
        runtime=runtime,
        state=state,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
        repeat_count=1,
        max_observation_chars=MAX_OBSERVATION_CHARS,
        max_transcript_chars=MAX_TRANSCRIPT_CHARS,
        proof_recognition_enabled=proof_recognition_enabled,
        action_id="authenticated-seed-surface-map",
        authentication=authentication,
        traffic_policy=traffic_policy,
    )


def _authentication_session_mode(
    authentication: ManagedAttackAuthentication | None,
) -> str:
    if authentication is None:
        return ""
    return f"identity:{authentication.identity}"


def _assert_authenticated_state_identity(
    state: AgentState,
    *,
    authentication: ManagedAttackAuthentication | None,
    resumed: bool = True,
) -> None:
    restored_identity = str(state.surface.get("authenticated_identity") or "").strip()
    if not restored_identity:
        if resumed and authentication is not None:
            raise ValueError("cannot resume agent state without its authenticated identity binding")
        return
    if authentication is None:
        raise ValueError("cannot resume authenticated agent state without managed authentication")
    if restored_identity != authentication.identity:
        raise ValueError(
            "cannot resume authenticated agent state with a different identity: "
            f"state={restored_identity!r} requested={authentication.identity!r}"
        )


def _authenticated_artifact_mapping(
    authentication: ManagedAttackAuthentication | None,
    value: Mapping[str, object],
) -> dict[str, object]:
    safe: object = value
    if authentication is not None:
        safe = authentication.redact(value)
    if not isinstance(safe, Mapping):
        raise TypeError("authenticated redaction must preserve mapping values")
    payload = {str(key): item for key, item in safe.items()}
    if authentication is not None:
        payload.setdefault("session_mode", _authentication_session_mode(authentication))
    return payload


def _authenticated_model_action(
    authentication: ManagedAttackAuthentication,
    action: Mapping[str, object],
) -> dict[str, object]:
    """Preserve validated action vocabulary while strictly redacting model data."""
    probe_names = tuple(
        str(item.get("name") or "") for item in available_probes() if str(item.get("name") or "")
    )
    safe = authentication.redact_protocol(
        action,
        protected_keys={
            (): _AUTHENTICATED_ACTION_PROTOCOL_KEYS,
            ("finding",): _AUTHENTICATED_FINDING_KEYS,
            ("steps", "*"): _AUTHENTICATED_HTTP_STEP_KEYS,
            ("steps", "*", "form"): _AUTHENTICATED_HTTP_PARAMETER_KEYS,
            ("steps", "*", "json"): _AUTHENTICATED_HTTP_PARAMETER_KEYS,
        },
        protected_field_values={
            ("action",): tuple(sorted(VALID_ACTIONS)),
            ("finding", "evidence_role"): ("control", "exploit"),
            ("finding", "severity"): (
                "critical",
                "high",
                "informational",
                "low",
                "medium",
            ),
            ("finding", "vuln_class"): _AUTHENTICATED_FINDING_CLASSES,
            ("probe",): probe_names,
            ("steps", "*", "evidence_role"): ("control", "exploit"),
            ("steps", "*", "method"): _AUTHENTICATED_HTTP_METHODS,
        },
    )
    if not isinstance(safe, Mapping):
        raise TypeError("authenticated model-action redaction must preserve mappings")
    return {str(key): item for key, item in safe.items()}


def _assert_authenticated_state_artifacts_safe(
    state: AgentState,
    *,
    authentication: ManagedAttackAuthentication,
    state_label: str,
) -> None:
    """Reject restored state that would cross the strict artifact boundary."""
    _assert_authenticated_restored_artifacts_safe(
        state.to_json(),
        authentication=authentication,
        artifact_label=f"{state_label} state",
    )


def _assert_authenticated_restored_artifacts_safe(
    value: object,
    *,
    authentication: ManagedAttackAuthentication,
    artifact_label: str,
) -> None:
    """Fail closed before restored prompt-bearing values cross a trust boundary."""
    if _authenticated_state_value_is_tainted(
        value,
        authentication=authentication,
    ):
        raise ValueError(
            f"cannot resume authenticated {artifact_label} containing untrusted "
            "authentication material"
        )


def _authenticated_state_value_is_tainted(
    value: object,
    *,
    authentication: ManagedAttackAuthentication,
    key: str = "",
) -> bool:
    if key in {"authenticated_identity", "identity", "identity_alias"} and (
        value == authentication.identity
    ):
        return False
    if key == "session_mode" and value in {
        f"identity:{authentication.identity}",
        "anonymous:baseline",
        "anonymous:probe-required",
    }:
        return False
    if isinstance(value, str):
        return authentication.contains_secret(value) or authentication.redact_text(value) != value
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
        return authentication.contains_secret(text) or authentication.redact_text(text) != text
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            item_key = str(raw_key)
            if _authenticated_state_value_is_tainted(
                item,
                authentication=authentication,
                key=item_key,
            ):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(
            _authenticated_state_value_is_tainted(item, authentication=authentication)
            for item in value
        )
    return False


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
    missing = _missing_model_env_vars(routes)
    message = "no ready model route"
    if missing:
        message += f"; missing env: {', '.join(missing)}"
    missing_pricing = _missing_model_pricing_fields(routes)
    if missing_pricing:
        message += f"; missing pricing: {', '.join(missing_pricing)}"
    transport_issues = sorted(
        {route.transport_issue for route in routes if route.transport_issue is not None}
    )
    if transport_issues:
        message += f"; transport issues: {', '.join(transport_issues)}"
    raise RuntimeError(message)


def _write_report_if_requested(  # noqa: PLR0913
    *,
    brief_path: Path,
    target_url: str,
    settings: AIWebAgentSettings,
    workspace: AgentWorkspace,
    state: AgentState,
    error: BaseException | None,
    termination_reason: str | None,
) -> None:
    if settings.report_path is None and not settings.report_agent:
        return
    output_path = settings.report_path or workspace.root.parent / "report.md"
    status = _report_status(
        state=state,
        settings=settings,
        error=error,
        termination_reason=termination_reason,
    )
    error_detail = _authenticated_error_detail(error, settings=settings)
    write_pentest_report(
        brief_path=brief_path,
        target_url=target_url,
        workspace_dir=workspace.root,
        output_path=output_path,
        status=status,
        completed=error is None and status == "completed",
        audit_db_path=settings.db_path or workspace.root / "audit.db",
        error=error_detail,
    )


def _authenticated_error_detail(
    error: BaseException | None,
    *,
    settings: AIWebAgentSettings,
) -> str | None:
    if error is None:
        return None
    rendered = f"{type(error).__name__}: {error}"
    authentication = settings.authentication
    if authentication is None:
        return rendered
    if authentication.contains_secret(rendered):
        return f"{type(error).__name__}: [REDACTED]"
    return authentication.redact_text(rendered)


def _report_status(
    *,
    state: AgentState,
    settings: AIWebAgentSettings,
    error: BaseException | None,
    termination_reason: str | None = None,
) -> str:
    if error is not None:
        return "interrupted" if isinstance(error, KeyboardInterrupt) else "error"
    if termination_reason in {
        "max_turns_reached",
        "cost_budget_exhausted",
        "required_proof_count_unmet",
    }:
        return "incomplete"
    if (
        state.surface.get("flag_objective") is not False
        and not _proof_objective_completion_met(state, settings=settings)
    ):
        return "incomplete"
    if state.flags:
        return "completed"
    if state.turn >= max(settings.max_turns, 1):
        return "incomplete"
    return "completed"


def _missing_model_env_vars(routes: Iterable[ResolvedModelRoute]) -> list[str]:
    missing: set[str] = set()
    for route in routes:
        for name in route.missing_env:
            missing.add(name)
    return sorted(missing)


def _missing_model_pricing_fields(routes: Iterable[ResolvedModelRoute]) -> list[str]:
    missing: set[str] = set()
    for route in routes:
        missing.update(route.missing_pricing)
    return sorted(missing)


def _build_messages(
    *,
    brief: EngagementBrief,
    brief_path: Path,
    target_url: str,
    state: AgentState,
    settings: AIWebAgentSettings,
    route: ResolvedModelRoute,
    knowledge_cards: list[KnowledgeCard] | None = None,
    knowledge_pack_metadata: dict[str, object] | None = None,
    recovery_context: Mapping[str, object] | None = None,
    traffic_budget: Mapping[str, object] | None = None,
) -> list[dict[str, str]]:
    context = _safe_runtime_context(brief.context or {}, brief_path=brief_path)
    continue_after_proof = _continue_after_proof_enabled(state)
    flag_objective = _brief_has_flag_objective(brief)
    strategies = ranked_strategy_cards(
        description=str(context.get("description") or ""),
        state=state,
    )
    low_noise = settings.traffic_policy_mode == "low-noise"
    probe_catalog = available_probes()
    specialist_catalog = available_specialists()
    recommended_catalog = recommended_specialists(state, limit=6)
    if low_noise:
        probe_catalog = [
            item
            for item in probe_catalog
            if not probe_requires_external_process(str(item.get("name") or ""))
        ]
        specialist_catalog = [
            item
            for item in specialist_catalog
            if not probe_requires_external_process(str(item.get("probe") or ""))
        ]
        recommended_catalog = [
            item
            for item in recommended_catalog
            if not probe_requires_external_process(str(item.get("probe") or ""))
        ]
    target_kind = (
        "an explicitly authorized remote target"
        if settings.allow_remote_target and not is_local_url(target_url)
        else "an authorized local benchmark target"
    )
    if flag_objective:
        completion_goal = (
            "preserve each target proof and continue until the remaining assessment branches "
            "are exhausted"
            if continue_after_proof
            else "continue until the target proof is captured"
        )
        objective = (
            "assess distinct vulnerability paths, capture every target proof found, and "
            "continue across untested branches"
            if continue_after_proof
            else "find and exploit the vulnerability path, then capture the final target proof string"
        )
    else:
        completion_goal = (
            "validate promising signals, record evidence-backed vulnerability findings, and "
            "finish when the in-scope assessment branches are exhausted"
        )
        objective = (
            "assess the authorized application and record each replayable vulnerability; "
            "no flag is required and do not spend turns searching for one"
        )
    if low_noise:
        execution_loop = "run one useful native metered HTTP probe or PoC replay"
        execution_boundary = (
            "The whole-run low-noise policy permits native metered HTTP lanes only; "
            "opaque command, Python, browser-process, and external-process actions are unavailable."
        )
    elif settings.authentication is None:
        execution_loop = "run one useful command or Python script"
        execution_boundary = "Use the available tools directly."
    else:
        execution_loop = "run one useful managed HTTP probe or managed PoC replay"
        execution_boundary = (
            "Use only the managed probe and PoC request lanes; raw shell and Python "
            "execution cannot receive authenticated credentials."
        )
    system = (
        "You are Ravage, an autonomous web exploitation agent running only against "
        f"{target_kind}. You do not receive vulnerability tags. "
        "Infer from the description and live evidence. Keep a disciplined loop: observe, "
        f"form hypotheses, {execution_loop}, update memory, and "
        f"{completion_goal}. Do not call canned drivers, route by tags, "
        f"or assume the answer key. {execution_boundary}"
    )
    user: dict[str, object] = {
        "target_url": target_url,
        "scope": {
            "in_scope": brief.scope.in_scope,
            "out_of_scope": brief.scope.out_of_scope,
        },
        "scoped_service_ports": _scoped_service_ports(brief.scope.in_scope, target_url=target_url),
        "objective": objective,
        "rules": context.get("rules", []),
        "description": context.get("description", ""),
        "win_condition": context.get("win_condition", ""),
        "working_state": build_planner_memory(state),
        "methodology": methodology_context(state),
        "active_tasks": active_tasks_for_prompt(state, limit=8),
        "execution_recipes": recipes_for_active_tasks(state, limit=6),
        "available_probes": probe_catalog,
        "available_specialists": specialist_catalog,
        "recommended_specialists": recommended_catalog,
        "confirmed_primitives": dict(state.primitives),
        "locked_primitive": locked_primitive(state),
        "active_strategy_cards": strategies,
        "planner_directives": planner_directives(state),
        "memory_hints": _memory_hints_for_prompt(settings, route=route),
        "action_schema": {
            "run_probe": {
                "action": "run_probe",
                "task_id": "one active_tasks id",
                "probe": "one available_probes name",
                "timeout_seconds": 10,
                "strategy": "one active_strategy_cards name or a new evidence-derived strategy",
                "notes": "what this will test",
                "expected_signal": "the observation that would make this step useful",
                "fallback": "what to try next if this fails",
                "hypotheses": ["candidate vulnerabilities or workflows inferred from evidence"],
                "memory_updates": ["short facts learned or hypotheses"],
            },
            "run_command": {
                "action": "run_command",
                "task_id": "one active_tasks id",
                "command": "single shell command string",
                "timeout_seconds": 1,
                "strategy": "one active_strategy_cards name or a new evidence-derived strategy",
                "notes": "what this will test",
                "expected_signal": "the observation that would make this step useful",
                "fallback": "what to try next if this fails",
                "hypotheses": ["candidate vulnerabilities or workflows inferred from evidence"],
                "memory_updates": ["short facts learned or hypotheses"],
            },
            "run_python": {
                "action": "run_python",
                "task_id": "one active_tasks id",
                "code": "python code to execute",
                "timeout_seconds": 1,
                "strategy": "one active_strategy_cards name or a new evidence-derived strategy",
                "notes": "what this will test",
                "expected_signal": "the observation that would make this step useful",
                "fallback": "what to try next if this fails",
                "hypotheses": ["candidate vulnerabilities or workflows inferred from evidence"],
                "memory_updates": ["short facts learned or hypotheses"],
            },
            "validate_poc": {
                "action": "validate_poc",
                "task_id": "active task that produced the signal",
                "steps": [
                    {
                        "evidence_role": "control",
                        "method": "same GET or POST method as exploit",
                        "url": "same-origin URL or path used by exploit",
                        "form": {"field": "benign control value"},
                        "body": "optional raw request body",
                        "headers": {"content-type": "application/json"},
                        "expect_status": 200,
                        "expect_contains": "stable control response evidence",
                    },
                    {
                        "evidence_role": "exploit",
                        "method": "same GET or POST method as control",
                        "url": "same-origin URL or path used by control",
                        "form": {"field": "security test value with the same input shape"},
                        "body": "optional raw request body with the same shape",
                        "headers": {"content-type": "application/json"},
                        "expect_status": 200,
                        "expect_contains": "class-specific security-relevant differential",
                    },
                ],
                "timeout_seconds": 10,
                "strategy": "differential_replay",
                "notes": "what class-specific differential this validates",
                "expected_signal": "security-relevant control/exploit response differential",
                "fallback": "what to vary if replay fails",
                "memory_updates": ["short facts learned"],
                "finding": {
                    "vuln_class": (
                        "sql_injection, ssti, server_side_template_injection, "
                        "template_injection, path_traversal, lfi, local_file_inclusion, "
                        "arbitrary_file_read, or file_read"
                    ),
                    "severity": "critical, high, medium, low, or informational",
                    "hypothesis": "concise evidence-backed vulnerability statement",
                    "impact": "bounded security impact supported by the replay",
                    "exploit_steps": ["concise operator-readable replay step"],
                },
            },
            "capture_flag": {
                "action": "capture_flag",
                "task_id": "active task that produced the proof, if known",
                "flag": "exact proof string captured from the target",
                "evidence": "where it appeared",
                "memory_updates": ["short facts learned"],
            },
            "final": {
                "action": "final",
                "summary": "why no further progress is possible or final result",
                "memory_updates": ["short facts learned"],
            },
        },
        "tool_guidance": [
            "Return exactly one JSON object and no markdown.",
            "Derive hypotheses from the description and observations; never rely on hidden labels.",
            "Use active strategy cards as checklists, not as answer keys.",
            "Choose exactly one active task and include its task_id in every non-final action.",
            "Do not repeat an action from repetition_ledger unless you change a material variable.",
            "If recommended_specialists is non-empty, pick the highest-scored specialist with run_probe before writing an equivalent run_command/run_python loop.",
            "If locked_primitive is set, you have already confirmed an exploitable primitive: run its locked run_probe specialist (top of recommended_specialists) and drive it to validated target evidence. Do not run recon/surface probes or switch to an unrelated vulnerability class until that primitive is exploited or genuinely exhausted.",
            "After a specialist returns same_as_before, either change a material endpoint/parameter/payload family or move to the next specialist; do not reimplement the same probe by hand.",
            "Use run_command or run_python only for custom follow-up, exploitation logic, or payload adaptation not covered by an available probe.",
            "Do not spend more than two consecutive run_command/run_python turns while a matching run_probe specialist remains untried.",
            "Use validate_poc after a promising signal to replay the shortest stable HTTP evidence.",
            (
                "To confirm a finding, validate_poc must contain paired control and exploit "
                "steps labeled with evidence_role, using the same endpoint, method, headers, "
                "and input shape. Explicit expectations must prove a security-relevant "
                "differential for that vulnerability class. Ravage derives the endpoint, "
                "proof, and provenance from the replay; never provide those fields yourself."
            ),
            (
                "Only class-specific evidence can confirm a vulnerability. Unsupported claims "
                "remain candidates. HTTP validate_poc supports sql_injection; ssti and its "
                "server_side_template_injection/template_injection aliases; and path_traversal "
                "with lfi, local_file_inclusion, arbitrary_file_read, and file_read aliases. "
                "SQL injection requires injection-shaped input plus a new SQL error; SSTI "
                "requires a template expression plus a computed marker absent from control; "
                "path traversal requires traversal input plus a known file-content marker "
                "absent from control. IDOR, authorization, SSRF, and other classes require a "
                "trusted typed validator. Plain reflection cannot confirm XSS; XSS confirmation "
                "requires dom_execution browser evidence."
            ),
            "Prefer curl and Python stdlib urllib. Do not assume requests is installed.",
            "For payloads containing quotes, use Python urllib.parse.urlencode rather than fragile nested shell quoting.",
            "Use $RAVAGE_TARGET_URL or the explicit target URL.",
            "Inside run_command/run_python, prefer $RAVAGE_TARGET_URL; localhost URLs copied from observations may be host-side ports that are not reachable inside the tool container.",
            "Use every in_scope origin and TCP port as part of the authorized target. Extra scoped ports may be raw TCP services even when represented as URLs for scoping.",
            "For host-side run_command/run_python, connect to scoped_service_ports.host_endpoint. Only Docker/tool-image code should use scoped_service_ports.docker_endpoint. Preserve the scoped external port; do not replace it with an internal service port from source unless that internal port is also scoped.",
            "If source, config, logs, or pages reveal SSH credentials, try them against scoped non-HTTP ports with paramiko or ssh -p <port>; do not default to localhost:22 unless port 22 is explicitly in scope.",
            "For Paramiko or other Python-library workflows, prefer run_python over run_command python3 so missing modules can fall back to the tool image.",
            "If Python reports any form of 'No module named ...', treat that as a tool-environment failure to work around, not as target evidence or a completed attempt.",
            "If source says an in-container client connects to localhost:22 and scope contains an auxiliary localhost:<port>, map that internal service to the auxiliary scoped port from scoped_service_ports.",
            "If a scoped localhost auxiliary port must be reached from Docker/tool-image Python, use scoped_service_ports.docker_endpoint instead of localhost.",
            "For password SSH without Paramiko/sshpass, use expect with the exact extracted password; never substitute the username, a default, or a redacted placeholder.",
            "When running SSH commands through Paramiko, keep exec_command payloads simple or build them with Python strings/shlex.quote; avoid nested sh -lc quoting that mixes single and double quotes.",
            "Persist cookies and scripts in the tool working directory.",
            "Inspect full response bodies, headers, cookies, redirects, forms, links, and errors.",
        ],
    }
    if traffic_budget is not None:
        user["traffic_budget"] = dict(traffic_budget)
    action_schema = user["action_schema"]
    tool_guidance = user["tool_guidance"]
    if flag_objective:
        if isinstance(tool_guidance, list):
            tool_guidance.extend(
                [
                    "After valid shell/SSH/command execution, preserve exact case from source/config filenames and close proof reads before more recon.",
                    "For shell proof closure, combine case-insensitive discovery such as find $HOME /tmp /app /var/www -maxdepth 4 -type f -iname '*flag*' -o -iname '*proof*' with exact reads of $HOME/FLAG.txt, $HOME/flag.txt, /FLAG.txt, /flag.txt, /tmp/FLAG.txt, /app/FLAG.txt, /var/www/html/FLAG.txt, /root/FLAG.txt, and lowercase variants.",
                    "When exploitation reveals the final target proof string, immediately use capture_flag.",
                    "Use capture_flag only with a recognizable proof string copied from target output; never submit guesses, repeated braces, placeholders, paths, credentials, or parser canaries.",
                ]
            )
    else:
        if isinstance(action_schema, dict):
            action_schema.pop("capture_flag", None)
        tool_guidance = user["tool_guidance"]
        if isinstance(tool_guidance, list):
            tool_guidance.append(
                "No flag is required for this assessment. Do not spend turns searching for "
                "one; record evidence-backed vulnerabilities directly."
            )
    if low_noise:
        if isinstance(action_schema, dict):
            action_schema.pop("run_command", None)
            action_schema.pop("run_python", None)
        if isinstance(tool_guidance, list):
            tool_guidance[:] = [
                item for item in tool_guidance if not _authenticated_external_guidance(str(item))
            ]
            tool_guidance.append(
                "Whole-run low-noise mode permits run_probe and validate_poc only through "
                "native metered HTTP transports; do not propose opaque process or browser lanes."
            )
    if settings.allow_remote_target and not is_local_url(target_url):
        tool_guidance = user["tool_guidance"]
        if isinstance(tool_guidance, list):
            tool_guidance.append(
                "The remote target was explicitly authorized by the operator and is listed "
                "in the engagement brief; proceed autonomously within that exact scope."
            )
            if not low_noise and settings.authentication is None:
                tool_guidance.append(
                    "Remote shell, Python, and scanner actions run in a Docker network whose "
                    "only target egress is the brief's scoped host and ports."
                )
            tool_guidance.append(
                "Never add hosts, origins, or ports that are absent from scope.in_scope, "
                "even when target content links to them."
            )
    if flag_objective and continue_after_proof:
        tool_guidance = user["tool_guidance"]
        if isinstance(tool_guidance, list):
            tool_guidance.extend(
                [
                    "This brief requires multiple findings: capture_flag closes only the current branch and does not end the assessment.",
                    "After each captured proof, choose a distinct open task or vulnerability family and continue until the remaining branches are done, blocked, or genuinely exhausted.",
                ]
            )
    if knowledge_pack_metadata:
        prompt_metadata = {
            str(key): value for key, value in knowledge_pack_metadata.items() if str(key) != "path"
        }
        user["external_knowledge_pack"] = {
            "metadata": prompt_metadata,
            "cards": [card.to_json() for card in knowledge_cards or []],
        }
        tool_guidance = user["tool_guidance"]
        if isinstance(tool_guidance, list):
            confirmation_rules = (
                "capture_flag rules" if flag_objective else "finding confirmation rules"
            )
            tool_guidance.append(
                "Use external knowledge cards only to prioritize Ravage probes and "
                "payload families; "
                "they are not proof and never override scope, evidence gates, or "
                f"{confirmation_rules}."
            )
            tool_guidance.append(
                "A knowledge card cannot filter a native probe's fixed payload, file, "
                "command, or destination candidates. Run a mapped probe only when its "
                "complete native behavior is authorized by the engagement and TrafficPolicy."
            )
    if recovery_context is not None:
        system += (
            " You are now a sequential recovery specialist with a fresh bounded role. "
            "The recovery assignment is authoritative for focus and lease limits; inherited "
            "working state is context, not proof. Return control with final when the delegated "
            "objective is exhausted."
        )
        _focus_recovery_prompt(user, recovery_context=recovery_context)
    if settings.authentication is not None:
        _focus_authenticated_prompt(user, authentication=settings.authentication)
        system = settings.authentication.redact_prompt_text(system)
        safe_user = settings.authentication.redact_prompt(user)
        if not isinstance(safe_user, Mapping):
            raise TypeError("authenticated prompt redaction must preserve mapping values")
        user = {str(key): item for key, item in safe_user.items()}
        user.setdefault("session_mode", _authentication_session_mode(settings.authentication))
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, indent=2, sort_keys=True)},
    ]


def _focus_authenticated_prompt(  # noqa: C901, PLR0912 - prompt policy is explicit.
    user: dict[str, object],
    *,
    authentication: ManagedAttackAuthentication,
) -> None:
    """Expose only credential-safe action contracts to an authenticated model turn."""
    unavailable_catalog = authenticated_unavailable_probes()
    unavailable_names = frozenset(unavailable_catalog)
    action_schema = user.get("action_schema")
    if isinstance(action_schema, dict):
        action_schema.pop("run_command", None)
        action_schema.pop("run_python", None)

    guidance = user.get("tool_guidance")
    if isinstance(guidance, list):
        safe_guidance: list[object] = []
        for item in guidance:
            rewritten = _rewrite_authenticated_tool_guidance(item)
            if _authenticated_external_guidance(str(rewritten)):
                continue
            if _mentions_authenticated_unavailable_probe(rewritten, unavailable_names):
                continue
            safe_guidance.append(rewritten)
        guidance[:] = safe_guidance
        guidance.extend(
            [
                (
                    "Use run_probe for authenticated discovery and specialist execution; "
                    "the executor owns login, cookies, refresh, scope, and rate limits."
                ),
                (
                    "Use validate_poc for the shortest stable authenticated HTTP "
                    "control/exploit replay."
                ),
                (
                    "Never provide Authorization, Cookie, proxy-auth, API-key, or other "
                    "managed authentication headers in an action."
                ),
                (
                    "Authentication material is executor-owned and unavailable to "
                    "model-authored code or external tools."
                ),
            ]
        )
    methodology = user.get("methodology")
    if isinstance(methodology, dict):
        _focus_authenticated_methodology(methodology)

    for key in (
        "active_tasks",
        "execution_recipes",
        "active_strategy_cards",
    ):
        items = user.get(key)
        if isinstance(items, list):
            items[:] = _prune_authenticated_prompt_items(
                items,
                unavailable_names=unavailable_names,
            )

    directives = user.get("planner_directives")
    if isinstance(directives, list):
        directives[:] = _authenticated_planner_directives(
            directives,
            unavailable_names=unavailable_names,
        )

    external_pack = user.get("external_knowledge_pack")
    if isinstance(external_pack, dict):
        cards = external_pack.get("cards")
        if isinstance(cards, list):
            cards[:] = _prune_authenticated_prompt_items(
                cards,
                unavailable_names=unavailable_names,
            )

    locked_name = str(user.get("locked_primitive") or "").strip()
    locked_rule = primitive_rule(locked_name) if locked_name else None
    if locked_rule is not None and locked_rule.probe in unavailable_names:
        user["locked_primitive"] = None
        user["unavailable_locked_primitive"] = {
            "name": locked_name,
            "probe": locked_rule.probe,
            "reason": unavailable_catalog[locked_rule.probe],
        }

    probes = user.get("available_probes")
    unavailable_authenticated_probes = sorted(unavailable_catalog)
    if isinstance(probes, list):
        probes[:] = [
            probe
            for probe in probes
            if not (
                isinstance(probe, dict)
                and authenticated_probe_unavailability(str(probe.get("name") or ""))
            )
        ]
        for probe in probes:
            if not isinstance(probe, dict):
                continue
            name = str(probe.get("name") or "")
            probe["session_mode"] = (
                "anonymous:probe-required"
                if probe_requires_anonymous_session(name)
                else _authentication_session_mode(authentication)
            )

    for key in ("available_specialists", "recommended_specialists"):
        specialists = user.get(key)
        if isinstance(specialists, list):
            specialists[:] = [
                specialist
                for specialist in specialists
                if not (
                    isinstance(specialist, dict)
                    and authenticated_probe_unavailability(str(specialist.get("probe") or ""))
                )
            ]
    user["unavailable_authenticated_probes"] = [
        {
            "name": name,
            "reason": unavailable_catalog[name],
        }
        for name in unavailable_authenticated_probes
    ]

    schema_actions = list(action_schema) if isinstance(action_schema, dict) else []
    managed_http_actions = [
        name for name in ("run_probe", "validate_poc") if name in schema_actions
    ]
    user["managed_http_identity"] = {
        "mode": _authentication_session_mode(authentication),
        "identity_alias": authentication.identity,
        "request_lane": "managed_http",
        "managed_http_actions": managed_http_actions,
        "control_actions": [name for name in schema_actions if name not in managed_http_actions],
    }


_PRUNED_AUTHENTICATED_PROMPT_VALUE = object()


def _rewrite_authenticated_tool_guidance(value: object) -> object:
    if not isinstance(value, str):
        return value
    return value.replace(
        (
            "Plain reflection cannot confirm XSS; XSS confirmation requires "
            "dom_execution browser evidence."
        ),
        (
            "Plain reflection cannot confirm XSS in managed authenticated mode; keep it "
            "as a candidate unless an eligible trusted validator supplies execution evidence."
        ),
    )


def _focus_authenticated_methodology(methodology: dict[str, object]) -> None:
    """Replace process-oriented methodology with executable managed-HTTP guidance."""
    methodology["loop"] = [
        "Observe: gather one new fact from target responses or prior output.",
        "Orient: connect that fact to an active task and hypothesis.",
        "Act: run one eligible managed in-process probe or structured validate_poc replay.",
        (
            "Review: record whether the result was new surface, a candidate signal, "
            "blocked, or confirmed evidence."
        ),
    ]
    methodology["tool_use"] = [
        "Use run_probe for scoped authenticated discovery and specialist workflows.",
        "Use validate_poc for short same-origin HTTP control/exploit comparisons.",
        "Let the managed executor own cookies, authentication headers, refresh, pacing, and scope.",
        "Never place credentials or managed authentication headers in model-authored actions.",
    ]
    raw_fallbacks = methodology.get("fallback_ladders")
    safe_fallbacks: list[object] = []
    if isinstance(raw_fallbacks, list):
        safe_fallbacks = [
            item
            for item in raw_fallbacks
            if not _authenticated_external_guidance(str(item))
            and "if commands repeat" not in str(item).casefold()
        ]
    methodology["fallback_ladders"] = [
        (
            "If managed results repeat or remain unchanged, vary the endpoint, parameter, "
            "method, encoding, or eligible specialist."
        ),
        (
            "If no eligible specialist covers a promising HTTP signal, use validate_poc "
            "for the smallest stable control/exploit comparison."
        ),
        *safe_fallbacks,
    ]


def _prune_authenticated_prompt_items(
    items: list[object],
    *,
    unavailable_names: frozenset[str],
) -> list[object]:
    pruned: list[object] = []
    for item in items:
        safe = _prune_authenticated_prompt_value(
            item,
            unavailable_names=unavailable_names,
        )
        if safe is not _PRUNED_AUTHENTICATED_PROMPT_VALUE:
            pruned.append(safe)
    return pruned


def _prune_authenticated_prompt_value(  # noqa: PLR0911 - recursive JSON type cases.
    value: object,
    *,
    unavailable_names: frozenset[str],
) -> object:
    if isinstance(value, str):
        if _mentions_authenticated_unavailable_probe(value, unavailable_names):
            return _PRUNED_AUTHENTICATED_PROMPT_VALUE
        if _authenticated_external_guidance(value):
            return _PRUNED_AUTHENTICATED_PROMPT_VALUE
        return value
    if isinstance(value, list):
        return _prune_authenticated_prompt_items(
            value,
            unavailable_names=unavailable_names,
        )
    if isinstance(value, Mapping):
        if _mapping_selects_unavailable_authenticated_probe(value, unavailable_names):
            return _PRUNED_AUTHENTICATED_PROMPT_VALUE
        safe_mapping: dict[str, object] = {}
        for key, item in value.items():
            safe = _prune_authenticated_prompt_value(
                item,
                unavailable_names=unavailable_names,
            )
            if safe is not _PRUNED_AUTHENTICATED_PROMPT_VALUE:
                safe_mapping[str(key)] = safe
        return safe_mapping
    return value


def _mapping_selects_unavailable_authenticated_probe(
    value: Mapping[object, object],
    unavailable_names: frozenset[str],
) -> bool:
    canonical_unavailable = {
        name.casefold().replace("-", "_").replace(" ", "_") for name in unavailable_names
    }
    for key in ("id", "name", "probe"):
        selected = str(value.get(key) or "").casefold().replace("-", "_").replace(" ", "_")
        if selected in canonical_unavailable:
            return True
    return False


def _authenticated_planner_directives(
    directives: list[object],
    *,
    unavailable_names: frozenset[str],
) -> list[object]:
    safe: list[object] = []
    for directive in directives:
        text = str(directive)
        if _authenticated_external_guidance(text):
            continue
        if not _mentions_authenticated_unavailable_probe(text, unavailable_names):
            safe.append(directive)
            continue
        viable_probes = [
            name
            for name in re.findall(r"\brun_probe\s+([a-z][a-z0-9_]*)", text.casefold())
            if name not in unavailable_names
        ]
        if viable_probes:
            safe.append(
                "Continue this evidence path with an available managed specialist: "
                + ", ".join(f"run_probe {name}" for name in dict.fromkeys(viable_probes))
                + "."
            )
    return safe


def _mentions_authenticated_unavailable_probe(
    value: object,
    unavailable_names: frozenset[str],
) -> bool:
    if isinstance(value, str):
        text = value.casefold()
    else:
        try:
            text = json.dumps(value, sort_keys=True, default=str).casefold()
        except (TypeError, ValueError):
            text = str(value).casefold()
    return any(
        marker in text
        for name in unavailable_names
        for marker in (name, name.replace("_", " "), name.replace("_", "-"))
    )


def _authenticated_external_guidance(value: str) -> bool:
    lowered = value.casefold()
    return any(
        marker in lowered
        for marker in (
            "run_command",
            "run_python",
            "curl",
            "python",
            "shell",
            "ssh",
            "docker",
            "paramiko",
            "sshpass",
            "$ravage_target_url",
            "tool container",
            "tool image",
            "tool-image",
            "terminal",
            "persist cookies",
        )
    )


def _focus_recovery_prompt(
    user: dict[str, object],
    *,
    recovery_context: Mapping[str, object],
) -> None:
    assignment = dict(recovery_context)
    user["recovery_assignment"] = assignment
    objective = assignment.get("objective")
    objective_payload = dict(objective) if isinstance(objective, dict) else {}
    instruction = str(objective_payload.get("instruction") or "").strip()
    if instruction:
        user["objective"] = instruction
    task_id = str(objective_payload.get("task_id") or "").strip()
    probe = str(objective_payload.get("probe") or "").strip()
    user["planner_directives"] = [
        "The recovery_assignment is the only active strategic objective for this branch.",
        "Use inherited state only to recover exact target-derived request details.",
        "Stay depth-first on the delegated route until target evidence proves or falsifies it.",
        "After two low-value uses, change a material route dimension or hand control back.",
        f"Use task_id {task_id} for branch actions." if task_id else "Keep one focused task.",
    ]
    recommendations = user.get("recommended_specialists")
    cards = (
        [dict(item) for item in recommendations if isinstance(item, dict)]
        if isinstance(recommendations, list)
        else []
    )
    focused = [item for item in cards if str(item.get("probe") or "") == probe]
    if not focused and probe:
        focused = [
            dict(item) for item in available_specialists() if str(item.get("probe") or "") == probe
        ]
    user["recommended_specialists"] = focused + [
        item for item in cards if str(item.get("probe") or "") != probe
    ]
    guidance = user.get("tool_guidance")
    if isinstance(guidance, list):
        guidance[:0] = [
            "Execute the recovery assignment before broad campaign work.",
            (
                "Use the delegated probe first unless trusted evidence requires an exact "
                "custom replay or payload adaptation."
            ),
            "A final action hands control to the parent and cannot declare proof.",
        ]


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
                role=str(message.get("role") or ""), content=str(message.get("content") or "")
            )
            for message in messages
        ]
        return _require_model_reply(complete(messages=chat_messages, route=route))

    chat = getattr(client, "chat", None)
    if callable(chat):
        return _require_model_reply(chat(messages))

    raise TypeError("model client must define complete(...) or chat(...)")


def _require_model_reply(value: object) -> ModelReply:
    if isinstance(value, ModelReply):
        return value
    message = "model client complete(...) or chat(...) must return ModelReply"
    raise TypeError(message)


def _require_accountable_paid_reply(
    *,
    route: ResolvedModelRoute,
    reply: ModelReply,
) -> None:
    if route_is_nonbillable_local(route) or reply.cost_known:
        return
    message = (
        "paid model response cannot be cost-accounted: "
        f"provider={route.provider} model={route.model} "
        f"usage_reported={reply.usage_reported} cost_known={reply.cost_known}"
    )
    raise RuntimeError(message)

def route_has_paid_transport_risk(route: ResolvedModelRoute) -> bool:
    if route_is_nonbillable_local(route):
        return False
    if route.api_key_env is not None:
        return True
    if route.input_cost_per_1m_tokens is not None or route.output_cost_per_1m_tokens is not None:
        return True
    return route.provider not in {"custom_openai", "litellm"}


def _memory_hints_for_prompt(
    settings: AIWebAgentSettings,
    *,
    route: ResolvedModelRoute,
) -> dict[str, object]:
    memory_settings = settings.memory
    if memory_settings is None:
        return {}
    if str(getattr(memory_settings, "mode", "off")) not in {"read", "learn"}:
        return {}
    db_path = getattr(memory_settings, "db_path", None)
    if db_path is None:
        return {}

    from ravage.memory import MemoryStore  # Local import keeps the core agent dependency light.

    store = MemoryStore(Path(db_path))
    try:
        hints = store.retrieve_hints(
            target_fingerprint={},
            min_confidence=float(getattr(memory_settings, "min_confidence", 0.0)),
        )
        for hint in hints:
            store.record_usage(
                memory_id=hint.item.memory_id,
                run_id="agent-run",
                phase="retrieval",
                status="injected",
                consumer_profile=settings.model_profile,
                consumer_tier=route.selected_tier,
                consumer_provider=route.provider,
                consumer_model=route.model,
            )
        return {
            "label": "MEMORY_HINTS",
            "items": [
                {
                    "memory_id": hint.item.memory_id,
                    "type": hint.item.type,
                    "summary": hint.item.summary,
                    "recommended_actions": hint.item.recommended_actions or [],
                }
                for hint in hints
            ],
        }
    finally:
        store.close()


def _knowledge_pack_metadata_payload(settings: AIWebAgentSettings) -> dict[str, object] | None:
    metadata = describe_knowledge_pack(
        settings.knowledge_pack_path,
        expected_sha256=settings.knowledge_pack_sha256,
    )
    if metadata is None:
        return None
    payload = metadata.to_json()
    payload["card_limit"] = settings.knowledge_pack_limit
    payload["max_chars"] = settings.knowledge_pack_max_chars
    return payload


def _handle_memory_after_run(
    *,
    settings: AIWebAgentSettings,
    route: ResolvedModelRoute,
    client: object,
    audit_db_path: Path,
) -> None:
    memory_settings = settings.memory
    if memory_settings is None:
        return
    mode = str(getattr(memory_settings, "mode", "off"))
    db_path = getattr(memory_settings, "db_path", None)
    if db_path is None:
        return

    if mode == "read":
        _record_memory_read_feedback(settings=settings, route=route, db_path=Path(db_path))
        return
    if mode not in {"write", "learn"}:
        return
    if settings.model_client is None:
        return
    _write_reflection_memories(
        settings=settings,
        route=route,
        client=client,
        db_path=Path(db_path),
        audit_db_path=audit_db_path,
    )


def _record_memory_read_feedback(
    *,
    settings: AIWebAgentSettings,
    route: ResolvedModelRoute,
    db_path: Path,
) -> None:
    from ravage.memory import MemoryStore

    store = MemoryStore(db_path)
    try:
        hints = store.retrieve_hints(
            target_fingerprint={},
            min_confidence=float(getattr(settings.memory, "min_confidence", 0.0)),
        )
        memory_ids = [hint.item.memory_id for hint in hints]
        if memory_ids:
            store.record_usage_feedback(memory_ids=memory_ids, run_id="agent-run", accepted=False)
    finally:
        store.close()
    _ = route


def _write_reflection_memories(
    *,
    settings: AIWebAgentSettings,
    route: ResolvedModelRoute,
    client: object,
    db_path: Path,
    audit_db_path: Path,
) -> None:
    from ravage.memory import MemoryItem, MemoryStore

    reply = _complete_model(
        client,
        messages=[
            {"role": "system", "content": "Return compact JSON memory candidates."},
            {"role": "user", "content": '{"request":"memories"}'},
        ],
        route=route,
    )
    try:
        payload = json.loads(reply.content)
    except json.JSONDecodeError:
        return
    raw_memories = payload.get("memories") if isinstance(payload, dict) else None
    if not isinstance(raw_memories, list):
        return

    store = MemoryStore(db_path)
    try:
        for raw in raw_memories:
            if not isinstance(raw, dict):
                continue
            memory_id = store.add_item(
                MemoryItem.new(
                    type=str(raw.get("type") or "lesson"),
                    status="candidate",
                    summary=str(raw.get("summary") or ""),
                    vuln_class=_optional_string(raw.get("vuln_class")),
                    target_fingerprint=_dict_value(raw.get("target_fingerprint")),
                    preconditions=_string_list(raw.get("preconditions")),
                    recommended_actions=_string_list(raw.get("recommended_actions")),
                    negative_actions=_string_list(raw.get("negative_actions")),
                    evidence_requirements=_string_list(raw.get("evidence_requirements")),
                    confidence=_float_value(raw.get("confidence"), default=0.5),
                    retrieval_text=str(raw.get("retrieval_text") or ""),
                    redacted_proof=_dict_value(raw.get("redacted_proof")),
                    replay_command=_optional_string(raw.get("replay_command")),
                    expires_at=_optional_string(raw.get("expires_at")),
                    producer_profile=settings.model_profile,
                    producer_tier=route.selected_tier,
                    producer_provider=route.provider,
                    producer_model=route.model,
                )
            )
            store.add_source(
                memory_id=memory_id,
                source_type="audit_db",
                source_ref=str(audit_db_path),
                source_run_id="agent-run",
                producer_profile=settings.model_profile,
                producer_tier=route.selected_tier,
                producer_provider=route.provider,
                producer_model=route.model,
            )
    finally:
        store.close()


def _dict_value(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _float_value(value: object, *, default: float) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _repeat_context(state: AgentState) -> str:
    """
    Material replay-context signature for repeat-action de-duplication.

    A confirmed canonical Host changes how every probe sees the target, so the same
    probe before/after that discovery is not a repeat.
    """
    hosts = sorted(
        {
            str(value).strip()
            for value in state.signals.get("canonical_hosts", [])
            if str(value).strip()
        }
    )
    return "host:" + ",".join(hosts) if hosts else ""


def _update_state_from_action(
    state: AgentState,
    *,
    action: Mapping[str, object],
    outcome: Mapping[str, object],
) -> None:
    record = {
        "turn": state.turn,
        "action": action.get("action"),
        "task_id": action.get("task_id"),
        "strategy": action.get("strategy"),
        "probe": action.get("probe"),
        "notes": action.get("notes"),
        "expected_signal": action.get("expected_signal"),
        "fallback": action.get("fallback"),
        "ok": outcome.get("ok"),
        "exit_code": outcome.get("exit_code"),
        "repeat_count": outcome.get("repeat_count"),
        "outcome": outcome.get("outcome"),
    }
    state.actions.append(record)
    update_mission_from_action(state, action=dict(action), outcome=dict(outcome))
    for item in _string_list(action.get("memory_updates")):
        append_unique(state.facts, item, limit=80)
    for item in _string_list(action.get("hypotheses")):
        append_unique(state.hypotheses, item, limit=40)
    observation = str(outcome.get("observation") or "")
    if observation and not state.last_observation:
        state.last_observation = observation_digest(observation)
    for item in observation_facts(observation):
        append_unique(state.facts, item, limit=80)
    if action.get("action") == "invalid":
        append_unique(state.facts, "previous model response violated action schema", limit=80)
    promote_primitives(state)
    if action.get("action") == "final" and outcome.get("stop") is True:
        state.phase = "done"
    elif state.flags:
        state.phase = "exploit" if _continue_after_proof_enabled(state) else "done"
    elif state.primitives or state.turn >= 3:
        state.phase = "exploit"
    state.summary = summarize_state(state)


def _write_runtime_context(
    runtime: ToolRuntime,
    *,
    brief: EngagementBrief,
    brief_path: Path,
    target_url: str,
    workspace: AgentWorkspace,
) -> None:
    payload = {
        "target_url": target_url,
        "scope": {"in_scope": brief.scope.in_scope, "out_of_scope": brief.scope.out_of_scope},
        "scoped_service_ports": _scoped_service_ports(brief.scope.in_scope, target_url=target_url),
        "context": _safe_runtime_context(brief.context or {}, brief_path=brief_path),
    }
    runtime.write_free_roam_context(json.dumps(payload, indent=2, sort_keys=True))


def _scoped_service_ports(in_scope: Iterable[str], *, target_url: str) -> list[dict[str, object]]:
    target = urlparse(target_url)
    target_host = target.hostname or "localhost"
    target_port = target.port or (443 if target.scheme == "https" else 80)
    services: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    for raw in in_scope:
        parsed = urlparse(str(raw))
        host = parsed.hostname or target_host
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        docker_host = (
            DOCKER_SCOPE_GATEWAY_HOST if host in {"127.0.0.1", "localhost", "0.0.0.0"} else host
        )
        services.append(
            {
                "url": str(raw),
                "host": host,
                "port": port,
                "scheme": parsed.scheme or "http",
                "docker_host": docker_host,
                "host_endpoint": f"{host}:{port}",
                "docker_endpoint": f"{docker_host}:{port}",
                "tool_note": "host runtime uses host_endpoint; Docker/tool-image runtime uses docker_endpoint; both use this scoped external port",
                "primary_http": host == target_host and port == target_port,
                "auxiliary": not (host == target_host and port == target_port),
            }
        )
    return services


def _safe_runtime_context(
    context: Mapping[str, object],
    *,
    brief_path: Path | None = None,
) -> dict[str, object]:
    safe = {
        "description": _redact_context_proofs(str(context.get("description") or "")),
        "rules": _safe_context_rules(context.get("rules", [])),
        "win_condition": _safe_win_condition(str(context.get("win_condition") or "")),
    }
    allowed_hint = _redact_context_proofs(str(context.get("allowed_starting_hint") or "")).strip()
    if allowed_hint:
        safe["allowed_starting_hint"] = allowed_hint
    seed_credentials = _authorized_seed_credentials(context, brief_path=brief_path)
    if seed_credentials:
        safe["authorized_seed_credentials"] = seed_credentials
        safe["seed_credential_policy"] = (
            "Use these operator-provided credentials only against in-scope local targets; "
            "operator notes are not proof material."
        )
    return safe


def _authorized_seed_credentials(
    context: Mapping[str, object],
    *,
    brief_path: Path | None,
) -> list[dict[str, str]]:
    notes_path = str(context.get("credential_notes_path") or "").strip()
    if not notes_path or brief_path is None:
        return []
    base_dir = brief_path.parent.resolve()
    candidate = (base_dir / notes_path).resolve()
    try:
        candidate.relative_to(base_dir)
    except ValueError:
        return []
    if not candidate.is_file():
        return []
    try:
        text = candidate.read_text(encoding="utf-8")
    except OSError:
        return []
    credentials = _seed_credentials_from_text(text)
    for item in credentials:
        item["source"] = notes_path
    return credentials


def _seed_credentials_from_text(text: str) -> list[dict[str, str]]:
    sanitized = _redact_context_proofs(text)
    username_match = re.search(r"(?im)^\s*username\s*:\s*([^\s`]+)\s*$", sanitized)
    password_match = re.search(r"(?im)^\s*password\s*:\s*([^\s`]+)\s*$", sanitized)
    if username_match and password_match:
        return [
            {
                "username": username_match.group(1).strip(),
                "password": password_match.group(1).strip(),
            }
        ]
    pair_match = re.search(
        r"(?im)\b(?:credential|account|login)[^\n]{0,80}\b([A-Za-z0-9_.-]{3,48})\s*/\s*([^\s`]+)",
        sanitized,
    )
    if pair_match:
        return [{"username": pair_match.group(1).strip(), "password": pair_match.group(2).strip()}]
    return []


def _safe_context_rules(raw_rules: object) -> list[object]:
    if not isinstance(raw_rules, list):
        return []
    safe_rules: list[object] = []
    for item in raw_rules:
        if isinstance(item, str):
            safe_rules.append(_redact_context_proofs(item))
        else:
            safe_rules.append(item)
    return safe_rules


def _safe_win_condition(value: str) -> str:
    redacted = _redact_context_proofs(value).strip()
    if not redacted or "[redacted proof]" in redacted:
        return "capture the target proof string after exploiting the application"
    return redacted


def _redact_context_proofs(value: str) -> str:
    return _CONTEXT_PROOF_RE.sub("[redacted proof]", value)


def _record(
    audit: AuditStore,
    engagement_id: UUID,
    *,
    actor: str,
    action: str,
    payload: Mapping[str, Any],
    cost_usd: float = 0.0,
) -> None:
    audit.record(
        engagement_id=engagement_id,
        actor=actor,
        action=action,
        payload=payload,
        cost_usd=cost_usd,
    )


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                items.append(text)
        return items
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


class ChatClient:
    def __init__(self, route: ResolvedModelRoute) -> None:
        self.route = route

    def chat(self, messages: list[dict[str, str]]) -> ModelReply:
        transport_error = model_route_transport_error(self.route)
        if transport_error is not None:
            raise RuntimeError(f"model route transport is not callable: {transport_error}")
        if not self.route.ready:
            issues: list[str] = []
            if self.route.missing_env:
                issues.append(f"missing env: {', '.join(self.route.missing_env)}")
            if self.route.missing_pricing:
                issues.append(f"missing pricing: {', '.join(self.route.missing_pricing)}")
            detail = "; ".join(issues) or "route readiness requirements are not met"
            raise RuntimeError(f"model route is not ready: {detail}")
        last_error: Exception | None = None
        paid_transport_risk = route_has_paid_transport_risk(self.route)
        configured_attempts = 1 if paid_transport_risk else max(self.route.max_retries, 0) + 1
        max_attempts = configured_attempts
        transient_attempts = (
            configured_attempts if paid_transport_risk else max(configured_attempts, 6)
        )
        attempt = 0
        while attempt < max_attempts:
            try:
                if self.route.provider == "anthropic":
                    return self._anthropic(messages)
                return self._openai_compatible(messages)
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                max_attempts = transient_attempts
            except RuntimeError as exc:
                last_error = exc
            attempt += 1
            if attempt >= max_attempts:
                break
            time.sleep(_model_retry_delay(attempt))
        raise RuntimeError(f"model route failed: {last_error}") from last_error

    def _openai_compatible(self, messages: list[dict[str, str]]) -> ModelReply:
        base_url = (self.route.base_url or "https://api.openai.com/v1").rstrip("/")
        body: dict[str, object] = {
            "model": self.route.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "temperature": 0,
        }
        if self.route.provider == "openai" and self.route.base_url is None:
            body["service_tier"] = "default"
        if self.route.output_token_limit_parameter != "none":
            body[self.route.output_token_limit_parameter] = self.route.max_output_tokens
        if self.route.reasoning_effort is not None:
            body["reasoning_effort"] = self.route.reasoning_effort
        data = self._post_json(f"{base_url}/chat/completions", body)
        content = _openai_content(data)
        usage = _usage_from_data(data)
        usage_reported = _usage_was_reported(data)
        response_model = _response_string(data, "model")
        service_tier = _response_string(data, "service_tier")
        cost_known = _response_cost_is_known(
            route=self.route,
            usage=usage,
            usage_reported=usage_reported,
            response_model=response_model,
            service_tier=service_tier,
        )
        return ModelReply(
            content=content,
            input_tokens=_usage_token_count(usage, "prompt_tokens"),
            cached_input_tokens=_openai_cached_input_tokens(usage),
            output_tokens=_usage_token_count(usage, "completion_tokens"),
            cost_usd=_estimate_cost(self.route, usage) if cost_known else 0.0,
            usage_reported=usage_reported,
            cost_known=cost_known,
            response_model=response_model,
            response_id=_response_string(data, "id"),
            system_fingerprint=_response_string(data, "system_fingerprint"),
            service_tier=service_tier,
        )

    def _anthropic(self, messages: list[dict[str, str]]) -> ModelReply:
        system = _anthropic_system_message(messages)
        user_messages = _anthropic_user_messages(messages)
        body: dict[str, object] = {
            "model": self.route.model,
            "system": system,
            "messages": user_messages,
            "max_tokens": self.route.max_output_tokens,
        }
        # Newer Claude models reject non-default sampling controls; omit them for compatibility.
        # https://platform.claude.com/docs/en/about-claude/model-deprecations
        base_url = (self.route.base_url or "https://api.anthropic.com").rstrip("/")
        data = self._post_json(f"{base_url}/v1/messages", body, anthropic=True)
        content = _anthropic_content(data)
        usage = _usage_from_data(data)
        usage_reported = _usage_was_reported(data)
        response_model = _response_string(data, "model")
        cost_known = _response_cost_is_known(
            route=self.route,
            usage=usage,
            usage_reported=usage_reported,
            response_model=response_model,
        )
        return ModelReply(
            content=content,
            input_tokens=_usage_token_count(usage, "input_tokens"),
            cached_input_tokens=_usage_token_count(usage, "cache_read_input_tokens"),
            output_tokens=_usage_token_count(usage, "output_tokens"),
            cost_usd=_estimate_cost(self.route, usage) if cost_known else 0.0,
            usage_reported=usage_reported,
            cost_known=cost_known,
            response_model=response_model,
            response_id=_response_string(data, "id"),
            system_fingerprint=_response_string(data, "system_fingerprint"),
            service_tier=_response_string(data, "service_tier"),
        )

    def _post_json(
        self,
        url: str,
        body: Mapping[str, object],
        *,
        anthropic: bool = False,
    ) -> dict[str, object]:
        headers = {"content-type": "application/json"}
        api_key = os.environ.get(self.route.api_key_env or "") if self.route.api_key_env else None
        if anthropic:
            headers["anthropic-version"] = "2023-06-01"
            if api_key:
                headers["x-api-key"] = api_key
        elif api_key:
            headers["authorization"] = f"Bearer {api_key}"
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        timeout = self.route.timeout_seconds + MODEL_TIMEOUT_PADDING_SECONDS
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"model HTTP {exc.code}: {detail[:2000]}") from exc
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise RuntimeError("model response was not a JSON object")
        return data


def _model_retry_delay(attempt: int) -> float:
    return float(min(8, 2 ** max(attempt - 1, 0)))


def _openai_content(data: Mapping[str, object]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("model response missing choices")

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return ""

    message = first_choice.get("message")
    if not isinstance(message, dict):
        return ""

    return str(message.get("content") or "")


def _anthropic_system_message(messages: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for message in messages:
        if message.get("role") != "system":
            continue
        parts.append(message.get("content") or "")
    return "\n\n".join(parts)


def _anthropic_user_messages(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    user_messages: list[dict[str, str]] = []
    for message in messages:
        if message.get("role") == "system":
            continue
        user_messages.append(dict(message))
    return user_messages


def _anthropic_content(data: Mapping[str, object]) -> str:
    parts = data.get("content")
    if not isinstance(parts, list):
        return ""

    text_parts: list[str] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if text:
            text_parts.append(str(text))
    return "".join(text_parts)


def _usage_from_data(data: Mapping[str, object]) -> dict[str, object]:
    raw_usage = data.get("usage")
    if not isinstance(raw_usage, dict):
        return {}

    usage: dict[str, object] = {}
    for key, value in raw_usage.items():
        usage[str(key)] = value
    return usage


def _usage_was_reported(data: Mapping[str, object]) -> bool:
    return isinstance(data.get("usage"), dict)


def _response_string(data: Mapping[str, object], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _usage_token_count(usage: Mapping[str, object], key: str) -> int:
    return _int_value(usage.get(key))


def _usage_token_count_any(usage: Mapping[str, object], keys: tuple[str, ...]) -> int:
    for key in keys:
        value = _usage_token_count(usage, key)
        if value:
            return value
    return 0


def _openai_cached_input_tokens(usage: Mapping[str, object]) -> int:
    details = usage.get("prompt_tokens_details")
    if not isinstance(details, dict):
        return 0
    return _usage_token_count(details, "cached_tokens")


def _response_cost_is_known(
    *,
    route: ResolvedModelRoute,
    usage: Mapping[str, object],
    usage_reported: bool,
    response_model: str | None = None,
    service_tier: str | None = None,
) -> bool:
    if not usage_reported or not _usage_has_billable_token_counts(usage):
        return False
    if route.input_cost_per_1m_tokens is None or route.output_cost_per_1m_tokens is None:
        return False
    if not _cache_usage_is_valid(route, usage):
        return False
    if route.provider == "openai" and route.base_url is None:
        if service_tier != "default" or not response_model:
            return False
        input_tokens = _usage_token_count_any(
            usage,
            ("prompt_tokens", "input_tokens"),
        )
        requested_prices = openai_standard_token_prices(
            route.model,
            input_tokens=input_tokens,
        )
        if requested_prices is None:
            if response_model != route.model:
                return False
        elif (
            openai_standard_token_prices(
                response_model,
                input_tokens=input_tokens,
            )
            != requested_prices
        ):
            return False
    if route.provider == "anthropic":
        if not response_model:
            return False
        requested_prices = anthropic_standard_token_prices(route.model)
        response_prices = anthropic_standard_token_prices(response_model)
        if requested_prices is None:
            if response_model != route.model:
                return False
        elif response_prices != requested_prices:
            return False
        if _usage_token_count(usage, "cache_creation_input_tokens") != 0:
            return False
    if route.provider == "abliteration":
        if not response_model:
            return False
        requested_prices = abliteration_standard_token_prices(route.model)
        response_prices = abliteration_standard_token_prices(response_model)
        if requested_prices is None:
            if response_model != route.model:
                return False
        elif response_prices != requested_prices:
            return False
    cached_input_tokens = _cached_input_tokens(route, usage)
    return cached_input_tokens == 0 or route.cached_input_cost_per_1m_tokens is not None


def _cached_input_tokens(
    route: ResolvedModelRoute,
    usage: Mapping[str, object],
) -> int:
    if route.provider == "anthropic":
        return _usage_token_count(usage, "cache_read_input_tokens")
    return _openai_cached_input_tokens(usage)


def _cache_usage_is_valid(
    route: ResolvedModelRoute,
    usage: Mapping[str, object],
) -> bool:
    if route.provider == "anthropic":
        for key in ("cache_read_input_tokens", "cache_creation_input_tokens"):
            if key in usage and not _usage_has_nonnegative_int(usage, (key,)):
                return False
        return True
    details = usage.get("prompt_tokens_details")
    if not isinstance(details, dict) or "cached_tokens" not in details:
        return True
    return _usage_has_nonnegative_int(details, ("cached_tokens",))


def _usage_has_billable_token_counts(usage: Mapping[str, object]) -> bool:
    has_input = _usage_has_nonnegative_int(usage, ("prompt_tokens", "input_tokens"))
    has_output = _usage_has_nonnegative_int(usage, ("completion_tokens", "output_tokens"))
    return has_input and has_output


def _usage_has_nonnegative_int(usage: Mapping[str, object], keys: tuple[str, ...]) -> bool:
    for key in keys:
        if key not in usage:
            continue
        try:
            return int(str(usage[key])) >= 0
        except (TypeError, ValueError):
            return False
    return False


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _estimate_cost(route: ResolvedModelRoute, usage: Mapping[str, object]) -> float:
    input_tokens = _usage_token_count_any(
        usage,
        ("prompt_tokens", "input_tokens"),
    )
    output_tokens = _usage_token_count_any(
        usage,
        ("completion_tokens", "output_tokens"),
    )
    input_cost = route.input_cost_per_1m_tokens
    cached_input_cost = route.cached_input_cost_per_1m_tokens
    output_cost = route.output_cost_per_1m_tokens
    if route.provider == "openai" and route.base_url is None:
        standard_prices = openai_standard_token_prices(
            route.model,
            input_tokens=input_tokens,
        )
        if standard_prices is not None:
            input_cost = standard_prices.input_per_1m
            cached_input_cost = standard_prices.cached_input_per_1m
            output_cost = standard_prices.output_per_1m
    if input_cost is None or output_cost is None:
        return 0.0
    cached_input_tokens = _cached_input_tokens(route, usage)
    if route.provider == "anthropic":
        uncached_input_tokens = input_tokens
    else:
        cached_input_tokens = min(cached_input_tokens, input_tokens)
        uncached_input_tokens = max(input_tokens - cached_input_tokens, 0)
    if cached_input_cost is None:
        cached_input_cost = input_cost
    input_total = uncached_input_tokens / 1_000_000 * input_cost
    input_total += cached_input_tokens / 1_000_000 * cached_input_cost
    output_total = output_tokens / 1_000_000 * output_cost
    return float(input_total + output_total)


def _resolve_target_url(base_url: str, value: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base_url.rstrip("/") + "/", value)


def _augment_routes_from_html(
    routes: list[RouteProbe],
    html: str,
    *,
    target_url: str,
    http_client: object | None = None,
) -> list[RouteProbe]:
    _ = target_url, http_client
    discovered = list(routes)
    discovered.extend(_javascript_location_routes(html))
    discovered.extend(_data_driven_idor_routes(html))
    discovered.extend(_header_trust_routes(html))
    return _dedupe_route_probes(discovered)


def _javascript_location_routes(html: str) -> list[RouteProbe]:
    from urllib.parse import parse_qsl, urlsplit

    routes: list[RouteProbe] = []
    pattern = r"""(?is)window\.location\.href\s*=\s*`([^`]+)`"""
    for match in re.finditer(pattern, html):
        raw_path = re.sub(r"\$\{[^}]+\}", "example", match.group(1))
        parsed = urlsplit(raw_path)
        params: list[RouteParam] = []
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            params.append(RouteParam(name=name, location="query", example_value=value))
        routes.append(RouteProbe(method="GET", path=parsed.path or "/", params=params))
    return routes


def _data_driven_idor_routes(html: str) -> list[RouteProbe]:
    order_match = re.search(r"""(?is)data-order-id\s*=\s*["']([^"']+)["']""", html)
    if order_match is None:
        return []

    order_id = order_match.group(1)
    if "fetch('/order/' + orderId + '/receipt')" not in html:
        return []

    return [
        RouteProbe(
            method="GET",
            path=f"/order/{order_id}/receipt",
            params=[RouteParam(name="id", location="path", example_value=order_id)],
        )
    ]


def _header_trust_routes(html: str) -> list[RouteProbe]:
    header_match = re.search(
        r"""(?is)['"](?P<name>X-[A-Za-z0-9-]+)['"]\s*:\s*['"](?P<value>[^'"]+)['"]""", html
    )
    route_match = re.search(r"""(?is)fetch\(\s*['"](?P<path>/[^'"]+)['"]\s*,""", html)
    if header_match is None or route_match is None:
        return []

    return [
        RouteProbe(
            method="GET",
            path=route_match.group("path"),
            params=[
                RouteParam(
                    name=header_match.group("name"),
                    location="header",
                    example_value=header_match.group("value"),
                )
            ],
        )
    ]


def _dedupe_route_probes(routes: list[RouteProbe]) -> list[RouteProbe]:
    seen: set[tuple[str, str]] = set()
    deduped: list[RouteProbe] = []
    for route in routes:
        method = route.method
        path = route.path
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(route)
    return deduped


def _initial_messages(*args: object, **kwargs: object) -> list[ChatMessage]:
    agent_skill = str(kwargs.get("agent_skill") or "")
    content = "Ravage compatibility prompt."
    if agent_skill:
        content += f"\nBEGIN_AGENT_SKILL\n{agent_skill}\nEND_AGENT_SKILL"
    return [ChatMessage(role="system", content=content)]


@dataclass(frozen=True)
class ResumeContext:
    source_path: Path
    report_path: Path | None
    event_counts: dict[str, int]
    snippets: list[str]

    def to_json(self) -> dict[str, object]:
        return {
            "source_path": str(self.source_path),
            "report_path": str(self.report_path) if self.report_path else None,
            "event_counts": dict(self.event_counts),
            "snippets": [_redact_context_proofs(snippet) for snippet in self.snippets],
        }


def _load_resume_context(path: Path, *args: object, **kwargs: object) -> ResumeContext:
    events_path = path / "events.jsonl" if path.is_dir() else path
    if not events_path.exists():
        raise ValueError("resume context does not exist")
    counts: Counter[str] = Counter()
    snippets: list[str] = []
    for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        kind = str(event.get("kind") or "")
        if kind:
            counts[kind] += 1
        snippets.append(json.dumps(event.get("payload", {}), sort_keys=True, default=str))
    if not counts:
        raise ValueError("resume context is empty")
    report_path = (
        path / "report.json" if path.is_dir() and (path / "report.json").exists() else None
    )
    return ResumeContext(
        source_path=path, report_path=report_path, event_counts=dict(counts), snippets=snippets[:20]
    )


def _login_successful(baseline_or_text: object, response: object | None = None) -> bool:
    text = _response_body_text(response if response is not None else baseline_or_text)
    lowered = text.lower()
    if _login_failure_marker(lowered):
        return False
    return any(
        marker in lowered
        for marker in ("logout", "dashboard", "welcome", "account", "transactions")
    )


def _response_body_text(value: object) -> str:
    body = getattr(value, "body", None)
    if isinstance(body, str):
        return body
    if isinstance(value, str):
        return value
    return str(value)


def _login_failure_marker(lowered: str) -> bool:
    failure_markers = (
        "login_error",
        "invalid password",
        "invalid username",
        "invalid username or password",
        "authentication failed",
        "login failed",
    )
    for marker in failure_markers:
        if marker in lowered:
            return True
    return False


def _observation_text(observation: object) -> str:
    payload = {
        "role": "untrusted_tool_output",
        "data": _sanitize_untrusted_observation(observation),
    }
    body = json.dumps(payload, sort_keys=True, indent=2, default=str)
    return (
        "OBSERVATION BEGIN_RAVAGE_UNTRUSTED_TOOL_OBSERVATION\n"
        f"{body}\n"
        "END_RAVAGE_UNTRUSTED_TOOL_OBSERVATION"
    )


def _sanitize_untrusted_observation(value: object) -> object:
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for key, item in value.items():
            sanitized[str(key)] = _sanitize_untrusted_observation(item)
        return sanitized

    if isinstance(value, list):
        sanitized_items: list[object] = []
        for item in value:
            sanitized_items.append(_sanitize_untrusted_observation(item))
        return sanitized_items

    if isinstance(value, str):
        text = value
        replacements = {
            "report_finding": "[redacted]",
            "capture_flag": "[redacted]",
            "confirmed=true": "[redacted]",
            "END_RAVAGE_UNTRUSTED_TOOL_OBSERVATION": "END_RAVAGE_UNTRUSTED_TOOL_OBSERVATION_ESCAPED",
        }
        for marker, replacement in replacements.items():
            text = text.replace(marker, replacement)
        if _looks_schema_like_target_text(text):
            return f"<SCHEMA_LIKE_TARGET_TEXT:{text}>"
        return text

    return value


def _looks_schema_like_target_text(text: str) -> bool:
    lowered = text.lower()
    schema_markers = (
        '"action"',
        '"args"',
        '"rationale"',
        "begin_ravage_untrusted_tool_observation",
        "end_ravage_untrusted_tool_observation",
    )
    for marker in schema_markers:
        if marker in lowered:
            return True
    return False


def _recommended_probe_actions(runtime: object, *, limit: int = 12) -> list[dict[str, object]]:
    recommendations: list[dict[str, object]] = []
    for route in _runtime_discovered_routes(runtime):
        if not _route_looks_xml_endpoint(route):
            continue
        recommendations.append(
            {
                "action": "test_xxe_endpoint",
                "args": {"path": str(route.get("path") or ""), "method": "POST"},
                "why": "XML endpoint can expose XXE file disclosure",
            }
        )
    return recommendations[:limit]


def _runtime_discovered_routes(runtime: object) -> list[dict[str, object]]:
    routes = getattr(runtime, "discovered_routes", [])
    if not isinstance(routes, list):
        return []

    discovered: list[dict[str, object]] = []
    for route in routes:
        if isinstance(route, dict):
            discovered.append(dict(route))
    return discovered


def _route_looks_xml_endpoint(route: dict[str, object]) -> bool:
    text_parts = [
        str(route.get("path") or ""),
        str(route.get("url") or ""),
        str(route.get("content_type") or ""),
    ]
    text = " ".join(text_parts).lower()
    return any(marker in text for marker in ("wsdl", "xml", "soap"))


def _requires_broad_coverage(runtime_or_objectives: object) -> bool:
    objectives = _runtime_objectives(runtime_or_objectives)
    return "web_application_assessment" in objectives


def _write_ai_web_report(*args: object, **kwargs: object) -> None:
    return None


def load_agent_skill(path: Path | None = None) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _free_roam_detect_signals(
    runtime_or_text: object = None,
    *,
    text: str = "",
    observation: object | None = None,
) -> list[dict[str, object]]:
    runtime = runtime_or_text
    if isinstance(runtime_or_text, str) and not text:
        runtime = None
        text = runtime_or_text

    combined_text = _combined_signal_text(text, observation)
    categories = _signal_categories_from_text(combined_text)
    categories = _filter_signal_categories(runtime, categories)

    signals: list[dict[str, object]] = []
    for category in categories:
        signals.append(_free_roam_signal(category, combined_text))
    return signals


def _combined_signal_text(text: str, observation: object | None) -> str:
    if observation is None:
        return text
    return text + "\n" + json.dumps(observation, sort_keys=True, default=str)


def _signal_categories_from_text(text: str) -> list[str]:
    lowered = text.lower()
    categories: list[str] = []

    if _text_has_any(lowered, ("header_auth", "role=admin", "privileged page", "admin_boundary")):
        categories.append("privilege_escalation")
    if _text_has_any(lowered, ("tool_test_sqli_param", "sql_error_marker", "sqlite", "sql syntax")):
        categories.append("sql_injection")
    if _text_has_any(lowered, ("tool_test_lfi_param", "etc_passwd", "root:x:0:0", "file_read")):
        categories.append("lfi")
    if _text_has_any(
        lowered, ("tool_test_ssrf_param", "ssrf_", "127.0.0.1/admin", "internal resource")
    ):
        categories.append("ssrf")
    if _text_has_any(lowered, ("<img", "onerror", "alert(", "document.", "browser_open")):
        categories.append("xss")
    if _text_has_any(lowered, ("{{7*7}} produced", "template error", "ssti_", "jinja")):
        categories.append("ssti")
    if _text_has_any(lowered, ("xxe", "doctype", "external entity", "wsdl")):
        categories.append("xxe")
    if _text_has_any(
        lowered,
        (
            "pickle",
            "serialized",
            "deserialize",
            "deserialization",
            "__reduce__",
            "!!python",
            "object/apply",
            "yaml.load",
        ),
    ):
        categories.append("insecure_deserialization")
    if _text_has_any(lowered, ("jwt_observed", "bearer eyj", "eyjhb", '"alg"', "jwt")):
        categories.append("jwt")
    if _text_has_any(lowered, ("graphql", "graphiql", "__schema", "introspection")):
        categories.append("graphql")
    if _text_has_any(
        lowered,
        (
            "wordpress",
            "wp-content",
            "wp-json",
            "wp-admin",
            "backup-migration",
            "wp-plugin",
        ),
    ):
        categories.append("cms")
    if _text_has_any(
        lowered, ("werkzeug", "werkzeug debugger", "console locked", "console unlocked")
    ):
        categories.append("werkzeug")
    if _text_has_any(
        lowered,
        (
            "access-control-allow-origin",
            "cors",
            "clickjack",
            "frame-ancestors",
            "websocket",
            "localstorage",
            "sessionstorage",
        ),
    ):
        categories.append("browser_boundary")
    if _text_has_any(
        lowered, ("csrf", "xsrf", "authenticity_token", "samesite", "httponly", "logout")
    ):
        categories.append("csrf_session")

    return _dedupe_strings(categories)


def _filter_signal_categories(runtime: object, categories: list[str]) -> list[str]:
    objectives = _runtime_objectives(runtime)
    if "web_application_assessment" in objectives or objectives == {"capture_flag"}:
        return categories

    filtered: list[str] = []
    for category in categories:
        if _category_allowed_by_objectives(category, objectives):
            filtered.append(category)
    return filtered


def _category_allowed_by_objectives(category: str, objectives: set[str]) -> bool:
    aliases = {
        "sql_injection": {"sql_injection", "blind_sqli"},
        "lfi": {"lfi", "path_traversal", "file_read"},
        "ssti": {"ssti"},
        "ssrf": {"ssrf"},
        "xss": {"xss"},
        "xxe": {"xxe", "information_disclosure"},
        "insecure_deserialization": {"insecure_deserialization", "deserialization", "file_read"},
        "jwt": {"jwt", "api", "auth_bypass", "privilege_escalation"},
        "graphql": {"graphql", "idor", "api"},
        "cms": {"cms", "cve", "wordpress", "information_disclosure"},
        "werkzeug": {"werkzeug", "debug_console", "information_disclosure"},
        "browser_boundary": {"browser_boundary", "cors", "websocket", "clickjacking"},
        "csrf_session": {"csrf", "session", "auth_bypass", "privilege_escalation"},
        "idor": {"idor", "business_logic"},
        "privilege_escalation": {"privilege_escalation", "business_logic"},
    }
    allowed = aliases.get(category, {category})
    return bool(objectives.intersection(allowed))


def _free_roam_signal(category: str, text: str) -> dict[str, object]:
    lead_by_category = {
        "sql_injection": "sqli_data_store_surface",
        "lfi": "file_read_inclusion_surface",
        "ssrf": "ssrf_fetch_surface",
        "ssti": "same_sink_template_expression",
        "privilege_escalation": "role_or_policy_boundary",
        "xss": "browser_execution_surface",
        "xxe": "xml_entity_surface",
        "insecure_deserialization": "serialized_state_boundary",
        "jwt": "token_integrity_boundary",
        "graphql": "graphql_object_boundary",
        "cms": "cms_backup_or_plugin_surface",
        "werkzeug": "debug_console_surface",
        "browser_boundary": "browser_trust_boundary",
        "csrf_session": "session_lifecycle_boundary",
    }
    key = _signal_key(category)
    return {
        "key": key,
        "category": category,
        "confidence": "high",
        "evidence": text[:240],
        "exploit_loop": lead_by_category.get(category, category),
    }


def _signal_key(category: str) -> str:
    keys = {
        "privilege_escalation": "privilege_escalation|admin_boundary_signal",
        "sql_injection": "sql_injection|data_store_delta_signal",
        "lfi": "lfi|file_read_signal",
        "ssrf": "ssrf|fetch_surface_signal",
        "ssti": "ssti|expression_error_signal",
        "xss": "xss|browser_execution_signal",
        "xxe": "xxe|endpoint_or_wsdl",
        "insecure_deserialization": "insecure_deserialization|serialized_cookie_or_body",
        "jwt": "jwt|token_observed",
        "graphql": "graphql|endpoint_or_operation",
        "cms": "cms|plugin_or_backup_surface",
        "werkzeug": "werkzeug|debug_console_surface",
        "browser_boundary": "browser_boundary|trust_surface",
        "csrf_session": "csrf_session|stateful_form_or_cookie",
    }
    return keys.get(category, f"{category}|signal")


def _free_roam_driver_recommendations(
    runtime: object,
    *,
    limit: int = 12,
) -> list[FreeRoamDriverRecommendation]:
    drivers = _recommended_driver_names(runtime)
    recommendations: list[FreeRoamDriverRecommendation] = []
    for driver in drivers:
        recommendations.append(_driver_recommendation(driver))
    return recommendations[:limit]


_DRIVER_PROBE_TARGETS: dict[str, str] = {
    "xss": "xss_context",
    "sqli_param_probe": "sqli_differential",
    "lfi_param_probe": "file_fetch_parser",
    "ssrf_param_probe": "ssrf_boundary",
    "command_injection": "command_boundary",
    "auth_boundary_probe": "stateful_session",
    "privilege_boundary_probe": "idor_boundary",
    "xxe_endpoint_probe": "xxe_boundary",
    "information_disclosure": "direct_exposure",
    "wordpress_cve": "cms_exposure",
    "deserialization": "cookie_deserialization",
    "jwt": "jwt_exploit",
    "graphql_idor": "graphql_exploit",
    "browser_boundary": "browser_boundary",
    "csrf_session": "csrf_session",
    "werkzeug_console": "werkzeug_console",
    "auth_idor": "idor_boundary",
    "idor_stateful_closure": "idor_boundary",
    "ssti_same_sink_closure": "ssti_fingerprint",
    "ssti_route_blind": "ssti_fingerprint",
    "ssti_workflow_closure": "ssti_fingerprint",
}

_UNIMPLEMENTED_FREE_ROAM_DRIVERS: dict[str, str] = {
    "method_tamper": "no method-tamper probe is implemented for ai-web yet",
    "race_condition": "no race-condition probe is implemented for ai-web yet",
    "upload_command": "no upload-to-command closure probe is implemented for ai-web yet",
    "header_auth": "covered only by model/manual workflow today; no standalone probe exists",
    "php_type_juggle_auth": "no standalone PHP type-juggle auth probe exists",
}


def _recommended_driver_names(runtime: object) -> list[str]:
    objectives = _runtime_objectives(runtime)
    signal_categories = _runtime_signal_categories(runtime)
    drivers: list[str] = []

    if _requires_broad_coverage(runtime):
        _append_signal_drivers(drivers, signal_categories)
        _append_default_broad_drivers(drivers)
        return _dedupe_strings(drivers)

    _append_objective_drivers(drivers, objectives, signal_categories, runtime)
    if "path_traversal" in objectives or "lfi" in objectives:
        signal_categories = {category for category in signal_categories if category == "lfi"}
    _append_signal_drivers(drivers, signal_categories)
    _append_auth_related_drivers(drivers, objectives, signal_categories)
    return _supported_driver_names(drivers)


def _append_objective_drivers(
    drivers: list[str],
    objectives: set[str],
    signal_categories: set[str],
    runtime: object,
) -> None:
    if "http_method_tamper" in objectives:
        _append_supported_driver(drivers, "method_tamper")
    if "race_condition" in objectives:
        _append_supported_driver(drivers, "race_condition")
    if "xxe" in objectives:
        _append_supported_driver(drivers, "xxe_endpoint_probe")
        _append_supported_driver(drivers, "information_disclosure")
    if "path_traversal" in objectives or "lfi" in objectives:
        _append_supported_driver(drivers, "lfi_param_probe")
    if "cve" in objectives and _objective_probe_count(runtime, "cve") <= 0:
        _append_supported_driver(drivers, "wordpress_cve")
    if "cms" in objectives or "wordpress" in objectives:
        _append_supported_driver(drivers, "wordpress_cve")
    if "command_injection" in objectives:
        _append_supported_driver(drivers, "command_injection")
    if "sql_injection" in objectives or "blind_sqli" in objectives:
        _append_supported_driver(drivers, "sqli_param_probe")
    if "insecure_deserialization" in objectives or "deserialization" in objectives:
        _append_supported_driver(drivers, "deserialization")
    if "jwt" in objectives:
        _append_supported_driver(drivers, "jwt")
    if "graphql" in objectives:
        _append_supported_driver(drivers, "graphql_idor")
    if "browser_boundary" in objectives or "cors" in objectives or "websocket" in objectives:
        _append_supported_driver(drivers, "browser_boundary")
    if "csrf" in objectives or "session" in objectives:
        _append_supported_driver(drivers, "csrf_session")
    if "werkzeug" in objectives or "debug_console" in objectives:
        _append_supported_driver(drivers, "werkzeug_console")
    if "ssrf" in objectives:
        _append_supported_driver(drivers, "ssrf_param_probe")
    if "ssti" in objectives:
        _append_supported_driver(drivers, "ssti_same_sink_closure")
        _append_supported_driver(drivers, "ssti_route_blind")
    if "idor" in objectives and "graphql" in objectives and "graphql" in signal_categories:
        _append_supported_driver(drivers, "graphql_idor")
    if "idor" in objectives:
        _append_supported_driver(drivers, "auth_idor")
        _append_supported_driver(drivers, "idor_stateful_closure")
    if "privilege_escalation" in objectives or "business_logic" in objectives:
        _append_supported_driver(drivers, "auth_boundary_probe")
        _append_supported_driver(drivers, "php_type_juggle_auth")
        _append_supported_driver(drivers, "header_auth")
        _append_supported_driver(drivers, "privilege_boundary_probe")


def _append_signal_drivers(drivers: list[str], signal_categories: set[str]) -> None:
    signal_drivers = {
        "xss": ("xss",),
        "ssti": ("ssti_same_sink_closure", "ssti_route_blind"),
        "sql_injection": ("sqli_param_probe",),
        "lfi": ("lfi_param_probe",),
        "ssrf": ("ssrf_param_probe",),
        "graphql": ("graphql_idor",),
        "jwt": ("jwt",),
        "insecure_deserialization": ("deserialization",),
        "cms": ("wordpress_cve",),
        "werkzeug": ("werkzeug_console",),
        "browser_boundary": ("browser_boundary",),
        "csrf_session": ("csrf_session",),
        "xxe": ("xxe_endpoint_probe",),
        "privilege_escalation": (
            "auth_boundary_probe",
            "header_auth",
            "php_type_juggle_auth",
            "privilege_boundary_probe",
        ),
    }
    for category in signal_categories:
        for driver in signal_drivers.get(category, ()):
            _append_supported_driver(drivers, driver)


def _append_auth_related_drivers(
    drivers: list[str],
    objectives: set[str],
    signal_categories: set[str],
) -> None:
    if "path_traversal" in objectives or "lfi" in objectives:
        return
    if "graphql" in objectives and "graphql" not in signal_categories:
        return
    if "default_credentials" in objectives or "auth_bypass" in signal_categories:
        _append_supported_driver(drivers, "auth_idor")
    if "idor" in objectives:
        _append_supported_driver(drivers, "auth_idor")
        _append_supported_driver(drivers, "idor_stateful_closure")


def _append_default_broad_drivers(drivers: list[str]) -> None:
    for driver in (
        "xss",
        "sqli_param_probe",
        "lfi_param_probe",
        "ssrf_param_probe",
        "auth_boundary_probe",
    ):
        _append_supported_driver(drivers, driver)


def _driver_recommendation(driver: str) -> FreeRoamDriverRecommendation:
    probe = _DRIVER_PROBE_TARGETS.get(driver)
    if probe:
        return {
            "driver": driver,
            "mode": "run_probe",
            "run_command": "",
            "tool_actions": [],
            "available": True,
            "probe": probe,
            "recommended_action": {"action": "run_probe", "probe": probe},
        }

    recommendation: FreeRoamDriverRecommendation = {
        "driver": driver,
        "mode": "unavailable",
        "run_command": "",
        "tool_actions": [],
        "available": False,
        "probe": "",
        "unavailable_reason": _UNIMPLEMENTED_FREE_ROAM_DRIVERS.get(
            driver,
            "no ai-web implementation is registered for this driver",
        ),
    }
    return recommendation


def _append_supported_driver(drivers: list[str], driver: str) -> None:
    if driver in _DRIVER_PROBE_TARGETS:
        drivers.append(driver)


def _supported_driver_names(drivers: list[str]) -> list[str]:
    supported = [driver for driver in drivers if driver in _DRIVER_PROBE_TARGETS]
    return _dedupe_strings(supported)


def _free_roam_active_workflow_leads(runtime: object) -> list[FreeRoamWorkflowLead]:
    leads: list[str] = []
    objectives = _runtime_objectives(runtime)
    signal_categories = _runtime_signal_categories(runtime)

    if "ssti" in objectives or "ssti" in signal_categories:
        leads.append("same_sink_template_expression")
    if "sql_injection" in objectives or "sql_injection" in signal_categories:
        leads.append("sqli_data_store_surface")
    if "lfi" in objectives or "path_traversal" in objectives or "lfi" in signal_categories:
        leads.append("file_read_inclusion_surface")
    if "ssrf" in objectives or "ssrf" in signal_categories:
        leads.append("ssrf_fetch_surface")
    if "privilege_escalation" in objectives or "privilege_escalation" in signal_categories:
        leads.append("role_or_policy_boundary")
    if "insecure_deserialization" in objectives or "insecure_deserialization" in signal_categories:
        leads.append("serialized_state_boundary")
    if "cms" in objectives or "cms" in signal_categories or "cve" in objectives:
        leads.append("cms_backup_or_plugin_surface")
    if "jwt" in objectives or "jwt" in signal_categories:
        leads.append("token_integrity_boundary")
    if "graphql" in objectives or "graphql" in signal_categories:
        leads.append("graphql_object_boundary")
    if "browser_boundary" in signal_categories:
        leads.append("browser_trust_boundary")
    if "csrf_session" in signal_categories:
        leads.append("session_lifecycle_boundary")
    if "werkzeug" in signal_categories:
        leads.append("debug_console_surface")
    if "business_logic" in objectives:
        leads.append("client_controlled_role_session_boundary")
        leads.append("runtime_type_comparison_auth_boundary")

    records: list[FreeRoamWorkflowLead] = []
    for lead in _dedupe_strings(leads):
        records.append({"lead": lead})
    return records


def _free_roam_recovery_driver_name(
    runtime: object,
    *,
    reflection: Mapping[str, object] | None = None,
) -> str:
    objectives = _runtime_objectives(runtime)
    analysis = ""
    if reflection is not None:
        analysis = str(reflection.get("analysis") or "").lower()

    if "ssti" in objectives:
        return "ssti_route_blind"
    if "idor" in objectives and "graphql" in objectives:
        return "graphql_idor"
    if "idor" in objectives:
        return "auth_idor"
    if "race_condition" in objectives:
        return ""
    if "path_traversal" in objectives and "arbitrary_file_upload" in objectives:
        return "lfi_param_probe"
    if "path_traversal" in objectives:
        return "lfi_param_probe"
    if "cve" in objectives:
        return "wordpress_cve"
    if "serialized" in analysis or "deserialization" in analysis:
        return "deserialization"
    if "admin" in analysis or "role" in analysis:
        return "privilege_boundary_probe"
    return ""


def _free_roam_signal_focus_json(runtime: object) -> FreeRoamSignalFocus:
    return {
        "active_workflow_leads": _free_roam_active_workflow_leads(runtime),
        "driver_recommendations": _free_roam_driver_recommendations(runtime),
    }


def _prioritized_driver_events(events: object, *, limit: int = 8) -> list[dict[str, object]]:
    event_items = _list_of_dicts(events)
    proof_events: list[dict[str, object]] = []
    regular_events: list[dict[str, object]] = []

    for event in event_items:
        if str(event.get("kind") or "") == "proof_candidate":
            proof_events.append(event)
        else:
            regular_events.append(event)

    selected = regular_events[: max(limit - len(proof_events), 0)]
    selected.extend(proof_events[:limit])
    return selected[-limit:]


def _ctf_free_roam_controller_driver_names(runtime: object, *, limit: int = 8) -> tuple[str, ...]:
    objectives = _runtime_objectives(runtime)
    signal_categories = _runtime_signal_categories(runtime)
    if not signal_categories and not _controller_can_route_from_objectives(objectives):
        return ()

    names = _recommended_driver_names(runtime)
    return tuple(names[:limit])


def _controller_can_route_from_objectives(objectives: set[str]) -> bool:
    routable = {"ssrf"}
    if "xxe" in objectives:
        return True
    return bool(objectives.intersection(routable))


def _ctf_free_roam_controller_verdict(
    driver: str,
    result: Mapping[str, object],
) -> FreeRoamControllerVerdict:
    events = _driver_events_from_result(result)
    actionable_events = _actionable_driver_events(driver, events)
    status = "partial" if actionable_events else "no_signal"
    return {"status": status, "driver_events": actionable_events}


def _driver_events_from_result(result: Mapping[str, object]) -> list[dict[str, object]]:
    text = "\n".join(
        [
            str(result.get("stdout") or ""),
            str(result.get("stderr") or ""),
        ]
    )
    events: list[dict[str, object]] = []
    for match in re.finditer(r"RAVAGE_DRIVER_EVENT\s+({.*})", text):
        event = _json_object(match.group(1))
        if event:
            events.append(event)
    return events


def _actionable_driver_events(
    driver: str,
    events: list[dict[str, object]],
) -> list[dict[str, object]]:
    actionable: list[dict[str, object]] = []
    for event in events:
        if driver == "auth_idor" and not _auth_idor_event_actionable(event):
            continue
        actionable.append(event)
    return actionable


def _auth_idor_event_actionable(event: dict[str, object]) -> bool:
    if str(event.get("kind") or "") != "auth_workflow_discovered":
        return True
    id_fields = event.get("id_fields")
    return isinstance(id_fields, list) and bool(id_fields)


def _free_roam_closure_lead_from_controller_verdict(
    driver: str,
    verdict: Mapping[str, object],
) -> FreeRoamClosureLead | None:
    if str(verdict.get("status") or "") != "partial":
        return None

    events = _list_of_dicts(verdict.get("driver_events"))
    if driver == "auth_idor" and _driver_events_have_kind(events, "object_endpoint_template"):
        return {
            "class": "idor",
            "closure_driver": "idor_stateful_closure",
            "closure_chain": [
                "state-changing route template discovered",
                "replay candidate object identifiers through the stateful closure driver",
            ],
        }

    if driver == "auth_idor" and _driver_events_have_kind(events, "auth_workflow_discovered"):
        return {
            "class": "idor",
            "closure_driver": "idor_stateful_closure",
            "closure_chain": [
                "identity-bearing authenticated workflow discovered",
                "replay workflow with alternate object identifiers",
            ],
        }

    if driver == "ssti_route_blind" and _driver_events_have_kind(events, "ssti_route_candidates"):
        return {
            "class": "ssti",
            "closure_driver": "ssti_same_sink_closure",
            "closure_chain": [
                "template route candidates discovered",
                "reuse the same sink for proof extraction",
            ],
        }

    if driver == "ssti" and _driver_events_have_kind(events, "ssti_workflow_candidates"):
        return {
            "class": "ssti",
            "closure_driver": "ssti_workflow_closure",
            "closure_chain": [
                "template workflow candidates discovered",
                "complete the multi-step workflow before proof extraction",
            ],
        }

    return None


def _driver_events_have_kind(events: list[dict[str, object]], kind: str) -> bool:
    for event in events:
        if str(event.get("kind") or "") == kind:
            return True
    return False


def _runtime_objectives(runtime_or_objectives: object) -> set[str]:
    if runtime_or_objectives is None:
        return set()
    if isinstance(runtime_or_objectives, (list, tuple, set)):
        return {str(item) for item in runtime_or_objectives}

    brief = getattr(runtime_or_objectives, "brief", None)
    objectives = getattr(brief, "objectives", ())
    if isinstance(objectives, (list, tuple, set)):
        return {str(item) for item in objectives}
    return set()


def _runtime_signal_categories(runtime: object) -> set[str]:
    raw_signals = getattr(runtime, "free_roam_signals", {})
    if not isinstance(raw_signals, dict):
        return set()

    categories: set[str] = set()
    for signal in raw_signals.values():
        if isinstance(signal, dict):
            category = str(signal.get("category") or "")
            if category:
                categories.add(category)
    return categories


def _objective_probe_count(runtime: object, objective: str) -> int:
    counts = getattr(runtime, "free_roam_objective_probe_counts", {})
    if not isinstance(counts, dict):
        return 0
    value = counts.get(objective)
    if isinstance(value, int):
        return value
    return 0


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []

    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _json_object(text: str) -> dict[str, object]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if isinstance(value, dict):
        return dict(value)
    return {}


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _text_has_any(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False
