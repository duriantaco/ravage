# Integration errors preserve exact fail-closed route context.
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from ravage.agent_core.agent_state import (
    AgentState,
    append_unique,
    load_agent_state,
    merge_signals,
    save_agent_state,
)
from ravage.agent_core.ai_agent import (
    _assert_authenticated_restored_artifacts_safe,
    _assert_authenticated_state_artifacts_safe,
)
from ravage.agent_core.autonomous_graph.action_bridge import (
    ActionExecution,
    EvidenceGraphExecutor,
)
from ravage.agent_core.autonomous_graph.action_executor import (
    execute_graph_action as execute_action,
)
from ravage.agent_core.autonomous_graph.adapter import (
    GraphRouteConfig,
    GraphRouteContext,
    GraphRouteResult,
    coordinator_objective,
    graph_objective_from_frontier,
    graph_route_run_id,
)
from ravage.agent_core.autonomous_graph.closure_routing import (
    GraphClosureRouter,
)
from ravage.agent_core.autonomous_graph.context_handoff import (
    seed_frozen_base_context,
)
from ravage.agent_core.autonomous_graph.learning import (
    GraphLearningError,
    learning_artifact_summary,
    promoted_policy_for_memory,
    record_route_lessons,
)
from ravage.agent_core.autonomous_graph.mission import GraphMission
from ravage.agent_core.autonomous_graph.model_bridge import (
    accounted_graph_role_model_policies,
    authenticated_graph_reply_content,
    graph_role_endpoint_portfolios,
    graph_role_model_policy_key,
    graph_route_instructions,
    select_graph_model_portfolio,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphAgentRole,
    GraphNodeStatus,
    GraphStatus,
)
from ravage.agent_core.autonomous_graph.operational_profile import (
    graph_operational_profile,
)
from ravage.agent_core.autonomous_graph.probe_scope import (
    scope_graph_probe_state,
)
from ravage.agent_core.autonomous_graph.run_ownership import RunOwnershipGuard
from ravage.agent_core.autonomous_graph.run_store import RunStore
from ravage.agent_core.autonomous_graph.runtime import (
    DockerGraphProcessBackend,
    PersistentGraphRuntime,
    RuntimeCleanupReceipt,
)
from ravage.agent_core.autonomous_graph.runtime_binding import (
    GraphRuntimePolicyKeys,
    GraphRuntimeResolver,
)
from ravage.agent_core.autonomous_graph.runtime_manifest import (
    GraphRuntimeManifest,
    bind_runtime_manifest,
    component_behavior_identity,
)
from ravage.agent_core.autonomous_graph.runtime_tools import GraphRuntimeExecutor
from ravage.agent_core.autonomous_graph.scoped_http import (
    ManagedGraphAuthentication,
    ScopedGraphHttpExecutor,
)
from ravage.agent_core.autonomous_graph.seed_portfolio import (
    build_seed_portfolio,
)
from ravage.agent_core.autonomous_graph.traffic_lifecycle import (
    GraphTrafficLifecycle,
    GraphTrafficTerminal,
    graph_traffic_session_id,
)
from ravage.agent_core.frontier_shared_runtime import (
    SharedToolRuntime,
    make_shared_tool_runtime,
    reverify_tool_runtime_cleanup,
)
from ravage.agent_core.observation_analysis import observation_facts
from ravage.agent_core.observation_memory import summarize_state
from ravage.agent_core.primitive_state import promote_primitives
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.agent_core.surface_graph_ingest import (
    ingest_captured_exchanges,
    project_surface_graph,
)
from ravage.run_data.audit import AuditStore
from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import DockerToolRuntime, NoProcessToolRuntime, ToolRuntime
from ravage.traffic.policy import (
    TrafficPolicyController,
    TrafficPolicyError,
    TrafficPolicyMode,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Any
    from uuid import UUID

    from pentest_schemas import EngagementBrief, Scope

    from ravage.agent_core.action_executor import ActionResult
    from ravage.agent_core.ai_agent import AIWebAgentSettings
    from ravage.agent_core.autonomous_graph.model_bridge import GraphModelEndpoint
    from ravage.agent_core.autonomous_graph.models import GraphObjective, GraphState
    from ravage.agent_core.autonomous_graph.seed_portfolio import SeedPortfolio
    from ravage.agent_core.autonomous_graph.worker import GraphComplete
    from ravage.agent_core.frontier_route import (
        BaseRouteOutcome,
        FrontierObjective,
    )
    from ravage.auth.runtime import ManagedAttackAuthentication
    from ravage.traffic.contracts import CapturedHttpExchange

_MAX_OBSERVATION_CHARS = 10_000
_MAX_TRANSCRIPT_CHARS = 80_000
_MAX_STATE_ACTIONS = 200
_MAX_STATE_ATTEMPTS = 200
_MAX_SURFACE_GRAPH_ERRORS = 32
_WORKSPACE_RUN_ID = "workspace:autonomous-graph"
_GRAPH_EXECUTION_TOOLS = frozenset(
    {
        "capture_flag",
        "http_request",
        "process_read",
        "process_start",
        "process_stop",
        "process_write",
        "run_command",
        "run_probe",
        "run_python",
        "validate_poc",
    }
)
_OPAQUE_NETWORK_TOOLS = frozenset(
    {
        "process_start",
        "process_read",
        "process_write",
        "process_stop",
        "run_command",
        "run_probe",
        "run_python",
        "validate_poc",
    }
)
_ACTION_EXECUTION_TOOLS = frozenset(
    {"capture_flag", "run_command", "run_probe", "run_python", "validate_poc"}
)


class GraphProductionError(RuntimeError):
    """Raised when production graph integration cannot preserve invariants."""


@dataclass(frozen=True)
class ProductionGraphRouteResult:
    """Graph result plus independently verifiable runtime cleanup receipts."""

    route: GraphRouteResult
    process_cleanup: dict[str, object]
    tool_cleanup: tuple[dict[str, object], ...]
    cleanup_verified: bool
    traffic: dict[str, object]

    @property
    def base(self) -> BaseRouteOutcome:
        return self.route.base

    @property
    def graph(self) -> object:
        return self.route.graph

    @property
    def route_model_requests(self) -> int:
        return self.route.route_model_requests

    @property
    def total_model_requests(self) -> int:
        return self.route.total_model_requests

    @property
    def route_cost_usd(self) -> float:
        return self.route.route_cost_usd

    @property
    def total_cost_usd(self) -> float:
        return self.route.total_cost_usd

    @property
    def investigation(self) -> dict[str, object]:
        return dict(self.route.investigation)

    @property
    def reason(self) -> str:
        if not self.cleanup_verified:
            return "graph_runtime_cleanup_unverified"
        return self.route.run.reason


class ThreadOwnedAudit:
    """Keep the SQLite audit chain on one dedicated thread."""

    def __init__(
        self,
        db_path: Path,
        *,
        scope: Scope,
    ) -> None:
        self.scope = scope
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="ravage-graph-audit",
        )
        self._store = self._executor.submit(
            AuditStore,
            db_path,
            scope=scope,
        ).result()
        self._closed = False
        self._lock = threading.Lock()

    def record(
        self,
        *,
        engagement_id: UUID,
        actor: str,
        action: str,
        payload: Mapping[str, Any],
        cost_usd: float = 0.0,
    ) -> None:
        with self._lock:
            if self._closed:
                raise GraphProductionError("cannot write a closed graph audit store")
            self._executor.submit(
                self._store.record,
                engagement_id=engagement_id,
                actor=actor,
                action=action,
                payload=dict(payload),
                cost_usd=cost_usd,
            ).result()

    def count_findings(
        self,
        *,
        status: str | None = None,
        engagement_id: UUID | str | None = None,
    ) -> int:
        with self._lock:
            if self._closed:
                raise GraphProductionError("cannot read a closed graph audit store")
            return self._executor.submit(
                self._store.count_findings,
                status=status,
                engagement_id=engagement_id,
            ).result()

    def has_finding(
        self,
        finding_id: str,
        *,
        engagement_id: UUID | str | None = None,
    ) -> bool:
        with self._lock:
            if self._closed:
                raise GraphProductionError("cannot read a closed graph audit store")
            return self._executor.submit(
                self._store.has_finding,
                finding_id,
                engagement_id=engagement_id,
            ).result()

    def has_finding_action(
        self,
        action: str,
        *,
        engagement_id: UUID | str,
        finding_id: str,
    ) -> bool:
        with self._lock:
            if self._closed:
                raise GraphProductionError("cannot read a closed graph audit store")
            return self._executor.submit(
                self._store.has_finding_action,
                action,
                engagement_id=engagement_id,
                finding_id=finding_id,
            ).result()

    def record_finding_payload(  # noqa: PLR0913 - audit boundary parity.
        self,
        *,
        finding_id: str,
        engagement_id: UUID,
        vuln_class: str,
        status: str,
        validator_vote: str | None,
        payload: Mapping[str, Any],
    ) -> None:
        with self._lock:
            if self._closed:
                raise GraphProductionError("cannot write a closed graph audit store")
            self._executor.submit(
                self._store.record_finding_payload,
                finding_id=finding_id,
                engagement_id=engagement_id,
                vuln_class=vuln_class,
                status=status,
                validator_vote=validator_vote,
                payload=dict(payload),
            ).result()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._executor.submit(self._store.close).result()
            self._closed = True
        self._executor.shutdown(wait=True)


class PersistentAgentActionCall:
    """Execute against a graph-owned copy of AgentState, never the frozen base."""

    def __init__(  # noqa: PLR0913 - existing executor dependencies are explicit.
        self,
        *,
        target_url: str,
        base_model_requests: int,
        coordinator: object,
        runtime: ToolRuntime,
        state: AgentState,
        workspace: AgentWorkspace,
        audit: ThreadOwnedAudit,
        engagement_id: UUID,
        proof_recognition_enabled: bool,
        allowed_action_tools: frozenset[str] | None = None,
        authentication: ManagedAttackAuthentication | None = None,
        traffic_policy: TrafficPolicyController | None = None,
    ) -> None:
        self.target_url = target_url
        self.base_model_requests = base_model_requests
        self.coordinator = coordinator
        self.runtime = runtime
        self.state = state
        self.workspace = workspace
        self.audit = audit
        self.engagement_id = engagement_id
        self.proof_recognition_enabled = proof_recognition_enabled
        self.allowed_action_tools = allowed_action_tools
        self.authentication = authentication
        self.traffic_policy = traffic_policy

    def __call__(
        self,
        *,
        node_id: str,
        action: dict[str, object],
        action_id: str,
    ) -> ActionExecution:
        action_kind = str(action.get("action") or "")
        if self.allowed_action_tools is not None and action_kind not in self.allowed_action_tools:
            detail = f"graph action tool is unavailable for this route: {action_kind}"
            raise GraphProductionError(detail)
        graph_state = cast("GraphState", getattr(self.coordinator, "state", None))
        graph_requests = int(getattr(graph_state, "model_requests_started", 0))
        self.state.turn = self.base_model_requests + graph_requests
        objective = graph_state.nodes[node_id].objective
        probe_scope = scope_graph_probe_state(
            self.state,
            objective=objective,
            action=action,
        )
        if probe_scope.applied:
            self.workspace.record_event(
                kind="graph_probe_scope",
                payload={
                    "node_id": node_id,
                    "probe": action.get("probe"),
                    "endpoint": probe_scope.endpoint,
                    "inputs": list(probe_scope.inputs),
                    "reason": probe_scope.reason,
                },
            )
        self.workspace.record_event(
            kind="autonomous_graph_action_started",
            payload={
                "node_id": node_id,
                "action_id": action_id,
                "action_kind": str(action.get("action") or ""),
            },
        )
        try:
            result = execute_action(
                action,
                target_url=self.target_url,
                runtime=self.runtime,
                state=probe_scope.state,
                workspace=self.workspace,
                audit=self.audit,  # type: ignore[arg-type]
                engagement_id=self.engagement_id,
                repeat_count=1,
                max_observation_chars=_MAX_OBSERVATION_CHARS,
                max_transcript_chars=_MAX_TRANSCRIPT_CHARS,
                proof_recognition_enabled=self.proof_recognition_enabled,
                action_id=action_id,
                authentication=self.authentication,
                traffic_policy=self.traffic_policy,
            )
        except BaseException as exc:
            with suppress(BaseException):
                self.workspace.record_event(
                    kind="autonomous_graph_action_failed",
                    payload={
                        "node_id": node_id,
                        "action_id": action_id,
                        "action_kind": str(action.get("action") or ""),
                        "error_type": type(exc).__name__,
                    },
                )
            raise
        if probe_scope.applied:
            self.state.last_observation = dict(probe_scope.state.last_observation)
            merge_signals(self.state, probe_scope.state.signals)
            self.state.surface_graph.merge_snapshot(probe_scope.state.surface_graph)
            self.state.surface = project_surface_graph(
                self.state.surface_graph,
                self.state.surface,
            )
        _remember_graph_action(
            state=self.state,
            node_id=node_id,
            action=action,
            result=result,
            action_id=action_id,
        )
        save_agent_state(
            self.workspace.state_path,
            target_url=self.target_url,
            state=self.state,
        )
        observation_id = str(probe_scope.state.last_observation.get("observation_id") or "").strip()
        self.workspace.record_event(
            kind="autonomous_graph_action_finished",
            payload={
                "node_id": node_id,
                "action_id": action_id,
                "action_kind": str(action.get("action") or ""),
                "outcome": result.outcome,
                "ok": result.ok,
                "timed_out": result.timed_out,
            },
        )
        return ActionExecution(
            result=result,
            observation_id=observation_id,
        )


def run_autonomous_graph_route(  # noqa: PLR0913 - public route boundary.
    *,
    brief_path: Path,
    target_url: str,
    base: BaseRouteOutcome,
    settings: AIWebAgentSettings,
    workspace_dir: Path,
    config: GraphRouteConfig | None = None,
    objectives: Sequence[FrontierObjective] | None = None,
) -> ProductionGraphRouteResult:
    """Run the opt-in graph route without changing the frozen base agent."""
    brief = load_engagement_brief(brief_path)
    base_state = load_agent_state(Path(base.state_ref))
    if base_state is None:
        raise GraphProductionError("cannot load frozen base state for graph route")
    _assert_graph_state_authentication(
        base_state,
        settings=settings,
        state_label="frozen base",
    )
    resumed_state_path = workspace_dir / "working_state.json"
    if resumed_state_path.exists():
        resumed_state = load_agent_state(resumed_state_path)
        if resumed_state is None:
            raise GraphProductionError("graph working state is not a valid agent state")
        _assert_graph_state_authentication(
            resumed_state,
            settings=settings,
            state_label="resumed graph",
        )
    restored_authentication = _graph_authentication(settings)
    if restored_authentication is not None:
        _assert_authenticated_graph_resume_artifacts_safe(
            workspace_dir,
            authentication=cast("ManagedAttackAuthentication", restored_authentication),
        )
    flag_objective = _graph_flag_objective(brief=brief, state=base_state)
    route_config = _route_config_for_mission(
        _route_config_with_remaining_budget(
            config or GraphRouteConfig(),
            brief=brief,
            base=base,
        ),
        flag_objective=flag_objective,
    )
    seed_portfolio: SeedPortfolio | None = None
    if objectives is None:
        learning_policy = promoted_policy_for_memory(settings.memory)
        seed_portfolio = build_seed_portfolio(
            base_state,
            base=base,
            limit=route_config.max_seeded_objectives,
            policy=learning_policy,
            flag_objective=flag_objective,
        )
        frontier_objectives = seed_portfolio.objectives
    else:
        frontier_objectives = tuple(objectives)
    graph_objectives = tuple(
        _graph_objective(objective, flag_objective=flag_objective)
        for objective in frontier_objectives
    )
    if not graph_objectives:
        raise GraphProductionError("frozen base produced no graph objectives")
    root_objective = coordinator_objective(
        graph_objectives,
        flag_objective=flag_objective,
    )

    model_endpoints = select_graph_model_portfolio(settings)
    return asyncio.run(
        _run_graph_route(
            brief=brief,
            target_url=target_url,
            base=base,
            settings=settings,
            workspace_dir=workspace_dir,
            config=route_config,
            root_objective=root_objective,
            graph_objectives=graph_objectives,
            model_endpoints=model_endpoints,
            base_state=base_state,
            seed_portfolio=seed_portfolio,
            flag_objective=flag_objective,
        )
    )


def _require_graph_traffic_lifecycle(
    lifecycle: GraphTrafficLifecycle | None,
) -> GraphTrafficLifecycle:
    if lifecycle is None:
        raise GraphProductionError("graph traffic lifecycle is unavailable")
    return lifecycle


def _require_graph_traffic_terminal(
    terminal: GraphTrafficTerminal | None,
) -> GraphTrafficTerminal:
    if terminal is None:
        raise GraphProductionError("graph traffic finalized without terminal metadata")
    return terminal


@dataclass(slots=True)
class _SurfaceGraphTrafficBinding:
    """Keep traffic capture authoritative while graph ingestion stays best-effort."""

    traffic: GraphTrafficLifecycle
    state: AgentState
    record_event: Callable[..., object] | None = None
    errors: list[str] = field(default_factory=list)
    dirty: bool = False
    finalized: bool = False

    def ingest(self, exchange: CapturedHttpExchange) -> None:
        if self.finalized:
            return
        try:
            ingest_captured_exchanges(self.state.surface_graph, (exchange,))
        except Exception as exc:  # noqa: BLE001 - graph enrichment cannot break capture.
            self.remember("exchange", exc)
        else:
            self.dirty = True

    def project(self, *, stage: str) -> None:
        if not self.dirty:
            return
        try:
            self.state.surface = project_surface_graph(
                self.state.surface_graph,
                self.state.surface,
            )
        except Exception as exc:  # noqa: BLE001 - preserve the canonical graph for later repair.
            self.remember(stage, exc)
        else:
            self.dirty = False

    def finalize(self) -> None:
        if self.finalized:
            return
        with suppress(Exception):
            self.traffic.recorder.set_exchange_sink(None)
        self.project(stage="final_projection")
        self.finalized = True
        callback = self.record_event
        if self.errors and callable(callback):
            with suppress(Exception):
                callback(
                    kind="surface_graph_ingest_warning",
                    payload={
                        "error_count": len(self.errors),
                        "error_kinds": sorted(set(self.errors)),
                    },
                )

    def remember(self, stage: str, error: Exception) -> None:
        if len(self.errors) < _MAX_SURFACE_GRAPH_ERRORS:
            self.errors.append(f"{stage}:{type(error).__name__}")


def _bind_surface_graph_traffic(
    traffic: GraphTrafficLifecycle,
    *,
    state: AgentState,
    target_url: str,
    record_event: Callable[..., object] | None = None,
) -> _SurfaceGraphTrafficBinding:
    """Bind managed exchanges after validating graph identity and batch projection."""
    expected = SurfaceGraphState.for_target(target_url)
    if (
        state.surface_graph.target_origin
        and state.surface_graph.target_origin != expected.target_origin
    ):
        raise GraphProductionError("surface graph belongs to a different target origin")
    if not state.surface_graph.target_origin:
        state.surface_graph = expected
    binding = _SurfaceGraphTrafficBinding(
        traffic=traffic,
        state=state,
        record_event=record_event,
    )
    captured = SurfaceGraphState.for_target(target_url)
    for exchange in traffic.store.exchanges():
        try:
            ingest_captured_exchanges(captured, (exchange,))
        except Exception as exc:  # noqa: BLE001 - one malformed exchange cannot break resume.
            binding.remember("resume_exchange", exc)
    state.surface_graph.merge_snapshot(captured)
    binding.dirty = bool(state.surface_graph.operations)
    binding.project(stage="resume_projection")
    traffic.recorder.set_exchange_sink(binding.ingest)
    return binding


async def _run_graph_route(  # noqa: PLR0913, PLR0915 - integration boundary.
    *,
    brief: EngagementBrief,
    target_url: str,
    base: BaseRouteOutcome,
    settings: AIWebAgentSettings,
    workspace_dir: Path,
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    graph_objectives: tuple[GraphObjective, ...],
    model_endpoints: tuple[GraphModelEndpoint, ...],
    base_state: AgentState,
    seed_portfolio: SeedPortfolio | None,
    flag_objective: bool,
) -> ProductionGraphRouteResult:
    run_store = RunStore.open(workspace_dir / "graph-run-store.sqlite3")
    graph_id = graph_route_run_id(
        base=base,
        target_url=target_url,
        scope=_scope_policy_identity(brief.scope),
        config=config,
        root_objective=root_objective,
        seeded_objectives=graph_objectives,
    )
    owner_id = f"local:{os.getpid()}:{uuid4().hex}"
    traffic_session_id = graph_traffic_session_id(graph_id)
    traffic_lifecycle: GraphTrafficLifecycle | None = None
    traffic_terminal: GraphTrafficTerminal | None = None
    tool_runtime: ToolRuntime | None = None
    tool_cleanup: tuple[dict[str, object], ...] = ()
    route_result: GraphRouteResult | None = None
    process_cleanup: dict[str, object] = {
        "verified": False,
        "reason": "graph_process_runtime_not_started",
    }
    ownership_epoch = 0
    production_result: ProductionGraphRouteResult | None = None
    route_traffic_policy: TrafficPolicyController | None = None
    traffic_policy_enforced = False
    async with RunOwnershipGuard(run_store, _WORKSPACE_RUN_ID, owner_id) as ownership:
        ownership_epoch = ownership.lease.epoch
        try:
            ownership.assert_reconciled()
            try:
                traffic_lifecycle = await asyncio.to_thread(
                    GraphTrafficLifecycle.open,
                    workspace_dir,
                    target_url=target_url,
                    in_scope=tuple(str(item) for item in brief.scope.in_scope),
                    out_of_scope=tuple(str(item) for item in brief.scope.out_of_scope),
                    capture_session_id=traffic_session_id,
                    graph_resume_expected=(workspace_dir / "graph-state.json").exists(),
                    identity_alias=_graph_authentication_identity(settings),
                )
            except BaseException as exc:
                traffic_terminal = GraphTrafficTerminal.failed_start(
                    capture_session_id=traffic_session_id,
                    error=exc,
                )
                raise
            if seed_portfolio is not None:
                await asyncio.to_thread(
                    seed_portfolio.save,
                    workspace_dir / "seed-portfolio.json",
                )
            route_traffic_policy = _graph_traffic_policy(
                settings,
                target_url=target_url,
                authenticated=_graph_authentication(settings) is not None,
            )
            traffic_policy_enforced = _traffic_policy_enforced(route_traffic_policy)
            tool_runtime = await asyncio.to_thread(
                _route_tool_runtime,
                settings=settings,
                brief=brief,
            )
            try:
                _require_verified_tool_runtime(
                    tool_runtime,
                    authenticated=_graph_authentication(settings) is not None,
                    traffic_policy_enforced=traffic_policy_enforced,
                )
                runtime_profile_key, tool_policies, role_policies = (
                    _production_runtime_policy_components(
                        flag_objective=flag_objective,
                        authenticated=_graph_authentication(settings) is not None,
                        traffic_policy_enforced=traffic_policy_enforced,
                    )
                )
                bind_runtime_manifest(
                    workspace_dir / "runtime-policy-manifest.json",
                    expected=GraphRuntimeManifest.create(
                        graph_id=graph_id,
                        execution_mode="local-target-scoped",
                        model_policies=graph_role_endpoint_portfolios(model_endpoints),
                        capabilities=tuple(
                            _graph_execution_tools(
                                flag_objective,
                                authenticated=_graph_authentication(settings) is not None,
                                traffic_policy_enforced=traffic_policy_enforced,
                            )
                        ),
                        policy_payload=_runtime_policy_payload(
                            runtime_profile_key=runtime_profile_key,
                            tool_policies=tool_policies,
                            role_policies=role_policies,
                            execution_policy=_production_execution_policy(
                                brief=brief,
                                settings=settings,
                                config=config,
                                tool_runtime=tool_runtime,
                                flag_objective=flag_objective,
                                traffic_policy=route_traffic_policy,
                            ),
                        ),
                        instructions=graph_route_instructions(
                            flag_objective=flag_objective,
                            authenticated=_graph_authentication(settings) is not None,
                            identity_alias=_graph_authentication_identity(settings),
                        ),
                    ),
                    resumed=(workspace_dir / "graph-state.json").exists(),
                )
                traffic_lifecycle = _require_graph_traffic_lifecycle(traffic_lifecycle)
                route_result, process_receipt, traffic_terminal = await ownership.run(
                    _run_owned_graph_route(
                        brief=brief,
                        target_url=target_url,
                        base=base,
                        settings=settings,
                        workspace_dir=workspace_dir,
                        config=config,
                        root_objective=root_objective,
                        graph_objectives=graph_objectives,
                        tool_runtime=tool_runtime,
                        model_endpoints=model_endpoints,
                        base_state=base_state,
                        run_store=run_store,
                        ownership=ownership,
                        graph_id=graph_id,
                        flag_objective=flag_objective,
                        traffic=traffic_lifecycle,
                        traffic_policy=route_traffic_policy,
                    )
                )
                process_cleanup = process_receipt.to_json()
            finally:
                tool_cleanup = await asyncio.to_thread(
                    _shutdown_tool_runtime,
                    tool_runtime,
                )
        except BaseException as exc:
            if traffic_lifecycle is not None and traffic_terminal is None:
                with suppress(BaseException):
                    traffic_terminal = await asyncio.to_thread(traffic_lifecycle.finalize)
            await _publish_route_failure_receipts(
                workspace_dir=workspace_dir,
                route_result=route_result,
                process_cleanup=process_cleanup,
                tool_cleanup=tool_cleanup,
                run_error=exc,
                ownership=ownership,
                ownership_epoch=ownership_epoch,
                owner_id=owner_id,
                traffic=(traffic_terminal.to_json() if traffic_terminal is not None else None),
            )
            raise
        try:
            ownership.assert_owned()
            if route_result is None:
                raise GraphProductionError(  # noqa: TRY301
                    "graph route completed without a result"
                )
            traffic_terminal = _require_graph_traffic_terminal(traffic_terminal)
            cleanup_verified = process_cleanup.get("verified") is True and _tool_cleanup_verified(
                tool_cleanup
            )
            production_result = ProductionGraphRouteResult(
                route=route_result,
                process_cleanup=process_cleanup,
                tool_cleanup=tool_cleanup,
                cleanup_verified=cleanup_verified,
                traffic=traffic_terminal.to_json(),
            )
            await asyncio.to_thread(
                _write_route_receipt,
                workspace_dir / "graph-route-receipt.json",
                route_result=route_result,
                process_cleanup=process_cleanup,
                tool_cleanup=tool_cleanup,
                run_error=None,
                ownership_epoch=ownership_epoch,
                ownership_release_status="guarded_pending_release",
                traffic=traffic_terminal.to_json(),
            )
            await asyncio.to_thread(
                _record_route_learning,
                workspace_dir,
                memory_settings=settings.memory,
            )
            ownership.assert_owned()
        except BaseException as exc:
            if traffic_lifecycle is not None and traffic_terminal is None:
                with suppress(BaseException):
                    traffic_terminal = await asyncio.to_thread(traffic_lifecycle.finalize)
            await _publish_route_failure_receipts(
                workspace_dir=workspace_dir,
                route_result=route_result,
                process_cleanup=process_cleanup,
                tool_cleanup=tool_cleanup,
                run_error=exc,
                ownership=ownership,
                ownership_epoch=ownership_epoch,
                owner_id=owner_id,
                traffic=(traffic_terminal.to_json() if traffic_terminal is not None else None),
            )
            raise

    if production_result is None:
        raise GraphProductionError("graph ownership finalized without a result")
    return production_result


async def _run_owned_graph_route(  # noqa: C901, PLR0912, PLR0913, PLR0915 - integration boundary.
    *,
    brief: EngagementBrief,
    target_url: str,
    base: BaseRouteOutcome,
    settings: AIWebAgentSettings,
    workspace_dir: Path,
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    graph_objectives: tuple[GraphObjective, ...],
    tool_runtime: ToolRuntime,
    model_endpoints: tuple[GraphModelEndpoint, ...],
    base_state: AgentState,
    run_store: RunStore,
    ownership: RunOwnershipGuard,
    graph_id: str,
    flag_objective: bool,
    traffic: GraphTrafficLifecycle,
    traffic_policy: TrafficPolicyController | None,
) -> tuple[GraphRouteResult, RuntimeCleanupReceipt, GraphTrafficTerminal]:
    context = await GraphRouteContext.open(
        base=base,
        target_url=target_url,
        scope=_scope_policy_identity(brief.scope),
        workspace_dir=workspace_dir,
        root_objective=root_objective,
        seeded_objectives=graph_objectives,
        config=config,
        available_model_routes=len(model_endpoints),
    )
    if context.coordinator.state.graph_id != graph_id:
        raise GraphProductionError("opened graph identity does not match its ownership binding")
    workspace = AgentWorkspace.open(
        workspace_dir,
        event_sink=settings.event_sink,
    )
    state = _route_state(
        context=context,
        workspace=workspace,
        base_state=base_state,
        target_url=target_url,
    )
    surface_graph_binding = _bind_surface_graph_traffic(
        traffic,
        state=state,
        target_url=target_url,
        record_event=workspace.record_event,
    )
    _assert_graph_state_authentication(
        state,
        settings=settings,
        state_label="graph working",
    )
    seed_frozen_base_context(
        context.sessions,
        node_ids=context.coordinator.state.nodes,
        state=base_state,
    )
    audit = await asyncio.to_thread(
        ThreadOwnedAudit,
        settings.db_path or workspace.root / "audit.db",
        scope=brief.scope,
    )
    authentication = _graph_authentication(settings)
    traffic_policy_enforced = _traffic_policy_enforced(traffic_policy)
    process_runtime: PersistentGraphRuntime | None = None
    if authentication is None and not traffic_policy_enforced:
        try:
            process_runtime = await asyncio.to_thread(
                _make_process_runtime,
                brief=brief,
                settings=settings,
                target_url=target_url,
                workspace_dir=workspace_dir,
            )
        except BaseException:
            with suppress(BaseException):
                await asyncio.to_thread(audit.close)
            raise
    cleanup: RuntimeCleanupReceipt | None = None
    result: GraphRouteResult | None = None
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    audit_error: BaseException | None = None
    graph_finished_payload: dict[str, object] | None = None
    traffic_terminal: GraphTrafficTerminal | None = None
    try:
        model_policies = accounted_graph_role_model_policies(
            endpoints=model_endpoints,
            audit=audit,
            engagement_id=brief.engagement_id,
            route_instructions=graph_route_instructions(
                flag_objective=flag_objective,
                authenticated=authentication is not None,
                identity_alias=(authentication.identity if authentication is not None else ""),
            ),
            record_event=workspace.record_event,
            redact_reply=(authentication.redact_text if authentication is not None else None),
            sanitize_reply=(
                (
                    lambda content: authenticated_graph_reply_content(
                        content,
                        authentication=cast("ManagedAttackAuthentication", authentication),
                    )
                )
                if authentication is not None
                else None
            ),
        )
        allowed_action_tools = _allowed_graph_action_tools(
            flag_objective=flag_objective,
            authenticated=authentication is not None,
            traffic_policy_enforced=traffic_policy_enforced,
        )
        action_call = PersistentAgentActionCall(
            target_url=target_url,
            base_model_requests=base.model_requests,
            coordinator=context.coordinator,
            runtime=tool_runtime,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=brief.engagement_id,
            proof_recognition_enabled=(settings.proof_recognition_enabled and flag_objective),
            allowed_action_tools=allowed_action_tools,
            authentication=cast("ManagedAttackAuthentication | None", authentication),
            traffic_policy=traffic_policy,
        )
        closure_router = GraphClosureRouter(
            blackboard=context.blackboard,
            objective_for_node=lambda node_id: context.coordinator.state.nodes[node_id].objective,
        )
        execute = EvidenceGraphExecutor(
            blackboard=context.blackboard,
            action_call=action_call,
            http_executor=ScopedGraphHttpExecutor(
                target_url=target_url,
                scope=brief.scope,
                allow_remote_target=settings.allow_remote_target,
                profile=graph_operational_profile(
                    config.operational_profile,
                    roe_max_rps=brief.roe.max_rps,
                    max_total_requests=config.limits.max_tool_calls,
                ),
                proof_recognition_enabled=(settings.proof_recognition_enabled and flag_objective),
                state_path=workspace_dir / "graph-http-state.json",
                traffic_observer=traffic.recorder,
                require_existing_state=traffic.graph_resumed,
                minimum_request_count=traffic.existing_agent_http_exchange_count,
                authentication=authentication,
                traffic_policy=traffic_policy,
            ),
            process_executor=(
                GraphRuntimeExecutor(process_runtime)
                if process_runtime is not None and not traffic_policy_enforced
                else None
            ),
            closure_router=closure_router,
            record_event=workspace.record_event,
            allowed_action_tools=allowed_action_tools,
            traffic_policy=traffic_policy,
        )
        runtime_resolver = _production_runtime_resolver(
            model_policies=model_policies,
            execute=execute,
            flag_objective=flag_objective,
            authenticated=authentication is not None,
            traffic_policy_enforced=traffic_policy_enforced,
        )
        default_model = model_policies[graph_role_model_policy_key(GraphAgentRole.COORDINATOR)]
        graph_started_payload = {
            "graph_id": context.coordinator.state.graph_id,
            "resumed": context.resumed,
            "base_model_requests": base.model_requests,
            "route_model_request_budget": config.limits.max_model_requests,
            "route_tool_call_budget": config.limits.max_tool_calls,
            "route_cost_budget_usd": config.limits.max_cost_usd,
            "investigation_enabled": config.investigation_enabled,
            "mission": (
                GraphMission.FLAG_CAPTURE.value
                if flag_objective
                else GraphMission.VULNERABILITY_ASSESSMENT.value
            ),
            "operational_profile": config.operational_profile.value,
            "model_route_portfolio": [
                {
                    "provider": endpoint.route.provider,
                    "model": endpoint.route.model,
                    "ordinal": endpoint.route.ordinal,
                }
                for endpoint in model_endpoints
            ],
            "provider_continuity_retries_per_node": 1,
        }
        if authentication is not None:
            graph_started_payload.update(
                {
                    "authentication_identity": str(authentication.identity).strip(),
                    "execution_capabilities": sorted(
                        _graph_execution_tools(
                            flag_objective,
                            authenticated=True,
                        )
                    ),
                }
            )
        if traffic_policy_enforced:
            graph_started_payload.update(
                {
                    "execution_capabilities": sorted(
                        _graph_execution_tools(
                            flag_objective,
                            authenticated=False,
                            traffic_policy_enforced=True,
                        )
                    ),
                    "traffic_policy_mode": TrafficPolicyMode.ENFORCE.value,
                }
            )
        await asyncio.to_thread(
            audit.record,
            engagement_id=brief.engagement_id,
            actor="agent",
            action="autonomous_graph_started",
            payload=graph_started_payload,
        )
        workspace.record_event(kind="autonomous_graph_started", payload=graph_started_payload)
        result = await context.run(
            complete=default_model,
            execute=execute,
            action_guard=execute.guard,
            runtime_resolver=runtime_resolver,
            run_store=run_store,
            run_lease=ownership.lease,
            assert_run_owned=ownership.assert_owned,
        )
        surface_graph_binding.finalize()
        traffic_terminal = _require_graph_traffic_terminal(
            await asyncio.to_thread(traffic.finalize)
        )
        save_agent_state(
            workspace.state_path,
            target_url=target_url,
            state=state,
        )
        graph_finished_payload = {
            "graph_id": result.graph.graph_id,
            "status": result.graph.status.value,
            "reason": result.run.reason,
            "route_model_requests": result.route_model_requests,
            "total_model_requests": result.total_model_requests,
            "route_tool_calls": result.graph.tool_calls_started,
            "route_cost_usd": result.route_cost_usd,
            "provider_continuity_retries": sum(
                node.provider_continuity_retries for node in result.graph.nodes.values()
            ),
            "stall_review_grants": len(result.graph.stall_review_tokens),
            "investigation": result.investigation,
            "traffic": traffic_terminal.to_json(),
        }
        await asyncio.to_thread(
            audit.record,
            engagement_id=brief.engagement_id,
            actor="agent",
            action="autonomous_graph_finished",
            payload=graph_finished_payload,
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        surface_graph_binding.finalize()
        if traffic_terminal is None:
            with suppress(BaseException):
                traffic_terminal = await asyncio.to_thread(traffic.finalize)
        if process_runtime is None:
            cleanup = _disabled_process_cleanup_receipt(
                reason=(
                    "managed_authentication_http_only"
                    if authentication is not None
                    else "whole_run_low_noise_enforced"
                )
            )
        else:
            try:
                cleanup = await asyncio.to_thread(process_runtime.close)
            except BaseException as exc:  # noqa: BLE001 - cleanup must be accounted.
                cleanup_error = exc
        try:
            await asyncio.to_thread(audit.close)
        except BaseException as exc:  # noqa: BLE001 - cleanup must be accounted.
            audit_error = exc
        terminal_error = next(
            (error for error in (primary_error, cleanup_error, audit_error) if error is not None),
            None,
        )
        if terminal_error is not None:
            terminal_kind = (
                "autonomous_graph_cancelled"
                if isinstance(terminal_error, (asyncio.CancelledError, KeyboardInterrupt))
                else "autonomous_graph_failed"
            )
            with suppress(BaseException):
                workspace.record_event(
                    kind=terminal_kind,
                    payload={
                        "graph_id": context.coordinator.state.graph_id,
                        "error_type": type(terminal_error).__name__,
                        "traffic": (
                            traffic_terminal.to_json() if traffic_terminal is not None else {}
                        ),
                    },
                )
        if primary_error is None:
            if cleanup_error is not None:
                raise cleanup_error
            if audit_error is not None:
                raise audit_error
    if (
        result is None
        or cleanup is None
        or graph_finished_payload is None
        or traffic_terminal is None
    ):
        error = GraphProductionError("graph route finalized without runtime cleanup evidence")
        with suppress(BaseException):
            workspace.record_event(
                kind="autonomous_graph_failed",
                payload={
                    "graph_id": context.coordinator.state.graph_id,
                    "error_type": type(error).__name__,
                    "traffic": (traffic_terminal.to_json() if traffic_terminal is not None else {}),
                },
            )
        raise error
    workspace.record_event(kind="autonomous_graph_finished", payload=graph_finished_payload)
    return result, cleanup, traffic_terminal


def _production_runtime_resolver(
    *,
    model_policies: Mapping[str, GraphComplete],
    execute: EvidenceGraphExecutor,
    flag_objective: bool = True,
    authenticated: bool = False,
    traffic_policy_enforced: bool = False,
) -> GraphRuntimeResolver:
    """Compose credential-free role policy IDs with live production callbacks."""
    runtime_profile_key, tool_policies, role_policies = _production_runtime_policy_components(
        flag_objective=flag_objective,
        authenticated=authenticated,
        traffic_policy_enforced=traffic_policy_enforced,
    )
    coordinator_model = model_policies.get(graph_role_model_policy_key(GraphAgentRole.COORDINATOR))
    if coordinator_model is None:
        raise GraphProductionError("coordinator model policy is unavailable")
    return GraphRuntimeResolver(
        default_complete=coordinator_model,
        default_execute=execute,
        model_policies=model_policies,
        runtime_profiles={runtime_profile_key: execute},
        tool_policies=tool_policies,
        role_policies=cast(
            "Mapping[GraphAgentRole | str, GraphRuntimePolicyKeys]",
            role_policies,
        ),
    )


def _graph_execution_tools(
    flag_objective: bool,  # noqa: FBT001 - mission mode is an explicit policy dimension.
    *,
    authenticated: bool = False,
    traffic_policy_enforced: bool = False,
) -> frozenset[str]:
    tools = _GRAPH_EXECUTION_TOOLS
    if traffic_policy_enforced:
        tools -= _OPAQUE_NETWORK_TOOLS
    if authenticated:
        # Only structured HTTP is connected to configured authentication. Keep
        # every subprocess, process, probe-runner, and PoC replay route out of
        # the authenticated capability set rather than silently downgrading it
        # to an anonymous session.
        tools = tools.intersection({"http_request", "capture_flag"})
    if not flag_objective:
        tools -= frozenset({"capture_flag"})
    return tools


def _allowed_graph_action_tools(
    *,
    flag_objective: bool,
    authenticated: bool,
    traffic_policy_enforced: bool,
) -> frozenset[str] | None:
    if not authenticated and not traffic_policy_enforced:
        return None
    return _graph_execution_tools(
        flag_objective,
        authenticated=authenticated,
        traffic_policy_enforced=traffic_policy_enforced,
    ).intersection(_ACTION_EXECUTION_TOOLS)


def _production_runtime_policy_components(
    *,
    flag_objective: bool = True,
    authenticated: bool = False,
    traffic_policy_enforced: bool = False,
) -> tuple[
    str,
    dict[str, frozenset[str]],
    dict[GraphAgentRole, GraphRuntimePolicyKeys],
]:
    """Return the single source of truth for local role policy composition."""
    runtime_profile_key = "local-runtime:target-scoped"
    execution_tools = _graph_execution_tools(
        flag_objective,
        authenticated=authenticated,
        traffic_policy_enforced=traffic_policy_enforced,
    )
    discovery_tools = execution_tools - frozenset({"validate_poc"})
    critic_tools = execution_tools
    if flag_objective:
        discovery_tools -= frozenset({"capture_flag"})
        critic_tools -= frozenset({"capture_flag"})
    tool_policies = {
        "local-tools:coordination": frozenset(),
        "local-tools:discovery": discovery_tools,
        "local-tools:critic": critic_tools,
        "local-tools:exploitation": execution_tools,
        "local-tools:validator": execution_tools,
        "local-tools:specialist": execution_tools,
    }
    role_policies = {
        role: GraphRuntimePolicyKeys(
            model_policy_key=graph_role_model_policy_key(role),
            runtime_profile_key=runtime_profile_key,
            tool_policy_key=(
                "local-tools:coordination"
                if role is GraphAgentRole.COORDINATOR
                else f"local-tools:{role.value}"
            ),
        )
        for role in GraphAgentRole
    }
    return runtime_profile_key, tool_policies, role_policies


def _runtime_policy_payload(
    *,
    runtime_profile_key: str,
    tool_policies: Mapping[str, frozenset[str]],
    role_policies: Mapping[GraphAgentRole, GraphRuntimePolicyKeys],
    execution_policy: Mapping[str, object],
) -> dict[str, object]:
    return {
        "roles": {
            role.value: {
                "model_policy_key": policy.model_policy_key,
                "runtime_profile_key": policy.runtime_profile_key,
                "tool_policy_key": policy.tool_policy_key,
                "default_session_policy_key": (
                    "fresh_typed" if role is GraphAgentRole.CRITIC else "node_isolated"
                ),
            }
            for role, policy in role_policies.items()
        },
        "tool_policies": dict(tool_policies),
        "runtime_profiles": (runtime_profile_key,),
        "allowed_session_policies": frozenset({"fresh_typed", "node_isolated"}),
        "execution_policy": dict(execution_policy),
    }


def _production_execution_policy(
    *,
    brief: EngagementBrief,
    settings: AIWebAgentSettings,
    config: GraphRouteConfig,
    tool_runtime: ToolRuntime,
    flag_objective: bool = True,
    traffic_policy: TrafficPolicyController | None = None,
) -> dict[str, object]:
    runtime: object = (
        tool_runtime.inner if isinstance(tool_runtime, SharedToolRuntime) else tool_runtime
    )
    framework_owned_runtime = (
        isinstance(tool_runtime, SharedToolRuntime) and tool_runtime.factory_owned
    )
    policy: dict[str, object] = {
        "scope": {
            "in_scope": sorted(set(brief.scope.in_scope)),
            "out_of_scope": sorted(set(brief.scope.out_of_scope)),
        },
        "rules_of_engagement": brief.roe.model_dump(mode="json"),
        "operational_profile": graph_operational_profile(
            config.operational_profile,
            roe_max_rps=brief.roe.max_rps,
            max_total_requests=config.limits.max_tool_calls,
        ).to_json(),
        "allow_remote_target": settings.allow_remote_target,
        "proof_recognition_enabled": (settings.proof_recognition_enabled and flag_objective),
        "mission": (
            GraphMission.FLAG_CAPTURE.value
            if flag_objective
            else GraphMission.VULNERABILITY_ASSESSMENT.value
        ),
        "tool_runtime_mode": settings.tool_runtime_mode,
        "tool_image": settings.tool_image,
        "tool_runtime_identity": component_behavior_identity(
            runtime,
            label="local tool runtime",
            allow_implicit_type=framework_owned_runtime,
        ),
    }
    authentication_identity = _graph_authentication_identity(settings)
    if authentication_identity:
        policy["authentication"] = {
            "configured": True,
            "identity": authentication_identity,
            "transport": "managed_scoped_http",
        }
    if traffic_policy is not None:
        policy["traffic_policy"] = _traffic_policy_manifest_binding(traffic_policy)
    return policy


def _graph_authentication(settings: AIWebAgentSettings) -> ManagedGraphAuthentication | None:
    """Return the ephemeral auth owner without requiring it on older settings."""
    value: object | None = getattr(settings, "authentication", None)
    return cast("ManagedGraphAuthentication | None", value)


def _graph_traffic_policy(
    settings: AIWebAgentSettings,
    *,
    target_url: str,
    authenticated: bool,
) -> TrafficPolicyController | None:
    """Join every graph transport to the exact durable whole-run ledger."""
    authentication = _graph_authentication(settings) if authenticated else None
    if authenticated and authentication is None:
        raise GraphProductionError("authenticated graph is missing its managed identity owner")
    reference = getattr(settings, "traffic_policy_reference", None)
    if reference is None:
        controller = (
            cast("TrafficPolicyController | None", getattr(authentication, "traffic_policy", None))
            if authentication is not None
            else None
        )
        if authentication is not None and controller is None:
            raise GraphProductionError(
                "managed authentication requires a bound whole-run traffic policy"
            )
        if settings.traffic_policy_mode == "low-noise" and controller is None:
            raise GraphProductionError(
                "low-noise graph requires an existing whole-run traffic policy"
            )
        if authentication is not None and controller is not None:
            try:
                authentication.assert_traffic_policy(controller)
            except Exception as exc:
                raise GraphProductionError(
                    "managed authentication traffic policy binding is invalid"
                ) from exc
        return controller
    if not isinstance(reference, Mapping):
        raise GraphProductionError("traffic policy reference is invalid")
    try:
        controller = TrafficPolicyController.from_reference(
            reference,
            require_existing=True,
        )
        expected_origin = SurfaceGraphState.for_target(target_url).target_origin
        actual_origin = SurfaceGraphState.for_target(controller.target_origin).target_origin
    except (OSError, TrafficPolicyError, ValueError) as exc:
        detail = f"traffic policy binding failed: {exc}"
        raise GraphProductionError(detail) from exc
    if actual_origin != expected_origin:
        raise GraphProductionError("traffic policy belongs to a different target origin")
    if authentication is not None:
        try:
            authentication.assert_traffic_policy(controller)
        except Exception as exc:
            raise GraphProductionError(
                "managed authentication traffic policy binding is invalid"
            ) from exc
    return controller


def _traffic_policy_manifest_binding(
    controller: TrafficPolicyController,
) -> dict[str, object]:
    payload = {
        "state_path": str(controller.state_path.resolve()),
        "target_origin": controller.target_origin,
        "config": controller.config.to_json(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "binding_sha256": hashlib.sha256(encoded).hexdigest(),
        "target_origin": controller.target_origin,
        "config": controller.config.to_json(),
    }


def _traffic_policy_enforced(controller: TrafficPolicyController | None) -> bool:
    return (
        controller is not None
        and controller.config.mode is TrafficPolicyMode.ENFORCE
    )


def _graph_authentication_identity(settings: AIWebAgentSettings) -> str:
    authentication = _graph_authentication(settings)
    if authentication is None:
        return ""
    identity = str(getattr(authentication, "identity", "")).strip()
    if not identity:
        raise GraphProductionError("configured graph authentication identity is missing")
    return identity


def _assert_graph_state_authentication(
    state: AgentState,
    *,
    settings: AIWebAgentSettings,
    state_label: str,
) -> None:
    restored_identity = str(state.surface.get("authenticated_identity") or "").strip()
    if not restored_identity:
        if _graph_authentication(settings) is not None:
            message = f"cannot use {state_label} state without an authenticated identity binding"
            raise GraphProductionError(message)
        return
    requested_identity = _graph_authentication_identity(settings)
    if not requested_identity:
        message = f"cannot use authenticated {state_label} state without managed authentication"
        raise GraphProductionError(message)
    if restored_identity != requested_identity:
        message = f"authenticated {state_label} state does not match configured graph identity"
        raise GraphProductionError(message)
    authentication = _graph_authentication(settings)
    if authentication is not None:
        try:
            _assert_authenticated_state_artifacts_safe(
                state,
                authentication=cast("ManagedAttackAuthentication", authentication),
                state_label=f"graph {state_label}",
            )
        except ValueError:
            message = (
                f"cannot use authenticated {state_label} state containing untrusted "
                "authentication material"
            )
            raise GraphProductionError(message) from None


def _assert_authenticated_graph_resume_artifacts_safe(  # noqa: C901
    workspace_dir: Path,
    *,
    authentication: ManagedAttackAuthentication,
) -> None:
    for path in (
        workspace_dir / "graph-state.json",
        workspace_dir / "evidence-blackboard.json",
    ):
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        try:
            _assert_authenticated_restored_artifacts_safe(
                payload,
                authentication=authentication,
                artifact_label="graph route artifact",
            )
        except ValueError:
            raise GraphProductionError(
                "cannot resume authenticated graph artifacts containing untrusted "
                "authentication material"
            ) from None
    sessions_root = workspace_dir / "sessions"
    if not sessions_root.is_dir():
        return
    for path in sorted(sessions_root.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            try:
                _assert_authenticated_restored_artifacts_safe(
                    payload,
                    authentication=authentication,
                    artifact_label="graph session",
                )
            except ValueError:
                raise GraphProductionError(
                    "cannot resume authenticated graph artifacts containing untrusted "
                    "authentication material"
                ) from None


def _scope_policy_identity(scope: Scope) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                *(f"in_scope:{item.strip()}" for item in scope.in_scope if item.strip()),
                *(f"out_of_scope:{item.strip()}" for item in scope.out_of_scope if item.strip()),
            }
        )
    )


def _graph_flag_objective(*, brief: EngagementBrief, state: AgentState) -> bool:
    saved_mode = state.surface.get("flag_objective")
    if isinstance(saved_mode, bool):
        return saved_mode
    return "capture_flag" in {
        str(item).strip().lower().replace("-", "_") for item in brief.objectives
    }


def _route_state(
    *,
    context: GraphRouteContext,
    workspace: AgentWorkspace,
    base_state: AgentState,
    target_url: str,
) -> AgentState:
    if context.resumed:
        if workspace.state_path.exists():
            resumed = load_agent_state(workspace.state_path)
            if resumed is None:
                raise GraphProductionError("graph working state is not a valid agent state")
            return resumed
        if not _is_pristine_graph_bootstrap(context):
            raise GraphProductionError(
                "graph resume requires its graph-owned working state once any work has started"
            )
        return _bootstrap_route_state(
            path=workspace.state_path,
            base_state=base_state,
            target_url=target_url,
        )
    if workspace.state_path.exists():
        raise GraphProductionError(
            "new graph route cannot overwrite an existing route working state"
        )
    return _bootstrap_route_state(
        path=workspace.state_path,
        base_state=base_state,
        target_url=target_url,
    )


def _bootstrap_route_state(
    *,
    path: Path,
    base_state: AgentState,
    target_url: str,
) -> AgentState:
    copied = AgentState.from_json(base_state.to_json())
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    try:
        save_agent_state(
            temporary,
            target_url=target_url,
            state=copied,
        )
        temporary.replace(path)
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
    return copied


def _is_pristine_graph_bootstrap(  # noqa: C901, PLR0911 - explicit fail-closed audit.
    context: GraphRouteContext,
) -> bool:
    state = context.coordinator.state
    if state.status is not GraphStatus.RUNNING:
        return False
    if (
        any(
            (
                state.model_requests_started,
                state.model_requests_completed,
                state.interrupted_model_requests,
                state.tool_calls_started,
                state.tool_calls_completed,
                state.interrupted_tool_calls,
                state.evidence_epoch,
            )
        )
        or state.spent_cost_usd != 0.0
    ):
        return False
    if any(
        (
            state.messages,
            state.trusted_progress_tokens,
            state.disproved_hypothesis_tokens,
            state.counterfactual_objective_fingerprints,
            state.stall_review_tokens,
            state.semantic_action_counts,
            state.proof_evidence_refs,
        )
    ):
        return False
    for group in state.race_groups.values():
        if group.winner_node_id or group.winning_validation_digest or group.winning_evidence_refs:
            return False
    for node in state.nodes.values():
        if node.status not in {GraphNodeStatus.READY, GraphNodeStatus.RUNNING}:
            return False
        if (
            any(
                (
                    node.lease_used,
                    node.model_requests_started,
                    node.model_requests_completed,
                    node.interrupted_model_requests,
                    node.provider_continuity_retries,
                    node.stall_review_grants,
                    node.tool_calls_started,
                    node.tool_calls_completed,
                    node.interrupted_tool_calls,
                    node.lease_extensions,
                    node.last_progress_epoch,
                    node.repeated_observation_count,
                )
            )
            or node.spent_cost_usd != 0.0
        ):
            return False
        if any(
            (
                node.pending_model_request_id,
                node.pending_tool_call_id,
                node.proof_eligible,
                node.last_observation_digest,
                node.completion_summary,
                node.completion_evidence_refs,
            )
        ):
            return False
    blackboard = context.blackboard.state
    if blackboard.records or blackboard.work_items or blackboard.next_sequence != 1:
        return False
    if any(blackboard.progress_snapshot.to_json().values()):
        return False
    try:
        return not any(
            path.is_file() and path.stat().st_size > 0 for path in context.sessions.root.iterdir()
        )
    except OSError:
        return False


def _graph_objective(
    objective: FrontierObjective,
    *,
    flag_objective: bool = True,
) -> GraphObjective:
    return graph_objective_from_frontier(
        family=objective.family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=objective.expected_signal,
        flag_objective=flag_objective,
    )


def _route_config_for_mission(
    config: GraphRouteConfig,
    *,
    flag_objective: bool,
) -> GraphRouteConfig:
    if flag_objective or config.limits.proof_reserve_model_requests == 0:
        return config
    return replace(
        config,
        limits=replace(
            config.limits,
            proof_reserve_model_requests=0,
        ),
    )


def _route_config_with_remaining_budget(
    config: GraphRouteConfig,
    *,
    brief: EngagementBrief,
    base: BaseRouteOutcome,
) -> GraphRouteConfig:
    remaining_cost = max(
        float(brief.budget.max_cost_usd) - max(base.cost_usd, 0.0),
        0.0,
    )
    if remaining_cost <= 0:
        raise GraphProductionError("no engagement cost budget remains for the autonomous graph")
    configured_cost = config.limits.max_cost_usd
    route_cost = remaining_cost if configured_cost is None else min(configured_cost, remaining_cost)
    route_wall = min(
        config.limits.max_wall_seconds,
        max(int(brief.budget.max_runtime_min * 60), 1),
    )
    return replace(
        config,
        limits=replace(
            config.limits,
            max_cost_usd=route_cost,
            max_wall_seconds=route_wall,
        ),
    )


def _route_tool_runtime(
    *,
    settings: AIWebAgentSettings,
    brief: EngagementBrief,
) -> ToolRuntime:
    if settings.tool_runtime is not None:
        return settings.tool_runtime
    return make_shared_tool_runtime(
        settings,
        brief,
        session_role="frontier",
    )


def _require_verified_tool_runtime(
    runtime: ToolRuntime,
    *,
    authenticated: bool,
    traffic_policy_enforced: bool = False,
) -> None:
    current: object = runtime
    if isinstance(current, SharedToolRuntime):
        current = current.inner
    if isinstance(current, DockerToolRuntime):
        return
    if (authenticated or traffic_policy_enforced) and isinstance(current, NoProcessToolRuntime):
        return
    if getattr(current, "network_isolation_verified", False) is True:
        return
    raise GraphProductionError("autonomous graph requires a verified target-scoped tool runtime")


def _make_process_runtime(
    *,
    brief: EngagementBrief,
    settings: AIWebAgentSettings,
    target_url: str,
    workspace_dir: Path,
) -> PersistentGraphRuntime:
    backend = DockerGraphProcessBackend(
        workspace=workspace_dir / "process-workspace",
        scope=brief.scope,
        session_id=f"{brief.engagement_id}-autonomous-graph-processes",
        image=settings.tool_image,
        cleanup_evidence_path=workspace_dir / "process-network-cleanup.json",
        allow_remote_target=settings.allow_remote_target,
    )
    return PersistentGraphRuntime(
        backend=backend,
        target_url=target_url,
        manifest_path=workspace_dir / "process-runtime.json",
        allow_remote_target=settings.allow_remote_target,
    )


def _managed_http_only_process_cleanup_receipt() -> RuntimeCleanupReceipt:
    """Account for the intentionally absent process surface in authenticated mode."""
    return _disabled_process_cleanup_receipt(reason="managed_authentication_http_only")


def _disabled_process_cleanup_receipt(*, reason: str) -> RuntimeCleanupReceipt:
    """Account for a process surface intentionally disabled by route policy."""
    return RuntimeCleanupReceipt(
        verified=True,
        processes_before=(),
        processes_after=(),
        backend={
            "verified": True,
            "kind": "disabled",
            "reason": reason,
        },
    )


def _shutdown_tool_runtime(
    runtime: ToolRuntime,
) -> tuple[dict[str, object], ...]:
    errors: list[str] = []
    try:
        runtime.close()
        if isinstance(runtime, SharedToolRuntime):
            runtime.shutdown()
    except Exception as exc:  # noqa: BLE001 - final receipt must survive cleanup errors.
        errors.append(f"runtime_close:{type(exc).__name__}:{exc}")
    try:
        receipts = reverify_tool_runtime_cleanup(runtime)
    except Exception as exc:  # noqa: BLE001 - final receipt must survive cleanup errors.
        errors.append(f"cleanup_reverification:{type(exc).__name__}:{exc}")
        receipts = ()
    if not errors:
        return receipts
    failure: dict[str, object] = {
        "cleanup": {
            "verified": False,
            "status": "error",
            "errors": errors,
        }
    }
    return (*receipts, failure)


def _tool_cleanup_verified(
    receipts: tuple[dict[str, object], ...],
) -> bool:
    if not receipts:
        return False
    for receipt in receipts:
        cleanup = receipt.get("cleanup")
        if not isinstance(cleanup, dict) or cleanup.get("verified") is not True:
            return False
    return True


def _remember_graph_action(
    *,
    state: AgentState,
    node_id: str,
    action: Mapping[str, object],
    result: ActionResult,
    action_id: str,
) -> None:
    if result.flag and result.evidence_source_kind.startswith("tool_"):
        append_unique(state.flags, result.flag, limit=20)
    for item in observation_facts(result.observation):
        append_unique(state.facts, item, limit=80)
    state.actions.append(
        {
            "turn": state.turn,
            "action": action.get("action"),
            "task_id": action.get("task_id"),
            "strategy": action.get("strategy"),
            "probe": action.get("probe"),
            "ok": result.ok,
            "outcome": result.outcome,
            "repeat_count": 1,
            "graph_node_id": node_id,
        }
    )
    del state.actions[:-_MAX_STATE_ACTIONS]
    state.attempts.append(
        {
            "action_id": action_id,
            "turn": state.turn,
            "selected_action": dict(action),
            "outcome": result.to_json(),
            "graph_node_id": node_id,
        }
    )
    del state.attempts[:-_MAX_STATE_ATTEMPTS]
    promote_primitives(state)
    if state.flags:
        state.phase = "done"
    elif state.primitives:
        state.phase = "exploit"
    state.summary = summarize_state(state)


def _write_route_receipt(  # noqa: PLR0913 - receipt fields stay explicit.
    path: Path,
    *,
    route_result: GraphRouteResult | None,
    process_cleanup: Mapping[str, object],
    tool_cleanup: Sequence[Mapping[str, object]],
    run_error: BaseException | None,
    ownership_epoch: int = 0,
    ownership_release_status: str = "untracked",
    traffic: Mapping[str, object] | None = None,
) -> None:
    payload: dict[str, object] = {
        "version": 1,
        "status": "error" if run_error is not None else "completed",
        "error_type": type(run_error).__name__ if run_error is not None else "",
        "ownership_epoch": ownership_epoch,
        "ownership_release_status": ownership_release_status,
        "process_cleanup": dict(process_cleanup),
        "tool_cleanup": [dict(item) for item in tool_cleanup],
    }
    if traffic is not None:
        payload["traffic"] = dict(traffic)
    if route_result is not None:
        payload["graph"] = {
            "graph_id": route_result.graph.graph_id,
            "status": route_result.graph.status.value,
            "reason": route_result.run.reason,
            "model_requests": route_result.route_model_requests,
            "tool_calls": route_result.graph.tool_calls_started,
            "cost_usd": route_result.route_cost_usd,
            "provider_continuity_retries": sum(
                node.provider_continuity_retries for node in route_result.graph.nodes.values()
            ),
            "stall_review_grants": len(route_result.graph.stall_review_tokens),
            "investigation": route_result.investigation,
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


async def _publish_route_failure_receipts(  # noqa: PLR0913 - failure evidence is explicit.
    *,
    workspace_dir: Path,
    route_result: GraphRouteResult | None,
    process_cleanup: Mapping[str, object],
    tool_cleanup: Sequence[Mapping[str, object]],
    run_error: BaseException,
    ownership: RunOwnershipGuard,
    ownership_epoch: int,
    owner_id: str,
    traffic: Mapping[str, object] | None = None,
) -> None:
    """Publish immutable failure evidence without letting it mask the run error."""
    try:
        ownership.assert_owned()
    except Exception:  # noqa: BLE001 - unprovable ownership selects immutable-only output.
        ownership_proven = False
    else:
        ownership_proven = True
    receipt_path = workspace_dir / "graph-route-receipt.json"
    unique_path = _epoch_failure_receipt_path(
        receipt_path,
        ownership_epoch=ownership_epoch,
        owner_id=owner_id,
    )
    release_status = "guarded_failure_pending_release" if ownership_proven else "ownership_unproven"
    for path in (unique_path, *((receipt_path,) if ownership_proven else ())):
        with suppress(Exception):
            await asyncio.to_thread(
                _write_route_receipt,
                path,
                route_result=route_result,
                process_cleanup=process_cleanup,
                tool_cleanup=tool_cleanup,
                run_error=run_error,
                ownership_epoch=ownership_epoch,
                ownership_release_status=release_status,
                traffic=traffic,
            )


def _epoch_failure_receipt_path(
    path: Path,
    *,
    ownership_epoch: int,
    owner_id: str,
) -> Path:
    owner_suffix = "".join(character for character in owner_id if character.isalnum())[-32:]
    safe_owner = owner_suffix or "unknown"
    return path.with_name(
        f"{path.stem}.epoch-{ownership_epoch:08d}-{safe_owner}.error{path.suffix}"
    )


def _record_route_learning(
    workspace_dir: Path,
    *,
    memory_settings: object | None,
) -> None:
    receipt_path = workspace_dir / "graph-learning-receipt.json"
    try:
        lessons = record_route_lessons(
            workspace_dir,
            memory_settings=memory_settings,
        )
        payload: dict[str, object] = {
            "version": 1,
            "status": "recorded",
            "lesson_count": len(lessons),
        }
        payload.update(learning_artifact_summary(memory_settings))
    except (GraphLearningError, OSError) as exc:
        payload = {
            "version": 1,
            "status": "rejected",
            "error_type": type(exc).__name__,
            "reason": str(exc),
        }
    try:
        temporary = receipt_path.with_name(f".{receipt_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(receipt_path)
    except OSError:
        # Learning is an optional next-run input. It must never mask the
        # executor-owned route result or cleanup receipt.
        return


__all__ = [
    "GraphProductionError",
    "PersistentAgentActionCall",
    "ProductionGraphRouteResult",
    "ThreadOwnedAudit",
    "run_autonomous_graph_route",
]
