# Remote-route failures preserve target/config identity and authorization context.
# ruff: noqa: ASYNC240, EM101, EM102, PLR0913, TRY003

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit
from uuid import uuid4

from ravage.agent_core.autonomous_graph.action_bridge import (
    EvidenceGraphExecutor,
)
from ravage.agent_core.autonomous_graph.adapter import selective_seed_race_lanes
from ravage.agent_core.autonomous_graph.closure_routing import (
    GraphClosureRouter,
)
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.evidence import (
    BlackboardProofGate,
    EvidenceBlackboard,
)
from ravage.agent_core.autonomous_graph.investigation import InvestigationEngine
from ravage.agent_core.autonomous_graph.model_bridge import (
    GraphModelEndpoint,
    accounted_graph_role_model_policies,
    graph_role_endpoint_portfolios,
    graph_role_model_policy_key,
    select_graph_model_portfolio,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphAgentRole,
    GraphObjective,
    GraphState,
)
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfile,
    graph_operational_profile,
)
from ravage.agent_core.autonomous_graph.run_ownership import RunOwnershipGuard
from ravage.agent_core.autonomous_graph.run_store import RunStore
from ravage.agent_core.autonomous_graph.runtime_binding import (
    GraphRuntimePolicyKeys,
    GraphRuntimeResolver,
)
from ravage.agent_core.autonomous_graph.runtime_manifest import (
    GraphRuntimeManifest,
    bind_runtime_manifest,
    component_behavior_identity,
)
from ravage.agent_core.autonomous_graph.scheduler import ProgressiveGraphScheduler
from ravage.agent_core.autonomous_graph.scoped_http import (
    ScopedGraphHttpExecutor,
    ScopedHttpTransport,
)
from ravage.agent_core.autonomous_graph.sessions import (
    GraphSessionStore,
    SessionRole,
)
from ravage.agent_core.autonomous_graph.traffic_lifecycle import (
    GraphTrafficLifecycle,
    GraphTrafficTerminal,
    graph_traffic_session_id,
)
from ravage.agent_core.autonomous_graph.worker import (
    GraphRunner,
    GraphRunResult,
    GraphWorker,
)
from ravage.run_data.audit import AuditStore
from ravage.run_data.brief import load_engagement_brief
from ravage.traffic.policy import TrafficPolicyController, TrafficPolicyError
from ravage.web_core.scope_policy import assert_authorized_target

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from pentest_schemas import EngagementBrief, Scope

    from ravage.agent_core.ai_agent import AIWebAgentSettings
    from ravage.agent_core.autonomous_graph.adapter import GraphRouteConfig
    from ravage.agent_core.autonomous_graph.worker import GraphComplete

_MANIFEST_VERSION = 1
_WORKSPACE_RUN_ID = "workspace:autonomous-graph"


class RemoteGraphProductionError(RuntimeError):
    """Raised before remote graph work when an invariant cannot be enforced."""


@dataclass(frozen=True)
class RemoteHttpGraphResult:
    graph: GraphState
    run: GraphRunResult
    resumed: bool
    operational_profile: dict[str, object]
    target_requests: int
    receipt_path: Path
    traffic: dict[str, object]

    @property
    def reason(self) -> str:
        return self.run.reason


@dataclass(frozen=True)
class _RemoteManifest:
    graph_id: str
    target_url: str
    scope_digest: str
    config_digest: str
    objective_digest: str

    def to_json(self) -> dict[str, object]:
        return {
            "version": _MANIFEST_VERSION,
            "graph_id": self.graph_id,
            "target_url": self.target_url,
            "scope_digest": self.scope_digest,
            "config_digest": self.config_digest,
            "objective_digest": self.objective_digest,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> _RemoteManifest:
        if payload.get("version") != _MANIFEST_VERSION:
            raise RemoteGraphProductionError("remote graph manifest version is unsupported")
        return cls(
            graph_id=_required_text(payload, "graph_id"),
            target_url=_required_text(payload, "target_url"),
            scope_digest=_required_text(payload, "scope_digest"),
            config_digest=_required_text(payload, "config_digest"),
            objective_digest=_required_text(payload, "objective_digest"),
        )


def run_remote_http_graph_route(
    *,
    brief_path: Path,
    target_url: str,
    settings: AIWebAgentSettings,
    workspace_dir: Path,
    config: GraphRouteConfig,
    transport: ScopedHttpTransport | None = None,
    resolver: Callable[[str, int], Sequence[str]] | None = None,
) -> RemoteHttpGraphResult:
    """
    Run an explicitly authorized remote HTTP-only graph.

    The frozen base is deliberately not invoked: its local tool/runtime contract
    remains unchanged. This route has its own manifest, state, budget, evidence,
    sessions, and request-policy receipts.
    """
    brief = load_engagement_brief(brief_path)
    if not settings.allow_remote_target:
        raise RemoteGraphProductionError(
            "remote HTTP graph requires explicit remote-target authorization"
        )
    try:
        assert_authorized_target(
            target_url,
            scope=brief.scope,
            allow_remote_target=True,
            agent_name="remote autonomous graph",
        )
    except ValueError as exc:
        raise RemoteGraphProductionError(str(exc)) from exc

    route_config = _bounded_remote_config(config, brief=brief)
    objectives = _remote_objectives(
        brief,
        target_url=target_url,
        limit=route_config.max_seeded_objectives,
    )
    root_objective = _remote_root_objective(objectives)
    profile = graph_operational_profile(
        route_config.operational_profile,
        roe_max_rps=brief.roe.max_rps,
        max_total_requests=route_config.limits.max_tool_calls,
    )
    workspace_dir.mkdir(parents=True, exist_ok=True)
    model_endpoints = select_graph_model_portfolio(settings)
    audit = AuditStore(
        settings.db_path or workspace_dir / "audit.db",
        scope=brief.scope,
    )
    receipt_path = workspace_dir / "remote-graph-receipt.json"
    try:
        return asyncio.run(
            _run_remote_http_graph(
                brief=brief,
                target_url=target_url,
                settings=settings,
                workspace_dir=workspace_dir,
                config=route_config,
                root_objective=root_objective,
                objectives=objectives,
                profile=profile,
                model_endpoints=model_endpoints,
                audit=audit,
                receipt_path=receipt_path,
                transport=transport,
                resolver=resolver,
            )
        )
    finally:
        audit.close()


def _require_remote_graph_traffic(
    lifecycle: GraphTrafficLifecycle | None,
) -> GraphTrafficLifecycle:
    if lifecycle is None:
        raise RemoteGraphProductionError("remote graph traffic lifecycle is unavailable")
    return lifecycle


async def _run_remote_http_graph(
    *,
    brief: EngagementBrief,
    target_url: str,
    settings: AIWebAgentSettings,
    workspace_dir: Path,
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    objectives: tuple[GraphObjective, ...],
    profile: GraphOperationalProfile,
    model_endpoints: tuple[GraphModelEndpoint, ...],
    audit: AuditStore,
    receipt_path: Path,
    transport: ScopedHttpTransport | None,
    resolver: Callable[[str, int], Sequence[str]] | None,
) -> RemoteHttpGraphResult:
    expected = _expected_manifest(
        target_url=target_url,
        scope=_scope_policy_identity(brief.scope),
        config=config,
        root_objective=root_objective,
        objectives=objectives,
    )
    run_store = RunStore.open(workspace_dir / "graph-run-store.sqlite3")
    owner_id = f"remote-http:{os.getpid()}:{uuid4().hex}"
    traffic_session_id = graph_traffic_session_id(expected.graph_id)
    traffic_lifecycle: GraphTrafficLifecycle | None = None
    traffic_terminal: GraphTrafficTerminal | None = None
    result: RemoteHttpGraphResult | None = None
    ownership_epoch = 0
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
                    graph_resume_expected=(workspace_dir / "remote-graph-state.json").exists(),
                )
            except BaseException as exc:
                traffic_terminal = GraphTrafficTerminal.failed_start(
                    capture_session_id=traffic_session_id,
                    error=exc,
                )
                raise
            runtime_profile_key, tool_policies, role_policies = _remote_runtime_policy_components()
            instructions = _remote_route_instructions(profile)
            bind_runtime_manifest(
                workspace_dir / "remote-runtime-policy-manifest.json",
                expected=GraphRuntimeManifest.create(
                    graph_id=expected.graph_id,
                    execution_mode="remote-scoped-http",
                    model_policies=graph_role_endpoint_portfolios(model_endpoints),
                    capabilities=("http_request",),
                    policy_payload=_remote_runtime_policy_payload(
                        runtime_profile_key=runtime_profile_key,
                        tool_policies=tool_policies,
                        role_policies=role_policies,
                        execution_policy=_remote_execution_policy(
                            brief=brief,
                            settings=settings,
                            target_url=target_url,
                            profile=profile,
                            transport=transport,
                            resolver=resolver,
                        ),
                    ),
                    instructions=instructions,
                ),
                resumed=(workspace_dir / "remote-graph-state.json").exists(),
            )
            traffic_lifecycle = _require_remote_graph_traffic(traffic_lifecycle)
            result = await ownership.run(
                _run_owned_remote_http_graph(
                    brief=brief,
                    target_url=target_url,
                    settings=settings,
                    workspace_dir=workspace_dir,
                    config=config,
                    root_objective=root_objective,
                    objectives=objectives,
                    profile=profile,
                    model_endpoints=model_endpoints,
                    audit=audit,
                    receipt_path=receipt_path,
                    transport=transport,
                    resolver=resolver,
                    expected=expected,
                    run_store=run_store,
                    ownership=ownership,
                    traffic=traffic_lifecycle,
                )
            )
        except BaseException as exc:
            if traffic_lifecycle is not None and traffic_terminal is None:
                with suppress(BaseException):
                    traffic_terminal = await asyncio.to_thread(traffic_lifecycle.finalize)
            await _publish_remote_failure_receipts(
                receipt_path=receipt_path,
                result=result,
                run_error=exc,
                profile=profile,
                ownership=ownership,
                ownership_epoch=ownership_epoch,
                owner_id=owner_id,
                traffic=(traffic_terminal.to_json() if traffic_terminal is not None else None),
            )
            raise
        try:
            ownership.assert_owned()
            if result is None:
                raise RemoteGraphProductionError(  # noqa: TRY301
                    "remote graph completed without a result"
                )
            await asyncio.to_thread(
                _write_remote_receipt,
                receipt_path,
                result=result,
                run_error=None,
                profile=profile,
                ownership_epoch=ownership_epoch,
                ownership_release_status="guarded_pending_release",
            )
            ownership.assert_owned()
        except BaseException as exc:
            if traffic_lifecycle is not None and traffic_terminal is None:
                with suppress(BaseException):
                    traffic_terminal = await asyncio.to_thread(traffic_lifecycle.finalize)
            await _publish_remote_failure_receipts(
                receipt_path=receipt_path,
                result=result,
                run_error=exc,
                profile=profile,
                ownership=ownership,
                ownership_epoch=ownership_epoch,
                owner_id=owner_id,
                traffic=(traffic_terminal.to_json() if traffic_terminal is not None else None),
            )
            raise

    if result is None:
        raise RemoteGraphProductionError("remote graph ownership finalized without a result")
    return result


async def _run_owned_remote_http_graph(
    *,
    brief: EngagementBrief,
    target_url: str,
    settings: AIWebAgentSettings,
    workspace_dir: Path,
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    objectives: tuple[GraphObjective, ...],
    profile: GraphOperationalProfile,
    model_endpoints: tuple[GraphModelEndpoint, ...],
    audit: AuditStore,
    receipt_path: Path,
    transport: ScopedHttpTransport | None,
    resolver: Callable[[str, int], Sequence[str]] | None,
    expected: _RemoteManifest,
    run_store: RunStore,
    ownership: RunOwnershipGuard,
    traffic: GraphTrafficLifecycle,
) -> RemoteHttpGraphResult:
    manifest_path = workspace_dir / "remote-graph-manifest.json"
    state_path = workspace_dir / "remote-graph-state.json"
    coordinator, resumed = await _open_remote_coordinator(
        state_path=state_path,
        manifest_path=manifest_path,
        expected=expected,
        config=config,
        root_objective=root_objective,
        objectives=objectives,
        available_model_routes=len(model_endpoints),
    )
    sessions = GraphSessionStore.open(workspace_dir / "remote-graph-sessions")
    _seed_remote_context(
        sessions,
        node_ids=tuple(coordinator.state.nodes),
        brief=brief,
        target_url=target_url,
        profile=profile,
    )
    blackboard = EvidenceBlackboard(
        target_url=target_url,
        state_path=workspace_dir / "remote-evidence-blackboard.json",
    )
    investigation = (
        InvestigationEngine.open(
            workspace_dir=workspace_dir,
            objectives=tuple(node.objective for node in coordinator.state.nodes.values()),
            evidence_validator=blackboard,
        )
        if config.investigation_enabled
        else None
    )
    model_policies = accounted_graph_role_model_policies(
        endpoints=model_endpoints,
        audit=audit,
        engagement_id=brief.engagement_id,
        route_instructions=_remote_route_instructions(profile),
    )
    traffic_policy = _remote_traffic_policy(settings, target_url=target_url)
    http_executor = ScopedGraphHttpExecutor(
        target_url=target_url,
        scope=brief.scope,
        allow_remote_target=True,
        profile=profile,
        proof_recognition_enabled=settings.proof_recognition_enabled,
        transport=transport,
        resolver=resolver,
        state_path=workspace_dir / "remote-http-state.json",
        traffic_observer=traffic.recorder,
        require_existing_state=traffic.graph_resumed,
        minimum_request_count=traffic.existing_agent_http_exchange_count,
        traffic_policy=traffic_policy,
    )
    closure_router = GraphClosureRouter(
        blackboard=blackboard,
        objective_for_node=lambda node_id: coordinator.state.nodes[node_id].objective,
    )
    execute = EvidenceGraphExecutor(
        blackboard=blackboard,
        http_executor=http_executor,
        closure_router=closure_router,
    )
    runtime_resolver = _remote_runtime_resolver(
        model_policies=model_policies,
        execute=execute,
    )
    default_model = model_policies[graph_role_model_policy_key(GraphAgentRole.COORDINATOR)]
    audit.record(
        engagement_id=brief.engagement_id,
        actor="agent",
        action="remote_autonomous_graph_started",
        payload={
            "graph_id": coordinator.state.graph_id,
            "resumed": resumed,
            "route_model_request_budget": config.limits.max_model_requests,
            "route_tool_call_budget": config.limits.max_tool_calls,
            "route_cost_budget_usd": config.limits.max_cost_usd,
            "operational_profile": profile.to_json(),
            "execution_capabilities": ["http_request"],
            "shell_enabled": False,
            "browser_enabled": False,
            "race_groups": len(coordinator.state.race_groups),
            "race_lanes": sum(
                len(group.member_node_ids) for group in coordinator.state.race_groups.values()
            ),
        },
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=sessions,
        complete=default_model,
        execute=execute,
        runtime_resolver=runtime_resolver,
        proof_gate=BlackboardProofGate(blackboard),
        evidence_validator=blackboard,
        action_guard=execute.guard,
        investigation_engine=investigation,
        context_provider=blackboard,
        run_store=run_store,
        run_lease=ownership.lease,
        assert_run_owned=ownership.assert_owned,
    )
    run = await GraphRunner(worker).run()
    snapshot = await coordinator.snapshot()
    traffic_terminal = await asyncio.to_thread(traffic.finalize)
    result = RemoteHttpGraphResult(
        graph=snapshot,
        run=run,
        resumed=resumed,
        operational_profile=profile.to_json(),
        target_requests=http_executor.request_count,
        receipt_path=receipt_path,
        traffic=traffic_terminal.to_json(),
    )
    audit.record(
        engagement_id=brief.engagement_id,
        actor="agent",
        action="remote_autonomous_graph_finished",
        payload={
            "graph_id": snapshot.graph_id,
            "status": snapshot.status.value,
            "reason": run.reason,
            "model_requests": snapshot.model_requests_started,
            "tool_calls": snapshot.tool_calls_started,
            "target_requests": http_executor.request_count,
            "cost_usd": snapshot.spent_cost_usd,
            "traffic": traffic_terminal.to_json(),
        },
    )
    return result


def _remote_runtime_resolver(
    *,
    model_policies: Mapping[str, GraphComplete],
    execute: EvidenceGraphExecutor,
) -> GraphRuntimeResolver:
    """Bind every remote role to a model policy and least-privilege tool set."""
    runtime_profile_key, tool_policies, role_policies = _remote_runtime_policy_components()
    coordinator_model = model_policies.get(graph_role_model_policy_key(GraphAgentRole.COORDINATOR))
    if coordinator_model is None:
        raise RemoteGraphProductionError("remote coordinator model policy is unavailable")
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


def _remote_runtime_policy_components() -> tuple[
    str,
    dict[str, frozenset[str]],
    dict[GraphAgentRole, GraphRuntimePolicyKeys],
]:
    """Return the single source of truth for remote role policy composition."""
    runtime_profile_key = "remote-runtime:scoped-http"
    role_policies = {
        role: GraphRuntimePolicyKeys(
            model_policy_key=graph_role_model_policy_key(role),
            runtime_profile_key=runtime_profile_key,
            tool_policy_key=(
                "remote-tools:coordination"
                if role is GraphAgentRole.COORDINATOR
                else "remote-tools:http"
            ),
        )
        for role in GraphAgentRole
    }
    tool_policies = {
        "remote-tools:coordination": frozenset(),
        "remote-tools:http": frozenset({"http_request"}),
    }
    return runtime_profile_key, tool_policies, role_policies


def _remote_runtime_policy_payload(
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


def _remote_execution_policy(
    *,
    brief: EngagementBrief,
    settings: AIWebAgentSettings,
    profile: GraphOperationalProfile,
    transport: ScopedHttpTransport | None,
    resolver: Callable[[str, int], Sequence[str]] | None,
    target_url: str | None = None,
) -> dict[str, object]:
    policy = {
        "scope": {
            "in_scope": sorted(set(brief.scope.in_scope)),
            "out_of_scope": sorted(set(brief.scope.out_of_scope)),
        },
        "rules_of_engagement": brief.roe.model_dump(mode="json"),
        "operational_profile": profile.to_json(),
        "allow_remote_target": settings.allow_remote_target,
        "proof_recognition_enabled": settings.proof_recognition_enabled,
        "transport_identity": component_behavior_identity(
            transport,
            label="remote HTTP transport",
            default_identity="ravage.remote.scoped-http.urllib:v1",
        ),
        "resolver_identity": component_behavior_identity(
            resolver,
            label="remote address resolver",
            default_identity="ravage.remote.scoped-http.system-resolver:v1",
            allow_named_function=True,
        ),
    }
    controller = (
        _remote_traffic_policy(settings, target_url=target_url)
        if target_url is not None
        else None
    )
    if controller is not None:
        payload = {
            "state_path": str(controller.state_path.resolve()),
            "target_origin": controller.target_origin,
            "config": controller.config.to_json(),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        policy["traffic_policy"] = {
            "binding_sha256": hashlib.sha256(encoded).hexdigest(),
            "target_origin": controller.target_origin,
            "config": controller.config.to_json(),
        }
    return policy


def _scope_policy_identity(scope: Scope) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                *(f"in_scope:{item.strip()}" for item in scope.in_scope if item.strip()),
                *(f"out_of_scope:{item.strip()}" for item in scope.out_of_scope if item.strip()),
            }
        )
    )


async def _open_remote_coordinator(
    *,
    state_path: Path,
    manifest_path: Path,
    expected: _RemoteManifest,
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    objectives: tuple[GraphObjective, ...],
    available_model_routes: int,
) -> tuple[GraphCoordinator, bool]:
    if state_path.exists():
        stored = _load_manifest(manifest_path)
        if stored != expected:
            raise RemoteGraphProductionError(
                "remote graph resume manifest does not match target or configuration"
            )
        persisted = GraphState.load(state_path)
        _require_remote_reconciled_model_billing(persisted)
        coordinator = GraphCoordinator.load(state_path)
        if (
            coordinator.state.graph_id != expected.graph_id
            or coordinator.state.limits != config.limits
        ):
            raise RemoteGraphProductionError("remote graph state does not match its manifest")
        return coordinator, True
    if manifest_path.exists():
        stored = _load_manifest(manifest_path)
        if stored != expected:
            raise RemoteGraphProductionError(
                "remote graph bootstrap manifest does not match target or configuration"
            )
    else:
        _write_json_atomic(manifest_path, expected.to_json())
    coordinator = GraphCoordinator.start(
        graph_id=expected.graph_id,
        root_objective=root_objective,
        limits=config.limits,
        root_name="remote-http-coordinator",
        root_lease_limit=config.root_lease_limit,
    )
    race_lanes = selective_seed_race_lanes(
        objective=objectives[0],
        config=config,
        available_model_routes=available_model_routes,
        seeded_objective_count=len(objectives),
        name_prefix="remote-http-specialist-1",
    )
    first_ordinary_index = 1
    if race_lanes:
        await coordinator.spawn_race_group(
            parent_id=coordinator.state.root_node_id,
            objective=objectives[0],
            lanes=race_lanes,
        )
        await coordinator.yield_node_turn(coordinator.state.root_node_id)
        first_ordinary_index = 2
    for index, objective in enumerate(
        objectives[first_ordinary_index - 1 :],
        start=first_ordinary_index,
    ):
        await coordinator.spawn_node(
            parent_id=coordinator.state.root_node_id,
            name=f"remote-http-specialist-{index}",
            objective=objective,
            lease_limit=config.child_lease_limit,
        )
    await coordinator.bind_state_path(state_path)
    return coordinator, False


def _require_remote_reconciled_model_billing(state: GraphState) -> None:
    pending = tuple(
        sorted(
            node.node_id
            for node in state.nodes.values()
            if node.pending_model_request_id is not None
        )
    )
    if pending:
        joined = ", ".join(pending)
        raise RemoteGraphProductionError(
            "cannot resume remote graph with pending model billing; "
            f"durable billing reconciliation is required for: {joined}"
        )


def _remote_objectives(
    brief: EngagementBrief,
    *,
    target_url: str,
    limit: int,
) -> tuple[GraphObjective, ...]:
    parsed = urlsplit(target_url)
    endpoint = parsed.path or "/"
    description = " ".join(str(brief.context.get("description") or "").split())
    objectives: list[GraphObjective] = []
    for family in dict.fromkeys(str(item) for item in brief.objectives):
        objective = GraphObjective.create(
            family=family,
            instruction=(
                f"Assess the authorized {family} objective through structured HTTP "
                f"only. Use finite evidence-led experiments, preserve session state, "
                f"and close with replayable target evidence. Brief: {description}"
            ),
            endpoint=endpoint,
            strategy="scoped_http_evidence_loop",
            expected_signal=(
                f"target-observed evidence for {family}, or a finite failure "
                "certificate covering materially distinct request dimensions"
            ),
        )
        objectives.append(objective)
        if len(objectives) >= limit:
            break
    if not objectives:
        raise RemoteGraphProductionError("remote graph requires at least one brief objective")
    return tuple(objectives)


def _remote_root_objective(
    objectives: tuple[GraphObjective, ...],
) -> GraphObjective:
    catalog = [
        {
            "family": objective.family,
            "endpoint": objective.endpoint,
            "expected_signal": objective.expected_signal,
        }
        for objective in objectives
    ]
    return GraphObjective.create(
        family="remote_graph_coordination",
        instruction=(
            "Coordinate the HTTP-only specialists, route typed evidence, prevent "
            "duplicate experiments, and prioritize proof closure. Catalog: "
            + json.dumps(catalog, ensure_ascii=False, sort_keys=True)
        ),
        strategy="bounded_scoped_http_graph",
        expected_signal=(
            "replayable target-observed proof, or bounded exhaustion with durable "
            "failure certificates"
        ),
    )


def _seed_remote_context(
    sessions: GraphSessionStore,
    *,
    node_ids: tuple[str, ...],
    brief: EngagementBrief,
    target_url: str,
    profile: GraphOperationalProfile,
) -> None:
    payload = {
        "marker": "RAVAGE_REMOTE_HTTP_ROUTE_CONTEXT_V1",
        "target_url": target_url,
        "scope": {
            "in_scope": list(brief.scope.in_scope),
            "out_of_scope": list(brief.scope.out_of_scope),
        },
        "objectives": [str(item) for item in brief.objectives],
        "brief_context": brief.context,
        "operational_profile": profile.to_json(),
        "capabilities": ["http_request"],
        "prohibited_capabilities": ["shell", "browser", "unscoped_egress"],
    }
    content = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    for node_id in node_ids:
        if sessions.records(node_id):
            continue
        sessions.append(
            node_id,
            role=SessionRole.USER,
            content=content,
        )


def _remote_route_instructions(
    profile: GraphOperationalProfile,
) -> str:
    return (
        "The only available execute tool is http_request. Do not call run_command, "
        "run_python, run_probe, validate_poc, process tools, or browser tools. "
        "http_request arguments are method, url or path, headers, one of "
        "body/json/form, and timeout_seconds. Every URL and redirect is code-checked "
        "against the engagement brief; do not attempt an out-of-scope host. Preserve "
        "the stable cookie and User-Agent identity. Do not rotate headers or add "
        "cover traffic. Change a material request dimension only when evidence or a "
        "finite campaign calls for it. The enforced operational profile is: "
        + json.dumps(profile.to_json(), ensure_ascii=False, sort_keys=True)
    )


def _bounded_remote_config(
    config: GraphRouteConfig,
    *,
    brief: EngagementBrief,
) -> GraphRouteConfig:
    configured_cost = config.limits.max_cost_usd
    max_cost = (
        float(brief.budget.max_cost_usd)
        if configured_cost is None
        else min(configured_cost, float(brief.budget.max_cost_usd))
    )
    return replace(
        config,
        limits=replace(
            config.limits,
            max_cost_usd=max_cost,
            max_wall_seconds=min(
                config.limits.max_wall_seconds,
                max(int(brief.budget.max_runtime_min * 60), 1),
            ),
        ),
    )


def _expected_manifest(
    *,
    target_url: str,
    scope: Sequence[str],
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    objectives: tuple[GraphObjective, ...],
) -> _RemoteManifest:
    scope_digest = _digest_json(sorted(set(scope)))
    config_digest = _digest_json(config.to_json())
    objective_digest = _digest_json(
        {
            "root": root_objective.fingerprint,
            "seeds": sorted(objective.fingerprint for objective in objectives),
        }
    )
    identity = {
        "version": _MANIFEST_VERSION,
        "target_url": target_url,
        "scope_digest": scope_digest,
        "config_digest": config_digest,
        "objective_digest": objective_digest,
    }
    return _RemoteManifest(
        graph_id=f"remote-graph-{_digest_json(identity)[:24]}",
        target_url=target_url,
        scope_digest=scope_digest,
        config_digest=config_digest,
        objective_digest=objective_digest,
    )


def _load_manifest(path: Path) -> _RemoteManifest:
    if not path.is_file():
        raise RemoteGraphProductionError("remote graph state exists without its manifest")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemoteGraphProductionError(f"cannot read remote graph manifest: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise RemoteGraphProductionError("remote graph manifest must be an object")
    return _RemoteManifest.from_json(payload)


def _write_remote_receipt(
    path: Path,
    *,
    result: RemoteHttpGraphResult | None,
    run_error: BaseException | None,
    profile: GraphOperationalProfile,
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
        "operational_profile": profile.to_json(),
        "capabilities": ["http_request"],
        "shell_enabled": False,
        "browser_enabled": False,
    }
    selected_traffic = result.traffic if result is not None else traffic
    if selected_traffic is not None:
        payload["traffic"] = dict(selected_traffic)
    if result is not None:
        payload["graph"] = {
            "graph_id": result.graph.graph_id,
            "status": result.graph.status.value,
            "reason": result.run.reason,
            "resumed": result.resumed,
            "model_requests": result.graph.model_requests_started,
            "tool_calls": result.graph.tool_calls_started,
            "target_requests": result.target_requests,
            "cost_usd": result.graph.spent_cost_usd,
        }
    _write_json_atomic(path, payload)


async def _publish_remote_failure_receipts(
    *,
    receipt_path: Path,
    result: RemoteHttpGraphResult | None,
    run_error: BaseException,
    profile: GraphOperationalProfile,
    ownership: RunOwnershipGuard,
    ownership_epoch: int,
    owner_id: str,
    traffic: Mapping[str, object] | None = None,
) -> None:
    """Publish immutable failure evidence without clobbering a successor."""
    try:
        ownership.assert_owned()
    except Exception:  # noqa: BLE001 - unprovable ownership selects immutable-only output.
        ownership_proven = False
    else:
        ownership_proven = True
    owner_suffix = "".join(character for character in owner_id if character.isalnum())[-32:]
    unique_path = receipt_path.with_name(
        f"{receipt_path.stem}.epoch-{ownership_epoch:08d}-"
        f"{owner_suffix or 'unknown'}.error{receipt_path.suffix}"
    )
    release_status = "guarded_failure_pending_release" if ownership_proven else "ownership_unproven"
    for path in (unique_path, *((receipt_path,) if ownership_proven else ())):
        with suppress(Exception):
            await asyncio.to_thread(
                _write_remote_receipt,
                path,
                result=result,
                run_error=run_error,
                profile=profile,
                ownership_epoch=ownership_epoch,
                ownership_release_status=release_status,
                traffic=traffic,
            )


def _write_json_atomic(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _required_text(payload: Mapping[str, object], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise RemoteGraphProductionError(f"remote graph manifest {key} is required")
    return value


def _remote_traffic_policy(
    settings: AIWebAgentSettings,
    *,
    target_url: str,
) -> TrafficPolicyController | None:
    reference = getattr(settings, "traffic_policy_reference", None)
    if reference is None:
        if settings.traffic_policy_mode == "low-noise":
            raise RemoteGraphProductionError(
                "low-noise remote graph requires an existing whole-run traffic policy"
            )
        return None
    if not isinstance(reference, Mapping):
        raise RemoteGraphProductionError("traffic policy reference is invalid")
    try:
        controller = TrafficPolicyController.from_reference(
            reference,
            require_existing=True,
        )
    except (OSError, TrafficPolicyError, ValueError) as exc:
        detail = f"traffic policy binding failed: {exc}"
        raise RemoteGraphProductionError(detail) from exc
    expected = _origin_identity(target_url)
    actual = _origin_identity(controller.target_origin)
    if actual != expected:
        raise RemoteGraphProductionError("traffic policy belongs to a different target origin")
    return controller


def _origin_identity(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.hostname is None or parsed.scheme.casefold() not in {"http", "https"}:
        raise RemoteGraphProductionError("traffic policy target origin is invalid")
    port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    return parsed.scheme.casefold(), parsed.hostname.casefold(), port


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "RemoteGraphProductionError",
    "RemoteHttpGraphResult",
    "run_remote_http_graph_route",
]
