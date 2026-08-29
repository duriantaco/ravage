from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _open_run_traffic_policy,
    run_ai_web_agent,
)
from ravage.agent_core.autonomous_graph.production import (
    GraphProductionError,
    ProductionGraphRouteResult,
    run_autonomous_graph_route,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    route_eligibility,
)
from ravage.agent_core.frontier_runtime_handoff import prepare_frontier_runtime
from ravage.agent_core.frontier_shared_runtime import (
    SharedToolRuntime,
    make_shared_tool_runtime,
)
from ravage.agent_core.frontier_transition import inspect_base_route
from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.workspace import AgentWorkspace
from ravage.traffic.policy import TrafficPolicyController, TrafficPolicyError

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.adapter import GraphRouteConfig


class GraphBaseRunner(Protocol):
    def __call__(
        self,
        *,
        brief_path: Path,
        target_url: str,
        settings: AIWebAgentSettings,
    ) -> None: ...


class AutonomousGraphRunner(Protocol):
    def __call__(  # noqa: PLR0913 - mirrors the route adapter boundary.
        self,
        *,
        brief_path: Path,
        target_url: str,
        base: BaseRouteOutcome,
        settings: AIWebAgentSettings,
        workspace_dir: Path,
        config: GraphRouteConfig | None = None,
    ) -> ProductionGraphRouteResult: ...


@dataclass(frozen=True)
class BaseThenGraphResult:
    """Frozen-base outcome plus an optional opt-in graph-route result."""

    base: BaseRouteOutcome
    route: ProductionGraphRouteResult | None
    base_ran: bool
    route_entered: bool
    route_resumed: bool
    reason: str

    @property
    def route_model_requests(self) -> int:
        return self.route.route_model_requests if self.route is not None else 0

    @property
    def total_model_requests(self) -> int:
        return self.base.model_requests + self.route_model_requests

    @property
    def base_cost_usd(self) -> float:
        return self.base.cost_usd

    @property
    def route_cost_usd(self) -> float:
        return self.route.route_cost_usd if self.route is not None else 0.0

    @property
    def total_cost_usd(self) -> float:
        return self.base_cost_usd + self.route_cost_usd


def run_base_then_autonomous_graph_route(  # noqa: PLR0913 - public boundary.
    *,
    brief_path: Path,
    target_url: str,
    settings: AIWebAgentSettings,
    config: GraphRouteConfig | None = None,
    base_runner: GraphBaseRunner = run_ai_web_agent,
    graph_runner: AutonomousGraphRunner = run_autonomous_graph_route,
) -> BaseThenGraphResult:
    """
    Run the frozen base, then independently enter the opt-in agent graph.

    This is intentionally separate from run_base_then_autonomous_route so the
    serial frontier remains the default until graph evidence earns promotion.
    """
    brief = load_engagement_brief(brief_path)
    base_workspace = settings.workspace_dir or Path("runs/ravage-agent/workspace")
    graph_workspace = base_workspace / "autonomous-route" / "agent-graph"
    graph_state_exists = (graph_workspace / "graph-state.json").exists()
    base_ran = False
    shared_runtime: SharedToolRuntime | None = None

    try:
        if _base_artifacts_exist(base_workspace):
            base = inspect_base_route(
                base_workspace,
                target_url=target_url,
                max_model_requests=settings.max_turns,
            )
        else:
            shared_runtime = make_shared_tool_runtime(
                settings,
                brief,
                session_role="base",
            )
            base_settings = replace(
                settings,
                recovery_profile="off",
                tool_runtime=shared_runtime,
                autonomous_route=True,
            )
            try:
                base_runner(
                    brief_path=brief_path,
                    target_url=target_url,
                    settings=base_settings,
                )
            except BaseException as exc:
                inspect_base_route(
                    base_workspace,
                    target_url=target_url,
                    max_model_requests=settings.max_turns,
                    run_error=exc,
                )
                raise
            base_ran = True
            base = inspect_base_route(
                base_workspace,
                target_url=target_url,
                max_model_requests=settings.max_turns,
            )

        eligibility = route_eligibility(
            base,
            route_state_exists=graph_state_exists,
        )
        if not eligibility.enter and not eligibility.resume:
            return BaseThenGraphResult(
                base=base,
                route=None,
                base_ran=base_ran,
                route_entered=False,
                route_resumed=False,
                reason=eligibility.reason,
            )

        traffic_policy_reference = _base_traffic_policy_reference(
            settings=settings,
            base=base,
            target_url=target_url,
            roe_max_rps=brief.roe.max_rps,
        )
        handoff = prepare_frontier_runtime(
            settings=settings,
            brief=brief,
            workspace_dir=graph_workspace,
            base_runtime=shared_runtime,
        )
        if not handoff.verified or handoff.runtime is None:
            return BaseThenGraphResult(
                base=base,
                route=None,
                base_ran=base_ran,
                route_entered=False,
                route_resumed=False,
                reason=handoff.reason,
            )
        shared_runtime = handoff.runtime
        route_settings = replace(
            settings,
            recovery_profile="off",
            tool_runtime=shared_runtime,
            traffic_policy_reference=traffic_policy_reference,
        )
        route = graph_runner(
            brief_path=brief_path,
            target_url=target_url,
            base=base,
            settings=route_settings,
            workspace_dir=graph_workspace,
            config=config,
        )
        return BaseThenGraphResult(
            base=base,
            route=route,
            base_ran=base_ran,
            route_entered=True,
            route_resumed=eligibility.resume,
            reason=route.reason,
        )
    finally:
        if shared_runtime is not None:
            shared_runtime.shutdown()


def _base_artifacts_exist(workspace_dir: Path) -> bool:
    return any(
        path.exists()
        for path in (
            workspace_dir / "working_state.json",
            workspace_dir / "events.jsonl",
            workspace_dir / "transcript.jsonl",
        )
    )


def _base_traffic_policy_reference(
    *,
    settings: AIWebAgentSettings,
    base: BaseRouteOutcome,
    target_url: str,
    roe_max_rps: float,
) -> dict[str, object]:
    """Resolve and verify the base run's controller before graph dispatch."""
    base_workspace = AgentWorkspace.open(Path(base.state_ref).expanduser().absolute().parent)
    try:
        controller = _open_base_traffic_policy(
            settings=settings,
            base_workspace=base_workspace,
            target_url=target_url,
            roe_max_rps=roe_max_rps,
        )
    except (OSError, TrafficPolicyError, ValueError) as exc:
        detail = f"base traffic policy handoff is invalid: {exc}"
        raise GraphProductionError(detail) from exc

    authentication = settings.authentication
    if authentication is not None:
        try:
            authentication.assert_traffic_policy(controller)
        except Exception as exc:
            message = "base traffic policy handoff does not match the managed identity"
            raise GraphProductionError(message) from exc
    return controller.to_reference()


def _open_base_traffic_policy(
    *,
    settings: AIWebAgentSettings,
    base_workspace: AgentWorkspace,
    target_url: str,
    roe_max_rps: float,
) -> TrafficPolicyController:
    controller = _open_run_traffic_policy(
        settings=settings,
        workspace=base_workspace,
        target_url=target_url,
        roe_max_rps=roe_max_rps,
    )
    ledger_path = base_workspace.root / "traffic-policy.json"
    if settings.traffic_policy_reference is None:
        if controller.state_path.resolve(strict=True) == ledger_path.resolve(strict=True):
            return controller
        message = "derived traffic policy does not use the canonical base workspace ledger"
        raise TrafficPolicyError(message)

    if not ledger_path.is_file():
        return controller
    run_owned = _open_run_traffic_policy(
        settings=replace(settings, traffic_policy_reference=None),
        workspace=base_workspace,
        target_url=target_url,
        roe_max_rps=roe_max_rps,
    )
    if _traffic_policy_binding(controller) != _traffic_policy_binding(run_owned):
        message = "traffic policy reference does not match the canonical base run ledger"
        raise TrafficPolicyError(message)
    return run_owned


def _traffic_policy_binding(
    controller: TrafficPolicyController,
) -> tuple[Path, object, str]:
    return (
        controller.state_path.resolve(strict=True),
        controller.config,
        controller.target_origin,
    )


__all__ = [
    "AutonomousGraphRunner",
    "BaseThenGraphResult",
    "GraphBaseRunner",
    "run_base_then_autonomous_graph_route",
]
