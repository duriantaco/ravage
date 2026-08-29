from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from ravage.agent_core.ai_agent import AIWebAgentSettings, run_ai_web_agent
from ravage.agent_core.autonomous_graph.entrypoint import (
    BaseThenGraphResult,
    run_base_then_autonomous_graph_route,
)
from ravage.agent_core.frontier_adapter import run_frontier_route
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    FrontierRoute,
    FrontierRouteConfig,
    route_eligibility,
)
from ravage.agent_core.frontier_runtime_handoff import prepare_frontier_runtime
from ravage.agent_core.frontier_shared_runtime import (
    SharedToolRuntime,
    make_shared_tool_runtime,
)
from ravage.agent_core.frontier_transition import inspect_base_route
from ravage.run_data.brief import load_engagement_brief


class BaseRunner(Protocol):
    def __call__(
        self,
        *,
        brief_path: Path,
        target_url: str,
        settings: AIWebAgentSettings,
    ) -> None: ...


class FrontierRunner(Protocol):
    def __call__(  # noqa: PLR0913 - mirrors the route adapter boundary.
        self,
        *,
        brief_path: Path,
        target_url: str,
        base: BaseRouteOutcome,
        settings: AIWebAgentSettings,
        workspace_dir: Path,
        config: FrontierRouteConfig,
    ) -> FrontierRoute: ...


@dataclass(frozen=True)
class AutonomousRouteResult:
    base: BaseRouteOutcome
    route: FrontierRoute | None
    base_ran: bool
    route_entered: bool
    route_resumed: bool
    reason: str

    @property
    def route_model_requests(self) -> int:
        return self.route.model_requests_started if self.route is not None else 0

    @property
    def total_model_requests(self) -> int:
        return self.base.model_requests + self.route_model_requests

    @property
    def base_cost_usd(self) -> float:
        return self.base.cost_usd

    @property
    def route_cost_usd(self) -> float:
        return self.route.spent_cost_usd if self.route is not None else 0.0

    @property
    def total_cost_usd(self) -> float:
        return self.base_cost_usd + self.route_cost_usd


def run_base_then_autonomous_route(  # noqa: PLR0913 - public orchestration boundary.
    *,
    brief_path: Path,
    target_url: str,
    settings: AIWebAgentSettings,
    config: FrontierRouteConfig | None = None,
    base_runner: BaseRunner = run_ai_web_agent,
    frontier_runner: FrontierRunner = run_frontier_route,
) -> AutonomousRouteResult:
    """Run the frozen base first, then enter or resume one bounded route."""
    brief = load_engagement_brief(brief_path)
    base_workspace = settings.workspace_dir or Path("runs/ravage-agent/workspace")
    route_workspace = base_workspace / "autonomous-route"
    route_state_exists = (route_workspace / "frontier-route.json").exists()
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
            route_state_exists=route_state_exists,
        )
        if not eligibility.enter and not eligibility.resume:
            return AutonomousRouteResult(
                base=base,
                route=None,
                base_ran=base_ran,
                route_entered=False,
                route_resumed=False,
                reason=eligibility.reason,
            )

        handoff = prepare_frontier_runtime(
            settings=settings,
            brief=brief,
            workspace_dir=route_workspace,
            base_runtime=shared_runtime,
        )
        if not handoff.verified or handoff.runtime is None:
            return AutonomousRouteResult(
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
        )
        route = frontier_runner(
            brief_path=brief_path,
            target_url=target_url,
            base=base,
            settings=route_settings,
            workspace_dir=route_workspace,
            config=config or FrontierRouteConfig(),
        )
        return AutonomousRouteResult(
            base=base,
            route=route,
            base_ran=base_ran,
            route_entered=True,
            route_resumed=eligibility.resume,
            reason=route.last_reason,
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


__all__ = [
    "AutonomousRouteResult",
    "BaseThenGraphResult",
    "run_base_then_autonomous_graph_route",
    "run_base_then_autonomous_route",
]
