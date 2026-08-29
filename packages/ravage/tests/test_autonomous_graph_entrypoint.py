from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.agent_core.ai_agent import AIWebAgentSettings
from ravage.agent_core.autonomous_graph.adapter import GraphRouteConfig
from ravage.agent_core.autonomous_graph.entrypoint import (
    run_base_then_autonomous_graph_route,
)
from ravage.agent_core.autonomous_graph.production import GraphProductionError
from ravage.agent_core.autonomous_route import (
    run_base_then_autonomous_graph_route as exported_graph_entrypoint,
)
from ravage.agent_core.frontier_route import BaseRouteOutcome
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import FakeToolRuntime
from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
ENGAGEMENT_ID = "99999999-9999-4999-9999-999999999999"
BASE_REQUESTS = 40
ROUTE_REQUESTS = 5
BASE_COST_USD = 0.5
ROUTE_COST_USD = 0.25


class CountingRuntime(FakeToolRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


@dataclass(frozen=True)
class FakeGraphResult:
    route_model_requests: int = ROUTE_REQUESTS
    route_cost_usd: float = ROUTE_COST_USD
    reason: str = "fixture_graph_finished"


def _write_brief(path: Path) -> None:
    path.write_text(
        f"""
engagement_id: "{ENGAGEMENT_ID}"
scope:
  in_scope:
    - "{TARGET_URL}"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "capture_flag"
budget:
  max_cost_usd: 3.0
  max_runtime_min: 10
context:
  description: "Authorized local web security exercise"
""".lstrip(),
        encoding="utf-8",
    )


def _finish_base(
    workspace_dir: Path,
    *,
    solved: bool = False,
    requests: int = BASE_REQUESTS,
    traffic_policy_config: TrafficPolicyConfig | None = None,
    traffic_policy_target_url: str = TARGET_URL,
) -> None:
    workspace = AgentWorkspace.open(workspace_dir)
    TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url=traffic_policy_target_url,
        config=traffic_policy_config or TrafficPolicyConfig(),
    )
    state = AgentState(
        turn=requests,
        flags=["flag{base-proof}"] if solved else [],
        facts=["search form accepts query"],
        signals={"endpoints": ["/search"], "parameters": ["query"]},
    )
    save_agent_state(
        workspace.state_path,
        target_url=TARGET_URL,
        state=state,
    )
    for turn in range(1, requests + 1):
        workspace.record_event(
            kind="model_request_started",
            payload={"turn": turn, "model_request_id": f"base-{turn}"},
        )
    workspace.record_event(
        kind="agent_finished",
        payload={
            "turns": requests,
            "flags": list(state.flags),
            "cost_usd": BASE_COST_USD,
        },
    )


def test_opt_in_entrypoint_runs_frozen_base_then_graph_without_changing_default(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    runtime = CountingRuntime()
    base_calls: list[AIWebAgentSettings] = []
    graph_calls: list[dict[str, object]] = []
    config = GraphRouteConfig()

    def base_runner(
        *,
        brief_path: Path,
        target_url: str,
        settings: AIWebAgentSettings,
    ) -> None:
        del brief_path
        assert target_url == TARGET_URL
        base_calls.append(settings)
        _finish_base(settings.workspace_dir or base_workspace)

    def graph_runner(**kwargs: object) -> FakeGraphResult:
        graph_calls.append(dict(kwargs))
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        assert settings.tool_runtime is base_calls[0].tool_runtime
        reference = settings.traffic_policy_reference
        assert reference is not None
        policy = TrafficPolicyController.from_reference(reference)
        assert policy.state_path == (base_workspace / "traffic-policy.json").absolute()
        assert policy.config == TrafficPolicyConfig()
        assert kwargs["config"] is config
        assert kwargs["workspace_dir"] == (base_workspace / "autonomous-route" / "agent-graph")
        return FakeGraphResult()

    result = run_base_then_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            recovery_profile="recovery-v1",
            tool_runtime=runtime,
        ),
        config=config,
        base_runner=base_runner,
        graph_runner=graph_runner,  # type: ignore[arg-type]
    )

    assert exported_graph_entrypoint is run_base_then_autonomous_graph_route
    assert len(base_calls) == 1
    assert base_calls[0].recovery_profile == "off"
    assert len(graph_calls) == 1
    assert result.route_entered is True
    assert result.route_resumed is False
    assert result.route_model_requests == ROUTE_REQUESTS
    assert result.total_model_requests == BASE_REQUESTS + ROUTE_REQUESTS
    assert result.total_cost_usd == BASE_COST_USD + ROUTE_COST_USD
    assert runtime.close_count == 1


def test_entrypoint_hands_low_noise_base_ledger_to_graph(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    expected_config = TrafficPolicyConfig.low_noise(
        max_physical_requests=23,
        max_rps=0.4,
    )
    graph_calls: list[dict[str, object]] = []

    def base_runner(**kwargs: object) -> None:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        assert settings.traffic_policy_reference is None
        _finish_base(
            settings.workspace_dir or base_workspace,
            traffic_policy_config=expected_config,
        )

    def graph_runner(**kwargs: object) -> FakeGraphResult:
        graph_calls.append(dict(kwargs))
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        reference = settings.traffic_policy_reference
        assert reference is not None
        policy = TrafficPolicyController.from_reference(reference)
        assert policy.state_path == (base_workspace / "traffic-policy.json").absolute()
        assert policy.config == expected_config
        return FakeGraphResult()

    result = run_base_then_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            tool_runtime=CountingRuntime(),
            traffic_policy_mode="low-noise",
            traffic_policy_max_physical_requests=23,
            traffic_policy_max_rps=0.4,
        ),
        base_runner=base_runner,
        graph_runner=graph_runner,  # type: ignore[arg-type]
    )

    assert len(graph_calls) == 1
    assert result.route_entered is True


@pytest.mark.parametrize("mismatch", ["identity", "config", "origin"])
def test_entrypoint_rejects_base_ledger_mismatch_before_graph_dispatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    if mismatch == "identity":
        _finish_base(base_workspace)
        alternate = TrafficPolicyController.open(
            tmp_path / "alternate-traffic-policy.json",
            target_url=TARGET_URL,
            config=TrafficPolicyConfig(),
        )
        settings = AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            tool_runtime=CountingRuntime(),
            traffic_policy_reference=alternate.to_reference(),
        )
    elif mismatch == "origin":
        _finish_base(
            base_workspace,
            traffic_policy_target_url="http://127.0.0.1:9999",
        )
        settings = AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            tool_runtime=CountingRuntime(),
        )
    else:
        _finish_base(base_workspace)
        settings = AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            tool_runtime=CountingRuntime(),
            traffic_policy_mode="low-noise",
            traffic_policy_max_physical_requests=23,
            traffic_policy_max_rps=0.4,
        )
    graph_calls: list[dict[str, object]] = []

    def graph_runner(**kwargs: object) -> FakeGraphResult:
        graph_calls.append(dict(kwargs))
        return FakeGraphResult()

    with pytest.raises(GraphProductionError, match="base traffic policy handoff is invalid"):
        run_base_then_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=settings,
            graph_runner=graph_runner,  # type: ignore[arg-type]
        )

    assert graph_calls == []


def test_entrypoint_rejects_managed_identity_policy_mismatch_before_graph_dispatch(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    _finish_base(base_workspace)
    graph_calls: list[dict[str, object]] = []

    class RejectingAuthentication:
        def assert_traffic_policy(self, _policy: TrafficPolicyController) -> None:
            message = "fixture identity mismatch"
            raise RuntimeError(message)

    def graph_runner(**kwargs: object) -> FakeGraphResult:
        graph_calls.append(dict(kwargs))
        return FakeGraphResult()

    with pytest.raises(GraphProductionError, match="does not match the managed identity"):
        run_base_then_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=AIWebAgentSettings(
                workspace_dir=base_workspace,
                max_turns=BASE_REQUESTS,
                tool_runtime=CountingRuntime(),
                authentication=RejectingAuthentication(),  # type: ignore[arg-type]
            ),
            graph_runner=graph_runner,  # type: ignore[arg-type]
        )

    assert graph_calls == []


def test_solved_base_never_enters_opt_in_graph(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    runtime = CountingRuntime()

    def base_runner(**kwargs: object) -> None:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        _finish_base(
            settings.workspace_dir or base_workspace,
            solved=True,
            requests=3,
        )

    def graph_runner(**_kwargs: object) -> FakeGraphResult:
        message = "graph must not run after base proof"
        raise AssertionError(message)

    result = run_base_then_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            tool_runtime=runtime,
        ),
        base_runner=base_runner,
        graph_runner=graph_runner,  # type: ignore[arg-type]
    )

    assert result.route_entered is False
    assert result.reason == "base_proof_confirmed"
    assert runtime.close_count == 1


def test_existing_graph_state_resumes_without_rerunning_base(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    _finish_base(base_workspace)
    graph_workspace = base_workspace / "autonomous-route" / "agent-graph"
    graph_workspace.mkdir(parents=True)
    (graph_workspace / "graph-state.json").write_text("{}\n", encoding="utf-8")
    runtime = CountingRuntime()
    calls = 0

    def base_runner(**_kwargs: object) -> None:
        message = "completed base must not rerun"
        raise AssertionError(message)

    def graph_runner(**kwargs: object) -> FakeGraphResult:
        nonlocal calls
        calls += 1
        base = kwargs["base"]
        assert isinstance(base, BaseRouteOutcome)
        return FakeGraphResult()

    result = run_base_then_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            tool_runtime=runtime,
        ),
        base_runner=base_runner,
        graph_runner=graph_runner,  # type: ignore[arg-type]
    )

    assert calls == 1
    assert result.base_ran is False
    assert result.route_entered is True
    assert result.route_resumed is True
    assert runtime.close_count == 1
