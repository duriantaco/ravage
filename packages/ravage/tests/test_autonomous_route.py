from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from ravage.agent_core import autonomous_route
from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.agent_core.ai_agent import AIWebAgentSettings
from ravage.agent_core.autonomous_route import run_base_then_autonomous_route
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    FrontierObjective,
    FrontierRoute,
    FrontierRouteConfig,
    FrontierRouteStatus,
)
from ravage.agent_core.frontier_runtime_handoff import FrontierRuntimeHandoff
from ravage.agent_core.frontier_shared_runtime import SharedToolRuntime
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import FakeToolRuntime

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
ENGAGEMENT_ID = "99999999-9999-4999-9999-999999999999"
BASE_REQUESTS = 40
ROUTE_REQUESTS = 5


class CountingRuntime(FakeToolRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


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
) -> None:
    workspace = AgentWorkspace.open(workspace_dir)
    state = AgentState(
        turn=requests,
        flags=["flag{base-proof}"] if solved else [],
        facts=["search form accepts a query parameter"],
        signals={"endpoints": ["/search"], "parameters": ["query"]},
    )
    save_agent_state(workspace.state_path, target_url=TARGET_URL, state=state)
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
            "cost_usd": 0.5,
        },
    )


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_differential",
        endpoint="/search",
        inputs=("query",),
        payload_class="specialist:sqli_differential",
        expected_signal="target-observed SQL differential",
        evidence_refs=("base-state:test",),
    )


def _finished_route(base: BaseRouteOutcome) -> FrontierRoute:
    route = FrontierRoute.start(
        base=base,
        initial_objective=_objective(),
        scope=(TARGET_URL,),
    )
    route.model_requests_started = ROUTE_REQUESTS
    route.model_requests_completed = ROUTE_REQUESTS
    route.status = FrontierRouteStatus.FRONTIER_EXHAUSTED
    route.active_worker_id = None
    route.last_reason = "test_route_finished"
    return route


def test_frozen_base_runs_first_then_enters_the_autonomous_route(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_calls: list[AIWebAgentSettings] = []
    route_calls: list[dict[str, object]] = []
    runtime = CountingRuntime()
    base_workspace = tmp_path / "base-workspace"

    def base_runner(
        *,
        brief_path: Path,
        target_url: str,
        settings: AIWebAgentSettings,
    ) -> None:
        del brief_path
        assert target_url == TARGET_URL
        base_calls.append(settings)
        assert settings.tool_runtime is not None
        settings.tool_runtime.close()
        _finish_base(settings.workspace_dir or base_workspace)

    def frontier_runner(**kwargs: object) -> FrontierRoute:
        route_calls.append(dict(kwargs))
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        assert settings.tool_runtime is base_calls[0].tool_runtime
        settings.tool_runtime.close()
        base = kwargs["base"]
        assert isinstance(base, BaseRouteOutcome)
        return _finished_route(base)

    result = run_base_then_autonomous_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            recovery_profile="recovery-v1",
            tool_runtime=runtime,
        ),
        base_runner=base_runner,
        frontier_runner=frontier_runner,
    )

    assert len(base_calls) == 1
    assert base_calls[0].max_turns == BASE_REQUESTS
    assert base_calls[0].recovery_profile == "off"
    assert len(route_calls) == 1
    assert result.route_entered is True
    assert result.route_resumed is False
    assert result.base.model_requests == BASE_REQUESTS
    assert result.route_model_requests == ROUTE_REQUESTS
    assert result.total_model_requests == BASE_REQUESTS + ROUTE_REQUESTS
    assert runtime.close_count == 1


def test_solved_base_never_enters_the_route(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    runtime = CountingRuntime()

    def base_runner(**kwargs: object) -> None:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        _finish_base(settings.workspace_dir or base_workspace, solved=True, requests=3)

    def frontier_runner(**_kwargs: object) -> FrontierRoute:
        message = "route must not run after base proof"
        raise AssertionError(message)

    result = run_base_then_autonomous_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            tool_runtime=runtime,
        ),
        base_runner=base_runner,
        frontier_runner=frontier_runner,
    )

    assert result.route_entered is False
    assert result.reason == "base_proof_confirmed"
    assert runtime.close_count == 1


def test_base_error_is_re_raised_and_never_enters_the_route(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    runtime = CountingRuntime()

    def base_runner(**kwargs: object) -> None:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        workspace = AgentWorkspace.open(settings.workspace_dir or tmp_path / "base")
        save_agent_state(
            workspace.state_path,
            target_url=TARGET_URL,
            state=AgentState(turn=1),
        )
        message = "provider quota exhausted"
        raise RuntimeError(message)

    def frontier_runner(**_kwargs: object) -> FrontierRoute:
        message = "route must not hide base errors"
        raise AssertionError(message)

    with pytest.raises(RuntimeError, match="quota exhausted"):
        run_base_then_autonomous_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=AIWebAgentSettings(
                workspace_dir=tmp_path / "base-workspace",
                tool_runtime=runtime,
            ),
            base_runner=base_runner,
            frontier_runner=frontier_runner,
        )

    assert runtime.close_count == 1


def test_existing_terminal_base_and_route_state_resume_without_rerunning_base(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    _finish_base(base_workspace)
    route_workspace = base_workspace / "autonomous-route"
    route_workspace.mkdir(parents=True)
    (route_workspace / "frontier-route.json").write_text("{}\n", encoding="utf-8")
    runtime = CountingRuntime()
    route_calls = 0

    def base_runner(**_kwargs: object) -> None:
        message = "completed base must not rerun"
        raise AssertionError(message)

    def frontier_runner(**kwargs: object) -> FrontierRoute:
        nonlocal route_calls
        route_calls += 1
        base = kwargs["base"]
        assert isinstance(base, BaseRouteOutcome)
        return _finished_route(base)

    result = run_base_then_autonomous_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            tool_runtime=runtime,
        ),
        base_runner=base_runner,
        frontier_runner=frontier_runner,
    )

    assert route_calls == 1
    assert result.base_ran is False
    assert result.route_entered is True
    assert result.route_resumed is True
    assert runtime.close_count == 1


def test_partial_base_workspace_is_not_blindly_replayed_or_escalated(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    workspace = AgentWorkspace.open(base_workspace)
    save_agent_state(
        workspace.state_path,
        target_url=TARGET_URL,
        state=AgentState(turn=7),
    )
    runtime = CountingRuntime()

    def base_runner(**_kwargs: object) -> None:
        message = "partial base requires explicit operator resume"
        raise AssertionError(message)

    def frontier_runner(**_kwargs: object) -> FrontierRoute:
        message = "partial base cannot enter the route"
        raise AssertionError(message)

    result = run_base_then_autonomous_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            tool_runtime=runtime,
        ),
        base_runner=base_runner,
        frontier_runner=frontier_runner,
    )

    assert result.base_ran is False
    assert result.route_entered is False
    assert result.reason.startswith("base_stop_not_eligible:interrupted")
    assert runtime.close_count == 0


def test_route_config_is_passed_without_increasing_the_frozen_base_budget(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    runtime = CountingRuntime()
    config = FrontierRouteConfig(max_model_requests=12, proof_lease=12)
    received: list[FrontierRouteConfig] = []

    def base_runner(**kwargs: object) -> None:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        assert settings.max_turns == BASE_REQUESTS
        _finish_base(settings.workspace_dir or base_workspace)

    def frontier_runner(**kwargs: object) -> FrontierRoute:
        received_config = kwargs["config"]
        assert isinstance(received_config, FrontierRouteConfig)
        received.append(received_config)
        base = kwargs["base"]
        assert isinstance(base, BaseRouteOutcome)
        return _finished_route(base)

    run_base_then_autonomous_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            tool_runtime=runtime,
        ),
        config=config,
        base_runner=base_runner,
        frontier_runner=frontier_runner,
    )

    assert received == [config]


def test_unverified_runtime_handoff_spends_no_route_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    runtime = CountingRuntime()
    route_calls = 0

    def base_runner(**kwargs: object) -> None:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        _finish_base(settings.workspace_dir or base_workspace)

    def frontier_runner(**kwargs: object) -> FrontierRoute:
        del kwargs
        nonlocal route_calls
        route_calls += 1
        message = "unverified handoff must not enter the route"
        raise AssertionError(message)

    monkeypatch.setattr(
        autonomous_route,
        "prepare_frontier_runtime",
        lambda **_kwargs: FrontierRuntimeHandoff(
            runtime=None,
            verified=False,
            rotated=False,
            reason="route_handoff_hygiene_unverified",
        ),
    )

    result = run_base_then_autonomous_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            workspace_dir=base_workspace,
            max_turns=BASE_REQUESTS,
            tool_runtime=runtime,
        ),
        base_runner=base_runner,
        frontier_runner=frontier_runner,
    )

    assert route_calls == 0
    assert result.route_entered is False
    assert result.route_model_requests == 0
    assert result.total_model_requests == BASE_REQUESTS
    assert result.reason == "route_handoff_hygiene_unverified"


def test_verified_runtime_handoff_passes_distinct_runtime_to_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base_workspace = tmp_path / "base-workspace"
    base_inner = CountingRuntime()
    route_inner = CountingRuntime()
    base_runtime = SharedToolRuntime(base_inner, factory_owned=True, session_role="base")
    route_runtime = SharedToolRuntime(route_inner, factory_owned=True, session_role="frontier")

    monkeypatch.setattr(
        autonomous_route,
        "make_shared_tool_runtime",
        lambda *_args, **_kwargs: base_runtime,
    )

    def handoff(**kwargs: object) -> FrontierRuntimeHandoff:
        assert kwargs["base_runtime"] is base_runtime
        return FrontierRuntimeHandoff(
            runtime=route_runtime,
            verified=True,
            rotated=True,
            reason="frontier_runtime_rotated",
        )

    monkeypatch.setattr(autonomous_route, "prepare_frontier_runtime", handoff)

    def base_runner(**kwargs: object) -> None:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        assert settings.tool_runtime is base_runtime
        _finish_base(settings.workspace_dir or base_workspace)

    def frontier_runner(**kwargs: object) -> FrontierRoute:
        settings = kwargs["settings"]
        assert isinstance(settings, AIWebAgentSettings)
        assert settings.tool_runtime is route_runtime
        assert settings.tool_runtime is not base_runtime
        base = kwargs["base"]
        assert isinstance(base, BaseRouteOutcome)
        return _finished_route(base)

    result = run_base_then_autonomous_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(workspace_dir=base_workspace),
        base_runner=base_runner,
        frontier_runner=frontier_runner,
    )

    assert result.route_entered is True
    assert base_inner.close_count == 0
    assert route_inner.close_count == 1
