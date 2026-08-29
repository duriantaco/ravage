from __future__ import annotations

from pathlib import Path

import pytest
from ravage.agent_core import autonomous_route_selection
from ravage.agent_core.ai_agent import AIWebAgentSettings
from ravage.agent_core.autonomous_graph.adapter import GraphRouteConfig
from ravage.agent_core.autonomous_route_selection import run_selected_autonomous_route
from ravage.agent_core.frontier_route import FrontierRouteConfig

TARGET_URL = "http://127.0.0.1:8765/"
ROUTE_REQUESTS = 12
BASE_REQUESTS = 40
PROOF_RESERVE = 4


def test_agent_graph_selection_preserves_base_settings_and_builds_graph_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    expected = object()

    def graph_runner(**kwargs: object) -> object:
        captured.update(kwargs)
        return expected

    monkeypatch.setattr(
        autonomous_route_selection,
        "run_base_then_autonomous_graph_route",
        graph_runner,
    )
    settings = AIWebAgentSettings(max_turns=BASE_REQUESTS)

    result = run_selected_autonomous_route(
        engine="agent-graph",
        max_model_requests=ROUTE_REQUESTS,
        brief_path=Path("brief.yaml"),
        target_url=TARGET_URL,
        settings=settings,
    )

    assert result is expected
    assert captured["settings"] is settings
    config = captured["config"]
    assert isinstance(config, GraphRouteConfig)
    assert config.limits.max_model_requests == ROUTE_REQUESTS
    assert config.limits.max_tool_calls == ROUTE_REQUESTS * 4
    assert config.limits.proof_reserve_model_requests == PROOF_RESERVE
    assert settings.max_turns == BASE_REQUESTS


def test_frontier_selection_remains_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    expected = object()

    def frontier_runner(**kwargs: object) -> object:
        captured.update(kwargs)
        return expected

    monkeypatch.setattr(
        autonomous_route_selection,
        "run_base_then_autonomous_route",
        frontier_runner,
    )

    result = run_selected_autonomous_route(
        engine="frontier",
        max_model_requests=ROUTE_REQUESTS,
        brief_path=Path("brief.yaml"),
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(max_turns=BASE_REQUESTS),
    )

    assert result is expected
    config = captured["config"]
    assert isinstance(config, FrontierRouteConfig)
    assert config.max_model_requests == ROUTE_REQUESTS


def test_route_selection_rejects_unknown_engine_before_execution() -> None:
    with pytest.raises(ValueError, match="unsupported autonomous route engine"):
        run_selected_autonomous_route(
            engine="unknown",  # type: ignore[arg-type]
            max_model_requests=ROUTE_REQUESTS,
            brief_path=Path("brief.yaml"),
            target_url=TARGET_URL,
            settings=AIWebAgentSettings(),
        )
