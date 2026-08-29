from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_engine import FrontierEngine, FrontierModelReply
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
    FrontierObjective,
    FrontierRoute,
    FrontierRouteConfig,
    FrontierRouteStatus,
)
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path

ROUTE_REQUESTS = 3
ROUTE_COST_USD = 0.03
REJECTED_ACTIONS = 2


def test_drift_is_charged_but_not_executed_and_handoff_requires_aligned_action(
    tmp_path: Path,
) -> None:
    target_url = "http://127.0.0.1:8765"
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
        expected_signal=(
            "The default run_probe sqli_exploit route is exhausted; do not rerun it unchanged."
        ),
    )
    route = FrontierRoute.start(
        base=BaseRouteOutcome(
            target_url=target_url,
            termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
            model_requests=40,
            state_digest="base-state",
        ),
        initial_objective=objective,
        scope=(target_url,),
        config=FrontierRouteConfig(
            max_model_requests=3,
            scout_lease=3,
            counterfactual_lease=3,
            proof_lease=3,
            max_workers=1,
            repeated_observation_limit=2,
            repeated_low_value_route_limit=2,
        ),
    )
    replies = iter(
        [
            FrontierModelReply(
                content=json.dumps(
                    {
                        "action": "run_command",
                        "command": "curl http://target/upload.php.bak",
                    }
                ),
                cost_usd=0.01,
            ),
            FrontierModelReply(
                content='{"action":"final","summary":"route exhausted"}',
                cost_usd=0.01,
            ),
            FrontierModelReply(
                content=json.dumps(
                    {
                        "action": "run_python",
                        "code": (
                            "data=urlencode({'username': user}); "
                            "Request(base+'index.php', data=data, method='POST')"
                        ),
                    }
                ),
                cost_usd=0.01,
            ),
        ]
    )
    model_calls: list[list[dict[str, str]]] = []

    def complete(messages: list[dict[str, str]]) -> FrontierModelReply:
        model_calls.append(messages)
        return next(replies)

    executed: list[dict[str, object]] = []

    def execute(
        action: dict[str, object],
        *,
        repeat_count: int,
        action_id: str,
    ) -> ActionResult:
        del repeat_count, action_id
        executed.append(action)
        return ActionResult(
            ok=True,
            observation="POST index.php accepted username field without proof",
            outcome="observed",
            evidence_source_kind="tool_run_python",
            evidence_observation="POST index.php accepted username field without proof",
        )

    state = AgentState(
        turn=40,
        facts=[
            "Confirmed SQLi on index.php username.",
            "A direct_exposure backup branch was recently preferred.",
        ],
    )
    engine = FrontierEngine(
        route=route,
        state=state,
        objectives=(objective,),
        workspace=AgentWorkspace.open(tmp_path / "frontier-workspace"),
        complete=complete,
        execute=execute,
    )

    result = engine.run()

    assert result.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert result.model_requests_started == ROUTE_REQUESTS
    assert result.model_requests_completed == ROUTE_REQUESTS
    assert result.spent_cost_usd == pytest.approx(ROUTE_COST_USD)
    assert len(executed) == 1
    assert executed[0]["action"] == "run_python"
    assert len(state.attempts) == 1
    assert state.attempts[0]["frontier_objective_aligned"] is True
    assert "backup" not in json.dumps(model_calls[0]).lower()
    assert "model request remains charged" in json.dumps(model_calls[1]).lower()
    assert "handoff_before_aligned_action" in json.dumps(model_calls[2]).lower()
    events = [
        json.loads(line)
        for line in engine.workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    rejected = [
        event for event in events if event["kind"] == "frontier_objective_alignment_rejected"
    ]
    assert len(rejected) == REJECTED_ACTIONS
