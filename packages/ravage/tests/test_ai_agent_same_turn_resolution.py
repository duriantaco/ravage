from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from ai_agent_fixtures import BRIEF_YAML, ScriptedModelClient
from ravage.agent_core import ai_agent
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _captured_proof_count,
    _final_is_premature,
    _resolve_same_turn_harness_action,
    run_ai_web_agent,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    import pytest
    from ravage.auth.runtime import ManagedAttackAuthentication


def test_premature_final_uses_open_surface_route_in_the_same_turn() -> None:
    state = AgentState(turn=3)
    state.surface["flag_objective"] = False
    state.tasks = [_task("surface-map", priority=100)]

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action={"action": "final", "summary": "stop"},
        selected_action={
            "action": "invalid",
            "error": "final is premature while required assessment work remains",
        },
        turn=3,
        max_turns=40,
        settings=AIWebAgentSettings(),
    )

    assert reason == "premature_final_open_task_fallback"
    assert selected["action"] == "run_probe"
    assert selected["probe"] == "surface_map"
    assert selected["task_id"] == "surface-map"


def test_injected_model_final_uses_open_surface_route_in_the_same_turn() -> None:
    state = AgentState(turn=3)
    state.surface["flag_objective"] = False
    state.tasks = [_task("surface-map", priority=100)]
    proposed = {"action": "final", "summary": "stop"}

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=3,
        max_turns=40,
        settings=AIWebAgentSettings(),
    )

    assert reason == "premature_final_required_work_fallback"
    assert selected["action"] == "run_probe"
    assert selected["probe"] == "surface_map"
    assert selected["task_id"] == "surface-map"


def test_locked_primitive_precedes_a_higher_priority_open_recon_task() -> None:
    state = AgentState(turn=4)
    state.surface["flag_objective"] = False
    state.tasks = [
        _task("surface-map", priority=100),
        _task("data-query", priority=60),
    ]
    state.primitives["sqli_confirmed"] = 4

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action={"action": "final", "summary": "stop"},
        selected_action={
            "action": "invalid",
            "error": "final is premature while required assessment work remains",
        },
        turn=4,
        max_turns=40,
        settings=AIWebAgentSettings(),
    )

    assert reason == "premature_final_open_task_fallback"
    assert selected["probe"] == "sqli_exploit"
    assert selected["task_id"] == "data-query"


def test_pending_closure_obligation_prevents_synthesized_final(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentState(turn=5)
    state.surface["flag_objective"] = False
    state.tasks = [_task("surface-map", priority=100, status="done")]
    proposed = {"action": "run_probe", "probe": "surface_map"}
    monkeypatch.setattr(ai_agent, "pending_closure_obligation", lambda _state: object())

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=5,
        max_turns=40,
        settings=AIWebAgentSettings(),
    )

    assert selected == proposed
    assert reason is None


def test_pending_closure_obligation_rejects_an_injected_model_final(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentState(turn=5)
    state.surface["flag_objective"] = False
    state.tasks = [_task("data-query", priority=100, status="done")]
    proposed = {"action": "final", "summary": "stop early"}
    monkeypatch.setattr(ai_agent, "pending_closure_obligation", lambda _state: object())

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=5,
        max_turns=40,
        settings=AIWebAgentSettings(),
    )

    assert selected["action"] == "invalid"
    assert reason == "premature_final_required_work_guard"


def test_live_tier_one_primitive_prevents_synthesized_final() -> None:
    state = AgentState(turn=5)
    state.surface["flag_objective"] = False
    state.tasks = [_task("api-behavior", priority=100, status="done")]
    state.primitives["jwt_observed"] = 5
    proposed = {"action": "run_probe", "probe": "surface_map"}

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=5,
        max_turns=40,
        settings=AIWebAgentSettings(),
    )

    assert selected == proposed
    assert reason is None


def test_injected_model_final_cannot_skip_a_live_primitive_route() -> None:
    state = AgentState(turn=5)
    state.surface["flag_objective"] = False
    state.tasks = [_task("api-behavior", priority=100, status="done")]
    state.primitives["jwt_observed"] = 5
    proposed = {"action": "final", "summary": "stop"}

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=5,
        max_turns=40,
        settings=AIWebAgentSettings(),
    )

    assert selected["action"] != "final"
    assert reason == "premature_final_required_work_guard"


def test_auth_unavailable_live_route_does_not_cost_an_extra_model_turn() -> None:
    state = AgentState(turn=5)
    state.surface["flag_objective"] = False
    state.tasks = [_task("api-behavior", priority=100, status="done")]
    state.primitives["browser_boundary_confirmed"] = 5
    proposed = {"action": "run_probe", "probe": "surface_map"}
    authentication = cast("ManagedAttackAuthentication", object())

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=5,
        max_turns=40,
        settings=AIWebAgentSettings(authentication=authentication),
    )

    assert selected["action"] == "final"
    assert reason == "assessment_complete_terminal"


def test_expected_proof_count_blocks_terminal_and_counts_unique_proofs() -> None:
    state = AgentState(
        turn=5,
        flags=["flag{one}", " flag{one} "],
        surface={
            "flag_objective": True,
            "continue_after_proof": True,
            "expected_proof_count": 2,
        },
        tasks=[_task("data-query", priority=100, status="done")],
    )
    proposed = {"action": "run_probe", "probe": "surface_map"}

    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=5,
        max_turns=5,
        settings=AIWebAgentSettings(),
    )

    assert _captured_proof_count(state) == 1
    assert selected == proposed
    assert reason is None
    assert _final_is_premature(
        action={"action": "final"},
        state=state,
        turn=5,
        max_turns=5,
    )

    state.flags.append("flag{two}")
    selected, reason = _resolve_same_turn_harness_action(
        state=state,
        proposed_action=proposed,
        selected_action=proposed,
        turn=5,
        max_turns=5,
        settings=AIWebAgentSettings(),
    )

    assert _captured_proof_count(state) == 2
    assert selected["action"] == "final"
    assert reason == "assessment_complete_terminal"


def test_injected_model_final_cannot_bypass_required_proof_count(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(ai_agent, "_seed_recon", _seed_one_existing_proof)
    monkeypatch.setattr(ai_agent, "refresh_mission_board", lambda *_args, **_kwargs: None)
    model = ScriptedModelClient([{"action": "final", "summary": "one is enough"}])
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML + "context:\n  expected_proof_count: 2\n",
        encoding="utf-8",
    )

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            max_turns=1,
        ),
    )

    events = _events(tmp_path / "workspace" / "events.jsonl")
    selection = next(event for event in events if event["kind"] == "harness_selection")
    assert selection["payload"]["selected_action"]["action"] == "invalid"
    assert not any(event["kind"] == "agent_final" for event in events)
    finished = next(event["payload"] for event in events if event["kind"] == "agent_finished")
    assert finished["status"] == "incomplete"
    assert finished["termination_reason"] == "max_turns_reached"
    assert finished["flag_objective"] is True
    assert finished["expected_proof_count"] == 2
    assert finished["captured_proof_count"] == 1
    assert finished["required_proof_count_unmet"] is True
    saved = json.loads((tmp_path / "workspace" / "working_state.json").read_text())
    assert saved["state"]["surface"]["expected_proof_count"] == 2


def test_two_proofs_from_one_closure_probe_finish_without_another_model_turn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(ai_agent, "_seed_recon", lambda **_kwargs: None)

    def refresh(state: AgentState, **_kwargs: object) -> None:
        if not state.tasks:
            state.tasks = [_task("data-query", priority=100)]
        state.primitives.setdefault("sqli_confirmed", state.turn)

    def execute(
        _action: Mapping[str, object],
        *,
        state: AgentState,
        **_kwargs: object,
    ) -> ActionResult:
        state.flags.extend(["flag{one}", "flag{two}"])
        return ActionResult(
            ok=True,
            observation="two target proofs",
            outcome="flag_candidate",
            stop=True,
            flag="flag{one}",
        )

    monkeypatch.setattr(ai_agent, "refresh_mission_board", refresh)
    monkeypatch.setattr(ai_agent, "execute_action", execute)
    model = ScriptedModelClient(
        [{"action": "run_probe", "task_id": "data-query", "probe": "sqli_exploit"}]
    )
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML + "context:\n  expected_proof_count: 2\n",
        encoding="utf-8",
    )

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            max_turns=5,
        ),
    )

    assert len(model.messages_seen) == 1
    events = _events(tmp_path / "workspace" / "events.jsonl")
    assert sum(event["kind"] == "harness_terminal_synthesized" for event in events) == 1
    finished = next(event["payload"] for event in events if event["kind"] == "agent_finished")
    assert finished["status"] == "completed"
    assert finished["captured_proof_count"] == 2
    assert finished["completion_requirements_met"] is True


def test_third_identical_action_is_replaced_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executed: list[dict[str, object]] = []
    _patch_single_surface_task(monkeypatch)

    def execute(action: Mapping[str, object], **_kwargs: object) -> ActionResult:
        executed.append(dict(action))
        return ActionResult(ok=True, observation="bounded no change", outcome="observed")

    monkeypatch.setattr(ai_agent, "execute_action", execute)
    repeated = {
        "action": "run_command",
        "task_id": "surface-map",
        "command": "true",
        "strategy": "manual_surface_check",
    }
    model = ScriptedModelClient([repeated, repeated, repeated])
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            max_turns=3,
        ),
    )

    assert [action["action"] for action in executed] == [
        "run_command",
        "run_command",
        "run_probe",
    ]
    assert executed[2]["probe"] == "surface_map"
    events = _events(tmp_path / "workspace" / "events.jsonl")
    selections = [event for event in events if event["kind"] == "harness_selection"]
    assert selections[2]["payload"]["selection_reason"] == "repeat_limit_open_task_fallback"
    assert selections[2]["payload"]["proposed_action"]["action"] == "run_command"
    assert selections[2]["payload"]["selected_action"]["probe"] == "surface_map"


def test_completed_task_queue_synthesizes_terminal_without_another_model_turn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_single_surface_task(monkeypatch)

    def execute(_action: Mapping[str, object], **_kwargs: object) -> ActionResult:
        return ActionResult(
            ok=True,
            observation="typed finding confirmed",
            outcome="finding_confirmed",
        )

    monkeypatch.setattr(ai_agent, "execute_action", execute)
    model = ScriptedModelClient(
        [{"action": "run_probe", "task_id": "surface-map", "probe": "surface_map"}]
    )
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            max_turns=5,
        ),
    )

    assert len(model.messages_seen) == 1
    events = _events(tmp_path / "workspace" / "events.jsonl")
    terminal = [event for event in events if event["kind"] == "harness_terminal_synthesized"]
    assert len(terminal) == 1
    assert terminal[0]["payload"]["synthesized"] is True
    agent_final = [event for event in events if event["kind"] == "agent_final"]
    assert len(agent_final) == 1
    assert agent_final[0]["payload"]["synthesized"] is True
    finished = next(event for event in events if event["kind"] == "agent_finished")
    assert finished["payload"]["termination_reason"] == "agent_final"
    saved = json.loads((tmp_path / "workspace" / "working_state.json").read_text())
    assert saved["state"]["phase"] == "done"


def _patch_single_surface_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ai_agent, "_seed_recon", lambda **_kwargs: None)

    def refresh(state: AgentState, **_kwargs: object) -> None:
        if not state.tasks:
            state.tasks = [_task("surface-map", priority=100)]

    monkeypatch.setattr(ai_agent, "refresh_mission_board", refresh)


def _seed_one_existing_proof(*, state: AgentState, **_kwargs: object) -> None:
    state.flags = ["flag{one}"]


def _task(task_id: str, *, priority: int, status: str = "pending") -> dict[str, object]:
    return {
        "id": task_id,
        "title": task_id,
        "priority": priority,
        "status": status,
        "attempts": 0,
        "rationale": "test task",
        "next_steps": [],
        "evidence": [],
        "last_outcome": "",
    }


def _events(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
