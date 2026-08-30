from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

import pytest
import ravage.agent_core.ai_agent as ai_agent_module
from ai_agent_fixtures import BRIEF_YAML, ScriptedModelClient
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import AIWebAgentSettings, ChatMessage, ModelReply, run_ai_web_agent
from ravage.agent_core.recovery_runtime import RecoveryCampaign

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from ravage.model_core.providers import ResolvedModelRoute

TARGET_URL = "http://127.0.0.1:8765"
PROOF = "FLAG{recovery-target-proof}"
EXPECTED_MODEL_REQUESTS = 7
EXPECTED_RESUMED_REQUESTS = 2
XSS_CONTRACT_EXPECTED_MODEL_REQUESTS = 5
GLOBAL_REQUEST_BUDGET = 40
MULTI_FINDING_BRIEF_YAML = (
    BRIEF_YAML
    + """
context:
  description: "Authorized local multi-finding assessment."
  win_condition: "Capture as many lab flags as possible from live target evidence."
"""
)


def _events(workspace: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (workspace / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def _payload(event: dict[str, object]) -> dict[str, object]:
    payload = event.get("payload")
    assert isinstance(payload, dict)
    return payload


def _core_action(index: int) -> dict[str, object]:
    return {
        "action": "run_command",
        "command": f"target XML parser check {index}",
        "task_id": "file-fetch-parser",
        "strategy": "xml_parser_mapping",
        "notes": "Target exposes an XML parser workflow.",
        "expected_signal": "A target-observed parser differential.",
        "fallback": "Change the XML request shape.",
        "memory_updates": ["target exposes an XML parser workflow"],
    }


def _xss_core_action(index: int) -> dict[str, object]:
    return {
        "action": "run_command",
        "command": (
            'curl -s "$RAVAGE_TARGET_URL/page?name=<script>alert(\\"XSS\\")</script>" '
            f"# route attempt {index}"
        ),
        "task_id": "input-reflection",
        "strategy": "client_execution",
        "notes": "Exercise the reflected browser-input route.",
        "expected_signal": "A target-observed XSS response differential.",
        "fallback": "Change the element or event family.",
    }


def _fake_executor(
    action: dict[str, object],
    **kwargs: object,
) -> ActionResult:
    _ = action
    state = cast("AgentState", kwargs["state"])
    turn = state.turn
    if turn == EXPECTED_MODEL_REQUESTS:
        last_observation = {
            "observation_id": "target-proof-observation",
            "source_kind": "tool_run_probe",
            "recognized_proofs": [PROOF],
        }
        state.last_observation = last_observation
        state.flags.append(PROOF)
        return ActionResult(
            ok=True,
            observation=PROOF,
            stop=True,
            outcome="flag_candidate",
            flag=PROOF,
            evidence_source_kind="tool_run_probe",
            evidence_observation=PROOF,
        )
    return ActionResult(
        ok=True,
        observation=f"target observation {turn}",
        outcome="observed",
        evidence_source_kind="tool_run_command",
        evidence_observation=f"target observation {turn}",
    )


def _proof_executor(
    action: dict[str, object],
    **kwargs: object,
) -> ActionResult:
    _ = action
    state = cast("AgentState", kwargs["state"])
    state.last_observation = {
        "observation_id": "target-proof-observation",
        "source_kind": "tool_run_probe",
        "recognized_proofs": [PROOF],
    }
    state.flags.append(PROOF)
    return ActionResult(
        ok=True,
        observation=PROOF,
        stop=True,
        outcome="flag_candidate",
        flag=PROOF,
        evidence_source_kind="tool_run_probe",
        evidence_observation=PROOF,
    )


def _no_progress_executor(
    action: dict[str, object],
    **kwargs: object,
) -> ActionResult:
    _ = action
    state = cast("AgentState", kwargs["state"])
    observation = f"distinct target observation {state.turn}"
    return ActionResult(
        ok=True,
        observation=observation,
        outcome="same_as_before",
        evidence_source_kind="tool_run_command",
        evidence_observation=observation,
    )


def _proof_on_second_executor(
    action: dict[str, object],
    **kwargs: object,
) -> ActionResult:
    state = cast("AgentState", kwargs["state"])
    if state.turn == EXPECTED_RESUMED_REQUESTS:
        return _proof_executor(action, **kwargs)
    return _no_progress_executor(action, **kwargs)


def _proof_only_for_xss_contract(
    action: dict[str, object],
    **kwargs: object,
) -> ActionResult:
    if (
        action.get("probe") == "xss_filter_constraint"
        and action.get("strategy") == "recovery_objective_contract"
    ):
        return _proof_executor(action, **kwargs)
    return _no_progress_executor(action, **kwargs)


def _multi_finding_proof_executor(
    action: dict[str, object],
    **kwargs: object,
) -> ActionResult:
    _ = action
    state = cast("AgentState", kwargs["state"])
    proof = f"FLAG{{multi-branch-{state.turn}}}"
    state.last_observation = {
        "observation_id": f"multi-proof-{state.turn}",
        "source_kind": "tool_run_probe",
        "recognized_proofs": [proof],
    }
    state.flags.append(proof)
    return ActionResult(
        ok=True,
        observation=proof,
        stop=True,
        outcome="flag_candidate",
        flag=proof,
        evidence_source_kind="tool_run_probe",
        evidence_observation=proof,
    )


def _seed_multi_finding_tasks(**kwargs: object) -> None:
    state = cast("AgentState", kwargs["state"])
    state.surface = {"target_url": TARGET_URL, "origin": TARGET_URL}
    if not state.tasks:
        state.tasks.extend(
            [
                {"id": "branch-one", "status": "pending", "priority": 100},
                {"id": "branch-two", "status": "pending", "priority": 90},
            ]
        )


class _NoProgressClient:
    def __init__(self) -> None:
        self.calls = 0

    def complete(
        self,
        *,
        messages: Sequence[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        _ = messages, route
        self.calls += 1
        if self.calls > GLOBAL_REQUEST_BUDGET:
            pytest.fail("recovery issued a model request beyond the global budget")
        return ModelReply(content=json.dumps(_core_action(self.calls)))


def test_recovery_profile_escalates_hands_off_and_solves_under_one_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    workspace = tmp_path / "workspace"
    model = ScriptedModelClient(
        [
            _core_action(1),
            _core_action(2),
            _core_action(3),
            _core_action(4),
            {
                "action": "run_command",
                "command": "manual delegated-route detour",
                "task_id": "file-fetch-parser",
                "strategy": "manual_loop",
            },
            {
                "action": "final",
                "summary": "I claim FLAG{model-fake}; password=not-evidence",
            },
            {
                "action": "run_probe",
                "probe": "xxe_boundary",
                "task_id": "file-fetch-parser",
                "strategy": "different_xml_shape",
                "notes": "Execute the delegated counterfactual.",
            },
        ]
    )
    monkeypatch.setattr(ai_agent_module, "execute_action", _fake_executor)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace,
            model_client=model,
            max_turns=40,
            recovery_profile="recovery-v1",
        ),
    )

    events = _events(workspace)
    requests = [event for event in events if event["kind"] == "model_request_started"]
    handoffs = [event for event in events if event["kind"] == "recovery_branch_handoff"]
    starts = [event for event in events if event["kind"] == "recovery_branch_started"]
    stopped = [event for event in events if event["kind"] == "recovery_campaign_stopped"]

    assert len(requests) == EXPECTED_MODEL_REQUESTS
    assert [_payload(event)["recovery_role"] for event in requests] == [
        "core",
        "core",
        "core",
        "core",
        "closure",
        "closure",
        "counterfactual",
    ]
    assert [_payload(event)["next_role"] for event in starts] == [
        "closure",
        "counterfactual",
    ]
    assert len(handoffs) == 1
    assert _payload(handoffs[0])["campaign_terminal"] is False
    assert "model-fake" not in json.dumps(_payload(handoffs[0]))
    assert "not-evidence" not in json.dumps(_payload(handoffs[0]))
    assert _payload(stopped[-1])["status"] == "solved"
    assert _payload(stopped[-1])["total_model_requests"] == EXPECTED_MODEL_REQUESTS

    closure_prompt = json.loads(model.messages_seen[4][-1].content)
    counterfactual_prompt = json.loads(model.messages_seen[6][-1].content)
    assert closure_prompt["recovery_assignment"]["role"] == "closure"
    assert counterfactual_prompt["recovery_assignment"]["role"] == "counterfactual"
    assert "fresh bounded role" in model.messages_seen[4][0].content

    selections = [event for event in events if event["kind"] == "harness_selection"]
    contract_selection = _payload(selections[4])
    assert contract_selection["selected_differs_from_model"] is True
    assert contract_selection["selected_action"]["action"] == "run_probe"
    assert (
        contract_selection["selected_action"]["probe"]
        == (closure_prompt["recovery_assignment"]["objective"]["probe"])
    )
    assert contract_selection["selected_action"]["strategy"] == "recovery_objective_contract"

    handoff_selection = _payload(selections[5])
    assert handoff_selection["selected_differs_from_model"] is False
    assert handoff_selection["selected_action"]["action"] == "final"

    saved = json.loads((workspace / "recovery-state.json").read_text(encoding="utf-8"))
    assert saved["scheduler"]["status"] == "solved"
    assert saved["scheduler"]["total_model_requests"] == EXPECTED_MODEL_REQUESTS


def test_recovery_executes_route_aligned_xss_objective_when_model_keeps_looping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    workspace = tmp_path / "workspace"
    model = ScriptedModelClient(
        [
            _xss_core_action(1),
            _xss_core_action(2),
            _xss_core_action(3),
            _xss_core_action(4),
            {
                "action": "run_command",
                "command": "curl another hand-written XSS payload",
                "task_id": "input-reflection",
                "strategy": "client_execution",
                "notes": "Continue manually despite the delegated objective.",
            },
        ]
    )
    monkeypatch.setattr(ai_agent_module, "execute_action", _proof_only_for_xss_contract)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace,
            model_client=model,
            max_turns=GLOBAL_REQUEST_BUDGET,
            recovery_profile="recovery-v1",
        ),
    )

    events = _events(workspace)
    requests = [event for event in events if event["kind"] == "model_request_started"]
    selections = [event for event in events if event["kind"] == "harness_selection"]
    stopped = [event for event in events if event["kind"] == "recovery_campaign_stopped"]

    assert len(requests) == XSS_CONTRACT_EXPECTED_MODEL_REQUESTS
    assert [_payload(event)["recovery_role"] for event in requests] == [
        "core",
        "core",
        "core",
        "core",
        "closure",
    ]
    closure_prompt = json.loads(model.messages_seen[4][-1].content)
    assert closure_prompt["recovery_assignment"]["objective"]["family"] == ("cross_site_scripting")
    assert closure_prompt["recovery_assignment"]["objective"]["probe"] == ("xss_filter_constraint")

    selected = _payload(selections[4])
    assert selected["selected_differs_from_model"] is True
    assert selected["selected_action"]["action"] == "run_probe"
    assert selected["selected_action"]["probe"] == "xss_filter_constraint"
    assert selected["selected_action"]["strategy"] == "recovery_objective_contract"
    assert _payload(stopped[-1])["status"] == "solved"
    assert _payload(stopped[-1])["total_model_requests"] == (XSS_CONTRACT_EXPECTED_MODEL_REQUESTS)


def test_default_and_explicit_off_profiles_keep_identical_prompts_and_no_recovery_events(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    default_model = ScriptedModelClient([{"action": "final", "summary": "done"}])
    explicit_model = ScriptedModelClient([{"action": "final", "summary": "done"}])

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "default.db",
            workspace_dir=tmp_path / "default-workspace",
            model_client=default_model,
            max_turns=1,
        ),
    )
    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "explicit.db",
            workspace_dir=tmp_path / "explicit-workspace",
            model_client=explicit_model,
            max_turns=1,
            recovery_profile="off",
        ),
    )

    assert default_model.messages_seen == explicit_model.messages_seen
    for workspace in (tmp_path / "default-workspace", tmp_path / "explicit-workspace"):
        events = _events(workspace)
        assert not any(str(event["kind"]).startswith("recovery_") for event in events)
        assert not (workspace / "recovery-state.json").exists()
        request = next(event for event in events if event["kind"] == "model_request_started")
        assert "recovery_role" not in _payload(request)


def test_multi_finding_run_continues_after_proof_and_resume_uses_next_turn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(MULTI_FINDING_BRIEF_YAML, encoding="utf-8")
    workspace = tmp_path / "workspace"
    db_path = tmp_path / "audit.db"
    first_model = ScriptedModelClient([{**_core_action(1), "task_id": "branch-one"}])
    second_model = ScriptedModelClient([{**_core_action(2), "task_id": "branch-two"}])
    monkeypatch.setattr(ai_agent_module, "_seed_recon", _seed_multi_finding_tasks)
    monkeypatch.setattr(ai_agent_module, "execute_action", _multi_finding_proof_executor)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=db_path,
            workspace_dir=workspace,
            model_client=first_model,
            max_turns=1,
        ),
    )
    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=db_path,
            workspace_dir=workspace,
            model_client=second_model,
            max_turns=2,
        ),
    )

    events = _events(workspace)
    requests = [event for event in events if event["kind"] == "model_request_started"]
    attempts = [event for event in events if event["kind"] == "agent_attempt_recorded"]
    saved = json.loads((workspace / "working_state.json").read_text(encoding="utf-8"))
    state = saved["state"]

    assert [_payload(event)["turn"] for event in requests] == [1, 2]
    assert [_payload(event)["outcome"]["stop"] for event in attempts] == [False, False]
    assert state["turn"] == 2
    assert state["phase"] == "exploit"
    assert state["flags"] == ["FLAG{multi-branch-1}", "FLAG{multi-branch-2}"]
    assert state["surface"]["continue_after_proof"] is True
    assert state["surface"]["scope_in_scope"] == [TARGET_URL]

    resumed_prompt = json.loads(second_model.messages_seen[0][-1].content)
    assert "multi-finding engagement" in " ".join(resumed_prompt["planner_directives"])
    assert "capture every target proof" in resumed_prompt["objective"]


def test_recovery_core_final_cannot_end_the_campaign_without_target_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    workspace = tmp_path / "workspace"
    model = ScriptedModelClient(
        [
            {"action": "final", "summary": "FLAG{model-only-claim}"},
            {
                "action": "run_probe",
                "probe": "xxe_boundary",
                "task_id": "file-fetch-parser",
            },
        ]
    )
    monkeypatch.setattr(ai_agent_module, "execute_action", _proof_on_second_executor)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace,
            model_client=model,
            max_turns=GLOBAL_REQUEST_BUDGET,
            recovery_profile="recovery-v1",
        ),
    )

    events = _events(workspace)
    selections = [event for event in events if event["kind"] == "harness_selection"]
    requests = [event for event in events if event["kind"] == "model_request_started"]
    stopped = [event for event in events if event["kind"] == "recovery_campaign_stopped"]
    finished = [event for event in events if event["kind"] == "agent_finished"]

    assert len(requests) == EXPECTED_RESUMED_REQUESTS
    assert _payload(selections[0])["selected_action"]["action"] != "final"
    assert not any(event["kind"] == "agent_final" for event in events)
    assert _payload(finished[-1])["flags"] == [PROOF]
    assert _payload(stopped[-1])["status"] == "solved"


class _InterruptingClient:
    def complete(
        self,
        *,
        messages: Sequence[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        _ = messages, route
        raise KeyboardInterrupt


def test_recovery_resume_charges_an_interrupted_model_request_without_replaying_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    workspace = tmp_path / "workspace"
    db_path = tmp_path / "audit.db"

    with pytest.raises(KeyboardInterrupt):
        run_ai_web_agent(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=AIWebAgentSettings(
                tool_runtime_mode="host",
                db_path=db_path,
                workspace_dir=workspace,
                model_client=_InterruptingClient(),
                max_turns=40,
                recovery_profile="recovery-v1",
            ),
        )

    pending = json.loads((workspace / "recovery-state.json").read_text(encoding="utf-8"))
    assert pending["started_model_requests"] == 1
    assert pending["scheduler"]["total_model_requests"] == 0
    interrupted_events = _events(workspace)
    interrupted_finished = [
        event for event in interrupted_events if event["kind"] == "agent_finished"
    ]
    assert _payload(interrupted_finished[-1])["status"] == "cancelled"
    assert _payload(interrupted_finished[-1])["error_type"] == "KeyboardInterrupt"

    monkeypatch.setattr(ai_agent_module, "execute_action", _proof_executor)
    resumed_model = ScriptedModelClient(
        [{"action": "run_probe", "probe": "xxe_boundary", "task_id": "file-fetch-parser"}]
    )
    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=db_path,
            workspace_dir=workspace,
            model_client=resumed_model,
            max_turns=40,
            recovery_profile="recovery-v1",
        ),
    )

    events = _events(workspace)
    requests = [event for event in events if event["kind"] == "model_request_started"]
    assert [_payload(event)["turn"] for event in requests] == [1, 2]
    accounting = [event for event in events if event["kind"] == "recovery_turn_accounted"]
    assert any(_payload(event)["interrupted_request"] is True for event in accounting)
    saved = json.loads((workspace / "recovery-state.json").read_text(encoding="utf-8"))
    assert saved["started_model_requests"] == EXPECTED_RESUMED_REQUESTS
    assert saved["scheduler"]["total_model_requests"] == EXPECTED_RESUMED_REQUESTS
    assert saved["interrupted_model_requests"] == 1


def test_recovery_resume_rejects_missing_agent_state_after_a_completed_turn(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "recovery-state.json"
    campaign = RecoveryCampaign.create(
        target_url=TARGET_URL,
        max_model_requests=GLOBAL_REQUEST_BUDGET,
    )
    campaign.begin_model_request()
    campaign.record_action_result(
        action=_core_action(1),
        outcome=ActionResult(
            ok=True,
            observation="target response",
            evidence_source_kind="tool_run_command",
            evidence_observation="target response",
        ),
    )
    campaign.save(state_path)

    with pytest.raises(ValueError, match="agent and recovery state disagree"):
        ai_agent_module._initial_recovery_campaign(  # noqa: SLF001
            settings=AIWebAgentSettings(
                max_turns=GLOBAL_REQUEST_BUDGET,
                recovery_profile="recovery-v1",
            ),
            state=AgentState(),
            target_url=TARGET_URL,
            state_path=state_path,
        )


def test_no_progress_campaign_stops_without_blindly_consuming_the_global_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    workspace = tmp_path / "workspace"
    model = _NoProgressClient()
    monkeypatch.setattr(ai_agent_module, "execute_action", _no_progress_executor)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace,
            model_client=model,
            max_turns=GLOBAL_REQUEST_BUDGET,
            recovery_profile="recovery-v1",
        ),
    )

    events = _events(workspace)
    requests = [event for event in events if event["kind"] == "model_request_started"]
    stopped = [event for event in events if event["kind"] == "recovery_campaign_stopped"]
    blocked = [event for event in events if event["kind"] == "recovery_route_blocked"]
    saved = json.loads((workspace / "recovery-state.json").read_text(encoding="utf-8"))

    assert stopped
    assert _payload(stopped[-1])["status"] == "exploration_exhausted"
    assert model.calls == len(requests) == saved["scheduler"]["total_model_requests"]
    assert model.calls < GLOBAL_REQUEST_BUDGET
    assert blocked
    scheduler = saved["scheduler"]
    config = scheduler["config"]
    assert scheduler["total_model_requests"] <= (
        config["max_model_requests"] - config["proof_reserve"]
    )
