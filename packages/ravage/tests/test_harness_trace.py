from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ai_agent_fixtures import BRIEF_YAML, ScriptedModelClient
from ravage.agent_core import ai_agent
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import AIWebAgentSettings, run_ai_web_agent
from ravage.agent_core.harness_trace import (
    attempt_record_payload,
    sanitize_action,
    selection_trace_payload,
    state_trace_delta,
    state_trace_snapshot,
    turn_trace_payload,
)
from ravage.agent_core.observation_memory import build_planner_memory
from ravage.agent_core.semantic_routes import semantic_action_fingerprint, semantic_action_route

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_harness_trace_redacts_secret_shaped_action_values() -> None:
    action = {
        "action": "run_command",
        "command": "curl -H 'Authorization: Bearer abc' '/profile?session=secret'",
        "headers": {"Cookie": "session=abc", "X-Api-Key": "key"},
        "memory_updates": ["found flag{secret-value}"],
    }

    payload = sanitize_action(action)

    assert "Bearer abc" not in str(payload)
    assert "session=secret" not in str(payload)
    assert "flag{secret-value}" not in str(payload)
    assert "flag{REDACTED}" in str(payload)


def test_harness_state_delta_tracks_counts_without_signal_values() -> None:
    state = AgentState(turn=1)
    state.signals["cookies"] = ["session=abc"]
    before = state_trace_snapshot(state)

    state.flags.append("flag{secret-value}")
    state.signals["markers"] = ["ssti_fingerprint_signal"]
    state.facts.append("SSTI signal observed")
    state.actions.append({"action": "run_probe", "probe": "ssti_fingerprint"})
    after = state_trace_snapshot(state)

    delta = state_trace_delta(before, after)

    assert delta["flags_delta"] == 1
    assert delta["facts_delta"] == 1
    assert delta["actions_delta"] == 1
    assert delta["signal_count_delta"] == {"markers": 1}
    assert "session=abc" not in str(after)


def test_harness_selection_and_turn_payloads_preserve_model_vs_selected_diff() -> None:
    proposed: dict[str, object] = {"action": "run_command", "command": "python3 manual.py"}
    selected: dict[str, object] = {
        "action": "run_probe",
        "task_id": "server-rendering",
        "probe": "ssti_fingerprint",
    }
    before = state_trace_snapshot(AgentState(turn=3))
    after_state = AgentState(turn=3, phase="exploit")
    after_state.actions.append(selected)
    after = state_trace_snapshot(after_state)

    selection = selection_trace_payload(
        turn=3,
        action_id="action-1",
        proposed_action=proposed,
        selected_action=selected,
        shadow_action=selected,
        shadow_reason="evidence_probe_route",
        repeat_context="",
    )
    trace = turn_trace_payload(
        turn=3,
        action_id="action-1",
        proposed_action=proposed,
        selected_action=selected,
        pre_state=before,
        post_state=after,
        outcome={
            "ok": True,
            "outcome": "confirmed_signal",
            "observation": "Authorization: Bearer abc\nflag{secret-value}",
        },
    )

    assert selection["selected_differs_from_model"] is True
    assert selection["selection_reason"] == "evidence_probe_route"
    shadow_router = selection["shadow_router"]
    assert isinstance(shadow_router, dict)
    assert shadow_router["suggestion_matches_selected"] is True
    assert trace["selected_differs_from_model"] is True
    state_delta = trace["state_delta"]
    assert isinstance(state_delta, dict)
    assert state_delta["actions_delta"] == 1
    assert "Bearer abc" not in str(trace)
    assert "flag{secret-value}" not in str(trace)


def test_recovery_contract_has_an_explicit_selection_reason() -> None:
    payload = selection_trace_payload(
        turn=5,
        action_id="action-recovery-contract",
        proposed_action={"action": "run_command", "command": "manual loop"},
        selected_action={
            "action": "run_probe",
            "probe": "xss_filter_constraint",
            "strategy": "recovery_objective_contract",
        },
        shadow_action={
            "action": "run_probe",
            "probe": "reflection_value_boundary",
        },
        shadow_reason="evidence_probe_route",
        repeat_context="",
    )

    assert payload["selection_reason"] == "recovery_objective_contract"


def test_semantic_route_groups_equivalent_traversal_commands_without_storing_values() -> None:
    first = {
        "action": "run_command",
        "command": "curl 'http://target/download?file=../../etc/passwd'",
        "strategy": "lfi traversal",
    }
    second = {
        "action": "run_command",
        "command": "curl 'http://target/download?file=../../../etc/hosts'",
        "strategy": "lfi traversal",
    }

    route = semantic_action_route(first)

    assert route["family"] == "path_traversal"
    assert route["endpoints"] == ["/download?file"]
    assert route["inputs"] == ["file"]
    assert route["payload_class"] == "traversal_plain"
    assert semantic_action_fingerprint(first) == semantic_action_fingerprint(second)
    assert "passwd" not in str(route)


def test_semantic_route_prefers_structured_probe_over_future_fallback() -> None:
    command_probe = {
        "action": "run_probe",
        "probe": "command_boundary",
        "notes": "test the observed command-shaped input",
        "fallback": "try SQL injection or path traversal next",
    }
    changed_fallback = {
        **command_probe,
        "fallback": "try CSRF against the login workflow next",
    }

    assert semantic_action_route(command_probe)["family"] == "command_injection"
    assert semantic_action_fingerprint(command_probe) == semantic_action_fingerprint(
        changed_fallback
    )


def test_semantic_route_keeps_unambiguous_probe_families_stable() -> None:
    cases = (
        ("csrf_session", "csrf", "login and session evidence; try SQL next"),
        ("default_credentials", "authentication", "fall back to SQL injection"),
        ("direct_exposure", "exposure", "inspect login then try path traversal"),
        ("sqli_differential", "sql_injection", "return to local file inclusion"),
        ("xxe_boundary", "xml_external_entity", "read a local file, then try login"),
    )

    for probe, family, fallback in cases:
        action = {
            "action": "run_probe",
            "probe": probe,
            "notes": "run the named specialist",
            "fallback": fallback,
        }
        assert semantic_action_route(action)["family"] == family


def test_semantic_route_keeps_multipurpose_probe_evidence_sensitive() -> None:
    file_read = {
        "action": "run_probe",
        "probe": "file_fetch_parser",
        "notes": "test local file inclusion and path traversal evidence",
    }
    upload = {
        "action": "run_probe",
        "probe": "file_fetch_parser",
        "notes": "test the observed multipart upload parser",
    }

    assert semantic_action_route(file_read)["family"] == "path_traversal"
    assert semantic_action_route(upload)["family"] == "file_upload"


def test_attempt_record_links_override_route_outcome_and_novelty() -> None:
    proposed = {
        "action": "run_command",
        "command": "curl 'http://target/download?file=../../etc/passwd'",
        "strategy": "lfi traversal",
    }
    selected = {
        "action": "run_probe",
        "task_id": "data-query",
        "probe": "sqli_differential",
        "strategy": "forced_evidence_sqli",
    }
    before = state_trace_snapshot(AgentState(turn=4))
    after_state = AgentState(turn=4)
    after_state.actions.append(selected)
    after = state_trace_snapshot(after_state)

    record = attempt_record_payload(
        turn=4,
        action_id="action-4",
        proposed_action=proposed,
        selected_action=selected,
        selection_reason="evidence_probe_route",
        repeat_context="",
        pre_state=before,
        post_state=after,
        outcome={"ok": True, "outcome": "observed", "repeat_count": 1},
    )

    assert record["selected_differs_from_model"] is True
    assert record["selection_reason"] == "evidence_probe_route"
    assert record["status"] == "low_value"
    assert record["novel"] is False
    assert record["proposed_fingerprint"] != record["selected_fingerprint"]


def test_attempt_ledger_round_trips_without_entering_baseline_prompt_memory() -> None:
    marker = "attempt-only-marker"
    state = AgentState(attempts=[{"turn": 1, "selection_reason": marker}])

    restored = AgentState.from_json(state.to_json())

    assert restored.attempts == state.attempts
    assert marker not in restored.to_prompt_context()
    assert marker not in str(build_planner_memory(restored))


def test_agent_persists_one_attempt_record_per_executed_turn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(ai_agent, "_seed_recon", lambda **_kwargs: None)
    monkeypatch.setattr(ai_agent, "refresh_mission_board", lambda *_args, **_kwargs: None)
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    workspace_dir = tmp_path / "workspace"

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace_dir,
            model_client=ScriptedModelClient([{"action": "final", "summary": "done"}]),
            max_turns=1,
        ),
    )

    saved = json.loads((workspace_dir / "working_state.json").read_text(encoding="utf-8"))
    attempts = saved["state"]["attempts"]
    assert len(attempts) == 1
    assert attempts[0]["selection_reason"] == "model_proposal"
    assert attempts[0]["status"] == "completed"

    events = [
        json.loads(line)
        for line in (workspace_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert sum(event["kind"] == "agent_attempt_recorded" for event in events) == 1
    traffic_started = [event for event in events if event["kind"] == "traffic_policy_started"]
    traffic_finished = [event for event in events if event["kind"] == "traffic_policy_finished"]
    assert len(traffic_started) == 1
    assert len(traffic_finished) == 1
    assert traffic_started[0]["payload"]["snapshot"]["physical_request_count"] == 0
    assert traffic_finished[0]["payload"]["snapshot"]["accounting_status"] == "exact"
    assert (workspace_dir / "traffic-policy.json").is_file()
    agent_finished = next(event for event in events if event["kind"] == "agent_finished")
    assert agent_finished["payload"]["traffic_policy_snapshot"] == traffic_finished[0][
        "payload"
    ]["snapshot"]
