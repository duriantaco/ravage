from __future__ import annotations

import json

from ravage.agent_core.action_planner import planner_directives, select_phase
from ravage.agent_core.agent_specialists import recommended_specialists
from ravage.agent_core.agent_state import AgentState, merge_signals
from ravage.agent_core.observation_analysis import extract_signals
from ravage.agent_core.primitive_state import (
    STALE_PRIMITIVE_TURNS,
    derive_primitives,
    locked_primitive,
    locked_probe,
    primitive_directives,
    probe_recently_exhausted,
    promote_primitives,
    routed_probes,
)

LOCKED_PROBE_SCORE = 100
EXHAUSTED_LOCKED_PROBE_SCORE = 20
JWT_OBSERVED_SCORE = 40
FIRST_PROMOTION_TURN = 3


def _confirm(state: AgentState, finding_type: str, **input_fields: str) -> None:
    finding: dict[str, object] = {"type": finding_type}
    if input_fields:
        finding["input"] = {
            "kind": "query_param",
            "url": "http://t/x",
            "input": "id",
            **input_fields,
        }
    merge_signals(state, extract_signals(json.dumps({"ok": True, "findings": [finding]})))


def _score(recommendation: dict[str, object]) -> int:
    score = recommendation.get("score")
    assert isinstance(score, int)
    return score


def test_sql_confirmation_promotes_locked_primitive() -> None:
    state = AgentState(turn=4)
    _confirm(state, "sql_injection_error_signal", input="id")

    assert promote_primitives(state) == ["sqli_confirmed"]
    assert state.primitives == {"sqli_confirmed": 4}
    assert locked_primitive(state) == "sqli_confirmed"
    assert locked_probe(state) == "sqli_exploit"
    assert routed_probes(state)["sqli_exploit"] == LOCKED_PROBE_SCORE


def test_locked_specialist_dominates_recommendations() -> None:
    state = AgentState(turn=5)
    _confirm(state, "sql_injection_error_signal", input="id")
    promote_primitives(state)

    recs = recommended_specialists(state, limit=4)
    assert recs[0]["probe"] == "sqli_exploit"
    assert _score(recs[0]) >= LOCKED_PROBE_SCORE


def test_blind_sql_maps_to_extraction_primitive() -> None:
    state = AgentState(turn=2)
    _confirm(state, "blind_sql_injection_timing_signal", input="id")
    promote_primitives(state)
    assert locked_primitive(state) == "blind_sqli_confirmed"
    assert locked_probe(state) == "sqli_exploit"


def test_promotion_is_idempotent_and_keeps_first_turn() -> None:
    state = AgentState(turn=FIRST_PROMOTION_TURN)
    _confirm(state, "command_boundary_proof")
    assert promote_primitives(state) == ["command_exec_confirmed"]
    state.turn = 7
    assert promote_primitives(state) == []
    assert state.primitives["command_exec_confirmed"] == FIRST_PROMOTION_TURN


def test_exploit_primitive_outranks_observed_jwt() -> None:
    state = AgentState(turn=4)
    _confirm(state, "jwt_observed")
    _confirm(state, "ssti_fingerprint_signal")
    promote_primitives(state)

    # tier-0 ssti is the hard lock; tier-1 jwt is still routed but not locked.
    assert locked_primitive(state) == "ssti_confirmed"
    boosts = routed_probes(state)
    assert boosts["ssti_fingerprint"] == LOCKED_PROBE_SCORE
    assert boosts["jwt_exploit"] == JWT_OBSERVED_SCORE


def test_client_execution_blocker_releases_lock_after_proof() -> None:
    state = AgentState(turn=2)
    _confirm(state, "client_side_execution", input="name")
    promote_primitives(state)
    assert locked_primitive(state) == "client_xss_confirmed"

    _confirm(state, "client_side_proof_extraction", input="name")
    assert locked_primitive(state) is None
    assert primitive_directives(state) == []


def test_captured_flag_clears_lock() -> None:
    state = AgentState(turn=3)
    _confirm(state, "sql_injection_error_signal", input="id")
    promote_primitives(state)
    state.flags.append("FLAG{real}")
    assert locked_primitive(state) is None
    assert derive_primitives(state)  # still derivable, but not a live lock


def test_unrelated_captured_flag_keeps_sql_lock_in_multi_proof_run() -> None:
    state = AgentState(
        turn=4,
        flags=["FLAG{unrelated}"],
        actions=[
            {
                "action": "run_probe",
                "probe": "idor_boundary",
                "outcome": "flag_candidate",
            }
        ],
        surface={"continue_after_proof": True},
    )
    _confirm(state, "sql_injection_error_signal", input="id")

    assert promote_primitives(state) == ["sqli_confirmed"]
    assert locked_primitive(state) == "sqli_confirmed"
    assert locked_probe(state) == "sqli_exploit"
    assert routed_probes(state)["sqli_exploit"] == LOCKED_PROBE_SCORE


def test_matching_specialist_proof_closes_only_its_multi_proof_primitive() -> None:
    state = AgentState(
        turn=5,
        flags=["FLAG{unrelated}", "FLAG{sql}"],
        attempts=[
            {
                "selected_action": {
                    "action": "run_probe",
                    "probe": "sqli_differential",
                    "task_id": "data-query",
                },
                "state_delta": {"flags_delta": 1},
                "turn": 5,
            }
        ],
        surface={"continue_after_proof": True},
    )
    _confirm(state, "sql_injection_error_signal", input="id")
    _confirm(state, "ssrf_boundary_signal", input="url")

    assert promote_primitives(state) == ["sqli_confirmed", "ssrf_confirmed"]
    assert locked_primitive(state) == "ssrf_confirmed"
    assert locked_probe(state) == "ssrf_boundary"


def test_replayed_known_proof_does_not_close_multi_proof_primitive() -> None:
    state = AgentState(
        turn=5,
        flags=["FLAG{sql}"],
        surface={"continue_after_proof": True},
    )
    _confirm(state, "sql_injection_error_signal", input="id")
    assert promote_primitives(state) == ["sqli_confirmed"]
    state.attempts.append(
        {
            "turn": 6,
            "selected_action": {
                "action": "run_probe",
                "probe": "sqli_exploit",
                "task_id": "data-query",
            },
            "outcome": {"classification": "flag_candidate"},
            "state_delta": {"flags_delta": 0},
        }
    )

    assert locked_primitive(state) == "sqli_confirmed"
    assert locked_probe(state) == "sqli_exploit"


def test_novel_explicit_capture_closes_matching_preceding_probe_branch() -> None:
    state = AgentState(
        turn=5,
        flags=["FLAG{unrelated}", "FLAG{sql}"],
        surface={"continue_after_proof": True},
    )
    _confirm(state, "sql_injection_error_signal", input="id")
    assert promote_primitives(state) == ["sqli_confirmed"]
    state.attempts.extend(
        [
            {
                "turn": 5,
                "selected_action": {
                    "action": "run_probe",
                    "probe": "sqli_differential",
                    "task_id": "data-query",
                },
                "outcome": {"ok": True, "classification": "confirmed_signal"},
                "state_delta": {"flags_delta": 0},
            },
            {
                "turn": 6,
                "selected_action": {
                    "action": "capture_flag",
                    "task_id": "data-query",
                },
                "outcome": {"ok": True, "classification": "flag_candidate"},
                "state_delta": {"flags_delta": 1},
            },
        ]
    )

    assert locked_primitive(state) is None
    assert locked_probe(state) is None


def test_novel_explicit_capture_does_not_close_by_task_id_alone() -> None:
    state = AgentState(
        turn=5,
        flags=["FLAG{unrelated}", "FLAG{other}"],
        surface={"continue_after_proof": True},
    )
    _confirm(state, "sql_injection_error_signal", input="id")
    assert promote_primitives(state) == ["sqli_confirmed"]
    state.attempts.extend(
        [
            {
                "turn": 5,
                "selected_action": {
                    "action": "run_probe",
                    "probe": "xss_context",
                    "task_id": "data-query",
                },
                "outcome": {"ok": True, "classification": "confirmed_signal"},
                "state_delta": {"flags_delta": 0},
            },
            {
                "turn": 6,
                "selected_action": {
                    "action": "capture_flag",
                    "task_id": "data-query",
                },
                "outcome": {"ok": True, "classification": "flag_candidate"},
                "state_delta": {"flags_delta": 1},
            },
        ]
    )

    assert locked_primitive(state) == "sqli_confirmed"
    assert locked_probe(state) == "sqli_exploit"


def test_novel_explicit_capture_uses_the_nearest_evidence_action() -> None:
    state = AgentState(
        turn=5,
        flags=["FLAG{unrelated}", "FLAG{command}"],
        surface={"continue_after_proof": True},
    )
    _confirm(state, "sql_injection_error_signal", input="id")
    assert promote_primitives(state) == ["sqli_confirmed"]
    state.attempts.extend(
        [
            {
                "turn": 5,
                "selected_action": {
                    "action": "run_probe",
                    "probe": "sqli_differential",
                    "task_id": "data-query",
                },
                "outcome": {"ok": True, "classification": "confirmed_signal"},
                "state_delta": {"flags_delta": 0},
            },
            {
                "turn": 6,
                "selected_action": {
                    "action": "run_command",
                    "command": "bounded custom follow-up",
                    "task_id": "data-query",
                },
                "outcome": {"ok": True, "classification": "observed"},
                "state_delta": {"flags_delta": 0},
            },
            {
                "turn": 7,
                "selected_action": {
                    "action": "capture_flag",
                    "task_id": "data-query",
                },
                "outcome": {"ok": True, "classification": "flag_candidate"},
                "state_delta": {"flags_delta": 1},
            },
        ]
    )

    assert locked_primitive(state) == "sqli_confirmed"
    assert locked_probe(state) == "sqli_exploit"


def test_budget_directive_escalates_when_primitive_goes_stale() -> None:
    state = AgentState(turn=3)
    _confirm(state, "sql_injection_error_signal", input="id")
    promote_primitives(state)

    state.turn = 3 + STALE_PRIMITIVE_TURNS
    directives = primitive_directives(state)
    assert any(text.startswith("PRIMITIVE CONFIRMED: sqli_confirmed") for text in directives)
    assert any(text.startswith("BUDGET:") for text in directives)


def test_exhausted_locked_probe_releases_hard_boost_and_budget_directive() -> None:
    state = AgentState(turn=3)
    _confirm(state, "sql_injection_error_signal", input="id")
    promote_primitives(state)
    state.turn = 7
    state.actions.append(
        {
            "action": "run_probe",
            "probe": "sqli_exploit",
            "outcome": "same_as_before",
            "repeat_count": 3,
        }
    )

    assert locked_probe(state) == "sqli_exploit"
    assert routed_probes(state)["sqli_exploit"] == EXHAUSTED_LOCKED_PROBE_SCORE
    directives = primitive_directives(state)
    assert "do not rerun it unchanged" in directives[0].lower()
    assert not any(text.startswith("BUDGET:") for text in directives)


def test_probe_progress_is_not_treated_as_exhaustion() -> None:
    older_exhaustion = {
        "turn": 6,
        "action": "run_probe",
        "probe": "sqli_exploit",
        "outcome": "same_as_before",
        "repeat_count": 3,
    }
    action = {
        "turn": 7,
        "action": "run_probe",
        "probe": "sqli_exploit",
        "outcome": "same_as_before",
        "repeat_count": 3,
    }
    epoch_advanced = AgentState(
        actions=[older_exhaustion, action],
        attempts=[
            {
                "turn": 7,
                "selected_action": {"action": "run_probe", "probe": "sqli_exploit"},
                "evidence_epoch_before": "epoch-a",
                "evidence_epoch_after": "epoch-b",
                "state_delta": {"new_primitives": []},
                "outcome": {"classification": "same_as_before"},
            }
        ],
    )
    primitive_advanced = AgentState(
        actions=[older_exhaustion, action],
        attempts=[
            {
                "turn": 7,
                "selected_action": {"action": "run_probe", "probe": "sqli_exploit"},
                "evidence_epoch_before": "epoch-a",
                "evidence_epoch_after": "epoch-a",
                "state_delta": {"new_primitives": ["sqli_confirmed"]},
                "outcome": {"classification": "same_as_before"},
            }
        ],
    )
    finding_confirmed = AgentState(
        actions=[older_exhaustion, {**action, "outcome": "finding_confirmed"}],
    )

    assert probe_recently_exhausted(epoch_advanced, "sqli_exploit") is False
    assert probe_recently_exhausted(primitive_advanced, "sqli_exploit") is False
    assert probe_recently_exhausted(finding_confirmed, "sqli_exploit") is False


def test_planner_prepends_primitive_directive_and_forces_exploit_phase() -> None:
    state = AgentState(turn=4)
    _confirm(state, "idor_boundary_exposed_secret")
    promote_primitives(state)

    assert select_phase(state) == "exploit"
    first = planner_directives(state)[0]
    assert first.startswith("PRIMITIVE CONFIRMED: idor_confirmed")


def test_multi_finding_phase_stays_in_exploit_after_first_flag() -> None:
    state = AgentState(
        flags=["FLAG{first-branch}"],
        surface={"continue_after_proof": True},
        tasks=[{"id": "another-branch", "status": "pending"}],
    )

    assert select_phase(state) == "exploit"
    assert any("multi-finding engagement" in item for item in planner_directives(state))


def test_primitives_round_trip_through_serialization() -> None:
    state = AgentState(turn=6)
    _confirm(state, "sql_injection_error_signal", input="id")
    promote_primitives(state)

    restored = AgentState.from_json(state.to_json())
    assert restored.primitives == {"sqli_confirmed": 6}
    assert "confirmed_primitives" in state.to_prompt_context()
