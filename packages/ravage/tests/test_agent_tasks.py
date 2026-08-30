from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.agent_tasks import (
    active_tasks_for_prompt,
    refresh_mission_board,
    update_mission_from_action,
)


def test_empty_secret_sweep_blocks_after_two_attempts() -> None:
    state = AgentState()
    state.tasks = [
        {
            "id": "flag-and-secret-sweep",
            "title": "Sweep exposed files and responses for flags or secrets",
            "status": "pending",
            "priority": 90,
            "attempts": 0,
            "rationale": "",
            "next_steps": [],
            "evidence": [],
            "last_outcome": "",
        },
        {
            "id": "data-query",
            "title": "Test whether inputs influence data queries",
            "status": "pending",
            "priority": 85,
            "attempts": 0,
            "rationale": "",
            "next_steps": [],
            "evidence": [],
            "last_outcome": "",
        },
    ]
    action = {"action": "run_probe", "task_id": "flag-and-secret-sweep", "probe": "secret_sweep"}
    outcome = {"outcome": "observed", "observation": '{"probe":"secret_sweep","findings":[]}'}

    update_mission_from_action(state, action=action, outcome=outcome)
    update_mission_from_action(state, action=action, outcome=outcome)

    assert state.tasks[0]["status"] == "blocked"
    assert active_tasks_for_prompt(state, limit=1)[0]["id"] == "data-query"


def test_secret_sweep_probe_is_attributed_even_with_wrong_task_id() -> None:
    state = AgentState()
    state.tasks = [
        _task("flag-and-secret-sweep", priority=90),
        _task("input-reflection", priority=85),
    ]
    action = {"action": "run_probe", "task_id": "input-reflection", "probe": "secret_sweep"}
    outcome = {"outcome": "observed", "observation": '{"probe":"secret_sweep","findings":[]}'}

    update_mission_from_action(state, action=action, outcome=outcome)

    assert state.tasks[0]["attempts"] == 1
    assert state.tasks[1]["attempts"] == 0


def test_sqli_probe_is_attributed_to_data_query_even_with_wrong_task_id() -> None:
    state = AgentState()
    state.tasks = [
        _task("input-reflection", priority=90),
        _task("data-query", priority=85),
    ]
    action = {"action": "run_probe", "task_id": "input-reflection", "probe": "sqli_exploit"}
    outcome = {"outcome": "same_as_before", "observation": '{"probe":"sqli_exploit","findings":[]}'}

    update_mission_from_action(state, action=action, outcome=outcome)

    assert state.tasks[0]["attempts"] == 0
    assert state.tasks[1]["attempts"] == 1


def test_filtered_and_preg_match_probes_are_attributed_to_data_query() -> None:
    for probe in ("filtered_query_bypass", "preg_match_subject"):
        state = AgentState()
        state.tasks = [
            _task("file-fetch-parser", priority=90),
            _task("data-query", priority=85),
        ]
        action = {"action": "run_probe", "task_id": "file-fetch-parser", "probe": probe}
        outcome = {"outcome": "same_as_before", "observation": f'{{"probe":"{probe}","findings":[]}}'}

        update_mission_from_action(state, action=action, outcome=outcome)

        assert state.tasks[0]["attempts"] == 0
        assert state.tasks[1]["attempts"] == 1


def test_confirmed_data_query_signal_stays_active_after_inconclusive_probe() -> None:
    state = AgentState()
    state.signals["markers"] = ["sql_injection_confirmed", "mysql"]
    state.signals["sqli_inputs"] = ['{"input":"fullname","kind":"form","url":"http://target/send.php"}']
    state.tasks = [_task("data-query", priority=90)]
    action = {"action": "run_probe", "task_id": "data-query", "probe": "sqli_exploit"}
    outcome = {"outcome": "same_as_before", "observation": '{"probe":"sqli_exploit","findings":[]}'}

    for _index in range(4):
        update_mission_from_action(state, action=action, outcome=outcome)

    assert state.tasks[0]["status"] == "in_progress"
    assert active_tasks_for_prompt(state, limit=1)[0]["id"] == "data-query"


def test_confirmed_finding_keeps_proof_oriented_task_open_until_proof() -> None:
    for continue_after_proof in (False, True):
        state = AgentState()
        state.surface = {
            "flag_objective": True,
            "continue_after_proof": continue_after_proof,
        }
        state.tasks = [_task("data-query", priority=90)]
        action = {
            "action": "run_probe",
            "task_id": "data-query",
            "probe": "sqli_differential",
        }

        update_mission_from_action(
            state,
            action=action,
            outcome={"outcome": "finding_confirmed", "observation": "confirmed SQLi"},
        )

        assert state.tasks[0]["status"] == "in_progress"

        update_mission_from_action(
            state,
            action={
                "action": "capture_flag",
                "task_id": "data-query",
            },
            outcome={"outcome": "same_as_before", "observation": "proof already captured"},
        )

        assert state.tasks[0]["status"] == "in_progress"

        update_mission_from_action(
            state,
            action={**action, "probe": "sqli_exploit"},
            outcome={"outcome": "flag_candidate", "observation": "proof captured"},
        )

        assert state.tasks[0]["status"] == "done"


def test_confirmed_finding_completes_non_proof_assessment_task() -> None:
    state = AgentState(surface={"flag_objective": False})
    state.tasks = [_task("data-query", priority=90)]

    update_mission_from_action(
        state,
        action={
            "action": "run_probe",
            "task_id": "data-query",
            "probe": "sqli_differential",
        },
        outcome={"outcome": "finding_confirmed", "observation": "confirmed SQLi"},
    )

    assert state.tasks[0]["status"] == "done"


def test_generic_form_prioritizes_input_reflection_before_data_query() -> None:
    state = AgentState()
    refresh_mission_board(
        state,
        description="Single-page form with a plain answer field.",
        surface={
            "counts": {"pages": 1, "forms": 1, "endpoints": 1},
            "forms": [
                {
                    "action": "http://127.0.0.1/page",
                    "method": "POST",
                    "inputs": [{"name": "solution", "type": "text"}],
                    "categories": ["generic_input"],
                }
            ],
            "parameters": [],
            "endpoints": [{"url": "http://127.0.0.1/page", "hints": ["page"]}],
        },
    )

    task_ids = [task["id"] for task in active_tasks_for_prompt(state, limit=6)]

    assert task_ids.index("input-reflection") < task_ids.index("data-query")


def test_query_like_form_prioritizes_data_query() -> None:
    state = AgentState()
    refresh_mission_board(
        state,
        description="Search form with result filtering.",
        surface={
            "counts": {"pages": 1, "forms": 1, "endpoints": 1},
            "forms": [
                {
                    "action": "http://127.0.0.1/search.php",
                    "method": "GET",
                    "inputs": [{"name": "q", "type": "search"}],
                    "categories": ["search"],
                }
            ],
            "parameters": [{"name": "q", "locations": ["http://127.0.0.1/search.php?q=a"]}],
            "endpoints": [{"url": "http://127.0.0.1/search.php", "hints": ["search"]}],
        },
    )

    task_ids = [task["id"] for task in active_tasks_for_prompt(state, limit=6)]

    assert task_ids.index("data-query") < task_ids.index("input-reflection")


def test_new_structured_form_signals_augment_initial_recon_surface() -> None:
    state = AgentState()
    state.signals["forms"] = [
        json.dumps(
            {
                "action": "http://127.0.0.1/admin/preview",
                "method": "GET",
                "inputs": [
                    {
                        "name": "url",
                        "type": "url",
                        "value": "http://127.0.0.1:9000/metadata",
                    }
                ],
            },
            sort_keys=True,
        )
    ]
    state.signals["parameters"] = ["url"]

    refresh_mission_board(
        state,
        description="Authenticated assessment",
        surface={
            "counts": {"pages": 1, "forms": 1, "endpoints": 1},
            "forms": [
                {
                    "action": "http://127.0.0.1/login",
                    "method": "POST",
                    "inputs": [{"name": "username", "type": "text"}],
                }
            ],
            "parameters": [{"name": "username", "hints": []}],
            "endpoints": [{"url": "http://127.0.0.1/login", "hints": ["auth"]}],
        },
    )

    task_ids = {str(task["id"]) for task in state.tasks}
    assert "file-fetch-parser" in task_ids


def test_repeated_low_value_secret_signals_are_blocked() -> None:
    state = AgentState()
    state.tasks = [_task("flag-and-secret-sweep", priority=90)]
    action = {"action": "run_probe", "task_id": "flag-and-secret-sweep", "probe": "secret_sweep"}
    outcome = {
        "outcome": "confirmed_signal",
        "observation": '{"findings":[{"matches":["filesystem_path:/var/www/html/login.php"]}]}',
    }

    for _index in range(4):
        update_mission_from_action(state, action=action, outcome=outcome)

    assert state.tasks[0]["status"] == "blocked"


def test_ordinary_assessment_omits_and_prunes_flag_sweep_task() -> None:
    state = AgentState()
    state.tasks = [_task("flag-and-secret-sweep", priority=90)]
    surface = {
        "flag_objective": False,
        "counts": {"pages": 1, "forms": 0, "endpoints": 1},
        "endpoints": [{"url": "http://127.0.0.1/", "hints": []}],
    }

    refresh_mission_board(state, description="Authorized assessment", surface=surface)

    task_ids = {str(task["id"]) for task in state.tasks}
    assert "surface-map" in task_ids
    assert "flag-and-secret-sweep" not in task_ids


def test_legacy_or_flag_assessment_keeps_flag_sweep_task() -> None:
    state = AgentState()

    refresh_mission_board(
        state,
        description="Capture the target proof",
        surface={"flag_objective": True, "counts": {}},
    )

    assert "flag-and-secret-sweep" in {str(task["id"]) for task in state.tasks}


def _task(task_id: str, *, priority: int) -> dict[str, object]:
    return {
        "id": task_id,
        "title": task_id,
        "status": "pending",
        "priority": priority,
        "attempts": 0,
        "rationale": "",
        "next_steps": [],
        "evidence": [],
        "last_outcome": "",
    }
