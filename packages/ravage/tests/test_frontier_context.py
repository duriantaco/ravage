from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_context import focused_frontier_context
from ravage.agent_core.frontier_route import FrontierObjective

EXPECTED_FACT_COUNT = 14
EXPECTED_ATTEMPT_COUNT = 6
EXPECTED_OMITTED_FACT_COUNT = 26
EXPECTED_OMITTED_ATTEMPT_COUNT = 14
MAX_CONTEXT_CHARS = 20_000


def _objective(*, dimension: str = "request_contract") -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="index.php",
        inputs=("username",),
        payload_class=f"confirmed_primitive:sqli_confirmed:{dimension}",
        expected_signal="continue the confirmed login SQL route",
    )


def test_context_keeps_assigned_sql_evidence_and_removes_stale_backup_branch() -> None:
    state = AgentState(
        phase="exploit",
        turn=46,
        facts=[
            "Confirmed SQLi exists on the index.php username input.",
            "Switching to direct exposure after stalled SQLi closure.",
            "A backup of upload.php may reveal source.",
        ],
        hypotheses=[
            "Replay the observed AJAX POST contract on index.php.",
            "The /upload.php.bak branch may expose source directly.",
        ],
        signals={
            "request_templates": [
                json.dumps({"method": "POST", "url": "index.php", "source": "jquery_ajax"})
            ],
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "url": "http://target/?username=admin%27--",
                        "payload_field": "username",
                    }
                )
            ],
            "endpoints": ["/index.php", "/index.php~", "/upload.php.bak"],
            "forms": [
                json.dumps(
                    {
                        "action": "index.php",
                        "method": "POST",
                        "inputs": ["username", "password"],
                    }
                )
            ],
        },
        primitives={"sqli_confirmed": 6, "direct_exposure_observed": 38},
        tasks=[
            {"id": "data-query", "title": "Test data query behavior"},
            {"id": "flag-sweep", "title": "Sweep backup files"},
        ],
        attempts=[
            {
                "turn": 41,
                "selected_action": {
                    "action": "run_command",
                    "command": "curl http://target/upload.php.bak",
                },
                "outcome": {"classification": "observed"},
            },
            {
                "turn": 35,
                "selected_action": {
                    "action": "run_probe",
                    "probe": "sqli_exploit",
                },
                "outcome": {"classification": "same_as_before"},
            },
        ],
        last_observation={"snippet": "404 from /upload.php.bak"},
    )

    context = focused_frontier_context(state, _objective())
    encoded = json.dumps(context).lower()

    assert "sqli" in encoded
    assert "index.php" in encoded
    assert "username" in encoded
    assert "jquery_ajax" in encoded
    assert "backup" not in encoded
    assert "upload.php.bak" not in encoded
    assert "direct_exposure" not in encoded
    assert context["last_relevant_observation"] == {}


def test_proof_channel_retains_downstream_access_transition_without_backup_noise() -> None:
    state = AgentState(
        facts=[
            "Authenticated session should unlock dashboard and upload.php.",
            "A backup file sweep was previously attempted.",
        ],
        primitives={"sqli_confirmed": 6},
    )

    encoded = json.dumps(
        focused_frontier_context(state, _objective(dimension="proof_channel"))
    ).lower()

    assert "authenticated session" in encoded
    assert "upload.php" in encoded
    assert "backup" not in encoded


def test_context_bounds_large_observations_and_reports_omissions() -> None:
    state = AgentState(
        facts=[f"SQLi fact {index}" for index in range(40)],
        attempts=[
            {
                "turn": index,
                "selected_action": {
                    "action": "run_python",
                    "code": "index.php username SQL " + ("x" * 10_000),
                },
                "outcome": {"classification": "observed"},
            }
            for index in range(20)
        ],
    )

    context = focused_frontier_context(state, _objective())
    encoded = json.dumps(context)

    assert len(context["facts"]) == EXPECTED_FACT_COUNT
    assert len(context["recent_relevant_attempts"]) == EXPECTED_ATTEMPT_COUNT
    assert context["omitted_counts"]["facts"] == EXPECTED_OMITTED_FACT_COUNT
    assert context["omitted_counts"]["attempts"] == EXPECTED_OMITTED_ATTEMPT_COUNT
    assert len(encoded) < MAX_CONTEXT_CHARS
