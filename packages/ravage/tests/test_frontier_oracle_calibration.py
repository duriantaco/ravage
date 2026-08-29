from __future__ import annotations

import json

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_oracle_calibration import (
    assess_oracle_calibration,
    oracle_calibration_message,
    pending_oracle_calibration_issue,
    remember_oracle_calibration_issue,
    remembered_oracle_calibration_issues,
    resolve_oracle_calibration_issues,
)
from ravage.agent_core.frontier_route import FrontierObjective


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract replayable target proof",
    )


def test_identical_docker_wrapped_controls_open_calibration_issue() -> None:
    objective = _objective()
    observation = json.dumps(
        {
            "stdout": (
                'CAL T 23 {"response":"password"}\nCAL F 23 {"response":"password"}\nPREFIX 1  \n'
            )
        }
    )

    assessment = assess_oracle_calibration(objective, observation)

    assert assessment.issue is not None
    assert not assessment.calibrated
    assert assessment.issue.true_labels == ("t",)
    assert assessment.issue.false_labels == ("f",)
    message = oracle_calibration_message(objective, assessment.issue)
    assert "identical signatures" in message
    assert "cannot independently match a baseline row" in message


def test_distinct_controls_resolve_durable_issue() -> None:
    objective = _objective()
    failed = assess_oracle_calibration(
        objective,
        ('CAL bool_true 23 {"response":"password"}\nCAL bool_false 23 {"response":"password"}'),
    )
    assert failed.issue is not None
    state = AgentState()
    remember_oracle_calibration_issue(state, failed.issue)
    assert pending_oracle_calibration_issue(state, objective=objective) is not None
    assert len(remembered_oracle_calibration_issues(state, objective=objective)) == 1

    corrected = assess_oracle_calibration(
        objective,
        ('CAL bool_true 23 {"response":"password"}\nCAL bool_false 23 {"response":"username"}'),
    )
    assert corrected.calibrated
    assert corrected.issue is None
    resolved = resolve_oracle_calibration_issues(state, objective=objective)

    assert resolved == (failed.issue.fingerprint,)
    assert pending_oracle_calibration_issue(state, objective=objective) is None
    assert remembered_oracle_calibration_issues(state, objective=objective) == []


def test_control_named_lines_are_calibrated() -> None:
    assessment = assess_oracle_calibration(
        _objective(),
        json.dumps(
            {
                "stdout": (
                    'CONTROL_TRUE {"response":"password"}\n'
                    'CONTROL_FALSE {"response":"username"}\n'
                    "PREFIX admin\n"
                )
            }
        ),
    )

    assert assessment.issue is None
    assert assessment.calibrated


def test_unlabeled_output_does_not_invent_calibration_state() -> None:
    assessment = assess_oracle_calibration(
        _objective(),
        '{"response":"password"}',
    )

    assert assessment.issue is None
    assert not assessment.calibrated


def test_calibration_literals_in_docker_command_are_not_observations() -> None:
    observation = json.dumps(
        {
            "command": [
                "sh",
                "-lc",
                (
                    'print(\'CAL T 23 {"response":"password"}\')\n'
                    'print(\'CAL F 23 {"response":"password"}\')'
                ),
            ],
            "exit_code": 0,
            "stdout": "calibration script did not emit controls\n",
        }
    )

    assessment = assess_oracle_calibration(_objective(), observation)

    assert assessment.issue is None
    assert not assessment.calibrated
