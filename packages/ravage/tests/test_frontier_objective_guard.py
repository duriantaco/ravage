from __future__ import annotations

import pytest
from ravage.agent_core.frontier_objective_guard import (
    alignment_guard_message,
    detect_objective_alignment_issue,
)
from ravage.agent_core.frontier_route import FrontierObjective


def _objective(*, dimension: str = "request_contract") -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="index.php",
        inputs=("username",),
        payload_class=f"confirmed_primitive:sqli_confirmed:{dimension}",
        expected_signal=(
            "Preserve the confirmed route. The default run_probe sqli_exploit "
            "route is exhausted; do not rerun it unchanged."
        ),
        evidence_refs=("primitive:sqli_confirmed:turn:6",),
    )


def test_run5_backup_action_is_rejected_without_tool_execution() -> None:
    action = {
        "action": "run_command",
        "command": (
            "sh -lc 'for p in /upload.php~ /dashboard.php~ /index.php~; "
            "do curl http://ravage-target:64811$p; done'"
        ),
        "expected_signal": ("A backup reveals login details for a later username SQL route."),
    }

    issue = detect_objective_alignment_issue(_objective(), action)

    assert issue is not None
    assert issue.code == "objective_drift"
    assert "assigned_endpoint" in issue.missing_dimensions
    assert "assigned_inputs" in issue.missing_dimensions


@pytest.mark.parametrize("suffix", ["~", ".bak", ".old"])
def test_endpoint_suffix_does_not_impersonate_assigned_endpoint(suffix: str) -> None:
    action = {
        "action": "run_command",
        "command": (f"curl -X POST http://target/index.php{suffix} --data username=admin"),
    }

    issue = detect_objective_alignment_issue(_objective(), action)

    assert issue is not None
    assert "assigned_endpoint" in issue.missing_dimensions


def test_exact_request_contract_action_is_admissible() -> None:
    action = {
        "action": "run_python",
        "code": (
            "data=urlencode({'username': user, 'password': password, "
            "'submit': 'submit'}); "
            "Request(base+'index.php', data=data, method='POST')"
        ),
    }

    assert detect_objective_alignment_issue(_objective(), action) is None


def test_shell_quoted_endpoint_is_checked_as_raw_execution_text() -> None:
    action = {
        "action": "run_command",
        "command": (
            'curl -X POST "$RAVAGE_TARGET_URL/index.php" '
            '--data "username=admin&password=x&submit=submit"'
        ),
    }

    assert detect_objective_alignment_issue(_objective(), action) is None


def test_payload_semantics_requires_a_family_specific_change() -> None:
    ordinary_login = {
        "action": "run_python",
        "code": ("Request(base+'index.php', data=urlencode({'username': user}), method='POST')"),
    }
    changed_oracle = {
        "action": "run_python",
        "code": (
            'payload="x\' AND ascii(substr((select password from users),1,1))>64-- -"; '
            "Request(base+'index.php', data=urlencode({'username': payload}), "
            "method='POST')"
        ),
    }

    issue = detect_objective_alignment_issue(
        _objective(dimension="payload_semantics"),
        ordinary_login,
    )

    assert issue is not None
    assert "changed_payload_semantics" in issue.missing_dimensions
    assert (
        detect_objective_alignment_issue(
            _objective(dimension="payload_semantics"),
            changed_oracle,
        )
        is None
    )


@pytest.mark.parametrize(
    "command",
    [
        ("post({'username': \"admin' OR '1'='1'-- -\", 'password': 'x'}, endpoint='index.php')"),
        ('curl "$RAVAGE_TARGET_URL/index.php?username=-1%27%20UNION%20SELECT%201--%20-"'),
    ],
)
def test_sql_payload_semantics_accept_boolean_and_encoded_union(
    command: str,
) -> None:
    action = {"action": "run_command", "command": command}

    assert (
        detect_objective_alignment_issue(
            _objective(dimension="payload_semantics"),
            action,
        )
        is None
    )


def test_unchanged_exhausted_specialist_is_rejected() -> None:
    issue = detect_objective_alignment_issue(
        _objective(),
        {"action": "run_probe", "probe": "sqli_exploit"},
    )

    assert issue is not None
    assert issue.code == "unchanged_specialist_route"


def test_guard_explicitly_preserves_budget_accounting() -> None:
    objective = _objective()
    issue = detect_objective_alignment_issue(
        objective,
        {"action": "run_command", "command": "curl http://target/upload.php.bak"},
    )

    assert issue is not None
    message = alignment_guard_message(objective, issue)
    assert "Action not executed" in message
    assert "model request remains charged" in message


def test_unconfirmed_objective_remains_unconstrained() -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_differential",
        endpoint="/search",
        inputs=("q",),
        payload_class="specialist:sqli_differential",
        expected_signal="paired target differential",
    )

    assert (
        detect_objective_alignment_issue(
            objective,
            {"action": "run_command", "command": "curl http://target/robots.txt"},
        )
        is None
    )
