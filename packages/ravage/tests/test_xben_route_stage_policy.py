# ruff: noqa: CPY001, PLR2004

from __future__ import annotations

from ravage.xben_parts.models import XbenSettings
from ravage.xben_parts.route_stage_policy import agent_stage_timeout_policy


def test_route_disabled_preserves_the_existing_case_timeout() -> None:
    policy = agent_stage_timeout_policy(
        XbenSettings(
            case_timeout_seconds=600,
            autonomous_route=False,
        )
    )

    assert policy.base_seconds == 600
    assert policy.autonomous_route_seconds == 0
    assert policy.subprocess_seconds == 600


def test_route_reserves_a_bounded_stage_after_the_frozen_base() -> None:
    policy = agent_stage_timeout_policy(
        XbenSettings(
            case_timeout_seconds=600,
            autonomous_route=True,
            autonomous_route_max_requests=24,
        )
    )

    assert policy.base_seconds == 600
    assert policy.autonomous_route_seconds == 600
    assert policy.subprocess_seconds == 1_200


def test_small_route_request_budget_gets_only_the_minimum_stage_allowance() -> None:
    policy = agent_stage_timeout_policy(
        XbenSettings(
            case_timeout_seconds=600,
            autonomous_route=True,
            autonomous_route_max_requests=2,
        )
    )

    assert policy.autonomous_route_seconds == 120
    assert policy.subprocess_seconds == 720


def test_route_allowance_never_exceeds_the_base_allowance() -> None:
    policy = agent_stage_timeout_policy(
        XbenSettings(
            case_timeout_seconds=60,
            autonomous_route=True,
            autonomous_route_max_requests=24,
        )
    )

    assert policy.autonomous_route_seconds == 60
    assert policy.subprocess_seconds == 120
