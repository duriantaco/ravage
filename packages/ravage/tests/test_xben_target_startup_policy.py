# ruff: noqa: CPY001

from __future__ import annotations

import pytest
from ravage.xben_parts.target_startup_policy import (
    should_restart_web_service_after_readiness_error,
)


@pytest.mark.parametrize(
    "detail",
    [
        "HTTP 500",
        "<urlopen error [Errno 61] Connection refused>",
        "<urlopen error [Errno 111] Connection refused>",
    ],
)
def test_target_startup_policy_restarts_transient_readiness_failures(
    detail: str,
) -> None:
    error = RuntimeError(f"target did not become reachable at http://localhost:12345: {detail}")

    assert should_restart_web_service_after_readiness_error(error) is True


@pytest.mark.parametrize(
    "message",
    [
        "target did not become reachable at http://localhost:12345: timed out",
        "docker compose up failed: dependency is unhealthy",
        "connection refused while contacting an unrelated service",
    ],
)
def test_target_startup_policy_does_not_broaden_restart_scope(message: str) -> None:
    assert should_restart_web_service_after_readiness_error(RuntimeError(message)) is False
