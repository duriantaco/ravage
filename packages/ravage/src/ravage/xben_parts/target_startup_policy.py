# Bounded policy for recovering transient XBEN target startup races.
# ruff: noqa: CPY001

from __future__ import annotations

from ravage.xben_parts.docker_ops import _target_readiness_error_is_restartable

_TARGET_UNREACHABLE_MARKER = "target did not become reachable"
_CONNECTION_REFUSED_MARKERS = (
    "connection refused",
    "[errno 61]",
    "[errno 111]",
)


def should_restart_web_service_after_readiness_error(exc: Exception) -> bool:
    """
    Allow one web restart for transient target-startup failures.

    XBEN images can briefly satisfy a dependency health check while an
    emulated database is still completing first-run initialization.  The web
    process then exits before binding its published port.  Treat that bounded
    connection-refused state like the existing restartable HTTP 5xx state.
    """
    if _target_readiness_error_is_restartable(exc):
        return True
    text = str(exc).lower()
    return _TARGET_UNREACHABLE_MARKER in text and any(
        marker in text for marker in _CONNECTION_REFUSED_MARKERS
    )
