from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

_RECENT_ATTEMPT_LIMIT = 6
_MIN_CONSENSUS_ATTEMPTS = 2
_UNKNOWN_FAMILIES = frozenset({"", "unknown"})


class RecoveryRouteAttempt(Protocol):
    family: str
    low_value: bool


def consensus_low_value_family(attempts: Sequence[RecoveryRouteAttempt]) -> str:
    """Return a recent strict-majority family only when the latest routes agree."""
    recent = [
        attempt.family
        for attempt in attempts[-_RECENT_ATTEMPT_LIMIT:]
        if attempt.low_value and attempt.family not in _UNKNOWN_FAMILIES
    ]
    if len(recent) < _MIN_CONSENSUS_ATTEMPTS:
        return ""

    candidate = recent[-1]
    trailing_support = 0
    for family in reversed(recent):
        if family != candidate:
            break
        trailing_support += 1
    if trailing_support < _MIN_CONSENSUS_ATTEMPTS:
        return ""

    total_support = sum(family == candidate for family in recent)
    if total_support * 2 <= len(recent):
        return ""
    return candidate


__all__ = ["consensus_low_value_family"]
