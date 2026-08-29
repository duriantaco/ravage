# ruff: noqa: CPY001

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

MAX_PROVIDER_CONTINUITY_RETRIES_PER_NODE = 1


class ProviderFailureKind(StrEnum):
    QUOTA = "quota"
    CAPACITY = "capacity"
    TRANSIENT = "transient"
    NON_RETRYABLE = "non_retryable"


@dataclass(frozen=True)
class ProviderFailure:
    kind: ProviderFailureKind
    retryable: bool
    reason: str


class GraphModelContinuityRequiredError(RuntimeError):
    """Ask the worker to account one interrupted call before changing route."""

    def __init__(
        self,
        *,
        failure: ProviderFailure,
        from_route: str,
        to_route: str,
    ) -> None:
        self.failure = failure
        self.from_route = from_route
        self.to_route = to_route
        super().__init__(f"provider_continuity:{failure.kind.value}:{from_route}->{to_route}")


_NON_RETRYABLE_MARKERS = (
    "authentication",
    "context length",
    "context window",
    "invalid api key",
    "invalid request",
    "permission",
    "policy violation",
    "prompt is too long",
    "unauthorized",
)
_QUOTA_MARKERS = (
    "429",
    "insufficient_quota",
    "quota",
    "rate limit",
    "rate_limit",
    "too many requests",
    "usage limit",
)
_CAPACITY_MARKERS = (
    "capacity",
    "model overloaded",
    "overloaded",
    "resource exhausted",
)
_TRANSIENT_MARKERS = (
    "502",
    "503",
    "504",
    "connection reset",
    "gateway unavailable",
    "service unavailable",
    "temporarily unavailable",
)


def classify_provider_failure(exc: BaseException) -> ProviderFailure:
    """Classify only explicit provider-side failures as continuity-safe."""
    text = " ".join(f"{type(exc).__name__}: {exc}".lower().split())
    if any(marker in text for marker in _NON_RETRYABLE_MARKERS):
        return ProviderFailure(
            kind=ProviderFailureKind.NON_RETRYABLE,
            retryable=False,
            reason="provider_failure_requires_logic_or_configuration_change",
        )
    if any(marker in text for marker in _QUOTA_MARKERS):
        return ProviderFailure(
            kind=ProviderFailureKind.QUOTA,
            retryable=True,
            reason="provider_rejected_for_quota_or_rate_limit",
        )
    if any(marker in text for marker in _CAPACITY_MARKERS):
        return ProviderFailure(
            kind=ProviderFailureKind.CAPACITY,
            retryable=True,
            reason="provider_rejected_for_capacity",
        )
    if any(marker in text for marker in _TRANSIENT_MARKERS):
        return ProviderFailure(
            kind=ProviderFailureKind.TRANSIENT,
            retryable=True,
            reason="provider_returned_explicit_transient_failure",
        )
    return ProviderFailure(
        kind=ProviderFailureKind.NON_RETRYABLE,
        retryable=False,
        reason="provider_failure_not_safe_for_automatic_continuity",
    )


__all__ = [
    "MAX_PROVIDER_CONTINUITY_RETRIES_PER_NODE",
    "GraphModelContinuityRequiredError",
    "ProviderFailure",
    "ProviderFailureKind",
    "classify_provider_failure",
]
