# ruff: noqa: CPY001, EM101, TRY003

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum


class GraphOperationalProfileName(StrEnum):
    """Auditable target-interaction modes for the additive graph route."""

    STANDARD = "standard"
    LOW_NOISE = "low-noise"


@dataclass(frozen=True)
class GraphOperationalProfile:
    name: GraphOperationalProfileName
    max_rps: float
    max_http_concurrency: int
    max_redirects: int
    max_total_requests: int
    jitter_min_seconds: float
    jitter_max_seconds: float
    stable_user_agent: str
    allow_shell: bool
    allow_browser: bool

    def __post_init__(self) -> None:
        if self.max_rps <= 0:
            raise ValueError("operational profile max_rps must be greater than zero")
        if self.max_http_concurrency <= 0:
            raise ValueError("operational profile max_http_concurrency must be greater than zero")
        if self.max_redirects < 0 or self.max_total_requests <= 0:
            raise ValueError("operational profile request limits are invalid")
        if not 0 <= self.jitter_min_seconds <= self.jitter_max_seconds:
            raise ValueError("operational profile jitter bounds are invalid")
        if not self.stable_user_agent.strip():
            raise ValueError("operational profile stable_user_agent is required")

    @property
    def minimum_interval_seconds(self) -> float:
        return 1.0 / self.max_rps

    def jitter_seconds(self, request_sequence: int) -> float:
        """Return replayable bounded jitter without mutable randomness."""
        if request_sequence <= 1 or self.jitter_max_seconds <= 0:
            return 0.0
        digest = hashlib.sha256(f"{self.name.value}:{request_sequence}".encode()).digest()
        fraction = int.from_bytes(digest[:8], "big") / ((1 << 64) - 1)
        spread = self.jitter_max_seconds - self.jitter_min_seconds
        return self.jitter_min_seconds + (spread * fraction)

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name.value,
            "max_rps": self.max_rps,
            "max_http_concurrency": self.max_http_concurrency,
            "max_redirects": self.max_redirects,
            "max_total_requests": self.max_total_requests,
            "jitter_min_seconds": self.jitter_min_seconds,
            "jitter_max_seconds": self.jitter_max_seconds,
            "stable_user_agent": self.stable_user_agent,
            "allow_shell": self.allow_shell,
            "allow_browser": self.allow_browser,
        }


def graph_operational_profile(
    name: GraphOperationalProfileName | str,
    *,
    roe_max_rps: int,
    max_total_requests: int,
) -> GraphOperationalProfile:
    """Resolve an operational profile under, never above, the brief's ROE."""
    selected = GraphOperationalProfileName(str(name))
    if roe_max_rps <= 0 or max_total_requests <= 0:
        raise ValueError("ROE and route request ceilings must be greater than zero")
    if selected is GraphOperationalProfileName.LOW_NOISE:
        return GraphOperationalProfile(
            name=selected,
            max_rps=min(float(roe_max_rps), 1.0),
            max_http_concurrency=1,
            max_redirects=4,
            max_total_requests=max_total_requests,
            jitter_min_seconds=0.15,
            jitter_max_seconds=0.45,
            stable_user_agent="ravage-authorized-assessment/1.0",
            allow_shell=False,
            allow_browser=False,
        )
    return GraphOperationalProfile(
        name=selected,
        max_rps=float(roe_max_rps),
        max_http_concurrency=1,
        max_redirects=4,
        max_total_requests=max_total_requests,
        jitter_min_seconds=0.0,
        jitter_max_seconds=0.0,
        stable_user_agent="ravage-authorized-assessment/1.0",
        allow_shell=False,
        allow_browser=False,
    )


__all__ = [
    "GraphOperationalProfile",
    "GraphOperationalProfileName",
    "graph_operational_profile",
]
