from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ravage.agent_core.autonomous_graph.models import GraphObjective


class GraphActionRejectedError(ValueError):
    """Raised before tool accounting when durable evidence forbids an action."""


@dataclass(frozen=True)
class GraphRoutingDirective:
    """Coordinator-validated request to assign one distinct closure worker."""

    name: str
    objective: GraphObjective
    reason: str
    evidence_refs: tuple[str, ...]
    work_id: str = ""
    lease_limit: int = 2
    park_source: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            message = "routing directive name is required"
            raise ValueError(message)
        if not self.reason.strip():
            message = "routing directive reason is required"
            raise ValueError(message)
        if self.lease_limit <= 0:
            message = "routing directive lease must be positive"
            raise ValueError(message)


class GraphActionGuard(Protocol):
    def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: Mapping[str, object],
    ) -> None: ...


__all__ = [
    "GraphActionGuard",
    "GraphActionRejectedError",
    "GraphRoutingDirective",
]
