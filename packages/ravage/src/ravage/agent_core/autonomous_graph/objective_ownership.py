from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.models import GraphObjective

_EXCLUSIVE_STRATEGIES = frozenset(
    {
        "sqli_auth_transition",
    }
)

ObjectiveOwnerKey = tuple[str, str, tuple[str, ...], str]


def exclusive_objective_owner_key(
    objective: GraphObjective,
) -> ObjectiveOwnerKey | None:
    """
    Identify transition workflows that must have only one active route owner.

    Exploratory objectives may intentionally share a broad probe while testing
    different material dimensions. State-transition workflows are different:
    concurrent workers would mutate or verify the same session boundary and
    repeat the same finite campaign.
    """
    strategy = _token(objective.strategy)
    if strategy not in _EXCLUSIVE_STRATEGIES:
        return None
    return (
        _token(objective.family),
        _endpoint(objective.endpoint),
        tuple(sorted({_token(item) for item in objective.inputs if _token(item)})),
        strategy,
    )


def _endpoint(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    parsed = urlsplit(text)
    path = parsed.path.rstrip("/") or "/"
    if parsed.scheme or parsed.netloc:
        return urlunsplit(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                path,
                parsed.query,
                "",
            )
        )
    return urlunsplit(("", "", path, parsed.query, ""))


def _token(value: str) -> str:
    return " ".join(value.strip().lower().split()).replace(" ", "_")


__all__ = [
    "ObjectiveOwnerKey",
    "exclusive_objective_owner_key",
]
