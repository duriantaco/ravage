from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from ravage.agent_core.recovery_policy import ProgressSnapshot

if TYPE_CHECKING:
    from collections.abc import Sequence


def trusted_material_progress_tokens(
    assessment: object,
    *,
    coordinator_progress: Sequence[str] = (),
) -> tuple[str, ...]:
    """Return only typed evidence deltas or independently validated coordinator work."""
    coordinator = {str(item) for item in coordinator_progress if str(item)}
    material = getattr(assessment, "material_progress", ())
    if not material:
        return tuple(sorted(coordinator))

    snapshot = getattr(assessment, "snapshot", None)
    payload = snapshot.to_json() if isinstance(snapshot, ProgressSnapshot) else {}
    tokens: set[str] = set(coordinator)
    for field, values in payload.items():
        if field in {"confirmed_proofs", "weak_signals"} or not isinstance(
            values,
            list,
        ):
            continue
        tokens.update(f"{field}:{_digest(str(value))}" for value in values)
    if tokens:
        return tuple(sorted(tokens))

    tokens.update(str(getattr(item, "value", item)) for item in material)
    return tuple(sorted(item for item in tokens if item))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = ["trusted_material_progress_tokens"]
