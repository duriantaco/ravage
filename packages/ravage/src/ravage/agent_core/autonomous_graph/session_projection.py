# ruff: noqa: CPY001, EM101, TRY003

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ravage.agent_core.autonomous_graph.sessions import SessionRecord


_CHECKPOINT_MARKER = "RAVAGE_TYPED_SESSION_CHECKPOINT_V1"
_CHECKPOINT_RESERVE_CHARS = 1_024


@dataclass(frozen=True)
class SessionProjectionLimits:
    max_records: int = 20
    max_chars: int = 64_000
    recent_records: int = 12

    def __post_init__(self) -> None:
        if self.max_records <= 0 or self.max_chars <= 0 or self.recent_records <= 0:
            raise ValueError("session projection limits must be greater than zero")
        if self.recent_records > self.max_records:
            raise ValueError("recent_records cannot exceed max_records")


@dataclass(frozen=True)
class SessionProjection:
    messages: tuple[dict[str, str], ...]
    compacted: bool
    omitted_records: int = 0
    omitted_sha256: str = ""


class SessionProjectionError(ValueError):
    """Raised when authoritative typed state cannot be preserved exactly."""


def project_session_records(
    records: Sequence[SessionRecord],
    *,
    authoritative_context: str,
    limits: SessionProjectionLimits | None = None,
) -> SessionProjection:
    """
    Project durable history without an LLM-authored summary.

    The latest typed worker context is authoritative and already contains the
    evidence blackboard, investigation ledger, inbox, and budget state. When
    older conversational records exceed the provider-facing allowance, retain
    a recent exact tail and replace the omitted prefix with a digest receipt.
    """
    selected_limits = limits or SessionProjectionLimits()
    all_records = tuple(records)
    if not all_records or all_records[-1].content != authoritative_context:
        raise SessionProjectionError(
            "latest session record must be the authoritative typed context"
        )
    if len(authoritative_context) + _CHECKPOINT_RESERVE_CHARS > selected_limits.max_chars:
        raise SessionProjectionError(
            "authoritative typed context exceeds the provider projection limit"
        )
    total_chars = sum(len(record.content) for record in all_records)
    if len(all_records) <= selected_limits.max_records and total_chars <= selected_limits.max_chars:
        return SessionProjection(
            messages=tuple(record.to_message() for record in all_records),
            compacted=False,
        )

    prior_records = all_records[:-1]
    tail = _bounded_exact_tail(
        prior_records,
        max_records=min(
            selected_limits.recent_records,
            selected_limits.max_records - 2,
        ),
        max_chars=(
            selected_limits.max_chars - len(authoritative_context) - _CHECKPOINT_RESERVE_CHARS
        ),
    )
    omitted_count = max(len(prior_records) - len(tail), 0)
    omitted = prior_records[:omitted_count]
    digest = _records_digest(omitted)
    checkpoint = {
        "marker": _CHECKPOINT_MARKER,
        "omitted_records": omitted_count,
        "omitted_sha256": digest,
        "authority": (
            "The current typed graph context and durable evidence/investigation "
            "state are authoritative. The digest proves which conversational "
            "prefix was omitted; it is not evidence and must not be interpreted "
            "as a factual summary."
        ),
    }
    checkpoint_message = {
        "role": "user",
        "content": json.dumps(
            checkpoint,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
    }
    return SessionProjection(
        messages=(
            checkpoint_message,
            *(record.to_message() for record in tail),
            all_records[-1].to_message(),
        ),
        compacted=True,
        omitted_records=omitted_count,
        omitted_sha256=digest,
    )


def _bounded_exact_tail(
    records: Sequence[SessionRecord],
    *,
    max_records: int,
    max_chars: int,
) -> tuple[SessionRecord, ...]:
    remaining = max(max_chars, 0)
    selected: list[SessionRecord] = []
    for record in reversed(records[-max_records:]):
        if len(record.content) > remaining:
            break
        selected.append(record)
        remaining -= len(record.content)
    return tuple(reversed(selected))


def _records_digest(records: Sequence[SessionRecord]) -> str:
    payload = [
        {
            "role": record.role.value,
            "content": record.content,
        }
        for record in records
    ]
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "SessionProjection",
    "SessionProjectionError",
    "SessionProjectionLimits",
    "project_session_records",
]
