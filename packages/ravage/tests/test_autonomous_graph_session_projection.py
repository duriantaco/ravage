# ruff: noqa: CPY001, PLR2004

from __future__ import annotations

import hashlib
import json

import pytest
from ravage.agent_core.autonomous_graph.session_projection import (
    SessionProjectionError,
    SessionProjectionLimits,
    project_session_records,
)
from ravage.agent_core.autonomous_graph.sessions import SessionRecord, SessionRole


def _record(role: SessionRole, content: str) -> SessionRecord:
    return SessionRecord(role=role, content=content)


def test_projection_preserves_small_session_exactly() -> None:
    context = '{"evidence_epoch": 2}'
    records = (
        _record(SessionRole.ASSISTANT, "prior"),
        _record(SessionRole.USER, context),
    )

    projection = project_session_records(
        records,
        authoritative_context=context,
    )

    assert projection.compacted is False
    assert projection.messages == tuple(item.to_message() for item in records)


def test_projection_replaces_old_prefix_with_digest_and_keeps_typed_context() -> None:
    context = '{"authoritative": true, "evidence_epoch": 9}'
    records = (
        _record(SessionRole.USER, "secret-old-prefix"),
        _record(SessionRole.ASSISTANT, "old-answer"),
        _record(SessionRole.TOOL, "recent-tool"),
        _record(SessionRole.ASSISTANT, "recent-answer"),
        _record(SessionRole.USER, context),
    )
    limits = SessionProjectionLimits(
        max_records=4,
        max_chars=2_000,
        recent_records=2,
    )

    projection = project_session_records(
        records,
        authoritative_context=context,
        limits=limits,
    )

    checkpoint = json.loads(projection.messages[0]["content"])
    expected_digest = hashlib.sha256(
        json.dumps(
            [
                {
                    "role": SessionRole.USER.value,
                    "content": "secret-old-prefix",
                },
                {
                    "role": SessionRole.ASSISTANT.value,
                    "content": "old-answer",
                },
            ],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert projection.compacted is True
    assert checkpoint["marker"] == "RAVAGE_TYPED_SESSION_CHECKPOINT_V1"
    assert checkpoint["omitted_records"] == 2
    assert checkpoint["omitted_sha256"] == expected_digest
    assert projection.messages[-1] == {
        "role": SessionRole.USER.value,
        "content": context,
    }
    assert "secret-old-prefix" not in json.dumps(projection.messages)
    assert [item["content"] for item in projection.messages[1:-1]] == [
        "recent-tool",
        "recent-answer",
    ]


def test_projection_never_silently_replaces_authoritative_context() -> None:
    with pytest.raises(SessionProjectionError, match="latest session record"):
        project_session_records(
            (_record(SessionRole.USER, "different"),),
            authoritative_context="current",
        )

    with pytest.raises(SessionProjectionError, match="exceeds"):
        project_session_records(
            (_record(SessionRole.USER, "x" * 1_100),),
            authoritative_context="x" * 1_100,
            limits=SessionProjectionLimits(
                max_records=3,
                max_chars=2_000,
                recent_records=1,
            ),
        )
