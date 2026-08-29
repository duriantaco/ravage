from __future__ import annotations

from ravage.agent_core.agent_strategy import observation_digest

_HIGH_SIGNAL_LIMIT = 600
_HEAD_TAIL_LIMIT = 120


def test_observation_digest_preserves_head_high_signal_stdout_and_tail() -> None:
    text = (
        '{"command":"'
        + ("W" * 4_000)
        + '","stdout":"root:x:0:0:root:/root:/bin/bash\\nwww-data:x:33:33:...",'
        + '"trailer":"'
        + ("T" * 2_000)
        + '"}'
    )

    digest = observation_digest(text, limit=_HIGH_SIGNAL_LIMIT)
    snippet = str(digest["snippet"])

    assert len(snippet) <= _HIGH_SIGNAL_LIMIT
    assert snippet.startswith('{"command":"')
    assert "root:x:0:0:" in snippet
    assert snippet.endswith('TTTTTTTTTTTTTTTTTT"}')
    assert digest["markers"] == ["root:x:0:0:"]


def test_observation_digest_uses_head_tail_when_no_high_signal_exists() -> None:
    text = "HEAD" + ("x" * 2_000) + "TAIL"

    snippet = str(observation_digest(text, limit=_HEAD_TAIL_LIMIT)["snippet"])

    assert len(snippet) <= _HEAD_TAIL_LIMIT
    assert snippet.startswith("HEAD")
    assert snippet.endswith("TAIL")
    assert "observation clipped" in snippet


def test_observation_digest_preserves_short_text_exactly() -> None:
    assert observation_digest("short", limit=20)["snippet"] == "short"
