# ruff: noqa: S608 - vulnerable source strings are analyzer fixtures.
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from ravage.model_core.providers import ResolvedModelRoute
from ravage.repository_review import ReviewMessage, ReviewReply, run_repository_review
from ravage.source_analysis import SourceLimitError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    import pytest

_SEEDED_REVIEW_MODEL_CALLS = 2


class _ScriptedClient:
    def __init__(
        self,
        actions: Sequence[dict[str, object]],
        *,
        before_reply: Callable[[int], None] | None = None,
    ) -> None:
        self.actions = list(actions)
        self.before_reply = before_reply
        self.messages_seen: list[tuple[ReviewMessage, ...]] = []

    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        del route
        self.messages_seen.append(tuple(messages))
        call = len(self.messages_seen)
        if self.before_reply is not None:
            self.before_reply(call)
        return ReviewReply(content=json.dumps(self.actions.pop(0)))


def _route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="low",
        selected_tier="low",
        ordinal=1,
        provider="ollama",
        model="fixture-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=256,
        output_token_limit_parameter="max_tokens",  # noqa: S106 - API parameter name.
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=5.0,
        max_retries=0,
    )


def _final(*, evidence_ids: list[str] | None = None) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    if evidence_ids is not None:
        findings.append(
            {
                "vuln_class": "sql_injection",
                "title": "Request input reaches SQL text",
                "severity": "high",
                "confidence": "high",
                "description": "The route concatenates request input into SQL text.",
                "recommendation": "Use a parameterized query.",
                "evidence_ids": evidence_ids,
            }
        )
    return {
        "action": "final",
        "args": {"summary": "Review complete.", "findings": findings},
    }


def _vulnerable_source(marker: str = "CAPTURED_QUERY_MARKER") -> str:
    return f"""from flask import Flask, request

app = Flask(__name__)

@app.get("/search")
def search():
    term = request.args.get("term")
    return database.execute("SELECT * FROM records WHERE name = '" + term + "'")  # {marker}
"""


def test_review_lists_snapshot_bound_source_candidates_without_rereading_disk(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    captured_marker = "CAPTURED_QUERY_MARKER"
    source.write_text(_vulnerable_source(captured_marker), encoding="utf-8")

    def mutate_after_capture(call: int) -> None:
        if call == 1:
            source.write_text("SAFE = True\n", encoding="utf-8")

    client = _ScriptedClient(
        [
            {
                "action": "list_source_candidates",
                "args": {
                    "family": "sql_injection",
                    "path_prefix": "app",
                    "cursor": 0,
                    "limit": 10,
                },
            },
            {
                "action": "excerpt",
                "args": {"path": "app.py", "start_line": 5, "end_line": 20},
            },
            _final(evidence_ids=["excerpt-1"]),
        ],
        before_reply=mutate_after_capture,
    )

    result = run_repository_review(
        source_root=tmp_path,
        route=_route(),
        client=client,
    )

    observation = result.steps[0].observation
    [candidate] = observation["candidates"]
    assert candidate == {
        "candidate_id": candidate["candidate_id"],
        "status": "hypothesis",
        "family": "sql_injection",
        "method": "GET",
        "route": "/search",
        "input_name": "term",
        "input_location": "query",
        "framework": "flask",
        "route_binding": "direct",
        "path": "app.py",
        "line": 8,
        "sink_kind": "sql_execute",
        "reason": "request input reaches the SQL text argument",
        "file_digest": candidate["file_digest"],
        "snapshot_id": result.snapshot_id,
    }
    evidence = result.findings[0].evidence[0]
    assert evidence.file_digest == candidate["file_digest"]
    assert evidence.snapshot_id == candidate["snapshot_id"]
    assert captured_marker in evidence.text
    assert source.read_text(encoding="utf-8") == "SAFE = True\n"
    assert result.source_candidates_enabled is True
    assert result.source_candidates_total == 1
    assert result.source_candidates_listed == 1
    assert result.source_candidate_files_listed == 1
    assert result.source_candidate_families_listed == 1
    assert result.source_candidate_analysis_available is True
    assert result.source_candidate_index_digest.startswith("sha256:")
    public_result = result.to_json()
    public_step = public_result["steps"][0]
    assert "path_prefix" not in public_step["observation"]
    assert "family" not in public_step["observation"]
    assert "path_prefix" not in public_step["arguments"]
    assert "family" not in public_step["arguments"]
    assert public_step["arguments"]["path_prefix_digest"].startswith("sha256:")
    assert public_step["arguments"]["family_digest"].startswith("sha256:")
    assert captured_marker not in json.dumps(public_result, sort_keys=True)


def test_source_candidate_exposure_can_be_disabled_for_literal_only_ab(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _vulnerable_source()
    (tmp_path / "app.py").write_text(source, encoding="utf-8")

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        message = "disabled A/B arm must not run source analysis"
        raise AssertionError(message)

    monkeypatch.setattr(
        "ravage.repository_review.build_repository_source_candidate_index",
        fail_if_called,
    )
    client = _ScriptedClient(
        [
            {"action": "search", "args": {"query": "database.execute"}},
            {
                "action": "excerpt",
                "args": {"path": "app.py", "start_line": 5, "end_line": 20},
            },
            _final(evidence_ids=["excerpt-1"]),
        ]
    )

    result = run_repository_review(
        source_root=tmp_path,
        route=_route(),
        client=client,
        source_candidates_enabled=False,
    )

    first_messages = client.messages_seen[0]
    assert "list_source_candidates" not in first_messages[0].content
    assert "source candidate" not in first_messages[0].content.casefold()
    assert hashlib.sha256(first_messages[0].content.encode()).hexdigest() == (
        "16682c84ed64935aa0be9dc9c3488a5929108cff9b3902697508e40e87324354"
    )
    assert "source_candidates" not in json.loads(first_messages[1].content)
    assert result.source_candidates_enabled is False
    assert result.source_candidates_total == 0
    assert result.source_candidates_seeded == 0
    assert result.source_candidates_listed == 0
    assert result.source_candidate_analysis_available is False
    assert result.to_json()["source_candidates"]["enabled"] is False


def test_review_seeds_candidates_without_forcing_an_extra_navigation_turn(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(_vulnerable_source(), encoding="utf-8")
    client = _ScriptedClient(
        [
            {
                "action": "excerpt",
                "args": {"path": "app.py", "start_line": 5, "end_line": 20},
            },
            _final(),
        ]
    )

    result = run_repository_review(
        source_root=tmp_path,
        route=_route(),
        client=client,
        max_turns=2,
    )

    initial = json.loads(client.messages_seen[0][1].content)
    [seeded] = initial["source_candidates"]["seeded_candidates"]
    assert seeded["family"] == "sql_injection"
    assert seeded["path"] == "app.py"
    assert result.model_calls == _SEEDED_REVIEW_MODEL_CALLS
    assert all(step.ok for step in result.steps)
    assert result.source_candidates_seeded == 1
    assert result.source_candidates_listed == 0
    assert result.source_candidates_excerpted == 1


def test_review_records_when_seeded_candidates_are_not_examined(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(_vulnerable_source(), encoding="utf-8")
    (tmp_path / "notes.txt").write_text("unrelated\n", encoding="utf-8")
    client = _ScriptedClient(
        [
            {
                "action": "excerpt",
                "args": {"path": "notes.txt", "start_line": 1, "end_line": 1},
            },
            _final(),
        ]
    )

    result = run_repository_review(
        source_root=tmp_path,
        route=_route(),
        client=client,
        max_turns=2,
    )

    assert all(step.ok for step in result.steps)
    assert result.source_candidates_seeded == 1
    assert result.source_candidates_excerpted == 0


def test_source_candidate_analysis_limit_failure_falls_back_to_generic_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    def fail_analysis(*_args: object, **_kwargs: object) -> None:
        message = "synthetic analyzer limit marker"
        raise SourceLimitError(message)

    monkeypatch.setattr(
        "ravage.repository_source_candidates.analyze_source_snapshots",
        fail_analysis,
    )
    client = _ScriptedClient(
        [
            {
                "action": "excerpt",
                "args": {"path": "module.py", "start_line": 1, "end_line": 1},
            },
            _final(),
        ]
    )

    result = run_repository_review(
        source_root=tmp_path,
        route=_route(),
        client=client,
    )

    assert result.findings == ()
    assert result.source_candidate_analysis_available is False
    assert result.source_candidate_analysis_error_digest is not None
    assert result.source_python_files_analyzed == 0
    assert result.source_candidates_total == 0
    public = result.to_json()["source_candidates"]
    assert public["analysis_available"] is False
    assert "synthetic analyzer limit marker" not in json.dumps(public)
