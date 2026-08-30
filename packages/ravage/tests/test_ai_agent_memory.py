from __future__ import annotations

import json
import sqlite3
from io import StringIO
from typing import TYPE_CHECKING

from ai_agent_fixtures import BRIEF_YAML, ScriptedModelClient, VulnerableOpenApiHttpClient
from ravage.agent_core import ai_agent
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    ChatMessage,
    ModelReply,
    run_ai_web_agent,
)
from ravage.memory import MemoryItem, MemoryRunSettings, MemoryStore

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    import pytest
    from ravage.model_core.providers import ResolvedModelRoute


class _CostlyScriptedModelClient(ScriptedModelClient):
    def complete(
        self,
        *,
        messages: Sequence[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        reply = super().complete(messages=messages, route=route)
        return ModelReply(content=reply.content, cost_usd=1.0)


def test_ai_web_memory_read_injects_only_verified_or_promoted_memories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    memory_db = tmp_path / "memory.db"
    store = MemoryStore(memory_db)
    try:
        store.add_item(
            MemoryItem.new(
                type="lesson",
                status="candidate",
                summary="Candidate hint should not be injected",
                confidence=0.99,
            )
        )
        verified_id = store.add_item(
            MemoryItem.new(
                type="playbook",
                status="verified",
                summary="When /api/admin appears, test JWT tampering with tool evidence.",
                vuln_class="jwt",
                target_fingerprint={"objectives": ["sql_injection"]},
                recommended_actions=["Use test_jwt_tamper only after a JWT is observed."],
                confidence=0.8,
            )
        )
    finally:
        store.close()

    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    model = ScriptedModelClient(
        [{"action": "final", "args": {"summary": "done"}, "rationale": "done"}]
    )
    monkeypatch.setattr(ai_agent, "_deterministic_harness_fallback", lambda **_kwargs: None)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            db_path=tmp_path / "run.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            http_client=VulnerableOpenApiHttpClient(),
            stdout=StringIO(),
            memory=MemoryRunSettings(mode="read", db_path=memory_db, min_confidence=0.0),
            memory_explicit=True,
            max_turns=1,
        ),
    )

    events = [
        json.loads(line)
        for line in (tmp_path / "workspace" / "events.jsonl").read_text().splitlines()
    ]
    finished = next(event["payload"] for event in events if event["kind"] == "agent_finished")
    assert finished["finding_count"] == 0
    assert finished["finding_record_path"] == str(
        tmp_path / "workspace" / "events.jsonl"
    )
    assert finished["audit_path"] == str(tmp_path / "run.db")
    assert finished["flag_objective"] is False
    assert finished["status"] == "incomplete"
    assert finished["termination_reason"] == "max_turns_reached"
    assert "report_path" not in finished

    first_request_text = "\n".join(message.content for message in model.messages_seen[0])
    assert "MEMORY_HINTS" in first_request_text
    assert verified_id in first_request_text
    assert "Candidate hint should not be injected" not in first_request_text


def test_ai_web_memory_write_stores_reflection_candidates_after_confirmed_evidence(
    tmp_path: Path,
) -> None:
    memory_db = tmp_path / "memory.db"
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    model = ScriptedModelClient(
        [
            {"action": "discover_attack_surface", "args": {}, "rationale": "map routes"},
            {
                "action": "test_sqli_param",
                "args": {
                    "path": "/search",
                    "method": "GET",
                    "param": "q",
                    "location": "query",
                },
                "rationale": "probe q",
            },
            {
                "action": "report_sqli",
                "args": {"path": "/search", "param": "q"},
                "rationale": "confirmed",
            },
            {
                "memories": [
                    {
                        "type": "playbook",
                        "summary": (
                            "When /search has q, confirm SQL injection with typed tool evidence."
                        ),
                        "vuln_class": "sql_injection",
                        "target_fingerprint": {
                            "objectives": ["sql_injection"],
                            "route_names": ["/search"],
                            "parameter_names": ["q"],
                        },
                        "preconditions": ["A /search route exposes a q parameter."],
                        "recommended_actions": ["Run test_sqli_param on /search q."],
                        "negative_actions": ["Do not report before confirmed=true."],
                        "evidence_requirements": ["tool_test_sqli_param confirmed=true"],
                        "confidence": 0.8,
                        "retrieval_text": "/search q sql_injection test_sqli_param",
                        "redacted_proof": {
                            "source_confirmed_tool_evidence": True,
                            "flag": "flag{raw_should_be_redacted}",
                        },
                        "replay_command": None,
                        "expires_at": None,
                    }
                ]
            },
        ]
    )

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            db_path=tmp_path / "run.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            http_client=VulnerableOpenApiHttpClient(),
            stdout=StringIO(),
            memory=MemoryRunSettings(mode="write", db_path=memory_db, min_confidence=0.0),
            memory_explicit=True,
            max_turns=3,
        ),
    )

    store = MemoryStore(memory_db)
    try:
        candidates = store.list_items(statuses=("candidate",), limit=10)
        exported = json.dumps(store.export_redacted(), sort_keys=True)
    finally:
        store.close()

    assert len(candidates) == 1
    assert candidates[0].type == "playbook"
    assert "raw_should_be_redacted" not in exported
    assert "flag{REDACTED}" in exported


def test_retrieved_memory_cannot_bypass_evidence_gate(tmp_path: Path) -> None:
    memory_db = tmp_path / "memory.db"
    store = MemoryStore(memory_db)
    try:
        memory_id = store.add_item(
            MemoryItem.new(
                type="playbook",
                status="promoted",
                summary="Advisory memory says /search q may be injectable.",
                vuln_class="sql_injection",
                target_fingerprint={"objectives": ["sql_injection"]},
                recommended_actions=["Use report_sqli only after test_sqli_param confirms."],
                confidence=0.9,
                redacted_proof={
                    "source_confirmed_tool_evidence": True,
                    "replay_passed": True,
                },
            )
        )
    finally:
        store.close()

    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    db_path = tmp_path / "run.db"
    model = ScriptedModelClient(
        [
            {
                "action": "report_sqli",
                "args": {"path": "/search", "param": "q"},
                "rationale": "try from memory",
            },
        ]
    )

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            db_path=db_path,
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            http_client=VulnerableOpenApiHttpClient(),
            stdout=StringIO(),
            memory=MemoryRunSettings(mode="read", db_path=memory_db, min_confidence=0.0),
            memory_explicit=True,
            max_turns=1,
        ),
    )

    conn = sqlite3.connect(db_path)
    try:
        finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    finally:
        conn.close()
    store = MemoryStore(memory_db)
    try:
        memory = store.get_item(memory_id)
    finally:
        store.close()

    assert finding_count == 0
    assert memory is not None
    assert memory.failure_count == 1


def test_ai_web_memory_records_model_provenance(tmp_path: Path) -> None:
    memory_db = tmp_path / "memory.db"
    store = MemoryStore(memory_db)
    try:
        injected_id = store.add_item(
            MemoryItem.new(
                type="lesson",
                status="verified",
                summary="Use confirmed tool evidence before reporting.",
                target_fingerprint={"objectives": ["sql_injection"]},
                confidence=0.8,
            )
        )
    finally:
        store.close()

    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    model = ScriptedModelClient(
        [
            {"action": "discover_attack_surface", "args": {}, "rationale": "map routes"},
            {
                "action": "test_sqli_param",
                "args": {
                    "path": "/search",
                    "method": "GET",
                    "param": "q",
                    "location": "query",
                },
                "rationale": "probe q",
            },
            {
                "action": "report_sqli",
                "args": {"path": "/search", "param": "q"},
                "rationale": "confirmed",
            },
            {
                "memories": [
                    {
                        "type": "playbook",
                        "summary": "When /search has q, run test_sqli_param before report_sqli.",
                        "vuln_class": "sql_injection",
                        "target_fingerprint": {
                            "objectives": ["sql_injection"],
                            "route_names": ["/search"],
                            "parameter_names": ["q"],
                        },
                        "preconditions": ["A /search route exposes q."],
                        "recommended_actions": ["Run test_sqli_param on /search q."],
                        "negative_actions": ["Do not report before confirmed=true."],
                        "evidence_requirements": ["tool_test_sqli_param confirmed=true"],
                        "confidence": 0.8,
                        "retrieval_text": "/search q sql_injection",
                        "redacted_proof": {"source_confirmed_tool_evidence": True},
                        "replay_command": None,
                        "expires_at": None,
                    }
                ]
            },
        ]
    )

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            db_path=tmp_path / "run.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            http_client=VulnerableOpenApiHttpClient(),
            stdout=StringIO(),
            memory=MemoryRunSettings(mode="learn", db_path=memory_db, min_confidence=0.0),
            memory_explicit=True,
            max_turns=3,
        ),
    )

    conn = sqlite3.connect(memory_db)
    try:
        produced = conn.execute(
            """
            SELECT producer_profile, producer_tier, producer_provider, producer_model
            FROM memory_items
            WHERE type = 'playbook'
            """
        ).fetchone()
        source = conn.execute(
            """
            SELECT producer_profile, producer_tier, producer_provider, producer_model
            FROM memory_sources
            WHERE source_type = 'audit_db'
            """
        ).fetchone()
        usage = conn.execute(
            """
            SELECT consumer_profile, consumer_tier, consumer_provider, consumer_model
            FROM memory_usage
            WHERE memory_id = ? AND phase = 'retrieval'
            """,
            (injected_id,),
        ).fetchone()
    finally:
        conn.close()

    assert produced == ("local-ollama", "mid", "ollama", "qwen2.5-coder:14b")
    assert source == ("local-ollama", "mid", "ollama", "qwen2.5-coder:14b")
    assert usage == ("local-ollama", "mid", "ollama", "qwen2.5-coder:14b")


def test_agent_finished_reports_max_turns_as_incomplete(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    model = ScriptedModelClient(
        [{"action": "discover_attack_surface", "args": {}, "rationale": "map routes"}]
    )

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            db_path=tmp_path / "run.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            http_client=VulnerableOpenApiHttpClient(),
            stdout=StringIO(),
            max_turns=1,
            report_path=tmp_path / "report.json",
        ),
    )

    events = [
        json.loads(line)
        for line in (tmp_path / "workspace" / "events.jsonl").read_text().splitlines()
    ]
    started = next(event["payload"] for event in events if event["kind"] == "agent_started")
    finished = next(event["payload"] for event in events if event["kind"] == "agent_finished")
    saved = json.loads((tmp_path / "workspace" / "working_state.json").read_text())

    assert started["flag_objective"] is False
    assert finished["status"] == "incomplete"
    assert finished["termination_reason"] == "max_turns_reached"
    assert json.loads((tmp_path / "report.json").read_text())["status"] == "incomplete"
    assert saved["state"]["surface"]["flag_objective"] is False
    assert all(
        task["id"] != "flag-and-secret-sweep" for task in saved["state"]["tasks"]
    )


def test_agent_finished_reports_cost_budget_as_incomplete(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    model = _CostlyScriptedModelClient(
        [{"action": "discover_attack_surface", "args": {}, "rationale": "map routes"}]
    )

    run_ai_web_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=AIWebAgentSettings(
            db_path=tmp_path / "run.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            http_client=VulnerableOpenApiHttpClient(),
            stdout=StringIO(),
            max_turns=2,
            report_path=tmp_path / "report.json",
        ),
    )

    events = [
        json.loads(line)
        for line in (tmp_path / "workspace" / "events.jsonl").read_text().splitlines()
    ]
    finished = next(event["payload"] for event in events if event["kind"] == "agent_finished")

    assert any(event["kind"] == "cost_budget_exhausted" for event in events)
    assert finished["status"] == "incomplete"
    assert finished["termination_reason"] == "cost_budget_exhausted"
    assert json.loads((tmp_path / "report.json").read_text())["status"] == "incomplete"
