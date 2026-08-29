from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from ravage.memory import (
    REDACTION_VERSION,
    MemoryGcSettings,
    MemoryItem,
    MemoryStore,
    UnsafeMemoryError,
    redact_for_memory,
)
from ravage.memory.reflection import (
    ReflectionPrompt,
    build_reflection_prompt,
    parse_reflection_memories,
)

if TYPE_CHECKING:
    from pathlib import Path


COMPACTED_USAGE_ROWS = 3
RETAINED_USAGE_ROWS = 2
PURGED_NOISE_ROWS = 2


def test_memory_schema_migration_creates_core_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "memory.db"
    store = MemoryStore(db_path)
    store.close()

    conn = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        }
    finally:
        conn.close()

    assert {
        "memory_items",
        "memory_sources",
        "memory_embeddings",
        "memory_promotions",
        "memory_usage",
        "memory_usage_rollups",
        "memory_tombstones",
        "memory_items_fts",
    }.issubset(tables)

    conn = sqlite3.connect(db_path)
    try:
        item_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(memory_items)").fetchall()
        }
        source_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(memory_sources)").fetchall()
        }
        usage_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(memory_usage)").fetchall()
        }
    finally:
        conn.close()

    assert {
        "producer_profile",
        "producer_tier",
        "producer_provider",
        "producer_model",
    }.issubset(item_columns)
    assert {
        "producer_profile",
        "producer_tier",
        "producer_provider",
        "producer_model",
    }.issubset(source_columns)
    assert {
        "consumer_profile",
        "consumer_tier",
        "consumer_provider",
        "consumer_model",
    }.issubset(usage_columns)
    assert {"ignored_count", "last_used_at"}.issubset(item_columns)


def test_memory_redaction_removes_sensitive_values() -> None:
    token = "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0."  # noqa: S105
    payload = {
        "flag": "flag{super_secret_flag}",
        "headers": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\nCookie: session=abcdef123456",
        "api": "api_key=sk-abcdefghijklmnopqrstuvwxyz123456",
        "jwt": token,
        "note": f"observed token {token} and sid=abcdef123456",
        "session_url": "/admin?sessionid=abcdef123456",
    }

    result = redact_for_memory(payload)
    rendered = json.dumps(result.value, sort_keys=True)

    assert result.safe
    assert "flag{REDACTED}" in rendered
    assert "super_secret_flag" not in rendered
    assert token not in rendered
    assert "abcdefghijklmnopqrstuvwxyz" not in rendered
    assert "abcdef123456" not in rendered
    assert "<JWT_REDACTED>" in rendered
    assert "<SESSION_REDACTED>" in rendered


def test_memory_redaction_removes_unknown_high_entropy_tokens() -> None:
    unknown_token = "Q2hhaW5lZC1Ub2tlbi05NzhhS1pQbTQ"  # noqa: S105
    lowercase_token = "mzxqplvkrnthydgfsowbcaeujilmprst"  # noqa: S105
    payload = {
        "summary": f"Observed opaque credential {unknown_token}",
        "notes": f"Observed opaque lowercase value {lowercase_token}",
        "retrieval_text": "Opaque credential in response body.",
    }

    result = redact_for_memory(payload)
    rendered = json.dumps(result.value, sort_keys=True)

    assert result.safe
    assert result.redaction_version == REDACTION_VERSION == "memory-redaction-v2"
    assert unknown_token not in rendered
    assert lowercase_token not in rendered
    assert "<HIGH_ENTROPY_REDACTED>" in rendered


def test_memory_redaction_does_not_overredact_prose_or_identifiers() -> None:
    payload = {
        "summary": "Use source_guided_probe_context before test_sqli_param.",
        "retrieval_text": "Ordinary prose and route names should stay useful.",
        "route": "/api/internal/status-page",
        "identifier": "skylos_detection_harness",
    }

    result = redact_for_memory(payload)
    rendered = json.dumps(result.value, sort_keys=True)

    assert result.safe
    assert "<HIGH_ENTROPY_REDACTED>" not in rendered
    assert "source_guided_probe_context" in rendered
    assert "skylos_detection_harness" in rendered


def test_memory_retrieval_ranks_exact_route_and_param_above_generic(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        generic_id = store.add_item(
            MemoryItem.new(
                type="lesson",
                status="verified",
                summary="Generic web testing lesson",
                vuln_class="sql_injection",
                target_fingerprint={"objectives": ["sql_injection"]},
                recommended_actions=["Map routes before testing."],
                confidence=0.95,
            )
        )
        exact_id = store.add_item(
            MemoryItem.new(
                type="playbook",
                status="verified",
                summary="Search q SQL injection playbook",
                vuln_class="sql_injection",
                target_fingerprint={
                    "objectives": ["sql_injection"],
                    "route_names": ["/search"],
                    "parameter_names": ["q"],
                },
                recommended_actions=["Use test_sqli_param on /search q."],
                confidence=0.65,
            )
        )

        retrieved = store.retrieve_hints(
            target_fingerprint={
                "objectives": ["sql_injection"],
                "route_names": ["/search"],
                "parameter_names": ["q"],
            },
            min_confidence=0.0,
        )
    finally:
        store.close()

    assert [item.item.memory_id for item in retrieved[:2]] == [exact_id, generic_id]


def test_reflection_parser_rejects_invalid_json_and_unsafe_memories() -> None:
    with pytest.raises(ValueError, match="invalid memory reflection JSON"):
        parse_reflection_memories("not json", source_run_id="run-1")

    unsafe = {
        "memories": [
            {
                "type": "lesson",
                "summary": "Do a destructive thing",
                "vuln_class": None,
                "target_fingerprint": {},
                "preconditions": [],
                "recommended_actions": ["run rm -rf / on the target"],
                "negative_actions": [],
                "evidence_requirements": [],
                "confidence": 0.8,
                "retrieval_text": "rm -rf",
                "redacted_proof": {},
                "replay_command": None,
                "expires_at": None,
            }
        ]
    }

    with pytest.raises(UnsafeMemoryError, match="destructive_payload"):
        parse_reflection_memories(json.dumps(unsafe), source_run_id="run-1")


def test_reflection_prompt_keeps_model_output_compact(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.db"
    events_path = tmp_path / "events.jsonl"
    conn = sqlite3.connect(audit_path)
    try:
        conn.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT,
                action TEXT,
                payload_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE findings (
                vuln_class TEXT,
                status TEXT,
                validator_vote TEXT,
                payload_json TEXT
            )
            """
        )
    finally:
        conn.close()
    events_path.write_text("", encoding="utf-8")

    prompt = build_reflection_prompt(
        audit_path=audit_path,
        workspace_events_path=events_path,
        engagement_id="run-1",
        target_url="http://127.0.0.1:5000",
        objectives=["capture_flag"],
        discovered_routes=[],
        confirmed_vuln_classes=[],
        captured_flags=[],
    )

    assert isinstance(prompt, ReflectionPrompt)
    assert "Return at most 3 memories" in prompt.system
    assert "retrieval_text under 300 characters" in prompt.system


def test_memory_promotion_requires_evidence_and_replay(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        unsupported = store.add_item(
            MemoryItem.new(
                type="playbook",
                status="candidate",
                summary="Unsupported candidate",
                confidence=0.8,
            )
        )
        with pytest.raises(ValueError, match="confirmed tool evidence"):
            store.promote(unsupported, reason="test", replay_passed=True)

        needs_replay = store.add_item(
            MemoryItem.new(
                type="playbook",
                status="candidate",
                summary="Supported candidate",
                confidence=0.8,
                redacted_proof={"source_confirmed_tool_evidence": True},
            )
        )
        with pytest.raises(ValueError, match="replay evidence"):
            store.promote(needs_replay, reason="test")

        store.promote(needs_replay, reason="test", replay_passed=True)
        promoted = store.get_item(needs_replay)
    finally:
        store.close()

    assert promoted is not None
    assert promoted.status == "promoted"


def test_memory_usage_feedback_updates_counters(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        memory_id = store.add_item(
            MemoryItem.new(
                type="lesson",
                status="verified",
                summary="Feedback counter lesson",
                confidence=0.8,
            )
        )
        store.record_usage_feedback(memory_ids=[memory_id], run_id="run-1", accepted=True)
        store.record_usage_feedback(memory_ids=[memory_id], run_id="run-2", accepted=False)
        item = store.get_item(memory_id)
    finally:
        store.close()

    assert item is not None
    assert item.success_count == 1
    assert item.failure_count == 1
    assert item.ignored_count == 1


def test_memory_gc_marks_contradicted_memories_and_excludes_retrieval(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        memory_id = store.add_item(
            MemoryItem.new(
                type="playbook",
                status="promoted",
                summary="Use /admin for the target.",
                target_fingerprint={"route_names": ["/admin"]},
                confidence=0.9,
                redacted_proof={
                    "source_confirmed_tool_evidence": True,
                    "replay_passed": True,
                },
            )
        )
        before = store.retrieve_hints(
            target_fingerprint={"route_names": ["/admin"]},
            min_confidence=0.0,
        )
        store.record_usage_feedback(memory_ids=[memory_id], run_id="run-1", accepted=False)
        store.record_usage_feedback(memory_ids=[memory_id], run_id="run-2", accepted=False)

        result = store.gc(MemoryGcSettings(contradiction_threshold=2, vacuum=False))
        after = store.retrieve_hints(
            target_fingerprint={"route_names": ["/admin"]},
            min_confidence=0.0,
        )
        memory = store.get_item(memory_id)
    finally:
        store.close()

    assert [item.item.memory_id for item in before] == [memory_id]
    assert result.contradicted == 1
    assert memory is not None
    assert memory.status == "contradicted"
    assert after == ()


def test_memory_gc_archives_old_candidates_then_purges_tombstones(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    old = (datetime.now(UTC) - timedelta(days=45)).isoformat()
    try:
        item = replace(
            MemoryItem.new(
                type="lesson",
                status="candidate",
                summary="Old unreviewed candidate",
                confidence=0.8,
            ),
            created_at=old,
        )
        memory_id = store.add_item(item)

        result = store.gc(
            MemoryGcSettings(
                candidate_ttl_days=30,
                archived_ttl_days=0,
                max_db_size_mb=256,
                vacuum=False,
            )
        )
        remaining = store.get_item(memory_id)
        tombstone = store._conn.execute(  # noqa: SLF001 - test inspects store-owned DB.
            "SELECT original_status, reason FROM memory_tombstones WHERE memory_id = ?",
            (memory_id,),
        ).fetchone()
    finally:
        store.close()

    assert result.archived == 1
    assert result.purged == 1
    assert remaining is None
    assert tuple(tombstone) == ("archived", "ttl")


def test_memory_gc_compacts_usage_rows_into_rollups(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        memory_id = store.add_item(
            MemoryItem.new(
                type="lesson",
                status="verified",
                summary="Compact usage rows",
                confidence=0.8,
            )
        )
        for index in range(5):
            store.record_usage(
                memory_id=memory_id,
                run_id=f"run-{index}",
                phase="retrieval",
                status="injected",
                consumer_profile="hosted-openai",
                consumer_tier="high",
                consumer_provider="openai",
                consumer_model="gpt-5.4",
            )

        result = store.gc(MemoryGcSettings(max_usage_rows=2, vacuum=False))
        remaining_usage = store._conn.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM memory_usage"
        ).fetchone()[0]
        rollup = store._conn.execute(  # noqa: SLF001
            """
            SELECT count, consumer_profile, consumer_model
            FROM memory_usage_rollups
            WHERE memory_id = ?
            """,
            (memory_id,),
        ).fetchone()
    finally:
        store.close()

    assert result.usage_rows_compacted == COMPACTED_USAGE_ROWS
    assert result.usage_rollups_written == 1
    assert remaining_usage == RETAINED_USAGE_ROWS
    assert tuple(rollup) == (COMPACTED_USAGE_ROWS, "hosted-openai", "gpt-5.4")


def test_memory_gc_size_cap_purges_nonpromoted_but_keeps_promoted(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        promoted_id = store.add_item(
            MemoryItem.new(
                type="playbook",
                status="promoted",
                summary="Replay-backed memory stays.",
                confidence=0.9,
                redacted_proof={
                    "source_confirmed_tool_evidence": True,
                    "replay_passed": True,
                },
            )
        )
        rejected_id = store.add_item(
            MemoryItem.new(
                type="lesson",
                status="rejected",
                summary="Rejected noise can be compacted.",
                confidence=0.2,
            )
        )
        candidate_id = store.add_item(
            MemoryItem.new(
                type="lesson",
                status="candidate",
                summary="Candidate noise can be compacted.",
                confidence=0.2,
            )
        )

        result = store.gc(MemoryGcSettings(max_db_size_mb=0, vacuum=False))
        promoted = store.get_item(promoted_id)
        rejected = store.get_item(rejected_id)
        candidate = store.get_item(candidate_id)
        tombstones = store._conn.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM memory_tombstones"
        ).fetchone()[0]
    finally:
        store.close()

    assert result.purged == PURGED_NOISE_ROWS
    assert promoted is not None
    assert promoted.status == "promoted"
    assert rejected is None
    assert candidate is None
    assert tombstones == PURGED_NOISE_ROWS


def test_memory_model_provenance_is_exported_redacted(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        memory_id = store.add_item(
            MemoryItem.new(
                type="lesson",
                status="verified",
                summary="Provenance lesson",
                confidence=0.8,
                producer_profile="hosted-openai",
                producer_tier="high",
                producer_provider="openai",
                producer_model="gpt-5.4",
            )
        )
        store.add_source(
            memory_id=memory_id,
            source_type="audit_db",
            source_ref="runs/provenance.db",
            source_run_id="run-1",
            producer_profile="hosted-openai",
            producer_tier="high",
            producer_provider="openai",
            producer_model="gpt-5.4",
        )
        store.record_usage(
            memory_id=memory_id,
            run_id="run-2",
            phase="retrieval",
            status="injected",
            evidence={"route": "/api/admin", "flag": "flag{raw_secret}"},
            consumer_profile="local-ollama",
            consumer_tier="mid",
            consumer_provider="ollama",
            consumer_model="qwen2.5-coder:14b",
        )
        exported = store.export_redacted()
    finally:
        store.close()

    rendered = json.dumps(exported, sort_keys=True)
    assert "hosted-openai" in rendered
    assert "gpt-5.4" in rendered
    assert "local-ollama" in rendered
    assert "qwen2.5-coder:14b" in rendered
    assert "raw_secret" not in rendered
    assert "flag{REDACTED}" in rendered


def test_memory_export_stays_redacted(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory.db")
    try:
        store.add_item(
            MemoryItem.new(
                type="lesson",
                status="candidate",
                summary="Found flag{raw_secret} with Authorization: Bearer abcdefghijklmnop",
                confidence=0.8,
            )
        )
        exported = store.export_redacted()
    finally:
        store.close()

    rendered = json.dumps(exported, sort_keys=True)
    assert "raw_secret" not in rendered
    assert "abcdefghijklmnop" not in rendered
    assert "flag{REDACTED}" in rendered
