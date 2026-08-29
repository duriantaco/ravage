from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

REDACTION_VERSION = "memory-redaction-v2"


class UnsafeMemoryError(ValueError):
    pass


@dataclass(frozen=True)
class RedactionResult:
    value: object
    safe: bool = True
    redaction_version: str = REDACTION_VERSION


@dataclass(frozen=True)
class MemoryItem:
    key: str = ""
    value: object = ""
    confidence: float = 1.0
    source: str = ""
    memory_id: str = ""
    type: str = "lesson"
    status: str = "candidate"
    summary: str = ""
    vuln_class: str | None = None
    target_fingerprint: dict[str, object] | None = None
    preconditions: list[str] | None = None
    recommended_actions: list[str] | None = None
    negative_actions: list[str] | None = None
    evidence_requirements: list[str] | None = None
    retrieval_text: str = ""
    redacted_proof: dict[str, object] | None = None
    replay_command: str | None = None
    expires_at: str | None = None
    created_at: str = ""
    updated_at: str = ""
    success_count: int = 0
    failure_count: int = 0
    ignored_count: int = 0
    producer_profile: str = ""
    producer_tier: str = ""
    producer_provider: str = ""
    producer_model: str = ""

    @classmethod
    def new(
        cls,
        *,
        type: str,  # noqa: A002 - public compatibility API uses `type=`.
        status: str = "candidate",
        summary: str,
        confidence: float = 1.0,
        vuln_class: str | None = None,
        target_fingerprint: dict[str, object] | None = None,
        preconditions: list[str] | None = None,
        recommended_actions: list[str] | None = None,
        negative_actions: list[str] | None = None,
        evidence_requirements: list[str] | None = None,
        retrieval_text: str = "",
        redacted_proof: dict[str, object] | None = None,
        replay_command: str | None = None,
        expires_at: str | None = None,
        producer_profile: str = "",
        producer_tier: str = "",
        producer_provider: str = "",
        producer_model: str = "",
    ) -> MemoryItem:
        now = _now()
        memory_id = f"mem_{uuid.uuid4().hex}"
        return cls(
            key=memory_id,
            value=summary,
            confidence=confidence,
            source="",
            memory_id=memory_id,
            type=type,
            status=status,
            summary=summary,
            vuln_class=vuln_class,
            target_fingerprint=target_fingerprint or {},
            preconditions=preconditions or [],
            recommended_actions=recommended_actions or [],
            negative_actions=negative_actions or [],
            evidence_requirements=evidence_requirements or [],
            retrieval_text=retrieval_text,
            redacted_proof=redacted_proof or {},
            replay_command=replay_command,
            expires_at=expires_at,
            created_at=now,
            updated_at=now,
            producer_profile=producer_profile,
            producer_tier=producer_tier,
            producer_provider=producer_provider,
            producer_model=producer_model,
        )


@dataclass(frozen=True)
class MemoryRunSettings:
    mode: str = "off"
    db_path: Path | None = None
    min_confidence: float = 0.5


@dataclass(frozen=True)
class MemoryGcSettings:
    max_items: int = 1000
    contradiction_threshold: int = 3
    candidate_ttl_days: int = 30
    archived_ttl_days: int = 90
    max_usage_rows: int = 1000
    max_db_size_mb: int = 256
    vacuum: bool = True


@dataclass(frozen=True)
class MemoryGcResult:
    contradicted: int = 0
    archived: int = 0
    purged: int = 0
    usage_rows_compacted: int = 0
    usage_rollups_written: int = 0


@dataclass(frozen=True)
class RetrievedMemory:
    item: MemoryItem
    score: float


def redact_for_memory(value: object) -> RedactionResult:
    return RedactionResult(_redact_value(value))


class MemoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def close(self) -> None:
        self._conn.close()

    def put(self, item: MemoryItem) -> None:
        redacted = redact_for_memory(item.value).value
        self._conn.execute(
            "INSERT OR REPLACE INTO memories(key, value, confidence, source) VALUES (?, ?, ?, ?)",
            (item.key, str(redacted), item.confidence, item.source),
        )
        self._conn.commit()

    def list(self, *, min_confidence: float = 0.0) -> list[MemoryItem]:
        rows = self._conn.execute(
            "SELECT key, value, confidence, source FROM memories WHERE confidence >= ? ORDER BY key",
            (min_confidence,),
        ).fetchall()
        return [
            MemoryItem(
                key=str(row["key"]),
                value=str(row["value"]),
                confidence=float(row["confidence"]),
                source=str(row["source"]),
            )
            for row in rows
        ]

    def add_item(self, item: MemoryItem) -> str:
        redacted = _redacted_item(item)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO memory_items (
                memory_id, type, status, summary, vuln_class, target_fingerprint,
                preconditions, recommended_actions, negative_actions, evidence_requirements,
                confidence, retrieval_text, redacted_proof, replay_command, expires_at,
                created_at, updated_at, success_count, failure_count, ignored_count,
                producer_profile, producer_tier, producer_provider, producer_model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            _item_row_values(redacted),
        )
        self._conn.commit()
        return redacted.memory_id

    def get_item(self, memory_id: str) -> MemoryItem | None:
        row = self._conn.execute(
            "SELECT * FROM memory_items WHERE memory_id = ?",
            (memory_id,),
        ).fetchone()
        if row is None:
            return None
        return _item_from_row(row)

    def list_items(
        self,
        *,
        statuses: tuple[str, ...] | None = None,
        limit: int = 50,
    ) -> list[MemoryItem]:
        params: list[object] = []
        where = ""
        if statuses:
            placeholders = ", ".join("?" for _status in statuses)
            where = f"WHERE status IN ({placeholders})"
            params.extend(statuses)
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM memory_items {where} ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [_item_from_row(row) for row in rows]

    def retrieve_hints(
        self,
        *,
        target_fingerprint: dict[str, object],
        min_confidence: float = 0.5,
        limit: int = 10,
    ) -> tuple[RetrievedMemory, ...]:
        rows = self._conn.execute(
            """
            SELECT * FROM memory_items
            WHERE confidence >= ?
              AND status IN ('verified', 'promoted')
            """,
            (min_confidence,),
        ).fetchall()
        scored: list[RetrievedMemory] = []
        for row in rows:
            item = _item_from_row(row)
            score = _fingerprint_score(item.target_fingerprint or {}, target_fingerprint)
            scored.append(RetrievedMemory(item=item, score=score + item.confidence / 100.0))
        scored.sort(key=lambda result: (-result.score, result.item.memory_id))
        return tuple(scored[:limit])

    def promote(self, memory_id: str, *, reason: str, replay_passed: bool = False) -> None:
        item = self.get_item(memory_id)
        if item is None:
            raise ValueError("memory not found")
        proof = item.redacted_proof or {}
        if proof.get("source_confirmed_tool_evidence") is not True:
            raise ValueError("promotion requires confirmed tool evidence")
        if not replay_passed and proof.get("replay_passed") is not True:
            raise ValueError("promotion requires replay evidence")
        self._conn.execute(
            "UPDATE memory_items SET status = 'promoted', updated_at = ? WHERE memory_id = ?",
            (_now(), memory_id),
        )
        self._conn.execute(
            "INSERT INTO memory_promotions(memory_id, reason, created_at) VALUES (?, ?, ?)",
            (memory_id, reason, _now()),
        )
        self._conn.commit()

    def add_source(
        self,
        *,
        memory_id: str,
        source_type: str,
        source_ref: str,
        source_run_id: str,
        producer_profile: str = "",
        producer_tier: str = "",
        producer_provider: str = "",
        producer_model: str = "",
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO memory_sources (
                memory_id, source_type, source_ref, source_run_id,
                producer_profile, producer_tier, producer_provider, producer_model, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                memory_id,
                source_type,
                source_ref,
                source_run_id,
                producer_profile,
                producer_tier,
                producer_provider,
                producer_model,
                _now(),
            ),
        )
        self._conn.commit()

    def record_usage(
        self,
        *,
        memory_id: str,
        run_id: str,
        phase: str,
        status: str,
        evidence: dict[str, object] | None = None,
        consumer_profile: str = "",
        consumer_tier: str = "",
        consumer_provider: str = "",
        consumer_model: str = "",
    ) -> None:
        redacted_evidence = redact_for_memory(evidence or {}).value
        self._conn.execute(
            """
            INSERT INTO memory_usage (
                memory_id, run_id, phase, status, evidence,
                consumer_profile, consumer_tier, consumer_provider, consumer_model, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                memory_id,
                run_id,
                phase,
                status,
                json.dumps(redacted_evidence, sort_keys=True),
                consumer_profile,
                consumer_tier,
                consumer_provider,
                consumer_model,
                _now(),
            ),
        )
        self._conn.execute(
            "UPDATE memory_items SET last_used_at = ? WHERE memory_id = ?",
            (_now(), memory_id),
        )
        self._conn.commit()

    def record_usage_feedback(
        self,
        *,
        memory_ids: list[str],
        run_id: str,
        accepted: bool,
    ) -> None:
        for memory_id in memory_ids:
            if accepted:
                self._conn.execute(
                    "UPDATE memory_items SET success_count = success_count + 1 WHERE memory_id = ?",
                    (memory_id,),
                )
                status = "accepted"
            else:
                self._conn.execute(
                    """
                    UPDATE memory_items
                    SET failure_count = failure_count + 1,
                        ignored_count = ignored_count + 1
                    WHERE memory_id = ?
                    """,
                    (memory_id,),
                )
                status = "ignored"
            self.record_usage(memory_id=memory_id, run_id=run_id, phase="feedback", status=status)
        self._conn.commit()

    def gc(self, settings: MemoryGcSettings) -> MemoryGcResult:
        contradicted = self._mark_contradicted(settings.contradiction_threshold)
        archived = self._archive_old_candidates(settings.candidate_ttl_days)
        purged = self._purge_archived(settings.archived_ttl_days)
        purged += self._purge_for_size_cap(settings.max_db_size_mb)
        compacted, rollups = self._compact_usage(settings.max_usage_rows)
        if settings.vacuum:
            self._conn.execute("VACUUM")
        self._conn.commit()
        return MemoryGcResult(
            contradicted=contradicted,
            archived=archived,
            purged=purged,
            usage_rows_compacted=compacted,
            usage_rollups_written=rollups,
        )

    def export_redacted(self) -> dict[str, object]:
        items = [self._export_item(row) for row in self._conn.execute("SELECT * FROM memory_items").fetchall()]
        sources = [
            dict(row)
            for row in self._conn.execute("SELECT * FROM memory_sources ORDER BY id").fetchall()
        ]
        usage = [
            dict(row)
            for row in self._conn.execute("SELECT * FROM memory_usage ORDER BY id").fetchall()
        ]
        return redact_for_memory({"items": items, "sources": sources, "usage": usage}).value  # type: ignore[return-value]

    def _migrate(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS memories (key TEXT PRIMARY KEY, value TEXT, confidence REAL, source TEXT)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_items (
                memory_id TEXT PRIMARY KEY,
                type TEXT,
                status TEXT,
                summary TEXT,
                vuln_class TEXT,
                target_fingerprint TEXT,
                preconditions TEXT,
                recommended_actions TEXT,
                negative_actions TEXT,
                evidence_requirements TEXT,
                confidence REAL,
                retrieval_text TEXT,
                redacted_proof TEXT,
                replay_command TEXT,
                expires_at TEXT,
                created_at TEXT,
                updated_at TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                ignored_count INTEGER DEFAULT 0,
                last_used_at TEXT,
                producer_profile TEXT,
                producer_tier TEXT,
                producer_provider TEXT,
                producer_model TEXT
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                memory_id TEXT,
                source_type TEXT,
                source_ref TEXT,
                source_run_id TEXT,
                producer_profile TEXT,
                producer_tier TEXT,
                producer_provider TEXT,
                producer_model TEXT,
                created_at TEXT
            )
            """
        )
        self._conn.execute("CREATE TABLE IF NOT EXISTS memory_embeddings (memory_id TEXT PRIMARY KEY, embedding TEXT)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS memory_promotions (id INTEGER PRIMARY KEY AUTOINCREMENT, memory_id TEXT, reason TEXT, created_at TEXT)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                memory_id TEXT,
                run_id TEXT,
                phase TEXT,
                status TEXT,
                evidence TEXT,
                consumer_profile TEXT,
                consumer_tier TEXT,
                consumer_provider TEXT,
                consumer_model TEXT,
                created_at TEXT
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_usage_rollups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                memory_id TEXT,
                count INTEGER,
                consumer_profile TEXT,
                consumer_tier TEXT,
                consumer_provider TEXT,
                consumer_model TEXT,
                created_at TEXT
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_tombstones (
                memory_id TEXT PRIMARY KEY,
                original_status TEXT,
                reason TEXT,
                created_at TEXT
            )
            """
        )
        self._conn.execute("CREATE TABLE IF NOT EXISTS memory_items_fts (memory_id TEXT PRIMARY KEY, text TEXT)")
        self._conn.commit()

    def _mark_contradicted(self, threshold: int) -> int:
        if threshold <= 0:
            return 0
        cursor = self._conn.execute(
            """
            UPDATE memory_items
            SET status = 'contradicted', updated_at = ?
            WHERE status IN ('verified', 'promoted')
              AND failure_count >= ?
            """,
            (_now(), threshold),
        )
        return cursor.rowcount

    def _archive_old_candidates(self, ttl_days: int) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=ttl_days)
        rows = self._conn.execute(
            "SELECT memory_id FROM memory_items WHERE status = 'candidate' AND created_at < ?",
            (cutoff.isoformat(),),
        ).fetchall()
        for row in rows:
            self._conn.execute(
                "UPDATE memory_items SET status = 'archived', updated_at = ? WHERE memory_id = ?",
                (_now(), row["memory_id"]),
            )
        return len(rows)

    def _purge_archived(self, ttl_days: int) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=ttl_days)
        rows = self._conn.execute(
            "SELECT memory_id, status FROM memory_items WHERE status = 'archived' AND updated_at <= ?",
            (cutoff.isoformat(),),
        ).fetchall()
        for row in rows:
            self._tombstone_and_delete(str(row["memory_id"]), original_status="archived", reason="ttl")
        return len(rows)

    def _purge_for_size_cap(self, max_db_size_mb: int) -> int:
        if max_db_size_mb > 0:
            return 0
        rows = self._conn.execute(
            "SELECT memory_id, status FROM memory_items WHERE status != 'promoted'"
        ).fetchall()
        for row in rows:
            self._tombstone_and_delete(str(row["memory_id"]), original_status=str(row["status"]), reason="size_cap")
        return len(rows)

    def _compact_usage(self, max_usage_rows: int) -> tuple[int, int]:
        rows = self._conn.execute("SELECT id, memory_id FROM memory_usage ORDER BY id").fetchall()
        if len(rows) <= max_usage_rows:
            return 0, 0
        compact_rows = rows[: len(rows) - max_usage_rows]
        compact_ids = [int(row["id"]) for row in compact_rows]
        first = self._conn.execute(
            """
            SELECT memory_id, consumer_profile, consumer_tier, consumer_provider, consumer_model
            FROM memory_usage
            WHERE id = ?
            """,
            (compact_ids[0],),
        ).fetchone()
        self._conn.execute(
            """
            INSERT INTO memory_usage_rollups (
                memory_id, count, consumer_profile, consumer_tier,
                consumer_provider, consumer_model, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                first["memory_id"],
                len(compact_ids),
                first["consumer_profile"],
                first["consumer_tier"],
                first["consumer_provider"],
                first["consumer_model"],
                _now(),
            ),
        )
        placeholders = ", ".join("?" for _item in compact_ids)
        self._conn.execute(f"DELETE FROM memory_usage WHERE id IN ({placeholders})", compact_ids)
        return len(compact_ids), 1

    def _tombstone_and_delete(self, memory_id: str, *, original_status: str, reason: str) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO memory_tombstones(memory_id, original_status, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (memory_id, original_status, reason, _now()),
        )
        self._conn.execute("DELETE FROM memory_items WHERE memory_id = ?", (memory_id,))

    def _export_item(self, row: sqlite3.Row) -> dict[str, object]:
        item = _item_from_row(row)
        return {
            "memory_id": item.memory_id,
            "type": item.type,
            "status": item.status,
            "summary": item.summary,
            "vuln_class": item.vuln_class,
            "target_fingerprint": item.target_fingerprint or {},
            "recommended_actions": item.recommended_actions or [],
            "redacted_proof": item.redacted_proof or {},
            "producer_profile": item.producer_profile,
            "producer_tier": item.producer_tier,
            "producer_provider": item.producer_provider,
            "producer_model": item.producer_model,
        }


def _item_row_values(item: MemoryItem) -> tuple[object, ...]:
    return (
        item.memory_id,
        item.type,
        item.status,
        item.summary,
        item.vuln_class,
        _json(item.target_fingerprint or {}),
        _json(item.preconditions or []),
        _json(item.recommended_actions or []),
        _json(item.negative_actions or []),
        _json(item.evidence_requirements or []),
        item.confidence,
        item.retrieval_text,
        _json(item.redacted_proof or {}),
        item.replay_command,
        item.expires_at,
        item.created_at or _now(),
        item.updated_at or _now(),
        item.success_count,
        item.failure_count,
        item.ignored_count,
        item.producer_profile,
        item.producer_tier,
        item.producer_provider,
        item.producer_model,
    )


def _item_from_row(row: sqlite3.Row) -> MemoryItem:
    memory_id = str(row["memory_id"])
    summary = str(row["summary"] or "")
    return MemoryItem(
        key=memory_id,
        value=summary,
        confidence=float(row["confidence"] or 0.0),
        source="",
        memory_id=memory_id,
        type=str(row["type"] or "lesson"),
        status=str(row["status"] or "candidate"),
        summary=summary,
        vuln_class=row["vuln_class"],
        target_fingerprint=_json_object(row["target_fingerprint"]),
        preconditions=_json_list(row["preconditions"]),
        recommended_actions=_json_list(row["recommended_actions"]),
        negative_actions=_json_list(row["negative_actions"]),
        evidence_requirements=_json_list(row["evidence_requirements"]),
        retrieval_text=str(row["retrieval_text"] or ""),
        redacted_proof=_json_object(row["redacted_proof"]),
        replay_command=row["replay_command"],
        expires_at=row["expires_at"],
        created_at=str(row["created_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
        success_count=int(row["success_count"] or 0),
        failure_count=int(row["failure_count"] or 0),
        ignored_count=int(row["ignored_count"] or 0),
        producer_profile=str(row["producer_profile"] or ""),
        producer_tier=str(row["producer_tier"] or ""),
        producer_provider=str(row["producer_provider"] or ""),
        producer_model=str(row["producer_model"] or ""),
    )


def _redacted_item(item: MemoryItem) -> MemoryItem:
    redacted_summary = str(redact_for_memory(item.summary).value)
    redacted_proof = redact_for_memory(item.redacted_proof or {}).value
    return MemoryItem(
        key=item.memory_id or item.key,
        value=redacted_summary,
        confidence=item.confidence,
        source=item.source,
        memory_id=item.memory_id or item.key or f"mem_{uuid.uuid4().hex}",
        type=item.type,
        status=item.status,
        summary=redacted_summary,
        vuln_class=item.vuln_class,
        target_fingerprint=item.target_fingerprint or {},
        preconditions=item.preconditions or [],
        recommended_actions=[str(redact_for_memory(value).value) for value in item.recommended_actions or []],
        negative_actions=item.negative_actions or [],
        evidence_requirements=item.evidence_requirements or [],
        retrieval_text=str(redact_for_memory(item.retrieval_text).value),
        redacted_proof=redacted_proof if isinstance(redacted_proof, dict) else {},
        replay_command=item.replay_command,
        expires_at=item.expires_at,
        created_at=item.created_at or _now(),
        updated_at=item.updated_at or _now(),
        success_count=item.success_count,
        failure_count=item.failure_count,
        ignored_count=item.ignored_count,
        producer_profile=item.producer_profile,
        producer_tier=item.producer_tier,
        producer_provider=item.producer_provider,
        producer_model=item.producer_model,
    )


def _fingerprint_score(memory: dict[str, object], target: dict[str, object]) -> float:
    score = 0.0
    for key, weight in (("route_names", 10.0), ("parameter_names", 8.0), ("objectives", 2.0)):
        score += weight * len(_string_set(memory.get(key)) & _string_set(target.get(key)))
    return score


def _redact_value(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): _redact_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_value(child) for child in value]
    if isinstance(value, tuple):
        return [_redact_value(child) for child in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(text: str) -> str:
    redacted = re.sub(r"(?i)flag\{[^}]*\}", "flag{REDACTED}", text)
    redacted = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*\b", "<JWT_REDACTED>", redacted)
    redacted = re.sub(r"(?i)(sessionid|session|sid)=([A-Za-z0-9._-]{8,})", r"\1=<SESSION_REDACTED>", redacted)
    redacted = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._-]{12,}", r"\1<HIGH_ENTROPY_REDACTED>", redacted)
    redacted = re.sub(r"(?i)(api[_-]?key=)[A-Za-z0-9._-]{12,}", r"\1<HIGH_ENTROPY_REDACTED>", redacted)
    redacted = re.sub(r"\b[A-Za-z0-9+/]{28,}={0,2}\b", "<HIGH_ENTROPY_REDACTED>", redacted)
    redacted = re.sub(r"\b[a-z]{28,}\b", "<HIGH_ENTROPY_REDACTED>", redacted)
    return redacted


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _json_object(value: object) -> dict[str, object]:
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: object) -> list[str]:
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value}


def _now() -> str:
    return datetime.now(UTC).isoformat()
