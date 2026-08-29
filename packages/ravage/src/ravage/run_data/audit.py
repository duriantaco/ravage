from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from typing import TYPE_CHECKING

from ravage.finding_evidence import confirmed_finding_evidence_failures

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path
    from typing import Any
    from uuid import UUID

    from pentest_schemas import Scope, SqlInjectionFinding, VulnerabilityFinding

GENESIS_HASH = "0" * 64


def _row_hash(  # noqa: PLR0913 - hash input mirrors immutable audit_log fields.
    prev_hash: str,
    *,
    timestamp: object,
    engagement_id: object,
    actor: object,
    action: object,
    payload_json: object,
    cost_usd: object,
) -> str:
    canonical = json.dumps(
        {
            "prev": prev_hash,
            "timestamp": timestamp,
            "engagement_id": engagement_id,
            "actor": actor,
            "action": action,
            "payload": payload_json,
            "cost_usd": cost_usd,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


class AuditStore:
    def __init__(self, db_path: Path, *, scope: Scope | None = None) -> None:
        self.db_path = db_path
        self.scope = scope
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                cost_usd REAL NOT NULL DEFAULT 0,
                prev_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL
            )
            """
        )
        self._ensure_audit_log_hash_columns()
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                vuln_class TEXT NOT NULL,
                status TEXT NOT NULL,
                validator_vote TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def _ensure_audit_log_hash_columns(self) -> None:
        columns = {
            str(row[1])
            for row in self._conn.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        legacy_without_hashes = "prev_hash" not in columns or "row_hash" not in columns
        for name, add_column in (
            ("timestamp", self._add_timestamp_column),
            ("engagement_id", self._add_engagement_id_column),
            ("actor", self._add_actor_column),
            ("action", self._add_action_column),
            ("payload_json", self._add_payload_json_column),
            ("cost_usd", self._add_cost_usd_column),
            ("prev_hash", self._add_prev_hash_column),
            ("row_hash", self._add_row_hash_column),
        ):
            if name not in columns:
                add_column()
        if legacy_without_hashes:
            self._backfill_hash_chain()

    def _add_timestamp_column(self) -> None:
        self._conn.execute(
            "ALTER TABLE audit_log ADD COLUMN timestamp TEXT NOT NULL DEFAULT ''"
        )

    def _add_engagement_id_column(self) -> None:
        self._conn.execute(
            "ALTER TABLE audit_log ADD COLUMN engagement_id TEXT NOT NULL DEFAULT ''"
        )

    def _add_actor_column(self) -> None:
        self._conn.execute("ALTER TABLE audit_log ADD COLUMN actor TEXT NOT NULL DEFAULT ''")

    def _add_action_column(self) -> None:
        self._conn.execute("ALTER TABLE audit_log ADD COLUMN action TEXT NOT NULL DEFAULT ''")

    def _add_payload_json_column(self) -> None:
        self._conn.execute(
            "ALTER TABLE audit_log ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'"
        )

    def _add_cost_usd_column(self) -> None:
        self._conn.execute(
            "ALTER TABLE audit_log ADD COLUMN cost_usd REAL NOT NULL DEFAULT 0"
        )

    def _add_prev_hash_column(self) -> None:
        self._conn.execute(
            "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"
        )

    def _add_row_hash_column(self) -> None:
        self._conn.execute(
            "ALTER TABLE audit_log ADD COLUMN row_hash TEXT NOT NULL DEFAULT ''"
        )

    def _backfill_hash_chain(self) -> None:
        rows = self._conn.execute(
            """
            SELECT
                id,
                timestamp,
                engagement_id,
                actor,
                action,
                payload_json,
                cost_usd,
                prev_hash,
                row_hash
            FROM audit_log
            ORDER BY id ASC
            """
        ).fetchall()
        prev = GENESIS_HASH
        updates: list[tuple[str, str, int]] = []
        for row in rows:
            (
                row_id,
                timestamp,
                engagement_id,
                actor,
                action,
                payload_json,
                cost_usd,
                stored_prev,
                stored_hash,
            ) = row
            if stored_prev and stored_hash:
                prev = str(stored_hash)
                continue
            computed_hash = _row_hash(
                prev,
                timestamp=timestamp,
                engagement_id=engagement_id,
                actor=actor,
                action=action,
                payload_json=payload_json,
                cost_usd=cost_usd,
            )
            updates.append((prev, computed_hash, int(row_id)))
            prev = computed_hash
        if updates:
            self._conn.executemany(
                "UPDATE audit_log SET prev_hash = ?, row_hash = ? WHERE id = ?",
                updates,
            )

    def close(self) -> None:
        self._conn.close()

    def record(
        self,
        *,
        engagement_id: UUID,
        actor: str,
        action: str,
        payload: Mapping[str, Any],
        cost_usd: float = 0.0,
    ) -> None:
        if action == "finding_confirmed":
            self._assert_confirmed_finding_payload(payload, status="confirmed")
        timestamp = datetime.now(UTC).isoformat()
        payload_json = json.dumps(payload, sort_keys=True)
        prev_hash = self.head_hash() or GENESIS_HASH
        row_hash = _row_hash(
            prev_hash,
            timestamp=timestamp,
            engagement_id=str(engagement_id),
            actor=actor,
            action=action,
            payload_json=payload_json,
            cost_usd=cost_usd,
        )
        self._conn.execute(
            """
            INSERT INTO audit_log (
                timestamp,
                engagement_id,
                actor,
                action,
                payload_json,
                cost_usd,
                prev_hash,
                row_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                str(engagement_id),
                actor,
                action,
                payload_json,
                cost_usd,
                prev_hash,
                row_hash,
            ),
        )
        self._conn.commit()

    def count_rows(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        if row is None:
            return 0
        return int(row[0])

    def count_findings(
        self,
        *,
        status: str | None = None,
        engagement_id: UUID | str | None = None,
    ) -> int:
        conditions: list[str] = []
        parameters: list[str] = []
        if status is not None:
            conditions.append("status = ?")
            parameters.append(status)
        if engagement_id is not None:
            conditions.append("engagement_id = ?")
            parameters.append(str(engagement_id))
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        row = self._conn.execute(
            f"SELECT COUNT(*) FROM findings{where}",  # noqa: S608 - fixed clauses only.
            tuple(parameters),
        ).fetchone()
        return int(row[0]) if row is not None else 0

    def has_finding(
        self,
        finding_id: str,
        *,
        engagement_id: UUID | str | None = None,
    ) -> bool:
        if engagement_id is None:
            row = self._conn.execute(
                "SELECT 1 FROM findings WHERE finding_id = ? LIMIT 1",
                (finding_id,),
            ).fetchone()
        else:
            row = self._conn.execute(
                """
                SELECT 1
                FROM findings
                WHERE finding_id = ? AND engagement_id = ?
                LIMIT 1
                """,
                (finding_id, str(engagement_id)),
            ).fetchone()
        return row is not None

    def has_finding_action(
        self,
        action: str,
        *,
        engagement_id: UUID | str,
        finding_id: str,
    ) -> bool:
        """Return whether one audit action already exists for an engagement finding."""
        return self.has_action_payload_value(
            action,
            engagement_id=engagement_id,
            key="finding_id",
            value=finding_id,
        )

    def has_action_payload_value(
        self,
        action: str,
        *,
        engagement_id: UUID | str,
        key: str,
        value: str,
    ) -> bool:
        """Return whether an audit action has an exact top-level payload value."""
        rows = self._conn.execute(
            """
            SELECT payload_json
            FROM audit_log
            WHERE engagement_id = ? AND action = ?
            ORDER BY id ASC
            """,
            (str(engagement_id), action),
        )
        for (payload_json,) in rows:
            try:
                payload = json.loads(str(payload_json))
            except (TypeError, ValueError):
                continue
            if isinstance(payload, dict) and str(payload.get(key) or "") == value:
                return True
        return False

    def head_hash(self) -> str | None:
        row = self._conn.execute(
            "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return str(row[0])

    def verify(self) -> tuple[bool, int | None]:
        prev = GENESIS_HASH
        rows = self._conn.execute(
            """
            SELECT
                id,
                timestamp,
                engagement_id,
                actor,
                action,
                payload_json,
                cost_usd,
                prev_hash,
                row_hash
            FROM audit_log
            ORDER BY id ASC
            """
        )
        for row in rows:
            (
                row_id,
                timestamp,
                engagement_id,
                actor,
                action,
                payload_json,
                cost_usd,
                stored_prev,
                stored_hash,
            ) = row
            if stored_prev != prev:
                return (False, int(row_id))
            computed_hash = _row_hash(
                prev,
                timestamp=timestamp,
                engagement_id=engagement_id,
                actor=actor,
                action=action,
                payload_json=payload_json,
                cost_usd=cost_usd,
            )
            if computed_hash != stored_hash:
                return (False, int(row_id))
            prev = str(stored_hash)
        return (True, None)

    def record_finding(self, finding: SqlInjectionFinding | VulnerabilityFinding) -> None:
        payload = json.loads(finding.model_dump_json())
        self._assert_confirmed_finding_payload(payload, status=finding.status)
        self.record_finding_payload(
            finding_id=str(finding.finding_id),
            engagement_id=finding.engagement_id,
            vuln_class=finding.vuln_class,
            status=finding.status,
            validator_vote=finding.validator_vote,
            payload=payload,
        )

    def record_finding_payload(  # noqa: PLR0913 - mirrors the findings table columns.
        self,
        *,
        finding_id: str,
        engagement_id: UUID,
        vuln_class: str,
        status: str,
        validator_vote: str | None,
        payload: Mapping[str, Any],
    ) -> None:
        stored_payload: dict[str, Any] = dict(payload)
        stored_payload["finding_id"] = finding_id
        stored_payload["engagement_id"] = str(engagement_id)
        stored_payload["vuln_class"] = vuln_class
        stored_payload["status"] = status
        if validator_vote is not None:
            stored_payload["validator_vote"] = validator_vote
        self._assert_confirmed_finding_payload(stored_payload, status=status)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO findings (
                finding_id,
                engagement_id,
                vuln_class,
                status,
                validator_vote,
                payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                str(engagement_id),
                vuln_class,
                status,
                validator_vote,
                json.dumps(stored_payload, sort_keys=True),
            ),
        )
        self._conn.commit()

    def _assert_confirmed_finding_payload(
        self,
        payload: Mapping[str, Any],
        *,
        status: str,
    ) -> None:
        if status != "confirmed":
            return
        failures = confirmed_finding_evidence_failures(dict(payload), scope=self.scope)
        if failures:
            raise ValueError("confirmed finding lacks required evidence: " + ", ".join(failures))
