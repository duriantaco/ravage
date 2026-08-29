from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from pentest_schemas import Scope
from ravage import __main__ as cli
from ravage.run_data.audit import GENESIS_HASH, AuditStore

if TYPE_CHECKING:
    from pathlib import Path

ENGAGEMENT_ID = UUID("33333333-3333-4333-8333-333333333333")
EXPECTED_AUDIT_ROWS = 2
HASH_HEX_LENGTH = 64


def _confirmed_finding_payload(url: str) -> dict[str, object]:
    return {
        "finding_id": "finding-1",
        "engagement_id": str(ENGAGEMENT_ID),
        "vuln_class": "idor",
        "status": "confirmed",
        "validator_vote": "confirm",
        "endpoint": {"url": url, "method": "GET", "params": []},
        "exploit_steps": [{"indicator": "paired access-control replay"}],
        "proof": {
            "http_request_final": "GET /account HTTP/1.1",
            "response_final": "HTTP 200; checks passed 1/1",
            "impact_description": "Unauthorized account data was returned.",
        },
    }


def test_audit_store_hash_chains_new_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    with closing(AuditStore(db_path)) as audit:
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="ai_web_agent",
            action="run_started",
            payload={"turn": 0},
        )
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="ai_web_agent",
            action="model_reply_received",
            payload={"turn": 1},
            cost_usd=0.01,
        )

        assert audit.verify() == (True, None)
        assert audit.count_rows() == EXPECTED_AUDIT_ROWS
        assert len(audit.head_hash() or "") == HASH_HEX_LENGTH

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, prev_hash, row_hash FROM audit_log ORDER BY id"
        ).fetchall()

    assert rows[0][1] == GENESIS_HASH
    assert len(rows[0][2]) == HASH_HEX_LENGTH
    assert rows[1][1] == rows[0][2]
    assert len(rows[1][2]) == HASH_HEX_LENGTH


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test.evil.invalid/account",
        "https://example.test/private/account",
    ],
)
def test_audit_rejects_confirmed_finding_outside_exact_scope(
    tmp_path: Path,
    url: str,
) -> None:
    scope = Scope(
        in_scope=["https://example.test/app"],
        out_of_scope=["https://example.test/private"],
    )
    with (
        closing(AuditStore(tmp_path / "audit.db", scope=scope)) as audit,
        pytest.raises(ValueError, match="outside engagement scope"),
    ):
        audit.record_finding_payload(
            finding_id="finding-1",
            engagement_id=ENGAGEMENT_ID,
            vuln_class="idor",
            status="confirmed",
            validator_vote="confirm",
            payload=_confirmed_finding_payload(url),
        )


@pytest.mark.parametrize("endpoint", [None, {}, {"url": ""}])
def test_audit_rejects_confirmed_web_finding_without_scoped_endpoint(
    tmp_path: Path,
    endpoint: object,
) -> None:
    scope = Scope(in_scope=["https://example.test/app"], out_of_scope=[])
    payload = _confirmed_finding_payload("https://example.test/app/account")
    if endpoint is None:
        payload.pop("endpoint")
    else:
        payload["endpoint"] = endpoint

    with (
        closing(AuditStore(tmp_path / "audit.db", scope=scope)) as audit,
        pytest.raises(ValueError, match=r"endpoint\.url is outside engagement scope"),
    ):
        audit.record_finding_payload(
            finding_id="finding-1",
            engagement_id=ENGAGEMENT_ID,
            vuln_class="idor",
            status="confirmed",
            validator_vote="confirm",
            payload=payload,
        )


def test_audit_finding_queries_can_be_scoped_to_one_engagement(tmp_path: Path) -> None:
    expected_total_findings = 2
    other_engagement_id = UUID("44444444-4444-4444-8444-444444444444")
    with closing(AuditStore(tmp_path / "audit.db")) as audit:
        for finding_id, engagement_id in (
            ("finding-current", ENGAGEMENT_ID),
            ("finding-other", other_engagement_id),
        ):
            audit.record_finding_payload(
                finding_id=finding_id,
                engagement_id=engagement_id,
                vuln_class="idor",
                status="confirmed",
                validator_vote="confirm",
                payload=_confirmed_finding_payload(
                    "https://example.test/app/account"
                ),
            )

        assert audit.count_findings(status="confirmed") == expected_total_findings
        assert (
            audit.count_findings(
                status="confirmed",
                engagement_id=ENGAGEMENT_ID,
            )
            == 1
        )
        assert audit.has_finding("finding-current", engagement_id=ENGAGEMENT_ID)
        assert not audit.has_finding(
            "finding-current",
            engagement_id=other_engagement_id,
        )


def test_audit_finding_action_query_matches_engagement_action_and_finding(
    tmp_path: Path,
) -> None:
    other_engagement_id = UUID("44444444-4444-4444-8444-444444444444")
    with closing(AuditStore(tmp_path / "audit.db")) as audit:
        confirmed_payload = _confirmed_finding_payload(
            "https://example.test/app/account"
        )
        confirmed_payload["finding_id"] = "finding-current"
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="agent",
            action="finding_confirmed",
            payload=confirmed_payload,
        )
        audit.record(
            engagement_id=other_engagement_id,
            actor="agent",
            action="finding_rejected_no_evidence",
            payload={"finding_id": "finding-current"},
        )

        assert audit.has_finding_action(
            "finding_confirmed",
            engagement_id=ENGAGEMENT_ID,
            finding_id="finding-current",
        )
        assert audit.has_finding_action(
            "finding_rejected_no_evidence",
            engagement_id=other_engagement_id,
            finding_id="finding-current",
        )
        assert not audit.has_finding_action(
            "finding_rejected_no_evidence",
            engagement_id=ENGAGEMENT_ID,
            finding_id="finding-current",
        )
        assert not audit.has_finding_action(
            "finding_confirmed",
            engagement_id=other_engagement_id,
            finding_id="finding-current",
        )
        assert not audit.has_finding_action(
            "finding_confirmed",
            engagement_id=ENGAGEMENT_ID,
            finding_id="finding-other",
        )


def test_audit_verify_flags_first_tampered_row(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    with closing(AuditStore(db_path)) as audit:
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="ai_web_agent",
            action="run_started",
            payload={"turn": 0},
        )
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="ai_web_agent",
            action="tool_http_get",
            payload={"status": 200},
        )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE audit_log SET payload_json = ? WHERE id = 2",
            (json.dumps({"status": 500}, sort_keys=True),),
        )

    with closing(AuditStore(db_path)) as audit:
        assert audit.verify() == (False, 2)


def test_audit_verify_flags_blank_hash_on_hashed_db(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    with closing(AuditStore(db_path)) as audit:
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="ai_web_agent",
            action="run_started",
            payload={"turn": 0},
        )

    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE audit_log SET row_hash = '' WHERE id = 1")

    with closing(AuditStore(db_path)) as audit:
        assert audit.verify() == (False, 1)


def test_audit_store_backfills_legacy_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy-audit.db"
    _create_legacy_audit_db(db_path)

    with closing(AuditStore(db_path)) as audit:
        assert audit.verify() == (True, None)
        assert len(audit.head_hash() or "") == HASH_HEX_LENGTH

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT prev_hash, row_hash FROM audit_log WHERE id = 1"
        ).fetchone()

    assert row is not None
    assert row[0] == GENESIS_HASH
    assert len(row[1]) == HASH_HEX_LENGTH


def _create_legacy_audit_db(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                cost_usd REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            INSERT INTO audit_log (
                timestamp,
                engagement_id,
                actor,
                action,
                payload_json,
                cost_usd
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-05-29T00:00:00+00:00",
                str(ENGAGEMENT_ID),
                "ai_web_agent",
                "run_started",
                json.dumps({"turn": 0}, sort_keys=True),
                0.0,
            ),
        )


def test_cli_audit_verify_accepts_run_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    with closing(AuditStore(run_dir / "audit.db")) as audit:
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="ai_web_agent",
            action="run_started",
            payload={"turn": 0},
        )

    cli.main(["audit", "verify", str(run_dir)])

    output = capsys.readouterr().out
    assert "audit verify OK" in output
    assert "rows=1" in output


def test_cli_audit_verify_exits_nonzero_on_tamper(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "audit.db"
    with closing(AuditStore(db_path)) as audit:
        audit.record(
            engagement_id=ENGAGEMENT_ID,
            actor="ai_web_agent",
            action="run_started",
            payload={"turn": 0},
        )
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE audit_log SET payload_json = ? WHERE id = 1",
            (json.dumps({"turn": 99}, sort_keys=True),),
        )

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["audit", "verify", str(db_path)])

    assert exc_info.value.code == 1
    output = capsys.readouterr().out
    assert "audit verify FAILED" in output
    assert "row_id=1" in output
