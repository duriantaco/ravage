from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING

from ravage import __main__ as cli
from ravage.competitor_harness import score_agent_output
from ravage.run_data.workspace import AgentWorkspace
from ravage.self_adapter import RESULT_SCHEMA_VERSION, build_ravage_competitor_result

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    import pytest

EXPECTED_TURNS = 1
EXPECTED_TOOL_CALLS = 4
EXPECTED_REQUESTS = 7
EXPECTED_COST_USD = 0.25
EXPECTED_REPORT_COST_USD = 0.125
EXPECTED_MAX_TURNS = 12
EXPECTED_INPUT_TOKENS = 100
EXPECTED_CACHED_INPUT_TOKENS = 25
EXPECTED_OUTPUT_TOKENS = 10


def test_build_ravage_competitor_result_emits_scoreable_payload(tmp_path: Path) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["schema_version"] == RESULT_SCHEMA_VERSION
    assert payload["mode"] == "ravage_benchmark"
    assert payload["cost_usd"] == EXPECTED_COST_USD
    assert payload["cost_status"] == "reported"
    assert payload["cost_provenance"] == "ravage_audit_log_legacy"
    assert payload["raw_flags"] == ["flag{one}"]
    actuals = _mapping(payload["actuals"])
    budgets = _mapping(payload["budgets"])
    artifacts = _mapping(payload["artifacts"])
    termination = _mapping(payload["termination"])
    assert actuals["turns_total"] == EXPECTED_TURNS
    assert actuals["model_calls"] == EXPECTED_TURNS
    assert actuals["tool_calls"] == EXPECTED_TOOL_CALLS
    assert actuals["input_tokens"] == EXPECTED_INPUT_TOKENS
    assert actuals["cached_input_tokens"] == EXPECTED_CACHED_INPUT_TOKENS
    assert actuals["output_tokens"] == EXPECTED_OUTPUT_TOKENS
    assert actuals["http_requests"] == EXPECTED_REQUESTS
    assert budgets["max_turns"] == EXPECTED_MAX_TURNS
    assert artifacts["benchmark_report_path"] == str(report_path)
    assert termination["status"] == "completed"
    assert payload["phases"] == [
        {
            "name": "ravage_kill_chain:controlled_exploitation",
            "stage_id": "controlled_exploitation",
            "events": 1,
            "turns": 1,
        }
    ]

    scored = score_agent_output(
        payload,
        expected_flags=["flag{one}"],
        evidence_root=tmp_path,
    )
    assert scored.valid_flags == ("flag{one}",)
    assert scored.false_positives == 0
    assert scored.total_reported_findings == 1
    assert scored.cost_status == "reported"
    assert scored.cost_provenance == "adapter_reported"


def test_build_ravage_competitor_result_marks_report_cost_source(tmp_path: Path) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["cases"][0]["cost_usd"] = EXPECTED_REPORT_COST_USD
    report["cases"][0]["cost_status"] = "known"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["cost_usd"] == EXPECTED_REPORT_COST_USD
    assert payload["cost_status"] == "reported"
    assert payload["cost_provenance"] == "ravage_benchmark_report"


def test_build_ravage_competitor_result_honors_explicit_unknown_cost_status(
    tmp_path: Path,
) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["cases"][0]["cost_usd"] = None
    report["cases"][0]["cost_status"] = "unknown"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["cost_usd"] is None
    assert payload["cost_status"] == "unknown"
    assert payload["cost_provenance"] == "unavailable"


def test_build_ravage_competitor_result_honors_explicit_invalid_cost_status(
    tmp_path: Path,
) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["cases"][0]["cost_usd"] = EXPECTED_REPORT_COST_USD
    report["cases"][0]["cost_status"] = "invalid"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["cost_usd"] is None
    assert payload["cost_status"] == "invalid"
    assert payload["cost_provenance"] == "ravage_benchmark_report"


def test_legacy_audit_fallback_does_not_override_explicit_null_cost(tmp_path: Path) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["cases"][0]["cost_usd"] = None
    report_path.write_text(json.dumps(report), encoding="utf-8")

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["cost_usd"] is None
    assert payload["cost_status"] == "unknown"
    assert payload["cost_provenance"] == "unavailable"


def test_legacy_audit_cost_rejects_unmatched_model_request_start(tmp_path: Path) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "case-one.workspace")
    workspace.record_event(
        kind="model_request_started",
        payload={"turn": 2, "provider": "openai", "model": "gpt-test"},
    )

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["cost_usd"] is None
    assert payload["cost_status"] == "unknown"
    assert payload["cost_provenance"] == "unavailable"


def test_legacy_audit_cost_rejects_unaccountable_model_reply(tmp_path: Path) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    db_path = tmp_path / "case-one.db"
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT payload_json FROM audit_log WHERE action = 'model_reply_received'"
        ).fetchone()
        assert row is not None
        audit_payload = json.loads(str(row[0]))
        audit_payload["cost_known"] = False
        conn.execute(
            "UPDATE audit_log SET payload_json = ? WHERE action = 'model_reply_received'",
            (json.dumps(audit_payload),),
        )

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["cost_usd"] is None
    assert payload["cost_status"] == "unknown"
    assert payload["cost_provenance"] == "unavailable"


def test_build_ravage_competitor_result_does_not_treat_unpriced_audit_as_free(
    tmp_path: Path,
) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    with sqlite3.connect(tmp_path / "case-one.db") as conn:
        conn.execute("UPDATE audit_log SET cost_usd = 0")

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["cost_usd"] is None
    assert payload["cost_status"] == "unknown"
    assert payload["cost_provenance"] == "unavailable"


def test_failed_case_does_not_emit_ground_truth_flag(tmp_path: Path) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    case = report["cases"][0]
    case["passed"] = False
    case["flag"] = "flag{answer-key-only}"
    case["found_flag"] = None
    report_path.write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "case-one.workspace" / "events.jsonl").write_text("", encoding="utf-8")

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["raw_flags"] == []
    assert _mapping(payload["termination"])["status"] == "failed"
    scored = score_agent_output(
        payload,
        expected_flags=["flag{answer-key-only}"],
        evidence_root=tmp_path,
    )
    assert scored.valid_flags == ()


def test_failed_case_ignores_flag_strings_outside_capture_events(tmp_path: Path) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    case = report["cases"][0]
    case["passed"] = False
    case["flag"] = "flag{answer-key-only}"
    case["found_flag"] = None
    report_path.write_text(json.dumps(report), encoding="utf-8")
    events_path = tmp_path / "case-one.workspace" / "events.jsonl"
    events_path.write_text(
        json.dumps(
            {
                "kind": "observation",
                "payload": {
                    "flag": "flag{answer-key-only}",
                    "proof": "flag{answer-key-only}",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    payload = build_ravage_competitor_result(
        benchmark_report_path=report_path,
        case_id="case-one",
    )

    assert payload["raw_flags"] == []


def test_cli_competitors_adapt_ravage_writes_result(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    report_path = _write_benchmark_artifacts(tmp_path)
    output_path = tmp_path / "agent-result.json"

    cli.main(
        [
            "competitors",
            "adapt-ravage",
            "--benchmark-report",
            str(report_path),
            "--case-id",
            "case-one",
            "--output",
            str(output_path),
        ]
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    adapter_metadata = _mapping(payload["adapter_metadata"])
    actuals = _mapping(payload["actuals"])
    assert adapter_metadata["adapter"] == "ravage_self_adapter"
    assert actuals["turns_total"] == EXPECTED_TURNS
    assert f"output={output_path}" in capsys.readouterr().out


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    return value


def _write_benchmark_artifacts(tmp_path: Path) -> Path:
    db_path = tmp_path / "case-one.db"
    _write_case_db(db_path)
    workspace = AgentWorkspace.open(tmp_path / "case-one.workspace")
    workspace.record_event(
        kind="kill_chain_stage",
        payload={
            "stage_id": "controlled_exploitation",
            "turn": 1,
            "action": "test_sqli_param",
        },
    )
    workspace.record_event(
        kind="model_request_started",
        payload={"turn": 1, "provider": "openai", "model": "gpt-test"},
    )
    workspace.record_event(
        kind="model_reply_received",
        payload={
            "turn": 1,
            "provider": "openai",
            "model": "gpt-test",
            "input_tokens": EXPECTED_INPUT_TOKENS,
            "cached_input_tokens": EXPECTED_CACHED_INPUT_TOKENS,
            "output_tokens": EXPECTED_OUTPUT_TOKENS,
        },
    )
    workspace.record_event(
        kind="agent_action",
        payload={
            "turn": 1,
            "action": "test_sqli_param",
            "kill_chain_stage": {"stage_id": "controlled_exploitation"},
        },
    )
    workspace.record_event(kind="tool_run_command", payload={"tool": "shell"})
    workspace.record_event(kind="tool_run_python", payload={"tool": "python"})
    workspace.record_event(kind="tool_run_probe", payload={"tool": "probe"})
    workspace.record_event(kind="tool_validate_poc", payload={"tool": "validate_poc"})
    workspace.record_event(kind="http_step", payload={"status": 200})
    workspace.record_event(kind="observation", payload={"status": "ok"})
    workspace.record_event(kind="finding_confirmed", payload={"vuln_class": "ssrf"})
    workspace.record_event(kind="flag_captured", payload={"flag": "flag{one}"})
    workspace.record_event(kind="run_completed", payload={"status": "completed"})
    workspace.record_transcript(role="assistant", content="tool call")

    report_path = tmp_path / "benchmark-report.json"
    report_path.write_text(
        json.dumps(
            {
                "preflight": {
                    "max_cost_usd": 1.0,
                    "cases": [
                        {
                            "case_id": "case-one",
                            "max_turns": EXPECTED_MAX_TURNS,
                            "model_request_ceiling": EXPECTED_MAX_TURNS,
                            "estimated_input_tokens_ceiling": 12000,
                            "estimated_output_tokens_ceiling": 4096,
                            "estimated_cost_usd": 0.5,
                            "budget": {
                                "max_http_requests": 50,
                                "max_seconds": 30.0,
                            },
                        }
                    ],
                },
                "cases": [
                    {
                        "case_id": "case-one",
                        "passed": True,
                        "elapsed_seconds": 1.25,
                        "request_count": EXPECTED_REQUESTS,
                        "true_positives": 1,
                        "false_positives": 0,
                        "false_negatives": 0,
                        "failures": [],
                        "db_path": str(db_path),
                        "workspace_path": str(workspace.root),
                        "events_path": str(workspace.events_path),
                        "transcript_path": str(workspace.transcript_path),
                        "artifacts_path": str(workspace.artifacts_dir),
                        "trace_summary": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return report_path


def _write_case_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    finding = {
        "vuln_class": "ssrf",
        "status": "confirmed",
        "validator_vote": "confirm",
        "endpoint": {
            "url": "http://target.local/fetch",
            "params": ["url"],
        },
        "proof": {
            "param": "url",
            "http_request_final": "GET /fetch?url=http://127.0.0.1 HTTP/1.1",
            "response_final": "HTTP/1.1 200 OK",
        },
    }
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE audit_log (action TEXT, payload_json TEXT, cost_usd REAL)"
        )
        conn.execute(
            "INSERT INTO audit_log (action, payload_json, cost_usd) VALUES (?, ?, ?)",
            (
                "model_reply_received",
                json.dumps(
                    {
                        "turn": 1,
                        "provider": "openai",
                        "model": "gpt-test",
                        "input_tokens": EXPECTED_INPUT_TOKENS,
                        "cached_input_tokens": EXPECTED_CACHED_INPUT_TOKENS,
                        "output_tokens": EXPECTED_OUTPUT_TOKENS,
                        "cost_usd": EXPECTED_COST_USD,
                        "usage_reported": True,
                        "cost_known": True,
                    }
                ),
                EXPECTED_COST_USD,
            ),
        )
        conn.execute("CREATE TABLE findings (payload_json TEXT)")
        conn.execute(
            "INSERT INTO findings (payload_json) VALUES (?)",
            (json.dumps(finding),),
        )
