# ruff: noqa: PLR2004
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tools.xben_head_to_head import report

if TYPE_CHECKING:
    from pathlib import Path


def _campaign() -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for number in range(1, 21):
        case_id = f"XBEN-{number:03d}-24"
        codex_solved = number <= 9
        strix_solved = number <= 5 or 10 <= number <= 11
        rows.extend(
            (
                {
                    "case_id": case_id,
                    "level": (number - 1) % 3 + 1,
                    "system": "codex_skill",
                    "status": "completed",
                    "solved": codex_solved,
                    "valid": True,
                    "duration_seconds": 1,
                    "request_count": 2,
                    "input_tokens": 100,
                    "cached_input_tokens": 20,
                    "output_tokens": 10,
                    "cost_usd": 0.1,
                    "error": None,
                    "declared_candidate_sha256s": [f"{number:064x}"],
                    "matched_candidate_sha256": f"{number:064x}" if codex_solved else None,
                    "sanitized_runner_receipt_sha256": "a" * 64,
                    "evidence_manifest_sha256": "b" * 64,
                    "evidence_path": f"evidence/{case_id}/codex_skill",
                    "codex_target_http_requests": 2,
                },
                {
                    "case_id": case_id,
                    "level": (number - 1) % 3 + 1,
                    "system": "strix",
                    "status": "completed",
                    "solved": strix_solved,
                    "valid": True,
                    "duration_seconds": 2,
                    "request_count": 3,
                    "input_tokens": 200,
                    "cached_input_tokens": 40,
                    "output_tokens": 20,
                    "cost_usd": None if number == 20 else 0.2,
                    "error": None,
                    "declared_candidate_sha256s": [f"{number + 20:064x}"],
                    "matched_candidate_sha256": f"{number + 20:064x}" if strix_solved else None,
                    "sanitized_runner_receipt_sha256": "c" * 64,
                    "evidence_manifest_sha256": "d" * 64,
                    "evidence_path": f"evidence/{case_id}/strix",
                    "strix_model_requests": 3,
                },
            )
        )
    return {
        "title": "fixed diagnostic",
        "created_at": "2026-09-16T01:00:00+00:00",
        "completed_at": "2026-09-16T02:00:00+00:00",
        "case_ids": [f"XBEN-{number:03d}-24" for number in range(1, 21)],
        "source": {
            "ravage_commit": "a" * 40,
            "strix_commit": "b" * 40,
            "xben_commit": "c" * 40,
        },
        "model": {
            "provider": "openai",
            "model": "gpt-5.4-2026-03-05",
            "reasoning_effort": "high",
        },
        "runtime": {
            "codex_version": "0.999.0",
            "strix_version": "1.6.2",
            "strix_sandbox_image": "ghcr.io/usestrix/strix-sandbox@sha256:" + "d" * 64,
        },
        "budgets": {
            "per_row_seconds": 600,
            "per_row_cost_usd": 5,
            "campaign_cost_usd": 200,
        },
        "methodology": {"selection": "seeded before execution"},
        "rows": rows,
    }


def test_build_report_computes_matched_outcomes_and_resources() -> None:
    built = report.build_report(_campaign())

    assert built["schema_version"] == report.REPORT_SCHEMA
    summary = built["summary"]
    assert summary["case_count"] == 20
    assert summary["row_count"] == 40
    assert summary["systems"]["codex_skill"]["solved"] == 9
    assert summary["systems"]["strix"]["solved"] == 7
    assert summary["contingency"] == {
        "both_solved": 5,
        "codex_skill_only": 4,
        "strix_only": 2,
        "neither_solved": 9,
        "discordant_pairs": 6,
        "solve_rate_delta_percentage_points": 10.0,
        "two_sided_exact_sign_test_p_value": 0.6875,
    }
    resources = summary["overall_resources"]
    assert resources["request_count"] == {"known_total": 100, "unknown_rows": 0}
    assert resources["input_tokens"] == {"known_total": 6000, "unknown_rows": 0}
    assert resources["total_tokens"] == {"known_total": 6600, "unknown_rows": 0}
    assert resources["duration_seconds"] == {"known_total": 60.0, "unknown_rows": 0}
    assert resources["cost_usd"] == {
        "known_subtotal": 5.8,
        "unknown_rows": 1,
        "total": None,
    }
    first = built["rows"][0]
    assert first["declared_candidate_sha256s"] == [f"{1:064x}"]
    assert first["matched_candidate_sha256"] == f"{1:064x}"
    assert first["sanitized_runner_receipt_sha256"] == "a" * 64
    assert first["evidence_manifest_sha256"] == "b" * 64
    assert first["codex_target_http_requests"] == 2


@pytest.mark.parametrize(
    ("first_only", "second_only", "expected"),
    [(0, 0, 1.0), (4, 2, 0.6875), (5, 0, 0.0625), (1, 1, 1.0)],
)
def test_exact_sign_test(first_only: int, second_only: int, expected: float) -> None:
    assert report.exact_sign_test_p_value(first_only, second_only) == expected


def test_markdown_is_explicit_complete_and_deterministic() -> None:
    campaign = _campaign()

    first = report.render_markdown(campaign)
    second = report.render_markdown(campaign)

    assert first == second
    assert first.startswith("# Codex + Ravage Skill vs Strix — 20-Case XBEN Diagnostic")
    assert "exploratory local diagnostic—not official/public/SOTA XBEN score" in first
    assert "gpt-5.4-2026-03-05" in first
    assert "ghcr.io/usestrix/strix-sandbox@sha256:" in first
    assert "| XBEN-001-24 |" in first
    assert "| XBEN-020-24 |" in first
    assert "| 5 | 4 | 2 | 9 | 6 | +10.0 pp |" in first
    assert "**0.6875**" in first
    assert "$5.8000 known (+1 unknown; total unknown)" in first
    assert "shared Docker authority" in first
    assert "no independent anti-cheat isolation" in first
    assert "Unknown cost, request, token, or runtime observations are unknown—not zero" in first
    assert "historical 96% result is contextual only" in first
    assert "Strix v0.4.0" in first
    assert "Gemini 3 Pro Preview" in first


def test_write_report_atomically_emits_stable_markdown_and_json(tmp_path: Path) -> None:
    campaign = _campaign()

    markdown_path, json_path = report.write_report(tmp_path / "out", campaign)
    first_markdown = markdown_path.read_bytes()
    first_json = json_path.read_bytes()
    second_markdown_path, second_json_path = report.write_report(tmp_path / "out", campaign)

    assert markdown_path.name == "COMPARISON.md"
    assert json_path.name == "report.json"
    assert second_markdown_path.read_bytes() == first_markdown
    assert second_json_path.read_bytes() == first_json
    assert json.loads(first_json)["summary"]["contingency"]["codex_skill_only"] == 4
    assert not list((tmp_path / "out").glob(".*.tmp"))


def test_rejects_duplicate_or_incomplete_pairs() -> None:
    campaign = _campaign()
    rows = campaign["rows"]
    assert isinstance(rows, list)
    rows[-1] = dict(rows[0])

    with pytest.raises(report.HeadToHeadReportError, match=r"duplicate|unique cases|missing"):
        report.build_report(campaign)


@pytest.mark.parametrize(
    ("status", "error"),
    [("timed_out", None), ("error", "runner failed"), ("completed", "cleanup failed")],
)
def test_report_never_scores_nonterminal_or_errored_claim_as_solved(
    status: str,
    error: str | None,
) -> None:
    campaign = _campaign()
    rows = campaign["rows"]
    assert isinstance(rows, list)
    row = rows[0]
    assert isinstance(row, dict)
    row.update(status=status, solved=True, valid=True, error=error)

    built = report.build_report(campaign)
    normalized = next(
        item
        for item in built["rows"]
        if item["case_id"] == "XBEN-001-24" and item["system"] == "codex_skill"
    )

    assert normalized["scored_solved"] is False
    assert normalized["evidence_valid"] is False
