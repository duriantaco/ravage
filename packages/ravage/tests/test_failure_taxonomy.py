from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ravage.failure_taxonomy import (
    CaseFailureClassification,
    FailureTaxonomyReport,
    build_failure_taxonomy,
    classify_case,
    load_failure_taxonomy,
    render_markdown,
    signals_from_events,
)
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path

EXPECTED_CASES = 2
EXPECTED_MODEL_REQUESTS = 10


def _case(workspace: AgentWorkspace, **overrides: object) -> dict[str, object]:
    case: dict[str, object] = {
        "benchmark_id": "XBEN-001-24",
        "status": "failed",
        "solved": False,
        "tags": ["idor", "default_credentials"],
        "level": 2,
        "model_request_count": 5,
        "http_request_count": 12,
        "elapsed_seconds": 30.0,
        "events_path": str(workspace.root / "events.jsonl"),
    }
    case.update(overrides)
    return case


def test_setup_failure_when_no_model_work(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    case = _case(
        workspace,
        status="errored",
        model_request_count=0,
        error="docker build failed",
    )

    report = build_failure_taxonomy({"cases": [case]})

    classification = report.cases[0]
    assert classification.primary_category == "setup"
    assert classification.terminated_by == "errored"


def test_recon_failure_when_only_discovery_actions(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "discover_attack_surface"},
    )
    workspace.record_event(kind="agent_action", payload={"turn": 2, "action": "http_get"})
    workspace.record_event(kind="max_turns_reached", payload={"max_turns": 12})

    report = build_failure_taxonomy({"cases": [_case(workspace)]})

    classification = report.cases[0]
    assert classification.primary_category == "recon"
    assert classification.terminated_by == "budget_exhausted"


def test_probe_failure_with_self_final(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "discover_attack_surface"},
    )
    workspace.record_event(kind="agent_action", payload={"turn": 2, "action": "test_sqli_param"})
    workspace.record_event(kind="agent_action", payload={"turn": 3, "action": "final"})

    report = build_failure_taxonomy({"cases": [_case(workspace)]})

    classification = report.cases[0]
    assert classification.primary_category == "probe"
    assert classification.terminated_by == "agent_final"


def test_evidence_failure_when_finding_confirmed_but_unsolved(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "test_idor_candidate"},
    )
    workspace.record_event(kind="finding_confirmed", payload={"vuln_class": "idor"})
    workspace.record_event(kind="max_turns_reached", payload={"max_turns": 12})

    report = build_failure_taxonomy({"cases": [_case(workspace)]})

    classification = report.cases[0]
    # Capability reached the proof stage; control ran out of budget. Both survive.
    assert classification.primary_category == "evidence"
    assert classification.terminated_by == "budget_exhausted"


def test_rejected_report_and_capture_actions_do_not_count_as_evidence(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "test_ssti_param"},
    )
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 2, "action": "report_finding"},
    )
    workspace.record_event(
        kind="finding_rejected",
        payload={"tool": "report_finding", "ok": False},
    )
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 3, "action": "capture_flag"},
    )
    workspace.record_event(
        kind="flag_rejected",
        payload={"tool": "capture_flag", "ok": False},
    )

    classification = report_first(build_failure_taxonomy({"cases": [_case(workspace)]}))

    assert classification.deepest_stage == "probe"
    assert classification.primary_category == "probe"


def test_budget_terminal_wins_over_blocked_final(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "test_ssti_param"},
    )
    workspace.record_event(kind="agent_action", payload={"turn": 2, "action": "final"})
    workspace.record_event(kind="max_turns_reached", payload={"max_turns": 2})

    classification = report_first(build_failure_taxonomy({"cases": [_case(workspace)]}))

    assert classification.primary_category == "probe"
    assert classification.terminated_by == "budget_exhausted"


def test_solved_case_excluded_from_failure_category_counts(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "test_idor_candidate"},
    )
    workspace.record_event(kind="flag_captured", payload={"flag": "flag{x}"})

    report = build_failure_taxonomy(
        {"cases": [_case(workspace, status="solved", solved=True, found_flag="flag{x}")]}
    )

    assert report.solved == 1
    assert report.solve_rate == 1.0
    assert report.cases[0].primary_category == "solved"
    assert report.cases[0].terminated_by == "solved"
    assert "solved" not in report.category_counts


def test_aggregate_counts_and_cost(tmp_path: Path) -> None:
    solved_ws = AgentWorkspace.open(tmp_path / "solved")
    solved_ws.record_event(kind="flag_captured", payload={"flag": "flag{x}"})
    failed_ws = AgentWorkspace.open(tmp_path / "failed")
    failed_ws.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "discover_attack_surface"},
    )

    report = build_failure_taxonomy(
        {
            "cases": [
                _case(
                    solved_ws,
                    benchmark_id="A",
                    solved=True,
                    status="solved",
                    model_request_count=4,
                ),
                _case(failed_ws, benchmark_id="B", model_request_count=6),
            ]
        }
    )

    assert report.total_cases == EXPECTED_CASES
    assert "solved" not in report.category_counts
    assert report.category_counts["recon"] == 1
    assert report.cost["model_requests_total"] == EXPECTED_MODEL_REQUESTS
    assert report.tag_solve_rates["idor"]["total"] == EXPECTED_CASES
    assert report.tag_solve_rates["idor"]["solved"] == 1


def test_model_provider_error_without_count_is_model_failure(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="tool_call",
        payload={"tool": "discover_attack_surface", "ok": True},
    )
    workspace.record_event(
        kind="run_error",
        payload={
            "type": "ModelClientError",
            "message": "all model routes failed: openai/gpt-5.4: insufficient_quota",
        },
    )

    report = build_failure_taxonomy(
        {"cases": [_case(workspace, status="errored", model_request_count=0)]}
    )

    classification = report.cases[0]
    assert classification.primary_category == "model"
    assert classification.deepest_stage == "recon"
    assert classification.signals["terminal_error_type"] == "ModelClientError"


def test_agent_crash_after_model_work_keeps_deepest_stage(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "test_ssti_param"},
    )
    workspace.record_event(
        kind="run_error",
        payload={
            "type": "AttributeError",
            "message": "'NoneType' object has no attribute 'route'",
        },
    )

    report = build_failure_taxonomy(
        {"cases": [_case(workspace, status="errored", model_request_count=3)]}
    )

    classification = report.cases[0]
    assert classification.primary_category == "probe"
    assert classification.terminated_by == "errored"


def test_source_guided_and_nosqli_actions_are_probe_stage() -> None:
    source_guided = signals_from_events(
        [{"kind": "agent_action", "payload": {"action": "source_guided_probe"}}]
    )
    nosqli = signals_from_events(
        [{"kind": "agent_action", "payload": {"action": "test_nosqli_param"}}]
    )

    assert source_guided.deepest_stage == "probe"
    assert nosqli.deepest_stage == "probe"


def test_terminal_calls_stage_underlying_command() -> None:
    sqlmap = signals_from_events(
        [
            {
                "kind": "terminal_call",
                "payload": {
                    "tool": "terminal_start",
                    "command": ["sqlmap", "-u", "http://example.test/?id=1"],
                },
            }
        ]
    )
    curl = signals_from_events(
        [
            {
                "kind": "terminal_call",
                "payload": {
                    "tool": "terminal_start",
                    "command": ["curl", "-i", "http://example.test/"],
                },
            }
        ]
    )

    assert sqlmap.deepest_stage == "probe"
    assert curl.deepest_stage == "recon"


def test_missing_events_file_is_setup_when_no_model_work(tmp_path: Path) -> None:
    case = {
        "benchmark_id": "XBEN-009-24",
        "status": "errored",
        "solved": False,
        "tags": [],
        "model_request_count": 0,
        "http_request_count": 0,
        "elapsed_seconds": 1.0,
        "events_path": str(tmp_path / "missing" / "events.jsonl"),
    }

    classification = report_first(build_failure_taxonomy({"cases": [case]}))

    assert classification.primary_category == "setup"
    assert classification.signals["events_present"] is False


def test_signals_from_events_tracks_deepest_stage() -> None:
    signals = signals_from_events(
        [
            {"kind": "agent_action", "payload": {"action": "discover_attack_surface"}},
            {"kind": "agent_action", "payload": {"action": "browser_login"}},
        ]
    )
    assert signals.deepest_stage == "auth"


def test_classify_case_direct_with_signals() -> None:
    signals = signals_from_events(
        [{"kind": "agent_action", "payload": {"action": "test_xss_param"}}]
    )
    classification = classify_case({"benchmark_id": "Z", "status": "failed"}, signals)
    assert classification.primary_category == "probe"


def test_load_and_render(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "ws")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "discover_attack_surface"},
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"cases": [_case(workspace)]}), encoding="utf-8")

    report = load_failure_taxonomy(report_path)
    markdown = render_markdown(report)

    assert "XBEN Failure Taxonomy" in markdown
    assert "recon" in markdown


def test_load_resolves_xben_relative_event_paths_from_report_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "xben" / "relative-run"
    workspace = AgentWorkspace.open(run_dir / "XBEN-023-24" / "workspace")
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "test_ssti_param"},
    )
    report_path = run_dir / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "benchmark_id": "XBEN-023-24",
                        "status": "failed",
                        "solved": False,
                        "model_request_count": 0,
                        "events_path": (
                            "runs/xben/relative-run/"
                            "XBEN-023-24/workspace/events.jsonl"
                        ),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    classification = report_first(load_failure_taxonomy(report_path))

    assert classification.primary_category == "probe"
    assert classification.signals["events_present"] is True


def report_first(report: FailureTaxonomyReport) -> CaseFailureClassification:
    return report.cases[0]
