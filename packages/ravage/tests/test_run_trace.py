from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from ravage.run_data.workspace import AgentWorkspace
from ravage.run_trace import TRACE_SCHEMA_VERSION, summarize_workspace_trace

if TYPE_CHECKING:
    from pathlib import Path

EXPECTED_TURNS_WITH_INVALID_ACTION = 2
CONCURRENT_EVENT_COUNT = 80


def test_summarize_workspace_trace_derives_ravage_turn_metrics(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.record_event(
        kind="model_reply",
        payload={"turn": 1, "content": '{"action":"discover_attack_surface"}'},
    )
    workspace.record_event(
        kind="agent_action",
        payload={"turn": 1, "action": "discover_attack_surface"},
    )
    workspace.record_event(kind="tool_call", payload={"tool": "discover_attack_surface"})
    workspace.record_event(kind="observation", payload={"status": "ok"})
    workspace.record_event(kind="invalid_model_action", payload={"turn": 2})
    workspace.record_event(kind="finding_confirmed", payload={"vuln_class": "ssrf"})
    workspace.record_event(kind="flag_captured", payload={"flag": "flag{one}"})
    workspace.record_event(
        kind="run_completed",
        payload={"status": "completed", "completed": True},
    )
    workspace.record_transcript(role="assistant", content="action")
    workspace.record_transcript(role="user", content="observation")

    summary = summarize_workspace_trace(workspace.root)
    payload = summary.to_json()

    assert payload["schema_version"] == TRACE_SCHEMA_VERSION
    assert payload["turns_total"] == EXPECTED_TURNS_WITH_INVALID_ACTION
    assert payload["model_calls"] == 1
    assert payload["tool_calls"] == 1
    assert payload["assistant_messages"] == 1
    assert payload["observations"] == 1
    assert payload["invalid_actions"] == 1
    assert payload["findings_confirmed"] == 1
    assert payload["flags_captured"] == 1
    assert payload["termination_status"] == "completed"


def test_summarize_workspace_trace_reports_unknowns_for_missing_files(tmp_path: Path) -> None:
    summary = summarize_workspace_trace(tmp_path / "missing-workspace")
    payload = summary.to_json()

    assert payload["events_present"] is False
    assert payload["transcript_present"] is False
    assert payload["turns_total"] is None
    assert payload["model_calls"] is None
    assert payload["assistant_messages"] is None


def test_workspace_serializes_events_from_concurrent_graph_workers(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")

    with ThreadPoolExecutor(max_workers=8) as pool:
        event_ids = list(
            pool.map(
                lambda index: workspace.record_event(
                    kind="graph_worker_event",
                    payload={"index": index},
                ),
                range(CONCURRENT_EVENT_COUNT),
            )
        )

    events = [
        json.loads(line)
        for line in workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(events) == CONCURRENT_EVENT_COUNT
    assert {event["event_id"] for event in events} == set(event_ids)
    assert {event["payload"]["index"] for event in events} == set(
        range(CONCURRENT_EVENT_COUNT)
    )
