from __future__ import annotations

import stat
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph import traffic_lifecycle
from ravage.agent_core.autonomous_graph.traffic_lifecycle import (
    GraphTrafficLifecycle,
    GraphTrafficLifecycleError,
    graph_traffic_session_id,
)
from ravage.traffic.contracts import build_captured_http_exchange
from ravage.traffic.manifest import TrafficRunManifest, read_traffic_manifest
from ravage.traffic.recorders import TrafficRecorderError
from ravage.traffic.store import TrafficStoreError

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.traffic.contracts import CapturedHttpExchange

TARGET_URL = "https://target.example/app"
IN_SCOPE = ("https://target.example/app",)
OUT_OF_SCOPE = ("https://target.example/admin",)
GRAPH_ID = "graph-route-lifecycle-test"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def _open(
    workspace: Path,
    *,
    graph_id: str = GRAPH_ID,
    identity_alias: str = "",
) -> GraphTrafficLifecycle:
    return GraphTrafficLifecycle.open(
        workspace,
        target_url=TARGET_URL,
        in_scope=IN_SCOPE,
        out_of_scope=OUT_OF_SCOPE,
        capture_session_id=graph_traffic_session_id(graph_id),
        identity_alias=identity_alias,
    )


def _record_one(lifecycle: GraphTrafficLifecycle) -> CapturedHttpExchange:
    stored = lifecycle.recorder(
        {
            "disposition": "sent",
            "source_observation_id": "http:obs-test",
            "resource_type": "agent_http",
            "method": "GET",
            "url": TARGET_URL,
            "request_headers": {"Accept": "application/json"},
            "response_status": 200,
            "response_url": TARGET_URL,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": b'{"ok":true}',
            "elapsed_ms": 5,
            "reason": "authorized autonomous graph HTTP request",
        }
    )
    assert stored is not None
    return stored


def test_graph_session_id_survives_manifest_validation() -> None:
    capture_session_id = graph_traffic_session_id(GRAPH_ID)

    manifest = TrafficRunManifest.create(
        target_url=TARGET_URL,
        capture_session_id=capture_session_id,
        in_scope=IN_SCOPE,
        out_of_scope=OUT_OF_SCOPE,
    )

    assert manifest.capture_session_id == capture_session_id


def test_graph_traffic_create_record_finalize_and_resume(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    lifecycle = _open(workspace)

    stored = _record_one(lifecycle)
    terminal = lifecycle.finalize()

    assert lifecycle.resumed is False
    assert stored.source == "agent_http"
    assert stored.source_observation_id == "http:obs-test"
    assert stored.response_error == ""
    assert terminal.to_json() == {
        "status": "completed",
        "capture_session_id": graph_traffic_session_id(GRAPH_ID),
        "resumed": False,
        "exchange_count": 1,
        "agent_http_exchange_count": 1,
        "manifest_completed": True,
        "warnings": [],
        "errors": [],
    }
    assert read_traffic_manifest(workspace).completed_at
    assert stat.S_IMODE((workspace / "traffic").stat().st_mode) == PRIVATE_DIRECTORY_MODE
    assert stat.S_IMODE((workspace / "traffic" / "run.json").stat().st_mode) == PRIVATE_FILE_MODE

    resumed = _open(workspace)

    assert resumed.resumed is True
    assert resumed.manifest.capture_session_id == graph_traffic_session_id(GRAPH_ID)
    assert resumed.finalize().exchange_count == 1


def test_graph_traffic_binds_authenticated_identity_across_resume(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    lifecycle = _open(workspace, identity_alias="analyst")

    stored = _record_one(lifecycle)
    lifecycle.finalize()

    assert stored.identity_alias == "analyst"
    assert _open(workspace, identity_alias="analyst").resumed is True
    with pytest.raises(GraphTrafficLifecycleError, match="authentication identity"):
        _open(workspace, identity_alias="administrator")
    with pytest.raises(GraphTrafficLifecycleError, match="authentication identity"):
        _open(workspace)


def test_graph_traffic_resume_rejects_target_scope_and_session_changes(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    _open(workspace).finalize()
    capture_session_id = graph_traffic_session_id(GRAPH_ID)

    with pytest.raises(GraphTrafficLifecycleError, match="target does not match"):
        GraphTrafficLifecycle.open(
            workspace,
            target_url="https://other.example/app",
            in_scope=IN_SCOPE,
            out_of_scope=OUT_OF_SCOPE,
            capture_session_id=capture_session_id,
        )
    with pytest.raises(GraphTrafficLifecycleError, match="scope does not match"):
        GraphTrafficLifecycle.open(
            workspace,
            target_url=TARGET_URL,
            in_scope=("https://target.example/other",),
            out_of_scope=OUT_OF_SCOPE,
            capture_session_id=capture_session_id,
        )
    with pytest.raises(GraphTrafficLifecycleError, match="capture session does not match"):
        GraphTrafficLifecycle.open(
            workspace,
            target_url=TARGET_URL,
            in_scope=IN_SCOPE,
            out_of_scope=OUT_OF_SCOPE,
            capture_session_id=graph_traffic_session_id("different-graph"),
        )


def test_graph_traffic_recorder_is_strict_and_terminal_keeps_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = _open(tmp_path / "workspace")

    def fail_append(_exchange: CapturedHttpExchange) -> CapturedHttpExchange:
        message = "traffic disk unavailable"
        raise TrafficStoreError(message)

    monkeypatch.setattr(lifecycle.store, "append_exchange", fail_append)

    with pytest.raises(TrafficRecorderError, match="traffic disk unavailable"):
        _record_one(lifecycle)

    terminal = lifecycle.finalize()
    assert terminal.to_json()["status"] == "error"
    assert terminal.errors == ("traffic disk unavailable",)


def test_graph_traffic_resume_rejects_store_records_from_another_session(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    lifecycle = _open(workspace)
    lifecycle.store.append_exchange(
        build_captured_http_exchange(
            capture_session_id=graph_traffic_session_id("other-graph"),
            source="agent_http",
            method="GET",
            url=TARGET_URL,
            request_sent=True,
            response_status=200,
            response_final_url=TARGET_URL,
            scope_decision="allowed",
        )
    )

    with pytest.raises(GraphTrafficLifecycleError, match="different capture session"):
        _open(workspace)


def test_graph_resume_requires_prior_traffic_history(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"

    with pytest.raises(GraphTrafficLifecycleError, match="missing its prior traffic"):
        GraphTrafficLifecycle.open(
            workspace,
            target_url=TARGET_URL,
            in_scope=IN_SCOPE,
            out_of_scope=OUT_OF_SCOPE,
            capture_session_id=graph_traffic_session_id(GRAPH_ID),
            graph_resume_expected=True,
        )


def test_new_graph_refuses_orphaned_agent_http_history(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    lifecycle = _open(workspace)
    _record_one(lifecycle)
    lifecycle.finalize()

    with pytest.raises(GraphTrafficLifecycleError, match="cannot reuse prior"):
        GraphTrafficLifecycle.open(
            workspace,
            target_url=TARGET_URL,
            in_scope=IN_SCOPE,
            out_of_scope=OUT_OF_SCOPE,
            capture_session_id=graph_traffic_session_id(GRAPH_ID),
            graph_resume_expected=False,
        )


def test_graph_traffic_finalization_warning_is_terminal_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = _open(tmp_path / "workspace")
    failure_message = "completion disk unavailable"

    def fail_write(_workspace: Path, _manifest: TrafficRunManifest) -> Path:
        raise OSError(failure_message)

    monkeypatch.setattr(traffic_lifecycle, "write_traffic_manifest", fail_write)

    terminal = lifecycle.finalize()

    assert terminal.to_json()["status"] == "warning"
    assert terminal.manifest_completed is False
    assert terminal.warnings == (
        "traffic manifest finalization failed: completion disk unavailable",
    )
