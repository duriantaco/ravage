from __future__ import annotations

# Test fixtures use literal credentials and status codes on purpose.
# ruff: noqa: S105, PLR2004
import json
import urllib.request
from typing import TYPE_CHECKING

import ravage.live_dashboard as ld
from ravage.agent_core.live_events import (
    describe_action,
    http_step_payload,
    mask_command_string,
    mask_mapping,
)
from ravage.live_dashboard import (
    DashboardSettings,
    _command_output,
    _StreamCursor,
    build_dashboard_state,
    start_cockpit,
    teardown_active_run,
)
from ravage.run_data.run_manifest import (
    STATUS_AGENT_RUNNING,
    STATUS_TORN_DOWN,
    RunManifest,
    find_active_run_dir,
    write_manifest,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

ACTION_EVENTS = [
    {
        "event_id": "1",
        "timestamp": "2026-07-02T10:00:00+00:00",
        "kind": "agent_started",
        "payload": {"target_url": "http://localhost:59999"},
    },
    {
        "event_id": "2",
        "timestamp": "2026-07-02T10:00:01+00:00",
        "kind": "action_started",
        "payload": {
            "action_id": "a1",
            "turn": 1,
            "action_kind": "validate_poc",
            "summary": "Validate PoC (1 step)",
            "detail": "POST /login",
            "params": {},
        },
    },
    {
        "event_id": "3",
        "timestamp": "2026-07-02T10:00:02+00:00",
        "kind": "http_step",
        "payload": {
            "action_id": "a1",
            "index": 1,
            "method": "POST",
            "path": "/login",
            "url": "http://localhost:59999/login",
            "fields": {"username": "alice", "password": "••••"},
            "status": 302,
            "ok": True,
        },
    },
]


def _seed_run(
    root: Path,
    run_id: str = "XBEN-001-24",
    *,
    status: str = STATUS_AGENT_RUNNING,
    target_alive: bool = True,
    events: list[dict] | None = None,
) -> tuple[Path, Path]:
    case = root / run_id
    workspace = case / "workspace"
    workspace.mkdir(parents=True)
    write_manifest(
        case,
        RunManifest(
            run_id=run_id,
            benchmark_id=run_id,
            status=status,
            phase=status,
            target_url="http://localhost:59999",
            docker_project=f"ravage-{run_id.lower()}-x",
            keep_target=True,
            target_alive=target_alive,
            workspace_dir=str(workspace),
        ),
    )
    if events:
        (workspace / "events.jsonl").write_text(
            "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8"
        )
    return case, workspace


def test_find_active_run_prefers_live_case(tmp_path: Path) -> None:
    _seed_run(tmp_path, "XBEN-001-24", status=STATUS_TORN_DOWN, target_alive=False)
    _seed_run(tmp_path, "XBEN-002-24", status=STATUS_AGENT_RUNNING)
    active = find_active_run_dir(tmp_path)
    assert active is not None
    assert active.name == "XBEN-002-24"


def test_mask_mapping_masks_only_secret_fields() -> None:
    masked = mask_mapping({"username": "alice", "password": "hunter2", "csrf_token": "abc"})
    assert masked["username"] == "alice"
    assert masked["password"] != "hunter2"
    assert masked["csrf_token"] != "abc"


def test_mask_command_string_redacts_inline_secret() -> None:
    out = mask_command_string("curl -d 'user=bob&password=s3cr3t' http://t")
    assert "s3cr3t" not in out
    assert "bob" in out


def test_describe_action_masks_validate_poc_password() -> None:
    described = describe_action(
        {
            "action": "validate_poc",
            "steps": [
                {"method": "POST", "url": "http://t/login", "form": {"u": "a", "password": "p"}},
            ],
        }
    )
    fields = described["params"]["steps"][0]["fields"]
    assert fields["password"] != "p"
    assert described["summary"].startswith("Validate PoC")


def test_http_step_payload_masks_and_normalizes() -> None:
    payload = http_step_payload(
        action_id="a1",
        index=1,
        method="post",
        url="http://t/login?x=1",
        form={"password": "p"},
        status=200,
        ok=True,
    )
    assert payload["method"] == "POST"
    assert payload["path"] == "/login?x=%5BREDACTED%5D"
    assert payload["fields"]["password"] != "p"


def test_http_step_payload_sanitizes_urls_and_response_headers() -> None:
    payload = http_step_payload(
        action_id="safe-artifact",
        index=1,
        method="get",
        url=(
            "https://alice:request-password@target.example/callback"
            "?view=request-query&token=request-token#request-fragment"
        ),
        form=None,
        status=302,
        ok=True,
        response_headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Location": (
                "https://target.example/next"
                "?view=location-query&code=location-code#location-fragment"
            ),
            "Set-Cookie": "session=response-cookie",
            "X-Debug": "response-header-secret",
        },
        body="non-secret response evidence",
    )

    serialized = json.dumps(payload, sort_keys=True)
    for secret in (
        "alice",
        "request-password",
        "request-query",
        "request-token",
        "request-fragment",
        "location-query",
        "location-code",
        "location-fragment",
        "response-cookie",
        "response-header-secret",
    ):
        assert secret not in serialized
    assert payload["url"] == (
        "https://target.example/callback"
        "?view=%5BREDACTED%5D&token=%5BREDACTED%5D"
    )
    assert payload["path"] == "/callback?view=%5BREDACTED%5D&token=%5BREDACTED%5D"
    headers = payload["response_headers"]
    assert isinstance(headers, dict)
    assert headers["location"] == (
        "https://target.example/next?view=%5BREDACTED%5D&code=%5BREDACTED%5D"
    )
    assert headers["set-cookie"] == "[REDACTED]"
    assert headers["x-debug"] == "[REDACTED]"


def test_describe_invalid_action_sanitizes_url_bearing_error() -> None:
    described = describe_action(
        {
            "action": "invalid",
            "error": (
                "failed https://alice:error-password@target.example/callback"
                "?view=error-query#error-fragment; "
                "Authorization: Bearer error-authorization"
            ),
        }
    )

    serialized = json.dumps(described, sort_keys=True)
    for secret in (
        "alice",
        "error-password",
        "error-query",
        "error-fragment",
        "error-authorization",
    ):
        assert secret not in serialized
    assert "https://target.example/callback?view=%5BREDACTED%5D" in serialized


# ---- dashboard state ----------------------------------------------------


def test_dashboard_surfaces_live_action_events(tmp_path: Path) -> None:
    _seed_run(tmp_path, events=ACTION_EVENTS)
    state = build_dashboard_state(DashboardSettings(workspace_dir=tmp_path, run_root=tmp_path))
    assert state["mode"] == "live"
    assert state["manifest"]["run_id"] == "XBEN-001-24"

    commands = state["viewer"]["commands"]
    kinds = [command["kind"] for command in commands]
    assert "action_started" in kinds
    assert "http_step" in kinds

    started = next(c for c in commands if c["kind"] == "action_started")
    assert started["status"] == "started"
    assert started["action_id"] == "a1"

    http_step = next(c for c in commands if c["kind"] == "http_step")
    assert "•" in http_step["detail"]  # password stays masked
    assert http_step["depth"] == 1


def test_dashboard_replay_mode_when_target_reaped(tmp_path: Path) -> None:
    _seed_run(tmp_path, status=STATUS_TORN_DOWN, target_alive=False, events=ACTION_EVENTS)
    state = build_dashboard_state(DashboardSettings(workspace_dir=tmp_path, run_root=tmp_path))
    assert state["mode"] == "replay"
    assert state["viewer"]["target"]["status"].get("replay") is True


def test_command_output_extracts_tool_result_and_reasoning() -> None:
    assert _command_output(
        {"kind": "tool_validate_poc", "payload": {"result": "admin panel reached"}}
    ) == "admin panel reached"
    assert _command_output(
        {"kind": "tool_run_command", "payload": {"stdout": "root:x:0:0", "stderr": ""}}
    ).startswith("root:x:0:0")
    assert _command_output(
        {"kind": "model_reply_received", "payload": {"content": "try IDOR on /profile"}}
    ) == "try IDOR on /profile"
    assert _command_output({"kind": "agent_started", "payload": {}}) == ""


def test_stream_cursor_emits_snapshot_then_nothing(tmp_path: Path) -> None:
    _seed_run(tmp_path, events=ACTION_EVENTS)
    settings = DashboardSettings(workspace_dir=tmp_path, run_root=tmp_path)
    cursor = _StreamCursor()
    first = cursor.deltas(build_dashboard_state(settings))
    assert [name for name, _ in first] == ["state"]
    assert cursor.deltas(build_dashboard_state(settings)) == []


def test_stream_cursor_appends_only_new_step(tmp_path: Path) -> None:
    _case, workspace = _seed_run(tmp_path, events=ACTION_EVENTS)
    settings = DashboardSettings(workspace_dir=tmp_path, run_root=tmp_path)
    cursor = _StreamCursor()
    cursor.deltas(build_dashboard_state(settings))  # seed

    appended = [
        *ACTION_EVENTS,
        {
            "event_id": "4",
            "timestamp": "2026-07-02T10:00:03+00:00",
            "kind": "http_step",
            "payload": {
                "action_id": "a1",
                "index": 2,
                "method": "GET",
                "path": "/flag",
                "url": "http://localhost:59999/flag",
                "fields": {},
                "status": 200,
                "ok": True,
            },
        },
    ]
    (workspace / "events.jsonl").write_text(
        "\n".join(json.dumps(event) for event in appended) + "\n", encoding="utf-8"
    )
    names = [name for name, _ in cursor.deltas(build_dashboard_state(settings))]
    assert "step" in names


# ---- teardown -----------------------------------------------------------


def test_teardown_flips_manifest_to_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_run(tmp_path, events=ACTION_EVENTS)
    monkeypatch.setattr(ld, "_teardown_docker_project", lambda _project: 3)
    settings = DashboardSettings(workspace_dir=tmp_path, run_root=tmp_path)
    result = teardown_active_run(settings)
    assert result["ok"] is True
    assert result["removed"] == 3
    assert build_dashboard_state(settings)["mode"] == "replay"


# ---- live server round trip --------------------------------------------


def test_cockpit_server_serves_state_and_stream(tmp_path: Path) -> None:
    _seed_run(tmp_path, events=ACTION_EVENTS)
    settings = DashboardSettings(workspace_dir=tmp_path, run_root=tmp_path)
    cockpit = start_cockpit(settings, host="127.0.0.1", port=0)
    try:
        port = cockpit.server.server_address[1]
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(base + "/api/state", timeout=5) as response:  # noqa: S310
            state = json.loads(response.read())
        assert state["manifest"]["run_id"] == "XBEN-001-24"

        with urllib.request.urlopen(base + "/", timeout=5) as response:  # noqa: S310
            frontend = response.read().decode("utf-8")
        assert response.status == 200
        assert "Ravage Cockpit" in frontend

        with urllib.request.urlopen(  # noqa: S310
            base + "/assets/ravage_logo.png", timeout=5
        ) as response:
            logo = response.read()
        assert response.status == 200
        assert logo.startswith(b"\x89PNG\r\n\x1a\n")

        with urllib.request.urlopen(base + "/api/events/stream", timeout=5) as response:  # noqa: S310
            frame = response.read(64)
        assert frame  # the stream produces bytes immediately (state event / keepalive)
    finally:
        cockpit.shutdown()
