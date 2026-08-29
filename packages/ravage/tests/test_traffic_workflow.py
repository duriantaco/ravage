from __future__ import annotations

import json
import multiprocessing
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, ClassVar

import pytest
import ravage.__main__ as cli
import ravage.traffic.store as traffic_store_module
from ravage.__main__ import main
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.traffic.capture_runtime import CaptureSummary
from ravage.traffic.contracts import (
    CapturedHttpExchange,
    build_captured_http_exchange,
    build_replay_receipt,
)
from ravage.traffic.manifest import (
    TrafficRunError,
    TrafficRunManifest,
    read_traffic_manifest,
    resolve_workspace,
    write_traffic_manifest,
)
from ravage.traffic.recorders import BrowserExchangeRecorder, ProbeTrafficRecorder
from ravage.traffic.replay import diff_records, replay_exchange
from ravage.traffic.store import TrafficStore, TrafficStoreError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_OK_STATUS = 200
_PRIVATE_FILE_MODE = 0o600
_CAPTURED_REQUESTS = 2


class _Handler(BaseHTTPRequestHandler):
    requests: ClassVar[list[tuple[str, str, bytes]]] = []
    request_headers: ClassVar[list[dict[str, str]]] = []

    def do_GET(self) -> None:
        type(self).requests.append(("GET", self.path, b""))
        type(self).request_headers.append(
            {name.casefold(): value for name, value in self.headers.items()}
        )
        body = b'{"ok":true}'
        self.send_response(_OK_STATUS)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        type(self).requests.append(("POST", self.path, body))
        type(self).request_headers.append(
            {name.casefold(): value for name, value in self.headers.items()}
        )
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format: str, *args: object) -> None:
        del args


@pytest.fixture
def local_server() -> Iterator[str]:
    _Handler.requests = []
    _Handler.request_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _traffic_run(tmp_path: Path, target_url: str) -> tuple[Path, TrafficStore]:
    run_dir = tmp_path / "run"
    workspace = run_dir / "workspace"
    store = TrafficStore.create(workspace)
    manifest = TrafficRunManifest.create(
        target_url=target_url,
        capture_session_id="browser-test",
    )
    write_traffic_manifest(workspace, manifest.complete())
    return run_dir, store


def _write_scan_brief(path: Path, target_url: str) -> None:
    path.write_text(
        f"""engagement_id: 11111111-1111-4111-8111-111111111111
scope:
  in_scope:
    - {target_url}
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
objectives:
  - capture_flag
budget:
  max_cost_usd: 1.0
  max_runtime_min: 5
context:
  description: traffic capture integration fixture
""",
        encoding="utf-8",
    )


def _exchange(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    unresolved_slots: tuple[str, ...] = (),
) -> CapturedHttpExchange:
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return build_captured_http_exchange(
        capture_session_id="browser-test",
        source="browser",
        method=method,
        url=url,
        request_headers=headers,
        request_body=body,
        request_sent=True,
        response_status=200,
        response_final_url=url,
        response_body=b'{"captured":true}',
        scope_decision="allowed",
        unresolved_slots=unresolved_slots,
    )


def _append_exchange_process(
    workspace: str,
    index: int,
    start: Any,
    results: Any,
) -> None:
    try:
        child_store = TrafficStore.open(workspace, writable=True)  # type: ignore[arg-type]
        start.wait()
        stored = child_store.append_exchange(
            build_captured_http_exchange(
                capture_session_id="concurrent-test",
                source="probe_session",
                method="GET",
                url=f"http://127.0.0.1/item/{index}",
                request_sent=True,
                scope_decision="allowed",
            )
        )
        results.put(stored.exchange_id)
    except Exception as exc:  # noqa: BLE001 - child failure must reach parent.
        results.put(f"error:{exc}")


def test_manifest_round_trip_and_explicit_workspace_resolution(tmp_path: Path) -> None:
    run_dir, _store = _traffic_run(tmp_path, "http://127.0.0.1:4321/private?token=secret")
    workspace = resolve_workspace(run_dir)
    manifest = read_traffic_manifest(workspace)

    assert workspace == run_dir / "workspace"
    assert manifest.target_url.endswith("/private?token=%5BREDACTED%5D")
    assert "secret" not in json.dumps(manifest.to_json())
    assert (workspace / "traffic" / "run.json").stat().st_mode & 0o777 == _PRIVATE_FILE_MODE


def test_workspace_resolution_finds_nested_agent_graph_and_refuses_ambiguity(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    base_workspace = run_dir / "workspace"
    graph_workspace = base_workspace / "autonomous-route" / "agent-graph"
    TrafficStore.create(graph_workspace)
    write_traffic_manifest(
        graph_workspace,
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:4321/",
            capture_session_id="agent-graph-test",
        ).complete(),
    )

    assert resolve_workspace(run_dir) == graph_workspace.resolve()
    assert resolve_workspace(base_workspace) == graph_workspace.resolve()

    TrafficStore.create(base_workspace)
    write_traffic_manifest(
        base_workspace,
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:4321/",
            capture_session_id="base-traffic-test",
        ).complete(),
    )

    with pytest.raises(TrafficRunError, match="multiple traffic histories"):
        resolve_workspace(run_dir)
    assert resolve_workspace(graph_workspace) == graph_workspace.resolve()


def test_manifest_rejects_dynamic_scope_paths_and_refuses_external_pointer(
    tmp_path: Path,
) -> None:
    with pytest.raises(TrafficRunError, match="stable parent path"):
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:4321/app/1234",
            capture_session_id="capture-short",
            in_scope=("http://127.0.0.1:4321/app/1234",),
        )
    with pytest.raises(TrafficRunError, match="stable parent path"):
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:4321/reset/shortSecret7",
            capture_session_id="capture-short",
            in_scope=("http://127.0.0.1:4321/reset/shortSecret7",),
        )

    external_root = tmp_path / "external"
    external_run, _store = _traffic_run(external_root, "http://127.0.0.1:4321/")
    bundle = tmp_path / "untrusted-bundle"
    bundle.mkdir()
    (bundle / "run.json").write_text(
        json.dumps({"workspace_dir": str((external_run / "workspace").resolve())}),
        encoding="utf-8",
    )

    with pytest.raises(TrafficRunError, match="no traffic history"):
        resolve_workspace(bundle)

    symlink_bundle = tmp_path / "symlink-bundle"
    symlink_bundle.mkdir()
    (symlink_bundle / "workspace").symlink_to(
        external_run / "workspace",
        target_is_directory=True,
    )

    with pytest.raises(TrafficRunError, match="no traffic history"):
        resolve_workspace(symlink_bundle)

    malformed_bundle = tmp_path / "malformed-bundle"
    malformed_bundle.mkdir()
    (malformed_bundle / "run.json").write_bytes(b"\xff")
    with pytest.raises(TrafficRunError, match="no traffic history"):
        resolve_workspace(malformed_bundle)

    oversized_bundle = tmp_path / "oversized-bundle"
    oversized_bundle.mkdir()
    with (oversized_bundle / "run.json").open("wb") as handle:
        handle.truncate(262_145)
    with pytest.raises(TrafficRunError, match="no traffic history"):
        resolve_workspace(oversized_bundle)

    hostile_json_bundle = tmp_path / "hostile-json-bundle"
    hostile_json_bundle.mkdir()
    (hostile_json_bundle / "run.json").write_text(
        '{"workspace_dir":' + ("9" * 10_000) + "}",
        encoding="utf-8",
    )
    with pytest.raises(TrafficRunError, match="no traffic history"):
        resolve_workspace(hostile_json_bundle)


def test_manifest_rejects_secret_like_ids_and_symlinked_directories(tmp_path: Path) -> None:
    with pytest.raises(TrafficRunError, match="non-secret identifier"):
        TrafficRunManifest.create(
            target_url="http://127.0.0.1:4321/",
            capture_session_id="capture-0123456789abcdef0123456789abcdef",
        )

    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "traffic").symlink_to(outside, target_is_directory=True)
    manifest = TrafficRunManifest.create(
        target_url="http://127.0.0.1:4321/",
        capture_session_id="capture-short",
    )

    with pytest.raises(TrafficRunError, match="cannot be a symlink"):
        write_traffic_manifest(workspace, manifest)

    assert not list(outside.iterdir())


def test_probe_recorder_persists_only_secret_free_contracts(tmp_path: Path) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="scan-test",
        known_secrets=("very-secret-value",),
    )

    recorder(
        {
            "disposition": "sent",
            "method": "POST",
            "url": "http://127.0.0.1:8080/login?token=very-secret-value",
            "request_headers": {
                "Authorization": "Bearer very-secret-value",
                "Cookie": "session=very-secret-value",
                "Content-Type": "application/json; charset=utf-8",
            },
            "request_body": b'{"password":"very-secret-value"}',
            "response_status": 401,
            "response_url": "http://127.0.0.1:8080/login",
            "response_headers": {"Set-Cookie": "session=very-secret-value"},
            "response_body": "bad very-secret-value",
            "elapsed_ms": 3,
        }
    )

    persisted = (store.root / "exchanges.jsonl").read_text(encoding="utf-8")
    exchange = store.exchanges()[0]
    assert "very-secret-value" not in persisted
    assert exchange.request_body_field_names == ("password",)
    assert exchange.unresolved_slots == (
        "body",
        "header.authorization",
        "header.cookie",
        "query.token",
    )


def test_probe_recorder_learns_auth_cookie_before_same_response_redirect(
    tmp_path: Path,
) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(store, capture_session_id="scan-test")

    recorder(
        {
            "disposition": "sent",
            "method": "POST",
            "url": "http://127.0.0.1:8080/administrator",
            "request_headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "request_body": b"username=alice&password=secret",
            "response_status": 302,
            "response_url": "http://127.0.0.1:8080/next/abc",
            "response_headers": {
                "Set-Cookie": "sessionid=abc; Path=/\nmalformed cookie line",
                "Location": "/next/abc",
            },
            "response_body": "",
            "error": "redirect diagnostic abc",
            "elapsed_ms": 1,
        }
    )
    recorder(
        {
            "disposition": "sent",
            "method": "GET",
            "url": "http://127.0.0.1:8080/next/abc",
            "request_headers": {},
            "response_status": 200,
            "response_url": "http://127.0.0.1:8080/next/abc",
            "response_headers": {},
            "response_body": "ok",
            "elapsed_ms": 1,
        }
    )

    exchange, followup = store.exchanges()
    persisted = (store.root / "exchanges.jsonl").read_text(encoding="utf-8")
    assert exchange.request_url == "http://127.0.0.1:8080/administrator"
    assert exchange.response_final_url == "http://127.0.0.1:8080/next/:redacted"
    assert ("location", "/next/:redacted") in exchange.response_headers
    assert exchange.response_error == "redirect diagnostic [REDACTED]"
    assert "abc" not in persisted
    assert exchange.request_body_sha256 == "unavailable"
    assert followup.request_url == "http://127.0.0.1:8080/next/:redacted"
    assert followup.response_final_url == "http://127.0.0.1:8080/next/:redacted"


def test_probe_recorder_does_not_treat_short_preference_cookie_as_global_secret(
    tmp_path: Path,
) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(store, capture_session_id="scan-test")

    recorder(
        {
            "disposition": "sent",
            "method": "GET",
            "url": "http://127.0.0.1:8080/v1/administrator",
            "request_headers": {},
            "response_status": 200,
            "response_url": "http://127.0.0.1:8080/v1/administrator",
            "response_headers": {"Set-Cookie": "theme=1; Path=/"},
            "response_body": "ok",
            "elapsed_ms": 1,
        }
    )
    recorder(
        {
            "disposition": "sent",
            "method": "GET",
            "url": "http://127.0.0.1:8080/v1/administrator",
            "request_headers": {},
            "response_status": 200,
            "response_url": "http://127.0.0.1:8080/v1/administrator",
            "response_headers": {},
            "response_body": "ok",
            "elapsed_ms": 1,
        }
    )

    for exchange in store.exchanges():
        assert exchange.request_url == "http://127.0.0.1:8080/v1/administrator"
        assert exchange.response_final_url == "http://127.0.0.1:8080/v1/administrator"


def test_probe_recorder_redacts_short_configured_secret_only_as_exact_url_segment(
    tmp_path: Path,
) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(store, capture_session_id="scan-test")
    recorder.register_url_segment_secret_values(("1",))

    recorder(
        {
            "disposition": "sent",
            "method": "GET",
            "url": "http://127.0.0.1:8080/administrator",
            "request_headers": {},
            "response_status": 200,
            "response_url": "http://127.0.0.1:8080/1",
            "response_headers": {"Location": "/1"},
            "response_body": "ok",
            "elapsed_ms": 1,
        }
    )

    [exchange] = store.exchanges()
    assert exchange.request_url == "http://127.0.0.1:8080/administrator"
    assert exchange.response_final_url == "http://127.0.0.1:8080/:redacted"
    assert ("location", "/:redacted") in exchange.response_headers


def test_probe_recorder_surfaces_sanitized_persistence_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    errors: list[str] = []
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="scan-test",
        known_secrets=("TOP-SECRET",),
        error_sink=errors,
    )

    def fail_append(_exchange: CapturedHttpExchange) -> CapturedHttpExchange:
        raise TrafficStoreError("could not save token=TOP-SECRET")

    monkeypatch.setattr(store, "append_exchange", fail_append)
    recorder(
        {
            "disposition": "sent",
            "method": "GET",
            "url": "http://127.0.0.1:4321/",
            "request_headers": {},
            "response_status": 200,
            "response_url": "http://127.0.0.1:4321/",
            "response_headers": {},
            "response_body": "ok",
            "elapsed_ms": 1,
        }
    )

    assert recorder.errors == tuple(errors)
    assert errors == ["could not save token=[REDACTED]"]


def test_browser_recorder_correlates_lifecycle_to_one_store_id(tmp_path: Path) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = BrowserExchangeRecorder(store)
    common = {
        "capture_session_id": "browser-test",
        "correlation_id": "browser-test:000001",
    }
    recorder.record_browser_event(
        {
            **common,
            "event_type": "request",
            "request": {
                "method": "GET",
                "url": "http://127.0.0.1:3000/api/items",
                "resource_type": "fetch",
                "is_navigation_request": False,
                "headers": {"accept": "application/json"},
                "body": {
                    "media_type": "",
                    "byte_length": 0,
                    "sha256": "",
                    "field_names": [],
                },
            },
            "scope": {"allowed": True},
        }
    )
    recorder.record_browser_event(
        {
            **common,
            "event_type": "response",
            "response": {
                "url": "http://127.0.0.1:3000/api/items",
                "status": 200,
                "headers": {"content-type": "application/json"},
            },
            "scope": {"allowed": True},
        }
    )
    recorder.record_browser_event(
        {**common, "event_type": "requestfinished", "scope": {"allowed": True}}
    )

    assert len(store.exchanges()) == 1
    assert store.exchanges()[0].exchange_id == "rq_0001"
    assert store.exchanges()[0].source_observation_id == "browser-test:000001"
    assert store.exchanges()[0].response_body_observed is False


def test_safe_replay_sends_once_and_diff_is_offline(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(_exchange(f"{local_server}/api/health"))
    manifest = read_traffic_manifest(run_dir / "workspace")

    result = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
    )
    before_diff = list(_Handler.requests)
    difference = diff_records(store, source.exchange_id, result.receipt.replay_id)

    assert result.sent is True
    assert result.receipt.response_status == _OK_STATUS
    assert _Handler.requests == [("GET", "/api/health", b"")]
    assert _Handler.requests == before_diff
    assert difference["left"]["id"] == "rq_0001"  # type: ignore[index]
    assert difference["right"]["id"] == "rp_0002"  # type: ignore[index]
    assert [receipt.outcome for receipt in store.replay_receipts()] == [
        "dispatch_reserved",
        "response",
    ]
    assert diff_records(store, source.exchange_id, source.exchange_id)["changes"] == {}


def test_replay_preserves_plus_and_space_path_semantics(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(
        _exchange(f"{local_server}/literal+plus/encoded%2Bplus/encoded%20space")
    )

    result = replay_exchange(
        store=store,
        manifest=read_traffic_manifest(run_dir / "workspace"),
        exchange=source,
        allow_remote_target=False,
    )

    assert result.sent
    assert _Handler.requests == [
        ("GET", "/literal+plus/encoded+plus/encoded%20space", b""),
    ]


def test_replay_rejects_other_sessions_blocked_captures_and_secret_header_controls(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    manifest = read_traffic_manifest(run_dir / "workspace")
    other_session = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="other-session",
            source="probe",
            method="GET",
            url=f"{local_server}/session-mismatch",
            request_sent=True,
            scope_decision="allowed",
        )
    )
    blocked_source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url=f"{local_server}/previously-blocked",
            request_sent=False,
            scope_decision="blocked",
        )
    )
    header_source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url=f"{local_server}/header",
            request_headers={"Authorization": "[REDACTED]"},
            request_sent=True,
            scope_decision="allowed",
            unresolved_slots=("header.authorization",),
        )
    )
    secret = "Bearer TOP-SECRET\r\nX-Evil: yes"

    mismatch = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=other_session,
        allow_remote_target=False,
    )
    blocked = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=blocked_source,
        allow_remote_target=False,
    )
    invalid_header = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=header_source,
        allow_remote_target=False,
        bindings={"header.authorization": secret},
    )

    assert not mismatch.sent
    assert not blocked.sent
    assert not invalid_header.sent
    assert _Handler.requests == []
    persisted = store.replays_path.read_text(encoding="utf-8")
    assert "TOP-SECRET" not in persisted
    assert "TOP-SECRET" not in invalid_header.error


def test_state_changing_replay_requires_arm_and_all_values(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(
        _exchange(
            f"{local_server}/api/items",
            method="POST",
            body=b'{"name":"old"}',
            unresolved_slots=("body",),
        )
    )
    manifest = read_traffic_manifest(run_dir / "workspace")

    unarmed = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
        bindings={"body": '{"name":"new"}'},
    )
    missing = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
        allow_state_change=True,
    )
    armed = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
        allow_state_change=True,
        bindings={"body": '{"name":"new"}'},
    )

    assert not unarmed.sent
    assert not missing.sent
    assert armed.sent
    assert _Handler.requests == [("POST", "/api/items", b'{"name":"new"}')]


def test_content_encoded_request_body_cannot_be_replayed(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="POST",
            url=f"{local_server}/encoded",
            request_headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
            request_body=b"compressed-body",
            request_sent=True,
            scope_decision="allowed",
        )
    )

    result = replay_exchange(
        store=store,
        manifest=read_traffic_manifest(run_dir / "workspace"),
        exchange=source,
        allow_remote_target=False,
        allow_state_change=True,
        bindings={"body": "replacement"},
    )

    assert source.replayability == "not_replayable"
    assert source.unresolved_slots == ()
    assert not result.sent
    assert _Handler.requests == []


def test_replay_preserves_distinct_duplicate_query_values(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(
        _exchange(
            f"{local_server}/search?Tag=one&Tag=two",
            unresolved_slots=("query.Tag[0]", "query.Tag[1]"),
        )
    )

    result = replay_exchange(
        store=store,
        manifest=read_traffic_manifest(run_dir / "workspace"),
        exchange=source,
        allow_remote_target=False,
        bindings={"query.Tag[0]": "first", "query.Tag[1]": "second"},
    )

    assert result.sent
    assert _Handler.requests == [("GET", "/search?Tag=first&Tag=second", b"")]


def test_replay_requires_custom_headers_and_refuses_host_override(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    authority = local_server.removeprefix("http://")
    source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url=f"{local_server}/tenant",
            request_headers={"Host": authority, "X-Tenant": "tenant-a"},
            request_sent=True,
            scope_decision="allowed",
        )
    )
    overridden_host = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url=f"{local_server}/wrong-host",
            request_headers={"Host": "other-tenant.example"},
            request_sent=True,
            scope_decision="allowed",
        )
    )
    manifest = read_traffic_manifest(run_dir / "workspace")

    missing = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
    )
    sent = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
        bindings={"header.x-tenant": "tenant-b"},
    )
    refused = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=overridden_host,
        allow_remote_target=False,
    )

    assert source.unresolved_slots == ("header.x-tenant",)
    assert "host" not in dict(source.request_headers)
    assert not missing.sent
    assert sent.sent
    assert _Handler.request_headers[0]["x-tenant"] == "tenant-b"
    assert overridden_host.replayability == "not_replayable"
    assert not refused.sent
    assert len(_Handler.requests) == 1


def test_method_override_requires_state_arm_and_proxy_auth_is_never_forwarded(
    tmp_path: Path,
    local_server: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url=f"{local_server}/override",
            request_headers={
                "Proxy-Authorization": "Basic transport-secret",
                "X-HTTP-Method-Override": "DELETE",
            },
            request_sent=True,
            scope_decision="allowed",
        )
    )
    manifest = read_traffic_manifest(run_dir / "workspace")
    bindings = {"header.x-http-method-override": "DELETE"}

    unarmed = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
        bindings=bindings,
    )
    armed = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
        allow_state_change=True,
        bindings=bindings,
    )

    assert source.replayability == "requires_authorization"
    assert "header.proxy-authorization" not in source.unresolved_slots
    assert not unarmed.sent
    assert armed.sent
    assert _Handler.request_headers[0]["x-http-method-override"] == "DELETE"
    assert "proxy-authorization" not in _Handler.request_headers[0]

    for header_name in ("X-HTTP-Method", "X-Method-Override"):
        variant = build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url=f"{local_server}/variant",
            request_headers={header_name: "DELETE"},
            request_sent=True,
            scope_decision="allowed",
        )
        assert variant.replayability == "requires_authorization"

    crafted = build_captured_http_exchange(
        capture_session_id="browser-test",
        source="browser",
        method="GET",
        url=f"{local_server}/crafted",
        request_sent=True,
        scope_decision="allowed",
        unresolved_slots=("header.x-method-override",),
    )
    crafted_result = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=store.append_exchange(crafted),
        allow_remote_target=False,
        bindings={"header.x-method-override": "DELETE"},
    )
    assert crafted.unresolved_slots == ()
    assert not crafted_result.sent


@pytest.mark.parametrize(
    "header_name",
    ["X-Original-URL", "X-Original-URI", "Destination", "If"],
)
def test_routing_override_headers_are_never_replayable(
    tmp_path: Path,
    local_server: str,
    header_name: str,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url=f"{local_server}/app/request",
            request_headers={header_name: "/admin"},
            request_sent=True,
            scope_decision="allowed",
        )
    )

    result = replay_exchange(
        store=store,
        manifest=read_traffic_manifest(run_dir / "workspace"),
        exchange=source,
        allow_remote_target=False,
        bindings={f"header.{header_name.casefold()}": "/admin"},
    )

    assert source.replayability == "not_replayable"
    assert not result.sent
    assert _Handler.requests == []


def test_remote_replay_connects_only_to_the_outer_scope_dns_pin(
    tmp_path: Path,
    local_server: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = local_server.replace("127.0.0.1", "approved.example")
    run_dir, store = _traffic_run(tmp_path, target)
    source = store.append_exchange(_exchange(f"{target}/pinned"))
    monkeypatch.setattr(
        "ravage.traffic.scope._resolve_addresses",
        lambda _host, _port: ("127.0.0.1",),
    )

    def reject_fresh_resolution(_host: str, _port: int) -> tuple[str, ...]:
        message = "ProbeSession must reuse the outer approved pin"
        raise AssertionError(message)

    monkeypatch.setattr(
        "ravage.web_core.http_probe._resolve_addresses",
        reject_fresh_resolution,
    )
    result = replay_exchange(
        store=store,
        manifest=read_traffic_manifest(run_dir / "workspace"),
        exchange=source,
        allow_remote_target=True,
    )

    assert result.sent
    assert result.receipt.response_status == _OK_STATUS
    assert _Handler.requests == [("GET", "/pinned", b"")]


def test_replay_dispatch_is_journaled_before_send_and_cannot_be_retried(
    tmp_path: Path,
    local_server: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir, store = _traffic_run(tmp_path, local_server)
    source = store.append_exchange(_exchange(f"{local_server}/once"))
    manifest = read_traffic_manifest(run_dir / "workspace")
    append_replay = store.append_replay

    def fail_final_receipt(_receipt: object) -> object:
        message = "simulated final receipt failure"
        raise TrafficStoreError(message)

    monkeypatch.setattr(store, "append_replay", fail_final_receipt)
    with pytest.raises(TrafficStoreError, match="final receipt failure"):
        replay_exchange(
            store=store,
            manifest=manifest,
            exchange=source,
            allow_remote_target=False,
        )
    monkeypatch.setattr(store, "append_replay", append_replay)
    retry = replay_exchange(
        store=store,
        manifest=manifest,
        exchange=source,
        allow_remote_target=False,
    )

    assert _Handler.requests == [("GET", "/once", b"")]
    assert not retry.sent
    assert "already has durable dispatch reservation" in retry.error
    assert store.replay_receipts()[0].outcome == "dispatch_reserved"


def test_store_rejects_hardlinked_and_oversized_traffic_files(tmp_path: Path) -> None:
    linked_store = TrafficStore.create(tmp_path / "linked-workspace")
    victim = tmp_path / "victim.jsonl"
    victim.write_text("owner data\n", encoding="utf-8")
    victim.chmod(0o600)
    linked_store.replays_path.unlink()
    os.link(victim, linked_store.replays_path)

    with pytest.raises(TrafficStoreError, match="hard-linked"):
        TrafficStore.open(linked_store.workspace_dir, writable=True)
    assert victim.read_text(encoding="utf-8") == "owner data\n"

    large_store = TrafficStore.create(tmp_path / "large-workspace")
    with large_store.exchanges_path.open("r+b") as handle:
        handle.truncate((64 * 1_024 * 1_024) + 1)
    with pytest.raises(TrafficStoreError, match="64 MiB"):
        TrafficStore.open(large_store.workspace_dir)


def test_store_serializes_appends_across_processes(tmp_path: Path) -> None:
    workspace = tmp_path / "concurrent-workspace"
    TrafficStore.create(workspace)
    process_count = 4
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()

    processes = [
        context.Process(
            target=_append_exchange_process,
            args=(str(workspace), index, start, results),
        )
        for index in range(process_count)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=10)
        assert not process.is_alive()
        assert process.exitcode == 0

    identifiers = sorted(results.get(timeout=2) for _ in range(process_count))
    assert identifiers == [f"rq_{index:04d}" for index in range(1, process_count + 1)]
    assert len(TrafficStore.open(workspace).exchanges()) == process_count


def test_traffic_cli_lists_shows_and_diffs_without_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, store = _traffic_run(tmp_path, "http://127.0.0.1:4321")
    source = store.append_exchange(_exchange("http://127.0.0.1:4321/api/health"))
    receipt = store.append_replay(
        build_replay_receipt(
            source_exchange=source,
            request_sent=False,
            scope_decision="blocked",
            scope_reason="offline fixture",
            outcome="blocked",
        )
    )
    capsys.readouterr()

    main(["traffic", "list", str(run_dir), "--json"])
    listing = json.loads(capsys.readouterr().out)
    main(["traffic", "show", str(run_dir), source.exchange_id, "--json"])
    shown = json.loads(capsys.readouterr().out)
    main(
        [
            "traffic",
            "diff",
            str(run_dir),
            source.exchange_id,
            receipt.replay_id,
            "--json",
        ]
    )
    difference = json.loads(capsys.readouterr().out)

    assert listing["requests"][0]["id"] == "rq_0001"
    assert shown["exchange"]["exchange_id"] == "rq_0001"
    assert difference["right"]["id"] == "rp_0001"


def test_show_prints_a_complete_remote_mutation_replay_skeleton(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, store = _traffic_run(tmp_path, "https://staging.example.test/app")
    source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="POST",
            url="https://staging.example.test/app/items?tenant=redacted",
            request_headers={
                "Authorization": "[REDACTED]",
                "Content-Type": "application/json",
            },
            request_body=b'{"name":"old"}',
            request_sent=True,
            scope_decision="allowed",
            unresolved_slots=("query.tenant", "header.authorization", "body"),
        )
    )

    main(["traffic", "show", str(run_dir), source.exchange_id])
    output = capsys.readouterr().out

    assert "export RAVAGE_REPLAY_BODY='<fill-me>'" in output
    assert "--bind query.tenant=RAVAGE_REPLAY_QUERY_TENANT" in output
    assert "--bind header.authorization=RAVAGE_REPLAY_HEADER_AUTHORIZATION" in output
    assert "--authorized-remote-target" in output
    assert "--allow-state-change" in output


def test_show_arms_safe_method_with_state_override_header(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, store = _traffic_run(tmp_path, "http://127.0.0.1:4321")
    source = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="browser-test",
            source="browser",
            method="GET",
            url="http://127.0.0.1:4321/override",
            request_headers={"X-Method-Override": "DELETE"},
            request_sent=True,
            scope_decision="allowed",
        )
    )

    main(["traffic", "show", str(run_dir), source.exchange_id])
    output = capsys.readouterr().out

    assert source.replayability == "requires_authorization"
    assert "--allow-state-change" in output


def test_json_blocked_replay_exits_nonzero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, store = _traffic_run(tmp_path, "http://127.0.0.1:4321")
    source = store.append_exchange(
        _exchange(
            "http://127.0.0.1:4321/api?token=redacted",
            unresolved_slots=("query.token",),
        )
    )

    with pytest.raises(SystemExit) as stopped:
        main(["traffic", "replay", str(run_dir), source.exchange_id, "--json"])

    assert stopped.value.code == 2
    assert json.loads(capsys.readouterr().out)["outcome"] == "blocked"


def test_scan_writes_probe_traffic_to_the_same_contract_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    _write_scan_brief(brief, "http://127.0.0.1:4321/")

    def run_probe(probe: str, **kwargs: object) -> ProbeRunResult:
        observer = kwargs.get("traffic_observer")
        assert callable(observer)
        observer(
            {
                "disposition": "sent",
                "method": "GET",
                "url": "http://127.0.0.1:4321/api/health",
                "request_headers": {"Accept": "application/json"},
                "request_body": None,
                "response_status": 200,
                "response_url": "http://127.0.0.1:4321/api/health",
                "response_headers": {"Content-Type": "application/json"},
                "response_body": '{"ok":true}',
                "elapsed_ms": 2,
            }
        )
        return ProbeRunResult(ok=True, probe=probe, summary="captured")

    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)
    main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )
    summary = json.loads(capsys.readouterr().out)
    store = TrafficStore.open(run_dir / "workspace", writable=True)

    assert summary["traffic_requests"] == 1
    assert summary["traffic_contracts"] == 1
    assert store.exchanges()[0].request_url.endswith("/api/health")
    assert read_traffic_manifest(run_dir / "workspace").completed_at


def test_scan_continues_when_redacted_traffic_history_cannot_represent_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    _write_scan_brief(brief, "http://127.0.0.1:4321/app/1234")

    def run_probe(probe: str, **kwargs: object) -> ProbeRunResult:
        assert kwargs.get("traffic_observer") is None
        return ProbeRunResult(ok=True, probe=probe, summary="scan still ran")

    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)
    main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )
    summary = json.loads(capsys.readouterr().out)

    assert summary["probes_run"] == 1
    assert summary["traffic_requests"] == 0
    assert summary["traffic_contracts"] == 0
    assert summary["traffic_recorder_errors"] == [
        "traffic history was disabled because its private store or redacted "
        "scope manifest could not be initialized"
    ]
    assert not (run_dir / "workspace" / "traffic").exists()


def test_scan_continues_when_traffic_store_setup_raises_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    _write_scan_brief(brief, "http://127.0.0.1:4321/")

    def fail_store_setup(*_args: object, **_kwargs: object) -> TrafficStore:
        raise OSError("raw filesystem detail")

    def run_probe(probe: str, **kwargs: object) -> ProbeRunResult:
        assert kwargs.get("traffic_observer") is None
        return ProbeRunResult(ok=True, probe=probe, summary="scan still ran")

    monkeypatch.setattr(cli.TrafficStore, "create", fail_store_setup)
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)
    main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )
    output = capsys.readouterr().out
    summary = json.loads(output)

    assert summary["probes_run"] == 1
    assert summary["traffic_requests"] == 0
    assert summary["traffic_contracts"] == 0
    assert len(summary["traffic_recorder_errors"]) == 1
    assert "raw filesystem detail" not in output


def test_scan_continues_when_traffic_completion_write_raises_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    _write_scan_brief(brief, "http://127.0.0.1:4321/")
    ordinary_write = cli.write_traffic_manifest

    def fail_completion_write(
        workspace_dir: Path,
        manifest: TrafficRunManifest,
    ) -> Path:
        if manifest.completed_at:
            raise OSError("raw completion detail")
        return ordinary_write(workspace_dir, manifest)

    def run_probe(probe: str, **_kwargs: object) -> ProbeRunResult:
        return ProbeRunResult(ok=True, probe=probe, summary="scan still ran")

    monkeypatch.setattr(cli, "write_traffic_manifest", fail_completion_write)
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)
    main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )
    output = capsys.readouterr().out
    summary = json.loads(output)

    assert summary["probes_run"] == 1
    assert summary["traffic_recorder_errors"] == [
        "traffic history was recorded but its completion metadata could not be saved"
    ]
    assert "raw completion detail" not in output


def test_native_windows_traffic_store_fails_with_an_actionable_wsl_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(traffic_store_module.os, "name", "nt")

    with pytest.raises(TrafficStoreError, match="Windows, use WSL"):
        TrafficStore.create(tmp_path / "workspace")


def test_traffic_capture_cli_passes_the_operator_safety_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "capture-run"
    received: dict[str, object] = {}

    def capture(**kwargs: object) -> CaptureSummary:
        received.update(kwargs)
        return CaptureSummary(
            run_dir=run_dir,
            workspace_dir=run_dir / "workspace",
            captured=_CAPTURED_REQUESTS,
            blocked=1,
            contracts=2,
            interrupted=False,
            recorder_errors=(),
        )

    monkeypatch.setattr(
        "ravage.traffic.capture_runtime.capture_browser_traffic",
        capture,
    )
    main(
        [
            "traffic",
            "capture",
            "https://staging.example.test/app",
            "--run-dir",
            str(run_dir),
            "--authorized-remote-target",
            "--headless",
            "--duration",
            "1",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert received["allow_remote_target"] is True
    assert received["headless"] is True
    assert received["duration_seconds"] == 1.0
    assert output["captured"] == _CAPTURED_REQUESTS
    assert output["blocked"] == 1


def test_traffic_capture_cli_reports_ctrl_c_as_partial_and_exits_130(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "capture-run"

    monkeypatch.setattr(
        "ravage.traffic.capture_runtime.capture_browser_traffic",
        lambda **_kwargs: CaptureSummary(
            run_dir=run_dir,
            workspace_dir=run_dir / "workspace",
            captured=1,
            blocked=0,
            contracts=1,
            interrupted=True,
            recorder_errors=(),
        ),
    )

    with pytest.raises(SystemExit) as stopped:
        main(["traffic", "capture", "http://127.0.0.1:4321", "--run-dir", str(run_dir)])

    output = capsys.readouterr().out
    assert stopped.value.code == 130
    assert "capture:partial" in output
    assert "capture:done" not in output
