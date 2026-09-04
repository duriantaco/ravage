# ruff: noqa: PLR2004

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from typing import TYPE_CHECKING
from urllib.parse import parse_qs
from uuid import uuid4

import pytest
from ai_agent_fixtures import BRIEF_YAML, ScriptedModelClient
from pentest_schemas import Scope
from ravage.agent_core import ai_agent
from ravage.agent_core.action_executor import execute_action
from ravage.agent_core.action_parser import parse_action
from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.agent_core.agent_strategy import action_fingerprint
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _update_state_from_action,
    run_ai_web_agent,
)
from ravage.agent_core.autonomous_graph.scoped_http import ScopedGraphHttpExecutor
from ravage.agent_core.stateful_http import StatefulHttpActionSession
from ravage.probes.specialists.shared import _generic_input_targets
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import NoProcessToolRuntime
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyMode,
)
from ravage.traffic.store import TrafficStore

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_FAKE_REQUEST_PROOF = "flag{request_payload_is_not_target_evidence_42a8}"
_FORGED_VALIDATOR_PROOF = "flag{validator_expectation_forgery_73c9}"
_LATE_RESPONSE_PROOF = "flag{late_persistent_validator_proof_91c7}"


@dataclass(frozen=True)
class _HttpTarget:
    url: str
    requests: list[dict[str, object]]


@pytest.fixture
def stateful_http_target() -> Iterator[_HttpTarget]:  # noqa: C901
    requests: list[dict[str, object]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "cookie": self.headers.get("Cookie", ""),
                    "form": parse_qs(body.decode()),
                }
            )
            if self.path == "/login":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Set-Cookie", "session=persistent; Path=/; HttpOnly")
                self.send_header("Content-Length", str(len(b"session established")))
                self.end_headers()
                self.wfile.write(b"session established")
                return
            if self.path == "/rotate":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Set-Cookie", "session=rotated; Path=/; HttpOnly")
                self.send_header("Content-Length", str(len(b"session rotated")))
                self.end_headers()
                self.wfile.write(b"session rotated")
                return
            if self.path == "/reflect-form":
                self._respond(
                    200,
                    (
                        b'<html><form method="post" action="/poisoned">'
                        b'<input name="fabricated_field" value="attacker-controlled">'
                        b"</form></html>"
                    ),
                )
                return
            self._respond(404, b"not found")

        def do_GET(self) -> None:
            cookie = self.headers.get("Cookie", "")
            requests.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "cookie": cookie,
                }
            )
            if self.path == "/redirect-outside":
                self._redirect(
                    "https://outside.example/private?token=redirect-secret-value"
                )
                return
            if self.path.startswith("/redirect-loop"):
                self._redirect("/redirect-loop?token=redirect-secret-value")
                return
            if self.path == "/dashboard":
                body = (
                    b"authenticated dashboard"
                    if "session=persistent" in cookie
                    else b"public login shell"
                )
                self._respond(200, body)
                return
            if self.path.startswith("/reflect"):
                self._respond(200, b"hello {{7*7}} response 49")
                return
            if self.path == "/long-proof":
                self._respond(200, (b"x" * 340) + b"\n" + _LATE_RESPONSE_PROOF.encode())
                return
            if self.path == "/form":
                self._respond(
                    200,
                    (
                        b'<html><form method="post" action="/generate">'
                        b'<input name="sentence" value="not-retained">'
                        b'<input type="hidden" name="csrf_token" value="secret">'
                        b"</form></html>"
                    ),
                )
                return
            if self.path == "/private" and "session=persistent" in cookie:
                self._respond(200, b"authenticated follow-up")
                return
            self._respond(401, b"authentication required")

        def _respond(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield _HttpTarget(url=f"http://{host}:{port}/", requests=requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_parser_validates_structured_http_request_shape() -> None:
    valid = parse_action(
        json.dumps(
            {
                "action": "http_request",
                "task_id": "authenticated-follow-up",
                "method": "POST",
                "path": "/login",
                "headers": {"Accept": "text/plain"},
                "form": {"username": "user", "password": "pass"},
            }
        )
    )

    assert valid["action"] == "http_request"
    assert valid["method"] == "POST"
    assert valid["path"] == "/login"
    assert valid["form"] == {"username": "user", "password": "pass"}


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({"action": "http_request", "method": "GET"}, "requires url or path"),
        (
            {"action": "http_request", "method": "DELETE", "path": "/item"},
            "method is not allowed",
        ),
        (
            {
                "action": "http_request",
                "method": "POST",
                "path": "/item",
                "body": "raw",
                "json": {"value": "json"},
            },
            "accepts only one",
        ),
        (
            {
                "action": "http_request",
                "method": "GET",
                "path": "/item",
                "form": {"value": "body"},
            },
            "cannot include a body",
        ),
        (
            {
                "action": "http_request",
                "method": "POST",
                "path": "/item",
                "headers": ["X-Test: invalid-shape"],
            },
            "headers must be an object",
        ),
    ],
)
def test_parser_rejects_invalid_structured_http_requests(
    payload: dict[str, object],
    error: str,
) -> None:
    parsed = parse_action(json.dumps(payload))

    assert parsed["action"] == "invalid"
    assert error in str(parsed["error"])


def test_http_fingerprint_uses_dispatch_material_not_mutable_notes() -> None:
    request = {
        "action": "http_request",
        "method": "POST",
        "path": "/generate",
        "form": {"sentence": "<%= 7 * 7 %>"},
        "notes": "first explanation",
    }

    same_dispatch = {**request, "notes": "rewritten explanation", "task_id": "other"}
    changed_dispatch = {**request, "form": {"sentence": "<%= 8 * 8 %>"}}

    assert action_fingerprint(request) == action_fingerprint(same_dispatch)
    assert action_fingerprint(request) != action_fingerprint(changed_dispatch)


def test_http_action_memory_retains_replay_shape_without_values() -> None:
    state = AgentState()
    action = {
        "action": "http_request",
        "method": "POST",
        "url": "https://target.example/search?q=private-search-value",
        "headers": {
            "Authorization": "Bearer private-token",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "form": {"query": "private-body-value", "submit": "Search"},
    }

    _update_state_from_action(
        state,
        action=action,
        outcome={"ok": True, "outcome": "http_response_observed"},
    )

    serialized = json.dumps(state.actions)
    assert "private-search-value" not in serialized
    assert "private-token" not in serialized
    assert "private-body-value" not in serialized
    shape = state.actions[-1]["request_shape"]
    assert shape == {
        "method": "POST",
        "url_shape": "https://target.example/search?q",
        "body_encoding": "form",
        "field_names": ["query", "submit"],
        "header_names": ["authorization", "content-type"],
        "values_retained": False,
    }


def test_http_action_memory_recognizes_json_array_without_retaining_values() -> None:
    state = AgentState()
    action = {
        "action": "http_request",
        "method": "POST",
        "path": "/batch",
        "json": [{"secret": "private-list-value"}],
    }

    _update_state_from_action(
        state,
        action=action,
        outcome={"ok": True, "outcome": "http_response_observed"},
    )

    serialized = json.dumps(state.actions)
    assert "private-list-value" not in serialized
    assert state.actions[-1]["request_shape"] == {
        "method": "POST",
        "url_shape": "/batch",
        "body_encoding": "json",
        "field_names": [],
        "header_names": [],
        "values_retained": False,
    }


@pytest.mark.parametrize(
    ("content_type", "body", "encoding", "field_names", "secret"),
    [
        (
            "application/x-www-form-urlencoded; charset=utf-8",
            "query=private-form-value&submit=Search",
            "form",
            ["query", "submit"],
            "private-form-value",
        ),
        (
            "application/problem+json",
            '{"query":"private-json-value"}',
            "json",
            ["query"],
            "private-json-value",
        ),
    ],
)
def test_http_action_memory_recovers_safe_fields_from_typed_raw_body(
    content_type: str,
    body: str,
    encoding: str,
    field_names: list[str],
    secret: str,
) -> None:
    state = AgentState()

    _update_state_from_action(
        state,
        action={
            "action": "http_request",
            "method": "POST",
            "path": "/submit",
            "headers": {"Content-Type": content_type},
            "body": body,
        },
        outcome={"ok": True, "outcome": "http_response_observed"},
    )

    serialized = json.dumps(state.actions)
    assert secret not in serialized
    shape = state.actions[-1]["request_shape"]
    assert isinstance(shape, dict)
    assert shape["body_encoding"] == encoding
    assert shape["field_names"] == field_names


def test_validate_poc_memory_persists_ordered_secret_free_request_shapes() -> None:
    state = AgentState()

    _update_state_from_action(
        state,
        action={
            "action": "validate_poc",
            "steps": [
                {
                    "method": "POST",
                    "path": "/search?q=private-query-value",
                    "form": {"sentence": "private-form-value"},
                },
                {
                    "method": "PATCH",
                    "url": "https://target.example/items/7?mode=private-mode",
                    "headers": {
                        "Authorization": "Bearer private-token",
                        "Content-Type": "application/json",
                    },
                    "body": '{"title":"private-json-value"}',
                },
            ],
        },
        outcome={"ok": False, "outcome": "blocked"},
    )

    serialized = json.dumps(state.to_json())
    for secret in (
        "private-query-value",
        "private-form-value",
        "private-mode",
        "private-token",
        "private-json-value",
    ):
        assert secret not in serialized
    shapes = state.actions[-1]["request_shapes"]
    assert shapes == [
        {
            "method": "POST",
            "url_shape": "/search?q",
            "body_encoding": "form",
            "field_names": ["sentence"],
            "header_names": [],
            "values_retained": False,
        },
        {
            "method": "PATCH",
            "url_shape": "https://target.example/items/7?mode",
            "body_encoding": "json",
            "field_names": ["title"],
            "header_names": ["authorization", "content-type"],
            "values_retained": False,
        },
    ]
    restored = AgentState.from_json(state.to_json())
    assert restored.actions[-1]["request_shapes"] == shapes


def test_same_name_cookie_rotation_reactivates_lead_without_advancing_repeat_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    state = AgentState()
    session = StatefulHttpActionSession(
        target_url=target_url,
        scope=Scope(in_scope=[target_url], out_of_scope=[]),
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=state,
    )
    reactivations: list[AgentState] = []
    monkeypatch.setattr(
        "ravage.agent_core.stateful_http.reactivate_for_session_change",
        reactivations.append,
    )
    try:
        session(
            node_id="base-agent",
            arguments={"method": "POST", "url": "/login", "form": {}},
            action_id="login",
        )
        epoch_after_login = state.surface["http_state_epoch"]
        reactivations.clear()

        session(
            node_id="base-agent",
            arguments={"method": "POST", "url": "/rotate", "form": {}},
            action_id="rotate",
        )
    finally:
        session.finalize()

    assert state.surface["http_state_epoch"] == epoch_after_login
    assert reactivations == [state]


def test_direct_http_reuses_cookie_and_links_traffic_evidence(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
        proof_recognition_enabled=True,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    engagement_id = uuid4()
    try:
        login = execute_action(
            {
                "action": "http_request",
                "task_id": "authenticated-follow-up",
                "method": "POST",
                "path": "/login",
                "form": {"username": _FAKE_REQUEST_PROOF, "password": "pass"},
            },
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            proof_recognition_enabled=True,
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="direct-login",
            http_executor=http_session,
        )
        private = execute_action(
            {
                "action": "http_request",
                "task_id": "authenticated-follow-up",
                "method": "GET",
                "path": "/private",
            },
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            proof_recognition_enabled=True,
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="direct-private",
            http_executor=http_session,
        )
        terminal = http_session.finalize()
    finally:
        audit.close()

    assert login.ok is True
    assert login.flag == ""
    assert login.stop is False
    assert private.ok is True
    assert private.flag == ""
    assert private.stop is False
    assert json.loads(private.evidence_observation)["response"]["body"] == (
        "authenticated follow-up"
    )
    assert state.flags == []
    assert all(
        _FAKE_REQUEST_PROOF not in value for values in state.signals.values() for value in values
    )
    assert stateful_http_target.requests == [
        {
            "method": "POST",
            "path": "/login",
            "cookie": "",
            "form": {"username": [_FAKE_REQUEST_PROOF], "password": ["pass"]},
        },
        {
            "method": "GET",
            "path": "/private",
            "cookie": "session=persistent",
        },
    ]

    assert terminal is not None
    assert terminal.agent_http_exchange_count == 2
    assert terminal.manifest_completed is True
    http_state = json.loads((workspace.root / "agent-http-state.json").read_text())
    assert http_state["request_count"] == 2

    exchanges = TrafficStore.open(workspace.root).exchanges()
    assert len(exchanges) == 2
    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    http_events = [event for event in events if event["kind"] == "tool_http_request"]
    assert len(http_events) == 2
    for event, exchange in zip(http_events, exchanges, strict=True):
        payload = event["payload"]
        assert payload["observation_id"] == exchange.source_observation_id
        assert payload["recognized_proofs"] == []
        evidence = json.loads(payload["result"])
        assert evidence["traffic_exchange_ids"] == [exchange.exchange_id]
        assert all(
            receipt["request_body_sha256"] == "unavailable"
            for receipt in evidence["requests"]
        )
    assert _FAKE_REQUEST_PROOF not in (workspace.root / "traffic" / "exchanges.jsonl").read_text()

    blackboard = json.loads((workspace.root / "evidence-blackboard.json").read_text())
    raw_records = [
        record for record in blackboard["records"] if record["kind"] == "raw_observation"
    ]
    assert {record["observation_id"] for record in raw_records} == {
        exchange.source_observation_id for exchange in exchanges
    }
    assert all(record["source"] == "tool_http_request" for record in raw_records)
    assert all(record["kind"] != "proof_confirmed" for record in blackboard["records"])


def test_resume_releases_nonpersisted_session_and_clears_durable_marker(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    initial = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=state,
    )

    execution = initial(
        node_id="initial-http",
        arguments={"method": "GET", "path": "/public"},
        action_id="initial-http-action",
    )
    assert execution.result.ok is True
    initial.finalize()
    assert state.surface["http_session_dirty"] is True
    persisted_before = json.loads(
        (workspace.root / "agent-http-state.json").read_text(encoding="utf-8")
    )
    assert persisted_before["session_dirty"] is True

    resumed = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=state,
        resume_expected=True,
    )
    try:
        assert resumed.opened is True
        assert "http_session_dirty" not in state.surface
        assert state.surface["http_state_epoch"] == 1
        assert any("session was reset on resume" in fact for fact in state.facts)
        persisted_after = json.loads(
            (workspace.root / "agent-http-state.json").read_text(encoding="utf-8")
        )
        assert persisted_after["session_dirty"] is False
    finally:
        resumed.finalize()


@pytest.mark.parametrize(
    ("path", "expected_request_count"),
    [
        ("/redirect-outside", 1),
        ("/redirect-loop", 5),
    ],
)
def test_redirect_policy_failure_closes_evidence_transaction_and_can_resume(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
    path: str,
    expected_request_count: int,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    initial = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    try:
        outcome = execute_action(
            {"action": "http_request", "method": "GET", "path": path},
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="redirect-policy-failure",
            http_executor=initial,
        )
        terminal = initial.finalize()
    finally:
        audit.close()

    assert outcome.ok is False
    assert outcome.outcome == "blocked"
    assert terminal is not None
    assert terminal.agent_http_exchange_count == expected_request_count
    assert len(stateful_http_target.requests) == expected_request_count
    http_state = json.loads(
        (workspace.root / "agent-http-state.json").read_text(encoding="utf-8")
    )
    assert http_state["request_count"] == expected_request_count
    exchanges = TrafficStore.open(workspace.root).exchanges()
    assert len(exchanges) == expected_request_count
    observation_ids = {item.source_observation_id for item in exchanges}
    assert len(observation_ids) == 1
    assert "" not in observation_ids

    blackboard_text = (workspace.root / "evidence-blackboard.json").read_text(
        encoding="utf-8"
    )
    blackboard = json.loads(blackboard_text)
    raw_records = [
        record
        for record in blackboard["records"]
        if record["kind"] == "raw_observation"
        and record["source"] == "tool_http_request"
    ]
    assert len(raw_records) == 1
    assert raw_records[0]["observation_id"] in observation_ids
    assert raw_records[0]["material"] is False
    assert raw_records[0]["payload"]["ok"] is False
    assert raw_records[0]["payload"]["outcome"] == "http_request_interrupted"
    assert "redirect-secret-value" not in blackboard_text
    assert "redirect-secret-value" not in workspace.events_path.read_text(encoding="utf-8")

    resumed = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
        resume_expected=True,
    )
    try:
        assert resumed.opened is True
        resumed_state = json.loads(
            (workspace.root / "agent-http-state.json").read_text(encoding="utf-8")
        )
        assert resumed_state["request_count"] == expected_request_count
    finally:
        resumed.finalize()

    assert len(stateful_http_target.requests) == expected_request_count


def test_transport_interrupt_closes_request_traffic_evidence_transaction(
    tmp_path: Path,
) -> None:
    target_url = "http://127.0.0.1:8765"
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    initial = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=state,
    )

    class InterruptingTransport:
        @staticmethod
        def send(_request: object) -> None:
            raise KeyboardInterrupt

    executor = initial._open()  # noqa: SLF001
    executor.transport = InterruptingTransport()
    with pytest.raises(KeyboardInterrupt):
        initial(
            node_id="interrupted-http",
            arguments={"method": "GET", "path": "/interrupted"},
            action_id="interrupted-http",
        )
    terminal = initial.finalize()

    assert terminal is not None
    assert terminal.agent_http_exchange_count == 1
    http_state = json.loads(
        (workspace.root / "agent-http-state.json").read_text(encoding="utf-8")
    )
    assert http_state["request_count"] == 1
    [exchange] = TrafficStore.open(workspace.root).exchanges()
    assert exchange.request_sent is True
    assert exchange.response_status is None
    assert exchange.response_error == "KeyboardInterrupt:transport dispatch interrupted"
    blackboard = json.loads(
        (workspace.root / "evidence-blackboard.json").read_text(encoding="utf-8")
    )
    raw_records = [
        record
        for record in blackboard["records"]
        if record["kind"] == "raw_observation"
        and record["source"] == "tool_http_request"
    ]
    assert len(raw_records) == 1
    assert raw_records[0]["observation_id"] == exchange.source_observation_id
    assert raw_records[0]["payload"]["outcome"] == "http_request_interrupted"

    resumed = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=state,
        resume_expected=True,
    )
    try:
        assert resumed.opened is True
        resumed_state = json.loads(
            (workspace.root / "agent-http-state.json").read_text(encoding="utf-8")
        )
        assert resumed_state["request_count"] == 1
    finally:
        resumed.finalize()


def test_failed_fresh_lane_initialization_rolls_back_partial_artifacts(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url

    class FailingExecutor:
        def __init__(self, **_kwargs: object) -> None:
            message = "injected executor initialization failure"
            raise RuntimeError(message)

    monkeypatch.setattr(
        "ravage.agent_core.stateful_http.ScopedGraphHttpExecutor",
        FailingExecutor,
    )
    session = StatefulHttpActionSession(
        target_url=target_url,
        scope=Scope(in_scope=[target_url], out_of_scope=[]),
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=AgentState(),
    )

    with pytest.raises(RuntimeError, match="injected executor initialization failure"):
        session._open()  # noqa: SLF001

    assert not (workspace.root / "agent-http-state.json").exists()
    assert not (workspace.root / "evidence-blackboard.json").exists()
    assert not (workspace.root / "traffic").exists()


def test_failed_resumed_evidence_validation_closes_opened_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = "http://127.0.0.1:8765"
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    initial = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=state,
    )
    initial._open()  # noqa: SLF001
    initial.finalize()

    finalize_calls: list[StatefulHttpActionSession] = []
    ordinary_finalize = StatefulHttpActionSession.finalize

    def recording_finalize(
        session: StatefulHttpActionSession,
    ) -> object:
        finalize_calls.append(session)
        return ordinary_finalize(session)

    def fail_validation(
        _session: StatefulHttpActionSession,
        _traffic: object,
    ) -> None:
        raise RuntimeError("injected resumed evidence failure")

    monkeypatch.setattr(StatefulHttpActionSession, "finalize", recording_finalize)
    monkeypatch.setattr(
        StatefulHttpActionSession,
        "_validate_resumed_evidence",
        fail_validation,
    )

    with pytest.raises(RuntimeError, match="injected resumed evidence failure"):
        StatefulHttpActionSession(
            target_url=target_url,
            scope=scope,
            allow_remote_target=False,
            roe_max_rps=100,
            max_total_requests=5,
            workspace_dir=workspace.root,
            state=state,
            resume_expected=True,
        )

    assert len(finalize_calls) == 1


def test_failed_resumed_session_marker_persistence_closes_opened_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = "http://127.0.0.1:8765"
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    initial = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=workspace.root,
        state=state,
    )
    executor = initial._open()  # noqa: SLF001
    executor.mark_session_dirty()
    initial.finalize()

    finalize_calls: list[StatefulHttpActionSession] = []
    ordinary_finalize = StatefulHttpActionSession.finalize

    def recording_finalize(
        session: StatefulHttpActionSession,
    ) -> object:
        finalize_calls.append(session)
        return ordinary_finalize(session)

    def fail_clear(_executor: ScopedGraphHttpExecutor) -> None:
        raise OSError("injected session marker persistence failure")

    monkeypatch.setattr(StatefulHttpActionSession, "finalize", recording_finalize)
    monkeypatch.setattr(ScopedGraphHttpExecutor, "clear_session_dirty", fail_clear)

    with pytest.raises(OSError, match="injected session marker persistence failure"):
        StatefulHttpActionSession(
            target_url=target_url,
            scope=scope,
            allow_remote_target=False,
            roe_max_rps=100,
            max_total_requests=5,
            workspace_dir=workspace.root,
            state=state,
            resume_expected=True,
        )

    assert len(finalize_calls) == 1


def test_http_finalizer_preserves_first_failure_and_reports_later_cleanup(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class FailingExecutor:
        def close(self) -> None:
            calls.append("executor")
            raise RuntimeError("executor-close-primary")

    class FailingTraffic:
        def finalize(self) -> None:
            calls.append("traffic")
            raise ValueError("traffic-finalize-secondary")

    session = StatefulHttpActionSession(
        target_url="http://127.0.0.1:8765",
        scope=Scope(in_scope=["http://127.0.0.1:8765"], out_of_scope=[]),
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=5,
        workspace_dir=tmp_path,
        state=AgentState(),
    )
    session._executor = FailingExecutor()  # type: ignore[assignment]  # noqa: SLF001
    session._traffic = FailingTraffic()  # type: ignore[assignment]  # noqa: SLF001

    with pytest.raises(RuntimeError, match="executor-close-primary") as error:
        session.finalize()

    assert calls == ["executor", "traffic"]
    assert any(
        "traffic finalization also failed: ValueError" in note
        for note in getattr(error.value, "__notes__", ())
    )


def test_http_last_observation_keeps_only_response_metadata(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    try:
        outcome = execute_action(
            {
                "action": "http_request",
                "method": "POST",
                "path": "/login",
                "form": {"username": _FAKE_REQUEST_PROOF, "password": "pass"},
            },
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="response-memory",
            http_executor=http_session,
        )
    finally:
        http_session.finalize()
        audit.close()

    assert outcome.ok is True
    response = state.last_observation["http_response"]
    assert isinstance(response, dict)
    assert response["status"] == 200
    assert response["final_url"] == f"{target_url}login"
    assert response["truncated"] is False
    assert response["error"] == ""
    headers = {str(name).casefold(): value for name, value in response["headers"].items()}
    assert headers["content-type"] == "text/plain"
    assert "session=persistent" not in str(headers["set-cookie"])
    assert _FAKE_REQUEST_PROOF not in json.dumps(state.last_observation)
    assert "username" not in json.dumps(state.last_observation)


def test_clean_get_retains_passive_form_as_canonical_request_template(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    try:
        outcome = execute_action(
            {
                "action": "http_request",
                "method": "GET",
                "path": "/form",
            },
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="passive-form-discovery",
            http_executor=http_session,
        )
    finally:
        http_session.finalize()
        audit.close()

    assert outcome.ok is True
    expected_url = f"{target_url}generate"
    assert {
        "source": "surface_graph",
        "method": "POST",
        "url": expected_url,
        "fields": {"csrf_token": "", "sentence": ""},
    } in state.surface["request_templates"]
    discovered = [
        operation
        for operation in (state.surface_graph.operations or {}).values()
        if operation.method == "POST" and operation.structural_url == expected_url
    ]
    assert len(discovered) == 1
    assert any(
        observation.operation_id == discovered[0].operation_id
        and observation.access_level == "declared"
        and observation.response_status is None
        for observation in (state.surface_graph.observations or {}).values()
    )
    assert {(item.location, item.name) for item in discovered[0].parameters} == {
        ("form", "csrf_token"),
        ("form", "sentence"),
    }
    [first_target, *_rest] = _generic_input_targets(state, limit=4)
    assert first_target["kind"] == "form"
    assert first_target["url"] == expected_url
    assert first_target["input"] == "sentence"
    assert first_target["authority"] == "target_observed"
    serialized = json.dumps(state.surface_graph.to_json(), sort_keys=True)
    assert "not-retained" not in serialized
    assert '"secret"' not in serialized


def test_mutated_response_cannot_poison_signals_or_surface_templates(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    try:
        outcome = execute_action(
            {
                "action": "http_request",
                "method": "POST",
                "path": "/reflect-form",
                "form": {"echo": "attacker-controlled"},
            },
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="mutated-form-reflection",
            http_executor=http_session,
        )
    finally:
        http_session.finalize()
        audit.close()

    assert outcome.ok is True
    poisoned_url = f"{target_url}poisoned"
    assert all(
        template.get("url") != poisoned_url
        for template in state.surface.get("request_templates", [])
    )
    assert all(
        operation.structural_url != poisoned_url
        for operation in (state.surface_graph.operations or {}).values()
    )
    assert "fabricated_field" not in state.signals.get("parameters", [])
    assert all("/poisoned" not in value for value in state.signals.get("endpoints", []))
    assert all("/poisoned" not in value for value in state.signals.get("forms", []))


def test_cookie_transition_makes_same_get_fresh_in_agent_repeat_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stateful_http_target: _HttpTarget,
) -> None:
    monkeypatch.setattr(ai_agent, "_seed_recon", lambda **_kwargs: None)
    monkeypatch.setattr(ai_agent, "refresh_mission_board", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ai_agent, "_forced_evidence_probe_action", lambda **_kwargs: None)
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        (
            f'engagement_id: "{uuid4()}"\n'
            "scope:\n"
            "  in_scope:\n"
            f'    - "{stateful_http_target.url}"\n'
            "  out_of_scope: []\n"
            "roe:\n"
            "  max_rps: 100\n"
            "  no_destructive_actions: true\n"
            '  data_handling: "placeholders_only"\n'
            "objectives:\n"
            '  - "web_application_assessment"\n'
            "budget:\n"
            "  max_cost_usd: 1.0\n"
            "  max_runtime_min: 10\n"
        ),
        encoding="utf-8",
    )
    dashboard = {
        "action": "http_request",
        "task_id": "stateful-session",
        "method": "GET",
        "path": "/dashboard",
    }
    model = ScriptedModelClient(
        [
            dashboard,
            {
                "action": "http_request",
                "task_id": "stateful-session",
                "method": "POST",
                "path": "/login",
                "form": {"username": "user", "password": "pass"},
            },
            dashboard,
            {"action": "final", "summary": "session replay complete"},
        ]
    )
    workspace_dir = tmp_path / "workspace"

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=stateful_http_target.url,
        settings=AIWebAgentSettings(
            tool_runtime_mode="host",
            tool_runtime=NoProcessToolRuntime(),
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace_dir,
            model_client=model,
            stdout=StringIO(),
            max_turns=4,
        ),
    )

    events = [
        json.loads(line)
        for line in (workspace_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    selections = [
        event["payload"] for event in events if event["kind"] == "agent_action_selected"
    ]
    http_selections = [
        item for item in selections if item["action"]["action"] == "http_request"
    ]
    assert [item["repeat_count"] for item in http_selections] == [1, 1, 1]
    assert http_selections[0]["action"]["path"] == "/dashboard"
    assert http_selections[2]["action"]["path"] == "/dashboard"
    assert stateful_http_target.requests == [
        {"method": "GET", "path": "/dashboard", "cookie": ""},
        {
            "method": "POST",
            "path": "/login",
            "cookie": "",
            "form": {"username": ["user"], "password": ["pass"]},
        },
        {
            "method": "GET",
            "path": "/dashboard",
            "cookie": "session=persistent",
        },
    ]
    saved = json.loads((workspace_dir / "working_state.json").read_text(encoding="utf-8"))
    assert saved["state"]["surface"]["http_state_epoch"] == 1


def test_default_structured_http_ceiling_is_independent_of_max_turns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ceilings: list[int] = []

    class RecordingHttpSession:
        def __init__(self, **kwargs: object) -> None:
            ceilings.append(int(kwargs["max_total_requests"]))

        def finalize(self) -> None:
            return None

    monkeypatch.setattr(ai_agent, "_seed_recon", lambda **_kwargs: None)
    monkeypatch.setattr(ai_agent, "refresh_mission_board", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ai_agent, "StatefulHttpActionSession", RecordingHttpSession)
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")

    for max_turns in (1, 73):
        run_ai_web_agent(
            brief_path=brief_path,
            target_url="http://127.0.0.1:8765",
            settings=AIWebAgentSettings(
                tool_runtime_mode="host",
                tool_runtime=NoProcessToolRuntime(),
                db_path=tmp_path / f"audit-{max_turns}.db",
                workspace_dir=tmp_path / f"workspace-{max_turns}",
                model_client=ScriptedModelClient(
                    [{"action": "final", "summary": "setup captured"}]
                ),
                stdout=StringIO(),
                max_turns=max_turns,
            ),
        )

    assert ceilings == [10_000, 10_000]


def test_partial_http_resume_closes_owned_runtime_before_raising(tmp_path: Path) -> None:
    target_url = "http://127.0.0.1:8765"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    state_path = workspace_dir / "working_state.json"
    save_agent_state(state_path, target_url=target_url, state=AgentState())
    TrafficPolicyController.open(
        workspace_dir / "traffic-policy.json",
        target_url=target_url,
        config=TrafficPolicyConfig(mode=TrafficPolicyMode.OBSERVE),
    )
    # Deliberately interrupted lane: request state exists, while its traffic
    # history and evidence ledger do not.
    (workspace_dir / "agent-http-state.json").write_text("{}\n", encoding="utf-8")

    class ClosingRuntime:
        def __init__(self) -> None:
            self.close_count = 0

        def close(self) -> None:
            self.close_count += 1

    runtime = ClosingRuntime()
    with pytest.raises(
        RuntimeError,
        match="structured HTTP resume requires request state, traffic history, and evidence",
    ):
        run_ai_web_agent(
            brief_path=brief_path,
            target_url=target_url,
            settings=AIWebAgentSettings(
                workspace_dir=workspace_dir,
                resume_from=state_path,
                tool_runtime=runtime,
                tool_runtime_mode="host",
                model_client=object(),
                stdout=StringIO(),
            ),
        )

    assert runtime.close_count == 1


def test_startup_validation_failure_finalizes_all_open_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = "http://127.0.0.1:8765"
    workspace_dir = tmp_path / "workspace"
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")

    class ClosingRuntime:
        def __init__(self) -> None:
            self.close_count = 0

        def close(self) -> None:
            self.close_count += 1

    class ClosingHttpSession:
        def __init__(self, **_kwargs: object) -> None:
            self.finalize_count = 0
            sessions.append(self)

        def finalize(self) -> None:
            self.finalize_count += 1

    sessions: list[ClosingHttpSession] = []
    monkeypatch.setattr(ai_agent, "StatefulHttpActionSession", ClosingHttpSession)
    ordinary_audit_close = AuditStore.close

    def close_audit_then_fail(store: AuditStore) -> None:
        ordinary_audit_close(store)
        raise OSError("audit-close-secondary")

    monkeypatch.setattr(ai_agent.AuditStore, "close", close_audit_then_fail)

    runtime = ClosingRuntime()
    with pytest.raises(
        ValueError,
        match="digest requires a knowledge-pack path",
    ) as error:
        run_ai_web_agent(
            brief_path=brief_path,
            target_url=target_url,
            settings=AIWebAgentSettings(
                workspace_dir=workspace_dir,
                tool_runtime=runtime,
                tool_runtime_mode="host",
                model_client=object(),
                knowledge_pack_sha256="0" * 64,
                stdout=StringIO(),
            ),
        )

    assert runtime.close_count == 1
    assert len(sessions) == 1
    assert sessions[0].finalize_count == 1
    assert any(
        "audit store cleanup also failed: OSError" in note
        for note in getattr(error.value, "__notes__", ())
    )


def test_validate_poc_captures_executor_proof_beyond_validator_summary(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
        proof_recognition_enabled=True,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    try:
        outcome = execute_action(
            {
                "action": "validate_poc",
                "task_id": "flag-and-secret-sweep",
                "steps": [
                    {
                        "method": "GET",
                        "url": "/long-proof",
                        "expect_status": 200,
                    }
                ],
            },
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            proof_recognition_enabled=True,
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="late-proof-validation",
            http_executor=http_session,
        )
    finally:
        http_session.finalize()
        audit.close()

    assert outcome.ok is True
    assert outcome.stop is True
    assert outcome.outcome == "flag_candidate"
    assert outcome.flag == _LATE_RESPONSE_PROOF
    assert state.flags == [_LATE_RESPONSE_PROOF]
    assert _LATE_RESPONSE_PROOF not in outcome.evidence_observation
    validation = json.loads(outcome.evidence_observation)
    response_summary = validation["steps"][0]["response"]
    assert response_summary["body_len"] > 300
    assert "...[truncated" in response_summary["body_snippet"]
    events = [
        json.loads(line)
        for line in workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    outer = next(event for event in events if event["kind"] == "tool_validate_poc")
    assert outer["payload"]["recognized_proofs"] == [_LATE_RESPONSE_PROOF]


def test_validate_poc_does_not_capture_proof_from_authored_expectation(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState()
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
        proof_recognition_enabled=True,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    try:
        outcome = execute_action(
            {
                "action": "validate_poc",
                "task_id": "forged-validator-proof",
                "steps": [
                    {
                        "method": "GET",
                        "url": "/dashboard",
                        "expect_contains": _FORGED_VALIDATOR_PROOF,
                    }
                ],
            },
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            proof_recognition_enabled=True,
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="forged-validator-proof",
            http_executor=http_session,
        )
    finally:
        http_session.finalize()
        audit.close()

    assert outcome.stop is False
    assert outcome.flag == ""
    assert state.flags == []
    assert _FORGED_VALIDATOR_PROOF not in outcome.evidence_observation
    assert "[REDACTED-PROOF]" in outcome.evidence_observation
    events = [
        json.loads(line)
        for line in workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    outer = next(event for event in events if event["kind"] == "tool_validate_poc")
    assert outer["payload"]["recognized_proofs"] == []


def test_low_noise_http_does_not_replay_pre_login_get_after_cookie_transition(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    traffic_policy = TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url=target_url,
        config=TrafficPolicyConfig.low_noise(
            max_physical_requests=10,
            max_rps=100,
        ),
    )
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=AgentState(),
        traffic_policy=traffic_policy,
        low_noise=True,
    )

    try:
        before_login = http_session(
            node_id="base-agent",
            arguments={"method": "GET", "path": "/dashboard"},
            action_id="dashboard-before-login",
        )
        http_session(
            node_id="base-agent",
            arguments={
                "method": "POST",
                "path": "/login",
                "form": {"username": "user", "password": "pass"},
            },
            action_id="login",
        )
        after_login = http_session(
            node_id="base-agent",
            arguments={"method": "GET", "path": "/dashboard"},
            action_id="dashboard-after-login",
        )
    finally:
        http_session.finalize()

    assert json.loads(before_login.result.evidence_observation)["response"]["body"] == (
        "public login shell"
    )
    assert json.loads(after_login.result.evidence_observation)["response"]["body"] == (
        "authenticated dashboard"
    )
    assert stateful_http_target.requests == [
        {"method": "GET", "path": "/dashboard", "cookie": ""},
        {
            "method": "POST",
            "path": "/login",
            "cookie": "",
            "form": {"username": ["user"], "password": ["pass"]},
        },
        {
            "method": "GET",
            "path": "/dashboard",
            "cookie": "session=persistent",
        },
    ]
    snapshot = traffic_policy.snapshot()
    assert snapshot.physical_request_count == 3
    assert snapshot.cache_hit_count == 0


def test_http_request_visible_request_cannot_promote_file_read_primitive() -> None:
    state = AgentState(turn=1)
    action = {
        "action": "http_request",
        "method": "GET",
        "path": "/?q=root:x:0:0:",
    }
    outcome = {
        "ok": True,
        "observation": json.dumps(
            {
                "requests": [{"url": "http://target.invalid/?q=root:x:0:0:"}],
                "response": {"body": "clean response", "status": 200},
            }
        ),
        "stop": False,
        "exit_code": None,
        "timed_out": False,
        "repeat_count": 1,
        "outcome": "http_response_observed",
        "flag": "",
    }

    _update_state_from_action(state, action=action, outcome=outcome)

    assert "local file read evidence observed" not in state.facts
    assert "file_read_confirmed" not in state.primitives


def test_reflected_ssti_text_from_raw_http_cannot_confirm_primitive(
    tmp_path: Path,
    stateful_http_target: _HttpTarget,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    target_url = stateful_http_target.url
    scope = Scope(in_scope=[target_url], out_of_scope=[])
    state = AgentState(turn=1)
    action = {
        "action": "http_request",
        "task_id": "server-rendering",
        "method": "GET",
        "path": "/reflect?value=%7B%7B7*7%7D%7D",
    }
    http_session = StatefulHttpActionSession(
        target_url=target_url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=10,
        workspace_dir=workspace.root,
        state=state,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)
    try:
        outcome = execute_action(
            action,
            target_url=target_url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="reflected-ssti",
            http_executor=http_session,
        )
        _update_state_from_action(state, action=action, outcome=outcome.to_json())
    finally:
        http_session.finalize()
        audit.close()

    assert outcome.ok is True
    assert "hello {{7*7}} response 49" in outcome.evidence_observation
    assert "ssti_fingerprint_signal" not in state.signals.get("markers", [])
    assert "ssti_confirmed" not in state.primitives
