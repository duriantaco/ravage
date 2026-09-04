# ruff: noqa: EM101, PLR2004, SLF001, TRY003
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from pentest_schemas import Scope
from ravage.agent_core import action_executor
from ravage.agent_core import stateful_http as stateful_http_module
from ravage.agent_core.action_executor import execute_action
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import _seed_recon
from ravage.agent_core.stateful_http import StatefulHttpActionSession
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.sqli import sqli as sqli_module
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import NoProcessToolRuntime
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyMode,
)
from ravage.web_core import http_probe as http_probe_module

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from ravage.web_core.http_probe import ProbeSession


@dataclass(frozen=True)
class _CookieTarget:
    url: str
    requests: list[tuple[str, str]]


@pytest.fixture
def cookie_target() -> Iterator[_CookieTarget]:  # noqa: C901 - compact test server.
    requests: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.path, self.headers.get("Cookie", "")))
            if self.path != "/login":
                self._respond(404, b"not found")
                return
            body = b"session established"
            self.send_response(200)
            self.send_header("Set-Cookie", "session=persistent; Path=/; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            cookie = self.headers.get("Cookie", "")
            requests.append((self.path, cookie))
            if self.path == "/":
                body = b"recon seeded"
                self.send_response(200)
                self.send_header("Set-Cookie", "recon=seeded; Path=/; HttpOnly")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/private" and "session=persistent" in cookie:
                self._respond(200, b"private")
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/source-only/search" and "recon=seeded" in cookie:
                value = parse_qs(parsed.query, keep_blank_values=True).get("term", [""])[-1]
                body = b"sqlite3.OperationalError: unrecognized token" if "'" in value else b"[]"
                self._respond(200, body)
                return
            if parsed.path == "/source-only/timing" and "recon=seeded" in cookie:
                value = parse_qs(parsed.query, keep_blank_values=True).get("term", [""])[-1]
                if value == "ravage-delay":
                    time.sleep(0.25)
                self._respond(200, b"[]")
                return
            self._respond(401, b"login required")

        def _respond(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield _CookieTarget(
            url=f"http://127.0.0.1:{server.server_port}/",
            requests=requests,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _http_owner(
    tmp_path: Path,
    *,
    target: _CookieTarget,
    state: AgentState,
    low_noise: bool = False,
) -> StatefulHttpActionSession:
    return StatefulHttpActionSession(
        target_url=target.url,
        scope=Scope(
            in_scope=[target.url],
            out_of_scope=[target.url + "blocked"],
        ),
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=20,
        workspace_dir=tmp_path / "workspace",
        state=state,
        low_noise=low_noise,
    )


def test_native_probe_adapter_reuses_cookie_scope_and_accounting(
    tmp_path: Path,
    cookie_target: _CookieTarget,
) -> None:
    state = AgentState()
    owner = _http_owner(tmp_path, target=cookie_target, state=state)
    try:
        login = owner.request("POST", "/login", data=b"")
        probe_session = owner.session_for_native_probe(timeout_seconds=2)
        private = probe_session.get("/private")
        count_before_block = probe_session.physical_request_count
        blocked = probe_session.fork(inherit_identity=False).get("/blocked")
    finally:
        owner.finalize()

    assert login.status == 200
    assert private.status == 200
    assert private.body == "private"
    assert blocked.status is None
    assert "out of scope" in blocked.error.lower()
    assert count_before_block == 2
    assert probe_session.physical_request_count == 2
    assert [path for path, _cookie in cookie_target.requests] == ["/login", "/private"]
    assert "session=persistent" in cookie_target.requests[-1][1]


def test_native_probe_adapter_enforces_deadline_before_dispatch(
    tmp_path: Path,
    cookie_target: _CookieTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 100.0}
    monkeypatch.setattr(stateful_http_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(http_probe_module.time, "monotonic", lambda: clock["now"])
    owner = _http_owner(tmp_path, target=cookie_target, state=AgentState())
    try:
        session = owner.session_for_native_probe(
            timeout_seconds=10,
            wall_timeout_seconds=1,
        )
        clock["now"] = 102.0
        with pytest.raises(TimeoutError, match="wall-clock deadline"):
            session.get("/private")
    finally:
        owner.finalize()

    assert cookie_target.requests == []


def test_native_probe_deadline_blocks_pacing_before_physical_dispatch(
    tmp_path: Path,
    cookie_target: _CookieTarget,
) -> None:
    owner = _http_owner(
        tmp_path,
        target=cookie_target,
        state=AgentState(),
        low_noise=True,
    )
    try:
        session = owner.session_for_native_probe(timeout_seconds=10)
        first = session.get("/")
        session.constrain_wall_clock(0.5)

        with pytest.raises(TimeoutError, match="wall-clock deadline"):
            session.get("/private")
    finally:
        owner.finalize()

    assert first.status == 200
    assert cookie_target.requests == [("/", "")]
    assert owner.request_count == 1


def test_source_sql_action_uses_stateful_probe_instead_of_subprocess(
    tmp_path: Path,
    cookie_target: _CookieTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentState(
        surface={
            "target_url": cookie_target.url,
            "origin": cookie_target.url.rstrip("/"),
            "source_validation_probe": "sqli_differential",
        }
    )
    owner = _http_owner(tmp_path, target=cookie_target, state=state)
    owner.request("POST", "/login", data=b"")
    seen_sessions: list[ProbeSession] = []

    def fake_run_builtin_probe(
        probe: str,
        *,
        session: ProbeSession,
        **_kwargs: object,
    ) -> ProbeRunResult:
        seen_sessions.append(session)
        before = session.physical_request_count
        response = session.get("/private")
        assert response.status == 200
        return ProbeRunResult(
            ok=True,
            probe=probe,
            summary="stateful source validation",
            http_request_count=session.physical_request_count - before,
        )

    def unexpected_subprocess(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("source SQL validation spawned an isolated probe")

    monkeypatch.setattr(action_executor, "run_builtin_probe", fake_run_builtin_probe)
    monkeypatch.setattr(action_executor, "_run_probe_action", unexpected_subprocess)
    workspace = AgentWorkspace.open(tmp_path / "agent")
    audit = AuditStore(
        tmp_path / "audit.db",
        scope=Scope(in_scope=[cookie_target.url], out_of_scope=[]),
    )
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "sqli_differential"},
            target_url=cookie_target.url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="source-sql-validation",
            http_executor=owner,
        )
    finally:
        owner.finalize()

    payload = json.loads(result.evidence_observation)
    assert result.ok is True
    assert result.session_mode == "anonymous:persistent"
    assert len(seen_sessions) == 1
    assert payload["http_request_count"] == 1
    assert owner.request_count == 2
    assert "session=persistent" in cookie_target.requests[-1][1]


def test_stateful_source_sql_probe_observes_transport_timing_delta(
    tmp_path: Path,
    cookie_target: _CookieTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentState()
    owner = _http_owner(tmp_path, target=cookie_target, state=state)
    try:
        seeded = owner.request("GET", "/")
        assert seeded.status == 200
        state.surface.update(
            {
                "source_validation_probe": "sqli_differential",
                "source_validation_candidate_ids": ["source-sql-timing"],
                "source_candidates": [
                    {
                        "candidate_id": "source-sql-timing",
                        "family": "sql_injection",
                        "method": "GET",
                        "route": "/source-only/timing",
                        "input_name": "term",
                        "input_location": "query",
                        "route_binding": "direct",
                        "live_validation": "automatic_get_query",
                        "query_fields": [
                            {
                                "name": "term",
                                "required": True,
                                "value_kind": "string",
                            }
                        ],
                        "relative_file": "app.py",
                        "line": 9,
                    }
                ],
            }
        )
        monkeypatch.setattr(sqli_module, "_sqli_error_payloads_for_target", lambda _target: [])
        monkeypatch.setattr(sqli_module, "_sqli_boolean_payloads_for_target", lambda _target: [])
        monkeypatch.setattr(
            sqli_module,
            "_sqli_timing_payloads_for_target",
            lambda _target: ["ravage-delay"],
        )
        monkeypatch.setattr(sqli_module, "_SQLI_TIMING_DELAY_SECONDS", 0.5)

        result = sqli_module.probe_sqli_differential(
            owner.session_for_native_probe(timeout_seconds=2),
            state,
        )
    finally:
        owner.finalize()

    assert result.ok is True
    timing = next(
        finding
        for finding in result.findings
        if finding.get("type") == "blind_sql_injection_timing_signal"
    )
    assert int(timing["probe_elapsed_ms"]) >= 200
    assert int(timing["elapsed_delta_ms"]) >= 150
    assert int(timing["repeat_elapsed_ms"]) >= 200
    assert int(timing["control_elapsed_ms"]) < 150


def test_stateful_source_probe_wall_timeout_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: dict[str, int] = {}

    class Owner:
        def session_for_native_probe(
            self,
            *,
            timeout_seconds: int,
            wall_timeout_seconds: int,
        ) -> object:
            received["request_timeout"] = timeout_seconds
            received["wall_timeout"] = wall_timeout_seconds
            return object()

    def timeout_probe(*_args: object, **_kwargs: object) -> ProbeRunResult:
        raise TimeoutError("deadline reached")

    monkeypatch.setattr(action_executor, "run_builtin_probe", timeout_probe)

    result = action_executor._run_stateful_probe_action(
        "sqli_differential",
        target_url="http://127.0.0.1:8765/",
        state=AgentState(),
        timeout_seconds=10,
        http_executor=Owner(),  # type: ignore[arg-type]
    )

    assert received == {"request_timeout": 10, "wall_timeout": 35}
    assert result.ok is False
    assert result.timed_out is True
    assert "wall-clock guard" in result.text


def test_source_recon_cookie_reaches_sql_validation_with_exact_accounting(
    tmp_path: Path,
    cookie_target: _CookieTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "agent")
    scope = Scope(in_scope=[cookie_target.url], out_of_scope=[])
    state = AgentState()
    traffic_policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=cookie_target.url,
        config=TrafficPolicyConfig(mode=TrafficPolicyMode.OBSERVE),
    )
    owner = StatefulHttpActionSession(
        target_url=cookie_target.url,
        scope=scope,
        allow_remote_target=False,
        roe_max_rps=100,
        max_total_requests=20,
        workspace_dir=workspace.root,
        state=state,
        traffic_policy=traffic_policy,
    )
    audit = AuditStore(tmp_path / "audit.db", scope=scope)

    def unexpected_subprocess(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("source SQL validation spawned an isolated probe")

    monkeypatch.setattr(action_executor, "_run_probe_action", unexpected_subprocess)
    try:
        _seed_recon(
            target_url=cookie_target.url,
            description="source-guided test",
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            allow_remote_target=False,
            in_scope=scope.in_scope,
            out_of_scope=scope.out_of_scope,
            max_rps=100,
            flag_objective=False,
            traffic_policy=traffic_policy,
            http_executor=owner,
        )
        state.surface.update(
            {
                "target_url": cookie_target.url,
                "origin": cookie_target.url.rstrip("/"),
                "source_validation_probe": "sqli_differential",
                "source_validation_candidate_ids": ["source-sql-1"],
                "source_candidates": [
                    {
                        "candidate_id": "source-sql-1",
                        "family": "sql_injection",
                        "method": "GET",
                        "route": "/source-only/search",
                        "route_binding": "direct",
                        "live_validation": "automatic_get_query",
                        "input_name": "term",
                        "input_location": "query",
                        "query_fields": [
                            {"name": "term", "value_kind": "string", "required": True}
                        ],
                        "relative_file": "app.py",
                        "line": 7,
                    }
                ],
            }
        )
        result = execute_action(
            {"action": "run_probe", "probe": "sqli_differential"},
            target_url=cookie_target.url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="source-sql-after-recon",
            traffic_policy=traffic_policy,
            http_executor=owner,
        )
    finally:
        owner.finalize()

    probe_payload = json.loads(result.evidence_observation)
    source_requests = [
        (path, cookie)
        for path, cookie in cookie_target.requests
        if path.startswith("/source-only/search")
    ]
    assert result.ok is True
    assert result.session_mode == "anonymous:persistent"
    assert len(source_requests) == 2
    assert all("recon=seeded" in cookie for _path, cookie in source_requests)
    assert probe_payload["http_request_count"] == 2
    assert owner.request_count == 3
    assert traffic_policy.snapshot().physical_request_count == 3
    assert len(cookie_target.requests) == 3


def test_ordinary_unauthenticated_probe_keeps_subprocess_isolation(
    tmp_path: Path,
    cookie_target: _CookieTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentState(surface={"target_url": cookie_target.url})
    owner = _http_owner(tmp_path, target=cookie_target, state=state)
    calls: list[str] = []

    def fake_subprocess_probe(probe: str, **_kwargs: object) -> object:
        calls.append(probe)
        return action_executor._ProbeActionResult(text="{}", ok=False)

    monkeypatch.setattr(action_executor, "_run_probe_action", fake_subprocess_probe)
    workspace = AgentWorkspace.open(tmp_path / "agent")
    audit = AuditStore(
        tmp_path / "audit.db",
        scope=Scope(in_scope=[cookie_target.url], out_of_scope=[]),
    )
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "sqli_differential"},
            target_url=cookie_target.url,
            runtime=NoProcessToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="ordinary-sql-probe",
            http_executor=owner,
        )
    finally:
        owner.finalize()

    assert calls == ["sqli_differential"]
    assert result.session_mode == ""
    assert owner.request_count == 0
