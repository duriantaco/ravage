# ruff: noqa: CPY001, PLR2004

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import TYPE_CHECKING
from uuid import uuid4

from pentest_schemas import Scope
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph import action_executor as graph_action_executor
from ravage.agent_core.autonomous_graph import bounded_probe
from ravage.agent_core.autonomous_graph.action_executor import (
    execute_graph_action,
)
from ravage.agent_core.autonomous_graph.bounded_probe import (
    BoundedGraphProbeSession,
    run_bounded_graph_probe,
)
from ravage.agent_core.autonomous_graph.effort_policy import (
    GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT,
)
from ravage.agent_core.autonomous_graph.production import ThreadOwnedAudit
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import FakeToolRuntime
from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    import pytest

TARGET_URL = "http://127.0.0.1:8765/"


class _LinkedTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:
        body = '<a href="/one">one</a><a href="/two">two</a><a href="/three">three</a>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class _Audit:
    scope: Scope | None = None

    def record(self, **_kwargs: object) -> None:
        return


def test_graph_action_executor_forwards_authentication_to_common_capture_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authentication = object()
    observed: list[object] = []

    def fake_execute_action(_action: dict[str, object], **kwargs: object) -> ActionResult:
        observed.append(kwargs.get("authentication"))
        return ActionResult(ok=False, observation="blocked", outcome="blocked")

    monkeypatch.setattr(graph_action_executor, "execute_action", fake_execute_action)

    result = execute_graph_action(
        {"action": "capture_flag", "flag": "FLAG{alice}"},
        target_url=TARGET_URL,
        runtime=FakeToolRuntime(),
        state=AgentState(),
        workspace=AgentWorkspace.open(tmp_path / "workspace"),
        audit=_Audit(),  # type: ignore[arg-type]
        engagement_id=uuid4(),
        repeat_count=1,
        max_observation_chars=10_000,
        max_transcript_chars=80_000,
        authentication=authentication,  # type: ignore[arg-type]
    )

    assert result.outcome == "blocked"
    assert observed == [authentication]


@contextmanager
def _linked_target() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LinkedTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_budget_is_shared_across_forked_probe_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_request(
        self: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del self, data, headers
        calls.append(url)
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="ok",
        )

    monkeypatch.setattr(ProbeSession, "request", fake_request)
    budget = bounded_probe._SharedTargetRequestBudget(2)  # noqa: SLF001
    session = BoundedGraphProbeSession(
        TARGET_URL,
        timeout_seconds=5,
        request_budget=budget,
    )
    forked = session.fork()

    assert session.get(TARGET_URL).status == 200
    assert forked.get(TARGET_URL + "one").status == 200
    denied = session.get(TARGET_URL + "two")

    assert denied.status is None
    assert denied.error == "graph_target_request_budget_exhausted"
    assert len(calls) == 2
    assert budget.receipt() == {
        "limit": 2,
        "used": 2,
        "denied": 1,
        "exhausted": True,
        "scope": "autonomous_graph_run_probe_only",
    }


def test_budget_denial_notifies_the_observer_inherited_by_a_fork(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[dict[str, object]] = []

    def fake_request(
        self: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del self, data, headers
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="ok",
        )

    monkeypatch.setattr(ProbeSession, "request", fake_request)
    budget = bounded_probe._SharedTargetRequestBudget(1)  # noqa: SLF001
    session = BoundedGraphProbeSession(
        TARGET_URL,
        timeout_seconds=5,
        request_budget=budget,
        traffic_observer=observed.append,
    )
    forked = session.fork()

    assert session.get(TARGET_URL).status == 200
    denied = forked.get(TARGET_URL + "denied")

    assert denied.error == "graph_target_request_budget_exhausted"
    assert len(observed) == 1
    event = observed[0]
    assert event["source"] == "probe_session"
    assert event["disposition"] == "blocked"
    assert event["reason"] == "graph_target_request_budget_exhausted"
    assert event["error"] == "graph_target_request_budget_exhausted"
    assert event["url"] == TARGET_URL + "denied"
    assert "request_headers" not in event


def test_bounded_probe_receipt_reports_actual_requests_not_denied_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def finite_handler(
        session: ProbeSession,
        state: AgentState,
    ) -> ProbeRunResult:
        del state
        requests = [session.get(TARGET_URL + str(index)).summary() for index in range(5)]
        return ProbeRunResult(
            ok=False,
            probe="fixture",
            summary="fixture exhausted",
            requests=requests,
        )

    def fake_request(
        self: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del self, data, headers
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="ok",
        )

    monkeypatch.setattr(ProbeSession, "request", fake_request)
    monkeypatch.setattr(
        bounded_probe,
        "_probe_handlers",
        lambda: {"fixture": finite_handler},
    )

    result, receipt = run_bounded_graph_probe(
        "fixture",
        target_url=TARGET_URL,
        state=AgentState(),
        timeout_seconds=5,
        target_request_limit=2,
    )

    assert result.ok is False
    assert len(result.requests) == 5
    assert receipt["used"] == 2
    assert receipt["denied"] == 3
    assert "grant exhausted at 2/2" in result.summary


def test_graph_action_executor_uses_bounded_subprocess_and_records_actual_count(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    with _linked_target() as target_url:
        result = execute_graph_action(
            {
                "action": "run_probe",
                "probe": "surface_map",
                GRAPH_TARGET_REQUEST_LIMIT_ARGUMENT: 2,
            },
            target_url=target_url,
            runtime=FakeToolRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=_Audit(),  # type: ignore[arg-type]
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=10_000,
            max_transcript_chars=80_000,
            proof_recognition_enabled=False,
            action_id="bounded-subprocess",
        )

    observation = json.loads(result.evidence_observation)
    receipt = observation["graph_target_request_budget"]
    assert result.evidence_source_kind == "tool_run_probe"
    assert receipt["limit"] == 2
    assert receipt["used"] == 2
    assert receipt["exhausted"] is True


def test_graph_action_executor_promotes_trusted_dom_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_text = json.dumps(
        {
            "probe": "dom_execution",
            "ok": True,
            "findings": [
                {
                    "type": "client_side_execution",
                    "request_template": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8765/search?q=redacted",
                        "payload_field": "q",
                    },
                    "evidence": {
                        "token_executed": True,
                        "executed_values": ["redacted"],
                        "dialogs": [],
                        "final_url": "http://127.0.0.1:8765/search",
                    },
                }
            ],
        }
    )
    monkeypatch.setattr(
        "ravage.agent_core.action_executor._run_probe_action",
        lambda *_args, **_kwargs: SimpleNamespace(
            text=probe_text,
            ok=True,
            timed_out=False,
        ),
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    audit = ThreadOwnedAudit(
        tmp_path / "audit.db",
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
    )
    try:
        result = execute_graph_action(
            {"action": "run_probe", "probe": "dom_execution"},
            target_url=TARGET_URL,
            runtime=FakeToolRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=10_000,
            max_transcript_chars=80_000,
            action_id="graph-dom-execution",
            traffic_policy=policy,
        )
        assert audit.count_findings(status="confirmed") == 1
    finally:
        audit.close()

    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    assert result.outcome == "finding_confirmed"
    assert sum(event["kind"] == "finding_confirmed" for event in events) == 1
    assert policy.snapshot().unmetered_action_count == 1
    assert policy.snapshot().accounting_status == "lower_bound"


def test_bounded_probe_subprocess_receives_shared_traffic_policy_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    requests: list[dict[str, object]] = []

    def run(*_args: object, **kwargs: object) -> SimpleNamespace:
        requests.append(json.loads(str(kwargs["input"])))
        return SimpleNamespace(
            stdout=json.dumps({"status": "ok", "ok": False, "text": "{}"}),
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(graph_action_executor.subprocess, "run", run)

    graph_action_executor._run_bounded_probe_action(  # noqa: SLF001
        "surface_map",
        target_url=TARGET_URL,
        state=AgentState(),
        timeout_seconds=5,
        target_request_limit=2,
        traffic_policy_reference=policy.to_reference(),
    )

    assert requests[0]["traffic_policy_reference"] == policy.to_reference()


def test_enforced_policy_blocks_external_process_probe_before_subprocess(
    tmp_path: Path,
) -> None:
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5),
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")

    result = execute_graph_action(
        {"action": "run_probe", "probe": "dom_execution"},
        target_url=TARGET_URL,
        runtime=FakeToolRuntime(),
        state=AgentState(),
        workspace=workspace,
        audit=_Audit(),  # type: ignore[arg-type]
        engagement_id=uuid4(),
        repeat_count=1,
        max_observation_chars=10_000,
        max_transcript_chars=80_000,
        traffic_policy=policy,
    )

    assert result.outcome == "blocked"
    assert policy.snapshot().blocked_count == 1
