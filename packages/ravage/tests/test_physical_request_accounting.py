from __future__ import annotations

import json
from email.message import Message
from http.client import BadStatusLine
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest
from ravage import probe_runner
from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite import run_builtin_probe
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyMode,
)
from ravage.web_core.http_probe import ProbeSession, _RequestPacer
from ravage.web_core.poc_validator import validate_http_poc

_TARGET_URL = "http://127.0.0.1:8000/"


def _loopback_resolver(_host: str, _port: int) -> tuple[str, ...]:
    return ("127.0.0.1",)


class _Response:
    status = 200

    def __init__(self, url: str, *, status: int = 200, body: bytes = b"ok") -> None:
        self._url = url
        self.status = status
        self._body = body
        self.headers = Message()
        self.headers["Content-Type"] = "text/plain; charset=utf-8"

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return self._url

    def read(self, _limit: int) -> bytes:
        return self._body


class _SuccessOpener:
    def open(self, request: object, *, timeout: float) -> _Response:
        del timeout
        assert isinstance(request, Request)
        return _Response(request.full_url)


class _TransportErrorOpener:
    def open(self, request: object, *, timeout: float) -> _Response:
        del request, timeout
        raise URLError("connection refused")


class _HttpErrorOpener:
    def open(self, request: object, *, timeout: float) -> _Response:
        del timeout
        assert isinstance(request, Request)
        headers = Message()
        headers["Content-Type"] = "text/plain"
        raise HTTPError(
            request.full_url,
            404,
            "not found",
            headers,
            BytesIO(b"missing"),
        )


class _Clock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class _SequenceOpener:
    def __init__(
        self,
        *,
        statuses: tuple[int, ...] = (200,),
        body: bytes = b"ok",
    ) -> None:
        self.statuses = statuses
        self.body = body
        self.calls = 0

    def open(self, request: object, *, timeout: float) -> _Response:
        del timeout
        assert isinstance(request, Request)
        index = min(self.calls, len(self.statuses) - 1)
        self.calls += 1
        return _Response(
            request.full_url,
            status=self.statuses[index],
            body=self.body,
        )


class _ProtocolErrorOpener:
    def open(self, request: object, *, timeout: float) -> _Response:
        del request, timeout
        raise BadStatusLine("malformed status")


class _UnexpectedErrorOpener:
    def open(self, request: object, *, timeout: float) -> _Response:
        del request, timeout
        raise RuntimeError("unexpected transport failure")


def _policy(
    tmp_path: Path,
    config: TrafficPolicyConfig,
    *,
    clock: _Clock | None = None,
) -> TrafficPolicyController:
    return TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url=_TARGET_URL,
        config=config,
        clock=clock or __import__("time").time,
        sleep=clock.sleep if clock is not None else __import__("time").sleep,
    )


@pytest.mark.parametrize(
    ("opener", "expected_status"),
    [
        pytest.param(_SuccessOpener(), 200, id="success"),
        pytest.param(_HttpErrorOpener(), 404, id="http-error"),
        pytest.param(_TransportErrorOpener(), None, id="url-error"),
    ],
)
def test_every_transport_dispatch_counts_once(
    monkeypatch: pytest.MonkeyPatch,
    opener: object,
    expected_status: int | None,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: opener,
    )
    session = ProbeSession(_TARGET_URL, resolver=_loopback_resolver)

    response = session.get("/")

    assert response.status == expected_status
    assert session.physical_request_count == 1


def test_scope_and_dns_blocks_do_not_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _SuccessOpener(),
    )
    scoped = ProbeSession(
        "http://127.0.0.1:8000/app",
        in_scope=["http://127.0.0.1:8000/app"],
        resolver=_loopback_resolver,
    )

    scope_response = scoped.get("/outside")

    assert scope_response.status is None
    assert "outside target origin" in scope_response.error
    assert scoped.physical_request_count == 0

    dns_blocked = ProbeSession(
        _TARGET_URL,
        resolver=lambda _host, _port: (),
    )

    dns_response = dns_blocked.get("/")

    assert dns_response.status is None
    assert "returned no addresses" in dns_response.error
    assert dns_blocked.physical_request_count == 0


def test_request_construction_failure_does_not_count(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _SuccessOpener(),
    )
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=1,
        ),
    )
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
    )

    def reject_request(*_args: object, **_kwargs: object) -> object:
        raise ValueError("request setup failed")

    monkeypatch.setattr("ravage.web_core.http_probe.Request", reject_request)

    with pytest.raises(ValueError, match="request setup failed"):
        session.get("/")

    assert session.physical_request_count == 0
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 0
    assert snapshot.reservation_count == 0


@pytest.mark.parametrize(
    ("method", "headers", "error"),
    [
        pytest.param("GE T", None, "method", id="method-space"),
        pytest.param("GET\r\nX-Injected", None, "method", id="method-crlf"),
        pytest.param("GET", {"Bad Name": "value"}, "header name", id="header-name"),
        pytest.param(
            "GET",
            {"X-Test": "safe\r\nX-Injected: value"},
            "header value",
            id="header-value-crlf",
        ),
    ],
)
def test_invalid_request_syntax_is_rejected_before_policy_acquire_or_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    method: str,
    headers: dict[str, str] | None,
    error: str,
) -> None:
    opener = _SequenceOpener()
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: opener,
    )
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=1,
        ),
    )
    acquire_calls = 0
    original_acquire = controller.acquire

    def acquire(*args: object, **kwargs: object) -> object:
        nonlocal acquire_calls
        acquire_calls += 1
        return original_acquire(*args, **kwargs)

    monkeypatch.setattr(controller, "acquire", acquire)
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
    )

    with pytest.raises(ValueError, match=error):
        session.request(method, "/", headers=headers)

    snapshot = controller.snapshot()
    assert acquire_calls == 0
    assert opener.calls == 0
    assert session.physical_request_count == 0
    assert snapshot.physical_request_count == 0
    assert snapshot.completed_request_count == 0
    assert snapshot.pending_dispatch_count == 0
    assert snapshot.reservation_count == 0


def test_forks_share_physical_request_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _SuccessOpener(),
    )
    session = ProbeSession(_TARGET_URL, resolver=_loopback_resolver)
    fork = session.fork()

    session.get("/one")
    fork.get("/two")

    assert session.physical_request_count == 2
    assert fork.physical_request_count == 2


def test_probe_result_uses_physical_delta_across_forks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _SuccessOpener(),
    )
    session = ProbeSession(_TARGET_URL, resolver=_loopback_resolver)
    session.get("/before-probe")

    def handler(
        probe_session: ProbeSession,
        _state: AgentState,
    ) -> ProbeRunResult:
        probe_session.get("/one")
        probe_session.fork().get("/two")
        return ProbeRunResult(
            ok=True,
            probe="counted",
            summary="done",
        )

    monkeypatch.setattr(
        "ravage.probe_suite._probe_handlers",
        lambda: {"counted": handler},
    )

    result = run_builtin_probe(
        "counted",
        target_url=_TARGET_URL,
        state=AgentState(),
        session=session,
    )

    assert session.physical_request_count == 3
    assert result.http_request_count == 2
    assert '"http_request_count": 2' in result.to_text()


def test_validate_http_poc_uses_physical_request_delta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _SuccessOpener(),
    )
    session = ProbeSession(_TARGET_URL, resolver=_loopback_resolver)
    session.get("/before-validation")
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        lambda *_args, **_kwargs: session,
    )

    result = validate_http_poc(
        target_url=_TARGET_URL,
        steps=[
            {
                "method": "GET",
                "url": "/proof",
                "expect_status": 200,
                "expect_contains": "ok",
            }
        ],
    )

    assert result.ok is True
    assert session.physical_request_count == 2
    assert result.http_request_count == 1
    assert '"http_request_count": 1' in result.to_text()


def test_policy_cap_blocks_second_request_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    opener = _SequenceOpener()
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: opener,
    )
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=1,
        ),
    )
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
    )

    first = session.get("/one")
    second = session.get("/two")

    assert first.status == 200
    assert second.status is None
    assert second.error == "whole-run physical request limit reached"
    assert opener.calls == 1
    assert session.physical_request_count == 1
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 1
    assert snapshot.completed_request_count == 1


def test_policy_cache_hit_avoids_dispatch_and_preserves_raw_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw_body = b"PK\x03\x04\xff\x00archive"
    opener = _SequenceOpener(body=raw_body)
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: opener,
    )
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            cache_enabled=True,
        ),
    )
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
        traffic_lane="recon",
        traffic_cacheable=True,
    )

    first = session.get("/archive.zip")
    second = session.get("/archive.zip")

    assert first.status == second.status == 200
    assert first.body_bytes == raw_body
    assert second.body_bytes == raw_body
    assert second.body == first.body
    assert opener.calls == 1
    assert session.physical_request_count == 1
    assert controller.snapshot().cache_hit_count == 1


def test_native_session_uses_sub_one_rps_policy_clock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    opener = _SequenceOpener()
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: opener,
    )
    clock = _Clock()
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_rps=0.5,
        ),
        clock=clock,
    )
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
    )

    session.get("/one")
    session.get("/two")

    assert opener.calls == 2
    assert clock.now == pytest.approx(1_002.0)
    assert clock.sleeps == [pytest.approx(2.0)]
    assert controller.snapshot().physical_request_count == 2


@pytest.mark.parametrize(
    ("method", "statuses", "expected_status", "expected_calls", "expected_retries"),
    [
        pytest.param("GET", (503, 200), 200, 2, 1, id="safe-get"),
        pytest.param("POST", (503,), 503, 1, 0, id="unsafe-post"),
    ],
)
def test_policy_retries_safe_get_but_never_post(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    method: str,
    statuses: tuple[int, ...],
    expected_status: int,
    expected_calls: int,
    expected_retries: int,
) -> None:
    opener = _SequenceOpener(statuses=statuses)
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: opener,
    )
    clock = _Clock()
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_retries=2,
            backoff_initial_seconds=0.25,
            backoff_max_seconds=0.25,
        ),
        clock=clock,
    )
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
        traffic_retryable=True,
    )

    response = session.request(method, "/retry")

    assert response.status == expected_status
    assert opener.calls == expected_calls
    assert session.physical_request_count == expected_calls
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == expected_calls
    assert snapshot.completed_request_count == expected_calls
    assert snapshot.retry_count == expected_retries


def test_protocol_error_completes_policy_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _ProtocolErrorOpener(),
    )
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(mode=TrafficPolicyMode.ENFORCE),
    )
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
    )

    response = session.get("/malformed")

    assert response.status is None
    assert response.error == "HTTP protocol error"
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 1
    assert snapshot.completed_request_count == 1
    assert snapshot.pending_dispatch_count == 0
    assert snapshot.reservation_count == 0


def test_unexpected_transport_error_completes_policy_lease_before_raising(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _UnexpectedErrorOpener(),
    )
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(mode=TrafficPolicyMode.ENFORCE),
    )
    session = ProbeSession(
        _TARGET_URL,
        resolver=_loopback_resolver,
        traffic_policy=controller,
    )

    with pytest.raises(RuntimeError, match="unexpected transport failure"):
        session.get("/explode")

    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 1
    assert snapshot.completed_request_count == 1
    assert snapshot.pending_dispatch_count == 0
    assert snapshot.reservation_count == 0


def test_probe_and_poc_share_policy_reference_and_whole_run_cap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    opener = _SequenceOpener()
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: opener,
    )
    monkeypatch.setattr(
        "ravage.web_core.http_probe._resolve_addresses",
        _loopback_resolver,
    )
    controller = _policy(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=1,
        ),
    )

    def handler(session: ProbeSession, _state: AgentState) -> ProbeRunResult:
        response = session.get("/from-probe")
        return ProbeRunResult(
            ok=response.status == 200,
            probe="shared-policy",
            summary="probe dispatched",
        )

    monkeypatch.setattr(
        "ravage.probe_suite._probe_handlers",
        lambda: {"shared-policy": handler},
    )

    probe_result = run_builtin_probe(
        "shared-policy",
        target_url=_TARGET_URL,
        state=AgentState(),
        traffic_policy_reference=controller.to_reference(),
    )
    poc_result = validate_http_poc(
        target_url=_TARGET_URL,
        steps=[{"method": "GET", "url": "/from-poc", "expect_status": 200}],
        traffic_policy_reference=controller.to_reference(),
    )

    assert probe_result.ok is True
    assert probe_result.http_request_count == 1
    assert poc_result.ok is False
    assert poc_result.http_request_count == 0
    response_summary = poc_result.steps[0]["response"]
    assert isinstance(response_summary, dict)
    assert response_summary["error"] == "whole-run physical request limit reached"
    assert opener.calls == 1
    assert controller.snapshot().physical_request_count == 1


@pytest.mark.parametrize(
    "max_rps",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-inf"),
        pytest.param(float("-inf"), id="negative-inf"),
        pytest.param(0.0, id="zero"),
        pytest.param(True, id="bool"),
        pytest.param(5e-324, id="infinite-interval"),
    ],
)
def test_standalone_request_pacer_rejects_invalid_rates(max_rps: float) -> None:
    with pytest.raises((TypeError, ValueError), match="max_rps"):
        _RequestPacer(max_rps)


def _invoke_probe_runner(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> dict[str, Any]:
    stdout = StringIO()
    monkeypatch.setattr(probe_runner.sys, "stdin", StringIO(json.dumps(payload)))
    monkeypatch.setattr(probe_runner.sys, "stdout", stdout)
    probe_runner.main()
    result = json.loads(stdout.getvalue())
    assert isinstance(result, dict)
    return result


def test_probe_runner_accepts_fractional_rate_and_object_policy_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run_builtin_probe(*_args: object, **kwargs: object) -> ProbeRunResult:
        captured.update(kwargs)
        return ProbeRunResult(ok=True, probe="runner", summary="accepted")

    monkeypatch.setattr(probe_runner, "run_builtin_probe", fake_run_builtin_probe)
    reference = {"schema": "test-reference"}

    result = _invoke_probe_runner(
        monkeypatch,
        {
            "probe": "runner",
            "target_url": _TARGET_URL,
            "max_rps": 0.5,
            "traffic_policy_reference": reference,
        },
    )

    assert result["status"] == "ok"
    assert captured["max_rps"] == 0.5
    assert captured["traffic_policy_reference"] == reference


@pytest.mark.parametrize(
    "invalid_fields",
    [
        pytest.param({"max_rps": "quiet"}, id="malformed-rate"),
        pytest.param({"max_rps": float("nan")}, id="nan-rate"),
        pytest.param({"max_rps": float("inf")}, id="infinite-rate"),
        pytest.param({"max_rps": 0}, id="zero-rate"),
        pytest.param({"max_rps": True}, id="boolean-rate"),
        pytest.param({"traffic_policy_reference": []}, id="empty-list-reference"),
        pytest.param(
            {"traffic_policy_reference": ["not", "an", "object"]},
            id="list-reference",
        ),
        pytest.param({"traffic_policy": "not-an-object"}, id="string-reference"),
    ],
)
def test_probe_runner_rejects_invalid_policy_inputs(
    monkeypatch: pytest.MonkeyPatch,
    invalid_fields: dict[str, object],
) -> None:
    called = False

    def unexpected_run_builtin_probe(*_args: object, **_kwargs: object) -> ProbeRunResult:
        nonlocal called
        called = True
        return ProbeRunResult(ok=True, probe="runner", summary="unexpected")

    monkeypatch.setattr(
        probe_runner,
        "run_builtin_probe",
        unexpected_run_builtin_probe,
    )
    payload: dict[str, object] = {
        "probe": "runner",
        "target_url": _TARGET_URL,
        **invalid_fields,
    }

    result = _invoke_probe_runner(monkeypatch, payload)

    assert result["status"] == "error"
    assert called is False
