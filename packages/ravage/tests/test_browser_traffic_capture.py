from __future__ import annotations

import json
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING

import pytest
from ravage.traffic.browser_capture import (
    BROWSER_EVENT_SCHEMA_VERSION,
    MAX_CAPTURE_BODY_BYTES,
    BrowserTrafficCapture,
    playwright_context_options,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


class _Recorder:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record_browser_event(self, event: Mapping[str, object], /) -> None:
        self.events.append(dict(event))


class _Context:
    def __init__(self) -> None:
        self.route_pattern = ""
        self.route_handler: Callable[[object], None] | None = None
        self.websocket_pattern = ""
        self.websocket_handler: Callable[[object], None] | None = None
        self.listeners: dict[str, Callable[[object], None]] = {}

    def route(self, url: str, handler: Callable[[object], None]) -> None:
        self.route_pattern = url
        self.route_handler = handler

    def route_web_socket(self, url: str, handler: Callable[[object], None]) -> None:
        self.websocket_pattern = url
        self.websocket_handler = handler

    def on(self, event: str, handler: Callable[[object], None]) -> None:
        self.listeners[event] = handler

    def route_request(self, request: _Request) -> _Route:
        assert self.route_handler is not None
        route = _Route(request)
        self.route_handler(route)
        return route

    def emit(self, event: str, value: object) -> None:
        self.listeners[event](value)

    def route_websocket(self, url: str) -> _WebSocketRoute:
        assert self.websocket_handler is not None
        route = _WebSocketRoute(url)
        self.websocket_handler(route)
        return route


@dataclass
class _Request:
    url: str
    method: str = "GET"
    resource_type: str = "document"
    headers: Mapping[str, str] = field(default_factory=dict)
    post_data: str | None = None
    redirected_from: _Request | None = None
    navigation: bool = False
    failure: str | None = None

    @property
    def frame(self) -> object:
        message = "browser capture must not access request.frame"
        raise AssertionError(message)

    def is_navigation_request(self) -> bool:
        return self.navigation

    def all_headers(self) -> Mapping[str, str]:
        return self.headers


class _Route:
    def __init__(self, request: _Request) -> None:
        self.request = request
        self.continued = 0
        self.aborted = 0

    def continue_(self) -> None:
        self.continued += 1

    def abort(self) -> None:
        self.aborted += 1


class _WebSocketRoute:
    def __init__(self, url: str) -> None:
        self.url = url
        self.connected = 0
        self.closed: list[tuple[int | None, str | None]] = []

    def connect_to_server(self) -> None:
        self.connected += 1

    def close(self, *, code: int | None = None, reason: str | None = None) -> None:
        self.closed.append((code, reason))


@dataclass
class _Response:
    request: _Request
    url: str
    status: int
    headers: Mapping[str, str]
    status_text: str = "OK"
    from_service_worker: bool = False

    def all_headers(self) -> Mapping[str, str]:
        return self.headers


@dataclass
class _Decision:
    allowed: bool
    reason: str = ""


def _capture(
    *,
    predicate: Callable[[str], bool | _Decision] | None = None,
    capture_all_resources: bool = False,
) -> tuple[BrowserTrafficCapture, _Recorder, _Context]:
    recorder = _Recorder()
    capture = BrowserTrafficCapture(
        recorder=recorder,
        scope_predicate=predicate or (lambda _url: True),
        capture_all_resources=capture_all_resources,
        capture_session_id="capture-test",
    )
    context = _Context()
    capture.attach(context)
    return capture, recorder, context


def test_context_contract_always_blocks_service_workers() -> None:
    assert playwright_context_options(ignore_https_errors=True) == {
        "accept_downloads": False,
        "ignore_https_errors": True,
        "service_workers": "block",
    }
    assert BrowserTrafficCapture.context_options() == {
        "accept_downloads": False,
        "service_workers": "block",
    }

    with pytest.raises(ValueError, match="service_workers='block'"):
        playwright_context_options(service_workers="allow")
    with pytest.raises(ValueError, match="accept_downloads=False"):
        playwright_context_options(accept_downloads=True)


def test_attach_registers_route_and_complete_lifecycle_with_one_correlation_id() -> None:
    _capture_instance, recorder, context = _capture()
    request = _Request(
        "https://target.test/api/jobs?view=full&token=query-secret",
        method="POST",
        resource_type="fetch",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer header-secret",
            "X-Trace": "trace-1",
        },
        post_data=json.dumps(
            {"job_type": "scan", "password": "body-secret", "nested": {"ok": True}}
        ),
    )

    context.emit("request", request)
    assert recorder.events == []  # Nothing is disclosed before the route scope decision.
    route = context.route_request(request)
    context.emit(
        "response",
        _Response(
            request=request,
            url=request.url,
            status=HTTPStatus.ACCEPTED,
            headers={"Content-Type": "application/json", "Set-Cookie": "sid=cookie-secret"},
        ),
    )
    context.emit("requestfinished", request)

    assert context.route_pattern == "**/*"
    assert context.websocket_pattern == "**/*"
    assert (route.continued, route.aborted) == (1, 0)
    assert [event["event_type"] for event in recorder.events] == [
        "request",
        "response",
        "requestfinished",
    ]
    assert {event["correlation_id"] for event in recorder.events} == {"capture-test:000001"}
    assert [event["event_sequence"] for event in recorder.events] == [1, 2, 3]
    assert all(event["schema_version"] == BROWSER_EVENT_SCHEMA_VERSION for event in recorder.events)

    recorded_request = recorder.events[0]["request"]
    assert isinstance(recorded_request, dict)
    assert recorded_request["headers"] == {
        "authorization": "[REDACTED]",
        "content-type": "application/json",
        "x-trace": "[REDACTED]",
    }
    assert recorded_request["url"].endswith("view=%5BREDACTED%5D&token=%5BREDACTED%5D")
    recorded_body = recorded_request["body"]
    assert isinstance(recorded_body, dict)
    assert isinstance(request.post_data, str)
    assert recorded_body["media_type"] == "application/json"
    assert recorded_body["byte_length"] == len(request.post_data.encode())
    assert recorded_body["sha256"] == "unavailable"
    assert recorded_body["field_names"] == ["job_type", "nested", "password"]
    recorded_response = recorder.events[1]["response"]
    assert isinstance(recorded_response, dict)
    assert recorded_response["status"] == HTTPStatus.ACCEPTED
    assert recorded_response["headers"] == {
        "content-type": "application/json",
        "set-cookie": "[REDACTED]",
    }
    serialized = json.dumps(recorder.events)
    assert "query-secret" not in serialized
    assert "header-secret" not in serialized
    assert "body-secret" not in serialized
    assert "cookie-secret" not in serialized


def test_oversized_declared_request_body_is_not_materialized() -> None:
    _capture_instance, recorder, context = _capture()
    declared = MAX_CAPTURE_BODY_BYTES + 1
    request = _Request(
        "https://target.test/api/upload",
        method="POST",
        resource_type="fetch",
        headers={
            "Content-Length": str(declared),
            "Content-Type": "application/json",
        },
        post_data='{"secret":"small fixture must not be inspected"}',
    )

    context.emit("request", request)
    context.route_request(request)
    context.emit("requestfinished", request)

    captured = recorder.events[0]["request"]
    assert isinstance(captured, dict)
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["byte_length"] == declared
    assert body["field_names"] == []
    assert body["truncated"] is True
    assert "small fixture" not in json.dumps(recorder.events)


def test_redirects_are_correlated_to_the_parent_request() -> None:
    _capture_instance, recorder, context = _capture()
    first = _Request("https://target.test/start", navigation=True)
    redirected = _Request(
        "https://target.test/final",
        redirected_from=first,
        navigation=True,
    )

    for request in (first, redirected):
        context.emit("request", request)
        context.route_request(request)
        context.emit(
            "response",
            _Response(
                request=request,
                url=request.url,
                status=302 if request is first else 200,
                headers={},
            ),
        )
        context.emit("requestfinished", request)

    request_events = [event for event in recorder.events if event["event_type"] == "request"]
    assert request_events[0]["parent_correlation_id"] is None
    assert request_events[1]["parent_correlation_id"] == request_events[0]["correlation_id"]


def test_out_of_scope_request_is_aborted_with_metadata_only() -> None:
    seen: list[str] = []

    def predicate(url: str) -> _Decision:
        seen.append(url)
        return _Decision(allowed=False, reason="outside engagement")

    _capture_instance, recorder, context = _capture(predicate=predicate)
    request = _Request(
        "https://outside.test/collect?password=query-secret",
        method="POST",
        resource_type="xhr",
        headers={"Authorization": "Bearer header-secret"},
        post_data="password=body-secret",
    )

    context.emit("request", request)
    route = context.route_request(request)

    assert seen == [request.url]
    assert (route.continued, route.aborted) == (0, 1)
    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert event["event_type"] == "request_blocked"
    assert event["scope"] == {"allowed": False, "reason": "outside engagement"}
    recorded_request = event["request"]
    assert isinstance(recorded_request, dict)
    assert set(recorded_request) == {"method", "url", "resource_type"}
    serialized = json.dumps(event)
    assert "query-secret" not in serialized
    assert "header-secret" not in serialized
    assert "body-secret" not in serialized


def test_scope_predicate_failure_aborts_the_route_and_is_sanitized() -> None:
    def broken_scope(_url: str) -> bool:
        message = "token=predicate-secret"
        raise RuntimeError(message)

    _capture_instance, recorder, context = _capture(predicate=broken_scope)
    request = _Request("https://target.test/api", resource_type="fetch")

    context.emit("request", request)
    route = context.route_request(request)

    assert (route.continued, route.aborted) == (0, 1)
    assert recorder.events[0]["event_type"] == "request_blocked"
    assert "predicate-secret" not in json.dumps(recorder.events)


def test_default_filter_still_scope_blocks_but_does_not_record_static_resources() -> None:
    seen: list[str] = []

    def predicate(url: str) -> bool:
        seen.append(url)
        return False

    _capture_instance, recorder, context = _capture(predicate=predicate)
    image = _Request("https://target.test/logo.png", resource_type="image")

    context.emit("request", image)
    route = context.route_request(image)
    context.emit("response", _Response(image, image.url, 200, {"Content-Type": "image/png"}))
    context.emit("requestfinished", image)

    assert seen == [image.url]
    assert (route.continued, route.aborted) == (0, 1)
    assert recorder.events == []


def test_capture_all_resources_includes_static_resources() -> None:
    _capture_instance, recorder, context = _capture(capture_all_resources=True)
    image = _Request("https://target.test/logo.png", resource_type="image")

    context.emit("request", image)
    context.route_request(image)
    context.emit("requestfinished", image)

    assert [event["event_type"] for event in recorder.events] == ["request", "requestfinished"]
    request = recorder.events[0]["request"]
    assert isinstance(request, dict)
    assert request["resource_type"] == "image"


def test_failed_service_worker_style_request_never_reads_frame() -> None:
    _capture_instance, recorder, context = _capture()
    request = _Request("https://target.test/api/slow", resource_type="fetch")
    request.failure = "net::ERR_FAILED token=failure-secret"

    context.emit("request", request)
    context.route_request(request)
    context.emit("requestfailed", request)
    context.emit("requestfinished", request)  # Late duplicate terminal event is ignored.

    assert [event["event_type"] for event in recorder.events] == ["request", "requestfailed"]
    assert "failure-secret" not in json.dumps(recorder.events)


def test_recorder_failure_is_observable_but_does_not_break_routing() -> None:
    class BrokenRecorder:
        def record_browser_event(self, _event: Mapping[str, object], /) -> None:
            message = "password=recorder-secret"
            raise RuntimeError(message)

    capture = BrowserTrafficCapture(
        recorder=BrokenRecorder(),
        scope_predicate=lambda _url: True,
        capture_session_id="capture-test",
    )
    context = _Context()
    capture.attach(context)
    request = _Request("https://target.test/")

    context.emit("request", request)
    route = context.route_request(request)

    assert (route.continued, route.aborted) == (1, 0)
    assert capture.recorder_errors == ("password=[REDACTED]",)


def test_one_capture_cannot_be_attached_twice() -> None:
    capture, _recorder, _context = _capture()

    with pytest.raises(RuntimeError, match="already attached"):
        capture.attach(_Context())


def test_websocket_handshakes_are_scope_checked_before_connect() -> None:
    seen: list[str] = []

    def predicate(url: str) -> _Decision:
        seen.append(url)
        return _Decision(url == "https://target.test/socket", "outside engagement")

    _capture_instance, _recorder, context = _capture(predicate=predicate)

    allowed = context.route_websocket("wss://target.test/socket")
    blocked = context.route_websocket("wss://outside.test/socket")

    assert seen == ["https://target.test/socket", "https://outside.test/socket"]
    assert allowed.connected == 1
    assert allowed.closed == []
    assert blocked.connected == 0
    assert blocked.closed == [(1008, "outside engagement")]


def test_request_limit_blocks_additional_routes_and_bounds_active_state() -> None:
    recorder = _Recorder()
    capture = BrowserTrafficCapture(
        recorder=recorder,
        scope_predicate=lambda _url: True,
        capture_all_resources=True,
        capture_session_id="capture-test",
        max_requests=1,
    )
    context = _Context()
    capture.attach(context)

    first = _Request("https://target.test/first")
    context.emit("request", first)
    first_route = context.route_request(first)
    context.emit("requestfinished", first)
    second = _Request("https://target.test/second")
    context.emit("request", second)
    second_route = context.route_request(second)

    assert first_route.continued == 1
    assert second_route.aborted == 1
    assert "additional requests were blocked" in capture.recorder_errors[0]
    assert len(capture._states) == 0  # noqa: SLF001 - verifies the memory bound.
