from __future__ import annotations

import json

import pytest
from ravage.web_core.http_probe import ProbeResponse
from ravage.web_core.poc_validator import validate_http_poc


def test_validate_http_poc_dispatches_and_reports_path_steps() -> None:
    calls: list[dict[str, object]] = []
    events: list[dict[str, object]] = []

    def request(
        method: str,
        url: str,
        *,
        data: bytes | None,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> ProbeResponse:
        calls.append(
            {
                "method": method,
                "url": url,
                "data": data,
                "headers": headers,
                "timeout_seconds": timeout_seconds,
            }
        )
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=f"http://127.0.0.1{url}",
            elapsed_ms=1,
            body="path proof",
        )

    result = validate_http_poc(
        target_url="http://127.0.0.1/",
        steps=[
            {
                "method": "GET",
                "path": "/path-proof",
                "expect_status": 200,
                "expect_contains": "path proof",
            }
        ],
        timeout_seconds=7,
        request=request,
        on_step=events.append,
    )

    assert result.ok
    assert calls == [
        {
            "method": "GET",
            "url": "/path-proof",
            "data": None,
            "headers": {},
            "timeout_seconds": 7,
        }
    ]
    assert result.steps[0]["request"] == {
        "method": "GET",
        "url": "/path-proof",
        "has_body": False,
    }
    assert events[0]["url"] == "/path-proof"


def test_validate_http_poc_preserves_declared_method_for_form_replay() -> None:
    calls: list[tuple[str, str, bytes | None, dict[str, str]]] = []

    def request(
        method: str,
        url: str,
        *,
        data: bytes | None,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> ProbeResponse:
        del timeout_seconds
        calls.append((method, url, data, headers))
        return ProbeResponse(
            method=method,
            url=url,
            status=204,
            final_url=f"http://127.0.0.1{url}",
            elapsed_ms=1,
        )

    result = validate_http_poc(
        target_url="http://127.0.0.1/",
        steps=[
            {
                "method": "PATCH",
                "path": "/profile",
                "form": {"name": "guest"},
                "expect_status": 204,
            }
        ],
        request=request,
    )

    assert result.ok
    assert calls == [
        (
            "PATCH",
            "/profile",
            b"name=guest",
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
    ]


def test_validate_http_poc_sanitizes_artifacts_without_changing_dispatch() -> None:
    request_url = (
        "/callback?view=request-query&token=request-token#request-fragment"
    )
    request_headers = {
        "Authorization": "Bearer request-authorization",
        "X-Debug": "request-header-secret",
    }
    calls: list[dict[str, object]] = []
    events: list[dict[str, object]] = []

    def request(
        method: str,
        url: str,
        *,
        data: bytes | None,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> ProbeResponse:
        calls.append(
            {
                "method": method,
                "url": url,
                "data": data,
                "headers": headers,
                "timeout_seconds": timeout_seconds,
            }
        )
        return ProbeResponse(
            method=method,
            url=url,
            status=502,
            final_url=(
                "https://target.example/final"
                "?view=final-query&code=final-code#final-fragment"
            ),
            elapsed_ms=1,
            headers={
                "Content-Type": "text/plain; charset=utf-8",
                "Location": (
                    "https://target.example/next"
                    "?view=location-query&session=location-session#location-fragment"
                ),
                "Set-Cookie": "session=response-cookie",
                "X-Debug": "response-header-secret",
            },
            body="ordinary response evidence",
            error=(
                "request to https://alice:error-password@target.example/fail"
                "?view=error-query#error-fragment failed; "
                "Authorization: Bearer error-authorization"
            ),
        )

    result = validate_http_poc(
        target_url="https://target.example/",
        steps=[
            {
                "method": "GET",
                "url": request_url,
                "headers": request_headers,
                "expect_contains": "flag{authored_expectation_secret_73c9}",
            }
        ],
        timeout_seconds=7,
        request=request,
        on_step=events.append,
    )

    assert calls == [
        {
            "method": "GET",
            "url": request_url,
            "data": None,
            "headers": request_headers,
            "timeout_seconds": 7,
        }
    ]
    serialized = json.dumps(
        {"result": json.loads(result.to_text()), "events": events},
        sort_keys=True,
    )
    for secret in (
        "request-query",
        "request-token",
        "request-fragment",
        "final-query",
        "final-code",
        "final-fragment",
        "location-query",
        "location-session",
        "location-fragment",
        "response-cookie",
        "response-header-secret",
        "alice",
        "error-password",
        "error-query",
        "error-fragment",
        "error-authorization",
        "authored_expectation_secret_73c9",
    ):
        assert secret not in serialized
    step = result.steps[0]
    request_artifact = step["request"]
    assert isinstance(request_artifact, dict)
    assert request_artifact["url"] == (
        "/callback?view=%5BREDACTED%5D&token=%5BREDACTED%5D"
    )
    response_artifact = step["response"]
    assert isinstance(response_artifact, dict)
    assert response_artifact["final_url"] == (
        "https://target.example/final?view=%5BREDACTED%5D&code=%5BREDACTED%5D"
    )
    response_headers = response_artifact["headers"]
    assert isinstance(response_headers, dict)
    assert response_headers["location"] == (
        "https://target.example/next?view=%5BREDACTED%5D&session=%5BREDACTED%5D"
    )
    assert response_headers["set-cookie"] == "[REDACTED]"
    assert response_headers["x-debug"] == "[REDACTED]"
    assert events[0]["url"] == request_artifact["url"]
    assert events[0]["headers"] == response_headers


@pytest.mark.parametrize(
    ("step", "error"),
    [
        ({"method": "GET", "path": "/item", "body": "payload"}, "cannot include a body"),
        ({"method": "POST", "path": "/item", "json": {"key": "value"}}, "support json"),
        ({"method": "POST", "path": "/item", "headers": []}, "headers must be an object"),
        ({"method": "POST", "path": "/item", "form": []}, "form must be an object"),
        ({"method": "POST", "path": "/item", "body": 7}, "body must be a string"),
    ],
)
def test_validate_http_poc_rejects_invalid_steps_before_dispatch(
    step: dict[str, object],
    error: str,
) -> None:
    call_count = 0

    def request(*_args: object, **_kwargs: object) -> ProbeResponse:
        nonlocal call_count
        call_count += 1
        return ProbeResponse("GET", "", 500, "", 0)

    result = validate_http_poc(
        target_url="http://127.0.0.1/",
        steps=[step],
        request=request,
    )

    assert not result.ok
    assert call_count == 0
    assert any(error in item for item in result.errors)
