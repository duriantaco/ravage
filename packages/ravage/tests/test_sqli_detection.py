from __future__ import annotations

import pytest
from ravage.probe_suite_parts.sqli.sqli import _probe_sqli_errors, _probe_sqli_timing
from ravage.probe_suite_parts.sqli.sqli_detection import (
    _boolean_sql_signal,
    _sql_error_markers,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession


class _StaticBodySession(ProbeSession):
    def __init__(self, body: str) -> None:
        self.target_url = "http://example.test/search"
        self._body = body

    def get(self, url: str) -> ProbeResponse:
        return ProbeResponse(
            method="GET",
            url=url,
            status=500,
            final_url=url,
            elapsed_ms=1,
            body=self._body,
        )


class _ElapsedSequenceSession(ProbeSession):
    def __init__(self, elapsed_values: list[int], *, statuses: list[int] | None = None) -> None:
        self.target_url = "http://example.test/search"
        self._elapsed_values = iter(elapsed_values)
        self._statuses = iter(statuses) if statuses is not None else None

    def get(self, url: str) -> ProbeResponse:
        return ProbeResponse(
            method="GET",
            url=url,
            status=next(self._statuses) if self._statuses is not None else 200,
            final_url=url,
            elapsed_ms=next(self._elapsed_values),
            body="same response",
        )


def _response(body: str) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url="http://example.test/search?q=ravage",
        status=200,
        final_url="http://example.test/search?q=ravage",
        elapsed_ms=1,
        body=body,
    )


@pytest.mark.parametrize(
    "body",
    [
        "Syntax error: expected an expression",
        "JSON syntax error at byte 14",
        "Warning: invalid character in configuration",
    ],
)
def test_generic_parser_errors_are_not_sql_error_markers(body: str) -> None:
    assert _sql_error_markers(body) == []


@pytest.mark.parametrize(
    ("body", "expected_marker"),
    [
        ("sqlite3.OperationalError: near quote", "sqlite"),
        ("You have an error in your SQL syntax", "sql syntax"),
        ("psycopg error: syntax error at or near quote", "syntax error at or near"),
        ("XPATH syntax error: invalid expression", "xpath syntax error"),
    ],
)
def test_database_specific_errors_remain_sql_error_markers(
    body: str,
    expected_marker: str,
) -> None:
    assert expected_marker in _sql_error_markers(body)


def test_generic_syntax_error_does_not_confirm_sql_injection() -> None:
    finding, requests, remaining = _probe_sqli_errors(
        _StaticBodySession("Syntax error: expected an expression"),
        {
            "kind": "query",
            "url": "http://example.test/search",
            "input": "q",
        },
        baseline=_response("normal result"),
        budget=2,
    )

    assert finding is None
    assert len(requests) == 2  # noqa: PLR2004 - exact bounded probe count is the contract.
    assert remaining == 0


@pytest.mark.parametrize(
    "body",
    [
        "Validation exception: malformed query parameter",
        "Warning: request rejected by policy",
        "Forbidden: unauthorized request",
        "Traceback: template rendering failed",
    ],
)
def test_non_database_error_delta_does_not_confirm_sql_injection(body: str) -> None:
    finding, requests, remaining = _probe_sqli_errors(
        _StaticBodySession(body),
        {
            "kind": "query",
            "url": "http://example.test/search",
            "input": "q",
        },
        baseline=_response("normal result"),
        budget=2,
    )

    assert finding is None
    assert len(requests) == 2  # noqa: PLR2004 - exact bounded probe count is the contract.
    assert remaining == 0


def test_database_specific_error_still_confirms_sql_injection() -> None:
    finding, requests, remaining = _probe_sqli_errors(
        _StaticBodySession("sqlite3.OperationalError: near quote"),
        {
            "kind": "query",
            "url": "http://example.test/search",
            "input": "q",
        },
        baseline=_response("normal result"),
        budget=2,
    )

    assert finding is not None
    assert finding["type"] == "sql_injection_error_signal"
    assert len(requests) == 1
    assert remaining == 1


def test_single_timing_spike_does_not_confirm_sql_injection() -> None:
    finding, requests, remaining = _probe_sqli_timing(
        _ElapsedSequenceSession([2_000, 10, 10]),
        {
            "kind": "query",
            "url": "http://example.test/search",
            "input": "q",
        },
        baseline=_response("same response"),
        budget=3,
        payloads=["1' OR SLEEP(2)-- -"],
    )

    assert finding is None
    assert [request["probe_kind"] for request in requests] == [
        "timing",
        "timing_control",
        "timing_repeat",
    ]
    assert remaining == 0


def test_slow_retryable_responses_do_not_confirm_timing_sql_injection() -> None:
    finding, requests, remaining = _probe_sqli_timing(
        _ElapsedSequenceSession([2_000, 10, 2_000], statuses=[503, 200, 503]),
        {
            "kind": "query",
            "url": "http://example.test/search",
            "input": "q",
        },
        baseline=_response("same response"),
        budget=3,
        payloads=["1' OR SLEEP(2)-- -"],
    )

    assert finding is None
    assert len(requests) == 3  # noqa: PLR2004 - exact confirmation sequence.
    assert remaining == 0


@pytest.mark.parametrize("unstable_status", [429, 502, 503, 504])
def test_retryable_status_delta_does_not_confirm_boolean_sql_injection(
    unstable_status: int,
) -> None:
    baseline = _response("normal result")
    true_response = ProbeResponse(
        method="GET",
        url=baseline.url,
        status=unstable_status,
        final_url=baseline.url,
        elapsed_ms=1,
        body="temporarily unavailable " + ("x" * 50),
    )
    false_response = _response("normal result")

    assert not _boolean_sql_signal(
        true_response,
        false_response,
        baseline,
        true_payload="1 OR 1=1",
        false_payload="1 OR 1=2",
    )
