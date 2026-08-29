from __future__ import annotations

from urllib.parse import urljoin

import pytest
from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.general.general import probe_surface_map
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

_SURFACE_REQUEST_COUNT = 13
_OK_STATUS = 200


class _SurfaceMapSession(ProbeSession):
    def __init__(self, outcomes: list[tuple[int | None, str]]) -> None:
        self.target_url = "http://127.0.0.1:8765/"
        self._outcomes = outcomes
        self.requested_urls: list[str] = []

    def absolute(self, value: str) -> str:
        return urljoin(self.target_url, value)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        index = len(self.requested_urls)
        self.requested_urls.append(url)
        status, error = self._outcomes[min(index, len(self._outcomes) - 1)]
        return ProbeResponse(
            method="GET",
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=2,
            body="reachable" if status is not None else "",
            error=error,
        )


def test_surface_map_fails_when_every_request_has_a_transport_error() -> None:
    session = _SurfaceMapSession(
        [
            (None, "  request   timed out  "),
            (None, "connection refused"),
        ]
    )

    result = probe_surface_map(session, AgentState())

    assert result.ok is False
    assert result.summary == "received 0/13 HTTP response(s), notable=0"
    assert result.errors == [
        "transport error (1 request): request timed out",
        "transport error (12 requests): connection refused",
    ]
    assert len(result.requests) == _SURFACE_REQUEST_COUNT
    assert all(request["status"] is None for request in result.requests)


@pytest.mark.parametrize("reachable_status", [200, 404, 503])
def test_surface_map_succeeds_when_any_request_receives_an_http_status(
    reachable_status: int,
) -> None:
    session = _SurfaceMapSession(
        [
            (None, "connection refused"),
            (reachable_status, ""),
        ]
    )

    result = probe_surface_map(session, AgentState())

    assert result.ok is True
    assert result.summary.startswith("received 12/13 HTTP response(s)")
    assert result.errors == []
    assert result.requests[0]["status"] is None
    assert result.requests[1]["status"] == reachable_status


def test_surface_map_preserves_the_normal_success_summary_and_findings() -> None:
    session = _SurfaceMapSession([(_OK_STATUS, "")])

    result = probe_surface_map(session, AgentState())

    assert result.ok is True
    assert result.summary == "fetched 13 URL(s), notable=13"
    assert result.errors == []
    assert len(result.findings) == _SURFACE_REQUEST_COUNT
    assert len(result.requests) == _SURFACE_REQUEST_COUNT
    assert all(request["status"] == _OK_STATUS for request in result.requests)
