from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.ssrf import probe_ssrf_boundary
from ravage.web_core.http_probe import ProbeResponse

if TYPE_CHECKING:
    from ravage.probe_suite_parts.result import ProbeRunResult

_SSRF_PROOF = "flag{ssrf_admin_flag_path}"


def _ssrf_proofs(result: ProbeRunResult) -> list[str]:
    proofs: list[str] = []
    for finding in result.findings:
        if finding.get("type") != "ssrf_extracted_proof":
            continue
        raw_proofs = finding.get("proofs")
        if isinstance(raw_proofs, list):
            proofs.extend(str(proof) for proof in raw_proofs)
    return proofs


def _request_target_kind(request: dict[str, object]) -> object:
    target = request.get("target")
    if not isinstance(target, dict):
        return None
    return target.get("kind")


class _LocalhostAdminSsrfSession:
    def __init__(
        self,
        target_url: str = "http://127.0.0.1/convert",
        *,
        timeout_seconds: int = 10,
    ) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        payload = str(fields.get("url") or "")
        body = "converted: not found"
        if payload.rstrip("/") in {"http://127.0.0.1", "http://localhost"}:
            body = "<h1>Flask localhost admin interface</h1>"
        elif urlsplit(payload).path == "/admin/flag":
            body = _SSRF_PROOF
        elif urlsplit(payload).path == "/admin":
            body = "<h1>Admin</h1><a href='/admin/flag'>flag</a>"
        return ProbeResponse(
            method="POST",
            url=self.absolute(url),
            status=200,
            final_url=self.absolute(url),
            elapsed_ms=5,
            body=body,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        return ProbeResponse(
            method=method,
            url=self.absolute(url),
            status=200,
            final_url=self.absolute(url),
            elapsed_ms=5,
            body="converted: not found",
        )


class _WeakSignalLocalhostAdminSsrfSession(_LocalhostAdminSsrfSession):
    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        payload = str(fields.get("url") or "")
        body = "converted: not found"
        if urlsplit(payload).path == "/admin/flag":
            body = _SSRF_PROOF
        elif urlsplit(payload).path == "/admin":
            body = "<h1>Admin</h1><a href='/admin/flag'>flag</a>"
        return ProbeResponse(
            method="POST",
            url=self.absolute(url),
            status=200,
            final_url=self.absolute(url),
            elapsed_ms=5,
            body=body,
        )


class _MappedPortLocalhostAdminSsrfSession(_WeakSignalLocalhostAdminSsrfSession):
    def __init__(
        self,
        target_url: str = "http://127.0.0.1:57183/convert",
        *,
        timeout_seconds: int = 10,
    ) -> None:
        super().__init__(target_url, timeout_seconds=timeout_seconds)
        self.origin = "http://127.0.0.1:57183"

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        payload = str(fields.get("url") or "")
        parsed = urlsplit(payload)
        body = "converted: not found"
        if parsed.path == "/admin/flag" and parsed.netloc in {"127.0.0.1", "localhost"}:
            body = _SSRF_PROOF
        return ProbeResponse(
            method="POST",
            url=self.absolute(url),
            status=200,
            final_url=self.absolute(url),
            elapsed_ms=5,
            body=body,
        )


class _ObservedInternalPortSsrfSession(_LocalhostAdminSsrfSession):
    def __init__(
        self,
        target_url: str = "http://127.0.0.1:57183/admin/preview",
        *,
        timeout_seconds: int = 10,
    ) -> None:
        super().__init__(target_url, timeout_seconds=timeout_seconds)
        self.origin = "http://127.0.0.1:57183"

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        payload = str(dict(parse_qsl(urlsplit(absolute).query)).get("url") or "")
        parsed = urlsplit(payload)
        body = "preview failed: not found"
        if parsed.netloc == "127.0.0.1:9000" and parsed.path == "/metadata":
            body = '{"service":"internal metadata","flag_endpoint":"/flag"}'
        elif parsed.netloc == "127.0.0.1:9000" and parsed.path == "/flag":
            body = _SSRF_PROOF
        return ProbeResponse(
            method="GET",
            url=absolute,
            status=200,
            final_url=absolute,
            elapsed_ms=5,
            body=body,
        )


class _AuthenticatedObservedInternalPortSsrfSession(_ObservedInternalPortSsrfSession):
    expected_cookie = "acme_session=forged-admin-token"

    def __init__(self) -> None:
        super().__init__()
        self.headers_seen: list[dict[str, str]] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        observed = dict(headers or {})
        self.headers_seen.append(observed)
        if observed.get("Cookie") != self.expected_cookie:
            absolute = self.absolute(url)
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=403,
                final_url=absolute,
                elapsed_ms=5,
                body="login required",
            )
        return super().get(url, headers=headers)


def test_ssrf_boundary_prioritizes_observed_internal_form_url() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1:57183/admin/preview",
        "origin": "http://127.0.0.1:57183",
        "parameters": [],
        "forms": [
            {
                "action": "http://127.0.0.1:57183/admin/preview",
                "method": "GET",
                "inputs": [
                    {
                        "name": "url",
                        "type": "url",
                        "value": "http://127.0.0.1:9000/metadata",
                    }
                ],
            }
        ],
    }

    result = probe_ssrf_boundary(_ObservedInternalPortSsrfSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert _SSRF_PROOF in _ssrf_proofs(result)
    assert any(
        str(request.get("payload") or "") == "http://127.0.0.1:9000/flag"
        for request in result.requests
    )


def test_ssrf_boundary_replays_preserved_form_auth_headers() -> None:
    session = _AuthenticatedObservedInternalPortSsrfSession()
    state = AgentState()
    state.surface = {
        "target_url": session.target_url,
        "origin": session.origin,
        "parameters": [],
        "forms": [],
    }
    state.signals = {
        "parameters": ["url"],
        "forms": [
            json.dumps(
                {
                    "action": session.target_url,
                    "method": "GET",
                    "auth_headers": {"Cookie": session.expected_cookie},
                    "inputs": [
                        {
                            "name": "url",
                            "type": "url",
                            "value": "http://127.0.0.1:9000/metadata",
                        }
                    ],
                },
                sort_keys=True,
            )
        ],
    }

    result = probe_ssrf_boundary(session, state)  # type: ignore[arg-type]

    assert result.ok
    assert _SSRF_PROOF in _ssrf_proofs(result)
    assert result.requests[0]["target"]["kind"] == "form"
    assert len(result.requests) <= 6
    assert session.headers_seen
    assert all(headers.get("Cookie") == session.expected_cookie for headers in session.headers_seen)


def test_ssrf_boundary_extracts_localhost_admin_flag_path() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/convert",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [
            {
                "action": "http://127.0.0.1/convert",
                "method": "POST",
                "inputs": [{"name": "url", "type": "url"}],
            }
        ],
    }

    result = probe_ssrf_boundary(_LocalhostAdminSsrfSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert _SSRF_PROOF in _ssrf_proofs(result)
    assert any("/admin/flag" in str(request.get("payload")) for request in result.requests)


def test_ssrf_boundary_extracts_admin_flag_without_initial_signal() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/convert",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [
            {
                "action": "http://127.0.0.1/convert",
                "method": "POST",
                "inputs": [{"name": "url", "type": "url"}],
            }
        ],
    }

    result = probe_ssrf_boundary(_WeakSignalLocalhostAdminSsrfSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert _SSRF_PROOF in _ssrf_proofs(result)
    assert any("/admin/flag" in str(request.get("payload")) for request in result.requests)


def test_ssrf_boundary_tries_post_form_for_url_parameter_locations() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "url",
                "locations": ["http://127.0.0.1/convert"],
                "hints": ["url"],
            }
        ],
        "forms": [],
    }

    result = probe_ssrf_boundary(_WeakSignalLocalhostAdminSsrfSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert _SSRF_PROOF in _ssrf_proofs(result)
    assert any(_request_target_kind(request) == "post_form_param" for request in result.requests)


def test_ssrf_boundary_prioritizes_internal_loopback_over_mapped_port() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1:57183/",
        "origin": "http://127.0.0.1:57183",
        "parameters": [
            {
                "name": "url",
                "locations": ["http://127.0.0.1:57183/convert"],
                "hints": ["url"],
            }
        ],
        "forms": [],
    }

    result = probe_ssrf_boundary(_MappedPortLocalhostAdminSsrfSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert _SSRF_PROOF in _ssrf_proofs(result)
    assert any(
        str(request.get("payload")) == "http://127.0.0.1/admin/flag"
        for request in result.requests
    )
