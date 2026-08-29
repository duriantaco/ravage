from __future__ import annotations

import html
import json
import re
from typing import cast
from urllib.parse import parse_qs, urlencode, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.command.command import probe_command_boundary
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

_INLINE_PROOF = "flag{command_boundary_proof_4f2a9d}"


def _session(value: object) -> ProbeSession:
    return cast(ProbeSession, value)


def _finding_proofs(finding: dict[str, object]) -> list[str]:
    proofs = finding.get("proofs")
    if not isinstance(proofs, list):
        return []
    return [str(proof) for proof in proofs]


def _apache_lane_request_count(session: _ApacheCgiTraversalSession) -> int:
    cgi_requests = sum(1 for _method, url, _body in session.requests if "/cgi-bin/" in url)
    return 1 + cgi_requests  # The Apache lane's banner baseline plus CGI requests.


class _CommandProofSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def fork(self, *, timeout_seconds: int | None = None) -> _CommandProofSession:
        if timeout_seconds is not None:
            self.timeout_seconds = timeout_seconds
        return self

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("POST", url, data=urlencode(fields).encode("utf-8"))

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        if data:
            fields.update({key: values[-1] for key, values in parse_qs(data.decode("utf-8", "ignore")).items()})
        value = fields.get("ip_address", "")
        marker_match = re.search(r"echo (RAVAGE_CMD_[A-Fa-f0-9]+)", value)
        if marker_match:
            body = f"Ping Result\n{marker_match.group(1)}\n"
        elif "cat /flag" in value:
            body = f"Ping Result\n{_INLINE_PROOF}\n"
        else:
            body = "Ping Result\n"
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)


class _EscapedReflectionSession(_CommandProofSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        if data:
            fields.update({key: values[-1] for key, values in parse_qs(data.decode("utf-8", "ignore")).items()})
        value = fields.get("ip_address", "")
        body = f"<h1>Ping Result for {html.escape(value)}</h1><pre>Host is reachable!</pre>"
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)


class _BlindCommandSession(_EscapedReflectionSession):
    files: dict[str, str] = {}

    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        super().__init__(target_url, timeout_seconds=timeout_seconds)
        self.files = {}

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        path = urlsplit(url).path
        if method == "GET" and path in self.files:
            return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=self.files[path])
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        if data:
            fields.update({key: values[-1] for key, values in parse_qs(data.decode("utf-8", "ignore")).items()})
        value = fields.get("ip_address", "")
        drop_match = re.search(r">\s*(?:\./)?static/(ravage_[a-z0-9_]+\.txt)", value)
        if drop_match:
            self.files[f"/static/{drop_match.group(1)}"] = _INLINE_PROOF
        elapsed = 2500 if "sleep 2" in value else 20
        body = f"<h1>Ping Result for {html.escape(value)}</h1><pre>Host is reachable!</pre>"
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=elapsed, body=body)


class _ParserOnlyBlindCommandSession(_EscapedReflectionSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        if data:
            fields.update({key: values[-1] for key, values in parse_qs(data.decode("utf-8", "ignore")).items()})
        value = fields.get("ip_address", "")
        if any(char in value for char in "<>|&"):
            body = "Invalid input, please try again."
            elapsed = 20
        elif "printf '2 packets transmitted" in value and value.startswith("invalid.invalid;"):
            body = (
                "Packets Transmitted: 2, "
                f"Packets Received: {_INLINE_PROOF}, "
                "Packet Loss: 0%"
            )
            elapsed = 20
        elif "sleep 2" in value and "test " not in value:
            body = "Failed to parse ping output"
            elapsed = 2500
        else:
            body = "Failed to parse ping output"
            elapsed = 20
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=elapsed, body=body)


class _OptionStyleCommandSession(_EscapedReflectionSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        if data:
            fields.update({key: values[-1] for key, values in parse_qs(data.decode("utf-8", "ignore")).items()})
        value = fields.get("ip_address", "")
        if value.startswith("-t custom echo "):
            body = value.removeprefix("-t custom echo ")
        elif value.startswith("-t custom cat "):
            body = _INLINE_PROOF
        else:
            body = "status ok"
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)


class _ApacheCgiTraversalSession:
    def __init__(self, target_url: str = "http://127.0.0.1/", *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds
        self.requests: list[tuple[str, str, str]] = []

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def fork(self, *, timeout_seconds: int | None = None) -> _ApacheCgiTraversalSession:
        if timeout_seconds is not None:
            self.timeout_seconds = timeout_seconds
        return self

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute_url = self.absolute(url)
        command = data.decode("utf-8", "ignore") if data else ""
        self.requests.append((method, absolute_url, command))
        body = ""
        if method == "POST" and "/cgi-bin/" in url and url.endswith("/bin/sh") and data:
            marker = _apache_split_marker(command)
            if marker:
                body = marker
            elif "head -c 8192 -- '/FLAG.txt'" in command:
                body = _INLINE_PROOF
        return ProbeResponse(
            method=method,
            url=absolute_url,
            status=200,
            final_url=absolute_url,
            elapsed_ms=5,
            headers={"server": "Apache/2.4.49"},
            body=body,
        )


class _ApacheTraversalFileReadSession(_ApacheCgiTraversalSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        absolute_url = self.absolute(url)
        body = ""
        if method == "GET" and absolute_url.endswith("/etc/passwd") and (
            "/cgi-bin/.%25%32%65/" in absolute_url or "/cgi-bin/.%%32%65/" in absolute_url
        ):
            body = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        elif method == "GET" and (
            "/cgi-bin/.%25%32%65/" in absolute_url or "/cgi-bin/.%%32%65/" in absolute_url
        ) and absolute_url.endswith("/FLAG.txt"):
            body = _INLINE_PROOF
        return ProbeResponse(
            method=method,
            url=absolute_url,
            status=200,
            final_url=absolute_url,
            elapsed_ms=5,
            headers={"server": "Apache/2.4.50"},
            body=body,
        )


class _ApacheLateRawCgiTraversalSession(_ApacheCgiTraversalSession):
    def __init__(self) -> None:
        super().__init__()
        self.requests: list[tuple[str, str, str]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute_url = self.absolute(url)
        command = data.decode("utf-8", "ignore") if data else ""
        self.requests.append((method, absolute_url, command))
        body = ""
        if method == "POST" and "/.%%32%65/" in absolute_url and absolute_url.endswith("/bin/sh"):
            marker = _apache_split_marker(command)
            if marker:
                body = marker
            elif "head -c 8192 -- '/FLAG.txt'" in command:
                body = "flag{apache_late_raw_command}"
        return ProbeResponse(
            method=method,
            url=absolute_url,
            status=200,
            final_url=absolute_url,
            elapsed_ms=5,
            headers={"server": "Apache/2.4.50"},
            body=body,
        )


class _ApacheDepthFiveCgiTraversalSession(_ApacheCgiTraversalSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute_url = self.absolute(url)
        command = data.decode("utf-8", "ignore") if data else ""
        self.requests.append((method, absolute_url, command))
        body = ""
        if (
            method == "POST"
            and absolute_url.count("/.%%32%65") == 5
            and absolute_url.endswith("/bin/sh")
        ):
            body = _apache_split_marker(command)
        return ProbeResponse(
            method=method,
            url=absolute_url,
            status=200,
            final_url=absolute_url,
            elapsed_ms=5,
            headers={"server": "Apache/2.4.50"},
            body=body,
        )


class _PatchedApacheOptionStyleCommandSession(_OptionStyleCommandSession):
    def __init__(self) -> None:
        super().__init__("http://127.0.0.1/")
        self.cgi_requests = 0

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        if "/cgi-bin/" in url:
            self.cgi_requests += 1
        response = super().request(method, url, data=data, headers=headers)
        response.headers["server"] = "Apache/2.4.50"
        return response


def _apache_split_marker(command: str) -> str:
    match = re.search(r"printf '%s%s' '([^']*)' '([^']*)'", command)
    if match is None:
        return ""
    return match.group(1) + match.group(2)


class _JsonOptionStyleCommandSession:
    def __init__(self, target_url: str = "http://127.0.0.1/", *, timeout_seconds: int = 10) -> None:
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

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute_url = self.absolute(url)
        body = "status ok"
        if method == "POST" and urlsplit(absolute_url).path == "/check_service" and data:
            payload = json.loads(data.decode("utf-8"))
            value = str(payload.get("service_name") or "")
            if value == "-t custom id":
                body = json.dumps({"status": "uid=1000(app) gid=1000(app)\ntrue"})
            elif value == "-t custom cat</FLAG.txt":
                body = json.dumps({"status": f"{_INLINE_PROOF}\ntrue"})
            else:
                body = json.dumps({"status": "true"})
        return ProbeResponse(
            method=method,
            url=absolute_url,
            status=200,
            final_url=absolute_url,
            elapsed_ms=5,
            body=body,
        )


def _state_with_ping_form() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/ping",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [
            {
                "id": "ping",
                "action": "http://127.0.0.1/ping",
                "method": "POST",
                "inputs": [{"name": "ip_address", "type": "text"}],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/ping", "hints": ["command_boundary"]}],
    }
    return state


def _state_with_json_service_endpoint() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [
            {
                "url": "http://127.0.0.1/check_service",
                "name": "service_name",
                "hints": ["json", "command_boundary"],
            }
        ],
    }
    return state


def test_command_boundary_checks_apache_cgi_traversal_rce() -> None:
    session = _ApacheCgiTraversalSession()
    result = probe_command_boundary(_session(session), AgentState())

    assert result.ok
    assert any(
        finding.get("proof_kind") == "controlled_execution_marker"
        for finding in result.findings
    )
    assert any(request.get("probe_kind") == "apache_cgi_traversal_signal" for request in result.requests)
    assert not any(
        request.get("probe_kind") == "apache_cgi_traversal_proof"
        for request in result.requests
    )
    assert all("find /" not in body and "cat " not in body for _method, _url, body in session.requests)


def test_command_boundary_apache_flag_closure_is_explicit_and_bounded() -> None:
    session = _ApacheCgiTraversalSession()
    state = AgentState()
    state.surface["flag_objective"] = True
    result = probe_command_boundary(_session(session), state)

    assert result.ok
    proofs = [finding.get("proof") for finding in result.findings if finding.get("type") == "command_boundary_proof"]
    assert _INLINE_PROOF in proofs
    assert _apache_lane_request_count(session) <= 16
    assert all("find /" not in body and "cat " not in body for _method, _url, body in session.requests)
    assert any("head -c 8192" in body for _method, _url, body in session.requests)


def test_command_boundary_reaches_late_raw_percent_cgi_and_sanitizes_discovery() -> None:
    session = _ApacheLateRawCgiTraversalSession()
    state = AgentState()
    state.surface["flag_objective"] = True

    result = probe_command_boundary(_session(session), state)

    assert result.ok
    proofs = [finding.get("proof") for finding in result.findings if finding.get("type") == "command_boundary_proof"]
    assert "flag{apache_late_raw_command}" in proofs
    assert any("/.%%32%65/" in url for _method, url, _body in session.requests)
    assert all("find /" not in body and "cat " not in body for _method, _url, body in session.requests)
    assert _apache_lane_request_count(session) <= 16


def test_command_boundary_reaches_depth_five_cgi_with_default_budget() -> None:
    session = _ApacheDepthFiveCgiTraversalSession()

    result = probe_command_boundary(_session(session), AgentState())

    assert result.ok
    assert any(
        finding.get("proof_kind") == "controlled_execution_marker"
        and finding.get("input", {}).get("depth") == 5
        for finding in result.findings
    )
    assert _apache_lane_request_count(session) <= 16
    assert all(
        method == "POST" and url.endswith("/bin/sh")
        for method, url, _body in session.requests
        if "/cgi-bin/" in url
    )


def test_patched_apache_does_not_starve_generic_command_form() -> None:
    session = _PatchedApacheOptionStyleCommandSession()

    result = probe_command_boundary(_session(session), _state_with_ping_form())

    assert result.ok
    assert any(_INLINE_PROOF in _finding_proofs(finding) for finding in result.findings)
    assert session.cgi_requests == 14


def test_command_boundary_checks_json_option_style_custom_command() -> None:
    result = probe_command_boundary(
        _session(_JsonOptionStyleCommandSession()),
        _state_with_json_service_endpoint(),
    )

    assert result.ok
    proof_findings = [finding for finding in result.findings if finding.get("type") == "command_boundary_proof"]
    assert proof_findings
    assert _INLINE_PROOF in _finding_proofs(proof_findings[0])
    assert any(request.get("probe_kind") == "command_json_option_proof" for request in result.requests)
