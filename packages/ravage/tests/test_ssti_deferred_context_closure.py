# ruff: noqa: CPY001

from __future__ import annotations

import threading
from collections import Counter
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urljoin, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.seed_portfolio import (
    build_seed_portfolio,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
)
from ravage.probe_suite import available_probes, run_builtin_probe
from ravage.probes.ssti_deferred_context import (
    deferred_ssti_contract,
    probe_ssti_deferred_context_closure,
)
from ravage.web_core.http_probe import ProbeResponse

if TYPE_CHECKING:
    from collections.abc import Iterator

EXPECTED_PROOF = "flag{deferred-context-closure}"
EXPECTED_PAYLOAD = "{{ messages.storages.0.signer.key }}"
BASE_DIGEST = "a" * 64
EXPECTED_REQUEST_COUNT = 5
MAX_REQUEST_COUNT = 28
MAX_REQUESTS_PER_PAYLOAD = 7


class _DeferredContextHandler(BaseHTTPRequestHandler):
    stored_name = ""
    emit_proof = True

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:
        if self.path.startswith("/accounts/register/step1/"):
            self._send(
                200,
                '<form action="/accounts/register/step1/" method="post">'
                '<input type="hidden" name="csrfmiddlewaretoken" value="token-1">'
                '<input name="name" type="text">'
                '<input name="password" type="password" minlength="10">'
                '<button type="submit">Next</button></form>',
            )
            return
        if self.path.startswith("/accounts/register/step2/"):
            self._send(
                200,
                '<form action="/accounts/register/step2/" method="post">'
                '<input name="email" type="email">'
                '<button type="submit">Next</button></form>',
            )
            return
        if self.path.startswith("/accounts/register/step3/"):
            rendered = (
                f"b'django.http.cookies{EXPECTED_PROOF}'"
                if self.emit_proof and self.stored_name == EXPECTED_PAYLOAD
                else self.stored_name
            )
            self._send(
                200,
                '<form action="/accounts/register/step3/" method="post">'
                '<input type="hidden" name="csrfmiddlewaretoken" value="token-3">'
                '<input name="is_premium" type="checkbox">'
                '<button type="submit">Complete</button></form>'
                f'<script>alert("Hello {rendered}")</script>',
            )
            return
        self._send(404, "not found")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        fields = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if self.path == "/accounts/register/step1/":
            if fields.get("csrfmiddlewaretoken", [""])[0] != "token-1":
                self._send(403, "csrf rejected")
                return
            type(self).stored_name = fields.get("name", [""])[0]
            self._redirect("/accounts/register/step2/")
            return
        if self.path == "/accounts/register/step2/":
            self._redirect("/accounts/register/step3/")
            return
        if self.path == "/accounts/register/step3/":
            self._redirect("/accounts/register/step1/")
            return
        self._send(400, "invalid")

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Set-Cookie", "sessionid=deferred; Path=/; HttpOnly")
        self.end_headers()

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


class _WorkflowSession:
    """Socket-free HTTP contract simulation for deterministic route tests."""

    def __init__(self, target_url: str, *, emit_proof: bool) -> None:
        self.target_url = target_url
        self.timeout_seconds = 5
        self.emit_proof = emit_proof
        self.stored_name = ""

    def fork(self, *, timeout_seconds: int | None = None) -> _WorkflowSession:
        forked = type(self)(self.target_url, emit_proof=self.emit_proof)
        forked.timeout_seconds = timeout_seconds or self.timeout_seconds
        return forked

    def in_scope(self, url: str) -> bool:
        return urlsplit(urljoin(self.target_url, url)).netloc == urlsplit(self.target_url).netloc

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = headers
        absolute = urljoin(self.target_url, url)
        path = urlsplit(absolute).path
        if path == "/accounts/register/step1/":
            return self._response(
                "GET",
                absolute,
                body=(
                    '<form action="/accounts/register/step1/" method="post">'
                    '<input type="hidden" name="csrfmiddlewaretoken" value="token-1">'
                    '<input name="name" type="text">'
                    '<input name="password" type="password" minlength="10">'
                    '<button type="submit">Next</button></form>'
                ),
            )
        if path == "/accounts/register/step2/":
            return self._response(
                "GET",
                absolute,
                body=(
                    '<form action="/accounts/register/step2/" method="post">'
                    '<input name="email" type="email">'
                    '<button type="submit">Next</button></form>'
                ),
            )
        if path == "/accounts/register/step3/":
            rendered = (
                f"b'django.http.cookies{EXPECTED_PROOF}'"
                if self.emit_proof and self.stored_name == EXPECTED_PAYLOAD
                else self.stored_name
            )
            return self._response(
                "GET",
                absolute,
                body=(
                    '<form action="/accounts/register/step3/" method="post">'
                    '<input type="hidden" name="csrfmiddlewaretoken" value="token-3">'
                    '<input name="is_premium" type="checkbox">'
                    '<button type="submit">Complete</button></form>'
                    f'<script>alert("Hello {rendered}")</script>'
                ),
            )
        return self._response("GET", absolute, status=404, body="not found")

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = headers
        absolute = urljoin(self.target_url, url)
        path = urlsplit(absolute).path
        if path == "/accounts/register/step1/":
            self.stored_name = fields.get("name", "")
            return self._redirect(absolute, "/accounts/register/step2/")
        if path == "/accounts/register/step2/":
            return self._redirect(absolute, "/accounts/register/step3/")
        if path == "/accounts/register/step3/":
            return self._redirect(absolute, "/accounts/register/step1/")
        return self._response("POST", absolute, status=400, body="invalid")

    @staticmethod
    def _response(
        method: str,
        url: str,
        *,
        status: int = 200,
        body: str = "",
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        return ProbeResponse(
            method=method,
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=1,
            headers=headers,
            body=body,
        )

    def _redirect(self, url: str, location: str) -> ProbeResponse:
        return self._response(
            "POST",
            url,
            status=302,
            headers={"location": location},
        )


@contextmanager
def _target(*, emit_proof: bool = True) -> Iterator[str]:
    _DeferredContextHandler.stored_name = ""
    _DeferredContextHandler.emit_proof = emit_proof
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DeferredContextHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _state(target_url: str) -> AgentState:
    endpoint = target_url + "accounts/register/step1/"
    state = AgentState(
        facts=["deferred_form_flow_signal confirmed on a multi-step registration workflow"],
        primitives={"ssti_confirmed": 3},
    )
    state.surface["forms"] = [
        {
            "action": endpoint,
            "method": "POST",
            "categories": ["auth", "csrf", "registration"],
            "inputs": [
                {
                    "name": "csrfmiddlewaretoken",
                    "type": "hidden",
                    "value": "token-1",
                },
                {"name": "name", "type": "text", "value": ""},
                {
                    "name": "password",
                    "type": "password",
                    "minlength": "10",
                    "value": "",
                },
            ],
        }
    ]
    return state


def test_deferred_context_probe_closes_confirmed_multi_step_ssti() -> None:
    with _target() as target_url:
        result = run_builtin_probe(
            "ssti_deferred_context_closure",
            target_url=target_url,
            state=_state(target_url),
            timeout_seconds=5,
        )

    assert result.ok is True
    assert result.findings[0]["type"] == "ssti_deferred_context_proof"
    assert result.findings[0]["proof"] == EXPECTED_PROOF
    assert result.findings[0]["payload"] == EXPECTED_PAYLOAD
    assert len(result.requests) == EXPECTED_REQUEST_COUNT


def test_deferred_context_probe_stops_cycles_at_exact_request_cap() -> None:
    with _target(emit_proof=False) as target_url:
        result = run_builtin_probe(
            "ssti_deferred_context_closure",
            target_url=target_url,
            state=_state(target_url),
            timeout_seconds=5,
        )

    payload_counts = Counter(str(item["payload"]) for item in result.requests)
    assert result.ok is False
    assert len(result.requests) == MAX_REQUEST_COUNT
    assert max(payload_counts.values()) == MAX_REQUESTS_PER_PAYLOAD
    assert all(
        count == 1
        for count in Counter(
            (
                str(item["payload"]),
                str(item["phase"]),
                str(item["final_url"]),
            )
            for item in result.requests
        ).values()
    )


def test_socket_free_deferred_context_proof_and_cycle_contracts() -> None:
    target_url = "http://127.0.0.1:8765/"
    solved = probe_ssti_deferred_context_closure(
        _WorkflowSession(target_url, emit_proof=True),  # type: ignore[arg-type]
        _state(target_url),
    )
    exhausted = probe_ssti_deferred_context_closure(
        _WorkflowSession(target_url, emit_proof=False),  # type: ignore[arg-type]
        _state(target_url),
    )

    payload_counts = Counter(str(item["payload"]) for item in exhausted.requests)
    assert solved.ok is True
    assert solved.findings[0]["proof"] == EXPECTED_PROOF
    assert solved.findings[0]["payload"] == EXPECTED_PAYLOAD
    assert len(solved.requests) == EXPECTED_REQUEST_COUNT
    assert exhausted.ok is False
    assert len(exhausted.requests) == MAX_REQUEST_COUNT
    assert max(payload_counts.values()) == MAX_REQUESTS_PER_PAYLOAD


def test_deferred_context_probe_is_inactive_without_confirmed_ssti() -> None:
    state = AgentState(
        facts=["registration form observed"],
        surface={"forms": []},
    )

    result = run_builtin_probe(
        "ssti_deferred_context_closure",
        target_url="http://127.0.0.1:8765/",
        state=state,
    )

    assert result.ok is False
    assert "inactive" in result.summary


def test_seed_portfolio_binds_deferred_ssti_to_observed_registration_form() -> None:
    target_url = "http://127.0.0.1:8765/"
    state = _state(target_url)
    state.signals["endpoints"] = [
        target_url + "socket.io/?EIO=4&transport=websocket",
        target_url + "accounts/register/step1/",
    ]
    base = BaseRouteOutcome(
        target_url=target_url,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest=BASE_DIGEST,
        state_ref="frozen-state.json",
    )

    contract = deferred_ssti_contract(state)
    portfolio = build_seed_portfolio(state, base=base, limit=4)
    objective = portfolio.objectives[0]

    assert contract is not None
    assert objective.probe == "ssti_deferred_context_closure"
    assert objective.endpoint.endswith("/accounts/register/step1/")
    assert "socket.io" not in objective.endpoint
    assert set(objective.inputs) == {
        "csrfmiddlewaretoken",
        "name",
        "password",
    }
    assert all(item.probe != "ssti_fingerprint" for item in portfolio.objectives)
    shadowed_ssti = [
        item
        for item in portfolio.suppressed
        if item.reason == "confirmed_deferred_closure_supersedes_generic_fingerprint"
    ]
    assert shadowed_ssti
    assert all(item.objective.probe == "ssti_fingerprint" for item in shadowed_ssti)
    assert all(
        item.reason == "confirmed_deferred_closure_supersedes_generic_fingerprint"
        for item in shadowed_ssti
    )


def test_deferred_context_closure_is_registered() -> None:
    assert "ssti_deferred_context_closure" in {item["name"] for item in available_probes()}
