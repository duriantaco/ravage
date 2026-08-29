# ruff: noqa: CPY001

from __future__ import annotations

import hashlib
import json
import re
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs
from uuid import UUID

from ravage.agent_core.action_executor import _run_probe_action
from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.agent_core.ai_agent import AIWebAgentSettings, ChatMessage, ModelReply
from ravage.agent_core.autonomous_graph import production
from ravage.agent_core.autonomous_graph.campaigns import campaigns_for_objective
from ravage.agent_core.autonomous_graph.config import graph_config_for_budget
from ravage.agent_core.autonomous_graph.coverage_ledger import CoverageStage
from ravage.agent_core.autonomous_graph.model_bridge import GraphModelEndpoint
from ravage.agent_core.autonomous_graph.models import GraphObjective, GraphStatus
from ravage.agent_core.autonomous_graph.production import run_autonomous_graph_route
from ravage.agent_core.autonomous_graph.runtime import RuntimeCleanupReceipt
from ravage.agent_core.frontier_route import BaseRouteOutcome, BaseRouteTermination
from ravage.model_core.providers import ResolvedModelRoute
from ravage.probe_suite import available_probes, run_builtin_probe
from ravage.runtime import FakeToolRuntime

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    import pytest

_EXPECTED_PROOF = "flag{production_dispatch_auth_transition}"
_MAX_REQUESTS = 64
_GRAPH_REQUEST_LIMIT = 12
_ENGAGEMENT_ID = UUID("99999999-9999-4999-9999-999999999999")


class _TargetState:
    def __init__(self, *, transition_enabled: bool) -> None:
        self.transition_enabled = transition_enabled
        self.login_attempts: list[dict[str, str]] = []
        self.protected_auth_requests = 0
        self.uploads: dict[str, bytes] = {}


class _Handler(BaseHTTPRequestHandler):
    server: _TargetServer

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.php", "/login", "/login.php", "/signin", "/signin.php"}:
            self._send(200, _login_page())
            return
        if path in {"/dashboard", "/dashboard.php"}:
            if not self._authenticated():
                self._send(302, "", headers={"Location": "/"})
                return
            self.server.target_state.protected_auth_requests += 1
            self._send(200, _dashboard_page())
            return
        if path.startswith("/uploaded_invoices/"):
            filename = path.rsplit("/", 1)[-1]
            body = self.server.target_state.uploads.get(filename)
            if body is None:
                self._send(404, "not found")
                return
            if b"file_get_contents" in body:
                self._send(200, _EXPECTED_PROOF)
                return
            self._send(200, body.decode("utf-8", errors="replace"))
            return
        self._send(404, "not found")

    def do_POST(self) -> None:
        if self.path == "/login":
            self._login()
            return
        if self.path == "/upload":
            self._upload()
            return
        self._send(404, "not found")

    def _login(self) -> None:
        fields = _form_fields(self._body())
        self.server.target_state.login_attempts.append(fields)
        controls_valid = fields.get("csrf") == "target-token" and fields.get("submit") == "submit"
        password = fields.get("password", "")
        transition = (
            self.server.target_state.transition_enabled
            and controls_valid
            and fields.get("username") == "admin"
            and "MD5('admin')" in password
            and "OR 1=1" in password
        )
        if transition:
            self._send(
                200,
                '{"response":"Success"}',
                headers={"Set-Cookie": "session=authenticated; Path=/"},
            )
            return
        if not self.server.target_state.transition_enabled and fields.get("username") == "admin":
            self._send(
                200,
                "Please try again",
                headers={"Set-Cookie": "session=anonymous; Path=/"},
            )
            return
        denied_field = "password" if fields.get("username") == "admin" else "username"
        self._send(
            200,
            json.dumps({"response": denied_field}),
            headers={"Set-Cookie": "session=anonymous; Path=/"},
        )

    def _upload(self) -> None:
        if not self._authenticated():
            self._send(403, "forbidden")
            return
        body = self._body()
        match = re.search(rb'filename="([^"]+)"', body)
        if match is None:
            self._send(400, "missing file")
            return
        filename = match.group(1).decode("utf-8", errors="replace")
        if ".pdf" not in filename.lower():
            self._send(200, "Upload failed. Allowed file types: pdf")
            return
        self.server.target_state.uploads[filename] = body
        self._send(200, "File is successfully uploaded to /uploaded_invoices/")

    def _authenticated(self) -> bool:
        return "session=authenticated" in self.headers.get("Cookie", "")

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def _send(
        self,
        status: int,
        body: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _TargetServer(ThreadingHTTPServer):
    target_state: _TargetState


def _login_page() -> str:
    return """
    <html><body>
      <form method="post" action="/login">
        <input type="hidden" name="csrf" value="target-token">
        <input type="text" name="username">
        <input type="password" name="password">
        <button type="submit" name="submit" value="submit">Sign in</button>
      </form>
    </body></html>
    """


def _dashboard_page() -> str:
    return """
    <html><body>
      <h1>Invoice dashboard</h1>
      <a href="/logout">Logout</a>
      <form method="post" action="/upload" enctype="multipart/form-data">
        <label>Upload PDF invoice</label>
        <input type="file" name="invoice" accept="application/pdf">
      </form>
    </body></html>
    """


def _form_fields(body: bytes) -> dict[str, str]:
    decoded = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {name: values[0] for name, values in decoded.items() if values}


@contextmanager
def _target(*, transition_enabled: bool = True) -> Iterator[tuple[str, _TargetState]]:
    state = _TargetState(transition_enabled=transition_enabled)
    server = _TargetServer(("127.0.0.1", 0), _Handler)
    server.target_state = state
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_registered_probe_closes_real_http_auth_and_upload() -> None:
    assert "sqli_auth_transition" in {item["name"] for item in available_probes()}
    with _target() as (target_url, target_state):
        result = run_builtin_probe(
            "sqli_auth_transition",
            target_url=target_url,
            state=AgentState(),
            timeout_seconds=3,
        )

    assert result.ok
    assert _EXPECTED_PROOF in result.to_text()
    transition = next(
        finding
        for finding in result.findings
        if finding.get("capability") == "sqli_auth_transition"
    )
    assert transition["authenticated"] is True
    assert transition["same_session"] is True
    assert transition["technique"] == "password_nested_function_parenthesis"
    assert transition["proofs"] == [_EXPECTED_PROOF]
    assert len(result.requests) <= _MAX_REQUESTS
    assert target_state.protected_auth_requests >= 1
    assert target_state.login_attempts[0]["csrf"] == "target-token"
    assert target_state.login_attempts[0]["submit"] == "submit"


def test_failure_cookie_is_not_accepted_as_authentication() -> None:
    with _target(transition_enabled=False) as (target_url, target_state):
        result = run_builtin_probe(
            "sqli_auth_transition",
            target_url=target_url,
            state=AgentState(),
            timeout_seconds=3,
        )

    assert not result.ok
    assert "sqli_auth_transition_exhausted" in result.to_text()
    assert _EXPECTED_PROOF not in result.to_text()
    assert target_state.protected_auth_requests == 0
    assert len(result.requests) <= _MAX_REQUESTS


def test_schema_words_cannot_displace_admin_transition_candidate() -> None:
    noisy_state = AgentState(
        surface={
            "username": "input",
            "user": "file",
            "login": "session",
            "email": "data",
            "name": "command",
            "cookie": {"name": "PHPSESSID"},
        },
    )
    with _target() as (target_url, target_state):
        result = run_builtin_probe(
            "sqli_auth_transition",
            target_url=target_url,
            state=noisy_state,
            timeout_seconds=3,
        )

    assert result.ok
    assert _EXPECTED_PROOF in result.to_text()
    assert any(
        attempt.get("username") == "admin" and "MD5('admin')" in attempt.get("password", "")
        for attempt in target_state.login_attempts
    )
    assert not any(
        attempt.get("username") in {"input", "file", "session", "data", "command", "PHPSESSID"}
        for attempt in target_state.login_attempts
    )
    assert len(result.requests) <= _MAX_REQUESTS


def test_subprocess_probe_dispatch_runs_the_registered_worker() -> None:
    with _target() as (target_url, _target_state):
        result = _run_probe_action(
            "sqli_auth_transition",
            target_url=target_url,
            state=AgentState(),
            timeout_seconds=5,
        )

    assert result.ok
    payload = json.loads(result.text)
    assert payload["probe"] == "sqli_auth_transition"
    assert _EXPECTED_PROOF in result.text


def test_credential_recovery_recommends_the_finite_transition_campaign() -> None:
    objective = GraphObjective.create(
        family="credential_recovery",
        instruction=(
            "The stored password representation was rejected as plaintext; close the "
            "preserved username/password login contract."
        ),
        endpoint="/login",
        inputs=("username", "password"),
        strategy="credential_representation_recovery",
        expected_signal="protected same-session access or bounded counter-evidence",
    )

    campaigns = campaigns_for_objective(objective, stage=CoverageStage.CLOSURE)

    assert campaigns
    assert any(campaign.probe == "sqli_auth_transition" for campaign in campaigns)


class _VerifiedRuntime(FakeToolRuntime):
    network_isolation_verified = True
    runtime_manifest_identity = "test-sqli-auth-transition-verified-runtime-v1"

    def __init__(self) -> None:
        super().__init__()
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


class _FakeProcessRuntime:
    network_isolation_verified = True

    def close(self) -> RuntimeCleanupReceipt:
        return RuntimeCleanupReceipt(
            verified=True,
            processes_before=(),
            processes_after=(),
            backend={"verified": True, "kind": "fixture"},
        )


class _TransitionGraphClient:
    def __init__(self) -> None:
        self.auth_campaigns: list[str] = []
        self.auth_probe_calls = 0

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        del route
        context = json.loads(
            next(message.content for message in reversed(messages) if message.role == "user")
        )
        objective = context["node"]["objective"]
        strategy = str(objective["strategy"])
        if strategy == "sqli_auth_transition":
            campaigns = context["investigation"]["recommended_campaigns"]
            self.auth_campaigns = [str(item["probe"]) for item in campaigns]
            proof_refs = _message_proof_refs(messages)
            if proof_refs:
                action = {
                    "kind": "submit_proof",
                    "payload": {"evidence_refs": proof_refs},
                    "rationale": "submit independently promoted target proof",
                }
            else:
                self.auth_probe_calls += 1
                action = {
                    "kind": "execute",
                    "payload": {
                        "tool": "run_probe",
                        "arguments": {
                            "probe": "sqli_auth_transition",
                            "strategy": "sql-auth-transition-and-session-closure",
                            "expected_signal": (
                                "protected same-session access and exact proof or "
                                "bounded transition exhaustion"
                            ),
                        },
                        "expected_signal": (
                            "protected same-session access and exact proof or "
                            "bounded transition exhaustion"
                        ),
                    },
                    "rationale": "run the first ranked finite campaign",
                }
        elif str(objective["family"]) == "graph_coordination":
            action = {
                "kind": "wait",
                "payload": {"timeout_seconds": 0},
                "rationale": "wait for bounded seeded specialists",
            }
        else:
            action = {
                "kind": "finish",
                "payload": {
                    "summary": "lower-ranked route yielded to auth closure",
                    "evidence_refs": [],
                },
                "rationale": "avoid unrelated duplicate exploration",
            }
        return ModelReply(
            content=json.dumps(action),
            cost_usd=0.01,
            usage_reported=True,
            cost_known=True,
        )


def _message_proof_refs(messages: list[ChatMessage]) -> list[str]:
    for message in reversed(messages):
        content = message.content
        if message.role == "user" and content.startswith("GRAPH_TOOL_OBSERVATION\n"):
            content = content.split("\n", 1)[1]
        elif message.role != "tool":
            continue
        try:
            payload = json.loads(content)
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            continue
        refs = evidence.get("proof_refs")
        if isinstance(refs, list) and refs:
            return [str(item) for item in refs]
    return []


def _graph_model_route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="high",
        selected_tier="high",
        ordinal=1,
        provider="ollama",
        model="fixture-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=512,
        output_token_limit_parameter="max_tokens",  # noqa: S106
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=30,
        max_retries=0,
    )


def _write_graph_brief(path: Path, *, target_url: str) -> None:
    path.write_text(
        f"""
engagement_id: "{_ENGAGEMENT_ID}"
scope:
  in_scope:
    - "{target_url}"
  out_of_scope: []
roe:
  max_rps: 20
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "capture_flag"
budget:
  max_cost_usd: 3.0
  max_runtime_min: 10
context:
  description: "Authorized local authentication and upload exercise"
""".lstrip(),
        encoding="utf-8",
    )


def _graph_base(path: Path, *, target_url: str) -> BaseRouteOutcome:
    form = {
        "action": f"{target_url.rstrip('/')}/login",
        "method": "POST",
        "inputs": [
            {"name": "csrf", "type": "hidden", "value": "target-token"},
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
        ],
    }
    save_agent_state(
        path,
        target_url=target_url,
        state=AgentState(
            turn=40,
            primitives={"sqli_confirmed": 6},
            signals={"forms": [json.dumps(form, sort_keys=True)]},
            facts=["Confirmed login SQL primitive needs authenticated closure."],
        ),
    )
    return BaseRouteOutcome(
        target_url=target_url,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest=hashlib.sha256(path.read_bytes()).hexdigest(),
        state_ref=str(path),
        cost_usd=0.5,
    )


def test_production_graph_dispatches_real_transition_probe_and_closes_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _target() as (target_url, target_state):
        brief_path = tmp_path / "brief.yaml"
        base_path = tmp_path / "base-working-state.json"
        _write_graph_brief(brief_path, target_url=target_url)
        base = _graph_base(base_path, target_url=target_url)
        frozen_before = base_path.read_bytes()
        client = _TransitionGraphClient()
        runtime = _VerifiedRuntime()
        monkeypatch.setattr(
            production,
            "select_graph_model_portfolio",
            lambda _settings: (
                GraphModelEndpoint(
                    client=client,
                    route=_graph_model_route(),
                ),
            ),
        )
        monkeypatch.setattr(
            production,
            "_make_process_runtime",
            lambda **_kwargs: _FakeProcessRuntime(),
        )
        monkeypatch.setattr(
            production,
            "reverify_tool_runtime_cleanup",
            lambda _runtime: (
                {
                    "cleanup": {
                        "verified": True,
                        "status": "verified",
                    }
                },
            ),
        )

        result = run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=target_url,
            base=base,
            settings=AIWebAgentSettings(
                workspace_dir=tmp_path / "base-workspace",
                tool_runtime=runtime,
                model_client=client,
                proof_recognition_enabled=True,
            ),
            workspace_dir=tmp_path / "agent-graph",
            config=graph_config_for_budget(_GRAPH_REQUEST_LIMIT),
        )

    assert base_path.read_bytes() == frozen_before
    assert result.graph.status is GraphStatus.SOLVED
    assert result.cleanup_verified is True
    assert result.route_model_requests <= _GRAPH_REQUEST_LIMIT
    assert client.auth_campaigns[0] == "sqli_auth_transition"
    assert client.auth_probe_calls == 1
    assert target_state.protected_auth_requests >= 1
    assert any(
        "MD5('admin')" in attempt.get("password", "") for attempt in target_state.login_attempts
    )
    assert runtime.close_count == 1
