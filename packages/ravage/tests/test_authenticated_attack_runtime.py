# ruff: noqa: PLR2004, S105, S106
from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.cookiejar import Cookie
from io import StringIO
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
from ai_agent_fixtures import ScriptedModelClient, VulnerableOpenApiHttpClient
from pentest_schemas import (
    AuthEndpoint,
    AuthenticationConfig,
    AuthFlow,
    AuthHealthCheck,
    AuthIdentity,
    AuthStaticHeader,
    Budget,
    EngagementBrief,
    RulesOfEngagement,
    Scope,
    SecretReference,
)
from ravage.agent_core import action_executor
from ravage.agent_core.action_executor import execute_action
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _assert_authenticated_state_artifacts_safe,
    _assert_authenticated_state_identity,
    _authenticated_model_action,
    _build_messages,
    _focus_authenticated_prompt,
    _make_tool_runtime,
    run_ai_web_agent,
)
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
    graph_operational_profile,
)
from ravage.agent_core.autonomous_graph.scoped_http import ScopedGraphHttpExecutor
from ravage.agent_core.frontier_adapter import (
    _assert_authenticated_state_identity as _assert_frontier_identity,
)
from ravage.agent_core.frontier_shared_runtime import make_shared_tool_runtime
from ravage.auth import (
    AuthArtifactRedactor,
    AuthenticationError,
    ConfiguredAuthenticationError,
    ManagedAttackAuthentication,
    MappingSecretResolver,
    SecretValue,
    build_authenticated_attack_runtime,
)
from ravage.auth import runtime as auth_runtime
from ravage.model_core.providers import ResolvedModelRoute
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import NoProcessToolRuntime, ToolResult, ToolRuntime
from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController
from ravage.web_core.http_probe import MAX_BODY_BYTES, ProbeResponse, ProbeSession
from ravage.web_core.poc_validator import ValidationResult, validate_http_poc

if TYPE_CHECKING:
    from pathlib import Path


_TARGET = "https://127.0.0.1:18731/"
_TOKEN = "service-token-must-not-leak"


def _cookie(name: str, value: str) -> Cookie:
    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain="127.0.0.1",
        domain_specified=False,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=True,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": ""},
        rfc2109=False,
    )


@dataclass
class _Backend:
    requests: list[dict[str, object]] = field(default_factory=list)
    sessions_created: int = 0
    expire_health_checks: int = 0
    health_always_expired: bool = False
    unauthorized_reads: int = 0
    target_error: str = ""
    health_error: str = ""
    rotate_health_cookie_to: str = ""
    switch_cookie_to: str = ""
    protected_body: str = f"protected flag{{{_TOKEN}}}"


class _RuntimeSession(ProbeSession):
    backend = _Backend()

    def __init__(self, target_url: str, **kwargs: object) -> None:
        timeout_seconds = kwargs.get("timeout_seconds", 10)
        max_body_bytes = kwargs.get("max_body_bytes", MAX_BODY_BYTES)
        traffic_policy = kwargs.get("traffic_policy")
        traffic_policy_reference = kwargs.get("traffic_policy_reference")
        assert isinstance(timeout_seconds, int)
        assert isinstance(max_body_bytes, int)
        assert traffic_policy is None or isinstance(traffic_policy, TrafficPolicyController)
        assert traffic_policy_reference is None or isinstance(traffic_policy_reference, dict)
        super().__init__(
            target_url,
            timeout_seconds=timeout_seconds,
            traffic_policy=traffic_policy,
            traffic_policy_reference=traffic_policy_reference,
            max_body_bytes=max_body_bytes,
        )
        self.backend.sessions_created += 1
        self.session_number = self.backend.sessions_created
        self.form_authenticated = False

    def fork(
        self,
        *,
        timeout_seconds: int | None = None,
        inherit_identity: bool | None = None,
        max_body_bytes: int | None = None,
    ) -> ProbeSession:
        copy_identity = (
            self._fork_inherits_managed_identity if inherit_identity is None else inherit_identity
        )
        default_headers = dict(self.default_headers)
        if not copy_identity and self._managed_identity_header_names:
            default_headers = {
                name: value
                for name, value in default_headers.items()
                if name.casefold() not in self._managed_identity_header_names
            }
        forked = _RuntimeSession(
            self.target_url,
            timeout_seconds=self.timeout_seconds if timeout_seconds is None else timeout_seconds,
            traffic_policy=self.traffic_policy,
            max_body_bytes=self.max_body_bytes if max_body_bytes is None else max_body_bytes,
        )
        forked.default_headers.update(default_headers)
        forked._fork_inherits_managed_identity = self._fork_inherits_managed_identity
        forked._managed_identity_header_names = self._managed_identity_header_names
        forked._request_gate = self._request_gate
        forked._traffic_identity_alias_override = self._traffic_identity_alias_override
        if copy_identity:
            for cookie in self.cookies:
                forked.cookies.set_cookie(_cookie(cookie.name, cookie.value))
            if self._managed_request_delegate is not None:
                generation = self.managed_identity_generation
                lease = self.managed_identity_lease
                assert generation is not None
                assert lease is not None
                assert self._managed_session_observer is not None
                forked.bind_managed_request_delegate(
                    self._managed_request_delegate,
                    generation=generation,
                    lease=lease,
                    session_observer=self._managed_session_observer,
                    source_session=self,
                )
        return forked

    def _request_direct(  # noqa: C901, PLR0911, PLR0913 - deterministic test transport.
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        max_body_bytes: int | None = None,
    ) -> ProbeResponse:
        del data, timeout_seconds, max_body_bytes
        absolute = self.absolute(url)
        merged_headers = dict(self.default_headers)
        merged_headers.update(headers or {})
        gate_commit = None
        if self._request_gate is not None:
            candidate = self._request_gate(method, absolute)
            gate_commit = candidate if callable(candidate) else None
        self.backend.requests.append(
            {
                "session": self.session_number,
                "method": method.upper(),
                "url": absolute,
                "headers": merged_headers,
                "cookies": {cookie.name: cookie.value for cookie in self.cookies},
            }
        )
        if gate_commit is not None:
            gate_commit()
        if absolute.endswith("/login"):
            return self._response(
                method,
                absolute,
                body=(
                    '<form method="post" action="/sessions">'
                    '<input name="username"><input name="password" type="password">'
                    "</form>"
                ),
            )
        if absolute.endswith("/me"):
            if self.backend.health_error:
                raise RuntimeError(self.backend.health_error)
            if self.backend.health_always_expired:
                return self._response(method, absolute, body="Sign in")
            if self.backend.expire_health_checks:
                self.backend.expire_health_checks -= 1
                return self._response(method, absolute, body="Sign in")
            valid_auth_values = {_TOKEN, f"Bearer {_TOKEN}"}
            header_authenticated = bool(valid_auth_values & set(self.default_headers.values()))
            healthy = header_authenticated or self.form_authenticated
            if healthy and self.backend.rotate_health_cookie_to:
                self.cookies.set_cookie(_cookie("session", self.backend.rotate_health_cookie_to))
                self.backend.rotate_health_cookie_to = ""
            return self._response(
                method,
                absolute,
                status=200 if healthy else 401,
                body="Account settings" if healthy else "Sign in",
            )
        if self.backend.target_error:
            raise RuntimeError(self.backend.target_error)
        if absolute.endswith("/switch") and self.backend.switch_cookie_to:
            self.cookies.set_cookie(_cookie("session", self.backend.switch_cookie_to))
            return self._response(method, absolute, body="identity switched")
        if method.upper() in {"GET", "HEAD", "OPTIONS"} and self.backend.unauthorized_reads:
            self.backend.unauthorized_reads -= 1
            return self._response(method, absolute, status=401, body="Sign in")
        self.cookies.set_cookie(_cookie("runtime-session", "runtime-cookie-secret"))
        return self._response(
            method,
            absolute,
            body=self.backend.protected_body,
            headers={"set-cookie": "runtime-session=runtime-cookie-secret"},
        )

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        if self._managed_request_delegate is not None:
            return super().post_form(url, fields, headers=headers)
        del headers
        absolute = self.absolute(url)
        self.backend.requests.append(
            {
                "session": self.session_number,
                "method": "POST",
                "url": absolute,
                "headers": {},
            }
        )
        self.form_authenticated = fields == {
            "password": "correct-horse",
            "username": "alice",
        }
        if self.form_authenticated:
            self.cookies.set_cookie(_cookie("session", "alice-runtime-cookie"))
        return self._response(
            "POST",
            absolute,
            status=303 if self.form_authenticated else 401,
        )

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
            headers=headers or {},
            body=body,
        )


def _bearer_config() -> AuthenticationConfig:
    return AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="service",
                roles=["api"],
                flow=AuthFlow(
                    kind="bearer",
                    secret_refs={"token": SecretReference(key="SERVICE_TOKEN")},
                ),
                health_check=_health_check(),
            )
        ]
    )


def _form_config() -> AuthenticationConfig:
    return AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="alice",
                roles=["customer"],
                flow=AuthFlow(
                    kind="form",
                    endpoint=AuthEndpoint(url=f"{_TARGET}login", scope="target"),
                    secret_refs={
                        "username": SecretReference(key="ALICE_USERNAME"),
                        "password": SecretReference(key="ALICE_PASSWORD"),
                    },
                ),
                health_check=_health_check(),
            )
        ]
    )


def _static_header_config() -> AuthenticationConfig:
    return AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="service",
                roles=["api"],
                flow=AuthFlow(
                    kind="static_header",
                    static_header=AuthStaticHeader(
                        name="X-Custom-Identity",
                        value=SecretReference(key="CUSTOM_IDENTITY"),
                    ),
                ),
                health_check=_health_check(),
            )
        ]
    )


def _health_check() -> AuthHealthCheck:
    return AuthHealthCheck(
        endpoint=AuthEndpoint(url=f"{_TARGET}me", scope="target"),
        authenticated_marker="Account settings",
        unauthenticated_marker="Sign in",
    )


def _test_traffic_policy(path: Path) -> TrafficPolicyController:
    return TrafficPolicyController.open(
        path,
        target_url=_TARGET,
        config=TrafficPolicyConfig(),
    )


def _owner_traffic_policy_reference(
    owner: ManagedAttackAuthentication,
) -> dict[str, object]:
    traffic_policy = owner.traffic_policy
    assert traffic_policy is not None
    return traffic_policy.to_reference()


def _build_owner(  # noqa: PLR0913 - explicit test builder options.
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: AuthenticationConfig | None = None,
    identity: str = "service",
    values: dict[str, str] | None = None,
    traffic_policy: TrafficPolicyController | None = None,
    traffic_policy_reference: dict[str, object] | None = None,
) -> tuple[ManagedAttackAuthentication, _Backend]:
    backend = _Backend()
    _RuntimeSession.backend = backend
    monkeypatch.setattr(auth_runtime, "ProbeSession", _RuntimeSession)
    source = values or {"SERVICE_TOKEN": _TOKEN}
    owner = build_authenticated_attack_runtime(
        config=config or _bearer_config(),
        target_url=_TARGET,
        identity=identity,
        timeout_seconds=5,
        allow_remote_target=False,
        in_scope=(_TARGET,),
        out_of_scope=(),
        max_rps=5,
        secret_resolver=MappingSecretResolver(source, provider="environment"),
        traffic_policy=traffic_policy,
        traffic_policy_reference=traffic_policy_reference,
    )
    return owner, backend


def test_authenticated_protocol_preserves_probe_and_injection_but_redacts_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={
            "ALICE_USERNAME": "alice",
            "ALICE_PASSWORD": "correct-horse",
        },
    )
    try:
        probe = _authenticated_model_action(
            owner,
            {"action": "run_probe", "probe": "secret_sweep", "notes": "bounded"},
        )
        poc = _authenticated_model_action(
            owner,
            {
                "action": "validate_poc",
                "steps": [
                    {
                        "method": "POST",
                        "url": f"{_TARGET}login",
                        "form": {
                            "password": "' OR 1=1--",
                            "username": "guest",
                        },
                    }
                ],
                "notes": "never replay correct-horse",
            },
        )

        assert probe["action"] == "run_probe"
        assert probe["probe"] == "secret_sweep"
        assert poc["action"] == "validate_poc"
        assert poc["steps"][0]["form"] == {  # type: ignore[index]
            "password": "' OR 1=1--",
            "username": "guest",
        }
        assert "correct-horse" not in str(poc["notes"])
    finally:
        owner.close()


def test_authenticated_resume_rejects_short_secret_values_without_key_collisions(
) -> None:
    redactor = AuthArtifactRedactor((SecretValue("action"),))

    class AuthenticationStub:
        identity = "service"

        @staticmethod
        def contains_secret(value: str) -> bool:
            return redactor.contains_secret(value)

        @staticmethod
        def redact_text(value: str) -> str:
            return redactor.redact_text(value)

    owner = AuthenticationStub()
    clean = AgentState(
        actions=[{"action": "run_probe", "probe": "surface_map"}],
        surface={
            "authenticated_identity": "service",
            "session_mode": "identity:service",
        },
    )
    _assert_authenticated_state_artifacts_safe(
        clean,
        authentication=owner,  # type: ignore[arg-type]
        state_label="agent",
    )

    clean.facts.append("legacy state leaked action value")
    with pytest.raises(ValueError, match="untrusted authentication material"):
        _assert_authenticated_state_artifacts_safe(
            clean,
            authentication=owner,  # type: ignore[arg-type]
            state_label="agent",
        )


def test_managed_request_preflights_health_refreshes_and_never_falls_back_anonymous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = {"SERVICE_TOKEN": _TOKEN}
    owner, backend = _build_owner(monkeypatch, values=source)
    try:
        assert source == {"SERVICE_TOKEN": _TOKEN}
        assert owner.identity == "service"
        with pytest.raises(AttributeError):
            owner.identity = "other"  # type: ignore[misc]

        backend.requests.clear()
        backend.expire_health_checks = 1
        response = owner.request("GET", f"{_TARGET}protected")
        assert response.status == 200
        assert [str(call["url"]) for call in backend.requests] == [
            f"{_TARGET}me",
            f"{_TARGET}me",
            f"{_TARGET}protected",
        ]
        assert backend.requests[0]["session"] != backend.requests[-1]["session"]
        assert owner.redact(response.body) == "protected [REDACTED]"
        assert owner.redact("runtime-cookie-secret") == "[REDACTED]"

        backend.requests.clear()
        backend.health_always_expired = True
        with pytest.raises(AuthenticationError, match="managed auth") as exc:
            owner.request("GET", f"{_TARGET}must-not-dispatch")
        assert _TOKEN not in str(exc.value)
        assert not any(str(call["url"]).endswith("/must-not-dispatch") for call in backend.requests)

        owner.close()
        owner.close()
    finally:
        owner.close()


def test_managed_request_preserves_one_safe_read_retry_and_redacts_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(monkeypatch)
    try:
        backend.requests.clear()
        backend.unauthorized_reads = 1
        response = owner.request("GET", f"{_TARGET}protected")
        protected_calls = [
            call for call in backend.requests if str(call["url"]).endswith("/protected")
        ]
        assert response.status == 200
        assert len(protected_calls) == 2
        assert protected_calls[0]["session"] != protected_calls[1]["session"]

        backend.requests.clear()
        backend.target_error = f"transport exposed {_TOKEN} and runtime-cookie-secret"
        with pytest.raises(AuthenticationError, match="managed authenticated request") as exc:
            owner.request("GET", f"{_TARGET}explode")
        assert _TOKEN not in str(exc.value)
        assert "runtime-cookie-secret" not in str(exc.value)

        backend.target_error = ""
        backend.health_error = f"health exposed {_TOKEN}"
        with pytest.raises(AuthenticationError, match="managed authentication health") as exc:
            owner.session_for_probe()
        assert _TOKEN not in str(exc.value)
    finally:
        owner.close()


def test_form_auth_rejects_authorization_override_before_any_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"}
    owner, backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values=values,
    )
    try:
        backend.requests.clear()
        with pytest.raises(ConfiguredAuthenticationError, match="Authorization"):
            owner.request(
                "GET",
                f"{_TARGET}protected",
                headers={"Authorization": "Bearer model-injected-identity"},
            )
        assert backend.requests == []
    finally:
        owner.close()


def test_managed_authentication_requires_a_bound_traffic_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = TrafficPolicyController.open(
        tmp_path / "policy.json",
        target_url=_TARGET,
        config=TrafficPolicyConfig(),
    )
    unbound, _backend = _build_owner(monkeypatch)
    try:
        with pytest.raises(AuthenticationError, match="traffic policy binding mismatch"):
            unbound.assert_traffic_policy(None)
        with pytest.raises(AuthenticationError, match="traffic policy binding mismatch"):
            unbound.assert_traffic_policy(policy)
    finally:
        unbound.close()

    bound, _backend = _build_owner(monkeypatch, traffic_policy=policy)
    try:
        with pytest.raises(AuthenticationError, match="traffic policy binding mismatch"):
            bound.assert_traffic_policy(None)
    finally:
        bound.close()


def test_managed_authentication_exposes_and_verifies_exact_policy_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = TrafficPolicyConfig.low_noise(max_physical_requests=11, max_rps=3)
    policy_path = tmp_path / "owned-policy.json"
    policy = TrafficPolicyController.open(
        policy_path,
        target_url=f"{_TARGET}nested/path",
        config=config,
    )
    owner, _backend = _build_owner(monkeypatch, traffic_policy=policy)
    equivalent = TrafficPolicyController.open(
        tmp_path / "path-alias" / ".." / policy_path.name,
        target_url=_TARGET,
        config=config,
        require_existing=True,
    )
    try:
        assert owner.traffic_policy is policy
        assert owner.traffic_policy_binding is not None
        assert owner.traffic_policy_binding.state_path == policy_path.resolve(strict=True)
        assert owner.traffic_policy_binding.target_origin == policy.target_origin
        assert owner.traffic_policy_binding.config == config

        owner.assert_traffic_policy(policy)
        owner.assert_traffic_policy(equivalent)
    finally:
        owner.close()


def test_managed_authentication_retains_policy_resolved_from_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _test_traffic_policy(tmp_path / "referenced-policy.json")
    owner, _backend = _build_owner(
        monkeypatch,
        traffic_policy_reference=policy.to_reference(),
    )
    try:
        assert owner.traffic_policy is not None
        assert owner.traffic_policy is not policy
        owner.assert_traffic_policy(policy)
    finally:
        owner.close()


def test_managed_authentication_rejects_each_policy_binding_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = TrafficPolicyConfig.low_noise(max_physical_requests=11, max_rps=3)
    policy = TrafficPolicyController.open(
        tmp_path / "owned-policy.json",
        target_url=_TARGET,
        config=config,
    )
    mismatches = (
        TrafficPolicyController.open(
            tmp_path / "other-path.json",
            target_url=_TARGET,
            config=config,
        ),
        TrafficPolicyController.open(
            tmp_path / "other-config.json",
            target_url=_TARGET,
            config=TrafficPolicyConfig.low_noise(max_physical_requests=12, max_rps=3),
        ),
        TrafficPolicyController.open(
            tmp_path / "other-origin.json",
            target_url="https://127.0.0.1:18732/",
            config=config,
        ),
    )
    owner, _backend = _build_owner(monkeypatch, traffic_policy=policy)
    try:
        for mismatch in mismatches:
            with pytest.raises(AuthenticationError, match="traffic policy binding mismatch"):
                owner.assert_traffic_policy(mismatch)
    finally:
        owner.close()


@pytest.mark.parametrize(
    "header_name",
    [
        "API-Key",
        "Authorization",
        "Cookie",
        "Proxy-Authorization",
        "X-Access-Token",
        "X-API-Key",
        "X-Auth-Token",
        "x-custom-identity",
    ],
)
def test_model_action_session_rejects_every_protected_header_override(
    monkeypatch: pytest.MonkeyPatch,
    header_name: str,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_static_header_config(),
        values={"CUSTOM_IDENTITY": _TOKEN},
    )
    session = owner.session_for_model_action()
    try:
        backend.requests.clear()
        with pytest.raises(ConfiguredAuthenticationError, match="cannot override managed header"):
            session.get(
                f"{_TARGET}protected",
                headers={header_name: "model-injected-identity"},
            )
        assert backend.requests == []
    finally:
        owner.retire_probe_session(session)
        owner.close()


def test_model_action_session_rejects_mutated_custom_identity_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_static_header_config(),
        values={"CUSTOM_IDENTITY": _TOKEN},
    )
    session = owner.session_for_model_action()
    try:
        backend.requests.clear()
        session.default_headers["X-Custom-Identity"] = "model-injected-identity"
        with pytest.raises(ConfiguredAuthenticationError, match="X-Custom-Identity"):
            session.get(f"{_TARGET}protected")
        assert backend.requests == []
    finally:
        owner.retire_probe_session(session)
        owner.close()


def test_form_auth_managed_probe_fork_keeps_cookie_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"}
    owner, _backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values=values,
    )
    session = owner.session_for_probe()
    inherited = session.fork()
    try:
        anonymous = session.fork(inherit_identity=False)

        assert [(cookie.name, cookie.value) for cookie in inherited.cookies] == [
            ("session", "alice-runtime-cookie")
        ]
        assert inherited.managed_identity_generation == session.managed_identity_generation
        assert list(anonymous.cookies) == []
        assert anonymous.managed_identity_generation is None
    finally:
        owner.close()

    assert session.managed_identity_generation is None
    assert inherited.managed_identity_generation is None
    assert list(session.cookies) == []
    assert list(inherited.cookies) == []


def test_managed_probe_requests_recheck_refresh_and_retire_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(monkeypatch)
    session = owner.session_for_probe()
    try:
        initial_generation = session.managed_identity_generation
        backend.requests.clear()
        backend.expire_health_checks = 1

        refreshed = session.get(f"{_TARGET}protected")

        assert refreshed.status == 200
        assert session.managed_identity_generation != initial_generation
        protected = [call for call in backend.requests if str(call["url"]).endswith("/protected")]
        assert len(protected) == 1
        assert protected[0]["headers"] == {"Authorization": f"Bearer {_TOKEN}"}

        generation_after_health = session.managed_identity_generation
        backend.requests.clear()
        backend.unauthorized_reads = 1

        retried = session.get(f"{_TARGET}protected")

        assert retried.status == 200
        assert session.managed_identity_generation != generation_after_health
        protected = [call for call in backend.requests if str(call["url"]).endswith("/protected")]
        assert len(protected) == 2
        assert all(call["headers"] == {"Authorization": f"Bearer {_TOKEN}"} for call in protected)
        assert owner.redact("runtime-cookie-secret") == "[REDACTED]"

        generation_after_retry = session.managed_identity_generation
        backend.requests.clear()
        backend.unauthorized_reads = 1

        controlled = session.get(
            f"{_TARGET}protected",
            headers={"Cookie": "session=probe-controlled-value"},
        )

        assert controlled.status == 401
        assert session.managed_identity_generation == generation_after_retry
        protected = [call for call in backend.requests if str(call["url"]).endswith("/protected")]
        assert len(protected) == 1
        assert protected[0]["headers"] == {
            "Authorization": f"Bearer {_TOKEN}",
            "Cookie": "session=probe-controlled-value",
        }
    finally:
        owner.retire_probe_session(session)
        owner.close()

    assert session.managed_identity_generation is None
    assert "Authorization" not in session.default_headers
    assert list(session.cookies) == []


def test_managed_probe_syncs_same_generation_health_cookie_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
    )
    session = owner.session_for_probe()
    try:
        original_generation = session.managed_identity_generation
        backend.requests.clear()
        backend.rotate_health_cookie_to = "rotated-session-cookie"

        response = session.get(f"{_TARGET}protected")

        assert response.status == 200
        assert session.managed_identity_generation == original_generation
        protected = [call for call in backend.requests if str(call["url"]).endswith("/protected")]
        assert protected[-1]["cookies"] == {"session": "rotated-session-cookie"}
    finally:
        owner.retire_probe_session(session)
        owner.close()


def test_stale_managed_probe_descendant_syncs_same_generation_cookie_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
    )
    stale_parent = owner.session_for_probe()
    rotating_peer = owner.session_for_probe()
    descendant: ProbeSession | None = None
    try:
        original_generation = stale_parent.managed_identity_generation
        backend.rotate_health_cookie_to = "rotated-session-cookie"
        assert rotating_peer.get(f"{_TARGET}protected").status == 200
        assert rotating_peer.managed_identity_generation == original_generation
        assert [(cookie.name, cookie.value) for cookie in stale_parent.cookies] == [
            ("session", "alice-runtime-cookie")
        ]
        stale_parent.cookies.set_cookie(_cookie("workflow", "probe-local-state"))

        descendant = stale_parent.fork()
        backend.requests.clear()
        response = descendant.get(f"{_TARGET}protected")

        assert response.status == 200
        assert descendant.managed_identity_generation == original_generation
        protected = [call for call in backend.requests if str(call["url"]).endswith("/protected")]
        assert protected[-1]["cookies"] == {
            "session": "rotated-session-cookie",
            "workflow": "probe-local-state",
        }
    finally:
        if descendant is not None:
            owner.retire_probe_session(descendant)
        owner.retire_probe_session(rotating_peer)
        owner.retire_probe_session(stale_parent)
        owner.close()


def test_runtime_redaction_distinguishes_identity_labels_and_preference_cookies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"}
    owner, _backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values=values,
    )
    session = owner.session_for_probe()
    try:
        session.cookies.set_cookie(_cookie("theme", "1"))
        owner.retire_probe_session(session)

        assert owner.redact_text("alice analyzes a target") == "alice analyzes a target"
        assert owner.redact_text("alice") == "[REDACTED]"
        assert owner.redact_text("HTTP/1.1 returned 1 finding") == ("HTTP/1.1 returned 1 finding")
        assert owner.redact_text("1") == "[REDACTED]"
        assert owner.redact_text("Cookie: theme=1") == "Cookie: [REDACTED]"
    finally:
        owner.close()


class _TrackingRuntime(ToolRuntime):
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del command, target_url, timeout_seconds
        self.calls.append("command")
        return _tool_result()

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del code, target_url, timeout_seconds
        self.calls.append("python")
        return _tool_result()


def _tool_result() -> ToolResult:
    return ToolResult(
        ok=True,
        tool="unexpected",
        command=(),
        exit_code=0,
        stdout="unexpected",
        stderr="",
    )


@pytest.mark.parametrize("kind", ["run_command", "run_python"])
def test_authenticated_external_actions_are_blocked_without_invoking_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        traffic_policy=_test_traffic_policy(tmp_path / f"{kind}-traffic.json"),
    )
    runtime = _TrackingRuntime()
    workspace = AgentWorkspace.open(tmp_path / kind)
    audit = AuditStore(tmp_path / f"{kind}.db")
    action = {"action": kind, "command": "echo unsafe", "code": "print('unsafe')"}
    try:
        result = execute_action(
            action,
            target_url=_TARGET,
            runtime=runtime,
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
    finally:
        audit.close()
        owner.close()

    assert not result.ok
    assert result.outcome == "blocked"
    assert result.session_mode == "identity:service"
    assert runtime.calls == []


def test_authenticated_runtime_does_not_construct_a_process_or_docker_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _backend = _build_owner(monkeypatch)
    settings = AIWebAgentSettings(
        authentication=owner,
        allow_remote_target=True,
        tool_runtime_mode="docker",
    )
    try:
        runtime = _make_tool_runtime(settings, _brief(), target_url="https://target.example/")
        shared = make_shared_tool_runtime(settings, _brief())
    finally:
        owner.close()

    assert isinstance(runtime, NoProcessToolRuntime)
    assert isinstance(shared.inner, NoProcessToolRuntime)
    blocked = runtime.run_command(command="id", target_url="https://target.example/")
    assert not blocked.ok
    assert "managed authenticated" in str(blocked.error)
    shared.shutdown()


def test_authenticated_probe_is_in_process_and_redacted_before_proof_recognition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        traffic_policy=_test_traffic_policy(tmp_path / "probe-traffic.json"),
    )
    runtime = _TrackingRuntime()
    workspace = AgentWorkspace.open(tmp_path / "probe")
    audit = AuditStore(tmp_path / "probe.db")
    recognized_inputs: list[str] = []
    supplied_sessions: list[ProbeSession] = []

    def run_probe(probe: str, **kwargs: object) -> ProbeRunResult:
        session = kwargs.get("session")
        assert isinstance(session, ProbeSession)
        supplied_sessions.append(session)
        return ProbeRunResult(
            ok=True,
            probe=probe,
            summary=f"target returned flag{{{_TOKEN}}}",
        )

    def recognize(text: str) -> list[str]:
        recognized_inputs.append(text)
        return []

    monkeypatch.setattr(action_executor, "run_builtin_probe", run_probe)
    monkeypatch.setattr(action_executor, "recognize_proofs", recognize)
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "surface_map", "timeout_seconds": 37},
            target_url=_TARGET,
            runtime=runtime,
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            proof_recognition_enabled=True,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
    finally:
        audit.close()
        owner.close()

    assert result.ok
    assert result.session_mode == "identity:service"
    assert supplied_sessions
    assert supplied_sessions[0].timeout_seconds == 37
    assert runtime.calls == []
    assert recognized_inputs
    assert all(_TOKEN not in text for text in recognized_inputs)
    assert _TOKEN not in result.observation
    assert _TOKEN not in workspace.events_path.read_text(encoding="utf-8")


def test_authenticated_probe_rejects_identity_tainted_proof_but_captures_adjacent_real_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
        traffic_policy=_test_traffic_policy(tmp_path / "proof-taint-traffic.json"),
    )
    workspace = AgentWorkspace.open(tmp_path / "proof-taint")
    audit = AuditStore(tmp_path / "proof-taint.db")
    state = AgentState()
    real_proof = "FLAG{authz_boundary_real_8f31c9}"
    backend.rotate_health_cookie_to = "abc"

    def run_probe(probe: str, **kwargs: object) -> ProbeRunResult:
        assert isinstance(kwargs.get("session"), ProbeSession)
        return ProbeRunResult(
            ok=True,
            probe=probe,
            summary=(
                f"reflected FLAG{{alice}}, redirected to /next/abc, "
                f"kept abc prose, then returned {real_proof}"
            ),
        )

    monkeypatch.setattr(action_executor, "run_builtin_probe", run_probe)
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "surface_map"},
            target_url=_TARGET,
            runtime=_TrackingRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            proof_recognition_enabled=True,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
        assert owner.redact_text("abc remains ordinary prose") == "abc remains ordinary prose"
    finally:
        audit.close()
        owner.close()

    assert result.flag == real_proof
    assert state.flags == [real_proof]
    assert state.last_observation["recognized_proofs"] == [real_proof]
    persisted = workspace.events_path.read_text(encoding="utf-8")
    assert "FLAG{alice}" not in persisted
    assert "/next/abc" not in persisted
    assert "abc prose" in persisted
    assert real_proof in persisted
    assert b"/next/abc" not in (tmp_path / "proof-taint.db").read_bytes()


@pytest.mark.parametrize("submitted", ["FLAG{alice}", "RkxBR3thbGljZX0="])
def test_authenticated_manual_capture_rejects_tainted_proof_without_persisting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    submitted: str,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
        traffic_policy=_test_traffic_policy(tmp_path / "capture-taint-traffic.json"),
    )
    workspace = AgentWorkspace.open(tmp_path / "capture-taint")
    audit = AuditStore(tmp_path / "capture-taint.db")
    state = AgentState()
    try:
        result = execute_action(
            {"action": "capture_flag", "flag": submitted, "evidence": submitted},
            target_url=_TARGET,
            runtime=_TrackingRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            proof_recognition_enabled=True,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
    finally:
        audit.close()
        owner.close()

    assert not result.ok
    assert result.outcome == "blocked"
    assert state.flags == []
    persisted = workspace.events_path.read_text(encoding="utf-8")
    assert "FLAG{alice}" not in persisted
    assert "RkxBR3thbGljZX0=" not in persisted
    assert b"FLAG{alice}" not in (tmp_path / "capture-taint.db").read_bytes()
    assert b"RkxBR3thbGljZX0=" not in (tmp_path / "capture-taint.db").read_bytes()


@pytest.mark.parametrize("recon_fails", [False, True])
def test_authenticated_model_reply_never_persists_contextual_identity_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recon_fails: bool,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
        traffic_policy=_test_traffic_policy(tmp_path / "model-proof-traffic.json"),
    )
    brief = EngagementBrief(
        engagement_id=uuid4(),
        scope=Scope(in_scope=[_TARGET]),
        roe=RulesOfEngagement(max_rps=5),
        objectives=["capture_flag"],
        budget=Budget(max_cost_usd=1.0, max_runtime_min=5),
        authentication=_form_config(),
        context={
            "description": "Authorized managed identity assessment.",
            "credential_notes_path": "OPERATOR_NOTES.md",
        },
    )
    brief_path = tmp_path / "brief.json"
    brief_path.write_text(json.dumps(brief.model_dump(mode="json")), encoding="utf-8")
    (tmp_path / "OPERATOR_NOTES.md").write_text(
        "username: legacy-user\npassword: legacy-seed-password\n",
        encoding="utf-8",
    )
    workspace_dir = tmp_path / "model-proof-taint"
    audit_path = tmp_path / "model-proof-taint.db"
    model = ScriptedModelClient(
        [
            {
                "action": "capture_flag",
                "flag": "FLAG{alice}",
                "evidence": "FLAG{alice}",
            },
            {"action": "final", "summary": "tainted candidate rejected"},
        ]
    )
    monkeypatch.setattr(
        "ravage.agent_core.ai_agent._select_model_route",
        lambda _settings: _route(),
    )

    class SensitiveAnonymousRecon:
        @staticmethod
        def to_json() -> dict[str, object]:
            return {
                "target_url": _TARGET,
                "origin": _TARGET,
                "pages": [
                    {
                        "url": _TARGET,
                        "title": "FLAG{alice}",
                        "headers": {"X-Debug": "FLAG{alice}"},
                        "interesting_markers": ["FLAG{alice}"],
                    }
                ],
                "query_parameter_names": [],
                "interesting_markers": ["FLAG{alice}"],
                "errors": [],
            }

    def sensitive_recon(*_args: object, **_kwargs: object) -> SensitiveAnonymousRecon:
        if recon_fails:
            raise RuntimeError("anonymous recon exposed FLAG{alice}")
        return SensitiveAnonymousRecon()

    monkeypatch.setattr("ravage.agent_core.ai_agent.run_recon", sensitive_recon)
    try:
        run_ai_web_agent(
            brief_path=brief_path,
            target_url=_TARGET,
            settings=AIWebAgentSettings(
                db_path=audit_path,
                workspace_dir=workspace_dir,
                max_turns=2,
                model_client=model,
                http_client=VulnerableOpenApiHttpClient(),
                stdout=StringIO(),
                authentication=owner,
                traffic_policy_reference=_owner_traffic_policy_reference(owner),
            ),
        )
    finally:
        owner.close()

    for artifact in workspace_dir.rglob("*"):
        if artifact.is_file():
            rendered = artifact.read_text(encoding="utf-8")
            assert "FLAG{alice}" not in rendered
            assert "legacy-seed-password" not in rendered
    assert b"FLAG{alice}" not in audit_path.read_bytes()
    assert b"legacy-seed-password" not in audit_path.read_bytes()


def test_authenticated_run_error_report_never_persists_secret_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
        traffic_policy=_test_traffic_policy(tmp_path / "run-error-traffic.json"),
    )
    backend.protected_body = "protected account"
    brief = EngagementBrief(
        engagement_id=uuid4(),
        scope=Scope(in_scope=[_TARGET]),
        roe=RulesOfEngagement(max_rps=5),
        objectives=["web_application_assessment"],
        budget=Budget(max_cost_usd=1.0, max_runtime_min=5),
        authentication=_form_config(),
        context={"description": "Authorized managed identity assessment."},
    )
    brief_path = tmp_path / "brief.json"
    brief_path.write_text(json.dumps(brief.model_dump(mode="json")), encoding="utf-8")
    workspace_dir = tmp_path / "error-workspace"
    audit_path = tmp_path / "error-audit.db"
    report_path = tmp_path / "report.json"

    class FailingModel:
        @staticmethod
        def complete(**_kwargs: object) -> object:
            raise RuntimeError("provider exposed FLAG{alice} and correct-horse")

    class EmptyRecon:
        @staticmethod
        def to_json() -> dict[str, object]:
            return {
                "target_url": _TARGET,
                "origin": _TARGET,
                "pages": [],
                "query_parameter_names": [],
                "interesting_markers": [],
                "errors": [],
            }

    monkeypatch.setattr(
        "ravage.agent_core.ai_agent._select_model_route",
        lambda _settings: _route(),
    )
    monkeypatch.setattr(
        "ravage.agent_core.ai_agent.run_recon",
        lambda *_args, **_kwargs: EmptyRecon(),
    )
    try:
        with pytest.raises(RuntimeError, match="provider exposed"):
            run_ai_web_agent(
                brief_path=brief_path,
                target_url=_TARGET,
                settings=AIWebAgentSettings(
                    db_path=audit_path,
                    report_path=report_path,
                    workspace_dir=workspace_dir,
                    max_turns=1,
                    model_client=FailingModel(),
                    http_client=VulnerableOpenApiHttpClient(),
                    stdout=StringIO(),
                    authentication=owner,
                    traffic_policy_reference=_owner_traffic_policy_reference(owner),
                ),
            )
    finally:
        owner.close()

    checkpoint = json.loads(
        (workspace_dir / "working_state.json").read_text(encoding="utf-8")
    )
    assert checkpoint["state"]["surface"]["authenticated_identity"] == "alice"
    assert checkpoint["state"]["surface"]["session_mode"] == "identity:alice"
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (*workspace_dir.rglob("*"), report_path)
        if path.is_file() and path != audit_path
    )
    assert "FLAG{alice}" not in artifact_text
    assert "correct-horse" not in artifact_text
    audit_bytes = audit_path.read_bytes()
    assert b"FLAG{alice}" not in audit_bytes
    assert b"correct-horse" not in audit_bytes


def test_authenticated_poc_filters_tainted_proof_candidate_independently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
        traffic_policy=_test_traffic_policy(tmp_path / "poc-proof-taint-traffic.json"),
    )
    workspace = AgentWorkspace.open(tmp_path / "poc-proof-taint")
    audit = AuditStore(tmp_path / "poc-proof-taint.db")
    state = AgentState()
    real_proof = "FLAG{poc_boundary_real_5d79a2}"
    monkeypatch.setattr(
        action_executor,
        "validate_http_poc",
        lambda **_kwargs: ValidationResult(
            ok=True,
            summary=f"reflected FLAG{{alice}} then returned {real_proof}",
        ),
    )
    try:
        result = execute_action(
            {"action": "validate_poc", "steps": [{"method": "GET", "url": "/"}]},
            target_url=_TARGET,
            runtime=_TrackingRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            proof_recognition_enabled=True,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
    finally:
        audit.close()
        owner.close()

    assert result.flag == real_proof
    assert state.flags == [real_proof]
    assert state.last_observation["recognized_proofs"] == [real_proof]
    persisted = workspace.events_path.read_text(encoding="utf-8")
    assert "FLAG{alice}" not in persisted
    assert real_proof in persisted


def test_authenticated_poc_identity_switch_cannot_mutate_canonical_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
        traffic_policy=_test_traffic_policy(tmp_path / "poc-session-traffic.json"),
    )
    backend.switch_cookie_to = "mallory-runtime-cookie"
    workspace = AgentWorkspace.open(tmp_path / "poc-session-isolation")
    audit = AuditStore(tmp_path / "poc-session-isolation.db")
    try:
        execute_action(
            {
                "action": "validate_poc",
                "steps": [{"method": "GET", "url": f"{_TARGET}switch"}],
            },
            target_url=_TARGET,
            runtime=_TrackingRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
        fresh = owner.session_for_probe()
        try:
            cookies = {cookie.name: cookie.value for cookie in fresh.cookies}
            assert cookies["session"] == "alice-runtime-cookie"
            assert "mallory-runtime-cookie" not in cookies.values()
        finally:
            owner.retire_probe_session(fresh)
    finally:
        audit.close()
        owner.close()


def test_authenticated_graph_identity_switch_cannot_mutate_canonical_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(
        monkeypatch,
        config=_form_config(),
        identity="alice",
        values={"ALICE_USERNAME": "alice", "ALICE_PASSWORD": "correct-horse"},
        traffic_policy=_test_traffic_policy(tmp_path / "graph-whole-run-traffic.json"),
    )
    backend.switch_cookie_to = "mallory-runtime-cookie"
    try:
        executor = ScopedGraphHttpExecutor(
            target_url=_TARGET,
            scope=Scope(in_scope=[_TARGET], out_of_scope=[]),
            allow_remote_target=False,
            profile=graph_operational_profile(
                GraphOperationalProfileName.LOW_NOISE,
                roe_max_rps=20,
                max_total_requests=20,
            ),
            resolver=lambda _host, _port: ("127.0.0.1",),
            state_path=tmp_path / "graph-http-state.json",
            authentication=owner,
        )

        execution = executor(
            node_id="node-auth-switch",
            arguments={"method": "GET", "path": "/switch"},
            action_id="action-auth-switch",
        )
        assert execution.result.ok
        fresh = owner.session_for_probe()
        try:
            cookies = {cookie.name: cookie.value for cookie in fresh.cookies}
            assert cookies["session"] == "alice-runtime-cookie"
            assert "mallory-runtime-cookie" not in cookies.values()
        finally:
            owner.retire_probe_session(fresh)
    finally:
        owner.close()


@pytest.mark.parametrize(
    "probe",
    ["default_credentials", "sqli_auth_transition", "stateful_session"],
)
def test_authenticated_boundary_probe_stays_in_process_without_managed_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe: str,
) -> None:
    runtime = _TrackingRuntime()
    workspace = AgentWorkspace.open(tmp_path / probe)
    audit = AuditStore(tmp_path / f"{probe}.db")
    observed_sessions: list[object] = []
    observed_policies: list[object] = []
    traffic_policy = TrafficPolicyController.open(
        tmp_path / f"{probe}-traffic.json",
        target_url=_TARGET,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=20),
    )
    owner, _backend = _build_owner(monkeypatch, traffic_policy=traffic_policy)

    def run_probe(name: str, **kwargs: object) -> ProbeRunResult:
        observed_sessions.append(kwargs.get("session"))
        observed_policies.append(kwargs.get("traffic_policy"))
        return ProbeRunResult(ok=True, probe=name, summary="anonymous boundary checked")

    def unexpected_subprocess_probe(*_args: object, **_kwargs: object) -> object:
        pytest.fail("authenticated boundary probes must not use the subprocess runner")

    monkeypatch.setattr(action_executor, "run_builtin_probe", run_probe)
    monkeypatch.setattr(action_executor, "_run_probe_action", unexpected_subprocess_probe)
    try:
        result = execute_action(
            {"action": "run_probe", "probe": probe},
            target_url=_TARGET,
            runtime=runtime,
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            authentication=owner,
            traffic_policy=traffic_policy,
        )
    finally:
        audit.close()
        owner.close()

    assert result.ok
    assert result.session_mode == "anonymous:probe-required"
    assert json.loads(result.observation)["session_mode"] == "anonymous:probe-required"
    assert observed_sessions == [None]
    assert observed_policies == [traffic_policy]
    assert runtime.calls == []


@pytest.mark.parametrize("probe", ["captcha_form_state", "dom_execution"])
def test_authenticated_external_process_probe_is_blocked_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe: str,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        traffic_policy=_test_traffic_policy(tmp_path / f"{probe}-traffic.json"),
    )
    runtime = _TrackingRuntime()
    workspace = AgentWorkspace.open(tmp_path / probe)
    audit = AuditStore(tmp_path / f"{probe}.db")

    def unexpected_probe(*_args: object, **_kwargs: object) -> ProbeRunResult:
        pytest.fail("an external-process probe must not dispatch in authenticated mode")

    monkeypatch.setattr(action_executor, "run_builtin_probe", unexpected_probe)
    try:
        result = execute_action(
            {"action": "run_probe", "probe": probe},
            target_url=_TARGET,
            runtime=runtime,
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
    finally:
        audit.close()
        owner.close()

    assert not result.ok
    assert result.outcome == "blocked"
    assert result.session_mode == "blocked:external-process"
    assert runtime.calls == []
    assert "blocked:external-process" in result.observation


@pytest.mark.parametrize("probe", ["browser_boundary", "cms_exposure"])
def test_authenticated_unmanaged_transport_probe_is_blocked_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe: str,
) -> None:
    owner, _backend = _build_owner(
        monkeypatch,
        traffic_policy=_test_traffic_policy(tmp_path / f"{probe}-traffic.json"),
    )
    runtime = _TrackingRuntime()
    workspace = AgentWorkspace.open(tmp_path / probe)
    audit = AuditStore(tmp_path / f"{probe}.db")

    def unexpected_probe(*_args: object, **_kwargs: object) -> ProbeRunResult:
        pytest.fail("an unmanaged transport probe must not dispatch in authenticated mode")

    monkeypatch.setattr(action_executor, "run_builtin_probe", unexpected_probe)
    try:
        result = execute_action(
            {"action": "run_probe", "probe": probe},
            target_url=_TARGET,
            runtime=runtime,
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            authentication=owner,
            traffic_policy=owner.traffic_policy,
        )
    finally:
        audit.close()
        owner.close()

    assert not result.ok
    assert result.outcome == "blocked"
    assert result.session_mode == "blocked:unmanaged-transport"
    assert runtime.calls == []


def test_authenticated_prompt_filters_unexecutable_recommendations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _backend = _build_owner(monkeypatch)
    user: dict[str, object] = {
        "action_schema": {"run_probe": {}, "run_command": {}, "run_python": {}, "final": {}},
        "tool_guidance": ["Run browser_boundary, then use curl."],
        "active_tasks": [{"id": "cms", "probe": "cms_exposure"}],
        "execution_recipes": [{"name": "dom", "good_first_actions": ["dom_execution"]}],
        "active_strategy_cards": [{"name": "captcha_form_state"}],
        "planner_directives": ["Run browser-boundary next."],
        "available_probes": [
            {"name": "surface_map"},
            {"name": "browser_boundary"},
            {"name": "captcha_form_state"},
            {"name": "cms_exposure"},
            {"name": "dom_execution"},
        ],
        "available_specialists": [{"probe": "surface_map"}, {"probe": "cms_exposure"}],
        "recommended_specialists": [{"probe": "browser_boundary"}],
        "locked_primitive": None,
    }
    try:
        _focus_authenticated_prompt(user, authentication=owner)
    finally:
        owner.close()

    actionable = json.dumps(
        {
            key: user[key]
            for key in (
                "tool_guidance",
                "active_tasks",
                "execution_recipes",
                "active_strategy_cards",
                "planner_directives",
                "available_probes",
                "available_specialists",
                "recommended_specialists",
            )
        }
    )
    for probe in (
        "browser_boundary",
        "captcha_form_state",
        "cms_exposure",
        "dom_execution",
    ):
        assert probe not in actionable
    assert "surface_map" in actionable


def test_authenticated_poc_uses_owner_request_and_redacts_callback_and_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend = _build_owner(monkeypatch)
    steps: list[dict[str, object]] = []
    try:
        result = validate_http_poc(
            target_url=_TARGET,
            steps=[{"method": "GET", "url": "/protected", "expect_status": 200}],
            request=owner.request,
            redact=owner.redact,
            on_step=steps.append,
        )
    finally:
        owner.close()

    assert result.ok
    assert steps
    serialized = json.dumps({"result": result.to_text(), "steps": steps})
    assert _TOKEN not in serialized
    assert "runtime-cookie-secret" not in serialized
    protected = [call for call in backend.requests if str(call["url"]).endswith("/protected")]
    assert protected
    assert protected[-1]["headers"]["Authorization"] == f"Bearer {_TOKEN}"  # type: ignore[index]


def test_authenticated_prompt_exposes_only_managed_http_lanes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _backend = _build_owner(monkeypatch)
    brief_path = tmp_path / "brief.yaml"
    state = AgentState(tasks=[{"id": "surface-map", "status": "pending"}])
    try:
        messages = _build_messages(
            brief=_brief(),
            brief_path=brief_path,
            target_url=_TARGET,
            state=state,
            settings=AIWebAgentSettings(authentication=owner),
            route=_route(),
        )
    finally:
        owner.close()

    system = messages[0]["content"]
    user = json.loads(messages[1]["content"])
    assert "managed HTTP probe or managed PoC replay" in system
    assert "run_command" not in user["action_schema"]
    assert "run_python" not in user["action_schema"]
    assert user["managed_http_identity"] == {
        "control_actions": ["final"],
        "identity_alias": "service",
        "managed_http_actions": ["run_probe", "validate_poc"],
        "mode": "identity:service",
        "request_lane": "managed_http",
    }
    assert user["managed_http_identity"] != "[REDACTED]"
    guidance = "\n".join(str(item).casefold() for item in user["tool_guidance"])
    for forbidden in ("run_command", "run_python", "curl", "python", "docker", "ssh"):
        assert forbidden not in guidance
    assert "http validate_poc supports sql_injection" in guidance
    assert "server_side_template_injection" in guidance
    assert "path_traversal" in guidance
    assert "plain reflection cannot confirm xss in managed authenticated mode" in guidance
    first_actions = user["execution_recipes"][0]["good_first_actions"]
    assert first_actions == [
        "run_probe surface_map to fetch common paths and summarize notable pages."
    ]
    probe_modes = {
        str(item["name"]): str(item["session_mode"]) for item in user["available_probes"]
    }
    assert probe_modes["surface_map"] == "identity:service"
    assert probe_modes["default_credentials"] == "anonymous:probe-required"
    assert probe_modes["sqli_auth_transition"] == "anonymous:probe-required"
    assert probe_modes["stateful_session"] == "anonymous:probe-required"
    assert "captcha_form_state" not in probe_modes
    assert "dom_execution" not in probe_modes
    assert user["unavailable_authenticated_probes"] == [
        {
            "name": "browser_boundary",
            "reason": (
                "raw WebSocket transport cannot traverse the managed identity owner or "
                "preserve its credentials and refresh semantics"
            ),
        },
        {
            "name": "captcha_form_state",
            "reason": ("requires an external process that cannot receive managed credentials"),
        },
        {
            "name": "cms_exposure",
            "reason": "managed binary downloads require an owner-controlled adapter",
        },
        {
            "name": "dom_execution",
            "reason": ("requires an external process that cannot receive managed credentials"),
        },
    ]


def test_base_and_frontier_resume_reject_identity_mixing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _backend = _build_owner(monkeypatch)
    mismatched = AgentState(surface={"authenticated_identity": "other"})
    authenticated = AgentState(surface={"authenticated_identity": "service"})
    try:
        with pytest.raises(ValueError, match="different identity"):
            _assert_authenticated_state_identity(mismatched, authentication=owner)
        with pytest.raises(ValueError, match="without managed authentication"):
            _assert_authenticated_state_identity(authenticated, authentication=None)
        with pytest.raises(ValueError, match="without its authenticated identity binding"):
            _assert_authenticated_state_identity(AgentState(), authentication=owner)
        _assert_authenticated_state_identity(
            AgentState(),
            authentication=owner,
            resumed=False,
        )
        with pytest.raises(ValueError, match="different identity"):
            _assert_frontier_identity(
                mismatched,
                settings=AIWebAgentSettings(authentication=owner),
            )
        with pytest.raises(ValueError, match="without managed authentication"):
            _assert_frontier_identity(authenticated, settings=AIWebAgentSettings())
        with pytest.raises(ValueError, match="without an identity binding"):
            _assert_frontier_identity(
                AgentState(),
                settings=AIWebAgentSettings(authentication=owner),
            )
    finally:
        owner.close()


def _brief() -> EngagementBrief:
    return EngagementBrief(
        engagement_id=UUID("00000000-0000-4000-8000-000000000001"),
        scope=Scope(in_scope=[_TARGET]),
        roe=RulesOfEngagement(max_rps=5),
        objectives=["web_application_assessment"],
        budget=Budget(max_cost_usd=1.0, max_runtime_min=5),
        authentication=_bearer_config(),
    )


def _route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="low",
        selected_tier="low",
        ordinal=0,
        provider="ollama",
        model="local",
        base_url="http://localhost:11434/v1",
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=256,
        output_token_limit_parameter="max_tokens",
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=1,
        max_retries=0,
    )
