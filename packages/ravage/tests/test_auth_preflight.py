from __future__ import annotations

# Deliberate sentinel credentials verify that preflight never returns them.
# ruff: noqa: EM102, S105, TRY003
import json
import os
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import TYPE_CHECKING
from uuid import UUID

import ravage.auth.preflight as preflight_module
from pentest_schemas import (
    AuthEndpoint,
    AuthenticationConfig,
    AuthFlow,
    AuthHealthCheck,
    AuthIdentity,
    Budget,
    EngagementBrief,
    RulesOfEngagement,
    Scope,
    SecretReference,
)
from ravage.auth import MappingSecretResolver, run_auth_preflight
from ravage.web_core.http_probe import ProbeResponse

if TYPE_CHECKING:
    from pathlib import Path

    import pytest
    from ravage.auth import SecretRef

_TARGET = "http://127.0.0.1:18782/"


@dataclass
class _Backend:
    expected_token: str = "correct-token"
    healthy: bool = True
    requests: list[tuple[str, str]] = field(default_factory=list)
    sessions: list[_FakeSession] = field(default_factory=list)


class _FakeSession:
    backend = _Backend()

    def __init__(self, target_url: str, **kwargs: object) -> None:
        del kwargs
        self.target_url = target_url
        self.default_headers: dict[str, str] = {}
        self.cookies = CookieJar()
        self.backend.sessions.append(self)

    def fork(self, *, timeout_seconds: int | None = None) -> _FakeSession:
        del timeout_seconds
        return _FakeSession(self.target_url)

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.target_url)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        del data, headers, timeout_seconds
        authorization = self.default_headers.get("Authorization", "")
        self.backend.requests.append((method, authorization))
        authorized = authorization == f"Bearer {self.backend.expected_token}"
        healthy = authorized and self.backend.healthy
        return ProbeResponse(
            method=method,
            url=url,
            status=200 if healthy else 401,
            final_url=url,
            elapsed_ms=1,
            body="Account settings" if healthy else "Sign in",
        )


def _brief(*, flow_kind: str = "bearer") -> EngagementBrief:
    if flow_kind == "bearer":
        flow = AuthFlow(
            kind="bearer",
            secret_refs={"token": SecretReference(key="SERVICE_TOKEN")},
        )
    else:
        flow = AuthFlow(
            kind="browser",
            endpoint=AuthEndpoint(url=f"{_TARGET}login", scope="target"),
        )
    return EngagementBrief(
        engagement_id=UUID("00000000-0000-4000-8000-000000000001"),
        scope=Scope(in_scope=[_TARGET]),
        roe=RulesOfEngagement(max_rps=10),
        objectives=["web_application_assessment"],
        budget=Budget(max_cost_usd=1.0, max_runtime_min=5),
        authentication=AuthenticationConfig(
            identities=[
                AuthIdentity(
                    alias="service",
                    roles=["api"],
                    flow=flow,
                    health_check=AuthHealthCheck(
                        endpoint=AuthEndpoint(url=f"{_TARGET}me", scope="target"),
                        authenticated_marker="Account settings",
                        unauthenticated_marker="Sign in",
                    ),
                )
            ]
        ),
    )


def _install_fake_session(monkeypatch: pytest.MonkeyPatch, *, healthy: bool = True) -> _Backend:
    backend = _Backend(healthy=healthy)
    _FakeSession.backend = backend
    monkeypatch.setattr(preflight_module, "ProbeSession", _FakeSession)
    return backend


def test_preflight_establishes_and_health_checks_a_managed_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    backend = _install_fake_session(monkeypatch)
    monkeypatch.chdir(tmp_path)

    result = run_auth_preflight(
        _brief(),
        "service",
        _TARGET,
        secret_resolver=MappingSecretResolver(
            {"SERVICE_TOKEN": "correct-token"},
            provider="environment",
        ),
    )

    assert result.passed
    assert result.reason_code == "ready"
    assert [stage.name for stage in result.stages] == [
        "configuration",
        "secrets",
        "login",
        "health",
    ]
    assert [stage.status.value for stage in result.stages] == ["passed"] * 4
    assert backend.requests == [("GET", "Bearer correct-token")]
    assert all(not session.default_headers for session in backend.sessions)
    assert "correct-token" not in (json.dumps(result.to_dict()) + repr(result))
    assert not (tmp_path / "runs").exists()


def test_empty_env_placeholder_fails_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _install_fake_session(monkeypatch)

    result = run_auth_preflight(
        _brief(),
        "service",
        _TARGET,
        environment={"SERVICE_TOKEN": ""},
    )

    assert not result.passed
    assert result.reason_code == "secret_unset"
    assert result.stages[1].detail == "environment variable SERVICE_TOKEN is empty"
    assert backend.requests == []


def test_env_file_is_loaded_without_mutating_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    backend = _install_fake_session(monkeypatch)
    monkeypatch.setenv("SERVICE_TOKEN", "wrong-process-token")
    env_file = tmp_path / ".env.ravage"
    env_file.write_text(
        'export SERVICE_TOKEN="correct-token" # explicit file value wins\n',
        encoding="utf-8",
    )

    result = run_auth_preflight(
        _brief(),
        "service",
        _TARGET,
        env_file=env_file,
    )

    assert result.passed
    assert backend.requests == [("GET", "Bearer correct-token")]
    assert os.environ["SERVICE_TOKEN"] == "wrong-process-token"


def test_health_rejection_is_distinct_from_login_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_session(monkeypatch, healthy=False)

    result = run_auth_preflight(
        _brief(),
        "service",
        _TARGET,
        environment={"SERVICE_TOKEN": "correct-token"},
    )

    assert not result.passed
    assert result.reason_code == "health_check_rejected"
    assert result.stages[2].reason_code == "login_succeeded"
    assert result.stages[3].status.value == "failed"


def test_unknown_identity_and_interactive_flow_have_actionable_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _install_fake_session(monkeypatch)

    unknown = run_auth_preflight(_brief(), "missing", _TARGET)
    unsupported = run_auth_preflight(_brief(flow_kind="browser"), "service", _TARGET)

    assert unknown.reason_code == "identity_not_found"
    assert "service" in unknown.stages[0].detail
    assert unsupported.reason_code == "unsupported_flow"
    assert backend.requests == []


def test_remote_cleartext_auth_is_rejected_before_session_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _install_fake_session(monkeypatch)
    remote = _brief().model_copy(
        update={
            "scope": Scope(in_scope=["http://example.test/"]),
            "authentication": AuthenticationConfig(
                identities=[
                    AuthIdentity(
                        alias="service",
                        roles=["api"],
                        flow=AuthFlow(
                            kind="bearer",
                            secret_refs={"token": SecretReference(key="SERVICE_TOKEN")},
                        ),
                        health_check=AuthHealthCheck(
                            endpoint=AuthEndpoint(
                                url="http://example.test/me",
                                scope="target",
                            )
                        ),
                    )
                ]
            ),
        }
    )

    result = run_auth_preflight(
        remote,
        "service",
        "http://example.test/",
        environment={"SERVICE_TOKEN": "correct-token"},
        allow_remote_target=True,
    )

    assert result.reason_code == "insecure_transport"
    assert backend.sessions == []


def test_health_endpoint_outside_target_scope_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _install_fake_session(monkeypatch)
    brief = _brief()
    assert brief.authentication is not None
    identity = brief.authentication.identities[0]
    out_of_scope_identity = identity.model_copy(
        update={
            "health_check": identity.health_check.model_copy(
                update={
                    "endpoint": AuthEndpoint(
                        url="https://other.example.test/me",
                        scope="target",
                    )
                }
            )
        }
    )
    brief = brief.model_copy(
        update={"authentication": AuthenticationConfig(identities=[out_of_scope_identity])}
    )

    result = run_auth_preflight(
        brief,
        "service",
        _TARGET,
        environment={"SERVICE_TOKEN": "correct-token"},
    )

    assert result.reason_code == "auth_endpoint_out_of_scope"
    assert backend.requests == []


def test_resolver_exceptions_never_reach_the_result(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _install_fake_session(monkeypatch)
    plaintext = "do-not-print-this-token"

    class _AdversarialResolver:
        def resolve(self, reference: SecretRef) -> object:
            del reference
            raise RuntimeError(f"provider failed with {plaintext}")

    result = run_auth_preflight(
        _brief(),
        "service",
        _TARGET,
        secret_resolver=_AdversarialResolver(),  # type: ignore[arg-type]
    )
    rendered = json.dumps(result.to_dict()) + repr(result)

    assert result.reason_code == "secret_resolution_failed"
    assert plaintext not in rendered
    assert backend.requests == []


def test_invalid_env_file_reports_line_without_echoing_its_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_session(monkeypatch)
    plaintext = "do-not-echo-this"
    env_file = tmp_path / ".env.ravage"
    env_file.write_text(f"not an assignment {plaintext}\n", encoding="utf-8")

    result = run_auth_preflight(
        _brief(),
        "service",
        _TARGET,
        env_file=env_file,
    )

    assert result.reason_code == "env_file_invalid"
    assert result.stages[1].detail == ("environment file line 1 is not a KEY=VALUE assignment")
    assert plaintext not in json.dumps(result.to_dict())
