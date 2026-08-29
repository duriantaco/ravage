from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import pytest
from pentest_schemas import (
    AuthEndpoint,
    AuthenticationConfig,
    AuthFlow,
    AuthHealthCheck,
    AuthIdentity,
    SecretReference,
    TotpConfig,
)
from ravage.auth import (
    AuthenticationError,
    MappingSecretResolver,
    SessionManager,
)
from ravage.auth.configured import (
    ConfiguredAuthenticationError,
    UnsupportedConfiguredAuthFlowError,
    _totp,
    assert_secure_configured_auth_transport,
    identity_profile_from_config,
    identity_profiles_from_config,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession


@dataclass
class _Backend:
    posted_fields: list[dict[str, str]] = field(default_factory=list)


class _ConfiguredSession:
    def __init__(self, backend: _Backend) -> None:
        self.backend = backend
        self.default_headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.authenticated = False
        self.target_url = "https://target.test/"

    def fork(self, *, timeout_seconds: int | None = None) -> _ConfiguredSession:
        del timeout_seconds
        return _ConfiguredSession(self.backend)

    def in_scope(self, url: str) -> bool:
        return url.startswith("https://target.test/")

    def get(self, url: str) -> ProbeResponse:
        return self.request("GET", url)

    def post_form(self, url: str, fields: dict[str, str]) -> ProbeResponse:
        self.backend.posted_fields.append(dict(fields))
        if (
            url == "https://target.test/sessions"
            and fields.get("username") == "alice"
            and fields.get("password") == "correct-horse"
            and fields.get("csrf_token") == "rotating-login-token"
        ):
            self.authenticated = True
            self.cookies["session"] = "alice-session"
            return self._response("POST", url, status=303)
        return self._response("POST", url, status=200, body="Welcome, maybe")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        if url == "https://target.test/login":
            return self._response(
                method,
                url,
                body=(
                    '<form method="post" action="/sessions">'
                    '<input type="hidden" name="csrf_token" '
                    'value="rotating-login-token">'
                    '<input name="username"><input name="password" type="password">'
                    "</form>"
                ),
            )
        if url == "https://target.test/me":
            bearer_ok = self.default_headers.get("Authorization") == "Bearer service-token"
            if self.authenticated or bearer_ok:
                return self._response(method, url, body="Account settings")
            return self._response(method, url, status=401, body="Sign in")
        return self._response(method, url, status=404)

    @staticmethod
    def _response(
        method: str,
        url: str,
        *,
        status: int = 200,
        body: str = "",
    ) -> ProbeResponse:
        return ProbeResponse(
            method=method,
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=1,
            body=body,
        )


def _health() -> AuthHealthCheck:
    return AuthHealthCheck(
        endpoint=AuthEndpoint(url="https://target.test/me", scope="target"),
        authenticated_marker="Account settings",
        unauthenticated_marker="Sign in",
    )


def test_form_config_resolves_secrets_at_login_and_preserves_rotating_hidden_fields() -> None:
    config = AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="alice",
                roles=["customer"],
                flow=AuthFlow(
                    kind="form",
                    endpoint=AuthEndpoint(
                        url="https://target.test/login",
                        scope="target",
                    ),
                    secret_refs={
                        "username": SecretReference(key="ALICE_USERNAME"),
                        "password": SecretReference(key="ALICE_PASSWORD"),
                    },
                ),
                health_check=_health(),
            )
        ]
    )
    profiles = identity_profiles_from_config(config)
    backend = _Backend()
    manager = SessionManager(
        cast("ProbeSession", _ConfiguredSession(backend)),
        profiles,
        secret_resolver=MappingSecretResolver(
            {
                "ALICE_USERNAME": "alice",
                "ALICE_PASSWORD": "correct-horse",
            },
            provider="environment",
        ),
    )

    handle = manager.acquire("alice")

    assert handle.generation == 1
    assert backend.posted_fields == [
        {
            "csrf_token": "rotating-login-token",
            "password": "correct-horse",
            "username": "alice",
        }
    ]
    assert "correct-horse" not in repr(profiles[0])
    assert profiles[0].to_public_dict()["secrets"] == {
        "username": {"provider": "environment", "key": "ALICE_USERNAME"},
        "password": {"provider": "environment", "key": "ALICE_PASSWORD"},
    }


def test_bearer_config_is_applied_before_the_protected_health_check() -> None:
    config = AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="service",
                roles=["api"],
                flow=AuthFlow(
                    kind="bearer",
                    secret_refs={"token": SecretReference(key="SERVICE_TOKEN")},
                ),
                health_check=_health(),
            )
        ]
    )
    manager = SessionManager(
        cast("ProbeSession", _ConfiguredSession(_Backend())),
        identity_profiles_from_config(config),
        secret_resolver=MappingSecretResolver(
            {"SERVICE_TOKEN": "service-token"},
            provider="environment",
        ),
    )

    handle = manager.acquire("service")

    assert handle.session.default_headers["Authorization"] == "Bearer service-token"


def test_deceptive_form_success_is_rejected_by_the_protected_health_check() -> None:
    config = AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="alice",
                roles=["customer"],
                flow=AuthFlow(
                    kind="form",
                    endpoint=AuthEndpoint(
                        url="https://target.test/login",
                        scope="target",
                    ),
                    secret_refs={
                        "username": SecretReference(key="ALICE_USERNAME"),
                        "password": SecretReference(key="ALICE_PASSWORD"),
                    },
                ),
                health_check=_health(),
            )
        ]
    )
    manager = SessionManager(
        cast("ProbeSession", _ConfiguredSession(_Backend())),
        identity_profiles_from_config(config),
        secret_resolver=MappingSecretResolver(
            {
                "ALICE_USERNAME": "alice",
                "ALICE_PASSWORD": "wrong-password",
            },
            provider="environment",
        ),
    )

    with pytest.raises(AuthenticationError):
        manager.acquire("alice")


def test_browser_and_sso_flows_fail_explicitly_until_checkpoint_adapter_is_armed() -> None:
    for kind in ("browser", "oauth2_oidc", "saml"):
        config = AuthenticationConfig(
            identities=[
                AuthIdentity(
                    alias="operator",
                    roles=["admin"],
                    flow=AuthFlow(
                        kind=kind,
                        endpoint=AuthEndpoint(
                            url="https://identity.test/login",
                            scope="auth_dependency",
                        ),
                    ),
                    health_check=_health(),
                )
            ]
        )

        with pytest.raises(
            UnsupportedConfiguredAuthFlowError,
            match="checkpoint adapter",
        ):
            identity_profiles_from_config(config)


def test_selected_supported_identity_ignores_unrelated_interactive_flow() -> None:
    config = AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="service",
                roles=["api"],
                flow=AuthFlow(
                    kind="bearer",
                    secret_refs={"token": SecretReference(key="SERVICE_TOKEN")},
                ),
                health_check=_health(),
            ),
            AuthIdentity(
                alias="operator",
                roles=["admin"],
                flow=AuthFlow(
                    kind="oauth2_oidc",
                    endpoint=AuthEndpoint(
                        url="https://identity.test/login",
                        scope="auth_dependency",
                    ),
                ),
                health_check=_health(),
            ),
        ]
    )

    profile = identity_profile_from_config(config, "service")

    assert profile.name == "service"


def test_configured_auth_requires_https_except_for_local_development() -> None:
    config = AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="service",
                roles=["api"],
                flow=AuthFlow(
                    kind="bearer",
                    secret_refs={"token": SecretReference(key="SERVICE_TOKEN")},
                ),
                health_check=_health(),
            )
        ]
    )

    with pytest.raises(ConfiguredAuthenticationError, match="requires HTTPS"):
        assert_secure_configured_auth_transport(
            config,
            target_url="http://target.test/",
            alias="service",
        )

    assert_secure_configured_auth_transport(
        config,
        target_url="http://127.0.0.1:8080/",
        alias="service",
    )


def test_totp_uses_rfc6238_generation_without_persisting_the_secret() -> None:
    config = TotpConfig(
        secret=SecretReference(key="TOTP_SECRET"),
        digits=8,
        period_seconds=30,
        algorithm="sha1",
    )

    assert _totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", config, at=59) == "94287082"
