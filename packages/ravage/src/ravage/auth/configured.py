# Config validation errors intentionally preserve actionable call-site context.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import base64
import binascii
import hmac
import struct
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from ravage.web_core.scope_policy import is_local_url

from .secrets import SecretRef
from .sessions import IdentityProfile, IdentitySecrets, SessionHealth

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from pentest_schemas import (
        AuthenticationConfig,
        AuthFlow,
        AuthHealthCheck,
        AuthIdentity,
        SecretReference,
        TotpConfig,
    )

    from ravage.web_core.http_probe import ProbeResponse, ProbeSession

_MAX_AUTH_REDIRECTS = 5
_HTTP_REDIRECT_MIN = 300
_HTTP_ERROR_MIN = 400
_STATIC_HEADER_REFERENCE_ALIAS = "static_header_value"
_TOTP_REFERENCE_ALIAS = "totp_secret"


class ConfiguredAuthenticationError(RuntimeError):
    """Configured authentication cannot be executed safely."""


class UnsupportedConfiguredAuthFlowError(ConfiguredAuthenticationError):
    """The typed flow is recognized but needs a browser/operator adapter."""


def identity_profiles_from_config(
    config: AuthenticationConfig,
) -> tuple[IdentityProfile, ...]:
    """
    Compile a validated brief authentication section into runtime profiles.

    Secret values are intentionally absent here. The returned profiles retain
    only provider references and resolve them inside the login callback.
    """
    return tuple(_identity_profile(identity) for identity in config.identities)


def identity_profile_from_config(
    config: AuthenticationConfig,
    alias: str,
) -> IdentityProfile:
    """Compile only the selected identity, leaving unrelated flows untouched."""
    selected = next(
        (identity for identity in config.identities if identity.alias == alias),
        None,
    )
    if selected is None:
        available = ", ".join(identity.alias for identity in config.identities)
        raise ConfiguredAuthenticationError(f"unknown identity; configured identities: {available}")
    return _identity_profile(selected)


def assert_secure_configured_auth_transport(
    config: AuthenticationConfig,
    *,
    target_url: str,
    alias: str,
) -> None:
    """Reject cleartext credential transport except on the local development loopback."""
    selected = next(
        (identity for identity in config.identities if identity.alias == alias),
        None,
    )
    if selected is None:
        return
    urls = [target_url]
    if selected.flow.endpoint is not None:
        urls.append(selected.flow.endpoint.url)
    urls.append(selected.health_check.endpoint.url)
    for url in urls:
        if url.lower().startswith("http://") and not is_local_url(url):
            raise ConfiguredAuthenticationError(
                "configured authentication requires HTTPS for non-local endpoints"
            )


def _identity_profile(identity: AuthIdentity) -> IdentityProfile:
    references = {
        name: _secret_ref(reference) for name, reference in identity.flow.secret_refs.items()
    }
    references.update(_flow_secret_references(identity.flow, existing=references))
    return IdentityProfile(
        name=identity.alias,
        login=_login_callback(identity.flow),
        health_check=_health_callback(identity.health_check),
        secrets=references,
    )


def _flow_secret_references(
    flow: AuthFlow,
    *,
    existing: Mapping[str, SecretRef],
) -> dict[str, SecretRef]:
    references: dict[str, SecretRef] = {}
    if flow.static_header is not None:
        _reserve_secret_alias(
            references,
            existing,
            _STATIC_HEADER_REFERENCE_ALIAS,
            _secret_ref(flow.static_header.value),
        )
    if flow.totp is not None:
        _reserve_secret_alias(
            references,
            existing,
            _TOTP_REFERENCE_ALIAS,
            _secret_ref(flow.totp.secret),
        )
    return references


def _reserve_secret_alias(
    target: dict[str, SecretRef],
    existing: Mapping[str, SecretRef],
    name: str,
    reference: SecretRef,
) -> None:
    collision = existing.get(name)
    if collision is not None and collision != reference:
        raise ConfiguredAuthenticationError(
            f"configured authentication reserves secret alias {name!r}"
        )
    target[name] = reference


def _secret_ref(reference: SecretReference) -> SecretRef:
    return SecretRef(provider=reference.provider, key=reference.key)


def _login_callback(
    flow: AuthFlow,
) -> Callable[[ProbeSession, IdentitySecrets], bool | None] | None:
    if flow.kind == "form":
        return _form_login(flow)
    if flow.kind == "bearer":
        if "token" not in flow.secret_refs:
            raise ConfiguredAuthenticationError("bearer authentication requires secret_refs.token")
        return _bearer_login
    if flow.kind == "static_header":
        if flow.static_header is None:
            raise ConfiguredAuthenticationError(
                "static-header authentication is missing its header configuration"
            )
        return _static_header_login(flow.static_header.name)
    if flow.kind in {"browser", "oauth2_oidc", "saml", "operator_checkpoint"}:
        raise UnsupportedConfiguredAuthFlowError(
            f"{flow.kind} authentication requires a browser/operator checkpoint adapter"
        )
    raise UnsupportedConfiguredAuthFlowError(f"unsupported configured auth flow: {flow.kind}")


def _bearer_login(session: ProbeSession, secrets: IdentitySecrets) -> None:
    _require_secure_auth_url(session.target_url)
    token = secrets.require("token").reveal()
    session.default_headers["Authorization"] = f"Bearer {token}"


def _static_header_login(
    header_name: str,
) -> Callable[[ProbeSession, IdentitySecrets], None]:
    def login(session: ProbeSession, secrets: IdentitySecrets) -> None:
        _require_secure_auth_url(session.target_url)
        session.default_headers[header_name] = secrets.require(
            _STATIC_HEADER_REFERENCE_ALIAS
        ).reveal()

    return login


def _form_login(
    flow: AuthFlow,
) -> Callable[[ProbeSession, IdentitySecrets], bool]:
    endpoint = flow.endpoint
    if endpoint is None:
        raise ConfiguredAuthenticationError("form authentication requires an endpoint")
    if endpoint.scope != "target":
        raise UnsupportedConfiguredAuthFlowError(
            "form authentication through an auth dependency requires a browser adapter"
        )

    def login(session: ProbeSession, secrets: IdentitySecrets) -> bool:
        _require_secure_auth_url(endpoint.url)
        page = session.get(endpoint.url)
        if page.status is None or page.status >= _HTTP_ERROR_MIN:
            return False
        form = _select_login_form(
            base_url=page.final_url or endpoint.url,
            body=page.body,
            secret_names=secrets.keys(),
        )
        fields = dict(form.hidden_fields) if form is not None else {}
        secret_names = secrets.keys()
        for name in secret_names:
            if name not in {
                _STATIC_HEADER_REFERENCE_ALIAS,
                _TOTP_REFERENCE_ALIAS,
            }:
                fields[name] = secrets.require(name).reveal()
        if flow.totp is not None:
            fields[flow.totp.field_name] = _totp(
                secrets.require(_TOTP_REFERENCE_ALIAS).reveal(),
                flow.totp,
            )
        action = endpoint.url if form is None else form.action
        if form is not None and form.method != "POST":
            raise ConfiguredAuthenticationError("configured form login resolved to a non-POST form")
        if not session.in_scope(action):
            raise ConfiguredAuthenticationError(
                "configured form login action is outside the target scope"
            )
        response = session.post_form(action, fields)
        return response.status is not None and response.status < _HTTP_ERROR_MIN

    return login


def _health_callback(
    health: AuthHealthCheck,
) -> Callable[[ProbeSession], SessionHealth]:
    if health.endpoint.scope != "target":
        raise UnsupportedConfiguredAuthFlowError(
            "authentication health checks must run against the target scope"
        )

    def check(session: ProbeSession) -> SessionHealth:
        _require_secure_auth_url(health.endpoint.url)
        response = _health_request(session, health)
        if response.error or response.status not in health.success_statuses:
            return SessionHealth.EXPIRED
        if (
            health.authenticated_marker is not None
            and health.authenticated_marker not in response.body
        ):
            return SessionHealth.EXPIRED
        if (
            health.unauthenticated_marker is not None
            and health.unauthenticated_marker in response.body
        ):
            return SessionHealth.EXPIRED
        return SessionHealth.HEALTHY

    return check


def _require_secure_auth_url(url: str) -> None:
    if url.lower().startswith("http://") and not is_local_url(url):
        raise ConfiguredAuthenticationError(
            "configured authentication requires HTTPS for non-local endpoints"
        )


def _health_request(session: ProbeSession, health: AuthHealthCheck) -> ProbeResponse:
    url = health.endpoint.url
    response = session.request(health.method, url)
    if not health.follow_redirects:
        return response
    for _ in range(_MAX_AUTH_REDIRECTS):
        if response.status is None or not _HTTP_REDIRECT_MIN <= response.status < _HTTP_ERROR_MIN:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        next_url = urljoin(response.final_url or url, location)
        if not session.in_scope(next_url):
            return response
        url = next_url
        response = session.request(health.method, url)
    return response


@dataclass(frozen=True, slots=True)
class _ParsedForm:
    action: str
    method: str
    hidden_fields: Mapping[str, str]
    input_names: frozenset[str]


class _LoginFormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[_ParsedForm] = []
        self._action = ""
        self._method = ""
        self._hidden: dict[str, str] | None = None
        self._input_names: set[str] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: Sequence[tuple[str, str | None]],
    ) -> None:
        attributes = {name.casefold(): value or "" for name, value in attrs}
        if tag.casefold() == "form":
            self._action = urljoin(self.base_url, attributes.get("action") or self.base_url)
            self._method = (attributes.get("method") or "GET").upper()
            self._hidden = {}
            self._input_names = set()
            return
        if tag.casefold() != "input" or self._hidden is None or self._input_names is None:
            return
        name = attributes.get("name", "").strip()
        if not name:
            return
        self._input_names.add(name)
        if attributes.get("type", "text").casefold() == "hidden":
            self._hidden[name] = attributes.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() != "form" or self._hidden is None or self._input_names is None:
            return
        self.forms.append(
            _ParsedForm(
                action=self._action,
                method=self._method,
                hidden_fields=dict(self._hidden),
                input_names=frozenset(self._input_names),
            )
        )
        self._hidden = None
        self._input_names = None


def _select_login_form(
    *,
    base_url: str,
    body: str,
    secret_names: Sequence[str],
) -> _ParsedForm | None:
    parser = _LoginFormParser(base_url)
    parser.feed(body)
    if not parser.forms:
        return None
    credential_names = set(secret_names) - {
        _STATIC_HEADER_REFERENCE_ALIAS,
        _TOTP_REFERENCE_ALIAS,
    }
    return max(
        parser.forms,
        key=lambda form: (
            form.method == "POST",
            len(credential_names & form.input_names),
            "password" in form.input_names,
        ),
    )


def _totp(secret: str, config: TotpConfig, *, at: float | None = None) -> str:
    normalized = "".join(secret.split()).upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        key = base64.b32decode(normalized + padding, casefold=True)
    except (binascii.Error, ValueError):
        raise ConfiguredAuthenticationError("configured TOTP secret is not valid base32") from None
    counter = int(time.time() if at is None else at) // config.period_seconds
    digest = hmac.new(
        key,
        struct.pack(">Q", counter),
        config.algorithm,
    ).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % (10**config.digits):0{config.digits}d}"


__all__ = [
    "ConfiguredAuthenticationError",
    "UnsupportedConfiguredAuthFlowError",
    "assert_secure_configured_auth_transport",
    "identity_profile_from_config",
    "identity_profiles_from_config",
]
