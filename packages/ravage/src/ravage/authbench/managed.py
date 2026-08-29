from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import cast
from urllib.parse import urlencode

from ravage.auth import (
    AuthenticationError,
    IdentityProfile,
    IdentitySecrets,
    SessionManager,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

from .contracts import AuthBenchIdentity, AuthBenchObservation
from .fixtures import (
    BEARER_REFRESH_CASE,
    FALSE_AUTH_CASE,
    FORCED_EXPIRY_CASE,
    FORM_COOKIE_CASE,
    ROTATING_CSRF_CASE,
    TWO_IDENTITY_CASE,
    UNSAFE_POST_CASE,
    AuthBenchCaseContext,
)

_CSRF_PATTERN = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


class ManagedSessionAuthBenchStrategy:
    """Exercise AuthBench through Ravage's production ``SessionManager``."""

    def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        handlers: dict[
            str,
            Callable[[AuthBenchCaseContext], AuthBenchObservation],
        ] = {
            FORM_COOKIE_CASE: self._form_cookie,
            ROTATING_CSRF_CASE: self._rotating_csrf,
            BEARER_REFRESH_CASE: self._bearer_refresh,
            FORCED_EXPIRY_CASE: self._forced_expiry,
            TWO_IDENTITY_CASE: self._two_identity,
            FALSE_AUTH_CASE: self._false_auth,
            UNSAFE_POST_CASE: self._unsafe_post,
        }
        handler = handlers.get(context.spec.case_id)
        if handler is None:
            raise ValueError(f"managed session strategy does not support {context.spec.case_id}")
        return handler(context)

    def _form_cookie(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        identity = _identity(context, "alice")
        profile = IdentityProfile(
            name=identity.identity_id,
            login=_form_login(context.spec.entrypoint, identity, expected_status=303),
        )
        with _manager(context, profile) as manager:
            profile_response = manager.request("alice", "GET", "/form/profile")
        return AuthBenchObservation(
            authenticated=profile_response.status == 200
            and _json_string(profile_response, "identity") == "alice"
        )

    def _rotating_csrf(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        identity = _identity(context, "alice")
        current_action_token: dict[str, str] = {}

        def login(session: ProbeSession, secrets: IdentitySecrets) -> bool:
            del secrets
            login_page = session.get(context.spec.entrypoint)
            token = _csrf_token(login_page)
            response = session.post_form(
                context.spec.entrypoint,
                {**_credentials(identity), "csrf_token": token},
            )
            if response.status != 200:
                return False
            current_action_token["value"] = _json_string(response, "csrf_token")
            return True

        profile = IdentityProfile(name="alice", login=login)
        with _manager(context, profile) as manager:
            manager.acquire("alice")
            mutation = manager.request(
                "alice",
                "POST",
                "/csrf/email",
                data=_form_data(
                    {
                        "csrf_token": current_action_token.get("value", ""),
                        "email": "alice+managed@example.test",
                    }
                ),
            )
        return AuthBenchObservation(authenticated=mutation.status == 200)

    def _bearer_refresh(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        identity = _identity(context, "alice")
        token_state: dict[str, str] = {}
        refreshed = False

        def login(session: ProbeSession, secrets: IdentitySecrets) -> bool:
            nonlocal refreshed
            del secrets
            refresh_token = token_state.get("refresh_token")
            if refresh_token is None:
                response = session.post_form(
                    context.spec.entrypoint,
                    _credentials(identity),
                )
            else:
                response = session.post_form(
                    "/bearer/refresh",
                    {"refresh_token": refresh_token},
                )
                refreshed = response.status == 200
            if response.status != 200:
                return False
            token_state["refresh_token"] = _json_string(response, "refresh_token")
            session.default_headers["Authorization"] = (
                f"Bearer {_json_string(response, 'access_token')}"
            )
            return True

        profile = IdentityProfile(name="alice", login=login)
        with _manager(context, profile) as manager:
            initial = manager.request("alice", "GET", "/bearer/resource")
            restored = manager.request("alice", "GET", "/bearer/resource")
        return AuthBenchObservation(
            authenticated=initial.status == 200 and restored.status == 200,
            refresh_performed=refreshed,
        )

    def _forced_expiry(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        identity = _identity(context, "alice")
        profile = IdentityProfile(
            name="alice",
            login=_form_login(context.spec.entrypoint, identity, expected_status=303),
        )
        with _manager(context, profile) as manager:
            initial = manager.request("alice", "GET", "/expiry/resource")
            restored = manager.request("alice", "GET", "/expiry/resource")
        return AuthBenchObservation(authenticated=initial.status == 200 and restored.status == 200)

    def _two_identity(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        alice = _identity(context, "alice")
        bob = _identity(context, "bob")
        profiles = tuple(
            IdentityProfile(
                name=identity.identity_id,
                login=_form_login(
                    context.spec.entrypoint,
                    identity,
                    expected_status=303,
                ),
            )
            for identity in (alice, bob)
        )
        with _manager(context, *profiles) as manager:
            alice_me = manager.request("alice", "GET", "/multi/me")
            bob_me = manager.request("bob", "GET", "/multi/me")
            alice_cross = manager.request("alice", "GET", "/multi/user/bob")
            bob_cross = manager.request("bob", "GET", "/multi/user/alice")
        identities = (
            _json_string(alice_me, "identity"),
            _json_string(bob_me, "identity"),
        )
        return AuthBenchObservation(
            authenticated=alice_me.status == 200
            and bob_me.status == 200
            and alice_cross.status == 403
            and bob_cross.status == 403,
            identities=identities,
        )

    def _false_auth(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        identity = _identity(context, "alice")

        def login(session: ProbeSession, secrets: IdentitySecrets) -> bool:
            del secrets
            response = session.post_form(
                context.spec.entrypoint,
                _credentials(identity),
            )
            if response.status != 200:
                return False
            verification = session.get("/negative/profile")
            return bool(verification.status == 200)

        manager = _manager(context, IdentityProfile(name="alice", login=login))
        try:
            with manager:
                manager.acquire("alice")
        except AuthenticationError:
            return AuthBenchObservation(authenticated=False)
        return AuthBenchObservation(authenticated=True)

    def _unsafe_post(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        identity = _identity(context, "alice")
        profile = IdentityProfile(
            name="alice",
            login=_form_login(context.spec.entrypoint, identity, expected_status=303),
        )
        with _manager(context, profile) as manager:
            response = manager.request(
                "alice",
                "POST",
                "/unsafe/charge",
                data=_form_data({"amount": "25"}),
            )
        return AuthBenchObservation(
            authenticated=response.status == 401,
            unsafe_request_replayed=False,
        )


def _manager(
    context: AuthBenchCaseContext,
    *profiles: IdentityProfile,
) -> SessionManager:
    base = context.new_client("managed-session-base")
    return SessionManager(cast(ProbeSession, base), profiles)


def _form_login(
    path: str,
    identity: AuthBenchIdentity,
    *,
    expected_status: int,
) -> Callable[[ProbeSession, IdentitySecrets], bool]:
    def login(session: ProbeSession, secrets: IdentitySecrets) -> bool:
        del secrets
        response = session.post_form(path, _credentials(identity))
        return bool(response.status == expected_status)

    return login


def _identity(context: AuthBenchCaseContext, identity_id: str) -> AuthBenchIdentity:
    for identity in context.spec.identities:
        if identity.identity_id == identity_id:
            return identity
    raise ValueError(f"case {context.spec.case_id} has no {identity_id} identity")


def _credentials(identity: AuthBenchIdentity) -> dict[str, str]:
    return {"username": identity.username, "password": identity.password}


def _form_data(fields: dict[str, str]) -> bytes:
    return urlencode(fields).encode("utf-8")


def _csrf_token(response: ProbeResponse) -> str:
    match = _CSRF_PATTERN.search(response.body)
    if match is None:
        raise ValueError("login response did not contain a CSRF token")
    return match.group(1)


def _json_string(response: ProbeResponse, key: str) -> str:
    value = json.loads(response.body).get(key)
    if not isinstance(value, str):
        raise ValueError(f"response field {key} is not a string")
    return value
