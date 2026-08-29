from __future__ import annotations

import re

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
    AuthBenchResponse,
)

_CSRF_PATTERN = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


class ReferenceAuthBenchStrategy:
    """Known-good client used to validate the fixture and evaluator contracts."""

    def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        handlers = {
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
            raise ValueError(f"reference strategy does not support {context.spec.case_id}")
        return handler(context)

    def _form_cookie(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        client = context.new_client()
        identity = _identity(context, "alice")
        login = client.post_form(context.spec.entrypoint, _credentials(identity))
        profile = client.get("/form/profile")
        return AuthBenchObservation(
            authenticated=login.status == 303
            and profile.status == 200
            and _json_string(profile, "identity") == "alice"
        )

    def _rotating_csrf(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        client = context.new_client()
        identity = _identity(context, "alice")
        login_page = client.get(context.spec.entrypoint)
        login_token = _csrf_token(login_page)
        login = client.post_form(
            context.spec.entrypoint,
            {**_credentials(identity), "csrf_token": login_token},
        )
        action_token = _json_string(login, "csrf_token")
        mutation = client.post_form(
            "/csrf/email",
            {
                "csrf_token": action_token,
                "email": "alice+rotated@example.test",
            },
        )
        return AuthBenchObservation(authenticated=login.status == 200 and mutation.status == 200)

    def _bearer_refresh(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        client = context.new_client()
        identity = _identity(context, "alice")
        login = client.post_form(context.spec.entrypoint, _credentials(identity))
        access_token = _json_string(login, "access_token")
        refresh_token = _json_string(login, "refresh_token")
        headers = {"Authorization": f"Bearer {access_token}"}
        initial = client.get("/bearer/resource", headers=headers)
        expired = client.get("/bearer/resource", headers=headers)
        refresh = client.post_form(
            "/bearer/refresh",
            {"refresh_token": refresh_token},
        )
        refreshed_access = _json_string(refresh, "access_token")
        restored = client.get(
            "/bearer/resource",
            headers={"Authorization": f"Bearer {refreshed_access}"},
        )
        return AuthBenchObservation(
            authenticated=initial.status == 200
            and expired.status == 401
            and restored.status == 200,
            refresh_performed=refresh.status == 200,
        )

    def _forced_expiry(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        client = context.new_client()
        identity = _identity(context, "alice")
        first_login = client.post_form(context.spec.entrypoint, _credentials(identity))
        first_access = client.get("/expiry/resource")
        expired = client.get("/expiry/resource")
        second_login = client.post_form(context.spec.entrypoint, _credentials(identity))
        restored = client.get("/expiry/resource")
        return AuthBenchObservation(
            authenticated=first_login.status == 303
            and first_access.status == 200
            and expired.status == 401
            and second_login.status == 303
            and restored.status == 200
        )

    def _two_identity(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        alice_client = context.new_client("alice-client")
        bob_client = context.new_client("bob-client")
        alice = _identity(context, "alice")
        bob = _identity(context, "bob")
        alice_login = alice_client.post_form(context.spec.entrypoint, _credentials(alice))
        bob_login = bob_client.post_form(context.spec.entrypoint, _credentials(bob))
        alice_me = alice_client.get("/multi/me")
        bob_me = bob_client.get("/multi/me")
        alice_cross = alice_client.get("/multi/user/bob")
        bob_cross = bob_client.get("/multi/user/alice")
        identities = (
            _json_string(alice_me, "identity"),
            _json_string(bob_me, "identity"),
        )
        return AuthBenchObservation(
            authenticated=alice_login.status == 303
            and bob_login.status == 303
            and alice_me.status == 200
            and bob_me.status == 200
            and alice_cross.status == 403
            and bob_cross.status == 403,
            identities=identities,
        )

    def _false_auth(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        client = context.new_client()
        identity = _identity(context, "alice")
        client.post_form(context.spec.entrypoint, _credentials(identity))
        protected = client.get("/negative/profile")
        return AuthBenchObservation(authenticated=protected.status == 200)

    def _unsafe_post(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
        client = context.new_client()
        identity = _identity(context, "alice")
        login = client.post_form(context.spec.entrypoint, _credentials(identity))
        client.post_form("/unsafe/charge", {"amount": "25"})
        return AuthBenchObservation(
            authenticated=login.status == 303,
            unsafe_request_replayed=False,
        )


def _identity(context: AuthBenchCaseContext, identity_id: str) -> AuthBenchIdentity:
    for identity in context.spec.identities:
        if identity.identity_id == identity_id:
            return identity
    raise ValueError(f"case {context.spec.case_id} has no {identity_id} identity")


def _credentials(identity: AuthBenchIdentity) -> dict[str, str]:
    return {"username": identity.username, "password": identity.password}


def _csrf_token(response: AuthBenchResponse) -> str:
    match = _CSRF_PATTERN.search(response.body)
    if match is None:
        raise ValueError("login response did not contain a CSRF token")
    return match.group(1)


def _json_string(response: AuthBenchResponse, key: str) -> str:
    value = response.json().get(key)
    if not isinstance(value, str):
        raise ValueError(f"response field {key} is not a string")
    return value
