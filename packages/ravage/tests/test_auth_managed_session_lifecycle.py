# ruff: noqa: EM102, PLR2004, TRY003
from __future__ import annotations

import json
import pickle
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.cookiejar import Cookie

import pytest
from ravage.auth import (
    AuthenticationError,
    HealthCheckError,
    IdentityProfile,
    MappingSecretResolver,
    SecretRef,
    SessionHealth,
    SessionLifecycle,
    SessionManager,
    SessionManagerClosedError,
    SessionRequestPolicy,
    UnknownIdentityError,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession


def _base_session() -> ProbeSession:
    return ProbeSession("http://127.0.0.1:18731/", timeout_seconds=1)


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
        secure=False,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": ""},
        rfc2109=False,
    )


class _ScriptedSession(ProbeSession):
    def __init__(self, state: dict[str, object]) -> None:
        super().__init__("http://127.0.0.1:18731/", timeout_seconds=1)
        self.state = state

    def fork(self, *, timeout_seconds: int | None = None) -> ProbeSession:
        del timeout_seconds
        return _ScriptedSession(self.state)

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
        calls = self.state.setdefault("requests", [])
        assert isinstance(calls, list)
        generation = self.default_headers.get("X-Auth-Generation", "")
        calls.append((method.upper(), generation))
        expired_generations = self.state.get("expired_generations", set())
        assert isinstance(expired_generations, set)
        status = 401 if generation in expired_generations else 200
        return ProbeResponse(
            method=method,
            url=self.absolute(url),
            status=status,
            final_url=self.absolute(url),
            elapsed_ms=1,
            body="unauthorized" if status == 401 else "ok",
        )


def test_each_identity_receives_an_isolated_probe_session_and_cookie_jar() -> None:
    def login(session: ProbeSession, secrets: object) -> bool:
        identity = secrets.identity  # type: ignore[attr-defined]
        session.cookies.set_cookie(_cookie("identity", identity))
        session.default_headers["X-Ravage-Identity"] = identity
        return True

    manager = SessionManager(
        _base_session(),
        [
            IdentityProfile("customer_a", login=login),
            IdentityProfile("customer_b", login=login),
        ],
    )

    first = manager.acquire("customer_a")
    second = manager.acquire("customer_b")

    assert first.session is not second.session
    assert first.session.cookies is not second.session.cookies
    assert first.session.default_headers == {"X-Ravage-Identity": "customer_a"}
    assert second.session.default_headers == {"X-Ravage-Identity": "customer_b"}
    assert [(cookie.name, cookie.value) for cookie in first.session.cookies] == [
        ("identity", "customer_a")
    ]
    assert [(cookie.name, cookie.value) for cookie in second.session.cookies] == [
        ("identity", "customer_b")
    ]


def test_concurrent_initial_acquire_runs_login_once_per_identity() -> None:
    login_count = 0
    count_lock = threading.Lock()

    def login(session: ProbeSession, secrets: object) -> None:
        del session, secrets
        nonlocal login_count
        time.sleep(0.02)
        with count_lock:
            login_count += 1

    manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer", login=login)],
    )

    with ThreadPoolExecutor(max_workers=12) as pool:
        handles = list(pool.map(lambda _: manager.acquire("customer"), range(24)))

    assert login_count == 1
    assert {handle.generation for handle in handles} == {1}
    assert len({id(handle.session) for handle in handles}) == 1


def test_different_identities_do_not_share_a_lifecycle_lock() -> None:
    both_logins_started = threading.Barrier(2)

    def login(session: ProbeSession, secrets: object) -> None:
        del session, secrets
        both_logins_started.wait(timeout=1)

    manager = SessionManager(
        _base_session(),
        [
            IdentityProfile("customer_a", login=login),
            IdentityProfile("customer_b", login=login),
        ],
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(manager.acquire, "customer_a"),
            pool.submit(manager.acquire, "customer_b"),
        ]

    assert [future.result().generation for future in futures] == [1, 1]


def test_generation_bound_relogin_is_single_flight() -> None:
    login_count = 0
    count_lock = threading.Lock()

    def login(session: ProbeSession, secrets: object) -> None:
        del session, secrets
        nonlocal login_count
        time.sleep(0.02)
        with count_lock:
            login_count += 1

    manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer", login=login)],
    )
    original = manager.acquire("customer")

    with ThreadPoolExecutor(max_workers=12) as pool:
        refreshed = list(pool.map(lambda _: manager.relogin(original), range(24)))

    assert login_count == 2
    assert {handle.generation for handle in refreshed} == {2}
    assert len({id(handle.session) for handle in refreshed}) == 1
    assert not manager.is_current(original)
    assert manager.is_current(refreshed[0])


def test_expired_health_check_relogs_with_a_fresh_generation() -> None:
    login_count = 0

    def login(session: ProbeSession, secrets: object) -> None:
        del secrets
        nonlocal login_count
        login_count += 1
        session.default_headers["X-Session-Healthy"] = "yes"

    def health(session: ProbeSession) -> SessionHealth:
        if session.default_headers.get("X-Session-Healthy") == "yes":
            return SessionHealth.HEALTHY
        return SessionHealth.EXPIRED

    manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer", login=login, health_check=health)],
    )
    original = manager.acquire("customer")
    original.session.default_headers["X-Session-Healthy"] = "no"

    refreshed = manager.ensure_healthy(original)

    assert login_count == 2
    assert refreshed.generation == 2
    assert refreshed.session is not original.session
    assert original.session.default_headers == {}


def test_invalidate_scrubs_session_and_next_acquire_reauthenticates() -> None:
    login_count = 0

    def login(session: ProbeSession, secrets: object) -> None:
        del secrets
        nonlocal login_count
        login_count += 1
        session.default_headers["Authorization"] = f"Bearer generation-{login_count}"
        session.cookies.set_cookie(_cookie("session", f"generation-{login_count}"))

    manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer", login=login)],
    )
    original = manager.acquire("customer")

    assert manager.invalidate(original)
    assert original.session.default_headers == {}
    assert list(original.session.cookies) == []
    assert not manager.invalidate(original)

    current = manager.acquire("customer")
    assert current.generation == 2
    assert current.session.default_headers["Authorization"] == "Bearer generation-2"


def test_login_uses_declared_secrets_without_leaking_them() -> None:
    plaintext = "super-secret-password"

    def login(session: ProbeSession, secrets: object) -> None:
        password = secrets.require("password")  # type: ignore[attr-defined]
        session.default_headers["Authorization"] = f"Bearer {password.reveal()}"
        raise ValueError(f"upstream rejected {password.reveal()}")

    manager = SessionManager(
        _base_session(),
        [
            IdentityProfile(
                "customer",
                login=login,
                secrets={"password": SecretRef("fixture", "password")},
            )
        ],
        secret_resolver=MappingSecretResolver(
            {"password": plaintext},
            provider="fixture",
        ),
    )

    with pytest.raises(AuthenticationError) as captured:
        manager.acquire("customer")

    snapshot = manager.snapshot("customer")
    combined = f"{captured.value!r}\n{manager!r}\n{snapshot!r}\n{snapshot.to_dict()!r}"
    assert plaintext not in combined
    assert snapshot.lifecycle is SessionLifecycle.FAILED
    assert snapshot.last_failure == "authentication_failed"


def test_failed_refresh_scrubs_old_and_candidate_secrets_without_leaking() -> None:
    plaintext = "refresh-secret-must-not-leak"
    attempts = 0

    def login(session: ProbeSession, secrets: object) -> None:
        nonlocal attempts
        attempts += 1
        password = secrets.require("password")  # type: ignore[attr-defined]
        session.default_headers["Authorization"] = f"Bearer {password.reveal()}"
        if attempts > 1:
            raise RuntimeError(f"refresh rejected {password.reveal()}")

    manager = SessionManager(
        _base_session(),
        [
            IdentityProfile(
                "customer",
                login=login,
                secrets={"password": SecretRef("fixture", "password")},
            )
        ],
        secret_resolver=MappingSecretResolver(
            {"password": plaintext},
            provider="fixture",
        ),
    )
    original = manager.acquire("customer")

    with pytest.raises(AuthenticationError) as captured:
        manager.relogin(original)

    snapshot = manager.snapshot("customer")
    combined = f"{captured.value!r}\n{manager!r}\n{snapshot!r}"
    assert plaintext not in combined
    assert original.session.default_headers == {}
    assert snapshot.lifecycle is SessionLifecycle.FAILED
    assert not snapshot.has_session


def test_health_callback_errors_are_sanitized_without_discarding_current_session() -> None:
    sensitive = "health-endpoint-secret"
    checks = 0

    def health(session: ProbeSession) -> bool:
        del session
        nonlocal checks
        checks += 1
        if checks == 1:
            return True
        raise RuntimeError(sensitive)

    manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer", health_check=health)],
    )
    handle = manager.acquire("customer")

    with pytest.raises(HealthCheckError) as captured:
        manager.ensure_healthy(handle)

    assert sensitive not in repr(captured.value)
    assert manager.is_current(handle)
    assert manager.snapshot("customer").last_failure == "health_check_failed"


def test_handles_are_redacted_non_serializable_and_manager_bound() -> None:
    first_manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer")],
    )
    second_manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer")],
    )
    handle = first_manager.acquire("customer")

    assert "ProbeSession" not in repr(handle)
    assert "cookies" not in repr(handle)
    with pytest.raises(TypeError):
        json.dumps(handle)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(handle)
    with pytest.raises(UnknownIdentityError, match="another manager"):
        second_manager.relogin(handle)
    with pytest.raises(AttributeError):
        handle.generation = 9  # type: ignore[misc]


def test_close_scrubs_sessions_and_rejects_new_operations() -> None:
    manager = SessionManager(
        _base_session(),
        [IdentityProfile("customer")],
    )
    handle = manager.acquire("customer")
    handle.session.default_headers["Authorization"] = "Bearer temporary"
    handle.session.cookies.set_cookie(_cookie("session", "temporary"))

    manager.close()
    manager.close()

    assert handle.session.default_headers == {}
    assert list(handle.session.cookies) == []
    snapshot = manager.snapshot("customer")
    assert snapshot.lifecycle is SessionLifecycle.CLOSED
    assert not snapshot.has_session
    with pytest.raises(SessionManagerClosedError):
        manager.acquire("customer")


def _request_manager(
    *,
    expired_generations: set[str],
) -> tuple[SessionManager, dict[str, object]]:
    state: dict[str, object] = {
        "expired_generations": expired_generations,
        "requests": [],
        "logins": 0,
    }

    def login(session: ProbeSession, secrets: object) -> None:
        del secrets
        previous_logins = state["logins"]
        assert isinstance(previous_logins, int)
        logins = previous_logins + 1
        state["logins"] = logins
        session.default_headers["X-Auth-Generation"] = str(logins)

    return (
        SessionManager(
            _ScriptedSession(state),
            [IdentityProfile("customer", login=login)],
        ),
        state,
    )


def test_safe_request_reauthenticates_and_replays_once_after_401() -> None:
    manager, state = _request_manager(expired_generations={"1"})

    response = manager.request("customer", "GET", "/account")

    assert response.status == 200
    assert state["logins"] == 2
    assert state["requests"] == [("GET", "1"), ("GET", "2")]
    assert manager.snapshot("customer").generation == 2


def test_concurrent_safe_401_requests_share_one_refresh_generation() -> None:
    manager, state = _request_manager(expired_generations={"1"})
    manager.acquire("customer")

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: manager.request("customer", "GET", "/account"),
                range(2),
            )
        )

    assert [response.status for response in responses] == [200, 200]
    assert state["logins"] == 2
    assert state["requests"] == [
        ("GET", "1"),
        ("GET", "2"),
        ("GET", "2"),
    ]
    assert manager.snapshot("customer").generation == 2


@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE", "PUT"])
def test_unsafe_401_request_is_invalidated_but_never_replayed(method: str) -> None:
    manager, state = _request_manager(expired_generations={"1"})

    response = manager.request(
        "customer",
        method,
        "/account",
        data=b'{"change":true}',
    )

    assert response.status == 401
    assert state["logins"] == 1
    assert state["requests"] == [(method, "1")]
    assert manager.snapshot("customer").lifecycle is SessionLifecycle.INVALIDATED


def test_second_401_is_returned_without_a_retry_loop() -> None:
    manager, state = _request_manager(expired_generations={"1", "2"})

    response = manager.request("customer", "GET", "/account")

    assert response.status == 401
    assert state["logins"] == 2
    assert state["requests"] == [("GET", "1"), ("GET", "2")]
    assert manager.snapshot("customer").lifecycle is SessionLifecycle.INVALIDATED


def test_request_policy_can_disable_automatic_relogin() -> None:
    manager, state = _request_manager(expired_generations={"1"})

    response = manager.request(
        "customer",
        "GET",
        "/account",
        policy=SessionRequestPolicy(auto_relogin_on_unauthorized=False),
    )

    assert response.status == 401
    assert state["logins"] == 1
    assert state["requests"] == [("GET", "1")]
