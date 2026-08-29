"""Managed authentication boundary for model-driven attack runtimes."""

from __future__ import annotations

import re
import threading
from contextlib import suppress
from copy import copy
from dataclasses import dataclass
from http.cookiejar import Cookie
from pathlib import Path
from typing import TYPE_CHECKING, Never, Self, SupportsIndex

from ravage.web_core.http_probe import ProbeResponse, ProbeSession

from .configured import (
    ConfiguredAuthenticationError,
    assert_secure_configured_auth_transport,
    identity_profile_from_config,
)
from .redaction import AuthArtifactRedactor
from .secrets import SecretResolutionError, SecretResolver, SecretSnapshotResolver, SecretValue
from .sessions import (
    AuthenticationError,
    SessionHandle,
    SessionManager,
    SessionRequestPolicy,
)

_AUTH_COOKIE_NAME_TOKENS = frozenset(
    {"auth", "credential", "jwt", "login", "session", "sid", "token"}
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from pentest_schemas import AuthenticationConfig

    from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController

    from .secrets import SecretRef


@dataclass(frozen=True, slots=True)
class _ManagedIdentitySnapshot:
    headers: tuple[tuple[str, str], ...]
    cookies: tuple[tuple[str, str, str, str], ...]


@dataclass(frozen=True, slots=True)
class TrafficPolicyBinding:
    """Non-secret identity of the whole-run traffic policy owned by an auth lane."""

    state_path: Path
    target_origin: str
    config: TrafficPolicyConfig


class ManagedAttackAuthentication:
    """Own one refreshable identity and its secret-safe attack request lane."""

    __slots__ = (
        "__handle",
        "__identity",
        "__lock",
        "__manager",
        "__probe_identity_snapshots",
        "__probe_sessions",
        "__protected_header_names",
        "__redactor",
        "__traffic_policy",
        "__traffic_policy_binding",
    )

    def __init__(
        self,
        *,
        identity: str,
        manager: SessionManager,
        handle: SessionHandle,
        redactor: AuthArtifactRedactor,
        traffic_policy: TrafficPolicyController | None,
    ) -> None:
        self.__identity = identity
        self.__manager = manager
        self.__handle = handle
        self.__redactor = redactor
        self.__traffic_policy = traffic_policy
        self.__traffic_policy_binding = _traffic_policy_binding(traffic_policy)
        self.__lock = threading.RLock()
        self.__probe_sessions: dict[object, set[ProbeSession]] = {}
        self.__probe_identity_snapshots: dict[ProbeSession, _ManagedIdentitySnapshot] = {}
        self.__protected_header_names = frozenset(
            {
                "api-key",
                "authorization",
                "cookie",
                "proxy-authorization",
                "x-access-token",
                "x-api-key",
                "x-auth-token",
                *(str(name).casefold() for name in handle.session.default_headers),
            }
        )
        self._register_session_secrets(handle)

    @property
    def identity(self) -> str:
        return self.__identity

    @property
    def traffic_policy(self) -> TrafficPolicyController | None:
        """Return the exact whole-run controller retained during construction."""
        return self.__traffic_policy

    @property
    def traffic_policy_binding(self) -> TrafficPolicyBinding | None:
        """Return the immutable, non-secret identity of the owned traffic policy."""
        return self.__traffic_policy_binding

    def assert_traffic_policy(
        self,
        traffic_policy: TrafficPolicyController | None,
    ) -> None:
        """Fail closed unless a caller uses this owner's whole-run policy binding."""
        expected = self.__traffic_policy_binding
        if expected is None or traffic_policy is None:
            message = "managed authentication traffic policy binding mismatch"
            raise AuthenticationError(message)
        try:
            retained = _traffic_policy_binding(self.__traffic_policy)
            current = _traffic_policy_binding(traffic_policy)
        except Exception:  # noqa: BLE001 - policy details must not escape this boundary.
            retained = None
            current = None
        if retained != expected or current != expected:
            message = "managed authentication traffic policy binding mismatch"
            raise AuthenticationError(message)

    def session_for_probe(self, *, timeout_seconds: int = 10) -> ProbeSession:
        """Return an isolated probe session whose requests stay owner-managed."""
        try:
            with self.__lock:
                self.__handle = self.__manager.ensure_healthy(self.__handle)
                self._register_session_secrets(self.__handle)
                session = self.__handle.session.fork(timeout_seconds=timeout_seconds)
                lease = object()
                session.bind_managed_request_delegate(
                    self._request_from_probe,
                    generation=self.__handle.generation,
                    lease=lease,
                    session_observer=self._register_probe_session,
                )
                self._register_probe_session_secrets(session)
                return session
        except Exception:  # noqa: BLE001 - sanitize every ordinary health failure.
            message = "managed authentication health check failed"
            raise AuthenticationError(message) from None

    def session_for_model_action(self, *, timeout_seconds: int = 10) -> ProbeSession:
        """Return an isolated model lane that cannot replace identity headers."""
        try:
            with self.__lock:
                self.__handle = self.__manager.ensure_healthy(self.__handle)
                self._register_session_secrets(self.__handle)
                session = self.__handle.session.fork(timeout_seconds=timeout_seconds)
                lease = object()
                session.bind_managed_request_delegate(
                    self._request_from_model_action,
                    generation=self.__handle.generation,
                    lease=lease,
                    session_observer=self._register_probe_session,
                )
                self._register_probe_session_secrets(session)
                return session
        except Exception:  # noqa: BLE001 - sanitize every ordinary health failure.
            message = "managed authentication health check failed"
            raise AuthenticationError(message) from None

    def retire_probe_session(self, session: ProbeSession) -> None:
        """Clear credentials from a completed ephemeral probe session."""
        with self.__lock:
            lease = session.managed_identity_lease
            sessions = self.__probe_sessions.pop(lease, set()) if lease is not None else {session}
            sessions.add(session)
            for issued in sessions:
                self._retire_probe_session_locked(issued)

    def configure_request_gate(
        self,
        gate: Callable[[str, str], object] | None,
    ) -> None:
        """Count every physical auth lifecycle and action request at dispatch."""
        with self.__lock:
            self.__manager.configure_request_gate(gate)
            for sessions in self.__probe_sessions.values():
                for session in sessions:
                    session.configure_request_gate(gate)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        """Send through the managed identity with bounded safe-read recovery."""
        self._reject_auth_header_override(headers)
        try:
            with self.__lock:
                # A health marker can detect deceptive 200 login pages that a 401-only
                # recovery policy cannot. Refresh before every model-authored PoC step.
                self.__handle = self.__manager.ensure_healthy(self.__handle)
                self._register_session_secrets(self.__handle)
                response = self.__manager.request(
                    self.identity,
                    method,
                    url,
                    data=data,
                    headers=headers,
                    timeout_seconds=timeout_seconds,
                )
                # ``SessionManager.request`` may refresh or invalidate a generation.
                # Retain the current generation for the next action without replaying
                # state-changing requests.
                self.__handle = self.__manager.acquire(self.identity)
                self._register_session_secrets(self.__handle)
                return response
        except Exception:  # noqa: BLE001 - sanitize every ordinary request failure.
            message = "managed authenticated request failed"
            raise AuthenticationError(message) from None

    def redact(self, value: object) -> object:
        """Redact configured and runtime-issued credentials from an artifact value."""
        with self.__lock:
            self._register_session_secrets(self.__handle)
            return self.__redactor.redact(value)

    def redact_text(self, value: str) -> str:
        """Redact configured and runtime-issued credentials from text."""
        with self.__lock:
            self._register_session_secrets(self.__handle)
            return self.__redactor.redact_text(value)

    def redact_prompt(self, value: object) -> object:
        """Redact a model prompt without corrupting ambiguous instruction tokens."""
        with self.__lock:
            self._register_session_secrets(self.__handle)
            return self.__redactor.redact_prompt(value)

    def redact_prompt_text(self, value: str) -> str:
        """Redact prompt text without corrupting ambiguous instruction tokens."""
        with self.__lock:
            self._register_session_secrets(self.__handle)
            return self.__redactor.redact_prompt_text(value)

    def redact_protocol(
        self,
        value: object,
        *,
        protected_keys: Mapping[tuple[str, ...], Sequence[str]],
        protected_field_values: Mapping[tuple[str, ...], Sequence[str]],
    ) -> object:
        """Strictly redact model data while retaining validated protocol vocabulary."""
        with self.__lock:
            self._register_session_secrets(self.__handle)
            return self.__redactor.redact_protocol(
                value,
                protected_keys=protected_keys,
                protected_field_values=protected_field_values,
            )

    def contains_secret(self, value: str) -> bool:
        """Return whether text contains configured or runtime-issued auth material."""
        with self.__lock:
            self._register_session_secrets(self.__handle)
            return self.__redactor.contains_secret(value)

    def close(self) -> None:
        with self.__lock:
            sessions = [session for lease in self.__probe_sessions.values() for session in lease]
            self.__probe_sessions.clear()
            for session in sessions:
                self._retire_probe_session_locked(session)
            self.__probe_identity_snapshots.clear()
            self.__manager.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(identity={self.identity!r}, credentials=[REDACTED])"

    def __reduce__(self) -> Never:
        message = "managed attack authentication cannot be serialized"
        raise TypeError(message)

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        message = "managed attack authentication cannot be serialized"
        raise TypeError(message)

    def _reject_auth_header_override(self, headers: Mapping[str, str] | None) -> None:
        if not headers:
            return
        collision = next(
            (
                str(name)
                for name in headers
                if str(name).casefold() in self.__protected_header_names
            ),
            "",
        )
        if collision:
            message = f"authenticated attack requests cannot override managed header {collision!r}"
            raise ConfiguredAuthenticationError(message)

    def _request_from_probe(
        self,
        session: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        """Health-check and refresh an ephemeral probe lane for every request."""
        try:
            with self.__lock:
                default_controls = self._probe_default_identity_controls(
                    session,
                    handle=self.__handle,
                )
                self.__handle = self.__manager.ensure_healthy(self.__handle)
                self._register_session_secrets(self.__handle)
                self._synchronize_probe_identity(session, self.__handle)
                session.default_headers.update(default_controls)
                control_override = self._probe_uses_identity_control(
                    session,
                    headers=headers,
                    handle=self.__handle,
                )
                response = session._request_direct(  # noqa: SLF001 - owner-bound lane.
                    method,
                    url,
                    data=data,
                    headers=headers,
                    timeout_seconds=timeout_seconds,
                )
                self._register_probe_session_secrets(session)
                # Trusted in-process specialists intentionally vary Cookie or
                # Authorization for paired controls. A rejection is evidence for
                # that variant, not proof that the owner session expired.
                if control_override:
                    return response
                policy = SessionRequestPolicy()
                if response.status != 401:
                    return response
                if not policy.permits_replay(method, response.status):
                    self.__manager.invalidate(self.__handle)
                    return response
                self.__handle = self.__manager.relogin(self.__handle)
                self._register_session_secrets(self.__handle)
                self._synchronize_probe_identity(session, self.__handle)
                retried = session._request_direct(  # noqa: SLF001 - owner-bound lane.
                    method,
                    url,
                    data=data,
                    headers=headers,
                    timeout_seconds=timeout_seconds,
                )
                self._register_probe_session_secrets(session)
                if retried.status == 401:
                    self.__manager.invalidate(self.__handle)
                return retried
        except ConfiguredAuthenticationError:
            raise
        except Exception:  # noqa: BLE001 - never expose target/auth failure details.
            with self.__lock:
                self._register_probe_session_secrets(session)
            message = "managed authenticated probe request failed"
            raise AuthenticationError(message) from None

    def _request_from_model_action(  # noqa: PLR0913 - managed delegate protocol.
        self,
        session: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        """Dispatch a model-authored request without allowing identity replacement."""
        self._reject_auth_header_override(headers)
        self._reject_model_session_header_override(session)
        return self._request_from_probe(
            session,
            method,
            url,
            data=data,
            headers=headers,
            timeout_seconds=timeout_seconds,
        )

    def _reject_model_session_header_override(self, session: ProbeSession) -> None:
        with self.__lock:
            snapshot = self.__probe_identity_snapshots.get(session)
            managed_headers = dict(snapshot.headers) if snapshot is not None else {}
            collision = next(
                (
                    str(name)
                    for name, value in session.default_headers.items()
                    if str(name).casefold() in self.__protected_header_names
                    and managed_headers.get(str(name).casefold()) != str(value)
                ),
                "",
            )
        if collision:
            message = f"authenticated attack requests cannot override managed header {collision!r}"
            raise ConfiguredAuthenticationError(message)

    def _probe_default_identity_controls(
        self,
        session: ProbeSession,
        *,
        handle: SessionHandle,
    ) -> dict[str, str]:
        root_headers = {
            str(name).casefold(): str(value)
            for name, value in handle.session.default_headers.items()
        }
        return {
            str(name): str(value)
            for name, value in session.default_headers.items()
            if str(name).casefold() in self.__protected_header_names
            and root_headers.get(str(name).casefold()) != str(value)
        }

    def _probe_uses_identity_control(
        self,
        session: ProbeSession,
        *,
        headers: Mapping[str, str] | None,
        handle: SessionHandle,
    ) -> bool:
        root_headers = {
            str(name).casefold(): str(value)
            for name, value in handle.session.default_headers.items()
        }
        candidate_headers = {
            str(name).casefold(): str(value) for name, value in session.default_headers.items()
        }
        candidate_headers.update(
            {str(name).casefold(): str(value) for name, value in (headers or {}).items()}
        )
        return any(
            name in self.__protected_header_names and root_headers.get(name) != value
            for name, value in candidate_headers.items()
        )

    def _synchronize_probe_identity(
        self,
        session: ProbeSession,
        handle: SessionHandle,
    ) -> None:
        current_snapshot = self._managed_identity_snapshot(handle.session)
        previous_snapshot = self.__probe_identity_snapshots.get(session)
        if (
            session.managed_identity_generation == handle.generation
            and previous_snapshot == current_snapshot
        ):
            return
        for name in tuple(session.default_headers):
            if name.casefold() in self.__protected_header_names:
                session.default_headers.pop(name, None)
        for name, value in handle.session.default_headers.items():
            if name.casefold() in self.__protected_header_names:
                session.default_headers[name] = value
        prior_cookie_keys = {
            (name, domain, path)
            for name, domain, path, _value in (
                previous_snapshot.cookies if previous_snapshot is not None else ()
            )
        }
        current_cookie_keys = {
            (cookie.name, cookie.domain, cookie.path) for cookie in handle.session.cookies
        }
        retained_cookies = [
            copy(cookie)
            for cookie in session.cookies
            if (cookie.name, cookie.domain, cookie.path)
            not in prior_cookie_keys | current_cookie_keys
        ]
        with suppress(KeyError, ValueError):
            session.cookies.clear()
        for cookie in retained_cookies:
            session.cookies.set_cookie(cookie)
        for cookie in handle.session.cookies:
            session.cookies.set_cookie(copy(cookie))
        session.update_managed_identity_generation(handle.generation)
        self.__probe_identity_snapshots[session] = current_snapshot

    def _register_session_secrets(self, handle: SessionHandle) -> None:
        handle.session.configure_managed_identity_forks(
            header_names=self.__protected_header_names,
        )
        self._register_probe_session_secrets(handle.session)

    def _register_probe_session(
        self,
        lease: object,
        session: ProbeSession,
        source_session: ProbeSession | None,
    ) -> None:
        with self.__lock:
            if source_session is None:
                snapshot = self._managed_identity_snapshot(self.__handle.session)
            else:
                snapshot = self.__probe_identity_snapshots.get(source_session)
                if snapshot is None:
                    message = "managed identity parent session is no longer active"
                    raise AuthenticationError(message)
            self.__probe_sessions.setdefault(lease, set()).add(session)
            self.__probe_identity_snapshots[session] = snapshot

    def _retire_probe_session_locked(self, session: ProbeSession) -> None:
        self._register_probe_session_secrets(session)
        self.__probe_identity_snapshots.pop(session, None)
        session.unbind_managed_request_delegate()
        for name in tuple(session.default_headers):
            if name.casefold() in self.__protected_header_names:
                session.default_headers.pop(name, None)
        with suppress(KeyError, ValueError):
            session.cookies.clear()

    def _register_probe_session_secrets(self, session: ProbeSession) -> None:
        for cookie in session.cookies:
            if not isinstance(cookie, Cookie) or not isinstance(cookie.value, str):
                continue
            if not cookie.value:
                continue
            auth_material = _cookie_is_auth_material(cookie)
            self.__redactor.register_secret_values(
                (SecretValue(cookie.value),),
                context_free=(auth_material and len(str(cookie.value)) >= 12),
                url_segment=auth_material,
            )

    def _managed_identity_snapshot(self, session: ProbeSession) -> _ManagedIdentitySnapshot:
        return _ManagedIdentitySnapshot(
            headers=tuple(
                sorted(
                    (str(name).casefold(), str(value))
                    for name, value in session.default_headers.items()
                    if str(name).casefold() in self.__protected_header_names
                )
            ),
            cookies=tuple(
                sorted(
                    (
                        str(cookie.name),
                        str(cookie.domain),
                        str(cookie.path),
                        str(cookie.value),
                    )
                    for cookie in session.cookies
                )
            ),
        )


def build_authenticated_attack_runtime(  # noqa: PLR0913 - explicit public builder API.
    *,
    config: AuthenticationConfig,
    target_url: str,
    identity: str,
    timeout_seconds: int,
    allow_remote_target: bool,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
    max_rps: int | None,
    secret_resolver: SecretResolver,
    traffic_policy: TrafficPolicyController | None = None,
    traffic_policy_reference: dict[str, object] | None = None,
) -> ManagedAttackAuthentication:
    """Build and authenticate one attack identity without mutating secret sources."""
    assert_secure_configured_auth_transport(
        config,
        target_url=target_url,
        alias=identity,
    )
    profile = identity_profile_from_config(config, identity)
    resolved_secrets: dict[SecretRef, SecretValue] = {}
    for reference in profile.secrets.values():
        if reference in resolved_secrets:
            continue
        resolved = secret_resolver.resolve(reference)
        if not resolved:
            message = f"secret reference is empty: {reference.provider}:{reference.key}"
            raise SecretResolutionError(message)
        resolved_secrets[reference] = resolved

    base_session = ProbeSession(
        target_url,
        timeout_seconds=timeout_seconds,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        max_rps=max_rps,
        traffic_policy=traffic_policy,
        traffic_policy_reference=traffic_policy_reference,
    )
    redactor = AuthArtifactRedactor()
    redactor.register_named_secret_values(
        {name: resolved_secrets[reference] for name, reference in profile.secrets.items()}
    )
    manager = SessionManager(
        base_session,
        (profile,),
        secret_resolver=SecretSnapshotResolver(resolved_secrets),
    )
    try:
        handle = manager.acquire(identity)
        return ManagedAttackAuthentication(
            identity=identity,
            manager=manager,
            handle=handle,
            redactor=redactor,
            traffic_policy=base_session.traffic_policy,
        )
    except Exception:  # noqa: BLE001 - prevent initialization details from escaping.
        with suppress(Exception):
            manager.close()
        message = "managed authentication initialization failed"
        raise AuthenticationError(message) from None


def _cookie_is_auth_material(cookie: Cookie) -> bool:
    name = str(cookie.name or "").casefold()
    tokens = frozenset(part for part in re.split(r"[^a-z0-9]+", name) if part)
    compact = "".join(tokens)
    auth_suffix = compact.endswith(("auth", "jwt", "sessionid", "sessid", "sid", "token"))
    return (
        bool(tokens & _AUTH_COOKIE_NAME_TOKENS) or auth_suffix or len(str(cookie.value or "")) >= 12
    )


def _traffic_policy_binding(
    traffic_policy: TrafficPolicyController | None,
) -> TrafficPolicyBinding | None:
    if traffic_policy is None:
        return None
    return TrafficPolicyBinding(
        state_path=Path(traffic_policy.state_path).expanduser().resolve(strict=True),
        target_origin=str(traffic_policy.target_origin),
        config=traffic_policy.config,
    )


__all__ = [
    "ManagedAttackAuthentication",
    "TrafficPolicyBinding",
    "build_authenticated_attack_runtime",
]
