# ruff: noqa: BLE001, EM101, EM102, FBT001, PLR0913, SLF001, TRY003, TRY301
from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Never, Self, SupportsIndex

from ravage.web_core.http_probe import ProbeResponse, ProbeSession

from .secrets import EnvironmentSecretResolver, SecretRef, SecretResolver, SecretValue

_IDENTITY_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_UNAUTHORIZED_STATUS = 401
_AUTOMATIC_REPLAY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class SessionError(RuntimeError):
    """Base error for managed authentication sessions."""


class UnknownIdentityError(SessionError):
    """The requested identity was not registered with the manager."""


class SessionManagerClosedError(SessionError):
    """The manager no longer accepts session operations."""


class AuthenticationError(SessionError):
    """An identity could not establish an authenticated session."""


class HealthCheckError(SessionError):
    """An identity health callback failed without exposing its raw exception."""


class SessionHealth(StrEnum):
    HEALTHY = "healthy"
    EXPIRED = "expired"


class SessionLifecycle(StrEnum):
    NEW = "new"
    AUTHENTICATING = "authenticating"
    READY = "ready"
    INVALIDATED = "invalidated"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class SessionRequestPolicy:
    """
    Conservative unauthorized-session recovery for managed HTTP requests.

    Replay is deliberately limited to HTTP read operations. Even methods that
    are nominally idempotent can trigger unsafe application behavior, so PUT,
    DELETE, POST, and PATCH are never automatically replayed.
    """

    auto_relogin_on_unauthorized: bool = True

    def permits_replay(self, method: str, status: int | None) -> bool:
        return (
            self.auto_relogin_on_unauthorized
            and status == _UNAUTHORIZED_STATUS
            and method.upper() in _AUTOMATIC_REPLAY_METHODS
        )


class IdentitySecrets:
    """A redacted, identity-scoped view over declared secret references."""

    __slots__ = ("__identity", "__references", "__resolver")

    def __init__(
        self,
        identity: str,
        references: Mapping[str, SecretRef],
        resolver: SecretResolver,
    ) -> None:
        self.__identity = identity
        self.__references = references
        self.__resolver = resolver

    @property
    def identity(self) -> str:
        return self.__identity

    def require(self, name: str) -> SecretValue:
        try:
            reference = self.__references[name]
        except KeyError:
            raise KeyError(f"identity {self.__identity!r} has no secret named {name!r}") from None
        return self.__resolver.resolve(reference)

    def __getitem__(self, name: str) -> SecretValue:
        return self.require(name)

    def __contains__(self, name: object) -> bool:
        return name in self.__references

    def keys(self) -> tuple[str, ...]:
        return tuple(self.__references)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(identity={self.__identity!r}, "
            f"names={self.keys()!r}, values=[REDACTED])"
        )

    def __reduce__(self) -> Never:
        raise TypeError("identity secrets cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("identity secrets cannot be serialized")


type LoginCallback = Callable[[ProbeSession, IdentitySecrets], bool | None]
type HealthCheckCallback = Callable[[ProbeSession], bool | SessionHealth]


@dataclass(frozen=True, slots=True)
class IdentityProfile:
    """Authentication lifecycle hooks for one isolated logical identity."""

    name: str
    login: LoginCallback | None = field(default=None, repr=False, compare=False)
    health_check: HealthCheckCallback | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    secrets: Mapping[str, SecretRef] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _IDENTITY_NAME.fullmatch(self.name):
            raise ValueError(
                "identity name must begin with a letter and contain only "
                "letters, numbers, dots, dashes, or underscores"
            )
        copied: dict[str, SecretRef] = {}
        for name, reference in self.secrets.items():
            if not isinstance(name, str) or not _IDENTITY_NAME.fullmatch(name):
                raise ValueError("secret alias must be a simple non-empty name")
            if not isinstance(reference, SecretRef):
                raise TypeError("identity secrets must contain SecretRef values")
            copied[name] = reference
        object.__setattr__(self, "secrets", MappingProxyType(copied))

    @property
    def requires_login(self) -> bool:
        return self.login is not None

    def to_public_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "requires_login": self.requires_login,
            "has_health_check": self.health_check is not None,
            "secrets": {
                name: reference.to_public_dict() for name, reference in self.secrets.items()
            },
        }


class SessionHandle:
    """A generation-bound reference to one identity's current HTTP session."""

    __slots__ = ("__generation", "__identity", "__manager_token", "__session")

    def __init__(
        self,
        *,
        identity: str,
        generation: int,
        session: ProbeSession,
        manager_token: object,
    ) -> None:
        self.__identity = identity
        self.__generation = generation
        self.__session = session
        self.__manager_token = manager_token

    @property
    def identity(self) -> str:
        return self.__identity

    @property
    def generation(self) -> int:
        return self.__generation

    @property
    def session(self) -> ProbeSession:
        return self.__session

    def __repr__(self) -> str:
        return f"{type(self).__name__}(identity={self.identity!r}, generation={self.generation})"

    def __reduce__(self) -> Never:
        raise TypeError("session handles cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("session handles cannot be serialized")

    def _belongs_to(self, manager_token: object) -> bool:
        return self.__manager_token is manager_token


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    identity: str
    lifecycle: SessionLifecycle
    generation: int
    has_session: bool
    last_failure: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity,
            "lifecycle": self.lifecycle.value,
            "generation": self.generation,
            "has_session": self.has_session,
            "last_failure": self.last_failure,
        }


@dataclass(slots=True)
class _IdentitySlot:
    profile: IdentityProfile
    lock: threading.RLock = field(default_factory=threading.RLock)
    session: ProbeSession | None = None
    generation: int = 0
    lifecycle: SessionLifecycle = SessionLifecycle.NEW
    last_failure: str = ""


class SessionManager:
    """
    Own isolated, refreshable ``ProbeSession`` instances per identity.

    Lifecycle work is synchronized independently for each identity. A refresh
    accepts the caller's generation-bound handle, so concurrent refreshes of the
    same expired generation collapse into one login operation.
    """

    __slots__ = (
        "__base_session",
        "__closed",
        "__manager_lock",
        "__manager_token",
        "__resolver",
        "__slots_by_name",
    )

    def __init__(
        self,
        base_session: ProbeSession,
        profiles: Iterable[IdentityProfile],
        *,
        secret_resolver: SecretResolver | None = None,
    ) -> None:
        slots: dict[str, _IdentitySlot] = {}
        for profile in profiles:
            if not isinstance(profile, IdentityProfile):
                raise TypeError("profiles must contain IdentityProfile values")
            if profile.name in slots:
                raise ValueError(f"duplicate identity profile: {profile.name}")
            slots[profile.name] = _IdentitySlot(profile=profile)
        if not slots:
            raise ValueError("at least one identity profile is required")
        self.__base_session = base_session
        self.__resolver = secret_resolver or EnvironmentSecretResolver()
        self.__slots_by_name = slots
        self.__manager_token = object()
        self.__manager_lock = threading.Lock()
        self.__closed = False

    @property
    def identities(self) -> tuple[str, ...]:
        return tuple(self.__slots_by_name)

    def acquire(self, identity: str, *, verify: bool = False) -> SessionHandle:
        slot = self._slot(identity)
        with slot.lock:
            self._require_open()
            if slot.session is None or slot.lifecycle is not SessionLifecycle.READY:
                return self._login_locked(slot)
            if (
                verify
                and slot.profile.health_check is not None
                and not self._is_healthy_locked(slot, slot.session)
            ):
                return self._login_locked(slot)
            return self._handle_locked(slot)

    def request(
        self,
        identity: str,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        policy: SessionRequestPolicy | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        """
        Execute an identity-scoped request with bounded 401 recovery.

        A read request may establish one fresh generation and be replayed once.
        State-changing requests are never replayed; their 401 response is
        returned after invalidating the expired generation.
        """
        request_policy = policy or SessionRequestPolicy()
        slot = self._slot(identity)
        # ProbeSession owns a mutable CookieJar. Holding the identity lifecycle
        # lock across request + recovery prevents cookie/token rotation and
        # generation changes from racing within one logical identity.
        with slot.lock:
            self._require_open()
            handle = self.acquire(identity)
            response = handle.session.request(
                method,
                url,
                data=data,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
            if response.status != _UNAUTHORIZED_STATUS:
                return response
            if not request_policy.permits_replay(method, response.status):
                self.invalidate(handle)
                return response
            refreshed = self.relogin(handle)
            retried = refreshed.session.request(
                method,
                url,
                data=data,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
            if retried.status == _UNAUTHORIZED_STATUS:
                self.invalidate(refreshed)
            return retried

    def ensure_healthy(self, handle: SessionHandle) -> SessionHandle:
        slot = self._slot_for_handle(handle)
        with slot.lock:
            self._require_open()
            if not self._matches_locked(slot, handle):
                if slot.session is None or slot.lifecycle is not SessionLifecycle.READY:
                    return self._login_locked(slot)
                return self._handle_locked(slot)
            if slot.profile.health_check is None:
                return self._handle_locked(slot)
            if self._is_healthy_locked(slot, handle.session):
                return self._handle_locked(slot)
            return self._login_locked(slot)

    def relogin(self, handle: SessionHandle) -> SessionHandle:
        """Refresh once for the handle's generation, coalescing other callers."""
        slot = self._slot_for_handle(handle)
        with slot.lock:
            self._require_open()
            if not self._matches_locked(slot, handle):
                if slot.session is None or slot.lifecycle is not SessionLifecycle.READY:
                    return self._login_locked(slot)
                return self._handle_locked(slot)
            return self._login_locked(slot)

    def invalidate(self, handle: SessionHandle) -> bool:
        """Invalidate only if ``handle`` still names the current generation."""
        slot = self._slot_for_handle(handle)
        with slot.lock:
            self._require_open()
            if not self._matches_locked(slot, handle):
                return False
            self._retire_session(slot.session)
            slot.session = None
            slot.lifecycle = SessionLifecycle.INVALIDATED
            slot.last_failure = ""
            return True

    def is_current(self, handle: SessionHandle) -> bool:
        try:
            slot = self._slot_for_handle(handle)
        except SessionError:
            return False
        with slot.lock:
            return self._matches_locked(slot, handle)

    def snapshot(self, identity: str) -> SessionSnapshot:
        slot = self._known_slot(identity)
        with slot.lock:
            return SessionSnapshot(
                identity=identity,
                lifecycle=slot.lifecycle,
                generation=slot.generation,
                has_session=slot.session is not None,
                last_failure=slot.last_failure,
            )

    def configure_request_gate(
        self,
        gate: Callable[[str, str], object] | None,
    ) -> None:
        """Apply a physical-request gate to the base and every live identity."""
        with self.__manager_lock:
            if self.__closed:
                raise SessionManagerClosedError("session manager is closed")
        self.__base_session.configure_request_gate(gate)
        for slot in self.__slots_by_name.values():
            with slot.lock:
                if slot.session is not None:
                    slot.session.configure_request_gate(gate)

    def close(self) -> None:
        with self.__manager_lock:
            if self.__closed:
                return
            self.__closed = True
        for slot in self.__slots_by_name.values():
            with slot.lock:
                self._retire_session(slot.session)
                slot.session = None
                slot.lifecycle = SessionLifecycle.CLOSED
                slot.last_failure = ""

    def __enter__(self) -> Self:
        with self.__manager_lock:
            if self.__closed:
                raise SessionManagerClosedError("session manager is closed")
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(identities={self.identities!r}, closed={self.__closed})"

    def __reduce__(self) -> Never:
        raise TypeError("session managers cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("session managers cannot be serialized")

    def _slot(self, identity: str) -> _IdentitySlot:
        with self.__manager_lock:
            if self.__closed:
                raise SessionManagerClosedError("session manager is closed")
        return self._known_slot(identity)

    def _known_slot(self, identity: str) -> _IdentitySlot:
        try:
            return self.__slots_by_name[identity]
        except KeyError:
            raise UnknownIdentityError(f"unknown identity: {identity}") from None

    def _require_open(self) -> None:
        with self.__manager_lock:
            if self.__closed:
                raise SessionManagerClosedError("session manager is closed")

    def _slot_for_handle(self, handle: SessionHandle) -> _IdentitySlot:
        if not isinstance(handle, SessionHandle) or not handle._belongs_to(self.__manager_token):
            raise UnknownIdentityError("session handle belongs to another manager")
        return self._slot(handle.identity)

    def _matches_locked(self, slot: _IdentitySlot, handle: SessionHandle) -> bool:
        return (
            slot.lifecycle is SessionLifecycle.READY
            and slot.generation == handle.generation
            and slot.session is handle.session
        )

    def _handle_locked(self, slot: _IdentitySlot) -> SessionHandle:
        if slot.session is None or slot.lifecycle is not SessionLifecycle.READY:
            raise SessionError("identity session is not ready")
        return SessionHandle(
            identity=slot.profile.name,
            generation=slot.generation,
            session=slot.session,
            manager_token=self.__manager_token,
        )

    def _login_locked(self, slot: _IdentitySlot) -> SessionHandle:
        slot.lifecycle = SessionLifecycle.AUTHENTICATING
        candidate: ProbeSession | None = None
        try:
            candidate = self.__base_session.fork()
            if slot.profile.login is not None:
                secrets = IdentitySecrets(
                    slot.profile.name,
                    slot.profile.secrets,
                    self.__resolver,
                )
                result = slot.profile.login(candidate, secrets)
                if result is not None and result is not True:
                    raise AuthenticationError("login callback rejected the session")
            if slot.profile.health_check is not None and not self._health_result(
                slot.profile.health_check(candidate)
            ):
                raise AuthenticationError("post-login health check rejected the session")
        except Exception:
            self._retire_session(candidate)
            self._retire_session(slot.session)
            slot.session = None
            slot.lifecycle = SessionLifecycle.FAILED
            slot.last_failure = "authentication_failed"
            raise AuthenticationError(
                f"authentication failed for identity {slot.profile.name!r}"
            ) from None

        self._retire_session(slot.session)
        slot.session = candidate
        slot.generation += 1
        slot.lifecycle = SessionLifecycle.READY
        slot.last_failure = ""
        return self._handle_locked(slot)

    def _is_healthy_locked(
        self,
        slot: _IdentitySlot,
        session: ProbeSession,
    ) -> bool:
        health_check = slot.profile.health_check
        if health_check is None:
            return True
        try:
            healthy = self._health_result(health_check(session))
        except Exception:
            slot.last_failure = "health_check_failed"
            raise HealthCheckError(
                f"health check failed for identity {slot.profile.name!r}"
            ) from None
        slot.last_failure = "" if healthy else "session_expired"
        return healthy

    @staticmethod
    def _health_result(result: bool | SessionHealth) -> bool:
        if result is True or result is SessionHealth.HEALTHY:
            return True
        if result is False or result is SessionHealth.EXPIRED:
            return False
        raise TypeError("health callback must return bool or SessionHealth")

    @staticmethod
    def _retire_session(session: ProbeSession | None) -> None:
        if session is None:
            return
        session.default_headers.clear()
        with suppress(KeyError, ValueError):
            session.cookies.clear()
