# ruff: noqa: EM101, EM102, PLR2004, TRY003
"""Read-only, identity-isolated runtime for authorization matrix checks."""

from __future__ import annotations

from contextlib import suppress
from types import MappingProxyType
from typing import TYPE_CHECKING, Never, Self, SupportsIndex

from ravage.web_core.http_probe import ProbeNetworkContext, ProbeResponse, ProbeSession

from .authorization_matrix import ANONYMOUS_ACTOR, AuthorizationMatrixRuntimeError
from .configured import ConfiguredAuthenticationError
from .runtime import ManagedAttackAuthentication, build_authenticated_attack_runtime
from .sessions import AuthenticationError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from pentest_schemas import AuthenticationConfig

    from ravage.traffic.policy import TrafficPolicyController, TrafficPolicySnapshot

    from .secrets import SecretResolver

_ANONYMOUS_IDENTITY = ANONYMOUS_ACTOR
_RESERVED_IDENTITY_ALIASES = frozenset({_ANONYMOUS_IDENTITY, "anon"})
_SAFE_MATRIX_METHOD = "GET"


class ManagedAuthorizationMatrix:
    """Own isolated identities and one anonymous lane under one traffic policy."""

    __slots__ = (
        "__anonymous_session",
        "__closed",
        "__identities",
        "__initial_traffic_snapshot",
        "__network_context",
        "__owners",
        "__roles",
        "__traffic_policy",
    )

    def __init__(
        self,
        *,
        owners: Mapping[str, ManagedAttackAuthentication],
        roles: Mapping[str, tuple[str, ...]],
        anonymous_session: ProbeSession,
        traffic_policy: TrafficPolicyController,
        initial_traffic_snapshot: TrafficPolicySnapshot,
        network_context: ProbeNetworkContext | None = None,
    ) -> None:
        shared_network_context = network_context or anonymous_session.network_context
        normalized_owners = dict(owners)
        identities = tuple(sorted(normalized_owners))
        if len(identities) < 2:
            raise AuthorizationMatrixRuntimeError(
                "authorization matrix requires at least two configured identities"
            )
        if any(alias.casefold() in _RESERVED_IDENTITY_ALIASES for alias in identities):
            raise AuthorizationMatrixRuntimeError(
                "configured identities cannot use the reserved anonymous alias"
            )
        if set(roles) != set(identities):
            raise AuthorizationMatrixRuntimeError(
                "authorization matrix roles do not match its identities"
            )
        if anonymous_session.traffic_policy is not traffic_policy:
            raise AuthorizationMatrixRuntimeError(
                "anonymous matrix traffic is not bound to the shared policy"
            )
        if anonymous_session.network_context is not shared_network_context:
            raise AuthorizationMatrixRuntimeError(
                "anonymous matrix traffic is not bound to the shared network context"
            )
        for alias, owner in normalized_owners.items():
            if owner.identity != alias:
                raise AuthorizationMatrixRuntimeError(
                    "authorization matrix owner identity does not match its alias"
                )
            try:
                owner.assert_traffic_policy(traffic_policy)
            except AuthenticationError as exc:
                raise AuthorizationMatrixRuntimeError(
                    "authorization matrix identities do not share one traffic policy"
                ) from exc
            if owner.network_context is not shared_network_context:
                raise AuthorizationMatrixRuntimeError(
                    "authorization matrix identities do not share one network context"
                )

        self.__owners = MappingProxyType(normalized_owners)
        self.__roles = MappingProxyType(
            {alias: tuple(sorted(set(roles[alias]))) for alias in identities}
        )
        self.__identities = identities
        self.__anonymous_session = anonymous_session
        self.__traffic_policy = traffic_policy
        self.__initial_traffic_snapshot = initial_traffic_snapshot
        self.__network_context = shared_network_context
        self.__closed = False

    @property
    def identities(self) -> tuple[str, ...]:
        return self.__identities

    @property
    def initial_traffic_snapshot(self) -> TrafficPolicySnapshot:
        return self.__initial_traffic_snapshot

    def roles(self, identity_alias: str) -> tuple[str, ...]:
        if identity_alias == _ANONYMOUS_IDENTITY:
            return ()
        try:
            return self.__roles[identity_alias]
        except KeyError:
            raise AuthorizationMatrixRuntimeError("unknown authorization matrix identity") from None

    def identity_generation(self, identity_alias: str | None) -> int:
        """Return non-secret generation metadata for stability checks."""
        self._require_open()
        if identity_alias is None or identity_alias == _ANONYMOUS_IDENTITY:
            return 0
        try:
            return self.__owners[identity_alias].identity_generation
        except KeyError:
            raise AuthorizationMatrixRuntimeError("unknown authorization matrix identity") from None

    def in_scope(self, url: str) -> bool:
        """Apply the exact shared session scope without exposing credentials."""
        self._require_open()
        return self.__anonymous_session.in_scope(url)

    def request(self, identity_alias: str | None, method: str, url: str) -> ProbeResponse:
        """Issue one GET without exposing or accepting authentication material."""
        self._require_open()
        normalized_method = str(method or "").strip().upper()
        if normalized_method != _SAFE_MATRIX_METHOD:
            raise AuthorizationMatrixRuntimeError("authorization matrix permits GET requests only")
        if identity_alias is None or identity_alias == _ANONYMOUS_IDENTITY:
            return self.__anonymous_session.request(_SAFE_MATRIX_METHOD, url)
        try:
            owner = self.__owners[identity_alias]
        except KeyError:
            raise AuthorizationMatrixRuntimeError("unknown authorization matrix identity") from None
        return owner.request(_SAFE_MATRIX_METHOD, url)

    def traffic_snapshot(self) -> TrafficPolicySnapshot:
        self._require_open()
        return self.__traffic_policy.snapshot()

    def close(self) -> None:
        if self.__closed:
            return
        self.__closed = True
        for owner in self.__owners.values():
            with suppress(Exception):
                owner.close()
        self.__anonymous_session.default_headers.clear()
        with suppress(KeyError, ValueError):
            self.__anonymous_session.cookies.clear()

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(identities={self.identities!r}, "
            "credentials=[REDACTED])"
        )

    def __reduce__(self) -> Never:
        raise TypeError("managed authorization matrices cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("managed authorization matrices cannot be serialized")

    def _require_open(self) -> None:
        if self.__closed:
            raise AuthorizationMatrixRuntimeError("authorization matrix runtime is closed")


def build_managed_authorization_matrix(  # noqa: PLR0913
    *,
    config: AuthenticationConfig,
    target_url: str,
    identities: Sequence[str],
    timeout_seconds: int,
    allow_remote_target: bool,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
    max_rps: float | None,
    secret_resolver: SecretResolver,
    traffic_policy: TrafficPolicyController,
    network_context: ProbeNetworkContext | None = None,
) -> ManagedAuthorizationMatrix:
    """Authenticate selected identities while retaining one global request ledger."""
    selected = tuple(sorted({str(alias).strip() for alias in identities if str(alias).strip()}))
    if len(selected) < 2:
        raise AuthorizationMatrixRuntimeError(
            "authorization matrix requires at least two configured identities"
        )
    if any(alias.casefold() in _RESERVED_IDENTITY_ALIASES for alias in selected):
        raise AuthorizationMatrixRuntimeError(
            "configured identities cannot use the reserved anonymous alias"
        )

    configured = {identity.alias: identity for identity in config.identities}
    missing = tuple(alias for alias in selected if alias not in configured)
    if missing:
        available = ", ".join(sorted(configured))
        raise ConfiguredAuthenticationError(
            f"unknown authorization matrix identity; configured identities: {available}"
        )

    initial_snapshot = traffic_policy.snapshot()
    shared_network_context = network_context or ProbeNetworkContext()
    owners: dict[str, ManagedAttackAuthentication] = {}
    anonymous_session: ProbeSession | None = None
    try:
        for alias in selected:
            owners[alias] = build_authenticated_attack_runtime(
                config=config,
                target_url=target_url,
                identity=alias,
                timeout_seconds=timeout_seconds,
                allow_remote_target=allow_remote_target,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
                max_rps=max_rps,
                secret_resolver=secret_resolver,
                traffic_policy=traffic_policy,
                network_context=shared_network_context,
            )
        anonymous_session = ProbeSession(
            target_url,
            timeout_seconds=timeout_seconds,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            max_rps=max_rps,
            traffic_policy=traffic_policy,
            network_context=shared_network_context,
        )
        return ManagedAuthorizationMatrix(
            owners=owners,
            roles={alias: tuple(configured[alias].roles) for alias in selected},
            anonymous_session=anonymous_session,
            traffic_policy=traffic_policy,
            initial_traffic_snapshot=initial_snapshot,
            network_context=shared_network_context,
        )
    except Exception:
        for owner in owners.values():
            with suppress(Exception):
                owner.close()
        if anonymous_session is not None:
            anonymous_session.default_headers.clear()
            with suppress(KeyError, ValueError):
                anonymous_session.cookies.clear()
        raise


__all__ = [
    "AuthorizationMatrixRuntimeError",
    "ManagedAuthorizationMatrix",
    "build_managed_authorization_matrix",
]
