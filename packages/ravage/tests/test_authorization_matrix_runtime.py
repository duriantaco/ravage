from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from email.message import Message
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest
from pentest_schemas import (
    AuthEndpoint,
    AuthenticationConfig,
    AuthFlow,
    AuthHealthCheck,
    AuthIdentity,
    SecretReference,
)
from ravage.auth import authorization_matrix_runtime as matrix_runtime
from ravage.auth.authorization_matrix import (
    AuthorizationMatrixCase,
    AuthorizationMatrixPlan,
    AuthorizationMatrixRunner,
    AuthorizationVerdict,
)
from ravage.auth.authorization_matrix_runtime import (
    AuthorizationMatrixRuntimeError,
    ManagedAuthorizationMatrix,
    build_managed_authorization_matrix,
)
from ravage.auth.configured import ConfiguredAuthenticationError
from ravage.auth.secrets import EnvironmentSecretResolver, MappingSecretResolver
from ravage.auth.sessions import AuthenticationError
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyMode,
)
from ravage.web_core.http_probe import ProbeNetworkContext, ProbeResponse

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path
    from urllib.request import Request


_TARGET = "http://127.0.0.1/"
_OWNER_SECRET = "owner-secret-must-not-escape"  # noqa: S105 - redaction sentinel.
_ANONYMOUS_SECRET = "anonymous-secret-must-not-escape"  # noqa: S105 - redaction sentinel.
_BUILT_OWNER_COUNT = 2
_END_TO_END_REQUEST_COUNT = 9
_ALICE_GENERATION = 3
_BOB_GENERATION = 7


@dataclass
class _StubOwner:
    identity: str
    traffic_policy: TrafficPolicyController
    network_context: ProbeNetworkContext | None = None
    identity_generation: int = 1
    secret: str = _OWNER_SECRET
    close_error: Exception | None = None
    requests: list[tuple[str, str]] = field(default_factory=list)
    close_calls: int = 0

    def assert_traffic_policy(self, candidate: TrafficPolicyController) -> None:
        if candidate is not self.traffic_policy:
            message = "stub traffic policy mismatch"
            raise AuthenticationError(message)

    def request(self, method: str, url: str) -> ProbeResponse:
        self.requests.append((method, url))
        return _response(method, url, body=self.identity)

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


@dataclass
class _StubSession:
    traffic_policy: TrafficPolicyController
    network_context: ProbeNetworkContext | None = None
    secret: str = _ANONYMOUS_SECRET
    requests: list[tuple[str, str]] = field(default_factory=list)
    default_headers: dict[str, str] = field(
        default_factory=lambda: {"Authorization": "Bearer anonymous-session-secret"}
    )
    cookies: dict[str, str] = field(default_factory=lambda: {"session": "anonymous-session-cookie"})

    def request(self, method: str, url: str) -> ProbeResponse:
        self.requests.append((method, url))
        return _response(method, url, body="anonymous")


def test_constructor_requires_two_identities_and_matching_role_keys(tmp_path: Path) -> None:
    policy = _traffic_policy(tmp_path)
    network_context = ProbeNetworkContext()
    anonymous = _StubSession(policy, network_context=network_context)
    alice = _StubOwner("alice", policy, network_context=network_context)

    with pytest.raises(AuthorizationMatrixRuntimeError, match="at least two"):
        ManagedAuthorizationMatrix(
            owners={"alice": alice},
            roles={"alice": ("member",)},
            anonymous_session=anonymous,  # type: ignore[arg-type]
            traffic_policy=policy,
            initial_traffic_snapshot=policy.snapshot(),
            network_context=network_context,
        )

    bob = _StubOwner("bob", policy, network_context=network_context)
    with pytest.raises(AuthorizationMatrixRuntimeError, match="roles do not match"):
        ManagedAuthorizationMatrix(
            owners={"alice": alice, "bob": bob},
            roles={"alice": ("member",)},
            anonymous_session=anonymous,  # type: ignore[arg-type]
            traffic_policy=policy,
            initial_traffic_snapshot=policy.snapshot(),
            network_context=network_context,
        )


@pytest.mark.parametrize("reserved_alias", ["anonymous", "Anon", "ANONYMOUS"])
def test_constructor_rejects_reserved_identity_aliases(
    tmp_path: Path,
    reserved_alias: str,
) -> None:
    policy = _traffic_policy(tmp_path)
    network_context = ProbeNetworkContext()

    with pytest.raises(AuthorizationMatrixRuntimeError, match="reserved anonymous alias"):
        ManagedAuthorizationMatrix(
            owners={
                "alice": _StubOwner("alice", policy, network_context=network_context),
                reserved_alias: _StubOwner(
                    reserved_alias,
                    policy,
                    network_context=network_context,
                ),
            },
            roles={"alice": ("member",), reserved_alias: ("guest",)},
            anonymous_session=_StubSession(  # type: ignore[arg-type]
                policy,
                network_context=network_context,
            ),
            traffic_policy=policy,
            initial_traffic_snapshot=policy.snapshot(),
            network_context=network_context,
        )


def test_constructor_rejects_owner_identity_mismatch(tmp_path: Path) -> None:
    policy = _traffic_policy(tmp_path)

    with pytest.raises(AuthorizationMatrixRuntimeError, match="identity does not match"):
        _matrix(
            policy,
            owners={
                "alice": _StubOwner("mallory", policy),
                "bob": _StubOwner("bob", policy),
            },
        )


def test_constructor_rejects_owner_and_anonymous_policy_mismatches(tmp_path: Path) -> None:
    policy = _traffic_policy(tmp_path, name="shared.json")
    other_policy = _traffic_policy(tmp_path, name="other.json")

    with pytest.raises(AuthorizationMatrixRuntimeError, match="identities do not share"):
        _matrix(
            policy,
            owners={
                "alice": _StubOwner("alice", policy),
                "bob": _StubOwner("bob", other_policy),
            },
        )

    with pytest.raises(AuthorizationMatrixRuntimeError, match="anonymous matrix traffic"):
        _matrix(policy, anonymous_session=_StubSession(other_policy))


def test_constructor_rejects_owner_and_anonymous_network_context_mismatches(
    tmp_path: Path,
) -> None:
    policy = _traffic_policy(tmp_path)
    shared = ProbeNetworkContext()
    other = ProbeNetworkContext()

    with pytest.raises(AuthorizationMatrixRuntimeError, match="identities do not share"):
        _matrix(
            policy,
            owners={
                "alice": _StubOwner("alice", policy, network_context=shared),
                "bob": _StubOwner("bob", policy, network_context=other),
            },
            network_context=shared,
        )

    with pytest.raises(AuthorizationMatrixRuntimeError, match="anonymous matrix traffic"):
        _matrix(
            policy,
            anonymous_session=_StubSession(policy, network_context=other),
            network_context=shared,
        )


def test_requests_route_to_configured_and_anonymous_lanes(tmp_path: Path) -> None:
    policy = _traffic_policy(tmp_path)
    alice = _StubOwner("alice", policy)
    bob = _StubOwner("bob", policy)
    anonymous = _StubSession(policy)
    runtime = _matrix(
        policy,
        owners={"alice": alice, "bob": bob},
        anonymous_session=anonymous,
    )

    assert runtime.request("alice", " get ", "/account").body == "alice"
    assert runtime.request(None, "GET", "/public").body == "anonymous"
    assert runtime.request("anonymous", "get", "/health").body == "anonymous"
    assert alice.requests == [("GET", "/account")]
    assert bob.requests == []
    assert anonymous.requests == [("GET", "/public"), ("GET", "/health")]

    with pytest.raises(AuthorizationMatrixRuntimeError, match="unknown authorization"):
        runtime.request("mallory", "GET", "/account")


@pytest.mark.parametrize("method", ["", "HEAD", "POST", "OPTIONS"])
def test_requests_are_get_only(tmp_path: Path, method: str) -> None:
    policy = _traffic_policy(tmp_path)
    alice = _StubOwner("alice", policy)
    anonymous = _StubSession(policy)
    runtime = _matrix(
        policy,
        owners={"alice": alice, "bob": _StubOwner("bob", policy)},
        anonymous_session=anonymous,
    )

    with pytest.raises(AuthorizationMatrixRuntimeError, match="GET requests only"):
        runtime.request("alice", method, "/unsafe")

    assert alice.requests == []
    assert anonymous.requests == []


def test_roles_are_normalized_and_fail_closed_for_unknown_aliases(tmp_path: Path) -> None:
    policy = _traffic_policy(tmp_path)
    source_roles = {
        "alice": ("viewer", "admin", "viewer"),
        "bob": ("member",),
    }
    runtime = _matrix(policy, roles=source_roles)
    source_roles["alice"] = ("changed",)

    assert runtime.identities == ("alice", "bob")
    assert runtime.roles("alice") == ("admin", "viewer")
    assert runtime.roles("bob") == ("member",)
    assert runtime.roles("anonymous") == ()
    with pytest.raises(AuthorizationMatrixRuntimeError, match="unknown authorization"):
        runtime.roles("mallory")


def test_identity_generations_are_exposed_without_credentials(tmp_path: Path) -> None:
    policy = _traffic_policy(tmp_path)
    runtime = _matrix(
        policy,
        owners={
            "alice": _StubOwner(
                "alice",
                policy,
                identity_generation=_ALICE_GENERATION,
            ),
            "bob": _StubOwner(
                "bob",
                policy,
                identity_generation=_BOB_GENERATION,
            ),
        },
    )

    assert runtime.identity_generation("alice") == _ALICE_GENERATION
    assert runtime.identity_generation("bob") == _BOB_GENERATION
    assert runtime.identity_generation(None) == 0
    assert runtime.identity_generation("anonymous") == 0
    with pytest.raises(AuthorizationMatrixRuntimeError, match="unknown authorization"):
        runtime.identity_generation("mallory")


def test_initial_snapshot_is_stable_and_current_snapshot_is_live(tmp_path: Path) -> None:
    policy = _traffic_policy(tmp_path)
    initial = policy.snapshot()
    runtime = _matrix(policy, initial_snapshot=initial)

    policy.record_unmetered_action()
    current = runtime.traffic_snapshot()

    assert runtime.initial_traffic_snapshot is initial
    assert runtime.initial_traffic_snapshot.unmetered_action_count == 0
    assert current.unmetered_action_count == 1
    assert current.accounting_status == "lower_bound"


def test_context_manager_closes_every_lane_once_and_clears_anonymous_state(
    tmp_path: Path,
) -> None:
    policy = _traffic_policy(tmp_path)
    alice = _StubOwner("alice", policy, close_error=RuntimeError("ignored close failure"))
    bob = _StubOwner("bob", policy)
    anonymous = _StubSession(policy)
    runtime = _matrix(
        policy,
        owners={"alice": alice, "bob": bob},
        anonymous_session=anonymous,
    )

    with runtime as entered:
        assert entered is runtime

    assert alice.close_calls == 1
    assert bob.close_calls == 1
    assert anonymous.default_headers == {}
    assert anonymous.cookies == {}

    runtime.close()
    assert alice.close_calls == 1
    assert bob.close_calls == 1
    with pytest.raises(AuthorizationMatrixRuntimeError, match="runtime is closed"):
        runtime.request("alice", "GET", "/")
    with pytest.raises(AuthorizationMatrixRuntimeError, match="runtime is closed"):
        runtime.traffic_snapshot()
    with pytest.raises(AuthorizationMatrixRuntimeError, match="runtime is closed"):
        runtime.__enter__()


@pytest.mark.parametrize("protocol", [0, pickle.HIGHEST_PROTOCOL])
def test_repr_and_pickle_do_not_expose_credentials(tmp_path: Path, protocol: int) -> None:
    policy = _traffic_policy(tmp_path)
    runtime = _matrix(policy)

    rendered = repr(runtime)

    assert rendered == (
        "ManagedAuthorizationMatrix(identities=('alice', 'bob'), credentials=[REDACTED])"
    )
    assert _OWNER_SECRET not in rendered
    assert _ANONYMOUS_SECRET not in rendered
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(runtime, protocol=protocol)


@pytest.mark.parametrize(
    "identities",
    [(), ("alice",), ("alice", " alice ")],
)
def test_builder_requires_two_distinct_identities(
    tmp_path: Path,
    identities: tuple[str, ...],
) -> None:
    with pytest.raises(AuthorizationMatrixRuntimeError, match="at least two"):
        _build(
            config=_authentication_config(),
            identities=identities,
            policy=_traffic_policy(tmp_path),
        )


@pytest.mark.parametrize("reserved_alias", ["anonymous", "Anon"])
def test_builder_rejects_reserved_aliases(tmp_path: Path, reserved_alias: str) -> None:
    with pytest.raises(AuthorizationMatrixRuntimeError, match="reserved anonymous alias"):
        _build(
            config=_authentication_config(),
            identities=("alice", reserved_alias),
            policy=_traffic_policy(tmp_path),
        )


def test_builder_rejects_unknown_aliases_before_owner_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_build(**_kwargs: object) -> None:
        pytest.fail("owner construction must not run for unknown identities")

    monkeypatch.setattr(matrix_runtime, "build_authenticated_attack_runtime", unexpected_build)

    with pytest.raises(
        ConfiguredAuthenticationError,
        match="unknown authorization matrix identity; configured identities: alice, bob, carol",
    ):
        _build(
            config=_authentication_config(),
            identities=("alice", "missing"),
            policy=_traffic_policy(tmp_path),
        )


def test_builder_selects_roles_shares_controller_and_snapshots_before_owners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _traffic_policy(tmp_path)
    network_context = ProbeNetworkContext()
    owner_calls: list[tuple[str, TrafficPolicyController]] = []
    anonymous_calls: list[TrafficPolicyController] = []
    owner_network_contexts: list[ProbeNetworkContext] = []
    anonymous_network_contexts: list[ProbeNetworkContext] = []
    anonymous = _StubSession(policy, network_context=network_context)

    def fake_build(**kwargs: object) -> _StubOwner:
        identity = kwargs["identity"]
        candidate = kwargs["traffic_policy"]
        candidate_network_context = kwargs["network_context"]
        assert isinstance(identity, str)
        assert isinstance(candidate, TrafficPolicyController)
        assert isinstance(candidate_network_context, ProbeNetworkContext)
        owner_calls.append((identity, candidate))
        owner_network_contexts.append(candidate_network_context)
        candidate.record_unmetered_action()
        return _StubOwner(
            identity,
            candidate,
            network_context=candidate_network_context,
        )

    def fake_probe_session(_target_url: str, **kwargs: object) -> _StubSession:
        candidate = kwargs["traffic_policy"]
        candidate_network_context = kwargs["network_context"]
        assert isinstance(candidate, TrafficPolicyController)
        assert isinstance(candidate_network_context, ProbeNetworkContext)
        anonymous_calls.append(candidate)
        anonymous_network_contexts.append(candidate_network_context)
        return anonymous

    monkeypatch.setattr(matrix_runtime, "build_authenticated_attack_runtime", fake_build)
    monkeypatch.setattr(matrix_runtime, "ProbeSession", fake_probe_session)

    runtime = _build(
        config=_authentication_config(),
        identities=(" bob ", "alice", "bob"),
        policy=policy,
        network_context=network_context,
    )

    assert runtime.identities == ("alice", "bob")
    assert runtime.roles("alice") == ("admin", "viewer")
    assert runtime.roles("bob") == ("member",)
    assert [alias for alias, _candidate in owner_calls] == ["alice", "bob"]
    assert all(candidate is policy for _alias, candidate in owner_calls)
    assert anonymous_calls == [policy]
    assert owner_network_contexts == [network_context, network_context]
    assert anonymous_network_contexts == [network_context]
    assert runtime.initial_traffic_snapshot.unmetered_action_count == 0
    assert runtime.traffic_snapshot().unmetered_action_count == _BUILT_OWNER_COUNT
    runtime.close()


def test_builder_closes_partial_owners_when_later_construction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _traffic_policy(tmp_path)
    alice = _StubOwner("alice", policy, close_error=RuntimeError("ignored close failure"))
    calls: list[str] = []

    def fake_build(**kwargs: object) -> _StubOwner:
        identity = kwargs["identity"]
        candidate = kwargs["traffic_policy"]
        network_context = kwargs["network_context"]
        assert isinstance(identity, str)
        assert candidate is policy
        assert isinstance(network_context, ProbeNetworkContext)
        calls.append(identity)
        if identity == "bob":
            message = "owner build exploded"
            raise RuntimeError(message)
        alice.network_context = network_context
        return alice

    def unexpected_probe_session(*_args: object, **_kwargs: object) -> None:
        pytest.fail("anonymous construction must not follow an owner failure")

    monkeypatch.setattr(matrix_runtime, "build_authenticated_attack_runtime", fake_build)
    monkeypatch.setattr(matrix_runtime, "ProbeSession", unexpected_probe_session)

    with pytest.raises(RuntimeError, match="owner build exploded"):
        _build(
            config=_authentication_config(),
            identities=("bob", "alice"),
            policy=policy,
        )

    assert calls == ["alice", "bob"]
    assert alice.close_calls == 1


def test_real_managed_runtime_keeps_bearer_identities_isolated_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "alice-private-order-proof"
    requests: list[tuple[str, str]] = []

    class TargetResponse:
        def __init__(self, url: str, status: int, body: str) -> None:
            self._url = url
            self.status = status
            self._body = body.encode()
            self.headers = Message()
            self.headers["Content-Type"] = "text/plain"
            self.headers["Content-Length"] = str(len(self._body))

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self._url

        def read(self, limit: int) -> bytes:
            return self._body[:limit]

    class TargetOpener:
        def open(self, request: Request, *, timeout: float) -> TargetResponse:
            del timeout
            authorization = next(
                (
                    str(value)
                    for name, value in request.header_items()
                    if str(name).casefold() == "authorization"
                ),
                "",
            )
            path = urlsplit(request.full_url).path
            requests.append((path, authorization))
            if path == "/health" and authorization in {
                "Bearer alice-token",
                "Bearer bob-token",
            }:
                status, body = 200, "signed in"
            elif path == "/orders/483920" and authorization == "Bearer alice-token":
                status, body = 200, marker
            elif path == "/orders/483920" and authorization == "Bearer bob-token":
                status, body = 403, "access denied"
            else:
                status, body = 401, "sign in"
            return TargetResponse(request.full_url, status, body)

    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: TargetOpener(),
    )
    target_url = _TARGET
    policy = TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url=target_url,
        config=TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=12,
            cache_enabled=True,
            deduplicate=True,
        ),
    )
    resolver = EnvironmentSecretResolver(
        {
            "ALICE_TOKEN": "alice-token",
            "BOB_TOKEN": "bob-token",
            "ORDER_MARKER": marker,
        }
    )
    config = _authentication_config(target_url=target_url)
    plan = AuthorizationMatrixPlan(
        cases=(
            AuthorizationMatrixCase(
                case_id="private-order",
                url=f"{target_url}orders/483920",
                owner="alice",
                marker_env="ORDER_MARKER",
                expect={"alice": "allow", "bob": "deny", "anonymous": "deny"},
            ),
        )
    )

    with build_managed_authorization_matrix(
        config=config,
        target_url=target_url,
        identities=("alice", "bob"),
        timeout_seconds=2,
        allow_remote_target=False,
        in_scope=(target_url,),
        out_of_scope=(),
        max_rps=None,
        secret_resolver=resolver,
        traffic_policy=policy,
    ) as runtime:
        result = AuthorizationMatrixRunner(resolver).run(plan, runtime)

    assert result.verdict is AuthorizationVerdict.NO_VIOLATION
    assert result.traffic_delta.physical_request_count == _END_TO_END_REQUEST_COUNT
    assert result.traffic_delta.completed_request_count == _END_TO_END_REQUEST_COUNT
    assert result.traffic_delta.cache_hit_count == 0
    assert result.traffic_delta.deduplicated_count == 0
    assert result.traffic_delta.current_accounting_status == "exact"
    assert requests == [
        ("/health", "Bearer alice-token"),
        ("/health", "Bearer bob-token"),
        ("/health", "Bearer alice-token"),
        ("/orders/483920", "Bearer alice-token"),
        ("/health", "Bearer alice-token"),
        ("/orders/483920", "Bearer alice-token"),
        ("/health", "Bearer bob-token"),
        ("/orders/483920", "Bearer bob-token"),
        ("/orders/483920", ""),
    ]


def _matrix(  # noqa: PLR0913 - explicit fault injection for constructor invariants.
    policy: TrafficPolicyController,
    *,
    owners: Mapping[str, _StubOwner] | None = None,
    roles: Mapping[str, tuple[str, ...]] | None = None,
    anonymous_session: _StubSession | None = None,
    initial_snapshot: object | None = None,
    network_context: ProbeNetworkContext | None = None,
) -> ManagedAuthorizationMatrix:
    selected_owners = dict(
        owners
        or {
            "alice": _StubOwner("alice", policy),
            "bob": _StubOwner("bob", policy),
        }
    )
    shared_network_context = network_context or next(
        (
            owner.network_context
            for owner in selected_owners.values()
            if owner.network_context is not None
        ),
        None,
    )
    if shared_network_context is None and anonymous_session is not None:
        shared_network_context = anonymous_session.network_context
    if shared_network_context is None:
        shared_network_context = ProbeNetworkContext()
    for owner in selected_owners.values():
        if owner.network_context is None:
            owner.network_context = shared_network_context
    selected_anonymous = anonymous_session or _StubSession(policy)
    if selected_anonymous.network_context is None:
        selected_anonymous.network_context = shared_network_context
    selected_roles = roles or dict.fromkeys(selected_owners, ("member",))
    snapshot = policy.snapshot() if initial_snapshot is None else initial_snapshot
    return ManagedAuthorizationMatrix(
        owners=selected_owners,  # type: ignore[arg-type]
        roles=selected_roles,
        anonymous_session=selected_anonymous,  # type: ignore[arg-type]
        traffic_policy=policy,
        initial_traffic_snapshot=snapshot,  # type: ignore[arg-type]
        network_context=shared_network_context,
    )


def _build(
    *,
    config: AuthenticationConfig,
    identities: Sequence[str],
    policy: TrafficPolicyController,
    network_context: ProbeNetworkContext | None = None,
) -> ManagedAuthorizationMatrix:
    return build_managed_authorization_matrix(
        config=config,
        target_url=_TARGET,
        identities=identities,
        timeout_seconds=5,
        allow_remote_target=False,
        in_scope=(_TARGET,),
        out_of_scope=(),
        max_rps=5,
        secret_resolver=MappingSecretResolver({}, provider="test"),
        traffic_policy=policy,
        network_context=network_context,
    )


def _authentication_config(*, target_url: str = _TARGET) -> AuthenticationConfig:
    health = AuthHealthCheck(
        endpoint=AuthEndpoint(url=f"{target_url}health", scope="target"),
        authenticated_marker="signed in",
    )
    return AuthenticationConfig(
        identities=[
            _identity("alice", ("viewer", "admin"), "ALICE_TOKEN", health),
            _identity("bob", ("member",), "BOB_TOKEN", health),
            _identity("carol", ("auditor",), "CAROL_TOKEN", health),
        ]
    )


def _identity(
    alias: str,
    roles: Sequence[str],
    token_key: str,
    health: AuthHealthCheck,
) -> AuthIdentity:
    return AuthIdentity(
        alias=alias,
        roles=list(roles),
        flow=AuthFlow(
            kind="bearer",
            secret_refs={"token": SecretReference(key=token_key)},
        ),
        health_check=health,
    )


def _traffic_policy(
    tmp_path: Path,
    *,
    name: str = "traffic.json",
) -> TrafficPolicyController:
    return TrafficPolicyController.open(
        tmp_path / name,
        target_url=_TARGET,
        config=TrafficPolicyConfig(),
    )


def _response(method: str, url: str, *, body: str) -> ProbeResponse:
    return ProbeResponse(
        method=method,
        url=url,
        status=200,
        final_url=url,
        elapsed_ms=1,
        body=body,
    )
