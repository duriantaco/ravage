# ruff: noqa: BLE001, C901, EM101, EM102, PLR0911, PLR0912, PLR0913, PLR2004, TC003, TRY003
"""Deterministic, role-aware surface candidates without authorization claims."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from typing import TYPE_CHECKING, Protocol
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

from ravage.agent_core.surface_graph import (
    SurfaceGraphError,
    SurfaceGraphState,
    SurfaceOperation,
    SurfaceParameter,
)
from ravage.web_core.recon import (
    PassiveReconOperation,
    PassiveReconParameter,
    parse_passive_recon_document,
)
from ravage.web_core.scope_policy import same_origin

from .authorization_matrix import (
    ANONYMOUS_ACTOR,
    AuthorizationMatrixRuntimeError,
    TrafficSnapshotDelta,
    traffic_policy_halted,
    traffic_policy_reason_codes,
    traffic_snapshot_delta,
)

if TYPE_CHECKING:
    from ravage.traffic.policy import TrafficPolicySnapshot


AUTHORIZATION_SURFACE_MAP_RESULT_SCHEMA = "ravage.authorization-surface-map.result.v1"

_SAFE_METHOD = "GET"
_MIN_IDENTITIES = 2
_MIN_STATUS = 100
_MAX_STATUS = 599
_MAX_URL_CHARS = 2_048
_MAX_FRONTIER_URLS = 50
_MAX_DECLARATIONS_PER_RESPONSE = 256
_MAX_PERCENT_DECODE_ROUNDS = 8
_MAX_RECEIPT_STATIC_SEGMENT_CHARS = 12
_UNSAFE_URL_CHARACTERS = frozenset({"\\", "{", "}", "<", ">", "*"})
_DENIAL_STATUSES = frozenset({401, 403, 404})
_STANDARD_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_STATIC_SUFFIXES = frozenset(
    {
        ".avif",
        ".css",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".map",
        ".png",
        ".svg",
        ".webp",
        ".woff",
        ".woff2",
    }
)
_ACTION_TOKENS = frozenset(
    {
        "activate",
        "add",
        "approve",
        "archive",
        "assign",
        "ban",
        "block",
        "buy",
        "callback",
        "cancel",
        "change",
        "charge",
        "checkout",
        "close",
        "confirm",
        "create",
        "deactivate",
        "delete",
        "deploy",
        "destroy",
        "disable",
        "drop",
        "enable",
        "enroll",
        "execute",
        "generate",
        "grant",
        "impersonate",
        "install",
        "invite",
        "issue",
        "join",
        "launch",
        "lock",
        "logoff",
        "logout",
        "merge",
        "migrate",
        "move",
        "pay",
        "purchase",
        "publish",
        "purge",
        "rebuild",
        "refund",
        "regenerate",
        "remove",
        "rename",
        "replace",
        "reset",
        "restart",
        "revoke",
        "rotate",
        "run",
        "save",
        "schedule",
        "send",
        "shutdown",
        "signout",
        "start",
        "stop",
        "submit",
        "subscribe",
        "suspend",
        "terminate",
        "token",
        "transfer",
        "trigger",
        "unlock",
        "unsubscribe",
        "unpublish",
        "update",
        "upgrade",
        "upload",
        "verify",
        "wipe",
        "withdraw",
    }
)
_RECEIPT_SENSITIVE_PATH_PARENTS = frozenset(
    {
        "artifact",
        "artifacts",
        "attachment",
        "attachments",
        "blob",
        "blobs",
        "download",
        "downloads",
        "key",
        "keys",
        "object",
        "objects",
        "token",
        "tokens",
    }
)
_RECEIPT_PLACEHOLDERS = frozenset({"{id}", "{int}", "{segment}", "{uuid}"})
_RECEIPT_STATIC_SEGMENT_RE = re.compile(rf"^[a-z]{{1,{_MAX_RECEIPT_STATIC_SEGMENT_CHARS}}}$")
_RECEIPT_API_VERSION_RE = re.compile(r"^v[0-9]{1,2}$")
_ACTION_COMPOUND_SUFFIXES = frozenset(
    {
        "account",
        "accounts",
        "credential",
        "credentials",
        "deployment",
        "deployments",
        "invoice",
        "invoices",
        "job",
        "jobs",
        "key",
        "keys",
        "member",
        "members",
        "order",
        "orders",
        "password",
        "passwords",
        "payment",
        "payments",
        "project",
        "projects",
        "role",
        "roles",
        "service",
        "services",
        "session",
        "sessions",
        "subscription",
        "subscriptions",
        "token",
        "tokens",
        "user",
        "users",
    }
)
_CAMEL_BOUNDARY_RE = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])"
    r"|(?<=[A-Z])(?=[A-Z][a-z])"
    r"|(?<=[A-Za-z])(?=[0-9])"
    r"|(?<=[0-9])(?=[A-Za-z])"
)
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_MALFORMED_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ENCODED_SEPARATOR_RE = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class AuthorizationSurfaceAccessClass(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    REDIRECT = "redirect"
    INCONCLUSIVE = "inconclusive"


class AuthorizationSurfaceMapRuntime(Protocol):
    """Identity-isolated GET transport with one whole-run traffic ledger."""

    @property
    def identities(self) -> Sequence[str]: ...

    @property
    def initial_traffic_snapshot(self) -> TrafficPolicySnapshot: ...

    def roles(self, identity_alias: str) -> Sequence[str]: ...

    def identity_generation(self, identity_alias: str | None) -> int: ...

    def in_scope(self, url: str) -> bool: ...

    def request(
        self,
        identity_alias: str | None,
        method: str,
        url: str,
    ) -> AuthorizationSurfaceHttpResponse: ...

    def traffic_snapshot(self) -> TrafficPolicySnapshot: ...


class AuthorizationSurfaceHttpResponse(Protocol):
    status: int | None
    final_url: str
    headers: Mapping[str, str]
    body: str
    body_bytes: bytes
    error: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class AuthorizationSurfaceActorResult:
    actor: str
    roles: tuple[str, ...]
    mapped_url_count: int
    observation_count: int
    success_count: int
    denied_count: int
    redirect_count: int
    inconclusive_count: int
    complete: bool

    def to_json(self) -> dict[str, object]:
        return {
            "actor": self.actor,
            "roles": list(self.roles),
            "mapped_url_count": self.mapped_url_count,
            "observation_count": self.observation_count,
            "success_count": self.success_count,
            "denied_count": self.denied_count,
            "redirect_count": self.redirect_count,
            "inconclusive_count": self.inconclusive_count,
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationSurfaceCandidateActor:
    actor: str
    roles: tuple[str, ...]
    declaration_observed: bool
    access_classes: tuple[str, ...]
    statuses: tuple[int, ...]
    stable: bool

    def to_json(self) -> dict[str, object]:
        return {
            "actor": self.actor,
            "roles": list(self.roles),
            "declaration_observed": self.declaration_observed,
            "access_classes": list(self.access_classes),
            "statuses": list(self.statuses),
            "stable": self.stable,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationSurfaceCandidate:
    candidate_id: str
    operation_id: str
    method: str
    route_shape: str
    parameters: tuple[SurfaceParameter, ...]
    discovered_by: tuple[str, ...]
    not_discovered_by: tuple[str, ...]
    actor_evidence: tuple[AuthorizationSurfaceCandidateActor, ...]
    reason_codes: tuple[str, ...]
    review_ready: bool
    requires_operator_input: bool = True

    def to_json(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "operation_id": self.operation_id,
            "method": self.method,
            "route_shape": self.route_shape,
            "parameters": [parameter.to_json() for parameter in self.parameters],
            "discovered_by": list(self.discovered_by),
            "not_discovered_by": list(self.not_discovered_by),
            "actor_evidence": [evidence.to_json() for evidence in self.actor_evidence],
            "reason_codes": list(self.reason_codes),
            "review_ready": self.review_ready,
            "requires_operator_input": self.requires_operator_input,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationSurfaceMapResult:
    complete: bool
    coverage_limited: bool
    reason_codes: tuple[str, ...]
    coverage_reason_codes: tuple[str, ...]
    actors: tuple[AuthorizationSurfaceActorResult, ...]
    candidates: tuple[AuthorizationSurfaceCandidate, ...]
    surface_graph: SurfaceGraphState
    traffic_delta: TrafficSnapshotDelta
    schema: str = AUTHORIZATION_SURFACE_MAP_RESULT_SCHEMA

    def to_json(self) -> dict[str, object]:
        """Return a stable receipt without bodies, header values, or exact URLs."""
        return {
            "schema": self.schema,
            "complete": self.complete,
            "coverage_limited": self.coverage_limited,
            "reason_codes": list(self.reason_codes),
            "coverage_reason_codes": list(self.coverage_reason_codes),
            "actors": [actor.to_json() for actor in self.actors],
            "candidates": [candidate.to_json() for candidate in self.candidates],
            "surface_graph": self.surface_graph.to_json(),
            "traffic_delta": self.traffic_delta.to_json(),
        }


@dataclass(slots=True)
class _ActorCounters:
    urls: set[str] = field(default_factory=set, repr=False)
    observations: int = 0
    success: int = 0
    denied: int = 0
    redirect: int = 0
    inconclusive: int = 0

    def record(self, url: str, access_class: AuthorizationSurfaceAccessClass) -> None:
        self.urls.add(url)
        self.observations += 1
        if access_class is AuthorizationSurfaceAccessClass.SUCCESS:
            self.success += 1
        elif access_class is AuthorizationSurfaceAccessClass.DENIED:
            self.denied += 1
        elif access_class is AuthorizationSurfaceAccessClass.REDIRECT:
            self.redirect += 1
        else:
            self.inconclusive += 1


@dataclass(frozen=True, slots=True, repr=False)
class _UrlAdmission:
    exact_url: str
    dispatchable: bool
    coverage_reason: str = ""


@dataclass(frozen=True, slots=True, repr=False)
class _TransientDeclaration:
    operation: SurfaceOperation
    exact_url: str
    dispatchable: bool
    coverage_reason: str = ""


@dataclass(frozen=True, slots=True, repr=False)
class _TransientObservation:
    actor: str
    roles: tuple[str, ...]
    attempt: int
    status: int | None
    access_class: AuthorizationSurfaceAccessClass
    generation_before: int | None
    generation_after: int | None
    declarations: tuple[_TransientDeclaration, ...] = ()
    reason_codes: tuple[str, ...] = ()


class AuthorizationSurfaceMapRunner:
    """Map a breadth-first union frontier and emit review candidates only."""

    def run(  # noqa: PLR0915 - the safety sequence is intentionally linear.
        self,
        target_url: str,
        runtime: AuthorizationSurfaceMapRuntime,
        *,
        include_anonymous: bool = False,
        max_urls: int = 8,
    ) -> AuthorizationSurfaceMapResult:
        if isinstance(max_urls, bool) or not 1 <= max_urls <= _MAX_FRONTIER_URLS:
            raise AuthorizationMatrixRuntimeError(
                f"authorization surface max_urls must be between 1 and {_MAX_FRONTIER_URLS}"
            )
        actors, roles = _runtime_context(runtime, include_anonymous=include_anonymous)
        seed = _admit_url(
            target_url,
            base_url=target_url,
            target_url=target_url,
            runtime=runtime,
            discovered=False,
        )
        if seed is None:
            raise AuthorizationMatrixRuntimeError(
                "authorization surface target is invalid or outside engagement scope"
            )

        graph = SurfaceGraphState.for_target(seed.exact_url)
        discovered_by: dict[str, set[str]] = defaultdict(set)
        comparisons: dict[
            str,
            list[Mapping[str, tuple[_TransientObservation, _TransientObservation]]],
        ] = defaultdict(list)
        counters = {actor: _ActorCounters() for actor in actors}
        reason_codes: set[str] = set()
        coverage_reasons: set[str] = set()

        root = SurfaceOperation.create(
            url=_receipt_safe_url(seed.exact_url),
            method=_SAFE_METHOD,
            provenance=("native_recon",),
        )
        for actor in actors:
            graph.add(
                url=root.structural_url,
                method=root.method,
                source_kind="native_recon",
                identity_alias=actor,
                access_level="declared",
                scope_decision="allowed",
                replayability="not_replayable",
            )
            discovered_by[root.operation_id].add(actor)

        try:
            initial = runtime.initial_traffic_snapshot
        except Exception as exc:
            raise AuthorizationMatrixRuntimeError(
                "authorization surface traffic snapshot is unavailable"
            ) from exc
        initial_policy_reasons = _current_policy_reasons(runtime, initial)
        if initial_policy_reasons:
            reason_codes.update(initial_policy_reasons)
            return _result(
                complete=False,
                coverage_reasons=coverage_reasons,
                reason_codes=reason_codes,
                actors=actors,
                roles=roles,
                counters=counters,
                graph=graph,
                discovered_by=discovered_by,
                comparisons=comparisons,
                initial=initial,
                runtime=runtime,
            )

        queue: deque[str] = deque((seed.exact_url,))
        queued = {seed.exact_url}
        processed = 0
        halted = False

        while queue and processed < max_urls and not halted:
            current_url = queue.popleft()
            first: dict[str, _TransientObservation] = {}
            for actor in actors:
                observation = _observe(
                    runtime,
                    actor=actor,
                    roles=roles[actor],
                    attempt=1,
                    url=current_url,
                    target_url=seed.exact_url,
                    coverage_reasons=coverage_reasons,
                )
                first[actor] = observation
                counters[actor].record(current_url, observation.access_class)
                if observation.reason_codes:
                    reason_codes.update(observation.reason_codes)
                if traffic_policy_halted(runtime, initial):
                    reason_codes.update(("comparison_incomplete", "traffic_policy_halted"))
                    halted = True
                    break
            if halted:
                break

            needs_repeat = _needs_repeat(tuple(first.values()))
            repeated: dict[str, _TransientObservation] = {}
            if needs_repeat:
                for actor in reversed(actors):
                    observation = _observe(
                        runtime,
                        actor=actor,
                        roles=roles[actor],
                        attempt=2,
                        url=current_url,
                        target_url=seed.exact_url,
                        coverage_reasons=coverage_reasons,
                    )
                    repeated[actor] = observation
                    counters[actor].record(current_url, observation.access_class)
                    if observation.reason_codes:
                        reason_codes.update(observation.reason_codes)
                    if traffic_policy_halted(runtime, initial):
                        reason_codes.update(("comparison_incomplete", "traffic_policy_halted"))
                        halted = True
                        break
            if halted:
                break

            for actor in actors:
                _record_response_observation(graph, current_url, first[actor])
                if actor in repeated:
                    _record_response_observation(graph, current_url, repeated[actor])

            stable_declarations: dict[str, tuple[_TransientDeclaration, ...]] = {}
            stable_pairs: dict[
                str,
                tuple[_TransientObservation, _TransientObservation],
            ] = {}
            if needs_repeat:
                for actor in actors:
                    pair = (first[actor], repeated[actor])
                    if not _stable_pair(*pair):
                        reason_codes.add("unstable_surface_observation")
                        continue
                    stable_pairs[actor] = pair
                    stable_declarations[actor] = _shared_declarations(*pair)

            next_urls: set[str] = set()
            for actor in actors:
                declarations = stable_declarations.get(actor, ())
                for declaration in declarations:
                    _record_declaration(graph, declaration, actor=actor)
                    discovered_by[declaration.operation.operation_id].add(actor)
                    if declaration.coverage_reason:
                        coverage_reasons.add(declaration.coverage_reason)
                    if declaration.dispatchable:
                        next_urls.add(declaration.exact_url)

            if _stable_access_difference(stable_pairs, actors=actors):
                comparisons[
                    root.operation_id
                    if current_url == seed.exact_url
                    else _operation_id(current_url)
                ].append(dict(stable_pairs))

            for next_url in sorted(next_urls):
                if next_url in queued:
                    continue
                if len(queued) >= max_urls:
                    coverage_reasons.add("frontier_limit_reached")
                    continue
                queued.add(next_url)
                queue.append(next_url)
            processed += 1

        if queue:
            coverage_reasons.add("frontier_limit_reached")

        return _result(
            complete=not reason_codes,
            coverage_reasons=coverage_reasons,
            reason_codes=reason_codes,
            actors=actors,
            roles=roles,
            counters=counters,
            graph=graph,
            discovered_by=discovered_by,
            comparisons=comparisons,
            initial=initial,
            runtime=runtime,
        )


def run_authorization_surface_map(
    target_url: str,
    *,
    runtime: AuthorizationSurfaceMapRuntime,
    include_anonymous: bool = False,
    max_urls: int = 8,
) -> AuthorizationSurfaceMapResult:
    return AuthorizationSurfaceMapRunner().run(
        target_url,
        runtime,
        include_anonymous=include_anonymous,
        max_urls=max_urls,
    )


def _runtime_context(
    runtime: AuthorizationSurfaceMapRuntime,
    *,
    include_anonymous: bool,
) -> tuple[tuple[str, ...], Mapping[str, tuple[str, ...]]]:
    try:
        identities = tuple(sorted(runtime.identities))
    except Exception as exc:
        raise AuthorizationMatrixRuntimeError(
            "authorization surface identities are unavailable"
        ) from exc
    if (
        len(identities) < _MIN_IDENTITIES
        or len(set(identities)) != len(identities)
        or any(
            not isinstance(alias, str)
            or _IDENTITY_RE.fullmatch(alias) is None
            or alias.casefold() in {"anon", ANONYMOUS_ACTOR}
            for alias in identities
        )
    ):
        raise AuthorizationMatrixRuntimeError(
            "authorization surface map requires at least two valid configured identities"
        )
    roles: dict[str, tuple[str, ...]] = {}
    for alias in identities:
        try:
            raw_roles = runtime.roles(alias)
        except Exception as exc:
            raise AuthorizationMatrixRuntimeError(
                "authorization surface roles are unavailable"
            ) from exc
        if isinstance(raw_roles, str) or any(
            not isinstance(role, str)
            or not role.strip()
            or len(role) > 128
            or any(ord(character) < 0x20 for character in role)
            for role in raw_roles
        ):
            raise AuthorizationMatrixRuntimeError("authorization surface roles must be a sequence")
        roles[alias] = tuple(sorted({role for role in raw_roles if role}))
    actors = identities
    if include_anonymous:
        actors = (*actors, ANONYMOUS_ACTOR)
        roles[ANONYMOUS_ACTOR] = ()
    return actors, roles


def _observe(
    runtime: AuthorizationSurfaceMapRuntime,
    *,
    actor: str,
    roles: tuple[str, ...],
    attempt: int,
    url: str,
    target_url: str,
    coverage_reasons: set[str],
) -> _TransientObservation:
    lane = None if actor == ANONYMOUS_ACTOR else actor
    try:
        generation_before = runtime.identity_generation(lane)
    except Exception:
        return _TransientObservation(
            actor=actor,
            roles=roles,
            attempt=attempt,
            status=None,
            access_class=AuthorizationSurfaceAccessClass.INCONCLUSIVE,
            generation_before=None,
            generation_after=None,
            reason_codes=("identity_generation_unavailable",),
        )
    try:
        response = runtime.request(lane, _SAFE_METHOD, url)
    except Exception:
        return _TransientObservation(
            actor=actor,
            roles=roles,
            attempt=attempt,
            status=None,
            access_class=AuthorizationSurfaceAccessClass.INCONCLUSIVE,
            generation_before=generation_before,
            generation_after=None,
            reason_codes=("authorization_surface_request_failed",),
        )
    try:
        generation_after = runtime.identity_generation(lane)
    except Exception:
        return _TransientObservation(
            actor=actor,
            roles=roles,
            attempt=attempt,
            status=None,
            access_class=AuthorizationSurfaceAccessClass.INCONCLUSIVE,
            generation_before=generation_before,
            generation_after=None,
            reason_codes=("identity_generation_unavailable",),
        )

    status = _response_status(response.status)
    reasons: set[str] = set()
    if generation_before != generation_after:
        reasons.add("identity_generation_changed")
    if bool(response.error):
        reasons.add("transport_error")
    if bool(response.truncated):
        reasons.add("response_truncated")
    access_class = _access_class(status)
    if access_class is AuthorizationSurfaceAccessClass.INCONCLUSIVE:
        reasons.add("inconclusive_response_status")
    if reasons:
        return _TransientObservation(
            actor=actor,
            roles=roles,
            attempt=attempt,
            status=status,
            access_class=AuthorizationSurfaceAccessClass.INCONCLUSIVE,
            generation_before=generation_before,
            generation_after=generation_after,
            reason_codes=tuple(sorted(reasons)),
        )

    declarations: tuple[_TransientDeclaration, ...] = ()
    try:
        declarations = _response_declarations(
            response,
            requested_url=url,
            target_url=target_url,
            runtime=runtime,
            coverage_reasons=coverage_reasons,
        )
    except Exception:  # Target material must never enter errors.
        return _TransientObservation(
            actor=actor,
            roles=roles,
            attempt=attempt,
            status=status,
            access_class=AuthorizationSurfaceAccessClass.INCONCLUSIVE,
            generation_before=generation_before,
            generation_after=generation_after,
            reason_codes=("surface_parser_failed",),
        )
    return _TransientObservation(
        actor=actor,
        roles=roles,
        attempt=attempt,
        status=status,
        access_class=access_class,
        generation_before=generation_before,
        generation_after=generation_after,
        declarations=declarations,
    )


def _response_declarations(
    response: AuthorizationSurfaceHttpResponse,
    *,
    requested_url: str,
    target_url: str,
    runtime: AuthorizationSurfaceMapRuntime,
    coverage_reasons: set[str],
) -> tuple[_TransientDeclaration, ...]:
    declarations: list[_TransientDeclaration] = []
    if response.status is not None and 300 <= response.status < 400:
        location = _header_value(response.headers, "location")
        if location:
            redirect_url = urljoin(requested_url, location)
            declaration = _project_declaration(
                PassiveReconOperation(
                    method="GET",
                    url=location,
                    parameters=tuple(
                        PassiveReconParameter(name=name, location="query")
                        for name, _value in parse_qsl(
                            urlsplit(redirect_url).query,
                            keep_blank_values=True,
                        )[:32]
                        if name
                    ),
                    hints=("redirect",),
                ),
                base_url=requested_url,
                target_url=target_url,
                runtime=runtime,
                discovered=True,
            )
            if declaration is not None:
                declarations.append(declaration)
                if declaration.coverage_reason:
                    coverage_reasons.add(declaration.coverage_reason)
        return tuple(declarations)

    if response.status is None or not 200 <= response.status < 300:
        return ()
    body = _response_body(response)
    content_type = _header_value(response.headers, "content-type")
    if not _looks_like_html(body, content_type):
        return ()
    final_url = str(response.final_url or requested_url)
    if not same_origin(target_url, final_url) or final_url != requested_url:
        raise AuthorizationMatrixRuntimeError("authorization surface response URL changed")
    document = parse_passive_recon_document(final_url, response.headers, body)
    for operation in document.operations[:_MAX_DECLARATIONS_PER_RESPONSE]:
        declaration = _project_declaration(
            operation,
            base_url=final_url,
            target_url=target_url,
            runtime=runtime,
            discovered=True,
        )
        if declaration is None:
            coverage_reasons.add("unsafe_surface_declaration_skipped")
            continue
        declarations.append(declaration)
        if declaration.coverage_reason:
            coverage_reasons.add(declaration.coverage_reason)
    deduplicated = {_declaration_key(item): item for item in declarations}
    return tuple(deduplicated[key] for key in sorted(deduplicated))


def _project_declaration(
    declaration: PassiveReconOperation,
    *,
    base_url: str,
    target_url: str,
    runtime: AuthorizationSurfaceMapRuntime,
    discovered: bool,
) -> _TransientDeclaration | None:
    method = str(declaration.method or "GET").strip().upper()
    if method not in _STANDARD_METHODS:
        return None
    admission = _admit_url(
        declaration.url,
        base_url=base_url,
        target_url=target_url,
        runtime=runtime,
        discovered=discovered,
    )
    if admission is None:
        return None
    parameters: list[SurfaceParameter] = []
    for parameter in declaration.parameters:
        try:
            parameters.append(
                SurfaceParameter.create(name=parameter.name, location=parameter.location)
            )
        except SurfaceGraphError:
            continue
    try:
        operation = SurfaceOperation.create(
            url=_receipt_safe_url(admission.exact_url),
            method=method,
            parameters=parameters,
            header_names=declaration.header_names,
            hints=declaration.hints,
            provenance=(declaration.source_kind,),
        )
    except SurfaceGraphError:
        return None
    navigation = bool({"link", "redirect"} & set(operation.hints))
    dispatchable = admission.dispatchable and method == _SAFE_METHOD and navigation
    reason = admission.coverage_reason
    if method != _SAFE_METHOD:
        reason = "non_get_operation_not_dispatched"
    elif "script" in operation.hints:
        reason = "static_asset_not_dispatched"
    elif not navigation:
        reason = "declared_operation_not_dispatched"
    return _TransientDeclaration(
        operation=operation,
        exact_url=admission.exact_url,
        dispatchable=dispatchable,
        coverage_reason=reason,
    )


def _admit_url(
    value: str,
    *,
    base_url: str,
    target_url: str,
    runtime: AuthorizationSurfaceMapRuntime,
    discovered: bool,
) -> _UrlAdmission | None:
    raw = str(value or "")
    if not raw or raw != raw.strip() or len(raw) > _MAX_URL_CHARS:
        return None
    if any(character in raw for character in _UNSAFE_URL_CHARACTERS):
        return None
    if any(ord(character) < 0x20 or character.isspace() for character in raw):
        return None
    if _MALFORMED_PERCENT_RE.search(raw):
        return None
    try:
        joined = urljoin(base_url, raw)
        parsed = urlsplit(joined)
        _ = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        return None
    if not same_origin(target_url, joined):
        return None
    if not _safe_decoded_path(parsed.path):
        return None
    target = urlsplit(target_url)
    exact = urlunsplit(
        (target.scheme.casefold(), target.netloc, parsed.path or "/", parsed.query, "")
    )
    try:
        if not runtime.in_scope(exact):
            return None
    except Exception:
        return None
    if not discovered:
        return _UrlAdmission(exact_url=exact, dispatchable=True)
    if parsed.query:
        return _UrlAdmission(
            exact_url=exact,
            dispatchable=False,
            coverage_reason="query_route_not_dispatched",
        )
    if _action_like(parsed.path, parsed.query):
        return _UrlAdmission(
            exact_url=exact,
            dispatchable=False,
            coverage_reason="action_route_not_dispatched",
        )
    if any(parsed.path.casefold().endswith(suffix) for suffix in _STATIC_SUFFIXES):
        return _UrlAdmission(
            exact_url=exact,
            dispatchable=False,
            coverage_reason="static_asset_not_dispatched",
        )
    return _UrlAdmission(exact_url=exact, dispatchable=True)


def _safe_decoded_path(path: str) -> bool:
    return _decode_to_stability(path) is not None


def _decode_to_stability(value: str) -> str | None:
    decoded = value
    for _round in range(_MAX_PERCENT_DECODE_ROUNDS + 1):
        if _MALFORMED_PERCENT_RE.search(decoded):
            return None
        if _ENCODED_SEPARATOR_RE.search(decoded):
            return None
        if any(
            character == "\\" or ord(character) < 0x20 or character.isspace()
            for character in decoded
        ):
            return None
        if any(segment in {".", ".."} for segment in decoded.split("/")):
            return None
        next_value = unquote(decoded)
        if next_value == decoded:
            return decoded
        decoded = next_value
    return None


def _action_like(path: str, query: str) -> bool:
    decoded = _decode_to_stability(f"{path}?{query}")
    if decoded is None:
        return True
    lowered = _CAMEL_BOUNDARY_RE.sub("-", decoded).casefold()
    ordered_tokens = tuple(token for token in _TOKEN_SPLIT_RE.split(lowered) if token)
    tokens = set(ordered_tokens)
    compact_parts = {
        re.sub(r"[^a-z0-9]", "", part) for part in re.split(r"[/&=?]+", lowered) if part
    }
    adjacent_compounds = {first + second for first, second in pairwise(ordered_tokens)}
    if (tokens | compact_parts | adjacent_compounds) & _ACTION_TOKENS:
        return True
    return any(
        compact == f"{action}{suffix}"
        for compact in compact_parts
        for action in _ACTION_TOKENS
        for suffix in _ACTION_COMPOUND_SUFFIXES
    )


def _record_response_observation(
    graph: SurfaceGraphState,
    url: str,
    observation: _TransientObservation,
) -> None:
    graph.add(
        url=_receipt_safe_url(url),
        method=_SAFE_METHOD,
        source_kind="probe",
        identity_alias=observation.actor,
        access_level="response",
        response_status=(
            observation.status
            if observation.access_class is not AuthorizationSurfaceAccessClass.INCONCLUSIVE
            else None
        ),
        scope_decision="allowed",
        replayability="not_replayable",
    )


def _record_declaration(
    graph: SurfaceGraphState,
    declaration: _TransientDeclaration,
    *,
    actor: str,
) -> None:
    operation = declaration.operation
    graph.add(
        url=operation.structural_url,
        method=operation.method,
        parameters=operation.parameters,
        header_names=operation.header_names,
        hints=operation.hints,
        source_kind=operation.provenance[0],
        identity_alias=actor,
        access_level="declared",
        scope_decision="allowed",
        replayability="not_replayable",
    )


def _needs_repeat(observations: Sequence[_TransientObservation]) -> bool:
    items = tuple(observations)
    if any(item.declarations for item in items):
        return True
    classes = {
        item.access_class
        for item in items
        if item.access_class is not AuthorizationSurfaceAccessClass.INCONCLUSIVE
    }
    return len(classes) > 1


def _stable_pair(first: _TransientObservation, second: _TransientObservation) -> bool:
    return (
        not first.reason_codes
        and not second.reason_codes
        and first.status == second.status
        and first.access_class is second.access_class
        and first.generation_before == first.generation_after
        and first.generation_after == second.generation_before
        and second.generation_before == second.generation_after
        and {_declaration_key(item) for item in first.declarations}
        == {_declaration_key(item) for item in second.declarations}
    )


def _shared_declarations(
    first: _TransientObservation,
    second: _TransientObservation,
) -> tuple[_TransientDeclaration, ...]:
    first_items = {_declaration_key(item): item for item in first.declarations}
    second_keys = {_declaration_key(item) for item in second.declarations}
    return tuple(first_items[key] for key in sorted(set(first_items) & second_keys))


def _stable_access_difference(
    pairs: Mapping[str, tuple[_TransientObservation, _TransientObservation]],
    *,
    actors: Sequence[str],
) -> bool:
    if set(pairs) != set(actors):
        return False
    classes = {pair[0].access_class for pair in pairs.values()}
    return AuthorizationSurfaceAccessClass.INCONCLUSIVE not in classes and len(classes) > 1


def _declaration_key(declaration: _TransientDeclaration) -> tuple[object, ...]:
    operation = declaration.operation
    return (
        declaration.exact_url if declaration.dispatchable else "",
        operation.operation_id,
        operation.parameters,
        operation.header_names,
        operation.hints,
        operation.provenance,
        declaration.dispatchable,
        declaration.coverage_reason,
    )


def _operation_id(url: str) -> str:
    return SurfaceOperation.create(
        url=_receipt_safe_url(url),
        method=_SAFE_METHOD,
        provenance=("probe",),
    ).operation_id


def _receipt_safe_url(url: str) -> str:
    """Project an admitted exact URL into a conservative receipt-only route shape."""
    operation = SurfaceOperation.create(
        url=url,
        method=_SAFE_METHOD,
        provenance=("probe",),
    )
    shaped_segments: list[str] = []
    previous = ""
    for segment in operation.route_shape.split("/"):
        if not segment:
            shaped = ""
        elif segment in _RECEIPT_PLACEHOLDERS:
            shaped = segment
        elif previous in _RECEIPT_SENSITIVE_PATH_PARENTS:
            shaped = "{id}"
        elif _RECEIPT_STATIC_SEGMENT_RE.fullmatch(segment) or _RECEIPT_API_VERSION_RE.fullmatch(
            segment
        ):
            shaped = segment
        else:
            shaped = "{segment}"
        shaped_segments.append(shaped)
        previous = segment.casefold()
    route_shape = "/".join(shaped_segments)
    if not route_shape.startswith("/"):
        route_shape = f"/{route_shape}"
    return f"{operation.origin}{route_shape}"


def _access_class(status: int | None) -> AuthorizationSurfaceAccessClass:
    if status is None or status == 429 or status >= 500:
        return AuthorizationSurfaceAccessClass.INCONCLUSIVE
    if 200 <= status < 300:
        return AuthorizationSurfaceAccessClass.SUCCESS
    if 300 <= status < 400:
        return AuthorizationSurfaceAccessClass.REDIRECT
    if status in _DENIAL_STATUSES:
        return AuthorizationSurfaceAccessClass.DENIED
    return AuthorizationSurfaceAccessClass.INCONCLUSIVE


def _response_status(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if _MIN_STATUS <= value <= _MAX_STATUS else None


def _response_body(response: AuthorizationSurfaceHttpResponse) -> bytes | str:
    body_bytes = response.body_bytes
    if isinstance(body_bytes, bytes):
        return body_bytes
    if isinstance(body_bytes, bytearray | memoryview):
        return bytes(body_bytes)
    return response.body if isinstance(response.body, str) else ""


def _header_value(headers: Mapping[str, str], wanted: str) -> str:
    return next(
        (str(value) for name, value in headers.items() if str(name).casefold() == wanted),
        "",
    )


def _looks_like_html(body: bytes | str, content_type: str) -> bool:
    if "html" in content_type.casefold():
        return True
    prefix = (
        body[:512].decode("utf-8", errors="replace") if isinstance(body, bytes) else body[:512]
    ).casefold()
    return "<html" in prefix or "<!doctype html" in prefix


def _current_policy_reasons(
    runtime: AuthorizationSurfaceMapRuntime,
    initial: TrafficPolicySnapshot,
) -> tuple[str, ...]:
    try:
        current = runtime.traffic_snapshot()
    except Exception:
        return ("traffic_snapshot_unavailable",)
    return traffic_policy_reason_codes(initial, current)


def _result(
    *,
    complete: bool,
    coverage_reasons: set[str],
    reason_codes: set[str],
    actors: tuple[str, ...],
    roles: Mapping[str, tuple[str, ...]],
    counters: Mapping[str, _ActorCounters],
    graph: SurfaceGraphState,
    discovered_by: Mapping[str, set[str]],
    comparisons: Mapping[
        str,
        Sequence[Mapping[str, tuple[_TransientObservation, _TransientObservation]]],
    ],
    initial: TrafficPolicySnapshot,
    runtime: AuthorizationSurfaceMapRuntime,
) -> AuthorizationSurfaceMapResult:
    policy_reasons: tuple[str, ...]
    try:
        current = runtime.traffic_snapshot()
    except Exception:
        current = initial
        policy_reasons = ("traffic_snapshot_unavailable",)
    else:
        policy_reasons = traffic_policy_reason_codes(initial, current)
    reason_codes.update(policy_reasons)
    complete = complete and not reason_codes
    delta = traffic_snapshot_delta(initial, current)
    actor_results = tuple(
        AuthorizationSurfaceActorResult(
            actor=actor,
            roles=roles[actor],
            mapped_url_count=len(counters[actor].urls),
            observation_count=counters[actor].observations,
            success_count=counters[actor].success,
            denied_count=counters[actor].denied,
            redirect_count=counters[actor].redirect,
            inconclusive_count=counters[actor].inconclusive,
            complete=complete and counters[actor].inconclusive == 0,
        )
        for actor in actors
    )
    candidates = _candidates(
        graph,
        actors=actors,
        roles=roles,
        discovered_by=discovered_by,
        comparisons=comparisons,
        complete=complete,
    )
    return AuthorizationSurfaceMapResult(
        complete=complete,
        coverage_limited=bool(coverage_reasons),
        reason_codes=tuple(sorted(reason_codes)),
        coverage_reason_codes=tuple(sorted(coverage_reasons)),
        actors=actor_results,
        candidates=candidates,
        surface_graph=graph,
        traffic_delta=delta,
    )


def _candidates(
    graph: SurfaceGraphState,
    *,
    actors: Sequence[str],
    roles: Mapping[str, tuple[str, ...]],
    discovered_by: Mapping[str, set[str]],
    comparisons: Mapping[
        str,
        Sequence[Mapping[str, tuple[_TransientObservation, _TransientObservation]]],
    ],
    complete: bool,
) -> tuple[AuthorizationSurfaceCandidate, ...]:
    candidates: list[AuthorizationSurfaceCandidate] = []
    actor_set = set(actors)
    for operation_id, operation in sorted((graph.operations or {}).items()):
        if operation.method != _SAFE_METHOD:
            continue
        if "script" in operation.hints and "link" not in operation.hints:
            continue
        discovered = set(discovered_by.get(operation_id, set()))
        reasons: set[str] = set()
        if discovered and discovered != actor_set:
            reasons.add("identity_visibility_difference")
        operation_comparisons = tuple(comparisons.get(operation_id, ()))
        if operation_comparisons:
            reasons.add("response_access_class_difference")
        if not reasons:
            continue
        actor_evidence = _candidate_actor_evidence(
            operation_comparisons,
            actors=actors,
            roles=roles,
            discovered=discovered,
        )
        stable = all(item.stable for item in actor_evidence)
        candidate_id = _candidate_id(operation_id, tuple(sorted(reasons)))
        candidates.append(
            AuthorizationSurfaceCandidate(
                candidate_id=candidate_id,
                operation_id=operation_id,
                method=operation.method,
                route_shape=operation.route_shape,
                parameters=operation.parameters,
                discovered_by=tuple(actor for actor in actors if actor in discovered),
                not_discovered_by=tuple(actor for actor in actors if actor not in discovered),
                actor_evidence=actor_evidence,
                reason_codes=tuple(sorted(reasons)),
                review_ready=complete and stable,
            )
        )
    return tuple(sorted(candidates, key=lambda item: item.candidate_id))


def _candidate_actor_evidence(
    comparisons: Sequence[Mapping[str, tuple[_TransientObservation, _TransientObservation]]],
    *,
    actors: Sequence[str],
    roles: Mapping[str, tuple[str, ...]],
    discovered: set[str],
) -> tuple[AuthorizationSurfaceCandidateActor, ...]:
    evidence: list[AuthorizationSurfaceCandidateActor] = []
    for actor in actors:
        pairs = tuple(comparison[actor] for comparison in comparisons if actor in comparison)
        statuses = {
            status
            for pair in pairs
            for status in (pair[0].status, pair[1].status)
            if status is not None
        }
        classes = {observation.access_class.value for pair in pairs for observation in pair}
        evidence.append(
            AuthorizationSurfaceCandidateActor(
                actor=actor,
                roles=roles[actor],
                declaration_observed=actor in discovered,
                access_classes=tuple(sorted(classes)),
                statuses=tuple(sorted(statuses)),
                stable=not pairs or all(_stable_pair(*pair) for pair in pairs),
            )
        )
    return tuple(evidence)


def _candidate_id(operation_id: str, reasons: tuple[str, ...]) -> str:
    digest = hashlib.sha256("\x00".join((operation_id, *reasons)).encode("utf-8")).hexdigest()
    return f"asm_{digest[:24]}"


__all__ = [
    "AUTHORIZATION_SURFACE_MAP_RESULT_SCHEMA",
    "AuthorizationSurfaceAccessClass",
    "AuthorizationSurfaceActorResult",
    "AuthorizationSurfaceCandidate",
    "AuthorizationSurfaceCandidateActor",
    "AuthorizationSurfaceHttpResponse",
    "AuthorizationSurfaceMapResult",
    "AuthorizationSurfaceMapRunner",
    "AuthorizationSurfaceMapRuntime",
    "run_authorization_surface_map",
]
