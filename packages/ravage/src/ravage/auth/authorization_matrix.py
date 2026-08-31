# Validation branches intentionally keep actionable call-site errors.
# ruff: noqa: C901, EM101, EM102, PLR0911, PLR0912, PLR0913, TRY003
"""Deterministic, secret-safe authorization boundary comparisons."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol
from urllib.parse import unquote_plus, urlsplit

import yaml  # type: ignore[import-untyped]

from ravage.traffic.redaction import sanitize_url

from .secrets import SecretRef, SecretResolver, SecretValue

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.traffic.policy import TrafficPolicySnapshot

AUTHORIZATION_MATRIX_PLAN_SCHEMA = "ravage.authorization-matrix.plan.v1"
AUTHORIZATION_MATRIX_RESULT_SCHEMA = "ravage.authorization-matrix.result.v1"
ANONYMOUS_ACTOR = "anonymous"

_SAFE_METHOD = "GET"
_MIN_ACTORS = 2
_MIN_HTTP_STATUS = 100
_SUCCESS_STATUS_MIN = 200
_REDIRECT_STATUS_MIN = 300
_RATE_LIMIT_STATUS = 429
_SERVER_ERROR_STATUS_MIN = 500
_MAX_HTTP_STATUS = 599
_MAX_URL_CHARS = 2_048
_MIN_MARKER_CHARS = 12
_MAX_MARKER_BYTES = 4_096
_ASCII_SPACE = 0x20
_SAFE_DENIAL_STATUSES = frozenset({401, 403, 404})
_RESERVED_ACTORS = frozenset({"anon", ANONYMOUS_ACTOR})
_TOP_LEVEL_FIELDS = frozenset({"schema", "cases"})
_CASE_FIELDS = frozenset({"id", "method", "url", "owner", "marker_env", "expect"})
_REQUIRED_CASE_FIELDS = frozenset({"id", "url", "owner", "marker_env", "expect"})
_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ENVIRONMENT_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_UNSAFE_URL_CHARACTERS = frozenset({"\\", "{", "}", "<", ">", "*"})


class AuthorizationMatrixPlanError(ValueError):
    """An authorization matrix plan is unsafe or malformed."""


class AuthorizationMatrixRuntimeError(RuntimeError):
    """The supplied runtime cannot execute an authorization matrix safely."""


class AuthorizationExpectation(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AuthorizationVerdict(StrEnum):
    NO_VIOLATION = "no_violation"
    CONFIRMED_VIOLATION = "confirmed_violation"
    INCONCLUSIVE = "inconclusive"


class AuthorizationObservationOutcome(StrEnum):
    EXPECTED_ALLOW = "expected_allow"
    SAFE_DENIAL = "safe_denial"
    MARKER_EXPOSED = "marker_exposed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class AuthorizationMatrixCase:
    """One concrete, read-only resource and its explicit access expectations."""

    case_id: str
    url: str
    owner: str
    marker_env: str
    expect: Mapping[str, AuthorizationExpectation | str]
    method: str = _SAFE_METHOD

    def __post_init__(self) -> None:
        _require_identifier(self.case_id, "case id")
        _require_concrete_http_url(self.url)
        _require_identity_alias(self.owner, field_name="owner")
        if self.owner.casefold() in _RESERVED_ACTORS:
            raise AuthorizationMatrixPlanError("case owner cannot use a reserved actor alias")
        if not _ENVIRONMENT_KEY_RE.fullmatch(self.marker_env):
            raise AuthorizationMatrixPlanError(
                "marker_env must be a non-empty environment variable name"
            )
        normalized_method = _require_string(self.method, "method").strip().upper()
        if normalized_method != _SAFE_METHOD:
            raise AuthorizationMatrixPlanError("authorization matrix cases permit GET only")

        expectations: dict[str, AuthorizationExpectation] = {}
        for raw_actor, raw_expectation in self.expect.items():
            actor = _require_string(raw_actor, "expect actor")
            _require_actor(actor)
            if actor in expectations:
                raise AuthorizationMatrixPlanError("case contains a duplicate actor")
            try:
                expectation = AuthorizationExpectation(raw_expectation)
            except (TypeError, ValueError):
                raise AuthorizationMatrixPlanError(
                    "expect values must be exactly allow or deny"
                ) from None
            expectations[actor] = expectation
        if len(expectations) < _MIN_ACTORS:
            raise AuthorizationMatrixPlanError("each case must compare at least two actors")
        if expectations.get(self.owner) is not AuthorizationExpectation.ALLOW:
            raise AuthorizationMatrixPlanError("case owner must explicitly expect allow")

        ordered = dict(sorted(expectations.items(), key=lambda item: _actor_sort_key(item[0])))
        object.__setattr__(self, "method", normalized_method)
        object.__setattr__(self, "expect", MappingProxyType(ordered))


@dataclass(frozen=True, slots=True)
class AuthorizationMatrixPlan:
    cases: tuple[AuthorizationMatrixCase, ...]
    schema: str = AUTHORIZATION_MATRIX_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != AUTHORIZATION_MATRIX_PLAN_SCHEMA:
            raise AuthorizationMatrixPlanError(
                f"unsupported authorization matrix plan schema: {self.schema}"
            )
        if not self.cases:
            raise AuthorizationMatrixPlanError("authorization matrix plan must contain cases")
        case_ids = tuple(case.case_id for case in self.cases)
        if len(case_ids) != len(set(case_ids)):
            raise AuthorizationMatrixPlanError("authorization matrix plan has duplicate case ids")
        object.__setattr__(
            self,
            "cases",
            tuple(sorted(self.cases, key=lambda case: (case.case_id.casefold(), case.case_id))),
        )


class AuthorizationMatrixHttpResponse(Protocol):
    status: int | None
    body: str
    body_bytes: bytes
    error: str
    truncated: bool


class AuthorizationMatrixRuntime(Protocol):
    """Identity-isolated GET transport backed by one whole-run traffic policy."""

    @property
    def identities(self) -> Sequence[str]: ...

    @property
    def initial_traffic_snapshot(self) -> TrafficPolicySnapshot: ...

    def roles(self, identity_alias: str) -> Sequence[str]: ...

    def request(
        self,
        identity_alias: str | None,
        method: str,
        url: str,
    ) -> AuthorizationMatrixHttpResponse: ...

    def traffic_snapshot(self) -> TrafficPolicySnapshot: ...


@dataclass(frozen=True, slots=True)
class AuthorizationObservation:
    actor: str
    roles: tuple[str, ...]
    expectation: AuthorizationExpectation
    attempt: int
    status: int | None
    body_bytes: int
    marker_observed: bool
    truncated: bool
    transport_error: bool
    outcome: AuthorizationObservationOutcome

    def to_json(self) -> dict[str, object]:
        return {
            "actor": self.actor,
            "roles": list(self.roles),
            "expectation": self.expectation.value,
            "attempt": self.attempt,
            "status": self.status,
            "body_bytes": self.body_bytes,
            "marker_observed": self.marker_observed,
            "truncated": self.truncated,
            "transport_error": self.transport_error,
            "outcome": self.outcome.value,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationCaseResult:
    case_id: str
    method: str
    sanitized_url: str
    owner: str
    verdict: AuthorizationVerdict
    violation_actors: tuple[str, ...]
    reason_codes: tuple[str, ...]
    observations: tuple[AuthorizationObservation, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.case_id,
            "method": self.method,
            "url": self.sanitized_url,
            "owner": self.owner,
            "verdict": self.verdict.value,
            "violation_actors": list(self.violation_actors),
            "reason_codes": list(self.reason_codes),
            "observations": [observation.to_json() for observation in self.observations],
        }


@dataclass(frozen=True, slots=True)
class TrafficSnapshotDelta:
    physical_request_count: int
    completed_request_count: int
    incomplete_request_count: int
    pending_dispatch_count: int
    reservation_count: int
    cache_hit_count: int
    deduplicated_count: int
    retry_count: int
    blocked_count: int
    circuit_open_count: int
    unmetered_action_count: int
    initial_accounting_status: str
    current_accounting_status: str

    def to_json(self) -> dict[str, object]:
        return {
            "physical_request_count": self.physical_request_count,
            "completed_request_count": self.completed_request_count,
            "incomplete_request_count": self.incomplete_request_count,
            "pending_dispatch_count": self.pending_dispatch_count,
            "reservation_count": self.reservation_count,
            "cache_hit_count": self.cache_hit_count,
            "deduplicated_count": self.deduplicated_count,
            "retry_count": self.retry_count,
            "blocked_count": self.blocked_count,
            "circuit_open_count": self.circuit_open_count,
            "unmetered_action_count": self.unmetered_action_count,
            "initial_accounting_status": self.initial_accounting_status,
            "current_accounting_status": self.current_accounting_status,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationMatrixResult:
    plan_schema: str
    verdict: AuthorizationVerdict
    cases: tuple[AuthorizationCaseResult, ...]
    traffic_delta: TrafficSnapshotDelta
    reason_codes: tuple[str, ...] = ()
    schema: str = AUTHORIZATION_MATRIX_RESULT_SCHEMA

    def to_json(self) -> dict[str, object]:
        """Return a stable receipt containing no raw URL, body, or marker values."""
        return {
            "schema": self.schema,
            "plan_schema": self.plan_schema,
            "verdict": self.verdict.value,
            "reason_codes": list(self.reason_codes),
            "cases": [case.to_json() for case in self.cases],
            "traffic_delta": self.traffic_delta.to_json(),
        }


class AuthorizationMatrixRunner:
    """Run immutable authorization comparisons without making state changes."""

    __slots__ = ("_secret_resolver",)

    def __init__(self, secret_resolver: SecretResolver) -> None:
        self._secret_resolver = secret_resolver

    def run(
        self,
        plan: AuthorizationMatrixPlan,
        runtime: AuthorizationMatrixRuntime,
    ) -> AuthorizationMatrixResult:
        identities, roles = _runtime_context(runtime)
        _validate_plan_actors(plan, identities)
        initial = runtime.initial_traffic_snapshot
        results: list[AuthorizationCaseResult] = []
        halted = False

        for case in plan.cases:
            if halted:
                known_marker, _marker_reason = self._resolve_marker(case.marker_env)
                results.append(
                    _skipped_case_result(
                        case,
                        "traffic_policy_halted",
                        known_marker=known_marker,
                    )
                )
                continue
            case_result, halted = self._run_case(
                case,
                runtime=runtime,
                roles=roles,
                initial_snapshot=initial,
            )
            results.append(case_result)

        policy_reasons: tuple[str, ...]
        try:
            current = runtime.traffic_snapshot()
        except Exception:  # noqa: BLE001 - runtime diagnostics must never enter receipts.
            current = initial
            policy_reasons = ("traffic_snapshot_unavailable",)
        else:
            policy_reasons = _traffic_policy_reason_codes(initial, current)
        delta = _snapshot_delta(initial, current)
        if policy_reasons:
            results = [
                _force_inconclusive(result, policy_reasons)
                for result in results
            ]
        verdict = _aggregate_verdict(results)
        return AuthorizationMatrixResult(
            plan_schema=plan.schema,
            verdict=verdict,
            cases=tuple(results),
            traffic_delta=delta,
            reason_codes=policy_reasons,
        )

    def _run_case(
        self,
        case: AuthorizationMatrixCase,
        *,
        runtime: AuthorizationMatrixRuntime,
        roles: Mapping[str, tuple[str, ...]],
        initial_snapshot: TrafficPolicySnapshot,
    ) -> tuple[AuthorizationCaseResult, bool]:
        marker, marker_reason = self._resolve_marker(case.marker_env)
        safe_url = sanitize_url(case.url, known_secrets=(() if marker is None else (marker,)))
        if marker_reason:
            return (
                AuthorizationCaseResult(
                    case_id=case.case_id,
                    method=case.method,
                    sanitized_url=safe_url,
                    owner=case.owner,
                    verdict=AuthorizationVerdict.INCONCLUSIVE,
                    violation_actors=(),
                    reason_codes=(marker_reason,),
                    observations=(),
                ),
                False,
            )
        if marker is None:  # Defensive narrowing for custom secret resolvers.
            raise AuthorizationMatrixRuntimeError("authorization marker resolution failed")
        if _url_contains_marker(case.url, marker):
            return (
                AuthorizationCaseResult(
                    case_id=case.case_id,
                    method=case.method,
                    sanitized_url=safe_url,
                    owner=case.owner,
                    verdict=AuthorizationVerdict.INCONCLUSIVE,
                    violation_actors=(),
                    reason_codes=("marker_present_in_request_url",),
                    observations=(),
                ),
                False,
            )

        observations: list[AuthorizationObservation] = []
        for attempt in (1, 2):
            observations.append(
                _request_observation(
                    runtime,
                    actor=case.owner,
                    roles=roles[case.owner],
                    expectation=AuthorizationExpectation.ALLOW,
                    attempt=attempt,
                    method=case.method,
                    url=case.url,
                    marker=marker,
                )
            )
            if _traffic_policy_halted(runtime, initial_snapshot):
                return (
                    _case_result(
                        case,
                        safe_url=safe_url,
                        observations=observations,
                        verdict=AuthorizationVerdict.INCONCLUSIVE,
                        reason_codes=("traffic_policy_halted",),
                    ),
                    True,
                )

        if not all(_is_expected_allow(observation) for observation in observations):
            return (
                _case_result(
                    case,
                    safe_url=safe_url,
                    observations=observations,
                    verdict=AuthorizationVerdict.INCONCLUSIVE,
                    reason_codes=("owner_baseline_inconclusive",),
                ),
                False,
            )

        violation_actors: list[str] = []
        inconclusive = False
        for actor, raw_expectation in case.expect.items():
            if actor == case.owner:
                continue
            expectation = AuthorizationExpectation(raw_expectation)
            first = _request_observation(
                runtime,
                actor=actor,
                roles=roles[actor],
                expectation=expectation,
                attempt=1,
                method=case.method,
                url=case.url,
                marker=marker,
            )
            observations.append(first)
            if _traffic_policy_halted(runtime, initial_snapshot):
                return (
                    _case_result(
                        case,
                        safe_url=safe_url,
                        observations=observations,
                        verdict=AuthorizationVerdict.INCONCLUSIVE,
                        reason_codes=("traffic_policy_halted",),
                    ),
                    True,
                )
            if expectation is AuthorizationExpectation.ALLOW:
                if not _is_expected_allow(first):
                    inconclusive = True
                continue
            if first.outcome is AuthorizationObservationOutcome.SAFE_DENIAL:
                continue
            if first.outcome is not AuthorizationObservationOutcome.MARKER_EXPOSED:
                inconclusive = True
                continue

            repeated = _request_observation(
                runtime,
                actor=actor,
                roles=roles[actor],
                expectation=expectation,
                attempt=2,
                method=case.method,
                url=case.url,
                marker=marker,
            )
            observations.append(repeated)
            if _traffic_policy_halted(runtime, initial_snapshot):
                return (
                    _case_result(
                        case,
                        safe_url=safe_url,
                        observations=observations,
                        verdict=AuthorizationVerdict.INCONCLUSIVE,
                        reason_codes=("traffic_policy_halted",),
                    ),
                    True,
                )
            if repeated.outcome is AuthorizationObservationOutcome.MARKER_EXPOSED:
                violation_actors.append(actor)
            else:
                inconclusive = True

        reasons: tuple[str, ...]
        if violation_actors:
            verdict = AuthorizationVerdict.CONFIRMED_VIOLATION
            reasons = ("denied_actor_marker_exposed",)
        elif inconclusive:
            verdict = AuthorizationVerdict.INCONCLUSIVE
            reasons = ("actor_comparison_inconclusive",)
        else:
            verdict = AuthorizationVerdict.NO_VIOLATION
            reasons = ()
        return (
            _case_result(
                case,
                safe_url=safe_url,
                observations=observations,
                verdict=verdict,
                reason_codes=reasons,
                violation_actors=violation_actors,
            ),
            False,
        )

    def _resolve_marker(self, environment_key: str) -> tuple[str | None, str]:
        try:
            value = self._secret_resolver.resolve(SecretRef.env(environment_key))
        except Exception:  # noqa: BLE001 - resolver exceptions may contain secret material.
            return None, "marker_unavailable"
        if not isinstance(value, SecretValue) or not value:
            return None, "marker_unavailable"
        marker = value.reveal()
        encoded = marker.encode("utf-8")
        if (
            len(marker) < _MIN_MARKER_CHARS
            or len(encoded) > _MAX_MARKER_BYTES
            or marker != marker.strip()
            or not marker.isprintable()
        ):
            return marker, "marker_not_distinctive"
        return marker, ""


def load_authorization_matrix_plan(
    path: Path,
    *,
    known_identities: Sequence[str],
) -> AuthorizationMatrixPlan:
    """Load one strict YAML plan and reject identities outside the auth configuration."""
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise AuthorizationMatrixPlanError("authorization matrix plan could not be loaded") from exc
    return parse_authorization_matrix_plan(payload, known_identities=known_identities)


def parse_authorization_matrix_plan(
    payload: object,
    *,
    known_identities: Sequence[str],
) -> AuthorizationMatrixPlan:
    """Validate already-decoded YAML using exact types and a closed field set."""
    if not isinstance(payload, Mapping):
        raise AuthorizationMatrixPlanError("authorization matrix plan must be a mapping")
    _require_exact_fields(payload, allowed=_TOP_LEVEL_FIELDS, required=_TOP_LEVEL_FIELDS)
    schema = _mapping_string(payload, "schema")
    if schema != AUTHORIZATION_MATRIX_PLAN_SCHEMA:
        raise AuthorizationMatrixPlanError(
            f"unsupported authorization matrix plan schema: {schema}"
        )
    identities = _known_identity_set(known_identities)
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise AuthorizationMatrixPlanError(
            "authorization matrix plan cases must be a non-empty list"
        )

    cases: list[AuthorizationMatrixCase] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, Mapping):
            raise AuthorizationMatrixPlanError("authorization matrix case must be a mapping")
        _require_exact_fields(
            raw_case,
            allowed=_CASE_FIELDS,
            required=_REQUIRED_CASE_FIELDS,
        )
        raw_expect = raw_case.get("expect")
        if not isinstance(raw_expect, Mapping):
            raise AuthorizationMatrixPlanError("case expect must be a mapping")
        expectation_mapping: dict[str, str] = {}
        for raw_actor, raw_value in raw_expect.items():
            actor = _require_string(raw_actor, "expect actor")
            if not isinstance(raw_value, str):
                raise AuthorizationMatrixPlanError("expect values must be strings")
            expectation_mapping[actor] = raw_value
        case = AuthorizationMatrixCase(
            case_id=_mapping_string(raw_case, "id"),
            method=_mapping_string(raw_case, "method") if "method" in raw_case else _SAFE_METHOD,
            url=_mapping_string(raw_case, "url"),
            owner=_mapping_string(raw_case, "owner"),
            marker_env=_mapping_string(raw_case, "marker_env"),
            expect=expectation_mapping,
        )
        _validate_case_actors(case, identities)
        cases.append(case)
    return AuthorizationMatrixPlan(cases=tuple(cases), schema=schema)


def run_authorization_matrix(
    plan: AuthorizationMatrixPlan,
    *,
    runtime: AuthorizationMatrixRuntime,
    secret_resolver: SecretResolver,
) -> AuthorizationMatrixResult:
    return AuthorizationMatrixRunner(secret_resolver).run(plan, runtime)


def _runtime_context(
    runtime: AuthorizationMatrixRuntime,
) -> tuple[frozenset[str], Mapping[str, tuple[str, ...]]]:
    try:
        raw_identities = tuple(runtime.identities)
    except Exception as exc:
        raise AuthorizationMatrixRuntimeError("runtime identities are unavailable") from exc
    try:
        identities = _known_identity_set(raw_identities)
    except AuthorizationMatrixPlanError as exc:
        raise AuthorizationMatrixRuntimeError("runtime identities are invalid") from exc
    roles: dict[str, tuple[str, ...]] = {ANONYMOUS_ACTOR: ()}
    for alias in sorted(identities, key=_actor_sort_key):
        try:
            raw_roles = runtime.roles(alias)
        except Exception as exc:
            raise AuthorizationMatrixRuntimeError("runtime roles are unavailable") from exc
        if isinstance(raw_roles, str) or any(not isinstance(role, str) for role in raw_roles):
            raise AuthorizationMatrixRuntimeError("runtime roles must be a sequence")
        roles[alias] = tuple(sorted(set(raw_roles)))
    return identities, MappingProxyType(roles)


def _known_identity_set(identities: Sequence[str]) -> frozenset[str]:
    normalized: set[str] = set()
    for raw_alias in identities:
        alias = _require_string(raw_alias, "identity alias")
        _require_identity_alias(alias, field_name="identity alias")
        if alias.casefold() in _RESERVED_ACTORS:
            raise AuthorizationMatrixPlanError("configured identity uses a reserved actor alias")
        if alias in normalized:
            raise AuthorizationMatrixPlanError("configured identity aliases must be unique")
        normalized.add(alias)
    if not normalized:
        raise AuthorizationMatrixPlanError("at least one configured identity is required")
    return frozenset(normalized)


def _validate_plan_actors(
    plan: AuthorizationMatrixPlan,
    identities: frozenset[str],
) -> None:
    for case in plan.cases:
        _validate_case_actors(case, identities)


def _validate_case_actors(
    case: AuthorizationMatrixCase,
    identities: frozenset[str],
) -> None:
    if case.owner not in identities:
        raise AuthorizationMatrixPlanError("case owner is not a configured identity")
    unknown = tuple(
        actor
        for actor in case.expect
        if actor != ANONYMOUS_ACTOR and actor not in identities
    )
    if unknown:
        raise AuthorizationMatrixPlanError("case expect contains an unknown actor")


def _request_observation(
    runtime: AuthorizationMatrixRuntime,
    *,
    actor: str,
    roles: tuple[str, ...],
    expectation: AuthorizationExpectation,
    attempt: int,
    method: str,
    url: str,
    marker: str,
) -> AuthorizationObservation:
    try:
        response = runtime.request(
            None if actor == ANONYMOUS_ACTOR else actor,
            method,
            url,
        )
        status = _response_status(response)
        body = _response_body_bytes(response)
        truncated = bool(response.truncated)
        transport_error = bool(response.error)
    except Exception:  # noqa: BLE001 - response errors must not enter durable receipts.
        status = None
        body = b""
        truncated = False
        transport_error = True
    marker_observed = marker.encode("utf-8") in body
    outcome = _observation_outcome(
        expectation=expectation,
        status=status,
        marker_observed=marker_observed,
        truncated=truncated,
        transport_error=transport_error,
    )
    return AuthorizationObservation(
        actor=actor,
        roles=roles,
        expectation=expectation,
        attempt=attempt,
        status=status,
        body_bytes=len(body),
        marker_observed=marker_observed,
        truncated=truncated,
        transport_error=transport_error,
        outcome=outcome,
    )


def _response_status(response: AuthorizationMatrixHttpResponse) -> int | None:
    status = response.status
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not _MIN_HTTP_STATUS <= status <= _MAX_HTTP_STATUS
    ):
        return None
    return status


def _response_body_bytes(response: AuthorizationMatrixHttpResponse) -> bytes:
    body_bytes = response.body_bytes
    if isinstance(body_bytes, bytes):
        return body_bytes
    if isinstance(body_bytes, bytearray | memoryview):
        return bytes(body_bytes)
    body = response.body
    return body.encode("utf-8", errors="replace") if isinstance(body, str) else b""


def _observation_outcome(
    *,
    expectation: AuthorizationExpectation,
    status: int | None,
    marker_observed: bool,
    truncated: bool,
    transport_error: bool,
) -> AuthorizationObservationOutcome:
    if transport_error or truncated or status is None:
        return AuthorizationObservationOutcome.INCONCLUSIVE
    if status == _RATE_LIMIT_STATUS or status >= _SERVER_ERROR_STATUS_MIN:
        return AuthorizationObservationOutcome.INCONCLUSIVE
    if expectation is AuthorizationExpectation.ALLOW:
        if _SUCCESS_STATUS_MIN <= status < _REDIRECT_STATUS_MIN and marker_observed:
            return AuthorizationObservationOutcome.EXPECTED_ALLOW
        return AuthorizationObservationOutcome.INCONCLUSIVE
    if marker_observed:
        return AuthorizationObservationOutcome.MARKER_EXPOSED
    if status in _SAFE_DENIAL_STATUSES:
        return AuthorizationObservationOutcome.SAFE_DENIAL
    return AuthorizationObservationOutcome.INCONCLUSIVE


def _is_expected_allow(observation: AuthorizationObservation) -> bool:
    return observation.outcome is AuthorizationObservationOutcome.EXPECTED_ALLOW


def _case_result(
    case: AuthorizationMatrixCase,
    *,
    safe_url: str,
    observations: Sequence[AuthorizationObservation],
    verdict: AuthorizationVerdict,
    reason_codes: Sequence[str],
    violation_actors: Sequence[str] = (),
) -> AuthorizationCaseResult:
    return AuthorizationCaseResult(
        case_id=case.case_id,
        method=case.method,
        sanitized_url=safe_url,
        owner=case.owner,
        verdict=verdict,
        violation_actors=tuple(sorted(set(violation_actors), key=_actor_sort_key)),
        reason_codes=tuple(sorted(set(reason_codes))),
        observations=tuple(observations),
    )


def _skipped_case_result(
    case: AuthorizationMatrixCase,
    reason: str,
    *,
    known_marker: str | None,
) -> AuthorizationCaseResult:
    return AuthorizationCaseResult(
        case_id=case.case_id,
        method=case.method,
        sanitized_url=sanitize_url(
            case.url,
            known_secrets=(() if known_marker is None else (known_marker,)),
        ),
        owner=case.owner,
        verdict=AuthorizationVerdict.INCONCLUSIVE,
        violation_actors=(),
        reason_codes=(reason,),
        observations=(),
    )


def _force_inconclusive(
    result: AuthorizationCaseResult,
    reason_codes: Sequence[str],
) -> AuthorizationCaseResult:
    return replace(
        result,
        verdict=AuthorizationVerdict.INCONCLUSIVE,
        violation_actors=(),
        reason_codes=tuple(sorted({*result.reason_codes, *reason_codes})),
    )


def _traffic_policy_halted(
    runtime: AuthorizationMatrixRuntime,
    initial: TrafficPolicySnapshot,
) -> bool:
    try:
        current = runtime.traffic_snapshot()
    except Exception:  # noqa: BLE001 - fail closed on policy inspection failure.
        return True
    delta = _snapshot_delta(initial, current)
    return delta.blocked_count > 0 or delta.circuit_open_count > 0


def _traffic_policy_reason_codes(
    initial: TrafficPolicySnapshot,
    current: TrafficPolicySnapshot,
) -> tuple[str, ...]:
    delta = _snapshot_delta(initial, current)
    reasons: set[str] = set()
    if initial.accounting_status != "exact" or current.accounting_status != "exact":
        reasons.add("traffic_accounting_not_exact")
    if initial.pending_dispatch_count or initial.reservation_count:
        reasons.add("initial_traffic_not_quiescent")
    if current.pending_dispatch_count or current.reservation_count:
        reasons.add("traffic_not_quiescent")
    if delta.blocked_count > 0:
        reasons.add("traffic_policy_blocked")
    if delta.circuit_open_count > 0:
        reasons.add("traffic_circuit_open")
    if delta.unmetered_action_count != 0:
        reasons.add("unmetered_traffic")
    if delta.cache_hit_count > 0 or delta.deduplicated_count > 0:
        reasons.add("reused_traffic_response")
    if delta.retry_count > 0:
        reasons.add("traffic_policy_retry")
    if delta.incomplete_request_count > 0:
        reasons.add("incomplete_traffic")
    if delta.physical_request_count != (
        delta.completed_request_count + delta.incomplete_request_count
    ):
        reasons.add("traffic_accounting_mismatch")
    counter_values = (
        delta.physical_request_count,
        delta.completed_request_count,
        delta.incomplete_request_count,
        delta.cache_hit_count,
        delta.deduplicated_count,
        delta.retry_count,
        delta.blocked_count,
        delta.circuit_open_count,
        delta.unmetered_action_count,
    )
    if any(value < 0 for value in counter_values):
        reasons.add("traffic_counter_regressed")
    return tuple(sorted(reasons))


def _snapshot_delta(
    initial: TrafficPolicySnapshot,
    current: TrafficPolicySnapshot,
) -> TrafficSnapshotDelta:
    return TrafficSnapshotDelta(
        physical_request_count=(
            current.physical_request_count - initial.physical_request_count
        ),
        completed_request_count=(
            current.completed_request_count - initial.completed_request_count
        ),
        incomplete_request_count=(
            current.incomplete_request_count - initial.incomplete_request_count
        ),
        pending_dispatch_count=(
            current.pending_dispatch_count - initial.pending_dispatch_count
        ),
        reservation_count=current.reservation_count - initial.reservation_count,
        cache_hit_count=current.cache_hit_count - initial.cache_hit_count,
        deduplicated_count=current.deduplicated_count - initial.deduplicated_count,
        retry_count=current.retry_count - initial.retry_count,
        blocked_count=current.blocked_count - initial.blocked_count,
        circuit_open_count=current.circuit_open_count - initial.circuit_open_count,
        unmetered_action_count=(
            current.unmetered_action_count - initial.unmetered_action_count
        ),
        initial_accounting_status=initial.accounting_status,
        current_accounting_status=current.accounting_status,
    )


def traffic_policy_halted(
    runtime: AuthorizationMatrixRuntime,
    initial: TrafficPolicySnapshot,
) -> bool:
    """Return whether a shared authorization traffic policy stopped dispatch."""
    return _traffic_policy_halted(runtime, initial)


def traffic_policy_reason_codes(
    initial: TrafficPolicySnapshot,
    current: TrafficPolicySnapshot,
) -> tuple[str, ...]:
    """Return stable fail-closed reasons for unusable authorization traffic."""
    return _traffic_policy_reason_codes(initial, current)


def traffic_snapshot_delta(
    initial: TrafficPolicySnapshot,
    current: TrafficPolicySnapshot,
) -> TrafficSnapshotDelta:
    """Return the whole-run traffic counters added after ``initial``."""
    return _snapshot_delta(initial, current)


def _aggregate_verdict(results: Sequence[AuthorizationCaseResult]) -> AuthorizationVerdict:
    if any(result.verdict is AuthorizationVerdict.CONFIRMED_VIOLATION for result in results):
        return AuthorizationVerdict.CONFIRMED_VIOLATION
    if any(result.verdict is AuthorizationVerdict.INCONCLUSIVE for result in results):
        return AuthorizationVerdict.INCONCLUSIVE
    return AuthorizationVerdict.NO_VIOLATION


def _require_exact_fields(
    value: Mapping[object, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
) -> None:
    keys = set(value)
    if any(not isinstance(key, str) for key in keys):
        raise AuthorizationMatrixPlanError("authorization matrix field names must be strings")
    unknown = keys - allowed
    missing = required - keys
    if unknown:
        raise AuthorizationMatrixPlanError("authorization matrix contains unknown fields")
    if missing:
        raise AuthorizationMatrixPlanError("authorization matrix is missing required fields")


def _mapping_string(value: Mapping[object, object], key: str) -> str:
    return _require_string(value.get(key), key)


def _require_string(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise AuthorizationMatrixPlanError(f"{field_name} must be a string")
    return value


def _require_identifier(value: str, field_name: str) -> None:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise AuthorizationMatrixPlanError(
            f"{field_name} must be a lowercase identifier up to 64 characters"
        )


def _require_identity_alias(value: str, *, field_name: str) -> None:
    _require_identifier(value, field_name)


def _require_actor(actor: str) -> None:
    if actor == ANONYMOUS_ACTOR:
        return
    _require_identity_alias(actor, field_name="actor alias")
    if actor.casefold() in _RESERVED_ACTORS:
        raise AuthorizationMatrixPlanError("case uses a reserved actor alias")


def _require_concrete_http_url(url: str) -> None:
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_CHARS:
        raise AuthorizationMatrixPlanError("case URL must be a non-empty HTTP URL")
    if any(character in url for character in _UNSAFE_URL_CHARACTERS):
        raise AuthorizationMatrixPlanError("case URL must be concrete and contain no templates")
    if any(ord(character) < _ASCII_SPACE or character.isspace() for character in url):
        raise AuthorizationMatrixPlanError("case URL contains unsafe whitespace")
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError as exc:
        raise AuthorizationMatrixPlanError("case URL is invalid") from exc
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise AuthorizationMatrixPlanError("case URL must be an absolute HTTP URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise AuthorizationMatrixPlanError("case URL contains unsafe userinfo or a fragment")


def _url_contains_marker(url: str, marker: str) -> bool:
    decoded = url
    for _round in range(2):
        decoded = unquote_plus(decoded)
    return marker in decoded


def _actor_sort_key(actor: str) -> tuple[int, str, str]:
    return (actor == ANONYMOUS_ACTOR, actor.casefold(), actor)


__all__ = [
    "ANONYMOUS_ACTOR",
    "AUTHORIZATION_MATRIX_PLAN_SCHEMA",
    "AUTHORIZATION_MATRIX_RESULT_SCHEMA",
    "AuthorizationCaseResult",
    "AuthorizationExpectation",
    "AuthorizationMatrixCase",
    "AuthorizationMatrixHttpResponse",
    "AuthorizationMatrixPlan",
    "AuthorizationMatrixPlanError",
    "AuthorizationMatrixResult",
    "AuthorizationMatrixRunner",
    "AuthorizationMatrixRuntime",
    "AuthorizationMatrixRuntimeError",
    "AuthorizationObservation",
    "AuthorizationObservationOutcome",
    "AuthorizationVerdict",
    "TrafficSnapshotDelta",
    "load_authorization_matrix_plan",
    "parse_authorization_matrix_plan",
    "run_authorization_matrix",
    "traffic_policy_halted",
    "traffic_policy_reason_codes",
    "traffic_snapshot_delta",
]
