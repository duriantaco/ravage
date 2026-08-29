from __future__ import annotations

from typing import Protocol

from .contracts import (
    AuthBenchCaseResult,
    AuthBenchCheck,
    AuthBenchManifest,
    AuthBenchObservation,
    AuthBenchResult,
)
from .fixtures import (
    BEARER_REFRESH_CASE,
    FALSE_AUTH_CASE,
    FORCED_EXPIRY_CASE,
    FORM_COOKIE_CASE,
    ROTATING_CSRF_CASE,
    TWO_IDENTITY_CASE,
    UNSAFE_POST_CASE,
    AuthBenchCaseContext,
    _AuthBenchFixture,
    _TruthEvent,
    default_manifest,
)


class AuthBenchStrategy(Protocol):
    def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation: ...


def run_authbench(
    strategy: AuthBenchStrategy,
    *,
    manifest: AuthBenchManifest | None = None,
) -> AuthBenchResult:
    selected_manifest = manifest or default_manifest()
    results: list[AuthBenchCaseResult] = []
    for spec in selected_manifest.cases:
        fixture = _AuthBenchFixture(spec)
        try:
            observation = strategy.run_case(fixture.context())
            if not isinstance(observation, AuthBenchObservation):
                raise TypeError("strategy must return AuthBenchObservation")
            checks = _grade_case(spec.case_id, fixture.truth_events(), observation)
            results.append(
                AuthBenchCaseResult(
                    case_id=spec.case_id,
                    passed=all(check.passed for check in checks),
                    checks=checks,
                    observation=observation,
                )
            )
        except Exception as exc:  # benchmark failures belong in the result contract
            results.append(
                AuthBenchCaseResult(
                    case_id=spec.case_id,
                    passed=False,
                    checks=(),
                    observation=AuthBenchObservation(),
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
    return AuthBenchResult(
        benchmark_id=selected_manifest.benchmark_id,
        manifest_schema_version=selected_manifest.schema_version,
        manifest_revision=selected_manifest.revision,
        cases=tuple(results),
    )


def _grade_case(
    case_id: str,
    events: tuple[_TruthEvent, ...],
    observation: AuthBenchObservation,
) -> tuple[AuthBenchCheck, ...]:
    if case_id == FORM_COOKIE_CASE:
        return (
            _check(
                "session_established",
                _count(events, "session_login", identity="alice") == 1,
                f"Alice session logins: {_count(events, 'session_login', identity='alice')}",
            ),
            _check(
                "protected_cookie_access",
                _count(events, "protected_access", identity="alice") == 1,
                f"Alice protected accesses: {_count(events, 'protected_access', identity='alice')}",
            ),
            _check(
                "reported_authenticated",
                observation.authenticated is True,
                f"strategy reported authenticated={observation.authenticated}",
            ),
        )
    if case_id == ROTATING_CSRF_CASE:
        issued = _count(events, "csrf_issued")
        accepted = _count(events, "csrf_accepted")
        mutations = _count(events, "csrf_mutation", identity="alice")
        return (
            _check(
                "csrf_rotated",
                issued >= 3,
                f"CSRF tokens issued across login and mutation: {issued}",
            ),
            _check(
                "csrf_consumed",
                accepted == 2,
                f"accepted one-time CSRF tokens: {accepted}",
            ),
            _check(
                "authenticated_mutation",
                mutations == 1,
                f"Alice protected mutations: {mutations}",
            ),
            _check(
                "reported_authenticated",
                observation.authenticated is True,
                f"strategy reported authenticated={observation.authenticated}",
            ),
        )
    if case_id == BEARER_REFRESH_CASE:
        generations = {
            event.detail
            for event in events
            if event.kind == "bearer_resource"
            and event.identity == "alice"
            and event.detail is not None
        }
        refreshes = _count(events, "bearer_refresh", identity="alice")
        return (
            _check(
                "initial_bearer_access",
                "1" in generations,
                f"successful token generations: {sorted(generations)}",
            ),
            _check(
                "expiry_detected",
                _count(events, "bearer_expired", identity="alice") == 1,
                f"expired access-token challenges: {_count(events, 'bearer_expired', identity='alice')}",
            ),
            _check(
                "refresh_rotated",
                refreshes == 1 and "2" in generations,
                f"refreshes={refreshes}; successful generations={sorted(generations)}",
            ),
            _check(
                "reported_refresh",
                observation.authenticated is True and observation.refresh_performed,
                (
                    "strategy reported "
                    f"authenticated={observation.authenticated}, "
                    f"refresh_performed={observation.refresh_performed}"
                ),
            ),
        )
    if case_id == FORCED_EXPIRY_CASE:
        logins = _count(events, "session_login", identity="alice")
        accesses = _count(events, "expiry_resource", identity="alice")
        challenges = _count(events, "forced_expiry_seen")
        return (
            _check(
                "expiry_observed",
                challenges == 1,
                f"forced-expiry challenges: {challenges}",
            ),
            _check(
                "session_reestablished",
                logins == 2,
                f"Alice session logins: {logins}",
            ),
            _check(
                "protected_access_restored",
                accesses == 2,
                f"Alice successful protected accesses: {accesses}",
            ),
            _check(
                "reported_authenticated",
                observation.authenticated is True,
                f"strategy reported authenticated={observation.authenticated}",
            ),
        )
    if case_id == TWO_IDENTITY_CASE:
        login_identities = _event_identities(events, "session_login")
        me_events = tuple(event for event in events if event.kind == "multi_me")
        me_identities = {event.identity for event in me_events}
        client_labels = {event.client_label for event in me_events}
        cross_denials = _count(events, "cross_identity_denied")
        return (
            _check(
                "two_sessions_established",
                login_identities == {"alice", "bob"},
                f"authenticated identities: {sorted(login_identities)}",
            ),
            _check(
                "cookie_jars_isolated",
                me_identities == {"alice", "bob"} and len(client_labels) == 2,
                (
                    f"protected identities={sorted(identity for identity in me_identities if identity)}; "
                    f"client jars={sorted(client_labels)}"
                ),
            ),
            _check(
                "cross_identity_denied",
                cross_denials == 2,
                f"cross-account denials: {cross_denials}",
            ),
            _check(
                "reported_identities",
                observation.authenticated is True
                and set(observation.identities) == {"alice", "bob"},
                f"strategy reported identities={sorted(observation.identities)}",
            ),
        )
    if case_id == FALSE_AUTH_CASE:
        deceptive = _count(events, "deceptive_login")
        denied = _count(events, "negative_protected_denied")
        sessions = _count(events, "session_login")
        return (
            _check(
                "deceptive_response_exercised",
                deceptive == 1,
                f"deceptive login responses: {deceptive}",
            ),
            _check(
                "protected_verification_failed",
                denied == 1 and sessions == 0,
                f"protected denials={denied}; sessions established={sessions}",
            ),
            _check(
                "reported_unauthenticated",
                observation.authenticated is False,
                f"strategy reported authenticated={observation.authenticated}",
            ),
        )
    if case_id == UNSAFE_POST_CASE:
        attempts = _count(events, "unsafe_post_attempt")
        commits = _count(events, "unsafe_post_committed", identity="alice")
        return (
            _check(
                "single_unsafe_attempt",
                attempts == 1,
                f"unsafe POST attempts: {attempts}",
            ),
            _check(
                "single_server_commit",
                commits == 1,
                f"server-side charge commits: {commits}",
            ),
            _check(
                "reported_no_replay",
                observation.unsafe_request_replayed is False,
                (
                    "strategy reported "
                    f"unsafe_request_replayed={observation.unsafe_request_replayed}"
                ),
            ),
        )
    raise ValueError(f"no evaluator-owned grader for AuthBench case: {case_id}")


def _check(name: str, passed: bool, detail: str) -> AuthBenchCheck:
    return AuthBenchCheck(name=name, passed=passed, detail=detail)


def _count(
    events: tuple[_TruthEvent, ...],
    kind: str,
    *,
    identity: str | None = None,
) -> int:
    return sum(
        event.kind == kind and (identity is None or event.identity == identity) for event in events
    )


def _event_identities(events: tuple[_TruthEvent, ...], kind: str) -> set[str]:
    return {event.identity for event in events if event.kind == kind and event.identity is not None}
