from __future__ import annotations

import json
import re

import pytest
from ravage.authbench import (
    MANIFEST_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    AuthBenchCaseContext,
    AuthBenchManifest,
    AuthBenchObservation,
    AuthBenchResult,
    ManagedSessionAuthBenchStrategy,
    ReferenceAuthBenchStrategy,
    default_manifest,
    run_authbench,
)
from ravage.authbench.__main__ import main
from ravage.authbench.fixtures import (
    BEARER_REFRESH_CASE,
    FALSE_AUTH_CASE,
    ROTATING_CSRF_CASE,
    TWO_IDENTITY_CASE,
    UNSAFE_POST_CASE,
)

_CSRF_PATTERN = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


def test_manifest_contract_is_versioned_and_round_trips() -> None:
    manifest = default_manifest()

    assert manifest.schema_version == MANIFEST_SCHEMA_VERSION
    assert len(manifest.cases) == 7
    assert AuthBenchManifest.from_dict(manifest.to_dict()) == manifest

    incompatible = manifest.to_dict()
    incompatible["schema_version"] = "ravage.authbench.manifest.v999"
    with pytest.raises(ValueError, match="unsupported AuthBench manifest schema"):
        AuthBenchManifest.from_dict(incompatible)


def test_reference_strategy_passes_every_evaluator_owned_case() -> None:
    result = run_authbench(ReferenceAuthBenchStrategy())

    assert result.schema_version == RESULT_SCHEMA_VERSION
    assert result.passed is True
    assert result.passed_cases == result.total_cases == 7
    assert all(case.checks for case in result.cases)
    assert AuthBenchResult.from_dict(result.to_dict()) == result


def test_managed_session_strategy_passes_every_case() -> None:
    result = run_authbench(ManagedSessionAuthBenchStrategy())

    assert result.passed is True
    assert result.passed_cases == result.total_cases == 7


def test_authbench_module_is_directly_executable(capsys: pytest.CaptureFixture[str]) -> None:
    assert main() == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == RESULT_SCHEMA_VERSION
    assert payload["passed"] is True
    assert payload["score"] == {"passed": 7, "total": 7}


def test_claiming_success_without_exercising_target_does_not_pass() -> None:
    class ClaimOnlyStrategy:
        def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
            del context
            return AuthBenchObservation(authenticated=True)

    manifest = _single_case_manifest(FALSE_AUTH_CASE)
    result = run_authbench(ClaimOnlyStrategy(), manifest=manifest)

    assert result.passed is False
    assert {check.name for check in result.cases[0].checks if not check.passed} == {
        "deceptive_response_exercised",
        "protected_verification_failed",
        "reported_unauthenticated",
    }


def test_deceptive_welcome_page_is_not_accepted_as_authentication() -> None:
    class WelcomeTextStrategy:
        def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
            client = context.new_client()
            identity = context.spec.identities[0]
            login = client.post_form(
                context.spec.entrypoint,
                {"username": identity.username, "password": identity.password},
            )
            client.get("/negative/profile")
            return AuthBenchObservation(authenticated="Welcome" in login.body)

    result = run_authbench(
        WelcomeTextStrategy(),
        manifest=_single_case_manifest(FALSE_AUTH_CASE),
    )

    assert result.passed is False
    failed = {check.name for check in result.cases[0].checks if not check.passed}
    assert failed == {"reported_unauthenticated"}


def test_rotating_csrf_rejects_stale_token_but_fresh_tokens_complete() -> None:
    class RotatingCsrfStrategy:
        def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
            client = context.new_client()
            identity = context.spec.identities[0]
            first = _csrf(client.get(context.spec.entrypoint).body)
            _csrf(client.get(context.spec.entrypoint).body)
            stale = client.post_form(
                context.spec.entrypoint,
                {
                    "username": identity.username,
                    "password": identity.password,
                    "csrf_token": first,
                },
            )
            fresh = _csrf(client.get(context.spec.entrypoint).body)
            login = client.post_form(
                context.spec.entrypoint,
                {
                    "username": identity.username,
                    "password": identity.password,
                    "csrf_token": fresh,
                },
            )
            action_token = login.json()["csrf_token"]
            assert isinstance(action_token, str)
            mutation = client.post_form(
                "/csrf/email",
                {"csrf_token": action_token, "email": "alice+fresh@example.test"},
            )
            return AuthBenchObservation(
                authenticated=stale.status == 403 and mutation.status == 200
            )

    result = run_authbench(
        RotatingCsrfStrategy(),
        manifest=_single_case_manifest(ROTATING_CSRF_CASE),
    )

    assert result.passed is True


def test_bearer_claim_without_refresh_fails_ground_truth() -> None:
    class NoRefreshStrategy:
        def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
            client = context.new_client()
            identity = context.spec.identities[0]
            login = client.post_form(
                context.spec.entrypoint,
                {"username": identity.username, "password": identity.password},
            )
            token = login.json()["access_token"]
            assert isinstance(token, str)
            headers = {"Authorization": f"Bearer {token}"}
            client.get("/bearer/resource", headers=headers)
            client.get("/bearer/resource", headers=headers)
            return AuthBenchObservation(authenticated=True, refresh_performed=True)

    result = run_authbench(
        NoRefreshStrategy(),
        manifest=_single_case_manifest(BEARER_REFRESH_CASE),
    )

    assert result.passed is False
    failed = {check.name for check in result.cases[0].checks if not check.passed}
    assert failed == {"refresh_rotated"}


def test_evaluator_catches_unsafe_post_replay_even_when_strategy_denies_it() -> None:
    class UnsafeReplayStrategy:
        def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
            client = context.new_client()
            identity = context.spec.identities[0]
            credentials = {"username": identity.username, "password": identity.password}
            client.post_form(context.spec.entrypoint, credentials)
            client.post_form("/unsafe/charge", {"amount": "25"})
            client.post_form(context.spec.entrypoint, credentials)
            client.post_form("/unsafe/charge", {"amount": "25"})
            return AuthBenchObservation(
                authenticated=True,
                unsafe_request_replayed=False,
            )

    result = run_authbench(
        UnsafeReplayStrategy(),
        manifest=_single_case_manifest(UNSAFE_POST_CASE),
    )

    assert result.passed is False
    failed = {check.name for check in result.cases[0].checks if not check.passed}
    assert failed == {"single_unsafe_attempt", "single_server_commit"}


def test_broken_strategy_cannot_fake_auth_replay_or_identity_isolation() -> None:
    class BrokenBoundaryStrategy:
        def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
            identity = context.spec.identities[0]
            credentials = {
                "username": identity.username,
                "password": identity.password,
            }
            client = context.new_client("shared-client")
            if context.spec.case_id == FALSE_AUTH_CASE:
                client.post_form(context.spec.entrypoint, credentials)
                return AuthBenchObservation(authenticated=True)
            if context.spec.case_id == UNSAFE_POST_CASE:
                client.post_form(context.spec.entrypoint, credentials)
                client.post_form("/unsafe/charge", {"amount": "25"})
                client.post_form(context.spec.entrypoint, credentials)
                client.post_form("/unsafe/charge", {"amount": "25"})
                return AuthBenchObservation(
                    authenticated=True,
                    unsafe_request_replayed=False,
                )
            if context.spec.case_id == TWO_IDENTITY_CASE:
                bob = context.spec.identities[1]
                client.post_form(context.spec.entrypoint, credentials)
                alice_me = client.get("/multi/me")
                client.post_form(
                    context.spec.entrypoint,
                    {"username": bob.username, "password": bob.password},
                )
                bob_me = client.get("/multi/me")
                client.get("/multi/user/bob")
                client.get("/multi/user/alice")
                return AuthBenchObservation(
                    authenticated=alice_me.status == bob_me.status == 200,
                    identities=("alice", "bob"),
                )
            raise AssertionError("unexpected case")

    result = run_authbench(
        BrokenBoundaryStrategy(),
        manifest=_cases_manifest(
            FALSE_AUTH_CASE,
            UNSAFE_POST_CASE,
            TWO_IDENTITY_CASE,
        ),
    )

    assert result.passed is False
    assert result.passed_cases == 0
    failed = {
        case.case_id: {check.name for check in case.checks if not check.passed}
        for case in result.cases
    }
    assert "reported_unauthenticated" in failed[FALSE_AUTH_CASE]
    assert "single_server_commit" in failed[UNSAFE_POST_CASE]
    assert "cookie_jars_isolated" in failed[TWO_IDENTITY_CASE]


def test_strategy_exception_is_serialized_as_case_failure() -> None:
    class BrokenStrategy:
        def run_case(self, context: AuthBenchCaseContext) -> AuthBenchObservation:
            raise RuntimeError(f"cannot handle {context.spec.case_id}")

    result = run_authbench(
        BrokenStrategy(),
        manifest=_single_case_manifest(FALSE_AUTH_CASE),
    )

    assert result.passed is False
    assert result.cases[0].checks == ()
    assert result.cases[0].error == "RuntimeError: cannot handle negative_false_auth"


def _single_case_manifest(case_id: str) -> AuthBenchManifest:
    return _cases_manifest(case_id)


def _cases_manifest(*case_ids: str) -> AuthBenchManifest:
    base = default_manifest()
    cases_by_id = {case.case_id: case for case in base.cases}
    return AuthBenchManifest(
        benchmark_id=f"{base.benchmark_id}-selected",
        revision=base.revision,
        cases=tuple(cases_by_id[case_id] for case_id in case_ids),
    )


def _csrf(body: str) -> str:
    match = _CSRF_PATTERN.search(body)
    assert match is not None
    return match.group(1)
