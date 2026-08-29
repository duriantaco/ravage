"""Target-specific, secret-safe configured-authentication preflight."""

# The public entry point intentionally converts every expected failure into one
# structured result, and its keyword-only inputs keep CLI adapters straightforward.
# ruff: noqa: BLE001, C901, EM101, PLR0911, PLR0912, PLR0913

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pentest_schemas import EngagementBrief

from ravage.runtime.common import assert_http_url
from ravage.web_core.http_probe import ProbeSession
from ravage.web_core.scope_policy import is_local_url

from .configured import (
    ConfiguredAuthenticationError,
    UnsupportedConfiguredAuthFlowError,
    assert_secure_configured_auth_transport,
    identity_profile_from_config,
)
from .secrets import (
    EnvironmentFileError,
    SecretResolutionError,
    SecretResolver,
    SecretValue,
    environment_secret_resolver,
)
from .sessions import AuthenticationError, IdentityProfile, SessionHealth, SessionManager

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from .sessions import HealthCheckCallback, IdentitySecrets, LoginCallback

AuthPreflightStageName = Literal["configuration", "secrets", "login", "health"]

_STAGE_ORDER: tuple[AuthPreflightStageName, ...] = (
    "configuration",
    "secrets",
    "login",
    "health",
)


class AuthPreflightStageStatus(StrEnum):
    """The terminal status of one authentication-preflight stage."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class AuthPreflightStage:
    """One secret-free, machine-readable authentication-preflight stage."""

    name: AuthPreflightStageName
    status: AuthPreflightStageStatus
    reason_code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class AuthPreflightResult:
    """Secret-safe result returned whether authentication succeeds or fails."""

    identity: str
    flow: str
    passed: bool
    reason_code: str
    stages: tuple[AuthPreflightStage, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity,
            "flow": self.flow,
            "passed": self.passed,
            "reason_code": self.reason_code,
            "stages": [stage.to_dict() for stage in self.stages],
        }


@dataclass(slots=True)
class _ExecutionState:
    login_started: bool = False
    login_passed: bool = False
    login_reason: str = "login_failed"
    health_started: bool = False
    health_passed: bool = False
    health_reason: str = "health_check_failed"


class _PreflightInputError(ValueError):
    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


def run_auth_preflight(
    brief: EngagementBrief,
    alias: str,
    target_url: str,
    *,
    secret_resolver: SecretResolver | None = None,
    environment: Mapping[str, str] | None = None,
    env_file: Path | None = None,
    timeout_seconds: int = 10,
    allow_remote_target: bool = False,
) -> AuthPreflightResult:
    """
    Validate and establish one configured identity without creating run artifacts.

    Expected configuration, secret, login, and health failures are represented in
    the returned result. Resolver exceptions and server responses are never copied
    into it, keeping even adversarial failure messages out of terminal/JSON output.
    """
    stages: list[AuthPreflightStage] = []
    flow = ""
    if not isinstance(brief, EngagementBrief):
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "brief_not_validated",
            "load and validate the engagement brief before checking authentication",
        )

    authentication = brief.authentication
    if authentication is None:
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "authentication_not_configured",
            "the engagement brief has no authentication identities",
        )
    selected = next(
        (identity for identity in authentication.identities if identity.alias == alias),
        None,
    )
    if selected is None:
        available = ", ".join(identity.alias for identity in authentication.identities)
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "identity_not_found",
            f"configured identities: {available}",
        )
    flow = selected.flow.kind

    try:
        profile = identity_profile_from_config(authentication, alias)
    except UnsupportedConfiguredAuthFlowError:
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "unsupported_flow",
            f"{flow} authentication requires an interactive adapter",
        )
    except ConfiguredAuthenticationError:
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "invalid_authentication_configuration",
            "the selected authentication identity cannot be compiled",
        )

    try:
        assert_http_url(target_url)
    except (TypeError, ValueError):
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "invalid_target",
            "the target URL must be a valid HTTP or HTTPS URL",
        )
    try:
        assert_secure_configured_auth_transport(
            authentication,
            target_url=target_url,
            alias=alias,
        )
    except ConfiguredAuthenticationError:
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "insecure_transport",
            "use HTTPS for non-local authentication endpoints",
        )
    if not allow_remote_target and not is_local_url(target_url):
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "remote_target_not_authorized",
            "remote authentication checks require explicit target authorization",
        )

    try:
        base_session = ProbeSession(
            target_url,
            timeout_seconds=timeout_seconds,
            allow_remote_target=allow_remote_target,
            in_scope=brief.scope.in_scope,
            out_of_scope=brief.scope.out_of_scope,
            max_rps=brief.roe.max_rps,
        )
    except (TypeError, ValueError):
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "invalid_target",
            "the target URL or engagement scope is invalid for this check",
        )
    configured_endpoints = [selected.health_check.endpoint.url]
    if selected.flow.endpoint is not None:
        configured_endpoints.append(selected.flow.endpoint.url)
    if any(not base_session.in_scope(url) for url in configured_endpoints):
        return _failed_result(
            alias,
            flow,
            stages,
            "configuration",
            "auth_endpoint_out_of_scope",
            "login and health-check URLs must be inside the selected target scope",
        )
    stages.append(_passed("configuration", "configuration_valid", "identity and target accepted"))

    try:
        resolver = _secret_resolver(
            secret_resolver=secret_resolver,
            environment=environment,
            env_file=env_file,
        )
    except _PreflightInputError as exc:
        return _failed_result(
            alias,
            flow,
            stages,
            "secrets",
            exc.reason_code,
            exc.detail,
        )

    secret_failure = _validate_secret_references(profile, resolver)
    if secret_failure is not None:
        reason_code, detail = secret_failure
        return _failed_result(
            alias,
            flow,
            stages,
            "secrets",
            reason_code,
            detail,
        )
    stages.append(
        _passed(
            "secrets",
            "secrets_available",
            f"{len(profile.secrets)} declared secret reference(s) resolved",
        )
    )

    execution = _ExecutionState()
    instrumented = _instrument_profile(profile, execution)
    manager = SessionManager(base_session, (instrumented,), secret_resolver=resolver)
    try:
        manager.acquire(alias)
    except AuthenticationError:
        return _execution_failure(alias, flow, stages, execution)
    finally:
        manager.close()

    stages.append(_passed("login", "login_succeeded", "authentication was established"))
    stages.append(_passed("health", "health_check_succeeded", "protected check passed"))
    return AuthPreflightResult(
        identity=alias,
        flow=flow,
        passed=True,
        reason_code="ready",
        stages=tuple(stages),
    )


def _secret_resolver(
    *,
    secret_resolver: SecretResolver | None,
    environment: Mapping[str, str] | None,
    env_file: Path | None,
) -> SecretResolver:
    if secret_resolver is not None:
        if environment is not None or env_file is not None:
            raise _PreflightInputError(
                "ambiguous_secret_source",
                "pass either a secret resolver or environment inputs, not both",
            )
        return secret_resolver
    try:
        return environment_secret_resolver(environment=environment, env_file=env_file)
    except EnvironmentFileError as exc:
        raise _PreflightInputError(exc.reason_code, exc.detail) from None


def _validate_secret_references(
    profile: IdentityProfile,
    resolver: SecretResolver,
) -> tuple[str, str] | None:
    for reference in profile.secrets.values():
        try:
            value = resolver.resolve(reference)
        except SecretResolutionError:
            return (
                "secret_unavailable",
                f"environment variable {reference.key} is not set",
            )
        except Exception:
            return (
                "secret_resolution_failed",
                f"environment variable {reference.key} could not be resolved",
            )
        if not isinstance(value, SecretValue):
            return (
                "secret_resolution_failed",
                f"environment variable {reference.key} did not resolve safely",
            )
        if not value:
            return (
                "secret_unset",
                f"environment variable {reference.key} is empty",
            )
    return None


def _instrument_profile(profile: IdentityProfile, state: _ExecutionState) -> IdentityProfile:
    login = _instrument_login(profile.login, state)
    health = _instrument_health(profile.health_check, state)
    return IdentityProfile(
        name=profile.name,
        login=login,
        health_check=health,
        secrets=profile.secrets,
    )


def _instrument_login(
    callback: LoginCallback | None,
    state: _ExecutionState,
) -> LoginCallback | None:
    if callback is None:
        return None

    def login(session: ProbeSession, secrets: IdentitySecrets) -> bool | None:
        state.login_started = True
        try:
            result = callback(session, secrets)
        except ConfiguredAuthenticationError:
            state.login_reason = "login_configuration_error"
            raise
        except Exception:
            state.login_reason = "login_request_failed"
            raise
        if result is None or result is True:
            state.login_passed = True
            state.login_reason = "login_succeeded"
            return result
        state.login_passed = False
        state.login_reason = "login_rejected"
        return False

    return login


def _instrument_health(
    callback: HealthCheckCallback | None,
    state: _ExecutionState,
) -> HealthCheckCallback | None:
    if callback is None:
        return None

    def health(session: ProbeSession) -> bool | SessionHealth:
        state.health_started = True
        try:
            result = callback(session)
        except Exception:
            state.health_reason = "health_check_failed"
            raise
        state.health_passed = result is True or result is SessionHealth.HEALTHY
        state.health_reason = (
            "health_check_succeeded" if state.health_passed else "health_check_rejected"
        )
        return result

    return health


def _execution_failure(
    alias: str,
    flow: str,
    stages: list[AuthPreflightStage],
    execution: _ExecutionState,
) -> AuthPreflightResult:
    if not execution.login_started:
        return _failed_result(
            alias,
            flow,
            stages,
            "login",
            "session_setup_failed",
            "an isolated authentication session could not be created",
        )
    if not execution.login_passed:
        return _failed_result(
            alias,
            flow,
            stages,
            "login",
            execution.login_reason,
            "the configured login did not establish a session",
        )
    stages.append(_passed("login", "login_succeeded", "authentication was established"))
    if not execution.health_started:
        return _failed_result(
            alias,
            flow,
            stages,
            "health",
            "health_check_not_run",
            "the protected health check did not run",
        )
    return _failed_result(
        alias,
        flow,
        stages,
        "health",
        execution.health_reason,
        "the protected health check did not confirm authentication",
    )


def _passed(name: AuthPreflightStageName, reason_code: str, detail: str) -> AuthPreflightStage:
    return AuthPreflightStage(
        name=name,
        status=AuthPreflightStageStatus.PASSED,
        reason_code=reason_code,
        detail=detail,
    )


def _failed_result(
    alias: str,
    flow: str,
    stages: list[AuthPreflightStage],
    failed_stage: AuthPreflightStageName,
    reason_code: str,
    detail: str,
) -> AuthPreflightResult:
    stages.append(
        AuthPreflightStage(
            name=failed_stage,
            status=AuthPreflightStageStatus.FAILED,
            reason_code=reason_code,
            detail=detail,
        )
    )
    completed_names = {stage.name for stage in stages}
    stages.extend(
        AuthPreflightStage(
            name=name,
            status=AuthPreflightStageStatus.SKIPPED,
            reason_code="not_run",
            detail="not run because an earlier stage failed",
        )
        for name in _STAGE_ORDER
        if name not in completed_names
    )
    return AuthPreflightResult(
        identity=alias,
        flow=flow,
        passed=False,
        reason_code=reason_code,
        stages=tuple(stages),
    )


__all__ = [
    "AuthPreflightResult",
    "AuthPreflightStage",
    "AuthPreflightStageName",
    "AuthPreflightStageStatus",
    "run_auth_preflight",
]
