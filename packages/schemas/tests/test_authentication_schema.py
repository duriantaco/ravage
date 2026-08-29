import json
from uuid import UUID

import pytest
from pentest_schemas import (
    AuthEndpoint,
    AuthenticationConfig,
    AuthFlow,
    AuthHealthCheck,
    AuthIdentity,
    AuthStaticHeader,
    Budget,
    EngagementBrief,
    OperatorCheckpoint,
    RulesOfEngagement,
    Scope,
    SecretReference,
    TotpConfig,
)
from pydantic import ValidationError

ENGAGEMENT_ID = UUID("11111111-1111-4111-8111-111111111111")


def _brief_payload() -> dict[str, object]:
    return {
        "engagement_id": str(ENGAGEMENT_ID),
        "scope": {"in_scope": ["https://target.test"], "out_of_scope": []},
        "roe": {"max_rps": 10},
        "objectives": ["web_application_assessment"],
        "budget": {"max_cost_usd": 10.0, "max_runtime_min": 30},
    }


def _health_check() -> AuthHealthCheck:
    return AuthHealthCheck(
        endpoint=AuthEndpoint(url="https://target.test/account", scope="target"),
        authenticated_marker="Account settings",
        unauthenticated_marker="Sign in",
    )


def test_engagement_brief_remains_backward_compatible_without_authentication() -> None:
    brief = EngagementBrief.model_validate_json(json.dumps(_brief_payload()))

    assert brief.authentication is None


def test_authentication_config_round_trips_secret_references_and_scopes() -> None:
    payload = _brief_payload()
    payload["authentication"] = {
        "identities": [
            {
                "alias": "customer_a",
                "roles": ["customer"],
                "flow": {
                    "kind": "form",
                    "endpoint": {
                        "url": "https://target.test/login",
                        "scope": "target",
                    },
                    "secret_refs": {
                        "username": {
                            "provider": "environment",
                            "key": "RAVAGE_CUSTOMER_A_USERNAME",
                        },
                        "password": {
                            "provider": "environment",
                            "key": "RAVAGE_CUSTOMER_A_PASSWORD",
                        },
                    },
                    "totp": {
                        "secret": {
                            "provider": "environment",
                            "key": "RAVAGE_CUSTOMER_A_TOTP",
                        }
                    },
                },
                "health_check": {
                    "endpoint": {
                        "url": "https://target.test/account",
                        "scope": "target",
                    },
                    "authenticated_marker": "Account settings",
                },
            },
            {
                "alias": "sso_admin",
                "roles": ["admin"],
                "flow": {
                    "kind": "oauth2_oidc",
                    "endpoint": {
                        "url": "https://identity.test/authorize",
                        "scope": "auth_dependency",
                    },
                    "operator_checkpoint": {
                        "kind": "webauthn",
                        "timeout_seconds": 180,
                    },
                },
                "health_check": {
                    "endpoint": {
                        "url": "https://target.test/admin",
                        "scope": "target",
                    },
                    "success_statuses": [200, 204],
                },
            },
        ]
    }

    original = EngagementBrief.model_validate_json(json.dumps(payload))
    round_tripped = EngagementBrief.model_validate_json(original.model_dump_json())

    assert round_tripped == original
    assert original.authentication is not None
    assert original.authentication.identities[0].flow.endpoint is not None
    assert original.authentication.identities[0].flow.endpoint.scope == "target"
    assert original.authentication.identities[1].flow.endpoint is not None
    assert original.authentication.identities[1].flow.endpoint.scope == "auth_dependency"
    assert (
        original.authentication.identities[0].flow.secret_refs["password"].key
        == "RAVAGE_CUSTOMER_A_PASSWORD"
    )


def test_secret_reference_rejects_inline_or_resolved_values() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SecretReference.model_validate(
            {
                "provider": "environment",
                "key": "RAVAGE_CUSTOMER_A_PASSWORD",
                "value": "inline-password",
            }
        )


def test_static_header_flow_requires_a_referenced_value() -> None:
    with pytest.raises(ValidationError, match="require static_header configuration"):
        AuthFlow(kind="static_header")

    flow = AuthFlow(
        kind="static_header",
        static_header=AuthStaticHeader(
            name="Authorization",
            value=SecretReference(key="RAVAGE_SERVICE_AUTHORIZATION"),
        ),
    )

    assert flow.static_header is not None
    assert flow.static_header.value.key == "RAVAGE_SERVICE_AUTHORIZATION"


@pytest.mark.parametrize("kind", ["form", "oauth2_oidc", "saml", "browser"])
def test_interactive_flows_require_an_endpoint(kind: str) -> None:
    with pytest.raises(ValidationError, match=rf"{kind} flows require an endpoint"):
        AuthFlow.model_validate({"kind": kind})


def test_bearer_and_static_header_flows_do_not_require_an_endpoint() -> None:
    bearer = AuthFlow(
        kind="bearer",
        secret_refs={"token": SecretReference(key="RAVAGE_SERVICE_TOKEN")},
    )
    static_header = AuthFlow(
        kind="static_header",
        static_header=AuthStaticHeader(
            name="X-Service-Key",
            value=SecretReference(key="RAVAGE_SERVICE_KEY"),
        ),
    )

    assert bearer.endpoint is None
    assert static_header.endpoint is None


@pytest.mark.parametrize(
    ("secret_refs", "error"),
    [
        ({}, "require exactly the token secret reference"),
        (
            {"access_token": {"key": "RAVAGE_SERVICE_TOKEN"}},
            "require exactly the token secret reference",
        ),
        (
            {
                "token": {"key": "RAVAGE_SERVICE_TOKEN"},
                "username": {"key": "RAVAGE_SERVICE_USERNAME"},
            },
            "require exactly the token secret reference",
        ),
    ],
)
def test_bearer_flow_requires_exactly_the_token_secret_reference(
    secret_refs: dict[str, object],
    error: str,
) -> None:
    with pytest.raises(ValidationError, match=error):
        AuthFlow.model_validate({"kind": "bearer", "secret_refs": secret_refs})


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        (
            {
                "endpoint": {
                    "url": "https://target.test/token",
                    "scope": "target",
                }
            },
            "endpoint configuration is not valid for bearer flows",
        ),
        (
            {"totp": {"secret": {"key": "RAVAGE_SERVICE_TOTP"}}},
            "totp configuration is not valid for bearer flows",
        ),
        (
            {
                "static_header": {
                    "name": "Authorization",
                    "value": {"key": "RAVAGE_SERVICE_AUTHORIZATION"},
                }
            },
            "static_header configuration is only valid for static_header flows",
        ),
    ],
)
def test_bearer_flow_rejects_unrelated_configuration(
    extra: dict[str, object],
    error: str,
) -> None:
    payload: dict[str, object] = {
        "kind": "bearer",
        "secret_refs": {"token": {"key": "RAVAGE_SERVICE_TOKEN"}},
        **extra,
    }

    with pytest.raises(ValidationError, match=error):
        AuthFlow.model_validate(payload)


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        (
            {
                "endpoint": {
                    "url": "https://target.test/header",
                    "scope": "target",
                }
            },
            "endpoint configuration is not valid for static_header flows",
        ),
        (
            {"secret_refs": {"token": {"key": "RAVAGE_SERVICE_TOKEN"}}},
            "secret_refs configuration is not valid for static_header flows",
        ),
        (
            {"totp": {"secret": {"key": "RAVAGE_SERVICE_TOTP"}}},
            "totp configuration is not valid for static_header flows",
        ),
    ],
)
def test_static_header_flow_rejects_unrelated_configuration(
    extra: dict[str, object],
    error: str,
) -> None:
    payload: dict[str, object] = {
        "kind": "static_header",
        "static_header": {
            "name": "X-Service-Key",
            "value": {"key": "RAVAGE_SERVICE_KEY"},
        },
        **extra,
    }

    with pytest.raises(ValidationError, match=error):
        AuthFlow.model_validate(payload)


def test_form_flow_permits_optional_totp_configuration() -> None:
    without_totp = AuthFlow(
        kind="form",
        endpoint=AuthEndpoint(url="https://target.test/login", scope="target"),
    )
    with_totp = AuthFlow(
        kind="form",
        endpoint=AuthEndpoint(url="https://target.test/login", scope="target"),
        totp=TotpConfig(secret=SecretReference(key="RAVAGE_CUSTOMER_A_TOTP")),
    )

    assert without_totp.totp is None
    assert with_totp.totp is not None


@pytest.mark.parametrize("kind", ["form", "bearer", "static_header"])
def test_operator_checkpoint_metadata_is_rejected_for_noninteractive_flows(kind: str) -> None:
    payload: dict[str, object] = {
        "kind": kind,
        "operator_checkpoint": {"kind": "captcha"},
    }
    if kind == "form":
        payload["endpoint"] = {"url": "https://target.test/login", "scope": "target"}
    if kind == "static_header":
        payload["static_header"] = {
            "name": "X-Service-Key",
            "value": {"key": "RAVAGE_SERVICE_KEY"},
        }

    with pytest.raises(ValidationError, match="operator_checkpoint configuration is not valid"):
        AuthFlow.model_validate(payload)


@pytest.mark.parametrize("kind", ["browser", "oauth2_oidc", "saml"])
def test_browser_and_sso_flows_accept_operator_checkpoints(kind: str) -> None:
    flow = AuthFlow.model_validate(
        {
            "kind": kind,
            "endpoint": {
                "url": "https://identity.test/login",
                "scope": "auth_dependency",
            },
            "operator_checkpoint": OperatorCheckpoint(kind="webauthn"),
        }
    )

    assert flow.operator_checkpoint is not None


def test_health_check_statuses_are_unique_valid_http_statuses() -> None:
    endpoint = AuthEndpoint(url="https://target.test/account", scope="target")

    with pytest.raises(ValidationError, match="success statuses must be unique"):
        AuthHealthCheck(endpoint=endpoint, success_statuses=[200, 200])

    for invalid_status in (99, 600):
        with pytest.raises(ValidationError):
            AuthHealthCheck(endpoint=endpoint, success_statuses=[invalid_status])


@pytest.mark.parametrize(
    "marker",
    [
        {"authenticated_marker": "Account settings"},
        {"unauthenticated_marker": "Sign in"},
        {
            "authenticated_marker": "Account settings",
            "unauthenticated_marker": "Sign in",
        },
    ],
)
def test_head_health_checks_reject_response_body_markers(marker: dict[str, str]) -> None:
    with pytest.raises(
        ValidationError,
        match="HEAD authentication health checks cannot use response-body markers",
    ):
        AuthHealthCheck.model_validate(
            {
                "endpoint": {
                    "url": "https://target.test/account",
                    "scope": "target",
                },
                "method": "HEAD",
                **marker,
            }
        )


def test_head_health_checks_can_use_status_only() -> None:
    health_check = AuthHealthCheck(
        endpoint=AuthEndpoint(url="https://target.test/account", scope="target"),
        method="HEAD",
        success_statuses=[200, 204],
    )

    assert health_check.method == "HEAD"


def test_authentication_aliases_and_roles_are_unique() -> None:
    identity = AuthIdentity(
        alias="customer_a",
        roles=["customer"],
        flow=AuthFlow(
            kind="form",
            endpoint=AuthEndpoint(url="https://target.test/login", scope="target"),
            secret_refs={
                "password": SecretReference(key="RAVAGE_CUSTOMER_A_PASSWORD"),
            },
            totp=TotpConfig(secret=SecretReference(key="RAVAGE_CUSTOMER_A_TOTP")),
        ),
        health_check=_health_check(),
    )

    with pytest.raises(ValidationError, match="aliases must be unique"):
        AuthenticationConfig(identities=[identity, identity])

    with pytest.raises(ValidationError, match="duplicate roles"):
        AuthIdentity(
            alias="customer_b",
            roles=["customer", "customer"],
            flow=identity.flow,
            health_check=_health_check(),
        )


def test_authentication_models_are_frozen_and_strict() -> None:
    secret_ref = SecretReference(key="RAVAGE_CUSTOMER_A_PASSWORD")

    with pytest.raises(ValidationError, match="Instance is frozen"):
        secret_ref.key = "RAVAGE_CHANGED_PASSWORD"

    with pytest.raises(ValidationError):
        AuthHealthCheck.model_validate(
            {
                "endpoint": AuthEndpoint(
                    url="https://target.test/account",
                    scope="target",
                ),
                "success_statuses": ["200"],
            }
        )


def test_authentication_models_compose_with_existing_brief_models() -> None:
    auth = AuthenticationConfig(
        identities=[
            AuthIdentity(
                alias="customer_a",
                roles=["customer"],
                flow=AuthFlow(
                    kind="bearer",
                    secret_refs={
                        "token": SecretReference(key="RAVAGE_CUSTOMER_A_TOKEN"),
                    },
                ),
                health_check=_health_check(),
            )
        ]
    )

    brief = EngagementBrief(
        engagement_id=ENGAGEMENT_ID,
        scope=Scope(in_scope=["https://target.test"]),
        roe=RulesOfEngagement(max_rps=10),
        objectives=["web_application_assessment"],
        budget=Budget(max_cost_usd=10.0, max_runtime_min=30),
        authentication=auth,
    )

    assert brief.authentication == auth
