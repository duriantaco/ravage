from __future__ import annotations

import json
import sys
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest
from ravage.control_plane.authorization_attestation import (
    AuthorizationReceiptAuthenticityError,
    AuthorizationReceiptKeyring,
    Ed25519AuthorizationReceiptSigner,
)
from ravage.control_plane.authorization_codec import (
    AuthorizationCodecError,
    decode_authorization_request,
    encode_authorization_request,
)
from ravage.control_plane.authorization_contracts import (
    AUTHORIZATION_REQUEST_SCHEMA,
    CommandAuthorizationRequest,
    canonical_command_payload_sha256,
)
from ravage.control_plane.authorization_state import (
    AuthoritativeResourceState,
    CommandReplayCapacityError,
    CommandReplayClaim,
    CommandReplayConflictError,
    CommandReplayInProgressError,
    CommandReplayReservation,
    ProcessLocalCommandReplayRegistry,
    ResourceLifecycleState,
    ResourceScope,
)
from ravage.control_plane.identity import (
    ActorContext,
    AuthenticationMethod,
    OrganizationId,
    TenantId,
    UserId,
)

NOW = datetime(2026, 8, 4, 2, 0, tzinfo=UTC)
SHA256_HEX_LENGTH = 64


def _request() -> CommandAuthorizationRequest:
    return CommandAuthorizationRequest(
        command_id="command:001",
        command_name="engagement.start",
        tenant_id=TenantId("tenant:001"),
        organization_id=OrganizationId("organization:001"),
        resource_kind="engagement",
        resource_id="engagement:001",
        payload_sha256=canonical_command_payload_sha256(
            {"engagement_id": "engagement:001", "operation": "engagement.start"}
        ),
    )


@pytest.mark.parametrize("identity_type", [TenantId, OrganizationId, UserId])
@pytest.mark.parametrize(
    "value",
    ["", "UPPERCASE", "-leading", "trailing_", "contains/slash", "tenant::empty"],
)
def test_identity_types_reject_ambiguous_values(
    identity_type: type[TenantId | OrganizationId | UserId],
    value: str,
) -> None:
    with pytest.raises(ValueError, match="must be"):
        identity_type(value)


def test_actor_context_is_policy_neutral_immutable_and_utc_normalized() -> None:
    singapore = timezone(timedelta(hours=8))
    actor = ActorContext(
        tenant_id=TenantId("tenant:001"),
        organization_id=OrganizationId("organization:001"),
        user_id=UserId("user:001"),
        roles=frozenset({"operator", "future_role"}),
        authentication_method=AuthenticationMethod.OIDC,
        authentication_event_id="authentication:001",
        authenticated_at=datetime(2026, 8, 4, 10, 0, tzinfo=singapore),
        expires_at=datetime(2026, 8, 4, 11, 0, tzinfo=singapore),
    )

    assert actor.authenticated_at == NOW
    assert actor.expires_at == NOW + timedelta(hours=1)
    with pytest.raises(FrozenInstanceError):
        actor.roles = frozenset()  # type: ignore[misc]


def test_request_contract_and_codec_round_trip_exact_canonical_bytes() -> None:
    request = _request()
    encoded = encode_authorization_request(request)

    assert request.schema_version == AUTHORIZATION_REQUEST_SCHEMA
    assert decode_authorization_request(encoded) == request
    assert encoded == json.dumps(
        request.to_json(),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


@pytest.mark.parametrize(
    "raw",
    [
        b'{"command_id":"one","command_id":"two"}',
        b'{ "unknown": true }',
        b'{"unknown":1.5}',
        b'{"unknown":NaN}',
    ],
)
def test_request_codec_rejects_ambiguous_or_noncanonical_json(raw: bytes) -> None:
    with pytest.raises(AuthorizationCodecError):
        decode_authorization_request(raw)


def test_canonical_payload_digest_is_order_independent_and_rejects_nan() -> None:
    assert canonical_command_payload_sha256({"b": 2, "a": 1}) == (
        canonical_command_payload_sha256({"a": 1, "b": 2})
    )
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_command_payload_sha256({"budget": float("nan")})


def test_receipt_attestation_keyring_enforces_signature_and_validity_window() -> None:
    signer = Ed25519AuthorizationReceiptSigner.generate(
        issuer_id="control-plane",
        key_id="authorization:001",
    )
    keyring = AuthorizationReceiptKeyring(
        (
            signer.verification_key(
                not_before=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=1),
            ),
        )
    )
    content = b"canonical-authorization-receipt"
    signature = signer.sign(content)

    keyring.verify(
        issuer_id=signer.issuer_id,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        evaluated_at=NOW,
        content=content,
        signature=signature,
    )
    with pytest.raises(AuthorizationReceiptAuthenticityError, match="invalid"):
        keyring.verify(
            issuer_id=signer.issuer_id,
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            evaluated_at=NOW,
            content=content + b"-tampered",
            signature=signature,
        )
    with pytest.raises(AuthorizationReceiptAuthenticityError, match="postdates"):
        keyring.verify(
            issuer_id=signer.issuer_id,
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            evaluated_at=NOW + timedelta(minutes=1),
            content=content,
            signature=signature,
        )


def test_authoritative_resource_digest_binds_complete_scope_and_state() -> None:
    state = AuthoritativeResourceState(
        scope=ResourceScope(
            tenant_id=TenantId("tenant:001"),
            organization_id=OrganizationId("organization:001"),
            resource_kind="engagement",
            resource_id="engagement:001",
        ),
        revision=7,
        lifecycle=ResourceLifecycleState.APPROVED,
        requested_by_user_id=UserId("requester:001"),
        approved_by_user_id=UserId("approver:001"),
    )

    assert len(state.state_sha256) == SHA256_HEX_LENGTH
    assert (
        state.state_sha256
        != AuthoritativeResourceState(
            scope=state.scope,
            revision=8,
            lifecycle=state.lifecycle,
            requested_by_user_id=state.requested_by_user_id,
            approved_by_user_id=state.approved_by_user_id,
        ).state_sha256
    )


def test_process_local_replay_registry_fences_conflicts_and_capacity() -> None:
    registry = ProcessLocalCommandReplayRegistry(max_entries=1)
    claim = CommandReplayClaim(
        tenant_id=TenantId("tenant:001"),
        organization_id=OrganizationId("organization:001"),
        command_id="command:001",
        request_sha256="a" * 64,
    )

    assert isinstance(registry.reserve(claim), CommandReplayReservation)
    with pytest.raises(CommandReplayInProgressError):
        registry.reserve(claim)
    with pytest.raises(CommandReplayConflictError):
        registry.reserve(
            CommandReplayClaim(
                tenant_id=claim.tenant_id,
                organization_id=claim.organization_id,
                command_id=claim.command_id,
                request_sha256="b" * 64,
            )
        )
    with pytest.raises(CommandReplayCapacityError):
        registry.reserve(
            CommandReplayClaim(
                tenant_id=claim.tenant_id,
                organization_id=claim.organization_id,
                command_id="command:002",
                request_sha256="c" * 64,
            )
        )


def test_importing_contract_modules_never_loads_private_platform_policy() -> None:
    assert "ravage_platform.policy" not in sys.modules
    assert "ravage.control_plane.enterprise_policy" not in sys.modules
