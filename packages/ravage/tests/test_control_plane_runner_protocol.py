from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ravage.control_plane.runner_protocol import (
    AuthenticationError,
    AuthorizationLineage,
    CanonicalPayload,
    DispatchAuthorizationError,
    Ed25519Signer,
    Heartbeat,
    InMemoryHeartbeatRegistry,
    InMemoryReplayProtector,
    InMemoryResultReceiptRegistry,
    JobIdentity,
    JobRequest,
    JobResponse,
    JobStatus,
    LeaseFence,
    LeaseFenceError,
    MessageSigner,
    ProtocolCodec,
    ProtocolError,
    RegistryCapacityError,
    ReplayClaim,
    ReplayError,
    ResultConflictError,
    ResultReceipt,
    VerificationKeyring,
    VerificationKeyStatus,
    VerifiedMessage,
    WireMessage,
    generate_nonce,
)

_NOW_MS = 1_000_000
_DIGEST = hashlib.sha256(b"policy").hexdigest()
_DEPLOYMENT_ID = "deployment-1"
_ENVIRONMENT = "production"
_ORGANIZATION_ID = "org-1"
_RUNNER_RECIPIENT = "runner-1"
_RUNNER_AUDIENCE = "ravage-runner"
_CONTROL_PLANE_RECIPIENT = "control-plane"
_CONTROL_PLANE_AUDIENCE = "ravage-control-plane"


def _nonce(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:32]


def _job(
    *,
    tenant_id: str = "tenant-1",
    organization_id: str = _ORGANIZATION_ID,
    job_id: str = "job-1",
) -> JobIdentity:
    return JobIdentity(
        tenant_id=tenant_id,
        organization_id=organization_id,
        engagement_id="engagement-1",
        job_id=job_id,
    )


def _authorization(
    *,
    authorized_at_ms: int = _NOW_MS - 60_000,
    expires_at_ms: int = _NOW_MS + 60_000,
) -> AuthorizationLineage:
    return AuthorizationLineage(
        receipt_digest=hashlib.sha256(b"authorization-receipt").hexdigest(),
        policy_digest=_DIGEST,
        actor_digest=hashlib.sha256(b"authorization-actor").hexdigest(),
        authorized_at_ms=authorized_at_ms,
        expires_at_ms=expires_at_ms,
    )


def _lease(
    *,
    job: JobIdentity | None = None,
    runner_id: str = "runner-1",
    epoch: int = 3,
    lease_id: str = "lease-3",
    expires_at_ms: int = _NOW_MS + 120_000,
) -> LeaseFence:
    return LeaseFence(
        job=job or _job(),
        runner_id=runner_id,
        lease_id=lease_id,
        epoch=epoch,
        expires_at_ms=expires_at_ms,
    )


def _request(
    *,
    message_id: str = "request-1",
    job: JobIdentity | None = None,
    lease: LeaseFence | None = None,
) -> JobRequest:
    identity = job or _job()
    return JobRequest(
        message_id=message_id,
        job=identity,
        runner_id="runner-1",
        lease=lease or _lease(job=identity),
        policy_digest=_DIGEST,
        authorization=_authorization(),
        workload=CanonicalPayload.from_mapping(
            {"objective": "validate scope", "attempt": 1, "flags": [True, None]}
        ),
    )


def _response(
    *,
    message_id: str = "response-1",
    request: JobRequest | None = None,
    result: CanonicalPayload | None = None,
) -> JobResponse:
    job_request = request or _request()
    return JobResponse(
        message_id=message_id,
        request_message_id=job_request.message_id,
        request_digest=job_request.request_digest,
        job=job_request.job,
        runner_id=job_request.runner_id,
        lease=job_request.lease,
        status=JobStatus.SUCCEEDED,
        started_at_ms=_NOW_MS + 1_000,
        completed_at_ms=_NOW_MS + 2_000,
        result=result or CanonicalPayload.from_mapping({"finding_count": 2}),
    )


def _signers() -> tuple[Ed25519Signer, Ed25519Signer]:
    control_plane = Ed25519Signer.generate(
        key_id="cp-key-1",
        tenant_id="tenant-1",
        organization_id=_ORGANIZATION_ID,
        sender_id="control-plane",
        allowed_message_types={JobRequest.MESSAGE_TYPE, ResultReceipt.MESSAGE_TYPE},
    )
    runner = Ed25519Signer.generate(
        key_id="runner-key-1",
        tenant_id="tenant-1",
        organization_id=_ORGANIZATION_ID,
        sender_id="runner-1",
        allowed_message_types={Heartbeat.MESSAGE_TYPE, JobResponse.MESSAGE_TYPE},
    )
    return control_plane, runner


def _codec(
    control_plane: Ed25519Signer,
    runner: Ed25519Signer,
    *,
    replay: InMemoryReplayProtector | None = None,
) -> ProtocolCodec:
    return ProtocolCodec(
        keyring=VerificationKeyring([control_plane.verification_key(), runner.verification_key()]),
        replay_protector=replay or InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )


def _encode(  # noqa: PLR0913 - test helper mirrors the explicit wire boundary
    codec: ProtocolCodec,
    message: WireMessage,
    *,
    signer: MessageSigner,
    nonce: str,
    issued_at_ms: int,
    expires_at_ms: int,
    recipient_id: str = _RUNNER_RECIPIENT,
    audience: str = _RUNNER_AUDIENCE,
) -> bytes:
    return codec.encode(
        message,
        signer=signer,
        nonce=nonce,
        recipient_id=recipient_id,
        audience=audience,
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
    )


def _decode(  # noqa: PLR0913 - test helper mirrors the explicit wire boundary
    codec: ProtocolCodec,
    raw: bytes,
    *,
    expected_tenant_id: str,
    expected_organization_id: str = _ORGANIZATION_ID,
    now_ms: int,
    expected_recipient_id: str = _RUNNER_RECIPIENT,
    expected_audience: str = _RUNNER_AUDIENCE,
    expected_sender_id: str = "control-plane",
    expected_message_type: str | None = None,
) -> WireMessage:
    return codec.decode_ephemeral(
        raw,
        expected_tenant_id=expected_tenant_id,
        expected_organization_id=expected_organization_id,
        expected_recipient_id=expected_recipient_id,
        expected_audience=expected_audience,
        now_ms=now_ms,
        expected_sender_id=expected_sender_id,
        expected_message_type=expected_message_type,
    )


def _authenticate(  # noqa: PLR0913 - test helper mirrors the explicit wire boundary
    codec: ProtocolCodec,
    raw: bytes,
    *,
    expected_tenant_id: str,
    expected_organization_id: str = _ORGANIZATION_ID,
    now_ms: int,
    expected_recipient_id: str = _RUNNER_RECIPIENT,
    expected_audience: str = _RUNNER_AUDIENCE,
    expected_sender_id: str = "control-plane",
) -> VerifiedMessage:
    return codec.authenticate(
        raw,
        expected_tenant_id=expected_tenant_id,
        expected_organization_id=expected_organization_id,
        expected_recipient_id=expected_recipient_id,
        expected_audience=expected_audience,
        expected_sender_id=expected_sender_id,
        now_ms=now_ms,
    )


def _sign_unchecked(  # noqa: PLR0913 - adversarial helper builds the full envelope
    message: WireMessage,
    *,
    signer: Ed25519Signer,
    nonce: str,
    recipient_id: str,
    audience: str,
    issued_at_ms: int = _NOW_MS,
    expires_at_ms: int = _NOW_MS + 60_000,
) -> bytes:
    unsigned = {
        "algorithm": "Ed25519",
        "audience": audience,
        "body": message.to_wire(),
        "deployment_id": _DEPLOYMENT_ID,
        "environment": _ENVIRONMENT,
        "expires_at_ms": expires_at_ms,
        "issued_at_ms": issued_at_ms,
        "key_id": signer.key_id,
        "message_id": message.message_id,
        "message_type": message.MESSAGE_TYPE,
        "nonce": nonce,
        "organization_id": message.organization_scope(),
        "protocol_version": 1,
        "recipient_id": recipient_id,
        "sender_id": signer.sender_id,
        "tenant_id": message.tenant_scope(),
    }
    canonical = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = signer.sign(
        b"ravage.outbound-runner-envelope.v1\x00" + canonical,
        message_type=message.MESSAGE_TYPE,
        tenant_id=message.tenant_scope(),
        organization_id=message.organization_scope(),
    )
    envelope = {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }
    return json.dumps(
        envelope,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


@pytest.mark.parametrize("kind", ["request", "response", "heartbeat", "receipt"])
def test_signed_protocol_messages_round_trip_canonically(kind: str) -> None:
    control_plane, runner = _signers()
    request = _request()
    response = _response(request=request)
    receipt = InMemoryResultReceiptRegistry().accept(
        response,
        authoritative_request=request,
        authoritative_lease=request.lease,
        accepted_at_ms=_NOW_MS + 3_000,
    )
    messages = {
        "request": (
            request,
            control_plane,
            "control-plane",
            _RUNNER_RECIPIENT,
            _RUNNER_AUDIENCE,
        ),
        "response": (
            response,
            runner,
            "runner-1",
            _CONTROL_PLANE_RECIPIENT,
            _CONTROL_PLANE_AUDIENCE,
        ),
        "heartbeat": (
            Heartbeat(
                message_id="heartbeat-1",
                tenant_id="tenant-1",
                organization_id=_ORGANIZATION_ID,
                runner_id="runner-1",
                sequence=8,
                observed_at_ms=_NOW_MS,
                active_leases=(request.lease,),
            ),
            runner,
            "runner-1",
            _CONTROL_PLANE_RECIPIENT,
            _CONTROL_PLANE_AUDIENCE,
        ),
        "receipt": (
            receipt,
            control_plane,
            "control-plane",
            _RUNNER_RECIPIENT,
            _RUNNER_AUDIENCE,
        ),
    }
    message, signer, sender_id, recipient_id, audience = messages[kind]
    codec = _codec(control_plane, runner)

    raw = _encode(
        codec,
        message,
        signer=signer,
        nonce=_nonce(f"nonce-{kind}"),
        recipient_id=recipient_id,
        audience=audience,
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )

    assert (
        raw
        == json.dumps(
            json.loads(raw),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    assert (
        codec.decode_ephemeral(
            raw,
            expected_tenant_id="tenant-1",
            expected_organization_id=_ORGANIZATION_ID,
            expected_recipient_id=recipient_id,
            expected_audience=audience,
            expected_sender_id=sender_id,
            expected_message_type=message.MESSAGE_TYPE,
            now_ms=_NOW_MS,
        )
        == message
    )


def test_signature_and_canonical_envelope_match_golden_vector() -> None:
    signer = Ed25519Signer(
        key_id="golden-key-1",
        tenant_id="tenant-1",
        organization_id=_ORGANIZATION_ID,
        sender_id="control-plane",
        private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
        allowed_message_types={JobRequest.MESSAGE_TYPE},
    )
    codec = ProtocolCodec(
        keyring=VerificationKeyring([signer.verification_key()]),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    raw = _encode(
        codec,
        _request(message_id="request-golden"),
        signer=signer,
        nonce="00112233445566778899aabbccddeeff",
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )
    document = json.loads(raw)

    assert document["signature"] == (
        "GaQ-c_GnmpEinaGJF_-cFXfVQrtk31jNC_zS65ldetjWFbtBRz9_EhXhnUIVxe3QSJZi_OMYGgOcvMAio2fjDA"
    )
    assert hashlib.sha256(raw).hexdigest() == (
        "07c28f3ac434ac56648be95571bd05d14b7361f823fd5ef8f1787f4a95363b75"
    )
    assert (
        _authenticate(
            codec,
            raw,
            expected_tenant_id="tenant-1",
            now_ms=_NOW_MS,
        ).message.message_id
        == "request-golden"
    )


def test_payload_and_job_identity_are_immutable_snapshots() -> None:
    source = {"nested": {"items": [1, 2]}}
    payload = CanonicalPayload.from_mapping(source)
    identity = _job()
    source["nested"]["items"].append(3)

    assert payload.to_mapping() == {"nested": {"items": [1, 2]}}
    copy = payload.to_mapping()
    copy["changed"] = True
    assert "changed" not in payload.to_mapping()
    with pytest.raises(FrozenInstanceError):
        identity.job_id = "another"  # type: ignore[misc]


@pytest.mark.parametrize(
    "payload",
    [
        {"float": 1.25},
        {"too_large": 1 << 64},
        {"set": {"not-json"}},
    ],
)
def test_payload_rejects_ambiguous_or_unbounded_json_types(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ProtocolError):
        CanonicalPayload.from_mapping(payload)


def test_payload_digest_is_checked_on_decode() -> None:
    payload = CanonicalPayload.from_mapping({"ok": True})

    with pytest.raises(ProtocolError, match="digest mismatch"):
        CanonicalPayload.from_wire(payload.to_mapping(), "0" * 64)


def test_nonce_requires_full_128_bit_canonical_encoding() -> None:
    generated = {generate_nonce() for _ in range(64)}
    assert len(generated) == 64  # noqa: PLR2004
    assert all(len(value) == 32 and value == value.lower() for value in generated)  # noqa: PLR2004
    control_plane, runner = _signers()

    with pytest.raises(ProtocolError, match="128 bits"):
        _encode(
            _codec(control_plane, runner),
            _request(),
            signer=control_plane,
            nonce="short",
            issued_at_ms=_NOW_MS,
            expires_at_ms=_NOW_MS + 60_000,
        )


def test_tampering_and_route_identity_mismatches_fail_authentication() -> None:
    control_plane, runner = _signers()
    codec = _codec(control_plane, runner)
    raw = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce("nonce-auth-1"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )
    document = json.loads(raw)
    document["body"]["workload"]["attempt"] = 2
    tampered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(AuthenticationError, match="signature"):
        _decode(codec, tampered, expected_tenant_id="tenant-1", now_ms=_NOW_MS)
    with pytest.raises(AuthenticationError, match="tenant"):
        _decode(codec, raw, expected_tenant_id="tenant-2", now_ms=_NOW_MS)
    with pytest.raises(AuthenticationError, match="sender"):
        _decode(
            codec,
            raw,
            expected_tenant_id="tenant-1",
            expected_sender_id="runner-1",
            now_ms=_NOW_MS,
        )


def test_same_tenant_different_organization_is_rejected_at_every_boundary() -> None:
    control_plane, runner = _signers()
    codec = _codec(control_plane, runner)
    request = _request()
    raw = _encode(
        codec,
        request,
        signer=control_plane,
        nonce=_nonce("organization-route"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )

    with pytest.raises(AuthenticationError, match="organization"):
        _authenticate(
            codec,
            raw,
            expected_tenant_id="tenant-1",
            expected_organization_id="org-2",
            now_ms=_NOW_MS,
        )

    other_job = _job(organization_id="org-2")
    with pytest.raises(AuthenticationError, match="organization"):
        _encode(
            codec,
            _request(job=other_job),
            signer=control_plane,
            nonce=_nonce("organization-signer"),
            issued_at_ms=_NOW_MS,
            expires_at_ms=_NOW_MS + 60_000,
        )

    other_signer = Ed25519Signer.generate(
        key_id="cp-org-2-key",
        tenant_id="tenant-1",
        organization_id="org-2",
        sender_id="control-plane",
        allowed_message_types={JobRequest.MESSAGE_TYPE},
    )
    org_codec = ProtocolCodec(
        keyring=VerificationKeyring(
            [replace(other_signer.verification_key(), organization_id="org-1")]
        ),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    other_raw = ProtocolCodec(
        keyring=VerificationKeyring([other_signer.verification_key()]),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    ).encode(
        _request(job=other_job),
        signer=other_signer,
        nonce=_nonce("organization-key"),
        recipient_id=_RUNNER_RECIPIENT,
        audience=_RUNNER_AUDIENCE,
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )
    with pytest.raises(AuthenticationError, match="key identity"):
        _authenticate(
            org_codec,
            other_raw,
            expected_tenant_id="tenant-1",
            expected_organization_id="org-2",
            now_ms=_NOW_MS,
        )


@pytest.mark.parametrize("kind", ["heartbeat", "response"])
def test_runner_key_cannot_sign_another_runners_body_identity(kind: str) -> None:
    control_plane, runner_one = _signers()
    runner_two_job = _job(job_id="job-runner-2")
    runner_two_lease = _lease(job=runner_two_job, runner_id="runner-2")
    runner_two_request = JobRequest(
        message_id="request-runner-2",
        job=runner_two_job,
        runner_id="runner-2",
        lease=runner_two_lease,
        policy_digest=_DIGEST,
        authorization=_authorization(),
        workload=CanonicalPayload.from_mapping({"work": "runner-2"}),
    )
    messages: dict[str, WireMessage] = {
        "heartbeat": Heartbeat(
            message_id="heartbeat-runner-2",
            tenant_id="tenant-1",
            organization_id=_ORGANIZATION_ID,
            runner_id="runner-2",
            sequence=1,
            observed_at_ms=_NOW_MS,
        ),
        "response": JobResponse(
            message_id="response-runner-2",
            request_message_id=runner_two_request.message_id,
            request_digest=runner_two_request.request_digest,
            job=runner_two_job,
            runner_id="runner-2",
            lease=runner_two_lease,
            status=JobStatus.SUCCEEDED,
            started_at_ms=_NOW_MS,
            completed_at_ms=_NOW_MS + 1,
            result=CanonicalPayload.from_mapping({"ok": True}),
        ),
    }
    message = messages[kind]
    codec = _codec(control_plane, runner_one)

    with pytest.raises(AuthenticationError, match="signing identity"):
        _encode(
            codec,
            message,
            signer=runner_one,
            nonce=_nonce(f"encoder-runner-impersonation-{kind}"),
            recipient_id=_CONTROL_PLANE_RECIPIENT,
            audience=_CONTROL_PLANE_AUDIENCE,
            issued_at_ms=_NOW_MS,
            expires_at_ms=_NOW_MS + 60_000,
        )

    forged_wire = _sign_unchecked(
        message,
        signer=runner_one,
        nonce=_nonce(f"decoder-runner-impersonation-{kind}"),
        recipient_id=_CONTROL_PLANE_RECIPIENT,
        audience=_CONTROL_PLANE_AUDIENCE,
    )
    with pytest.raises(AuthenticationError, match="body principal"):
        codec.authenticate(
            forged_wire,
            expected_tenant_id="tenant-1",
            expected_organization_id=_ORGANIZATION_ID,
            expected_recipient_id=_CONTROL_PLANE_RECIPIENT,
            expected_audience=_CONTROL_PLANE_AUDIENCE,
            expected_sender_id="runner-1",
            now_ms=_NOW_MS,
        )


def test_recipient_audience_deployment_and_environment_are_enforced() -> None:
    control_plane, runner = _signers()
    codec = _codec(control_plane, runner)
    raw = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce("route-bindings"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )

    with pytest.raises(AuthenticationError, match="recipient"):
        codec.authenticate(
            raw,
            expected_tenant_id="tenant-1",
            expected_organization_id=_ORGANIZATION_ID,
            expected_recipient_id="runner-2",
            expected_audience=_RUNNER_AUDIENCE,
            expected_sender_id="control-plane",
            now_ms=_NOW_MS,
        )
    with pytest.raises(AuthenticationError, match="audience"):
        codec.authenticate(
            raw,
            expected_tenant_id="tenant-1",
            expected_organization_id=_ORGANIZATION_ID,
            expected_recipient_id=_RUNNER_RECIPIENT,
            expected_audience="another-service",
            expected_sender_id="control-plane",
            now_ms=_NOW_MS,
        )
    for deployment_id, environment, reason in (
        ("deployment-2", _ENVIRONMENT, "deployment"),
        (_DEPLOYMENT_ID, "staging", "environment"),
    ):
        other_boundary = ProtocolCodec(
            keyring=VerificationKeyring(
                [control_plane.verification_key(), runner.verification_key()]
            ),
            replay_protector=InMemoryReplayProtector(),
            deployment_id=deployment_id,
            environment=environment,
        )
        with pytest.raises(AuthenticationError, match=reason):
            other_boundary.authenticate(
                raw,
                expected_tenant_id="tenant-1",
                expected_organization_id=_ORGANIZATION_ID,
                expected_recipient_id=_RUNNER_RECIPIENT,
                expected_audience=_RUNNER_AUDIENCE,
                expected_sender_id="control-plane",
                now_ms=_NOW_MS,
            )

    with pytest.raises(AuthenticationError, match="body recipient"):
        _encode(
            codec,
            _request(),
            signer=control_plane,
            nonce=_nonce("wrong-body-recipient"),
            recipient_id="runner-2",
            audience=_RUNNER_AUDIENCE,
            issued_at_ms=_NOW_MS,
            expires_at_ms=_NOW_MS + 60_000,
        )


def test_key_purpose_prevents_runner_from_signing_control_plane_request() -> None:
    control_plane, runner = _signers()
    codec = _codec(control_plane, runner)

    with pytest.raises(AuthenticationError, match="message type"):
        _encode(
            codec,
            _request(),
            signer=runner,
            nonce=_nonce("nonce-wrong-purpose"),
            issued_at_ms=_NOW_MS,
            expires_at_ms=_NOW_MS + 60_000,
        )


def test_key_ids_support_rotation_and_reject_ambiguous_or_unknown_keys() -> None:
    old_key, runner = _signers()
    new_key = Ed25519Signer.generate(
        key_id="cp-key-2",
        tenant_id="tenant-1",
        organization_id=_ORGANIZATION_ID,
        sender_id="control-plane",
        allowed_message_types={JobRequest.MESSAGE_TYPE},
    )
    codec = ProtocolCodec(
        keyring=VerificationKeyring(
            [old_key.verification_key(), new_key.verification_key(), runner.verification_key()]
        ),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    for sequence, signer in enumerate((old_key, new_key), start=1):
        raw = _encode(
            codec,
            _request(message_id=f"request-rotation-{sequence}"),
            signer=signer,
            nonce=_nonce(f"nonce-rotation-{sequence}"),
            issued_at_ms=_NOW_MS,
            expires_at_ms=_NOW_MS + 60_000,
        )
        assert _decode(codec, raw, expected_tenant_id="tenant-1", now_ms=_NOW_MS)

    duplicate_id_key = Ed25519Signer.generate(
        key_id=old_key.key_id,
        tenant_id="tenant-1",
        organization_id=_ORGANIZATION_ID,
        sender_id="control-plane",
        allowed_message_types={JobRequest.MESSAGE_TYPE},
    )
    with pytest.raises(ProtocolError, match="duplicate verification key ID"):
        VerificationKeyring([old_key.verification_key(), duplicate_id_key.verification_key()])

    unknown_key_codec = ProtocolCodec(
        keyring=VerificationKeyring([runner.verification_key()]),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    raw = _encode(
        codec,
        _request(message_id="request-unknown-key"),
        signer=old_key,
        nonce=_nonce("nonce-unknown-key"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )
    with pytest.raises(AuthenticationError, match="unknown verification key"):
        _decode(unknown_key_codec, raw, expected_tenant_id="tenant-1", now_ms=_NOW_MS)


def test_verification_key_validity_is_checked_against_signed_issue_time() -> None:
    control_plane, runner = _signers()
    codec = ProtocolCodec(
        keyring=VerificationKeyring(
            [
                control_plane.verification_key(not_before_ms=_NOW_MS + 1),
                runner.verification_key(),
            ]
        ),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    raw = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce("nonce-before-key"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )

    with pytest.raises(AuthenticationError, match="predates"):
        _decode(codec, raw, expected_tenant_id="tenant-1", now_ms=_NOW_MS)


@pytest.mark.parametrize(
    "status",
    [VerificationKeyStatus.REVOKED, VerificationKeyStatus.COMPROMISED],
)
def test_revoked_or_compromised_key_is_rejected_immediately(
    status: VerificationKeyStatus,
) -> None:
    control_plane, _runner = _signers()
    codec = ProtocolCodec(
        keyring=VerificationKeyring(
            [
                control_plane.verification_key(
                    status=status,
                    status_changed_at_ms=_NOW_MS,
                )
            ]
        ),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    raw = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce(f"key-{status.value}"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )

    with pytest.raises(AuthenticationError, match=status.value):
        _decode(codec, raw, expected_tenant_id="tenant-1", now_ms=_NOW_MS)


def test_retired_key_only_verifies_pre_retirement_messages_during_overlap() -> None:
    control_plane, _runner = _signers()
    retired_at_ms = _NOW_MS + 1_000
    verification_expires_at_ms = _NOW_MS + 10_000
    codec = ProtocolCodec(
        keyring=VerificationKeyring(
            [
                control_plane.verification_key(
                    expires_at_ms=verification_expires_at_ms,
                    status=VerificationKeyStatus.RETIRED,
                    status_changed_at_ms=retired_at_ms,
                )
            ]
        ),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    before = _encode(
        codec,
        _request(message_id="request-before-retirement"),
        signer=control_plane,
        nonce=_nonce("before-retirement"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 5_000,
    )
    after = _encode(
        codec,
        _request(message_id="request-after-retirement"),
        signer=control_plane,
        nonce=_nonce("after-retirement"),
        issued_at_ms=retired_at_ms,
        expires_at_ms=retired_at_ms + 5_000,
    )

    assert (
        _decode(
            codec,
            before,
            expected_tenant_id="tenant-1",
            now_ms=retired_at_ms + 1,
        ).message_id
        == "request-before-retirement"
    )
    with pytest.raises(AuthenticationError, match=r"after.*retirement"):
        _decode(
            codec,
            after,
            expected_tenant_id="tenant-1",
            now_ms=retired_at_ms + 1,
        )


def test_verification_key_expiry_uses_authoritative_current_time() -> None:
    control_plane, _runner = _signers()
    key_expires_at_ms = _NOW_MS + 1_000
    codec = ProtocolCodec(
        keyring=VerificationKeyring(
            [control_plane.verification_key(expires_at_ms=key_expires_at_ms)]
        ),
        replay_protector=InMemoryReplayProtector(),
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
    )
    raw = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce("key-current-expiry"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )

    with pytest.raises(AuthenticationError, match="key has expired"):
        _decode(
            codec,
            raw,
            expected_tenant_id="tenant-1",
            now_ms=key_expires_at_ms,
        )


def test_replay_protection_rejects_message_id_and_nonce_reuse() -> None:
    control_plane, runner = _signers()
    codec = _codec(control_plane, runner)
    first = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce("nonce-replay-1"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )
    _decode(codec, first, expected_tenant_id="tenant-1", now_ms=_NOW_MS)

    with pytest.raises(ReplayError, match="message ID"):
        _decode(codec, first, expected_tenant_id="tenant-1", now_ms=_NOW_MS)

    second = _encode(
        codec,
        _request(message_id="request-2"),
        signer=control_plane,
        nonce=_nonce("nonce-replay-1"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )
    with pytest.raises(ReplayError, match="nonce"):
        _decode(codec, second, expected_tenant_id="tenant-1", now_ms=_NOW_MS)


def test_authentication_can_defer_replay_claim_to_a_durable_transaction() -> None:
    control_plane, runner = _signers()
    replay = InMemoryReplayProtector()
    codec = _codec(control_plane, runner, replay=replay)
    raw = _encode(
        codec,
        _request(message_id="request-transactional"),
        signer=control_plane,
        nonce=_nonce("nonce-transactional"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )

    verified = _authenticate(codec, raw, expected_tenant_id="tenant-1", now_ms=_NOW_MS)
    assert _authenticate(codec, raw, expected_tenant_id="tenant-1", now_ms=_NOW_MS) == verified
    replay.accept(verified.replay_claim, now_ms=_NOW_MS)
    with pytest.raises(ReplayError):
        _decode(codec, raw, expected_tenant_id="tenant-1", now_ms=_NOW_MS)


def test_replay_registry_fails_closed_at_capacity_and_purges_expired_entries() -> None:
    replay = InMemoryReplayProtector(max_entries=1)
    replay.accept(
        ReplayClaim(
            deployment_id=_DEPLOYMENT_ID,
            environment=_ENVIRONMENT,
            tenant_id="tenant-1",
            organization_id=_ORGANIZATION_ID,
            sender_id="runner-1",
            recipient_id=_CONTROL_PLANE_RECIPIENT,
            audience=_CONTROL_PLANE_AUDIENCE,
            message_id="message-1",
            nonce=_nonce("nonce-1"),
            expires_at_ms=_NOW_MS + 1,
        ),
        now_ms=_NOW_MS,
    )
    with pytest.raises(RegistryCapacityError):
        replay.accept(
            ReplayClaim(
                deployment_id=_DEPLOYMENT_ID,
                environment=_ENVIRONMENT,
                tenant_id="tenant-1",
                organization_id=_ORGANIZATION_ID,
                sender_id="runner-1",
                recipient_id=_CONTROL_PLANE_RECIPIENT,
                audience=_CONTROL_PLANE_AUDIENCE,
                message_id="message-2",
                nonce=_nonce("nonce-2"),
                expires_at_ms=_NOW_MS + 2,
            ),
            now_ms=_NOW_MS,
        )

    replay.accept(
        ReplayClaim(
            deployment_id=_DEPLOYMENT_ID,
            environment=_ENVIRONMENT,
            tenant_id="tenant-1",
            organization_id=_ORGANIZATION_ID,
            sender_id="runner-1",
            recipient_id=_CONTROL_PLANE_RECIPIENT,
            audience=_CONTROL_PLANE_AUDIENCE,
            message_id="message-2",
            nonce=_nonce("nonce-2"),
            expires_at_ms=_NOW_MS + 3,
        ),
        now_ms=_NOW_MS + 1,
    )


def test_replay_identity_is_namespaced_by_organization() -> None:
    replay = InMemoryReplayProtector()
    base = ReplayClaim(
        deployment_id=_DEPLOYMENT_ID,
        environment=_ENVIRONMENT,
        tenant_id="tenant-1",
        organization_id="org-1",
        sender_id="runner-1",
        recipient_id=_CONTROL_PLANE_RECIPIENT,
        audience=_CONTROL_PLANE_AUDIENCE,
        message_id="organization-scoped-message",
        nonce=_nonce("organization-scoped-nonce"),
        expires_at_ms=_NOW_MS + 60_000,
    )

    replay.accept(base, now_ms=_NOW_MS)
    replay.accept(replace(base, organization_id="org-2"), now_ms=_NOW_MS)


def test_heartbeat_sequence_rejects_reordering_with_fresh_message_ids() -> None:
    registry = InMemoryHeartbeatRegistry()
    newest = Heartbeat(
        message_id="heartbeat-9",
        tenant_id="tenant-1",
        organization_id=_ORGANIZATION_ID,
        runner_id="runner-1",
        sequence=9,
        observed_at_ms=_NOW_MS,
    )
    registry.accept(newest)

    with pytest.raises(ReplayError, match="sequence"):
        registry.accept(replace(newest, message_id="heartbeat-replay", sequence=9))
    with pytest.raises(ReplayError, match="sequence"):
        registry.accept(replace(newest, message_id="heartbeat-old", sequence=8))
    expected_sequence = 10
    assert (
        registry.accept(
            replace(newest, message_id="heartbeat-10", sequence=expected_sequence)
        ).sequence
        == expected_sequence
    )


def test_expired_future_and_excessive_ttl_messages_are_rejected() -> None:
    control_plane, runner = _signers()
    codec = _codec(control_plane, runner)
    expired = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce("nonce-expired"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 1,
    )
    with pytest.raises(AuthenticationError, match="expired"):
        _decode(codec, expired, expected_tenant_id="tenant-1", now_ms=_NOW_MS + 1)

    future = _encode(
        codec,
        _request(message_id="request-future"),
        signer=control_plane,
        nonce=_nonce("nonce-future"),
        issued_at_ms=_NOW_MS + 30_001,
        expires_at_ms=_NOW_MS + 60_000,
    )
    with pytest.raises(AuthenticationError, match="future"):
        _decode(codec, future, expected_tenant_id="tenant-1", now_ms=_NOW_MS)

    with pytest.raises(ProtocolError, match="maximum TTL"):
        _encode(
            codec,
            _request(message_id="request-long"),
            signer=control_plane,
            nonce=_nonce("nonce-long"),
            issued_at_ms=_NOW_MS,
            expires_at_ms=_NOW_MS + 300_001,
        )


def test_wire_decoder_rejects_duplicate_keys_and_noncanonical_json() -> None:
    control_plane, runner = _signers()
    codec = _codec(control_plane, runner)
    with pytest.raises(ProtocolError, match="duplicate JSON key"):
        _decode(
            codec,
            b'{"protocol_version":1,"protocol_version":1}',
            expected_tenant_id="tenant-1",
            now_ms=_NOW_MS,
        )

    raw = _encode(
        codec,
        _request(),
        signer=control_plane,
        nonce=_nonce("nonce-canonical"),
        issued_at_ms=_NOW_MS,
        expires_at_ms=_NOW_MS + 60_000,
    )
    with pytest.raises(ProtocolError, match="canonical"):
        _decode(codec, raw + b"\n", expected_tenant_id="tenant-1", now_ms=_NOW_MS)


@pytest.mark.parametrize(
    "malformed",
    [
        b'{"x":' + (b"[" * 20_000) + b"0" + (b"]" * 20_000) + b"}",
        b'{"x":' + (b"9" * 5_000) + b"}",
        b'{"x":1.5}',
        json.dumps({"x": [0] * 5_000}, separators=(",", ":")).encode(),
    ],
)
def test_wire_decoder_normalizes_global_resource_bound_failures(
    malformed: bytes,
) -> None:
    control_plane, runner = _signers()

    with pytest.raises(ProtocolError):
        _decode(
            _codec(control_plane, runner),
            malformed,
            expected_tenant_id="tenant-1",
            now_ms=_NOW_MS,
        )


def test_heartbeat_active_lease_count_is_bounded() -> None:
    leases = tuple(_lease(job=_job(job_id=f"job-{index:03d}")) for index in range(257))

    with pytest.raises(ProtocolError, match="active leases"):
        Heartbeat(
            message_id="heartbeat-too-many-leases",
            tenant_id="tenant-1",
            organization_id=_ORGANIZATION_ID,
            runner_id="runner-1",
            sequence=1,
            observed_at_ms=_NOW_MS,
            active_leases=leases,
        )


@pytest.mark.parametrize(
    ("presented", "reason"),
    [
        (_lease(epoch=2, lease_id="lease-2"), "epoch"),
        (_lease(lease_id="another-lease"), "lease ID"),
        (_lease(runner_id="runner-2"), "runner"),
        (_lease(job=_job(job_id="job-2")), "job identity"),
        (_lease(expires_at_ms=_NOW_MS + 119_999), "expiry"),
    ],
)
def test_lease_fence_rejects_stale_or_rebound_presentations(
    presented: LeaseFence,
    reason: str,
) -> None:
    with pytest.raises(LeaseFenceError, match=reason):
        _lease().assert_allows(presented, now_ms=_NOW_MS)


def test_lease_fence_rejects_expiration_at_exact_boundary() -> None:
    lease = _lease(expires_at_ms=_NOW_MS)

    with pytest.raises(LeaseFenceError, match="expired"):
        lease.assert_allows(lease, now_ms=_NOW_MS)


def test_job_request_requires_current_lease_and_authorization_before_dispatch() -> None:
    request = _request()
    request.assert_dispatchable(authoritative_lease=request.lease, now_ms=_NOW_MS)

    with pytest.raises(LeaseFenceError, match="epoch"):
        request.assert_dispatchable(
            authoritative_lease=replace(request.lease, epoch=request.lease.epoch + 1),
            now_ms=_NOW_MS,
        )
    with pytest.raises(LeaseFenceError, match="expired"):
        request.assert_dispatchable(
            authoritative_lease=request.lease,
            now_ms=request.lease.expires_at_ms,
        )

    expired = replace(
        request,
        authorization=_authorization(
            authorized_at_ms=_NOW_MS - 10,
            expires_at_ms=_NOW_MS,
        ),
    )
    with pytest.raises(DispatchAuthorizationError, match="expired"):
        expired.assert_dispatchable(authoritative_lease=expired.lease, now_ms=_NOW_MS)

    future = replace(
        request,
        authorization=_authorization(
            authorized_at_ms=_NOW_MS + 1,
            expires_at_ms=_NOW_MS + 10,
        ),
    )
    with pytest.raises(DispatchAuthorizationError, match="not active"):
        future.assert_dispatchable(authoritative_lease=future.lease, now_ms=_NOW_MS)


def test_job_request_binds_policy_to_authorization_lineage() -> None:
    with pytest.raises(ProtocolError, match="authorization lineage"):
        replace(
            _request(),
            authorization=replace(_authorization(), policy_digest="0" * 64),
        )


def test_result_acceptance_is_idempotent_and_conflicts_fail_closed() -> None:
    request = _request()
    response = _response(request=request)
    registry = InMemoryResultReceiptRegistry()
    first = registry.accept(
        response,
        authoritative_request=request,
        authoritative_lease=response.lease,
        accepted_at_ms=_NOW_MS + 3_000,
    )
    transport_retry = replace(response, message_id="response-transport-retry")
    replay = registry.accept(
        transport_retry,
        authoritative_request=request,
        authoritative_lease=response.lease,
        accepted_at_ms=_NOW_MS + 4_000,
    )

    assert replay is first
    assert replay.accepted_at_ms == _NOW_MS + 3_000
    assert replay.response_message_id == response.message_id
    assert replay.request_message_id == request.message_id
    assert replay.logical_result_digest == response.logical_result_digest
    conflicting = replace(
        transport_retry,
        result=CanonicalPayload.from_mapping({"finding_count": 3}),
    )
    with pytest.raises(ResultConflictError):
        registry.accept(
            conflicting,
            authoritative_request=request,
            authoritative_lease=response.lease,
            accepted_at_ms=_NOW_MS + 5_000,
        )


def test_result_must_bind_to_issued_request_before_first_acceptance() -> None:
    request = _request()
    response = _response(request=request)
    another_request = replace(request, message_id="request-other")

    with pytest.raises(ResultConflictError, match="authoritative request"):
        InMemoryResultReceiptRegistry().accept(
            response,
            authoritative_request=another_request,
            authoritative_lease=request.lease,
            accepted_at_ms=_NOW_MS + 3_000,
        )


def test_accepted_result_replay_survives_lease_expiry_or_rotation() -> None:
    request = _request()
    response = _response(request=request)
    registry = InMemoryResultReceiptRegistry()
    receipt = registry.accept(
        response,
        authoritative_request=request,
        authoritative_lease=request.lease,
        accepted_at_ms=_NOW_MS + 3_000,
    )
    replacement_lease = replace(
        request.lease,
        epoch=request.lease.epoch + 1,
        lease_id="lease-4",
        expires_at_ms=request.lease.expires_at_ms + 120_000,
    )

    assert (
        registry.accept(
            response,
            authoritative_request=request,
            authoritative_lease=replacement_lease,
            accepted_at_ms=request.lease.expires_at_ms + 1,
        )
        is receipt
    )


def test_result_acceptance_is_atomic_under_concurrency() -> None:
    request = _request()
    response = _response(request=request)
    registry = InMemoryResultReceiptRegistry()

    def accept_result(_: int) -> ResultReceipt:
        return registry.accept(
            response,
            authoritative_request=request,
            authoritative_lease=response.lease,
            accepted_at_ms=_NOW_MS + 3_000,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(accept_result, range(32)))

    assert len({receipt.message_id for receipt in receipts}) == 1
    assert all(receipt is receipts[0] for receipt in receipts)


def test_result_acceptance_requires_current_unexpired_authority() -> None:
    request = _request()
    response = _response(request=request)
    registry = InMemoryResultReceiptRegistry()

    with pytest.raises(LeaseFenceError, match="epoch"):
        registry.accept(
            response,
            authoritative_request=request,
            authoritative_lease=replace(response.lease, epoch=response.lease.epoch + 1),
            accepted_at_ms=_NOW_MS + 3_000,
        )
    with pytest.raises(LeaseFenceError, match="expired"):
        registry.accept(
            response,
            authoritative_request=request,
            authoritative_lease=response.lease,
            accepted_at_ms=response.lease.expires_at_ms,
        )


def test_result_registry_never_evicts_idempotency_records() -> None:
    first_request = _request()
    first = _response(request=first_request)
    second_request = _request(message_id="request-2", job=_job(job_id="job-2"))
    second = _response(message_id="response-2", request=second_request)
    registry = InMemoryResultReceiptRegistry(max_entries=1)
    registry.accept(
        first,
        authoritative_request=first_request,
        authoritative_lease=first.lease,
        accepted_at_ms=_NOW_MS + 3_000,
    )

    with pytest.raises(RegistryCapacityError):
        registry.accept(
            second,
            authoritative_request=second_request,
            authoritative_lease=second.lease,
            accepted_at_ms=_NOW_MS + 3_000,
        )


def test_heartbeat_rejects_cross_scope_runner_and_unsorted_leases() -> None:
    with pytest.raises(ProtocolError, match="tenant, organization, or runner"):
        Heartbeat(
            message_id="heartbeat-cross-runner",
            tenant_id="tenant-1",
            organization_id=_ORGANIZATION_ID,
            runner_id="runner-1",
            sequence=1,
            observed_at_ms=_NOW_MS,
            active_leases=(_lease(runner_id="runner-2"),),
        )

    with pytest.raises(ProtocolError, match="tenant, organization, or runner"):
        Heartbeat(
            message_id="heartbeat-cross-organization",
            tenant_id="tenant-1",
            organization_id="org-2",
            runner_id="runner-1",
            sequence=1,
            observed_at_ms=_NOW_MS,
            active_leases=(_lease(),),
        )

    with pytest.raises(ProtocolError, match="sorted"):
        Heartbeat(
            message_id="heartbeat-unsorted",
            tenant_id="tenant-1",
            organization_id=_ORGANIZATION_ID,
            runner_id="runner-1",
            sequence=1,
            observed_at_ms=_NOW_MS,
            active_leases=(
                _lease(job=_job(job_id="job-2")),
                _lease(job=_job(job_id="job-1")),
            ),
        )
