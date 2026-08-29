"""Strict canonical JSON codecs for public authorization contracts."""
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, cast

from ravage.control_plane.authorization_contracts import (
    AUTHORIZATION_RECEIPT_SCHEMA,
    AuthorizationDecision,
    AuthorizationReason,
    CommandAuthorizationReceipt,
    CommandAuthorizationRequest,
)
from ravage.control_plane.authorization_state import ResourceLifecycleState
from ravage.control_plane.identity import (
    AuthenticationMethod,
    OrganizationId,
    TenantId,
    UserId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

AUTHORIZATION_WIRE_MAX_BYTES = 65_536

_MAX_INTEGER = (1 << 63) - 1
_MAX_INTEGER_DIGITS = 19
_MAX_JSON_DEPTH = 16
_MAX_JSON_ITEMS = 4_096
_CANONICAL_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9_.:-]{0,126}[a-z0-9])?\Z")
_ATTESTATION_ALGORITHM = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]{0,126}[A-Za-z0-9])?\Z")


class AuthorizationCodecError(ValueError):
    """Raised when a public authorization message is not strict canonical JSON."""


def encode_authorization_request(request: CommandAuthorizationRequest) -> bytes:
    """Encode one request to bounded canonical JSON and prove its round trip."""
    if type(request) is not CommandAuthorizationRequest:
        raise TypeError("request must be a CommandAuthorizationRequest")
    encoded = _encode(request.to_json(), "authorization request")
    if decode_authorization_request(encoded) != request:
        raise AuthorizationCodecError("authorization request did not survive round trip")
    return encoded


def decode_authorization_request(raw: bytes) -> CommandAuthorizationRequest:
    """Decode an exact-key, versioned authorization request."""
    root = _decode_object(raw, "authorization request")
    _require_exact_keys(
        root,
        {
            "command_id",
            "command_name",
            "organization_id",
            "payload_sha256",
            "resource_id",
            "resource_kind",
            "schema",
            "tenant_id",
        },
        "authorization request",
    )
    try:
        request = CommandAuthorizationRequest(
            command_id=_required_string(root["command_id"], "command_id"),
            command_name=_required_string(root["command_name"], "command_name"),
            tenant_id=TenantId(_required_string(root["tenant_id"], "tenant_id")),
            organization_id=OrganizationId(
                _required_string(root["organization_id"], "organization_id")
            ),
            resource_kind=_required_string(root["resource_kind"], "resource_kind"),
            resource_id=_required_string(root["resource_id"], "resource_id"),
            payload_sha256=_required_string(root["payload_sha256"], "payload_sha256"),
            schema_version=_required_string(root["schema"], "schema"),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise AuthorizationCodecError(
            "authorization request failed structural validation"
        ) from error
    if _encode(request.to_json(), "authorization request") != raw:
        raise AuthorizationCodecError("authorization request changed during semantic decoding")
    return request


def encode_authorization_receipt(receipt: CommandAuthorizationReceipt) -> bytes:
    """Encode one signed receipt to bounded canonical JSON and prove its round trip."""
    if type(receipt) is not CommandAuthorizationReceipt:
        raise TypeError("receipt must be a CommandAuthorizationReceipt")
    encoded = _encode(receipt.to_json(), "authorization receipt")
    if decode_authorization_receipt(encoded) != receipt:
        raise AuthorizationCodecError("authorization receipt did not survive round trip")
    return encoded


def decode_authorization_receipt(raw: bytes) -> CommandAuthorizationReceipt:
    """Decode a strict signed receipt; callers must still verify its attestation."""
    root = _decode_object(raw, "authorization receipt")
    try:
        _require_exact_keys(
            root,
            {
                "actor",
                "attestation_signature",
                "command",
                "decision",
                "evaluated_at",
                "granting_roles",
                "issuer",
                "policy_sha256",
                "policy_version",
                "reason",
                "receipt_id",
                "receipt_sha256",
                "resource_state",
                "schema",
                "target",
            },
            "authorization receipt",
        )
        actor = _json_object(root["actor"], "actor")
        _require_exact_keys(
            actor,
            {
                "authentication_event_id",
                "authentication_method",
                "authenticated_at",
                "expires_at",
                "organization_id",
                "roles",
                "tenant_id",
                "user_id",
            },
            "actor",
        )
        command = _json_object(root["command"], "command")
        _require_exact_keys(
            command,
            {
                "command_claim_sha256",
                "command_id",
                "command_name",
                "payload_sha256",
                "required_permission",
                "resource_id",
                "resource_kind",
            },
            "command",
        )
        issuer = _json_object(root["issuer"], "issuer")
        _require_exact_keys(issuer, {"algorithm", "issuer_id", "key_id"}, "issuer")
        resource_state = _json_object(root["resource_state"], "resource_state")
        _require_exact_keys(
            resource_state,
            {
                "approved_by_user_id",
                "lifecycle",
                "requested_by_user_id",
                "revision",
                "state_sha256",
            },
            "resource_state",
        )
        target = _json_object(root["target"], "target")
        _require_exact_keys(target, {"organization_id", "tenant_id"}, "target")
        schema_version = _authorization_receipt_schema(root["schema"])

        receipt = CommandAuthorizationReceipt(
            receipt_id=_required_string(root["receipt_id"], "receipt_id"),
            receipt_sha256=_required_string(root["receipt_sha256"], "receipt_sha256"),
            schema_version=schema_version,
            policy_version=_required_string(root["policy_version"], "policy_version"),
            policy_sha256=_required_string(root["policy_sha256"], "policy_sha256"),
            issuer_id=_required_string(issuer["issuer_id"], "issuer.issuer_id"),
            issuer_key_id=_required_string(issuer["key_id"], "issuer.key_id"),
            attestation_algorithm=_algorithm_string(issuer["algorithm"]),
            attestation_signature=_required_string(
                root["attestation_signature"], "attestation_signature"
            ),
            evaluated_at=_utc_datetime(root["evaluated_at"], "evaluated_at"),
            decision=AuthorizationDecision(_required_string(root["decision"], "decision")),
            reason=AuthorizationReason(_required_string(root["reason"], "reason")),
            command_id=_required_string(command["command_id"], "command.command_id"),
            command_claim_sha256=_required_string(
                command["command_claim_sha256"], "command.command_claim_sha256"
            ),
            command_name=_required_string(command["command_name"], "command.command_name"),
            payload_sha256=_required_string(command["payload_sha256"], "command.payload_sha256"),
            resource_kind=_required_string(command["resource_kind"], "command.resource_kind"),
            resource_id=_required_string(command["resource_id"], "command.resource_id"),
            target_tenant_id=TenantId(_required_string(target["tenant_id"], "target.tenant_id")),
            target_organization_id=OrganizationId(
                _required_string(target["organization_id"], "target.organization_id")
            ),
            resource_revision=_optional_integer(
                resource_state["revision"], "resource_state.revision"
            ),
            resource_lifecycle=_optional_enum(
                resource_state["lifecycle"],
                ResourceLifecycleState,
                "resource_state.lifecycle",
            ),
            resource_state_sha256=_optional_string(
                resource_state["state_sha256"], "resource_state.state_sha256"
            ),
            requested_by_user_id=_optional_user_id(
                resource_state["requested_by_user_id"],
                "resource_state.requested_by_user_id",
            ),
            approved_by_user_id=_optional_user_id(
                resource_state["approved_by_user_id"],
                "resource_state.approved_by_user_id",
            ),
            actor_tenant_id=TenantId(_required_string(actor["tenant_id"], "actor.tenant_id")),
            actor_organization_id=OrganizationId(
                _required_string(actor["organization_id"], "actor.organization_id")
            ),
            actor_user_id=UserId(_required_string(actor["user_id"], "actor.user_id")),
            authentication_method=AuthenticationMethod(
                _required_string(actor["authentication_method"], "actor.authentication_method")
            ),
            authentication_event_id=_canonical_string(
                actor["authentication_event_id"], "actor.authentication_event_id"
            ),
            actor_authenticated_at=_utc_datetime(
                actor["authenticated_at"], "actor.authenticated_at"
            ),
            actor_expires_at=_utc_datetime(actor["expires_at"], "actor.expires_at"),
            actor_roles=_canonical_string_tuple(actor["roles"], "actor.roles"),
            granting_roles=_canonical_string_tuple(root["granting_roles"], "granting_roles"),
            required_permission=_optional_string(
                command["required_permission"], "command.required_permission"
            ),
        )
    except AuthorizationCodecError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AuthorizationCodecError(
            "authorization receipt failed structural validation"
        ) from error
    if _encode(receipt.to_json(), "authorization receipt") != raw:
        raise AuthorizationCodecError("authorization receipt changed during semantic decoding")
    return receipt


def _encode(value: object, label: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise AuthorizationCodecError(f"{label} is not canonical JSON") from error
    if len(encoded) > AUTHORIZATION_WIRE_MAX_BYTES:
        raise AuthorizationCodecError(f"{label} exceeds the wire-size bound")
    return encoded


def _decode_object(raw: bytes, label: str) -> dict[str, object]:
    if type(raw) is not bytes:
        raise TypeError(f"{label} must be a byte string")
    if len(raw) > AUTHORIZATION_WIRE_MAX_BYTES:
        raise AuthorizationCodecError(f"{label} exceeds the wire-size bound")
    try:
        parsed: object = json.loads(
            raw.decode("ascii", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_parse_bounded_json_integer,
        )
    except (RecursionError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise AuthorizationCodecError(f"{label} is not valid strict JSON") from error
    _validate_json_tree(parsed)
    root = _json_object(parsed, label)
    if _encode(root, label) != raw:
        raise AuthorizationCodecError(f"{label} is not canonical JSON")
    return root


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _reject_json_float(value: str) -> object:
    raise ValueError(f"floating-point JSON number is not allowed: {value}")


def _parse_bounded_json_integer(value: str) -> int:
    if len(value.lstrip("-")) > _MAX_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds the signed 64-bit bound")
    parsed = int(value)
    if not 0 <= parsed <= _MAX_INTEGER:
        raise ValueError("JSON integer is outside the supported range")
    return parsed


def _validate_json_tree(root: object) -> None:
    stack: list[tuple[object, int]] = [(root, 1)]
    item_count = 0
    while stack:
        value, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            raise AuthorizationCodecError("authorization JSON exceeds the depth bound")
        if type(value) is dict:
            item_count += len(value)
            stack.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            item_count += len(value)
            stack.extend((item, depth + 1) for item in value)
        elif value is None or type(value) in {str, bool, int}:
            continue
        else:
            raise AuthorizationCodecError("authorization JSON contains an unsupported value")
        if item_count > _MAX_JSON_ITEMS:
            raise AuthorizationCodecError("authorization JSON exceeds the item-count bound")


def _json_object(value: object, field_name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise AuthorizationCodecError(f"{field_name} must be a JSON object")
    if any(type(key) is not str for key in value):
        raise AuthorizationCodecError(f"{field_name} contains a non-string key")
    return cast("dict[str, object]", value)


def _require_exact_keys(
    value: dict[str, object],
    expected: set[str],
    field_name: str,
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise AuthorizationCodecError(
            f"{field_name} fields mismatch; missing={missing}, unknown={unknown}"
        )


def _required_string(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    return value


def _authorization_receipt_schema(value: object) -> str:
    schema_version = _required_string(value, "schema")
    if schema_version != AUTHORIZATION_RECEIPT_SCHEMA:
        raise AuthorizationCodecError("unsupported authorization receipt schema")
    return schema_version


def _canonical_string(value: object, field_name: str) -> str:
    parsed = _required_string(value, field_name)
    if _CANONICAL_IDENTIFIER.fullmatch(parsed) is None:
        raise ValueError(f"{field_name} is not canonical")
    return parsed


def _algorithm_string(value: object) -> str:
    parsed = _required_string(value, "issuer.algorithm")
    if _ATTESTATION_ALGORITHM.fullmatch(parsed) is None:
        raise ValueError("issuer.algorithm is not canonical")
    return parsed


def _optional_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_string(value, field_name)


def _optional_integer(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= _MAX_INTEGER:
        raise ValueError(f"{field_name} must be a non-negative signed 64-bit integer or null")
    return value


def _optional_user_id(value: object, field_name: str) -> UserId | None:
    if value is None:
        return None
    return UserId(_required_string(value, field_name))


def _optional_enum[EnumT](
    value: object,
    enum_type: Callable[[str], EnumT],
    field_name: str,
) -> EnumT | None:
    if value is None:
        return None
    return enum_type(_required_string(value, field_name))


def _canonical_string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise TypeError(f"{field_name} must be an array")
    return tuple(_canonical_string(item, f"{field_name}[]") for item in value)


def _utc_datetime(value: object, field_name: str) -> datetime:
    encoded = _required_string(value, field_name)
    parsed = datetime.fromisoformat(encoded)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be normalized to UTC")
    if parsed.isoformat() != encoded:
        raise ValueError(f"{field_name} is not a canonical ISO-8601 datetime")
    return parsed


__all__ = [
    "AUTHORIZATION_WIRE_MAX_BYTES",
    "AuthorizationCodecError",
    "decode_authorization_receipt",
    "decode_authorization_request",
    "encode_authorization_receipt",
    "encode_authorization_request",
]
