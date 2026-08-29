# Runtime-manifest errors carry field-specific fail-closed context.
# ruff: noqa: EM101, EM102, TRY003

"""Credential-free durable identity for production graph runtime policies."""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

if TYPE_CHECKING:
    from pathlib import Path

_RUNTIME_MANIFEST_VERSION = 2
_SHA256_HEX_CHARS = 64
_COMPONENT_IDENTITY_ATTRIBUTE = "runtime_manifest_identity"
_MAX_COMPONENT_IDENTITY_CHARS = 512
_SECRET_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_SECRET_KEY_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_cookie",
    "_credential",
    "_password",
    "_private_key",
    "_secret",
    "_access_token",
    "_bearer_token",
    "_refresh_token",
)
_ROUTE_CONFIGURATION_FIELDS = (
    "requested_tier",
    "selected_tier",
    "reasoning_effort",
    "max_output_tokens",
    "output_token_limit_parameter",
    "input_cost_per_1m_tokens",
    "output_cost_per_1m_tokens",
    "cached_input_cost_per_1m_tokens",
    "timeout_seconds",
    "max_retries",
)


class GraphRuntimeManifestError(RuntimeError):
    """Raised when a resumed graph cannot prove the same runtime policy identity."""


@dataclass(frozen=True)
class RuntimeModelRouteIdentity:
    """Non-secret identity of one configured provider route."""

    provider: str
    model: str
    ordinal: int
    configuration_digest: str

    def __post_init__(self) -> None:
        if not self.provider.strip() or not self.model.strip():
            raise GraphRuntimeManifestError("runtime model route identity is incomplete")
        if isinstance(self.ordinal, bool) or self.ordinal < 0:
            raise GraphRuntimeManifestError("runtime model route ordinal must be non-negative")
        _require_sha256(
            self.configuration_digest,
            label="runtime model route configuration digest",
        )

    def to_json(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model": self.model,
            "ordinal": self.ordinal,
            "configuration_digest": self.configuration_digest,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RuntimeModelRouteIdentity:
        ordinal = payload.get("ordinal")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int):
            raise GraphRuntimeManifestError("runtime model route ordinal is invalid")
        return cls(
            provider=str(payload.get("provider") or ""),
            model=str(payload.get("model") or ""),
            ordinal=ordinal,
            configuration_digest=str(payload.get("configuration_digest") or ""),
        )


@dataclass(frozen=True)
class RuntimeModelPolicyIdentity:
    """Ordered failover portfolio bound to one persisted policy key."""

    policy_key: str
    routes: tuple[RuntimeModelRouteIdentity, ...]

    def __post_init__(self) -> None:
        if not self.policy_key.strip():
            raise GraphRuntimeManifestError("runtime model policy key is required")
        if not self.routes:
            raise GraphRuntimeManifestError("runtime model policy needs at least one route")

    def to_json(self) -> dict[str, object]:
        return {
            "policy_key": self.policy_key,
            "routes": [route.to_json() for route in self.routes],
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RuntimeModelPolicyIdentity:
        routes = payload.get("routes")
        if not isinstance(routes, list) or not all(isinstance(item, dict) for item in routes):
            raise GraphRuntimeManifestError("runtime model policy routes are invalid")
        return cls(
            policy_key=str(payload.get("policy_key") or ""),
            routes=tuple(RuntimeModelRouteIdentity.from_json(item) for item in routes),
        )


@dataclass(frozen=True)
class GraphRuntimeManifest:
    """Exact runtime identity required to resume a production graph."""

    graph_id: str
    execution_mode: str
    model_policies: tuple[RuntimeModelPolicyIdentity, ...]
    capabilities: tuple[str, ...]
    policy_payload_digest: str
    instructions_digest: str

    def __post_init__(self) -> None:
        if not self.graph_id.strip() or not self.execution_mode.strip():
            raise GraphRuntimeManifestError("runtime manifest identity is incomplete")
        keys = tuple(policy.policy_key for policy in self.model_policies)
        if not keys or len(keys) != len(set(keys)):
            raise GraphRuntimeManifestError("runtime model policy keys must be unique")
        if tuple(sorted(keys)) != keys:
            raise GraphRuntimeManifestError("runtime model policy keys must be sorted")
        if tuple(sorted(set(self.capabilities))) != self.capabilities:
            raise GraphRuntimeManifestError("runtime capabilities must be sorted and unique")
        _require_sha256(
            self.policy_payload_digest,
            label="runtime policy payload digest",
        )
        _require_sha256(
            self.instructions_digest,
            label="runtime instructions digest",
        )

    @classmethod
    def create(  # noqa: PLR0913 - each identity dimension is independently bound.
        cls,
        *,
        graph_id: str,
        execution_mode: str,
        model_policies: Mapping[str, Sequence[object]],
        capabilities: Sequence[str],
        policy_payload: Mapping[str, object] | None = None,
        instructions: str = "",
    ) -> GraphRuntimeManifest:
        if not isinstance(instructions, str):
            raise GraphRuntimeManifestError("runtime instructions must be a string")
        effective_policy_payload = {} if policy_payload is None else policy_payload
        policies: list[RuntimeModelPolicyIdentity] = []
        for policy_key, endpoints in sorted(model_policies.items()):
            routes: list[RuntimeModelRouteIdentity] = []
            for endpoint in endpoints:
                route = getattr(endpoint, "route", None)
                if route is None:
                    raise GraphRuntimeManifestError("model endpoint has no resolved route")
                routes.append(
                    RuntimeModelRouteIdentity(
                        provider=str(getattr(route, "provider", "")),
                        model=str(getattr(route, "model", "")),
                        ordinal=int(getattr(route, "ordinal", -1)),
                        configuration_digest=_route_configuration_digest(
                            endpoint=endpoint,
                            route=route,
                        ),
                    )
                )
            policies.append(RuntimeModelPolicyIdentity(policy_key=policy_key, routes=tuple(routes)))
        return cls(
            graph_id=graph_id,
            execution_mode=execution_mode,
            model_policies=tuple(policies),
            capabilities=_canonical_capabilities(capabilities),
            policy_payload_digest=_policy_payload_digest(effective_policy_payload),
            instructions_digest=_digest_text(_normalized_instructions(instructions)),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "version": _RUNTIME_MANIFEST_VERSION,
            "graph_id": self.graph_id,
            "execution_mode": self.execution_mode,
            "model_policies": [policy.to_json() for policy in self.model_policies],
            "capabilities": list(self.capabilities),
            "policy_payload_digest": self.policy_payload_digest,
            "instructions_digest": self.instructions_digest,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> GraphRuntimeManifest:
        version = payload.get("version")
        if isinstance(version, bool) or version != _RUNTIME_MANIFEST_VERSION:
            raise GraphRuntimeManifestError("unsupported runtime manifest version")
        policies = payload.get("model_policies")
        capabilities = payload.get("capabilities")
        if not isinstance(policies, list) or not all(isinstance(item, dict) for item in policies):
            raise GraphRuntimeManifestError("runtime model policies are invalid")
        if not isinstance(capabilities, list) or not all(
            isinstance(item, str) for item in capabilities
        ):
            raise GraphRuntimeManifestError("runtime capabilities are invalid")
        return cls(
            graph_id=str(payload.get("graph_id") or ""),
            execution_mode=str(payload.get("execution_mode") or ""),
            model_policies=tuple(RuntimeModelPolicyIdentity.from_json(item) for item in policies),
            capabilities=tuple(capabilities),
            policy_payload_digest=str(payload.get("policy_payload_digest") or ""),
            instructions_digest=str(payload.get("instructions_digest") or ""),
        )

    @classmethod
    def load(cls, path: Path) -> GraphRuntimeManifest:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GraphRuntimeManifestError(f"cannot read runtime manifest: {exc}") from exc
        if not isinstance(payload, dict):
            raise GraphRuntimeManifestError("runtime manifest must be a JSON object")
        return cls.from_json(payload)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


def bind_runtime_manifest(
    path: Path,
    *,
    expected: GraphRuntimeManifest,
    resumed: bool,
) -> None:
    """Create a new binding or require an exact match before resumed execution."""
    if path.exists():
        if GraphRuntimeManifest.load(path) != expected:
            raise GraphRuntimeManifestError(
                "runtime policy manifest does not match the persisted graph"
            )
        return
    if resumed:
        raise GraphRuntimeManifestError("resumed graph is missing its runtime policy manifest")
    expected.save(path)


def component_behavior_identity(
    value: object | None,
    *,
    label: str,
    default_identity: str | None = None,
    allow_implicit_type: bool = False,
    allow_named_function: bool = False,
) -> str:
    """
    Return a stable, credential-safe digest for injected runtime behavior.

    Stateful injected objects must explicitly declare ``runtime_manifest_identity``.
    Framework-owned defaults may opt into type identity, while resolvers may opt into
    the import-stable identity of a named, non-local Python function. The declared
    value is always hashed before it reaches a policy payload so raw configuration or
    accidentally supplied secrets are never persisted.
    """
    if value is None:
        if default_identity is None:
            raise GraphRuntimeManifestError(f"{label} identity is required")
        return _component_identity_digest(
            kind="default",
            implementation="",
            identity=_validated_component_identity(default_identity, label=label),
        )

    implementation = _implementation_identity(value)
    declared = _declared_component_identity(value, label=label)
    if declared is not None:
        return _component_identity_digest(
            kind="declared",
            implementation=implementation,
            identity=declared,
        )
    if allow_named_function and inspect.isfunction(value):
        module = str(getattr(value, "__module__", "") or "").strip()
        qualname = str(getattr(value, "__qualname__", "") or "").strip()
        if module and qualname and "<locals>" not in qualname and "<lambda>" not in qualname:
            return _component_identity_digest(
                kind="named-function",
                implementation=f"{module}.{qualname}",
                identity="",
            )
    if allow_implicit_type:
        return _component_identity_digest(
            kind="framework-type",
            implementation=implementation,
            identity="",
        )
    raise GraphRuntimeManifestError(
        f"{label} must declare a stable {_COMPONENT_IDENTITY_ATTRIBUTE}"
    )


def _declared_component_identity(value: object, *, label: str) -> str | None:
    try:
        declared = getattr(value, _COMPONENT_IDENTITY_ATTRIBUTE, None)
    except Exception:  # noqa: BLE001 - component details must not escape.
        raise GraphRuntimeManifestError(f"cannot read {label} behavior identity") from None
    if declared is None:
        return None
    if not isinstance(declared, str):
        raise GraphRuntimeManifestError(
            f"{label} {_COMPONENT_IDENTITY_ATTRIBUTE} must be a string"
        )
    return _validated_component_identity(declared, label=label)


def _validated_component_identity(value: str, *, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise GraphRuntimeManifestError(f"{label} behavior identity is empty")
    if len(normalized) > _MAX_COMPONENT_IDENTITY_CHARS or any(
        not character.isprintable() for character in normalized
    ):
        raise GraphRuntimeManifestError(f"{label} behavior identity is invalid")
    return normalized


def _implementation_identity(value: object) -> str:
    if inspect.isfunction(value):
        module = str(getattr(value, "__module__", "") or "").strip()
        qualname = str(getattr(value, "__qualname__", "") or "").strip()
        if module and qualname:
            return f"{module}.{qualname}"
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"


def _component_identity_digest(
    *,
    kind: str,
    implementation: str,
    identity: str,
) -> str:
    digest = _digest_json(
        {
            "version": 1,
            "kind": kind,
            "implementation": implementation,
            "identity": identity,
        }
    )
    return f"runtime-component-v1:sha256:{digest}"


def _route_configuration_digest(*, endpoint: object, route: object) -> str:
    """Hash behavior-affecting route settings without serializing credentials."""
    missing_env = getattr(route, "missing_env", ())
    if not isinstance(missing_env, (list, tuple, set, frozenset)):
        missing_env = ()
    payload: dict[str, object] = {
        "client_type": _type_identity(getattr(endpoint, "client", None)),
        "endpoint": _credential_free_endpoint(str(getattr(route, "base_url", "") or "")),
        "credential_reference_configured": bool(getattr(route, "api_key_env", None)),
        "missing_credential_reference_count": len(missing_env),
    }
    for field_name in _ROUTE_CONFIGURATION_FIELDS:
        payload[field_name] = _normalize_policy_value(
            getattr(route, field_name, None),
            path=f"route.{field_name}",
        )
    return _digest_json(payload)


def _type_identity(value: object) -> str:
    if value is None:
        return ""
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"


def _credential_free_endpoint(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        query = urlencode(
            [
                (key, "<redacted>" if _secret_key(key) else item)
                for key, item in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            doseq=True,
        )
        return urlunsplit(
            (
                parsed.scheme.lower(),
                f"{host.lower()}{port}",
                parsed.path,
                query,
                "",
            )
        )
    except ValueError:
        return f"unparseable:{_digest_text(raw)}"


def _canonical_capabilities(capabilities: Sequence[str]) -> tuple[str, ...]:
    if isinstance(capabilities, (str, bytes, bytearray)):
        raise GraphRuntimeManifestError("runtime capabilities must be a sequence of names")
    normalized: set[str] = set()
    for capability in capabilities:
        if not isinstance(capability, str) or not capability.strip():
            raise GraphRuntimeManifestError("runtime capability names must be non-empty strings")
        normalized.add(capability.strip())
    return tuple(sorted(normalized))


def _policy_payload_digest(payload: Mapping[str, object]) -> str:
    if not isinstance(payload, Mapping):
        raise GraphRuntimeManifestError("runtime policy payload must be a mapping")
    return _digest_json(_normalize_policy_value(payload, path="policy"))


def _normalize_policy_value(value: object, *, path: str) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise GraphRuntimeManifestError(f"runtime policy value is not finite: {path}")
        return value
    if isinstance(value, Enum):
        return _normalize_policy_value(value.value, path=path)
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for raw_key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            if not isinstance(raw_key, str) or not raw_key.strip():
                raise GraphRuntimeManifestError(f"runtime policy mapping key is invalid: {path}")
            key = raw_key.strip()
            normalized[key] = (
                "<redacted>"
                if _secret_key(key)
                else _normalize_policy_value(item, path=f"{path}.{key}")
            )
        return normalized
    if isinstance(value, AbstractSet):
        normalized_items = [_normalize_policy_value(item, path=f"{path}[]") for item in value]
        return sorted(normalized_items, key=_canonical_sort_key)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _normalize_policy_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    raise GraphRuntimeManifestError(
        f"runtime policy value has unsupported type at {path}: {type(value).__name__}"
    )


def _canonical_sort_key(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _secret_key(value: str) -> bool:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    return normalized in _SECRET_KEYS or normalized.endswith(_SECRET_KEY_SUFFIXES)


def _normalized_instructions(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").strip()


def _digest_json(value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return _digest_text(canonical)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _require_sha256(value: str, *, label: str) -> None:
    if len(value) != _SHA256_HEX_CHARS or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise GraphRuntimeManifestError(f"{label} must be a lowercase SHA-256 digest")


__all__ = [
    "GraphRuntimeManifest",
    "GraphRuntimeManifestError",
    "RuntimeModelPolicyIdentity",
    "RuntimeModelRouteIdentity",
    "bind_runtime_manifest",
    "component_behavior_identity",
]
