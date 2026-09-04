# ruff: noqa: EM101, EM102, TRY003
"""
Canonical, identity-aware attack-surface graph.

The graph stores request *shape*, not query/body/header values or response
bodies. Identity-like path children are normalized conservatively. Operations
are identity-independent nodes; observations are the identity/source-specific
edges that describe how an operation was seen.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit, urlunsplit

from ravage.traffic.redaction import REDACTED_URL, sanitize_url

if TYPE_CHECKING:
    from ravage.traffic.contracts import CapturedHttpExchange

SURFACE_GRAPH_SCHEMA = "ravage.surface-graph.v1"
SURFACE_GRAPH_VERSION = 1
MAX_SURFACE_OPERATIONS = 512
MAX_SURFACE_OBSERVATIONS = 2_048
MAX_OPERATION_PARAMETERS = 64
MAX_OPERATION_METADATA_ITEMS = 64
MAX_OBSERVATION_EVIDENCE_REFS = 64
_MAX_INSPECTED_ITEMS = 4_096
_MAX_HOST_CHARS = 253
_MAX_METADATA_CHARS = 128
_MAX_TIMESTAMP_CHARS = 64
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599
_MIN_SUCCESSFUL_HTTP_STATUS = 200
_FIRST_UNSUCCESSFUL_HTTP_STATUS = 400

_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.:\[\]-]+")
_STATIC_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]{1,80}$")
_INTEGER_RE = re.compile(r"^[0-9]+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_OPAQUE_ID_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9_-]{16,}$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IDENTITY_PATH_PARENTS = frozenset(
    {
        "account",
        "accounts",
        "comment",
        "comments",
        "customer",
        "customers",
        "document",
        "documents",
        "file",
        "files",
        "invoice",
        "invoices",
        "member",
        "members",
        "order",
        "orders",
        "org",
        "orgs",
        "organization",
        "organizations",
        "post",
        "posts",
        "profile",
        "profiles",
        "project",
        "projects",
        "session",
        "sessions",
        "team",
        "teams",
        "tenant",
        "tenants",
        "user",
        "users",
    }
)
_STATIC_COLLECTION_ACTIONS = frozenset(
    {
        "archive",
        "create",
        "current",
        "export",
        "health",
        "import",
        "lookup",
        "me",
        "new",
        "recent",
        "search",
        "self",
        "settings",
        "status",
    }
)
_ALLOWED_PARAMETER_LOCATIONS = frozenset(
    {"body", "cookie", "form", "graphql", "header", "path", "query", "unknown"}
)
_ALLOWED_SOURCE_KINDS = frozenset(
    {
        "native_recon",
        "javascript_inline",
        "javascript_external",
        "openapi",
        "graphql",
        "browser",
        "probe",
        "source_code",
        "agent_http_response",
        "external_tool",
        "legacy_import",
    }
)
_ALLOWED_ACCESS_LEVELS = frozenset({"declared", "request", "response"})
_ALLOWED_REPLAYABILITY = frozenset({"unknown", "safe", "requires_authorization", "not_replayable"})


class SurfaceGraphError(ValueError):
    """Raised when graph input is malformed, unsafe, or from another target."""


@dataclass(frozen=True, slots=True, order=True)
class SurfaceParameter:
    name: str
    location: str
    data_type: str = "unknown"
    required: bool = False

    @classmethod
    def create(
        cls,
        *,
        name: object,
        location: object,
        data_type: object = "unknown",
        required: object = False,
    ) -> SurfaceParameter:
        safe_name = _safe_name(name, label="parameter name")
        safe_location = _safe_name(location, label="parameter location").casefold()
        if safe_location not in _ALLOWED_PARAMETER_LOCATIONS:
            raise SurfaceGraphError("unsupported parameter location")
        safe_type = _safe_name(data_type or "unknown", label="parameter type")
        return cls(
            name=safe_name,
            location=safe_location,
            data_type=safe_type,
            required=_boolean(required, label="parameter required"),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "location": self.location,
            "data_type": self.data_type,
            "required": self.required,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> SurfaceParameter:
        _reject_unexpected_fields(
            payload,
            allowed={"name", "location", "data_type", "required"},
            label="surface parameter",
        )
        return cls.create(
            name=payload.get("name"),
            location=payload.get("location"),
            data_type=payload.get("data_type"),
            required=payload.get("required"),
        )


@dataclass(frozen=True, slots=True)
class SurfaceOperation:
    operation_id: str
    protocol: str
    method: str
    origin: str
    route_shape: str
    selector: str
    parameters: tuple[SurfaceParameter, ...]
    content_types: tuple[str, ...]
    header_names: tuple[str, ...]
    hints: tuple[str, ...]
    provenance: tuple[str, ...]

    @classmethod
    def create(  # noqa: PLR0913 - operation shape is deliberately explicit.
        cls,
        *,
        url: object,
        method: object = "GET",
        selector: object = "",
        parameters: Iterable[SurfaceParameter | Mapping[str, object]] = (),
        content_types: Iterable[object] = (),
        header_names: Iterable[object] = (),
        hints: Iterable[object] = (),
        provenance: Iterable[object] = (),
    ) -> SurfaceOperation:
        origin, protocol, route_shape = canonical_operation_url(url)
        normalized_method = str(method or "GET").strip().upper()
        if not _METHOD_RE.fullmatch(normalized_method):
            raise SurfaceGraphError("invalid operation method")
        safe_selector = _optional_name(selector)
        normalized_parameters = _parameters(parameters)
        normalized_content_types = _content_types(content_types)
        normalized_header_names = _header_names(header_names)
        normalized_hints = _safe_names(hints)
        normalized_provenance = _source_kinds(provenance)
        operation_id = _stable_id(
            "operation",
            protocol,
            normalized_method,
            origin,
            route_shape,
            safe_selector,
        )
        return cls(
            operation_id=operation_id,
            protocol=protocol,
            method=normalized_method,
            origin=origin,
            route_shape=route_shape,
            selector=safe_selector,
            parameters=normalized_parameters,
            content_types=normalized_content_types,
            header_names=normalized_header_names,
            hints=normalized_hints,
            provenance=normalized_provenance,
        )

    def merged(self, other: SurfaceOperation) -> SurfaceOperation:
        if self.operation_id != other.operation_id:
            raise SurfaceGraphError("cannot merge different surface operations")
        return replace(
            self,
            parameters=tuple(sorted(set(self.parameters) | set(other.parameters)))[
                :MAX_OPERATION_PARAMETERS
            ],
            content_types=tuple(sorted(set(self.content_types) | set(other.content_types)))[
                :MAX_OPERATION_METADATA_ITEMS
            ],
            header_names=tuple(sorted(set(self.header_names) | set(other.header_names)))[
                :MAX_OPERATION_METADATA_ITEMS
            ],
            hints=tuple(sorted(set(self.hints) | set(other.hints)))[:MAX_OPERATION_METADATA_ITEMS],
            provenance=tuple(sorted(set(self.provenance) | set(other.provenance))),
        )

    @property
    def structural_url(self) -> str:
        return f"{self.origin}{self.route_shape}"

    @property
    def actionable(self) -> bool:
        """Whether trusted discovery, rather than attack traffic alone, found this shape."""
        return any(source != "probe" for source in self.provenance)

    def to_json(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "protocol": self.protocol,
            "method": self.method,
            "origin": self.origin,
            "route_shape": self.route_shape,
            "selector": self.selector,
            "parameters": [item.to_json() for item in self.parameters],
            "content_types": list(self.content_types),
            "header_names": list(self.header_names),
            "hints": list(self.hints),
            "provenance": list(self.provenance),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> SurfaceOperation:
        _reject_unexpected_fields(
            payload,
            allowed={
                "operation_id",
                "protocol",
                "method",
                "origin",
                "route_shape",
                "selector",
                "parameters",
                "content_types",
                "header_names",
                "hints",
                "provenance",
            },
            label="surface operation",
        )
        operation = cls.create(
            url=f"{payload.get('origin') or ''}{payload.get('route_shape') or ''}",
            method=payload.get("method"),
            selector=payload.get("selector"),
            parameters=_json_mapping_items(
                payload.get("parameters"),
                label="surface operation parameters",
            ),
            content_types=_json_object_items(
                payload.get("content_types"),
                label="surface operation content_types",
            ),
            header_names=_json_object_items(
                payload.get("header_names"),
                label="surface operation header_names",
            ),
            hints=_json_object_items(
                payload.get("hints"),
                label="surface operation hints",
            ),
            provenance=_json_object_items(
                payload.get("provenance"),
                label="surface operation provenance",
            ),
        )
        if str(payload.get("operation_id") or "") != operation.operation_id:
            raise SurfaceGraphError("surface operation identity does not match its shape")
        if str(payload.get("protocol") or "") != operation.protocol:
            raise SurfaceGraphError("surface operation protocol does not match its URL")
        return operation


@dataclass(frozen=True, slots=True)
class SurfaceAccessObservation:
    observation_id: str
    operation_id: str
    identity_alias: str
    source_kind: str
    access_level: str
    response_status: int | None
    scope_decision: str
    replayability: str
    evidence_refs: tuple[str, ...]
    observation_count: int = 1
    first_observed_at: str = ""
    last_observed_at: str = ""

    @classmethod
    def create(  # noqa: PLR0913 - access edge identity is explicit.
        cls,
        *,
        operation_id: object,
        identity_alias: object = "anonymous",
        source_kind: object,
        access_level: object = "declared",
        response_status: object = None,
        scope_decision: object = "unknown",
        replayability: object = "unknown",
        evidence_refs: Iterable[object] = (),
        observed_at: object = "",
    ) -> SurfaceAccessObservation:
        operation = str(operation_id or "").strip()
        if not operation.startswith("op_"):
            raise SurfaceGraphError("invalid surface operation reference")
        identity = _safe_name(identity_alias or "anonymous", label="identity alias")
        source = _source_kind(source_kind)
        level = str(access_level or "declared").strip().lower()
        if level not in _ALLOWED_ACCESS_LEVELS:
            raise SurfaceGraphError("invalid surface access level")
        status = _optional_status(response_status)
        scope = _safe_name(scope_decision or "unknown", label="scope decision")
        replay = str(replayability or "unknown").strip().lower()
        if replay not in _ALLOWED_REPLAYABILITY:
            raise SurfaceGraphError("invalid surface replayability")
        if status is not None and level != "response":
            raise SurfaceGraphError("a response status requires response-level access")
        refs = _safe_names(evidence_refs, limit=MAX_OBSERVATION_EVIDENCE_REFS)
        timestamp = _safe_timestamp(observed_at)
        observation_id = _stable_id(
            "access",
            operation,
            identity,
            source,
            level,
            "" if status is None else str(status),
            scope,
            replay,
        )
        return cls(
            observation_id=observation_id,
            operation_id=operation,
            identity_alias=identity,
            source_kind=source,
            access_level=level,
            response_status=status,
            scope_decision=scope,
            replayability=replay,
            evidence_refs=refs,
            first_observed_at=timestamp,
            last_observed_at=timestamp,
        )

    def merged(self, other: SurfaceAccessObservation) -> SurfaceAccessObservation:
        if self.observation_id != other.observation_id:
            raise SurfaceGraphError("cannot merge different surface observations")
        first = (
            min(item for item in (self.first_observed_at, other.first_observed_at) if item)
            if (self.first_observed_at or other.first_observed_at)
            else ""
        )
        last = max(self.last_observed_at, other.last_observed_at)
        return replace(
            self,
            evidence_refs=tuple(sorted(set(self.evidence_refs) | set(other.evidence_refs)))[
                :MAX_OBSERVATION_EVIDENCE_REFS
            ],
            observation_count=self.observation_count + other.observation_count,
            first_observed_at=first,
            last_observed_at=last,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "observation_id": self.observation_id,
            "operation_id": self.operation_id,
            "identity_alias": self.identity_alias,
            "source_kind": self.source_kind,
            "access_level": self.access_level,
            "response_status": self.response_status,
            "scope_decision": self.scope_decision,
            "replayability": self.replayability,
            "evidence_refs": list(self.evidence_refs),
            "observation_count": self.observation_count,
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> SurfaceAccessObservation:
        _reject_unexpected_fields(
            payload,
            allowed={
                "observation_id",
                "operation_id",
                "identity_alias",
                "source_kind",
                "access_level",
                "response_status",
                "scope_decision",
                "replayability",
                "evidence_refs",
                "observation_count",
                "first_observed_at",
                "last_observed_at",
            },
            label="surface observation",
        )
        observation = cls.create(
            operation_id=payload.get("operation_id"),
            identity_alias=payload.get("identity_alias"),
            source_kind=payload.get("source_kind"),
            access_level=payload.get("access_level"),
            response_status=payload.get("response_status"),
            scope_decision=payload.get("scope_decision"),
            replayability=payload.get("replayability"),
            evidence_refs=_json_object_items(
                payload.get("evidence_refs"),
                label="surface observation evidence_refs",
            ),
            observed_at=payload.get("first_observed_at"),
        )
        if str(payload.get("observation_id") or "") != observation.observation_id:
            raise SurfaceGraphError("surface observation identity does not match its shape")
        count = _positive_int(payload.get("observation_count"), label="observation count")
        last = _safe_timestamp(payload.get("last_observed_at"))
        if bool(observation.first_observed_at) != bool(last):
            raise SurfaceGraphError("surface observation timestamps must both be present or absent")
        if observation.first_observed_at and last and last < observation.first_observed_at:
            raise SurfaceGraphError("surface observation timestamps are reversed")
        return replace(observation, observation_count=count, last_observed_at=last)


@dataclass(slots=True)
class SurfaceGraphState:
    target_origin: str = ""
    operations: dict[str, SurfaceOperation] | None = None
    observations: dict[str, SurfaceAccessObservation] | None = None
    schema_version: int = SURFACE_GRAPH_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SURFACE_GRAPH_VERSION:
            raise SurfaceGraphError("unsupported surface graph version")
        self.target_origin = _optional_origin(self.target_origin)
        initial_operations = {} if self.operations is None else dict(self.operations)
        initial_observations = {} if self.observations is None else dict(self.observations)
        self.operations = {}
        self.observations = {}
        for key, operation in initial_operations.items():
            if str(key) != getattr(operation, "operation_id", None):
                raise SurfaceGraphError("surface operation mapping key does not match its identity")
            self.add_operation(operation)
        for key, observation in initial_observations.items():
            if str(key) != getattr(observation, "observation_id", None):
                raise SurfaceGraphError(
                    "surface observation mapping key does not match its identity"
                )
            self.observe(observation)

    @classmethod
    def for_target(cls, target_url: object) -> SurfaceGraphState:
        origin, _protocol, _route = canonical_operation_url(target_url)
        return cls(target_origin=_target_binding_origin(origin))

    def add_operation(self, operation: SurfaceOperation) -> SurfaceOperation:
        operation = _validated_operation(operation)
        self._assert_target(operation.origin)
        assert self.operations is not None
        assert self.observations is not None
        existing = self.operations.get(operation.operation_id)
        merged = operation if existing is None else existing.merged(operation)
        self.operations[operation.operation_id] = merged
        removed = frozenset(_bound_mapping(self.operations, MAX_SURFACE_OPERATIONS))
        if removed:
            self.observations = {
                key: item
                for key, item in self.observations.items()
                if item.operation_id not in removed
            }
        # The bound evicts oldest entries, so a newly accepted operation survives.
        return self.operations[operation.operation_id]

    def observe(self, observation: SurfaceAccessObservation) -> SurfaceAccessObservation:
        observation = _validated_observation(observation)
        assert self.operations is not None
        assert self.observations is not None
        if observation.operation_id not in self.operations:
            raise SurfaceGraphError("surface observation references an unknown operation")
        existing = self.observations.get(observation.observation_id)
        merged = observation if existing is None else existing.merged(observation)
        self.observations[observation.observation_id] = merged
        _bound_mapping(self.observations, MAX_SURFACE_OBSERVATIONS)
        return self.observations.get(observation.observation_id, merged)

    def add(  # noqa: PLR0913 - convenience API mirrors the typed contracts.
        self,
        *,
        url: object,
        method: object = "GET",
        selector: object = "",
        parameters: Iterable[SurfaceParameter | Mapping[str, object]] = (),
        content_types: Iterable[object] = (),
        header_names: Iterable[object] = (),
        hints: Iterable[object] = (),
        source_kind: object,
        identity_alias: object = "anonymous",
        access_level: object = "declared",
        response_status: object = None,
        scope_decision: object = "unknown",
        replayability: object = "unknown",
        evidence_refs: Iterable[object] = (),
        observed_at: object = "",
    ) -> SurfaceOperation:
        source = _source_kind(source_kind)
        route_only_metadata = source in {"probe", "agent_http_response"}
        operation = self.add_operation(
            SurfaceOperation.create(
                url=url,
                method=method,
                selector=selector,
                # Probe mutations remain access evidence, never discovery
                # metadata. A successful agent-authored HTTP request confirms
                # only the method/route, not its model-authored request fields.
                parameters=() if route_only_metadata else parameters,
                content_types=() if route_only_metadata else content_types,
                header_names=() if route_only_metadata else header_names,
                hints=() if route_only_metadata else hints,
                provenance=(source,),
            )
        )
        self.observe(
            SurfaceAccessObservation.create(
                operation_id=operation.operation_id,
                identity_alias=identity_alias,
                source_kind=source,
                access_level=access_level,
                response_status=response_status,
                scope_decision=scope_decision,
                replayability=replayability,
                evidence_refs=evidence_refs,
                observed_at=observed_at,
            )
        )
        return operation

    def ingest_exchange(self, exchange: CapturedHttpExchange) -> SurfaceOperation:
        successful_agent_http = _successful_agent_http_exchange(exchange)
        source = (
            "agent_http_response"
            if successful_agent_http
            else _exchange_source_kind(exchange.source)
        )
        retain_request_metadata = source not in {"probe", "agent_http_response"}
        parameters = _exchange_parameters(exchange) if retain_request_metadata else ()
        content_types = (
            tuple(
                value
                for name, value in exchange.request_headers
                if name.casefold() == "content-type"
            )
            if retain_request_metadata
            else ()
        )
        return self.add(
            url=exchange.request_url,
            method=exchange.request_method,
            parameters=parameters,
            content_types=content_types,
            header_names=(
                (name for name, _value in exchange.request_headers)
                if retain_request_metadata
                else ()
            ),
            hints=(exchange.request_resource_type,) if retain_request_metadata else (),
            source_kind=source,
            identity_alias=exchange.identity_alias or "anonymous",
            access_level="response" if exchange.response_status is not None else "request",
            response_status=exchange.response_status,
            scope_decision=exchange.scope_decision,
            replayability=exchange.replayability,
            evidence_refs=(exchange.exchange_id, exchange.source_observation_id),
            observed_at=exchange.captured_at,
        )

    def merge_snapshot(self, other: SurfaceGraphState) -> None:
        """Merge a cloned/scoped state without double-counting inherited edges."""
        if other.target_origin:
            self._assert_target(other.target_origin)
        assert self.operations is not None
        assert self.observations is not None
        for operation in (other.operations or {}).values():
            self.add_operation(operation)
        for observation in (other.observations or {}).values():
            if observation.operation_id not in self.operations:
                continue
            current = self.observations.get(observation.observation_id)
            if current is None:
                self.observations[observation.observation_id] = observation
                continue
            first = min(
                (
                    item
                    for item in (current.first_observed_at, observation.first_observed_at)
                    if item
                ),
                default="",
            )
            self.observations[observation.observation_id] = replace(
                current,
                evidence_refs=tuple(
                    sorted(set(current.evidence_refs) | set(observation.evidence_refs))
                )[:MAX_OBSERVATION_EVIDENCE_REFS],
                observation_count=max(current.observation_count, observation.observation_count),
                first_observed_at=first,
                last_observed_at=max(current.last_observed_at, observation.last_observed_at),
            )
        _bound_mapping(self.observations, MAX_SURFACE_OBSERVATIONS)

    def to_json(self) -> dict[str, object]:
        assert self.operations is not None
        assert self.observations is not None
        return {
            "schema": SURFACE_GRAPH_SCHEMA,
            "schema_version": self.schema_version,
            "target_origin": self.target_origin,
            "operations": [self.operations[key].to_json() for key in sorted(self.operations)],
            "observations": [self.observations[key].to_json() for key in sorted(self.observations)],
        }

    def to_prompt_json(self, *, limit: int = 40) -> dict[str, object]:
        assert self.operations is not None
        assert self.observations is not None
        actionable_operations = [
            self.operations[key]
            for key in sorted(self.operations)
            if self.operations[key].actionable
        ]
        operations = actionable_operations[:limit]
        statuses: dict[str, dict[str, list[int]]] = {}
        for observation in self.observations.values():
            if observation.response_status is None:
                continue
            by_identity = statuses.setdefault(observation.operation_id, {})
            bucket = by_identity.setdefault(observation.identity_alias, [])
            if observation.response_status not in bucket:
                bucket.append(observation.response_status)
                bucket.sort()
        return {
            "counts": {
                "operations": len(self.operations),
                "candidate_operations": len(actionable_operations),
                "identity_observations": len(self.observations),
            },
            "operations": [
                {
                    "id": operation.operation_id,
                    "method": operation.method,
                    "route": operation.route_shape,
                    "selector": operation.selector,
                    "parameters": [item.to_json() for item in operation.parameters],
                    "sources": list(operation.provenance),
                    "identity_statuses": statuses.get(operation.operation_id, {}),
                }
                for operation in operations
            ],
        }

    @classmethod
    def from_json(cls, payload: object) -> SurfaceGraphState:
        if payload is None:
            return cls()
        if not isinstance(payload, Mapping):
            raise SurfaceGraphError("surface graph must be a mapping")
        _reject_unexpected_fields(
            payload,
            allowed={
                "schema",
                "schema_version",
                "target_origin",
                "operations",
                "observations",
            },
            label="surface graph",
        )
        if payload.get("schema") != SURFACE_GRAPH_SCHEMA:
            raise SurfaceGraphError("unsupported surface graph schema")
        version = _positive_int(payload.get("schema_version"), label="surface graph version")
        if version != SURFACE_GRAPH_VERSION:
            raise SurfaceGraphError("unsupported surface graph version")
        graph = cls(target_origin=str(payload.get("target_origin") or ""), schema_version=version)
        raw_operations = _json_mapping_items(
            payload.get("operations"),
            label="surface graph operations",
        )
        raw_observations = _json_mapping_items(
            payload.get("observations"),
            label="surface graph observations",
        )
        if len(raw_operations) > MAX_SURFACE_OPERATIONS:
            raise SurfaceGraphError("surface graph contains too many operations")
        if len(raw_observations) > MAX_SURFACE_OBSERVATIONS:
            raise SurfaceGraphError("surface graph contains too many observations")
        for raw_operation in raw_operations:
            graph.add_operation(SurfaceOperation.from_json(raw_operation))
        for raw_observation in raw_observations:
            graph.observe(SurfaceAccessObservation.from_json(raw_observation))
        return graph

    def _assert_target(self, origin: str) -> None:
        binding_origin = _target_binding_origin(origin)
        if not self.target_origin:
            self.target_origin = binding_origin
            return
        if binding_origin != _target_binding_origin(self.target_origin):
            raise SurfaceGraphError("surface operation belongs to another origin")


def canonical_operation_url(url: object) -> tuple[str, str, str]:
    text = str(url or "").strip()
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise SurfaceGraphError("invalid surface operation URL") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        raise SurfaceGraphError("surface operation URL must be absolute HTTP(S) or WS(S)")
    if parsed.username is not None or parsed.password is not None:
        raise SurfaceGraphError("surface operation URL must not contain user information")
    text = _sanitize_operation_url(text, scheme=scheme)
    parsed = urlsplit(text)
    port = parsed.port
    if parsed.hostname is None:
        raise SurfaceGraphError("invalid surface operation URL")
    host = _canonical_host(parsed.hostname)
    default_port = (scheme in {"http", "ws"} and port in (None, 80)) or (
        scheme in {"https", "wss"} and port in (None, 443)
    )
    rendered_host = f"[{host}]" if ":" in host else host
    netloc = rendered_host if default_port else f"{rendered_host}:{port}"
    origin = urlunsplit((scheme, netloc, "", "", ""))
    route_shape = _route_shape(parsed.path)
    return origin, scheme, route_shape


def _sanitize_operation_url(url: str, *, scheme: str) -> str:
    sanitized_scheme = {"ws": "http", "wss": "https"}.get(scheme, scheme)
    parsed = urlsplit(url)
    candidate = urlunsplit(
        (sanitized_scheme, parsed.netloc, parsed.path, parsed.query, "")
    )
    safe = sanitize_url(candidate)
    if safe == REDACTED_URL:
        raise SurfaceGraphError("invalid surface operation URL")
    safe_parsed = urlsplit(safe)
    return urlunsplit((scheme, safe_parsed.netloc, safe_parsed.path, safe_parsed.query, ""))


def _route_shape(path: str) -> str:
    if not path:
        return "/"
    segments: list[str] = []
    previous_segment = ""
    for raw_segment in path.split("/"):
        segment = unquote(raw_segment)
        if not segment:
            segments.append("")
        elif segment in {"{int}", "{uuid}", "{id}", "{segment}"}:
            segments.append(segment)
        elif segment.startswith("[REDACTED") and segment.endswith("]"):
            segments.append("{id}")
        elif _INTEGER_RE.fullmatch(segment):
            segments.append("{int}")
        elif _UUID_RE.fullmatch(segment):
            segments.append("{uuid}")
        elif _OPAQUE_ID_RE.fullmatch(segment):
            segments.append("{id}")
        elif (
            previous_segment in _IDENTITY_PATH_PARENTS
            and segment.casefold() not in _STATIC_COLLECTION_ACTIONS
        ):
            segments.append("{id}")
        elif _STATIC_SEGMENT_RE.fullmatch(segment):
            segments.append(segment)
        else:
            segments.append("{segment}")
        previous_segment = segment.casefold()
    shaped = "/".join(segments)
    return shaped if shaped.startswith("/") else f"/{shaped}"


def _optional_origin(value: object) -> str:
    if not str(value or "").strip():
        return ""
    origin, _protocol, route = canonical_operation_url(value)
    if route != "/":
        raise SurfaceGraphError("surface graph target must be an origin")
    return _target_binding_origin(origin)


def _target_binding_origin(origin: str) -> str:
    """Map WebSocket schemes to their HTTP handshake origin for target ownership."""
    parsed = urlsplit(origin)
    scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme.casefold(), parsed.scheme)
    return urlunsplit((scheme, parsed.netloc, "", "", ""))


def _canonical_host(value: str) -> str:
    host = value.casefold().rstrip(".")
    if not host or any(character in host for character in "\r\n\x00%"):
        raise SurfaceGraphError("invalid surface operation host")
    if ":" in host:
        try:
            return IPv6Address(host).compressed
        except ValueError as exc:
            raise SurfaceGraphError("invalid surface operation host") from exc
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SurfaceGraphError("invalid surface operation host") from exc
    if len(ascii_host) > _MAX_HOST_CHARS or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in ascii_host.split(".")
    ):
        raise SurfaceGraphError("invalid surface operation host")
    return ascii_host


def _parameters(
    values: Iterable[SurfaceParameter | Mapping[str, object]],
) -> tuple[SurfaceParameter, ...]:
    items: set[SurfaceParameter] = set()
    for index, value in enumerate(values):
        if index >= _MAX_INSPECTED_ITEMS:
            break
        item = value if isinstance(value, SurfaceParameter) else SurfaceParameter.from_json(value)
        items.add(item)
        if len(items) > MAX_OPERATION_PARAMETERS:
            items.remove(max(items))
    return tuple(sorted(items))[:MAX_OPERATION_PARAMETERS]


def _exchange_parameters(exchange: CapturedHttpExchange) -> tuple[SurfaceParameter, ...]:
    parsed = urlsplit(exchange.request_url)
    parameters: set[SurfaceParameter] = set()
    query_names = {
        piece.split("=", 1)[0]
        for piece in parsed.query.split("&", _MAX_INSPECTED_ITEMS)[:_MAX_INSPECTED_ITEMS]
        if piece
    }
    for index, name in enumerate(sorted(query_names)):
        if index >= _MAX_INSPECTED_ITEMS:
            break
        try:
            parameters.add(SurfaceParameter.create(name=unquote(name), location="query"))
        except SurfaceGraphError:
            continue
    for index, name in enumerate(exchange.request_body_field_names):
        if index >= _MAX_INSPECTED_ITEMS:
            break
        try:
            parameters.add(SurfaceParameter.create(name=name, location="body"))
        except SurfaceGraphError:
            continue
    return tuple(sorted(parameters))[:MAX_OPERATION_PARAMETERS]


def _content_types(values: Iterable[object]) -> tuple[str, ...]:
    content_types: set[str] = set()
    for index, value in enumerate(values):
        if index >= _MAX_INSPECTED_ITEMS:
            break
        media_type = str(value or "").split(";", 1)[0].strip().casefold()
        if media_type and len(media_type) <= _MAX_METADATA_CHARS and "/" in media_type:
            content_types.add(media_type)
            if len(content_types) > MAX_OPERATION_METADATA_ITEMS:
                content_types.remove(max(content_types))
    return tuple(sorted(content_types))


def _header_names(values: Iterable[object]) -> tuple[str, ...]:
    names: set[str] = set()
    for index, value in enumerate(values):
        if index >= _MAX_INSPECTED_ITEMS:
            break
        name = str(value or "").strip().casefold()
        if name and len(name) <= _MAX_METADATA_CHARS and re.fullmatch(r"[a-z0-9-]+", name):
            names.add(name)
            if len(names) > MAX_OPERATION_METADATA_ITEMS:
                names.remove(max(names))
    return tuple(sorted(names))


def _safe_name(value: object, *, label: str) -> str:
    text = _SAFE_NAME_RE.sub("_", str(value or "").strip())[:_MAX_METADATA_CHARS].strip("_")
    if not text:
        raise SurfaceGraphError(f"{label} is required")
    return text


def _optional_name(value: object) -> str:
    return "" if not str(value or "").strip() else _safe_name(value, label="selector")


def _safe_names(
    values: Iterable[object],
    *,
    limit: int = MAX_OPERATION_METADATA_ITEMS,
) -> tuple[str, ...]:
    names: set[str] = set()
    for index, value in enumerate(values):
        if index >= _MAX_INSPECTED_ITEMS:
            break
        if str(value or "").strip():
            names.add(_safe_name(value, label="surface metadata"))
            if len(names) > limit:
                names.remove(max(names))
    return tuple(sorted(names))


def _source_kind(value: object) -> str:
    source = str(value or "").strip().casefold()
    if source not in _ALLOWED_SOURCE_KINDS:
        raise SurfaceGraphError("unsupported surface provenance source")
    return source


def _source_kinds(values: Iterable[object]) -> tuple[str, ...]:
    sources: set[str] = set()
    for index, value in enumerate(values):
        if index >= len(_ALLOWED_SOURCE_KINDS):
            break
        sources.add(_source_kind(value))
    return tuple(sorted(sources))


def _exchange_source_kind(source: object) -> str:
    text = str(source or "").casefold()
    if "browser" in text:
        return "browser"
    if "external" in text or "tool" in text:
        return "external_tool"
    return "probe"


def _successful_agent_http_exchange(exchange: CapturedHttpExchange) -> bool:
    status = exchange.response_status
    return (
        exchange.source == "agent_http"
        and status is not None
        and _MIN_SUCCESSFUL_HTTP_STATUS <= status < _FIRST_UNSUCCESSFUL_HTTP_STATUS
    )


def _optional_status(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        status = int(str(value))
    except (TypeError, ValueError) as exc:
        raise SurfaceGraphError("invalid response status") from exc
    if not _MIN_HTTP_STATUS <= status <= _MAX_HTTP_STATUS:
        raise SurfaceGraphError("invalid response status")
    return status


def _safe_timestamp(value: object) -> str:
    text = str(value or "").strip()
    if len(text) > _MAX_TIMESTAMP_CHARS or any(character in text for character in "\r\n\x00"):
        raise SurfaceGraphError("invalid surface observation timestamp")
    if not text:
        return ""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SurfaceGraphError("invalid surface observation timestamp") from exc
    if moment.tzinfo is None:
        raise SurfaceGraphError("surface observation timestamp must include a timezone")
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _boolean(value: object, *, label: str) -> bool:
    if value in (None, "", False, 0):
        return False
    if value in (True, 1):
        return True
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized == "false":
            return False
        if normalized == "true":
            return True
    raise SurfaceGraphError(f"invalid {label}")


def _positive_int(value: object, *, label: str) -> int:
    try:
        result = int(str(value))
    except (TypeError, ValueError) as exc:
        raise SurfaceGraphError(f"invalid {label}") from exc
    if result <= 0:
        raise SurfaceGraphError(f"invalid {label}")
    return result


def _stable_id(kind: str, *parts: str) -> str:
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return f"{'op' if kind == 'operation' else 'so'}_{digest[:24]}"


def _bound_mapping(values: dict[str, Any], limit: int) -> tuple[str, ...]:
    removed: list[str] = []
    while len(values) > limit:
        oldest = next(iter(values))
        values.pop(oldest)
        removed.append(oldest)
    return tuple(removed)


def _validated_operation(operation: object) -> SurfaceOperation:
    if not isinstance(operation, SurfaceOperation):
        raise SurfaceGraphError("surface graph accepts only typed operations")
    try:
        canonical = SurfaceOperation.from_json(operation.to_json())
    except (AttributeError, TypeError, SurfaceGraphError) as exc:
        raise SurfaceGraphError("surface operation is not canonical") from exc
    if canonical != operation:
        raise SurfaceGraphError("surface operation is not canonical")
    return canonical


def _validated_observation(observation: object) -> SurfaceAccessObservation:
    if not isinstance(observation, SurfaceAccessObservation):
        raise SurfaceGraphError("surface graph accepts only typed observations")
    try:
        canonical = SurfaceAccessObservation.from_json(observation.to_json())
    except (AttributeError, TypeError, SurfaceGraphError) as exc:
        raise SurfaceGraphError("surface observation is not canonical") from exc
    if canonical != observation:
        raise SurfaceGraphError("surface observation is not canonical")
    return canonical


def _reject_unexpected_fields(
    payload: Mapping[str, object],
    *,
    allowed: set[str],
    label: str,
) -> None:
    if any(not isinstance(key, str) or key not in allowed for key in payload):
        raise SurfaceGraphError(f"{label} contains unsupported fields")


def _json_mapping_items(
    value: object,
    *,
    label: str,
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list):
        raise SurfaceGraphError(f"{label} must be an array")
    if any(not isinstance(item, Mapping) for item in value):
        raise SurfaceGraphError(f"{label} must contain only objects")
    return tuple(item for item in value if isinstance(item, Mapping))


def _json_object_items(value: object, *, label: str) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise SurfaceGraphError(f"{label} must be an array")
    return tuple(value)


def _mapping_items(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _object_items(value: object) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return ()
    return tuple(value)


__all__ = [
    "MAX_SURFACE_OBSERVATIONS",
    "MAX_SURFACE_OPERATIONS",
    "SURFACE_GRAPH_SCHEMA",
    "SURFACE_GRAPH_VERSION",
    "SurfaceAccessObservation",
    "SurfaceGraphError",
    "SurfaceGraphState",
    "SurfaceOperation",
    "SurfaceParameter",
    "canonical_operation_url",
]
