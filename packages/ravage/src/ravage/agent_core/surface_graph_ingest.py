# ruff: noqa: EM101, EM102, TRY003
"""Typed ingestion adapters for the canonical surface graph."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

from ravage.agent_core.surface_graph import (
    MAX_SURFACE_OBSERVATIONS,
    MAX_SURFACE_OPERATIONS,
    SurfaceAccessObservation,
    SurfaceGraphError,
    SurfaceGraphState,
    SurfaceOperation,
    SurfaceParameter,
)
from ravage.traffic.contracts import CapturedHttpExchange

SURFACE_OBSERVATION_INPUT_SCHEMA = "ravage.surface-observation-input.v1"
SURFACE_OBSERVATION_BATCH_SCHEMA = "ravage.surface-observation-batch.v1"
_HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_OPENAPI_METHODS = frozenset(method.casefold() for method in _HTTP_METHODS)
_GRAPHQL_TYPE_RE = re.compile(
    r"\btype\s+(Query|Mutation|Subscription)\s*\{(?P<body>.*?)\}", re.DOTALL
)
_GRAPHQL_FIELD_RE = re.compile(r"(?m)^\s*([_A-Za-z][_0-9A-Za-z]*)\s*(?:\(([^)]*)\))?\s*:")
_GRAPHQL_ARG_RE = re.compile(r"([_A-Za-z][_0-9A-Za-z]*)\s*:\s*([\[\]!_0-9A-Za-z]+)")
_GRAPHQL_NAME_RE = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")
_GRAPHQL_OPERATION_KINDS = {
    "query": "Query",
    "mutation": "Mutation",
    "subscription": "Subscription",
}
_MAX_DOCUMENT_INSPECTIONS = 4_096
_MAX_COLLECTION_ITEMS = 512
_MAX_JAVASCRIPT_SOURCE_CHARS = 262_144
_MAX_GRAPHQL_SOURCE_CHARS = 524_288
_MAX_EXTERNAL_ARRAY_ITEMS = 64
_MAX_CAPTURED_EXCHANGE_IMPORTS = 2_048
_MAX_OPENAPI_REF_DEPTH = 32
_MAX_OPENAPI_REF_CHARS = 512
_MAX_SOURCE_CODE_CANDIDATES = 512
_MAX_SOURCE_ROUTE_CHARS = 1_024
_MAX_SOURCE_FILE_CHARS = 240
_MAX_SOURCE_LINE = 10_000_000
_SOURCE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$")
_SOURCE_INPUT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:\[\]-]{0,127}$")
_SOURCE_FILE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.@+\-\[\]()$]+$")
_SOURCE_CANDIDATE_REQUIRED_FIELDS = frozenset(
    {
        "candidate_id",
        "family",
        "input_location",
        "input_name",
        "line",
        "method",
        "relative_file",
        "route",
    }
)
_SOURCE_CANDIDATE_OPTIONAL_FIELDS = frozenset({"sink_kind"})


@dataclass(slots=True)
class _InspectionBudget:
    remaining: int = dataclass_field(default_factory=lambda: _MAX_DOCUMENT_INSPECTIONS)

    def take(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


@dataclass(frozen=True, slots=True)
class _SourceCodeCandidate:
    candidate_id: str
    family: str
    input_location: str
    input_name: str
    line: int
    method: str
    relative_file: str
    route: str
    sink_kind: str = ""

    @classmethod
    def from_mapping(cls, value: object) -> _SourceCodeCandidate:
        if not isinstance(value, Mapping):
            raise SurfaceGraphError("source code candidate must be a mapping")
        fields = set(value)
        allowed = _SOURCE_CANDIDATE_REQUIRED_FIELDS | _SOURCE_CANDIDATE_OPTIONAL_FIELDS
        if any(not isinstance(field, str) for field in fields) or fields - allowed:
            raise SurfaceGraphError("source code candidate contains unsupported fields")
        if missing := _SOURCE_CANDIDATE_REQUIRED_FIELDS - fields:
            raise SurfaceGraphError(
                f"source code candidate is missing required field: {min(missing)}"
            )

        method = _source_identifier(value.get("method"), label="source method").upper()
        if method not in _HTTP_METHODS:
            raise SurfaceGraphError("source code candidate has unsupported HTTP method")
        family = _source_identifier(value.get("family"), label="source family").casefold()
        candidate_id = _source_identifier(
            value.get("candidate_id"),
            label="source candidate id",
        )
        input_name = _source_input_name(value.get("input_name"))
        input_location = _source_input_location(value.get("input_location"))
        sink_kind = (
            _source_identifier(value.get("sink_kind"), label="source sink kind").casefold()
            if "sink_kind" in value
            else ""
        )
        line = _source_line(value.get("line"))
        return cls(
            candidate_id=candidate_id,
            family=family,
            input_location=input_location,
            input_name=input_name,
            line=line,
            method=method,
            relative_file=_source_relative_file(value.get("relative_file")),
            route=_source_route(value.get("route")),
            sink_kind=sink_kind,
        )

    @property
    def parameter(self) -> SurfaceParameter:
        return SurfaceParameter.create(name=self.input_name, location=self.input_location)

    @property
    def content_types(self) -> tuple[str, ...]:
        if self.input_location == "body":
            return ("application/json",)
        if self.input_location == "form":
            return ("application/x-www-form-urlencoded",)
        return ()

    @property
    def hints(self) -> tuple[str, ...]:
        # Only validated structural identifiers enter the graph.  Source text,
        # values, defaults, examples, and absolute filesystem paths are not part
        # of this contract and therefore cannot leak through these hints.
        hints = [
            "source_code",
            self.family,
            f"source_family:{self.family}",
            f"source_location:{self.relative_file}:{self.line}",
            f"source_candidate:{self.candidate_id}",
        ]
        if self.sink_kind:
            hints.extend((self.sink_kind, f"source_sink:{self.sink_kind}"))
        return tuple(hints)


@dataclass(slots=True)
class _OpenAPIResolver:
    """Resolve only bounded, in-document JSON references."""

    document: Mapping[str, object]
    budget: _InspectionBudget

    def mapping(  # noqa: C901, PLR0911 - strict bounded JSON-pointer traversal.
        self,
        value: object,
        *,
        seen: frozenset[str] = frozenset(),
        depth: int = 0,
    ) -> Mapping[str, object] | None:
        if not isinstance(value, Mapping):
            return None
        raw_ref = value.get("$ref")
        if raw_ref is None:
            return value
        reference = str(raw_ref)
        if (
            not reference.startswith("#/")
            or len(reference) > _MAX_OPENAPI_REF_CHARS
            or depth >= _MAX_OPENAPI_REF_DEPTH
            or reference in seen
            or not self.budget.take()
        ):
            return None
        target: object = self.document
        for raw_token in unquote(reference[2:]).split("/"):
            if not self.budget.take() or re.search(r"~(?![01])", raw_token):
                return None
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if isinstance(target, Mapping):
                if token not in target:
                    return None
                target = target[token]
            elif isinstance(target, list) and token.isdecimal():
                index = int(token)
                if index >= len(target):
                    return None
                target = target[index]
            else:
                return None
        resolved = self.mapping(
            target,
            seen=seen | {reference},
            depth=depth + 1,
        )
        if resolved is None:
            return None
        siblings = {str(key): item for key, item in value.items() if key != "$ref"}
        return dict(resolved) | siblings


@dataclass(frozen=True, slots=True)
class SurfaceObservationInput:
    """Strict value-free adapter contract for supported external tools."""

    url: str
    method: str
    source_kind: str = "external_tool"
    identity_alias: str = "anonymous"
    access_level: str = "declared"
    response_status: int | None = None
    scope_decision: str = "unknown"
    replayability: str = "unknown"
    selector: str = ""
    parameters: tuple[SurfaceParameter, ...] = ()
    content_types: tuple[str, ...] = ()
    header_names: tuple[str, ...] = ()
    hints: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    observed_at: str = ""

    @classmethod
    def from_json(cls, payload: object) -> SurfaceObservationInput:
        if not isinstance(payload, Mapping):
            raise SurfaceGraphError("external surface observation must be a mapping")
        if payload.get("schema") != SURFACE_OBSERVATION_INPUT_SCHEMA:
            raise SurfaceGraphError("unsupported external surface observation schema")
        unexpected = set(payload) - {
            "schema",
            "url",
            "method",
            "source_kind",
            "identity_alias",
            "access_level",
            "response_status",
            "scope_decision",
            "replayability",
            "selector",
            "parameters",
            "content_types",
            "header_names",
            "hints",
            "evidence_refs",
            "observed_at",
        }
        if unexpected:
            raise SurfaceGraphError("external surface observation contains unsupported fields")
        parameters = _external_parameters(payload.get("parameters"))
        source_kind = str(payload.get("source_kind") or "external_tool")
        if source_kind != "external_tool":
            raise SurfaceGraphError("external adapter cannot claim an internal provenance source")
        content_types = _external_string_items(payload.get("content_types"), label="content_types")
        header_names = _external_string_items(payload.get("header_names"), label="header_names")
        hints = _external_string_items(payload.get("hints"), label="hints")
        evidence_refs = _external_string_items(
            payload.get("evidence_refs"),
            label="evidence_refs",
        )
        operation = SurfaceOperation.create(
            url=payload.get("url"),
            method=payload.get("method") or "GET",
            selector=payload.get("selector") or "",
            parameters=parameters,
            content_types=content_types,
            header_names=header_names,
            hints=hints,
            provenance=(source_kind,),
        )
        observation = SurfaceAccessObservation.create(
            operation_id=operation.operation_id,
            identity_alias=payload.get("identity_alias") or "anonymous",
            source_kind=source_kind,
            access_level=payload.get("access_level") or "declared",
            response_status=payload.get("response_status"),
            scope_decision=payload.get("scope_decision") or "unknown",
            replayability=payload.get("replayability") or "unknown",
            evidence_refs=evidence_refs,
            observed_at=payload.get("observed_at") or "",
        )
        return cls(
            url=operation.structural_url,
            method=operation.method,
            source_kind=source_kind,
            identity_alias=observation.identity_alias,
            access_level=observation.access_level,
            response_status=observation.response_status,
            scope_decision=observation.scope_decision,
            replayability=observation.replayability,
            selector=operation.selector,
            parameters=operation.parameters,
            content_types=operation.content_types,
            header_names=operation.header_names,
            hints=operation.hints,
            evidence_refs=observation.evidence_refs,
            observed_at=observation.first_observed_at,
        )

    def ingest(self, graph: SurfaceGraphState) -> SurfaceOperation:
        return graph.add(
            url=self.url,
            method=self.method,
            selector=self.selector,
            parameters=self.parameters,
            content_types=self.content_types,
            header_names=self.header_names,
            hints=self.hints,
            source_kind=self.source_kind,
            identity_alias=self.identity_alias,
            access_level=self.access_level,
            response_status=self.response_status,
            scope_decision=self.scope_decision,
            replayability=self.replayability,
            evidence_refs=self.evidence_refs,
            observed_at=self.observed_at,
        )


def ingest_surface_observation_batch(
    graph: SurfaceGraphState,
    payload: object,
    *,
    identity_alias: str = "anonymous",
    evidence_ref: str = "",
) -> int:
    """
    Atomically ingest a strict, value-free external observation batch.

    The caller owns the identity and evidence context.  Adapter-provided identity
    aliases are parsed for contract validity but never trusted at this runtime
    boundary.  All observations are staged against the graph target before the
    canonical state is mutated, so a cross-target or malformed item cannot leave
    a partially imported batch behind.
    """
    if not graph.target_origin:
        raise SurfaceGraphError("external surface batch requires a target-bound graph")
    if not isinstance(payload, Mapping):
        raise SurfaceGraphError("external surface observation batch must be a mapping")
    if payload.get("schema") != SURFACE_OBSERVATION_BATCH_SCHEMA:
        raise SurfaceGraphError("unsupported external surface observation batch schema")
    unexpected = set(payload) - {"schema", "observations"}
    if unexpected:
        raise SurfaceGraphError("external surface observation batch contains unsupported fields")
    raw_observations = payload.get("observations")
    if not isinstance(raw_observations, list):
        raise SurfaceGraphError("external surface observation batch observations must be a list")
    if len(raw_observations) > _MAX_EXTERNAL_ARRAY_ITEMS:
        raise SurfaceGraphError("external surface observation batch exceeds item limit")
    observations = tuple(SurfaceObservationInput.from_json(item) for item in raw_observations)
    staged = SurfaceGraphState.for_target(graph.target_origin)
    for observation in observations:
        trusted = replace(
            observation,
            identity_alias=identity_alias,
            evidence_refs=tuple(
                item for item in (*observation.evidence_refs, evidence_ref) if item
            ),
        )
        trusted.ingest(staged)
    graph.merge_snapshot(staged)
    return len(observations)


def ingest_captured_exchanges(
    graph: SurfaceGraphState,
    exchanges: Iterable[CapturedHttpExchange],
) -> int:
    """
    Import a bounded batch of already-captured, typed HTTP exchanges.

    This adapter performs no I/O.  It stages the immutable capture contracts
    against the graph target before merging, preserving browser/probe provenance
    without allowing a malformed or cross-target exchange to partially import.
    """
    if not graph.target_origin:
        raise SurfaceGraphError("captured exchange import requires a target-bound graph")
    staged = SurfaceGraphState.for_target(graph.target_origin)
    imported = 0
    for index, exchange in enumerate(exchanges):
        if index >= _MAX_CAPTURED_EXCHANGE_IMPORTS:
            break
        if not isinstance(exchange, CapturedHttpExchange):
            raise SurfaceGraphError("captured exchange import requires typed exchanges")
        staged.ingest_exchange(exchange)
        imported += 1
    graph.merge_snapshot(staged)
    return imported


def ingest_source_code_candidates(
    graph: SurfaceGraphState,
    candidates: Iterable[Mapping[str, object]],
    *,
    target_url: str,
) -> int:
    """
    Atomically ingest bounded, value-free routes derived from declared source.

    ``target_url`` is the sole authority for network origin.  Candidate mappings
    may describe only a relative route, one input, and a relative code location;
    they cannot provide a URL, origin, request value, response, or evidence.
    Static source establishes useful attack-surface candidates, but every access
    observation remains declaration-only until a managed runtime validates it.
    """
    staged = SurfaceGraphState.for_target(target_url)
    if graph.target_origin and staged.target_origin != graph.target_origin:
        raise SurfaceGraphError("source code target does not match surface graph target")

    existing_operation_ids = set(graph.operations or {})
    existing_observation_ids = set(graph.observations or {})
    operation_slots = max(0, MAX_SURFACE_OPERATIONS - len(existing_operation_ids))
    observation_slots = max(0, MAX_SURFACE_OBSERVATIONS - len(existing_observation_ids))
    staged_operation_ids: set[str] = set()
    staged_observation_ids: set[str] = set()
    imported = 0
    for index, raw_candidate in enumerate(candidates):
        if index >= _MAX_SOURCE_CODE_CANDIDATES:
            raise SurfaceGraphError("source code candidates exceed the item limit")
        candidate = _SourceCodeCandidate.from_mapping(raw_candidate)
        url = f"{staged.target_origin}{candidate.route}"
        operation = SurfaceOperation.create(
            url=url,
            method=candidate.method,
            parameters=(candidate.parameter,),
            content_types=candidate.content_types,
            hints=candidate.hints,
            provenance=("source_code",),
        )
        observation = SurfaceAccessObservation.create(
            operation_id=operation.operation_id,
            identity_alias="anonymous",
            source_kind="source_code",
            access_level="declared",
            response_status=None,
            scope_decision="unknown",
            replayability="unknown",
            evidence_refs=(),
        )
        operation_is_new = operation.operation_id not in (
            existing_operation_ids | staged_operation_ids
        )
        observation_is_new = observation.observation_id not in (
            existing_observation_ids | staged_observation_ids
        )
        if (operation_is_new and not operation_slots) or (
            observation_is_new and not observation_slots
        ):
            continue
        staged.add(
            url=url,
            method=candidate.method,
            parameters=(candidate.parameter,),
            content_types=candidate.content_types,
            hints=candidate.hints,
            source_kind="source_code",
            identity_alias="anonymous",
            access_level="declared",
            response_status=None,
            scope_decision="unknown",
            replayability="unknown",
            evidence_refs=(),
        )
        if operation_is_new:
            operation_slots -= 1
            staged_operation_ids.add(operation.operation_id)
        if observation_is_new:
            observation_slots -= 1
            staged_observation_ids.add(observation.observation_id)
        imported += 1

    graph.merge_snapshot(staged)
    return imported


def ingest_recon_surface(
    graph: SurfaceGraphState,
    recon_payload: Mapping[str, object],
    *,
    identity_alias: str = "anonymous",
) -> None:
    """Ingest native recon pages, links, scripts, forms, and JS templates."""
    for page_index, page in enumerate(
        _mapping_items(recon_payload.get("pages"), limit=_MAX_COLLECTION_ITEMS)
    ):
        page_url = str(page.get("final_url") or page.get("url") or "")
        page_ref = f"recon_page_{page_index}"
        _try_add(
            graph,
            url=page_url,
            method="GET",
            parameters=_query_parameters(page_url),
            header_names=_header_keys(page.get("headers")),
            hints=("page",),
            source_kind="native_recon",
            identity_alias=identity_alias,
            access_level="response" if page.get("status") is not None else "request",
            response_status=page.get("status"),
            scope_decision="allowed",
            replayability="safe",
            evidence_refs=(page_ref,),
        )
        for link in _string_items(page.get("links")):
            _try_add(
                graph,
                url=urljoin(page_url, link),
                method="GET",
                parameters=_query_parameters(urljoin(page_url, link)),
                hints=("link",),
                source_kind="native_recon",
                identity_alias=identity_alias,
                evidence_refs=(page_ref,),
            )
        for script in _string_items(page.get("scripts")):
            _try_add(
                graph,
                url=urljoin(page_url, script),
                method="GET",
                hints=("script",),
                source_kind="native_recon",
                identity_alias=identity_alias,
                evidence_refs=(page_ref,),
            )
        for form_index, form in enumerate(_mapping_items(page.get("forms"))):
            inputs = _mapping_items(form.get("inputs"))
            parameters = _parameter_items(
                inputs,
                location=(
                    "query"
                    if str(form.get("method") or "GET").upper() in {"GET", "HEAD"}
                    else "form"
                ),
                default_type="string",
            )
            enctype = str(form.get("enctype") or "").strip()
            _try_add(
                graph,
                url=urljoin(page_url, str(form.get("action") or page_url)),
                method=form.get("method") or "GET",
                parameters=parameters,
                content_types=(enctype,) if enctype else (),
                hints=("form",),
                source_kind="native_recon",
                identity_alias=identity_alias,
                evidence_refs=(page_ref, f"recon_form_{page_index}_{form_index}"),
            )
        for template_index, template in enumerate(_mapping_items(page.get("request_templates"))):
            source_kind = (
                "javascript_external"
                if str(template.get("source") or "").casefold() == "javascript_external"
                else "javascript_inline"
            )
            fields = template.get("fields")
            parameters = _field_parameters(fields, location="body")
            headers = template.get("headers")
            _try_add(
                graph,
                url=urljoin(page_url, str(template.get("url") or "")),
                method=template.get("method") or "GET",
                parameters=parameters,
                header_names=(headers.keys() if isinstance(headers, Mapping) else ()),
                hints=("javascript",),
                source_kind=source_kind,
                identity_alias=identity_alias,
                evidence_refs=(page_ref, f"js_template_{page_index}_{template_index}"),
            )


def ingest_javascript_source(  # noqa: PLR0913
    graph: SurfaceGraphState,
    *,
    script_text: str,
    base_url: str,
    identity_alias: str = "anonymous",
    external: bool = True,
    evidence_ref: str = "",
) -> int:
    """Extract request templates from bounded JS already fetched by a managed lane."""
    from ravage.web_core.recon import parse_javascript_request_templates  # noqa: PLC0415

    # This API never fetches on its own: callers must obtain source through a
    # metered transport.  The hard byte bound prevents parser/token blowups.
    templates = parse_javascript_request_templates(script_text[:_MAX_JAVASCRIPT_SOURCE_CHARS])
    source_kind = "javascript_external" if external else "javascript_inline"
    added = 0
    for index, template in enumerate(templates[:128]):
        fields = template.get("fields")
        parameters = _field_parameters(fields, location="body")
        headers = template.get("headers")
        operation = _try_add(
            graph,
            url=urljoin(base_url, str(template.get("url") or "")),
            method=template.get("method") or "GET",
            parameters=parameters,
            header_names=(headers.keys() if isinstance(headers, Mapping) else ()),
            hints=("javascript",),
            source_kind=source_kind,
            identity_alias=identity_alias,
            evidence_refs=tuple(item for item in (evidence_ref, f"js_template_{index}") if item),
        )
        added += operation is not None
    return added


def ingest_openapi_document(  # noqa: C901 - bounded v2/v3 shape adapter.
    graph: SurfaceGraphState,
    document: Mapping[str, object],
    *,
    document_url: str,
    identity_alias: str = "anonymous",
    evidence_ref: str = "openapi_document",
) -> int:
    """Ingest OpenAPI v2/v3 path and parameter shapes without examples/defaults."""
    base_url = _openapi_base_url(document, document_url=document_url)
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return 0
    budget = _InspectionBudget()
    resolver = _OpenAPIResolver(document=document, budget=budget)
    added = 0
    for raw_path, raw_path_item in paths.items():
        if not budget.take():
            break
        path_item = resolver.mapping(raw_path_item)
        if path_item is None:
            continue
        shared_parameters = _openapi_parameters(
            path_item.get("parameters"),
            budget=budget,
            resolver=resolver,
        )
        for raw_method, candidate_operation in path_item.items():
            if not budget.take():
                break
            method = str(raw_method).casefold()
            if method not in _OPENAPI_METHODS:
                continue
            raw_operation = resolver.mapping(candidate_operation)
            if raw_operation is None:
                continue
            parameters = (
                *shared_parameters,
                *_openapi_parameters(
                    raw_operation.get("parameters"),
                    budget=budget,
                    resolver=resolver,
                ),
            )
            request_body = resolver.mapping(raw_operation.get("requestBody"))
            content_types: tuple[str, ...] = ()
            if isinstance(request_body, Mapping):
                content = request_body.get("content")
                if isinstance(content, Mapping):
                    content_types = _bounded_mapping_keys(content)
                    parameters = (
                        *parameters,
                        *_openapi_body_parameters(
                            content,
                            budget=budget,
                            resolver=resolver,
                        ),
                    )
            consumes = raw_operation.get("consumes") or document.get("consumes")
            if not content_types:
                content_types = _string_items(consumes)
            operation_id = str(raw_operation.get("operationId") or "")
            hints = tuple(item for item in ("api", operation_id) if item)
            operation = _try_add(
                graph,
                url=urljoin(base_url.rstrip("/") + "/", str(raw_path).lstrip("/")),
                method=method.upper(),
                parameters=parameters,
                content_types=content_types,
                hints=hints,
                source_kind="openapi",
                identity_alias=identity_alias,
                evidence_refs=(evidence_ref,),
            )
            added += operation is not None
    return added


def ingest_graphql_schema(
    graph: SurfaceGraphState,
    schema: Mapping[str, object] | str,
    *,
    endpoint_url: str,
    identity_alias: str = "anonymous",
    evidence_ref: str = "graphql_schema",
) -> int:
    """Ingest GraphQL selectors/arguments plus their HTTP transport operation."""
    budget = _InspectionBudget()
    selectors = (
        _graphql_introspection_selectors(schema, budget=budget)
        if isinstance(schema, Mapping)
        else _graphql_sdl_selectors(schema, budget=budget)
    )
    added = 0
    for selector, parameters in selectors:
        operation = _try_add(
            graph,
            url=endpoint_url,
            method="POST",
            selector=selector,
            parameters=parameters,
            content_types=("application/json", "application/graphql"),
            hints=("api", "graphql"),
            source_kind="graphql",
            identity_alias=identity_alias,
            replayability="requires_authorization",
            evidence_refs=(evidence_ref,),
        )
        added += operation is not None
    return added


def ingest_probe_result(  # noqa: C901 - typed finding adapters remain explicit.
    graph: SurfaceGraphState,
    probe_payload: Mapping[str, object],
    *,
    identity_alias: str = "anonymous",
    source_observation_id: str = "",
) -> int:
    """Retain probe attempts while promoting only exact typed surface findings."""
    probe_name = str(probe_payload.get("probe") or "probe")
    refs = tuple(item for item in (source_observation_id, probe_name) if item)
    added = 0
    for request in _mapping_items(probe_payload.get("requests")):
        url = str(request.get("url") or "")
        method = str(request.get("method") or "GET").upper()
        scope_decision = str(request.get("scope_decision") or "unknown")
        request_sent = request.get("request_sent") is not False
        operation = _try_add(
            graph,
            url=url,
            method=method,
            # Attack probes deliberately mutate URLs, field names, and headers.
            # Preserve their operation/observation evidence, but do not merge
            # those attacker-generated attributes into a trusted operation that
            # native recon, browser capture, or a typed adapter already mapped.
            parameters=(),
            header_names=(),
            hints=(),
            source_kind="probe",
            identity_alias=identity_alias,
            access_level=(
                "response"
                if request.get("status") is not None
                else "request"
                if request_sent
                else "declared"
            ),
            response_status=request.get("status"),
            scope_decision=scope_decision,
            replayability=(
                "not_replayable"
                if not request_sent or scope_decision.casefold() == "blocked"
                else "safe"
                if method in {"GET", "HEAD", "OPTIONS"}
                else "requires_authorization"
            ),
            evidence_refs=refs,
        )
        added += operation is not None
    for finding in _mapping_items(probe_payload.get("findings")):
        finding_type = str(finding.get("type") or "")
        if finding_type == "surface_observation_batch":
            # Only executor-owned native probe JSON reaches this adapter.  The
            # strict public batch contract still revalidates every item and the
            # runtime-provided identity overrides adapter-provided aliases.
            with suppress(SurfaceGraphError):
                added += ingest_surface_observation_batch(
                    graph,
                    finding.get("batch"),
                    identity_alias=identity_alias,
                    evidence_ref=source_observation_id or probe_name,
                )
            continue
        if finding_type == "openapi_route_signal":
            for route in _mapping_items(finding.get("routes")):
                parameters = _parameter_items(
                    _mapping_items(route.get("parameters")),
                    location="query",
                    location_key="location",
                )
                content_type = str(route.get("content_type") or "")
                operation = _try_add(
                    graph,
                    url=route.get("url")
                    or urljoin(graph.target_origin + "/", str(route.get("path") or "")),
                    method=route.get("method") or "GET",
                    parameters=parameters,
                    content_types=(content_type,) if content_type else (),
                    hints=("api", "openapi"),
                    source_kind="openapi",
                    identity_alias=identity_alias,
                    evidence_refs=refs,
                )
                added += operation is not None
        if finding_type == "graphql_schema_mapped":
            endpoint = str(finding.get("url") or "")
            for shape in _mapping_items(
                finding.get("operations"),
                limit=_MAX_COLLECTION_ITEMS,
            ):
                operation_kind = str(shape.get("operation_type") or "").casefold()
                field_name = str(shape.get("field_name") or "")
                selector_prefix = _GRAPHQL_OPERATION_KINDS.get(operation_kind)
                if selector_prefix is None or not _GRAPHQL_NAME_RE.fullmatch(field_name):
                    continue
                parameters = _graphql_probe_parameters(shape.get("arguments"))
                operation = _try_add(
                    graph,
                    url=endpoint,
                    method="POST",
                    selector=f"{selector_prefix}.{field_name}",
                    parameters=parameters,
                    content_types=("application/json", "application/graphql"),
                    hints=("api", "graphql"),
                    source_kind="graphql",
                    identity_alias=identity_alias,
                    replayability="requires_authorization",
                    evidence_refs=refs,
                )
                added += operation is not None
        if finding_type == "graphql_mutation_discovered":
            endpoint = str(finding.get("url") or "")
            for mutation in _string_items(finding.get("mutations")):
                operation = _try_add(
                    graph,
                    url=endpoint,
                    method="POST",
                    selector=f"Mutation.{mutation}",
                    content_types=("application/json",),
                    hints=("api", "graphql"),
                    source_kind="graphql",
                    identity_alias=identity_alias,
                    evidence_refs=refs,
                )
                added += operation is not None
    return added


def project_surface_graph(
    graph: SurfaceGraphState,
    legacy_surface: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Additively project canonical operations into the legacy planner surface."""
    legacy = dict(legacy_surface or {})
    operations = graph.operations or {}
    if not operations:
        # A scoped action that learned no surface must remain a semantic no-op.
        return legacy
    existing_endpoints = {
        str(item.get("url") or ""): _copy_legacy_record(
            item,
            list_fields=("sources", "hints"),
        )
        for item in _mapping_items(legacy.get("endpoints"))[:512]
        if str(item.get("url") or "")
    }
    templates_by_key = {
        (
            str(item.get("method") or "GET").upper(),
            str(item.get("url") or ""),
            str(item.get("selector") or ""),
        ): _copy_legacy_record(
            item,
            list_fields=("content_types", "hints"),
            mapping_fields=("fields", "input_locations"),
        )
        for item in _mapping_items(legacy.get("request_templates"))[:512]
    }
    parameters_by_name = {
        str(item.get("name") or ""): _copy_legacy_record(
            item,
            list_fields=(
                "sources",
                "locations",
                "hints",
                "data_types",
                "input_locations",
                "methods",
            ),
        )
        for item in _mapping_items(legacy.get("parameters"))[:512]
        if str(item.get("name") or "")
    }
    for operation in (
        operations[key]
        for key in sorted(operations)
        if _operation_is_actionable_projection(operations[key])
    ):
        url = operation.structural_url
        structural = "{" in operation.route_shape
        source_backed = "source_code" in operation.provenance
        endpoint = existing_endpoints.setdefault(
            url,
            {
                "url": url,
                "sources": list(operation.provenance),
                "hints": list(operation.hints),
                "priority": 0,
                "structural": structural,
            },
        )
        endpoint["sources"] = sorted(
            set(_string_items(endpoint.get("sources"))) | set(operation.provenance)
        )
        endpoint["hints"] = sorted(set(_string_items(endpoint.get("hints"))) | set(operation.hints))
        endpoint["structural"] = bool(endpoint.get("structural")) or structural
        if source_backed:
            endpoint["priority"] = max(
                300,
                _projection_priority(endpoint.get("priority")),
            )
        if not structural:
            template_key = (operation.method, url, operation.selector)
            template = templates_by_key.setdefault(
                template_key,
                {
                    "source": "surface_graph",
                    "method": operation.method,
                    "url": url,
                    "fields": {},
                    **({"selector": operation.selector} if operation.selector else {}),
                },
            )
            if source_backed:
                _project_source_template(template, operation)
            for parameter in operation.parameters:
                _project_template_parameter(
                    template,
                    parameter,
                    include_location=source_backed,
                )
        for parameter in operation.parameters:
            payload = parameters_by_name.setdefault(
                parameter.name,
                {
                    "name": parameter.name,
                    "sources": [],
                    "locations": [],
                    "hints": [],
                    "data_types": [],
                    "required": False,
                    "priority": 0,
                },
            )
            source = f"surface_graph:{parameter.location}"
            payload["sources"] = sorted(
                set(_string_items(payload.get("sources")))
                | {source}
                | ({"source_code"} if source_backed else set())
            )[:16]
            payload["locations"] = sorted(set(_string_items(payload.get("locations"))) | {url})[:16]
            payload["data_types"] = sorted(
                set(_string_items(payload.get("data_types"))) | {parameter.data_type}
            )[:16]
            payload["required"] = bool(payload.get("required")) or parameter.required
            if source_backed:
                _project_source_parameter(payload, operation, parameter)
    legacy["endpoints"] = list(existing_endpoints.values())[:512]
    legacy["request_templates"] = list(templates_by_key.values())[:512]
    legacy["parameters"] = list(parameters_by_name.values())[:512]
    raw_counts = legacy.get("counts")
    counts: dict[str, object] = (
        {str(key): item for key, item in raw_counts.items()}
        if isinstance(raw_counts, Mapping)
        else {}
    )
    counts.update(
        {
            "graph_operations": len(operations),
            "graph_identity_observations": len(graph.observations or {}),
        }
    )
    legacy["counts"] = counts
    return legacy


def _operation_is_actionable_projection(operation: SurfaceOperation) -> bool:
    """Keep all probe history canonical without promoting attack-made candidates."""
    return operation.actionable


def _project_source_template(
    template: dict[str, object],
    operation: SurfaceOperation,
) -> None:
    if str(template.get("source") or "") in {"", "source_code", "surface_graph"}:
        template["source"] = "source_code"
    template["hints"] = sorted(set(_string_items(template.get("hints"))) | set(operation.hints))[
        :16
    ]
    template["content_types"] = sorted(
        set(_string_items(template.get("content_types"))) | set(operation.content_types)
    )[:16]
    template["priority"] = max(300, _projection_priority(template.get("priority")))
    if encoding := _source_operation_encoding(operation):
        template.setdefault("encoding", encoding)


def _project_template_parameter(
    template: dict[str, object],
    parameter: SurfaceParameter,
    *,
    include_location: bool,
) -> None:
    if parameter.location not in {"body", "form", "graphql", "query"}:
        return
    fields = template.setdefault("fields", {})
    if isinstance(fields, dict):
        fields.setdefault(parameter.name, "")
    if not include_location:
        return
    input_locations = template.setdefault("input_locations", {})
    if isinstance(input_locations, dict):
        input_locations.setdefault(parameter.name, parameter.location)


def _project_source_parameter(
    payload: dict[str, object],
    operation: SurfaceOperation,
    parameter: SurfaceParameter,
) -> None:
    payload["input_locations"] = sorted(
        set(_string_items(payload.get("input_locations"))) | {parameter.location}
    )[:16]
    payload["methods"] = sorted(set(_string_items(payload.get("methods"))) | {operation.method})[
        :16
    ]
    payload["hints"] = sorted(set(_string_items(payload.get("hints"))) | set(operation.hints))[:16]
    payload["priority"] = max(300, _projection_priority(payload.get("priority")))


def _source_operation_encoding(operation: SurfaceOperation) -> str:
    content_types = set(operation.content_types)
    if "application/json" in content_types or any(
        parameter.location == "body" for parameter in operation.parameters
    ):
        return "application/json"
    if "application/x-www-form-urlencoded" in content_types or any(
        parameter.location == "form" for parameter in operation.parameters
    ):
        return "application/x-www-form-urlencoded"
    return ""


def _projection_priority(value: object) -> int:
    try:
        priority = int(str(value))
    except (TypeError, ValueError):
        return 0
    return max(0, priority)


def import_legacy_surface(
    graph: SurfaceGraphState,
    legacy_surface: Mapping[str, object],
    *,
    identity_alias: str = "anonymous",
) -> None:
    """Deterministically seed old saved state that predates the graph."""
    target_url = str(legacy_surface.get("target_url") or graph.target_origin or "")
    for index, endpoint in enumerate(_mapping_items(legacy_surface.get("endpoints"))):
        _try_add(
            graph,
            url=urljoin(target_url, str(endpoint.get("url") or "")),
            method="GET",
            hints=_string_items(endpoint.get("hints")),
            source_kind="legacy_import",
            identity_alias=identity_alias,
            evidence_refs=(f"legacy_endpoint_{index}",),
        )
    for index, template in enumerate(_mapping_items(legacy_surface.get("request_templates"))):
        fields = template.get("fields")
        _try_add(
            graph,
            url=urljoin(target_url, str(template.get("url") or "")),
            method=template.get("method") or "GET",
            parameters=_field_parameters(fields, location="body"),
            source_kind="legacy_import",
            identity_alias=identity_alias,
            evidence_refs=(f"legacy_template_{index}",),
        )


def _try_add(graph: SurfaceGraphState, **kwargs: object) -> SurfaceOperation | None:
    try:
        return graph.add(**kwargs)  # pyright: ignore[reportArgumentType]
    except SurfaceGraphError:
        # Recon and third-party specs commonly mention other origins.  They are
        # intentionally excluded from this target-owned graph.
        return None


def _copy_legacy_record(
    value: Mapping[str, object],
    *,
    list_fields: tuple[str, ...] = (),
    mapping_fields: tuple[str, ...] = (),
) -> dict[str, object]:
    copied = dict(value)
    for field in list_fields:
        item = copied.get(field)
        if isinstance(item, list):
            copied[field] = list(item)
    for field in mapping_fields:
        item = copied.get(field)
        if isinstance(item, Mapping):
            copied[field] = dict(item)
    return copied


def _query_parameters(url: str) -> tuple[SurfaceParameter, ...]:
    try:
        pairs = parse_qsl(
            urlsplit(url).query[:_MAX_JAVASCRIPT_SOURCE_CHARS],
            keep_blank_values=True,
        )
    except ValueError:
        return ()
    parameters: list[SurfaceParameter] = []
    for index, name in enumerate(sorted({name for name, _value in pairs if name})):
        if index >= _MAX_COLLECTION_ITEMS:
            break
        parameter = _try_parameter(name=name, location="query")
        if parameter is not None:
            parameters.append(parameter)
    return tuple(parameters)


def _field_parameters(value: object, *, location: str) -> tuple[SurfaceParameter, ...]:
    if not isinstance(value, Mapping):
        return ()
    parameters: list[SurfaceParameter] = []
    for index, name in enumerate(value):
        if index >= _MAX_COLLECTION_ITEMS:
            break
        if not str(name).strip():
            continue
        parameter = _try_parameter(name=name, location=location)
        if parameter is not None:
            parameters.append(parameter)
    return tuple(parameters)


def _parameter_items(
    items: tuple[Mapping[str, object], ...],
    *,
    location: str,
    location_key: str = "",
    default_type: str = "unknown",
) -> tuple[SurfaceParameter, ...]:
    parameters: list[SurfaceParameter] = []
    for index, item in enumerate(items):
        if index >= _MAX_COLLECTION_ITEMS:
            break
        if not str(item.get("name") or "").strip():
            continue
        parameter = _try_parameter(
            name=item.get("name"),
            location=(item.get(location_key) or location) if location_key else location,
            data_type=item.get("type") or default_type,
            required=item.get("required"),
        )
        if parameter is not None:
            parameters.append(parameter)
    return tuple(parameters)


def _try_parameter(
    *,
    name: object,
    location: object,
    data_type: object = "unknown",
    required: object = False,
) -> SurfaceParameter | None:
    try:
        return SurfaceParameter.create(
            name=name,
            location=location,
            data_type=data_type,
            required=required,
        )
    except SurfaceGraphError:
        return None


def _header_keys(value: object) -> tuple[str, ...]:
    return _bounded_mapping_keys(value) if isinstance(value, Mapping) else ()


def _bounded_mapping_keys(
    value: Mapping[object, object],
    *,
    limit: int = _MAX_COLLECTION_ITEMS,
) -> tuple[str, ...]:
    keys: list[str] = []
    for index, key in enumerate(value):
        if index >= limit:
            break
        keys.append(str(key))
    return tuple(keys)


def _openapi_base_url(document: Mapping[str, object], *, document_url: str) -> str:
    servers = document.get("servers")
    if isinstance(servers, list):
        for index, server in enumerate(servers):
            if index >= _MAX_COLLECTION_ITEMS:
                break
            if isinstance(server, Mapping) and str(server.get("url") or ""):
                return urljoin(document_url, str(server["url"]))
    host = str(document.get("host") or "")
    base_path = str(document.get("basePath") or "/")
    schemes = _string_items(document.get("schemes"))
    if host:
        return f"{schemes[0] if schemes else urlsplit(document_url).scheme}://{host}{base_path}"
    parsed = urlsplit(document_url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def _openapi_parameters(
    value: object,
    *,
    budget: _InspectionBudget,
    resolver: _OpenAPIResolver,
) -> tuple[SurfaceParameter, ...]:
    parameters: list[SurfaceParameter] = []
    for candidate in _mapping_items(value):
        if not budget.take():
            break
        item = resolver.mapping(candidate)
        if item is None:
            continue
        name = str(item.get("name") or "")
        location = str(item.get("in") or "unknown").casefold()
        if not name:
            continue
        if location == "body":
            schema = resolver.mapping(item.get("schema"))
            if schema is None:
                continue
            body_parameters = _openapi_schema_parameters(
                schema,
                budget=budget,
                resolver=resolver,
                fallback_name=name,
                fallback_required=item.get("required", False),
            )
            parameters.extend(body_parameters)
            continue
        if location == "formdata":
            location = "form"
        raw_parameter_schema = item.get("schema")
        schema_payload = resolver.mapping(raw_parameter_schema) or item
        parameter = _try_parameter(
            name=name,
            location=location,
            data_type=schema_payload.get("type") or "unknown",
            required=item.get("required"),
        )
        if parameter is not None:
            parameters.append(parameter)
    return tuple(parameters)


def _openapi_body_parameters(
    content: Mapping[object, object],
    *,
    budget: _InspectionBudget,
    resolver: _OpenAPIResolver,
) -> tuple[SurfaceParameter, ...]:
    parameters: list[SurfaceParameter] = []
    for candidate_media_payload in content.values():
        if not budget.take():
            break
        media_payload = resolver.mapping(candidate_media_payload)
        if media_payload is None:
            continue
        schema = resolver.mapping(media_payload.get("schema"))
        if schema is None:
            continue
        parameters.extend(
            _openapi_schema_parameters(
                schema,
                budget=budget,
                resolver=resolver,
            )
        )
    return tuple(parameters)


def _openapi_schema_parameters(
    schema: Mapping[str, object],
    *,
    budget: _InspectionBudget,
    resolver: _OpenAPIResolver,
    fallback_name: str = "",
    fallback_required: object = False,
) -> tuple[SurfaceParameter, ...]:
    resolved_schema = resolver.mapping(schema)
    if resolved_schema is None:
        return ()
    if str(resolved_schema.get("type") or "").casefold() == "array":
        item_schema = resolver.mapping(resolved_schema.get("items"))
        if item_schema is not None:
            resolved_schema = item_schema
    properties = resolved_schema.get("properties")
    required = set(_string_items(resolved_schema.get("required")))
    parameters: list[SurfaceParameter] = []
    if isinstance(properties, Mapping):
        for name, raw_property in properties.items():
            if not budget.take():
                break
            property_payload = resolver.mapping(raw_property)
            if property_payload is None:
                continue
            parameter = _try_parameter(
                name=name,
                location="body",
                data_type=property_payload.get("type") or "unknown",
                required=str(name) in required,
            )
            if parameter is not None:
                parameters.append(parameter)
    if parameters or not fallback_name:
        return tuple(parameters)
    fallback = _try_parameter(
        name=fallback_name,
        location="body",
        data_type=resolved_schema.get("type") or "unknown",
        required=fallback_required,
    )
    return (fallback,) if fallback is not None else ()


def _graphql_introspection_selectors(  # noqa: C901, PLR0912 - bounded nested schema.
    schema: Mapping[str, object],
    *,
    budget: _InspectionBudget,
) -> tuple[tuple[str, tuple[SurfaceParameter, ...]], ...]:
    data = schema.get("data")
    root = data if isinstance(data, Mapping) else schema
    raw_schema = root.get("__schema") if isinstance(root, Mapping) else None
    if (
        not isinstance(raw_schema, Mapping)
        and isinstance(root, Mapping)
        and isinstance(root.get("types"), list)
        and any(
            isinstance(root.get(key), Mapping)
            for key in ("queryType", "mutationType", "subscriptionType")
        )
    ):
        raw_schema = root
    if not isinstance(raw_schema, Mapping):
        return ()
    root_names: dict[str, str] = {}
    for kind, key in (
        ("Query", "queryType"),
        ("Mutation", "mutationType"),
        ("Subscription", "subscriptionType"),
    ):
        value = raw_schema.get(key)
        if isinstance(value, Mapping) and str(value.get("name") or ""):
            root_names[str(value["name"])] = kind
    selectors: list[tuple[str, tuple[SurfaceParameter, ...]]] = []
    for raw_type in _mapping_items(raw_schema.get("types")):
        if not budget.take():
            break
        root_kind = root_names.get(str(raw_type.get("name") or ""))
        if not root_kind:
            continue
        for field in _mapping_items(raw_type.get("fields")):
            if not budget.take():
                break
            name = str(field.get("name") or "")
            if not name:
                continue
            parameters: list[SurfaceParameter] = []
            for argument in _mapping_items(field.get("args")):
                if not budget.take():
                    break
                if not str(argument.get("name") or ""):
                    continue
                parameter = _try_parameter(
                    name=argument.get("name"),
                    location="graphql",
                    data_type=_graphql_type_name(argument.get("type")),
                    required=_graphql_type_required(argument.get("type")),
                )
                if parameter is not None:
                    parameters.append(parameter)
            selectors.append((f"{root_kind}.{name}", tuple(parameters)))
    return tuple(selectors)


def _graphql_type_name(value: object) -> str:
    current = value
    names: list[str] = []
    for _depth in range(32):
        if not isinstance(current, Mapping):
            break
        kind = str(current.get("kind") or "")
        name = str(current.get("name") or "")
        if name:
            names.append(name)
        elif kind:
            names.append(kind)
        current = current.get("ofType")
    return "_".join(names) or "unknown"


def _graphql_type_required(value: object) -> bool:
    return isinstance(value, Mapping) and str(value.get("kind") or "") == "NON_NULL"


def _graphql_sdl_selectors(
    schema: str,
    *,
    budget: _InspectionBudget,
) -> tuple[tuple[str, tuple[SurfaceParameter, ...]], ...]:
    selectors: list[tuple[str, tuple[SurfaceParameter, ...]]] = []
    for type_match in _GRAPHQL_TYPE_RE.finditer(schema[:_MAX_GRAPHQL_SOURCE_CHARS]):
        if not budget.take():
            break
        kind = type_match.group(1)
        for field_match in _GRAPHQL_FIELD_RE.finditer(type_match.group("body")):
            if not budget.take():
                break
            parameters: list[SurfaceParameter] = []
            for argument in _GRAPHQL_ARG_RE.finditer(field_match.group(2) or ""):
                if not budget.take():
                    break
                parameter = _try_parameter(
                    name=argument.group(1),
                    location="graphql",
                    data_type=argument.group(2).replace("!", "required"),
                    required="!" in argument.group(2),
                )
                if parameter is not None:
                    parameters.append(parameter)
            selectors.append((f"{kind}.{field_match.group(1)}", tuple(parameters)))
    return tuple(selectors)


def _graphql_probe_parameters(value: object) -> tuple[SurfaceParameter, ...]:
    parameters: list[SurfaceParameter] = []
    for argument in _mapping_items(value, limit=_MAX_EXTERNAL_ARRAY_ITEMS):
        name = str(argument.get("name") or "")
        if not _GRAPHQL_NAME_RE.fullmatch(name):
            continue
        parameter = _try_parameter(
            name=name,
            location="graphql",
            data_type=argument.get("data_type") or argument.get("type") or "unknown",
            required=argument.get("required", False),
        )
        if parameter is not None:
            parameters.append(parameter)
    return tuple(parameters)


def _source_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise SurfaceGraphError(f"{label} must be a bounded structural identifier")
    if not _SOURCE_IDENTIFIER_RE.fullmatch(value):
        raise SurfaceGraphError(f"{label} must be a bounded structural identifier")
    return value


def _source_input_name(value: object) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise SurfaceGraphError("source input name must be a bounded structural identifier")
    if not _SOURCE_INPUT_NAME_RE.fullmatch(value):
        raise SurfaceGraphError("source input name must be a bounded structural identifier")
    return value


def _source_input_location(value: object) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise SurfaceGraphError("source input location must be a string")
    location = value.casefold()
    # SurfaceParameter owns the canonical location allow-list.  Constructing a
    # temporary parameter keeps this adapter aligned with that typed contract.
    return SurfaceParameter.create(name="input", location=location).location


def _source_line(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SurfaceGraphError("source line must be a positive integer")
    if value <= 0 or value > _MAX_SOURCE_LINE:
        raise SurfaceGraphError("source line must be a positive integer")
    return value


def _source_relative_file(value: object) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise SurfaceGraphError("source file must be a normalized relative path")
    if not value or len(value) > _MAX_SOURCE_FILE_CHARS or "\\" in value:
        raise SurfaceGraphError("source file must be a normalized relative path")
    if re.match(r"^[A-Za-z]:", value):
        raise SurfaceGraphError("source file must be a normalized relative path")
    path = PurePosixPath(value)
    parts = value.split("/")
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
        or any(not _SOURCE_FILE_SEGMENT_RE.fullmatch(part) for part in parts)
    ):
        raise SurfaceGraphError("source file must be a normalized relative path")
    return value


def _source_route(value: object) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise SurfaceGraphError("source route must be a normalized absolute path")
    if _source_route_has_unsafe_syntax(value):
        raise SurfaceGraphError("source route must be a normalized absolute path")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise SurfaceGraphError("source route must be a normalized absolute path") from exc
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise SurfaceGraphError("source route must be a normalized absolute path")

    decoded = _decode_source_route(value)
    if any(part in {".", ".."} for part in decoded.split("/")) or "//" in decoded:
        raise SurfaceGraphError("source route must be a normalized absolute path")
    return value


def _source_route_has_unsafe_syntax(value: str) -> bool:
    unsafe_character = any(
        character.isspace() or not character.isprintable() for character in value
    )
    return any(
        (
            not value.startswith("/"),
            value.startswith("//"),
            len(value) > _MAX_SOURCE_ROUTE_CHARS,
            "\\" in value,
            "?" in value,
            "#" in value,
            unsafe_character,
            re.search(r"%(?![0-9A-Fa-f]{2})", value) is not None,
            re.search(r"%2[fF]|%5[cC]", value) is not None,
        )
    )


def _decode_source_route(value: str) -> str:
    decoded = value
    for _depth in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            return decoded
        if expanded.count("/") != decoded.count("/"):
            raise SurfaceGraphError("source route must be a normalized absolute path")
        decoded = expanded
        if (
            decoded.startswith("//")
            or "\\" in decoded
            or "?" in decoded
            or "#" in decoded
            or any(character.isspace() or not character.isprintable() for character in decoded)
        ):
            raise SurfaceGraphError("source route must be a normalized absolute path")
    if unquote(decoded) != decoded:
        raise SurfaceGraphError("source route must be a normalized absolute path")
    return decoded


def _mapping_items(
    value: object,
    *,
    limit: int = _MAX_DOCUMENT_INSPECTIONS,
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list):
        return ()
    items: list[Mapping[str, object]] = []
    for index, item in enumerate(value):
        if index >= limit:
            break
        if isinstance(item, Mapping):
            items.append(item)
    return tuple(items)


def _external_parameters(value: object) -> tuple[SurfaceParameter, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SurfaceGraphError("external parameters must be an array")
    if len(value) > _MAX_EXTERNAL_ARRAY_ITEMS:
        raise SurfaceGraphError("external parameters exceed the item limit")
    parameters: list[SurfaceParameter] = []
    allowed = {"name", "location", "data_type", "required"}
    for item in value:
        if not isinstance(item, Mapping):
            raise SurfaceGraphError("external parameters must contain only objects")
        if any(not isinstance(key, str) or key not in allowed for key in item):
            raise SurfaceGraphError("external parameter contains unsupported fields")
        parameters.append(SurfaceParameter.from_json(item))
    return tuple(parameters)


def _external_string_items(value: object, *, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SurfaceGraphError(f"external {label} must be an array of strings")
    if len(value) > _MAX_EXTERNAL_ARRAY_ITEMS:
        raise SurfaceGraphError(f"external {label} exceeds the item limit")
    if any(not isinstance(item, str) for item in value):
        raise SurfaceGraphError(f"external {label} must be an array of strings")
    return tuple(value)


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return ()
    items: list[str] = []
    for index, item in enumerate(value):
        if index >= _MAX_COLLECTION_ITEMS:
            break
        if str(item):
            items.append(str(item))
    return tuple(items)


__all__ = [
    "SURFACE_OBSERVATION_BATCH_SCHEMA",
    "SURFACE_OBSERVATION_INPUT_SCHEMA",
    "SurfaceObservationInput",
    "import_legacy_surface",
    "ingest_captured_exchanges",
    "ingest_graphql_schema",
    "ingest_javascript_source",
    "ingest_openapi_document",
    "ingest_probe_result",
    "ingest_recon_surface",
    "ingest_source_code_candidates",
    "ingest_surface_observation_batch",
    "project_surface_graph",
]
