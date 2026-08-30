# ruff: noqa: PLR2004
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from ravage.agent_core import surface_graph as surface_graph_module
from ravage.agent_core import surface_graph_ingest as surface_graph_ingest_module
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.surface_graph import (
    SurfaceGraphError,
    SurfaceGraphState,
    SurfaceOperation,
    SurfaceParameter,
    canonical_operation_url,
)
from ravage.agent_core.surface_graph_ingest import (
    SURFACE_OBSERVATION_BATCH_SCHEMA,
    SURFACE_OBSERVATION_INPUT_SCHEMA,
    SurfaceObservationInput,
    ingest_captured_exchanges,
    ingest_graphql_schema,
    ingest_javascript_source,
    ingest_openapi_document,
    ingest_probe_result,
    ingest_recon_surface,
    ingest_surface_observation_batch,
    project_surface_graph,
)
from ravage.traffic.contracts import build_captured_http_exchange
from ravage.web_core import recon as recon_module

TARGET = "https://example.test"


def test_operations_dedupe_by_safe_route_shape_and_merge_provenance() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    first = graph.add(
        url=f"{TARGET}/users/123?token=first-secret",
        method="GET",
        parameters=(SurfaceParameter.create(name="token", location="query"),),
        source_kind="native_recon",
        identity_alias="anonymous",
    )
    second = graph.add(
        url=f"{TARGET}/users/456?token=second-secret",
        method="GET",
        header_names=("Authorization",),
        source_kind="browser",
        identity_alias="alice",
    )

    assert first.operation_id == second.operation_id
    operation = graph.operations[first.operation_id]  # type: ignore[index]
    assert operation.route_shape == "/users/{int}"
    assert operation.provenance == ("browser", "native_recon")
    serialized = json.dumps(graph.to_json())
    assert "first-secret" not in serialized
    assert "second-secret" not in serialized


def test_identity_like_alphabetic_path_children_are_not_persisted() -> None:
    graph = SurfaceGraphState.for_target(TARGET)

    operation = graph.add(
        url=f"{TARGET}/users/alice/settings",
        method="GET",
        source_kind="probe",
        identity_alias="anonymous",
    )
    collection_action = graph.add(
        url=f"{TARGET}/users/search",
        method="GET",
        source_kind="native_recon",
        identity_alias="anonymous",
    )

    assert operation.route_shape == "/users/{id}/settings"
    assert collection_action.route_shape == "/users/search"
    assert "alice" not in json.dumps(graph.to_json())


def test_identity_access_edges_keep_anonymous_401_and_authenticated_200() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    operation = graph.add(
        url=f"{TARGET}/admin",
        source_kind="probe",
        identity_alias="anonymous",
        access_level="response",
        response_status=401,
    )
    graph.add(
        url=f"{TARGET}/admin",
        source_kind="probe",
        identity_alias="alice",
        access_level="response",
        response_status=200,
    )

    observations = [
        item
        for item in graph.observations.values()  # type: ignore[union-attr]
        if item.operation_id == operation.operation_id
    ]
    assert {(item.identity_alias, item.response_status) for item in observations} == {
        ("anonymous", 401),
        ("alice", 200),
    }


def test_exchange_ingestion_keeps_shapes_but_never_values_or_bodies() -> None:
    exchange = build_captured_http_exchange(
        capture_session_id="browser-test",
        source="browser_capture",
        source_observation_id="browser-observation-1",
        identity_alias="alice",
        method="POST",
        url=f"{TARGET}/orders/550e8400-e29b-41d4-a716-446655440000?coupon=super-secret",
        request_headers={
            "Authorization": "Bearer super-secret",
            "Content-Type": "application/json",
        },
        request_body={"card_number": "4111111111111111", "amount": 10},
        request_sent=True,
        response_status=201,
        response_final_url=f"{TARGET}/orders/550e8400-e29b-41d4-a716-446655440000",
        response_body={"receipt": "secret-receipt"},
        scope_decision="allowed",
        replayability="requires_authorization",
        known_secrets=("super-secret", "4111111111111111", "secret-receipt"),
    ).with_store_identity(exchange_id="rq_0001", sequence=1)
    graph = SurfaceGraphState.for_target(TARGET)

    operation = graph.ingest_exchange(exchange)

    assert operation.route_shape == "/orders/{id}"
    assert {(item.name, item.location) for item in operation.parameters} == {
        ("amount", "body"),
        ("card_number", "body"),
        ("coupon", "query"),
    }
    serialized = json.dumps(graph.to_json())
    for secret in ("super-secret", "4111111111111111", "secret-receipt"):
        assert secret not in serialized


def test_recon_javascript_openapi_and_graphql_feed_one_graph() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    ingest_recon_surface(
        graph,
        {
            "pages": [
                {
                    "url": f"{TARGET}/",
                    "final_url": f"{TARGET}/",
                    "status": 200,
                    "links": [f"{TARGET}/api/users/1"],
                    "scripts": [f"{TARGET}/static/app.js"],
                    "forms": [
                        {
                            "action": f"{TARGET}/login",
                            "method": "POST",
                            "enctype": "application/x-www-form-urlencoded",
                            "inputs": [
                                {"name": "username", "type": "text", "required": True},
                                {"name": "password", "type": "password", "required": True},
                            ],
                        }
                    ],
                    "request_templates": [],
                }
            ]
        },
    )
    assert (
        ingest_javascript_source(
            graph,
            script_text=(
                'fetch("/api/search", {method: "POST", body: JSON.stringify({query: value})})'
            ),
            base_url=f"{TARGET}/static/app.js",
            evidence_ref="script_1",
        )
        == 1
    )
    assert (
        ingest_openapi_document(
            graph,
            {
                "openapi": "3.0.0",
                "paths": {
                    "/api/users/{id}": {
                        "get": {
                            "operationId": "getUser",
                            "parameters": [
                                {
                                    "name": "id",
                                    "in": "path",
                                    "required": True,
                                    "schema": {"type": "integer"},
                                }
                            ],
                        }
                    }
                },
            },
            document_url=f"{TARGET}/openapi.json",
        )
        == 1
    )
    assert (
        ingest_graphql_schema(
            graph,
            (
                "type Query { user(id: ID!): User } "
                "type Mutation { rename(id: ID!, name: String!): User }"
            ),
            endpoint_url=f"{TARGET}/graphql",
        )
        == 2
    )

    sources = {
        source
        for operation in graph.operations.values()  # type: ignore[union-attr]
        for source in operation.provenance
    }
    assert {"native_recon", "javascript_external", "openapi", "graphql"} <= sources
    selectors = {item.selector for item in graph.operations.values() if item.selector}  # type: ignore[union-attr]
    assert selectors == {"Query.user", "Mutation.rename"}


def test_external_adapter_is_typed_value_free_and_cannot_spoof_internal_source() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    payload = {
        "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
        "url": f"{TARGET}/api/items/99?secret=not-persisted",
        "method": "GET",
        "source_kind": "external_tool",
        "parameters": [{"name": "secret", "location": "query", "data_type": "string"}],
        "evidence_refs": ["tool-observation-1"],
    }
    SurfaceObservationInput.from_json(payload).ingest(graph)
    assert "not-persisted" not in json.dumps(graph.to_json())

    payload["source_kind"] = "browser"
    with pytest.raises(SurfaceGraphError, match="cannot claim"):
        SurfaceObservationInput.from_json(payload)


def test_external_adapter_canonicalizes_immediately_and_rejects_nested_values() -> None:
    payload = {
        "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
        "url": f"{TARGET}/api/items/99?secret=adapter-secret",
        "method": "get",
        "parameters": [
            {
                "name": "secret",
                "location": "query",
                "data_type": "string",
                "required": "false",
            }
        ],
    }

    observation = SurfaceObservationInput.from_json(payload)

    assert observation.url == f"{TARGET}/api/items/{'{int}'}"
    assert observation.method == "GET"
    assert observation.parameters[0].required is False
    assert "adapter-secret" not in repr(observation)

    unsafe_payload = dict(payload)
    unsafe_payload["parameters"] = [
        {
            "name": "secret",
            "location": "query",
            "data_type": "string",
            "required": False,
            "value": "nested-secret",
        }
    ]
    with pytest.raises(SurfaceGraphError, match="unsupported fields"):
        SurfaceObservationInput.from_json(unsafe_payload)


def test_response_status_requires_response_access_and_boolean_input_is_strict() -> None:
    payload = {
        "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
        "url": f"{TARGET}/health",
        "method": "GET",
        "response_status": 200,
    }
    with pytest.raises(SurfaceGraphError, match="response-level"):
        SurfaceObservationInput.from_json(payload)

    with pytest.raises(SurfaceGraphError, match="parameter required"):
        SurfaceParameter.create(name="q", location="query", required="definitely")


def test_probe_adapter_ingests_requests_openapi_routes_and_graphql_selectors() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    added = ingest_probe_result(
        graph,
        {
            "probe": "api_behavior",
            "requests": [
                {
                    "method": "POST",
                    "url": f"{TARGET}/graphql",
                    "status": 200,
                    "headers": {"content-type": "application/json"},
                }
            ],
            "findings": [
                {
                    "type": "openapi_route_signal",
                    "routes": [
                        {
                            "method": "GET",
                            "url": f"{TARGET}/api/items/1",
                            "parameters": [
                                {
                                    "name": "id",
                                    "location": "path",
                                    "type": "integer",
                                    "required": True,
                                }
                            ],
                        }
                    ],
                },
                {
                    "type": "graphql_mutation_discovered",
                    "url": f"{TARGET}/graphql",
                    "mutations": ["renameUser"],
                },
            ],
        },
        identity_alias="alice",
        source_observation_id="obs_1",
    )

    assert added == 3
    assert {source for item in graph.operations.values() for source in item.provenance} >= {  # type: ignore[union-attr]
        "probe",
        "openapi",
        "graphql",
    }
    assert any(item.selector == "Mutation.renameUser" for item in graph.operations.values())  # type: ignore[union-attr]
    probe_operation = next(
        item
        for item in graph.operations.values()  # type: ignore[union-attr]
        if item.provenance == ("probe",)
    )
    assert probe_operation.header_names == ()
    probe_observation = next(
        item
        for item in graph.observations.values()  # type: ignore[union-attr]
        if item.operation_id == probe_operation.operation_id
    )
    assert probe_observation.scope_decision == "unknown"
    assert probe_operation.actionable is False
    promoted = [item for item in graph.operations.values() if item.actionable]  # type: ignore[union-attr]
    assert {source for item in promoted for source in item.provenance} >= {
        "openapi",
        "graphql",
    }
    projected = project_surface_graph(graph)
    assert {item["url"] for item in projected["endpoints"]} >= {  # type: ignore[index]
        f"{TARGET}/api/items/{'{int}'}",
        f"{TARGET}/graphql",
    }


def test_probe_query_fields_cannot_contaminate_an_existing_trusted_operation() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    trusted = graph.add(
        url=f"{TARGET}/search?q=observed",
        parameters=(SurfaceParameter.create(name="q", location="query"),),
        source_kind="native_recon",
    )

    ingest_probe_result(
        graph,
        {
            "probe": "browser_boundary",
            "requests": [
                {
                    "method": "GET",
                    "url": f"{TARGET}/search?q=attack&fabricated_password=attack",
                    "status": 200,
                    "request_header_names": ["X-Fabricated-Auth"],
                    "probe_kind": "browser_boundary_attack",
                }
            ],
        },
        source_observation_id="obs_attack",
    )

    merged = graph.operations[trusted.operation_id]  # type: ignore[index]
    assert merged.provenance == ("native_recon", "probe")
    assert {item.name for item in merged.parameters} == {"q"}
    assert merged.header_names == ()
    assert merged.hints == ()
    assert len(graph.observations or {}) == 2
    projected = project_surface_graph(graph)
    [template] = projected["request_templates"]  # type: ignore[misc]
    assert template["fields"] == {"q": ""}


def test_old_state_imports_legacy_surface_and_versioned_state_fails_closed() -> None:
    old = AgentState.from_json(
        {
            "surface": {
                "target_url": TARGET,
                "endpoints": [{"url": f"{TARGET}/health", "hints": ["api"]}],
                "request_templates": [
                    {
                        "method": "POST",
                        "url": f"{TARGET}/api/search",
                        "fields": {"query": "legacy-value"},
                    }
                ],
            }
        }
    )
    assert len(old.surface_graph.operations or {}) == 2
    assert "legacy-value" not in json.dumps(old.surface_graph.to_json())

    payload = old.to_json()
    payload["surface_graph"] = dict(payload["surface_graph"])  # type: ignore[arg-type]
    payload["surface_graph"]["schema_version"] = 99  # type: ignore[index]
    with pytest.raises(SurfaceGraphError, match="unsupported"):
        AgentState.from_json(payload)


def test_legacy_projection_is_additive_and_contains_no_observed_values() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    graph.add(
        url=f"{TARGET}/api/users/42?expand=private-value",
        method="GET",
        parameters=(SurfaceParameter.create(name="expand", location="query"),),
        source_kind="openapi",
    )

    projected = project_surface_graph(
        graph,
        {"visible_description": "keep me", "endpoints": [{"url": f"{TARGET}/existing"}]},
    )

    assert projected["visible_description"] == "keep me"
    assert {item["url"] for item in projected["endpoints"]} >= {  # type: ignore[index]
        f"{TARGET}/existing",
        f"{TARGET}/api/users/{'{int}'}",
    }
    assert "private-value" not in json.dumps(projected)
    assert not any(
        item.get("url") == f"{TARGET}/api/users/{'{int}'}"
        for item in projected["request_templates"]  # type: ignore[union-attr]
    )


def test_empty_projection_is_an_exact_noop_and_projection_does_not_mutate_input() -> None:
    legacy = {
        "visible_description": "keep me",
        "endpoints": [{"url": f"{TARGET}/search", "sources": ["legacy"]}],
        "request_templates": [
            {
                "method": "GET",
                "url": f"{TARGET}/search",
                "fields": {"existing": "value"},
            }
        ],
        "parameters": [
            {
                "name": "q",
                "sources": ["legacy"],
                "locations": [f"{TARGET}/search"],
                "hints": ["query"],
            }
        ],
    }
    before = json.loads(json.dumps(legacy))

    assert project_surface_graph(SurfaceGraphState.for_target(TARGET), legacy) == legacy

    graph = SurfaceGraphState.for_target(TARGET)
    graph.add(
        url=f"{TARGET}/search?q=secret",
        parameters=(SurfaceParameter.create(name="q", location="query"),),
        source_kind="probe",
    )
    projected = project_surface_graph(graph, legacy)

    assert legacy == before
    assert projected["endpoints"][0]["sources"] == ["legacy"]  # type: ignore[index]
    assert projected["request_templates"][0]["fields"] == {"existing": "value"}  # type: ignore[index]


def test_projection_retains_probe_history_without_promoting_attack_surface() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    missing = graph.add(
        url=f"{TARGET}/missing?q=example",
        parameters=(SurfaceParameter.create(name="q", location="query"),),
        source_kind="probe",
        access_level="response",
        response_status=404,
    )
    gone = graph.add(
        url=f"{TARGET}/gone",
        parameters=(SurfaceParameter.create(name="gone_id", location="query"),),
        source_kind="probe",
        access_level="response",
        response_status=410,
    )
    late_missing = graph.add(
        url=f"{TARGET}/late-missing",
        parameters=(SurfaceParameter.create(name="candidate", location="query"),),
        source_kind="probe",
    )
    graph.add(
        url=f"{TARGET}/late-missing",
        source_kind="probe",
        access_level="response",
        response_status=404,
    )
    graph.add(
        url=f"{TARGET}/statusless-request",
        source_kind="probe",
        access_level="request",
    )
    graph.add(
        url=f"{TARGET}/authenticate",
        source_kind="probe",
        access_level="response",
        response_status=401,
    )
    graph.add(
        url=f"{TARGET}/protected",
        source_kind="probe",
        access_level="response",
        response_status=403,
    )
    graph.add(
        url=f"{TARGET}/method-specific",
        method="POST",
        source_kind="probe",
        access_level="response",
        response_status=405,
    )
    graph.add(
        url=f"{TARGET}/mixed-history",
        source_kind="probe",
        access_level="response",
        response_status=404,
    )
    graph.add(
        url=f"{TARGET}/mixed-history",
        source_kind="probe",
        access_level="response",
        response_status=200,
    )
    graph.add(
        url=f"{TARGET}/declared",
        method="POST",
        parameters=(SurfaceParameter.create(name="schema_field", location="body"),),
        source_kind="openapi",
    )
    graph.add(
        url=f"{TARGET}/declared",
        method="POST",
        source_kind="probe",
        access_level="response",
        response_status=404,
    )

    projected = project_surface_graph(graph)
    endpoint_urls = {item["url"] for item in projected["endpoints"]}  # type: ignore[index]
    template_urls = {
        item["url"] for item in projected["request_templates"]  # type: ignore[index]
    }
    parameter_names = {
        item["name"] for item in projected["parameters"]  # type: ignore[index]
    }

    assert missing.operation_id in graph.operations  # type: ignore[operator]
    assert gone.operation_id in graph.operations  # type: ignore[operator]
    assert late_missing.operation_id in graph.operations  # type: ignore[operator]
    assert f"{TARGET}/missing" not in endpoint_urls
    assert f"{TARGET}/gone" not in endpoint_urls
    assert f"{TARGET}/late-missing" not in endpoint_urls
    assert f"{TARGET}/missing" not in template_urls
    assert f"{TARGET}/gone" not in template_urls
    assert f"{TARGET}/late-missing" not in template_urls
    assert not {"q", "gone_id", "candidate"} & parameter_names
    assert f"{TARGET}/statusless-request" not in endpoint_urls
    assert f"{TARGET}/authenticate" not in endpoint_urls
    assert f"{TARGET}/protected" not in endpoint_urls
    assert f"{TARGET}/method-specific" not in endpoint_urls
    assert f"{TARGET}/mixed-history" not in endpoint_urls
    assert f"{TARGET}/declared" in endpoint_urls
    assert f"{TARGET}/declared" in template_urls
    assert "schema_field" in parameter_names
    assert projected["counts"] == {
        "graph_operations": len(graph.operations or {}),
        "graph_identity_observations": len(graph.observations or {}),
    }


def test_capacity_eviction_keeps_new_operation_and_cascades_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(surface_graph_module, "MAX_SURFACE_OPERATIONS", 2)
    candidates = sorted(
        (
            SurfaceOperation.create(
                url=f"{TARGET}/capacity/route-{index}",
                provenance=("probe",),
            )
            for index in range(8)
        ),
        key=lambda item: item.operation_id,
    )
    graph = SurfaceGraphState.for_target(TARGET)

    for operation in candidates[:3]:
        graph.add(url=operation.structural_url, source_kind="probe")

    assert candidates[2].operation_id in graph.operations  # type: ignore[operator]
    assert len(graph.operations or {}) == 2
    assert len(graph.observations or {}) == 2
    assert all(
        item.operation_id in (graph.operations or {})
        for item in (graph.observations or {}).values()
    )


def test_persisted_graph_fails_closed_on_shape_errors_and_orphans() -> None:
    with pytest.raises(SurfaceGraphError, match="schema"):
        SurfaceGraphState.from_json({})

    graph = SurfaceGraphState.for_target(TARGET)
    graph.add(url=f"{TARGET}/health", source_kind="probe")
    payload = graph.to_json()
    payload["operations"] = []
    with pytest.raises(SurfaceGraphError, match="unknown operation"):
        SurfaceGraphState.from_json(payload)

    unsafe = SurfaceOperation(
        operation_id="op_not-canonical",
        protocol="https",
        method="GET",
        origin=TARGET,
        route_shape="/credential-value",
        selector="",
        parameters=(),
        content_types=(),
        header_names=(),
        hints=(),
        provenance=("probe",),
    )
    with pytest.raises(SurfaceGraphError, match="not canonical"):
        graph.add_operation(unsafe)


def test_url_canonicalization_handles_ipv6_and_rejects_credentialed_urls() -> None:
    assert canonical_operation_url("https://[2001:0db8::1]:443/users/1?secret=value") == (
        "https://[2001:db8::1]",
        "https",
        "/users/{int}",
    )
    with pytest.raises(SurfaceGraphError, match="user information"):
        canonical_operation_url("https://user:password@example.test/admin")


def test_websocket_operations_bind_to_http_handshake_origin_without_losing_protocol() -> None:
    graph = SurfaceGraphState.for_target("https://example.test/app")

    operation = graph.add(
        url="wss://example.test/socket/123",
        method="GET",
        source_kind="browser",
    )

    assert graph.target_origin == TARGET
    assert operation.protocol == "wss"
    assert operation.origin == "wss://example.test"
    assert operation.route_shape == "/socket/{int}"
    with pytest.raises(SurfaceGraphError, match="another origin"):
        graph.add(
            url="ws://example.test/socket",
            method="GET",
            source_kind="browser",
        )


def test_malformed_recon_and_openapi_parameters_are_skipped_not_fatal() -> None:
    graph = SurfaceGraphState.for_target(TARGET)

    ingest_recon_surface(
        graph,
        {
            "pages": [
                {
                    "url": f"{TARGET}/search?!!!=bad&valid=ok",
                    "status": 200,
                    "forms": [
                        {
                            "action": f"{TARGET}/submit",
                            "method": "POST",
                            "inputs": [
                                {"name": "!!!", "type": "text"},
                                {"name": "email", "type": "text", "required": True},
                                {"name": "bad-required", "required": "sometimes"},
                            ],
                        }
                    ],
                }
            ]
        },
    )
    assert (
        ingest_openapi_document(
            graph,
            {
                "swagger": "2.0",
                "paths": {
                    "/upload": {
                        "post": {
                            "parameters": [
                                {"name": "file", "in": "formData", "type": "string"},
                                {"name": "!!!", "in": "query", "type": "string"},
                                {"name": "matrix", "in": "matrix", "type": "string"},
                                {"name": "valid", "in": "query", "required": True},
                            ]
                        }
                    }
                },
            },
            document_url=f"{TARGET}/swagger.json",
        )
        == 1
    )

    operations = tuple((graph.operations or {}).values())
    search = next(item for item in operations if item.route_shape == "/search")
    form = next(item for item in operations if item.route_shape == "/submit")
    upload = next(item for item in operations if item.route_shape == "/upload")
    assert {(item.name, item.location) for item in search.parameters} == {("valid", "query")}
    assert {(item.name, item.location) for item in form.parameters} == {("email", "form")}
    assert {(item.name, item.location) for item in upload.parameters} == {
        ("file", "form"),
        ("valid", "query"),
    }


def test_openapi_document_inspection_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(surface_graph_ingest_module, "_MAX_DOCUMENT_INSPECTIONS", 6)
    graph = SurfaceGraphState.for_target(TARGET)
    document = {
        "paths": {
            f"/bounded/route-{index}": {"get": {"operationId": f"operation-{index}"}}
            for index in range(20)
        }
    }

    added = ingest_openapi_document(
        graph,
        document,
        document_url=f"{TARGET}/openapi.json",
    )

    assert added == 3
    assert len(graph.operations or {}) == 3


def test_javascript_ingestion_calls_public_recon_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def parse(text: str) -> list[dict[str, object]]:
        calls.append(text)
        return [{"url": "/public-parser", "method": "GET", "fields": {}}]

    monkeypatch.setattr(recon_module, "parse_javascript_request_templates", parse)
    graph = SurfaceGraphState.for_target(TARGET)

    added = ingest_javascript_source(
        graph,
        script_text="managed-source",
        base_url=f"{TARGET}/app.js",
    )

    assert calls == ["managed-source"]
    assert added == 1
    assert next(iter((graph.operations or {}).values())).route_shape == "/public-parser"


def test_sensitive_path_values_are_structuralized_before_graph_persistence() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    sensitive_path_value = "private-native-probe-value"

    operation = graph.add(
        url=f"{TARGET}/reset/{sensitive_path_value}",
        source_kind="probe",
    )

    assert sensitive_path_value not in json.dumps(graph.to_json())
    assert operation.route_shape == "/reset/{segment}"


def test_exchange_parameter_adapter_skips_malformed_names_per_item() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    exchange = SimpleNamespace(
        source="external_tool",
        request_url=f"{TARGET}/items?!!!=bad&valid=ok",
        request_method="POST",
        request_body_field_names=("!!!", "email"),
        request_headers=(),
        request_resource_type="http",
        identity_alias="anonymous",
        response_status=200,
        scope_decision="allowed",
        replayability="safe",
        exchange_id="rq_0001",
        source_observation_id="probe-observation",
        captured_at="2026-08-26T00:00:00Z",
    )

    operation = graph.ingest_exchange(exchange)  # type: ignore[arg-type]

    assert {(item.name, item.location) for item in operation.parameters} == {
        ("email", "body"),
        ("valid", "query"),
    }


def test_external_adapter_rejects_oversized_arrays_before_ingestion() -> None:
    payload = {
        "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
        "url": f"{TARGET}/items",
        "method": "GET",
        "parameters": [
            {"name": f"field-{index}", "location": "query"}
            for index in range(65)
        ],
    }

    with pytest.raises(SurfaceGraphError, match="item limit"):
        SurfaceObservationInput.from_json(payload)


def test_external_batch_is_atomic_and_runtime_identity_owned() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    batch = {
        "schema": SURFACE_OBSERVATION_BATCH_SCHEMA,
        "observations": [
            {
                "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
                "url": f"{TARGET}/api/items/99?credential=not-persisted",
                "method": "GET",
                "identity_alias": "adapter-claimed-user",
                "parameters": [
                    {
                        "name": "credential",
                        "location": "query",
                        "data_type": "string",
                    }
                ],
                "evidence_refs": ["adapter-item-1"],
            }
        ],
    }

    assert (
        ingest_surface_observation_batch(
            graph,
            batch,
            identity_alias="identity:alice",
            evidence_ref="probe-observation-1",
        )
        == 1
    )

    [observation] = (graph.observations or {}).values()
    assert observation.identity_alias == "identity:alice"
    assert observation.source_kind == "external_tool"
    assert observation.evidence_refs == ("adapter-item-1", "probe-observation-1")
    assert "not-persisted" not in json.dumps(graph.to_json())

    invalid = {
        "schema": SURFACE_OBSERVATION_BATCH_SCHEMA,
        "observations": [
            {
                "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
                "url": f"{TARGET}/valid",
                "method": "GET",
            },
            {
                "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
                "url": "https://outside.invalid/not-imported",
                "method": "GET",
            },
        ],
    }
    empty = SurfaceGraphState.for_target(TARGET)
    with pytest.raises(SurfaceGraphError, match="another origin"):
        ingest_surface_observation_batch(empty, invalid)
    assert not empty.operations
    assert not empty.observations


def test_probe_result_wires_strict_external_batch_and_graphql_operation_shapes() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    added = ingest_probe_result(
        graph,
        {
            "probe": "typed_adapter",
            "findings": [
                {
                    "type": "surface_observation_batch",
                    "batch": {
                        "schema": SURFACE_OBSERVATION_BATCH_SCHEMA,
                        "observations": [
                            {
                                "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
                                "url": f"{TARGET}/adapter/search?term=value",
                                "method": "GET",
                                "parameters": [
                                    {"name": "term", "location": "query"}
                                ],
                            }
                        ],
                    },
                },
                {
                    "type": "graphql_schema_mapped",
                    "url": f"{TARGET}/graphql",
                    "operations": [
                        {
                            "operation_type": "query",
                            "field_name": "user",
                            "arguments": [
                                {
                                    "name": "id",
                                    "data_type": "NON_NULL_ID",
                                    "required": True,
                                }
                            ],
                        },
                        {
                            "operation_type": "mutation",
                            "field_name": "renameUser",
                            "arguments": [
                                {"name": "name", "data_type": "String"}
                            ],
                        },
                    ],
                },
            ],
        },
        identity_alias="alice",
        source_observation_id="probe-observation-2",
    )

    assert added == 3
    operations = tuple((graph.operations or {}).values())
    selectors = {item.selector: item for item in operations if item.selector}
    assert set(selectors) == {"Query.user", "Mutation.renameUser"}
    assert selectors["Query.user"].parameters == (
        SurfaceParameter.create(
            name="id",
            location="graphql",
            data_type="NON_NULL_ID",
            required=True,
        ),
    )
    adapter = next(item for item in operations if item.route_shape == "/adapter/search")
    assert adapter.provenance == ("external_tool",)


def test_graphql_raw_native_schema_shape_is_supported() -> None:
    raw_schema = {
        "queryType": {"name": "RootQuery"},
        "mutationType": {"name": "RootMutation"},
        "types": [
            {
                "name": "RootQuery",
                "fields": [
                    {
                        "name": "user",
                        "args": [
                            {
                                "name": "id",
                                "type": {
                                    "kind": "NON_NULL",
                                    "ofType": {"kind": "SCALAR", "name": "ID"},
                                },
                            }
                        ],
                    }
                ],
            },
            {
                "name": "RootMutation",
                "fields": [{"name": "renameUser", "args": []}],
            },
        ],
    }
    graph = SurfaceGraphState.for_target(TARGET)

    assert (
        ingest_graphql_schema(
            graph,
            raw_schema,
            endpoint_url=f"{TARGET}/graphql",
        )
        == 2
    )
    assert {item.selector for item in (graph.operations or {}).values()} == {
        "Query.user",
        "Mutation.renameUser",
    }


def test_openapi_local_refs_and_v2_body_shapes_are_bounded_and_value_free() -> None:
    document = {
        "swagger": "2.0",
        "consumes": ["application/json"],
        "parameters": {
            "CreateUserBody": {
                "name": "payload",
                "in": "body",
                "required": True,
                "schema": {"$ref": "#/definitions/CreateUser"},
            }
        },
        "definitions": {
            "CreateUser": {
                "type": "object",
                "required": ["username"],
                "properties": {
                    "username": {"type": "string", "example": "not-persisted"},
                    "role": {"$ref": "#/definitions/Role"},
                },
            },
            "Role": {"type": "string", "enum": ["admin-secret", "user"]},
        },
        "x-path-items": {
            "create-user": {
                "post": {
                    "parameters": [{"$ref": "#/parameters/CreateUserBody"}],
                }
            },
            "cycle": {"$ref": "#/x-path-items/cycle"},
        },
        "paths": {
            "/users": {"$ref": "#/x-path-items/create-user"},
            "/cycle": {"$ref": "#/x-path-items/cycle"},
        },
    }
    graph = SurfaceGraphState.for_target(TARGET)

    assert (
        ingest_openapi_document(
            graph,
            document,
            document_url=f"{TARGET}/swagger.json",
        )
        == 1
    )

    [operation] = (graph.operations or {}).values()
    assert operation.route_shape == "/users"
    assert operation.content_types == ("application/json",)
    assert {(item.name, item.data_type, item.required) for item in operation.parameters} == {
        ("username", "string", True),
        ("role", "string", False),
    }
    persisted = json.dumps(graph.to_json())
    assert "not-persisted" not in persisted
    assert "admin-secret" not in persisted


def test_captured_exchange_import_is_typed_target_bound_and_atomic() -> None:
    browser = build_captured_http_exchange(
        capture_session_id="browser-import",
        source="browser_capture",
        source_observation_id="browser:1",
        identity_alias="anonymous",
        method="POST",
        url=f"{TARGET}/browser/orders/123?coupon=not-persisted",
        request_headers={"Content-Type": "application/json"},
        request_body={"sku": "private-value"},
        request_sent=True,
        response_status=201,
        scope_decision="allowed",
        replayability="requires_authorization",
        known_secrets=("not-persisted", "private-value"),
    ).with_store_identity(exchange_id="rq_0001", sequence=1)
    graph = SurfaceGraphState.for_target(TARGET)

    assert ingest_captured_exchanges(graph, (browser,)) == 1
    [operation] = (graph.operations or {}).values()
    assert operation.provenance == ("browser",)
    assert operation.route_shape == "/browser/orders/{int}"
    assert "not-persisted" not in json.dumps(graph.to_json())

    with pytest.raises(SurfaceGraphError, match="typed exchanges"):
        ingest_captured_exchanges(SurfaceGraphState.for_target(TARGET), (object(),))  # type: ignore[arg-type]
