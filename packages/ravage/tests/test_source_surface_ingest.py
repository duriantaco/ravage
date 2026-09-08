# ruff: noqa: PLR2004
from __future__ import annotations

import json

import pytest
from ravage.agent_core import surface_graph_ingest as surface_graph_ingest_module
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.attack_surface import compact_surface_for_prompt
from ravage.agent_core.surface_graph import SurfaceGraphError, SurfaceGraphState, SurfaceParameter
from ravage.agent_core.surface_graph_ingest import (
    ingest_source_code_candidates,
    project_surface_graph,
)

TARGET = "https://example.test"


def _candidate(**updates: object) -> dict[str, object]:
    candidate: dict[str, object] = {
        "candidate_id": "src_a0b1c2d3e4f5",
        "family": "sqli",
        "input_location": "body",
        "input_name": "query",
        "line": 41,
        "method": "POST",
        "relative_file": "app/routes/search.py",
        "route": "/api/search",
        "sink_kind": "sql_execute",
    }
    candidate.update(updates)
    return candidate


def test_source_candidates_bind_origin_and_project_exact_request_shape() -> None:
    graph = SurfaceGraphState()

    assert (
        ingest_source_code_candidates(
            graph,
            [_candidate()],
            target_url=f"{TARGET}/ignored-base?token=not-persisted",
        )
        == 1
    )

    assert graph.target_origin == TARGET
    [operation] = (graph.operations or {}).values()
    assert operation.origin == TARGET
    assert operation.method == "POST"
    assert operation.route_shape == "/api/search"
    assert operation.parameters == (SurfaceParameter.create(name="query", location="body"),)
    assert operation.content_types == ("application/json",)
    assert operation.provenance == ("source_code",)
    assert {"source_code", "sqli", "sql_execute"} <= set(operation.hints)

    [observation] = (graph.observations or {}).values()
    assert observation.source_kind == "source_code"
    assert observation.access_level == "declared"
    assert observation.response_status is None
    assert observation.evidence_refs == ()
    assert graph.to_prompt_json()["operations"][0]["identity_statuses"] == {}

    projected = project_surface_graph(graph)
    [template] = projected["request_templates"]
    assert template["source"] == "source_code"
    assert template["method"] == "POST"
    assert template["url"] == f"{TARGET}/api/search"
    assert template["fields"] == {"query": ""}
    assert template["input_locations"] == {"query": "body"}
    assert template["encoding"] == "application/json"
    assert template["priority"] == 300

    [parameter] = projected["parameters"]
    assert parameter["sources"] == ["source_code", "surface_graph:body"]
    assert parameter["input_locations"] == ["body"]
    assert parameter["methods"] == ["POST"]
    assert parameter["priority"] == 300
    assert {"source_code", "sqli", "sql_execute"} <= set(parameter["hints"])
    assert "not-persisted" not in json.dumps(graph.to_json())
    assert "not-persisted" not in json.dumps(projected)


def test_source_form_candidate_projects_form_encoding() -> None:
    graph = SurfaceGraphState.for_target(TARGET)

    ingest_source_code_candidates(
        graph,
        [
            _candidate(
                candidate_id="src_b0b1c2d3e4f5",
                input_location="form",
                input_name="username",
                relative_file="app/routes/login.py",
                route="/login",
                sink_kind="query_builder",
            )
        ],
        target_url=TARGET,
    )

    projected = project_surface_graph(graph)
    [template] = projected["request_templates"]
    assert template["encoding"] == "application/x-www-form-urlencoded"
    assert template["input_locations"] == {"username": "form"}
    [operation] = (graph.operations or {}).values()
    assert operation.content_types == ("application/x-www-form-urlencoded",)


def test_source_candidate_merges_with_existing_operation_without_claiming_proof() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    existing = graph.add(
        url=f"{TARGET}/api/search",
        method="POST",
        parameters=(SurfaceParameter.create(name="page", location="query"),),
        source_kind="openapi",
    )

    ingest_source_code_candidates(
        graph,
        [_candidate()],
        target_url=TARGET,
    )

    assert len(graph.operations or {}) == 1
    operation = (graph.operations or {})[existing.operation_id]
    assert operation.provenance == ("openapi", "source_code")
    assert {(item.name, item.location) for item in operation.parameters} == {
        ("page", "query"),
        ("query", "body"),
    }
    observations = list((graph.observations or {}).values())
    source_observation = next(item for item in observations if item.source_kind == "source_code")
    assert source_observation.access_level == "declared"
    assert source_observation.response_status is None
    assert source_observation.evidence_refs == ()

    restored = SurfaceGraphState.from_json(graph.to_json())
    assert restored.to_json() == graph.to_json()


def test_source_candidate_target_mismatch_is_atomic() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    before = graph.to_json()

    with pytest.raises(SurfaceGraphError, match="does not match"):
        ingest_source_code_candidates(
            graph,
            [_candidate()],
            target_url="https://other.test",
        )

    assert graph.to_json() == before


def test_source_candidates_cannot_evict_existing_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    live = graph.add(
        url=f"{TARGET}/observed",
        method="GET",
        source_kind="browser",
        access_level="response",
        response_status=200,
    )
    before_ids = set(graph.operations or {})
    monkeypatch.setattr(surface_graph_ingest_module, "MAX_SURFACE_OPERATIONS", 1)

    imported = ingest_source_code_candidates(
        graph,
        [
            _candidate(route="/source-only"),
            _candidate(
                candidate_id="src_c0b1c2d3e4f5",
                input_location="query",
                method="GET",
                route="/observed",
            ),
        ],
        target_url=TARGET,
    )

    assert imported == 1
    assert set(graph.operations or {}) == before_ids
    merged = (graph.operations or {})[live.operation_id]
    assert merged.provenance == ("browser", "source_code")
    assert any(
        observation.operation_id == live.operation_id and observation.response_status == 200
        for observation in (graph.observations or {}).values()
    )


def test_source_candidates_cannot_evict_existing_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    operation = graph.add(
        url=f"{TARGET}/observed",
        method="GET",
        source_kind="browser",
        access_level="response",
        response_status=200,
    )
    before = graph.to_json()
    monkeypatch.setattr(surface_graph_ingest_module, "MAX_SURFACE_OBSERVATIONS", 1)

    imported = ingest_source_code_candidates(
        graph,
        [
            _candidate(
                input_location="query",
                method="GET",
                route="/observed",
            )
        ],
        target_url=TARGET,
    )

    assert imported == 0
    assert graph.to_json() == before
    assert (graph.operations or {})[operation.operation_id].provenance == ("browser",)


def test_source_projection_stays_bounded_in_model_context() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    candidates = [
        _candidate(
            candidate_id=f"src_{index:04d}",
            input_location="query",
            input_name=f"query_{index:04d}",
            line=index + 1,
            method="GET",
            route=f"/source/{index:04d}",
        )
        for index in range(512)
    ]
    ingest_source_code_candidates(graph, candidates, target_url=TARGET)
    state = AgentState(surface=project_surface_graph(graph), surface_graph=graph)

    prompt = state.to_prompt_context()
    payload = json.loads(prompt)

    assert len(prompt) < 100_000
    assert len(payload["surface"]["notable_endpoints"]) <= 16
    assert len(payload["surface"]["request_templates"]) <= 10
    assert len(payload["surface"]["high_value_parameters"]) <= 16
    assert len(payload["surface_graph"]["operations"]) <= 40


def test_prompt_reserves_source_families_and_ranks_source_projection() -> None:
    candidates = [
        _candidate(
            candidate_id=f"src_sql_{index}",
            family="sql_injection",
            route=f"/sql/{index}",
        )
        for index in range(8)
    ]
    candidates.extend(
        [
            _candidate(candidate_id="src_ssti", family="ssti", route="/template"),
            _candidate(candidate_id="src_ssrf", family="ssrf", route="/fetch"),
            _candidate(
                candidate_id="src_shell",
                family="command_injection",
                route="/command",
            ),
            _candidate(
                candidate_id="src_file",
                family="path_traversal",
                route="/download",
            ),
        ]
    )
    surface = {
        "source_candidates": candidates,
        "endpoints": [
            {"url": f"{TARGET}/visible", "priority": 1},
            {"url": f"{TARGET}/source", "priority": 300},
        ],
        "parameters": [
            {"name": "visible", "priority": 1},
            {"name": "source", "priority": 300},
        ],
        "request_templates": [
            {"method": "GET", "url": f"{TARGET}/visible", "priority": 1},
            {"method": "POST", "url": f"{TARGET}/source", "priority": 300},
        ],
    }

    compact = compact_surface_for_prompt(surface)

    assert {item["family"] for item in compact["source_candidates"]} >= {
        "sql_injection",
        "ssti",
        "ssrf",
        "command_injection",
        "path_traversal",
    }
    assert compact["notable_endpoints"][0]["url"].endswith("/source")
    assert compact["high_value_parameters"][0]["name"] == "source"
    assert compact["request_templates"][0]["url"].endswith("/source")


@pytest.mark.parametrize(
    "route",
    [
        "api/search",
        "//other.test/search",
        "https://other.test/search",
        "/safe/../admin",
        "/safe/%2e%2e/admin",
        "/safe%252fadmin",
        "/search?q=secret",
        "/bad\\route",
    ],
)
def test_source_candidate_rejects_malformed_or_escaping_routes(route: str) -> None:
    graph = SurfaceGraphState.for_target(TARGET)

    with pytest.raises(SurfaceGraphError, match="source route"):
        ingest_source_code_candidates(
            graph,
            [_candidate(route=route)],
            target_url=TARGET,
        )

    assert graph.to_json() == SurfaceGraphState.for_target(TARGET).to_json()


@pytest.mark.parametrize(
    "relative_file",
    [
        "/etc/passwd",
        "../app.py",
        "src/../../app.py",
        "C:/app.py",
        "src\\app.py",
        "src//app.py",
        "./src/app.py",
    ],
)
def test_source_candidate_rejects_absolute_or_escaping_source_paths(
    relative_file: str,
) -> None:
    graph = SurfaceGraphState.for_target(TARGET)

    with pytest.raises(SurfaceGraphError, match="source file"):
        ingest_source_code_candidates(
            graph,
            [_candidate(relative_file=relative_file)],
            target_url=TARGET,
        )

    assert not graph.operations
    assert not graph.observations


def test_source_candidate_batch_rejects_values_and_never_partially_imports() -> None:
    graph = SurfaceGraphState.for_target(TARGET)
    unsafe = _candidate(candidate_id="src_f0b1c2d3e4f5")
    unsafe["value"] = "super-secret"

    with pytest.raises(SurfaceGraphError, match="unsupported fields"):
        ingest_source_code_candidates(
            graph,
            [_candidate(), unsafe],
            target_url=TARGET,
        )

    assert not graph.operations
    assert not graph.observations
    assert "super-secret" not in json.dumps(graph.to_json())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("line", 0, "source line"),
        ("line", "41", "source line"),
        ("input_location", "url", "parameter location"),
        ("input_name", "query=value", "source input name"),
        ("candidate_id", "candidate id with spaces", "source candidate id"),
        ("sink_kind", "sql.execute()", "source sink kind"),
    ],
)
def test_source_candidate_requires_typed_structural_metadata(
    field: str,
    value: object,
    message: str,
) -> None:
    graph = SurfaceGraphState.for_target(TARGET)

    with pytest.raises(SurfaceGraphError, match=message):
        ingest_source_code_candidates(
            graph,
            [_candidate(**{field: value})],
            target_url=TARGET,
        )

    assert not graph.operations
