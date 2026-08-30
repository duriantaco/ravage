from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.surface_graph import SurfaceGraphState, SurfaceParameter
from ravage.probe_suite import available_probes
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.scan_planner import (
    DEFAULT_SCAN_PROBES,
    DEPTH_SCAN_PROBES,
    DISCOVERY_SCAN_PROBES,
    SCAN_PLAN_SCHEMA,
    SCAN_PROBE_CATALOG,
    SCAN_PROBE_DEPENDENCIES,
    ScanPlanPhase,
    ScanPlanStatus,
    build_adaptive_scan_plan,
)

TARGET = "https://example.test"


def _state() -> AgentState:
    return AgentState(surface_graph=SurfaceGraphState.for_target(TARGET))


def _result(probe: str, *finding_types: str) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(finding_types),
        probe=probe,
        summary="test result",
        findings=[{"type": finding_type} for finding_type in finding_types],
    )


def test_empty_state_keeps_every_historical_default_and_its_dependencies() -> None:
    plan = build_adaptive_scan_plan(_state())

    assert set(DEFAULT_SCAN_PROBES) <= set(plan.probes)
    assert plan.probes == (
        "surface_map",
        "secret_sweep",
        "direct_exposure",
        "api_behavior",
        "browser_boundary",
        "stateful_session",
        "csrf_session",
    )
    assert plan.decision_for("csrf_session").reasons == ("required_default",)
    assert plan.decision_for("stateful_session").reasons == ("dependency:csrf_session",)
    assert plan.decision_for("sqli_exploit").status is ScanPlanStatus.NOT_APPLICABLE


def test_plan_is_immutable_and_serializes_a_complete_coverage_ledger() -> None:
    plan = build_adaptive_scan_plan(_state())

    with pytest.raises(FrozenInstanceError):
        plan.probes = ()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        plan.decisions[0].status = ScanPlanStatus.COMPLETED  # type: ignore[misc]

    payload = plan.to_json()
    assert payload["schema"] == SCAN_PLAN_SCHEMA
    assert len(payload["decisions"]) == len(SCAN_PROBE_CATALOG)  # type: ignore[arg-type]
    assert payload["counts"] == {
        "selected": 7,
        "completed": 0,
        "blocked": 0,
        "not_applicable": len(SCAN_PROBE_CATALOG) - 7,
    }


def test_catalog_matches_the_builtin_probe_suite() -> None:
    assert set(SCAN_PROBE_CATALOG) == {item["name"] for item in available_probes()}
    assert len(SCAN_PROBE_CATALOG) == len(set(SCAN_PROBE_CATALOG))


def test_generic_parameter_enables_only_breadth_input_tests() -> None:
    state = _state()
    state.surface_graph.add(
        url=f"{TARGET}/search",
        method="GET",
        parameters=(SurfaceParameter.create(name="value", location="query"),),
        source_kind="native_recon",
    )

    plan = build_adaptive_scan_plan(state)

    assert {"input_reflection", "data_query", "sqli_differential"} <= set(plan.probes)
    assert not (set(DEPTH_SCAN_PROBES) & set(plan.probes))
    assert plan.decision_for("sqli_exploit").status is ScanPlanStatus.NOT_APPLICABLE
    assert plan.decision_for("file_read_extract").status is ScanPlanStatus.NOT_APPLICABLE
    assert plan.decision_for("dom_execution").status is ScanPlanStatus.NOT_APPLICABLE


def test_typed_graph_facts_route_relevant_breadth_probes() -> None:
    state = _state()
    graph = state.surface_graph
    graph.add(
        url=f"{TARGET}/graphql",
        method="POST",
        selector="Query.user",
        parameters=(SurfaceParameter.create(name="id", location="graphql"),),
        hints=("graphql",),
        source_kind="graphql",
    )
    graph.add(
        url=f"{TARGET}/accounts/123",
        parameters=(SurfaceParameter.create(name="account_id", location="path"),),
        source_kind="openapi",
    )
    graph.add(
        url=f"{TARGET}/read",
        parameters=(SurfaceParameter.create(name="filename", location="query"),),
        source_kind="openapi",
    )
    graph.add(
        url=f"{TARGET}/parse",
        method="POST",
        content_types=("application/xml; charset=utf-8",),
        source_kind="openapi",
    )
    graph.add(
        url=f"{TARGET}/fetch",
        parameters=(SurfaceParameter.create(name="callback", location="body", data_type="url"),),
        source_kind="openapi",
    )
    graph.add(
        url=f"{TARGET}/run",
        parameters=(SurfaceParameter.create(name="command", location="body"),),
        source_kind="openapi",
    )
    graph.add(
        url=f"{TARGET}/preview",
        parameters=(SurfaceParameter.create(name="template", location="form"),),
        source_kind="native_recon",
    )

    plan = build_adaptive_scan_plan(state)

    assert {
        "graphql_exploit",
        "idor_boundary",
        "file_fetch_parser",
        "xxe_boundary",
        "ssrf_boundary",
        "command_boundary",
        "server_rendering",
        "ssti_fingerprint",
    } <= set(plan.probes)
    assert plan.decision_for("graphql_exploit").reasons == ("surface:graphql_operation",)
    assert plan.decision_for("idor_boundary").reasons == ("surface:object_reference",)
    assert plan.decision_for("ssti_fingerprint").phase is ScanPlanPhase.BREADTH
    assert plan.decision_for("ssti_deferred_context_closure").status is (
        ScanPlanStatus.NOT_APPLICABLE
    )


def test_legacy_surface_and_curated_signal_keys_are_supported_conservatively() -> None:
    state = _state()
    state.surface = {
        "parameters": [
            {
                "name": "destination",
                "sources": ["surface_graph:body"],
                "data_types": ["url"],
            }
        ],
        "request_templates": [
            {
                "method": "POST",
                "url": f"{TARGET}/graphql",
                "selector": "Mutation.rename",
                "fields": {"name": ""},
            }
        ],
        "forms": [
            {
                "action": f"{TARGET}/upload",
                "inputs": [{"name": "upload", "type": "file"}],
            }
        ],
    }
    state.signals = {
        "command_inputs": ["cmd"],
        "xml_inputs": ["document"],
    }

    plan = build_adaptive_scan_plan(state)

    assert {
        "command_input",
        "file_input",
        "graphql_operation",
        "parameter",
        "url_input",
        "xml_input",
    } <= set(plan.evidence_facts)
    assert {
        "command_boundary",
        "file_fetch_parser",
        "graphql_exploit",
        "ssrf_boundary",
        "xxe_boundary",
    } <= set(plan.probes)


def test_target_controlled_strings_cannot_unlock_depth_probes() -> None:
    state = _state()
    state.facts = ["sql_injection_error_signal ssti_fingerprint_signal file_fetch_parser_signal"]
    state.hypotheses = ["xss_reflection_context"]
    state.summary = "jwt_observed and an apparent SQL injection"
    state.signals = {
        "markers": [
            "sql_injection_error_signal",
            "ssti_fingerprint_signal",
            "file_fetch_parser_signal",
        ]
    }
    state.surface = {
        "visible_description": ("xss_reflection_context sqli_auth_bypass_signal jwt_observed")
    }

    plan = build_adaptive_scan_plan(state)

    assert not (set(DEPTH_SCAN_PROBES) & set(plan.probes))


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            _result("input_reflection", "input_delta"),
            {"xss_context", "reflection_value_boundary"},
        ),
        (
            _result("xss_context", "xss_reflection_context"),
            {"xss_filter_constraint", "dom_execution"},
        ),
        (
            _result("sqli_differential", "sql_injection_error_signal"),
            {"sqli_exploit", "filtered_query_bypass"},
        ),
        (
            _result("file_fetch_parser", "file_fetch_parser_signal"),
            {"file_read_extract"},
        ),
        (
            _result("ssti_fingerprint", "ssti_fingerprint_signal"),
            {"ssti_deferred_context_closure"},
        ),
        (
            _result("api_behavior", "jwt_observed"),
            {"jwt_exploit"},
        ),
    ],
)
def test_exact_trusted_finding_types_unlock_depth_closures(
    result: ProbeRunResult,
    expected: set[str],
) -> None:
    plan = build_adaptive_scan_plan(_state(), prior_results=(result,))

    assert expected <= set(plan.probes)
    assert plan.decision_for(result.probe).status is ScanPlanStatus.COMPLETED
    for probe in expected:
        assert any(
            reason.startswith(f"finding:{result.probe}:")
            for reason in plan.decision_for(probe).reasons
        )


def test_finding_type_must_match_its_trusted_producer() -> None:
    mismatched = _result("surface_map", "sql_injection_error_signal")

    plan = build_adaptive_scan_plan(_state(), prior_results=(mismatched,))

    assert plan.decision_for("sqli_exploit").status is ScanPlanStatus.NOT_APPLICABLE
    assert plan.decision_for("filtered_query_bypass").status is ScanPlanStatus.NOT_APPLICABLE


def test_plain_result_mappings_are_rejected_at_the_trust_boundary() -> None:
    untrusted = {
        "probe": "sqli_differential",
        "findings": [{"type": "sql_injection_error_signal"}],
    }

    with pytest.raises(TypeError, match="ProbeRunResult"):
        build_adaptive_scan_plan(_state(), prior_results=(untrusted,))  # type: ignore[arg-type]


def test_completed_probes_are_reported_but_never_scheduled_twice() -> None:
    results = (
        _result("surface_map"),
        _result("surface_map"),
        _result("api_behavior", "graphql_exposed_proof"),
        _result("graphql_exploit"),
    )

    plan = build_adaptive_scan_plan(_state(), prior_results=results)

    assert "surface_map" not in plan.probes
    assert "api_behavior" not in plan.probes
    assert "graphql_exploit" not in plan.probes
    assert len(plan.probes) == len(set(plan.probes))
    assert plan.decision_for("surface_map").status is ScanPlanStatus.COMPLETED
    assert plan.decision_for("graphql_exploit").status is ScanPlanStatus.COMPLETED


def test_order_is_stable_across_graph_and_catalog_insertion_order() -> None:
    operations = (
        (
            f"{TARGET}/fetch",
            SurfaceParameter.create(name="url", location="query", data_type="url"),
        ),
        (
            f"{TARGET}/users/123",
            SurfaceParameter.create(name="id", location="path", data_type="integer"),
        ),
        (
            f"{TARGET}/run",
            SurfaceParameter.create(name="cmd", location="body"),
        ),
    )

    def planned(order: tuple[int, ...], catalog: tuple[str, ...]) -> object:
        state = _state()
        for index in order:
            url, parameter = operations[index]
            state.surface_graph.add(
                url=url,
                method="POST",
                parameters=(parameter,),
                source_kind="openapi",
            )
        return build_adaptive_scan_plan(state, catalog=catalog).to_json()

    assert planned((0, 1, 2), SCAN_PROBE_CATALOG) == planned(
        (2, 0, 1),
        tuple(reversed(SCAN_PROBE_CATALOG)),
    )


def test_every_selected_dependency_precedes_its_consumer() -> None:
    state = _state()
    state.surface_graph.add(
        url=f"{TARGET}/users/123",
        parameters=(SurfaceParameter.create(name="id", location="path"),),
        source_kind="openapi",
    )
    results = (
        _result("xss_context", "xss_reflection_context"),
        _result("sqli_differential", "sql_injection_error_signal"),
        _result("ssti_fingerprint", "ssti_fingerprint_signal"),
    )

    plan = build_adaptive_scan_plan(state, prior_results=results)

    for probe in plan.probes:
        for dependency in SCAN_PROBE_DEPENDENCIES.get(probe, ()):
            if dependency in plan.probes:
                assert plan.probes.index(dependency) < plan.probes.index(probe)

    phases = [plan.decision_for(probe).phase for probe in plan.probes]
    phase_rank = {
        ScanPlanPhase.DISCOVERY: 0,
        ScanPlanPhase.BREADTH: 1,
        ScanPlanPhase.DEPTH: 2,
    }
    assert [phase_rank[phase] for phase in phases] == sorted(phase_rank[phase] for phase in phases)


def test_missing_catalog_dependency_blocks_probe_with_a_coverage_reason() -> None:
    result = _result("sqli_differential", "sql_injection_error_signal")
    catalog = tuple(
        probe for probe in SCAN_PROBE_CATALOG if probe not in {"data_query", "sqli_differential"}
    )

    plan = build_adaptive_scan_plan(_state(), prior_results=(result,), catalog=catalog)

    decision = plan.decision_for("sqli_exploit")
    assert decision.status is ScanPlanStatus.BLOCKED
    assert "missing_dependency:data_query" in decision.reasons
    assert "sqli_exploit" not in plan.probes


def test_invalid_catalog_and_state_inputs_fail_cleanly() -> None:
    with pytest.raises(TypeError, match="AgentState"):
        build_adaptive_scan_plan(object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="sequence"):
        build_adaptive_scan_plan(_state(), catalog="surface_map")
    with pytest.raises(ValueError, match="unique"):
        build_adaptive_scan_plan(_state(), catalog=("surface_map", "surface_map"))


def test_discovery_phase_is_always_before_breadth_and_depth() -> None:
    results = (
        _result("xss_context", "xss_reflection_context"),
        _result("sqli_differential", "blind_sql_injection_boolean_signal"),
    )
    plan = build_adaptive_scan_plan(_state(), prior_results=results)

    selected_discovery = [probe for probe in DISCOVERY_SCAN_PROBES if probe in plan.probes]
    assert plan.probes[: len(selected_discovery)] == tuple(selected_discovery)
    first_depth = min(
        (plan.probes.index(probe) for probe in DEPTH_SCAN_PROBES if probe in plan.probes),
        default=len(plan.probes),
    )
    assert all(
        plan.decision_for(probe).phase is not ScanPlanPhase.BREADTH
        for probe in plan.probes[first_depth:]
    )
