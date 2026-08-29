from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.agent_core.frontier_route import (
    BaseRouteTermination,
    FrontierObjectiveBasis,
    FrontierRoute,
)
from ravage.agent_core.frontier_transition import (
    inspect_base_route,
    seed_frontier_objectives,
)
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
MAX_BASE_REQUESTS = 40
BASE_COST_USD = 0.75
SEEDED_OBJECTIVE_COUNT = 4


def _workspace(tmp_path: Path, *, state: AgentState) -> AgentWorkspace:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    save_agent_state(workspace.state_path, target_url=TARGET_URL, state=state)
    return workspace


def _record_model_requests(workspace: AgentWorkspace, count: int) -> None:
    for turn in range(1, count + 1):
        workspace.record_event(
            kind="model_request_started",
            payload={"turn": turn, "model_request_id": f"request-{turn}"},
        )


def _record_finished(workspace: AgentWorkspace, *, turns: int, cost_usd: float = 0.0) -> None:
    workspace.record_event(
        kind="agent_finished",
        payload={"turns": turns, "flags": [], "cost_usd": cost_usd},
    )


def test_inspector_marks_an_unsolved_full_base_run_as_route_eligible(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path, state=AgentState(turn=MAX_BASE_REQUESTS))
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS, cost_usd=BASE_COST_USD)

    outcome = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    assert outcome.termination is BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED
    assert outcome.model_requests == MAX_BASE_REQUESTS
    assert outcome.proof_confirmed is False
    assert outcome.cost_usd == BASE_COST_USD
    assert outcome.state_digest


def test_inspector_never_serializes_the_exact_base_proof(tmp_path: Path) -> None:
    proof = "flag{executor-observed-secret}"
    workspace = _workspace(
        tmp_path,
        state=AgentState(turn=3, flags=[proof]),
    )
    _record_model_requests(workspace, 3)
    _record_finished(workspace, turns=3)

    outcome = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    assert outcome.termination is BaseRouteTermination.SOLVED
    assert outcome.proof_confirmed is True
    assert proof not in json.dumps(outcome.to_json())


def test_inspector_does_not_route_around_a_cost_stop(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, state=AgentState(turn=5))
    _record_model_requests(workspace, 5)
    workspace.record_event(
        kind="cost_budget_exhausted",
        payload={"turn": 5, "spent_cost_usd": 2.0, "max_cost_usd": 2.0},
    )
    _record_finished(workspace, turns=5, cost_usd=2.0)

    outcome = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    assert outcome.termination is BaseRouteTermination.COST_BUDGET_EXHAUSTED


def test_inspector_marks_a_missing_terminal_event_as_interrupted(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, state=AgentState(turn=2))
    _record_model_requests(workspace, 2)

    outcome = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    assert outcome.termination is BaseRouteTermination.INTERRUPTED


def test_explicit_base_error_is_not_misclassified_as_strategic_exhaustion(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path, state=AgentState(turn=2))
    _record_model_requests(workspace, 2)
    _record_finished(workspace, turns=2)

    outcome = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
        run_error=RuntimeError("provider quota exhausted"),
    )

    assert outcome.termination is BaseRouteTermination.ERROR


def test_frontier_seed_uses_untried_generic_specialists_from_base_state(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        facts=["search form returns a different row count for query-like values"],
        signals={
            "endpoints": ["/search"],
            "parameters": ["query"],
            "markers": ["data_query_signal"],
        },
        actions=[
            {
                "action": "run_probe",
                "probe": "surface_map",
                "outcome": "observed",
            }
        ],
    )
    workspace = _workspace(tmp_path, state=state)
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    objectives = seed_frontier_objectives(state, base=base, limit=4)

    assert objectives
    assert objectives[0].probe != "surface_map"
    assert objectives[0].basis is FrontierObjectiveBasis.BASE_FRONTIER
    assert objectives[0].evidence_refs == (f"base-state:{base.state_digest}",)
    assert any(item.family == "sql_injection" for item in objectives)


def test_authenticated_frontier_seed_omits_unmanaged_transport_specialists(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        surface={"authenticated_identity": "analyst"},
        facts=["browser boundary and CMS exposure observed"],
        primitives={
            "browser_boundary_confirmed": 5,
            "cms_exposure_observed": 4,
        },
    )
    workspace = _workspace(tmp_path, state=state)
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    objectives = seed_frontier_objectives(state, base=base, limit=16)

    assert "browser_boundary" not in {item.probe for item in objectives}
    assert "cms_exposure" not in {item.probe for item in objectives}


def test_frontier_seed_is_deterministic_and_has_no_benchmark_answer_channel(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        facts=["upload form accepts XML documents"],
        signals={"endpoints": ["/import"], "parameters": ["document"]},
    )
    workspace = _workspace(tmp_path, state=state)
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    first = seed_frontier_objectives(state, base=base, limit=3)
    second = seed_frontier_objectives(state, base=base, limit=3)
    encoded = json.dumps([item.to_json() for item in first]).lower()

    assert first == second
    assert "xben" not in encoded
    assert "benchmark" not in encoded
    assert "ground_truth" not in encoded
    assert "flag{" not in encoded


def test_frontier_seed_prioritizes_confirmed_primitive_with_material_variations(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        facts=["ssti_stored_signal observed in a multi-step form"],
        signals={
            "endpoints": ["/register/final"],
            "parameters": ["name", "csrfmiddlewaretoken"],
        },
        primitives={"ssti_confirmed": 5},
        actions=[
            {
                "action": "run_probe",
                "probe": "ssti_fingerprint",
                "outcome": "same_as_before",
                "repeat_count": 4,
            }
        ],
    )
    workspace = _workspace(tmp_path, state=state)
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    objectives = seed_frontier_objectives(state, base=base, limit=4)

    assert [item.probe for item in objectives[:3]] == [
        "ssti_fingerprint",
        "ssti_fingerprint",
        "ssti_fingerprint",
    ]
    assert [item.payload_class.rsplit(":", 1)[-1] for item in objectives[:3]] == [
        "request_contract",
        "payload_semantics",
        "proof_channel",
    ]
    assert "do not rerun it unchanged" in objectives[0].expected_signal.lower()
    assert objectives[0].endpoint == "/register/final"


def test_frontier_seed_stays_depth_first_on_primary_primitive_before_branching(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        facts=["sql_injection_confirmed on login", "xml upload parser observed"],
        signals={
            "request_templates": [json.dumps({"method": "POST", "url": "/index.php"})],
            "sqli_inputs": [json.dumps({"input": "username", "url": "/index.php"})],
            "xml_requests": [json.dumps({"input": "document", "url": "/upload"})],
        },
        primitives={"sqli_confirmed": 6, "xxe_surface_observed": 7},
    )
    workspace = _workspace(tmp_path, state=state)
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    objectives = seed_frontier_objectives(state, base=base, limit=4)

    assert [item.payload_class for item in objectives] == [
        "confirmed_primitive:sqli_confirmed:request_contract",
        "confirmed_primitive:sqli_confirmed:payload_semantics",
        "confirmed_primitive:sqli_confirmed:proof_channel",
        "confirmed_primitive:xxe_surface_observed:request_contract",
    ]


def test_confirmed_primitive_uses_family_request_templates_over_polluted_surface(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        facts=["sql_injection_confirmed on the login transport"],
        signals={
            "endpoints": ["/unrelated/traversal/flag.txt", "/index.php"],
            "request_templates": [
                json.dumps(
                    {
                        "method": "POST",
                        "source": "jquery_ajax",
                        "url": "index.php",
                    }
                )
            ],
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "POST",
                        "payload_field": "username",
                        "url": "/index.php",
                    }
                )
            ],
        },
        primitives={"sqli_confirmed": 6},
        actions=[
            {
                "action": "run_probe",
                "probe": "sqli_exploit",
                "outcome": "same_as_before",
                "repeat_count": 4,
            }
        ],
        attempts=[
            {
                "selected_route": {
                    "family": "sql_injection",
                    "endpoints": ["/"],
                    "inputs": ["username"],
                }
            }
        ],
    )
    workspace = _workspace(tmp_path, state=state)
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    objective = seed_frontier_objectives(state, base=base, limit=1)[0]

    assert objective.family == "sql_injection"
    assert objective.endpoint == "index.php"
    assert objective.inputs == ("username",)


def test_run22_seed_uses_get_replay_as_candidate_over_generic_post_template(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        facts=["SQLi is confirmed and should be exploited for extraction."],
        signals={
            "request_templates": [
                json.dumps(
                    {
                        "method": "POST",
                        "source": "jquery_ajax",
                        "url": "index.php",
                    }
                )
            ],
            "forms": [
                json.dumps(
                    {
                        "method": "POST",
                        "action": TARGET_URL,
                        "inputs": [
                            {"name": "username"},
                            {"name": "password"},
                        ],
                    }
                )
            ],
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "replay_hint": "Replay this confirmed template verbatim.",
                        "source": "replay",
                        "url": f"{TARGET_URL}/?username=admin%27--",
                    }
                )
            ],
            "sqli_inputs": [
                json.dumps(
                    {
                        "input": "username",
                        "kind": "replay",
                        "url": f"{TARGET_URL}/?username=admin%27--",
                    }
                )
            ],
        },
        primitives={"sqli_confirmed": 6, "xxe_surface_observed": 7},
        actions=[
            {
                "action": "run_probe",
                "probe": "sqli_exploit",
                "outcome": "same_as_before",
                "repeat_count": 5,
            }
        ],
    )
    workspace = _workspace(tmp_path, state=state)
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )

    objectives = seed_frontier_objectives(
        state,
        base=base,
        limit=SEEDED_OBJECTIVE_COUNT,
    )

    assert len(objectives) == SEEDED_OBJECTIVE_COUNT
    assert all(item.endpoint == f"{TARGET_URL}/" for item in objectives[:3])
    assert all(item.inputs == ("username",) for item in objectives[:3])
    assert all(
        any(ref.startswith("replay-contract:") for ref in item.evidence_refs)
        for item in objectives[:3]
    )
    assert all("method=GET" in item.expected_signal for item in objectives[:3])
    assert all(
        "Candidate base-tool replay to validate" in item.expected_signal for item in objectives[:3]
    )
    assert objectives[3].family == "xml_external_entity"


def test_seeded_objective_can_start_the_bounded_route_without_mutating_base(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=MAX_BASE_REQUESTS,
        facts=["URL fetch form posts a callback parameter"],
        signals={"endpoints": ["/fetch"], "parameters": ["url"]},
    )
    workspace = _workspace(tmp_path, state=state)
    before = workspace.state_path.read_bytes()
    _record_model_requests(workspace, MAX_BASE_REQUESTS)
    _record_finished(workspace, turns=MAX_BASE_REQUESTS)
    base = inspect_base_route(
        workspace.root,
        target_url=TARGET_URL,
        max_model_requests=MAX_BASE_REQUESTS,
    )
    objective = seed_frontier_objectives(state, base=base, limit=1)[0]

    route = FrontierRoute.start(
        base=base,
        initial_objective=objective,
        scope=(TARGET_URL,),
    )

    assert route.active_worker is not None
    assert workspace.state_path.read_bytes() == before
