from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from ravage.agent_core.autonomous_graph.adapter import (
    GraphRouteAdapterError,
    GraphRouteConfig,
    GraphRouteContext,
    coordinator_objective,
    graph_objective_from_frontier,
)
from ravage.agent_core.autonomous_graph.model_bridge import graph_role_model_policy_key
from ravage.agent_core.autonomous_graph.models import (
    GraphAgentRole,
    GraphLimits,
    GraphObjective,
    GraphStatus,
)
from ravage.agent_core.autonomous_graph.worker import (
    GraphModelReply,
    GraphToolResult,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
)

TARGET_URL = "http://127.0.0.1:8765"
BASE_REQUESTS = 40
BASE_COST_USD = 0.5
MODEL_TURN_COST_USD = 0.1
EXPECTED_GRAPH_TURNS = 3
INITIAL_NODE_COUNT = 2
DYNAMIC_NODE_COUNT = 3
RACED_NODE_COUNT = 3


def _base(tmp_path: Path) -> BaseRouteOutcome:
    state_path = tmp_path / "working_state.json"
    state_path.write_text(
        json.dumps(
            {
                "target_url": TARGET_URL,
                "state": {"facts": ["search accepts query"]},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=BASE_REQUESTS,
        state_digest=hashlib.sha256(state_path.read_bytes()).hexdigest(),
        state_ref=str(state_path),
        cost_usd=BASE_COST_USD,
    )


def _seed(
    *,
    family: str = "sql_injection",
    strategy: str = "sqli_differential",
) -> GraphObjective:
    return GraphObjective.create(
        family=family,
        instruction=f"Investigate the {strategy} route depth-first",
        endpoint="/search",
        inputs=("query",),
        strategy=strategy,
        expected_signal=f"target-observed progress for {strategy}",
    )


def _root(seeds: tuple[GraphObjective, ...]) -> GraphObjective:
    return coordinator_objective(seeds)


@pytest.mark.asyncio
async def test_new_route_binds_base_scope_config_and_seeded_nodes(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    route_dir = tmp_path / "graph-route"

    context = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=_root((seed,)),
        seeded_objectives=(seed,),
    )

    assert context.resumed is False
    assert context.coordinator.state.graph_id == context.manifest.graph_id
    assert len(context.coordinator.state.nodes) == INITIAL_NODE_COUNT
    assert context.manifest.seeded_objective_fingerprints == (seed.fingerprint,)
    assert (route_dir / "graph-state.json").is_file()
    assert (route_dir / "graph-route-manifest.json").is_file()
    assert (route_dir / "evidence-blackboard.json").is_file()


@pytest.mark.asyncio
async def test_matching_resume_does_not_duplicate_seeded_nodes(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    root = _root((seed,))
    route_dir = tmp_path / "graph-route"
    first = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )

    resumed = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )

    assert first.resumed is False
    assert resumed.resumed is True
    assert len(resumed.coordinator.state.nodes) == INITIAL_NODE_COUNT


@pytest.mark.asyncio
async def test_resume_rejects_pending_model_billing_without_mutating_snapshot(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    root = _root((seed,))
    route_dir = tmp_path / "pending-model-route"
    context = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )
    await context.coordinator.begin_model_request(context.coordinator.state.root_node_id)
    state_path = route_dir / "graph-state.json"
    persisted_before = state_path.read_bytes()

    with pytest.raises(GraphRouteAdapterError, match="durable billing reconciliation"):
        await GraphRouteContext.open(
            base=base,
            target_url=TARGET_URL,
            scope=(TARGET_URL,),
            workspace_dir=route_dir,
            root_objective=root,
            seeded_objectives=(seed,),
        )

    assert state_path.read_bytes() == persisted_before


@pytest.mark.asyncio
async def test_selective_race_uses_two_role_models_and_resume_does_not_duplicate(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    root = _root((seed,))
    route_dir = tmp_path / "raced-graph-route"
    config = GraphRouteConfig(
        max_seeded_objectives=1,
        max_race_groups=1,
    )

    first = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
        config=config,
        available_model_routes=2,
    )
    resumed = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
        config=config,
        available_model_routes=2,
    )

    assert first.resumed is False
    assert resumed.resumed is True
    assert len(resumed.coordinator.state.nodes) == RACED_NODE_COUNT
    assert len(resumed.coordinator.state.race_groups) == 1
    group = next(iter(resumed.coordinator.state.race_groups.values()))
    lanes = [resumed.coordinator.state.nodes[node_id] for node_id in group.member_node_ids]
    assert [node.agent_spec.role for node in lanes] == [
        GraphAgentRole.DISCOVERY,
        GraphAgentRole.CRITIC,
    ]
    assert [node.agent_spec.model_policy_key for node in lanes] == [
        graph_role_model_policy_key(GraphAgentRole.DISCOVERY),
        graph_role_model_policy_key(GraphAgentRole.CRITIC),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("available_model_routes", "limits", "max_race_groups"),
    [
        (1, GraphLimits(), 1),
        (2, GraphLimits(), 0),
        (2, GraphLimits(max_nodes=2, max_concurrent_nodes=2), 1),
        (
            2,
            GraphLimits(
                max_model_requests=2,
                proof_reserve_model_requests=1,
            ),
            1,
        ),
    ],
)
async def test_selective_race_falls_back_when_capability_or_budget_is_insufficient(
    tmp_path: Path,
    available_model_routes: int,
    limits: GraphLimits,
    max_race_groups: int,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    context = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=(
            tmp_path / f"fallback-{available_model_routes}-{limits.max_nodes}-{max_race_groups}"
        ),
        root_objective=_root((seed,)),
        seeded_objectives=(seed,),
        config=GraphRouteConfig(
            limits=limits,
            max_seeded_objectives=1,
            max_race_groups=max_race_groups,
        ),
        available_model_routes=available_model_routes,
    )

    assert context.coordinator.state.race_groups == {}
    assert len(context.coordinator.state.nodes) == INITIAL_NODE_COUNT


def test_heterogeneous_racing_is_opt_in_and_rejects_finite_cost_limits() -> None:
    assert GraphRouteConfig().max_race_groups == 0
    assert (
        GraphRouteConfig(
            limits=GraphLimits(max_cost_usd=0.25),
        ).max_race_groups
        == 0
    )

    with pytest.raises(GraphRouteAdapterError, match="trusted per-route cost ceilings"):
        GraphRouteConfig(
            limits=GraphLimits(max_cost_usd=0.25),
            max_race_groups=1,
        )


@pytest.mark.asyncio
async def test_resume_allows_additional_model_spawned_children(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    root = _root((seed,))
    route_dir = tmp_path / "graph-route"
    context = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )
    await context.coordinator.spawn_node(
        parent_id=context.coordinator.state.root_node_id,
        name="novel-counterfactual",
        objective=_seed(
            family="path_traversal",
            strategy="file_read_boundary",
        ),
        lease_limit=2,
    )

    resumed = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )

    assert resumed.resumed is True
    assert len(resumed.coordinator.state.nodes) == DYNAMIC_NODE_COUNT


@pytest.mark.asyncio
async def test_changed_target_base_scope_or_config_fails_before_work(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    root = _root((seed,))
    route_dir = tmp_path / "graph-route"
    await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )

    with pytest.raises(GraphRouteAdapterError, match="target does not match"):
        await GraphRouteContext.open(
            base=base,
            target_url="http://127.0.0.1:9999",
            scope=(TARGET_URL,),
            workspace_dir=route_dir,
            root_objective=root,
            seeded_objectives=(seed,),
        )
    with pytest.raises(GraphRouteAdapterError, match="scope_identity mismatch"):
        await GraphRouteContext.open(
            base=base,
            target_url=TARGET_URL,
            scope=(TARGET_URL, "http://127.0.0.1:9000"),
            workspace_dir=route_dir,
            root_objective=root,
            seeded_objectives=(seed,),
        )
    changed = GraphRouteConfig(
        limits=replace(GraphLimits(), max_tool_calls=95),
    )
    with pytest.raises(GraphRouteAdapterError, match="config_identity mismatch"):
        await GraphRouteContext.open(
            base=base,
            target_url=TARGET_URL,
            scope=(TARGET_URL,),
            workspace_dir=route_dir,
            root_objective=root,
            seeded_objectives=(seed,),
            config=changed,
        )

    assert context_request_count(route_dir) == 0


@pytest.mark.asyncio
async def test_changed_base_artifact_fails_before_resume(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    root = _root((seed,))
    route_dir = tmp_path / "graph-route"
    await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )
    _overwrite_state(Path(base.state_ref))

    with pytest.raises(GraphRouteAdapterError, match="digest no longer matches"):
        await GraphRouteContext.open(
            base=base,
            target_url=TARGET_URL,
            scope=(TARGET_URL,),
            workspace_dir=route_dir,
            root_objective=root,
            seeded_objectives=(seed,),
        )

    assert context_request_count(route_dir) == 0


@pytest.mark.asyncio
async def test_orphan_state_or_manifest_fails_closed(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    route_dir = tmp_path / "graph-route"
    route_dir.mkdir()
    (route_dir / "graph-state.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(GraphRouteAdapterError, match="without its identity manifest"):
        await GraphRouteContext.open(
            base=base,
            target_url=TARGET_URL,
            scope=(TARGET_URL,),
            workspace_dir=route_dir,
            root_objective=_root((seed,)),
            seeded_objectives=(seed,),
        )

    assert not (route_dir / "evidence-blackboard.json").exists()


@pytest.mark.asyncio
async def test_manifest_first_bootstrap_recovers_when_state_was_not_published(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    root = _root((seed,))
    route_dir = tmp_path / "manifest-first-route"
    first = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )
    (route_dir / "graph-state.json").unlink()

    recovered = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=route_dir,
        root_objective=root,
        seeded_objectives=(seed,),
    )

    assert recovered.resumed is False
    assert recovered.manifest == first.manifest
    assert (route_dir / "graph-state.json").is_file()


@pytest.mark.asyncio
async def test_bounded_graph_run_combines_base_and_route_accounting(
    tmp_path: Path,
) -> None:
    base = _base(tmp_path)
    seed = _seed()
    context = await GraphRouteContext.open(
        base=base,
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        workspace_dir=tmp_path / "graph-route",
        root_objective=_root((seed,)),
        seeded_objectives=(seed,),
    )

    async def complete(
        node_id: str,
        _messages: list[dict[str, str]],
    ) -> GraphModelReply:
        children = context.coordinator.state.children_of(node_id)
        active_children = [child for child in children if child.status.value != "completed"]
        if active_children:
            payload = {
                "kind": "wait",
                "payload": {"timeout_seconds": 0},
                "rationale": "wait for seeded specialist",
            }
        else:
            payload = {
                "kind": "finish",
                "payload": {
                    "summary": "bounded route completed without proof",
                    "evidence_refs": [],
                },
                "rationale": "assigned work is complete",
            }
        return GraphModelReply(
            content=json.dumps(payload),
            cost_usd=MODEL_TURN_COST_USD,
        )

    async def execute(
        _node_id: str,
        _tool: str,
        _arguments: dict[str, object],
    ) -> GraphToolResult:
        message = "this fixture should finish without tool execution"
        raise AssertionError(message)

    result = await context.run(
        complete=complete,
        execute=execute,
    )

    assert result.graph.status is GraphStatus.EXHAUSTED
    assert result.route_model_requests == EXPECTED_GRAPH_TURNS
    assert result.total_model_requests == BASE_REQUESTS + EXPECTED_GRAPH_TURNS
    assert result.route_cost_usd == pytest.approx(EXPECTED_GRAPH_TURNS * MODEL_TURN_COST_USD)
    assert result.total_cost_usd == pytest.approx(
        BASE_COST_USD + EXPECTED_GRAPH_TURNS * MODEL_TURN_COST_USD
    )
    assert result.investigation["enabled"] is True
    assert result.investigation["coverage_cells"] == INITIAL_NODE_COUNT
    assert (context.workspace_dir / "investigation-coverage.json").is_file()
    assert (context.workspace_dir / "investigation-failures.json").is_file()


def test_investigation_engine_can_be_disabled_without_changing_base_limits() -> None:
    config = GraphRouteConfig(investigation_enabled=False)

    assert config.investigation_enabled is False
    assert config.to_json()["investigation_enabled"] is False
    assert config.limits == GraphLimits()


def test_frontier_translation_drops_unverifiable_base_evidence_refs() -> None:
    objective = graph_objective_from_frontier(
        family="sql_injection",
        probe="sqli_differential",
        endpoint="/search",
        inputs=("query",),
        payload_class="specialist:sqli_differential",
        expected_signal="target-observed SQL response differential",
    )

    assert objective.family == "sql_injection"
    assert objective.strategy == "sqli_differential"
    assert objective.evidence_refs == ()
    assert "sqli_differential" in objective.instruction


def test_non_flag_frontier_and_coordinator_use_finding_or_coverage_mission() -> None:
    seed = graph_objective_from_frontier(
        family="sql_injection",
        probe="sqli_differential",
        endpoint="/search",
        inputs=("query",),
        payload_class="specialist:sqli_differential:proof_channel",
        expected_signal="target proof or flag closure",
        flag_objective=False,
    )
    root = coordinator_objective((seed,), flag_objective=False)
    encoded = json.dumps(
        {"seed": seed.to_json(), "root": root.to_json()},
        sort_keys=True,
    ).lower()

    assert seed.strategy.startswith("finding_confirmation:")
    assert root.strategy == "evidence_gated_finding_graph"
    assert "confirmed finding" in root.instruction
    assert "bounded coverage" in root.expected_signal
    assert "submit_proof" not in encoded
    assert "capture_flag" not in encoded
    assert "target proof or flag closure" not in encoded


def context_request_count(route_dir: Path) -> int:
    payload = json.loads((route_dir / "graph-state.json").read_text(encoding="utf-8"))
    return int(payload["model_requests_started"])


def _overwrite_state(path: Path) -> None:
    path.write_text("{}\n", encoding="utf-8")
