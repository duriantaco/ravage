# Route-adapter errors carry field-specific fail-closed context.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.evidence import (
    BlackboardProofGate,
    EvidenceBlackboard,
)
from ravage.agent_core.autonomous_graph.investigation import InvestigationEngine
from ravage.agent_core.autonomous_graph.mission import VULNERABILITY_ASSESSMENT_STRATEGY
from ravage.agent_core.autonomous_graph.model_bridge import graph_role_model_policy_key
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphAgentRole,
    GraphLimits,
    GraphObjective,
    GraphRaceLane,
    GraphState,
)
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
)
from ravage.agent_core.autonomous_graph.runtime_binding import GraphRuntimeResolver
from ravage.agent_core.autonomous_graph.scheduler import ProgressiveGraphScheduler
from ravage.agent_core.autonomous_graph.sessions import GraphSessionStore
from ravage.agent_core.autonomous_graph.worker import (
    GraphComplete,
    GraphExecute,
    GraphProofGate,
    GraphRunner,
    GraphRunResult,
    GraphWorker,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from ravage.agent_core.autonomous_graph.routing import GraphActionGuard
    from ravage.agent_core.autonomous_graph.run_store import RunLease, RunStore

_MANIFEST_VERSION = 1
_SELECTIVE_RACE_LANES = 2


class GraphRouteAdapterError(RuntimeError):
    """Raised before graph work when route identity or state is unsafe."""


def _validate_race_settings(
    *,
    max_race_lanes: int,
    max_race_groups: int,
    max_cost_usd: float | None,
) -> None:
    if max_race_lanes != _SELECTIVE_RACE_LANES:
        raise GraphRouteAdapterError("max_race_lanes must be exactly two")
    if isinstance(max_race_groups, bool) or max_race_groups not in {0, 1}:
        raise GraphRouteAdapterError("max_race_groups must be zero or one")
    if max_race_groups and max_cost_usd is not None:
        raise GraphRouteAdapterError(
            "race groups require trusted per-route cost ceilings when max_cost_usd is finite"
        )


@dataclass(frozen=True)
class GraphRouteConfig:
    """Opt-in graph-route settings kept independent of the frozen base."""

    limits: GraphLimits = field(default_factory=GraphLimits)
    root_lease_limit: int = 2
    child_lease_limit: int = 2
    max_seeded_objectives: int = 4
    max_race_lanes: int = _SELECTIVE_RACE_LANES
    max_race_groups: int = 0
    investigation_enabled: bool = True
    operational_profile: GraphOperationalProfileName = GraphOperationalProfileName.STANDARD

    def __post_init__(self) -> None:
        if not isinstance(self.investigation_enabled, bool):
            raise GraphRouteAdapterError("investigation_enabled must be a boolean")
        if not isinstance(
            self.operational_profile,
            GraphOperationalProfileName,
        ):
            raise GraphRouteAdapterError(
                "operational_profile must be a GraphOperationalProfileName"
            )
        positive = {
            "root_lease_limit": self.root_lease_limit,
            "child_lease_limit": self.child_lease_limit,
            "max_seeded_objectives": self.max_seeded_objectives,
            "max_race_lanes": self.max_race_lanes,
        }
        for name, value in positive.items():
            if value <= 0:
                raise GraphRouteAdapterError(f"{name} must be greater than zero")
        if self.root_lease_limit > self.limits.max_node_lease:
            raise GraphRouteAdapterError("root lease exceeds the graph node lease cap")
        if self.child_lease_limit > self.limits.max_node_lease:
            raise GraphRouteAdapterError("child lease exceeds the graph node lease cap")
        if self.max_seeded_objectives >= self.limits.max_nodes:
            raise GraphRouteAdapterError(
                "seeded objective limit must leave one node for the coordinator"
            )
        _validate_race_settings(
            max_race_lanes=self.max_race_lanes,
            max_race_groups=self.max_race_groups,
            max_cost_usd=self.limits.max_cost_usd,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "limits": self.limits.to_json(),
            "root_lease_limit": self.root_lease_limit,
            "child_lease_limit": self.child_lease_limit,
            "max_seeded_objectives": self.max_seeded_objectives,
            "max_race_lanes": self.max_race_lanes,
            "max_race_groups": self.max_race_groups,
            "investigation_enabled": self.investigation_enabled,
            "operational_profile": self.operational_profile.value,
        }


@dataclass(frozen=True)
class GraphRouteManifest:
    """Durable binding between a graph and its frozen-base provenance."""

    graph_id: str
    target_identity: str
    base_identity: str
    scope_identity: str
    config_identity: str
    root_objective_fingerprint: str
    seeded_objective_fingerprints: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "version": _MANIFEST_VERSION,
            "graph_id": self.graph_id,
            "target_identity": self.target_identity,
            "base_identity": self.base_identity,
            "scope_identity": self.scope_identity,
            "config_identity": self.config_identity,
            "root_objective_fingerprint": self.root_objective_fingerprint,
            "seeded_objective_fingerprints": list(self.seeded_objective_fingerprints),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> GraphRouteManifest:
        version = payload.get("version")
        if isinstance(version, bool) or version != _MANIFEST_VERSION:
            raise GraphRouteAdapterError("unsupported autonomous graph manifest version")
        manifest = cls(
            graph_id=str(payload.get("graph_id") or ""),
            target_identity=str(payload.get("target_identity") or ""),
            base_identity=str(payload.get("base_identity") or ""),
            scope_identity=str(payload.get("scope_identity") or ""),
            config_identity=str(payload.get("config_identity") or ""),
            root_objective_fingerprint=str(payload.get("root_objective_fingerprint") or ""),
            seeded_objective_fingerprints=_string_tuple(
                payload.get("seeded_objective_fingerprints")
            ),
        )
        if not all(
            (
                manifest.graph_id,
                manifest.target_identity,
                manifest.base_identity,
                manifest.scope_identity,
                manifest.config_identity,
                manifest.root_objective_fingerprint,
            )
        ):
            raise GraphRouteAdapterError("autonomous graph manifest is incomplete")
        return manifest

    @classmethod
    def load(cls, path: Path) -> GraphRouteManifest:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GraphRouteAdapterError(f"cannot read autonomous graph manifest: {exc}") from exc
        if not isinstance(payload, dict):
            raise GraphRouteAdapterError("autonomous graph manifest must be an object")
        return cls.from_json(payload)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


@dataclass(frozen=True)
class GraphRouteResult:
    """One bounded graph execution joined to the frozen base accounting."""

    base: BaseRouteOutcome
    graph: GraphState
    run: GraphRunResult
    resumed: bool
    investigation: dict[str, object]

    @property
    def route_model_requests(self) -> int:
        return self.graph.model_requests_started

    @property
    def total_model_requests(self) -> int:
        return self.base.model_requests + self.route_model_requests

    @property
    def route_cost_usd(self) -> float:
        return self.graph.spent_cost_usd

    @property
    def total_cost_usd(self) -> float:
        return self.base.cost_usd + self.route_cost_usd


@dataclass
class GraphRouteContext:
    """Opened route components after all base/resume identity checks pass."""

    base: BaseRouteOutcome
    workspace_dir: Path
    manifest: GraphRouteManifest
    coordinator: GraphCoordinator
    blackboard: EvidenceBlackboard
    sessions: GraphSessionStore
    config: GraphRouteConfig
    resumed: bool

    @classmethod
    async def open(  # noqa: PLR0913 - explicit route identity boundary.
        cls,
        *,
        base: BaseRouteOutcome,
        target_url: str,
        scope: Sequence[object],
        workspace_dir: Path,
        root_objective: GraphObjective,
        seeded_objectives: Sequence[GraphObjective],
        config: GraphRouteConfig | None = None,
        available_model_routes: int = 0,
    ) -> GraphRouteContext:
        route_config = config or GraphRouteConfig()
        _validate_available_model_routes(available_model_routes)
        _validate_base(
            base,
            target_url=target_url,
        )
        seeds = _canonical_seeded_objectives(
            seeded_objectives,
            root_objective=root_objective,
            limit=route_config.max_seeded_objectives,
        )
        expected = _expected_manifest(
            base=base,
            target_url=target_url,
            scope=scope,
            config=route_config,
            root_objective=root_objective,
            seeded_objectives=seeds,
        )
        manifest_path = workspace_dir / "graph-route-manifest.json"
        state_path = workspace_dir / "graph-state.json"
        state_exists = state_path.exists()
        manifest_exists = manifest_path.exists()
        if state_exists and not manifest_exists:
            raise GraphRouteAdapterError(
                "autonomous graph state exists without its identity manifest"
            )

        if state_exists:
            stored = GraphRouteManifest.load(manifest_path)
            _require_matching_manifest(stored, expected)
            persisted = GraphState.load(state_path)
            _require_reconciled_model_billing(persisted)
            coordinator = GraphCoordinator.load(state_path)
            _validate_loaded_graph(
                coordinator.state,
                manifest=stored,
                config=route_config,
            )
            blackboard = EvidenceBlackboard(
                target_url=target_url,
                state_path=workspace_dir / "evidence-blackboard.json",
            )
            sessions = GraphSessionStore.open(workspace_dir / "sessions")
            return cls(
                base=base,
                workspace_dir=workspace_dir,
                manifest=stored,
                coordinator=coordinator,
                blackboard=blackboard,
                sessions=sessions,
                config=route_config,
                resumed=True,
            )

        _prepare_workspace(workspace_dir)
        if manifest_exists:
            stored = GraphRouteManifest.load(manifest_path)
            _require_matching_manifest(stored, expected)
        else:
            expected.save(manifest_path)
        blackboard = EvidenceBlackboard(
            target_url=target_url,
            state_path=workspace_dir / "evidence-blackboard.json",
        )
        sessions = GraphSessionStore.open(workspace_dir / "sessions")
        coordinator = GraphCoordinator.start(
            graph_id=expected.graph_id,
            root_objective=root_objective,
            limits=route_config.limits,
            root_name="route-coordinator",
            root_lease_limit=route_config.root_lease_limit,
        )
        race_lanes = selective_seed_race_lanes(
            objective=seeds[0],
            config=route_config,
            available_model_routes=available_model_routes,
            seeded_objective_count=len(seeds),
            name_prefix="seeded-specialist-01",
        )
        first_ordinary_index = 1
        if race_lanes:
            await coordinator.spawn_race_group(
                parent_id=coordinator.state.root_node_id,
                objective=seeds[0],
                lanes=race_lanes,
            )
            await coordinator.yield_node_turn(coordinator.state.root_node_id)
            first_ordinary_index = 2
        for index, objective in enumerate(
            seeds[first_ordinary_index - 1 :],
            start=first_ordinary_index,
        ):
            await coordinator.spawn_node(
                parent_id=coordinator.state.root_node_id,
                name=f"seeded-specialist-{index:02d}-{_safe_name(objective.family)}",
                objective=objective,
                lease_limit=route_config.child_lease_limit,
            )
        await coordinator.bind_state_path(state_path)
        return cls(
            base=base,
            workspace_dir=workspace_dir,
            manifest=expected,
            coordinator=coordinator,
            blackboard=blackboard,
            sessions=sessions,
            config=route_config,
            resumed=False,
        )

    async def run(  # noqa: PLR0913 - explicit runtime dependency boundary.
        self,
        *,
        complete: GraphComplete,
        execute: GraphExecute,
        proof_gate: GraphProofGate | None = None,
        action_guard: GraphActionGuard | None = None,
        runtime_resolver: GraphRuntimeResolver | None = None,
        run_store: RunStore | None = None,
        run_lease: RunLease | None = None,
        assert_run_owned: Callable[[], None] | None = None,
    ) -> GraphRouteResult:
        investigation = (
            InvestigationEngine.open(
                workspace_dir=self.workspace_dir,
                objectives=tuple(node.objective for node in self.coordinator.state.nodes.values()),
                evidence_validator=self.blackboard,
            )
            if self.config.investigation_enabled
            else None
        )
        worker = GraphWorker(
            coordinator=self.coordinator,
            scheduler=ProgressiveGraphScheduler(self.coordinator),
            sessions=self.sessions,
            complete=complete,
            execute=execute,
            runtime_resolver=(
                runtime_resolver
                or GraphRuntimeResolver(
                    default_complete=complete,
                    default_execute=execute,
                )
            ),
            proof_gate=proof_gate or BlackboardProofGate(self.blackboard),
            evidence_validator=self.blackboard,
            action_guard=action_guard,
            investigation_engine=investigation,
            context_provider=self.blackboard,
            run_store=run_store,
            run_lease=run_lease,
            assert_run_owned=assert_run_owned,
        )
        run = await GraphRunner(worker).run()
        snapshot = await self.coordinator.snapshot()
        return GraphRouteResult(
            base=self.base,
            graph=snapshot,
            run=run,
            resumed=self.resumed,
            investigation=(
                investigation.summary() if investigation is not None else {"enabled": False}
            ),
        )


def _require_reconciled_model_billing(state: GraphState) -> None:
    pending = tuple(
        sorted(
            node.node_id
            for node in state.nodes.values()
            if node.pending_model_request_id is not None
        )
    )
    if pending:
        joined = ", ".join(pending)
        raise GraphRouteAdapterError(
            "cannot resume autonomous graph with pending model billing; "
            f"durable billing reconciliation is required for: {joined}"
        )


def graph_route_run_id(  # noqa: PLR0913 - route identity inputs stay explicit.
    *,
    base: BaseRouteOutcome,
    target_url: str,
    scope: Sequence[object],
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    seeded_objectives: Sequence[GraphObjective],
) -> str:
    """Return the exact graph identity used for fenced production ownership."""
    _validate_base(base, target_url=target_url)
    seeds = _canonical_seeded_objectives(
        seeded_objectives,
        root_objective=root_objective,
        limit=config.max_seeded_objectives,
    )
    return _expected_manifest(
        base=base,
        target_url=target_url,
        scope=scope,
        config=config,
        root_objective=root_objective,
        seeded_objectives=seeds,
    ).graph_id


def selective_seed_race_lanes(
    *,
    objective: GraphObjective,
    config: GraphRouteConfig,
    available_model_routes: int,
    seeded_objective_count: int,
    name_prefix: str,
) -> tuple[GraphRaceLane, ...]:
    """Return two trusted heterogeneous lanes only when every bound can fund them."""
    _validate_available_model_routes(available_model_routes)
    if (
        config.max_race_groups == 0
        or available_model_routes < config.max_race_lanes
        or config.limits.max_concurrent_nodes < config.max_race_lanes
    ):
        return ()
    total_nodes = 1 + seeded_objective_count + (config.max_race_lanes - 1)
    exploration_capacity = (
        config.limits.max_model_requests - config.limits.proof_reserve_model_requests
    )
    if total_nodes > config.limits.max_nodes or exploration_capacity < config.max_race_lanes:
        return ()
    safe_prefix = _safe_name(name_prefix) or "seeded-race"
    skills = (objective.family, objective.strategy)
    return (
        GraphRaceLane(
            lane_id="01-discovery",
            name=f"{safe_prefix}-discovery",
            agent_spec=AgentSpec.create(
                role=GraphAgentRole.DISCOVERY,
                model_policy_key=graph_role_model_policy_key(GraphAgentRole.DISCOVERY),
                session_policy_key="node_isolated",
                skill_ids=skills,
            ),
        ),
        GraphRaceLane(
            lane_id="02-critic",
            name=f"{safe_prefix}-critic",
            agent_spec=AgentSpec.create(
                role=GraphAgentRole.CRITIC,
                model_policy_key=graph_role_model_policy_key(GraphAgentRole.CRITIC),
                session_policy_key="fresh_typed",
                skill_ids=skills,
            ),
        ),
    )


def _validate_available_model_routes(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GraphRouteAdapterError("available_model_routes must be a non-negative integer")


def graph_objective_from_frontier(  # noqa: PLR0913 - source fields stay explicit.
    *,
    family: str,
    probe: str,
    endpoint: str,
    inputs: Sequence[str],
    payload_class: str,
    expected_signal: str,
    flag_objective: bool = True,
) -> GraphObjective:
    """Translate a base-derived frontier without carrying fake evidence IDs."""
    route = probe.strip() or endpoint.strip() or "evidence-led exploration"
    payload = payload_class.strip() or "unspecified"
    if flag_objective:
        instruction = (
            f"Investigate {route} depth-first using the {payload} route. "
            "Prefer a replayable request contract and hand off any independently "
            "validated closure evidence by its blackboard reference."
        )
        signal = expected_signal
        strategy = route
    else:
        instruction = (
            f"Assess {route} depth-first using the {payload} route. "
            "Use class-aware controls and executor-owned observations. Finish this "
            "route when a confirmed vulnerability finding is persisted, or when its "
            "finite materially distinct checks produce a bounded negative result."
        )
        signal = (
            "executor-persisted, evidence-backed vulnerability confirmation for "
            f"{family.strip() or 'the assigned class'}, or bounded coverage completion "
            "with no confirmed finding"
        )
        strategy = f"finding_confirmation:{route}"
    return GraphObjective.create(
        family=family,
        instruction=instruction,
        endpoint=endpoint,
        inputs=tuple(inputs),
        strategy=strategy,
        expected_signal=signal,
    )


def coordinator_objective(
    seeded_objectives: Sequence[GraphObjective],
    *,
    flag_objective: bool = True,
) -> GraphObjective:
    """Build a bounded root task that coordinates, rather than duplicates, seeds."""
    catalog = [
        {
            "family": objective.family,
            "endpoint": objective.endpoint,
            "inputs": list(objective.inputs),
            "strategy": objective.strategy,
            "expected_signal": objective.expected_signal,
        }
        for objective in seeded_objectives
    ]
    if flag_objective:
        instruction = (
            "Coordinate the seeded specialists, route typed evidence between them, "
            "prioritize proof closure over fresh reconnaissance, and submit only "
            "blackboard-confirmed target proof. Seed catalog: "
            + json.dumps(catalog, ensure_ascii=False, sort_keys=True)
        )
        expected_signal = (
            "replayable target-observed proof, or bounded exhaustion after each "
            "materially distinct seeded route is closed"
        )
        strategy = "evidence_gated_specialist_graph"
    else:
        instruction = (
            "Coordinate the seeded vulnerability-assessment specialists and route "
            "typed evidence between them. Prioritize executor-persisted confirmed "
            "findings over fresh reconnaissance. A seeded route is complete when it "
            "persists a confirmed finding or finishes its finite materially distinct "
            "checks with a bounded negative result. Finish after every seeded route "
            "has reached one of those outcomes and no descendant remains active. "
            "Seed catalog: "
            + json.dumps(catalog, ensure_ascii=False, sort_keys=True)
        )
        expected_signal = (
            "one or more executor-persisted confirmed findings, or complete bounded "
            "coverage of every materially distinct seeded route"
        )
        strategy = VULNERABILITY_ASSESSMENT_STRATEGY
    return GraphObjective.create(
        family="graph_coordination",
        instruction=instruction,
        strategy=strategy,
        expected_signal=expected_signal,
    )


def _validate_base(
    base: BaseRouteOutcome,
    *,
    target_url: str,
) -> None:
    if target_url != base.target_url:
        raise GraphRouteAdapterError(
            "autonomous graph target does not match the frozen base target"
        )
    if base.proof_confirmed or base.termination is BaseRouteTermination.SOLVED:
        raise GraphRouteAdapterError("solved frozen base cannot enter the graph route")
    if base.termination not in {
        BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        BaseRouteTermination.EXPLORATION_EXHAUSTED,
    }:
        raise GraphRouteAdapterError(f"frozen base is not graph-eligible: {base.termination.value}")
    if not base.state_digest.strip() or not base.state_ref.strip():
        raise GraphRouteAdapterError("frozen base requires a durable state reference")
    state_path = _path(base.state_ref)
    if not state_path.is_file():
        raise GraphRouteAdapterError("frozen base state reference does not exist")
    actual = hashlib.sha256(state_path.read_bytes()).hexdigest()
    if actual != base.state_digest:
        raise GraphRouteAdapterError("frozen base state digest no longer matches its artifact")


def _expected_manifest(  # noqa: PLR0913 - identity fields stay explicit.
    *,
    base: BaseRouteOutcome,
    target_url: str,
    scope: Sequence[object],
    config: GraphRouteConfig,
    root_objective: GraphObjective,
    seeded_objectives: Sequence[GraphObjective],
) -> GraphRouteManifest:
    target_identity = _digest(target_url.strip())
    base_identity = _digest_json(
        {
            "target_identity": target_identity,
            "termination": base.termination.value,
            "state_digest": base.state_digest,
            "model_requests": base.model_requests,
            "cost_usd": base.cost_usd,
            "proof_confirmed": base.proof_confirmed,
        }
    )
    scope_identity = _digest_json(
        sorted({str(item).strip() for item in scope if str(item).strip()})
    )
    config_identity = _digest_json(config.to_json())
    seed_fingerprints = tuple(sorted(objective.fingerprint for objective in seeded_objectives))
    route_identity = {
        "version": _MANIFEST_VERSION,
        "target_identity": target_identity,
        "base_identity": base_identity,
        "scope_identity": scope_identity,
        "config_identity": config_identity,
        "root_objective_fingerprint": root_objective.fingerprint,
        "seeded_objective_fingerprints": list(seed_fingerprints),
    }
    return GraphRouteManifest(
        graph_id=f"graph-{_digest_json(route_identity)[:24]}",
        target_identity=target_identity,
        base_identity=base_identity,
        scope_identity=scope_identity,
        config_identity=config_identity,
        root_objective_fingerprint=root_objective.fingerprint,
        seeded_objective_fingerprints=seed_fingerprints,
    )


def _require_matching_manifest(
    stored: GraphRouteManifest,
    expected: GraphRouteManifest,
) -> None:
    fields = (
        "target_identity",
        "base_identity",
        "scope_identity",
        "config_identity",
        "root_objective_fingerprint",
        "seeded_objective_fingerprints",
        "graph_id",
    )
    for field_name in fields:
        if getattr(stored, field_name) != getattr(expected, field_name):
            raise GraphRouteAdapterError(f"autonomous graph resume {field_name} mismatch")


def _validate_loaded_graph(
    state: GraphState,
    *,
    manifest: GraphRouteManifest,
    config: GraphRouteConfig,
) -> None:
    if state.graph_id != manifest.graph_id:
        raise GraphRouteAdapterError("graph state does not match its route manifest")
    if state.limits != config.limits:
        raise GraphRouteAdapterError("graph state limits do not match route configuration")
    root = state.nodes[state.root_node_id]
    if root.objective.fingerprint != manifest.root_objective_fingerprint:
        raise GraphRouteAdapterError("graph root objective does not match route manifest")
    direct_children = {
        node.objective.fingerprint
        for node in state.nodes.values()
        if node.parent_id == state.root_node_id
    }
    if not set(manifest.seeded_objective_fingerprints).issubset(direct_children):
        raise GraphRouteAdapterError("graph seeded objectives do not match route manifest")


def _canonical_seeded_objectives(
    objectives: Sequence[GraphObjective],
    *,
    root_objective: GraphObjective,
    limit: int,
) -> tuple[GraphObjective, ...]:
    by_fingerprint: dict[str, GraphObjective] = {}
    for objective in objectives:
        if objective.fingerprint == root_objective.fingerprint:
            raise GraphRouteAdapterError("root objective cannot also be a seeded objective")
        by_fingerprint.setdefault(objective.fingerprint, objective)
    seeds = tuple(by_fingerprint[key] for key in sorted(by_fingerprint))
    if not seeds:
        raise GraphRouteAdapterError("graph route requires at least one seeded objective")
    if len(seeds) > limit:
        raise GraphRouteAdapterError("seeded objectives exceed the configured route limit")
    return seeds


def _path(value: str) -> Path:
    from pathlib import Path  # noqa: PLC0415

    return Path(value)


def _prepare_workspace(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _safe_name(value: str) -> str:
    safe = "".join(
        character if character.isalnum() or character in {"-", "_"} else "-"
        for character in value.strip().lower()
    )
    return safe or "unknown"


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        sorted({str(item).strip() for item in value if isinstance(item, str) and item.strip()})
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "GraphRouteAdapterError",
    "GraphRouteConfig",
    "GraphRouteContext",
    "GraphRouteManifest",
    "GraphRouteResult",
    "coordinator_objective",
    "graph_objective_from_frontier",
    "graph_route_run_id",
    "selective_seed_race_lanes",
]
