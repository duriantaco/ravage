from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
    DuplicateFrontierObjectiveError,
    FrontierObjective,
    FrontierObjectiveBasis,
    FrontierObservation,
    FrontierRoute,
    FrontierRouteConfig,
    FrontierRouteStatus,
    FrontierWorkerRole,
    InvalidFrontierRouteStateError,
    OutOfScopeFrontierObjectiveError,
    frontier_config_for_budget,
    route_eligibility,
)

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
BASE_REQUESTS = 40
ROUTE_REQUESTS = 24
SMALL_ROUTE_REQUESTS = 3
SECOND_WORKER_COUNT = 2
FIFTH_WORKER_COUNT = 5
LIVE_WORKER_LIMIT = 8
REQUESTS_BEFORE_PROOF_CHANNEL = 4
WATCHDOG_REQUESTS = 2


def _base(
    termination: BaseRouteTermination = BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
    *,
    proof_confirmed: bool = False,
) -> BaseRouteOutcome:
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=termination,
        model_requests=BASE_REQUESTS,
        state_digest="base-state-sha256",
        state_ref="workspace/working_state.json",
        proof_confirmed=proof_confirmed,
        cost_usd=0.75,
    )


def _objective(
    family: str = "path_traversal",
    *,
    endpoint: str = "/download",
    payload_class: str = "encoded_traversal",
    basis: FrontierObjectiveBasis = FrontierObjectiveBasis.BASE_FRONTIER,
    evidence_refs: tuple[str, ...] = ("base-observation-1",),
) -> FrontierObjective:
    return FrontierObjective.create(
        family=family,
        probe="file_read_extract",
        endpoint=endpoint,
        inputs=("file",),
        payload_class=payload_class,
        expected_signal="target returns file content or a stable path differential",
        evidence_refs=evidence_refs,
        basis=basis,
    )


def _route(
    *,
    config: FrontierRouteConfig | None = None,
) -> FrontierRoute:
    return FrontierRoute.start(
        base=_base(),
        initial_objective=_objective(),
        scope=(TARGET_URL,),
        config=config or FrontierRouteConfig(),
    )


def _observation(  # noqa: PLR0913 - compact route-observation fixture.
    suffix: str,
    *,
    source_kind: str = "tool_run_probe",
    material_progress: tuple[str, ...] = (),
    proofs: tuple[str, ...] = (),
    next_objective: FrontierObjective | None = None,
    route_fingerprint: str = "route-a",
    cost_usd: float = 0.01,
) -> FrontierObservation:
    return FrontierObservation(
        source_kind=source_kind,
        observation_digest=f"observation-{suffix}",
        route_fingerprint=route_fingerprint,
        material_progress=material_progress,
        proofs=proofs,
        next_objective=next_objective,
        cost_usd=cost_usd,
    )


@pytest.mark.parametrize(
    "termination",
    [
        BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        BaseRouteTermination.EXPLORATION_EXHAUSTED,
    ],
)
def test_route_only_enters_after_a_terminal_unsolved_base(
    termination: BaseRouteTermination,
) -> None:
    eligibility = route_eligibility(_base(termination))

    assert eligibility.enter is True
    assert eligibility.resume is False
    assert eligibility.reason == "terminal_base_unsolved"


@pytest.mark.parametrize(
    "termination",
    [
        BaseRouteTermination.SOLVED,
        BaseRouteTermination.COST_BUDGET_EXHAUSTED,
        BaseRouteTermination.INTERRUPTED,
        BaseRouteTermination.ERROR,
    ],
)
def test_route_does_not_enter_for_solved_or_non_strategic_base_stops(
    termination: BaseRouteTermination,
) -> None:
    outcome = _base(
        termination,
        proof_confirmed=termination is BaseRouteTermination.SOLVED,
    )

    assert route_eligibility(outcome).enter is False


def test_confirmed_base_proof_blocks_the_route_even_with_an_exhausted_label() -> None:
    eligibility = route_eligibility(_base(proof_confirmed=True))

    assert eligibility.enter is False
    assert eligibility.reason == "base_proof_confirmed"


def test_route_starts_with_a_small_lease_and_separate_accounting() -> None:
    route = _route()

    assert route.status is FrontierRouteStatus.RUNNING
    assert route.base.model_requests == BASE_REQUESTS
    assert route.model_requests_started == 0
    assert route.config.max_model_requests == ROUTE_REQUESTS
    assert route.active_worker is not None
    assert route.active_worker.role is FrontierWorkerRole.SCOUT
    assert route.active_worker.lease_limit == route.config.scout_lease
    assert route.total_model_requests_including_base == BASE_REQUESTS


def test_small_operator_budget_scales_every_lease_without_breaking_the_cap() -> None:
    config = frontier_config_for_budget(SMALL_ROUTE_REQUESTS)

    assert config.max_model_requests == SMALL_ROUTE_REQUESTS
    assert config.scout_lease == SMALL_ROUTE_REQUESTS
    assert config.counterfactual_lease == SMALL_ROUTE_REQUESTS
    assert config.proof_lease == SMALL_ROUTE_REQUESTS
    assert config.max_workers == SMALL_ROUTE_REQUESTS


def test_live_budget_can_cover_seeded_objectives_and_proof_transitions() -> None:
    route = _route(config=frontier_config_for_budget(ROUTE_REQUESTS))
    payload_semantics = _objective(
        "sql_injection",
        endpoint="/index.php",
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
    )
    proof_channel = _objective(
        "sql_injection",
        endpoint="/index.php",
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
    )

    route.begin_model_request()
    route.record_observation(_observation("request-contract", material_progress=("ajax_contract",)))
    route.begin_model_request()
    route.record_handoff(
        summary="request-contract proof route exhausted",
        next_objective=payload_semantics,
    )
    route.begin_model_request()
    route.record_observation(
        _observation("payload-semantics", material_progress=("boolean_oracle",))
    )
    route.begin_model_request()

    decision = route.record_handoff(
        summary="known extraction exhausted; pivot to proof channel",
        next_objective=proof_channel,
    )

    assert route.config.max_workers == LIVE_WORKER_LIMIT
    assert route.status is FrontierRouteStatus.RUNNING
    assert decision.reason == "explicit_handoff_counterfactual_lease_granted"
    assert decision.remaining_model_requests == ROUTE_REQUESTS - REQUESTS_BEFORE_PROOF_CHANNEL
    assert len(route.workers) == FIFTH_WORKER_COUNT
    assert route.active_worker is not None
    assert route.active_worker.objective is proof_channel


def test_started_request_is_charged_and_not_replayed_after_resume(tmp_path: Path) -> None:
    state_path = tmp_path / "frontier-route.json"
    route = _route()
    route.begin_model_request()
    route.save(state_path)

    restored = FrontierRoute.load(state_path)
    decision = restored.account_interrupted_request()

    assert restored.model_requests_started == 1
    assert restored.model_requests_completed == 1
    assert restored.interrupted_model_requests == 1
    assert restored.pending_worker_id is None
    assert decision.reason == "interrupted_request_charged"
    assert restored.active_worker is not None
    assert restored.active_worker.requests_started == 1


def test_failure_alone_does_not_buy_a_larger_lease() -> None:
    route = _route()

    for turn in range(route.config.scout_lease):
        route.begin_model_request()
        decision = route.record_observation(_observation(str(turn)))

    assert route.model_requests_started == route.config.scout_lease
    assert route.status is FrontierRouteStatus.FRONTIER_EXHAUSTED
    assert decision.reason == "lease_exhausted_without_novel_objective"
    assert len(route.workers) == 1


def test_novel_counterfactual_unlocks_one_larger_bounded_lease() -> None:
    route = _route()
    alternative = _objective(
        "server_side_request_forgery",
        endpoint="/fetch",
        payload_class="loopback_url",
    )

    for turn in range(route.config.scout_lease):
        route.begin_model_request()
        decision = route.record_observation(
            _observation(
                str(turn),
                next_objective=(alternative if turn == route.config.scout_lease - 1 else None),
            )
        )

    assert decision.reason == "novel_counterfactual_lease_granted"
    assert route.status is FrontierRouteStatus.RUNNING
    assert route.active_worker is not None
    assert route.active_worker.role is FrontierWorkerRole.COUNTERFACTUAL
    assert route.active_worker.lease_limit == route.config.counterfactual_lease
    assert len(route.workers) == SECOND_WORKER_COUNT


def test_duplicate_objective_cannot_respawn_a_worker() -> None:
    route = _route()

    for turn in range(route.config.scout_lease):
        route.begin_model_request()
        decision = route.record_observation(
            _observation(
                str(turn),
                next_objective=(_objective() if turn == route.config.scout_lease - 1 else None),
            )
        )

    assert route.status is FrontierRouteStatus.FRONTIER_EXHAUSTED
    assert decision.reason == "duplicate_objective_rejected"
    assert len(route.workers) == 1


def test_duplicate_objective_is_rejected_when_directly_spawned() -> None:
    route = _route()

    with pytest.raises(DuplicateFrontierObjectiveError):
        route.spawn_counterfactual(_objective())


def test_only_trusted_material_progress_unlocks_a_proof_closure_lease() -> None:
    route = _route()
    route.begin_model_request()
    decision = route.record_observation(
        _observation(
            "primitive",
            material_progress=("file_read_primitive",),
        )
    )

    assert decision.reason == "trusted_progress_proof_lease_granted"
    assert route.active_worker is not None
    assert route.active_worker.role is FrontierWorkerRole.PROOF_CLOSURE
    assert route.active_worker.lease_limit == route.config.proof_lease
    assert len(route.workers) == SECOND_WORKER_COUNT


def test_model_authored_progress_cannot_unlock_more_budget() -> None:
    route = _route()
    route.begin_model_request()
    decision = route.record_observation(
        _observation(
            "claim",
            source_kind="model_handoff",
            material_progress=("claimed_rce",),
        )
    )

    assert decision.reason == "worker_continues"
    assert route.active_worker is not None
    assert route.active_worker.role is FrontierWorkerRole.SCOUT
    assert len(route.workers) == 1


def test_repeated_observation_pivots_early_only_to_a_novel_objective() -> None:
    route = _route()
    alternative = _objective(
        "sql_injection",
        endpoint="/search",
        payload_class="boolean_differential",
    )

    route.begin_model_request()
    route.record_observation(_observation("same"))
    route.begin_model_request()
    decision = route.record_observation(
        FrontierObservation(
            source_kind="tool_run_probe",
            observation_digest="observation-same",
            route_fingerprint="route-a",
            next_objective=alternative,
        )
    )

    assert route.model_requests_started == WATCHDOG_REQUESTS
    assert decision.reason == "observation_watchdog_counterfactual_lease_granted"
    assert route.active_worker is not None
    assert route.active_worker.role is FrontierWorkerRole.COUNTERFACTUAL


def test_untrusted_proof_cannot_solve_but_trusted_tool_proof_can() -> None:
    route = _route()
    proof = "flag{target-observed-proof}"
    route.begin_model_request()
    first = route.record_observation(
        _observation("claim", source_kind="model_handoff", proofs=(proof,))
    )

    assert first.reason == "worker_continues"
    assert route.status is FrontierRouteStatus.RUNNING

    route.begin_model_request()
    second = route.record_observation(_observation("proof", proofs=(proof,)))

    assert second.reason == "trusted_proof_confirmed"
    assert route.status is FrontierRouteStatus.SOLVED
    assert route.proof_digests
    assert proof not in json.dumps(route.to_json())


def test_explicit_worker_handoff_returns_control_instead_of_ending_the_route() -> None:
    route = _route()
    alternative = _objective(
        "object_authorization",
        endpoint="/orders/2",
        payload_class="cross_identity",
    )
    route.begin_model_request()
    decision = route.record_handoff(
        summary="route exhausted; test the observed object boundary",
        next_objective=alternative,
        cost_usd=0.02,
    )

    assert decision.reason == "explicit_handoff_counterfactual_lease_granted"
    assert route.status is FrontierRouteStatus.RUNNING
    assert route.active_worker is not None
    assert route.active_worker.role is FrontierWorkerRole.COUNTERFACTUAL
    assert route.handoffs[0].summary_digest
    assert "route exhausted" not in json.dumps(route.to_json())


def test_worker_cap_stops_cleanly_instead_of_raising_on_handoff() -> None:
    route = _route(
        config=FrontierRouteConfig(
            max_model_requests=8,
            scout_lease=2,
            counterfactual_lease=4,
            proof_lease=4,
            max_workers=2,
        )
    )
    second = _objective(
        "sql_injection",
        endpoint="/search",
        payload_class="boolean_differential",
    )
    third = _objective(
        "server_side_request_forgery",
        endpoint="/fetch",
        payload_class="loopback_url",
    )
    route.begin_model_request()
    route.record_handoff(summary="first handoff", next_objective=second)
    route.begin_model_request()

    decision = route.record_handoff(summary="second handoff", next_objective=third)

    assert route.status is FrontierRouteStatus.FRONTIER_EXHAUSTED
    assert decision.reason == "worker_limit_reached"
    assert len(route.workers) == SECOND_WORKER_COUNT


def test_trusted_progress_at_worker_cap_renews_current_proof_lease(
    tmp_path: Path,
) -> None:
    config = FrontierRouteConfig(
        max_model_requests=8,
        scout_lease=2,
        counterfactual_lease=4,
        proof_lease=4,
        max_workers=2,
    )
    route = _route(config=config)
    second = _objective(
        "sql_injection",
        endpoint="/search",
        payload_class="boolean_differential",
    )
    route.begin_model_request()
    route.record_handoff(summary="first handoff", next_objective=second)
    worker = route.active_worker
    assert worker is not None
    worker_id = worker.worker_id
    route.begin_model_request()
    started_before_progress = worker.requests_started

    decision = route.record_observation(
        _observation(
            "partial-secret-prefix",
            material_progress=("credential_prefix_7d3",),
        )
    )

    assert route.status is FrontierRouteStatus.RUNNING
    assert decision.reason == "trusted_progress_proof_lease_renewed_at_worker_cap"
    assert len(route.workers) == SECOND_WORKER_COUNT
    assert route.active_worker is worker
    assert worker.worker_id == worker_id
    assert worker.role is FrontierWorkerRole.PROOF_CLOSURE
    assert worker.objective.basis is FrontierObjectiveBasis.MATERIAL_PROGRESS
    assert worker.lease_limit == started_before_progress + config.proof_lease
    assert route.attempted_objective_fingerprints == {
        item.objective.fingerprint for item in route.workers
    }

    state_path = tmp_path / "renewed-frontier-route.json"
    route.save(state_path)
    restored = FrontierRoute.load(state_path)

    assert restored.status is FrontierRouteStatus.RUNNING
    assert restored.active_worker is not None
    assert restored.active_worker.worker_id == worker_id
    assert restored.active_worker.role is FrontierWorkerRole.PROOF_CLOSURE


def test_proof_lease_renewal_at_worker_cap_is_single_and_globally_bounded() -> None:
    config = FrontierRouteConfig(
        max_model_requests=6,
        scout_lease=2,
        counterfactual_lease=3,
        proof_lease=3,
        max_workers=2,
    )
    route = _route(config=config)
    second = _objective(
        "sql_injection",
        endpoint="/search",
        payload_class="boolean_differential",
    )
    route.begin_model_request()
    route.record_handoff(summary="first handoff", next_objective=second)
    route.begin_model_request()
    route.record_observation(_observation("prefix-one", material_progress=("prefix_one",)))
    worker = route.active_worker
    assert worker is not None
    renewed_lease = worker.lease_limit

    route.begin_model_request()
    decision = route.record_observation(
        _observation("prefix-two", material_progress=("prefix_two",))
    )

    assert decision.reason == "worker_continues"
    assert worker.lease_limit == renewed_lease
    while route.status is FrontierRouteStatus.RUNNING:
        route.begin_model_request()
        decision = route.record_observation(_observation(str(route.model_requests_started)))

    assert route.model_requests_started <= config.max_model_requests
    assert decision.reason in {
        "global_request_budget_exhausted",
        "lease_exhausted_without_novel_objective",
    }


def test_global_request_cap_applies_across_all_workers() -> None:
    config = FrontierRouteConfig(
        max_model_requests=5,
        scout_lease=2,
        counterfactual_lease=3,
        proof_lease=3,
    )
    route = _route(config=config)
    alternative = _objective(
        "sql_injection",
        endpoint="/search",
        payload_class="boolean_differential",
    )

    for turn in range(config.scout_lease):
        route.begin_model_request()
        route.record_observation(
            _observation(
                f"scout-{turn}",
                next_objective=(alternative if turn == config.scout_lease - 1 else None),
            )
        )
    for turn in range(config.counterfactual_lease):
        route.begin_model_request()
        decision = route.record_observation(_observation(f"counter-{turn}"))

    assert route.model_requests_started == config.max_model_requests
    assert route.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert decision.reason == "global_request_budget_exhausted"
    with pytest.raises(RuntimeError, match="request budget"):
        route.begin_model_request()


def test_optional_cost_cap_stops_the_entire_route() -> None:
    route = _route(config=FrontierRouteConfig(max_cost_usd=0.05))
    route.begin_model_request()
    decision = route.record_observation(_observation("costly", cost_usd=0.05))

    assert decision.reason == "route_cost_budget_exhausted"
    assert route.status is FrontierRouteStatus.COST_BUDGET_EXHAUSTED


def test_out_of_scope_objective_is_rejected_before_worker_creation() -> None:
    route = _route()
    objective = _objective(endpoint="http://example.com/admin")

    with pytest.raises(OutOfScopeFrontierObjectiveError):
        route.spawn_counterfactual(objective)


def test_existing_route_state_is_resumed_instead_of_started_twice(tmp_path: Path) -> None:
    state_path = tmp_path / "frontier-route.json"
    route = FrontierRoute.load_or_start(
        state_path,
        base=_base(),
        initial_objective=_objective(),
        scope=(TARGET_URL,),
        config=FrontierRouteConfig(),
    )
    route.begin_model_request()
    route.record_observation(_observation("first"))
    route.save(state_path)

    restored = FrontierRoute.load_or_start(
        state_path,
        base=_base(),
        initial_objective=_objective(),
        scope=(TARGET_URL,),
        config=FrontierRouteConfig(),
    )

    assert len(restored.workers) == 1
    assert restored.model_requests_started == 1
    assert route_eligibility(_base(), route_state_exists=True).resume is True


def test_loaded_route_rejects_request_accounting_that_does_not_match_workers() -> None:
    route = _route()
    route.begin_model_request()
    route.record_observation(_observation("first"))
    payload = route.to_json()
    payload["model_requests_started"] = 0
    payload["model_requests_completed"] = 0

    with pytest.raises(InvalidFrontierRouteStateError, match="worker accounting"):
        FrontierRoute.from_json(payload)


def test_loaded_route_rejects_requests_above_the_global_cap() -> None:
    route = _route()
    payload = route.to_json()
    payload["model_requests_started"] = ROUTE_REQUESTS + 1
    payload["model_requests_completed"] = ROUTE_REQUESTS + 1

    with pytest.raises(InvalidFrontierRouteStateError, match="global limit"):
        FrontierRoute.from_json(payload)


def test_objective_schema_has_no_benchmark_or_ground_truth_channel() -> None:
    payload = _objective().to_json()

    assert set(payload) == {
        "basis",
        "endpoint",
        "evidence_refs",
        "expected_signal",
        "family",
        "fingerprint",
        "inputs",
        "payload_class",
        "probe",
    }
    assert "benchmark" not in json.dumps(payload).lower()
    assert "ground_truth" not in json.dumps(payload).lower()
