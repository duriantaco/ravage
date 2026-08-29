from __future__ import annotations

import json

import pytest
from ravage.agent_core.recovery_policy import (
    MaterialProgressKind,
    ProgressSnapshot,
    RecoveryConfig,
    RecoveryDecision,
    RecoveryRole,
    RecoveryScheduler,
    RecoveryStatus,
)

EMPTY = ProgressSnapshot()


def _record_empty_turns(scheduler: RecoveryScheduler, count: int) -> None:
    for _ in range(count):
        scheduler.record_model_turn(EMPTY)


def _finish_current_lease(
    scheduler: RecoveryScheduler,
    snapshot: ProgressSnapshot = EMPTY,
    *,
    next_objective_fingerprint: str = "",
) -> RecoveryDecision:
    remaining = scheduler.lease_limit - scheduler.lease_used
    decision: RecoveryDecision | None = None
    for turn in range(remaining):
        decision = scheduler.record_model_turn(
            snapshot,
            next_objective_fingerprint=(
                next_objective_fingerprint if turn == remaining - 1 else ""
            ),
        )
    assert decision is not None
    return decision


def test_default_budgets_start_small_and_escalate_progressively() -> None:
    expected_initial_lease = 4
    config = RecoveryConfig()

    assert config.initial_core_lease == expected_initial_lease
    assert config.initial_core_lease < config.closure_lease
    assert config.closure_lease < config.counterfactual_lease
    assert config.progress_lease == config.counterfactual_lease
    assert config.proof_reserve < config.max_model_requests


def test_initial_core_receives_only_its_small_lease() -> None:
    scheduler = RecoveryScheduler()

    _record_empty_turns(scheduler, scheduler.config.initial_core_lease - 1)
    assert scheduler.role is RecoveryRole.CORE
    decision = scheduler.record_model_turn(EMPTY)

    assert decision.executed_role is RecoveryRole.CORE
    assert decision.executed_lease_budget == scheduler.config.initial_core_lease
    assert decision.executed_lease_used == scheduler.config.initial_core_lease
    assert decision.reason == "initial_core_lease_exhausted"
    assert decision.next_role is RecoveryRole.CLOSURE
    assert decision.next_lease_budget == scheduler.config.closure_lease
    assert decision.next_lease_used == 0


def test_weak_surface_growth_does_not_buy_a_larger_lease() -> None:
    scheduler = RecoveryScheduler()

    for turn in range(1, scheduler.config.initial_core_lease + 1):
        decision = scheduler.record_model_turn(
            ProgressSnapshot(weak_signals=frozenset({f"surface-{turn}"})),
            observation_digest=f"weak-{turn}",
        )

    assert decision.material_progress == ()
    assert decision.reason == "initial_core_lease_exhausted"
    assert decision.next_lease_budget == scheduler.config.closure_lease
    assert decision.next_lease_budget != scheduler.config.progress_lease


def test_failed_leases_pivot_to_a_different_role_with_a_larger_budget() -> None:
    scheduler = RecoveryScheduler()
    _finish_current_lease(scheduler)
    assert scheduler.role is RecoveryRole.CLOSURE

    _finish_current_lease(scheduler)

    assert scheduler.role is RecoveryRole.COUNTERFACTUAL
    assert scheduler.lease_limit == scheduler.config.counterfactual_lease
    assert scheduler.branches_started_in_epoch == [
        RecoveryRole.CLOSURE,
        RecoveryRole.COUNTERFACTUAL,
    ]


def test_specialist_handoff_returns_control_without_spending_the_remaining_lease() -> None:
    scheduler = RecoveryScheduler()
    _finish_current_lease(scheduler)
    assert scheduler.role is RecoveryRole.CLOSURE

    decision = scheduler.record_model_turn(
        EMPTY,
        next_objective_fingerprint="sql|different-technique",
        branch_handoff=True,
    )

    assert decision.branch_handoff_triggered is True
    assert decision.executed_role is RecoveryRole.CLOSURE
    assert decision.executed_lease_used == 1
    assert decision.next_role is RecoveryRole.COUNTERFACTUAL
    assert decision.next_lease_used == 0
    assert decision.next_objective_fingerprint == "sql|different-technique"


@pytest.mark.parametrize(
    ("field_name", "expected_kind"),
    [
        ("confirmed_primitives", MaterialProgressKind.PRIMITIVE_CONFIRMED),
        ("authenticated_states", MaterialProgressKind.AUTH_STATE_CHANGED),
        (
            "validated_request_templates",
            MaterialProgressKind.REQUEST_TEMPLATE_VALIDATED,
        ),
        (
            "validated_response_differentials",
            MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
        ),
        ("confirmed_hypotheses", MaterialProgressKind.HYPOTHESIS_CONFIRMED),
    ],
)
def test_only_material_progress_unlocks_a_focused_progress_lease(
    field_name: str,
    expected_kind: MaterialProgressKind,
) -> None:
    scheduler = RecoveryScheduler()
    snapshot = ProgressSnapshot(**{field_name: frozenset({"target-evidence"})})

    decision = scheduler.record_model_turn(snapshot)

    assert decision.executed_role is RecoveryRole.CORE
    assert decision.next_role is RecoveryRole.CLOSURE
    assert decision.reason == "material_progress_lease_granted"
    assert decision.material_progress == (expected_kind,)
    assert decision.next_lease_budget == scheduler.config.progress_lease
    assert decision.next_lease_used == 0
    assert scheduler.branch_uses_proof_reserve is True
    assert scheduler.evidence_epoch == 1


def test_weak_specialist_activity_cannot_renew_a_progress_lease() -> None:
    scheduler = RecoveryScheduler()
    primitive = ProgressSnapshot(confirmed_primitives=frozenset({"confirmed-file-read"}))
    scheduler.record_model_turn(primitive)
    first_progress_branch = scheduler.active_branch_id

    for turn in range(scheduler.config.progress_lease):
        decision = scheduler.record_model_turn(
            ProgressSnapshot(
                confirmed_primitives=primitive.confirmed_primitives,
                weak_signals=frozenset({f"marker-{turn}"}),
            ),
            observation_digest=f"progress-weak-{turn}",
        )

    assert decision.material_progress == ()
    assert decision.reason == "closure_lease_exhausted"
    assert decision.next_role is RecoveryRole.COUNTERFACTUAL
    assert scheduler.active_branch_id != first_progress_branch
    assert scheduler.branch_uses_proof_reserve is False


def test_disproved_hypothesis_pivots_without_unlocking_the_proof_reserve() -> None:
    scheduler = RecoveryScheduler()

    decision = scheduler.record_model_turn(
        ProgressSnapshot(disproved_hypotheses=frozenset({"login-is-not-sqli"}))
    )

    assert decision.material_progress == (MaterialProgressKind.HYPOTHESIS_DISPROVED,)
    assert decision.reason == "disproved_hypothesis_counterfactual_lease_granted"
    assert decision.next_role is RecoveryRole.COUNTERFACTUAL
    assert decision.next_lease_budget == scheduler.config.counterfactual_lease
    assert scheduler.branch_uses_proof_reserve is False
    assert decision.proof_reserve_remaining == scheduler.config.proof_reserve


def test_new_material_progress_replaces_the_branch_with_one_new_focused_lease() -> None:
    expected_evidence_epoch = 2
    scheduler = RecoveryScheduler()
    primitive = ProgressSnapshot(confirmed_primitives=frozenset({"confirmed-file-read"}))
    scheduler.record_model_turn(primitive)
    first_branch = scheduler.active_branch_id
    scheduler.record_model_turn(primitive)

    decision = scheduler.record_model_turn(
        ProgressSnapshot(
            confirmed_primitives=primitive.confirmed_primitives,
            validated_request_templates=frozenset({"GET /download?file=VALUE"}),
        )
    )

    assert decision.reason == "material_progress_lease_granted"
    assert decision.executed_role is RecoveryRole.CLOSURE
    assert decision.next_role is RecoveryRole.CLOSURE
    assert decision.next_lease_budget == scheduler.config.progress_lease
    assert decision.next_lease_used == 0
    assert scheduler.active_branch_id != first_branch
    assert scheduler.evidence_epoch == expected_evidence_epoch


def test_confirmed_proof_stops_without_allocating_another_lease() -> None:
    scheduler = RecoveryScheduler()
    decision = scheduler.record_model_turn(
        ProgressSnapshot(confirmed_proofs=frozenset({"flag{target-proof}"}))
    )

    assert decision.status is RecoveryStatus.SOLVED
    assert decision.reason == "proof_confirmed"
    assert decision.next_role is None
    assert decision.next_lease_budget is None
    assert decision.remaining_model_requests > 0
    with pytest.raises(RuntimeError, match="after scheduler status solved"):
        scheduler.record_model_turn(EMPTY)


def test_repeated_observation_ends_the_core_lease_early() -> None:
    scheduler = RecoveryScheduler()
    digest = "same-target-response"

    first = scheduler.record_model_turn(EMPTY, observation_digest=digest)
    second = scheduler.record_model_turn(EMPTY, observation_digest=digest)

    assert first.observation_watchdog_triggered is False
    assert second.observation_watchdog_triggered is True
    assert second.reason == "core_observation_watchdog_pivot"
    assert second.total_model_requests < scheduler.config.initial_core_lease
    assert second.next_role is RecoveryRole.CLOSURE


def test_different_observations_do_not_trigger_the_watchdog() -> None:
    scheduler = RecoveryScheduler()

    for turn in range(1, scheduler.config.initial_core_lease):
        decision = scheduler.record_model_turn(
            EMPTY,
            observation_digest=f"different-{turn}",
        )

    assert decision.observation_watchdog_triggered is False
    assert decision.next_role is RecoveryRole.CORE


def test_same_low_value_route_is_blocked_until_material_evidence_changes() -> None:
    scheduler = RecoveryScheduler()
    fingerprint = "path-traversal|/download|file|dotdot"

    first = scheduler.record_model_turn(
        EMPTY,
        route_fingerprint=fingerprint,
        low_value_route=True,
    )
    second = scheduler.record_model_turn(
        EMPTY,
        route_fingerprint=fingerprint,
        low_value_route=True,
    )

    assert first.route_exhausted is False
    assert second.route_exhausted is True
    assert scheduler.route_is_available(fingerprint) is False
    assert scheduler.route_is_available("different-route") is True

    scheduler.record_model_turn(
        ProgressSnapshot(validated_response_differentials=frozenset({"admin-vs-user-object-diff"}))
    )
    assert scheduler.route_is_available(fingerprint) is True


def test_no_progress_path_stops_instead_of_spending_the_full_campaign_budget() -> None:
    scheduler = RecoveryScheduler()

    while scheduler.status is RecoveryStatus.RUNNING:
        decision = scheduler.record_model_turn(EMPTY)

    expected_spend = (
        scheduler.config.initial_core_lease
        + scheduler.config.closure_lease
        + scheduler.config.counterfactual_lease
    )
    assert scheduler.status is RecoveryStatus.EXPLORATION_EXHAUSTED
    assert scheduler.total_model_requests == expected_spend
    assert scheduler.total_model_requests < scheduler.config.max_model_requests
    assert decision.reason == "unchanged_evidence_epoch_exhausted"
    assert decision.next_role is None


def test_distinct_counterfactual_objectives_receive_bounded_additional_leases() -> None:
    scheduler = RecoveryScheduler()
    _finish_current_lease(scheduler)
    _finish_current_lease(
        scheduler,
        next_objective_fingerprint="auth|/login|session|bypass",
    )
    assert scheduler.active_objective_fingerprint == "auth|/login|session|bypass"

    second = _finish_current_lease(
        scheduler,
        next_objective_fingerprint="idor|/orders|order_id|cross-account",
    )
    assert second.reason == "novel_counterfactual_lease_granted"
    assert scheduler.active_objective_fingerprint == ("idor|/orders|order_id|cross-account")

    third = _finish_current_lease(
        scheduler,
        next_objective_fingerprint="ssti|/render|template|expression",
    )
    assert third.reason == "novel_counterfactual_lease_granted"
    assert scheduler.counterfactual_leases_started == (
        scheduler.config.max_counterfactual_leases_per_epoch
    )

    terminal = _finish_current_lease(
        scheduler,
        next_objective_fingerprint="ssrf|/fetch|url|loopback",
    )
    assert terminal.status is RecoveryStatus.EXPLORATION_EXHAUSTED
    assert terminal.reason == "proof_reserve_preserved"
    assert terminal.remaining_model_requests == scheduler.config.proof_reserve


def test_duplicate_counterfactual_objective_cannot_respawn_a_branch() -> None:
    scheduler = RecoveryScheduler()
    objective = "auth|/login|session|bypass"
    _finish_current_lease(scheduler)
    _finish_current_lease(
        scheduler,
        next_objective_fingerprint=objective,
    )

    decision = _finish_current_lease(
        scheduler,
        next_objective_fingerprint=objective,
    )

    assert decision.status is RecoveryStatus.EXPLORATION_EXHAUSTED
    assert decision.reason == "duplicate_counterfactual_objective_rejected"
    assert decision.next_role is None


def test_material_evidence_opens_a_new_objective_epoch() -> None:
    scheduler = RecoveryScheduler()
    objective = "auth|/login|session|bypass"
    _finish_current_lease(scheduler)
    _finish_current_lease(
        scheduler,
        next_objective_fingerprint=objective,
    )
    assert scheduler.objective_is_available(objective) is False

    scheduler.record_model_turn(
        ProgressSnapshot(confirmed_primitives=frozenset({"confirmed-auth-bypass"}))
    )

    assert scheduler.evidence_epoch == 1
    assert scheduler.objective_is_available(objective) is True
    assert scheduler.attempted_objective_fingerprints == set()


def test_counterfactual_branch_count_is_bounded_even_with_unused_global_budget() -> None:
    max_counterfactual_leases = 2
    scheduler = RecoveryScheduler(
        RecoveryConfig(
            max_model_requests=60,
            proof_reserve=6,
            max_counterfactual_leases_per_epoch=max_counterfactual_leases,
        )
    )
    _finish_current_lease(scheduler)
    _finish_current_lease(
        scheduler,
        next_objective_fingerprint="family-a",
    )
    _finish_current_lease(
        scheduler,
        next_objective_fingerprint="family-b",
    )

    decision = _finish_current_lease(
        scheduler,
        next_objective_fingerprint="family-c",
    )

    assert decision.status is RecoveryStatus.EXPLORATION_EXHAUSTED
    assert decision.reason == "counterfactual_lease_limit_reached"
    assert decision.remaining_model_requests > scheduler.config.proof_reserve


def test_exploration_cannot_consume_the_proof_reserve() -> None:
    max_requests = 20
    proof_reserve = 5
    expected_exploration_spend = max_requests - proof_reserve
    scheduler = RecoveryScheduler(
        RecoveryConfig(
            max_model_requests=max_requests,
            initial_core_lease=5,
            closure_lease=5,
            counterfactual_lease=10,
            progress_lease=8,
            proof_reserve=proof_reserve,
        )
    )

    while scheduler.status is RecoveryStatus.RUNNING:
        decision = scheduler.record_model_turn(EMPTY)

    assert scheduler.status is RecoveryStatus.EXPLORATION_EXHAUSTED
    assert scheduler.total_model_requests == expected_exploration_spend
    assert decision.reason == "proof_reserve_preserved"
    assert decision.remaining_model_requests == proof_reserve
    assert decision.proof_reserve_remaining == proof_reserve


def test_progress_focused_lease_may_use_reserve_but_never_exceed_hard_cap() -> None:
    max_requests = 10
    scheduler = RecoveryScheduler(
        RecoveryConfig(
            max_model_requests=max_requests,
            initial_core_lease=2,
            closure_lease=2,
            counterfactual_lease=2,
            progress_lease=10,
            proof_reserve=3,
        )
    )
    primitive = ProgressSnapshot(confirmed_primitives=frozenset({"confirmed-command-execution"}))
    scheduler.record_model_turn(primitive)

    while scheduler.status is RecoveryStatus.RUNNING:
        decision = scheduler.record_model_turn(primitive)

    assert scheduler.total_model_requests == max_requests
    assert scheduler.status is RecoveryStatus.BUDGET_EXHAUSTED
    assert decision.reason == "global_model_budget_exhausted"
    assert decision.remaining_model_requests == 0
    assert decision.proof_reserve_remaining == 0


def test_even_material_progress_on_every_turn_cannot_create_an_infinite_loop() -> None:
    max_requests = 12
    scheduler = RecoveryScheduler(
        RecoveryConfig(
            max_model_requests=max_requests,
            initial_core_lease=2,
            closure_lease=2,
            counterfactual_lease=3,
            progress_lease=4,
            proof_reserve=3,
        )
    )
    primitives: set[str] = set()

    while scheduler.status is RecoveryStatus.RUNNING:
        primitives.add(f"confirmed-primitive-{scheduler.total_model_requests + 1}")
        decision = scheduler.record_model_turn(
            ProgressSnapshot(confirmed_primitives=frozenset(primitives))
        )
        assert scheduler.total_model_requests <= max_requests

    assert scheduler.status is RecoveryStatus.BUDGET_EXHAUSTED
    assert scheduler.total_model_requests == max_requests
    assert decision.reason == "global_model_budget_exhausted"
    assert decision.next_role is None


def test_scheduler_can_pivot_progress_pivot_again_and_then_solve() -> None:
    scheduler = RecoveryScheduler(
        RecoveryConfig(
            max_model_requests=20,
            initial_core_lease=2,
            closure_lease=3,
            counterfactual_lease=4,
            progress_lease=4,
            proof_reserve=4,
        )
    )
    primitive = ProgressSnapshot(confirmed_primitives=frozenset({"confirmed-file-read"}))
    scheduler.record_model_turn(primitive)
    _finish_current_lease(scheduler, primitive)
    assert scheduler.role is RecoveryRole.COUNTERFACTUAL

    auth = ProgressSnapshot(
        confirmed_primitives=primitive.confirmed_primitives,
        authenticated_states=frozenset({"admin-session"}),
    )
    second_progress = scheduler.record_model_turn(auth)
    assert second_progress.reason == "material_progress_lease_granted"
    assert second_progress.next_role is RecoveryRole.CLOSURE

    solved = scheduler.record_model_turn(
        ProgressSnapshot(
            confirmed_proofs=frozenset({"flag{eventual-proof}"}),
            confirmed_primitives=primitive.confirmed_primitives,
            authenticated_states=auth.authenticated_states,
        )
    )
    assert solved.status is RecoveryStatus.SOLVED
    assert solved.next_role is None
    assert solved.total_model_requests < scheduler.config.max_model_requests


def test_scheduler_state_round_trips_mid_progress_lease() -> None:
    scheduler = RecoveryScheduler()
    scheduler.record_model_turn(
        ProgressSnapshot(confirmed_primitives=frozenset({"confirmed-file-read"}))
    )
    scheduler.record_model_turn(
        scheduler.last_snapshot,
        route_fingerprint="closure-route",
        low_value_route=True,
        observation_digest="closure-observation",
    )

    encoded = json.loads(json.dumps(scheduler.to_json()))
    restored = RecoveryScheduler.from_json(encoded)

    assert restored.to_json() == scheduler.to_json()
    assert restored.role is RecoveryRole.CLOSURE
    assert restored.branch_uses_proof_reserve is True
    assert restored.lease_limit == scheduler.config.progress_lease
    assert restored.lease_used == 1


def test_objective_ledger_round_trips_mid_counterfactual_lease() -> None:
    scheduler = RecoveryScheduler()
    objective = "idor|/orders|order_id|cross-account"
    _finish_current_lease(scheduler)
    _finish_current_lease(
        scheduler,
        next_objective_fingerprint=objective,
    )
    scheduler.record_model_turn(EMPTY, observation_digest="counterfactual-observation")

    encoded = json.loads(json.dumps(scheduler.to_json()))
    restored = RecoveryScheduler.from_json(encoded)

    assert restored.to_json() == scheduler.to_json()
    assert restored.active_objective_fingerprint == objective
    assert restored.attempted_objective_fingerprints == {objective}
    assert restored.counterfactual_leases_started == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"max_model_requests": 0},
        {"initial_core_lease": 0},
        {"closure_lease": 0},
        {"counterfactual_lease": 0},
        {"progress_lease": 0},
        {"proof_reserve": 0},
        {"low_value_route_limit": 0},
        {"repeated_observation_limit": 0},
        {"max_counterfactual_leases_per_epoch": 0},
        {"max_model_requests": 10, "proof_reserve": 10},
        {"max_model_requests": 10, "proof_reserve": 4, "initial_core_lease": 7},
    ],
)
def test_invalid_scheduler_bounds_fail_closed(changes: dict[str, int]) -> None:
    with pytest.raises(ValueError, match=r"greater than zero|smaller than|cannot exceed"):
        RecoveryConfig(**changes)
