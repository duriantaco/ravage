# ruff: noqa: PLR2004
from __future__ import annotations

import hashlib
import json

import pytest
from ravage.agent_core.autonomous_graph.branch_search import (
    BRANCH_SEARCH_POLICY_VERSION,
    PLANNER_FEEDBACK_SCHEMA_VERSION,
    BranchOutcomeIndex,
    BranchSearchError,
    seal_planner_feedback_attempt,
)


def _attempt(  # noqa: PLR0913 - the planner receipt fields are explicit.
    identity: str,
    *,
    cell_id: str = "cell:search",
    planner_cell_id: str | None = None,
    strategy: str = "sql-calibration",
    dimension: str = "query-oracle",
    progress_class: str = "support",
    outcome: str = "typed_progress:response_differential_validated",
    stage_before: str = "observed",
    stage: str = "calibrated",
    target_requests: int = 4,
    hypothesis_path: tuple[str, ...] = ("hypothesis:leaf", "hypothesis:parent"),
    repeated: bool = False,
    planner_attempt_count_before: int = 0,
    planner_evidence_version_before: int = 0,
    planner_evidence_refs_before: tuple[str, ...] = (),
    planner_no_progress_streak_before: int = 0,
    planner_previous_feedback_digest: str = "",
    planner_stage_before: str | None = None,
    planner_target_requests_before: int = 0,
) -> dict[str, object]:
    kinds_by_class = {
        "empty": (),
        "support": ("response_differential_validated",),
        "confirm": ("hypothesis_confirmed",),
        "disprove": ("hypothesis_disproved",),
        "pivot": ("hypothesis_disproved", "request_template_validated"),
        "proof": ("proof_confirmed",),
    }
    progress_kinds = tuple(sorted(kinds_by_class[progress_class]))
    progress_digest = (
        "progress-batch:" + hashlib.sha256(identity.encode()).hexdigest() if progress_kinds else ""
    )
    evidence_refs = (f"evidence:{identity}",) if progress_kinds else ()
    return seal_planner_feedback_attempt(
        {
            "reservation_id": identity,
            "node_id": "node:search",
            "cell_id": cell_id,
            "planner_cell_id": planner_cell_id or cell_id,
            "strategy": "_".join(strategy.replace("-", " ").split()),
            "dimension": "_".join(dimension.replace("-", " ").split()),
            "reservation_evidence_version": 0,
            "evidence_version_before": 0,
            "evidence_version_after": int(bool(progress_kinds)),
            "progress_class": progress_class,
            "progress_kinds": list(progress_kinds),
            "planner_attributed": True,
            "planner_state_attributed": True,
            "planner_attempt_count_before": planner_attempt_count_before,
            "planner_attempt_count_after": planner_attempt_count_before + 1,
            "planner_evidence_version_before": planner_evidence_version_before,
            "planner_evidence_version_after": (
                planner_evidence_version_before + int(bool(progress_kinds))
            ),
            "planner_evidence_refs_before": list(planner_evidence_refs_before),
            "planner_evidence_refs_after": sorted(
                {*planner_evidence_refs_before, *evidence_refs}
            ),
            "planner_no_progress_streak_before": planner_no_progress_streak_before,
            "planner_no_progress_streak_after": (
                0 if progress_kinds else planner_no_progress_streak_before + 1
            ),
            "planner_previous_feedback_digest": planner_previous_feedback_digest,
            "planner_stage_before": planner_stage_before or stage_before,
            "planner_stage_after": (
                stage if planner_stage_before is None else planner_stage_before
            ),
            "planner_target_requests_before": planner_target_requests_before,
            "planner_target_requests_after": planner_target_requests_before + target_requests,
            "outcome": outcome,
            "stage_before": stage_before,
            "stage": stage,
            "material_progress": bool(progress_kinds),
            "evidence_changed": bool(progress_kinds),
            "validated_batch_digest": progress_digest,
            "target_requests": target_requests,
            "hypothesis_fingerprint": hypothesis_path[0] if hypothesis_path else "",
            "hypothesis_path": list(hypothesis_path),
            "repeated_observation": repeated,
            "evidence_refs": list(evidence_refs),
            "agent_spec_fingerprint": "agent-spec:search",
            "belief_revision_id": "",
            "belief_disposition": "",
            "executor_receipt_digest": "",
        }
    )


def test_legacy_attempts_are_ignored_and_cold_start_adjustment_is_zero() -> None:
    legacy = _attempt("reservation:legacy")
    legacy.pop("planner_feedback_schema_version")
    legacy.pop("planner_feedback_digest")
    index = BranchOutcomeIndex.from_attempts((legacy,))

    score = index.score(
        cell_id="cell:search",
        strategy="sql-calibration",
        dimension="query-oracle",
        proof_proximity=100,
        attempts_used=7,
        max_attempts=8,
    )

    assert index.ignored_legacy_attempts == 1
    assert index.outcome_ids == ()
    assert score.cold_start is True
    assert score.total_adjustment == 0
    assert set(score.to_json()["components"].values()) == {0}


def test_outcome_updates_campaign_and_backpropagates_discounted_hypothesis_value() -> None:
    index = BranchOutcomeIndex.from_attempts((_attempt("reservation:one"),))

    campaign = index.campaign_stats(
        cell_id="cell:search",
        strategy="sql calibration",
        dimension="query oracle",
    )
    leaf = index.hypothesis_stats("hypothesis:leaf")
    parent = index.hypothesis_stats("hypothesis:parent")
    unrelated = index.hypothesis_stats("hypothesis:unrelated")

    assert campaign.visits == 1
    assert campaign.reward_sum_basis_points == 5_000
    assert leaf.reward_sum_basis_points == 5_000
    assert parent.reward_sum_basis_points == 3_750
    assert unrelated.visits == 0
    assert unrelated.reward_sum_basis_points == 0


def test_duplicate_progress_or_reservation_identity_is_rejected() -> None:
    first = _attempt("reservation:one")
    second = dict(first)

    with pytest.raises(BranchSearchError, match="duplicate branch outcome identity"):
        BranchOutcomeIndex.from_attempts((first, second))


def test_resealed_duplicate_reservation_is_rejected_independently_of_payload() -> None:
    first = _attempt("reservation:one")
    replay = _attempt(
        "reservation:one",
        progress_class="empty",
        outcome="no_typed_progress",
        stage_before="observed",
        stage="observed",
        planner_attempt_count_before=1,
        planner_evidence_version_before=1,
        planner_evidence_refs_before=("evidence:reservation:one",),
        planner_stage_before="calibrated",
        planner_target_requests_before=4,
        planner_previous_feedback_digest=str(first["planner_feedback_digest"]),
    )

    with pytest.raises(BranchSearchError, match="duplicate planner feedback reservation"):
        BranchOutcomeIndex.from_attempts((first, replay))


def test_resealed_duplicate_progress_batch_is_rejected() -> None:
    first = _attempt("reservation:one")
    replay = _attempt(
        "reservation:two",
        planner_attempt_count_before=1,
        planner_evidence_version_before=1,
        planner_evidence_refs_before=("evidence:reservation:one",),
        planner_stage_before="calibrated",
        planner_target_requests_before=4,
        planner_previous_feedback_digest=str(first["planner_feedback_digest"]),
    )
    replay.pop("planner_feedback_digest")
    replay["validated_batch_digest"] = first["validated_batch_digest"]
    replay = seal_planner_feedback_attempt(replay)

    with pytest.raises(BranchSearchError, match="duplicate validated progress batch"):
        BranchOutcomeIndex.from_attempts((first, replay))


def test_planner_cell_chain_rejects_a_missing_predecessor() -> None:
    first = _attempt("reservation:one")
    second = _attempt(
        "reservation:two",
        progress_class="empty",
        outcome="no_typed_progress",
        stage_before="observed",
        stage="observed",
        planner_attempt_count_before=1,
        planner_evidence_version_before=1,
        planner_evidence_refs_before=("evidence:reservation:one",),
        planner_stage_before="calibrated",
        planner_target_requests_before=4,
    )

    with pytest.raises(BranchSearchError, match="cell transition chain"):
        BranchOutcomeIndex.from_attempts((first, second))


def test_state_only_counterfactual_advances_bounds_without_receiving_reward() -> None:
    first = _attempt(
        "reservation:catalog",
        progress_class="empty",
        outcome="no_typed_progress",
        stage_before="observed",
        stage="observed",
        target_requests=1,
    )
    creative = _attempt(
        "reservation:creative",
        strategy="run-command",
        dimension="model-declared-material-counterfactual",
        progress_class="empty",
        outcome="no_typed_progress",
        stage_before="observed",
        stage="observed",
        target_requests=0,
        planner_attempt_count_before=1,
        planner_no_progress_streak_before=1,
        planner_target_requests_before=1,
        planner_previous_feedback_digest=str(first["planner_feedback_digest"]),
    )
    creative.pop("planner_feedback_digest")
    creative["planner_attributed"] = False
    creative = seal_planner_feedback_attempt(creative)

    index = BranchOutcomeIndex.from_attempts((first, creative))

    assert index.cell_stats("cell:search").attempt_count == 2
    assert index.cell_stats("cell:search").no_progress_streak == 2
    assert index.campaign_stats(
        cell_id="cell:search",
        strategy="run-command",
        dimension="model-declared-material-counterfactual",
    ).visits == 0


def test_projection_and_digest_are_independent_of_attempt_arrival_order() -> None:
    success = _attempt("reservation:success")
    failure = _attempt(
        "reservation:failure",
        progress_class="empty",
        outcome="repeated_observation",
        stage_before="observed",
        stage="observed",
        target_requests=8,
        repeated=True,
        planner_attempt_count_before=1,
        planner_evidence_version_before=1,
        planner_evidence_refs_before=("evidence:reservation:success",),
        planner_stage_before="calibrated",
        planner_target_requests_before=4,
        planner_previous_feedback_digest=str(success["planner_feedback_digest"]),
    )

    forward = BranchOutcomeIndex.from_attempts((success, failure))
    reverse = BranchOutcomeIndex.from_attempts((failure, success))

    assert forward == reverse
    assert forward.to_json() == reverse.to_json()


def test_score_exposes_integer_empirical_exploration_difficulty_cost_and_horizon() -> None:
    index = BranchOutcomeIndex.from_attempts((_attempt("reservation:one"),))

    score = index.score(
        cell_id="cell:search",
        strategy="sql-calibration",
        dimension="query-oracle",
        proof_proximity=80,
        attempts_used=4,
        max_attempts=8,
    )
    receipt = score.to_json()

    assert score.cold_start is False
    assert score.empirical_value == 50
    assert score.exploration_bonus == 25
    assert score.difficulty_penalty == 0
    assert score.request_cost_penalty == 1
    assert score.horizon_value == 20
    assert score.total_adjustment == 94
    assert receipt["total_adjustment"] == 94
    assert receipt["planner_feedback_schema_version"] == PLANNER_FEEDBACK_SCHEMA_VERSION
    assert receipt["branch_search_policy_version"] == BRANCH_SEARCH_POLICY_VERSION
    assert receipt["inputs"]["attempt_pressure_basis_points"] == 5_000
    assert json.loads(json.dumps(receipt)) == receipt


def test_no_progress_and_repetition_reduce_branch_value() -> None:
    success = BranchOutcomeIndex.from_attempts((_attempt("reservation:success"),))
    failure = BranchOutcomeIndex.from_attempts(
        (
            _attempt(
                "reservation:failure",
                progress_class="empty",
                outcome="repeated_observation",
                stage_before="observed",
                stage="observed",
                target_requests=20,
                repeated=True,
            ),
        )
    )
    arguments = {
        "cell_id": "cell:search",
        "strategy": "sql-calibration",
        "dimension": "query-oracle",
        "proof_proximity": 80,
        "attempts_used": 4,
        "max_attempts": 8,
    }

    success_score = success.score(**arguments)
    failure_score = failure.score(**arguments)

    assert failure_score.difficulty_penalty == 50
    assert failure_score.request_cost_penalty == 5
    assert failure_score.total_adjustment < 0
    assert success_score.total_adjustment > failure_score.total_adjustment


def test_tried_failure_makes_an_unvisited_campaign_explorable() -> None:
    attempted = _attempt(
        "reservation:failure",
        progress_class="empty",
        outcome="repeated_observation",
        stage_before="observed",
        stage="observed",
        repeated=True,
    )
    index = BranchOutcomeIndex.from_attempts((attempted,))
    common = {
        "cell_id": "cell:search",
        "strategy": "sql-calibration",
        "proof_proximity": 0,
        "attempts_used": 1,
        "max_attempts": 8,
    }

    tried = index.score(dimension="query-oracle", **common)
    unvisited = index.score(dimension="encoding-boundary", **common)

    assert tried.stats.repeated_count == 1
    assert unvisited.stats.visits == 0
    assert unvisited.cold_start is False
    assert unvisited.exploration_bonus > 0
    assert unvisited.total_adjustment > tried.total_adjustment


def test_feedback_from_an_unrelated_surface_does_not_change_cold_start_order() -> None:
    unrelated = _attempt("reservation:other", cell_id="cell:other")
    index = BranchOutcomeIndex.from_attempts((unrelated,))

    score = index.score(
        cell_id="cell:new",
        strategy="sql-calibration",
        dimension="query-oracle",
        proof_proximity=100,
        attempts_used=0,
        max_attempts=8,
    )

    assert score.cold_start is True
    assert score.total_adjustment == 0


def test_execution_route_feedback_is_keyed_to_its_recommendation_cell() -> None:
    attempt = _attempt(
        "reservation:routed",
        cell_id="cell:semantic-action-route",
        planner_cell_id="cell:objective-recommendation",
    )
    index = BranchOutcomeIndex.from_attempts((attempt,))

    recommendation = index.score(
        cell_id="cell:objective-recommendation",
        strategy="sql-calibration",
        dimension="query-oracle",
        proof_proximity=50,
        attempts_used=1,
        max_attempts=8,
    )
    execution = index.score(
        cell_id="cell:semantic-action-route",
        strategy="sql-calibration",
        dimension="query-oracle",
        proof_proximity=50,
        attempts_used=1,
        max_attempts=8,
    )

    assert recommendation.stats.visits == 1
    assert execution.cold_start is True


def test_unattributed_tool_outcome_cannot_steer_catalog_campaigns() -> None:
    attempt = _attempt("reservation:generic")
    attempt.pop("planner_feedback_digest")
    attempt["planner_attributed"] = False
    attempt["planner_state_attributed"] = False
    index = BranchOutcomeIndex.from_attempts((seal_planner_feedback_attempt(attempt),))

    assert index.outcome_ids == ()
    assert index.ignored_unattributed_attempts == 1
    assert (
        index.score(
            cell_id="cell:search",
            strategy="sql-calibration",
            dimension="query-oracle",
            proof_proximity=80,
            attempts_used=1,
            max_attempts=8,
        ).cold_start
        is True
    )


def test_horizon_value_only_favors_proof_near_work_under_attempt_pressure() -> None:
    index = BranchOutcomeIndex.from_attempts((_attempt("reservation:one"),))
    common = {
        "cell_id": "cell:search",
        "strategy": "sql-calibration",
        "dimension": "query-oracle",
        "max_attempts": 8,
    }

    early = index.score(proof_proximity=100, attempts_used=0, **common)
    late_far = index.score(proof_proximity=20, attempts_used=7, **common)
    late_near = index.score(proof_proximity=100, attempts_used=7, **common)

    assert early.horizon_value == 0
    assert late_near.horizon_value > late_far.horizon_value


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"proof_proximity": 101}, "proof proximity"),
        ({"attempts_used": 9}, "attempts used cannot exceed"),
        ({"max_attempts": 0}, "max attempts"),
    ],
)
def test_score_rejects_unbounded_inputs(
    overrides: dict[str, int],
    message: str,
) -> None:
    index = BranchOutcomeIndex.from_attempts((_attempt("reservation:one"),))
    arguments = {
        "cell_id": "cell:search",
        "strategy": "sql-calibration",
        "dimension": "query-oracle",
        "proof_proximity": 80,
        "attempts_used": 4,
        "max_attempts": 8,
        **overrides,
    }

    with pytest.raises(BranchSearchError, match=message):
        index.score(**arguments)


def test_opted_in_feedback_requires_identity_and_acyclic_hypothesis_path() -> None:
    missing_identity = _attempt("reservation:one")
    missing_identity.pop("planner_feedback_digest")
    missing_identity["reservation_id"] = ""
    cyclic = _attempt("reservation:cycle")
    cyclic.pop("planner_feedback_digest")
    cyclic["hypothesis_path"] = ["hypothesis:leaf", "hypothesis:leaf"]

    with pytest.raises(BranchSearchError, match="reservation id"):
        seal_planner_feedback_attempt(missing_identity)
    with pytest.raises(BranchSearchError, match="empty or cyclic"):
        seal_planner_feedback_attempt(cyclic)


def test_typed_progress_requires_executor_evidence_references() -> None:
    missing_evidence = _attempt("reservation:missing-evidence")
    missing_evidence.pop("planner_feedback_digest")
    missing_evidence["evidence_refs"] = []
    missing_evidence["planner_evidence_refs_after"] = []

    with pytest.raises(BranchSearchError, match="executor evidence references"):
        seal_planner_feedback_attempt(missing_evidence)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("planner_evidence_version_before", 1, "evidence version exceeds attempt count"),
        ("planner_no_progress_streak_before", 1, "streak exceeds attempt count"),
        ("planner_target_requests_before", 97, "target requests exceed route bound"),
    ],
)
def test_planner_feedback_rejects_unreachable_root_state(
    field: str,
    value: int,
    message: str,
) -> None:
    poisoned = _attempt(
        "reservation:poisoned",
        progress_class="empty",
        outcome="no_typed_progress",
        stage_before="observed",
        stage="observed",
        target_requests=0,
    )
    poisoned.pop("planner_feedback_digest")
    poisoned[field] = value
    if field == "planner_evidence_version_before":
        poisoned["planner_evidence_version_after"] = value
    elif field == "planner_no_progress_streak_before":
        poisoned["planner_no_progress_streak_after"] = value + 1
    elif field == "planner_target_requests_before":
        poisoned["planner_target_requests_after"] = value

    with pytest.raises(BranchSearchError, match=message):
        seal_planner_feedback_attempt(poisoned)


def test_planner_feedback_chain_requires_a_canonical_zero_state_root() -> None:
    individually_valid_suffix = _attempt(
        "reservation:suffix",
        progress_class="empty",
        outcome="no_typed_progress",
        stage_before="observed",
        stage="observed",
        target_requests=0,
        planner_attempt_count_before=7,
        planner_evidence_version_before=7,
        planner_evidence_refs_before=tuple(
            f"evidence:prior-{index}" for index in range(7)
        ),
    )

    with pytest.raises(BranchSearchError, match="cell root is not canonical"):
        BranchOutcomeIndex.from_attempts((individually_valid_suffix,))
