from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.capability_gaps import CapabilityGapBacklog
from ravage.agent_core.autonomous_graph.learning import (
    GraphLearningError,
    ReplayMetrics,
    RouteLesson,
    RouteLessonStore,
    SeedLearningPolicy,
    SeedPolicyAdjustment,
    active_policy_path,
    build_candidate_policy,
    candidate_policy_path,
    capability_backlog_path,
    extract_route_lessons,
    learning_artifact_summary,
    promote_candidate_policy,
    record_route_lessons,
)
from ravage.agent_core.autonomous_graph.seed_portfolio import (
    build_seed_portfolio,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
)

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765/"
BASE_DIGEST = "a" * 64
POSITIVE_SCORE_DELTA = 95
EXPECTED_LESSON_COUNT = 2
REPLAY_CASES = 3
MINIMUM_INDEPENDENT_RUNS = 2
LEARNED_TARGET_REQUESTS = 9
NORMALIZED_SCORE_DELTA = 65


def _base() -> BaseRouteOutcome:
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest=BASE_DIGEST,
        state_ref="frozen-state.json",
    )


def _lesson(  # noqa: PLR0913 - compact immutable fixture.
    source: str,
    *,
    sequence: int = 0,
    progress: bool,
    proof: bool = False,
    loop_stopped: bool = False,
    probe: str = "filtered_query_bypass",
) -> RouteLesson:
    verification = (
        {
            "hypothesis_fingerprint": "hypothesis:" + "b" * 64,
            "agent_spec_fingerprint": "agent-spec:" + "c" * 64,
            "belief_revision_id": "belief:" + "d" * 64,
            "belief_disposition": "confirmed" if proof else "supported",
            "executor_receipt_digest": "executor-receipt:" + "e" * 64,
        }
        if progress
        else {}
    )
    return RouteLesson.create(
        source_digest=source,
        sequence=sequence,
        family="sql_injection",
        probe=probe,
        dimension="filter_and_encoding_boundary",
        outcome="proof_confirmed" if proof else ("typed_progress" if progress else "plateau"),
        material_progress=progress,
        proof_confirmed=proof,
        loop_stopped=loop_stopped,
        target_requests=3,
        **verification,
    )


def test_extract_route_lessons_uses_only_generic_receipt_fields(
    tmp_path: Path,
) -> None:
    cell_id = "cell:generic"
    coverage = {
        "version": 1,
        "cells": {
            cell_id: {
                "cell": {
                    "cell_id": cell_id,
                    "family": "sql_injection",
                    "endpoint": "/private/search",
                    "method": "POST",
                    "inputs": ["secret_parameter"],
                    "identity": "anonymous",
                    "content_type": "application/x-www-form-urlencoded",
                }
            }
        },
        "attempts": [
            {
                "cell_id": cell_id,
                "strategy": "sql-filter-counterfactual",
                "dimension": "filter_and_encoding_boundary",
                "evidence_version_after": 0,
                "stage": "observed",
                "material_progress": False,
                "outcome": "no_typed_progress",
                "target_requests": 4,
            }
        ],
    }
    failures = {
        "version": 1,
        "certificates": {
            "failure:one": {
                "cell_id": cell_id,
                "strategy": "sql_filter_counterfactual",
                "dimension": "filter_and_encoding_boundary",
                "evidence_version": 0,
            }
        },
        "order": ["failure:one"],
    }
    (tmp_path / "investigation-coverage.json").write_text(
        json.dumps(coverage),
        encoding="utf-8",
    )
    (tmp_path / "investigation-failures.json").write_text(
        json.dumps(failures),
        encoding="utf-8",
    )

    lessons = extract_route_lessons(tmp_path)
    encoded = json.dumps([lesson.to_json() for lesson in lessons])

    assert len(lessons) == 1
    assert lessons[0].probe == "filtered_query_bypass"
    assert lessons[0].loop_stopped is True
    assert "/private/search" not in encoded
    assert "secret_parameter" not in encoded


def test_unknown_model_taxonomy_is_collapsed_before_global_learning(
    tmp_path: Path,
) -> None:
    cell_id = "cell:secret"
    coverage = {
        "version": 1,
        "cells": {
            cell_id: {
                "cell": {
                    "cell_id": cell_id,
                    "family": "customer_secret_family",
                }
            }
        },
        "attempts": [
            {
                "cell_id": cell_id,
                "strategy": "secret-target-specific-strategy",
                "dimension": "secret_target_dimension",
                "evidence_version_after": 0,
                "stage": "observed",
                "material_progress": False,
                "outcome": "no_typed_progress",
                "target_requests": 1,
            }
        ],
    }
    failures = {
        "version": 1,
        "certificates": {
            "failure:secret": {
                "cell_id": cell_id,
                "strategy": "secret_target_specific_strategy",
                "dimension": "secret_target_dimension",
                "evidence_version": 0,
            }
        },
        "order": ["failure:secret"],
    }
    (tmp_path / "investigation-coverage.json").write_text(
        json.dumps(coverage),
        encoding="utf-8",
    )
    (tmp_path / "investigation-failures.json").write_text(
        json.dumps(failures),
        encoding="utf-8",
    )

    lesson = extract_route_lessons(tmp_path)[0]
    encoded = json.dumps(lesson.to_json())

    assert lesson.family == "unclassified"
    assert lesson.probe == "custom_counterfactual"
    assert lesson.dimension == "custom_counterfactual"
    assert "customer_secret_family" not in encoded
    assert "secret_target_specific_strategy" not in encoded
    assert "secret_target_dimension" not in encoded


def test_lesson_store_is_append_only_and_idempotent(tmp_path: Path) -> None:
    store = RouteLessonStore(tmp_path / "lessons.jsonl")
    first = _lesson("route-source:first", progress=True)
    second = _lesson("route-source:second", progress=False, loop_stopped=True)

    assert store.append((first,)) == (first,)
    assert store.append((first, second)) == (second,)
    assert store.append((first, second)) == ()
    assert store.load() == (first, second)


def test_legacy_route_lesson_round_trips_without_gaining_verification(
    tmp_path: Path,
) -> None:
    canonical = {
        "source_digest": "route_source:legacy",
        "sequence": 0,
        "family": "sql_injection",
        "probe": "filtered_query_bypass",
        "dimension": "filter_and_encoding_boundary",
        "outcome": "typed_progress",
        "material_progress": True,
        "proof_confirmed": False,
        "loop_stopped": False,
        "target_requests": 3,
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    payload = {
        "version": 1,
        "lesson_id": ("route-lesson:" + hashlib.sha256(encoded).hexdigest()[:24]),
        **canonical,
    }

    lesson = RouteLesson.from_json(payload)
    store = RouteLessonStore(tmp_path / "legacy-lessons.jsonl")
    store.append((lesson,))

    assert lesson.executor_verified is False
    assert lesson.schema_version == 1
    assert store.load() == (lesson,)


def test_learn_mode_refreshes_review_only_candidate_and_gap_backlog(
    tmp_path: Path,
) -> None:
    memory_db = tmp_path / "memory.sqlite3"
    settings = SimpleNamespace(mode="learn", db_path=memory_db)
    first_workspace = tmp_path / "run-one"
    second_workspace = tmp_path / "run-two"
    _write_failed_learning_workspace(
        first_workspace,
        source_suffix="one",
        target_requests=4,
    )
    _write_failed_learning_workspace(
        second_workspace,
        source_suffix="two",
        target_requests=5,
    )

    record_route_lessons(first_workspace, memory_settings=settings)
    first_candidate = SeedLearningPolicy.load(candidate_policy_path(memory_db))
    first_backlog = CapabilityGapBacklog.load(capability_backlog_path(memory_db))

    assert first_candidate.adjustments == ()
    assert first_backlog.gaps == ()
    assert not active_policy_path(memory_db).exists()

    record_route_lessons(second_workspace, memory_settings=settings)
    candidate = SeedLearningPolicy.load(candidate_policy_path(memory_db))
    backlog = CapabilityGapBacklog.load(capability_backlog_path(memory_db))
    summary = learning_artifact_summary(settings)
    encoded = json.dumps({"candidate": candidate.to_json(), "backlog": backlog.to_json()})

    assert candidate.status == "candidate"
    assert len(candidate.adjustments) == 1
    assert candidate.adjustments[0].score_delta < 0
    assert len(backlog.gaps) == 1
    assert backlog.gaps[0].status == "needs_specialist"
    assert backlog.gaps[0].target_requests == LEARNED_TARGET_REQUESTS
    assert summary["candidate_policy"]["ready_for_held_out_replay"] is True
    assert summary["capability_backlog"]["gap_count"] == 1
    assert not active_policy_path(memory_db).exists()
    assert "/private/one" not in encoded
    assert "/private/two" not in encoded
    assert "secret_one" not in encoded
    assert "secret_two" not in encoded


def test_candidate_policy_requires_independent_runs_and_aggregates_outcomes() -> None:
    one_run = (
        _lesson("route-source:one", progress=True),
        _lesson(
            "route-source:one",
            sequence=1,
            progress=False,
            loop_stopped=True,
        ),
    )
    two_runs = (
        *one_run,
        _lesson("route-source:two", progress=True, proof=True),
    )

    assert build_candidate_policy(one_run).adjustments == ()
    candidate = build_candidate_policy(two_runs)

    assert candidate.status == "candidate"
    assert len(candidate.adjustments) == 1
    adjustment = candidate.adjustments[0]
    assert adjustment.independent_runs == MINIMUM_INDEPENDENT_RUNS
    assert adjustment.proof_count == 1
    assert adjustment.failure_count == 1
    assert adjustment.score_delta == POSITIVE_SCORE_DELTA


def test_unverified_positive_lessons_cannot_promote_route_scores() -> None:
    unverified = (
        RouteLesson.create(
            source_digest="route-source:one",
            sequence=0,
            family="sql_injection",
            probe="filtered_query_bypass",
            dimension="filter_and_encoding_boundary",
            outcome="typed_progress",
            material_progress=True,
            proof_confirmed=False,
            loop_stopped=False,
            target_requests=3,
        ),
        RouteLesson.create(
            source_digest="route-source:two",
            sequence=0,
            family="sql_injection",
            probe="filtered_query_bypass",
            dimension="filter_and_encoding_boundary",
            outcome="proof_confirmed",
            material_progress=True,
            proof_confirmed=True,
            loop_stopped=False,
            target_requests=3,
        ),
    )

    candidate = build_candidate_policy(unverified)

    assert candidate.adjustments == ()


def test_candidate_score_is_normalized_per_run_not_attempt_volume() -> None:
    one_failed_attempt = (
        _lesson(
            "route-source:one",
            progress=False,
            loop_stopped=True,
        ),
        _lesson("route-source:two", progress=True, proof=True),
    )
    repeated_failed_attempts = (
        *(
            _lesson(
                "route-source:one",
                sequence=sequence,
                progress=False,
                loop_stopped=True,
            )
            for sequence in range(10)
        ),
        _lesson("route-source:two", progress=True, proof=True),
    )

    baseline = build_candidate_policy(one_failed_attempt)
    noisy = build_candidate_policy(repeated_failed_attempts)

    assert baseline.adjustments[0].score_delta == NORMALIZED_SCORE_DELTA
    assert noisy.adjustments[0].score_delta == NORMALIZED_SCORE_DELTA


def test_candidate_policy_cannot_change_live_seed_scores() -> None:
    adjustment = SeedPolicyAdjustment(
        family="sql_injection",
        probe="filtered_query_bypass",
        score_delta=100,
        independent_runs=2,
        progress_count=2,
        proof_count=0,
        failure_count=0,
        loop_stop_count=0,
    )
    candidate = SeedLearningPolicy.create(
        status="candidate",
        adjustments=(adjustment,),
    )
    state = AgentState(
        facts=["filtered search input"],
        signals={"endpoints": ["/search"], "parameters": ["query"]},
    )

    with pytest.raises(GraphLearningError, match="candidate seed policy"):
        build_seed_portfolio(
            state,
            base=_base(),
            limit=4,
            policy=candidate,
        )


def test_promotion_requires_held_out_solve_gain_and_no_regressions(
    tmp_path: Path,
) -> None:
    candidate_policy = build_candidate_policy(
        (
            _lesson("route-source:one", progress=True),
            _lesson("route-source:two", progress=True, proof=True),
        )
    )
    baseline = ReplayMetrics(
        cases=REPLAY_CASES,
        solved=1,
        false_proofs=0,
        loop_violations=0,
        unmatched_model_attempts=0,
        cost_usd=3.0,
        model_requests=30,
    )
    regressed = ReplayMetrics(
        cases=REPLAY_CASES,
        solved=2,
        false_proofs=1,
        loop_violations=1,
        unmatched_model_attempts=1,
        cost_usd=4.0,
        model_requests=36,
    )
    output_path = tmp_path / "active-policy.json"

    rejected = promote_candidate_policy(
        candidate_policy,
        baseline=baseline,
        candidate=regressed,
        output_path=output_path,
    )

    assert rejected.accepted is False
    assert "false_proof_regression" in rejected.reasons
    assert "loop_safety_regression" in rejected.reasons
    assert "candidate_model_accounting_incomplete" in rejected.reasons
    assert not output_path.exists()

    improved = ReplayMetrics(
        cases=REPLAY_CASES,
        solved=2,
        false_proofs=0,
        loop_violations=0,
        unmatched_model_attempts=0,
        cost_usd=4.0,
        model_requests=36,
    )
    accepted = promote_candidate_policy(
        candidate_policy,
        baseline=baseline,
        candidate=improved,
        output_path=output_path,
    )
    promoted = SeedLearningPolicy.load_promoted(output_path)

    assert accepted.accepted is True
    assert promoted.status == "promoted"
    assert promoted.replay_receipt_digest == accepted.receipt_digest


def test_promoted_policy_adjustment_is_applied_and_audited() -> None:
    state = AgentState(
        facts=["filtered search input"],
        signals={"endpoints": ["/search"], "parameters": ["query"]},
        tasks=[
            {
                "id": "data-query",
                "status": "in_progress",
                "priority": 100,
                "attempts": 2,
            }
        ],
    )
    adjustment = SeedPolicyAdjustment(
        family="sql_injection",
        probe="filtered_query_bypass",
        score_delta=100,
        independent_runs=2,
        progress_count=2,
        proof_count=0,
        failure_count=0,
        loop_stop_count=0,
    )
    promoted = SeedLearningPolicy.create(
        status="promoted",
        adjustments=(adjustment,),
        replay_receipt_digest="replay-receipt:" + "b" * 64,
    )
    baseline = build_seed_portfolio(state, base=_base(), limit=4)
    learned = build_seed_portfolio(
        state,
        base=_base(),
        limit=4,
        policy=promoted,
    )
    baseline_scores = {item.objective.fingerprint: item.score for item in baseline.ranking}
    learned_item = next(
        item for item in learned.ranking if item.objective.probe == "filtered_query_bypass"
    )

    assert learned.policy_id == promoted.policy_id
    assert learned_item.score == (
        baseline_scores[learned_item.objective.fingerprint] + adjustment.score_delta
    )


def _write_failed_learning_workspace(
    workspace: Path,
    *,
    source_suffix: str,
    target_requests: int,
) -> None:
    workspace.mkdir(parents=True)
    cell_id = f"cell:{source_suffix}"
    coverage = {
        "version": 1,
        "cells": {
            cell_id: {
                "cell": {
                    "cell_id": cell_id,
                    "family": "sql_injection",
                    "endpoint": f"/private/{source_suffix}",
                    "method": "POST",
                    "inputs": [f"secret_{source_suffix}"],
                    "identity": "anonymous",
                    "content_type": "application/x-www-form-urlencoded",
                }
            }
        },
        "attempts": [
            {
                "cell_id": cell_id,
                "strategy": "sql-filter-counterfactual",
                "dimension": "filter_and_encoding_boundary",
                "evidence_version_after": 0,
                "stage": "observed",
                "material_progress": False,
                "outcome": "no_typed_progress",
                "target_requests": target_requests,
            }
        ],
    }
    failures = {
        "version": 1,
        "certificates": {
            f"failure:{source_suffix}": {
                "cell_id": cell_id,
                "strategy": "sql_filter_counterfactual",
                "dimension": "filter_and_encoding_boundary",
                "evidence_version": 0,
            }
        },
        "order": [f"failure:{source_suffix}"],
    }
    (workspace / "investigation-coverage.json").write_text(
        json.dumps(coverage),
        encoding="utf-8",
    )
    (workspace / "investigation-failures.json").write_text(
        json.dumps(failures),
        encoding="utf-8",
    )
