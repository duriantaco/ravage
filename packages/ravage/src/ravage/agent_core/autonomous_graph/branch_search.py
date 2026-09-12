# ruff: noqa: EM101, EM102, TRY003
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

PLANNER_FEEDBACK_SCHEMA_VERSION = 1
BRANCH_SEARCH_POLICY_VERSION = 1
MAX_PLANNER_ATTEMPTS_PER_CELL = 8
MAX_PLANNER_OUTCOMES = 500
_MAX_BP = 10_000
_MAX_ADJUSTMENT = 100
_MAX_CHARGED_REQUESTS = 96
_MAX_HISTORY_BYTES = 16 * 1024 * 1024
_MAX_FEEDBACK_BYTES = 64 * 1024
_MAX_TEXT_LENGTH = 4_096
_MAX_IDENTITY_LENGTH = 1_024
_MAX_HYPOTHESIS_PATH = 64
_MAX_EVIDENCE_REFS = 128
_SHA256_HEX_LENGTH = 64
_STAGE_RANK = {
    "observed": 0,
    "contracted": 1,
    "calibrated": 2,
    "primitive": 3,
    "closure": 4,
    "proof": 5,
}
_PROGRESS_STAGE = {
    "request_template_validated": "contracted",
    "response_differential_validated": "calibrated",
    "sql_oracle_calibrated": "calibrated",
    "hypothesis_confirmed": "calibrated",
    "primitive_confirmed": "primitive",
    "auth_state_changed": "closure",
    "extraction_checkpoint": "closure",
    "proof_confirmed": "proof",
}
_PROGRESS_KINDS = frozenset(
    {
        "proof_confirmed",
        "primitive_confirmed",
        "auth_state_changed",
        "request_template_validated",
        "response_differential_validated",
        "sql_oracle_calibrated",
        "extraction_checkpoint",
        "hypothesis_confirmed",
        "hypothesis_disproved",
    }
)
_FEEDBACK_FIELDS = frozenset(
    {
        "agent_spec_fingerprint",
        "belief_disposition",
        "belief_revision_id",
        "cell_id",
        "dimension",
        "evidence_changed",
        "evidence_refs",
        "evidence_version_after",
        "evidence_version_before",
        "executor_receipt_digest",
        "hypothesis_fingerprint",
        "hypothesis_path",
        "material_progress",
        "node_id",
        "outcome",
        "planner_feedback_digest",
        "planner_feedback_schema_version",
        "planner_attributed",
        "planner_attempt_count_after",
        "planner_attempt_count_before",
        "planner_cell_id",
        "planner_evidence_version_after",
        "planner_evidence_version_before",
        "planner_evidence_refs_after",
        "planner_evidence_refs_before",
        "progress_class",
        "progress_kinds",
        "planner_no_progress_streak_after",
        "planner_no_progress_streak_before",
        "planner_previous_feedback_digest",
        "planner_stage_after",
        "planner_stage_before",
        "planner_state_attributed",
        "planner_target_requests_after",
        "planner_target_requests_before",
        "repeated_observation",
        "reservation_evidence_version",
        "reservation_id",
        "stage",
        "stage_before",
        "strategy",
        "target_requests",
        "validated_batch_digest",
    }
)


class BranchSearchError(ValueError):
    """Raised when planner feedback is ambiguous, unbounded, or replayed."""


class BranchKind(StrEnum):
    CAMPAIGN = "campaign"
    HYPOTHESIS = "hypothesis"


class BranchOutcomeClass(StrEnum):
    EMPTY = "empty"
    SUPPORT = "support"
    CONFIRM = "confirm"
    DISPROVE = "disprove"
    PIVOT = "pivot"
    PROOF = "proof"


@dataclass(frozen=True)
class BranchStats:
    branch_id: str
    kind: BranchKind
    visits: int = 0
    reward_sum_basis_points: int = 0
    proof_count: int = 0
    progress_count: int = 0
    disproof_count: int = 0
    no_progress_count: int = 0
    repeated_count: int = 0
    target_requests: int = 0

    @property
    def mean_reward_basis_points(self) -> int:
        return _signed_div(self.reward_sum_basis_points, self.visits) if self.visits else 0

    @property
    def failure_basis_points(self) -> int:
        if not self.visits:
            return 0
        failures = self.disproof_count + self.no_progress_count
        return min(failures * _MAX_BP // self.visits, _MAX_BP)

    @property
    def repeated_basis_points(self) -> int:
        return min(self.repeated_count * _MAX_BP // self.visits, _MAX_BP) if self.visits else 0

    @property
    def average_target_requests(self) -> int:
        return (self.target_requests + self.visits - 1) // self.visits if self.visits else 0

    def to_json(self) -> dict[str, object]:
        return {
            "branch_id": self.branch_id,
            "kind": self.kind.value,
            "visits": self.visits,
            "reward_sum_basis_points": self.reward_sum_basis_points,
            "mean_reward_basis_points": self.mean_reward_basis_points,
            "proof_count": self.proof_count,
            "progress_count": self.progress_count,
            "disproof_count": self.disproof_count,
            "no_progress_count": self.no_progress_count,
            "repeated_count": self.repeated_count,
            "target_requests": self.target_requests,
            "average_target_requests": self.average_target_requests,
            "failure_basis_points": self.failure_basis_points,
            "repeated_basis_points": self.repeated_basis_points,
        }


@dataclass(frozen=True)
class PlannerCellStats:
    cell_id: str
    attempt_count: int = 0
    evidence_version: int = 0
    no_progress_streak: int = 0
    target_requests: int = 0
    stage: str = "observed"
    root_stage: str = "observed"
    attempted_dimensions: tuple[tuple[str, int], ...] = ()
    evidence_refs: tuple[str, ...] = ()
    last_dimension: str = ""
    last_outcome: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "cell_id": self.cell_id,
            "attempt_count": self.attempt_count,
            "evidence_version": self.evidence_version,
            "no_progress_streak": self.no_progress_streak,
            "target_requests": self.target_requests,
            "stage": self.stage,
            "root_stage": self.root_stage,
            "attempted_dimensions": dict(self.attempted_dimensions),
            "evidence_refs": list(self.evidence_refs),
            "last_dimension": self.last_dimension,
            "last_outcome": self.last_outcome,
        }


@dataclass(frozen=True)
class BranchScoreAdjustment:
    branch_id: str
    source_digest: str
    total_adjustment: int
    raw_adjustment: int
    empirical_value: int
    exploration_bonus: int
    difficulty_penalty: int
    request_cost_penalty: int
    horizon_value: int
    proof_proximity: int
    attempts_used: int
    max_attempts: int
    attempt_pressure_basis_points: int
    cold_start: bool
    capped: bool
    stats: BranchStats

    def to_json(self) -> dict[str, object]:
        return {
            "planner_feedback_schema_version": PLANNER_FEEDBACK_SCHEMA_VERSION,
            "branch_search_policy_version": BRANCH_SEARCH_POLICY_VERSION,
            "branch_id": self.branch_id,
            "source_digest": self.source_digest,
            "total_adjustment": self.total_adjustment,
            "raw_adjustment": self.raw_adjustment,
            "cold_start": self.cold_start,
            "capped": self.capped,
            "components": {
                "empirical_value": self.empirical_value,
                "exploration_bonus": self.exploration_bonus,
                "difficulty_penalty": self.difficulty_penalty,
                "request_cost_penalty": self.request_cost_penalty,
                "horizon_value": self.horizon_value,
            },
            "inputs": {
                "proof_proximity": self.proof_proximity,
                "attempts_used": self.attempts_used,
                "max_attempts": self.max_attempts,
                "attempt_pressure_basis_points": self.attempt_pressure_basis_points,
            },
            "stats": self.stats.to_json(),
        }


@dataclass(frozen=True)
class BranchOutcomeIndex:
    """Pure projection of opted-in coverage attempts with integer backpropagation."""

    source_digest: str
    outcome_ids: tuple[str, ...]
    ignored_legacy_attempts: int
    ignored_unattributed_attempts: int
    cell_visits: tuple[tuple[str, int], ...]
    cell_heads: tuple[tuple[str, str], ...]
    cells: tuple[PlannerCellStats, ...]
    campaigns: tuple[BranchStats, ...]
    hypotheses: tuple[BranchStats, ...]

    @classmethod
    def from_attempts(cls, attempts: Sequence[Mapping[str, object]]) -> BranchOutcomeIndex:
        if len(attempts) > MAX_PLANNER_OUTCOMES:
            raise BranchSearchError(
                f"branch history exceeds {MAX_PLANNER_OUTCOMES} outcomes"
            )
        if _encoded_size(attempts, "branch history") > _MAX_HISTORY_BYTES:
            raise BranchSearchError("branch history exceeds its byte limit")
        outcomes: list[_Outcome] = []
        scoring_outcomes: list[_Outcome] = []
        validated_batches: list[str] = []
        executor_receipts: list[str] = []
        ignored = 0
        ignored_unattributed = 0
        for attempt in attempts:
            if "planner_feedback_version" in attempt:
                raise BranchSearchError("ambiguous legacy planner feedback version field")
            version = attempt.get("planner_feedback_schema_version")
            if version is None:
                ignored += 1
                continue
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version != PLANNER_FEEDBACK_SCHEMA_VERSION
            ):
                raise BranchSearchError(f"unsupported planner feedback schema version: {version}")
            validate_planner_feedback_attempt(attempt)
            outcome = _normalize(attempt)
            if attempt["planner_state_attributed"] is not True:
                ignored_unattributed += 1
                continue
            outcomes.append(outcome)
            if attempt["planner_attributed"] is True:
                scoring_outcomes.append(outcome)
            batch_digest = str(attempt["validated_batch_digest"])
            if batch_digest:
                validated_batches.append(batch_digest)
            executor_digest = str(attempt["executor_receipt_digest"])
            if executor_digest:
                executor_receipts.append(executor_digest)
        identities = tuple(outcome.outcome_id for outcome in outcomes)
        if len(set(identities)) != len(identities):
            raise BranchSearchError("duplicate branch outcome identity")
        reservation_ids = tuple(outcome.reservation_id for outcome in outcomes)
        if len(set(reservation_ids)) != len(reservation_ids):
            raise BranchSearchError("duplicate planner feedback reservation identity")
        if len(set(validated_batches)) != len(validated_batches):
            raise BranchSearchError("duplicate validated progress batch identity")
        if len(set(executor_receipts)) != len(executor_receipts):
            raise BranchSearchError("duplicate executor receipt identity")

        accumulators: dict[tuple[BranchKind, str], _Accumulator] = {}
        cell_accumulators: dict[str, list[_Outcome]] = {}
        for outcome in outcomes:
            cell_accumulators.setdefault(outcome.planner_cell_id, []).append(outcome)
        for outcome in scoring_outcomes:
            _add(
                accumulators,
                BranchKind.CAMPAIGN,
                campaign_branch_id(
                    cell_id=outcome.planner_cell_id,
                    strategy=outcome.strategy,
                    dimension=outcome.dimension,
                ),
                outcome,
                outcome.reward_basis_points,
            )
            reward = outcome.reward_basis_points
            # Policy v1 keeps ancestry statistics as replayable diagnostics for
            # future node scheduling. Campaign ordering intentionally consumes
            # only the matching cell/strategy/dimension statistics below.
            for hypothesis in outcome.hypothesis_path:
                _add(accumulators, BranchKind.HYPOTHESIS, hypothesis, outcome, reward)
                reward = _signed_div(reward * 3, 4)

        stats = tuple(
            accumulator.freeze(kind, branch_id)
            for (kind, branch_id), accumulator in sorted(
                accumulators.items(), key=lambda item: (item[0][0].value, item[0][1])
            )
        )
        canonical = {
            "planner_feedback_schema_version": PLANNER_FEEDBACK_SCHEMA_VERSION,
            "branch_search_policy_version": BRANCH_SEARCH_POLICY_VERSION,
            "ignored_legacy_attempts": ignored,
            "ignored_unattributed_attempts": ignored_unattributed,
            "outcomes": [
                item.to_json() for item in sorted(outcomes, key=lambda item: item.outcome_id)
            ],
        }
        return cls(
            source_digest="branch-outcomes:" + _digest(canonical),
            outcome_ids=tuple(sorted(identities)),
            ignored_legacy_attempts=ignored,
            ignored_unattributed_attempts=ignored_unattributed,
            cell_visits=tuple(
                sorted(Counter(item.planner_cell_id for item in scoring_outcomes).items())
            ),
            cell_heads=tuple(
                (
                    cell_id,
                    max(
                        cell_outcomes,
                        key=lambda item: (
                            item.planner_attempt_count_after,
                            item.outcome_id,
                        ),
                    ).outcome_id,
                )
                for cell_id, cell_outcomes in sorted(cell_accumulators.items())
            ),
            cells=tuple(
                _freeze_cell(cell_id, cell_outcomes)
                for cell_id, cell_outcomes in sorted(cell_accumulators.items())
            ),
            campaigns=tuple(item for item in stats if item.kind is BranchKind.CAMPAIGN),
            hypotheses=tuple(item for item in stats if item.kind is BranchKind.HYPOTHESIS),
        )

    def campaign_stats(self, *, cell_id: str, strategy: str, dimension: str) -> BranchStats:
        branch_id = campaign_branch_id(cell_id=cell_id, strategy=strategy, dimension=dimension)
        return next(
            (item for item in self.campaigns if item.branch_id == branch_id),
            BranchStats(branch_id=branch_id, kind=BranchKind.CAMPAIGN),
        )

    def hypothesis_stats(self, fingerprint: str) -> BranchStats:
        branch_id = _text(fingerprint, "hypothesis fingerprint")
        return next(
            (item for item in self.hypotheses if item.branch_id == branch_id),
            BranchStats(branch_id=branch_id, kind=BranchKind.HYPOTHESIS),
        )

    def cell_stats(self, cell_id: str) -> PlannerCellStats:
        normalized = _text(cell_id, "planner cell ID")
        return next(
            (item for item in self.cells if item.cell_id == normalized),
            PlannerCellStats(cell_id=normalized),
        )

    def cell_head_digest(self, cell_id: str) -> str:
        normalized = _text(cell_id, "planner cell ID")
        return dict(self.cell_heads).get(normalized, "")

    def score(  # noqa: PLR0913
        self,
        *,
        cell_id: str,
        strategy: str,
        dimension: str,
        proof_proximity: int,
        attempts_used: int,
        max_attempts: int,
    ) -> BranchScoreAdjustment:
        proximity = _bounded(proof_proximity, "proof proximity", 0, 100)
        used = _non_negative(attempts_used, "attempts used")
        maximum = _positive(max_attempts, "max attempts")
        if used > maximum:
            raise BranchSearchError("attempts used cannot exceed max attempts")
        stats = self.campaign_stats(cell_id=cell_id, strategy=strategy, dimension=dimension)
        cell_visit_count = dict(self.cell_visits).get(cell_id, 0)
        pressure = used * _MAX_BP // maximum
        if cell_visit_count == 0:
            return BranchScoreAdjustment(
                branch_id=stats.branch_id,
                source_digest=self.source_digest,
                total_adjustment=0,
                raw_adjustment=0,
                empirical_value=0,
                exploration_bonus=0,
                difficulty_penalty=0,
                request_cost_penalty=0,
                horizon_value=0,
                proof_proximity=proximity,
                attempts_used=used,
                max_attempts=maximum,
                attempt_pressure_basis_points=pressure,
                cold_start=True,
                capped=False,
                stats=stats,
            )
        empirical = _signed_div(stats.mean_reward_basis_points, 100)
        exploration = _exploration(cell_visit_count, stats.visits)
        difficulty = (
            stats.failure_basis_points * 40 // _MAX_BP + stats.repeated_basis_points * 10 // _MAX_BP
        )
        request_cost = (min(stats.average_target_requests, _MAX_CHARGED_REQUESTS) + 3) // 4
        horizon = proximity * pressure // _MAX_BP // 2
        raw = empirical + exploration + horizon - difficulty - request_cost
        total = max(-_MAX_ADJUSTMENT, min(raw, _MAX_ADJUSTMENT))
        return BranchScoreAdjustment(
            branch_id=stats.branch_id,
            source_digest=self.source_digest,
            total_adjustment=total,
            raw_adjustment=raw,
            empirical_value=empirical,
            exploration_bonus=exploration,
            difficulty_penalty=difficulty,
            request_cost_penalty=request_cost,
            horizon_value=horizon,
            proof_proximity=proximity,
            attempts_used=used,
            max_attempts=maximum,
            attempt_pressure_basis_points=pressure,
            cold_start=False,
            capped=raw != total,
            stats=stats,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "planner_feedback_schema_version": PLANNER_FEEDBACK_SCHEMA_VERSION,
            "branch_search_policy_version": BRANCH_SEARCH_POLICY_VERSION,
            "source_digest": self.source_digest,
            "outcome_count": len(self.outcome_ids),
            "outcome_ids": list(self.outcome_ids),
            "ignored_legacy_attempts": self.ignored_legacy_attempts,
            "ignored_unattributed_attempts": self.ignored_unattributed_attempts,
            "cell_visits": [
                {"cell_id": cell_id, "visits": visits} for cell_id, visits in self.cell_visits
            ],
            "cell_heads": [
                {"cell_id": cell_id, "feedback_digest": digest}
                for cell_id, digest in self.cell_heads
            ],
            "cells": [item.to_json() for item in self.cells],
            "campaigns": [item.to_json() for item in self.campaigns],
            "hypotheses": [item.to_json() for item in self.hypotheses],
        }


def campaign_branch_id(*, cell_id: str, strategy: str, dimension: str) -> str:
    value = {
        "cell_id": _text(cell_id, "cell ID"),
        "strategy": _token(strategy, "strategy"),
        "dimension": _token(dimension, "dimension"),
    }
    return f"campaign:{_digest(value)[:24]}"


@dataclass(frozen=True)
class _Outcome:
    outcome_id: str
    reservation_id: str
    execution_cell_id: str
    planner_cell_id: str
    strategy: str
    dimension: str
    outcome_class: BranchOutcomeClass
    outcome_text: str
    stage_before: str
    stage_after: str
    repeated: bool
    evidence_changed: bool
    planner_attempt_count_before: int
    planner_attempt_count_after: int
    planner_evidence_version_before: int
    planner_evidence_version_after: int
    planner_evidence_refs_before: tuple[str, ...]
    planner_evidence_refs_after: tuple[str, ...]
    planner_no_progress_streak_before: int
    planner_no_progress_streak_after: int
    planner_target_requests_before: int
    planner_target_requests_after: int
    previous_feedback_digest: str
    target_requests: int
    evidence_refs: tuple[str, ...]
    hypothesis_path: tuple[str, ...]
    reward_basis_points: int

    def to_json(self) -> dict[str, object]:
        return {
            "outcome_id": self.outcome_id,
            "reservation_id": self.reservation_id,
            "execution_cell_id": self.execution_cell_id,
            "planner_cell_id": self.planner_cell_id,
            "strategy": self.strategy,
            "dimension": self.dimension,
            "outcome_class": self.outcome_class.value,
            "outcome_text": self.outcome_text,
            "stage_before": self.stage_before,
            "stage_after": self.stage_after,
            "repeated": self.repeated,
            "evidence_changed": self.evidence_changed,
            "planner_attempt_count_before": self.planner_attempt_count_before,
            "planner_attempt_count_after": self.planner_attempt_count_after,
            "planner_evidence_version_before": self.planner_evidence_version_before,
            "planner_evidence_version_after": self.planner_evidence_version_after,
            "planner_evidence_refs_before": list(self.planner_evidence_refs_before),
            "planner_evidence_refs_after": list(self.planner_evidence_refs_after),
            "planner_no_progress_streak_before": self.planner_no_progress_streak_before,
            "planner_no_progress_streak_after": self.planner_no_progress_streak_after,
            "planner_target_requests_before": self.planner_target_requests_before,
            "planner_target_requests_after": self.planner_target_requests_after,
            "previous_feedback_digest": self.previous_feedback_digest,
            "target_requests": self.target_requests,
            "evidence_refs": list(self.evidence_refs),
            "hypothesis_path": list(self.hypothesis_path),
            "reward_basis_points": self.reward_basis_points,
        }


@dataclass
class _Accumulator:
    visits: int = 0
    rewards: int = 0
    proof: int = 0
    progress: int = 0
    disproof: int = 0
    no_progress: int = 0
    repeated: int = 0
    requests: int = 0

    def add(self, outcome: _Outcome, reward: int) -> None:
        self.visits += 1
        self.rewards += reward
        self.proof += int(outcome.outcome_class is BranchOutcomeClass.PROOF)
        self.progress += int(
            outcome.outcome_class
            in {
                BranchOutcomeClass.SUPPORT,
                BranchOutcomeClass.CONFIRM,
                BranchOutcomeClass.PIVOT,
                BranchOutcomeClass.PROOF,
            }
        )
        self.disproof += int(outcome.outcome_class is BranchOutcomeClass.DISPROVE)
        self.no_progress += int(outcome.outcome_class is BranchOutcomeClass.EMPTY)
        self.repeated += int(outcome.repeated)
        self.requests += outcome.target_requests

    def freeze(self, kind: BranchKind, branch_id: str) -> BranchStats:
        return BranchStats(
            branch_id=branch_id,
            kind=kind,
            visits=self.visits,
            reward_sum_basis_points=self.rewards,
            proof_count=self.proof,
            progress_count=self.progress,
            disproof_count=self.disproof,
            no_progress_count=self.no_progress,
            repeated_count=self.repeated,
            target_requests=self.requests,
        )


def _freeze_cell(cell_id: str, outcomes: Sequence[_Outcome]) -> PlannerCellStats:
    ordered = sorted(
        outcomes,
        key=lambda item: (item.planner_attempt_count_after, item.outcome_id),
    )
    first = ordered[0]
    if (
        first.previous_feedback_digest
        or first.planner_attempt_count_before != 0
        or first.planner_evidence_version_before != 0
        or first.planner_no_progress_streak_before != 0
        or first.planner_target_requests_before != 0
        or first.planner_evidence_refs_before
    ):
        raise BranchSearchError("planner feedback cell root is not canonical")
    attempt_count = first.planner_attempt_count_before
    evidence_version = first.planner_evidence_version_before
    no_progress_streak = first.planner_no_progress_streak_before
    stage = first.stage_before
    target_requests = first.planner_target_requests_before
    attempted_dimensions: dict[str, int] = {}
    last_dimension = ""
    last_outcome = ""
    previous_feedback_digest = ""
    evidence_refs = set(first.planner_evidence_refs_before)
    for outcome in ordered:
        if (
            outcome.planner_attempt_count_before != attempt_count
            or outcome.planner_evidence_version_before != evidence_version
            or outcome.planner_no_progress_streak_before != no_progress_streak
            or outcome.planner_target_requests_before != target_requests
            or outcome.stage_before != stage
            or outcome.previous_feedback_digest != previous_feedback_digest
            or set(outcome.planner_evidence_refs_before) != evidence_refs
        ):
            raise BranchSearchError("planner feedback cell transition chain is invalid")
        attempt_count = outcome.planner_attempt_count_after
        evidence_version = outcome.planner_evidence_version_after
        no_progress_streak = outcome.planner_no_progress_streak_after
        stage = outcome.stage_after
        target_requests = outcome.planner_target_requests_after
        key = f"{outcome.strategy}:{outcome.dimension}"
        attempted_dimensions[key] = (
            evidence_version
            if (
                outcome.outcome_class
                in {
                    BranchOutcomeClass.DISPROVE,
                    BranchOutcomeClass.PIVOT,
                    BranchOutcomeClass.EMPTY,
                }
                or outcome.repeated
            )
            else outcome.planner_evidence_version_before
        )
        last_dimension = outcome.dimension
        last_outcome = outcome.outcome_text
        previous_feedback_digest = outcome.outcome_id
        evidence_refs = set(outcome.planner_evidence_refs_after)
    return PlannerCellStats(
        cell_id=cell_id,
        attempt_count=attempt_count,
        evidence_version=evidence_version,
        no_progress_streak=no_progress_streak,
        target_requests=target_requests,
        stage=stage,
        root_stage=first.stage_before,
        attempted_dimensions=tuple(sorted(attempted_dimensions.items())),
        evidence_refs=tuple(sorted(evidence_refs)),
        last_dimension=last_dimension,
        last_outcome=last_outcome,
    )


def seal_planner_feedback_attempt(attempt: Mapping[str, object]) -> dict[str, object]:
    """Return one canonical, self-checking planner feedback receipt."""
    payload = dict(attempt)
    if "planner_feedback_digest" in payload:
        raise BranchSearchError("planner feedback digest must be generated by the ledger")
    payload["planner_feedback_schema_version"] = PLANNER_FEEDBACK_SCHEMA_VERSION
    payload["planner_feedback_digest"] = "planner-feedback:" + _feedback_digest(payload)
    validate_planner_feedback_attempt(payload)
    return payload


def validate_planner_feedback_attempt(  # noqa: C901, PLR0912, PLR0915 - strict schema boundary.
    attempt: Mapping[str, object],
) -> None:
    """Validate the complete policy-input receipt before it can affect ranking."""
    if _encoded_size(attempt, "planner feedback") > _MAX_FEEDBACK_BYTES:
        raise BranchSearchError("planner feedback exceeds its byte limit")
    fields = frozenset(attempt)
    if fields != _FEEDBACK_FIELDS:
        missing = ",".join(sorted(_FEEDBACK_FIELDS - fields))
        extra = ",".join(sorted(fields - _FEEDBACK_FIELDS))
        raise BranchSearchError(
            f"planner feedback fields do not match schema; missing={missing}; extra={extra}"
        )
    version = attempt["planner_feedback_schema_version"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != PLANNER_FEEDBACK_SCHEMA_VERSION
    ):
        raise BranchSearchError(f"unsupported planner feedback schema version: {version}")

    for field in ("reservation_id", "node_id", "cell_id", "planner_cell_id"):
        value = attempt[field]
        if (
            not isinstance(value, str)
            or len(value) > _MAX_IDENTITY_LENGTH
            or value != _text(value, field.replace("_", " "))
        ):
            raise BranchSearchError(f"planner feedback {field} is not canonical")
    for field in ("strategy", "dimension"):
        value = attempt[field]
        if (
            not isinstance(value, str)
            or len(value) > _MAX_IDENTITY_LENGTH
            or value != _token(value, field)
        ):
            raise BranchSearchError(f"planner feedback {field} is not canonical")
    for field in (
        "agent_spec_fingerprint",
        "belief_disposition",
        "belief_revision_id",
        "executor_receipt_digest",
        "hypothesis_fingerprint",
        "outcome",
        "validated_batch_digest",
    ):
        value = attempt[field]
        if (
            not isinstance(value, str)
            or len(value) > _MAX_TEXT_LENGTH
            or value != " ".join(value.strip().split())
        ):
            raise BranchSearchError(f"planner feedback {field} is not canonical")
    previous_feedback_digest = attempt["planner_previous_feedback_digest"]
    if not isinstance(previous_feedback_digest, str) or (
        previous_feedback_digest
        and not _valid_prefixed_sha256(previous_feedback_digest, "planner-feedback:")
    ):
        raise BranchSearchError("planner previous feedback digest is invalid")

    stage_before = _stage(_required_string(attempt, "stage_before"))
    stage_after = _stage(_required_string(attempt, "stage"))
    evidence_before = _non_negative(attempt["evidence_version_before"], "evidence version before")
    evidence_after = _non_negative(attempt["evidence_version_after"], "evidence version after")
    reservation_version = _non_negative(
        attempt["reservation_evidence_version"],
        "reservation evidence version",
    )
    if reservation_version > evidence_before:
        raise BranchSearchError("reservation evidence version exceeds attempt start version")
    target_requests = _non_negative(attempt["target_requests"], "target requests")

    material_progress = _required_bool(attempt, "material_progress")
    evidence_changed = _required_bool(attempt, "evidence_changed")
    repeated = _required_bool(attempt, "repeated_observation")
    _required_bool(attempt, "planner_attributed")
    planner_state_attributed = _required_bool(attempt, "planner_state_attributed")
    if attempt["planner_attributed"] is True and not planner_state_attributed:
        raise BranchSearchError("planner reward attribution requires state attribution")
    progress_kinds = _canonical_string_list(attempt, "progress_kinds")
    evidence_refs = _canonical_string_list(attempt, "evidence_refs")
    planner_evidence_refs_before = _canonical_string_list(
        attempt,
        "planner_evidence_refs_before",
    )
    planner_evidence_refs_after = _canonical_string_list(
        attempt,
        "planner_evidence_refs_after",
    )
    unknown_kinds = set(progress_kinds) - _PROGRESS_KINDS
    if unknown_kinds:
        raise BranchSearchError("planner feedback contains an unsupported progress kind")
    expected_progress = bool(progress_kinds)
    if material_progress is not expected_progress or evidence_changed is not expected_progress:
        raise BranchSearchError("planner feedback progress booleans disagree with typed progress")
    expected_evidence_after = evidence_before + int(evidence_changed)
    if evidence_after != expected_evidence_after:
        raise BranchSearchError("planner feedback evidence version transition is invalid")

    expected_class = _feedback_progress_class(progress_kinds)
    progress_class = _required_string(attempt, "progress_class")
    if progress_class != expected_class.value:
        raise BranchSearchError("planner feedback class disagrees with typed progress")
    expected_stage = _feedback_stage_after(stage_before, progress_kinds)
    if stage_after != expected_stage:
        raise BranchSearchError("planner feedback stage transition is invalid")
    planner_attempt_before = _non_negative(
        attempt["planner_attempt_count_before"],
        "planner attempt count before",
    )
    planner_attempt_after = _non_negative(
        attempt["planner_attempt_count_after"],
        "planner attempt count after",
    )
    if planner_attempt_after != planner_attempt_before + 1:
        raise BranchSearchError("planner attempt-count transition is invalid")
    if planner_attempt_after > MAX_PLANNER_ATTEMPTS_PER_CELL:
        raise BranchSearchError("planner attempt count exceeds per-cell policy bound")
    planner_evidence_before = _non_negative(
        attempt["planner_evidence_version_before"],
        "planner evidence version before",
    )
    planner_evidence_after = _non_negative(
        attempt["planner_evidence_version_after"],
        "planner evidence version after",
    )
    if planner_evidence_after != planner_evidence_before + int(evidence_changed):
        raise BranchSearchError("planner evidence-version transition is invalid")
    if planner_evidence_before > planner_attempt_before:
        raise BranchSearchError("planner evidence version exceeds attempt count")
    expected_planner_refs_after = tuple(
        sorted(set(planner_evidence_refs_before).union(evidence_refs))
    )
    if planner_evidence_refs_after != expected_planner_refs_after:
        raise BranchSearchError("planner evidence-reference transition is invalid")
    if progress_kinds and not evidence_refs:
        raise BranchSearchError("typed planner progress requires executor evidence references")
    if evidence_changed and not set(evidence_refs) - set(planner_evidence_refs_before):
        raise BranchSearchError("planner feedback reuses known evidence")
    planner_streak_before = _non_negative(
        attempt["planner_no_progress_streak_before"],
        "planner no-progress streak before",
    )
    planner_streak_after = _non_negative(
        attempt["planner_no_progress_streak_after"],
        "planner no-progress streak after",
    )
    expected_streak_after = 0 if material_progress else planner_streak_before + 1
    if planner_streak_after != expected_streak_after:
        raise BranchSearchError("planner no-progress transition is invalid")
    if planner_streak_before > planner_attempt_before:
        raise BranchSearchError("planner no-progress streak exceeds attempt count")
    planner_requests_before = _non_negative(
        attempt["planner_target_requests_before"],
        "planner target requests before",
    )
    planner_requests_after = _non_negative(
        attempt["planner_target_requests_after"],
        "planner target requests after",
    )
    if planner_requests_after != planner_requests_before + target_requests:
        raise BranchSearchError("planner target-request transition is invalid")
    if (
        target_requests > _MAX_CHARGED_REQUESTS
        or planner_requests_before > _MAX_CHARGED_REQUESTS
        or planner_requests_after > _MAX_CHARGED_REQUESTS
    ):
        raise BranchSearchError("planner target requests exceed route bound")
    planner_stage_before = _stage(_required_string(attempt, "planner_stage_before"))
    planner_stage_after = _stage(_required_string(attempt, "planner_stage_after"))
    expected_planner_stage = _feedback_stage_after(planner_stage_before, progress_kinds)
    if planner_stage_after != expected_planner_stage:
        raise BranchSearchError("planner stage transition is invalid")
    if planner_stage_before == "proof":
        raise BranchSearchError("planner feedback cannot start from a proof-complete cell")
    expected_outcome = _feedback_outcome(progress_kinds, repeated=repeated)
    if attempt["outcome"] != expected_outcome:
        raise BranchSearchError("planner feedback outcome disagrees with typed progress")

    batch_digest = str(attempt["validated_batch_digest"])
    if batch_digest and not _valid_prefixed_sha256(batch_digest, "progress-batch:"):
        raise BranchSearchError("planner feedback progress batch digest is invalid")
    if progress_kinds and not batch_digest:
        raise BranchSearchError("typed planner progress requires a validated batch digest")
    hypothesis_path = _canonical_identity_path(attempt, "hypothesis_path")
    hypothesis = str(attempt["hypothesis_fingerprint"])
    if hypothesis and (not hypothesis_path or hypothesis_path[0] != hypothesis):
        raise BranchSearchError("hypothesis path does not start at the attempt hypothesis")

    digest = attempt["planner_feedback_digest"]
    if not isinstance(digest, str) or not _valid_prefixed_sha256(digest, "planner-feedback:"):
        raise BranchSearchError("planner feedback digest is invalid")
    if digest != "planner-feedback:" + _feedback_digest(attempt):
        raise BranchSearchError("planner feedback digest does not match its canonical fields")


def _normalize(attempt: Mapping[str, object]) -> _Outcome:
    outcome_text = " ".join(str(attempt.get("outcome") or "").strip().split())
    outcome_class = _classify(attempt, outcome_text)
    stage_after = _stage(str(attempt.get("planner_stage_after") or "observed"))
    stage_before = _stage(str(attempt.get("planner_stage_before") or stage_after))
    repeated = (
        outcome_text == "repeated_observation"
        or attempt.get("repeated") is True
        or attempt.get("repeated_observation") is True
    )
    return _Outcome(
        outcome_id=_outcome_id(attempt),
        reservation_id=_required_string(attempt, "reservation_id"),
        execution_cell_id=_text(str(attempt.get("cell_id") or ""), "cell ID"),
        planner_cell_id=_text(
            str(attempt.get("planner_cell_id") or ""),
            "planner cell ID",
        ),
        strategy=_token(str(attempt.get("strategy") or ""), "strategy"),
        dimension=_token(str(attempt.get("dimension") or ""), "dimension"),
        outcome_class=outcome_class,
        outcome_text=outcome_text,
        stage_before=stage_before,
        stage_after=stage_after,
        repeated=repeated,
        evidence_changed=attempt.get("evidence_changed") is True,
        planner_attempt_count_before=_non_negative(
            attempt.get("planner_attempt_count_before"),
            "planner attempt count before",
        ),
        planner_attempt_count_after=_non_negative(
            attempt.get("planner_attempt_count_after"),
            "planner attempt count after",
        ),
        planner_evidence_version_before=_non_negative(
            attempt.get("planner_evidence_version_before"),
            "planner evidence version before",
        ),
        planner_evidence_version_after=_non_negative(
            attempt.get("planner_evidence_version_after"),
            "planner evidence version after",
        ),
        planner_evidence_refs_before=tuple(
            str(item) for item in attempt.get("planner_evidence_refs_before", ())
        ),
        planner_evidence_refs_after=tuple(
            str(item) for item in attempt.get("planner_evidence_refs_after", ())
        ),
        planner_no_progress_streak_before=_non_negative(
            attempt.get("planner_no_progress_streak_before"),
            "planner no-progress streak before",
        ),
        planner_no_progress_streak_after=_non_negative(
            attempt.get("planner_no_progress_streak_after"),
            "planner no-progress streak after",
        ),
        planner_target_requests_before=_non_negative(
            attempt.get("planner_target_requests_before"),
            "planner target requests before",
        ),
        planner_target_requests_after=_non_negative(
            attempt.get("planner_target_requests_after"),
            "planner target requests after",
        ),
        previous_feedback_digest=str(attempt.get("planner_previous_feedback_digest") or ""),
        target_requests=_non_negative(attempt.get("target_requests", 0), "target requests"),
        evidence_refs=tuple(str(item) for item in attempt.get("evidence_refs", ())),
        hypothesis_path=_hypothesis_path(attempt),
        reward_basis_points=_reward(
            outcome_class,
            outcome_text,
            stage_before,
            stage_after,
            repeated=repeated,
        ),
    )


def _outcome_id(attempt: Mapping[str, object]) -> str:
    return _required_string(attempt, "planner_feedback_digest")


def _classify(attempt: Mapping[str, object], outcome: str) -> BranchOutcomeClass:
    explicit = str(attempt.get("progress_class") or "").strip().lower()
    if explicit:
        try:
            return BranchOutcomeClass(explicit)
        except ValueError as exc:
            raise BranchSearchError(f"unknown progress class: {explicit}") from exc
    if outcome == "proof_confirmed" or attempt.get("stage") == "proof":
        return BranchOutcomeClass.PROOF
    if "hypothesis_disproved" in outcome:
        return BranchOutcomeClass.DISPROVE
    if "hypothesis_confirmed" in outcome:
        return BranchOutcomeClass.CONFIRM
    if outcome.startswith("typed_progress:") or attempt.get("material_progress") is True:
        return BranchOutcomeClass.SUPPORT
    return BranchOutcomeClass.EMPTY


def _hypothesis_path(attempt: Mapping[str, object]) -> tuple[str, ...]:
    leaf = " ".join(str(attempt.get("hypothesis_fingerprint") or "").strip().split())
    raw = attempt.get("hypothesis_path")
    if raw is None:
        return (leaf,) if leaf else ()
    if not isinstance(raw, (list, tuple)):
        raise BranchSearchError("hypothesis path must be a list")
    path = tuple(" ".join(str(item).strip().split()) for item in raw)
    if (
        len(path) > _MAX_HYPOTHESIS_PATH
        or any(not item or len(item) > _MAX_IDENTITY_LENGTH for item in path)
        or len(set(path)) != len(path)
    ):
        raise BranchSearchError("hypothesis path is empty or cyclic")
    if leaf and (not path or path[0] != leaf):
        raise BranchSearchError("hypothesis path does not start at the attempt hypothesis")
    return path


def _feedback_progress_class(progress_kinds: Sequence[str]) -> BranchOutcomeClass:
    kinds = set(progress_kinds)
    if not kinds:
        return BranchOutcomeClass.EMPTY
    if "proof_confirmed" in kinds:
        if "hypothesis_disproved" in kinds:
            raise BranchSearchError("proof and disproof cannot share planner feedback")
        return BranchOutcomeClass.PROOF
    if "hypothesis_disproved" in kinds:
        if "hypothesis_confirmed" in kinds:
            raise BranchSearchError("confirmation and disproof cannot share planner feedback")
        return BranchOutcomeClass.PIVOT if len(kinds) > 1 else BranchOutcomeClass.DISPROVE
    if "hypothesis_confirmed" in kinds:
        return BranchOutcomeClass.CONFIRM
    return BranchOutcomeClass.SUPPORT


def _feedback_stage_after(stage_before: str, progress_kinds: Sequence[str]) -> str:
    stages = [stage_before]
    stages.extend(_PROGRESS_STAGE[kind] for kind in progress_kinds if kind in _PROGRESS_STAGE)
    return max(stages, key=_STAGE_RANK.__getitem__)


def _feedback_outcome(progress_kinds: Sequence[str], *, repeated: bool) -> str:
    if "proof_confirmed" in progress_kinds:
        return "proof_confirmed"
    if "hypothesis_disproved" in progress_kinds:
        return "hypothesis_disproved"
    if progress_kinds:
        return "typed_progress:" + ",".join(progress_kinds)
    return "repeated_observation" if repeated else "no_typed_progress"


def _required_string(attempt: Mapping[str, object], field: str) -> str:
    value = attempt[field]
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT_LENGTH:
        raise BranchSearchError(f"planner feedback {field} must be a non-empty string")
    return value


def _required_bool(attempt: Mapping[str, object], field: str) -> bool:
    value = attempt[field]
    if not isinstance(value, bool):
        raise BranchSearchError(f"planner feedback {field} must be a boolean")
    return value


def _canonical_string_list(
    attempt: Mapping[str, object],
    field: str,
) -> tuple[str, ...]:
    raw = attempt[field]
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise BranchSearchError(f"planner feedback {field} must be a string list")
    canonical = tuple(sorted({" ".join(item.strip().split()) for item in raw if item.strip()}))
    maximum = len(_PROGRESS_KINDS) if field == "progress_kinds" else _MAX_EVIDENCE_REFS
    if len(canonical) > maximum or any(len(item) > _MAX_TEXT_LENGTH for item in canonical):
        raise BranchSearchError(f"planner feedback {field} exceeds its bound")
    if list(canonical) != raw:
        raise BranchSearchError(f"planner feedback {field} is not canonical")
    return canonical


def _canonical_identity_path(
    attempt: Mapping[str, object],
    field: str,
) -> tuple[str, ...]:
    raw = attempt[field]
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise BranchSearchError(f"planner feedback {field} must be a string list")
    canonical = tuple(" ".join(item.strip().split()) for item in raw)
    if (
        len(canonical) > _MAX_HYPOTHESIS_PATH
        or any(not item or len(item) > _MAX_IDENTITY_LENGTH for item in canonical)
        or len(set(canonical)) != len(canonical)
    ):
        raise BranchSearchError(f"planner feedback {field} is empty or cyclic")
    if list(canonical) != raw:
        raise BranchSearchError(f"planner feedback {field} is not canonical")
    return canonical


def _valid_prefixed_sha256(value: str, prefix: str) -> bool:
    if not value.startswith(prefix):
        return False
    hexadecimal = value[len(prefix) :]
    return len(hexadecimal) == _SHA256_HEX_LENGTH and all(
        character in "0123456789abcdef" for character in hexadecimal
    )


def _feedback_digest(attempt: Mapping[str, object]) -> str:
    return _digest(
        {key: value for key, value in attempt.items() if key != "planner_feedback_digest"}
    )


def _reward(
    outcome_class: BranchOutcomeClass,
    outcome: str,
    stage_before: str,
    stage_after: str,
    *,
    repeated: bool,
) -> int:
    value = {
        BranchOutcomeClass.EMPTY: -2_500,
        BranchOutcomeClass.SUPPORT: 4_000,
        BranchOutcomeClass.CONFIRM: 6_500,
        BranchOutcomeClass.DISPROVE: 1_000,
        BranchOutcomeClass.PIVOT: 1_500,
        BranchOutcomeClass.PROOF: 10_000,
    }[outcome_class]
    if outcome_class is BranchOutcomeClass.SUPPORT and any(
        marker in outcome
        for marker in ("primitive_confirmed", "auth_state_changed", "extraction_checkpoint")
    ):
        value = 7_000
    value += max(_STAGE_RANK[stage_after] - _STAGE_RANK[stage_before], 0) * 500
    value -= 1_500 if repeated else 0
    return max(-5_000, min(value, _MAX_BP))


def _add(
    values: dict[tuple[BranchKind, str], _Accumulator],
    kind: BranchKind,
    branch_id: str,
    outcome: _Outcome,
    reward: int,
) -> None:
    values.setdefault((kind, branch_id), _Accumulator()).add(outcome, reward)


def _exploration(total_visits: int, branch_visits: int) -> int:
    if total_visits == 0:
        return 0
    if branch_visits == 0:
        return 30
    log_visits = max((total_visits + 1).bit_length() - 1, 1)
    return min(math.isqrt(log_visits * _MAX_BP // branch_visits) // 4, 30)


def _stage(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in _STAGE_RANK:
        raise BranchSearchError(f"invalid coverage stage: {value}")
    return normalized


def _bounded(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise BranchSearchError(f"{label} must be between {minimum} and {maximum}")
    return value


def _non_negative(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BranchSearchError(f"{label} must be a non-negative integer")
    return value


def _positive(value: object, label: str) -> int:
    parsed = _non_negative(value, label)
    if parsed == 0:
        raise BranchSearchError(f"{label} must be greater than zero")
    return parsed


def _text(value: str, label: str) -> str:
    normalized = " ".join(value.strip().split())
    if not normalized or len(normalized) > _MAX_IDENTITY_LENGTH:
        raise BranchSearchError(f"{label} is required")
    return normalized


def _token(value: str, label: str) -> str:
    normalized = "_".join(value.strip().lower().replace("-", " ").split())
    if not normalized or len(normalized) > _MAX_IDENTITY_LENGTH:
        raise BranchSearchError(f"{label} is required")
    return normalized


def _signed_div(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _encoded_size(value: object, label: str) -> int:
    try:
        return len(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
    except (TypeError, ValueError) as exc:
        raise BranchSearchError(f"{label} is not canonical JSON") from exc


__all__ = [
    "BRANCH_SEARCH_POLICY_VERSION",
    "MAX_PLANNER_ATTEMPTS_PER_CELL",
    "MAX_PLANNER_OUTCOMES",
    "PLANNER_FEEDBACK_SCHEMA_VERSION",
    "BranchKind",
    "BranchOutcomeClass",
    "BranchOutcomeIndex",
    "BranchScoreAdjustment",
    "BranchSearchError",
    "BranchStats",
    "PlannerCellStats",
    "campaign_branch_id",
    "seal_planner_feedback_attempt",
    "validate_planner_feedback_attempt",
]
