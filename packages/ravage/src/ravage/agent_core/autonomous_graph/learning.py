# Graph learning is target-agnostic and cannot promote itself during a live run.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
import math
import os
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.beliefs import (
    BeliefLedgerError,
    BeliefLedgerState,
)
from ravage.agent_core.autonomous_graph.campaigns import ALL_CAMPAIGNS
from ravage.agent_core.autonomous_graph.capability_gaps import (
    CapabilityGapBacklog,
    CapabilityGapError,
    build_capability_gap_backlog,
)

if TYPE_CHECKING:
    from ravage.agent_core.frontier_route import FrontierObjective

_LEGACY_LESSON_VERSION = 1
_LESSON_VERSION = 2
_SUPPORTED_LESSON_VERSIONS = frozenset({_LEGACY_LESSON_VERSION, _LESSON_VERSION})
_POLICY_VERSION = 1
_MIN_POLICY_RUNS = 2
_MIN_REPLAY_CASES = 3
_MAX_SCORE_DELTA = 400
_MAX_EFFICIENCY_REGRESSION = 0.15
_SHA256_HEX_LENGTH = 64


class GraphLearningError(RuntimeError):
    """Raised when a learning artifact cannot preserve promotion invariants."""


@dataclass(frozen=True)
class RouteLesson:
    """One secret-free campaign outcome derived from executor-owned receipts."""

    lesson_id: str
    source_digest: str
    sequence: int
    family: str
    probe: str
    dimension: str
    outcome: str
    material_progress: bool
    proof_confirmed: bool
    loop_stopped: bool
    target_requests: int
    hypothesis_fingerprint: str = ""
    agent_spec_fingerprint: str = ""
    belief_revision_id: str = ""
    belief_disposition: str = ""
    executor_receipt_digest: str = ""
    schema_version: int = _LESSON_VERSION

    @classmethod
    def create(  # noqa: PLR0913 - immutable lesson identity is explicit.
        cls,
        *,
        source_digest: str,
        sequence: int,
        family: str,
        probe: str,
        dimension: str,
        outcome: str,
        material_progress: bool,
        proof_confirmed: bool,
        loop_stopped: bool,
        target_requests: int,
        hypothesis_fingerprint: str = "",
        agent_spec_fingerprint: str = "",
        belief_revision_id: str = "",
        belief_disposition: str = "",
        executor_receipt_digest: str = "",
    ) -> RouteLesson:
        if sequence < 0 or target_requests < 0:
            raise GraphLearningError("lesson counters must be non-negative")
        normalized_source_digest = _required_token(
            source_digest,
            "source digest",
        )
        normalized_family = _required_token(family, "family")
        normalized_probe = _required_token(probe, "probe")
        normalized_dimension = _required_token(dimension, "dimension")
        normalized_outcome = _required_text(outcome, "outcome")
        normalized_material_progress = bool(material_progress)
        normalized_proof_confirmed = bool(proof_confirmed)
        normalized_loop_stopped = bool(loop_stopped)
        base = {
            "source_digest": normalized_source_digest,
            "sequence": sequence,
            "family": normalized_family,
            "probe": normalized_probe,
            "dimension": normalized_dimension,
            "outcome": normalized_outcome,
            "material_progress": normalized_material_progress,
            "proof_confirmed": normalized_proof_confirmed,
            "loop_stopped": normalized_loop_stopped,
            "target_requests": target_requests,
        }
        verification = {
            "hypothesis_fingerprint": hypothesis_fingerprint.strip(),
            "agent_spec_fingerprint": agent_spec_fingerprint.strip(),
            "belief_revision_id": belief_revision_id.strip(),
            "belief_disposition": belief_disposition.strip(),
            "executor_receipt_digest": executor_receipt_digest.strip(),
        }
        populated = sum(bool(value) for value in verification.values())
        if populated not in {0, len(verification)}:
            raise GraphLearningError(
                "route-lesson verification identity must be complete or absent"
            )
        if populated:
            _validate_lesson_verification(verification)
        canonical = {**base, **verification}
        return cls(
            lesson_id=f"route-lesson:{_digest_json(canonical)[:24]}",
            source_digest=normalized_source_digest,
            sequence=sequence,
            family=normalized_family,
            probe=normalized_probe,
            dimension=normalized_dimension,
            outcome=normalized_outcome,
            material_progress=normalized_material_progress,
            proof_confirmed=normalized_proof_confirmed,
            loop_stopped=normalized_loop_stopped,
            target_requests=target_requests,
            hypothesis_fingerprint=verification["hypothesis_fingerprint"],
            agent_spec_fingerprint=verification["agent_spec_fingerprint"],
            belief_revision_id=verification["belief_revision_id"],
            belief_disposition=verification["belief_disposition"],
            executor_receipt_digest=verification["executor_receipt_digest"],
        )

    @property
    def executor_verified(self) -> bool:
        return all(
            (
                self.hypothesis_fingerprint,
                self.agent_spec_fingerprint,
                self.belief_revision_id,
                self.belief_disposition,
                self.executor_receipt_digest,
            )
        )

    @property
    def verified_material_progress(self) -> bool:
        return (
            self.executor_verified
            and self.material_progress
            and self.belief_disposition in {"supported", "confirmed"}
        )

    @property
    def verified_proof(self) -> bool:
        return (
            self.executor_verified
            and self.proof_confirmed
            and self.belief_disposition == "confirmed"
        )

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "version": self.schema_version,
            "lesson_id": self.lesson_id,
            "source_digest": self.source_digest,
            "sequence": self.sequence,
            "family": self.family,
            "probe": self.probe,
            "dimension": self.dimension,
            "outcome": self.outcome,
            "material_progress": self.material_progress,
            "proof_confirmed": self.proof_confirmed,
            "loop_stopped": self.loop_stopped,
            "target_requests": self.target_requests,
        }
        if self.schema_version >= _LESSON_VERSION:
            payload.update(
                {
                    "hypothesis_fingerprint": self.hypothesis_fingerprint,
                    "agent_spec_fingerprint": self.agent_spec_fingerprint,
                    "belief_revision_id": self.belief_revision_id,
                    "belief_disposition": self.belief_disposition,
                    "executor_receipt_digest": self.executor_receipt_digest,
                }
            )
        return payload

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RouteLesson:
        version = payload.get("version")
        if version not in _SUPPORTED_LESSON_VERSIONS:
            raise GraphLearningError("unsupported route-lesson version")
        source_digest = str(payload.get("source_digest") or "")
        sequence = _non_negative_int(payload.get("sequence"), "sequence")
        family = str(payload.get("family") or "")
        probe = str(payload.get("probe") or "")
        dimension = str(payload.get("dimension") or "")
        outcome = str(payload.get("outcome") or "")
        material_progress = payload.get("material_progress") is True
        proof_confirmed = payload.get("proof_confirmed") is True
        loop_stopped = payload.get("loop_stopped") is True
        target_requests = _non_negative_int(
            payload.get("target_requests"),
            "target requests",
        )
        if version == _LEGACY_LESSON_VERSION:
            normalized_source_digest = _required_token(
                source_digest,
                "source digest",
            )
            normalized_family = _required_token(family, "family")
            normalized_probe = _required_token(probe, "probe")
            normalized_dimension = _required_token(
                dimension,
                "dimension",
            )
            normalized_outcome = _required_text(outcome, "outcome")
            canonical = {
                "source_digest": normalized_source_digest,
                "sequence": sequence,
                "family": normalized_family,
                "probe": normalized_probe,
                "dimension": normalized_dimension,
                "outcome": normalized_outcome,
                "material_progress": material_progress,
                "proof_confirmed": proof_confirmed,
                "loop_stopped": loop_stopped,
                "target_requests": target_requests,
            }
            lesson = cls(
                lesson_id=f"route-lesson:{_digest_json(canonical)[:24]}",
                source_digest=normalized_source_digest,
                sequence=sequence,
                family=normalized_family,
                probe=normalized_probe,
                dimension=normalized_dimension,
                outcome=normalized_outcome,
                material_progress=material_progress,
                proof_confirmed=proof_confirmed,
                loop_stopped=loop_stopped,
                target_requests=target_requests,
                schema_version=_LEGACY_LESSON_VERSION,
            )
        else:
            lesson = cls.create(
                source_digest=source_digest,
                sequence=sequence,
                family=family,
                probe=probe,
                dimension=dimension,
                outcome=outcome,
                material_progress=material_progress,
                proof_confirmed=proof_confirmed,
                loop_stopped=loop_stopped,
                target_requests=target_requests,
                hypothesis_fingerprint=str(payload.get("hypothesis_fingerprint") or ""),
                agent_spec_fingerprint=str(payload.get("agent_spec_fingerprint") or ""),
                belief_revision_id=str(payload.get("belief_revision_id") or ""),
                belief_disposition=str(payload.get("belief_disposition") or ""),
                executor_receipt_digest=str(payload.get("executor_receipt_digest") or ""),
            )
        if str(payload.get("lesson_id") or "") != lesson.lesson_id:
            raise GraphLearningError("route-lesson ID mismatch")
        return lesson


class RouteLessonStore:
    """Append-only-by-identity corpus with atomic, idempotent persistence."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> tuple[RouteLesson, ...]:
        if not self.path.exists():
            return ()
        lessons: list[RouteLesson] = []
        seen: set[str] = set()
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise GraphLearningError(f"invalid route-lesson JSON: {exc}") from exc
            if not isinstance(raw, Mapping):
                raise GraphLearningError("route-lesson record must be an object")
            lesson = RouteLesson.from_json(raw)
            if lesson.lesson_id in seen:
                raise GraphLearningError("duplicate route-lesson identity")
            seen.add(lesson.lesson_id)
            lessons.append(lesson)
        return tuple(lessons)

    def append(self, lessons: Sequence[RouteLesson]) -> tuple[RouteLesson, ...]:
        existing = list(self.load())
        seen = {lesson.lesson_id for lesson in existing}
        added = [lesson for lesson in lessons if lesson.lesson_id not in seen]
        if not added:
            return ()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            for lesson in (*existing, *added):
                stream.write(json.dumps(lesson.to_json(), sort_keys=True) + "\n")
        temporary.replace(self.path)
        return tuple(added)


@dataclass(frozen=True)
class SeedPolicyAdjustment:
    family: str
    probe: str
    score_delta: int
    independent_runs: int
    progress_count: int
    proof_count: int
    failure_count: int
    loop_stop_count: int

    def to_json(self) -> dict[str, object]:
        return {
            "family": self.family,
            "probe": self.probe,
            "score_delta": self.score_delta,
            "independent_runs": self.independent_runs,
            "progress_count": self.progress_count,
            "proof_count": self.proof_count,
            "failure_count": self.failure_count,
            "loop_stop_count": self.loop_stop_count,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> SeedPolicyAdjustment:
        score_delta = _int(payload.get("score_delta"), "score delta")
        if abs(score_delta) > _MAX_SCORE_DELTA:
            raise GraphLearningError("seed-policy score delta exceeds the safety cap")
        return cls(
            family=_required_token(str(payload.get("family") or ""), "family"),
            probe=_required_token(str(payload.get("probe") or ""), "probe"),
            score_delta=score_delta,
            independent_runs=_non_negative_int(
                payload.get("independent_runs"),
                "independent runs",
            ),
            progress_count=_non_negative_int(
                payload.get("progress_count"),
                "progress count",
            ),
            proof_count=_non_negative_int(payload.get("proof_count"), "proof count"),
            failure_count=_non_negative_int(
                payload.get("failure_count"),
                "failure count",
            ),
            loop_stop_count=_non_negative_int(
                payload.get("loop_stop_count"),
                "loop-stop count",
            ),
        )


@dataclass(frozen=True)
class SeedLearningPolicy:
    policy_id: str
    status: str
    adjustments: tuple[SeedPolicyAdjustment, ...]
    replay_receipt_digest: str = ""

    def score_delta(self, objective: FrontierObjective) -> int:
        if self.status != "promoted":
            raise GraphLearningError("candidate seed policy cannot affect live route selection")
        return sum(
            adjustment.score_delta
            for adjustment in self.adjustments
            if adjustment.family == objective.family and adjustment.probe == objective.probe
        )

    def to_json(self) -> dict[str, object]:
        return {
            "version": _POLICY_VERSION,
            "policy_id": self.policy_id,
            "status": self.status,
            "adjustments": [item.to_json() for item in self.adjustments],
            "replay_receipt_digest": self.replay_receipt_digest,
        }

    @classmethod
    def create(
        cls,
        *,
        status: str,
        adjustments: Sequence[SeedPolicyAdjustment],
        replay_receipt_digest: str = "",
    ) -> SeedLearningPolicy:
        if status not in {"candidate", "promoted"}:
            raise GraphLearningError("seed policy status must be candidate or promoted")
        ordered = tuple(
            sorted(
                adjustments,
                key=lambda item: (item.family, item.probe),
            )
        )
        canonical = {
            "adjustments": [item.to_json() for item in ordered],
            "replay_receipt_digest": replay_receipt_digest,
        }
        return cls(
            policy_id=f"graph-seed-policy:{_digest_json(canonical)[:24]}",
            status=status,
            adjustments=ordered,
            replay_receipt_digest=replay_receipt_digest,
        )

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> SeedLearningPolicy:
        if payload.get("version") != _POLICY_VERSION:
            raise GraphLearningError("unsupported seed-learning policy version")
        raw_adjustments = payload.get("adjustments")
        if not isinstance(raw_adjustments, list):
            raise GraphLearningError("seed-learning adjustments must be a list")
        policy = cls.create(
            status=str(payload.get("status") or ""),
            adjustments=tuple(
                SeedPolicyAdjustment.from_json(item)
                for item in raw_adjustments
                if isinstance(item, Mapping)
            ),
            replay_receipt_digest=str(payload.get("replay_receipt_digest") or ""),
        )
        if len(policy.adjustments) != len(raw_adjustments):
            raise GraphLearningError("seed-learning adjustment must be an object")
        if str(payload.get("policy_id") or "") != policy.policy_id:
            raise GraphLearningError("seed-learning policy ID mismatch")
        return policy

    @classmethod
    def load(cls, path: Path) -> SeedLearningPolicy:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GraphLearningError(f"cannot read seed-learning policy: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise GraphLearningError("seed-learning policy must be an object")
        return cls.from_json(raw)

    @classmethod
    def load_promoted(cls, path: Path) -> SeedLearningPolicy:
        policy = cls.load(path)
        if policy.status != "promoted":
            raise GraphLearningError("only a promoted seed policy may affect a run")
        if not policy.replay_receipt_digest:
            raise GraphLearningError("promoted seed policy requires a replay receipt")
        return policy

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


@dataclass(frozen=True)
class ReplayMetrics:
    cases: int
    solved: int
    false_proofs: int
    loop_violations: int
    unmatched_model_attempts: int
    cost_usd: float
    model_requests: int

    def __post_init__(self) -> None:
        integer_values = (
            self.cases,
            self.solved,
            self.false_proofs,
            self.loop_violations,
            self.unmatched_model_attempts,
            self.model_requests,
        )
        if any(value < 0 for value in integer_values):
            raise GraphLearningError("replay metrics cannot be negative")
        if self.solved > self.cases:
            raise GraphLearningError("replay solves cannot exceed replay cases")
        if not math.isfinite(self.cost_usd) or self.cost_usd < 0:
            raise GraphLearningError("replay cost must be finite and non-negative")

    def to_json(self) -> dict[str, object]:
        return {
            "cases": self.cases,
            "solved": self.solved,
            "false_proofs": self.false_proofs,
            "loop_violations": self.loop_violations,
            "unmatched_model_attempts": self.unmatched_model_attempts,
            "cost_usd": self.cost_usd,
            "model_requests": self.model_requests,
        }


@dataclass(frozen=True)
class PolicyPromotionDecision:
    accepted: bool
    reasons: tuple[str, ...]
    receipt_digest: str

    def to_json(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "reasons": list(self.reasons),
            "receipt_digest": self.receipt_digest,
        }


def extract_route_lessons(workspace_dir: Path) -> tuple[RouteLesson, ...]:
    """Derive generic lessons from graph-owned coverage and failure receipts."""
    coverage_path = workspace_dir / "investigation-coverage.json"
    failures_path = workspace_dir / "investigation-failures.json"
    beliefs_path = workspace_dir / "investigation-beliefs.json"
    if not coverage_path.exists():
        return ()
    coverage = _read_mapping(coverage_path, label="investigation coverage")
    failures = (
        _read_mapping(failures_path, label="investigation failures")
        if failures_path.exists()
        else {}
    )
    raw_beliefs = (
        _read_mapping(beliefs_path, label="investigation beliefs") if beliefs_path.exists() else {}
    )
    try:
        beliefs = BeliefLedgerState.from_json(raw_beliefs) if raw_beliefs else None
    except BeliefLedgerError as exc:
        raise GraphLearningError(f"cannot validate investigation beliefs: {exc}") from exc
    raw_attempts = coverage.get("attempts")
    raw_cells = coverage.get("cells")
    if not isinstance(raw_attempts, list) or not isinstance(raw_cells, Mapping):
        raise GraphLearningError("coverage lessons require attempts and cells")
    source_digest = _source_digest(coverage, failures, raw_beliefs)
    failure_routes = _failure_routes(failures)
    campaigns_by_strategy = {
        _required_token(campaign.name, "campaign name"): campaign for campaign in ALL_CAMPAIGNS
    }
    known_families = {family for campaign in ALL_CAMPAIGNS for family in campaign.families}
    lessons: list[RouteLesson] = []
    for sequence, raw_attempt in enumerate(raw_attempts):
        if not isinstance(raw_attempt, Mapping):
            raise GraphLearningError("coverage attempt must be an object")
        cell_id = str(raw_attempt.get("cell_id") or "")
        raw_cell_state = raw_cells.get(cell_id)
        if not isinstance(raw_cell_state, Mapping):
            raise GraphLearningError("coverage attempt references an unknown cell")
        raw_cell = raw_cell_state.get("cell")
        if not isinstance(raw_cell, Mapping):
            raise GraphLearningError("coverage cell is malformed")
        strategy = _required_token(
            str(raw_attempt.get("strategy") or ""),
            "strategy",
        )
        route_dimension = _required_token(
            str(raw_attempt.get("dimension") or ""),
            "dimension",
        )
        campaign = campaigns_by_strategy.get(strategy)
        family = _required_token(str(raw_cell.get("family") or ""), "family")
        if family not in known_families:
            family = "unclassified"
        probe = campaign.probe if campaign is not None else "custom_counterfactual"
        dimension = campaign.dimension if campaign is not None else "custom_counterfactual"
        evidence_version = _non_negative_int(
            raw_attempt.get("evidence_version_after"),
            "evidence version",
        )
        outcome = _required_text(
            str(raw_attempt.get("outcome") or ""),
            "outcome",
        )
        proof_confirmed = (
            str(raw_attempt.get("stage") or "") == "proof" or outcome == "proof_confirmed"
        )
        route_key = (cell_id, strategy, route_dimension, evidence_version)
        verification = _attempt_verification(
            raw_attempt,
            beliefs=beliefs,
            proof_confirmed=proof_confirmed,
        )
        lessons.append(
            RouteLesson.create(
                source_digest=source_digest,
                sequence=sequence,
                family=family,
                probe=probe,
                dimension=dimension,
                outcome=outcome,
                material_progress=raw_attempt.get("material_progress") is True,
                proof_confirmed=proof_confirmed,
                loop_stopped=route_key in failure_routes,
                target_requests=_non_negative_int(
                    raw_attempt.get("target_requests"),
                    "target requests",
                ),
                **verification,
            )
        )
    return tuple(lessons)


def build_candidate_policy(
    lessons: Sequence[RouteLesson],
    *,
    min_independent_runs: int = _MIN_POLICY_RUNS,
) -> SeedLearningPolicy:
    if min_independent_runs < _MIN_POLICY_RUNS:
        raise GraphLearningError("candidate policy requires at least two independent runs")
    grouped: dict[tuple[str, str], list[RouteLesson]] = defaultdict(list)
    for lesson in lessons:
        grouped[(lesson.family, lesson.probe)].append(lesson)
    adjustments: list[SeedPolicyAdjustment] = []
    for (family, probe), items in grouped.items():
        by_run: dict[str, list[RouteLesson]] = defaultdict(list)
        for item in items:
            by_run[item.source_digest].append(item)
        independent_runs = len(by_run)
        if independent_runs < min_independent_runs:
            continue
        proof_count = sum(item.verified_proof for item in items)
        progress_count = sum(
            item.verified_material_progress and not item.verified_proof for item in items
        )
        failure_count = sum(
            not item.material_progress or item.belief_disposition == "disproved" for item in items
        )
        loop_stop_count = sum(item.loop_stopped for item in items)
        raw_delta = sum(_run_score_delta(run_items) for run_items in by_run.values())
        score_delta = max(-_MAX_SCORE_DELTA, min(raw_delta, _MAX_SCORE_DELTA))
        if score_delta == 0:
            continue
        adjustments.append(
            SeedPolicyAdjustment(
                family=family,
                probe=probe,
                score_delta=score_delta,
                independent_runs=independent_runs,
                progress_count=progress_count,
                proof_count=proof_count,
                failure_count=failure_count,
                loop_stop_count=loop_stop_count,
            )
        )
    return SeedLearningPolicy.create(
        status="candidate",
        adjustments=adjustments,
    )


def _run_score_delta(lessons: Sequence[RouteLesson]) -> int:
    proof_confirmed = any(item.verified_proof for item in lessons)
    material_progress = any(
        item.verified_material_progress and not item.verified_proof for item in lessons
    )
    explicit_failure = any(
        not item.material_progress or item.belief_disposition == "disproved" for item in lessons
    )
    score = (
        120 if proof_confirmed else (30 if material_progress else (-25 if explicit_failure else 0))
    )
    if (proof_confirmed or material_progress) and explicit_failure:
        score -= 25
    if any(item.loop_stopped for item in lessons):
        score -= 30
    return score


def evaluate_policy_promotion(
    *,
    baseline: ReplayMetrics,
    candidate: ReplayMetrics,
) -> PolicyPromotionDecision:
    reasons: list[str] = []
    if baseline.cases != candidate.cases:
        reasons.append("replay_case_count_mismatch")
    if candidate.cases < _MIN_REPLAY_CASES:
        reasons.append("insufficient_held_out_cases")
    if candidate.solved <= baseline.solved:
        reasons.append("held_out_solve_count_did_not_improve")
    if candidate.false_proofs > baseline.false_proofs:
        reasons.append("false_proof_regression")
    if candidate.loop_violations > baseline.loop_violations:
        reasons.append("loop_safety_regression")
    if candidate.unmatched_model_attempts != 0:
        reasons.append("candidate_model_accounting_incomplete")
    if _efficiency_regressed(
        baseline.cost_usd,
        baseline.solved,
        candidate.cost_usd,
        candidate.solved,
    ):
        reasons.append("cost_per_solve_regression")
    if _efficiency_regressed(
        float(baseline.model_requests),
        baseline.solved,
        float(candidate.model_requests),
        candidate.solved,
    ):
        reasons.append("requests_per_solve_regression")
    receipt = {
        "version": 1,
        "baseline": baseline.to_json(),
        "candidate": candidate.to_json(),
        "accepted": not reasons,
        "reasons": reasons,
    }
    return PolicyPromotionDecision(
        accepted=not reasons,
        reasons=tuple(reasons),
        receipt_digest=f"replay-receipt:{_digest_json(receipt)}",
    )


def promote_candidate_policy(
    candidate_policy: SeedLearningPolicy,
    *,
    baseline: ReplayMetrics,
    candidate: ReplayMetrics,
    output_path: Path,
) -> PolicyPromotionDecision:
    if candidate_policy.status != "candidate":
        raise GraphLearningError("only a candidate policy can be promoted")
    decision = evaluate_policy_promotion(
        baseline=baseline,
        candidate=candidate,
    )
    if not decision.accepted:
        return decision
    promoted = SeedLearningPolicy.create(
        status="promoted",
        adjustments=candidate_policy.adjustments,
        replay_receipt_digest=decision.receipt_digest,
    )
    promoted.save(output_path)
    return decision


def record_route_lessons(
    workspace_dir: Path,
    *,
    memory_settings: object | None = None,
) -> tuple[RouteLesson, ...]:
    lessons = extract_route_lessons(workspace_dir)
    RouteLessonStore(workspace_dir / "graph-route-lessons.jsonl").append(lessons)
    if _memory_mode(memory_settings) == "learn":
        db_path = _memory_db_path(memory_settings)
        if db_path is not None:
            global_store = RouteLessonStore(global_lesson_path(db_path))
            global_store.append(lessons)
            refresh_learning_artifacts(
                db_path,
                lessons=global_store.load(),
            )
    return lessons


def refresh_learning_artifacts(
    memory_db_path: Path,
    *,
    lessons: Sequence[RouteLesson] | None = None,
) -> tuple[SeedLearningPolicy, CapabilityGapBacklog]:
    """Refresh review-only candidate artifacts from the append-only lesson corpus."""
    corpus = (
        tuple(lessons)
        if lessons is not None
        else RouteLessonStore(global_lesson_path(memory_db_path)).load()
    )
    candidate = build_candidate_policy(corpus)
    candidate.save(candidate_policy_path(memory_db_path))
    try:
        backlog = build_capability_gap_backlog(corpus)
        backlog.save(capability_backlog_path(memory_db_path))
    except CapabilityGapError as exc:
        raise GraphLearningError(f"cannot refresh capability backlog: {exc}") from exc
    return candidate, backlog


def learning_artifact_summary(
    memory_settings: object | None,
) -> dict[str, object]:
    """Return an auditable, secret-free summary for the per-run receipt."""
    if _memory_mode(memory_settings) != "learn":
        return {}
    db_path = _memory_db_path(memory_settings)
    if db_path is None:
        return {}
    candidate_path = candidate_policy_path(db_path)
    backlog_path = capability_backlog_path(db_path)
    if not candidate_path.exists() or not backlog_path.exists():
        return {}
    candidate = SeedLearningPolicy.load(candidate_path)
    try:
        backlog = CapabilityGapBacklog.load(backlog_path)
    except CapabilityGapError as exc:
        raise GraphLearningError(f"cannot read capability backlog: {exc}") from exc
    return {
        "candidate_policy": {
            "policy_id": candidate.policy_id,
            "status": candidate.status,
            "adjustment_count": len(candidate.adjustments),
            "ready_for_held_out_replay": bool(candidate.adjustments),
        },
        "capability_backlog": {
            "backlog_id": backlog.backlog_id,
            "gap_count": len(backlog.gaps),
            "source_lesson_count": backlog.source_lesson_count,
        },
    }


def promoted_policy_for_memory(
    memory_settings: object | None,
) -> SeedLearningPolicy | None:
    if _memory_mode(memory_settings) not in {"read", "learn"}:
        return None
    db_path = _memory_db_path(memory_settings)
    if db_path is None:
        return None
    policy_path = active_policy_path(db_path)
    if not policy_path.exists():
        return None
    return SeedLearningPolicy.load_promoted(policy_path)


def global_lesson_path(memory_db_path: Path) -> Path:
    return memory_db_path.with_name(f"{memory_db_path.stem}.graph-route-lessons.jsonl")


def active_policy_path(memory_db_path: Path) -> Path:
    return memory_db_path.with_name(f"{memory_db_path.stem}.graph-seed-policy.json")


def candidate_policy_path(memory_db_path: Path) -> Path:
    return memory_db_path.with_name(f"{memory_db_path.stem}.graph-seed-policy.candidate.json")


def capability_backlog_path(memory_db_path: Path) -> Path:
    return memory_db_path.with_name(f"{memory_db_path.stem}.graph-capability-backlog.json")


def _failure_routes(
    payload: Mapping[str, object],
) -> set[tuple[str, str, str, int]]:
    raw_certificates = payload.get("certificates")
    if raw_certificates is None:
        return set()
    if not isinstance(raw_certificates, Mapping):
        raise GraphLearningError("failure certificates must be an object")
    routes: set[tuple[str, str, str, int]] = set()
    for raw in raw_certificates.values():
        if not isinstance(raw, Mapping):
            raise GraphLearningError("failure certificate must be an object")
        routes.add(
            (
                str(raw.get("cell_id") or ""),
                _required_token(str(raw.get("strategy") or ""), "strategy"),
                _required_token(str(raw.get("dimension") or ""), "dimension"),
                _non_negative_int(
                    raw.get("evidence_version"),
                    "evidence version",
                ),
            )
        )
    return routes


def _source_digest(
    coverage: Mapping[str, object],
    failures: Mapping[str, object],
    beliefs: Mapping[str, object],
) -> str:
    return "route-source:" + _digest_json(
        {
            "coverage": coverage,
            "failures": failures,
            "beliefs": beliefs,
        }
    )


def _attempt_verification(
    attempt: Mapping[str, object],
    *,
    beliefs: BeliefLedgerState | None,
    proof_confirmed: bool,
) -> dict[str, str]:
    verification = {
        "hypothesis_fingerprint": str(attempt.get("hypothesis_fingerprint") or "").strip(),
        "agent_spec_fingerprint": str(attempt.get("agent_spec_fingerprint") or "").strip(),
        "belief_revision_id": str(attempt.get("belief_revision_id") or "").strip(),
        "belief_disposition": str(attempt.get("belief_disposition") or "").strip(),
        "executor_receipt_digest": str(attempt.get("executor_receipt_digest") or "").strip(),
    }
    populated = sum(bool(value) for value in verification.values())
    if populated == 0:
        return verification
    if populated != len(verification):
        raise GraphLearningError("coverage attempt has incomplete executor verification identity")
    if beliefs is None:
        raise GraphLearningError("coverage attempt references a missing belief ledger")
    revision = beliefs.revisions.get(verification["belief_revision_id"])
    if revision is None:
        raise GraphLearningError("coverage attempt references an unknown belief revision")
    expected = {
        "hypothesis_fingerprint": revision.hypothesis_fingerprint,
        "agent_spec_fingerprint": revision.agent_spec_fingerprint,
        "belief_revision_id": revision.revision_id,
        "belief_disposition": revision.disposition.value,
        "executor_receipt_digest": revision.executor_receipt_digest,
    }
    if verification != expected:
        raise GraphLearningError("coverage attempt does not match its executor belief revision")
    if revision.producer_node_id != str(attempt.get("node_id") or ""):
        raise GraphLearningError("coverage attempt producer does not match its belief revision")
    material_progress = attempt.get("material_progress") is True
    if revision.disposition.value in {"supported", "confirmed"} and not material_progress:
        raise GraphLearningError("supporting belief revision requires material progress")
    if proof_confirmed and revision.disposition.value != "confirmed":
        raise GraphLearningError("proof lesson requires a confirmed belief revision")
    return verification


def _efficiency_regressed(
    baseline_value: float,
    baseline_solved: int,
    candidate_value: float,
    candidate_solved: int,
) -> bool:
    baseline_unit = baseline_value / max(baseline_solved, 1)
    candidate_unit = candidate_value / max(candidate_solved, 1)
    if baseline_unit == 0:
        return candidate_unit > 0
    return candidate_unit > baseline_unit * (1 + _MAX_EFFICIENCY_REGRESSION)


def _read_mapping(path: Path, *, label: str) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GraphLearningError(f"cannot read {label}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise GraphLearningError(f"{label} must be an object")
    return dict(raw)


def _memory_mode(settings: object | None) -> str:
    return str(getattr(settings, "mode", "off")) if settings is not None else "off"


def _memory_db_path(settings: object | None) -> Path | None:
    raw = getattr(settings, "db_path", None) if settings is not None else None
    return Path(raw) if raw is not None else None


def _validate_lesson_verification(verification: Mapping[str, str]) -> None:
    _require_sha256_identity(
        verification["hypothesis_fingerprint"],
        prefix="hypothesis:",
        label="hypothesis fingerprint",
    )
    _require_sha256_identity(
        verification["agent_spec_fingerprint"],
        prefix="agent-spec:",
        label="agent spec fingerprint",
    )
    _require_sha256_identity(
        verification["belief_revision_id"],
        prefix="belief:",
        label="belief revision ID",
    )
    if verification["belief_disposition"] not in {
        "supported",
        "confirmed",
        "disproved",
    }:
        raise GraphLearningError("route-lesson belief disposition is invalid")
    _require_sha256_identity(
        verification["executor_receipt_digest"],
        prefix="executor-receipt:",
        label="executor receipt digest",
    )


def _require_sha256_identity(value: str, *, prefix: str, label: str) -> None:
    suffix = value.removeprefix(prefix)
    if (
        not value.startswith(prefix)
        or len(suffix) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise GraphLearningError(f"{label} is invalid")


def _required_token(value: str, label: str) -> str:
    token = "_".join(value.strip().lower().replace("-", " ").split())
    if not token:
        raise GraphLearningError(f"{label} is required")
    return token


def _required_text(value: str, label: str) -> str:
    text = " ".join(value.strip().split())
    if not text:
        raise GraphLearningError(f"{label} is required")
    return text


def _non_negative_int(value: object, label: str) -> int:
    parsed = _int(value, label)
    if parsed < 0:
        raise GraphLearningError(f"{label} must be non-negative")
    return parsed


def _int(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise GraphLearningError(f"{label} must be an integer")
    try:
        return int(str(value))
    except (TypeError, ValueError) as exc:
        raise GraphLearningError(f"{label} must be an integer") from exc


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "GraphLearningError",
    "PolicyPromotionDecision",
    "ReplayMetrics",
    "RouteLesson",
    "RouteLessonStore",
    "SeedLearningPolicy",
    "SeedPolicyAdjustment",
    "active_policy_path",
    "build_candidate_policy",
    "candidate_policy_path",
    "capability_backlog_path",
    "evaluate_policy_promotion",
    "extract_route_lessons",
    "global_lesson_path",
    "learning_artifact_summary",
    "promote_candidate_policy",
    "promoted_policy_for_memory",
    "record_route_lessons",
    "refresh_learning_artifacts",
]
