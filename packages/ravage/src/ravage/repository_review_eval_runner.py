"""Repeatable A/B execution for source-candidate repository-review evaluations."""

# Evaluation input failures deliberately retain precise diagnostics.
# ruff: noqa: EM101, EM102, TRY003, TRY301

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final, cast

from ravage.repository_context import RepositoryContext, capture_repository
from ravage.repository_review import (
    DEFAULT_REVIEW_MAX_COST_USD,
    DEFAULT_REVIEW_MAX_TURNS,
    DEFAULT_REVIEW_OBJECTIVE,
    RepositoryReviewResult,
    ReviewReply,
    run_repository_review,
    validate_repository_review_options,
    validate_repository_review_route,
)
from ravage.repository_review_eval import (
    MANIFEST_SCHEMA_VERSION,
    RepositoryReviewCaseScore,
    RepositoryReviewEvalCase,
    RepositoryReviewEvalInputError,
    RepositoryReviewEvalManifest,
    aggregate_repository_review_scores,
    score_repository_review_result,
)
from ravage.repository_source_candidates import (
    RepositorySourceCandidateIndex,
    build_repository_source_candidate_index,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from ravage.model_core.providers import ResolvedModelRoute
    from ravage.repository_context import ContextLimits
    from ravage.repository_review import ReviewMessage, ReviewModelClient

REPORT_SCHEMA_VERSION: Final = "ravage.repository-review-ab-eval-report.v1"
LITERAL_ONLY_ARM: Final = "literal_only"
CANDIDATE_ASSISTED_ARM: Final = "candidate_assisted"
_ARMS: Final = (LITERAL_ONLY_ARM, CANDIDATE_ASSISTED_ARM)
_MAX_MANIFEST_BYTES = 2_000_000
_MAX_REPEATS = 100
_MAX_ERROR_CHARS = 2_000
_COST_ABS_TOLERANCE = 1e-12
_CANDIDATE_BEARING_STRATUM = "candidate_bearing"
_CANDIDATE_EMPTY_STRATUM = "candidate_empty"


class RepositoryReviewEvalRunnerError(RuntimeError):
    """An A/B evaluation cannot be configured or executed safely."""


class RepositoryReviewEvalCostLimitError(RepositoryReviewEvalRunnerError):
    """The aggregate actual model cost reached or exceeded its ceiling."""


@dataclass
class _ModelTelemetry:
    requests: int = 0
    replies: int = 0
    invalid_replies: int = 0
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    unknown_cost_replies: int = 0
    requested_actions: Counter[str] = field(default_factory=Counter)

    def copy(self) -> _ModelTelemetry:
        return _ModelTelemetry(
            requests=self.requests,
            replies=self.replies,
            invalid_replies=self.invalid_replies,
            input_tokens=self.input_tokens,
            cached_input_tokens=self.cached_input_tokens,
            output_tokens=self.output_tokens,
            cost_usd=self.cost_usd,
            unknown_cost_replies=self.unknown_cost_replies,
            requested_actions=self.requested_actions.copy(),
        )

    def since(self, before: _ModelTelemetry) -> _ModelTelemetry:
        return _ModelTelemetry(
            requests=self.requests - before.requests,
            replies=self.replies - before.replies,
            invalid_replies=self.invalid_replies - before.invalid_replies,
            input_tokens=self.input_tokens - before.input_tokens,
            cached_input_tokens=self.cached_input_tokens - before.cached_input_tokens,
            output_tokens=self.output_tokens - before.output_tokens,
            cost_usd=self.cost_usd - before.cost_usd,
            unknown_cost_replies=self.unknown_cost_replies - before.unknown_cost_replies,
            requested_actions=self.requested_actions - before.requested_actions,
        )

    def add(self, other: _ModelTelemetry) -> None:
        self.requests += other.requests
        self.replies += other.replies
        self.invalid_replies += other.invalid_replies
        self.input_tokens += other.input_tokens
        self.cached_input_tokens += other.cached_input_tokens
        self.output_tokens += other.output_tokens
        self.cost_usd += other.cost_usd
        self.unknown_cost_replies += other.unknown_cost_replies
        self.requested_actions.update(other.requested_actions)

    def to_json(self) -> dict[str, object]:
        return {
            "requests": self.requests,
            "replies": self.replies,
            "invalid_replies": self.invalid_replies,
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "output_tokens": self.output_tokens,
            "actual_cost_usd": round(self.cost_usd, 8),
            "cost_known": self.unknown_cost_replies == 0,
            "unknown_cost_replies": self.unknown_cost_replies,
            "requested_actions": dict(sorted(self.requested_actions.items())),
        }


@dataclass
class _ToolTelemetry:
    context_actions: int = 0
    searches: int = 0
    files_listed: int = 0
    files_matched: int = 0
    files_excerpted: int = 0
    source_candidates_seeded: int = 0
    source_candidates_listed: int = 0
    source_candidates_excerpted: int = 0
    source_candidate_files_listed: int = 0
    source_candidate_families_listed: int = 0

    @classmethod
    def from_result(cls, result: RepositoryReviewResult) -> _ToolTelemetry:
        return cls(
            context_actions=result.context_actions,
            searches=result.searches,
            files_listed=result.files_listed,
            files_matched=result.files_matched,
            files_excerpted=result.files_excerpted,
            source_candidates_seeded=result.source_candidates_seeded,
            source_candidates_listed=result.source_candidates_listed,
            source_candidates_excerpted=result.source_candidates_excerpted,
            source_candidate_files_listed=result.source_candidate_files_listed,
            source_candidate_families_listed=result.source_candidate_families_listed,
        )

    def add(self, other: _ToolTelemetry) -> None:
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def to_json(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class _RunRecord:
    arm: str
    case_id: str
    source_root: str
    repeat: int
    stratum: str
    source_candidate_count: int
    initial_prompt_digest: str | None
    model: _ModelTelemetry
    tools: _ToolTelemetry
    result: RepositoryReviewResult | None = None
    score: RepositoryReviewCaseScore | None = None
    error_type: str | None = None
    error_message: str | None = None

    @property
    def completed(self) -> bool:
        return self.result is not None

    def to_json(self) -> dict[str, object]:
        failure: dict[str, object] | None = None
        if self.error_type is not None:
            failure = {
                "type": self.error_type,
                "message": self.error_message,
            }
        model = self.model.to_json()
        model["initial_prompt_digest"] = self.initial_prompt_digest
        return {
            "arm": self.arm,
            "case_id": self.case_id,
            "source_root": self.source_root,
            "repeat": self.repeat,
            "stratum": self.stratum,
            "source_candidate_count": self.source_candidate_count,
            "completed": self.completed,
            "failure": failure,
            "score": self.score.to_json() if self.score is not None else None,
            "tools": self.tools.to_json(),
            "model": model,
            "review": self.result.to_json() if self.result is not None else None,
        }


class _AccountingReviewClient:
    def __init__(self, client: ReviewModelClient, *, cost_ceiling_usd: float) -> None:
        self._client = client
        self._cost_ceiling_usd = cost_ceiling_usd
        self.telemetry = _ModelTelemetry()
        self.initial_prompt_digest: str | None = None

    def begin_run(self) -> None:
        self.initial_prompt_digest = None

    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        if _cost_at_ceiling(self.telemetry.cost_usd, self._cost_ceiling_usd):
            raise RepositoryReviewEvalCostLimitError(
                "aggregate model-cost ceiling was reached before the next request"
            )
        if self.initial_prompt_digest is None:
            self.initial_prompt_digest = _messages_digest(messages)
        self.telemetry.requests += 1
        reply = self._client.complete(messages=messages, route=route)
        if not isinstance(reply, ReviewReply):
            self.telemetry.invalid_replies += 1
            return reply
        self.telemetry.replies += 1
        self.telemetry.input_tokens += reply.input_tokens
        self.telemetry.cached_input_tokens += reply.cached_input_tokens
        self.telemetry.output_tokens += reply.output_tokens
        self.telemetry.cost_usd += reply.cost_usd
        if not reply.cost_known:
            self.telemetry.unknown_cost_replies += 1
        self.telemetry.requested_actions[_requested_action(reply.content)] += 1
        if self.telemetry.cost_usd > self._cost_ceiling_usd and not math.isclose(
            self.telemetry.cost_usd,
            self._cost_ceiling_usd,
            rel_tol=0.0,
            abs_tol=_COST_ABS_TOLERANCE,
        ):
            raise RepositoryReviewEvalCostLimitError(
                "aggregate actual model cost exceeded its configured ceiling"
            )
        return reply


@dataclass(frozen=True)
class _PreparedCase:
    case: RepositoryReviewEvalCase
    source_root: Path
    context: RepositoryContext
    source_candidate_index: RepositorySourceCandidateIndex

    @property
    def snapshot_id(self) -> str:
        return str(self.context.snapshot_id)

    @property
    def stratum(self) -> str:
        if self.source_candidate_index.candidates:
            return _CANDIDATE_BEARING_STRATUM
        return _CANDIDATE_EMPTY_STRATUM


def load_repository_review_eval_manifest(path: Path) -> RepositoryReviewEvalManifest:
    """Read a bounded, duplicate-key-free JSON manifest through its strict schema."""
    manifest, _ = _load_manifest_with_digest(path)
    return manifest


def _load_manifest_with_digest(path: Path) -> tuple[RepositoryReviewEvalManifest, str]:
    raw = _read_manifest_bytes(Path(path))
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise RepositoryReviewEvalInputError(
            "evaluation manifest must be canonical UTF-8 JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise RepositoryReviewEvalInputError("evaluation manifest must be a JSON object")
    manifest = RepositoryReviewEvalManifest.from_mapping(cast("Mapping[str, object]", payload))
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    return manifest, digest


def _read_manifest_bytes(supplied: Path) -> bytes:
    descriptor: int | None = None
    try:
        metadata = supplied.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise RepositoryReviewEvalInputError("evaluation manifest cannot be a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise RepositoryReviewEvalInputError("evaluation manifest must be a regular file")
        if metadata.st_size > _MAX_MANIFEST_BYTES:
            raise RepositoryReviewEvalInputError("evaluation manifest exceeds the size limit")
        descriptor = os.open(
            supplied,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RepositoryReviewEvalInputError("evaluation manifest must be a regular file")
        if metadata.st_size > _MAX_MANIFEST_BYTES:
            raise RepositoryReviewEvalInputError("evaluation manifest exceeds the size limit")
        raw = _read_bounded(descriptor)
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise RepositoryReviewEvalInputError("evaluation manifest exceeds the size limit")
    except RepositoryReviewEvalInputError:
        raise
    except OSError as exc:
        raise RepositoryReviewEvalInputError(f"cannot read evaluation manifest: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return raw


def run_repository_review_ab_evaluation(  # noqa: PLR0913
    *,
    manifest_path: Path,
    repository_root: Path,
    route: ResolvedModelRoute,
    client: ReviewModelClient,
    repeats: int = 1,
    objective: str = DEFAULT_REVIEW_OBJECTIVE,
    max_turns: int = DEFAULT_REVIEW_MAX_TURNS,
    max_cost_usd_per_run: float = DEFAULT_REVIEW_MAX_COST_USD,
    aggregate_cost_ceiling_usd: float = DEFAULT_REVIEW_MAX_COST_USD,
    allow_paid_models: bool = False,
    context_limits: ContextLimits | None = None,
) -> dict[str, object]:
    """Run paired literal-only and candidate-assisted reviews and return a report."""
    manifest, manifest_digest = _load_manifest_with_digest(manifest_path)
    normalized_objective = validate_repository_review_options(
        objective=objective,
        max_turns=max_turns,
        max_cost_usd=max_cost_usd_per_run,
    )
    _validate_runner_options(
        repeats=repeats,
        aggregate_cost_ceiling_usd=aggregate_cost_ceiling_usd,
        allow_paid_models=allow_paid_models,
    )
    validate_repository_review_route(route, allow_paid_models=allow_paid_models)
    case_roots = _resolve_case_roots(manifest, repository_root)
    prepared_cases = _prepare_cases(manifest, case_roots, context_limits=context_limits)
    accounting_client = _AccountingReviewClient(
        client,
        cost_ceiling_usd=float(aggregate_cost_ceiling_usd),
    )
    records: list[_RunRecord] = []
    budget_exhausted = False

    for repeat in range(1, repeats + 1):
        for case_index, prepared in enumerate(prepared_cases):
            arm_order = _arm_order(repeat=repeat, case_index=case_index)
            for arm in arm_order:
                remaining_cost = (
                    float(aggregate_cost_ceiling_usd) - accounting_client.telemetry.cost_usd
                )
                if remaining_cost <= 0 or _cost_at_ceiling(
                    accounting_client.telemetry.cost_usd,
                    float(aggregate_cost_ceiling_usd),
                ):
                    budget_exhausted = True
                    break
                before = accounting_client.telemetry.copy()
                accounting_client.begin_run()
                try:
                    result = run_repository_review(
                        source_root=prepared.source_root,
                        route=route,
                        client=accounting_client,
                        objective=normalized_objective,
                        max_turns=max_turns,
                        max_cost_usd=min(
                            float(max_cost_usd_per_run),
                            remaining_cost + _COST_ABS_TOLERANCE,
                        ),
                        allow_paid_models=allow_paid_models,
                        context_limits=context_limits,
                        source_candidates_enabled=arm == CANDIDATE_ASSISTED_ARM,
                    )
                    run_model = accounting_client.telemetry.since(before)
                    _verify_result(
                        result,
                        expected_snapshot_id=prepared.snapshot_id,
                        source_candidates_enabled=arm == CANDIDATE_ASSISTED_ARM,
                        expected_source_candidate_index=prepared.source_candidate_index,
                        route=route,
                        model=run_model,
                    )
                    score = score_repository_review_result(
                        prepared.case,
                        result,
                        prepared.context,
                    )
                    records.append(
                        _RunRecord(
                            arm=arm,
                            case_id=prepared.case.case_id,
                            source_root=prepared.case.source_root,
                            repeat=repeat,
                            stratum=prepared.stratum,
                            source_candidate_count=len(prepared.source_candidate_index.candidates),
                            initial_prompt_digest=accounting_client.initial_prompt_digest,
                            model=run_model,
                            tools=_ToolTelemetry.from_result(result),
                            result=result,
                            score=score,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - failures are evaluation data.
                    records.append(
                        _RunRecord(
                            arm=arm,
                            case_id=prepared.case.case_id,
                            source_root=prepared.case.source_root,
                            repeat=repeat,
                            stratum=prepared.stratum,
                            source_candidate_count=len(prepared.source_candidate_index.candidates),
                            initial_prompt_digest=accounting_client.initial_prompt_digest,
                            model=accounting_client.telemetry.since(before),
                            tools=_ToolTelemetry(),
                            error_type=type(exc).__name__,
                            error_message=_bounded_error(exc),
                        )
                    )
                    if isinstance(exc, RepositoryReviewEvalCostLimitError):
                        budget_exhausted = True
                        break
                if _cost_at_ceiling(
                    accounting_client.telemetry.cost_usd,
                    float(aggregate_cost_ceiling_usd),
                ):
                    budget_exhausted = True
                    break
            if budget_exhausted:
                break
        if budget_exhausted:
            break

    planned_runs = len(manifest.cases) * repeats * len(_ARMS)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "manifest": {
            "case_count": len(manifest.cases),
            "case_ids": [case.case_id for case in manifest.cases],
            "file_digest": manifest_digest,
            "fixture_snapshots": [
                {
                    "case_id": prepared.case.case_id,
                    "source_root": prepared.case.source_root,
                    "snapshot_id": prepared.snapshot_id,
                    "stratum": prepared.stratum,
                    "source_candidate_count": len(prepared.source_candidate_index.candidates),
                    "source_candidate_index_digest": (prepared.source_candidate_index.index_digest),
                }
                for prepared in prepared_cases
            ],
        },
        "configuration": {
            "arms": list(_ARMS),
            "repeats": repeats,
            "max_turns": max_turns,
            "max_cost_usd_per_run": float(max_cost_usd_per_run),
            "aggregate_cost_ceiling_usd": float(aggregate_cost_ceiling_usd),
            "allow_paid_models": allow_paid_models,
            "objective_digest": "sha256:"
            + hashlib.sha256(normalized_objective.encode()).hexdigest(),
        },
        "route": _route_json(route),
        "budget": {
            "ceiling_usd": float(aggregate_cost_ceiling_usd),
            "actual_cost_usd": round(accounting_client.telemetry.cost_usd, 8),
            "exhausted": budget_exhausted,
        },
        "completion": _completion_json(records, planned_runs),
        "failures": _failures_json(records),
        "detection": _detection_json(records, planned_runs),
        "tools": _aggregate_tools(records).to_json(),
        "model": accounting_client.telemetry.to_json(),
        "arms": [
            _arm_json(
                arm,
                records,
                planned_runs=len(manifest.cases) * repeats,
            )
            for arm in _ARMS
        ],
        "strata": [
            _stratum_json(
                stratum,
                records,
                planned_runs=sum(prepared.stratum == stratum for prepared in prepared_cases)
                * repeats
                * len(_ARMS),
            )
            for stratum in (_CANDIDATE_BEARING_STRATUM, _CANDIDATE_EMPTY_STRATUM)
            if any(prepared.stratum == stratum for prepared in prepared_cases)
        ],
        "runs": [record.to_json() for record in records],
    }


def _validate_runner_options(
    *,
    repeats: int,
    aggregate_cost_ceiling_usd: float,
    allow_paid_models: bool,
) -> None:
    if type(repeats) is not int or not 1 <= repeats <= _MAX_REPEATS:
        raise ValueError("repeats must be an integer from 1 through 100")
    if (
        isinstance(aggregate_cost_ceiling_usd, bool)
        or not isinstance(aggregate_cost_ceiling_usd, (int, float))
        or not math.isfinite(aggregate_cost_ceiling_usd)
        or aggregate_cost_ceiling_usd <= 0
    ):
        raise ValueError("aggregate_cost_ceiling_usd must be a finite positive number")
    if not isinstance(allow_paid_models, bool):
        raise TypeError("allow_paid_models must be a boolean")


def _verify_result(  # noqa: PLR0913 - the trust checks stay explicit.
    result: RepositoryReviewResult,
    *,
    expected_snapshot_id: str,
    source_candidates_enabled: bool,
    expected_source_candidate_index: RepositorySourceCandidateIndex,
    route: ResolvedModelRoute,
    model: _ModelTelemetry,
) -> None:
    if result.snapshot_id != expected_snapshot_id:
        raise RepositoryReviewEvalRunnerError(
            "repository-review result does not match the independently pinned snapshot"
        )
    if result.source_candidates_enabled is not source_candidates_enabled:
        raise RepositoryReviewEvalRunnerError(
            "repository-review result reports the wrong A/B source-candidate arm"
        )
    if source_candidates_enabled:
        expected_candidates = (
            len(expected_source_candidate_index.candidates),
            expected_source_candidate_index.index_digest,
            expected_source_candidate_index.analysis_available,
            expected_source_candidate_index.analysis_error_digest,
        )
        observed_candidates = (
            result.source_candidates_total,
            result.source_candidate_index_digest,
            result.source_candidate_analysis_available,
            result.source_candidate_analysis_error_digest,
        )
        if observed_candidates != expected_candidates:
            raise RepositoryReviewEvalRunnerError(
                "repository-review result source candidates do not match the pinned snapshot"
            )
    elif result.source_candidates_total != 0:
        raise RepositoryReviewEvalRunnerError(
            "literal-only result unexpectedly contains source candidates"
        )
    expected_route = (
        route.provider,
        route.model,
        route.requested_tier,
        route.selected_tier,
        route.ordinal,
        route.reasoning_effort,
        route.max_output_tokens,
    )
    observed_route = (
        result.provider,
        result.model,
        result.requested_tier,
        result.selected_tier,
        result.route_ordinal,
        result.reasoning_effort,
        result.max_output_tokens,
    )
    if observed_route != expected_route:
        raise RepositoryReviewEvalRunnerError(
            "repository-review result model route does not match the injected route"
        )
    expected_usage = (
        model.replies,
        model.input_tokens,
        model.cached_input_tokens,
        model.output_tokens,
    )
    observed_usage = (
        result.model_calls,
        result.input_tokens,
        result.cached_input_tokens,
        result.output_tokens,
    )
    if observed_usage != expected_usage or not math.isclose(
        result.cost_usd,
        model.cost_usd,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise RepositoryReviewEvalRunnerError(
            "repository-review result usage does not match the observed model replies"
        )


def _resolve_case_roots(
    manifest: RepositoryReviewEvalManifest,
    repository_root: Path,
) -> tuple[Path, ...]:
    supplied = Path(repository_root)
    if supplied.is_symlink():
        raise RepositoryReviewEvalRunnerError("repository root cannot be a symlink")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise RepositoryReviewEvalRunnerError(f"cannot resolve repository root: {exc}") from exc
    if not root.is_dir():
        raise RepositoryReviewEvalRunnerError("repository root must be a directory")
    resolved: list[Path] = []
    for case in manifest.cases:
        relative = PurePosixPath(case.source_root)
        unresolved = root.joinpath(*relative.parts)
        if unresolved.is_symlink():
            raise RepositoryReviewEvalRunnerError(
                f"source_root for case {case.case_id} cannot be a symlink"
            )
        try:
            candidate = unresolved.resolve(strict=True)
        except OSError as exc:
            raise RepositoryReviewEvalRunnerError(
                f"cannot resolve source_root for case {case.case_id}: {exc}"
            ) from exc
        if not candidate.is_relative_to(root):
            raise RepositoryReviewEvalRunnerError(
                f"source_root for case {case.case_id} escapes repository root"
            )
        if not candidate.is_dir():
            raise RepositoryReviewEvalRunnerError(
                f"source_root for case {case.case_id} must be a directory"
            )
        resolved.append(candidate)
    return tuple(resolved)


def _prepare_cases(
    manifest: RepositoryReviewEvalManifest,
    case_roots: Sequence[Path],
    *,
    context_limits: ContextLimits | None,
) -> tuple[_PreparedCase, ...]:
    prepared: list[_PreparedCase] = []
    for case, source_root in zip(manifest.cases, case_roots, strict=True):
        context = capture_repository(source_root, limits=context_limits)
        if case.snapshot_id != context.snapshot_id:
            raise RepositoryReviewEvalRunnerError(
                f"snapshot_id for case {case.case_id} does not match its captured source_root"
            )
        prepared.append(
            _PreparedCase(
                case=case,
                source_root=source_root,
                context=context,
                source_candidate_index=build_repository_source_candidate_index(context),
            )
        )
    return tuple(prepared)


def _arm_order(*, repeat: int, case_index: int) -> tuple[str, str]:
    pair_index = (repeat - 1) + case_index
    if pair_index % 2:
        return CANDIDATE_ASSISTED_ARM, LITERAL_ONLY_ARM
    return LITERAL_ONLY_ARM, CANDIDATE_ASSISTED_ARM


def _completion_json(records: Sequence[_RunRecord], planned_runs: int) -> dict[str, object]:
    completed = sum(record.completed for record in records)
    attempted = len(records)
    return {
        "planned_runs": planned_runs,
        "attempted_runs": attempted,
        "completed_runs": completed,
        "failed_runs": attempted - completed,
        "skipped_runs": planned_runs - attempted,
        "completion_rate": round(completed / planned_runs, 8) if planned_runs else 1.0,
    }


def _detection_json(records: Sequence[_RunRecord], planned_runs: int) -> dict[str, object]:
    scores = tuple(record.score for record in records if record.score is not None)
    aggregate = aggregate_repository_review_scores(scores).to_json() if scores else None
    return {
        "scored_runs": len(scores),
        "unscored_runs": planned_runs - len(scores),
        "score": aggregate,
    }


def _failures_json(records: Sequence[_RunRecord]) -> list[dict[str, object]]:
    return [
        {
            "arm": record.arm,
            "case_id": record.case_id,
            "repeat": record.repeat,
            "type": record.error_type,
            "message": record.error_message,
        }
        for record in records
        if not record.completed
    ]


def _aggregate_tools(records: Sequence[_RunRecord]) -> _ToolTelemetry:
    total = _ToolTelemetry()
    for record in records:
        total.add(record.tools)
    return total


def _aggregate_model(records: Sequence[_RunRecord]) -> _ModelTelemetry:
    total = _ModelTelemetry()
    for record in records:
        total.add(record.model)
    return total


def _arm_json(
    arm: str,
    records: Sequence[_RunRecord],
    *,
    planned_runs: int,
) -> dict[str, object]:
    selected = tuple(record for record in records if record.arm == arm)
    return {
        "arm": arm,
        "completion": _completion_json(selected, planned_runs),
        "detection": _detection_json(selected, planned_runs),
        "tools": _aggregate_tools(selected).to_json(),
        "model": _aggregate_model(selected).to_json(),
    }


def _stratum_json(
    stratum: str,
    records: Sequence[_RunRecord],
    *,
    planned_runs: int,
) -> dict[str, object]:
    selected = tuple(record for record in records if record.stratum == stratum)
    return {
        "stratum": stratum,
        "completion": _completion_json(selected, planned_runs),
        "detection": _detection_json(selected, planned_runs),
        "tools": _aggregate_tools(selected).to_json(),
        "model": _aggregate_model(selected).to_json(),
        "arms": [
            _arm_json(
                arm,
                selected,
                planned_runs=planned_runs // len(_ARMS),
            )
            for arm in _ARMS
        ],
    }


def _route_json(route: ResolvedModelRoute) -> dict[str, object]:
    return {
        "provider": route.provider,
        "model": route.model,
        "requested_tier": route.requested_tier,
        "selected_tier": route.selected_tier,
        "route_ordinal": route.ordinal,
        "reasoning_effort": route.reasoning_effort,
        "max_output_tokens": route.max_output_tokens,
    }


def _requested_action(content: str) -> str:
    try:
        payload = json.loads(content)
    except (json.JSONDecodeError, RecursionError, TypeError):
        return "invalid_json"
    if not isinstance(payload, dict) or not isinstance(payload.get("action"), str):
        return "invalid_action"
    return cast("str", payload["action"])


def _messages_digest(messages: Sequence[ReviewMessage]) -> str:
    payload = [{"role": message.role, "content": message.content} for message in messages]
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= _MAX_MANIFEST_BYTES:
        chunk = os.read(descriptor, min(65_536, _MAX_MANIFEST_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def _bounded_error(exc: Exception) -> str:
    message = str(exc)
    if len(message) <= _MAX_ERROR_CHARS:
        return message
    return message[:_MAX_ERROR_CHARS] + "..."


def _cost_at_ceiling(cost_usd: float, ceiling_usd: float) -> bool:
    return cost_usd >= ceiling_usd or math.isclose(
        cost_usd,
        ceiling_usd,
        rel_tol=0.0,
        abs_tol=_COST_ABS_TOLERANCE,
    )


__all__ = [
    "CANDIDATE_ASSISTED_ARM",
    "LITERAL_ONLY_ARM",
    "REPORT_SCHEMA_VERSION",
    "RepositoryReviewEvalCostLimitError",
    "RepositoryReviewEvalRunnerError",
    "load_repository_review_eval_manifest",
    "run_repository_review_ab_evaluation",
]
