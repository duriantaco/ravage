# Capability-gap learning is target-agnostic and never modifies executable code.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.autonomous_graph.learning import RouteLesson

_BACKLOG_VERSION = 1
_MIN_FAILED_RUNS = 2
_MAX_PRIORITY = 1_000


class CapabilityGapError(RuntimeError):
    """Raised when a capability backlog cannot preserve its invariants."""


@dataclass(frozen=True)
class CapabilityGap:
    """A repeated generic route deficit, without target or secret material."""

    gap_id: str
    family: str
    probe: str
    dimension: str
    status: str
    independent_runs: int
    failed_runs: int
    attempt_count: int
    progress_count: int
    proof_count: int
    failure_count: int
    loop_stop_count: int
    target_requests: int
    priority: int

    @classmethod
    def create(  # noqa: PLR0913 - aggregate identity is intentionally explicit.
        cls,
        *,
        family: str,
        probe: str,
        dimension: str,
        status: str,
        independent_runs: int,
        failed_runs: int,
        attempt_count: int,
        progress_count: int,
        proof_count: int,
        failure_count: int,
        loop_stop_count: int,
        target_requests: int,
        priority: int,
    ) -> CapabilityGap:
        if status not in {
            "needs_specialist",
            "needs_closure",
            "needs_reliability",
        }:
            raise CapabilityGapError("unsupported capability-gap status")
        canonical = {
            "family": _required_token(family, "family"),
            "probe": _required_token(probe, "probe"),
            "dimension": _required_token(dimension, "dimension"),
            "status": status,
            "independent_runs": _non_negative(independent_runs, "independent runs"),
            "failed_runs": _non_negative(failed_runs, "failed runs"),
            "attempt_count": _non_negative(attempt_count, "attempt count"),
            "progress_count": _non_negative(progress_count, "progress count"),
            "proof_count": _non_negative(proof_count, "proof count"),
            "failure_count": _non_negative(failure_count, "failure count"),
            "loop_stop_count": _non_negative(loop_stop_count, "loop-stop count"),
            "target_requests": _non_negative(target_requests, "target requests"),
            "priority": _non_negative(priority, "priority"),
        }
        if canonical["priority"] > _MAX_PRIORITY:
            raise CapabilityGapError("capability-gap priority exceeds its safety cap")
        if canonical["failed_runs"] > canonical["independent_runs"]:
            raise CapabilityGapError("failed runs cannot exceed independent runs")
        return cls(
            gap_id=f"capability-gap:{_digest_json(canonical)[:24]}",
            **canonical,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "gap_id": self.gap_id,
            "family": self.family,
            "probe": self.probe,
            "dimension": self.dimension,
            "status": self.status,
            "independent_runs": self.independent_runs,
            "failed_runs": self.failed_runs,
            "attempt_count": self.attempt_count,
            "progress_count": self.progress_count,
            "proof_count": self.proof_count,
            "failure_count": self.failure_count,
            "loop_stop_count": self.loop_stop_count,
            "target_requests": self.target_requests,
            "priority": self.priority,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> CapabilityGap:
        gap = cls.create(
            family=str(payload.get("family") or ""),
            probe=str(payload.get("probe") or ""),
            dimension=str(payload.get("dimension") or ""),
            status=str(payload.get("status") or ""),
            independent_runs=_integer(payload.get("independent_runs"), "independent runs"),
            failed_runs=_integer(payload.get("failed_runs"), "failed runs"),
            attempt_count=_integer(payload.get("attempt_count"), "attempt count"),
            progress_count=_integer(payload.get("progress_count"), "progress count"),
            proof_count=_integer(payload.get("proof_count"), "proof count"),
            failure_count=_integer(payload.get("failure_count"), "failure count"),
            loop_stop_count=_integer(payload.get("loop_stop_count"), "loop-stop count"),
            target_requests=_integer(payload.get("target_requests"), "target requests"),
            priority=_integer(payload.get("priority"), "priority"),
        )
        if str(payload.get("gap_id") or "") != gap.gap_id:
            raise CapabilityGapError("capability-gap ID mismatch")
        return gap


@dataclass(frozen=True)
class CapabilityGapBacklog:
    """Review queue built from repeated run receipts, never benchmark source."""

    backlog_id: str
    source_digest: str
    source_lesson_count: int
    gaps: tuple[CapabilityGap, ...]

    @classmethod
    def create(
        cls,
        *,
        source_lesson_ids: Sequence[str],
        gaps: Sequence[CapabilityGap],
    ) -> CapabilityGapBacklog:
        ordered_lesson_ids = tuple(sorted(set(source_lesson_ids)))
        ordered_gaps = tuple(
            sorted(
                gaps,
                key=lambda item: (
                    -item.priority,
                    item.family,
                    item.probe,
                    item.dimension,
                ),
            )
        )
        source_digest = f"lesson-corpus:{_digest_json(ordered_lesson_ids)}"
        identity = {
            "source_digest": source_digest,
            "source_lesson_count": len(ordered_lesson_ids),
            "gaps": [item.to_json() for item in ordered_gaps],
        }
        return cls(
            backlog_id=f"capability-backlog:{_digest_json(identity)[:24]}",
            source_digest=source_digest,
            source_lesson_count=len(ordered_lesson_ids),
            gaps=ordered_gaps,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "version": _BACKLOG_VERSION,
            "backlog_id": self.backlog_id,
            "source_digest": self.source_digest,
            "source_lesson_count": self.source_lesson_count,
            "gaps": [item.to_json() for item in self.gaps],
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> CapabilityGapBacklog:
        if payload.get("version") != _BACKLOG_VERSION:
            raise CapabilityGapError("unsupported capability-backlog version")
        raw_gaps = payload.get("gaps")
        if not isinstance(raw_gaps, list):
            raise CapabilityGapError("capability backlog gaps must be a list")
        gaps = tuple(
            CapabilityGap.from_json(item) for item in raw_gaps if isinstance(item, Mapping)
        )
        if len(gaps) != len(raw_gaps):
            raise CapabilityGapError("capability backlog gap must be an object")
        source_lesson_count = _integer(
            payload.get("source_lesson_count"),
            "source lesson count",
        )
        source_digest = str(payload.get("source_digest") or "")
        if not source_digest.startswith("lesson-corpus:"):
            raise CapabilityGapError("capability backlog source digest is invalid")
        identity = {
            "source_digest": source_digest,
            "source_lesson_count": source_lesson_count,
            "gaps": [item.to_json() for item in gaps],
        }
        backlog_id = f"capability-backlog:{_digest_json(identity)[:24]}"
        if str(payload.get("backlog_id") or "") != backlog_id:
            raise CapabilityGapError("capability-backlog ID mismatch")
        return cls(
            backlog_id=backlog_id,
            source_digest=source_digest,
            source_lesson_count=source_lesson_count,
            gaps=gaps,
        )

    @classmethod
    def load(cls, path: Path) -> CapabilityGapBacklog:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityGapError(f"cannot read capability backlog: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise CapabilityGapError("capability backlog must be an object")
        return cls.from_json(raw)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


def build_capability_gap_backlog(
    lessons: Sequence[RouteLesson],
    *,
    min_failed_runs: int = _MIN_FAILED_RUNS,
) -> CapabilityGapBacklog:
    if min_failed_runs < _MIN_FAILED_RUNS:
        raise CapabilityGapError("capability gaps require at least two failed runs")
    grouped: dict[tuple[str, str, str], list[RouteLesson]] = defaultdict(list)
    for lesson in lessons:
        grouped[(lesson.family, lesson.probe, lesson.dimension)].append(lesson)
    gaps: list[CapabilityGap] = []
    for (family, probe, dimension), items in grouped.items():
        independent_runs = len({item.source_digest for item in items})
        failed_runs = len(
            {
                item.source_digest
                for item in items
                if (
                    not item.material_progress
                    or item.belief_disposition == "disproved"
                    or item.loop_stopped
                )
            }
        )
        if failed_runs < min_failed_runs:
            continue
        progress_count = sum(
            item.verified_material_progress and not item.verified_proof for item in items
        )
        proof_count = sum(item.verified_proof for item in items)
        failure_count = sum(
            not item.material_progress or item.belief_disposition == "disproved" for item in items
        )
        loop_stop_count = sum(item.loop_stopped for item in items)
        status = (
            "needs_reliability"
            if proof_count
            else ("needs_closure" if progress_count else "needs_specialist")
        )
        target_requests = sum(item.target_requests for item in items)
        priority = min(
            _MAX_PRIORITY,
            failed_runs * 100
            + min(loop_stop_count, failed_runs) * 30
            + min(failure_count, failed_runs) * 20
            + min(target_requests, 100),
        )
        gaps.append(
            CapabilityGap.create(
                family=family,
                probe=probe,
                dimension=dimension,
                status=status,
                independent_runs=independent_runs,
                failed_runs=failed_runs,
                attempt_count=len(items),
                progress_count=progress_count,
                proof_count=proof_count,
                failure_count=failure_count,
                loop_stop_count=loop_stop_count,
                target_requests=target_requests,
                priority=priority,
            )
        )
    return CapabilityGapBacklog.create(
        source_lesson_ids=tuple(lesson.lesson_id for lesson in lessons),
        gaps=gaps,
    )


def _required_token(value: str, label: str) -> str:
    token = "_".join(value.strip().lower().replace("-", " ").split())
    if not token:
        raise CapabilityGapError(f"{label} is required")
    return token


def _non_negative(value: int, label: str) -> int:
    if value < 0:
        raise CapabilityGapError(f"{label} must be non-negative")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise CapabilityGapError(f"{label} must be an integer")
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as exc:
        raise CapabilityGapError(f"{label} must be an integer") from exc
    return _non_negative(parsed, label)


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "CapabilityGap",
    "CapabilityGapBacklog",
    "CapabilityGapError",
    "build_capability_gap_backlog",
]
