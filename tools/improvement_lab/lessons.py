"""Build target-agnostic capability briefs from secret-safe trajectory capsules."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from tools.improvement_lab.corpus import CORPUS_SCHEMA_VERSION, scan_for_leaks

# Validation diagnostics are bounded schema errors, never raw log excerpts.
# ruff: noqa: EM101, EM102, PLR0913, TRY003

BRIEF_SCHEMA_VERSION: Final = "ravage.improvement-brief.v1"
_MAX_GAPS = 6
_MAX_PRIORITY = 100
_BASELINE_FIELDS = (
    "capsules",
    "turns",
    "attempts",
    "low_value_or_repeated",
    "blocked",
    "evidence_not_advanced",
    "other_family",
    "probe_actions",
    "closure_actions",
    "harness_overrides",
    "confirmed_findings",
    "incomplete_requests",
    "unmetered_actions",
    "lower_bound_accounting",
)
_GAP_TEXT = {
    "novelty_and_dedup": (
        "Reduce semantically repeated or low-value actions across the whole run.",
        "Lower repeat/low-value rate with no vulnerability-recall loss.",
    ),
    "blocked_route_recovery": (
        "Recover from blocked routes using identity-aware alternate evidence paths.",
        "More evidence advancement after blocked actions without extra safety violations.",
    ),
    "family_classification_and_surface_graph": (
        "Improve target-agnostic family classification and canonical surface correlation.",
        "Fewer unclassified actions and better held-out finding recall.",
    ),
    "breadth_to_depth_closure": (
        "Convert promising probe evidence into bounded exploit and validation closure.",
        "Higher verified-finding conversion on renamed and reordered fixtures.",
    ),
    "model_harness_alignment": (
        "Make model proposals satisfy harness safety and novelty constraints earlier.",
        "Fewer harness overrides with unchanged loop and provenance safety.",
    ),
    "evidence_efficiency": (
        "Prefer actions with a measurable evidence-state transition.",
        "Higher evidence-advance rate within the same physical-request budget.",
    ),
    "traffic_accounting_integrity": (
        "Eliminate incomplete, unmetered, or lower-bound request accounting.",
        "Exact physical-request accounting in every matched live receipt.",
    ),
}


class ImprovementBriefError(RuntimeError):
    """Raised when a candidate brief cannot be derived safely."""


@dataclass(frozen=True)
class CapabilityGap:
    kind: str
    priority: int
    observed_ratio: float
    observations: int
    objective: str
    acceptance_signal: str

    @property
    def gap_id(self) -> str:
        payload = {
            "kind": self.kind,
            "priority": self.priority,
            "observed_ratio": self.observed_ratio,
            "observations": self.observations,
            "objective": self.objective,
            "acceptance_signal": self.acceptance_signal,
        }
        return f"gap_{_digest_json(payload)[:24]}"

    def to_json(self) -> dict[str, object]:
        return {
            "gap_id": self.gap_id,
            "kind": self.kind,
            "priority": self.priority,
            "observed_ratio": self.observed_ratio,
            "observations": self.observations,
            "objective": self.objective,
            "acceptance_signal": self.acceptance_signal,
        }


def build_improvement_brief(corpus: Mapping[str, object]) -> dict[str, object]:
    """Turn a validated development corpus into a generic change brief."""
    scan_for_leaks(corpus)
    if corpus.get("schema_version") != CORPUS_SCHEMA_VERSION:
        raise ImprovementBriefError("candidate corpus schema is unsupported")
    raw_capsules = corpus.get("capsules")
    if not isinstance(raw_capsules, list):
        raise ImprovementBriefError("candidate corpus trajectory capsules must be a list")
    capsules = _mapping_sequence(raw_capsules, label="capsules")

    counters: Counter[str] = Counter()
    for capsule in capsules:
        metadata = _mapping(capsule.get("metadata"), label="capsule metadata")
        if (
            metadata.get("partition") != "development"
            or metadata.get("candidate_visible") is not True
        ):
            raise ImprovementBriefError("candidate brief cannot consume sealed capsules")
        turns = _mapping_sequence(capsule.get("turns"), label="turns")
        counters["capsules"] += 1
        counters["turns"] += len(turns)
        aggregate = _mapping(capsule.get("aggregate"), label="aggregate")
        counters["confirmed_findings"] += _count(aggregate.get("confirmed_finding_count"))
        traffic = _mapping(aggregate.get("traffic"), label="traffic")
        counters["incomplete_requests"] += _count(traffic.get("incomplete_request_count"))
        counters["unmetered_actions"] += _count(traffic.get("unmetered_action_count"))
        counters["lower_bound_accounting"] += int(
            traffic.get("accounting_status") not in {"exact", "unknown"}
        )
        for turn in turns:
            _accumulate_turn(turn, counters)

    gaps = _derive_gaps(counters)
    dataset_digest = f"sha256:{_digest_json(corpus)}"
    brief: dict[str, object] = {
        "schema_version": BRIEF_SCHEMA_VERSION,
        "dataset_digest": dataset_digest,
        "decision": "propose_candidates" if gaps else "hold_champion",
        "baseline": {key: counters[key] for key in _BASELINE_FIELDS},
        "capability_gaps": [gap.to_json() for gap in gaps],
        "candidate_contract": _candidate_contract(),
    }
    brief["brief_digest"] = f"sha256:{_digest_json(brief)}"
    return brief


def validate_improvement_brief(  # noqa: C901 - strict candidate boundary schema.
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Validate every candidate-visible brief field and fixed instruction string."""
    expected_fields = {
        "schema_version",
        "dataset_digest",
        "decision",
        "baseline",
        "capability_gaps",
        "candidate_contract",
        "brief_digest",
    }
    if set(payload) != expected_fields or payload.get("schema_version") != BRIEF_SCHEMA_VERSION:
        raise ImprovementBriefError("candidate capability brief fields are invalid")
    dataset_digest = payload.get("dataset_digest")
    if (
        not isinstance(dataset_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", dataset_digest) is None
    ):
        raise ImprovementBriefError("candidate capability brief dataset digest is invalid")
    baseline = _mapping(payload.get("baseline"), label="brief baseline")
    if set(baseline) != set(_BASELINE_FIELDS) or any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in baseline.values()
    ):
        raise ImprovementBriefError("candidate capability brief baseline is invalid")
    raw_gaps = payload.get("capability_gaps")
    if not isinstance(raw_gaps, list) or len(raw_gaps) > _MAX_GAPS:
        raise ImprovementBriefError("candidate capability brief gaps are invalid")
    validated_gaps: list[dict[str, object]] = []
    seen_kinds: set[str] = set()
    for raw_gap in raw_gaps:
        gap = _mapping(raw_gap, label="capability gap")
        if set(gap) != {
            "gap_id",
            "kind",
            "priority",
            "observed_ratio",
            "observations",
            "objective",
            "acceptance_signal",
        }:
            raise ImprovementBriefError("candidate capability gap fields are invalid")
        kind = str(gap.get("kind") or "")
        expected_text = _GAP_TEXT.get(kind)
        priority = gap.get("priority")
        ratio = gap.get("observed_ratio")
        observations = gap.get("observations")
        if (
            expected_text is None
            or kind in seen_kinds
            or isinstance(priority, bool)
            or not isinstance(priority, int)
            or not 1 <= priority <= _MAX_PRIORITY
            or isinstance(ratio, bool)
            or not isinstance(ratio, int | float)
            or not math.isfinite(float(ratio))
            or not 0 <= float(ratio) <= 1
            or isinstance(observations, bool)
            or not isinstance(observations, int)
            or observations <= 0
            or (gap.get("objective"), gap.get("acceptance_signal")) != expected_text
        ):
            raise ImprovementBriefError("candidate capability gap values are invalid")
        rebuilt = CapabilityGap(
            kind=kind,
            priority=priority,
            observed_ratio=float(ratio),
            observations=observations,
            objective=expected_text[0],
            acceptance_signal=expected_text[1],
        ).to_json()
        if rebuilt != dict(gap):
            raise ImprovementBriefError("candidate capability gap identity is invalid")
        seen_kinds.add(kind)
        validated_gaps.append(rebuilt)
    decision = payload.get("decision")
    if decision != ("propose_candidates" if validated_gaps else "hold_champion"):
        raise ImprovementBriefError("candidate capability brief decision is invalid")
    if payload.get("candidate_contract") != _candidate_contract():
        raise ImprovementBriefError("candidate capability brief contract is invalid")
    unsigned = {key: value for key, value in payload.items() if key != "brief_digest"}
    if payload.get("brief_digest") != f"sha256:{_digest_json(unsigned)}":
        raise ImprovementBriefError("candidate capability brief digest is invalid")
    return {str(key): value for key, value in payload.items()}


def _candidate_contract() -> dict[str, object]:
    return {
        "candidate_may_read": ["development_capsules", "this_brief"],
        "candidate_must_not_read": [
            "raw_logs",
            "sealed_holdouts",
            "proof_values",
            "benchmark_metadata",
            "champion_source_checkout",
        ],
        "allowed_candidate_types": [
            "knowledge_pack",
            "policy_patch",
            "source_patch",
        ],
        "required_gates": [
            "deterministic_replay",
            "metamorphic_fixtures",
            "matched_live_repeats",
            "unrelated_controls",
            "zero_safety_regressions",
            "bounded_efficiency_regression",
        ],
        "promotion_authority": "human_reviewed_archive_receipt_only",
    }


def _accumulate_turn(turn: Mapping[str, object], counters: Counter[str]) -> None:
    selection = _mapping(turn.get("selection"), label="selection")
    attempt = _mapping(turn.get("attempt"), label="attempt")
    if selection:
        counters["selections"] += 1
        counters["harness_overrides"] += int(selection.get("changed") is True)
        selected = _mapping(selection.get("selected"), label="selected action")
        category = str(selected.get("category") or "unknown")
        family = str(selected.get("family") or "unknown")
        counters["probe_actions"] += int(category == "probe")
        counters["closure_actions"] += int(category in {"exploit", "validate"})
        counters["other_family"] += int(family in {"other", "unknown"})
    if attempt:
        counters["attempts"] += 1
        status = str(attempt.get("status") or "unknown")
        outcome = _mapping(attempt.get("outcome"), label="attempt outcome")
        classification = str(outcome.get("classification") or "unknown")
        counters["low_value_or_repeated"] += int(
            status == "low_value" or classification == "repeated"
        )
        counters["blocked"] += int(classification == "blocked")
        counters["evidence_not_advanced"] += int(attempt.get("evidence_advanced") is False)


def _derive_gaps(counters: Counter[str]) -> tuple[CapabilityGap, ...]:
    attempts = max(1, counters["attempts"])
    selections = max(1, counters["selections"])
    probes = max(1, counters["probe_actions"])
    candidates: list[CapabilityGap] = []
    _maybe_gap(
        candidates,
        kind="novelty_and_dedup",
        numerator=counters["low_value_or_repeated"],
        denominator=attempts,
        threshold=0.25,
        objective="Reduce semantically repeated or low-value actions across the whole run.",
        acceptance_signal="Lower repeat/low-value rate with no vulnerability-recall loss.",
    )
    _maybe_gap(
        candidates,
        kind="blocked_route_recovery",
        numerator=counters["blocked"],
        denominator=attempts,
        threshold=0.20,
        objective="Recover from blocked routes using identity-aware alternate evidence paths.",
        acceptance_signal=(
            "More evidence advancement after blocked actions without extra safety violations."
        ),
    )
    _maybe_gap(
        candidates,
        kind="family_classification_and_surface_graph",
        numerator=counters["other_family"],
        denominator=selections,
        threshold=0.25,
        objective=(
            "Improve target-agnostic family classification and canonical surface correlation."
        ),
        acceptance_signal="Fewer unclassified actions and better held-out finding recall.",
    )
    _maybe_gap(
        candidates,
        kind="breadth_to_depth_closure",
        numerator=max(0, counters["probe_actions"] - counters["closure_actions"]),
        denominator=probes,
        threshold=0.70,
        objective="Convert promising probe evidence into bounded exploit and validation closure.",
        acceptance_signal="Higher verified-finding conversion on renamed and reordered fixtures.",
    )
    _maybe_gap(
        candidates,
        kind="model_harness_alignment",
        numerator=counters["harness_overrides"],
        denominator=selections,
        threshold=0.20,
        objective="Make model proposals satisfy harness safety and novelty constraints earlier.",
        acceptance_signal="Fewer harness overrides with unchanged loop and provenance safety.",
    )
    _maybe_gap(
        candidates,
        kind="evidence_efficiency",
        numerator=counters["evidence_not_advanced"],
        denominator=attempts,
        threshold=0.40,
        objective="Prefer actions with a measurable evidence-state transition.",
        acceptance_signal="Higher evidence-advance rate within the same physical-request budget.",
    )
    accounting_failures = (
        counters["incomplete_requests"]
        + counters["unmetered_actions"]
        + counters["lower_bound_accounting"]
    )
    _maybe_gap(
        candidates,
        kind="traffic_accounting_integrity",
        numerator=accounting_failures,
        denominator=max(1, counters["capsules"]),
        threshold=0.01,
        objective="Eliminate incomplete, unmetered, or lower-bound request accounting.",
        acceptance_signal="Exact physical-request accounting in every matched live receipt.",
    )
    candidates.sort(key=lambda gap: (-gap.priority, gap.kind))
    return tuple(candidates[:_MAX_GAPS])


def _maybe_gap(
    output: list[CapabilityGap],
    *,
    kind: str,
    numerator: int,
    denominator: int,
    threshold: float,
    objective: str,
    acceptance_signal: str,
) -> None:
    raw_ratio = numerator / max(1, denominator)
    if numerator <= 0 or raw_ratio < threshold:
        return
    ratio = min(1.0, raw_ratio)
    output.append(
        CapabilityGap(
            kind=kind,
            priority=min(100, max(1, round(ratio * 100))),
            observed_ratio=round(ratio, 6),
            observations=numerator,
            objective=objective,
            acceptance_signal=acceptance_signal,
        )
    )


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ImprovementBriefError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _mapping_sequence(value: object, *, label: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise ImprovementBriefError(f"{label} must be a list")
    output = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ImprovementBriefError(f"{label} entries must be objects")
        output.append({str(key): nested for key, nested in item.items()})
    return tuple(output)


def _count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "BRIEF_SCHEMA_VERSION",
    "CapabilityGap",
    "ImprovementBriefError",
    "build_improvement_brief",
    "validate_improvement_brief",
]
