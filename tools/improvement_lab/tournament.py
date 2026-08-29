"""Deterministic ranking of already accepted candidate evaluation receipts."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

# Tournament errors describe schema/matching failures, never target data.
# ruff: noqa: EM101, TRY003

if TYPE_CHECKING:
    from tools.improvement_lab.attestation import EvaluationBinding
    from tools.improvement_lab.evaluation import EvaluationReceipt

TOURNAMENT_SCHEMA_VERSION: Final = "ravage.improvement-tournament.v1"


class TournamentError(RuntimeError):
    """Raised when candidate evaluations are not safe to compare."""


@dataclass(frozen=True)
class TournamentCandidate:
    candidate_id: str
    evaluation_id: str
    receipt: EvaluationReceipt
    binding: EvaluationBinding


def rank_candidates(entries: Sequence[TournamentCandidate]) -> dict[str, object]:
    """Rank accepted candidates; never mutate a champion pointer."""
    if not entries:
        raise TournamentError("tournament requires at least one candidate evaluation")
    if len({entry.candidate_id for entry in entries}) != len(entries):
        raise TournamentError("tournament candidate identities must be unique")
    _require_comparable(entries)
    rows = [_row(entry) for entry in entries]
    eligible = sorted(
        (row for row in rows if row["accepted"] is True),
        key=_rank_key,
    )
    rejected = sorted(
        (row for row in rows if row["accepted"] is not True),
        key=lambda row: str(row["candidate_id"]),
    )
    ranked = []
    for rank, row in enumerate(eligible, start=1):
        ranked.append({**row, "rank": rank})
    ranked.extend({**row, "rank": None} for row in rejected)
    payload: dict[str, object] = {
        "schema_version": TOURNAMENT_SCHEMA_VERSION,
        "selection_policy": (
            "accepted_only_then_stability_distinct_detection_efficiency_deterministic_tie_break"
        ),
        "candidate_count": len(entries),
        "eligible_count": len(eligible),
        "winner_candidate_id": eligible[0]["candidate_id"] if eligible else None,
        "winner_evaluation_id": eligible[0]["evaluation_id"] if eligible else None,
        "candidates": ranked,
        "promotion_authority": "none_human_accept_required",
    }
    payload["tournament_digest"] = f"sha256:{_digest_json(payload)}"
    return payload


def _require_comparable(entries: Sequence[TournamentCandidate]) -> None:
    first = entries[0].receipt.to_json()
    config = first["config"]
    champion = _champion_aggregate(first)
    comparison_identity = _comparison_identity(entries[0])
    for entry in entries:
        if entry.binding.candidate_id != entry.candidate_id:
            raise TournamentError("tournament binding and candidate identity disagree")
    for entry in entries[1:]:
        payload = entry.receipt.to_json()
        if payload["config"] != config:
            raise TournamentError("tournament evaluations use different gate configurations")
        if _champion_aggregate(payload) != champion:
            raise TournamentError("tournament evaluations do not share one champion baseline")
        if _comparison_identity(entry) != comparison_identity:
            raise TournamentError(
                "tournament evaluations do not share one exact campaign, panel, "
                "and champion receipt set"
            )


def _comparison_identity(entry: TournamentCandidate) -> dict[str, object]:
    binding = entry.binding
    return {
        "campaign_id": binding.campaign_id,
        "candidate_parent_ref": binding.candidate_parent_ref,
        "champion_commit": binding.champion_commit,
        "champion_tree": binding.champion_tree,
        "evaluation_config_object": binding.evaluation_config_object,
        "evaluation_suite_object": binding.evaluation_suite_object,
        "runner_image": binding.runner_image,
        "champion_receipts_object": binding.champion_receipts_object,
    }


def _champion_aggregate(payload: Mapping[str, object]) -> object:
    aggregate = _mapping(payload.get("aggregate"))
    promotable = _mapping(aggregate.get("promotable_receipts"))
    return promotable.get("champion")


def _row(entry: TournamentCandidate) -> dict[str, object]:
    payload = entry.receipt.to_json()
    stability = _mapping(payload.get("stability"))
    detection = _mapping(stability.get("detection_delta"))
    efficiency = _mapping(_mapping(payload.get("aggregate")).get("efficiency"))
    metrics = _mapping(efficiency.get("metrics"))
    return {
        "candidate_id": entry.candidate_id,
        "evaluation_id": entry.evaluation_id,
        "accepted": entry.receipt.accepted,
        "stable_improved_cases": _number(stability.get("stable_improved_cases")),
        "decisive_win_rate_lower_bound": _number(stability.get("decisive_win_rate_lower_bound")),
        "wins": _number(stability.get("wins")),
        "losses": _number(stability.get("losses")),
        "detection_gain": _number(detection.get("evidence_backed_vulnerability_count")),
        "verified_gain": _number(detection.get("verified_vulnerability_count")),
        "confirmed_gain": _number(detection.get("confirmed_finding_count")),
        "cost_per_utility": _candidate_efficiency(metrics, "cost_usd"),
        "model_requests_per_utility": _candidate_efficiency(
            metrics,
            "model_request_count",
        ),
        "physical_requests_per_utility": _candidate_efficiency(
            metrics,
            "physical_request_count",
        ),
        "rejection_codes": [item.code for item in entry.receipt.rejections],
        "receipt_digest": payload["receipt_digest"],
    }


def _rank_key(row: Mapping[str, object]) -> tuple[object, ...]:
    return (
        -_number(row.get("stable_improved_cases")),
        -_number(row.get("decisive_win_rate_lower_bound")),
        -_number(row.get("wins")),
        _number(row.get("losses")),
        -_number(row.get("detection_gain")),
        -_number(row.get("verified_gain")),
        -_number(row.get("confirmed_gain")),
        _sortable_efficiency(row.get("cost_per_utility")),
        _sortable_efficiency(row.get("model_requests_per_utility")),
        _sortable_efficiency(row.get("physical_requests_per_utility")),
        str(row.get("candidate_id") or ""),
    )


def _candidate_efficiency(metrics: Mapping[str, object], field: str) -> float | None:
    metric = _mapping(metrics.get(field))
    value = metric.get("candidate_per_utility")
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def _sortable_efficiency(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return math.inf
    parsed = float(value)
    return parsed if math.isfinite(parsed) else math.inf


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    parsed = float(value)
    return parsed if math.isfinite(parsed) else 0.0


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
    "TOURNAMENT_SCHEMA_VERSION",
    "TournamentCandidate",
    "TournamentError",
    "rank_candidates",
]
