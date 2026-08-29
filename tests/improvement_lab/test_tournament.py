from __future__ import annotations

import pytest

from tools.improvement_lab.attestation import EvaluationBinding
from tools.improvement_lab.evaluation import EvaluationConfig, EvaluationReceipt, Rejection
from tools.improvement_lab.tournament import TournamentCandidate, TournamentError, rank_candidates

_TWO_ELIGIBLE = 2
_CANDIDATE_A = f"candidate_{'a' * 24}"
_CANDIDATE_B = f"candidate_{'b' * 24}"
_CANDIDATE_C = f"candidate_{'c' * 24}"


def _binding(candidate_id: str) -> EvaluationBinding:
    return EvaluationBinding(
        campaign_id=f"campaign_{'a' * 24}",
        candidate_id=candidate_id,
        candidate_parent_ref=f"source:{'b' * 40}",
        champion_commit="b" * 40,
        champion_tree="c" * 40,
        candidate_patch_object=f"sha256:{'1' * 64}",
        candidate_config_object=f"sha256:{'2' * 64}",
        evaluation_config_object=f"sha256:{'3' * 64}",
        evaluation_suite_object=f"sha256:{'4' * 64}",
        runner_image=f"example.invalid/referee@sha256:{'5' * 64}",
        champion_receipts_object=f"sha256:{'6' * 64}",
        candidate_receipts_object=f"sha256:{'7' * 64}",
    )


def _receipt(
    *,
    accepted: bool,
    stable: int,
    lower_bound: float,
    gain: int,
    cost: float,
) -> EvaluationReceipt:
    rejection = ()
    if not accepted:
        rejection = (Rejection(gate="reliability", code="candidate_error", message="failed"),)
    return EvaluationReceipt(
        accepted=accepted,
        config=EvaluationConfig(),
        matching={},
        aggregate={
            "promotable_receipts": {"champion": {"fixed": 1}},
            "efficiency": {
                "metrics": {
                    "cost_usd": {"candidate_per_utility": cost},
                    "model_request_count": {"candidate_per_utility": 2.0},
                    "physical_request_count": {"candidate_per_utility": 4.0},
                }
            },
        },
        stability={
            "stable_improved_cases": stable,
            "decisive_win_rate_lower_bound": lower_bound,
            "wins": stable * 3,
            "losses": 0,
            "detection_delta": {
                "evidence_backed_vulnerability_count": gain,
                "verified_vulnerability_count": gain,
                "confirmed_finding_count": gain,
            },
        },
        rejections=rejection,
    )


def test_tournament_ranks_only_accepted_candidates_deterministically() -> None:
    entries = (
        TournamentCandidate(
            _CANDIDATE_B,
            "evaluation_b",
            _receipt(accepted=True, stable=2, lower_bound=0.5, gain=2, cost=0.3),
            _binding(_CANDIDATE_B),
        ),
        TournamentCandidate(
            _CANDIDATE_A,
            "evaluation_a",
            _receipt(accepted=True, stable=2, lower_bound=0.5, gain=2, cost=0.2),
            _binding(_CANDIDATE_A),
        ),
        TournamentCandidate(
            _CANDIDATE_C,
            "evaluation_c",
            _receipt(accepted=False, stable=9, lower_bound=0.9, gain=9, cost=0.01),
            _binding(_CANDIDATE_C),
        ),
    )

    result = rank_candidates(entries)

    assert result["winner_candidate_id"] == _CANDIDATE_A
    assert result["eligible_count"] == _TWO_ELIGIBLE
    assert result["candidates"][0]["rank"] == 1
    assert result["candidates"][2]["rank"] is None
    assert result["promotion_authority"] == "none_human_accept_required"


def test_tournament_rejects_different_panel_or_champion_receipt_set() -> None:
    first = TournamentCandidate(
        _CANDIDATE_A,
        "evaluation_a",
        _receipt(accepted=True, stable=1, lower_bound=0.4, gain=1, cost=0.2),
        _binding(_CANDIDATE_A),
    )
    changed = _binding(_CANDIDATE_B).to_json()
    changed["champion_receipts_object"] = f"sha256:{'9' * 64}"
    second = TournamentCandidate(
        _CANDIDATE_B,
        "evaluation_b",
        _receipt(accepted=True, stable=1, lower_bound=0.4, gain=1, cost=0.2),
        EvaluationBinding.from_mapping(changed),
    )

    with pytest.raises(TournamentError, match="exact campaign, panel"):
        rank_candidates((first, second))
