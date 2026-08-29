from __future__ import annotations

from ravage.competitor_benchmarks import (
    BenchmarkClaim,
    build_matrix,
    ravage_score_from_taxonomy,
    render_markdown,
)
from ravage.failure_taxonomy import build_failure_taxonomy

EXPECTED_CASES = 2
EXPECTED_SOLVE_RATE = 50.0
EXAMPLE_CLAIMS = (
    BenchmarkClaim(
        system="System Alpha",
        benchmark="Benchmark Suite",
        setting="source-aware",
        hint_policy="source-aware",
        score_percent=96.15,
        source="primary source checked",
        verified=True,
    ),
    BenchmarkClaim(
        system="System Beta",
        benchmark="unstated",
        setting="unstated",
        hint_policy="unknown",
        score_percent=91.0,
        source="unverified summary",
        verified=False,
    ),
    BenchmarkClaim(
        system="System Gamma",
        benchmark="Benchmark Suite",
        setting="black-box",
        hint_policy="black-box",
        score_percent=76.9,
        source="primary source checked",
        verified=True,
    ),
)


def test_default_matrix_has_no_runtime_seed_claims() -> None:
    matrix = build_matrix()
    payload = matrix.to_json()
    assert payload["competitors"] == []
    assert payload["unverified_competitor_count"] == 0


def test_unverified_claims_are_marked() -> None:
    # Phase 0 discipline: only primary-source-checked numbers can be verified.
    verified = {claim.system: claim.verified for claim in EXAMPLE_CLAIMS}
    assert verified["System Alpha"] is True
    assert verified["System Beta"] is False
    assert verified["System Gamma"] is True


def test_matrix_counts_unverified_competitors() -> None:
    matrix = build_matrix(competitor_claims=EXAMPLE_CLAIMS)
    payload = matrix.to_json()
    assert payload["unverified_competitor_count"] == 1


def test_render_marks_unverified_rows() -> None:
    matrix = build_matrix(competitor_claims=EXAMPLE_CLAIMS)
    markdown = render_markdown(matrix)
    assert "**NO**" in markdown
    assert "no XBEN run scored yet" in markdown


def test_render_includes_verified_when_flagged() -> None:
    claim = BenchmarkClaim(
        system="System Alpha",
        benchmark="Benchmark Suite",
        setting="source-aware",
        hint_policy="source-aware",
        score_percent=96.15,
        source="repo commit abc123",
        verified=True,
    )
    markdown = render_markdown(build_matrix(competitor_claims=(claim,)))
    assert "| yes |" in markdown
    assert "96.15%" in markdown


def test_ravage_score_from_taxonomy_uses_solve_rate() -> None:
    taxonomy = build_failure_taxonomy(
        {
            "cases": [
                {"benchmark_id": "A", "status": "solved", "solved": True, "tags": []},
                {"benchmark_id": "B", "status": "failed", "solved": False, "tags": []},
            ]
        }
    )
    score = ravage_score_from_taxonomy(
        taxonomy,
        hint_policy="black-box",
        setting="black-box",
    )
    assert score.cases == EXPECTED_CASES
    assert score.score_percent == EXPECTED_SOLVE_RATE

    markdown = render_markdown(build_matrix((score,)))
    assert "50.00%" in markdown


def test_ravage_score_handles_empty_run() -> None:
    taxonomy = build_failure_taxonomy({"cases": []})
    score = ravage_score_from_taxonomy(taxonomy, hint_policy="black-box", setting="bb")
    assert score.score_percent is None
    assert score.cases == 0
