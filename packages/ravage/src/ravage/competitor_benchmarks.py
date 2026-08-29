from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkClaim:
    system: str
    benchmark: str = ""
    cases: int = 0
    solved: int = 0
    verified: bool = False
    score_percent: float | None = None
    hint_policy: str = ""
    setting: str = ""
    source: str = ""


@dataclass(frozen=True)
class BenchmarkMatrix:
    competitors: tuple[BenchmarkClaim, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "competitors": [claim.__dict__ for claim in self.competitors],
            "unverified_competitor_count": sum(1 for claim in self.competitors if not claim.verified),
        }


def build_matrix(competitor_claims: tuple[BenchmarkClaim, ...] = ()) -> BenchmarkMatrix:
    return BenchmarkMatrix(tuple(competitor_claims))


def render_markdown(matrix: BenchmarkMatrix) -> str:
    lines = ["| system | verified | score |", "| --- | --- | --- |"]
    for claim in matrix.competitors:
        if not claim.verified or claim.score_percent is None:
            score = "no XBEN run scored yet"
        else:
            score = f"{claim.score_percent:.2f}%"
        lines.append(f"| {claim.system} | {'yes' if claim.verified else '**NO**'} | {score} |")
    if not matrix.competitors:
        lines.append("| Ravage | yes | no XBEN run scored yet |")
    return "\n".join(lines)


def ravage_score_from_taxonomy(taxonomy: object, *, hint_policy: str, setting: str) -> BenchmarkClaim:
    cases = len(getattr(taxonomy, "cases", ()) or ())
    solved = sum(
        1
        for case in getattr(taxonomy, "cases", ()) or ()
        if getattr(case, "signals", {}).get("solved")
        or getattr(case, "primary_category", "") == "solved"
    )
    score = None if cases == 0 else solved / cases * 100
    return BenchmarkClaim(
        "Ravage",
        benchmark="XBEN",
        cases=cases,
        solved=solved,
        verified=True,
        score_percent=score,
        hint_policy=hint_policy,
        setting=setting,
    )
