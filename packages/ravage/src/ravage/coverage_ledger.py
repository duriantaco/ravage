from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CoverageEntry:
    objective: str
    status: str
    remaining_candidates: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "objective": self.objective,
            "status": self.status,
            "remaining_candidates": self.remaining_candidates,
        }


@dataclass(frozen=True)
class CoverageLedger:
    entries: tuple[CoverageEntry, ...]

    @property
    def confirmed(self) -> tuple[str, ...]:
        return tuple(entry.objective for entry in self.entries if entry.status == "confirmed")

    @property
    def remaining(self) -> tuple[CoverageEntry, ...]:
        return tuple(entry for entry in self.entries if entry.status in {"untested", "in_progress"})

    @property
    def has_remaining(self) -> bool:
        return bool(self.remaining)

    def render_line(self) -> str:
        if not self.entries:
            return ""
        remaining = ", ".join(
            f"{entry.objective}({entry.status},{entry.remaining_candidates} left)"
            for entry in self.remaining
        )
        if not remaining:
            return f"coverage: {len(self.confirmed)}/{len(self.entries)} objectives confirmed; no untested high-value surface remains"
        return f"coverage: {len(self.confirmed)}/{len(self.entries)} objectives confirmed; remaining: {remaining}. Work these before selecting final."

    def to_json(self) -> dict[str, object]:
        return {
            "total_objectives": len(self.entries),
            "remaining_count": len(self.remaining),
            "entries": [entry.to_json() for entry in self.entries],
        }


def build_coverage_ledger(
    objectives: list[str],
    *,
    confirmed: set[str],
    tested_counts: dict[str, int],
    remaining_candidates: dict[str, int],
) -> CoverageLedger:
    entries: list[CoverageEntry] = []
    for objective in dict.fromkeys(objectives):
        remaining = int(remaining_candidates.get(objective, 0))
        if objective in confirmed:
            status = "confirmed"
        elif tested_counts.get(objective, 0) and remaining:
            status = "in_progress"
        elif tested_counts.get(objective, 0):
            status = "exhausted"
        else:
            status = "untested"
        entries.append(CoverageEntry(objective, status, remaining))
    return CoverageLedger(tuple(entries))
