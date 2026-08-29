from __future__ import annotations

from ravage.coverage_ledger import build_coverage_ledger


def test_confirmed_objective_is_not_remaining() -> None:
    ledger = build_coverage_ledger(
        ["sql_injection", "idor"],
        confirmed={"sql_injection"},
        tested_counts={"sql_injection": 3},
        remaining_candidates={"idor": 4},
    )
    statuses = {entry.objective: entry.status for entry in ledger.entries}
    assert statuses["sql_injection"] == "confirmed"
    assert statuses["idor"] == "untested"
    assert ledger.confirmed == ("sql_injection",)
    assert {entry.objective for entry in ledger.remaining} == {"idor"}


def test_in_progress_when_tested_with_candidates_left() -> None:
    ledger = build_coverage_ledger(
        ["idor"],
        confirmed=set(),
        tested_counts={"idor": 2},
        remaining_candidates={"idor": 5},
    )
    assert ledger.entries[0].status == "in_progress"
    assert ledger.has_remaining is True


def test_exhausted_when_tested_but_no_candidates_left() -> None:
    ledger = build_coverage_ledger(
        ["lfi"],
        confirmed=set(),
        tested_counts={"lfi": 6},
        remaining_candidates={"lfi": 0},
    )
    assert ledger.entries[0].status == "exhausted"
    # Exhausted is done work, not remaining breadth.
    assert ledger.has_remaining is False


def test_untested_objective_is_surfaced_even_without_candidates() -> None:
    ledger = build_coverage_ledger(
        ["ssti"],
        confirmed=set(),
        tested_counts={},
        remaining_candidates={},
    )
    entry = ledger.entries[0]
    assert entry.status == "untested"
    assert entry.remaining_candidates == 0
    assert ledger.has_remaining is True


def test_render_line_lists_remaining_first() -> None:
    ledger = build_coverage_ledger(
        ["sql_injection", "idor", "lfi"],
        confirmed={"sql_injection"},
        tested_counts={"lfi": 1},
        remaining_candidates={"idor": 4, "lfi": 2},
    )
    line = ledger.render_line()
    assert line.startswith("coverage: 1/3 objectives confirmed")
    assert "idor(untested,4 left)" in line
    assert "lfi(in_progress,2 left)" in line
    assert "Work these before selecting final." in line


def test_render_line_when_nothing_remains() -> None:
    ledger = build_coverage_ledger(
        ["sql_injection"],
        confirmed={"sql_injection"},
        tested_counts={"sql_injection": 2},
        remaining_candidates={},
    )
    assert ledger.render_line() == (
        "coverage: 1/1 objectives confirmed; no untested high-value surface remains"
    )


def test_empty_scope_renders_empty_line() -> None:
    ledger = build_coverage_ledger([], confirmed=set(), tested_counts={}, remaining_candidates={})
    assert ledger.entries == ()
    assert ledger.render_line() == ""
    assert ledger.has_remaining is False


def test_duplicate_objectives_collapsed() -> None:
    ledger = build_coverage_ledger(
        ["idor", "idor"],
        confirmed=set(),
        tested_counts={},
        remaining_candidates={"idor": 1},
    )
    assert len(ledger.entries) == 1