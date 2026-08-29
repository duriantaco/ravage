from __future__ import annotations

import io
from dataclasses import replace

import pytest
from ravage.cli_live_renderer import (
    DashboardActivity,
    RichRunDashboard,
    RunDashboardSnapshot,
)
from rich.console import Console


def _render(snapshot: RunDashboardSnapshot, *, width: int) -> str:
    renderer = RichRunDashboard(stream=io.StringIO(), color=False, unicode=True)
    output = io.StringIO()
    console = Console(
        file=output,
        width=width,
        color_system=None,
        markup=False,
        highlight=False,
    )
    console.print(renderer._render(snapshot, width=width))  # noqa: SLF001
    return output.getvalue()


def _snapshot() -> RunDashboardSnapshot:
    return RunDashboardSnapshot(
        target="https://public-firing-range.appspot.com",
        model="openai/gpt-5.4-mini",
        agent_mode="ctf free roam",
        phase="exploit",
        turn=2,
        max_turns=6,
        input_tokens=36_100,
        output_tokens=454,
        cost_usd=0.0179,
        candidate_signals=3,
        findings=1,
        flags=1,
        run_elapsed_seconds=31.2,
        activities=(
            DashboardActivity("Mapping the target", 7.5),
            DashboardActivity("Validating PoC · turn 2", 4.2, current=True),
        ),
    )


def test_wide_dashboard_shows_context_work_budget_and_security_results() -> None:
    width = 100
    text = _render(_snapshot(), width=width)

    assert "LIVE STATUS" in text
    assert "public-firing-range.appspot.com" in text
    assert "Mapping the target" in text
    assert "Validating PoC · turn 2" in text
    assert "EXPLOIT" in text
    assert "TURN 2/6" in text
    assert "$0.0179" in text
    assert "1 finding" in text
    assert "1 flag" in text
    assert "3 signals" in text
    assert "36.1k in / 454 out" in text
    assert "elapsed 31.2s" in text
    assert all(len(line) <= width for line in text.splitlines())


def test_narrow_dashboard_keeps_decision_critical_fields_without_wrapping() -> None:
    width = 60
    text = _render(_snapshot(), width=width)

    assert "EXPLOIT" in text
    assert "TURN 2/6" in text
    assert "$0.0179" in text
    assert "1 finding" in text
    assert "1 flag" in text
    assert "36.1k in" not in text
    assert all(len(line) <= width for line in text.splitlines())


def test_live_dashboard_preserves_scrollback_and_never_uses_alternate_screen() -> None:
    output = io.StringIO()
    renderer = RichRunDashboard(stream=output, color=True, unicode=True)

    renderer.print_line("run", "Plan · turn 1 · probe xss_context", width=80)
    renderer.update(_snapshot(), width=80)
    renderer.print_line("ok", "Probe finished · 3 candidate signals", width=80)
    renderer.stop()
    renderer.stop()

    raw = output.getvalue()
    assert "Plan · turn 1 · probe xss_context" in raw
    assert "Probe finished · 3 candidate signals" in raw
    assert "\x1b[?1049h" not in raw
    assert "\x1b[?1049l" not in raw
    assert raw.count("\x1b[?25h") == 1


@pytest.mark.parametrize("width", [20, 31])
def test_tiny_dashboard_degrades_to_one_bounded_status_row(width: int) -> None:
    text = _render(_snapshot(), width=width)

    assert "Validating PoC" in text
    assert len(text.splitlines()) == 1
    assert all(len(line) <= width for line in text.splitlines())


def test_minimum_panel_width_omits_target_instead_of_showing_a_fragment() -> None:
    width = 32
    text = _render(_snapshot(), width=width)

    assert "LIVE STATUS" in text
    assert "public-firing-range" not in text
    assert all(len(line) <= width for line in text.splitlines())


def test_idle_and_terminal_dashboard_states_are_distinct() -> None:
    idle = replace(_snapshot(), activities=(), terminal=False)
    terminal = replace(idle, terminal=True)

    idle_text = _render(idle, width=80)
    terminal_text = _render(terminal, width=80)

    assert "Waiting for next step" in idle_text
    assert "Finalizing run" not in idle_text
    assert "Finalizing run" in terminal_text


def test_ascii_dashboard_contains_no_unicode_terminal_glyphs() -> None:
    renderer = RichRunDashboard(stream=io.StringIO(), color=False, unicode=False)
    output = io.StringIO()
    console = Console(file=output, width=60, color_system=None)

    console.print(renderer._render(_snapshot(), width=60))  # noqa: SLF001

    output.getvalue().encode("ascii")
    assert "|" in output.getvalue()
