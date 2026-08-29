from __future__ import annotations

import math
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from rich import box
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from typing import TextIO


Tone = Literal["ok", "fail", "warn", "run", "info"]

_TONE_STYLE = {
    "ok": "bold bright_green",
    "fail": "bold bright_red",
    "warn": "bold bright_yellow",
    "run": "bold bright_cyan",
    "info": "dim",
}
_TONE_SYMBOL = {
    "ok": "✓",
    "fail": "×",  # noqa: RUF001 - intentional terminal status glyph
    "warn": "!",
    "run": "›",  # noqa: RUF001 - intentional terminal status glyph
    "info": "·",
}

_COMPACT_WIDTH = 72
_MIN_PANEL_WIDTH = 32
_THOUSAND = 1_000
_MILLION = 1_000_000
_TENTH_SECOND = 0.1
_MINUTE_SECONDS = 60


class _ExplicitLiveConsole(Console):
    @property
    def is_dumb_terminal(self) -> bool:
        """Honor an explicit live-mode selection despite an inherited dumb TERM."""
        return False


@dataclass(frozen=True)
class DashboardActivity:
    label: str
    elapsed_seconds: float
    current: bool = False


@dataclass(frozen=True)
class RunDashboardSnapshot:
    target: str = ""
    model: str = ""
    agent_mode: str = ""
    phase: str = ""
    turn: int = 0
    max_turns: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    candidate_signals: int = 0
    findings: int = 0
    flags: int = 0
    run_elapsed_seconds: float = 0.0
    activities: tuple[DashboardActivity, ...] = ()
    terminal: bool = False


class RichRunDashboard:
    """Scrollback-preserving live status panel for an interactive run."""

    def __init__(
        self,
        *,
        stream: TextIO,
        color: bool,
        unicode: bool,
    ) -> None:
        self.console = _ExplicitLiveConsole(
            file=stream,
            force_terminal=True,
            color_system="standard" if color else None,
            no_color=not color,
            markup=False,
            highlight=False,
            soft_wrap=False,
        )
        self._unicode = unicode
        self._started = False
        self._closed = False
        self._failed = False
        self._live = Live(
            Text(""),
            console=self.console,
            auto_refresh=False,
            refresh_per_second=8,
            screen=False,
            transient=True,
            redirect_stdout=False,
            redirect_stderr=False,
            vertical_overflow="ellipsis",
        )

    def update(self, snapshot: RunDashboardSnapshot, *, width: int) -> bool:
        if self._closed or self._failed:
            return False
        try:
            self.console.width = max(4, width)
            if not self._started:
                self._live.start(refresh=False)
                self._started = True
            self._live.update(self._render(snapshot, width=width), refresh=True)
        except Exception:  # noqa: BLE001 - display failures must not abort an attack.
            self._failed = True
            self.stop()
            return False
        return True

    @property
    def started(self) -> bool:
        return self._started

    def print_line(self, tone: Tone, value: str, *, width: int) -> bool:
        if self._closed or self._failed:
            return False
        symbol = _TONE_SYMBOL.get(tone, "·") if self._unicode else _ascii_symbol(tone)
        line = Text(no_wrap=True, overflow="ellipsis")
        line.append(symbol, style=_TONE_STYLE.get(tone, "dim"))
        line.append(" ")
        line.append(_terminal_text(value, unicode=self._unicode))
        try:
            self.console.width = max(4, width)
            self.console.print(line, overflow="ellipsis", no_wrap=True)
        except Exception:  # noqa: BLE001 - display failures must not abort an attack.
            self._failed = True
            self.stop()
            return False
        return True

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        if not self._started:
            return
        with suppress(Exception):
            self._live.stop()

    def _render(self, snapshot: RunDashboardSnapshot, *, width: int) -> RenderableType:
        if width < _MIN_PANEL_WIDTH:
            activity = snapshot.activities[-1] if snapshot.activities else None
            label = activity.label if activity is not None else "Running"
            elapsed = _duration(
                activity.elapsed_seconds
                if activity is not None
                else snapshot.run_elapsed_seconds
            )
            marker = "✻" if self._unicode else "*"
            status = _terminal_text(
                f"{marker} {label} · {elapsed}",
                unicode=self._unicode,
            )
            text = Text(
                status,
                no_wrap=True,
                overflow="ellipsis",
            )
            text.truncate(max(1, width), overflow="ellipsis")
            return text
        compact = width < _COMPACT_WIDTH
        title = Text("LIVE STATUS", style="bold bright_cyan")
        if snapshot.target and not compact:
            title.append("  ")
            title.append(
                _terminal_text(snapshot.target, unicode=self._unicode),
                style="dim",
            )

        rows: list[RenderableType] = []
        activities = snapshot.activities[-(2 if compact else 3) :]
        if activities:
            table = Table.grid(expand=True, padding=(0, 1))
            table.add_column(width=1, no_wrap=True)
            table.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
            table.add_column(justify="right", no_wrap=True)
            for activity in activities:
                if activity.current:
                    marker = "✻" if self._unicode else "*"
                else:
                    marker = "·" if self._unicode else "."
                marker_style = "bold bright_cyan" if activity.current else "dim"
                table.add_row(
                    Text(marker, style=marker_style),
                    Text(
                        _terminal_text(activity.label, unicode=self._unicode),
                        no_wrap=True,
                        overflow="ellipsis",
                    ),
                    Text(_duration(activity.elapsed_seconds), style="dim"),
                )
            rows.append(table)
        else:
            idle_label = "Finalizing run" if snapshot.terminal else "Waiting for next step"
            rows.append(Text(idle_label, style="dim"))

        rows.extend(self._metrics(snapshot, compact=compact))
        subtitle = _terminal_text(
            _subtitle(snapshot, compact=compact, width=width),
            unicode=self._unicode,
        )
        panel_box = box.ROUNDED if self._unicode else box.ASCII
        return Panel(
            Group(*rows),
            title=title,
            title_align="left",
            subtitle=Text(subtitle, style="dim") if subtitle else None,
            subtitle_align="right",
            border_style="bright_black",
            box=panel_box,
            padding=(0, 1),
            expand=True,
        )

    def _metrics(
        self,
        snapshot: RunDashboardSnapshot,
        *,
        compact: bool,
    ) -> tuple[Text, ...]:
        primary: list[tuple[str, str]] = []
        if snapshot.phase:
            primary.append((snapshot.phase.upper(), "bold"))
        if snapshot.turn:
            turn = str(snapshot.turn)
            if snapshot.max_turns:
                turn += f"/{snapshot.max_turns}"
            primary.append((f"TURN {turn}", "bold"))
        if snapshot.cost_usd > 0:
            primary.append((f"${snapshot.cost_usd:.4f}", "bright_yellow"))
        primary.append(
            (
                _count(snapshot.findings, "finding"),
                "bold bright_red" if snapshot.findings else "dim",
            )
        )
        primary.append(
            (
                _count(snapshot.flags, "flag"),
                "bold bright_magenta" if snapshot.flags else "dim",
            )
        )
        rows = [self._metric_row(primary, compact=compact)]
        if compact:
            return tuple(rows)

        secondary: list[tuple[str, str]] = []
        if snapshot.candidate_signals:
            secondary.append(
                (_count(snapshot.candidate_signals, "signal"), "bright_cyan")
            )
        if snapshot.input_tokens or snapshot.output_tokens:
            secondary.append(
                (
                    (
                        f"{_quantity(snapshot.input_tokens)} in / "
                        f"{_quantity(snapshot.output_tokens)} out"
                    ),
                    "dim",
                )
            )
        secondary.append((f"elapsed {_duration(snapshot.run_elapsed_seconds)}", "dim"))
        rows.append(self._metric_row(secondary, compact=False))
        return tuple(rows)

    def _metric_row(self, values: list[tuple[str, str]], *, compact: bool) -> Text:
        text = Text(no_wrap=True, overflow="ellipsis")
        for index, (value, style) in enumerate(values):
            if index:
                if self._unicode:
                    separator = " · " if compact else "  ·  "
                else:
                    separator = " | " if compact else "  |  "
                text.append(separator, style="bright_black")
            text.append(value, style=style)
        return text


def _subtitle(snapshot: RunDashboardSnapshot, *, compact: bool, width: int) -> str:
    if compact:
        return snapshot.target if len(snapshot.target) <= max(0, width - 8) else ""
    return " · ".join(value for value in (snapshot.model, snapshot.agent_mode) if value)


def _ascii_symbol(tone: Tone) -> str:
    return {"ok": "+", "fail": "x", "warn": "!", "run": ">", "info": "."}.get(
        tone,
        ".",
    )


def _terminal_text(value: str, *, unicode: bool) -> str:
    if unicode:
        return value
    replacements = {
        "·": "|",
        "→": "->",
        "✓": "+",
        "✻": "*",
        "×": "x",  # noqa: RUF001 - source glyph being downgraded
        "›": ">",  # noqa: RUF001 - source glyph being downgraded
        "…": "...",
    }
    return "".join(replacements.get(char, char) for char in value)


def _quantity(value: int) -> str:
    if value < _THOUSAND:
        return str(value)
    if value < _MILLION:
        return f"{value / _THOUSAND:.1f}k"
    return f"{value / _MILLION:.1f}m"


def _count(value: int, noun: str) -> str:
    return f"{value} {noun}{'' if value == 1 else 's'}"


def _duration(seconds: float) -> str:
    if not math.isfinite(seconds) or seconds < 0:
        seconds = 0
    if seconds < _TENTH_SECOND:
        return "<0.1s"
    if seconds < _MINUTE_SECONDS:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), _MINUTE_SECONDS)
    return f"{minutes}m {remainder:02d}s"


__all__ = [
    "DashboardActivity",
    "RichRunDashboard",
    "RunDashboardSnapshot",
    "Tone",
]
