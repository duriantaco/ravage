from __future__ import annotations

import os
import sys
from typing import TextIO

_ANSI = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
}

_TONE = {
    "ok": ("green", "bold"),
    "fail": ("red", "bold"),
    "warn": ("yellow", "bold"),
    "info": ("cyan", "bold"),
    "muted": ("dim",),
    "accent": ("green", "bold"),
    "agent": ("yellow", "bold"),
}


def color_enabled(stream: TextIO | None = None) -> bool:
    target = stream or sys.stdout
    color_mode = os.environ.get("RAVAGE_COLOR", "on").strip().lower()
    if color_mode in {"always", "1", "true", "yes", "force"}:
        return True
    if color_mode in {"never", "0", "false", "no", "off"}:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(target, "isatty", lambda: False)())


def paint(text: object, *styles: str, stream: TextIO | None = None) -> str:
    value = str(text)
    if not styles or not color_enabled(stream):
        return value
    codes = [_ANSI[style] for style in styles if style in _ANSI]
    if not codes:
        return value
    return f"\x1b[{';'.join(codes)}m{value}\x1b[0m"


def tone(text: object, name: str, *, stream: TextIO | None = None) -> str:
    return paint(text, *_TONE.get(name, ("white",)), stream=stream)


def badge(label: object, name: str = "info", *, stream: TextIO | None = None) -> str:
    return tone(f"[{label}]", name, stream=stream)


def banner(title: str, subtitle: str = "") -> str:
    head = f"{tone('RAVAGE', 'accent')} {paint('//', 'dim')} {tone(title, 'info')}"
    if subtitle:
        return f"{head}\n{paint(subtitle, 'dim')}"
    return head


def status_line(status: object, name: object, detail: object) -> str:
    status_text = str(status)
    style = "ok" if status_text == "ok" else "fail" if status_text == "fail" else "warn"
    return f"{badge(status_text, style)} {tone(f'{name!s:<12}', 'info')} {detail}"
