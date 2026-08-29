from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BrowserResult:
    ok: bool
    action: str
    url: str = ""
    data: Any = field(default_factory=dict)
    error: str = ""
    text: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "action": self.action,
            "url": self.url,
            "data": self.data,
            "error": self.error,
            "text": self.text,
        }


class FakeBrowserRuntime:
    def __init__(self, results: dict[str, BrowserResult] | None = None) -> None:
        self.results = results or {}
        self.calls: list[tuple[str, dict[str, object]]] = []

    def run(self, action: str, **kwargs: object) -> BrowserResult:
        self.calls.append((action, dict(kwargs)))
        result = self.results.get(action)
        if result is not None:
            return result
        return BrowserResult(ok=False, action=action, error="fake browser result not configured")

    def __getattr__(self, name: str):
        if not name.startswith("browser_"):
            raise AttributeError(name)

        def _call(**kwargs: object) -> BrowserResult:
            return self.run(name, **kwargs)

        return _call


def _selector_candidates(selector: str) -> tuple[str, ...]:
    candidates: list[str] = []
    for raw_part in selector.split(","):
        part = raw_part.strip()
        if part:
            candidates.append(part)
    if selector not in candidates:
        candidates.insert(0, selector)
    return tuple(dict.fromkeys(candidates))
