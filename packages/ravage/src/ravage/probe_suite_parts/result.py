from __future__ import annotations

import json
from dataclasses import dataclass, field

ProbeName = str


@dataclass(frozen=True)
class ProbeRunResult:
    ok: bool
    probe: str
    summary: str
    findings: list[dict[str, object]] = field(default_factory=list)
    requests: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    http_request_count: int = 0
    http_request_count_status: str = "exact"

    def to_text(self) -> str:
        return json.dumps(
            {
                "ok": self.ok,
                "probe": self.probe,
                "summary": self.summary,
                "findings": self.findings,
                "requests": self.requests,
                "errors": self.errors,
                "http_request_count": self.http_request_count,
                "http_request_count_status": self.http_request_count_status,
            },
            indent=2,
            sort_keys=True,
        )
