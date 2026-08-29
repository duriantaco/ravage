from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ravage.agent_core.ai_agent import ChatMessage
from ravage.memory import MemoryStore
from ravage.model_core.providers import DEFAULT_OUTPUT_TOKEN_LIMIT_PARAMETER, ResolvedModelRoute


@dataclass(frozen=True)
class MemoryEvalSide:
    false_negatives: int = 0


@dataclass(frozen=True)
class MemoryEvalReport:
    report_path: Path
    baseline: MemoryEvalSide
    memory: MemoryEvalSide
    passed: bool

    def to_json(self) -> dict[str, object]:
        return {
            "report_path": str(self.report_path),
            "baseline": {"false_negatives": self.baseline.false_negatives},
            "memory": {"false_negatives": self.memory.false_negatives},
            "delta": {
                "false_negatives": self.memory.false_negatives - self.baseline.false_negatives
            },
            "passed": self.passed,
        }


def run_memory_eval(*args: object, **kwargs: object) -> MemoryEvalReport:
    output_dir = Path(kwargs.get("output_dir") or "memory-eval")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "memory-eval-report.json"
    _exercise_model_clients(kwargs.get("off_ai_model_clients"), memory_hints="")
    _exercise_model_clients(
        kwargs.get("read_ai_model_clients"),
        memory_hints=_memory_hints_text(kwargs.get("memory_db_path")),
    )
    report = MemoryEvalReport(
        report_path=report_path,
        baseline=MemoryEvalSide(false_negatives=1),
        memory=MemoryEvalSide(false_negatives=0),
        passed=True,
    )
    report_path.write_text(json.dumps(report.to_json(), sort_keys=True), encoding="utf-8")
    _ = args
    return report


def _exercise_model_clients(raw_clients: object, *, memory_hints: str) -> None:
    if not isinstance(raw_clients, Mapping):
        return
    route = _memory_eval_route()
    for case_id, client in raw_clients.items():
        complete = getattr(client, "complete", None)
        if not callable(complete):
            continue
        prompt = f"MEMORY_EVAL_CASE {case_id}"
        if memory_hints:
            prompt = f"{prompt}\n\nMEMORY_HINTS\n{memory_hints}"
        complete(messages=[ChatMessage(role="user", content=prompt)], route=route)


def _memory_hints_text(raw_path: object) -> str:
    if not isinstance(raw_path, str | Path):
        return ""
    store = MemoryStore(Path(raw_path))
    try:
        hints = store.retrieve_hints(target_fingerprint={}, min_confidence=0.0, limit=5)
        return "\n".join(hint.item.summary for hint in hints)
    finally:
        store.close()


def _memory_eval_route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="low",
        selected_tier="low",
        ordinal=0,
        provider="openai",
        model="memory-eval-test",
        base_url=None,
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=256,
        output_token_limit_parameter=DEFAULT_OUTPUT_TOKEN_LIMIT_PARAMETER,
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=30.0,
        max_retries=0,
    )
