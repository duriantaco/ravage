from __future__ import annotations

import json
from io import StringIO
from typing import TYPE_CHECKING

from ai_agent_fixtures import BRIEF_YAML, ScriptedModelClient
from ravage.benchmark import BenchmarkOverrides
from ravage.memory import MemoryItem, MemoryStore
from ravage.memory_eval import run_memory_eval

if TYPE_CHECKING:
    from pathlib import Path


def test_memory_eval_compares_off_and_read_runs(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        f"""
cases:
  - id: memory-eval-search
    agent: ai-web
    brief: {brief_path}
    target_url: http://127.0.0.1:8765
    fixture: vulnerable_openapi
    expect:
      present:
        - vuln_class: sql_injection
          endpoint_path: /search
          param: q
      absent: []
    budget:
      max_seconds: 5.0
      max_http_requests: 20
""".lstrip(),
        encoding="utf-8",
    )
    memory_db_path = tmp_path / "memory.db"
    store = MemoryStore(memory_db_path)
    try:
        store.add_item(
            MemoryItem.new(
                type="playbook",
                status="verified",
                summary="Search q should be tested with test_sqli_param before reporting.",
                vuln_class="sql_injection",
                target_fingerprint={"objectives": ["sql_injection"]},
                recommended_actions=["Run test_sqli_param on /search q."],
                confidence=0.8,
            )
        )
    finally:
        store.close()

    off_model = ScriptedModelClient(
        [
            {"action": "discover_attack_surface", "args": {}, "rationale": "map"},
            {"action": "final", "args": {"summary": "done"}, "rationale": "done"},
        ]
    )
    read_model = ScriptedModelClient(
        [
            {
                "action": "test_sqli_param",
                "args": {
                    "path": "/search",
                    "method": "GET",
                    "param": "q",
                    "location": "query",
                },
                "rationale": "memory points at q",
            },
            {
                "action": "report_sqli",
                "args": {"path": "/search", "param": "q"},
                "rationale": "confirmed evidence exists",
            },
            {"action": "final", "args": {"summary": "done"}, "rationale": "done"},
        ]
    )

    report = run_memory_eval(
        manifest_path=manifest_path,
        output_dir=tmp_path / "reports",
        memory_db_path=memory_db_path,
        overrides=BenchmarkOverrides(max_turns=3),
        stdout=StringIO(),
        off_ai_model_clients={"memory-eval-search": off_model},
        read_ai_model_clients={"memory-eval-search": read_model},
    )

    saved = json.loads(report.report_path.read_text(encoding="utf-8"))
    off_messages = "\n".join(
        message.content for messages in off_model.messages_seen for message in messages
    )
    read_messages = "\n".join(
        message.content for messages in read_model.messages_seen for message in messages
    )

    assert report.baseline.false_negatives == 1
    assert report.memory.false_negatives == 0
    assert saved["delta"]["false_negatives"] == -1
    assert saved["passed"] is True
    assert "MEMORY_HINTS" not in off_messages
    assert "MEMORY_HINTS" in read_messages
