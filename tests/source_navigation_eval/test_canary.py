from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tools.source_navigation_eval.canary import ScriptedDriver, run_arm, run_canary
from tools.source_navigation_eval.corpus import load_cases, materialize

if TYPE_CHECKING:
    from pathlib import Path

PAIRS = 3
SCRIPTED_SOURCE_READS = 3


def test_scripted_canary_links_actual_receipts_and_preserves_isolation() -> None:
    result = run_canary(pairs=PAIRS)
    assert result["passed"], result
    assert result["model_calls"] == result["cost_usd"] == 0
    assert result["completed_arms"] == result["planned_arms"] == PAIRS * 2
    route_hashes = {arm["route_sha256"] for arm in result["arms"]}
    assert len(route_hashes) == PAIRS
    for arm in result["arms"]:
        assert not arm["errors"]
        if arm["arm"] == "treatment":
            assert arm["success"]
            assert arm["receipt_route_requests"] == arm["linked_receipts"] == 1
            assert arm["source_reads"] == SCRIPTED_SOURCE_READS
            assert arm["trace"][-1]["task_id"] == "surface-map"
        else:
            assert not arm["success"]
            assert arm["receipt_route_requests"] == arm["linked_receipts"] == 0
            assert not any(turn["route_in_prompt"] for turn in arm["trace"])
    serialized = json.dumps(result)
    assert "/canary_" not in serialized
    assert "/receipt_" not in serialized


@pytest.mark.parametrize(
    ("action", "code"),
    [
        ({"action": "run_probe", "probe": "surface_map"}, "unsupported_action"),
        ({"action": "run_command", "command": "anything"}, "unsupported_action"),
        ({"action": "http_request", "method": "POST", "path": "/"}, "unsupported_method"),
        (
            {"action": "http_request", "method": "GET", "url": "https://example.invalid/"},
            "unexpected_fields",
        ),
        (
            {"action": "http_request", "method": "GET", "path": "//example.invalid/"},
            "invalid_relative_path",
        ),
        (
            {"action": "http_request", "method": "GET", "path": "http://example.invalid/"},
            "invalid_relative_path",
        ),
        (
            {"action": "http_request", "method": "GET", "path": "/\r\nHeader: value"},
            "invalid_relative_path",
        ),
        (
            {"action": "http_request", "method": "GET", "path": "/", "body": "data"},
            "unexpected_fields",
        ),
        (
            {"action": "http_request", "method": "GET", "path": "/", "headers": {}},
            "unexpected_fields",
        ),
    ],
)
def test_unsupported_actions_send_no_traffic(
    tmp_path: Path, action: dict[str, object], code: str
) -> None:
    class InvalidDriver(ScriptedDriver):
        def action(self, _prompt: dict[str, object]) -> dict[str, object]:
            return {"task_id": "surface-map", **action}

    case = next(case for case in load_cases() if case.name == "fastapi-mounted")
    materialize(case, tmp_path)
    result = run_arm(tmp_path, "/api/health", treatment=False, driver=InvalidDriver())
    assert not result["passed"]
    assert result["errors"] == [f"local action rejected: {code}"]
    assert result["request_count"] == 0


def test_partial_source_evidence_cannot_trigger_a_request(tmp_path: Path) -> None:
    class PartialDriver(ScriptedDriver):
        def action(self, _prompt: dict[str, object]) -> dict[str, object]:
            self.turn += 1
            if self.turn == 1:
                return {
                    "action": "source_context",
                    "task_id": "surface-map",
                    "operation": "excerpt",
                    "args": {"path": "service/routes.py", "start_line": 1, "end_line": 40},
                }
            return {
                "action": "http_request",
                "task_id": "surface-map",
                "method": "GET",
                "path": "/api/health",
            }

    case = next(case for case in load_cases() if case.name == "fastapi-mounted")
    materialize(case, tmp_path)
    result = run_arm(tmp_path, "/api/health", treatment=True, driver=PartialDriver())
    assert not result["passed"]
    assert result["request_count"] == result["linked_receipts"] == 0


def test_model_claiming_success_is_not_a_receipt(tmp_path: Path) -> None:
    class ClaimDriver(ScriptedDriver):
        def action(self, _prompt: dict[str, object]) -> dict[str, object]:
            return {"action": "finish", "success": True, "receipt": "invented"}

    case = next(case for case in load_cases() if case.name == "fastapi-mounted")
    materialize(case, tmp_path)
    result = run_arm(tmp_path, "/api/health", treatment=True, driver=ClaimDriver())
    assert not result["passed"]
    assert not result["success"]
    assert result["request_count"] == 0


def test_driver_error_stops_campaign_without_disclosing_error_contents() -> None:
    class BrokenDriver(ScriptedDriver):
        def action(self, _prompt: dict[str, object]) -> dict[str, object]:
            message = "sensitive transport detail"
            raise RuntimeError(message)

    result = run_canary(pairs=PAIRS, driver_factory=BrokenDriver)
    assert not result["passed"]
    assert result["completed_arms"] == 1
    assert result["arms"][0]["errors"] == ["driver failure: RuntimeError"]
    assert "sensitive transport detail" not in json.dumps(result)
