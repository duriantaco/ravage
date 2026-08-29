# This subprocess entrypoint is used only by the autonomous graph route.

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Any

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.bounded_probe import (
    run_bounded_graph_probe,
)


def main() -> None:
    try:
        payload = _mapping(json.load(sys.stdin))
        result, receipt = run_bounded_graph_probe(
            str(payload.get("probe") or ""),
            target_url=str(payload.get("target_url") or ""),
            state=AgentState.from_json(_dict(payload.get("state"))),
            timeout_seconds=_bounded_int(
                payload.get("timeout_seconds"),
                minimum=1,
                maximum=120,
            ),
            target_request_limit=_bounded_int(
                payload.get("target_request_limit"),
                minimum=1,
                maximum=96,
            ),
            traffic_policy_reference=_optional_dict(
                payload.get("traffic_policy_reference")
            ),
        )
        result_payload = json.loads(result.to_text())
        result_payload["graph_target_request_budget"] = receipt
        response = {
            "status": "ok",
            "ok": result.ok,
            "text": json.dumps(
                result_payload,
                indent=2,
                sort_keys=True,
            ),
        }
    except BaseException as exc:  # noqa: BLE001
        response = {
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    sys.stdout.write(json.dumps(response, sort_keys=True))


def _dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _optional_dict(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        message = "traffic policy reference must be a JSON object"
        raise TypeError(message)
    return {str(key): item for key, item in value.items()}


def _mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    message = "graph probe runner input must be a JSON object"
    raise TypeError(message)


def _bounded_int(
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    parsed = int(str(value))
    if not minimum <= parsed <= maximum:
        message = f"integer must be between {minimum} and {maximum}, got {parsed}"
        raise ValueError(message)
    return parsed


if __name__ == "__main__":
    main()
