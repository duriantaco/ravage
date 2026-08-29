from __future__ import annotations

import json
import math
import sys
from typing import Any

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite import run_builtin_probe


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise TypeError("probe runner input must be a JSON object")
        if "traffic_policy" in payload:
            raise ValueError("traffic_policy is unsupported; use traffic_policy_reference")
        result = run_builtin_probe(
            str(payload.get("probe") or ""),
            target_url=str(payload.get("target_url") or ""),
            state=AgentState.from_json(_dict(payload.get("state"))),
            timeout_seconds=_int(payload.get("timeout_seconds"), default=10),
            allow_remote_target=payload.get("allow_remote_target") is True,
            in_scope=_strings(payload.get("in_scope")),
            out_of_scope=_strings(payload.get("out_of_scope")),
            max_rps=_optional_float(payload.get("max_rps")),
            traffic_policy_reference=_optional_dict(payload.get("traffic_policy_reference")),
        )
        response = {"status": "ok", "ok": result.ok, "text": result.to_text()}
    except BaseException as exc:  # noqa: BLE001
        response = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(response, sort_keys=True))


def _dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _int(value: object, *, default: int) -> int:
    try:
        return max(1, min(int(str(value)), 120))
    except (TypeError, ValueError):
        return default


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("max_rps must be a finite number between 0 and 100")
    try:
        parsed = float(str(value))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("max_rps must be a finite number between 0 and 100") from exc
    if not math.isfinite(parsed) or not 0 < parsed <= 100:
        raise ValueError("max_rps must be a finite number between 0 and 100")
    return parsed


def _optional_dict(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TypeError("traffic_policy_reference must be a JSON object")
    return {str(key): item for key, item in value.items()}


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


if __name__ == "__main__":
    main()
