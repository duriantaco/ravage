from __future__ import annotations

import json
from typing import cast

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.sqli.sqli_values import _replay_baseline_value
from ravage.probe_suite_parts.support import (
    _dict_value,
    _string_items,
    _url_looks_static_oauth_redirect,
)

def _confirmed_sqli_input_keys(state: AgentState) -> set[tuple[str, str, str]]:
    keys = set()
    for raw in state.signals.get("sqli_inputs", []):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        sqli_input = cast(dict[str, object], payload)
        keys.add(
            (
                str(sqli_input.get("kind") or ""),
                str(sqli_input.get("url") or ""),
                str(sqli_input.get("input") or ""),
            )
        )
    return keys

def _confirmed_sqli_replay_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for raw in state.signals.get("sqli_replays", []):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        replay = cast(dict[str, object], payload)
        url = str(replay.get("url") or "")
        input_name = str(replay.get("payload_field") or "")
        method = str(replay.get("method") or "GET").upper()
        if not url or not input_name or method not in {"GET", "POST"}:
            continue
        if _url_looks_static_oauth_redirect(url):
            continue
        form = _dict_value(replay.get("form"))
        source_form = _dict_value(replay.get("source_form"))
        target: dict[str, object] = {
            "kind": "replay",
            "url": url,
            "input": input_name,
            "payload_field": input_name,
            "method": method,
            "form": form,
            "headers": _dict_value(replay.get("headers")),
            "encoding": str(replay.get("encoding") or "application/x-www-form-urlencoded"),
            "required_fields": _string_items(replay.get("required_fields")),
            "baseline": _replay_baseline_value(replay, input_name),
            "hints": ["confirmed_sqli_replay"],
            "priority": 1000,
        }
        if source_form:
            target["source_form"] = source_form
        targets.append(target)
    return targets[:8]

def _replay_headers(target: dict[str, object]) -> dict[str, str]:
    headers = _dict_value(target.get("headers"))
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key).strip()
        if not name:
            continue
        if name.lower() == "content-type":
            continue
        cleaned[name] = str(value)
    return cleaned
