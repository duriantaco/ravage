from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ravage.agent_core.observation_markers import DATABASE_FACT_MARKERS, SQL_RELEVANT_FINDING_TYPES

if TYPE_CHECKING:
    from collections.abc import Mapping

_BOOLEAN_TRUE_TOKENS = ("'1'='1'", '"1"="1"', "1=1", " OR TRUE", " OR true")
_REPLAY_KEYS = ("baseline_replay", "replay", "true_replay", "false_replay")
_ACTIONABLE_LENGTH_DELTA = 25


def sqli_input_signals(payload: Mapping[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        if not _finding_is_sql_relevant(finding):
            continue
        signal = _sqli_input_signal_from_finding(finding)
        if signal:
            signals.append(signal)
    return signals[:12]


def sqli_replay_signals(payload: Mapping[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        if not _finding_replay_relevant(finding):
            continue
        signals.extend(_replay_signals_for_finding(finding))
    return signals[:12]


def sqli_boolean_template_signals(payload: Mapping[str, object]) -> list[str]:
    templates: list[str] = []
    for finding in _findings(payload):
        signal = _boolean_template_signal_from_finding(finding)
        if signal:
            templates.append(signal)
    return templates[:8]


def _sqli_input_signal_from_finding(finding: dict[str, object]) -> str:
    raw_input = finding.get("input")
    if isinstance(raw_input, dict):
        raw_input_value = _dict_value(raw_input)
        return _sqli_structured_input_signal(raw_input_value)
    return _sqli_form_input_signal(finding)


def _sqli_structured_input_signal(raw_input: dict[str, object]) -> str:
    url = str(raw_input.get("url") or "")
    input_name = str(raw_input.get("input") or raw_input.get("name") or "")
    kind = str(raw_input.get("kind") or "")
    return _sqli_input_signal(kind=kind, url=url, input_name=input_name)


def _sqli_form_input_signal(finding: dict[str, object]) -> str:
    raw_form = _dict_value(finding.get("form"))
    url = str(raw_form.get("action") or raw_form.get("url") or "")
    input_name = str(finding.get("input") or "")
    kind = ""
    if raw_form:
        kind = "form"
    return _sqli_input_signal(kind=kind, url=url, input_name=input_name)


def _sqli_input_signal(*, kind: str, url: str, input_name: str) -> str:
    if not url or not input_name:
        return ""
    signal = {"kind": kind, "url": url, "input": input_name}
    return json.dumps(signal, sort_keys=True)


def _replay_signals_for_finding(finding: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for key in _REPLAY_KEYS:
        replay = _dict_value(finding.get(key))
        if not _sqli_replay_signal_valid(replay):
            continue
        replay_payload = dict(replay)
        replay_payload["source"] = key
        signals.append(json.dumps(replay_payload, sort_keys=True))
    return signals


def _finding_replay_relevant(finding: dict[str, object]) -> bool:
    if _finding_type(finding) == "captcha_form_state_replay":
        return True
    return _finding_is_sql_relevant(finding)


def _finding_is_sql_relevant(finding: dict[str, object]) -> bool:
    finding_type = _finding_type(finding).lower()
    if (
        finding_type == "filtered_query_bypass_signal"
        and not _filtered_query_signal_actionable(finding)
    ):
        return False
    if "sql" in finding_type:
        return True
    if finding_type in SQL_RELEVANT_FINDING_TYPES:
        return True

    expected = str(finding.get("expected") or "").lower()
    if expected == "sql":
        return True

    marker_text = _delta_error_marker_text(finding)
    return _contains_database_marker(marker_text)


def _filtered_query_signal_actionable(finding: dict[str, object]) -> bool:
    if bool(finding.get("blocked_payloads_seen")):
        return True
    delta = _dict_value(finding.get("delta"))
    if bool(delta.get("status_changed")):
        return True
    if _int_value(delta.get("length_delta")) >= _ACTIONABLE_LENGTH_DELTA:
        return True
    raw_markers = delta.get("new_error_markers")
    return isinstance(raw_markers, list) and bool(raw_markers)


def _delta_error_marker_text(finding: dict[str, object]) -> str:
    delta = _dict_value(finding.get("delta"))
    raw_markers = delta.get("new_error_markers")
    if not isinstance(raw_markers, list):
        return ""

    return " ".join(str(value).lower() for value in raw_markers if value)


def _contains_database_marker(text: str) -> bool:
    return any(marker in text for marker in DATABASE_FACT_MARKERS)


def _int_value(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return abs(value)
    if isinstance(value, float):
        return abs(int(value))
    if isinstance(value, str) and value.strip():
        try:
            return abs(int(float(value)))
        except ValueError:
            return 0
    return 0


def _boolean_template_signal_from_finding(finding: dict[str, object]) -> str:
    if _finding_type(finding) != "blind_sql_injection_boolean_signal":
        return ""

    true_payload = str(finding.get("true_payload") or "")
    template = _boolean_template_from_payload(true_payload)
    if not template:
        return ""

    raw_input = _dict_value(finding.get("input"))
    signal = {
        "template": template,
        "kind": str(raw_input.get("kind") or ""),
        "url": str(raw_input.get("url") or ""),
        "input": str(raw_input.get("input") or ""),
    }
    return json.dumps(signal, sort_keys=True)


def _boolean_template_from_payload(true_payload: str) -> str:
    if not true_payload:
        return ""
    if "{" in true_payload or "}" in true_payload:
        return ""

    for token in _BOOLEAN_TRUE_TOKENS:
        if token not in true_payload:
            continue
        if token in (" OR TRUE", " OR true"):
            return true_payload.replace(token, " OR ({cond})", 1)
        return true_payload.replace(token, "({cond})", 1)
    return ""


def _sqli_replay_signal_valid(replay: dict[str, object]) -> bool:
    if not replay:
        return False
    method = str(replay.get("method") or "GET").upper()
    if method not in {"GET", "POST"}:
        return False
    if not str(replay.get("url") or ""):
        return False
    payload_field = str(replay.get("payload_field") or "")
    if not payload_field:
        return False
    return method != "POST" or isinstance(replay.get("form"), dict)


def _findings(payload: Mapping[str, object]) -> list[dict[str, object]]:
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        return []

    return [dict(item) for item in raw_findings if isinstance(item, dict)]


def _finding_type(finding: dict[str, object]) -> str:
    return str(finding.get("type") or "")


def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    return {}
