from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from ravage.probe_suite_parts.support import _dict_value, _list_of_dicts

def _sqli_baseline_value(name: str) -> str:
    lowered = name.lower()
    if lowered in {"id", "page", "limit", "offset"} or lowered.endswith("id"):
        return "1"
    if "email" in lowered:
        return "ravage@example.test"
    if "pass" in lowered:
        return "RavagePass123!"
    return "ravage"

def _target_baseline_value(target: dict[str, object]) -> str:
    input_name = str(target.get("input") or "")
    value = str(target.get("baseline") or "")
    if value:
        return value
    url_value = _query_param_value(str(target.get("url") or ""), input_name)
    if url_value:
        return url_value
    return _sqli_baseline_value(input_name)

def _query_param_value(url: str, input_name: str) -> str:
    if not url or not input_name:
        return ""
    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key == input_name and value:
            return value
    return ""

def _form_input_value(form: dict[str, object], input_name: str) -> str:
    for input_field in _list_of_dicts(form.get("inputs")):
        if str(input_field.get("name") or "") != input_name:
            continue
        value = str(input_field.get("value") or "")
        if value:
            return value
    return _sqli_baseline_value(input_name)

def _replay_baseline_value(replay: dict[str, object], input_name: str) -> str:
    form = _dict_value(replay.get("form"))
    value = str(form.get(input_name) or "")
    if value and not _looks_like_sqli_payload(value):
        return value
    url_value = _query_param_value(str(replay.get("url") or ""), input_name)
    if url_value and not _looks_like_sqli_payload(url_value):
        return url_value
    return _sqli_baseline_value(input_name)

def _looks_like_sqli_payload(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "'",
            '"',
            "--",
            "/*",
            " or ",
            " and ",
            "sleep(",
            "pg_sleep",
            "union",
            "select ",
            "updatexml",
            "extractvalue",
        )
    )
