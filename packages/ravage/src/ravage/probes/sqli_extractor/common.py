from __future__ import annotations

def _dict_items(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []

    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items

def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    return {}

def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    items: list[str] = []
    for item in value:
        if isinstance(item, str):
            items.append(item)
    return items

def _int_value(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default

def _prioritize(values: list[str], priority: list[str]) -> list[str]:
    ordered = sorted(
        _dedupe(values),
        key=lambda value: (
            priority.index(value.lower()) if value.lower() in priority else len(priority),
            value,
        ),
    )
    return ordered

def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result
