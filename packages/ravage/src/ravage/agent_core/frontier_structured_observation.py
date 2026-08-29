from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from ravage.agent_core.frontier_observation_text import output_observation_texts

_MAX_DECODE_CHARS = 20_000
_MAX_DEPTH = 8
_MAX_MAPPINGS = 128
_EXECUTION_WRAPPER_KEYS = frozenset(
    {
        "args",
        "argv",
        "code",
        "command",
        "exit_code",
        "invocation",
        "script",
        "stderr",
        "stdin",
        "timed_out",
        "tool",
    }
)
_SOURCE_KEYS = frozenset(
    {
        "args",
        "arguments",
        "argv",
        "code",
        "command",
        "input",
        "invocation",
        "request",
        "script",
        "source",
        "stdin",
    }
)


def structured_output_mappings(  # noqa: C901 - bounded recursive shape handling.
    observation: str,
) -> tuple[dict[str, object], ...]:
    """Decode bounded JSON mappings found only in trusted tool output leaves."""
    texts = list(output_observation_texts(observation))
    direct = _direct_output_payload(observation)
    if direct is not None:
        texts.insert(0, observation)

    mappings: list[dict[str, object]] = []
    seen: set[str] = set()

    def remember(value: Mapping[object, object]) -> None:
        if len(mappings) >= _MAX_MAPPINGS:
            return
        normalized = {str(key): child for key, child in value.items()}
        try:
            identity = json.dumps(normalized, sort_keys=True, default=str)
        except (TypeError, ValueError):
            identity = repr(normalized)
        if identity in seen:
            return
        seen.add(identity)
        mappings.append(normalized)

    def walk(value: object, *, depth: int) -> None:
        if depth > _MAX_DEPTH or len(mappings) >= _MAX_MAPPINGS:
            return
        if isinstance(value, str):
            for decoded in _decoded_values(value):
                if decoded != value:
                    walk(decoded, depth=depth + 1)
            return
        if isinstance(value, Mapping):
            remember(value)
            for key, child in value.items():
                if str(key).lower() in _SOURCE_KEYS:
                    continue
                walk(child, depth=depth + 1)
            return
        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            for child in value:
                walk(child, depth=depth + 1)

    for text in dict.fromkeys(texts):
        for decoded in _decoded_values(text):
            walk(decoded, depth=0)
            if len(mappings) >= _MAX_MAPPINGS:
                break
    return tuple(mappings)


def _direct_output_payload(observation: str) -> object | None:
    try:
        payload = json.loads(observation)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, (Mapping, list)):
        return None
    if (
        isinstance(payload, Mapping)
        and {str(key).lower() for key in payload} & _EXECUTION_WRAPPER_KEYS
    ):
        return None
    return payload


def _decoded_values(text: str) -> tuple[object, ...]:
    clipped = text[:_MAX_DECODE_CHARS]
    try:
        return (json.loads(clipped),)
    except (TypeError, ValueError):
        pass

    decoder = json.JSONDecoder()
    decoded: list[object] = []
    cursor = 0
    while cursor < len(clipped) and len(decoded) < _MAX_MAPPINGS:
        starts = [
            index for index in (clipped.find("{", cursor), clipped.find("[", cursor)) if index >= 0
        ]
        if not starts:
            break
        start = min(starts)
        try:
            value, consumed = decoder.raw_decode(clipped[start:])
        except ValueError:
            cursor = start + 1
            continue
        decoded.append(value)
        cursor = start + max(consumed, 1)
    return tuple(decoded)


__all__ = ["structured_output_mappings"]
