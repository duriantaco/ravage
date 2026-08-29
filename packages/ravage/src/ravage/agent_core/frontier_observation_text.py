from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

_MAX_DEPTH = 8
_MAX_TEXTS = 128
_OUTPUT_KEYS = frozenset(
    {
        "body",
        "body_snippet",
        "content",
        "observation",
        "output",
        "response",
        "result",
        "stdout",
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


def embedded_observation_texts(  # noqa: C901 - bounded recursive shape handling.
    observation: str,
) -> tuple[str, ...]:
    """Return bounded text leaves from a trusted tool observation wrapper."""
    texts: list[str] = []
    seen: set[str] = set()

    def remember(value: str) -> None:
        if not value or value in seen or len(texts) >= _MAX_TEXTS:
            return
        seen.add(value)
        texts.append(value)

    remember(observation)
    try:
        payload = json.loads(observation)
    except (TypeError, ValueError):
        return tuple(texts)

    def walk(value: object, *, depth: int) -> None:
        if depth > _MAX_DEPTH or len(texts) >= _MAX_TEXTS:
            return
        if isinstance(value, str):
            remember(value)
            return
        if isinstance(value, Mapping):
            for child in value.values():
                walk(child, depth=depth + 1)
            return
        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            for child in value:
                walk(child, depth=depth + 1)

    walk(payload, depth=0)
    return tuple(texts)


def output_observation_texts(  # noqa: C901 - bounded trusted-shape handling.
    observation: str,
) -> tuple[str, ...]:
    """Return trusted output leaves without scanning tool command/source fields."""
    try:
        payload = json.loads(observation)
    except (TypeError, ValueError):
        return (observation,) if observation else ()
    if not isinstance(payload, Mapping):
        return (observation,) if observation else ()

    texts: list[str] = []
    seen: set[str] = set()

    def remember(value: str) -> None:
        if not value or value in seen or len(texts) >= _MAX_TEXTS:
            return
        seen.add(value)
        texts.append(value)

    def walk_output(
        value: object,
        *,
        depth: int,
        trusted_output: bool,
    ) -> None:
        if depth > _MAX_DEPTH or len(texts) >= _MAX_TEXTS:
            return
        if isinstance(value, str):
            if trusted_output:
                remember(value)
            return
        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized_key = str(key).lower()
                if normalized_key in _SOURCE_KEYS:
                    continue
                walk_output(
                    child,
                    depth=depth + 1,
                    trusted_output=(trusted_output or normalized_key in _OUTPUT_KEYS),
                )
            return
        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            for child in value:
                walk_output(
                    child,
                    depth=depth + 1,
                    trusted_output=trusted_output,
                )

    walk_output(payload, depth=0, trusted_output=False)
    return tuple(texts)


__all__ = ["embedded_observation_texts", "output_observation_texts"]
