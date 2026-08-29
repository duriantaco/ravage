from __future__ import annotations

# The parser deliberately returns actionable validation messages to operators.
# Keeping those messages at each validation branch is clearer than a large
# exception-class factory for this small, dependency-free format.
# ruff: noqa: EM101, TRY003
import re

_MAX_FRONTMATTER_CHARS = 4_096
_MAX_FRONTMATTER_LINES = 32
_ASCII_CONTROL_LIMIT = 32
_QUOTED_SCALAR_MIN_LENGTH = 2
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class FrontmatterError(ValueError):
    """Raised when a knowledge skill frontmatter block is ambiguous or malformed."""


def parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise FrontmatterError("knowledge skill requires YAML-style frontmatter")

    end_index = _frontmatter_end_index(lines)
    metadata = _parse_metadata_lines(lines[1:end_index])
    body = "\n".join(lines[end_index + 1 :]).strip()
    return metadata, body


def _frontmatter_end_index(lines: list[str]) -> int:
    for index, line in enumerate(lines[1 : _MAX_FRONTMATTER_LINES + 1], start=1):
        if line == "---":
            if sum(len(item) + 1 for item in lines[: index + 1]) > _MAX_FRONTMATTER_CHARS:
                raise FrontmatterError("knowledge skill frontmatter exceeds the size limit")
            return index
    raise FrontmatterError("knowledge skill frontmatter is unterminated or too long")


def _parse_metadata_lines(lines: list[str]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    for line in lines:
        if not line:
            continue
        if line != line.strip() or line.startswith("-"):
            raise FrontmatterError("knowledge skill frontmatter accepts only flat scalars")
        key, sep, value = line.partition(":")
        if not sep:
            raise FrontmatterError("knowledge skill frontmatter contains a malformed field")
        key = key.strip()
        if _KEY_RE.fullmatch(key) is None:
            raise FrontmatterError("knowledge skill frontmatter contains an invalid field name")
        if key in metadata:
            raise FrontmatterError("knowledge skill frontmatter contains a duplicate field")
        metadata[key] = _parse_scalar(value.strip())
    return metadata


def _parse_scalar(value: str) -> object:
    if not value:
        return ""
    if any(ord(character) < _ASCII_CONTROL_LIMIT and character != "\t" for character in value):
        raise FrontmatterError("knowledge skill frontmatter contains a control character")
    if len(value) >= _QUOTED_SCALAR_MIN_LENGTH and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value
