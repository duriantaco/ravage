from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_REFLECTION_FINDING_MARKERS = ("reflection", "xss")
_SERVER_FETCH_SINK_MARKERS = (
    "file_get_contents(",
    "curl_exec(",
    "urllib.request.urlopen(",
    "requests.get(",
)
_REMOTE_INPUT_NAMES = frozenset(
    {
        "callback",
        "destination",
        "endpoint",
        "feed",
        "host",
        "link",
        "remote",
        "remote_url",
        "resource",
        "target_url",
        "uri",
        "url",
        "webhook",
    }
)


def recovery_family_override(
    finding_type: str,
    *,
    finding: Mapping[str, object],
    inputs: Sequence[str],
) -> str:
    """Attribute ambiguous reflection findings from target-observed sink semantics."""
    lowered_type = finding_type.lower()
    if not any(marker in lowered_type for marker in _REFLECTION_FINDING_MARKERS):
        return ""
    if not _has_server_fetch_sink(finding):
        return ""
    if not any(_is_remote_input(name) for name in inputs):
        return ""
    return "server_side_request_forgery"


def _has_server_fetch_sink(finding: Mapping[str, object]) -> bool:
    encoded = json.dumps(finding, sort_keys=True, default=str).lower()
    return any(marker in encoded for marker in _SERVER_FETCH_SINK_MARKERS)


def _is_remote_input(name: str) -> bool:
    normalized = name.strip().lower().replace("-", "_")
    return normalized in _REMOTE_INPUT_NAMES or normalized.endswith("_url")
