from __future__ import annotations

import html
import re
from urllib.parse import unquote

from ravage.web_core.http_probe import ProbeResponse, ResponseDelta
from ravage.probe_suite_parts.command.command_payloads import _COMMAND_TIMING_THRESHOLD_MS
from ravage.probe_suite_parts.support import _contains_word, _dedupe


def command_payload_signal(
    response: ProbeResponse,
    expected: str,
    payload: str,
    delta: ResponseDelta,
) -> bool:
    del delta
    if not expected:
        return False
    body = response.body
    if expected not in body and expected not in html.unescape(body):
        return False
    return expected in _body_without_reflected_payload(body, payload)


def _body_without_reflected_payload(body: str, payload: str) -> str:
    raw = body
    unescaped = html.unescape(body)
    for variant in _payload_reflection_variants(payload):
        raw = raw.replace(variant, "")
        unescaped = unescaped.replace(variant, "")
    return raw + "\n" + unescaped


def _payload_reflection_variants(payload: str) -> list[str]:
    return _dedupe(
        [
            payload,
            unquote(payload),
            html.escape(payload, quote=True),
            html.escape(payload, quote=False),
            html.escape(unquote(payload), quote=True),
            html.escape(unquote(payload), quote=False),
        ]
    )


def _command_body_is_stored_eval_payload(body: str, marker: str) -> bool:
    if marker not in body and marker not in html.unescape(body):
        return False
    decoded = html.unescape(body)
    marker_positions: list[int] = []
    for match in re.finditer(re.escape(marker), decoded):
        marker_positions.append(match.start())
    if not marker_positions:
        return False
    for position in marker_positions:
        if not _command_marker_context_is_stored_payload(decoded, position):
            return False
    return True


def _command_marker_context_is_stored_payload(body: str, position: int) -> bool:
    start = max(0, position - 180)
    end = min(len(body), position + 180)
    context = body[start:end].lower()
    if _contains_word(context, ("result", "output", "stdout", "stderr", "response")):
        return False
    return (
        "__import__" in context
        or ".popen(" in context
        or "\"script\"" in context
        or "'script'" in context
        or "json_script_command_payload" in context
    )


def _body_contains_command_marker(body: str, marker: str) -> bool:
    decoded = html.unescape(body)
    if marker not in decoded:
        return False
    return not _command_body_is_stored_eval_payload(decoded, marker)


def _command_timing_signal(control: ProbeResponse, timed: ProbeResponse) -> bool:
    if control.status is None or timed.status is None:
        return False
    return timed.elapsed_ms - control.elapsed_ms >= _COMMAND_TIMING_THRESHOLD_MS


def _has_command_proof(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "command_boundary_proof":
            return True
    return False
