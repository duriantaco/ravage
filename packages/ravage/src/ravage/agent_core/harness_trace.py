from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from ravage.agent_core.agent_strategy import (
    action_fingerprint,
    observation_digest,
)
from ravage.agent_core.recovery_action_contract import RECOVERY_OBJECTIVE_ACTION_STRATEGY
from ravage.agent_core.semantic_routes import semantic_action_fingerprint, semantic_action_route
from ravage.traffic.redaction import redact_headers, redact_text, sanitize_url

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

HARNESS_TRACE_SCHEMA_VERSION = 2
_MAX_SANITIZED_CHARS = 1000

_PROOF_RE = re.compile(r"\b(?:flag|FLAG|HTB|CTF)\{[^}\s]{3,512}\}")
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(authorization|cookie|token|secret|password|passwd|pwd|api[_-]?key|session)"
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Za-z0-9_.-]*(?:token|secret|password|passwd|pwd|api[_-]?key|session)[A-Za-z0-9_.-]*)"
    r"\s*=\s*([^&\s;,\"]+)"
)
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:authorization|cookie|x-api-key|x-auth-token|x-access-token)\s*:\s*).+$"
)
_INLINE_SENSITIVE_HEADER_RE = re.compile(
    r"(?i)((?:authorization|cookie|x-api-key|x-auth-token|x-access-token)\s*:\s*)[^'\"\n]+"
)
_EMBEDDED_URL_RE = re.compile(
    r"(?i)(?:https?://[^\s'\"<>]+|(?<![A-Za-z0-9:/])/[^\s'\"<>]*[?#][^\s'\"<>]+)"
)


def state_trace_snapshot(state: AgentState) -> dict[str, object]:
    return {
        "phase": state.phase,
        "turn": state.turn,
        "flags_count": len(state.flags),
        "primitives": sorted(state.primitives),
        "signal_counts": {key: len(values) for key, values in sorted(state.signals.items())},
        "facts_count": len(state.facts),
        "hypotheses_count": len(state.hypotheses),
        "actions_count": len(state.actions),
        "attempts_count": len(state.attempts),
        "task_status_counts": _task_status_counts(state),
        "last_observation": _sanitize_mapping(state.last_observation),
    }


def state_trace_delta(
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> dict[str, object]:
    before_signal_counts = _mapping_of_ints(before.get("signal_counts"))
    after_signal_counts = _mapping_of_ints(after.get("signal_counts"))
    signal_count_delta: dict[str, int] = {}
    for key in sorted(set(before_signal_counts) | set(after_signal_counts)):
        delta = after_signal_counts.get(key, 0) - before_signal_counts.get(key, 0)
        if delta:
            signal_count_delta[key] = delta

    before_tasks = _mapping_of_ints(before.get("task_status_counts"))
    after_tasks = _mapping_of_ints(after.get("task_status_counts"))
    task_status_delta: dict[str, int] = {}
    for key in sorted(set(before_tasks) | set(after_tasks)):
        delta = after_tasks.get(key, 0) - before_tasks.get(key, 0)
        if delta:
            task_status_delta[key] = delta

    before_primitives = set(_string_list(before.get("primitives")))
    after_primitives = set(_string_list(after.get("primitives")))
    return {
        "phase_changed": before.get("phase") != after.get("phase"),
        "phase_before": before.get("phase"),
        "phase_after": after.get("phase"),
        "flags_delta": _int(after.get("flags_count")) - _int(before.get("flags_count")),
        "new_primitives": sorted(after_primitives - before_primitives),
        "signal_count_delta": signal_count_delta,
        "facts_delta": _int(after.get("facts_count")) - _int(before.get("facts_count")),
        "hypotheses_delta": _int(after.get("hypotheses_count"))
        - _int(before.get("hypotheses_count")),
        "actions_delta": _int(after.get("actions_count")) - _int(before.get("actions_count")),
        "attempts_delta": _int(after.get("attempts_count")) - _int(before.get("attempts_count")),
        "task_status_delta": task_status_delta,
    }


def selection_trace_payload(  # noqa: PLR0913 - flat fields define the trace schema.
    *,
    turn: int,
    action_id: str,
    proposed_action: Mapping[str, object],
    selected_action: Mapping[str, object],
    shadow_action: Mapping[str, object] | None,
    shadow_reason: str,
    repeat_context: str,
) -> dict[str, object]:
    reason = selection_reason(
        proposed_action=proposed_action,
        selected_action=selected_action,
        shadow_reason=shadow_reason,
    )
    return {
        "schema_version": HARNESS_TRACE_SCHEMA_VERSION,
        "turn": turn,
        "action_id": action_id,
        "proposed_action": sanitize_action(proposed_action),
        "selected_action": sanitize_action(selected_action),
        "selected_differs_from_model": _action_signature(proposed_action)
        != _action_signature(selected_action),
        "selection_reason": reason,
        "proposed_route": semantic_action_route(proposed_action, context=repeat_context),
        "selected_route": semantic_action_route(selected_action, context=repeat_context),
        "shadow_router": {
            "would_route": shadow_action is not None,
            "reason": shadow_reason,
            "suggested_action": sanitize_action(shadow_action or {}),
            "suggestion_matches_selected": shadow_action is not None
            and bool(shadow_action)
            and _action_signature(shadow_action) == _action_signature(selected_action),
        },
        "repeat_context": _sanitize_string(repeat_context),
    }


def selection_reason(
    *,
    proposed_action: Mapping[str, object],
    selected_action: Mapping[str, object],
    shadow_reason: str,
) -> str:
    if _action_signature(proposed_action) == _action_signature(selected_action):
        return "model_proposal"
    if selected_action.get("strategy") == RECOVERY_OBJECTIVE_ACTION_STRATEGY:
        return RECOVERY_OBJECTIVE_ACTION_STRATEGY
    if shadow_reason and shadow_reason != "no_shadow_route":
        return shadow_reason
    return "harness_override"


def attempt_record_payload(  # noqa: PLR0913 - mirrors the turn boundary.
    *,
    turn: int,
    action_id: str,
    proposed_action: Mapping[str, object],
    selected_action: Mapping[str, object],
    selection_reason: str,
    repeat_context: str,
    pre_state: Mapping[str, object],
    post_state: Mapping[str, object],
    outcome: Mapping[str, object],
) -> dict[str, object]:
    delta = state_trace_delta(pre_state, post_state)
    classification = str(outcome.get("outcome") or "observed")
    novel = _attempt_has_progress(classification=classification, state_delta=delta)
    return {
        "schema_version": HARNESS_TRACE_SCHEMA_VERSION,
        "turn": turn,
        "action_id": action_id,
        "proposed_action": sanitize_action(proposed_action),
        "selected_action": sanitize_action(selected_action),
        "selected_differs_from_model": _action_signature(proposed_action)
        != _action_signature(selected_action),
        "selection_reason": selection_reason,
        "proposed_route": semantic_action_route(proposed_action, context=repeat_context),
        "selected_route": semantic_action_route(selected_action, context=repeat_context),
        "proposed_fingerprint": semantic_action_fingerprint(
            proposed_action,
            context=repeat_context,
        ),
        "selected_fingerprint": semantic_action_fingerprint(
            selected_action,
            context=repeat_context,
        ),
        "exact_selected_fingerprint": _stable_digest(
            action_fingerprint(
                sanitize_action(selected_action),
                context=repeat_context,
            )
        ),
        "evidence_epoch_before": _evidence_epoch(pre_state),
        "evidence_epoch_after": _evidence_epoch(post_state),
        "outcome": {
            "ok": outcome.get("ok"),
            "stop": outcome.get("stop"),
            "classification": classification,
            "repeat_count": outcome.get("repeat_count"),
        },
        "novel": novel,
        "status": _attempt_status(
            classification=classification,
            novel=novel,
            stop=bool(outcome.get("stop")),
        ),
        "state_delta": delta,
    }


def turn_trace_payload(  # noqa: PLR0913 - flat fields define the trace schema.
    *,
    turn: int,
    action_id: str,
    proposed_action: Mapping[str, object],
    selected_action: Mapping[str, object],
    pre_state: Mapping[str, object],
    post_state: Mapping[str, object],
    outcome: Mapping[str, object],
) -> dict[str, object]:
    observation = str(outcome.get("observation") or "")
    sanitized_observation = _sanitize_string(observation) if observation else ""
    return {
        "schema_version": HARNESS_TRACE_SCHEMA_VERSION,
        "turn": turn,
        "action_id": action_id,
        "proposed_action": sanitize_action(proposed_action),
        "selected_action": sanitize_action(selected_action),
        "selected_differs_from_model": _action_signature(proposed_action)
        != _action_signature(selected_action),
        "outcome": {
            "ok": outcome.get("ok"),
            "stop": outcome.get("stop"),
            "exit_code": outcome.get("exit_code"),
            "timed_out": outcome.get("timed_out"),
            "repeat_count": outcome.get("repeat_count"),
            "classification": outcome.get("outcome"),
            "flag_captured": bool(outcome.get("flag")),
            "observation_digest": observation_digest(sanitized_observation)
            if sanitized_observation
            else {},
        },
        "pre_state": dict(pre_state),
        "post_state": dict(post_state),
        "state_delta": state_trace_delta(pre_state, post_state),
    }


def sanitize_action(action: Mapping[str, object]) -> dict[str, object]:
    kind = str(action.get("action") or "")
    if kind == "http_request":
        return _sanitize_http_step(action)
    sanitized: dict[str, object] = {}
    for key, value in action.items():
        if _SENSITIVE_KEY_RE.search(str(key)):
            sanitized[str(key)] = "[redacted]"
            continue
        if kind == "validate_poc" and str(key) == "steps" and isinstance(value, list):
            sanitized[str(key)] = [
                _sanitize_http_step(item) if isinstance(item, Mapping) else _sanitize_value(item)
                for item in value[:20]
            ]
            continue
        if kind == "validate_poc" and str(key) in {"url", "path"}:
            sanitized[str(key)] = sanitize_url(value)
            continue
        sanitized[str(key)] = _sanitize_value(value)
    return sanitized


def _sanitize_http_step(step: Mapping[str, object]) -> dict[str, object]:
    sanitized: dict[str, object] = {}
    for key, value in step.items():
        text_key = str(key)
        lowered = text_key.casefold()
        if _SENSITIVE_KEY_RE.search(text_key):
            sanitized[text_key] = "[redacted]"
        elif lowered in {"url", "path"}:
            sanitized[text_key] = sanitize_url(value)
        elif lowered == "headers" and isinstance(value, Mapping):
            sanitized[text_key] = _sanitize_headers(value, response=False)
        else:
            sanitized[text_key] = _sanitize_value(value)
    return sanitized


def _sanitize_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _sanitize_mapping(value)
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value[:20]]
    if isinstance(value, tuple):
        return [_sanitize_value(item) for item in value[:20]]
    if isinstance(value, str):
        return _sanitize_string(value)
    return copy.deepcopy(value)


def _sanitize_mapping(value: Mapping[str, object] | Mapping[object, object]) -> dict[str, object]:
    sanitized: dict[str, object] = {}
    for key, item in value.items():
        text_key = str(key)
        lowered = text_key.casefold()
        if _SENSITIVE_KEY_RE.search(text_key):
            sanitized[text_key] = "[redacted]"
            continue
        if lowered in {"url", "final_url", "location"}:
            sanitized[text_key] = sanitize_url(item)
            continue
        if lowered in {"headers", "response_headers"} and isinstance(item, Mapping):
            sanitized[text_key] = _sanitize_headers(item, response=True)
            continue
        if lowered == "error" and isinstance(item, str):
            sanitized[text_key] = redact_text(
                _sanitize_embedded_urls(item),
                max_chars=_MAX_SANITIZED_CHARS,
            )
            continue
        sanitized[text_key] = _sanitize_value(item)
    return sanitized


def _sanitize_headers(headers: Mapping[object, object], *, response: bool) -> dict[str, str]:
    normalized = {str(name): value for name, value in headers.items()}
    return dict(redact_headers(normalized, response=response))


def _sanitize_string(value: str) -> str:
    text = _sanitize_embedded_urls(value)
    text = _PROOF_RE.sub(lambda match: _mask_proof(match.group(0)), text)
    text = _SENSITIVE_HEADER_RE.sub(r"\1[redacted]", text)
    text = _INLINE_SENSITIVE_HEADER_RE.sub(r"\1[redacted]", text)
    text = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1=[redacted]", text)
    if len(text) > _MAX_SANITIZED_CHARS:
        return text[:_MAX_SANITIZED_CHARS] + "... [truncated]"
    return text


def _sanitize_embedded_urls(value: str) -> str:
    return _EMBEDDED_URL_RE.sub(lambda match: sanitize_url(match.group(0)), value)


def _mask_proof(value: str) -> str:
    prefix = value.split("{", 1)[0]
    return f"{prefix}{{REDACTED}}"


def _task_status_counts(state: AgentState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for task in state.tasks:
        status = str(task.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _action_signature(action: Mapping[str, object]) -> str:
    return action_fingerprint(action)


def _attempt_has_progress(
    *,
    classification: str,
    state_delta: Mapping[str, object],
) -> bool:
    if classification in {
        "confirmed_signal",
        "finding_confirmed",
        "new_surface",
        "flag_candidate",
    }:
        return True
    if _int(state_delta.get("flags_delta")) > 0:
        return True
    if _string_list(state_delta.get("new_primitives")):
        return True
    signal_delta = state_delta.get("signal_count_delta")
    return isinstance(signal_delta, Mapping) and any(
        _int(value) > 0 for value in signal_delta.values()
    )


def _attempt_status(*, classification: str, novel: bool, stop: bool) -> str:
    if stop:
        return "completed"
    if novel:
        return "progressed"
    if classification in {"blocked", "same_as_before", "observed"}:
        return "low_value"
    return "attempted"


def _evidence_epoch(snapshot: Mapping[str, object]) -> str:
    material = {
        "flags_count": _int(snapshot.get("flags_count")),
        "primitives": sorted(_string_list(snapshot.get("primitives"))),
        "signal_counts": _mapping_of_ints(snapshot.get("signal_counts")),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return _stable_digest(encoded)


def _stable_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _mapping_of_ints(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, int] = {}
    for key, item in value.items():
        result[str(key)] = _int(item)
    return result


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
