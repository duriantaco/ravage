from __future__ import annotations

import json
import re
from typing import Any

VALID_ACTIONS = {
    "http_request",
    "run_command",
    "run_python",
    "run_probe",
    "validate_poc",
    "capture_flag",
    "final",
    "invalid",
}

_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"})
_BODYLESS_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_VALIDATE_POC_STEPS = 12

REQUIRED_TEXT_FIELDS = {
    "run_command": "command",
    "run_python": "code",
    "run_probe": "probe",
    "capture_flag": "flag",
}

_FINDING_TEXT_FIELDS = ("vuln_class", "severity", "hypothesis", "impact")
_FINDING_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_MAX_FINDING_FIELD_CHARS = 1_000
_VULN_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


def parse_action(text: str) -> dict[str, object]:
    cleaned = _strip_fence(text.strip())
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        candidates = _json_object_candidates(cleaned)
        if not candidates:
            return invalid_action("model response was not JSON", raw=cleaned)
        first_error = ""
        for candidate in candidates:
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError as exc:
                first_error = first_error or str(exc)
                continue
            if not isinstance(payload, dict):
                continue
            normalized = normalize_action(payload)
            if normalized.get("action") != "invalid":
                return normalized
            first_error = first_error or str(normalized.get("error") or "")
        return invalid_action(
            f"embedded JSON did not parse: {first_error or 'no valid action object'}", raw=cleaned
        )
    if not isinstance(payload, dict):
        return invalid_action("model response JSON was not an object")
    return normalize_action(payload)


def normalize_action(payload: dict[str, Any]) -> dict[str, object]:
    action = _action_name(payload)
    raw_payload = _raw_payload(payload)
    validation_error = _validation_error(action, payload)
    if validation_error:
        return invalid_action(validation_error, raw=raw_payload)

    normalized: dict[str, object] = dict(payload)
    normalized["action"] = action
    if action == "http_request":
        normalized["method"] = _canonical_http_method(payload.get("method"))
    elif action == "validate_poc":
        steps = payload.get("steps")
        assert isinstance(steps, list)
        normalized["steps"] = [
            {**step, "method": _canonical_http_method(step.get("method"))}
            for step in steps
            if isinstance(step, dict)
        ]
    return normalized


def invalid_action(error: str, *, raw: str = "") -> dict[str, object]:
    return {"action": "invalid", "error": error, "raw": raw[:2000]}


def _action_name(payload: dict[str, Any]) -> str:
    return str(payload.get("action") or "").strip()


def _canonical_http_method(value: object) -> str:
    return str(value or "GET").strip().upper()


def _validation_error(action: str, payload: dict[str, Any]) -> str:
    if action not in VALID_ACTIONS:
        return f"invalid action: {action}"
    required_text_field = REQUIRED_TEXT_FIELDS.get(action)
    if required_text_field and not _has_text(payload.get(required_text_field)):
        return f"{action} requires {required_text_field}"
    if action == "http_request":
        return _http_request_validation_error(payload)
    if action == "validate_poc":
        step_error = _validate_poc_steps_validation_error(payload.get("steps"))
        if step_error:
            return step_error
        if payload.get("finding") is not None:
            return _finding_validation_error(payload.get("finding"))
    return ""


def _http_request_validation_error(payload: dict[str, Any]) -> str:  # noqa: PLR0911
    if not (_has_text(payload.get("url")) or _has_text(payload.get("path"))):
        return "http_request requires url or path"
    method = _canonical_http_method(payload.get("method"))
    if method not in _HTTP_METHODS:
        return f"http_request method is not allowed: {method}"
    if payload.get("headers") is not None and not isinstance(payload.get("headers"), dict):
        return "http_request headers must be an object"
    body_fields = [
        name for name in ("body", "json", "form") if payload.get(name) is not None
    ]
    if len(body_fields) > 1:
        return "http_request accepts only one of body, json, or form"
    if method in _BODYLESS_HTTP_METHODS and body_fields:
        return f"{method} http_request cannot include a body"
    if payload.get("form") is not None and not isinstance(payload.get("form"), dict):
        return "http_request form must be an object"
    if payload.get("json") is not None and not isinstance(payload.get("json"), (dict, list)):
        return "http_request json must be an object or list"
    if payload.get("body") is not None and not isinstance(payload.get("body"), str):
        return "http_request body must be a string"
    return ""


def _validate_poc_steps_validation_error(value: object) -> str:
    if not isinstance(value, list) or not value:
        return "validate_poc requires a non-empty steps list"
    if len(value) > _MAX_VALIDATE_POC_STEPS:
        return f"validate_poc accepts at most {_MAX_VALIDATE_POC_STEPS} steps"
    for index, step in enumerate(value, start=1):
        step_error = _validate_poc_step_validation_error(step)
        if step_error:
            return f"validate_poc step {index} {step_error}"
    return ""


def _validate_poc_step_validation_error(value: object) -> str:  # noqa: C901, PLR0911
    if not isinstance(value, dict):
        return "must be an object"
    for location_field in ("url", "path"):
        location = value.get(location_field)
        if location is not None and not isinstance(location, str):
            return f"{location_field} must be a string"
    if not (_has_text(value.get("url")) or _has_text(value.get("path"))):
        return "requires url or path"

    method = _canonical_http_method(value.get("method"))
    if method not in _HTTP_METHODS:
        return f"method is not allowed: {method}"
    if value.get("headers") is not None and not isinstance(value.get("headers"), dict):
        return "headers must be an object"
    if value.get("json") is not None:
        return "does not support json; encode JSON in body and set Content-Type"

    body_fields = [name for name in ("body", "form") if value.get(name) is not None]
    if len(body_fields) > 1:
        return "accepts only one of body or form"
    if method in _BODYLESS_HTTP_METHODS and body_fields:
        return f"{method} request cannot include a body"
    if value.get("form") is not None and not isinstance(value.get("form"), dict):
        return "form must be an object"
    if value.get("body") is not None and not isinstance(value.get("body"), str):
        return "body must be a string"
    return ""


def _finding_validation_error(value: object) -> str:
    if not isinstance(value, dict):
        return "validate_poc finding must be an object"
    for field in _FINDING_TEXT_FIELDS:
        field_value = value.get(field)
        if not _has_text(field_value):
            return f"validate_poc finding requires {field}"
        if len(str(field_value)) > _MAX_FINDING_FIELD_CHARS:
            return f"validate_poc finding {field} is too long"
    severity = str(value.get("severity") or "").strip().lower()
    if severity not in _FINDING_SEVERITIES:
        return (
            "validate_poc finding severity must be critical, high, medium, low, "
            "or informational"
        )
    vuln_class = str(value.get("vuln_class") or "").strip()
    if not _VULN_CLASS_RE.fullmatch(vuln_class):
        return "validate_poc finding vuln_class must be a canonical snake_case identifier"
    exploit_steps = value.get("exploit_steps")
    if not isinstance(exploit_steps, list) or not exploit_steps:
        return "validate_poc finding requires non-empty exploit_steps list"
    if any(not _has_text(item) for item in exploit_steps):
        return "validate_poc finding exploit_steps must contain non-empty text"
    if any(len(str(item)) > _MAX_FINDING_FIELD_CHARS for item in exploit_steps):
        return "validate_poc finding exploit_steps item is too long"
    forbidden = sorted({"endpoint", "proof", "provenance"}.intersection(value))
    if forbidden:
        return (
            "validate_poc finding cannot provide executor-owned fields: "
            + ", ".join(forbidden)
        )
    return ""


def _has_text(value: object) -> bool:
    return bool(str(value or "").strip())


def _raw_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, default=str)


def _strip_fence(text: str) -> str:
    if not text.startswith("```"):
        return text
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    return re.sub(r"\s*```$", "", text)


def _json_object_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
            continue
        if char != "}" or depth == 0:
            continue
        depth -= 1
        if depth == 0 and start is not None:
            candidates.append(text[start : index + 1])
            start = None
    return candidates
