from __future__ import annotations

import json
import re
from html import unescape
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from ravage.traffic.redaction import REDACTED, redact_headers, redact_text, sanitize_url

MASK = "••••"

_SECRET_KEY_HINTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "otp",
    "apikey",
    "api_key",
    "access_key",
    "authorization",
    "session",
    "cookie",
    "credential",
    "private_key",
)
_SECRET_EXACT_KEYS = frozenset({"code", "pin"})

_SECRET_INLINE_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|otp|api[_-]?key|access[_-]?key|authorization)\b"
    r"(\s*[=:]\s*)"
    r"(\"?)([^\"'&\s]+)(\"?)"
)

_MAX_DETAIL_CHARS = 160
PROBE_HTTP_EVENT_PREFIX = "RAVAGE_PROBE_HTTP "
_MAX_TRACE_QUERY_FIELDS = 12
_MAX_TRACE_VALUE_CHARS = 160
_MAX_TRACE_RESPONSE_CHARS = 240
_HTML_TAG_RE = re.compile(r"<[^>]{0,512}>")
_WHITESPACE_RE = re.compile(r"\s+")
_QUOTED_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)([\"'][^\"']*(?:password|passwd|pwd|secret|token|otp|api[_-]?key|"
    r"access[_-]?key|authorization|session|cookie|credential|private[_-]?key|code|pin)"
    r"[^\"']*[\"']\s*:\s*[\"'])([^\"']*)([\"'])"
)
_EMBEDDED_URL_RE = re.compile(
    r"(?i)(?:https?://[^\s'\"<>]+|(?<![A-Za-z0-9:/])/[^\s'\"<>]*[?#][^\s'\"<>]+)"
)


def looks_secret(key: str) -> bool:
    lowered = str(key).strip().lower()
    return lowered in _SECRET_EXACT_KEYS or any(hint in lowered for hint in _SECRET_KEY_HINTS)


def mask_value(key: str, value: object) -> object:
    if looks_secret(key) and value not in (None, ""):
        return MASK
    return value


def mask_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    return {str(key): mask_value(str(key), value) for key, value in mapping.items()}


def mask_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    bounded = dict(list(headers.items())[:24])
    return dict(redact_headers(bounded, response=True))


def mask_command_string(text: str) -> str:
    return _SECRET_INLINE_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{MASK}{match.group(5)}",
        str(text),
    )


def describe_action(action: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911
    kind = str(action.get("action") or "")
    if kind == "http_request":
        step = _describe_http_step(action)
        method = str(step.get("method") or "GET")
        path = str(step.get("path") or "")
        return {
            "summary": f"HTTP {method}",
            "detail": _clip(path),
            "params": step,
        }
    if kind == "validate_poc":
        return _describe_validate_poc(action)
    if kind == "run_command":
        command = mask_command_string(str(action.get("command") or "").strip())
        return {
            "summary": "Run command",
            "detail": _clip(command),
            "params": {"command": _clip(command, 400)},
        }
    if kind == "run_python":
        return {"summary": "Run Python helper", "detail": "", "params": {}}
    if kind == "run_probe":
        probe = str(action.get("probe") or "").strip()
        return {
            "summary": f"Run probe {probe}".strip(),
            "detail": str(action.get("strategy") or ""),
            "params": {"probe": probe},
        }
    if kind == "capture_flag":
        return {"summary": "Capture flag candidate", "detail": "", "params": {}}
    if kind == "final":
        return {
            "summary": "Finish run",
            "detail": _clip(str(action.get("summary") or "")),
            "params": {},
        }
    if kind == "invalid":
        return {
            "summary": "Invalid action",
            "detail": _safe_error_text(action.get("error"), max_chars=_MAX_DETAIL_CHARS),
            "params": {},
        }
    return {"summary": kind or "action", "detail": "", "params": {}}


def _describe_validate_poc(action: dict[str, Any]) -> dict[str, Any]:
    steps = action.get("steps")
    parsed: list[dict[str, Any]] = []
    if isinstance(steps, list):
        for raw in steps[:12]:
            if isinstance(raw, dict):
                parsed.append(_describe_http_step(raw))

    detail_parts: list[str] = []
    for item in parsed[:4]:
        method = str(item.get("method") or "")
        path = str(item.get("path") or "")
        detail_parts.append(f"{method} {path}".strip())
    detail = ", ".join(detail_parts)

    step_word = "steps"
    if len(parsed) == 1:
        step_word = "step"

    return {
        "summary": f"Validate PoC ({len(parsed)} {step_word})",
        "detail": _clip(detail),
        "params": {"steps": parsed},
    }


def _describe_http_step(step: dict[str, Any]) -> dict[str, Any]:
    method = str(step.get("method") or "GET").upper()
    url = sanitize_url(step.get("url") or step.get("path") or "")
    path = _path_of(url)
    if not path:
        path = url

    form = step.get("form")
    fields: dict[str, Any] = {}
    if isinstance(form, dict):
        fields = mask_mapping(form)

    return {
        "method": method,
        "path": path,
        "url": url,
        "fields": fields,
    }


def http_step_payload(  # noqa: PLR0913 - flat kwargs mirror the recorded payload
    *,
    action_id: str,
    index: int,
    method: str,
    url: str,
    form: dict[str, Any] | None,
    status: int | None,
    ok: bool | None,
    response_headers: object = None,
    body: object = None,
) -> dict[str, Any]:
    safe_url = sanitize_url(url)
    return {
        "action_id": action_id,
        "index": index,
        "method": str(method or "GET").upper(),
        "path": _path_of(safe_url) or safe_url,
        "url": safe_url,
        "fields": mask_mapping(form) if isinstance(form, dict) else {},
        "status": status,
        "ok": ok,
        "response_headers": mask_headers(response_headers),
        "body": _clip(str(body), 800) if isinstance(body, str) and body else "",
    }


def probe_http_exchange_payload(
    event: dict[str, object],
    *,
    index: int,
    probe: str,
) -> dict[str, Any]:
    """Build a bounded, secret-safe live view of one probe HTTP exchange."""
    method = str(event.get("method") or "GET").strip().upper()
    path, query = _trace_request_target(event.get("url"))
    status_value = event.get("response_status")
    status = (
        status_value
        if isinstance(status_value, int) and not isinstance(status_value, bool)
        else None
    )
    elapsed_value = event.get("elapsed_ms")
    elapsed_ms = (
        max(0, elapsed_value)
        if isinstance(elapsed_value, int) and not isinstance(elapsed_value, bool)
        else 0
    )
    request_body = _trace_body(event.get("request_body"), response=False)
    response_body = _trace_body(event.get("response_body"), response=True)
    return {
        "index": max(1, index),
        "probe": _clip(str(probe or "probe"), 80),
        "method": method if re.fullmatch(r"[A-Z]{3,12}", method) else "HTTP",
        "path": path,
        "query": query,
        "request_body": request_body,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "response_summary": response_body,
        "disposition": _clip(str(event.get("disposition") or "sent"), 24),
        "error": _safe_error_text(event.get("error"), max_chars=160),
    }


def _safe_error_text(value: object, *, max_chars: int) -> str:
    text = _EMBEDDED_URL_RE.sub(
        lambda match: sanitize_url(match.group(0)),
        str(value or ""),
    )
    return redact_text(text, max_chars=max_chars)


def _trace_request_target(value: object) -> tuple[str, list[dict[str, str]]]:
    raw_url = str(value or "")
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        return "/", []
    safe_url = sanitize_url(raw_url)
    try:
        path = unquote(urlparse(safe_url).path or "/")
    except ValueError:
        path = "/"
    path = redact_text(path, max_chars=240) or "/"
    try:
        items = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            max_num_fields=_MAX_TRACE_QUERY_FIELDS,
        )
    except ValueError:
        items = []
    query: list[dict[str, str]] = []
    for raw_name, raw_value in items[:_MAX_TRACE_QUERY_FIELDS]:
        name = redact_text(raw_name, max_chars=80)
        if not name:
            continue
        value_text = (
            REDACTED
            if looks_secret(name)
            else redact_text(raw_value, max_chars=_MAX_TRACE_VALUE_CHARS)
        )
        query.append({"name": name, "value": value_text})
    return path, query


def _trace_body(value: object, *, response: bool) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        return ""
    structured = _trace_json_body(text)
    if structured is not None:
        text = structured
    elif response:
        text = unescape(_HTML_TAG_RE.sub(" ", text))
    else:
        form = _trace_form_body(text)
        if form is None:
            return "[request body omitted]"
        text = form
    text = _QUOTED_SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]\3", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    limit = _MAX_TRACE_RESPONSE_CHARS if response else _MAX_TRACE_VALUE_CHARS
    return redact_text(text, max_chars=limit).replace("%5BREDACTED%5D", REDACTED)


def _trace_json_body(value: str) -> str | None:
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(decoded, dict | list):
        return None
    masked = _mask_trace_value(decoded)
    return json.dumps(masked, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _trace_form_body(value: str) -> str | None:
    if "=" not in value or "\n" in value or "\r" in value:
        return None
    try:
        items = parse_qsl(
            value,
            keep_blank_values=True,
            max_num_fields=_MAX_TRACE_QUERY_FIELDS,
        )
    except ValueError:
        return None
    if not items:
        return None
    fields: list[str] = []
    for raw_name, raw_value in items[:_MAX_TRACE_QUERY_FIELDS]:
        name = redact_text(raw_name, max_chars=80)
        if not name:
            continue
        field_value = (
            REDACTED
            if looks_secret(name)
            else redact_text(raw_value, max_chars=_MAX_TRACE_VALUE_CHARS)
        )
        fields.append(f"{name}={field_value}")
    return "&".join(fields)


def _mask_trace_value(value: object, *, depth: int = 0) -> object:
    if depth >= 6:
        return "[nested value omitted]"
    if isinstance(value, dict):
        masked: dict[str, object] = {}
        for raw_key, raw_value in list(value.items())[:24]:
            key = redact_text(raw_key, max_chars=80)
            if not key:
                continue
            masked[key] = (
                REDACTED
                if looks_secret(key)
                else _mask_trace_value(raw_value, depth=depth + 1)
            )
        return masked
    if isinstance(value, list):
        return [_mask_trace_value(item, depth=depth + 1) for item in value[:24]]
    if isinstance(value, str):
        return redact_text(value, max_chars=_MAX_TRACE_VALUE_CHARS)
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(value, max_chars=_MAX_TRACE_VALUE_CHARS)


def _path_of(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    path = parsed.path or ""
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


def _clip(value: str, limit: int = _MAX_DETAIL_CHARS) -> str:
    value = str(value)
    return value if len(value) <= limit else value[: limit - 1] + "…"
