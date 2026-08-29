from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

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

_SECRET_INLINE_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|otp|api[_-]?key|access[_-]?key|authorization)\b"
    r"(\s*[=:]\s*)"
    r"(\"?)([^\"'&\s]+)(\"?)"
)

_MAX_DETAIL_CHARS = 160


def looks_secret(key: str) -> bool:
    lowered = str(key).lower()
    return any(hint in lowered for hint in _SECRET_KEY_HINTS)


def mask_value(key: str, value: object) -> object:
    if looks_secret(key) and value not in (None, ""):
        return MASK
    return value


def mask_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    return {str(key): mask_value(str(key), value) for key, value in mapping.items()}


_SECRET_HEADERS = frozenset(
    {"set-cookie", "cookie", "authorization", "x-api-key", "x-auth-token", "x-csrf-token"}
)


def mask_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in list(headers.items())[:24]:
        if str(key).lower() in _SECRET_HEADERS:
            out[str(key)] = MASK
        else:
            out[str(key)] = _clip(str(value), 200)
    return out


def mask_command_string(text: str) -> str:
    return _SECRET_INLINE_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{MASK}{match.group(5)}",
        str(text),
    )


def describe_action(action: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911
    kind = str(action.get("action") or "")
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
            "detail": _clip(str(action.get("error") or "")),
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
    url = str(step.get("url") or "")
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
    return {
        "action_id": action_id,
        "index": index,
        "method": str(method or "GET").upper(),
        "path": _path_of(url) or url,
        "url": url,
        "fields": mask_mapping(form) if isinstance(form, dict) else {},
        "status": status,
        "ok": ok,
        "response_headers": mask_headers(response_headers),
        "body": _clip(str(body), 800) if isinstance(body, str) and body else "",
    }


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
