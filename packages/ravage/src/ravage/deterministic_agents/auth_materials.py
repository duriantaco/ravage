from __future__ import annotations

import base64
import html
import json
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from ravage.deterministic_agents.auth_forms import _body_has_login_form, _body_has_password_form
from ravage.probe_suite_parts.support import _body_words
from ravage.probes.cookie.cookie_deserialization import classify_cookie_value
from ravage.web_core.http_probe import ProbeResponse

_AUTH_HEADER_LIMIT = 10
_TOKEN_FIELD_NAMES = (
    "access_token",
    "auth_token",
    "id_token",
    "session_token",
    "api_token",
    "csrf_token",
    "token",
    "jwt",
    "session",
    "api_key",
)


@dataclass(frozen=True)
class _AuthMaterial:
    name: str
    value: str
    source: str

    def to_json(self) -> dict[str, str]:
        return {
            "name": self.name,
            "value": self.value,
            "source": self.source,
        }


def _auth_materials(response: ProbeResponse) -> list[_AuthMaterial]:
    materials: list[_AuthMaterial] = []
    text = response.body + "\n" + json.dumps(response.headers, sort_keys=True)
    materials.extend(_json_auth_materials(response.body))
    materials.extend(_html_input_auth_materials(response.body))
    materials.extend(_regex_auth_materials(text))
    return _dedupe_auth_materials(materials)


def _json_auth_materials(body: str) -> list[_AuthMaterial]:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return []

    materials: list[_AuthMaterial] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if _looks_like_token_name(str(key)) and isinstance(item, str) and _looks_like_token_value(item):
                    materials.append(_AuthMaterial(name=str(key), value=item, source="json"))
                visit(item)
            return
        if isinstance(value, list):
            for item in value[:20]:
                visit(item)

    visit(parsed)
    return materials


def _html_input_auth_materials(body: str) -> list[_AuthMaterial]:
    materials: list[_AuthMaterial] = []
    for match in re.finditer(r"(?is)<input\b[^>]*>", body):
        tag = match.group(0)
        name = _html_attr(tag, "name")
        value = _html_attr(tag, "value")
        if _looks_like_token_name(name) and _looks_like_token_value(value):
            materials.append(_AuthMaterial(name=name, value=value, source="html_input"))
    return materials


def _html_attr(tag: str, name: str) -> str:
    match = re.search(rf"""(?is)\b{re.escape(name)}\s*=\s*(['"])(.*?)\1""", tag)
    if not match:
        return ""
    return html.unescape(match.group(2))


def _regex_auth_materials(text: str) -> list[_AuthMaterial]:
    materials: list[_AuthMaterial] = []
    for match in re.finditer(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", text):
        if _looks_like_jwt_value(match.group(0)):
            materials.append(_AuthMaterial(name="jwt", value=match.group(0), source="regex"))

    token_names = _token_name_pattern()
    pattern = rf"(?is)\b({token_names})\b\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{{8,512}})"
    for match in re.finditer(pattern, text):
        value = match.group(2).strip().rstrip("',\";<>")
        if _looks_like_token_value(value):
            materials.append(_AuthMaterial(name=match.group(1), value=value, source="regex"))
    return materials


def _token_name_pattern() -> str:
    escaped_names: list[str] = []
    for name in _TOKEN_FIELD_NAMES:
        escaped_names.append(re.escape(name))
    return "|".join(escaped_names)


def _auth_header_variants(materials: list[_AuthMaterial]) -> list[dict[str, str]]:
    headers: list[dict[str, str]] = []
    for material in materials:
        value = material.value
        lowered = material.name.lower()
        cookie_only = _auth_material_cookie_only(lowered, value)
        if not cookie_only:
            headers.append({"Authorization": f"Bearer {value}"})
            headers.append({"Authorization": f"Token {value}"})
            headers.append({"X-Access-Token": value})
            headers.append({"X-Auth-Token": value})
        headers.append({"Cookie": f"{lowered}={value}"})
        if not cookie_only and lowered != "access_token":
            headers.append({"Cookie": f"access_token={value}"})
        if not cookie_only and lowered != "token":
            headers.append({"Cookie": f"token={value}"})
    return _dedupe_headers(headers)


def _auth_material_cookie_only(name: str, value: str) -> bool:
    if name in {"session", "sessionid", "sid", "connect.sid"}:
        return True
    fmt = classify_cookie_value(value)
    return fmt.kind == "flask_signed"


def _looks_like_jwt_value(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_urlsafe_b64decode_text(parts[0]))
    except (ValueError, json.JSONDecodeError):
        return False
    if not isinstance(header, dict):
        return False
    return bool(header.get("alg") or str(header.get("typ") or "").upper() == "JWT")


def _urlsafe_b64decode_text(value: str) -> str:
    padded = value + ("=" * (-len(value) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="replace")


def _authenticated_followup_signal(response: ProbeResponse, *, headers: dict[str, str]) -> dict[str, object]:
    if response.status in {None, 401, 403, 404, 405}:
        return {}
    if _body_has_password_form(response.body) or _body_has_login_form(response.body):
        return {}
    if response.status in {301, 302, 303, 307, 308}:
        location = str(response.headers.get("location") or response.headers.get("Location") or "")
        if _redirect_looks_auth_gate(response.url, location):
            return {}

    markers = _body_words(
        response.body,
        (
            "logout",
            "profile",
            "account",
            "dashboard",
            "settings",
            "admin",
            "email",
            "role",
            "orders",
            "transactions",
            "receipt",
            "invoice",
        ),
    )
    if not markers and not headers:
        return {}
    if markers:
        return {"kind": "authenticated_body_markers", "markers": markers}
    if headers and response.status and 200 <= response.status < 300 and len(response.body.strip()) > 2:
        return {"kind": "auth_material_accepted", "status": response.status, "body_len": len(response.body)}
    return {}


def _redirect_looks_auth_gate(source_url: str, location: str) -> bool:
    if not location:
        return False
    target = urljoin(source_url, location)
    try:
        parsed = urlsplit(target)
    except ValueError:
        return False

    path = parsed.path.lower()
    query = parsed.query.lower()
    if _text_contains_any(path, ("/login", "/signin", "/auth", "/session", "/oauth", "/sso")):
        return True
    if not _text_contains_any(query, ("next=", "redirect=", "return=", "continue=")):
        return False
    return _text_contains_any(target.lower(), ("login", "signin", "auth"))


def _looks_like_token_name(value: str) -> bool:
    lowered = value.lower()
    for name in _TOKEN_FIELD_NAMES:
        if name in lowered:
            return True
    return False


def _looks_like_token_value(value: str) -> bool:
    if len(value) < 8 or len(value) > 1024:
        return False
    for char in value:
        if char.isspace():
            return False
    if not re.search(r"[A-Za-z]", value):
        return False
    return bool(re.search(r"[0-9._~+/=-]", value))


def _dedupe_auth_materials(materials: list[_AuthMaterial]) -> list[_AuthMaterial]:
    seen: set[tuple[str, str]] = set()
    result: list[_AuthMaterial] = []
    for material in materials:
        key = (material.name.lower(), material.value)
        if key in seen:
            continue
        seen.add(key)
        result.append(material)
    return result[:12]


def _dedupe_headers(headers: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    result: list[dict[str, str]] = []
    for header in headers:
        key = tuple(sorted(header.items()))
        if key in seen:
            continue
        seen.add(key)
        result.append(header)
    return result[:_AUTH_HEADER_LIMIT]


def _redact_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if len(value) <= 18:
            redacted[name] = value
        else:
            redacted[name] = value[:10] + "...[redacted]"
    return redacted


def _text_contains_any(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False
