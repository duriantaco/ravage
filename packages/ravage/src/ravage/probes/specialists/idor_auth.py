from __future__ import annotations

import json
import re

from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.shared import (
    _dedupe,
    _signal_form_targets,
    _target_headers,
)

_COOKIE_ATTRIBUTE_NAMES = {
    "domain",
    "expires",
    "httponly",
    "max-age",
    "path",
    "samesite",
    "secure",
}


def _idor_auth_header_contexts(state: AgentState) -> list[dict[str, str]]:
    contexts: list[tuple[int, dict[str, str]]] = []
    cookie_contexts: list[dict[str, str]] = []
    supplemental_contexts: list[dict[str, str]] = []
    cookie_values: list[str] = []
    for raw in state.signals.get("cookies", []):
        cookie_values.extend(_cookie_pair_values(str(raw)))
    combined_cookie = _combined_cookie_header(cookie_values)
    if combined_cookie:
        cookie_context = {"Cookie": combined_cookie}
        cookie_contexts.append(cookie_context)
        contexts.append((0, cookie_context))
    for cookie in _dedupe(cookie_values)[:6]:
        cookie_context = {"Cookie": cookie}
        cookie_contexts.append(cookie_context)
        contexts.append((5, cookie_context))
    for form in _signal_form_targets(state):
        headers = _target_headers({"form": form})
        if headers:
            cleaned = _usable_replay_headers(headers)
            if cleaned:
                contexts.append((_rank_for_form_headers(cleaned), cleaned))
                cookie = cleaned.get("Cookie")
                if cookie:
                    cookie_contexts.append({"Cookie": cookie})
                supplemental = _supplemental_replay_headers(cleaned)
                if supplemental:
                    supplemental_contexts.append(supplemental)
    for raw in state.signals.get("auth_headers", []):
        headers = _headers_from_signal(str(raw))
        cleaned = _usable_replay_headers(headers)
        if cleaned:
            contexts.append((_rank_for_signal_headers(cleaned), cleaned))
            cookie = cleaned.get("Cookie")
            if cookie:
                cookie_contexts.append({"Cookie": cookie})
            supplemental = _supplemental_replay_headers(cleaned)
            if supplemental:
                supplemental_contexts.append(supplemental)
    supplemental_contexts = _dedupe_header_contexts(supplemental_contexts)
    for cookie_headers in cookie_contexts[:3]:
        combined = dict(cookie_headers)
        for supplemental in supplemental_contexts[:6]:
            combined.update(supplemental)
        if len(combined) > len(cookie_headers):
            contexts.append((1, combined))
        for supplemental in supplemental_contexts[:8]:
            combined = dict(cookie_headers)
            combined.update(supplemental)
            contexts.append((1, combined))
    deduped: dict[str, dict[str, str]] = {}
    for _rank, headers in sorted(contexts, key=_ranked_header_context_sort_key):
        normalized = _normalized_headers(headers)
        if not normalized:
            continue
        key = json.dumps(sorted(normalized.items()))
        if key not in deduped:
            deduped[key] = normalized
    return list(deduped.values())[:6]


def _rank_for_form_headers(headers: dict[str, str]) -> int:
    if "Cookie" in headers:
        return 0
    return 2


def _rank_for_signal_headers(headers: dict[str, str]) -> int:
    if "Cookie" in headers:
        return 0
    return 3


def _ranked_header_context_sort_key(item: tuple[int, dict[str, str]]) -> int:
    return item[0]


def _normalized_headers(headers: dict[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        if name and value:
            normalized[name] = value
    return normalized


def _usable_replay_headers(headers: dict[str, str]) -> dict[str, str]:
    usable: dict[str, str] = {}
    for name, value in headers.items():
        header = str(name).strip()
        text = str(value).strip()
        if not header or not text or _placeholder_header_value(text):
            continue
        if header.lower() == "cookie":
            cookie = _combined_cookie_header([text])
            if cookie:
                usable["Cookie"] = cookie
            continue
        usable[header] = text
    return usable


def _supplemental_replay_headers(headers: dict[str, str]) -> dict[str, str]:
    supplemental: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in {"cookie", "authorization"}:
            continue
        if lowered.startswith("x-") or _header_name_has_supplemental_marker(lowered):
            supplemental[name] = value
    return supplemental


def _header_name_has_supplemental_marker(lowered: str) -> bool:
    for token in ("user", "account", "tenant", "org", "member", "customer", "role"):
        if token in lowered:
            return True
    return False


def _placeholder_header_value(value: str) -> bool:
    lowered = value.lower()
    return (
        "redacted" in lowered
        or "..." in value
        or lowered in {"token", "bearer", "changeme", "placeholder"}
    )


def _dedupe_header_contexts(contexts: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: dict[str, dict[str, str]] = {}
    for headers in contexts:
        if not headers:
            continue
        key = json.dumps(sorted(headers.items()))
        deduped[key] = headers
    return list(deduped.values())


def _cookie_pair_values(raw: str) -> list[str]:
    pairs: list[str] = []
    for line in re.split(r"[\r\n]+", raw or ""):
        text = re.sub(r"(?i)^\s*set-cookie:\s*", "", line).strip()
        if not text:
            continue
        for chunk in re.split(r",\s*(?=[A-Za-z0-9_.-]+=)", text):
            for part in chunk.split(";"):
                candidate = part.strip()
                if _cookie_pair_usable(candidate):
                    pairs.append(candidate)
    return _dedupe(pairs)


def _cookie_pair_usable(candidate: str) -> bool:
    if "=" not in candidate:
        return False
    name, value = candidate.split("=", 1)
    name = name.strip()
    value = value.strip()
    if not name or not value:
        return False
    if name.lower() in _COOKIE_ATTRIBUTE_NAMES:
        return False
    for char in name:
        if char.isspace() or char == ",":
            return False
    return True


def _combined_cookie_header(values: list[str]) -> str:
    cookies: dict[str, str] = {}
    for raw in values:
        for pair in _cookie_pair_values(raw):
            name, value = pair.split("=", 1)
            cookies[name.strip()] = value.strip()
    pairs: list[str] = []
    for name, value in cookies.items():
        if name and value:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def _headers_from_signal(raw: str) -> dict[str, str]:
    text = raw.strip()
    if not text or ":" not in text:
        return {}
    name, value = text.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name or not value:
        return {}
    return {name: value}
