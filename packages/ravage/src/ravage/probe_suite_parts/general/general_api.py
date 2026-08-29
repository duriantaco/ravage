from __future__ import annotations

import base64
import json
import re
from typing import Protocol
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _body_words,
    _contains_word_in_list,
    _dedupe,
    _path_looks_static_asset,
    _string_items,
    _surface_endpoint_items,
    _url_in_scope,
)
from ravage.web_core.proof_recognizer import recognize_proofs


class _ApiBehaviorSession(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        ...

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        ...


def probe_api_behavior(session: _ApiBehaviorSession, state: AgentState) -> ProbeRunResult:
    endpoints = _api_candidate_endpoints(state)
    if not endpoints:
        endpoints = _surface_endpoint_items(state)[:8]
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for endpoint in endpoints[:12]:
        url = str(endpoint.get("url") or "")
        options = session.request("OPTIONS", url)
        get = _safe_api_get(session, url)
        requests.extend(
            [
                options.summary(body_chars=100) | {"probe_kind": "api_options"},
                get.summary(body_chars=240) | {"probe_kind": "api_get"},
            ]
        )
        if options.headers or get.status in {200, 401, 403, 405, 500}:
            findings.append(
                {
                    "type": "api_endpoint_behavior",
                    "url": url,
                    "hints": _string_items(endpoint.get("hints")),
                    "options": options.summary(body_chars=80),
                    "get": get.summary(body_chars=120),
                }
            )
        token_findings = _jwt_findings_from_response(url=url, response=get)
        findings.extend(token_findings)
        if _endpoint_looks_graphql(endpoint, url):
            graph_findings, graph_requests = _probe_graphql_endpoint(session, url)
            findings.extend(graph_findings)
            requests.extend(graph_requests)
    return ProbeRunResult(
        ok=bool(findings),
        probe="api_behavior",
        summary=f"checked {len(endpoints[:12])} endpoint(s), findings={len(findings)}",
        findings=findings[:30],
        requests=requests[:60],
    )


def _safe_api_get(session: _ApiBehaviorSession, url: str) -> ProbeResponse:
    try:
        return session.get(url)
    except Exception as exc:
        return ProbeResponse(
            method="GET",
            url=url,
            status=None,
            final_url=url,
            elapsed_ms=0,
            body="",
            error=str(exc),
        )


def _probe_graphql_endpoint(session: _ApiBehaviorSession, url: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    probes = [
        ("typename", {"query": "{__typename}"}),
        (
            "introspection",
            {
                "query": (
                    "query IntrospectionProbe { __schema { queryType { name } mutationType { name } "
                    "types { name kind fields { name } } } }"
                )
            },
        ),
    ]
    for label, payload in probes:
        body = json.dumps(payload).encode("utf-8")
        response = session.request("POST", url, data=body, headers={"Content-Type": "application/json"})
        requests.append(response.summary(body_chars=500) | {"probe_kind": f"graphql_{label}"})
        if response.status is None:
            continue
        proofs = recognize_proofs(response.body)
        if proofs:
            findings.append(
                {
                    "type": "graphql_exposed_proof",
                    "url": url,
                    "query": label,
                    "proofs": proofs,
                    "response": response.summary(body_chars=900),
                }
            )
            break
        signal = _graphql_signal(response.body, label=label)
        if signal:
            finding_type = "graphql_probe"
            if label == "introspection":
                finding_type = "graphql_schema_signal"
            findings.append(
                {
                    "type": finding_type,
                    "url": url,
                    "query": label,
                    "signal": signal,
                    "response": response.summary(body_chars=700),
                    "next": "Use the discovered schema/types to query only in-scope fields with bounded depth.",
                }
            )
            if label == "introspection":
                break
    return findings, requests

def _graphql_signal(body: str, *, label: str) -> dict[str, object]:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        text = json.dumps(parsed, sort_keys=True).lower()
        if "__typename" in text:
            return {"kind": "typename", "query": label}
        schema = parsed.get("data")
        if isinstance(schema, dict) and isinstance(schema.get("__schema"), dict):
            return {
                "kind": "introspection_enabled",
                "type_names": _graphql_type_names(schema.get("__schema")),
            }
    lowered = body.lower()
    if "cannot query field" in lowered or "graphql" in lowered:
        return {"kind": "graphql_error", "marker": _body_words(body, ("graphql", "query", "field", "schema"))}
    return {}

def _graphql_type_names(schema: object) -> list[str]:
    if not isinstance(schema, dict):
        return []
    names: list[str] = []
    for item in schema.get("types", []):
        if isinstance(item, dict):
            name = str(item.get("name") or "")
            if name and not name.startswith("__"):
                names.append(name)
    return names[:20]

def _jwt_findings_from_response(*, url: str, response: ProbeResponse) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    text = response.body + "\n" + json.dumps(response.headers, sort_keys=True)
    for token in _jwt_values(text):
        decoded = _decode_jwt_unverified(token)
        if not decoded:
            continue
        header = decoded.get("header")
        payload = decoded.get("payload")
        finding: dict[str, object] = {
            "type": "jwt_observed",
            "url": url,
            "token": token,
            "algorithm": _jwt_algorithm(header),
            "claims": _jwt_public_claims(payload),
            "locations": _jwt_token_locations(response, token),
            "next": (
                "Replay only observed tokens first; try role/id claim mutation "
                "only against same-origin authenticated read paths."
            ),
        }
        weakness = _jwt_weakness_signal(header, payload)
        if weakness:
            finding["weakness"] = weakness
        findings.append(finding)
    return findings[:6]

def _jwt_values(text: str) -> list[str]:
    candidates: list[str] = []
    pattern = r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
    for match in re.finditer(pattern, text):
        candidates.append(match.group(1))
    return _dedupe(candidates)[:8]

def _decode_jwt_unverified(token: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        header = json.loads(_urlsafe_b64decode(parts[0]).decode("utf-8"))
        payload = json.loads(_urlsafe_b64decode(parts[1]).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return {}
    return {"header": header, "payload": payload}

def _urlsafe_b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))

def _jwt_algorithm(header: object) -> str:
    if not isinstance(header, dict):
        return ""
    return str(header.get("alg") or "")

def _jwt_public_claims(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {}
    interesting = (
        "sub",
        "uid",
        "user",
        "user_id",
        "username",
        "email",
        "role",
        "roles",
        "admin",
        "is_admin",
        "tenant",
        "tenant_id",
        "account_id",
        "exp",
        "iat",
    )
    claims: dict[str, object] = {}
    for key in interesting:
        if key in payload:
            claims[key] = payload[key]
    return claims

def _jwt_weakness_signal(header: object, payload: object) -> dict[str, object]:
    alg = _jwt_algorithm(header).lower()
    if alg == "none":
        return {"kind": "unsigned_jwt"}
    if not isinstance(payload, dict):
        return {}
    identity_claims = ("admin", "is_admin", "role", "user_id", "account_id")
    for key in identity_claims:
        if key in payload:
            return {"kind": "identity_or_role_claims_present"}
    return {}

def _jwt_token_locations(response: ProbeResponse, token: str) -> list[str]:
    locations: list[str] = []
    if token in response.body:
        locations.append("body")
    for name, value in response.headers.items():
        if token in str(value):
            locations.append(f"header:{name}")
    return locations[:6]

def _api_candidate_endpoints(state: AgentState) -> list[dict[str, object]]:
    endpoints: list[dict[str, object]] = []
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    for item in _surface_endpoint_items(state):
        url = str(item.get("url") or "")
        if not url or not _url_in_scope(url, origin):
            continue
        hints = _string_items(item.get("hints"))
        if _path_looks_static_asset(urlsplit(url).path) and not _url_looks_api_endpoint(url):
            continue
        if _contains_word_in_list(hints, ("api", "graphql", "interesting_file")) or _url_looks_api_endpoint(url):
            endpoints.append(item)
    endpoints.sort(key=_api_endpoint_sort_key)
    return endpoints

def _api_endpoint_sort_key(endpoint: dict[str, object]) -> tuple[int, str]:
    url = str(endpoint.get("url") or "")
    lowered = url.lower()
    hints = _string_items(endpoint.get("hints"))
    if "openapi" in lowered or "swagger" in lowered or _contains_word_in_list(hints, ("openapi", "swagger")):
        priority = 0
    elif "graphql" in lowered or _contains_word_in_list(hints, ("graphql",)):
        priority = 1
    elif "/api" in lowered or _contains_word_in_list(hints, ("api",)):
        priority = 2
    else:
        priority = 3
    return priority, url

def _url_looks_api_endpoint(url: str) -> bool:
    lowered = url.lower()
    path = urlsplit(url).path.lower()
    return any(
        marker in lowered
        for marker in ("openapi", "swagger", "graphql", "graphiql")
    ) or path == "/api" or path.startswith("/api/")

def _endpoint_looks_graphql(endpoint: dict[str, object], url: str) -> bool:
    hints_text = json.dumps(_string_items(endpoint.get("hints"))).lower()
    if "graphql" in hints_text:
        return True
    return "graphql" in url.lower()
