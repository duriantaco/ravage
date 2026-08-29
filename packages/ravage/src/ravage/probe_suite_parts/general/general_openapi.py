from __future__ import annotations

import json
import re
from urllib.parse import urlencode, urlsplit

from ravage.web_core.http_probe import ProbeResponse, ProbeSession

def _openapi_route_findings(session: ProbeSession, response: ProbeResponse, url: str) -> list[dict[str, object]]:
    if response.status not in {200, 201, 202, 206}:
        return []
    lowered_url = url.lower()
    content_type = str(response.headers.get("content-type") or "").lower()
    if not (
        "openapi" in response.body[:200].lower()
        or "swagger" in lowered_url
        or "openapi" in lowered_url
        or "json" in content_type
    ):
        return []
    try:
        document = json.loads(response.body)
    except json.JSONDecodeError:
        return []
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return []
    routes: list[dict[str, object]] = []
    forms: list[dict[str, object]] = []
    for path, raw_path_item in document["paths"].items():
        if not isinstance(path, str) or not isinstance(raw_path_item, dict):
            continue
        path_parameters = _openapi_parameters(raw_path_item.get("parameters"), document)
        for method, operation in raw_path_item.items():
            method_upper = str(method).upper()
            if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or not isinstance(operation, dict):
                continue
            route_url = session.absolute(_openapi_path_to_request_path(path))
            parameters = path_parameters + _openapi_parameters(operation.get("parameters"), document)
            body_inputs, content_type_name = _openapi_body_inputs(operation.get("requestBody"), document)
            route = {
                "method": method_upper,
                "path": path,
                "url": route_url,
                "parameters": parameters[:20],
                "content_type": content_type_name,
            }
            routes.append(route)
            form = _openapi_route_form(route_url, method_upper, parameters, body_inputs, content_type_name)
            if form:
                forms.append(form)
    if not routes:
        return []
    return [
        {
            "type": "openapi_route_signal",
            "url": url,
            "routes": routes[:24],
            "forms": forms[:12],
            "detail": "OpenAPI/Swagger document exposes callable same-origin routes and request fields.",
        }
    ]

def _openapi_path_to_request_path(path: str) -> str:
    rendered = re.sub(r"\{[^}/]+\}", "1", path.strip() or "/")
    if rendered.startswith("/"):
        return rendered
    return "/" + rendered

def _openapi_parameters(raw_parameters: object, document: dict[str, object]) -> list[dict[str, object]]:
    parameters: list[dict[str, object]] = []
    if not isinstance(raw_parameters, list):
        return parameters
    for raw in raw_parameters:
        parameter = _openapi_resolve_ref(raw, document)
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "")
        location = str(parameter.get("in") or "query")
        if not name:
            continue
        schema = _openapi_resolve_ref(parameter.get("schema"), document)
        parameters.append(
            {
                "name": name,
                "location": location,
                "type": _openapi_schema_type(schema),
                "required": bool(parameter.get("required")),
            }
        )
    return parameters

def _openapi_body_inputs(
    raw_body: object,
    document: dict[str, object],
) -> tuple[list[dict[str, object]], str]:
    body = _openapi_resolve_ref(raw_body, document)
    if not isinstance(body, dict):
        return [], ""
    content = body.get("content")
    if not isinstance(content, dict):
        return [], ""
    for content_type in (
        "multipart/form-data",
        "application/x-www-form-urlencoded",
        "application/json",
    ):
        media = content.get(content_type)
        if not isinstance(media, dict):
            continue
        schema = _openapi_resolve_ref(media.get("schema"), document)
        return _openapi_schema_inputs(schema, document), content_type
    return [], ""

def _openapi_schema_inputs(schema: object, document: dict[str, object]) -> list[dict[str, object]]:
    schema = _openapi_resolve_ref(schema, document)
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    required: set[str] = set()
    raw_required = schema.get("required", [])
    if isinstance(raw_required, list):
        for name in raw_required:
            if name:
                required.add(str(name))
    inputs: list[dict[str, object]] = []
    for name, raw_property in properties.items():
        if not isinstance(name, str) or not name:
            continue
        prop = _openapi_resolve_ref(raw_property, document)
        inputs.append(
            {
                "name": name,
                "type": _openapi_input_type(prop),
                "required": name in required,
            }
        )
    return inputs

def _openapi_input_type(schema: object) -> str:
    if isinstance(schema, dict) and str(schema.get("format") or "").lower() == "binary":
        return "file"
    return _openapi_schema_type(schema)

def _openapi_schema_type(schema: object) -> str:
    if not isinstance(schema, dict):
        return "string"
    schema_type = str(schema.get("type") or "")
    return schema_type or "string"

def _openapi_route_form(
    route_url: str,
    method: str,
    parameters: list[dict[str, object]],
    body_inputs: list[dict[str, object]],
    content_type_name: str,
) -> dict[str, object] | None:
    query_inputs: list[dict[str, object]] = []
    for parameter in parameters:
        location = str(parameter.get("location") or "query")
        if location not in {"query", "body"}:
            continue
        query_inputs.append(
            {
                "name": str(parameter.get("name") or ""),
                "type": str(parameter.get("type") or "string"),
            }
        )
    inputs: list[dict[str, object]] = []
    for item in [*query_inputs, *body_inputs]:
        if item.get("name"):
            inputs.append(item)
    if not inputs:
        return None
    categories = ["api", "openapi"]
    for item in inputs:
        if str(item.get("type") or "").lower() == "file":
            categories.extend(["upload", "file"])
            break
    for name in ("login", "auth", "session"):
        if name in route_url.lower():
            categories.append("auth")
            break
    return {
        "id": "openapi:" + method + ":" + route_url,
        "action": _openapi_action_url(route_url, parameters),
        "method": method,
        "enctype": content_type_name or "application/x-www-form-urlencoded",
        "categories": categories,
        "inputs": inputs[:20],
    }

def _openapi_action_url(route_url: str, parameters: list[dict[str, object]]) -> str:
    query_fields = {
        str(parameter.get("name")): _openapi_default_value(str(parameter.get("type") or "string"))
        for parameter in parameters
        if str(parameter.get("location") or "query") == "query" and parameter.get("name")
    }
    if not query_fields:
        return route_url
    separator = "?"
    if urlsplit(route_url).query:
        separator = "&"
    return route_url + separator + urlencode(query_fields)

def _openapi_default_value(schema_type: str) -> str:
    if schema_type in {"integer", "number"}:
        return "1"
    if schema_type == "boolean":
        return "true"
    return "ravage"

def _openapi_resolve_ref(value: object, document: dict[str, object]) -> object:
    if not isinstance(value, dict):
        return value
    ref = str(value.get("$ref") or "")
    if not ref.startswith("#/"):
        return value
    current: object = document
    for part in ref[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            return value
        current = current[key]
    return current
