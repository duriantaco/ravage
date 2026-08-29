from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ravage.probe_suite_parts.support import _dedupe, _form_brief, _list_of_dicts, _string_items
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, inject_query_param


def _body_has_password_form(body: str) -> bool:
    return bool(re.search(r"(?is)<form\b.*?<input\b[^>]*(?:type=['\"]?password|name=['\"]?[^'\"]*pass)", body))


def _body_has_login_form(body: str) -> bool:
    if "<form" not in body.lower():
        return False
    return bool(re.search(r"(?is)<input\b[^>]*\bname\s*=\s*['\"]?(?:username|user|login|email)\b", body))


def _form_has_password_input(form: dict[str, object]) -> bool:
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "").lower()
        input_type = str(input_field.get("type") or "").lower()
        if input_type == "password" or "pass" in name:
            return True
    return False


def _forms_from_html(
    final_url: str,
    body: str,
    *,
    auth_headers: dict[str, str],
    base_categories: tuple[str, ...] = ("authenticated",),
) -> list[dict[str, object]]:
    parser = _AuthFollowupHTMLParser(final_url, base_categories=base_categories)
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed target HTML should not discard the auth finding.
        return []

    forms: list[dict[str, object]] = []
    for form in parser.forms:
        if auth_headers:
            form["auth_headers"] = dict(auth_headers)
            form.setdefault("categories", [])
            categories = form["categories"]
            if isinstance(categories, list) and "authenticated" not in categories:
                categories.append("authenticated")
        forms.append(form)
    return forms[:8]


class _AuthFollowupHTMLParser(HTMLParser):
    def __init__(self, final_url: str, *, base_categories: tuple[str, ...]) -> None:
        super().__init__(convert_charrefs=True)
        self.final_url = final_url
        self.base_categories = base_categories
        self.forms: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = _html_attributes(attrs)
        tag = tag.lower()
        if tag == "form":
            action = attributes.get("action") or self.final_url
            self._current = {
                "id": attributes.get("id") or f"auth-followup-form-{len(self.forms)}",
                "action": urljoin(self.final_url, action),
                "method": (attributes.get("method") or "GET").upper(),
                "enctype": attributes.get("enctype") or "",
                "inputs": [],
                "categories": list(self.base_categories),
            }
            return

        if self._current is None:
            return
        if tag not in {"input", "textarea", "select", "button"}:
            return

        inputs = self._current.setdefault("inputs", [])
        if isinstance(inputs, list):
            inputs.append(
                {
                    "name": attributes.get("name") or "",
                    "type": _input_type_for_tag(tag, attributes),
                    "value": attributes.get("value") or "",
                    "disabled": "disabled" in attributes,
                    "required": "required" in attributes,
                    "minlength": attributes.get("minlength") or "",
                    "maxlength": attributes.get("maxlength") or "",
                    "pattern": attributes.get("pattern") or "",
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current is None:
            return
        self._current["categories"] = _form_categories(self._current, base_categories=self.base_categories)
        self.forms.append(self._current)
        self._current = None


def _html_attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for name, value in attrs:
        attributes[name.lower()] = value or ""
    return attributes


def _input_type_for_tag(tag: str, attributes: dict[str, str]) -> str:
    if "hidden" in attributes:
        return "hidden"
    input_type = attributes.get("type")
    if input_type:
        return input_type
    return tag


def _form_categories(form: dict[str, object], *, base_categories: tuple[str, ...]) -> list[str]:
    text = json.dumps(form, sort_keys=True).lower()
    categories = list(base_categories)
    if _text_contains_any(text, ("login", "signin", "username", "password", "email")):
        categories.append("auth")
    if "multipart/form-data" in text or '"type": "file"' in text or "upload" in text:
        categories.extend(["upload", "file"])
    if _text_contains_any(text, ("include", "template", "path", "filename", "url", "xml")):
        categories.append("file")
    if "profile" in text:
        categories.append("profile")
    return _dedupe(categories)


def _auth_form_brief(form: dict[str, object]) -> dict[str, object]:
    brief = _form_brief(form)
    constraints = _form_constraints(form)
    if constraints:
        brief["constraints"] = constraints
    return brief


def _form_constraints(form: dict[str, object]) -> list[dict[str, object]]:
    constraints: list[dict[str, object]] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if not name:
            continue
        item: dict[str, object] = {"name": name}
        for key in ("required", "minlength", "maxlength", "pattern"):
            value = input_field.get(key)
            if value not in (None, "", False):
                item[key] = value
        if len(item) > 1:
            constraints.append(item)
    return constraints[:12]


def _dedupe_dicts(items: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    result: list[dict[str, object]] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _fresh_form_from_response(form: dict[str, object], response: ProbeResponse) -> dict[str, object] | None:
    if response.status not in {200, 201, 202}:
        return None

    candidates = _forms_from_html(response.final_url, response.body, auth_headers={}, base_categories=())
    match = _matching_live_form(form, candidates)
    if match is None:
        return None

    if _form_has_password_input(match):
        script_headers = _script_identity_headers(response.body)
        match = _script_adjusted_password_form(match, response, script_headers)

    categories = _string_items(form.get("categories"))
    if categories:
        current = _string_items(match.get("categories"))
        match["categories"] = _dedupe(current + categories)
    return match


def _matching_live_form(form: dict[str, object], candidates: list[dict[str, object]]) -> dict[str, object] | None:
    original_names = _form_input_names(form)
    original_action = str(form.get("action") or "")
    original_method = str(form.get("method") or "GET").upper()
    best: tuple[int, dict[str, object]] | None = None
    for candidate in candidates:
        candidate_method = str(candidate.get("method") or "GET").upper()
        if candidate_method != original_method:
            continue
        candidate_names = _form_input_names(candidate)
        overlap = len(original_names & candidate_names)
        if original_action and str(candidate.get("action") or "").rstrip("/") == original_action.rstrip("/"):
            overlap += 2
        if overlap <= 0:
            continue
        if best is None or overlap > best[0]:
            best = (overlap, candidate)

    if best is None:
        return None
    return dict(best[1])


def _form_input_names(form: dict[str, object]) -> set[str]:
    names: set[str] = set()
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if name:
            names.add(name)
    return names


def _script_adjusted_password_form(
    form: dict[str, object],
    page: ProbeResponse,
    script_headers: dict[str, str],
) -> dict[str, object]:
    adjusted = dict(form)
    script_target = _script_request_target(page.body, page.final_url)
    if script_target:
        adjusted["method"] = "POST"
        adjusted["action"] = script_target
    elif _script_posts_current_page(page.body):
        adjusted["method"] = "POST"
        adjusted["action"] = page.final_url

    headers = dict(script_headers)
    if _script_uses_ajax(page.body):
        headers.setdefault("X-Requested-With", "XMLHttpRequest")
    if headers:
        adjusted["script_headers"] = headers

    script_fields = _script_literal_data_fields(page.body)
    if script_fields:
        adjusted["script_extra_fields"] = script_fields
    return adjusted


def _script_request_target(body: str, base_url: str) -> str | None:
    for pattern in (
        r"""(?is)\burl\s*:\s*(['"])(.*?)\1""",
        r"""(?is)\bfetch\s*\(\s*(['"])(.*?)\1""",
    ):
        for match in re.finditer(pattern, body):
            value = html.unescape(match.group(2).strip())
            if not value or value.startswith(("javascript:", "data:", "mailto:")):
                continue
            absolute = urljoin(base_url, value)
            target_parts = urlsplit(absolute)
            base_parts = urlsplit(base_url)
            if target_parts.scheme in {"http", "https"} and target_parts.netloc == base_parts.netloc:
                return absolute
            if not urlsplit(value).netloc:
                return absolute
    return None


def _script_uses_ajax(body: str) -> bool:
    lowered = body.lower()
    return "fetch(" in lowered or "$.ajax" in lowered or ".ajax(" in lowered


def _script_posts_current_page(body: str) -> bool:
    if not _script_uses_ajax(body):
        return False
    return bool(re.search(r"(?is)\bmethod\s*:\s*['\"]post['\"]", body))


def _script_identity_headers(body: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    header_blocks = re.findall(r"(?is)\bheaders\s*:\s*\{(.*?)\}", body)
    for block in header_blocks:
        for match in re.finditer(r"""(?is)['"]([^'"]+)['"]\s*:\s*['"]([^'"]{1,160})['"]""", block):
            name = match.group(1).strip()
            value = html.unescape(match.group(2).strip())
            lowered = name.lower()
            if lowered.startswith("x-") or lowered in {"authorization"}:
                headers[name] = value
    return headers


def _script_literal_data_fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for block in re.findall(r"(?is)\bdata\s*:\s*\{(.*?)\}", body):
        for match in re.finditer(
            r"""(?is)(?:['"]?([A-Za-z_][\w.\-]*)['"]?)\s*:\s*(?:(['"])(.*?)\2|\b(true|false|null|\d{1,8})\b)""",
            block,
        ):
            name = match.group(1).strip()

            if match.group(3) is not None:
                value = match.group(3)
            else:
                value = match.group(4)

            if not name or value is None:
                continue
            lowered = name.lower()
            if lowered in {"username", "user", "email", "password", "pass"}:
                continue
            if re.search(r"[+(){};]", value):
                continue
            fields[name] = html.unescape(value.strip())
    return fields


def _form_script_headers(form: dict[str, object]) -> dict[str, str]:
    raw = form.get("script_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key).strip()
        if name:
            headers[name] = str(value)
    return headers


def _submit_form(
    session: ProbeSession,
    form: dict[str, object],
    fields: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
) -> ProbeResponse:
    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or session.target_url)
    if method == "POST":
        return session.post_form(action, fields, headers=headers)

    query_url = action
    for name, value in fields.items():
        query_url = inject_query_param(query_url, name, value)
    return session.get(query_url, headers=headers)


def _text_contains_any(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False
