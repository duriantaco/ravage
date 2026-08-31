from __future__ import annotations

import re
import secrets
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from html.parser import HTMLParser
from http.cookies import CookieError, Morsel, SimpleCookie
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import (
    SplitResult,
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from ravage.runtime.common import assert_tool_target_url
from ravage.traffic.policy import TrafficPolicyController
from ravage.web_core.http_probe import ProbeResponse, ProbeSession
from ravage.web_core.scope_policy import url_in_scope_entries

if TYPE_CHECKING:
    from collections.abc import Iterable


class _HeaderMapping(Protocol):
    def get_content_charset(self, failobj: Any = None) -> Any:
        ...

    def get_all(self, name: str, failobj: Any = None) -> Any:
        ...

    def items(self) -> Any:
        ...


HTTP_SCHEMES = {"http", "https"}
HEADER_NAMES = {
    "allow",
    "cache-control",
    "content-length",
    "content-security-policy",
    "content-type",
    "location",
    "server",
    "vary",
    "www-authenticate",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
}
MARKER_WORDS = {
    "csrf": ("csrf", "xsrf", "anti-csrf", "csrf-token", "_token"),
    "debug": ("debug", "traceback", "stack trace", "stacktrace"),
    "error": ("error", "exception", "fatal", "warning"),
    "graphql": ("graphql", "__typename", "graphiql"),
    "json": ("application/json", "json"),
    "sql": (
        "sql syntax",
        "mysqli",
        "mysql",
        "sqlite",
        "postgres",
        "pdoexception",
        "database",
        "connection failed",
    ),
    "upload": ("upload", "multipart/form-data", 'type="file"', "type='file'", "filename"),
    "xml": ("application/xml", "text/xml", "<?xml", ".xml"),
}
SKIPPED_PROBE_WORDS = (
    "create",
    "delete",
    "destroy",
    "disable",
    "enable",
    "logout",
    "remove",
    "update",
)
MAX_BODY_BYTES = 1_000_000
MAX_PROBES_PER_RUN = 8
MAX_PROBES_PER_PAGE = 3
MAX_FORM_INPUTS_IN_PROBE = 20
MAX_REDIRECT_HOPS = 5
MAX_EXTERNAL_SCRIPTS_PER_RUN = 8
MAX_EXTERNAL_SCRIPT_BYTES_PER_RUN = 800_000


@dataclass
class ReconInput:
    name: str
    input_type: str
    value: str = ""
    required: bool = False
    disabled: bool = False
    minlength: str = ""
    maxlength: str = ""
    pattern: str = ""

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "type": self.input_type,
            "value": self.value,
            "required": self.required,
            "disabled": self.disabled,
        }
        if self.minlength:
            payload["minlength"] = self.minlength
        if self.maxlength:
            payload["maxlength"] = self.maxlength
        if self.pattern:
            payload["pattern"] = self.pattern
        return payload


@dataclass
class ReconForm:
    method: str
    action: str
    inputs: list[ReconInput] = field(default_factory=list)
    enctype: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "method": self.method,
            "action": self.action,
            "enctype": self.enctype,
            "inputs": _input_json_items(self.inputs),
        }


@dataclass
class ReconPage:
    url: str
    status: int | None
    final_url: str
    title: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, object]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[ReconForm] = field(default_factory=list)
    request_templates: list[dict[str, object]] = field(default_factory=list)
    query_parameter_names: list[str] = field(default_factory=list)
    interesting_markers: list[str] = field(default_factory=list)
    reflected_parameters: list[dict[str, str]] = field(default_factory=list)
    error: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "url": self.url,
            "status": self.status,
            "final_url": self.final_url,
            "title": self.title,
            "headers": dict(self.headers),
            "cookies": _dict_items(self.cookies),
            "links": list(self.links),
            "scripts": list(self.scripts),
            "forms": _form_json_items(self.forms),
            "request_templates": _dict_items(self.request_templates),
            "query_parameter_names": list(self.query_parameter_names),
            "interesting_markers": list(self.interesting_markers),
            "reflected_parameters": _string_dict_items(self.reflected_parameters),
            "error": self.error,
        }


@dataclass
class ReconResult:
    target_url: str
    origin: str
    pages: list[ReconPage] = field(default_factory=list)
    query_parameter_names: list[str] = field(default_factory=list)
    interesting_markers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    http_request_count: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "target_url": self.target_url,
            "origin": self.origin,
            "pages": _page_json_items(self.pages),
            "query_parameter_names": list(self.query_parameter_names),
            "interesting_markers": list(self.interesting_markers),
            "errors": list(self.errors),
            "http_request_count": self.http_request_count,
        }


def _input_json_items(inputs: list[ReconInput]) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for input_field in inputs:
        items.append(input_field.to_json())
    return items


def _form_json_items(forms: list[ReconForm]) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for form in forms:
        items.append(form.to_json())
    return items


def _page_json_items(pages: list[ReconPage]) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for page in pages:
        items.append(page.to_json())
    return items


def _dict_items(items: list[dict[str, object]]) -> list[dict[str, object]]:
    copied: list[dict[str, object]] = []
    for item in items:
        copied.append(dict(item))
    return copied


def _string_dict_items(items: list[dict[str, str]]) -> list[dict[str, str]]:
    copied: list[dict[str, str]] = []
    for item in items:
        copied.append(dict(item))
    return copied


@dataclass(frozen=True)
class _ParsedReconDocument:
    title: str
    headers: dict[str, str]
    cookies: list[dict[str, object]]
    links: list[str]
    scripts: list[str]
    forms: list[ReconForm]
    request_templates: list[dict[str, object]]
    body_text: str
    query_parameter_names: list[str]
    interesting_markers: list[str]


@dataclass(frozen=True, slots=True, repr=False)
class PassiveReconParameter:
    """One transient parameter name and location extracted without its value."""

    name: str
    location: str


@dataclass(frozen=True, slots=True, repr=False)
class PassiveReconOperation:
    """One transient request declaration from an already-fetched document.

    ``url`` can contain concrete identifiers and query values. Callers must keep
    this object in memory and project it through the canonical surface graph
    before writing, displaying, or logging it.
    """

    method: str
    url: str
    parameters: tuple[PassiveReconParameter, ...] = ()
    header_names: tuple[str, ...] = ()
    hints: tuple[str, ...] = ()
    source_kind: str = "native_recon"


@dataclass(frozen=True, slots=True, repr=False)
class PassiveReconDocument:
    """Transient bounded navigation data without body, cookie, or field values."""

    links: tuple[str, ...]
    operations: tuple[PassiveReconOperation, ...]


class _ReconHeaders:
    """Header adapter retaining the small interface used by recon parsing."""

    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = dict(headers)

    def get_content_charset(self, failobj: Any = None) -> Any:
        content_type = next(
            (
                str(value)
                for name, value in self._headers.items()
                if str(name).casefold() == "content-type"
            ),
            "",
        )
        match = re.search(r"(?:^|;)\s*charset\s*=\s*['\"]?([^;'\"\s]+)", content_type)
        return match.group(1) if match is not None else failobj

    def get_all(self, name: str, failobj: Any = None) -> Any:
        value = next(
            (
                str(item)
                for key, item in self._headers.items()
                if str(key).casefold() == name.casefold()
            ),
            "",
        )
        if not value:
            return [] if failobj is None else failobj
        return value.splitlines()

    def items(self) -> Any:
        return self._headers.items()


class _ReconHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[ReconForm] = []
        self._current_form: ReconForm | None = None
        self._in_title = False

    @property
    def title(self) -> str:
        return _clean_text(" ".join(self.title_parts))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_by_name = _attrs_to_dict(attrs)
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "base":
            self._update_base(attrs_by_name.get("href", ""))
        elif tag in {"a", "area", "link"}:
            self._append_url(self.links, attrs_by_name.get("href", ""))
        elif tag == "script":
            self._append_url(self.scripts, attrs_by_name.get("src", ""))
        elif tag == "form":
            self._start_form(attrs_by_name)
        elif tag in {"button", "input", "select", "textarea"}:
            self._append_form_input(tag, attrs_by_name)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() == "form":
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    def _update_base(self, href: str) -> None:
        updated = _absolute_http_url(href, self.base_url)
        if updated is not None:
            self.base_url = updated

    def _append_url(self, target: list[str], value: str) -> None:
        url = _absolute_http_url(value, self.base_url)
        if url is not None:
            target.append(url)

    def _start_form(self, attrs: dict[str, str]) -> None:
        method = attrs.get("method", "GET").strip().upper() or "GET"
        action = _absolute_http_url(attrs.get("action", ""), self.base_url) or self.base_url
        form = ReconForm(
            method=method,
            action=action,
            enctype=attrs.get("enctype", "").strip(),
        )
        self.forms.append(form)
        self._current_form = form

    def _append_form_input(self, tag: str, attrs: dict[str, str]) -> None:
        if self._current_form is None:
            return
        input_type = attrs.get("type", tag).strip().lower() or tag
        if tag != "input":
            input_type = tag
        self._current_form.inputs.append(
            ReconInput(
                name=attrs.get("name", "").strip(),
                input_type=input_type,
                value=attrs.get("value", ""),
                required="required" in attrs,
                disabled="disabled" in attrs,
                minlength=attrs.get("minlength", "").strip(),
                maxlength=attrs.get("maxlength", "").strip(),
                pattern=attrs.get("pattern", "").strip(),
            )
        )


def run_recon(
    target_url: str,
    *,
    max_pages: int = 12,
    timeout_seconds: int = 8,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
    max_rps: float | None = None,
    session: ProbeSession | None = None,
    traffic_policy: TrafficPolicyController | None = None,
    traffic_policy_reference: dict[str, object] | None = None,
) -> ReconResult:
    assert_tool_target_url(
        target_url,
        allow_remote_target=allow_remote_target,
    )
    parsed_target = urlsplit(target_url)
    if parsed_target.scheme.lower() not in HTTP_SCHEMES or parsed_target.hostname is None:
        msg = "target_url must be an http(s) URL with a host"
        raise ValueError(msg)
    if timeout_seconds <= 0:
        msg = "timeout_seconds must be positive"
        raise ValueError(msg)

    origin = _origin_from_parts(parsed_target)
    canonical_target = _canonical_url(target_url)
    if in_scope and not url_in_scope_entries(
        canonical_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    ):
        raise ValueError("recon target URL must be listed in engagement scope")
    result = ReconResult(
        target_url=canonical_target,
        origin=_origin_to_url(origin),
    )
    if max_pages <= 0:
        return result
    if session is not None:
        if traffic_policy is not None or traffic_policy_reference is not None:
            raise ValueError("traffic policy cannot be supplied with an existing recon session")
        if _origin_from_parts(urlsplit(session.target_url)) != origin:
            raise ValueError("provided recon session belongs to a different target origin")
        if not session.in_scope(canonical_target):
            raise ValueError("provided recon session does not permit the target URL")
    else:
        session = ProbeSession(
            canonical_target,
            timeout_seconds=timeout_seconds,
            default_headers={"User-Agent": "ravage-recon/1.0"},
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            max_rps=max_rps,
            traffic_policy=traffic_policy,
            traffic_policy_reference=traffic_policy_reference,
            traffic_lane="recon",
            traffic_cacheable=True,
            traffic_retryable=True,
            max_body_bytes=MAX_BODY_BYTES,
        )
    request_count_before = session.physical_request_count
    queue: deque[str] = deque([canonical_target])
    queued = {canonical_target}
    visited: set[str] = set()
    remaining_probe_budget = min(max_pages, MAX_PROBES_PER_RUN)
    remaining_script_count = MAX_EXTERNAL_SCRIPTS_PER_RUN
    remaining_script_bytes = MAX_EXTERNAL_SCRIPT_BYTES_PER_RUN
    fetched_scripts: set[str] = set()

    while queue and len(result.pages) < max_pages:
        url = queue.popleft()
        if url in visited or not _url_allowed(
            url,
            origin=origin,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ):
            continue
        visited.add(url)

        page, body_text = _fetch_recon_page(
            session,
            url,
            origin=origin,
            timeout_seconds=timeout_seconds,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )
        if page.error:
            result.errors.append(f"{url}: {page.error}")
        if page.scripts and remaining_script_count > 0 and remaining_script_bytes > 0:
            (
                external_templates,
                remaining_script_count,
                remaining_script_bytes,
            ) = _external_javascript_templates(
                session,
                page.scripts,
                origin=origin,
                timeout_seconds=timeout_seconds,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
                fetched_scripts=fetched_scripts,
                remaining_count=remaining_script_count,
                remaining_bytes=remaining_script_bytes,
            )
            page.request_templates = _dedupe_templates(
                [*page.request_templates, *external_templates]
            )[:32]
        if remaining_probe_budget > 0 and body_text:
            reflected, remaining_probe_budget = _probe_reflections(
                session,
                page,
                origin=origin,
                timeout_seconds=timeout_seconds,
                remaining_budget=remaining_probe_budget,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
            )
            page.reflected_parameters = reflected

        result.pages.append(page)
        _extend_queue(
            queue,
            queued,
            page.links,
            origin=origin,
            max_pages=max_pages,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )

    result.query_parameter_names = _result_query_parameter_names(result.pages)
    result.interesting_markers = _result_interesting_markers(result.pages)
    result.http_request_count = max(0, session.physical_request_count - request_count_before)
    return result


def _result_query_parameter_names(pages: list[ReconPage]) -> list[str]:
    names: list[str] = []
    for page in pages:
        for name in page.query_parameter_names:
            names.append(name)
    return _sorted_unique(names)


def _result_interesting_markers(pages: list[ReconPage]) -> list[str]:
    markers: list[str] = []
    for page in pages:
        for marker in page.interesting_markers:
            markers.append(marker)
    return _sorted_unique(markers)


def _get_following_safe_redirects(
    session: ProbeSession,
    url: str,
    *,
    origin: tuple[str, str, int | None],
    timeout_seconds: int,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> ProbeResponse:
    """Follow bounded same-origin redirects as individually counted requests."""
    original_url = _canonical_url(url)
    current_url = original_url
    visited: set[str] = set()
    response: ProbeResponse | None = None
    for _hop in range(MAX_REDIRECT_HOPS + 1):
        response = session.request(
            "GET",
            current_url,
            timeout_seconds=timeout_seconds,
        )
        if response.status not in {301, 302, 303, 307, 308}:
            break
        location = _header_value(response.headers, "location")
        candidate = _absolute_http_url(location, current_url) if location else None
        if candidate is None or candidate in visited or not _url_allowed(
            candidate,
            origin=origin,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ):
            break
        visited.add(current_url)
        current_url = candidate
    if response is None:
        return ProbeResponse(
            method="GET",
            url=original_url,
            status=None,
            final_url=original_url,
            elapsed_ms=0,
            error="request failed before dispatch",
        )
    return replace(
        response,
        url=original_url,
        final_url=_canonical_url(current_url),
    )


def _external_javascript_templates(  # noqa: PLR0913
    session: ProbeSession,
    scripts: Sequence[str],
    *,
    origin: tuple[str, str, int | None],
    timeout_seconds: int,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
    fetched_scripts: set[str],
    remaining_count: int,
    remaining_bytes: int,
) -> tuple[list[dict[str, object]], int, int]:
    templates: list[dict[str, object]] = []
    for raw_url in scripts:
        if remaining_count <= 0 or remaining_bytes <= 0:
            break
        script_url = _canonical_url(raw_url)
        if script_url in fetched_scripts or not _url_allowed(
            script_url,
            origin=origin,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ):
            continue
        fetched_scripts.add(script_url)
        remaining_count -= 1
        script_session = session.fork(
            timeout_seconds=timeout_seconds,
            max_body_bytes=min(MAX_BODY_BYTES, remaining_bytes),
        )
        response = _get_following_safe_redirects(
            script_session,
            script_url,
            origin=origin,
            timeout_seconds=timeout_seconds,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )
        if response.status is None:
            continue
        bounded = response.body.encode("utf-8")[:remaining_bytes]
        remaining_bytes -= len(bounded)
        source_text = bounded.decode("utf-8", errors="replace")
        for raw_template in parse_javascript_request_templates(source_text):
            template = dict(raw_template)
            transport = str(template.get("source") or "")
            template["source"] = "javascript_external"
            template["script_url"] = script_url
            if transport:
                template["transport"] = transport
            templates.append(template)
    return _dedupe_templates(templates)[:32], remaining_count, remaining_bytes


def _header_value(headers: dict[str, str], name: str) -> str:
    return next(
        (
            str(value)
            for key, value in headers.items()
            if str(key).casefold() == name.casefold()
        ),
        "",
    )


def _fetch_recon_page(
    session: ProbeSession,
    url: str,
    *,
    origin: tuple[str, str, int | None],
    timeout_seconds: int,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> tuple[ReconPage, str]:
    response = _get_following_safe_redirects(
        session,
        url,
        origin=origin,
        timeout_seconds=timeout_seconds,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    if response.status is None:
        return (
            ReconPage(
                url=url,
                status=None,
                final_url=url,
                error=_clean_text(response.error) or "request failed",
            ),
            "",
        )
    status = response.status
    headers = _ReconHeaders(response.headers)
    final_url = _canonical_url(response.final_url)

    document = _parse_recon_document(final_url, headers, response.body)

    if not _url_allowed(
        final_url,
        origin=origin,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    ):
        links = []
        scripts = []
        forms = []
        request_templates = []
    else:
        links = document.links
        scripts = document.scripts
        forms = document.forms
        request_templates = document.request_templates

    return (
        ReconPage(
            url=url,
            status=status,
            final_url=final_url,
            title=document.title,
            headers=document.headers,
            cookies=document.cookies,
            links=links,
            scripts=scripts,
            forms=forms,
            request_templates=request_templates,
            query_parameter_names=document.query_parameter_names,
            interesting_markers=document.interesting_markers,
        ),
        document.body_text,
    )


def _header_charset(headers: _HeaderMapping) -> str | None:
    charset = headers.get_content_charset()
    if isinstance(charset, str):
        return charset
    return None


def _probe_reflections(
    session: ProbeSession,
    page: ReconPage,
    *,
    origin: tuple[str, str, int | None],
    timeout_seconds: int,
    remaining_budget: int,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> tuple[list[dict[str, str]], int]:
    marker = f"ravage_recon_{secrets.token_hex(8)}"
    probes = _reflection_probe_urls(
        page,
        marker,
        origin=origin,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    reflected: list[dict[str, str]] = []
    used_urls: set[str] = set()
    page_budget = min(remaining_budget, MAX_PROBES_PER_PAGE)

    for source, name, probe_url in probes:
        if page_budget <= 0 or remaining_budget <= 0:
            break
        if probe_url in used_urls:
            continue
        used_urls.add(probe_url)
        page_budget -= 1
        remaining_budget -= 1
        body = _fetch_probe_body(
            session,
            probe_url,
            origin=origin,
            timeout_seconds=timeout_seconds,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )
        if marker in body:
            reflected.append(
                {
                    "source": source,
                    "name": name,
                    "url": _redact_marker(probe_url, marker),
                }
            )

    return reflected, remaining_budget


def _reflection_probe_urls(
    page: ReconPage,
    marker: str,
    *,
    origin: tuple[str, str, int | None],
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> list[tuple[str, str, str]]:
    probes: list[tuple[str, str, str]] = []
    for link in page.links:
        if not _is_safe_probe_url(
            link,
            origin=origin,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ):
            continue
        names = _query_names(link)
        for name in names:
            probes.append(("link", name, _url_with_marker_param(link, name, marker)))

    for form in page.forms:
        if form.method != "GET" or not _is_safe_probe_url(
            form.action,
            origin=origin,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ):
            continue
        for input_field in form.inputs:
            if not input_field.name or input_field.disabled:
                continue
            probes.append(
                (
                    "form",
                    input_field.name,
                    _form_url_with_marker(form, input_field.name, marker),
                )
            )
    return probes


def _fetch_probe_body(
    session: ProbeSession,
    url: str,
    *,
    origin: tuple[str, str, int | None],
    timeout_seconds: int,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> str:
    response = _get_following_safe_redirects(
        session,
        url,
        origin=origin,
        timeout_seconds=timeout_seconds,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    return response.body if response.status is not None else ""


def _parse_html(
    body_text: str,
    final_url: str,
    content_type: str,
) -> _ReconHTMLParser | None:
    if body_text and _looks_like_html(body_text, content_type):
        parser = _ReconHTMLParser(final_url)
        parser.feed(body_text)
        parser.close()
        return parser
    return None


def _parse_recon_document(
    final_url: str,
    headers: _HeaderMapping,
    body: bytes | str,
) -> _ParsedReconDocument:
    headers_subset = _headers_subset(headers)
    body_text = body if isinstance(body, str) else _decode_body(body, _header_charset(headers))
    parser = _parse_html(body_text, final_url, headers_subset.get("content-type", ""))
    links = _document_links(parser)
    scripts = _document_scripts(parser)
    forms = _document_forms(parser)
    request_templates = _javascript_request_templates(body_text)
    marker_text = "\n".join((body_text[:MAX_BODY_BYTES], "\n".join(headers_subset.values())))
    return _ParsedReconDocument(
        title=_document_title(parser),
        headers=headers_subset,
        cookies=_cookies_from_headers(headers),
        links=links,
        scripts=scripts,
        forms=forms,
        request_templates=request_templates,
        body_text=body_text,
        query_parameter_names=_page_query_parameter_names(final_url, links, scripts, forms),
        interesting_markers=_interesting_markers(marker_text),
    )


def parse_passive_recon_document(
    final_url: str,
    headers: Mapping[str, str],
    body: bytes | str,
) -> PassiveReconDocument:
    """Extract transient navigation declarations without retaining field values.

    This parser performs no I/O.  It deliberately omits response text, titles,
    cookies, header values, form defaults, and JavaScript payload values. Exact
    URLs remain transient and must never be serialized or logged directly.
    """
    document = _parse_recon_document(
        final_url,
        _ReconHeaders({str(name): str(value) for name, value in headers.items()}),
        body,
    )
    operations: list[PassiveReconOperation] = []
    page_url = _canonical_url(final_url)
    links = tuple(item for item in sorted(set(document.links))[:128] if item != page_url)
    for link in links:
        operations.append(
            PassiveReconOperation(
                method="GET",
                url=link,
                parameters=tuple(
                    PassiveReconParameter(name=name, location="query")
                    for name in _query_names(link)[:32]
                ),
                hints=("link",),
            )
        )
    for script in (item for item in sorted(set(document.scripts))[:64] if item != page_url):
        operations.append(
            PassiveReconOperation(
                method="GET",
                url=script,
                parameters=tuple(
                    PassiveReconParameter(name=name, location="query")
                    for name in _query_names(script)[:32]
                ),
                hints=("script",),
            )
        )
    for form in document.forms[:64]:
        fields = tuple(
            sorted({field.name for field in form.inputs[:64] if field.name and not field.disabled})
        )
        query_parameters = tuple(
            PassiveReconParameter(name=name, location="query")
            for name in _query_names(form.action)[:32]
        )
        form_parameters = tuple(
            PassiveReconParameter(
                name=name,
                location="query" if form.method == "GET" else "form",
            )
            for name in fields[:64]
        )
        operations.append(
            PassiveReconOperation(
                method=form.method,
                url=form.action,
                parameters=tuple((*query_parameters, *form_parameters))[:64],
                hints=("form",),
            )
        )
    for template in document.request_templates[:64]:
        template_fields = template.get("fields")
        template_headers = template.get("headers")
        template_url = urljoin(final_url, str(template.get("url") or ""))
        query_parameters = tuple(
            PassiveReconParameter(name=name, location="query")
            for name in _query_names(template_url)[:32]
        )
        body_parameters = (
            tuple(
                PassiveReconParameter(name=name, location="body")
                for name in sorted(
                    str(raw_name) for raw_name in template_fields if str(raw_name).strip()
                )
            )
            if isinstance(template_fields, Mapping)
            else ()
        )
        operations.append(
            PassiveReconOperation(
                method=str(template.get("method") or "GET").strip().upper(),
                url=template_url,
                parameters=tuple((*query_parameters, *body_parameters))[:64],
                header_names=(
                    tuple(sorted(str(name) for name in template_headers if str(name).strip()))[:64]
                    if isinstance(template_headers, Mapping)
                    else ()
                ),
                hints=("javascript",),
                source_kind="javascript_inline",
            )
        )
    return PassiveReconDocument(
        links=links,
        operations=tuple(operations[:256]),
    )


def _looks_like_html(body_text: str, content_type: str) -> bool:
    content_type = content_type.lower()
    if "html" in content_type:
        return True
    prefix = body_text[:512].lower()
    return "<html" in prefix or "<!doctype html" in prefix


def _document_title(parser: _ReconHTMLParser | None) -> str:
    if parser is None:
        return ""
    return parser.title


def _document_links(parser: _ReconHTMLParser | None) -> list[str]:
    if parser is None:
        return []
    return _dedupe(parser.links)


def _document_scripts(parser: _ReconHTMLParser | None) -> list[str]:
    if parser is None:
        return []
    return _dedupe(parser.scripts)


def _document_forms(parser: _ReconHTMLParser | None) -> list[ReconForm]:
    if parser is None:
        return []
    return parser.forms


def parse_javascript_request_templates(text: str) -> list[dict[str, object]]:
    """Extract bounded structural request templates from JavaScript source."""
    templates: list[dict[str, object]] = []
    for arguments in _javascript_fetch_call_arguments(text):
        template = _javascript_fetch_template(arguments)
        if template:
            templates.append(template)
    return _dedupe_templates(templates)[:16]


def _javascript_request_templates(text: str) -> list[dict[str, object]]:
    return parse_javascript_request_templates(text)


def _javascript_fetch_call_arguments(text: str) -> list[str]:
    arguments: list[str] = []
    for match in re.finditer(r"\bfetch\s*\(", text, flags=re.IGNORECASE):
        open_paren = match.end() - 1
        close_paren = _matching_javascript_char(text, open_paren, "(", ")")
        if close_paren <= open_paren:
            continue
        arguments.append(text[open_paren + 1 : close_paren])
    return arguments[:16]


def _javascript_fetch_template(arguments: str) -> dict[str, object]:
    match = re.match(
        r"\s*([`'\"])([^`'\"\r\n]{1,300})\1\s*(?:,(?P<options>.*))?\s*$",
        arguments,
        flags=re.DOTALL,
    )
    if match is None:
        return {}

    url = match.group(2).strip()
    if not _javascript_url_value_usable(url):
        return {}

    options = _javascript_first_object_literal(match.group("options") or "")
    template: dict[str, object] = {
        "source": "fetch",
        "method": _javascript_method_from_block(options, default="GET"),
        "url": url,
    }
    fields = _javascript_fetch_body_fields(options)
    if fields:
        template["fields"] = fields
    headers = _javascript_headers_from_block(options)
    if headers:
        template["headers"] = headers
    return template


def _javascript_first_object_literal(text: str) -> str:
    match = re.search(r"\{", text)
    if match is None:
        return ""
    open_brace = match.start()
    close_brace = _matching_javascript_char(text, open_brace, "{", "}")
    if close_brace <= open_brace:
        return ""
    return text[open_brace + 1 : close_brace]


def _javascript_method_from_block(block: str, *, default: str) -> str:
    method = _javascript_property_string_value(block, "method")
    upper = method.upper()
    if upper in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return upper
    return default


def _javascript_fetch_body_fields(options: str) -> dict[str, str]:
    for body in _javascript_json_stringify_objects(options):
        fields = _javascript_payload_pairs_from_object(body)
        if fields:
            return fields
    body_object = _javascript_property_object(options, "body")
    if body_object:
        return _javascript_payload_pairs_from_object(body_object)
    return {}


def _javascript_json_stringify_objects(text: str) -> list[str]:
    objects: list[str] = []
    for match in re.finditer(r"\bJSON\s*\.\s*stringify\s*\(\s*\{", text, flags=re.IGNORECASE):
        open_brace = match.end() - 1
        close_brace = _matching_javascript_char(text, open_brace, "{", "}")
        if close_brace <= open_brace:
            continue
        objects.append(text[open_brace + 1 : close_brace])
    return objects[:8]


def _javascript_headers_from_block(block: str) -> dict[str, str]:
    header_block = _javascript_property_object(block, "headers")
    if not header_block:
        return {}

    headers: dict[str, str] = {}
    for name, raw_value in _javascript_object_pairs(header_block):
        value = _javascript_literal_value(raw_value)
        if name and value:
            headers[name] = value
    return headers


def _javascript_property_object(block: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*:\s*\{{", block, flags=re.IGNORECASE)
    if match is None:
        return ""
    open_brace = match.end() - 1
    close_brace = _matching_javascript_char(block, open_brace, "{", "}")
    if close_brace <= open_brace:
        return ""
    return block[open_brace + 1 : close_brace]


def _javascript_property_string_value(block: str, name: str) -> str:
    pattern = rf"\b{name}\s*:\s*([`'\"])([^`'\"\r\n]{{1,300}})\1"
    match = re.search(pattern, block, flags=re.IGNORECASE)
    if match is None:
        return ""
    return match.group(2).strip()


def _javascript_payload_pairs_from_object(data_block: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for name, raw_value in _javascript_object_pairs(data_block):
        if not _javascript_payload_key_usable(name):
            continue
        pairs[name] = _javascript_default_value_for_pair(name, raw_value)
    return pairs


def _javascript_object_pairs(body: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    pattern = (
        r"(?:^|,)\s*"
        r"(?:([A-Za-z_$][\w$]*)|['\"]([^'\"]{1,80})['\"])\s*:\s*"
        r"([^,\r\n}]{1,200})"
    )
    for match in re.finditer(pattern, body):
        name = match.group(1) or match.group(2) or ""
        raw_value = match.group(3).strip()
        if name:
            pairs.append((name, raw_value))
    return pairs[:20]


def _javascript_default_value_for_pair(name: str, raw_value: str) -> str:
    literal = _javascript_literal_value(raw_value)
    if literal:
        return literal
    lowered = name.lower()
    if lowered.endswith("id") or lowered == "id":
        return "1"
    return "ravage"


def _javascript_literal_value(raw_value: str) -> str:
    stripped = raw_value.strip()
    quoted = re.fullmatch(r"([`'\"])(.*?)\1", stripped)
    if quoted is not None:
        return quoted.group(2)
    numeric = re.fullmatch(r"-?\d+(?:\.\d+)?", stripped)
    if numeric is not None:
        return numeric.group(0)
    if stripped in {"true", "false", "null"}:
        return stripped
    return ""


def _javascript_url_value_usable(value: str) -> bool:
    if not value:
        return False
    lowered = value.lower()
    if lowered.startswith(("javascript:", "data:", "mailto:", "#", "//")):
        return False
    return value.startswith(("/", "./", "../", "http://", "https://")) or "/" in value


def _javascript_payload_key_usable(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,79}", name))


def _matching_javascript_char(text: str, open_index: int, opener: str, closer: str) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_index, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == opener:
            depth += 1
            continue
        if char == closer:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _dedupe_templates(templates: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for template in templates:
        key = repr(sorted(template.items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(template)
    return deduped


def _headers_subset(headers: _HeaderMapping) -> dict[str, str]:
    subset: dict[str, str] = {}
    for name, value in headers.items():
        normalized = str(name).lower()
        if normalized in HEADER_NAMES:
            subset[normalized] = _clean_text(str(value))
    return subset


def _cookies_from_headers(headers: _HeaderMapping) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for value in _set_cookie_headers(headers):
        cookie = _parse_set_cookie(value)
        if cookie is None:
            continue
        for morsel in cookie.values():
            records.append(_cookie_record(morsel))
    return records


def _set_cookie_headers(headers: _HeaderMapping) -> list[str]:
    values = headers.get_all("Set-Cookie", [])
    if not isinstance(values, list):
        return []
    headers_list: list[str] = []
    for value in values:
        headers_list.append(str(value))
    return headers_list


def _cookie_record(morsel: Morsel[str]) -> dict[str, object]:
    return {
        "name": morsel.key,
        "value": morsel.value,
        "domain": morsel["domain"],
        "path": morsel["path"],
        "secure": bool(morsel["secure"]),
        "httponly": bool(morsel["httponly"]),
        "samesite": morsel["samesite"],
    }


def _parse_set_cookie(value: str) -> SimpleCookie | None:
    cookie = SimpleCookie()
    try:
        cookie.load(value)
    except CookieError:
        return None
    return cookie


def _page_query_parameter_names(
    final_url: str,
    links: Iterable[str],
    scripts: Iterable[str],
    forms: Iterable[ReconForm],
) -> list[str]:
    names: list[str] = []
    names.extend(_query_names(final_url))
    for url in links:
        names.extend(_query_names(url))
    for url in scripts:
        names.extend(_query_names(url))
    for form in forms:
        names.extend(_query_names(form.action))
        if form.method == "GET":
            for input_field in form.inputs:
                if input_field.name and not input_field.disabled:
                    names.append(input_field.name)
    return _sorted_unique(names)


def _interesting_markers(text: str) -> list[str]:
    lowered = text.lower()
    markers: list[str] = []
    for marker, words in MARKER_WORDS.items():
        if _contains_any(lowered, words):
            markers.append(marker)
    return sorted(markers)


def _extend_queue(
    queue: deque[str],
    queued: set[str],
    links: Iterable[str],
    *,
    origin: tuple[str, str, int | None],
    max_pages: int,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> None:
    for link in links:
        if len(queued) >= max_pages * 4:
            return
        canonical = _canonical_url(link)
        if canonical not in queued and _url_allowed(
            canonical,
            origin=origin,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ):
            queued.add(canonical)
            queue.append(canonical)


def _decode_body(body: bytes, charset: str | None) -> str:
    if not body:
        return ""
    charset = charset or "utf-8"
    try:
        return body[:MAX_BODY_BYTES].decode(charset, errors="replace")
    except LookupError:
        return body[:MAX_BODY_BYTES].decode("utf-8", errors="replace")


def _absolute_http_url(value: str, base_url: str) -> str | None:
    if not value:
        return _canonical_url(base_url)
    joined = urljoin(base_url, value.strip())
    parsed = urlsplit(joined)
    if parsed.scheme.lower() not in HTTP_SCHEMES or parsed.hostname is None:
        return None
    return _canonical_url(joined)


def _canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = _parsed_hostname(parsed)
    port = _safe_port(parsed)
    netloc = _host_for_netloc(hostname)
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo = f"{userinfo}:{parsed.password}"
        netloc = f"{userinfo}@{netloc}"
    if port is not None and port != _default_port(scheme):
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def _parsed_hostname(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    if hostname is None:
        return ""
    return hostname.lower()


def _origin_from_parts(parsed: SplitResult) -> tuple[str, str, int | None]:
    hostname = parsed.hostname or ""
    return (
        parsed.scheme.lower(),
        hostname.lower(),
        _safe_port(parsed) or _default_port(parsed.scheme.lower()),
    )


def _origin_to_url(origin: tuple[str, str, int | None]) -> str:
    scheme, host, port = origin
    formatted_host = _host_for_netloc(host)
    if port is None or port == _default_port(scheme):
        return f"{scheme}://{formatted_host}"
    return f"{scheme}://{formatted_host}:{port}"


def _is_same_origin(url: str, origin: tuple[str, str, int | None]) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in HTTP_SCHEMES or parsed.hostname is None:
        return False
    return _origin_from_parts(parsed) == origin


def _url_allowed(
    url: str,
    *,
    origin: tuple[str, str, int | None],
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> bool:
    if not _is_same_origin(url, origin):
        return False
    if not in_scope:
        return True
    return url_in_scope_entries(
        url,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def _host_for_netloc(hostname: str) -> str:
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname


def _safe_port(parsed: SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def _query_names(url: str) -> list[str]:
    names: list[str] = []
    for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if name:
            names.append(name)
    return _dedupe(names)


def _url_with_marker_param(url: str, name: str, marker: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = _replace_query_value(pairs, name=name, marker=marker)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            urlencode(updated, doseq=True),
            "",
        )
    )


def _replace_query_value(
    pairs: list[tuple[str, str]],
    *,
    name: str,
    marker: str,
) -> list[tuple[str, str]]:
    updated: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == name:
            updated.append((key, marker))
        else:
            updated.append((key, value))
    return updated


def _form_url_with_marker(form: ReconForm, name: str, marker: str) -> str:
    parsed = urlsplit(form.action)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    input_pairs: list[tuple[str, str]] = []
    for input_field in form.inputs[:MAX_FORM_INPUTS_IN_PROBE]:
        if _skip_marker_input(input_field):
            continue
        value = _marker_input_value(input_field, name=name, marker=marker)
        input_pairs.append((input_field.name, value))
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            urlencode(pairs + input_pairs, doseq=True),
            "",
        )
    )


def _marker_input_value(input_field: ReconInput, *, name: str, marker: str) -> str:
    if input_field.name == name:
        return marker
    return input_field.value


def _skip_marker_input(input_field: ReconInput) -> bool:
    if not input_field.name:
        return True
    if input_field.disabled:
        return True
    return _skip_form_input(input_field)


def _skip_form_input(input_field: ReconInput) -> bool:
    return input_field.input_type in {"button", "file", "image", "reset", "submit"}


def _is_safe_probe_url(
    url: str,
    *,
    origin: tuple[str, str, int | None],
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> bool:
    if not _url_allowed(
        url,
        origin=origin,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    ):
        return False
    lowered = urlsplit(url).path.lower() + "?" + urlsplit(url).query.lower()
    if _contains_any(lowered, SKIPPED_PROBE_WORDS):
        return False
    return True


def _redact_marker(url: str, marker: str) -> str:
    return url.replace(marker, "<recon-marker>")


def _attrs_to_dict(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    values: dict[str, str] = {}
    for name, value in attrs:
        values[name.lower()] = value or ""
    return values


def _clean_text(value: str) -> str:
    return " ".join(value.split())


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _sorted_unique(values: Iterable[str]) -> list[str]:
    unique: set[str] = set()
    for value in values:
        if value:
            unique.add(value)
    return sorted(unique)


def _contains_any(text: str, words: Iterable[str]) -> bool:
    for word in words:
        if word in text:
            return True
    return False


__all__ = [
    "PassiveReconDocument",
    "PassiveReconOperation",
    "PassiveReconParameter",
    "ReconForm",
    "ReconInput",
    "ReconPage",
    "ReconResult",
    "parse_passive_recon_document",
    "run_recon",
]
