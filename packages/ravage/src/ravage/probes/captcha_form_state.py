from __future__ import annotations

import base64
import binascii
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_forms import (
    _forms_from_html,
    _fresh_form_from_response,
    _matching_live_form,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults, inject_query_param
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import _form_targets, _list_of_dicts, _string_items
from ravage.web_core.proof_recognizer import recognize_proofs


@dataclass(frozen=True)
class PreparedStatefulForm:
    form: dict[str, object]
    fields: dict[str, str]
    page: ProbeResponse | None = None
    metadata: dict[str, object] = field(default_factory=dict)


def prepare_stateful_form_fields(
    session: ProbeSession,
    form: dict[str, object],
    *,
    marker_name: str = "",
    marker: str = "",
    seed_fields: dict[str, str] | None = None,
) -> PreparedStatefulForm:

    if _form_requires_state_refresh(form):
        page, live_form = _fresh_form(session, form)
    else:
        page, live_form = None, form
    fields = form_defaults(live_form, marker_name=marker_name, marker=marker)
    if seed_fields:
        _merge_seed_fields(fields, live_form, seed_fields=seed_fields, marker_name=marker_name)

    if page is not None:
        page_body = page.body
    else:
        page_body = ""
        
    solutions = _challenge_solutions(session, body=page_body)
    challenge_names = _challenge_field_names(live_form, fields, allow_code=bool(solutions))
    applied: list[dict[str, str]] = []
    for challenge_name in challenge_names:
        if challenge_name == marker_name:
            continue
        solution = _best_solution_for_field(challenge_name, solutions)
        if not solution:
            continue
        fields[challenge_name] = solution.value
        applied.append({"field": challenge_name, "source": solution.source})

    metadata: dict[str, object] = {}
    if applied:
        metadata["challenge_fields"] = applied
    if page is not None:
        metadata["refresh_url"] = page.url
        metadata["refresh_status"] = page.status
    return PreparedStatefulForm(form=live_form, fields=fields, page=page, metadata=metadata)


def probe_captcha_form_state(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    targets = _captcha_form_targets(session, state)
    for form in targets[:8]:
        payload_field = _payload_field_for_form(form)
        prepared = prepare_stateful_form_fields(
            session,
            form,
            marker_name=payload_field,
            marker=_baseline_value(payload_field),
        )
        if prepared.page is not None:
            requests.append(
                prepared.page.summary(body_chars=180)
                | {"probe_kind": "captcha_form_refresh", "form_action": str(prepared.form.get("action") or "")}
            )
        if not prepared.metadata.get("challenge_fields"):
            findings.append(
                {
                    "type": "captcha_form_state_required",
                    "form": _form_brief(prepared.form),
                    "input": payload_field,
                    "detail": "form appears to require captcha/code state, but no generic visible or weak-cookie solution was derived",
                }
            )
            continue

        response = _submit_form(session, prepared.form, prepared.fields)
        requests.append(
            response.summary(body_chars=220)
            | {"probe_kind": "captcha_form_state_replay", "payload_field": payload_field}
        )
        proofs = recognize_proofs(response.body)
        replay = _replay_for_form(prepared.form, payload_field, prepared.fields, metadata=prepared.metadata)
        finding: dict[str, object] = {
            "type": "captcha_form_state_replay",
            "form": _form_brief(prepared.form),
            "input": payload_field,
            "replay": replay,
            "state": prepared.metadata,
            "response": response.summary(body_chars=260),
            "next": "Use this replay template for query/auth/form probes; refresh volatile fields before each state-changing request.",
        }
        if proofs:
            finding["type"] = "captcha_form_state_proof"
            finding["proofs"] = proofs
        findings.append(finding)
        if proofs:
            break

    return ProbeRunResult(
        ok=bool(findings),
        probe="captcha_form_state",
        summary=f"tested {len(targets[:8])} captcha/code form(s), findings={len(findings)}",
        findings=findings[:12],
        requests=requests[:24],
    )


def form_field_looks_volatile(name: str) -> bool:
    lowered = name.lower()
    return (
        "csrf" in lowered
        or "xsrf" in lowered
        or "nonce" in lowered
        or lowered in {"token", "_token", "authenticity_token"}
        or _name_looks_challenge(lowered)
    )


def form_field_looks_challenge(name: str) -> bool:
    return _name_looks_challenge(name)


def _form_requires_state_refresh(form: dict[str, object]) -> bool:
    if _form_has_challenge_context(form):
        return True
    return any(form_field_looks_volatile(str(input_field.get("name") or "")) for input_field in _list_of_dicts(form.get("inputs")))


def _form_has_challenge_context(form: dict[str, object]) -> bool:
    text = str(form).lower()
    if any(marker in text for marker in ("captcha", "challenge", "verification", "security code", "invalid captcha", "invalid code")):
        return True
    for input_field in _list_of_dicts(form.get("inputs")):
        if form_field_looks_challenge(str(input_field.get("name") or "")):
            return True
    return False


def _fresh_form(session: ProbeSession, form: dict[str, object]) -> tuple[ProbeResponse | None, dict[str, object]]:
    urls = _refresh_urls(session, form)
    for url in urls:
        page = session.get(url)
        if page.status not in {200, 201, 202}:
            continue
        match = _fresh_form_from_response(form, page)
        if match is not None:
            return page, match
        candidates = _forms_from_html(page.final_url, page.body, auth_headers={}, base_categories=())
        fallback = _matching_live_form(form, candidates) or _challenge_form_from_candidates(candidates)
        if fallback is not None:
            return page, fallback
    return None, form


def _refresh_urls(session: ProbeSession, form: dict[str, object]) -> list[str]:
    values = [
        str(form.get("page") or ""),
        str(form.get("source_url") or ""),
        str(form.get("action") or ""),
        session.target_url,
    ]
    urls: list[str] = []
    for value in values:
        if not value:
            continue
        url = session.absolute(value)
        in_scope = getattr(session, "in_scope", None)
        if (in_scope is None or in_scope(url)) and url not in urls:
            urls.append(url)
    return urls


def _merge_seed_fields(
    fields: dict[str, str],
    form: dict[str, object],
    *,
    seed_fields: dict[str, str],
    marker_name: str,
) -> None:
    volatile = _volatile_names(form, fields)
    for name, value in seed_fields.items():
        key = str(name)
        if not key or key == marker_name or key in volatile:
            continue
        fields[key] = str(value)


def _volatile_names(form: dict[str, object], fields: dict[str, str]) -> set[str]:
    names = {name for name in fields if form_field_looks_volatile(name)}
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "").lower()
        if input_type == "hidden" and form_field_looks_volatile(name):
            names.add(name)
    return names


@dataclass(frozen=True)
class _ChallengeSolution:
    value: str
    source: str
    confidence: int = 0
    cookie_name: str = ""


def _challenge_solutions(session: ProbeSession, *, body: str) -> list[_ChallengeSolution]:
    solutions: list[_ChallengeSolution] = []
    for value, source in _text_challenge_values(body):
        solutions.append(_ChallengeSolution(value=value, source=source, confidence=60))
    for value, source in _image_challenge_values(body):
        solutions.append(_ChallengeSolution(value=value, source=source, confidence=70))
    for cookie_name, value in _weak_cookie_challenge_values(session):
        solutions.append(
            _ChallengeSolution(value=value, source="weak_aes_cookie", confidence=80, cookie_name=cookie_name)
        )
    return _dedupe_solutions(solutions)


def _best_solution_for_field(field_name: str, solutions: list[_ChallengeSolution]) -> _ChallengeSolution | None:
    if not solutions:
        return None
    lowered = field_name.lower()
    ranked = sorted(
        solutions,
        key=lambda item: (
            -item.confidence,
            0 if ("captcha" in lowered and "captcha" in item.source) else 1,
            item.source,
            item.value,
        ),
    )
    return ranked[0]


def _text_challenge_values(body: str) -> list[tuple[str, str]]:
    if not body:
        return []
    values: list[tuple[str, str]] = []
    patterns = (
        r"(?is)\b(?:captcha|challenge|verification\s*code|security\s*code|answer)\b[^A-Za-z0-9]{0,40}([A-Za-z0-9_-]{3,16})",
        r"(?is)\b(?:enter|type)\s+(?:the\s+)?(?:code|captcha)\b[^A-Za-z0-9]{0,40}([A-Za-z0-9_-]{3,16})",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, body):
            value = _clean_solution(match.group(1))
            if value:
                values.append((value, "visible_text"))
    return values[:6]


def _image_challenge_values(body: str) -> list[tuple[str, str]]:
    if not body or "data:image" not in body.lower():
        return []
    values: list[tuple[str, str]] = []
    for match in re.finditer(r"(?is)data:image/(?:png|jpeg|jpg|gif);base64,([A-Za-z0-9+/=\s_-]{80,})", body):
        raw = re.sub(r"\s+", "", match.group(1))
        try:
            image = base64.b64decode(raw, validate=False)
        except (binascii.Error, ValueError):
            continue
        value = _ocr_image(image)
        if value:
            values.append((value, "captcha_image_ocr"))
    return values[:4]


def _ocr_image(image: bytes) -> str:
    tesseract = shutil.which("tesseract")
    if not tesseract or not image:
        return ""
    with tempfile.TemporaryDirectory(prefix="ravage-captcha-") as tmp:
        image_path = Path(tmp) / "captcha.png"
        output_base = Path(tmp) / "out"
        image_path.write_bytes(image[:1_000_000])
        command = [
            tesseract,
            str(image_path),
            str(output_base),
            "--psm",
            "7",
            "-c",
            "tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
        ]
        try:
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            text = output_base.with_suffix(".txt").read_text(encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return ""
    return _clean_solution(text)


def _weak_cookie_challenge_values(session: ProbeSession) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for cookie_name, cookie_value in _session_cookie_values(session):
        plaintext = _weak_aes_cookie_plaintext(cookie_value)
        if plaintext:
            values.append((cookie_name, plaintext))
    return values[:6]


def _session_cookie_values(session: ProbeSession) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for cookie in getattr(session, "cookies", []):
        name = str(getattr(cookie, "name", "") or "")
        value = str(getattr(cookie, "value", "") or "")
        if name and value:
            values.append((name, value))
    values.sort(key=lambda item: (0 if _name_looks_challenge(item[0]) else 1, item[0]))
    return values


def _weak_aes_cookie_plaintext(value: str) -> str:
    raw = _decode_cookie_value(value)
    if len(raw) < 32 or len(raw) % 16 != 0:
        return ""
    iv = raw[:16]
    ciphertext = raw[16:]
    for key in _weak_aes_keys():
        decrypted = _aes_cbc_decrypt(ciphertext, key=key, iv=iv)
        plaintext = _clean_pkcs7_plaintext(decrypted)
        if plaintext:
            return plaintext
    return ""


def _decode_cookie_value(value: str) -> bytes:
    text = unquote(value.strip())
    for candidate in (text, text + "=" * (-len(text) % 4)):
        try:
            decoded = base64.b64decode(candidate.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError):
            decoded = b""
        if decoded:
            return decoded
        try:
            decoded = base64.urlsafe_b64decode(candidate.encode("ascii"))
        except (binascii.Error, UnicodeEncodeError, ValueError):
            decoded = b""
        if decoded:
            return decoded
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def _weak_aes_keys() -> list[bytes]:
    keys: list[bytes] = []
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for size in (16, 24, 32):
        for char in alphabet:
            keys.append((char * size).encode("ascii"))
    for word in ("secret", "password", "captcha", "challenge", "token", "default"):
        for size in (16, 24, 32):
            repeated = (word * ((size // len(word)) + 1))[:size]
            keys.append(repeated.encode("ascii"))
    return keys


def _aes_cbc_decrypt(ciphertext: bytes, *, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:  # noqa: BLE001 - optional dependency or invalid decrypt candidate.
        pass
    try:
        from Crypto.Cipher import AES  # type: ignore[import-not-found]

        return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    except Exception:  # noqa: BLE001 - optional dependency or invalid decrypt candidate.
        return b""


def _clean_pkcs7_plaintext(value: bytes) -> str:
    if not value:
        return ""
    pad = value[-1]
    if 1 <= pad <= 16 and value.endswith(bytes([pad]) * pad):
        value = value[:-pad]
    if not value:
        return ""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return _clean_solution(text)


def _clean_solution(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "", value.strip())
    if not 2 <= len(cleaned) <= 32:
        return ""
    if cleaned.lower() in {"captcha", "challenge", "answer", "code", "token", "submit", "invalid"}:
        return ""
    return cleaned


def _dedupe_solutions(solutions: list[_ChallengeSolution]) -> list[_ChallengeSolution]:
    seen: set[tuple[str, str]] = set()
    deduped: list[_ChallengeSolution] = []
    for solution in solutions:
        key = (solution.value, solution.source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(solution)
    return deduped[:8]


def _captcha_form_targets(session: ProbeSession, state: AgentState) -> list[dict[str, object]]:
    forms = _form_targets(state, limit=16)
    if not forms:
        page = session.get(session.target_url)
        forms.extend(_forms_from_html(page.final_url, page.body, auth_headers={}, base_categories=()))
    candidates: list[dict[str, object]] = []
    for form in forms:
        if _form_has_challenge(form):
            candidates.append(form)
    if not candidates:
        candidates = forms
    return candidates[:10]


def _form_has_challenge(form: dict[str, object]) -> bool:
    text = _form_challenge_text(form)
    if _text_has_challenge_marker(text):
        return True
    return _form_has_challenge_input(form)


def _form_challenge_text(form: dict[str, object]) -> str:
    parts: list[str] = []

    action = str(form.get("action") or "")
    if action:
        parts.append(action)

    categories = _string_items(form.get("categories"))
    parts.extend(categories)
    parts.extend(_csrf_field_names(form))

    return " ".join(parts).lower()


def _csrf_field_names(form: dict[str, object]) -> list[str]:
    raw_fields = form.get("csrf_fields")
    if not isinstance(raw_fields, list):
        return []

    names: list[str] = []
    for raw_name in raw_fields:
        name = str(raw_name)
        if name:
            names.append(name)
    return names


def _text_has_challenge_marker(text: str) -> bool:
    markers = ("captcha", "challenge", "verification", "security code")
    for marker in markers:
        if marker in text:
            return True
    return False


def _form_has_challenge_input(form: dict[str, object]) -> bool:
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if _name_looks_challenge(name):
            return True
    return False


def _challenge_form_from_candidates(candidates: list[dict[str, object]]) -> dict[str, object] | None:
    for form in candidates:
        if _form_has_challenge(form):
            return form
    if candidates:
        return candidates[0]
    return None


def _challenge_field_names(form: dict[str, object], fields: dict[str, str], *, allow_code: bool) -> list[str]:
    names: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "text").lower()
        if not name or input_type in {"hidden", "submit", "button", "reset", "file", "password", "email"}:
            continue
        if _name_looks_challenge(name) or (allow_code and _name_looks_code(name)):
            names.append(name)
    if names:
        return _dedupe(names)
    if allow_code:
        for name in fields:
            if _name_is_payload_identity(name) or form_field_looks_volatile(name):
                continue
            if _name_looks_code(name):
                names.append(name)
        if not names:
            for name in fields:
                if not _name_is_payload_identity(name) and not form_field_looks_volatile(name):
                    names.append(name)
    return _dedupe(names)[:3]


def _name_looks_challenge(name: str) -> bool:
    lowered = name.lower()
    markers = ("captcha", "challenge", "verification", "security_code")
    for marker in markers:
        if marker in lowered:
            return True
    return False


def _name_looks_code(name: str) -> bool:
    lowered = name.lower()
    if lowered in {"code", "otp", "answer", "pin"}:
        return True
    markers = ("verify", "verification", "challenge", "security")
    for marker in markers:
        if marker in lowered:
            return True
    return False


def _name_is_payload_identity(name: str) -> bool:
    lowered = name.lower()
    return lowered in {
        "username",
        "user",
        "email",
        "password",
        "pass",
        "name",
        "q",
        "query",
        "search",
        "term",
        "submit",
        "action",
    }


def _payload_field_for_form(form: dict[str, object]) -> str:
    preferred: list[str] = []
    fallback: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "text").lower()
        if not name or input_type in {"hidden", "submit", "button", "reset", "file"}:
            continue
        if form_field_looks_volatile(name):
            continue
        if name.lower() in {"username", "user", "email", "name", "q", "query", "search", "id"}:
            preferred.append(name)
        else:
            fallback.append(name)
    return (preferred or fallback or ["q"])[0]


def _baseline_value(name: str) -> str:
    lowered = name.lower()
    if "email" in lowered:
        return "user@example.test"
    if "password" in lowered or lowered in {"pass", "pwd"}:
        return "Password123!"
    if "id" in lowered:
        return "1"
    return "ravage"


def _submit_form(session: ProbeSession, form: dict[str, object], fields: dict[str, str]) -> ProbeResponse:
    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or session.target_url)
    if method == "POST":
        return session.post_form(action, fields)
    url = action
    for name, value in fields.items():
        url = inject_query_param(url, name, value)
    return session.get(url)


def _replay_for_form(
    form: dict[str, object],
    payload_field: str,
    fields: dict[str, str],
    *,
    metadata: dict[str, object],
) -> dict[str, object]:
    replay_hint = (
        "Refresh the source form, preserve hidden/submit fields, "
        "solve visible captcha/code state, and change only payload_field."
    )
    replay: dict[str, object] = {
        "method": str(form.get("method") or "GET").upper(),
        "url": str(form.get("action") or ""),
        "payload_field": payload_field,
        "form": _replay_form_fields(fields),
        "source_form": _source_form_for_replay(form),
        "required_fields": _required_replay_fields(fields),
        "encoding": str(form.get("enctype") or "application/x-www-form-urlencoded"),
        "refresh_state": True,
        "replay_hint": replay_hint,
    }
    headers = _replay_headers(form)
    if headers:
        replay["headers"] = headers
    if metadata:
        replay["state"] = metadata
    return replay


def _replay_form_fields(fields: dict[str, str]) -> dict[str, str]:
    replay_fields: dict[str, str] = {}
    for name, value in fields.items():
        replay_fields[str(name)] = str(value)
    return replay_fields


def _required_replay_fields(fields: dict[str, str]) -> list[str]:
    required_fields: list[str] = []
    for name in fields:
        required_fields.append(str(name))
    return sorted(required_fields)


def _replay_headers(form: dict[str, object]) -> dict[str, str]:
    raw_headers = form.get("auth_headers")
    if not isinstance(raw_headers, dict):
        return {}

    headers: dict[str, str] = {}
    for name, value in raw_headers.items():
        headers[str(name)] = str(value)
    return headers


def _source_form_for_replay(form: dict[str, object]) -> dict[str, object]:
    source = dict(form)
    if "inputs" in source:
        inputs: list[dict[str, object]] = []
        for item in _list_of_dicts(source.get("inputs")):
            inputs.append(dict(item))
        source["inputs"] = inputs
    return source


def _form_brief(form: dict[str, object]) -> dict[str, object]:
    input_names: list[str] = []
    for item in _list_of_dicts(form.get("inputs")):
        name = str(item.get("name") or "")
        if name:
            input_names.append(name)
    return {
        "id": form.get("id"),
        "method": form.get("method"),
        "action": form.get("action"),
        "categories": _string_items(form.get("categories")),
        "inputs": input_names,
    }


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
