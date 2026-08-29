from __future__ import annotations

import json

from ravage.probe_suite_parts.support import _list_of_dicts
from ravage.probes.captcha_form_state import form_field_looks_challenge, form_field_looks_volatile


def _sqli_skip_form_field(name: str, form: dict[str, object]) -> bool:
    lowered = name.lower()
    if form_field_looks_volatile(name):
        return True
    if not _form_has_challenge_context(form):
        return False
    if lowered in {"code", "otp", "pin", "answer"} and _form_has_non_challenge_text_field(form):
        return True
    return False


def _form_has_challenge_context(form: dict[str, object]) -> bool:
    text = json.dumps(form, sort_keys=True).lower()
    challenge_markers = (
        "captcha",
        "challenge",
        "verification",
        "security code",
        "invalid captcha",
        "invalid code",
    )
    for marker in challenge_markers:
        if marker in text:
            return True
    for input_field in _list_of_dicts(form.get("inputs")):
        if form_field_looks_challenge(str(input_field.get("name") or "")):
            return True
    return False


def _form_has_non_challenge_text_field(form: dict[str, object]) -> bool:
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "text").lower()
        if input_type in {"hidden", "submit", "button", "reset", "file"}:
            continue
        if not name:
            continue
        if form_field_looks_volatile(name):
            continue
        if name.lower() in {"code", "otp", "pin", "answer"}:
            continue
        return True
    return False


def _form_requires_state_refresh(form: dict[str, object]) -> bool:
    if _form_has_challenge_context(form):
        return True
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if form_field_looks_volatile(name):
            return True
    return False


def _source_form_for_sqli_replay(form: dict[str, object]) -> dict[str, object]:
    source = dict(form)
    if "inputs" in source:
        inputs: list[dict[str, object]] = []
        for item in _list_of_dicts(source.get("inputs")):
            inputs.append(dict(item))
        source["inputs"] = inputs
    return source
