from __future__ import annotations

import secrets

from ravage.probe_suite_parts.support import _contains_word, _list_of_dicts
from ravage.web_core.http_probe import form_defaults

__all__ = [
    "_identity",
    "_identity_fields",
    "_preserve_working_credential_values",
]


def _identity(prefix: str) -> dict[str, str]:
    username = f"ravage_{prefix}_{secrets.token_hex(4)}"
    return {
        "username": username,
        "email": f"{username}@example.test",
        "password": "RavagePass123!",
    }


def _identity_fields(form: dict[str, object], identity: dict[str, str]) -> dict[str, str]:
    fields = form_defaults(form)
    protected = _protected_hidden_identity_fields(form)
    inputs_by_name = _inputs_by_name(form)

    for name in list(fields):
        if name in protected:
            continue

        replacement = _auth_field_value(name, identity)
        if not replacement:
            continue

        fields[name] = _fit_input_constraints(replacement, inputs_by_name.get(name, {}))

    raw_extra = form.get("script_extra_fields")
    if isinstance(raw_extra, dict):
        for key, value in raw_extra.items():
            name = str(key).strip()
            if name and name not in fields:
                fields[name] = str(value)

    return fields


def _preserve_working_credential_values(
    forms: list[dict[str, object]],
    *,
    username: str,
    password: str,
) -> list[dict[str, object]]:
    preserved: list[dict[str, object]] = []
    identity = {
        "username": username,
        "password": password,
        "email": username,
    }

    for form in forms:
        copied = dict(form)
        inputs: list[dict[str, object]] = []
        changed = False

        for input_field in _list_of_dicts(form.get("inputs")):
            field = dict(input_field)
            name = str(field.get("name") or "")
            input_type = str(field.get("type") or "").lower()

            if _should_preserve_password(field, input_type=input_type, password=password):
                field["value"] = password
                changed = True
            elif _should_preserve_username(field, name=name, username=username, identity=identity):
                field["value"] = username
                changed = True

            inputs.append(field)

        if changed:
            copied["inputs"] = inputs
        preserved.append(copied)

    return preserved


def _should_preserve_password(field: dict[str, object], *, input_type: str, password: str) -> bool:
    if input_type != "password":
        return False
    if not password:
        return False
    return not str(field.get("value") or "")


def _should_preserve_username(
    field: dict[str, object],
    *,
    name: str,
    username: str,
    identity: dict[str, str],
) -> bool:
    if str(field.get("value") or ""):
        return False
    if not username:
        return False
    return _auth_field_value(name, identity) == username


def _inputs_by_name(form: dict[str, object]) -> dict[str, dict[str, object]]:
    inputs: dict[str, dict[str, object]] = {}
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if name:
            inputs[name] = input_field
    return inputs


def _fit_input_constraints(value: str, input_field: dict[str, object]) -> str:
    min_len = _input_length(input_field, "minlength", "min_length")
    max_len = _input_length(input_field, "maxlength", "max_length", "max")
    fitted = value

    if min_len and len(fitted) < min_len:
        seed = fitted or "RavagePass123!"
        suffix = "A1!"
        while len(fitted) < min_len:
            fitted = (fitted or seed) + suffix

    if max_len and max_len > 0 and len(fitted) > max_len:
        fitted = fitted[:max_len]

    return fitted


def _input_length(input_field: dict[str, object], *names: str) -> int:
    for name in names:
        raw = input_field.get(name)
        if raw in (None, ""):
            continue

        try:
            parsed = int(str(raw))
        except ValueError:
            continue

        return max(0, parsed)

    return 0


def _protected_hidden_identity_fields(form: dict[str, object]) -> set[str]:
    protected: set[str] = set()
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "").lower()
        value = str(input_field.get("value") or "")
        lowered = name.lower().replace("-", "_")

        if input_type != "hidden":
            continue
        if not value:
            continue
        if lowered == "id" or lowered.endswith("_id") or lowered.endswith("id"):
            protected.add(name)

    return protected


def _auth_field_value(name: str, identity: dict[str, str]) -> str:
    lowered = name.lower().replace("-", "_")
    if lowered in {"log", "user_login"}:
        return identity["username"]
    if lowered in {"pwd", "user_pass"}:
        return identity["password"]
    if _contains_word(lowered, ("user", "login")):
        return identity["username"]
    if lowered in {"name", "full_name", "fullname", "display_name", "displayname", "account_name"}:
        return identity["username"]
    if "email" in lowered:
        return identity["email"]
    if "pass" in lowered:
        return identity["password"]
    return ""
