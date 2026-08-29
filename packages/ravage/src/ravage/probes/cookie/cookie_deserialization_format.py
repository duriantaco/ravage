from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from urllib.parse import quote, unquote


@dataclass(frozen=True)
class CookieFormat:
    kind: str  # pickle | yaml | php | flask_signed | jwt | json | none
    signed: bool
    encoding: str  # standard | urlsafe | raw | none
    url_encoded: bool

    @property
    def exploitable(self) -> bool:
        return self.kind in {"pickle", "yaml", "php"} and not self.signed

    def encode(self, payload: bytes) -> str:
        if self.encoding == "standard":
            value = base64.b64encode(payload).decode("ascii")
        elif self.encoding == "urlsafe":
            value = base64.urlsafe_b64encode(payload).decode("ascii")
        else:
            value = payload.decode("utf-8", errors="replace")
        if self.url_encoded:
            return quote(value, safe="")
        return value


def classify_cookie_value(raw_value: str) -> CookieFormat:
    value = raw_value.strip()
    url_encoded = "%" in value
    decoded_text = value
    if url_encoded:
        decoded_text = unquote(value)

    if _looks_like_jwt(decoded_text):
        return CookieFormat("jwt", signed=True, encoding="urlsafe", url_encoded=url_encoded)
    if _looks_like_flask_signed(decoded_text):
        return CookieFormat(
            "flask_signed", signed=True, encoding="urlsafe", url_encoded=url_encoded
        )

    for encoding, decoded in _b64_variants(decoded_text):
        if _looks_like_pickle(decoded):
            return CookieFormat("pickle", signed=False, encoding=encoding, url_encoded=url_encoded)
        text = decoded.decode("utf-8", errors="replace")
        if _looks_like_yaml(text):
            return CookieFormat("yaml", signed=False, encoding=encoding, url_encoded=url_encoded)
        if _looks_like_php_serialized(text):
            return CookieFormat("php", signed=False, encoding=encoding, url_encoded=url_encoded)
        if _looks_like_json(text):
            return CookieFormat("json", signed=False, encoding=encoding, url_encoded=url_encoded)

    if _looks_like_yaml(decoded_text):
        return CookieFormat("yaml", signed=False, encoding="raw", url_encoded=url_encoded)
    if _looks_like_php_serialized(decoded_text):
        return CookieFormat("php", signed=False, encoding="raw", url_encoded=url_encoded)
    return CookieFormat("none", signed=False, encoding="none", url_encoded=url_encoded)


# --- detection helpers --------------------------------------------------------


def _b64_variants(value: str):
    cleaned = value.strip()
    if not cleaned or not re.fullmatch(r"[A-Za-z0-9_+/=.\-]+", cleaned):
        return
    candidate = cleaned
    if cleaned.count(".") >= 2:
        candidate = cleaned.split(".")[0]
    padded = candidate + "=" * (-len(candidate) % 4)
    for name, decoder in (("standard", base64.b64decode), ("urlsafe", base64.urlsafe_b64decode)):
        try:
            decoded = decoder(padded)
        except Exception:  # noqa: BLE001 - arbitrary cookie text.
            continue
        if decoded:
            yield name, decoded


def _looks_like_pickle(data: bytes) -> bool:
    if not data:
        return False
    if data[:1] == b"\x80" and len(data) > 1 and data[1] in (1, 2, 3, 4, 5):
        return True
    markers = (
        b"c__builtin__",
        b"cbuiltins",
        b"csubprocess",
        b"cos\n",
        b"cposix",
        b"__reduce__",
        b"\x93",
    )
    for marker in markers:
        if marker in data:
            return True
    return data[:1] in (b"(", b"]", b"}", b"c") and (
        b"tR" in data or b".\n" in data or data.endswith(b".")
    )


def _looks_like_yaml(text: str) -> bool:
    if "!!python/" in text or "!!map" in text:
        return True
    stripped = text.strip()
    if stripped in {"[]", "{}"}:
        return True
    if stripped.startswith("- "):
        return len(stripped) <= 4096
    if "<" in text or ">" in text:
        return False
    return bool(re.search(r"(?m)^[\w.\-]+:\s", text)) and len(text) <= 4096


def _looks_like_php_serialized(text: str) -> bool:
    return bool(re.match(r'^[aOsidb]:\d+(?:[:;]|:")', text.strip()))


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        json.loads(stripped)
    except Exception:  # noqa: BLE001
        return False
    return True


def _looks_like_flask_signed(value: str) -> bool:
    if value.startswith(".eJ") or value.startswith("eyJ"):
        return value.count(".") >= 2
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{16,}", value))


def _looks_like_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header = parts[0] + "=" * (-len(parts[0]) % 4)
    try:
        decoded = base64.urlsafe_b64decode(header)
        payload = json.loads(decoded)
    except Exception:  # noqa: BLE001
        return False
    return isinstance(payload, dict) and "alg" in payload


def _decode_cookie_text(value: str, fmt: CookieFormat) -> str:
    raw = value
    if fmt.url_encoded:
        raw = unquote(value)
    if fmt.encoding == "raw":
        return raw
    padded = raw + "=" * (-len(raw) % 4)
    decoder = base64.b64decode
    if fmt.encoding == "urlsafe":
        decoder = base64.urlsafe_b64decode
    try:
        return decoder(padded).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""
