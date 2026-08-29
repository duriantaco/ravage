"""Secret-safe normalization helpers for persisted HTTP traffic metadata."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
REDACTED_URL = "[REDACTED-URL]"

type HeaderInput = Mapping[str, object] | Sequence[tuple[object, object]]

_MAX_URL_CHARS = 16_384
_MAX_TEXT_CHARS = 2_048
_MAX_HEADER_NAME_CHARS = 128
_MAX_HEADER_VALUE_CHARS = 1_024
_MAX_FIELD_NAME_CHARS = 128
_MAX_BODY_PARSE_BYTES = 1_048_576
_MIN_ENTROPY_TOKEN_CHARS = 24
_MIN_DYNAMIC_NUMERIC_CHARS = 4

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,128}$")
_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_KNOWN_TOKEN_RE = re.compile(
    r"(?i)^(?:"
    r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]+|"
    r"sk[-_](?:proj[-_])?[A-Za-z0-9_-]{8,}|"
    r"gh(?:p|o|u|s|r)_[A-Za-z0-9]{8,}|"
    r"github_pat_[A-Za-z0-9_]{8,}|"
    r"xox(?:b|p|a|r|s)-[A-Za-z0-9-]{8,}|"
    r"AKIA[A-Z0-9]{12,}|"
    r"(?:token|secret|session|auth)[._-][A-Za-z0-9._-]+"
    r")$"
)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]*(?![A-Za-z0-9_-])"
)
_AUTH_RE = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\s*[:=]\s*)"
    r"(?:bearer|basic|token)\s+[^\s,;<]+"
)
_BEARER_RE = re.compile(r"(?i)\b((?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b[A-Za-z0-9_.-]*(?:auth|authorization|cookie|credential|jwt|"
    r"token|secret|password|passwd|pwd|api[_-]?key|session|code|signature)"
    r"[A-Za-z0-9_.-]*\s*[:=]\s*[\"']?)[^\"'&\s<;,]+"
)
_QUERY_VALUE_RE = re.compile(r"([?&])([^=&#\s]{1,256})=([^&#\s]*)")
_PEM_PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?"
    r"(?:-----END [^-\r\n]*PRIVATE KEY-----|$)"
)
_PROOF_RE = re.compile(r"\b(?:flag|HTB|CTF)\{[^}\s]{3,512}\}", re.IGNORECASE)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GENERIC_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_.-])[A-Za-z0-9_+=./-]{24,}(?![A-Za-z0-9_.-])")
_MULTIPART_NAME_RE = re.compile(
    rb"(?i)content-disposition\s*:\s*form-data\s*;[^\r\n]*\bname=\"([^\"\r\n]{1,256})\""
)

_SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    }
)
_SAFE_REQUEST_HEADER_VALUES = frozenset(
    {
        "accept",
        "content-encoding",
        "content-language",
        "content-type",
    }
)
_SAFE_RESPONSE_HEADER_VALUES = frozenset(
    {
        "accept-ranges",
        "access-control-allow-credentials",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "access-control-allow-origin",
        "allow",
        "cache-control",
        "content-encoding",
        "content-language",
        "content-length",
        "content-type",
        "vary",
    }
)
_SENSITIVE_PATH_PARENTS = frozenset(
    {
        "activate",
        "callback",
        "confirm",
        "invite",
        "login",
        "magic",
        "otp",
        "password-reset",
        "recover",
        "reset",
        "session",
        "token",
        "verify",
    }
)


@dataclass(frozen=True, slots=True)
class BodyMetadata:
    """Non-reversible metadata for a request or response body."""

    media_type: str
    byte_length: int
    sha256: str
    field_names: tuple[str, ...] = ()


def redact_text(
    value: object,
    *,
    known_secrets: Iterable[object] = (),
    max_chars: int = _MAX_TEXT_CHARS,
) -> str:
    """Return bounded text with common credential and proof forms removed."""
    if max_chars <= 0:
        return ""
    text = _clean_text(value)
    for raw_secret in sorted(
        {str(secret) for secret in known_secrets if str(secret)},
        key=len,
        reverse=True,
    ):
        text = text.replace(raw_secret, REDACTED)
    text = _PEM_PRIVATE_KEY_RE.sub("[REDACTED-PRIVATE-KEY]", text)
    text = _PROOF_RE.sub("[REDACTED-PROOF]", text)
    text = _AWS_ACCESS_KEY_RE.sub("[REDACTED-ACCESS-KEY]", text)
    text = _JWT_RE.sub("[REDACTED-JWT]", text)
    text = _AUTH_RE.sub(r"\1" + REDACTED, text)
    text = _BEARER_RE.sub(r"\1" + REDACTED, text)
    text = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1" + REDACTED, text)
    text = _QUERY_VALUE_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}=%5BREDACTED%5D",
        text,
    )
    text = _GENERIC_TOKEN_RE.sub(_redact_generic_token, text)
    return _bounded(text, max_chars=max_chars)


def sanitize_url(
    value: object,
    *,
    known_secrets: Iterable[object] = (),
) -> str:
    """Preserve an HTTP URL's route shape while discarding all query values."""
    secrets = tuple(known_secrets)
    raw = _clean_text(value).strip()
    if not raw or len(raw) > _MAX_URL_CHARS:
        return REDACTED_URL
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return REDACTED_URL
    if parsed.scheme and parsed.scheme.casefold() not in {"http", "https"}:
        return REDACTED_URL
    if parsed.netloc and not parsed.hostname:
        return REDACTED_URL

    netloc = _safe_netloc(parsed, known_secrets=secrets)
    path = _safe_path(parsed.path, known_secrets=secrets)
    query = _safe_query(parsed.query, known_secrets=secrets)
    result = urlunsplit((parsed.scheme.casefold(), netloc, path, query, ""))
    return result or "/"


def semantic_url_shape(value: object) -> str:
    """Return a deterministic URL identity containing query names, never values."""
    safe = sanitize_url(value)
    if safe == REDACTED_URL:
        return safe
    parsed = urlsplit(safe)
    # Query names are case-sensitive on many applications. Preserve their
    # spelling and multiplicity; only header names are case-insensitive.
    names = sorted(
        (name for name, _value in _safe_parse_query(parsed.query)),
        key=lambda name: (name.casefold(), name),
    )
    query = "&".join(quote(name, safe="._[]-") for name in names)
    return urlunsplit((parsed.scheme, parsed.netloc.casefold(), parsed.path or "/", query, ""))


def redact_headers(
    headers: HeaderInput | None,
    *,
    response: bool = False,
    known_secrets: Iterable[object] = (),
) -> tuple[tuple[str, str], ...]:
    """Return ordered header pairs with only structural values retained."""
    secrets = tuple(known_secrets)
    safe_values = _SAFE_RESPONSE_HEADER_VALUES if response else _SAFE_REQUEST_HEADER_VALUES
    redacted: list[tuple[str, str]] = []
    for raw_name, raw_value in _header_items(headers):
        name = _safe_header_name(raw_name, known_secrets=secrets)
        if not name:
            continue
        value = _clean_text(raw_value).strip()
        if not value:
            redacted.append((name, ""))
        elif name in _SENSITIVE_HEADER_NAMES:
            redacted.append((name, REDACTED))
        elif response and name == "location":
            redacted.append((name, sanitize_url(value, known_secrets=secrets)))
        elif name == "content-type" and name in safe_values:
            media_type = _normalized_media_type(value)
            redacted.append((name, media_type or REDACTED))
        elif name in safe_values:
            redacted.append(
                (
                    name,
                    redact_text(
                        value,
                        known_secrets=secrets,
                        max_chars=_MAX_HEADER_VALUE_CHARS,
                    ),
                )
            )
        else:
            redacted.append((name, REDACTED))
    return tuple(redacted)


def body_metadata(
    body: object | None,
    *,
    media_type: str = "",
    byte_length: int | None = None,
    sha256: str = "",
    known_secrets: Iterable[object] = (),
) -> BodyMetadata:
    """Describe a body without retaining any body value."""
    encoded = _encode_body(body)
    resolved_length = len(encoded) if encoded is not None else _non_negative(byte_length)
    resolved_digest = _body_digest(encoded, supplied=sha256, byte_length=resolved_length)
    normalized_media_type = _normalized_media_type(media_type)
    fields = _body_field_names(
        body,
        encoded=encoded,
        media_type=normalized_media_type,
        known_secrets=known_secrets,
    )
    return BodyMetadata(
        media_type=normalized_media_type,
        byte_length=resolved_length,
        sha256=resolved_digest,
        field_names=fields,
    )


def safe_identifier(
    value: object,
    *,
    max_chars: int = 128,
    known_secrets: Iterable[object] = (),
) -> str:
    """Normalize an operator-controlled label without retaining secret material."""
    text = redact_text(value, known_secrets=known_secrets, max_chars=max_chars).strip()
    text = re.sub(r"[^A-Za-z0-9_.:@/-]+", "-", text).strip("-")
    return _bounded(text, max_chars=max_chars)


def safe_field_names(
    values: Iterable[object],
    *,
    known_secrets: Iterable[object] = (),
) -> tuple[str, ...]:
    """Normalize and sort structural field names."""
    normalized: set[str] = set()
    secrets = tuple(known_secrets)
    for value in values:
        name = redact_text(value, known_secrets=secrets, max_chars=_MAX_FIELD_NAME_CHARS).strip()
        if _FIELD_NAME_RE.fullmatch(name):
            normalized.add(name)
    return tuple(sorted(normalized, key=lambda item: (item.casefold(), item)))


def _safe_netloc(parsed: object, *, known_secrets: Iterable[object]) -> str:
    hostname = str(getattr(parsed, "hostname", "") or "").casefold()
    for secret in sorted(
        {str(item).casefold() for item in known_secrets if str(item)},
        key=len,
        reverse=True,
    ):
        hostname = hostname.replace(secret, "redacted")
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = getattr(parsed, "port", None)
    except ValueError:
        return "[invalid-host]"
    return f"{hostname}:{port}" if port is not None else hostname


def _safe_path(path: str, *, known_secrets: Iterable[object]) -> str:
    if not path:
        return "/"
    safe_segments: list[str] = []
    previous = ""
    for raw_segment in path.split("/"):
        decoded = _bounded_path_unquote(raw_segment)
        decoded = redact_text(decoded, known_secrets=known_secrets, max_chars=512)
        if _dynamic_path_segment(decoded, previous=previous):
            safe_segments.append(":redacted" if _secret_path_segment(decoded) else ":id")
        else:
            safe_segments.append(quote(decoded, safe="!$&'()*+,;=:@-._~[]"))
        if decoded:
            previous = decoded.casefold()
    result = "/".join(safe_segments)
    return result[:2_048] or "/"


def _safe_query(query: str, *, known_secrets: Iterable[object]) -> str:
    secrets = tuple(known_secrets)
    pairs = _safe_parse_query(query)
    names = [
        safe
        for raw_name, _raw_value in pairs
        if (safe := _safe_query_name(raw_name, known_secrets=secrets))
    ]
    return urlencode([(name, REDACTED) for name in names], doseq=True)


def _safe_parse_query(query: str) -> list[tuple[str, str]]:
    if not query:
        return []
    try:
        return parse_qsl(query, keep_blank_values=True, max_num_fields=256)
    except ValueError:
        pairs: list[tuple[str, str]] = []
        for item in query.split("&")[:256]:
            name, _, value = item.partition("=")
            pairs.append((_bounded_unquote(name), value))
        return pairs


def _safe_query_name(value: str, *, known_secrets: Iterable[object] = ()) -> str:
    name = redact_text(
        _bounded_unquote(value),
        known_secrets=known_secrets,
        max_chars=_MAX_FIELD_NAME_CHARS,
    ).strip()
    return name if _FIELD_NAME_RE.fullmatch(name) else "redacted-field"


def _secret_path_segment(value: str) -> bool:
    return bool(
        _KNOWN_TOKEN_RE.fullmatch(value)
        or _JWT_RE.fullmatch(value)
        or _PROOF_RE.search(value)
        or REDACTED in value
    )


def _dynamic_path_segment(value: str, *, previous: str) -> bool:
    if not value:
        return False
    if value in {":id", ":redacted"}:
        return False
    if (
        _secret_path_segment(value)
        or previous in _SENSITIVE_PATH_PARENTS
        or _UUID_RE.fullmatch(value)
        or (value.isdigit() and len(value) >= _MIN_DYNAMIC_NUMERIC_CHARS)
        or re.fullmatch(r"(?i)[0-9a-f]{16,}", value)
    ):
        return True
    if len(value) < _MIN_ENTROPY_TOKEN_CHARS:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._~+=-]+", value):
        return False
    has_alpha = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    mixed_case = any(character.islower() for character in value) and any(
        character.isupper() for character in value
    )
    return has_alpha and (has_digit or mixed_case)


def _header_items(headers: HeaderInput | None) -> tuple[tuple[object, object], ...]:
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        items: list[tuple[object, object]] = []
        for name, value in headers.items():
            if isinstance(value, (list, tuple)):
                items.extend((name, item) for item in value)
            else:
                items.append((name, value))
        return tuple(items)
    return tuple(headers)


def _safe_header_name(value: object, *, known_secrets: Iterable[object]) -> str:
    name = (
        redact_text(
            value,
            known_secrets=known_secrets,
            max_chars=_MAX_HEADER_NAME_CHARS,
        )
        .strip()
        .casefold()
    )
    if len(name) > _MAX_HEADER_NAME_CHARS or not _HEADER_NAME_RE.fullmatch(name):
        return ""
    return name


def _encode_body(body: object | None) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray | memoryview):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8", errors="replace")
    try:
        encoded = json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        try:
            encoded = str(body).encode("utf-8", errors="replace")
        except RecursionError:
            encoded = None
    return encoded


def _body_digest(encoded: bytes | None, *, supplied: str, byte_length: int) -> str:
    # A persisted hash of a raw body is an offline verifier for low-entropy
    # passwords, OTPs, flags, and CSRF values. Keep only structural metadata.
    del encoded, supplied
    return "" if byte_length == 0 else "unavailable"


def _body_field_names(  # noqa: PLR0911 - body formats have distinct safe exits.
    body: object | None,
    *,
    encoded: bytes | None,
    media_type: str,
    known_secrets: Iterable[object],
) -> tuple[str, ...]:
    secrets = tuple(known_secrets)
    if isinstance(body, Mapping):
        return safe_field_names(body.keys(), known_secrets=secrets)
    if encoded is None or len(encoded) > _MAX_BODY_PARSE_BYTES:
        return ()
    if media_type == "application/x-www-form-urlencoded":
        text = encoded.decode("utf-8", errors="replace")
        return safe_field_names(
            (name for name, _value in _safe_parse_query(text)),
            known_secrets=secrets,
        )
    if media_type == "multipart/form-data":
        return safe_field_names(
            (
                match.group(1).decode("utf-8", errors="replace")
                for match in _MULTIPART_NAME_RE.finditer(encoded)
            ),
            known_secrets=secrets,
        )
    if media_type == "application/json" or media_type.endswith("+json"):
        try:
            decoded = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return ()
        if isinstance(decoded, Mapping):
            return safe_field_names(decoded.keys(), known_secrets=secrets)
    return ()


def _normalized_media_type(value: object) -> str:
    media_type = _clean_text(value).split(";", 1)[0].strip().casefold()
    if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
        return ""
    return media_type[:128]


def _non_negative(value: int | None) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or value < 0:
        message = "body byte length must be a non-negative integer"
        raise ValueError(message)
    return value


def _bounded_unquote(value: str, *, rounds: int = 2) -> str:
    decoded = value
    for _ in range(rounds):
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _bounded_path_unquote(value: str) -> str:
    """Decode one URL path layer without applying form-style plus semantics."""
    return unquote(value)


def _clean_text(value: object) -> str:
    text = str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _BIDI_RE.sub("", _CONTROL_RE.sub("", text))


def _bounded(value: str, *, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max(0, max_chars - 1)] + "…"


def _redact_generic_token(match: re.Match[str]) -> str:
    value = match.group(0)
    if value.casefold().startswith(("http://", "https://")):
        return value
    has_alpha = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    mixed_case = any(character.islower() for character in value) and any(
        character.isupper() for character in value
    )
    return "[REDACTED-TOKEN]" if has_alpha and (has_digit or mixed_case) else value


__all__ = [
    "REDACTED",
    "REDACTED_URL",
    "BodyMetadata",
    "HeaderInput",
    "body_metadata",
    "redact_headers",
    "redact_text",
    "safe_field_names",
    "safe_identifier",
    "sanitize_url",
    "semantic_url_shape",
]
