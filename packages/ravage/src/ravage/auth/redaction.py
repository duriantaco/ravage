"""Secret-aware serialization boundary for authenticated run artifacts."""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable, Mapping
from typing import Never, SupportsIndex
from urllib.parse import quote

from ravage.web_core.proof_recognizer import BARE_BRACED_PROOF_PATTERN, recognize_proofs

from .secrets import SecretValue

REDACTED = "[REDACTED]"
_MIN_PROOF_SUBSTRING_SECRET_CHARS = 4
_MIN_DISTINCTIVE_LITERAL_SECRET_CHARS = 6
_MIN_UNCONDITIONAL_LITERAL_SECRET_CHARS = 12

_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "auth_headers",
        "auth_materials",
        "authorization",
        "cookie",
        "cookie_header",
        "cookies",
        "credential",
        "credentials",
        "csrf_token",
        "id_token",
        "jwt",
        "otp",
        "password",
        "passwd",
        "proxy_authorization",
        "pwd",
        "refresh_token",
        "secret",
        "session_token",
        "set_cookie",
        "token",
        "totp",
        "x_api_key",
        "x_auth_token",
        "x_csrf_token",
    }
)
_SENSITIVE_KEY_TOKENS = frozenset(
    {
        "cookie",
        "credential",
        "jwt",
        "otp",
        "passwd",
        "password",
        "pwd",
        "secret",
        "token",
        "totp",
    }
)
_IDENTITY_LABEL_SECRET_TOKENS = frozenset({"account", "email", "login", "user", "username"})
_CREDENTIAL_SECRET_TOKENS = frozenset(
    {
        "api",
        "bearer",
        "credential",
        "key",
        "otp",
        "pass",
        "password",
        "secret",
        "token",
        "totp",
    }
)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]*(?![A-Za-z0-9_-])"
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\s*[:=]\s*)(?:bearer|basic|token)\s+[^\s,;<]+"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|csrf[_-]?token|session[_-]?token|token)"
    r"\s*[:=]\s*[\"']?)[^\"'&\s<;,]+"
)
_COOKIE_LINE_RE = re.compile(r"(?i)(\b(?:set-cookie|cookie)\s*[:=]\s*)[^\r\n<]+")
_PREFIXED_PROOF_SHAPED_RE = re.compile(r"\b(?:flag|FLAG|HTB|CTF|XBEN)\{[^}\r\n]{3,512}\}")
_BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])"
)


class AuthArtifactRedactor:
    """Redact configured secret values and credential-shaped artifact fields."""

    __slots__ = (
        "__context_free_secrets",
        "__literal_secrets",
        "__proof_derivatives",
        "__secrets",
        "__url_segment_secrets",
    )

    def __init__(self, secret_values: Iterable[SecretValue] = ()) -> None:
        self.__secrets: tuple[str, ...] = ()
        self.__context_free_secrets: tuple[str, ...] = ()
        self.__literal_secrets: tuple[str, ...] = ()
        self.__proof_derivatives: tuple[str, ...] = ()
        self.__url_segment_secrets: tuple[str, ...] = ()
        self.register_secret_values(secret_values)

    def register_secret_values(
        self,
        secret_values: Iterable[SecretValue],
        *,
        context_free: bool = True,
        url_segment: bool = True,
    ) -> None:
        """Add newly issued credentials, such as runtime session-cookie values."""
        values = set(self.__secrets)
        context_free_values = set(self.__context_free_secrets)
        literal_values = set(self.__literal_secrets)
        proof_derivatives = set(self.__proof_derivatives)
        url_segment_values = set(self.__url_segment_secrets)
        for secret in secret_values:
            if not isinstance(secret, SecretValue):
                message = "secret_values must contain SecretValue objects"
                raise TypeError(message)
            value = secret.reveal()
            if value:
                values.add(value)
                proof_derivatives.update(recognize_proofs(value))
                if context_free:
                    context_free_values.add(value)
                    if _secret_is_distinctive_literal(value):
                        literal_values.add(value)
                if url_segment:
                    url_segment_values.add(value)
        self.__secrets = tuple(sorted(values, key=len, reverse=True))
        self.__context_free_secrets = tuple(sorted(context_free_values, key=len, reverse=True))
        self.__literal_secrets = tuple(sorted(literal_values, key=len, reverse=True))
        self.__proof_derivatives = tuple(sorted(proof_derivatives, key=len, reverse=True))
        self.__url_segment_secrets = tuple(
            sorted(url_segment_values, key=len, reverse=True)
        )

    def register_named_secret_values(self, secret_values: Mapping[str, SecretValue]) -> None:
        """Register configured values while treating login labels as contextual data."""
        for name, secret in secret_values.items():
            self.register_secret_values(
                (secret,),
                context_free=not _secret_name_is_identity_label(str(name)),
            )

    def redact(self, value: object) -> object:
        return self._redact(value, prompt_safe=False)

    def redact_prompt(self, value: object) -> object:
        """Redact a model prompt without corrupting common action-language tokens."""
        return self._redact(value, prompt_safe=True)

    def contains_secret(self, value: str) -> bool:
        """Return whether text is tainted by any configured or issued secret."""
        raw = str(value)
        if raw in self.__secrets or raw in self.__proof_derivatives:
            return True
        proof_substring_secrets = {
            secret
            for secret in self.__context_free_secrets
            if len(secret) >= _MIN_PROOF_SUBSTRING_SECRET_CHARS
        }
        if any(secret in raw for secret in proof_substring_secrets):
            return True
        contextual = set(self.__secrets).difference(proof_substring_secrets)
        return any(_contextual_secret_in_text(secret, raw) for secret in contextual)

    def redact_text(self, value: str) -> str:
        return self._redact_text(value, prompt_safe=False)

    def redact_prompt_text(self, value: str) -> str:
        """Redact prompt text while retaining ambiguous short instruction words."""
        return self._redact_text(value, prompt_safe=True)

    def redact_protocol(
        self,
        value: object,
        *,
        protected_keys: Mapping[tuple[str, ...], Iterable[str]],
        protected_field_values: Mapping[tuple[str, ...], Iterable[str]],
    ) -> object:
        """Strictly redact data while preserving path-bound protocol vocabulary."""
        keys = {
            tuple(str(part) for part in path): frozenset(str(item) for item in items)
            for path, items in protected_keys.items()
        }
        field_values = {
            tuple(str(part) for part in path): frozenset(str(item) for item in items)
            for path, items in protected_field_values.items()
        }
        return self._redact_protocol(
            value,
            path=(),
            protected_keys=keys,
            protected_field_values=field_values,
        )

    def _redact_text(self, value: str, *, prompt_safe: bool) -> str:
        raw = str(value)
        if raw in self.__secrets:
            return REDACTED
        redacted = self._redact_tainted_proofs(raw)
        redacted = _JWT_RE.sub(REDACTED, redacted)
        redacted = _AUTHORIZATION_RE.sub(r"\1" + REDACTED, redacted)
        redacted = _SECRET_ASSIGNMENT_RE.sub(r"\1" + REDACTED, redacted)
        redacted = _COOKIE_LINE_RE.sub(r"\1" + REDACTED, redacted)
        for secret in self.__literal_secrets:
            redacted = redacted.replace(secret, REDACTED)
        if not prompt_safe:
            redacted = _redact_context_free_secret_tokens(
                redacted,
                self.__context_free_secrets,
            )
        return _redact_url_segment_secrets(redacted, self.__url_segment_secrets)

    def _redact_tainted_proofs(self, value: str) -> str:
        def replace_if_tainted(match: re.Match[str]) -> str:
            candidates = recognize_proofs(match.group(0))
            if any(self.contains_secret(candidate) for candidate in candidates):
                return REDACTED
            return match.group(0)

        def replace_encoded_if_tainted(match: re.Match[str]) -> str:
            token = match.group(0)
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - arbitrary artifact text.
                return token
            candidates = recognize_proofs(decoded)
            if any(self.contains_secret(candidate) for candidate in candidates):
                return REDACTED
            return token

        redacted = _PREFIXED_PROOF_SHAPED_RE.sub(replace_if_tainted, value)
        redacted = BARE_BRACED_PROOF_PATTERN.sub(replace_if_tainted, redacted)
        return _BASE64_CANDIDATE_RE.sub(replace_encoded_if_tainted, redacted)

    def _redact(self, value: object, *, prompt_safe: bool) -> object:
        if isinstance(value, str):
            return self._redact_text(value, prompt_safe=prompt_safe)
        if isinstance(value, Mapping):
            safe: dict[str, object] = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                safe_key = _unique_mapping_key(
                    self._redact_text(key, prompt_safe=prompt_safe), existing=safe
                )
                if _sensitive_key(key):
                    safe[safe_key] = REDACTED if item not in (None, "", [], {}) else item
                else:
                    safe[safe_key] = self._redact(item, prompt_safe=prompt_safe)
            return safe
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._redact(item, prompt_safe=prompt_safe) for item in value]
        if isinstance(value, bytes):
            return self._redact_text(
                value.decode("utf-8", errors="replace"), prompt_safe=prompt_safe
            )
        return value

    def _redact_protocol(
        self,
        value: object,
        *,
        path: tuple[str, ...],
        protected_keys: Mapping[tuple[str, ...], frozenset[str]],
        protected_field_values: Mapping[tuple[str, ...], frozenset[str]],
    ) -> object:
        if isinstance(value, str):
            allowed_values = _protocol_values_for_path(path, protected_field_values)
            if value in allowed_values:
                return value
            return self.redact_text(value)
        if isinstance(value, Mapping):
            safe: dict[str, object] = {}
            allowed_keys = _protocol_values_for_path(path, protected_keys)
            for raw_key, item in value.items():
                key = str(raw_key)
                safe_key = key if key in allowed_keys else self.redact_text(key)
                safe_key = _unique_mapping_key(safe_key, existing=safe)
                safe[safe_key] = self._redact_protocol(
                    item,
                    path=(*path, key),
                    protected_keys=protected_keys,
                    protected_field_values=protected_field_values,
                )
            return safe
        if isinstance(value, (list, tuple, set, frozenset)):
            return [
                self._redact_protocol(
                    item,
                    path=(*path, "*"),
                    protected_keys=protected_keys,
                    protected_field_values=protected_field_values,
                )
                for item in value
            ]
        if isinstance(value, bytes):
            return self.redact_text(value.decode("utf-8", errors="replace"))
        return value

    def __repr__(self) -> str:
        return f"{type(self).__name__}(secrets={REDACTED})"

    def __reduce__(self) -> Never:
        message = "auth artifact redactors cannot be serialized"
        raise TypeError(message)

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        message = "auth artifact redactors cannot be serialized"
        raise TypeError(message)


def _sensitive_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    if normalized in _SENSITIVE_KEYS:
        return True
    return bool(_SENSITIVE_KEY_TOKENS.intersection(normalized.split("_")))


def _secret_name_is_identity_label(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")
    tokens = frozenset(part for part in normalized.split("_") if part)
    return bool(tokens & _IDENTITY_LABEL_SECRET_TOKENS) and not bool(
        tokens & _CREDENTIAL_SECRET_TOKENS
    )


def is_contextual_identity_secret_name(name: str) -> bool:
    """Return whether a configured value is a reusable identity label, not a credential."""
    return _secret_name_is_identity_label(name)


def _contextual_secret_in_text(secret: str, value: str) -> bool:
    if value == secret:
        return True
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
            value,
        )
    )


def _secret_is_distinctive_literal(value: str) -> bool:
    if len(value) >= _MIN_UNCONDITIONAL_LITERAL_SECRET_CHARS:
        return True
    if len(value) < _MIN_DISTINCTIVE_LITERAL_SECRET_CHARS:
        return False
    character_classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(not character.isalnum() for character in value),
        )
    )
    return character_classes >= 2


def _redact_url_segment_secrets(value: str, secrets: Iterable[str]) -> str:
    redacted = value
    for secret in secrets:
        candidates = {secret, quote(secret, safe="")}
        for candidate in sorted(candidates, key=len, reverse=True):
            if not candidate:
                continue
            redacted = re.sub(
                rf"(?<=[/?:&=@]){re.escape(candidate)}"
                rf"(?=$|[/?:&#@\s\"'<>),;\]])",
                REDACTED,
                redacted,
            )
    return redacted


def _redact_context_free_secret_tokens(value: str, secrets: Iterable[str]) -> str:
    redacted = value
    for secret in secrets:
        if len(secret) < _MIN_PROOF_SUBSTRING_SECRET_CHARS:
            continue
        redacted = re.sub(
            rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
            REDACTED,
            redacted,
        )
    return redacted


def _unique_mapping_key(key: str, *, existing: Mapping[str, object]) -> str:
    if key not in existing:
        return key
    index = 2
    while f"{key}#{index}" in existing:
        index += 1
    return f"{key}#{index}"


def _protocol_values_for_path(
    path: tuple[str, ...],
    policies: Mapping[tuple[str, ...], frozenset[str]],
) -> frozenset[str]:
    values: set[str] = set()
    for pattern, candidates in policies.items():
        if len(pattern) != len(path):
            continue
        if all(expected == "*" or expected == actual for expected, actual in zip(pattern, path)):
            values.update(candidates)
    return frozenset(values)


__all__ = ["AuthArtifactRedactor", "is_contextual_identity_secret_name"]
