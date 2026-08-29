from __future__ import annotations

import base64
import re

PROOF_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:flag|FLAG|HTB|CTF|XBEN)\{[^}\s]{3,256}\}"),
    re.compile(r"\b(?:flag|FLAG|HTB|CTF|XBEN)\{[A-Za-z0-9_./+=:\-\s]{3,512}\}"),
)
BARE_BRACED_PROOF_PATTERN = re.compile(r"(?<![A-Za-z0-9_{}-])\{[A-Za-z0-9_/+=@#\-\s]{6,256}\}(?!\})")

PLACEHOLDER_PROOFS = {"flag{...}", "flag{redacted}", "ctf{...}", "htb{...}"}
PLACEHOLDER_BODIES = {
    "...",
    "0",
    "1",
    "admin",
    "demo",
    "example",
    "none",
    "null",
    "placeholder",
    "redacted",
    "sample",
    "test",
    "todo",
}
# Filler words that, when they make up the entire braced body, mark a templated
# placeholder rather than a real captured proof. Kept generic: a single
# non-filler token in the body keeps the candidate as a real proof.
# in the body keeps the candidate as a real proof.
PLACEHOLDER_TOKENS = {
    "changeme",
    "demo",
    "dummy",
    "example",
    "fake",
    "flag",
    "goes",
    "here",
    "insert",
    "me",
    "none",
    "null",
    "placeholder",
    "real",
    "redacted",
    "replace",
    "sample",
    "string",
    "test",
    "todo",
    "value",
    "your",
}
CODE_FRAGMENT_TOKENS = {
    "arg",
    "args",
    "array",
    "attrs",
    "bootstrap",
    "bundle",
    "callback",
    "class",
    "config",
    "const",
    "ctx",
    "data",
    "default",
    "document",
    "element",
    "else",
    "error",
    "errors",
    "event",
    "false",
    "for",
    "function",
    "html",
    "http",
    "href",
    "idx",
    "if",
    "index",
    "input",
    "item",
    "items",
    "key",
    "keys",
    "let",
    "map",
    "module",
    "name",
    "node",
    "null",
    "option",
    "options",
    "output",
    "param",
    "params",
    "props",
    "query",
    "request",
    "response",
    "result",
    "results",
    "return",
    "script",
    "src",
    "state",
    "string",
    "style",
    "target",
    "template",
    "text",
    "this",
    "true",
    "type",
    "undefined",
    "value",
    "var",
    "while",
    "window",
}


def recognize_proofs(text: str) -> list[str]:
    candidates: list[str] = []
    for rendered in (text, *_decoded_fragments(text)):
        for pattern in PROOF_PATTERNS:
            for match in pattern.finditer(rendered):
                _append_candidate(candidates, match.group(0))
        for match in BARE_BRACED_PROOF_PATTERN.finditer(rendered):
            _append_bare_braced_candidate(candidates, match.group(0))
    return candidates


def decoded_braced_fragments(text: str) -> list[str]:
    """Return decoded braced artifacts without treating them as captured proofs."""
    fragments: list[str] = []
    for rendered in _decoded_fragments(text):
        for match in re.finditer(r"[A-Za-z0-9_-]{0,32}\{[^}\r\n]{1,256}\}", rendered):
            candidate = _canonicalize_proof(match.group(0).strip())
            if is_placeholder_proof(candidate):
                continue
            if 4 <= len(candidate) <= 300 and candidate not in fragments:
                fragments.append(candidate)
    return fragments


def _append_candidate(candidates: list[str], candidate: str) -> None:
    stripped = _canonicalize_proof(candidate.strip())
    lowered = stripped.lower()
    if lowered in PLACEHOLDER_PROOFS or "redacted" in lowered:
        return
    if is_placeholder_proof(candidate.strip()):
        return
    if _looks_like_synthetic_proof(stripped):
        return
    if len(stripped) < 8 or len(stripped) > 300:
        return
    if stripped not in candidates:
        candidates.append(stripped)


def _append_bare_braced_candidate(candidates: list[str], candidate: str) -> None:
    stripped = _canonicalize_proof(candidate.strip())
    if not _looks_like_bare_braced_proof(stripped):
        return
    if stripped not in candidates:
        candidates.append(stripped)


def _canonicalize_proof(candidate: str) -> str:
    match = re.fullmatch(r"([A-Za-z0-9_-]*)\{([^}]*)\}", candidate, flags=re.DOTALL)
    if match is None:
        return candidate
    body = re.sub(r"\s+", "", match.group(2))
    return f"{match.group(1)}{{{body}}}"


def is_placeholder_proof(text: str) -> bool:
    """Return True when ``text`` is a proof-shaped placeholder, not a real flag.

    Catches templated bodies such as redacted, angle-bracket, or replacement
    placeholders. Generic only: a body with any non-filler token is treated as a
    real proof.
    """
    stripped = text.strip()
    match = re.fullmatch(r"[A-Za-z0-9_-]*\{([^}]*)\}", stripped)
    if match is None:
        return False
    if stripped.lower() in PLACEHOLDER_PROOFS:
        return True
    return _body_is_placeholder(match.group(1))


def _body_is_placeholder(raw_body: str) -> bool:
    body = raw_body.strip().lower()
    if not body or "redacted" in body or "<" in body or ">" in body or "..." in body:
        return True
    if body in PLACEHOLDER_BODIES:
        return True
    compact = body.replace(" ", "")
    if len(compact) >= 6 and len(set(compact)) == 1:
        return True
    tokens = [token for token in re.split(r"[^a-z0-9]+", body) if token]
    return bool(tokens) and all(_is_placeholder_token(token) for token in tokens)


def _is_placeholder_token(token: str) -> bool:
    if token in PLACEHOLDER_TOKENS:
        return True
    return bool(token) and set(token) <= {"x", "y", "z"}


def _looks_like_synthetic_proof(candidate: str) -> bool:
    match = re.fullmatch(r"[A-Za-z0-9_-]*\{([^}\s]{0,256})\}", candidate)
    if match is None:
        return False
    return _body_is_placeholder(match.group(1))


def _looks_like_bare_braced_proof(candidate: str) -> bool:
    match = re.fullmatch(r"\{([^}]*)\}", candidate, flags=re.DOTALL)
    if match is None:
        return False
    if is_placeholder_proof(candidate) or _looks_like_synthetic_proof(candidate):
        return False
    body = match.group(1).strip()
    compact = re.sub(r"\s+", "", body)
    if len(compact) < 6 or len(compact) > 256:
        return False
    if not re.search(r"[A-Za-z]", compact):
        return False
    if "." in body or "'" in body or '"' in body:
        return False
    if len(set(compact.lower())) <= 3:
        return False
    if "," in body:
        return False
    if _looks_like_code_fragment_body(body, compact):
        return False
    if _looks_like_high_entropy_bare_body(compact):
        return True
    if re.search(r"[A-Za-z]", compact) and re.search(r"\d", compact) and len(compact) >= 12:
        return True
    tokens = _body_tokens(body)
    return bool(
        re.search(r"[_/+=@#\-\s]", body)
        and re.search(r"\d", compact)
        and len(compact) >= 16
        and len(tokens) >= 3
    )


def _body_tokens(body: str) -> list[str]:
    return [token for token in re.split(r"[^A-Za-z0-9]+", body) if token]


def _looks_like_code_fragment_body(body: str, compact: str) -> bool:
    if "'" in body:
        return False

    tokens = _body_tokens(body)
    if not tokens:
        return False
    lowered_tokens = [token.lower() for token in tokens]
    high_entropy = _looks_like_high_entropy_bare_body(compact)
    has_digit = bool(re.search(r"\d", compact))
    if any(token in CODE_FRAGMENT_TOKENS for token in lowered_tokens) and not high_entropy:
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", compact) and not has_digit:
        if len(tokens) <= 2:
            return True
        short_tokens = [token for token in lowered_tokens if len(token) <= 2]
        if len(short_tokens) >= len(tokens) - 1:
            return True
    return False


def _looks_like_high_entropy_bare_body(compact: str) -> bool:
    if re.fullmatch(r"[A-Fa-f0-9]{16,}", compact):
        return bool(re.search(r"[A-Fa-f]", compact) and re.search(r"\d", compact))
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", compact):
        has_alpha = bool(re.search(r"[A-Za-z]", compact))
        has_digit = bool(re.search(r"\d", compact))
        mixed_case = bool(re.search(r"[a-z]", compact) and re.search(r"[A-Z]", compact))
        if ("_" in compact or "-" in compact) and not has_digit:
            return False
        return has_alpha and (has_digit or mixed_case) and len(set(compact.lower())) >= 8
    return False


def _decoded_fragments(text: str) -> list[str]:
    fragments: list[str] = []
    pattern = r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])"
    for match in re.finditer(pattern, text):
        token = match.group(1)
        try:
            decoded = base64.b64decode(token, validate=True)
        except Exception:  # noqa: BLE001 - arbitrary response text.
            continue
        rendered = decoded.decode("utf-8", errors="replace")
        if "{" in rendered:
            fragments.append(rendered)
    return fragments
