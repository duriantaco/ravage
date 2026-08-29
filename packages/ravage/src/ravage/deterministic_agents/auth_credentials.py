from __future__ import annotations

import json
import re

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.support import _dedupe
from ravage.web_core.http_probe import ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs

_DEFAULT_CREDENTIAL_IDENTITY_LIMIT = 56


def _common_credential_identities() -> list[dict[str, str]]:
    pairs = (
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("admin", "wordpress"),
        ("admin", "wordpress123"),
        ("admin", "backup"),
        ("admin", "backup123"),
        ("admin", "123456"),
        ("administrator", "password"),
        ("root", "root"),
        ("root", "toor"),
        ("user", "user"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("test", "test"),
        ("admin", "changeme"),
    )
    return _identities_from_pairs(list(pairs))


def _default_credential_identities() -> list[dict[str, str]]:
    pairs = (
        ("admin", "admin"),
        ("admin", "adminpass"),
        ("admin", "password"),
        ("admin", "password123"),
        ("admin", "admin123"),
        ("admin", "wordpress"),
        ("admin", "wordpress123"),
        ("admin", "backup"),
        ("admin", "backup123"),
        ("admin", "123456"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "qwerty"),
        ("admin", "letmein"),
        ("admin", "welcome"),
        ("admin", "changeme"),
        ("admin", "admin@123"),
        ("admin", "P@ssw0rd"),
        ("administrator", "password"),
        ("administrator", "administrator"),
        ("administrator", "admin"),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("john", "password123"),
        ("user", "user"),
        ("user", "password"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("test", "test"),
        ("support", "support"),
        ("operator", "operator"),
        ("manager", "manager"),
        ("webadmin", "password"),
        ("webadmin", "webadmin"),
        ("tomcat", "tomcat"),
        ("sa", ""),
        ("sa", "sa"),
        ("postgres", "postgres"),
        ("mysql", "mysql"),
        ("wordpress", "wordpress"),
        ("default", "default"),
        ("cisco", "cisco"),
        ("ubnt", "ubnt"),
        ("pi", "raspberry"),
    )
    return _identities_from_pairs(list(pairs))


def _default_credential_identities_for_state(
    session: ProbeSession,
    state: AgentState,
    requests: list[dict[str, object]],
    *,
    auth_forms: list[dict[str, object]] | None = None,
    limit: int = _DEFAULT_CREDENTIAL_IDENTITY_LIMIT,
) -> list[dict[str, str]]:
    seed_pairs = _state_seed_credential_pairs(state)
    discovered_pairs = _discover_default_credential_pairs(session, state, requests, auth_forms=auth_forms)
    usernames = _discover_default_credential_usernames(session, state, requests)
    for username in usernames:
        discovered_pairs.extend(
            [
                (username, username),
                (username, "password"),
                (username, "password123"),
                (username, "admin"),
                ("admin", username),
            ]
        )

    priority_defaults = _identities_from_pairs(
        [
            ("admin", "admin"),
            ("user", "user"),
            ("demo", "demo"),
            ("test", "test"),
            ("guest", "guest"),
            ("admin", "password"),
            ("admin", "password123"),
        ]
    )
    discovered = _identities_from_pairs([*seed_pairs, *discovered_pairs])
    defaults = _default_credential_identities()
    identities: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for identity in [*priority_defaults, *discovered, *defaults]:
        key = (identity["username"], identity["password"])
        if key in seen:
            continue
        seen.add(key)
        identities.append(identity)
    return identities[:limit]


def _state_seed_credential_pairs(state: AgentState) -> list[tuple[str, str]]:
    raw = state.surface.get("authorized_seed_credentials")
    if not isinstance(raw, list):
        return []

    pairs: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        password = str(item.get("password") or "").strip()
        if not username or not password:
            continue
        if recognize_proofs(username) or recognize_proofs(password):
            continue
        if not _looks_like_login_username(username):
            continue
        pairs.append((username, password))
    return _dedupe_pairs(pairs)[:4]


def _discover_default_credential_pairs(
    session: ProbeSession,
    state: AgentState,
    requests: list[dict[str, object]],
    *,
    auth_forms: list[dict[str, object]] | None = None,
) -> list[tuple[str, str]]:
    text = json.dumps(state.surface, sort_keys=True) + "\n" + json.dumps(state.signals, sort_keys=True)
    pairs = _credential_pairs_from_text(text)
    for url in _credential_discovery_urls(session, auth_forms=auth_forms):
        if len(pairs) >= 8:
            break
        response = session.get(url)
        requests.append(
            response.summary(body_chars=520)
            | {"probe_kind": "default_credentials_pair_discovery", "url": response.url}
        )
        if response.status not in {200, 201, 202}:
            continue
        pairs.extend(_credential_pairs_from_text(response.body))
    return _usable_credential_pairs(pairs)[:8]


def _credential_discovery_urls(
    session: ProbeSession,
    *,
    auth_forms: list[dict[str, object]] | None = None,
) -> list[str]:
    urls = [session.target_url, session.absolute("/"), session.absolute("/login"), session.absolute("/signin")]
    for form in auth_forms or []:
        action = str(form.get("action") or "")
        if action:
            urls.append(action)

    scoped_urls: list[str] = []
    for url in urls:
        if session.in_scope(url):
            scoped_urls.append(url)
    return _dedupe(scoped_urls)[:6]


def _credential_pairs_from_text(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for window in _credential_hint_windows(text):
        pairs.extend(_credential_pairs_from_window(window))
    return _dedupe_pairs(pairs)[:12]


def _credential_hint_windows(text: str) -> list[str]:
    windows: list[str] = []
    pattern = r"(?is)(?:default|credential|creds?|password|username|login|account|testing account|test account|todo)[^<\r\n]{0,180}"
    for match in re.finditer(pattern, text):
        start = max(0, match.start() - 80)
        end = min(len(text), match.end() + 80)
        windows.append(text[start:end])
    return windows[:20]


def _credential_pairs_from_window(window: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for match in re.finditer(
        r"\b([A-Za-z0-9_.-]{3,48})\s*[:/]\s*([A-Za-z0-9_.!@#$%^&*+=,;?-]{1,64})\b",
        window,
    ):
        username, password = match.group(1), match.group(2)
        if _credential_token_is_label(username):
            continue
        if _credential_pair_looks_static_asset(username, password):
            continue
        pairs.append((username, password))

    pattern = r"(?is)\b(?:user(?:name)?|login)\s*[:=]\s*([A-Za-z0-9_.-]{3,48}).{0,80}\bpass(?:word)?\s*[:=]\s*([A-Za-z0-9_.!@#$%^&*+=,;?-]{1,64})"
    for match in re.finditer(pattern, window):
        pairs.append((match.group(1), match.group(2)))
    return pairs


def _usable_credential_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    usable: list[tuple[str, str]] = []
    for username, password in pairs:
        if not _looks_like_login_username(username):
            continue
        if not _looks_like_default_password(password):
            continue
        if _credential_pair_looks_static_asset(username, password):
            continue
        usable.append((username, password))
    return _dedupe_pairs(usable)


def _credential_pair_looks_static_asset(username: str, password: str) -> bool:
    lowered_username = username.lower().strip()
    lowered_password = password.lower().strip()
    static_extensions = (
        ".js",
        ".css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".woff",
        ".woff2",
    )
    for extension in static_extensions:
        if lowered_password.endswith(extension):
            return True
    if "." in lowered_username and _text_contains_any(
        lowered_username,
        (
            "bootstrap",
            "cdn",
            "cdnjs",
            "code.jquery",
            "jquery",
            "jsdelivr",
            "popper",
            "stackpath",
            "static",
        ),
    ):
        return True
    if "." in lowered_username and _text_contains_any(lowered_password, ("jquery", "bootstrap", "popper", "bundle")):
        return True
    if "." in lowered_username and re.search(r"\b(?:cdn|static|assets?|js|css)\b", lowered_password):
        return True
    return False


def _credential_token_is_label(value: str) -> bool:
    return value.lower().strip(".-_") in {
        "http",
        "https",
        "todo",
        "delete",
        "account",
        "username",
        "password",
        "login",
        "credential",
        "credentials",
        "testing",
    }


def _looks_like_default_password(value: str) -> bool:
    if not value or len(value) > 64:
        return False
    for char in value:
        if char.isspace():
            return False
    lowered = value.lower().strip(".-_")
    return lowered not in {"http", "https", "username", "password", "login", "account", "credential"}


def _dedupe_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for username, password in pairs:
        key = (username, password)
        if key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def _discover_default_credential_usernames(
    session: ProbeSession,
    state: AgentState,
    requests: list[dict[str, object]],
) -> list[str]:
    text = json.dumps(state.surface, sort_keys=True) + "\n" + json.dumps(state.signals, sort_keys=True)
    usernames = _username_candidates_from_text(text)
    if _state_looks_wordpress(state) or usernames:
        for path in ("/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users", "/?author=1"):
            response = session.get(session.absolute(path))
            requests.append(
                response.summary(body_chars=420)
                | {"probe_kind": "default_credentials_username_discovery", "url": response.url}
            )
            usernames.extend(_username_candidates_from_text(response.body))
            location = str(response.headers.get("location") or response.headers.get("Location") or "")
            if location:
                usernames.extend(_username_candidates_from_text(location))
            if len(usernames) >= 8:
                break

    usable: list[str] = []
    for username in usernames:
        if _looks_like_login_username(username):
            usable.append(username)
    return _dedupe(usable)[:8]


def _state_looks_wordpress(state: AgentState) -> bool:
    text = (json.dumps(state.surface, sort_keys=True) + "\n" + json.dumps(state.signals, sort_keys=True)).lower()
    return _text_contains_any(text, ("wordpress", "wp-content", "wp-json", "wp-login.php", "wp-admin"))


def _username_candidates_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    for pattern in (
        r'''"(?:slug|username|user_login|login|user)\s*"\s*:\s*"([A-Za-z0-9_.-]{3,48})"''',
        r'''\buser_login['"`\s:=]+([A-Za-z0-9_.-]{3,48})''',
        r'''/author/([A-Za-z0-9_.-]{3,48})(?:[/?#'"<\s]|$)''',
        r'''\bauthor_name=([A-Za-z0-9_.-]{3,48})''',
        r'''\b([A-Za-z0-9_.-]{3,48})@[A-Za-z0-9_.-]+\.[A-Za-z]{2,}\b''',
    ):
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            candidates.append(match.group(1))
    return _dedupe(candidates)[:16]


def _looks_like_login_username(value: str) -> bool:
    lowered = value.lower().strip(".-_")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,47}", lowered):
        return False
    return lowered not in {
        "admin@example",
        "example",
        "localhost",
        "wordpress",
        "administrator",
        "password",
        "username",
        "login",
        "author",
        "users",
        "posts",
        "pages",
        "media",
    }


def _identities_from_pairs(pairs: list[tuple[str, str]]) -> list[dict[str, str]]:
    identities: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for username, password in pairs:
        if not username or (username, password) in seen:
            continue
        seen.add((username, password))
        identities.append(
            {
                "username": username,
                "email": f"{username}@example.test",
                "password": password,
            }
        )
    return identities


def _text_contains_any(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False
