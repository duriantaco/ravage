from __future__ import annotations

import base64
import pickle
import re
from typing import cast
from urllib.parse import unquote, urljoin

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probes.cookie_deserialization import (
    classify_cookie_value,
    probe_cookie_deserialization,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

SECRET = "FLAG{c00kie_d3s3r_pwn}"
ENV_SECRET = "FLAG{env_cookie_flag}"
_TOKEN = re.compile(rb"RAVAGE_DESER_[0-9a-f]+")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _jwt() -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"user":"guest"}').rstrip(b"=").decode()
    return f"{header}.{payload}.c2lnbmF0dXJlc2lnbmF0dXJl"


def _run_cookie_probe(session: ProbeSession, state: AgentState | None = None) -> ProbeRunResult:
    if state is None:
        state = AgentState()
    return probe_cookie_deserialization(session, state)


def test_classify_cookie_value_recognizes_formats() -> None:
    assert classify_cookie_value(_b64(pickle.dumps({"user": "guest"}, protocol=2))).kind == "pickle"
    assert classify_cookie_value(_b64(b"user: guest\nrole: user\n")).kind == "yaml"
    assert classify_cookie_value(_b64(b"[]\n")).kind == "yaml"
    assert classify_cookie_value(_b64(b'O:8:"stdClass":1:{s:4:"user";s:5:"guest";}')).kind == "php"
    assert classify_cookie_value(_b64(b'{"user":"guest"}')).kind == "json"

    flask = classify_cookie_value("eyJ1c2VyIjoiZ3Vlc3QifQ.aBcDeF.Zm9yZ2VyeXNpZ25hdHVyZXZhbHVl")
    assert flask.kind == "flask_signed" and flask.signed is True

    jwt = classify_cookie_value(_jwt())
    assert jwt.kind == "jwt" and jwt.signed is True

    assert classify_cookie_value("just-a-random-session-id-1234").kind == "none"


class _ReflectingApp:
    """Vulnerable app that reflects the deserialized cookie value in the page."""

    def __init__(self, cookie_value: str) -> None:
        self.target_url = "http://127.0.0.1/"
        self.cookie_value = cookie_value

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        if _is_gadget((headers or {}).get("Cookie", "")):
            return _resp(url, body=f"<h1>Welcome back {SECRET}</h1>")
        set_cookie = f"session={self.cookie_value}; Path=/; HttpOnly"
        return _resp(url, body="<h1>Welcome guest</h1>", set_cookie=set_cookie)


class _ReadbackApp:
    """Vulnerable app that does not reflect, but serves the written readback file."""

    def __init__(self, cookie_value: str) -> None:
        self.target_url = "http://127.0.0.1/"
        self.cookie_value = cookie_value

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        if re.search(r"/RAVAGE_DESER_[0-9a-f]+\.txt$", url):
            return _resp(url, body=f"{SECRET}\n")
        if _is_gadget((headers or {}).get("Cookie", "")):
            return _resp(url, body="<h1>Welcome guest</h1>")
        set_cookie = f"session={self.cookie_value}; Path=/"
        return _resp(url, body="<h1>Welcome guest</h1>", set_cookie=set_cookie)


class _BookmarkYamlApp:
    """App that expects a list-shaped YAML cookie and a sibling user cookie."""

    target_url = "http://127.0.0.1/"

    def __init__(self) -> None:
        self.cookie_value = _b64(b"[]\n")

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        cookie = (headers or {}).get("Cookie", "")
        if "user=keepme" in cookie and _decoded_cookie_contains(cookie, "bookmarks", b"- name: !!python/object/apply"):
            return _resp(url, body=f"<h5>{SECRET}</h5>")
        return _resp(url, body="<h1>Welcome guest</h1>", set_cookie=f"bookmarks={self.cookie_value}; Path=/, user=keepme; Path=/")


class _EnvironmentBookmarkYamlApp:
    """XBEN-075-style YAML cookie app with the proof stored in an environment variable."""

    target_url = "http://127.0.0.1/"

    def __init__(self) -> None:
        self.cookie_value = _b64(b"[]\n")

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        cookie = (headers or {}).get("Cookie", "")
        has_user_cookie = "user=keepme" in cookie
        has_environment_payload = _decoded_cookie_contains(cookie, "bookmarks", b"$FLAG")

        if has_user_cookie and has_environment_payload:
            body = f"<h5>b&#39;{ENV_SECRET}\\nRAVAGE_DESER_deadbeef&#39;</h5>"
            return _resp(url, body=body)

        set_cookie = f"bookmarks={self.cookie_value}; Path=/, user=keepme; Path=/"
        return _resp(url, body="<h1>Welcome guest</h1>", set_cookie=set_cookie)


class _FormIssuedYamlApp:
    """App that only creates the serialized cookie after a normal form workflow."""

    target_url = "http://127.0.0.1/"

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.target_url) or url.startswith("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        cookie = (headers or {}).get("Cookie", "")
        if "user=keepme" in cookie and _decoded_cookie_contains(cookie, "bookmarks", b"- name: !!python/object/apply"):
            return _resp(url, body=f"<h5>{SECRET}</h5>")
        return _resp(url, body="<form method='post' action='/add'><input name='name'><input name='url'></form>", set_cookie="user=keepme; Path=/")

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del fields, headers
        cookie = _b64(b"- !!python/object:app.models.UrlObj\n  name: ravage\n  url: http://127.0.0.1/\n")
        return _resp(url, body="<h1>saved</h1>", set_cookie=f"bookmarks={cookie}; Path=/\nuser=keepme; Path=/")


class _SignedApp:
    def __init__(self, cookie_value: str) -> None:
        self.target_url = "http://127.0.0.1/"
        self.cookie_value = cookie_value
        self.gadget_replays = 0

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        if _is_gadget((headers or {}).get("Cookie", "")):
            self.gadget_replays += 1
        set_cookie = f"session={self.cookie_value}; Path=/"
        return _resp(url, body="<h1>Welcome guest</h1>", set_cookie=set_cookie)


class _BodyPayloadDeserializationApp:
    target_url = "http://127.0.0.1/"

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.target_url) or url.startswith("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return _resp(url, body="<h1>Import profile</h1>")

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        value = fields.get("payload", "")
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:  # noqa: BLE001
            decoded = b""
        if _TOKEN.search(decoded):
            return _resp(url, body=f"loaded profile {SECRET}")
        return _resp(url, body="invalid payload", set_cookie="")


def _resp(url: str, *, body: str, set_cookie: str = "") -> ProbeResponse:
    headers = {"set-cookie": set_cookie} if set_cookie else {}
    return ProbeResponse(method="GET", url=url, status=200, final_url=url, elapsed_ms=5, headers=headers, body=body)


def _is_gadget(cookie: str) -> bool:
    if "=" not in cookie:
        return False
    value = unquote(cookie.split("=", 1)[1])
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(value + "=" * (-len(value) % 4))
        except Exception:  # noqa: BLE001
            continue
        if _TOKEN.search(decoded):
            return True
    return "RAVAGE_DESER_" in value


def _decoded_cookie_contains(cookie: str, name: str, needle: bytes) -> bool:
    for part in cookie.split(";"):
        part = part.strip()
        if not part.startswith(name + "="):
            continue
        value = unquote(part.split("=", 1)[1])
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:  # noqa: BLE001
            return False
        return needle in decoded
    return False


def _findings_by_type(result) -> set[str]:
    return {str(finding.get("type")) for finding in result.findings}


def test_pickle_cookie_deserialization_reflects_proof() -> None:
    cookie = _b64(pickle.dumps({"user": "guest"}, protocol=2))
    result = _run_cookie_probe(cast(ProbeSession, _ReflectingApp(cookie)))

    types = _findings_by_type(result)
    assert "insecure_deserialization_cookie_signal" in types
    assert "cookie_deserialization_extracted_proof" in types
    assert result.ok
    proofs = [f["proof"] for f in result.findings if f.get("type") == "cookie_deserialization_extracted_proof"]
    assert SECRET in proofs


def test_yaml_cookie_deserialization_reflects_proof() -> None:
    cookie = _b64(b"user: guest\nrole: user\n")
    result = _run_cookie_probe(cast(ProbeSession, _ReflectingApp(cookie)))

    assert "cookie_deserialization_extracted_proof" in _findings_by_type(result)


def test_cookie_deserialization_readback_channel() -> None:
    cookie = _b64(pickle.dumps({"user": "guest"}, protocol=2))
    result = _run_cookie_probe(cast(ProbeSession, _ReadbackApp(cookie)))

    proofs = [
        f for f in result.findings if f.get("type") == "cookie_deserialization_extracted_proof"
    ]
    assert proofs and proofs[0]["channel"] == "readback"
    assert proofs[0]["proof"] == SECRET


def test_yaml_cookie_deserialization_preserves_container_shape_and_sibling_cookies() -> None:
    result = _run_cookie_probe(cast(ProbeSession, _BookmarkYamlApp()))

    types = _findings_by_type(result)
    assert "insecure_deserialization_cookie_signal" in types
    assert "cookie_deserialization_extracted_proof" in types


def test_yaml_cookie_deserialization_extracts_environment_backed_flag() -> None:
    result = _run_cookie_probe(cast(ProbeSession, _EnvironmentBookmarkYamlApp()))

    proofs: list[object] = []
    for finding in result.findings:
        if finding.get("type") == "cookie_deserialization_extracted_proof":
            proofs.append(finding["proof"])

    assert ENV_SECRET in proofs


def test_cookie_deserialization_harvests_serialized_cookies_from_forms() -> None:
    state = AgentState()
    state.surface = {
        "forms": [
            {
                "method": "POST",
                "action": "http://127.0.0.1/add",
                "inputs": [
                    {"name": "name", "type": "text"},
                    {"name": "url", "type": "url"},
                ],
            }
        ]
    }

    result = _run_cookie_probe(cast(ProbeSession, _FormIssuedYamlApp()), state)

    types = _findings_by_type(result)
    assert "insecure_deserialization_cookie_signal" in types
    assert "cookie_deserialization_extracted_proof" in types


def test_body_payload_deserialization_extracts_proof_from_observed_form_field() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "forms": [
            {
                "method": "POST",
                "action": "http://127.0.0.1/import",
                "inputs": [{"name": "payload", "type": "text"}],
            }
        ],
    }

    result = _run_cookie_probe(cast(ProbeSession, _BodyPayloadDeserializationApp()), state)

    types = _findings_by_type(result)
    assert "body_deserialization_extracted_proof" in types
    proofs = [f["proof"] for f in result.findings if f.get("type") == "body_deserialization_extracted_proof"]
    assert SECRET in proofs
    assert any(request.get("probe_kind") == "body_deserialization_payload" for request in result.requests)


def test_signed_cookie_is_reported_not_forged() -> None:
    app = _SignedApp("eyJ1c2VyIjoiZ3Vlc3QifQ.aBcDeF.Zm9yZ2VyeXNpZ25hdHVyZXZhbHVl")
    result = _run_cookie_probe(cast(ProbeSession, app))

    types = _findings_by_type(result)
    assert "insecure_deserialization_cookie_signal" in types
    assert "cookie_deserialization_extracted_proof" not in types
    assert app.gadget_replays == 0


def test_cookie_from_state_signal_is_considered() -> None:
    cookie = _b64(pickle.dumps({"user": "guest"}, protocol=2))
    state = AgentState()
    state.signals["cookies"] = [f"session={cookie}; Path=/; HttpOnly"]

    class _NoBaselineCookie(_ReflectingApp):
        def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
            if _is_gadget((headers or {}).get("Cookie", "")):
                return _resp(url, body=f"<h1>{SECRET}</h1>")
            return _resp(url, body="<h1>guest</h1>")  # baseline hands out no cookie

    result = _run_cookie_probe(cast(ProbeSession, _NoBaselineCookie(cookie)), state)
    assert "cookie_deserialization_extracted_proof" in _findings_by_type(result)


class _PhpTamperApp:
    target_url = "http://127.0.0.1/"

    def __init__(self) -> None:
        self.cookie_value = _b64(b'O:11:"UserProfile":1:{s:6:"userid";i:3;}')

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        cookie = (headers or {}).get("Cookie", "")
        if "=" in cookie:
            encoded = unquote(cookie.split("=", 1)[1])
            decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8", errors="replace")
            if 's:6:"userid";i:1;' in decoded:
                return _resp(url, body=f"<h1>admin profile {SECRET}</h1>")
        return _resp(url, body="<h1>guest profile</h1>", set_cookie=f"data={self.cookie_value}; Path=/")


def test_php_serialized_cookie_property_tamper_extracts_proof() -> None:
    result = _run_cookie_probe(cast(ProbeSession, _PhpTamperApp()))

    types = _findings_by_type(result)
    assert "insecure_deserialization_cookie_signal" in types
    assert "cookie_deserialization_extracted_proof" in types


class _PhpAuthCookieApp:
    target_url = "http://127.0.0.1/"

    def __init__(self) -> None:
        self.cookie_value = _b64(b'O:11:"UserProfile":2:{s:6:"userid";i:3;s:8:"username";s:4:"demo";}')
        self.registered: dict[str, str] = {}

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.target_url) or url.startswith("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        cookie = (headers or {}).get("Cookie", "")
        if "=" in cookie:
            encoded = unquote(cookie.split("data=", 1)[1].split(";", 1)[0]) if "data=" in cookie else ""
            if encoded:
                decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8", errors="replace")
                if 's:6:"userid";i:1;' in decoded:
                    return _resp(url, body=f"<h1>Welcome admin</h1><p>{SECRET}</p>")
        return _resp(url, body="<h1>Sign in</h1>")

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        path = url.split("http://127.0.0.1", 1)[-1]
        username = fields.get("username", "")
        password = fields.get("password", "")
        if path.endswith("/sign-up.php") and username and password:
            self.registered[username] = password
            return _resp(url, body="registered")
        if path.endswith("/sign-in.php") and self.registered.get(username) == password:
            return _resp(url, body="signed in", set_cookie=f"data={self.cookie_value}; Path=/")
        return _resp(url, body="invalid")


class _TransientPhpAuthCookieApp(_PhpAuthCookieApp):
    def __init__(self) -> None:
        super().__init__()
        self.transient_failures = 2

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        if self.transient_failures > 0:
            self.transient_failures -= 1
            return _resp(
                url,
                body=(
                    "<b>Warning</b>: mysqli::__construct(): (HY000/2002): "
                    "Connection refused<br>Connection failed: Connection refused"
                ),
            )
        return super().post_form(url, fields, headers=headers)


def test_php_serialized_cookie_harvests_auth_flow_then_tampers_identity() -> None:
    state = AgentState()
    state.surface = {
        "forms": [
            {
                "method": "POST",
                "action": "http://127.0.0.1/sign-in.php",
                "page": "http://127.0.0.1/sign-in.php",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                    {"name": "", "type": "submit", "value": "Login"},
                ],
            },
            {
                "method": "POST",
                "action": "http://127.0.0.1/sign-up.php",
                "page": "http://127.0.0.1/sign-up.php",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                    {"name": "", "type": "submit", "value": "Register"},
                ],
            },
        ],
    }

    result = _run_cookie_probe(cast(ProbeSession, _PhpAuthCookieApp()), state)

    types = _findings_by_type(result)
    assert "insecure_deserialization_cookie_signal" in types
    assert "cookie_deserialization_extracted_proof" in types
    assert any(request.get("gadget") == "auth_cookie_harvest" for request in result.requests)


def test_php_auth_cookie_harvest_retries_transient_backend_startup(monkeypatch) -> None:
    monkeypatch.setattr(
        "ravage.probes.cookie.cookie_deserialization_discovery.time.sleep",
        lambda _delay: None,
    )
    state = AgentState()
    state.surface = {
        "forms": [
            {
                "method": "POST",
                "action": "http://127.0.0.1/sign-in.php",
                "page": "http://127.0.0.1/sign-in.php",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                    {"name": "", "type": "submit", "value": "Login"},
                ],
            },
            {
                "method": "POST",
                "action": "http://127.0.0.1/sign-up.php",
                "page": "http://127.0.0.1/sign-up.php",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                    {"name": "", "type": "submit", "value": "Register"},
                ],
            },
        ],
    }
    app = _TransientPhpAuthCookieApp()

    result = _run_cookie_probe(cast(ProbeSession, app), state)

    assert app.transient_failures == 0
    assert "cookie_deserialization_extracted_proof" in _findings_by_type(result)
