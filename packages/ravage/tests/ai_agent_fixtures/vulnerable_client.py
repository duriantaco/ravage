from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from ravage.local_agent import HttpExchange

from .common import _decode_test_jwt, _test_jwt

if TYPE_CHECKING:
    from collections.abc import Mapping


class VulnerableOpenApiHttpClient:
    def get(  # noqa: C901, PLR0911, PLR0912 - fixture routes stay readable.
        self,
        url: str,
    ) -> HttpExchange:
        parsed = urlparse(url)
        if parsed.path == "/openapi.json":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body=json.dumps(
                    {
                        "paths": {
                            "/search": {
                                "get": {
                                    "parameters": [
                                        {"name": "q", "in": "query"},
                                    ],
                                },
                            }
                        },
                    }
                ),
            )
        if parsed.path == "/":
            return HttpExchange(method="GET", url=url, status_code=200, body="<html></html>")
        if parsed.path == "/search":
            return self._search_response(url)
        if parsed.path == "/direct-union":
            return self._direct_union_response(url)
        if parsed.path == "/reflected-union":
            return self._reflected_union_response(url)
        if parsed.path == "/ssti":
            return self._ssti_response(url)
        if parsed.path == "/cmd":
            return self._command_response(url)
        if parsed.path == "/file":
            return self._lfi_response(url)
        if parsed.path == "/idor":
            return self._idor_response(url)
        if parsed.path == "/ssrf":
            return self._ssrf_response(url)
        if parsed.path == "/login":
            return HttpExchange(method="GET", url=url, status_code=200, body="login form")
        if parsed.path == "/api/session":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body=json.dumps({"session": _test_jwt({"sub": "user", "admin": False})}),
            )
        if parsed.path == "/race":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body="success flag{race_condition}",
            )
        return HttpExchange(method="GET", url=url, status_code=404, body="")

    def post_form(self, url: str, _data: Mapping[str, str]) -> HttpExchange:
        return HttpExchange(method="POST", url=url, status_code=404, body="")

    def post_json(self, url: str, _data: Mapping[str, str]) -> HttpExchange:
        return HttpExchange(method="POST", url=url, status_code=404, body="")

    def request(  # noqa: PLR0911, PLR0913 - test double mirrors low-level HTTP request fields.
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        body: bytes | None = None,
        body_text: str | None = None,
    ) -> HttpExchange:
        _ = headers, cookies, body
        parsed = urlparse(url)
        request_body = body_text or ""
        if method == "GET" and parsed.path == "/jwt":
            return self._jwt_response(url, headers or {}, cookies or {})
        if method == "GET" and parsed.path == "/api/admin":
            return self._jwt_response(url, headers or {}, cookies or {})
        if method == "GET":
            return self.get(url)
        if method == "POST" and parsed.path == "/echo":
            return HttpExchange(
                method=method,
                url=url,
                status_code=200,
                body=f"echo:{request_body}:flag{{unit_xben_capture}}",
                request_body=request_body,
            )
        if method == "POST" and parsed.path == "/login":
            return self._login_response(url, request_body)
        if method == "POST" and parsed.path == "/xxe":
            return self._xxe_response(url, request_body)
        if method == "POST" and parsed.path == "/upload":
            return self._upload_response(url, request_body)
        if method == "POST" and parsed.path == "/nosql":
            return self._nosql_response(url, request_body)
        if method == "POST" and parsed.path == "/race":
            return HttpExchange(
                method=method,
                url=url,
                status_code=200,
                body="success flag{race_condition}",
                request_body=request_body,
            )
        return HttpExchange(
            method=method,
            url=url,
            status_code=404,
            body="",
            request_body=request_body,
        )

    def _search_response(self, url: str) -> HttpExchange:
        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        if q == "%' OR 1=1 -- ":
            body = '{"results":["alice","bob","charlie"]}'
        elif q == "%' AND 1=2 -- ":
            body = '{"results":[]}'
        elif q == "'":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=500,
                body="sqlite3.OperationalError: unrecognized token",
            )
        else:
            body = '{"results":["alice"]}'
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _direct_union_response(self, url: str) -> HttpExchange:
        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        if "union select" in q.lower():
            body = "direct union disclosure flag{direct_union_flag}"
        elif "'" in q:
            return HttpExchange(
                method="GET",
                url=url,
                status_code=500,
                body="sqlite syntax error near quote",
            )
        else:
            body = "ordinary search result"
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _reflected_union_response(self, url: str) -> HttpExchange:
        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        lowered = q.lower()
        if q == "'":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=500,
                body="sqlite syntax error near quote",
            )
        if "union select" in lowered and " from secrets" in lowered and "value" in lowered:
            body = json.dumps(
                {
                    "query": f"SELECT id, name FROM products WHERE name LIKE '%{q}%'",  # noqa: S608
                    "results": [{"name": "flag{reflected_union_flag}"}],
                }
            )
            return HttpExchange(method="GET", url=url, status_code=200, body=body)
        if "union select" in lowered and "ravage_sqli_" in lowered:
            markers = re.findall(r"RAVAGE_SQLI_[A-Za-z0-9_]+", q)
            body = json.dumps(
                {
                    "query": f"SELECT id, name FROM products WHERE name LIKE '%{q}%'",  # noqa: S608
                    "results": [{"marker": marker} for marker in markers],
                }
            )
            return HttpExchange(method="GET", url=url, status_code=200, body=body)
        body = json.dumps(
            {
                "query": f"SELECT id, name FROM products WHERE name LIKE '%{q}%'",  # noqa: S608
                "results": [],
            }
        )
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _idor_response(self, url: str) -> HttpExchange:
        user_id = parse_qs(urlparse(url).query).get("id", ["1"])[0]
        body = "profile:alice" if user_id == "1" else "admin secret flag{idor_access}"
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _jwt_response(
        self,
        url: str,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
    ) -> HttpExchange:
        raw_token = headers.get("Authorization", "").removeprefix("Bearer ").strip()
        raw_token = raw_token or cookies.get("session", "")
        payload = _decode_test_jwt(raw_token)
        body = (
            "admin dashboard flag{jwt_admin}" if payload.get("admin") is True else "user dashboard"
        )
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _ssrf_response(self, url: str) -> HttpExchange:
        candidate = parse_qs(urlparse(url).query).get("url", [""])[0]
        if candidate in {"http://127.0.0.1/admin", "http://localhost/admin"}:
            body = "internal admin flag{ssrf_local}"
        elif candidate == "http://127.0.0.1/metadata":
            body = json.dumps({"service": {"flag_path": "/internal/flag"}})
        elif candidate == "http://127.0.0.1/internal/flag":
            body = "internal service flag{ssrf_followup}"
        else:
            body = "fetch failed"
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _ssti_response(self, url: str) -> HttpExchange:
        value = parse_qs(urlparse(url).query).get("tpl", [""])[0]
        if "popen" in value and "flag.txt" in value:
            body = "rendered:flag{ssti_file_read}"
        else:
            body = "rendered:49" if value in {"{{7*7}}", "${7*7}"} else "rendered:baseline"
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _command_response(self, url: str) -> HttpExchange:
        value = parse_qs(urlparse(url).query).get("name", [""])[0]
        if value == "'":
            body = "sh: syntax error: unterminated quoted string"
        elif " cat flag.txt" in value or " cat ./flag.txt" in value:
            body = "flag{command_followup_flag}"
        elif " echo " in value:
            marker = value.split(" echo ", 1)[1].split()[0]
            body = marker
        else:
            body = f"hello {value}"
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _lfi_response(self, url: str) -> HttpExchange:
        value = parse_qs(urlparse(url).query).get("path", [""])[0]
        if "etc/passwd" in value:
            body = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            )
        elif value in {"flag.txt", "./flag.txt", "../flag.txt", "../../flag.txt"}:
            body = "flag{lfi_followup_flag}"
        else:
            body = "file not found"
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def _login_response(self, url: str, body_text: str) -> HttpExchange:
        values = parse_qs(body_text)
        body = (
            "welcome admin dashboard flag{default_creds}"
            if values.get("username") == ["admin"] and values.get("password") == ["admin"]
            else "invalid login"
        )
        return HttpExchange(method="POST", url=url, status_code=200, body=body)

    def _xxe_response(self, url: str, body_text: str) -> HttpExchange:
        body = "root:x:0:0:root:/root:/bin/bash" if "/etc/passwd" in body_text else "ok"
        return HttpExchange(
            method="POST",
            url=url,
            status_code=200,
            body=body,
            request_body=body_text,
        )

    def _upload_response(self, url: str, body_text: str) -> HttpExchange:
        match = re.search(r"RAVAGE_UPLOAD_[A-Fa-f0-9]+", body_text)
        body = f"stored {match.group(0)}" if match else "upload failed"
        return HttpExchange(
            method="POST",
            url=url,
            status_code=200,
            body=body,
            request_body=body_text,
        )

    def _nosql_response(self, url: str, body_text: str) -> HttpExchange:
        body = "admin flag{nosqli_operator}" if "$ne" in body_text else "login denied"
        return HttpExchange(
            method="POST",
            url=url,
            status_code=200,
            body=body,
            request_body=body_text,
        )
