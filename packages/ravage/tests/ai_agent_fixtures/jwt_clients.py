from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ravage.local_agent import HttpExchange

from .common import _decode_test_jwt
from .vulnerable_client import VulnerableOpenApiHttpClient

if TYPE_CHECKING:
    from collections.abc import Mapping

class IdentityBoundJwtHttpClient(VulnerableOpenApiHttpClient):
    def _jwt_response(
        self,
        url: str,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
    ) -> HttpExchange:
        raw_token = headers.get("Authorization", "").removeprefix("Bearer ").strip()
        raw_token = raw_token or cookies.get("session", "")
        payload = _decode_test_jwt(raw_token)
        if payload.get("username") != "auditor":
            return HttpExchange(method="GET", url=url, status_code=401, body="unknown user")
        if payload.get("role") == "admin" or payload.get("admin") is True:
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body="admin dashboard flag{jwt_identity_bound_admin}",
            )
        return HttpExchange(method="GET", url=url, status_code=403, body="admin required")


class NoDeltaJwtHttpClient(VulnerableOpenApiHttpClient):
    def get(self, url: str) -> HttpExchange:
        parsed = urlparse(url)
        if parsed.path == "/openapi.json":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body=json.dumps(
                    {
                        "paths": {
                            "/api/session": {"get": {}},
                            "/admin": {"get": {}},
                            "/admin/fetch": {"get": {}},
                            "/dashboard": {"get": {}},
                        }
                    }
                ),
            )
        return super().get(url)

    def request(  # noqa: PLR0913 - mirrors low-level HTTP client shape.
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        body: bytes | None = None,
        body_text: str | None = None,
    ) -> HttpExchange:
        _ = headers, cookies, body, body_text
        parsed = urlparse(url)
        if method == "GET" and parsed.path in {
            "/admin",
            "/admin/fetch",
            "/dashboard",
            "/api/admin",
        }:
            return HttpExchange(method="GET", url=url, status_code=404, body="not found")
        return super().request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            body=body,
            body_text=body_text,
        )
