from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from ravage.local_agent import HttpExchange

from .vulnerable_client import VulnerableOpenApiHttpClient

if TYPE_CHECKING:
    from collections.abc import Mapping


class BlockedSsrfAfterAuthHttpClient(VulnerableOpenApiHttpClient):
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
                            "/admin/fetch": {
                                "get": {
                                    "parameters": [
                                        {"name": "url", "in": "query"},
                                    ],
                                },
                            },
                        },
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
        _ = headers, body, body_text
        parsed = urlparse(url)
        if method == "GET" and parsed.path == "/admin/fetch":
            if (cookies or {}).get("session") != "admin":
                return HttpExchange(method="GET", url=url, status_code=403, body="requires admin")
            candidate = parse_qs(parsed.query).get("url", [""])[0]
            response_body = (
                "internal admin flag{ssrf_after_auth}"
                if candidate == "http://127.0.0.1/admin"
                else "fetch failed"
            )
            return HttpExchange(method="GET", url=url, status_code=200, body=response_body)
        return super().request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            body=body,
            body_text=body_text,
        )


class BlockedIdorAfterAuthHttpClient(VulnerableOpenApiHttpClient):
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
                            "/api/orders": {
                                "get": {
                                    "parameters": [
                                        {"name": "id", "in": "query"},
                                    ],
                                },
                            },
                        },
                    }
                ),
            )
        return super().get(url)

    def request(  # noqa: PLR0913 - test double mirrors low-level HTTP client shape.
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        body: bytes | None = None,
        body_text: str | None = None,
    ) -> HttpExchange:
        _ = headers, body, body_text
        parsed = urlparse(url)
        if method == "POST" and parsed.path == "/login":
            return HttpExchange(method="POST", url=url, status_code=401, body="login required")
        if method == "GET" and parsed.path == "/api/orders":
            if (cookies or {}).get("session") != "buyer":
                return HttpExchange(method="GET", url=url, status_code=401, body="login required")
            order_id = parse_qs(parsed.query).get("id", ["1"])[0]
            response_body = (
                "order owner=admin flag{idor_after_auth}"
                if order_id == "2"
                else "order owner=buyer"
            )
            return HttpExchange(method="GET", url=url, status_code=200, body=response_body)
        return super().request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            body=body,
            body_text=body_text,
        )
