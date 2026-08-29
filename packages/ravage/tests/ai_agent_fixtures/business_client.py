from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ravage.local_agent import HttpExchange

from .vulnerable_client import VulnerableOpenApiHttpClient

if TYPE_CHECKING:
    from collections.abc import Mapping


class JsonBusinessLogicHttpClient(VulnerableOpenApiHttpClient):
    def __init__(self) -> None:
        self.beta_admin = False

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
                            "/api/preferences": {"post": {}},
                            "/beta/deals": {"get": {}},
                        },
                    }
                ),
            )
        if parsed.path == "/beta/deals":
            body = (
                "beta admin flag{json_business_logic}"
                if self.beta_admin
                else "beta controls locked"
            )
            return HttpExchange(method="GET", url=url, status_code=200, body=body)
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
        _ = headers, cookies, body
        parsed = urlparse(url)
        if method == "POST" and parsed.path == "/api/preferences":
            request_body = body_text or "{}"
            payload = json.loads(request_body)
            if _contains_truthy_key(payload, {"admin", "is_admin", "isAdmin", "betaAdmin"}):
                self.beta_admin = True
            return HttpExchange(
                method=method,
                url=url,
                status_code=200,
                body=json.dumps({"ok": True, "beta_admin": self.beta_admin}),
                request_body=request_body,
            )
        return super().request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            body=body,
            body_text=body_text,
        )


def _contains_truthy_key(value: object, keys: set[str]) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in keys and child is True:
                return True
            if _contains_truthy_key(child, keys):
                return True
    if isinstance(value, list):
        return any(_contains_truthy_key(child, keys) for child in value)
    return False
