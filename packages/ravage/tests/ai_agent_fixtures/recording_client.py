from __future__ import annotations

from typing import TYPE_CHECKING

from ravage.local_agent import HttpExchange

from .vulnerable_client import VulnerableOpenApiHttpClient

if TYPE_CHECKING:
    from collections.abc import Mapping

class RecordingHttpClient(VulnerableOpenApiHttpClient):
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

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
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers or {}),
                "cookies": dict(cookies or {}),
                "body": body,
                "body_text": body_text,
            }
        )
        return HttpExchange(method=method, url=url, status_code=200, body="ok")
