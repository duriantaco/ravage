"""Small stdlib-backed subset of ``requests`` for isolated agent scripts.

The host runtime executes generated Python in a fresh temporary directory where
third-party packages are intentionally not assumed to exist.  This module is
copied there as ``requests.py`` and implements the common session, cookie, and
request helpers needed by generated web probes.
"""

from __future__ import annotations

import http.cookiejar
import json as _json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping, MutableMapping
from typing import Any


class RequestException(Exception):
    """Base exception compatible with the public requests exception shape."""


class HTTPError(RequestException):
    """Raised by :meth:`Response.raise_for_status` for HTTP error responses."""


class RequestsCookieJar(http.cookiejar.CookieJar, MutableMapping[str, str]):
    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __setitem__(self, name: str, value: str) -> None:
        self.set(name, value)

    def __delitem__(self, name: str) -> None:
        removed = False
        for cookie in list(http.cookiejar.CookieJar.__iter__(self)):
            if cookie.name != name:
                continue
            self.clear(cookie.domain, cookie.path, cookie.name)
            removed = True
        if not removed:
            raise KeyError(name)

    def __iter__(self) -> Iterator[str]:
        return iter(self.get_dict())

    def __len__(self) -> int:
        return len(self.get_dict())

    def set(
        self,
        name: str,
        value: str,
        *,
        domain: str = "",
        path: str = "/",
        **_kwargs: object,
    ) -> None:
        cookie = http.cookiejar.Cookie(
            version=0,
            name=str(name),
            value=str(value),
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=bool(domain),
            domain_initial_dot=domain.startswith("."),
            path=path,
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        )
        self.set_cookie(cookie)

    def get(
        self,
        name: str,
        default: str | None = None,
        *,
        domain: str | None = None,
        path: str | None = None,
    ) -> str | None:
        for cookie in http.cookiejar.CookieJar.__iter__(self):
            if cookie.name != name:
                continue
            if domain is not None and cookie.domain != domain:
                continue
            if path is not None and cookie.path != path:
                continue
            return cookie.value
        return default

    def get_dict(
        self,
        domain: str | None = None,
        path: str | None = None,
    ) -> dict[str, str]:
        result: dict[str, str] = {}
        for cookie in http.cookiejar.CookieJar.__iter__(self):
            if domain is not None and cookie.domain != domain:
                continue
            if path is not None and cookie.path != path:
                continue
            result[cookie.name] = cookie.value
        return result

    def update(self, other: Mapping[str, str] | None = None, **kwargs: str) -> None:
        values = dict(other or {})
        values.update(kwargs)
        for name, value in values.items():
            self.set(str(name), str(value))


class Response:
    def __init__(self, raw: Any) -> None:
        self.status_code = int(getattr(raw, "status", getattr(raw, "code", 0)) or 0)
        self.headers = dict(getattr(raw, "headers", {}) or {})
        self.url = str(raw.geturl())
        self.content = bytes(raw.read())
        self.encoding = "utf-8"

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> object:
        return _json.loads(self.text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise HTTPError(f"HTTP {self.status_code} for {self.url}")


class Session:
    def __init__(self) -> None:
        self.cookies = RequestsCookieJar()
        self.headers: dict[str, str] = {}
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, object] | list[tuple[str, object]] | None = None,
        data: Mapping[str, object] | list[tuple[str, object]] | bytes | str | None = None,
        json: object | None = None,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        timeout: float | None = None,
        **_kwargs: object,
    ) -> Response:
        if params:
            query = urllib.parse.urlencode(params, doseq=True)
            separator = "&" if urllib.parse.urlsplit(url).query else "?"
            url = f"{url}{separator}{query}"
        request_headers = dict(self.headers)
        request_headers.update(headers or {})
        if cookies:
            self.cookies.update(cookies)

        body: bytes | None = None
        if json is not None:
            body = _json.dumps(json).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, bytes):
            body = data
        elif isinstance(data, str):
            body = data.encode("utf-8")
        elif data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
            request_headers.setdefault(
                "Content-Type",
                "application/x-www-form-urlencoded",
            )

        request = urllib.request.Request(
            url,
            data=body,
            headers=request_headers,
            method=method.upper(),
        )
        try:
            raw = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            raw = exc
        except (OSError, urllib.error.URLError) as exc:
            raise RequestException(str(exc)) from exc
        return Response(raw)

    def get(self, url: str, **kwargs: object) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: object) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: object) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: object) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: object) -> Response:
        return self.request("DELETE", url, **kwargs)

    def close(self) -> None:
        return None

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def request(method: str, url: str, **kwargs: object) -> Response:
    with Session() as session:
        return session.request(method, url, **kwargs)


def get(url: str, **kwargs: object) -> Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: object) -> Response:
    return request("POST", url, **kwargs)


class _Exceptions:
    RequestException = RequestException
    HTTPError = HTTPError


class _Cookies:
    RequestsCookieJar = RequestsCookieJar


exceptions = _Exceptions()
cookies = _Cookies()
