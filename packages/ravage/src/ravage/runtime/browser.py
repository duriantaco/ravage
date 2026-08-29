from __future__ import annotations

import contextlib
import base64
import html
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from http.client import HTTPMessage
from typing import IO, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from ravage.runtime.common import assert_tool_target_url
from ravage.web_core.scope_policy import is_local_url, same_origin, url_in_scope_entries

# JavaScript binding the probe payloads call to prove real DOM execution. A
# reflected marker only tells us text came back; calling this binding (or firing
# a dialog that carries the token) tells us the browser actually executed it.
EXEC_BINDING = "__ravage_exec"

_NAV_TIMEOUT_PADDING_MS = 2_000
_DEFAULT_SETTLE_MS = 1_500
_SNIPPET_CHARS = 600
_CONSOLE_CHARS = 2_000
_MAX_REDIRECTS = 6
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_CHROME_CANDIDATES = (
    "google-chrome",
    "chromium",
    "chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


class _BrowserRoute(Protocol):
    request: object

    def continue_(self) -> None:
        ...

    def abort(self) -> None:
        ...


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        _ = req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True)
class BrowserStatus:
    available: bool
    reason: str = ""


@dataclass(frozen=True)
class BrowserObservation:
    available: bool
    url: str
    token_executed: bool = False
    final_url: str = ""
    title: str = ""
    executed_values: list[str] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)
    console: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    body_snippet: str = ""
    error: str = ""
    reason: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "available": self.available,
            "url": self.url,
            "token_executed": self.token_executed,
            "final_url": self.final_url,
            "title": self.title,
            "executed_values": self.executed_values,
            "dialogs": self.dialogs,
            "console": self.console,
            "page_errors": self.page_errors,
            "body_snippet": self.body_snippet,
            "error": self.error,
            "reason": self.reason,
        }


def browser_backend_status() -> BrowserStatus:
    """Report whether a headless browser backend is usable, without launching it."""
    playwright_status = _playwright_backend_status()
    if playwright_status.available:
        return playwright_status
    chrome_path = _chrome_executable()
    if chrome_path:
        return BrowserStatus(
            available=True,
            reason=f"{playwright_status.reason}; using local Chrome DevTools fallback",
        )
    return playwright_status


def _playwright_backend_status() -> BrowserStatus:
    try:
        import playwright.sync_api  # noqa: F401, PLC0415 - optional dependency probed lazily.
    except Exception as exc:  # noqa: BLE001 - any import failure means unavailable.
        return BrowserStatus(
            available=False,
            reason=f"playwright import failed: {exc}",
        )
    return BrowserStatus(available=True)


def _chrome_executable() -> str:
    for candidate in _CHROME_CANDIDATES:
        if "/" in candidate:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        path = shutil.which(candidate)
        if path:
            return path
    return ""


def render_url(
    url: str,
    *,
    token: str,
    origin: str,
    timeout_seconds: int = 10,
    settle_ms: int = _DEFAULT_SETTLE_MS,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> BrowserObservation:
    """
    Load ``url`` in headless Chromium and report whether ``token`` executed.

    Target-origin and URL-scope guards mirror the HTTP probe path so the browser
    cannot be steered outside the authorized target. Any backend or navigation
    failure is returned as a structured observation rather than raised, so a
    missing browser never aborts the agent loop.
    """
    status = _playwright_backend_status()
    if not status.available:
        return _render_url_with_chrome_devtools(
            url,
            token=token,
            origin=origin,
            timeout_seconds=timeout_seconds,
            settle_ms=settle_ms,
            unavailable_reason=status.reason,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )

    scope_error = _scope_error(
        origin=origin,
        url=url,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    if scope_error:
        return BrowserObservation(available=True, url=url, error=scope_error)
    resolved_url, redirect_error = _resolve_scoped_redirects(
        url,
        origin=origin,
        timeout_seconds=timeout_seconds,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    if redirect_error:
        return BrowserObservation(available=True, url=url, error=redirect_error)

    from playwright.sync_api import (  # noqa: PLC0415 - optional dependency imported lazily.
        Error as PlaywrightError,
    )
    from playwright.sync_api import (
        TimeoutError as PlaywrightTimeoutError,
    )
    from playwright.sync_api import (
        sync_playwright,
    )

    executed: list[str] = []
    dialogs: list[str] = []
    console: list[str] = []
    page_errors: list[str] = []
    nav_timeout_ms = max(1, timeout_seconds) * 1000 + _NAV_TIMEOUT_PADDING_MS

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = browser.new_context(ignore_https_errors=True, service_workers="block")
                context.route(
                    "**/*",
                    lambda route: _guard_route(
                        route,
                        origin,
                        allow_remote_target=allow_remote_target,
                        in_scope=in_scope,
                        out_of_scope=out_of_scope,
                    ),
                )
                page = context.new_page()
                page.expose_function(
                    EXEC_BINDING,
                    lambda *args: executed.append(str(args[0]) if args else ""),
                )
                page.on("dialog", lambda dialog: _handle_dialog(dialog, dialogs))
                page.on("console", lambda message: console.append(_console_text(message)))
                page.on("pageerror", lambda error: page_errors.append(_clip(str(error))))
                page.goto(resolved_url, wait_until="load", timeout=nav_timeout_ms)
                page.wait_for_timeout(settle_ms)
                final_url = page.url
                final_scope_error = _scope_error(
                    origin=origin,
                    url=final_url,
                    allow_remote_target=allow_remote_target,
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                )
                if final_scope_error:
                    return BrowserObservation(
                        available=True,
                        url=url,
                        token_executed=_token_executed(token, executed, dialogs),
                        final_url=final_url,
                        executed_values=executed[:10],
                        dialogs=dialogs[:10],
                        console=console[:20],
                        page_errors=page_errors[:10],
                        error=f"final browser URL outside scope: {final_scope_error}",
                    )
                title = _clip(page.title())
                body = page.content()
            finally:
                browser.close()
    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        error = _classify_launch_error(str(exc))
        backend_unavailable = _is_backend_unavailable_error(str(exc))
        return BrowserObservation(
            available=not backend_unavailable,
            url=url,
            token_executed=_token_executed(token, executed, dialogs),
            executed_values=executed,
            dialogs=dialogs,
            console=console[:20],
            page_errors=page_errors[:10],
            error=error,
            reason=error if backend_unavailable else "",
        )
    except Exception as exc:  # noqa: BLE001 - the browser must never crash the loop.
        return BrowserObservation(available=True, url=url, error=str(exc)[:300])

    return BrowserObservation(
        available=True,
        url=url,
        token_executed=_token_executed(token, executed, dialogs),
        final_url=final_url,
        title=title,
        executed_values=executed[:10],
        dialogs=dialogs[:10],
        console=console[:20],
        page_errors=page_errors[:10],
        body_snippet=_clip(body, _SNIPPET_CHARS),
    )


def render_request(
    url: str,
    *,
    method: str,
    fields: dict[str, str] | None,
    token: str,
    origin: str,
    page_url: str = "",
    timeout_seconds: int = 10,
    settle_ms: int = _DEFAULT_SETTLE_MS,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> BrowserObservation:
    """Render a same-origin GET/POST request in Chromium.

    ``render_url`` is enough for query-string XSS, but form-backed sinks often
    require preserving the original method and hidden fields. This helper keeps
    the browser verifier aligned with the discovered request template.
    """
    upper_method = method.upper()
    if upper_method == "GET":
        return render_url(
            url,
            token=token,
            origin=origin,
            timeout_seconds=timeout_seconds,
            settle_ms=settle_ms,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )
    if upper_method != "POST":
        return BrowserObservation(available=True, url=url, error=f"unsupported browser request method: {upper_method}")

    status = _playwright_backend_status()
    if not status.available:
        return _render_request_with_chrome_devtools(
            url,
            method=upper_method,
            fields=fields or {},
            token=token,
            origin=origin,
            page_url=page_url,
            timeout_seconds=timeout_seconds,
            settle_ms=settle_ms,
            unavailable_reason=status.reason,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )

    scope_error = _scope_error(
        origin=origin,
        url=url,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    if scope_error:
        return BrowserObservation(available=True, url=url, error=scope_error)
    # POST verifier pages only need a same-origin context before auto-submitting
    # the preserved form. Fetching the form page itself can be slow or side-effectful,
    # so prefer the origin root unless the caller supplied no origin.
    start_url = _scoped_start_url(
        origin=origin,
        page_url=page_url,
        request_url=url,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )

    from playwright.sync_api import (  # noqa: PLC0415 - optional dependency imported lazily.
        Error as PlaywrightError,
    )
    from playwright.sync_api import (
        TimeoutError as PlaywrightTimeoutError,
    )
    from playwright.sync_api import (
        sync_playwright,
    )

    executed: list[str] = []
    dialogs: list[str] = []
    console: list[str] = []
    page_errors: list[str] = []
    nav_timeout_ms = max(1, timeout_seconds) * 1000 + _NAV_TIMEOUT_PADDING_MS

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = browser.new_context(ignore_https_errors=True, service_workers="block")
                context.route(
                    "**/*",
                    lambda route: _guard_route(
                        route,
                        origin,
                        allow_remote_target=allow_remote_target,
                        in_scope=in_scope,
                        out_of_scope=out_of_scope,
                    ),
                )
                page = context.new_page()
                page.expose_function(
                    EXEC_BINDING,
                    lambda *args: executed.append(str(args[0]) if args else ""),
                )
                page.on("dialog", lambda dialog: _handle_dialog(dialog, dialogs))
                page.on("console", lambda message: console.append(_console_text(message)))
                page.on("pageerror", lambda error: page_errors.append(_clip(str(error))))
                page.goto(start_url, wait_until="load", timeout=nav_timeout_ms)
                page.set_content(_auto_submit_form_html(url, upper_method, fields or {}), wait_until="domcontentloaded")
                page.evaluate("document.forms[0].submit()")
                page.wait_for_load_state("load", timeout=nav_timeout_ms)
                page.wait_for_timeout(settle_ms)
                final_url = page.url
                final_scope_error = _scope_error(
                    origin=origin,
                    url=final_url,
                    allow_remote_target=allow_remote_target,
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                )
                if final_scope_error:
                    return BrowserObservation(
                        available=True,
                        url=url,
                        token_executed=_token_executed(token, executed, dialogs),
                        final_url=final_url,
                        executed_values=executed[:10],
                        dialogs=dialogs[:10],
                        console=console[:20],
                        page_errors=page_errors[:10],
                        error=f"final browser URL outside scope: {final_scope_error}",
                    )
                title = _clip(page.title())
                body = page.content()
            finally:
                browser.close()
    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        error = _classify_launch_error(str(exc))
        backend_unavailable = _is_backend_unavailable_error(str(exc))
        return BrowserObservation(
            available=not backend_unavailable,
            url=url,
            token_executed=_token_executed(token, executed, dialogs),
            executed_values=executed,
            dialogs=dialogs,
            console=console[:20],
            page_errors=page_errors[:10],
            error=error,
            reason=error if backend_unavailable else "",
        )
    except Exception as exc:  # noqa: BLE001 - the browser must never crash the loop.
        return BrowserObservation(available=True, url=url, error=str(exc)[:300])

    return BrowserObservation(
        available=True,
        url=url,
        token_executed=_token_executed(token, executed, dialogs),
        final_url=final_url,
        title=title,
        executed_values=executed[:10],
        dialogs=dialogs[:10],
        console=console[:20],
        page_errors=page_errors[:10],
        body_snippet=_clip(body, _SNIPPET_CHARS),
    )


def _render_url_with_chrome_devtools(
    url: str,
    *,
    token: str,
    origin: str,
    timeout_seconds: int,
    settle_ms: int,
    unavailable_reason: str,
    allow_remote_target: bool,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> BrowserObservation:
    chrome_path = _chrome_executable()
    if not chrome_path:
        return BrowserObservation(available=False, url=url, reason=unavailable_reason)
    scope_error = _scope_error(
        origin=origin,
        url=url,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    if scope_error:
        return BrowserObservation(available=True, url=url, error=scope_error)
    if allow_remote_target and not is_local_url(origin):
        reason = (
            "remote browser execution requires Playwright so every navigation and "
            "subresource request can be scope-intercepted"
        )
        return BrowserObservation(available=False, url=url, reason=reason)
    resolved_url, redirect_error = _resolve_scoped_redirects(
        url,
        origin=origin,
        timeout_seconds=timeout_seconds,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    if redirect_error:
        return BrowserObservation(available=True, url=url, error=redirect_error)
    try:
        with _ChromeDevToolsPage(chrome_path, timeout_seconds=timeout_seconds) as page:
            page.prepare()
            page.navigate(resolved_url)
            page.wait_for_settle(settle_ms)
            return page.observation(
                url=url,
                token=token,
                origin=origin,
                allow_remote_target=allow_remote_target,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
            )
    except Exception as exc:  # noqa: BLE001 - browser fallback must not crash the probe.
        return BrowserObservation(available=True, url=url, error=f"chrome devtools fallback failed: {exc!s}"[:300])


def _render_request_with_chrome_devtools(
    url: str,
    *,
    method: str,
    fields: dict[str, str],
    token: str,
    origin: str,
    page_url: str,
    timeout_seconds: int,
    settle_ms: int,
    unavailable_reason: str,
    allow_remote_target: bool,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> BrowserObservation:
    chrome_path = _chrome_executable()
    if not chrome_path:
        return BrowserObservation(available=False, url=url, reason=unavailable_reason)
    if method != "POST":
        return BrowserObservation(available=True, url=url, error=f"unsupported browser request method: {method}")
    scope_error = _scope_error(
        origin=origin,
        url=url,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    if scope_error:
        return BrowserObservation(available=True, url=url, error=scope_error)
    if allow_remote_target and not is_local_url(origin):
        reason = (
            "remote browser execution requires Playwright so every navigation and "
            "subresource request can be scope-intercepted"
        )
        return BrowserObservation(available=False, url=url, reason=reason)
    start_url = _scoped_start_url(
        origin=origin,
        page_url=page_url,
        request_url=url,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )
    try:
        with _ChromeDevToolsPage(chrome_path, timeout_seconds=timeout_seconds) as page:
            page.prepare()
            page.navigate(start_url)
            page.submit_form(url, method, fields)
            page.wait_for_settle(settle_ms)
            return page.observation(
                url=url,
                token=token,
                origin=origin,
                allow_remote_target=allow_remote_target,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
            )
    except Exception as exc:  # noqa: BLE001 - browser fallback must not crash the probe.
        return BrowserObservation(available=True, url=url, error=f"chrome devtools fallback failed: {exc!s}"[:300])


class _ChromeDevToolsPage:
    def __init__(self, chrome_path: str, *, timeout_seconds: int) -> None:
        self.chrome_path = chrome_path
        self.timeout_seconds = max(1, timeout_seconds)
        self.port = _free_tcp_port()
        self.tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.ws: _CdpWebSocket | None = None
        self._next_id = 1
        self._last_load = 0.0
        self.executed: list[str] = []
        self.dialogs: list[str] = []
        self.console: list[str] = []
        self.page_errors: list[str] = []

    def __enter__(self) -> "_ChromeDevToolsPage":
        self.tmpdir = tempfile.TemporaryDirectory(prefix="ravage-chrome-")
        cmd = [
            self.chrome_path,
            "--headless=new",
            "--disable-gpu",
            "--disable-background-networking",
            "--no-first-run",
            "--no-default-browser-check",
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.tmpdir.name}",
            "about:blank",
        ]
        self.process = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ws_url = self._open_page_websocket_url()
        self.ws = _CdpWebSocket.connect(ws_url, timeout_seconds=self.timeout_seconds)
        return self

    def __exit__(self, *_exc: object) -> None:
        with contextlib.suppress(Exception):
            if self.ws is not None:
                self.ws.close()
        if self.process is not None:
            self.process.terminate()
            with contextlib.suppress(Exception):
                self.process.wait(timeout=2)
            if self.process.poll() is None:
                with contextlib.suppress(Exception):
                    self.process.kill()
        if self.tmpdir is not None:
            self.tmpdir.cleanup()

    def prepare(self) -> None:
        self.command("Runtime.enable")
        self.command("Page.enable")
        self.command("Runtime.addBinding", {"name": EXEC_BINDING})
        self.command(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": _devtools_bootstrap_source()},
        )

    def navigate(self, url: str) -> None:
        self.command("Page.navigate", {"url": url})
        self.wait_for_load()

    def submit_form(self, url: str, method: str, fields: dict[str, str]) -> None:
        form_html = _auto_submit_form_html(url, method, fields)
        expression = (
            "document.open();"
            f"document.write({json.dumps(form_html)});"
            "document.close();"
            "document.forms[0].submit();"
        )
        self.command("Runtime.evaluate", {"expression": expression, "awaitPromise": False})
        self.wait_for_load()

    def wait_for_load(self) -> None:
        deadline = time.monotonic() + self.timeout_seconds + (_NAV_TIMEOUT_PADDING_MS / 1000)
        while time.monotonic() < deadline:
            event = self.recv(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            if event is None:
                continue
            self.process_message(event)
            if event.get("method") == "Page.loadEventFired":
                self._last_load = time.monotonic()
                return

    def wait_for_settle(self, settle_ms: int) -> None:
        deadline = time.monotonic() + max(0, settle_ms) / 1000
        while time.monotonic() < deadline:
            event = self.recv(timeout=min(0.2, max(0.01, deadline - time.monotonic())))
            if event is not None:
                self.process_message(event)

    def observation(
        self,
        *,
        url: str,
        token: str,
        origin: str,
        allow_remote_target: bool = False,
        in_scope: Sequence[str] = (),
        out_of_scope: Sequence[str] = (),
    ) -> BrowserObservation:
        final_url = self.evaluate_string("location.href")
        final_scope_error = (
            _scope_error(
                origin=origin,
                url=final_url,
                allow_remote_target=allow_remote_target,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
            )
            if final_url
            else ""
        )
        title = self.evaluate_string("document.title")
        body = self.evaluate_string("document.documentElement ? document.documentElement.outerHTML : ''")
        return BrowserObservation(
            available=True,
            url=url,
            token_executed=_token_executed(token, self.executed, self.dialogs),
            final_url=final_url,
            title=_clip(title),
            executed_values=self.executed[:10],
            dialogs=self.dialogs[:10],
            console=self.console[:20],
            page_errors=self.page_errors[:10],
            body_snippet=_clip(body, _SNIPPET_CHARS),
            error=f"final browser URL outside scope: {final_scope_error}" if final_scope_error else "",
        )

    def evaluate_string(self, expression: str) -> str:
        response = self.command(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True},
        )
        result = response.get("result")
        if not isinstance(result, dict):
            return ""
        value = result.get("result")
        if not isinstance(value, dict):
            return ""
        return str(value.get("value") or "")

    def command(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if self.ws is None:
            raise RuntimeError("devtools websocket is not connected")
        command_id = self._next_id
        self._next_id += 1
        self.ws.send_json({"id": command_id, "method": method, "params": params or {}})
        deadline = time.monotonic() + self.timeout_seconds + (_NAV_TIMEOUT_PADDING_MS / 1000)
        while time.monotonic() < deadline:
            message = self.recv(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            if message is None:
                continue
            if message.get("id") == command_id:
                error = message.get("error")
                if error:
                    raise RuntimeError(str(error)[:300])
                return message
            self.process_message(message)
        raise TimeoutError(f"timed out waiting for {method}")

    def recv(self, *, timeout: float) -> dict[str, object] | None:
        if self.ws is None:
            return None
        return self.ws.recv_json(timeout=timeout)

    def process_message(self, message: dict[str, object]) -> None:
        method = str(message.get("method") or "")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if method == "Runtime.bindingCalled":
            if params.get("name") == EXEC_BINDING:
                self.executed.append(_clip(str(params.get("payload") or "")))
        elif method == "Page.javascriptDialogOpening":
            self.dialogs.append(_clip(str(params.get("message") or "")))
            self._send_no_wait("Page.handleJavaScriptDialog", {"accept": False})
        elif method == "Runtime.consoleAPICalled":
            args = params.get("args") if isinstance(params.get("args"), list) else []
            text = " ".join(_cdp_arg_text(arg) for arg in args if isinstance(arg, dict)).strip()
            if text:
                self.console.append(_clip(text, _CONSOLE_CHARS))
        elif method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails")
            self.page_errors.append(_clip(json.dumps(details, sort_keys=True) if details else "runtime exception"))

    def _send_no_wait(self, method: str, params: dict[str, object]) -> None:
        if self.ws is None:
            return
        command_id = self._next_id
        self._next_id += 1
        self.ws.send_json({"id": command_id, "method": method, "params": params})

    def _open_page_websocket_url(self) -> str:
        deadline = time.monotonic() + self.timeout_seconds + 3
        last_error = ""
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError("chrome exited before DevTools became ready")
            try:
                request = Request(
                    f"http://127.0.0.1:{self.port}/json/new?{quote('about:blank', safe='')}",
                    method="PUT",
                )
                with urlopen(request, timeout=1) as response:  # noqa: S310 - localhost CDP only.
                    payload = json.loads(response.read().decode("utf-8", errors="replace"))
                ws_url = str(payload.get("webSocketDebuggerUrl") or "")
                if ws_url:
                    return ws_url
            except Exception as exc:  # noqa: BLE001 - retry until Chrome exposes CDP.
                last_error = str(exc)
                time.sleep(0.1)
        raise TimeoutError(f"chrome devtools endpoint did not become ready: {last_error}")


class _CdpWebSocket:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    @classmethod
    def connect(cls, ws_url: str, *, timeout_seconds: int) -> "_CdpWebSocket":
        parsed = urlsplit(ws_url)
        if parsed.scheme != "ws":
            raise ValueError("unsupported DevTools websocket URL")
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        sock = socket.create_connection((host, port), timeout=max(1, timeout_seconds))
        sock.settimeout(max(1, timeout_seconds))
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("ascii"))
        response = _read_http_headers(sock)
        if b" 101 " not in response.split(b"\r\n", 1)[0]:
            raise RuntimeError("DevTools websocket handshake failed")
        return cls(sock)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._send_frame(b"", opcode=0x8)
        with contextlib.suppress(Exception):
            self.sock.close()

    def send_json(self, payload: dict[str, object]) -> None:
        self._send_frame(json.dumps(payload, separators=(",", ":")).encode("utf-8"), opcode=0x1)

    def recv_json(self, *, timeout: float) -> dict[str, object] | None:
        self.sock.settimeout(timeout)
        try:
            while True:
                opcode, payload = self._recv_frame()
                if opcode == 0x1:
                    return json.loads(payload.decode("utf-8", errors="replace"))
                if opcode == 0x8:
                    return None
                if opcode == 0x9:
                    self._send_frame(payload, opcode=0xA)
        except socket.timeout:
            return None

    def _send_frame(self, payload: bytes, *, opcode: int) -> None:
        first = 0x80 | opcode
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", first, 0x80 | length)
        elif length <= 0xFFFF:
            header = struct.pack("!BBH", first, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", first, 0x80 | 127, length)
        mask = secrets.token_bytes(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def _recv_frame(self) -> tuple[int, bytes]:
        header = _read_exact(self.sock, 2)
        first, second = header[0], header[1]
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", _read_exact(self.sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _read_exact(self.sock, 8))[0]
        masked = bool(second & 0x80)
        mask = _read_exact(self.sock, 4) if masked else b""
        payload = _read_exact(self.sock, length) if length else b""
        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return opcode, payload


def _auto_submit_form_html(url: str, method: str, fields: dict[str, str]) -> str:
    controls = "\n".join(
        (
            '<input type="hidden" '
            f'name="{html.escape(str(name), quote=True)}" '
            f'value="{html.escape(str(value), quote=True)}">'
        )
        for name, value in fields.items()
    )
    return (
        "<!doctype html><html><body>"
        f'<form method="{html.escape(method, quote=True)}" action="{html.escape(url, quote=True)}">'
        f"{controls}</form></body></html>"
    )


def _devtools_bootstrap_source() -> str:
    return (
        "try {"
        "window.addEventListener('error', function(e) {"
        "  try { console.log('RAVAGE_PAGE_ERROR ' + (e.message || 'error')); } catch (_) {}"
        "});"
        "} catch (_) {}"
    )


def _cdp_arg_text(arg: dict[str, object]) -> str:
    if "value" in arg:
        return str(arg.get("value") or "")
    if "description" in arg:
        return str(arg.get("description") or "")
    return ""


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _read_http_headers(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        chunks.append(chunk)
        if b"".join(chunks).endswith(b"\r\n\r\n"):
            break
        if len(chunks) > 16384:
            raise RuntimeError("websocket handshake headers too large")
    return b"".join(chunks)


def _read_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("websocket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _scope_error(
    *,
    origin: str,
    url: str,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> str:
    try:
        assert_tool_target_url(
            url,
            allow_remote_target=allow_remote_target,
        )
    except ValueError as exc:
        return str(exc)
    try:
        if not same_origin(origin, url):
            return "url is outside target origin"
    except ValueError as exc:
        return str(exc)
    if in_scope and not url_in_scope_entries(
        url,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    ):
        return "url is outside engagement scope"
    return ""


def _scoped_start_url(
    *,
    origin: str,
    page_url: str,
    request_url: str,
    allow_remote_target: bool,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str],
) -> str:
    for candidate in (origin, page_url, request_url):
        if candidate and not _scope_error(
            origin=origin,
            url=candidate,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        ):
            return candidate
    return request_url


def _resolve_scoped_redirects(
    url: str,
    *,
    origin: str,
    timeout_seconds: int,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> tuple[str, str]:
    opener = build_opener(_NoRedirectHandler)
    current = url
    for _ in range(_MAX_REDIRECTS):
        scope_error = _scope_error(
            origin=origin,
            url=current,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )
        if scope_error:
            return "", scope_error
        request = Request(
            current,
            method="GET",
            headers={"User-Agent": "ravage-browser-probe/1.0", "Accept-Encoding": "identity"},
        )
        try:
            with opener.open(request, timeout=max(1, min(timeout_seconds, 10))) as response:
                status = int(getattr(response, "status", response.getcode()))
                location = response.headers.get("Location")
        except HTTPError as exc:
            status = exc.code
            location = exc.headers.get("Location")
            with contextlib.suppress(Exception):
                exc.close()
        except (OSError, URLError):
            return current, ""
        if status not in _REDIRECT_STATUSES or not location:
            return current, ""
        next_url = urljoin(current, location)
        scope_error = _scope_error(
            origin=origin,
            url=next_url,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )
        if scope_error:
            return "", f"redirect target outside scope: {scope_error}"
        current = next_url
    return "", "redirect chain exceeded browser probe limit"


def _token_executed(token: str, executed: list[str], dialogs: list[str]) -> bool:
    return any(token in value for value in executed) or any(token in message for message in dialogs)


def _request_in_scope(
    origin: str,
    url: str,
    *,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> bool:
    return (
        _scope_error(
            origin=origin,
            url=url,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )
        == ""
    )


def _guard_route(
    route: _BrowserRoute,
    origin: str,
    *,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] = (),
    out_of_scope: Sequence[str] = (),
) -> None:
    request = getattr(route, "request", None)
    request_url = str(getattr(request, "url", ""))
    if _request_in_scope(
        origin,
        request_url,
        allow_remote_target=allow_remote_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    ):
        route.continue_()
        return
    with contextlib.suppress(Exception):
        route.abort()


def _handle_dialog(dialog: object, sink: list[str]) -> None:
    message = getattr(dialog, "message", "")
    sink.append(_clip(str(message)))
    dismiss = getattr(dialog, "dismiss", None)
    if callable(dismiss):
        # Dialog may already be handled or the page gone; dismissal is best-effort.
        with contextlib.suppress(Exception):
            dismiss()


def _console_text(message: object) -> str:
    text = str(getattr(message, "text", ""))
    return _clip(text, _CONSOLE_CHARS)


def _classify_launch_error(message: str) -> str:
    lowered = message.lower()
    if _is_backend_unavailable_error(lowered):
        return (
            "chromium not installed for playwright; run `playwright install chromium`. "
            f"detail: {message[:200]}"
        )
    return message[:300]


def _is_backend_unavailable_error(message: str) -> bool:
    lowered = message.lower()
    return "executable doesn't exist" in lowered or "playwright install" in lowered


def _clip(text: str, limit: int = 240) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[+{len(text) - limit}]"
