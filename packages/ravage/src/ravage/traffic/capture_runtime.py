"""Operator-driven Playwright traffic capture runtime."""

from __future__ import annotations

import math
import sys
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast
from urllib.parse import urlsplit

from ravage.run_data.run_manifest import (
    STATUS_AGENT_RUNNING,
    STATUS_FINISHED,
    RunManifest,
    write_manifest,
)
from ravage.traffic.browser_capture import (
    DEFAULT_MAX_CAPTURE_REQUESTS,
    BrowserContextLike,
    BrowserTrafficCapture,
    ScopePredicate,
    playwright_context_options,
)
from ravage.traffic.loopback_socks import PinnedSocksProxy
from ravage.traffic.manifest import (
    TrafficRunManifest,
    write_traffic_manifest,
)
from ravage.traffic.recorders import BrowserExchangeRecorder
from ravage.traffic.redaction import redact_text, sanitize_url
from ravage.traffic.scope import TrafficScope
from ravage.traffic.store import TrafficStore

if TYPE_CHECKING:
    from ravage.traffic.contracts import CapturedHttpExchange

_WAIT_SLICE_MS = 250
_MISSING_BROWSER_MARKERS = (
    "executable doesn't exist",
    "executable does not exist",
    "playwright install",
    "browser was not found",
)
_REMOTE_BROWSER_PROXY_ARGS = (
    "--disable-quic",
    "--proxy-bypass-list=<-loopback>",
)


class BrowserCaptureError(RuntimeError):
    """Raised when operator browser capture cannot start or continue."""


# Kept as a compatibility name for callers/tests written while the feature was
# under development. The public CLI uses the shorter BrowserCaptureError.
TrafficCaptureRuntimeError = BrowserCaptureError


@dataclass(frozen=True, slots=True)
class CaptureSummary:
    run_dir: Path
    workspace_dir: Path
    captured: int
    blocked: int
    contracts: int
    interrupted: bool
    recorder_errors: tuple[str, ...]
    request_limit: int = DEFAULT_MAX_CAPTURE_REQUESTS

    def to_json(self) -> dict[str, object]:
        return {
            "run_dir": str(self.run_dir),
            "workspace_dir": str(self.workspace_dir),
            "captured": self.captured,
            "blocked": self.blocked,
            "contracts": self.contracts,
            "interrupted": self.interrupted,
            "recorder_errors": list(self.recorder_errors),
            "request_limit": self.request_limit,
        }


class _PageLike(Protocol):
    def on(self, event: str, handler: Callable[..., object]) -> None: ...

    def goto(
        self,
        url: str,
        *,
        wait_until: str,
        timeout: float,
    ) -> object: ...

    def wait_for_timeout(self, timeout: float) -> None: ...


class _BrowserContextLike(BrowserContextLike, Protocol):
    def new_page(self) -> _PageLike: ...

    def close(self) -> None: ...


class _BrowserLike(Protocol):
    def on(self, event: str, handler: Callable[..., object]) -> None: ...

    def new_context(self, **options: object) -> _BrowserContextLike: ...

    def close(self) -> None: ...


class _BrowserTypeLike(Protocol):
    def launch(
        self,
        *,
        headless: bool,
        args: Sequence[str],
    ) -> _BrowserLike: ...


class _PlaywrightLike(Protocol):
    chromium: _BrowserTypeLike


class _PlaywrightManagerLike(Protocol):
    def __enter__(self) -> _PlaywrightLike: ...

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> object: ...


PlaywrightFactory = Callable[[], _PlaywrightManagerLike]


def capture_browser_traffic(  # noqa: C901, PLR0912, PLR0913, PLR0915 - explicit boundary.
    *,
    target_url: str,
    run_dir: Path,
    allow_remote_target: bool,
    headless: bool = False,
    duration_seconds: float | None = None,
    timeout_seconds: int = 30,
    max_requests: int = DEFAULT_MAX_CAPTURE_REQUESTS,
    on_exchange: Callable[[CapturedHttpExchange], None] | None = None,
) -> CaptureSummary:
    """Open an authorized target and capture operator-driven browser traffic."""
    _validate_runtime_options(
        duration_seconds=duration_seconds,
        timeout_seconds=timeout_seconds,
        max_requests=max_requests,
    )
    try:
        scope = TrafficScope(
            target_url=target_url,
            allow_remote_target=allow_remote_target,
        )
    except ValueError as exc:
        raise TrafficCaptureRuntimeError(str(exc)) from None

    resolved_run_dir = Path(run_dir)
    _validate_capture_run_dir(resolved_run_dir)
    initial_scope_decision = scope.decide(target_url)
    if not initial_scope_decision.allowed:
        reason = initial_scope_decision.reason or "target is outside authorized scope"
        message = f"Browser traffic capture is blocked: {reason}"
        raise TrafficCaptureRuntimeError(message)
    pinned_addresses = scope.pinned_addresses(target_url)
    browser_proxy = _remote_browser_proxy(
        target_url=target_url,
        pinned_addresses=pinned_addresses,
    )
    workspace_dir = resolved_run_dir / "workspace"
    # Keep the explicitly non-secret correlation label below the shared
    # redactor's high-entropy-token threshold.
    capture_session_id = f"capture-{uuid.uuid4().hex[:12]}"
    traffic_manifest = TrafficRunManifest.create(
        target_url=target_url,
        capture_session_id=capture_session_id,
        in_scope=scope.in_scope,
        out_of_scope=scope.out_of_scope,
    )
    ordinary_manifest = RunManifest(
        run_id=resolved_run_dir.name or "traffic-capture",
        status=STATUS_AGENT_RUNNING,
        phase="traffic_capture",
        target_url=traffic_manifest.target_url,
        workspace_dir=str(workspace_dir),
    )

    run_manifest_written = False
    traffic_manifest_written = False
    interrupted = False
    failed = False
    primary_error: BaseException | None = None
    runtime_recorder_errors: list[str] = []
    store: TrafficStore | None = None
    recorder: BrowserExchangeRecorder | None = None
    capture: BrowserTrafficCapture | None = None
    try:
        write_manifest(resolved_run_dir, ordinary_manifest)
        run_manifest_written = True
        store = TrafficStore.create(workspace_dir, require_empty=True)
        write_traffic_manifest(workspace_dir, traffic_manifest)
        traffic_manifest_written = True
        recorder = BrowserExchangeRecorder(
            store,
            on_exchange=on_exchange,
        )
        capture = BrowserTrafficCapture(
            recorder=recorder,
            scope_predicate=cast("ScopePredicate", scope.decide_using_pins),
            capture_all_resources=True,
            capture_session_id=capture_session_id,
            max_requests=max_requests,
        )
        _run_scoped_playwright_capture(
            target_url=target_url,
            capture=capture,
            headless=headless,
            duration_seconds=duration_seconds,
            timeout_seconds=timeout_seconds,
            browser_proxy=browser_proxy,
        )
    except KeyboardInterrupt:
        interrupted = True
    except TrafficCaptureRuntimeError as exc:
        failed = True
        primary_error = exc
        raise
    except Exception as exc:
        failed = True
        message = _capture_failure_message(exc, target_url=target_url)
        primary_error = TrafficCaptureRuntimeError(message)
        raise primary_error from exc
    except BaseException as exc:
        failed = True
        primary_error = exc
        raise
    finally:
        if recorder is not None:
            try:
                recorder.finalize_pending()
            except Exception as exc:  # noqa: BLE001 - finalize run metadata regardless.
                runtime_recorder_errors.append(_finalization_warning("recorder", exc))

        if traffic_manifest_written:
            try:
                write_traffic_manifest(workspace_dir, traffic_manifest.complete())
            except Exception as exc:  # noqa: BLE001 - preserve the capture result.
                runtime_recorder_errors.append(_finalization_warning("traffic manifest", exc))

        capture_recorder_errors = capture.recorder_errors if capture is not None else ()
        result_label = _result_label(
            interrupted=interrupted,
            failed=failed,
            recorder_errors=(*capture_recorder_errors, *runtime_recorder_errors),
        )
        if run_manifest_written:
            ordinary_manifest.status = STATUS_FINISHED
            ordinary_manifest.result_label = result_label
            ordinary_manifest.finished_at = datetime.now(UTC).isoformat()
            try:
                write_manifest(resolved_run_dir, ordinary_manifest)
            except Exception as exc:  # noqa: BLE001 - preserve the capture result.
                runtime_recorder_errors.append(_finalization_warning("run manifest", exc))

        if primary_error is not None:
            for warning in (*capture_recorder_errors, *runtime_recorder_errors):
                primary_error.add_note(f"Capture warning: {warning}")

    exchanges = store.exchanges() if store is not None else ()
    capture_recorder_errors = capture.recorder_errors if capture is not None else ()
    return CaptureSummary(
        run_dir=resolved_run_dir,
        workspace_dir=workspace_dir,
        captured=sum(exchange.scope_decision == "allowed" for exchange in exchanges),
        blocked=sum(exchange.scope_decision == "blocked" for exchange in exchanges),
        contracts=len(store.contracts()) if store is not None else 0,
        interrupted=interrupted,
        recorder_errors=(*capture_recorder_errors, *runtime_recorder_errors),
        request_limit=max_requests,
    )


def _run_playwright_capture(  # noqa: PLR0913 - explicit browser boundary.
    *,
    target_url: str,
    capture: BrowserTrafficCapture,
    headless: bool,
    duration_seconds: float | None,
    timeout_seconds: int,
    proxy_url: str | None = None,
) -> None:
    factory = _load_sync_playwright()
    with factory() as playwright:
        browser = _launch_browser(
            playwright,
            headless=headless,
            proxy_url=proxy_url,
        )
        context: _BrowserContextLike | None = None
        stop = threading.Event()
        try:
            browser.on("disconnected", lambda *_args: stop.set())
            context = browser.new_context(**playwright_context_options())
            # Routing must exist before page creation so the first document
            # navigation cannot escape observation or scope enforcement.
            capture.attach(context)
            page = context.new_page()
            page.on("close", lambda *_args: stop.set())
            try:
                page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1_000,
                )
                _start_enter_listener(stop, enabled=duration_seconds is None)
                _wait_for_operator(
                    page,
                    stop=stop,
                    duration_seconds=duration_seconds,
                )
            except Exception as exc:
                if not stop.is_set() and not _is_browser_closed_error(exc):
                    raise
        finally:
            if context is not None:
                with suppress(Exception):
                    context.close()
            with suppress(Exception):
                browser.close()


def _start_enter_listener(stop: threading.Event, *, enabled: bool) -> None:
    """Let a terminal operator finish capture without blocking Playwright events."""
    if not enabled or not sys.stdin.isatty():
        return

    def wait_for_enter() -> None:
        try:
            sys.stdin.readline()
        except (OSError, ValueError):
            return
        stop.set()

    threading.Thread(
        target=wait_for_enter,
        name="ravage-traffic-enter",
        daemon=True,
    ).start()


def _wait_for_operator(
    page: _PageLike,
    *,
    stop: threading.Event,
    duration_seconds: float | None,
) -> None:
    deadline = None if duration_seconds is None else time.monotonic() + duration_seconds
    while not stop.is_set():
        if deadline is None:
            wait_ms = _WAIT_SLICE_MS
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            wait_ms = min(_WAIT_SLICE_MS, max(1, math.ceil(remaining * 1_000)))
        try:
            page.wait_for_timeout(wait_ms)
        except Exception as exc:
            if stop.is_set() or _is_browser_closed_error(exc):
                return
            raise


def _run_scoped_playwright_capture(  # noqa: PLR0913 - explicit browser boundary.
    *,
    target_url: str,
    capture: BrowserTrafficCapture,
    headless: bool,
    duration_seconds: float | None,
    timeout_seconds: int,
    browser_proxy: PinnedSocksProxy | None,
) -> None:
    if browser_proxy is None:
        _run_playwright_capture(
            target_url=target_url,
            capture=capture,
            headless=headless,
            duration_seconds=duration_seconds,
            timeout_seconds=timeout_seconds,
        )
        return
    with browser_proxy:
        _run_playwright_capture(
            target_url=target_url,
            capture=capture,
            headless=headless,
            duration_seconds=duration_seconds,
            timeout_seconds=timeout_seconds,
            proxy_url=browser_proxy.url,
        )


def _remote_browser_proxy(
    *,
    target_url: str,
    pinned_addresses: Sequence[str],
) -> PinnedSocksProxy | None:
    if not pinned_addresses:
        return None
    parsed = urlsplit(target_url)
    host = parsed.hostname
    if not host:
        message = "remote browser target has no host"
        raise TrafficCaptureRuntimeError(message)
    port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    return PinnedSocksProxy(host, port, pinned_addresses)


def _launch_browser(
    playwright: _PlaywrightLike,
    *,
    headless: bool,
    proxy_url: str | None,
) -> _BrowserLike:
    browser_args = (*_REMOTE_BROWSER_PROXY_ARGS, f"--proxy-server={proxy_url}") if proxy_url else ()
    try:
        return playwright.chromium.launch(headless=headless, args=browser_args)
    except Exception as exc:
        detail = redact_text(exc, max_chars=500)
        if any(marker in detail.casefold() for marker in _MISSING_BROWSER_MARKERS):
            message = (
                "Playwright Chromium is not installed. Run "
                "`python -m playwright install chromium`, then retry the capture."
            )
        else:
            message = f"Could not launch Playwright Chromium: {detail}"
        raise TrafficCaptureRuntimeError(message) from exc


def _load_sync_playwright() -> PlaywrightFactory:
    try:
        return _import_sync_playwright()
    except (ImportError, ModuleNotFoundError) as exc:
        message = (
            "Browser capture requires Playwright. Run "
            "`python -m pip install playwright`, then "
            "`python -m playwright install chromium`."
        )
        raise TrafficCaptureRuntimeError(message) from exc


def _import_sync_playwright() -> PlaywrightFactory:
    from playwright.sync_api import (  # type: ignore[import-not-found] # noqa: PLC0415
        sync_playwright,
    )

    return cast("PlaywrightFactory", sync_playwright)


def _validate_runtime_options(
    *,
    duration_seconds: float | None,
    timeout_seconds: int,
    max_requests: int,
) -> None:
    if timeout_seconds <= 0:
        message = "timeout_seconds must be greater than zero"
        raise ValueError(message)
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or max_requests <= 0:
        message = "max_requests must be a positive integer"
        raise ValueError(message)
    if duration_seconds is not None and (
        duration_seconds < 0 or not math.isfinite(duration_seconds)
    ):
        message = "duration_seconds must be a finite non-negative number"
        raise ValueError(message)


def _validate_capture_run_dir(run_dir: Path) -> None:
    """Reject unsafe or occupied capture destinations before writing artifacts."""
    if run_dir.is_symlink():
        message = f"capture run path cannot be a symlink: {run_dir}; choose a new --run-dir"
        raise BrowserCaptureError(message)
    if not run_dir.exists():
        return
    if not run_dir.is_dir():
        message = f"capture run path is not a directory: {run_dir}; choose a new --run-dir"
        raise BrowserCaptureError(message)
    try:
        has_prior_state = any(run_dir.iterdir())
    except OSError as exc:
        detail = redact_text(exc, max_chars=300)
        message = f"could not inspect capture run directory {run_dir}: {detail}"
        raise BrowserCaptureError(message) from exc
    if has_prior_state:
        message = f"capture run directory is not empty: {run_dir}; choose a new --run-dir"
        raise BrowserCaptureError(message)


def _is_browser_closed_error(exc: Exception) -> bool:
    detail = str(exc).casefold()
    return any(
        marker in detail
        for marker in (
            "browser has been closed",
            "browser has been disconnected",
            "context or browser has been closed",
            "page has been closed",
            "target page, context or browser has been closed",
        )
    )


def _capture_failure_message(exc: Exception, *, target_url: str) -> str:
    detail = redact_text(exc, max_chars=500)
    safe_target = sanitize_url(target_url)
    if "timeout" in detail.casefold():
        return (
            f"Timed out opening {safe_target}. Verify the target is running or increase "
            "the capture timeout."
        )
    return f"Browser traffic capture failed for {safe_target}: {detail}"


def _finalization_warning(stage: str, exc: Exception) -> str:
    detail = redact_text(exc, max_chars=300)
    return f"{stage} finalization failed: {detail}"


def _result_label(
    *,
    interrupted: bool,
    failed: bool,
    recorder_errors: tuple[str, ...],
) -> str:
    if failed:
        return "failed"
    if interrupted:
        return "interrupted"
    if recorder_errors:
        return "completed_with_errors"
    return "completed"


__all__ = [
    "BrowserCaptureError",
    "CaptureSummary",
    "TrafficCaptureRuntimeError",
    "capture_browser_traffic",
]
