from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from ravage.__main__ import main
from ravage.run_data.run_manifest import STATUS_FINISHED, read_manifest
from ravage.traffic import capture_runtime
from ravage.traffic.capture_runtime import (
    TrafficCaptureRuntimeError,
    capture_browser_traffic,
)
from ravage.traffic.manifest import TrafficRunManifest, read_traffic_manifest
from ravage.traffic.store import TrafficStore

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping
    from pathlib import Path

    from ravage.traffic.contracts import CapturedHttpExchange


TARGET_URL = "http://127.0.0.1:8765/"
REMOTE_TARGET_URL = "https://capture.example.test:8443/app"
DEFAULT_TIMEOUT_MS = 30_000
CLI_USAGE_ERROR = 2


@dataclass
class _RequestPlan:
    url: str
    resource_type: str = "document"
    method: str = "GET"
    status: int = 200
    terminal: str = "requestfinished"
    headers: Mapping[str, str] = field(default_factory=dict)
    post_data: str | None = None


@dataclass
class _Scenario:
    plans: list[_RequestPlan] = field(default_factory=list)
    wait_action: str = "close_page"
    launch_error: Exception | None = None
    log: list[str] = field(default_factory=list)
    routes: list[_Route] = field(default_factory=list)
    launch_headless: bool | None = None
    launch_args: tuple[str, ...] = ()
    context_options: dict[str, object] = field(default_factory=dict)
    goto_timeout: float = 0


class _Request:
    def __init__(self, plan: _RequestPlan) -> None:
        self.url = plan.url
        self.resource_type = plan.resource_type
        self.method = plan.method
        self.headers = dict(plan.headers)
        self.post_data = plan.post_data
        self.redirected_from = None
        self.failure = "net::ERR_FAILED" if plan.terminal == "requestfailed" else None

    @property
    def frame(self) -> object:
        message = "capture runtime must not access request.frame"
        raise AssertionError(message)

    def is_navigation_request(self) -> bool:
        return self.resource_type == "document"

    def all_headers(self) -> Mapping[str, str]:
        return self.headers


class _Response:
    def __init__(self, request: _Request, status: int) -> None:
        self.request = request
        self.url = request.url
        self.status = status
        self.status_text = "OK"
        self.headers = {"Content-Type": "text/html"}
        self.from_service_worker = False

    def all_headers(self) -> Mapping[str, str]:
        return self.headers


class _Route:
    def __init__(self, request: _Request) -> None:
        self.request = request
        self.continued = False
        self.aborted = False

    def continue_(self) -> None:
        self.continued = True

    def abort(self) -> None:
        self.aborted = True


class _Page:
    def __init__(self, scenario: _Scenario, context: _Context, browser: _Browser) -> None:
        self._scenario = scenario
        self._context = context
        self._browser = browser
        self._listeners: dict[str, Callable[..., object]] = {}

    def on(self, event: str, handler: Callable[..., object]) -> None:
        self._listeners[event] = handler
        self._scenario.log.append(f"page.on:{event}")

    def goto(self, url: str, *, wait_until: str, timeout: float) -> None:
        self._scenario.log.append(f"goto:{url}:{wait_until}")
        self._scenario.goto_timeout = timeout
        for plan in self._scenario.plans:
            self._context.emit_plan(plan)

    def wait_for_timeout(self, timeout: float) -> None:
        self._scenario.log.append(f"wait:{timeout}")
        action = self._scenario.wait_action
        self._scenario.wait_action = "none"
        if action == "close_page":
            self._listeners["close"]()
        elif action == "disconnect":
            self._browser.emit("disconnected")
        elif action == "interrupt":
            raise KeyboardInterrupt


class _Context:
    def __init__(self, scenario: _Scenario, browser: _Browser) -> None:
        self._scenario = scenario
        self._browser = browser
        self._route_handler: Callable[[object], None] | None = None
        self._listeners: dict[str, Callable[[object], None]] = {}

    def route(self, pattern: str, handler: Callable[[object], None]) -> None:
        self._scenario.log.append(f"route:{pattern}")
        self._route_handler = handler

    def route_web_socket(self, pattern: str, _handler: Callable[[object], None]) -> None:
        self._scenario.log.append(f"route_web_socket:{pattern}")

    def on(self, event: str, handler: Callable[[object], None]) -> None:
        self._scenario.log.append(f"context.on:{event}")
        self._listeners[event] = handler

    def new_page(self) -> _Page:
        self._scenario.log.append("new_page")
        return _Page(self._scenario, self, self._browser)

    def close(self) -> None:
        self._scenario.log.append("context.close")

    def emit_plan(self, plan: _RequestPlan) -> None:
        request = _Request(plan)
        self._listeners["request"](request)
        assert self._route_handler is not None
        route = _Route(request)
        self._scenario.routes.append(route)
        self._route_handler(route)
        if route.aborted or not plan.terminal:
            return
        self._listeners["response"](_Response(request, plan.status))
        self._listeners[plan.terminal](request)


class _Browser:
    def __init__(self, scenario: _Scenario) -> None:
        self._scenario = scenario
        self._listeners: dict[str, Callable[..., object]] = {}

    def on(self, event: str, handler: Callable[..., object]) -> None:
        self._scenario.log.append(f"browser.on:{event}")
        self._listeners[event] = handler

    def emit(self, event: str) -> None:
        self._listeners[event]()

    def new_context(self, **options: object) -> _Context:
        self._scenario.log.append("new_context")
        self._scenario.context_options = options
        return _Context(self._scenario, self)

    def close(self) -> None:
        self._scenario.log.append("browser.close")


class _BrowserType:
    def __init__(self, scenario: _Scenario) -> None:
        self._scenario = scenario

    def launch(self, *, headless: bool, args: tuple[str, ...]) -> _Browser:
        self._scenario.log.append(f"launch:{headless}")
        self._scenario.launch_headless = headless
        self._scenario.launch_args = tuple(args)
        if self._scenario.launch_error is not None:
            raise self._scenario.launch_error
        return _Browser(self._scenario)


class _Playwright:
    def __init__(self, scenario: _Scenario) -> None:
        self.chromium = _BrowserType(scenario)


class _Manager:
    def __init__(self, scenario: _Scenario) -> None:
        self._scenario = scenario

    def __enter__(self) -> _Playwright:
        self._scenario.log.append("playwright.enter")
        return _Playwright(self._scenario)

    def __exit__(self, *_args: object) -> None:
        self._scenario.log.append("playwright.exit")


def _install_fake(monkeypatch: pytest.MonkeyPatch, scenario: _Scenario) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_load_sync_playwright",
        lambda: lambda: _Manager(scenario),
    )


def test_headed_capture_attaches_before_page_and_finishes_manifests(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(plans=[_RequestPlan(TARGET_URL)])
    _install_fake(monkeypatch, scenario)
    observed: list[CapturedHttpExchange] = []

    summary = capture_browser_traffic(
        target_url=TARGET_URL,
        run_dir=tmp_path / "capture-run",
        allow_remote_target=False,
        on_exchange=observed.append,
    )

    assert scenario.launch_headless is False
    assert scenario.launch_args == ()
    assert scenario.context_options["service_workers"] == "block"
    assert scenario.log.index("route:**/*") < scenario.log.index("new_page")
    assert scenario.log.index("new_page") < scenario.log.index(
        f"goto:{TARGET_URL}:domcontentloaded"
    )
    assert scenario.goto_timeout == DEFAULT_TIMEOUT_MS
    assert summary.captured == 1
    assert summary.blocked == 0
    assert summary.interrupted is False
    assert summary.recorder_errors == ()
    assert len(observed) == 1
    assert observed[0].source_observation_id.startswith("capture-")

    ordinary = read_manifest(summary.run_dir)
    assert ordinary is not None
    assert ordinary.status == STATUS_FINISHED
    assert ordinary.phase == "traffic_capture"
    assert ordinary.result_label == "completed"
    traffic = read_traffic_manifest(summary.workspace_dir)
    assert traffic.completed_at
    assert len(TrafficStore.open(summary.workspace_dir).exchanges()) == 1


def test_headless_duration_and_blocked_subresource(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outside = "http://127.0.0.2:8765/private?token=secret"
    scenario = _Scenario(
        plans=[
            _RequestPlan(TARGET_URL),
            _RequestPlan(outside, resource_type="xhr"),
        ],
        wait_action="none",
    )
    _install_fake(monkeypatch, scenario)

    summary = capture_browser_traffic(
        target_url=TARGET_URL,
        run_dir=tmp_path / "headless-run",
        allow_remote_target=False,
        headless=True,
        duration_seconds=0,
    )

    assert scenario.launch_headless is True
    assert summary.captured == 1
    assert summary.blocked == 1
    assert scenario.routes[0].continued is True
    assert scenario.routes[1].aborted is True
    assert "secret" not in (summary.workspace_dir / "traffic" / "exchanges.jsonl").read_text()


def test_remote_capture_forces_chromium_through_the_pinned_loopback_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(plans=[_RequestPlan(REMOTE_TARGET_URL)])
    _install_fake(monkeypatch, scenario)
    monkeypatch.setattr(
        "ravage.traffic.scope._resolve_addresses",
        lambda _host, _port: ("127.0.0.1",),
    )
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.example.test:8080")

    summary = capture_browser_traffic(
        target_url=REMOTE_TARGET_URL,
        run_dir=tmp_path / "remote-run",
        allow_remote_target=True,
    )

    proxy_argument = next(
        argument
        for argument in scenario.launch_args
        if argument.startswith("--proxy-server=socks5://127.0.0.1:")
    )
    assert proxy_argument.rsplit(":", maxsplit=1)[1].isdigit()
    assert "--proxy-bypass-list=<-loopback>" in scenario.launch_args
    assert "--disable-quic" in scenario.launch_args
    assert "ambient-proxy" not in " ".join(scenario.launch_args)
    assert summary.captured == 1
    assert summary.blocked == 0


def test_remote_capture_freezes_the_preflight_pin_instead_of_reresolving_each_route(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    answers = iter((("127.0.0.1",), ("127.0.0.2",)))
    resolution_count = 0
    scenario = _Scenario(plans=[_RequestPlan(REMOTE_TARGET_URL)])
    _install_fake(monkeypatch, scenario)

    def rotating_dns(_host: str, _port: int) -> tuple[str, ...]:
        nonlocal resolution_count
        resolution_count += 1
        return next(answers)

    monkeypatch.setattr(
        "ravage.traffic.scope._resolve_addresses",
        rotating_dns,
    )

    summary = capture_browser_traffic(
        target_url=REMOTE_TARGET_URL,
        run_dir=tmp_path / "remote-rotating-dns-run",
        allow_remote_target=True,
    )

    assert resolution_count == 1
    assert scenario.routes[0].continued is True
    assert scenario.routes[0].aborted is False
    assert summary.captured == 1
    assert summary.blocked == 0


def test_remote_capture_dns_failure_writes_no_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "remote-dns-failure"

    def fail_dns(_host: str, _port: int) -> tuple[str, ...]:
        raise OSError

    monkeypatch.setattr("ravage.traffic.scope._resolve_addresses", fail_dns)

    with pytest.raises(TrafficCaptureRuntimeError, match="DNS resolution failed"):
        capture_browser_traffic(
            target_url=REMOTE_TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=True,
        )

    assert not run_dir.exists()


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "::ffff:0.0.0.0"])
def test_remote_capture_rejects_unspecified_dns_without_writing_a_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    address: str,
) -> None:
    run_dir = tmp_path / "remote-unspecified-dns"
    monkeypatch.setattr(
        "ravage.traffic.scope._resolve_addresses",
        lambda _host, _port: (address,),
    )

    with pytest.raises(TrafficCaptureRuntimeError, match="unspecified address"):
        capture_browser_traffic(
            target_url=REMOTE_TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=True,
        )

    assert not run_dir.exists()


def test_ctrl_c_is_graceful_and_finalizes_pending_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(
        plans=[_RequestPlan(TARGET_URL, terminal="")],
        wait_action="interrupt",
    )
    _install_fake(monkeypatch, scenario)

    summary = capture_browser_traffic(
        target_url=TARGET_URL,
        run_dir=tmp_path / "interrupted-run",
        allow_remote_target=False,
    )

    assert summary.interrupted is True
    assert summary.captured == 1
    exchange = TrafficStore.open(summary.workspace_dir).exchanges()[0]
    assert exchange.response_error == "capture closed before completion"
    ordinary = read_manifest(summary.run_dir)
    assert ordinary is not None
    assert ordinary.result_label == "interrupted"
    assert read_traffic_manifest(summary.workspace_dir).completed_at


def test_browser_disconnect_is_a_normal_interactive_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(plans=[_RequestPlan(TARGET_URL)], wait_action="disconnect")
    _install_fake(monkeypatch, scenario)

    summary = capture_browser_traffic(
        target_url=TARGET_URL,
        run_dir=tmp_path / "closed-run",
        allow_remote_target=False,
    )

    assert summary.interrupted is False
    assert summary.captured == 1
    assert "browser.close" in scenario.log
    assert "playwright.exit" in scenario.log


def test_missing_playwright_error_is_actionable_and_manifests_finish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def missing() -> object:
        message = "No module named 'playwright'"
        raise ModuleNotFoundError(message)

    monkeypatch.setattr(capture_runtime, "_import_sync_playwright", missing)
    run_dir = tmp_path / "missing-playwright"

    with pytest.raises(TrafficCaptureRuntimeError) as captured:
        capture_browser_traffic(
            target_url=TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=False,
        )

    message = str(captured.value)
    assert "python -m pip install playwright" in message
    assert "python -m playwright install chromium" in message
    ordinary = read_manifest(run_dir)
    assert ordinary is not None
    assert ordinary.status == STATUS_FINISHED
    assert ordinary.result_label == "failed"
    assert read_traffic_manifest(run_dir / "workspace").completed_at


def test_missing_chromium_error_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(
        launch_error=RuntimeError(
            "Executable doesn't exist. Please run: playwright install chromium"
        )
    )
    _install_fake(monkeypatch, scenario)

    with pytest.raises(TrafficCaptureRuntimeError) as captured:
        capture_browser_traffic(
            target_url=TARGET_URL,
            run_dir=tmp_path / "missing-browser",
            allow_remote_target=False,
        )

    assert "Playwright Chromium is not installed" in str(captured.value)
    assert "python -m playwright install chromium" in str(captured.value)


def test_exchange_callback_failure_is_reported_without_losing_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(plans=[_RequestPlan(TARGET_URL)])
    _install_fake(monkeypatch, scenario)

    def broken_callback(_exchange: CapturedHttpExchange) -> None:
        message = "token=callback-secret"
        raise RuntimeError(message)

    summary = capture_browser_traffic(
        target_url=TARGET_URL,
        run_dir=tmp_path / "callback-error",
        allow_remote_target=False,
        on_exchange=broken_callback,
    )

    assert summary.captured == 1
    assert summary.recorder_errors == ("token=[REDACTED]",)
    ordinary = read_manifest(summary.run_dir)
    assert ordinary is not None
    assert ordinary.result_label == "completed_with_errors"


def test_traffic_manifest_finalization_failure_warns_and_finishes_run_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(plans=[_RequestPlan(TARGET_URL)])
    _install_fake(monkeypatch, scenario)
    real_write = capture_runtime.write_traffic_manifest

    def fail_completed_manifest(
        workspace_dir: Path,
        manifest: TrafficRunManifest,
    ) -> Path:
        if manifest.completed_at:
            message = "token=manifest-finalizer-secret"
            raise RuntimeError(message)
        return real_write(workspace_dir, manifest)

    monkeypatch.setattr(
        capture_runtime,
        "write_traffic_manifest",
        fail_completed_manifest,
    )

    summary = capture_browser_traffic(
        target_url=TARGET_URL,
        run_dir=tmp_path / "manifest-finalization-error",
        allow_remote_target=False,
    )

    assert summary.captured == 1
    assert summary.recorder_errors == ("traffic manifest finalization failed: token=[REDACTED]",)
    ordinary = read_manifest(summary.run_dir)
    assert ordinary is not None
    assert ordinary.status == STATUS_FINISHED
    assert ordinary.result_label == "completed_with_errors"
    assert not read_traffic_manifest(summary.workspace_dir).completed_at


def test_finalization_failure_does_not_replace_the_capture_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scenario = _Scenario(launch_error=RuntimeError("primary browser failure"))
    _install_fake(monkeypatch, scenario)
    real_write = capture_runtime.write_traffic_manifest

    def fail_completed_manifest(
        workspace_dir: Path,
        manifest: TrafficRunManifest,
    ) -> Path:
        if manifest.completed_at:
            message = "token=manifest-finalizer-secret"
            raise RuntimeError(message)
        return real_write(workspace_dir, manifest)

    monkeypatch.setattr(
        capture_runtime,
        "write_traffic_manifest",
        fail_completed_manifest,
    )
    run_dir = tmp_path / "capture-and-finalization-error"

    with pytest.raises(TrafficCaptureRuntimeError, match="primary browser failure") as captured:
        capture_browser_traffic(
            target_url=TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=False,
        )

    assert "manifest-finalizer-secret" not in str(captured.value)
    assert captured.value.__notes__ == [
        "Capture warning: traffic manifest finalization failed: token=[REDACTED]"
    ]
    ordinary = read_manifest(run_dir)
    assert ordinary is not None
    assert ordinary.status == STATUS_FINISHED
    assert ordinary.result_label == "failed"


@pytest.mark.parametrize("duration", [-1.0, float("inf"), float("nan")])
def test_invalid_duration_is_rejected_before_writing_a_run(
    tmp_path: Path,
    duration: float,
) -> None:
    run_dir = tmp_path / "invalid-duration"

    with pytest.raises(ValueError, match="finite non-negative"):
        capture_browser_traffic(
            target_url=TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=False,
            duration_seconds=duration,
        )

    assert not run_dir.exists()


def test_capture_refuses_to_mix_with_an_existing_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "existing-run"
    run_dir.mkdir()
    marker = run_dir / "keep.txt"
    marker.write_text("user data", encoding="utf-8")

    with pytest.raises(TrafficCaptureRuntimeError, match="not empty"):
        capture_browser_traffic(
            target_url=TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=False,
        )

    assert marker.read_text(encoding="utf-8") == "user data"


def test_capture_rejects_a_symlinked_run_directory(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    run_dir = tmp_path / "capture-link"
    run_dir.symlink_to(destination, target_is_directory=True)

    with pytest.raises(TrafficCaptureRuntimeError, match="cannot be a symlink"):
        capture_browser_traffic(
            target_url=TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=False,
        )

    assert not list(destination.iterdir())


def test_capture_wraps_run_directory_inspection_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "unreadable-run"
    run_dir.mkdir()
    path_type = type(run_dir)
    original_iterdir = path_type.iterdir

    def denied(path: Path) -> Iterator[Path]:
        if path == run_dir:
            message = "permission denied"
            raise PermissionError(message)
        return original_iterdir(path)

    monkeypatch.setattr(path_type, "iterdir", denied)

    with pytest.raises(TrafficCaptureRuntimeError, match="could not inspect"):
        capture_browser_traffic(
            target_url=TARGET_URL,
            run_dir=run_dir,
            allow_remote_target=False,
        )


def test_capture_cli_rejects_a_file_run_path_without_a_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_path = tmp_path / "not-a-directory"
    run_path.write_text("keep", encoding="utf-8")

    with pytest.raises(SystemExit) as stopped:
        main(
            [
                "traffic",
                "capture",
                TARGET_URL,
                "--run-dir",
                str(run_path),
                "--headless",
                "--duration",
                "1",
            ]
        )

    captured = capsys.readouterr()
    assert stopped.value.code == CLI_USAGE_ERROR
    assert "not a directory" in captured.err
    assert "Traceback" not in captured.err
    assert run_path.read_text(encoding="utf-8") == "keep"
