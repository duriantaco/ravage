from __future__ import annotations

from ravage import probe_suite
from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.xss import (
    _dom_execution_budget_for_backend,
    _dom_targets,
)
from ravage.deterministic_agents.xss_payloads import (
    _DOM_EXEC_FETCH_TIMEOUT_MS,
    _browser_proof_extractor_call,
    _dom_exec_payloads,
)
from ravage.probe_suite import available_probes, run_builtin_probe
from ravage.runtime.browser import (
    BrowserObservation,
    BrowserStatus,
    _is_backend_unavailable_error,
    _request_in_scope,
    _resolve_scoped_redirects,
)


def _state_with_reflected_param() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/search",
        "parameters": [
            {
                "name": "q",
                "locations": ["http://127.0.0.1/search?q=1"],
                "hints": ["reflected"],
                "priority": 90,
            }
        ],
        "reflections": [{"name": "q", "source": "query", "url": "http://127.0.0.1/search?q=1"}],
        "forms": [],
        "endpoints": [],
    }
    return state


def _set_available(monkeypatch, *, available: bool, reason: str = "") -> None:
    monkeypatch.setattr(
        probe_suite,
        "browser_backend_status",
        lambda: BrowserStatus(available=available, reason=reason),
    )


def test_dom_execution_is_an_available_probe() -> None:
    assert "dom_execution" in {item["name"] for item in available_probes()}


def test_dom_execution_degrades_when_backend_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        probe_suite,
        "browser_backend_status",
        lambda: BrowserStatus(available=False, reason="playwright import failed: no module"),
    )

    result = run_builtin_probe(
        "dom_execution",
        target_url="http://127.0.0.1/search",
        state=_state_with_reflected_param(),
    )

    assert result.ok is False
    assert "unavailable" in result.summary
    assert result.findings == []
    assert any("playwright install chromium" in error for error in result.errors)


def test_dom_execution_no_finding_when_token_does_not_execute(monkeypatch) -> None:
    _set_available(monkeypatch, available=True)

    def fake_render(url: str, **_kwargs: object) -> BrowserObservation:
        return BrowserObservation(
            available=True, url=url, token_executed=False, body_snippet="reflected only"
        )

    monkeypatch.setattr(probe_suite, "render_url", fake_render)

    result = run_builtin_probe(
        "dom_execution",
        target_url="http://127.0.0.1/search",
        state=_state_with_reflected_param(),
    )

    assert result.ok is False
    assert result.findings == []
    assert "confirmed executions=0" in result.summary


def test_dom_execution_finding_carries_executor_execution_marker(monkeypatch) -> None:
    _set_available(monkeypatch, available=True)

    def fake_render(url: str, **kwargs: object) -> BrowserObservation:
        token = str(kwargs.get("token") or "")
        return BrowserObservation(
            available=True,
            url=url,
            token_executed=True,
            final_url=url,
            executed_values=[token],
        )

    monkeypatch.setattr(probe_suite, "render_url", fake_render)

    result = run_builtin_probe(
        "dom_execution",
        target_url="http://127.0.0.1/search",
        state=_state_with_reflected_param(),
    )

    assert result.ok is True
    finding = result.findings[0]
    assert finding["type"] == "client_side_execution"
    evidence = finding["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["token_executed"] is True


def test_dom_execution_surfaces_render_errors(monkeypatch) -> None:
    _set_available(monkeypatch, available=True)

    def fake_render(url: str, **_kwargs: object) -> BrowserObservation:
        return BrowserObservation(available=True, url=url, error="navigation failed")

    monkeypatch.setattr(probe_suite, "render_url", fake_render)

    result = run_builtin_probe(
        "dom_execution",
        target_url="http://127.0.0.1/search",
        state=_state_with_reflected_param(),
    )

    assert result.ok is False
    assert "navigation failed" in result.errors


def test_dom_execution_browser_fetch_scan_allows_slow_same_origin_responses() -> None:
    extractor = _browser_proof_extractor_call("RAVAGE_XSSEXEC_test", "__ravage_exec")

    assert f"setTimeout(function(){{c.abort()}},{_DOM_EXEC_FETCH_TIMEOUT_MS});" in extractor
    assert "setTimeout(function(){c.abort()},700);" not in extractor


def test_dom_execution_chrome_fallback_uses_small_budget() -> None:
    status = BrowserStatus(True, "playwright import failed; using local Chrome DevTools fallback")

    assert _dom_execution_budget_for_backend(status) == 1


def test_dom_execution_prioritizes_post_form_for_visible_xss_objective() -> None:
    state = AgentState()
    state.surface = {
        "visible_description": "Execute XSS with alert('XSS').",
        "target_url": "http://127.0.0.1:8000/",
        "parameters": [
            {"name": "q", "locations": ["http://127.0.0.1:8000/?q=1"], "priority": 99}
        ],
        "forms": [
            {
                "action": "http://127.0.0.1:8000/page",
                "method": "POST",
                "inputs": [{"name": "solution"}],
            }
        ],
    }
    state.signals["reflections"] = ["q reflected in root"]

    targets = _dom_targets(state)

    assert targets[0]["name"] == "solution"
    assert targets[0]["method"] == "POST"


def test_dom_execution_payloads_try_direct_xss_dialogs_first() -> None:
    payloads = _dom_exec_payloads("TOKEN", "__ravage_exec", [])

    assert payloads[0] == "<image/src/onerror=alert('XSS')>"
    assert "<svg onload=alert('XSS')>" in payloads[:6]
    assert "<img src=x onerror=alert('XSS')>" in payloads[:6]


def test_dom_execution_aborts_cleanly_if_backend_drops_midrun(monkeypatch) -> None:
    _set_available(monkeypatch, available=True)

    def fake_render(url: str, **_kwargs: object) -> BrowserObservation:
        return BrowserObservation(available=False, url=url, reason="browser process died")

    monkeypatch.setattr(probe_suite, "render_url", fake_render)

    result = run_builtin_probe(
        "dom_execution",
        target_url="http://127.0.0.1/search",
        state=_state_with_reflected_param(),
    )

    assert result.ok is False
    assert "browser process died" in result.summary


def test_browser_scope_guard_allows_only_same_origin_local_urls() -> None:
    origin = "http://127.0.0.1:8000/"

    assert _request_in_scope(origin, "http://127.0.0.1:8000/static/app.js") is True
    assert _request_in_scope(origin, "http://127.0.0.1:8001/static/app.js") is False
    assert _request_in_scope(origin, "https://127.0.0.1:8000/static/app.js") is False
    assert _request_in_scope(origin, "https://example.com/payload.js") is False
    assert _request_in_scope(origin, "data:text/javascript,alert(1)") is False


def test_browser_scope_guard_allows_only_explicit_remote_path_scope() -> None:
    origin = "https://staging.example.test/app"
    kwargs = {
        "allow_remote_target": True,
        "in_scope": ["https://staging.example.test/app"],
        "out_of_scope": ["https://staging.example.test/app/admin"],
    }

    assert _request_in_scope(origin, "https://staging.example.test/app/main.js", **kwargs)
    assert not _request_in_scope(origin, "https://staging.example.test/app/admin", **kwargs)
    assert not _request_in_scope(origin, "https://cdn.example.test/main.js", **kwargs)


def test_browser_backend_error_classification() -> None:
    assert _is_backend_unavailable_error("Executable doesn't exist at /tmp/chromium") is True
    assert _is_backend_unavailable_error("please run playwright install chromium") is True
    assert _is_backend_unavailable_error("net::ERR_ABORTED") is False


def test_browser_redirect_preflight_blocks_cross_origin_redirect(monkeypatch) -> None:
    monkeypatch.setattr(
        "ravage.runtime.browser.build_opener",
        lambda *_args: _FakeRedirectOpener([_FakeRedirectResponse(302, "https://example.com/out")]),
    )

    origin = "http://127.0.0.1:8000/"
    resolved, error = _resolve_scoped_redirects(origin, origin=origin, timeout_seconds=1)

    assert resolved == ""
    assert "redirect target outside scope" in error


def test_browser_redirect_preflight_allows_same_origin_relative_redirect(monkeypatch) -> None:
    monkeypatch.setattr(
        "ravage.runtime.browser.build_opener",
        lambda *_args: _FakeRedirectOpener(
            [_FakeRedirectResponse(302, "/next"), _FakeRedirectResponse(200, "")]
        ),
    )

    origin = "http://127.0.0.1:8000/"
    resolved, error = _resolve_scoped_redirects(
        f"{origin}start",
        origin=origin,
        timeout_seconds=1,
    )

    assert error == ""
    assert resolved == f"{origin}next"


class _FakeRedirectOpener:
    def __init__(self, responses: list["_FakeRedirectResponse"]) -> None:
        self._responses = responses

    def open(self, *_args: object, **_kwargs: object) -> "_FakeRedirectResponse":
        return self._responses.pop(0)


class _FakeHeaders(dict[str, str]):
    def get_content_charset(self) -> str | None:
        return None


class _FakeRedirectResponse:
    def __init__(self, status: int, location: str) -> None:
        self.status = status
        self.headers = _FakeHeaders()
        if location:
            self.headers["Location"] = location

    def __enter__(self) -> "_FakeRedirectResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status
