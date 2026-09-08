"""Real browser regression checks, run explicitly by the cockpit CI job."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest
import ravage.live_dashboard as dashboard
from playwright.sync_api import sync_playwright
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Response


@pytest.mark.parametrize("engine", ["firefox", "chromium"])
def test_private_link_login_reload_stream_and_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    workspace.record_event(kind="agent_started", payload={"target_url": "http://127.0.0.1:8765"})
    teardown_calls: list[str] = []

    def fixture_teardown(_settings: dashboard.DashboardSettings, run_id: str) -> dict[str, bool]:
        teardown_calls.append(run_id)
        return {"ok": True}

    monkeypatch.setattr(dashboard, "teardown_active_run", fixture_teardown)
    server = dashboard.start_cockpit(
        dashboard.DashboardSettings(workspace_dir=workspace.root), port=0
    )
    origin = f"http://127.0.0.1:{server.server.server_port}"
    try:
        with sync_playwright() as playwright:
            browser = getattr(playwright, engine).launch()
            try:
                context = browser.new_context()
                page = context.new_page()
                responses: list[tuple[str, int]] = []

                def record_response(response: Response) -> None:
                    path = urlsplit(response.url).path
                    if path.startswith("/api/"):
                        responses.append((path, response.status))

                page.on("response", record_response)
                with page.expect_response(f"{origin}/api/session") as login:
                    page.goto(server.url)
                assert login.value.status == HTTPStatus.OK
                assert login.value.request.header_value("origin") == origin
                assert login.value.request.header_value("cookie") is None
                page.wait_for_url(f"{origin}/index.html")
                page.wait_for_function("() => document.querySelector('.conn.ok') !== null")
                assert ("/api/state", HTTPStatus.OK) in responses
                assert ("/api/events/stream", HTTPStatus.OK) in responses
                assert context.cookies() == []

                page.reload()
                page.wait_for_function("() => document.querySelector('.conn.ok') !== null")
                # Invoke the app's transport; Firefox must generate the Origin itself.
                with page.expect_response(f"{origin}/api/teardown") as mutation:
                    result = page.evaluate("""async () => {
                        const { cockpitFetch } = await import('/src/transport.js');
                        const response = await cockpitFetch('/api/teardown', { method: 'POST' });
                        return response.json();
                    }""")
                assert mutation.value.status == HTTPStatus.OK
                assert mutation.value.request.header_value("origin") == origin
                assert mutation.value.request.header_value("cookie") is None
                assert result == {"ok": True}
                assert teardown_calls == [""]
            finally:
                browser.close()
    finally:
        server.shutdown()
