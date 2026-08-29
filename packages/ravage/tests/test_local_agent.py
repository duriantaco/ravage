from __future__ import annotations

import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import pytest
from pentest_schemas import Scope
from ravage.local_agent import (
    HTTP_OK,
    HttpExchange,
    LocalAgentSettings,
    UrllibHttpClient,
    run_local_sqli_agent,
)

if TYPE_CHECKING:
    from pathlib import Path

BRIEF_YAML = """
engagement_id: "55555555-5555-4555-8555-555555555555"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "sql_injection"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
""".lstrip()


class FakeSearchClient:
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
                            "/search": {
                                "get": {
                                    "parameters": [
                                        {"name": "q", "in": "query"},
                                    ],
                                },
                            },
                        },
                    }
                ),
            )

        query = parse_qs(parsed.query)
        q = query.get("q", [""])[0]
        if q == "%' OR 1=1 -- ":
            body = '{"results":[["alice"],["bob"],["charlie"]]}'
        elif q == "%' AND 1=2 -- ":
            body = '{"results":[]}'
        elif q == "'":
            body = "Internal Server Error"
            return HttpExchange(method="GET", url=url, status_code=500, body=body)
        else:
            body = '{"results":[["alice"]]}'
        return HttpExchange(method="GET", url=url, status_code=200, body=body)

    def post_form(self, url: str, data: dict[str, str]) -> HttpExchange:
        del data
        return HttpExchange(method="POST", url=url, status_code=404, body="")

    def post_json(self, url: str, data: dict[str, str]) -> HttpExchange:
        del data
        return HttpExchange(method="POST", url=url, status_code=404, body="")


class FakeBwappClient:
    def get(self, url: str) -> HttpExchange:
        parsed = urlparse(url)
        if parsed.path.endswith("/login.php"):
            return HttpExchange(method="GET", url=url, status_code=200, body="<title>bWAPP</title>")
        if parsed.path.endswith("/portal.php"):
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body='<a href="sqli_1.php?title=test&action=search">SQL Injection</a>',
            )
        if parsed.path.endswith("/sqli_1.php"):
            query = parse_qs(parsed.query)
            title = query.get("title", [""])[0]
            if title == "%' OR 1=1 -- ":
                body = "movie: alice\nmovie: bob\nmovie: charlie"
            elif title == "%' AND 1=2 -- ":
                body = "No movies were found."
            elif title == "'":
                body = "You have an error in your SQL syntax"
            else:
                body = "movie: alice"
            return HttpExchange(method="GET", url=url, status_code=200, body=body)
        return HttpExchange(method="GET", url=url, status_code=404, body="")

    def post_form(self, url: str, data: dict[str, str]) -> HttpExchange:
        assert data["login"] == "bee"
        assert "password" in data
        return HttpExchange(method="POST", url=url, status_code=200, body="portal")

    def post_json(self, url: str, data: dict[str, str]) -> HttpExchange:
        del data
        return HttpExchange(method="POST", url=url, status_code=404, body="")


class FakeXben006Client:
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
                            "/": {"get": {}},
                            "/jobs": {"post": {}},
                            "/ping": {"get": {}},
                        },
                    }
                ),
            )
        if parsed.path == "/":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body="""
<script>
fetch('/jobs', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({ job_type: jobType })
})
</script>
<option value="front-end">front-end</option>
""",
            )
        return HttpExchange(method="GET", url=url, status_code=200, body="{}")

    def post_form(self, url: str, data: dict[str, str]) -> HttpExchange:
        del data
        return HttpExchange(method="POST", url=url, status_code=404, body="")

    def post_json(self, url: str, data: dict[str, str]) -> HttpExchange:
        job_type = data.get("job_type", "")
        if job_type == "private' -- ":
            body = (
                '[{"id":3,"name":"Hidden job","type":"private",'
                '"description":"flag{unit_xben_006}"}]'
            )
        elif job_type == "definitely-missing' -- ":
            body = "[]"
        elif job_type == "'":
            body = "sqlite3.OperationalError: unrecognized token"
            return HttpExchange(
                method="POST",
                url=url,
                status_code=500,
                body=body,
                request_body=json.dumps(data, sort_keys=True),
            )
        else:
            body = '[{"id":1,"name":"Senior Frontend Dev","type":"front-end"}]'
        return HttpExchange(
            method="POST",
            url=url,
            status_code=200,
            body=body,
            request_body=json.dumps(data, sort_keys=True),
        )


def test_urllib_http_client_blocks_out_of_scope_redirect() -> None:
    off_scope_hits: list[str] = []

    class OffScopeHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            off_scope_hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"off scope")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
            return

    off_scope_server = ThreadingHTTPServer(("127.0.0.1", 0), OffScopeHandler)
    off_scope_thread = threading.Thread(target=off_scope_server.serve_forever, daemon=True)
    off_scope_thread.start()
    off_scope_url = f"http://127.0.0.1:{off_scope_server.server_port}/secret"

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", off_scope_url)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
            return

    redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    redirect_thread = threading.Thread(target=redirect_server.serve_forever, daemon=True)
    redirect_thread.start()
    target_url = f"http://127.0.0.1:{redirect_server.server_port}"

    try:
        client = UrllibHttpClient(
            target_url=target_url,
            scope=Scope(in_scope=[target_url], out_of_scope=[]),
            allow_remote_target=False,
        )

        exchange = client.get(f"{target_url}/start")

        assert exchange.status_code is None
        assert exchange.error is not None
        assert "must be listed in engagement scope" in exchange.error
        assert off_scope_hits == []
    finally:
        redirect_server.shutdown()
        off_scope_server.shutdown()
        redirect_server.server_close()
        off_scope_server.server_close()


def test_urllib_http_client_pins_remote_host_and_preserves_host_header() -> None:
    hits: list[tuple[str, str | None]] = []

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append((self.path, self.headers.get("Host")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
            return

    target_server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
    target_thread.start()
    target_url = f"http://rebind.test:{target_server.server_port}"
    resolver_calls: list[tuple[str, int]] = []

    def resolver(host: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((host, port))
        return ("127.0.0.1",)

    try:
        client = UrllibHttpClient(
            target_url=target_url,
            scope=Scope(in_scope=[target_url], out_of_scope=[]),
            allow_remote_target=True,
            address_resolver=resolver,
        )

        exchange = client.get(f"{target_url}/ok")

        assert exchange.status_code == HTTP_OK
        assert exchange.body == "ok"
        assert hits == [("/ok", f"rebind.test:{target_server.server_port}")]
        assert resolver_calls == [
            ("rebind.test", target_server.server_port),
            ("rebind.test", target_server.server_port),
        ]
    finally:
        target_server.shutdown()
        target_server.server_close()


def test_urllib_http_client_blocks_dns_rebinding_after_initial_pin() -> None:
    target_url = "http://rebind.test:8080"
    answers = [("127.0.0.1",), ("169.254.169.254",)]

    def resolver(_host: str, _port: int) -> tuple[str, ...]:
        return answers.pop(0)

    client = UrllibHttpClient(
        target_url=target_url,
        scope=Scope(in_scope=[target_url], out_of_scope=[]),
        allow_remote_target=True,
        address_resolver=resolver,
    )

    exchange = client.get(f"{target_url}/secret")

    assert exchange.status_code is None
    assert exchange.error is not None
    assert "DNS resolution changed outside pinned scope" in exchange.error
    assert answers == []


def test_local_sqli_agent_confirms_openapi_boolean_sqli(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    db_path = tmp_path / "agent.db"
    stdout = StringIO()

    run_local_sqli_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=LocalAgentSettings(
            db_path=db_path,
            stdout=stdout,
            http_client=FakeSearchClient(),
        ),
    )

    output = stdout.getvalue()
    assert "[plan] mode=real-agent agent=local-sqli profile=openapi" in output
    assert "[state] exploit_started" in output
    assert "[finding] confirmed sql_injection" in output
    assert "[done] confirmed_findings=1" in output

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT status, payload_json FROM findings").fetchone()

    assert row is not None
    assert row[0] == "confirmed"
    payload = json.loads(row[1])
    assert payload["endpoint"]["url"] == "http://127.0.0.1:8765/search"
    assert payload["proof"]["impact_description"] == (
        "Confirmed SQL injection by boolean_response_delta."
    )


def test_local_sqli_agent_confirms_bwapp_sql_error(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", "http://127.0.0.1:8080/bWAPP/"),
        encoding="utf-8",
    )
    db_path = tmp_path / "bwapp-agent.db"
    stdout = StringIO()

    run_local_sqli_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8080/bWAPP/",
        settings=LocalAgentSettings(
            db_path=db_path,
            profile="bwapp",
            stdout=stdout,
            http_client=FakeBwappClient(),
        ),
    )

    output = stdout.getvalue()
    assert "[recon] login form discovered" in output
    assert "[tool:http_post] POST http://127.0.0.1:8080/bWAPP/login.php" in output
    assert "[recon] discovered GET sqli_1.php?title=test&action=search" in output
    assert "[done] confirmed_findings=" in output

    with sqlite3.connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM findings WHERE status = 'confirmed'").fetchone()

    assert count is not None
    assert count[0] >= 1


def test_local_sqli_agent_confirms_xben_post_json_sqli(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", "http://127.0.0.1:8000"),
        encoding="utf-8",
    )
    db_path = tmp_path / "xben-agent.db"
    stdout = StringIO()

    run_local_sqli_agent(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8000",
        settings=LocalAgentSettings(
            db_path=db_path,
            stdout=stdout,
            http_client=FakeXben006Client(),
        ),
    )

    output = stdout.getvalue()
    assert "[recon] discovered POST /jobs params=job_type" in output
    assert "[tool:http_post_json] POST http://127.0.0.1:8000/jobs json_keys=job_type" in output
    assert "[finding] confirmed sql_injection" in output
    assert "flag_disclosure" in output or "[done] confirmed_findings=1" in output

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT payload_json FROM findings").fetchone()

    assert row is not None
    payload = json.loads(row[0])
    assert payload["endpoint"]["url"] == "http://127.0.0.1:8000/jobs"
    assert payload["endpoint"]["params"][0]["name"] == "job_type"
    assert "flag{unit_xben_006}" in payload["proof"]["response_final"]
    assert payload["proof"]["impact_description"] == "Confirmed SQL injection by flag_disclosure."


def test_local_sqli_agent_refuses_non_local_targets(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")

    with pytest.raises(ValueError, match="only runs against localhost"):
        run_local_sqli_agent(
            brief_path=brief_path,
            target_url="https://example.com",
            settings=LocalAgentSettings(http_client=FakeSearchClient()),
        )


def test_local_sqli_agent_allows_explicit_scoped_remote_target(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    remote_url = "https://staging.example.test"
    brief_path.write_text(BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url), encoding="utf-8")
    db_path = tmp_path / "remote.db"

    run_local_sqli_agent(
        brief_path=brief_path,
        target_url=remote_url,
        settings=LocalAgentSettings(
            db_path=db_path,
            http_client=FakeSearchClient(),
            stdout=StringIO(),
            allow_remote_target=True,
        ),
    )

    conn = sqlite3.connect(db_path)
    try:
        payload = json.loads(conn.execute("SELECT payload_json FROM findings").fetchone()[0])
    finally:
        conn.close()
    assert payload["endpoint"]["url"] == "https://staging.example.test/search"


def test_local_sqli_agent_blocks_unscoped_remote_target_even_when_enabled(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", "https://staging.example.test"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must be listed in engagement scope"):
        run_local_sqli_agent(
            brief_path=brief_path,
            target_url="https://outside.example.test",
            settings=LocalAgentSettings(
                http_client=FakeSearchClient(),
                stdout=StringIO(),
                allow_remote_target=True,
            ),
        )


def test_urllib_http_client_returns_error_for_malformed_url_instead_of_raising() -> None:
    client = UrllibHttpClient()
    exchange = client.get("http://127.0.0.1:8765/bad\r\npath")

    assert isinstance(exchange, HttpExchange)
    assert exchange.status_code is None
    assert exchange.error
