import json
import sqlite3
from io import StringIO
from pathlib import Path

from ravage.dry_run import (
    DryRunSettings,
    PageProbe,
    discover_bwapp_routes,
    parse_openapi_routes,
    run_dry_run,
)

OPENAPI_BODY = json.dumps(
    {
        "paths": {
            "/hash": {
                "get": {
                    "parameters": [
                        {"name": "data", "in": "query", "schema": {"type": "string"}},
                    ],
                },
            },
            "/search": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                    ],
                },
            },
            "/users/{user_id}": {
                "get": {
                    "parameters": [
                        {"name": "user_id", "in": "path", "schema": {"type": "integer"}},
                    ],
                },
            },
            "/webhook": {"post": {}},
            "/profile": {
                "patch": {
                    "parameters": [
                        {"name": "session", "in": "cookie", "schema": {"type": "string"}},
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "display_name": {"type": "string"},
                                        "avatar_url": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                },
            },
        },
    },
)
PROBE_TIMEOUT_SECONDS = 5.0


def test_parse_openapi_routes_discovers_methods_and_params() -> None:
    routes = parse_openapi_routes(OPENAPI_BODY)

    assert [(route.method, route.path) for route in routes] == [
        ("GET", "/hash"),
        ("PATCH", "/profile"),
        ("GET", "/search"),
        ("GET", "/users/{user_id}"),
        ("POST", "/webhook"),
    ]
    assert routes[2].params[0].name == "q"
    assert routes[2].params[0].location == "query"
    assert routes[3].params[0].location == "path"
    assert {(param.name, param.location) for param in routes[1].params} == {
        ("session", "cookie"),
        ("display_name", "body"),
        ("avatar_url", "body"),
    }


def test_run_dry_run_prints_trace_and_writes_audit_rows(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        """
engagement_id: "33333333-3333-4333-8333-333333333333"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope: []
roe:
  max_rps: 10
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "sql_injection"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
""".lstrip(),
        encoding="utf-8",
    )
    db_path = tmp_path / "run.db"
    stdout = StringIO()

    def fake_fetcher(url: str, timeout: float) -> tuple[int, str]:
        assert url == "http://127.0.0.1:8765/openapi.json"
        assert timeout == PROBE_TIMEOUT_SECONDS
        return 200, OPENAPI_BODY

    returned_db_path = run_dry_run(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        settings=DryRunSettings(db_path=db_path, stdout=stdout, fetcher=fake_fetcher),
    )

    output = stdout.getvalue()
    assert returned_db_path == db_path
    assert "[plan] mode=dry-run profile=openapi real_agents=not_started" in output
    assert "[state] recon_started" in output
    assert "[tool:http_get] GET http://127.0.0.1:8765/openapi.json" in output
    assert "[recon] discovered GET /search params=q" in output
    assert "[attack_surface] endpoints=5" in output
    assert "[state] exploit_skipped" in output

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT actor, action, payload_json FROM audit_log ORDER BY id"
        ).fetchall()

    actions = [(row[0], row[1]) for row in rows]
    assert ("orchestrator", "engagement_loaded") in actions
    assert ("orchestrator", "scope_firewall_plan_generated") in actions
    assert ("recon_dry_run", "http_probe_completed") in actions
    assert ("recon_dry_run", "attack_surface_emitted") in actions
    assert ("exploit_dry_run", "phase_skipped") in actions
    assert ("orchestrator", "run_completed") in actions

    attack_surface_payload = next(
        json.loads(row[2])
        for row in rows
        if row[0] == "recon_dry_run" and row[1] == "attack_surface_emitted"
    )
    endpoint_urls = [endpoint["url"] for endpoint in attack_surface_payload["endpoints"]]
    assert "http://127.0.0.1:8765/search" in endpoint_urls
    search_endpoint = next(
        endpoint
        for endpoint in attack_surface_payload["endpoints"]
        if endpoint["url"] == "http://127.0.0.1:8765/search"
    )
    assert search_endpoint["params"][0]["name"] == "q"


def test_discover_bwapp_routes_from_portal_links() -> None:
    probes = (
        PageProbe(
            path="portal.php",
            url="http://127.0.0.1:8080/bWAPP/portal.php",
            status_code=200,
            body="""
<html>
  <body>
    <a href="sqli_1.php?title=test&action=search">SQL Injection GET Search</a>
    <a href="/bWAPP/sqli_2.php?movie=1&action=go">SQL Injection GET Select</a>
    <a href="xss_get.php">XSS</a>
  </body>
</html>
""",
            error=None,
        ),
    )

    routes = discover_bwapp_routes("http://127.0.0.1:8080/bWAPP/", probes)

    assert [(route.method, route.path) for route in routes] == [
        ("GET", "login.php"),
        ("GET", "portal.php"),
        ("GET", "sqli_1.php?title=test&action=search"),
        ("GET", "sqli_2.php?movie=1&action=go"),
    ]
    assert routes[2].params[0].name == "title"
    assert routes[3].params[0].name == "movie"
