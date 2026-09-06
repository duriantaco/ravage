from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.source_context import SourceContextExecutor
from ravage.agent_core.source_navigation import (
    SourceNavigationPolicy,
    build_source_navigation_policy,
)
from ravage.repository_context import RepositoryContext, capture_repository

if TYPE_CHECKING:
    from pathlib import Path


def _context(
    tmp_path: Path, files: dict[str, str]
) -> tuple[RepositoryContext, SourceNavigationPolicy, SourceContextExecutor]:
    for relative, text in files.items():
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    context = capture_repository(tmp_path)
    return context, build_source_navigation_policy(context), SourceContextExecutor(context)


def _excerpt(
    executor: SourceContextExecutor,
    path: str,
    start_line: int,
    end_line: int,
) -> dict[str, object]:
    return executor.execute(
        {
            "action": "source_context",
            "operation": "excerpt",
            "args": {"path": path, "start_line": start_line, "end_line": end_line},
        }
    ).observation


def _search(executor: SourceContextExecutor, query: str) -> dict[str, object]:
    return executor.execute(
        {
            "action": "source_context",
            "operation": "search",
            "args": {"query": query, "max_matches": 20},
        }
    ).observation


def test_python_route_and_query_require_their_exact_visible_lines(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                "@app.get(\n"
                '    "/hidden/admin",\n'
                ")\n"
                "def hidden_admin():\n"
                '    term = request.args.get("term")\n'
                "    return term\n"
            ),
            "other.py": '@app.get("/other")\ndef other():\n    return "ok"\n',
        },
    )

    full = _excerpt(executor, "app.py", 1, 6)
    route_only = _excerpt(executor, "app.py", 1, 4)
    literal_search = _search(executor, "/hidden/admin")

    assert policy.route_count == 2  # noqa: PLR2004
    assert policy.query_name_count == 1
    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/hidden/admin?term="},
        observation=full,
    )
    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/hidden/admin"},
        observation=route_only,
    )
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/hidden/admin?term="},
        observation=route_only,
    )
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/hidden/admin"},
        observation=literal_search,
    )
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/other"},
        observation=full,
    )


def test_one_line_search_can_authorize_only_that_direct_route(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {"app.py": '@app.get("/visible")\ndef visible():\n    return "ok"\n'},
    )

    observation = _search(executor, "app.get")

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/visible"},
        observation=observation,
    )


def test_python_route_methods_are_authorized_individually(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                '@app.route("/status", methods=["GET", "HEAD", "POST"])\n'
                "def status():\n"
                '    return "ok"\n'
            )
        },
    )
    observation = _excerpt(executor, "app.py", 1, 2)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/status"},
        observation=observation,
    )
    assert policy.permits_http_action(
        {"action": "http_request", "method": "HEAD", "path": "/status"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "OPTIONS", "path": "/status"},
        observation=observation,
    )


def test_javascript_const_path_requires_binding_use_and_get_check(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "server.ts": (
                'const diagnosticRoute: string = "/diag/7fc2";\n'
                'if (req.method === "GET" && url.pathname === diagnosticRoute) {\n'
                '  const verbose = req.query.get("verbose");\n'
                "}\n"
            )
        },
    )

    binding_only = _excerpt(executor, "server.ts", 1, 1)
    use_only = _excerpt(executor, "server.ts", 2, 3)
    route = _excerpt(executor, "server.ts", 1, 2)
    route_and_query = _excerpt(executor, "server.ts", 1, 3)
    action = {"action": "http_request", "method": "GET", "path": "/diag/7fc2"}

    assert policy.route_count == 1
    assert not policy.permits_http_action(action, observation=binding_only)
    assert not policy.permits_http_action(action, observation=use_only)
    assert policy.permits_http_action(action, observation=route)
    assert policy.permits_http_action(
        {**action, "path": "/diag/7fc2?verbose="},
        observation=route_and_query,
    )
    assert not policy.permits_http_action(
        {**action, "path": "/diag/7fc2?verbose="},
        observation=route,
    )


def test_javascript_query_name_must_belong_to_the_same_route_branch(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "server.js": (
                'if (req.method === "GET" && url.pathname === "/safe") {}\n'
                'function unrelated(request) { request.query.get("ACME_INTERNAL_QUERY"); }\n'
            )
        },
    )
    observation = _excerpt(executor, "server.js", 1, 2)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/safe?ACME_INTERNAL_QUERY=",
        },
        observation=observation,
    )


def test_javascript_direct_multiline_registration_is_structural(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "server.js": (
                "app.get(\n"
                '  "/multiline",\n'
                "  (req, res) => res.send(req.query.mode),\n"
                ");\n"
            )
        },
    )

    observation = _excerpt(executor, "server.js", 1, 4)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/multiline?mode="},
        observation=observation,
    )


@pytest.mark.parametrize(
    "source",
    [
        '// app.get("/comment", handler);\n',
        'const note = \'app.get("/string", handler)\';\n',
        'client.get("/client", handler);\n',
        'app.get("/getter");\n',
        'let ROUTE = "/let"; app.get(ROUTE, handler);\n',
        "const ROUTE = `/${name}`; app.get(ROUTE, handler);\n",
        'const ROUTE = "/joined" + "/tail"; app.get(ROUTE, handler);\n',
        'const ROUTE = "/old"; ROUTE = "/new"; app.get(ROUTE, handler);\n',
        'const ROUTE\nmetadata = "/ACME_INTERNAL_LEAK";\napp.get(ROUTE, handler);\n',
        '/* app.get("/unterminated", handler);\n',
        'if (req.method === "GET" && user.pathname === "/ACME_INTERNAL_LEAK") {}\n',
    ],
)
def test_javascript_decoys_and_dynamic_routes_grant_no_authority(
    tmp_path: Path,
    source: str,
) -> None:
    _captured, policy, executor = _context(tmp_path, {"server.js": source})

    observation = _excerpt(executor, "server.js", 1, len(source.splitlines()))

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/comment"},
        observation=observation,
    )


@pytest.mark.parametrize(
    "action",
    [
        {"action": "http_request", "method": "HEAD", "path": "/hidden"},
        {"action": "http_request", "method": "GET", "path": "/Hidden"},
        {"action": "http_request", "method": "GET", "path": "/hidden/extra"},
        {"action": "http_request", "method": "GET", "path": "/hidden%2fextra"},
        {"action": "http_request", "method": "GET", "path": "/hidden?term=value"},
        {"action": "http_request", "method": "GET", "path": "/hidden?term=&term="},
        {"action": "http_request", "method": "GET", "path": "/hidden?unknown="},
        {"action": "http_request", "method": "GET", "path": "/hidden?%74erm="},
        {"action": "http_request", "method": "GET", "path": "/hidden#fragment"},
        {"action": "http_request", "method": "GET", "url": "https://example.test/hidden"},
    ],
)
def test_http_shape_must_match_exact_static_source_fact(
    tmp_path: Path,
    action: dict[str, object],
) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                '@app.get("/hidden")\n'
                "def hidden():\n"
                '    return request.args.get("term")\n'
            )
        },
    )
    observation = _excerpt(executor, "app.py", 1, 3)

    assert not policy.permits_http_action(action, observation=observation)


def test_candidate_payloads_and_nonruntime_files_never_grant_authority(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    tests.joinpath("fixture.py").write_text(
        '@app.get("/decoy")\ndef decoy():\n    return "ok"\n',
        encoding="utf-8",
    )
    context = capture_repository(tmp_path)
    policy = build_source_navigation_policy(
        context,
        candidate_payloads=(
            {
                "method": "GET",
                "route": "/candidate-only",
                "route_binding": "direct",
                "relative_file": "missing.py",
                "line": 1,
            },
        ),
    )
    observation = _excerpt(SourceContextExecutor(context), "tests/fixture.py", 1, 2)

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/decoy"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/candidate-only"},
        observation=observation,
    )
