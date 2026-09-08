from __future__ import annotations

from dataclasses import FrozenInstanceError
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
                "from flask import Flask, request\n"
                "app = Flask(__name__)\n"
                "@app.get(\n"
                '    "/hidden/admin",\n'
                ")\n"
                "def hidden_admin():\n"
                '    term = request.args.get("term")\n'
                "    return term\n"
            ),
            "other.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/other")\n'
                "def other():\n"
                '    return "ok"\n'
            ),
        },
    )

    full = _excerpt(executor, "app.py", 1, 8)
    route_only = _excerpt(executor, "app.py", 1, 6)
    literal_search = _search(executor, "/hidden/admin")

    assert policy.route_count == 2  # noqa: PLR2004
    assert policy.query_name_count == 1
    assert policy.authorized_http_routes(observation=full) == (
        ("GET", "/hidden/admin"),
    )
    assert policy.authorized_http_routes(observation=literal_search) == ()
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


def test_ephemeral_evidence_combines_split_route_requirements(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/split")\n'
                "def split(): return 'ok'\n"
            )
        },
    )
    binding = _excerpt(executor, "app.py", 1, 2)
    route = _excerpt(executor, "app.py", 3, 4)
    action = {"action": "http_request", "method": "GET", "path": "/split"}
    evidence = policy.begin_evidence()

    assert evidence.observe(binding)
    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(action)
    assert evidence.observe(route)
    assert evidence.authorized_http_routes() == (("GET", "/split"),)
    assert evidence.permits_http_action(action)

    evidence.clear()
    assert evidence.observation_count == 0
    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(action)


def test_ephemeral_evidence_poisoning_discards_prior_authority(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/guarded")\n'
                "def guarded(): return 'ok'\n"
            )
        },
    )
    full = _excerpt(executor, "app.py", 1, 4)
    forged = dict(full)
    forged["snapshot_id"] = "sha256:wrong"
    malformed = dict(full)
    malformed["start_line"] = 0
    error = dict(full)
    error["type"] = "error"
    action = {"action": "http_request", "method": "GET", "path": "/guarded"}
    evidence = policy.begin_evidence()

    for invalid in (forged, malformed, error):
        evidence.clear()
        assert evidence.observe(full)
        assert evidence.permits_http_action(action)
        assert not evidence.observe(invalid)
        assert not evidence.permits_http_action(action)
        assert evidence.authorized_http_routes() == ()

    evidence.clear()
    assert evidence.observe(full)
    assert evidence.permits_http_action(action)

    file_list = executor.execute(
        {
            "action": "source_context",
            "operation": "list_files",
            "args": {"limit": 10},
        }
    ).observation
    assert evidence.observe(file_list)
    assert evidence.permits_http_action(action)


def test_ephemeral_evidence_overflow_clears_and_poison_session(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/bounded")\n'
                "def bounded(): return 'ok'\n"
            )
        },
    )
    full = _excerpt(executor, "app.py", 1, 4)
    action = {"action": "http_request", "method": "GET", "path": "/bounded"}
    evidence = policy.begin_evidence()

    for _ in range(16):
        assert evidence.observe(full)
    assert evidence.permits_http_action(action)

    assert not evidence.observe(full)
    assert evidence.observation_count == 0
    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(action)
    assert not evidence.observe(full)


def test_task_bound_evidence_rejects_missing_and_switched_tasks(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/task-bound")\n'
                "def task_bound(): return 'ok'\n"
            )
        },
    )
    binding = _excerpt(executor, "app.py", 1, 2)
    route = _excerpt(executor, "app.py", 3, 4)
    evidence = policy.begin_evidence(require_task=True)

    assert evidence.task_id == ""

    assert not evidence.observe(binding)
    assert evidence.task_id == ""
    assert not evidence.observe(route, task_id="task-a")

    evidence.clear()
    assert evidence.observe(binding, task_id="task-a")
    assert evidence.task_id == "task-a"
    assert evidence.observe(route, task_id="task-b")
    assert evidence.task_id == "task-b"
    assert not evidence.permits_http_action(
        {
            "action": "http_request",
            "task_id": "task-b",
            "method": "GET",
            "path": "/task-bound",
        }
    )
    assert evidence.observe(binding, task_id="task-b")
    assert evidence.permits_http_action(
        {
            "action": "http_request",
            "task_id": "task-b",
            "method": "GET",
            "path": "/task-bound",
        }
    )
    assert not evidence.permits_http_action(
        {
            "action": "http_request",
            "task_id": "task-a",
            "method": "GET",
            "path": "/task-bound",
        }
    )


def test_evidence_atoms_cannot_be_reused_across_snapshots(tmp_path: Path) -> None:
    _captured_a, policy_a, executor_a = _context(
        tmp_path / "a",
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/route-a")\n'
                "def route_a(): return 'a'\n"
            )
        },
    )
    _captured_b, policy_b, _executor_b = _context(
        tmp_path / "b",
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/route-b")\n'
                "def route_b(): return 'b'\n"
            )
        },
    )
    evidence = policy_a.begin_evidence()
    assert evidence.observe(_excerpt(executor_a, "app.py", 1, 4))

    with pytest.raises(FrozenInstanceError):
        evidence._policy = policy_b  # type: ignore[misc]  # noqa: SLF001

    object.__setattr__(evidence, "_policy", policy_b)
    assert not evidence.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/route-b"}
    )


def test_one_line_search_cannot_hide_framework_receiver_provenance(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/visible")\n'
                "def visible():\n"
                '    return "ok"\n'
            )
        },
    )

    observation = _search(executor, "app.get")
    full = _excerpt(executor, "app.py", 1, 5)

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/visible"},
        observation=observation,
    )
    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/visible"},
        observation=full,
    )


def test_python_route_methods_are_authorized_individually(tmp_path: Path) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "app.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.route("/status", methods=["GET", "HEAD", "POST"])\n'
                "def status():\n"
                '    return "ok"\n'
            )
        },
    )
    observation = _excerpt(executor, "app.py", 1, 4)

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
                'const http = require("node:http");\n'
                'const diagnosticRoute: string = "/diag/7fc2";\n'
                "http.createServer((req, res) => {\n"
                '  const url = new URL(req.url, "http://localhost");\n'
                '  if (req.method === "GET" && url.pathname === diagnosticRoute) {\n'
                '    const verbose = req.query.get("verbose");\n'
                "  }\n"
                "});\n"
            )
        },
    )

    binding_only = _excerpt(executor, "server.ts", 1, 2)
    use_only = _excerpt(executor, "server.ts", 3, 7)
    route = _excerpt(executor, "server.ts", 1, 5)
    route_and_query = _excerpt(executor, "server.ts", 1, 6)
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
                'const http = require("node:http");\n'
                "http.createServer((req, res) => {\n"
                '  const url = new URL(req.url, "http://localhost");\n'
                '  if (req.method === "GET" && url.pathname === "/safe") {}\n'
                "});\n"
                'function unrelated(request) { request.query.get("ACME_INTERNAL_QUERY"); }\n'
            )
        },
    )
    observation = _excerpt(executor, "server.js", 1, 6)

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
                'const express = require("express");\n'
                "const app = express();\n"
                "app.get(\n"
                '  "/multiline",\n'
                "  (req, res) => res.send(req.query.mode),\n"
                ");\n"
            )
        },
    )

    observation = _excerpt(executor, "server.js", 1, 6)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/multiline?mode="},
        observation=observation,
    )


def test_express_query_requires_the_handler_request_parameter(tmp_path: Path) -> None:
    source = (
        'const express=require("express");\n'
        "const app=express();\n"
        'app.get("/safe",(request,res)=>{\n'
        "  const req=metadata;\n"
        "  return req.query.LOCAL_METADATA;\n"
        "});\n"
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, 6)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/safe?LOCAL_METADATA=",
        },
        observation=observation,
    )


def test_native_pathname_requires_a_url_derived_from_callback_request(
    tmp_path: Path,
) -> None:
    source = (
        'const http=require("node:http");\n'
        "http.createServer((req,res)=>{\n"
        '  const url={pathname:"/local-metadata"};\n'
        '  if(req.method==="GET"&&url.pathname==="/local-metadata"){}\n'
        "});\n"
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, 5)

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/local-metadata"},
        observation=observation,
    )


def test_native_query_requires_the_create_server_request_parameter(
    tmp_path: Path,
) -> None:
    source = (
        'const http=require("node:http");\n'
        "http.createServer((request,res)=>{\n"
        '  const url=new URL(request.url,"http://localhost");\n'
        '  if(request.method==="GET"&&url.pathname==="/safe"){\n'
        "    const req=metadata;\n"
        "    req.query.LOCAL_METADATA;\n"
        "  }\n"
        "});\n"
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, 8)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/safe?LOCAL_METADATA=",
        },
        observation=observation,
    )


def test_python_decorator_requires_a_known_module_receiver_constructor(
    tmp_path: Path,
) -> None:
    source = (
        "class Labels:\n"
        "    class app:\n"
        "        @staticmethod\n"
        "        def get(label):\n"
        "            return lambda fn: fn\n"
        "\n"
        '@Labels.app.get("/PYTHON_LEAK")\n'
        "def metadata_label():\n"
        "    return None\n"
    )
    _captured, policy, executor = _context(tmp_path, {"labels.py": source})
    observation = _excerpt(executor, "labels.py", 1, len(source.splitlines()))

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/PYTHON_LEAK"},
        observation=observation,
    )


def test_python_receiver_reassignment_invalidates_framework_provenance(
    tmp_path: Path,
) -> None:
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "app = metadata_registry\n"
        '@app.get("/REASSIGNED_PYTHON_LEAK")\n'
        "def metadata_label():\n"
        "    return None\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    observation = _excerpt(executor, "app.py", 1, len(source.splitlines()))

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/REASSIGNED_PYTHON_LEAK",
        },
        observation=observation,
    )


def test_python_query_extraction_stays_in_reachable_handler_scope(tmp_path: Path) -> None:
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.get("/safe")\n'
        "def handler():\n"
        "    if False:\n"
        '        request.args.get("DEAD_QUERY_LEAK")\n'
        "    if False and metadata:\n"
        '        request.args.get("COMPOUND_DEAD_QUERY_LEAK")\n'
        "    def nested():\n"
        '        return request.args.get("NESTED_QUERY_LEAK")\n'
        "    class Nested:\n"
        '        value = request.args.get("CLASS_QUERY_LEAK")\n'
        '    callback = lambda: request.args.get("LAMBDA_QUERY_LEAK")\n'
        "    return callback\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    observation = _excerpt(executor, "app.py", 1, len(source.splitlines()))

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe"},
        observation=observation,
    )
    for name in (
        "CLASS_QUERY_LEAK",
        "COMPOUND_DEAD_QUERY_LEAK",
        "DEAD_QUERY_LEAK",
        "LAMBDA_QUERY_LEAK",
        "NESTED_QUERY_LEAK",
    ):
        assert not policy.permits_http_action(
            {"action": "http_request", "method": "GET", "path": f"/safe?{name}="},
            observation=observation,
        )


def test_python_locally_shadowed_request_grants_no_query_authority(
    tmp_path: Path,
) -> None:
    source = (
        "from flask import Flask\n"
        "app=Flask(__name__)\n"
        '@app.get("/safe")\n'
        "def handler():\n"
        "    request=Metadata()\n"
        '    return request.args.get("SHADOW_QUERY")\n'
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    observation = _excerpt(executor, "app.py", 1, 6)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe?SHADOW_QUERY="},
        observation=observation,
    )


@pytest.mark.parametrize(
    "source",
    [
        (
            'const express = require("express");\n'
            "const app = express();\n"
            "app = metadataRegistry;\n"
            'app.get("/REASSIGN_LEAK", handler);\n'
        ),
        (
            'const express = require("express");\n'
            "const app = express();\n"
            "const registry = { app };\n"
            'registry.app.get("/PROPERTY_LEAK", handler);\n'
        ),
        (
            'const express = require("express");\n'
            "express = metadataFactory;\n"
            "const app = express();\n"
            'app.get("/FACTORY_REASSIGN_LEAK", handler);\n'
        ),
        (
            "let app = realRouter;\n"
            "app = metadataRegistry;\n"
            'app.get("/LET_REASSIGN_LEAK", handler);\n'
        ),
    ],
)
def test_javascript_route_receiver_requires_immutable_constructor_provenance(
    tmp_path: Path,
    source: str,
) -> None:
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, len(source.splitlines()))

    assert policy.route_count == 0
    assert policy.authorized_http_routes(observation=observation) == ()


def test_javascript_express_router_constructor_is_a_realistic_positive(
    tmp_path: Path,
) -> None:
    source = (
        'const express = require("express");\n'
        "const router = express.Router();\n"
        'router.get("/router-status", (req, res) => res.send(req.query.mode));\n'
    )
    _captured, policy, executor = _context(tmp_path, {"routes.js": source})
    observation = _excerpt(executor, "routes.js", 1, 3)

    assert policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/router-status?mode=",
        },
        observation=observation,
    )


@pytest.mark.parametrize("suffix", ["jsx", "tsx"])
def test_jsx_expression_cannot_authorize_a_route(tmp_path: Path, suffix: str) -> None:
    source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'const node = <Widget value={app.get("/JSX_LEAK", handler)} />;\n'
    )
    path = f"component.{suffix}"
    _captured, policy, executor = _context(tmp_path, {path: source})
    observation = _excerpt(executor, path, 1, 3)

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/JSX_LEAK"},
        observation=observation,
    )


def test_javascript_dead_branch_query_does_not_attach_to_pathname_route(
    tmp_path: Path,
) -> None:
    source = (
        'const http = require("node:http");\n'
        "http.createServer((req, res) => {\n"
        '  const url = new URL(req.url, "http://localhost");\n'
        '  if (req.method === "GET" && url.pathname === "/safe") {\n'
        '    if (false) { request.query.get("DEAD_JS_QUERY_LEAK"); }\n'
        "  }\n"
        "});\n"
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, 7)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/safe?DEAD_JS_QUERY_LEAK=",
        },
        observation=observation,
    )


@pytest.mark.parametrize(
    ("case", "source", "path"),
    [
        (
            "false operand",
            'const express=require("express");\nconst app=express();\n'
            'false && app.get("/dead", handler);\n',
            "/dead",
        ),
        (
            "arrow expression",
            'const express=require("express");\nconst app=express();\n'
            'const deferred=()=>app.get("/deferred", handler);\n',
            "/deferred",
        ),
        (
            "ternary operand",
            'const express=require("express");\nconst app=express();\n'
            'enabled ? app.get("/conditional", handler) : noop();\n',
            "/conditional",
        ),
        (
            "one argument getter",
            'const express=require("express");\nconst app=express();\n'
            'app.get("/getter",);\n',
            "/getter",
        ),
        (
            "unmatched call",
            'const express=require("express");\nconst app=express();\n'
            'app.get("/broken", handler;\n',
            "/broken",
        ),
        (
            "malformed declaration invalidates file",
            'const express=require("express");\nconst app=express();\n'
            'app.get("/valid-looking",handler);\nconst = ;\n',
            "/valid-looking",
        ),
        (
            "empty declaration initializer invalidates file",
            'const express=require("express");\nconst app=express();\n'
            'app.get("/valid-looking-empty",handler);\nconst broken=;\n',
            "/valid-looking-empty",
        ),
        (
            "malformed call invalidates file",
            'const express=require("express");\nconst app=express();\n'
            'app.get("/valid-looking-call",handler);\nmetadata(,value);\n',
            "/valid-looking-call",
        ),
        (
            "mutated receiver method",
            'const express=require("express");\nconst app=express();\n'
            'app.get=metadataLookup;\napp.get("/mutated", handler);\n',
            "/mutated",
        ),
        (
            "receiver method replaced through Object.assign",
            'const express=require("express");\nconst app=express();\n'
            'Object.assign(app,{get:fake});\napp.get("/object-mutated", handler);\n',
            "/object-mutated",
        ),
        (
            "computed receiver method mutation",
            'const express=require("express");\nconst app=express();\n'
            'app["get"]=fake;\napp.get("/computed-mutated", handler);\n',
            "/computed-mutated",
        ),
        (
            "receiver method replaced through Reflect.set",
            'const express=require("express");\nconst app=express();\n'
            'Reflect.set(app,"get",fake);\napp.get("/reflect-mutated", handler);\n',
            "/reflect-mutated",
        ),
        (
            "receiver method replaced through Object.defineProperty",
            'const express=require("express");\nconst app=express();\n'
            'Object.defineProperty(app,"get",{value:fake});\n'
            'app.get("/defined-mutated", handler);\n',
            "/defined-mutated",
        ),
        (
            "receiver escapes through a local alias",
            'const express=require("express");\nconst app=express();\nconst alias=app;\n'
            'alias.get=fake;\napp.get("/alias-mutated", handler);\n',
            "/alias-mutated",
        ),
        (
            "mutated factory method",
            'const express=require("express");\nexpress.Router=metadataFactory;\n'
            'const router=express.Router();\nrouter.get("/mutated-factory", handler);\n',
            "/mutated-factory",
        ),
        (
            "shadowed require binding",
            'const require=metadataLookup;\nconst express=require("express");\n'
            'const app=express();\napp.get("/shadowed-require", handler);\n',
            "/shadowed-require",
        ),
        (
            "shadowed require function",
            'function require(name){return metadataLookup;}\n'
            'const express=require("express");\nconst app=express();\n'
            'app.get("/function-require", handler);\n',
            "/function-require",
        ),
        (
            "route before receiver",
            'app.get("/before", handler);\nconst express=require("express");\n'
            "const app=express();\n",
            "/before",
        ),
        (
            "if zero single statement",
            'const express=require("express");\nconst app=express();\nif(0)\n'
            'app.get("/if-zero",handler);\n',
            "/if-zero",
        ),
        (
            "while false single statement",
            'const express=require("express");\nconst app=express();\nwhile(false)\n'
            'app.get("/while-false",handler);\n',
            "/while-false",
        ),
        (
            "while zero single statement",
            'const express=require("express");\nconst app=express();\nwhile(0)\n'
            'app.get("/while-zero",handler);\n',
            "/while-zero",
        ),
        (
            "for false single statement",
            'const express=require("express");\nconst app=express();\nfor(;false;)\n'
            'app.get("/for-false",handler);\n',
            "/for-false",
        ),
        (
            "shadowed path constant",
            'const express=require("express");\nconst app=express();\n'
            'const ROUTE="/real";\nfunction metadata(){const ROUTE="/decoy";}\n'
            "app.get(ROUTE, handler);\n",
            "/decoy",
        ),
        (
            "path constant after use",
            'const http=require("http");\nhttp.createServer((req,res)=>{\n'
            'if(req.method==="GET"&&url.pathname===ROUTE){}\n});\n'
            'const ROUTE="/after";\n',
            "/after",
        ),
        (
            "bare pathname",
            'if(req.method==="GET"&&url.pathname==="/bare"){}\n',
            "/bare",
        ),
        (
            "pathname outside callback",
            'const http=require("http");\nhttp.createServer((req,res)=>{});\n'
            'if(req.method==="GET"&&url.pathname==="/outside"){}\n',
            "/outside",
        ),
        (
            "hashbang comment",
            '#! app.get("/hashbang", handler)\nconst express=require("express");\n'
            "const app=express();\n",
            "/hashbang",
        ),
        (
            "html open comment",
            'const express=require("express");\nconst app=express();\n'
            '<!-- metadata && app.get("/html-comment", handler);\n',
            "/html-comment",
        ),
        (
            "inline html open comment",
            'const express=require("express"); const app=express(); '
            '<!-- ; app.get("/inline-html", handler);\n',
            "/inline-html",
        ),
        (
            "entirely regex literal",
            'const pattern=/[;const express=require("express");const app=express();'
            'app.get("/all-regex",handler);]/;\n',
            "/all-regex",
        ),
        (
            "route-shaped regex literal",
            'const express=require("express");\nconst app=express();\n'
            'const pattern=/[;app.get("/regex-decoy",handler);]/;\n',
            "/regex-decoy",
        ),
        (
            "regex after typeof",
            'typeof /[;const express=require("express");const app=express();'
            'app.get("/regex-typeof",handler);]/;\n',
            "/regex-typeof",
        ),
        (
            "regex after void",
            'void /[;const express=require("express");const app=express();'
            'app.get("/regex-void",handler);]/;\n',
            "/regex-void",
        ),
        (
            "regex after unary plus",
            '+/[;const express=require("express");const app=express();'
            'app.get("/regex-plus",handler);]/;\n',
            "/regex-plus",
        ),
        (
            "regex statement after control condition",
            'if(true) /[;const express=require("express");const app=express();'
            'app.get("/regex-after-if",handler);]/;\n',
            "/regex-after-if",
        ),
        (
            "regex statement after block",
            'if(true){} /[;const express=require("express");const app=express();'
            'app.get("/regex-after-block",handler);]/;\n',
            "/regex-after-block",
        ),
        (
            "division cannot hide direct member mutation",
            'const express=require("express");\nconst app=express();\n'
            'const ignored=1/(app.get=fake)/2;\napp.get("/division-dot",handler);\n',
            "/division-dot",
        ),
        (
            "division cannot hide Object.assign mutation",
            'const express=require("express");\nconst app=express();\n'
            'const ignored=1/Object.assign(app,{get:fake})/2;\n'
            'app.get("/division-object",handler);\n',
            "/division-object",
        ),
        (
            "nested template interpolation",
            'const doc=`${` ;const express=require("express");const app=express();'
            'app.get("/nested-template",handler); `}`;\n',
            "/nested-template",
        ),
        (
            "createServer options metadata callback",
            'const http=require("node:http");\n'
            'http.createServer({metadata:function(req){const url={pathname:'
            '"/node-options-decoy"};if(req.method==="GET"&&url.pathname==='
            '"/node-options-decoy"){} }},realHandler);\n',
            "/node-options-decoy",
        ),
        (
            "html close comment",
            'const express=require("express");\nconst app=express();\n'
            '--> app.get("/html-close", handler);\n',
            "/html-close",
        ),
        (
            "mounted router without composed path",
            'const express=require("express");\nconst app=express();\n'
            'const router=express.Router();\napp.use("/api",router);\n'
            'router.get("/health", handler);\n',
            "/health",
        ),
    ],
)
def test_adversarial_javascript_shapes_do_not_authorize(
    tmp_path: Path,
    case: str,
    source: str,
    path: str,
) -> None:
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, len(source.splitlines()))

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": path},
        observation=observation,
    ), case


def test_javascript_nested_and_dead_queries_stay_out_of_handler_fact(
    tmp_path: Path,
) -> None:
    source = (
        'const express=require("express");\n'
        "const app=express();\n"
        'app.get("/safe",(req,res)=>{\n'
        '  function metadata(){req.query.get("NESTED_LEAK");}\n'
        "  const expressionMetadata=()=>req.query.NESTED_EXPR;\n"
        "  const holder={metadata(){req.query.NESTED_METHOD;}};\n"
        "  false && req.query.DEAD_LEAK;\n"
        "});\n"
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, 8)

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/safe"},
        observation=observation,
    )
    for query in ("DEAD_LEAK", "NESTED_EXPR", "NESTED_LEAK", "NESTED_METHOD"):
        assert not policy.permits_http_action(
            {"action": "http_request", "method": "GET", "path": f"/safe?{query}="},
            observation=observation,
        )


def test_escaped_newline_keeps_physical_route_coordinates(tmp_path: Path) -> None:
    source = (
        'const note="continued\\\nline";\n'
        'const express=require("express");\n'
        "const app=express();\n"
        'app.get("/physical-line", handler);\n'
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    omitted_route = _excerpt(executor, "server.js", 1, 4)
    full = _excerpt(executor, "server.js", 1, 5)
    action = {"action": "http_request", "method": "GET", "path": "/physical-line"}

    assert policy.route_count == 1
    assert not policy.permits_http_action(action, observation=omitted_route)
    assert policy.permits_http_action(action, observation=full)


@pytest.mark.parametrize(
    ("case", "source", "path"),
    [
        (
            "shadowed constructor import",
            "from flask import Flask\nfrom metadata import Flask\n"
            "app=Flask(__name__)\n@app.get('/shadowed')\ndef route(): return 'x'\n",
            "/shadowed",
        ),
        (
            "duplicate constructor import",
            "from flask import Flask\nfrom flask import Flask\n"
            "app=Flask(__name__)\n@app.get('/duplicate')\ndef route(): return 'x'\n",
            "/duplicate",
        ),
        (
            "nested constructor import shadow",
            "from flask import Flask\nif True:\n from metadata import Factory as Flask\n"
            "app=Flask(__name__)\n@app.get('/nested-shadow')\n"
            "def route(): return 'x'\n",
            "/nested-shadow",
        ),
        (
            "route before constructor",
            "@app.get('/before')\ndef route(): return 'x'\n"
            "from flask import Flask\napp=Flask(__name__)\n",
            "/before",
        ),
        (
            "assigned receiver method",
            "from flask import Flask\napp=Flask(__name__)\napp.get=lambda path: None\n"
            "@app.get('/mutated')\ndef route(): return 'x'\n",
            "/mutated",
        ),
        (
            "setattr receiver method",
            "from flask import Flask\napp=Flask(__name__)\nsetattr(app,'get',fake)\n"
            "@app.get('/setattr-mutated')\ndef route(): return 'x'\n",
            "/setattr-mutated",
        ),
        (
            "deleted receiver method",
            "from flask import Flask\napp=Flask(__name__)\ndel app.get\n"
            "@app.get('/deleted')\ndef route(): return 'x'\n",
            "/deleted",
        ),
        (
            "qualified constructor mutation",
            "import flask\nflask.Flask=metadataFactory\napp=flask.Flask(__name__)\n"
            "@app.get('/constructor-mutated')\ndef route(): return 'x'\n",
            "/constructor-mutated",
        ),
        (
            "setattr qualified constructor mutation",
            "import flask\nsetattr(flask,'Flask',fake)\napp=flask.Flask(__name__)\n"
            "@app.get('/setattr-constructor')\ndef route(): return 'x'\n",
            "/setattr-constructor",
        ),
        (
            "route in literal dead branch",
            "from flask import Flask\napp=Flask(__name__)\nif 0:\n"
            " @app.get('/dead')\n def route(): return 'x'\n",
            "/dead",
        ),
        (
            "route in false-and branch",
            "from flask import Flask\napp=Flask(__name__)\nif False and metadata:\n"
            " @app.get('/false-and')\n def route(): return 'x'\n",
            "/false-and",
        ),
        (
            "route in false comparison branch",
            "from flask import Flask\napp=Flask(__name__)\nif 1 == 0:\n"
            " @app.get('/false-comparison')\n def route(): return 'x'\n",
            "/false-comparison",
        ),
        (
            "route in type-checking branch",
            "from typing import TYPE_CHECKING\nfrom flask import Flask\n"
            "app=Flask(__name__)\nif TYPE_CHECKING:\n"
            " @app.get('/type-checking')\n def route(): return 'x'\n",
            "/type-checking",
        ),
    ],
)
def test_adversarial_python_shapes_do_not_authorize(
    tmp_path: Path,
    case: str,
    source: str,
    path: str,
) -> None:
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    observation = _excerpt(executor, "app.py", 1, len(source.splitlines()))

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": path},
        observation=observation,
    ), case


@pytest.mark.parametrize(
    ("source", "suffix", "path"),
    [
        (
            'const express=require("express")\nconst web=express()\n'
            'web.get("/semicolonless", handler)\n',
            "js",
            "/semicolonless",
        ),
        (
            'const express=require("express");\nconst app=express();\n'
            'do\napp.get("/do-once",handler);\nwhile(false);\n',
            "js",
            "/do-once",
        ),
        (
            'const express=require("express");\nconst app=express();\n'
            'for (const signal of ["SIGINT", "SIGTERM"]) { consume(signal); }\n'
            'app.get("/after-for-of",handler);\n',
            "js",
            "/after-for-of",
        ),
        (
            'import expressAlias from "express";\nconst custom=expressAlias();\n'
            'custom.get("/alias", handler);\n',
            "js",
            "/alias",
        ),
        (
            'import express from "express";\nconst app: Express=express();\n'
            'app.get("/typed", handler);\n',
            "ts",
            "/typed",
        ),
        (
            'import express from "express";\nconst app=express();\n'
            'app.get("/module-ts", handler);\n',
            "mts",
            "/module-ts",
        ),
        (
            'const express=require("express");\nconst app=express();\n'
            'app.get("/common-ts", handler);\n',
            "cts",
            "/common-ts",
        ),
    ],
)
def test_safe_javascript_constructor_forms_authorize(
    tmp_path: Path,
    source: str,
    suffix: str,
    path: str,
) -> None:
    filename = f"routes.{suffix}"
    _captured, policy, executor = _context(tmp_path, {filename: source})
    observation = _excerpt(executor, filename, 1, len(source.splitlines()))

    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": path},
        observation=observation,
    )


@pytest.mark.parametrize(
    ("constructor", "prefix_keyword"),
    [("APIRouter", "prefix"), ("Blueprint", "url_prefix")],
)
def test_unmounted_python_router_prefix_does_not_grant_live_route_authority(
    tmp_path: Path,
    constructor: str,
    prefix_keyword: str,
) -> None:
    module = "fastapi" if constructor == "APIRouter" else "flask"
    arguments = (
        f'{prefix_keyword}="/api"'
        if constructor == "APIRouter"
        else f'"api", __name__, {prefix_keyword}="/api"'
    )
    source = (
        f"from {module} import {constructor}\n"
        f"router={constructor}({arguments})\n"
        '@router.get("/health")\n'
        "def route(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"routes.py": source})
    observation = _excerpt(executor, "routes.py", 1, 4)

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/health"},
        observation=observation,
    )
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/api/health"},
        observation=observation,
    )


def test_fastapi_mounted_router_authorizes_only_the_composed_route(
    tmp_path: Path,
) -> None:
    source = (
        "from fastapi import APIRouter, FastAPI\n"
        "app=FastAPI()\n"
        "router=APIRouter()\n"
        '@router.get("/health")\n'
        "def health(): return {'ok': True}\n"
        'app.include_router(router,prefix="/api")\n'
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    observation = _excerpt(executor, "app.py", 1, 6)

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/health"},
        observation=observation,
    )
    assert policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/api/health"},
        observation=observation,
    )


def test_python_nested_member_mutation_invalidates_receiver(tmp_path: Path) -> None:
    source = (
        "from flask import Flask\n"
        "app=Flask(__name__)\n"
        "def replace_route_method():\n"
        "    app.get=fake\n"
        "replace_route_method()\n"
        '@app.get("/mutated")\n'
        "def route(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    observation = _excerpt(executor, "app.py", 1, 7)

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/mutated"},
        observation=observation,
    )


def test_python_route_decorator_rejects_extra_positional_argument(tmp_path: Path) -> None:
    source = (
        "from flask import Flask\n"
        "app=Flask(__name__)\n"
        '@app.get("/invalid", unexpected)\n'
        "def route(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    observation = _excerpt(executor, "app.py", 1, 4)

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/invalid"},
        observation=observation,
    )


def test_javascript_false_constant_control_does_not_register_route(tmp_path: Path) -> None:
    source = (
        'const express=require("express");\n'
        "const app=express();\n"
        "const enabled=false;\n"
        "if(enabled)\n"
        'app.get("/disabled",handler);\n'
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, 5)

    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/disabled"},
        observation=observation,
    )


def test_javascript_excessive_nesting_fails_file_closed(tmp_path: Path) -> None:
    nesting = 33
    source = (
        'const express=require("express");\n'
        "const app=express();\n"
        f"const marker={'(' * nesting}true{')' * nesting};\n"
        'app.get("/too-deep",handler);\n'
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, 4)

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/too-deep"},
        observation=observation,
    )


@pytest.mark.parametrize("throw_statement", ["throw;", "throw\nmetadata;"])
def test_javascript_invalid_throw_fails_file_closed(
    tmp_path: Path,
    throw_statement: str,
) -> None:
    source = (
        'const express=require("express");\n'
        "const app=express();\n"
        f"{throw_statement}\n"
        'app.get("/after-invalid-throw",handler);\n'
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, len(source.splitlines()))

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/after-invalid-throw",
        },
        observation=observation,
    )


def test_javascript_top_level_throw_fails_file_closed(tmp_path: Path) -> None:
    source = (
        'const express=require("express");\n'
        "const app=express();\n"
        'throw new Error("stop");\n'
        'app.get("/after-throw",handler);\n'
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, len(source.splitlines()))

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {"action": "http_request", "method": "GET", "path": "/after-throw"},
        observation=observation,
    )


@pytest.mark.parametrize(
    "constructor",
    ["express(unknown)", 'require("express")(unknown)'],
)
def test_javascript_constructor_arguments_fail_closed(
    tmp_path: Path,
    constructor: str,
) -> None:
    source = (
        'const express=require("express");\n'
        f"const app={constructor};\n"
        'app.get("/constructor-argument",handler);\n'
    )
    _captured, policy, executor = _context(tmp_path, {"server.js": source})
    observation = _excerpt(executor, "server.js", 1, len(source.splitlines()))

    assert policy.route_count == 0
    assert not policy.permits_http_action(
        {
            "action": "http_request",
            "method": "GET",
            "path": "/constructor-argument",
        },
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
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                '@app.get("/hidden")\n'
                "def hidden():\n"
                '    return request.args.get("term")\n'
            )
        },
    )
    observation = _excerpt(executor, "app.py", 1, 5)

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
