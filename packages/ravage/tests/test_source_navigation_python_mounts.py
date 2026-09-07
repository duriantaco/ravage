from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.source_context import SourceContextExecutor
from ravage.agent_core.source_navigation import (
    SourceNavigationEvidence,
    SourceNavigationPolicy,
    build_source_navigation_policy,
)
from ravage.repository_context import ContextLimits, RepositoryContext, capture_repository

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class _MountCase:
    child_source: str
    parent_source: str
    dynamic_mount: str


_FASTAPI = _MountCase(
    child_source=(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/health")\n'
        "def health():\n"
        '    return request.query_params.get("debug")\n'
    ),
    parent_source=(
        "from fastapi import FastAPI\n"
        "from .routes import router\n"
        "app = FastAPI()\n"
        'app.include_router(router, prefix="/api")\n'
    ),
    dynamic_mount="app.include_router(router, prefix=route_prefix())",
)

_FLASK = _MountCase(
    child_source=(
        "from flask import Blueprint, request\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        '    return request.args.get("debug")\n'
    ),
    parent_source=(
        "from flask import Flask\n"
        "from .routes import blueprint\n"
        "app = Flask(__name__)\n"
        'app.register_blueprint(blueprint, url_prefix="/api")\n'
    ),
    dynamic_mount=("app.register_blueprint(blueprint, url_prefix=route_prefix())"),
)


def _context(
    tmp_path: Path, files: Mapping[str, str]
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
    result = executor.execute(
        {
            "action": "source_context",
            "operation": "excerpt",
            "args": {"path": path, "start_line": start_line, "end_line": end_line},
        }
    )
    assert result.ok
    return result.observation


def _full_excerpt(executor: SourceContextExecutor, path: str, source: str) -> dict[str, object]:
    return _excerpt(executor, path, 1, len(source.splitlines()))


def _evidence(
    policy: SourceNavigationPolicy,
    observations: Sequence[Mapping[str, object]],
) -> SourceNavigationEvidence:
    evidence = policy.begin_evidence()
    for observation in observations:
        assert evidence.observe(observation)
    return evidence


def _request(path: str, *, method: str = "GET") -> dict[str, object]:
    return {"action": "http_request", "method": method, "path": path}


def _mounted_evidence(
    tmp_path: Path,
    case: _MountCase,
    *,
    child_source: str | None = None,
    parent_source: str | None = None,
    extra_sources: Mapping[str, str] | None = None,
) -> SourceNavigationEvidence:
    child = child_source or case.child_source
    parent = parent_source or case.parent_source
    sources = {
        "service/__init__.py": "",
        "service/routes.py": child,
        "service/main.py": parent,
        **(extra_sources or {}),
    }
    _captured, policy, executor = _context(tmp_path, sources)
    return _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", child),
            _full_excerpt(executor, "service/main.py", parent),
        ),
    )


@pytest.mark.parametrize("case", [_FASTAPI, _FLASK], ids=["fastapi", "flask"])
def test_cross_file_python_mount_requires_both_files_and_composes_prefix(
    tmp_path: Path,
    case: _MountCase,
) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": case.child_source,
            "service/main.py": case.parent_source,
        },
    )
    child = _full_excerpt(executor, "service/routes.py", case.child_source)
    parent = _full_excerpt(executor, "service/main.py", case.parent_source)

    for lone_observation in (child, parent):
        evidence = _evidence(policy, (lone_observation,))
        assert evidence.authorized_http_routes() == ()
        assert not evidence.permits_http_action(_request("/health"))
        assert not evidence.permits_http_action(_request("/api/health"))

    for observations in ((child, parent), (parent, child)):
        evidence = _evidence(policy, observations)
        assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
        assert evidence.permits_http_action(_request("/api/health"))
        assert not evidence.permits_http_action(_request("/health"))


@pytest.mark.parametrize("case", [_FASTAPI, _FLASK], ids=["fastapi", "flask"])
def test_cross_file_python_mount_requires_the_mount_statement_line(
    tmp_path: Path,
    case: _MountCase,
) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": case.child_source,
            "service/main.py": case.parent_source,
        },
    )
    child = _full_excerpt(executor, "service/routes.py", case.child_source)
    parent_without_mount = _excerpt(executor, "service/main.py", 1, 3)
    evidence = _evidence(policy, (child, parent_without_mount))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/api/health"))
    assert not evidence.permits_http_action(_request("/health"))


def test_cross_file_flask_mount_requires_the_child_query_line(
    tmp_path: Path,
) -> None:
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": _FLASK.child_source,
            "service/main.py": _FLASK.parent_source,
        },
    )
    child_route = _excerpt(executor, "service/routes.py", 1, 4)
    child_query = _excerpt(executor, "service/routes.py", 5, 5)
    parent = _full_excerpt(executor, "service/main.py", _FLASK.parent_source)
    evidence = _evidence(policy, (parent, child_route))

    assert evidence.permits_http_action(_request("/api/health"))
    assert not evidence.permits_http_action(_request("/api/health?debug="))

    assert evidence.observe(child_query)
    assert evidence.permits_http_action(_request("/api/health?debug="))
    assert not evidence.permits_http_action(_request("/health?debug="))


@pytest.mark.parametrize("case", [_FASTAPI, _FLASK], ids=["fastapi", "flask"])
def test_cross_file_python_mount_rejects_dynamic_prefix(
    tmp_path: Path,
    case: _MountCase,
) -> None:
    parent_lines = case.parent_source.splitlines()
    parent_source = (
        "\n".join((*parent_lines[:-1], 'def route_prefix(): return "/api"', case.dynamic_mount))
        + "\n"
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": case.child_source,
            "service/main.py": parent_source,
        },
    )
    child = _full_excerpt(executor, "service/routes.py", case.child_source)
    parent = _full_excerpt(executor, "service/main.py", parent_source)
    evidence = _evidence(policy, (child, parent))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/api/health"))
    assert not evidence.permits_http_action(_request("/health"))


def test_cross_file_fastapi_reexport_does_not_convey_mount_authority(
    tmp_path: Path,
) -> None:
    parent_source = (
        "from fastapi import FastAPI\n"
        "from .public import router\n"
        "app = FastAPI()\n"
        'app.include_router(router, prefix="/api")\n'
    )
    reexport_source = "from .routes import router\n"
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": _FASTAPI.child_source,
            "service/public.py": reexport_source,
            "service/main.py": parent_source,
        },
    )
    observations = (
        _full_excerpt(executor, "service/routes.py", _FASTAPI.child_source),
        _full_excerpt(executor, "service/public.py", reexport_source),
        _full_excerpt(executor, "service/main.py", parent_source),
    )
    evidence = _evidence(policy, observations)

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/api/health"))
    assert not evidence.permits_http_action(_request("/health"))


def test_cross_file_fastapi_duplicate_import_binding_fails_closed(
    tmp_path: Path,
) -> None:
    other_source = (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/status")\n'
        "def status(): return {'ok': True}\n"
    )
    parent_source = (
        "from fastapi import FastAPI\n"
        "from .routes import router\n"
        "from .other_routes import router\n"
        "app = FastAPI()\n"
        'app.include_router(router, prefix="/api")\n'
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": _FASTAPI.child_source,
            "service/other_routes.py": other_source,
            "service/main.py": parent_source,
        },
    )
    observations = (
        _full_excerpt(executor, "service/routes.py", _FASTAPI.child_source),
        _full_excerpt(executor, "service/other_routes.py", other_source),
        _full_excerpt(executor, "service/main.py", parent_source),
    )
    evidence = _evidence(policy, observations)

    assert evidence.authorized_http_routes() == ()
    for path in ("/health", "/status", "/api/health", "/api/status"):
        assert not evidence.permits_http_action(_request(path))


def test_cross_file_flask_registration_prefix_overrides_blueprint_prefix(
    tmp_path: Path,
) -> None:
    child_source = _FLASK.child_source.replace(
        'Blueprint("health", __name__)',
        'Blueprint("health", __name__, url_prefix="/local")',
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": child_source,
            "service/main.py": _FLASK.parent_source,
        },
    )
    child = _full_excerpt(executor, "service/routes.py", child_source)
    parent = _full_excerpt(executor, "service/main.py", _FLASK.parent_source)
    evidence = _evidence(policy, (child, parent))

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert evidence.permits_http_action(_request("/api/health"))
    assert not evidence.permits_http_action(_request("/local/health"))
    assert not evidence.permits_http_action(_request("/health"))


@pytest.mark.parametrize(
    ("missing_file", "missing_line"),
    [
        ("service/routes.py", 1),
        ("service/routes.py", 2),
        ("service/routes.py", 3),
        ("service/routes.py", 4),
        ("service/main.py", 1),
        ("service/main.py", 2),
        ("service/main.py", 3),
        ("service/main.py", 4),
    ],
)
def test_cross_file_fastapi_mount_requires_every_structural_line(
    tmp_path: Path,
    missing_file: str,
    missing_line: int,
) -> None:
    sources = {
        "service/__init__.py": "",
        "service/routes.py": _FASTAPI.child_source,
        "service/main.py": _FASTAPI.parent_source,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    observations = [
        _excerpt(executor, path, line, line)
        for path, required_lines in (
            ("service/routes.py", (1, 2, 3, 4)),
            ("service/main.py", (1, 2, 3, 4)),
        )
        for line in required_lines
        if (path, line) != (missing_file, missing_line)
    ]
    evidence = _evidence(policy, observations)

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/api/health"))


def test_same_file_fastapi_mount_requires_route_registration_order(
    tmp_path: Path,
) -> None:
    mounted_after_route = (
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        '@router.get("/health")\n'
        "def health(): return {'ok': True}\n"
        'app.include_router(router, prefix="/api")\n'
    )
    mounted_before_route = (
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        'app.include_router(router, prefix="/api")\n'
        '@router.get("/health")\n'
        "def health(): return {'ok': True}\n"
    )
    for directory, source, expected in (
        ("after", mounted_after_route, True),
        ("before", mounted_before_route, False),
    ):
        _captured, policy, executor = _context(
            tmp_path / directory,
            {"app.py": source},
        )
        evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))
        assert evidence.permits_http_action(_request("/api/health")) is expected
        assert not evidence.permits_http_action(_request("/health"))


def test_fastapi_mount_composes_router_and_registration_prefixes(tmp_path: Path) -> None:
    child_source = _FASTAPI.child_source.replace(
        "APIRouter()",
        'APIRouter(prefix="/v1")',
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": child_source,
            "service/main.py": _FASTAPI.parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", child_source),
            _full_excerpt(executor, "service/main.py", _FASTAPI.parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == (("GET", "/api/v1/health"),)
    assert evidence.permits_http_action(_request("/api/v1/health"))
    assert not evidence.permits_http_action(_request("/api/health"))
    assert not evidence.permits_http_action(_request("/v1/health"))


def test_flask_mount_without_override_retains_blueprint_prefix(tmp_path: Path) -> None:
    child_source = _FLASK.child_source.replace(
        'Blueprint("health", __name__)',
        'Blueprint("health", __name__, url_prefix="/local")',
    )
    parent_source = _FLASK.parent_source.replace(
        'app.register_blueprint(blueprint, url_prefix="/api")',
        "app.register_blueprint(blueprint)",
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/main.py", parent_source),
            _full_excerpt(executor, "service/routes.py", child_source),
        ),
    )

    assert evidence.authorized_http_routes() == (("GET", "/local/health"),)
    assert evidence.permits_http_action(_request("/local/health"))
    assert not evidence.permits_http_action(_request("/health"))


@pytest.mark.parametrize("framework", ["fastapi", "flask"])
def test_aliased_import_and_keyword_mount_child_are_composed(
    tmp_path: Path,
    framework: str,
) -> None:
    case = _FASTAPI if framework == "fastapi" else _FLASK
    symbol = "router" if framework == "fastapi" else "blueprint"
    alias = "mounted_routes"
    child_keyword = symbol
    parent_source = case.parent_source.replace(
        f"from .routes import {symbol}",
        f"from .routes import {symbol} as {alias}",
    ).replace(
        f"({symbol},",
        f"({child_keyword}={alias},",
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": case.child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", case.child_source),
            _full_excerpt(executor, "service/main.py", parent_source),
        ),
    )

    assert evidence.permits_http_action(_request("/api/health"))
    assert not evidence.permits_http_action(_request("/health"))


def test_nested_fastapi_mount_chain_requires_all_three_modules(tmp_path: Path) -> None:
    leaf_source = (
        "from fastapi import APIRouter\n"
        'leaf = APIRouter(prefix="/leaf")\n'
        '@leaf.get("/health")\n'
        "def health(): return {'ok': True}\n"
    )
    middle_source = (
        "from fastapi import APIRouter\n"
        "from .leaf import leaf\n"
        'middle = APIRouter(prefix="/middle")\n'
        'middle.include_router(leaf, prefix="/nested")\n'
    )
    root_source = (
        "from fastapi import FastAPI\n"
        "from .middle import middle\n"
        "app = FastAPI()\n"
        'app.include_router(middle, prefix="/api")\n'
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/leaf.py": leaf_source,
            "service/middle.py": middle_source,
            "service/main.py": root_source,
        },
    )
    leaf = _full_excerpt(executor, "service/leaf.py", leaf_source)
    middle = _full_excerpt(executor, "service/middle.py", middle_source)
    root = _full_excerpt(executor, "service/main.py", root_source)

    incomplete = _evidence(policy, (leaf, root))
    assert incomplete.authorized_http_routes() == ()

    complete = _evidence(policy, (root, leaf, middle))
    path = "/api/middle/nested/leaf/health"
    assert complete.authorized_http_routes() == (("GET", path),)
    assert complete.permits_http_action(_request(path))
    assert not complete.permits_http_action(_request("/health"))


@pytest.mark.parametrize(
    "mutation",
    [
        "FastAPI.include_router = lambda *args, **kwargs: None\n",
        "alias = app\nalias.include_router = lambda *args, **kwargs: None\n",
        "alias = router\nalias.get = lambda *args, **kwargs: None\n",
    ],
    ids=["constructor-class", "application-alias", "imported-router-alias"],
)
def test_fastapi_mount_method_mutation_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    parent_lines = _FASTAPI.parent_source.splitlines()
    insertion = 2 if mutation.startswith("FastAPI") else 3
    parent_lines[insertion:insertion] = mutation.rstrip().splitlines()
    parent_source = "\n".join(parent_lines) + "\n"
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": _FASTAPI.child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", _FASTAPI.child_source),
            _full_excerpt(executor, "service/main.py", parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/api/health"))


def test_flask_explicit_empty_registration_prefix_overrides_blueprint_prefix(
    tmp_path: Path,
) -> None:
    child_source = _FLASK.child_source.replace(
        'Blueprint("health", __name__)',
        'Blueprint("health", __name__, url_prefix="/local")',
    )
    parent_source = _FLASK.parent_source.replace('url_prefix="/api"', 'url_prefix=""')
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", child_source),
            _full_excerpt(executor, "service/main.py", parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == (("GET", "/health"),)
    assert evidence.permits_http_action(_request("/health"))
    assert not evidence.permits_http_action(_request("/local/health"))


def test_fastapi_unknown_root_prefix_fails_closed(
    tmp_path: Path,
) -> None:
    parent_source = _FASTAPI.parent_source.replace(
        "FastAPI()",
        'FastAPI(url_prefix="/fake")',
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": _FASTAPI.child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", _FASTAPI.child_source),
            _full_excerpt(executor, "service/main.py", parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/fake/api/health"))


def test_fastapi_root_static_metadata_keeps_mounted_route(tmp_path: Path) -> None:
    parent_source = _FASTAPI.parent_source.replace(
        "FastAPI()",
        'FastAPI(title="Service", docs_url="/documentation", debug=True)',
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, parent_source=parent_source)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)


def test_fastapi_mount_with_unknown_keyword_fails_closed(tmp_path: Path) -> None:
    parent_source = _FASTAPI.parent_source.replace(
        'prefix="/api")',
        'prefix="/api", nonsense=True)',
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": _FASTAPI.child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", _FASTAPI.child_source),
            _full_excerpt(executor, "service/main.py", parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    ("child_constructor", "mount_prefix"),
    [
        ("APIRouter()", "/api/"),
        ('APIRouter(prefix="/local/")', "/api"),
    ],
    ids=["registration-prefix", "router-prefix"],
)
def test_fastapi_trailing_slash_prefix_fails_closed(
    tmp_path: Path,
    child_constructor: str,
    mount_prefix: str,
) -> None:
    child_source = _FASTAPI.child_source.replace("APIRouter()", child_constructor)
    parent_source = _FASTAPI.parent_source.replace('prefix="/api"', f'prefix="{mount_prefix}"')
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", child_source),
            _full_excerpt(executor, "service/main.py", parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


def test_exception_target_rebinding_of_imported_router_fails_closed(
    tmp_path: Path,
) -> None:
    parent_source = _FASTAPI.parent_source.replace(
        "app = FastAPI()\n",
        ("app = FastAPI()\ntry:\n    pass\nexcept RuntimeError as router:\n    pass\n"),
    )
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": _FASTAPI.child_source,
            "service/main.py": parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", _FASTAPI.child_source),
            _full_excerpt(executor, "service/main.py", parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    ("case", "constructor"),
    [
        (_FASTAPI, 'APIRouter(**{"prefix": "/local"})'),
        (_FASTAPI, 'APIRouter("/local")'),
        (_FASTAPI, "APIRouter(prefix=None)"),
        (_FASTAPI, 'APIRouter(prefix="/one", prefix="/two")'),
        (_FLASK, 'Blueprint("health", __name__, **{"url_prefix": "/local"})'),
        (_FLASK, 'Blueprint("health", __name__, None, None, None, "/local")'),
        (_FLASK, 'Blueprint("bad.name", __name__)'),
        (_FLASK, 'Blueprint("health", None)'),
        (_FLASK, 'Blueprint("health", __name__, url_prefix="/one", url_prefix="/two")'),
    ],
    ids=[
        "fastapi-unpacked-keywords",
        "fastapi-positional-prefix",
        "fastapi-none-prefix",
        "fastapi-duplicate-prefix",
        "flask-unpacked-keywords",
        "flask-positional-prefix",
        "flask-dotted-name",
        "flask-none-import-name",
        "flask-duplicate-prefix",
    ],
)
def test_ambiguous_component_constructor_fails_closed(
    tmp_path: Path,
    case: _MountCase,
    constructor: str,
) -> None:
    original = "APIRouter()" if case is _FASTAPI else 'Blueprint("health", __name__)'
    child_source = case.child_source.replace(original, constructor)
    _captured, policy, executor = _context(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/routes.py": child_source,
            "service/main.py": case.parent_source,
        },
    )
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", child_source),
            _full_excerpt(executor, "service/main.py", case.parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize("operation", ["api_route", "head", "options"])
def test_flask_unsupported_route_decorator_fails_closed(
    tmp_path: Path,
    operation: str,
) -> None:
    child_source = _FLASK.child_source.replace("@blueprint.get", f"@blueprint.{operation}")
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child_source)

    assert evidence.authorized_http_routes() == ()


def test_route_under_unknown_module_condition_fails_closed(tmp_path: Path) -> None:
    child_source = (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "enabled = []\n"
        "if enabled:\n"
        '    @router.get("/health")\n'
        "    def health(): return {'ok': True}\n"
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, child_source=child_source)

    assert evidence.authorized_http_routes() == ()


def test_match_capture_rebinding_of_imported_router_fails_closed(tmp_path: Path) -> None:
    parent_source = (
        "from fastapi import APIRouter, FastAPI\n"
        "from .routes import router\n"
        "app = FastAPI()\n"
        "match APIRouter():\n"
        "    case router:\n"
        "        pass\n"
        'app.include_router(router, prefix="/api")\n'
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, parent_source=parent_source)

    assert evidence.authorized_http_routes() == ()


def test_nested_star_import_rebinding_fails_closed(tmp_path: Path) -> None:
    parent_source = (
        "from fastapi import FastAPI\n"
        "from .routes import router\n"
        "if True:\n"
        "    from .empty import *\n"
        "app = FastAPI()\n"
        'app.include_router(router, prefix="/api")\n'
    )
    empty_source = 'from fastapi import APIRouter\n__all__ = ["router"]\nrouter = APIRouter()\n'
    evidence = _mounted_evidence(
        tmp_path,
        _FASTAPI,
        parent_source=parent_source,
        extra_sources={"service/empty.py": empty_source},
    )

    assert evidence.authorized_http_routes() == ()


def test_relative_framework_import_spoof_fails_closed(tmp_path: Path) -> None:
    fake_framework = (
        "class APIRouter:\n"
        "    def get(self, _path): return lambda function: function\n"
        "class FastAPI:\n"
        "    def include_router(self, _router, **_kwargs): return None\n"
    )
    child_source = _FASTAPI.child_source.replace(
        "from fastapi import APIRouter",
        "from .fastapi import APIRouter",
    )
    parent_source = _FASTAPI.parent_source.replace(
        "from fastapi import FastAPI",
        "from .fastapi import FastAPI",
    )
    evidence = _mounted_evidence(
        tmp_path,
        _FASTAPI,
        child_source=child_source,
        parent_source=parent_source,
        extra_sources={"service/fastapi.py": fake_framework},
    )

    assert evidence.authorized_http_routes() == ()


def test_repository_framework_module_shadow_fails_closed(tmp_path: Path) -> None:
    evidence = _mounted_evidence(
        tmp_path,
        _FASTAPI,
        extra_sources={"fastapi.py": "class FastAPI: pass\nclass APIRouter: pass\n"},
    )

    assert evidence.authorized_http_routes() == ()


def test_shadowed_typing_import_fails_closed(tmp_path: Path) -> None:
    child_source = _FASTAPI.child_source.replace(
        "from fastapi import APIRouter\n",
        "from fastapi import APIRouter\nfrom typing import Optional\n",
    )
    evidence = _mounted_evidence(
        tmp_path,
        _FASTAPI,
        child_source=child_source,
        extra_sources={"typing.py": "raise RuntimeError('shadowed')\n"},
    )

    assert evidence.authorized_http_routes() == ()


def test_package_initializer_mutation_fails_closed(tmp_path: Path) -> None:
    initializer = "import fastapi\nfastapi.FastAPI.include_router = lambda *args, **kwargs: None\n"
    evidence = _mounted_evidence(
        tmp_path,
        _FASTAPI,
        extra_sources={"service/__init__.py": initializer},
    )

    assert evidence.authorized_http_routes() == ()


def test_route_rewriting_component_option_fails_closed(tmp_path: Path) -> None:
    child_source = (
        "from fastapi import APIRouter\n"
        "class Rewrite: pass\n"
        "router = APIRouter(route_class=Rewrite)\n"
        '@router.get("/health")\n'
        "def health(): return {'ok': True}\n"
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, child_source=child_source)

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    ("case", "mutation"),
    [
        (_FASTAPI, "router.routes.clear()\n"),
        (_FASTAPI, "router.routes[:] = []\n"),
        (
            _FASTAPI,
            "def disable(value): value.get = lambda path: (lambda function: function)\n"
            "disable(router)\n",
        ),
        (_FLASK, "blueprint.deferred_functions.clear()\n"),
        (_FLASK, 'blueprint.url_prefix = "/mutated"\n'),
        (
            _FLASK,
            "def disable(value): value.get = lambda path: (lambda function: function)\n"
            "disable(blueprint)\n",
        ),
        (
            _FLASK,
            "@blueprint.record\ndef rewrite(state): blueprint.url_prefix = '/mutated'\n",
        ),
    ],
    ids=[
        "fastapi-clear-routes",
        "fastapi-slice-routes",
        "fastapi-helper-escape",
        "flask-clear-deferred",
        "flask-prefix-mutation",
        "flask-helper-escape",
        "flask-record-hook",
    ],
)
def test_component_mutation_or_escape_fails_closed(
    tmp_path: Path,
    case: _MountCase,
    mutation: str,
) -> None:
    constructor_line = 2
    lines = case.child_source.splitlines()
    lines[constructor_line:constructor_line] = mutation.rstrip().splitlines()
    child_source = "\n".join(lines) + "\n"
    evidence = _mounted_evidence(tmp_path, case, child_source=child_source)

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "app.routes.clear()\n",
        "app.router.include_router = lambda *args, **kwargs: None\n",
    ],
    ids=["route-table-clear", "nested-mount-method"],
)
def test_fastapi_parent_mutation_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    parent_source = _FASTAPI.parent_source + mutation
    evidence = _mounted_evidence(tmp_path, _FASTAPI, parent_source=parent_source)

    assert evidence.authorized_http_routes() == ()


def test_module_qualified_mount_method_mutation_fails_closed(tmp_path: Path) -> None:
    parent_source = (
        "import fastapi\n"
        "from .routes import router\n"
        "app = fastapi.FastAPI()\n"
        "fastapi.FastAPI.include_router = lambda *args, **kwargs: None\n"
        'app.include_router(router, prefix="/api")\n'
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, parent_source=parent_source)

    assert evidence.authorized_http_routes() == ()


def test_flask_root_constructor_unknown_keyword_fails_closed(tmp_path: Path) -> None:
    parent_source = _FLASK.parent_source.replace(
        "Flask(__name__)",
        "Flask(__name__, nonsense=True)",
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, parent_source=parent_source)

    assert evidence.authorized_http_routes() == ()


def test_fastapi_root_invalid_documentation_path_fails_closed(tmp_path: Path) -> None:
    parent_source = _FASTAPI.parent_source.replace(
        "FastAPI()",
        'FastAPI(docs_url="relative")',
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, parent_source=parent_source)

    assert evidence.authorized_http_routes() == ()


def test_direct_application_receiver_escape_fails_closed(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def disable(value): value.get = lambda path: (lambda function: function)\n"
        "disable(app)\n"
        '@app.get("/health")\n'
        "def health(): return {'ok': True}\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    ("constructor_prefix", "registration_prefix", "expected"),
    [
        ("/local/", None, "/local/health"),
        ("/local/", "/api/", "/api/health"),
        ("/", None, "/health"),
        ("/local", "/", "/health"),
    ],
)
def test_flask_trailing_slash_prefixes_are_normalized(
    tmp_path: Path,
    constructor_prefix: str,
    registration_prefix: str | None,
    expected: str,
) -> None:
    child_source = _FLASK.child_source.replace(
        'Blueprint("health", __name__)',
        f'Blueprint("health", __name__, url_prefix="{constructor_prefix}")',
    )
    if registration_prefix is None:
        parent_source = _FLASK.parent_source.replace(
            'app.register_blueprint(blueprint, url_prefix="/api")',
            "app.register_blueprint(blueprint)",
        )
    else:
        parent_source = _FLASK.parent_source.replace(
            'url_prefix="/api"',
            f'url_prefix="{registration_prefix}"',
        )
    evidence = _mounted_evidence(
        tmp_path,
        _FLASK,
        child_source=child_source,
        parent_source=parent_source,
    )

    assert evidence.authorized_http_routes() == (("GET", expected),)
    assert evidence.permits_http_action(_request(expected))


@pytest.mark.parametrize(
    "source",
    [
        (
            "from fastapi import FastAPI\n"
            "from typing import Optional\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health(value: Optional[int, str]): return 'ok'\n"
        ),
        (
            "import fastapi\n"
            "app = fastapi.FastAPI()\n"
            '@app.get("/health")\n'
            "def health(value: fastapi.DefinitelyMissing): return 'ok'\n"
        ),
        (
            "from __future__ import annotations\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health(value: DefinitelyMissing): return 'ok'\n"
        ),
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health() -> None | None: return None\n"
        ),
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health() -> int | (None | None): return 1\n"
        ),
    ],
    ids=[
        "invalid-typing-arity",
        "unknown-framework-type",
        "unresolved-forward-reference",
        "none-union",
        "nested-none-union",
    ],
)
def test_import_time_handler_annotations_fail_closed(tmp_path: Path, source: str) -> None:
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize("helper_position", ["before", "after"])
def test_import_time_helper_annotation_failure_fails_module_closed(
    tmp_path: Path,
    helper_position: str,
) -> None:
    helper = "def helper(value: DefinitelyMissing): return value\n"
    route = '@app.get("/health")\ndef health(): return "ok"\n'
    statements = helper + route if helper_position == "before" else route + helper
    source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        f"{statements}"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "signature",
    [
        "def health(value: int = 1, /):",
        "def health(*values: int):",
        "def health(**values: int):",
        "def health(request: Request, /):",
    ],
    ids=["positional-only", "varargs", "kwargs", "positional-request"],
)
def test_fastapi_uninvokable_handler_signatures_fail_closed(
    tmp_path: Path,
    signature: str,
) -> None:
    source = (
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        '@app.get("/health")\n'
        f"{signature}\n"
        "    return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_flask_required_static_route_parameter_fails_closed(tmp_path: Path) -> None:
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__, static_folder=None)\n"
        '@app.get("/health")\n'
        "def health(value: int): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_flask_async_handler_without_dependency_provenance_fails_closed(
    tmp_path: Path,
) -> None:
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__, static_folder=None)\n"
        '@app.get("/health")\n'
        "async def health(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_fastapi_async_handler_remains_supported(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        '@app.get("/health")\n'
        "async def health(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == (("GET", "/health"),)


@pytest.mark.parametrize(
    ("signature", "body"),
    [
        ("def health() -> dict[str, bool]:", "    return {'ok': True}\n"),
        ("def health(limit: int | None = None) -> list[str]:", "    return []\n"),
        (
            "def health(limit: Optional[int] = None) -> Union[str, bytes]:",
            "    return 'ok'\n",
        ),
        ("def health(request: Request) -> tuple[str, ...]:", "    return ('ok',)\n"),
        (
            "def health(values: Sequence[str] = ()) -> Mapping[str, int]:",
            "    return {}\n",
        ),
    ],
    ids=["return-dict", "pep604", "typing-union", "request", "typing-containers"],
)
def test_common_fastapi_handler_annotations_are_supported(
    tmp_path: Path,
    signature: str,
    body: str,
) -> None:
    child = (
        "from fastapi import APIRouter, Request\n"
        "from typing import Mapping, Optional, Sequence, Union\n"
        "router = APIRouter()\n"
        '@router.get("/health")\n'
        f"{signature}\n"
        f"{body}"
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert evidence.permits_http_action(_request("/api/health"))


def test_fastapi_annotation_import_line_is_required_evidence(tmp_path: Path) -> None:
    child = (
        "from fastapi import APIRouter\n"
        "from fastapi import Request\n"
        "router = APIRouter()\n"
        '@router.get("/health")\n'
        "def health(request: Request) -> dict[str, bool]:\n"
        "    return {'ok': True}\n"
    )
    sources = {
        "service/__init__.py": "",
        "service/routes.py": child,
        "service/main.py": _FASTAPI.parent_source,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    observations = [
        _excerpt(executor, "service/routes.py", 1, 1),
        _excerpt(executor, "service/routes.py", 3, 6),
        _full_excerpt(executor, "service/main.py", _FASTAPI.parent_source),
    ]
    evidence = _evidence(policy, observations)

    assert evidence.authorized_http_routes() == ()
    assert evidence.observe(_excerpt(executor, "service/routes.py", 2, 2))
    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)


@pytest.mark.parametrize(
    "annotation",
    [
        "Request | None",
        "Optional[Request]",
        "list[Request]",
    ],
    ids=["request-union", "optional-request", "request-container"],
)
def test_composite_fastapi_request_annotations_fail_closed(
    tmp_path: Path,
    annotation: str,
) -> None:
    source = (
        "from fastapi import FastAPI, Request\n"
        "from typing import Optional\n"
        "app = FastAPI()\n"
        '@app.get("/health")\n'
        f"def health(request: {annotation}): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_annotation_import_after_handler_fails_closed(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/health")\n'
        "def health(value: Optional[int]): return 'ok'\n"
        "from typing import Optional\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_annotated_package_initializer_fails_closed(tmp_path: Path) -> None:
    evidence = _mounted_evidence(
        tmp_path,
        _FASTAPI,
        extra_sources={"service/__init__.py": "marker: int[str] = 1\n"},
    )

    assert evidence.authorized_http_routes() == ()


def test_component_defined_in_package_initializer_is_supported(tmp_path: Path) -> None:
    sources = {
        "service/__init__.py": "",
        "service/routes/__init__.py": _FASTAPI.child_source,
        "service/main.py": _FASTAPI.parent_source,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        (
            _full_excerpt(
                executor,
                "service/routes/__init__.py",
                _FASTAPI.child_source,
            ),
            _full_excerpt(executor, "service/main.py", _FASTAPI.parent_source),
        ),
    )

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)


def test_invalid_package_alternative_to_imported_module_fails_closed(
    tmp_path: Path,
) -> None:
    evidence = _mounted_evidence(
        tmp_path,
        _FASTAPI,
        extra_sources={"service/routes/__init__.py": "def invalid(:\n"},
    )

    assert evidence.authorized_http_routes() == ()


def test_flask_duplicate_handler_endpoint_fails_closed(tmp_path: Path) -> None:
    child_source = (
        "from flask import Blueprint\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/one")\n'
        "def same(): return 'one'\n"
        '@blueprint.get("/two")\n'
        "def same(): return 'two'\n"
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child_source)

    assert evidence.authorized_http_routes() == ()


def test_flask_multiple_routes_on_one_handler_remain_supported(tmp_path: Path) -> None:
    child_source = (
        "from flask import Blueprint\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/one")\n'
        '@blueprint.get("/two")\n'
        "def same(): return 'ok'\n"
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child_source)

    assert evidence.authorized_http_routes() == (
        ("GET", "/api/one"),
        ("GET", "/api/two"),
    )


def test_flask_duplicate_blueprint_registration_name_fails_closed(tmp_path: Path) -> None:
    first = (
        "from flask import Blueprint\n"
        'first = Blueprint("same", __name__)\n'
        '@first.get("/one")\n'
        "def one(): return 'one'\n"
    )
    second = (
        "from flask import Blueprint\n"
        'second = Blueprint("same", __name__)\n'
        '@second.get("/two")\n'
        "def two(): return 'two'\n"
    )
    parent = (
        "from flask import Flask\n"
        "from .first import first\n"
        "from .second import second\n"
        "app = Flask(__name__)\n"
        'app.register_blueprint(first, url_prefix="/a")\n'
        'app.register_blueprint(second, url_prefix="/b")\n'
    )
    sources = {
        "service/__init__.py": "",
        "service/first.py": first,
        "service/second.py": second,
        "service/main.py": parent,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        tuple(
            _full_excerpt(executor, source_file, sources[source_file])
            for source_file in ("service/first.py", "service/second.py", "service/main.py")
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    ("constructor", "expected"),
    [("Flask(__name__)", ()), ("Flask(__name__, static_folder=None)", (("GET", "/health"),))],
    ids=["default-static-endpoint", "static-endpoint-disabled"],
)
def test_flask_static_endpoint_collision_matches_constructor(
    tmp_path: Path,
    constructor: str,
    expected: tuple[tuple[str, str], ...],
) -> None:
    source = (
        "from flask import Flask\n"
        f"app = {constructor}\n"
        '@app.get("/health")\n'
        "def static(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == expected


@pytest.mark.parametrize("static_folder", ["<", "<foo", "<>", "<path:>", "<x:x>"])
def test_flask_malformed_static_folder_fails_closed(
    tmp_path: Path,
    static_folder: str,
) -> None:
    parent_source = _FLASK.parent_source.replace(
        "Flask(__name__)",
        f"Flask(__name__, static_folder={static_folder!r})",
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, parent_source=parent_source)

    assert evidence.authorized_http_routes() == ()


def test_flask_safe_custom_static_folder_keeps_mounted_route(tmp_path: Path) -> None:
    parent_source = _FLASK.parent_source.replace(
        "Flask(__name__)",
        'Flask(__name__, static_folder="assets")',
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, parent_source=parent_source)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)


@pytest.mark.parametrize("receiver", ["blueprint", "application"])
def test_flask_literal_namespace_import_name_fails_closed(
    tmp_path: Path,
    receiver: str,
) -> None:
    observed_files: tuple[str, ...]
    if receiver == "blueprint":
        child = (
            "from flask import Blueprint\n"
            'blueprint = Blueprint("health", "service")\n'
            '@blueprint.get("/health")\n'
            "def health(): return 'ok'\n"
        )
        sources = {
            "service/routes.py": child,
            "service/main.py": _FLASK.parent_source,
        }
        observed_files = ("service/routes.py", "service/main.py")
    else:
        child = ""
        sources = {
            "service/main.py": (
                "from flask import Flask\n"
                'app = Flask("service")\n'
                '@app.get("/health")\n'
                "def health(): return 'ok'\n"
            )
        }
        observed_files = ("service/main.py",)
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        tuple(_full_excerpt(executor, path, sources[path]) for path in observed_files),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "source",
    [
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health(value, value): return 'ok'\n"
        ),
        (
            "marker = 1\n"
            "from __future__ import annotations\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
        (
            "from fastapi import FastAPI, DefinitelyMissing\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
        (
            "from fastapi import FastAPI, Request as __package__\n"
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
        (
            "from fastapi import FastAPI\n"
            'marker = -"invalid"\n'
            "app = FastAPI()\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
    ],
    ids=[
        "duplicate-function-argument",
        "misplaced-future-import",
        "unknown-framework-import",
        "import-control-binding",
        "invalid-passive-expression",
    ],
)
def test_import_time_failure_cases_do_not_authorize_routes(
    tmp_path: Path,
    source: str,
) -> None:
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "extra_import",
    [
        "from sanic import Request",
        "from quart import request",
        "from typing_extensions import Any",
    ],
    ids=["sanic", "quart", "typing-extensions"],
)
def test_optional_unrelated_imports_fail_closed(
    tmp_path: Path,
    extra_import: str,
) -> None:
    source = (
        "from fastapi import FastAPI\n"
        f"{extra_import}\n"
        "app = FastAPI()\n"
        '@app.get("/health")\n'
        "def health(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "source",
    [
        (
            "from quart import Quart\n"
            "app = Quart(__name__)\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
        (
            "from sanic import Sanic\n"
            'app = Sanic("service")\n'
            '@app.get("/health")\n'
            "def health(_request): return 'ok'\n"
        ),
        (
            "from sanic import Sanic\n"
            'app = Sanic("service")\n'
            '@app.get("/health")\n'
            "@missing\n"
            "def health(_request): return 'ok'\n"
        ),
    ],
    ids=["quart", "sanic", "sanic-unknown-decorator"],
)
def test_unvalidated_python_frameworks_do_not_grant_authority(
    tmp_path: Path,
    source: str,
) -> None:
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "source",
    [
        (
            "from fastapi import APIRouter, FastAPI\n"
            "router = APIRouter()\n"
            "router.include_router(router)\n"
            "app = FastAPI()\n"
            "app.include_router(router)\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
        (
            "from fastapi import APIRouter, FastAPI\n"
            "first = APIRouter()\n"
            "second = APIRouter()\n"
            "first.include_router(second)\n"
            "second.include_router(first)\n"
            "app = FastAPI()\n"
            "app.include_router(first)\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
        (
            "from flask import Blueprint, Flask\n"
            'blueprint = Blueprint("self", __name__)\n'
            "blueprint.register_blueprint(blueprint)\n"
            "app = Flask(__name__)\n"
            "app.register_blueprint(blueprint)\n"
            '@app.get("/health")\n'
            "def health(): return 'ok'\n"
        ),
    ],
    ids=["fastapi-self", "fastapi-two-router", "flask-self"],
)
def test_mount_cycles_fail_the_containing_module_closed(
    tmp_path: Path,
    source: str,
) -> None:
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "constructor",
    [
        "FastAPI()",
        'FastAPI(docs_url="/manual")',
    ],
    ids=["default-docs", "configured-docs"],
)
def test_fastapi_builtin_route_collision_is_not_source_authority(
    tmp_path: Path,
    constructor: str,
) -> None:
    path = "/manual" if "manual" in constructor else "/docs"
    source = (
        "from fastapi import FastAPI\n"
        f"app = {constructor}\n"
        f'@app.get("{path}")\n'
        "def source_handler(): return 'source'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_disabling_fastapi_docs_releases_the_static_path(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI(docs_url=None)\n"
        '@app.get("/docs")\n'
        "def source_handler(): return 'source'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == (("GET", "/docs"),)


@pytest.mark.parametrize("framework", ["fastapi", "flask"])
def test_competing_effective_route_definitions_fail_closed(
    tmp_path: Path,
    framework: str,
) -> None:
    if framework == "fastapi":
        child = (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            '@router.get("/same")\n'
            "def child(): return 'child'\n"
        )
        parent = (
            "from fastapi import FastAPI\n"
            "from .routes import router\n"
            "app = FastAPI()\n"
            '@app.get("/same")\n'
            "def parent(): return 'parent'\n"
            "app.include_router(router)\n"
        )
    else:
        child = (
            "from flask import Blueprint\n"
            'blueprint = Blueprint("child", __name__)\n'
            '@blueprint.get("/same")\n'
            "def child(): return 'child'\n"
        )
        parent = (
            "from flask import Flask\n"
            "from .routes import blueprint\n"
            "app = Flask(__name__)\n"
            '@app.get("/same")\n'
            "def parent(): return 'parent'\n"
            "app.register_blueprint(blueprint)\n"
        )
    sources = {
        "service/__init__.py": "",
        "service/routes.py": child,
        "service/main.py": parent,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "service/routes.py", child),
            _full_excerpt(executor, "service/main.py", parent),
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize("location", ["route", "static-folder"])
def test_python_route_surrogates_fail_closed(tmp_path: Path, location: str) -> None:
    escaped_surrogate = "\\ud800"
    if location == "route":
        parent = _FLASK.parent_source
        child = _FLASK.child_source.replace("/health", f"/{escaped_surrogate}")
    else:
        parent = _FLASK.parent_source.replace(
            "Flask(__name__)",
            f'Flask(__name__, static_folder="{escaped_surrogate}")',
        )
        child = _FLASK.child_source
    evidence = _mounted_evidence(
        tmp_path,
        _FLASK,
        child_source=child,
        parent_source=parent,
    )

    assert evidence.authorized_http_routes() == ()


def test_rebound_global_query_root_grants_no_query_authority(tmp_path: Path) -> None:
    child = (
        "from flask import Blueprint, request\n"
        "request = ()\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        '    return request.args.get("secret")\n'
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert not evidence.permits_http_action(_request("/api/health?secret="))


def test_flask_query_requires_the_global_request_import_line(tmp_path: Path) -> None:
    child = (
        "from flask import Blueprint\n"
        "from flask import request\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        '    return request.args.get("secret")\n'
    )
    sources = {
        "service/__init__.py": "",
        "service/routes.py": child,
        "service/main.py": _FLASK.parent_source,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    observations = [_excerpt(executor, "service/routes.py", line, line) for line in (1, 3, 4, 5, 6)]
    observations.append(_full_excerpt(executor, "service/main.py", _FLASK.parent_source))
    evidence = _evidence(policy, observations)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert not evidence.permits_http_action(_request("/api/health?secret="))
    assert evidence.observe(_excerpt(executor, "service/routes.py", 2, 2))
    assert evidence.permits_http_action(_request("/api/health?secret="))


@pytest.mark.parametrize(
    ("alias", "reference", "expected"),
    [
        ("REQ", "REQ", True),
        ("REQ", "req", False),
        ("Request", "request", False),
    ],
    ids=["exact-uppercase", "lowercase-mismatch", "mixed-case-mismatch"],
)
def test_flask_query_aliases_are_correlated_case_sensitively(
    tmp_path: Path,
    alias: str,
    reference: str,
    *,
    expected: bool,
) -> None:
    child = (
        f"from flask import Blueprint, request as {alias}\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        f'    return {reference}.args.get("secret")\n'
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert evidence.permits_http_action(_request("/api/health?secret=")) is expected


@pytest.mark.parametrize(
    "body",
    [
        (
            "    try:\n"
            "        raise ValueError()\n"
            "    except ValueError as request:\n"
            '        return request.args.get("secret")\n'
        ),
        ('    match 1:\n        case request:\n            return request.args.get("secret")\n'),
        (
            "    match []:\n"
            "        case [*request]:\n"
            '            return request.args.get("secret")\n'
        ),
        (
            "    match {}:\n"
            "        case {**request}:\n"
            '            return request.args.get("secret")\n'
        ),
    ],
    ids=["except", "match-as", "match-star", "match-rest"],
)
def test_flask_string_valued_local_binders_shadow_global_request(
    tmp_path: Path,
    body: str,
) -> None:
    child = (
        "from flask import Blueprint, request\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        f"{body}"
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert not evidence.permits_http_action(_request("/api/health?secret="))


@pytest.mark.parametrize(
    "expression",
    [
        'request.args.has("secret")',
        'request.query.get("secret")',
        'request.query_params.get("secret")',
        'request.ARGS.get("secret")',
    ],
    ids=["unsupported-has", "query", "query-params", "case-mismatched-args"],
)
def test_flask_unsupported_query_access_grants_no_query_authority(
    tmp_path: Path,
    expression: str,
) -> None:
    child = (
        "from flask import Blueprint, request\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        f"    return {expression}\n"
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert not evidence.permits_http_action(_request("/api/health?secret="))


def test_flask_request_import_does_not_authorize_fastapi_query(tmp_path: Path) -> None:
    child = (
        "from fastapi import APIRouter\n"
        "from flask import Flask, request\n"
        "router = APIRouter()\n"
        "decoy = Flask(__name__, static_folder=None)\n"
        '@router.get("/health")\n'
        "def health():\n"
        '    return request.args.get("secret")\n'
    )
    evidence = _mounted_evidence(tmp_path, _FASTAPI, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert not evidence.permits_http_action(_request("/api/health?secret="))


def test_competing_routes_on_distinct_app_roots_fail_closed(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "from flask import Flask, request\n"
        "api = FastAPI()\n"
        "flask_app = Flask(__name__, static_folder=None)\n"
        '@api.get("/health")\n'
        '@flask_app.get("/health")\n'
        "def health():\n"
        '    return request.args.get("secret")\n'
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/health?secret="))


def test_unsafe_alternate_app_root_still_occupies_its_route(tmp_path: Path) -> None:
    first = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/same")\n'
        "def first(): return 'first'\n"
    )
    second = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "print('startup')\n"
        '@app.get("/same")\n'
        "def second(): return 'second'\n"
    )
    sources = {
        "service/__init__.py": "",
        "service/first.py": first,
        "service/second.py": second,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(policy, (_full_excerpt(executor, "service/first.py", first),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same"))


def test_ambiguous_alternate_app_root_still_occupies_its_route(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "first_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)\n"
        "second_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)\n"
        '@first_app.get("/same")\n'
        "def first(): return 'first'\n"
        '@second_app.get("/same")\n'
        "def second(): return 'second'\n"
        '@second_app.get("/same")\n'
        "def third(): return 'third'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"service.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "service.py", source),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same"))


def test_unresolved_mount_prevents_cross_root_authority(tmp_path: Path) -> None:
    first = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/same")\n'
        "def first(): return 'first'\n"
    )
    second = (
        "from fastapi import APIRouter, FastAPI\n"
        "PREFIX = ''\n"
        "router = APIRouter()\n"
        "app = FastAPI()\n"
        '@router.get("/same")\n'
        "def second(): return 'second'\n"
        "app.include_router(router, prefix=PREFIX)\n"
    )
    sources = {"first.py": first, "second.py": second}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(policy, (_full_excerpt(executor, "first.py", first),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same"))


def test_unresolved_mount_through_root_alias_prevents_cross_root_authority(
    tmp_path: Path,
) -> None:
    first = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/same")\n'
        "def first(): return 'first'\n"
    )
    second = (
        "from fastapi import APIRouter, FastAPI\n"
        "router = APIRouter()\n"
        "app = FastAPI()\n"
        "alias = app\n"
        '@router.get("/same")\n'
        "def second(): return 'second'\n"
        "alias.include_router(router)\n"
    )
    sources = {"first.py": first, "second.py": second}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(policy, (_full_excerpt(executor, "first.py", first),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same"))


def test_handler_route_table_mutation_fails_the_policy_closed(tmp_path: Path) -> None:
    first = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/same")\n'
        "def first(): return 'first'\n"
    )
    second = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def live(): return {'live': True}\n"
        '@app.get("/trigger")\n'
        "def trigger():\n"
        "    app.add_api_route('/same', live, methods=['GET'])\n"
        "    return 'ok'\n"
    )
    sources = {"first.py": first, "second.py": second}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(policy, (_full_excerpt(executor, "first.py", first),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same"))


def test_mount_depth_overflow_fails_the_policy_closed(tmp_path: Path) -> None:
    first = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/same")\n'
        "def first(): return 'first'\n"
    )
    router_declarations = "".join(f"router_{index} = APIRouter()\n" for index in range(1, 10))
    nested_mounts = "".join(
        f"router_{index}.include_router(router_{index + 1})\n" for index in range(1, 9)
    )
    second = (
        "from fastapi import APIRouter, FastAPI\n"
        f"{router_declarations}"
        "app = FastAPI()\n"
        '@router_9.get("/same")\n'
        "def second(): return 'second'\n"
        f"{nested_mounts}"
        "app.include_router(router_1)\n"
    )
    sources = {"first.py": first, "second.py": second}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(policy, (_full_excerpt(executor, "first.py", first),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same"))


def test_cross_language_route_ownership_collision_fails_closed(tmp_path: Path) -> None:
    python_source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/same")\n'
        "def python_handler(): return 'python'\n"
    )
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/same", (_req, res) => res.send("script"));\n'
    )
    sources = {"service.py": python_source, "service.js": script_source}
    _captured, policy, executor = _context(tmp_path, sources)
    observations = (
        _full_excerpt(executor, "service.py", python_source),
        _full_excerpt(executor, "service.js", script_source),
    )
    evidence = _evidence(policy, observations)

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same"))


def test_builtin_route_on_alternate_root_occupies_its_path(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "custom = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)\n"
        "default = FastAPI()\n"
        '@custom.get("/docs")\n'
        "def custom_docs(): return 'custom'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/docs"))


def test_flask_builtin_static_route_on_alternate_root_occupies_prefix(tmp_path: Path) -> None:
    source = (
        "from flask import Flask\n"
        "custom = Flask(__name__, static_folder=None)\n"
        "default = Flask(__name__)\n"
        '@custom.get("/static/foo.txt")\n'
        "def custom_static(): return 'custom'\n"
    )
    sources = {"service/app.py": source, "service/static/foo.txt": "LIVE\n"}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(policy, (_full_excerpt(executor, "service/app.py", source),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/static/foo.txt"))


def test_flask_builtin_static_route_occupies_its_own_prefix(tmp_path: Path) -> None:
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.get("/static/foo.txt")\n'
        "def custom_static(): return 'custom'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"service/app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "service/app.py", source),))

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
def test_flask_get_on_alternate_root_occupies_implicit_method(
    tmp_path: Path,
    method: str,
) -> None:
    source = (
        "from flask import Flask\n"
        "explicit = Flask(__name__, static_folder=None)\n"
        "implicit = Flask(__name__, static_folder=None)\n"
        f'@explicit.route("/same", methods=["{method}"])\n'
        "def explicit_method(): return 'explicit'\n"
        '@implicit.get("/same")\n'
        "def implicit_methods(): return 'implicit'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == (("GET", "/same"),)
    assert not evidence.permits_http_action(_request("/same", method=method))


def test_flask_non_get_route_on_alternate_root_occupies_automatic_options(
    tmp_path: Path,
) -> None:
    source = (
        "from flask import Flask\n"
        "explicit = Flask(__name__, static_folder=None)\n"
        "automatic = Flask(__name__, static_folder=None)\n"
        '@explicit.route("/same", methods=["OPTIONS"])\n'
        "def explicit_options(): return 'explicit'\n"
        '@automatic.route("/same", methods=["POST"])\n'
        "def automatic_options(): return 'automatic'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same", method="OPTIONS"))


@pytest.mark.parametrize(
    ("python_source", "method", "path"),
    [
        (
            "from fastapi import FastAPI\napp = FastAPI()\n",
            "GET",
            "/docs",
        ),
        (
            "from fastapi import FastAPI\napp = FastAPI()\n",
            "GET",
            "/docs/",
        ),
        (
            "from flask import Flask\napp = Flask(__name__)\n",
            "GET",
            "/static/foo.txt",
        ),
        (
            "from flask import Flask\n"
            "app = Flask(__name__, static_folder=None)\n"
            '@app.get("/same")\n'
            "def implicit_methods(): return 'python'\n",
            "HEAD",
            "/same",
        ),
        (
            "from flask import Flask\n"
            "app = Flask(__name__, static_folder=None)\n"
            '@app.get("/same")\n'
            "def implicit_methods(): return 'python'\n",
            "OPTIONS",
            "/same",
        ),
    ],
    ids=[
        "fastapi-docs",
        "fastapi-docs-redirect",
        "flask-static",
        "flask-head",
        "flask-options",
    ],
)
def test_python_runtime_occupancy_blocks_script_fact(
    tmp_path: Path,
    python_source: str,
    method: str,
    path: str,
) -> None:
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        f'app.{method.lower()}("{path}", (_req, res) => res.send("script"));\n'
    )
    sources = {"service.py": python_source, "service.js": script_source}
    _captured, policy, executor = _context(tmp_path, sources)
    observations = (
        _full_excerpt(executor, "service.py", python_source),
        _full_excerpt(executor, "service.js", script_source),
    )
    evidence = _evidence(policy, observations)

    assert (method, path) not in evidence.authorized_http_routes()
    assert not evidence.permits_http_action(_request(path, method=method))


def test_fastapi_alternate_slash_paths_collide_across_roots(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "plain = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        "slash = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        '@plain.get("/same")\n'
        "def plain_route(): return 'plain'\n"
        '@slash.get("/same/")\n'
        "def slash_route(): return 'slash'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_fastapi_redirect_slashes_false_releases_alternate_paths(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "plain = FastAPI("
        "openapi_url=None, docs_url=None, redoc_url=None, redirect_slashes=False)\n"
        "slash = FastAPI("
        "openapi_url=None, docs_url=None, redoc_url=None, redirect_slashes=False)\n"
        '@plain.get("/same")\n'
        "def plain_route(): return 'plain'\n"
        '@slash.get("/same/")\n'
        "def slash_route(): return 'slash'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == (
        ("GET", "/same"),
        ("GET", "/same/"),
    )


def test_flask_trailing_slash_redirect_occupies_plain_path(tmp_path: Path) -> None:
    source = (
        "from flask import Flask\n"
        "plain = Flask(__name__, static_folder=None)\n"
        "slash = Flask(__name__, static_folder=None)\n"
        '@plain.get("/same")\n'
        "def plain_route(): return 'plain'\n"
        '@slash.get("/same/")\n'
        "def slash_route(): return 'slash'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == (("GET", "/same/"),)
    assert not evidence.permits_http_action(_request("/same"))


def test_fastapi_builtin_redirect_occupies_alternate_path(tmp_path: Path) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "custom = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        "default = FastAPI()\n"
        '@custom.get("/docs/")\n'
        "def custom_docs(): return 'custom'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_fastapi_post_route_redirect_occupies_all_navigation_methods(
    tmp_path: Path,
) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "explicit = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        "redirecting = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        '@explicit.head("/same")\n'
        "def explicit_head(): return 'explicit'\n"
        '@redirecting.api_route("/same/", methods=["POST"])\n'
        "def redirecting_post(): return 'redirecting'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()
    assert not evidence.permits_http_action(_request("/same", method="HEAD"))


@pytest.mark.parametrize("framework", ["fastapi", "flask"])
def test_framework_application_factory_makes_global_occupancy_incomplete(
    tmp_path: Path,
    framework: str,
) -> None:
    if framework == "fastapi":
        python_source = (
            "from fastapi import FastAPI\ndef create_app(): return FastAPI()\napp = create_app()\n"
        )
        path = "/docs"
    else:
        python_source = (
            "from flask import Flask\n"
            "def create_app(): return Flask(__name__)\n"
            "app = create_app()\n"
        )
        path = "/static/foo.txt"
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        f'app.get("{path}", (_req, res) => res.send("script"));\n'
    )
    sources = {"app.py": python_source, "app.js": script_source}
    _captured, policy, executor = _context(tmp_path, sources)
    observations = (
        _full_excerpt(executor, "app.py", python_source),
        _full_excerpt(executor, "app.js", script_source),
    )
    evidence = _evidence(policy, observations)

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize("framework", ["fastapi", "flask"])
def test_dynamic_framework_constructor_access_makes_global_occupancy_incomplete(
    tmp_path: Path,
    framework: str,
) -> None:
    constructor = "FastAPI" if framework == "fastapi" else "Flask"
    arguments = "__name__" if framework == "flask" else ""
    hidden_source = (
        f"import {framework}\n"
        f'hidden = getattr({framework}, "{constructor}")({arguments})\n'
    )
    path = "/docs" if framework == "fastapi" else "/static/foo.txt"
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        f'app.get("{path}", (_req, res) => res.send("script"));\n'
    )
    sources = {"hidden.py": hidden_source, "app.js": script_source}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "hidden.py", hidden_source),
            _full_excerpt(executor, "app.js", script_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "hidden_source",
    [
        (
            "from fastapi import __dict__ as exported\n"
            'hidden = exported["FastAPI"]()\n'
        ),
        (
            "from fastapi import FastAPI\n"
            'hidden = globals()["FastAPI"]()\n'
        ),
        (
            "from fastapi import applications\n"
            "hidden = applications.FastAPI()\n"
        ),
        (
            "from flask import app\n"
            "hidden = app.Flask(__name__)\n"
        ),
    ],
    ids=["export-dictionary", "globals-lookup", "fastapi-submodule", "flask-submodule"],
)
def test_indirect_framework_constructor_access_fails_global_policy_closed(
    tmp_path: Path,
    hidden_source: str,
) -> None:
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/docs", (_req, res) => res.send("script"));\n'
    )
    sources = {"hidden.py": hidden_source, "app.js": script_source}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "hidden.py", hidden_source),
            _full_excerpt(executor, "app.js", script_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "hidden_source",
    [
        (
            "import importlib\n"
            'framework = importlib.import_module("fastapi")\n'
            "hidden = framework.FastAPI()\n"
        ),
        'hidden = __import__("fastapi").FastAPI()\n',
        (
            "from importlib import import_module\n"
            'framework = import_module(name="flask")\n'
            "hidden = framework.Flask(__name__)\n"
        ),
        (
            "from importlib import import_module as load\n"
            'framework = load("fastapi")\n'
            "hidden = framework.FastAPI()\n"
        ),
        (
            "loader = __import__\n"
            'framework = loader("fastapi")\n'
            "hidden = framework.FastAPI()\n"
        ),
        (
            "import importlib\n"
            'framework = importlib.import_module("fast" + "api")\n'
            "hidden = framework.FastAPI()\n"
        ),
    ],
    ids=[
        "module-import",
        "builtin-import",
        "named-import",
        "aliased-import",
        "aliased-builtin",
        "constant-expression",
    ],
)
def test_literal_dynamic_framework_import_fails_global_policy_closed(
    tmp_path: Path,
    hidden_source: str,
) -> None:
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/docs", (_req, res) => res.send("script"));\n'
    )
    sources = {"hidden.py": hidden_source, "app.js": script_source}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "hidden.py", hidden_source),
            _full_excerpt(executor, "app.js", script_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize("receiver", ["root", "component"])
def test_unconsumed_cross_file_receiver_import_fails_global_policy_closed(
    tmp_path: Path,
    receiver: str,
) -> None:
    if receiver == "root":
        main_source = (
            "from fastapi import FastAPI\n"
            "app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
            '@app.get("/health")\n'
            "def health(): return {'ok': True}\n"
        )
        mutator_source = "from .main import app\napp.router.routes.clear()\n"
    else:
        main_source = _FASTAPI.parent_source
        mutator_source = "from .routes import router\nrouter.routes.clear()\n"
    sources = {
        "service/__init__.py": "",
        "service/routes.py": _FASTAPI.child_source,
        "service/main.py": main_source,
        "service/mutator.py": mutator_source,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        tuple(
            _full_excerpt(executor, path, source)
            for path, source in sources.items()
            if source
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "mutator_source",
    [
        "from service.main import app\napp.router.routes.clear()\n",
        "from . import main\nmain.app.router.routes.clear()\n",
        "import service.main as main\nmain.app.router.routes.clear()\n",
    ],
    ids=["absolute-symbol", "relative-module", "absolute-module"],
)
def test_cross_file_root_module_import_fails_global_policy_closed(
    tmp_path: Path,
    mutator_source: str,
) -> None:
    main_source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        '@app.get("/health")\n'
        "def health(): return {'ok': True}\n"
    )
    sources = {
        "service/__init__.py": "",
        "service/main.py": main_source,
        "service/mutator.py": mutator_source,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        tuple(
            _full_excerpt(executor, path, source)
            for path, source in sources.items()
            if source
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "mutator_source",
    [
        (
            "import importlib\n"
            'main = importlib.import_module("service.main")\n'
            "main.app.router.routes.clear()\n"
        ),
        (
            'main = __import__("service.main", fromlist=["app"])\n'
            "main.app.router.routes.clear()\n"
        ),
    ],
    ids=["import-module", "builtin-import"],
)
def test_literal_dynamic_root_module_import_fails_global_policy_closed(
    tmp_path: Path,
    mutator_source: str,
) -> None:
    main_source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)\n"
        '@app.get("/health")\n'
        "def health(): return {'ok': True}\n"
    )
    sources = {
        "service/__init__.py": "",
        "service/main.py": main_source,
        "service/mutator.py": mutator_source,
    }
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        tuple(
            _full_excerpt(executor, path, source)
            for path, source in sources.items()
            if source
        ),
    )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "python_source",
    [
        "from fastapi.applications import FastAPI\napp = FastAPI()\n",
        "from flask import *\napp = Flask(__name__)\n",
    ],
    ids=["framework-submodule", "framework-star-import"],
)
def test_unresolved_framework_import_makes_global_occupancy_incomplete(
    tmp_path: Path,
    python_source: str,
) -> None:
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/docs", (_req, res) => res.send("script"));\n'
    )
    sources = {"app.py": python_source, "app.js": script_source}
    _captured, policy, executor = _context(tmp_path, sources)
    evidence = _evidence(
        policy,
        (
            _full_excerpt(executor, "app.py", python_source),
            _full_excerpt(executor, "app.js", script_source),
        ),
    )

    assert evidence.authorized_http_routes() == ()


def test_omitted_runtime_source_makes_global_occupancy_incomplete(tmp_path: Path) -> None:
    python_source = "from flask import Flask\napp = Flask(__name__)\n" + "# omitted padding\n" * 20
    script_source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/static/foo.txt", (_req, res) => res.send("script"));\n'
    )
    tmp_path.joinpath("app.py").write_text(python_source, encoding="utf-8")
    tmp_path.joinpath("app.js").write_text(script_source, encoding="utf-8")
    context = capture_repository(tmp_path, limits=ContextLimits(max_file_bytes=200))
    policy = build_source_navigation_policy(context)
    executor = SourceContextExecutor(context)
    evidence = _evidence(policy, (_full_excerpt(executor, "app.js", script_source),))

    assert [(item.path, item.reason) for item in context.omissions] == [
        ("app.py", "file_too_large")
    ]
    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize(
    "expression",
    [
        'False and request.args.get("secret")',
        'True or request.args.get("secret")',
        'request.args.get("secret") if False else "ok"',
        '"ok" if True else request.args.get("secret")',
    ],
    ids=["false-and", "true-or", "false-if-expression", "true-if-expression"],
)
def test_dead_query_expressions_grant_no_query_authority(
    tmp_path: Path,
    expression: str,
) -> None:
    child = (
        "from flask import Blueprint, request\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        f"    return {expression}\n"
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert not evidence.permits_http_action(_request("/api/health?secret="))


@pytest.mark.parametrize(
    "body",
    [
        ("    for _item in ():\n        request.args.get(\"secret\")\n    return 'ok'\n"),
        '    return [request.args.get("secret") for _item in ()]\n',
        ("    if True:\n        return 'ok'\n    return request.args.get(\"secret\")\n"),
        (
            "    try:\n"
            "        return 'ok'\n"
            "    except Exception:\n"
            '        return request.args.get("secret")\n'
        ),
        (
            "    match 1:\n"
            "        case 2:\n"
            '            return request.args.get("secret")\n'
            "    return 'ok'\n"
        ),
        '    return 2 < 1 < request.args.get("secret")\n',
        ("    while True:\n        return 'ok'\n    return request.args.get(\"secret\")\n"),
    ],
    ids=[
        "empty-for",
        "empty-comprehension",
        "after-static-return",
        "unreachable-except",
        "nonmatching-case",
        "short-circuited-comparison",
        "after-non-falling-loop",
    ],
)
def test_unreachable_query_control_flow_grants_no_query_authority(
    tmp_path: Path,
    body: str,
) -> None:
    child = (
        "from flask import Blueprint, request\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/health")\n'
        "def health():\n"
        f"{body}"
    )
    evidence = _mounted_evidence(tmp_path, _FLASK, child_source=child)

    assert evidence.authorized_http_routes() == (("GET", "/api/health"),)
    assert not evidence.permits_http_action(_request("/api/health?secret="))


@pytest.mark.parametrize("location", ["route-module", "package-initializer"])
def test_shadowed_empty_set_constructor_fails_closed(
    tmp_path: Path,
    location: str,
) -> None:
    passive_lines = "set = 0\nmarker = set()\n"
    if location == "route-module":
        child = _FASTAPI.child_source.replace(
            "from fastapi import APIRouter\n",
            f"from fastapi import APIRouter\n{passive_lines}",
        )
        evidence = _mounted_evidence(tmp_path, _FASTAPI, child_source=child)
    else:
        evidence = _mounted_evidence(
            tmp_path,
            _FASTAPI,
            extra_sources={"service/__init__.py": passive_lines},
        )

    assert evidence.authorized_http_routes() == ()


@pytest.mark.parametrize("keyword", ["title", "version"])
def test_fastapi_required_metadata_cannot_be_empty(
    tmp_path: Path,
    keyword: str,
) -> None:
    source = (
        "from fastapi import FastAPI\n"
        f'app = FastAPI({keyword}="")\n'
        '@app.get("/health")\n'
        "def health(): return 'ok'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_flask_route_added_after_blueprint_registration_fails_closed(
    tmp_path: Path,
) -> None:
    source = (
        "from flask import Blueprint, Flask\n"
        "app = Flask(__name__)\n"
        'blueprint = Blueprint("health", __name__)\n'
        '@blueprint.get("/before")\n'
        "def before(): return 'before'\n"
        'app.register_blueprint(blueprint, url_prefix="/api")\n'
        '@blueprint.get("/after")\n'
        "def after(): return 'after'\n"
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_flask_nested_mount_added_after_parent_registration_fails_closed(
    tmp_path: Path,
) -> None:
    source = (
        "from flask import Blueprint, Flask\n"
        "app = Flask(__name__)\n"
        'parent = Blueprint("parent", __name__)\n'
        'child = Blueprint("child", __name__)\n'
        '@parent.get("/before")\n'
        "def before(): return 'before'\n"
        'app.register_blueprint(parent, url_prefix="/api")\n'
        'parent.register_blueprint(child, url_prefix="/nested")\n'
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == ()


def test_flask_nested_mount_before_parent_registration_is_composed(
    tmp_path: Path,
) -> None:
    source = (
        "from flask import Blueprint, Flask\n"
        "app = Flask(__name__)\n"
        'parent = Blueprint("parent", __name__)\n'
        'child = Blueprint("child", __name__)\n'
        '@child.get("/health")\n'
        "def health(): return 'ok'\n"
        'parent.register_blueprint(child, url_prefix="/nested")\n'
        'app.register_blueprint(parent, url_prefix="/api")\n'
    )
    _captured, policy, executor = _context(tmp_path, {"app.py": source})
    evidence = _evidence(policy, (_full_excerpt(executor, "app.py", source),))

    assert evidence.authorized_http_routes() == (("GET", "/api/nested/health"),)
