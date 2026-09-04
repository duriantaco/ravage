# ruff: noqa: PLR2004
from __future__ import annotations

import json
from pathlib import Path

import pytest
from ravage.source_analysis import (
    SourceLimitError,
    SourceMap,
    SourceRootError,
    analyze_source_root,
)


def _write_source(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _candidate_shape(source_map: SourceMap) -> set[tuple[str, str, str, str, str, str]]:
    candidates = source_map.candidates
    return {
        (
            candidate.method,
            candidate.family,
            candidate.input_name,
            candidate.input_location,
            candidate.sink_kind,
            candidate.framework,
        )
        for candidate in candidates
    }


def test_flask_maps_request_inputs_to_every_supported_sink(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "routes.py",
        """
import os
import requests
from flask import Flask as FlaskApplication, render_template_string, request, send_file

web = FlaskApplication(__name__)

@web.route("/combined/<uuid:item_id>", methods=["POST", "GET"])
def combined(item_id):
    query = request.args.get("q")
    template = request.form["template"]
    command = request.values.get("command")
    filename = request.cookies.get("filename")
    target = request.headers.get("X-Target")
    database.execute("SELECT * FROM things WHERE name = '" + query + "'")
    render_template_string(template)
    os.system(command)
    send_file(filename)
    return requests.get(target)
""",
    )

    source_map = analyze_source_root(source_root)

    assert source_map.routes_discovered == 2
    assert len(source_map.candidates) == 10
    assert {candidate.route for candidate in source_map.candidates} == {"/combined/{item_id}"}
    per_method = {
        (
            "sql_injection",
            "q",
            "query",
            "sql_execute",
            "flask",
        ),
        (
            "ssti",
            "template",
            "form",
            "template_render_template_string",
            "flask",
        ),
        (
            "command_injection",
            "command",
            "unknown",
            "shell_system",
            "flask",
        ),
        (
            "path_traversal",
            "filename",
            "cookie",
            "file_send_file",
            "flask",
        ),
        (
            "ssrf",
            "X-Target",
            "header",
            "outbound_get",
            "flask",
        ),
    }
    assert {
        (family, input_name, location, sink, framework)
        for method, family, input_name, location, sink, framework in _candidate_shape(source_map)
        if method == "GET"
    } == per_method
    assert {
        (family, input_name, location, sink, framework)
        for method, family, input_name, location, sink, framework in _candidate_shape(source_map)
        if method == "POST"
    } == per_method


def test_fastapi_maps_decorated_parameters_and_constructor_aliases(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
import httpx
import subprocess
from fastapi import APIRouter as Router, Body, Cookie, FastAPI as API, Form, Header, Query
from pathlib import Path

application = API()
router = Router()

@router.api_route("/items/{item_id}", methods=["PATCH", "POST"])
async def update_item(
    item_id: str,
    query: str = Query(...),
    template: str = Body(...),
    command: str = Form(...),
    filename: str = Cookie(...),
    target: str = Header(...),
):
    database.execute(query)
    template_engine.from_string(template)
    subprocess.run(command, shell=True)
    Path(filename).read_text()
    return httpx.get(target)

@application.get("/lookup")
def lookup(term: str):
    return database.execute(term)
""",
    )

    source_map = analyze_source_root(source_root)

    assert source_map.routes_discovered == 3
    assert len(source_map.candidates) == 11
    assert {
        (candidate.route, candidate.method, candidate.input_name, candidate.input_location)
        for candidate in source_map.candidates
        if candidate.family == "sql_injection"
    } == {
        ("/items/{item_id}", "PATCH", "query", "query"),
        ("/items/{item_id}", "POST", "query", "query"),
        ("/lookup", "GET", "term", "query"),
    }
    assert {
        (
            candidate.method,
            candidate.family,
            candidate.input_name,
            candidate.input_location,
            candidate.sink_kind,
        )
        for candidate in source_map.candidates
        if candidate.route == "/items/{item_id}"
    } == {
        (method, family, input_name, location, sink)
        for method in ("PATCH", "POST")
        for family, input_name, location, sink in (
            ("sql_injection", "query", "query", "sql_execute"),
            ("ssti", "template", "body", "template_from_string"),
            ("command_injection", "command", "form", "shell_run"),
            ("path_traversal", "filename", "cookie", "file_read_text"),
            ("ssrf", "target", "header", "outbound_get"),
        )
    }
    assert {candidate.framework for candidate in source_map.candidates} == {"fastapi"}


def test_flask_request_import_alias_is_tracked(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "aliased_request.py",
        """
from flask import Flask, request as req

app = Flask(__name__)

@app.get("/aliased-request")
def aliased_request():
    term = req.args.get("term")
    return database.execute(term)
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.family == "sql_injection"
    assert candidate.input_name == "term"
    assert candidate.input_location == "query"


def test_fastapi_input_marker_alias_preserves_body_location(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "aliased_marker.py",
        """
from fastapi import Body as Payload, FastAPI

app = FastAPI()

@app.post("/aliased-marker")
def aliased_marker(query: str = Payload(...)):
    return database.execute(query)
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.family == "sql_injection"
    assert candidate.input_location == "body"


def test_requests_request_uses_keyword_url_after_positional_method(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "keyword_url.py",
        """
import requests
from flask import Flask, request

app = Flask(__name__)

@app.get("/proxy")
def proxy():
    target = request.args.get("target")
    return requests.request("GET", url=target)
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.family == "ssrf"
    assert candidate.input_name == "target"
    assert candidate.sink_kind == "outbound_request"


def test_keyword_write_mode_is_not_classified_as_file_read(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "write_only.py",
        """
from flask import Flask, request

app = Flask(__name__)

@app.post("/write-only")
def write_only():
    filename = request.form.get("filename")
    with open(filename, mode="w") as handle:
        handle.write("safe fixed content")
    return "ok"
""",
    )

    source_map = analyze_source_root(source_root)

    assert source_map.routes_discovered == 1
    assert source_map.candidates == ()


def test_flask_path_parameter_maps_to_file_read(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "download.py",
        """
from flask import Blueprint

downloads = Blueprint("downloads", __name__)

@downloads.get("/download/<path:filename>")
def download(filename):
    with open(filename) as handle:
        return handle.read()
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.route == "/download/{filename}"
    assert candidate.input_name == "filename"
    assert candidate.input_location == "path"
    assert candidate.family == "path_traversal"
    assert candidate.sink_kind == "file_open"


def test_static_blueprint_and_api_router_prefixes_bind_live_routes(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "flask_routes.py",
        """
from flask import Blueprint, request

blueprint = Blueprint("search", __name__, url_prefix="/api")

@blueprint.get("/search")
def search():
    return database.execute(request.args.get("term"))
""",
    )
    _write_source(
        source_root,
        "fastapi_routes.py",
        """
from fastapi import APIRouter

router = APIRouter(prefix="/v1")

@router.get("/users")
def users(name: str):
    return database.execute(name)
""",
    )

    source_map = analyze_source_root(source_root)

    assert {candidate.route for candidate in source_map.candidates} == {
        "/api/search",
        "/v1/users",
    }


def test_static_registration_prefixes_bind_live_routes(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "flask_routes.py",
        """
import flask
from flask import request

app = flask.Flask(__name__)
blueprint = flask.Blueprint("search", __name__, url_prefix="/ignored")
app.register_blueprint(blueprint, url_prefix="/api")

@blueprint.get("/search")
def search():
    return database.execute(request.args.get("term"))
""",
    )
    _write_source(
        source_root,
        "fastapi_routes.py",
        """
import fastapi

app = fastapi.FastAPI()
router = fastapi.APIRouter(prefix="/users")
app.include_router(router, prefix="/v1")

@router.get("/{user_id}")
def user(user_id: str):
    return database.execute(user_id)
""",
    )

    source_map = analyze_source_root(source_root)

    assert {candidate.route for candidate in source_map.candidates} == {
        "/api/search",
        "/v1/users/{user_id}",
    }
    flask_candidate = next(
        candidate for candidate in source_map.candidates if candidate.route == "/api/search"
    )
    assert flask_candidate.route_binding == "mounted"
    assert flask_candidate.live_validation == "automatic_get_query"


def test_prefixed_root_route_preserves_trailing_slash(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter(prefix="/api")
app.include_router(router)

@router.get("/")
def root(term: str):
    return database.execute(term)
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.route == "/api/"
    assert candidate.route_binding == "mounted"


def test_fastapi_annotated_alias_kwonly_and_required_query_shape(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
from typing import Annotated
from fastapi import FastAPI, Query

app = FastAPI()

@app.get("/search")
def search(
    *,
    term: Annotated[str, Query(alias="q")],
    tenant: str,
    page: int = 1,
):
    return database.execute(term)
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.input_name == "q"
    assert candidate.input_location == "query"
    assert candidate.route_binding == "direct"
    assert candidate.live_validation == "automatic_get_query"
    assert [field.to_json() for field in candidate.query_fields] == [
        {"name": "page", "required": False, "value_kind": "integer"},
        {"name": "q", "required": True, "value_kind": "string"},
        {"name": "tenant", "required": True, "value_kind": "string"},
    ]


def test_fastapi_model_body_is_not_mislabeled_as_query_input(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class SearchBody(BaseModel):
    term: str

@app.post("/search")
def search(payload: SearchBody):
    return database.execute(payload.term)
""",
    )

    source_map = analyze_source_root(source_root)

    assert source_map.routes_discovered == 1
    assert source_map.candidates == ()
    assert source_map.flow_patterns_skipped == 1


def test_fastapi_request_annotation_alias_tracks_query_input(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
from fastapi import FastAPI, Request as WebRequest

app = FastAPI()

@app.get("/search")
async def search(req: WebRequest):
    term = req.query_params["term"]
    return database.execute(term)
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.input_name == "term"
    assert candidate.input_location == "query"
    assert candidate.live_validation == "automatic_get_query"


def test_starlette_request_annotation_alias_tracks_query_input(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
from fastapi import FastAPI
from starlette.requests import Request as WebRequest

app = FastAPI()

@app.get("/search")
async def search(req: WebRequest):
    term = req.query_params["term"]
    return database.execute(term)
""",
    )

    [candidate] = analyze_source_root(source_root).candidates

    assert candidate.input_name == "term"
    assert candidate.input_location == "query"
    assert candidate.live_validation == "automatic_get_query"


@pytest.mark.parametrize(
    "route",
    [
        "/admin/delete_user",
        "/remove-item",
        "/accounts/reset_password",
        "/users/disableAccount",
        "/account/change-password",
        "/tokens/rotate_token",
        "/admin/runMigration",
    ],
)
def test_mutating_get_route_stays_hint_only(tmp_path: Path, route: str) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        f"""
from fastapi import FastAPI

app = FastAPI()

@app.get({route!r})
def mutate(term: str):
    return database.execute(term)
""",
    )

    [candidate] = analyze_source_root(source_root).candidates

    assert candidate.live_validation == "hint_only"
    assert candidate.query_fields == ()


def test_flask_json_container_and_branch_taint_are_preserved(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
from flask import Flask, request

app = Flask(__name__)

@app.post("/search")
def search():
    payload = request.get_json()
    term = payload["term"]
    if request.args.get("enabled"):
        query = term
    else:
        query = "fixed"
    return database.execute(query)
""",
    )

    source_map = analyze_source_root(source_root)

    [candidate] = source_map.candidates
    assert candidate.input_name == "term"
    assert candidate.input_location == "body"
    assert candidate.live_validation == "hint_only"
    assert source_map.flow_patterns_skipped == 0


def test_starlette_awaited_form_alias_is_tracked(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "api.py",
        """
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/search")
async def search(request: Request):
    form = await request.form()
    term = form["term"]
    return database.execute(term)
""",
    )

    [candidate] = analyze_source_root(source_root).candidates

    assert candidate.input_name == "term"
    assert candidate.input_location == "form"
    assert candidate.live_validation == "hint_only"


def test_constructor_derived_http_clients_are_ssrf_sinks(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "proxy.py",
        """
import httpx
import requests
from flask import Flask, request

app = Flask(__name__)

@app.get("/sync-proxy")
def sync_proxy():
    session = requests.Session()
    target = request.args.get("target")
    return session.get(target)

@app.get("/async-proxy")
async def async_proxy():
    client = httpx.AsyncClient()
    target = request.args.get("target")
    return await client.get(target)

@app.get("/direct-proxy")
def direct_proxy():
    target = request.args.get("target")
    return httpx.Client().get(target)
""",
    )

    source_map = analyze_source_root(source_root)

    assert {
        (candidate.route, candidate.family, candidate.input_name)
        for candidate in source_map.candidates
    } == {
        ("/sync-proxy", "ssrf", "target"),
        ("/async-proxy", "ssrf", "target"),
        ("/direct-proxy", "ssrf", "target"),
    }


def test_aiohttp_async_context_client_is_an_ssrf_sink(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "proxy.py",
        """
import aiohttp
from fastapi import FastAPI

app = FastAPI()

@app.get("/proxy")
async def proxy(target: str):
    async with aiohttp.ClientSession() as session:
        return await session.get(target)
""",
    )

    [candidate] = analyze_source_root(source_root).candidates

    assert candidate.family == "ssrf"
    assert candidate.input_name == "target"


def test_supported_sink_keyword_arguments_are_tracked(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "keywords.py",
        """
import subprocess
from flask import Flask, render_template_string, request, send_file
from starlette.responses import FileResponse

app = Flask(__name__)

@app.get("/keywords")
def keywords():
    template = request.args.get("template")
    command = request.args.get("command")
    first_path = request.args.get("first_path")
    second_path = request.args.get("second_path")
    third_path = request.args.get("third_path")
    render_template_string(source=template)
    subprocess.run(args=command, shell=True)
    open(file=first_path)
    send_file(path_or_file=second_path)
    return FileResponse(path=third_path)
""",
    )

    source_map = analyze_source_root(source_root)

    assert {
        (candidate.family, candidate.input_name, candidate.sink_kind)
        for candidate in source_map.candidates
    } == {
        ("ssti", "template", "template_render_template_string"),
        ("command_injection", "command", "shell_run"),
        ("path_traversal", "first_path", "file_open"),
        ("path_traversal", "second_path", "file_send_file"),
        ("path_traversal", "third_path", "file_fileresponse"),
    }


def test_unknown_route_owner_and_dynamic_prefix_are_skipped(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "routes.py",
        """
from fastapi import APIRouter

PREFIX = "/v1"
router = APIRouter(prefix=PREFIX)

@router.get("/dynamic")
def dynamic(term: str):
    return database.execute(term)

@cache.get("/not-http")
def cached(term: str):
    return database.execute(term)

def Flask(*args, **kwargs):
    return cache

fake_app = Flask(__name__)

@fake_app.get("/also-not-http")
def also_cached(term: str):
    return database.execute(term)
""",
    )

    source_map = analyze_source_root(source_root)

    assert source_map.routes_discovered == 0
    assert source_map.route_patterns_skipped == 1
    assert source_map.candidates == ()


def test_parameterized_sql_and_non_code_text_are_safe_controls(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "safe.py",
        '''
from flask import Flask, request

app = Flask(__name__)

@app.get("/safe")
def safe_lookup():
    """db.execute(request.args.get('from_docstring'))"""
    # db.execute(request.args.get("from_comment"))
    name = request.args.get("name")
    return database.execute("SELECT * FROM users WHERE name = ?", (name,))
''',
    )

    source_map = analyze_source_root(source_root)

    assert source_map.routes_discovered == 1
    assert source_map.candidates == ()


def test_generic_execute_method_is_not_assumed_to_be_a_sql_sink(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "worker.py",
        """
from flask import Flask, request

app = Flask(__name__)

@app.get("/jobs")
def run_job():
    job = request.args.get("job")
    return worker.execute(job)
""",
    )

    source_map = analyze_source_root(source_root)

    assert source_map.routes_discovered == 1
    assert source_map.candidates == ()


def test_common_database_qualified_sql_sinks_remain_supported(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "database_calls.py",
        """
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.get("/database-calls")
def database_calls():
    direct = request.args.get("direct")
    sqlite = request.args.get("sqlite")
    cursor = request.args.get("cursor")
    session = request.args.get("session")
    statement = request.args.get("statement")
    raw = request.args.get("raw")
    database.execute(direct)
    sqlite3.connect("app.db").execute(sqlite)
    connection.cursor().executemany(cursor)
    db.session.execute(session)
    User.query.from_statement(statement)
    return User.objects.raw(raw)
""",
    )

    source_map = analyze_source_root(source_root)

    assert {(candidate.input_name, candidate.sink_kind) for candidate in source_map.candidates} == {
        ("direct", "sql_execute"),
        ("sqlite", "sql_execute"),
        ("cursor", "sql_executemany"),
        ("session", "sql_execute"),
        ("statement", "sql_from_statement"),
        ("raw", "sql_raw"),
    }


def test_database_keyword_statements_and_async_fetch_are_supported(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "database_keywords.py",
        """
from flask import Flask, request

app = Flask(__name__)

@app.get("/database-keywords")
def database_keywords():
    statement = request.args.get("statement")
    fetch_query = request.args.get("fetch_query")
    raw_query = request.args.get("raw_query")
    db.session.execute(statement=statement)
    connection.fetch(query=fetch_query)
    return User.objects.raw(raw_query=raw_query)
""",
    )

    source_map = analyze_source_root(source_root)

    assert {(candidate.input_name, candidate.sink_kind) for candidate in source_map.candidates} == {
        ("statement", "sql_execute"),
        ("fetch_query", "sql_fetch"),
        ("raw_query", "sql_raw"),
    }


def test_serialized_map_contains_only_structural_metadata(tmp_path: Path) -> None:
    source_root = tmp_path / "private-source-root"
    _write_source(
        source_root,
        "routes/search.py",
        '''
from flask import Blueprint, request

router = Blueprint("search", __name__)
API_TOKEN = "literal-token-that-must-not-leak"

@router.get("/search")
def search():
    """Internal customer codename: glass-durian."""
    # Never serialize this note: confidential-comment-marker.
    term = request.args.get("term")
    return database.execute("SELECT private_column FROM secret_table WHERE name = '" + term)
''',
    )

    payload = analyze_source_root(source_root).to_json()
    serialized = json.dumps(payload, sort_keys=True)

    assert set(payload) == {
        "schema",
        "analyzer_contract",
        "source_digest",
        "candidate_digest",
        "counts",
        "candidates",
    }
    [candidate] = payload["candidates"]
    assert set(candidate) == {
        "candidate_id",
        "family",
        "framework",
        "input_location",
        "input_name",
        "live_validation",
        "line",
        "method",
        "query_fields",
        "reason",
        "relative_file",
        "route",
        "route_binding",
        "sink_kind",
        "status",
    }
    assert candidate["route_binding"] == "relative"
    assert candidate["live_validation"] == "hint_only"
    assert candidate["query_fields"] == []
    assert str(source_root) not in serialized
    for sensitive_text in (
        "literal-token-that-must-not-leak",
        "glass-durian",
        "confidential-comment-marker",
        "private_column",
        "secret_table",
        "SELECT ",
    ):
        assert sensitive_text not in serialized
    assert not ({"source", "snippet", "literal", "source_root"} & set(candidate))


def test_symlinked_files_and_directories_are_not_traversed(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    outside_root = tmp_path / "outside"
    _write_source(
        source_root,
        "real.py",
        """
from flask import Flask, request
app = Flask(__name__)
@app.get("/inside")
def inside():
    return database.execute(request.args.get("inside"))
""",
    )
    outside_file = _write_source(
        outside_root,
        "outside.py",
        """
from flask import Flask, request
app = Flask(__name__)
@app.get("/outside")
def outside():
    return database.execute(request.args.get("outside_secret"))
""",
    )
    (source_root / "linked.py").symlink_to(outside_file)
    (source_root / "linked-directory").symlink_to(outside_root, target_is_directory=True)

    source_map = analyze_source_root(source_root)

    assert source_map.files_scanned == 1
    assert source_map.symlinks_skipped == 2
    assert {candidate.route for candidate in source_map.candidates} == {"/inside"}
    assert "outside_secret" not in json.dumps(source_map.to_json())


def test_symbolic_link_source_root_is_rejected(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(SourceRootError, match="must not be a symbolic link"):
        analyze_source_root(linked_root)


def test_conventional_environment_directory_is_excluded_before_file_limit(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "app.py",
        """
from flask import Flask, request

app = Flask(__name__)

@app.get("/real-app")
def real_app():
    return database.execute(request.args.get("term"))
""",
    )
    dependency_root = source_root / ".venv" / "lib" / "site-packages" / "dependency"
    for index in range(2_001):
        _write_source(dependency_root, f"module_{index:04d}.py", "VALUE = 1\n")

    source_map = analyze_source_root(source_root)

    assert source_map.files_scanned == 1
    assert source_map.excluded_directories == 1
    assert [candidate.route for candidate in source_map.candidates] == ["/real-app"]


def test_python_file_count_limit_fails_without_partial_results(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root, "one.py", "ONE = 1\n")
    _write_source(source_root, "two.py", "TWO = 2\n")

    with pytest.raises(SourceLimitError, match="file count exceeds 1"):
        analyze_source_root(source_root, max_files=1)


def test_directory_count_limit_fails_without_partial_results(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root, "nested/app.py", "APP = True\n")

    with pytest.raises(SourceLimitError):
        analyze_source_root(source_root, max_directories=1)


def test_directory_entry_limit_fails_without_partial_results(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root, "one.py", "ONE = 1\n")
    _write_source(source_root, "two.py", "TWO = 2\n")

    with pytest.raises(SourceLimitError):
        analyze_source_root(source_root, max_directory_entries=1)


def test_per_file_byte_limit_fails_without_partial_results(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root, "large.py", "VALUE = 'too large'\n")

    with pytest.raises(SourceLimitError, match="source file exceeds 8 bytes"):
        analyze_source_root(
            source_root,
            max_file_bytes=8,
            max_total_bytes=32,
        )


def test_total_byte_limit_fails_without_partial_results(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root, "one.py", "ONE = 1\n")
    _write_source(source_root, "two.py", "TWO = 2\n")

    with pytest.raises(SourceLimitError, match="source tree exceeds 15 bytes"):
        analyze_source_root(
            source_root,
            max_file_bytes=10,
            max_total_bytes=15,
        )


@pytest.mark.parametrize(
    ("max_files", "max_total_bytes", "max_file_bytes"),
    [
        (0, 10, 10),
        (1, 0, 1),
        (1, 10, 0),
        (True, 10, 10),
        (1, 4, 5),
    ],
)
def test_invalid_scan_limits_are_rejected(
    tmp_path: Path,
    max_files: int,
    max_total_bytes: int,
    max_file_bytes: int,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()

    with pytest.raises(SourceLimitError):
        analyze_source_root(
            source_root,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_file_bytes=max_file_bytes,
        )


def test_digest_and_candidate_ids_are_stable_across_roots_and_creation_order(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    shared_source = """
from flask import Flask, request
app = Flask(__name__)
@app.get("/search")
def search():
    return database.execute(request.args.get("term"))
"""
    _write_source(first_root, "z_unused.py", "UNUSED = True\n")
    _write_source(first_root, "routes/search.py", shared_source)
    _write_source(second_root, "routes/search.py", shared_source)
    _write_source(second_root, "z_unused.py", "UNUSED = True\n")

    first = analyze_source_root(first_root)
    repeated = analyze_source_root(first_root)
    second = analyze_source_root(second_root)

    assert first.source_digest == repeated.source_digest == second.source_digest
    assert first.to_json() == repeated.to_json() == second.to_json()
    assert [item.candidate_id for item in first.candidates] == [
        item.candidate_id for item in second.candidates
    ]
    assert first.source_digest.startswith("sha256:")
    assert all(item.candidate_id.startswith("src-") for item in first.candidates)


def test_digest_changes_but_candidate_id_does_not_for_unrelated_file_change(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        "route.py",
        """
from flask import Flask, request
app = Flask(__name__)
@app.get("/search")
def search():
    return database.execute(request.args.get("term"))
""",
    )
    metadata = _write_source(source_root, "metadata.py", "VERSION = 1\n")
    before = analyze_source_root(source_root)

    metadata.write_text("VERSION = 2\n", encoding="utf-8")
    after = analyze_source_root(source_root)

    assert before.source_digest != after.source_digest
    assert [item.candidate_id for item in before.candidates] == [
        item.candidate_id for item in after.candidates
    ]


def test_syntax_errors_are_counted_without_hiding_valid_files(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root, "broken.py", "def broken(:\n")
    _write_source(
        source_root,
        "valid.py",
        """
from fastapi import FastAPI
app = FastAPI()
@app.get("/valid")
def valid(term: str):
    return database.execute(term)
""",
    )

    source_map = analyze_source_root(source_root)

    assert source_map.files_scanned == 2
    assert source_map.files_parsed == 1
    assert source_map.parse_failures == 1
    assert source_map.routes_discovered == 1
    assert [candidate.route for candidate in source_map.candidates] == ["/valid"]


def test_empty_tree_has_stable_empty_digest(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    _write_source(first_root, "README.txt", "not Python source")

    first = analyze_source_root(first_root)
    second = analyze_source_root(second_root)

    assert first.source_digest == second.source_digest
    assert first.files_scanned == 0
    assert first.bytes_scanned == 0
    assert first.candidates == ()
    assert first.source_digest == (
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_non_directory_and_missing_roots_are_rejected(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("APP = True\n", encoding="utf-8")

    with pytest.raises(SourceRootError, match="is not a directory"):
        analyze_source_root(source_file)
    with pytest.raises(SourceRootError, match="cannot access source root"):
        analyze_source_root(tmp_path / "missing")


def test_scan_does_not_change_process_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    working_directory = tmp_path / "working"
    working_directory.mkdir()
    monkeypatch.chdir(working_directory)

    analyze_source_root(source_root)

    assert Path.cwd() == working_directory
