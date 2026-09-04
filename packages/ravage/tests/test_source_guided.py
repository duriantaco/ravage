from __future__ import annotations

import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import (
    _completed_source_validation_actions,
    _source_validation_action_id,
    _source_validation_attempt_complete,
)
from ravage.agent_core.source_guided import (
    assert_source_resume_available,
    prepare_source_guided_analysis,
)
from ravage.probe_suite import run_builtin_probe
from ravage.run_data.workspace import AgentWorkspace
from ravage.source_analysis import SourceChangedError

if TYPE_CHECKING:
    from pathlib import Path


_PRIVATE_FILE_MODE = 0o600
_UNIQUE_SOURCE_REQUEST_SHAPES = 2
_MAX_PROMPT_SOURCE_CANDIDATES = 64
_FLASK_SOURCE = """
from flask import Flask, request

app = Flask(__name__)

@app.get("/unlinked/search")
def unlinked_search():
    term = request.args.get("term", "")
    return db.execute(f"SELECT name FROM products WHERE name = '{term}'").fetchall()

@app.get("/safe/search")
def safe_search():
    term = request.args.get("term", "")
    return db.execute("SELECT name FROM products WHERE name = ?", (term,)).fetchall()

TOP_SECRET_LITERAL = "must-never-enter-source-map"
"""


def _write_source(root: Path, text: str = _FLASK_SOURCE) -> None:
    root.mkdir()
    root.joinpath("app.py").write_text(text, encoding="utf-8")


def test_prepare_source_guided_analysis_is_private_structural_and_unverified(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root)
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    state = AgentState()

    prepared = prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=state,
        workspace=workspace,
        resumed=False,
    )

    assert prepared.candidates_found == 1
    assert prepared.candidates_ingested == 1
    assert [action["probe"] for action in prepared.validation_actions] == ["sqli_differential"]
    artifact = prepared.artifact_path
    assert stat.S_IMODE(artifact.stat().st_mode) == _PRIVATE_FILE_MODE
    artifact_text = artifact.read_text(encoding="utf-8")
    assert "must-never-enter-source-map" not in artifact_text
    payload = json.loads(artifact_text)
    assert payload["candidates"][0]["route"] == "/unlinked/search"
    assert payload["candidates"][0]["relative_file"] == "app.py"
    assert payload["candidates"][0]["status"] == "hypothesis"
    assert all("safe/search" not in item["route"] for item in payload["candidates"])
    assert all(
        "source_code" in operation.provenance
        for operation in (state.surface_graph.operations or {}).values()
    )
    assert all(
        observation.response_status is None and not observation.evidence_refs
        for observation in (state.surface_graph.observations or {}).values()
    )


def test_source_guided_resume_rejects_drift_and_missing_source(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root)
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    state = AgentState()
    prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=state,
        workspace=workspace,
        resumed=False,
    )

    with pytest.raises(SourceChangedError, match="same --source-root"):
        assert_source_resume_available(state=state, source_root=None)

    source_root.joinpath("app.py").write_text(
        _FLASK_SOURCE + "\nDRIFT = True\n",
        encoding="utf-8",
    )
    with pytest.raises(SourceChangedError, match="source tree changed"):
        prepare_source_guided_analysis(
            source_root=source_root,
            target_url="http://127.0.0.1:8765/",
            state=state,
            workspace=workspace,
            resumed=True,
        )


def test_source_analysis_discloses_incomplete_coverage(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root)
    source_root.joinpath("broken.py").write_text("def broken(", encoding="utf-8")
    source_root.joinpath("linked.py").symlink_to(source_root / "app.py")
    state = AgentState()

    prepared = prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=state,
        workspace=AgentWorkspace.open(tmp_path / "workspace"),
        resumed=False,
    )

    analysis = state.surface["source_analysis"]
    assert isinstance(analysis, dict)
    assert prepared.analysis_complete is False
    assert prepared.parse_failures == 1
    assert prepared.symlinks_skipped == 1
    assert prepared.route_patterns_skipped == 0
    assert analysis["analysis_complete"] is False
    assert analysis["parse_failures"] == 1
    assert analysis["symlinks_skipped"] == 1
    assert analysis["route_patterns_skipped"] == 0
    assert "coverage is incomplete" in state.facts[-1]
    event = prepared.event_payload(workspace=AgentWorkspace.open(tmp_path / "workspace"))
    assert event["analysis_complete"] is False
    assert event["parse_failures"] == 1
    assert event["symlinks_skipped"] == 1
    assert event["route_patterns_skipped"] == 0


def test_dynamic_framework_route_is_recorded_as_incomplete(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    _write_source(
        source_root,
        """
from fastapi import APIRouter

PREFIX = "/v1"
router = APIRouter(prefix=PREFIX)

@router.get("/search")
def search(term: str):
    return database.execute(term)
""",
    )
    state = AgentState()

    prepared = prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=state,
        workspace=AgentWorkspace.open(tmp_path / "workspace"),
        resumed=False,
    )

    assert prepared.analysis_complete is False
    assert prepared.route_patterns_skipped == 1
    assert state.surface["source_analysis"]["route_patterns_skipped"] == 1
    assert "coverage is incomplete" in state.facts[-1]


def test_cross_file_router_stays_a_hint_and_never_becomes_live_target(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    (source_root / "routes.py").parent.mkdir(parents=True)
    (source_root / "routes.py").write_text(
        """
from fastapi import APIRouter

router = APIRouter()

@router.get("/search")
def search(term: str):
    return database.execute(term)
""",
        encoding="utf-8",
    )
    (source_root / "main.py").write_text(
        """
from fastapi import FastAPI
from routes import router

app = FastAPI()
app.include_router(router, prefix="/api")
""",
        encoding="utf-8",
    )
    state = AgentState()

    prepared = prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=state,
        workspace=AgentWorkspace.open(tmp_path / "workspace"),
        resumed=False,
    )

    assert prepared.analysis_complete is False
    assert prepared.route_patterns_skipped == 1
    assert prepared.validation_actions == ()
    [candidate] = prepared.candidate_payloads
    assert candidate["route_binding"] == "relative"
    assert candidate["live_validation"] == "hint_only"
    assert not state.surface_graph.operations


def test_source_validation_completion_is_bound_and_requires_live_pairs(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root)
    state = AgentState()
    prepared = prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=state,
        workspace=AgentWorkspace.open(tmp_path / "workspace"),
        resumed=False,
    )
    action = prepared.validation_actions[0]
    candidate_ids = list(action["source_candidate_ids"])
    validation_id = _source_validation_action_id(prepared, action=action)
    target = {"source_candidate_ids": candidate_ids}
    envelope = {
        "probe": "sqli_differential",
        "errors": [],
        "http_request_count": 2,
        "http_request_count_status": "exact",
        "requests": [
            {"target": target, "probe_kind": "baseline", "status": 200, "error": ""},
            {"target": target, "probe_kind": "error", "status": 500, "error": ""},
        ],
    }
    clean_negative = ActionResult(
        ok=False,
        observation="",
        evidence_observation=json.dumps(envelope),
    )

    assert _source_validation_attempt_complete(
        clean_negative,
        probe="sqli_differential",
        candidate_ids=candidate_ids,
    ) == (True, "all_candidates_received_live_differential_responses")
    state.surface["source_validation"] = {
        "analyzer_contract": prepared.analyzer_contract,
        "source_digest": prepared.source_digest,
        "candidate_digest": prepared.candidate_digest,
        "completed_actions": [validation_id],
    }
    assert _completed_source_validation_actions(
        state,
        preparation=prepared,
    ) == {validation_id}
    state.surface["source_validation"]["candidate_digest"] = "sha256:" + ("0" * 64)
    assert not _completed_source_validation_actions(state, preparation=prepared)

    infrastructure_failure = ActionResult(
        ok=False,
        observation="",
        evidence_observation=json.dumps(
            {
                "probe": "sqli_differential",
                "errors": ["owner unavailable"],
                "findings": [],
            }
        ),
    )
    complete, reason = _source_validation_attempt_complete(
        infrastructure_failure,
        probe="sqli_differential",
        candidate_ids=candidate_ids,
    )
    assert complete is False
    assert reason == "inexact_request_accounting"


@pytest.mark.parametrize(
    ("baseline_status", "differential_status", "expected_reason"),
    [
        (429, 429, "retryable_http_status"),
        (503, 503, "retryable_http_status"),
        (200, 429, "retryable_http_status"),
        (200, 502, "retryable_http_status"),
        (200, 504, "retryable_http_status"),
        (500, 200, "unhealthy_baseline_status"),
    ],
)
def test_source_validation_retries_transient_or_unhealthy_http_statuses(
    baseline_status: int,
    differential_status: int,
    expected_reason: str,
) -> None:
    candidate_id = "src-000000000000000000000001"
    target = {"source_candidate_ids": [candidate_id]}
    outcome = ActionResult(
        ok=False,
        observation="",
        evidence_observation=json.dumps(
            {
                "probe": "sqli_differential",
                "errors": [],
                "http_request_count": 2,
                "http_request_count_status": "exact",
                "requests": [
                    {
                        "target": target,
                        "probe_kind": "baseline",
                        "status": baseline_status,
                        "error": "",
                    },
                    {
                        "target": target,
                        "probe_kind": "sql_error",
                        "status": differential_status,
                        "error": "",
                    },
                ],
            }
        ),
    )

    complete, reason = _source_validation_attempt_complete(
        outcome,
        probe="sqli_differential",
        candidate_ids=[candidate_id],
    )

    assert complete is False
    assert reason == expected_reason


def test_source_validation_accepts_healthy_baseline_and_sql_error_response() -> None:
    candidate_id = "src-000000000000000000000001"
    target = {"source_candidate_ids": [candidate_id]}
    outcome = ActionResult(
        ok=True,
        observation="",
        evidence_observation=json.dumps(
            {
                "probe": "sqli_differential",
                "errors": [],
                "http_request_count": 2,
                "http_request_count_status": "exact",
                "requests": [
                    {
                        "target": target,
                        "probe_kind": "baseline",
                        "status": 200,
                        "error": "",
                    },
                    {
                        "target": target,
                        "probe_kind": "sql_error",
                        "status": 500,
                        "error": "",
                    },
                ],
            }
        ),
    )

    assert _source_validation_attempt_complete(
        outcome,
        probe="sqli_differential",
        candidate_ids=[candidate_id],
    ) == (True, "all_candidates_received_live_differential_responses")


def test_source_validation_budget_counts_unique_request_shapes(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    repeated_sinks = "\n".join("    database.execute(term)" for _ in range(9))
    _write_source(
        source_root,
        f"""\
from flask import Flask, request

app = Flask(__name__)

@app.get("/first")
def first():
    term = request.args.get("term")
{repeated_sinks}
    return "ok"

@app.get("/second")
def second():
    query = request.args.get("query")
    database.execute(query)
    return "ok"
""",
    )

    prepared = prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=AgentState(),
        workspace=AgentWorkspace.open(tmp_path / "workspace"),
        resumed=False,
    )

    actions = prepared.validation_actions
    selected_ids = {
        str(candidate_id)
        for action in actions
        for candidate_id in action["source_candidate_ids"]
    }
    assert len(actions) == _UNIQUE_SOURCE_REQUEST_SHAPES
    assert len(selected_ids) == _UNIQUE_SOURCE_REQUEST_SHAPES
    assert {
        str(candidate["route"])
        for candidate in prepared.candidate_payloads
        if candidate["candidate_id"] in selected_ids
    } == {"/first", "/second"}


def test_prompt_candidates_reserve_non_sql_families_beyond_sql_backlog(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    sql_routes = "\n\n".join(
        f"""\
@app.get("/sql/{index:02d}")
def sql_{index:02d}(term_{index:02d}: str):
    return database.execute(term_{index:02d})
"""
        for index in range(70)
    )
    _write_source(
        source_root,
        f"""\
from fastapi import FastAPI
from flask import render_template_string

app = FastAPI()

{sql_routes}

@app.get("/template")
def template(value: str):
    return render_template_string(value)
""",
    )
    state = AgentState()

    prepared = prepare_source_guided_analysis(
        source_root=source_root,
        target_url="http://127.0.0.1:8765/",
        state=state,
        workspace=AgentWorkspace.open(tmp_path / "workspace"),
        resumed=False,
    )
    prompt = json.loads(state.to_prompt_context())

    assert len(prepared.candidate_payloads) == _MAX_PROMPT_SOURCE_CANDIDATES
    assert any(item["family"] == "ssti" for item in prepared.candidate_payloads)
    assert any(item["family"] == "ssti" for item in prompt["surface"]["source_candidates"])


def test_source_candidate_finds_unlinked_sqli_only_after_live_validation(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    _write_source(source_root)
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            parsed = urlsplit(self.path)
            value = parse_qs(parsed.query, keep_blank_values=True).get("term", [""])[-1]
            if parsed.path == "/unlinked/search" and "'" in value:
                body = "sqlite3.OperationalError: unrecognized token"
            elif parsed.path == "/unlinked/search":
                body = "[]"
            else:
                body = "home"
            encoded = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target_url = f"http://127.0.0.1:{server.server_port}/"
    try:
        blackbox_state = AgentState(
            surface={"target_url": target_url, "origin": target_url.rstrip("/")}
        )
        blackbox = run_builtin_probe(
            "sqli_differential",
            target_url=target_url,
            state=blackbox_state,
            timeout_seconds=2,
        )
        assert not blackbox.ok
        assert not any(path.startswith("/unlinked/search") for path in requests)

        requests.clear()
        state = AgentState()
        prepared = prepare_source_guided_analysis(
            source_root=source_root,
            target_url=target_url,
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            resumed=False,
        )
        assert not state.flags
        state.surface["source_validation_probe"] = "sqli_differential"
        state.surface["source_validation_candidate_ids"] = list(
            prepared.validation_actions[0]["source_candidate_ids"]
        )
        result = run_builtin_probe(
            "sqli_differential",
            target_url=target_url,
            state=state,
            timeout_seconds=2,
        )
        state.surface.pop("source_validation_probe", None)
        state.surface.pop("source_validation_candidate_ids", None)

        assert result.ok
        assert result.findings[0]["type"] == "sql_injection_error_signal"
        assert result.findings[0]["input"]["url"] == target_url + "unlinked/search"
        assert any(path.startswith("/unlinked/search") for path in requests)
        assert not any(path.startswith("/safe/search") for path in requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
