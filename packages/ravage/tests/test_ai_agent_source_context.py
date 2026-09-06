from __future__ import annotations

import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from typing import TYPE_CHECKING

import pytest
from ai_agent_fixtures import ScriptedModelClient
from ravage.agent_core import ai_agent
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _authenticated_model_action,
    _enforce_evidence_lead_action,
    _open_source_context_executor,
    _update_source_context_binding,
    _without_source_narrative,
    run_ai_web_agent,
)
from ravage.agent_core.evidence_lead_lock import EvidenceLead, _lead_fingerprint
from ravage.agent_core.source_context import SourceContextExecutor
from ravage.agent_core.source_navigation import (
    SourceNavigationPolicy,
    build_source_navigation_policy,
)
from ravage.repository_context import capture_repository
from ravage.runtime import NoProcessToolRuntime
from ravage.source_analysis import SourceChangedError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


SOURCE_SENTINEL = "SOURCE_SENTINEL_7d91c9f0"
SEARCH_SENTINEL = "SEARCH_ONLY_MARKER_16e2"


@pytest.fixture
def hidden_route_target() -> Iterator[tuple[str, list[str]]]:
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            body = b"hidden route reached" if self.path == "/hidden/admin" else b"root"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _write_brief(path: Path, target_url: str) -> None:
    path.write_text(
        (
            'engagement_id: "98989898-9898-4989-8989-989898989898"\n'
            "scope:\n"
            "  in_scope:\n"
            f'    - "{target_url}"\n'
            "  out_of_scope: []\n"
            "roe:\n"
            "  max_rps: 100\n"
            "  no_destructive_actions: true\n"
            '  data_handling: "placeholders_only"\n'
            "objectives:\n"
            '  - "web_application_assessment"\n'
            "budget:\n"
            "  max_cost_usd: 1.0\n"
            "  max_runtime_min: 10\n"
            "context:\n"
            "  description: Inspect the authorized local application.\n"
            "  win_condition: Exercise and assess reachable routes.\n"
        ),
        encoding="utf-8",
    )


def _write_source(root: Path) -> None:
    root.mkdir()
    root.joinpath("app.py").write_text(
        (
            "from flask import Flask\n"
            "\n"
            "app = Flask(__name__)\n"
            f'SOURCE_NOTE = "{SOURCE_SENTINEL}"\n'
            "\n"
            '@app.get("/hidden/admin")\n'
            "def hidden_admin():\n"
            "    return 'ok'\n"
            "\n"
            f"# {SEARCH_SENTINEL}\n"
        ),
        encoding="utf-8",
    )


def _prompt(model: ScriptedModelClient, index: int) -> dict[str, object]:
    return json.loads(model.messages_seen[index][-1].content)


def _source_gate_policy(tmp_path: Path) -> tuple[SourceNavigationPolicy, dict[str, object]]:
    source_root = tmp_path / "gate-source"
    source_root.mkdir()
    source_root.joinpath("app.py").write_text(
        (
            '@app.get("/hidden")\n'
            "def hidden():\n"
            '    return request.args.get("mode")\n'
        ),
        encoding="utf-8",
    )
    context = capture_repository(source_root)
    observation = SourceContextExecutor(context).execute(
        {
            "action": "source_context",
            "operation": "excerpt",
            "args": {"path": "app.py", "start_line": 1, "end_line": 3},
        }
    ).observation
    return build_source_navigation_policy(context), observation


def test_source_navigation_is_transient_and_can_drive_a_live_route(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    hidden_route_target: tuple[str, list[str]],
) -> None:
    target_url, requests = hidden_route_target
    brief_path = tmp_path / "brief.yaml"
    source_root = tmp_path / "source"
    workspace = tmp_path / "workspace"
    audit_path = tmp_path / "audit.db"
    _write_brief(brief_path, target_url)
    _write_source(source_root)
    model = ScriptedModelClient(
        [
            {
                "action": "source_context",
                "task_id": "surface-map",
                "operation": "search",
                "args": {"query": SEARCH_SENTINEL, "max_matches": 4},
            },
            {
                "action": "source_context",
                "task_id": "surface-map",
                "operation": "excerpt",
                "args": {"path": "app.py", "start_line": 1, "end_line": 8},
            },
            {
                "action": "http_request",
                "task_id": "surface-map",
                "method": "GET",
                "path": f"/hidden/admin?probe={SOURCE_SENTINEL}",
                "notes": SOURCE_SENTINEL,
            },
            {
                "action": "source_context",
                "task_id": "surface-map",
                "operation": "excerpt",
                "args": {"path": SOURCE_SENTINEL, "start_line": 1, "end_line": 1},
            },
            {
                "action": "source_context",
                "task_id": "surface-map",
                "operation": "excerpt",
                "args": {"path": "app.py", "start_line": 4, "end_line": 8},
            },
            {
                "action": "http_request",
                "task_id": "surface-map",
                "method": "GET",
                "path": "/hidden/admin",
                "notes": SOURCE_SENTINEL,
                "strategy": SOURCE_SENTINEL,
                "memory_updates": [SOURCE_SENTINEL],
                "hypotheses": [SOURCE_SENTINEL],
            },
        ]
    )
    monkeypatch.setattr(ai_agent, "_forced_evidence_probe_action", lambda **_kwargs: None)
    monkeypatch.setattr(ai_agent, "_forced_primitive_probe_action", lambda **_kwargs: None)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=target_url,
        settings=AIWebAgentSettings(
            source_root=source_root,
            allow_source_to_model=True,
            tool_runtime_mode="host",
            tool_runtime=NoProcessToolRuntime(),
            db_path=audit_path,
            workspace_dir=workspace,
            model_client=model,
            stdout=StringIO(),
            max_turns=6,
        ),
    )

    assert "source_context_observation" not in _prompt(model, 0)
    assert any(
        "Before generic vulnerability probes, inspect the repository now" in instruction
        for instruction in _prompt(model, 0)["tool_guidance"]
    )
    source_schema = _prompt(model, 0)["action_schema"]["source_context"]
    assert source_schema["valid_examples"][0]["args"] == {
        "prefix": "",
        "cursor": 0,
        "limit": 50,
    }
    assert _prompt(model, 1)["source_context_observation"]["operation"] == "search"
    assert SEARCH_SENTINEL in json.dumps(_prompt(model, 1))
    assert _prompt(model, 2)["source_context_observation"]["operation"] == "excerpt"
    assert SOURCE_SENTINEL in json.dumps(_prompt(model, 2))
    assert SEARCH_SENTINEL not in json.dumps(_prompt(model, 2))
    assert "source_context_observation" not in _prompt(model, 3)
    assert _prompt(model, 4)["source_context_observation"]["type"] == "error"
    assert _prompt(model, 5)["source_context_observation"]["operation"] == "excerpt"

    events = [
        json.loads(line)
        for line in workspace.joinpath("events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    selections = [
        event["payload"]["action"]
        for event in events
        if event["kind"] == "agent_action_selected"
    ]
    selection_payloads = [
        event["payload"] for event in events if event["kind"] == "agent_action_selected"
    ]
    assert selections[2]["action"] == "invalid"
    assert selections[3] == {
        "action": "source_context",
        "operation": "excerpt",
        "args": {"path_chars": len(SOURCE_SENTINEL), "start_line": 1, "end_line": 1},
    }
    assert selections[5] == {
        "action": "http_request",
        "method": "GET",
        "path": "/hidden/admin",
        "task_id": "surface-map",
    }
    assert selection_payloads[5]["source_informed"] is True
    assert "/hidden/admin" in requests
    assert all(SOURCE_SENTINEL not in request for request in requests)

    for artifact in [*workspace.rglob("*"), audit_path]:
        if artifact.is_file():
            contents = artifact.read_bytes()
            assert SOURCE_SENTINEL.encode() not in contents
            assert SEARCH_SENTINEL.encode() not in contents

    saved_envelope = json.loads(
        workspace.joinpath("working_state.json").read_text(encoding="utf-8")
    )
    saved = saved_envelope["state"]
    evidence_memory = json.dumps(
        {
            "facts": saved["facts"],
            "hypotheses": saved["hypotheses"],
            "last_observation": saved["last_observation"],
            "primitives": saved["primitives"],
        }
    )
    assert SOURCE_SENTINEL not in evidence_memory
    assert SEARCH_SENTINEL not in evidence_memory
    assert saved["actions"][-1]["source_informed"] is True
    assert saved["last_observation"]["source_informed"] is True


def test_final_harness_rewrite_cannot_bypass_source_navigation_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    hidden_route_target: tuple[str, list[str]],
) -> None:
    target_url, requests = hidden_route_target
    brief_path = tmp_path / "brief.yaml"
    source_root = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _write_brief(brief_path, target_url)
    _write_source(source_root)
    model = ScriptedModelClient(
        [
            {
                "action": "source_context",
                "task_id": "surface-map",
                "operation": "excerpt",
                "args": {"path": "app.py", "start_line": 4, "end_line": 8},
            },
            {
                "action": "http_request",
                "task_id": "surface-map",
                "method": "GET",
                "path": "/hidden/admin",
            },
        ]
    )
    original_selector = ai_agent._model_action_from_parsed  # noqa: SLF001

    def rewrite_after_source(
        action: dict[str, object],
        **kwargs: object,
    ) -> dict[str, object]:
        if action.get("action") == "source_context":
            return original_selector(action, **kwargs)  # type: ignore[arg-type]
        return {
            "action": "http_request",
            "method": "GET",
            "path": f"/{SOURCE_SENTINEL}",
        }

    monkeypatch.setattr(ai_agent, "_model_action_from_parsed", rewrite_after_source)
    monkeypatch.setattr(ai_agent, "_forced_evidence_probe_action", lambda **_kwargs: None)
    monkeypatch.setattr(ai_agent, "_forced_primitive_probe_action", lambda **_kwargs: None)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=target_url,
        settings=AIWebAgentSettings(
            source_root=source_root,
            allow_source_to_model=True,
            tool_runtime_mode="host",
            tool_runtime=NoProcessToolRuntime(),
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace,
            model_client=model,
            stdout=StringIO(),
            max_turns=2,
        ),
    )

    events = [
        json.loads(line)
        for line in workspace.joinpath("events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    selections = [
        event["payload"]["action"]
        for event in events
        if event["kind"] == "agent_action_selected"
    ]
    assert selections[-1]["action"] == "invalid"
    assert all(SOURCE_SENTINEL not in request for request in requests)
    assert SOURCE_SENTINEL.encode() not in workspace.joinpath("events.jsonl").read_bytes()


def test_source_root_alone_does_not_enable_model_source_actions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    hidden_route_target: tuple[str, list[str]],
) -> None:
    target_url, _requests = hidden_route_target
    brief_path = tmp_path / "brief.yaml"
    source_root = tmp_path / "source"
    _write_brief(brief_path, target_url)
    _write_source(source_root)
    model = ScriptedModelClient([{"action": "final", "summary": "done"}])
    monkeypatch.setattr(ai_agent, "_deterministic_harness_fallback", lambda **_kwargs: None)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=target_url,
        settings=AIWebAgentSettings(
            source_root=source_root,
            tool_runtime_mode="host",
            tool_runtime=NoProcessToolRuntime(),
            db_path=tmp_path / "audit.db",
            workspace_dir=tmp_path / "workspace",
            model_client=model,
            stdout=StringIO(),
            max_turns=1,
        ),
    )

    prompt = _prompt(model, 0)
    assert "source_context" not in prompt
    assert "source_context" not in prompt["action_schema"]
    assert SOURCE_SENTINEL not in json.dumps(prompt)


def test_identical_source_lookup_is_blocked_after_two_executions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    hidden_route_target: tuple[str, list[str]],
) -> None:
    target_url, _requests = hidden_route_target
    brief_path = tmp_path / "brief.yaml"
    source_root = tmp_path / "source"
    workspace = tmp_path / "workspace"
    _write_brief(brief_path, target_url)
    _write_source(source_root)
    repeated = {
        "action": "source_context",
        "task_id": "surface-map",
        "operation": "search",
        "args": {"query": SEARCH_SENTINEL, "max_matches": 2},
    }
    model = ScriptedModelClient([repeated, repeated, repeated])
    monkeypatch.setattr(ai_agent, "_deterministic_harness_fallback", lambda **_kwargs: None)

    run_ai_web_agent(
        brief_path=brief_path,
        target_url=target_url,
        settings=AIWebAgentSettings(
            source_root=source_root,
            allow_source_to_model=True,
            tool_runtime_mode="host",
            tool_runtime=NoProcessToolRuntime(),
            db_path=tmp_path / "audit.db",
            workspace_dir=workspace,
            model_client=model,
            stdout=StringIO(),
            max_turns=3,
        ),
    )

    events = [
        json.loads(line)
        for line in workspace.joinpath("events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    receipts = [
        event["payload"]["receipt"]
        for event in events
        if event["kind"] == "source_context_observed"
    ]
    assert [receipt["ok"] for receipt in receipts] == [True, True, False]
    assert receipts[2]["error_code"] == "identical_action_limit"
    assert receipts[2]["cumulative_observation_chars"] == receipts[1][
        "cumulative_observation_chars"
    ]
    assert SEARCH_SENTINEL.encode() not in workspace.joinpath("events.jsonl").read_bytes()


def test_post_source_gate_requires_visible_structural_path_and_query_names(
    tmp_path: Path,
) -> None:
    state = AgentState(
        tasks=[{"id": "surface-map", "status": "pending"}],
    )
    policy, observation = _source_gate_policy(tmp_path)
    allowed = _without_source_narrative(
        {
            "action": "http_request",
            "task_id": "surface-map",
            "method": "GET",
            "path": "/hidden?mode=",
            "notes": SOURCE_SENTINEL,
        },
        state=state,
        navigation_policy=policy,
        source_observation=observation,
    )
    blocked = _without_source_narrative(
        {
            "action": "http_request",
            "task_id": "unknown-task",
            "method": "GET",
            "path": f"/{SOURCE_SENTINEL}?{SOURCE_SENTINEL}=",
        },
        state=state,
        navigation_policy=policy,
        source_observation=observation,
    )

    assert allowed == {
        "action": "http_request",
        "task_id": "surface-map",
        "method": "GET",
        "path": "/hidden?mode=",
    }
    assert blocked["action"] == "invalid"
    assert SOURCE_SENTINEL not in json.dumps(blocked)


@pytest.mark.parametrize("value", ["1234", "admin", "abc123", "%31%32%33%34"])
def test_post_source_gate_rejects_every_nonempty_query_value(
    tmp_path: Path,
    value: str,
) -> None:
    state = AgentState(tasks=[{"id": "surface-map", "status": "pending"}])
    policy, observation = _source_gate_policy(tmp_path)

    blocked = _without_source_narrative(
        {
            "action": "http_request",
            "task_id": "surface-map",
            "method": "GET",
            "path": f"/hidden?mode={value}",
        },
        state=state,
        navigation_policy=policy,
        source_observation=observation,
    )

    assert blocked["action"] == "invalid"
    assert value not in json.dumps(blocked)


@pytest.mark.parametrize("kind", ["http_request", "run_probe"])
def test_post_source_gate_drops_timeout_and_unused_action_fields(
    tmp_path: Path,
    kind: str,
) -> None:
    copied_source = "SOURCE_TIMEOUT_SENTINEL_8c31"
    state = AgentState(tasks=[{"id": "surface-map", "status": "pending"}])
    action: dict[str, object] = {
        "action": kind,
        "task_id": "surface-map",
        "timeout_seconds": copied_source,
        "unused": copied_source,
    }
    if kind == "http_request":
        action.update({"method": "GET", "path": "/hidden"})
    else:
        action["probe"] = "surface_map"

    policy, observation = _source_gate_policy(tmp_path)
    safe = _without_source_narrative(
        action,
        state=state,
        navigation_policy=policy,
        source_observation=observation,
    )

    assert safe["action"] == kind
    assert copied_source not in json.dumps(safe)
    assert "timeout_seconds" not in safe
    assert "unused" not in safe


def test_post_source_gate_rejects_dual_http_locations() -> None:
    state = AgentState(tasks=[{"id": "surface-map", "status": "pending"}])

    blocked = _without_source_narrative(
        {
            "action": "http_request",
            "task_id": "surface-map",
            "method": "GET",
            "path": "/hidden",
            "url": "SOURCE_UNUSED_URL_SENTINEL_13ac",
        },
        state=state,
    )

    assert blocked["action"] == "invalid"
    assert "SOURCE_UNUSED_URL_SENTINEL_13ac" not in json.dumps(blocked)


def test_authenticated_protocol_preserves_enabled_source_action_fields() -> None:
    class Authentication:
        def __init__(self) -> None:
            self.protected_keys: dict[tuple[str, ...], object] = {}
            self.protected_values: dict[tuple[str, ...], object] = {}

        def redact_protocol(
            self,
            value: object,
            *,
            protected_keys: dict[tuple[str, ...], object],
            protected_field_values: dict[tuple[str, ...], object],
        ) -> object:
            self.protected_keys = protected_keys
            self.protected_values = protected_field_values
            return value

    authentication = Authentication()
    action = {
        "action": "source_context",
        "operation": "search",
        "args": {"query": "handler", "max_matches": 3},
    }

    safe = _authenticated_model_action(
        authentication,  # type: ignore[arg-type]
        action,
        allow_source_context=True,
    )

    assert safe == action
    assert "source_context" in authentication.protected_values[("action",)]
    assert "search" in authentication.protected_values[("operation",)]
    assert "query" in authentication.protected_keys[("args",)]


def test_active_evidence_lead_blocks_source_navigation() -> None:
    state = AgentState()
    lead = EvidenceLead(
        fingerprint="",
        family="template_injection",
        probe="ssti_fingerprint",
        finding_type="ssti_fingerprint_signal",
        method="POST",
        origin="https://target.example",
        endpoint="/render",
        inputs=("sentence",),
        input_locations=(("body", "sentence"),),
        request_inputs=(("body", "sentence"),),
        body_encoding="form",
        source_kind="tool_run_probe",
        source_observation_id="observation-one",
        stage="candidate",
    )
    state.surface["evidence_lead_lock"] = replace(
        lead,
        fingerprint=_lead_fingerprint(lead),
    ).to_json()

    selected, reason = _enforce_evidence_lead_action(
        state,
        {
            "action": "source_context",
            "operation": "search",
            "args": {"query": "render"},
        },
    )

    assert selected["action"] == "invalid"
    assert reason == "evidence_lead_lock"
    assert "source_context" in selected["raw"]


def test_source_context_resume_restores_budget_and_rejects_snapshot_drift(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    _write_source(source_root)
    context = capture_repository(source_root)
    state = AgentState()
    executor = _open_source_context_executor(context=context, state=state, resumed=False)
    assert executor is not None
    result = executor.execute(
        {
            "action": "source_context",
            "operation": "search",
            "args": {"query": SEARCH_SENTINEL},
        }
    )
    assert result.ok is True
    _update_source_context_binding(state, executor=executor)

    resumed = _open_source_context_executor(context=context, state=state, resumed=True)

    assert resumed is not None
    assert resumed.observation_chars_used == executor.observation_chars_used
    with pytest.raises(SourceChangedError, match="--allow-source-to-model"):
        _open_source_context_executor(context=None, state=state, resumed=True)

    source_root.joinpath("other.txt").write_text("snapshot drift\n", encoding="utf-8")
    with pytest.raises(SourceChangedError, match="repository context changed"):
        _open_source_context_executor(
            context=capture_repository(source_root),
            state=state,
            resumed=True,
        )
