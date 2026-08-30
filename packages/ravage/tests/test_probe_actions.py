from __future__ import annotations

import json
import sqlite3
import subprocess
from typing import TYPE_CHECKING, Never
from uuid import UUID, uuid4

import pytest
from pentest_schemas import Scope
from ravage.agent_core.action_executor import ActionResult, _clip_probe_text, execute_action
from ravage.agent_core.action_parser import parse_action
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.agent_strategy import observation_digest
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.agent_core.surface_graph_ingest import (
    SURFACE_OBSERVATION_BATCH_SCHEMA,
    SURFACE_OBSERVATION_INPUT_SCHEMA,
)
from ravage.probe_suite import available_probes
from ravage.probe_suite_parts.sqli.sqli_targets import _sqli_targets
from ravage.probe_suite_parts.support import _form_targets
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import ToolResult, ToolRuntime
from ravage.scan_planner import build_adaptive_scan_plan
from ravage.web_core.http_probe import ProbeResponse
from ravage.web_core.poc_validator import validate_http_poc

if TYPE_CHECKING:
    from pathlib import Path


def test_action_parser_accepts_probe_and_poc_actions() -> None:
    probe = parse_action('{"action":"run_probe","task_id":"surface-map","probe":"surface_map"}')
    poc = parse_action(
        '{"action":"validate_poc","task_id":"surface-map","steps":[{"url":"/","expect_status":200}]}'
    )

    assert probe["action"] == "run_probe"
    assert poc["action"] == "validate_poc"


def test_available_probes_cover_core_black_box_workflows() -> None:
    names = {item["name"] for item in available_probes()}

    assert {
        "surface_map",
        "secret_sweep",
        "input_reflection",
        "xss_context",
        "stateful_session",
        "csrf_session",
        "default_credentials",
        "server_rendering",
        "ssti_fingerprint",
        "data_query",
        "sqli_differential",
        "sqli_exploit",
        "filtered_query_bypass",
        "preg_match_subject",
        "direct_exposure",
        "command_boundary",
        "file_fetch_parser",
        "file_read_extract",
        "xxe_boundary",
        "api_behavior",
        "browser_boundary",
        "idor_boundary",
    }.issubset(names)


def test_executor_owned_probe_batch_feeds_canonical_surface_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = "http://127.0.0.1/"
    probe_text = json.dumps(
        {
            "ok": True,
            "probe": "surface_map",
            "summary": "typed adapter result",
            "findings": [
                {
                    "type": "surface_observation_batch",
                    "batch": {
                        "schema": SURFACE_OBSERVATION_BATCH_SCHEMA,
                        "observations": [
                            {
                                "schema": SURFACE_OBSERVATION_INPUT_SCHEMA,
                                "url": f"{target_url}external/items/123?token=not-persisted",
                                "method": "GET",
                                "identity_alias": "untrusted-adapter-identity",
                                "parameters": [{"name": "token", "location": "query"}],
                            }
                        ],
                    },
                }
            ],
            "requests": [],
            "errors": [],
        }
    )

    def runner(*args: object, **kwargs: object) -> _CompletedProbeRunner:
        del args, kwargs
        return _CompletedProbeRunner(json.dumps({"status": "ok", "ok": True, "text": probe_text}))

    _patch_probe_runner(monkeypatch, runner)
    state = AgentState(surface_graph=SurfaceGraphState.for_target(target_url))
    audit = AuditStore(tmp_path / "audit.db")
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "surface_map"},
            target_url=target_url,
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="typed-surface-adapter",
        )
    finally:
        audit.close()

    assert result.ok is True
    [operation] = (state.surface_graph.operations or {}).values()
    assert operation.route_shape == "/external/items/{int}"
    assert operation.provenance == ("external_tool",)
    [observation] = (state.surface_graph.observations or {}).values()
    assert observation.identity_alias == "anonymous"
    assert "not-persisted" not in json.dumps(state.surface_graph.to_json())


def test_browser_attack_traffic_cannot_fabricate_future_forms_or_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = "http://127.0.0.1/"
    attack_url = f"{target_url}fabricated-login?username=attack&password=attack"
    fabricated_form = (
        '<form action="/fabricated-login" method="post">'
        '<input name="username"><input name="password"></form>'
    )
    probe_text = json.dumps(
        {
            "ok": True,
            "probe": "browser_boundary",
            "summary": "attack response contained target-controlled markup",
            "findings": [
                {
                    "type": "clickjacking_frame_policy_missing",
                    "url": attack_url,
                    "body_snippet": fabricated_form,
                }
            ],
            "requests": [
                {
                    "method": "POST",
                    "url": attack_url,
                    "status": 200,
                    "body_snippet": fabricated_form,
                    "request_headers": {"X-Ravage-Probe": "attack"},
                    "probe_kind": "browser_boundary_attack",
                },
                {
                    "method": "GET",
                    "url": f"{target_url}fabricated-admin?tenant=attack",
                    "status": 403,
                    "body_snippet": "access denied",
                    "probe_kind": "browser_boundary_attack",
                },
            ],
            "errors": [],
        }
    )

    def runner(*args: object, **kwargs: object) -> _CompletedProbeRunner:
        del args, kwargs
        return _CompletedProbeRunner(
            json.dumps({"status": "ok", "ok": True, "text": probe_text})
        )

    _patch_probe_runner(monkeypatch, runner)
    state = AgentState(
        surface={"target_url": target_url, "origin": target_url.rstrip("/")},
        surface_graph=SurfaceGraphState.for_target(target_url),
    )
    targets_before = _sqli_targets(state)
    plan_before = build_adaptive_scan_plan(state).probes
    audit = AuditStore(tmp_path / "audit.db")
    try:
        execute_action(
            {"action": "run_probe", "probe": "browser_boundary"},
            target_url=target_url,
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=8_000,
        )
    finally:
        audit.close()

    attempts = tuple((state.surface_graph.operations or {}).values())
    assert {attempt.route_shape for attempt in attempts} == {
        "/fabricated-admin",
        "/fabricated-login",
    }
    assert all(attempt.provenance == ("probe",) for attempt in attempts)
    assert all(attempt.actionable is False for attempt in attempts)
    assert all(attempt.parameters == () for attempt in attempts)
    assert len(state.surface_graph.observations or {}) == 2
    prompt_graph = state.surface_graph.to_prompt_json()
    assert prompt_graph["operations"] == []
    assert prompt_graph["counts"] == {
        "operations": 2,
        "candidate_operations": 0,
        "identity_observations": 2,
    }
    assert state.surface.get("endpoints") == []
    assert state.surface.get("request_templates") == []
    assert state.surface.get("parameters") == []
    assert _form_targets(state, limit=10) == []
    assert _sqli_targets(state) == targets_before
    plan_after = build_adaptive_scan_plan(state)
    assert plan_after.probes == plan_before
    assert "parameter" not in plan_after.evidence_facts
    for key in ("forms", "endpoints", "parameters", "request_templates"):
        assert not state.signals.get(key)


def test_validate_http_poc_replays_same_origin_expectations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ravage.web_core.poc_validator.ProbeSession", _FakeProbeSession)

    result = validate_http_poc(
        target_url="http://127.0.0.1/",
        steps=[
            {
                "method": "GET",
                "url": "/",
                "expect_status": 200,
                "expect_contains": "proof-token",
            }
        ],
        timeout_seconds=5,
    )

    assert result.ok
    assert result.summary == "replayed HTTP sequence; checks passed 2/2"


def test_validate_poc_promotes_executor_owned_non_flag_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _SqlErrorProbeSession,
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    engagement_id = uuid4()
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    action = {
        "action": "validate_poc",
        "task_id": "data-query",
        "steps": [
            {
                "method": "GET",
                "url": "/search?q=%27",
                "evidence_role": "exploit",
                "expect_status": 200,
                "expect_contains": "SQLite syntax error",
            },
            {
                "method": "GET",
                "url": "/search?q=ravage-control",
                "evidence_role": "control",
                "expect_status": 200,
            },
        ],
        "finding": {
            "vuln_class": "sql_injection",
            "severity": "critical",
            "hypothesis": "The q parameter reaches an SQL query.",
            "impact": "Model claims total infrastructure compromise.",
            "exploit_steps": ["Send an apostrophe in q and observe the response."],
            "proof": {"response_final": "model-authored proof must be ignored"},
        },
    }
    try:
        outcome = execute_action(
            action,
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="poc-finding-action",
        )
        duplicate = execute_action(
            action,
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="poc-finding-action-replay",
        )
        assert audit.count_findings(status="confirmed") == 1
    finally:
        audit.close()

    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    confirmed = next(event for event in events if event["kind"] == "finding_confirmed")
    assert sum(event["kind"] == "finding_confirmed" for event in events) == 1
    payload = confirmed["payload"]
    assert outcome.ok is True
    assert outcome.outcome == "finding_confirmed"
    assert duplicate.outcome == "same_as_before"
    assert outcome.flag == ""
    assert payload["vuln_class"] == "sql_injection"
    assert payload["severity"] == "High"
    assert payload["assessment_source"] == "executor_policy"
    assert payload["impact"] != action["finding"]["impact"]
    assert payload["endpoint"] == {
        "method": "GET",
        "url": "http://127.0.0.1/search",
        "params": [{"location": "query", "name": "q"}],
    }
    assert payload["evidence_checks"] == {"passed": 3, "required": 3}
    assert payload["evidence_kind"] == "http_poc_replay"
    assert payload["source_kind"] == "tool_validate_poc"
    assert payload["source_observation_id"]
    assert payload["action_id"] == "poc-finding-action"
    assert payload["finding_record_path"] == str(workspace.events_path)
    assert "%27" in payload["proof"]["http_request_final"]
    assert [step["evidence_role"] for step in payload["exploit_steps"]] == [
        "exploit",
        "control",
    ]
    assert "model-authored proof" not in json.dumps(payload["proof"])
    with sqlite3.connect(tmp_path / "audit.db") as conn:
        actions = [row[0] for row in conn.execute("SELECT action FROM audit_log")]
        stored_payload = json.loads(conn.execute("SELECT payload_json FROM findings").fetchone()[0])
    assert actions.count("finding_confirmed") == 1
    assert stored_payload["finding_id"] == payload["finding_id"]
    assert stored_payload["vuln_class"] == "sql_injection"


def test_validate_poc_keeps_distinct_affected_parameters_and_merges_duplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_finding_count = 2
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _SqlErrorProbeSession,
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    engagement_id = uuid4()
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")

    def action_for(parameter: str) -> dict[str, object]:
        exploit_values = {"alpha": "plain", "beta": "plain"}
        exploit_values[parameter] = "%27"
        return {
            "action": "validate_poc",
            "steps": [
                {
                    "method": "GET",
                    "url": (
                        "/lookup?alpha="
                        f"{exploit_values['alpha']}&beta={exploit_values['beta']}"
                    ),
                    "evidence_role": "exploit",
                    "expect_contains": "SQLite syntax error",
                },
                {
                    "method": "GET",
                    "url": "/lookup?alpha=plain&beta=plain",
                    "evidence_role": "control",
                    "expect_status": 200,
                },
            ],
            "finding": _finding_metadata("sql_injection"),
        }

    try:
        first = execute_action(
            action_for("alpha"),
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="validated-alpha",
        )
        duplicate = execute_action(
            action_for("alpha"),
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="validated-alpha-duplicate",
        )
        second = execute_action(
            action_for("beta"),
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="validated-beta",
        )
        assert audit.count_findings(status="confirmed") == expected_finding_count
    finally:
        audit.close()

    confirmed = [
        json.loads(line)["payload"]
        for line in workspace.events_path.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["kind"] == "finding_confirmed"
    ]
    assert first.outcome == "finding_confirmed"
    assert duplicate.outcome == "same_as_before"
    assert second.outcome == "finding_confirmed"
    assert len(confirmed) == expected_finding_count
    assert confirmed[0]["endpoint"] == confirmed[1]["endpoint"]
    assert confirmed[0]["finding_id"] != confirmed[1]["finding_id"]
    assert {
        finding["input"]["affected_parameters"][0]["name"]
        for finding in confirmed
    } == {"alpha", "beta"}


def test_confirmation_retry_repairs_row_only_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _SqlErrorProbeSession,
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    engagement_id = uuid4()
    audit = AuditStore(tmp_path / "audit.db")
    original_record = audit.record

    def fail_after_finding_row(**kwargs: object) -> None:
        if kwargs.get("action") == "finding_confirmed":
            message = "injected failure after finding row"
            raise RuntimeError(message)
        original_record(**kwargs)

    monkeypatch.setattr(audit, "record", fail_after_finding_row)
    try:
        with pytest.raises(RuntimeError, match="after finding row"):
            _execute_sql_finding_confirmation(
                workspace=workspace,
                audit=audit,
                engagement_id=engagement_id,
                action_id="row-only-first",
            )

        with sqlite3.connect(tmp_path / "audit.db") as conn:
            finding_id = str(conn.execute("SELECT finding_id FROM findings").fetchone()[0])
        assert not audit.has_finding_action(
            "finding_confirmed",
            engagement_id=engagement_id,
            finding_id=finding_id,
        )

        monkeypatch.setattr(audit, "record", original_record)
        recovered = _execute_sql_finding_confirmation(
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id="row-only-retry",
        )
    finally:
        audit.close()

    assert recovered.outcome == "finding_confirmed"
    _assert_single_complete_finding_bundle(
        workspace=workspace,
        db_path=tmp_path / "audit.db",
    )


def test_confirmation_retry_repairs_finding_audit_event_only_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _SqlErrorProbeSession,
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    engagement_id = uuid4()
    audit = AuditStore(tmp_path / "audit.db")
    original_record_event = AgentWorkspace.record_event

    def fail_before_finding_workspace_event(
        target: AgentWorkspace,
        *,
        kind: str,
        payload: object,
    ) -> str:
        if target is workspace and kind == "finding_confirmed":
            message = "injected failure before finding workspace event"
            raise RuntimeError(message)
        return original_record_event(target, kind=kind, payload=payload)

    monkeypatch.setattr(AgentWorkspace, "record_event", fail_before_finding_workspace_event)
    try:
        with pytest.raises(RuntimeError, match="before finding workspace event"):
            _execute_sql_finding_confirmation(
                workspace=workspace,
                audit=audit,
                engagement_id=engagement_id,
                action_id="finding-event-first",
            )

        with sqlite3.connect(tmp_path / "audit.db") as conn:
            finding_id = str(conn.execute("SELECT finding_id FROM findings").fetchone()[0])
        assert audit.has_finding_action(
            "finding_confirmed",
            engagement_id=engagement_id,
            finding_id=finding_id,
        )

        monkeypatch.setattr(AgentWorkspace, "record_event", original_record_event)
        recovered = _execute_sql_finding_confirmation(
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id="finding-event-retry",
        )
    finally:
        audit.close()

    assert recovered.outcome == "finding_confirmed"
    _assert_single_complete_finding_bundle(
        workspace=workspace,
        db_path=tmp_path / "audit.db",
    )


def _execute_sql_finding_confirmation(
    *,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
) -> ActionResult:
    return execute_action(
        {
            "action": "validate_poc",
            "steps": [
                {
                    "method": "GET",
                    "url": "/search?q=%27",
                    "evidence_role": "exploit",
                    "expect_contains": "SQLite syntax error",
                },
                {
                    "method": "GET",
                    "url": "/search?q=ravage-control",
                    "evidence_role": "control",
                    "expect_status": 200,
                },
            ],
            "finding": _finding_metadata("sql_injection"),
        },
        target_url="http://127.0.0.1/",
        runtime=_ProofRuntime(),
        state=AgentState(),
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
        repeat_count=1,
        max_observation_chars=2_000,
        max_transcript_chars=4_000,
        action_id=action_id,
    )


def _assert_single_complete_finding_bundle(
    *,
    workspace: AgentWorkspace,
    db_path: Path,
) -> None:
    events = [
        json.loads(line) for line in workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    confirmed = [event for event in events if event["kind"] == "finding_confirmed"]
    assert len(confirmed) == 1
    with sqlite3.connect(db_path) as conn:
        actions = [row[0] for row in conn.execute("SELECT action FROM audit_log")]
        finding_rows = conn.execute("SELECT payload_json FROM findings").fetchall()
    assert len(finding_rows) == 1
    stored_payload = json.loads(finding_rows[0][0])
    assert actions.count("finding_confirmed") == 1
    assert stored_payload["status"] == "confirmed"
    assert stored_payload["finding_id"] == confirmed[0]["payload"]["finding_id"]


def test_validate_poc_rejects_finding_without_explicit_expectation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ravage.web_core.poc_validator.ProbeSession", _FakeProbeSession)
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "validate_poc",
                "steps": [{"method": "GET", "url": "/debug"}],
                "finding": _finding_metadata("information_disclosure"),
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="poc-no-expectation",
        )
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()

    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    rejected = next(event for event in events if event["kind"] == "finding_rejected_no_evidence")
    assert outcome.ok is False
    assert outcome.outcome == "blocked"
    assert "explicit passed expectation" in rejected["payload"]["reason"]


def test_validate_poc_does_not_confirm_xss_from_plain_reflection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ravage.web_core.poc_validator.ProbeSession", _FakeProbeSession)
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "validate_poc",
                "steps": [
                    {
                        "method": "GET",
                        "url": "/search?q=proof-token",
                        "expect_contains": "proof-token",
                    }
                ],
                "finding": _finding_metadata("xss"),
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="poc-reflection-only",
        )
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()

    assert outcome.ok is False
    assert "client-side execution" in outcome.observation


def test_validate_poc_rejects_finding_with_out_of_scope_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _OutOfScopeProbeSession,
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(
        tmp_path / "audit.db",
        scope=Scope(in_scope=["http://127.0.0.1/"], out_of_scope=[]),
    )
    try:
        outcome = execute_action(
            {
                "action": "validate_poc",
                "steps": [
                    {
                        "method": "GET",
                        "url": "/debug?view=control",
                        "evidence_role": "control",
                        "expect_status": 200,
                    },
                    {
                        "method": "GET",
                        "url": "/debug?view=exploit",
                        "evidence_role": "exploit",
                        "expect_contains": "proof-token",
                    },
                ],
                "finding": _finding_metadata("information_disclosure"),
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="poc-out-of-scope",
        )
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()

    assert outcome.ok is False
    assert "outside engagement scope" in outcome.observation


def test_validate_poc_rejects_generic_differential_as_sql_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _OrdinaryDifferentialProbeSession,
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "validate_poc",
                "steps": [
                    {
                        "method": "GET",
                        "url": "/account?role=guest",
                        "evidence_role": "control",
                        "expect_contains": "signed out",
                    },
                    {
                        "method": "GET",
                        "url": "/account?role=admin",
                        "evidence_role": "exploit",
                        "expect_contains": "welcome admin",
                    },
                ],
                "finding": _finding_metadata("sql_injection"),
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="poc-generic-differential",
        )
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()

    assert outcome.ok is False
    assert "injection-shaped exploit input" in outcome.observation
    assert "database error" in outcome.observation


def test_validate_poc_does_not_treat_reflected_sql_error_text_as_database_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _ReflectedSqlMarkerProbeSession,
    )
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "validate_poc",
                "steps": [
                    {
                        "method": "GET",
                        "url": "/search?q=control",
                        "evidence_role": "control",
                        "expect_contains": "control",
                    },
                    {
                        "method": "GET",
                        "url": "/search?q=%27SQLite%20syntax%20error",
                        "evidence_role": "exploit",
                        "expect_contains": "SQLite syntax error",
                    },
                ],
                "finding": _finding_metadata("sql_injection"),
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=AgentState(),
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
            action_id="reflected-sql-marker",
        )
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()

    assert outcome.outcome == "blocked"
    assert "executor-observed database error" in outcome.observation


def test_validate_poc_uses_typed_ssti_and_file_read_validators(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _TypedReplayProbeSession,
    )
    cases = [
        (
            "ssti",
            [
                {
                    "method": "GET",
                    "url": "/render?name=ravage-control",
                    "evidence_role": "control",
                    "expect_contains": "Hello control",
                },
                {
                    "method": "GET",
                    "url": "/render?name=%7B%7B137*139%7D%7D",
                    "evidence_role": "exploit",
                    "expect_contains": "19043",
                },
            ],
            "ssti",
        ),
        (
            "lfi",
            [
                {
                    "method": "GET",
                    "url": "/download?file=public.txt",
                    "evidence_role": "control",
                    "expect_contains": "public document",
                },
                {
                    "method": "GET",
                    "url": "/download?file=..%2F..%2Fetc%2Fpasswd",
                    "evidence_role": "exploit",
                    "expect_contains": "root:x:0:0:",
                },
            ],
            "path_traversal",
        ),
    ]

    for index, (claimed_class, steps, expected_class) in enumerate(cases):
        case_dir = tmp_path / str(index)
        workspace = AgentWorkspace.open(case_dir / "workspace")
        audit = AuditStore(case_dir / "audit.db")
        try:
            outcome = execute_action(
                {
                    "action": "validate_poc",
                    "steps": steps,
                    "finding": _finding_metadata(claimed_class),
                },
                target_url="http://127.0.0.1/",
                runtime=_ProofRuntime(),
                state=AgentState(),
                workspace=workspace,
                audit=audit,
                engagement_id=uuid4(),
                repeat_count=1,
                max_observation_chars=2_000,
                max_transcript_chars=4_000,
                action_id=f"typed-finding-{index}",
            )
            assert audit.count_findings(status="confirmed") == 1
        finally:
            audit.close()

        events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
        confirmed = next(event for event in events if event["kind"] == "finding_confirmed")
        assert outcome.outcome == "finding_confirmed"
        assert confirmed["payload"]["vuln_class"] == expected_class


def test_typed_validators_require_class_payload_to_be_introduced_by_exploit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.poc_validator.ProbeSession",
        _SameClassPayloadProbeSession,
    )
    cases = [
        (
            "sql_injection",
            "/search?q=%27&variant=control",
            "/search?q=%27&variant=exploit",
            "SQLite syntax error",
            "injection-shaped exploit input",
        ),
        (
            "ssti",
            "/render?name=%7B%7B7*7%7D%7D&variant=control",
            "/render?name=%7B%7B137*139%7D%7D&variant=exploit",
            "19043",
            "bounded arithmetic template expression",
        ),
        (
            "path_traversal",
            "/download?file=..%2F..%2Fetc%2Fpasswd&variant=control",
            "/download?file=..%2F..%2Fetc%2Fpasswd&variant=exploit",
            "root:x:0:0:",
            "traversal-shaped exploit input",
        ),
    ]

    for index, (vuln_class, control_url, exploit_url, marker, rejection) in enumerate(cases):
        case_dir = tmp_path / str(index)
        audit = AuditStore(case_dir / "audit.db")
        try:
            outcome = execute_action(
                {
                    "action": "validate_poc",
                    "steps": [
                        {
                            "method": "GET",
                            "url": control_url,
                            "evidence_role": "control",
                            "expect_contains": "control",
                        },
                        {
                            "method": "GET",
                            "url": exploit_url,
                            "evidence_role": "exploit",
                            "expect_contains": marker,
                        },
                    ],
                    "finding": _finding_metadata(vuln_class),
                },
                target_url="http://127.0.0.1/",
                runtime=_ProofRuntime(),
                state=AgentState(),
                workspace=AgentWorkspace.open(case_dir / "workspace"),
                audit=audit,
                engagement_id=uuid4(),
                repeat_count=1,
                max_observation_chars=2_000,
                max_transcript_chars=4_000,
                action_id=f"same-class-payload-{index}",
            )
            assert audit.count_findings(status="confirmed") == 0
        finally:
            audit.close()

        assert outcome.outcome == "blocked"
        assert rejection in outcome.observation


def test_terminal_proof_recognition_is_disabled_by_default(tmp_path: Path) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_command",
                "task_id": "surface-map",
                "command": "echo proof",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
        )
    finally:
        audit.close()

    assert not outcome.stop
    assert outcome.flag == ""
    assert state.flags == []


def test_terminal_proof_recognition_is_benchmark_gated(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_command",
                "task_id": "surface-map",
                "command": "echo proof",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert outcome.stop
    assert outcome.flag == "flag{terminal_fallback_proof}"
    assert state.flags == ["flag{terminal_fallback_proof}"]
    assert capsys.readouterr().out == ""


def test_process_output_admits_only_one_proof_per_observation(tmp_path: Path) -> None:
    class TwoProofRuntime(_ProofRuntime):
        def run_command(
            self,
            *,
            command: str,
            target_url: str,
            timeout_seconds: int | None = None,
        ) -> ToolResult:
            del command, target_url, timeout_seconds
            return ToolResult(
                ok=True,
                tool="command",
                command=("sh", "-lc", "echo proof"),
                exit_code=0,
                stdout="flag{process_one} flag{process_two}",
                stderr="",
            )

    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {"action": "run_command", "task_id": "surface-map", "command": "echo proof"},
            target_url="http://127.0.0.1/",
            runtime=TwoProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert outcome.flag == "flag{process_one}"
    assert state.flags == ["flag{process_one}"]
    assert state.last_observation["recognized_proofs"] == ["flag{process_one}"]


def test_long_tool_action_result_preserves_stdout_head_and_tail(tmp_path: Path) -> None:
    class LongOutputRuntime(_ProofRuntime):
        def run_command(
            self,
            *,
            command: str,
            target_url: str,
            timeout_seconds: int | None = None,
        ) -> ToolResult:
            del command, target_url, timeout_seconds
            return ToolResult(
                ok=True,
                tool="command",
                command=("sh", "-lc", "wrapper " + ("W" * 80_000)),
                exit_code=0,
                stdout="STDOUT_HEAD_SIGNAL\n" + ("X" * 80_000) + "\nSTDOUT_TAIL_SIGNAL",
                stderr="",
            )

    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {"action": "run_command", "task_id": "surface-map", "command": "wrapper"},
            target_url="http://127.0.0.1/",
            runtime=LongOutputRuntime(),
            state=AgentState(),
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=10_000,
            max_transcript_chars=80_000,
        )
    finally:
        audit.close()

    assert len(outcome.observation) <= 10_000
    payload = json.loads(outcome.observation)
    assert "STDOUT_HEAD_SIGNAL" in payload["stdout"]
    assert "STDOUT_TAIL_SIGNAL" in payload["stdout"]


@pytest.mark.parametrize("action_name", ["run_command", "run_python"])
def test_local_process_markers_do_not_claim_target_confirmation(
    tmp_path: Path,
    action_name: str,
) -> None:
    class PrintedMarkerRuntime(_ProofRuntime):
        def run_command(
            self,
            *,
            command: str,
            target_url: str,
            timeout_seconds: int | None = None,
        ) -> ToolResult:
            del command, target_url, timeout_seconds
            return ToolResult(
                ok=True,
                tool="command",
                command=("sh", "-lc", "local-helper"),
                exit_code=0,
                stdout="SQL syntax error and root:x:0:0: from a local fixture",
                stderr="",
            )

        def run_python(
            self,
            *,
            code: str,
            target_url: str,
            timeout_seconds: int | None = None,
        ) -> ToolResult:
            del code
            return self.run_command(command="", target_url=target_url, timeout_seconds=timeout_seconds)

    action = {"action": action_name, "task_id": "surface-map"}
    action["command" if action_name == "run_command" else "code"] = "local-helper"
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            action,
            target_url="http://127.0.0.1/",
            runtime=PrintedMarkerRuntime(),
            state=AgentState(),
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=4_000,
        )

        assert outcome.outcome == "observed"
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()


def test_terminal_proof_recognition_ignores_bare_braced_decoys(tmp_path: Path) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_command",
                "task_id": "surface-map",
                "command": "echo proof",
            },
            target_url="http://127.0.0.1/",
            runtime=_BareBracedProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert not outcome.stop
    assert outcome.flag == ""
    assert state.flags == []


def test_terminal_proof_recognition_ignores_command_arguments(tmp_path: Path) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_command",
                "task_id": "surface-map",
                "command": "python3 -c \"print('FLAG{command_argument_only}')\"",
            },
            target_url="http://127.0.0.1/",
            runtime=_CommandOnlyProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert not outcome.stop
    assert outcome.flag == ""
    assert state.flags == []


def test_terminal_proof_recognition_rejects_session_hashes(tmp_path: Path) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_command",
                "task_id": "surface-map",
                "command": "curl -i target",
            },
            target_url="http://127.0.0.1/",
            runtime=_SessionHashRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert not outcome.stop
    assert outcome.flag == ""
    assert state.flags == []


def test_capture_flag_rejects_urls_and_credentials(tmp_path: Path) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    try:
        for value in ("http://127.0.0.1/dashboard", "/dashboard", "test:test", "session=abc123"):
            outcome = execute_action(
                {
                    "action": "capture_flag",
                    "task_id": "stateful-session",
                    "flag": value,
                    "evidence": "not a proof",
                },
                target_url="http://127.0.0.1/",
                runtime=_ProofRuntime(),
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=uuid4(),
                repeat_count=1,
                max_observation_chars=2000,
                max_transcript_chars=4000,
            )
            assert outcome.ok is False
            assert outcome.stop is False
    finally:
        audit.close()

    assert state.flags == []


def test_capture_flag_rejects_templated_placeholder_flags(tmp_path: Path) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    try:
        for value in ("FLAG{...}", "FLAG{your_flag_here}", "flag{REPLACE_ME}", "FLAG{<flag>}"):
            outcome = execute_action(
                {
                    "action": "capture_flag",
                    "task_id": "stateful-session",
                    "flag": value,
                    "evidence": "placeholder, not a captured proof",
                },
                target_url="http://127.0.0.1/",
                runtime=_ProofRuntime(),
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=uuid4(),
                repeat_count=1,
                max_observation_chars=2000,
                max_transcript_chars=4000,
            )
            assert outcome.ok is False
            assert outcome.stop is False
    finally:
        audit.close()

    assert state.flags == []


def test_capture_flag_rejects_malformed_non_proofs(tmp_path: Path) -> None:
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    try:
        for value in ("{{{{{{{{{{", "aaaaaaaaaaaaaaaaaaaaaaaa", "the flag is probably admin"):
            outcome = execute_action(
                {
                    "action": "capture_flag",
                    "task_id": "stateful-session",
                    "flag": value,
                    "evidence": "not a recognized proof",
                },
                target_url="http://127.0.0.1/",
                runtime=_ProofRuntime(),
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=uuid4(),
                repeat_count=1,
                max_observation_chars=2000,
                max_transcript_chars=4000,
            )
            assert outcome.ok is False
            assert outcome.stop is False
    finally:
        audit.close()

    assert state.flags == []


def test_capture_flag_accepts_observed_proof(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = AgentState()
    state.last_observation = {
        "snippet": "target response contained flag{observed_capture_proof}",
        "observation_id": "target-observation-1",
        "source_kind": "tool_run_probe",
        "recognized_proofs": ["flag{observed_capture_proof}"],
    }
    audit = AuditStore(tmp_path / "audit.db")
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    try:
        outcome = execute_action(
            {
                "action": "capture_flag",
                "task_id": "stateful-session",
                "flag": "flag{observed_capture_proof}",
                "evidence": "copied from target response",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            action_id="capture-observed",
        )
    finally:
        audit.close()

    assert outcome.ok is True
    assert outcome.stop is True
    assert outcome.evidence_source_kind == "tool_run_probe"
    assert state.flags == ["flag{observed_capture_proof}"]
    events = [
        json.loads(line) for line in workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    captured = next(event for event in events if event["kind"] == "flag_captured")
    assert captured["payload"]["action_id"] == "capture-observed"
    assert capsys.readouterr().out == ""


def test_rejected_capture_cannot_seed_its_own_evidence(tmp_path: Path) -> None:
    proof = "flag{model_authored_guess}"
    state = AgentState()
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    action = {
        "action": "capture_flag",
        "task_id": "stateful-session",
        "flag": proof,
        "evidence": "model claim",
    }
    try:
        first = execute_action(
            action,
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
        )
        state.last_observation = observation_digest(first.observation)
        second = execute_action(
            action,
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=2,
            max_observation_chars=2000,
            max_transcript_chars=4000,
        )
    finally:
        audit.close()

    assert first.outcome == "blocked"
    assert second.outcome == "blocked"
    assert state.flags == []


def test_capture_flag_treats_known_proof_as_non_material(tmp_path: Path) -> None:
    proof = "flag{observed_capture_proof}"
    state = AgentState(flags=[proof])
    events: list[dict[str, object]] = []
    workspace = AgentWorkspace.open(tmp_path / "workspace", event_sink=events.append)
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "capture_flag",
                "task_id": "stateful-session",
                "flag": proof,
                "evidence": "copied from an earlier target response",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            action_id="capture-duplicate",
        )
    finally:
        audit.close()

    assert outcome.ok is True
    assert outcome.stop is False
    assert outcome.outcome == "same_as_before"
    assert outcome.flag == ""
    assert state.flags == [proof]
    assert not any(event["kind"] == "flag_captured" for event in events)
    duplicate = next(event for event in events if event["kind"] == "flag_capture_duplicate")
    assert duplicate["payload"]["action_id"] == "capture-duplicate"


def test_capture_flag_rejects_unobserved_proof_shaped_guess(tmp_path: Path) -> None:
    state = AgentState()
    state.last_observation = {"snippet": "target response did not contain the submitted proof"}
    audit = AuditStore(tmp_path / "audit.db")
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    try:
        outcome = execute_action(
            {
                "action": "capture_flag",
                "task_id": "stateful-session",
                "flag": "flag{hidden_posts_in_secret_category}",
                "evidence": "inferred from page purpose",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
        )
    finally:
        audit.close()

    assert outcome.ok is False
    assert outcome.stop is False
    assert state.flags == []


def test_capture_flag_rejects_model_authored_evidence_containing_guess(
    tmp_path: Path,
) -> None:
    flag = "flag{model_authored_evidence_is_not_observation}"
    state = AgentState()
    state.last_observation = {"snippet": "target returned no proof"}
    state.facts.append(flag)
    state.hypotheses.append(flag)
    audit = AuditStore(tmp_path / "audit.db")
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    try:
        outcome = execute_action(
            {
                "action": "capture_flag",
                "task_id": "stateful-session",
                "flag": flag,
                "evidence": flag,
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
        )
    finally:
        audit.close()

    assert outcome.ok is False
    assert outcome.stop is False
    assert state.flags == []


def test_builtin_probe_output_proof_fallback_is_benchmark_gated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_proof)
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "surface-map",
                "probe": "surface_map",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
        )
    finally:
        audit.close()

    assert not outcome.stop
    assert outcome.flag == ""
    assert state.flags == []


def test_builtin_probe_output_auto_captures_when_benchmark_gated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_proof)
    state = AgentState()
    events: list[dict[str, object]] = []
    workspace = AgentWorkspace.open(tmp_path / "workspace", event_sink=events.append)
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "data-query",
                "probe": "sqli_differential",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
            action_id="probe-auto-capture",
        )
    finally:
        audit.close()

    assert outcome.stop
    assert outcome.flag == "flag{probe_auto_capture_123}"
    assert state.flags == ["flag{probe_auto_capture_123}"]
    captured = next(event for event in events if event["kind"] == "flag_captured")
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["action_id"] == "probe-auto-capture"
    assert payload["flag_record_path"] == str(workspace.events_path)


def test_builtin_probe_auto_captures_all_novel_proofs_from_one_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_two_proofs)
    events: list[dict[str, object]] = []
    state = AgentState()
    workspace = AgentWorkspace.open(tmp_path / "workspace", event_sink=events.append)
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "data-query",
                "probe": "sqli_differential",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
            action_id="probe-two-proofs",
        )
    finally:
        audit.close()

    assert outcome.outcome == "flag_candidate"
    assert len(state.flags) == 2
    captured = [event for event in events if event["kind"] == "flag_captured"]
    assert len(captured) == 2
    assert {event["payload"]["action_id"] for event in captured} == {"probe-two-proofs"}


def test_broad_probe_fallback_prefers_a_novel_proof_after_a_known_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_known_then_novel_proof)
    state = AgentState(flags=["flag{known_first}"])
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "surface-map",
                "probe": "surface_map",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert outcome.flag == "flag{novel_second}"
    assert state.flags == ["flag{known_first}", "flag{novel_second}"]
    assert state.last_observation["recognized_proofs"] == ["flag{novel_second}"]


def test_builtin_probe_known_proof_replay_is_non_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_proof)
    proof = "flag{probe_auto_capture_123}"
    state = AgentState(flags=[proof])
    events: list[dict[str, object]] = []
    workspace = AgentWorkspace.open(tmp_path / "workspace", event_sink=events.append)
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "data-query",
                "probe": "sqli_differential",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
            action_id="probe-known-proof",
        )
    finally:
        audit.close()

    assert outcome.stop is False
    assert outcome.outcome == "same_as_before"
    assert outcome.flag == ""
    assert state.flags == [proof]
    assert not any(event["kind"] == "flag_captured" for event in events)


def test_builtin_probe_known_proof_replay_preserves_new_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_known_proof_and_finding)
    proof = "flag{probe_auto_capture_123}"
    state = AgentState(flags=[proof])
    events: list[dict[str, object]] = []
    workspace = AgentWorkspace.open(tmp_path / "workspace", event_sink=events.append)
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "data-query",
                "probe": "sqli_differential",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
            proof_recognition_enabled=True,
            action_id="probe-known-proof-new-signal",
        )
    finally:
        audit.close()

    assert outcome.stop is False
    assert outcome.outcome == "confirmed_signal"
    assert outcome.flag == ""
    assert state.flags == [proof]
    assert not any(event["kind"] == "flag_captured" for event in events)


def test_builtin_probe_output_scans_full_text_before_clipping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_late_proof)
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "data-query",
                "probe": "sqli_differential",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=300,
            max_transcript_chars=300,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert outcome.stop
    assert outcome.flag == "flag{probe_late_capture_123}"
    assert "flag{probe_late_capture_123}" not in outcome.observation


def test_long_probe_output_preserves_proof_finding_prefix() -> None:
    text = (
        '{"findings":[{"type":"reflection_value_proof",'
        '"proofs":["flag{linewrapped_proof_123}"],'
        '"response":{"body_snippet":"' + ("A" * 5000) + '"}}],"requests":[{"tail":"kept"}]}'
    )

    clipped = _clip_probe_text(text, max_chars=500)

    assert '"proofs":["flag{linewrapped_proof_123}"]' in clipped
    assert '"tail":"kept"' in clipped
    assert "truncated from middle" in clipped


def test_probe_event_keeps_display_summary_when_raw_result_is_artifacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_with_display_summary)
    events: list[dict[str, object]] = []
    workspace = AgentWorkspace.open(tmp_path / "workspace", event_sink=events.append)
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "input-reflection",
                "probe": "xss_context",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            action_id="probe-display-summary",
        )
    finally:
        audit.close()

    assert outcome.ok is True
    event = next(event for event in events if event["kind"] == "tool_run_probe")
    payload = event["payload"]
    assert isinstance(payload, dict)
    assert isinstance(payload["result"], dict)
    assert payload["display_summary"] == {
        "probe": "xss_context",
        "summary": "tested reflected contexts",
        "findings": 2,
        "finding_types": ["xss_reflection_context"],
        "requests": 80,
        "errors": 0,
    }


def test_multiple_evidence_variants_cannot_downgrade_new_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = "http://127.0.0.1/"
    baseline_url = f"{target_url}objects/1"
    alternate_url = f"{target_url}objects/2"
    probe_text = json.dumps(
        {
            "probe": "idor_boundary",
            "ok": True,
            "summary": "two independently useful authorization-boundary observations",
            "findings": [
                {
                    "type": "idor_boundary_exposed_secret",
                    "signal": {"kind": "private_field"},
                    "matches": ["private field"],
                    "replay": {"method": "GET", "url": alternate_url},
                    "baseline_replay": {"method": "GET", "url": baseline_url},
                    "baseline": {"method": "GET", "url": baseline_url, "status": 200},
                    "response": {
                        "method": "GET",
                        "url": alternate_url,
                        "status": 200,
                        "body_sha_hint": "alternate-object",
                    },
                },
                {
                    "type": "idor_boundary_followup_exposed_secret",
                    "signal": {"kind": "followup_private_field"},
                    "matches": ["follow-up private field"],
                    "replay": {"method": "GET", "url": alternate_url},
                    "source_response": {
                        "method": "GET",
                        "url": baseline_url,
                        "status": 200,
                    },
                    "response": {
                        "method": "GET",
                        "url": alternate_url,
                        "status": 200,
                        "body_sha_hint": "alternate-object",
                    },
                },
            ],
            "requests": [],
            "errors": [],
        }
    )

    def runner(*args: object, **kwargs: object) -> _CompletedProbeRunner:
        del args, kwargs
        return _CompletedProbeRunner(json.dumps({"status": "ok", "ok": True, "text": probe_text}))

    _patch_probe_runner(monkeypatch, runner)
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    engagement_id = uuid4()
    audit = AuditStore(
        tmp_path / "audit.db",
        scope=Scope(in_scope=[target_url], out_of_scope=[]),
    )
    try:
        result = execute_action(
            {"action": "run_probe", "task_id": "stateful-session", "probe": "idor_boundary"},
            target_url=target_url,
            runtime=_ProofRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=2,
            max_observation_chars=4_000,
            max_transcript_chars=20_000,
            action_id="multi-evidence-promotion",
        )
        assert audit.count_findings(status="confirmed", engagement_id=engagement_id) == 1
    finally:
        audit.close()

    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    assert result.outcome == "finding_confirmed"
    assert sum(event["kind"] == "finding_confirmed" for event in events) == 1
    assert sum(event["kind"] == "outcome_evidence_observed" for event in events) == 2


def test_dom_execution_promotes_browser_confirmed_xss_without_a_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _dom_execution_runner())
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    engagement_id = uuid4()
    state = AgentState()
    audit = AuditStore(
        tmp_path / "audit.db",
        scope=Scope(in_scope=["http://127.0.0.1/"], out_of_scope=[]),
    )
    try:
        first = execute_action(
            {
                "action": "run_probe",
                "task_id": "input-reflection",
                "probe": "dom_execution",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            action_id="dom-confirmed",
        )
        duplicate = execute_action(
            {
                "action": "run_probe",
                "task_id": "input-reflection",
                "probe": "dom_execution",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            action_id="dom-confirmed-replay",
        )
        assert audit.count_findings(status="confirmed") == 1
    finally:
        audit.close()

    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    confirmed = [event for event in events if event["kind"] == "finding_confirmed"]
    assert len(confirmed) == 1
    payload = confirmed[0]["payload"]
    assert first.outcome == "finding_confirmed"
    assert first.stop is False
    assert first.flag == ""
    assert duplicate.outcome == "same_as_before"
    assert payload["vuln_class"] == "xss"
    assert payload["severity"] == "Medium"
    assert payload["endpoint"] == {
        "method": "POST",
        "url": "http://127.0.0.1/comment",
        "params": [{"location": "body", "name": "comment"}],
    }
    assert payload["evidence_kind"] == "browser_execution"
    assert payload["evidence_checks"] == {"passed": 1, "required": 1}
    assert payload["source_kind"] == "tool_run_probe"
    finding_text = json.dumps(payload)
    for secret in ("url-secret", "form-secret", "random-browser-secret", "svg-secret"):
        assert secret not in finding_text


def test_probe_findings_other_than_trusted_dom_execution_stay_candidates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = (
        ("xss_context", "client_side_execution"),
        ("dom_execution", "client_side_proof_extraction"),
        ("dom_execution", "xss_reflection_context"),
    )
    for index, (requested_probe, finding_type) in enumerate(cases):
        _patch_probe_runner(
            monkeypatch,
            _dom_execution_runner(finding_type=finding_type),
        )
        case_dir = tmp_path / str(index)
        workspace = AgentWorkspace.open(case_dir / "workspace")
        audit = AuditStore(case_dir / "audit.db")
        try:
            outcome = execute_action(
                {
                    "action": "run_probe",
                    "task_id": "input-reflection",
                    "probe": requested_probe,
                },
                target_url="http://127.0.0.1/",
                runtime=_ProofRuntime(),
                state=AgentState(),
                workspace=workspace,
                audit=audit,
                engagement_id=uuid4(),
                repeat_count=1,
                max_observation_chars=2_000,
                max_transcript_chars=20_000,
                action_id=f"candidate-{index}",
            )
            assert audit.count_findings(status="confirmed") == 0
        finally:
            audit.close()

        events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
        assert outcome.outcome != "finding_confirmed"
        assert not any(event["kind"] == "finding_confirmed" for event in events)


def test_dom_execution_confirmation_is_still_scope_gated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(
        monkeypatch,
        _dom_execution_runner(url="https://outside.invalid/comment"),
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(
        tmp_path / "audit.db",
        scope=Scope(in_scope=["http://127.0.0.1/"], out_of_scope=[]),
    )
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "input-reflection",
                "probe": "dom_execution",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            action_id="dom-out-of-scope",
        )
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()

    assert outcome.outcome == "blocked"
    assert "outside engagement scope" in outcome.observation


def test_dom_execution_keeps_flag_stop_while_recording_xss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(
        monkeypatch,
        _dom_execution_runner(proof="flag{dom_execution_target_proof_123}"),
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "input-reflection",
                "probe": "dom_execution",
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            proof_recognition_enabled=True,
            action_id="dom-proof-and-finding",
        )
        assert audit.count_findings(status="confirmed") == 1
    finally:
        audit.close()

    assert outcome.stop is True
    assert outcome.outcome == "flag_candidate"
    assert outcome.flag == "flag{dom_execution_target_proof_123}"
    assert state.flags == ["flag{dom_execution_target_proof_123}"]


def test_builtin_probe_wall_clock_timeout_returns_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_probe_runner(monkeypatch, _probe_runner_timeout)
    monkeypatch.setattr(
        "ravage.agent_core.action_executor._probe_wall_timeout",
        _one_second_timeout,
    )
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "server-rendering",
                "probe": "ssti_fingerprint",
                "timeout_seconds": 1,
            },
            target_url="http://127.0.0.1/",
            runtime=_ProofRuntime(),
            state=state,
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2000,
            max_transcript_chars=4000,
        )
    finally:
        audit.close()

    assert outcome.ok is False
    assert outcome.timed_out is True
    assert "run_probe ssti_fingerprint exceeded 1s wall-clock limit" in outcome.observation


def _finding_metadata(vuln_class: str) -> dict[str, object]:
    return {
        "vuln_class": vuln_class,
        "severity": "medium",
        "hypothesis": f"The endpoint exhibits {vuln_class} behavior.",
        "impact": "The observed behavior crosses an intended security boundary.",
        "exploit_steps": ["Replay the validated HTTP request."],
    }


class _FakeProbeSession:
    def __init__(
        self,
        target_url: str,
        *,
        timeout_seconds: int = 10,
        **_kwargs: object,
    ) -> None:
        self.target_url = target_url
        self.timeout_seconds = timeout_seconds

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/plain"},
            body="proof-token",
        )

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del fields
        return self.request("POST", url, data=None, headers=headers)


class _SqlErrorProbeSession(_FakeProbeSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        body = "SQLite syntax error near quote" if "%27" in url else "normal results"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/plain"},
            body=body,
        )


class _OrdinaryDifferentialProbeSession(_FakeProbeSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        body = "welcome admin" if "role=admin" in url else "signed out"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/plain"},
            body=body,
        )


class _TypedReplayProbeSession(_FakeProbeSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        if "137*139" in url:
            body = "Hello 19043"
        elif "passwd" in url:
            body = "root:x:0:0:root:/root:/bin/bash"
        elif "/render" in url:
            body = "Hello control"
        else:
            body = "public document"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/plain"},
            body=body,
        )


class _ReflectedSqlMarkerProbeSession(_FakeProbeSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        body = "'SQLite syntax error" if "SQLite" in url else "control"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/plain"},
            body=body,
        )


class _SameClassPayloadProbeSession(_FakeProbeSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        if "variant=control" in url:
            body = "control 49"
        elif "/search" in url:
            body = "SQLite syntax error"
        elif "/render" in url:
            body = "19043"
        else:
            body = "root:x:0:0:root:/root:/bin/bash"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/plain"},
            body=body,
        )


class _OutOfScopeProbeSession(_FakeProbeSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del url, data, headers
        return ProbeResponse(
            method=method,
            url="https://outside.invalid/debug",
            status=200,
            final_url="https://outside.invalid/debug",
            elapsed_ms=1,
            headers={"content-type": "text/plain"},
            body="proof-token",
        )


class _ProofRuntime(ToolRuntime):
    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del command, target_url, timeout_seconds
        return ToolResult(
            ok=True,
            tool="command",
            command=("sh", "-lc", "echo proof"),
            exit_code=0,
            stdout="proof flag{terminal_fallback_proof}",
            stderr="",
        )

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del code, target_url, timeout_seconds
        return self.run_command(command="", target_url="")


class _SessionHashRuntime(_ProofRuntime):
    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del command, target_url, timeout_seconds
        return ToolResult(
            ok=True,
            tool="command",
            command=("sh", "-lc", "curl -i target"),
            exit_code=0,
            stdout="Set-Cookie: PHPSESSID=54f6b14df56f8f10395e77eefc5701e9; path=/",
            stderr="",
        )


class _BareBracedProofRuntime(_ProofRuntime):
    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del command, target_url, timeout_seconds
        return ToolResult(
            ok=True,
            tool="command",
            command=("sh", "-lc", "echo proof"),
            exit_code=0,
            stdout="proof {I'm_a_Script_Kiddie}",
            stderr="",
        )


class _CommandOnlyProofRuntime(_ProofRuntime):
    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del command, target_url, timeout_seconds
        return ToolResult(
            ok=True,
            tool="command",
            command=("python3", "-c", "print('FLAG{command_argument_only}')"),
            exit_code=0,
            stdout="no proof in process output",
            stderr="",
        )


class _ProbeWithProof:
    ok = True

    def to_text(self) -> str:
        return '{"ok": true, "summary": "saw flag{probe_auto_capture_123}"}'


def _fake_probe_with_proof(*args: object, **kwargs: object) -> _ProbeWithProof:
    del args, kwargs
    return _ProbeWithProof()


class _CompletedProbeRunner:
    returncode = 0
    stderr = ""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def _probe_runner_with_proof(*args: object, **kwargs: object) -> _CompletedProbeRunner:
    del args, kwargs
    return _CompletedProbeRunner(
        json.dumps(
            {
                "status": "ok",
                "ok": True,
                "text": json.dumps({"ok": True, "summary": "saw flag{probe_auto_capture_123}"}),
            }
        )
    )


def _probe_runner_with_known_proof_and_finding(
    *args: object,
    **kwargs: object,
) -> _CompletedProbeRunner:
    del args, kwargs
    return _CompletedProbeRunner(
        json.dumps(
            {
                "status": "ok",
                "ok": True,
                "text": json.dumps(
                    {
                        "ok": True,
                        "probe": "sqli_differential",
                        "summary": "saw flag{probe_auto_capture_123}",
                        "findings": [{"type": "sql_injection_error_signal"}],
                    }
                ),
            }
        )
    )


def _probe_runner_with_two_proofs(*args: object, **kwargs: object) -> _CompletedProbeRunner:
    del args, kwargs
    return _CompletedProbeRunner(
        json.dumps(
            {
                "status": "ok",
                "ok": True,
                "text": json.dumps(
                    {
                        "ok": True,
                        "summary": "saw flag{first_observation} and flag{second_observation}",
                        "findings": [
                            {
                                "type": "synthetic_extracted_proof",
                                "proofs": [
                                    "flag{first_observation}",
                                    "flag{second_observation}",
                                ],
                            }
                        ],
                    }
                ),
            }
        )
    )


def _probe_runner_with_known_then_novel_proof(
    *args: object,
    **kwargs: object,
) -> _CompletedProbeRunner:
    del args, kwargs
    return _CompletedProbeRunner(
        json.dumps(
            {
                "status": "ok",
                "ok": True,
                "text": json.dumps(
                    {
                        "ok": True,
                        "summary": "saw flag{known_first} and flag{novel_second}",
                    }
                ),
            }
        )
    )


def _probe_runner_with_late_proof(*args: object, **kwargs: object) -> _CompletedProbeRunner:
    del args, kwargs
    long_text = (
        '{"ok": true, "summary": "'
        + ("A" * 2000)
        + " flag{probe_late_capture_123} "
        + ("B" * 2000)
        + '"}'
    )
    return _CompletedProbeRunner(json.dumps({"status": "ok", "ok": True, "text": long_text}))


def _probe_runner_with_display_summary(*args: object, **kwargs: object) -> _CompletedProbeRunner:
    del args, kwargs
    probe_text = json.dumps(
        {
            "probe": "xss_context",
            "ok": True,
            "summary": "tested reflected contexts",
            "findings": [
                {"type": "xss_reflection_context"},
                {"type": "xss_reflection_context"},
            ],
            "requests": [{"body": "x" * 100} for _ in range(80)],
            "errors": [],
        }
    )
    return _CompletedProbeRunner(json.dumps({"status": "ok", "ok": True, "text": probe_text}))


def _dom_execution_runner(
    *,
    finding_type: str = "client_side_execution",
    url: str = "http://user:password@127.0.0.1/comment?token=url-secret",
    proof: str = "",
) -> object:
    def _runner(*args: object, **kwargs: object) -> _CompletedProbeRunner:
        del args, kwargs
        probe_text = json.dumps(
            {
                "probe": "dom_execution",
                "ok": True,
                "summary": f"headless browser execution result {proof}".strip(),
                "findings": [
                    {
                        "type": finding_type,
                        "method": "POST",
                        "payload": "<svg id=svg-secret onload=alert(1)>",
                        "probe_url": url,
                        "request_template": {
                            "method": "POST",
                            "url": url,
                            "payload_field": "comment",
                            "fields": {
                                "comment": "<svg id=svg-secret onload=alert(1)>",
                                "csrf_token": "form-secret",
                            },
                        },
                        "evidence": {
                            "token_executed": True,
                            "executed_values": ["random-browser-secret"],
                            "dialogs": [],
                            "final_url": url,
                        },
                    }
                ],
                "requests": [],
                "errors": [],
            }
        )
        return _CompletedProbeRunner(json.dumps({"status": "ok", "ok": True, "text": probe_text}))

    return _runner


def _probe_runner_timeout(*args: object, **kwargs: object) -> Never:
    del args, kwargs
    raise subprocess.TimeoutExpired(cmd=("python", "-m", "ravage.probe_runner"), timeout=1)


def _patch_probe_runner(monkeypatch: pytest.MonkeyPatch, runner: object) -> None:
    monkeypatch.setattr("ravage.agent_core.action_executor.subprocess.run", runner)


def _one_second_timeout(_timeout_seconds: object, **_: object) -> int:
    return 1
