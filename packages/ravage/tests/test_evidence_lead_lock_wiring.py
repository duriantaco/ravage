from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
import ravage.agent_core.ai_agent as ai_agent_module
from ravage.agent_core.action_executor import ActionResult, execute_action
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import (
    _execute_recovery_action,
    _model_action,
    _repeat_context,
    _update_state_from_action,
)
from ravage.agent_core.autonomous_graph.action_bridge import ActionExecution
from ravage.agent_core.evidence_lead_lock import (
    awaiting_session_lead,
    pending_lead,
    reactivate_for_session_change,
    record_aligned_outcome,
    remember_from_probe_result,
    unresolved_lead,
)
from ravage.agent_core.recovery_runtime import RecoveryCampaign
from ravage.agent_core.semantic_routes import semantic_action_fingerprint
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path


def _ssti_probe_text(*, origin: str = "https://target.example") -> str:
    return json.dumps(
        {
            "probe": "ssti_fingerprint",
            "ok": True,
            "findings": [
                {
                    "type": "ssti_fingerprint_signal",
                    "signal": {"kind": "evaluated_expression", "observed": "49"},
                    "replay": {
                        "method": "POST",
                        "url": f"{origin}/generate",
                        "payload_field": "sentence",
                        "encoding": "application/x-www-form-urlencoded",
                        "form": {"sentence": "<%= 7 * 7 %>", "submit": "Render"},
                    },
                    "baseline_replay": {
                        "method": "POST",
                        "url": f"{origin}/generate",
                        "payload_field": "sentence",
                        "encoding": "application/x-www-form-urlencoded",
                        "form": {"sentence": "control", "submit": "Render"},
                    },
                    "response": {
                        "method": "POST",
                        "url": f"{origin}/generate",
                        "status": 200,
                        "body_len": 120,
                        "body_sha_hint": "abc123",
                    },
                    "delta": {"body_changed": True},
                }
            ],
            "requests": [],
            "errors": [],
        }
    )


def _state_with_lead() -> AgentState:
    state = AgentState()
    opened = remember_from_probe_result(
        state,
        _ssti_probe_text(),
        {"action": "run_probe", "probe": "ssti_fingerprint"},
        "observation-lead",
    )
    assert opened is not None
    return state


def _state_with_primary_and_lead(
    *,
    primary_origin: str,
    lead_origin: str,
) -> AgentState:
    state = AgentState(
        surface_graph=SurfaceGraphState.for_target(primary_origin),
    )
    opened = remember_from_probe_result(
        state,
        _ssti_probe_text(origin=lead_origin),
        {"action": "run_probe", "probe": "ssti_fingerprint"},
        "observation-lead",
    )
    assert opened is not None
    return state


def _aligned_http_action() -> dict[str, object]:
    return {
        "action": "http_request",
        "vuln_class": "ssti",
        "method": "POST",
        "url": "https://target.example/generate",
        "form": {"sentence": "<%= 8 * 8 %>", "submit": "Render"},
    }


def _http_action_outcome(status: int) -> ActionResult:
    evidence = json.dumps(
        {
            "response": {
                "status": status,
                "final_url": "https://target.example/generate",
                "headers": {},
                "body": "no proof",
                "body_sha256": "unavailable",
                "truncated": False,
                "error": "",
            }
        },
        sort_keys=True,
    )
    return ActionResult(
        ok=True,
        observation=evidence,
        outcome="http_response_observed",
        evidence_source_kind="tool_http_request",
        evidence_observation=evidence,
    )


@pytest.mark.parametrize(
    "proposed",
    [
        {
            "action": "http_request",
            "vuln_class": "sql_injection",
            "method": "GET",
            "url": "https://target.example/search?q=%27",
        },
        {"action": "final", "summary": "pivot away from the observed route"},
    ],
)
def test_model_action_blocks_unrelated_family_and_final(
    proposed: dict[str, object],
) -> None:
    state = _state_with_lead()

    selected = _model_action(json.dumps(proposed), state=state, turn=2, max_turns=10)

    assert selected["action"] == "invalid"
    assert "Evidence lead lock active" in str(selected["error"])
    assert selected["raw"] == f"blocked action kind: {proposed['action']}"


def test_model_action_allows_exact_http_replay_and_capture_flag() -> None:
    state = _state_with_lead()
    aligned = _aligned_http_action()

    selected = _model_action(json.dumps(aligned), state=state, turn=2, max_turns=10)
    capture = _model_action(
        json.dumps(
            {
                "action": "capture_flag",
                "flag": "FLAG{executor_will_verify_this}",
                "evidence": "exact proof appeared in trusted target evidence",
            }
        ),
        state=state,
        turn=3,
        max_turns=10,
    )

    assert selected == aligned
    assert capture["action"] == "capture_flag"
    assert capture["flag"] == "FLAG{executor_will_verify_this}"


def test_model_action_rejects_relative_replay_for_auxiliary_origin_lead() -> None:
    state = _state_with_primary_and_lead(
        primary_origin="https://main.example/app",
        lead_origin="https://aux.example",
    )
    relative = {
        **_aligned_http_action(),
        "url": "/generate",
    }
    absolute_auxiliary = {
        **relative,
        "url": "https://aux.example/generate",
    }

    blocked = _model_action(json.dumps(relative), state=state, turn=2, max_turns=10)
    allowed = _model_action(
        json.dumps(absolute_auxiliary),
        state=state,
        turn=3,
        max_turns=10,
    )

    assert blocked["action"] == "invalid"
    assert blocked["raw"] == "blocked action kind: http_request"
    assert allowed == absolute_auxiliary


def test_model_action_allows_relative_replay_when_lead_uses_primary_origin() -> None:
    state = _state_with_primary_and_lead(
        primary_origin="https://target.example/app",
        lead_origin="https://target.example",
    )
    relative = {
        **_aligned_http_action(),
        "url": "/generate",
    }

    selected = _model_action(json.dumps(relative), state=state, turn=2, max_turns=10)

    assert selected == relative


def test_model_action_rejects_metadata_only_native_probe_replay() -> None:
    state = _state_with_lead()
    proposed = {
        "action": "run_probe",
        "probe": "ssti_fingerprint",
        "vuln_class": "ssti",
        "method": "POST",
        "url": "https://target.example/generate",
        "field": "sentence",
    }

    selected = _model_action(json.dumps(proposed), state=state, turn=2, max_turns=10)

    assert selected["action"] == "invalid"
    assert selected["raw"] == "blocked action kind: run_probe"


def test_repeat_context_includes_active_lead_fingerprint() -> None:
    state = _state_with_lead()
    lead = pending_lead(state)
    assert lead is not None

    assert _repeat_context(state) == lead.fingerprint

    state.signals["canonical_hosts"] = ["target.internal"]
    assert _repeat_context(state) == f"host:target.internal|{lead.fingerprint}"


def test_reactivated_lead_gets_a_fresh_exact_replay_budget(tmp_path: Path) -> None:
    state = _state_with_lead()
    action = _aligned_http_action()
    initial_context = _repeat_context(state, action=action)

    assert state.ledger.remember(action, context=initial_context) == 1
    first = record_aligned_outcome(
        state,
        action,
        {"ok": True, "outcome": "http_response_observed"},
    )
    assert first is not None
    assert first.aligned_no_progress == 1
    assert state.ledger.remember(action, context=initial_context) == 2
    assert record_aligned_outcome(
        state,
        action,
        {
            "ok": True,
            "outcome": "http_response_observed",
            "_evidence_observation": json.dumps({"response": {"status": 401}}),
        },
    ) is None
    assert state.surface["evidence_lead_lock"]["status"] == "awaiting_session"

    reactivated = reactivate_for_session_change(state)
    assert reactivated is not None
    replay_context = _repeat_context(state, action=action)
    assert replay_context != initial_context
    replay_count = state.ledger.remember(action, context=replay_context)
    assert replay_count == 1

    calls: list[dict[str, object]] = []
    evidence = json.dumps(
        {
            "response": {
                "status": 200,
                "final_url": "https://target.example/generate",
                "headers": {},
                "body": "clean response",
                "body_sha256": "unavailable",
                "truncated": False,
                "error": "",
            }
        },
        sort_keys=True,
    )

    def http_executor(**kwargs: object) -> ActionExecution:
        calls.append(dict(kwargs))
        return ActionExecution(
            result=ActionResult(
                ok=True,
                observation=evidence,
                outcome="http_response_observed",
                evidence_source_kind="tool_http_request",
                evidence_observation=evidence,
            ),
            observation_id="post-auth-replay",
        )

    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        result = execute_action(
            action,
            target_url="https://target.example/",
            runtime=object(),  # type: ignore[arg-type]
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=replay_count,
            max_observation_chars=2_000,
            max_transcript_chars=8_000,
            action_id="post-auth-replay",
            http_executor=http_executor,
        )
    finally:
        audit.close()

    assert result.ok is True
    assert len(calls) == 1
    unchanged_context = _repeat_context(state, action=action)
    assert reactivate_for_session_change(state) is None
    assert _repeat_context(state, action=action) == unchanged_context


def test_awaiting_session_allows_login_http_and_blocks_probe_or_final() -> None:
    state = _state_with_lead()
    action = _aligned_http_action()
    unauthorized = {
        "ok": True,
        "outcome": "http_response_observed",
        "_evidence_observation": json.dumps({"response": {"status": 401}}),
    }
    assert record_aligned_outcome(state, action, unauthorized) is None
    assert pending_lead(state) is None
    assert awaiting_session_lead(state) is not None
    assert unresolved_lead(state) is not None

    login = {
        "action": "http_request",
        "method": "POST",
        "url": "https://target.example/login",
        "form": {"username": "analyst", "password": "test-password"},
    }
    assert _model_action(json.dumps(login), state=state, turn=2, max_turns=10) == login

    blocked_probe = _model_action(
        json.dumps({"action": "run_probe", "probe": "ssti_fingerprint"}),
        state=state,
        turn=3,
        max_turns=10,
    )
    blocked_final = _model_action(
        json.dumps({"action": "final", "summary": "give up"}),
        state=state,
        turn=4,
        max_turns=10,
    )
    assert blocked_probe["action"] == "invalid"
    assert blocked_final["action"] == "invalid"
    assert "Establish authentication" in str(blocked_final["error"])


def test_auth_paused_lead_replay_outranks_exhausted_recovery_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state_with_lead()
    action = _aligned_http_action()
    recovery = RecoveryCampaign.create(target_url="https://target.example/", max_model_requests=40)
    unauthorized = _http_action_outcome(403)

    for _attempt in range(2):
        recovery.begin_model_request()
        recovery.record_action_result(action=action, outcome=unauthorized)
        record_aligned_outcome(
            state,
            action,
            {
                **unauthorized.to_json(),
                "_evidence_observation": unauthorized.evidence_observation,
            },
        )

    assert awaiting_session_lead(state) is not None
    route_fingerprint = semantic_action_fingerprint(action)
    assert recovery.scheduler.route_is_available(route_fingerprint) is False
    calls: list[dict[str, object]] = []

    def fake_execute_action(
        selected: dict[str, object],
        **kwargs: object,
    ) -> ActionResult:
        calls.append({"action": selected, **kwargs})
        return unauthorized

    monkeypatch.setattr(ai_agent_module, "execute_action", fake_execute_action)
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        result, branch_handoff = _execute_recovery_action(
            recovery=recovery,
            action=action,
            target_url="https://target.example/",
            runtime=object(),  # type: ignore[arg-type]
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            proof_recognition_enabled=False,
            action_id="auth-paused-replay",
            authentication=None,
            traffic_policy=object(),  # type: ignore[arg-type]
            http_executor=object(),  # type: ignore[arg-type]
        )
    finally:
        audit.close()

    assert result is unauthorized
    assert branch_handoff is False
    assert len(calls) == 1


def test_reactivated_lead_attempt_outranks_exhausted_recovery_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state_with_lead()
    action = _aligned_http_action()
    recovery = RecoveryCampaign.create(target_url="https://target.example/", max_model_requests=40)

    unauthorized = _http_action_outcome(401)
    recovery.begin_model_request()
    recovery.record_action_result(action=action, outcome=unauthorized)
    record_aligned_outcome(
        state,
        action,
        {
            **unauthorized.to_json(),
            "_evidence_observation": unauthorized.evidence_observation,
        },
    )
    assert state.surface["evidence_lead_lock"]["status"] == "awaiting_session"
    assert reactivate_for_session_change(state) is not None

    first_replay = _http_action_outcome(200)
    recovery.begin_model_request()
    recovery.record_action_result(action=action, outcome=first_replay)
    record_aligned_outcome(
        state,
        action,
        {
            **first_replay.to_json(),
            "_evidence_observation": first_replay.evidence_observation,
        },
    )
    lead = pending_lead(state)
    assert lead is not None
    assert lead.aligned_no_progress == 1
    route_fingerprint = semantic_action_fingerprint(action)
    assert recovery.scheduler.route_is_available(route_fingerprint) is False

    calls: list[dict[str, object]] = []
    second_replay = _http_action_outcome(200)

    def fake_execute_action(
        selected: dict[str, object],
        **kwargs: object,
    ) -> ActionResult:
        calls.append({"action": selected, **kwargs})
        return second_replay

    monkeypatch.setattr(ai_agent_module, "execute_action", fake_execute_action)
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        result, branch_handoff = _execute_recovery_action(
            recovery=recovery,
            action=action,
            target_url="https://target.example/",
            runtime=object(),  # type: ignore[arg-type]
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            proof_recognition_enabled=False,
            action_id="post-auth-attempt-2",
            authentication=None,
            traffic_policy=object(),  # type: ignore[arg-type]
            http_executor=object(),  # type: ignore[arg-type]
        )
    finally:
        audit.close()

    assert result is second_replay
    assert branch_handoff is False
    assert len(calls) == 1
    record_aligned_outcome(
        state,
        action,
        {
            **result.to_json(),
            "_evidence_observation": result.evidence_observation,
        },
    )
    assert pending_lead(state) is None
    assert state.surface["evidence_lead_lock"]["status"] == "exhausted"


def test_action_update_accounting_only_exhausts_complete_aligned_attempts() -> None:
    state = _state_with_lead()
    action = _aligned_http_action()
    ignored_outcomes = (
        {"ok": False, "outcome": "blocked", "timed_out": False},
        {"ok": False, "outcome": "observed", "timed_out": True},
        {"ok": False, "outcome": "same_as_before", "timed_out": False},
    )

    for outcome in ignored_outcomes:
        record_aligned_outcome(state, action, outcome)
        _update_state_from_action(state, action=action, outcome=outcome)

    unchanged = pending_lead(state)
    assert unchanged is not None
    assert unchanged.aligned_no_progress == 0

    first = {"ok": True, "outcome": "observed", "timed_out": False}
    record_aligned_outcome(state, action, first)
    _update_state_from_action(state, action=action, outcome=first)
    after_first = pending_lead(state)
    assert after_first is not None
    assert after_first.aligned_no_progress == 1

    second = {"ok": True, "outcome": "observed", "timed_out": False}
    record_aligned_outcome(state, action, second)
    _update_state_from_action(state, action=action, outcome=second)

    assert pending_lead(state) is None
    assert state.surface["evidence_lead_lock"]["status"] == "exhausted"
    assert len(state.actions) == 5


@dataclass(frozen=True)
class _CompletedProbe:
    text: str
    ok: bool = True
    timed_out: bool = False


def test_execute_trusted_probe_opens_lead_without_spending_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.agent_core.action_executor._run_probe_action",
        lambda *_args, **_kwargs: _CompletedProbe(_ssti_probe_text()),
    )
    state = AgentState(surface={"flag_objective": True})
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "ssti_fingerprint"},
            target_url="https://target.example/",
            runtime=object(),  # type: ignore[arg-type]
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=8_000,
            action_id="trusted-ssti-probe",
        )
    finally:
        audit.close()

    lead = pending_lead(state)
    assert result.ok is True
    assert lead is not None
    assert lead.family == "template_injection"
    assert lead.method == "POST"
    assert lead.endpoint == "/generate"
    assert lead.inputs == ("sentence",)
    assert lead.aligned_no_progress == 0
    assert lead.source_observation_id == state.last_observation["observation_id"]
