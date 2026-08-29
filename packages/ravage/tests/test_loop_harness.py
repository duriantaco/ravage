from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

from ravage.loop_harness import (
    LoopHarnessRecord,
    LoopHarnessState,
    add_loop_harness_record,
    build_loop_verification_report,
    load_loop_harness_state,
    loop_state_path,
    loop_verification_path,
    snapshot_ai_web_runtime,
    write_loop_harness_state,
    write_loop_verification_report,
)
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from pathlib import Path


def test_loop_harness_state_json_round_trip(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    state = LoopHarnessState(
        engagement_id="eng-1",
        target_url="http://127.0.0.1:8080",
        status="running",
        phase="reconnaissance",
        turn=2,
        discovered_surfaces=(
            LoopHarnessRecord(
                kind="route",
                key="GET /search",
                source="runtime",
                value={"params": ["q"]},
            ),
        ),
        budget_counters={"model_requests": 1, "route_count": 1},
    )

    write_loop_harness_state(state, loop_state_path(workspace.root))
    loaded = load_loop_harness_state(loop_state_path(workspace.root))

    assert loaded.engagement_id == "eng-1"
    assert loaded.discovered_surfaces[0].key == "GET /search"
    assert loaded.budget_counters["model_requests"] == 1


def test_loop_harness_record_json_redacts_query_key() -> None:
    record = LoopHarnessRecord(
        kind="session",
        key="GET /profile?session=secret-session",
        source="runtime",
        value={"callback": "/callback?api_key=secret-key"},
    )

    payload = record.to_json()

    assert payload["key"] == "GET /profile?session=%5Bredacted%5D"
    assert payload["value"] == {"callback": "/callback?api_key=%5Bredacted%5D"}


def test_loop_harness_record_redacts_nested_auth_material() -> None:
    sensitive_value = "SUPERSECRET"
    jwt_value = "headerpart.payloadpart.signaturevalue"
    record = LoopHarnessRecord(
        kind="auth",
        key=(f"GET /callback?authorization={sensitive_value}&credential={sensitive_value}"),
        source="runtime",
        value={
            "endpoint": f"https://admin:{sensitive_value}@host/private",
            "headers": {"X-Auth": f"Bearer {sensitive_value}"},
            "jwt": jwt_value,
            "credential": sensitive_value,
        },
    )

    serialized = json.dumps(record.to_json(), sort_keys=True)

    assert sensitive_value not in serialized
    assert jwt_value not in serialized
    assert "authorization=%5Bredacted%5D" in serialized
    assert "credential=%5Bredacted%5D" in serialized
    assert "https://admin:[redacted]@host/private" in serialized


def test_loop_harness_record_redacts_common_credential_artifacts() -> None:
    sensitive_value = "SUPERSECRET"
    key_kind = "PRIVATE"
    private_key = f"-----BEGIN {key_kind} KEY-----\n{sensitive_value}\n-----END {key_kind} KEY-----"
    record = LoopHarnessRecord(
        kind="auth",
        key="credentials",
        source="runtime",
        value={
            "private_key": private_key,
            "access_key": "AKIAABCDEFGHIJKLMNOP",
            "database_url": f"postgres://admin:{sensitive_value}@db/internal",
            "headers": {"X-Custom": f"Basic {sensitive_value}"},
            "encoded_key": f"/callback?%74oken={sensitive_value}",
            "encoded_proof": f"/callback?value=flag%7B{sensitive_value}%7D",
        },
    )

    serialized = json.dumps(record.to_json(), sort_keys=True)

    assert sensitive_value not in serialized
    assert private_key not in serialized
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized
    assert "postgres://admin:" not in serialized
    assert "Basic SUPERSECRET" not in serialized
    assert "%74oken=%5Bredacted%5D" in serialized
    assert "value=%5Bredacted%5D" in serialized


def test_loop_harness_record_redacts_encoded_and_password_only_artifacts() -> None:
    sensitive_value = "SUPERSECRET"
    unsecured_jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    record = LoopHarnessRecord(
        kind="observation",
        key="credential-shaped artifacts",
        source="runtime",
        value={
            "opaque_shape": unsecured_jwt,
            "service_url": f"redis://:{sensitive_value}@host/0",
            "generic_encoded": f"observed flag%7B{sensitive_value}%7D in body",
            "double_encoded_key": f"/callback?%2574oken={sensitive_value}",
            "double_encoded_value": (f"/callback?value=flag%257B{sensitive_value}%257D"),
        },
    )

    serialized = json.dumps(record.to_json(), sort_keys=True)

    assert sensitive_value not in serialized
    assert unsecured_jwt not in serialized
    assert "redis://:" in serialized
    assert "%2574oken=%5Bredacted%5D" in serialized
    assert "value=%5Bredacted%5D" in serialized


def test_add_loop_harness_record_replaces_existing_key() -> None:
    state = LoopHarnessState(engagement_id="eng-1")
    first = LoopHarnessRecord(
        kind="probe_candidate",
        key="GET /item id query",
        source="coverage_ledger",
        status="attempted",
    )
    second = LoopHarnessRecord(
        kind="probe_candidate",
        key="GET /item id query",
        source="coverage_ledger",
        status="confirmed",
    )

    updated = add_loop_harness_record(
        add_loop_harness_record(state, section="attempted_candidates", record=first),
        section="attempted_candidates",
        record=second,
    )

    assert len(updated.attempted_candidates) == 1
    assert updated.attempted_candidates[0].status == "confirmed"


def test_build_loop_verification_report_aggregates_trace_quality(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    for _ in range(3):
        workspace.record_event(
            kind="tool_call",
            payload={
                "tool": "http_probe",
                "method": "GET",
                "path": "/search?token=secret-token",
            },
        )
    workspace.record_event(kind="finding_confirmed", payload={"vuln_class": "ssrf"})

    report = build_loop_verification_report(workspace.root, require_trace=True)
    write_loop_verification_report(report, loop_verification_path(workspace.root))

    payload = report.to_json()
    feedback_codes = {item.key for item in report.verifier_feedback}
    suggestion_codes = {item.key for item in report.hill_climb_suggestions}
    assert payload["passed"] is False
    assert "repeated_identical_tool_call" in feedback_codes
    assert "finding_without_replayable_proof" in feedback_codes
    assert "finding_without_replayable_proof" in suggestion_codes
    repeated = next(
        item for item in report.verifier_feedback if item.key == "repeated_identical_tool_call"
    )
    assert "/search?token=%5Bredacted%5D" in str(repeated.value["evidence"])
    assert loop_verification_path(workspace.root).exists()


def test_build_loop_verification_report_blocks_evidence_free_final(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.record_event(kind="agent_action", payload={"turn": 1, "action": "final"})
    workspace.record_event(kind="run_completed", payload={"status": "completed"})

    report = build_loop_verification_report(
        workspace.root,
        expect_present_evidence=True,
        require_trace=True,
    )

    assert report.passed is False
    assert "premature_final_without_evidence" in {item.key for item in report.verifier_feedback}


def test_build_loop_verification_report_rejects_malformed_required_trace(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.events_path.write_text("not-json\n", encoding="utf-8")

    report = build_loop_verification_report(workspace.root, require_trace=True)

    feedback_codes = {item.key for item in report.verifier_feedback}
    assert report.passed is False
    assert "missing_parseable_trace_events" in feedback_codes
    assert "trace_parse_errors" in feedback_codes


def test_build_loop_verification_report_rejects_non_utf8_required_trace(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.events_path.write_bytes(b"\xff\xfe\xfd\n")

    report = build_loop_verification_report(workspace.root, require_trace=True)

    feedback_codes = {item.key for item in report.verifier_feedback}
    assert report.passed is False
    assert "missing_parseable_trace_events" in feedback_codes
    assert "trace_parse_errors" in feedback_codes


def test_build_loop_verification_report_rejects_placeholder_proof(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.record_event(kind="flag_captured", payload={"flag": "flag{REDACTED}"})
    workspace.record_event(kind="agent_final", payload={})

    report = build_loop_verification_report(
        workspace.root,
        expect_present_evidence=True,
        require_trace=True,
    )

    assert report.passed is False
    assert "premature_final_without_evidence" in {item.key for item in report.verifier_feedback}


def test_build_loop_verification_report_rejects_skeletal_proof_bundle(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.record_event(
        kind="finding_confirmed",
        payload={
            "proof_bundle": {
                "controls": [{"passed": True}],
                "verifier": {"verdict": "accepted"},
            }
        },
    )
    workspace.record_event(kind="agent_final", payload={})

    report = build_loop_verification_report(
        workspace.root,
        expect_present_evidence=True,
        require_trace=True,
    )

    feedback_codes = {item.key for item in report.verifier_feedback}
    assert report.passed is False
    assert "finding_without_replayable_proof" in feedback_codes
    assert "premature_final_without_evidence" in feedback_codes


def test_build_loop_verification_report_blocks_evidence_free_max_turns(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.record_event(kind="max_turns_reached", payload={"turn": 40})

    report = build_loop_verification_report(
        workspace.root,
        expect_present_evidence=True,
        require_trace=True,
    )

    exhausted = next(
        item
        for item in report.verifier_feedback
        if item.key == "turn_budget_exhausted_without_evidence"
    )
    assert report.passed is False
    assert exhausted.status == "error"


def test_build_loop_verification_report_keeps_warning_only_trace_nonblocking(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    for _ in range(2):
        workspace.record_event(
            kind="tool_call",
            payload={"tool": "http_probe", "method": "GET", "path": "/health"},
        )

    report = build_loop_verification_report(workspace.root, require_trace=True)

    repeated = next(
        item for item in report.verifier_feedback if item.key == "repeated_identical_tool_call"
    )
    assert report.passed is True
    assert repeated.status == "warning"
    assert "trace_quality" in report.to_json()


def test_snapshot_ai_web_runtime_summarizes_state_without_secret_values(
    tmp_path: Path,
) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    runtime = SimpleNamespace(
        brief=SimpleNamespace(engagement_id="eng-1"),
        target_url="http://127.0.0.1:8080",
        workspace=workspace,
        discovered_routes=[
            {
                "method": "GET",
                "path": "/search",
                "source": "crawl",
                "params": [{"name": "q", "location": "query"}],
            }
        ],
        captured_flags={"flag{secret}"},
        observed_flags=set(),
        default_headers={"Authorization": "Bearer token"},
        default_cookies={"session": "abc"},
        discovered_jwts=["jwt"],
        jwt_hmac_secrets=["secret"],
        tested_probe_keys={"GET /search q query"},
        confirmed_evidence={
            "ssrf:/callback": SimpleNamespace(
                source_tool="test_ssrf_param",
                confirmed=True,
                vuln_class="ssrf",
                endpoint_url="http://127.0.0.1:8080/callback?token=secret-token",
                method="GET",
                param_name="url",
                param_location="query",
                indicator="callback?api_key=secret-key",
            )
        },
        model_requests=2,
        blocked_probe_keys={"GET /admin id query"},
        blocked_probe_actions={
            "GET /admin id query": {
                "Authorization": "Bearer token",
                "reason": "redundant",
            }
        },
        pending_replay_actions=[],
        free_roam_tool_calls=1,
        free_roam_tool_budget=40,
        free_roam_failure_streak=0,
        access_epoch=1,
        memory_settings=SimpleNamespace(
            mode="read",
            db_path=tmp_path / "memory.db",
            retrieval_limit=5,
            min_confidence=0.65,
        ),
        retrieved_memories=[],
    )

    state = snapshot_ai_web_runtime(
        runtime,  # type: ignore[arg-type]
        status="running",
        last_action={"Authorization": "Bearer token", "action": "http_get"},
        last_observation={
            "tool": "http_get",
            "url": "http://127.0.0.1:8080/profile?session=secret-session",
            "response_snippet": "flag{secret}",
        },
    )

    assert state.discovered_surfaces[0].value["params"] == ["q"]
    assert state.sessions[0].value["names"] == ["Authorization"]
    assert state.identities[0].value["count"] == 1
    assert state.last_action is not None
    assert state.last_action["Authorization"] == "[redacted]"
    assert state.last_observation is not None
    assert str(state.last_observation["url"]).endswith("session=%5Bredacted%5D")
    assert state.last_observation["snippet"] == "flag{REDACTED}"
    assert state.blocked_actions[0].value["Authorization"] == "[redacted]"
    assert (
        state.evidence_ledger[0].value["endpoint_url"]
        == "http://127.0.0.1:8080/callback?token=%5Bredacted%5D"
    )
    assert state.evidence_ledger[0].value["indicator"] == "callback?api_key=%5Bredacted%5D"
