from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest
from ravage import __main__ as cli
from ravage.cli_run_display import RunDisplay, redacted_target_url

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any


class _TTYBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class _ASCIIBuffer(io.StringIO):
    @property
    def encoding(self) -> str:
        return "ascii"


def test_attack_sink_keeps_live_ansi_out_of_plain_transcript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    console = _TTYBuffer()
    transcript = io.StringIO()
    monkeypatch.setattr(
        cli.sys,
        "stdout",
        cli._TeeStream(console, transcript),  # noqa: SLF001
    )
    sink = cli._attack_event_sink(mode="auto")  # noqa: SLF001

    sink(_event("agent_started", {"target_url": "http://127.0.0.1:8080"}))
    sink(_event("recon_completed"))
    sink.close()

    console_text = console.getvalue()
    transcript_text = transcript.getvalue()
    assert "\x1b[" in console_text
    assert "Agent started" in console_text
    assert "\x1b[" not in transcript_text
    assert "[info] Agent started" in transcript_text
    assert "[ok] Recon complete" in transcript_text


def test_tee_strips_terminal_controls_from_all_transcript_writes() -> None:
    console = io.StringIO()
    transcript = io.StringIO()
    tee = cli._TeeStream(console, transcript)  # noqa: SLF001
    value = "\x1b[31mwarning\x1b[0m\roverwrite\x07\u202edone\n"

    assert tee.write(value) == len(value)

    assert console.getvalue() == value
    assert transcript.getvalue() == "warning\noverwritedone\n"


def _event(kind: str, payload: Mapping[str, Any] | None = None) -> dict[str, object]:
    return {"kind": kind, "payload": dict(payload or {})}


def test_auto_uses_stable_plain_lines_for_redirected_output() -> None:
    output = io.StringIO()
    now = [10.0]
    display = RunDisplay(mode="auto", stream=output, clock=lambda: now[0])

    display(
        _event(
            "agent_started",
            {
                "target_url": "https://user:password@example.test/app?token=secret",
                "provider": "openai",
                "model": "gpt-test",
                "max_turns": 4,
            },
        )
    )
    display(
        _event(
            "model_request_started",
            {
                "model_request_id": "request-1",
                "turn": 1,
                "provider": "openai",
                "model": "gpt-test",
                "phase": "recon",
            },
        )
    )
    now[0] = 11.25
    display(
        _event(
            "model_reply_received",
            {
                "model_request_id": "request-1",
                "turn": 1,
                "input_tokens": 1_250,
                "output_tokens": 80,
                "cost_usd": 0.0012,
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert display.mode == "plain"
    assert "\x1b[" not in text
    assert "https://example.test" in text
    assert "/app" not in text
    assert "user:password" not in text
    assert "secret" not in text
    assert "[run] Thinking" in text
    assert "Model replied" in text
    assert "1.2s" in text
    assert "1.2k in / 80 out" in text
    assert "$0.0012" in text


def test_target_summary_never_prints_userinfo_paths_or_query_secrets() -> None:
    target = "https://user:password@example.test/private/reset?token=secret"

    assert redacted_target_url(target) == "https://example.test"


@pytest.mark.parametrize(
    "target",
    [
        "https://evil\x1bX.test/",
        "https://safe\u202eevil.test/",
        "https://zero\u200bwidth.test/",
        "https://example.test:not-a-port/private/secret",
        "ftp://example.test/file",
    ],
)
def test_target_summary_rejects_terminal_spoofing_and_unsupported_schemes(
    target: str,
) -> None:
    assert redacted_target_url(target) == "[invalid target]"


def test_target_summary_canonicalizes_ipv6_and_internationalized_hosts() -> None:
    assert redacted_target_url("https://[2001:db8::1]:8443/private") == (
        "https://[2001:db8::1]:8443"
    )
    assert redacted_target_url("https://bücher.example/private") == (
        "https://xn--bcher-kva.example"
    )


def test_live_mode_animates_one_row_and_restores_cursor() -> None:
    output = _TTYBuffer()
    now = [2.0]
    display = RunDisplay(mode="live", stream=output, clock=lambda: now[0])

    display(_event("agent_started", {"target_url": "http://127.0.0.1:8080"}))
    now[0] = 2.5
    display(_event("recon_completed"))
    display.close()
    display.close()

    text = output.getvalue()
    assert display.mode == "live"
    assert "\x1b[?25l" in text
    assert "\r\x1b[2K" in text
    assert "Mapping the target" in text
    assert "Recon complete" in text
    assert "0.5s" in text
    assert text.count("\x1b[?25h") == 1


def test_live_dashboard_stays_silent_before_the_run_starts() -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode="live", stream=output)

    assert display._render_dashboard() is True  # noqa: SLF001
    display.close()

    assert output.getvalue() == ""


def test_quiet_mode_writes_nothing() -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode="quiet", stream=output)

    display(_event("agent_started", {"target_url": "http://example.test"}))
    display(_event("agent_finished", {"status": "completed", "turns": 1}))
    display.close()

    assert output.getvalue() == ""


def test_auto_uses_plain_output_for_dumb_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "dumb")
    output = _TTYBuffer()
    display = RunDisplay(mode="auto", stream=output)

    display(_event("agent_started", {"target_url": "http://example.test"}))
    display.close()

    assert display.mode == "plain"
    assert "\x1b[" not in output.getvalue()


def test_plain_output_uses_ascii_fallback_for_non_utf_streams() -> None:
    output = _ASCIIBuffer()
    display = RunDisplay(mode="plain", stream=output)

    display(_event("agent_started", {"target_url": "https://example.test"}))
    display(_event("recon_completed"))
    display.close()

    text = output.getvalue()
    text.encode("ascii")
    assert "[info] Agent started | https://example.test" in text


def test_auto_uses_plain_output_in_ci(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("CI", "true")
    output = _TTYBuffer()
    display = RunDisplay(mode="auto", stream=output)

    display(_event("agent_started"))
    display.close()

    assert display.mode == "plain"
    assert "\x1b[" not in output.getvalue()


def test_no_color_keeps_live_layout_but_removes_sgr_color(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("NO_COLOR", "")
    output = _TTYBuffer()
    display = RunDisplay(mode="auto", stream=output)

    display(_event("agent_started", {"target_url": "https://example.test"}))
    display.close()

    text = output.getvalue()
    assert display.mode == "live"
    assert "\x1b[?25l" in text
    assert "\x1b[36m" not in text


@pytest.mark.parametrize("name", ["RAVAGE_NO_MOTION", "RAVAGE_SCREEN_READER"])
def test_accessibility_environment_forces_plain_output(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setenv(name, "1")
    output = _TTYBuffer()
    display = RunDisplay(mode="live", stream=output)

    display(_event("agent_started", {"target_url": "https://example.test"}))
    display.close()

    assert display.mode == "plain"
    assert "\x1b[" not in output.getvalue()


def test_action_and_tool_lines_redact_secrets_proofs_and_raw_output() -> None:
    output = io.StringIO()
    now = [0.0]
    display = RunDisplay(mode="plain", stream=output, clock=lambda: now[0])
    command = (
        "curl -H 'Authorization: Bearer very-secret-token' "
        "'https://example.test/check?token=also-secret' FLAG{do-not-print}"
    )

    display(
        _event(
            "action_started",
            {
                "action_id": "action-1",
                "turn": 2,
                "action_kind": "run_command",
                "summary": "Run command",
                "detail": command,
            },
        )
    )
    now[0] = 0.75
    display(
        _event(
            "tool_run_command",
            {
                "action_id": "action-1",
                "ok": True,
                "tool": "curl",
                "exit_code": 0,
                "stdout": "raw target output FLAG{do-not-print}",
                "recognized_proofs": ["FLAG{do-not-print}"],
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "very-secret-token" not in text
    assert "also-secret" not in text
    assert "FLAG{do-not-print}" not in text
    assert "raw target output" not in text
    assert "Run command" in text
    assert "Command finished" in text
    assert "proofs=1" in text


def test_confirmed_findings_and_proofs_are_counted_without_exposing_evidence() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    confirmed_finding = {
        "finding_id": "finding-sqli-1",
        "status": "confirmed",
        "vuln_class": "sql_injection",
        "severity": "high",
        "title": "secret title must not render",
        "endpoint": {"url": "https://example.test/search?token=endpoint-secret"},
        "exploit_steps": [{"http_request": "GET /search", "indicator": "SQL error"}],
        "proof": {
            "http_request_final": "GET /search",
            "response_final": "FLAG{finding-secret}",
            "impact_description": "Database query behavior is attacker-controlled.",
        },
    }
    display(_event("finding_confirmed", confirmed_finding))
    display(_event("finding_confirmed", confirmed_finding))
    display(
        _event(
            "finding_confirmed",
            {
                "finding_id": "candidate-only",
                "status": "candidate",
                "vuln_class": "cross_site_scripting",
                "severity": "critical",
            },
        )
    )
    proof = {
        "action_id": "action-proof-1",
        "flag": "FLAG{captured-secret}",
        "flag_record_path": "runs/demo/workspace/events.jsonl",
        "source_kind": "tool_run_probe",
        "evidence": "target output contains FLAG{captured-secret}",
    }
    display(_event("flag_captured", proof))
    display(_event("flag_captured", proof))
    display(
        _event(
            "agent_attempt_recorded",
            {
                "action_id": "action-proof-1",
                "turn": 3,
                "status": "completed",
                "novel": True,
                "outcome": {"ok": True, "classification": "flag_candidate"},
                "state_delta": {"signal_count_delta": {}},
            },
        )
    )
    display(
        _event(
            "agent_finished",
            {
                "status": "completed",
                "turns": 3,
                "phase": "exploit",
                "flags": ["FLAG{captured-secret}"],
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert text.count("Vulnerability confirmed") == 1
    assert "Vulnerability confirmed · sql injection · High · findings=1" in text
    assert "cross site scripting" not in text
    assert text.count("Flag found") == 1
    assert "Flag found · 1 unique flag total · probe evidence · value masked" in text
    assert text.count("Flag recorded in") == 1
    assert "Flag recorded in · runs/demo/workspace/events.jsonl" in text
    assert "Look for · event=flag_captured · field=payload.flag" in text
    assert "Result · turn 3 · flag candidate" not in text
    assert "Agent finished · 3 turns · exploit · findings=1 · flags=1" in text
    for secret in ("secret title", "endpoint-secret", "finding-secret", "captured-secret"):
        assert secret not in text


def test_confirmed_finding_renders_safe_location_evidence_and_result_paths() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)
    finding_id = "6a989647-e9c8-437a-a1b2-bb4ed4cb3b7f"

    display(
        _event(
            "finding_confirmed",
            {
                "finding_id": finding_id,
                "status": "confirmed",
                "vuln_class": "cross_site_scripting",
                "severity": "high",
                "title": "token=raw-title-secret",
                "endpoint": {
                    "method": "POST",
                    "url": (
                        "https://user:password@example.test/search"
                        "?token=query-secret&return_to=%2Fadmin"
                    ),
                    "params": [{"name": "q", "value": "field-secret"}],
                },
                "exploit_steps": [
                    {"http_request": "POST /search", "indicator": "browser execution"}
                ],
                "proof": {
                    "http_request_final": "Authorization: Bearer proof-secret",
                    "response_final": "FLAG{raw-proof-secret}",
                    "impact_description": "Script execution in the application origin.",
                },
                "evidence_kind": "http_poc_replay",
                "evidence_checks": {"passed": 4, "required": 4},
                "source_kind": "tool_validate_poc",
                "finding_record_path": "runs/demo/workspace/events.jsonl",
            },
        )
    )
    display(
        _event(
            "agent_finished",
            {
                "status": "completed",
                "turns": 2,
                "phase": "exploit",
                "finding_count": 1,
                "flags": [],
                "flag_objective": False,
                "finding_record_path": "runs/demo/workspace/events.jsonl",
                "report_path": "runs/demo/report.md",
                "audit_path": "runs/demo/audit.db",
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "Vulnerability confirmed · cross site scripting · High · findings=1" in text
    assert "Location · POST /search · parameters=q,token,return_to" in text
    assert "Evidence · HTTP PoC replay · 4/4 checks passed · PoC validation evidence" in text
    assert f"Finding · {finding_id}" in text
    assert "Recorded in · runs/demo/workspace/events.jsonl" in text
    assert "Agent finished · 2 turns · exploit · findings=1" in text
    assert "flags=0" not in text
    assert "Evidence · runs/demo/workspace/events.jsonl" in text
    assert "Report · runs/demo/report.md" in text
    assert "Audit · runs/demo/audit.db" in text
    for secret in (
        "raw-title-secret",
        "password",
        "query-secret",
        "/admin",
        "field-secret",
        "proof-secret",
        "raw-proof-secret",
    ):
        assert secret not in text


def test_confirmed_finding_requires_evidence_and_redacts_dynamic_path_segments() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "finding_confirmed",
            {
                "finding_id": "invalid-finding",
                "status": "confirmed",
                "vuln_class": "idor",
                "severity": "high",
                "endpoint": {"method": "GET", "url": "https://example.test/users/42"},
            },
        )
    )
    display(
        _event(
            "finding_confirmed",
            {
                "finding_id": "valid-finding",
                "status": "confirmed",
                "vuln_class": "auth_bypass",
                "severity": "critical",
                "endpoint": {
                    "method": "GET",
                    "url": (
                        "https://example.test/download/token.FAKESECRETVALUE123/"
                        "550e8400-e29b-41d4-a716-446655440000"
                    ),
                },
                "exploit_steps": [{"http_request": "GET /reset/:token"}],
                "proof": {
                    "http_request_final": "GET /reset/:token",
                    "response_final": "Account access granted",
                    "impact_description": "An attacker can bypass account recovery.",
                },
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert text.count("Vulnerability confirmed") == 1
    assert "Vulnerability confirmed · auth bypass · Critical · findings=1" in text
    assert "Location · GET /download/:redacted/:id" in text
    assert "FAKESECRETVALUE" not in text
    assert "550e8400" not in text
    assert "invalid-finding" not in text


@pytest.mark.parametrize(
    ("reason", "label"),
    [
        ("max_turns_reached", "max turns reached"),
        ("cost_budget_exhausted", "cost budget exhausted"),
    ],
)
def test_incomplete_agent_finish_is_a_warning(reason: str, label: str) -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "agent_finished",
            {
                "status": "incomplete",
                "termination_reason": reason,
                "turns": 6,
                "finding_count": 0,
                "flag_objective": False,
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert f"[warn] Agent incomplete · {label} · 6 turns · findings=0" in text
    assert "[ok] Agent finished" not in text


def test_finding_without_required_evidence_is_rendered_as_candidate_only() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "finding_rejected_no_evidence",
            {
                "finding_id": "candidate-17",
                "vuln_class": "sql_injection",
                "evidence_checks": {"passed": 1, "required": 4},
                "reason": (
                    "missing proof.http_request_final; "
                    "missing proof.response_final; missing exploit_steps"
                ),
                "error": "token=must-not-render FLAG{must-not-render}",
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "Candidate not confirmed · sql injection · evidence gate failed" in text
    assert "1/4 checks passed" in text
    assert "Evidence gap · request replay · response evidence · exploit steps" in text
    assert "Candidate · candidate-17" in text
    assert "Vulnerability confirmed" not in text
    assert "must-not-render" not in text


@pytest.mark.parametrize(
    ("reason", "label"),
    [
        (
            "finding confirmation requires paired control and exploit replay steps",
            "paired control and exploit replays",
        ),
        (
            "control and exploit replays each require a passed expectation",
            "passing control and exploit expectations",
        ),
        (
            "control and exploit replays must target the same endpoint and method",
            "matching replay endpoint and method",
        ),
        (
            "control and exploit replay inputs are identical",
            "distinct control and exploit inputs",
        ),
        (
            "control and exploit replays must vary the same input shape",
            "matching replay input shape",
        ),
        (
            "control and exploit responses lack a security-relevant differential",
            "security-relevant response differential",
        ),
        (
            "SQL injection confirmation requires a new executor-observed database error",
            "executor-observed database error",
        ),
        (
            "finding class requires a trusted typed validator",
            "trusted typed validator",
        ),
        (
            "file-read confirmation requires new executor-observed local-file content",
            "executor-observed local-file content",
        ),
    ],
)
def test_paired_replay_rejection_reason_is_actionable(reason: str, label: str) -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "finding_rejected_no_evidence",
            {
                "vuln_class": "sql_injection",
                "reason": reason,
                "evidence_checks": {"passed": 1, "required": 2},
            },
        )
    )
    display.close()

    assert f"Evidence gap · {label}" in output.getvalue()


def test_non_flag_assessment_reports_zero_findings_without_flags_zero() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "agent_finished",
            {
                "status": "completed",
                "turns": 3,
                "finding_count": 0,
                "flag_count": 0,
                "flag_objective": False,
                "finding_record_path": "runs/demo/workspace/events.jsonl",
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "Agent finished · 3 turns · findings=0" in text
    assert "flags=0" not in text
    assert "Evidence · runs/demo/workspace/events.jsonl" in text


def test_probe_summary_relabels_raw_findings_as_candidate_signals() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "tool_run_probe",
            {
                "ok": True,
                "display_summary": {
                    "probe": "xss_context",
                    "summary": "findings=2; one finding needs browser validation",
                    "findings": 2,
                    "finding_types": ["xss_reflection_context"],
                    "errors": 0,
                },
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "2 candidate signals" in text
    assert "signals=xss reflection context" in text
    assert "candidate signals=2; one candidate signal needs browser validation" in text
    assert "findings" not in text.lower()


@pytest.mark.parametrize("mode", ["plain", "live"])
def test_base_agent_narrates_plan_probe_result_and_evidence_progress(mode: str) -> None:
    output = _TTYBuffer() if mode == "live" else io.StringIO()
    now = [1.0]
    display = RunDisplay(mode=mode, stream=output, clock=lambda: now[0])  # type: ignore[arg-type]

    display(
        _event(
            "harness_selection",
            {
                "turn": 1,
                "action_id": "action-plan-1",
                "selected_action": {
                    "action": "run_probe",
                    "probe": "xss_context",
                    "notes": "Map reflected sink contexts before browser verification.",
                    "expected_signal": "A concrete reflected HTML or script context.",
                },
                "selected_route": {"family": "cross_site_scripting"},
                "selection_reason": "model_proposal",
                "selected_differs_from_model": False,
            },
        )
    )
    display(
        _event(
            "action_started",
            {
                "action_id": "action-plan-1",
                "turn": 1,
                "action_kind": "run_probe",
                "params": {"probe": "xss_context"},
                "fallback": "Try a bounded reflection differential.",
            },
        )
    )
    now[0] = 1.5
    display(
        _event(
            "tool_run_probe",
            {
                "action_id": "action-plan-1",
                "ok": True,
                "display_summary": {
                    "probe": "xss_context",
                    "summary": "tested 4 input targets; reflected contexts found",
                    "requests": 36,
                    "findings": 3,
                    "errors": 0,
                    "finding_types": ["xss_reflection_context"],
                },
            },
        )
    )
    display(
        _event(
            "agent_attempt_recorded",
            {
                "action_id": "action-plan-1",
                "turn": 1,
                "status": "progressed",
                "novel": True,
                "outcome": {"ok": True, "classification": "confirmed_signal"},
                "state_delta": {
                    "facts_delta": 2,
                    "signal_count_delta": {"endpoints": 10, "xss_contexts": 6},
                },
            },
        )
    )
    display(
        _event(
            "harness_turn_trace",
            {
                "action_id": "action-plan-1",
                "turn": 1,
                "outcome": {"ok": True, "classification": "confirmed_signal"},
                "post_state": {
                    "phase": "exploit",
                    "flags_count": 0,
                    "signal_counts": {"endpoints": 10, "xss_contexts": 6},
                },
            },
        )
    )
    display(_event("agent_finished", {"status": "completed", "turns": 1, "phase": "exploit"}))
    display.close()

    text = output.getvalue()
    assert "Plan · turn 1 · probe xss_context · cross site scripting" in text
    assert "Intent · Map reflected sink contexts before browser verification." in text
    assert "Looking for · A concrete reflected HTML or script context." in text
    assert "Run probe xss_context · turn 1" in text
    assert (
        "Probe xss_context finished · 0.5s · 36 requests · 3 candidate signals · 0 errors" in text
    )
    assert "3 findings" not in text
    assert "Observed · tested 4 input targets; reflected contexts found" in text
    assert "Result · turn 1 · candidate signal observed · +10 endpoints · +6 XSS contexts" in text
    assert text.count("candidate signal observed") == 1
    assert "Mapped signals · 10 endpoints · 6 XSS contexts" in text


def test_plan_narration_explains_harness_override_and_redacts_sensitive_text() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "harness_selection",
            {
                "turn": 4,
                "proposed_action": {"action": "final"},
                "selected_action": {
                    "action": "invalid",
                    "notes": "Retry token=plan-secret FLAG{plan-proof}",
                    "expected_signal": "Authorization: Bearer bearer-secret",
                },
                "selected_route": {"family": "unknown"},
                "selection_reason": "premature_final_guard",
                "selected_differs_from_model": True,
            },
        )
    )
    display(
        _event(
            "action_started",
            {
                "action_id": "action-invalid-4",
                "turn": 4,
                "action_kind": "invalid",
                "fallback": "Try token=fallback-secret with another valid probe.",
            },
        )
    )
    display(
        _event(
            "invalid_action",
            {
                "action_id": "action-invalid-4",
                "turn": 4,
                "error": "final is premature while required assessment work remains",
            },
        )
    )
    display(
        _event(
            "agent_attempt_recorded",
            {
                "action_id": "action-invalid-4",
                "turn": 4,
                "status": "blocked",
                "novel": False,
                "outcome": {"ok": False, "classification": "blocked"},
                "state_delta": {"signal_count_delta": {}},
            },
        )
    )
    display(
        _event(
            "harness_turn_trace",
            {
                "action_id": "action-invalid-4",
                "turn": 4,
                "outcome": {"ok": False, "classification": "blocked"},
                "post_state": {"phase": "exploit", "signal_counts": {}},
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "finish run → invalid action" in text
    assert "Plan adjusted by harness · premature final guard" in text
    assert text.count("Invalid model action") == 1
    assert (
        "Invalid model action · final is premature while required assessment work remains" in text
    )
    assert "Result · turn 4 · blocked" not in text
    assert "Suggested next · Try token=" in text
    assert "with another valid probe." in text
    assert "plan-secret" not in text
    assert "FLAG{plan-proof}" not in text
    assert "bearer-secret" not in text
    assert "fallback-secret" not in text


def test_http_step_shows_shape_without_field_or_query_values() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "http_step",
            {
                "method": "POST",
                "path": "/login?next=/admin&token=query-secret",
                "fields": {"username": "admin", "password": "field-secret"},
                "status": 302,
                "ok": True,
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "POST request" in text
    assert "username,password" in text
    assert "/login" not in text
    assert "next=" not in text
    assert "token=" not in text
    assert "/admin" not in text
    assert "query-secret" not in text
    assert "field-secret" not in text


@pytest.mark.parametrize(
    ("status", "expected"),
    [("completed", "Agent finished"), ("failed", "Agent failed"), ("cancelled", "Agent cancelled")],
)
def test_finish_status_is_not_always_reported_as_success(status: str, expected: str) -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "agent_finished",
            {
                "status": status,
                "turns": 3,
                "flags": ["FLAG{masked}"],
                "cost_usd": 0.25,
                "error_type": "RuntimeError",
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert expected in text
    assert "flags=1" in text
    assert "FLAG{masked}" not in text


def test_autonomous_run_labels_base_completion_as_an_intermediate_phase() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(_event("agent_started", {"autonomous_route": True}))
    display(_event("agent_finished", {"status": "completed", "turns": 4}))
    display.close()

    text = output.getvalue()
    assert "Base phase finished" in text
    assert "Agent finished" not in text


def test_frontier_and_graph_events_are_safe_and_readable() -> None:
    output = io.StringIO()
    now = [1.0]
    display = RunDisplay(mode="plain", stream=output, clock=lambda: now[0])

    display(_event("frontier_route_started", {"route_model_request_budget": 4}))
    display(
        _event(
            "frontier_model_request_started",
            {
                "worker_id": "worker-secret-ish-id",
                "role": "validator",
                "worker_request": 1,
                "route_model_request": 1,
                "route_model_request_budget": 4,
            },
        )
    )
    now[0] = 2.0
    display(
        _event(
            "frontier_model_reply_received",
            {
                "worker_id": "worker-secret-ish-id",
                "role": "validator",
                "worker_request": 1,
                "cost_usd": 0.01,
            },
        )
    )
    display(
        _event(
            "autonomous_graph_started",
            {"operational_profile": "low-noise", "route_model_request_budget": 6},
        )
    )
    display(
        _event(
            "graph_probe_scope",
            {"node_id": "node-1234567890", "probe": "sqli", "endpoint": "/search?q=secret"},
        )
    )
    display(
        _event(
            "autonomous_graph_finished",
            {
                "status": "solved",
                "route_model_requests": 2,
                "route_tool_calls": 3,
                "route_cost_usd": 0.02,
                "investigation": {"raw": "FLAG{never-print}"},
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "Frontier route started" in text
    assert "Frontier thinking" in text
    assert "Frontier thought complete" in text
    assert "Agent graph started" in text
    assert "Graph scoped sqli" in text
    assert "Agent graph finished" in text
    assert "q=" not in text
    assert "secret" not in text
    assert "FLAG{never-print}" not in text


def test_live_display_restores_an_overlapping_pending_graph_request() -> None:
    output = _TTYBuffer()
    now = [1.0]
    display = RunDisplay(mode="live", stream=output, clock=lambda: now[0])

    display(
        _event(
            "autonomous_graph_model_request_started",
            {"model_request_id": "a", "graph_node_id": "node-a"},
        )
    )
    display(
        _event(
            "autonomous_graph_model_request_started",
            {"model_request_id": "b", "graph_node_id": "node-b"},
        )
    )
    now[0] = 2.0
    display(
        _event(
            "autonomous_graph_model_reply_received",
            {"model_request_id": "b", "graph_node_id": "node-b"},
        )
    )

    assert display._activity is not None  # noqa: SLF001
    assert display._activity.key == "graph-model:a"  # noqa: SLF001
    display.close()
    assert "node-a" in output.getvalue()


def test_proof_event_does_not_finish_the_parent_autonomous_route() -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode="live", stream=output)

    display(_event("autonomous_graph_started"))
    display(
        _event(
            "autonomous_graph_action_started",
            {
                "node_id": "node-a",
                "action_id": "action-a",
                "action_kind": "run_command",
            },
        )
    )
    display(
        _event(
            "tool_run_command",
            {
                "action_id": "action-a",
                "ok": True,
                "recognized_proofs": ["FLAG{hidden}"],
            },
        )
    )
    display(_event("flag_captured", {"flag": "FLAG{hidden}"}))

    assert display._activity is not None  # noqa: SLF001
    assert display._activity.key == "agent-graph"  # noqa: SLF001
    display.close()


def test_correlated_proof_event_finishes_only_its_frontier_action() -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode="live", stream=output)

    display(_event("frontier_route_started"))
    display(
        _event(
            "frontier_action_started",
            {
                "action_id": "capture-a",
                "action_kind": "capture_flag",
            },
        )
    )
    display(
        _event(
            "flag_capture_rejected",
            {"action_id": "capture-a", "flag": "FLAG{hidden}"},
        )
    )

    assert display._activity is not None  # noqa: SLF001
    assert display._activity.key == "frontier-route"  # noqa: SLF001
    display.close()


def test_plain_lines_are_clipped_to_terminal_width(monkeypatch: pytest.MonkeyPatch) -> None:
    width = 48
    monkeypatch.setenv("COLUMNS", str(width))
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "agent_started",
            {
                "target_url": "http://example.test",
                "provider": "provider",
                "model": "model-" + ("x" * 300),
            },
        )
    )
    display.close()

    lines = output.getvalue().splitlines()
    assert lines
    assert all(len(line) <= width for line in lines)
    assert lines[0].endswith("…")


def test_unknown_events_are_ignored_instead_of_dumping_payloads() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(_event("unknown_vendor_event", {"password": "must-not-leak"}))
    display.close()

    assert output.getvalue() == ""


@pytest.mark.parametrize("mode", ["plain", "live"])
def test_untrusted_text_cannot_inject_terminal_control_sequences(mode: str) -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode=mode, stream=output)  # type: ignore[arg-type]
    malicious = "safe\x1b[31mINJECT\x1b[2J\x1b]52;c;Y2xpcGJvYXJk\x07done\x00\u202e"

    display(_event("agent_started", {"model": malicious}))
    display.close()

    text = output.getvalue()
    payload_text = text.replace("\x1b[2K", "").replace("\x1b[?25h", "")
    assert "INJECT" in payload_text
    assert "[31m" not in text
    assert "[2J" not in text
    assert "]52;" not in text
    assert "\x07" not in text
    assert "\x00" not in text
    assert "\u202e" not in text


@pytest.mark.parametrize(
    ("value", "secret"),
    [
        ('{"token":"json-secret"}', "json-secret"),
        ("{'token': 'python-secret'}", "python-secret"),
        ("cookie=session-secret", "session-secret"),
        ("session: abc123", "abc123"),
        ("--api-key cli-secret", "cli-secret"),
        ("credential=alice:password", "alice:password"),
        ("OPENAI_API_KEY=sk-live-secret", "sk-live-secret"),
        ("AWS_SECRET_ACCESS_KEY=aws-live-secret", "aws-live-secret"),
        ("password hunter2", "hunter2"),
        ("https://example.test/?session_id=opaque", "opaque"),
    ],
)
def test_untrusted_key_value_secret_forms_are_redacted(value: str, secret: str) -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(_event("agent_started", {"provider": "provider", "model": value}))
    display.close()

    text = output.getvalue()
    assert secret not in text
    assert "Agent started" in text


def test_unstructured_action_tool_and_final_text_is_never_rendered() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "action_started",
            {
                "action_id": "action-opaque",
                "action_kind": "run_command",
                "detail": "opaque-action-secret",
                "strategy": "opaque-strategy-secret",
            },
        )
    )
    display(
        _event(
            "tool_run_command",
            {
                "action_id": "action-opaque",
                "ok": True,
                "result": '{"summary":"opaque-tool-secret"}',
            },
        )
    )
    display(_event("agent_final", {"summary": "opaque-model-secret"}))
    display.close()

    text = output.getvalue()
    assert "Run command" in text
    assert "Command finished" in text
    assert "Agent returned a final response" in text
    assert "opaque-" not in text


def test_autonomous_action_and_failure_events_close_their_activities() -> None:
    output = io.StringIO()
    now = [1.0]
    display = RunDisplay(mode="plain", stream=output, clock=lambda: now[0])

    display(_event("frontier_route_started"))
    display(
        _event(
            "frontier_action_started",
            {
                "worker_id": "worker-123",
                "action_id": "frontier-action-1",
                "action_kind": "run_probe",
            },
        )
    )
    now[0] = 2.0
    display(
        _event(
            "frontier_action_completed",
            {
                "action_id": "frontier-action-1",
                "action": {"action": "run_probe"},
                "outcome": {"ok": False, "outcome": "no_signal"},
            },
        )
    )
    display(_event("frontier_route_failed", {"error_type": "RuntimeError"}))
    display(_event("autonomous_graph_started"))
    display(
        _event(
            "autonomous_graph_action_started",
            {
                "node_id": "node-123",
                "action_id": "graph-action-1",
                "action_kind": "run_command",
            },
        )
    )
    display(
        _event(
            "autonomous_graph_action_failed",
            {
                "node_id": "node-123",
                "action_id": "graph-action-1",
                "action_kind": "run_command",
                "error_type": "ToolError",
            },
        )
    )
    display(_event("autonomous_graph_cancelled", {"error_type": "KeyboardInterrupt"}))
    display.close()

    text = output.getvalue()
    assert "Frontier Run probe" in text
    assert "Frontier route failed" in text
    assert "runtimeerror" in text
    assert "Graph Run command" in text
    assert "Graph Run command failed" in text
    assert "Agent graph cancelled" in text
    assert display._activity is None  # noqa: SLF001
    assert display._started == {}  # noqa: SLF001


def test_malformed_metrics_are_ignored_instead_of_breaking_display() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "agent_finished",
            {
                "status": "completed",
                "turns": float("nan"),
                "cost_usd": float("inf"),
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "Agent finished" in text
    assert "$nan" not in text
    assert "$inf" not in text


def test_live_animation_does_not_consume_the_injected_event_clock() -> None:
    output = _TTYBuffer()
    ticks = iter((10.0, 10.5))
    display = RunDisplay(mode="live", stream=output, clock=lambda: next(ticks))

    display(_event("agent_started"))
    display(_event("recon_completed"))
    display.close()

    assert "0.5s" in output.getvalue()


def test_dashboard_usage_and_signal_totals_ignore_replayed_events() -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode="live", stream=output)
    expected_input_tokens = 1_250
    expected_output_tokens = 80
    expected_signals = 3
    reply = {
        "model_request_id": "request-1",
        "input_tokens": expected_input_tokens,
        "output_tokens": expected_output_tokens,
        "cost_usd": 0.0012,
    }
    probe = {
        "action_id": "action-1",
        "ok": True,
        "display_summary": {"candidate_signals": expected_signals},
    }

    display(_event("model_reply_received", reply))
    display(_event("model_reply_received", reply))
    display(_event("tool_run_probe", probe))
    display(_event("tool_run_probe", probe))

    assert display._run_input_tokens == expected_input_tokens  # noqa: SLF001
    assert display._run_output_tokens == expected_output_tokens  # noqa: SLF001
    assert display._run_cost_usd == pytest.approx(0.0012)  # noqa: SLF001
    assert display._candidate_signal_count == expected_signals  # noqa: SLF001
    display.close()


def test_missing_executor_status_is_neutral_instead_of_success() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(_event("tool_run_command", {"action_id": "unknown-result"}))
    display(_event("agent_finished", {"turns": 1}))
    display.close()

    text = output.getvalue()
    assert "[info] Command finished" in text
    assert "[ok] Command finished" not in text
    assert "[warn] Agent status unknown" in text


def test_explicit_tool_failure_cannot_be_overwritten_by_nested_success() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "tool_run_command",
            {
                "action_id": "conflicting-result",
                "ok": False,
                "result": {"ok": True, "exit_code": 0},
            },
        )
    )
    display(
        _event(
            "tool_run_command",
            {
                "action_id": "conflicting-exit",
                "ok": True,
                "exit_code": 0,
                "result": {"ok": True, "exit_code": 7},
            },
        )
    )
    display.close()

    text = output.getvalue()
    expected_failure_count = 2
    assert text.count("[fail] Command finished") == expected_failure_count
    assert "exit=7" in text
    assert "[ok] Command finished" not in text


def test_resumed_run_reconciles_executor_final_finding_and_flag_totals() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "agent_finished",
            {
                "status": "completed",
                "turns": 4,
                "finding_count": 2,
                "flags": ["FLAG{resume-secret}"],
                "flag_record_path": "runs/resumed/workspace/events.jsonl",
            },
        )
    )

    text = output.getvalue()
    assert "Agent finished · 4 turns · findings=2 · flags=1" in text
    assert "Flag recorded in · runs/resumed/workspace/events.jsonl" in text
    assert "Look for · event=flag_captured · field=payload.flag" in text
    assert "resume-secret" not in text
    expected_findings = 2
    assert display._dashboard_findings == expected_findings  # noqa: SLF001
    assert display._dashboard_flags == 1  # noqa: SLF001
    display.close()


class _FailingDashboard:
    def __init__(self) -> None:
        self.stop_calls = 0

    def print_line(self, *_args: object, **_kwargs: object) -> bool:
        return False

    def stop(self) -> None:
        self.stop_calls += 1


class _RefreshFailingDashboard(_FailingDashboard):
    def print_line(self, *_args: object, **_kwargs: object) -> bool:
        return True

    def update(self, *_args: object, **_kwargs: object) -> bool:
        return False


def test_live_renderer_failure_degrades_once_and_preserves_later_output() -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode="plain", stream=output)
    failing = _FailingDashboard()
    display.mode = "live"
    display._dashboard = failing  # type: ignore[assignment]  # noqa: SLF001

    display(_event("recon_completed"))
    display(_event("agent_finished", {"status": "completed", "turns": 1}))
    display.close()

    text = output.getvalue()
    assert text.count("Live display unavailable; continuing in plain mode") == 1
    assert "[ok] Recon complete" in text
    assert "[ok] Agent finished" in text
    assert display.mode == "plain"
    assert failing.stop_calls == 1


def test_live_refresh_failure_preserves_current_activity_in_plain_output() -> None:
    output = _TTYBuffer()
    display = RunDisplay(mode="plain", stream=output)
    failing = _RefreshFailingDashboard()
    display.mode = "live"
    display._dashboard = failing  # type: ignore[assignment]  # noqa: SLF001

    display._set_activity("probe", "Validating PoC")  # noqa: SLF001
    display(_event("recon_completed"))
    display.close()

    text = output.getvalue()
    assert text.count("Live display unavailable; continuing in plain mode") == 1
    assert "[run] Validating PoC" in text
    assert "[ok] Recon complete" in text
    assert display.mode == "plain"
    assert failing.stop_calls == 1


def test_stale_final_flag_total_does_not_reduce_observed_flags() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(_event("flag_captured", {"flag": "FLAG{first}"}))
    display(_event("flag_captured", {"flag": "FLAG{second}"}))
    display(
        _event(
            "agent_finished",
            {"status": "completed", "turns": 2, "flags": [], "flag_count": 0},
        )
    )
    display.close()

    text = output.getvalue()
    assert "Agent finished · 2 turns · flags=2" in text
    assert "FLAG{" not in text


def test_flag_totals_remain_cumulative_across_agent_phases() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)

    display(
        _event(
            "agent_started",
            {"target_url": "https://example.test", "autonomous_route": True},
        )
    )
    display(_event("flag_captured", {"flag": "FLAG{first}"}))
    display(_event("flag_captured", {"flag": "FLAG{second}"}))
    display(
        _event(
            "agent_finished",
            {
                "status": "completed",
                "turns": 2,
                "flags": ["FLAG{first}", "FLAG{second}"],
            },
        )
    )
    display(_event("flag_captured", {"flag": "FLAG{third}"}))
    display.close()

    text = output.getvalue()
    assert "Base phase finished · 2 turns · flags=2" in text
    assert "Flag found · 3 unique flags total" in text
    expected_flags = 3
    assert display._dashboard_flags == expected_flags  # noqa: SLF001
    assert "FLAG{" not in text


def test_unicode_format_controls_cannot_forge_live_or_plain_rows() -> None:
    output = io.StringIO()
    display = RunDisplay(mode="plain", stream=output)
    malicious = "safe\u2028FORGED\u2029ROW\u200bZERO\u2060WIDTH\u00adSOFT"

    display(
        _event(
            "harness_selection",
            {
                "selected_action": {"action": "run_probe", "notes": malicious},
                "selected_route": {},
            },
        )
    )
    display.close()

    text = output.getvalue()
    assert "safe FORGED ROWZEROWIDTHSOFT" in text
    for control in ("\u2028", "\u2029", "\u200b", "\u2060", "\u00ad"):
        assert control not in text
