from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import sys
import textwrap
import threading
import time
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal
from urllib.parse import parse_qsl, unquote, urlsplit

from ravage.agent_core.live_events import MASK, mask_command_string
from ravage.cli_live_renderer import (
    DashboardActivity,
    RichRunDashboard,
    RunDashboardSnapshot,
)
from ravage.finding_evidence import confirmed_finding_evidence_failures
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from types import TracebackType
    from typing import Any, Self, TextIO

DisplayMode = Literal["auto", "live", "plain", "quiet"]

_DISPLAY_MODES = frozenset({"auto", "live", "plain", "quiet"})
_TICK_SECONDS = 0.12
_MIN_WIDTH = 4
_MAX_WIDTH = 240
_DEFAULT_WIDTH = 100
_MAX_DETAIL_CHARS = 180
_MAX_UNTRUSTED_INPUT_CHARS = 65_536
_MAX_SIGNAL_DETAILS = 6
_MAX_DNS_HOST_CHARS = 253
_MAX_DNS_LABEL_CHARS = 63
_SHORT_ID_CHARS = 12
_MIN_DYNAMIC_NUMERIC_SEGMENT_CHARS = 2
_MIN_ENTROPY_PATH_SEGMENT_CHARS = 20
_HTTP_CLIENT_ERROR_STATUS = 400
_HTTP_SERVER_ERROR_STATUS = 500
_THOUSAND = 1_000
_MILLION = 1_000_000
_TENTH_SECOND = 0.1
_MINUTE_SECONDS = 60

_OPTION_SECRET_RE = re.compile(
    r"(?i)(^|\s)((?:--?(?:password|passwd|pwd|secret|token|api[-_]?key|authorization|"
    r"cookie|session)|-u)\s+)(?:'[^']*'|\"[^\"]*\"|\S+)"
)
_INLINE_SECRET_RE = re.compile(
    r"(?i)((?:['\"]?\b(?:password|passwd|pwd|secret|token|otp|api[-_]?key|"
    r"access[-_]?key|authorization|session|cookie|credential|private[-_]?key)"
    r"\b['\"]?)\s*[=:]\s*)"
    r"(?:'[^']*'|\"[^\"]*\"|[^,}\]\s;&]+)"
)
_ENV_SECRET_RE = re.compile(
    r"(?i)(\b[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|"
    r"ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?))(\s*=\s*)"
    r"(?:'[^']*'|\"[^\"]*\"|[^,}\]\s;&]+)"
)
_SPACED_SECRET_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|token|otp|api[-_]?key|access[-_]?key|"
    r"authorization|session|cookie|credential|private[-_]?key)\b\s+)"
    r"(?:'[^']*'|\"[^\"]*\"|\S+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s'\"]+")
_HEADER_SECRET_RE = re.compile(
    r"(?i)\b(Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:\s*[^'\"\r\n]+"
)
_URL_CREDENTIAL_RE = re.compile(r"(?i)(https?://)[^/@\s]+@")
_URL_QUERY_VALUE_RE = re.compile(r"([?&][^=&#\s]+)=([^&#\s]*)")
_ANSI_SEQUENCE_RE = re.compile(
    r"\x1b(?:"
    r"\][^\x07\x1b]*(?:\x07|\x1b\\)|"
    r"\[[0-?]*[ -/]*[@-~]|"
    r"[PX^_].*?\x1b\\|"
    r"[@-_]"
    r")",
    re.DOTALL,
)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_TRANSCRIPT_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_BIDI_CONTROL_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")

_ACTION_LABELS = {
    "run_command": "Run command",
    "run_python": "Run Python helper",
    "run_probe": "Run probe",
    "validate_poc": "Validate PoC",
    "capture_flag": "Check proof candidate",
    "final": "Finish run",
    "invalid": "Invalid action",
    "http_request": "HTTP request",
    "process_start": "Start process",
    "process_read": "Read process",
    "process_write": "Write process",
    "process_stop": "Stop process",
}
_HTTP_METHODS = frozenset(
    {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}
)
_UUID_PATH_SEGMENT_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_TOKEN_PATH_SEGMENT_RE = re.compile(
    r"(?i)^(?:"
    r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]+|"
    r"sk[-_](?:proj[-_])?[A-Za-z0-9_-]{8,}|"
    r"gh(?:p|o|u|s|r)_[A-Za-z0-9]{8,}|"
    r"github_pat_[A-Za-z0-9_]{8,}|"
    r"xox(?:b|p|a|r|s)-[A-Za-z0-9-]{8,}|"
    r"AKIA[A-Z0-9]{12,}|"
    r"(?:token|secret|session|auth)[._-][A-Za-z0-9._-]+"
    r")$"
)
_SENSITIVE_PATH_PARENTS = frozenset(
    {
        "activate",
        "callback",
        "confirm",
        "invite",
        "magic",
        "otp",
        "password-reset",
        "recover",
        "reset",
        "session",
        "token",
        "verify",
    }
)
@dataclass(frozen=True)
class _Activity:
    key: str
    label: str
    started_at: float
    animation_started_at: float


@dataclass(frozen=True)
class _Line:
    tone: Literal["ok", "fail", "warn", "run", "info", "agent"]
    text: str


class RunDisplay:
    """Render structured run events as a live dashboard or stable plain lines."""

    def __init__(  # noqa: PLR0915
        self,
        mode: DisplayMode = "auto",
        *,
        stream: TextIO | None = None,
        clock: Callable[[], float] | None = None,
        show_agent_actions: bool = False,
    ) -> None:
        if mode not in _DISPLAY_MODES:
            choices = ", ".join(sorted(_DISPLAY_MODES))
            message = f"display mode must be one of: {choices}"
            raise ValueError(message)
        self.stream = stream or sys.stdout
        self.mode: DisplayMode = _resolve_mode(mode, self.stream)
        self._unicode = _unicode_supported(self.stream)
        self.clock = clock or time.monotonic
        self.show_agent_actions = show_agent_actions
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._closed = False
        self._activity: _Activity | None = None
        self._started: dict[str, float] = {}
        self._pending: dict[str, _Activity] = {}
        self._tool_completed_actions: set[str] = set()
        self._action_probes: dict[str, str] = {}
        self._action_fallbacks: dict[str, str] = {}
        self._blocked_actions: set[str] = set()
        self._proof_actions: set[str] = set()
        self._proof_fingerprints: set[str] = set()
        self._finding_fingerprints: set[str] = set()
        self._confirmed_finding_count = 0
        self._confirmed_flag_count = 0
        self._flag_objective: bool | None = None
        self._finding_record_path = ""
        self._report_path = ""
        self._audit_path = ""
        self._flag_record_path = ""
        self._flag_location_announced = False
        self._narrated_attempts: set[str] = set()
        self._last_signal_counts: dict[str, int] = {}
        self._run_target = ""
        self._run_model = ""
        self._run_agent_mode = ""
        self._run_phase = ""
        self._run_turn = 0
        self._run_max_turns = 0
        self._run_input_tokens = 0
        self._run_output_tokens = 0
        self._run_cost_usd = 0.0
        self._accounted_model_replies: set[str] = set()
        self._accounted_tool_summaries: set[str] = set()
        self._candidate_signal_count = 0
        self._dashboard_findings = 0
        self._dashboard_flags = 0
        self._run_started = False
        self._run_terminal = False
        self._run_animation_started_at = time.monotonic()
        self._autonomous_route_expected = False
        self._dashboard: RichRunDashboard | None = None
        if self.mode == "live":
            try:
                self._dashboard = RichRunDashboard(
                    stream=self.stream,
                    color=_color_enabled(),
                    unicode=self._unicode,
                )
            except Exception:  # noqa: BLE001 - display setup must not abort an attack.
                self.mode = "plain"
                self._write_plain_line(
                    _Line("warn", "Live display unavailable; continuing in plain mode")
                )
        self._thread: threading.Thread | None = None
        if self.mode == "live":
            self._thread = threading.Thread(
                target=self._animate,
                name="ravage-run-display",
                daemon=True,
            )
            self._thread.start()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __call__(self, event: Mapping[str, Any]) -> None:
        if self.mode == "quiet":
            return
        with self._lock:
            if self._closed:
                return
            self._handle_event(event)

    def close(self) -> None:
        thread: threading.Thread | None
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            self._activity = None
            self._pending.clear()
            self._started.clear()
            self._tool_completed_actions.clear()
            self._action_probes.clear()
            self._action_fallbacks.clear()
            self._blocked_actions.clear()
            self._proof_actions.clear()
            self._proof_fingerprints.clear()
            self._finding_fingerprints.clear()
            self._confirmed_finding_count = 0
            self._confirmed_flag_count = 0
            self._flag_objective = None
            self._finding_record_path = ""
            self._report_path = ""
            self._audit_path = ""
            self._flag_record_path = ""
            self._flag_location_announced = False
            self._narrated_attempts.clear()
            self._last_signal_counts.clear()
            self._accounted_model_replies.clear()
            self._accounted_tool_summaries.clear()
            if self._dashboard is not None:
                with suppress(Exception):
                    self._dashboard.stop()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=0.5)

    def _handle_event(self, event: Mapping[str, Any]) -> None:  # noqa: C901, PLR0911, PLR0912
        kind = str(event.get("kind") or "")
        payload_value = event.get("payload")
        payload = payload_value if isinstance(payload_value, dict) else {}
        self._track_run_context(kind, payload)

        if kind == "agent_started":
            self._agent_started(payload)
            return
        if kind in {"recon_completed", "recon_failed"}:
            self._recon_finished(kind, payload)
            return
        if kind == "model_request_started":
            self._model_started(payload)
            return
        if kind == "model_reply_received":
            self._model_finished(payload)
            return
        if kind == "model_request_failed":
            self._model_failed(payload)
            return
        if kind == "harness_selection":
            self._selection(payload)
            return
        if kind == "action_started":
            self._action_started(payload)
            return
        if kind == "probe_http_exchange":
            if self.show_agent_actions:
                self._probe_http_exchange(payload)
            return
        if kind in {
            "tool_run_command",
            "tool_run_python",
            "tool_run_probe",
            "tool_validate_poc",
        }:
            self._tool_finished(kind, payload)
            return
        if kind == "http_step":
            self._http_step(payload)
            return
        if kind == "agent_attempt_recorded":
            self._attempt_finished(payload)
            return
        if kind == "harness_turn_trace":
            self._turn_finished(payload)
            return
        if kind in {"repeated_action_blocked", "invalid_action"}:
            self._action_blocked(kind, payload)
            return
        if kind == "finding_confirmed":
            self._finding_confirmed(payload)
            return
        if kind == "finding_rejected_no_evidence":
            self._finding_rejected_no_evidence(payload)
            return
        if kind in {"flag_captured", "flag_capture_rejected"}:
            self._proof_event(kind, payload)
            return
        if kind == "agent_final":
            self._agent_final(payload)
            return
        if kind == "cost_budget_exhausted":
            self._cost_exhausted(payload)
            return
        if kind == "agent_finished":
            self._agent_finished(payload)
            return
        if kind.startswith("frontier_"):
            self._frontier_event(kind, payload)
            return
        if kind.startswith("autonomous_graph_") or kind == "graph_probe_scope":
            self._graph_event(kind, payload)

    def _track_run_context(  # noqa: C901, PLR0912, PLR0915
        self,
        kind: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Project safe, executor-owned run state for the interactive dashboard."""
        turn = _positive_int(payload.get("turn"))
        if turn:
            self._run_turn = turn
        phase = _safe_identifier(payload.get("phase"))
        if phase:
            self._run_phase = phase

        if kind == "agent_started":
            self._clear_correlation_state()
            self._proof_fingerprints.clear()
            self._finding_fingerprints.clear()
            self._confirmed_finding_count = 0
            self._confirmed_flag_count = 0
            self._flag_objective = None
            self._finding_record_path = ""
            self._report_path = ""
            self._audit_path = ""
            self._flag_record_path = ""
            self._flag_location_announced = False
            self._run_target = _safe_target(payload.get("target_url"))
            self._run_model = _model_label(payload)
            self._run_agent_mode = _human_identifier(payload.get("agent_mode"))
            self._run_max_turns = _positive_int(payload.get("max_turns"))
            self._run_phase = "recon"
            self._run_turn = 0
            self._run_input_tokens = 0
            self._run_output_tokens = 0
            self._run_cost_usd = 0.0
            self._accounted_model_replies.clear()
            self._accounted_tool_summaries.clear()
            self._candidate_signal_count = 0
            self._dashboard_findings = 0
            self._dashboard_flags = 0
            self._run_started = True
            self._run_terminal = False
            self._run_animation_started_at = time.monotonic()
            return

        if kind in {
            "model_reply_received",
            "frontier_model_reply_received",
            "autonomous_graph_model_reply_received",
        }:
            reply_key = _dashboard_model_reply_key(kind, payload)
            if not reply_key or reply_key not in self._accounted_model_replies:
                if reply_key:
                    self._accounted_model_replies.add(reply_key)
                self._run_input_tokens += _non_negative_int(payload.get("input_tokens"))
                self._run_output_tokens += _non_negative_int(payload.get("output_tokens"))
                self._run_cost_usd += _finite_non_negative_float(payload.get("cost_usd"))

        if kind in {
            "tool_run_command",
            "tool_run_python",
            "tool_run_probe",
            "tool_validate_poc",
        }:
            summary = _object(payload.get("display_summary"))
            action_id = str(payload.get("action_id") or "").strip()
            if action_id and action_id in self._accounted_tool_summaries:
                return
            if action_id:
                self._accounted_tool_summaries.add(action_id)
            signal_value = next(
                (
                    summary.get(key)
                    for key in ("candidate_signals", "signals", "findings")
                    if key in summary
                ),
                0,
            )
            self._candidate_signal_count += _non_negative_int(signal_value)

        if kind == "frontier_route_started":
            self._run_phase = "frontier"
            self._run_terminal = False
        elif kind == "autonomous_graph_started":
            self._run_phase = "agent_graph"
            self._run_terminal = False
        elif kind == "agent_finished":
            final_cost = _finite_non_negative_float(payload.get("cost_usd"))
            self._run_cost_usd = max(self._run_cost_usd, final_cost)
            self._dashboard_findings = max(
                self._dashboard_findings,
                _non_negative_int(payload.get("finding_count")),
            )
            reported_flags = payload.get("flags")
            reported_flag_count = max(
                len(reported_flags) if isinstance(reported_flags, list) else 0,
                _non_negative_int(payload.get("flag_count")),
            )
            self._dashboard_flags = max(
                self._dashboard_flags,
                reported_flag_count,
            )
            self._run_terminal = not self._autonomous_route_expected
        elif kind in {
            "frontier_route_finished",
            "frontier_route_failed",
            "frontier_route_cancelled",
            "autonomous_graph_finished",
            "autonomous_graph_failed",
            "autonomous_graph_cancelled",
        }:
            self._run_terminal = True

    def _agent_started(self, payload: Mapping[str, Any]) -> None:
        self._autonomous_route_expected = payload.get("autonomous_route") is True
        if isinstance(payload.get("flag_objective"), bool):
            self._flag_objective = payload["flag_objective"]
        target = _safe_target(payload.get("target_url"))
        model = _model_label(payload)
        mode = _safe_identifier(payload.get("agent_mode"))
        max_turns = _positive_int(payload.get("max_turns"))
        details = [item for item in (target, model, mode) if item]
        if max_turns:
            details.append(f"up to {max_turns} turns")
        self._emit(_Line("info", _join("Agent started", details)))
        self._begin("recon", "Mapping the target")

    def _recon_finished(self, kind: str, payload: Mapping[str, Any]) -> None:
        elapsed = self._finish("recon")
        if kind == "recon_failed":
            error_type = _safe_identifier(payload.get("error_type"))
            self._emit(_Line("warn", _join("Recon degraded", [elapsed, error_type])))
            return
        outcome = _recon_outcome(payload)
        if outcome == "failed":
            self._emit(_Line("fail", _join("Recon failed", [elapsed, *_recon_details(payload)])))
        elif outcome == "degraded":
            self._emit(_Line("warn", _join("Recon degraded", [elapsed, *_recon_details(payload)])))
        else:
            self._emit(_Line("ok", _join("Recon complete", [elapsed, *_recon_details(payload)])))
        if self.show_agent_actions:
            self._recon_actions(payload)

    def _model_started(self, payload: Mapping[str, Any]) -> None:
        key = _model_key(payload)
        turn = _turn_label(payload)
        model = _model_label(payload)
        phase = _safe_identifier(payload.get("phase"))
        label = _join("Thinking", [turn, model, phase])
        self._start(key)
        if self.mode == "plain":
            self._emit(_Line("run", label))
        if self.show_agent_actions:
            self._narrate(
                "I'm reviewing the mapped inputs and choosing the smallest safe test."
            )
        self._set_activity(key, label)

    def _model_finished(self, payload: Mapping[str, Any]) -> None:
        key = _model_key(payload)
        elapsed = self._finish(key)
        turn = _turn_label(payload)
        usage = _token_usage(payload)
        cost = _cost(payload.get("cost_usd"))
        self._emit(_Line("ok", _join("Model replied", [turn, elapsed, usage, cost])))

    def _model_failed(self, payload: Mapping[str, Any]) -> None:
        key = _model_key(payload)
        elapsed = self._finish(key)
        turn = _turn_label(payload)
        error_type = _safe_identifier(payload.get("error_type"))
        self._emit(_Line("fail", _join("Model request failed", [turn, elapsed, error_type])))

    def _selection(self, payload: Mapping[str, Any]) -> None:  # noqa: C901, PLR0912
        action = _object(payload.get("selected_action"))
        route = _object(payload.get("selected_route"))
        turn = _turn_label(payload)
        action_label = _planned_action_label(action)
        family = _human_identifier(route.get("family"))
        if family == "unknown":
            family = ""
        details = [turn]
        override_reason = ""
        if payload.get("selected_differs_from_model") is True:
            proposed = _object(payload.get("proposed_action"))
            proposed_label = _planned_action_label(proposed)
            if proposed_label and proposed_label != action_label:
                action_label = f"{proposed_label} → {action_label}"
            override_reason = _human_identifier(payload.get("selection_reason"))
        details.extend([action_label, family])
        self._emit(_Line("run", _join("Plan", details)))
        if override_reason:
            self._emit(_Line("warn", _join("Plan adjusted by harness", [override_reason])))

        if self.show_agent_actions:
            hypotheses = action.get("hypotheses")
            if isinstance(hypotheses, list):
                for value in hypotheses[:3]:
                    hypothesis = _safe_narrative(value)
                    if hypothesis:
                        self._narrate("I suspect " + _sentence_fragment(hypothesis))
            notes = _safe_narrative(action.get("notes"))
            if notes:
                self._narrate("Next I'll " + _sentence_fragment(notes))
            else:
                planned = _planned_action_narrative(action)
                if planned:
                    self._narrate("Next I'll " + planned)
            expected = _safe_narrative(action.get("expected_signal"))
            if expected:
                self._narrate("I'm looking for this signal: " + expected)
            fallback = _safe_narrative(action.get("fallback"))
            if fallback:
                self._narrate("If that signal is absent, my fallback is: " + fallback)
            return

        notes = _safe_narrative(action.get("notes"))
        if notes:
            self._emit(_Line("info", "  " + _join("Intent", [notes])))

        expected = _safe_narrative(action.get("expected_signal"))
        if expected:
            self._emit(_Line("info", "  " + _join("Looking for", [expected])))

    def _action_started(self, payload: Mapping[str, Any]) -> None:
        key = _action_key(payload)
        action_kind = _safe_identifier(payload.get("action_kind"))
        probe = _probe_name(payload)
        summary = _action_started_label(action_kind, probe=probe)
        turn = _turn_label(payload)
        label = _join(summary, [turn])
        action_id = str(payload.get("action_id") or "").strip()
        if action_id:
            if probe:
                self._action_probes[action_id] = probe
            fallback = _safe_narrative(payload.get("fallback"))
            if fallback:
                self._action_fallbacks[action_id] = fallback
        self._start(key)
        if self.mode == "plain":
            self._emit(_Line("run", label))
        if self.show_agent_actions:
            narrative = _probe_start_narrative(probe)
            if narrative:
                self._narrate(narrative)
        self._set_activity(key, label)

    def _tool_finished(  # noqa: C901, PLR0912
        self,
        kind: str,
        payload: Mapping[str, Any],
    ) -> None:
        elapsed = self._finish_action(payload)
        timed_out = payload.get("timed_out") is True
        result = _object(payload.get("result"))
        if result:
            timed_out = result.get("timed_out") is True or timed_out
        status_values = [
            value
            for value in (payload.get("ok"), result.get("ok"))
            if isinstance(value, bool)
        ]
        if False in status_values:
            ok_value: bool | None = False
        elif True in status_values:
            ok_value = True
        else:
            ok_value = None
        exit_code = _resolved_tool_exit_code(payload, result)
        if exit_code is not None:
            if exit_code != 0:
                ok_value = False
            elif ok_value is None:
                ok_value = True
        action_id = str(payload.get("action_id") or "").strip()
        probe = self._action_probes.get(action_id, "")
        display_summary = _object(payload.get("display_summary"))
        if not probe:
            probe = _safe_identifier(display_summary.get("probe"))
        label = _tool_label(kind, payload, result, probe=probe)
        details = _tool_details(payload, result, probe_result=kind == "tool_run_probe")
        details.extend(_probe_display_details(display_summary))
        if elapsed:
            details.insert(0, elapsed)
        tone: Literal["ok", "fail", "warn", "info"] = "info"
        if timed_out:
            tone = "fail"
            details.append("timed out")
        elif ok_value is False:
            tone = "fail"
        elif ok_value is True:
            tone = "ok"
        self._emit(_Line(tone, _join(label, details)))
        summary = _safe_narrative(display_summary.get("summary"))
        if summary:
            if kind == "tool_run_probe":
                summary = _candidate_signal_narrative(summary)
            self._emit(_Line("info", "  " + _join("Observed", [summary])))
        if action_id:
            self._tool_completed_actions.add(action_id)

    def _http_step(self, payload: Mapping[str, Any]) -> None:
        method = _http_method(payload.get("method"))
        status = _positive_int(payload.get("status"))
        ok = payload.get("ok")
        fields_value = payload.get("fields")
        fields = [str(key) for key in fields_value] if isinstance(fields_value, dict) else []
        details = [f"→ {status}" if status else ""]
        if fields:
            details.append("fields=" + ",".join(fields[:6]))
        tone: Literal["ok", "fail", "run"] = "run"
        if ok is True:
            tone = "ok"
        elif ok is False:
            tone = "fail"
        self._emit(_Line(tone, "  " + _join(f"{method} request", details)))

    def _probe_http_exchange(self, payload: Mapping[str, Any]) -> None:
        before, after = _probe_exchange_narrative(payload)
        if before:
            self._narrate(before)
        index = _positive_int(payload.get("index"))
        method = _http_method(payload.get("method"))
        target = _probe_request_target(payload)
        request_body = _safe_narrative(payload.get("request_body"))
        request_label = _join(
            f"Request {index:02d}" if index else "Request",
            [method],
        )
        if target:
            request_label += " · " + target
        if request_body:
            request_label += " · body=" + request_body
        self._emit(_Line("run", "  " + request_label))

        status = _positive_int(payload.get("status"))
        elapsed_ms = _non_negative_int(payload.get("elapsed_ms"))
        disposition = _safe_identifier(payload.get("disposition"))
        error = _safe_narrative(payload.get("error"))
        response = _safe_narrative(payload.get("response_summary"))
        details = [str(status) if status else disposition, f"{elapsed_ms}ms"]
        if error:
            details.append(error)
        elif response:
            details.append(response)
        tone: Literal["ok", "fail", "info"] = "info"
        if status and status < _HTTP_CLIENT_ERROR_STATUS:
            tone = "ok"
        elif error or disposition == "blocked" or status >= _HTTP_SERVER_ERROR_STATUS:
            tone = "fail"
        self._emit(_Line(tone, "    " + _join("Response", details)))
        if after:
            self._narrate(after)

    def _recon_actions(self, payload: Mapping[str, Any]) -> None:  # noqa: C901
        pages = payload.get("pages")
        if not isinstance(pages, list):
            return
        for raw_page in pages[:8]:
            if not isinstance(raw_page, dict):
                continue
            page = raw_page
            path, _query_names = _safe_url_shape(
                str(page.get("final_url") or page.get("url") or "")
            )
            status = _positive_int(page.get("status"))
            title = _safe_narrative(page.get("title"))
            self._emit(
                _Line(
                    "info",
                    "  "
                    + _join(
                        "Mapped", ["GET " + (path or "/"), str(status) if status else "", title]
                    ),
                )
            )
            reflections = page.get("reflected_parameters")
            if isinstance(reflections, list):
                for raw_reflection in reflections[:6]:
                    if not isinstance(raw_reflection, dict):
                        continue
                    name = _safe_parameter_name(raw_reflection.get("name"))
                    reflection_path, _names = _safe_url_shape(str(raw_reflection.get("url") or ""))
                    if name:
                        self._emit(
                            _Line(
                                "ok",
                                "  "
                                + _join(
                                    "Reflection",
                                    [name, f"GET {reflection_path or path or '/'}"],
                                ),
                            )
                        )
                        self._narrate(
                            _sentence(
                                f"I found the {name} input reflected by "
                                f"GET {reflection_path or path or '/'}"
                            )
                        )
                        self._narrate(
                            "I should compare a normal value with harmless, "
                            "context-specific probes."
                        )
            forms = page.get("forms")
            if not isinstance(forms, list):
                continue
            for raw_form in forms[:6]:
                if not isinstance(raw_form, dict):
                    continue
                form = raw_form
                method = _http_method(form.get("method"))
                form_path, _names = _safe_url_shape(str(form.get("action") or ""))
                inputs = form.get("inputs")
                fields = _form_input_names(inputs)
                details = [f"{method} {form_path or '/'}"]
                if fields:
                    details.append("fields=" + ",".join(fields))
                self._emit(_Line("info", "  " + _join("Form", details)))

    def _narrate(self, value: str) -> None:
        narrative = _safe_narrative(_sentence(value))
        if not narrative:
            return
        prefix_width = 2 if self._dashboard is not None else len("[agent] ")
        width = max(24, _terminal_width(self.stream) - prefix_width)
        sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", narrative)
        for sentence in sentences:
            for line in textwrap.wrap(
                sentence,
                width=width,
                break_long_words=False,
                break_on_hyphens=False,
            ):
                self._emit(_Line("agent", line))

    def _attempt_finished(self, payload: Mapping[str, Any]) -> None:
        action_id = str(payload.get("action_id") or "").strip()
        if action_id:
            self._narrated_attempts.add(action_id)
        if action_id and action_id in self._blocked_actions:
            self._blocked_actions.discard(action_id)
            self._action_probes.pop(action_id, None)
            self._action_fallbacks.pop(action_id, None)
            return
        if action_id and action_id in self._proof_actions:
            self._proof_actions.discard(action_id)
            self._action_probes.pop(action_id, None)
            self._action_fallbacks.pop(action_id, None)
            return
        outcome = _object(payload.get("outcome"))
        classification = _safe_identifier(outcome.get("classification"))
        status = _safe_identifier(payload.get("status"))
        novel = payload.get("novel") is True
        tone: Literal["ok", "warn", "info"] = "info"
        if novel or classification in {"confirmed_signal", "flag_candidate", "new_surface"}:
            tone = "ok"
        elif outcome.get("ok") is False or classification in {"blocked", "same_as_before"}:
            tone = "warn"

        result = _outcome_label(classification or status) or "observed"
        delta = _object(payload.get("state_delta"))
        progress = _state_delta_details(delta)
        if not progress and tone == "warn":
            progress.append("no new evidence")
        self._emit(_Line(tone, _join("Result", [_turn_label(payload), result, *progress])))

        if tone == "warn" and action_id:
            fallback = self._action_fallbacks.get(action_id, "")
            if fallback:
                self._emit(_Line("info", "  " + _join("Suggested next", [fallback])))
        if action_id:
            self._action_probes.pop(action_id, None)
            self._action_fallbacks.pop(action_id, None)

    def _turn_finished(self, payload: Mapping[str, Any]) -> None:
        outcome = _object(payload.get("outcome"))
        state = _object(payload.get("post_state"))
        self._remember_signal_counts(state)
        action_id = str(payload.get("action_id") or "").strip()
        if action_id and action_id in self._narrated_attempts:
            self._narrated_attempts.discard(action_id)
            return
        classification = _safe_identifier(outcome.get("classification"))
        flags = _non_negative_int(state.get("flags_count"))
        phase = _safe_identifier(state.get("phase"))
        tone: Literal["ok", "warn"] = "ok" if outcome.get("ok") is not False else "warn"
        details = [_turn_label(payload), phase]
        if flags:
            details.append(f"flags={flags}")
        label = _outcome_label(classification).capitalize() if classification else "Turn complete"
        self._emit(_Line(tone, _join(label, details)))

    def _action_blocked(self, kind: str, payload: Mapping[str, Any]) -> None:
        action_id = str(payload.get("action_id") or "").strip()
        if action_id:
            self._finish_action(payload)
            self._tool_completed_actions.add(action_id)
            self._blocked_actions.add(action_id)
        else:
            self._finish(_action_key(payload), fallback_to_active=True)
        if kind == "invalid_action":
            error = _safe_narrative(payload.get("error"))
            detail = error or "asking for a corrected action"
            self._emit(_Line("fail", _join("Invalid model action", [detail])))
        else:
            repeats = _positive_int(payload.get("repeat_count"))
            detail = f"repeat {repeats}" if repeats else ""
            self._emit(_Line("fail", _join("Repeated action blocked", [detail])))
        fallback = self._action_fallbacks.get(action_id, "")
        if fallback:
            self._emit(_Line("info", "  " + _join("Suggested next", [fallback])))

    def _finding_confirmed(self, payload: Mapping[str, Any]) -> None:
        if not _is_evidence_confirmed_finding(payload):
            return
        fingerprint = _finding_fingerprint(payload)
        if fingerprint and fingerprint in self._finding_fingerprints:
            return
        if fingerprint:
            self._finding_fingerprints.add(fingerprint)
        self._confirmed_finding_count += 1
        self._dashboard_findings += 1
        vuln_class = _human_identifier(payload.get("vuln_class") or payload.get("type"))
        severity = _severity_label(payload.get("severity"))
        total = f"findings={self._confirmed_finding_count}"
        self._emit(_Line("ok", _join("Vulnerability confirmed", [vuln_class, severity, total])))

        location = _finding_location(payload)
        if location:
            self._emit(_Line("info", "  " + _join("Location", location)))

        evidence = _finding_evidence_details(payload)
        if evidence:
            self._emit(_Line("info", "  " + _join("Evidence", evidence)))

        finding_id = _safe_record_id(payload.get("finding_id"))
        if finding_id:
            self._emit(_Line("info", "  " + _join("Finding", [finding_id])))

        record_path = _first_safe_path(
            payload,
            "finding_record_path",
            "events_path",
            "record_path",
        )
        if record_path:
            self._finding_record_path = record_path
            self._emit(_Line("info", "  " + _join("Recorded in", [record_path])))

        report_path = _first_safe_path(payload, "report_path")
        if report_path:
            self._report_path = report_path
            self._emit(_Line("info", "  " + _join("Report", [report_path])))

    def _finding_rejected_no_evidence(self, payload: Mapping[str, Any]) -> None:
        vuln_class = _human_identifier(payload.get("vuln_class") or payload.get("type"))
        evidence = _rejected_evidence_details(payload)
        check_summary = evidence[0] if evidence and "checks passed" in evidence[0] else ""
        self._emit(
            _Line(
                "fail",
                _join(
                    "Candidate not confirmed",
                    [vuln_class, "evidence gate failed", check_summary],
                ),
            )
        )
        remaining = evidence[1:] if check_summary else evidence
        for detail in remaining:
            label = detail.removeprefix("missing=").replace(",", " · ")
            self._emit(_Line("info", "  " + _join("Evidence gap", [label])))
        finding_id = _safe_record_id(payload.get("finding_id") or payload.get("candidate_id"))
        if finding_id:
            self._emit(_Line("info", "  " + _join("Candidate", [finding_id])))

    def _proof_event(self, kind: str, payload: Mapping[str, Any]) -> None:
        action_id = str(payload.get("action_id") or "").strip()
        if action_id:
            self._finish_action(payload)
            self._tool_completed_actions.add(action_id)
        if kind == "flag_captured":
            if action_id:
                self._proof_actions.add(action_id)
            record_path = _safe_narrative(payload.get("flag_record_path"))
            if record_path:
                self._flag_record_path = record_path
            fingerprint = _value_fingerprint(payload.get("flag"))
            if not fingerprint:
                self._emit(_Line("fail", "Flag event ignored · validated value missing"))
                return
            if fingerprint in self._proof_fingerprints:
                self._announce_flag_location()
                return
            self._proof_fingerprints.add(fingerprint)
            self._confirmed_flag_count += 1
            self._dashboard_flags = max(
                self._dashboard_flags,
                self._confirmed_flag_count,
            )
            source = _proof_source_label(payload.get("source_kind"))
            total = f"{_count(self._confirmed_flag_count, 'unique flag')} total"
            self._emit(_Line("ok", _join("Flag found", [total, source, "value masked"])))
            self._announce_flag_location()
            return
        if action_id:
            self._blocked_actions.add(action_id)
        error = _safe_narrative(payload.get("error"))
        self._emit(
            _Line(
                "fail",
                _join("Proof candidate rejected by the evidence gate", [error]),
            )
        )

    def _agent_final(self, payload: Mapping[str, Any]) -> None:
        action_id = str(payload.get("action_id") or "").strip()
        if action_id:
            elapsed = self._finish_action(payload)
            self._tool_completed_actions.add(action_id)
        else:
            elapsed = self._finish_active()
        self._emit(_Line("info", _join("Agent returned a final response", [elapsed])))

    def _cost_exhausted(self, payload: Mapping[str, Any]) -> None:
        self._finish_active()
        spent = _cost(payload.get("spent_cost_usd"))
        limit = _cost(payload.get("max_cost_usd"))
        detail = f"spent {spent} of {limit}" if spent and limit else spent or limit
        self._emit(_Line("warn", _join("Cost budget exhausted", [detail])))

    def _agent_finished(  # noqa: C901, PLR0912, PLR0915
        self,
        payload: Mapping[str, Any],
    ) -> None:
        self._finish_active()
        status = _safe_identifier(payload.get("status")) or "unknown"
        turns = _non_negative_int(payload.get("turns"))
        if isinstance(payload.get("flag_objective"), bool):
            self._flag_objective = payload["flag_objective"]
        reported_flags = payload.get("flags")
        if isinstance(reported_flags, list):
            for reported_flag in reported_flags:
                fingerprint = _value_fingerprint(reported_flag)
                if fingerprint:
                    self._proof_fingerprints.add(fingerprint)
        reported_flag_count = max(
            len(reported_flags) if isinstance(reported_flags, list) else 0,
            _non_negative_int(payload.get("flag_count")),
        )
        flag_count = max(
            self._confirmed_flag_count,
            len(self._proof_fingerprints),
            reported_flag_count,
        )
        self._confirmed_flag_count = flag_count
        record_path = _safe_narrative(payload.get("flag_record_path"))
        if record_path:
            self._flag_record_path = record_path
        if flag_count:
            self._announce_flag_location()
        phase = _safe_identifier(payload.get("phase"))
        cost = _cost(payload.get("cost_usd"))
        finding_count = max(
            self._confirmed_finding_count,
            _non_negative_int(payload.get("finding_count")),
        )
        self._confirmed_finding_count = finding_count
        findings = (
            f"findings={finding_count}"
            if finding_count or "finding_count" in payload
            else ""
        )
        flags_detail = ""
        if flag_count:
            flags_detail = f"flags={flag_count}"
        elif self._flag_objective is not False:
            flags_detail = "flags=0"
        details = [
            _count(turns, "turn") if turns else "",
            phase,
            findings,
            flags_detail,
            cost,
        ]
        signal_summary = _signal_count_details(self._last_signal_counts)
        if signal_summary:
            self._emit(_Line("info", _join("Mapped signals", signal_summary)))
        if status == "failed":
            error_type = _safe_identifier(payload.get("error_type"))
            self._emit(_Line("fail", _join("Agent failed", [*details, error_type])))
            self._announce_result_paths(payload)
            self._clear_correlation_state()
            return
        if status == "cancelled":
            self._emit(_Line("warn", _join("Agent cancelled", details)))
            self._announce_result_paths(payload)
            self._clear_correlation_state()
            return
        if status not in {"completed", "incomplete"}:
            self._emit(_Line("warn", _join("Agent status unknown", details)))
            self._announce_result_paths(payload)
            self._clear_correlation_state()
            return
        termination_reason = _agent_termination_reason(payload)
        if status == "incomplete" or termination_reason in {
            "cost_budget_exhausted",
            "max_turns_reached",
        }:
            label = (
                "Base phase incomplete"
                if self._autonomous_route_expected
                else "Agent incomplete"
            )
            self._emit(
                _Line(
                    "warn",
                    _join(label, [_termination_reason_label(termination_reason), *details]),
                )
            )
            self._announce_result_paths(payload)
            self._clear_correlation_state()
            return
        label = "Base phase finished" if self._autonomous_route_expected else "Agent finished"
        self._emit(_Line("ok", _join(label, details)))
        self._announce_result_paths(payload)
        self._clear_correlation_state()

    def _announce_result_paths(self, payload: Mapping[str, Any]) -> None:
        evidence_path = _first_safe_path(
            payload,
            "finding_record_path",
            "evidence_path",
            "events_path",
        )
        if evidence_path:
            self._finding_record_path = evidence_path
        report_path = _first_safe_path(payload, "report_path")
        if report_path:
            self._report_path = report_path
        audit_path = _first_safe_path(payload, "audit_path")
        if audit_path:
            self._audit_path = audit_path

        if self._finding_record_path:
            self._emit(_Line("info", _join("Evidence", [self._finding_record_path])))
        if self._report_path:
            self._emit(_Line("info", _join("Report", [self._report_path])))
        if self._audit_path:
            self._emit(_Line("info", _join("Audit", [self._audit_path])))

    def _frontier_event(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        kind: str,
        payload: Mapping[str, Any],
    ) -> None:
        if kind == "frontier_route_started":
            budget = _positive_int(payload.get("route_model_request_budget"))
            detail = f"up to {budget} model requests" if budget else ""
            self._emit(_Line("info", _join("Frontier route started", [detail])))
            self._begin("frontier-route", "Exploring the remaining attack frontier")
            return
        if kind == "frontier_model_request_started":
            key = _frontier_model_key(payload)
            role = _safe_identifier(payload.get("role"))
            request = _positive_int(payload.get("route_model_request"))
            budget = _positive_int(payload.get("route_model_request_budget"))
            progress = f"request {request}/{budget}" if request and budget else ""
            label = _join("Frontier thinking", [role, progress])
            self._start(key)
            if self.mode == "plain":
                self._emit(_Line("run", label))
            self._set_activity(key, label)
            return
        if kind == "frontier_model_reply_received":
            key = _frontier_model_key(payload)
            elapsed = self._finish(key)
            role = _safe_identifier(payload.get("role"))
            cost = _cost(payload.get("cost_usd"))
            self._emit(_Line("ok", _join("Frontier thought complete", [role, elapsed, cost])))
            return
        if kind == "frontier_action_completed":
            action_id = str(payload.get("action_id") or "").strip()
            if action_id in self._tool_completed_actions:
                self._tool_completed_actions.discard(action_id)
                return
            elapsed = self._finish(_frontier_action_key(payload))
            action = _object(payload.get("action"))
            outcome = _object(payload.get("outcome"))
            action_kind = _safe_identifier(action.get("action"))
            action_label = _ACTION_LABELS.get(action_kind, "Action")
            result = _safe_identifier(outcome.get("outcome"))
            action_tone: Literal["ok", "warn"] = (
                "ok" if outcome.get("ok") is not False else "warn"
            )
            self._emit(_Line(action_tone, _join(f"Frontier {action_label}", [elapsed, result])))
            return
        if kind == "frontier_action_started":
            key = _frontier_action_key(payload)
            action_kind = _safe_identifier(payload.get("action_kind"))
            label = _join(
                f"Frontier {_ACTION_LABELS.get(action_kind, 'action')}",
                [_short_id(payload.get("worker_id"))],
            )
            self._start(key)
            if self.mode == "plain":
                self._emit(_Line("run", label))
            self._set_activity(key, label)
            return
        if kind == "frontier_route_decision":
            status = _safe_identifier(payload.get("status"))
            remaining = _non_negative_int(payload.get("remaining_model_requests"))
            decision_tone: Literal["info", "warn"] = (
                "info" if status == "running" else "warn"
            )
            detail = f"{remaining} requests left" if status == "running" else status
            self._emit(_Line(decision_tone, _join("Frontier decision", [detail])))
            return
        if kind == "frontier_route_finished":
            elapsed = self._finish("frontier-route", fallback_to_active=True)
            status = _safe_identifier(payload.get("status"))
            requests = _non_negative_int(payload.get("route_model_requests"))
            cost = _cost(payload.get("route_cost_usd"))
            finish_tone: Literal["ok", "warn"] = (
                "ok" if status in {"solved", "completed"} else "warn"
            )
            detail = _count(requests, "model request") if requests else ""
            line = _join("Frontier route finished", [status, elapsed, detail, cost])
            self._emit(_Line(finish_tone, line))
            self._clear_correlation_state()
            return
        if kind in {"frontier_route_failed", "frontier_route_cancelled"}:
            elapsed = self._finish("frontier-route", fallback_to_active=True)
            error_type = _safe_identifier(payload.get("error_type"))
            if kind.endswith("cancelled"):
                self._emit(_Line("warn", _join("Frontier route cancelled", [elapsed])))
            else:
                self._emit(_Line("fail", _join("Frontier route failed", [elapsed, error_type])))
            self._clear_correlation_state()

    def _graph_event(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        kind: str,
        payload: Mapping[str, Any],
    ) -> None:
        if kind == "autonomous_graph_started":
            budget = _positive_int(payload.get("route_model_request_budget"))
            profile = _safe_identifier(payload.get("operational_profile"))
            detail = f"up to {budget} model requests" if budget else ""
            self._emit(_Line("info", _join("Agent graph started", [profile, detail])))
            self._begin("agent-graph", "Coordinating the agent graph")
            return
        if kind == "autonomous_graph_model_request_started":
            key = _graph_model_key(payload)
            node = _short_id(payload.get("graph_node_id"))
            model = _model_label(payload)
            label = _join("Graph thinking", [node, model])
            self._start(key)
            if self.mode == "plain":
                self._emit(_Line("run", label))
            self._set_activity(key, label)
            return
        if kind in {
            "autonomous_graph_model_reply_received",
            "autonomous_graph_model_request_failed",
        }:
            key = _graph_model_key(payload)
            elapsed = self._finish(key)
            node = _short_id(payload.get("graph_node_id"))
            if kind.endswith("failed"):
                error_type = _safe_identifier(payload.get("error_type"))
                line = _join("Graph model request failed", [node, elapsed, error_type])
                self._emit(_Line("fail", line))
            else:
                usage = _token_usage(payload)
                cost = _cost(payload.get("cost_usd"))
                line = _join("Graph thought complete", [node, elapsed, usage, cost])
                self._emit(_Line("ok", line))
            return
        if kind == "graph_probe_scope":
            probe = _safe_identifier(payload.get("probe")) or "probe"
            node = _short_id(payload.get("node_id"))
            self._emit(_Line("info", _join(f"Graph scoped {probe}", [node])))
            return
        if kind == "autonomous_graph_action_started":
            key = _graph_action_key(payload)
            action_kind = _safe_identifier(payload.get("action_kind"))
            node = _short_id(payload.get("node_id"))
            label = _join(
                f"Graph {_ACTION_LABELS.get(action_kind, 'action')}",
                [node],
            )
            self._start(key)
            if self.mode == "plain":
                self._emit(_Line("run", label))
            self._set_activity(key, label)
            return
        if kind in {"autonomous_graph_action_finished", "autonomous_graph_action_failed"}:
            action_id = str(payload.get("action_id") or "").strip()
            if kind.endswith("finished") and action_id in self._tool_completed_actions:
                self._tool_completed_actions.discard(action_id)
                return
            elapsed = self._finish(_graph_action_key(payload))
            action_kind = _safe_identifier(payload.get("action_kind"))
            node = _short_id(payload.get("node_id"))
            if kind.endswith("failed"):
                error_type = _safe_identifier(payload.get("error_type"))
                label = f"Graph {_ACTION_LABELS.get(action_kind, 'action')} failed"
                self._emit(_Line("fail", _join(label, [node, elapsed, error_type])))
                return
            outcome = _safe_identifier(payload.get("outcome"))
            action_tone: Literal["ok", "warn"] = (
                "ok" if payload.get("ok") is not False else "warn"
            )
            label = f"Graph {_ACTION_LABELS.get(action_kind, 'action')} finished"
            self._emit(_Line(action_tone, _join(label, [node, elapsed, outcome])))
            return
        if kind == "autonomous_graph_finished":
            elapsed = self._finish("agent-graph", fallback_to_active=True)
            status = _safe_identifier(payload.get("status"))
            requests = _non_negative_int(payload.get("route_model_requests"))
            tools = _non_negative_int(payload.get("route_tool_calls"))
            cost = _cost(payload.get("route_cost_usd"))
            tone: Literal["ok", "warn"] = "ok" if status in {"solved", "completed"} else "warn"
            details = [status, elapsed]
            if requests:
                details.append(_count(requests, "model request"))
            if tools:
                details.append(_count(tools, "tool call"))
            details.append(cost)
            self._emit(_Line(tone, _join("Agent graph finished", details)))
            self._clear_correlation_state()
            return
        if kind in {"autonomous_graph_failed", "autonomous_graph_cancelled"}:
            elapsed = self._finish("agent-graph", fallback_to_active=True)
            error_type = _safe_identifier(payload.get("error_type"))
            if kind.endswith("cancelled"):
                self._emit(_Line("warn", _join("Agent graph cancelled", [elapsed])))
            else:
                self._emit(_Line("fail", _join("Agent graph failed", [elapsed, error_type])))
            self._clear_correlation_state()

    def _start(self, key: str) -> None:
        self._started[key] = self.clock()

    def _begin(self, key: str, label: str) -> None:
        self._start(key)
        if self.mode == "plain":
            self._emit(_Line("run", label))
        self._set_activity(key, label)

    def _set_activity(self, key: str, label: str) -> None:
        started_at = self._started.get(key)
        if started_at is None:
            started_at = self.clock()
            self._started[key] = started_at
        if self.mode == "live":
            self._clear_row()
        activity = _Activity(
            key=key,
            label=_safe_text(label),
            started_at=started_at,
            animation_started_at=time.monotonic(),
        )
        self._pending[key] = activity
        self._activity = activity
        if self.mode == "live" and not self._render_dashboard():
            self._degrade_live_display()

    def _finish(self, key: str, *, fallback_to_active: bool = False) -> str:
        started_at = self._started.pop(key, None)
        activity = self._activity
        self._pending.pop(key, None)
        if activity is not None and (activity.key == key or fallback_to_active):
            if started_at is None:
                started_at = activity.started_at
            if fallback_to_active and activity.key != key:
                self._pending.pop(activity.key, None)
            self._activity = next(reversed(self._pending.values()), None)
        if started_at is None:
            return ""
        return _duration(max(0.0, self.clock() - started_at))

    def _finish_active(self) -> str:
        if self._activity is None:
            return ""
        return self._finish(self._activity.key)

    def _finish_action(self, payload: Mapping[str, Any]) -> str:
        keys = (
            _action_key(payload),
            _frontier_action_key(payload),
            _graph_action_key(payload),
        )
        for key in keys:
            elapsed = self._finish(key)
            if elapsed:
                return elapsed
        return ""

    def _clear_correlation_state(self) -> None:
        self._clear_row()
        self._activity = None
        self._pending.clear()
        self._started.clear()
        self._tool_completed_actions.clear()
        self._action_probes.clear()
        self._action_fallbacks.clear()
        self._blocked_actions.clear()
        self._proof_actions.clear()
        self._narrated_attempts.clear()
        self._last_signal_counts.clear()

    def _remember_signal_counts(self, state: Mapping[str, Any]) -> None:
        counts = state.get("signal_counts")
        if not isinstance(counts, dict):
            return
        self._last_signal_counts = _non_negative_counts(counts)

    def _announce_flag_location(self) -> None:
        if self._flag_location_announced or not self._flag_record_path:
            return
        self._emit(
            _Line(
                "info",
                _join("Flag recorded in", [self._flag_record_path]),
            )
        )
        self._emit(
            _Line(
                "info",
                "  " + _join("Look for", ["event=flag_captured", "field=payload.flag"]),
            )
        )
        self._flag_location_announced = True

    def _emit(self, line: _Line) -> None:
        if not line.text or self.mode == "quiet":
            return
        if self._dashboard is not None:
            width = _terminal_width(self.stream)
            text = _clip(line.text, max(1, width - 2))
            if not self._dashboard.print_line(line.tone, text, width=width):
                self._degrade_live_display()
                self._write_plain_line(line)
                return
            if not self._render_dashboard():
                self._degrade_live_display()
            return
        self._write_plain_line(line)

    def _write_plain_line(self, line: _Line) -> None:
        prefix = _plain_prefix(line.tone)
        rendered = _clip(f"{prefix} {line.text}", _terminal_width(self.stream))
        if not self._unicode:
            rendered = _ascii_terminal_text(rendered)
        self._write(rendered + "\n")

    def _animate(self) -> None:
        while not self._stop.wait(_TICK_SECONDS):
            with self._lock:
                if self._closed:
                    return
                if self._dashboard is not None and not self._render_dashboard():
                    self._degrade_live_display()

    def _render_dashboard(self) -> bool:
        activity = self._activity
        dashboard = self._dashboard
        if dashboard is None:
            return False
        if not self._run_started and not self._pending:
            return True
        now = time.monotonic()
        width = _terminal_width(self.stream)
        activities = tuple(
            DashboardActivity(
                label=item.label,
                elapsed_seconds=max(0.0, now - item.animation_started_at),
                current=activity is not None and item.key == activity.key,
            )
            for item in self._pending.values()
        )
        snapshot = RunDashboardSnapshot(
            target=self._run_target,
            model=self._run_model,
            agent_mode=self._run_agent_mode,
            phase=self._run_phase,
            turn=self._run_turn,
            max_turns=self._run_max_turns,
            input_tokens=self._run_input_tokens,
            output_tokens=self._run_output_tokens,
            cost_usd=self._run_cost_usd,
            candidate_signals=self._candidate_signal_count,
            findings=self._dashboard_findings,
            flags=self._dashboard_flags,
            run_elapsed_seconds=max(0.0, now - self._run_animation_started_at),
            activities=activities,
            terminal=self._run_terminal,
        )
        return dashboard.update(snapshot, width=width)

    def _degrade_live_display(self) -> None:
        dashboard = self._dashboard
        if dashboard is None:
            return
        with suppress(Exception):
            dashboard.stop()
        self._dashboard = None
        self.mode = "plain"
        self._stop.set()
        self._write_plain_line(
            _Line("warn", "Live display unavailable; continuing in plain mode")
        )
        if self._activity is not None:
            self._write_plain_line(_Line("run", self._activity.label))

    def _clear_row(self) -> None:
        # Rich's Live console owns redraws and safely writes timeline rows above the panel.
        return

    def _write(self, value: str) -> None:
        try:
            self.stream.write(value)
            self.stream.flush()
        except (OSError, UnicodeError, ValueError):
            self._stop.set()


def _resolve_mode(mode: DisplayMode, stream: TextIO) -> DisplayMode:
    if mode != "quiet" and (
        _truthy_environment("RAVAGE_NO_MOTION")
        or _truthy_environment("RAVAGE_SCREEN_READER")
    ):
        return "plain"
    if mode != "auto":
        return mode
    if _truthy_environment("CI"):
        return "plain"
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return "plain"
    try:
        return "live" if stream.isatty() else "plain"
    except (AttributeError, OSError):
        return "plain"


def _truthy_environment(name: str) -> bool:
    value = os.environ.get(name, "").strip().lower()
    return value not in {"", "0", "false", "no", "off"}


def _color_enabled() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    value = os.environ.get("RAVAGE_COLOR", "auto").strip().lower()
    return value not in {"never", "0", "false", "no", "off"}


def _unicode_supported(stream: TextIO) -> bool:
    encoding = str(getattr(stream, "encoding", "") or "").lower()
    if not encoding:
        return True
    return "utf" in encoding


def _ascii_terminal_text(value: str) -> str:
    replacements = {
        "·": "|",
        "→": "->",
        "✓": "+",
        "✻": "*",
        "×": "x",  # noqa: RUF001 - source glyph being downgraded
        "›": ">",  # noqa: RUF001 - source glyph being downgraded
        "…": "...",
    }
    return "".join(replacements.get(char, char) for char in value)


def sanitize_transcript_text(value: object) -> str:
    """Remove terminal controls while preserving stable line-oriented layout."""
    text = _ANSI_SEQUENCE_RE.sub("", str(value))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _TRANSCRIPT_CONTROL_RE.sub("", text)
    return _BIDI_CONTROL_RE.sub("", text)


def redacted_artifact_path(value: object) -> str:
    """Return a bounded, secret-safe artifact path for terminal summaries."""
    return _safe_text(value)


def redacted_target_url(value: object) -> str:
    """Return the origin-only form of a target URL for terminal summaries."""
    return _safe_target(value)


def _plain_prefix(tone: str) -> str:
    return {
        "ok": "[ok]",
        "fail": "[fail]",
        "warn": "[warn]",
        "run": "[run]",
        "info": "[info]",
        "agent": "[agent]",
    }.get(tone, "[info]")


def _model_key(payload: Mapping[str, Any]) -> str:
    request_id = str(payload.get("model_request_id") or "").strip()
    if request_id:
        return f"model:{request_id}"
    return "model:" + ":".join(
        (
            str(payload.get("turn") or ""),
            str(payload.get("provider") or ""),
            str(payload.get("model") or ""),
        )
    )


def _action_key(payload: Mapping[str, Any]) -> str:
    action_id = str(payload.get("action_id") or "").strip()
    return f"action:{action_id}" if action_id else "action:current"


def _frontier_action_key(payload: Mapping[str, Any]) -> str:
    action_id = str(payload.get("action_id") or "").strip()
    return f"frontier-action:{action_id}" if action_id else "frontier-action:current"


def _graph_action_key(payload: Mapping[str, Any]) -> str:
    action_id = str(payload.get("action_id") or "").strip()
    return f"graph-action:{action_id}" if action_id else "graph-action:current"


def _frontier_model_key(payload: Mapping[str, Any]) -> str:
    worker = str(payload.get("worker_id") or "")
    request = str(payload.get("worker_request") or payload.get("route_model_request") or "")
    return f"frontier-model:{worker}:{request}"


def _graph_model_key(payload: Mapping[str, Any]) -> str:
    request_id = str(payload.get("model_request_id") or "")
    node_id = str(payload.get("graph_node_id") or "")
    return f"graph-model:{request_id or node_id}"


def _dashboard_model_reply_key(kind: str, payload: Mapping[str, Any]) -> str:
    if kind == "model_reply_received":
        return _model_key(payload)
    if kind == "frontier_model_reply_received":
        return _frontier_model_key(payload)
    if kind == "autonomous_graph_model_reply_received":
        return _graph_model_key(payload)
    return ""


def _model_label(payload: Mapping[str, Any]) -> str:
    provider = _safe_word(payload.get("provider"))
    model = _safe_word(payload.get("model"))
    return "/".join(item for item in (provider, model) if item)


def _turn_label(payload: Mapping[str, Any]) -> str:
    turn = _positive_int(payload.get("turn"))
    return f"turn {turn}" if turn else ""


def _token_usage(payload: Mapping[str, Any]) -> str:
    input_tokens = _non_negative_int(payload.get("input_tokens"))
    output_tokens = _non_negative_int(payload.get("output_tokens"))
    if not input_tokens and not output_tokens:
        return ""
    return f"{_quantity(input_tokens)} in / {_quantity(output_tokens)} out"


def _recon_details(payload: Mapping[str, Any]) -> list[str]:
    pages = payload.get("pages")
    page_items = pages if isinstance(pages, list) else []
    response_pages = [
        page
        for page in page_items
        if isinstance(page, dict) and _positive_int(page.get("status"))
    ]
    parameters = payload.get("query_parameter_names")
    parameter_items = parameters if isinstance(parameters, list) else []
    reflection_count = 0
    form_count = 0
    for page in page_items:
        if not isinstance(page, dict):
            continue
        reflections = page.get("reflected_parameters")
        forms = page.get("forms")
        if isinstance(reflections, list):
            reflection_count += len(reflections)
        if isinstance(forms, list):
            form_count += len(forms)
    errors = payload.get("errors")
    error_count = len(errors) if isinstance(errors, list) else 0
    details = [
        _count(len(response_pages), "page") if response_pages else "",
        _count(len(parameter_items), "parameter") if parameter_items else "",
        _count(reflection_count, "reflection") if reflection_count else "",
        _count(form_count, "form") if form_count else "",
    ]
    if error_count:
        details.append(_count(error_count, "error"))
    return details


def _recon_outcome(payload: Mapping[str, Any]) -> Literal["complete", "degraded", "failed"]:
    pages = payload.get("pages")
    page_items = pages if isinstance(pages, list) else []
    errors = payload.get("errors")
    has_errors = bool(errors) if isinstance(errors, list) else False
    has_errors = has_errors or any(
        bool(_safe_narrative(page.get("error")))
        for page in page_items
        if isinstance(page, dict)
    )
    if not has_errors:
        return "complete"
    has_response = any(
        _positive_int(page.get("status"))
        for page in page_items
        if isinstance(page, dict)
    )
    return "degraded" if has_response else "failed"


def _tool_label(
    kind: str,
    payload: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    probe: str = "",
) -> str:
    del payload, result
    if kind == "tool_run_python":
        return "Python helper finished"
    if kind == "tool_validate_poc":
        return "PoC validation finished"
    if kind == "tool_run_probe":
        return f"Probe {probe} finished" if probe else "Probe finished"
    return "Command finished"


def _tool_details(
    payload: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    probe_result: bool = False,
) -> list[str]:
    details: list[str] = []
    exit_code = _resolved_tool_exit_code(payload, result)
    if exit_code is not None:
        details.append(f"exit={exit_code}")
    findings = result.get("findings")
    if isinstance(findings, list):
        noun = "candidate signal" if probe_result else "finding"
        details.append(_count(len(findings), noun))
    proofs = payload.get("recognized_proofs", result.get("recognized_proofs"))
    if isinstance(proofs, list) and proofs:
        details.append(f"proofs={len(proofs)}")
    return details


def _resolved_tool_exit_code(
    payload: Mapping[str, Any],
    result: Mapping[str, Any],
) -> int | None:
    exit_codes = [
        value
        for value in (payload.get("exit_code"), result.get("exit_code"))
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    return next((value for value in exit_codes if value != 0), 0 if exit_codes else None)


def _probe_display_details(summary: Mapping[str, Any]) -> list[str]:
    details: list[str] = []
    if "requests" in summary:
        count = _non_negative_int(summary.get("requests"))
        if count:
            details.append(_count(count, "request"))

    signal_key = next(
        (key for key in ("candidate_signals", "signals", "findings") if key in summary),
        "",
    )
    if signal_key:
        count = _non_negative_int(summary.get(signal_key))
        details.append(_count(count, "candidate signal"))

    if "errors" in summary:
        details.append(_count(_non_negative_int(summary.get("errors")), "error"))

    signal_types = summary.get("signal_types", summary.get("finding_types"))
    if isinstance(signal_types, list):
        labels = [_human_identifier(item) for item in signal_types[:3]]
        labels = [label for label in labels if label]
        if labels:
            details.append("signals=" + ",".join(labels))
    return details


def _candidate_signal_narrative(value: str) -> str:
    value = re.sub(r"\bfindings\b", "candidate signals", value, flags=re.IGNORECASE)
    return re.sub(r"\bfinding\b", "candidate signal", value, flags=re.IGNORECASE)


def _planned_action_label(action: Mapping[str, Any]) -> str:
    action_kind = _safe_identifier(action.get("action"))
    if action_kind == "run_probe":
        probe = _safe_identifier(action.get("probe"))
        return f"probe {probe}" if probe else "probe"
    label = _ACTION_LABELS.get(action_kind, "Action")
    return label[:1].lower() + label[1:]


def _planned_action_narrative(action: Mapping[str, Any]) -> str:
    action_kind = _safe_identifier(action.get("action"))
    if action_kind == "run_probe":
        probe = _human_identifier(action.get("probe"))
        if probe:
            return f"run the {probe} probe against the mapped input"
        return "run a bounded probe against the mapped input"
    label = _ACTION_LABELS.get(action_kind, "")
    return _sentence_fragment(label) if label else ""


def _probe_start_narrative(probe: str) -> str:
    if probe == "ssti_fingerprint":
        return "I'm starting with a baseline, then harmless SSTI fingerprints, stopping on proof."
    label = _human_identifier(probe)
    if not label:
        return ""
    return (
        f"I'm starting the {label} probe. I'll compare each response with the "
        "mapped baseline before choosing the next check."
    )


def _probe_exchange_narrative(payload: Mapping[str, Any]) -> tuple[str, str]:
    probe = _safe_identifier(payload.get("probe"))
    if probe == "ssti_fingerprint":
        return _ssti_exchange_narrative(payload)

    index = _positive_int(payload.get("index"))
    method = _http_method(payload.get("method"))
    path = _safe_path_shape(str(payload.get("path") or "/")) or "/"
    probe_label = _human_identifier(probe) or "probe"
    request_label = f"request {index}" if index else "the next request"
    before = (
        f"I'm sending {request_label} from the {probe_label} probe to "
        f"{method} {path}."
    )
    return before, _generic_probe_response_narrative(payload)


def _ssti_exchange_narrative(payload: Mapping[str, Any]) -> tuple[str, str]:
    method = _http_method(payload.get("method"))
    path = _safe_path_shape(str(payload.get("path") or "/")) or "/"
    parameter, value = _primary_probe_input(payload)
    location = f"{method} {path}"
    input_label = f" through {parameter}" if parameter else ""

    if not value or not _looks_like_template_expression(value):
        before = (
            f"I'm establishing a baseline for {location} with an ordinary "
            f"value{input_label}."
        )
        response = _safe_narrative(payload.get("response_summary"))
        if value and value in response:
            after = (
                "The ordinary value was reflected. I can now distinguish plain echo "
                "from evaluation."
            )
        else:
            after = (
                "The baseline is recorded. I'll compare the template probes with "
                "this response."
            )
        return before, _failed_probe_response_narrative(payload) or after

    if _looks_like_ssti_proof_read(value):
        before = (
            "Template evaluation worked. Now I'm trying the smallest "
            "engine-specific proof read."
        )
        response = _safe_narrative(payload.get("response_summary"))
        if "[REDACTED-PROOF]" in response or MASK in response:
            after = (
                "A proof-shaped value came back. The objective is met, so I'm "
                "stopping and recording it."
            )
        else:
            after = (
                "No proof-shaped value came back. I should try the next bounded "
                "engine-specific read."
            )
        return before, _failed_probe_response_narrative(payload) or after

    expected, engine = _ssti_fingerprint_expectation(value)
    if expected:
        engine_label = f"{engine} " if engine else ""
        before = (
            f"Now I'm trying harmless {engine_label}template arithmetic{input_label}; "
            f"{expected} would prove evaluation."
        )
        response = _safe_narrative(payload.get("response_summary"))
        if expected in response:
            conclusion = (
                f" and points to {engine}" if engine else ""
            )
            after = (
                f"The response became {expected}, not the literal expression. "
                f"That matches the template-evaluation signal{conclusion}. "
                "I'm waiting for probe validation before calling it confirmed."
            )
        else:
            after = (
                f"That signature did not evaluate to {expected}, so I should try "
                "the next template-engine fingerprint."
            )
        return before, _failed_probe_response_narrative(payload) or after

    before = (
        f"Now I'm testing one bounded template expression{input_label} against "
        "the baseline."
    )
    return before, _generic_probe_response_narrative(payload)


def _primary_probe_input(payload: Mapping[str, Any]) -> tuple[str, str]:
    query = payload.get("query")
    if not isinstance(query, list):
        return "", ""
    for raw_item in query[:12]:
        if not isinstance(raw_item, dict):
            continue
        name = _safe_parameter_name(raw_item.get("name"))
        value = _safe_narrative(raw_item.get("value"))
        if name and value and value not in {MASK, "[REDACTED]"}:
            return name, value
    return "", ""


def _looks_like_template_expression(value: str) -> bool:
    return any(marker in value for marker in ("{{", "{%", "${", "#{", "<%=", "[[${", "*{"))


def _looks_like_ssti_proof_read(value: str) -> bool:
    lowered = value.casefold()
    return any(
        marker in lowered
        for marker in (
            "flag",
            "secret_key",
            "popen",
            "printenv",
            "system(",
        )
    )


def _ssti_fingerprint_expectation(value: str) -> tuple[str, str]:
    compact = re.sub(r"\s+", "", value)
    fingerprints = (
        (('|add:"42"',), "49", "Django"),
        (("7*'7'",), "7777777", "Jinja-style"),
        (("|upper", ".upper()"), "RAVAGE", "Jinja-style"),
        (("1==1",), "True", "Jinja-style"),
        (("6*7",), "42", "Jinja-style"),
        (("7*7",), "49", "Jinja-style"),
    )
    for markers, expected, engine in fingerprints:
        if any(marker in compact for marker in markers):
            return expected, engine
    return "", ""


def _failed_probe_response_narrative(payload: Mapping[str, Any]) -> str:
    status = _positive_int(payload.get("status"))
    disposition = _safe_identifier(payload.get("disposition"))
    error = _safe_narrative(payload.get("error"))
    if error or disposition == "blocked":
        return (
            "That request was blocked or failed before producing a usable result. "
            "I should stay within the bounded fallback path."
        )
    if status >= _HTTP_CLIENT_ERROR_STATUS:
        return (
            f"HTTP {status} is not a usable signal here. I should move to the next "
            "bounded check."
        )
    return ""


def _generic_probe_response_narrative(payload: Mapping[str, Any]) -> str:
    failure = _failed_probe_response_narrative(payload)
    if failure:
        return failure
    status = _positive_int(payload.get("status"))
    if status:
        return (
            f"HTTP {status} came back. I'm comparing it with earlier responses "
            "before the next check."
        )
    return "The request completed without a comparable HTTP response."


def _sentence_fragment(value: str) -> str:
    text = value.strip()
    if text.startswith(("A ", "An ", "The ")):
        return text[0].lower() + text[1:]
    if len(text) > 1 and text[0].isupper() and text[1].islower():
        return text[0].lower() + text[1:]
    return text


def _sentence(value: str) -> str:
    text = value.strip()
    if not text or text.endswith((".", "!", "?")):
        return text
    return text + "."


def _action_started_label(action_kind: str, *, probe: str) -> str:
    if action_kind == "run_probe" and probe:
        return f"Run probe {probe}"
    return _ACTION_LABELS.get(action_kind, "Action")


def _probe_name(payload: Mapping[str, Any]) -> str:
    params = _object(payload.get("params"))
    return _safe_identifier(params.get("probe"))


def _human_identifier(value: object) -> str:
    identifier = _safe_identifier(value)
    return identifier.replace("_", " ") if identifier else ""


def _outcome_label(value: object) -> str:
    identifier = _safe_identifier(value)
    if identifier == "confirmed_signal":
        return "candidate signal observed"
    return identifier.replace("_", " ") if identifier else ""


def _agent_termination_reason(payload: Mapping[str, Any]) -> str:
    for key in ("termination_reason", "terminal_reason", "stop_reason"):
        reason = _safe_identifier(payload.get(key))
        if reason:
            return reason
    if payload.get("max_turns_reached") is True:
        return "max_turns_reached"
    if payload.get("cost_budget_exhausted") is True:
        return "cost_budget_exhausted"
    return ""


def _termination_reason_label(value: object) -> str:
    reason = _safe_identifier(value)
    return {
        "max_turns_reached": "max turns reached",
        "cost_budget_exhausted": "cost budget exhausted",
    }.get(reason, _human_identifier(reason))


def _state_delta_details(delta: Mapping[str, Any]) -> list[str]:
    details: list[str] = []
    signal_delta = delta.get("signal_count_delta")
    if isinstance(signal_delta, dict):
        details.extend(_signal_count_details(_positive_counts(signal_delta), prefix="+"))
    new_primitives = delta.get("new_primitives")
    if isinstance(new_primitives, list):
        for primitive in new_primitives[:2]:
            label = _human_identifier(primitive)
            if label:
                details.append(f"{label} exploit lead")
    return details[:6]


def _positive_counts(value: Mapping[object, object]) -> dict[str, int]:
    return {
        str(key): count
        for key, item in value.items()
        if (count := _non_negative_int(item)) > 0
    }


def _non_negative_counts(value: Mapping[object, object]) -> dict[str, int]:
    return {str(key): _non_negative_int(item) for key, item in value.items()}


def _signal_count_details(counts: Mapping[str, int], *, prefix: str = "") -> list[str]:
    priority = ("endpoints", "pages", "parameters", "reflections", "xss_contexts", "markers")
    ordered = [*priority, *(sorted(set(counts) - set(priority)))]
    details: list[str] = []
    for key in ordered:
        count = _non_negative_int(counts.get(key))
        identifier = _safe_identifier(key)
        if not count or not identifier:
            continue
        label = _signal_label(identifier, count=count)
        details.append(f"{prefix}{count} {label}")
        if len(details) == _MAX_SIGNAL_DETAILS:
            break
    return details


def _signal_label(identifier: str, *, count: int) -> str:
    if identifier == "xss_contexts":
        return "XSS context" if count == 1 else "XSS contexts"
    label = identifier.replace("_", " ")
    if count == 1 and label.endswith("s"):
        return label[:-1]
    return label


def _object(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _safe_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value)[:_MAX_UNTRUSTED_INPUT_CHARS]
    text = unicodedata.normalize("NFC", _ANSI_SEQUENCE_RE.sub("", text))
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = _BIDI_CONTROL_RE.sub("", text)
    text = "".join(_safe_display_character(char) for char in text).strip()
    text = mask_command_string(text)
    text = _ENV_SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{MASK}", text)
    text = _OPTION_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{MASK}",
        text,
    )
    text = _INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}{MASK}", text)
    text = _SPACED_SECRET_RE.sub(lambda match: f"{match.group(1)}{MASK}", text)
    text = _BEARER_RE.sub(f"Bearer {MASK}", text)
    text = _HEADER_SECRET_RE.sub(lambda match: f"{match.group(1)}: {MASK}", text)
    text = _URL_CREDENTIAL_RE.sub(lambda match: f"{match.group(1)}{MASK}@", text)
    text = _URL_QUERY_VALUE_RE.sub(lambda match: f"{match.group(1)}={MASK}", text)
    for proof in recognize_proofs(text):
        text = text.replace(proof, MASK)
    return _clip(text, _MAX_DETAIL_CHARS)


def _safe_display_character(char: str) -> str:
    if char.isspace() or unicodedata.category(char).startswith("Z"):
        return " "
    if unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
        return ""
    return char


def _safe_narrative(value: object) -> str:
    return _safe_text(value) if isinstance(value, str) else ""


def _severity_label(value: object) -> str:
    severity = _safe_identifier(value)
    if severity not in {"critical", "high", "medium", "low", "informational"}:
        return ""
    return severity.title()


def _proof_source_label(value: object) -> str:
    source = _safe_identifier(value)
    return {
        "tool_run_command": "command evidence",
        "tool_run_probe": "probe evidence",
        "tool_run_python": "Python evidence",
        "tool_validate_poc": "PoC validation evidence",
    }.get(source, "target evidence")


def _finding_fingerprint(payload: Mapping[str, Any]) -> str:
    finding_id = str(payload.get("finding_id") or "").strip()
    if finding_id:
        return _value_fingerprint(finding_id)
    vuln_class = _safe_identifier(payload.get("vuln_class") or payload.get("type"))
    location = _finding_location(payload)
    if not vuln_class or not location:
        return ""
    return _value_fingerprint("\x00".join([vuln_class, *location]))


def _is_evidence_confirmed_finding(payload: Mapping[str, Any]) -> bool:
    if _safe_identifier(payload.get("status")) != "confirmed":
        return False
    return not confirmed_finding_evidence_failures(dict(payload))


def confirmed_finding_result_line(payload: Mapping[str, Any]) -> str:
    """Return a bounded, secret-safe result label for a confirmed finding."""
    if not _is_evidence_confirmed_finding(payload):
        return ""
    severity = _severity_label(payload.get("severity")) or "Informational"
    vuln_class = (
        _human_identifier(payload.get("vuln_class") or payload.get("type"))
        or "vulnerability"
    )
    return _join(severity, [vuln_class, *_finding_location(payload)])


def _finding_location(payload: Mapping[str, Any]) -> list[str]:
    endpoint = _object(payload.get("endpoint"))
    method_value = endpoint.get("method", payload.get("method"))
    method = _http_method(method_value) if str(method_value or "").strip() else ""
    url = str(endpoint.get("url") or payload.get("url") or "").strip()
    path, query_names = _safe_url_shape(url)
    finding_input = _object(payload.get("input"))
    parameter_names = _parameter_names(finding_input.get("affected_parameters"))
    if not parameter_names:
        parameter_names = _parameter_names(endpoint.get("params"))
        for name in query_names:
            if name not in parameter_names:
                parameter_names.append(name)

    request = " ".join(item for item in (method, path) if item)
    details = [request]
    if parameter_names:
        details.append("parameters=" + ",".join(parameter_names[:6]))
    return [detail for detail in details if detail]


def _safe_url_shape(value: str) -> tuple[str, list[str]]:
    if not value:
        return "", []
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "", []
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return "", []
    path = _safe_path_shape(parsed.path or ("/" if parsed.netloc else ""))
    try:
        query_items = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=24)
    except ValueError:
        query_items = []
    names: list[str] = []
    for key, _value in query_items:
        name = _safe_parameter_name(key)
        if name and name not in names:
            names.append(name)
    return path, names[:6]


def _safe_path_shape(value: str) -> str:
    if not value:
        return ""
    raw_segments = value.split("/")
    safe_segments: list[str] = []
    previous = ""
    for raw_segment in raw_segments:
        segment = _safe_narrative(raw_segment)
        decoded = unquote(segment)
        if _dynamic_path_segment(decoded, previous=previous):
            safe_segments.append(":redacted" if _secret_path_segment(decoded) else ":id")
        else:
            safe_segments.append(segment)
        if decoded:
            previous = decoded.lower()
    return _safe_narrative("/".join(safe_segments))


def _dynamic_path_segment(value: str, *, previous: str) -> bool:
    if not value:
        return False
    fixed_shape = (
        _secret_path_segment(value)
        or previous in _SENSITIVE_PATH_PARENTS
        or bool(_UUID_PATH_SEGMENT_RE.fullmatch(value))
        or (value.isdigit() and len(value) >= _MIN_DYNAMIC_NUMERIC_SEGMENT_CHARS)
        or bool(re.fullmatch(r"(?i)[0-9a-f]{16,}", value))
    )
    if fixed_shape:
        return True
    if len(value) >= _MIN_ENTROPY_PATH_SEGMENT_CHARS and re.fullmatch(r"[A-Za-z0-9._~+=-]+", value):
        has_alpha = any(char.isalpha() for char in value)
        has_digit = any(char.isdigit() for char in value)
        mixed_case = any(char.islower() for char in value) and any(char.isupper() for char in value)
        return has_alpha and (has_digit or mixed_case)
    return False


def _secret_path_segment(value: str) -> bool:
    return bool(_TOKEN_PATH_SEGMENT_RE.fullmatch(value))


def _parameter_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for item in value[:12]:
        raw_name: object = item
        if isinstance(item, dict):
            raw_name = item.get("name") or item.get("param")
        name = _safe_parameter_name(raw_name)
        if name and name not in names:
            names.append(name)
    return names[:6]


def _safe_parameter_name(value: object) -> str:
    text = _safe_text(value)
    if not re.fullmatch(r"[A-Za-z0-9_.\[\]-]{1,64}", text):
        return ""
    return text


def _probe_request_target(payload: Mapping[str, Any]) -> str:
    path = _safe_path_shape(str(payload.get("path") or "/")) or "/"
    query_value = payload.get("query")
    pairs: list[str] = []
    if isinstance(query_value, list):
        for raw_item in query_value[:12]:
            if not isinstance(raw_item, dict):
                continue
            name = _safe_parameter_name(raw_item.get("name"))
            value = _safe_narrative(raw_item.get("value"))
            if name:
                pairs.append(f"{name}={value}")
    if pairs:
        return _clip(path + "?" + "&".join(pairs), _MAX_DETAIL_CHARS)
    return path


def _form_input_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for raw_input in value[:12]:
        if not isinstance(raw_input, dict):
            continue
        name = _safe_parameter_name(raw_input.get("name"))
        if name and name not in names:
            names.append(name)
    return names[:6]


def _finding_evidence_details(payload: Mapping[str, Any]) -> list[str]:
    details: list[str] = []
    evidence_kind = _safe_identifier(payload.get("evidence_kind"))
    evidence_label = {
        "http_poc_replay": "HTTP PoC replay",
        "browser_execution": "browser execution",
        "response_differential": "response differential",
        "proof_bundle": "verified proof bundle",
    }.get(evidence_kind, _human_identifier(evidence_kind))
    if evidence_label:
        details.append(evidence_label)

    check_summary = _evidence_check_summary(payload.get("evidence_checks"))
    if check_summary:
        details.append(check_summary)

    source_kind = _safe_identifier(payload.get("source_kind"))
    if source_kind:
        details.append(_proof_source_label(source_kind))
    return details


def _evidence_check_summary(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    required = _evidence_check_count(value.get("required"), passed=False)
    passed = _evidence_check_count(value.get("passed"), passed=True)
    if required:
        return f"{min(passed, required)}/{required} checks passed"
    if passed:
        return _count(passed, "check") + " passed"
    return ""


def _evidence_check_count(value: object, *, passed: bool) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        if passed:
            return sum(item is True for item in value.values())
        return len(value)
    return 0


def _rejected_evidence_details(payload: Mapping[str, Any]) -> list[str]:
    details: list[str] = []
    summary = _evidence_check_summary(payload.get("evidence_checks"))
    if summary:
        details.append(summary)

    failures_value = payload.get(
        "evidence_failures",
        payload.get(
            "failures",
            payload.get("missing_evidence", payload.get("reason")),
        ),
    )
    if isinstance(failures_value, list):
        failures = failures_value
    elif isinstance(failures_value, str):
        failures = failures_value.split(";")
    else:
        failures = [failures_value]
    labels: list[str] = []
    for failure in failures[:8]:
        label = _evidence_failure_label(failure)
        if label and label not in labels:
            labels.append(label)
    if labels:
        details.append("missing=" + ",".join(labels))
    elif not details:
        reason = _human_identifier(payload.get("reason"))
        details.append(reason or "required evidence missing")
    return details


def _evidence_failure_label(value: object) -> str:
    text = str(value or "").strip().lower()
    return {
        "finding metadata must be an object": "finding metadata",
        "missing finding.vuln_class": "vulnerability class",
        "missing finding.severity": "severity",
        "missing finding.hypothesis": "hypothesis",
        "missing finding.impact": "impact",
        "missing finding.exploit_steps": "exploit steps",
        "finding.severity is not supported": "supported severity",
        "finding.vuln_class must be a canonical snake_case identifier": (
            "canonical vulnerability class"
        ),
        "finding.exploit_steps contains empty text": "complete exploit steps",
        "http replay cannot confirm xss": "trusted browser execution",
        "require trusted client-side execution evidence": "trusted browser execution",
        "http poc replay did not pass": "passing HTTP PoC replay",
        "http poc replay requires at least one explicit passed expectation": (
            "passed replay expectation"
        ),
        "finding confirmation requires paired control and exploit replay steps": (
            "paired control and exploit replays"
        ),
        "control and exploit replays each require a passed expectation": (
            "passing control and exploit expectations"
        ),
        "control and exploit replays must target the same endpoint and method": (
            "matching replay endpoint and method"
        ),
        "control and exploit replay inputs are identical": ("distinct control and exploit inputs"),
        "control and exploit replays must vary the same input shape": (
            "matching replay input shape"
        ),
        "control and exploit responses lack a security-relevant differential": (
            "security-relevant response differential"
        ),
        "finding class requires a trusted typed validator": "trusted typed validator",
        "generic http differences remain candidate signals": "trusted typed validator",
        "sql injection confirmation requires injection-shaped exploit input": (
            "injection-shaped exploit input"
        ),
        "sql injection confirmation requires a new executor-observed database error": (
            "executor-observed database error"
        ),
        "ssti confirmation requires a bounded arithmetic template expression": (
            "bounded template expression"
        ),
        (
            "ssti confirmation requires the executor-derived expression result only in "
            "the exploit response"
        ): "executor-observed template result differential",
        "file-read confirmation requires traversal-shaped exploit input": (
            "traversal-shaped exploit input"
        ),
        (
            "file-read confirmation requires new executor-observed local-file content"
        ): "executor-observed local-file content",
        "validated finding endpoint is outside engagement scope": "scope check",
        "validated finding lacks executor-owned http replay provenance": "executor provenance",
        "browser execution has an unsupported http method": "supported browser request method",
        "browser execution endpoint is outside engagement scope": "scope check",
        "browser execution lacks an affected input name": "affected browser input",
        "browser execution lacks executor-owned execution evidence": ("browser execution evidence"),
        "browser execution lacks executor-owned probe provenance": "executor provenance",
        "missing proof": "proof",
        "missing proof.http_request_final": "request replay",
        "missing proof.response_final": "response evidence",
        "missing proof.impact_description": "impact evidence",
        "missing exploit_steps": "exploit steps",
        "endpoint.url is outside engagement scope": "scope check",
    }.get(text, _human_identifier(text))


def _safe_record_id(value: object) -> str:
    text = _safe_text(value)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}", text):
        return ""
    return text


def _first_safe_path(payload: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        path = _safe_narrative(payload.get(key))
        if path:
            return path
    return ""


def _value_fingerprint(value: object) -> str:
    text = str(value or "")
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def _safe_word(value: object, *, default: str = "") -> str:
    text = _safe_text(value)
    return text.split()[0] if text else default


def _safe_identifier(value: object) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,47}", text):
        return ""
    return text


def _http_method(value: object) -> str:
    method = str(value or "GET").strip().upper()
    return method if method in _HTTP_METHODS else "HTTP"


def _safe_target(value: object) -> str:
    text = str(value or "")[:_MAX_UNTRUSTED_INPUT_CHARS].strip()
    if not text:
        return ""
    if any(
        char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for char in text
    ):
        return "[invalid target]"
    try:
        parsed = urlsplit(text)
        scheme = parsed.scheme.lower()
        host = _canonical_target_host(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        return "[invalid target]"
    if scheme not in {"http", "https"} or not host:
        return "[invalid target]"
    if ":" in host:
        host = f"[{host}]"
    authority = f"{host}:{port}" if port is not None else host
    return f"{scheme}://{authority}"


def _canonical_target_host(host: str) -> str:
    host = unicodedata.normalize("NFC", host)
    if not host or len(host) > _MAX_DNS_HOST_CHARS:
        return ""
    if any(
        char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for char in host
    ):
        return ""
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    try:
        dns_host = host.removesuffix(".")
        ascii_host = dns_host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    labels = ascii_host.split(".")
    if (
        not ascii_host
        or len(ascii_host) > _MAX_DNS_HOST_CHARS
        or any(
            not label
            or len(label) > _MAX_DNS_LABEL_CHARS
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        )
    ):
        return ""
    return ascii_host


def _short_id(value: object) -> str:
    text = _safe_word(value)
    return text if len(text) <= _SHORT_ID_CHARS else text[:_SHORT_ID_CHARS]


def _join(label: str, details: list[str]) -> str:
    clean = [item for item in (_safe_text(value) for value in details) if item]
    return " · ".join([_safe_text(label), *clean])


def _cost(value: object) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float, str)):
        try:
            amount = float(value)
        except (OverflowError, TypeError, ValueError):
            return ""
    else:
        return ""
    if not math.isfinite(amount) or amount <= 0:
        return ""
    return f"${amount:.4f}"


def _finite_non_negative_float(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    if not isinstance(value, (int, float, str)):
        return 0.0
    try:
        amount = float(value)
    except (OverflowError, TypeError, ValueError):
        return 0.0
    return max(0.0, amount) if math.isfinite(amount) else 0.0


def _positive_int(value: object) -> int:
    return _non_negative_int(value)


def _non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, str)):
        try:
            return max(0, int(value))
        except (OverflowError, TypeError, ValueError):
            return 0
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        return max(0, int(value))
    return 0


def _quantity(value: int) -> str:
    if value < _THOUSAND:
        return str(value)
    if value < _MILLION:
        return f"{value / _THOUSAND:.1f}k"
    return f"{value / _MILLION:.1f}m"


def _count(value: int, noun: str) -> str:
    suffix = "" if value == 1 else "s"
    return f"{value} {noun}{suffix}"


def _duration(seconds: float) -> str:
    if seconds < _TENTH_SECOND:
        return "<0.1s"
    if seconds < _MINUTE_SECONDS:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), _MINUTE_SECONDS)
    return f"{minutes}m {remainder:02d}s"


def _terminal_width(stream: TextIO) -> int:
    try:
        fallback_columns = int(os.environ.get("COLUMNS", _DEFAULT_WIDTH))
    except ValueError:
        fallback_columns = _DEFAULT_WIDTH
    fallback_columns = max(_MIN_WIDTH, min(fallback_columns, _MAX_WIDTH))
    try:
        width = os.get_terminal_size(stream.fileno()).columns
    except (AttributeError, OSError, ValueError):
        width = fallback_columns
    return max(_MIN_WIDTH, min(width, _MAX_WIDTH))


def _clip(value: str, limit: int) -> str:
    text = str(value)
    if _display_width(text) <= limit:
        return text
    if limit <= 1:
        return "…"[:limit]
    remaining = limit - 1
    clipped: list[str] = []
    for char in text:
        width = _character_width(char)
        if width > remaining:
            break
        clipped.append(char)
        remaining -= width
    return "".join(clipped) + "…"


def _display_width(value: str) -> int:
    return sum(_character_width(char) for char in value)


def _character_width(char: str) -> int:
    if unicodedata.combining(char):
        return 0
    return 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1


__all__ = [
    "DisplayMode",
    "RunDisplay",
    "confirmed_finding_result_line",
    "redacted_artifact_path",
    "redacted_target_url",
    "sanitize_transcript_text",
]
