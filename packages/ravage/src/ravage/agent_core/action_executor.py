from __future__ import annotations

import json
import re
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qsl, unquote_plus, urljoin, urlsplit, urlunsplit
from uuid import UUID, uuid5

from ravage.agent_core.agent_state import AgentState, append_unique, merge_signals
from ravage.agent_core.agent_strategy import observation_digest
from ravage.agent_core.live_events import http_step_payload, mask_headers
from ravage.agent_core.observation_analysis import classify_action_result, extract_signals
from ravage.agent_core.surface_graph_ingest import ingest_probe_result, project_surface_graph
from ravage.auth.sessions import AuthenticationError
from ravage.finding_evidence import confirmed_finding_evidence_failures
from ravage.outcome_evidence import (
    OutcomeStage,
    native_confirmed_finding_payload,
    outcome_evidence_payload,
    outcome_stage_rank,
    qualify_probe_findings,
)
from ravage.probe_suite import (
    authenticated_probe_unavailability,
    probe_requires_anonymous_session,
    probe_requires_external_process,
    run_builtin_probe,
)
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import ToolResult, ToolRuntime
from ravage.traffic.policy import TrafficPolicyBlocked, TrafficPolicyController
from ravage.web_core.poc_validator import ValidationResult, validate_http_poc
from ravage.web_core.proof_recognizer import is_placeholder_proof, recognize_proofs
from ravage.web_core.scope_policy import same_origin, url_in_scope_entries

if TYPE_CHECKING:
    from ravage.auth.runtime import ManagedAttackAuthentication
    from ravage.web_core.http_probe import ProbeSession

_EXECUTOR_TOOL_RECOGNIZER = "executor_tool_observation"
_MAX_DISPLAY_FINDING_TYPES = 3
_MAX_DISPLAY_NAME_CHARS = 80
_MAX_DISPLAY_SUMMARY_CHARS = 240
_MAX_FINDING_EVIDENCE_CHARS = 1_200
_MAX_FINDING_TEXT_CHARS = 1_000
MAX_IDENTICAL_ACTION_EXECUTIONS = 2
_FINDING_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
_VULN_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_HTTP_FINDING_CLASS_ALIASES = {
    "arbitrary_file_read": "path_traversal",
    "file_read": "path_traversal",
    "lfi": "path_traversal",
    "local_file_inclusion": "path_traversal",
    "path_traversal": "path_traversal",
    "server_side_template_injection": "ssti",
    "sql_injection": "sql_injection",
    "ssti": "ssti",
    "template_injection": "ssti",
}
_HTTP_FINDING_ASSESSMENTS = {
    "sql_injection": {
        "severity": "High",
        "hypothesis": (
            "Attacker-controlled input reaches a database query and produces a new "
            "database error under an injection-shaped replay."
        ),
        "impact": (
            "This confirms an injectable database-query path; reachable data access "
            "depends on the query context and database permissions."
        ),
    },
    "ssti": {
        "severity": "High",
        "hypothesis": (
            "Attacker-controlled input is evaluated as a server-side template expression."
        ),
        "impact": (
            "Server-side template evaluation can expose application data or enable deeper "
            "server compromise, depending on the template engine and sandbox."
        ),
    },
    "path_traversal": {
        "severity": "High",
        "hypothesis": ("A traversal-shaped input returns recognizable local-file content."),
        "impact": (
            "An attacker can read local files available to the application process through "
            "the affected endpoint."
        ),
    },
}
_SQL_ERROR_MARKERS = (
    "database error",
    "jdbc exception",
    "mysql syntax",
    "mysql_fetch",
    "odbc sql",
    "ora-",
    "pg_query(",
    "postgresql error",
    "sql syntax",
    "sqlite error",
    "sqlite syntax error",
    "sqlite3.",
    "sqlstate[",
    "syntax error at or near",
    "unclosed quotation",
    "unterminated quoted",
    "you have an error in your sql syntax",
)
_FILE_CONTENT_MARKERS = (
    "root:x:0:0:",
    "daemon:x:",
    "[boot loader]",
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
)
_TEMPLATE_EXPRESSION_RE = re.compile(
    r"(?:\{\{|\$\{|<%=)\s*(\d{1,4})\s*([+*\-/])\s*(\d{1,4})\s*(?:\}\}|\}|%>)"
)


class ProbeExecutionTimeout(TimeoutError):
    pass


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    observation: str
    stop: bool = False
    exit_code: int | None = None
    timed_out: bool = False
    repeat_count: int = 0
    outcome: str = "observed"
    flag: str = ""
    session_mode: str = ""
    evidence_source_kind: str = ""
    evidence_observation: str = field(default="", repr=False, compare=False)

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ok": self.ok,
            "observation": self.observation,
            "stop": self.stop,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "repeat_count": self.repeat_count,
            "outcome": self.outcome,
            "flag": self.flag,
        }
        if self.session_mode:
            payload["session_mode"] = self.session_mode
        return payload


@dataclass(frozen=True)
class _ProbeActionResult:
    text: str
    ok: bool
    timed_out: bool = False


def execute_action(  # noqa: PLR0913
    action: dict[str, object],
    *,
    target_url: str,
    runtime: ToolRuntime,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    repeat_count: int,
    max_observation_chars: int,
    max_transcript_chars: int,
    proof_recognition_enabled: bool = False,
    action_id: str = "",
    authentication: ManagedAttackAuthentication | None = None,
    traffic_policy: TrafficPolicyController | None = None,
) -> ActionResult:
    if authentication is not None:
        authentication.assert_traffic_policy(traffic_policy)
    kind = str(action.get("action") or "")
    if kind == "invalid":
        return _invalid(
            action,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
        )
    if authentication is not None and kind in {"run_command", "run_python"}:
        return _block_authenticated_external_action(
            kind=kind,
            authentication=authentication,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
        )
    if (
        kind in {"run_command", "run_python", "run_probe", "validate_poc"}
        and repeat_count > MAX_IDENTICAL_ACTION_EXECUTIONS
    ):
        return _repeated(
            action,
            repeat_count=repeat_count,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
        )
    if kind in {"run_command", "run_python"}:
        blocked = _guard_unmetered_action(
            traffic_policy,
            lane=kind,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
        )
        if blocked is not None:
            return blocked
    if kind == "run_command":
        tool_result = runtime.run_command(
            command=str(action.get("command") or "").strip(),
            target_url=target_url,
            timeout_seconds=_command_timeout(action.get("timeout_seconds")),
        )
        return _record_tool_result(
            tool_result,
            kind="tool_run_command",
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            proof_recognition_enabled=proof_recognition_enabled,
            action_id=action_id,
            repeat_count=repeat_count,
            max_observation_chars=max_observation_chars,
            max_transcript_chars=max_transcript_chars,
        )
    if kind == "run_python":
        tool_result = runtime.run_python(
            code=str(action.get("code") or "").strip(),
            target_url=target_url,
            timeout_seconds=_command_timeout(action.get("timeout_seconds")),
        )
        return _record_tool_result(
            tool_result,
            kind="tool_run_python",
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            proof_recognition_enabled=proof_recognition_enabled,
            action_id=action_id,
            repeat_count=repeat_count,
            max_observation_chars=max_observation_chars,
            max_transcript_chars=max_transcript_chars,
        )
    if kind == "run_probe":
        probe = str(action.get("probe") or "").strip()
        unavailable_reason = (
            authenticated_probe_unavailability(probe) if authentication is not None else ""
        )
        if authentication is not None and unavailable_reason:
            return _block_authenticated_unavailable_probe(
                probe=probe,
                reason=unavailable_reason,
                authentication=authentication,
                workspace=workspace,
                audit=audit,
                engagement_id=engagement_id,
                action_id=action_id,
            )
        if probe_requires_external_process(probe):
            blocked = _guard_unmetered_action(
                traffic_policy,
                lane=f"run_probe:{probe}",
                workspace=workspace,
                audit=audit,
                engagement_id=engagement_id,
                action_id=action_id,
            )
            if blocked is not None:
                return blocked
        timeout_seconds = _timeout(action.get("timeout_seconds")) or 10
        session_mode = ""
        if authentication is not None:
            use_managed_identity = not probe_requires_anonymous_session(probe)
            session_mode = (
                f"identity:{authentication.identity}"
                if use_managed_identity
                else "anonymous:probe-required"
            )
            probe_result = _run_authenticated_probe_action(
                probe,
                target_url=target_url,
                state=state,
                timeout_seconds=timeout_seconds,
                authentication=authentication,
                use_managed_identity=use_managed_identity,
                traffic_policy=traffic_policy,
            )
        else:
            probe_result = _run_probe_action(
                probe,
                target_url=target_url,
                state=state,
                timeout_seconds=timeout_seconds,
                traffic_policy_reference=(
                    traffic_policy.to_reference() if traffic_policy is not None else None
                ),
            )
        result = record_probe_result(
            probe_result.text,
            ok=probe_result.ok,
            kind="tool_run_probe",
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            proof_recognition_enabled=proof_recognition_enabled,
            action_id=action_id,
            repeat_count=repeat_count,
            timed_out=probe_result.timed_out,
            max_observation_chars=max_observation_chars,
            max_transcript_chars=max_transcript_chars,
            session_mode=session_mode,
            authentication=authentication,
        )
        return record_verified_probe_findings(
            probe=probe,
            probe_text=probe_result.text,
            result=result,
            target_url=target_url,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
        )
    if kind == "validate_poc":
        session_mode = f"identity:{authentication.identity}" if authentication is not None else ""
        poc_session: ProbeSession | None = None

        def _emit_http_step(info: dict[str, object]) -> None:
            index_value = info.get("index")
            index = 0
            if isinstance(index_value, int) and not isinstance(index_value, bool):
                index = index_value
            elif isinstance(index_value, str):
                try:
                    index = int(index_value)
                except ValueError:
                    index = 0

            method = str(info.get("method") or "GET")
            url = str(info.get("url") or "")

            form_value = info.get("form")
            form_payload: dict[str, Any] | None = None
            if isinstance(form_value, dict):
                form_payload = cast(dict[str, Any], form_value)

            status_value = info.get("status")
            status: int | None = None
            if isinstance(status_value, int) and not isinstance(status_value, bool):
                status = status_value

            ok_value = info.get("ok")
            ok: bool | None = None
            if isinstance(ok_value, bool):
                ok = ok_value

            response_headers = info.get("headers")
            body = info.get("body")

            payload = http_step_payload(
                action_id=action_id,
                index=index,
                method=method,
                url=url,
                form=form_payload,
                status=status,
                ok=ok,
                response_headers=response_headers,
                body=body,
            )
            if session_mode:
                payload["session_mode"] = session_mode
            workspace.record_event(kind="http_step", payload=payload)

        poc_timeout = _timeout(action.get("timeout_seconds")) or 10
        try:
            if authentication is not None:
                poc_session = authentication.session_for_model_action(
                    timeout_seconds=poc_timeout
                )
            validation_result = validate_http_poc(
                target_url=target_url,
                steps=action.get("steps"),
                timeout_seconds=poc_timeout,
                on_step=_emit_http_step,
                allow_remote_target=state.surface.get("allow_remote_target") is True,
                in_scope=_surface_string_list(state, "scope_in_scope"),
                out_of_scope=_surface_string_list(state, "scope_out_of_scope"),
                max_rps=_surface_int(state, "scope_max_rps"),
                session=poc_session,
                redact=(authentication.redact if authentication is not None else None),
                traffic_policy_reference=(
                    traffic_policy.to_reference()
                    if traffic_policy is not None and poc_session is None
                    else None
                ),
            )
        finally:
            if authentication is not None and poc_session is not None:
                authentication.retire_probe_session(poc_session)
        validation_text = validation_result.to_text()
        safe_action: Mapping[str, object] = action
        if authentication is not None:
            safe_action = _authenticated_mapping(authentication.redact(action))
            validation_payload = _authenticated_mapping(
                authentication.redact(json.loads(validation_text))
            )
            validation_payload["session_mode"] = session_mode
            validation_text = json.dumps(validation_payload, indent=2, sort_keys=True)
        result = record_probe_result(
            validation_text,
            ok=validation_result.ok,
            kind="tool_validate_poc",
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            proof_recognition_enabled=proof_recognition_enabled,
            action_id=action_id,
            repeat_count=repeat_count,
            timed_out=False,
            max_observation_chars=max_observation_chars,
            max_transcript_chars=max_transcript_chars,
            session_mode=session_mode,
            authentication=authentication,
        )
        finding = safe_action.get("finding")
        if finding is None:
            return result
        return _record_validated_finding(
            finding,
            validation=validation_result,
            action=safe_action,
            result=result,
            target_url=target_url,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
        )
    if kind == "capture_flag":
        return _capture(
            action,
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
            authentication=authentication,
        )
    summary = str(action.get("summary") or "agent stopped")
    final_payload: dict[str, object] = {"summary": summary}
    if action_id:
        final_payload["action_id"] = action_id
    workspace.record_event(kind="agent_final", payload=final_payload)
    return ActionResult(ok=True, observation=summary, stop=True, outcome="final")


def _record(
    audit: AuditStore, engagement_id: UUID, *, actor: str, action: str, payload: dict[str, Any]
) -> None:
    audit.record(engagement_id=engagement_id, actor=actor, action=action, payload=payload)


def _guard_unmetered_action(
    traffic_policy: TrafficPolicyController | None,
    *,
    lane: str,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
) -> ActionResult | None:
    if traffic_policy is None:
        return None
    try:
        traffic_policy.record_unmetered_action()
    except TrafficPolicyBlocked as exc:
        payload = {
            "action_id": action_id,
            "lane": lane,
            "reason": str(exc),
        }
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="traffic_policy_blocked",
            payload=payload,
        )
        workspace.record_event(kind="traffic_policy_blocked", payload=payload)
        return ActionResult(
            ok=False,
            observation=(
                f"Whole-run low-noise traffic policy blocked opaque lane {lane!r}; "
                "use a native HTTP probe or validate_poc action instead."
            ),
            outcome="blocked",
        )
    return None


def _invalid(
    action: dict[str, object],
    *,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str = "",
) -> ActionResult:
    error = str(action.get("error") or "invalid model action")
    payload = {"error": error, "raw": str(action.get("raw") or "")[:2000]}
    if action_id:
        payload["action_id"] = action_id
    _record(audit, engagement_id, actor="agent", action="invalid_action", payload=payload)
    workspace.record_event(kind="invalid_action", payload=payload)
    return ActionResult(
        ok=False,
        observation="Invalid action. Return exactly one JSON object matching the action schema. "
        f"Error: {error}",
        outcome="blocked",
    )


def _block_authenticated_external_action(
    *,
    kind: str,
    authentication: ManagedAttackAuthentication,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
) -> ActionResult:
    session_mode = f"identity:{authentication.identity}"
    payload = _authenticated_mapping(
        authentication.redact(
            {
                "action_kind": kind,
                "action_id": action_id,
                "reason": (
                    "authenticated attack credentials are available only to managed "
                    "HTTP probes and PoC replay"
                ),
            }
        )
    )
    payload["session_mode"] = session_mode
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="authenticated_external_action_blocked",
        payload=payload,
    )
    workspace.record_event(
        kind="authenticated_external_action_blocked",
        payload=payload,
    )
    return ActionResult(
        ok=False,
        observation=json.dumps(payload, sort_keys=True),
        outcome="blocked",
        session_mode=session_mode,
    )


def _block_authenticated_unavailable_probe(
    *,
    probe: str,
    reason: str,
    authentication: ManagedAttackAuthentication,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
) -> ActionResult:
    session_mode = (
        "blocked:external-process"
        if probe_requires_external_process(probe)
        else "blocked:unmanaged-transport"
    )
    payload = _authenticated_mapping(
        authentication.redact(
            {
                "probe": probe,
                "action_id": action_id,
                "reason": reason,
            }
        )
    )
    payload["session_mode"] = session_mode
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="authenticated_unavailable_probe_blocked",
        payload=payload,
    )
    workspace.record_event(
        kind="authenticated_unavailable_probe_blocked",
        payload=payload,
    )
    observation = json.dumps(payload, sort_keys=True)
    return ActionResult(
        ok=False,
        observation=observation,
        outcome="blocked",
        session_mode=session_mode,
        evidence_source_kind="tool_run_probe",
        evidence_observation=observation,
    )


def _authenticated_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError("authenticated redaction must preserve mapping values")
    return {str(key): item for key, item in value.items()}


def _repeated(
    action: dict[str, object],
    *,
    repeat_count: int,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str = "",
) -> ActionResult:
    payload = {
        "repeat_count": repeat_count,
        "strategy": action.get("strategy"),
        "notes": action.get("notes"),
    }
    if action_id:
        payload["action_id"] = action_id
    _record(audit, engagement_id, actor="agent", action="repeated_action_blocked", payload=payload)
    workspace.record_event(kind="repeated_action_blocked", payload=payload)
    return ActionResult(
        ok=False,
        repeat_count=repeat_count,
        outcome="same_as_before",
        observation=(
            "Repeated identical action blocked. Change a material variable, use a "
            "different endpoint/parameter/session, or switch strategy."
        ),
    )


def _capture(  # noqa: PLR0913
    action: dict[str, object],
    *,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str = "",
    authentication: ManagedAttackAuthentication | None = None,
) -> ActionResult:
    flag = str(action.get("flag") or "").strip()
    evidence = str(action.get("evidence") or "")
    if authentication is not None and authentication.contains_secret(evidence):
        evidence = "[REDACTED]"
    elif authentication is not None:
        evidence = authentication.redact_text(evidence)
    safe_submitted_flag = authentication.redact_text(flag) if authentication is not None else flag
    payload: dict[str, object] = {
        "flag": safe_submitted_flag,
        "evidence": evidence,
        "flag_record_path": str(workspace.events_path),
    }
    if action_id:
        payload["action_id"] = action_id
    if authentication is not None and authentication.contains_secret(flag):
        payload["flag"] = "[REDACTED]"
        payload["error"] = "capture_flag rejected an authentication-tainted proof"
        _record(
            audit, engagement_id, actor="agent", action="flag_capture_rejected", payload=payload
        )
        workspace.record_event(kind="flag_capture_rejected", payload=payload)
        return ActionResult(
            ok=False,
            observation=json.dumps(payload),
            stop=False,
            outcome="blocked",
        )
    if _looks_like_placeholder_flag(flag):
        payload["error"] = "capture_flag requires the exact proof string, not a placeholder"
        _record(
            audit, engagement_id, actor="agent", action="flag_capture_rejected", payload=payload
        )
        workspace.record_event(kind="flag_capture_rejected", payload=payload)
        return ActionResult(
            ok=False,
            observation=json.dumps(payload),
            stop=False,
            outcome="blocked",
        )
    proofs = recognize_proofs(flag)
    if not proofs:
        payload["error"] = (
            "capture_flag requires a recognized proof string, not inferred or malformed text"
        )
        _record(
            audit, engagement_id, actor="agent", action="flag_capture_rejected", payload=payload
        )
        workspace.record_event(kind="flag_capture_rejected", payload=payload)
        return ActionResult(
            ok=False,
            observation=json.dumps(payload),
            stop=False,
            outcome="blocked",
        )
    flag = proofs[0]
    if authentication is not None and authentication.contains_secret(flag):
        payload["flag"] = "[REDACTED]"
        payload["error"] = "capture_flag rejected an authentication-tainted proof"
        _record(
            audit, engagement_id, actor="agent", action="flag_capture_rejected", payload=payload
        )
        workspace.record_event(kind="flag_capture_rejected", payload=payload)
        return ActionResult(
            ok=False,
            observation=json.dumps(payload),
            stop=False,
            outcome="blocked",
        )
    payload["flag"] = flag
    if flag in state.flags:
        payload["reason"] = "proof was already captured"
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="flag_capture_duplicate",
            payload=payload,
        )
        workspace.record_event(kind="flag_capture_duplicate", payload=payload)
        return ActionResult(
            ok=True,
            observation=json.dumps(payload),
            stop=False,
            outcome="same_as_before",
        )
    if not _capture_has_observed_evidence(flag, state=state):
        payload["error"] = (
            "capture_flag requires the exact proof string to appear in recent target evidence"
        )
        _record(
            audit, engagement_id, actor="agent", action="flag_capture_rejected", payload=payload
        )
        workspace.record_event(kind="flag_capture_rejected", payload=payload)
        return ActionResult(
            ok=False,
            observation=json.dumps(payload),
            stop=False,
            outcome="blocked",
        )
    payload.update(_capture_provenance(state=state, capture_method="agent_submission"))
    if flag and flag not in state.flags:
        state.flags.append(flag)
    _record(audit, engagement_id, actor="agent", action="flag_captured", payload=payload)
    workspace.record_event(kind="flag_captured", payload=payload)
    source_kind = str(state.last_observation.get("source_kind") or "")
    return ActionResult(
        ok=True,
        observation=json.dumps(payload),
        stop=True,
        outcome="flag_candidate",
        flag=flag,
        evidence_source_kind=source_kind,
    )


def _record_validated_finding(  # noqa: PLR0913
    finding_value: object,
    *,
    validation: ValidationResult,
    action: Mapping[str, object],
    result: ActionResult,
    target_url: str,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
) -> ActionResult:
    finding, metadata_failures = _validated_finding_metadata(finding_value)
    passed_checks, required_checks = _validation_check_counts(validation)
    failures = list(metadata_failures)
    if finding.get("vuln_class", "").lower() in {"xss", "cross_site_scripting"}:
        failures.append(
            "HTTP replay cannot confirm XSS; require trusted client-side execution evidence"
        )
    if not validation.ok:
        failures.append("HTTP PoC replay did not pass")
    if required_checks < 1 or passed_checks < 1:
        failures.append("HTTP PoC replay requires at least one explicit passed expectation")
    evidence_step, replay_failures = _paired_replay_evidence(
        action,
        validation=validation,
        target_url=target_url,
    )
    failures.extend(replay_failures)
    canonical_class, class_failures = _class_specific_replay_evidence(
        action,
        validation=validation,
        vuln_class=finding.get("vuln_class", ""),
    )
    failures.extend(class_failures)

    endpoint = _finding_endpoint(
        evidence_step,
        action=action,
        target_url=target_url,
    )
    finding_input = _validated_finding_input(
        action,
        endpoint=endpoint,
        target_url=target_url,
    )
    endpoint_url = str(endpoint.get("url") or "")
    if not endpoint_url or not _finding_url_in_scope(
        endpoint_url,
        target_url=target_url,
        audit=audit,
    ):
        failures.append("validated finding endpoint is outside engagement scope")

    source_observation_id = str(state.last_observation.get("observation_id") or "").strip()
    source_kind = str(state.last_observation.get("source_kind") or "").strip()
    if not source_observation_id or source_kind != "tool_validate_poc":
        failures.append("validated finding lacks executor-owned HTTP replay provenance")
    if failures:
        return _reject_finding(
            finding=finding,
            failures=failures,
            passed_checks=passed_checks,
            required_checks=required_checks,
            result=result,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
            source_observation_id=source_observation_id,
        )

    assessment = _HTTP_FINDING_ASSESSMENTS[canonical_class]
    exploit_steps = _finding_exploit_steps(validation, action=action)
    final_step = next(
        (step for step in exploit_steps if step.get("evidence_role") == "exploit"),
        exploit_steps[-1],
    )
    finding_id = _finding_id(
        engagement_id=engagement_id,
        finding={"vuln_class": canonical_class},
        endpoint=endpoint,
        finding_input=finding_input,
    )
    payload: dict[str, object] = {
        "finding_id": finding_id,
        "engagement_id": str(engagement_id),
        "vuln_class": canonical_class,
        "severity": assessment["severity"],
        "hypothesis": assessment["hypothesis"],
        "impact": assessment["impact"],
        "assessment_source": "executor_policy",
        "endpoint": endpoint,
        "input": finding_input,
        "exploit_steps": exploit_steps,
        "proof": {
            "http_request_final": final_step["http_request"],
            "response_final": final_step["response_snippet"],
            "impact_description": assessment["impact"],
        },
        "status": "confirmed",
        "validator_vote": "confirm",
        "evidence_checks": {"passed": passed_checks, "required": required_checks},
        "evidence_kind": "http_poc_replay",
        "outcome_stage": OutcomeStage.VERIFIED_VULNERABILITY.value,
        "source_kind": source_kind,
        "source_observation_id": source_observation_id,
        "action_id": action_id,
        "finding_record_path": str(workspace.events_path),
        "provenance": {
            "evidence_kind": "http_poc_replay",
            "source_kind": source_kind,
            "source_observation_id": source_observation_id,
            "action_id": action_id,
            "assessment_source": "executor_policy",
            "model_claims_used": False,
        },
    }
    evidence_failures = confirmed_finding_evidence_failures(payload, scope=audit.scope)
    if evidence_failures:
        return _reject_finding(
            finding=finding,
            failures=list(evidence_failures),
            passed_checks=passed_checks,
            required_checks=required_checks,
            result=result,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
            source_observation_id=source_observation_id,
        )

    return _persist_confirmed_finding(
        payload,
        result=result,
        state=state,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
    )


def record_verified_probe_findings(  # noqa: C901, PLR0912, PLR0913
    *,
    probe: str,
    probe_text: str,
    result: ActionResult,
    target_url: str,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
) -> ActionResult:
    probe_payload = _json_object(probe_text)
    qualified_findings = qualify_probe_findings(
        probe=probe,
        probe_text=probe_text,
        target_url=target_url,
    )
    if not qualified_findings:
        return result
    raw_findings = probe_payload.get("findings")
    if not isinstance(raw_findings, list):
        return result
    source_observation_id = str(state.last_observation.get("observation_id") or "").strip()
    source_kind = str(state.last_observation.get("source_kind") or "").strip()
    if not source_observation_id or source_kind != "tool_run_probe":
        return result

    current = result
    for qualified in qualified_findings:
        endpoint_url = str(qualified.endpoint.get("url") or "")
        if not endpoint_url or not _finding_url_in_scope(
            endpoint_url,
            target_url=target_url,
            audit=audit,
        ):
            if qualified.contract.promotion_kind == "dom":
                candidate = _raw_probe_finding(raw_findings, qualified.finding_type)
                if candidate is not None:
                    current = _promote_dom_execution(
                        candidate,
                        result=current,
                        target_url=target_url,
                        state=state,
                        workspace=workspace,
                        audit=audit,
                        engagement_id=engagement_id,
                        action_id=action_id,
                    )
            continue

        confirmed = False
        forced_stage: OutcomeStage | None = None
        if qualified.promotable and qualified.contract.promotion_kind == "dom":
            candidate = _raw_probe_finding(raw_findings, qualified.finding_type)
            if candidate is not None:
                current = _promote_dom_execution(
                    candidate,
                    result=current,
                    target_url=target_url,
                    state=state,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=engagement_id,
                    action_id=action_id,
                )
                confirmed = audit.has_finding(
                    qualified.finding_id(engagement_id),
                    engagement_id=engagement_id,
                )
                if not confirmed:
                    forced_stage = OutcomeStage.SUSPECTED_VULNERABILITY
        elif qualified.promotable and qualified.contract.promotion_kind == "native":
            finding_payload = native_confirmed_finding_payload(
                qualified,
                engagement_id=engagement_id,
                source_observation_id=source_observation_id,
                action_id=action_id,
                finding_record_path=str(workspace.events_path),
            )
            evidence_failures = confirmed_finding_evidence_failures(
                finding_payload,
                scope=audit.scope,
            )
            if not evidence_failures:
                current = _persist_confirmed_finding(
                    finding_payload,
                    result=current,
                    state=state,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=engagement_id,
                )
                confirmed = True
            else:
                forced_stage = OutcomeStage.SUSPECTED_VULNERABILITY
        else:
            forced_stage = OutcomeStage.SUSPECTED_VULNERABILITY

        evidence_payload = outcome_evidence_payload(
            qualified,
            engagement_id=engagement_id,
            source_observation_id=source_observation_id,
            action_id=action_id,
            confirmed=confirmed,
            forced_stage=forced_stage,
        )
        _record_outcome_evidence(
            evidence_payload,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
        )
    return current


# Compatibility alias for existing internal consumers. New deterministic
# runners should use the public shared recorder above instead of creating a
# second finding-promotion path.
_record_verified_probe_finding = record_verified_probe_findings


def _raw_probe_finding(
    findings: Sequence[object],
    finding_type: str,
) -> dict[str, object] | None:
    return next(
        (
            dict(item)
            for item in findings
            if isinstance(item, Mapping) and item.get("type") == finding_type
        ),
        None,
    )


def _record_outcome_evidence(
    payload: dict[str, object],
    *,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
) -> None:
    if _workspace_has_outcome_stage(
        workspace,
        engagement_id=engagement_id,
        evidence_id=str(payload.get("evidence_id") or ""),
        stage=str(payload.get("stage") or ""),
    ):
        return
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="outcome_evidence_observed",
        payload=payload,
    )
    workspace.record_event(kind="outcome_evidence_observed", payload=payload)


def _promote_dom_execution(  # noqa: PLR0913
    candidate: Mapping[str, object],
    *,
    result: ActionResult,
    target_url: str,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
) -> ActionResult:
    request = _mapping(candidate.get("request_template"))
    evidence = _mapping(candidate.get("evidence"))
    method = str(request.get("method") or candidate.get("method") or "GET").upper()
    raw_url = str(request.get("url") or candidate.get("probe_url") or "").strip()
    endpoint_url = _canonical_endpoint_url(urljoin(target_url, raw_url))
    parameter = str(request.get("payload_field") or "").strip()[:120]
    source_observation_id = str(state.last_observation.get("observation_id") or "").strip()
    source_kind = str(state.last_observation.get("source_kind") or "").strip()

    failures: list[str] = []
    if method not in {"GET", "POST"}:
        failures.append("browser execution has an unsupported HTTP method")
    if not endpoint_url or not _finding_url_in_scope(
        endpoint_url,
        target_url=target_url,
        audit=audit,
    ):
        failures.append("browser execution endpoint is outside engagement scope")
    if not parameter:
        failures.append("browser execution lacks an affected input name")
    if not _browser_execution_observed(evidence):
        failures.append("browser execution lacks executor-owned execution evidence")
    if not source_observation_id or source_kind != "tool_run_probe":
        failures.append("browser execution lacks executor-owned probe provenance")
    if failures:
        return _reject_verified_probe_finding(
            failures=failures,
            result=result,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
            source_observation_id=source_observation_id,
        )

    confirmation_method = (
        "browser binding" if evidence.get("token_executed") is True else "browser dialog"
    )
    execution_summary = {
        "confirmation_method": confirmation_method,
        "executed_value_count": _list_count(evidence.get("executed_values")),
        "dialog_count": _list_count(evidence.get("dialogs")),
    }
    final_url = _canonical_endpoint_url(urljoin(target_url, str(evidence.get("final_url") or "")))
    if final_url and _finding_url_in_scope(final_url, target_url=target_url, audit=audit):
        execution_summary["final_url"] = final_url
    endpoint = {
        "method": method,
        "url": endpoint_url,
        "params": [
            {
                "name": parameter,
                "location": "body" if method == "POST" else "query",
            }
        ],
    }
    safe_request = {
        "method": method,
        "url": endpoint_url,
        "payload_field": parameter,
    }
    finding_id = _verified_probe_finding_id(
        engagement_id=engagement_id,
        vuln_class="xss",
        endpoint=endpoint,
    )
    payload: dict[str, object] = {
        "finding_id": finding_id,
        "engagement_id": str(engagement_id),
        "vuln_class": "xss",
        "severity": "Medium",
        "hypothesis": "User-controlled input executes JavaScript in a browser context.",
        "impact": (
            "An attacker can execute JavaScript in an affected user's browser in the "
            "application origin."
        ),
        "assessment_source": "executor_policy",
        "endpoint": endpoint,
        "exploit_steps": [
            {
                "http_request": _bounded_json(safe_request),
                "response_snippet": _bounded_json(execution_summary),
                "indicator": "headless browser observed injected JavaScript execution",
            }
        ],
        "proof": {
            "http_request_final": _bounded_json(safe_request),
            "response_final": _bounded_json(execution_summary),
            "impact_description": (
                "Injected JavaScript executed in the application browser origin."
            ),
        },
        "status": "confirmed",
        "validator_vote": "confirm",
        "evidence_checks": {"passed": 1, "required": 1},
        "evidence_kind": "browser_execution",
        "outcome_stage": OutcomeStage.EXPLOIT_PRIMITIVE.value,
        "source_kind": source_kind,
        "source_observation_id": source_observation_id,
        "action_id": action_id,
        "finding_record_path": str(workspace.events_path),
        "provenance": {
            "evidence_kind": "browser_execution",
            "source_kind": source_kind,
            "source_observation_id": source_observation_id,
            "action_id": action_id,
            "probe": "dom_execution",
            "finding_type": "client_side_execution",
            "assessment_source": "executor_policy",
            "model_claims_used": False,
        },
    }
    evidence_failures = confirmed_finding_evidence_failures(payload, scope=audit.scope)
    if evidence_failures:
        return _reject_verified_probe_finding(
            failures=list(evidence_failures),
            result=result,
            workspace=workspace,
            audit=audit,
            engagement_id=engagement_id,
            action_id=action_id,
            source_observation_id=source_observation_id,
        )
    return _persist_confirmed_finding(
        payload,
        result=result,
        state=state,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
    )


def _browser_execution_observed(evidence: Mapping[str, object]) -> bool:
    if evidence.get("token_executed") is True:
        return True
    return (
        _list_count(evidence.get("executed_values")) > 0 or _list_count(evidence.get("dialogs")) > 0
    )


def _list_count(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def _verified_probe_finding_id(
    *,
    engagement_id: UUID,
    vuln_class: str,
    endpoint: Mapping[str, object],
) -> str:
    identity = json.dumps(
        {"vuln_class": vuln_class, "endpoint": endpoint},
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return str(uuid5(engagement_id, identity))


def _persist_confirmed_finding(  # noqa: PLR0913
    payload: dict[str, object],
    *,
    result: ActionResult,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
) -> ActionResult:
    finding_id = str(payload.get("finding_id") or "")
    vuln_class = str(payload.get("vuln_class") or "")
    append_unique(
        state.facts,
        f"confirmed finding {finding_id}: {vuln_class}",
        limit=80,
    )
    finding_stored = audit.has_finding(finding_id, engagement_id=engagement_id)
    finding_audited = audit.has_finding_action(
        "finding_confirmed",
        engagement_id=engagement_id,
        finding_id=finding_id,
    )
    finding_in_workspace = _workspace_has_finding_event(
        workspace,
        kind="finding_confirmed",
        engagement_id=engagement_id,
        finding_id=finding_id,
    )
    already_complete = all(
        (
            finding_stored,
            finding_audited,
            finding_in_workspace,
        )
    )

    if not already_complete:
        audit.record_finding_payload(
            finding_id=finding_id,
            engagement_id=engagement_id,
            vuln_class=vuln_class,
            status="confirmed",
            validator_vote="confirm",
            payload=payload,
        )
    if not finding_audited:
        _record(
            audit,
            engagement_id,
            actor="agent",
            action="finding_confirmed",
            payload=payload,
        )
    if not finding_in_workspace:
        workspace.record_event(kind="finding_confirmed", payload=payload)
    # A probe can emit multiple evidence variants that resolve to the same
    # canonical finding. Once one variant promoted this action, a later
    # already-recorded variant must not downgrade the action back to a repeat.
    if result.stop or result.outcome == "finding_confirmed":
        return result
    if already_complete:
        return replace(
            result,
            ok=True,
            observation=json.dumps({"finding_already_recorded": finding_id}, sort_keys=True),
            outcome="same_as_before",
        )
    confirmation = json.dumps(
        {
            "finding_confirmed": finding_id,
            "vuln_class": vuln_class,
            "evidence_checks": payload.get("evidence_checks"),
        },
        sort_keys=True,
    )
    return replace(
        result,
        ok=True,
        observation=confirmation,
        outcome="finding_confirmed",
    )


def _workspace_has_finding_event(
    workspace: AgentWorkspace,
    *,
    kind: str,
    engagement_id: UUID,
    finding_id: str,
) -> bool:
    return _workspace_has_payload_event(
        workspace,
        kind=kind,
        engagement_id=engagement_id,
        key="finding_id",
        value=finding_id,
    )


def _workspace_has_payload_event(
    workspace: AgentWorkspace,
    *,
    kind: str,
    engagement_id: UUID,
    key: str,
    value: str,
) -> bool:
    if not workspace.events_path.exists():
        return False
    try:
        lines = workspace.events_path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    except OSError:
        return False
    for line in lines:
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict) or event.get("kind") != kind:
            continue
        event_payload = event.get("payload")
        if not isinstance(event_payload, dict):
            continue
        if str(event_payload.get("engagement_id") or "") != str(engagement_id):
            continue
        if str(event_payload.get(key) or "") == value:
            return True
    return False


def _workspace_has_outcome_stage(
    workspace: AgentWorkspace,
    *,
    engagement_id: UUID,
    evidence_id: str,
    stage: str,
) -> bool:
    if not evidence_id or not workspace.events_path.exists():
        return False
    try:
        lines = workspace.events_path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    except OSError:
        return False
    required_rank = outcome_stage_rank(stage)
    for line in lines:
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict) or event.get("kind") != "outcome_evidence_observed":
            continue
        event_payload = event.get("payload")
        if not isinstance(event_payload, dict):
            continue
        if str(event_payload.get("engagement_id") or "") != str(engagement_id):
            continue
        if str(event_payload.get("evidence_id") or "") != evidence_id:
            continue
        if outcome_stage_rank(str(event_payload.get("stage") or "")) >= required_rank:
            return True
    return False


def _reject_verified_probe_finding(  # noqa: PLR0913
    *,
    failures: list[str],
    result: ActionResult,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
    source_observation_id: str,
) -> ActionResult:
    payload: dict[str, object] = {
        "vuln_class": "xss",
        "reason": "; ".join(dict.fromkeys(failures))[:_MAX_FINDING_TEXT_CHARS],
        "evidence_checks": {"passed": 0, "required": 1},
        "evidence_kind": "browser_execution",
        "source_kind": "tool_run_probe",
        "source_observation_id": source_observation_id,
        "action_id": action_id,
        "finding_record_path": str(workspace.events_path),
    }
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="finding_rejected_no_evidence",
        payload=payload,
    )
    workspace.record_event(kind="finding_rejected_no_evidence", payload=payload)
    if result.stop:
        return result
    return replace(
        result,
        ok=False,
        observation=json.dumps(payload, sort_keys=True),
        outcome="blocked",
    )


def _validated_finding_metadata(value: object) -> tuple[dict[str, str], tuple[str, ...]]:
    if not isinstance(value, Mapping):
        return {}, ("finding metadata must be an object",)
    finding = {
        "vuln_class": _bounded_finding_text(value.get("vuln_class")),
        "severity": _bounded_finding_text(value.get("severity")).title(),
        "hypothesis": _bounded_finding_text(value.get("hypothesis")),
        "impact": _bounded_finding_text(value.get("impact")),
    }
    failures = [f"missing finding.{key}" for key, item in finding.items() if not item]
    if finding["severity"] and finding["severity"] not in _FINDING_SEVERITIES:
        failures.append("finding.severity is not supported")
    if finding["vuln_class"] and not _VULN_CLASS_RE.fullmatch(finding["vuln_class"]):
        failures.append("finding.vuln_class must be a canonical snake_case identifier")
    steps = value.get("exploit_steps")
    if not isinstance(steps, list) or not steps:
        failures.append("missing finding.exploit_steps")
    elif any(not str(item or "").strip() for item in steps):
        failures.append("finding.exploit_steps contains empty text")
    return finding, tuple(failures)


def _bounded_finding_text(value: object) -> str:
    return str(value or "").strip()[:_MAX_FINDING_TEXT_CHARS]


def _validation_check_counts(validation: ValidationResult) -> tuple[int, int]:
    passed = 0
    required = 0
    for step in validation.steps:
        checks = step.get("checks")
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, Mapping):
                continue
            required += 1
            if check.get("passed") is True:
                passed += 1
    return passed, required


def _paired_replay_evidence(
    action: Mapping[str, object],
    *,
    validation: ValidationResult,
    target_url: str,
) -> tuple[dict[str, object], tuple[str, ...]]:
    roles = _replay_role_steps(action, validation=validation)
    if set(roles) != {"control", "exploit"}:
        return {}, ("finding confirmation requires paired control and exploit replay steps",)

    control_raw, control = roles["control"]
    exploit_raw, exploit = roles["exploit"]
    failures: list[str] = []
    if not _step_has_passed_expectation(control) or not _step_has_passed_expectation(exploit):
        failures.append("control and exploit replays each require a passed expectation")
    if not _same_replay_endpoint(
        control,
        exploit,
        target_url=target_url,
    ):
        failures.append("control and exploit replays must target the same endpoint and method")
    if _replay_material(control_raw) == _replay_material(exploit_raw):
        failures.append("control and exploit replay inputs are identical")
    control_shape = _replay_input_shape(control_raw, target_url=target_url)
    exploit_shape = _replay_input_shape(exploit_raw, target_url=target_url)
    if control_shape and exploit_shape and control_shape != exploit_shape:
        failures.append("control and exploit replays must vary the same input shape")
    if not _security_relevant_response_delta(control, exploit):
        failures.append("control and exploit responses lack a security-relevant differential")
    return exploit, tuple(failures)


def _replay_role_steps(
    action: Mapping[str, object],
    *,
    validation: ValidationResult,
) -> dict[str, tuple[Mapping[str, object], dict[str, object]]]:
    raw_steps = action.get("steps")
    if not isinstance(raw_steps, list):
        return {}
    roles: dict[str, tuple[Mapping[str, object], dict[str, object]]] = {}
    validation_by_index = {
        _positive_step_index(step.get("index")): step for step in validation.steps
    }
    for index, raw_step in enumerate(raw_steps, start=1):
        if not isinstance(raw_step, Mapping):
            continue
        role = str(raw_step.get("evidence_role") or "").strip().lower()
        validated = validation_by_index.get(index)
        if role in {"control", "exploit"} and validated is not None and role not in roles:
            roles[role] = (raw_step, validated)
    return roles


def _class_specific_replay_evidence(
    action: Mapping[str, object],
    *,
    validation: ValidationResult,
    vuln_class: str,
) -> tuple[str, tuple[str, ...]]:
    normalized = vuln_class.strip().lower()
    if normalized in {"xss", "cross_site_scripting"}:
        return "", ()
    canonical = _HTTP_FINDING_CLASS_ALIASES.get(normalized, "")
    if not canonical:
        return "", (
            "finding class requires a trusted typed validator; generic HTTP differences "
            "remain candidate signals",
        )
    roles = _replay_role_steps(action, validation=validation)
    if set(roles) != {"control", "exploit"}:
        return canonical, ()
    control_raw, control = roles["control"]
    exploit_raw, exploit = roles["exploit"]
    if canonical == "sql_injection":
        failures = _sql_injection_replay_failures(
            control_raw,
            control,
            exploit_raw,
            exploit,
        )
    elif canonical == "ssti":
        failures = _ssti_replay_failures(
            control_raw,
            control,
            exploit_raw,
            exploit,
        )
    else:
        failures = _path_traversal_replay_failures(
            control_raw,
            control,
            exploit_raw,
            exploit,
        )
    return canonical, tuple(failures)


def _sql_injection_replay_failures(
    control_raw: Mapping[str, object],
    control: Mapping[str, object],
    exploit_raw: Mapping[str, object],
    exploit: Mapping[str, object],
) -> list[str]:
    failures: list[str] = []
    control_material = _decoded_replay_request_text(control_raw).lower()
    exploit_material = _decoded_replay_request_text(exploit_raw).lower()
    control_markers = _sql_injection_input_markers(control_material)
    exploit_markers = _sql_injection_input_markers(exploit_material)
    if not exploit_markers.difference(control_markers):
        failures.append("SQL injection confirmation requires injection-shaped exploit input")
    if not _new_response_marker(
        control,
        exploit,
        markers=_SQL_ERROR_MARKERS,
        exploit_request_text=exploit_material,
    ):
        failures.append(
            "SQL injection confirmation requires a new executor-observed database error"
        )
    return failures


def _ssti_replay_failures(
    control_raw: Mapping[str, object],
    control: Mapping[str, object],
    exploit_raw: Mapping[str, object],
    exploit: Mapping[str, object],
) -> list[str]:
    failures: list[str] = []
    control_material = _decoded_replay_request_text(control_raw)
    exploit_material = _decoded_replay_request_text(exploit_raw)
    computed = _template_expression_result(exploit_material)
    control_body = _response_body_snippet(control)
    exploit_body = _response_body_snippet(exploit)
    if not computed or _template_expression_result(control_material):
        failures.append("SSTI confirmation requires a bounded arithmetic template expression")
    elif computed in exploit_material or computed in control_body or computed not in exploit_body:
        failures.append(
            "SSTI confirmation requires the executor-derived expression result only in "
            "the exploit response"
        )
    return failures


def _path_traversal_replay_failures(
    control_raw: Mapping[str, object],
    control: Mapping[str, object],
    exploit_raw: Mapping[str, object],
    exploit: Mapping[str, object],
) -> list[str]:
    failures: list[str] = []
    control_material = _decoded_replay_request_text(control_raw).lower()
    exploit_material = _decoded_replay_request_text(exploit_raw).lower()
    control_markers = _traversal_input_markers(control_material)
    exploit_markers = _traversal_input_markers(exploit_material)
    if not exploit_markers.difference(control_markers):
        failures.append("file-read confirmation requires traversal-shaped exploit input")
    if not _new_response_marker(
        control,
        exploit,
        markers=_FILE_CONTENT_MARKERS,
        exploit_request_text=exploit_material,
    ):
        failures.append("file-read confirmation requires new executor-observed local-file content")
    return failures


def _decoded_replay_request_text(step: Mapping[str, object]) -> str:
    parts = [str(step.get("url") or ""), str(step.get("body") or "")]
    form = step.get("form")
    if isinstance(form, Mapping):
        parts.extend(f"{name}={value}" for name, value in form.items())
    return unquote_plus("\n".join(parts))


def _sql_injection_input_markers(value: str) -> frozenset[str]:
    markers: set[str] = set()
    patterns = {
        "union_select": r"\bunion\s+(?:all\s+)?select\b",
        "boolean_predicate": r"\b(?:or|and)\s+['\"\d]+\s*=\s*['\"\d]+",
        "time_function": r"\b(?:sleep|benchmark|pg_sleep)\s*\(",
        "sql_comment": r"--|/\*",
    }
    for name, pattern in patterns.items():
        if re.search(pattern, value, flags=re.IGNORECASE):
            markers.add(name)
    if "'" in value or '"' in value:
        markers.add("quote")
    return frozenset(markers)


def _traversal_input_markers(value: str) -> frozenset[str]:
    markers: set[str] = set()
    for name, marker in {
        "parent_slash": "../",
        "parent_backslash": "..\\",
        "unix_password_file": "/etc/passwd",
        "windows_ini_file": "win.ini",
        "file_scheme": "file://",
    }.items():
        if marker in value:
            markers.add(name)
    return frozenset(markers)


def _new_response_marker(
    control: Mapping[str, object],
    exploit: Mapping[str, object],
    *,
    markers: tuple[str, ...],
    exploit_request_text: str = "",
) -> bool:
    control_body = _response_body_snippet(control).lower()
    exploit_body = _response_body_snippet(exploit).lower()
    request_text = exploit_request_text.lower()
    return any(
        marker in exploit_body and marker not in control_body and marker not in request_text
        for marker in markers
    )


def _response_body_snippet(step: Mapping[str, object]) -> str:
    response = _mapping(step.get("response"))
    return str(response.get("body_snippet") or "")


def _template_expression_result(value: str) -> str:
    match = _TEMPLATE_EXPRESSION_RE.search(value)
    if match is None:
        return ""
    left = int(match.group(1))
    right = int(match.group(3))
    operator = match.group(2)
    if operator == "+":
        result = left + right
    elif operator == "-":
        result = left - right
    elif operator == "*":
        result = left * right
    elif right:
        result = left // right
    else:
        return ""
    return str(result)


def _step_has_passed_expectation(step: Mapping[str, object]) -> bool:
    checks = step.get("checks")
    return isinstance(checks, list) and any(
        isinstance(check, Mapping) and check.get("passed") is True for check in checks
    )


def _same_replay_endpoint(
    control: Mapping[str, object],
    exploit: Mapping[str, object],
    *,
    target_url: str,
) -> bool:
    control_request = _mapping(control.get("request"))
    exploit_request = _mapping(exploit.get("request"))
    control_method = str(control_request.get("method") or "GET").upper()
    exploit_method = str(exploit_request.get("method") or "GET").upper()
    control_url = _canonical_endpoint_url(
        urljoin(target_url, str(control_request.get("url") or ""))
    )
    exploit_url = _canonical_endpoint_url(
        urljoin(target_url, str(exploit_request.get("url") or ""))
    )
    return bool(control_url and control_method == exploit_method and control_url == exploit_url)


def _replay_material(step: Mapping[str, object]) -> str:
    material = {
        key: step.get(key) for key in ("method", "url", "form", "body", "headers") if key in step
    }
    return json.dumps(material, sort_keys=True, default=str, separators=(",", ":"))


def _replay_input_shape(
    step: Mapping[str, object],
    *,
    target_url: str,
) -> tuple[str, ...]:
    names: set[str] = set()
    raw_url = urljoin(target_url, str(step.get("url") or ""))
    for name, _value in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True):
        names.add(f"query:{name}")
    form = step.get("form")
    if isinstance(form, Mapping):
        names.update(f"body:{name}" for name in form)
    if step.get("body") is not None:
        names.add("body:raw")
    headers = step.get("headers")
    if isinstance(headers, Mapping):
        names.update(f"header:{str(name).lower()}" for name in headers)
    return tuple(sorted(names))


def _security_relevant_response_delta(
    control: Mapping[str, object],
    exploit: Mapping[str, object],
) -> bool:
    control_response = _mapping(control.get("response"))
    exploit_response = _mapping(exploit.get("response"))
    if control_response.get("status") != exploit_response.get("status"):
        return True
    control_final = _canonical_endpoint_url(str(control_response.get("final_url") or ""))
    exploit_final = _canonical_endpoint_url(str(exploit_response.get("final_url") or ""))
    if control_final and exploit_final and control_final != exploit_final:
        return True
    body_changed = bool(
        control_response.get("body_sha_hint")
        and exploit_response.get("body_sha_hint")
        and control_response.get("body_sha_hint") != exploit_response.get("body_sha_hint")
    )
    return body_changed and _has_passed_contains_check(exploit)


def _has_passed_contains_check(step: Mapping[str, object]) -> bool:
    checks = step.get("checks")
    return isinstance(checks, list) and any(
        isinstance(check, Mapping)
        and check.get("kind") == "contains"
        and check.get("passed") is True
        for check in checks
    )


def _finding_endpoint(
    step: Mapping[str, object],
    *,
    action: Mapping[str, object],
    target_url: str,
) -> dict[str, object]:
    request = _mapping(step.get("request"))
    response = _mapping(step.get("response"))
    raw_url = str(response.get("url") or request.get("url") or "").strip()
    absolute_url = urljoin(target_url, raw_url)
    method = str(request.get("method") or response.get("method") or "GET").upper()
    index = _positive_step_index(step.get("index"))
    raw_step = _action_step(action, index=index)
    return {
        "method": method,
        "url": _canonical_endpoint_url(absolute_url),
        "params": _endpoint_params(absolute_url, raw_step=raw_step),
    }


def _validated_finding_input(
    action: Mapping[str, object],
    *,
    endpoint: Mapping[str, object],
    target_url: str,
) -> dict[str, object]:
    raw_parameters = endpoint.get("params")
    result: dict[str, object] = {
        "method": str(endpoint.get("method") or "GET"),
        "parameters": list(raw_parameters) if isinstance(raw_parameters, list) else [],
    }
    affected_parameters = _changed_replay_parameters(action, target_url=target_url)
    if affected_parameters:
        result["affected_parameters"] = affected_parameters
    return result


def _changed_replay_parameters(
    action: Mapping[str, object],
    *,
    target_url: str,
) -> list[dict[str, str]]:
    roles: dict[str, Mapping[str, object]] = {}
    raw_steps = action.get("steps")
    if not isinstance(raw_steps, list):
        return []
    for step in raw_steps[:12]:
        if not isinstance(step, Mapping):
            continue
        role = str(step.get("evidence_role") or "").strip().lower()
        if role in {"control", "exploit"} and role not in roles:
            roles[role] = step
    if set(roles) != {"control", "exploit"}:
        return []
    control = _replay_parameter_values(roles["control"], target_url=target_url)
    exploit = _replay_parameter_values(roles["exploit"], target_url=target_url)
    return [
        {"name": name, "location": location}
        for location, name in sorted(set(control) | set(exploit))
        if control.get((location, name)) != exploit.get((location, name))
    ][:32]


def _replay_parameter_values(
    step: Mapping[str, object],
    *,
    target_url: str,
) -> dict[tuple[str, str], tuple[str, ...]]:
    values: dict[tuple[str, str], list[str]] = {}
    raw_url = urljoin(target_url, str(step.get("url") or ""))
    for name, value in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True):
        values.setdefault(("query", name.strip()[:120]), []).append(value)
    form = step.get("form")
    if isinstance(form, Mapping):
        for name, value in form.items():
            values[("body", str(name).strip()[:120])] = [str(value)]
    if step.get("body") is not None:
        values[("body", "raw_body")] = [str(step.get("body"))]
    headers = step.get("headers")
    if isinstance(headers, Mapping):
        for name, value in headers.items():
            values[("header", str(name).strip().lower()[:120])] = [str(value)]
    return {
        key: tuple(items)
        for key, items in values.items()
        if key[1]
    }


def _finding_url_in_scope(url: str, *, target_url: str, audit: AuditStore) -> bool:
    scope = audit.scope
    if scope is None:
        return same_origin(target_url, url)
    return url_in_scope_entries(
        url,
        in_scope=scope.in_scope,
        out_of_scope=scope.out_of_scope,
    )


def _canonical_endpoint_url(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if scheme not in {"http", "https"} or hostname is None:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    host = hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 80 if scheme == "http" else 443
    authority = f"{host}:{port}" if port is not None and port != default_port else host
    return urlunsplit((scheme, authority, parsed.path or "/", "", ""))


def _endpoint_params(url: str, *, raw_step: Mapping[str, object]) -> list[dict[str, str]]:
    params: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        _append_endpoint_param(params, seen=seen, name=name, location="query")
    form = raw_step.get("form")
    if isinstance(form, Mapping):
        for name in form:
            _append_endpoint_param(params, seen=seen, name=str(name), location="body")
    return params[:32]


def _append_endpoint_param(
    params: list[dict[str, str]],
    *,
    seen: set[tuple[str, str]],
    name: str,
    location: str,
) -> None:
    clean_name = name.strip()[:120]
    key = (clean_name, location)
    if not clean_name or key in seen:
        return
    seen.add(key)
    params.append({"name": clean_name, "location": location})


def _positive_step_index(value: object) -> int:
    try:
        return max(1, int(str(value)))
    except (TypeError, ValueError):
        return 1


def _action_step(action: Mapping[str, object], *, index: int) -> Mapping[str, object]:
    steps = action.get("steps")
    if not isinstance(steps, list) or index > len(steps):
        return {}
    step = steps[index - 1]
    return step if isinstance(step, Mapping) else {}


def _finding_exploit_steps(
    validation: ValidationResult,
    *,
    action: Mapping[str, object],
) -> list[dict[str, str]]:
    steps: list[dict[str, str]] = []
    for step in validation.steps[:12]:
        request = _mapping(step.get("request"))
        response = _safe_validation_response(_mapping(step.get("response")))
        checks = step.get("checks")
        safe_checks = checks if isinstance(checks, list) else []
        item = {
            "http_request": _bounded_json(request),
            "response_snippet": _bounded_json(response),
            "indicator": _bounded_json(safe_checks),
        }
        raw_step = _action_step(action, index=_positive_step_index(step.get("index")))
        role = str(raw_step.get("evidence_role") or "").strip().lower()
        if role in {"control", "exploit"}:
            item["evidence_role"] = role
        steps.append(item)
    return steps


def _safe_validation_response(value: Mapping[str, object]) -> dict[str, object]:
    response = dict(value)
    response["headers"] = mask_headers(response.get("headers"))
    return response


def _bounded_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str)
    return encoded[:_MAX_FINDING_EVIDENCE_CHARS]


def _finding_id(
    *,
    engagement_id: UUID,
    finding: Mapping[str, str],
    endpoint: Mapping[str, object],
    finding_input: Mapping[str, object],
) -> str:
    identity_parts: dict[str, object] = {
        "vuln_class": finding.get("vuln_class"),
        "endpoint": endpoint,
    }
    affected_parameters = finding_input.get("affected_parameters")
    if isinstance(affected_parameters, list) and affected_parameters:
        identity_parts["affected_parameters"] = affected_parameters
    identity = json.dumps(
        identity_parts,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return str(uuid5(engagement_id, identity))


def _reject_finding(  # noqa: PLR0913
    *,
    finding: Mapping[str, str],
    failures: list[str],
    passed_checks: int,
    required_checks: int,
    result: ActionResult,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    action_id: str,
    source_observation_id: str,
) -> ActionResult:
    payload: dict[str, object] = {
        "vuln_class": finding.get("vuln_class", ""),
        "reason": "; ".join(dict.fromkeys(failures))[:_MAX_FINDING_TEXT_CHARS],
        "evidence_checks": {"passed": passed_checks, "required": required_checks},
        "evidence_kind": "http_poc_replay",
        "source_kind": "tool_validate_poc",
        "source_observation_id": source_observation_id,
        "action_id": action_id,
        "finding_record_path": str(workspace.events_path),
    }
    _record(
        audit,
        engagement_id,
        actor="agent",
        action="finding_rejected_no_evidence",
        payload=payload,
    )
    workspace.record_event(kind="finding_rejected_no_evidence", payload=payload)
    return replace(
        result,
        ok=False,
        observation=json.dumps(payload, sort_keys=True),
        stop=False,
        outcome="blocked",
    )


def _mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, Mapping) else {}


def _capture_has_observed_evidence(
    flag: str,
    *,
    state: AgentState,
) -> bool:
    # Only the most recent executor-produced observation is admissible. Model-authored
    # evidence, hypotheses, facts, and signals cannot validate the model's own claim.
    observation_id = str(state.last_observation.get("observation_id") or "").strip()
    source_kind = str(state.last_observation.get("source_kind") or "").strip()
    if not observation_id or not source_kind.startswith("tool_"):
        return False
    recognized = state.last_observation.get("recognized_proofs")
    if not isinstance(recognized, list):
        return False
    return flag in {item for item in recognized if isinstance(item, str)}


def _capture_provenance(
    *,
    state: AgentState,
    capture_method: str,
) -> dict[str, str]:
    observation_id = str(state.last_observation.get("observation_id") or "").strip()
    source_kind = str(state.last_observation.get("source_kind") or "").strip()
    if not observation_id or not source_kind.startswith("tool_"):
        return {}
    return {
        "recognizer": _EXECUTOR_TOOL_RECOGNIZER,
        "capture_method": capture_method,
        "source_observation_id": observation_id,
        "source_kind": source_kind,
    }


def _looks_like_placeholder_flag(flag: str) -> bool:
    stripped = flag.strip()
    lowered = stripped.lower()
    if is_placeholder_proof(stripped):
        return True
    if recognize_proofs(flag):
        return False
    if lowered.startswith(("http://", "https://", "www.")):
        return True
    if lowered.startswith(("/", "./", "../")):
        return True
    if re.fullmatch(r"[a-z][a-z0-9+.-]*://.+", lowered):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.-]+:[^\s/]+", stripped):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.-]+=[^\s]+", stripped):
        return True
    if "ravage" in lowered or "xssexec" in lowered:
        return True
    if lowered.startswith(("canary", "marker", "token_")):
        return True
    if lowered in {"flag", "ctf", "proof", "secret", "token", "admin"}:
        return True
    if len(flag.strip()) < 8 and "{" not in flag:
        return True
    return False


def _record_tool_result(  # noqa: PLR0913
    result: ToolResult,
    *,
    kind: str,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    proof_recognition_enabled: bool,
    action_id: str = "",
    repeat_count: int,
    max_observation_chars: int,
    max_transcript_chars: int,
) -> ActionResult:
    observation_id = str(uuid.uuid4())
    proof_text = _tool_proof_text(result)
    # Process actions are model-authored and may echo arbitrary text. Preserve
    # the established single-proof evidence boundary for each observation.
    recognized_proofs = recognize_proofs(proof_text)[:1]
    payload = _tool_result_payload(
        result,
        repeat_count=repeat_count,
        action_id=action_id,
        observation_id=observation_id,
        recognized_proofs=recognized_proofs,
    )
    _record_tool_payload(
        payload,
        kind=kind,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
    )

    tool_text = _tool_text(result, max_chars=max_transcript_chars)
    _record_tool_observation(
        tool_text,
        state=state,
        workspace=workspace,
        observation_id=observation_id,
        source_kind=kind,
        recognized_proofs=recognized_proofs,
    )

    known_proof_replayed = _only_known_auto_capture_proofs(
        proof_text,
        enabled=proof_recognition_enabled,
        state=state,
        recognized_proofs=recognized_proofs,
    )
    found = _capture_recognized_proof(
        proof_text,
        enabled=proof_recognition_enabled,
        state=state,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
        evidence="tool output",
        action_id=action_id,
        recognized_proofs=recognized_proofs,
    )

    outcome = classify_action_result(
        ok=result.ok,
        repeat_count=repeat_count,
        text=tool_text,
        trusted_target_evidence=False,
    )
    if found:
        outcome = "flag_candidate"
    elif known_proof_replayed and outcome == "observed":
        outcome = "same_as_before"

    model_tool_text = _tool_text(result, max_chars=max_observation_chars)
    return _action_result_from_observation(
        ok=result.ok,
        repeat_count=repeat_count,
        text=model_tool_text,
        max_observation_chars=max_observation_chars,
        outcome=outcome,
        stop=bool(found),
        flag=found,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        evidence_source_kind=kind,
        evidence_observation=tool_text,
    )


def _tool_result_payload(
    result: ToolResult,
    *,
    repeat_count: int,
    action_id: str,
    observation_id: str,
    recognized_proofs: list[str],
) -> dict[str, object]:
    payload = result.to_json()
    payload["repeat_count"] = repeat_count
    payload["action_id"] = action_id
    payload["observation_id"] = observation_id
    payload["recognized_proofs"] = recognized_proofs
    return payload


def _record_tool_payload(
    payload: dict[str, object],
    *,
    kind: str,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
) -> None:
    _record(audit, engagement_id, actor="tool", action=kind, payload=payload)
    workspace.record_event(kind=kind, payload=payload)


def _record_tool_observation(  # noqa: PLR0913
    text: str,
    *,
    state: AgentState,
    workspace: AgentWorkspace,
    observation_id: str,
    source_kind: str,
    recognized_proofs: list[str],
) -> None:
    state.last_observation = _observation_digest_with_source(
        text,
        observation_id=observation_id,
        source_kind=source_kind,
        recognized_proofs=recognized_proofs,
    )
    workspace.record_transcript(role="tool", content=text)
    merge_signals(state, extract_signals(text))


def _tool_proof_text(result: ToolResult) -> str:
    parts: list[str] = []
    if result.stdout:
        parts.append(result.stdout)
    if result.stderr:
        parts.append(result.stderr)
    return "\n".join(parts)


def record_probe_result(  # noqa: PLR0913
    text: str,
    *,
    ok: bool,
    kind: str,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    proof_recognition_enabled: bool,
    action_id: str = "",
    repeat_count: int,
    timed_out: bool,
    max_observation_chars: int,
    max_transcript_chars: int,
    session_mode: str = "",
    authentication: ManagedAttackAuthentication | None = None,
) -> ActionResult:
    observation_id = str(uuid.uuid4())
    recognized_proofs = _probe_recognized_proofs(
        text,
        kind=kind,
        authentication=authentication,
        known_proofs=state.flags,
    )
    if kind == "tool_run_probe":
        _ingest_probe_surface_graph(
            text,
            state=state,
            identity_alias=_probe_identity_alias(session_mode),
            source_observation_id=observation_id,
        )
    clipped = _clip_probe_text(text, max_chars=max_transcript_chars)
    payload = {
        "ok": ok,
        "repeat_count": repeat_count,
        "result": clipped,
        "display_summary": _probe_display_summary(text),
        "timed_out": timed_out,
        "action_id": action_id,
        "observation_id": observation_id,
        "recognized_proofs": recognized_proofs,
    }
    if session_mode:
        payload["session_mode"] = session_mode
    _record(audit, engagement_id, actor="tool", action=kind, payload=payload)
    workspace.record_event(kind=kind, payload=payload)
    workspace.record_transcript(role="tool", content=clipped)
    state.last_observation = _observation_digest_with_source(
        clipped,
        observation_id=observation_id,
        source_kind=kind,
        recognized_proofs=recognized_proofs,
    )
    merge_signals(state, extract_signals(text))
    known_proof_replayed = _only_known_auto_capture_proofs(
        text,
        enabled=proof_recognition_enabled,
        state=state,
        recognized_proofs=recognized_proofs,
    )
    found = _capture_recognized_proof(
        text,
        enabled=proof_recognition_enabled,
        state=state,
        workspace=workspace,
        audit=audit,
        engagement_id=engagement_id,
        evidence=kind,
        action_id=action_id,
        recognized_proofs=recognized_proofs,
    )
    outcome = classify_action_result(
        ok=ok,
        repeat_count=repeat_count,
        text=clipped,
        trusted_target_evidence=kind in {"tool_run_probe", "tool_validate_poc"},
    )
    if known_proof_replayed and not found and outcome == "observed":
        outcome = "same_as_before"
    return _action_result_from_observation(
        ok=ok,
        repeat_count=repeat_count,
        text=clipped,
        max_observation_chars=max_observation_chars,
        outcome="flag_candidate" if found else outcome,
        stop=bool(found),
        flag=found,
        timed_out=timed_out,
        evidence_source_kind=kind,
        evidence_observation=text,
        session_mode=session_mode,
    )


# Compatibility alias for focused tests and older internal imports. Keeping a
# single implementation makes probe provenance identical across agent and scan
# entry points.
_record_probe_result = record_probe_result


def _ingest_probe_surface_graph(
    text: str,
    *,
    state: AgentState,
    identity_alias: str,
    source_observation_id: str,
) -> None:
    payload = _json_object(text)
    if not payload:
        return
    ingest_probe_result(
        state.surface_graph,
        payload,
        identity_alias=identity_alias,
        source_observation_id=source_observation_id,
    )
    state.surface = project_surface_graph(state.surface_graph, state.surface)


def _probe_identity_alias(session_mode: str) -> str:
    prefix = "identity:"
    if session_mode.startswith(prefix):
        return session_mode.removeprefix(prefix).strip() or "authenticated"
    return "anonymous"


def _probe_display_summary(text: str) -> dict[str, object]:
    value = _json_object(text)
    if not value:
        return {}

    summary: dict[str, object] = {}
    probe = _bounded_string(value.get("probe"), limit=_MAX_DISPLAY_NAME_CHARS)
    description = _bounded_string(value.get("summary"), limit=_MAX_DISPLAY_SUMMARY_CHARS)
    if probe:
        summary["probe"] = probe
    if description:
        summary["summary"] = description

    for key in ("findings", "requests", "errors"):
        items = value.get(key)
        if isinstance(items, list):
            summary[key] = len(items)
    finding_types = _probe_finding_types(value.get("findings"))
    if finding_types:
        summary["finding_types"] = finding_types
    return summary


def _json_object(text: str) -> dict[str, object]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _bounded_string(value: object, *, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else ""


def _probe_finding_types(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    finding_types: list[str] = []
    for finding in value:
        if not isinstance(finding, dict):
            continue
        clean_type = _bounded_string(
            finding.get("type"),
            limit=_MAX_DISPLAY_NAME_CHARS,
        )
        if clean_type and clean_type not in finding_types:
            finding_types.append(clean_type)
        if len(finding_types) == _MAX_DISPLAY_FINDING_TYPES:
            break
    return finding_types


def _clip_probe_text(text: str, *, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 80:
        return text[:max_chars]
    marker = "\n...[truncated from middle]...\n"
    keep = max_chars - len(marker)
    if keep <= 0:
        return text[:max_chars]
    head_chars = max(1, (keep * 2) // 3)
    tail_chars = keep - head_chars
    return text[:head_chars] + marker + text[-tail_chars:]


def _action_result_from_observation(
    *,
    ok: bool,
    repeat_count: int,
    text: str,
    max_observation_chars: int,
    outcome: str,
    stop: bool,
    flag: str,
    exit_code: int | None = None,
    timed_out: bool = False,
    evidence_source_kind: str = "",
    evidence_observation: str = "",
    session_mode: str = "",
) -> ActionResult:
    return ActionResult(
        ok=ok,
        exit_code=exit_code,
        timed_out=timed_out,
        repeat_count=repeat_count,
        observation=text[-max_observation_chars:],
        outcome=outcome,
        stop=stop,
        flag=flag,
        session_mode=session_mode,
        evidence_source_kind=evidence_source_kind,
        evidence_observation=evidence_observation,
    )


def _capture_recognized_proof(
    text: str,
    *,
    enabled: bool,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    evidence: str,
    action_id: str = "",
    recognized_proofs: Sequence[str] | None = None,
) -> str:
    if not enabled:
        return ""
    first_captured = ""
    for proof in _auto_capture_proofs(text, recognized_proofs=recognized_proofs):
        if proof in state.flags:
            continue
        state.flags.append(proof)
        payload = {
            "flag": proof,
            "evidence": evidence,
            "flag_record_path": str(workspace.events_path),
        }
        if action_id:
            payload["action_id"] = action_id
        payload.update(_capture_provenance(state=state, capture_method="automatic"))
        _record(audit, engagement_id, actor="agent", action="flag_captured", payload=payload)
        workspace.record_event(kind="flag_captured", payload=payload)
        if not first_captured:
            first_captured = proof
    return first_captured


def _only_known_auto_capture_proofs(
    text: str,
    *,
    enabled: bool,
    state: AgentState,
    recognized_proofs: Sequence[str] | None = None,
) -> bool:
    if not enabled:
        return False
    candidates = _auto_capture_proofs(text, recognized_proofs=recognized_proofs)
    return bool(candidates) and all(proof in state.flags for proof in candidates)


def _auto_capture_proofs(
    text: str,
    *,
    recognized_proofs: Sequence[str] | None = None,
) -> list[str]:
    candidates = recognize_proofs(text) if recognized_proofs is None else recognized_proofs
    return [proof for proof in candidates if _auto_capture_proof_has_prefix(proof)]


def _authentication_safe_proofs(
    text: str,
    *,
    authentication: ManagedAttackAuthentication | None,
) -> list[str]:
    candidates = recognize_proofs(text)
    if authentication is None:
        return candidates
    return [proof for proof in candidates if not authentication.contains_secret(proof)]


def _probe_recognized_proofs(
    text: str,
    *,
    kind: str,
    authentication: ManagedAttackAuthentication | None,
    known_proofs: Sequence[str],
) -> list[str]:
    candidates = _authentication_safe_proofs(text, authentication=authentication)
    if len(candidates) <= 1:
        return candidates
    if kind == "tool_run_probe":
        explicit = set(_structured_finding_proofs(text))
        if explicit:
            return [proof for proof in candidates if proof in explicit]
    # Broad native transcripts and PoC summaries can include incidental proof-like
    # strings. Admit one per observation, preferring a genuinely novel target proof
    # so an earlier known token cannot hide later evidence.
    known = {str(proof) for proof in known_proofs}
    return [next((proof for proof in candidates if proof not in known), candidates[0])]


def _structured_finding_proofs(text: str) -> list[str]:
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return []
    if not isinstance(payload, Mapping):
        return []
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []
    proofs: list[str] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        for key in ("proof", "proofs"):
            value = finding.get(key)
            for proof in recognize_proofs(json.dumps(value, sort_keys=True, default=str)):
                if proof not in proofs:
                    proofs.append(proof)
    return proofs


def _observation_digest_with_source(
    text: str,
    *,
    observation_id: str,
    source_kind: str,
    recognized_proofs: list[str],
) -> dict[str, Any]:
    digest = observation_digest(text)
    digest["observation_id"] = observation_id
    digest["source_kind"] = source_kind
    digest["recognized_proofs"] = recognized_proofs
    return digest


def _auto_capture_proof_has_prefix(proof: str) -> bool:
    return bool(re.match(r"(?i)^(?:[A-Za-z0-9_-]*flag|htb|ctf|xben)\{", proof.strip()))


def _tool_text(result: ToolResult, *, max_chars: int) -> str:
    def render(content_budget: int) -> str:
        evidence_budget = (content_budget * 3) // 4
        evidence = {
            "stdout": (result.stdout, 4),
            "stderr": (result.stderr, 3),
            "error": (result.error or "", 2),
        }
        active_weight = sum(weight for value, weight in evidence.values() if value)
        budgets = {
            key: (evidence_budget * weight) // active_weight if value and active_weight else 0
            for key, (value, weight) in evidence.items()
        }
        payload = {
            "stdout": _clip_probe_text(result.stdout, max_chars=budgets["stdout"]),
            "stderr": _clip_probe_text(result.stderr, max_chars=budgets["stderr"]),
            "error": (
                _clip_probe_text(result.error, max_chars=budgets["error"])
                if result.error is not None
                else None
            ),
            "ok": result.ok,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "tool": result.tool,
            "action": result.action or result.tool,
            "command": _bounded_tool_command(
                result.command,
                max_chars=content_budget - evidence_budget,
            ),
        }
        return json.dumps(payload, indent=2)

    empty = render(0)
    if len(empty) > max_chars:
        return _clip_probe_text(empty, max_chars=max_chars)

    best = empty
    low = 1
    high = max(0, max_chars)
    while low <= high:
        content_budget = (low + high) // 2
        candidate = render(content_budget)
        if len(candidate) <= max_chars:
            best = candidate
            low = content_budget + 1
        else:
            high = content_budget - 1
    return best


def _bounded_tool_command(command: Sequence[str], *, max_chars: int) -> list[str]:
    items = list(command)
    if len(json.dumps(items)) <= max_chars:
        return items
    empty_string_list_chars = len(json.dumps([""]))
    if max_chars <= empty_string_list_chars:
        return []
    return [
        _clip_probe_text(
            "\n".join(items),
            max_chars=max_chars - empty_string_list_chars,
        )
    ]


def _run_authenticated_probe_action(
    probe: str,
    *,
    target_url: str,
    state: AgentState,
    timeout_seconds: int,
    authentication: ManagedAttackAuthentication,
    use_managed_identity: bool,
    traffic_policy: TrafficPolicyController | None = None,
) -> _ProbeActionResult:
    session: ProbeSession | None = None
    session_mode = (
        f"identity:{authentication.identity}"
        if use_managed_identity
        else "anonymous:probe-required"
    )
    try:
        session = (
            authentication.session_for_probe(timeout_seconds=timeout_seconds)
            if use_managed_identity
            else None
        )
        result = run_builtin_probe(
            probe,
            target_url=target_url,
            state=state,
            timeout_seconds=timeout_seconds,
            allow_remote_target=state.surface.get("allow_remote_target") is True,
            in_scope=_surface_string_list(state, "scope_in_scope"),
            out_of_scope=_surface_string_list(state, "scope_out_of_scope"),
            max_rps=_surface_int(state, "scope_max_rps"),
            session=session,
            traffic_policy=(traffic_policy if not use_managed_identity else None),
        )
    except AuthenticationError:
        raise
    except Exception as exc:  # noqa: BLE001 - match anonymous probe failure behavior.
        raw_error = str(exc)
        safe_error = (
            "probe execution failed"
            if authentication.contains_secret(raw_error)
            else authentication.redact_text(raw_error)
        )
        payload = _authenticated_mapping(
            authentication.redact(
                json.loads(
                    _probe_failure_text(
                        probe=probe,
                        summary="authenticated probe failed",
                        errors=[safe_error or "probe execution failed"],
                    )
                )
            )
        )
        payload["session_mode"] = session_mode
        payload["request_policy"] = (
            "managed_identity_with_trusted_probe_controls"
            if use_managed_identity
            else "deliberate_anonymous_boundary"
        )
        return _ProbeActionResult(
            text=json.dumps(payload, indent=2, sort_keys=True),
            ok=False,
        )
    finally:
        if session is not None:
            authentication.retire_probe_session(session)
    payload = _authenticated_mapping(authentication.redact(json.loads(result.to_text())))
    payload["session_mode"] = session_mode
    payload["request_policy"] = (
        "managed_identity_with_trusted_probe_controls"
        if use_managed_identity
        else "deliberate_anonymous_boundary"
    )
    return _ProbeActionResult(text=json.dumps(payload, indent=2, sort_keys=True), ok=result.ok)


def _run_probe_action(
    probe: str,
    *,
    target_url: str,
    state: AgentState,
    timeout_seconds: int,
    traffic_policy_reference: dict[str, object] | None = None,
) -> _ProbeActionResult:
    try:
        return _run_probe_with_wall_clock(
            probe,
            target_url=target_url,
            state=state,
            timeout_seconds=timeout_seconds,
            traffic_policy_reference=traffic_policy_reference,
        )
    except ProbeExecutionTimeout as exc:
        return _ProbeActionResult(
            text=_probe_failure_text(
                probe=probe,
                summary=f"probe timed out after {timeout_seconds}s request timeout and wall-clock guard",
                errors=[str(exc)],
            ),
            ok=False,
            timed_out=True,
        )
    except Exception as exc:  # noqa: BLE001
        return _ProbeActionResult(
            text=_probe_failure_text(
                probe=probe,
                summary="probe raised an exception before producing observations",
                errors=[f"{type(exc).__name__}: {exc}"],
            ),
            ok=False,
        )


def _run_probe_with_wall_clock(
    probe: str,
    *,
    target_url: str,
    state: AgentState,
    timeout_seconds: int,
    traffic_policy_reference: dict[str, object] | None = None,
) -> _ProbeActionResult:
    wall_timeout = _probe_wall_timeout(timeout_seconds, probe=probe)
    request = json.dumps(
        {
            "probe": probe,
            "target_url": target_url,
            "state": state.to_json(),
            "timeout_seconds": timeout_seconds,
            "allow_remote_target": state.surface.get("allow_remote_target") is True,
            "in_scope": _surface_string_list(state, "scope_in_scope"),
            "out_of_scope": _surface_string_list(state, "scope_out_of_scope"),
            "max_rps": _surface_int(state, "scope_max_rps"),
            "traffic_policy_reference": traffic_policy_reference,
        },
        sort_keys=True,
    )
    try:
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "ravage.probe_runner"],
            input=request,
            capture_output=True,
            text=True,
            timeout=wall_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeExecutionTimeout(
            f"run_probe {probe} exceeded {wall_timeout}s wall-clock limit"
        ) from exc
    payload = _decode_probe_runner_payload(
        completed.stdout, stderr=completed.stderr, returncode=completed.returncode
    )
    if payload.get("status") == "ok":
        return _ProbeActionResult(
            text=str(payload.get("text") or ""),
            ok=bool(payload.get("ok")),
        )
    return _ProbeActionResult(
        text=_probe_failure_text(
            probe=probe,
            summary="probe raised an exception before producing observations",
            errors=[str(payload.get("error") or "probe runner failed")],
        ),
        ok=False,
    )


def _probe_failure_text(*, probe: str, summary: str, errors: list[str]) -> str:
    payload = {
        "errors": errors,
        "findings": [],
        "ok": False,
        "probe": probe,
        "summary": summary,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _decode_probe_runner_payload(stdout: str, *, stderr: str, returncode: int) -> dict[str, object]:
    if not stdout.strip():
        return {
            "status": "error",
            "error": f"probe runner exited with code {returncode}: {stderr[-1000:]}",
        }
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {
            "status": "error",
            "error": f"probe runner returned invalid JSON: {exc}; stderr={stderr[-1000:]}",
        }
    if isinstance(payload, dict):
        decoded: dict[str, object] = {}
        for key, value in payload.items():
            decoded[str(key)] = value
        return decoded
    return {
        "status": "error",
        "error": "probe runner returned non-object JSON",
    }


_EXTRACTION_PROBES = frozenset(
    {
        "sqli_exploit",
        "file_read_extract",
        "file_fetch_parser",
        "direct_exposure",
        "cookie_deserialization",
        "csrf_session",
        "browser_boundary",
        "jwt_exploit",
        "graphql_exploit",
        "werkzeug_console",
        "command_boundary",
        "ssti_fingerprint",
        "ssrf_boundary",
        "xxe_boundary",
        "preg_match_subject",
    }
)


def _probe_wall_timeout(timeout_seconds: int, probe: str = "") -> int:
    if probe in _EXTRACTION_PROBES:
        floor = 30
    else:
        floor = 10
    return max(floor, min((timeout_seconds * 3) + 5, 45))


def _timeout(value: object) -> int | None:
    if value is None:
        return None
    try:
        return max(3, min(int(str(value)), 120))
    except ValueError:
        return None


def _surface_string_list(state: AgentState, key: str) -> list[str]:
    value = state.surface.get(key)
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _surface_int(state: AgentState, key: str) -> int | None:
    value = state.surface.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


_COMMAND_TIMEOUT_FLOOR_SECONDS = 10


def _command_timeout(value: object) -> int:
    resolved = _timeout(value)
    return max(_COMMAND_TIMEOUT_FLOOR_SECONDS, resolved or _COMMAND_TIMEOUT_FLOOR_SECONDS)
