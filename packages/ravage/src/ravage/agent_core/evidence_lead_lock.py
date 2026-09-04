from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, unquote, urlsplit

from ravage.agent_core.semantic_routes import semantic_action_route
from ravage.outcome_evidence import (
    OutcomeStage,
    QualifiedProbeFinding,
    outcome_stage_rank,
    qualify_probe_findings,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_SURFACE_KEY = "evidence_lead_lock"
_REPLAY_GENERATION_KEY = "evidence_lead_replay_generation"
_STATE_VERSION = 2
_MAX_ALIGNED_NO_PROGRESS = 2
_MAX_VALIDATION_STEPS = 12
_MAX_REQUEST_INPUTS = 32
_MAX_REFERENCE_LENGTH = 160
_QUALIFICATION_ORIGIN = "http://lead-lock.invalid/"
_ACTIVE = "active"
_AWAITING_SESSION = "awaiting_session"
_RESOLVED = "resolved"
_REJECTED = "rejected"
_EXHAUSTED = "exhausted"
_ALLOWED_ACTIONS = frozenset({"capture_flag", "http_request", "validate_poc"})
_NON_ATTEMPT_OUTCOMES = frozenset(
    {
        "blocked",
        "policy_blocked",
        "same_as_before",
        "timeout",
        "timed_out",
    }
)
_CONFIRMED_OUTCOMES = frozenset(
    {
        "flag_candidate",
        "flag_captured",
        "proof_confirmed",
    }
)
_REJECTED_OUTCOMES = frozenset({"hypothesis_disproved", "lead_rejected"})
_AUTH_FAMILIES = frozenset({"auth", "authentication", "authorization_session"})
_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
_INPUT_LOCATIONS = frozenset({"body", "query"})
_AFFECTED_INPUT_LOCATIONS = frozenset({"body", "query"})
_BODY_ENCODINGS = frozenset({"form", "json", "none", "raw"})
_INPUT_RE = re.compile(r"^[A-Za-z0-9_.\[\]:-]{1,120}$")
_FAMILY_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_FAMILY_ALIASES = {
    "arbitrary_file_read": "path_traversal",
    "file_read": "path_traversal",
    "idor": "object_authorization",
    "lfi": "path_traversal",
    "server_side_template_injection": "template_injection",
    "sqli": "sql_injection",
    "ssrf": "server_side_request_forgery",
    "ssti": "template_injection",
    "xss": "cross_site_scripting",
    "xxe": "xml_external_entity",
}


@dataclass(frozen=True, slots=True)
class EvidenceLead:
    """Secret-free, executor-owned route that remains locked until disposition."""

    fingerprint: str
    family: str
    probe: str
    finding_type: str
    method: str
    origin: str
    endpoint: str
    inputs: tuple[str, ...]
    input_locations: tuple[tuple[str, str], ...]
    request_inputs: tuple[tuple[str, str], ...]
    body_encoding: str
    source_kind: str
    source_observation_id: str
    stage: str
    aligned_no_progress: int = 0
    status: str = _ACTIVE

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "fingerprint": self.fingerprint,
            "family": self.family,
            "probe": self.probe,
            "finding_type": self.finding_type,
            "method": self.method,
            "origin": self.origin,
            "endpoint": self.endpoint,
            "inputs": list(self.inputs),
            "input_locations": _input_specs_json(self.input_locations),
            "request_inputs": _input_specs_json(self.request_inputs),
            "body_encoding": self.body_encoding,
            "source_kind": self.source_kind,
            "source_observation_id": self.source_observation_id,
            "stage": self.stage,
            "aligned_no_progress": self.aligned_no_progress,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class _DispatchShape:
    declared_method: str
    method: str
    origin: str
    endpoint: str
    inputs: tuple[tuple[str, str], ...]
    body_encoding: str


def remember_from_probe_result(
    state: AgentState,
    text: str,
    action: Mapping[str, object],
    source_observation_id: str,
) -> EvidenceLead | None:
    """
    Persist a trusted material lead, refusing untyped or auth-only observations.

    The caller owns provenance: ``source_observation_id`` must identify the
    executor observation associated with ``text``. This function additionally
    requires either a valid native ``run_probe`` result or the executor's final
    confirmed-finding payload for ``validate_poc``.
    """
    observation_id = _safe_reference(source_observation_id)
    if not observation_id:
        return None
    kind = str(action.get("action") or "")
    if kind == "run_probe":
        candidate = _lead_from_native_probe(
            text=text,
            action=action,
            source_observation_id=observation_id,
        )
    elif kind == "validate_poc":
        candidate = _lead_from_confirmed_validate_poc(
            text=text,
            action=action,
            source_observation_id=observation_id,
        )
    else:
        # Raw HTTP and Python/shell output are observations, not typed findings.
        return None
    if candidate is None:
        return None

    current = _stored_lead(state)
    if current is not None and current.status in {_ACTIVE, _AWAITING_SESSION}:
        # A later observation cannot silently preempt an unresolved exact route.
        return current
    state.surface[_SURFACE_KEY] = candidate.to_json()
    return candidate


def pending_lead(state: AgentState) -> EvidenceLead | None:
    """Return the active persisted lead, failing closed on malformed state."""
    lead = unresolved_lead(state)
    if lead is None or lead.status != _ACTIVE:
        return None
    return lead


def awaiting_session_lead(state: AgentState) -> EvidenceLead | None:
    """Return an auth-paused lead without treating it as an exact replay lock."""
    lead = unresolved_lead(state)
    if lead is None or lead.status != _AWAITING_SESSION:
        return None
    return lead


def unresolved_lead(state: AgentState) -> EvidenceLead | None:
    """Return an active or auth-paused persisted lead, failing closed."""
    lead = _stored_lead(state)
    if lead is None or lead.status not in {_ACTIVE, _AWAITING_SESSION}:
        return None
    return lead


def release_for_session_reset(state: AgentState) -> EvidenceLead | None:
    """Release a lead whose in-memory request session cannot be resumed."""
    lead = _stored_lead(state)
    if lead is None or lead.status not in {_ACTIVE, _AWAITING_SESSION}:
        return None
    released = replace(lead, status=_EXHAUSTED)
    payload = released.to_json()
    payload["release_reason"] = "http_session_reset"
    state.surface[_SURFACE_KEY] = payload
    return released


def reactivate_for_session_change(state: AgentState) -> EvidenceLead | None:
    """Reactivate an auth-paused lead after the persistent lane gains a session."""
    lead = _stored_lead(state)
    if lead is None or lead.status != _AWAITING_SESSION:
        return None
    return _reactivate_lead(state, lead)


def lead_replay_generation(state: AgentState) -> int:
    """Return the secret-free generation for a genuinely reactivated lead."""
    value = state.surface.get(_REPLAY_GENERATION_KEY)
    if not isinstance(value, int) or isinstance(value, bool):
        return 0
    return max(0, value)


def action_matches_lead(
    action: Mapping[str, object],
    lead: EvidenceLead,
    *,
    primary_origin: str = "",
) -> bool:
    """Require every physically dispatched request shape to align with the lead."""
    kind = str(action.get("action") or "")
    if kind not in _ALLOWED_ACTIONS:
        return False
    # The executor independently requires the exact proof to have appeared in
    # recent trusted target evidence. Let that strict closure action through.
    if kind == "capture_flag":
        return True
    route = semantic_action_route(action)
    action_family = _action_family(action, route=route)
    if lead.family and action_family != lead.family:
        return False
    dispatches = _action_dispatch_shapes(action)
    if not dispatches:
        return False
    return all(
        _dispatch_matches_lead(
            dispatch,
            lead,
            primary_origin=primary_origin,
        )
        for dispatch in dispatches
    )


def record_aligned_outcome(  # noqa: PLR0911 - explicit fail-closed lifecycle states.
    state: AgentState,
    action: Mapping[str, object],
    outcome: Mapping[str, object],
) -> EvidenceLead | None:
    """
    Record one aligned execution and return the lead if it remains pending.

    Request-boundary failures, timeouts, and deduplicated actions do not
    consume either of the two complete no-progress attempts. A ``validate_poc``
    result that contains a response for every aligned replay step does count,
    even when the executor rejects the finding claim built from those replies.
    """
    lead = _stored_lead(state)
    if lead is None or lead.status not in {_ACTIVE, _AWAITING_SESSION}:
        return None
    if not action_matches_lead(
        action,
        lead,
        primary_origin=state.surface_graph.target_origin,
    ):
        return lead if lead.status == _ACTIVE else None

    auth_status = _authentication_required_http_status(state, action, outcome)
    if auth_status is not None:
        waiting = replace(lead, status=_AWAITING_SESSION)
        payload = waiting.to_json()
        payload["pause_reason"] = "authentication_required"
        payload["response_status"] = auth_status
        state.surface[_SURFACE_KEY] = payload
        fact = (
            f"evidence route {lead.method} {lead.endpoint} paused after HTTP {auth_status}; "
            "establish authentication in the persistent http_request lane, then replay it"
        )
        if fact not in state.facts:
            state.facts.append(fact)
            del state.facts[:-80]
        return None
    outcome_name = str(outcome.get("outcome") or "").strip().lower()
    if _outcome_confirmed(outcome, outcome_name=outcome_name):
        _store(state, replace(lead, status=_RESOLVED))
        return None
    if outcome_name in _REJECTED_OUTCOMES:
        _store(state, replace(lead, status=_REJECTED))
        return None
    completed = (
        _complete_attempt(outcome, outcome_name=outcome_name)
        or _completed_validate_attempt(action, outcome)
    )
    if lead.status == _AWAITING_SESSION:
        if not completed:
            return None
        lead = _reactivate_lead(state, lead)
    if not completed:
        return lead

    count = lead.aligned_no_progress + 1
    status = _EXHAUSTED if count >= _MAX_ALIGNED_NO_PROGRESS else _ACTIVE
    updated = replace(lead, aligned_no_progress=count, status=status)
    _store(state, updated)
    return updated if status == _ACTIVE else None


def directive(state: AgentState) -> str:
    """Render concise prompt guidance for the active exact-route obligation."""
    lead = _stored_lead(state)
    if lead is None:
        return ""
    inputs = ", ".join(lead.inputs) if lead.inputs else "the observed request shape"
    if lead.status == _AWAITING_SESSION:
        return (
            f"Evidence route {lead.method} {lead.endpoint} is paused because its prior session "
            "was unavailable. Establish authentication in the persistent http_request lane; "
            "the exact route lock will reactivate when session state changes."
        )
    if lead.status != _ACTIVE:
        return ""
    remaining = _MAX_ALIGNED_NO_PROGRESS - lead.aligned_no_progress
    return (
        "Evidence lead lock active: continue "
        f"{lead.family} on {lead.method or 'the observed method'} "
        f"{lead.endpoint or 'the observed endpoint'} using {inputs}. "
        "Stay on this route until it yields the target proof or a typed rejection; "
        f"{remaining} complete aligned no-progress attempt(s) remain."
    )


def _lead_from_native_probe(
    *,
    text: str,
    action: Mapping[str, object],
    source_observation_id: str,
) -> EvidenceLead | None:
    probe = str(action.get("probe") or "").strip()
    if not probe:
        return None
    candidates = qualify_probe_findings(
        probe=probe,
        probe_text=text,
        target_url=_qualification_origin(action, text=text),
    )
    eligible = [item for item in candidates if _material_native_finding(item)]
    if not eligible:
        return None
    qualified = max(
        eligible,
        key=lambda item: (outcome_stage_rank(item.stage), item.finding_type),
    )
    raw_endpoint = str(qualified.endpoint.get("url") or "")
    endpoint = _normalize_endpoint(raw_endpoint)
    origin = _normalize_origin(raw_endpoint) or _normalize_origin(
        _qualification_origin(action, text=text)
    )
    method = _safe_method(qualified.endpoint.get("method") or qualified.request.get("method"))
    family = _normalize_family(qualified.contract.vuln_class)
    if not family or family in _AUTH_FAMILIES or not origin or not endpoint or not method:
        return None
    if _has_unmodelled_parameter(qualified.request.get("params")):
        return None
    native_shape, native_request_seen = _native_dispatch_shape(text, qualified)
    if native_request_seen and native_shape is None:
        return None
    request_inputs = (
        native_shape.inputs
        if native_shape is not None
        else _parameter_specs(qualified.request.get("params") or qualified.endpoint.get("params"))
    )
    input_locations = _qualified_affected_inputs(qualified) or request_inputs
    body_encoding = (
        native_shape.body_encoding
        if native_shape is not None
        else _native_body_encoding(text, qualified)
    )
    return _build_lead(
        family=family,
        probe=qualified.probe,
        finding_type=qualified.finding_type,
        method=method,
        origin=origin,
        endpoint=endpoint,
        input_locations=input_locations,
        request_inputs=request_inputs,
        body_encoding=body_encoding,
        source_kind="tool_run_probe",
        source_observation_id=source_observation_id,
        stage=qualified.stage.value,
    )


def _lead_from_confirmed_validate_poc(
    *,
    text: str,
    action: Mapping[str, object],
    source_observation_id: str,
) -> EvidenceLead | None:
    payload = _json_object(text)
    provenance = payload.get("provenance")
    provenance_map = provenance if isinstance(provenance, Mapping) else {}
    checks = payload.get("evidence_checks")
    check_map = checks if isinstance(checks, Mapping) else {}
    stage = str(payload.get("outcome_stage") or "")
    source_matches = (
        str(payload.get("source_kind") or "") == "tool_validate_poc"
        and str(payload.get("source_observation_id") or "") == source_observation_id
        and str(provenance_map.get("source_kind") or "") == "tool_validate_poc"
        and str(provenance_map.get("source_observation_id") or "") == source_observation_id
    )
    required = _nonnegative_int(check_map.get("required"))
    passed = _nonnegative_int(check_map.get("passed"))
    if not (
        payload.get("status") == "confirmed"
        and payload.get("validator_vote") == "confirm"
        and payload.get("assessment_source") == "executor_policy"
        and payload.get("evidence_kind") == "http_poc_replay"
        and provenance_map.get("model_claims_used") is False
        and source_matches
        and required >= 1
        and passed >= required
        and outcome_stage_rank(stage) >= outcome_stage_rank(OutcomeStage.VERIFIED_VULNERABILITY)
    ):
        return None

    endpoint_value = payload.get("endpoint")
    endpoint_map = endpoint_value if isinstance(endpoint_value, Mapping) else {}
    input_value = payload.get("input")
    input_map = input_value if isinstance(input_value, Mapping) else {}
    family = _normalize_family(payload.get("vuln_class"))
    raw_endpoint = str(endpoint_map.get("url") or "")
    endpoint = _normalize_endpoint(raw_endpoint)
    origin = _normalize_origin(raw_endpoint)
    method = _safe_method(endpoint_map.get("method") or input_map.get("method"))
    if any(
        _has_unmodelled_parameter(value)
        for value in (
            input_map.get("parameters"),
            input_map.get("affected_parameters"),
            endpoint_map.get("params"),
        )
    ):
        return None
    input_locations = _parameter_specs(input_map.get("affected_parameters"))
    dispatch = _validated_dispatch_shape(
        action,
        method=method,
        origin=origin,
        endpoint=endpoint,
    )
    if (
        not family
        or family in _AUTH_FAMILIES
        or not origin
        or not endpoint
        or not method
        or dispatch is None
    ):
        return None
    request_inputs = dispatch.inputs
    if not input_locations:
        input_locations = request_inputs
    body_encoding = dispatch.body_encoding
    finding_type = str(provenance_map.get("finding_type") or "confirmed_validate_poc")
    return _build_lead(
        family=family,
        probe=str(provenance_map.get("probe") or "validate_poc"),
        finding_type=finding_type,
        method=method,
        origin=origin,
        endpoint=endpoint,
        input_locations=input_locations,
        request_inputs=request_inputs,
        body_encoding=body_encoding,
        source_kind="tool_validate_poc",
        source_observation_id=source_observation_id,
        stage=stage,
    )


def _material_native_finding(finding: QualifiedProbeFinding) -> bool:
    verified_rank = outcome_stage_rank(OutcomeStage.VERIFIED_VULNERABILITY)
    return (
        finding.promotable
        and finding.contract_status == "registered"
        and outcome_stage_rank(finding.stage) >= verified_rank
        and _normalize_family(finding.contract.vuln_class) not in _AUTH_FAMILIES
    )


def _qualified_affected_inputs(
    finding: QualifiedProbeFinding,
) -> tuple[tuple[str, str], ...]:
    affected = finding.request.get("affected_parameter")
    if isinstance(affected, Mapping):
        return _parameter_specs([affected])
    return ()


def _parameter_specs(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        return ()
    specs = [
        (location, name)
        for item in value[:_MAX_REQUEST_INPUTS]
        if isinstance(item, Mapping)
        if (name := _safe_input(item.get("name")))
        if (location := _safe_input_location(item.get("location")))
    ]
    return tuple(sorted(specs))


def _has_unmodelled_parameter(value: object) -> bool:
    if not isinstance(value, list):
        return False
    return any(
        isinstance(item, Mapping)
        and str(item.get("location") or "").strip().casefold()
        not in _AFFECTED_INPUT_LOCATIONS
        for item in value[:_MAX_REQUEST_INPUTS]
    )


def _native_dispatch_shape(
    text: str,
    finding: QualifiedProbeFinding,
) -> tuple[_DispatchShape | None, bool]:
    payload = _json_object(text)
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        return None, False
    expected_method = _safe_method(
        finding.endpoint.get("method") or finding.request.get("method")
    )
    expected_endpoint = _normalize_endpoint(str(finding.endpoint.get("url") or ""))
    expected_origin = _normalize_origin(str(finding.endpoint.get("url") or ""))
    request_seen = False
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, Mapping):
            continue
        if str(raw_finding.get("type") or "") != finding.finding_type:
            continue
        for key in finding.contract.request_keys:
            raw_request = raw_finding.get(key)
            if not isinstance(raw_request, Mapping):
                continue
            request_seen = True
            request = _request_with_declared_encoding(raw_request)
            shape = _dispatch_shape(request, validator_step=False)
            if shape is None:
                continue
            if (
                shape.method == expected_method
                and shape.endpoint == expected_endpoint
                and (not shape.origin or not expected_origin or shape.origin == expected_origin)
            ):
                return shape, True
    return None, request_seen


def _request_with_declared_encoding(
    request: Mapping[str, object],
) -> dict[str, object]:
    prepared = dict(request)
    encoding = _encoding_label(request.get("encoding"))
    if encoding not in {"form", "json"} or _request_content_type(request):
        return prepared
    headers = request.get("headers")
    copied_headers = dict(headers) if isinstance(headers, Mapping) else {}
    copied_headers["Content-Type"] = (
        "application/x-www-form-urlencoded" if encoding == "form" else "application/json"
    )
    prepared["headers"] = copied_headers
    return prepared


def _native_body_encoding(  # noqa: C901 - typed native shapes vary by specialist.
    text: str,
    finding: QualifiedProbeFinding,
) -> str:
    payload = _json_object(text)
    raw_findings = payload.get("findings")
    if isinstance(raw_findings, list):
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                continue
            if str(raw_finding.get("type") or "") != finding.finding_type:
                continue
            for key in finding.contract.request_keys:
                request = raw_finding.get(key)
                if not isinstance(request, Mapping):
                    continue
                declared = _safe_method(request.get("method") or "GET")
                endpoint = _normalize_endpoint(str(request.get("url") or ""))
                if declared != str(finding.endpoint.get("method") or "").upper():
                    continue
                if endpoint != _normalize_endpoint(str(finding.endpoint.get("url") or "")):
                    continue
                encoding = _encoding_label(request.get("encoding"))
                if encoding:
                    return encoding
                inferred = _request_body_encoding(request, validator_step=False)
                if inferred:
                    return inferred
    encoding = _encoding_label(finding.request.get("encoding"))
    if encoding:
        return encoding
    request_inputs = _parameter_specs(
        finding.request.get("params") or finding.endpoint.get("params")
    )
    return "raw" if any(location == "body" for location, _name in request_inputs) else "none"


def _validated_dispatch_shape(
    action: Mapping[str, object],
    *,
    method: str,
    origin: str,
    endpoint: str,
) -> _DispatchShape | None:
    steps = action.get("steps")
    if not isinstance(steps, list):
        return None
    ordered = sorted(
        (step for step in steps if isinstance(step, Mapping)),
        key=lambda step: str(step.get("evidence_role") or "") != "exploit",
    )
    for step in ordered:
        shape = _dispatch_shape(step, validator_step=True)
        if shape is None:
            continue
        if (
            shape.method == method
            and shape.endpoint == endpoint
            and (not shape.origin or shape.origin == origin)
        ):
            return shape
    return None


def _encoding_label(value: object) -> str:
    label = str(value or "").strip().casefold()
    if label in _BODY_ENCODINGS:
        return label
    media_type = label.split(";", 1)[0].strip()
    if media_type == "application/x-www-form-urlencoded":
        return "form"
    if media_type == "application/json" or media_type.endswith("+json"):
        return "json"
    return ""


def _safe_body_encoding(
    value: object,
    *,
    request_inputs: tuple[tuple[str, str], ...],
) -> str:
    encoding = _encoding_label(value)
    if encoding:
        return encoding
    return "raw" if any(location == "body" for location, _name in request_inputs) else "none"


def _safe_input_location(value: object) -> str:
    location = str(value or "").strip().casefold()
    return location if location in _INPUT_LOCATIONS else ""


def _input_specs_json(specs: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
    return [{"location": location, "name": name} for location, name in specs]


def _build_lead(  # noqa: PLR0913
    *,
    family: str,
    probe: str,
    finding_type: str,
    method: str,
    origin: str,
    endpoint: str,
    input_locations: tuple[tuple[str, str], ...],
    request_inputs: tuple[tuple[str, str], ...],
    body_encoding: str,
    source_kind: str,
    source_observation_id: str,
    stage: str,
) -> EvidenceLead | None:
    affected = tuple(sorted(set(input_locations)))
    request_shape_items = list(request_inputs)
    request_shape_items.extend(item for item in affected if item not in request_shape_items)
    request_shape = tuple(sorted(request_shape_items))
    encoding = _safe_body_encoding(body_encoding, request_inputs=request_shape)
    if (
        not affected
        or len(request_shape) > _MAX_REQUEST_INPUTS
        or any(location not in _AFFECTED_INPUT_LOCATIONS for location, _name in affected)
        or any(name.startswith("path[") for _location, name in affected)
        or any(name == "raw_body" for _location, name in affected)
        or _is_structural_endpoint(endpoint)
        or encoding == "raw"
        or (
            any(location == "body" for location, _name in affected)
            and encoding not in {"form", "json"}
        )
    ):
        # The lock matcher mutates named query/form/JSON slots only. Header
        # names may constrain the exact request shape, but never become an
        # affected input because their values cannot be persisted safely.
        return None
    lead = EvidenceLead(
        fingerprint="",
        family=family,
        probe=probe,
        finding_type=finding_type,
        method=method,
        origin=origin,
        endpoint=endpoint,
        inputs=tuple(sorted({name for _location, name in affected})),
        input_locations=affected,
        request_inputs=request_shape,
        body_encoding=encoding,
        source_kind=source_kind,
        source_observation_id=source_observation_id,
        stage=stage,
    )
    return replace(lead, fingerprint=_lead_fingerprint(lead))


def _lead_fingerprint(lead: EvidenceLead) -> str:
    identity = {
        "family": lead.family,
        "probe": lead.probe,
        "finding_type": lead.finding_type,
        "method": lead.method,
        "origin": lead.origin,
        "endpoint": lead.endpoint,
        "inputs": list(lead.inputs),
        "input_locations": _input_specs_json(lead.input_locations),
        "request_inputs": _input_specs_json(lead.request_inputs),
        "body_encoding": lead.body_encoding,
        "source_kind": lead.source_kind,
        "source_observation_id": lead.source_observation_id,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "lead:" + hashlib.sha256(encoded.encode()).hexdigest()[:20]


def _lead_from_json(value: Mapping[str, object]) -> EvidenceLead | None:
    if value.get("version") != _STATE_VERSION:
        return None
    family = _normalize_family(value.get("family"))
    method = _safe_method(value.get("method"))
    origin = _normalize_origin(str(value.get("origin") or ""))
    endpoint = _normalize_endpoint(str(value.get("endpoint") or ""))
    fingerprint = str(value.get("fingerprint") or "")
    source_observation_id = _safe_reference(value.get("source_observation_id"))
    status = str(value.get("status") or "")
    inputs_value = value.get("inputs")
    inputs = (
        tuple(
            sorted(
                {
                    name
                    for item in inputs_value
                    if (name := _safe_input(item))
                }
            )
        )
        if isinstance(inputs_value, list)
        else ()
    )
    no_progress = _nonnegative_int(value.get("aligned_no_progress"))
    source_kind = str(value.get("source_kind") or "")
    input_locations = _parameter_specs(value.get("input_locations"))
    request_inputs = _parameter_specs(value.get("request_inputs"))
    body_encoding = _safe_body_encoding(
        value.get("body_encoding"),
        request_inputs=request_inputs,
    )
    expected_inputs = tuple(sorted({name for _location, name in input_locations}))
    if (
        not fingerprint.startswith("lead:")
        or not family
        or not method
        or not origin
        or not endpoint
        or not source_observation_id
        or status not in {_ACTIVE, _AWAITING_SESSION, _EXHAUSTED, _REJECTED, _RESOLVED}
        or source_kind not in {"tool_run_probe", "tool_validate_poc"}
        or no_progress > _MAX_ALIGNED_NO_PROGRESS
        or tuple(sorted(inputs)) != expected_inputs
        or len(request_inputs) > _MAX_REQUEST_INPUTS
        or input_locations != tuple(sorted(set(input_locations)))
        or not set(input_locations).issubset(request_inputs)
        or any(
            location not in _AFFECTED_INPUT_LOCATIONS
            for location, _name in input_locations
        )
        or any(name.startswith("path[") for _location, name in input_locations)
        or any(name == "raw_body" for _location, name in input_locations)
        or _is_structural_endpoint(endpoint)
        or body_encoding == "raw"
        or (
            any(location == "body" for location, _name in input_locations)
            and body_encoding not in {"form", "json"}
        )
    ):
        return None
    lead = EvidenceLead(
        fingerprint="",
        family=family,
        probe=str(value.get("probe") or ""),
        finding_type=str(value.get("finding_type") or ""),
        method=method,
        origin=origin,
        endpoint=endpoint,
        inputs=inputs,
        input_locations=input_locations,
        request_inputs=request_inputs,
        body_encoding=body_encoding,
        source_kind=source_kind,
        source_observation_id=source_observation_id,
        stage=str(value.get("stage") or ""),
        aligned_no_progress=no_progress,
        status=status,
    )
    expected = _lead_fingerprint(lead)
    return replace(lead, fingerprint=expected) if fingerprint == expected else None


def _action_family(
    action: Mapping[str, object],
    *,
    route: Mapping[str, object],
) -> str:
    explicit = action.get("family") or action.get("vuln_class")
    finding = action.get("finding")
    if not explicit and isinstance(finding, Mapping):
        explicit = finding.get("vuln_class")
    return _normalize_family(explicit or route.get("family"))


def _normalize_family(value: object) -> str:
    family = str(value or "").strip().lower()
    normalized = _FAMILY_ALIASES.get(family, family)
    return normalized if _FAMILY_RE.fullmatch(normalized) else ""


def _action_dispatch_shapes(action: Mapping[str, object]) -> tuple[_DispatchShape, ...]:
    kind = str(action.get("action") or "")
    if kind == "http_request":
        shape = _dispatch_shape(action, validator_step=False)
        return (shape,) if shape is not None else ()
    if kind != "validate_poc":
        return ()
    steps = action.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > _MAX_VALIDATION_STEPS:
        return ()
    shapes: list[_DispatchShape] = []
    for step in steps:
        if not isinstance(step, Mapping):
            return ()
        shape = _dispatch_shape(step, validator_step=True)
        if shape is None:
            return ()
        shapes.append(shape)
    return tuple(shapes)


def _dispatch_shape(
    request: Mapping[str, object],
    *,
    validator_step: bool,
) -> _DispatchShape | None:
    declared_method = _safe_method(request.get("method") or "GET")
    raw_endpoint = str(request.get("url") or request.get("path") or "")
    endpoint = _normalize_endpoint(raw_endpoint)
    origin = _normalize_origin(raw_endpoint)
    try:
        parsed_endpoint = urlsplit(raw_endpoint)
    except ValueError:
        return None
    if (parsed_endpoint.scheme or parsed_endpoint.netloc) and not origin:
        return None
    if (
        not declared_method
        or not endpoint
        or _is_structural_endpoint(endpoint)
        or _has_duplicate_case_insensitive_headers(request)
    ):
        return None
    method = declared_method
    body_encoding = _request_body_encoding(request, validator_step=validator_step)
    if body_encoding not in _BODY_ENCODINGS or not _headers_are_modelled(
        request,
        body_encoding=body_encoding,
    ):
        return None
    inputs = _request_input_specs(request, body_encoding=body_encoding)
    if inputs is None:
        return None
    return _DispatchShape(
        declared_method=declared_method,
        method=method,
        origin=origin,
        endpoint=endpoint,
        inputs=inputs,
        body_encoding=body_encoding,
    )


def _dispatch_matches_lead(
    dispatch: _DispatchShape,
    lead: EvidenceLead,
    *,
    primary_origin: str,
) -> bool:
    effective_origin = dispatch.origin or _normalize_origin(primary_origin)
    return (
        dispatch.declared_method == lead.method
        and dispatch.method == lead.method
        and effective_origin == lead.origin
        and dispatch.endpoint == lead.endpoint
        and dispatch.inputs == lead.request_inputs
        and dispatch.body_encoding == lead.body_encoding
        and set(lead.input_locations).issubset(dispatch.inputs)
    )


def _request_input_specs(
    request: Mapping[str, object],
    *,
    body_encoding: str,
) -> tuple[tuple[str, str], ...] | None:
    raw_url = str(request.get("url") or request.get("path") or "")
    try:
        query_pairs = parse_qsl(urlsplit(raw_url).query, keep_blank_values=True)
    except ValueError:
        query_pairs = []
    specs = [
        ("query", name)
        for raw_name, _value in query_pairs
        if (name := _safe_input(raw_name))
    ]
    container = request.get("form") if body_encoding == "form" else request.get("json")
    if body_encoding == "json" and container is not None and not isinstance(
        container,
        Mapping,
    ):
        # JSON arrays/scalars have no stable named slots for this lock.
        return None
    if isinstance(container, Mapping):
        if any(not _safe_input(raw_name) for raw_name in container):
            return None
        specs.extend(
            ("body", name)
            for raw_name in container
            if (name := _safe_input(raw_name))
        )
    elif body_encoding in {"form", "json"} and request.get("body") is not None:
        raw_specs = _raw_body_input_specs(request.get("body"), encoding=body_encoding)
        if raw_specs is None:
            return None
        specs.extend(raw_specs)
    return tuple(sorted(specs))


def _headers_are_modelled(
    request: Mapping[str, object],
    *,
    body_encoding: str,
) -> bool:
    headers = request.get("headers")
    if not isinstance(headers, Mapping) or not headers:
        return True
    normalized = {
        str(name).strip().casefold(): str(value).split(";", 1)[0].strip().casefold()
        for name, value in headers.items()
    }
    if set(normalized) != {"content-type"}:
        return False
    content_type = normalized["content-type"]
    if body_encoding == "form":
        return content_type == "application/x-www-form-urlencoded"
    if body_encoding == "json":
        return content_type == "application/json" or content_type.endswith("+json")
    return False


def _raw_body_input_specs(
    value: object,
    *,
    encoding: str,
) -> list[tuple[str, str]] | None:
    text = str(value or "")
    if encoding == "form":
        try:
            pairs = parse_qsl(
                text,
                keep_blank_values=True,
                max_num_fields=_MAX_REQUEST_INPUTS,
            )
        except ValueError:
            return None
        names = [_safe_input(raw_name) for raw_name, _item in pairs]
        if (text and not pairs) or any(not name for name in names):
            return None
        return [
            ("body", name)
            for name in names
        ]
    if encoding != "json":
        return []
    try:
        payload = json.loads(text, object_pairs_hook=lambda pairs: tuple(pairs))
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, tuple):
        return None
    names = [_safe_input(raw_name) for raw_name, _value in payload]
    if any(not name for name in names):
        return None
    return [("body", name) for name in names]


def _request_body_encoding(  # noqa: PLR0911 - fail closed by physical encoding.
    request: Mapping[str, object],
    *,
    validator_step: bool,
) -> str:
    form = request.get("form")
    if isinstance(form, Mapping):
        content_type = _request_content_type(request)
        return (
            "form"
            if not content_type or content_type == "application/x-www-form-urlencoded"
            else ""
        )
    if request.get("json") is not None:
        # validate_http_poc does not dispatch its json key. Refuse to treat
        # declarative JSON metadata as a physical body in that lane.
        if validator_step:
            return ""
        content_type = _request_content_type(request)
        return (
            "json"
            if not content_type
            or content_type == "application/json"
            or content_type.endswith("+json")
            else ""
        )
    if request.get("body") is None:
        return "none"
    content_type = _request_content_type(request)
    if content_type == "application/x-www-form-urlencoded":
        return "form"
    if content_type == "application/json" or content_type.endswith("+json"):
        return "json"
    return "raw"


def _request_content_type(request: Mapping[str, object]) -> str:
    headers = request.get("headers")
    if not isinstance(headers, Mapping):
        return ""
    for name, value in headers.items():
        if str(name).strip().casefold() == "content-type":
            return str(value).split(";", 1)[0].strip().casefold()
    return ""


def _has_duplicate_case_insensitive_headers(request: Mapping[str, object]) -> bool:
    headers = request.get("headers")
    if not isinstance(headers, Mapping):
        return False
    normalized_names = [str(name).strip().casefold() for name in headers]
    return len(normalized_names) != len(set(normalized_names))


def _normalize_endpoint(value: str) -> str:
    if not value.strip():
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    return parsed.path or "/"


def _is_structural_endpoint(value: str) -> bool:
    """Reject redacted/templated paths that are not concrete replay targets."""
    try:
        path = urlsplit(value).path
    except ValueError:
        return True
    for raw_segment in path.split("/"):
        decoded = raw_segment
        for _attempt in range(2):
            expanded = unquote(decoded)
            if expanded == decoded:
                break
            decoded = expanded
        lowered = decoded.strip().casefold()
        if (
            "{" in lowered
            or "}" in lowered
            or "<" in lowered
            or ">" in lowered
            or lowered in {":id", ":redacted"}
        ):
            return True
    return False


def _normalize_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.casefold()
    hostname = str(parsed.hostname or "").casefold().rstrip(".")
    if scheme not in {"http", "https"} or not hostname or parsed.username or parsed.password:
        return ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 80 if scheme == "http" else 443
    authority = hostname if port in {None, default_port} else f"{hostname}:{port}"
    return f"{scheme}://{authority}"


def _safe_method(value: object) -> str:
    method = str(value or "").strip().upper()
    return method if method in _HTTP_METHODS else ""


def _safe_input(value: object) -> str:
    name = str(value or "").strip()
    return name if _INPUT_RE.fullmatch(name) else ""


def _safe_reference(value: object) -> str:
    reference = str(value or "").strip()
    if not reference or len(reference) > _MAX_REFERENCE_LENGTH:
        return ""
    allowed = "-_.:"
    if any(
        not (character.isascii() and (character.isalnum() or character in allowed))
        for character in reference
    ):
        return ""
    return reference


def _qualification_origin(action: Mapping[str, object], *, text: str) -> str:
    for candidate in (action.get("target_url"), action.get("url")):
        value = str(candidate or "").strip()
        if _absolute_http_url(value):
            parsed = urlsplit(value)
            return f"{parsed.scheme}://{parsed.netloc}/"
    payload = _json_object(text)
    absolute = _first_absolute_url(payload)
    if absolute:
        parsed = urlsplit(absolute)
        return f"{parsed.scheme}://{parsed.netloc}/"
    return _QUALIFICATION_ORIGIN


def _first_absolute_url(value: object) -> str:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key) in {"url", "target", "endpoint", "final_url", "replay_url"}:
                candidate = str(item or "").strip()
                if _absolute_http_url(candidate):
                    return candidate
            nested = _first_absolute_url(item)
            if nested:
                return nested
    elif isinstance(value, list):
        for item in value:
            nested = _first_absolute_url(item)
            if nested:
                return nested
    return ""


def _absolute_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _json_object(text: str) -> dict[str, object]:
    try:
        value = json.JSONDecoder(strict=False).decode(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(str(value)))
    except (TypeError, ValueError):
        return 0


def _outcome_confirmed(outcome: Mapping[str, object], *, outcome_name: str) -> bool:
    return bool(
        outcome.get("flag")
        or outcome.get("flag_captured")
        or outcome_name in _CONFIRMED_OUTCOMES
    )


def _complete_attempt(outcome: Mapping[str, object], *, outcome_name: str) -> bool:
    if outcome.get("timed_out") is True or outcome_name in _NON_ATTEMPT_OUTCOMES:
        return False
    return outcome.get("ok") is True


def _completed_validate_attempt(  # noqa: PLR0911 - strict evidence gate.
    action: Mapping[str, object],
    outcome: Mapping[str, object],
) -> bool:
    """Recognize a physically completed paired replay without trusting its vote."""
    if str(action.get("action") or "") != "validate_poc" or outcome.get("timed_out") is True:
        return False
    raw_steps = action.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        return False
    evidence_text = outcome.get("_evidence_observation")
    if not isinstance(evidence_text, str) or not evidence_text:
        return False
    payload = _json_object(evidence_text)
    completed_steps = payload.get("steps")
    if not isinstance(completed_steps, list) or len(completed_steps) != len(raw_steps):
        return False
    for step in completed_steps:
        if not isinstance(step, Mapping):
            return False
        response = step.get("response")
        if not isinstance(response, Mapping):
            return False
        status = response.get("status")
        if not isinstance(status, int) or isinstance(status, bool) or response.get("error"):
            return False
    return True


def _authentication_required_http_status(  # noqa: C901, PLR0911
    state: AgentState,
    action: Mapping[str, object],
    outcome: Mapping[str, object],
) -> int | None:
    kind = str(action.get("action") or "")
    if kind == "http_request":
        evidence_text = outcome.get("_evidence_observation")
        if isinstance(evidence_text, str) and evidence_text:
            response = _json_object(evidence_text).get("response")
            if not isinstance(response, Mapping):
                return None
            return _auth_required_status(response.get("status"))
        # A pre-dispatch block does not replace ``last_observation``. Do not let
        # a prior request's auth response pause the current aligned attempt.
        if outcome.get("ok") is not True:
            return None
        response = state.last_observation.get("http_response")
        if not isinstance(response, Mapping):
            return None
        return _auth_required_status(response.get("status"))
    if kind != "validate_poc":
        return None
    raw_steps = action.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        return None
    evidence_text = outcome.get("_evidence_observation")
    if not isinstance(evidence_text, str) or not evidence_text:
        return None
    steps = _json_object(evidence_text).get("steps")
    if not isinstance(steps, list) or len(steps) != len(raw_steps):
        return None
    statuses: list[int] = []
    for step in steps:
        response = step.get("response") if isinstance(step, Mapping) else None
        status = _auth_required_status(
            response.get("status") if isinstance(response, Mapping) else None
        )
        if status is None:
            return None
        statuses.append(status)
    return statuses[0]


def _auth_required_status(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if value in {401, 403, 407} else None


def _stored_lead(state: AgentState) -> EvidenceLead | None:
    value = state.surface.get(_SURFACE_KEY)
    return _lead_from_json(value) if isinstance(value, Mapping) else None


def _store(state: AgentState, lead: EvidenceLead) -> None:
    state.surface[_SURFACE_KEY] = lead.to_json()


def _reactivate_lead(state: AgentState, lead: EvidenceLead) -> EvidenceLead:
    active = replace(lead, status=_ACTIVE, aligned_no_progress=0)
    _store(state, active)
    state.surface[_REPLAY_GENERATION_KEY] = lead_replay_generation(state) + 1
    return active
