# ruff: noqa: CPY001

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ravage.agent_core.recovery_family_attribution import recovery_family_override
from ravage.agent_core.recovery_policy import (
    MaterialProgressKind,
    ProgressSnapshot,
)
from ravage.agent_core.semantic_routes import (
    semantic_action_fingerprint,
    semantic_action_route,
)

_TRUSTED_TOOL_SOURCES = frozenset(
    {
        "tool_run_command",
        "tool_run_python",
        "tool_run_probe",
        "tool_validate_poc",
        "tool_http_request",
    }
)
_TRUSTED_STRUCTURED_SOURCES = frozenset({"tool_run_probe", "tool_validate_poc"})

# These are deliberately narrower than observation_markers.CONFIRMATION_FINDING_TYPES.
# Candidate/surface findings can guide a pivot, but cannot buy a focused lease.
_AUTH_STATE_FINDINGS = frozenset(
    {
        "auth_session_followup_signal",
        "auth_workflow_completed_signal",
        "cookie_privilege_tamper_signal",
        "default_credentials_valid",
        "privilege_escalation_signal",
        "session_followup_proof",
        "sqli_auth_bypass_session",
        "two_identity_session_delta",
    }
)
_REQUEST_TEMPLATE_FINDINGS = frozenset(
    {
        "blind_sql_injection_boolean_signal",
        "blind_sql_injection_timing_signal",
        "data_query_signal",
        "filtered_query_bypass_signal",
        "idor_boundary_followup_signal",
        "idor_boundary_signal",
        "sql_injection_error_signal",
        "sql_literal_comment_bypass_signal",
        "sql_literal_comment_exposed_secret",
    }
)
_RESPONSE_DIFFERENTIAL_FINDINGS = frozenset(
    {
        "blind_sql_injection_boolean_signal",
        "blind_sql_injection_timing_signal",
        "command_boundary_signal",
        "command_boundary_timing_signal",
        "filtered_query_bypass_signal",
        "idor_boundary_followup_signal",
        "idor_boundary_signal",
        "reflection_value_delta",
        "sql_injection_error_signal",
        "sql_literal_comment_bypass_signal",
        "sql_literal_comment_exposed_secret",
        "ssti_engine_execution",
        "ssti_fingerprint_signal",
        "ssti_stored_signal",
        "two_identity_session_delta",
    }
)
_PRIMITIVE_FINDINGS = frozenset(
    {
        "client_side_execution",
        "command_boundary_proof",
        "cookie_deserialization_marker",
        "file_fetch_parser_signal",
        "file_read_extracted_content",
        "file_read_primitive",
        "insecure_deserialization_cookie_signal",
        "php_include_execution",
        "ssrf_boundary_signal",
        "ssrf_internal_path_signal",
        "werkzeug_console_unlocked",
        "xxe_file_read_signal",
    }
)

_VARIABLE_PATH_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f-]{27,}|[A-Za-z0-9_-]{24,})$",
    flags=re.IGNORECASE,
)
_MAX_SOURCE_FINDING_DEPTH = 4

_FINDING_FAMILY_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sql_injection", ("sql", "data_query", "filtered_query")),
    ("template_injection", ("ssti", "template_")),
    ("xml_external_entity", ("xxe", "external_entity")),
    ("path_traversal", ("file_read", "file_fetch", "php_include")),
    ("object_authorization", ("idor", "two_identity")),
    ("command_injection", ("command_boundary", "werkzeug")),
    ("server_side_request_forgery", ("ssrf",)),
    ("deserialization", ("deserial", "cookie_deserialization")),
    ("cross_site_scripting", ("client_side", "reflection", "xss")),
    (
        "authentication",
        ("auth_", "credential", "session", "privilege", "cookie_privilege"),
    ),
)


@dataclass(frozen=True)
class RecoveryLead:
    """Secret-free target lead suitable for a bounded specialist handoff."""

    fingerprint: str
    finding_type: str
    family: str
    probe: str
    method: str
    endpoints: tuple[str, ...]
    inputs: tuple[str, ...]
    progress_kinds: tuple[MaterialProgressKind, ...]

    @property
    def material(self) -> bool:
        return bool(self.progress_kinds)

    def to_json(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "finding_type": self.finding_type,
            "family": self.family,
            "probe": self.probe,
            "method": self.method,
            "endpoints": list(self.endpoints),
            "inputs": list(self.inputs),
            "progress_kinds": [kind.value for kind in self.progress_kinds],
            "material": self.material,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RecoveryLead:
        raw_kinds = payload.get("progress_kinds")
        kinds = raw_kinds if isinstance(raw_kinds, list) else []
        return cls(
            fingerprint=str(payload.get("fingerprint") or ""),
            finding_type=str(payload.get("finding_type") or ""),
            family=str(payload.get("family") or "unknown"),
            probe=str(payload.get("probe") or ""),
            method=str(payload.get("method") or ""),
            endpoints=_json_string_tuple(payload.get("endpoints")),
            inputs=_json_string_tuple(payload.get("inputs")),
            progress_kinds=tuple(MaterialProgressKind(str(kind)) for kind in kinds),
        )


@dataclass(frozen=True)
class RecoveryEvidenceAssessment:
    """Secret-free, target-proven evidence derived at one executed turn."""

    snapshot: ProgressSnapshot
    material_progress: tuple[MaterialProgressKind, ...]
    observation_digest: str
    route_fingerprint: str
    low_value_route: bool
    source_trusted: bool
    reason_codes: tuple[str, ...]
    leads: tuple[RecoveryLead, ...]


@dataclass
class _EvidenceAccumulator:
    proofs: set[str]
    primitives: set[str]
    authenticated_states: set[str]
    request_templates: set[str]
    response_differentials: set[str]
    confirmed_hypotheses: set[str]
    disproved_hypotheses: set[str]
    weak_signals: set[str]

    @classmethod
    def from_snapshot(cls, snapshot: ProgressSnapshot) -> _EvidenceAccumulator:
        return cls(
            proofs=set(snapshot.confirmed_proofs),
            primitives=set(snapshot.confirmed_primitives),
            authenticated_states=set(snapshot.authenticated_states),
            request_templates=set(snapshot.validated_request_templates),
            response_differentials=set(snapshot.validated_response_differentials),
            confirmed_hypotheses=set(snapshot.confirmed_hypotheses),
            disproved_hypotheses=set(snapshot.disproved_hypotheses),
            weak_signals=set(snapshot.weak_signals),
        )

    def snapshot(self) -> ProgressSnapshot:
        return ProgressSnapshot(
            confirmed_proofs=frozenset(self.proofs),
            confirmed_primitives=frozenset(self.primitives),
            authenticated_states=frozenset(self.authenticated_states),
            validated_request_templates=frozenset(self.request_templates),
            validated_response_differentials=frozenset(self.response_differentials),
            confirmed_hypotheses=frozenset(self.confirmed_hypotheses),
            disproved_hypotheses=frozenset(self.disproved_hypotheses),
            weak_signals=frozenset(self.weak_signals),
        )


def assess_recovery_evidence(
    previous: ProgressSnapshot,
    *,
    action: Mapping[str, object],
    outcome: Mapping[str, object],
    source_kind: str,
    raw_observation: str | None = None,
) -> RecoveryEvidenceAssessment:
    """Derive cumulative recovery progress without consulting model-authored state."""
    source_trusted = source_kind in _TRUSTED_TOOL_SOURCES
    observation_text = (
        raw_observation if raw_observation is not None else str(outcome.get("observation") or "")
    )
    structured = (
        _structured_result(observation_text) if source_kind in _TRUSTED_STRUCTURED_SOURCES else {}
    )
    observation_digest = _trusted_observation_digest(
        action=action,
        outcome=outcome,
        source_kind=source_kind,
        structured=structured,
        observation_text=observation_text,
    )
    route_fingerprint = semantic_action_fingerprint(action)
    leads = _recovery_leads(
        structured=structured,
        action=action,
        source_trusted=source_trusted,
    )

    accumulator = _EvidenceAccumulator.from_snapshot(previous)
    reason_codes = _apply_proof(
        accumulator,
        outcome=outcome,
        source_trusted=source_trusted,
        observation_digest=observation_digest,
    )
    reason_codes.extend(
        _apply_tool_evidence(
            accumulator,
            structured=structured,
            source_kind=source_kind,
            source_trusted=source_trusted,
        )
    )

    snapshot_without_weak = accumulator.snapshot()
    material_progress = snapshot_without_weak.material_delta(previous)
    if source_trusted and not material_progress:
        accumulator.weak_signals.add(f"weak:{observation_digest}")
        reason_codes.append("weak_only")
    return RecoveryEvidenceAssessment(
        snapshot=accumulator.snapshot(),
        material_progress=material_progress,
        observation_digest=observation_digest,
        route_fingerprint=route_fingerprint,
        low_value_route=not material_progress,
        source_trusted=source_trusted,
        reason_codes=tuple(dict.fromkeys(reason_codes)),
        leads=leads,
    )


def _recovery_leads(
    *,
    structured: Mapping[str, object],
    action: Mapping[str, object],
    source_trusted: bool,
) -> tuple[RecoveryLead, ...]:
    if not structured or not source_trusted:
        return ()
    probe = str(structured.get("probe") or action.get("probe") or "")
    leads: list[RecoveryLead] = []
    seen: set[str] = set()
    for finding, shape in _finding_shapes(structured):
        finding_type = str(finding.get("type") or "")
        family = _finding_family(
            finding_type,
            finding=finding,
            shape=shape,
            action=action,
        )
        progress_kinds = _finding_progress_kinds(finding_type, finding)
        identity = {
            "finding_type": finding_type,
            "family": family,
            "probe": probe,
            "shape": shape,
            "progress_kinds": [kind.value for kind in progress_kinds],
        }
        fingerprint = _fingerprint("lead", identity)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        leads.append(
            RecoveryLead(
                fingerprint=fingerprint,
                finding_type=finding_type,
                family=family,
                probe=probe,
                method=str(shape.get("method") or ""),
                endpoints=tuple(str(item) for item in shape.get("endpoints") or []),
                inputs=tuple(str(item) for item in shape.get("inputs") or []),
                progress_kinds=progress_kinds,
            )
        )
    return tuple(leads)


def _finding_family(
    finding_type: str,
    *,
    finding: Mapping[str, object],
    shape: Mapping[str, object],
    action: Mapping[str, object],
) -> str:
    inputs = shape.get("inputs")
    override = recovery_family_override(
        finding_type,
        finding=finding,
        inputs=inputs if isinstance(inputs, list) else (),
    )
    if override:
        return override
    lowered = finding_type.lower()
    for family, markers in _FINDING_FAMILY_MARKERS:
        if any(marker in lowered for marker in markers):
            return family
    return str(semantic_action_route(action).get("family") or "unknown")


def _finding_progress_kinds(
    finding_type: str,
    finding: Mapping[str, object],
) -> tuple[MaterialProgressKind, ...]:
    kinds: list[MaterialProgressKind] = []
    if finding_type in _PRIMITIVE_FINDINGS:
        kinds.append(MaterialProgressKind.PRIMITIVE_CONFIRMED)
    if finding_type in _AUTH_STATE_FINDINGS:
        kinds.append(MaterialProgressKind.AUTH_STATE_CHANGED)
    if finding_type in _REQUEST_TEMPLATE_FINDINGS and _validated_request_template(finding):
        kinds.append(MaterialProgressKind.REQUEST_TEMPLATE_VALIDATED)
    if finding_type in _RESPONSE_DIFFERENTIAL_FINDINGS and _differential_is_supported(
        finding_type, finding
    ):
        kinds.append(MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED)
    return tuple(kinds)


def _apply_proof(
    accumulator: _EvidenceAccumulator,
    *,
    outcome: Mapping[str, object],
    source_trusted: bool,
    observation_digest: str,
) -> list[str]:
    proof_captured = bool(outcome.get("flag") or outcome.get("flag_captured"))
    if not proof_captured:
        return []
    if not source_trusted:
        return ["untrusted_proof_rejected"]
    accumulator.proofs.add(
        _proof_fingerprint(outcome=outcome, observation_digest=observation_digest)
    )
    return ["tool_proof_confirmed"]


def _apply_tool_evidence(
    accumulator: _EvidenceAccumulator,
    *,
    structured: Mapping[str, object],
    source_kind: str,
    source_trusted: bool,
) -> list[str]:
    if structured and source_trusted:
        finding_shapes = _finding_shapes(structured)
        for finding, shape in finding_shapes:
            _apply_finding(accumulator, finding=finding, shape=shape)
        return [
            "structured_tool_findings" if finding_shapes else "structured_tool_without_findings"
        ]
    if source_kind in _TRUSTED_STRUCTURED_SOURCES:
        return ["unparseable_structured_tool_result"]
    if source_trusted:
        # Shell/Python stdout can contain model-authored echo/print claims. It is
        # useful context, but only the existing proof gate can promote it.
        return ["untyped_tool_output"]
    return ["untrusted_source"]


def _apply_finding(
    accumulator: _EvidenceAccumulator,
    *,
    finding: Mapping[str, object],
    shape: Mapping[str, object],
) -> None:
    finding_type = str(finding.get("type") or "")
    if finding_type in _AUTH_STATE_FINDINGS:
        accumulator.authenticated_states.add(_fingerprint("auth", shape))
    if finding_type in _PRIMITIVE_FINDINGS:
        accumulator.primitives.add(_fingerprint("primitive", shape))
    if finding_type in _REQUEST_TEMPLATE_FINDINGS:
        template = _validated_request_template(finding)
        if template:
            accumulator.request_templates.add(_fingerprint("template", template))
    if finding_type in _RESPONSE_DIFFERENTIAL_FINDINGS and _differential_is_supported(
        finding_type, finding
    ):
        accumulator.response_differentials.add(_fingerprint("differential", shape))


def _differential_is_supported(
    finding_type: str,
    finding: Mapping[str, object],
) -> bool:
    if finding_type != "ssti_fingerprint_signal":
        return True
    signal = finding.get("signal")
    if not isinstance(signal, Mapping):
        return False
    signal_kind = str(signal.get("kind") or "")
    if signal_kind in {"evaluated_expression", "template_error"}:
        return True
    if signal_kind != "expression_repetition":
        return False
    count = signal.get("count")
    expected = finding.get("expected")
    expected_counts = {
        int(value) for value in expected if isinstance(expected, list) and str(value).isdigit()
    }
    return isinstance(count, int) and count > 0 and count in expected_counts


def _structured_result(text: str) -> dict[str, object]:
    if not text.strip():
        return {}
    try:
        value = json.JSONDecoder(strict=False).decode(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _finding_shapes(
    structured: Mapping[str, object],
) -> list[tuple[dict[str, object], dict[str, object]]]:
    raw_findings = structured.get("findings")
    if not isinstance(raw_findings, list):
        return []
    shapes: list[tuple[dict[str, object], dict[str, object]]] = []
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, Mapping):
            continue
        finding = dict(raw_finding)
        finding_type = str(finding.get("type") or "").strip()
        if not finding_type:
            continue
        shapes.append(
            (
                finding,
                {
                    "type": finding_type,
                    "endpoints": _finding_endpoints(finding),
                    "inputs": _finding_inputs(finding),
                    "method": _finding_method(finding),
                },
            )
        )
    return shapes


def _validated_request_template(finding: Mapping[str, object]) -> dict[str, object]:
    for view in _finding_views(finding):
        replay = view.get("replay")
        if not isinstance(replay, Mapping):
            continue
        method = str(replay.get("method") or "GET").upper()
        url = str(replay.get("url") or "").strip()
        endpoint = _normalize_endpoint(url)
        if not endpoint:
            continue
        field_names: set[str] = set()
        payload_field = str(replay.get("payload_field") or "").strip()
        if payload_field:
            field_names.add(payload_field)
        for key in ("form", "json", "params"):
            values = replay.get(key)
            if isinstance(values, Mapping):
                field_names.update(str(name) for name in values)
        return {
            "method": method,
            "endpoint": endpoint,
            "fields": sorted(field_names),
        }
    return {}


def _finding_endpoints(finding: Mapping[str, object]) -> list[str]:
    candidates: list[str] = []
    for view in _finding_views(finding):
        for key in ("url", "target", "endpoint"):
            value = view.get(key)
            if isinstance(value, str):
                candidates.append(value)
        for key in ("response", "replay", "baseline", "candidate"):
            value = view.get(key)
            if not isinstance(value, Mapping):
                continue
            for url_key in ("url", "final_url", "replay_url"):
                url = value.get(url_key)
                if isinstance(url, str):
                    candidates.append(url)
        form = view.get("form")
        if isinstance(form, Mapping):
            action = form.get("action")
            if isinstance(action, str):
                candidates.append(action)
    normalized = [_normalize_endpoint(value) for value in candidates]
    return list(dict.fromkeys(value for value in normalized if value))[:4]


def _finding_inputs(finding: Mapping[str, object]) -> list[str]:
    names: set[str] = set()
    for view in _finding_views(finding):
        for key in ("input", "parameter", "field", "payload_field"):
            _add_input_names(names, view.get(key))
        replay = view.get("replay")
        if isinstance(replay, Mapping):
            _add_input_names(names, replay.get("payload_field"))
            for key in ("form", "json", "params"):
                values = replay.get(key)
                if isinstance(values, Mapping):
                    names.update(str(name) for name in values)
        form = view.get("form")
        if isinstance(form, Mapping):
            _add_input_names(names, form.get("inputs"))
    return sorted(names)[:12]


def _finding_method(finding: Mapping[str, object]) -> str:
    for view in _finding_views(finding):
        for value in (view, view.get("replay"), view.get("response"), view.get("form")):
            if isinstance(value, Mapping):
                method = str(value.get("method") or "").strip().upper()
                if method:
                    return method
    return ""


def _finding_views(finding: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    views: list[Mapping[str, object]] = []
    current: Mapping[str, object] | None = finding
    while current is not None and len(views) < _MAX_SOURCE_FINDING_DEPTH:
        views.append(current)
        nested = current.get("source_finding")
        current = nested if isinstance(nested, Mapping) else None
    return tuple(views)


def _add_input_names(names: set[str], value: object) -> None:
    if isinstance(value, str):
        if value.strip():
            names.add(value.strip())
        return
    if isinstance(value, Mapping):
        for key in ("input", "name", "parameter", "field"):
            _add_input_names(names, value.get(key))
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _add_input_names(names, item)


def _normalize_endpoint(value: str) -> str:
    if not value.strip():
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    path = parsed.path or "/"
    normalized_path = "/".join(
        "{id}" if _VARIABLE_PATH_SEGMENT_RE.fullmatch(segment) else segment
        for segment in path.split("/")
    )
    query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    return normalized_path + ("?" + "&".join(query_names) if query_names else "")


def _trusted_observation_digest(
    *,
    action: Mapping[str, object],
    outcome: Mapping[str, object],
    source_kind: str,
    structured: Mapping[str, object],
    observation_text: str,
) -> str:
    if structured:
        identity: dict[str, object] = {
            "source": source_kind,
            "probe": str(structured.get("probe") or action.get("probe") or ""),
            "ok": structured.get("ok"),
            "findings": [shape for _finding, shape in _finding_shapes(structured)],
            "errors": len(structured.get("errors") or [])
            if isinstance(structured.get("errors"), list)
            else 0,
        }
    else:
        identity = {
            "source": source_kind,
            "action": str(action.get("action") or ""),
            "ok": outcome.get("ok"),
            "classification": str(outcome.get("classification") or outcome.get("outcome") or ""),
            "text_sha256": hashlib.sha256(observation_text.encode("utf-8")).hexdigest()[:16],
        }
    return _fingerprint("observation", identity).split(":", 1)[1]


def _proof_fingerprint(
    *,
    outcome: Mapping[str, object],
    observation_digest: str,
) -> str:
    proof = str(outcome.get("flag") or "")
    identity = proof or observation_digest
    return _fingerprint("proof", identity)


def _fingerprint(namespace: str, value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]
    return f"{namespace}:{digest}"


def _json_string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str) and item)
