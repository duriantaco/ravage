from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal
from urllib.parse import unquote_plus

from pentest_schemas import ProofBundle
from pydantic import ValidationError

from ravage.finding_evidence import confirmed_finding_evidence_failures
from ravage.proof_bundle import accepted_proof_bundle_failures
from ravage.run_trace import summarize_workspace_trace
from ravage.trace_quality import grade_workspace_trace
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from pathlib import Path

LOOP_HARNESS_SCHEMA_VERSION = "ravage.loop-harness.v1"
LOOP_VERIFICATION_SCHEMA_VERSION = "ravage.loop-verification.v1"

LoopRecordSection = Literal[
    "discovered_surfaces",
    "sessions",
    "identities",
    "attempted_candidates",
    "blocked_actions",
    "evidence_ledger",
    "memory_feedback",
    "verifier_feedback",
    "hill_climb_suggestions",
]

_RECORD_SECTIONS: tuple[LoopRecordSection, ...] = (
    "discovered_surfaces",
    "sessions",
    "identities",
    "attempted_candidates",
    "blocked_actions",
    "evidence_ledger",
    "memory_feedback",
    "verifier_feedback",
    "hill_climb_suggestions",
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(access[_-]?key|auth|authorization|client[_-]?secret|cookie|credential|"
    r"database[_-]?url|jwt|token|secret|password|passwd|private[_-]?key|pwd|"
    r"api[_-]?key|session|signature|verification[_-]?code|reset[_-]?code|invite[_-]?code)"
)
_SENSITIVE_QUERY_RE = re.compile(
    r"(?i)([?&][^=&#\s]*(?:auth|authorization|cookie|credential|jwt|token|secret|"
    r"password|passwd|pwd|api[_-]?key|session|code|signature)"
    r"[^=&#\s]*=)[^&#\s]*"
)
_PROOF_RE = re.compile(r"\b(?:flag|FLAG|HTB|CTF)\{[^}\s]{3,512}\}")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![?&])\b([A-Za-z0-9_.-]*(?:auth|authorization|cookie|credential|jwt|"
    r"token|secret|password|passwd|pwd|api[_-]?key|session|code|signature)"
    r"[A-Za-z0-9_.-]*)\s*=\s*([^&\s;,\"]+)"
)
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:authorization|cookie|x-api-key|x-auth-token|x-access-token)\s*:\s*).+$"
)
_INLINE_SENSITIVE_HEADER_RE = re.compile(
    r"(?i)((?:authorization|cookie|x-api-key|x-auth-token|x-access-token)\s*:\s*)[^'\"\n]+"
)
_BEARER_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_BASIC_RE = re.compile(r"(?i)\b(Basic\s+)[A-Za-z0-9+/=]+")
_JWT_RE = re.compile(
    r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"(?:[A-Za-z0-9_-]{8,}\b)?"
)
_URL_USERINFO_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^:/@\s]*:)[^@/\s]+@")
_PEM_PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?"
    r"(?:-----END [^-\r\n]*PRIVATE KEY-----|$)"
)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_QUERY_PARAMETER_RE = re.compile(r"([?&])([^=&#\s]+)=([^&#\s]*)")
_REDACTED_QUERY_VALUE = "%5Bredacted%5D"
_REPEATED_CALL_THRESHOLD = 2


@dataclass(frozen=True)
class LoopHarnessRecord:
    kind: str
    key: str
    source: str
    value: dict[str, object] = field(default_factory=dict)
    status: str = "observed"

    def to_json(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "key": _sanitize_string(self.key),
            "source": _sanitize_string(self.source),
            "status": self.status,
            "value": _sanitize_mapping(self.value),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> LoopHarnessRecord:
        return cls(
            kind=str(payload.get("kind") or ""),
            key=str(payload.get("key") or ""),
            source=str(payload.get("source") or ""),
            status=str(payload.get("status") or "observed"),
            value=_mapping(payload.get("value")),
        )


@dataclass(frozen=True)
class LoopHarnessState:
    engagement_id: str = ""
    target_url: str = ""
    status: str = "unknown"
    phase: str = ""
    turn: int = 0
    discovered_surfaces: tuple[LoopHarnessRecord, ...] = ()
    sessions: tuple[LoopHarnessRecord, ...] = ()
    identities: tuple[LoopHarnessRecord, ...] = ()
    attempted_candidates: tuple[LoopHarnessRecord, ...] = ()
    blocked_actions: tuple[LoopHarnessRecord, ...] = ()
    evidence_ledger: tuple[LoopHarnessRecord, ...] = ()
    budget_counters: dict[str, int] = field(default_factory=dict)
    memory_feedback: tuple[LoopHarnessRecord, ...] = ()
    verifier_feedback: tuple[LoopHarnessRecord, ...] = ()
    hill_climb_suggestions: tuple[LoopHarnessRecord, ...] = ()
    last_action: dict[str, object] | None = None
    last_observation: dict[str, object] | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": LOOP_HARNESS_SCHEMA_VERSION,
            "engagement_id": self.engagement_id,
            "target_url": _sanitize_string(self.target_url),
            "status": self.status,
            "phase": self.phase,
            "turn": self.turn,
            **{
                section: [record.to_json() for record in getattr(self, section)]
                for section in _RECORD_SECTIONS
            },
            "budget_counters": dict(sorted(self.budget_counters.items())),
            "last_action": _sanitize_optional_mapping(self.last_action),
            "last_observation": _sanitize_optional_mapping(self.last_observation),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> LoopHarnessState:
        sections = {section: _record_tuple(payload.get(section)) for section in _RECORD_SECTIONS}
        return cls(
            engagement_id=str(payload.get("engagement_id") or ""),
            target_url=str(payload.get("target_url") or ""),
            status=str(payload.get("status") or "unknown"),
            phase=str(payload.get("phase") or ""),
            turn=_int(payload.get("turn")),
            budget_counters=_int_mapping(payload.get("budget_counters")),
            last_action=_optional_mapping(payload.get("last_action")),
            last_observation=_optional_mapping(payload.get("last_observation")),
            **sections,
        )


@dataclass(frozen=True)
class LoopVerificationReport:
    passed: bool
    trace_summary: dict[str, object]
    trace_quality: dict[str, object]
    verifier_feedback: tuple[LoopHarnessRecord, ...] = ()
    hill_climb_suggestions: tuple[LoopHarnessRecord, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": LOOP_VERIFICATION_SCHEMA_VERSION,
            "passed": self.passed,
            "trace_summary": _sanitize_mapping(self.trace_summary),
            "trace_quality": _sanitize_mapping(self.trace_quality),
            "verifier_feedback": [item.to_json() for item in self.verifier_feedback],
            "hill_climb_suggestions": [item.to_json() for item in self.hill_climb_suggestions],
        }


def loop_state_path(run_dir: Path) -> Path:
    return run_dir / "loop_state.json"


def loop_verification_path(run_dir: Path) -> Path:
    return run_dir / "loop_verification.json"


def load_loop_harness_state(path: Path) -> LoopHarnessState:
    if not path.exists():
        return LoopHarnessState()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return LoopHarnessState()
    if not isinstance(payload, dict):
        return LoopHarnessState()
    return LoopHarnessState.from_json(payload)


def write_loop_harness_state(state: LoopHarnessState, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(state.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def add_loop_harness_record(
    state: LoopHarnessState,
    *,
    section: LoopRecordSection,
    record: LoopHarnessRecord,
) -> LoopHarnessState:
    records = getattr(state, section)
    updated: list[LoopHarnessRecord] = []
    replaced_existing = False
    for existing in records:
        if existing.key == record.key:
            if not replaced_existing:
                updated.append(record)
                replaced_existing = True
            continue
        updated.append(existing)
    if not replaced_existing:
        updated.append(record)
    return replace(state, **{section: tuple(updated)})


def snapshot_ai_web_runtime(
    runtime: object,
    *,
    status: str,
    last_action: Mapping[str, object] | None = None,
    last_observation: Mapping[str, object] | None = None,
) -> LoopHarnessState:
    brief = getattr(runtime, "brief", None)
    state = getattr(runtime, "state", None)
    discovered_surfaces = tuple(_surface_records(runtime))
    sessions = tuple(_session_records(runtime))
    identities = tuple(_identity_records(runtime))
    attempted_candidates = tuple(_attempted_candidate_records(runtime))
    blocked_actions = tuple(_blocked_action_records(runtime))
    evidence_ledger = tuple(_evidence_records(runtime))
    memory_feedback = tuple(_memory_records(runtime))
    return LoopHarnessState(
        engagement_id=str(getattr(brief, "engagement_id", "") or ""),
        target_url=_sanitize_string(str(getattr(runtime, "target_url", "") or "")),
        status=status,
        phase=str(getattr(runtime, "phase", "") or getattr(state, "phase", "") or ""),
        turn=_int(getattr(runtime, "turn", getattr(state, "turn", 0))),
        discovered_surfaces=discovered_surfaces,
        sessions=sessions,
        identities=identities,
        attempted_candidates=attempted_candidates,
        blocked_actions=blocked_actions,
        evidence_ledger=evidence_ledger,
        budget_counters=_budget_counters(runtime, discovered_surfaces),
        memory_feedback=memory_feedback,
        last_action=_sanitize_optional_mapping(last_action),
        last_observation=_snapshot_observation(last_observation),
    )


def build_loop_verification_report(
    workspace_dir: Path,
    *,
    expect_present_evidence: bool = False,
    require_trace: bool = False,
) -> LoopVerificationReport:
    trace_summary = summarize_workspace_trace(workspace_dir).to_json()
    quality = grade_workspace_trace(workspace_dir, require_trace=require_trace)
    trace_quality = quality.to_json()
    events = _read_jsonl(workspace_dir / "events.jsonl")
    feedback: list[LoopHarnessRecord] = []

    if require_trace and not events:
        feedback.append(
            _feedback_record(
                "missing_parseable_trace_events",
                status="error",
                value={"events_present": trace_summary.get("events_present")},
            )
        )
    if _int(trace_summary.get("parse_errors")):
        feedback.append(
            _feedback_record(
                "trace_parse_errors",
                status="error",
                value={"parse_errors": _int(trace_summary.get("parse_errors"))},
            )
        )

    for finding in quality.findings:
        code = str(finding.get("code") or "trace_quality_finding")
        feedback.append(
            LoopHarnessRecord(
                kind="verifier_feedback",
                key=code,
                source="trace_quality",
                status=str(finding.get("severity") or "warning"),
                value=_sanitize_mapping(finding),
            )
        )

    feedback.extend(_repeated_tool_feedback(events))
    feedback.extend(_finding_proof_feedback(events))
    evidence_present = _trace_has_present_evidence(events)
    if expect_present_evidence and _final_action_seen(events) and not evidence_present:
        feedback.append(
            _feedback_record(
                "premature_final_without_evidence",
                status="error",
                value={"evidence_present": False},
            )
        )
    if _turn_budget_exhausted(events) and not evidence_present:
        exhaustion_status = "warning"
        if expect_present_evidence:
            exhaustion_status = "error"
        feedback.append(
            _feedback_record(
                "turn_budget_exhausted_without_evidence",
                status=exhaustion_status,
                value={"evidence_present": False},
            )
        )

    feedback = _dedupe_records(feedback)
    suggestions = _suggestions_for_feedback(feedback)
    blocking_feedback = any(item.status in {"blocked", "error", "failure"} for item in feedback)
    return LoopVerificationReport(
        passed=quality.passed and not blocking_feedback,
        trace_summary=trace_summary,
        trace_quality=trace_quality,
        verifier_feedback=tuple(feedback),
        hill_climb_suggestions=tuple(suggestions),
    )


def write_loop_verification_report(report: LoopVerificationReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _surface_records(runtime: object) -> list[LoopHarnessRecord]:
    records: list[LoopHarnessRecord] = []
    routes = getattr(runtime, "discovered_routes", [])
    if not isinstance(routes, list):
        return records
    for route in routes:
        if not isinstance(route, Mapping):
            continue
        method = str(route.get("method") or "GET").upper()
        path = str(route.get("path") or route.get("url") or "/")
        params: list[str] = []
        raw_params = route.get("params")
        if isinstance(raw_params, list):
            for param in raw_params:
                if isinstance(param, Mapping):
                    name = str(param.get("name") or "")
                else:
                    name = str(param or "")
                if name and name not in params:
                    params.append(name)
        records.append(
            LoopHarnessRecord(
                kind="route",
                key=_sanitize_string(f"{method} {path}"),
                source=str(route.get("source") or "runtime"),
                value={"params": params},
            )
        )
    return records


def _session_records(runtime: object) -> list[LoopHarnessRecord]:
    records: list[LoopHarnessRecord] = []
    for kind, attribute in (
        ("headers", "default_headers"),
        ("cookies", "default_cookies"),
    ):
        value = getattr(runtime, attribute, {})
        if not isinstance(value, Mapping) or not value:
            continue
        names = sorted(str(name) for name in value)
        records.append(
            LoopHarnessRecord(
                kind=kind,
                key=attribute,
                source="runtime",
                value={"names": names, "count": len(names)},
            )
        )
    return records


def _identity_records(runtime: object) -> list[LoopHarnessRecord]:
    records: list[LoopHarnessRecord] = []
    for kind, attribute in (
        ("jwt", "discovered_jwts"),
        ("captured_proof", "captured_flags"),
        ("observed_proof", "observed_flags"),
        ("jwt_hmac_secret", "jwt_hmac_secrets"),
    ):
        count = _collection_size(getattr(runtime, attribute, ()))
        if not count:
            continue
        records.append(
            LoopHarnessRecord(
                kind=kind,
                key=attribute,
                source="runtime",
                value={"count": count},
                status="confirmed" if kind == "captured_proof" else "observed",
            )
        )
    return records


def _attempted_candidate_records(runtime: object) -> list[LoopHarnessRecord]:
    keys = getattr(runtime, "tested_probe_keys", set())
    if not isinstance(keys, (set, list, tuple)):
        return []
    return [
        LoopHarnessRecord(
            kind="probe_candidate",
            key=_sanitize_string(str(key)),
            source="coverage_ledger",
            status="attempted",
        )
        for key in sorted(str(item) for item in keys)
    ]


def _blocked_action_records(runtime: object) -> list[LoopHarnessRecord]:
    raw_actions = getattr(runtime, "blocked_probe_actions", {})
    action_map = raw_actions if isinstance(raw_actions, Mapping) else {}
    raw_keys = getattr(runtime, "blocked_probe_keys", set())
    keys = {str(key) for key in action_map}
    if isinstance(raw_keys, (set, list, tuple)):
        keys.update(str(key) for key in raw_keys)
    records: list[LoopHarnessRecord] = []
    for key in sorted(keys):
        details = action_map.get(key)
        records.append(
            LoopHarnessRecord(
                kind="blocked_action",
                key=_sanitize_string(key),
                source="runtime",
                status="blocked",
                value=_sanitize_mapping(_mapping(details)) if isinstance(details, Mapping) else {},
            )
        )
    return records


def _evidence_records(runtime: object) -> list[LoopHarnessRecord]:
    evidence = getattr(runtime, "confirmed_evidence", {})
    if not isinstance(evidence, Mapping):
        return []
    records: list[LoopHarnessRecord] = []
    for key in sorted(str(item) for item in evidence):
        item = evidence.get(key)
        value = _evidence_value(item)
        source = str(value.pop("source_tool", "runtime") or "runtime")
        records.append(
            LoopHarnessRecord(
                kind="confirmed_evidence",
                key=_sanitize_string(key),
                source=source,
                status="confirmed" if bool(value.get("confirmed", True)) else "observed",
                value=_sanitize_mapping(value),
            )
        )
    return records


def _evidence_value(item: object) -> dict[str, object]:
    fields = (
        "source_tool",
        "confirmed",
        "vuln_class",
        "endpoint_url",
        "method",
        "param_name",
        "param_location",
        "indicator",
        "proof_bundle_id",
    )
    if isinstance(item, Mapping):
        mapped = _mapping(item)
        return {name: mapped[name] for name in fields if name in mapped}
    return {name: value for name in fields if (value := getattr(item, name, None)) is not None}


def _memory_records(runtime: object) -> list[LoopHarnessRecord]:
    records: list[LoopHarnessRecord] = []
    settings = getattr(runtime, "memory_settings", None)
    if settings is not None:
        value: dict[str, object] = {
            "mode": str(getattr(settings, "mode", "off") or "off"),
            "db_path": str(getattr(settings, "db_path", "") or ""),
            "retrieval_limit": _int(getattr(settings, "retrieval_limit", 0)),
            "min_confidence": _float(getattr(settings, "min_confidence", 0.0)),
        }
        records.append(
            LoopHarnessRecord(
                kind="memory_settings",
                key="memory",
                source="runtime",
                value=value,
            )
        )
    retrieved = getattr(runtime, "retrieved_memories", [])
    count = _collection_size(retrieved)
    if count:
        records.append(
            LoopHarnessRecord(
                kind="memory_retrieval",
                key="retrieved_memories",
                source="runtime",
                value={"count": count},
            )
        )
    return records


def _budget_counters(
    runtime: object,
    discovered_surfaces: tuple[LoopHarnessRecord, ...],
) -> dict[str, int]:
    counters = {
        "model_requests": _int(getattr(runtime, "model_requests", 0)),
        "route_count": len(discovered_surfaces),
        "free_roam_tool_calls": _int(getattr(runtime, "free_roam_tool_calls", 0)),
        "free_roam_tool_budget": _int(getattr(runtime, "free_roam_tool_budget", 0)),
        "free_roam_failure_streak": _int(getattr(runtime, "free_roam_failure_streak", 0)),
        "access_epoch": _int(getattr(runtime, "access_epoch", 0)),
    }
    return {key: value for key, value in counters.items() if value or key == "route_count"}


def _snapshot_observation(
    observation: Mapping[str, object] | None,
) -> dict[str, object] | None:
    if observation is None:
        return None
    payload = _sanitize_mapping(observation)
    response_snippet = payload.pop("response_snippet", None)
    if response_snippet is not None and "snippet" not in payload:
        payload["snippet"] = response_snippet
    return payload


def _repeated_tool_feedback(events: list[dict[str, object]]) -> list[LoopHarnessRecord]:
    feedback = _explicit_repetition_feedback(events)
    occurrences: Counter[str] = Counter()
    evidence_by_signature: dict[str, dict[str, object]] = {}
    for event in events:
        if event.get("kind") != "tool_call":
            continue
        payload = _mapping(event.get("payload"))
        evidence = {
            key: payload[key]
            for key in ("tool", "method", "path", "url", "param")
            if key in payload
        }
        signature = json.dumps(evidence, sort_keys=True, default=str)
        occurrences[signature] += 1
        evidence_by_signature[signature] = _sanitize_mapping(evidence)
    for signature, count in sorted(occurrences.items()):
        if count < _REPEATED_CALL_THRESHOLD:
            continue
        feedback.append(
            _feedback_record(
                "repeated_identical_tool_call",
                status="warning",
                value={"count": count, "evidence": evidence_by_signature[signature]},
            )
        )
    return feedback


def _explicit_repetition_feedback(
    events: list[dict[str, object]],
) -> list[LoopHarnessRecord]:
    feedback: list[LoopHarnessRecord] = []
    for event in events:
        kind = str(event.get("kind") or "")
        payload = _mapping(event.get("payload"))
        repeat_count = _int(payload.get("repeat_count"))
        repeated = kind == "repeated_action_blocked"
        if kind == "agent_action_selected" and repeat_count >= _REPEATED_CALL_THRESHOLD:
            repeated = True
        if not repeated:
            continue
        feedback.append(
            _feedback_record(
                "repeated_identical_tool_call",
                status="warning",
                value={
                    "count": max(repeat_count, _REPEATED_CALL_THRESHOLD),
                    "evidence": _sanitize_mapping(payload),
                },
            )
        )
    return feedback


def _finding_proof_feedback(events: list[dict[str, object]]) -> list[LoopHarnessRecord]:
    missing: list[dict[str, object]] = []
    for event in events:
        if event.get("kind") != "finding_confirmed":
            continue
        payload = _mapping(event.get("payload"))
        if not _payload_has_replayable_proof(payload):
            missing.append(_sanitize_mapping(payload))
    if not missing:
        return []
    return [
        _feedback_record(
            "finding_without_replayable_proof",
            status="error",
            value={"count": len(missing), "evidence": missing[:5]},
        )
    ]


def _trace_has_present_evidence(events: list[dict[str, object]]) -> bool:
    accepted_bundle_ids = _accepted_bundle_ids(events)
    for event in events:
        kind = str(event.get("kind") or "")
        payload = _mapping(event.get("payload"))
        if kind == "flag_captured" and _recognized_proof(payload.get("flag")):
            return True
        if kind == "finding_confirmed" and _payload_has_replayable_proof(payload):
            return True
    return bool(accepted_bundle_ids)


def _payload_has_replayable_proof(payload: Mapping[str, object]) -> bool:
    proof_bundle = payload.get("proof_bundle")
    if proof_bundle is not None:
        return _valid_accepted_bundle(proof_bundle)
    finding = dict(payload)
    return not confirmed_finding_evidence_failures(finding)


def _recognized_proof(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return bool(recognize_proofs(value))


def _valid_accepted_bundle(bundle: object) -> bool:
    if accepted_proof_bundle_failures(bundle):
        return False
    try:
        validated = ProofBundle.model_validate(bundle)
    except ValidationError:
        return False
    return validated.verifier.verdict == "accepted"


def _accepted_bundle_ids(events: list[dict[str, object]]) -> set[str]:
    candidate_bundles: dict[str, dict[str, object]] = {}
    accepted_verdicts: dict[str, dict[str, object]] = {}
    for event in events:
        kind = str(event.get("kind") or "")
        payload = _mapping(event.get("payload"))
        bundle_id = str(payload.get("bundle_id") or "")
        if not bundle_id:
            continue
        if kind == "candidate_proof_bundle":
            candidate_bundles[bundle_id] = payload
        elif kind == "proof_bundle_verified" and payload.get("verdict") == "accepted":
            accepted_verdicts[bundle_id] = payload

    accepted: set[str] = set()
    for bundle_id in sorted(set(candidate_bundles) & set(accepted_verdicts)):
        bundle = dict(candidate_bundles[bundle_id])
        verdict = accepted_verdicts[bundle_id]
        bundle["verifier"] = {
            "verdict": "accepted",
            "confidence": str(verdict.get("confidence") or "low"),
            "rationale": str(verdict.get("rationale") or "accepted by verifier"),
            "impact": verdict.get("impact"),
        }
        if _valid_accepted_bundle(bundle):
            accepted.add(bundle_id)
    return accepted


def _final_action_seen(events: list[dict[str, object]]) -> bool:
    for event in events:
        kind = str(event.get("kind") or "")
        if kind == "agent_final":
            return True
        payload = _mapping(event.get("payload"))
        if kind == "action_started" and payload.get("action_kind") == "final":
            return True
        if kind not in {"agent_action", "agent_action_selected"}:
            continue
        action = payload.get("action")
        if isinstance(action, Mapping):
            action = action.get("action")
        if str(action or "") == "final":
            return True
    return False


def _turn_budget_exhausted(events: list[dict[str, object]]) -> bool:
    for event in events:
        kind = str(event.get("kind") or "")
        if kind in {"max_turns_reached", "turn_budget_exhausted"}:
            return True
        if kind == "run_completed":
            status = str(_mapping(event.get("payload")).get("status") or "")
            if status in {"max_turns", "max_turns_reached"}:
                return True
    return False


def _suggestions_for_feedback(
    feedback: list[LoopHarnessRecord],
) -> list[LoopHarnessRecord]:
    suggestions: list[LoopHarnessRecord] = []
    for item in feedback:
        suggestions.append(  # noqa: PERF401 - explicit records are easier to audit.
            LoopHarnessRecord(
                kind="harness_improvement",
                key=item.key,
                source=item.source,
                status="candidate",
                value={"trigger_status": item.status},
            )
        )
    return _dedupe_records(suggestions)


def _feedback_record(
    key: str,
    *,
    status: str,
    value: dict[str, object],
) -> LoopHarnessRecord:
    return LoopHarnessRecord(
        kind="verifier_feedback",
        key=key,
        source="trace_quality",
        status=status,
        value=value,
    )


def _dedupe_records(records: list[LoopHarnessRecord]) -> list[LoopHarnessRecord]:
    severity = {
        "candidate": 0,
        "observed": 0,
        "warning": 1,
        "blocked": 2,
        "error": 3,
        "failure": 3,
    }
    deduped: dict[tuple[str, str], LoopHarnessRecord] = {}
    for record in records:
        identity = (record.kind, record.key)
        existing = deduped.get(identity)
        if existing is None or severity.get(record.status, 0) > severity.get(existing.status, 0):
            deduped[identity] = record
    return [deduped[key] for key in sorted(deduped)]


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    events: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def _sanitize_optional_mapping(
    value: Mapping[str, object] | None,
) -> dict[str, object] | None:
    return None if value is None else _sanitize_mapping(value)


def _sanitize_mapping(value: Mapping[str, object]) -> dict[str, object]:
    sanitized: dict[str, object] = {}
    for key, item in value.items():
        text_key = str(key)
        if _SENSITIVE_KEY_RE.search(text_key):
            sanitized[text_key] = "[redacted]"
        else:
            sanitized[text_key] = _sanitize_value(item)
    return sanitized


def _sanitize_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _sanitize_mapping(_mapping(value))
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, set):
        return [_sanitize_value(item) for item in sorted(value, key=str)]
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


def _sanitize_string(value: str) -> str:
    text = _sanitize_percent_encoded_query_values(value)
    text = _sanitize_percent_encoded_proofs(text)
    text = _PROOF_RE.sub(lambda match: f"{match.group(0).split('{', 1)[0]}{{REDACTED}}", text)
    text = _URL_USERINFO_RE.sub(r"\1[redacted]@", text)
    text = _PEM_PRIVATE_KEY_RE.sub("[redacted-private-key]", text)
    text = _AWS_ACCESS_KEY_RE.sub("[redacted-access-key]", text)
    text = _SENSITIVE_HEADER_RE.sub(r"\1[redacted]", text)
    text = _INLINE_SENSITIVE_HEADER_RE.sub(r"\1[redacted]", text)
    text = _BEARER_RE.sub(r"\1[redacted]", text)
    text = _BASIC_RE.sub(r"\1[redacted]", text)
    text = _JWT_RE.sub("[redacted-jwt]", text)
    text = _SENSITIVE_QUERY_RE.sub(
        lambda match: match.group(1) + _REDACTED_QUERY_VALUE,
        text,
    )
    text = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1=[redacted]", text)
    return text  # noqa: RET504 - staged redaction is easier to audit.


def _sanitize_percent_encoded_query_values(value: str) -> str:
    def redact(match: re.Match[str]) -> str:
        raw_key = match.group(2)
        raw_value = match.group(3)
        decoded_key = _bounded_unquote(raw_key)
        decoded_value = _bounded_unquote(raw_value)
        sensitive_key = bool(_SENSITIVE_KEY_RE.search(decoded_key))
        encoded_proof = bool(_PROOF_RE.search(decoded_value))
        if not sensitive_key and not encoded_proof:
            return match.group(0)
        return f"{match.group(1)}{raw_key}={_REDACTED_QUERY_VALUE}"

    sanitized = _QUERY_PARAMETER_RE.sub(redact, value)
    return sanitized  # noqa: RET504 - named redaction keeps returns simple.


def _sanitize_percent_encoded_proofs(value: str) -> str:
    decoded = _bounded_unquote(value)
    encoded_proof_present = decoded != value and bool(_PROOF_RE.search(decoded))
    if encoded_proof_present:
        return "[redacted-encoded-proof]"
    return value


def _bounded_unquote(value: str, *, rounds: int = 2) -> str:
    decoded = value
    for _ in range(rounds):
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items()}


def _optional_mapping(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    return _mapping(value)


def _record_tuple(value: object) -> tuple[LoopHarnessRecord, ...]:
    if not isinstance(value, list):
        return ()
    records: list[LoopHarnessRecord] = []
    for item in value:
        if isinstance(item, Mapping):
            records.append(  # noqa: PERF401 - explicit narrowing keeps Pylance precise.
                LoopHarnessRecord.from_json(_mapping(item))
            )
    return tuple(records)


def _int_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): _int(item) for key, item in value.items()}


def _collection_size(value: object) -> int:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return 0


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _float(value: object) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


__all__ = [
    "LOOP_HARNESS_SCHEMA_VERSION",
    "LOOP_VERIFICATION_SCHEMA_VERSION",
    "LoopHarnessRecord",
    "LoopHarnessState",
    "LoopVerificationReport",
    "add_loop_harness_record",
    "build_loop_verification_report",
    "load_loop_harness_state",
    "loop_state_path",
    "loop_verification_path",
    "snapshot_ai_web_runtime",
    "write_loop_harness_state",
    "write_loop_verification_report",
]
