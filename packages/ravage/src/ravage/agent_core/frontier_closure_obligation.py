from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.agent_state import append_unique
from ravage.agent_core.frontier_auth_transition import (
    action_attempts_sql_auth_bypass,
)
from ravage.agent_core.frontier_observation_text import output_observation_texts
from ravage.agent_core.frontier_route import (
    FrontierObjective,
    FrontierObjectiveBasis,
)
from ravage.agent_core.frontier_structured_observation import (
    structured_output_mappings,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_OBLIGATION_SIGNAL = "frontier_closure_obligations"
_ATTEMPT_SIGNAL = "frontier_closure_obligation_attempts"
_HANDOFF_REJECTION_SIGNAL = "frontier_closure_handoff_rejections"
_MAX_SIGNAL_ITEMS = 30
_PRIMITIVE_PREFIX_PARTS = 2
_CLOSURE_EVIDENCE_PREFIX = "closure-obligation:"
_IDENTIFIER_COLUMNS = frozenset({"username", "user", "email", "name", "login"})
_SECRET_COLUMNS = frozenset({"password", "passwd", "pass", "secret", "token", "credential"})
_OPERATION_MARKERS = (
    "ascii",
    "curl",
    "http",
    "length",
    "post",
    "requests",
    "select",
    "substring",
    "urlencode",
    "urllib",
)
_EXTRACTION_MARKERS = ("ascii", "length", "select", "substring")
_ACCESS_BOOLEAN_KEYS = frozenset(
    {
        "authenticated",
        "has_access",
        "login_success",
        "post_login_has_upload",
        "protected_access",
        "success",
    }
)
_ACCESS_TITLE_KEYS = frozenset({"page_title", "post_login_title", "title"})
_ACCESS_URL_KEYS = frozenset({"dashboard_url", "post_login_url", "protected_url", "upload_url"})
_POSITIVE_TITLES = ("admin", "dashboard", "upload")
_PROTECTED_PATHS = ("/admin", "/dashboard", "/upload")
_TRUE_VALUES = frozenset({"1", "true", "yes"})
_SUCCESS_RESPONSE = re.compile(r'(?i)"response"\s*:\s*"(?:authenticated|logged\s+in|success)"')
_BOOLEAN_ACCESS_LINE = re.compile(
    r"(?i)^(?:AUTHENTICATED|HAS_ACCESS|LOGIN_SUCCESS|POST_LOGIN_HAS_UPLOAD|"
    r"PROTECTED_ACCESS)\s*[:=]\s*(?:1|true|yes)\s*$"
)
_TITLE_ACCESS_LINE = re.compile(
    r"(?i)^(?:PAGE_TITLE|POST_LOGIN_TITLE|TITLE)\s*[:=]\s*"
    r"(?:admin|dashboard|upload)(?:\s+.*)?$"
)
_URL_ACCESS_LINE = re.compile(
    r"(?i)^(?:DASHBOARD_URL|POST_LOGIN_URL|PROTECTED_URL|UPLOAD_URL)\s*[:=]\s*"
    r"\S*(?:/admin|/dashboard|/upload)\S*$"
)
_STABLE_CLOSURE_EVIDENCE_PREFIXES = (
    "base-state:",
    "contract:",
    "primitive:",
    "replay-contract:",
    "request-contract:",
    "sql-oracle:",
)


@dataclass(frozen=True)
class ExtractedArtifact:
    table: str
    column: str
    row: int
    value: str

    def to_json(self) -> dict[str, object]:
        return {
            "table": self.table,
            "column": self.column,
            "row": self.row,
            "value": self.value,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> ExtractedArtifact:
        return cls(
            table=str(payload.get("table") or ""),
            column=str(payload.get("column") or ""),
            row=_int(payload.get("row")),
            value=str(payload.get("value") or ""),
        )


@dataclass(frozen=True)
class ClosureObligation:
    family: str
    stage: str
    artifacts: tuple[ExtractedArtifact, ...]
    required_transition: str
    fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        family: str,
        stage: str,
        artifacts: tuple[ExtractedArtifact, ...],
        required_transition: str,
    ) -> ClosureObligation:
        normalized = {
            "family": family.strip().lower(),
            "stage": stage.strip().lower(),
            "artifacts": [artifact.to_json() for artifact in artifacts],
            "required_transition": required_transition.strip(),
        }
        fingerprint = hashlib.sha256(
            json.dumps(normalized, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return cls(
            family=str(normalized["family"]),
            stage=str(normalized["stage"]),
            artifacts=artifacts,
            required_transition=str(normalized["required_transition"]),
            fingerprint=fingerprint,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "family": self.family,
            "stage": self.stage,
            "artifacts": [artifact.to_json() for artifact in self.artifacts],
            "required_transition": self.required_transition,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> ClosureObligation:
        raw_artifacts = payload.get("artifacts")
        artifacts = (
            tuple(
                ExtractedArtifact.from_json(item)
                for item in raw_artifacts
                if isinstance(item, Mapping)
            )
            if isinstance(raw_artifacts, list)
            else ()
        )
        obligation = cls.create(
            family=str(payload.get("family") or ""),
            stage=str(payload.get("stage") or ""),
            artifacts=artifacts,
            required_transition=str(payload.get("required_transition") or ""),
        )
        stored = str(payload.get("fingerprint") or "")
        if stored and stored != obligation.fingerprint:
            message = "closure obligation fingerprint does not match its content"
            raise ValueError(message)
        return obligation


@dataclass(frozen=True)
class _SqlClosureEvidence:
    artifacts: tuple[ExtractedArtifact, ...]
    proof_seen: bool
    access_transition_seen: bool


def closure_obligation_from_observation(
    observation: str,
    *,
    family: str,
) -> ClosureObligation | None:
    if "sql" not in family.lower():
        return None
    payload = _structured_payload(observation)
    if not payload:
        return None
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return None

    evidence = _sql_closure_evidence(findings)
    if evidence.proof_seen or not evidence.artifacts:
        return None
    stage, transition = _closure_stage(evidence)
    return ClosureObligation.create(
        family=family,
        stage=stage,
        artifacts=evidence.artifacts,
        required_transition=transition,
    )


def _sql_closure_evidence(findings: list[object]) -> _SqlClosureEvidence:
    artifacts: list[ExtractedArtifact] = []
    proof_seen = False
    access_transition_seen = False
    for raw_finding in findings:
        if not isinstance(raw_finding, Mapping):
            continue
        proof_seen = proof_seen or _finding_has_proof(raw_finding)
        access_transition_seen = access_transition_seen or _finding_has_access(raw_finding)
        artifacts.extend(_finding_artifacts(raw_finding))
    return _SqlClosureEvidence(
        artifacts=tuple(dict.fromkeys(artifacts))[:20],
        proof_seen=proof_seen,
        access_transition_seen=access_transition_seen,
    )


def _finding_has_proof(finding: Mapping[str, object]) -> bool:
    if str(finding.get("type") or "").lower() == "sql_extracted_proof":
        return True
    proofs = finding.get("proofs")
    return isinstance(proofs, list) and any(str(item) for item in proofs)


def _finding_has_access(finding: Mapping[str, object]) -> bool:
    for key in ("login_attempts", "auth_bypass_attempts"):
        attempts = finding.get(key)
        if not isinstance(attempts, list):
            continue
        for attempt in attempts:
            if isinstance(attempt, Mapping) and _mapping_has_access(attempt):
                return True
            if isinstance(attempt, str) and _text_has_access(attempt):
                return True
    return False


def _finding_artifacts(
    finding: Mapping[str, object],
) -> list[ExtractedArtifact]:
    extracted = finding.get("extracted")
    if not isinstance(extracted, list):
        return []
    artifacts: list[ExtractedArtifact] = []
    for raw_artifact in extracted:
        if not isinstance(raw_artifact, Mapping):
            continue
        artifact = ExtractedArtifact.from_json(raw_artifact)
        if artifact.table and artifact.column and artifact.value:
            artifacts.append(artifact)
    return artifacts


def _closure_stage(evidence: _SqlClosureEvidence) -> tuple[str, str]:
    columns = {artifact.column.lower() for artifact in evidence.artifacts}
    if evidence.access_transition_seen:
        return (
            "objective_proof",
            (
                "Use the target-observed access transition to reach the shortest proof-bearing "
                "readback; do not re-run credential discovery."
            ),
        )
    if columns & _SECRET_COLUMNS:
        return (
            "authenticated_transition",
            (
                "Replay the extracted identifier/secret pair through the preserved request "
                "contract and verify a protected same-session access transition."
            ),
        )
    if columns & _IDENTIFIER_COLUMNS:
        return (
            "paired_secret",
            (
                "Use the preserved login contract and known identifier. First run one finite "
                "username-side and adjacent password-side SQL authentication-bypass matrix, "
                "preserving every required field and verifying explicit success plus protected "
                "same-session access. Emit AUTH_CASE[field]=payload, LOGIN_RESPONSE=body, and "
                "POST_LOGIN_URL=url for coordinator verification. Only if that bounded matrix "
                "is target-observed exhausted, continue the confirmed oracle at the same table "
                "and row to extract the paired secret; do not re-enumerate the known identifier "
                "or schema."
            ),
        )
    return (
        "objective_proof",
        (
            "Use the extracted target data as a stepping stone to one replayable access or "
            "proof transition; do not submit the intermediate value as proof."
        ),
    )


def remember_closure_obligation(
    state: AgentState,
    obligation: ClosureObligation,
) -> None:
    append_unique(
        state.signals.setdefault(_OBLIGATION_SIGNAL, []),
        json.dumps(obligation.to_json(), sort_keys=True),
        limit=_MAX_SIGNAL_ITEMS,
    )


def pending_closure_obligation(state: AgentState) -> ClosureObligation | None:
    attempted = set(state.signals.get(_ATTEMPT_SIGNAL, []))
    for raw in reversed(state.signals.get(_OBLIGATION_SIGNAL, [])):
        payload = _json_mapping(raw)
        if not payload:
            continue
        try:
            obligation = ClosureObligation.from_json(payload)
        except ValueError:
            continue
        if obligation.fingerprint not in attempted:
            return obligation
    return None


def action_advances_closure_obligation(
    action: Mapping[str, object],
    obligation: ClosureObligation,
) -> bool:
    kind = str(action.get("action") or "")
    if kind not in {"run_command", "run_python"}:
        return False
    source = str(action.get("command") or action.get("code") or "").lower()
    if not source or not any(marker in source for marker in _OPERATION_MARKERS):
        return False
    if obligation.stage == "paired_secret":
        return action_attempts_sql_auth_bypass(action) or (
            any(marker in source for marker in _SECRET_COLUMNS)
            and any(marker in source for marker in _EXTRACTION_MARKERS)
        )
    if obligation.stage == "authenticated_transition":
        return any(
            marker in source
            for marker in ("auth", "cookie", "dashboard", "login", "session", "upload")
        )
    return any(marker in source for marker in ("flag", "proof", "read", "shell", "upload", "file"))


def closure_obligation_completed_by_result(
    action: Mapping[str, object],
    obligation: ClosureObligation,
    *,
    tool_ok: bool,
    observation: str,
    checkpoint: object | None = None,
) -> bool:
    """Release an obligation only after trusted output advances its required stage."""
    if not tool_ok or not action_advances_closure_obligation(action, obligation):
        return False
    next_obligation = closure_obligation_from_observation(
        observation,
        family=obligation.family,
    )
    if (
        next_obligation is not None
        and next_obligation.fingerprint != obligation.fingerprint
        and next_obligation.stage != obligation.stage
    ):
        return True
    access_seen = _access_transition_seen(observation)
    if obligation.stage == "paired_secret":
        return access_seen or (
            closure_obligation_after_checkpoint(obligation, checkpoint) is not None
        )
    if obligation.stage == "authenticated_transition":
        return access_seen
    return access_seen or any(
        "flag{" in text.lower() for text in output_observation_texts(observation)
    )


def closure_obligation_after_checkpoint(
    obligation: ClosureObligation,
    checkpoint: object | None,
) -> ClosureObligation | None:
    """Advance a paired-secret stage without mistaking stored data for access."""
    if obligation.stage != "paired_secret" or checkpoint is None:
        return None
    checkpoint_kind = str(getattr(checkpoint, "candidate_kind", "")).lower()
    checkpoint_value = str(getattr(checkpoint, "prefix", ""))
    if (
        not bool(getattr(checkpoint, "complete", False))
        or checkpoint_kind not in _SECRET_COLUMNS
        or not checkpoint_value
    ):
        return None
    anchor = next(
        (
            artifact
            for artifact in obligation.artifacts
            if artifact.column.lower() in _IDENTIFIER_COLUMNS
        ),
        None,
    )
    if anchor is None:
        return None
    secret = ExtractedArtifact(
        table=anchor.table,
        column=checkpoint_kind,
        row=anchor.row,
        value=checkpoint_value,
    )
    artifacts = tuple(dict.fromkeys((*obligation.artifacts, secret)))
    stage, transition = _closure_stage(
        _SqlClosureEvidence(
            artifacts=artifacts,
            proof_seen=False,
            access_transition_seen=False,
        )
    )
    return ClosureObligation.create(
        family=obligation.family,
        stage=stage,
        artifacts=artifacts,
        required_transition=transition,
    )


def closure_obligation_objective(
    template: FrontierObjective,
    obligation: ClosureObligation,
) -> FrontierObjective:
    evidence_ref = f"{_CLOSURE_EVIDENCE_PREFIX}{obligation.fingerprint}"
    if evidence_ref in template.evidence_refs:
        return template
    payload_prefix = _closure_payload_prefix(template)
    evidence_refs = tuple(
        sorted(
            {
                evidence_ref,
                *(
                    item
                    for item in template.evidence_refs
                    if item.startswith(_STABLE_CLOSURE_EVIDENCE_PREFIXES)
                ),
            }
        )
    )
    return FrontierObjective.create(
        family=template.family,
        probe=template.probe,
        endpoint=template.endpoint,
        inputs=template.inputs,
        payload_class=(
            f"{payload_prefix}:closure_{obligation.stage}_{obligation.fingerprint[:16]}"
        ),
        expected_signal=(
            "Coordinator-owned bounded closure route for one evidence epoch. "
            f"{obligation.required_transition} Preserve prior target-observed contracts "
            "and artifacts, change only the required closure dimension, and return "
            "target evidence rather than another narrative handoff."
        ),
        evidence_refs=evidence_refs,
        basis=FrontierObjectiveBasis.MATERIAL_PROGRESS,
    )


def closure_objective_matches_obligation(
    objective: FrontierObjective,
    obligation: ClosureObligation,
) -> bool:
    return f"{_CLOSURE_EVIDENCE_PREFIX}{obligation.fingerprint}" in objective.evidence_refs


def closure_obligation_worker_attempted(
    state: AgentState,
    *,
    obligation: ClosureObligation,
    worker_id: str,
) -> bool:
    for attempt in state.attempts:
        if str(attempt.get("frontier_worker_id") or "") != worker_id:
            continue
        action = attempt.get("selected_action")
        if isinstance(action, Mapping) and action_advances_closure_obligation(
            action,
            obligation,
        ):
            return True
    return False


def closure_handoff_rejection_count(
    state: AgentState,
    *,
    obligation: ClosureObligation,
    worker_id: str,
) -> int:
    key = _closure_handoff_key(obligation, worker_id=worker_id)
    return state.signals.get(_HANDOFF_REJECTION_SIGNAL, []).count(key)


def record_closure_handoff_rejection(
    state: AgentState,
    *,
    obligation: ClosureObligation,
    worker_id: str,
) -> int:
    key = _closure_handoff_key(obligation, worker_id=worker_id)
    values = state.signals.setdefault(_HANDOFF_REJECTION_SIGNAL, [])
    values.append(key)
    del values[:-_MAX_SIGNAL_ITEMS]
    return values.count(key)


def _closure_handoff_key(
    obligation: ClosureObligation,
    *,
    worker_id: str,
) -> str:
    return f"{worker_id}:{obligation.fingerprint}"


def mark_closure_obligation_attempted(
    state: AgentState,
    obligation: ClosureObligation,
) -> None:
    append_unique(
        state.signals.setdefault(_ATTEMPT_SIGNAL, []),
        obligation.fingerprint,
        limit=_MAX_SIGNAL_ITEMS,
    )


def _access_transition_seen(observation: str) -> bool:
    if any(_mapping_has_access(payload) for payload in structured_output_mappings(observation)):
        return True
    return any(_text_has_access(text) for text in output_observation_texts(observation))


def _mapping_has_access(payload: Mapping[str, object]) -> bool:
    for raw_key, value in payload.items():
        key = str(raw_key).strip().lower()
        if key in _ACCESS_BOOLEAN_KEYS and _is_true(value):
            return True
        if key in _ACCESS_TITLE_KEYS and any(
            marker in str(value).strip().lower() for marker in _POSITIVE_TITLES
        ):
            return True
        if key in _ACCESS_URL_KEYS and any(
            marker in str(value).strip().lower() for marker in _PROTECTED_PATHS
        ):
            return True
        if key in {"body", "login_response", "response", "response_body"}:
            rendered = (
                json.dumps(dict(value), sort_keys=True)
                if isinstance(value, Mapping)
                else str(value)
            )
            if _SUCCESS_RESPONSE.search(rendered):
                return True
    return False


def _text_has_access(text: str) -> bool:
    if _SUCCESS_RESPONSE.search(text):
        return True
    for line in text.splitlines():
        stripped = line.strip()
        if (
            _BOOLEAN_ACCESS_LINE.fullmatch(stripped)
            or _TITLE_ACCESS_LINE.fullmatch(stripped)
            or _URL_ACCESS_LINE.fullmatch(stripped)
        ):
            return True
    lowered = text.lower()
    return "logout" in lowered and ("dashboard" in lowered or "upload" in lowered)


def _is_true(value: object) -> bool:
    if value is True:
        return True
    return isinstance(value, (int, str)) and str(value).strip().lower() in _TRUE_VALUES


def _closure_payload_prefix(template: FrontierObjective) -> str:
    parts = template.payload_class.split(":")
    if len(parts) >= _PRIMITIVE_PREFIX_PARTS and parts[0] == "confirmed_primitive":
        return ":".join(parts[:_PRIMITIVE_PREFIX_PARTS])
    return f"closure_route:{template.family}"


def closure_obligation_message(obligation: ClosureObligation) -> str:
    payload = json.dumps(obligation.to_json(), sort_keys=True)
    return (
        f"COORDINATOR_CLOSURE_OBLIGATION {payload}\n"
        "The latest trusted tool result is partial closure material, not objective proof. "
        f"{obligation.required_transition} Execute one focused target-observed action for "
        "this transition before handing control back. Global request, worker, repetition, "
        "scope, and cost limits remain enforced."
    )


def closure_obligation_context(state: AgentState) -> dict[str, object] | None:
    obligation = pending_closure_obligation(state)
    return obligation.to_json() if obligation is not None else None


def _structured_payload(text: str) -> dict[str, object]:
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        return dict(payload)

    decoder = json.JSONDecoder()
    for index, char in enumerate(text[:20_000]):
        if char != "{":
            continue
        try:
            candidate, _end = decoder.raw_decode(text[index:])
        except ValueError:
            continue
        if isinstance(candidate, dict) and isinstance(candidate.get("findings"), list):
            return dict(candidate)
    findings = _standalone_findings_array(text, decoder=decoder)
    if findings is not None:
        return {"findings": findings}
    return {}


def _standalone_findings_array(
    text: str,
    *,
    decoder: json.JSONDecoder,
) -> list[object] | None:
    marker = '"findings"'
    marker_index = text.find(marker)
    if marker_index < 0:
        return None
    array_index = text.find("[", marker_index + len(marker))
    if array_index < 0:
        return None
    try:
        findings, _end = decoder.raw_decode(text[array_index:])
    except ValueError:
        return None
    return findings if isinstance(findings, list) else None


def _json_mapping(raw: object) -> dict[str, object]:
    try:
        payload = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return dict(payload) if isinstance(payload, dict) else {}


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


__all__ = [
    "ClosureObligation",
    "ExtractedArtifact",
    "action_advances_closure_obligation",
    "closure_handoff_rejection_count",
    "closure_objective_matches_obligation",
    "closure_obligation_after_checkpoint",
    "closure_obligation_completed_by_result",
    "closure_obligation_context",
    "closure_obligation_from_observation",
    "closure_obligation_message",
    "closure_obligation_objective",
    "closure_obligation_worker_attempted",
    "mark_closure_obligation_attempted",
    "pending_closure_obligation",
    "record_closure_handoff_rejection",
    "remember_closure_obligation",
]
