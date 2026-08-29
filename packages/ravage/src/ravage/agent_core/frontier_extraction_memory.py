from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState, append_unique
from ravage.agent_core.frontier_extractor_correctness import (
    detect_extractor_correctness_issue,
)
from ravage.agent_core.frontier_observation_text import output_observation_texts
from ravage.agent_core.frontier_proof_work import action_attempts_bounded_proof_work
from ravage.agent_core.frontier_route import (
    FrontierObjective,
    FrontierObjectiveBasis,
)
from ravage.agent_core.frontier_structured_observation import (
    structured_output_mappings,
)

_CHECKPOINT_SIGNAL = "frontier_sql_extraction_checkpoints"
_MAX_SIGNAL_ITEMS = 30
_MAX_VALUE_CHARS = 512
_MAX_EXPECTED_LENGTH = 4096
_EXTRACTED = re.compile(
    rf"(?im)\bEXTRACTED_(?P<kind>PASSWORD|SECRET|CREDENTIAL|VALUE|CHUNK)="
    rf"(?P<value>[^\r\n]{{1,{_MAX_VALUE_CHARS}}})"
)
_DIRECT_EXTRACTED = re.compile(
    rf"(?im)^(?P<kind>PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|VALUE)"
    rf"\s*[:=]\s*(?P<value>[^\r\n]{{1,{_MAX_VALUE_CHARS}}})$"
)
_PREFIX = re.compile(
    rf"(?im)\bPREFIX\[(?P<position>\d{{1,4}})\]="
    rf"(?P<value>[^\r\n]{{1,{_MAX_VALUE_CHARS}}})"
)
_SPACED_PREFIX = re.compile(
    rf"(?im)^PREFIX\s+(?P<position>\d{{1,4}})\s+"
    rf"(?P<value>[^\r\n]{{1,{_MAX_VALUE_CHARS}}})"
)
_CUMULATIVE_PREFIX = re.compile(
    rf"(?im)^(?:FINAL_)?PREFIX\s+"
    rf"(?P<value>(?!\d{{1,4}}\s)[^\r\n]{{1,{_MAX_VALUE_CHARS}}})$"
)
_COLON_PREFIX = re.compile(
    rf"(?im)^(?:FINAL_)?PREFIX\s*:\s*"
    rf"(?P<value>[^\r\n]{{1,{_MAX_VALUE_CHARS}}})$"
)
_PARTIAL = re.compile(
    rf"(?im)\bpos=(?P<position>\d{{1,4}})[^\r\n]*?\bpartial="
    rf"(?P<value>[^\r\n]{{1,{_MAX_VALUE_CHARS}}})"
)
_TARGET_LENGTH = re.compile(r"(?im)\bTARGET_LEN=(?P<length>\d{1,4})\b")
_CANDIDATE_KIND = re.compile(
    r"(?i)\b(password|passwd|secret|token|credential|flag|username|user|email|account)\b"
)


@dataclass(frozen=True)
class ExtractionCheckpoint:
    objective_fingerprint: str
    family: str
    endpoint: str
    candidate_kind: str
    position: int
    expected_length: int | None
    prefix: str
    complete: bool
    fingerprint: str

    @classmethod
    def create(  # noqa: PLR0913 - checkpoint identity is intentionally explicit.
        cls,
        *,
        objective_fingerprint: str,
        family: str,
        endpoint: str,
        candidate_kind: str,
        position: int,
        expected_length: int | None,
        prefix: str,
        complete: bool,
    ) -> ExtractionCheckpoint:
        payload = {
            "objective_fingerprint": objective_fingerprint,
            "family": family,
            "endpoint": endpoint,
            "candidate_kind": candidate_kind,
            "position": position,
            "expected_length": expected_length,
            "prefix": prefix,
            "complete": complete,
        }
        fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return cls(fingerprint=fingerprint, **payload)

    def to_json(self) -> dict[str, object]:
        return {
            "objective_fingerprint": self.objective_fingerprint,
            "family": self.family,
            "endpoint": self.endpoint,
            "candidate_kind": self.candidate_kind,
            "position": self.position,
            "expected_length": self.expected_length,
            "prefix": self.prefix,
            "complete": self.complete,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> ExtractionCheckpoint:
        raw_expected = payload.get("expected_length")
        checkpoint = cls.create(
            objective_fingerprint=str(payload.get("objective_fingerprint") or ""),
            family=str(payload.get("family") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            candidate_kind=str(payload.get("candidate_kind") or "value"),
            position=int(payload.get("position") or 0),
            expected_length=(int(raw_expected) if isinstance(raw_expected, int) else None),
            prefix=str(payload.get("prefix") or ""),
            complete=bool(payload.get("complete")),
        )
        stored = str(payload.get("fingerprint") or "")
        if stored and stored != checkpoint.fingerprint:
            raise ValueError
        return checkpoint

    @property
    def material_progress_token(self) -> str:
        return (
            "sql_extraction_checkpoint:"
            f"{self.objective_fingerprint[:16]}:{self.position}:"
            f"{self.fingerprint[:16]}"
        )


@dataclass(frozen=True)
class ExtractionMemoryUpdate:
    checkpoint: ExtractionCheckpoint | None = None
    material_progress: tuple[str, ...] = ()
    issue: ExtractionCheckpointIssue | None = None


@dataclass(frozen=True)
class ExtractionCheckpointIssue:
    code: str
    candidate_kind: str
    position: int

    def to_json(self) -> dict[str, object]:
        return {
            "code": self.code,
            "candidate_kind": self.candidate_kind,
            "position": self.position,
        }


def remember_extraction_checkpoint(
    state: AgentState,
    *,
    objective: FrontierObjective,
    action: Mapping[str, object],
    observation: str,
    oracle_calibrated: bool = False,
) -> ExtractionMemoryUpdate:
    checkpoint = extraction_checkpoint_from_observation(
        objective=objective,
        action=action,
        observation=observation,
    )
    if checkpoint is None:
        return ExtractionMemoryUpdate()
    if not oracle_calibrated:
        return ExtractionMemoryUpdate(
            issue=ExtractionCheckpointIssue(
                code="checkpoint_without_calibrated_oracle",
                candidate_kind=checkpoint.candidate_kind,
                position=checkpoint.position,
            )
        )
    previous = latest_extraction_checkpoint(state, objective=objective)
    if previous is not None:
        if checkpoint.position <= previous.position:
            return ExtractionMemoryUpdate()
        if not checkpoint.prefix.startswith(previous.prefix):
            return ExtractionMemoryUpdate()
    append_unique(
        state.signals.setdefault(_CHECKPOINT_SIGNAL, []),
        json.dumps(checkpoint.to_json(), sort_keys=True),
        limit=_MAX_SIGNAL_ITEMS,
    )
    return ExtractionMemoryUpdate(
        checkpoint=checkpoint,
        material_progress=(checkpoint.material_progress_token,),
    )


def extraction_calibration_objective(
    objective: FrontierObjective,
    issue: ExtractionCheckpointIssue,
) -> FrontierObjective:
    evidence_ref = f"coordinator:{issue.code}"
    return FrontierObjective.create(
        family=objective.family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=(
            "Calibrate the exact request contract with repeated target-observed true "
            "predicates 1=1 and 2=2 and false predicates 1=0 and 2=1, then run one "
            "bounded finite extractor using only that stable mapping. UNION/error or "
            "baseline responses cannot define truth, and uncalibrated prefixes are not "
            "progress."
        ),
        evidence_refs=tuple(dict.fromkeys((*objective.evidence_refs, evidence_ref))),
        basis=FrontierObjectiveBasis.NOVEL_COUNTERFACTUAL,
    )


def extraction_checkpoint_issue_message(
    objective: FrontierObjective,
    issue: ExtractionCheckpointIssue,
) -> str:
    return (
        "COORDINATOR_EXTRACTION_CHECKPOINT_GUARD\n"
        "The tool output emitted an extraction prefix, but no repeated target-observed "
        "tautology/contradiction mapping established which response means true. The "
        "prefix was quarantined and cannot open a proof lease.\n"
        f"Reason: {issue.code}; candidate_kind={issue.candidate_kind}; "
        f"position={issue.position}; endpoint={objective.endpoint}. Calibrate 1=1 and "
        "2=2 against 1=0 and 2=1, then rerun a bounded extractor. The model request "
        "remains charged and all global request, worker, scope, and cost limits remain "
        "enforced."
    )


def extraction_checkpoint_from_observation(  # noqa: C901, PLR0912
    *,
    objective: FrontierObjective,
    action: Mapping[str, object],
    observation: str,
) -> ExtractionCheckpoint | None:
    if (
        objective.family != "sql_injection"
        or not objective.payload_class.startswith("confirmed_primitive:")
        or not action_attempts_bounded_proof_work(action)
        or detect_extractor_correctness_issue(objective, action) is not None
    ):
        return None
    source = str(action.get("code") or action.get("command") or "")
    candidate_kind = _candidate_kind(source)
    candidates: list[tuple[int, str, str, bool]] = []
    expected_length: int | None = None
    candidates.extend(_structured_extraction_candidates(observation))
    for text in output_observation_texts(observation):
        for match in _TARGET_LENGTH.finditer(text):
            value = int(match.group("length"))
            if 0 < value <= _MAX_EXPECTED_LENGTH:
                expected_length = value
        for match in _EXTRACTED.finditer(text):
            value = _clean_value(match.group("value"))
            if value:
                kind = match.group("kind").lower()
                candidates.append((len(value), value, kind, kind != "chunk"))
        for match in _DIRECT_EXTRACTED.finditer(text):
            value = _clean_value(match.group("value"))
            if value:
                candidates.append((len(value), value, match.group("kind").lower(), True))
        for pattern in (_PREFIX, _SPACED_PREFIX, _PARTIAL):
            for match in pattern.finditer(text):
                position = int(match.group("position"))
                value = _clean_value(match.group("value"))
                if value and position == len(value):
                    candidates.append((position, value, candidate_kind, False))
        for match in _CUMULATIVE_PREFIX.finditer(text):
            value = _clean_value(match.group("value"))
            if value:
                candidates.append(
                    (len(value), value, candidate_kind, False),
                )
        for match in _COLON_PREFIX.finditer(text):
            value = _clean_value(match.group("value"))
            if value:
                candidates.append((len(value), value, candidate_kind, False))
    if not candidates:
        return None
    position, prefix, kind, complete_marker = max(
        candidates,
        key=lambda item: (item[0], item[3]),
    )
    if position <= 0 or position > _MAX_EXPECTED_LENGTH:
        return None
    if complete_marker and expected_length is None:
        expected_length = position
    complete = complete_marker or (expected_length is not None and position == expected_length)
    return ExtractionCheckpoint.create(
        objective_fingerprint=objective.fingerprint,
        family=objective.family,
        endpoint=objective.endpoint,
        candidate_kind=kind or candidate_kind,
        position=position,
        expected_length=expected_length,
        prefix=prefix,
        complete=complete,
    )


def remembered_extraction_checkpoints(
    state: AgentState,
    *,
    objective: FrontierObjective | None = None,
) -> list[dict[str, object]]:
    checkpoints: list[dict[str, object]] = []
    for raw in state.signals.get(_CHECKPOINT_SIGNAL, [])[-12:]:
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                continue
            checkpoint = ExtractionCheckpoint.from_json(payload)
        except (TypeError, ValueError):
            continue
        if objective is not None and not _checkpoint_matches_objective(
            checkpoint,
            objective,
        ):
            continue
        checkpoints.append(checkpoint.to_json())
    return checkpoints[-4:]


def latest_extraction_checkpoint(
    state: AgentState,
    *,
    objective: FrontierObjective,
) -> ExtractionCheckpoint | None:
    payloads = remembered_extraction_checkpoints(state, objective=objective)
    if not payloads:
        return None
    try:
        return ExtractionCheckpoint.from_json(payloads[-1])
    except ValueError:
        return None


def _checkpoint_matches_objective(
    checkpoint: ExtractionCheckpoint,
    objective: FrontierObjective,
) -> bool:
    if checkpoint.family != objective.family:
        return False
    checkpoint_path = _normalized_path(checkpoint.endpoint)
    objective_path = _normalized_path(objective.endpoint)
    return objective_path in {"/", checkpoint_path}


def _normalized_path(value: str) -> str:
    path = urlsplit(value).path.strip()
    return f"/{path.strip('/')}" if path else "/"


def _candidate_kind(source: str) -> str:
    matches = tuple(_CANDIDATE_KIND.finditer(source))
    if not matches:
        return "value"
    kind = matches[-1].group(1).lower()
    return "username" if kind in {"user", "email", "account"} else kind


def _structured_extraction_candidates(
    observation: str,
) -> list[tuple[int, str, str, bool]]:
    candidates: list[tuple[int, str, str, bool]] = []
    for payload in structured_output_mappings(observation):
        extracted = payload.get("extracted")
        if not isinstance(extracted, list):
            continue
        for raw_artifact in extracted:
            if not isinstance(raw_artifact, Mapping):
                continue
            column = str(raw_artifact.get("column") or "").strip().lower()
            raw_value = raw_artifact.get("value")
            if not column or raw_value is None:
                continue
            value = _clean_value(str(raw_value))
            if not value or len(value) > _MAX_EXPECTED_LENGTH:
                continue
            candidates.append(
                (
                    len(value),
                    value,
                    _normalized_candidate_kind(column),
                    True,
                )
            )
    return candidates


def _normalized_candidate_kind(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    aliases = {
        "account": "username",
        "email": "username",
        "pass": "password",
        "passwd": "password",
        "user": "username",
    }
    return aliases.get(normalized, normalized or "value")


def _clean_value(value: str) -> str:
    return value.strip().strip("'\"")[:_MAX_VALUE_CHARS]


__all__ = [
    "ExtractionCheckpoint",
    "ExtractionCheckpointIssue",
    "ExtractionMemoryUpdate",
    "extraction_calibration_objective",
    "extraction_checkpoint_from_observation",
    "extraction_checkpoint_issue_message",
    "latest_extraction_checkpoint",
    "remember_extraction_checkpoint",
    "remembered_extraction_checkpoints",
]
