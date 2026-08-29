from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import append_unique
from ravage.agent_core.frontier_observation_text import output_observation_texts

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.frontier_route import FrontierObjective

_ISSUE_SIGNAL = "frontier_oracle_calibration_issues"
_RESOLVED_SIGNAL = "frontier_oracle_calibration_resolved"
_MAX_SIGNAL_ITEMS = 30
_CALIBRATION_LINE = re.compile(
    r"(?im)^CAL\s+(?P<label>[A-Za-z0-9_-]{1,64})\s+"
    r"(?P<signature>[^\r\n]{1,2000})"
)
_CONTROL_LINE = re.compile(
    r"(?im)^CONTROL_(?P<label>TRUE|FALSE)\s+"
    r"(?P<signature>[^\r\n]{1,2000})"
)
_TRUE_LABELS = frozenset({"t", "true", "bool_true", "ctrl_true"})
_FALSE_LABELS = frozenset({"f", "false", "bool_false", "ctrl_false"})


@dataclass(frozen=True)
class OracleCalibrationIssue:
    objective_fingerprint: str
    family: str
    endpoint: str
    true_labels: tuple[str, ...]
    false_labels: tuple[str, ...]
    shared_signature_digest: str
    fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        objective: FrontierObjective,
        true_labels: tuple[str, ...],
        false_labels: tuple[str, ...],
        shared_signature: str,
    ) -> OracleCalibrationIssue:
        payload = {
            "objective_fingerprint": objective.fingerprint,
            "family": objective.family,
            "endpoint": objective.endpoint,
            "true_labels": true_labels,
            "false_labels": false_labels,
            "shared_signature_digest": hashlib.sha256(shared_signature.encode("utf-8")).hexdigest(),
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
            "true_labels": list(self.true_labels),
            "false_labels": list(self.false_labels),
            "shared_signature_digest": self.shared_signature_digest,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_json(cls, payload: dict[str, object]) -> OracleCalibrationIssue:
        issue = cls(
            objective_fingerprint=str(payload.get("objective_fingerprint") or ""),
            family=str(payload.get("family") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            true_labels=_string_tuple(payload.get("true_labels")),
            false_labels=_string_tuple(payload.get("false_labels")),
            shared_signature_digest=str(payload.get("shared_signature_digest") or ""),
            fingerprint=str(payload.get("fingerprint") or ""),
        )
        expected = hashlib.sha256(
            json.dumps(
                {
                    "objective_fingerprint": issue.objective_fingerprint,
                    "family": issue.family,
                    "endpoint": issue.endpoint,
                    "true_labels": issue.true_labels,
                    "false_labels": issue.false_labels,
                    "shared_signature_digest": issue.shared_signature_digest,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        if not issue.fingerprint or issue.fingerprint != expected:
            raise ValueError
        return issue


@dataclass(frozen=True)
class OracleCalibrationAssessment:
    issue: OracleCalibrationIssue | None = None
    calibrated: bool = False


def assess_oracle_calibration(
    objective: FrontierObjective,
    observation: str,
) -> OracleCalibrationAssessment:
    if objective.family != "sql_injection" or not objective.payload_class.startswith(
        "confirmed_primitive:"
    ):
        return OracleCalibrationAssessment()
    true_signatures: list[str] = []
    false_signatures: list[str] = []
    true_labels: list[str] = []
    false_labels: list[str] = []
    for text in output_observation_texts(observation):
        for pattern in (_CALIBRATION_LINE, _CONTROL_LINE):
            for match in pattern.finditer(text):
                label = match.group("label").lower().replace("-", "_")
                signature = _normalized_signature(match.group("signature"))
                if _is_true_label(label):
                    true_labels.append(label)
                    true_signatures.append(signature)
                elif _is_false_label(label):
                    false_labels.append(label)
                    false_signatures.append(signature)
    if not true_signatures or not false_signatures:
        return OracleCalibrationAssessment()
    signatures = {*true_signatures, *false_signatures}
    if len(signatures) == 1:
        return OracleCalibrationAssessment(
            issue=OracleCalibrationIssue.create(
                objective=objective,
                true_labels=tuple(dict.fromkeys(true_labels)),
                false_labels=tuple(dict.fromkeys(false_labels)),
                shared_signature=signatures.pop(),
            )
        )
    if set(true_signatures).isdisjoint(false_signatures):
        return OracleCalibrationAssessment(calibrated=True)
    return OracleCalibrationAssessment()


def remember_oracle_calibration_issue(
    state: AgentState,
    issue: OracleCalibrationIssue,
) -> None:
    append_unique(
        state.signals.setdefault(_ISSUE_SIGNAL, []),
        json.dumps(issue.to_json(), sort_keys=True),
        limit=_MAX_SIGNAL_ITEMS,
    )


def resolve_oracle_calibration_issues(
    state: AgentState,
    *,
    objective: FrontierObjective,
) -> tuple[str, ...]:
    resolved = set(state.signals.get(_RESOLVED_SIGNAL, []))
    newly_resolved = tuple(
        issue.fingerprint
        for issue in _remembered_issues(state)
        if issue.fingerprint not in resolved and _issue_matches_objective(issue, objective)
    )
    for fingerprint in newly_resolved:
        append_unique(
            state.signals.setdefault(_RESOLVED_SIGNAL, []),
            fingerprint,
            limit=_MAX_SIGNAL_ITEMS,
        )
    return newly_resolved


def pending_oracle_calibration_issue(
    state: AgentState,
    *,
    objective: FrontierObjective,
) -> OracleCalibrationIssue | None:
    resolved = set(state.signals.get(_RESOLVED_SIGNAL, []))
    for issue in reversed(_remembered_issues(state)):
        if issue.fingerprint in resolved:
            continue
        if _issue_matches_objective(issue, objective):
            return issue
    return None


def remembered_oracle_calibration_issues(
    state: AgentState,
    *,
    objective: FrontierObjective,
) -> list[dict[str, object]]:
    resolved = set(state.signals.get(_RESOLVED_SIGNAL, []))
    return [
        issue.to_json()
        for issue in _remembered_issues(state)
        if issue.fingerprint not in resolved and _issue_matches_objective(issue, objective)
    ][-4:]


def oracle_calibration_constraints(
    objective: FrontierObjective,
) -> tuple[str, ...]:
    if objective.family != "sql_injection" or not objective.payload_class.startswith(
        "confirmed_primitive:"
    ):
        return ()
    return (
        (
            "Before extraction, require repeated tautology and contradiction controls to "
            "produce distinct target-observed signatures."
        ),
        (
            "If both controls match, change the injection prefix/closure so the baseline "
            "prefix cannot independently select a row; do not enumerate characters yet."
        ),
    )


def oracle_calibration_message(
    objective: FrontierObjective,
    issue: OracleCalibrationIssue,
) -> str:
    del issue
    return (
        "COORDINATOR_ORACLE_CALIBRATION_GATE\n"
        "The target produced identical signatures for the labeled tautology and "
        "contradiction controls, so this is not a usable Boolean oracle and any derived "
        "prefix is invalid. Keep the observed request contract fixed, but change the "
        "injection prefix/closure so the prefix cannot independently match a baseline "
        f"row on endpoint={objective.endpoint}; then repeat at least two true/false "
        "control pairs. Do not enumerate characters or hand off until target-observed "
        "controls diverge. The model request remains charged; global request, worker, "
        "scope, and cost limits remain enforced."
    )


def oracle_calibration_resolved_message() -> str:
    return (
        "COORDINATOR_ORACLE_CALIBRATION_RESOLVED\n"
        "Target-observed true and false control signatures now diverge. Continue with "
        "the same calibrated request contract and bounded extraction."
    )


def _remembered_issues(state: AgentState) -> list[OracleCalibrationIssue]:
    issues: list[OracleCalibrationIssue] = []
    for raw in state.signals.get(_ISSUE_SIGNAL, [])[-12:]:
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                issues.append(OracleCalibrationIssue.from_json(payload))
        except (TypeError, ValueError):
            continue
    return issues


def _issue_matches_objective(
    issue: OracleCalibrationIssue,
    objective: FrontierObjective,
) -> bool:
    if issue.family != objective.family:
        return False
    issue_path = _normalized_path(issue.endpoint)
    objective_path = _normalized_path(objective.endpoint)
    return objective_path in {"/", issue_path}


def _is_true_label(label: str) -> bool:
    return label in _TRUE_LABELS or label.endswith("_true")


def _is_false_label(label: str) -> bool:
    return label in _FALSE_LABELS or label.endswith("_false")


def _normalized_signature(value: str) -> str:
    return " ".join(value.split())


def _normalized_path(value: str) -> str:
    path = urlsplit(value).path.strip()
    return f"/{path.strip('/')}" if path else "/"


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if str(item))


__all__ = [
    "OracleCalibrationAssessment",
    "OracleCalibrationIssue",
    "assess_oracle_calibration",
    "oracle_calibration_constraints",
    "oracle_calibration_message",
    "oracle_calibration_resolved_message",
    "pending_oracle_calibration_issue",
    "remember_oracle_calibration_issue",
    "remembered_oracle_calibration_issues",
    "resolve_oracle_calibration_issues",
]
