from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import unquote_plus, urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ravage.agent_core.frontier_route import FrontierObjective

_GUARD_PREFIX = "COORDINATOR_OBJECTIVE_ALIGNMENT_GUARD"
_CONFIRMED_PREFIX = "confirmed_primitive:"
_MIN_FAMILY_TOKEN_CHARS = 4
_REQUEST_MARKERS = (
    "curl",
    "fetch(",
    "http",
    "request(",
    "requests.",
    "urlopen",
    "urllib",
    "method=",
    'method":',
    "method':",
    " post ",
    " get ",
)
_PROOF_MARKERS = (
    "admin",
    "credential",
    "dashboard",
    "extract",
    "flag",
    "login",
    "password",
    "proof",
    "readback",
    "secret",
    "session",
    "upload",
)
_FAMILY_MARKERS: dict[str, tuple[str, ...]] = {
    "sql_injection": (
        "ascii(",
        "benchmark(",
        "boolean",
        "database",
        "information_schema",
        "mysql",
        "oracle",
        "payload",
        "postgres",
        "select ",
        "sleep(",
        "sql",
        "substr",
        "substring",
        "union ",
    ),
    "xml_external_entity": (
        "doctype",
        "entity",
        "file://",
        "soap",
        "svg",
        "xml",
        "xxe",
    ),
    "template_injection": (
        "${",
        "{{",
        "freemarker",
        "jinja",
        "ssti",
        "template",
        "twig",
    ),
    "path_traversal": ("../", "file", "path", "read", "traversal"),
    "server_side_request_forgery": (
        "fetch",
        "internal",
        "localhost",
        "metadata",
        "ssrf",
        "url",
    ),
}
_NARRATIVE_FIELDS = frozenset(
    {"expected_signal", "hypotheses", "memory_updates", "strategy", "summary"}
)
_SQL_BOOLEAN_PAYLOAD = re.compile(
    r"(?is)['\"]\s*(?:or|and)\s+(?:['\"(]|\d)|\b(?:union\s+select|order\s+by)\b"
)


@dataclass(frozen=True)
class ObjectiveAlignmentIssue:
    code: str
    action_kind: str
    missing_dimensions: tuple[str, ...]
    objective_fingerprint: str

    def to_json(self) -> dict[str, object]:
        return {
            "code": self.code,
            "action_kind": self.action_kind,
            "missing_dimensions": list(self.missing_dimensions),
            "objective_fingerprint": self.objective_fingerprint,
        }


def objective_requires_aligned_action(objective: FrontierObjective) -> bool:
    return objective.payload_class.startswith(_CONFIRMED_PREFIX)


def detect_objective_alignment_issue(  # noqa: C901, PLR0911, PLR0912
    objective: FrontierObjective,
    action: Mapping[str, object],
) -> ObjectiveAlignmentIssue | None:
    """Reject tool work that cannot advance a confirmed-primitive assignment."""
    if not objective_requires_aligned_action(objective):
        return None

    action_kind = str(action.get("action") or "").strip()
    if action_kind in {"final", "capture_flag"}:
        return None
    if action_kind == "run_probe":
        probe = str(action.get("probe") or "").strip()
        if probe == objective.probe:
            if "do not rerun it unchanged" not in objective.expected_signal.lower():
                return None
            return _issue(
                objective,
                action_kind,
                code="unchanged_specialist_route",
                missing=("materially_changed_execution",),
            )
        if _family_present(_execution_source(action), objective.family):
            return None
        return _issue(
            objective,
            action_kind,
            code="unrelated_specialist",
            missing=("assigned_family",),
        )
    if action_kind not in {"run_command", "run_python", "validate_poc"}:
        return _issue(
            objective,
            action_kind or "invalid",
            code="non_executable_action",
            missing=("scoped_target_action",),
        )

    source = _execution_source(action)
    missing: list[str] = []
    if not _endpoint_present(source, objective.endpoint):
        missing.append("assigned_endpoint")

    dimension = _objective_dimension(objective)
    present_inputs = tuple(item for item in objective.inputs if _token_present(source, item))
    if objective.inputs:
        if dimension == "request_contract":
            if len(present_inputs) != len(objective.inputs):
                missing.append("assigned_inputs")
        elif not present_inputs:
            missing.append("assigned_input")

    if dimension == "request_contract":
        if not any(marker in source for marker in _REQUEST_MARKERS):
            missing.append("request_execution")
    elif dimension == "payload_semantics":
        if not _family_present(source, objective.family):
            missing.append("changed_payload_semantics")
    elif dimension == "proof_channel":
        if not any(marker in source for marker in _PROOF_MARKERS):
            missing.append("proof_or_access_transition")
    elif not _family_present(source, objective.family):
        missing.append("assigned_family")

    if not missing:
        return None
    return _issue(
        objective,
        action_kind,
        code="objective_drift",
        missing=tuple(missing),
    )


def alignment_guard_message(
    objective: FrontierObjective,
    issue: ObjectiveAlignmentIssue,
) -> str:
    missing = ", ".join(issue.missing_dimensions)
    inputs = ", ".join(objective.inputs) or "none recorded"
    return (
        f"{_GUARD_PREFIX}\n"
        "Action not executed. This model request remains charged against the global "
        "and worker budgets.\n"
        f"Reason: {issue.code}; missing objective dimensions: {missing}.\n"
        f"Stay on family={objective.family}, endpoint={objective.endpoint or 'root'}, "
        f"inputs={inputs}, dimension={_objective_dimension(objective)}.\n"
        "Return one executable action that materially tests this assignment; do not "
        "switch to a different discovery branch."
    )


def missing_aligned_action_issue(
    objective: FrontierObjective,
) -> ObjectiveAlignmentIssue:
    return _issue(
        objective,
        "final",
        code="handoff_before_aligned_action",
        missing=("objective_aligned_target_observation",),
    )


def _issue(
    objective: FrontierObjective,
    action_kind: str,
    *,
    code: str,
    missing: tuple[str, ...],
) -> ObjectiveAlignmentIssue:
    return ObjectiveAlignmentIssue(
        code=code,
        action_kind=action_kind,
        missing_dimensions=missing,
        objective_fingerprint=objective.fingerprint,
    )


def _execution_source(action: Mapping[str, object]) -> str:
    action_kind = str(action.get("action") or "")
    if action_kind == "run_command":
        value: object = action.get("command")
    elif action_kind == "run_python":
        value = action.get("code")
    elif action_kind == "validate_poc":
        value = action.get("steps")
    else:
        value = {key: item for key, item in action.items() if key not in _NARRATIVE_FIELDS}
    if isinstance(value, str):
        raw = value.lower()
        decoded = unquote_plus(raw)
        return raw if decoded == raw else f"{raw}\n{decoded}"
    return json.dumps(value, default=str, sort_keys=True).lower()


def _objective_dimension(objective: FrontierObjective) -> str:
    return objective.payload_class.rsplit(":", maxsplit=1)[-1]


def _endpoint_present(source: str, endpoint: str) -> bool:
    path = urlsplit(endpoint).path if "://" in endpoint else endpoint
    path = "/" + path.lstrip("/")
    if path in {"", "/"}:
        return True
    needle = re.escape(path.lstrip("/").lower())
    pattern = rf"(?<![a-z0-9_.~%-])/?{needle}(?=$|[/?#&=:'\"\s)\],+])"
    return re.search(pattern, source) is not None


def _token_present(source: str, token: str) -> bool:
    value = token.strip().lower()
    if not value:
        return False
    return re.search(rf"(?<![a-z0-9_-]){re.escape(value)}(?![a-z0-9_-])", source) is not None


def _family_present(source: str, family: str) -> bool:
    if family == "sql_injection" and _SQL_BOOLEAN_PAYLOAD.search(source):
        return True
    markers = _FAMILY_MARKERS.get(family, ())
    if markers:
        return any(marker in source for marker in markers)
    return any(
        _token_present(source, item)
        for item in family.replace("-", "_").split("_")
        if len(item) >= _MIN_FAMILY_TOKEN_CHARS
    )


__all__ = [
    "ObjectiveAlignmentIssue",
    "alignment_guard_message",
    "detect_objective_alignment_issue",
    "missing_aligned_action_issue",
    "objective_requires_aligned_action",
]
