from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.agent_state import append_unique
from ravage.agent_core.frontier_contract_memory import remembered_request_contracts
from ravage.agent_core.frontier_observation_text import output_observation_texts

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.frontier_closure_obligation import ClosureObligation

_ATTEMPT_SIGNAL = "frontier_auth_bypass_matrix_attempts"
_MAX_SIGNAL_ITEMS = 30
_EXECUTABLE_ACTIONS = frozenset({"run_command", "run_python"})
_REQUEST_MARKERS = ("curl", "http", "post(", "requests.", "urlopen", "urllib")
_SECRET_MARKERS = ("credential", "pass", "password", "secret", "token")
_EXTRACTION_MARKERS = ("ascii", "length", "select", "substring")
_AUTH_BYPASS_PREDICATES = (
    " or 1=1",
    " or '1'='1",
    ' or "1"="1',
    " or true",
    " union select",
)
_SQL_COMMENT_MARKERS = ("--", "#", "/*")
_UNBOUNDED_LOOP_MARKERS = ("while true", "while 1", "itertools.count(")
_TARGET_RESPONSE_MARKERS = (
    '"response"',
    "auth_case[",
    "login_body",
    "login_response",
    "post_login_",
)


@dataclass(frozen=True)
class AuthTransitionIssue:
    code: str
    obligation_fingerprint: str
    stage: str

    def to_json(self) -> dict[str, object]:
        return {
            "code": self.code,
            "obligation_fingerprint": self.obligation_fingerprint,
            "stage": self.stage,
        }


def action_attempts_sql_auth_bypass(action: Mapping[str, object]) -> bool:
    source = _action_source(action)
    return bool(
        source
        and "username" in source
        and "password" in source
        and any(marker in source for marker in _REQUEST_MARKERS)
        and any(marker in source for marker in _AUTH_BYPASS_PREDICATES)
        and any(marker in source for marker in _SQL_COMMENT_MARKERS)
        and not any(marker in source for marker in _UNBOUNDED_LOOP_MARKERS)
    )


def action_attempts_paired_secret_extraction(
    action: Mapping[str, object],
) -> bool:
    source = _action_source(action)
    return bool(
        source
        and any(marker in source for marker in _REQUEST_MARKERS)
        and any(marker in source for marker in _SECRET_MARKERS)
        and any(marker in source for marker in _EXTRACTION_MARKERS)
    )


def detect_auth_transition_issue(
    state: AgentState,
    *,
    obligation: ClosureObligation | None,
    action: Mapping[str, object],
) -> AuthTransitionIssue | None:
    if (
        obligation is None
        or obligation.stage != "paired_secret"
        or not _has_target_observed_login_contract(state)
        or not action_attempts_paired_secret_extraction(action)
        or auth_bypass_matrix_attempted(state, obligation)
    ):
        return None
    return AuthTransitionIssue(
        code="bounded_auth_bypass_required_before_secret_extraction",
        obligation_fingerprint=obligation.fingerprint,
        stage=obligation.stage,
    )


def remember_auth_bypass_matrix_attempt(
    state: AgentState,
    *,
    obligation: ClosureObligation | None,
    action: Mapping[str, object],
    observation: str,
) -> bool:
    if (
        obligation is None
        or not action_attempts_sql_auth_bypass(action)
        or not _target_response_observed(observation)
    ):
        return False
    values = state.signals.setdefault(_ATTEMPT_SIGNAL, [])
    if obligation.fingerprint in values:
        return False
    append_unique(values, obligation.fingerprint, limit=_MAX_SIGNAL_ITEMS)
    return True


def auth_bypass_matrix_attempted(
    state: AgentState,
    obligation: ClosureObligation,
) -> bool:
    return obligation.fingerprint in state.signals.get(_ATTEMPT_SIGNAL, [])


def auth_transition_guard_message(
    obligation: ClosureObligation,
    issue: AuthTransitionIssue,
) -> str:
    return (
        "COORDINATOR_AUTH_TRANSITION_GATE\n"
        "Action not executed. A known identifier plus a preserved login contract makes "
        "full blind-secret extraction the expensive branch, not the first branch. Run "
        "one finite username-side and adjacent password-side SQL authentication-bypass "
        "matrix first, preserving all required fields and one cookie jar. Require an "
        "explicit success response plus protected same-session access; a fresh cookie is "
        "not success. Emit AUTH_CASE[field]=payload, LOGIN_RESPONSE=body, and "
        "POST_LOGIN_URL=url from trusted output. If the bounded matrix is target-observed "
        "exhausted, paired-secret extraction is unlocked.\n"
        f"Reason: {issue.code}; stage={obligation.stage}. The rejected model request "
        "remains charged and all global request, worker, repetition, scope, and cost "
        "limits remain enforced."
    )


def _action_source(action: Mapping[str, object]) -> str:
    if str(action.get("action") or "") not in _EXECUTABLE_ACTIONS:
        return ""
    return str(action.get("command") or action.get("code") or "").lower()


def _has_target_observed_login_contract(state: AgentState) -> bool:
    for contract in remembered_request_contracts(state):
        if str(contract.get("method") or "").upper() != "POST":
            continue
        fields = contract.get("fields")
        if not isinstance(fields, list):
            continue
        names = {
            str(field.get("name") or "").strip().lower()
            for field in fields
            if isinstance(field, Mapping)
        }
        if names & {"username", "user", "email", "login"} and names & {
            "password",
            "pass",
            "passwd",
        }:
            return True
    return False


def _target_response_observed(observation: str) -> bool:
    return any(
        marker in text.lower()
        for text in output_observation_texts(observation)
        for marker in _TARGET_RESPONSE_MARKERS
    )


__all__ = [
    "AuthTransitionIssue",
    "action_attempts_paired_secret_extraction",
    "action_attempts_sql_auth_bypass",
    "auth_bypass_matrix_attempted",
    "auth_transition_guard_message",
    "detect_auth_transition_issue",
    "remember_auth_bypass_matrix_attempt",
]
