from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.agent_state import append_unique
from ravage.agent_core.frontier_observation_text import output_observation_texts
from ravage.agent_core.frontier_structured_observation import (
    structured_output_mappings,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.frontier_extraction_memory import ExtractionCheckpoint
    from ravage.agent_core.frontier_route import FrontierObjective

_REJECTION_SIGNAL = "frontier_rejected_credential_replays"
_MAX_SIGNAL_ITEMS = 30
_LOGIN_RESPONSE = re.compile(
    r"(?im)\bLOGIN_(?:RESPONSE|BODY)\s*[:=]\s*(?P<response>[^\r\n]{1,512})"
)
_RAW_JSON_RESPONSE = re.compile(r'(?i)\{\s*"response"\s*:\s*"(?P<response>[^"\r\n]{1,256})"\s*\}')
_FAILURE_MARKERS = (
    "invalid",
    "password",
    "username",
    "unauthorized",
    "forbidden",
    "failed",
    "sign in",
)
_SUCCESS_MARKERS = ("success", "authenticated", "dashboard", "logged in")
_HEX_SHAPES = frozenset({32, 40, 64, 96, 128})
_REPLAY_CANDIDATE_FIELDS = frozenset(
    {"candidate", "credential", "pass", "passwd", "password", "secret", "value"}
)
_REPLAY_RESPONSE_FIELDS = (
    "body",
    "login_body",
    "login_response",
    "response",
    "response_body",
)


@dataclass(frozen=True)
class RejectedCredentialReplay:
    objective_fingerprint: str
    family: str
    endpoint: str
    candidate_kind: str
    candidate_length: int
    candidate_digest: str
    representation_hint: str
    failure_marker: str
    fingerprint: str

    @classmethod
    def create(  # noqa: PLR0913 - replay identity is intentionally explicit.
        cls,
        *,
        objective_fingerprint: str,
        family: str,
        endpoint: str,
        candidate_kind: str,
        candidate: str,
        failure_marker: str,
    ) -> RejectedCredentialReplay:
        candidate_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        representation_hint = (
            "hash_shaped"
            if len(candidate) in _HEX_SHAPES
            and all(character in "0123456789abcdefABCDEF" for character in candidate)
            else "stored_value"
        )
        payload = {
            "objective_fingerprint": objective_fingerprint,
            "family": family,
            "endpoint": endpoint,
            "candidate_kind": candidate_kind,
            "candidate_length": len(candidate),
            "candidate_digest": candidate_digest,
            "representation_hint": representation_hint,
            "failure_marker": failure_marker,
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
            "candidate_length": self.candidate_length,
            "candidate_digest": self.candidate_digest,
            "representation_hint": self.representation_hint,
            "failure_marker": self.failure_marker,
            "fingerprint": self.fingerprint,
        }


def detect_rejected_credential_replay(
    *,
    objective: FrontierObjective,
    checkpoint: ExtractionCheckpoint | None,
    action: Mapping[str, object] | None = None,
    observation: str,
) -> RejectedCredentialReplay | None:
    if (
        checkpoint is None
        or objective.family != "sql_injection"
        or checkpoint.candidate_kind not in {"password", "passwd", "secret", "credential"}
    ):
        return None
    raw_response_allowed = _action_replays_checkpoint(action, checkpoint)
    responses = list(_structured_replay_responses(observation, checkpoint))
    for text in output_observation_texts(observation):
        matches = list(_LOGIN_RESPONSE.finditer(text))
        if raw_response_allowed:
            matches.extend(_RAW_JSON_RESPONSE.finditer(text))
        responses.extend(match.group("response").strip() for match in matches)
    for response in dict.fromkeys(responses):
        lowered = response.lower()
        if any(marker in lowered for marker in _SUCCESS_MARKERS):
            continue
        failure = next(
            (marker for marker in _FAILURE_MARKERS if marker in lowered),
            "",
        )
        if not failure:
            continue
        return RejectedCredentialReplay.create(
            objective_fingerprint=objective.fingerprint,
            family=objective.family,
            endpoint=objective.endpoint,
            candidate_kind=checkpoint.candidate_kind,
            candidate=checkpoint.prefix,
            failure_marker=failure,
        )
    return None


def _structured_replay_responses(
    observation: str,
    checkpoint: ExtractionCheckpoint,
) -> tuple[str, ...]:
    responses: list[str] = []
    for payload in structured_output_mappings(observation):
        if not _structured_mapping_replays_checkpoint(payload, checkpoint):
            continue
        for field in _REPLAY_RESPONSE_FIELDS:
            value = payload.get(field)
            if isinstance(value, Mapping):
                responses.append(json.dumps(dict(value), sort_keys=True))
            elif isinstance(value, str) and value.strip():
                responses.append(value.strip())
    return tuple(dict.fromkeys(responses))


def _structured_mapping_replays_checkpoint(
    payload: Mapping[str, object],
    checkpoint: ExtractionCheckpoint,
) -> bool:
    for key, value in payload.items():
        if str(key).lower() not in _REPLAY_CANDIDATE_FIELDS:
            continue
        if str(value) == checkpoint.prefix:
            return True
    return False


def _action_replays_checkpoint(
    action: Mapping[str, object] | None,
    checkpoint: ExtractionCheckpoint,
) -> bool:
    if action is None or str(action.get("action") or "") not in {
        "run_command",
        "run_python",
    }:
        return False
    source = str(action.get("command") or action.get("code") or "")
    if not checkpoint.prefix or checkpoint.prefix not in source:
        return False
    lowered = source.lower()
    return any(marker in lowered for marker in ("curl", "http", "post(", "requests."))


def remember_rejected_credential_replay(
    state: AgentState,
    replay: RejectedCredentialReplay,
) -> bool:
    encoded = json.dumps(replay.to_json(), sort_keys=True)
    values = state.signals.setdefault(_REJECTION_SIGNAL, [])
    if encoded in values:
        return False
    append_unique(values, encoded, limit=_MAX_SIGNAL_ITEMS)
    return True


def remembered_rejected_credential_replays(
    state: AgentState,
    *,
    objective: FrontierObjective | None = None,
) -> list[dict[str, object]]:
    replays: list[dict[str, object]] = []
    for raw in state.signals.get(_REJECTION_SIGNAL, [])[-12:]:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        if objective is not None and str(payload.get("family") or "") != (objective.family):
            continue
        replays.append(dict(payload))
    return replays[-4:]


def rejected_credential_replay_message(replay: RejectedCredentialReplay) -> str:
    return (
        "COORDINATOR_CREDENTIAL_REPRESENTATION_GATE\n"
        "The target rejected the just-extracted value when it was replayed as a "
        f"{replay.candidate_kind} ({replay.representation_hint}, length="
        f"{replay.candidate_length}). It is target data, but not a validated plaintext "
        "credential. Keep the observed request contract and same session; change one "
        "material authentication dimension next—representation/transform or an adjacent "
        "request field/sink—and require a target-observed success/session transition. "
        "Do not promote the rejected value or switch to an unrelated vulnerability "
        "family. Worker lease, global request, scope, and cost limits remain enforced."
    )


def rejected_credential_replay_constraints(
    state: AgentState,
    *,
    objective: FrontierObjective,
) -> tuple[str, ...]:
    replays = remembered_rejected_credential_replays(state, objective=objective)
    if not replays:
        return ()
    latest = replays[-1]
    return (
        (
            "A target-observed login response rejected the extracted candidate when replayed "
            f"unchanged ({latest.get('representation_hint', 'stored_value')}, length="
            f"{latest.get('candidate_length', 'unknown')}); do not submit that same value "
            "again as presumed plaintext."
        ),
        (
            "Keep the authoritative request contract and test one bounded material "
            "authentication dimension: target-side representation/transform, an adjacent "
            "request field or sink, or the same-session protected-resource transition. "
            "Require an explicit target success response plus protected access; a fresh "
            "session cookie by itself is not authentication."
        ),
    )


__all__ = [
    "RejectedCredentialReplay",
    "detect_rejected_credential_replay",
    "rejected_credential_replay_constraints",
    "rejected_credential_replay_message",
    "remember_rejected_credential_replay",
    "remembered_rejected_credential_replays",
]
