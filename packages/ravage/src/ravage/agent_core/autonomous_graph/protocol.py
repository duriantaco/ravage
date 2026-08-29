from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from ravage.agent_core.autonomous_graph.models import (
    GraphMessageKind,
    GraphObjective,
    GraphStateError,
    Hypothesis,
)

_JSON_FENCE = re.compile(
    r"\A\s*```(?:json)?\s*(?P<body>\{.*\})\s*```\s*\Z",
    flags=re.DOTALL | re.IGNORECASE,
)
_NON_SEMANTIC_KEYS = frozenset(
    {
        "action_id",
        "nonce",
        "request_id",
        "timestamp",
        "trace_id",
    }
)
_MODEL_FORBIDDEN_SPAWN_KEYS = frozenset(
    {
        "agent_spec",
        "model_policy_key",
        "tool_policy_key",
        "runtime_profile_key",
        "session_policy_key",
    }
)
_MODEL_FORBIDDEN_HYPOTHESIS_KEYS = frozenset(
    {
        "fingerprint",
        "objective_fingerprint",
        "parent_hypothesis_fingerprint",
        "status",
        "disposition",
        "belief",
        "belief_basis_points",
        "belief_revision_id",
    }
)


class GraphProtocolError(ValueError):
    """Raised when a model reply is not one valid structured graph action."""


class GraphActionKind(StrEnum):
    EXECUTE = "execute"
    SPAWN = "spawn"
    MESSAGE = "message"
    WAIT = "wait"
    HANDOFF = "handoff"
    FINISH = "finish"
    SUBMIT_PROOF = "submit_proof"


@dataclass(frozen=True)
class GraphWorkerAction:
    kind: GraphActionKind
    payload: dict[str, object]
    rationale: str = ""

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> GraphWorkerAction:
        raw_kind = payload.get("kind")
        try:
            kind = GraphActionKind(str(raw_kind or ""))
        except ValueError as exc:
            message = f"unknown graph worker action kind: {raw_kind}"
            raise GraphProtocolError(message) from exc
        raw_action_payload = payload.get("payload")
        if not isinstance(raw_action_payload, Mapping):
            message = "graph worker action payload must be an object"
            raise GraphProtocolError(message)
        action_payload = _json_mapping(raw_action_payload)
        _validate_action_payload(kind, action_payload)
        return cls(
            kind=kind,
            payload=action_payload,
            rationale=" ".join(str(payload.get("rationale") or "").split()),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "payload": _json_mapping(self.payload),
            "rationale": self.rationale,
        }

    def spawn_objective(self) -> GraphObjective:
        if self.kind is not GraphActionKind.SPAWN:
            message = "spawn_objective is only valid for spawn actions"
            raise GraphProtocolError(message)
        raw = self.payload["objective"]
        if not isinstance(raw, Mapping):
            message = "spawn objective must be an object"
            raise GraphProtocolError(message)
        try:
            return GraphObjective.create(
                family=str(raw.get("family") or ""),
                instruction=str(raw.get("instruction") or ""),
                endpoint=str(raw.get("endpoint") or ""),
                inputs=_string_tuple(raw.get("inputs")),
                strategy=str(raw.get("strategy") or ""),
                expected_signal=str(raw.get("expected_signal") or ""),
                evidence_refs=_string_tuple(raw.get("evidence_refs")),
            )
        except GraphStateError as exc:
            message = f"invalid spawn objective: {exc}"
            raise GraphProtocolError(message) from exc

    def spawn_hypothesis(
        self,
        *,
        parent_hypothesis_fingerprint: str = "",
    ) -> Hypothesis:
        """Parse a model proposal while binding identity in the control plane."""
        if self.kind is not GraphActionKind.SPAWN:
            message = "spawn_hypothesis is only valid for spawn actions"
            raise GraphProtocolError(message)
        objective = self.spawn_objective()
        raw = self.payload.get("hypothesis")
        if raw is None:
            return Hypothesis.from_objective(
                objective,
                parent_hypothesis_fingerprint=parent_hypothesis_fingerprint,
            )
        if not isinstance(raw, Mapping):
            message = "spawn hypothesis must be an object"
            raise GraphProtocolError(message)
        forbidden = _MODEL_FORBIDDEN_HYPOTHESIS_KEYS & set(raw)
        if forbidden:
            message = "spawn hypothesis contains control-plane fields: " + ",".join(
                sorted(forbidden)
            )
            raise GraphProtocolError(message)
        required_capabilities = _validated_string_tuple(
            raw.get("required_capabilities", []),
            label="hypothesis required_capabilities",
        )
        basis_evidence_refs = _validated_string_tuple(
            raw.get("basis_evidence_refs", []),
            label="hypothesis basis_evidence_refs",
        )
        try:
            return Hypothesis.create(
                objective_fingerprint=objective.fingerprint,
                claim=str(raw.get("claim") or ""),
                support_signal=str(raw.get("support_signal") or ""),
                falsification_signal=str(raw.get("falsification_signal") or ""),
                next_discriminating_test=str(raw.get("next_discriminating_test") or ""),
                required_capabilities=required_capabilities,
                basis_evidence_refs=basis_evidence_refs,
                parent_hypothesis_fingerprint=parent_hypothesis_fingerprint,
            )
        except GraphStateError as exc:
            message = f"invalid spawn hypothesis: {exc}"
            raise GraphProtocolError(message) from exc

    def message_kind(self) -> GraphMessageKind:
        if self.kind not in {
            GraphActionKind.MESSAGE,
            GraphActionKind.HANDOFF,
        }:
            message = "message_kind is only valid for message actions"
            raise GraphProtocolError(message)
        raw = self.payload.get("message_kind", GraphMessageKind.INFORMATION.value)
        try:
            return GraphMessageKind(str(raw))
        except ValueError as exc:
            message = f"unknown graph message kind: {raw}"
            raise GraphProtocolError(message) from exc


def parse_worker_action(content: str) -> GraphWorkerAction:
    """Parse one JSON action; surrounding model prose is rejected."""
    stripped = content.strip()
    fenced = _JSON_FENCE.fullmatch(stripped)
    candidate = fenced.group("body") if fenced is not None else stripped
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        message = f"graph worker reply is not valid JSON: {exc.msg}"
        raise GraphProtocolError(message) from exc
    if not isinstance(payload, Mapping):
        message = "graph worker reply must be one JSON object"
        raise GraphProtocolError(message)
    return GraphWorkerAction.from_json(payload)


def semantic_action_fingerprint(action: GraphWorkerAction) -> str:
    """Canonicalize an executable effect independently of model wording."""
    if action.kind is not GraphActionKind.EXECUTE:
        message = "only execute actions have tool-effect fingerprints"
        raise GraphProtocolError(message)
    canonical = {
        "tool": _normalized_text(str(action.payload["tool"])).lower(),
        "arguments": _canonical_value(action.payload["arguments"]),
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_action_payload(  # noqa: C901, PLR0912 - closed action union.
    kind: GraphActionKind,
    payload: Mapping[str, object],
) -> None:
    if kind is GraphActionKind.EXECUTE:
        _required_text(payload, "tool")
        if not isinstance(payload.get("arguments"), Mapping):
            message = "execute action arguments must be an object"
            raise GraphProtocolError(message)
        _required_text(payload, "expected_signal")
        return
    if kind is GraphActionKind.SPAWN:
        forbidden = _MODEL_FORBIDDEN_SPAWN_KEYS & set(payload)
        if forbidden:
            message = "spawn action cannot select control-plane policy: " + ",".join(
                sorted(forbidden)
            )
            raise GraphProtocolError(message)
        _required_text(payload, "name")
        raw_objective = payload.get("objective")
        if not isinstance(raw_objective, Mapping):
            message = "spawn action objective must be an object"
            raise GraphProtocolError(message)
        GraphWorkerAction(
            kind=kind,
            payload=dict(payload),
        ).spawn_hypothesis()
        lease_limit = payload.get("lease_limit", 2)
        if isinstance(lease_limit, bool) or not isinstance(lease_limit, int):
            message = "spawn action lease_limit must be an integer"
            raise GraphProtocolError(message)
        if lease_limit <= 0:
            message = "spawn action lease_limit must be positive"
            raise GraphProtocolError(message)
        return
    if kind in {GraphActionKind.MESSAGE, GraphActionKind.HANDOFF}:
        _required_text(payload, "target_id")
        raw_body = payload.get("body")
        if not isinstance(raw_body, Mapping):
            message = "message action body must be an object"
            raise GraphProtocolError(message)
        raw_message_kind = payload.get(
            "message_kind",
            GraphMessageKind.INFORMATION.value,
        )
        try:
            GraphMessageKind(str(raw_message_kind))
        except ValueError as exc:
            message = f"unknown graph message kind: {raw_message_kind}"
            raise GraphProtocolError(message) from exc
        if kind is GraphActionKind.HANDOFF:
            _required_text(payload, "summary")
        return
    if kind is GraphActionKind.WAIT:
        timeout = payload.get("timeout_seconds")
        if timeout is not None and (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0
        ):
            message = "wait timeout_seconds must be a non-negative number"
            raise GraphProtocolError(message)
        return
    if kind is GraphActionKind.FINISH:
        _required_text(payload, "summary")
        _validate_evidence_refs(payload, required=False)
        return
    if kind is GraphActionKind.SUBMIT_PROOF:
        _validate_evidence_refs(payload, required=True)
        return
    message = f"unsupported graph worker action kind: {kind.value}"
    raise GraphProtocolError(message)


def _validate_evidence_refs(
    payload: Mapping[str, object],
    *,
    required: bool,
) -> None:
    raw = payload.get("evidence_refs", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        message = "evidence_refs must be a list of non-empty strings"
        raise GraphProtocolError(message)
    if required and not raw:
        message = "submit_proof requires at least one evidence ref"
        raise GraphProtocolError(message)


def _required_text(payload: Mapping[str, object], key: str) -> str:
    text = _normalized_text(str(payload.get(key) or ""))
    if not text:
        message = f"{key} must be a non-empty string"
        raise GraphProtocolError(message)
    return text


def _canonical_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in sorted(
                value.items(),
                key=lambda pair: str(pair[0]),
            )
            if str(key) not in _NON_SEMANTIC_KEYS
        }
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, str):
        return _normalized_text(value)
    return value


def _normalized_text(value: str) -> str:
    return " ".join(value.strip().split())


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        sorted({_normalized_text(str(item)) for item in value if _normalized_text(str(item))})
    )


def _validated_string_tuple(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and _normalized_text(item) for item in value
    ):
        message = f"{label} must be a list of non-empty strings"
        raise GraphProtocolError(message)
    return _string_tuple(value)


def _json_mapping(value: Mapping[str, object]) -> dict[str, object]:
    try:
        encoded = json.dumps(dict(value), ensure_ascii=False, sort_keys=True)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        message = f"graph action payload must be JSON serializable: {exc}"
        raise GraphProtocolError(message) from exc
    if not isinstance(decoded, dict):
        message = "graph action payload must encode to an object"
        raise GraphProtocolError(message)
    return dict(decoded)


__all__ = [
    "GraphActionKind",
    "GraphProtocolError",
    "GraphWorkerAction",
    "parse_worker_action",
    "semantic_action_fingerprint",
]
