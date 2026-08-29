from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    FrontierObjective,
    FrontierObjectiveBasis,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_IDENTITY_MARKERS = ("username", "user", "login", "email")
_PASSWORD_MARKERS = ("password", "passwd", "pass")
_FORM_NAME = re.compile(r"""(?i)\bname\s*=\s*["']([^"']+)["']""")
_FORM_METHOD = re.compile(r"""(?i)\bmethod\s*=\s*["']?([a-z]+)""")
_FORM_ACTION = re.compile(r"""(?i)\baction\s*=\s*["']([^"']*)["']""")


@dataclass(frozen=True)
class ObservedLoginContract:
    endpoint: str
    inputs: tuple[str, ...]
    evidence_ref: str


def augment_transition_objectives(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
    objectives: Sequence[FrontierObjective],
    limit: int,
) -> tuple[FrontierObjective, ...]:
    """
    Add a finite auth-closure route when base evidence supports the transition.

    This does not infer a benchmark label or vulnerability from prose alone. It
    requires both a confirmed SQL primitive and a target-observed username/password
    form contract.
    """
    if limit <= 0:
        return ()
    transition = sql_auth_transition_objective(state, base=base)
    ordered = [transition] if transition is not None else []
    ordered.extend(objectives)
    deduped: list[FrontierObjective] = []
    seen: set[str] = set()
    for objective in ordered:
        if objective.fingerprint in seen:
            continue
        seen.add(objective.fingerprint)
        deduped.append(objective)
        if len(deduped) >= limit:
            break
    return tuple(deduped)


def sql_auth_transition_objective(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
) -> FrontierObjective | None:
    primitive_turn = _positive_int(state.primitives.get("sqli_confirmed"))
    if primitive_turn is None:
        return None
    contract = _observed_login_contract(state, target_url=base.target_url)
    if contract is None:
        return None
    return FrontierObjective.create(
        family="authentication",
        probe="sqli_auth_transition",
        endpoint=contract.endpoint,
        inputs=contract.inputs,
        payload_class="confirmed_primitive:sqli_confirmed:authentication_transition",
        expected_signal=(
            "Convert the confirmed SQL primitive on the target-observed login contract "
            "into an explicit authenticated transition. Require protected same-session "
            "access against a fresh anonymous control, then preserve that session for "
            "bounded proof closure; otherwise emit target-observed finite exhaustion."
        ),
        evidence_refs=(
            f"base-state:{base.state_digest}",
            f"primitive:sqli_confirmed:turn:{primitive_turn}",
            contract.evidence_ref,
        ),
        basis=FrontierObjectiveBasis.BASE_FRONTIER,
    )


def _observed_login_contract(
    state: AgentState,
    *,
    target_url: str,
) -> ObservedLoginContract | None:
    for raw in reversed(state.signals.get("forms", [])):
        parsed = _parse_form(raw, target_url=target_url)
        if parsed is not None:
            return parsed
    return None


def _parse_form(raw: object, *, target_url: str) -> ObservedLoginContract | None:
    text = str(raw).strip()
    if not text:
        return None
    payload = _json_mapping(raw)
    if payload:
        method = str(payload.get("method") or "GET").strip().upper()
        action = str(payload.get("action") or target_url).strip()
        names = _mapping_form_names(payload)
    else:
        method_match = _FORM_METHOD.search(text)
        method = method_match.group(1).upper() if method_match else "GET"
        action_match = _FORM_ACTION.search(text)
        action = action_match.group(1).strip() if action_match else target_url
        names = tuple(
            dict.fromkeys(
                match.group(1).strip()
                for match in _FORM_NAME.finditer(text)
                if match.group(1).strip()
            )
        )
    lowered = tuple(name.lower() for name in names)
    if method != "POST" or not _has_login_fields(lowered):
        return None
    endpoint = urljoin(target_url, action or target_url)
    if _origin(endpoint) != _origin(target_url):
        return None
    evidence_digest = hashlib.sha256(text.encode()).hexdigest()
    return ObservedLoginContract(
        endpoint=endpoint,
        inputs=names,
        evidence_ref=f"base-login-contract:{evidence_digest}",
    )


def _mapping_form_names(payload: Mapping[str, object]) -> tuple[str, ...]:
    inputs = payload.get("inputs")
    if not isinstance(inputs, list):
        return ()
    names: list[str] = []
    for item in inputs:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _has_login_fields(names: Sequence[str]) -> bool:
    return any(
        any(marker in name for marker in _IDENTITY_MARKERS)
        and not any(marker in name for marker in _PASSWORD_MARKERS)
        for name in names
    ) and any(any(marker in name for marker in _PASSWORD_MARKERS) for name in names)


def _json_mapping(raw: object) -> dict[str, object]:
    try:
        payload = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _origin(value: str) -> tuple[str, str]:
    parsed = urlsplit(value)
    return parsed.scheme.lower(), parsed.netloc.lower()


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


__all__ = [
    "ObservedLoginContract",
    "augment_transition_objectives",
    "sql_auth_transition_objective",
]
