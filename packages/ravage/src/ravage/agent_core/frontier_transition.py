from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from ravage.agent_core.agent_specialists import (
    available_specialists,
    recommended_specialists,
)
from ravage.agent_core.agent_state import AgentState, load_agent_state
from ravage.agent_core.frontier_replay_contract import (
    authoritative_replay_for_family,
    replay_contract_expected_clause,
)
from ravage.agent_core.frontier_route import (
    DEFAULT_SEEDED_OBJECTIVE_LIMIT,
    BaseRouteOutcome,
    BaseRouteTermination,
    FrontierObjective,
    FrontierObjectiveBasis,
)
from ravage.agent_core.primitive_state import (
    derive_primitives,
    locked_primitive,
    primitive_rule,
    probe_recently_exhausted,
)
from ravage.agent_core.semantic_routes import semantic_action_route
from ravage.probe_suite import authenticated_probe_unavailability

if TYPE_CHECKING:
    from pathlib import Path

_MAX_SURFACE_DEPTH = 4
_FAMILY_SIGNAL_KEYS: dict[str, tuple[str, ...]] = {
    "sql_injection": ("request_templates", "sqli_replays", "sqli_inputs"),
    "xml_external_entity": ("xxe_replays", "xml_requests", "forms"),
    "authentication": ("request_templates", "auth_replays", "forms"),
    "object_authorization": ("idor_replays", "request_templates"),
    "path_traversal": ("file_read_inputs", "file_read_replays"),
    "server_side_request_forgery": ("ssrf_replays", "request_templates"),
}
_ENDPOINT_KEYS = frozenset({"action", "endpoint", "path", "url"})


def inspect_base_route(
    workspace_dir: Path,
    *,
    target_url: str,
    max_model_requests: int,
    run_error: BaseException | None = None,
) -> BaseRouteOutcome:
    """Derive a secret-free terminal outcome without mutating the base workspace."""
    state_path = workspace_dir / "working_state.json"
    events_path = workspace_dir / "events.jsonl"
    state = load_agent_state(state_path)
    state_digest = _file_digest(state_path)
    state_target = _state_target_url(state_path)
    events = _read_jsonl(events_path)
    request_count = _model_request_count(events)
    finished = _latest_event_payload(events, kind="agent_finished")
    cost_stop = _latest_event_payload(events, kind="cost_budget_exhausted")
    cost_usd = _finished_cost(finished)
    proof_confirmed = bool(state and state.flags)

    if proof_confirmed:
        termination = BaseRouteTermination.SOLVED
    elif run_error is not None or state is None or state_target not in {"", target_url}:
        termination = BaseRouteTermination.ERROR
    elif cost_stop is not None:
        termination = BaseRouteTermination.COST_BUDGET_EXHAUSTED
    elif finished is None:
        termination = BaseRouteTermination.INTERRUPTED
    elif request_count >= max(max_model_requests, 1):
        termination = BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED
    else:
        termination = BaseRouteTermination.EXPLORATION_EXHAUSTED

    return BaseRouteOutcome(
        target_url=target_url,
        termination=termination,
        model_requests=request_count,
        state_digest=state_digest,
        state_ref=str(state_path),
        proof_confirmed=proof_confirmed,
        cost_usd=cost_usd,
    )


def seed_frontier_objectives(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
    limit: int = DEFAULT_SEEDED_OBJECTIVE_LIMIT,
) -> tuple[FrontierObjective, ...]:
    """Build a deterministic, benchmark-agnostic frontier from base-run evidence."""
    if limit <= 0:
        return ()
    attempted_probes = _attempted_probes(state)
    cards = _ordered_specialist_cards(state, attempted_probes=attempted_probes)
    endpoints = _state_endpoints(state)
    inputs = _state_inputs(state)
    evidence_refs = (f"base-state:{base.state_digest}",)
    objectives = _primitive_frontier_objectives(
        state,
        target_url=base.target_url,
        endpoints=endpoints,
        inputs=inputs,
        evidence_refs=evidence_refs,
    )
    if len(objectives) >= limit:
        return tuple(objectives[:limit])
    seeded_probes = {objective.probe for objective in objectives}

    for card in cards:
        probe = str(card.get("probe") or "").strip()
        if not probe or probe in seeded_probes:
            continue
        family = str(
            semantic_action_route({"action": "run_probe", "probe": probe}).get("family")
            or "unknown"
        )
        route = _recent_route_for_family(state, family=family)
        route_endpoints = _string_tuple(route.get("endpoints"))
        route_inputs = _string_tuple(route.get("inputs"))
        endpoint = (route_endpoints or endpoints or ("",))[0]
        objective = FrontierObjective.create(
            family=family,
            probe=probe,
            endpoint=endpoint,
            inputs=(route_inputs or inputs)[:4],
            payload_class=f"specialist:{probe}",
            expected_signal=(
                f"new target-observed {family} evidence that confirms, disproves, "
                "or materially narrows this route"
            ),
            evidence_refs=evidence_refs,
            basis=FrontierObjectiveBasis.BASE_FRONTIER,
        )
        if objective.fingerprint in {item.fingerprint for item in objectives}:
            continue
        objectives.append(objective)
        seeded_probes.add(probe)
        if len(objectives) >= limit:
            break
    return tuple(objectives)


def _primitive_frontier_objectives(
    state: AgentState,
    *,
    target_url: str,
    endpoints: tuple[str, ...],
    inputs: tuple[str, ...],
    evidence_refs: tuple[str, ...],
) -> list[FrontierObjective]:
    names = _ordered_live_primitives(state)
    if not names:
        return []
    primary = names[0]
    objectives = [
        _primitive_objective(
            state,
            name=primary,
            dimension=dimension,
            target_url=target_url,
            endpoints=endpoints,
            inputs=inputs,
            evidence_refs=evidence_refs,
        )
        for dimension in ("request_contract", "payload_semantics", "proof_channel")
    ]
    objectives.extend(
        _primitive_objective(
            state,
            name=name,
            dimension="request_contract",
            target_url=target_url,
            endpoints=endpoints,
            inputs=inputs,
            evidence_refs=evidence_refs,
        )
        for name in names[1:]
    )
    return objectives


def _ordered_live_primitives(state: AgentState) -> list[str]:
    names = [
        name
        for name in derive_primitives(state)
        if name in state.primitives
        and (rule := primitive_rule(name)) is not None
        and not _authenticated_probe_unavailable_for_state(
            state,
            rule.probe,
        )
    ]
    locked = locked_primitive(state)
    if locked in names:
        names.remove(locked)
        names.insert(0, locked)
    return names


def _primitive_objective(  # noqa: PLR0913 - structured objective fields stay explicit.
    state: AgentState,
    *,
    name: str,
    dimension: str,
    target_url: str,
    endpoints: tuple[str, ...],
    inputs: tuple[str, ...],
    evidence_refs: tuple[str, ...],
) -> FrontierObjective:
    rule = primitive_rule(name)
    if rule is None:
        message = f"unknown confirmed primitive: {name}"
        raise ValueError(message)
    family = str(
        semantic_action_route({"action": "run_probe", "probe": rule.probe}).get("family")
        or "unknown"
    )
    route = _recent_route_for_family(state, family=family)
    route_endpoints = _string_tuple(route.get("endpoints"))
    route_inputs = _string_tuple(route.get("inputs"))
    signal_endpoints, signal_inputs = _family_signal_route(state, family=family)
    replay = authoritative_replay_for_family(
        state,
        family=family,
        target_url=target_url,
        preferred_inputs=signal_inputs or route_inputs or inputs,
    )
    endpoint = (
        replay.endpoint
        if replay is not None
        else (signal_endpoints or route_endpoints or endpoints or ("",))[0]
    )
    objective_inputs = (
        (replay.payload_field,)
        if replay is not None
        else (signal_inputs or route_inputs or inputs)[:4]
    )
    exhausted = probe_recently_exhausted(state, rule.probe)
    expected_signal = _primitive_expected_signal(
        name=name,
        probe=rule.probe,
        dimension=dimension,
        exhausted=exhausted,
    )
    if replay is not None:
        expected_signal += replay_contract_expected_clause(replay)
    return FrontierObjective.create(
        family=family,
        probe=rule.probe,
        endpoint=endpoint,
        inputs=objective_inputs,
        payload_class=f"confirmed_primitive:{name}:{dimension}",
        expected_signal=expected_signal,
        evidence_refs=tuple(
            dict.fromkeys(
                (
                    *evidence_refs,
                    f"primitive:{name}:turn:{state.primitives.get(name, 0)}",
                    *((replay.evidence_ref,) if replay is not None else ()),
                )
            )
        ),
        basis=FrontierObjectiveBasis.BASE_FRONTIER,
    )


def _primitive_expected_signal(
    *,
    name: str,
    probe: str,
    dimension: str,
    exhausted: bool,
) -> str:
    focus = {
        "request_contract": (
            "preserve the accepted endpoint, method, parameters, cookies, and workflow "
            "state; obtain one new target-observed transition toward proof"
        ),
        "payload_semantics": (
            "hold the request contract fixed and change one payload family, encoding, "
            "or engine-specific exploit semantic; obtain a new target differential"
        ),
        "proof_channel": (
            "hold the confirmed exploit route fixed and change only the output, readback, "
            "or proof-extraction channel; obtain replayable target proof"
        ),
    }[dimension]
    exhausted_note = (
        f" The default run_probe {probe} route is exhausted; do not rerun it unchanged."
        if exhausted
        else ""
    )
    return f"Confirmed {name}: {focus}.{exhausted_note}"


def _ordered_specialist_cards(
    state: AgentState,
    *,
    attempted_probes: set[str],
) -> list[dict[str, object]]:
    recommended = recommended_specialists(state, limit=16)
    combined = [*recommended, *available_specialists()]
    unique: list[dict[str, object]] = []
    seen: set[str] = set()
    for card in combined:
        probe = str(card.get("probe") or "").strip()
        if not probe or probe in seen or _authenticated_probe_unavailable_for_state(state, probe):
            continue
        seen.add(probe)
        unique.append(dict(card))
    return sorted(
        unique,
        key=lambda card: (
            -_card_score(card),
            str(card.get("probe") or "") in attempted_probes,
        ),
    )


def _authenticated_probe_unavailable_for_state(state: AgentState, probe: str) -> bool:
    return bool(
        str(state.surface.get("authenticated_identity") or "").strip()
        and authenticated_probe_unavailability(probe)
    )


def _card_score(card: Mapping[str, object]) -> int:
    try:
        return int(str(card.get("score") or 0))
    except ValueError:
        return 0


def _attempted_probes(state: AgentState) -> set[str]:
    probes = {
        str(action.get("probe") or "").strip()
        for action in state.actions
        if isinstance(action, Mapping)
    }
    for attempt in state.attempts:
        for key in ("selected_action", "proposed_action"):
            action = attempt.get(key)
            if isinstance(action, Mapping):
                probes.add(str(action.get("probe") or "").strip())
    probes.discard("")
    return probes


def _recent_route_for_family(
    state: AgentState,
    *,
    family: str,
) -> dict[str, object]:
    for attempt in reversed(state.attempts):
        for key in ("selected_route", "proposed_route"):
            route = attempt.get(key)
            if isinstance(route, Mapping) and str(route.get("family") or "") == family:
                return dict(route)
    return {}


def _family_signal_route(
    state: AgentState,
    *,
    family: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    endpoints: list[str] = []
    inputs: list[str] = []
    for key in _FAMILY_SIGNAL_KEYS.get(family, ()):
        for raw in state.signals.get(key, []):
            value = _json_value(raw)
            endpoints.extend(_nested_strings(value, keys=_ENDPOINT_KEYS))
            inputs.extend(
                _nested_strings(
                    value,
                    keys={"field", "input", "name", "param", "parameter", "payload_field"},
                )
            )
    return _dedupe(endpoints), _dedupe(inputs)


def _json_value(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _nested_strings(
    value: object,
    *,
    keys: set[str] | frozenset[str],
    depth: int = 0,
) -> list[str]:
    if depth >= _MAX_SURFACE_DEPTH:
        return []
    found: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            if str(raw_key).lower() in keys:
                found.extend(_strings(item))
            found.extend(_nested_strings(item, keys=keys, depth=depth + 1))
    elif isinstance(value, list):
        for item in value[:100]:
            found.extend(_nested_strings(item, keys=keys, depth=depth + 1))
    return found


def _state_endpoints(state: AgentState) -> tuple[str, ...]:
    values: list[str] = []
    for key in ("endpoints", "urls", "routes"):
        values.extend(_strings(state.signals.get(key)))
    values.extend(_surface_strings(state.surface, keys={"endpoint", "path", "url"}))
    return _dedupe(values)[:12]


def _state_inputs(state: AgentState) -> tuple[str, ...]:
    values: list[str] = []
    for key in (
        "parameters",
        "parameter_names",
        "query_parameters",
        "form_fields",
        "inputs",
    ):
        values.extend(_strings(state.signals.get(key)))
    values.extend(
        _surface_strings(
            state.surface,
            keys={"field", "input", "name", "parameter", "param"},
        )
    )
    return _dedupe(values)[:12]


def _surface_strings(
    value: object,
    *,
    keys: set[str],
    depth: int = 0,
) -> list[str]:
    if depth >= _MAX_SURFACE_DEPTH:
        return []
    found: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).lower()
            if key in keys:
                found.extend(_strings(item))
            found.extend(_surface_strings(item, keys=keys, depth=depth + 1))
    elif isinstance(value, list):
        for item in value[:100]:
            found.extend(_surface_strings(item, keys=keys, depth=depth + 1))
    return found


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


def _model_request_count(events: Iterable[Mapping[str, object]]) -> int:
    identities: set[str] = set()
    anonymous = 0
    for event in events:
        if event.get("kind") != "model_request_started":
            continue
        payload = event.get("payload")
        request_id = (
            str(payload.get("model_request_id") or "").strip()
            if isinstance(payload, Mapping)
            else ""
        )
        if request_id:
            identities.add(request_id)
        else:
            anonymous += 1
    return len(identities) + anonymous


def _latest_event_payload(
    events: Iterable[Mapping[str, object]],
    *,
    kind: str,
) -> dict[str, object] | None:
    found: dict[str, object] | None = None
    for event in events:
        if event.get("kind") != kind:
            continue
        payload = event.get("payload")
        if isinstance(payload, Mapping):
            found = dict(payload)
    return found


def _finished_cost(finished: Mapping[str, object] | None) -> float:
    if finished is None:
        return 0.0
    try:
        return max(float(str(finished.get("cost_usd") or 0.0)), 0.0)
    except ValueError:
        return 0.0


def _file_digest(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _state_target_url(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ""
    if not isinstance(payload, Mapping):
        return ""
    return str(payload.get("target_url") or "")


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _string_tuple(value: object) -> tuple[str, ...]:
    return _dedupe(_strings(value))


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


__all__ = ["inspect_base_route", "seed_frontier_objectives"]
