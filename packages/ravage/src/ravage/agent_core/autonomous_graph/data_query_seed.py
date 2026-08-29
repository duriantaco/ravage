# Data-query seeding is additive and reads only frozen target-observed state.
# ruff: noqa: C901, CPY001, PLR0912

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from ravage.agent_core.frontier_route import (
    FrontierObjective,
    FrontierObjectiveBasis,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.frontier_route import BaseRouteOutcome

_FORM_ACTION = re.compile(
    r"\baction\s*=\s*[\"']?([^\"'\s>]+)",
    flags=re.IGNORECASE,
)
_QUERY_PATH = re.compile(
    r"(?:^|[/_.-])(?:search|query|filter|lookup|find)(?:[/_.-]|$)",
    flags=re.IGNORECASE,
)
_QUERY_HINTS = frozenset({"data", "filter", "lookup", "query", "search"})
_QUERY_INPUT_MARKERS = (
    "filter",
    "query",
    "search",
    "lookup",
    "term",
    "keyword",
    "email",
    "username",
    "user",
    "name",
    "category",
    "sort",
    "order",
    "id",
)
_TRANSPORT_INPUTS = frozenset(
    {
        "action",
        "csrf",
        "csrfmiddlewaretoken",
        "eio",
        "submit",
        "transport",
        "wsdl",
    }
)
_MAX_QUERY_INPUTS = 2


@dataclass(frozen=True)
class DataQueryContract:
    endpoint: str
    inputs: tuple[str, ...]


def data_query_seed_objective(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
) -> FrontierObjective | None:
    contract = data_query_contract(state, target_url=base.target_url)
    if contract is None:
        return None
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_differential",
        endpoint=contract.endpoint,
        inputs=contract.inputs,
        payload_class="graph_constraint:data_query_request_contract",
        expected_signal=(
            "Bind SQL work to this target-observed query endpoint and input set. "
            "First recover and replay the exact request contract with paired controls. "
            "On no typed differential, pivot once to the finite filter/encoding boundary; "
            "on a stable differential, continue only to bounded extraction or auth closure."
        ),
        evidence_refs=(f"base-state:{base.state_digest}",),
        basis=FrontierObjectiveBasis.BASE_FRONTIER,
    )


def data_query_contract(
    state: AgentState,
    *,
    target_url: str,
) -> DataQueryContract | None:
    if not _data_query_work_is_live(state):
        return None
    endpoints = _query_endpoints(state, target_url=target_url)
    if not endpoints:
        return None
    inputs = _query_inputs(state, endpoint=endpoints[0][1])
    if not inputs:
        return None
    return DataQueryContract(
        endpoint=endpoints[0][1],
        inputs=inputs,
    )


def _data_query_work_is_live(state: AgentState) -> bool:
    return any(
        str(task.get("id") or "") == "data-query" and str(task.get("status") or "") != "done"
        for task in state.tasks
        if isinstance(task, Mapping)
    )


def _query_endpoints(
    state: AgentState,
    *,
    target_url: str,
) -> tuple[tuple[int, str], ...]:
    candidates: dict[str, int] = {}
    raw_endpoints = state.surface.get("endpoints")
    if isinstance(raw_endpoints, Sequence) and not isinstance(raw_endpoints, str):
        for raw in raw_endpoints:
            if not isinstance(raw, Mapping):
                continue
            endpoint = _scoped_url(str(raw.get("url") or ""), target_url=target_url)
            if not endpoint:
                continue
            hints = {
                str(item).strip().lower() for item in raw.get("hints", []) if str(item).strip()
            }
            query_path = bool(_QUERY_PATH.search(urlsplit(endpoint).path))
            query_hints = hints.intersection(_QUERY_HINTS)
            # Structured surface inventory is authoritative. A live generic
            # data-query task must not turn every endpoint (especially an
            # authentication-only form) into a SQL objective.
            if not query_path and not query_hints:
                continue
            score = _integer(raw.get("priority"))
            if query_hints:
                score += 300
            if query_path:
                score += 220
            candidates[endpoint] = max(candidates.get(endpoint, 0), score)
    for raw in state.signals.get("forms", []):
        match = _FORM_ACTION.search(_normalized_form_text(raw))
        if match is None:
            continue
        endpoint = _scoped_url(match.group(1), target_url=target_url)
        if endpoint and _QUERY_PATH.search(urlsplit(endpoint).path):
            candidates[endpoint] = max(candidates.get(endpoint, 0), 240)
    for raw in state.signals.get("endpoints", []):
        endpoint = _scoped_url(str(raw), target_url=target_url)
        if endpoint and _QUERY_PATH.search(urlsplit(endpoint).path):
            candidates[endpoint] = max(candidates.get(endpoint, 0), 180)
    return tuple(
        sorted(
            ((score, endpoint) for endpoint, score in candidates.items()),
            key=lambda item: (-item[0], item[1]),
        )
    )


def _query_inputs(
    state: AgentState,
    *,
    endpoint: str,
) -> tuple[str, ...]:
    observed: list[str] = []
    raw_parameters = state.surface.get("parameters")
    if isinstance(raw_parameters, Sequence) and not isinstance(raw_parameters, str):
        for raw in raw_parameters:
            if isinstance(raw, Mapping):
                locations = _string_sequence(raw.get("locations"))
                if locations and not any(
                    _same_endpoint(location, endpoint) for location in locations
                ):
                    continue
                name = str(raw.get("name") or raw.get("input") or "").strip()
            else:
                name = str(raw).strip()
            if name:
                observed.append(name)
    raw_forms = state.surface.get("forms")
    if isinstance(raw_forms, Sequence) and not isinstance(raw_forms, str):
        for raw in raw_forms:
            if not isinstance(raw, Mapping):
                continue
            action = str(raw.get("action") or raw.get("page") or "").strip()
            if not action or not _same_endpoint(action, endpoint):
                continue
            for item in raw.get("inputs", []):
                if not isinstance(item, Mapping):
                    continue
                name = str(item.get("name") or "").strip()
                if name:
                    observed.append(name)

    # Legacy base state sometimes has only a query-specific action plus a global
    # parameter list. Falling back is safe only after the endpoint itself passed
    # the explicit query-path/query-hint gate above.
    if not observed:
        for raw in state.signals.get("parameters", []):
            name = str(raw).strip()
            if name:
                observed.append(name)
    scored = {
        name: _query_input_score(name)
        for name in observed
        if name.lower() not in _TRANSPORT_INPUTS and _query_input_score(name) > 0
    }
    return tuple(
        name
        for name, _score in sorted(
            scored.items(),
            key=lambda item: (-item[1], item[0].lower(), item[0]),
        )[:_MAX_QUERY_INPUTS]
    )


def _query_input_score(name: str) -> int:
    lowered = name.strip().lower()
    if not lowered:
        return 0
    for index, marker in enumerate(_QUERY_INPUT_MARKERS):
        if lowered == marker:
            return 200 - index
        if marker in lowered:
            return 100 - index
    return 0


def _normalized_form_text(value: object) -> str:
    return str(value).replace('\\"', '"').replace("\\'", "'")


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _same_endpoint(left: str, right: str) -> bool:
    left_parts = urlsplit(left)
    right_parts = urlsplit(right)
    return (
        left_parts.scheme.lower(),
        left_parts.netloc.lower(),
        left_parts.path.rstrip("/") or "/",
    ) == (
        right_parts.scheme.lower(),
        right_parts.netloc.lower(),
        right_parts.path.rstrip("/") or "/",
    )


def _scoped_url(value: str, *, target_url: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    candidate = urljoin(target_url.rstrip("/") + "/", raw)
    target = urlsplit(target_url)
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if (parsed.hostname, parsed.port) != (target.hostname, target.port):
        return ""
    return candidate


def _integer(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


__all__ = [
    "DataQueryContract",
    "data_query_contract",
    "data_query_seed_objective",
]
